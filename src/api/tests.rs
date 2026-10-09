// The JSON API served on a real socket (127.0.0.1, port chosen by the OS) and spoken to with reqwest.
use super::*;
use crate::db::testutil::*;
use crate::limiter::LocalLimiter;
use crate::security::{ApiAuth, TrustedProxies};
use crate::state::Metrics;
use hmac::{Hmac, Mac};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, TokenUrl};
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

const KEY: &str = "test-internal-key-0123456789abcdef";
const WH: &str = "whsec_unit_test";
const TOK: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";

pub(crate) fn test_state(pool: sqlx::SqlitePool, auth: ApiAuth, base_url: &str) -> Arc<AppState> {
    Arc::new(AppState {
        pool,
        // never connected to: port 1 refuses, which is the "Redis is down" condition
        redis: redis::Client::open("redis://127.0.0.1:1").unwrap(),
        oauth_client: BasicClient::new(
            ClientId::new("id".into()),
            Some(ClientSecret::new("secret".into())),
            AuthUrl::new("https://discord.invalid/authorize".into()).unwrap(),
            Some(TokenUrl::new("https://discord.invalid/token".into()).unwrap()),
        ),
        http_client: reqwest::Client::new(),
        stripe_secret: "sk_test".into(),
        stripe_webhook_secret: WH.into(),
        base_url: base_url.into(),
        api_auth: auth,
        trusted_proxies: TrustedProxies::none(),
        local_limiter: LocalLimiter::new(1000),
        metrics: Arc::new(Metrics::default()),
        shutdown: Arc::new(AtomicBool::new(false)),
    })
}

struct Server {
    base: String,
    http: reqwest::Client,
    state: Arc<AppState>,
    _db: TempDb,
}

async fn serve_with(auth: ApiAuth, base_url: &str) -> Server {
    let db = temp_db().await;
    let state = test_state(db.pool.clone(), auth, base_url);
    let app = finish(routes(), state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    Server { base: format!("http://{}", addr), http: reqwest::Client::builder().no_proxy().build().unwrap(), state, _db: db }
}

async fn serve() -> Server {
    serve_with(ApiAuth::from_config(Some(KEY), false).unwrap(), "http://localhost:4000").await
}

impl Server {
    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.get(format!("{}{}", self.base, path))
    }
    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.post(format!("{}{}", self.base, path))
    }
}

fn webhook_body(evt: &str, token: &str, cents: i64) -> String {
    serde_json::json!({
        "id": evt, "type": "checkout.session.completed",
        "data": {"object": {"id": format!("cs_{evt}"), "amount_total": cents, "currency": "usd",
                            "payment_status": "paid", "metadata": {"access_token": token, "amount_dollars": "99.00"}}}
    })
    .to_string()
}

fn sig(body: &str, ts: i64, secret: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{ts}.{body}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ---- I2 ---------------------------------------------------------------------------
#[tokio::test]
async fn internal_endpoints_need_the_key() {
    let s = serve().await;
    seed(&s.state.pool, "victim", TOK, 0, 3.0, false).await;
    sqlx::query("UPDATE users SET discord_id = '4242'").execute(&s.state.pool).await.unwrap();
    let body = serde_json::json!({"access_token": TOK, "bytes_used": 1});
    for (method, path) in [("GET", "/api/user/discord/4242"), ("GET", "/api/stats"), ("GET", "/metrics"), ("POST", "/api/usage/report")] {
        for key in [None, Some(""), Some("wrong"), Some(&KEY[..KEY.len() - 1]), Some("test-internal-key-0123456789abcdeF")] {
            let mut rb = if method == "GET" { s.get(path) } else { s.post(path).json(&body) };
            if let Some(k) = key {
                rb = rb.header("X-Internal-Key", k);
            }
            let r = rb.send().await.unwrap();
            assert_eq!(r.status(), 401, "{method} {path} with key {key:?}");
        }
        let mut rb = if method == "GET" { s.get(path) } else { s.post(path).json(&body) };
        rb = rb.header("X-Internal-Key", KEY);
        assert_eq!(rb.send().await.unwrap().status(), 200, "{method} {path} with the key");
    }
    // and a failed attempt leaks nothing: the 401 has no token in it
    let r = s.get("/api/user/discord/4242").send().await.unwrap();
    assert!(!r.text().await.unwrap().contains(TOK));
}

#[tokio::test]
async fn an_explicitly_open_api_answers_without_a_key() {
    let s = serve_with(ApiAuth::from_config(None, true).unwrap(), "http://localhost:4000").await;
    assert_eq!(s.get("/api/stats").send().await.unwrap().status(), 200);
    assert_eq!(s.get("/metrics").send().await.unwrap().status(), 200);
}

// ---- I3 ---------------------------------------------------------------------------
#[tokio::test]
async fn usage_reports_over_the_cap_are_a_400_and_change_nothing() {
    let s = serve().await;
    seed(&s.state.pool, "meter", TOK, 1000, 5.0, false).await;
    for bytes in ["18446744073709551115", "9223372036854775807", "1099511627777", "18446744073709551615"] {
        let body = format!(r#"{{"access_token":"{TOK}","bytes_used":{bytes}}}"#);
        let r = s.post("/api/usage/report").header("X-Internal-Key", KEY).header("content-type", "application/json").body(body).send().await.unwrap();
        assert_eq!(r.status(), 400, "{bytes}");
    }
    assert_eq!(used(&s.state.pool, TOK).await, 1000);
    let r = s.post("/api/usage/report").header("X-Internal-Key", KEY).json(&serde_json::json!({"access_token": TOK, "bytes_used": 4096})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(used(&s.state.pool, TOK).await, 1000 + 4096);
    // negative, fractional and string amounts are not u64s
    for bad in [r#"-1"#, r#"1.5"#, r#""12""#, r#"null"#] {
        let body = format!(r#"{{"access_token":"{TOK}","bytes_used":{bad}}}"#);
        let r = s.post("/api/usage/report").header("X-Internal-Key", KEY).header("content-type", "application/json").body(body).send().await.unwrap();
        assert!(r.status().is_client_error(), "{bad}");
    }
    assert_eq!(used(&s.state.pool, TOK).await, 1000 + 4096);
}

#[tokio::test]
async fn an_unknown_or_malformed_token_is_404_and_a_db_failure_does_not_echo_its_text() {
    let s = serve().await;
    for tok in ["z".repeat(32), "short".into(), "../../etc/passwd".into(), "x".repeat(33)] {
        let r = s.post("/api/usage/report").header("X-Internal-Key", KEY).json(&serde_json::json!({"access_token": tok, "bytes_used": 1})).send().await.unwrap();
        assert_eq!(r.status(), 404, "{tok}");
    }
    s.state.pool.close().await;
    let r = s.post("/api/usage/report").header("X-Internal-Key", KEY).json(&serde_json::json!({"access_token": TOK, "bytes_used": 1})).send().await.unwrap();
    assert_eq!(r.status(), 500);
    let text = r.text().await.unwrap().to_lowercase();
    for leak in ["pool", "sqlx", "sqlite", "update", "users", "database", "closed", "error returned"] {
        assert!(!text.contains(leak), "the 500 body leaks {leak:?}: {text}");
    }
}

// ---- token verification ---------------------------------------------------------------
#[tokio::test]
async fn verify_token_requires_the_shape_and_returns_the_row() {
    let s = serve().await;
    seed(&s.state.pool, "alice", TOK, 5, 1.5, false).await;
    let r = s.get("/api/user/verify").bearer_auth(TOK).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["data"]["username"], "alice");
    for bad in ["", "short", &"a".repeat(33), "' OR '1'='1", &format!("{}\u{e9}", "a".repeat(30))] {
        let r = s.get("/api/user/verify").bearer_auth(bad).send().await.unwrap();
        assert_eq!(r.status(), 401, "{bad:?}");
    }
    assert_eq!(s.get("/api/user/verify").send().await.unwrap().status(), 401);
}

#[tokio::test]
async fn a_row_with_text_in_a_numeric_column_is_a_500_and_the_server_lives() {
    let s = serve().await;
    seed(&s.state.pool, "typeconf", TOK, 5, 1.5, false).await;
    sqlx::query("UPDATE users SET account_balance = 'garbage', discord_id = '77'").execute(&s.state.pool).await.unwrap();
    let r = s.get("/api/user/verify").bearer_auth(TOK).send().await.unwrap();
    assert_eq!(r.status(), 500);
    let r = s.get("/api/user/discord/77").header("X-Internal-Key", KEY).send().await.unwrap();
    assert_eq!(r.status(), 500);
    assert_eq!(s.get("/health").send().await.unwrap().status(), 200, "still serving");
}

// ---- health, headers, limits ------------------------------------------------------------
#[tokio::test]
async fn health_is_open_and_minimal() {
    let s = serve().await;
    let r = s.get("/health").send().await.unwrap();
    assert_eq!(r.status(), 200);
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j.as_object().unwrap().keys().collect::<Vec<_>>(), vec!["status"]);
    assert_eq!(j["status"], "degraded", "Redis is down in this fixture");
}

#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let s = serve().await;
    for path in ["/health", "/api/stats", "/metrics", "/no/such/route"] {
        let r = s.get(path).send().await.unwrap();
        let h = r.headers();
        assert_eq!(h["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(h["x-frame-options"], "DENY", "{path}");
        assert_eq!(h["referrer-policy"], "no-referrer", "{path}");
        assert_eq!(h["cache-control"], "no-store", "{path}");
        assert!(h.get("strict-transport-security").is_none(), "no HSTS over an http base_url ({path})");
    }
    let s = serve_with(ApiAuth::from_config(Some(KEY), false).unwrap(), "https://id.example.com").await;
    let r = s.get("/health").send().await.unwrap();
    assert!(r.headers()["strict-transport-security"].to_str().unwrap().starts_with("max-age="));
}

#[tokio::test]
async fn bodies_over_64_kib_are_refused() {
    let s = serve().await;
    let r = s.post("/api/usage/report").header("X-Internal-Key", KEY).header("content-type", "application/json").body(vec![b' '; 70_000]).send().await.unwrap();
    assert_eq!(r.status(), 413);
}

// ---- Stripe webhook over HTTP ---------------------------------------------------------------
async fn deliver(s: &Server, body: &str, header: &str) -> u16 {
    s.post("/stripe/webhook").header("Stripe-Signature", header).body(body.to_string()).send().await.unwrap().status().as_u16()
}

#[tokio::test]
async fn webhook_credits_once_checks_every_v1_and_refuses_the_rest() {
    let s = serve().await;
    seed(&s.state.pool, "payer", TOK, 0, 0.0, false).await;
    let now = chrono::Utc::now().timestamp();
    let body = webhook_body("evt_1", TOK, 500);
    let good = sig(&body, now, WH);
    let bad = "0".repeat(64);
    // rotation: the valid v1 first, a stale one last
    assert_eq!(deliver(&s, &body, &format!("t={now},v1={good},v1={bad}")).await, 200);
    assert_eq!(balance(&s.state.pool, TOK).await, 5.0, "credited Stripe's 500 cents, not metadata's $99");
    // the same signed delivery again, and a retry with a fresh signature: still 200, still $5
    assert_eq!(deliver(&s, &body, &format!("t={now},v1={good}")).await, 200);
    let now2 = now + 1;
    assert_eq!(deliver(&s, &body, &format!("t={now2},v1={}", sig(&body, now2, WH))).await, 200);
    assert_eq!(balance(&s.state.pool, TOK).await, 5.0);
    // refused: wrong secret, stale, malformed header, no header
    let b2 = webhook_body("evt_2", TOK, 500);
    assert_eq!(deliver(&s, &b2, &format!("t={now},v1={}", sig(&b2, now, "whsec_wrong"))).await, 400);
    assert_eq!(deliver(&s, &b2, &format!("t={},v1={}", now - 3600, sig(&b2, now - 3600, WH))).await, 400);
    assert_eq!(deliver(&s, &b2, &format!("t={now}, v1={}", sig(&b2, now, WH))).await, 400);
    assert_eq!(deliver(&s, &b2, "").await, 400);
    assert_eq!(s.post("/stripe/webhook").body(b2.clone()).send().await.unwrap().status(), 400);
    assert_eq!(balance(&s.state.pool, TOK).await, 5.0);
    // another event type is acknowledged and ignored
    let other = r#"{"id":"evt_9","type":"charge.refunded","data":{"object":{}}}"#;
    assert_eq!(deliver(&s, other, &format!("t={now},v1={}", sig(other, now, WH))).await, 200);
}

#[tokio::test]
async fn webhook_database_failure_is_a_500_so_stripe_retries() {
    let s = serve().await;
    seed(&s.state.pool, "payer", TOK, 0, 0.0, false).await;
    s.state.pool.close().await;
    let now = chrono::Utc::now().timestamp();
    let body = webhook_body("evt_db", TOK, 500);
    assert_eq!(deliver(&s, &body, &format!("t={now},v1={}", sig(&body, now, WH))).await, 500);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credits_and_usage_reports_over_http_lose_no_money() {
    let s = Arc::new(serve().await);
    seed(&s.state.pool, "racer", TOK, crate::billing::FREE_TIER_BYTES, 1000.0, false).await;
    let n = 30usize;
    let mut hs = vec![];
    for i in 0..n {
        let s2 = s.clone();
        hs.push(tokio::spawn(async move {
            let now = chrono::Utc::now().timestamp();
            let body = webhook_body(&format!("evt_h{i}"), TOK, 500);
            deliver(&s2, &body, &format!("t={now},v1={}", sig(&body, now, WH))).await == 200
        }));
        let s2 = s.clone();
        hs.push(tokio::spawn(async move {
            s2.post("/api/usage/report").header("X-Internal-Key", KEY).json(&serde_json::json!({"access_token": TOK, "bytes_used": 1u64 << 30})).send().await.unwrap().status() == 200
        }));
    }
    for h in hs {
        assert!(h.await.unwrap());
    }
    let expected = 1000.0 + n as f64 * 5.0 - n as f64 * 0.05;
    assert!((balance(&s.state.pool, TOK).await - expected).abs() < 1e-6);
}
