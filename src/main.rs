// ============================================================================
// DeMoD Communications Framework - Identity & Billing Service
// ============================================================================
// Copyright (c) 2024-2025 DeMoD LLC. All Rights Reserved.
// ============================================================================
// Redis-Backed Production Version
//
// Uses Redis for:
//   - Session storage (survives restarts)
//   - Rate limiting (distributed, persistent)
//   - CSRF tokens (shared across instances)
//
// This file holds what needs the askama template (templates/index.html): the
// HTML handlers and the process wiring. Everything else is in the library
// (src/lib.rs and its modules) so that `cargo test --lib` runs without it.
// ============================================================================

use askama::Template;
use axum::{
    body::Body,
    extract::{ConnectInfo, Form, Query, State},
    http::{
        header::{LOCATION, RETRY_AFTER, SET_COOKIE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use dcf_id::{
    api, auth, billing, db, gate,
    limiter::LocalLimiter,
    security::{self, ApiAuth, TrustedProxies},
    state::{
        AppState, Metrics, SessionData, CSRF_TOKEN_DURATION_SECS, HASH_QUEUE_WAIT, LOCAL_LIMITER_KEYS, LOCKOUT_DURATION_SECS,
        SESSION_DURATION_SECS,
    },
    VERSION,
};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use sqlx::sqlite::SqlitePoolOptions;
use std::{
    env,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{signal, sync::Semaphore};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const BYTES_PER_GB: f64 = billing::BYTES_PER_GB;
const FREE_TIER_BYTES: i64 = billing::FREE_TIER_BYTES;
const PRICE_PER_BYTE: f64 = billing::PRICE_PER_GB / BYTES_PER_GB;

// ============================================================================
// TEMPLATES
// ============================================================================
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    user: Option<UserDisplay>,
    error: Option<String>,
    version: &'static str,
}

struct UserDisplay {
    username: String,
    access_token: String,
    trial_pct: f64,
    paid_pct: f64,
    used_fmt: String,
    balance_fmt: String,
    cost_fmt: String,
    status_class: String,
    status_text: String,
    is_locked: bool,
    is_vip: bool,
}

// ============================================================================
// REQUEST TYPES
// ============================================================================
#[derive(Deserialize)]
struct AuthPayload {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct OAuthCallback {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct CheckoutForm {
    amount: Option<f64>,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
fn generate_token(len: usize) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}

fn with_cookie(mut resp: Response, cookie: HeaderValue) -> Response {
    resp.headers_mut().append(SET_COOKIE, cookie);
    resp
}

// ============================================================================
// CORE LOGIC
// ============================================================================
async fn dashboard_logic(pool: &sqlx::SqlitePool, username: &str) -> Option<UserDisplay> {
    let u = db::get_user_by_username(pool, username).await?;
    let (uname, token, data_used, balance, is_vip) = (u.username, u.access_token, u.data_used, u.account_balance, u.is_vip);

    let used = data_used as f64;
    let free_cap = FREE_TIER_BYTES as f64;

    let (trial_pct, paid_pct, projected_cost, is_locked) = if is_vip {
        (100.0, 100.0, 0.0, false)
    } else if used <= free_cap {
        ((used / free_cap) * 100.0, 0.0, 0.0, false)
    } else {
        let paid_used = used - free_cap;
        let cost = paid_used * PRICE_PER_BYTE;
        let limit_by_balance = balance / PRICE_PER_BYTE;
        let paid_pct = if limit_by_balance > 0.0 { (paid_used / limit_by_balance) * 100.0 } else { 100.0 };
        (100.0, paid_pct.min(100.0), cost, cost > balance)
    };

    Some(UserDisplay {
        username: uname,
        access_token: if is_locked && !is_vip { "LOCKED".into() } else { token },
        trial_pct,
        paid_pct,
        used_fmt: format!("{:.2} MB", used / 1_048_576.0),
        balance_fmt: format!("{:.2}", balance),
        cost_fmt: if is_vip { "VIP".into() } else { format!("${:.4}", projected_cost) },
        status_class: if is_vip { "vip".into() } else if is_locked { "locked".into() } else { "ok".into() },
        status_text: if is_vip { "VIP".into() } else if is_locked { "LOCKED".into() } else { "ACTIVE".into() },
        is_locked,
        is_vip,
    })
}

fn render_error(message: String) -> Response {
    let html = IndexTemplate { user: None, error: Some(message), version: VERSION }.render().unwrap_or_else(|_| "Error".into());
    Html(html).into_response()
}

fn render_index(user: Option<UserDisplay>) -> String {
    IndexTemplate { user, error: None, version: VERSION }.render().unwrap_or_else(|_| "Error".into())
}

/// Every Argon2 slot is taken and none came free in time: 503, try again.
fn busy_response() -> Response {
    let mut resp = render_error("The server is busy. Please try again in a moment.".into());
    *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    resp.headers_mut().insert(RETRY_AFTER, HeaderValue::from_static("2"));
    resp
}

/// Log the user in: a new session in Redis, the dashboard, and the session cookie.
async fn start_session(state: &AppState, username: &str, client_ip: &str) -> Response {
    let session_id = generate_token(64);
    let now = Utc::now();
    let session = SessionData {
        username: username.to_string(),
        expires_at: now.timestamp() + SESSION_DURATION_SECS,
        created_ip: client_ip.to_string(),
        created_at: now.to_rfc3339(),
    };
    let _ = state.save_session(&session_id, &session).await;

    let user = dashboard_logic(&state.pool, username).await;
    let html = render_index(user);
    Response::builder()
        .status(StatusCode::OK)
        .header(SET_COOKIE, security::session_cookie(&session_id, SESSION_DURATION_SECS, state.is_https()))
        .body(html.into())
        .unwrap_or_else(|_| render_error("Response failed".into()))
}

/// The username behind the first valid session cookie, if any.
async fn session_username(state: &AppState, headers: &HeaderMap) -> Option<String> {
    for sid in security::session_ids(headers) {
        if let Some(session) = state.get_session(sid).await {
            if session.expires_at > Utc::now().timestamp() {
                return Some(session.username);
            }
        }
    }
    None
}

// ============================================================================
// CORE HANDLERS
// ============================================================================
async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    if let Some(username) = session_username(&state, &headers).await {
        let user = dashboard_logic(&state.pool, &username).await;
        return Html(render_index(user));
    }
    Html(render_index(None))
}

async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(payload): Form<AuthPayload>,
) -> Response {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    if let Err(e) = security::validate_username(&payload.username) {
        return render_error(e);
    }
    if let Err(e) = security::validate_password(&payload.password) {
        return render_error(e);
    }

    let client_ip = state.client_ip(&headers, addr);
    let ip = client_ip.to_string();
    if !state.register_allowed(&ip).await {
        warn!(event = "register_throttled", ip = %ip);
        return render_error("Too many registration attempts from this address. Try again later.".into());
    }

    // Argon2 on the blocking pool, behind the same bounded permits as login; "busy" is a 503, not a queue.
    let password_hash = match auth::hash_password(&state, &payload.password).await {
        Ok(h) => h,
        Err(auth::HashError::Busy) => return busy_response(),
        Err(auth::HashError::Failed) => return render_error("Registration failed".into()),
    };

    let token = generate_token(32);
    let stored_ip = security::ip_for_storage(client_ip);
    match db::register_user(&state.pool, &payload.username, &password_hash, &token, stored_ip.as_deref()).await {
        Ok(()) => {
            info!(event = "user_registered", username = %payload.username);
            state.metrics.registrations.fetch_add(1, Ordering::Relaxed);
            start_session(&state, &payload.username, &ip).await
        }
        Err(db::RegisterError::Taken) => render_error("Username already taken".into()),
        Err(db::RegisterError::Db(e)) => {
            error!("Registration failed: {}", e);
            render_error("Registration failed".into())
        }
    }
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(payload): Form<AuthPayload>,
) -> Response {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    let client_ip = state.client_ip(&headers, addr);
    let ip = client_ip.to_string();

    // The attempt takes its slot (address, username) before any hashing, and Argon2 runs on the blocking
    // pool behind a bounded number of permits: see src/auth.rs.
    match auth::attempt_login(&state, &ip, &payload.username, &payload.password).await {
        auth::LoginOutcome::Success => {
            info!(event = "login_success", username = %payload.username);
            state.metrics.logins_success.fetch_add(1, Ordering::Relaxed);
            let stored_ip = security::ip_for_storage(client_ip);
            db::update_user_ip(&state.pool, &payload.username, stored_ip.as_deref()).await;
            start_session(&state, &payload.username, &ip).await
        }
        auth::LoginOutcome::BadCredentials => {
            state.metrics.logins_failed.fetch_add(1, Ordering::Relaxed);
            render_error("Invalid credentials".into())
        }
        auth::LoginOutcome::Locked(ttl) => {
            render_error(format!("Too many attempts. Try again in {} seconds.", ttl.min(LOCKOUT_DURATION_SECS)))
        }
        auth::LoginOutcome::Busy => busy_response(),
    }
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    for sid in security::session_ids(&headers) {
        state.delete_session(sid).await;
    }
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(LOCATION, "/")
        .header(SET_COOKIE, security::clear_session_cookie(state.is_https()))
        .body(Body::empty())
        .unwrap_or_else(|_| Redirect::to("/").into_response())
}

// ============================================================================
// OAUTH HANDLERS
// ============================================================================
async fn discord_auth(State(state): State<Arc<AppState>>) -> Response {
    // The state is ours (32 alphanumerics), is remembered in Redis for one use, and is ALSO put in an
    // HttpOnly cookie on this browser: the callback only proceeds for the browser that started the flow.
    let state_token = generate_token(32);
    let st = state_token.clone();
    let (auth_url, _) = state.oauth_client.authorize_url(move || CsrfToken::new(st)).add_scope(Scope::new("identify".into())).url();

    if state.save_csrf_token(&state_token).await.is_err() {
        return render_error("Sign in with Discord is temporarily unavailable.".into());
    }
    let location = match HeaderValue::from_str(auth_url.as_str()) {
        Ok(l) => l,
        Err(_) => return render_error("Sign in with Discord is temporarily unavailable.".into()),
    };
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(LOCATION, location)
        .header(SET_COOKIE, security::oauth_state_cookie(&state_token, CSRF_TOKEN_DURATION_SECS, state.is_https()))
        .body(Body::empty())
        .unwrap_or_else(|_| render_error("Response failed".into()))
}

async fn discord_callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<OAuthCallback>,
) -> Response {
    let client_ip = state.client_ip(&headers, addr);
    let ip = client_ip.to_string();
    let secure = state.is_https();
    let bad_state = |why: &str| {
        warn!(event = "csrf_validation_failed", ip = %ip, why);
        with_cookie(render_error("Invalid or expired OAuth state. Please try again.".into()), security::clear_oauth_state_cookie(secure))
    };

    // 1. The state must have the shape we issue, and must be the one in THIS browser's cookie
    //    (otherwise any valid state, e.g. the attacker's own, would sign a victim in as the attacker).
    if !security::valid_access_token(&params.state) {
        return bad_state("state has the wrong shape");
    }
    let cookie_matches = security::cookie_values(&headers, security::OAUTH_STATE_COOKIE)
        .into_iter()
        .fold(false, |acc, c| acc | security::ct_eq_str(c.as_bytes(), params.state.as_bytes()));
    if !cookie_matches {
        return bad_state("no matching oauth_state cookie");
    }
    // 2. ... and it must still be live in Redis; it is consumed here, so it works once.
    if !state.validate_csrf_token(&params.state).await {
        return bad_state("state unknown or already used");
    }

    // Exchange code for token
    let token_result = state.oauth_client.exchange_code(AuthorizationCode::new(params.code)).request_async(async_http_client).await;
    let token = match token_result {
        Ok(t) => t,
        Err(e) => {
            error!("OAuth token exchange failed: {}", e);
            return with_cookie(render_error("Authentication failed. Please try again.".into()), security::clear_oauth_state_cookie(secure));
        }
    };

    // Get Discord user info
    let user_response = state.http_client.get("https://discord.com/api/users/@me").bearer_auth(token.access_token().secret()).send().await;
    let discord_user: DiscordUser = match user_response {
        Ok(r) => match r.json().await {
            Ok(u) => u,
            Err(_) => return render_error("Failed to get user info".into()),
        },
        Err(_) => return render_error("Failed to contact Discord".into()),
    };
    if !security::valid_discord_id(&discord_user.id) {
        error!("Discord returned an id that is not a snowflake");
        return render_error("Failed to get user info".into());
    }

    let stored_ip = security::ip_for_storage(client_ip);
    let access_token = generate_token(32);
    let username = match db::find_or_create_discord_user(&state.pool, &discord_user.id, &discord_user.username, &access_token, stored_ip.as_deref()).await {
        Ok((u, created)) => {
            if created {
                info!(event = "discord_user_registered", username = %u, discord_id = %discord_user.id);
                state.metrics.registrations.fetch_add(1, Ordering::Relaxed);
            }
            u
        }
        Err(db::DiscordUserError::Exhausted) => return render_error("Unable to create unique username".into()),
        Err(db::DiscordUserError::Db(e)) => {
            error!("Failed to create Discord user: {}", e);
            return render_error("Registration failed".into());
        }
    };

    db::update_user_ip(&state.pool, &username, stored_ip.as_deref()).await;
    with_cookie(start_session(&state, &username, &ip).await, security::clear_oauth_state_cookie(secure))
}

// ============================================================================
// STRIPE CHECKOUT
// ============================================================================
async fn create_checkout(State(state): State<Arc<AppState>>, headers: HeaderMap, Form(form): Form<CheckoutForm>) -> Response {
    let amount_dollars = form.amount.unwrap_or(5.0);
    // NaN compares false with everything, so a range test written as "below min or above max" lets it through.
    if !amount_dollars.is_finite() || !(2.50..=100.0).contains(&amount_dollars) {
        return render_error("Amount must be between $2.50 and $100".into());
    }
    let amount_cents = (amount_dollars * 100.0).round() as u64;
    if gate::admitte_summam(amount_cents).is_err() {
        return render_error("Amount must be between $2.50 and $100".into());
    }

    let username = match session_username(&state, &headers).await {
        Some(u) => u,
        None => return render_error("Please log in first".into()),
    };
    // The row id, not the access token, goes to Stripe: the token is a secret and Stripe keeps metadata.
    let user_id = match db::get_user_id(&state.pool, &username).await {
        Some(id) => id,
        None => return render_error("User not found".into()),
    };

    let gb_amount = amount_dollars / 0.05;
    let product_name = format!("DCF Credits - {:.0}GB", gb_amount);
    let amount_str = amount_cents.to_string();
    let user_id_str = user_id.to_string();

    let checkout = state
        .http_client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .header("Authorization", format!("Bearer {}", state.stripe_secret))
        .form(&[
            ("payment_method_types[]", "card"),
            ("line_items[0][price_data][currency]", "usd"),
            ("line_items[0][price_data][product_data][name]", &product_name),
            ("line_items[0][price_data][unit_amount]", &amount_str),
            ("line_items[0][quantity]", "1"),
            ("mode", "payment"),
            ("success_url", &format!("{}/", state.base_url)),
            ("cancel_url", &format!("{}/", state.base_url)),
            ("metadata[user_id]", &user_id_str),
            ("metadata[amount_dollars]", &format!("{:.2}", amount_dollars)),
        ])
        .send()
        .await;

    match checkout {
        Ok(r) => {
            if let Ok(json) = r.json::<serde_json::Value>().await {
                if let Some(url) = json.get("url").and_then(|u| u.as_str()) {
                    return Redirect::to(url).into_response();
                }
            }
            render_error("Failed to create checkout".into())
        }
        Err(e) => {
            error!("Stripe checkout failed: {}", e);
            render_error("Payment service unavailable".into())
        }
    }
}

// ============================================================================
// SHUTDOWN
// ============================================================================
async fn shutdown_signal(shutdown: Arc<AtomicBool>) {
    #[cfg(unix)]
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).expect("failed to install SIGTERM handler");

    #[cfg(unix)]
    let terminate = async move {
        sigterm.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        result = signal::ctrl_c() => {
            if let Err(e) = result {
                error!("Failed to listen for Ctrl+C: {}", e);
            }
        },
        _ = terminate => {},
    }

    info!("Shutdown signal received");
    shutdown.store(true, Ordering::Relaxed);
}

// ============================================================================
// MAIN
// ============================================================================
#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "dcf_id=info,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!("DeMoD Identity Service v{} starting...", VERSION);

    dotenvy::dotenv().ok();

    // Config that must be right before anything listens
    let internal_key = env::var("DCF_ID_INTERNAL_KEY").ok();
    let allow_open = env::var("DCF_ID_ALLOW_OPEN_API").map(|v| v == "1").unwrap_or(false);
    let api_auth = match ApiAuth::from_config(internal_key.as_deref(), allow_open) {
        Ok(a) => a,
        Err(e) => {
            error!("{}", e);
            std::process::exit(1);
        }
    };
    if api_auth.is_open() {
        error!(
            "DCF_ID_ALLOW_OPEN_API=1 and no DCF_ID_INTERNAL_KEY: /api/user/discord/:id (returns access tokens), \
             /api/usage/report (moves balances), /api/stats and /metrics are OPEN TO EVERYONE who can reach this port"
        );
    }
    let trusted_proxies = match TrustedProxies::parse(&env::var("TRUSTED_PROXIES").unwrap_or_default()) {
        Ok(t) => t,
        Err(e) => {
            error!("TRUSTED_PROXIES: {}", e);
            std::process::exit(1);
        }
    };
    if trusted_proxies.is_empty() {
        info!("TRUSTED_PROXIES is empty: X-Forwarded-For is ignored and the socket peer is the client address");
    }
    let stripe_secret = env::var("STRIPE_SECRET_KEY").expect("STRIPE_SECRET_KEY missing");
    let stripe_webhook_secret = env::var("STRIPE_WEBHOOK_SECRET").expect("STRIPE_WEBHOOK_SECRET missing");
    if stripe_webhook_secret.is_empty() {
        error!("STRIPE_WEBHOOK_SECRET is empty: an empty HMAC key is a key anyone has; refusing to start");
        std::process::exit(1);
    }
    let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:4000".into());
    let port: u16 = env::var("IDENTITY_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(4000);

    // Database
    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:/data/identity.db?mode=rwc".into());
    let pool = SqlitePoolOptions::new().max_connections(10).connect(&db_url).await.expect("Failed to connect to DB");
    let report = db::init(&pool).await.expect("Users table migration failed");
    info!(username_nocase_unique = report.username_nocase_unique, "database ready");

    // Redis
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let redis = redis::Client::open(redis_url.as_str()).expect("Invalid Redis URL");

    // Test Redis connection
    match redis.get_multiplexed_async_connection().await {
        Ok(mut conn) => {
            let pong: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
            if pong.is_ok() {
                info!("Redis connected"); // the URL is not logged: it can carry a password
            } else {
                warn!("Redis PING failed, sessions may not persist");
            }
        }
        Err(e) => {
            warn!("Redis connection failed: {} - degraded mode: sessions do not persist, throttles are per-process", e);
        }
    }

    // OAuth
    let oauth_client = BasicClient::new(
        ClientId::new(env::var("DISCORD_CLIENT_ID").expect("DISCORD_CLIENT_ID missing")),
        Some(ClientSecret::new(env::var("DISCORD_CLIENT_SECRET").expect("DISCORD_CLIENT_SECRET missing"))),
        AuthUrl::new("https://discord.com/api/oauth2/authorize".into()).unwrap(),
        Some(TokenUrl::new("https://discord.com/api/oauth2/token".into()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(env::var("DISCORD_REDIRECT_URL").unwrap_or_else(|_| format!("{}/auth/callback", base_url))).unwrap());

    let shutdown = Arc::new(AtomicBool::new(false));

    // One Argon2 at a time per CPU (each holds ~19 MiB and a core); more wait, briefly, then get a 503.
    let hash_slots = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).max(1);
    info!(argon2_slots = hash_slots, "password hashing is bounded to one operation per CPU");

    let state = Arc::new(AppState {
        pool,
        redis,
        oauth_client,
        http_client: HttpClient::builder().timeout(Duration::from_secs(30)).build().unwrap(),
        stripe_secret,
        stripe_webhook_secret,
        base_url,
        api_auth,
        trusted_proxies,
        local_limiter: LocalLimiter::new(LOCAL_LIMITER_KEYS),
        hash_permits: Arc::new(Semaphore::new(hash_slots)),
        hash_wait: HASH_QUEUE_WAIT,
        metrics: Arc::new(Metrics::default()),
        shutdown: shutdown.clone(),
    });

    let html_routes = Router::new()
        // Core routes
        .route("/", get(index))
        // Auth routes
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/discord", get(discord_auth))
        .route("/auth/callback", get(discord_callback))
        // Billing routes
        .route("/checkout", post(create_checkout));

    // health, metrics, the Stripe webhook and the GSN integration API come from the library
    let app = api::finish(html_routes.merge(api::routes()), state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    info!("Listening on port {}", port);

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal(shutdown))
        .await
        .unwrap();

    info!("Shutdown complete");
}
