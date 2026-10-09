// The throttles, sessions and OAuth state: once with Redis unreachable (the in-process limiter
// answers), and -- when a redis-server binary exists on this machine -- once against a real one.
use super::*;
use crate::api::tests::test_state;
use crate::db::testutil::temp_db;
use crate::security::ApiAuth;

fn state_without_redis(db: &crate::db::testutil::TempDb) -> Arc<AppState> {
    test_state(db.pool.clone(), ApiAuth::Open, "http://localhost:4000")
}

struct RedisServer {
    child: std::process::Child,
    port: u16,
    dir: std::path::PathBuf,
}

impl Drop for RedisServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A throwaway redis-server, or None (and a note on stderr) if there is no binary: those tests then
/// do not run, and the summary line says so, rather than passing for something they did not check.
fn redis_server() -> Option<RedisServer> {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        l.local_addr().ok()?.port()
    };
    let dir = std::env::temp_dir().join(format!("dcfid-redis-{}-{}", std::process::id(), port));
    std::fs::create_dir_all(&dir).ok()?;
    let child = std::process::Command::new("redis-server")
        .args(["--port", &port.to_string(), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir"])
        .arg(&dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| eprintln!("NOTE: redis-server not runnable ({e}); the Redis-backed tests are SKIPPED"))
        .ok()?;
    let srv = RedisServer { child, port, dir };
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(srv);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

async fn state_with_redis(db: &crate::db::testutil::TempDb, port: u16) -> AppState {
    let arc = state_without_redis(db);
    let mut st = Arc::try_unwrap(arc).ok().expect("sole owner");
    st.redis = redis::Client::open(format!("redis://127.0.0.1:{port}")).unwrap();
    st
}

async fn exercise_throttles(st: &AppState) {
    let ukey = user_throttle_key("Victim");
    assert_eq!(st.login_lockout("1.1.1.1", &ukey).await, None);
    // five failures from one address lock that address, not the username
    for i in 0..5 {
        assert_eq!(st.login_lockout("1.1.1.1", &ukey).await, None, "before failure {i}");
        st.record_login_failure("1.1.1.1", &ukey).await;
    }
    let ttl = st.login_lockout("1.1.1.1", &ukey).await.expect("locked after 5");
    assert!((1..=LOCKOUT_DURATION_SECS).contains(&ttl), "ttl {ttl}");
    assert_eq!(st.login_lockout("2.2.2.2", &user_throttle_key("someone-else")).await, None, "other address, other name");
    // the lockout is per name too: 19 more failures from 19 different addresses stay under 20 ...
    for i in 0..14 {
        st.record_login_failure(&format!("9.9.9.{i}"), &ukey).await;
    }
    assert_eq!(st.login_lockout("8.8.8.8", &ukey).await, None, "19 failures against the name");
    // ... the 20th locks the NAME, wherever it comes from
    st.record_login_failure("8.8.4.4", &ukey).await;
    assert!(st.login_lockout("7.7.7.7", &ukey).await.is_some());
    assert!(st.login_lockout("7.7.7.7", &user_throttle_key("victim")).await.is_some(), "case-insensitive");
    // a successful login clears the count: three failures, a success, three failures is not six
    let other = user_throttle_key("careful");
    for _ in 0..3 {
        st.record_login_failure("3.3.3.3", &other).await;
    }
    st.clear_login_failures("3.3.3.3", &other).await;
    for _ in 0..3 {
        st.record_login_failure("3.3.3.3", &other).await;
    }
    assert_eq!(st.login_lockout("3.3.3.3", &other).await, None);

    // registrations: 10 an hour per address
    for i in 0..MAX_REGISTRATIONS_PER_HOUR {
        assert!(st.register_allowed("5.5.5.5").await, "attempt {i}");
    }
    assert!(!st.register_allowed("5.5.5.5").await);
    assert!(st.register_allowed("5.5.5.6").await);
}

#[test]
fn throttle_keys_are_fixed_size_and_case_folded() {
    assert_eq!(user_throttle_key("Alice"), user_throttle_key("aLICE"));
    assert_ne!(user_throttle_key("alice"), user_throttle_key("alice2"));
    for name in ["", "x", "\u{430}dmin", &"y".repeat(100_000), "a\r\nSET evil 1"] {
        let k = user_throttle_key(name);
        assert!(k.len() == 5 + 32 && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':'), "{k}");
    }
}

#[tokio::test]
async fn throttles_work_without_redis_using_the_in_process_limiter() {
    let db = temp_db().await;
    let st = state_without_redis(&db);
    exercise_throttles(&st).await;
    assert!(st.metrics.redis_errors.load(Ordering::Relaxed) > 0, "the Redis failures were counted");
}

#[tokio::test]
async fn throttles_work_against_a_real_redis() {
    let Some(srv) = redis_server() else { return };
    let db = temp_db().await;
    let st = state_with_redis(&db, srv.port).await;
    exercise_throttles(&st).await;
    assert_eq!(st.metrics.redis_errors.load(Ordering::Relaxed), 0, "Redis answered everything; the fallback was not used");
    assert!(st.local_limiter.is_empty(), "nothing leaked into the in-process limiter");
}

#[tokio::test]
async fn sessions_need_a_gate_clean_id_and_oauth_state_is_single_use() {
    let Some(srv) = redis_server() else { return };
    let db = temp_db().await;
    let st = state_with_redis(&db, srv.port).await;
    let sess = SessionData { username: "alice".into(), expires_at: Utc::now().timestamp() + 60, created_ip: "1.2.3.4".into(), created_at: "x".into() };
    let id = "a".repeat(64);
    st.save_session(&id, &sess).await.unwrap();
    assert_eq!(st.get_session(&id).await.unwrap().username, "alice");
    // ids that are not 64 ASCII alphanumerics are neither stored nor looked up
    for bad in ["short".to_string(), "a".repeat(65), format!("{}*", "a".repeat(63)), "session:other".to_string(), String::new()] {
        assert!(st.save_session(&bad, &sess).await.is_err(), "{bad:?}");
        assert!(st.get_session(&bad).await.is_none(), "{bad:?}");
    }
    st.delete_session(&id).await;
    assert!(st.get_session(&id).await.is_none());

    // The gate is applied BEFORE Redis is asked: plant keys under shapes the service never issues and show
    // they cannot be reached (an id that merely "happens to" be unknown would pass without the gate).
    let planted = serde_json::to_string(&sess).unwrap();
    let client = redis::Client::open(format!("redis://127.0.0.1:{}", srv.port)).unwrap();
    let mut raw = client.get_multiplexed_async_connection().await.unwrap();
    for (key, shape) in [("session:short", "short"), ("session:sess-with-dash", "sess-with-dash")] {
        let _: () = redis::cmd("SET").arg(key).arg(&planted).query_async(&mut raw).await.unwrap();
        assert!(st.get_session(shape).await.is_none(), "{shape}");
    }
    let _: () = redis::cmd("SET").arg("csrf:short").arg("1").query_async(&mut raw).await.unwrap();
    assert!(!st.validate_csrf_token("short").await);
    let still: Option<String> = redis::cmd("GET").arg("csrf:short").query_async(&mut raw).await.unwrap();
    assert_eq!(still.as_deref(), Some("1"), "a refused state is not even looked up, let alone consumed");

    let state_token = "Z".repeat(32);
    st.save_csrf_token(&state_token).await.unwrap();
    assert!(st.validate_csrf_token(&state_token).await);
    assert!(!st.validate_csrf_token(&state_token).await, "consumed by the first use");
    for bad in ["short".to_string(), "Z".repeat(64), "*".repeat(32), String::new()] {
        assert!(st.save_csrf_token(&bad).await.is_err());
        assert!(!st.validate_csrf_token(&bad).await);
    }
}

#[tokio::test]
async fn a_wildcard_in_a_cookie_cannot_reach_redis() {
    let Some(srv) = redis_server() else { return };
    let db = temp_db().await;
    let st = state_with_redis(&db, srv.port).await;
    let sess = SessionData { username: "alice".into(), expires_at: Utc::now().timestamp() + 60, created_ip: "x".into(), created_at: "x".into() };
    st.save_session(&"a".repeat(64), &sess).await.unwrap();
    // 64 characters that would glob-match the key above, were the value ever used in a pattern
    assert!(st.get_session(&format!("{}[a-z]", "a".repeat(62))).await.is_none());
    assert!(st.get_session(&"?".repeat(64)).await.is_none());
}
