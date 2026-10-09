// The throttles, sessions and OAuth state: once with Redis unreachable (the in-process limiter
// answers), and -- when a redis-server binary exists on this machine -- once against a real one.
use super::*;
use crate::api::tests::test_state;
use crate::db::testutil::temp_db;
use crate::security::ApiAuth;

pub(crate) fn state_without_redis(db: &crate::db::testutil::TempDb) -> Arc<AppState> {
    test_state(db.pool.clone(), ApiAuth::Open, "http://localhost:4000")
}

pub(crate) struct RedisServer {
    child: std::process::Child,
    pub(crate) port: u16,
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
pub(crate) fn redis_server() -> Option<RedisServer> {
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

pub(crate) async fn state_with_redis(db: &crate::db::testutil::TempDb, port: u16) -> Arc<AppState> {
    let arc = state_without_redis(db);
    let mut st = Arc::try_unwrap(arc).ok().expect("sole owner");
    st.redis = redis::Client::open(format!("redis://127.0.0.1:{port}")).unwrap();
    Arc::new(st)
}

fn admitted(r: &SlotResult) -> bool {
    matches!(r, SlotResult::Admitted(_))
}

/// N concurrent takes released together; how many were admitted, and the slots they hold.
async fn concurrent_takes(st: &Arc<AppState>, n: usize, who: impl Fn(usize) -> (String, String)) -> (usize, Vec<LoginSlots>) {
    let bar = Arc::new(tokio::sync::Barrier::new(n));
    let mut hs = vec![];
    for i in 0..n {
        let (st, bar) = (st.clone(), bar.clone());
        let (ip, user) = who(i);
        hs.push(tokio::spawn(async move {
            bar.wait().await;
            st.take_login_slots(&ip, &user).await
        }));
    }
    let mut held = vec![];
    let mut locked = 0;
    for h in hs {
        match h.await.unwrap() {
            SlotResult::Admitted(s) => held.push(s),
            SlotResult::Locked(ttl) => {
                assert!((1..=LOCKOUT_DURATION_SECS).contains(&ttl), "ttl {ttl}");
                locked += 1;
            }
        }
    }
    assert_eq!(held.len() + locked, n);
    (held.len(), held)
}

async fn exercise_throttles(st: &Arc<AppState>) {
    let victim = user_throttle_key("Victim");

    // ---- one at a time: five, then locked, with the time left
    let mut held = vec![];
    for i in 0..MAX_LOGIN_ATTEMPTS {
        match st.take_login_slots("1.1.1.1", &victim).await {
            SlotResult::Admitted(s) => held.push(s),
            SlotResult::Locked(_) => panic!("attempt {i} was turned away"),
        }
    }
    match st.take_login_slots("1.1.1.1", &victim).await {
        SlotResult::Locked(ttl) => assert!((800..=LOCKOUT_DURATION_SECS).contains(&ttl), "ttl {ttl}"),
        SlotResult::Admitted(_) => panic!("the sixth attempt was admitted"),
    }
    assert!(admitted(&st.take_login_slots("2.2.2.2", &user_throttle_key("someone-else")).await), "other address, other name");

    // ---- a burst of 100 from one address naming one user: exactly 5 get through, however they interleave
    let (n, held) = concurrent_takes(st, 100, |_| ("3.3.3.3".into(), user_throttle_key("burst"))).await;
    assert_eq!(n, MAX_LOGIN_ATTEMPTS as usize, "100 concurrent attempts from one address");
    // the 95 turned away were NOT counted: give the 5 held slots back and the address has all five again
    // (a counter that kept the turned-away attempts would sit at 95 here and refuse everything until it expired)
    for s in held {
        st.release_login_slots(s).await;
    }
    let (n, held) = concurrent_takes(st, 20, |_| ("3.3.3.3".into(), user_throttle_key("burst2"))).await;
    assert_eq!(n, MAX_LOGIN_ATTEMPTS as usize, "turned-away attempts inflated the counter");
    for s in held {
        st.release_login_slots(s).await;
    }
    // re-take under the original name for the next step
    let (n, _) = concurrent_takes(st, 100, |_| ("3.3.3.4".into(), user_throttle_key("burst"))).await;
    assert_eq!(n, MAX_LOGIN_ATTEMPTS as usize);
    // ... and the 95 that were turned away did not touch the username's counter: 15 more fit from other addresses
    let (n, _) = concurrent_takes(st, 40, |i| (format!("4.4.4.{i}"), user_throttle_key("burst"))).await;
    assert_eq!(n, (MAX_USER_LOGIN_ATTEMPTS - MAX_LOGIN_ATTEMPTS) as usize, "the rest of the username's budget");

    // ---- a burst of 100 addresses naming one user: exactly 20 get through; the turned-away ones got their address slot back
    let target = user_throttle_key("target");
    let (n, _) = concurrent_takes(st, 100, |i| (format!("5.5.{}.{}", i / 50, i % 50), target.clone())).await;
    assert_eq!(n, MAX_USER_LOGIN_ATTEMPTS as usize, "100 concurrent attempts from 100 addresses at one username");
    // the 20 that got through spent one address slot each; the 80 turned away got theirs back, so they have all five
    let mut with_all_five = 0;
    for i in 0..100 {
        let mut k = 0;
        for j in 0..MAX_LOGIN_ATTEMPTS {
            if admitted(&st.take_login_slots(&format!("5.5.{}.{}", i / 50, i % 50), &user_throttle_key(&format!("other{i}-{j}"))).await) {
                k += 1;
            }
        }
        if k == MAX_LOGIN_ATTEMPTS {
            with_all_five += 1;
        }
    }
    assert_eq!(with_all_five, 80, "an address turned away because of the USERNAME must keep its slot");

    // ---- a locked address cannot burn someone else's budget
    for i in 0..MAX_LOGIN_ATTEMPTS {
        assert!(admitted(&st.take_login_slots("6.6.6.6", &user_throttle_key(&format!("filler{i}"))).await));
    }
    let owner = user_throttle_key("owner");
    for _ in 0..50 {
        assert!(!admitted(&st.take_login_slots("6.6.6.6", &owner).await));
    }
    let (n, _) = concurrent_takes(st, 30, |i| (format!("7.7.7.{i}"), owner.clone())).await;
    assert_eq!(n, MAX_USER_LOGIN_ATTEMPTS as usize, "the owner's username still has its whole budget");

    // ---- a success clears the address's count and the username's count; release refunds both
    let name = user_throttle_key("careful");
    let mut slots = vec![];
    for _ in 0..MAX_LOGIN_ATTEMPTS {
        match st.take_login_slots("8.8.8.8", &name).await {
            SlotResult::Admitted(s) => slots.push(s),
            SlotResult::Locked(_) => panic!("turned away"),
        }
    }
    assert!(!admitted(&st.take_login_slots("8.8.8.8", &name).await));
    st.login_succeeded(slots.pop().unwrap()).await;
    let (n, _) = concurrent_takes(st, 10, |_| ("8.8.8.8".into(), name.clone())).await;
    assert_eq!(n, MAX_LOGIN_ATTEMPTS as usize, "the address starts again from zero");
    // the username's count was cleared too: 20 fresh attempts fit from other addresses (5 are spent above)
    let (n, _) = concurrent_takes(st, 25, |i| (format!("9.9.9.{i}"), name.clone())).await;
    assert_eq!(n, (MAX_USER_LOGIN_ATTEMPTS - MAX_LOGIN_ATTEMPTS) as usize, "cleared, then filled again");
    let rel = user_throttle_key("release");
    let mut slots = vec![];
    for _ in 0..MAX_LOGIN_ATTEMPTS {
        if let SlotResult::Admitted(s) = st.take_login_slots("10.0.0.1", &rel).await {
            slots.push(s);
        }
    }
    assert_eq!(slots.len(), MAX_LOGIN_ATTEMPTS as usize);
    for s in slots {
        st.release_login_slots(s).await;
    }
    let (n, _) = concurrent_takes(st, 10, |_| ("10.0.0.1".into(), rel.clone())).await;
    assert_eq!(n, MAX_LOGIN_ATTEMPTS as usize, "released slots are free again");

    // ---- registrations: 10 an hour per address
    for i in 0..MAX_REGISTRATIONS_PER_HOUR {
        assert!(st.register_allowed("11.1.1.1").await, "attempt {i}");
    }
    assert!(!st.register_allowed("11.1.1.1").await);
    assert!(st.register_allowed("11.1.1.2").await);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn throttles_work_without_redis_using_the_in_process_limiter() {
    let db = temp_db().await;
    let st = state_without_redis(&db);
    exercise_throttles(&st).await;
    assert!(st.metrics.redis_errors.load(Ordering::Relaxed) > 0, "the Redis failures were counted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn throttles_work_against_a_real_redis() {
    let Some(srv) = redis_server() else { return };
    let db = temp_db().await;
    let st = state_with_redis(&db, srv.port).await;
    exercise_throttles(&st).await;
    assert_eq!(st.metrics.redis_errors.load(Ordering::Relaxed), 0, "Redis answered everything; the fallback was not used");
    assert!(st.local_limiter.is_empty(), "nothing leaked into the in-process limiter");

    // a counter that lost its expiry (a crash between INCR and EXPIRE, in a script-less implementation) is repaired
    let client = redis::Client::open(format!("redis://127.0.0.1:{}", srv.port)).unwrap();
    let mut raw = client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis::cmd("SET").arg("ratelimit:12.1.1.1").arg(3).query_async(&mut raw).await.unwrap();
    assert!(admitted(&st.take_login_slots("12.1.1.1", &user_throttle_key("ttl-repair")).await));
    let ttl: i64 = redis::cmd("TTL").arg("ratelimit:12.1.1.1").query_async(&mut raw).await.unwrap();
    assert!((1..=LOCKOUT_DURATION_SECS).contains(&ttl), "ttl {ttl}: the counter must expire");
    // the lockout window restarts at the last permitted attempt (the 5th), as in the old code
    for _ in 0..4 {
        st.take_login_slots("12.1.1.2", &user_throttle_key("window")).await;
    }
    let ttl: i64 = redis::cmd("TTL").arg("ratelimit:12.1.1.2").query_async(&mut raw).await.unwrap();
    assert!(ttl > LOCKOUT_DURATION_SECS - 5, "ttl {ttl}");
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
