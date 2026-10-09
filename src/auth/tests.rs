// The login decision under concurrency, with real Argon2 and a real (temp-file) database. "Evaluated"
// is counted by the server's own `argon2_runs` metric, not inferred from responses.
use super::*;
use crate::api::tests::test_state;
use crate::db::testutil::{temp_db, TempDb};
use crate::security::ApiAuth;
use crate::state::tests::{redis_server, state_with_redis, state_without_redis};
use crate::state::{MAX_LOGIN_ATTEMPTS, MAX_USER_LOGIN_ATTEMPTS};
use std::time::Duration;

const PW: &str = "correct-horse-1";
const TOK: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";

fn hash(pw: &str) -> String {
    Argon2::default().hash_password(pw.as_bytes(), &SaltString::generate(&mut OsRng)).unwrap().to_string()
}

async fn world() -> (TempDb, Arc<AppState>) {
    let db = temp_db().await;
    db::register_user(&db.pool, "victim1", &hash(PW), TOK, None).await.unwrap();
    let st = state_without_redis(&db);
    (db, st)
}

fn runs(st: &AppState) -> u64 {
    st.metrics.argon2_runs.load(Ordering::Relaxed)
}

#[derive(Default, Debug)]
struct Tally {
    success: usize,
    bad: usize,
    locked: usize,
    busy: usize,
}

/// n concurrent logins released together; `who(i)` -> (ip, username, password).
async fn burst(st: &Arc<AppState>, n: usize, who: impl Fn(usize) -> (String, String, String)) -> Tally {
    let bar = Arc::new(tokio::sync::Barrier::new(n));
    let mut hs = vec![];
    for i in 0..n {
        let (st, bar) = (st.clone(), bar.clone());
        let (ip, user, pw) = who(i);
        hs.push(tokio::spawn(async move {
            bar.wait().await;
            attempt_login(&st, &ip, &user, &pw).await
        }));
    }
    let mut t = Tally::default();
    for h in hs {
        match h.await.unwrap() {
            LoginOutcome::Success => t.success += 1,
            LoginOutcome::BadCredentials => t.bad += 1,
            LoginOutcome::Locked(_) => t.locked += 1,
            LoginOutcome::Busy => t.busy += 1,
        }
    }
    t
}

fn same_ip(user: &'static str, pw: impl Fn(usize) -> String + 'static) -> impl Fn(usize) -> (String, String, String) {
    move |i| ("203.0.113.9".to_string(), user.to_string(), pw(i))
}

// ---- NEW-1: a burst cannot buy more than `limit` verifications ---------------------------------------------
async fn wrong_burst_is_capped(st: Arc<AppState>) {
    for n in [30usize, 100] {
        let before = runs(&st);
        // a fresh address per round so the previous round's lockout is not what is being measured
        let t = burst(&st, n, move |i| (format!("198.51.100.{n}"), "victim1".into(), format!("wrong-guess-{i}"))).await;
        assert_eq!(runs(&st) - before, MAX_LOGIN_ATTEMPTS, "n={n}: Argon2 runs ({t:?})");
        assert_eq!((t.bad, t.locked, t.success, t.busy), (MAX_LOGIN_ATTEMPTS as usize, n - 5, 0, 0), "n={n}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_wrong_logins_runs_at_most_the_limit_of_verifications_without_redis() {
    let (_db, st) = world().await;
    wrong_burst_is_capped(st).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_wrong_logins_runs_at_most_the_limit_of_verifications_with_redis() {
    let Some(srv) = redis_server() else { return };
    let db = temp_db().await;
    db::register_user(&db.pool, "victim1", &hash(PW), TOK, None).await.unwrap();
    let st = state_with_redis(&db, srv.port).await;
    wrong_burst_is_capped(st.clone()).await;
    assert_eq!(st.metrics.redis_errors.load(Ordering::Relaxed), 0);
    assert!(st.local_limiter.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_dummy_hash_path_for_unknown_users_is_capped_too() {
    let (_db, st) = world().await;
    let t = burst(&st, 30, |i| ("203.0.113.9".into(), format!("nosuchuser{i}"), format!("guess-{i}-xxxx"))).await;
    assert_eq!(runs(&st), MAX_LOGIN_ATTEMPTS);
    assert_eq!((t.bad, t.locked), (5, 25), "{t:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_addresses_against_one_username_are_capped_by_the_username() {
    let (_db, st) = world().await;
    let t = burst(&st, 100, |i| (format!("203.0.{}.{}", i / 50, i % 50), "victim1".into(), format!("wrong-{i}"))).await;
    assert_eq!(runs(&st), MAX_USER_LOGIN_ATTEMPTS, "{t:?}");
    assert_eq!((t.bad, t.locked), (20, 80));
    // what the per-username limit means for the owner: a 21st attempt from a new address is refused even with the
    // right password, until the window ends
    let right = attempt_login(&st, "192.0.2.77", "victim1", PW).await;
    assert!(matches!(right, LoginOutcome::Locked(ttl) if ttl > 800), "{right:?}");
}

// ---- no false positives for the legitimate user -------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_correct_logins_up_to_the_limit_all_succeed_and_leave_nothing_behind() {
    let (_db, st) = world().await;
    let t = burst(&st, MAX_LOGIN_ATTEMPTS as usize, same_ip("victim1", |_| PW.into())).await;
    assert_eq!((t.success, t.locked, t.bad), (5, 0, 0), "{t:?}");
    // every slot came back: the address and the username start from zero again
    assert_eq!(st.local_limiter.held("lock:203.0.113.9"), 0);
    assert_eq!(st.local_limiter.held(&format!("lock:{}", user_throttle_key("victim1"))), 0);
    // so a full set of wrong guesses still gets its 5, and the right password works until the 5th wrong one
    let t = burst(&st, 20, same_ip("victim1", |i| format!("wrong-{i}"))).await;
    assert_eq!((t.bad, t.locked), (5, 15));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_correct_logins_beyond_the_limit_does_not_leave_the_owner_locked() {
    let (_db, st) = world().await;
    let t = burst(&st, 30, same_ip("victim1", |_| PW.into())).await;
    assert_eq!(t.success + t.locked, 30, "{t:?}");
    assert!(t.success >= 5, "{t:?}");
    // the turned-away attempts were not counted: the owner is not locked out afterwards
    assert_eq!(attempt_login(&st, "203.0.113.9", "victim1", PW).await, LoginOutcome::Success);
    assert_eq!(st.local_limiter.held("lock:203.0.113.9"), 0);
}

#[tokio::test]
async fn sequential_semantics_are_those_of_the_old_failure_counter() {
    let (_db, st) = world().await;
    let ip = "203.0.113.50";
    for i in 0..4 {
        assert_eq!(attempt_login(&st, ip, "victim1", &format!("wrong-{i}")).await, LoginOutcome::BadCredentials);
    }
    // the right password on the 5th attempt still works, and clears the username's count
    assert_eq!(attempt_login(&st, ip, "victim1", PW).await, LoginOutcome::Success);
    for i in 0..4 {
        assert_eq!(attempt_login(&st, ip, "victim1", &format!("wrong-{i}")).await, LoginOutcome::BadCredentials);
    }
    // the success cleared the count: four more wrong guesses and one more make five, and then even the right
    // password is refused
    assert_eq!(attempt_login(&st, ip, "victim1", "wrong-last").await, LoginOutcome::BadCredentials);
    assert!(matches!(attempt_login(&st, ip, "victim1", PW).await, LoginOutcome::Locked(_)));
    // another address is not affected by that one's lockout
    assert_eq!(attempt_login(&st, "203.0.113.51", "victim1", PW).await, LoginOutcome::Success);
}

#[tokio::test]
async fn a_success_clears_the_address_but_not_the_username_of_someone_else() {
    // What interleaving successes on one's OWN account buys: more guesses per ADDRESS window (a success clears
    // the address's count, as before, so shared addresses stay usable) -- but never more than the USERNAME limit
    // at any one victim, which a success on another username does not clear.
    let (_db, st) = world().await;
    db::register_user(&st.pool, "attacker1", &hash("attackers-pw-1"), "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", None).await.unwrap();
    let ip = "203.0.113.60";
    let mut guesses = 0;
    for round in 0..40 {
        assert_eq!(attempt_login(&st, ip, "attacker1", "attackers-pw-1").await, LoginOutcome::Success, "round {round}");
        match attempt_login(&st, ip, "victim1", &format!("guess-{round}")).await {
            LoginOutcome::BadCredentials => guesses += 1,
            LoginOutcome::Locked(_) => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(guesses, MAX_USER_LOGIN_ATTEMPTS as usize, "the victim's username caps the guesses");
}

// ---- the other limits ---------------------------------------------------------------------------------------
#[tokio::test]
async fn oversized_input_is_refused_without_hashing_and_the_slot_stays_spent() {
    let (_db, st) = world().await;
    let ip = "203.0.113.70";
    assert_eq!(attempt_login(&st, ip, "victim1", &"p".repeat(257)).await, LoginOutcome::BadCredentials);
    assert_eq!(attempt_login(&st, ip, &"u".repeat(129), "whatever-12").await, LoginOutcome::BadCredentials);
    assert_eq!(runs(&st), 0);
    assert_eq!(st.local_limiter.held(&format!("lock:{ip}")), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn when_no_argon2_slot_comes_free_the_answer_is_busy_and_the_attempt_does_not_count() {
    let db = temp_db().await;
    db::register_user(&db.pool, "victim1", &hash(PW), TOK, None).await.unwrap();
    let mut st = Arc::try_unwrap(test_state(db.pool.clone(), ApiAuth::Open, "http://localhost:4000")).ok().unwrap();
    st.hash_permits = Arc::new(tokio::sync::Semaphore::new(1));
    st.hash_wait = Duration::from_millis(1);
    let st = Arc::new(st);

    // hold the only permit: every login is busy, and none of them is counted
    let held = st.hash_permits.clone().acquire_owned().await.unwrap();
    for i in 0..10 {
        assert_eq!(attempt_login(&st, "203.0.113.80", "victim1", PW).await, LoginOutcome::Busy, "attempt {i}");
    }
    assert_eq!(st.local_limiter.held("lock:203.0.113.80"), 0, "busy attempts gave their slots back");
    assert_eq!(st.local_limiter.held(&format!("lock:{}", user_throttle_key("victim1"))), 0);
    assert_eq!(runs(&st), 0);
    assert_eq!(st.metrics.argon2_busy.load(Ordering::Relaxed), 10);
    assert_eq!(hash_password(&st, "a-new-password").await, Err(HashError::Busy));
    drop(held);
    // and then it works
    assert_eq!(attempt_login(&st, "203.0.113.80", "victim1", PW).await, LoginOutcome::Success);
    assert!(hash_password(&st, "a-new-password").await.unwrap().starts_with("$argon2"));

    // under real contention with one permit, some are busy, none is lost: every outcome is accounted for
    let t = burst(&st, 8, |i| (format!("203.0.113.{}", 100 + i), "victim1".into(), format!("wrong-{i}"))).await;
    assert_eq!(t.success + t.bad + t.locked + t.busy, 8);
    assert!(t.busy >= 1, "{t:?}");
    assert_eq!(runs(&st) - 2, (t.bad + t.success) as u64, "only admitted attempts hashed ({t:?})");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn argon2_never_runs_on_an_async_worker() {
    // With ONE worker thread, a long burst of logins must not stop the runtime from serving a timer.
    // (If Argon2 ran inline the timer below would fire late by the sum of the hashes.)
    let (_db, st) = world().await;
    let ticker = tokio::spawn(async {
        let mut worst = Duration::ZERO;
        for _ in 0..30 {
            let t = std::time::Instant::now();
            tokio::time::sleep(Duration::from_millis(5)).await;
            worst = worst.max(t.elapsed());
        }
        worst
    });
    let _ = burst(&st, 20, |i| (format!("203.0.114.{i}"), "victim1".into(), format!("wrong-{i}"))).await;
    let worst = ticker.await.unwrap();
    assert!(worst < Duration::from_millis(250), "the timer was starved for {worst:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registration_hashes_under_the_same_permits() {
    let (_db, st) = world().await;
    let h = hash_password(&st, "another-password").await.unwrap();
    assert!(PasswordHash::new(&h).is_ok());
    assert_eq!(runs(&st), 1);
}
