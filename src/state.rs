// ============================================================================
// Application state, Redis-backed sessions / OAuth state, and the throttles.
// ============================================================================
use crate::gate::{self, Genus};
use crate::limiter::LocalLimiter;
use crate::security::{ApiAuth, TrustedProxies};
use chrono::Utc;
use oauth2::basic::BasicClient;
use redis::AsyncCommands;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqlitePool;
use std::{
    net::{IpAddr, SocketAddr},
    sync::OnceLock,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{error, warn};

pub const SESSION_DURATION_SECS: i64 = 86400 * 7; // 7 days
/// Password attempts one client ADDRESS may make per window. An attempt takes its slot before any hashing
/// is done, so a concurrent burst cannot get more than this many verifications through.
pub const MAX_LOGIN_ATTEMPTS: u64 = 5;
pub const LOCKOUT_DURATION_SECS: i64 = 900; // 15 minutes
/// Password attempts naming one USERNAME, from all addresses together, per window. Generous on purpose: it
/// exists to stop a guesser spread over many addresses. It is also a lever against the owner: anyone who can
/// send this many requests naming a user can keep that user out of password login for a window (see the README).
pub const MAX_USER_LOGIN_ATTEMPTS: u64 = 20;
/// How long a request waits for an Argon2 slot before it is turned away with 503.
pub const HASH_QUEUE_WAIT: Duration = Duration::from_secs(2);
pub const CSRF_TOKEN_DURATION_SECS: i64 = 600; // 10 minutes
pub const MAX_REGISTRATIONS_PER_HOUR: u64 = 10;
pub const REGISTER_WINDOW_SECS: i64 = 3600;
/// Entries the in-process fallback limiter will hold.
pub const LOCAL_LIMITER_KEYS: usize = 10_000;
const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);

const REDIS_SESSION_PREFIX: &str = "session:";
const REDIS_RATELIMIT_PREFIX: &str = "ratelimit:";
const REDIS_CSRF_PREFIX: &str = "csrf:";

pub struct AppState {
    pub pool: SqlitePool,
    pub redis: redis::Client,
    pub oauth_client: BasicClient,
    pub http_client: HttpClient,
    pub stripe_secret: String,
    pub stripe_webhook_secret: String,
    pub base_url: String,
    pub api_auth: ApiAuth,
    pub trusted_proxies: TrustedProxies,
    pub local_limiter: LocalLimiter,
    /// Argon2 hashing and verification run on the blocking pool, at most this many at once.
    pub hash_permits: Arc<Semaphore>,
    /// How long a request may wait for one of them.
    pub hash_wait: Duration,
    pub metrics: Arc<Metrics>,
    pub shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub requests_total: AtomicU64,
    pub logins_success: AtomicU64,
    pub logins_failed: AtomicU64,
    pub registrations: AtomicU64,
    pub payments_total: AtomicU64,
    pub payments_amount_cents: AtomicU64,
    pub api_calls: AtomicU64,
    pub redis_errors: AtomicU64,
    /// Argon2 operations actually run (verifications, dummy hashes for unknown users, registrations).
    pub argon2_runs: AtomicU64,
    /// Requests turned away with 503 because no Argon2 slot came free in time.
    pub argon2_busy: AtomicU64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionData {
    pub username: String,
    pub expires_at: i64,
    pub created_ip: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Redis,
    Local,
}

/// The attempt slots one admitted login holds (and in which store each lives).
#[derive(Debug)]
pub struct LoginSlots {
    ip: String,
    ip_backend: Backend,
    user_key: String,
    user_backend: Backend,
}

#[derive(Debug)]
pub enum SlotResult {
    Admitted(LoginSlots),
    /// Turned away; seconds until the window ends.
    Locked(i64),
}

// KEYS[1] counter; ARGV[1] max, ARGV[2] window seconds. Returns {admitted, count, ttl}.
// The increment, the window (restarted at the max-th attempt, so a lockout lasts a full window from the last
// permitted guess), the turn-away (an attempt over max is un-counted) and a repair for a counter that lost its
// expiry are one atomic step.
const TAKE_LUA: &str = r#"
local n = redis.call('INCR', KEYS[1])
local max = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
if n == 1 or n == max then redis.call('EXPIRE', KEYS[1], window) end
local admitted = 1
if n > max then
  redis.call('DECR', KEYS[1])
  n = n - 1
  admitted = 0
end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then redis.call('EXPIRE', KEYS[1], window); ttl = window end
return {admitted, n, ttl}
"#;

const REFUND_LUA: &str = r#"
local n = redis.call('DECR', KEYS[1])
if n <= 0 then redis.call('DEL', KEYS[1]) end
return n
"#;

fn take_script() -> &'static redis::Script {
    static S: OnceLock<redis::Script> = OnceLock::new();
    S.get_or_init(|| redis::Script::new(TAKE_LUA))
}

fn refund_script() -> &'static redis::Script {
    static S: OnceLock<redis::Script> = OnceLock::new();
    S.get_or_init(|| redis::Script::new(REFUND_LUA))
}

/// The throttle key for a username: its lower-cased SHA-256, so what reaches Redis is neither
/// attacker-shaped nor attacker-sized, and `Alice` and `alice` share a counter.
pub fn user_throttle_key(username: &str) -> String {
    let d = Sha256::digest(username.to_lowercase().as_bytes());
    format!("user:{}", hex::encode(&d[..16]))
}

impl AppState {
    pub fn is_https(&self) -> bool {
        self.base_url.starts_with("https")
    }

    pub fn client_ip(&self, headers: &axum::http::HeaderMap, peer: SocketAddr) -> IpAddr {
        crate::security::client_ip(headers, peer, &self.trusted_proxies)
    }

    fn redis_failed(&self, what: &str, e: &redis::RedisError) {
        self.metrics.redis_errors.fetch_add(1, Ordering::Relaxed);
        error!("Redis {} error: {}", what, e);
    }

    pub async fn redis_conn(&self) -> Result<redis::aio::MultiplexedConnection, redis::RedisError> {
        match tokio::time::timeout(REDIS_CONNECT_TIMEOUT, self.redis.get_multiplexed_async_connection()).await {
            Ok(r) => r,
            Err(_) => Err((redis::ErrorKind::IoError, "connect timed out").into()),
        }
    }

    // ------------------------------------------------------------------ sessions
    pub async fn save_session(&self, session_id: &str, data: &SessionData) -> Result<(), ()> {
        if gate::admitte_signum(session_id, Genus::Session).is_err() {
            return Err(());
        }
        let mut conn = self.redis_conn().await.map_err(|e| self.redis_failed("connection", &e))?;
        let key = format!("{}{}", REDIS_SESSION_PREFIX, session_id);
        let json = serde_json::to_string(data).map_err(|_| ())?;
        let ttl = (data.expires_at - Utc::now().timestamp()).max(1) as u64;
        conn.set_ex::<_, _, ()>(&key, &json, ttl).await.map_err(|e| self.redis_failed("SET", &e))?;
        Ok(())
    }

    /// None for an id that is not 64 ASCII alphanumerics, whatever Redis holds.
    pub async fn get_session(&self, session_id: &str) -> Option<SessionData> {
        if gate::admitte_signum(session_id, Genus::Session).is_err() {
            return None;
        }
        let mut conn = self.redis_conn().await.ok()?;
        let key = format!("{}{}", REDIS_SESSION_PREFIX, session_id);
        let json: Option<String> = conn.get(&key).await.ok()?;
        json.and_then(|j| serde_json::from_str(&j).ok())
    }

    pub async fn delete_session(&self, session_id: &str) {
        if gate::admitte_signum(session_id, Genus::Session).is_err() {
            return;
        }
        if let Ok(mut conn) = self.redis_conn().await {
            let key = format!("{}{}", REDIS_SESSION_PREFIX, session_id);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    // --------------------------------------------------------- throttles: Redis, else local
    /// One connection for the whole operation, or None (counted, logged) if Redis cannot be reached.
    async fn throttle_conn(&self) -> Option<redis::aio::MultiplexedConnection> {
        match self.redis_conn().await {
            Ok(c) => Some(c),
            Err(e) => {
                self.redis_failed("connection", &e);
                warn!("Redis unavailable for rate limiting; using the in-process limiter");
                None
            }
        }
    }

    /// Take one slot under `key`, in Redis or, if Redis fails, in the in-process limiter. One script, so the
    /// increment, the window and the turn-away are a single step: concurrent callers get distinct counts.
    async fn take_one(
        &self,
        conn: &mut Option<redis::aio::MultiplexedConnection>,
        key: &str,
        max: u64,
        window_secs: i64,
    ) -> (Backend, bool, i64) {
        if let Some(c) = conn.as_mut() {
            let r: Result<(i64, i64, i64), _> = take_script()
                .key(format!("{}{}", REDIS_RATELIMIT_PREFIX, key))
                .arg(max)
                .arg(window_secs)
                .invoke_async(c)
                .await;
            match r {
                Ok((admitted, _count, ttl)) => return (Backend::Redis, admitted == 1, ttl.max(1)),
                Err(e) => {
                    self.redis_failed("EVAL", &e);
                    *conn = None;
                }
            }
        }
        let (admitted, ttl) = self.local_limiter.take(&format!("lock:{}", key), max, Duration::from_secs(window_secs as u64));
        (Backend::Local, admitted, ttl)
    }

    async fn refund_one(&self, conn: &mut Option<redis::aio::MultiplexedConnection>, key: &str, backend: Backend) {
        match (backend, conn.as_mut()) {
            (Backend::Redis, Some(c)) => {
                let r: Result<i64, _> = refund_script().key(format!("{}{}", REDIS_RATELIMIT_PREFIX, key)).invoke_async(c).await;
                if let Err(e) = r {
                    self.redis_failed("EVAL", &e);
                    *conn = None;
                }
            }
            (Backend::Redis, None) => {} // Redis went away after the slot was taken: its TTL will release it
            (Backend::Local, _) => self.local_limiter.refund(&format!("lock:{}", key)),
        }
    }

    async fn reset_one(&self, conn: &mut Option<redis::aio::MultiplexedConnection>, key: &str, backend: Backend) {
        match (backend, conn.as_mut()) {
            (Backend::Redis, Some(c)) => {
                let r: Result<(), _> = c.del(format!("{}{}", REDIS_RATELIMIT_PREFIX, key)).await;
                if let Err(e) = r {
                    self.redis_failed("DEL", &e);
                    *conn = None;
                }
            }
            (Backend::Redis, None) => {}
            (Backend::Local, _) => self.local_limiter.clear(&format!("lock:{}", key)),
        }
    }

    /// Take the attempt slots for one password login, BEFORE any password is hashed or compared.
    ///
    /// The address's slot is taken first; if it is spent, the request is turned away without touching the
    /// username's counter (a locked address cannot burn a victim's budget). Then the username's slot; if that
    /// is spent, the address's slot is given back (nothing was evaluated). Both are atomic increments, so a
    /// burst of N concurrent requests is admitted at most MAX_LOGIN_ATTEMPTS (address) and
    /// MAX_USER_LOGIN_ATTEMPTS (username) times, however the requests interleave.
    pub async fn take_login_slots(&self, ip: &str, user_key: &str) -> SlotResult {
        let mut conn = self.throttle_conn().await;
        let (ip_backend, ok, ttl) = self.take_one(&mut conn, ip, MAX_LOGIN_ATTEMPTS, LOCKOUT_DURATION_SECS).await;
        if !ok {
            warn!(event = "lockout", key = %ip, "address over its login attempts");
            return SlotResult::Locked(ttl);
        }
        let (user_backend, ok, ttl) = self.take_one(&mut conn, user_key, MAX_USER_LOGIN_ATTEMPTS, LOCKOUT_DURATION_SECS).await;
        if !ok {
            warn!(event = "lockout", key = %user_key, "username over its login attempts");
            self.refund_one(&mut conn, ip, ip_backend).await;
            return SlotResult::Locked(ttl);
        }
        SlotResult::Admitted(LoginSlots { ip: ip.to_string(), ip_backend, user_key: user_key.to_string(), user_backend })
    }

    /// The password was right: the address's count and the username's count are both cleared (as they always
    /// were). This keeps a shared address (a campus, a mobile carrier's NAT) usable: one person's typos do not
    /// outlast another person's successful login. It also means an attacker with a valid account of their own can
    /// interleave logins with guesses at the ADDRESS limit; the USERNAME limit is what bounds guesses at any one
    /// victim, and it is not reachable that way (a success on another username does not clear it).
    pub async fn login_succeeded(&self, slots: LoginSlots) {
        let mut conn = self.throttle_conn().await;
        self.reset_one(&mut conn, &slots.ip, slots.ip_backend).await;
        self.reset_one(&mut conn, &slots.user_key, slots.user_backend).await;
    }

    /// Nothing was evaluated (no Argon2 slot came free): give both slots back.
    pub async fn release_login_slots(&self, slots: LoginSlots) {
        let mut conn = self.throttle_conn().await;
        self.refund_one(&mut conn, &slots.ip, slots.ip_backend).await;
        self.refund_one(&mut conn, &slots.user_key, slots.user_backend).await;
    }

    /// One of the Argon2 slots, or None (counted) if none comes free within `hash_wait`.
    pub async fn acquire_hash_permit(&self) -> Option<OwnedSemaphorePermit> {
        match tokio::time::timeout(self.hash_wait, self.hash_permits.clone().acquire_owned()).await {
            Ok(Ok(p)) => Some(p),
            _ => {
                self.metrics.argon2_busy.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Count one registration attempt that got as far as hashing a password; false once this address
    /// is past MAX_REGISTRATIONS_PER_HOUR. (Argon2 is the expensive step; a name that fails validation
    /// costs nothing and is not counted.)
    pub async fn register_allowed(&self, ip: &str) -> bool {
        let key = format!("reg:{}", ip);
        if let Some(mut conn) = self.throttle_conn().await {
            let ckey = format!("{}{}", REDIS_RATELIMIT_PREFIX, key);
            match conn.incr::<_, _, i64>(&ckey, 1).await {
                Ok(count) => {
                    if count == 1 {
                        let _: Result<(), _> = conn.expire(&ckey, REGISTER_WINDOW_SECS).await;
                    }
                    return count as u64 <= MAX_REGISTRATIONS_PER_HOUR;
                }
                Err(e) => self.redis_failed("INCR", &e),
            }
        }
        self.local_limiter.allow(&key, MAX_REGISTRATIONS_PER_HOUR, Duration::from_secs(REGISTER_WINDOW_SECS as u64))
    }

    // ------------------------------------------------------------------ OAuth state
    pub async fn save_csrf_token(&self, token: &str) -> Result<(), ()> {
        if gate::admitte_signum(token, Genus::Token).is_err() {
            return Err(());
        }
        let mut conn = self.redis_conn().await.map_err(|_| ())?;
        let key = format!("{}{}", REDIS_CSRF_PREFIX, token);
        conn.set_ex::<_, _, ()>(&key, "1", CSRF_TOKEN_DURATION_SECS as u64).await.map_err(|_| ())
    }

    /// Single use: GET and DELETE in one command. A value that is not 32 ASCII alphanumerics never reaches Redis.
    pub async fn validate_csrf_token(&self, token: &str) -> bool {
        if gate::admitte_signum(token, Genus::Token).is_err() {
            return false;
        }
        if let Ok(mut conn) = self.redis_conn().await {
            let key = format!("{}{}", REDIS_CSRF_PREFIX, token);
            let exists: Option<String> = conn.get_del(&key).await.ok().flatten();
            return exists.is_some();
        }
        false
    }
}

#[cfg(test)]
pub(crate) mod tests;
