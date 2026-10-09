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
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tracing::{error, warn};

pub const SESSION_DURATION_SECS: i64 = 86400 * 7; // 7 days
pub const MAX_LOGIN_ATTEMPTS: u64 = 5;
pub const LOCKOUT_DURATION_SECS: i64 = 900; // 15 minutes
/// Failures against one USERNAME, from any addresses, before that username is locked for the
/// same 15 minutes. Generous on purpose: it exists to stop a distributed guesser, and locking a
/// name is itself a nuisance an attacker can cause.
pub const MAX_USER_LOGIN_FAILURES: u64 = 20;
pub const CSRF_TOKEN_DURATION_SECS: i64 = 600; // 10 minutes
pub const MAX_REGISTRATIONS_PER_HOUR: u64 = 10;
pub const REGISTER_WINDOW_SECS: i64 = 3600;
/// Entries the in-process fallback limiter will hold.
pub const LOCAL_LIMITER_KEYS: usize = 10_000;
const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);

const REDIS_SESSION_PREFIX: &str = "session:";
const REDIS_RATELIMIT_PREFIX: &str = "ratelimit:";
const REDIS_LOCKOUT_PREFIX: &str = "lockout:";
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
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionData {
    pub username: String,
    pub expires_at: i64,
    pub created_ip: String,
    pub created_at: String,
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

    async fn redis_lock_ttl(conn: &mut redis::aio::MultiplexedConnection, key: &str) -> Result<Option<i64>, redis::RedisError> {
        let ttl: i64 = conn.ttl(format!("{}{}", REDIS_LOCKOUT_PREFIX, key)).await?;
        // -2: no key; -1: key without expiry (treat as locked for the full window)
        Ok(match ttl {
            -2 => None,
            -1 => Some(LOCKOUT_DURATION_SECS),
            t => Some(t.max(1)),
        })
    }

    async fn redis_fail(
        conn: &mut redis::aio::MultiplexedConnection,
        key: &str,
        max: u64,
        window_secs: i64,
    ) -> Result<bool, redis::RedisError> {
        let ckey = format!("{}{}", REDIS_RATELIMIT_PREFIX, key);
        let count: i64 = conn.incr(&ckey, 1).await?;
        if count == 1 {
            let _: Result<(), _> = conn.expire(&ckey, window_secs).await;
        }
        let locked = count as u64 >= max;
        if locked {
            let _: Result<(), _> =
                conn.set_ex::<_, _, ()>(format!("{}{}", REDIS_LOCKOUT_PREFIX, key), "1", window_secs as u64).await;
        }
        Ok(locked)
    }

    /// Seconds left if this address, or this username, is locked out of login. Redis is asked first; if it
    /// cannot be reached the in-process limiter answers instead -- a lockout that exists, not one that fails open.
    pub async fn login_lockout(&self, ip: &str, user_key: &str) -> Option<i64> {
        let mut conn = self.throttle_conn().await;
        let mut worst: Option<i64> = None;
        for key in [ip, user_key] {
            let ttl = match conn.as_mut() {
                Some(c) => match Self::redis_lock_ttl(c, key).await {
                    Ok(t) => t,
                    Err(e) => {
                        self.redis_failed("TTL", &e);
                        conn = None;
                        self.local_limiter.locked_ttl(&format!("lock:{}", key))
                    }
                },
                None => self.local_limiter.locked_ttl(&format!("lock:{}", key)),
            };
            worst = match (worst, ttl) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
        }
        worst
    }

    pub async fn record_login_failure(&self, ip: &str, user_key: &str) {
        let mut conn = self.throttle_conn().await;
        for (key, max) in [(ip, MAX_LOGIN_ATTEMPTS), (user_key, MAX_USER_LOGIN_FAILURES)] {
            let via_redis = match conn.as_mut() {
                Some(c) => match Self::redis_fail(c, key, max, LOCKOUT_DURATION_SECS).await {
                    Ok(locked) => {
                        if locked {
                            warn!(event = "lockout", key = %key, "locked out after {} failures", max);
                        }
                        true
                    }
                    Err(e) => {
                        self.redis_failed("INCR", &e);
                        conn = None;
                        false
                    }
                },
                None => false,
            };
            if !via_redis {
                self.local_limiter.fail(&format!("lock:{}", key), max, Duration::from_secs(LOCKOUT_DURATION_SECS as u64));
            }
        }
    }

    pub async fn clear_login_failures(&self, ip: &str, user_key: &str) {
        let mut conn = self.throttle_conn().await;
        for key in [ip, user_key] {
            let done = match conn.as_mut() {
                Some(c) => {
                    let r: Result<(), _> = c.del(format!("{}{}", REDIS_RATELIMIT_PREFIX, key)).await;
                    if let Err(e) = &r {
                        self.redis_failed("DEL", e);
                    }
                    r.is_ok()
                }
                None => false,
            };
            if !done {
                self.local_limiter.clear(&format!("lock:{}", key));
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
mod tests;
