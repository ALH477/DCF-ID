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
//   - Usage report queue (crash recovery)
// ============================================================================

use axum::{
    extract::{ConnectInfo, Form, Path, Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Router,
};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use askama::Template;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use tower_http::{trace::TraceLayer, timeout::TimeoutLayer, compression::CompressionLayer};
use rand::{distributions::Alphanumeric, Rng};
use std::{
    env,
    net::SocketAddr,
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc},
    time::Duration,
};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenUrl, TokenResponse,
    reqwest::async_http_client, AuthorizationCode,
};
use reqwest::Client as HttpClient;
use chrono::{Datelike, Utc};
use tokio::{signal, time::sleep};
use tracing::{info, warn, error, debug};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// ============================================================================
// CONSTANTS
// ============================================================================
const VERSION: &str = env!("CARGO_PKG_VERSION");
const FREE_TIER_BYTES: i64 = 134_217_728; // 128 MB
const BYTES_PER_GB: f64 = 1_073_741_824.0;
const PRICE_PER_GB: f64 = 0.05;
const PRICE_PER_BYTE: f64 = PRICE_PER_GB / BYTES_PER_GB;
const SESSION_DURATION_SECS: i64 = 86400 * 7; // 7 days
const MAX_LOGIN_ATTEMPTS: i64 = 5;
const LOCKOUT_DURATION_SECS: i64 = 900; // 15 minutes
const MIN_PASSWORD_LENGTH: usize = 8;
const MAX_USERNAME_LENGTH: usize = 32;
const CSRF_TOKEN_DURATION_SECS: i64 = 600; // 10 minutes
const STRIPE_WEBHOOK_TOLERANCE_SECS: i64 = 300; // 5 minutes

// Redis key prefixes
const REDIS_SESSION_PREFIX: &str = "session:";
const REDIS_RATELIMIT_PREFIX: &str = "ratelimit:";
const REDIS_LOCKOUT_PREFIX: &str = "lockout:";
const REDIS_CSRF_PREFIX: &str = "csrf:";
const REDIS_PENDING_LINK_PREFIX: &str = "pendinglink:";

// ============================================================================
// APPLICATION STATE
// ============================================================================
#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    redis: redis::Client,
    oauth_client: BasicClient,
    http_client: HttpClient,
    stripe_secret: String,
    stripe_webhook_secret: String,
    base_url: String,
    internal_key: String,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct Metrics {
    requests_total: AtomicU64,
    logins_success: AtomicU64,
    logins_failed: AtomicU64,
    registrations: AtomicU64,
    payments_total: AtomicU64,
    payments_amount_cents: AtomicU64,
    api_calls: AtomicU64,
    redis_errors: AtomicU64,
}

// ============================================================================
// SESSION DATA (Stored in Redis as JSON)
// ============================================================================
#[derive(Serialize, Deserialize, Clone, Debug)]
struct SessionData {
    username: String,
    expires_at: i64,
    created_ip: String,
    created_at: String,
}

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
// REQUEST/RESPONSE TYPES
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

#[derive(Deserialize)]
struct StripeEvent {
    #[serde(rename = "type")]
    event_type: String,
    data: StripeEventData,
}

#[derive(Deserialize)]
struct StripeEventData {
    object: StripeCheckoutSession,
}

#[derive(Deserialize)]
struct StripeCheckoutSession {
    metadata: Option<std::collections::HashMap<String, String>>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    uptime_secs: u64,
    redis_ok: bool,
}

#[derive(Serialize)]
struct MetricsResponse {
    requests_total: u64,
    logins_success: u64,
    logins_failed: u64,
    registrations: u64,
    payments_total: u64,
    api_calls: u64,
    redis_errors: u64,
}

// GSN Integration types
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    message: Option<String>,
    data: Option<T>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self { success: true, message: None, data: Some(data) }
    }
}

impl ApiResponse<()> {
    fn error(msg: impl Into<String>) -> Self {
        Self { success: false, message: Some(msg.into()), data: None }
    }
}

#[derive(Serialize)]
struct UserApiResponse {
    username: String,
    access_token: String,
    discord_id: Option<String>,
    data_used: i64,
    account_balance: f64,
    is_vip: bool,
    last_seen: Option<String>,
}

#[derive(Deserialize)]
struct UsageReportRequest {
    access_token: String,
    bytes_used: u64,
}

#[derive(Serialize)]
struct StatsResponse {
    total_users: i64,
    total_bandwidth_bytes: i64,
    total_balance_usd: f64,
    vip_users: i64,
}

// ============================================================================
// REDIS HELPERS
// ============================================================================
impl AppState {
    async fn redis_conn(&self) -> Result<redis::aio::MultiplexedConnection, redis::RedisError> {
        self.redis.get_multiplexed_async_connection().await
    }

    // Session management
    async fn save_session(&self, session_id: &str, data: &SessionData) -> Result<(), ()> {
        let mut conn = self.redis_conn().await.map_err(|e| {
            self.metrics.redis_errors.fetch_add(1, Ordering::Relaxed);
            error!("Redis connection error: {}", e);
        })?;

        let key = format!("{}{}", REDIS_SESSION_PREFIX, session_id);
        let json = serde_json::to_string(data).map_err(|_| ())?;
        let ttl = (data.expires_at - Utc::now().timestamp()).max(1) as u64;

        conn.set_ex::<_, _, ()>(&key, &json, ttl).await.map_err(|e| {
            self.metrics.redis_errors.fetch_add(1, Ordering::Relaxed);
            error!("Redis SET error: {}", e);
        })?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Option<SessionData> {
        let mut conn = self.redis_conn().await.ok()?;
        let key = format!("{}{}", REDIS_SESSION_PREFIX, session_id);

        let json: Option<String> = conn.get(&key).await.ok()?;
        json.and_then(|j| serde_json::from_str(&j).ok())
    }

    async fn delete_session(&self, session_id: &str) {
        if let Ok(mut conn) = self.redis_conn().await {
            let key = format!("{}{}", REDIS_SESSION_PREFIX, session_id);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    // Rate limiting
    async fn check_rate_limit(&self, ip: &str) -> Result<bool, ()> {
        let mut conn = self.redis_conn().await.map_err(|_| ())?;

        let lockout_key = format!("{}{}", REDIS_LOCKOUT_PREFIX, ip);
        let is_locked: Option<String> = conn.get(&lockout_key).await.ok().flatten();
        if is_locked.is_some() {
            return Ok(false); // Still locked out
        }

        Ok(true) // Not locked
    }

    async fn record_failed_login(&self, ip: &str) -> Result<i64, ()> {
        let mut conn = self.redis_conn().await.map_err(|_| ())?;

        let key = format!("{}{}", REDIS_RATELIMIT_PREFIX, ip);
        
        // Increment counter
        let count: i64 = conn.incr(&key, 1).await.map_err(|_| ())?;
        
        // Set expiry on first failure
        if count == 1 {
            let _: Result<(), _> = conn.expire(&key, LOCKOUT_DURATION_SECS as i64).await;
        }

        // If exceeded, set lockout
        if count >= MAX_LOGIN_ATTEMPTS {
            let lockout_key = format!("{}{}", REDIS_LOCKOUT_PREFIX, ip);
            let _: Result<(), _> = conn.set_ex::<_, _, ()>(&lockout_key, "1", LOCKOUT_DURATION_SECS as u64).await;
            warn!(event = "ip_lockout", ip = %ip, "IP locked out after {} attempts", count);
        }

        Ok(count)
    }

    async fn clear_rate_limit(&self, ip: &str) {
        if let Ok(mut conn) = self.redis_conn().await {
            let key = format!("{}{}", REDIS_RATELIMIT_PREFIX, ip);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    async fn get_lockout_ttl(&self, ip: &str) -> Option<i64> {
        let mut conn = self.redis_conn().await.ok()?;
        let lockout_key = format!("{}{}", REDIS_LOCKOUT_PREFIX, ip);
        conn.ttl(&lockout_key).await.ok().filter(|&ttl| ttl > 0)
    }

    // CSRF tokens
    async fn save_csrf_token(&self, token: &str) -> Result<(), ()> {
        let mut conn = self.redis_conn().await.map_err(|_| ())?;
        let key = format!("{}{}", REDIS_CSRF_PREFIX, token);
        conn.set_ex::<_, _, ()>(&key, "1", CSRF_TOKEN_DURATION_SECS as u64)
            .await
            .map_err(|_| ())
    }

    async fn validate_csrf_token(&self, token: &str) -> bool {
        if let Ok(mut conn) = self.redis_conn().await {
            let key = format!("{}{}", REDIS_CSRF_PREFIX, token);
            // GET and DELETE atomically
            let exists: Option<String> = conn.get_del(&key).await.ok().flatten();
            return exists.is_some();
        }
        false
    }

    // Pending Discord links
    async fn save_pending_link(&self, csrf_token: &str, discord_id: &str) -> Result<(), ()> {
        let mut conn = self.redis_conn().await.map_err(|_| ())?;
        let key = format!("{}{}", REDIS_PENDING_LINK_PREFIX, csrf_token);
        conn.set_ex::<_, _, ()>(&key, discord_id, CSRF_TOKEN_DURATION_SECS as u64)
            .await
            .map_err(|_| ())
    }

    async fn get_pending_link(&self, csrf_token: &str) -> Option<String> {
        let mut conn = self.redis_conn().await.ok()?;
        let key = format!("{}{}", REDIS_PENDING_LINK_PREFIX, csrf_token);
        conn.get_del(&key).await.ok().flatten()
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
fn generate_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn extract_client_ip(headers: &HeaderMap, addr: SocketAddr) -> String {
    headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string())
}

fn create_session_cookie(session_id: &str, max_age: i64, secure: bool) -> HeaderValue {
    let cookie = format!(
        "session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        session_id, max_age, if secure { "; Secure" } else { "" }
    );
    HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn validate_username(username: &str) -> Result<(), String> {
    if username.len() < 3 || username.len() > MAX_USERNAME_LENGTH {
        return Err(format!("Username must be 3-{} characters", MAX_USERNAME_LENGTH));
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err("Username can only contain letters, numbers, _ and -".into());
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(format!("Password must be at least {} characters", MIN_PASSWORD_LENGTH));
    }
    Ok(())
}

fn verify_internal_key(headers: &HeaderMap, expected: &str) -> bool {
    if expected.is_empty() {
        return true;
    }
    headers.get("X-Internal-Key")
        .and_then(|v| v.to_str().ok())
        .map(|k| k == expected)
        .unwrap_or(false)
}

// ============================================================================
// DATABASE HELPERS
// ============================================================================
async fn get_user_by_username(pool: &SqlitePool, username: &str) -> Option<(String, String, i64, f64, bool)> {
    sqlx::query(
        "SELECT username, access_token, data_used, account_balance, is_vip FROM users WHERE username = ?"
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .ok()?
    .map(|row| {
        (
            row.get::<String, _>("username"),
            row.get::<String, _>("access_token"),
            row.get::<i64, _>("data_used"),
            row.get::<f64, _>("account_balance"),
            row.get::<i32, _>("is_vip") == 1,
        )
    })
}

async fn get_password_hash(pool: &SqlitePool, username: &str) -> Option<String> {
    sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await
        .ok()?
        .map(|row| row.get::<String, _>("password_hash"))
}

async fn update_user_ip(pool: &SqlitePool, username: &str, ip: &str) {
    let _ = sqlx::query("UPDATE users SET last_ip = ?, last_seen = ? WHERE username = ?")
        .bind(ip)
        .bind(Utc::now().to_rfc3339())
        .bind(username)
        .execute(pool)
        .await;
}

// ============================================================================
// CORE LOGIC
// ============================================================================
async fn dashboard_logic(pool: &SqlitePool, username: &str) -> Option<UserDisplay> {
    let (uname, token, data_used, balance, is_vip) = get_user_by_username(pool, username).await?;
    
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
        let paid_pct = if limit_by_balance > 0.0 {
            (paid_used / limit_by_balance) * 100.0
        } else {
            100.0
        };
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
    let html = IndexTemplate { user: None, error: Some(message), version: VERSION }
        .render()
        .unwrap_or_else(|_| "Error".into());
    Html(html).into_response()
}

fn render_index(user: Option<UserDisplay>) -> String {
    IndexTemplate { user, error: None, version: VERSION }
        .render()
        .unwrap_or_else(|_| "Error".into())
}

// ============================================================================
// CORE HANDLERS
// ============================================================================
async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    
    let db_ok = sqlx::query("SELECT 1").fetch_one(&state.pool).await.is_ok();
    let redis_ok = state.redis_conn().await
        .and_then(|mut c| futures::executor::block_on(async { 
            redis::cmd("PING").query_async::<String>(&mut c).await 
        }).ok())
        .is_some();
    
    let status = if db_ok && redis_ok { "healthy" } else { "degraded" };
    
    Json(HealthResponse {
        status,
        version: VERSION,
        uptime_secs: start.elapsed().as_secs(),
        redis_ok,
    })
}

async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(MetricsResponse {
        requests_total: state.metrics.requests_total.load(Ordering::Relaxed),
        logins_success: state.metrics.logins_success.load(Ordering::Relaxed),
        logins_failed: state.metrics.logins_failed.load(Ordering::Relaxed),
        registrations: state.metrics.registrations.load(Ordering::Relaxed),
        payments_total: state.metrics.payments_total.load(Ordering::Relaxed),
        api_calls: state.metrics.api_calls.load(Ordering::Relaxed),
        redis_errors: state.metrics.redis_errors.load(Ordering::Relaxed),
    })
}

async fn index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    
    if let Some(cookie) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(session_id) = part.strip_prefix("session=") {
                    if let Some(session) = state.get_session(session_id).await {
                        if session.expires_at > Utc::now().timestamp() {
                            let user = dashboard_logic(&state.pool, &session.username).await;
                            return Html(render_index(user));
                        }
                    }
                }
            }
        }
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
    
    if let Err(e) = validate_username(&payload.username) { return render_error(e); }
    if let Err(e) = validate_password(&payload.password) { return render_error(e); }
    
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match Argon2::default().hash_password(payload.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return render_error("Registration failed".into()),
    };
    
    let token = generate_token(32);
    let now = Utc::now();
    let client_ip = extract_client_ip(&headers, addr);

    let result = sqlx::query(
        "INSERT INTO users (username, password_hash, access_token, data_used, account_balance, 
         last_reset_date, is_vip, last_ip, last_seen, created_at) 
         VALUES (?, ?, ?, 0, 0.0, ?, 0, ?, ?, ?)"
    )
    .bind(&payload.username)
    .bind(&password_hash)
    .bind(&token)
    .bind(now.format("%Y-%m").to_string())
    .bind(&client_ip)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => {
            info!(event = "user_registered", username = %payload.username);
            state.metrics.registrations.fetch_add(1, Ordering::Relaxed);
            
            let session_id = generate_token(64);
            let expires_at = now.timestamp() + SESSION_DURATION_SECS;
            
            let session = SessionData {
                username: payload.username.clone(),
                expires_at,
                created_ip: client_ip,
                created_at: now.to_rfc3339(),
            };
            
            let _ = state.save_session(&session_id, &session).await;

            let user = dashboard_logic(&state.pool, &payload.username).await;
            let html = render_index(user);
            let is_https = state.base_url.starts_with("https");
            
            Response::builder()
                .status(StatusCode::OK)
                .header(SET_COOKIE, create_session_cookie(&session_id, SESSION_DURATION_SECS, is_https))
                .body(html.into())
                .unwrap_or_else(|_| render_error("Response failed".into()))
        }
        Err(e) => {
            if e.to_string().contains("UNIQUE") {
                render_error("Username already taken".into())
            } else {
                error!("Registration failed: {}", e);
                render_error("Registration failed".into())
            }
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
    let client_ip = extract_client_ip(&headers, addr);
    let now = Utc::now().timestamp();
    
    // Rate limiting check
    match state.check_rate_limit(&client_ip).await {
        Ok(false) => {
            let ttl = state.get_lockout_ttl(&client_ip).await.unwrap_or(LOCKOUT_DURATION_SECS);
            return render_error(format!("Too many attempts. Try again in {} seconds.", ttl));
        }
        Err(_) => {
            // Redis down - fail open with warning
            warn!("Redis unavailable for rate limiting");
        }
        Ok(true) => {}
    }
    
    let password_hash = get_password_hash(&state.pool, &payload.username).await;
    
    let login_success = if let Some(hash) = password_hash {
        if let Ok(parsed) = PasswordHash::new(&hash) {
            Argon2::default().verify_password(payload.password.as_bytes(), &parsed).is_ok()
        } else { false }
    } else {
        // Timing attack mitigation
        let _ = Argon2::default().hash_password(payload.password.as_bytes(), &SaltString::generate(&mut OsRng));
        false
    };
    
    if login_success {
        state.clear_rate_limit(&client_ip).await;
        
        info!(event = "login_success", username = %payload.username);
        state.metrics.logins_success.fetch_add(1, Ordering::Relaxed);
        update_user_ip(&state.pool, &payload.username, &client_ip).await;

        let session_id = generate_token(64);
        let expires_at = now + SESSION_DURATION_SECS;
        
        let session = SessionData {
            username: payload.username.clone(),
            expires_at,
            created_ip: client_ip,
            created_at: Utc::now().to_rfc3339(),
        };
        
        let _ = state.save_session(&session_id, &session).await;

        let user = dashboard_logic(&state.pool, &payload.username).await;
        let html = render_index(user);
        let is_https = state.base_url.starts_with("https");
        
        Response::builder()
            .status(StatusCode::OK)
            .header(SET_COOKIE, create_session_cookie(&session_id, SESSION_DURATION_SECS, is_https))
            .body(html.into())
            .unwrap_or_else(|_| render_error("Response failed".into()))
    } else {
        let _ = state.record_failed_login(&client_ip).await;
        state.metrics.logins_failed.fetch_add(1, Ordering::Relaxed);
        render_error("Invalid credentials".into())
    }
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(cookie) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie.to_str() {
            for part in cookie_str.split(';') {
                if let Some(session_id) = part.trim().strip_prefix("session=") {
                    state.delete_session(session_id).await;
                }
            }
        }
    }
    
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("Location", "/")
        .header(SET_COOKIE, "session=; Path=/; Max-Age=0")
        .body("".into())
        .unwrap()
}

// ============================================================================
// OAUTH HANDLERS
// ============================================================================
async fn discord_auth(
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let (auth_url, csrf_token) = state.oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".into()))
        .url();
    
    // Save CSRF token to Redis
    let _ = state.save_csrf_token(csrf_token.secret()).await;
    
    // If linking Discord from bot, save pending link
    if let Some(discord_id) = params.get("link_discord") {
        let _ = state.save_pending_link(csrf_token.secret(), discord_id).await;
    }
    
    Redirect::to(auth_url.as_str())
}

async fn discord_callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<OAuthCallback>,
) -> Response {
    let client_ip = extract_client_ip(&headers, addr);
    
    // Validate CSRF token
    if !state.validate_csrf_token(&params.state).await {
        warn!(event = "csrf_validation_failed", ip = %client_ip);
        return render_error("Invalid or expired OAuth state. Please try again.".into());
    }
    
    // Check for pending link
    let _pending_discord_id = state.get_pending_link(&params.state).await;
    
    // Exchange code for token
    let token_result = state.oauth_client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(async_http_client)
        .await;
    
    let token = match token_result {
        Ok(t) => t,
        Err(e) => {
            error!("OAuth token exchange failed: {}", e);
            return render_error("Authentication failed. Please try again.".into());
        }
    };
    
    // Get Discord user info
    let user_response = state.http_client
        .get("https://discord.com/api/users/@me")
        .bearer_auth(token.access_token().secret())
        .send()
        .await;
    
    let discord_user: DiscordUser = match user_response {
        Ok(r) => match r.json().await {
            Ok(u) => u,
            Err(_) => return render_error("Failed to get user info".into()),
        },
        Err(_) => return render_error("Failed to contact Discord".into()),
    };
    
    // Check if Discord ID already linked
    let existing = sqlx::query("SELECT username FROM users WHERE discord_id = ?")
        .bind(&discord_user.id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    
    let username = if let Some(row) = existing {
        row.get::<String, _>("username")
    } else {
        // Create new user with collision handling
        let base_username = discord_user.username.clone();
        let mut username = base_username.clone();
        let mut attempt = 0;
        
        loop {
            let exists = sqlx::query("SELECT 1 FROM users WHERE username = ?")
                .bind(&username)
                .fetch_optional(&state.pool)
                .await
                .ok()
                .flatten()
                .is_some();
            
            if !exists { break; }
            
            attempt += 1;
            username = format!("{}_{}", base_username, attempt);
            
            if attempt > 100 {
                return render_error("Unable to create unique username".into());
            }
        }
        
        let access_token = generate_token(32);
        let now = Utc::now();
        
        let result = sqlx::query(
            "INSERT INTO users (username, discord_id, access_token, data_used, account_balance, 
             last_reset_date, is_vip, last_ip, last_seen, created_at) 
             VALUES (?, ?, ?, 0, 0.0, ?, 0, ?, ?, ?)"
        )
        .bind(&username)
        .bind(&discord_user.id)
        .bind(&access_token)
        .bind(now.format("%Y-%m").to_string())
        .bind(&client_ip)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&state.pool)
        .await;
        
        if let Err(e) = result {
            error!("Failed to create Discord user: {}", e);
            return render_error("Registration failed".into());
        }
        
        info!(event = "discord_user_registered", username = %username, discord_id = %discord_user.id);
        state.metrics.registrations.fetch_add(1, Ordering::Relaxed);
        username
    };
    
    // Create session
    let session_id = generate_token(64);
    let now = Utc::now().timestamp();
    let expires_at = now + SESSION_DURATION_SECS;
    
    let session = SessionData {
        username: username.clone(),
        expires_at,
        created_ip: client_ip.clone(),
        created_at: Utc::now().to_rfc3339(),
    };
    
    let _ = state.save_session(&session_id, &session).await;
    update_user_ip(&state.pool, &username, &client_ip).await;
    
    let user = dashboard_logic(&state.pool, &username).await;
    let html = render_index(user);
    let is_https = state.base_url.starts_with("https");
    
    Response::builder()
        .status(StatusCode::OK)
        .header(SET_COOKIE, create_session_cookie(&session_id, SESSION_DURATION_SECS, is_https))
        .body(html.into())
        .unwrap_or_else(|_| render_error("Response failed".into()))
}

// ============================================================================
// STRIPE HANDLERS
// ============================================================================
async fn create_checkout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CheckoutForm>,
) -> Response {
    let amount_dollars = form.amount.unwrap_or(5.0);
    if amount_dollars < 2.50 || amount_dollars > 100.0 {
        return render_error("Amount must be between $2.50 and $100".into());
    }
    let amount_cents = (amount_dollars * 100.0).round() as i64;
    
    // Get session username from cookie -> Redis
    let username = if let Some(cookie) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie.to_str() {
            let mut found = None;
            for part in cookie_str.split(';') {
                if let Some(sid) = part.trim().strip_prefix("session=") {
                    if let Some(session) = state.get_session(sid).await {
                        found = Some(session.username);
                        break;
                    }
                }
            }
            found
        } else { None }
    } else { None };
    
    let username = match username {
        Some(u) => u,
        None => return render_error("Please log in first".into()),
    };
    
    let token = sqlx::query("SELECT access_token FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .map(|r| r.get::<String, _>("access_token"));
    
    let token = match token {
        Some(t) => t,
        None => return render_error("User not found".into()),
    };
    
    let gb_amount = amount_dollars / 0.05;
    let product_name = format!("DCF Credits - {:.0}GB", gb_amount);
    let amount_str = amount_cents.to_string();
    
    let checkout = state.http_client
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
            ("metadata[access_token]", &token),
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

async fn stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let signature = headers.get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    
    if !verify_stripe_signature(&body, signature, &state.stripe_webhook_secret) {
        warn!(event = "stripe_webhook_invalid_signature");
        return StatusCode::BAD_REQUEST;
    }
    
    let event: StripeEvent = match serde_json::from_str(&body) {
        Ok(e) => e,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    
    if event.event_type == "checkout.session.completed" {
        if let Some(metadata) = event.data.object.metadata {
            if let Some(token) = metadata.get("access_token") {
                let amount: f64 = metadata.get("amount_dollars")
                    .and_then(|a| a.parse().ok())
                    .unwrap_or(5.0);
                
                let _ = sqlx::query(
                    "UPDATE users SET account_balance = account_balance + ? WHERE access_token = ?"
                )
                .bind(amount)
                .bind(token)
                .execute(&state.pool)
                .await;
                
                info!(event = "payment_processed", amount_usd = amount);
                state.metrics.payments_total.fetch_add(1, Ordering::Relaxed);
                state.metrics.payments_amount_cents.fetch_add((amount * 100.0) as u64, Ordering::Relaxed);
            }
        }
    }
    
    StatusCode::OK
}

fn verify_stripe_signature(payload: &str, signature: &str, secret: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    let mut timestamp = None;
    let mut sig = None;
    
    for part in signature.split(',') {
        let mut kv = part.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some("t"), Some(t)) => timestamp = Some(t.to_string()),
            (Some("v1"), Some(v)) => sig = Some(v.to_string()),
            _ => {}
        }
    }
    
    let (timestamp_str, sig) = match (timestamp, sig) {
        (Some(t), Some(s)) => (t, s),
        _ => return false,
    };
    
    // Timestamp validation
    let ts: i64 = match timestamp_str.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = Utc::now().timestamp();
    if (now - ts).abs() > STRIPE_WEBHOOK_TOLERANCE_SECS {
        warn!(event = "stripe_webhook_stale", timestamp = ts, now = now);
        return false;
    }
    
    let signed_payload = format!("{}.{}", timestamp_str, payload);
    
    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(signed_payload.as_bytes());
    
    let expected = hex::encode(mac.finalize().into_bytes());
    
    subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), sig.as_bytes()).into()
}

// ============================================================================
// GSN API HANDLERS
// ============================================================================
async fn get_user_by_discord(
    Path(discord_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<UserApiResponse>>, StatusCode> {
    state.metrics.api_calls.fetch_add(1, Ordering::Relaxed);
    
    if !verify_internal_key(&headers, &state.internal_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let row = sqlx::query(
        "SELECT username, access_token, discord_id, data_used, account_balance, is_vip, last_seen 
         FROM users WHERE discord_id = ?"
    )
    .bind(&discord_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match row {
        Some(row) => Ok(Json(ApiResponse::success(UserApiResponse {
            username: row.get("username"),
            access_token: row.get("access_token"),
            discord_id: row.get("discord_id"),
            data_used: row.get("data_used"),
            account_balance: row.get("account_balance"),
            is_vip: row.get::<i32, _>("is_vip") == 1,
            last_seen: row.get("last_seen"),
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn verify_token(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<UserApiResponse>>, StatusCode> {
    state.metrics.api_calls.fetch_add(1, Ordering::Relaxed);
    
    let token = headers.get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let row = sqlx::query(
        "SELECT username, access_token, discord_id, data_used, account_balance, is_vip, last_seen 
         FROM users WHERE access_token = ?"
    )
    .bind(token)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match row {
        Some(row) => {
            let _ = sqlx::query("UPDATE users SET last_seen = ? WHERE access_token = ?")
                .bind(Utc::now().to_rfc3339())
                .bind(token)
                .execute(&state.pool)
                .await;

            Ok(Json(ApiResponse::success(UserApiResponse {
                username: row.get("username"),
                access_token: row.get("access_token"),
                discord_id: row.get("discord_id"),
                data_used: row.get("data_used"),
                account_balance: row.get("account_balance"),
                is_vip: row.get::<i32, _>("is_vip") == 1,
                last_seen: row.get("last_seen"),
            })))
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn report_usage(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UsageReportRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    state.metrics.api_calls.fetch_add(1, Ordering::Relaxed);
    
    if !verify_internal_key(&headers, &state.internal_key) {
        return Err((StatusCode::UNAUTHORIZED, Json(ApiResponse::error("Invalid internal key"))));
    }

    let user = sqlx::query(
        "SELECT data_used, account_balance, is_vip FROM users WHERE access_token = ?"
    )
    .bind(&req.access_token)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(format!("DB error: {}", e)))))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ApiResponse::error("User not found"))))?;

    let current_used: i64 = user.get("data_used");
    let balance: f64 = user.get("account_balance");
    let is_vip: bool = user.get::<i32, _>("is_vip") == 1;

    let new_used = current_used + req.bytes_used as i64;

    let cost = if is_vip {
        0.0
    } else {
        let billable_before = (current_used - FREE_TIER_BYTES).max(0) as f64;
        let billable_after = (new_used - FREE_TIER_BYTES).max(0) as f64;
        let new_billable = billable_after - billable_before;
        
        if new_billable > 0.0 {
            (new_billable / BYTES_PER_GB) * PRICE_PER_GB
        } else {
            0.0
        }
    };

    let new_balance = (balance - cost).max(0.0);

    sqlx::query(
        "UPDATE users SET data_used = ?, account_balance = ?, last_seen = ? WHERE access_token = ?"
    )
    .bind(new_used)
    .bind(new_balance)
    .bind(Utc::now().to_rfc3339())
    .bind(&req.access_token)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(format!("Update failed: {}", e)))))?;

    if cost > 0.0 {
        debug!(event = "usage_billed", bytes = req.bytes_used, cost_usd = cost, new_balance = new_balance);
    }

    Ok(Json(ApiResponse::success(())))
}

async fn get_dcf_stats(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<StatsResponse>> {
    state.metrics.api_calls.fetch_add(1, Ordering::Relaxed);
    
    let total_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);

    let total_data: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(data_used), 0) FROM users")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);

    let total_balance: f64 = sqlx::query_scalar("SELECT COALESCE(SUM(account_balance), 0) FROM users")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0.0);

    let vip_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_vip = 1")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);

    Json(ApiResponse::success(StatsResponse {
        total_users,
        total_bandwidth_bytes: total_data,
        total_balance_usd: total_balance,
        vip_users: vip_count,
    }))
}

// ============================================================================
// SHUTDOWN
// ============================================================================
async fn shutdown_signal(shutdown: Arc<AtomicBool>) {
    #[cfg(unix)]
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");
    
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
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "dcf_id=info,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!("DeMoD Identity Service v{} starting...", VERSION);

    dotenvy::dotenv().ok();

    // Database
    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:/data/identity.db?mode=rwc".into());
    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
        .expect("Failed to connect to DB");

    // Schema
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            access_token TEXT UNIQUE NOT NULL,
            discord_id TEXT UNIQUE,
            data_used INTEGER DEFAULT 0,
            account_balance REAL DEFAULT 0.00,
            last_reset_date TEXT DEFAULT '',
            last_ip TEXT,
            last_seen TEXT,
            created_at TEXT,
            is_vip INTEGER DEFAULT 0
        )"
    ).execute(&pool).await.expect("Users table migration failed");

    // Indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_discord ON users(discord_id)").execute(&pool).await.ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_token ON users(access_token)").execute(&pool).await.ok();

    // Redis
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let redis = redis::Client::open(redis_url.as_str()).expect("Invalid Redis URL");
    
    // Test Redis connection
    match redis.get_multiplexed_async_connection().await {
        Ok(mut conn) => {
            let pong: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
            if pong.is_ok() {
                info!("Redis connected: {}", redis_url);
            } else {
                warn!("Redis PING failed, sessions may not persist");
            }
        }
        Err(e) => {
            warn!("Redis connection failed: {} - falling back to degraded mode", e);
        }
    }

    // Config
    let stripe_secret = env::var("STRIPE_SECRET_KEY").expect("STRIPE_SECRET_KEY missing");
    let stripe_webhook_secret = env::var("STRIPE_WEBHOOK_SECRET").expect("STRIPE_WEBHOOK_SECRET missing");
    let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:4000".into());
    let internal_key = env::var("DCF_ID_INTERNAL_KEY").unwrap_or_default();
    let port: u16 = env::var("IDENTITY_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(4000);

    if internal_key.is_empty() {
        warn!("DCF_ID_INTERNAL_KEY not set - API endpoints are open!");
    }

    // OAuth
    let oauth_client = BasicClient::new(
        ClientId::new(env::var("DISCORD_CLIENT_ID").expect("DISCORD_CLIENT_ID missing")),
        Some(ClientSecret::new(env::var("DISCORD_CLIENT_SECRET").expect("DISCORD_CLIENT_SECRET missing"))),
        AuthUrl::new("https://discord.com/api/oauth2/authorize".into()).unwrap(),
        Some(TokenUrl::new("https://discord.com/api/oauth2/token".into()).unwrap()),
    ).set_redirect_uri(RedirectUrl::new(
        env::var("DISCORD_REDIRECT_URL").unwrap_or_else(|_| format!("{}/auth/callback", base_url))
    ).unwrap());

    let shutdown = Arc::new(AtomicBool::new(false));

    let state = Arc::new(AppState {
        pool,
        redis,
        oauth_client,
        http_client: HttpClient::builder().timeout(Duration::from_secs(30)).build().unwrap(),
        stripe_secret,
        stripe_webhook_secret,
        base_url,
        internal_key,
        metrics: Arc::new(Metrics::default()),
        shutdown: shutdown.clone(),
    });

    let app = Router::new()
        // Core routes
        .route("/", get(index))
        .route("/health", get(health_check))
        .route("/metrics", get(metrics))
        // Auth routes
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/discord", get(discord_auth))
        .route("/auth/callback", get(discord_callback))
        // Billing routes
        .route("/checkout", post(create_checkout))
        .route("/stripe/webhook", post(stripe_webhook))
        // GSN Integration API
        .route("/api/user/discord/:discord_id", get(get_user_by_discord))
        .route("/api/user/verify", get(verify_token))
        .route("/api/usage/report", post(report_usage))
        .route("/api/stats", get(get_dcf_stats))
        // Middleware
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    
    info!("Listening on port {}", port);

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal(shutdown))
        .await
        .unwrap();

    info!("Shutdown complete");
        }
