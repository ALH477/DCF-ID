// ============================================================================
// DeMoD Communications Framework - Identity & Billing Service
// ============================================================================
// Copyright (c) 2024-2025 DeMoD LLC. All Rights Reserved.
// ============================================================================
// PATCHED VERSION - Production Ready
// Changes:
//   - Added GSN integration API routes
//   - Fixed CSRF validation on OAuth
//   - Added session persistence to SQLite
//   - Added Stripe webhook timestamp validation
//   - Added internal API key authentication
//   - Improved username collision handling
//   - Added database indexes
// ============================================================================

use axum::{
    extract::{ConnectInfo, Form, Path, Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Router,
};
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
    collections::HashMap,
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
use tokio::{signal, sync::RwLock, time::sleep};
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
const MAX_LOGIN_ATTEMPTS: u32 = 5;
const LOCKOUT_DURATION_SECS: i64 = 900; // 15 minutes
const MIN_PASSWORD_LENGTH: usize = 8;
const MAX_USERNAME_LENGTH: usize = 32;
const CSRF_TOKEN_DURATION_SECS: i64 = 600; // 10 minutes
const STRIPE_WEBHOOK_TOLERANCE_SECS: i64 = 300; // 5 minutes

// ============================================================================
// APPLICATION STATE
// ============================================================================
#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    oauth_client: BasicClient,
    http_client: HttpClient,
    login_attempts: Arc<RwLock<HashMap<String, LoginAttempts>>>,
    csrf_tokens: Arc<RwLock<HashMap<String, i64>>>, // CSRF token -> expires_at
    stripe_secret: String,
    stripe_webhook_secret: String,
    base_url: String,
    internal_key: String, // For service-to-service auth
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Default)]
struct LoginAttempts {
    count: u32,
    last_attempt: i64,
    lockout_until: Option<i64>,
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
    state: String, // Now validated!
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
    metadata: Option<HashMap<String, String>>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct MetricsResponse {
    requests_total: u64,
    logins_success: u64,
    logins_failed: u64,
    registrations: u64,
    payments_total: u64,
    api_calls: u64,
}

// ============================================================================
// GSN INTEGRATION TYPES
// ============================================================================
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
        return true; // Dev mode: no key required
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

// Session persistence helpers
async fn save_session(pool: &SqlitePool, session_id: &str, username: &str, expires_at: i64, ip: &str) {
    let _ = sqlx::query(
        "INSERT OR REPLACE INTO sessions (id, username, expires_at, created_ip, created_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(session_id)
    .bind(username)
    .bind(expires_at)
    .bind(ip)
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await;
}

async fn get_session(pool: &SqlitePool, session_id: &str) -> Option<(String, i64)> {
    sqlx::query("SELECT username, expires_at FROM sessions WHERE id = ? AND expires_at > ?")
        .bind(session_id)
        .bind(Utc::now().timestamp())
        .fetch_optional(pool)
        .await
        .ok()?
        .map(|row| (row.get("username"), row.get("expires_at")))
}

async fn delete_session(pool: &SqlitePool, session_id: &str) {
    let _ = sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(session_id)
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
    
    Json(HealthResponse {
        status: if db_ok { "healthy" } else { "degraded" },
        version: VERSION,
        uptime_secs: start.elapsed().as_secs(),
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
    })
}

async fn index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    
    // Check for session cookie
    if let Some(cookie) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(session_id) = part.strip_prefix("session=") {
                    // Check database for session (persistent)
                    if let Some((username, _)) = get_session(&state.pool, session_id).await {
                        let user = dashboard_logic(&state.pool, &username).await;
                        return Html(render_index(user));
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
            
            // Persist session to database
            save_session(&state.pool, &session_id, &payload.username, expires_at, &client_ip).await;

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
    
    // Rate limiting
    {
        let attempts = state.login_attempts.read().await;
        if let Some(attempt) = attempts.get(&client_ip) {
            if let Some(lockout_until) = attempt.lockout_until {
                if now < lockout_until {
                    return render_error(format!("Too many attempts. Try again in {} seconds.", lockout_until - now));
                }
            }
        }
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
        { let mut attempts = state.login_attempts.write().await; attempts.remove(&client_ip); }
        
        info!(event = "login_success", username = %payload.username);
        state.metrics.logins_success.fetch_add(1, Ordering::Relaxed);
        update_user_ip(&state.pool, &payload.username, &client_ip).await;

        let session_id = generate_token(64);
        let expires_at = now + SESSION_DURATION_SECS;
        
        // Persist session
        save_session(&state.pool, &session_id, &payload.username, expires_at, &client_ip).await;

        let user = dashboard_logic(&state.pool, &payload.username).await;
        let html = render_index(user);
        let is_https = state.base_url.starts_with("https");
        
        Response::builder()
            .status(StatusCode::OK)
            .header(SET_COOKIE, create_session_cookie(&session_id, SESSION_DURATION_SECS, is_https))
            .body(html.into())
            .unwrap_or_else(|_| render_error("Response failed".into()))
    } else {
        {
            let mut attempts = state.login_attempts.write().await;
            let attempt = attempts.entry(client_ip.clone()).or_default();
            attempt.count += 1;
            attempt.last_attempt = now;
            if attempt.count >= MAX_LOGIN_ATTEMPTS {
                attempt.lockout_until = Some(now + LOCKOUT_DURATION_SECS);
                warn!(event = "ip_lockout", ip = %client_ip);
            }
        }
        state.metrics.logins_failed.fetch_add(1, Ordering::Relaxed);
        render_error("Invalid credentials".into())
    }
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(cookie) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie.to_str() {
            for part in cookie_str.split(';') {
                if let Some(session_id) = part.trim().strip_prefix("session=") {
                    delete_session(&state.pool, session_id).await;
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
// OAUTH HANDLERS (with CSRF protection)
// ============================================================================
async fn discord_auth(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (auth_url, csrf_token) = state.oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".into()))
        .url();
    
    // Store CSRF token with expiration
    {
        let mut csrf_tokens = state.csrf_tokens.write().await;
        csrf_tokens.insert(
            csrf_token.secret().clone(),
            Utc::now().timestamp() + CSRF_TOKEN_DURATION_SECS
        );
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
    {
        let mut csrf_tokens = state.csrf_tokens.write().await;
        match csrf_tokens.remove(&params.state) {
            Some(expires) if expires > Utc::now().timestamp() => {
                debug!("CSRF token validated");
            },
            _ => {
                warn!(event = "csrf_validation_failed", ip = %client_ip);
                return render_error("Invalid or expired OAuth state. Please try again.".into());
            }
        }
    }
    
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
    
    save_session(&state.pool, &session_id, &username, expires_at, &client_ip).await;
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
// STRIPE HANDLERS (with timestamp validation)
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
    
    // Get session username from database
    let username = if let Some(cookie) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie.to_str() {
            let mut found_username = None;
            for part in cookie_str.split(';') {
                if let Some(sid) = part.trim().strip_prefix("session=") {
                    if let Some((uname, _)) = get_session(&state.pool, sid).await {
                        found_username = Some(uname);
                        break;
                    }
                }
            }
            found_username
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
    
    // Timestamp validation (replay attack protection)
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
// GSN INTEGRATION API HANDLERS
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
            // Update last_seen
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

    // Calculate cost if over free tier
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
// BACKGROUND TASKS
// ============================================================================
fn spawn_session_cleanup(pool: SqlitePool, shutdown: Arc<AtomicBool>) {
    tokio::spawn(async move {
        while !shutdown.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(300)).await;
            let now = Utc::now().timestamp();
            let _ = sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
                .bind(now)
                .execute(&pool)
                .await;
        }
    });
}

fn spawn_csrf_cleanup(csrf_tokens: Arc<RwLock<HashMap<String, i64>>>, shutdown: Arc<AtomicBool>) {
    tokio::spawn(async move {
        while !shutdown.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(60)).await;
            let now = Utc::now().timestamp();
            let mut tokens = csrf_tokens.write().await;
            tokens.retain(|_, expires| *expires > now);
        }
    });
}

async fn shutdown_signal(shutdown: Arc<AtomicBool>) {
    // Create signal listeners BEFORE the async blocks
    // This ensures they're registered immediately, not lazily
    
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

    // Schema - Users table
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

    // Schema - Sessions table (NEW)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_ip TEXT,
            created_at TEXT,
            FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
        )"
    ).execute(&pool).await.expect("Sessions table migration failed");

    // Indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_discord ON users(discord_id)").execute(&pool).await.ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_token ON users(access_token)").execute(&pool).await.ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)").execute(&pool).await.ok();

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
    let csrf_tokens = Arc::new(RwLock::new(HashMap::new()));

    let state = Arc::new(AppState {
        pool: pool.clone(),
        oauth_client,
        http_client: HttpClient::builder().timeout(Duration::from_secs(30)).build().unwrap(),
        login_attempts: Arc::new(RwLock::new(HashMap::new())),
        csrf_tokens: csrf_tokens.clone(),
        stripe_secret,
        stripe_webhook_secret,
        base_url,
        internal_key,
        metrics: Arc::new(Metrics::default()),
        shutdown: shutdown.clone(),
    });

    spawn_session_cleanup(pool, shutdown.clone());
    spawn_csrf_cleanup(csrf_tokens, shutdown.clone());

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
        // GSN Integration API (NEW)
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
