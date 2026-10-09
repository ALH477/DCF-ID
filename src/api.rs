// ============================================================================
// The JSON half of the service: health, metrics, the Stripe webhook, and the
// GSN integration API. None of it renders HTML, so it lives in the library and
// `cargo test --lib` can serve it on a real socket.
// ============================================================================
use crate::billing::{self, CreditOutcome, SignatureError, StripeEvent, UsageError};
use crate::security::{self, security_headers};
use crate::state::AppState;
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{sync::atomic::Ordering, sync::Arc, time::Duration};
use tower_http::{compression::CompressionLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{error, warn};

/// Request bodies are forms and small JSON; the framework default (2 MB) lets a
/// stranger make the server read and hold 2 MB per request.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Serialize)]
pub struct MetricsResponse {
    pub requests_total: u64,
    pub logins_success: u64,
    pub logins_failed: u64,
    pub registrations: u64,
    pub payments_total: u64,
    pub api_calls: u64,
    pub redis_errors: u64,
    pub argon2_runs: u64,
    pub argon2_busy: u64,
}

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<T>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self { success: true, message: None, data: Some(data) }
    }
}

impl ApiResponse<()> {
    pub fn error(msg: impl Into<String>) -> Self {
        Self { success: false, message: Some(msg.into()), data: None }
    }
}

#[derive(Serialize)]
pub struct UserApiResponse {
    pub username: String,
    pub access_token: String,
    pub discord_id: Option<String>,
    pub data_used: i64,
    pub account_balance: f64,
    pub is_vip: bool,
    pub last_seen: Option<String>,
}

#[derive(Deserialize)]
pub struct UsageReportRequest {
    pub access_token: String,
    pub bytes_used: u64,
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub total_users: i64,
    pub total_bandwidth_bytes: i64,
    pub total_balance_usd: f64,
    pub vip_users: i64,
}

/// The routes with no HTML in them.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(metrics))
        .route("/stripe/webhook", post(stripe_webhook))
        .route("/api/user/discord/:discord_id", get(get_user_by_discord))
        .route("/api/user/verify", get(verify_token))
        .route("/api/usage/report", post(report_usage))
        .route("/api/stats", get(get_dcf_stats))
}

/// The layers every route gets, in one place so the tests and the binary agree.
pub fn finish(router: Router<Arc<AppState>>, state: Arc<AppState>) -> Router {
    let hsts = state.is_https();
    router
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(middleware::from_fn_with_state(hsts, security_headers))
        .with_state(state)
}

fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<UserApiResponse, sqlx::Error> {
    Ok(UserApiResponse {
        username: row.try_get("username")?,
        access_token: row.try_get("access_token")?,
        discord_id: row.try_get("discord_id")?,
        data_used: row.try_get::<Option<i64>, _>("data_used")?.unwrap_or(0),
        account_balance: row.try_get::<Option<f64>, _>("account_balance")?.unwrap_or(0.0),
        is_vip: row.try_get::<Option<i64>, _>("is_vip")?.unwrap_or(0) == 1,
        last_seen: row.try_get("last_seen")?,
    })
}

// ---------------------------------------------------------------------------
// Health and metrics
// ---------------------------------------------------------------------------
/// Open, and says only whether the service is up: no version, uptime or backend detail to strangers.
pub async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").fetch_one(&state.pool).await.is_ok();
    let redis_ok = match state.redis_conn().await {
        Ok(mut c) => redis::cmd("PING").query_async::<_, String>(&mut c).await.is_ok(),
        Err(_) => false,
    };
    let status = if db_ok && redis_ok { "healthy" } else { "degraded" };
    Json(HealthResponse { status })
}

pub async fn metrics(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<MetricsResponse>, StatusCode> {
    if !state.api_auth.check(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(MetricsResponse {
        requests_total: state.metrics.requests_total.load(Ordering::Relaxed),
        logins_success: state.metrics.logins_success.load(Ordering::Relaxed),
        logins_failed: state.metrics.logins_failed.load(Ordering::Relaxed),
        registrations: state.metrics.registrations.load(Ordering::Relaxed),
        payments_total: state.metrics.payments_total.load(Ordering::Relaxed),
        api_calls: state.metrics.api_calls.load(Ordering::Relaxed),
        redis_errors: state.metrics.redis_errors.load(Ordering::Relaxed),
        argon2_runs: state.metrics.argon2_runs.load(Ordering::Relaxed),
        argon2_busy: state.metrics.argon2_busy.load(Ordering::Relaxed),
    }))
}

// ---------------------------------------------------------------------------
// Stripe webhook
// ---------------------------------------------------------------------------
pub async fn stripe_webhook(State(state): State<Arc<AppState>>, headers: HeaderMap, body: String) -> StatusCode {
    let signature = headers.get("stripe-signature").and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Err(e) = billing::verify_stripe_signature(&body, signature, &state.stripe_webhook_secret, Utc::now().timestamp()) {
        billing::warn_signature(&e);
        return match e {
            SignatureError::NoSecret => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        };
    }
    let event: StripeEvent = match serde_json::from_str(&body) {
        Ok(e) => e,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    if event.event_type != "checkout.session.completed" {
        return StatusCode::OK;
    }
    match billing::credit_checkout(&state.pool, &event).await {
        Ok(CreditOutcome::Credited { cents, .. }) => {
            state.metrics.payments_total.fetch_add(1, Ordering::Relaxed);
            state.metrics.payments_amount_cents.fetch_add(cents, Ordering::Relaxed);
            StatusCode::OK
        }
        Ok(CreditOutcome::Duplicate) => {
            tracing::info!(event = "stripe_event_duplicate", "already credited");
            StatusCode::OK
        }
        Ok(CreditOutcome::NoSuchUser { .. }) => StatusCode::OK,
        Ok(CreditOutcome::Ignored(why)) => {
            warn!(event = "stripe_event_ignored", why);
            StatusCode::OK
        }
        Ok(CreditOutcome::Rejected(why)) => {
            error!(event = "stripe_event_rejected", why);
            StatusCode::BAD_REQUEST
        }
        Err(e) => {
            // Not recorded, not credited: let Stripe retry.
            error!("stripe credit failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// GSN integration API
// ---------------------------------------------------------------------------
pub async fn get_user_by_discord(
    Path(discord_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<UserApiResponse>>, StatusCode> {
    state.metrics.api_calls.fetch_add(1, Ordering::Relaxed);
    if !state.api_auth.check(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !security::valid_discord_id(&discord_id) {
        return Err(StatusCode::NOT_FOUND);
    }
    let row = sqlx::query(
        "SELECT username, access_token, discord_id, data_used, account_balance, is_vip, last_seen
         FROM users WHERE discord_id = ?",
    )
    .bind(&discord_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        error!("discord lookup: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    match row {
        Some(row) => user_from_row(&row).map(|u| Json(ApiResponse::success(u))).map_err(|e| {
            error!("discord lookup: bad row: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn verify_token(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<UserApiResponse>>, StatusCode> {
    state.metrics.api_calls.fetch_add(1, Ordering::Relaxed);
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    // A token has exactly one shape; anything else cannot be one and is not looked up.
    if !security::valid_access_token(token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let row = sqlx::query(
        "SELECT username, access_token, discord_id, data_used, account_balance, is_vip, last_seen
         FROM users WHERE access_token = ?",
    )
    .bind(token)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        error!("verify_token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    match row {
        Some(row) => {
            let user = user_from_row(&row).map_err(|e| {
                error!("verify_token: bad row: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            let _ = sqlx::query("UPDATE users SET last_seen = ? WHERE access_token = ?")
                .bind(Utc::now().to_rfc3339())
                .bind(token)
                .execute(&state.pool)
                .await;
            Ok(Json(ApiResponse::success(user)))
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

pub async fn report_usage(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UsageReportRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    state.metrics.api_calls.fetch_add(1, Ordering::Relaxed);
    let fail = |code: StatusCode, msg: &str| (code, Json(ApiResponse::error(msg)));

    if !state.api_auth.check(&headers) {
        return Err(fail(StatusCode::UNAUTHORIZED, "Invalid internal key"));
    }
    if req.bytes_used > billing::MAX_REPORT_BYTES {
        return Err(fail(StatusCode::BAD_REQUEST, "bytes_used is too large for one report"));
    }
    if !security::valid_access_token(&req.access_token) {
        return Err(fail(StatusCode::NOT_FOUND, "User not found"));
    }
    match billing::apply_usage(&state.pool, &req.access_token, req.bytes_used).await {
        Ok(()) => Ok(Json(ApiResponse::success(()))),
        Err(UsageError::NotFound) => Err(fail(StatusCode::NOT_FOUND, "User not found")),
        Err(UsageError::TooLarge) => Err(fail(StatusCode::BAD_REQUEST, "bytes_used is too large for one report")),
        Err(UsageError::OutOfRange) => {
            error!("usage counter out of range for a token; refusing to change it");
            Err(fail(StatusCode::CONFLICT, "Usage counter is out of range"))
        }
        Err(UsageError::Db(e)) => {
            error!("usage report failed: {}", e); // the detail stays in the log, not in the reply
            Err(fail(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"))
        }
    }
}

pub async fn get_dcf_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<StatsResponse>>, StatusCode> {
    state.metrics.api_calls.fetch_add(1, Ordering::Relaxed);
    if !state.api_auth.check(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let total_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(&state.pool).await.unwrap_or(0);
    let total_data: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(data_used), 0) FROM users").fetch_one(&state.pool).await.unwrap_or(0);
    let total_balance: f64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(account_balance), 0) FROM users").fetch_one(&state.pool).await.unwrap_or(0.0);
    let vip_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_vip = 1").fetch_one(&state.pool).await.unwrap_or(0);
    Ok(Json(ApiResponse::success(StatsResponse {
        total_users,
        total_bandwidth_bytes: total_data,
        total_balance_usd: total_balance,
        vip_users: vip_count,
    })))
}

#[cfg(test)]
pub(crate) mod tests;
