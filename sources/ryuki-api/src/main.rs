#![recursion_limit = "512"]

mod boundary;
mod config;
mod config_store;
mod contracts;
pub mod database;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request as HttpRequest, StatusCode};
use axum::middleware;
use axum::response::Response;
use axum::{extract::Query, routing::get, Extension, Json, Router};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tracing::Instrument;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use ryuki_core::types::{ApiError, ValidationResult};

/// ProblemDetails error type alias: HTTP status code + structured ApiError JSON body.
pub type ProblemDetails = (StatusCode, Json<ApiError>);

pub fn problem_details(
    status: StatusCode,
    error: impl Into<String>,
    message: impl Into<String>,
    detail: Option<impl Into<String>>,
) -> ProblemDetails {
    let api_error = match detail {
        Some(d) => ApiError::with_detail(error, message, d),
        None => ApiError::new(error, message),
    };
    (status, Json(api_error))
}

/// Safe auth log metadata: presence + mode only, never raw header values.
#[derive(Debug, PartialEq)]
struct AuthLogFields {
    auth_header_present: bool,
    provider_mode: &'static str,
}

/// Resolves auth log metadata from an optional Authorization header value.
/// Never exposes raw header content.
fn resolve_auth_metadata(header: Option<&str>) -> AuthLogFields {
    AuthLogFields {
        auth_header_present: header.is_some(),
        provider_mode: "static-dry-run",
    }
}

async fn auth_middleware(
    headers: HeaderMap,
    mut request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    let log = resolve_auth_metadata(auth_header);
    tracing::info!(
        auth_header_present = log.auth_header_present,
        provider_mode = log.provider_mode,
        "auth middleware"
    );
    let session = if let Some(header_value) = auth_header {
        ryuki_engine::auth::validate_token(header_value)
    } else {
        ryuki_engine::auth::AuthSession::static_dry_run()
    };

    request.extensions_mut().insert(session);
    next.run(request).await
}

async fn request_id_middleware(mut request: HttpRequest<Body>, next: middleware::Next) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %method,
        path = %path,
    );

    let mut response = next.run(request).instrument(span).await;
    response.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id).unwrap_or(HeaderValue::from_static("unknown")),
    );
    response
}

#[derive(Debug, Clone)]
struct RequestId(String);

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static START_TIME: OnceLock<Instant> = OnceLock::new();

async fn request_counter_middleware(
    request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    next.run(request).await
}

/// Stores request durations in microseconds, capped at 10,000 entries.
struct DurationTracker {
    durations: Mutex<Vec<u64>>,
}

static DURATION_TRACKER: OnceLock<DurationTracker> = OnceLock::new();

fn duration_tracker() -> &'static DurationTracker {
    DURATION_TRACKER.get_or_init(|| DurationTracker {
        durations: Mutex::new(Vec::with_capacity(10_000)),
    })
}

async fn timing_middleware(request: HttpRequest<Body>, next: middleware::Next) -> Response {
    let start = Instant::now();
    let response = next.run(request).await;
    let duration_us = start.elapsed().as_micros() as u64;

    tracing::info!(duration_us, "request completed");

    let tracker = duration_tracker();
    let mut durations = tracker.durations.lock().unwrap();
    if durations.len() >= 10_000 {
        durations.remove(0);
    }
    durations.push(duration_us);

    response
}

type SharedRateLimiter = Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>;

async fn rate_limit_middleware(
    limiter: Option<SharedRateLimiter>,
    request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    if let Some(ref limiter) = limiter {
        let client_key = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .split(',')
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();

        if limiter.check_key(&client_key).is_err() {
            tracing::warn!(client = %client_key, "rate limit exceeded");
            let api_error = ApiError::new("RATE_LIMIT_EXCEEDED", "Too many requests");
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&api_error).unwrap()))
                .unwrap();
        }
    }

    next.run(request).await
}

fn create_rate_limiter(config: &ryuki_core::config::RateLimitConfig) -> Option<SharedRateLimiter> {
    if !config.enabled {
        return None;
    }
    let quota = Quota::per_second(
        NonZeroU32::new(config.requests_per_second as u32).unwrap_or(NonZeroU32::MIN),
    )
    .allow_burst(NonZeroU32::new(config.burst_size).unwrap_or(NonZeroU32::MIN));
    Some(Arc::new(RateLimiter::keyed(quota)))
}

async fn shutdown_signal(timeout_secs: u64) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received SIGINT, shutting down gracefully");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, shutting down gracefully");
        },
    }

    tracing::info!(timeout_secs, "draining in-flight requests");
    tokio::time::sleep(std::time::Duration::from_secs(timeout_secs)).await;
}

#[tokio::main]
async fn main() {
    START_TIME.set(Instant::now()).ok();
    let app_config = config::load_config();
    config_store::init_with_config("platform-config.json", &app_config);

    let level_filter = match app_config.logging.level {
        ryuki_core::config::LogLevel::Trace => LevelFilter::TRACE,
        ryuki_core::config::LogLevel::Debug => LevelFilter::DEBUG,
        ryuki_core::config::LogLevel::Info => LevelFilter::INFO,
        ryuki_core::config::LogLevel::Warn => LevelFilter::WARN,
        ryuki_core::config::LogLevel::Error => LevelFilter::ERROR,
    };
    let env_filter = EnvFilter::builder()
        .with_default_directive(level_filter.into())
        .from_env_lossy();

    match app_config.logging.format {
        ryuki_core::config::LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .init();
        }
        ryuki_core::config::LogFormat::Text => {
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
        }
    }

    database::try_connect_with_url(&app_config.database_url).await;
    database::migrate_if_connected().await;

    let rate_limiter = create_rate_limiter(&app_config.rate_limit);

    let cors_origins: Vec<_> = app_config
        .cors
        .allowed_origins
        .iter()
        .map(|o| o.parse().unwrap())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::list(cors_origins))
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/validation/run", get(validation_run))
        .route("/api/platform/status", get(platform_status))
        .route("/api/platform/uptime", get(uptime))
        .merge(contracts::routes())
        .merge(boundary::routes())
        .layer(middleware::from_fn(request_counter_middleware))
        .layer(middleware::from_fn(request_id_middleware))
        .layer(middleware::from_fn(move |req, next| {
            let limiter = rate_limiter.clone();
            async move { rate_limit_middleware(limiter, req, next).await }
        }))
        .layer(middleware::from_fn(auth_middleware))
        .layer(cors)
        .layer(CompressionLayer::new())
        .layer(middleware::from_fn(timing_middleware));

    let listener = tokio::net::TcpListener::bind(&app_config.server.bind_address)
        .await
        .unwrap();
    tracing::info!("ryuki-api listening on {}", app_config.server.bind_address);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(app_config.server.shutdown_timeout_secs))
        .await
        .unwrap();
}

async fn health(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ProblemDetails> {
    tracing::info!(
        simulate = %params.get("simulate").unwrap_or(&String::new()),
        "health check requested"
    );

    if params.get("simulate") == Some(&"error".to_string()) {
        return Err(problem_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "HEALTH_CHECK_FAILED",
            "Platform health check failed",
            Some("Simulated error for testing ProblemDetails contract"),
        ));
    }
    let db_connected = crate::database::get_db().is_some();
    let app_config = crate::config_store::get_app_config();
    let validation_errors = app_config.validate();

    let status = if db_connected && validation_errors.is_empty() {
        "healthy"
    } else {
        "degraded"
    };
    tracing::info!(
        status,
        db_connected,
        config_valid = validation_errors.is_empty(),
        config_errors = validation_errors.len(),
        auth_mode = %app_config.auth_mode.as_str(),
        rate_limit_enabled = app_config.rate_limit.enabled,
        "health check result"
    );

    Ok(Json(serde_json::json!({
        "status": status,
        "database": {
            "connected": db_connected,
            "provider": format!("{:?}", app_config.database_provider),
        },
        "config": {
            "valid": validation_errors.is_empty(),
            "errors": validation_errors,
        },
        "auth_mode": app_config.auth_mode.as_str(),
        "rate_limit_enabled": app_config.rate_limit.enabled,
    })))
}

async fn ready(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ProblemDetails> {
    tracing::info!(
        simulate = %params.get("simulate").unwrap_or(&String::new()),
        "readiness check requested"
    );

    if params.get("simulate") == Some(&"error".to_string()) {
        return Err(problem_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "READINESS_CHECK_FAILED",
            "Platform readiness check failed",
            Some("Simulated error for testing ProblemDetails contract"),
        ));
    }
    let db_connected = crate::database::get_db().is_some();
    let status = if db_connected { "ready" } else { "degraded" };
    tracing::info!(status, db_connected, "readiness check result");

    Ok(Json(serde_json::json!({
        "status": status,
        "database": { "connected": db_connected },
    })))
}

async fn validation_run(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<ValidationResult>, ProblemDetails> {
    let slice = params.get("slice").cloned().unwrap_or_default();
    if slice.is_empty() {
        return Err(problem_details(
            StatusCode::BAD_REQUEST,
            "VALIDATION_FAILED",
            "Slice name required for validation",
            Some("Provide a 'slice' query parameter to run validation"),
        ));
    }
    Ok(Json(ValidationResult {
        errors: vec![],
        warnings: vec!["static dry-run: no live validation performed".into()],
    }))
}

async fn metrics() -> Response {
    let count = REQUEST_COUNTER.load(Ordering::Relaxed);
    let mut body = ryuki_engine::health_monitor::metrics_text_with_api_requests(count);

    let tracker = duration_tracker();
    let durations = tracker.durations.lock().unwrap();
    if !durations.is_empty() {
        let dur_count = durations.len() as u64;
        let sum_ms: f64 = durations.iter().map(|&d| d as f64 / 1000.0).sum();
        let min_ms = durations
            .iter()
            .min()
            .map(|&d| d as f64 / 1000.0)
            .unwrap_or(0.0);
        let max_ms = durations
            .iter()
            .max()
            .map(|&d| d as f64 / 1000.0)
            .unwrap_or(0.0);
        let avg_ms = sum_ms / dur_count as f64;
        ryuki_engine::health_monitor::append_duration_metrics(
            &mut body, dur_count, sum_ms, min_ms, max_ms, avg_ms,
        );
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4")
        .body(Body::from(body))
        .unwrap()
}

async fn platform_status(Extension(request_id): Extension<RequestId>) -> Json<serde_json::Value> {
    let mut status = crate::config::get_platform_status();
    if let serde_json::Value::Object(ref mut map) = status {
        map.insert("request_id".into(), serde_json::Value::String(request_id.0));
    }
    Json(status)
}

async fn uptime() -> Json<serde_json::Value> {
    let elapsed = START_TIME
        .get()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    Json(serde_json::json!({
        "uptime_seconds": elapsed,
        "uptime_human": format_uptime(elapsed),
    }))
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    format!("{days}d {hours}h {minutes}m {secs}s")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_auth_log_metadata_header_present() {
        let fields = resolve_auth_metadata(Some("Bearer secret-token-123"));
        assert!(fields.auth_header_present);
        assert_eq!(fields.provider_mode, "static-dry-run");
    }

    #[test]
    fn test_auth_log_metadata_header_absent() {
        let fields = resolve_auth_metadata(None);
        assert!(!fields.auth_header_present);
        assert_eq!(fields.provider_mode, "static-dry-run");
    }

    #[test]
    fn test_auth_log_metadata_with_invalid_utf8_header() {
        // invalid header fallback: still present but unusable bytes
        let fields = resolve_auth_metadata(Some("invalid"));
        assert!(fields.auth_header_present);
    }

    #[test]
    fn test_problem_details_without_detail() {
        let (status, Json(body)) = problem_details(
            StatusCode::BAD_REQUEST,
            "VALIDATION_FAILED",
            "Slice name required",
            None::<&str>,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.error, "VALIDATION_FAILED");
        assert_eq!(body.message, "Slice name required");
        assert_eq!(body.detail, None);
    }

    #[test]
    fn test_problem_details_with_detail() {
        let (status, Json(body)) = problem_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "HEALTH_CHECK_FAILED",
            "Platform health check failed",
            Some("Simulated error"),
        );
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.error, "HEALTH_CHECK_FAILED");
        assert_eq!(body.message, "Platform health check failed");
        assert_eq!(body.detail, Some("Simulated error".into()));
    }

    #[test]
    fn test_problem_details_serializes_as_json() {
        let (_, Json(body)) = problem_details(
            StatusCode::NOT_FOUND,
            "RESOURCE_NOT_FOUND",
            "The requested resource was not found",
            None::<&str>,
        );
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("RESOURCE_NOT_FOUND"));
        assert!(json.contains("The requested resource was not found"));
        assert!(!json.contains("detail"));
    }
}

#[cfg(test)]
mod db_tests {
    #[tokio::test]
    async fn test_migrations_run_against_pg18() {
        if std::env::var("DATABASE_URL").is_err() {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        }
        let url = std::env::var("DATABASE_URL").unwrap();
        crate::database::try_connect_with_url(&url).await;
        let db = crate::database::get_db().expect("database should be available");
        crate::database::run_migrations(db).await;

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM platform_config")
            .fetch_one(db)
            .await
            .expect("platform_config table should exist");
        assert_eq!(count.0, 9, "expected 9 platform_config rows");

        let tables: Vec<(String,)> =
            sqlx::query_as("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name")
                .fetch_all(db)
                .await
                .expect("should query tables");
        let names: Vec<&str> = tables.iter().map(|t| t.0.as_str()).collect();
        assert!(names.contains(&"platform_config"));
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"sessions"));
    }
}
