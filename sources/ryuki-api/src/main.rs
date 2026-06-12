#![recursion_limit = "512"]

mod boundary;
mod config;
mod config_store;
mod contracts;
pub mod database;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request as HttpRequest, StatusCode};
use axum::middleware;
use axum::response::Response;
use axum::{extract::Query, routing::get, Extension, Json, Router};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::time::Instant;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::Instrument;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::database::MigrationStatus;
use ryuki_core::config::AuthMode;
use ryuki_core::types::{ApiError, ValidationResult};
use ryuki_engine::auth::AuthSession;

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
fn resolve_auth_metadata(header: Option<&str>, provider_mode: &'static str) -> AuthLogFields {
    AuthLogFields {
        auth_header_present: header.is_some(),
        provider_mode,
    }
}

fn auth_session_for_request(auth_mode: AuthMode, auth_header: Option<&str>) -> AuthSession {
    match auth_mode {
        AuthMode::MockDryRun | AuthMode::StaticDryRun | AuthMode::Local => {
            AuthSession::static_dry_run()
        }
        AuthMode::EntraId => auth_header
            .map(ryuki_engine::auth::validate_token)
            .unwrap_or_else(AuthSession::unverified_entra),
    }
}

#[derive(sqlx::FromRow)]
struct DbAuthSessionRow {
    user_id: String,
    display_name: String,
    roles: Vec<String>,
}

fn unverified_session(provider_mode: &str) -> AuthSession {
    AuthSession {
        user_id: "unauthenticated".into(),
        display_name: "Unauthenticated".into(),
        roles: Vec::new(),
        token_valid: false,
        provider_mode: provider_mode.into(),
    }
}

fn session_from_db_row(row: DbAuthSessionRow) -> AuthSession {
    AuthSession {
        user_id: row.user_id,
        display_name: row.display_name,
        roles: row.roles,
        token_valid: true,
        provider_mode: "persisted-session".into(),
    }
}

fn bearer_value(auth_header: Option<&str>) -> Option<&str> {
    auth_header?.trim().strip_prefix("Bearer ").map(str::trim)
}

fn session_id_from_headers(
    headers: &HeaderMap,
    auth_header: Option<&str>,
) -> Option<Result<Uuid, ()>> {
    if let Some(raw_session_id) = headers
        .get("X-Ryuki-Session-Id")
        .and_then(|value| value.to_str().ok())
    {
        return Some(Uuid::parse_str(raw_session_id.trim()).map_err(|_| ()));
    }

    let auth_value = bearer_value(auth_header)?;
    if auth_value.is_empty() {
        return None;
    }
    Uuid::parse_str(auth_value).ok().map(Ok)
}

async fn auth_session_from_persisted_session(
    headers: &HeaderMap,
    auth_header: Option<&str>,
) -> Option<AuthSession> {
    let session_id = match session_id_from_headers(headers, auth_header)? {
        Ok(session_id) => session_id,
        Err(()) => return Some(unverified_session("invalid-session-id")),
    };
    let pool = crate::database::get_db()?;
    match sqlx::query_as::<_, DbAuthSessionRow>(
        "SELECT user_id, display_name, roles FROM sessions WHERE id = $1 AND expires_at > NOW()",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(row)) => Some(session_from_db_row(row)),
        Ok(None) => Some(unverified_session("session-not-found")),
        Err(error) => {
            tracing::error!(error = %error, "auth session lookup failed");
            Some(unverified_session("session-lookup-failed"))
        }
    }
}

fn is_unsafe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn is_auth_exempt_path(path: &str) -> bool {
    matches!(path, "/api/auth/login" | "/api/auth/logout")
}

fn auth_session_allows_unsafe_method(session: &AuthSession) -> bool {
    session.token_valid || session.provider_mode == "static-dry-run"
}

async fn auth_middleware(
    headers: HeaderMap,
    mut request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    let auth_mode = crate::config_store::get_app_config().auth_mode.clone();
    let log = resolve_auth_metadata(auth_header, auth_mode.as_str());
    tracing::info!(
        auth_header_present = log.auth_header_present,
        provider_mode = log.provider_mode,
        "auth middleware"
    );
    let session = auth_session_from_persisted_session(&headers, auth_header)
        .await
        .unwrap_or_else(|| auth_session_for_request(auth_mode, auth_header));

    if is_unsafe_method(&method)
        && !is_auth_exempt_path(&path)
        && !auth_session_allows_unsafe_method(&session)
    {
        let body = serde_json::to_string(&ApiError::new(
            "AUTH_REQUIRED",
            "Verified authentication is required for this operation",
        ))
        .unwrap_or_else(|_| {
            r#"{"error":"AUTH_REQUIRED","message":"Verified authentication is required for this operation"}"#.into()
        });
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
    }

    request.extensions_mut().insert(session);
    next.run(request).await
}

async fn request_id_middleware(mut request: HttpRequest<Body>, next: middleware::Next) -> Response {
    let request_id = request
        .headers()
        .get("traceparent")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| {
            let parts: Vec<&str> = v.splitn(4, '-').collect();
            if parts.len() >= 2 && parts[1].len() == 32 {
                Some(parts[1].to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| Uuid::new_v4().to_string());

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
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id).unwrap_or(HeaderValue::from_static("unknown")),
    );
    let span_id = Uuid::new_v4().to_string().replace('-', "");
    headers.insert(
        HeaderName::from_static("traceresponse"),
        HeaderValue::from_str(&format!("00-{}-{}-01", request_id, &span_id[..16])).unwrap_or(
            HeaderValue::from_static("00-00000000000000000000000000000000-0000000000000000-01"),
        ),
    );
    response
}

#[derive(Debug, Clone)]
struct RequestId(String);

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static START_TIME: OnceLock<Instant> = OnceLock::new();
static DRAINING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessStatus {
    Ready,
    ConfigInvalid,
    DatabaseUnavailable,
    MigrationsNotApplied,
    MigrationsFailed,
    DatabaseUnusable,
}

/// Per-endpoint request counts keyed by "METHOD /path".
/// Uses std::sync::Mutex with HashMap — acceptable for dev/light production.
/// For high-throughput deployments, replace with dashmap or sharded approach.
struct PerEndpointCounter {
    counts: Mutex<HashMap<String, u64>>,
}

static PER_ENDPOINT: OnceLock<PerEndpointCounter> = OnceLock::new();

fn per_endpoint() -> &'static PerEndpointCounter {
    PER_ENDPOINT.get_or_init(|| PerEndpointCounter {
        counts: Mutex::new(HashMap::new()),
    })
}

fn set_draining() {
    DRAINING.store(true, Ordering::Release);
}

fn is_draining() -> bool {
    DRAINING.load(Ordering::Acquire)
}

async fn cache_control_middleware(request: HttpRequest<Body>, next: middleware::Next) -> Response {
    let path = request.uri().path().to_string();
    let is_contract = path.contains("-contract") || path.contains("/contract");
    let mut response = next.run(request).await;
    if is_contract && response.status().is_success() {
        response.headers_mut().insert(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("public, max-age=300"),
        );
    }
    response
}

async fn request_counter_middleware(
    request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let label = format!(
        "{} {}",
        request.method(),
        normalize_metrics_path(request.uri().path())
    );
    {
        let mut counts = per_endpoint().counts.lock().unwrap();
        *counts.entry(label).or_insert(0) += 1;
    }
    next.run(request).await
}

fn normalize_metrics_path(path: &str) -> String {
    let segments: Vec<String> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if Uuid::parse_str(segment).is_ok() || segment.chars().all(|c| c.is_ascii_digit()) {
                "{id}".to_string()
            } else {
                segment.to_ascii_lowercase()
            }
        })
        .collect();

    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
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
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();

    let response = next.run(request).await;
    let duration_us = start.elapsed().as_micros() as u64;
    let status = response.status();

    tracing::info!(
        method = %method,
        path = %path,
        status = status.as_u16(),
        duration_us,
        request_id = %request_id,
        "access"
    );

    let tracker = duration_tracker();
    let mut durations = tracker.durations.lock().unwrap();
    if durations.len() >= 10_000 {
        durations.remove(0);
    }
    durations.push(duration_us);

    response
}

type SharedRateLimiter = Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>;

#[derive(Clone)]
struct RateLimiters {
    default: SharedRateLimiter,
    path_overrides: Arc<HashMap<String, SharedRateLimiter>>,
}

impl RateLimiters {
    fn for_path_group(&self, path_group: &str) -> &SharedRateLimiter {
        self.path_overrides.get(path_group).unwrap_or(&self.default)
    }

    #[cfg(test)]
    fn has_override(&self, path_group: &str) -> bool {
        self.path_overrides.contains_key(path_group)
    }
}

type SharedRateLimiters = Arc<RateLimiters>;

async fn rate_limit_middleware(
    limiter: Option<SharedRateLimiters>,
    request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    if let Some(ref limiters) = limiter {
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

        let path_group = rate_limit_path_group(request.uri().path());

        let key = format!("{path_group}:{client_key}");
        let limiter = limiters.for_path_group(&path_group);

        if limiter.check_key(&key).is_err() {
            tracing::warn!(client = %client_key, path_group, "rate limit exceeded");
            let body =
                serde_json::to_string(&ApiError::new("RATE_LIMIT_EXCEEDED", "Too many requests"))
                    .unwrap_or_else(|_| {
                        r#"{"error":"RATE_LIMIT_EXCEEDED","message":"Too many requests"}"#.into()
                    });
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
        }
    }

    next.run(request).await
}

fn rate_limit_path_group(path: &str) -> String {
    path.split('/')
        .nth(1)
        .filter(|s| !s.is_empty())
        .unwrap_or("root")
        .to_ascii_lowercase()
}

fn normalize_rate_limit_override_key(path_group: &str) -> String {
    let normalized = path_group.trim_matches('/').trim().to_ascii_lowercase();
    if normalized.is_empty() {
        "root".into()
    } else {
        normalized
    }
}

fn rate_limit_quota(requests_per_second: u64, burst_size: u32) -> Quota {
    let requests_per_second = u32::try_from(requests_per_second).unwrap_or(u32::MAX);
    Quota::per_second(NonZeroU32::new(requests_per_second).unwrap_or(NonZeroU32::MIN))
        .allow_burst(NonZeroU32::new(burst_size).unwrap_or(NonZeroU32::MIN))
}

fn create_rate_limiter(config: &ryuki_core::config::RateLimitConfig) -> Option<SharedRateLimiters> {
    if !config.enabled {
        return None;
    }
    let default = Arc::new(RateLimiter::keyed(rate_limit_quota(
        config.requests_per_second,
        config.burst_size,
    )));

    let path_overrides = config
        .path_overrides
        .iter()
        .map(|(path_group, override_config)| {
            (
                normalize_rate_limit_override_key(path_group),
                Arc::new(RateLimiter::keyed(rate_limit_quota(
                    override_config.requests_per_second,
                    override_config.burst_size,
                ))),
            )
        })
        .collect();

    Some(Arc::new(RateLimiters {
        default,
        path_overrides: Arc::new(path_overrides),
    }))
}

async fn security_headers_middleware(
    request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    let security = &crate::config_store::get_app_config().security;
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    headers.insert(
        HeaderName::from_static("x-download-options"),
        HeaderValue::from_static("noopen"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_str(&security.content_security_policy)
            .unwrap_or(HeaderValue::from_static("default-src 'self'")),
    );
    if security.hsts_enabled {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_str(&format!(
                "max-age={}; includeSubDomains",
                security.hsts_max_age_secs
            ))
            .unwrap_or(HeaderValue::from_static("max-age=31536000")),
        );
    }
    headers.insert(
        HeaderName::from_static("x-api-version"),
        HeaderValue::from_static("0.1.0"),
    );
    response
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
    set_draining();
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

    database::try_connect_with_url(
        &app_config.database_url,
        app_config.server.pool_max_connections,
        app_config.server.pool_min_connections,
        app_config.server.pool_idle_timeout_secs,
        app_config.server.pool_acquire_timeout_secs,
        app_config.server.pool_max_lifetime_secs,
    )
    .await;
    database::migrate_if_connected().await;

    let rate_limiter = create_rate_limiter(&app_config.rate_limit);

    let cors_origins: Vec<_> = app_config
        .cors
        .allowed_origins
        .iter()
        .filter_map(|o| {
            o.parse()
                .inspect_err(
                    |e| tracing::warn!(origin = %o, error = %e, "invalid CORS origin, skipping"),
                )
                .ok()
        })
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::list(cors_origins))
        .allow_methods(Any)
        .allow_headers(Any)
        .max_age(Duration::from_secs(app_config.cors.max_age_secs));

    let compression =
        CompressionLayer::new().quality(tower_http::compression::CompressionLevel::Precise(
            app_config.server.compression_quality as i32,
        ));

    let body_limit = app_config.server.max_body_size_bytes;
    let timeout_secs = app_config.server.request_timeout_secs;

    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/validation/run", get(validation_run))
        .route("/api/platform/status", get(platform_status))
        .route("/api/platform/uptime", get(uptime))
        .merge(contracts::routes())
        .merge(boundary::routes())
        .fallback(not_found)
        .layer(ConcurrencyLimitLayer::new(
            app_config.server.max_concurrent_connections,
        ))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(middleware::from_fn(request_counter_middleware))
        .layer(middleware::from_fn(request_id_middleware))
        .layer(middleware::from_fn(
            move |req: HttpRequest<Body>, next: middleware::Next| {
                let limiter = rate_limiter.clone();
                async move { rate_limit_middleware(limiter, req, next).await }
            },
        ))
        .layer(middleware::from_fn(auth_middleware))
        .layer(middleware::from_fn(
            move |req: HttpRequest<Body>, next: middleware::Next| async move {
                let path = req.uri().path().to_string();
                match tokio::time::timeout(Duration::from_secs(timeout_secs), next.run(req)).await {
                    Ok(response) => response,
                    Err(_elapsed) => {
                        tracing::warn!(path = %path, timeout_secs, "request timeout");
                        let body = serde_json::to_string(&ApiError::new(
                            "REQUEST_TIMEOUT",
                            format!("Request exceeded {}s timeout", timeout_secs),
                        ))
                        .unwrap_or_else(|_| {
                            format!(r#"{{"error":"REQUEST_TIMEOUT","message":"Request exceeded {}s timeout"}}"#, timeout_secs)
                        });
                        Response::builder()
                            .status(StatusCode::GATEWAY_TIMEOUT)
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap()
                    }
                }
            },
        ))
        .layer(RequestBodyLimitLayer::new(body_limit))
        .layer(cors)
        .layer(compression)
        .layer(middleware::from_fn(cache_control_middleware))
        .layer(middleware::from_fn(timing_middleware));

    let listener = match tokio::net::TcpListener::bind(&app_config.server.bind_address).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(
                address = %app_config.server.bind_address,
                error = %e,
                "failed to bind to address"
            );
            std::process::exit(1);
        }
    };
    tracing::info!("ryuki-api listening on {}", app_config.server.bind_address);
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(app_config.server.shutdown_timeout_secs))
        .await
    {
        tracing::error!(error = %e, "server error");
        std::process::exit(1);
    }
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
    let validation_warnings = app_config.validation_warnings();

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
        config_warnings = validation_warnings.len(),
        auth_mode = %app_config.auth_mode.as_str(),
        rate_limit_enabled = app_config.rate_limit.enabled,
        "health check result"
    );

    Ok(Json(serde_json::json!({
        "status": status,
        "database": {
            "connected": db_connected,
            "provider": app_config.database_provider.as_str(),
        },
        "config": {
            "valid": validation_errors.is_empty(),
            "errors": validation_errors,
            "warnings": validation_warnings,
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

    if is_draining() {
        return Err(problem_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "DRAINING",
            "Server is draining and not accepting traffic",
            Some("Shutdown in progress"),
        ));
    }

    let readiness_status = readiness_check().await;
    let result = readiness_response(readiness_status);
    let status = if result.is_ok() { "ready" } else { "not_ready" };
    tracing::info!(status, ?readiness_status, "readiness check result");
    result
}

async fn readiness_check() -> ReadinessStatus {
    let app_config = crate::config_store::get_app_config();
    let validation_errors = app_config.validate();
    if !validation_errors.is_empty() {
        tracing::warn!(
            config_errors = validation_errors.len(),
            "readiness failed because hard config validation failed"
        );
        return ReadinessStatus::ConfigInvalid;
    }

    let Some(pool) = crate::database::get_db() else {
        return ReadinessStatus::DatabaseUnavailable;
    };

    let status = readiness_status_for_pool_state(true, crate::database::migration_status());
    if status != ReadinessStatus::Ready {
        return status;
    }

    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(pool)
        .await
    {
        Ok(1) => ReadinessStatus::Ready,
        Ok(_) => ReadinessStatus::DatabaseUnusable,
        Err(e) => {
            tracing::warn!(error = %e, "database readiness probe failed");
            ReadinessStatus::DatabaseUnusable
        }
    }
}

fn readiness_status_for_pool_state(
    pool_present: bool,
    migration_status: MigrationStatus,
) -> ReadinessStatus {
    if !pool_present {
        return ReadinessStatus::DatabaseUnavailable;
    }

    match migration_status {
        MigrationStatus::Applied => ReadinessStatus::Ready,
        MigrationStatus::NotApplied => ReadinessStatus::MigrationsNotApplied,
        MigrationStatus::Failed => ReadinessStatus::MigrationsFailed,
    }
}

fn readiness_response(status: ReadinessStatus) -> Result<Json<serde_json::Value>, ProblemDetails> {
    match status {
        ReadinessStatus::Ready => Ok(Json(serde_json::json!({
            "status": "ready",
            "database": {
                "connected": true,
                "migrations": "applied",
            },
        }))),
        ReadinessStatus::ConfigInvalid => Err(problem_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "CONFIG_INVALID",
            "Configuration is invalid",
            Some("Readiness requires hard config validation to pass"),
        )),
        ReadinessStatus::DatabaseUnavailable => Err(problem_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "DATABASE_UNAVAILABLE",
            "Database is unavailable",
            Some("Readiness requires an active database connection"),
        )),
        ReadinessStatus::MigrationsNotApplied => Err(problem_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "DATABASE_MIGRATIONS_NOT_APPLIED",
            "Database migrations are not applied",
            Some("Readiness requires completed database migrations"),
        )),
        ReadinessStatus::MigrationsFailed => Err(problem_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "DATABASE_MIGRATIONS_FAILED",
            "Database migrations failed",
            Some("Readiness requires successful database migrations"),
        )),
        ReadinessStatus::DatabaseUnusable => Err(problem_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "DATABASE_UNUSABLE",
            "Database is unusable",
            Some("Database readiness probe failed"),
        )),
    }
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

    body.push_str("# HELP ryuki_api_requests_per_endpoint_total Requests per endpoint\n");
    body.push_str("# TYPE ryuki_api_requests_per_endpoint_total counter\n");
    let counts = per_endpoint().counts.lock().unwrap();
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by_key(|(k, _)| *k);
    for (label, n) in &sorted {
        let parts: Vec<&str> = label.splitn(2, ' ').collect();
        let (method, path) = match parts.as_slice() {
            [m, p] => (*m, *p),
            _ => ("UNKNOWN", label.as_str()),
        };
        body.push_str(&format!(
            "ryuki_api_requests_per_endpoint_total{{method=\"{}\",path=\"{}\"}} {}\n",
            method, path, n
        ));
    }

    let pool = crate::database::pool_metrics();
    body.push_str("# HELP ryuki_db_pool_connections Database connection pool\n");
    body.push_str("# TYPE ryuki_db_pool_connections gauge\n");
    body.push_str(&format!(
        "ryuki_db_pool_connections{{state=\"size\"}} {}\n",
        pool.size
    ));
    body.push_str(&format!(
        "ryuki_db_pool_connections{{state=\"idle\"}} {}\n",
        pool.idle
    ));
    body.push_str(&format!(
        "ryuki_db_pool_connections{{state=\"active\"}} {}\n",
        pool.active
    ));
    body.push_str(&format!(
        "ryuki_db_pool_connected {}\n",
        if pool.connected { 1 } else { 0 }
    ));

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
    let elapsed = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);
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

async fn not_found() -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError::new(
            "NOT_FOUND",
            "The requested resource was not found",
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_auth_log_metadata_header_present() {
        let fields = resolve_auth_metadata(Some("Bearer redacted-token"), "static-dry-run");
        assert!(fields.auth_header_present);
        assert_eq!(fields.provider_mode, "static-dry-run");
    }

    #[test]
    fn test_auth_log_metadata_header_absent() {
        let fields = resolve_auth_metadata(None, "static-dry-run");
        assert!(!fields.auth_header_present);
        assert_eq!(fields.provider_mode, "static-dry-run");
    }

    #[test]
    fn test_auth_log_metadata_with_invalid_utf8_header() {
        // invalid header fallback: still present but unusable bytes
        let fields = resolve_auth_metadata(Some("invalid"), "entra-id");
        assert!(fields.auth_header_present);
        assert_eq!(fields.provider_mode, "entra-id");
    }

    #[test]
    fn test_static_auth_mode_ignores_authorization_header() {
        let session = auth_session_for_request(
            AuthMode::MockDryRun,
            Some("header.eyJyb2xlcyI6WyJQbGF0Zm9ybUFkbWluIl19.signature"),
        );
        assert_eq!(session.provider_mode, "static-dry-run");
        assert_eq!(session.roles, vec!["PlatformAdmin"]);
        assert!(!session.token_valid);
    }

    #[test]
    fn test_entra_auth_mode_rejects_unsigned_roles_claim() {
        let session = auth_session_for_request(
            AuthMode::EntraId,
            Some("header.eyJyb2xlcyI6WyJQbGF0Zm9ybUFkbWluIl19.signature"),
        );
        assert_eq!(session.provider_mode, "entra-id-unverified");
        assert!(session.roles.is_empty());
        assert!(!session.token_valid);
    }

    #[test]
    fn test_session_id_from_header() {
        let session_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Ryuki-Session-Id",
            HeaderValue::from_str(&session_id.to_string()).unwrap(),
        );

        let parsed = session_id_from_headers(&headers, None)
            .expect("session header should be recognized")
            .expect("session header should parse");
        assert_eq!(parsed, session_id);
    }

    #[test]
    fn test_session_id_from_bearer_uuid() {
        let session_id = Uuid::new_v4();
        let headers = HeaderMap::new();

        let parsed = session_id_from_headers(&headers, Some(&format!("Bearer {}", session_id)))
            .expect("bearer uuid should be recognized")
            .expect("bearer uuid should parse");
        assert_eq!(parsed, session_id);
    }

    #[test]
    fn test_non_uuid_bearer_is_not_session_id() {
        let headers = HeaderMap::new();
        assert!(session_id_from_headers(&headers, Some("Bearer jwt-token")).is_none());
    }

    #[test]
    fn test_db_session_row_maps_to_verified_session() {
        let session = session_from_db_row(DbAuthSessionRow {
            user_id: "platform-engineer".into(),
            display_name: "Platform Engineer".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_PLATFORM_ADMIN.into()],
        });

        assert_eq!(session.provider_mode, "persisted-session");
        assert!(session.token_valid);
        assert!(session
            .roles
            .contains(&ryuki_engine::auth::APP_ROLE_PLATFORM_ADMIN.to_string()));
    }

    #[test]
    fn test_unsafe_method_detection() {
        assert!(is_unsafe_method(&Method::POST));
        assert!(is_unsafe_method(&Method::PUT));
        assert!(is_unsafe_method(&Method::PATCH));
        assert!(is_unsafe_method(&Method::DELETE));
        assert!(!is_unsafe_method(&Method::GET));
    }

    #[test]
    fn test_auth_exempt_paths_are_limited_to_auth_flow() {
        assert!(is_auth_exempt_path("/api/auth/login"));
        assert!(is_auth_exempt_path("/api/auth/logout"));
        assert!(!is_auth_exempt_path("/api/requests"));
    }

    #[test]
    fn test_unsafe_method_auth_requires_static_or_verified_session() {
        let static_session = AuthSession::static_dry_run();
        let unverified = AuthSession::unverified_entra();
        let mut verified = AuthSession::unverified_entra();
        verified.token_valid = true;

        assert!(auth_session_allows_unsafe_method(&static_session));
        assert!(auth_session_allows_unsafe_method(&verified));
        assert!(!auth_session_allows_unsafe_method(&unverified));
    }

    #[test]
    fn test_normalize_metrics_path_replaces_uuid_segments() {
        assert_eq!(
            normalize_metrics_path("/api/requests/550e8400-e29b-41d4-a716-446655440000/execute"),
            "/api/requests/{id}/execute"
        );
    }

    #[test]
    fn test_normalize_metrics_path_replaces_numeric_segments() {
        assert_eq!(
            normalize_metrics_path("/api/catalog/items/12345"),
            "/api/catalog/items/{id}"
        );
        assert_eq!(normalize_metrics_path("/"), "/");
    }

    #[test]
    fn test_rate_limit_path_group_normalizes_first_path_segment() {
        assert_eq!(rate_limit_path_group("/health"), "health");
        assert_eq!(rate_limit_path_group("/API/platform/status"), "api");
        assert_eq!(rate_limit_path_group("/"), "root");
    }

    #[test]
    fn test_create_rate_limiter_normalizes_override_keys() {
        let mut config = ryuki_core::config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst_size: 1,
            path_overrides: HashMap::new(),
        };
        config.path_overrides.insert(
            "/HEALTH/".into(),
            ryuki_core::config::RateLimitPathOverride {
                requests_per_second: 2,
                burst_size: 2,
            },
        );

        let limiters = create_rate_limiter(&config).expect("rate limiter should be enabled");
        assert!(limiters.has_override("health"));
        assert!(!limiters.has_override("api"));
        assert!(!Arc::ptr_eq(
            limiters.for_path_group("health"),
            limiters.for_path_group("api")
        ));
    }

    #[test]
    fn test_path_override_limiter_enforces_separate_quota() {
        let mut config = ryuki_core::config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst_size: 1,
            path_overrides: HashMap::new(),
        };
        config.path_overrides.insert(
            "health".into(),
            ryuki_core::config::RateLimitPathOverride {
                requests_per_second: 2,
                burst_size: 2,
            },
        );

        let limiters = create_rate_limiter(&config).expect("rate limiter should be enabled");
        let default_key = "api:client-a".to_string();
        let health_key = "health:client-a".to_string();

        let default_limiter = limiters.for_path_group("api");
        assert!(default_limiter.check_key(&default_key).is_ok());
        assert!(default_limiter.check_key(&default_key).is_err());

        let health_limiter = limiters.for_path_group("health");
        assert!(health_limiter.check_key(&health_key).is_ok());
        assert!(health_limiter.check_key(&health_key).is_ok());
        assert!(health_limiter.check_key(&health_key).is_err());
    }

    #[test]
    fn test_readiness_response_with_db_is_ready() {
        let Json(body) =
            readiness_response(ReadinessStatus::Ready).expect("ready response should succeed");
        assert_eq!(body["status"], "ready");
        assert_eq!(body["database"]["connected"], true);
        assert_eq!(body["database"]["migrations"], "applied");
    }

    #[test]
    fn test_readiness_response_without_db_is_service_unavailable() {
        let Err((status, Json(body))) = readiness_response(ReadinessStatus::DatabaseUnavailable)
        else {
            panic!("readiness should fail when database is unavailable");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.error, "DATABASE_UNAVAILABLE");
    }

    #[test]
    fn test_readiness_response_for_invalid_config_is_safe_503() {
        let Err((status, Json(body))) = readiness_response(ReadinessStatus::ConfigInvalid) else {
            panic!("readiness should fail when config is invalid");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.error, "CONFIG_INVALID");
        assert_eq!(body.message, "Configuration is invalid");
        assert_eq!(
            body.detail,
            Some("Readiness requires hard config validation to pass".into())
        );
    }

    #[test]
    fn test_readiness_response_for_migrations_not_applied_is_safe_503() {
        let Err((status, Json(body))) = readiness_response(ReadinessStatus::MigrationsNotApplied)
        else {
            panic!("readiness should fail when migrations are not applied");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.error, "DATABASE_MIGRATIONS_NOT_APPLIED");
        assert_eq!(body.message, "Database migrations are not applied");
        assert_eq!(
            body.detail,
            Some("Readiness requires completed database migrations".into())
        );
    }

    #[test]
    fn test_readiness_response_for_failed_migrations_is_safe_503() {
        let Err((status, Json(body))) = readiness_response(ReadinessStatus::MigrationsFailed)
        else {
            panic!("readiness should fail when migrations failed");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.error, "DATABASE_MIGRATIONS_FAILED");
        assert_eq!(body.message, "Database migrations failed");
        assert_eq!(
            body.detail,
            Some("Readiness requires successful database migrations".into())
        );
    }

    #[test]
    fn test_readiness_response_for_unusable_database_is_safe_503() {
        let Err((status, Json(body))) = readiness_response(ReadinessStatus::DatabaseUnusable)
        else {
            panic!("readiness should fail when database probe fails");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.error, "DATABASE_UNUSABLE");
        assert_eq!(body.message, "Database is unusable");
        assert_eq!(body.detail, Some("Database readiness probe failed".into()));
    }

    #[test]
    fn test_readiness_status_requires_pool_before_migrations() {
        assert_eq!(
            readiness_status_for_pool_state(false, MigrationStatus::Applied),
            ReadinessStatus::DatabaseUnavailable
        );
    }

    #[test]
    fn test_readiness_status_requires_applied_migrations() {
        assert_eq!(
            readiness_status_for_pool_state(true, MigrationStatus::NotApplied),
            ReadinessStatus::MigrationsNotApplied
        );
        assert_eq!(
            readiness_status_for_pool_state(true, MigrationStatus::Failed),
            ReadinessStatus::MigrationsFailed
        );
        assert_eq!(
            readiness_status_for_pool_state(true, MigrationStatus::Applied),
            ReadinessStatus::Ready
        );
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
        if std::env::var("RYUKI_DATABASE_URL").is_err() {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        }
        let url = std::env::var("RYUKI_DATABASE_URL").unwrap();
        crate::database::try_connect_with_url(&url, 5, 2, 300, 30, 1800).await;
        let db = crate::database::get_db().expect("database should be available");
        crate::database::run_migrations(db)
            .await
            .expect("migrations should run");

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
