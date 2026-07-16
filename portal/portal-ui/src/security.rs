//! Browser and endpoint configuration controls for the SSR portal boundary.
#![cfg(feature = "ssr")]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header::ORIGIN, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{middleware, Router};
use tokio::sync::Semaphore;
use tower_http::limit::RequestBodyLimitLayer;

/// Canonical public origin used to validate browser-initiated mutations.
pub const PUBLIC_ORIGIN_ENV: &str = "RYUKI_PORTAL_PUBLIC_ORIGIN";
/// Explicit development/test escape hatch for plain HTTP on loopback only.
pub const ALLOW_INSECURE_LOOPBACK_ENV: &str = "RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK";
/// Maximum request body accepted by a portal server function.
pub const SERVER_FUNCTION_MAX_BODY_BYTES_ENV: &str = "RYUKI_PORTAL_SERVER_FN_MAX_BODY_BYTES";
/// Maximum number of portal server functions allowed to execute concurrently.
pub const SERVER_FUNCTION_MAX_CONCURRENCY_ENV: &str =
    "RYUKI_PORTAL_SERVER_FN_MAX_CONCURRENT_REQUESTS";
/// Wall-clock deadline for one portal server-function request.
pub const SERVER_FUNCTION_TIMEOUT_SECS_ENV: &str = "RYUKI_PORTAL_SERVER_FN_REQUEST_TIMEOUT_SECS";

const DEFAULT_SERVER_FUNCTION_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_SERVER_FUNCTION_MAX_CONCURRENCY: usize = 128;
const DEFAULT_SERVER_FUNCTION_TIMEOUT_SECS: u64 = 30;
const MAX_SERVER_FUNCTION_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_SERVER_FUNCTION_MAX_CONCURRENCY: usize = 1024;
const MAX_SERVER_FUNCTION_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalConfigError {
    variable: &'static str,
    reason: &'static str,
}

impl PortalConfigError {
    pub(crate) fn new(variable: &'static str, reason: &'static str) -> Self {
        Self { variable, reason }
    }
}

impl std::fmt::Display for PortalConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} {}", self.variable, self.reason)
    }
}

impl std::error::Error for PortalConfigError {}

/// Shared, process-local resource budget for the server-function catch-all.
///
/// The semaphore is deliberately non-queuing: once the admitted execution
/// budget is full, new work is rejected immediately instead of accumulating
/// unbounded request futures in front of Leptos or the upstream API.
#[derive(Debug, Clone)]
pub struct PortalServerFunctionLimits {
    max_body_bytes: usize,
    request_timeout: Duration,
    permits: Arc<Semaphore>,
}

impl PortalServerFunctionLimits {
    pub fn from_env() -> Result<Self, PortalConfigError> {
        Self::new(
            read_usize_env(
                SERVER_FUNCTION_MAX_BODY_BYTES_ENV,
                DEFAULT_SERVER_FUNCTION_MAX_BODY_BYTES,
            )?,
            read_usize_env(
                SERVER_FUNCTION_MAX_CONCURRENCY_ENV,
                DEFAULT_SERVER_FUNCTION_MAX_CONCURRENCY,
            )?,
            read_u64_env(
                SERVER_FUNCTION_TIMEOUT_SECS_ENV,
                DEFAULT_SERVER_FUNCTION_TIMEOUT_SECS,
            )?,
        )
    }

    pub fn new(
        max_body_bytes: usize,
        max_concurrent_requests: usize,
        request_timeout_secs: u64,
    ) -> Result<Self, PortalConfigError> {
        ensure_bounded(
            SERVER_FUNCTION_MAX_BODY_BYTES_ENV,
            max_body_bytes,
            MAX_SERVER_FUNCTION_MAX_BODY_BYTES,
        )?;
        ensure_bounded(
            SERVER_FUNCTION_MAX_CONCURRENCY_ENV,
            max_concurrent_requests,
            MAX_SERVER_FUNCTION_MAX_CONCURRENCY,
        )?;
        ensure_bounded(
            SERVER_FUNCTION_TIMEOUT_SECS_ENV,
            request_timeout_secs,
            MAX_SERVER_FUNCTION_TIMEOUT_SECS,
        )?;

        Ok(Self {
            max_body_bytes,
            request_timeout: Duration::from_secs(request_timeout_secs),
            permits: Arc::new(Semaphore::new(max_concurrent_requests)),
        })
    }

    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }
}

fn read_usize_env(variable: &'static str, default: usize) -> Result<usize, PortalConfigError> {
    match std::env::var(variable) {
        Ok(raw) => raw
            .trim()
            .parse::<usize>()
            .map_err(|_| PortalConfigError::new(variable, "must be a positive decimal integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(PortalConfigError::new(
            variable,
            "must contain valid Unicode",
        )),
    }
}

fn read_u64_env(variable: &'static str, default: u64) -> Result<u64, PortalConfigError> {
    match std::env::var(variable) {
        Ok(raw) => raw
            .trim()
            .parse::<u64>()
            .map_err(|_| PortalConfigError::new(variable, "must be a positive decimal integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(PortalConfigError::new(
            variable,
            "must contain valid Unicode",
        )),
    }
}

fn ensure_bounded<T>(variable: &'static str, value: T, maximum: T) -> Result<(), PortalConfigError>
where
    T: Copy + Ord + From<u8>,
{
    if value < T::from(1) {
        return Err(PortalConfigError::new(
            variable,
            "must be greater than zero",
        ));
    }
    if value > maximum {
        return Err(PortalConfigError::new(
            variable,
            "exceeds the portal safety ceiling",
        ));
    }
    Ok(())
}

/// Returns true only for the explicit opt-in value `true`.
pub fn insecure_loopback_allowed_from_env() -> bool {
    std::env::var(ALLOW_INSECURE_LOOPBACK_ENV)
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Parses a configured HTTP endpoint and applies the shared transport policy.
///
/// Both portal public origin and API base URL are origins, not arbitrary URLs:
/// credentials, query strings, fragments, and path prefixes are rejected.
/// HTTPS is mandatory unless plain HTTP is explicitly enabled for a loopback
/// development/test endpoint.
pub(crate) fn validate_endpoint_origin(
    raw: &str,
    variable: &'static str,
    allow_insecure_loopback: bool,
) -> Result<reqwest::Url, PortalConfigError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(PortalConfigError::new(variable, "must be set"));
    }

    let url = reqwest::Url::parse(value)
        .map_err(|_| PortalConfigError::new(variable, "must be a valid absolute URL"))?;

    // `Url::username()` cannot distinguish an absent userinfo component from
    // the syntactically present but empty form `https://@host`, so also check
    // the raw authority for the delimiter.
    let raw_authority_has_userinfo = value
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .is_some_and(|authority| authority.contains('@'));
    if raw_authority_has_userinfo || !url.username().is_empty() || url.password().is_some() {
        return Err(PortalConfigError::new(
            variable,
            "must not contain userinfo",
        ));
    }
    if url.fragment().is_some() {
        return Err(PortalConfigError::new(
            variable,
            "must not contain a fragment",
        ));
    }
    if url.query().is_some() {
        return Err(PortalConfigError::new(
            variable,
            "must not contain a query string",
        ));
    }
    if url.path() != "/" {
        return Err(PortalConfigError::new(
            variable,
            "must be an origin without a path",
        ));
    }
    let Some(host) = url.host_str() else {
        return Err(PortalConfigError::new(variable, "must contain a host"));
    };

    match url.scheme() {
        "https" => {}
        "http" if allow_insecure_loopback && is_loopback_host(host) => {}
        "http" => {
            return Err(PortalConfigError::new(
                variable,
                "must use HTTPS (plain HTTP is allowed only for explicitly enabled loopback development/test endpoints)",
            ));
        }
        _ => {
            return Err(PortalConfigError::new(
                variable,
                "must use the HTTPS scheme",
            ));
        }
    }

    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    let address_literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || address_literal
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

#[derive(Debug, Clone)]
pub struct PortalPublicOrigin {
    canonical: String,
    secure_cookies: bool,
}

impl PortalPublicOrigin {
    pub fn from_env() -> Result<Self, PortalConfigError> {
        let value = std::env::var(PUBLIC_ORIGIN_ENV)
            .map_err(|_| PortalConfigError::new(PUBLIC_ORIGIN_ENV, "must be set"))?;
        Self::parse(&value, insecure_loopback_allowed_from_env())
    }

    pub fn parse(value: &str, allow_insecure_loopback: bool) -> Result<Self, PortalConfigError> {
        let url = validate_endpoint_origin(value, PUBLIC_ORIGIN_ENV, allow_insecure_loopback)?;
        Ok(Self {
            canonical: url.origin().ascii_serialization(),
            secure_cookies: url.scheme() == "https",
        })
    }

    /// Whether browser credentials for this public origin must carry the
    /// `Secure` attribute. The only false case is an explicitly admitted
    /// loopback HTTP development/test origin.
    pub fn secure_cookies(&self) -> bool {
        self.secure_cookies
    }

    /// Whether this browser-visible origin is a literal loopback development
    /// origin. HTTPS loopback remains local even though it uses secure cookies.
    pub fn is_loopback(&self) -> bool {
        reqwest::Url::parse(&self.canonical)
            .ok()
            .and_then(|url| url.host_str().map(is_loopback_host))
            .unwrap_or(false)
    }

    fn permits(&self, method: &Method, headers: &HeaderMap) -> bool {
        if is_safe_method(method) {
            return true;
        }

        let mut origins = headers.get_all(ORIGIN).iter();
        let Some(origin) = origins.next() else {
            return false;
        };
        // Duplicate Origin fields are ambiguous and therefore fail closed.
        if origins.next().is_some() {
            return false;
        }

        origin
            .to_str()
            .map(|origin| origin == self.canonical)
            .unwrap_or(false)
    }
}

fn is_safe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// Route middleware for every `/portal/api/*` server-function request.
/// Unsafe methods require one exact, non-null Origin match.
pub async fn enforce_server_function_origin(
    State(public_origin): State<PortalPublicOrigin>,
    request: Request,
    next: Next,
) -> Response {
    if !public_origin.permits(request.method(), request.headers()) {
        return (StatusCode::FORBIDDEN, "forbidden request origin").into_response();
    }
    next.run(request).await
}

/// Admits one server-function execution or fails fast when the process-local
/// budget is exhausted. The owned permit is released on success, error,
/// cancellation, or deadline expiry.
pub async fn enforce_server_function_capacity(
    State(limits): State<PortalServerFunctionLimits>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = limits.permits.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "1")],
            "portal server-function capacity exhausted",
        )
            .into_response();
    };

    match tokio::time::timeout(limits.request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            "portal server-function request deadline exceeded",
        )
            .into_response(),
    }
}

/// Applies the complete ingress boundary to an existing server-function
/// router. The origin check runs first, then the streaming body cap, then the
/// non-queuing execution/deadline guard immediately around Leptos dispatch.
pub fn protect_server_function_routes<S>(
    router: Router<S>,
    public_origin: PortalPublicOrigin,
    limits: PortalServerFunctionLimits,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let max_body_bytes = limits.max_body_bytes();
    router
        .route_layer(middleware::from_fn_with_state(
            limits,
            enforce_server_function_capacity,
        ))
        .route_layer(RequestBodyLimitLayer::new(max_body_bytes))
        .route_layer(middleware::from_fn_with_state(
            public_origin,
            enforce_server_function_origin,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header::CONTENT_LENGTH, HeaderValue, Request};
    use axum::routing::any;
    use axum::Router;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;
    use tower::ServiceExt;

    fn test_origin() -> PortalPublicOrigin {
        PortalPublicOrigin::parse("https://portal.example.test", false)
            .expect("test origin is valid")
    }

    fn test_limits(
        max_body_bytes: usize,
        max_concurrent_requests: usize,
        request_timeout: Duration,
    ) -> PortalServerFunctionLimits {
        PortalServerFunctionLimits {
            max_body_bytes,
            request_timeout,
            permits: Arc::new(Semaphore::new(max_concurrent_requests)),
        }
    }

    fn protected_post(path: &str, body: Body, content_length: usize) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(ORIGIN, "https://portal.example.test")
            .header(CONTENT_LENGTH, content_length.to_string())
            .body(body)
            .expect("protected request builds")
    }

    fn guarded_router() -> Router {
        protect_server_function_routes(
            Router::new().route("/portal/api/test", any(|| async { StatusCode::NO_CONTENT })),
            test_origin(),
            PortalServerFunctionLimits::new(1024, 8, 5).expect("test limits are valid"),
        )
    }

    async fn guarded_status(method: Method, origin: Option<&str>) -> StatusCode {
        let mut request = Request::builder()
            .method(method)
            .uri("/portal/api/test")
            .body(Body::empty())
            .expect("request builds");
        if let Some(origin) = origin {
            request.headers_mut().insert(
                ORIGIN,
                HeaderValue::from_str(origin).expect("test origin header is valid"),
            );
        }
        guarded_router()
            .oneshot(request)
            .await
            .expect("guarded route responds")
            .status()
    }

    #[tokio::test]
    async fn unsafe_methods_require_one_exact_origin() {
        assert_eq!(
            guarded_status(Method::POST, Some("https://portal.example.test")).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            guarded_status(Method::POST, Some("https://foreign.example.test")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            guarded_status(Method::POST, None).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            guarded_status(Method::POST, Some("null")).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn safe_methods_remain_available_without_origin() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
            assert_eq!(
                guarded_status(method.clone(), None).await,
                StatusCode::NO_CONTENT,
                "{method} must remain available"
            );
        }
    }

    #[tokio::test]
    async fn oversized_server_function_body_is_rejected_before_dispatch() {
        let dispatches = Arc::new(AtomicUsize::new(0));
        let dispatches_for_handler = dispatches.clone();
        let router = protect_server_function_routes(
            Router::new().route(
                "/portal/api/{*fn_name}",
                any(move || {
                    let dispatches = dispatches_for_handler.clone();
                    async move {
                        dispatches.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
            test_origin(),
            test_limits(8, 1, Duration::from_secs(1)),
        );

        let oversized = router
            .clone()
            .oneshot(protected_post(
                "/portal/api/auth-login",
                Body::from(vec![b'x'; 9]),
                9,
            ))
            .await
            .expect("oversized request receives a response");
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);

        let valid = router
            .oneshot(protected_post(
                "/portal/api/auth-login",
                Body::from(vec![b'x'; 8]),
                8,
            ))
            .await
            .expect("valid request receives a response");
        assert_eq!(valid.status(), StatusCode::NO_CONTENT);
        assert_eq!(dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn over_concurrency_request_fails_fast_without_displacing_admitted_work() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let entered_for_handler = entered.clone();
        let release_for_handler = release.clone();
        let router = protect_server_function_routes(
            Router::new().route(
                "/portal/api/{*fn_name}",
                any(move || {
                    let entered = entered_for_handler.clone();
                    let release = release_for_handler.clone();
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
            test_origin(),
            test_limits(1024, 1, Duration::from_secs(30)),
        );

        let admitted = tokio::spawn(router.clone().oneshot(protected_post(
            "/portal/api/slow",
            Body::empty(),
            0,
        )));
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("first request reaches the admitted handler");

        let overloaded = router
            .clone()
            .oneshot(protected_post("/portal/api/login", Body::empty(), 0))
            .await
            .expect("overloaded request receives a response");
        assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            overloaded
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );

        release.notify_one();
        let admitted = admitted
            .await
            .expect("admitted task joins")
            .expect("admitted request receives a response");
        assert_eq!(admitted.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn request_deadline_releases_capacity_permit() {
        let dispatches = Arc::new(AtomicUsize::new(0));
        let dispatches_for_handler = dispatches.clone();
        let router = protect_server_function_routes(
            Router::new().route(
                "/portal/api/{*fn_name}",
                any(move || {
                    let dispatches = dispatches_for_handler.clone();
                    async move {
                        if dispatches.fetch_add(1, Ordering::SeqCst) == 0 {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
            test_origin(),
            test_limits(1024, 1, Duration::from_millis(20)),
        );

        let timed_out = router
            .clone()
            .oneshot(protected_post("/portal/api/slow", Body::empty(), 0))
            .await
            .expect("timed-out request receives a response");
        assert_eq!(timed_out.status(), StatusCode::GATEWAY_TIMEOUT);

        let after_timeout = router
            .oneshot(protected_post("/portal/api/login", Body::empty(), 0))
            .await
            .expect("request after timeout receives a response");
        assert_eq!(after_timeout.status(), StatusCode::NO_CONTENT);
        assert_eq!(dispatches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn capacity_configuration_cannot_disable_or_unbound_the_guard() {
        assert!(PortalServerFunctionLimits::new(0, 1, 1).is_err());
        assert!(PortalServerFunctionLimits::new(1, 0, 1).is_err());
        assert!(PortalServerFunctionLimits::new(1, 1, 0).is_err());
        assert!(
            PortalServerFunctionLimits::new(MAX_SERVER_FUNCTION_MAX_BODY_BYTES + 1, 1, 1,).is_err()
        );
        assert!(
            PortalServerFunctionLimits::new(1, MAX_SERVER_FUNCTION_MAX_CONCURRENCY + 1, 1,)
                .is_err()
        );
        assert!(
            PortalServerFunctionLimits::new(1, 1, MAX_SERVER_FUNCTION_TIMEOUT_SECS + 1,).is_err()
        );
    }

    #[test]
    fn endpoint_origin_requires_https_except_explicit_loopback() {
        let external = PortalPublicOrigin::parse("https://portal.example.test", false).unwrap();
        assert!(!external.is_loopback());
        assert!(PortalPublicOrigin::parse("http://portal.example.test", true).is_err());
        assert!(PortalPublicOrigin::parse("http://127.0.0.1:8080", false).is_err());
        for value in [
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://localhost:8080",
            "https://localhost:8443",
        ] {
            let origin = PortalPublicOrigin::parse(value, true).unwrap();
            assert!(origin.is_loopback(), "{value} must remain a local origin");
        }
    }

    #[test]
    fn endpoint_origin_rejects_credentials_fragments_and_non_origins() {
        for value in [
            "https://user@portal.example.test",
            "https://@portal.example.test",
            "HTTPS://@portal.example.test",
            "https://portal.example.test/#fragment",
            "https://portal.example.test/?query=1",
            "https://portal.example.test/base",
        ] {
            assert!(
                PortalPublicOrigin::parse(value, false).is_err(),
                "{value:?} must be rejected"
            );
        }
    }
}
