//! SSR-only HTTP client for the platform API upstream.
//!
//! The browser never talks to the API directly: server functions forward
//! requests through this client after the path has passed the
//! `PortalServerBoundary` allowlist. The entire module is compiled only for
//! the SSR build so reqwest never reaches the hydrate/wasm artifact.
#![cfg(feature = "ssr")]

use std::time::Duration;

use crate::security::{
    insecure_loopback_allowed_from_env, validate_endpoint_origin, PortalConfigError,
    PortalPublicOrigin,
};

/// Env var naming the upstream API base URL.
pub const API_URL_ENV: &str = "RYUKI_API_URL";
/// Env var selecting the portal execution mode.
pub const EXECUTION_MODE_ENV: &str = "RYUKI_PORTAL_EXECUTION_MODE";
/// Optional assertion for the Secure flag derived from the public origin.
pub const COOKIE_SECURE_ENV: &str = "RYUKI_PORTAL_COOKIE_SECURE";

/// Default upstream base URL for plain-HTTP local development.
pub const DEFAULT_API_URL: &str = "http://127.0.0.1:8081";
/// Live provider execution against the configured upstream API.
pub const LIVE_PROVIDER_MODE: &str = "live-provider";
/// Explicit preview-only mode. It is accepted only for a loopback public
/// origin so a missing or mistyped production mode can never manufacture the
/// synthetic static authority surface.
pub const STATIC_DRY_RUN_MODE: &str = "static-dry-run";
/// Host-only session cookie used by every HTTPS portal origin. The `__Host-`
/// prefix is enforced by browsers: it requires `Secure`, `Path=/`, and no
/// `Domain` attribute, preventing a sibling host from planting a competitor.
pub const PORTAL_SESSION_COOKIE: &str = "__Host-ryuki_session";
/// Unprefixed compatibility name used only by the explicitly enabled
/// plain-HTTP loopback development/test origin, where `__Host-` cookies cannot
/// be set because the `Secure` attribute is unavailable.
pub const LOOPBACK_PORTAL_SESSION_COOKIE: &str = "ryuki_session";
/// Compatibility header carrying the forwarded opaque session token to the API.
pub const SESSION_ID_HEADER: &str = "X-Ryuki-Session-Id";
/// Maximum response body accepted from the platform API (1 MiB).
pub const MAX_UPSTREAM_RESPONSE_BYTES: usize = 1024 * 1024;

/// Transport-level failure (connect error, timeout, or upstream 5xx).
/// Reads may degrade to static fallbacks on this error; mutations never do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamUnreachable {
    pub detail: String,
}

impl std::fmt::Display for UpstreamUnreachable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("API unreachable")
    }
}

impl std::error::Error for UpstreamUnreachable {}

/// A completed upstream exchange (2xx-4xx). 5xx and transport failures are
/// classified as [`UpstreamUnreachable`] before this type is constructed.
#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub status: u16,
    pub body: String,
    /// Parsed `X-Total-Count` header, when present and a valid `u64`. The API
    /// emits it on list endpoints (e.g. `GET /api/requests`) as the filtered
    /// total BEFORE limit/offset. Display-only — never used to derive paging.
    pub total_count: Option<u64>,
}

impl UpstreamResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.body)
    }

    /// Extracts the `message` from the canonical `{"error","message"}` API
    /// error body, if parseable.
    pub fn api_error_message(&self) -> Option<String> {
        let value: serde_json::Value = serde_json::from_str(&self.body).ok()?;
        value
            .get("message")
            .and_then(|message| message.as_str())
            .map(str::to_string)
    }
}

#[derive(Clone)]
pub struct UpstreamClient {
    base_url: reqwest::Url,
    http: reqwest::Client,
    live: bool,
    cookie_secure: bool,
}

impl UpstreamClient {
    /// Builds the client once from the environment. `RYUKI_API_URL` defaults
    /// to the local API. The execution mode is closed and mandatory: external
    /// origins require `live-provider`, while `static-dry-run` is available
    /// only for an explicitly configured loopback preview.
    pub fn from_env(public_origin: &PortalPublicOrigin) -> Result<Self, PortalConfigError> {
        let base_url = std::env::var(API_URL_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_API_URL.to_string());
        let configured_mode = std::env::var(EXECUTION_MODE_ENV).ok();
        let live = execution_mode_for_origin(configured_mode.as_deref(), public_origin)?;
        let cookie_secure = cookie_secure_for_origin(public_origin)?;
        Self::new(
            &base_url,
            live,
            insecure_loopback_allowed_from_env(),
            cookie_secure,
        )
    }

    fn new(
        base_url: &str,
        live: bool,
        allow_insecure_loopback: bool,
        cookie_secure: bool,
    ) -> Result<Self, PortalConfigError> {
        Self::new_with_http_builder(
            base_url,
            live,
            allow_insecure_loopback,
            cookie_secure,
            reqwest::Client::builder(),
        )
    }

    fn new_with_http_builder(
        base_url: &str,
        live: bool,
        allow_insecure_loopback: bool,
        cookie_secure: bool,
        http_builder: reqwest::ClientBuilder,
    ) -> Result<Self, PortalConfigError> {
        let base_url = validate_endpoint_origin(base_url, API_URL_ENV, allow_insecure_loopback)?;
        let https_only = base_url.scheme() == "https";
        let http = http_builder
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            // API session credentials must never traverse ambient HTTP(S) or
            // ALL_PROXY configuration. This also prevents an explicitly
            // admitted loopback endpoint from escaping through a proxy.
            .no_proxy()
            // A credential-bearing request must never be replayed to a
            // redirect-selected authority.
            .redirect(reqwest::redirect::Policy::none())
            // HTTPS origins remain HTTPS-only below the URL-origin guard;
            // explicit loopback HTTP keeps its narrowly validated exception.
            .https_only(https_only)
            .build()
            .map_err(|_| {
                PortalConfigError::new(API_URL_ENV, "could not initialize the HTTP client")
            })?;
        Ok(Self {
            base_url,
            http,
            live,
            cookie_secure,
        })
    }

    /// True when the portal runs in `live-provider` mode.
    pub fn live(&self) -> bool {
        self.live
    }

    /// Secure-cookie policy validated once against the public origin during
    /// startup. Request handlers never re-read a mutable environment flag.
    pub fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }

    fn url(&self, path: &str) -> Result<reqwest::Url, UpstreamUnreachable> {
        if !path.starts_with('/') || path.starts_with("//") || path.contains('#') {
            return Err(UpstreamUnreachable {
                detail: "upstream path was rejected".to_string(),
            });
        }
        let url = self.base_url.join(path).map_err(|_| UpstreamUnreachable {
            detail: "upstream path was rejected".to_string(),
        })?;
        if url.origin() != self.base_url.origin() {
            return Err(UpstreamUnreachable {
                detail: "upstream path was rejected".to_string(),
            });
        }
        Ok(url)
    }

    async fn dispatch(
        &self,
        mut request: reqwest::RequestBuilder,
        session_id: Option<&str>,
    ) -> Result<UpstreamResponse, UpstreamUnreachable> {
        if let Some(session_id) = session_id {
            request = request.header(SESSION_ID_HEADER, session_id);
        }
        let mut response = request.send().await.map_err(|error| UpstreamUnreachable {
            detail: redact_transport_error(&error),
        })?;
        let status = response.status().as_u16();
        if response.status().is_server_error() {
            return Err(UpstreamUnreachable {
                detail: format!("upstream returned status {status}"),
            });
        }
        // Read the total-count header BEFORE consuming the body (response.text()
        // takes ownership). Absent/non-numeric headers degrade to None.
        let total_count = parse_total_count_header(response.headers());
        if response
            .content_length()
            .is_some_and(|length| length > MAX_UPSTREAM_RESPONSE_BYTES as u64)
        {
            return Err(UpstreamUnreachable {
                detail: "upstream response body exceeded limit".to_string(),
            });
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| UpstreamUnreachable {
            detail: "upstream body read failed".to_string(),
        })? {
            let next_len = body
                .len()
                .checked_add(chunk.len())
                .filter(|length| *length <= MAX_UPSTREAM_RESPONSE_BYTES)
                .ok_or_else(|| UpstreamUnreachable {
                    detail: "upstream response body exceeded limit".to_string(),
                })?;
            body.reserve(next_len.saturating_sub(body.len()));
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(body).map_err(|_| UpstreamUnreachable {
            detail: "upstream response body was not valid UTF-8".to_string(),
        })?;
        Ok(UpstreamResponse {
            status,
            body,
            total_count,
        })
    }

    /// GET an allowlisted API path, forwarding the session id when present.
    pub async fn get(
        &self,
        path: &str,
        session_id: Option<&str>,
    ) -> Result<UpstreamResponse, UpstreamUnreachable> {
        let url = self.url(path)?;
        self.dispatch(self.http.get(url), session_id).await
    }

    /// DELETE an allowlisted API path, forwarding the session id when present.
    pub async fn delete(
        &self,
        path: &str,
        session_id: Option<&str>,
    ) -> Result<UpstreamResponse, UpstreamUnreachable> {
        let url = self.url(path)?;
        self.dispatch(self.http.delete(url), session_id).await
    }

    /// POST an allowlisted API path with an optional JSON body.
    pub async fn post(
        &self,
        path: &str,
        body: Option<&serde_json::Value>,
        session_id: Option<&str>,
    ) -> Result<UpstreamResponse, UpstreamUnreachable> {
        let url = self.url(path)?;
        let mut request = self.http.post(url);
        if let Some(body) = body {
            request = request.json(body);
        }
        self.dispatch(request, session_id).await
    }

    /// PUT an allowlisted API path with a JSON body (full-resource replace,
    /// e.g. platform settings).
    pub async fn put(
        &self,
        path: &str,
        body: &serde_json::Value,
        session_id: Option<&str>,
    ) -> Result<UpstreamResponse, UpstreamUnreachable> {
        let url = self.url(path)?;
        let request = self.http.put(url).json(body);
        self.dispatch(request, session_id).await
    }
}

fn execution_mode_for_origin(
    configured: Option<&str>,
    public_origin: &PortalPublicOrigin,
) -> Result<bool, PortalConfigError> {
    match configured.map(str::trim) {
        Some(LIVE_PROVIDER_MODE) => Ok(true),
        Some(STATIC_DRY_RUN_MODE) if public_origin.is_loopback() => Ok(false),
        Some(STATIC_DRY_RUN_MODE) => Err(PortalConfigError::new(
            EXECUTION_MODE_ENV,
            "static-dry-run is permitted only for an explicit loopback public origin",
        )),
        Some("") | None => Err(PortalConfigError::new(
            EXECUTION_MODE_ENV,
            "execution mode is required and must be live-provider or static-dry-run",
        )),
        Some(_) => Err(PortalConfigError::new(
            EXECUTION_MODE_ENV,
            "execution mode must be exactly live-provider or static-dry-run",
        )),
    }
}

/// Canonical name of the filtered-total header emitted by list endpoints.
pub const TOTAL_COUNT_HEADER: &str = "x-total-count";

/// Extracts the filtered total from an `X-Total-Count` header map. Returns
/// `None` when the header is absent, non-ASCII, or not a valid `u64` so a
/// contract drift degrades the display total rather than the whole read.
fn parse_total_count_header(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(TOTAL_COUNT_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

/// Transport errors can embed full URLs; keep only the failure class.
fn redact_transport_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "upstream request timed out".to_string()
    } else if error.is_connect() {
        "upstream connection failed".to_string()
    } else {
        "upstream request failed".to_string()
    }
}

/// Derives the cookie transport policy from the already validated public
/// origin. The legacy environment value is an optional assertion only: it
/// cannot silently weaken HTTPS, and false is accepted only for the explicit
/// loopback-HTTP development/test origin admitted by `PortalPublicOrigin`.
pub fn cookie_secure_for_origin(
    public_origin: &PortalPublicOrigin,
) -> Result<bool, PortalConfigError> {
    let configured = match std::env::var(COOKIE_SECURE_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(PortalConfigError::new(
                COOKIE_SECURE_ENV,
                "must contain valid Unicode",
            ));
        }
    };
    cookie_secure_for_origin_setting(public_origin, configured.as_deref())
}

fn cookie_secure_for_origin_setting(
    public_origin: &PortalPublicOrigin,
    configured: Option<&str>,
) -> Result<bool, PortalConfigError> {
    let required = public_origin.secure_cookies();
    let Some(configured) = configured else {
        return Ok(required);
    };
    let configured = match configured.trim().to_ascii_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => {
            return Err(PortalConfigError::new(
                COOKIE_SECURE_ENV,
                "must be true or false",
            ));
        }
    };
    if configured != required {
        let reason = if required {
            "must be true when RYUKI_PORTAL_PUBLIC_ORIGIN uses HTTPS"
        } else {
            "must be false for an explicitly enabled loopback HTTP public origin"
        };
        return Err(PortalConfigError::new(COOKIE_SECURE_ENV, reason));
    }
    Ok(required)
}

/// Strict UUID syntax check (8-4-4-4-12 lowercase/uppercase hex) without
/// pulling a uuid dependency into the portal.
pub fn is_uuid_syntax(candidate: &str) -> bool {
    let groups: Vec<&str> = candidate.split('-').collect();
    let expected_lengths = [8usize, 4, 4, 4, 12];
    groups.len() == expected_lengths.len()
        && groups.iter().zip(expected_lengths).all(|(group, length)| {
            group.len() == length && group.chars().all(|char| char.is_ascii_hexdigit())
        })
}

/// Exact canonical wire-shape check for a 256-bit rys_ session bearer without
/// decoding or retaining another copy of its secret payload.
pub fn is_session_bearer_syntax(candidate: &str) -> bool {
    let Some(payload) = candidate.strip_prefix("rys_") else {
        return false;
    };
    if payload.len() != 43
        || !payload
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return false;
    }

    // For a 32-byte input, the last base64url character contains four data
    // bits and two zero padding bits. Restricting it to indices divisible by
    // four rejects alternate, non-canonical encodings.
    matches!(
        payload.as_bytes()[42],
        b'A' | b'E'
            | b'I'
            | b'M'
            | b'Q'
            | b'U'
            | b'Y'
            | b'c'
            | b'g'
            | b'k'
            | b'o'
            | b's'
            | b'w'
            | b'0'
            | b'4'
            | b'8'
    )
}

/// Returns the only cookie name admitted for the validated public-origin
/// transport mode. `secure = false` is possible only for the explicitly
/// enabled loopback HTTP development/test origin.
pub fn portal_session_cookie_name(secure: bool) -> &'static str {
    if secure {
        PORTAL_SESSION_COOKIE
    } else {
        LOOPBACK_PORTAL_SESSION_COOKIE
    }
}

fn is_portal_session_cookie_name(name: &str) -> bool {
    name == PORTAL_SESSION_COOKIE || name == LOOPBACK_PORTAL_SESSION_COOKIE
}

/// Parses one or more raw Cookie header values and validates the exact opaque
/// bearer syntax. Exactly one credential-cookie pair must be present, and its
/// name must match the validated public-origin mode. Any duplicate active
/// name, or an old/new-name pair, is ambiguous and fails closed regardless of
/// value validity or header ordering. Legacy/admin UUID bearers are rejected.
fn session_id_from_cookie_headers<'a>(
    cookie_headers: impl IntoIterator<Item = &'a str>,
    secure: bool,
) -> Option<String> {
    let mut credential = None;
    for cookie_header in cookie_headers {
        for pair in cookie_header.split(';') {
            let pair = pair.trim();
            let Some((name, value)) = pair.split_once('=') else {
                if is_portal_session_cookie_name(pair) {
                    return None;
                }
                continue;
            };
            let name = name.trim();
            if !is_portal_session_cookie_name(name) {
                continue;
            }
            if credential.is_some() {
                return None;
            }
            credential = Some((name, value.trim()));
        }
    }

    let (name, value) = credential?;
    (name == portal_session_cookie_name(secure) && is_session_bearer_syntax(value))
        .then(|| value.to_string())
}

/// Parses a single raw Cookie header with the same duplicate and mode-selection
/// invariants applied by request extraction.
pub fn session_id_from_cookie_header(cookie_header: &str, secure: bool) -> Option<String> {
    session_id_from_cookie_headers([cookie_header], secure)
}

/// Extracts the portal session token from the inbound request cookie, if any.
/// Only the validated opaque bearer is ever forwarded upstream — never the raw
/// `Cookie` header.
pub async fn session_id_from_request() -> Option<String> {
    // Use the process-validated client context that the server-function route
    // installs at startup. Missing context fails closed; request metadata or a
    // mutable environment value must never select the weaker cookie name.
    let secure = leptos::prelude::use_context::<UpstreamClient>()?.cookie_secure();
    let headers = leptos_axum::extract::<axum::http::HeaderMap>().await.ok()?;
    let cookie_headers = headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .map(|value| value.to_str())
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    session_id_from_cookie_headers(cookie_headers, secure)
}

/// Default session cookie lifetime when the upstream expiry is absent,
/// unparseable, or already in the past.
pub const DEFAULT_SESSION_COOKIE_MAX_AGE_SECS: u64 = 86_400;

/// Derives the portal cookie Max-Age from the upstream `expires_at`
/// RFC 3339 timestamp so the cookie and the upstream session expire
/// together. Falls back to [`DEFAULT_SESSION_COOKIE_MAX_AGE_SECS`] when the
/// timestamp does not parse or is not in the future.
pub fn cookie_max_age_from_expires_at(expires_at: &str) -> u64 {
    parse_rfc3339_epoch_seconds(expires_at)
        .and_then(|expiry| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs() as i64;
            let remaining = expiry.checked_sub(now)?;
            (remaining > 0).then_some(remaining as u64)
        })
        .unwrap_or(DEFAULT_SESSION_COOKIE_MAX_AGE_SECS)
}

/// Minimal RFC 3339 parse to Unix epoch seconds (fractional seconds are
/// truncated). Returns `None` for anything malformed; no time dependency is
/// pulled into the portal for a single cookie lifetime computation.
fn parse_rfc3339_epoch_seconds(timestamp: &str) -> Option<i64> {
    let timestamp = timestamp.trim();
    let (date, time_with_offset) = timestamp.split_once(['T', 't', ' '])?;

    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let (time, offset_secs) = if let Some(time) = time_with_offset.strip_suffix(['Z', 'z']) {
        (time, 0i64)
    } else {
        let position = time_with_offset.rfind(['+', '-'])?;
        let (time, offset) = time_with_offset.split_at(position);
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        (time, sign * parse_utc_offset_seconds(&offset[1..])?)
    };

    let whole_seconds = time.split('.').next()?;
    let mut time_parts = whole_seconds.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some()
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }

    Some(
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
            - offset_secs,
    )
}

fn parse_utc_offset_seconds(offset: &str) -> Option<i64> {
    let (hours, minutes) = offset.split_once(':')?;
    let hours: i64 = hours.parse().ok()?;
    let minutes: i64 = minutes.parse().ok()?;
    ((0..24).contains(&hours) && (0..60).contains(&minutes)).then_some(hours * 3_600 + minutes * 60)
}

/// Days since 1970-01-01 for a proleptic Gregorian civil date (Howard
/// Hinnant's `days_from_civil` algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = i64::from((month + 9) % 12);
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Builds the portal-origin session cookie. `max_age_secs = 0` clears it.
pub fn portal_session_cookie(session_id: &str, max_age_secs: u64, secure: bool) -> String {
    named_portal_session_cookie(
        portal_session_cookie_name(secure),
        session_id,
        max_age_secs,
        secure,
    )
}

fn named_portal_session_cookie(
    name: &str,
    session_id: &str,
    max_age_secs: u64,
    secure: bool,
) -> String {
    let mut cookie =
        format!("{name}={session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Appends a Set-Cookie header on the portal response that stores the
/// session id for `max_age_secs` seconds.
pub fn set_portal_session_cookie(session_id: &str, max_age_secs: u64, secure: bool) {
    append_set_cookie(&portal_session_cookie(session_id, max_age_secs, secure));
    if secure {
        // Retire the old host-only production cookie during migration. A
        // sibling's parent-Domain cookie cannot be deleted from this host and
        // therefore remains an explicit fail-closed ambiguity in the parser.
        append_set_cookie(&named_portal_session_cookie(
            LOOPBACK_PORTAL_SESSION_COOKIE,
            "",
            0,
            true,
        ));
    }
}

/// Appends a Set-Cookie header that clears the portal session cookie.
pub fn clear_portal_session_cookie(secure: bool) {
    append_set_cookie(&portal_session_cookie("", 0, secure));
    if secure {
        append_set_cookie(&named_portal_session_cookie(
            LOOPBACK_PORTAL_SESSION_COOKIE,
            "",
            0,
            true,
        ));
    }
}

/// Host-prefixed Entra login binding used by every HTTPS portal origin.
pub const SECURE_ENTRA_LOGIN_BINDING_COOKIE: &str = "__Host-entra_login_csrf";
/// Compatibility binding name used only by explicitly enabled loopback HTTP.
pub const LOOPBACK_ENTRA_LOGIN_BINDING_COOKIE: &str = "entra_login_csrf";

pub fn entra_login_binding_cookie_name(secure: bool) -> &'static str {
    if secure {
        SECURE_ENTRA_LOGIN_BINDING_COOKIE
    } else {
        LOOPBACK_ENTRA_LOGIN_BINDING_COOKIE
    }
}

/// Builds the Entra login CSRF-binding cookie. HttpOnly (the binding never
/// reaches page JavaScript), SameSite=Lax so the browser presents it on the
/// top-level redirect back from the IdP to the API callback, Max-Age matching
/// the API's 10-minute login-state TTL. `Path=/` so it reaches the API
/// callback route in same-origin deployments.
pub fn entra_login_binding_cookie(binding: &str, secure: bool) -> String {
    let name = entra_login_binding_cookie_name(secure);
    let mut cookie = format!("{name}={binding}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Validates that at most one binding cookie matching the process-validated
/// transport name appears across all inbound `Cookie` header fields. The
/// sibling-plantable loopback name is not active on HTTPS origins.
pub fn entra_login_binding_cookie_headers_are_unambiguous<'a>(
    cookie_headers: impl IntoIterator<Item = &'a str>,
    secure: bool,
) -> bool {
    let expected_name = entra_login_binding_cookie_name(secure);
    let mut found = false;
    for cookie_header in cookie_headers {
        for pair in cookie_header.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let Some((name, _)) = pair.split_once('=') else {
                if pair == expected_name {
                    return false;
                }
                continue;
            };
            if name.trim() != expected_name {
                continue;
            }
            if found {
                return false;
            }
            found = true;
        }
    }
    true
}

/// Appends a Set-Cookie header carrying the Entra login CSRF binding on the
/// portal response. The upstream client cannot forward upstream Set-Cookie
/// headers, so the authorize-url server function re-issues the binding cookie
/// itself from the API's JSON payload.
pub fn set_entra_login_binding_cookie(binding: &str, secure: bool) {
    append_set_cookie(&entra_login_binding_cookie(binding, secure));
}

fn append_set_cookie(cookie: &str) {
    use leptos::prelude::use_context;

    let Some(response) = use_context::<leptos_axum::ResponseOptions>() else {
        return;
    };
    if let Ok(value) = axum::http::HeaderValue::from_str(cookie) {
        response.append_header(axum::http::header::SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_execution_mode_is_explicit_and_external_origins_require_live_provider() {
        let external = PortalPublicOrigin::parse("https://portal.example.test", false).unwrap();
        let loopback = PortalPublicOrigin::parse("http://127.0.0.1:8080", true).unwrap();

        assert_eq!(
            execution_mode_for_origin(Some(LIVE_PROVIDER_MODE), &external),
            Ok(true)
        );
        assert_eq!(
            execution_mode_for_origin(Some(LIVE_PROVIDER_MODE), &loopback),
            Ok(true)
        );
        assert_eq!(
            execution_mode_for_origin(Some(STATIC_DRY_RUN_MODE), &loopback),
            Ok(false)
        );

        for configured in [None, Some(""), Some("static"), Some("LIVE-PROVIDER")] {
            assert!(
                execution_mode_for_origin(configured, &external).is_err(),
                "missing or unknown mode {configured:?} must fail closed"
            );
        }
        assert!(execution_mode_for_origin(Some(STATIC_DRY_RUN_MODE), &external).is_err());
    }

    #[test]
    fn upstream_requires_https_except_explicit_loopback() {
        assert!(UpstreamClient::new("https://api.example.test", true, false, true).is_ok());
        assert!(UpstreamClient::new("http://api.example.test", true, true, false).is_err());
        assert!(UpstreamClient::new("http://127.0.0.1:8081", true, false, false).is_err());
        assert!(UpstreamClient::new("http://127.0.0.1:8081", true, true, false).is_ok());
        assert!(UpstreamClient::new("http://[::1]:8081", true, true, false).is_ok());
        assert!(UpstreamClient::new("http://localhost:8081", true, true, false).is_ok());
    }

    #[test]
    fn cookie_secure_policy_is_derived_from_public_origin() {
        let https = PortalPublicOrigin::parse("https://portal.example.test", false).unwrap();
        assert_eq!(cookie_secure_for_origin_setting(&https, None), Ok(true));
        assert_eq!(
            cookie_secure_for_origin_setting(&https, Some("true")),
            Ok(true)
        );
        assert!(cookie_secure_for_origin_setting(&https, Some("false")).is_err());

        let loopback = PortalPublicOrigin::parse("http://127.0.0.1:8080", true).unwrap();
        assert_eq!(cookie_secure_for_origin_setting(&loopback, None), Ok(false));
        assert_eq!(
            cookie_secure_for_origin_setting(&loopback, Some("false")),
            Ok(false)
        );
        assert!(cookie_secure_for_origin_setting(&loopback, Some("true")).is_err());
        assert!(cookie_secure_for_origin_setting(&https, Some("yes")).is_err());
    }

    #[test]
    fn upstream_rejects_userinfo_fragments_and_non_origins() {
        for value in [
            "https://user@api.example.test",
            "https://@api.example.test",
            "HTTPS://@api.example.test",
            "https://api.example.test/#fragment",
            "https://api.example.test/?query=1",
            "https://api.example.test/base",
        ] {
            assert!(
                UpstreamClient::new(value, true, false, true).is_err(),
                "{value:?} must be rejected"
            );
        }
    }

    async fn serve_one(listener: tokio::net::TcpListener, response: String) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut stream, _) = listener.accept().await.expect("test client connects");
        let mut request = vec![0_u8; 16 * 1024];
        let length = stream
            .read(&mut request)
            .await
            .expect("request is readable");
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response is writable");
        String::from_utf8_lossy(&request[..length]).into_owned()
    }

    fn canonical_test_session(fill: char, canonical_tail: char) -> String {
        let mut payload = fill.to_string().repeat(42);
        payload.push(canonical_tail);
        format!("rys_{payload}")
    }

    fn request_has_session_header(request: &str, session: &str) -> bool {
        request.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case(SESSION_ID_HEADER) && value.trim() == session
            })
        })
    }

    #[tokio::test]
    async fn loopback_upstream_bypasses_all_proxy_configuration() {
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("target listener binds");
        let target_address = target_listener
            .local_addr()
            .expect("target address is available");
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy listener binds");
        let proxy_address = proxy_listener
            .local_addr()
            .expect("proxy address is available");
        let target = tokio::spawn(serve_one(
            target_listener,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string(),
        ));
        let configured_proxy = reqwest::Proxy::all(format!("http://{proxy_address}"))
            .expect("test proxy URL is valid");
        let client = UpstreamClient::new_with_http_builder(
            &format!("http://{target_address}"),
            true,
            true,
            false,
            reqwest::Client::builder().proxy(configured_proxy),
        )
        .expect("loopback test upstream is allowed");
        let session = canonical_test_session('A', 'A');

        let response = client
            .get("/direct", Some(&session))
            .await
            .expect("loopback request connects directly");

        assert_eq!(response.status, 200);
        let target_request = target.await.expect("target server completes");
        assert!(
            request_has_session_header(&target_request, &session),
            "the configured loopback upstream receives the session directly"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), proxy_listener.accept())
                .await
                .is_err(),
            "neither ambient nor explicitly seeded proxies may receive a connection"
        );
    }

    #[tokio::test]
    async fn redirects_do_not_replay_the_session_credential() {
        let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("redirect listener binds");
        let redirect_address = redirect_listener
            .local_addr()
            .expect("redirect address is available");
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("target listener binds");
        let target_address = target_listener
            .local_addr()
            .expect("target address is available");
        let redirect_response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/capture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let first_hop = tokio::spawn(serve_one(redirect_listener, redirect_response));

        let client = UpstreamClient::new(&format!("http://{redirect_address}"), true, true, false)
            .expect("loopback test upstream is allowed");
        let session = canonical_test_session('A', 'A');
        let response = client
            .get("/redirect", Some(&session))
            .await
            .expect("redirect response is returned without following it");

        assert_eq!(response.status, 302);
        let first_request = first_hop.await.expect("first-hop server completes");
        assert!(
            request_has_session_header(&first_request, &session),
            "configured upstream receives the intended session header"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), target_listener.accept())
                .await
                .is_err(),
            "redirect target must not receive any connection"
        );
    }

    #[tokio::test]
    async fn oversized_upstream_response_is_rejected_before_buffering() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let address = listener.local_addr().expect("test address is available");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_UPSTREAM_RESPONSE_BYTES + 1
        );
        let server = tokio::spawn(serve_one(listener, response));
        let client = UpstreamClient::new(&format!("http://{address}"), true, true, false)
            .expect("loopback test upstream is allowed");

        let error = client
            .get("/large", None)
            .await
            .expect_err("oversized response must fail closed");
        assert_eq!(error.detail, "upstream response body exceeded limit");
        server.await.expect("test server completes");
    }

    #[test]
    fn uuid_syntax_accepts_canonical_uuids_only() {
        assert!(is_uuid_syntax("3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b"));
        assert!(is_uuid_syntax("3F2B8D44-9C1A-4E5F-8A2B-1C9D3E4F5A6B"));
        for candidate in [
            "",
            "not-a-uuid",
            "3f2b8d44-9c1a-4e5f-8a2b",
            "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b-extra",
            "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6g",
            "../../etc/passwd",
        ] {
            assert!(!is_uuid_syntax(candidate), "{candidate} must be rejected");
        }
    }

    #[test]
    fn production_session_cookie_parser_accepts_only_one_host_cookie() {
        let session = canonical_test_session('A', 'A');
        let header = format!("theme=dark; {PORTAL_SESSION_COOKIE}={session}; other=1");
        assert_eq!(
            session_id_from_cookie_header(&header, true),
            Some(session.clone())
        );
        assert_eq!(
            session_id_from_cookie_header(
                &format!("{PORTAL_SESSION_COOKIE}=3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b"),
                true,
            ),
            None,
            "legacy/admin UUID bearers must be rejected"
        );
        assert_eq!(
            session_id_from_cookie_header(
                &format!("{PORTAL_SESSION_COOKIE}=rys_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"),
                true,
            ),
            None,
            "non-canonical trailing bits must be rejected"
        );
        assert_eq!(session_id_from_cookie_header("other=value", true), None);
        assert_eq!(
            session_id_from_cookie_header(
                &format!("{LOOPBACK_PORTAL_SESSION_COOKIE}={session}"),
                true,
            ),
            None,
            "production must not accept the old unprefixed singleton"
        );
    }

    #[test]
    fn loopback_session_cookie_parser_accepts_only_one_legacy_cookie() {
        let session = canonical_test_session('A', 'A');
        assert_eq!(
            session_id_from_cookie_header(
                &format!("{LOOPBACK_PORTAL_SESSION_COOKIE}={session}"),
                false,
            ),
            Some(session.clone())
        );
        assert_eq!(
            session_id_from_cookie_header(&format!("{PORTAL_SESSION_COOKIE}={session}"), false,),
            None,
            "plain-HTTP loopback must not rely on a browser-rejected __Host- cookie"
        );
    }

    #[test]
    fn duplicate_session_cookies_reject_attacker_first_and_attacker_last() {
        let victim = canonical_test_session('A', 'A');
        let attacker = canonical_test_session('B', 'E');

        for secure in [true, false] {
            let name = portal_session_cookie_name(secure);
            let attacker_first = format!("{name}={attacker}; {name}={victim}");
            let attacker_last = format!("{name}={victim}; {name}={attacker}");
            let malformed_first = format!("{name}=malformed; {name}={victim}");
            let malformed_last = format!("{name}={victim}; {name}=malformed");
            for header in [
                attacker_first,
                attacker_last,
                malformed_first,
                malformed_last,
            ] {
                assert_eq!(
                    session_id_from_cookie_header(&header, secure),
                    None,
                    "duplicate credential cookies must fail closed: {header}"
                );
            }
        }

        let first_field = format!("{PORTAL_SESSION_COOKIE}={attacker}");
        let second_field = format!("{PORTAL_SESSION_COOKIE}={victim}");
        assert_eq!(
            session_id_from_cookie_headers([first_field.as_str(), second_field.as_str()], true,),
            None,
            "duplicates split across Cookie header fields must also fail closed"
        );
    }

    #[test]
    fn old_and_new_session_cookie_names_are_ambiguous_in_either_order() {
        let old = canonical_test_session('B', 'E');
        let current = canonical_test_session('A', 'A');
        let old_first =
            format!("{LOOPBACK_PORTAL_SESSION_COOKIE}={old}; {PORTAL_SESSION_COOKIE}={current}");
        let new_first =
            format!("{PORTAL_SESSION_COOKIE}={current}; {LOOPBACK_PORTAL_SESSION_COOKIE}={old}");

        for secure in [true, false] {
            assert_eq!(session_id_from_cookie_header(&old_first, secure), None);
            assert_eq!(session_id_from_cookie_header(&new_first, secure), None);
        }
    }

    #[test]
    fn portal_session_cookie_uses_host_prefix_except_on_loopback_http() {
        let session = canonical_test_session('A', 'A');
        let production = portal_session_cookie(&session, 86_400, true);
        assert_eq!(
            production,
            format!(
                "__Host-ryuki_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400; Secure"
            )
        );
        assert!(!production.contains("Domain="));

        let loopback = portal_session_cookie(&session, 86_400, false);
        assert_eq!(
            loopback,
            format!("ryuki_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
        );
        assert!(!loopback.contains("; Secure"));

        let cleared = portal_session_cookie("", 0, true);
        assert!(cleared.starts_with("__Host-ryuki_session=;"));
        assert!(cleared.contains("Max-Age=0"));
        assert!(cleared.ends_with("; Secure"));
        let loopback_cleared = portal_session_cookie("", 0, false);
        assert!(loopback_cleared.starts_with("ryuki_session=;"));
        assert!(loopback_cleared.contains("Max-Age=0"));
    }

    #[test]
    fn entra_binding_cookie_sets_security_attributes() {
        let cookie = entra_login_binding_cookie("binding-value", false);
        assert_eq!(
            cookie,
            "entra_login_csrf=binding-value; Path=/; HttpOnly; SameSite=Lax; Max-Age=600"
        );
        let secure = entra_login_binding_cookie("binding-value", true);
        assert!(secure.starts_with("__Host-entra_login_csrf=binding-value;"));
        assert!(secure.ends_with("; Secure"));
        assert!(!secure.contains("Domain="));
    }

    #[test]
    fn entra_binding_cookie_rejects_matching_duplicates_across_fields() {
        let first = "__Host-entra_login_csrf=first";
        let second = "other=value; __Host-entra_login_csrf=second";
        assert!(!entra_login_binding_cookie_headers_are_unambiguous(
            [first, second],
            true
        ));
        assert!(!entra_login_binding_cookie_headers_are_unambiguous(
            ["__Host-entra_login_csrf=first; __Host-entra_login_csrf=second"],
            true
        ));
    }

    #[test]
    fn entra_binding_cookie_name_is_selected_only_by_validated_origin_mode() {
        assert!(entra_login_binding_cookie_headers_are_unambiguous(
            ["entra_login_csrf=sibling-plant; __Host-entra_login_csrf=host-only"],
            true
        ));
        assert!(entra_login_binding_cookie_headers_are_unambiguous(
            ["__Host-entra_login_csrf=ignored; entra_login_csrf=loopback"],
            false
        ));
        assert_eq!(
            entra_login_binding_cookie_name(true),
            "__Host-entra_login_csrf"
        );
        assert_eq!(entra_login_binding_cookie_name(false), "entra_login_csrf");
    }

    #[test]
    fn rfc3339_epoch_parse_handles_utc_offsets_and_fractions() {
        // 2026-06-13T12:00:00Z == 1781352000.
        assert_eq!(
            parse_rfc3339_epoch_seconds("2026-06-13T12:00:00Z"),
            Some(1_781_352_000)
        );
        assert_eq!(
            parse_rfc3339_epoch_seconds("2026-06-13T12:00:00+00:00"),
            Some(1_781_352_000)
        );
        assert_eq!(
            parse_rfc3339_epoch_seconds("2026-06-13T12:00:00.514321+00:00"),
            Some(1_781_352_000)
        );
        // +02:00 is two hours earlier in UTC.
        assert_eq!(
            parse_rfc3339_epoch_seconds("2026-06-13T12:00:00+02:00"),
            Some(1_781_344_800)
        );
        assert_eq!(
            parse_rfc3339_epoch_seconds("2026-06-13T12:00:00-02:00"),
            Some(1_781_359_200)
        );
        // The Unix epoch itself.
        assert_eq!(parse_rfc3339_epoch_seconds("1970-01-01T00:00:00Z"), Some(0));

        for malformed in [
            "",
            "not-a-timestamp",
            "2026-06-13",
            "2026-13-13T12:00:00Z",
            "2026-06-13T25:00:00Z",
            "2026-06-13T12:00:00",
        ] {
            assert_eq!(
                parse_rfc3339_epoch_seconds(malformed),
                None,
                "{malformed} must be rejected"
            );
        }
    }

    #[test]
    fn cookie_max_age_tracks_future_expiry_and_falls_back_otherwise() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs() as i64;
        // Re-render a future epoch as RFC 3339 via the same civil-date math
        // used by the parser, exercising the round trip.
        let future = now + 7_200;
        let max_age = cookie_max_age_from_expires_at(&epoch_to_rfc3339_utc(future));
        assert!(
            (7_195..=7_200).contains(&max_age),
            "expected ~2h remaining, got {max_age}"
        );

        // Past expiry and unparseable values fall back to the default.
        assert_eq!(
            cookie_max_age_from_expires_at(&epoch_to_rfc3339_utc(now - 60)),
            DEFAULT_SESSION_COOKIE_MAX_AGE_SECS
        );
        assert_eq!(
            cookie_max_age_from_expires_at("not-a-timestamp"),
            DEFAULT_SESSION_COOKIE_MAX_AGE_SECS
        );
        assert_eq!(
            cookie_max_age_from_expires_at(""),
            DEFAULT_SESSION_COOKIE_MAX_AGE_SECS
        );
    }

    /// Test-only inverse of `parse_rfc3339_epoch_seconds` (UTC, whole
    /// seconds) so the max-age test does not hardcode wall-clock values.
    fn epoch_to_rfc3339_utc(epoch: i64) -> String {
        let days = epoch.div_euclid(86_400);
        let secs = epoch.rem_euclid(86_400);
        // Inverse of days_from_civil (Howard Hinnant's civil_from_days).
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let day_of_era = z - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        };
        let year = if month <= 2 { year + 1 } else { year };
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            secs / 3_600,
            (secs % 3_600) / 60,
            secs % 60
        )
    }

    #[test]
    fn upstream_response_extracts_canonical_api_error_message() {
        let response = UpstreamResponse {
            status: 409,
            body: r#"{"error":"LIFECYCLE_GUARD","message":"Request is not in a valid stage"}"#
                .to_string(),
            total_count: None,
        };
        assert!(!response.is_success());
        assert_eq!(
            response.api_error_message(),
            Some("Request is not in a valid stage".to_string())
        );

        let unparseable = UpstreamResponse {
            status: 404,
            body: "not json".to_string(),
            total_count: None,
        };
        assert_eq!(unparseable.api_error_message(), None);
    }

    #[test]
    fn total_count_header_parses_only_valid_unsigned_integers() {
        use reqwest::header::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        headers.insert(TOTAL_COUNT_HEADER, HeaderValue::from_static("142"));
        assert_eq!(parse_total_count_header(&headers), Some(142));

        // Surrounding whitespace is tolerated.
        let mut padded = HeaderMap::new();
        padded.insert(TOTAL_COUNT_HEADER, HeaderValue::from_static("  7 "));
        assert_eq!(parse_total_count_header(&padded), Some(7));

        // Absent header → None.
        assert_eq!(parse_total_count_header(&HeaderMap::new()), None);

        // Non-numeric / negative / empty values degrade to None.
        for bad in ["", "abc", "-1", "1.0", "12x"] {
            let mut headers = HeaderMap::new();
            headers.insert(TOTAL_COUNT_HEADER, HeaderValue::from_str(bad).unwrap());
            assert_eq!(
                parse_total_count_header(&headers),
                None,
                "{bad:?} must not parse"
            );
        }

        // A non-ASCII / opaque header value (to_str() fails) → None, not a panic.
        let mut opaque = HeaderMap::new();
        opaque.insert(
            TOTAL_COUNT_HEADER,
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        assert_eq!(parse_total_count_header(&opaque), None);
    }
}
