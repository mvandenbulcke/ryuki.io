//! SSR-only HTTP client for the platform API upstream.
//!
//! The browser never talks to the API directly: server functions forward
//! requests through this client after the path has passed the
//! `PortalServerBoundary` allowlist. The entire module is compiled only for
//! the SSR build so reqwest never reaches the hydrate/wasm artifact.
#![cfg(feature = "ssr")]

use std::time::Duration;

/// Env var naming the upstream API base URL.
pub const API_URL_ENV: &str = "RYUKI_API_URL";
/// Env var selecting the portal execution mode.
pub const EXECUTION_MODE_ENV: &str = "RYUKI_PORTAL_EXECUTION_MODE";
/// Env var controlling the Secure flag on the portal-origin cookie.
pub const COOKIE_SECURE_ENV: &str = "RYUKI_PORTAL_COOKIE_SECURE";

/// Default upstream base URL for plain-HTTP local development.
pub const DEFAULT_API_URL: &str = "http://127.0.0.1:8081";
/// Opt-in live mode value; anything else stays static-dry-run.
pub const LIVE_PROVIDER_MODE: &str = "live-provider";
/// Name of the session cookie on the portal origin.
pub const PORTAL_SESSION_COOKIE: &str = "ryuki_session";
/// Header carrying the forwarded session id to the API.
pub const SESSION_ID_HEADER: &str = "X-Ryuki-Session-Id";

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
    base_url: String,
    http: reqwest::Client,
    live: bool,
}

impl UpstreamClient {
    /// Builds the client once from the environment. `RYUKI_API_URL` defaults
    /// to the local API; live mode is strictly opt-in via
    /// `RYUKI_PORTAL_EXECUTION_MODE=live-provider`.
    pub fn from_env() -> Self {
        let base_url = std::env::var(API_URL_ENV)
            .ok()
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_API_URL.to_string());
        let live = std::env::var(EXECUTION_MODE_ENV)
            .map(|mode| mode.trim() == LIVE_PROVIDER_MODE)
            .unwrap_or(false);
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("portal upstream HTTP client must build");
        Self {
            base_url,
            http,
            live,
        }
    }

    /// True when the portal runs in `live-provider` mode.
    pub fn live(&self) -> bool {
        self.live
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    async fn dispatch(
        &self,
        mut request: reqwest::RequestBuilder,
        session_id: Option<&str>,
    ) -> Result<UpstreamResponse, UpstreamUnreachable> {
        if let Some(session_id) = session_id {
            request = request.header(SESSION_ID_HEADER, session_id);
        }
        let response = request.send().await.map_err(|error| UpstreamUnreachable {
            detail: redact_transport_error(&error),
        })?;
        let status = response.status().as_u16();
        if response.status().is_server_error() {
            return Err(UpstreamUnreachable {
                detail: format!("upstream returned status {status}"),
            });
        }
        let body = response.text().await.map_err(|_| UpstreamUnreachable {
            detail: "upstream body read failed".to_string(),
        })?;
        Ok(UpstreamResponse { status, body })
    }

    /// GET an allowlisted API path, forwarding the session id when present.
    pub async fn get(
        &self,
        path: &str,
        session_id: Option<&str>,
    ) -> Result<UpstreamResponse, UpstreamUnreachable> {
        self.dispatch(self.http.get(self.url(path)), session_id)
            .await
    }

    /// POST an allowlisted API path with an optional JSON body.
    pub async fn post(
        &self,
        path: &str,
        body: Option<&serde_json::Value>,
        session_id: Option<&str>,
    ) -> Result<UpstreamResponse, UpstreamUnreachable> {
        let mut request = self.http.post(self.url(path));
        if let Some(body) = body {
            request = request.json(body);
        }
        self.dispatch(request, session_id).await
    }
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

/// True when `RYUKI_PORTAL_COOKIE_SECURE=true`; defaults to false for
/// plain-HTTP development.
pub fn cookie_secure_from_env() -> bool {
    std::env::var(COOKIE_SECURE_ENV)
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
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

/// Parses the `ryuki_session` cookie out of a raw `Cookie` header value and
/// validates UUID syntax. Never returns malformed values.
pub fn session_id_from_cookie_header(cookie_header: &str) -> Option<String> {
    cookie_header
        .split(';')
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name.trim() == PORTAL_SESSION_COOKIE).then(|| value.trim().to_string())
        })
        .find(|value| is_uuid_syntax(value))
}

/// Extracts the portal session id from the inbound request cookie, if any.
/// Only the validated UUID is ever forwarded upstream — never the raw
/// `Cookie` header.
pub async fn session_id_from_request() -> Option<String> {
    let headers = leptos_axum::extract::<axum::http::HeaderMap>().await.ok()?;
    let cookie_header = headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .to_string();
    session_id_from_cookie_header(&cookie_header)
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
    } else if let Some(position) = time_with_offset.rfind(['+', '-']) {
        let (time, offset) = time_with_offset.split_at(position);
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        (time, sign * parse_utc_offset_seconds(&offset[1..])?)
    } else {
        return None;
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
    let mut cookie = format!(
        "{PORTAL_SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Appends a Set-Cookie header on the portal response that stores the
/// session id for `max_age_secs` seconds.
pub fn set_portal_session_cookie(session_id: &str, max_age_secs: u64) {
    append_set_cookie(&portal_session_cookie(
        session_id,
        max_age_secs,
        cookie_secure_from_env(),
    ));
}

/// Appends a Set-Cookie header that clears the portal session cookie.
pub fn clear_portal_session_cookie() {
    append_set_cookie(&portal_session_cookie("", 0, cookie_secure_from_env()));
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
    fn session_cookie_parsing_extracts_validated_session_only() {
        let session = "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b";
        let header = format!("theme=dark; ryuki_session={session}; other=1");
        assert_eq!(
            session_id_from_cookie_header(&header),
            Some(session.to_string())
        );
        assert_eq!(
            session_id_from_cookie_header("ryuki_session=not-a-uuid"),
            None
        );
        assert_eq!(session_id_from_cookie_header("other=value"), None);
    }

    #[test]
    fn portal_session_cookie_sets_security_attributes() {
        let session = "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b";
        let cookie = portal_session_cookie(session, 86_400, false);
        assert_eq!(
            cookie,
            format!("ryuki_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
        );
        assert!(portal_session_cookie(session, 86_400, true).ends_with("; Secure"));

        let cleared = portal_session_cookie("", 0, false);
        assert!(cleared.starts_with("ryuki_session=;"));
        assert!(cleared.contains("Max-Age=0"));
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
        };
        assert!(!response.is_success());
        assert_eq!(
            response.api_error_message(),
            Some("Request is not in a valid stage".to_string())
        );

        let unparseable = UpstreamResponse {
            status: 404,
            body: "not json".to_string(),
        };
        assert_eq!(unparseable.api_error_message(), None);
    }
}
