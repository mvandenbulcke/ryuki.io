#![recursion_limit = "512"]

mod agents;
mod audit;
mod boundary;
mod config;
mod config_store;
mod contracts;
pub mod cp_identity;
pub mod database;
mod entra_auth;
mod integration;
mod repos;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request as HttpRequest, StatusCode};
use axum::middleware;
use axum::response::Response;
use axum::{
    extract::{Query, State},
    routing::get,
    Extension, Json, Router,
};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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
use crate::entra_auth::EntraTokenValidator;
use ryuki_core::config::{AuthMode, TrustedProxyNetwork};
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

/// Resolves the request session AND a SAFE failure-reason string (EntraId
/// failures only) for logging. Mock/static/local arms are byte-unchanged and
/// never touch the validator.
async fn resolve_request_session(
    auth_mode: AuthMode,
    auth_header: Option<&str>,
    validator: &EntraTokenValidator,
) -> (AuthSession, Option<&'static str>) {
    match auth_mode {
        AuthMode::MockDryRun | AuthMode::StaticDryRun => (AuthSession::static_dry_run(), None),
        // Local mode without a persisted session is unauthenticated: zero
        // roles, token_valid=false. Both unsafe methods AND non-exempt reads
        // 401 until login (B3) — the portal sends X-Ryuki-Session-Id after the
        // local login flow.
        AuthMode::Local => (unverified_session("local-unauthenticated"), None),
        // EntraId: a real bearer token is cryptographically validated by the
        // injected validator (RS256 + iss/aud/exp/nbf + JWKS). A missing header
        // or any failure path is unverified_entra().
        AuthMode::EntraId => match auth_header {
            Some(h) => {
                let outcome = validator.validate_with_reason(h).await;
                (outcome.session, outcome.failure_reason)
            }
            None => (AuthSession::unverified_entra(), Some("missing-bearer")),
        },
    }
}

/// Resolves the request session for the given auth mode and optional bearer
/// header. Validator-aware: EntraId tokens are cryptographically validated by
/// the injected validator; all other modes are unchanged.
#[cfg_attr(not(test), allow(dead_code))]
async fn auth_session_for_request(
    auth_mode: AuthMode,
    auth_header: Option<&str>,
    validator: &EntraTokenValidator,
) -> AuthSession {
    resolve_request_session(auth_mode, auth_header, validator)
        .await
        .0
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

/// Extracts the `ryuki_session` cookie value from the Cookie header, if any.
fn session_cookie_value(headers: &HeaderMap) -> Option<&str> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        if name.trim() == "ryuki_session" {
            Some(value.trim())
        } else {
            None
        }
    })
}

/// Which request surface carried the session id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionIdSource {
    /// `X-Ryuki-Session-Id` header (the portal's canonical surface).
    Header,
    /// `Authorization: Bearer <uuid>` (direct API callers).
    Bearer,
    /// `ryuki_session` cookie. Browsers attach it automatically, so it never
    /// authorizes unsafe methods (CSRF defense).
    Cookie,
}

/// Resolves the caller's session id, in order: X-Ryuki-Session-Id header,
/// `Authorization: Bearer <uuid>`, then the `ryuki_session` cookie. Returns
/// the parse result together with the source that carried the id.
fn session_id_from_headers(
    headers: &HeaderMap,
    auth_header: Option<&str>,
) -> Option<(Result<Uuid, ()>, SessionIdSource)> {
    if let Some(raw_session_id) = headers
        .get("X-Ryuki-Session-Id")
        .and_then(|value| value.to_str().ok())
    {
        return Some((
            Uuid::parse_str(raw_session_id.trim()).map_err(|_| ()),
            SessionIdSource::Header,
        ));
    }

    if let Some(auth_value) = bearer_value(auth_header) {
        // A non-UUID bearer value is not a session id (e.g. a JWT); fall
        // through to the cookie source instead of failing.
        if !auth_value.is_empty() {
            if let Ok(session_id) = Uuid::parse_str(auth_value) {
                return Some((Ok(session_id), SessionIdSource::Bearer));
            }
        }
    }

    if let Some(cookie_value) = session_cookie_value(headers) {
        return Some((
            Uuid::parse_str(cookie_value).map_err(|_| ()),
            SessionIdSource::Cookie,
        ));
    }

    None
}

/// The dispatch discriminator for API-token bearers. A bearer that starts with
/// this prefix is an `api_tokens` credential, never a session UUID.
pub const API_TOKEN_PREFIX: &str = "ryk_";

/// Lowercase-hex SHA-256 of the FULL plaintext token (prefix included). This is
/// exactly what is persisted in `api_tokens.token_hash`; the token carries 256
/// bits of CSPRNG entropy, so a single fast hash is sufficient (slow KDFs exist
/// to stretch low-entropy passwords and would only add per-request latency).
pub fn sha256_hex(plaintext: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(plaintext.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(sqlx::FromRow)]
struct ApiTokenRow {
    id: Uuid,
    name: String,
    owner_principal: String,
    roles: Vec<String>,
    token_valid: bool,
    token_hash: String,
}

/// Resolves an `ryk_` API-token bearer to an `AuthSession`.
///
/// The WHERE clause filters by the exact hash and excludes revoked/expired rows;
/// the returned row's stored hash is then re-verified against the recomputed
/// digest with a constant-time compare (defense-in-depth). Not-found, expired,
/// revoked, and hash-mismatch all collapse to a single low-cardinality reason so
/// the failure surface cannot be used as an enumeration oracle. On success the
/// session carries the row's `roles`/`token_valid` verbatim and
/// `provider_mode = "api-token"`; scopes are persisted but not yet carried on
/// the session (scoped enforcement is a later feature).
async fn resolve_api_token(plaintext: &str, pool: &sqlx::PgPool) -> AuthSession {
    use subtle::ConstantTimeEq;

    let hash_hex = sha256_hex(plaintext);
    let row = sqlx::query_as::<_, ApiTokenRow>(
        "SELECT id, name, owner_principal, roles, token_valid, token_hash \
         FROM api_tokens \
         WHERE token_hash = $1 AND revoked_at IS NULL \
         AND (expires_at IS NULL OR expires_at > NOW())",
    )
    .bind(&hash_hex)
    .fetch_optional(pool)
    .await;

    let row = match row {
        Ok(Some(row)) => row,
        Ok(None) => return unverified_session("api-token-invalid"),
        Err(error) => {
            tracing::error!(error = %error, "api token lookup failed");
            return unverified_session("api-token-invalid");
        }
    };

    // Constant-time compare over the recomputed hash and the stored hash. The
    // WHERE already filtered by exact hash, so this is belt-and-suspenders, but
    // it guards against any non-constant-time comparator on the lookup path.
    if hash_hex.as_bytes().ct_eq(row.token_hash.as_bytes()).into() {
        // Update last_used_at; a failure here is non-fatal to resolution.
        if let Err(error) = sqlx::query("UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1")
            .bind(row.id)
            .execute(pool)
            .await
        {
            tracing::warn!(error = %error, token_id = %row.id, "api token last_used_at update failed");
        }
        AuthSession {
            user_id: row.owner_principal,
            display_name: row.name,
            roles: row.roles,
            token_valid: row.token_valid,
            provider_mode: "api-token".into(),
        }
    } else {
        unverified_session("api-token-mismatch")
    }
}

async fn auth_session_from_persisted_session(
    headers: &HeaderMap,
    auth_header: Option<&str>,
    auth_mode: &AuthMode,
) -> Option<(AuthSession, SessionIdSource)> {
    // API-token bearers (`ryk_...`) are resolved BEFORE the UUID/cookie path: a
    // `ryk_` string is not a valid UUID, so without this explicit branch it
    // would silently fall through to the UUID parse and become unverified.
    //
    // B5: only a SUCCESSFUL token resolution early-returns. A bogus or
    // unresolvable `ryk_` bearer (including the no-DB case where it cannot be
    // validated) must NOT shadow a valid `X-Ryuki-Session-Id` — it falls
    // through to the session-id resolution below. `session_id_from_headers`
    // already prefers the header over the bearer, so the fall-through correctly
    // honors the valid session header.
    if let Some(token) = bearer_value(auth_header) {
        if token.strip_prefix(API_TOKEN_PREFIX).is_some() {
            if let Some(pool) = crate::database::get_db() {
                let candidate = resolve_api_token(token, pool).await;
                if candidate.token_valid {
                    return Some((candidate, SessionIdSource::Bearer));
                }
                // Token did not resolve to a valid credential: fall through so a
                // valid X-Ryuki-Session-Id header is still honored.
            }
            // No pool (token cannot be validated) OR a failed resolution: do
            // NOT early-return unverified — fall through to session-id
            // resolution.
        }
    }

    let (parsed, source) = session_id_from_headers(headers, auth_header)?;
    let session_id = match parsed {
        Ok(session_id) => session_id,
        Err(()) => return Some((unverified_session("invalid-session-id"), source)),
    };
    let pool = crate::database::get_db()?;
    // Local mode only honors sessions minted by the local login flow: stale
    // dry-run sessions must not survive a switch to local auth.
    let query = if *auth_mode == AuthMode::Local {
        "SELECT user_id, display_name, roles FROM sessions \
         WHERE id = $1 AND expires_at > NOW() AND provider = 'local'"
    } else {
        "SELECT user_id, display_name, roles FROM sessions WHERE id = $1 AND expires_at > NOW()"
    };
    match sqlx::query_as::<_, DbAuthSessionRow>(query)
        .bind(session_id)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(row)) => Some((session_from_db_row(row), source)),
        Ok(None) => Some((unverified_session("session-not-found"), source)),
        Err(error) => {
            tracing::error!(error = %error, "auth session lookup failed");
            Some((unverified_session("session-lookup-failed"), source))
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
    // Exempt = reachable WITHOUT a resolved session. Two groups:
    //   1. the 4 auth POSTs (login/logout x2) — login mints a session,
    //      logout stays exempt so an expired session can still clear cookies;
    //   2. the pre-login GET reads the portal hits before a session exists,
    //      plus the infra probes (/health, /ready) which must never 401.
    // B3: groups (2) are added so read-authentication does not break the
    // portal's bootstrap or liveness/readiness probes.
    //   /api/platform/summary is the bootstrap endpoint the LOGIN VIEW itself
    //   fetches before any session exists, to choose its sign-in copy
    //   (authenticationMode local|entra-id|static-dry-run). Without the
    //   exemption an anonymous fetch 401s and the login page renders the
    //   "Platform API unreachable" degraded arm instead of the correct
    //   local-mode note, breaking the local-mode portal. The payload is
    //   non-sensitive branding/mode metadata only (product name, lifecycle
    //   stage labels, component/guardrail names, auth mode, an
    //   entra-groups-configured boolean) — no request data, secrets, tenant
    //   ids, or network values — so it is safe to read pre-login.
    matches!(
        path,
        // auth POSTs
        "/api/auth/login"
            | "/api/auth/logout"
            | "/api/auth/local/login"
            | "/api/auth/local/logout"
            // pre-login portal reads + infra probes (GET)
            | "/health"
            | "/ready"
            | "/api/auth/status"
            | "/api/auth/session"
            | "/api/auth/roles"
            | "/api/platform/summary"
    )
}

fn auth_session_allows_unsafe_method(session: &AuthSession) -> bool {
    session.token_valid || session.provider_mode == "static-dry-run"
}

/// Decides whether the resolved session may perform this request.
///
/// CSRF defense: the `ryuki_session` cookie is attached automatically by
/// browsers, so a session resolved from the COOKIE source alone never
/// authorizes unsafe methods (POST/PUT/PATCH/DELETE). The portal always
/// sends X-Ryuki-Session-Id; direct API callers use `Authorization: Bearer`.
/// Auth endpoints keep their existing exemption only because they are
/// already auth-exempt.
fn session_authorizes_request(
    method: &Method,
    path: &str,
    session: &AuthSession,
    session_source: Option<SessionIdSource>,
) -> bool {
    if !is_unsafe_method(method) || is_auth_exempt_path(path) {
        return true;
    }
    if session_source == Some(SessionIdSource::Cookie) {
        return false;
    }
    auth_session_allows_unsafe_method(session)
}

/// One row of the central mutating-route RBAC table: an unsafe-method path
/// prefix and the coarse permission required to reach it.
struct RoutePermission {
    prefix: &'static str,
    permission: &'static str,
}

/// Central route -> required-permission table for unsafe methods.
///
/// ORDER MATTERS: more-specific prefixes come FIRST so the longest match wins
/// (e.g. `/api/protect/secrets/rotate-all` is `admin` while the rest of
/// `/api/protect` is `execute`, and `/api/ops/emergency` is `admin` while the
/// rest of `/api/ops` is `execute`). `route_permission_for` scans this slice in
/// order and returns the first prefix that matches. The method is implicitly
/// "any unsafe method" this wave (POST/PUT/PATCH/DELETE on a family share a
/// permission; finer method/sub-path granularity is a later wave).
///
/// `/api/requests` is handled by the dedicated `requests_route_permission`
/// resolver BEFORE this table is consulted, because its sub-paths split across
/// request/approve/execute.
static ROUTE_PERMISSIONS: &[RoutePermission] = &[
    // emergency / break-glass and platform admin (most specific first)
    RoutePermission {
        prefix: "/api/ops/emergency",
        permission: "admin",
    },
    RoutePermission {
        prefix: "/api/admin",
        permission: "admin",
    },
    RoutePermission {
        prefix: "/api/protect/secrets/rotate-all",
        permission: "admin",
    },
    RoutePermission {
        prefix: "/api/protect",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/identity",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/network",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/build",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/vm",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/maintain",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/observe",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/monitoring",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/datacenter",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/inventory",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/cmdb",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/analytics",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/evidence",
        permission: "execute",
    },
    // incident/runbook/shift — after the /api/ops/emergency admin row above
    RoutePermission {
        prefix: "/api/ops",
        permission: "execute",
    },
    RoutePermission {
        prefix: "/api/retire",
        permission: "execute",
    },
];

/// Fail-closed default: an unsafe, non-exempt route that matches no row is
/// locked to `admin` until someone classifies it. A newly added mutating route
/// is never silently open.
const DEFAULT_ROUTE_PERMISSION: &str = "admin";

/// Resolves the permission for a mutation under `/api/requests`.
///
/// - `/api/requests` exactly (POST create)                -> "request"
/// - `/api/requests/{id}/approve`                          -> "approve"
/// - `/api/requests/{id}/reject`                           -> "approve"
///   (reject is an approver act — the inverse of approve — so the central
///   route gate matches the handler guard)
/// - `/api/requests/{id}/cancel`                           -> "request"
///   (coarse requester-tier floor: a cancel can be initiated by the requester
///   who raised the request, so the central gate must admit `request`-holders;
///   the finer requester-OWNS-it-or-admin SoD check is enforced in the handler
///   against `created_by`, which the central table cannot see. An admin passes
///   via the superuser model.)
/// - `/api/requests/{id}/{validate|plan|lock|execute|verify}` -> "execute"
/// - any other `/api/requests/...` mutation                -> "execute"
///   (fail-toward-operator; a request-family mutation never falls back to the
///   requester tier or to the global admin default)
///
/// Returns `None` when `path` is not under `/api/requests`, so the caller falls
/// through to the static prefix table.
fn requests_route_permission(path: &str) -> Option<&'static str> {
    if path == "/api/requests" {
        return Some("request");
    }
    let rest = path.strip_prefix("/api/requests/")?;
    // rest looks like "{id}", "{id}/approve", "{id}/validate", ...
    match rest.rsplit('/').next() {
        Some("approve") => Some("approve"),
        // reject is an approver decision (the inverse of approve)
        Some("reject") => Some("approve"),
        // cancel: requester-tier floor so the requester who raised the request
        // reaches the handler, where the finer requester-OWNS-it-or-admin SoD
        // check runs against the row's created_by (the route table cannot
        // evaluate it). Admin passes via the superuser model.
        Some("cancel") => Some("request"),
        // live-apply approval mints a CP-signed grant authorising infrastructure
        // mutation — admin-tier (the handler re-checks admin as defence-in-depth).
        Some("approve-live-apply") => Some("admin"),
        // every other request-family mutation is operator-tier
        _ => Some("execute"),
    }
}

/// Resolves the permission for operational maker/checker APPROVAL sign-offs.
///
/// These routes sit under `execute`-tier families (`/api/ops`, `/api/maintain`,
/// `/api/build`, …) but each transitions an entity into an `Approved`/decided
/// state that gates further action — so, exactly like `/api/requests/{id}/approve`,
/// they require the higher `approve` tier. Without this row an Operator (who holds
/// `execute`, not `approve`) could self-approve work they created or validated,
/// collapsing the platform's maker/checker separation of duties into a single
/// operator capability. The handlers do their own `Approved`-state transition with
/// no in-handler permission check, so the central gate is the only boundary.
///
/// The access-review family carries all three reviewer VERDICTS (approve / revoke /
/// exempt) at the `approve` tier, mirroring how the request family routes both
/// `approve` and `reject` (the inverse verdict) to `approve`.
///
/// NOT included — `/api/cmdb/servicenow/approve` and
/// `/api/maintain/certificates/approve` carry the `approve` NAME but gate nothing
/// (read-only acknowledgements: no `Approved` state exists in their domain and no
/// downstream action requires them), so they stay operator-tier.
///
/// Returns `None` for non-approval paths so the caller falls through to the prefix
/// table.
fn approval_signoff_permission(path: &str) -> Option<&'static str> {
    // id-at-end or no-id forms: a static prefix matches `{prefix}` exactly or
    // `{prefix}/{id}`.
    const APPROVE_SIGNOFF_PREFIXES: &[&str] = &[
        "/api/ops/runbook/approve",
        "/api/maintain/patch/approve",
        "/api/maintain/software/approve",
        "/api/protect/backup/restore-approve",
        "/api/build/app-environment/approve",
        "/api/retire/decommission/approve",
    ];
    if APPROVE_SIGNOFF_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
    {
        return Some("approve");
    }
    // Access-review reviewer verdicts put the id in the MIDDLE
    // (`/api/identity/access-review/{id}/{approve|revoke|exempt}`), which a static
    // prefix cannot express. Match exactly one id segment then the verdict.
    if let Some(rest) = path.strip_prefix("/api/identity/access-review/") {
        for verdict in ["approve", "revoke", "exempt"] {
            if let Some(id) = rest.strip_suffix(&format!("/{verdict}")) {
                if !id.is_empty() && !id.contains('/') {
                    return Some("approve");
                }
            }
        }
    }
    None
}

/// Central resolver applied in `auth_middleware` for unsafe methods. `method`
/// is accepted for forward-compatibility (per-method granularity is a later
/// wave); this wave treats every unsafe method on a path family identically.
/// Returns the required coarse permission, defaulting fail-closed to `admin`.
fn route_permission_for(_method: &Method, path: &str) -> &'static str {
    if let Some(permission) = requests_route_permission(path) {
        return permission;
    }
    // Maker/checker approval sign-offs that live under execute-tier families must
    // be resolved BEFORE the prefix table, which would otherwise map them to
    // `execute` via their family root.
    if let Some(permission) = approval_signoff_permission(path) {
        return permission;
    }
    ROUTE_PERMISSIONS
        .iter()
        .find(|row| path == row.prefix || path.starts_with(&format!("{}/", row.prefix)))
        .map(|row| row.permission)
        .unwrap_or(DEFAULT_ROUTE_PERMISSION)
}

/// Read families that carry identity/secret-grade data and require `admin` to
/// read, not the ordinary `audit` read tier. These are disjoint family roots
/// (no longest-match needed): an `admin` is returned if ANY matches.
static SENSITIVE_READ_PREFIXES: &[&str] =
    &["/api/protect/secrets", "/api/ops/emergency", "/api/admin"];

/// Resolves the permission required to READ (safe method) a path. Reuse of
/// `route_permission_for` is wrong for reads because the mutating table maps
/// families like `/api/protect`->execute and `/api/requests`->request, which
/// would lock a plain auditor out of ordinary GETs. Instead: sensitive read
/// prefixes require `admin`; everything else is an ordinary read requiring
/// `audit`. A logged-in Auditor (holds `audit`) reads ordinary GETs but 403s on
/// the sensitive prefixes; a static-dry-run/PlatformAdmin session satisfies
/// both via the superuser model, so the demo and mock mode keep reading.
fn read_permission_for(path: &str) -> &'static str {
    let sensitive = SENSITIVE_READ_PREFIXES
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")));
    if sensitive {
        "admin"
    } else {
        "audit"
    }
}

/// Audit-grade reads carry identity-grade who-did-what-when data and require
/// the `audit` tier SPECIFICALLY — never the ordinary `request` tier. Matching
/// the central gate to the handler's own `check_permission(audit)` closes the
/// defense-in-depth gap where a `request`-only Requester passed the route gate
/// (and was only stopped by the handler). Covers the global activity feed, every
/// per-request `/api/requests/{id}/audit` trail, and the per-request
/// `/api/requests/{id}/evidence` compliance pack (which embeds the audit trail);
/// the plain request detail (`/api/requests/{id}`, no suffix) stays
/// `request`-readable.
fn is_audit_read_path(path: &str) -> bool {
    path == "/api/activity/audit"
        || (path.starts_with("/api/requests/")
            && (path.ends_with("/audit") || path.ends_with("/evidence")))
}

/// Whether `session` may read `path`. Sensitive prefixes require `admin`; audit
/// trails require the `audit` tier specifically; all other ordinary reads
/// accept any standard read permission — `audit`
/// (Auditor/operators/approver/service-desk) OR `request`
/// (Requester/service-desk) — so a Requester can view their own requests.
/// `admin` satisfies everything via the check_permission superuser rule.
fn read_authorized(session: &AuthSession, path: &str) -> bool {
    if is_audit_read_path(path) {
        return ryuki_engine::auth::check_permission(session, "audit");
    }
    match read_permission_for(path) {
        "admin" => ryuki_engine::auth::check_permission(session, "admin"),
        _ => {
            ryuki_engine::auth::check_permission(session, "audit")
                || ryuki_engine::auth::check_permission(session, "request")
        }
    }
}

/// Notification self-service mutations (mark-one-read, mark-all-read) are
/// authorized at the ordinary read tier (`audit` OR `request`) rather than the
/// fail-closed `admin` default, because every notification recipient holds one
/// of those tiers and the repo's recipient-filtered UPDATE is the real
/// authorization boundary. Without this a plain Requester could see their own
/// notifications but not mark them read. Scoped to exactly the two mutation
/// paths so no other `/api/notifications` route is affected.
fn is_notifications_self_service_path(path: &str) -> bool {
    if path == "/api/notifications/read-all" {
        return true;
    }
    // Exactly `/api/notifications/{id}/read`: one non-empty id segment, no
    // extra path segments (so deeper/other paths don't inherit the read tier).
    if let Some(id) = path
        .strip_prefix("/api/notifications/")
        .and_then(|rest| rest.strip_suffix("/read"))
    {
        return !id.is_empty() && !id.contains('/');
    }
    false
}

/// Builds the 403 ProblemDetails response for a missing mutating permission.
fn forbidden(required: &str) -> Response {
    let body = serde_json::to_string(&ApiError::with_detail(
        "FORBIDDEN",
        "You do not have permission to perform this operation",
        format!("Missing required permission: {required}"),
    ))
    .unwrap_or_else(|_| {
        r#"{"error":"FORBIDDEN","message":"You do not have permission to perform this operation"}"#
            .into()
    });
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// Returns the first configured local-auth role that is not in the
/// application role catalog, as (entry index, role). Never touches passwords.
fn find_unknown_local_auth_role(
    local_auth: &ryuki_core::config::LocalAuthConfig,
) -> Option<(usize, String)> {
    for (entry_index, user) in local_auth.users.users().iter().enumerate() {
        for role in &user.roles {
            if !ryuki_engine::auth::ALL_APP_ROLES.contains(&role.as_str()) {
                return Some((entry_index, role.clone()));
            }
        }
    }
    None
}

fn bind_address_is_loopback(bind_address: &str) -> bool {
    bind_address
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or(false)
}

/// Resolves the session, enforces the 401 verified-auth gates (unsafe + read),
/// then the RBAC gate, before handing off to the handler.
///
/// READ AUTHENTICATION (B3): non-exempt GETs are now authenticated. A read
/// requires a resolved session UNLESS the session is static-dry-run, which is
/// admitted so the GitHub Pages demo and mock mode keep rendering reads
/// anonymously. Ordinary reads require the `audit` tier; sensitive read
/// prefixes (`/api/protect/secrets`, `/api/ops/emergency`, `/api/admin`)
/// require `admin`. Mutations are unchanged. The exempt set
/// (`is_auth_exempt_path`) covers the auth POSTs plus the pre-login portal
/// reads and infra probes so the portal bootstrap and liveness/readiness checks
/// are never gated.
async fn auth_middleware(
    State(validator): State<Arc<EntraTokenValidator>>,
    headers: HeaderMap,
    mut request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    let auth_mode = crate::config_store::get_app_config().auth_mode.clone();
    let log = resolve_auth_metadata(auth_header, auth_mode.as_str());

    // Persisted DB session wins for Local/persisted flows; only the None
    // fallback runs validator-aware resolution.
    let (session, session_source, failure_reason) =
        match auth_session_from_persisted_session(&headers, auth_header, &auth_mode).await {
            Some((session, source)) => (session, Some(source), None),
            None => {
                let (session, reason) =
                    resolve_request_session(auth_mode, auth_header, &validator).await;
                (session, None, reason)
            }
        };

    // SAFE logging: presence + mode + token_valid + an optional low-cardinality
    // failure-reason string. NEVER the token, claims, oid, or header bytes.
    tracing::info!(
        auth_header_present = log.auth_header_present,
        provider_mode = log.provider_mode,
        token_valid = session.token_valid,
        failure_reason = failure_reason.unwrap_or(""),
        "auth middleware"
    );

    // 401 gate for UNSAFE methods (POST/PUT/PATCH/DELETE): a verified or
    // static-dry-run session is required; cookie-only sessions are refused
    // (CSRF defense). Unchanged.
    if !session_authorizes_request(&method, &path, &session, session_source) {
        return auth_required_response();
    }

    // B3: 401 gate for SAFE methods (reads). A non-exempt GET now requires a
    // resolved session UNLESS it is static-dry-run — that admission keeps the
    // GitHub Pages demo and mock mode reading anonymously (token_valid=false,
    // provider_mode=="static-dry-run"). A Local-mode anonymous GET (an
    // unverified, zero-role session that is NOT static-dry-run) 401s, which is
    // correct: the portal sends X-Ryuki-Session-Id after login. The CSRF
    // cookie-only restriction does NOT apply to reads (GETs are safe), so the
    // Cookie==>false rule is intentionally not reused here.
    let read_requires_session = !is_unsafe_method(&method) && !is_auth_exempt_path(&path);
    if read_requires_session && !session.token_valid && session.provider_mode != "static-dry-run" {
        return auth_required_response();
    }

    // RBAC gate. Runs for EVERY non-exempt method (B3 dropped the
    // `is_unsafe_method` precondition so GETs are gated too) and AFTER the 401
    // gates, so an unauthenticated caller still 401s and only an
    // authenticated-but-underprivileged caller 403s. The only difference is
    // WHICH permission the path maps to: mutations use the mutating route
    // table; reads use the read-permission tier (audit, or admin for sensitive
    // read prefixes). Handler-level check_permission calls stay as
    // defense-in-depth.
    if !is_auth_exempt_path(&path) {
        // Notification self-service mutations are gated like reads (audit OR
        // request), not as ordinary mutations (which would fall to the admin
        // default); the repo's recipient filter is the real boundary.
        let notif_self_service =
            is_unsafe_method(&method) && is_notifications_self_service_path(&path);
        let required = if is_unsafe_method(&method) && !notif_self_service {
            route_permission_for(&method, &path)
        } else {
            read_permission_for(&path)
        };
        // Mutations require the exact route permission; reads — and notification
        // self-service mutations — use the shared read_authorized tier (sensitive
        // -> admin; ordinary -> audit OR request) so a recipient can manage their
        // own feed and a Requester can view their own requests.
        let authorized = if is_unsafe_method(&method) && !notif_self_service {
            ryuki_engine::auth::check_permission(&session, required)
        } else {
            read_authorized(&session, &path)
        };
        if !authorized {
            tracing::warn!(
                user_id = %session.user_id,
                method = %method,
                path = %path,
                required,
                "authorization denied: missing required permission"
            );
            // B7: audit the denial for AUTHENTICATED callers only. The
            // token_valid guard keeps anonymous callers (who already 401 at the
            // gates above for unsafe/sensitive/Local reads) from flooding the
            // trail; static-dry-run (token_valid=false) never fails a check
            // anyway (superuser), so it is intentionally not recorded here. A
            // failure to record never changes the 403.
            if session.token_valid {
                audit::record_denied(
                    crate::database::get_db(),
                    &session,
                    &audit::AuditRecord {
                        action: "authz.denied",
                        request_id: None,
                        from_status: None,
                        to_status: "denied",
                        from_stage: None,
                        to_stage: "denied",
                        detail: serde_json::json!({
                            "method": method.as_str(),
                            "path": path,
                            "required": required,
                        }),
                        outcome: "denied",
                    },
                )
                .await;
            }
            return forbidden(required);
        }
    }

    request.extensions_mut().insert(session);
    next.run(request).await
}

/// The 401 AUTH_REQUIRED response, shared by the unsafe-method gate and the B3
/// read-auth gate.
fn auth_required_response() -> Response {
    let body = serde_json::to_string(&ApiError::new(
        "AUTH_REQUIRED",
        "Verified authentication is required for this operation",
    ))
    .unwrap_or_else(|_| {
        r#"{"error":"AUTH_REQUIRED","message":"Verified authentication is required for this operation"}"#.into()
    });
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
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
        let mut counts = lock_or_recover(&per_endpoint().counts);
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

/// Acquires a mutex guard, recovering from poisoning instead of panicking.
/// These mutexes guard best-effort metrics state only; a poisoned lock
/// (from a panic elsewhere) must never cascade into an API outage. A
/// possibly-inconsistent metric read after a panic is acceptable.
fn lock_or_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
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
    let mut durations = lock_or_recover(&tracker.durations);
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
    /// Peers matching one of these networks may speak for their clients via
    /// X-Forwarded-For; everyone else is keyed on their own peer address.
    trusted_proxies: Arc<Vec<TrustedProxyNetwork>>,
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

/// How the rate-limit client key was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientKeySource {
    /// The TCP peer address (the default; never spoofable).
    Peer,
    /// X-Forwarded-For, honored only because the peer is a trusted proxy.
    Forwarded,
}

impl ClientKeySource {
    fn as_str(self) -> &'static str {
        match self {
            ClientKeySource::Peer => "peer",
            ClientKeySource::Forwarded => "forwarded",
        }
    }
}

/// Resolves the rate-limit client key. The connecting peer address is
/// authoritative; X-Forwarded-For is consulted only when the peer is a
/// trusted proxy, in which case the rightmost entry that is not itself a
/// trusted proxy wins (entries left of it are client-controlled, entries
/// right of it are our own proxy tier). If the whole chain is trusted
/// proxies — or the header is absent — the peer address is the key.
fn resolve_rate_limit_client_key(
    peer_addr: SocketAddr,
    forwarded_for: Option<&str>,
    trusted_proxies: &[TrustedProxyNetwork],
) -> (String, ClientKeySource) {
    let peer_ip = peer_addr.ip().to_canonical();
    let is_trusted = |ip: IpAddr| trusted_proxies.iter().any(|network| network.contains(ip));
    let peer_key = || (peer_ip.to_string(), ClientKeySource::Peer);

    if !is_trusted(peer_ip) {
        return peer_key();
    }
    let Some(forwarded_for) = forwarded_for else {
        return peer_key();
    };
    for entry in forwarded_for.rsplit(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        match parse_forwarded_entry_ip(entry) {
            Some(ip) => {
                let ip = ip.to_canonical();
                if is_trusted(ip) {
                    // a hop our own proxy tier appended; keep walking left
                    continue;
                }
                return (ip.to_string(), ClientKeySource::Forwarded);
            }
            // A non-IP entry (e.g. an RFC 7239 obfuscated identifier written
            // by the trusted proxy) cannot be a trusted proxy: key on it.
            None => return (entry.to_string(), ClientKeySource::Forwarded),
        }
    }
    peer_key()
}

/// Parses one X-Forwarded-For entry: a plain IP, `ip:port`, or `[v6]:port`.
fn parse_forwarded_entry_ip(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }
    entry.parse::<SocketAddr>().map(|socket| socket.ip()).ok()
}

async fn rate_limit_middleware(
    limiter: Option<SharedRateLimiters>,
    request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    if let Some(ref limiters) = limiter {
        // Inserted by into_make_service_with_connect_info in main(); absent
        // only if the router is served without connect info (a programming
        // error), in which case requests pass unlimited rather than sharing
        // one global bucket.
        let Some(ConnectInfo(peer_addr)) = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .copied()
        else {
            tracing::error!("peer address unavailable; request not rate limited");
            return next.run(request).await;
        };

        let forwarded_for = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());
        let (client_key, key_source) =
            resolve_rate_limit_client_key(peer_addr, forwarded_for, &limiters.trusted_proxies);

        let path_group = rate_limit_path_group(request.uri().path());

        let key = format!("{path_group}:{client_key}");
        let limiter = limiters.for_path_group(&path_group);

        if limiter.check_key(&key).is_err() {
            tracing::warn!(
                client = %client_key,
                key_source = key_source.as_str(),
                path_group,
                "rate limit exceeded"
            );
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

    // Config validation (RyukiConfig::validate) already flags malformed
    // entries as hard errors; skipping here keeps boot resilient while
    // never silently trusting a peer the operator did not spell correctly.
    let trusted_proxies = config
        .trusted_proxies
        .iter()
        .filter_map(|entry| {
            TrustedProxyNetwork::parse(entry)
                .inspect_err(|error| {
                    tracing::warn!(entry = %entry, error = %error, "invalid trusted proxy entry, skipping");
                })
                .ok()
        })
        .collect();

    Some(Arc::new(RateLimiters {
        default,
        path_overrides: Arc::new(path_overrides),
        trusted_proxies: Arc::new(trusted_proxies),
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

    if app_config.auth_mode == AuthMode::Local {
        if let Some((entry_index, role)) = find_unknown_local_auth_role(&app_config.local_auth) {
            tracing::error!(
                entry_index,
                role = %role,
                "local_auth.users entry references a role outside the application role catalog"
            );
            std::process::exit(1);
        }
    }
    if !app_config.session.cookie_secure
        && !bind_address_is_loopback(&app_config.server.bind_address)
    {
        tracing::warn!(
            bind_address = %app_config.server.bind_address,
            "session.cookie_secure is false on a non-loopback bind address; session cookies may be exposed over plain HTTP"
        );
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

    // ── Site registry startup hydration ──────────────────────────────────────
    //
    // Load persisted active/inactive toggles from the DB and apply them to the
    // engine's static store (write-through cache). This makes cross-engine reads
    // (is_valid_site, get_active_site_codes) reflect the persisted state on boot.
    // Guard: only when a pool is available. Non-fatal on error.
    if let Some(pool) = crate::database::get_db() {
        match crate::repos::site_registry::list_active_states(pool).await {
            Ok(states) => {
                ryuki_engine::site_registry::hydrate_active_states(&states);
                tracing::info!(count = states.len(), "site registry hydrated from DB");
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "site registry hydration failed — falling back to seed defaults"
                );
            }
        }
    }

    // ── CP signing identity ───────────────────────────────────────────────────
    //
    // The control plane's Ed25519 keypair is used to sign `VerifiedLiveContext`
    // grants that authorise `LiveApply` jobs (S5a-2). The 32-byte raw seed is
    // persisted create-only at mode 0600; the public key is logged at startup
    // (NOT the secret) so operators can confirm the key fingerprint.
    {
        let key_path_str = std::env::var("RYUKI_CP_SIGNING_KEY_PATH")
            .unwrap_or_else(|_| "cp-signing.key".to_string());
        let key_path = std::path::Path::new(&key_path_str);
        match cp_identity::load_or_generate_cp_key(key_path) {
            Ok(key) => {
                let pubkey_b64 = ryuki_protocol::encode_verifying_key(&key.verifying_key());
                tracing::info!(
                    cp_pubkey = %pubkey_b64,
                    key_path = %key_path_str,
                    "CP signing key loaded (public key fingerprint logged; secret NOT logged)"
                );
                cp_identity::init_cp_key(key);
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    key_path = %key_path_str,
                    "failed to load or generate CP signing key — LiveApply grants will be unavailable"
                );
                // Non-fatal: the server continues; LiveApply jobs that require a
                // CP-signed grant will return 503 from the grant endpoint.
            }
        }
    }

    // Spawn background lease-expiry sweep (Fix 4: DB-time deadlines + periodic
    // expiry). Only spawns when a DB pool is available. The task is idempotent
    // and cancelled automatically when the tokio runtime shuts down.
    if let Some(pool) = crate::database::get_db() {
        agents::spawn_lease_expiry_sweep(pool.clone(), 30);
        tracing::info!("agent lease expiry sweep started (interval: 30s)");
    }

    let rate_limiter = create_rate_limiter(&app_config.rate_limit);
    // Per-username failed-login throttle for POST /api/auth/local/login,
    // shared with the handler through an Extension (no global mutable state).
    let local_login_throttle = Arc::new(contracts::LocalLoginThrottle::default());

    // Entra ID token validator, built ONCE at startup from the live config.
    // issuer/audience are fixed for the process lifetime (a settings change
    // takes effect on the next restart, like every other entra_* consumer);
    // only the JWKS keyset refreshes live, behind its own lock inside the Arc.
    let entra_validator = Arc::new(EntraTokenValidator::from_app_config(
        &app_config.entra_tenant_id,
        &app_config.entra_client_id,
        &app_config.entra_authority,
        app_config.entra_jwks_ttl_secs,
        app_config.entra_leeway_secs,
    ));

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

    // ── Route composition (Fix 2: agent-token vs human auth separation) ──────
    //
    // Agent endpoints (register, poll, ack, heartbeat) must NOT pass through the
    // human `auth_middleware`. `register` is the open enrollment endpoint — it
    // MINTS the "rya_" token and creates a `pending` agent (no token yet, admin
    // must approve before it can pull). poll/ack/heartbeat carry that "rya_"
    // bearer token, validated inside each handler by `authenticate_agent`.
    //
    // admin_approve sits under /api/admin/agents/ and IS gated by the human
    // auth_middleware (which enforces `admin` RBAC for any /api/admin prefix
    // via the fail-closed DEFAULT_ROUTE_PERMISSION = "admin").
    //
    // The structure is:
    //   outer_app = human_gated_app   (auth + RBAC)
    //             + agent_token_app   (bypasses human auth — own bearer gate)
    //             + infra routes      (health/ready/metrics — also bypass auth)
    //
    // Axum applies layers only to the sub-router they wrap, so
    // agent_routes() and infra routes merged at the outer level never see
    // auth_middleware.

    // Inner router: everything that must go through human session auth. These
    // /metrics + /api/platform/* + /api/validation/run endpoints were auth-gated
    // before the agent-router split (auth_middleware ran on them; they are NOT in
    // is_auth_exempt_path) — they expose metrics and config/status that must
    // require a session, so they stay inside the human-gated router.
    let human_gated_app = Router::new()
        .route("/metrics", get(metrics))
        .route("/api/validation/run", get(validation_run))
        .route("/api/platform/status", get(platform_status))
        .route("/api/platform/uptime", get(uptime))
        .merge(agents::admin_routes())
        .merge(contracts::routes())
        .merge(boundary::routes())
        .merge(integration::routes())
        .layer(middleware::from_fn_with_state(
            entra_validator.clone(),
            auth_middleware,
        ));

    let app = Router::new()
        // Infra probes only — must never 401 (were exempt via is_auth_exempt_path).
        .route("/health", get(health))
        .route("/ready", get(ready))
        // Agent-token endpoints bypass human auth_middleware entirely (they
        // authenticate via authenticate_agent / the rya_ bearer token).
        .merge(agents::agent_routes())
        // Human-session routes (includes admin_approve + all existing routes).
        .merge(human_gated_app)
        .fallback(not_found)
        .layer(Extension(local_login_throttle))
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
    // Connect info gives rate limiting a trustworthy peer address.
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
    let durations = lock_or_recover(&tracker.durations);
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
    let counts = lock_or_recover(&per_endpoint().counts);
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
    fn lock_or_recover_returns_usable_guard_after_poison() {
        use std::sync::{Arc, Mutex};
        let m = Arc::new(Mutex::new(0u64));
        // Poison the mutex: lock it in a thread that panics while holding the guard.
        let m2 = Arc::clone(&m);
        let handle = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("intentional panic while holding the lock");
        });
        assert!(handle.join().is_err()); // thread panicked -> mutex now poisoned
                                         // Helper must still return a usable guard without panicking.
        let mut g = lock_or_recover(&m); // would panic with .lock().unwrap()
        *g += 1;
        assert_eq!(*g, 1);
    }

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
    fn test_sha256_hex_is_lowercase_64_hex() {
        // Known SHA-256 of the empty string. Confirms lowercase hex, fixed width.
        let digest = sha256_hex("");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digest.len(), 64);
        assert!(digest
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    #[test]
    fn test_sha256_hex_covers_full_prefixed_plaintext() {
        // The hash is over the full `ryk_`-prefixed string, so two tokens that
        // differ only after the prefix hash to different values, and the prefix
        // is part of the hashed input (changing it changes the digest).
        let token_a = format!("{API_TOKEN_PREFIX}aaaa");
        let token_b = format!("{API_TOKEN_PREFIX}bbbb");
        assert_ne!(sha256_hex(&token_a), sha256_hex(&token_b));
        assert_ne!(sha256_hex(&token_a), sha256_hex("xyz_aaaa"));
    }

    #[test]
    fn test_constant_time_hash_compare_matches_only_identical() {
        use subtle::ConstantTimeEq;
        let token = format!("{API_TOKEN_PREFIX}sometoken");
        let hash = sha256_hex(&token);
        let same = sha256_hex(&token);
        let different = sha256_hex(&format!("{API_TOKEN_PREFIX}othertoken"));
        let matches: bool = hash.as_bytes().ct_eq(same.as_bytes()).into();
        let mismatches: bool = hash.as_bytes().ct_eq(different.as_bytes()).into();
        assert!(matches);
        assert!(!mismatches);
    }

    #[test]
    fn test_api_token_prefix_dispatch() {
        // The resolution branch keys on the `ryk_` prefix; a bearer that lacks
        // it falls through to the session-id path (it is not an API token).
        assert!(format!("{API_TOKEN_PREFIX}abc")
            .strip_prefix(API_TOKEN_PREFIX)
            .is_some());
        assert!(Uuid::parse_str("not-a-ryk-token").is_err());
        assert!("550e8400-e29b-41d4-a716-446655440000"
            .strip_prefix(API_TOKEN_PREFIX)
            .is_none());
    }

    /// Builds an enabled, network-backed validator with no usable keyset. It is
    /// used by middleware-arm tests that never expect a successful validation
    /// (mock arm short-circuits; the unsigned-entra token fails to decode).
    fn test_validator() -> EntraTokenValidator {
        EntraTokenValidator::from_app_config(
            "test-tenant",
            "test-client",
            "https://login.microsoftonline.com",
            86_400,
            60,
        )
    }

    #[tokio::test]
    async fn test_static_auth_mode_ignores_authorization_header() {
        let validator = test_validator();
        let session = auth_session_for_request(
            AuthMode::MockDryRun,
            Some("header.eyJyb2xlcyI6WyJQbGF0Zm9ybUFkbWluIl19.signature"),
            &validator,
        )
        .await;
        assert_eq!(session.provider_mode, "static-dry-run");
        assert_eq!(session.roles, vec!["PlatformAdmin"]);
        assert!(!session.token_valid);
    }

    #[tokio::test]
    async fn test_entra_auth_mode_rejects_unsigned_roles_claim() {
        let validator = test_validator();
        let session = auth_session_for_request(
            AuthMode::EntraId,
            Some("Bearer header.eyJyb2xlcyI6WyJQbGF0Zm9ybUFkbWluIl19.signature"),
            &validator,
        )
        .await;
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

        let (parsed, source) =
            session_id_from_headers(&headers, None).expect("session header should be recognized");
        assert_eq!(parsed.expect("session header should parse"), session_id);
        assert_eq!(source, SessionIdSource::Header);
    }

    #[test]
    fn test_session_id_from_bearer_uuid() {
        let session_id = Uuid::new_v4();
        let headers = HeaderMap::new();

        let (parsed, source) =
            session_id_from_headers(&headers, Some(&format!("Bearer {}", session_id)))
                .expect("bearer uuid should be recognized");
        assert_eq!(parsed.expect("bearer uuid should parse"), session_id);
        assert_eq!(source, SessionIdSource::Bearer);
    }

    #[test]
    fn test_non_uuid_bearer_is_not_session_id() {
        let headers = HeaderMap::new();
        assert!(session_id_from_headers(&headers, Some("Bearer jwt-token")).is_none());
    }

    #[test]
    fn test_session_id_from_ryuki_session_cookie() {
        let session_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!(
                "other=1; ryuki_session={}; theme=dark",
                session_id
            ))
            .unwrap(),
        );

        let (parsed, source) =
            session_id_from_headers(&headers, None).expect("session cookie should be recognized");
        assert_eq!(parsed.expect("session cookie should parse"), session_id);
        assert_eq!(source, SessionIdSource::Cookie);
    }

    #[test]
    fn test_malformed_session_cookie_is_invalid_not_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("ryuki_session=not-a-uuid"),
        );

        assert_eq!(
            session_id_from_headers(&headers, None),
            Some((Err(()), SessionIdSource::Cookie))
        );
    }

    #[test]
    fn test_session_header_takes_precedence_over_cookie() {
        let header_id = Uuid::new_v4();
        let cookie_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Ryuki-Session-Id",
            HeaderValue::from_str(&header_id.to_string()).unwrap(),
        );
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!("ryuki_session={}", cookie_id)).unwrap(),
        );

        let (parsed, source) = session_id_from_headers(&headers, None).unwrap();
        assert_eq!(parsed.unwrap(), header_id);
        assert_eq!(source, SessionIdSource::Header);
    }

    #[test]
    fn test_non_uuid_bearer_falls_through_to_cookie() {
        let cookie_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!("ryuki_session={}", cookie_id)).unwrap(),
        );

        let (parsed, source) = session_id_from_headers(&headers, Some("Bearer jwt-token")).unwrap();
        assert_eq!(parsed.unwrap(), cookie_id);
        assert_eq!(source, SessionIdSource::Cookie);
    }

    #[test]
    fn test_no_session_sources_yields_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("theme=dark; other=1"),
        );
        assert!(session_id_from_headers(&headers, None).is_none());
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
    fn test_notifications_self_service_matcher_is_precise() {
        // Exactly the two self-service mutation paths get the relaxed read tier.
        assert!(is_notifications_self_service_path(
            "/api/notifications/read-all"
        ));
        assert!(is_notifications_self_service_path(
            "/api/notifications/pn-123/read"
        ));
        // Anything else under /api/notifications must NOT inherit the read tier.
        assert!(!is_notifications_self_service_path("/api/notifications"));
        assert!(!is_notifications_self_service_path(
            "/api/notifications/pn-123"
        ));
        assert!(!is_notifications_self_service_path(
            "/api/notifications//read"
        )); // empty id
        assert!(!is_notifications_self_service_path(
            "/api/notifications/a/b/read"
        )); // multi-segment
        assert!(!is_notifications_self_service_path(
            "/api/notifications/read"
        )); // missing id
        assert!(!is_notifications_self_service_path("/api/other/pn-1/read"));
    }

    #[test]
    fn test_auth_exempt_paths_are_limited_to_auth_flow() {
        assert!(is_auth_exempt_path("/api/auth/login"));
        assert!(is_auth_exempt_path("/api/auth/logout"));
        assert!(is_auth_exempt_path("/api/auth/local/login"));
        assert!(is_auth_exempt_path("/api/auth/local/logout"));
        assert!(!is_auth_exempt_path("/api/auth/local/me"));
        assert!(!is_auth_exempt_path("/api/requests"));
    }

    #[tokio::test]
    async fn test_local_auth_mode_yields_unauthenticated_session_without_login() {
        let validator = test_validator();
        let session = auth_session_for_request(AuthMode::Local, None, &validator).await;
        assert_eq!(session.provider_mode, "local-unauthenticated");
        assert!(session.roles.is_empty());
        assert!(!session.token_valid);
        assert!(!auth_session_allows_unsafe_method(&session));
    }

    fn local_auth_with_roles(roles: &str) -> ryuki_core::config::LocalAuthConfig {
        // placeholder credentials for tests only
        serde_json::from_value(serde_json::json!({
            "users": format!("alice:placeholder-pass-1:{roles}")
        }))
        .expect("test local auth config should parse")
    }

    #[test]
    fn test_find_unknown_local_auth_role_accepts_catalog_roles() {
        let local_auth = local_auth_with_roles("PlatformAdmin|VMwareOperator");
        assert_eq!(find_unknown_local_auth_role(&local_auth), None);
    }

    #[test]
    fn test_find_unknown_local_auth_role_names_role_and_entry_index() {
        let local_auth = local_auth_with_roles("PlatformAdmin|NotARole");
        assert_eq!(
            find_unknown_local_auth_role(&local_auth),
            Some((0, "NotARole".to_string()))
        );
    }

    #[test]
    fn test_bind_address_is_loopback() {
        assert!(bind_address_is_loopback("127.0.0.1:8081"));
        assert!(bind_address_is_loopback("[::1]:8081"));
        assert!(!bind_address_is_loopback("0.0.0.0:8080"));
        assert!(!bind_address_is_loopback("not-an-address"));
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

    fn verified_persisted_session() -> AuthSession {
        session_from_db_row(DbAuthSessionRow {
            user_id: "admin".into(),
            display_name: "admin".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_PLATFORM_ADMIN.into()],
        })
    }

    #[test]
    fn test_cookie_sourced_session_never_authorizes_unsafe_methods() {
        let session = verified_persisted_session();

        // unsafe method with a cookie-only session → denied (middleware 401)
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(!session_authorizes_request(
                &method,
                "/api/requests",
                &session,
                Some(SessionIdSource::Cookie),
            ));
        }

        // the same session via the portal header or a bearer uuid → allowed (200)
        assert!(session_authorizes_request(
            &Method::POST,
            "/api/requests",
            &session,
            Some(SessionIdSource::Header),
        ));
        assert!(session_authorizes_request(
            &Method::POST,
            "/api/requests",
            &session,
            Some(SessionIdSource::Bearer),
        ));
    }

    #[test]
    fn test_cookie_sourced_session_still_allows_safe_methods_and_exempt_paths() {
        let session = verified_persisted_session();

        // safe methods remain readable with a cookie session
        assert!(session_authorizes_request(
            &Method::GET,
            "/api/requests",
            &session,
            Some(SessionIdSource::Cookie),
        ));
        // auth endpoints keep their existing auth exemption (cookie logout)
        assert!(session_authorizes_request(
            &Method::POST,
            "/api/auth/local/logout",
            &session,
            Some(SessionIdSource::Cookie),
        ));
    }

    #[test]
    fn test_sessionless_unsafe_requests_keep_existing_auth_gate() {
        // no session id at all: the existing token_valid/static-dry-run gate
        // decides, unchanged.
        let unverified = unverified_session("local-unauthenticated");
        assert!(!session_authorizes_request(
            &Method::POST,
            "/api/requests",
            &unverified,
            None,
        ));
        let static_session = AuthSession::static_dry_run();
        assert!(session_authorizes_request(
            &Method::POST,
            "/api/requests",
            &static_session,
            None,
        ));
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
            trusted_proxies: Vec::new(),
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
            trusted_proxies: Vec::new(),
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

    fn peer(addr: &str) -> SocketAddr {
        addr.parse().expect("test peer address should parse")
    }

    fn trusted(networks: &[&str]) -> Vec<TrustedProxyNetwork> {
        networks
            .iter()
            .map(|n| TrustedProxyNetwork::parse(n).expect("test network should parse"))
            .collect()
    }

    #[test]
    fn test_forged_xff_from_untrusted_peer_keys_on_peer_address() {
        let trusted_proxies = trusted(&["10.0.0.0/8"]);
        let (key, source) = resolve_rate_limit_client_key(
            peer("198.51.100.7:50000"),
            Some("203.0.113.99, 203.0.113.100"),
            &trusted_proxies,
        );
        assert_eq!(key, "198.51.100.7");
        assert_eq!(source, ClientKeySource::Peer);

        // no trusted proxies configured at all: the header is always ignored
        let (key, source) =
            resolve_rate_limit_client_key(peer("198.51.100.7:50000"), Some("203.0.113.99"), &[]);
        assert_eq!(key, "198.51.100.7");
        assert_eq!(source, ClientKeySource::Peer);
    }

    #[test]
    fn test_trusted_proxy_xff_resolves_rightmost_non_trusted_hop() {
        let trusted_proxies = trusted(&["10.0.0.0/8", "127.0.0.1"]);

        // forged client-supplied entry on the left, real client in the
        // middle, our own proxy hop on the right: the real client wins
        let (key, source) = resolve_rate_limit_client_key(
            peer("10.0.0.5:443"),
            Some("203.0.113.99, 198.51.100.20, 10.0.0.6"),
            &trusted_proxies,
        );
        assert_eq!(key, "198.51.100.20");
        assert_eq!(source, ClientKeySource::Forwarded);

        // chain made entirely of trusted proxies: fall back to the peer
        let (key, source) = resolve_rate_limit_client_key(
            peer("10.0.0.5:443"),
            Some("10.0.0.6, 127.0.0.1"),
            &trusted_proxies,
        );
        assert_eq!(key, "10.0.0.5");
        assert_eq!(source, ClientKeySource::Peer);

        // trusted peer without the header: peer address is the key
        let (key, source) =
            resolve_rate_limit_client_key(peer("10.0.0.5:443"), None, &trusted_proxies);
        assert_eq!(key, "10.0.0.5");
        assert_eq!(source, ClientKeySource::Peer);
    }

    #[test]
    fn test_forwarded_entries_with_ports_resolve_to_their_ip() {
        let trusted_proxies = trusted(&["127.0.0.1"]);
        let (key, source) = resolve_rate_limit_client_key(
            peer("127.0.0.1:9000"),
            Some("198.51.100.20:38422"),
            &trusted_proxies,
        );
        assert_eq!(key, "198.51.100.20");
        assert_eq!(source, ClientKeySource::Forwarded);

        let (key, _) = resolve_rate_limit_client_key(
            peer("127.0.0.1:9000"),
            Some("[2001:db8::1]:38422"),
            &trusted_proxies,
        );
        assert_eq!(key, "2001:db8::1");
    }

    #[test]
    fn test_two_distinct_direct_clients_get_distinct_buckets() {
        let config = ryuki_core::config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst_size: 1,
            path_overrides: HashMap::new(),
            trusted_proxies: Vec::new(),
        };
        let limiters = create_rate_limiter(&config).expect("rate limiter should be enabled");

        let (key_a, _) = resolve_rate_limit_client_key(peer("198.51.100.1:50000"), None, &[]);
        let (key_b, _) = resolve_rate_limit_client_key(peer("198.51.100.2:50000"), None, &[]);
        assert_ne!(key_a, key_b);

        let limiter = limiters.for_path_group("api");
        // client A exhausts its own bucket without touching client B's
        assert!(limiter.check_key(&format!("api:{key_a}")).is_ok());
        assert!(limiter.check_key(&format!("api:{key_a}")).is_err());
        assert!(limiter.check_key(&format!("api:{key_b}")).is_ok());
    }

    #[test]
    fn test_create_rate_limiter_parses_trusted_proxies_and_skips_malformed() {
        let config = ryuki_core::config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst_size: 1,
            path_overrides: HashMap::new(),
            trusted_proxies: vec!["10.0.0.0/8".into(), "not-an-ip".into()],
        };
        let limiters = create_rate_limiter(&config).expect("rate limiter should be enabled");
        assert_eq!(limiters.trusted_proxies.len(), 1);
        assert!(limiters.trusted_proxies[0].contains("10.1.2.3".parse().unwrap()));
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

    /// Hardcoded list of mutating-route prefixes the API exposes (excluding the
    /// auth-exempt /api/auth/* endpoints, which the gate never reaches). Kept in
    /// sync by hand with `contracts::routes()`; the coverage test below asserts
    /// every one resolves to a non-empty permission.
    const MUTATING_ROUTES: &[&str] = &[
        "/api/requests",
        "/api/requests/00000000-0000-0000-0000-000000000000/validate",
        "/api/requests/00000000-0000-0000-0000-000000000000/plan",
        "/api/requests/00000000-0000-0000-0000-000000000000/approve",
        "/api/requests/00000000-0000-0000-0000-000000000000/lock",
        "/api/requests/00000000-0000-0000-0000-000000000000/execute",
        "/api/requests/00000000-0000-0000-0000-000000000000/verify",
        "/api/requests/00000000-0000-0000-0000-000000000000/protect",
        "/api/requests/00000000-0000-0000-0000-000000000000/publish",
        "/api/requests/00000000-0000-0000-0000-000000000000/retire",
        "/api/requests/00000000-0000-0000-0000-000000000000/reject",
        "/api/requests/00000000-0000-0000-0000-000000000000/cancel",
        "/api/identity/access-review/r1/start",
        "/api/identity/access-review/r1/approve",
        "/api/identity/access-review/r1/revoke",
        "/api/identity/access-review/r1/exempt",
        "/api/identity/access-review/campaign",
        "/api/identity/ad/prestage",
        "/api/identity/ad/validate",
        "/api/identity/ad/move/host1",
        "/api/identity/ad/disable/host1",
        "/api/identity/ad/enable/host1",
        "/api/identity/ad/delete/host1",
        "/api/identity/gmsa/create",
        "/api/identity/gmsa/validate",
        "/api/identity/gmsa/assign/svc1/host1",
        "/api/identity/gmsa/remove/svc1/host1",
        "/api/identity/gmsa/rotate/svc1",
        "/api/identity/gmsa/test/svc1/host1",
        "/api/identity/shares/recertify/s1",
        "/api/identity/shares/revoke/s1/g1",
        "/api/audit/compliance/controls/c1/assess",
        "/api/audit/compliance/reports/generate",
        "/api/audit/compliance/findings/f1/resolve",
        "/api/audit/compliance/findings/f1/waive",
        "/api/evidence/collect",
        "/api/evidence/redact",
        "/api/evidence/verify-compliance",
        "/api/inventory/sync",
        "/api/inventory/reconcile",
        "/api/build/sql/plan",
        "/api/build/sql/validate",
        "/api/build/sql/install/d1",
        "/api/build/sql/configure/d1",
        "/api/build/sql/verify/d1",
        "/api/build/sql/backup/d1",
        "/api/build/sql/monitoring/d1",
        "/api/ops/runbook/start",
        "/api/ops/runbook/step/e1/s1",
        "/api/ops/runbook/approve/e1",
        "/api/ops/runbook/complete/e1",
        "/api/ops/runbook/fail/e1",
        "/api/ops/runbook/rollback/e1",
        "/api/ops/shift/acknowledge/i1",
        "/api/ops/shift/assign/i1",
        "/api/ops/shift/escalate/i1",
        "/api/ops/shift/resolve/i1",
        "/api/ops/emergency/initiate",
        "/api/ops/emergency/approve/e1",
        "/api/ops/emergency/execute/e1",
        "/api/ops/emergency/verify/e1",
        "/api/ops/emergency/close/e1",
        "/api/ops/incident/assemble",
        "/api/ops/incident/i1/resolve",
        "/api/ops/incident/i1/add-ci",
        "/api/ops/incident/i1/escalate",
        "/api/operations/outage-comms/notices",
        "/api/operations/outage-comms/notices/n1/send",
        "/api/operations/outage-comms/notices/n1/acknowledge",
        "/api/operations/outage-comms/notices/n1/complete",
        "/api/operations/outage-comms/notices/n1/cancel",
        "/api/platform/degradation/check/SITE",
        "/api/platform/degradation/enter/SITE",
        "/api/platform/degradation/exit/SITE",
        "/api/maintain/patch/plan",
        "/api/maintain/patch/validate",
        "/api/maintain/patch/approve",
        "/api/maintain/patch/execute",
        "/api/maintain/patch/verify",
        "/api/maintain/patch/reboot",
        "/api/maintain/software/validate",
        "/api/maintain/software/plan",
        "/api/maintain/software/approve/s1",
        "/api/maintain/software/execute/s1",
        "/api/maintain/software/verify/s1",
        "/api/maintain/baseline/check/srv1",
        "/api/maintain/baseline/remediate/srv1/chk1",
        "/api/protect/repository-capacity/update/r1",
        "/api/protect/secrets",
        "/api/protect/secrets/s1/rotate",
        "/api/protect/secrets/rotate-all",
        "/api/protect/secrets/fail",
        "/api/protect/immutability/check/i1",
        "/api/protect/immutability/retention-lock/i1",
        "/api/protect/immutability/air-gap/i1",
        "/api/protect/immutability/verify-all",
        "/api/protect/legal-hold/place",
        "/api/protect/legal-hold/validate/l1",
        "/api/protect/legal-hold/extend/l1",
        "/api/protect/legal-hold/release/l1",
        "/api/observe/synthetic/run/c1",
        "/api/observe/synthetic/run-all",
        "/api/observe/logs/onboard",
        "/api/observe/logs/validate/host1",
        "/api/observe/logs/verify/host1",
        "/api/observe/logs/disable/host1",
        "/api/cmdb/import",
        "/api/cmdb/reconcile",
        "/api/cmdb/impact/analyze",
        "/api/cmdb/servicenow/incident",
        "/api/cmdb/servicenow/change",
        "/api/cmdb/servicenow/request",
        "/api/cmdb/servicenow/validate/x1",
        "/api/cmdb/servicenow/approve/x1",
        "/api/cmdb/servicenow/submit/x1",
        "/api/cmdb/servicenow/cancel/x1",
        "/api/admin/sites/USNYC/activate",
        "/api/admin/sites/USNYC/deactivate",
        "/api/admin/platform-settings",
        "/api/admin/platform-settings/reset",
        "/api/analytics/aiops/generate",
        "/api/analytics/aiops/review/a1",
        "/api/analytics/aiops/accept/a1",
        "/api/analytics/aiops/reject/a1",
        "/api/analytics/aiops/implement/a1",
        "/api/monitoring/alert-routes",
        "/api/monitoring/alert-routes/a1",
        "/api/monitoring/alerts/resolve",
        "/api/monitoring/zabbix/drift/detect",
        "/api/monitoring/zabbix/drift/plan/d1",
        "/api/monitoring/zabbix/drift/execute/d1",
        "/api/monitoring/zabbix/drift/verify/d1",
        "/api/monitoring/noise/detect",
        "/api/monitoring/noise/flapping",
        "/api/monitoring/noise/suggest/n1",
        "/api/monitoring/noise/suppress/n1",
        "/api/monitoring/noise/resolve/n1",
        "/api/maintain/certificates/request",
        "/api/maintain/certificates/validate",
        "/api/maintain/certificates/approve/c1",
        "/api/maintain/certificates/install/c1",
        "/api/maintain/certificates/verify/c1",
        "/api/maintain/certificates/renew/c1",
        "/api/maintain/certificates/revoke/c1",
        "/api/vm/day2/plan",
        "/api/vm/day2/validate",
        "/api/vm/day2/execute",
        "/api/vm/day2/verify",
        "/api/protect/dr/plans",
        "/api/protect/dr/plans/p1/rpo-rto",
        "/api/protect/dr/tests/start",
        "/api/protect/dr/tests/complete",
        "/api/protect/snapshot/plan",
        "/api/protect/snapshot/validate",
        "/api/protect/snapshot/review",
        "/api/protect/snapshot/flag-stale",
        "/api/protect/snapshot/remediate",
        "/api/protect/backup/coverage-report",
        "/api/protect/backup/restore-plan",
        "/api/protect/backup/restore-validate",
        "/api/protect/backup/restore-approve",
        "/api/protect/backup/restore-execute",
        "/api/build/k8s/namespaces",
        "/api/build/k8s/namespaces/n1/quota",
        "/api/build/k8s/namespaces/n1/suspend",
        "/api/build/k8s/namespaces/n1/resume",
        "/api/build/k8s/namespaces/n1/terminate",
        "/api/build/k8s/validate-name",
        "/api/build/linux/plan",
        "/api/build/linux/validate",
        "/api/build/linux/execute",
        "/api/build/linux/verify",
        "/api/build/app-environment/plan",
        "/api/build/app-environment/validate",
        "/api/build/app-environment/approve/a1",
        "/api/build/app-environment/deploy/a1",
        "/api/build/app-environment/verify/a1",
        "/api/build/app-environment/retire/a1",
        "/api/retire/decommission/plan",
        "/api/retire/decommission/validate",
        "/api/retire/decommission/approve/d1",
        "/api/retire/decommission/quarantine/d1",
        "/api/retire/decommission/execute/d1",
        "/api/retire/decommission/verify/d1",
        "/api/retire/decommission/rollback/d1",
        "/api/maintain/calendar/schedule",
        "/api/maintain/calendar/cancel/c1",
        "/api/network/dns/records",
        "/api/network/dns/records/r1",
        "/api/network/ipam/reserve",
        "/api/network/ipam/release/r1",
        "/api/network/firewall/rules",
        "/api/network/firewall/rules/r1",
        "/api/network/firewall/rules/r1/update",
        "/api/network/firewall/validate",
        "/api/network/firewall/rule-sets",
        "/api/network/firewall/rule-sets/r1/apply",
        "/api/network/firewall/rule-sets/r1/revoke",
        "/api/network/loadbalancer/vs",
        "/api/network/loadbalancer/vs/v1/member",
        "/api/network/loadbalancer/vs/v1/member/host1",
        "/api/network/loadbalancer/vs/v1/drain",
        "/api/network/loadbalancer/vs/v1/disable",
        "/api/network/loadbalancer/vs/v1/enable",
        "/api/network/loadbalancer/validate-vip",
        "/api/datacenter/network/reserve-ports",
        "/api/datacenter/network/reserve-ips",
        "/api/datacenter/network/release/r1",
        "/api/datacenter/oob/test/o1",
        "/api/datacenter/oob/validate-cert/o1",
        "/api/datacenter/oob/check-defaults/o1",
        "/api/datacenter/oob/validate-site/SITE",
        "/api/datacenter/storage/volumes",
        "/api/datacenter/storage/volumes/v1/extend",
        "/api/datacenter/storage/volumes/v1/map",
        "/api/datacenter/storage/volumes/v1/unmap",
        "/api/datacenter/storage/volumes/v1/retire",
        "/api/datacenter/storage/check-capacity",
        "/api/datacenter/hardware/firmware-check/h1",
        "/api/datacenter/hardware/add",
        "/api/datacenter/hardware/update-firmware/h1",
        "/api/datacenter/firmware/check/f1",
        "/api/datacenter/firmware/exception",
        "/api/datacenter/firmware/revoke/f1",
        "/api/datacenter/image-factory/initiate-build",
        "/api/datacenter/image-factory/run-tests/i1",
        "/api/datacenter/image-factory/promote/i1",
        "/api/datacenter/image-factory/reject/i1",
        "/api/datacenter/image-factory/schedule-monthly",
    ];

    #[test]
    fn test_every_mutating_route_resolves_to_a_permission() {
        for path in MUTATING_ROUTES {
            let permission = route_permission_for(&Method::POST, path);
            assert!(
                !permission.is_empty(),
                "route {path} resolved to an empty permission"
            );
            // Every resolved permission must be one the model recognizes.
            assert!(
                ["request", "execute", "approve", "admin"].contains(&permission),
                "route {path} resolved to unexpected permission {permission}"
            );
        }
    }

    #[test]
    fn test_unknown_mutating_route_fails_closed_to_admin() {
        assert_eq!(
            route_permission_for(&Method::POST, "/api/totally-new/thing"),
            "admin"
        );
        // A brand-new top-level family also fails closed.
        assert_eq!(
            route_permission_for(&Method::DELETE, "/api/something/else/entirely"),
            "admin"
        );
    }

    #[test]
    fn test_high_risk_routes_resolve_to_expected_permissions() {
        // emergency / break-glass is admin-only
        assert_eq!(
            route_permission_for(&Method::POST, "/api/ops/emergency/initiate"),
            "admin"
        );
        assert_eq!(
            route_permission_for(&Method::POST, "/api/ops/emergency/approve/e1"),
            "admin"
        );
        // rotate-all secrets is admin-only, more specific than /api/protect
        assert_eq!(
            route_permission_for(&Method::POST, "/api/protect/secrets/rotate-all"),
            "admin"
        );
        // but a regular protect mutation is operator-tier
        assert_eq!(
            route_permission_for(&Method::POST, "/api/protect/secrets/s1/rotate"),
            "execute"
        );
        // AD delete is operator-tier (execute), not admin
        assert_eq!(
            route_permission_for(&Method::POST, "/api/identity/ad/delete/host1"),
            "execute"
        );
        // request lifecycle split
        assert_eq!(
            route_permission_for(&Method::POST, "/api/requests"),
            "request"
        );
        assert_eq!(
            route_permission_for(
                &Method::POST,
                "/api/requests/00000000-0000-0000-0000-000000000000/approve"
            ),
            "approve"
        );
        assert_eq!(
            route_permission_for(
                &Method::POST,
                "/api/requests/00000000-0000-0000-0000-000000000000/execute"
            ),
            "execute"
        );
        // reject routes to the approver gate; cancel to the requester floor
        // (the handler enforces requester-owns-it-or-admin SoD against the row)
        assert_eq!(
            route_permission_for(
                &Method::POST,
                "/api/requests/00000000-0000-0000-0000-000000000000/reject"
            ),
            "approve"
        );
        assert_eq!(
            route_permission_for(
                &Method::POST,
                "/api/requests/00000000-0000-0000-0000-000000000000/cancel"
            ),
            "request"
        );
        // /api/admin family is admin-only
        assert_eq!(
            route_permission_for(&Method::PUT, "/api/admin/platform-settings"),
            "admin"
        );
        // a non-emergency ops route is operator-tier (after the emergency carve-out)
        assert_eq!(
            route_permission_for(&Method::POST, "/api/ops/runbook/start"),
            "execute"
        );
    }

    #[test]
    fn test_operational_approval_signoffs_require_approver_tier() {
        // Genuine maker/checker sign-offs that transition an entity to an Approved
        // state: each must require the approver tier, not the execute tier of its
        // family root — otherwise an Operator self-approves their own work.
        for path in [
            "/api/ops/runbook/approve/r1",
            "/api/maintain/patch/approve",
            "/api/maintain/software/approve/s1",
            "/api/protect/backup/restore-approve",
            "/api/build/app-environment/approve/e1",
            "/api/retire/decommission/approve/d1",
            // access-review carries all three reviewer verdicts (id is mid-path)
            "/api/identity/access-review/ar1/approve",
            "/api/identity/access-review/ar1/revoke",
            "/api/identity/access-review/ar1/exempt",
        ] {
            assert_eq!(
                route_permission_for(&Method::POST, path),
                "approve",
                "{path} is a maker/checker approval sign-off and must require the approver tier"
            );
        }

        // Routes that carry the 'approve' NAME but gate nothing (read-only
        // acknowledgements, no Approved state) stay operator-tier.
        assert_eq!(
            route_permission_for(&Method::POST, "/api/cmdb/servicenow/approve/sn1"),
            "execute"
        );
        assert_eq!(
            route_permission_for(&Method::POST, "/api/maintain/certificates/approve/c1"),
            "execute"
        );

        // Sibling operator actions in the same families are NOT bumped — only the
        // approval verdict is.
        assert_eq!(
            route_permission_for(&Method::POST, "/api/maintain/patch/execute"),
            "execute"
        );
        assert_eq!(
            route_permission_for(&Method::POST, "/api/maintain/patch/validate"),
            "execute"
        );

        // Shape guard: a deeper path past the access-review verdict is not a
        // verdict route and falls through to the family tier.
        assert_eq!(
            route_permission_for(
                &Method::POST,
                "/api/identity/access-review/ar1/approve/extra"
            ),
            "execute"
        );
    }

    #[test]
    fn test_requests_route_permission_splits_correctly() {
        assert_eq!(requests_route_permission("/api/requests"), Some("request"));
        assert_eq!(
            requests_route_permission("/api/requests/abc/validate"),
            Some("execute")
        );
        assert_eq!(
            requests_route_permission("/api/requests/abc/plan"),
            Some("execute")
        );
        assert_eq!(
            requests_route_permission("/api/requests/abc/lock"),
            Some("execute")
        );
        assert_eq!(
            requests_route_permission("/api/requests/abc/execute"),
            Some("execute")
        );
        assert_eq!(
            requests_route_permission("/api/requests/abc/verify"),
            Some("execute")
        );
        assert_eq!(
            requests_route_permission("/api/requests/abc/approve"),
            Some("approve")
        );
        // reject is an approver act — same gate as approve
        assert_eq!(
            requests_route_permission("/api/requests/abc/reject"),
            Some("approve")
        );
        // cancel is a requester-tier floor (handler enforces requester-owns-it
        // -or-admin SoD against the row)
        assert_eq!(
            requests_route_permission("/api/requests/abc/cancel"),
            Some("request")
        );
        // GET /api/requests/{id} would also resolve here, but the gate only runs
        // for unsafe methods; a request-family mutation never falls back to the
        // requester tier — it fails toward operator.
        assert_eq!(
            requests_route_permission("/api/requests/abc"),
            Some("execute")
        );
        // not a requests path -> None so the static table is consulted
        assert_eq!(requests_route_permission("/api/identity/ad/prestage"), None);
    }

    /// Pins the static-dry-run / mock demo: with the superuser model, the
    /// static_dry_run session (roles=[PlatformAdmin], holds `admin`) must
    /// satisfy every distinct permission in the route table plus the fail-closed
    /// default. Guards against a future change to the superuser model silently
    /// breaking the GitHub Pages / static demo.
    #[test]
    fn test_static_dry_run_session_passes_every_route_permission() {
        let session = AuthSession::static_dry_run();
        for perm in ["request", "execute", "approve", "admin"] {
            assert!(
                ryuki_engine::auth::check_permission(&session, perm),
                "static-dry-run must satisfy permission {perm}"
            );
        }
        // fail-closed default is "admin"; static-dry-run satisfies it too.
        assert!(ryuki_engine::auth::check_permission(
            &session,
            DEFAULT_ROUTE_PERMISSION
        ));
        // And it satisfies every concrete mutating route resolution.
        for path in MUTATING_ROUTES {
            let required = route_permission_for(&Method::POST, path);
            assert!(
                ryuki_engine::auth::check_permission(&session, required),
                "static-dry-run must pass route {path} (requires {required})"
            );
        }
    }

    // ---- B3: read authentication ----

    /// A logged-in Auditor: holds exactly `audit`, fails `admin`. The read tier
    /// (ordinary reads need `audit`, sensitive reads need `admin`) is built so
    /// an Auditor reads ordinary GETs but is refused sensitive ones.
    fn auditor_session() -> AuthSession {
        AuthSession {
            user_id: "auditor-1".into(),
            display_name: "Auditor One".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_AUDITOR.to_string()],
            token_valid: true,
            provider_mode: "persisted-session".into(),
        }
    }

    /// Hardcoded representative list of non-exempt GET routes the API exposes,
    /// kept in sync by hand with `contracts::routes()` (mirrors the
    /// MUTATING_ROUTES pattern). Covers all three sensitive read prefixes plus a
    /// spread of ordinary reads. The walk test below pins the read tier and the
    /// gate invariants against every entry.
    const GET_ROUTES: &[&str] = &[
        // ordinary reads (audit tier).
        // NOTE: /api/platform/summary is intentionally NOT here — it is
        // auth-exempt (the pre-login portal bootstrap read), asserted
        // separately in test_platform_summary_is_pre_login_exempt.
        "/api/requests",
        "/api/requests/00000000-0000-0000-0000-000000000000",
        "/api/requests/00000000-0000-0000-0000-000000000000/audit",
        "/api/requests/00000000-0000-0000-0000-000000000000/evidence",
        "/api/activity/audit",
        "/api/catalog/categories",
        "/api/identity/shares",
        "/api/audit/compliance/summary",
        "/api/ops/runbook/catalog",
        "/api/ops/incident/active",
        "/api/observe/logs/coverage",
        "/api/cmdb/export",
        "/api/analytics/capacity",
        "/api/network/dns/records",
        "/api/datacenter/storage/arrays",
        "/api/maintain/patch/compliance",
        // sensitive reads (admin tier)
        "/api/protect/secrets",
        "/api/protect/secrets/s1",
        "/api/protect/secrets/due",
        "/api/ops/emergency/active",
        "/api/ops/emergency/history",
        "/api/ops/emergency/stats",
        "/api/admin/tokens",
        "/api/admin/sessions",
        "/api/admin/platform-settings",
        "/api/admin/rbac-roles",
    ];

    /// `read_permission_for` returns `admin` for each sensitive prefix and
    /// `audit` for a representative ordinary path.
    #[test]
    fn test_read_permission_tier() {
        // ordinary read
        assert_eq!(read_permission_for("/api/requests"), "audit");
        // each sensitive prefix root + a sub-path under it
        assert_eq!(read_permission_for("/api/protect/secrets"), "admin");
        assert_eq!(read_permission_for("/api/protect/secrets/s1"), "admin");
        assert_eq!(read_permission_for("/api/ops/emergency"), "admin");
        assert_eq!(read_permission_for("/api/ops/emergency/history"), "admin");
        assert_eq!(read_permission_for("/api/admin"), "admin");
        assert_eq!(read_permission_for("/api/admin/tokens"), "admin");
        // a near-miss that is NOT a sensitive prefix stays audit
        assert_eq!(
            read_permission_for("/api/protect/repository-capacity"),
            "audit"
        );
        assert_eq!(read_permission_for("/api/ops/runbook/catalog"), "audit");
    }

    /// B3/B6 reconciliation: the login view fetches `/api/platform/summary`
    /// BEFORE any session exists, to choose its sign-in copy. It must therefore
    /// be auth-exempt (readable anonymously) so an anonymous fetch does not 401
    /// and force the login page into the "Platform API unreachable" degraded
    /// arm instead of the correct local-mode note. The other pre-login portal
    /// reads stay exempt; an ordinary gated read (e.g. /api/requests) and every
    /// sensitive read stay NON-exempt.
    #[test]
    fn test_platform_summary_is_pre_login_exempt() {
        assert!(
            is_auth_exempt_path("/api/platform/summary"),
            "/api/platform/summary must be readable pre-login so the local-mode \
             login copy renders instead of the degraded API-unreachable arm"
        );
        // The other pre-login bootstrap reads remain exempt.
        assert!(is_auth_exempt_path("/api/auth/status"));
        assert!(is_auth_exempt_path("/api/auth/session"));
        assert!(is_auth_exempt_path("/api/auth/roles"));
        // Ordinary and sensitive reads stay gated (NOT exempt).
        assert!(!is_auth_exempt_path("/api/requests"));
        assert!(!is_auth_exempt_path("/api/protect/secrets"));
        assert!(!is_auth_exempt_path("/api/ops/emergency/history"));
        assert!(!is_auth_exempt_path("/api/admin/tokens"));
    }

    /// The exact read-auth admission predicate used in `auth_middleware`: a
    /// non-exempt read is admitted only when the session is verified
    /// (token_valid) OR static-dry-run. Returns true == admitted (no 401).
    fn read_admitted(session: &AuthSession) -> bool {
        session.token_valid || session.provider_mode == "static-dry-run"
    }

    /// Router-walk: every non-exempt GET must resolve to a non-empty read
    /// permission; an anonymous Local session (zero roles, NOT static) is
    /// refused at the read-auth gate (would 401); static-dry-run passes every
    /// GET (demo invariant); a logged-in Auditor passes every NON-sensitive GET
    /// and is refused every sensitive one.
    #[test]
    fn test_get_routes_read_auth_walk() {
        let anon = unverified_session("local-unauthenticated");
        let static_session = AuthSession::static_dry_run();
        let auditor = auditor_session();

        for path in GET_ROUTES {
            assert!(
                !is_auth_exempt_path(path),
                "GET_ROUTES must not contain an exempt path: {path}"
            );
            let required = read_permission_for(path);
            assert!(
                !required.is_empty(),
                "read permission for {path} must be non-empty"
            );
            assert!(
                ["audit", "admin"].contains(&required),
                "read permission for {path} must be a read tier, got {required}"
            );

            // Anonymous Local read is refused at the 401 read-auth gate.
            assert!(
                !read_admitted(&anon),
                "anonymous local session must be refused read of {path}"
            );

            // static-dry-run is admitted AND passes the RBAC check for every GET
            // (demo invariant: PlatformAdmin superuser).
            assert!(read_admitted(&static_session));
            assert!(
                ryuki_engine::auth::check_permission(&static_session, required),
                "static-dry-run must pass GET {path} (requires {required})"
            );

            // A logged-in Auditor is admitted (token_valid) and passes ordinary
            // AND audit-trail reads (holds `audit`) but is refused sensitive
            // ones — asserted via the same read_authorized helper the gate uses.
            assert!(read_admitted(&auditor));
            if required == "admin" {
                assert!(
                    !read_authorized(&auditor, path),
                    "auditor must be refused sensitive GET {path}"
                );
            } else {
                assert!(
                    read_authorized(&auditor, path),
                    "auditor must pass ordinary/audit GET {path}"
                );
            }

            // A Requester (holds only `request`) reads ordinary GETs (e.g. view
            // their own requests) but never sensitive ones — and never the
            // identity-grade audit trails, which require the `audit` tier.
            let requester = AuthSession {
                user_id: "req-1".into(),
                display_name: "Requester One".into(),
                roles: vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()],
                token_valid: true,
                provider_mode: "persisted-session".into(),
            };
            if required == "admin" || is_audit_read_path(path) {
                assert!(
                    !read_authorized(&requester, path),
                    "requester must be refused sensitive/audit GET {path}"
                );
            } else {
                assert!(
                    read_authorized(&requester, path),
                    "requester must pass ordinary GET {path}"
                );
            }
        }
    }

    /// The audit trails (global activity feed + per-request `/audit`) require the
    /// `audit` tier at the CENTRAL gate, matching the handler's own check — a
    /// `request`-only Requester is refused at the gate, not merely the handler.
    /// The plain request detail (no `/audit` suffix) stays `request`-readable.
    #[test]
    fn test_audit_read_paths_require_audit_tier() {
        assert!(is_audit_read_path("/api/activity/audit"));
        assert!(is_audit_read_path(
            "/api/requests/00000000-0000-0000-0000-000000000000/audit"
        ));
        assert!(is_audit_read_path(
            "/api/requests/00000000-0000-0000-0000-000000000000/evidence"
        ));
        assert!(!is_audit_read_path(
            "/api/requests/00000000-0000-0000-0000-000000000000"
        ));
        assert!(!is_audit_read_path("/api/requests"));
        assert!(!is_audit_read_path("/api/activity"));

        let auditor = auditor_session();
        let requester = AuthSession {
            user_id: "req-1".into(),
            display_name: "Requester One".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()],
            token_valid: true,
            provider_mode: "persisted-session".into(),
        };
        for path in [
            "/api/activity/audit",
            "/api/requests/00000000-0000-0000-0000-000000000000/audit",
            "/api/requests/00000000-0000-0000-0000-000000000000/evidence",
        ] {
            assert!(read_authorized(&auditor, path), "auditor reads {path}");
            assert!(
                !read_authorized(&requester, path),
                "requester (no audit tier) refused {path} at the central gate"
            );
        }
        // Plain detail stays request-readable so requesters see their own work.
        assert!(read_authorized(
            &requester,
            "/api/requests/00000000-0000-0000-0000-000000000000"
        ));
    }

    /// B3 (a): a credential-less GET to each sensitive path is refused — 401 at
    /// the read-auth gate (anonymous, non-static), and 403 for a logged-in
    /// Auditor (admitted but lacks `admin`). Modeled at the predicate level
    /// (the gate is private middleware): anonymous -> not admitted (401);
    /// Auditor -> admitted but `check_permission(admin)` false (403).
    #[test]
    fn test_sensitive_get_without_credentials_401_or_403() {
        let anon = unverified_session("local-unauthenticated");
        let auditor = auditor_session();
        for path in [
            "/api/protect/secrets",
            "/api/ops/emergency/history",
            "/api/admin/tokens",
        ] {
            let required = read_permission_for(path);
            assert_eq!(required, "admin", "{path} must be a sensitive read");
            // anonymous, non-static -> 401 (not admitted)
            assert!(!read_admitted(&anon), "{path} anon must 401");
            // auditor -> admitted (no 401) but 403 (lacks admin)
            assert!(read_admitted(&auditor), "{path} auditor admitted");
            assert!(
                !ryuki_engine::auth::check_permission(&auditor, required),
                "{path} auditor must 403"
            );
        }
    }

    /// B7 drift: the central gate's resolved permission for each lifecycle path
    /// must match the permission the handler's own `check_permission` arg uses,
    /// so the gate and handler can never silently diverge.
    #[test]
    fn test_route_permission_matches_handler_guard() {
        let id = "00000000-0000-0000-0000-000000000000";
        let cases: &[(String, &str)] = &[
            (format!("/api/requests/{id}/validate"), "execute"),
            (format!("/api/requests/{id}/plan"), "execute"),
            (format!("/api/requests/{id}/lock"), "execute"),
            (format!("/api/requests/{id}/execute"), "execute"),
            (format!("/api/requests/{id}/verify"), "execute"),
            (format!("/api/requests/{id}/approve"), "approve"),
            (format!("/api/requests/{id}/reject"), "approve"),
            (format!("/api/requests/{id}/cancel"), "request"),
            ("/api/requests".to_string(), "request"),
        ];
        for (path, expected) in cases {
            assert_eq!(
                route_permission_for(&Method::POST, path),
                *expected,
                "gate permission for {path} must match handler guard {expected}"
            );
        }
    }
}

#[cfg(test)]
mod db_tests {
    #[tokio::test]
    async fn test_migrations_run_against_pg18() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        // Skip when unset OR empty: `make test-unit` runs with
        // `RYUKI_DATABASE_URL=` (empty string, not unset), so an `.is_err()`
        // check alone would not skip and the empty-URL connect would panic.
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("SKIP: RYUKI_DATABASE_URL not set");
                return;
            }
        };
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
