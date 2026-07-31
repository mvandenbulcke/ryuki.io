#![recursion_limit = "512"]

mod agents;
mod audit;
mod authenticator_runtime;
mod background;
mod boundary;
mod build_identity;
mod config;
mod config_store;
mod contracts;
mod cookie_runtime;
pub mod cp_identity;
pub mod database;
mod entra_auth;
mod entra_sso;
mod first_owner_runtime;
mod human_authority;
mod idempotency;
mod identity_authority;
mod inbound_webhooks;
mod integration;
mod oidc_callback;
mod openapi;
mod postgresql_tls_channel;
mod principal_registry;
mod repos;
mod request_authority;
mod scheduler;
mod secret_provider_runtime;
mod security_contracts;
mod session_credentials;
mod session_lookup_admission;
#[cfg(test)]
mod test_crypto;

use axum::body::Body;
use axum::extract::{ConnectInfo, MatchedPath};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request as HttpRequest, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::{
    extract::{Query, State},
    routing::get,
    Extension, Json, Router,
};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::time::Instant;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::Instrument;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::database::MigrationStatus;
use crate::entra_auth::EntraTokenValidator;
use ryuki_core::config::{AuthMode, RyukiConfig, TrustedProxyNetwork};
use ryuki_core::types::{ApiError, ValidationResult};
use ryuki_core::PrincipalId;
use ryuki_engine::auth::{AuthSession, OperationCapability};

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
    validator: Option<&Arc<EntraTokenValidator>>,
) -> (
    AuthSession,
    Option<&'static str>,
    Option<crate::request_authority::DirectFederatedCredential>,
    Option<crate::entra_auth::VerifiedEntraBearerIdentity>,
) {
    match auth_mode {
        AuthMode::MockDryRun | AuthMode::StaticDryRun => {
            (AuthSession::static_dry_run(), None, None, None)
        }
        // Local mode without a persisted session is unauthenticated: zero
        // roles, token_valid=false. Both unsafe methods AND non-exempt reads
        // 401 until login (B3) — the portal sends X-Ryuki-Session-Id after the
        // local login flow.
        AuthMode::Local => (
            unverified_session("local-unauthenticated"),
            None,
            None,
            None,
        ),
        // EntraId: a real bearer token is cryptographically validated by the
        // injected validator (RS256 + iss/aud/exp/nbf + JWKS). A missing header
        // or any failure path is unverified_entra().
        AuthMode::EntraId => match validator {
            Some(validator) => match auth_header {
                Some(h) => {
                    let outcome = validator.validate_with_reason(h).await;
                    (
                        outcome.session,
                        outcome.failure_reason,
                        outcome.request_read_credential,
                        outcome.verified_identity,
                    )
                }
                None => (
                    AuthSession::unverified_entra(),
                    Some("missing-bearer"),
                    None,
                    None,
                ),
            },
            None => (
                AuthSession::unverified_entra(),
                Some("unbound-verifier"),
                None,
                None,
            ),
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
    validator: &Arc<EntraTokenValidator>,
) -> AuthSession {
    resolve_request_session(auth_mode, auth_header, Some(validator))
        .await
        .0
}

#[derive(sqlx::FromRow)]
struct DbAuthSessionRow {
    session_record_id: Uuid,
    principal_id: Uuid,
    principal_lifecycle_version: i64,
    principal_authority_version: i64,
    principal_key_id: Uuid,
    principal_key_version: i64,
    principal_link_id: Uuid,
    principal_link_version: i64,
    display_name: String,
    roles: Vec<String>,
    bearer_verifier: Vec<u8>,
    expires_at: chrono::DateTime<chrono::Utc>,
    created_at: chrono::DateTime<chrono::Utc>,
    provider_id: String,
    issuer: String,
    subject: String,
    site_authority_mode: String,
    site_scope: Vec<String>,
    environment_authority_mode: String,
    environment_scope: Vec<String>,
    authenticator_origin_binding_digest: Option<Vec<u8>>,
    registered_origin_binding_digest: Option<Vec<u8>>,
    current_origin_binding_digest: Option<Vec<u8>>,
}

fn session_row_matches_origin(
    row: &DbAuthSessionRow,
    origin: &crate::session_lookup_admission::SessionLookupOriginAuthority,
) -> bool {
    use subtle::ConstantTimeEq;

    match origin.origin_binding_digest() {
        None if origin.is_local() => {
            row.authenticator_origin_binding_digest.is_none()
                && row.registered_origin_binding_digest.is_none()
                && row.current_origin_binding_digest.is_none()
        }
        Some(expected) => {
            let session_matches = row
                .authenticator_origin_binding_digest
                .as_deref()
                .is_some_and(|actual| {
                    actual.len() == expected.len() && bool::from(actual.ct_eq(expected.as_slice()))
                });
            let registered_matches =
                row.registered_origin_binding_digest
                    .as_deref()
                    .is_some_and(|actual| {
                        actual.len() == expected.len()
                            && bool::from(actual.ct_eq(expected.as_slice()))
                    });
            let current_matches =
                row.current_origin_binding_digest
                    .as_deref()
                    .is_some_and(|actual| {
                        actual.len() == expected.len()
                            && bool::from(actual.ct_eq(expected.as_slice()))
                    });
            session_matches && registered_matches && current_matches
        }
        None => false,
    }
}

fn authority_context_from_db_row(
    row: &DbAuthSessionRow,
) -> Option<crate::human_authority::InteractiveHumanAuthorityContext> {
    let principal_id = PrincipalId::from_uuid(row.principal_id).ok()?;
    Some(crate::human_authority::InteractiveHumanAuthorityContext {
        principal_binding: crate::principal_registry::PrincipalBinding {
            principal_id,
            principal_lifecycle_version: row.principal_lifecycle_version,
            principal_authority_version: row.principal_authority_version,
            principal_key_id: row.principal_key_id,
            principal_key_version: row.principal_key_version,
            principal_link_id: row.principal_link_id,
            principal_link_version: row.principal_link_version,
        },
        provider: row.provider_id.clone(),
        issuer: row.issuer.clone(),
        subject: row.subject.clone(),
        // These compatibility fields now expose the exact internal principal
        // generations; provider subjects are provenance only.
        identity_epoch: row.principal_lifecycle_version,
        assignment_version: row.principal_authority_version,
        roles: row.roles.clone(),
        site_mode: crate::human_authority::HumanAuthorityMode::parse(&row.site_authority_mode)
            .ok()?,
        site_scope: row.site_scope.clone(),
        environment_mode: crate::human_authority::HumanAuthorityMode::parse(
            &row.environment_authority_mode,
        )
        .ok()?,
        environment_scope: row.environment_scope.clone(),
    })
}

fn unverified_session(provider_mode: &str) -> AuthSession {
    AuthSession {
        display_user_id: "unauthenticated".into(),
        display_name: "Unauthenticated".into(),
        roles: Vec::new(),
        token_valid: false,
        provider_mode: provider_mode.into(),
        // Unscoped (unrestricted) — scoping applies only to scoped api-tokens.
        ..Default::default()
    }
}

fn session_from_db_row(row: &DbAuthSessionRow) -> Option<AuthSession> {
    let principal_id = PrincipalId::from_uuid(row.principal_id).ok()?;
    Some(AuthSession {
        display_user_id: principal_id.to_string(),
        principal_id: Some(principal_id),
        display_name: row.display_name.clone(),
        roles: row.roles.clone(),
        token_valid: true,
        actor_class: ryuki_engine::auth::ActorClass::VerifiedHuman,
        // Preserve the carrier classification used by the settings-write gate.
        // Provider provenance remains available on the database row and in the
        // authority-cache binding, but a browser/session bearer is never a
        // freshly verified interactive external credential.
        provider_mode: "persisted-session".into(),
        site_scope: row.site_scope.clone(),
        environment_scope: row.environment_scope.clone(),
    })
}

fn request_read_digest(domain: &[u8], values: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.finalize().into()
}

fn persisted_request_read_authority(
    row: &DbAuthSessionRow,
    config: &RyukiConfig,
    session_credentials: &crate::session_credentials::DerivedSessionCredentialRuntime,
    session: &AuthSession,
    authority: &crate::human_authority::InteractiveHumanAuthorityContext,
    origin: &crate::session_lookup_admission::SessionLookupOriginAuthority,
) -> Result<
    crate::request_authority::RequestReadAuthority,
    crate::request_authority::RequestAuthorityError,
> {
    use crate::request_authority::{
        InteractiveRequestReadPrincipal, PersistedSessionCredential, RequestAuthorityError,
        RequestReadCredentialDigests, RequestReadCredentialWindow,
    };
    use ryuki_engine::authorization::AssuranceLevel;

    let bearer_verifier: [u8; 32] = row
        .bearer_verifier
        .as_slice()
        .try_into()
        .map_err(|_| RequestAuthorityError::InvalidBinding("session bearer verifier length"))?;
    let principal_lifecycle_version = row.principal_lifecycle_version.to_be_bytes();
    let principal_authority_version = row.principal_authority_version.to_be_bytes();
    let principal_key_version = row.principal_key_version.to_be_bytes();
    let principal_link_version = row.principal_link_version.to_be_bytes();
    let identity_authority_digest = request_read_digest(
        b"ryuki-request-read-principal-binding-v2",
        &[
            row.principal_id.as_bytes(),
            &principal_lifecycle_version,
            &principal_authority_version,
            row.principal_key_id.as_bytes(),
            &principal_key_version,
            row.principal_link_id.as_bytes(),
            &principal_link_version,
            row.provider_id.as_bytes(),
            row.issuer.as_bytes(),
            row.subject.as_bytes(),
            origin
                .origin_binding_digest()
                .map(|digest| digest.as_slice())
                .unwrap_or(&[]),
        ],
    );
    // A persisted federated session is minted only after a fresh provider
    // assertion. Its creation time is therefore the conservative freshness
    // origin after migration 199; provider subject data remains provenance and
    // never becomes the principal identifier.
    let identity_last_asserted_at =
        (row.provider_id != crate::identity_authority::LOCAL_PROVIDER).then_some(row.created_at);
    let identity_fresh_until = if row.provider_id == crate::identity_authority::LOCAL_PROVIDER {
        None
    } else {
        let last_asserted_at = identity_last_asserted_at.ok_or(
            RequestAuthorityError::InvalidBinding("federated assertion time is missing"),
        )?;
        let staleness =
            i64::try_from(session_credentials.federated_authority_max_staleness_seconds())
                .map_err(|_| RequestAuthorityError::InvalidBinding("federated freshness bound"))?;
        Some(
            last_asserted_at
                .checked_add_signed(chrono::Duration::seconds(staleness))
                .ok_or(RequestAuthorityError::InvalidBinding(
                    "federated freshness bound overflow",
                ))?,
        )
    };
    let principal = InteractiveRequestReadPrincipal::new(
        session,
        authority,
        identity_authority_digest,
        identity_last_asserted_at,
        identity_fresh_until,
    )?;
    let namespace = crate::config_store::security_contract_context_if_initialized()
        .ok_or(RequestAuthorityError::InvalidBinding(
            "security-contract context is unavailable",
        ))?
        .request_read_security_namespace(&config.auth_mode, &row.provider_id)
        .map_err(|reason| {
            tracing::warn!(reason, "request-read security namespace was not admitted");
            RequestAuthorityError::InvalidBinding("security-contract namespace")
        })?;
    let session_runtime_observation = session_credentials.runtime_observation();
    let key_identity_binding = session_runtime_observation
        .key_identity_binding_digest()
        .ok_or(RequestAuthorityError::InvalidBinding(
            "derived-session credential authority is unavailable",
        ))?;
    let digests = RequestReadCredentialDigests::new(
        bearer_verifier,
        request_read_digest(
            b"ryuki-request-read-session-deployment-recipient-v1",
            &[
                namespace.deployment_id.as_bytes(),
                namespace.trust_domain_id.as_bytes(),
                namespace.tenant_id.as_deref().unwrap_or("").as_bytes(),
            ],
        ),
        request_read_digest(
            b"ryuki-request-read-session-key-v1",
            &[key_identity_binding.as_bytes()],
        ),
    )?;
    let window = RequestReadCredentialWindow::new(
        1,
        row.created_at,
        row.created_at,
        row.expires_at,
        AssuranceLevel::SingleFactor,
        row.expires_at,
    )?;
    let credential = PersistedSessionCredential::new(
        row.session_record_id,
        bearer_verifier,
        origin.browser_binding().cloned(),
        row.created_at,
        window,
        digests,
    )?;
    crate::request_authority::RequestReadAuthority::from_persisted_session(
        namespace, principal, credential,
    )
}

fn direct_request_read_authority(
    admitted: &crate::identity_authority::AdmittedFederatedBearer,
    credential: crate::request_authority::DirectFederatedCredential,
) -> Result<
    crate::request_authority::RequestReadAuthority,
    crate::request_authority::RequestAuthorityError,
> {
    use crate::request_authority::{InteractiveRequestReadPrincipal, RequestAuthorityError};

    let staleness = i64::try_from(
        admitted
            .authenticator_origin
            .federated_authority_max_staleness_seconds()
            .map_err(|_| RequestAuthorityError::InvalidBinding("direct bearer origin"))?,
    )
    .map_err(|_| RequestAuthorityError::InvalidBinding("federated freshness bound"))?;
    let identity_fresh_until = admitted
        .identity_last_asserted_at
        .checked_add_signed(chrono::Duration::seconds(staleness))
        .ok_or(RequestAuthorityError::InvalidBinding(
            "federated freshness bound overflow",
        ))?;
    admitted
        .authenticator_origin
        .verify_integrity()
        .map_err(|_| RequestAuthorityError::InvalidBinding("direct bearer origin"))?;
    if admitted.authenticator_origin.provider_id() != admitted.authority.provider
        || !admitted
            .authenticator_origin
            .matches_validated_issuer(&admitted.authority.issuer)
    {
        return Err(RequestAuthorityError::InvalidBinding(
            "direct bearer origin provenance",
        ));
    }
    let identity_authority_digest = request_read_digest(
        b"ryuki-request-read-direct-identity-authority-v2",
        &[
            &admitted.identity_authority_digest,
            admitted.authenticator_origin.origin_binding_digest_bytes(),
        ],
    );
    let principal = InteractiveRequestReadPrincipal::new(
        &admitted.session,
        &admitted.authority,
        identity_authority_digest,
        Some(admitted.identity_last_asserted_at),
        Some(identity_fresh_until),
    )?;
    let namespace = crate::config_store::security_contract_context_if_initialized()
        .ok_or(RequestAuthorityError::InvalidBinding(
            "security-contract context is unavailable",
        ))?
        .request_read_security_namespace(
            &AuthMode::EntraId,
            admitted.authenticator_origin.provider_id(),
        )
        .map_err(|reason| {
            tracing::warn!(
                reason,
                "direct bearer request-read namespace was not admitted"
            );
            RequestAuthorityError::InvalidBinding("security-contract namespace")
        })?;
    crate::request_authority::RequestReadAuthority::from_direct_federated(
        namespace,
        principal,
        credential,
        Arc::clone(&admitted.authenticator_origin),
    )
}

fn development_request_read_authority(
    session: &AuthSession,
    auth_mode: &AuthMode,
) -> Result<
    crate::request_authority::RequestReadAuthority,
    crate::request_authority::RequestAuthorityError,
> {
    let namespace = crate::config_store::security_contract_context_if_initialized()
        .ok_or(
            crate::request_authority::RequestAuthorityError::InvalidBinding(
                "security-contract context is unavailable",
            ),
        )?
        .request_read_security_namespace(auth_mode, "development-fixture")
        .map_err(|reason| {
            tracing::warn!(
                reason,
                "development request-read namespace was not admitted"
            );
            crate::request_authority::RequestAuthorityError::InvalidBinding(
                "security-contract namespace",
            )
        })?;
    let authenticated_at = chrono::Utc::now();
    crate::request_authority::RequestReadAuthority::development_fixture(
        namespace,
        session,
        authenticated_at,
        authenticated_at + chrono::Duration::seconds(60),
    )
}

fn bearer_value(auth_header: Option<&str>) -> Option<&str> {
    auth_header?.trim().strip_prefix("Bearer ").map(str::trim)
}

/// Which request surface carried the opaque session bearer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionIdSource {
    /// X-Ryuki-Session-Id header (the portal's compatibility surface).
    Header,
    /// Authorization: Bearer rys_... (direct API callers).
    Bearer,
    /// Mode-selected session cookie. Browsers attach it automatically, so it
    /// never authorizes unsafe methods (CSRF defense).
    Cookie,
}

/// Resolves the caller's opaque session bearer, in order:
/// X-Ryuki-Session-Id, Authorization: Bearer rys_..., then the mode-selected
/// session cookie. Administrative session UUIDs and legacy UUID bearers are
/// never accepted.
fn session_credential_from_headers<'a, C: cookie_runtime::SessionParserConsumer>(
    headers: &'a HeaderMap,
    auth_header: Option<&'a str>,
    parser: &cookie_runtime::SessionCookieParser<C>,
) -> Option<(Result<&'a str, ()>, SessionIdSource)> {
    let raw_header_value = headers.get("X-Ryuki-Session-Id");
    let header_value = raw_header_value.and_then(|value| value.to_str().ok());
    let raw_authorization = headers.get(axum::http::header::AUTHORIZATION);
    // Unit-level callers may provide the already-parsed value directly. The
    // real request path also carries the raw header, which must count as
    // credential evidence even when it is not valid text.
    let authorization_present = raw_authorization.is_some() || auth_header.is_some();
    let cookie_evidence = match parser.parse(headers) {
        cookie_runtime::CookieEvidence::Absent => None,
        cookie_runtime::CookieEvidence::Value(value) => Some(Ok(value)),
        cookie_runtime::CookieEvidence::Invalid => Some(Err(())),
    };
    let evidence_count = usize::from(raw_header_value.is_some())
        + usize::from(authorization_present)
        + usize::from(cookie_evidence.is_some());
    if evidence_count > 1 {
        let source = if raw_header_value.is_some() {
            SessionIdSource::Header
        } else if authorization_present {
            SessionIdSource::Bearer
        } else {
            SessionIdSource::Cookie
        };
        return Some((Err(()), source));
    }

    if raw_header_value.is_some() && header_value.is_none() {
        return Some((Err(()), SessionIdSource::Header));
    }
    if raw_authorization.is_some() && auth_header.is_none() {
        return Some((Err(()), SessionIdSource::Bearer));
    }

    if let Some(raw_session_id) = header_value {
        let candidate = raw_session_id.trim();
        return Some((
            crate::session_credentials::is_well_formed_session_bearer(candidate)
                .then_some(candidate)
                .ok_or(()),
            SessionIdSource::Header,
        ));
    }

    if let Some(auth_value) = bearer_value(auth_header) {
        // API tokens are handled before this function, and Entra/OIDC JWTs
        // must reach their validator. Only the explicit session prefix claims
        // this credential class.
        if auth_value.starts_with(crate::session_credentials::SESSION_BEARER_PREFIX) {
            return Some((
                crate::session_credentials::is_well_formed_session_bearer(auth_value)
                    .then_some(auth_value)
                    .ok_or(()),
                SessionIdSource::Bearer,
            ));
        }
    }

    if let Some(cookie_evidence) = cookie_evidence {
        return Some((
            cookie_evidence.and_then(|cookie_value| {
                crate::session_credentials::is_well_formed_session_bearer(cookie_value)
                    .then_some(cookie_value)
                    .ok_or(())
            }),
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
    issuing_principal_id: Uuid,
    roles: Vec<String>,
    token_valid: bool,
    token_hash: String,
    site_scope: Option<String>,
    environment_scope: Option<String>,
}

const API_TOKEN_LOOKUP_SQL: &str =
    "SELECT t.id, t.name, t.issuing_principal_id, t.roles, t.token_valid, t.token_hash, \
            t.site_scope, t.environment_scope \
     FROM api_tokens t \
     JOIN principal_keys k \
       ON k.principal_key_id = t.principal_key_id \
      AND k.key_version = t.principal_key_version \
      AND k.key_state = 'active' \
     JOIN principal_links l \
       ON l.principal_link_id = t.principal_link_id \
      AND l.link_version = t.principal_link_version \
      AND l.principal_key_id = t.principal_key_id \
      AND l.principal_id = t.issuing_principal_id \
      AND l.link_state = 'active' \
     JOIN principals p \
       ON p.principal_id = t.issuing_principal_id \
      AND p.lifecycle_version = t.issuing_principal_lifecycle_version \
      AND p.authority_version = t.issuing_principal_authority_version \
      AND p.lifecycle_state = 'active' \
      AND p.principal_kind = 'human' \
     WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.token_valid \
       AND t.expires_at > NOW() \
       AND cardinality(t.roles) > 0 \
       AND NOT EXISTS ( \
         SELECT 1 FROM principal_provider_tombstones pt \
         WHERE pt.provider_id = k.provider_id \
       ) \
       AND t.roles <@ p.role_allowlist \
       AND ( \
         (t.site_scope IS NULL AND p.site_authority_mode = 'global') \
         OR (t.site_scope IS NOT NULL AND t.site_scope <> '' \
           AND (p.site_authority_mode = 'global' \
             OR string_to_array(t.site_scope, ',') <@ p.site_scope)) \
       ) \
       AND ( \
         (t.environment_scope IS NULL AND p.environment_authority_mode = 'global') \
         OR (t.environment_scope IS NOT NULL AND t.environment_scope <> '' \
           AND (p.environment_authority_mode = 'global' \
             OR string_to_array(t.environment_scope, ',') <@ p.environment_scope)) \
       ) \
     FOR UPDATE OF t";

/// Parse a persisted scope column (a comma-separated TEXT, or NULL) into the
/// authorized-scope list: trimmed, non-empty values. NULL/empty ⇒ `[]` =
/// UNRESTRICTED (see `ryuki_engine::auth::scope_permits`).
fn parse_token_scope(raw: Option<String>) -> Vec<String> {
    raw.as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Resolves an `ryk_` API-token bearer to an `AuthSession`.
///
/// The WHERE clause filters by the exact hash and excludes revoked/expired rows;
/// the returned row's stored hash is then re-verified against the recomputed
/// digest with a constant-time compare (defense-in-depth). Not-found, expired,
/// revoked, and hash-mismatch all collapse to a single low-cardinality reason so
/// the failure surface cannot be used as an enumeration oracle. On success the
/// session carries the row's `roles`/`token_valid` verbatim and
/// `provider_mode = "api-token"`; persisted site and environment scopes are
/// carried onto the resulting session for downstream authorization checks.
async fn resolve_api_token(plaintext: &str, pool: &sqlx::PgPool) -> AuthSession {
    use subtle::ConstantTimeEq;

    let hash_hex = sha256_hex(plaintext);
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => {
            tracing::error!(error = %error, "api token lookup transaction failed");
            return unverified_session("api-token-invalid");
        }
    };
    let provenance = sqlx::query_as::<_, (String, String, String)>(
        "SELECT k.provider_id, k.issuer, k.subject \
         FROM api_tokens t \
         JOIN principal_keys k \
           ON k.principal_key_id = t.principal_key_id \
          AND k.key_version = t.principal_key_version \
         WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.token_valid \
           AND t.expires_at > NOW()",
    )
    .bind(&hash_hex)
    .fetch_optional(&mut *tx)
    .await;
    let (provider, issuer, subject) = match provenance {
        Ok(Some(provenance)) => provenance,
        Ok(None) => return unverified_session("api-token-invalid"),
        Err(error) => {
            tracing::error!(error = %error, "api token provenance lookup failed");
            return unverified_session("api-token-invalid");
        }
    };
    if let Err(error) =
        crate::human_authority::prepare_reader_tx(&mut tx, &provider, &issuer, &subject).await
    {
        tracing::error!(error = %error, "api token authority lock failed");
        return unverified_session("api-token-invalid");
    }
    let row = sqlx::query_as::<_, ApiTokenRow>(API_TOKEN_LOOKUP_SQL)
        .bind(&hash_hex)
        .fetch_optional(&mut *tx)
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
        if let Err(error) = sqlx::query(
            "UPDATE api_tokens SET last_used_at = GREATEST( \
                 COALESCE(last_used_at, '-infinity'::timestamptz), statement_timestamp() \
             ) WHERE id = $1",
        )
        .bind(row.id)
        .execute(&mut *tx)
        .await
        {
            tracing::warn!(error = %error, token_id = %row.id, "api token last_used_at update failed");
        } else if let Err(error) = tx.commit().await {
            tracing::warn!(error = %error, token_id = %row.id, "api token last_used_at commit failed");
        }
        let principal_id = match PrincipalId::from_uuid(row.issuing_principal_id) {
            Ok(principal_id) => principal_id,
            Err(_) => return unverified_session("api-token-invalid"),
        };
        AuthSession {
            display_user_id: principal_id.to_string(),
            principal_id: Some(principal_id),
            display_name: row.name,
            roles: row.roles,
            token_valid: row.token_valid,
            actor_class: ryuki_engine::auth::ActorClass::Workload,
            provider_mode: "api-token".into(),
            // #2: carry the token's persisted scopes onto the session so handlers
            // can enforce them. NULL/empty ⇒ unrestricted.
            site_scope: parse_token_scope(row.site_scope),
            environment_scope: parse_token_scope(row.environment_scope),
        }
    } else {
        unverified_session("api-token-mismatch")
    }
}

#[cfg(test)]
pub(crate) async fn auth_session_from_persisted_session(
    headers: &HeaderMap,
    auth_header: Option<&str>,
    config: &RyukiConfig,
) -> Option<(AuthSession, SessionIdSource)> {
    let admission = crate::session_lookup_admission::global_admission();
    auth_session_from_persisted_session_with_admission(
        headers,
        auth_header,
        config,
        &admission,
        None,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn auth_session_from_persisted_session_with_admission(
    headers: &HeaderMap,
    auth_header: Option<&str>,
    config: &RyukiConfig,
    admission: &Arc<crate::session_lookup_admission::SessionLookupAdmission>,
    proof: Option<crate::session_lookup_admission::SessionLookupAdmissionProof>,
) -> Option<(AuthSession, SessionIdSource)> {
    let cookie_runtime = test_cookie_runtime(config);
    let session_parser = cookie_runtime.session_auth_parser();
    let session_credentials =
        crate::session_credentials::DerivedSessionCredentialRuntime::from_admitted_config(
            &config.session,
        )
        .expect("test config must construct session credential runtime");
    let origin_authority =
        crate::session_lookup_admission::SessionLookupOriginAuthority::for_test_auth_mode(
            &config.auth_mode,
        );
    auth_session_from_persisted_session_with_authority_admission(
        headers,
        auth_header,
        proof,
        PersistedSessionResolutionContext {
            config,
            admission,
            session_parser: &session_parser,
            session_credentials: session_credentials.as_ref(),
            origin_authority: &origin_authority,
        },
    )
    .await
    .map(|(session, source, _authority, _request_read)| (session, source))
}

#[cfg(test)]
fn test_cookie_runtime(config: &RyukiConfig) -> Arc<cookie_runtime::ApiCookieRuntime> {
    let mut config = config.clone();
    if !config.session.cookie_secure {
        config.server.bind_address = "127.0.0.1:0".into();
    }
    cookie_runtime::ApiCookieRuntime::from_admitted_config(&config, false)
        .expect("test config must construct a cookie runtime")
}

struct PersistedSessionResolutionContext<'a> {
    config: &'a RyukiConfig,
    admission: &'a Arc<crate::session_lookup_admission::SessionLookupAdmission>,
    session_parser: &'a cookie_runtime::ApiSessionAuthParser,
    session_credentials: &'a crate::session_credentials::DerivedSessionCredentialRuntime,
    origin_authority: &'a crate::session_lookup_admission::SessionLookupOriginAuthority,
}

async fn auth_session_from_persisted_session_with_authority_admission(
    headers: &HeaderMap,
    auth_header: Option<&str>,
    proof: Option<crate::session_lookup_admission::SessionLookupAdmissionProof>,
    context: PersistedSessionResolutionContext<'_>,
) -> Option<(
    AuthSession,
    SessionIdSource,
    Option<crate::human_authority::InteractiveHumanAuthorityContext>,
    Option<crate::request_authority::RequestReadAuthority>,
)> {
    let PersistedSessionResolutionContext {
        config,
        admission,
        session_parser,
        session_credentials,
        origin_authority,
    } = context;
    let auth_mode = &config.auth_mode;
    // Classify all credential evidence once. Any malformed session bearer or
    // simultaneous header/Authorization/cookie evidence fails closed before a
    // credential-specific resolver can fall through to another identity.
    let session_evidence = session_credential_from_headers(headers, auth_header, session_parser);
    if let Some((Err(()), source)) = session_evidence {
        return Some((
            unverified_session("conflicting-or-invalid-credentials"),
            source,
            None,
            None,
        ));
    }

    // API-token bearers (`ryk_...`) are resolved BEFORE the UUID/cookie path: a
    // `ryk_` string is not a valid UUID, so without this explicit branch it
    // would silently fall through to the UUID parse and become unverified.
    //
    if let Some(token) = bearer_value(auth_header) {
        if token.strip_prefix(API_TOKEN_PREFIX).is_some() {
            if let Some(pool) = crate::database::get_db() {
                let candidate = resolve_api_token(token, pool).await;
                if candidate.token_valid {
                    return Some((candidate, SessionIdSource::Bearer, None, None));
                }
                return Some((candidate, SessionIdSource::Bearer, None, None));
            }
            return Some((
                unverified_session("api-token-verifier-unavailable"),
                SessionIdSource::Bearer,
                None,
                None,
            ));
        }
    }

    // Persisted browser sessions are not an authentication mechanism in the
    // credential-free static development modes.
    if matches!(auth_mode, AuthMode::MockDryRun | AuthMode::StaticDryRun) {
        if let Some((Ok(_), source)) = session_evidence {
            return Some((
                unverified_session("session-auth-disabled"),
                source,
                None,
                None,
            ));
        }
        return None;
    }

    let (Ok(bearer), source) = session_evidence? else {
        unreachable!("invalid session evidence returned above");
    };
    let pool = crate::database::get_db()?;
    let verifier = match session_credentials.verifier(bearer) {
        Ok(verifier) => verifier,
        Err(error) => {
            tracing::error!(reason = %error, "session verifier configuration rejected");
            return Some((
                unverified_session("session-verifier-unavailable"),
                source,
                None,
                None,
            ));
        }
    };
    let mut cached_authority = None;
    let _lookup_guard = match admission.admit_for_resolver(verifier, origin_authority, proof) {
        crate::session_lookup_admission::SessionLookupDecision::KnownPositive(authority) => {
            cached_authority = authority;
            None
        }
        crate::session_lookup_admission::SessionLookupDecision::Unknown(guard) => Some(guard),
        crate::session_lookup_admission::SessionLookupDecision::CachedMiss => {
            return Some((
                unverified_session("session-not-found-cached"),
                source,
                None,
                None,
            ));
        }
        crate::session_lookup_admission::SessionLookupDecision::Rejected(_) => {
            return Some((
                unverified_session("session-lookup-admission-rejected"),
                source,
                None,
                None,
            ));
        }
    };
    // The disabled browser namespace never admits a persisted session. Local
    // sessions retain NULL provenance; federated sessions must join the exact
    // append-only origin generation derived from the retained runtime Arc.
    if !origin_authority.permits_persisted_sessions() {
        admission.record_miss_for_origin(verifier, origin_authority);
        return Some((
            unverified_session("browser-session-auth-disabled"),
            source,
            None,
            None,
        ));
    }
    let browser_origin = origin_authority.browser_binding();
    let query = "SELECT s.session_record_id, s.principal_id, \
                s.principal_lifecycle_version, s.principal_authority_version, \
                s.principal_key_id, s.principal_key_version, \
                s.principal_link_id, s.principal_link_version, \
                s.display_name, s.roles, \
                s.session_bearer_verifier_v3 AS bearer_verifier, \
                s.expires_at, s.created_at, \
                k.provider_id, k.issuer, k.subject, \
                s.site_authority_mode, s.site_scope, \
                s.environment_authority_mode, s.environment_scope, \
                s.authenticator_origin_binding_digest, \
                registered_origin.authenticator_origin_binding_digest \
                    AS registered_origin_binding_digest, \
                current_browser.current_origin_binding_digest \
                    AS current_origin_binding_digest \
         FROM sessions s \
         JOIN principal_keys k \
           ON k.principal_key_id = s.principal_key_id \
          AND k.key_version = s.principal_key_version \
          AND k.key_state = 'active' \
         JOIN principal_links l \
           ON l.principal_link_id = s.principal_link_id \
          AND l.link_version = s.principal_link_version \
          AND l.principal_key_id = s.principal_key_id \
          AND l.principal_id = s.principal_id \
          AND l.link_state = 'active' \
         JOIN principals p \
           ON p.principal_id = s.principal_id \
          AND p.lifecycle_version = s.principal_lifecycle_version \
          AND p.authority_version = s.principal_authority_version \
          AND p.lifecycle_state = 'active' \
          AND p.principal_kind = 'human' \
         LEFT JOIN authenticator_authority_generations registered_origin \
           ON registered_origin.authenticator_origin_binding_digest = \
              s.authenticator_origin_binding_digest \
         LEFT JOIN authenticator_authority_current_paths current_browser \
           ON current_browser.provider_id = registered_origin.provider_id \
          AND current_browser.path_kind = 'browser-derived-session' \
         WHERE s.session_bearer_verifier_v3 = $1 AND s.expires_at > NOW() \
           AND cardinality(s.roles) > 0 \
           AND s.roles <@ p.role_allowlist \
           AND NOT EXISTS ( \
             SELECT 1 FROM principal_provider_tombstones pt \
             WHERE pt.provider_id = k.provider_id \
           ) \
           AND (p.site_authority_mode = 'global' OR ( \
             s.site_authority_mode = 'scoped' AND s.site_scope <@ p.site_scope \
           )) \
           AND (p.environment_authority_mode = 'global' OR ( \
             s.environment_authority_mode = 'scoped' \
             AND s.environment_scope <@ p.environment_scope \
           )) \
           AND (k.provider_id = 'local' OR \
                s.created_at >= NOW() - make_interval(secs => $2)) \
           AND ( \
             ($3 AND s.authenticator_origin_binding_digest IS NULL \
                 AND registered_origin.authenticator_origin_binding_digest IS NULL \
                 AND current_browser.current_origin_binding_digest IS NULL \
                 AND k.provider_id = 'local' AND k.issuer = $4) \
             OR ($5::BYTEA IS NOT NULL \
                 AND s.authenticator_origin_binding_digest = $5 \
                 AND registered_origin.authenticator_origin_binding_digest = $5 \
                 AND current_browser.path_status = 'active' \
                 AND current_browser.current_origin_binding_digest = $5 \
                 AND registered_origin.deployment_id = $6 \
                 AND registered_origin.trust_domain_id = $7 \
                 AND registered_origin.tenant_id IS NOT DISTINCT FROM $8 \
                 AND registered_origin.provider_id = $9 \
                 AND k.provider_id = registered_origin.provider_id \
                 AND registered_origin.provider_configuration_version = $10 \
                 AND registered_origin.provider_configuration_payload_digest = $11 \
                 AND registered_origin.provider_lifecycle_record_version = $12 \
                 AND registered_origin.provider_lifecycle_state = 'active' \
                 AND registered_origin.binding_document_id = $13 \
                 AND registered_origin.binding_document_version = $14 \
                 AND registered_origin.binding_document_digest = $15 \
                 AND registered_origin.binding_document_locator = $16 \
                 AND registered_origin.provider_policy_binding_digest = $17 \
                 AND registered_origin.runtime_binding_digest = $18 \
                 AND registered_origin.path_id = $19 \
                 AND registered_origin.path_version = $20 \
                 AND registered_origin.path_kind = $21) \
           )";
    let lookup_observation = admission.start_database_lookup();
    let lookup_result = sqlx::query_as::<_, DbAuthSessionRow>(query)
        .bind(verifier.as_slice())
        .bind(session_credentials.federated_authority_max_staleness_seconds() as f64)
        .bind(origin_authority.is_local())
        .bind(crate::identity_authority::LOCAL_ISSUER)
        .bind(browser_origin.map(|binding| binding.origin_binding_digest().as_slice()))
        .bind(browser_origin.map(|binding| binding.deployment_id()))
        .bind(browser_origin.map(|binding| binding.trust_domain_id()))
        .bind(browser_origin.and_then(|binding| binding.tenant_id()))
        .bind(browser_origin.map(|binding| binding.provider_id()))
        .bind(browser_origin.map(|binding| binding.provider_configuration_version()))
        .bind(
            browser_origin
                .map(|binding| binding.provider_configuration_payload_digest().as_slice()),
        )
        .bind(browser_origin.map(|binding| binding.provider_lifecycle_record_version()))
        .bind(browser_origin.map(|binding| binding.binding_document_id()))
        .bind(browser_origin.map(|binding| binding.binding_document_version()))
        .bind(browser_origin.map(|binding| binding.binding_document_digest().as_slice()))
        .bind(browser_origin.map(|binding| binding.binding_document_locator()))
        .bind(browser_origin.map(|binding| binding.provider_policy_binding_digest().as_slice()))
        .bind(browser_origin.map(|binding| binding.runtime_binding_digest().as_slice()))
        .bind(browser_origin.map(|binding| binding.path_id()))
        .bind(browser_origin.map(|binding| binding.path_version()))
        .bind(browser_origin.map(|binding| binding.path_kind()))
        .fetch_optional(pool)
        .await;
    let lookup_outcome = match &lookup_result {
        Ok(Some(_)) => crate::session_lookup_admission::SessionDatabaseLookupOutcome::Row,
        Ok(None) => crate::session_lookup_admission::SessionDatabaseLookupOutcome::Miss,
        Err(_) => crate::session_lookup_admission::SessionDatabaseLookupOutcome::Error,
    };
    lookup_observation.finish(lookup_outcome);
    match lookup_result {
        Ok(Some(row)) => {
            use subtle::ConstantTimeEq;
            if bool::from(verifier.as_slice().ct_eq(row.bearer_verifier.as_slice()))
                && session_row_matches_origin(&row, origin_authority)
            {
                let authority_binding =
                    crate::session_lookup_admission::SessionAuthorityCacheBinding {
                        principal_id: PrincipalId::from_uuid(row.principal_id).ok()?,
                        principal_lifecycle_version: row.principal_lifecycle_version,
                        principal_authority_version: row.principal_authority_version,
                        principal_key_id: row.principal_key_id,
                        principal_key_version: row.principal_key_version,
                        principal_link_id: row.principal_link_id,
                        principal_link_version: row.principal_link_version,
                    };
                if let Some(cached) = cached_authority.filter(|cached| *cached != authority_binding)
                {
                    admission.evict_binding(cached);
                    admission.evict_binding(authority_binding);
                    return Some((
                        unverified_session("session-authority-cache-stale"),
                        source,
                        None,
                        None,
                    ));
                }
                let valid_for = (row.expires_at - chrono::Utc::now())
                    .to_std()
                    .unwrap_or(Duration::ZERO);
                admission.record_hit_for_origin(
                    verifier,
                    origin_authority,
                    valid_for,
                    authority_binding,
                );
                let Some(authority) = authority_context_from_db_row(&row) else {
                    admission.record_miss_for_origin(verifier, origin_authority);
                    return Some((
                        unverified_session("session-authority-shape-invalid"),
                        source,
                        None,
                        None,
                    ));
                };
                let Some(admitted_session) = session_from_db_row(&row) else {
                    admission.record_miss_for_origin(verifier, origin_authority);
                    return Some((
                        unverified_session("session-principal-id-invalid"),
                        source,
                        None,
                        None,
                    ));
                };
                let request_read = match persisted_request_read_authority(
                    &row,
                    config,
                    session_credentials,
                    &admitted_session,
                    &authority,
                    origin_authority,
                ) {
                    Ok(authority) => Some(authority),
                    Err(error) => {
                        tracing::warn!(reason = %error, "persisted session has no request-read authority");
                        None
                    }
                };
                Some((admitted_session, source, Some(authority), request_read))
            } else {
                admission.record_miss_for_origin(verifier, origin_authority);
                Some((
                    unverified_session("session-verifier-mismatch"),
                    source,
                    None,
                    None,
                ))
            }
        }
        Ok(None) => {
            admission.record_miss_for_origin(verifier, origin_authority);
            Some((unverified_session("session-not-found"), source, None, None))
        }
        Err(error) => {
            tracing::error!(error = %error, "auth session lookup failed");
            Some((
                unverified_session("session-lookup-failed"),
                source,
                None,
                None,
            ))
        }
    }
}

fn is_unsafe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// Source of truth for the PUBLIC (no-auth) surface documented in
/// `openapi.rs`. Cross-checked by `openapi.rs`'s drift-guard tests: adding or
/// removing a public route here without updating the OpenAPI document (or
/// vice versa) fails those tests. Kept separate from `is_auth_exempt_path`'s
/// `matches!` (which also exempts the auth POSTs / OIDC routes that are NOT
/// part of the documented public OpenAPI surface) so the doc's scope stays
/// intentionally narrower than the full exemption list.
#[allow(dead_code)]
pub const PUBLIC_ROUTE_PATHS: &[(&str, &str)] = &[
    ("GET", "/health"),
    ("GET", "/ready"),
    ("GET", "/api/auth/status"),
    ("GET", "/api/auth/session"),
    ("GET", "/api/auth/roles"),
    ("GET", "/api/platform/summary"),
];

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
            // OIDC browser sign-in (GET — runs before any session exists)
            | "/api/auth/oidc/login"
            // OIDC authorization-code callback (GET — no session yet)
            | "/api/auth/oidc/callback"
            // Entra ID browser SSO (GET — both run before any session exists;
            // gated on auth_mode == entra-id inside the handlers)
            | "/api/auth/entra/authorize-url"
            | "/api/auth/entra/callback"
    )
}

/// Preserve the explicit, permanent 400 response for Entra browser endpoints
/// when this process has no sealed browser handler authority. A deployment
/// with a declared browser path is rejected during startup; this middleware is
/// therefore reachable only for non-Entra mode or an intentionally disabled
/// Entra browser path and never fabricates dependencies or origin provenance.
async fn unavailable_entra_browser_routes(
    request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    if !matches!(
        request.uri().path(),
        "/api/auth/entra/authorize-url" | "/api/auth/entra/callback"
    ) {
        return next.run(request).await;
    }
    let config = crate::config_store::get_app_config();
    let (error, message) = if config.auth_mode == AuthMode::EntraId {
        (
            "ENTRA_SSO_NOT_CONFIGURED",
            "Entra ID SSO is not fully configured (tenant id, client id, and redirect URI are required)",
        )
    } else {
        (
            "ENTRA_AUTH_DISABLED",
            "Entra ID sign-in requires auth_mode entra-id",
        )
    };
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": error, "message": message })),
    )
        .into_response()
}

fn auth_session_allows_unsafe_method(session: &AuthSession) -> bool {
    session.token_valid || session.provider_mode == "static-dry-run"
}

/// Decides whether the resolved session may perform this request.
///
/// CSRF defense: the mode-selected session cookie is attached automatically
/// by browsers, so a session resolved from the COOKIE source alone never
/// authorizes unsafe methods (POST/PUT/PATCH/DELETE). The portal always sends
/// X-Ryuki-Session-Id; direct API callers use `Authorization: Bearer`.
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
        prefix: "/api/metrics",
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

/// True only when `path` is one direct member below `prefix`. This deliberately
/// rejects the collection itself, empty identifiers, and extra child paths so a
/// protected capability cannot be inherited through a broad string prefix.
fn is_single_segment_member(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|segment| !segment.is_empty() && !segment.contains('/'))
}

/// True only for the single-event and batch acknowledgement route shapes.  A
/// broad prefix/suffix test would let an unrelated future child route inherit
/// triage mutation authority, so the middle portion must be exactly one
/// non-empty path segment.
fn is_alert_acknowledgement_path(path: &str) -> bool {
    path.strip_prefix("/api/events/alerts/")
        .and_then(|rest| rest.strip_suffix("/ack"))
        .is_some_and(|segment| !segment.is_empty() && !segment.contains('/'))
}

/// Resolves the closed functional capability required by security-sensitive
/// read and mutation shapes. This decision runs before the legacy coarse
/// permission tables: holding `request`, `audit`, or `execute` is never
/// sufficient for one of these operations.
///
/// Resource authority remains a separate handler decision. For example, a
/// software operator must hold `software.deployment.execute` here and still
/// satisfy the deployment row's authoritative site/environment scope later.
fn operation_capability_for(method: &Method, path: &str) -> Option<OperationCapability> {
    // Operational alert disclosure and triage mutation are intentionally
    // separate grants. Keep the GET exact and the POST shapes closed so neither
    // capability can be inherited by its sibling or by a future route.
    if method == Method::GET && path == "/api/events/alerts" {
        return Some(OperationCapability::MonitoringAlertRead);
    }
    if method == Method::POST && is_alert_acknowledgement_path(path) {
        return Some(OperationCapability::MonitoringAlertAcknowledge);
    }

    if !is_unsafe_method(method) {
        return None;
    }

    if method == Method::POST && is_single_segment_member(path, "/api/identity/ad/delete") {
        return Some(OperationCapability::IdentityAdComputerDelete);
    }
    if path == "/api/network/firewall" || path.starts_with("/api/network/firewall/") {
        return Some(OperationCapability::NetworkFirewallManage);
    }
    if path == "/api/monitoring/alert-routes" || path.starts_with("/api/monitoring/alert-routes/") {
        return Some(OperationCapability::MonitoringAlertRoutingManage);
    }
    if method == Method::DELETE && is_single_segment_member(path, "/api/datacenter/storage/arrays")
    {
        return Some(OperationCapability::StorageArrayDecommission);
    }
    if method == Method::POST && is_single_segment_member(path, "/api/maintain/software/execute") {
        return Some(OperationCapability::SoftwareDeploymentExecute);
    }

    None
}

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
        // rework (send back to Intake for fixes) is the non-terminal sibling of
        // reject — also an approver decision.
        Some("rework") => Some("approve"),
        // fail (mark terminally Failed) is an operator act during execution.
        Some("fail") => Some("execute"),
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
/// operator capability. The central gate is mandatory for every sign-off.
/// Security-sensitive newer handlers (including firmware exceptions) repeat it
/// as defense in depth; several legacy sign-off handlers still rely on this
/// resolver as their only permission boundary.
///
/// The access-review family carries reviewer CLAIM plus all three reviewer
/// VERDICTS (start / approve / revoke / exempt) at the `approve` tier. `start`
/// establishes the stable reviewer designation, so allowing an execute-tier
/// workload to win that CAS would strand the review: the workload could not
/// produce the later human verdict and no reassignment route exists.
///
/// NOT included — `/api/cmdb/servicenow/approve` and
/// `/api/maintain/certificates/approve` carry the `approve` NAME but gate nothing
/// (read-only acknowledgements: no `Approved` state exists in their domain and no
/// downstream action requires them), so they stay operator-tier.
///
/// Returns `None` for non-approval paths so the caller falls through to the prefix
/// table.
fn approval_signoff_permission(path: &str) -> Option<&'static str> {
    // VM Day-2 approval is a body-id action with no path child. Keep the
    // checker gate exact so future sibling/deeper actions do not inherit it.
    if path == "/api/vm/day2/approve" {
        return Some("approve");
    }

    // Image promotion and rejection are the two durable reviewer verdicts and
    // each accepts one exact image id. Keep these shapes closed.
    if is_single_segment_member(path, "/api/datacenter/image-factory/promote") {
        return Some("approve");
    }
    if is_single_segment_member(path, "/api/datacenter/image-factory/reject") {
        return Some("approve");
    }

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
    // Firmware exceptions use an id-in-the-middle two-party decision route.
    // The sibling collection route creates Pending requests and remains at the
    // datacenter execute tier; only the explicit checker verdict is approve-tier.
    if let Some(rest) = path.strip_prefix("/api/datacenter/firmware/exception/") {
        if let Some(id) = rest.strip_suffix("/approve") {
            if !id.is_empty() && !id.contains('/') {
                return Some("approve");
            }
        }
    }
    // Revoking an active exception invalidates previously approved governance
    // evidence and therefore carries the same human approver tier.
    if is_single_segment_member(path, "/api/datacenter/firmware/revoke") {
        return Some("approve");
    }
    // Access-review reviewer claim/verdict actions put the id in the MIDDLE
    // (`/api/identity/access-review/{id}/{start|approve|revoke|exempt}`), which a
    // static prefix cannot express. Match exactly one id segment then the action.
    if let Some(rest) = path.strip_prefix("/api/identity/access-review/") {
        for action in ["start", "approve", "revoke", "exempt"] {
            if let Some(id) = rest.strip_suffix(&format!("/{action}")) {
                if !id.is_empty() && !id.contains('/') {
                    return Some("approve");
                }
            }
        }
    }
    None
}

/// Human judgments and derived-credential grants that must never be produced
/// by a workload, unknown carrier, or simulated identity. This is deliberately
/// path-shape based and provider-neutral: the separate admission proof decides
/// whether the actor is an exact governed human.
fn requires_verified_human_signoff(method: &Method, path: &str) -> bool {
    if !is_unsafe_method(method) {
        return false;
    }

    // Every request approval verdict (including batch and step-scoped
    // live-apply grants) ends with one of these closed action names.
    if let Some(rest) = path.strip_prefix("/api/requests/") {
        if matches!(
            rest.rsplit('/').next(),
            Some("approve" | "reject" | "rework" | "approve-live-apply")
        ) {
            return true;
        }
    }

    if approval_signoff_permission(path).is_some() {
        return true;
    }

    // Break-glass is a human-only control plane from initiation through close.
    // Safe inventory reads are excluded by the unsafe-method check above.
    if path == "/api/ops/emergency/initiate" || path.starts_with("/api/ops/emergency/") {
        return true;
    }

    // Direct admin-grade sign-off, attestation, and derived-credential sinks
    // whose coarse route permission is not the ordinary `approve` tier.
    path == "/api/admin/agents/enrollment-challenges"
        || path == "/api/admin/agents/live-apply-jobs"
        || path == "/api/protect/snapshot/review"
        || is_single_segment_member(path, "/api/protect/legal-hold/release")
        || is_single_segment_member(path, "/api/analytics/aiops/review")
        || member_action_path(path, "/api/admin/agents", "approve")
        || member_action_path(path, "/api/admin/agents", "revoke")
        || is_single_segment_member(path, "/api/identity/ad/quarantine-recovery/review")
        || is_single_segment_member(path, "/api/identity/ad/quarantine-recovery/approve")
        || is_single_segment_member(path, "/api/identity/ad/quarantine-recovery/apply")
        || is_single_segment_member(path, "/api/identity/shares/recertify")
        || member_action_path(path, "/api/audit/compliance/controls", "assess")
        || member_action_path(path, "/api/audit/compliance/findings", "waive")
}

/// Exactly `{collection}/{one-id}/{action}` with no additional segments.
fn member_action_path(path: &str, collection: &str, action: &str) -> bool {
    let Some(rest) = path.strip_prefix(&format!("{collection}/")) else {
        return false;
    };
    let Some(id) = rest.strip_suffix(&format!("/{action}")) else {
        return false;
    };
    !id.is_empty() && !id.contains('/')
}

/// Platform-global identity administration must stay on the exact interactive
/// Global-human authority path. API tokens may retain explicitly granted
/// machine operations, but can neither administer peer credentials nor create
/// or enumerate access-recertification campaigns whose counts span every site.
fn requires_global_verified_human_administration(path: &str) -> bool {
    let credential_administration = path == "/api/admin/tokens"
        || is_single_segment_member(path, "/api/admin/tokens")
        || path == "/api/admin/sessions"
        || is_single_segment_member(path, "/api/admin/sessions");
    let access_campaign_administration = path == "/api/identity/access-review/campaign"
        || is_single_segment_member(path, "/api/identity/access-review/campaign")
        || path == "/api/identity/access-review/campaigns";
    credential_administration || access_campaign_administration
}

fn interactive_authority_matches_session(
    session: &AuthSession,
    authority: Option<&crate::human_authority::InteractiveHumanAuthorityContext>,
) -> bool {
    let Some(authority) = authority else {
        return false;
    };
    session.is_verified_human()
        && !authority.provider.trim().is_empty()
        && !authority.issuer.trim().is_empty()
        && !authority.subject.trim().is_empty()
        && authority.identity_epoch > 0
        && authority.assignment_version > 0
        && session.principal_id == Some(authority.principal_binding.principal_id)
        && authority.roles == session.roles
        && authority.site_scope == session.site_scope
        && authority.environment_scope == session.environment_scope
        && matches!(
            authority.site_mode,
            crate::human_authority::HumanAuthorityMode::Global
                | crate::human_authority::HumanAuthorityMode::Scoped
        )
        && matches!(
            authority.environment_mode,
            crate::human_authority::HumanAuthorityMode::Global
                | crate::human_authority::HumanAuthorityMode::Scoped
        )
}

fn global_interactive_authority_matches_session(
    session: &AuthSession,
    authority: Option<&crate::human_authority::InteractiveHumanAuthorityContext>,
) -> bool {
    interactive_authority_matches_session(session, authority)
        && session.site_scope.is_empty()
        && session.environment_scope.is_empty()
        && authority.is_some_and(|authority| {
            authority.site_mode == crate::human_authority::HumanAuthorityMode::Global
                && authority.environment_mode == crate::human_authority::HumanAuthorityMode::Global
        })
}

/// Mutations whose FAMILY ROOT is otherwise unclassified in `ROUTE_PERMISSIONS` (so the
/// fail-closed `admin` default would apply) but whose handler intends a specific LOWER
/// tier. Without these, the mutation is accidentally admin-only and the handler's looser
/// check is unreachable for the intended principals. SHAPE-matched (NOT a method-agnostic
/// `/api/events`/`/api/audit` prefix) so any OTHER future unsafe route under these families
/// stays fail-closed to `admin` until explicitly classified.
fn unclassified_family_mutation_permission(method: &Method, path: &str) -> Option<&'static str> {
    // The dedicated capability is authoritative; `execute` is only the coarse
    // route-table floor for this otherwise-unclassified mutation family.
    if method == Method::POST && is_alert_acknowledgement_path(path) {
        return Some("execute");
    }
    // Audit hash-chain re-verify — audit_log_verify checks `audit`.
    if method == Method::POST && path == "/api/audit/log/verify" {
        return Some("audit");
    }
    None
}

/// Central coarse-permission resolver for unsafe methods. Exact exceptional
/// shapes are method-aware; the legacy family table remains method-independent.
/// Returns the required coarse permission, defaulting fail-closed to `admin`.
fn route_permission_for(method: &Method, path: &str) -> &'static str {
    if let Some(permission) = requests_route_permission(path) {
        return permission;
    }
    // Maker/checker approval sign-offs that live under execute-tier families must
    // be resolved BEFORE the prefix table, which would otherwise map them to
    // `execute` via their family root.
    if let Some(permission) = approval_signoff_permission(path) {
        return permission;
    }
    // Lower-tier mutations whose family root is unclassified (would else fail-closed to
    // admin) — alert ack (`execute`), audit-chain verify (`audit`). Shape-matched.
    if let Some(permission) = unclassified_family_mutation_permission(method, path) {
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

/// Exact static contract documents that are safe for a Requester to inspect.
/// A future route whose name happens to end in `-contract` defaults to the
/// audit tier until it is reviewed and added here.
static REQUESTER_CONTRACT_PATHS: &[&str] = &[
    "/api/build/k8s-contract",
    "/api/build/sql-contract",
    "/api/catalog/policy-guardrails-contract",
    "/api/catalog/request-form-contract",
    "/api/catalog/site-catalog-contract",
    "/api/cmdb/impact-contract",
    "/api/dashboard/global-overview-contract",
    "/api/dashboard/risk-heatmap-contract",
    "/api/images/factory-contract",
    "/api/observe/logs-contract",
    "/api/ops/shift-contract",
    "/api/platform/status-contract",
    "/api/platform/vault-secret-delivery-contract",
    "/api/protect/backup-coverage-contract",
    "/api/protect/backup-coverage-gap-contract",
    "/api/protect/dr-contract",
    "/api/protect/immutability-contract",
    "/api/protect/legal-hold-contract",
    "/api/protect/repository-capacity-contract",
    "/api/protect/secrets-contract",
    "/api/requests/lifecycle-contract",
    "/api/requests/preflight-contract",
    "/api/admin/approval-groups-contract",
    "/api/admin/delegation-boundary-contract",
    "/api/admin/feature-flag-governance-contract",
    "/api/admin/site-registry-contract",
    "/api/admin/worker-capability-contract",
    "/api/analytics/aiops-contract",
    "/api/analytics/cost-capacity-contract",
    "/api/approvals/decision-readiness-contract",
    "/api/audit/compliance-contract",
    "/api/build/app-environment-contract",
    "/api/build/linux-deploy-contract",
    "/api/catalog/evidence-redaction-contract",
    "/api/catalog/offerings-contract",
    "/api/catalog/recommendations-contract",
    "/api/cmdb/impact-analysis-contract",
    "/api/cmdb/reconciliation-contract",
    "/api/cmdb/relationship-graph-contract",
    "/api/cmdb/servicenow-contract",
    "/api/datacenter/check-cooling-contract",
    "/api/datacenter/check-power-contract",
    "/api/datacenter/check-rack-space-contract",
    "/api/datacenter/check-switchports-contract",
    "/api/datacenter/failing-checks-contract",
    "/api/datacenter/firmware-contract",
    "/api/datacenter/full-readiness-contract",
    "/api/datacenter/hardware-contract",
    "/api/datacenter/image-factory-contract",
    "/api/datacenter/network-contract",
    "/api/datacenter/oob-contract",
    "/api/datacenter/readiness-score-contract",
    "/api/datacenter/site-report-contract",
    "/api/datacenter/sites-contract",
    "/api/datacenter/storage-contract",
    "/api/evidence/compliance-dashboard-contract",
    "/api/evidence/export-retention-contract",
    "/api/identity/access-review-contract",
    "/api/identity/access-review-recertification-contract",
    "/api/identity/ad-computer-contract",
    "/api/identity/ad-computer-lifecycle-contract",
    "/api/identity/entra-rbac-approval-readiness-contract",
    "/api/identity/file-share-ntfs-recertification-contract",
    "/api/identity/gmsa-contract",
    "/api/identity/gmsa-lifecycle-contract",
    "/api/identity/local-privilege-access-contract",
    "/api/identity/rbac-approval-model-contract",
    "/api/identity/shares-contract",
    "/api/integrations/adapter-contract-test-contract",
    "/api/integrations/adapter-readiness-matrix-contract",
    "/api/integrations/servicenow/cmdb-file-contract",
    "/api/integrations/servicenow/future-api-contract",
    "/api/integrations/vmware/cluster-capacity-admission-contract",
    "/api/integrations/vmware/customization-spec-governance-contract",
    "/api/integrations/vmware/day2-change-contract",
    "/api/integrations/vmware/decommission-quarantine-contract",
    "/api/integrations/vmware/object-placement-contract",
    "/api/integrations/vmware/snapshot-governance-contract",
    "/api/integrations/vmware/vsan-esxi-lifecycle-contract",
    "/api/inventory/coverage-contract",
    "/api/inventory/os-baseline-compliance-contract",
    "/api/inventory/ownership-risk-contract",
    "/api/inventory/resource-overview-contract",
    "/api/maintain/baseline-contract",
    "/api/maintain/calendar-contract",
    "/api/maintain/certificate-contract",
    "/api/maintain/patch-contract",
    "/api/maintain/software-contract",
    "/api/monitoring/alert-routing-contract",
    "/api/monitoring/noise-contract",
    "/api/monitoring/zabbix-drift-contract",
    "/api/network/dns-ipam-contract",
    "/api/network/firewall-contract",
    "/api/network/loadbalancer-contract",
    "/api/observe/alert-routing-contract",
    "/api/observe/log-forwarder-onboarding-contract",
    "/api/observe/monitoring-coverage-gap-contract",
    "/api/observe/monitoring-review-queue-contract",
    "/api/observe/noise-flapping-remediation-contract",
    "/api/observe/synthetic-health-check-contract",
    "/api/observe/zabbix-drift-remediation-contract",
    "/api/observe/zabbix-onboarding-contract",
    "/api/operations/activity-queue-contract",
    "/api/operations/aiops-suggestion-contract",
    "/api/operations/certificate-lifecycle-contract",
    "/api/operations/datacenter-readiness-contract",
    "/api/operations/degradation-mode-contract",
    "/api/operations/dependency-replay-contract",
    "/api/operations/emergency-change-contract",
    "/api/operations/firmware-compliance-exception-contract",
    "/api/operations/hardware-lifecycle-contract",
    "/api/operations/incident-context-contract",
    "/api/operations/knowledge-suggestion-contract",
    "/api/operations/maintenance-communications-contract",
    "/api/operations/network-vlan-readiness-contract",
    "/api/operations/out-of-band-access-validation-contract",
    "/api/operations/outage-comms-contract",
    "/api/operations/platform-health-contract",
    "/api/operations/run-state-contract",
    "/api/operations/runbook-launch-contract",
    "/api/operations/shift-queue-contract",
    "/api/operations/standard-task-contract",
    "/api/ops/emergency-contract",
    "/api/ops/incident-context-contract",
    "/api/ops/runbook-contract",
    "/api/patching/maintenance-calendar-contract",
    "/api/patching/maintenance-contract",
    "/api/patching/policy-import-contract",
    "/api/patching/reboot-orchestration-contract",
    "/api/platform/database-readiness-contract",
    "/api/platform/degradation-contract",
    "/api/platform/design-system-contract",
    "/api/platform/kubernetes-runtime-readiness-contract",
    "/api/platform/local-container-readiness-contract",
    "/api/platform/object-storage-readiness-contract",
    "/api/platform/portal-information-architecture-contract",
    "/api/platform/registry-readiness-contract",
    "/api/platform/release-promotion-contract",
    "/api/platform/security-baseline-contract",
    "/api/platform/ui-mockup-acceptance-contract",
    "/api/platform/vault-deployment-readiness-contract",
    "/api/protect/application-aware-backup-validation-contract",
    "/api/protect/backup-dr-assignment-contract",
    "/api/protect/controlled-restore-contract",
    "/api/protect/immutability-air-gap-compliance-contract",
    "/api/protect/legal-hold-retention-contract",
    "/api/protect/restore-testing-contract",
    "/api/protect/snapshot-governance-contract",
    "/api/requests/execution-timeline-contract",
    "/api/requests/intake-support-contract",
    "/api/retire/decommission-contract",
    "/api/software/approved-deployment-contract",
    "/api/vm/day2-change-contract",
    "/api/workflows/application-environment/deployment-contract",
    "/api/workflows/application-environment/retirement-contract",
    "/api/workflows/azure-landing-zone/validation-contract",
    "/api/workflows/server-lifecycle/dry-run-contract",
    "/api/workflows/sql-server/deployment-contract",
];

fn is_requester_contract_path(path: &str) -> bool {
    REQUESTER_CONTRACT_PATHS.contains(&path)
}

fn is_requester_static_read_path(path: &str) -> bool {
    matches!(
        path,
        "/api/catalog"
            | "/api/catalog/approval-routes"
            | "/api/catalog/categories"
            | "/api/catalog/policy-guardrails"
            | "/api/metrics/series"
            | "/api/metrics/series/aggregated"
            | "/api/metrics/insights"
            | "/api/metrics/what-if"
            | "/api/metrics/budgets"
            | "/api/metrics/budgets/status"
            | "/api/metrics/commitment"
            | "/api/metrics/slo"
            | "/api/metrics/slo/status"
            | "/api/notifications"
            | "/api/notifications/unread-count"
    )
}

/// Requester-readable GETs are an explicit, closed set. Each dynamic member is
/// self-owned by repository/handler predicates; static catalog data contains no
/// tenant/provider inventory. New routes therefore default to `audit` instead
/// of silently inheriting Requester visibility.
fn is_requester_read_path(path: &str) -> bool {
    if path == "/api/requests"
        || path == "/api/auth/local/roles"
        || path == "/api/auth/local/me"
        || path == "/api/auth/local/decision"
        || path == "/api/me"
        || path == "/api/me/preferences"
        || is_requester_static_read_path(path)
        || is_notifications_self_service_path(path)
        || path == "/api/events"
        || path == "/api/operations/failure-patterns"
        || path == "/api/operations/knowledge-suggestion-readiness"
        || path == "/api/observe/monitoring-review-queue"
        || is_requester_contract_path(path)
    {
        return true;
    }

    let Some(rest) = path.strip_prefix("/api/requests/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let Some(request_id) = segments.next() else {
        return false;
    };
    if request_id.is_empty() {
        return false;
    }
    matches!(
        (segments.next(), segments.next()),
        (None, None) | (Some("policy-eval" | "execution-job"), None)
    )
}

/// Resolves the permission required to READ (safe method) a path. Reuse of
/// `route_permission_for` is wrong for reads because mutation and read actions
/// intentionally differ. Sensitive prefixes and the exact persisted network-
/// readiness data paths require `admin`, operator working data requires
/// `execute`, the closed self-owned/static set above is `request`, and every
/// unclassified read fails closed to `audit`.
/// The shift queue (`/api/ops/shift/...`) is OPERATOR working data: every per-item
/// read (summary/handover/my-items/stale/items) carries open-item descriptions +
/// assignees, so it requires the `execute` (operator) tier — NOT the ordinary
/// `audit` read tier that safe-method reads default to (a wedged auth gap: GETs use
/// `read_permission_for`, and `route_permission_for`'s `/api/ops`→`execute` mapping
/// applies only to UNSAFE methods). Without this, an `audit`/`request`-tier
/// principal could read the whole operator queue. The static `/api/ops/shift-contract`
/// advertisement (not under `/shift/`) stays ordinary-readable. `admin` satisfies it
/// via the check_permission superuser rule.
fn is_execute_read_path(path: &str) -> bool {
    path == "/api/ops/shift"
        || path.starts_with("/api/ops/shift/")
        || path == "/api/ops/scheduler/schedules"
        || path == "/api/ops/scheduler/executions"
}

fn is_approve_read_path(path: &str) -> bool {
    path == "/api/approvals/pending"
}

/// Persisted network-readiness data remains admin-only until a dedicated
/// network-inventory capability exists. Match exact data paths so the static,
/// redacted contract advertisement remains ordinary Requester-readable.
fn is_network_inventory_read_path(path: &str) -> bool {
    matches!(
        path,
        "/api/datacenter/network/readiness"
            | "/api/datacenter/network/capacity"
            | "/api/datacenter/network/ports"
            | "/api/datacenter/network/vlans"
    )
}

fn read_permission_for(path: &str) -> &'static str {
    if is_approve_read_path(path) {
        return "approve";
    }
    if is_execute_read_path(path) {
        return "execute";
    }
    if is_network_inventory_read_path(path) {
        return "admin";
    }
    let sensitive = SENSITIVE_READ_PREFIXES
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")));
    if sensitive {
        "admin"
    } else if is_requester_read_path(path) {
        "request"
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
            && (path.ends_with("/audit")
                || path.ends_with("/evidence")
                // The approval ledger + quorum reads are audit-grade (approver
                // identities/decisions/reasons), like the per-request audit trail —
                // their handlers check `audit`, so the central gate must too (else a
                // `request`-only Requester passes the gate and is only stopped by the
                // handler — a defense-in-depth gap).
                || path.ends_with("/approval-decisions")
                || path.ends_with("/approval-quorum")))
}

/// Whether `session` may read `path`. Requester access exists only for the
/// closed self-owned/static set classified as `request`; all unclassified reads
/// require `audit`. `admin` satisfies every class through the superuser rule.
fn read_authorized(session: &AuthSession, path: &str) -> bool {
    if is_audit_read_path(path) {
        return ryuki_engine::auth::check_permission(session, "audit");
    }
    match read_permission_for(path) {
        "admin" => ryuki_engine::auth::check_permission(session, "admin"),
        "approve" => ryuki_engine::auth::check_permission(session, "approve"),
        // Operator-data reads (the shift queue) require `execute` — admin still
        // satisfies it via the superuser rule inside check_permission.
        "execute" => ryuki_engine::auth::check_permission(session, "execute"),
        "request" => {
            ryuki_engine::auth::check_permission(session, "audit")
                || ryuki_engine::auth::check_permission(session, "request")
        }
        _ => ryuki_engine::auth::check_permission(session, "audit"),
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

/// The user's own scope-preferences endpoint (#59) is self-service: the PUT is
/// authorized at the ordinary read tier (`audit` OR `request`) rather than the
/// fail-closed `admin` default, because every authenticated user holds one of
/// those tiers and the handler's keying on the typed `session.principal_id` (never
/// a client-supplied id) is the real authorization boundary — exactly like the
/// notifications self-service mutations. Scoped to the exact path so nothing
/// else is affected.
fn is_user_preferences_path(path: &str) -> bool {
    path == "/api/me/preferences"
}

/// Whether a MUTATION is a self-service action gated at the read tier (audit OR
/// request) rather than the fail-closed admin default. Method-AND-path exact:
/// notification mark-read, and PUT of the user's own preferences. Anything else
/// (a different method on the preferences path, a deeper path) falls through to
/// the ordinary mutation gate.
fn is_self_service_mutation(method: &Method, path: &str) -> bool {
    if !is_unsafe_method(method) {
        return false;
    }
    is_notifications_self_service_path(path)
        || (*method == Method::PUT && is_user_preferences_path(path))
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
    State(authenticator_runtime): State<Arc<authenticator_runtime::ApiAuthenticatorRuntime>>,
    headers: HeaderMap,
    mut request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    let method = request.method().clone();
    let method_label = metrics_method_label(&method);
    let path = request.uri().path().to_string();
    let route = request_route_label(&request);
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    let app_config = crate::config_store::get_app_config();
    let cookie_runtime = crate::config_store::get_api_cookie_runtime();
    let session_auth_parser = cookie_runtime.session_auth_parser();
    let session_credentials = authenticator_runtime.derived_session_credentials();
    let auth_mode = authenticator_runtime.auth_mode().clone();
    let log = resolve_auth_metadata(auth_header, auth_mode.as_str());
    let lookup_admission = crate::session_lookup_admission::global_admission();
    let lookup_proof = request
        .extensions()
        .get::<crate::session_lookup_admission::SessionLookupAdmissionProof>()
        .copied();
    let session_origin_authority =
        match crate::session_lookup_admission::SessionLookupOriginAuthority::from_runtime(
            &authenticator_runtime,
        ) {
            Ok(authority) => authority,
            Err(reason) => {
                tracing::error!(reason, "persisted-session origin authority is unavailable");
                return auth_required_response();
            }
        };

    // Logout owns its caller-credential delete/audit transaction in the
    // handler and is auth-exempt specifically so expired sessions can be
    // cleared. Do not duplicate that keyed database access here. Every other
    // route resolves persisted DB sessions first; only the None fallback runs
    // validator-aware resolution.
    let (session, session_source, failure_reason, interactive_authority, request_read_authority) =
        if matches!(path.as_str(), "/api/auth/logout" | "/api/auth/local/logout") {
            (
                unverified_session("logout-self-revocation"),
                None,
                None,
                None,
                None,
            )
        } else {
            match auth_session_from_persisted_session_with_authority_admission(
                &headers,
                auth_header,
                lookup_proof,
                PersistedSessionResolutionContext {
                    config: app_config,
                    admission: &lookup_admission,
                    session_parser: &session_auth_parser,
                    session_credentials: session_credentials.as_ref(),
                    origin_authority: &session_origin_authority,
                },
            )
            .await
            {
                Some((session, source, authority, request_read)) => {
                    (session, Some(source), None, authority, request_read)
                }
                None => {
                    let entra_bearer_validator = authenticator_runtime.entra_bearer_validator();
                    let (validated, reason, direct_credential, verified_identity) =
                        resolve_request_session(
                            auth_mode.clone(),
                            auth_header,
                            entra_bearer_validator.as_ref(),
                        )
                        .await;
                    if auth_mode == AuthMode::EntraId
                        && validated.token_valid
                        && !matches!(
                            validated.actor_class,
                            ryuki_engine::auth::ActorClass::VerifiedHuman
                        )
                    {
                        tracing::warn!(
                            actor_class = ?validated.actor_class,
                            "validated Entra bearer is not a delegated human token"
                        );
                        (
                            unverified_session("entra-id-actor-kind-rejected"),
                            None,
                            Some("actor-kind-rejected"),
                            None,
                            None,
                        )
                    } else if auth_mode == AuthMode::EntraId && validated.token_valid {
                        let verified_runtime_binding =
                            authenticator_runtime.verified_entra_runtime_binding();
                        let normalized = if authenticator_runtime
                            .retains_verified_entra_runtime_binding(&verified_runtime_binding)
                        {
                            if let (Some(pool), Some(runtime_binding), Some(identity)) = (
                                crate::database::get_db(),
                                verified_runtime_binding.as_ref(),
                                verified_identity.as_ref(),
                            ) {
                                crate::identity_authority::admit_federated_bearer(
                                    pool,
                                    runtime_binding,
                                    identity,
                                )
                                .await
                            } else {
                                Err(crate::identity_authority::IdentityAuthorityError::AssertionRejected)
                            }
                        } else {
                            Err(crate::identity_authority::IdentityAuthorityError::AssertionRejected)
                        };
                        match normalized {
                            Ok(admitted) => {
                                let request_read = direct_credential.and_then(|credential| {
                                    match direct_request_read_authority(&admitted, credential) {
                                        Ok(authority) => Some(authority),
                                        Err(error) => {
                                            tracing::warn!(reason = %error, "direct bearer has no request-read authority");
                                            None
                                        }
                                    }
                                });
                                (
                                    admitted.session,
                                    None,
                                    None,
                                    Some(admitted.authority),
                                    request_read,
                                )
                            }
                            Err(error) => {
                                tracing::warn!(reason = %error, "verified bearer has no active platform authority assignment");
                                (
                                    unverified_session("entra-id-authority-rejected"),
                                    None,
                                    Some("authority-rejected"),
                                    None,
                                    None,
                                )
                            }
                        }
                    } else {
                        let request_read = if matches!(
                            auth_mode,
                            AuthMode::MockDryRun | AuthMode::StaticDryRun
                        ) {
                            match development_request_read_authority(&validated, &auth_mode) {
                                Ok(authority) => Some(authority),
                                Err(error) => {
                                    tracing::warn!(reason = %error, "development fixture has no request-read authority");
                                    None
                                }
                            }
                        } else {
                            None
                        };
                        (validated, None, reason, None, request_read)
                    }
                }
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
        // Self-service mutations (notification mark-read, the user's own scope
        // preferences) are gated like reads (audit OR request), not as ordinary
        // mutations (which would fall to the admin default); the handler's keying
        // on the verified session.principal_id is the real boundary.
        let self_service = is_self_service_mutation(&method, &path);
        let operation_capability = if !self_service {
            operation_capability_for(&method, &path)
        } else {
            None
        };
        let actor_requirement = if requires_verified_human_signoff(&method, &path) {
            Some("verified-human-signoff")
        } else if requires_global_verified_human_administration(&path) {
            Some("global-verified-human-administration")
        } else {
            None
        };
        let actor_authorized = match actor_requirement {
            Some("verified-human-signoff") => {
                interactive_authority_matches_session(&session, interactive_authority.as_ref())
            }
            Some("global-verified-human-administration") => {
                global_interactive_authority_matches_session(
                    &session,
                    interactive_authority.as_ref(),
                )
            }
            Some(_) => false,
            None => true,
        };
        let required = if actor_requirement == Some("global-verified-human-administration") {
            // These objects have platform-wide authority and no resource scope
            // that could narrow them. Require the admin role centrally for
            // both safe enumeration and unsafe lifecycle operations.
            "admin"
        } else if let Some(capability) = operation_capability {
            capability.as_str()
        } else if is_unsafe_method(&method) && !self_service {
            route_permission_for(&method, &path)
        } else {
            read_permission_for(&path)
        };
        // Mutations require the exact route permission; reads — and self-service
        // mutations — use the shared read_authorized tier (sensitive -> admin;
        // ordinary -> audit OR request) so a recipient can manage their own feed,
        // a user can set their own preferences, and a Requester can view their
        // own requests.
        let role_authorized = if actor_requirement == Some("global-verified-human-administration") {
            ryuki_engine::auth::check_permission(&session, required)
        } else if let Some(capability) = operation_capability {
            ryuki_engine::auth::check_operation_capability(&session, capability)
        } else if is_unsafe_method(&method) && !self_service {
            ryuki_engine::auth::check_permission(&session, required)
        } else {
            read_authorized(&session, &path)
        };
        let authorized = actor_authorized && role_authorized;
        if !authorized {
            let denied_requirement = if actor_authorized {
                required
            } else {
                actor_requirement.unwrap_or(required)
            };
            tracing::warn!(
                method = method_label,
                route = %route,
                required = denied_requirement,
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
                            "required": denied_requirement,
                        }),
                        outcome: "denied",
                    },
                )
                .await;
            }
            return forbidden(denied_requirement);
        }
    }

    if let Some(authority) = interactive_authority {
        request.extensions_mut().insert(authority);
    }
    if let Some(authority) = request_read_authority {
        request.extensions_mut().insert(authority);
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

    let method = metrics_method_label(request.method());
    let route = request_route_label(&request);
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        method,
        route = %route,
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
pub(crate) struct RequestId(pub(crate) String);

impl RequestId {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static START_TIME: OnceLock<Instant> = OnceLock::new();
static DRAINING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessStatus {
    Ready,
    ConfigInvalid,
    SecretProviderUnavailable,
    DatabaseUnavailable,
    MigrationsNotApplied,
    MigrationsFailed,
    DatabaseUnusable,
}

struct ReadinessProbeCache {
    latest: tokio::sync::RwLock<Option<(Instant, ReadinessStatus)>>,
    refresh_permit: tokio::sync::Semaphore,
}

static READINESS_PROBE_CACHE: OnceLock<ReadinessProbeCache> = OnceLock::new();
const READINESS_PROBE_CACHE_TTL: Duration = Duration::from_secs(2);
const READINESS_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

fn readiness_probe_cache() -> &'static ReadinessProbeCache {
    READINESS_PROBE_CACHE.get_or_init(|| ReadinessProbeCache {
        latest: tokio::sync::RwLock::new(None),
        refresh_permit: tokio::sync::Semaphore::new(1),
    })
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
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    let label = format!(
        "{} {}",
        metrics_method_label(request.method()),
        metrics_path_label(request.uri().path(), matched_path)
    );
    {
        let mut counts = lock_or_recover(&per_endpoint().counts);
        *counts.entry(label).or_insert(0) += 1;
    }
    next.run(request).await
}

fn metrics_method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::TRACE => "TRACE",
        _ => "OTHER",
    }
}

/// Returns a stable, bounded-cardinality route label for request telemetry.
///
/// A trusted Axum route template is preferred. Requests that did not match a
/// route collapse to a single label, so subject or resource identifiers from
/// attacker-controlled paths never enter logs or metrics.
fn request_route_label(request: &HttpRequest<Body>) -> String {
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    metrics_path_label(request.uri().path(), matched_path)
}

/// Produce a bounded-cardinality metrics label. A matched Axum route template
/// comes from the trusted router definition. Unmatched attacker-controlled
/// paths collapse into one label instead of becoming map/Prometheus keys.
fn metrics_path_label(request_path: &str, matched_path: Option<&str>) -> String {
    if let Some(template) = matched_path {
        return normalize_metrics_path(template);
    }
    match request_path {
        "/health" | "/ready" | "/metrics" => request_path.to_string(),
        _ => "/__unmatched__".into(),
    }
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

const REQUEST_DURATION_SAMPLE_CAPACITY: usize = 10_000;

/// Stores request durations in microseconds in a bounded ring buffer. Both
/// insertion and eviction are O(1), including after the buffer reaches its
/// steady-state capacity under sustained rejected traffic.
struct DurationTracker {
    durations: Mutex<VecDeque<u64>>,
}

static DURATION_TRACKER: OnceLock<DurationTracker> = OnceLock::new();

fn duration_tracker() -> &'static DurationTracker {
    DURATION_TRACKER.get_or_init(|| DurationTracker {
        durations: Mutex::new(VecDeque::with_capacity(REQUEST_DURATION_SAMPLE_CAPACITY)),
    })
}

fn push_bounded_duration(durations: &mut VecDeque<u64>, duration_us: u64, capacity: usize) {
    if capacity == 0 {
        return;
    }
    if durations.len() >= capacity {
        durations.pop_front();
    }
    durations.push_back(duration_us);
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
    let method = metrics_method_label(request.method());
    let route = request_route_label(&request);
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();

    let response = next.run(request).await;
    let duration_us = start.elapsed().as_micros() as u64;
    let status = response.status();

    tracing::info!(
        method,
        route = %route,
        status = status.as_u16(),
        duration_us,
        request_id = %request_id,
        "access"
    );

    let tracker = duration_tracker();
    let mut durations = lock_or_recover(&tracker.durations);
    push_bounded_duration(
        &mut durations,
        duration_us,
        REQUEST_DURATION_SAMPLE_CAPACITY,
    );

    response
}

type SharedRateLimiter = Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>;

#[derive(Clone)]
struct RateLimiters {
    default: SharedRateLimiter,
    path_overrides: Arc<HashMap<String, SharedRateLimiter>>,
    /// Per-process unpredictable salt prevents a client from calculating which
    /// bounded quota bucket another identity occupies.
    bucket_salt: [u8; 32],
    /// Peers matching one of these networks may speak for their clients via
    /// X-Forwarded-For; everyone else is keyed on their own peer address.
    trusted_proxies: Arc<Vec<TrustedProxyNetwork>>,
}

impl RateLimiters {
    fn for_path_group(&self, path_group: &str) -> &SharedRateLimiter {
        self.path_overrides.get(path_group).unwrap_or(&self.default)
    }

    fn retain_recent(&self) {
        self.default.retain_recent();
        for limiter in self.path_overrides.values() {
            limiter.retain_recent();
        }
    }

    #[cfg(test)]
    fn has_override(&self, path_group: &str) -> bool {
        self.path_overrides.contains_key(path_group)
    }
}

type SharedRateLimiters = Arc<RateLimiters>;

fn spawn_rate_limit_maintenance(limiters: SharedRateLimiters) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let limiters = limiters.clone();
            if let Err(error) = tokio::task::spawn_blocking(move || limiters.retain_recent()).await
            {
                tracing::error!(error = %error, "rate-limit state maintenance failed");
            }
        }
    });
}

/// How the rate-limit client key was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientKeySource {
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
pub(crate) fn resolve_rate_limit_client_key(
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

    // X-Forwarded-For is security admission input, not an arbitrary identity
    // label. Validate the complete, bounded chain before trusting any hop so a
    // malformed or excessively long prefix cannot rotate limiter buckets.
    if forwarded_for.is_empty() || forwarded_for.len() > MAX_FORWARDED_FOR_BYTES {
        return peer_key();
    }
    let mut hop_count = 0_usize;
    for entry in forwarded_for.split(',') {
        let entry = entry.trim();
        hop_count += 1;
        if hop_count > MAX_FORWARDED_FOR_HOPS
            || entry.is_empty()
            || parse_forwarded_entry_ip(entry).is_none()
        {
            return peer_key();
        }
    }

    for entry in forwarded_for.rsplit(',') {
        let entry = entry.trim();
        let ip = parse_forwarded_entry_ip(entry)
            .expect("the complete forwarded chain was validated above")
            .to_canonical();
        if is_trusted(ip) {
            // a hop our own proxy tier appended; keep walking left
            continue;
        }
        return (ip.to_string(), ClientKeySource::Forwarded);
    }
    peer_key()
}

/// Maximum accepted wire size and hop count for one authoritative
/// X-Forwarded-For field. Duplicate fields are rejected by the header-aware
/// resolver below, preventing ambiguous concatenation/order semantics.
const MAX_FORWARDED_FOR_BYTES: usize = 4 * 1024;
const MAX_FORWARDED_FOR_HOPS: usize = 32;

/// Resolve a rate-limit identity from the full header map. Exactly one valid
/// X-Forwarded-For field is accepted; duplicate, non-ASCII, empty, malformed,
/// or oversized evidence fails safely to the TCP peer identity.
pub(crate) fn resolve_rate_limit_client_key_from_headers(
    peer_addr: SocketAddr,
    headers: &HeaderMap,
    trusted_proxies: &[TrustedProxyNetwork],
) -> (String, ClientKeySource) {
    let mut values = headers.get_all("x-forwarded-for").iter();
    let forwarded_for = match (values.next(), values.next()) {
        (None, _) => None,
        (Some(value), None) => value.to_str().ok(),
        (Some(_), Some(_)) => None,
    };
    resolve_rate_limit_client_key(peer_addr, forwarded_for, trusted_proxies)
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
        // error). When limiting is enabled, missing admission context fails
        // closed rather than silently bypassing the quota.
        let Some(ConnectInfo(peer_addr)) = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .copied()
        else {
            tracing::error!("peer address unavailable; rejecting rate-limited request");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::new(
                    "RATE_LIMIT_CONTEXT_UNAVAILABLE",
                    "Request admission context is unavailable",
                )),
            )
                .into_response();
        };

        let (client_key, key_source) = resolve_rate_limit_client_key_from_headers(
            peer_addr,
            request.headers(),
            &limiters.trusted_proxies,
        );

        let path_group = rate_limit_path_group(request.uri().path());

        let key = bounded_rate_limit_key(path_group, &client_key, &limiters.bucket_salt);
        let limiter = limiters.for_path_group(path_group);

        if let Err(not_until) = limiter.check_key(&key) {
            tracing::warn!(
                bucket = %key,
                key_source = key_source.as_str(),
                path_group,
                "rate limit exceeded"
            );
            // #32: a 429 SHOULD carry Retry-After (RFC 9110 §10.2.3) so clients —
            // notably the polling execution agents — back off instead of hammering
            // the same bucket. Derive whole seconds from the governor NotUntil
            // (rounded down, min 1) so the hint tracks the real bucket refill.
            let retry_after_secs = not_until
                .wait_time_from(governor::clock::Clock::now(
                    &governor::clock::DefaultClock::default(),
                ))
                .as_secs()
                .max(1);
            let body =
                serde_json::to_string(&ApiError::new("RATE_LIMIT_EXCEEDED", "Too many requests"))
                    .unwrap_or_else(|_| {
                        r#"{"error":"RATE_LIMIT_EXCEEDED","message":"Too many requests"}"#.into()
                    });
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("content-type", "application/json")
                .header("retry-after", retry_after_secs.to_string())
                .body(Body::from(body))
                .unwrap();
        }
    }

    next.run(request).await
}

fn rate_limit_path_group(path: &str) -> &'static str {
    match path.split('/').nth(1).unwrap_or_default() {
        segment if segment.eq_ignore_ascii_case("api") => "api",
        segment if segment.eq_ignore_ascii_case("health") => "health",
        segment if segment.eq_ignore_ascii_case("ready") => "ready",
        segment if segment.eq_ignore_ascii_case("metrics") => "metrics",
        "" => "root",
        _ => "unmatched",
    }
}

/// Fixed number of pseudorandom client buckets per closed route group. This
/// bounds governor's keyed state even when an attacker controls forwarded
/// identifiers or rotates source addresses. Collisions intentionally share a
/// quota; the bucket count keeps that trade-off negligible for normal traffic.
const RATE_LIMIT_CLIENT_BUCKETS: u16 = 16_384;

pub(crate) fn bounded_rate_limit_key(
    path_group: &str,
    client_key: &str,
    salt: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update((client_key.len() as u64).to_be_bytes());
    hasher.update(client_key.as_bytes());
    let digest = hasher.finalize();
    let raw = u16::from_be_bytes([digest[0], digest[1]]);
    let bucket = raw % RATE_LIMIT_CLIENT_BUCKETS;
    format!("{path_group}:bucket-{bucket:04x}")
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
        bucket_salt: rand::random(),
        trusted_proxies: Arc::new(trusted_proxies),
    }))
}

async fn request_timeout_middleware(
    State(timeout): State<Duration>,
    request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    let route = request_route_label(&request);
    let method = metrics_method_label(request.method());
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|request_id| request_id.0.clone())
        .unwrap_or_default();
    let started = Instant::now();
    let timeout_secs = timeout.as_secs();
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_elapsed) => {
            tracing::warn!(
                request_id = %request_id,
                method,
                route = %route,
                timeout_secs,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "request timeout"
            );
            let body = serde_json::to_string(&ApiError::new(
                "REQUEST_TIMEOUT",
                format!("Request exceeded {}s timeout", timeout_secs),
            ))
            .unwrap_or_else(|_| {
                format!(
                    r#"{{"error":"REQUEST_TIMEOUT","message":"Request exceeded {}s timeout"}}"#,
                    timeout_secs
                )
            });
            Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }
    }
}

/// Shared whole-application concurrency budget. Anonymous local-login attempts
/// are deliberately excluded because their outer, non-queueing admission gate
/// already owns a small fixed budget that covers the complete handler lifetime:
/// verification, uniform failure delay, or successful session persistence and
/// response construction. Letting those requests also hold this semaphore
/// would allow the eight login slots to starve every unrelated route when the
/// global limit is eight or lower.
#[derive(Clone)]
struct GlobalConcurrencyAdmission {
    permits: Arc<tokio::sync::Semaphore>,
}

impl GlobalConcurrencyAdmission {
    fn new(max_concurrent_requests: usize) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(max_concurrent_requests)),
        }
    }
}

fn bypasses_global_concurrency_budget(request: &HttpRequest<Body>) -> bool {
    contracts::is_local_login_attempt(request.method(), request.uri().path())
        && request
            .extensions()
            .get::<contracts::LocalLoginAdmissionPermit>()
            .is_some()
}

async fn global_concurrency_middleware(
    State(admission): State<GlobalConcurrencyAdmission>,
    request: HttpRequest<Body>,
    next: middleware::Next,
) -> Response {
    if bypasses_global_concurrency_budget(&request) {
        return next.run(request).await;
    }

    // Do not turn a burst into an unbounded set of in-process semaphore
    // waiters. The request timeout would eventually cancel them, but retaining
    // every queued future until then is itself an availability risk.
    let Ok(_permit) = admission.permits.clone().try_acquire_owned() else {
        return problem_details(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Service temporarily unavailable",
            None::<String>,
        )
        .into_response();
    };

    next.run(request).await
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

/// The outer response envelope must wrap every path-aware admission and shared
/// transport limit. Keeping the two layers together prevents a future router
/// edit from making timeout, quota, or body-limit rejections uncorrelatable.
fn with_response_envelope(app: Router) -> Router {
    app.layer(middleware::from_fn(security_headers_middleware))
        .layer(middleware::from_fn(request_id_middleware))
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

struct SecretProviderMaintenanceTask {
    runtime: Arc<crate::secret_provider_runtime::VaultKubernetesRuntime>,
    shutdown: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<
        Result<(), crate::secret_provider_runtime::VaultKubernetesRuntimeError>,
    >,
}

impl SecretProviderMaintenanceTask {
    fn spawn(runtime: Arc<crate::secret_provider_runtime::VaultKubernetesRuntime>) -> Self {
        let (shutdown, mut receiver) = tokio::sync::watch::channel(false);
        let task_runtime = Arc::clone(&runtime);
        let join = tokio::spawn(async move {
            loop {
                if *receiver.borrow() {
                    break;
                }
                // A poisoned runtime state can request immediate maintenance.
                // Keep that failure mode bounded rather than spinning a core.
                let delay = task_runtime
                    .next_maintenance_delay()
                    .max(Duration::from_millis(100));
                tokio::select! {
                    changed = receiver.changed() => {
                        if changed.is_err() || *receiver.borrow() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(delay) => {
                        tokio::select! {
                            changed = receiver.changed() => {
                                if changed.is_err() || *receiver.borrow() {
                                    break;
                                }
                            }
                            result = task_runtime.maintenance_step() => {
                                if let Err(error) = result {
                                    tracing::warn!(error = %error, "secret-provider workload-auth maintenance failed");
                                }
                            }
                        }
                    }
                }
            }
            task_runtime.shutdown().await
        });
        Self {
            runtime,
            shutdown,
            join,
        }
    }

    async fn stop(mut self) -> Result<(), String> {
        // Runtime shutdown invalidates the bearer synchronously before its
        // first possible suspension point. Always signal and join/abort the
        // maintenance owner even if shutdown itself reports an error.
        let runtime_result =
            match tokio::time::timeout(Duration::from_secs(15), self.runtime.shutdown()).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(format!(
                    "secret-provider workload-auth shutdown failed: {error}"
                )),
                Err(_) => Err("secret-provider workload-auth shutdown timed out".into()),
            };
        let _ = self.shutdown.send(true);
        let join_result = match tokio::time::timeout(Duration::from_secs(5), &mut self.join).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(format!(
                "secret-provider workload-auth shutdown failed: {error}"
            )),
            Ok(Err(error)) => Err(format!(
                "secret-provider workload-auth maintenance task failed: {error}"
            )),
            Err(_) => {
                self.join.abort();
                let _ = self.join.await;
                Err("secret-provider workload-auth maintenance shutdown timed out".into())
            }
        };
        match (runtime_result, join_result) {
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

// ─── Hidden docs-extraction flag (`ryuki-api --dump-route-meta`) ────────────
//
// Maintenance subcommand used by `ryuki-validator generate-api-doc`; it is
// NOT part of the served API surface (no route, absent from the OpenAPI
// document) and exits before config/logging/DB/server startup.
//
// Input  (stdin):  JSON array of {"path": "...", "method": "..."} route keys.
// Output (stdout): one JSON envelope:
//   {"meta":    [{"path","method","tier","auth_exempt"}, ...],
//    "openapi": <openapi::openapi_document()>}
//
// Human tiers call the same functions the auth middleware runs
// (`is_auth_exempt_path`, `is_self_service_mutation`, `route_permission_for`,
// `is_audit_read_path`, `read_permission_for`). The effective metadata also
// accounts for sibling agent/webhook routers and exact handler-level admin
// guards. The `openapi` half carries the curated public/agent-protocol spec
// verbatim so the docs site can publish it as machine-readable JSON.

#[derive(serde::Deserialize)]
struct RouteMetaKey {
    path: String,
    method: String,
}

#[derive(serde::Serialize)]
struct RouteMetaEntry {
    path: String,
    method: String,
    tier: Option<&'static str>,
    auth_exempt: bool,
}

/// The effective access class for one (method, path) route, following the
/// human middleware, sibling-router topology, and explicit handler gates:
///
/// * `public`  — auth-exempt (reachable without a session);
/// * `agent` / `webhook` — bypass human sessions but require their named
///   protocol credential;
/// * integration management — explicit handler-level `admin` guards;
/// * functional reads and mutations — `operation_capability_for` (a stable
///   dotted capability id) before any coarse route tier;
/// * remaining mutations — `route_permission_for`
///   (admin/approve/execute/request/...), unless the mutation is self-service
///   (gated like a read);
/// * audit-grade reads — `audit` specifically;
/// * remaining reads/self-service — the exact closed `read_permission_for`
///   class (`request`, `audit`, `approve`, `execute`, or `admin`).
///
/// Returns `None` only for a method the HTTP layer cannot parse or the
/// synthetic `ANY` placeholder, where enforcement is method-dependent and
/// cannot be attested.
fn route_meta_tier(method_str: &str, path: &str) -> Option<&'static str> {
    if method_str.eq_ignore_ascii_case("any") {
        return None;
    }
    let method: Method = method_str.parse().ok()?;
    if is_auth_exempt_path(path) {
        return Some("public");
    }
    // The agent subrouter under /api/agents/ bypasses the human auth_middleware
    // entirely. Its enrolment/bootstrap endpoints are open (no token yet by
    // definition): register mints the first token, and the CP public key and
    // agent-facing OpenAPI spec are fetched before one exists. The rest
    // (poll/ack/heartbeat/result) carry the "rya_" agent bearer token,
    // validated inside each handler by `authenticate_agent`. /api/admin/agents/*
    // is a separate, human-gated prefix that falls through to the admin logic.
    if matches!(
        path,
        "/api/agents/register" | "/api/agents/cp-public-key" | "/api/agents/openapi.json"
    ) {
        return Some("public");
    }
    if path.starts_with("/api/agents/") {
        return Some("agent");
    }
    if method == Method::POST && path == "/api/integrations/{connection_id}/webhook" {
        return Some("webhook");
    }
    // The separately mounted integration connection-management router is an
    // exact 16-operation admin surface. Keep this method-and-template matcher
    // deliberately closed: contracts.rs also owns unrelated routes below
    // /api/integrations, which retain their ordinary runtime classification.
    if is_integration_management_route(&method, path) {
        return Some("admin");
    }
    let self_service = is_self_service_mutation(&method, path);
    if !self_service {
        if let Some(capability) = operation_capability_for(&method, path) {
            return Some(capability.as_str());
        }
    }
    if is_unsafe_method(&method) && !self_service {
        return Some(route_permission_for(&method, path));
    }
    if is_audit_read_path(path) {
        return Some("audit");
    }
    Some(match read_permission_for(path) {
        "admin" => "admin",
        "approve" => "approve",
        "execute" => "execute",
        "request" => "request",
        _ => "audit",
    })
}

fn is_integration_management_route(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::POST, "/api/integrations")
            | (&Method::GET, "/api/integrations")
            | (&Method::GET, "/api/integrations/{id}")
            | (&Method::PUT, "/api/integrations/{id}")
            | (&Method::DELETE, "/api/integrations/{id}")
            | (&Method::POST, "/api/integrations/{id}/webhook-secret")
            | (&Method::POST, "/api/integrations/{id}/test")
            | (&Method::GET, "/api/integrations/{id}/health")
            | (&Method::POST, "/api/integrations/{id}/credential-expiry")
            | (&Method::GET, "/api/integrations/credentials/expiring")
            | (&Method::GET, "/api/integrations/circuits")
            | (&Method::GET, "/api/integrations/{id}/circuit")
            | (&Method::POST, "/api/integrations/{id}/circuit/record")
            | (&Method::POST, "/api/integrations/{id}/circuit/reset")
            | (&Method::GET, "/api/integrations/capabilities")
            | (&Method::GET, "/api/integrations/capabilities/{vendor_type}")
    )
}

/// Builds the `--dump-route-meta` JSON envelope from the stdin payload.
/// Pure (no IO) so it is unit-testable.
fn dump_route_meta(input: &str) -> Result<String, String> {
    let routes: Vec<RouteMetaKey> = serde_json::from_str(input).map_err(|error| {
        format!(
            "--dump-route-meta expects a JSON array of {{path,method}} objects on stdin: {error}"
        )
    })?;
    let meta: Vec<RouteMetaEntry> = routes
        .into_iter()
        .map(|key| {
            let tier = route_meta_tier(&key.method, &key.path);
            RouteMetaEntry {
                // `auth_exempt` means no authentication at all, not merely
                // bypassing HUMAN session middleware. Agent/webhook tiers use
                // their own required credentials and therefore stay false.
                auth_exempt: tier == Some("public"),
                tier,
                path: key.path,
                method: key.method,
            }
        })
        .collect();
    let envelope = serde_json::json!({
        "meta": meta,
        "openapi": openapi::openapi_document(),
    });
    serde_json::to_string(&envelope)
        .map_err(|error| format!("failed to serialize route meta: {error}"))
}

#[tokio::main]
async fn main() {
    // Hidden maintenance flag (see `dump_route_meta` above): answer and exit
    // BEFORE config/logging/DB/server startup so it works in a bare checkout.
    if std::env::args().nth(1).as_deref() == Some("--dump-route-meta") {
        let mut input = String::new();
        if let Err(error) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input) {
            eprintln!("failed to read stdin: {error}");
            std::process::exit(2);
        }
        match dump_route_meta(&input) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    // Every serving and migration process admits one independently pinned,
    // content-addressed deployment security root before it can touch database
    // configuration, signing keys, workers, routers, or listener state. The
    // route-metadata maintenance mode above is intentionally read-only and is
    // the sole configuration-free exception.
    let security_pins =
        security_contracts::StartupSecurityPins::from_environment().unwrap_or_else(|error| {
            eprintln!("security contract preflight failed: {error}");
            std::process::exit(1);
        });
    let mut security_contract =
        security_contracts::load_startup_security_contract_for_serving(&security_pins)
            .await
            .unwrap_or_else(|error| {
                eprintln!("security contract preflight failed: {error}");
                std::process::exit(1);
            });

    let migration_mode = database::migration_startup_mode_from_env().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });
    if security_contract.is_production()
        && migration_mode == database::MigrationStartupMode::LocalAuto
    {
        eprintln!(
            "production rejects local-auto migrations; use the isolated apply-only job and verify-only serving mode"
        );
        std::process::exit(1);
    }
    if !migration_mode.serves_http() {
        // Apply-only intentionally does not load the API configuration needed
        // by serving guards. Production instead validates a narrower one-shot
        // prerequisite derived from the sealed DurablePostgresql requirement.
        // The returned one-shot capability retains the independently pinned
        // PostgreSQL-infrastructure authority and cannot release DDL authority
        // until that authority authenticates the exact connected target and
        // durable-storage binding. This path can never publish an application
        // pool, initialize workers, build a router, or serve.
        let migration_admission = security_contract
            .into_apply_only_migration_admission(migration_mode, &security_pins, chrono::Utc::now())
            .unwrap_or_else(|error| {
                eprintln!("migration admission failed: {error}");
                std::process::exit(1);
            });
        // The one-shot runner intentionally stops here: it does not load
        // application/auth/provider configuration, initialize the normal pool,
        // reconcile identity state, spawn background work, or bind a listener.
        // Kubernetes injects a separate migrator credential into this process.
        let migration_url = database::migration_database_url_from_env().unwrap_or_else(|error| {
            eprintln!("{error}");
            std::process::exit(1);
        });
        let timeouts = database::MigrationTimeouts::from_env().unwrap_or_else(|error| {
            eprintln!("{error}");
            std::process::exit(1);
        });
        match database::apply_embedded_migrations_with_admission(
            &migration_url,
            timeouts,
            migration_admission,
        )
        .await
        {
            Ok(inventory) => {
                eprintln!(
                    "embedded migrations applied and verified (count={}, latest={:?}, inventory={})",
                    inventory.embedded_count, inventory.latest_version, inventory.content_digest,
                );
                if let Some(operation) = inventory.production_operation.as_ref() {
                    eprintln!(
                        "production migration operation confirmed (operation_id={}, reconciled_after_prior_attempt={})",
                        operation.operation_id(),
                        operation.reconciled_after_prior_attempt(),
                    );
                }
                if let Some(attestation) = inventory.production_attestation.as_ref() {
                    eprintln!(
                        "production migration attestation verified (authority={}, epoch={}, revision={}, profile={}, profile_version={}, profile_digest={}, measurement_sequence={}, response_digest={}, session_digest={}, database_digest={}, storage_digest={})",
                        attestation.authority_id(),
                        attestation.authority_epoch(),
                        attestation.authority_revision(),
                        attestation.attestation_profile_id(),
                        attestation.attestation_profile_version(),
                        attestation.attestation_profile_digest(),
                        attestation.measurement_sequence(),
                        attestation.response_digest(),
                        attestation.session_binding_digest(),
                        attestation.database_identity_digest(),
                        attestation.storage_binding_digest(),
                    );
                }
                return;
            }
            Err(error) => {
                eprintln!("migration apply-only process failed: {error}");
                std::process::exit(1);
            }
        }
    }

    security_contract
        .verify_https_public_urls_runtime_guard(&security_pins)
        .await
        .unwrap_or_else(|error| {
            eprintln!("https-public-urls runtime guard failed: {error}");
            std::process::exit(1);
        });

    let production = security_contract.is_production();
    let runtime_binding = security_contract
        .verified_secret_provider_runtime_binding()
        .unwrap_or_else(|error| {
            eprintln!("secret-provider runtime binding admission failed: {error}");
            std::process::exit(1);
        });
    let runtime_config =
        secret_provider_runtime::VaultKubernetesRuntimeConfig::from_environment(production)
            .unwrap_or_else(|error| {
                eprintln!("secret-provider workload-auth configuration failed: {error}");
                std::process::exit(1);
            });
    let fingerprint_keyring_path =
        secret_provider_runtime::fingerprint_keyring_path_from_environment(production)
            .unwrap_or_else(|error| {
                eprintln!("SecretRef fingerprint keyring configuration failed: {error}");
                std::process::exit(1);
            });
    let (app_config, api_secret_provider_runtime) =
        config::load_config(production).unwrap_or_else(|error| {
            eprintln!("{error}");
            std::process::exit(1);
        });
    if let Some(path) = fingerprint_keyring_path.as_deref() {
        api_secret_provider_runtime
            .bind_reference_fingerprint_keyring_from_file(path)
            .unwrap_or_else(|error| {
                eprintln!("SecretRef fingerprint keyring admission failed: {error}");
                std::process::exit(1);
            });
    }
    let vault_kubernetes_runtime = match (runtime_binding, runtime_config) {
        (Some(binding), Some(runtime_config)) => {
            let runtime = secret_provider_runtime::VaultKubernetesRuntime::from_config(
                runtime_config,
                Arc::clone(&binding),
            )
            .unwrap_or_else(|error| {
                eprintln!("secret-provider workload-auth runtime admission failed: {error}");
                std::process::exit(1);
            });
            api_secret_provider_runtime
                .bind_admitted_provider_identity(
                    binding.provider_id().to_string(),
                    binding.provider_configuration_version(),
                    binding.deployment_id().to_string(),
                    binding.trust_domain_id().to_string(),
                )
                .unwrap_or_else(|error| {
                    eprintln!("secret-provider identity binding failed: {error}");
                    std::process::exit(1);
                });
            api_secret_provider_runtime
                .bind_workload_runtime(Arc::clone(&runtime))
                .unwrap_or_else(|error| {
                    eprintln!("secret-provider workload runtime binding failed: {error}");
                    std::process::exit(1);
                });
            Some(runtime)
        }
        (None, None) if !production => None,
        _ => {
            eprintln!(
                "secret-provider runtime configuration and its verified binding must be present together"
            );
            std::process::exit(1);
        }
    };
    let api_cookie_runtime = cookie_runtime::ApiCookieRuntime::from_admitted_config(
        &app_config,
        security_contract.is_production(),
    )
    .unwrap_or_else(|error| {
        eprintln!("API cookie runtime admission failed: {error}");
        std::process::exit(1);
    });
    api_cookie_runtime
        .validate_config_binding(&app_config, security_contract.is_production())
        .unwrap_or_else(|error| {
            eprintln!("API cookie runtime binding failed: {error}");
            std::process::exit(1);
        });
    let entra_authenticator_authority_identity = if app_config.auth_mode == AuthMode::EntraId {
        Some(
            security_contract
                .resolved_entra_authenticator_authority(!app_config.entra_redirect_uri.is_empty())
                .unwrap_or_else(|error| {
                    eprintln!("Entra authenticator authority admission failed: {error}");
                    std::process::exit(1);
                }),
        )
    } else {
        None
    };
    let authenticator_bearer_limits_identity = entra_authenticator_authority_identity
        .as_ref()
        .map(|authority| Arc::clone(authority.bearer_limits()));
    let authenticator_browser_limits_identity = entra_authenticator_authority_identity
        .as_ref()
        .and_then(|authority| authority.browser_limits().map(Arc::clone));
    let api_authenticator_runtime =
        authenticator_runtime::ApiAuthenticatorRuntime::from_admitted_config(
            &app_config,
            Arc::clone(&api_cookie_runtime),
            entra_authenticator_authority_identity
                .as_ref()
                .map(Arc::clone),
            security_contract.is_production(),
        )
        .unwrap_or_else(|error| {
            eprintln!("API authenticator runtime admission failed: {error}");
            std::process::exit(1);
        });
    if security_contract.is_production() {
        api_authenticator_runtime
            .validate_production_posture()
            .unwrap_or_else(|error| {
                eprintln!("production authenticator posture failed: {error}");
                std::process::exit(1);
            });
    }
    security_contract
        .verify_non_development_authenticator_runtime_guard(&api_authenticator_runtime)
        .unwrap_or_else(|error| {
            eprintln!("non-development authenticator runtime guard failed: {error}");
            std::process::exit(1);
        });
    let authenticator_observation_identity =
        Arc::clone(api_authenticator_runtime.operational_observation());
    let retained_entra_authenticator_authority_identity =
        api_authenticator_runtime.entra_authenticator_authority();
    let entra_bearer_validator_identity = api_authenticator_runtime.entra_bearer_validator();
    let entra_bearer_observation_identity = api_authenticator_runtime.entra_bearer_observation();
    let derived_session_credentials_identity =
        api_authenticator_runtime.derived_session_credentials();
    let derived_session_observation_identity =
        api_authenticator_runtime.derived_session_observation();
    let verified_entra_runtime_binding_identity =
        api_authenticator_runtime.verified_entra_runtime_binding();
    let browser_authenticator_origin_identity =
        api_authenticator_runtime.browser_authenticator_origin();
    let oidc_callback_dependencies_identity =
        api_authenticator_runtime.oidc_callback_dependencies();
    let entra_sso_dependencies_identity = api_authenticator_runtime.entra_sso_dependencies();
    let entra_sso_handler_dependencies_identity =
        api_authenticator_runtime.entra_sso_handler_dependencies();
    let local_login_throttle_identity = api_authenticator_runtime.local_login_throttle();
    security_contract
        .verify_secure_cookie_runtime_guard(&api_cookie_runtime)
        .unwrap_or_else(|error| {
            eprintln!("secure-cookie runtime guard failed: {error}");
            std::process::exit(1);
        });
    if let Some(runtime) = &vault_kubernetes_runtime {
        security_contract
            .verify_approved_secret_provider_runtime_guard(runtime)
            .await
            .unwrap_or_else(|error| {
                eprintln!("approved-secret-provider runtime guard failed: {error}");
                std::process::exit(1);
            });
        if !api_secret_provider_runtime.is_live_resolution_ready()
            || !api_secret_provider_runtime.retains_workload_runtime(runtime)
        {
            eprintln!("secret-provider runtime was not retained by the typed API owner");
            std::process::exit(1);
        }
    }
    // Production constructs and independently attests the exact application-
    // serving PostgreSQL channel before the remaining runtime guards are
    // evaluated. Keep this allocation unpublished: only the future complete
    // eight-guard admission may consume it through `publish_after_admission`.
    // Naming the owner (instead of discarding the result) keeps the measured
    // relay and pool alive across the terminal remaining-guard check below.
    let unpublished_production_database = if security_contract.is_production() {
        Some(
            security_contract
                .verify_durable_postgresql_runtime_guard(&security_pins, &app_config)
                .await
                .unwrap_or_else(|error| {
                    eprintln!("durable-postgresql runtime guard failed: {error}");
                    std::process::exit(1);
                }),
        )
    } else {
        None
    };
    if let Some(unpublished) = unpublished_production_database.as_ref() {
        security_contract
            .verify_first_owner_path_closed_runtime_guard(&security_pins, unpublished)
            .await
            .unwrap_or_else(|error| {
                eprintln!("first-owner-path-closed runtime guard failed: {error}");
                std::process::exit(1);
            });
    }
    if let Err(error) = security_contract.validate_runtime_bindings(
        &app_config,
        std::env::var_os("RYUKI_AUTH_MODE").is_some(),
        chrono::Utc::now(),
    ) {
        // `process::exit` does not run destructors. Explicitly release both
        // owners of the unpublished relay/pool so failed production admission
        // cannot leave a live task or relay directory behind.
        drop(unpublished_production_database);
        drop(security_contract);
        eprintln!("security contract runtime binding failed: {error}");
        std::process::exit(1);
    }
    // The only production success path will obtain a database-publication
    // capability from the complete eight-witness aggregate. Until the final
    // three guards exist, the check above is terminal and this owner remains
    // deliberately unpublished.
    if unpublished_production_database.is_some() {
        eprintln!(
            "complete production runtime admission returned without database publication authority"
        );
        drop(unpublished_production_database);
        drop(security_contract);
        std::process::exit(1);
    }
    START_TIME.set(Instant::now()).ok();
    let api_cookie_runtime_identity = Arc::clone(&api_cookie_runtime);
    let api_authenticator_runtime_identity = Arc::clone(&api_authenticator_runtime);
    let api_secret_provider_runtime_identity = Arc::clone(&api_secret_provider_runtime);
    let vault_kubernetes_runtime_identity = vault_kubernetes_runtime.clone();
    config_store::init_with_security_contract(
        "platform-config.json",
        &app_config,
        security_contract,
        api_cookie_runtime,
        Arc::clone(&api_authenticator_runtime),
        api_secret_provider_runtime,
        vault_kubernetes_runtime.clone(),
    );
    if !Arc::ptr_eq(
        &api_cookie_runtime_identity,
        &config_store::get_api_cookie_runtime(),
    ) {
        eprintln!("API cookie runtime identity changed during startup retention");
        std::process::exit(1);
    }
    match (
        vault_kubernetes_runtime_identity.as_ref(),
        config_store::get_vault_kubernetes_runtime().as_ref(),
    ) {
        (Some(expected), Some(retained))
            if Arc::ptr_eq(expected, retained)
                && api_secret_provider_runtime_identity.retains_workload_runtime(retained)
                && config_store::get_security_contract_context()
                    .retains_approved_secret_provider_runtime(retained) => {}
        (None, None) => {}
        _ => {
            eprintln!("Vault Kubernetes runtime identity changed during startup retention");
            std::process::exit(1);
        }
    }
    if !Arc::ptr_eq(
        &api_secret_provider_runtime_identity,
        &config_store::get_api_secret_provider_runtime(),
    ) || !api_secret_provider_runtime_identity.is_bound_to_config(&app_config)
    {
        eprintln!("API secret-provider runtime identity changed during startup retention");
        std::process::exit(1);
    }
    if !Arc::ptr_eq(
        &api_authenticator_runtime_identity,
        &config_store::get_api_authenticator_runtime(),
    ) || !api_authenticator_runtime_identity
        .retains_cookie_runtime(&config_store::get_api_cookie_runtime())
        || !api_authenticator_runtime_identity
            .retains_operational_observation(&authenticator_observation_identity)
        || !api_authenticator_runtime_identity
            .retains_entra_authenticator_authority(&entra_authenticator_authority_identity)
        || !api_authenticator_runtime_identity
            .retains_entra_authenticator_authority(&retained_entra_authenticator_authority_identity)
        || !api_authenticator_runtime_identity
            .retains_authenticator_bearer_limits(&authenticator_bearer_limits_identity)
        || !api_authenticator_runtime_identity
            .retains_authenticator_browser_limits(&authenticator_browser_limits_identity)
        || !api_authenticator_runtime_identity
            .retains_entra_bearer_validator(&entra_bearer_validator_identity)
        || !api_authenticator_runtime_identity
            .retains_entra_bearer_observation(&entra_bearer_observation_identity)
        || !api_authenticator_runtime_identity.remeasures_entra_bearer_observation()
        || !api_authenticator_runtime_identity
            .retains_derived_session_credentials(&derived_session_credentials_identity)
        || !api_authenticator_runtime_identity
            .retains_derived_session_observation(&derived_session_observation_identity)
        || !api_authenticator_runtime_identity.remeasures_derived_session_observation()
        || !api_authenticator_runtime_identity
            .retains_verified_entra_runtime_binding(&verified_entra_runtime_binding_identity)
        || !api_authenticator_runtime_identity
            .retains_browser_authenticator_origin(&browser_authenticator_origin_identity)
        || !Arc::ptr_eq(
            &derived_session_credentials_identity,
            &config_store::get_derived_session_credentials(),
        )
        || !api_authenticator_runtime_identity
            .retains_oidc_callback_dependencies(&oidc_callback_dependencies_identity)
        || !api_authenticator_runtime_identity
            .retains_entra_sso_dependencies(&entra_sso_dependencies_identity)
        || !api_authenticator_runtime_identity
            .retains_entra_sso_handler_dependencies(&entra_sso_handler_dependencies_identity)
        || !oidc_callback_dependencies_identity
            .retains_session_credentials(&derived_session_credentials_identity)
        || !oidc_callback_dependencies_identity.retains_cookie_runtime(&api_cookie_runtime_identity)
        || !entra_sso_dependencies_identity
            .retains_session_credentials(&derived_session_credentials_identity)
        || !entra_sso_dependencies_identity.retains_cookie_runtime(&api_cookie_runtime_identity)
        || !entra_sso_dependencies_identity
            .retains_browser_limits(&authenticator_browser_limits_identity)
        || !api_authenticator_runtime_identity
            .retains_local_login_throttle(&local_login_throttle_identity)
    {
        eprintln!("API authenticator runtime identity changed during startup retention");
        std::process::exit(1);
    }
    let declared_entra_browser_path = entra_authenticator_authority_identity
        .as_ref()
        .is_some_and(|authority| authority.browser_path_id().is_some());
    if declared_entra_browser_path != browser_authenticator_origin_identity.is_some()
        || declared_entra_browser_path != entra_sso_handler_dependencies_identity.is_some()
    {
        eprintln!(
            "Entra browser routes require one exact retained runtime, origin, and handler authority"
        );
        std::process::exit(1);
    }
    match (
        app_config.auth_mode == AuthMode::EntraId,
        verified_entra_runtime_binding_identity.is_some(),
    ) {
        (true, true) | (false, false) => {}
        (true, false) => {
            eprintln!("Entra startup has no sealed authenticator runtime R");
            std::process::exit(1);
        }
        (false, true) => {
            eprintln!("non-Entra startup retained an Entra authenticator runtime R");
            std::process::exit(1);
        }
    }
    let session_lookup_admission =
        crate::session_lookup_admission::initialize_global(app_config.server.pool_max_connections);
    let session_lookup_middleware_state =
        crate::session_lookup_admission::SessionLookupAdmissionMiddlewareState::new(
            Arc::clone(&session_lookup_admission),
            Arc::clone(&api_authenticator_runtime),
        );
    if !session_lookup_middleware_state.retains_admission(&session_lookup_admission)
        || !session_lookup_middleware_state
            .retains_authenticator_runtime(&api_authenticator_runtime)
    {
        eprintln!("session lookup middleware state did not retain the admitted runtime graph");
        std::process::exit(1);
    }

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

    let admitted_security = config_store::get_security_contract_context();
    tracing::info!(
        deployment_id = %admitted_security.profile.deployment_id,
        security_profile = admitted_security.profile.security_profile.as_str(),
        profile_digest = %admitted_security.profile_digest,
        contract_root = %admitted_security.contract_root.display(),
        profile_path = %admitted_security.profile_path.display(),
        "deployment security contract admitted"
    );
    if app_config.auth_mode == AuthMode::Local {
        if !app_config.local_auth.users.is_empty() {
            if let Err(reason) = app_config.local_auth.human_authority() {
                tracing::error!(
                    reason,
                    "local_auth requires explicit valid site and environment authority"
                );
                std::process::exit(1);
            }
        }
        if let Some((entry_index, role)) = find_unknown_local_auth_role(&app_config.local_auth) {
            tracing::error!(
                entry_index,
                role = %role,
                "local_auth.users entry references a role outside the application role catalog"
            );
            std::process::exit(1);
        }
    }
    // Database verification, migration, and reconciliation are authority-
    // bearing startup operations. Do not begin them under an expired external
    // checkpoint, even though the listener has its own later freshness fence.
    config_store::get_security_contract_context()
        .validate_serving_checkpoint_freshness(chrono::Utc::now())
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "security checkpoint freshness fence failed before database startup");
            std::process::exit(1);
        });
    config_store::get_security_contract_context()
        .remeasure_durable_postgresql_runtime_guard(chrono::Utc::now())
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "durable-postgresql exact remeasurement failed before database startup");
            std::process::exit(1);
        });
    config_store::get_security_contract_context()
        .remeasure_first_owner_path_closed_runtime_guard(chrono::Utc::now())
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "first-owner-path-closed exact remeasurement failed before database startup");
            std::process::exit(1);
        });
    match migration_mode {
        database::MigrationStartupMode::VerifyOnly if production => {
            tracing::error!(
                "production reached database startup without complete eight-guard publication authority"
            );
            std::process::exit(1);
        }
        database::MigrationStartupMode::VerifyOnly => {
            let role_contract =
                database::ApplicationRoleContract::from_env().unwrap_or_else(|error| {
                    tracing::error!(%error, "invalid verify-only database role contract");
                    std::process::exit(1);
                });
            database::try_connect_with_role_contract(
                &app_config.database_url,
                app_config.server.pool_max_connections,
                app_config.server.pool_min_connections,
                app_config.server.pool_idle_timeout_secs,
                app_config.server.pool_acquire_timeout_secs,
                app_config.server.pool_max_lifetime_secs,
                role_contract,
            )
            .await;
        }
        database::MigrationStartupMode::LocalAuto => {
            // Local/test databases intentionally need no pre-provisioned roles.
            database::try_connect_with_url(
                &app_config.database_url,
                app_config.server.pool_max_connections,
                app_config.server.pool_min_connections,
                app_config.server.pool_idle_timeout_secs,
                app_config.server.pool_acquire_timeout_secs,
                app_config.server.pool_max_lifetime_secs,
            )
            .await;
        }
        database::MigrationStartupMode::ApplyOnly => {
            unreachable!("apply-only exits before application startup")
        }
    }
    match migration_mode {
        database::MigrationStartupMode::LocalAuto => {
            let timeouts = database::MigrationTimeouts::from_env().unwrap_or_else(|error| {
                tracing::error!(%error, "invalid dedicated migration-runner timeout configuration");
                std::process::exit(1);
            });
            if let Err(error) =
                database::migrate_if_connected(&app_config.database_url, timeouts).await
            {
                tracing::error!(
                    %error,
                    "local-auto migration failed on a connected database; refusing to serve"
                );
                std::process::exit(1);
            }
        }
        database::MigrationStartupMode::VerifyOnly => {
            let Some(pool) = database::get_db() else {
                tracing::error!(
                    "verify-only startup requires the application database connection; refusing to serve"
                );
                std::process::exit(1);
            };
            match database::verify_embedded_migrations(pool).await {
                Ok(inventory) => tracing::info!(
                    embedded_count = inventory.embedded_count,
                    latest_version = ?inventory.latest_version,
                    inventory_digest = %inventory.content_digest,
                    "verify-only startup accepted the complete embedded migration inventory"
                ),
                Err(error) => {
                    tracing::error!(
                        %error,
                        "verify-only startup rejected missing, dirty, unexpected, or modified migrations"
                    );
                    std::process::exit(1);
                }
            }
        }
        database::MigrationStartupMode::ApplyOnly => {
            unreachable!("apply-only exits before application startup")
        }
    }
    if !migration_mode
        .permits_serving_with(database::migration_status(), database::get_db().is_some())
    {
        tracing::error!(
            mode = %migration_mode,
            status = ?database::migration_status(),
            "migration startup policy refused HTTP serving"
        );
        std::process::exit(1);
    }

    // Reconcile identity authority before serving any request. Local account
    // password/role/removal/rollback changes advance a monotonic epoch. When
    // Local mode is disabled, its complete authority namespace is revoked.
    // Browser credentials are then reconciled by exact sealed authenticator
    // origin rather than ambient issuer/tenant labels, so a configuration
    // rollback cannot make an older D/P/Q/R/path generation current again.
    if let Some(pool) = crate::database::get_db() {
        let local_result = if app_config.auth_mode == AuthMode::Local {
            crate::identity_authority::reconcile_local_authorities(
                pool,
                &app_config.local_auth,
                derived_session_credentials_identity.as_ref(),
            )
            .await
        } else {
            let disabled_local_auth = ryuki_core::config::LocalAuthConfig::default();
            crate::identity_authority::reconcile_local_authorities(
                pool,
                &disabled_local_auth,
                derived_session_credentials_identity.as_ref(),
            )
            .await
        };
        if let Err(error) = local_result {
            tracing::error!(%error, "local identity-authority reconciliation failed");
            std::process::exit(1);
        }
        // Entra advances bearer and browser current-path pointers atomically
        // from one exact sealed R before any persisted-session prewarm or
        // listener publication. Browser-disabled state is an explicit durable
        // pointer anchored to that same bearer generation. Every non-Entra
        // mode durably disables external provider pointers so an Entra-to-local
        // rollback cannot leave a previous runtime active.
        match (
            app_config.auth_mode == AuthMode::EntraId,
            verified_entra_runtime_binding_identity.as_ref(),
        ) {
            (true, Some(runtime_binding)) => {
                if let Err(error) =
                    crate::identity_authority::reconcile_current_authenticator_runtime(
                        pool,
                        runtime_binding,
                    )
                    .await
                {
                    tracing::error!(%error, "current authenticator runtime reconciliation failed");
                    std::process::exit(1);
                }
                tracing::info!("current authenticator runtime reconciled");
            }
            (true, None) => {
                tracing::error!("Entra startup has no sealed authenticator runtime R");
                std::process::exit(1);
            }
            (false, None) => {
                if let Err(error) =
                    crate::identity_authority::disable_current_authenticator_runtimes(pool).await
                {
                    tracing::error!(%error, "external authenticator runtime disable failed");
                    std::process::exit(1);
                }
                tracing::info!("external authenticator runtimes disabled");
            }
            (false, Some(_)) => {
                tracing::error!("non-Entra startup retained an Entra authenticator runtime R");
                std::process::exit(1);
            }
        }
        match crate::session_lookup_admission::prewarm(pool, &api_authenticator_runtime_identity)
            .await
        {
            Ok(report) => tracing::info!(
                truncated = report.truncated,
                "persisted-session lookup admission prewarmed"
            ),
            Err(error) => {
                tracing::error!(%error, "persisted-session lookup admission prewarm failed");
                std::process::exit(1);
            }
        }
    }

    // ── Site registry startup hydration ──────────────────────────────────────
    //
    // Load the complete registry from the DB, including operator-defined codes.
    // This makes cross-engine reads (is_valid_site, get_active_site_codes)
    // reflect both persisted membership and active state after a restart.
    // Guard: only when a pool is available. Non-fatal on error.
    if let Some(pool) = crate::database::get_db() {
        match crate::repos::site_registry::list_all(pool).await {
            Ok(entries) => {
                let count = entries.len();
                for entry in entries {
                    let code_system = match entry.code_system.as_str() {
                        "unlocode" => ryuki_engine::site_registry::SiteCodeSystem::Unlocode,
                        "custom" => ryuki_engine::site_registry::SiteCodeSystem::Custom,
                        other => {
                            tracing::warn!(
                                code = %entry.unlocode,
                                code_system = %other,
                                "ignoring site registry entry with unsupported code system"
                            );
                            continue;
                        }
                    };
                    let site = ryuki_engine::site_registry::SiteEntry {
                        unlocode: entry.unlocode,
                        name: entry.name,
                        country: entry.country,
                        country_code: entry.country_code,
                        timezone: entry.timezone,
                        active: entry.active,
                    };
                    if let Err(error) = ryuki_engine::site_registry::upsert_site(site, code_system)
                    {
                        tracing::warn!(%error, "ignoring invalid persisted site registry entry");
                    }
                }
                tracing::info!(count, "site registry hydrated from DB");
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "site registry hydration failed — falling back to seed defaults"
                );
            }
        }
    }

    // ── DR plans startup hydration ────────────────────────────────────────────
    //
    // DR plans are persisted in the DB, but the engine's static store is still the
    // cross-domain read surface for test-run creation (start_test resolves a plan
    // from it). Replay the persisted plans into the static so DB-created plans
    // (and any that survived a restart) are visible to test-run creation.
    // Guard: only when a pool is available. Non-fatal on error.
    if let Some(pool) = crate::database::get_db() {
        match crate::repos::dr_plans::list(pool).await {
            Ok(plans) => {
                let count = plans.len();
                // DB-authoritative: REPLACE the store's seed plans with the DB set
                // (not upsert-on-top). seed_data() always seeds the demo plans into
                // the store, so an upsert-on-top hydration would resurrect a plan
                // DELETEd from the DB on the next restart. Replacing wholesale makes
                // the store mirror the DB exactly — a deleted plan stays gone.
                ryuki_engine::dr_testing::replace_plans(plans);
                tracing::info!(count, "dr plans hydrated from DB (store reconciled)");
            }
            Err(e) => {
                // FATAL: the DB is configured (the pool connected and migrations ran
                // at startup, so dr_plans exists) but the authoritative DR plan set
                // could not be loaded. We must NOT serve the DR surface in an unknown
                // state — neither stale seed plans (upsert-on-top would resurrect a
                // deleted plan) nor an empty store (which would misreport due-tests
                // and readiness as "0 due / fully ready"). Refuse to start so an
                // operator resolves the DB fault, matching the other fatal startup
                // conditions in this function.
                tracing::error!(
                    error = %e,
                    "FATAL: dr plans hydration failed in DB mode — refusing to start \
                     (cannot serve the DR surface without the authoritative plan set)"
                );
                std::process::exit(1);
            }
        }
    }

    // ── CP signing identity ───────────────────────────────────────────────────
    //
    // The control plane's Ed25519 keypair is used to sign `VerifiedLiveContext`
    // grants that authorise `LiveApply` jobs (S5a-2). The 32-byte raw seed is
    // persisted create-only at mode 0600. Only the deterministic non-secret key
    // id is logged; raw encoded key material is not copied into logs.
    {
        let key_path_str = std::env::var("RYUKI_CP_SIGNING_KEY_PATH")
            .unwrap_or_else(|_| "cp-signing.key".to_string());
        let key_path = std::path::Path::new(&key_path_str);
        match cp_identity::load_or_generate_cp_key(key_path) {
            Ok(key) => {
                let key_id = ryuki_protocol::control_plane_grant_key_id(&key.verifying_key());
                tracing::info!(
                    cp_signing_key_id = %key_id,
                    keyset_version = 1_u64,
                    key_path = %key_path_str,
                    "CP signing key loaded"
                );
                if let Err(error) = cp_identity::init_cp_key(key) {
                    tracing::error!(
                        error = %error,
                        "CP signing keyring initialization conflicted; refusing to start"
                    );
                    std::process::exit(1);
                }
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

    // Do not start serving-related background work under a checkpoint that
    // expired while database/configuration/key startup was in progress. The
    // listener boundary repeats this check after router construction.
    config_store::get_security_contract_context()
        .validate_serving_checkpoint_freshness(chrono::Utc::now())
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "security checkpoint freshness fence failed");
            std::process::exit(1);
        });
    config_store::get_security_contract_context()
        .remeasure_durable_postgresql_runtime_guard(chrono::Utc::now())
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "durable-postgresql exact remeasurement failed before worker startup");
            std::process::exit(1);
        });
    config_store::get_security_contract_context()
        .remeasure_first_owner_path_closed_runtime_guard(chrono::Utc::now())
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "first-owner-path-closed exact remeasurement failed before worker startup");
            std::process::exit(1);
        });

    // Spawn background sweeps (lease-expiry + idempotency retention). Only when
    // a DB pool is available. Both are idempotent and cancelled automatically
    // when the tokio runtime shuts down.
    if let Some(pool) = crate::database::get_db() {
        agents::spawn_lease_expiry_sweep(pool.clone(), 30);
        tracing::info!("agent lease expiry sweep started (interval: 30s)");
        idempotency::spawn_idempotency_sweep(pool.clone(), 3600);
        tracing::info!("idempotency retention sweep started (interval: 3600s)");
        // One 128-row batch per second drains faster than this process's
        // feature-local 50 req/s sustained webhook admission ceiling.
        repos::inbound_webhook_receipts::spawn_cleanup(pool.clone(), 1);
        tracing::info!("inbound webhook receipt cleanup started (interval: 1s)");
        repos::oidc_login_states::spawn_expired_login_state_cleanup(pool.clone(), 60);
        tracing::info!("OIDC login-state cleanup started (interval: 60s)");
        scheduler::spawn_scheduler(pool.clone(), 60);
        tracing::info!("durable scheduler started (tick interval: 60s)");
        audit::spawn_audit_verification_worker(pool.clone(), 5);
        tracing::info!("bounded audit-chain verification worker started (interval: 5s)");
        contracts::spawn_noise_site_reconciliation(pool.clone(), 1);
        tracing::info!(
            "bounded noisy-trigger site reconciliation started (interval: 1s, batch: 128)"
        );
        // #11 slice 2b: SLO-breach scan emits slo.breach/slo.recovered domain
        // events on transition (write-capable, so separate from the read-only
        // scheduler). 5-minute cadence — SLO windows are days, so sub-minute
        // checking adds no signal.
        contracts::spawn_slo_breach_scan(pool.clone(), 300);
        tracing::info!("slo-breach scan started (interval: 300s)");
        // #11 slice 2c: budget-breach scan emits budget.breach/budget.recovered
        // domain events on transition (write-capable, same posture as the SLO
        // scan). 5-minute cadence.
        contracts::spawn_budget_breach_scan(pool.clone(), 300);
        tracing::info!("budget-breach scan started (interval: 300s)");
        // #11 slice 2d: agent-offline scan emits agent.offline/agent.online on
        // transition. Scan every 60s; an approved agent unseen for >180s is
        // offline (agents heartbeat far more often than that).
        agents::spawn_agent_offline_scan(pool.clone(), 60, 180);
        tracing::info!("agent-offline scan started (interval: 60s, threshold: 180s)");
        // Portal-notifications retention: prunes expired feed rows (receipts +
        // dispatch-outbox rows cascade) in bounded oldest-first batches. Hourly,
        // like the idempotency retention sweep — retention windows are DAYS, so
        // sub-hour checking adds no signal, and the hourly 20k per-run cap
        // drains any first-run backlog quickly.
        contracts::spawn_notifications_retention_sweep(pool.clone(), 3600);
        tracing::info!("notifications retention sweep started (interval: 3600s)");
        // run-5/B: the wedge monitor turns the in-memory loop-liveness registry into
        // PUSHED, acknowledgeable `background_loop.overdue` domain events (edge-
        // triggered), so a silently-wedged scheduler/scan pages an operator instead of
        // only showing a 503 on /api/platform/health/loops. Spawned LAST so every loop
        // it watches is already registering; independent of those loops (a wedged tick
        // cannot self-report), and itself a registered loop so the health probe is its
        // watchdog-of-watchdog. 60s cadence — overdue thresholds are >=660s.
        crate::background::spawn_loop_monitor(pool.clone(), 60);
        tracing::info!("background-loop wedge monitor started (interval: 60s)");
    }

    let rate_limiter = create_rate_limiter(&app_config.rate_limit);
    if let Some(limiters) = rate_limiter.clone() {
        spawn_rate_limit_maintenance(limiters);
    }
    // Feature-specific anonymous gates remain enabled even when the general
    // limiter above is disabled. Reuse only validated trusted-proxy networks so
    // each per-client budget derives the same non-spoofable source identity.
    let anonymous_admission_trusted_proxies = app_config
        .rate_limit
        .parsed_trusted_proxies()
        .unwrap_or_else(|error| {
            // load_config validation normally makes this unreachable. Empty is
            // fail-safe: no peer may then assert X-Forwarded-For identity.
            tracing::error!(%error, "invalid anonymous-admission trusted-proxy configuration");
            Vec::new()
        });
    let webhook_admission =
        inbound_webhooks::WebhookAdmission::production(anonymous_admission_trusted_proxies.clone());
    webhook_admission.spawn_maintenance();
    let agent_registration_admission =
        agents::AgentRegistrationAdmission::production(anonymous_admission_trusted_proxies);
    // The exact human-authenticator allocations were built and retained before
    // the general production runtime-binding fence. Router consumers receive
    // only Arc clones originating from that immutable owner.
    let local_login_throttle = local_login_throttle_identity;

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
    let human_gated_app = build_human_gated_routes()
        // Idempotency runs INSIDE auth (auth gates first, then this), so an
        // unauthorized request never claims a key. Opt-in per request via the
        // Idempotency-Key header; no header / no DB → pass-through (unchanged).
        .layer(middleware::from_fn(idempotency::idempotency_middleware))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&api_authenticator_runtime),
            auth_middleware,
        ));

    let app = Router::new()
        // Infra probes only — must never 401 (were exempt via is_auth_exempt_path).
        .route("/health", get(health))
        .route("/ready", get(ready))
        // Agent-token endpoints bypass human auth_middleware entirely (they
        // authenticate via authenticate_agent / the rya_ bearer token).
        .merge(agents::agent_routes())
        // The inbound receiver is public and bypasses human auth, but requires a
        // fresh, connection-bound signed delivery envelope. A path-aware layer
        // outside the shared concurrency budget owns its always-on
        // per-client/global/in-flight gate; the optional general limiter remains
        // defense in depth.
        .merge(inbound_webhooks::routes())
        // Human-session routes (includes admin_approve + all existing routes).
        .merge(human_gated_app)
        .fallback(not_found)
        .layer(Extension(local_login_throttle.clone()))
        .layer(Extension(oidc_callback_dependencies_identity));
    // Entra handlers receive one post-seal wrapper that retains both their
    // measured dependency graph and exact browser origin. Never expose the
    // independently swappable base EntraSsoDeps as an Extension.
    let app = match entra_sso_handler_dependencies_identity {
        Some(handler) => app.layer(Extension(handler)),
        None => app.layer(middleware::from_fn(unavailable_entra_browser_routes)),
    };
    let app = app
        .layer(middleware::from_fn_with_state(
            GlobalConcurrencyAdmission::new(app_config.server.max_concurrent_connections),
            global_concurrency_middleware,
        ))
        .layer(middleware::from_fn(request_counter_middleware))
        .layer(middleware::from_fn(
            move |req: HttpRequest<Body>, next: middleware::Next| {
                let limiter = rate_limiter.clone();
                async move { rate_limit_middleware(limiter, req, next).await }
            },
        ))
        .layer(middleware::from_fn_with_state(
            Duration::from_secs(timeout_secs),
            request_timeout_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(body_limit))
        .layer(cors)
        .layer(compression)
        .layer(middleware::from_fn(cache_control_middleware))
        .layer(middleware::from_fn(timing_middleware))
        // Feature-local anonymous admission runs before telemetry, body polling,
        // the optional general limiter, and the fail-fast whole-app concurrency
        // layer. Non-matching paths pass through without consuming its budgets.
        .layer(middleware::from_fn_with_state(
            webhook_admission,
            inbound_webhooks::webhook_admission_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            agent_registration_admission,
            agents::agent_registration_admission_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            local_login_throttle,
            contracts::local_login_admission_middleware,
        ))
        .layer(middleware::from_fn(
            contracts::login_initiation_prequeue_middleware,
        ))
        // Persisted-session miss admission is outside the fail-fast whole-app
        // concurrency layer. Unknown verifiers use try-only capacity; recently
        // confirmed live sessions bypass the miss budget but are still checked
        // against PostgreSQL and the current authority epoch on every request.
        .layer(middleware::from_fn_with_state(
            session_lookup_middleware_state,
            session_lookup_admission::session_lookup_admission_middleware,
        ));
    // These two cheap wrappers remain outside every early-returning gate so
    // timeout, body-limit, rate-limit, and feature-admission responses all
    // carry the same security and correlation headers. RequestId must be
    // outermost so timeout/access middleware can read it from extensions.
    let app = with_response_envelope(app);

    // Startup work can outlive the authority's short checkpoint lease. Recheck
    // the immutable admitted proof at the final serving boundary so an expired
    // reconciliation can never be carried into a newly bound listener.
    config_store::get_security_contract_context()
        .validate_serving_checkpoint_freshness(chrono::Utc::now())
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "security checkpoint freshness fence failed");
            std::process::exit(1);
        });
    config_store::get_security_contract_context()
        .remeasure_durable_postgresql_runtime_guard(chrono::Utc::now())
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "durable-postgresql exact remeasurement failed before listener bind");
            std::process::exit(1);
        });
    config_store::get_security_contract_context()
        .remeasure_first_owner_path_closed_runtime_guard(chrono::Utc::now())
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "first-owner-path-closed exact remeasurement failed before listener bind");
            std::process::exit(1);
        });
    // The approved-secret-provider witness retains the exact initial lease Arc.
    // Start rotation only after the final pre-bind witness recheck; otherwise a
    // confirmation during lengthy startup could replace that Arc and invalidate
    // the immutable startup witness before serving begins.
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
    let secret_provider_maintenance_task = vault_kubernetes_runtime
        .as_ref()
        .map(|runtime| SecretProviderMaintenanceTask::spawn(Arc::clone(runtime)));
    tracing::info!("ryuki-api listening on {}", app_config.server.bind_address);
    // Connect info gives rate limiting a trustworthy peer address.
    let server_result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(app_config.server.shutdown_timeout_secs))
    .await;
    let maintenance_result = match secret_provider_maintenance_task {
        Some(task) => task.stop().await,
        None => Ok(()),
    };
    if let Err(error) = maintenance_result {
        tracing::error!(%error, "secret-provider workload-auth runtime did not stop cleanly");
        std::process::exit(1);
    }
    if let Err(e) = server_result {
        tracing::error!(error = %e, "server error");
        std::process::exit(1);
    }
}

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    let db_connected = crate::database::get_db().is_some();
    let app_config = crate::config_store::get_app_config();
    let config_valid = app_config.validate().is_empty();

    let healthy = db_connected && config_valid;
    let status = if healthy { "healthy" } else { "degraded" };
    tracing::info!(status, "health check result");

    public_health_response(healthy)
}

async fn ready() -> (StatusCode, Json<serde_json::Value>) {
    if is_draining() {
        return public_readiness_response(false);
    }

    let readiness_status = readiness_check().await;
    let result = readiness_response(readiness_status);
    let status = if readiness_status == ReadinessStatus::Ready {
        "ready"
    } else {
        "not_ready"
    };
    tracing::info!(status, "readiness check result");
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

    if crate::config_store::get_security_contract_context().is_production() {
        let api_runtime = crate::config_store::get_api_secret_provider_runtime();
        let Some(vault_runtime) = crate::config_store::get_vault_kubernetes_runtime() else {
            return ReadinessStatus::SecretProviderUnavailable;
        };
        if !api_runtime.is_live_resolution_ready() || !vault_runtime.readiness_snapshot().is_ready()
        {
            return ReadinessStatus::SecretProviderUnavailable;
        }
    }

    let Some(pool) = crate::database::get_db() else {
        return ReadinessStatus::DatabaseUnavailable;
    };

    let status = readiness_status_for_pool_state(true, crate::database::migration_status());
    if status != ReadinessStatus::Ready {
        return status;
    }

    cached_database_readiness(pool).await
}

async fn cached_database_readiness(pool: &sqlx::PgPool) -> ReadinessStatus {
    let cache = readiness_probe_cache();
    if let Some(status) = fresh_readiness_snapshot(*cache.latest.read().await) {
        return status;
    }

    // Do not queue unauthenticated readiness callers behind the DB pool. One
    // request refreshes the snapshot; concurrent callers reuse the last value
    // or fail closed when no snapshot exists yet.
    let Ok(_permit) = cache.refresh_permit.try_acquire() else {
        return fresh_readiness_snapshot(*cache.latest.read().await)
            .unwrap_or(ReadinessStatus::DatabaseUnusable);
    };

    // A request may have waited between the first cache read and acquiring the
    // permit. Reuse a fresh value before touching the database.
    if let Some(status) = fresh_readiness_snapshot(*cache.latest.read().await) {
        return status;
    }

    // Never enter the pool's async waiter queue on behalf of a public probe.
    // A saturated pool is itself a not-ready signal; cache that fail-closed
    // result rather than competing with authenticated application work for the
    // next released connection.
    let status = match try_readiness_connection(pool) {
        Some(mut connection) => {
            let probe = tokio::time::timeout(
                READINESS_PROBE_TIMEOUT,
                sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&mut *connection),
            )
            .await;
            match probe {
                Ok(Ok(1)) => ReadinessStatus::Ready,
                Ok(Ok(unexpected)) => {
                    tracing::warn!(
                        result = unexpected,
                        "database readiness probe returned an unexpected result (expected 1)"
                    );
                    ReadinessStatus::DatabaseUnusable
                }
                Ok(Err(error)) => {
                    tracing::warn!(error = %error, "database readiness probe failed");
                    ReadinessStatus::DatabaseUnusable
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_ms = READINESS_PROBE_TIMEOUT.as_millis() as u64,
                        "database readiness probe timed out"
                    );
                    ReadinessStatus::DatabaseUnusable
                }
            }
        }
        None => ReadinessStatus::DatabaseUnusable,
    };
    *cache.latest.write().await = Some((Instant::now(), status));
    status
}

fn try_readiness_connection(
    pool: &sqlx::PgPool,
) -> Option<sqlx::pool::PoolConnection<sqlx::Postgres>> {
    pool.try_acquire()
}

fn fresh_readiness_snapshot(
    snapshot: Option<(Instant, ReadinessStatus)>,
) -> Option<ReadinessStatus> {
    fresh_readiness_snapshot_at(snapshot, Instant::now())
}

fn fresh_readiness_snapshot_at(
    snapshot: Option<(Instant, ReadinessStatus)>,
    now: Instant,
) -> Option<ReadinessStatus> {
    snapshot.and_then(|(checked_at, status)| {
        (now.saturating_duration_since(checked_at) < READINESS_PROBE_CACHE_TTL).then_some(status)
    })
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

fn readiness_response(status: ReadinessStatus) -> (StatusCode, Json<serde_json::Value>) {
    public_readiness_response(status == ReadinessStatus::Ready)
}

fn public_health_response(healthy: bool) -> (StatusCode, Json<serde_json::Value>) {
    let status = if healthy { "healthy" } else { "degraded" };
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": status })),
    )
}

/// Projects every internal readiness result onto the same bounded public
/// contract. Dependency identities and failure reasons remain available only
/// through the authenticated operational diagnostics endpoint.
fn public_readiness_response(ready: bool) -> (StatusCode, Json<serde_json::Value>) {
    let (http_status, status) = if ready {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not_ready")
    };
    (http_status, Json(serde_json::json!({ "status": status })))
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
    // Dependency-backed health board: the `ryuki_platform_health` gauge reflects
    // a REAL database probe (when a pool is configured) so it can read 0 during
    // an outage instead of the simulated placeholder's permanent 1.
    let health = crate::database::live_platform_health().await;
    let mut body = ryuki_engine::health_monitor::metrics_text_from_health(&health, count);

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
    crate::session_lookup_admission::append_global_metrics(&mut body);

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

/// GET /api/platform/health/dependencies — dependency-backed self-health (#6).
///
/// Unlike the binary `/ready`, this reports EACH backing dependency
/// (database connectivity, migrations, scheduler liveness) and an aggregate
/// verdict. Alerting-safe: a probe that errors is `down` (never silently
/// healthy), and the aggregate maps to 200 (healthy/degraded — still serving)
/// or 503 (unhealthy). Authenticated (it lives in the human-gated router).
async fn platform_self_health() -> (StatusCode, Json<serde_json::Value>) {
    use ryuki_engine::self_health::{aggregate, DependencyProbe};

    let mut probes: Vec<DependencyProbe> = Vec::new();
    let pool = crate::database::get_db();

    // 1. Database connectivity.
    match pool {
        None => probes.push(DependencyProbe::down(
            "database",
            "no database pool configured",
        )),
        Some(p) => match sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(p).await {
            Ok(1) => probes.push(DependencyProbe::healthy("database")),
            Ok(_) => probes.push(DependencyProbe::down("database", "unexpected probe result")),
            Err(e) => {
                tracing::warn!(error = %e, "self-health: database probe failed");
                probes.push(DependencyProbe::down(
                    "database",
                    "connectivity probe failed",
                ));
            }
        },
    }

    // 2. Migrations applied.
    probes.push(match crate::database::migration_status() {
        MigrationStatus::Applied => DependencyProbe::healthy("migrations"),
        MigrationStatus::NotApplied => DependencyProbe::down("migrations", "not applied"),
        MigrationStatus::Failed => DependencyProbe::down("migrations", "failed"),
    });

    // 3. Scheduler liveness — an enabled schedule whose next_run_at is >2x its
    //    interval overdue means the leader tick is not advancing it.
    match pool {
        None => probes.push(DependencyProbe::down("scheduler", "no database pool")),
        Some(p) => match probe_scheduler_liveness(p).await {
            Ok(probe) => probes.push(probe),
            Err(e) => {
                tracing::warn!(error = %e, "self-health: scheduler probe failed");
                // Alerting-safe: a failed probe is NOT healthy.
                probes.push(DependencyProbe::down("scheduler", "liveness probe failed"));
            }
        },
    }

    // 4. Background-loop liveness — in-memory heartbeats, no DB needed. A loop
    //    wedged past its timeout-and-backoff-aware budget reports `down`, which
    //    makes the aggregate non-serving (503) exactly like a down scheduler.
    probes.push(crate::background::classify_loop_liveness(
        &crate::background::loop_liveness(),
    ));

    let overall = aggregate(&probes);
    let http = if overall.is_serving() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = serde_json::json!({
        "status": overall.as_str(),
        "dependencies": probes,
        "checked_at": chrono::Utc::now().to_rfc3339(),
    });
    (http, Json(body))
}

/// GET /api/platform/health/loops — per-loop breakdown of the background-loop
/// heartbeat registry. The aggregate `/api/platform/health/dependencies` reports
/// only THAT a loop is wedged; this reports WHICH loop, its cadence, how long it has
/// been silent (`age_secs`), and its overdue `threshold_secs`, so an operator can
/// diagnose. Authenticated like its sibling (it lives in the human-gated router; the
/// loop names are already surfaced by the aggregate's `down` detail). A wedged loop
/// maps to 503 (else 200); the body always carries the full breakdown.
async fn platform_loop_liveness() -> (StatusCode, Json<serde_json::Value>) {
    let report = crate::background::loop_status_report(&crate::background::loop_liveness());
    let (code, body) = crate::background::loop_liveness_payload(report);
    (
        StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
        Json(body),
    )
}

/// Probe whether the scheduler tick is advancing its schedules. A LIVE leader
/// tick advances EVERY due schedule's next_run_at within its own interval, so
/// ANY enabled schedule slipping past 2x its interval means the tick failed to
/// run it — that is `down` (it must page), NOT degraded: a partial outage that
/// left a long-interval schedule not-yet-overdue would otherwise mask a dead
/// tick behind a 200. `healthy` when none are overdue; `degraded` only when
/// there are no enabled schedules at all (informational — nothing to run).
async fn probe_scheduler_liveness(
    pool: &sqlx::PgPool,
) -> Result<ryuki_engine::self_health::DependencyProbe, sqlx::Error> {
    // An enabled schedule is "overdue" when its next_run_at slipped more than 2x
    // its own interval into the past — a live tick advances next_run_at each run.
    let (enabled, overdue): (i64, i64) = sqlx::query_as(
        "SELECT \
           count(*) FILTER (WHERE enabled), \
           count(*) FILTER (WHERE enabled AND next_run_at \
                            < now() - (interval_secs * 2) * interval '1 second') \
         FROM schedules",
    )
    .fetch_one(pool)
    .await?;
    Ok(classify_scheduler_liveness(enabled, overdue))
}

/// Pure verdict for the scheduler-liveness probe from the enabled/overdue counts.
fn classify_scheduler_liveness(
    enabled: i64,
    overdue: i64,
) -> ryuki_engine::self_health::DependencyProbe {
    use ryuki_engine::self_health::DependencyProbe;
    if enabled == 0 {
        DependencyProbe::degraded("scheduler", "no enabled schedules")
    } else if overdue <= 0 {
        DependencyProbe::healthy("scheduler")
    } else {
        // ANY schedule >2x its interval overdue ⇒ the tick failed to run it ⇒
        // down. A healthy tick keeps every schedule within its interval, so even
        // one straggler signals a stuck/dead leader, not a per-schedule lag.
        DependencyProbe::down(
            "scheduler",
            format!(
                "{overdue} of {enabled} enabled schedule(s) overdue past 2x interval; scheduler tick may be dead"
            ),
        )
    }
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

/// The route SKELETON for the human-session-gated app — every `.route()`/
/// `.merge()` for the inner router, WITHOUT the auth/idempotency layers (which
/// need runtime deps). Extracted so a test can CONSTRUCT it: building the merged
/// matchit tree validates every route path, so a bad path syntax (e.g. the
/// axum-0.7 `:id` that once crashed startup) or a route overlap panics in a
/// test instead of only at server boot. `main()` calls this, then applies the
/// layers — behaviour is identical.
fn build_human_gated_routes() -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/api/validation/run", get(validation_run))
        .route("/api/platform/status", get(platform_status))
        .route("/api/platform/uptime", get(uptime))
        .route(
            "/api/platform/health/dependencies",
            get(platform_self_health),
        )
        .route("/api/platform/health/loops", get(platform_loop_liveness))
        .merge(agents::admin_routes())
        .merge(contracts::routes())
        .merge(boundary::routes())
        .merge(integration::routes())
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
    use tower::ServiceExt;

    fn test_principal_id() -> PrincipalId {
        PrincipalId::from_uuid(Uuid::new_v4()).expect("generated principal id")
    }

    fn test_principal_binding() -> crate::principal_registry::PrincipalBinding {
        crate::principal_registry::PrincipalBinding {
            principal_id: test_principal_id(),
            principal_lifecycle_version: 1,
            principal_authority_version: 1,
            principal_key_id: Uuid::new_v4(),
            principal_key_version: 1,
            principal_link_id: Uuid::new_v4(),
            principal_link_version: 1,
        }
    }

    #[derive(Clone)]
    struct GlobalConcurrencyTestGates {
        login_started: Arc<tokio::sync::Semaphore>,
        login_release: Arc<tokio::sync::Semaphore>,
        ordinary_started: Arc<tokio::sync::Semaphore>,
    }

    impl Default for GlobalConcurrencyTestGates {
        fn default() -> Self {
            Self {
                login_started: Arc::new(tokio::sync::Semaphore::new(0)),
                login_release: Arc::new(tokio::sync::Semaphore::new(0)),
                ordinary_started: Arc::new(tokio::sync::Semaphore::new(0)),
            }
        }
    }

    async fn blocked_successful_local_login_probe(
        State(gates): State<GlobalConcurrencyTestGates>,
        Extension(admission_permit): Extension<contracts::LocalLoginAdmissionPermit>,
    ) -> StatusCode {
        // Model the successful handler tail after credential verification:
        // database/session work remains in flight while this feature-local
        // permit is retained, even though the global budget is bypassed.
        gates.login_started.add_permits(1);
        gates
            .login_release
            .acquire()
            .await
            .expect("login test gate remains open")
            .forget();
        drop(admission_permit);
        StatusCode::OK
    }

    async fn blocked_ordinary_probe(State(gates): State<GlobalConcurrencyTestGates>) -> StatusCode {
        gates.ordinary_started.add_permits(1);
        std::future::pending::<()>().await;
        StatusCode::NO_CONTENT
    }

    fn init_transport_middleware_test_config() {
        crate::config_store::init_with_config(
            "/tmp/ryuki-unused-transport-middleware-test.json",
            &RyukiConfig::default(),
        );
    }

    fn request_with_trace(
        method: Method,
        uri: &str,
        trace_id: &str,
        body: Body,
    ) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header("traceparent", format!("00-{trace_id}-1111111111111111-01"))
            .body(body)
            .expect("transport test request")
    }

    fn assert_response_envelope(response: &Response, trace_id: &str) {
        assert_eq!(response.headers()["x-request-id"], trace_id);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["x-api-version"], "0.1.0");
    }

    #[tokio::test]
    async fn successful_local_login_tail_is_bounded_without_consuming_global_budget() {
        const LOCAL_LOGIN_PATH: &str = "/api/auth/local/login";
        const LOCAL_LOGIN_SLOTS: usize = 8;
        const ORDINARY_BLOCKED_PATH: &str = "/ordinary/blocked";
        const ORDINARY_PROBE_PATH: &str = "/ordinary/probe";

        let request = |method: Method, path: &'static str| {
            HttpRequest::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("concurrency test request")
        };
        // A raw exact-path request cannot self-select the bypass. The outer
        // local gate must first attach its unforgeable in-process permit.
        assert!(!bypasses_global_concurrency_budget(&request(
            Method::POST,
            LOCAL_LOGIN_PATH,
        )));
        assert!(!bypasses_global_concurrency_budget(&request(
            Method::GET,
            LOCAL_LOGIN_PATH,
        )));
        assert!(!bypasses_global_concurrency_budget(&request(
            Method::POST,
            "/api/auth/local/login/",
        )));

        let gates = GlobalConcurrencyTestGates::default();
        let app = Router::new()
            .route(
                LOCAL_LOGIN_PATH,
                axum::routing::post(blocked_successful_local_login_probe),
            )
            .route(ORDINARY_BLOCKED_PATH, get(blocked_ordinary_probe))
            .route(
                ORDINARY_PROBE_PATH,
                get(|| async { StatusCode::NO_CONTENT }),
            )
            .with_state(gates.clone())
            .layer(middleware::from_fn_with_state(
                GlobalConcurrencyAdmission::new(1),
                global_concurrency_middleware,
            ))
            // This is the production ordering: the feature-local, fail-fast
            // login gate runs before the shared budget and remains the sole
            // capacity owner for the exempt route.
            .layer(middleware::from_fn_with_state(
                Arc::new(contracts::LocalLoginThrottle::default()),
                contracts::local_login_admission_middleware,
            ));

        let mut login_tasks = Vec::with_capacity(LOCAL_LOGIN_SLOTS);
        for _ in 0..LOCAL_LOGIN_SLOTS {
            let app = app.clone();
            login_tasks.push(tokio::spawn(async move {
                app.oneshot(request(Method::POST, LOCAL_LOGIN_PATH))
                    .await
                    .expect("admitted login response")
            }));
        }
        for _ in 0..LOCAL_LOGIN_SLOTS {
            tokio::time::timeout(Duration::from_secs(1), gates.login_started.acquire())
                .await
                .expect("all admitted login probes must enter")
                .expect("login start gate remains open")
                .forget();
        }

        // The local gate remains fail-fast and bounded even though login no
        // longer consumes a permit from the global budget.
        let saturated_login = tokio::time::timeout(
            Duration::from_millis(250),
            app.clone().oneshot(request(Method::POST, LOCAL_LOGIN_PATH)),
        )
        .await
        .expect("saturated login gate must reject without queueing")
        .expect("saturated login response");
        assert_eq!(saturated_login.status(), StatusCode::TOO_MANY_REQUESTS);

        // Eight blocked successful-login tails cannot consume the sole shared
        // permit, so an unrelated route still completes immediately while the
        // feature-local budget prevents a ninth session-persistence future.
        let ordinary_during_login = tokio::time::timeout(
            Duration::from_millis(250),
            app.clone()
                .oneshot(request(Method::GET, ORDINARY_PROBE_PATH)),
        )
        .await
        .expect("login delay must not block an unrelated route")
        .expect("unrelated response while logins are delayed");
        assert_eq!(ordinary_during_login.status(), StatusCode::NO_CONTENT);

        gates.login_release.add_permits(LOCAL_LOGIN_SLOTS);
        for login_task in login_tasks {
            let response = tokio::time::timeout(Duration::from_secs(1), login_task)
                .await
                .expect("admitted login probe must finish")
                .expect("admitted login task must not panic");
            assert_eq!(response.status(), StatusCode::OK);
        }

        // Non-exempt routes still share exactly one permit and saturation is
        // fail-fast, rather than retaining an unbounded semaphore waiter set.
        let blocking_app = app.clone();
        let blocking_task = tokio::spawn(async move {
            blocking_app
                .oneshot(request(Method::GET, ORDINARY_BLOCKED_PATH))
                .await
                .expect("blocking ordinary response")
        });
        tokio::time::timeout(Duration::from_secs(1), gates.ordinary_started.acquire())
            .await
            .expect("blocking ordinary probe must enter")
            .expect("ordinary start gate remains open")
            .forget();

        let saturated_ordinary = tokio::time::timeout(
            Duration::from_millis(250),
            app.clone()
                .oneshot(request(Method::GET, ORDINARY_PROBE_PATH)),
        )
        .await
        .expect("saturated global budget must reject without queueing")
        .expect("saturated ordinary response");
        assert_eq!(saturated_ordinary.status(), StatusCode::SERVICE_UNAVAILABLE);
        let saturated_body = axum::body::to_bytes(saturated_ordinary.into_body(), 4096)
            .await
            .expect("structured concurrency rejection body");
        let saturated_body: serde_json::Value =
            serde_json::from_slice(&saturated_body).expect("concurrency rejection JSON");
        assert_eq!(saturated_body["error"], "SERVICE_UNAVAILABLE");
        assert_eq!(saturated_body["message"], "Service temporarily unavailable");

        // Cancellation of the admitted handler must release its owned permit.
        blocking_task.abort();
        let cancelled = tokio::time::timeout(Duration::from_secs(1), blocking_task)
            .await
            .expect("cancelled ordinary task must terminate")
            .expect_err("aborted ordinary task must report cancellation");
        assert!(cancelled.is_cancelled());
        assert_eq!(
            tokio::time::timeout(
                Duration::from_millis(250),
                app.clone()
                    .oneshot(request(Method::GET, ORDINARY_PROBE_PATH)),
            )
            .await
            .expect("permit cancellation must restore capacity")
            .expect("ordinary response after cancellation")
            .status(),
            StatusCode::NO_CONTENT
        );

        let closed_admission = GlobalConcurrencyAdmission::new(1);
        closed_admission.permits.close();
        let closed_app = Router::new()
            .route(
                ORDINARY_PROBE_PATH,
                get(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                LOCAL_LOGIN_PATH,
                axum::routing::post(|| async { StatusCode::OK }),
            )
            .layer(middleware::from_fn_with_state(
                closed_admission,
                global_concurrency_middleware,
            ));
        assert_eq!(
            closed_app
                .clone()
                .oneshot(request(Method::GET, ORDINARY_PROBE_PATH))
                .await
                .expect("closed global budget response")
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let raw_local_login = closed_app
            .oneshot(request(Method::POST, LOCAL_LOGIN_PATH))
            .await
            .expect("raw local-login request without permit");
        assert_eq!(
            raw_local_login.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an exact-path request without the outer admission permit must not bypass"
        );
        let raw_local_login = axum::body::to_bytes(raw_local_login.into_body(), 4096)
            .await
            .expect("raw local-login concurrency rejection body");
        let raw_local_login: serde_json::Value =
            serde_json::from_slice(&raw_local_login).expect("raw local-login rejection JSON");
        assert_eq!(raw_local_login["error"], "SERVICE_UNAVAILABLE");
        assert_eq!(
            raw_local_login["message"],
            "Service temporarily unavailable"
        );
    }

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
    fn duration_tracker_uses_a_bounded_fifo_ring() {
        let mut durations = VecDeque::with_capacity(3);
        for value in 1..=4 {
            push_bounded_duration(&mut durations, value, 3);
        }
        assert_eq!(durations, VecDeque::from([2, 3, 4]));

        push_bounded_duration(&mut durations, 5, 0);
        assert_eq!(durations, VecDeque::from([2, 3, 4]));
    }

    #[tokio::test]
    async fn response_envelope_covers_timeout_rejections() {
        const PATH: &str = "/slow";

        async fn slow_probe() -> StatusCode {
            tokio::time::sleep(Duration::from_millis(50)).await;
            StatusCode::NO_CONTENT
        }

        init_transport_middleware_test_config();
        let app = Router::new()
            .route(PATH, get(slow_probe))
            .layer(middleware::from_fn_with_state(
                Duration::from_millis(1),
                request_timeout_middleware,
            ));
        let app = with_response_envelope(app);
        let trace_id = "11111111111111111111111111111111";
        let response = app
            .oneshot(request_with_trace(
                Method::GET,
                PATH,
                trace_id,
                Body::empty(),
            ))
            .await
            .expect("timeout response");

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_response_envelope(&response, trace_id);
    }

    #[tokio::test]
    async fn response_envelope_covers_rate_limit_rejections() {
        const PATH: &str = "/api/rate-envelope-test";

        init_transport_middleware_test_config();
        let config = ryuki_core::config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst_size: 1,
            path_overrides: HashMap::new(),
            trusted_proxies: Vec::new(),
        };
        let limiter = create_rate_limiter(&config).expect("enabled limiter");
        let app = Router::new()
            .route(PATH, get(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn(
                move |request: HttpRequest<Body>, next: middleware::Next| {
                    let limiter = Some(limiter.clone());
                    async move { rate_limit_middleware(limiter, request, next).await }
                },
            ));
        let app = with_response_envelope(app);
        let request = |trace_id: &str| {
            let mut request = request_with_trace(Method::GET, PATH, trace_id, Body::empty());
            request
                .extensions_mut()
                .insert(ConnectInfo(peer("198.51.100.80:443")));
            request
        };

        assert_eq!(
            app.clone()
                .oneshot(request("22222222222222222222222222222222"))
                .await
                .expect("first rate-limited request")
                .status(),
            StatusCode::NO_CONTENT
        );
        let trace_id = "33333333333333333333333333333333";
        let response = app
            .oneshot(request(trace_id))
            .await
            .expect("rate-limit rejection");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_response_envelope(&response, trace_id);
    }

    #[tokio::test]
    async fn response_envelope_covers_body_limit_rejections() {
        const PATH: &str = "/body";

        async fn body_probe(_body: axum::body::Bytes) -> StatusCode {
            StatusCode::NO_CONTENT
        }

        init_transport_middleware_test_config();
        let app = Router::new()
            .route(PATH, axum::routing::post(body_probe))
            .layer(RequestBodyLimitLayer::new(4));
        let app = with_response_envelope(app);
        let trace_id = "44444444444444444444444444444444";
        let response = app
            .oneshot(request_with_trace(
                Method::POST,
                PATH,
                trace_id,
                Body::from(vec![b'x'; 5]),
            ))
            .await
            .expect("body-limit rejection");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_response_envelope(&response, trace_id);
    }

    #[tokio::test]
    async fn platform_loop_liveness_lists_a_registered_loop() {
        // Register a uniquely-named fresh loop; the per-loop endpoint must include it
        // with overdue=false and a positive threshold. We do NOT assert the HTTP code
        // or `overall` — the registry is process-global and other tests' loops + the
        // wall clock make those non-deterministic (the 200/503 logic is covered by
        // background.rs's pure loop_liveness_payload test). Status must be 200 OR 503.
        let name: &'static str =
            Box::leak(format!("test-loops-endpoint-{}", uuid::Uuid::new_v4()).into_boxed_str());
        crate::background::register_loop(name, 30);

        let (code, Json(body)) = platform_loop_liveness().await;
        assert!(
            code == StatusCode::OK || code == StatusCode::SERVICE_UNAVAILABLE,
            "loops endpoint returns 200 or 503, got {code}"
        );
        let mine = body["loops"]
            .as_array()
            .expect("loops is an array")
            .iter()
            .find(|l| l["name"] == name)
            .expect("the registered loop appears in the breakdown");
        assert_eq!(mine["interval_secs"], 30);
        assert_eq!(mine["overdue"], false, "a fresh loop is not overdue");
        assert!(mine["threshold_secs"].as_u64().unwrap() > 0);
    }

    #[test]
    fn scheduler_liveness_verdict_covers_all_cases() {
        use ryuki_engine::self_health::DependencyHealth;
        // No enabled schedules -> degraded (informational, nothing to run).
        assert_eq!(
            classify_scheduler_liveness(0, 0).health,
            DependencyHealth::Degraded
        );
        // All caught up -> healthy.
        assert_eq!(
            classify_scheduler_liveness(3, 0).health,
            DependencyHealth::Healthy
        );
        // Even ONE schedule overdue past 2x interval -> down: a live tick would
        // have advanced it, so a straggler means the tick is stuck/dead. This
        // must page (not hide behind a 200) even when other schedules are fine.
        assert_eq!(
            classify_scheduler_liveness(3, 1).health,
            DependencyHealth::Down
        );
        // All overdue -> down.
        assert_eq!(
            classify_scheduler_liveness(3, 3).health,
            DependencyHealth::Down
        );
    }

    #[tokio::test]
    async fn scheduler_liveness_sql_is_valid() {
        // Validates the FILTER + interval SQL against a real Postgres — nothing
        // else exercises this query string. DB-gated; skips without a DB.
        use crate::database::DB_TEST_SERIAL;
        let _serial = DB_TEST_SERIAL.lock().await;
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect");
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply");
        let probe = probe_scheduler_liveness(&pool)
            .await
            .expect("scheduler liveness SQL must be valid");
        assert_eq!(probe.name, "scheduler");
    }

    #[tokio::test]
    async fn self_health_without_db_is_unhealthy_503() {
        // With no DB pool every probe is down -> aggregate unhealthy -> 503.
        let (status, body) = platform_self_health().await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["status"], serde_json::json!("unhealthy"));
        let deps = body.0["dependencies"]
            .as_array()
            .expect("dependencies array");
        assert!(
            deps.iter()
                .any(|d| d["name"] == "database" && d["health"] == "down"),
            "database probe must be down with no pool"
        );
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

    #[test]
    fn test_api_token_lookup_has_one_source_clause() {
        assert_eq!(API_TOKEN_LOOKUP_SQL.matches("FROM api_tokens").count(), 1);
    }

    #[tokio::test]
    async fn test_api_token_lookup_and_usage_telemetry_guards() {
        use crate::database::DB_TEST_SERIAL;
        let _serial = DB_TEST_SERIAL.lock().await;
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect");
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply");

        let token_id = Uuid::new_v4();
        let plaintext = format!("{API_TOKEN_PREFIX}{}", Uuid::new_v4().simple());
        let token_hash = sha256_hex(&plaintext);
        let provider = "local";
        let issuer = "urn:ryuki:test:api-token-lookup";
        let subject = "session-boundary-query-user";
        let roles = vec!["Auditor".to_string()];
        let authority_digest: [u8; 32] = Sha256::digest(Uuid::new_v4().as_bytes()).into();
        let mut token_tx = pool.begin().await.expect("begin API token seed");
        let (binding, _) = crate::principal_registry::resolve_or_create_active_binding_tx(
            &mut token_tx,
            provider,
            issuer,
            subject,
            &crate::principal_registry::InitialHumanAuthority {
                authority_digest: &authority_digest,
                roles: &roles,
                site_mode: "global",
                site_scope: &[],
                environment_mode: "global",
                environment_scope: &[],
                created_by: "api-token-lookup-test",
            },
        )
        .await
        .expect("seed exact token issuer binding");
        sqlx::query(
            "INSERT INTO api_tokens \
             (id, name, token_hash, roles, token_valid, expires_at, \
              issuing_principal_id, issuing_principal_lifecycle_version, \
              issuing_principal_authority_version, principal_key_id, principal_key_version, \
              principal_link_id, principal_link_version) \
             VALUES ($1, $2, $3, $4, TRUE, NOW() + INTERVAL '1 hour', \
                     $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(token_id)
        .bind("session-boundary-query-test")
        .bind(&token_hash)
        .bind(&roles)
        .bind(binding.principal_id.into_uuid())
        .bind(binding.principal_lifecycle_version)
        .bind(binding.principal_authority_version)
        .bind(binding.principal_key_id)
        .bind(binding.principal_key_version)
        .bind(binding.principal_link_id)
        .bind(binding.principal_link_version)
        .execute(&mut *token_tx)
        .await
        .expect("seed API token");
        token_tx.commit().await.expect("commit API token seed");

        let session = resolve_api_token(&plaintext, &pool).await;
        assert!(session.token_valid);
        assert_eq!(session.provider_mode, "api-token");
        assert_eq!(session.principal_id, Some(binding.principal_id));
        assert_eq!(session.display_user_id, binding.principal_id.to_string());
        let last_used_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT last_used_at FROM api_tokens WHERE id = $1")
                .bind(token_id)
                .fetch_one(&pool)
                .await
                .expect("read last-used timestamp");
        assert!(last_used_at.is_some());

        // A raw writer can only signal use; the trigger replaces both future
        // and past caller values with authoritative database statement time.
        for supplied_value in [
            "statement_timestamp() + INTERVAL '1 hour'",
            "TIMESTAMPTZ '2000-01-01 00:00:00+00'",
        ] {
            let (database_now, recorded): (
                chrono::DateTime<chrono::Utc>,
                chrono::DateTime<chrono::Utc>,
            ) = sqlx::query_as(&format!(
                "WITH updated AS (\
                   UPDATE api_tokens SET last_used_at = {supplied_value} WHERE id = $1 \
                   RETURNING last_used_at\
                 ) \
                 SELECT statement_timestamp(), last_used_at FROM updated"
            ))
            .bind(token_id)
            .fetch_one(&pool)
            .await
            .expect("database must own API token usage time");
            assert_eq!(recorded, database_now);
        }

        let clear_error = sqlx::query("UPDATE api_tokens SET last_used_at = NULL WHERE id = $1")
            .bind(token_id)
            .execute(&pool)
            .await
            .expect_err("API token usage telemetry may not be cleared");
        assert_eq!(
            clear_error
                .as_database_error()
                .and_then(|database_error| database_error.code())
                .as_deref(),
            Some("23514")
        );

        // Reproduce the former transaction-time race with two connections:
        // the older transaction writes after the newer transaction commits.
        // The final value must still advance rather than rewind to the older
        // transaction's NOW().
        let mut older_tx = pool.begin().await.expect("begin older telemetry tx");
        let older_started_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT transaction_timestamp()")
                .fetch_one(&mut *older_tx)
                .await
                .expect("read older transaction time");
        sqlx::query("SELECT pg_sleep(0.01)")
            .execute(&mut *older_tx)
            .await
            .expect("separate transaction start times");

        let mut newer_tx = pool.begin().await.expect("begin newer telemetry tx");
        let newer_started_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT transaction_timestamp()")
                .fetch_one(&mut *newer_tx)
                .await
                .expect("read newer transaction time");
        assert!(older_started_at < newer_started_at);
        let newer_recorded: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "UPDATE api_tokens SET last_used_at = transaction_timestamp() \
             WHERE id = $1 RETURNING last_used_at",
        )
        .bind(token_id)
        .fetch_one(&mut *newer_tx)
        .await
        .expect("newer transaction records token use");
        newer_tx.commit().await.expect("commit newer telemetry tx");

        let older_recorded: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "UPDATE api_tokens SET last_used_at = transaction_timestamp() \
             WHERE id = $1 RETURNING last_used_at",
        )
        .bind(token_id)
        .fetch_one(&mut *older_tx)
        .await
        .expect("older transaction records token use after newer commit");
        older_tx.commit().await.expect("commit older telemetry tx");
        assert!(older_recorded >= newer_recorded);

        let final_last_used_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT last_used_at FROM api_tokens WHERE id = $1")
                .bind(token_id)
                .fetch_one(&pool)
                .await
                .expect("read final last-used timestamp");
        assert_eq!(final_last_used_at, older_recorded);

        for forbidden_update in [
            "UPDATE api_tokens SET id = gen_random_uuid() WHERE id = $1",
            "UPDATE api_tokens SET name = 'rewritten-evidence' WHERE id = $1",
            "UPDATE api_tokens SET token_hash = 'rebound-hash' WHERE id = $1",
            "UPDATE api_tokens SET created_at = NOW() - INTERVAL '7 days' WHERE id = $1",
            "UPDATE api_tokens SET expires_at = NOW() + INTERVAL '7 days' WHERE id = $1",
        ] {
            let error = sqlx::query(forbidden_update)
                .bind(token_id)
                .execute(&pool)
                .await
                .expect_err("API token evidence fields must be immutable");
            assert_eq!(
                error
                    .as_database_error()
                    .and_then(|database_error| database_error.code())
                    .as_deref(),
                Some("23514")
            );
        }

        sqlx::query(
            "UPDATE api_tokens SET token_valid = FALSE, \
                    revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1",
        )
        .bind(token_id)
        .execute(&pool)
        .await
        .expect("soft-revoke API token evidence");
        let post_revoke_usage_error =
            sqlx::query("UPDATE api_tokens SET last_used_at = statement_timestamp() WHERE id = $1")
                .bind(token_id)
                .execute(&pool)
                .await
                .expect_err("revoked API token may not record fresh usage telemetry");
        assert_eq!(
            post_revoke_usage_error
                .as_database_error()
                .and_then(|database_error| database_error.code())
                .as_deref(),
            Some("23514")
        );
        let delete_error = sqlx::query("DELETE FROM api_tokens WHERE id = $1")
            .bind(token_id)
            .execute(&pool)
            .await
            .expect_err("API token evidence must reject hard deletion");
        assert_eq!(
            delete_error
                .as_database_error()
                .and_then(|database_error| database_error.code())
                .as_deref(),
            Some("23514")
        );
        pool.close().await;
    }

    /// Builds an enabled, network-backed validator with no usable keyset. It is
    /// used by middleware-arm tests that never expect a successful validation
    /// (mock arm short-circuits; the unsigned-entra token fails to decode).
    fn test_validator() -> Arc<EntraTokenValidator> {
        Arc::new(EntraTokenValidator::from_app_config(
            "test-tenant",
            "test-client",
            "https://login.microsoftonline.com",
            86_400,
            crate::security_contracts::ResolvedAuthenticatorBearerLimits::fixture(60, 3_600),
        ))
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

    #[tokio::test]
    async fn test_entra_auth_mode_without_bound_validator_stays_unverified() {
        let (session, failure_reason, direct_credential, verified_identity) =
            resolve_request_session(
                AuthMode::EntraId,
                Some("Bearer header.payload.signature"),
                None,
            )
            .await;

        assert_eq!(session.provider_mode, "entra-id-unverified");
        assert!(session.roles.is_empty());
        assert!(!session.token_valid);
        assert_eq!(failure_reason, Some("unbound-verifier"));
        assert!(direct_credential.is_none());
        assert!(verified_identity.is_none());
    }

    const SECURE_SESSION_COOKIE_NAME: &str = "__Host-ryuki_session";
    const LOOPBACK_SESSION_COOKIE_NAME: &str = "ryuki_session";

    fn secure_session_config() -> cookie_runtime::ApiSessionAuthParser {
        cookie_runtime::ApiCookieRuntime::from_admitted_config(&RyukiConfig::default(), false)
            .unwrap()
            .session_auth_parser()
    }

    fn loopback_session_config() -> cookie_runtime::ApiSessionAuthParser {
        let mut config = RyukiConfig::default();
        config.session.cookie_secure = false;
        config.server.bind_address = "127.0.0.1:0".into();
        cookie_runtime::ApiCookieRuntime::from_admitted_config(&config, false)
            .unwrap()
            .session_auth_parser()
    }

    #[test]
    fn test_session_credential_from_header() {
        let session_token = crate::session_credentials::generate_session_bearer();
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Ryuki-Session-Id",
            HeaderValue::from_str(session_token.as_str()).unwrap(),
        );

        let (parsed, source) =
            session_credential_from_headers(&headers, None, &secure_session_config())
                .expect("session header should be recognized");
        assert_eq!(
            parsed.expect("session header should parse"),
            session_token.as_str()
        );
        assert_eq!(source, SessionIdSource::Header);
    }

    #[test]
    fn test_admin_management_uuid_is_not_an_authentication_credential() {
        let management_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Ryuki-Session-Id",
            HeaderValue::from_str(&management_id.to_string()).unwrap(),
        );

        assert_eq!(
            session_credential_from_headers(&headers, None, &secure_session_config()),
            Some((Err(()), SessionIdSource::Header)),
            "an admin-visible session UUID must never authenticate"
        );

        let no_headers = HeaderMap::new();
        let authorization = format!("Bearer {management_id}");
        assert!(
            session_credential_from_headers(
                &no_headers,
                Some(&authorization),
                &secure_session_config(),
            )
            .is_none(),
            "an admin-visible UUID must not claim the session-bearer class"
        );

        let mut cookie_headers = HeaderMap::new();
        cookie_headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!("{SECURE_SESSION_COOKIE_NAME}={management_id}"))
                .unwrap(),
        );
        assert_eq!(
            session_credential_from_headers(&cookie_headers, None, &secure_session_config(),),
            Some((Err(()), SessionIdSource::Cookie)),
            "an admin-visible UUID cookie must never authenticate"
        );
    }

    #[test]
    fn test_session_credential_from_bearer() {
        let session_token = crate::session_credentials::generate_session_bearer();
        let headers = HeaderMap::new();
        let authorization = format!("Bearer {}", session_token.as_str());

        let (parsed, source) = session_credential_from_headers(
            &headers,
            Some(&authorization),
            &secure_session_config(),
        )
        .expect("session bearer should be recognized");
        assert_eq!(
            parsed.expect("session bearer should parse"),
            session_token.as_str()
        );
        assert_eq!(source, SessionIdSource::Bearer);
    }

    #[test]
    fn test_non_session_bearer_is_not_session_credential() {
        let headers = HeaderMap::new();
        assert!(session_credential_from_headers(
            &headers,
            Some("Bearer jwt-token"),
            &secure_session_config(),
        )
        .is_none());
    }

    #[test]
    fn test_https_session_cookie_accepts_only_host_prefixed_singleton() {
        let session_token = crate::session_credentials::generate_session_bearer();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!(
                "other=1; {SECURE_SESSION_COOKIE_NAME}={}; theme=dark",
                session_token.as_str()
            ))
            .unwrap(),
        );

        let (parsed, source) =
            session_credential_from_headers(&headers, None, &secure_session_config())
                .expect("secure session cookie should be recognized");
        assert_eq!(
            parsed.expect("secure session cookie should parse"),
            session_token.as_str()
        );
        assert_eq!(source, SessionIdSource::Cookie);

        let mut old_singleton = HeaderMap::new();
        old_singleton.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!(
                "{LOOPBACK_SESSION_COOKIE_NAME}={}",
                session_token.as_str()
            ))
            .unwrap(),
        );
        assert_eq!(
            session_credential_from_headers(&old_singleton, None, &secure_session_config(),),
            Some((Err(()), SessionIdSource::Cookie)),
            "HTTPS must not fall through past an unprefixed session singleton"
        );
    }

    #[test]
    fn test_loopback_session_cookie_accepts_only_unprefixed_singleton() {
        let session_token = crate::session_credentials::generate_session_bearer();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!(
                "{LOOPBACK_SESSION_COOKIE_NAME}={}",
                session_token.as_str()
            ))
            .unwrap(),
        );
        let (parsed, source) =
            session_credential_from_headers(&headers, None, &loopback_session_config())
                .expect("loopback session cookie should be recognized");
        assert_eq!(parsed.unwrap(), session_token.as_str());
        assert_eq!(source, SessionIdSource::Cookie);

        let mut host_singleton = HeaderMap::new();
        host_singleton.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!(
                "{SECURE_SESSION_COOKIE_NAME}={}",
                session_token.as_str()
            ))
            .unwrap(),
        );
        assert_eq!(
            session_credential_from_headers(&host_singleton, None, &loopback_session_config(),),
            Some((Err(()), SessionIdSource::Cookie))
        );
    }

    #[test]
    fn test_duplicate_session_cookies_reject_attacker_first_and_last() {
        let victim = crate::session_credentials::generate_session_bearer();
        let attacker = crate::session_credentials::generate_session_bearer();
        for (session, name) in [
            (secure_session_config(), SECURE_SESSION_COOKIE_NAME),
            (loopback_session_config(), LOOPBACK_SESSION_COOKIE_NAME),
        ] {
            for header in [
                format!("{name}={}; {name}={}", attacker.as_str(), victim.as_str()),
                format!("{name}={}; {name}={}", victim.as_str(), attacker.as_str()),
                format!("{name}=malformed; {name}={}", victim.as_str()),
                format!("{name}={}; {name}=malformed", victim.as_str()),
            ] {
                let mut headers = HeaderMap::new();
                headers.insert(
                    axum::http::header::COOKIE,
                    HeaderValue::from_str(&header).unwrap(),
                );
                assert_eq!(
                    session_credential_from_headers(&headers, None, &session),
                    Some((Err(()), SessionIdSource::Cookie)),
                    "duplicate credential cookies must fail closed: {header}"
                );
            }
        }

        let mut split_fields = HeaderMap::new();
        split_fields.append(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!(
                "{SECURE_SESSION_COOKIE_NAME}={}",
                attacker.as_str()
            ))
            .unwrap(),
        );
        split_fields.append(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!("{SECURE_SESSION_COOKIE_NAME}={}", victim.as_str()))
                .unwrap(),
        );
        assert_eq!(
            session_credential_from_headers(&split_fields, None, &secure_session_config()),
            Some((Err(()), SessionIdSource::Cookie))
        );
    }

    #[test]
    fn test_mixed_old_and_new_session_cookie_names_reject_both_orders() {
        let old = crate::session_credentials::generate_session_bearer();
        let current = crate::session_credentials::generate_session_bearer();
        for header in [
            format!(
                "{LOOPBACK_SESSION_COOKIE_NAME}={}; {SECURE_SESSION_COOKIE_NAME}={}",
                old.as_str(),
                current.as_str()
            ),
            format!(
                "{SECURE_SESSION_COOKIE_NAME}={}; {LOOPBACK_SESSION_COOKIE_NAME}={}",
                current.as_str(),
                old.as_str()
            ),
        ] {
            for session in [secure_session_config(), loopback_session_config()] {
                let mut headers = HeaderMap::new();
                headers.insert(
                    axum::http::header::COOKIE,
                    HeaderValue::from_str(&header).unwrap(),
                );
                assert_eq!(
                    session_credential_from_headers(&headers, None, &session),
                    Some((Err(()), SessionIdSource::Cookie))
                );
            }
        }

        let old_field = format!("{LOOPBACK_SESSION_COOKIE_NAME}={}", old.as_str());
        let current_field = format!("{SECURE_SESSION_COOKIE_NAME}={}", current.as_str());
        for (first, second) in [
            (old_field.as_str(), current_field.as_str()),
            (current_field.as_str(), old_field.as_str()),
        ] {
            for session in [secure_session_config(), loopback_session_config()] {
                let mut headers = HeaderMap::new();
                headers.append(
                    axum::http::header::COOKIE,
                    HeaderValue::from_str(first).unwrap(),
                );
                headers.append(
                    axum::http::header::COOKIE,
                    HeaderValue::from_str(second).unwrap(),
                );
                assert_eq!(
                    session_credential_from_headers(&headers, None, &session),
                    Some((Err(()), SessionIdSource::Cookie)),
                    "mixed names split across Cookie fields must fail closed"
                );
            }
        }
    }

    #[test]
    fn test_malformed_cookie_encoding_and_pairs_are_invalid_evidence() {
        let mut non_text = HeaderMap::new();
        non_text.append(
            axum::http::header::COOKIE,
            HeaderValue::from_bytes(b"theme=dark; \x80")
                .expect("opaque Cookie header bytes are accepted"),
        );
        assert_eq!(
            session_credential_from_headers(&non_text, None, &secure_session_config()),
            Some((Err(()), SessionIdSource::Cookie))
        );

        let mut malformed_pair = HeaderMap::new();
        malformed_pair.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("theme=dark; malformed"),
        );
        assert_eq!(
            session_credential_from_headers(&malformed_pair, None, &secure_session_config()),
            Some((Err(()), SessionIdSource::Cookie))
        );

        let valid_cookie = crate::session_credentials::generate_session_bearer();
        let valid_field = HeaderValue::from_str(&format!(
            "{SECURE_SESSION_COOKIE_NAME}={}",
            valid_cookie.as_str()
        ))
        .unwrap();
        for malformed_first in [true, false] {
            let malformed_field = HeaderValue::from_bytes(b"theme=dark; \x80")
                .expect("opaque Cookie header bytes are accepted");
            let mut split_fields = HeaderMap::new();
            if malformed_first {
                split_fields.append(axum::http::header::COOKIE, malformed_field);
                split_fields.append(axum::http::header::COOKIE, valid_field.clone());
            } else {
                split_fields.append(axum::http::header::COOKIE, valid_field.clone());
                split_fields.append(axum::http::header::COOKIE, malformed_field);
            }
            assert_eq!(
                session_credential_from_headers(&split_fields, None, &secure_session_config(),),
                Some((Err(()), SessionIdSource::Cookie)),
                "malformed Cookie field must not fall through in either order"
            );
        }
    }

    #[test]
    fn test_malformed_session_cookie_is_invalid_not_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("__Host-ryuki_session=not-a-session"),
        );

        assert_eq!(
            session_credential_from_headers(&headers, None, &secure_session_config()),
            Some((Err(()), SessionIdSource::Cookie))
        );
    }

    #[test]
    fn test_conflicting_session_header_and_cookie_are_rejected() {
        let header_session_token = crate::session_credentials::generate_session_bearer();
        let cookie_session_token = crate::session_credentials::generate_session_bearer();
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Ryuki-Session-Id",
            HeaderValue::from_str(header_session_token.as_str()).unwrap(),
        );
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!(
                "{SECURE_SESSION_COOKIE_NAME}={}",
                cookie_session_token.as_str()
            ))
            .unwrap(),
        );

        let (parsed, source) =
            session_credential_from_headers(&headers, None, &secure_session_config()).unwrap();
        assert_eq!(parsed, Err(()));
        assert_eq!(source, SessionIdSource::Header);
    }

    #[test]
    fn test_authorization_and_cookie_evidence_are_rejected_together() {
        let cookie_session_token = crate::session_credentials::generate_session_bearer();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!(
                "{SECURE_SESSION_COOKIE_NAME}={}",
                cookie_session_token.as_str()
            ))
            .unwrap(),
        );

        let (parsed, source) = session_credential_from_headers(
            &headers,
            Some("Bearer jwt-token"),
            &secure_session_config(),
        )
        .unwrap();
        assert_eq!(parsed, Err(()));
        assert_eq!(source, SessionIdSource::Bearer);
    }

    #[test]
    fn test_non_text_authorization_header_cannot_fall_through_to_cookie() {
        let cookie_session_token = crate::session_credentials::generate_session_bearer();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \x80").expect("opaque header bytes are accepted"),
        );
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!(
                "{SECURE_SESSION_COOKIE_NAME}={}",
                cookie_session_token.as_str()
            ))
            .unwrap(),
        );

        let (parsed, source) =
            session_credential_from_headers(&headers, None, &secure_session_config())
                .expect("raw Authorization bytes are credential evidence");
        assert_eq!(parsed, Err(()));
        assert_eq!(source, SessionIdSource::Bearer);
    }

    #[test]
    fn test_no_session_sources_yields_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("theme=dark; other=1"),
        );
        assert!(
            session_credential_from_headers(&headers, None, &secure_session_config()).is_none()
        );
    }

    #[test]
    fn test_db_session_row_maps_to_verified_session() {
        let principal_id = Uuid::new_v4();
        let session = session_from_db_row(&DbAuthSessionRow {
            session_record_id: Uuid::new_v4(),
            principal_id,
            principal_lifecycle_version: 1,
            principal_authority_version: 1,
            principal_key_id: Uuid::new_v4(),
            principal_key_version: 1,
            principal_link_id: Uuid::new_v4(),
            principal_link_version: 1,
            display_name: "Platform Engineer".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_PLATFORM_ADMIN.into()],
            bearer_verifier: random_bearer_verifier_fixture(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            provider_id: "local".into(),
            issuer: crate::identity_authority::LOCAL_ISSUER.into(),
            subject: "platform-engineer".into(),
            site_authority_mode: "scoped".into(),
            site_scope: vec!["SITE-A".into()],
            environment_authority_mode: "global".into(),
            environment_scope: vec![],
            authenticator_origin_binding_digest: None,
            registered_origin_binding_digest: None,
            current_origin_binding_digest: None,
        })
        .expect("generated row has a non-nil principal id");

        assert_eq!(session.provider_mode, "persisted-session");
        assert_eq!(session.display_user_id, principal_id.to_string());
        assert_eq!(
            session.principal_id,
            Some(PrincipalId::from_uuid(principal_id).unwrap())
        );
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
    fn full_app_route_tree_builds_without_panic() {
        // Regression guard for the whole app: constructing the merged route tree
        // runs matchit's path validation across EVERY merged router (infra,
        // agent-token, and all human-gated routers — agents/contracts/boundary/
        // integration). A bad route-path syntax (the axum-0.7 `:id` that once
        // crashed server startup) or a route overlap panics HERE — in a test —
        // instead of only when the server boots. main() merges this same set.
        let _app = Router::new()
            .route("/health", get(health))
            .route("/ready", get(ready))
            .merge(agents::agent_routes())
            .merge(build_human_gated_routes());
    }

    #[test]
    fn user_preferences_self_service_matcher_is_exact() {
        // Only the exact preferences path gets the relaxed (read-tier) mutation
        // gate; nothing adjacent inherits it.
        assert!(is_user_preferences_path("/api/me/preferences"));
        assert!(!is_user_preferences_path("/api/me/preferences/extra"));
        assert!(!is_user_preferences_path("/api/me/preferences/"));
        assert!(!is_user_preferences_path("/api/me"));
        assert!(!is_user_preferences_path("/api/me/other"));
        assert!(!is_user_preferences_path("/api/users/preferences"));
    }

    #[test]
    fn self_service_mutation_is_method_and_path_exact() {
        // PUT preferences IS self-service; any OTHER method on that path is NOT
        // (it falls through to the fail-closed admin default).
        assert!(is_self_service_mutation(
            &Method::PUT,
            "/api/me/preferences"
        ));
        for m in [Method::POST, Method::PATCH, Method::DELETE] {
            assert!(
                !is_self_service_mutation(&m, "/api/me/preferences"),
                "{m} on the preferences path must NOT be self-service"
            );
        }
        // A safe method is never a "mutation" exemption (reads use read_authorized).
        assert!(!is_self_service_mutation(
            &Method::GET,
            "/api/me/preferences"
        ));
        // Notification mark-read stays self-service for its unsafe method.
        assert!(is_self_service_mutation(
            &Method::POST,
            "/api/notifications/read-all"
        ));
        // An unrelated mutation is not self-service.
        assert!(!is_self_service_mutation(&Method::POST, "/api/requests"));
    }

    #[test]
    fn test_auth_exempt_paths_are_limited_to_auth_flow() {
        assert!(is_auth_exempt_path("/api/auth/login"));
        assert!(is_auth_exempt_path("/api/auth/logout"));
        assert!(is_auth_exempt_path("/api/auth/local/login"));
        assert!(is_auth_exempt_path("/api/auth/local/logout"));
        assert!(!is_auth_exempt_path("/api/auth/local/me"));
        assert!(!is_auth_exempt_path("/api/requests"));
        assert!(is_auth_exempt_path("/api/auth/oidc/login"));
        assert!(is_auth_exempt_path("/api/auth/oidc/callback"));
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
            "users": format!("alice:placeholder-pass-1:{roles}"),
            "site_authority": "global",
            "environment_authority": "global"
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
    fn test_unsafe_method_auth_requires_static_or_verified_session() {
        let static_session = AuthSession::static_dry_run();
        let unverified = AuthSession::unverified_entra();
        let mut verified = AuthSession::unverified_entra();
        verified.token_valid = true;

        assert!(auth_session_allows_unsafe_method(&static_session));
        assert!(auth_session_allows_unsafe_method(&verified));
        assert!(!auth_session_allows_unsafe_method(&unverified));
    }

    fn persisted_session_row_fixture() -> DbAuthSessionRow {
        DbAuthSessionRow {
            session_record_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            principal_lifecycle_version: 1,
            principal_authority_version: 1,
            principal_key_id: Uuid::new_v4(),
            principal_key_version: 1,
            principal_link_id: Uuid::new_v4(),
            principal_link_version: 1,
            display_name: "admin".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_PLATFORM_ADMIN.into()],
            bearer_verifier: random_bearer_verifier_fixture(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            provider_id: "local".into(),
            issuer: crate::identity_authority::LOCAL_ISSUER.into(),
            subject: "admin".into(),
            site_authority_mode: "global".into(),
            site_scope: vec![],
            environment_authority_mode: "global".into(),
            environment_scope: vec![],
            authenticator_origin_binding_digest: None,
            registered_origin_binding_digest: None,
            current_origin_binding_digest: None,
        }
    }

    fn verified_persisted_session() -> AuthSession {
        session_from_db_row(&persisted_session_row_fixture())
            .expect("generated row has a non-nil principal id")
    }

    #[test]
    fn persisted_session_origin_requires_the_exact_active_current_pointer() {
        let origin = crate::session_lookup_admission::SessionLookupOriginAuthority::browser_fixture(
            "current-pointer",
        );
        let expected = origin
            .origin_binding_digest()
            .expect("browser fixture has an origin digest")
            .to_vec();
        let mut row = persisted_session_row_fixture();
        row.authenticator_origin_binding_digest = Some(expected.clone());
        row.registered_origin_binding_digest = Some(expected.clone());
        row.current_origin_binding_digest = Some(expected);
        assert!(session_row_matches_origin(&row, &origin));

        row.current_origin_binding_digest = None;
        assert!(
            !session_row_matches_origin(&row, &origin),
            "a disabled browser pointer must reject its former session generation"
        );

        let mut stale_digest = rand::random::<[u8; 32]>().to_vec();
        if stale_digest
            == row
                .authenticator_origin_binding_digest
                .as_deref()
                .unwrap_or_default()
        {
            stale_digest[0] ^= 1;
        }
        row.current_origin_binding_digest = Some(stale_digest);
        assert!(
            !session_row_matches_origin(&row, &origin),
            "a stale current pointer must reject the old process-local origin"
        );
    }

    fn random_bearer_verifier_fixture() -> Vec<u8> {
        rand::random::<[u8; crate::session_credentials::SESSION_VERIFIER_LEN]>().to_vec()
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
    fn test_observability_route_labels_use_templates_and_collapse_subject_paths() {
        assert_eq!(
            metrics_path_label(
                "/api/requests/alice@example.test",
                Some("/api/requests/{id}")
            ),
            "/api/requests/{id}"
        );
        for path in [
            "/random-a/alice@example.test",
            "/random-b/principal-123",
            "/api-does-not-exist/550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert_eq!(metrics_path_label(path, None), "/__unmatched__");
        }
        let extension_method = Method::from_bytes(b"ATTACKER-METHOD").unwrap();
        assert_eq!(metrics_method_label(&extension_method), "OTHER");
    }

    #[test]
    fn test_rate_limit_path_group_normalizes_first_path_segment() {
        assert_eq!(rate_limit_path_group("/health"), "health");
        assert_eq!(rate_limit_path_group("/API/platform/status"), "api");
        assert_eq!(rate_limit_path_group("/"), "root");
        assert_eq!(rate_limit_path_group("/attacker-a/x"), "unmatched");
        assert_eq!(rate_limit_path_group("/attacker-b/y"), "unmatched");
    }

    #[test]
    fn test_rate_limit_keys_use_a_fixed_bucket_namespace() {
        let salt: [u8; 32] = rand::random();
        let mut buckets = std::collections::HashSet::new();
        for index in 0..(u32::from(RATE_LIMIT_CLIENT_BUCKETS) * 2) {
            let key = bounded_rate_limit_key("api", &format!("client-{index}"), &salt);
            assert!(key.starts_with("api:bucket-"));
            buckets.insert(key);
        }
        assert!(buckets.len() <= usize::from(RATE_LIMIT_CLIENT_BUCKETS));
        assert_ne!(
            bounded_rate_limit_key("api", "same-client", &salt),
            bounded_rate_limit_key("health", "same-client", &salt),
            "closed route groups retain independent quotas"
        );
        let salted_key = bounded_rate_limit_key("api", "same-client", &salt);
        let differently_salted_key = (0..256)
            .find_map(|_| {
                let alternate_salt: [u8; 32] = rand::random();
                let alternate_key = bounded_rate_limit_key("api", "same-client", &alternate_salt);
                (alternate_key != salted_key).then_some(alternate_key)
            })
            .expect("independent random salts should reach more than one bounded bucket");
        assert_ne!(
            salted_key, differently_salted_key,
            "bucket assignment must not be predictable across processes"
        );
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
    fn test_forwarded_header_evidence_is_unique_and_fully_validated() {
        let trusted_proxies = trusted(&["10.0.0.0/8"]);
        let proxy = peer("10.0.0.5:443");

        let mut valid = HeaderMap::new();
        valid.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.20, 10.0.0.6"),
        );
        assert_eq!(
            resolve_rate_limit_client_key_from_headers(proxy, &valid, &trusted_proxies),
            ("198.51.100.20".into(), ClientKeySource::Forwarded)
        );

        for values in [["198.51.100.20", "10.0.0.6"], ["10.0.0.6", "198.51.100.20"]] {
            let mut duplicate = HeaderMap::new();
            for value in values {
                duplicate.append(
                    "x-forwarded-for",
                    HeaderValue::from_str(value).expect("forwarded fixture"),
                );
            }
            assert_eq!(
                resolve_rate_limit_client_key_from_headers(proxy, &duplicate, &trusted_proxies),
                ("10.0.0.5".into(), ClientKeySource::Peer),
                "duplicate attacker-first or attacker-last fields must fail to the peer"
            );
        }

        let mut non_ascii = HeaderMap::new();
        non_ascii.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(&[0xff]).expect("opaque header value is representable"),
        );
        assert_eq!(
            resolve_rate_limit_client_key_from_headers(proxy, &non_ascii, &trusted_proxies),
            ("10.0.0.5".into(), ClientKeySource::Peer)
        );
    }

    #[test]
    fn test_malformed_or_excessive_forwarded_chain_falls_back_to_peer() {
        let trusted_proxies = trusted(&["10.0.0.0/8"]);
        let proxy = peer("10.0.0.5:443");
        let too_many_hops = std::iter::repeat_n("198.51.100.20", MAX_FORWARDED_FOR_HOPS + 1)
            .collect::<Vec<_>>()
            .join(",");
        let oversized = "1".repeat(MAX_FORWARDED_FOR_BYTES + 1);

        for forwarded_for in [
            "",
            "unknown",
            "198.51.100.20,,10.0.0.6",
            "attacker-token, 198.51.100.20, 10.0.0.6",
            too_many_hops.as_str(),
            oversized.as_str(),
        ] {
            assert_eq!(
                resolve_rate_limit_client_key(proxy, Some(forwarded_for), &trusted_proxies),
                ("10.0.0.5".into(), ClientKeySource::Peer),
                "invalid chain must fail to the authoritative peer: {forwarded_for:?}"
            );
        }
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
    fn test_public_health_response_is_stable_and_value_free() {
        for (healthy, expected_status) in [(true, "healthy"), (false, "degraded")] {
            let (status, Json(body)) = public_health_response(healthy);
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, serde_json::json!({ "status": expected_status }));
        }
    }

    #[test]
    fn test_readiness_response_with_db_is_ready_and_value_free() {
        let (status, Json(body)) = readiness_response(ReadinessStatus::Ready);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({ "status": "ready" }));
    }

    #[test]
    fn test_all_readiness_failures_have_one_stable_value_free_projection() {
        for internal_status in [
            ReadinessStatus::ConfigInvalid,
            ReadinessStatus::SecretProviderUnavailable,
            ReadinessStatus::DatabaseUnavailable,
            ReadinessStatus::MigrationsNotApplied,
            ReadinessStatus::MigrationsFailed,
            ReadinessStatus::DatabaseUnusable,
        ] {
            let (status, Json(body)) = readiness_response(internal_status);
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body, serde_json::json!({ "status": "not_ready" }));
        }
    }

    #[test]
    fn test_public_readiness_response_without_db_is_service_unavailable() {
        let (status, Json(body)) = readiness_response(ReadinessStatus::DatabaseUnavailable);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, serde_json::json!({ "status": "not_ready" }));
    }

    #[tokio::test]
    async fn test_readiness_probe_cache_never_queues_parallel_refreshes() {
        let cache = ReadinessProbeCache {
            latest: tokio::sync::RwLock::new(None),
            refresh_permit: tokio::sync::Semaphore::new(1),
        };
        let first = cache
            .refresh_permit
            .try_acquire()
            .expect("first caller owns the single refresh permit");
        assert!(
            cache.refresh_permit.try_acquire().is_err(),
            "a readiness burst must not queue another DB probe"
        );
        drop(first);
        assert!(
            cache.refresh_permit.try_acquire().is_ok(),
            "the permit is immediately reusable after refresh completion"
        );
    }

    #[test]
    fn test_readiness_probe_cache_never_serves_stale_ready() {
        assert_eq!(
            fresh_readiness_snapshot(Some((Instant::now(), ReadinessStatus::Ready))),
            Some(ReadinessStatus::Ready)
        );
        let stale = Instant::now()
            .checked_sub(READINESS_PROBE_CACHE_TTL + Duration::from_millis(1))
            .expect("test instant can move back by the cache ttl");
        assert_eq!(
            fresh_readiness_snapshot(Some((stale, ReadinessStatus::Ready))),
            None,
            "an in-flight refresh cannot make an expired Ready snapshot authoritative"
        );
    }

    #[test]
    fn test_readiness_probe_cache_expires_ready_at_exact_ttl_boundary() {
        let now = Instant::now();
        let boundary = now
            .checked_sub(READINESS_PROBE_CACHE_TTL)
            .expect("test instant can move back by the cache ttl");
        let still_fresh = now
            .checked_sub(READINESS_PROBE_CACHE_TTL - Duration::from_millis(1))
            .expect("test instant can move within the cache ttl");

        assert_eq!(
            fresh_readiness_snapshot_at(Some((boundary, ReadinessStatus::Ready)), now),
            None,
            "a Ready result must fail closed as soon as its TTL is exhausted"
        );
        assert_eq!(
            fresh_readiness_snapshot_at(
                Some((still_fresh, ReadinessStatus::DatabaseUnusable)),
                now
            ),
            Some(ReadinessStatus::DatabaseUnusable),
            "a fresh dependency failure remains authoritative without another DB probe"
        );
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
        // Lower-tier mutations whose family root is unclassified — see
        // unclassified_family_mutation_permission. Without a classification these would
        // fail-closed to admin and the request/audit-tier handlers would be unreachable.
        "/api/events/alerts/00000000-0000-0000-0000-000000000000/ack",
        "/api/events/alerts/batch/ack",
        "/api/audit/log/verify",
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
        "/api/admin/sites",
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
        "/api/vm/day2/approve",
        "/api/vm/day2/lock",
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
        "/api/datacenter/firmware/exception/f1/approve",
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
            // Every resolved permission must be one the model recognizes. `audit` is
            // included for the audit-chain verify mutation (the first audit-tier mutation).
            assert!(
                ["request", "execute", "approve", "audit", "admin"].contains(&permission),
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
    fn test_dump_route_meta_tier_mirrors_middleware_decisions() {
        // exempt surface
        assert_eq!(route_meta_tier("GET", "/health"), Some("public"));
        assert_eq!(
            route_meta_tier("POST", "/api/auth/local/login"),
            Some("public")
        );
        // mutations resolve through the central mutating table
        assert_eq!(route_meta_tier("POST", "/api/admin/tokens"), Some("admin"));
        assert_eq!(route_meta_tier("POST", "/api/requests"), Some("request"));
        assert_eq!(
            route_meta_tier("POST", "/api/requests/{id}/approve"),
            Some("approve")
        );
        assert_eq!(
            route_meta_tier("POST", "/api/requests/{id}/validate"),
            Some("execute")
        );
        assert_eq!(
            route_meta_tier("POST", "/api/maintain/software/execute/{id}"),
            Some("software.deployment.execute")
        );
        assert_eq!(
            route_meta_tier("DELETE", "/api/network/firewall/rules/{id}"),
            Some("network.firewall.manage")
        );
        // self-service mutations are gated like reads, not fail-closed admin
        assert_eq!(
            route_meta_tier("POST", "/api/notifications/{id}/read"),
            Some("request")
        );
        assert_eq!(
            route_meta_tier("PUT", "/api/me/preferences"),
            Some("request")
        );
        // reads: audit-grade, sensitive-admin, operator shift queue, ordinary
        assert_eq!(route_meta_tier("GET", "/api/activity/audit"), Some("audit"));
        assert_eq!(
            route_meta_tier("GET", "/api/requests/{id}/audit"),
            Some("audit")
        );
        assert_eq!(route_meta_tier("GET", "/api/admin/tokens"), Some("admin"));
        assert_eq!(
            route_meta_tier("GET", "/api/ops/shift/summary"),
            Some("execute")
        );
        assert_eq!(route_meta_tier("GET", "/api/requests"), Some("request"));
        assert_eq!(
            route_meta_tier("GET", "/api/events/alerts"),
            Some(OperationCapability::MonitoringAlertRead.as_str())
        );
        assert_eq!(
            route_meta_tier("POST", "/api/events/alerts/{event_id}/ack"),
            Some(OperationCapability::MonitoringAlertAcknowledge.as_str())
        );
        assert_eq!(
            route_meta_tier("POST", "/api/events/alerts/batch/ack"),
            Some(OperationCapability::MonitoringAlertAcknowledge.as_str())
        );
        // agent subrouter: open bootstrap endpoints are public, the rest carry
        // the agent bearer token; the human /api/admin/agents prefix stays admin
        assert_eq!(
            route_meta_tier("POST", "/api/agents/register"),
            Some("public")
        );
        assert_eq!(
            route_meta_tier("GET", "/api/agents/cp-public-key"),
            Some("public")
        );
        assert_eq!(
            route_meta_tier("POST", "/api/agents/{agent_id}/heartbeat"),
            Some("agent")
        );
        assert_eq!(route_meta_tier("GET", "/api/admin/agents"), Some("admin"));
        assert_eq!(
            route_meta_tier("POST", "/api/admin/agents/enrollment-challenges"),
            Some("admin")
        );
        // The separately mounted integration management router is an exact
        // admin surface; unrelated contracts.rs integration routes are not
        // blanket-promoted by prefix.
        assert_eq!(route_meta_tier("GET", "/api/integrations"), Some("admin"));
        assert_eq!(
            route_meta_tier("POST", "/api/integrations/{id}/circuit/reset"),
            Some("admin")
        );
        assert_eq!(
            route_meta_tier("GET", "/api/integrations/readiness"),
            Some("audit")
        );
        assert_eq!(
            route_meta_tier("POST", "/api/integrations/{connection_id}/webhook"),
            Some("webhook")
        );
        // the synthetic ANY placeholder cannot be attested
        assert_eq!(route_meta_tier("ANY", "/api/requests"), None);
    }

    #[test]
    fn test_integration_management_route_meta_is_exactly_admin() {
        let routes = [
            ("POST", "/api/integrations"),
            ("GET", "/api/integrations"),
            ("GET", "/api/integrations/{id}"),
            ("PUT", "/api/integrations/{id}"),
            ("DELETE", "/api/integrations/{id}"),
            ("POST", "/api/integrations/{id}/webhook-secret"),
            ("POST", "/api/integrations/{id}/test"),
            ("GET", "/api/integrations/{id}/health"),
            ("POST", "/api/integrations/{id}/credential-expiry"),
            ("GET", "/api/integrations/credentials/expiring"),
            ("GET", "/api/integrations/circuits"),
            ("GET", "/api/integrations/{id}/circuit"),
            ("POST", "/api/integrations/{id}/circuit/record"),
            ("POST", "/api/integrations/{id}/circuit/reset"),
            ("GET", "/api/integrations/capabilities"),
            ("GET", "/api/integrations/capabilities/{vendor_type}"),
        ];
        assert_eq!(routes.len(), 16);
        for (method, path) in routes {
            assert_eq!(
                route_meta_tier(method, path),
                Some("admin"),
                "{method} {path} must remain admin"
            );
        }
        assert_eq!(
            route_meta_tier("GET", "/api/integrations/readiness"),
            Some("audit")
        );
    }

    #[test]
    fn test_dump_route_meta_envelope_shape() {
        let output = dump_route_meta(
            r#"[
                {"path":"/health","method":"GET"},
                {"path":"/api/admin/tokens","method":"POST"},
                {"path":"/api/agents/register","method":"POST"},
                {"path":"/api/agents/{agent_id}/heartbeat","method":"POST"},
                {"path":"/api/integrations/{connection_id}/webhook","method":"POST"}
            ]"#,
        )
        .expect("dump must succeed");
        let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
        assert_eq!(value["meta"][0]["path"], "/health");
        assert_eq!(value["meta"][0]["tier"], "public");
        assert_eq!(value["meta"][0]["auth_exempt"], true);
        assert_eq!(value["meta"][1]["tier"], "admin");
        assert_eq!(value["meta"][1]["auth_exempt"], false);
        // Public agent bootstrap requires no credential at all; protocol
        // agent and webhook routes bypass human auth but require their own
        // credentials, so auth_exempt remains false for those tiers.
        assert_eq!(value["meta"][2]["tier"], "public");
        assert_eq!(value["meta"][2]["auth_exempt"], true);
        assert_eq!(value["meta"][3]["tier"], "agent");
        assert_eq!(value["meta"][3]["auth_exempt"], false);
        assert_eq!(value["meta"][4]["tier"], "webhook");
        assert_eq!(value["meta"][4]["auth_exempt"], false);
        // the curated OpenAPI document rides along verbatim
        assert_eq!(value["openapi"]["openapi"], "3.1.0");
        // malformed stdin fails with a clear message instead of panicking
        assert!(dump_route_meta("not json").is_err());
    }

    #[test]
    fn test_high_risk_routes_resolve_to_expected_permissions() {
        // Site-registry creation changes the authorization namespace and stays
        // behind the central admin gate in addition to its handler-level guard.
        assert_eq!(
            route_permission_for(&Method::POST, "/api/admin/sites"),
            "admin"
        );
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
        // AD deletion is classified by its functional capability before the
        // broader identity family's coarse execute tier is considered.
        assert_eq!(
            operation_capability_for(&Method::POST, "/api/identity/ad/delete/host1"),
            Some(OperationCapability::IdentityAdComputerDelete)
        );
        // patch-wave DELETE is operator-tier (execute) via the /api/maintain prefix —
        // the method is irrelevant (route_permission_for ignores it), so the DELETE
        // route inherits the same execute gate the patch mutations already enforce.
        assert_eq!(
            route_permission_for(
                &Method::DELETE,
                "/api/maintain/patch/waves/cccccccc-0000-0000-0000-0000000000c1"
            ),
            "execute"
        );
        // Alert ack + audit-chain verify: lower-tier mutations whose family root is
        // unclassified — must resolve to the handler's tier, NOT the admin fail-closed
        // default (which silently made them admin-only before this fix).
        assert_eq!(
            route_permission_for(&Method::POST, "/api/events/alerts/e1/ack"),
            "execute",
            "single alert ack is operator-tier, not Requester self-service"
        );
        assert_eq!(
            route_permission_for(&Method::POST, "/api/events/alerts/batch/ack"),
            "execute",
            "batch alert ack is operator-tier"
        );
        assert_eq!(
            route_permission_for(&Method::POST, "/api/audit/log/verify"),
            "audit",
            "audit-chain verify is audit-tier (matches the handler), not admin"
        );
        // Fail-closed is PRESERVED: the shape matcher does NOT over-match — any OTHER
        // unsafe route under these families still defaults to admin until classified.
        assert_eq!(
            route_permission_for(&Method::POST, "/api/events/alerts/e1/suppress"),
            "admin",
            "a non-ack /api/events mutation stays fail-closed"
        );
        assert_eq!(
            route_permission_for(&Method::DELETE, "/api/events/alerts/e1/ack"),
            "admin",
            "an acknowledgement-shaped path with the wrong method stays fail-closed"
        );
        assert_eq!(
            route_permission_for(&Method::POST, "/api/audit/log/rotate"),
            "admin",
            "a non-verify /api/audit mutation stays fail-closed"
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
    fn test_functional_operation_capability_routes_are_exact_and_fail_closed() {
        let cases = [
            (
                Method::GET,
                "/api/events/alerts",
                OperationCapability::MonitoringAlertRead,
            ),
            (
                Method::POST,
                "/api/events/alerts/42/ack",
                OperationCapability::MonitoringAlertAcknowledge,
            ),
            (
                Method::POST,
                "/api/events/alerts/batch/ack",
                OperationCapability::MonitoringAlertAcknowledge,
            ),
            (
                Method::POST,
                "/api/identity/ad/delete/host1",
                OperationCapability::IdentityAdComputerDelete,
            ),
            (
                Method::POST,
                "/api/network/firewall/rules",
                OperationCapability::NetworkFirewallManage,
            ),
            (
                Method::DELETE,
                "/api/network/firewall/rules/r1",
                OperationCapability::NetworkFirewallManage,
            ),
            (
                Method::DELETE,
                "/api/monitoring/alert-routes/a1",
                OperationCapability::MonitoringAlertRoutingManage,
            ),
            (
                Method::DELETE,
                "/api/datacenter/storage/arrays/a1",
                OperationCapability::StorageArrayDecommission,
            ),
            (
                Method::POST,
                "/api/maintain/software/execute/d1",
                OperationCapability::SoftwareDeploymentExecute,
            ),
        ];
        for (method, path, expected) in cases {
            assert_eq!(
                operation_capability_for(&method, path),
                Some(expected),
                "{method} {path} must resolve to {}",
                expected.as_str()
            );
        }

        for (method, path) in [
            (Method::POST, "/api/events/alerts"),
            (Method::GET, "/api/events/alerts/42/ack"),
            (Method::DELETE, "/api/events/alerts/42/ack"),
            (Method::GET, "/api/events/alerts/"),
            (Method::POST, "/api/events/alerts//ack"),
            (Method::POST, "/api/events/alerts/42/extra/ack"),
            (Method::GET, "/api/identity/ad/delete/host1"),
            (Method::POST, "/api/identity/ad/delete"),
            (Method::POST, "/api/identity/ad/delete/host1/extra"),
            (Method::POST, "/api/network/firewallish/rules"),
            (Method::GET, "/api/network/firewall/rules"),
            (Method::POST, "/api/monitoring/alert-routesish"),
            (Method::GET, "/api/monitoring/alert-routes/a1"),
            (Method::PUT, "/api/datacenter/storage/arrays/a1"),
            (Method::DELETE, "/api/datacenter/storage/arrays/a1/extra"),
            (Method::GET, "/api/maintain/software/execute/d1"),
            (Method::POST, "/api/maintain/software/execute/d1/extra"),
            (Method::POST, "/api/maintain/patch/execute"),
        ] {
            assert_eq!(
                operation_capability_for(&method, path),
                None,
                "{method} {path} must not over-match a functional capability"
            );
        }
    }

    #[test]
    fn operational_reviewer_actions_and_signoffs_require_approver_tier() {
        // Genuine maker/checker sign-offs, plus the access-review claim that
        // establishes the only eligible decider: each must require the approver
        // tier, not the execute tier of its family root.
        for path in [
            "/api/ops/runbook/approve/r1",
            "/api/maintain/patch/approve",
            "/api/maintain/software/approve/s1",
            "/api/protect/backup/restore-approve",
            "/api/build/app-environment/approve/e1",
            "/api/retire/decommission/approve/d1",
            "/api/datacenter/image-factory/promote/i1",
            "/api/datacenter/image-factory/reject/i1",
            "/api/vm/day2/approve",
            "/api/datacenter/firmware/exception/fwex-1/approve",
            "/api/datacenter/firmware/revoke/fwex-1",
            // access-review carries the reviewer claim and all three verdicts
            // (id is mid-path). Claiming must not remain execute-tier because it
            // establishes the only subject allowed to decide the review.
            "/api/identity/access-review/ar1/start",
            "/api/identity/access-review/ar1/approve",
            "/api/identity/access-review/ar1/revoke",
            "/api/identity/access-review/ar1/exempt",
        ] {
            assert_eq!(
                route_permission_for(&Method::POST, path),
                "approve",
                "{path} is a reviewer/approval action and must require the approver tier"
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
        assert_eq!(
            route_permission_for(&Method::POST, "/api/vm/day2/lock"),
            "execute"
        );
        assert_eq!(
            route_permission_for(
                &Method::POST,
                "/api/datacenter/image-factory/promote/i1/extra"
            ),
            "execute",
            "a deeper image-factory child must not inherit promotion authority"
        );
        assert_eq!(
            route_permission_for(&Method::POST, "/api/vm/day2/approve/extra"),
            "execute",
            "a deeper VM Day-2 child must not inherit approval authority"
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
        assert_eq!(
            route_permission_for(&Method::POST, "/api/identity/access-review/ar1/start/extra"),
            "execute"
        );
        assert_eq!(
            route_permission_for(
                &Method::POST,
                "/api/datacenter/firmware/exception/fwex-1/approve/extra"
            ),
            "execute"
        );
        assert_eq!(
            route_permission_for(&Method::POST, "/api/datacenter/firmware/exception"),
            "execute",
            "the maker request remains execute-tier and never self-approves"
        );
    }

    #[test]
    fn human_signoff_route_manifest_is_closed_and_method_aware() {
        for path in [
            "/api/requests/r1/approve",
            "/api/requests/r1/reject",
            "/api/requests/r1/rework",
            "/api/requests/batch/approve",
            "/api/requests/batch/reject",
            "/api/requests/batch/rework",
            "/api/requests/r1/approve-live-apply",
            "/api/requests/r1/steps/s1/approve-live-apply",
            "/api/ops/runbook/approve/r1",
            "/api/ops/emergency/initiate",
            "/api/ops/emergency/approve/e1",
            "/api/ops/emergency/execute/e1",
            "/api/ops/emergency/verify/e1",
            "/api/ops/emergency/close/e1",
            "/api/admin/agents/enrollment-challenges",
            "/api/admin/agents/a1/approve",
            "/api/admin/agents/a1/revoke",
            "/api/admin/agents/live-apply-jobs",
            "/api/protect/snapshot/review",
            "/api/protect/legal-hold/release/lh1",
            "/api/analytics/aiops/review/a1",
            "/api/identity/access-review/r1/start",
            "/api/identity/access-review/r1/approve",
            "/api/identity/access-review/r1/revoke",
            "/api/identity/access-review/r1/exempt",
            "/api/identity/ad/quarantine-recovery/review/host1",
            "/api/identity/ad/quarantine-recovery/approve/r1",
            "/api/identity/ad/quarantine-recovery/apply/r1",
            "/api/identity/shares/recertify/s1",
            "/api/audit/compliance/controls/c1/assess",
            "/api/audit/compliance/findings/f1/waive",
            "/api/datacenter/image-factory/reject/i1",
            "/api/datacenter/firmware/revoke/fwex-1",
        ] {
            assert!(
                requires_verified_human_signoff(&Method::POST, path),
                "missing verified-human route classification for {path}"
            );
            assert!(
                !requires_verified_human_signoff(&Method::GET, path),
                "safe reads must not be classified as sign-off mutations: {path}"
            );
        }

        for path in [
            "/api/requests/r1/execute",
            "/api/datacenter/firmware/exception",
            "/api/audit/compliance/findings/f1/resolve",
            "/api/cmdb/servicenow/approve/sn1",
            "/api/maintain/certificates/approve/c1",
        ] {
            assert!(
                !requires_verified_human_signoff(&Method::POST, path),
                "{path}"
            );
        }

        assert!(
            !requires_verified_human_signoff(&Method::POST, "/api/analytics/aiops/review/a1/extra"),
            "AIOps review authority must not leak to deeper descendants"
        );
        assert!(
            !requires_verified_human_signoff(
                &Method::POST,
                "/api/protect/legal-hold/release/lh1/extra"
            ),
            "legal-hold release authority must match exactly one hold id"
        );
        assert!(
            !requires_verified_human_signoff(
                &Method::POST,
                "/api/identity/access-review/r1/start/extra"
            ),
            "reviewer-claim authority must match exactly one review id"
        );
    }

    #[test]
    fn exact_interactive_authority_proves_human_independent_of_provider_label() {
        use crate::human_authority::{HumanAuthorityMode, InteractiveHumanAuthorityContext};
        use ryuki_engine::auth::{ActorClass, APP_ROLE_PLATFORM_ADMIN};

        for (provider, issuer, carrier) in [
            ("local", "urn:ryuki:local", "persisted-session"),
            ("entra-id", "https://issuer.example/tenant", "entra-id"),
        ] {
            let principal_binding = test_principal_binding();
            let session = AuthSession {
                display_user_id: principal_binding.principal_id.to_string(),
                principal_id: Some(principal_binding.principal_id),
                display_name: "Verified Human".into(),
                roles: vec![APP_ROLE_PLATFORM_ADMIN.to_string()],
                token_valid: true,
                provider_mode: carrier.into(),
                actor_class: ActorClass::VerifiedHuman,
                site_scope: vec!["SITE-A".into()],
                environment_scope: vec!["prod".into()],
            };
            let authority = InteractiveHumanAuthorityContext {
                principal_binding,
                provider: provider.into(),
                issuer: issuer.into(),
                subject: "external-human-subject".into(),
                identity_epoch: 2,
                assignment_version: 7,
                roles: session.roles.clone(),
                site_mode: HumanAuthorityMode::Scoped,
                site_scope: session.site_scope.clone(),
                environment_mode: HumanAuthorityMode::Scoped,
                environment_scope: session.environment_scope.clone(),
            };
            assert!(interactive_authority_matches_session(
                &session,
                Some(&authority)
            ));

            for actor_class in [
                ActorClass::Workload,
                ActorClass::Unknown,
                ActorClass::Simulated,
            ] {
                let rejected = AuthSession {
                    actor_class,
                    // Keep the same human-looking provider label and roles: the
                    // typed actor class, not the carrier string, is authoritative.
                    ..session.clone()
                };
                assert!(!interactive_authority_matches_session(
                    &rejected,
                    Some(&authority)
                ));
            }
            assert!(!interactive_authority_matches_session(&session, None));
            let mut mismatched = authority.clone();
            mismatched.subject = "different-subject".into();
            assert!(interactive_authority_matches_session(
                &session,
                Some(&mismatched)
            ));
            mismatched.principal_binding.principal_id = test_principal_id();
            assert!(!interactive_authority_matches_session(
                &session,
                Some(&mismatched)
            ));
        }
    }

    #[test]
    fn platform_global_administration_requires_exact_global_human_authority() {
        use crate::human_authority::{HumanAuthorityMode, InteractiveHumanAuthorityContext};
        use ryuki_engine::auth::{ActorClass, APP_ROLE_PLATFORM_ADMIN};

        for path in [
            "/api/admin/tokens",
            "/api/admin/tokens/t1",
            "/api/admin/sessions",
            "/api/admin/sessions/s1",
            "/api/identity/access-review/campaign",
            "/api/identity/access-review/campaign/c1",
            "/api/identity/access-review/campaigns",
        ] {
            assert!(requires_global_verified_human_administration(path));
        }
        assert!(!requires_global_verified_human_administration(
            "/api/admin/platform-settings"
        ));
        assert!(!requires_global_verified_human_administration(
            "/api/identity/access-review/campaign/c1/extra"
        ));
        assert!(!requires_global_verified_human_administration(
            "/api/identity/access-review/reviews"
        ));

        let principal_binding = test_principal_binding();
        let session = AuthSession {
            display_user_id: principal_binding.principal_id.to_string(),
            principal_id: Some(principal_binding.principal_id),
            roles: vec![APP_ROLE_PLATFORM_ADMIN.to_string()],
            token_valid: true,
            actor_class: ActorClass::VerifiedHuman,
            provider_mode: "persisted-session".into(),
            ..AuthSession::default()
        };
        let mut authority = InteractiveHumanAuthorityContext {
            principal_binding,
            provider: "local".into(),
            issuer: "urn:ryuki:local".into(),
            subject: "local-admin-login-name".into(),
            identity_epoch: 1,
            assignment_version: 1,
            roles: session.roles.clone(),
            site_mode: HumanAuthorityMode::Global,
            site_scope: vec![],
            environment_mode: HumanAuthorityMode::Global,
            environment_scope: vec![],
        };
        assert!(global_interactive_authority_matches_session(
            &session,
            Some(&authority)
        ));

        authority.site_mode = HumanAuthorityMode::Scoped;
        authority.site_scope = vec!["SITE-A".into()];
        assert!(!global_interactive_authority_matches_session(
            &session,
            Some(&authority)
        ));
        authority.site_mode = HumanAuthorityMode::Global;
        authority.site_scope.clear();
        let workload = AuthSession {
            actor_class: ActorClass::Workload,
            provider_mode: "persisted-session".into(),
            ..session
        };
        assert!(!global_interactive_authority_matches_session(
            &workload,
            Some(&authority)
        ));
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
        // approve-live-apply mints a CP-signed live-mutation grant — admin-tier,
        // never the execute fallback.
        assert_eq!(
            requests_route_permission("/api/requests/abc/approve-live-apply"),
            Some("admin")
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

    /// Static/mock identities retain ordinary demo administration but are
    /// explicitly barred from human approvals.
    #[test]
    fn test_static_dry_run_session_cannot_satisfy_approval_permission() {
        let session = AuthSession::static_dry_run();
        for perm in ["request", "execute", "admin"] {
            assert!(
                ryuki_engine::auth::check_permission(&session, perm),
                "static-dry-run must satisfy permission {perm}"
            );
        }
        assert!(!ryuki_engine::auth::check_permission(&session, "approve"));
        // fail-closed default is "admin"; static-dry-run satisfies it too.
        assert!(ryuki_engine::auth::check_permission(
            &session,
            DEFAULT_ROUTE_PERMISSION
        ));
        // And it satisfies every concrete mutating route resolution.
        for path in MUTATING_ROUTES {
            let required = route_permission_for(&Method::POST, path);
            if required == "approve" {
                assert!(!ryuki_engine::auth::check_permission(&session, required));
            } else {
                assert!(
                    ryuki_engine::auth::check_permission(&session, required),
                    "static-dry-run must pass non-signoff route {path} (requires {required})"
                );
            }
        }
    }

    // ---- B3: read authentication ----

    /// A logged-in Auditor: holds exactly `audit`, fails `admin`. The read tier
    /// (ordinary reads need `audit`, sensitive reads need `admin`) is built so
    /// an Auditor reads ordinary GETs but is refused sensitive ones.
    fn auditor_session() -> AuthSession {
        let principal_id = test_principal_id();
        AuthSession {
            display_user_id: principal_id.to_string(),
            principal_id: Some(principal_id),
            display_name: "Auditor One".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_AUDITOR.to_string()],
            token_valid: true,
            actor_class: ryuki_engine::auth::ActorClass::VerifiedHuman,
            provider_mode: "persisted-session".into(),
            ..Default::default()
        }
    }

    /// Hardcoded representative list of non-exempt GET routes the API exposes,
    /// kept in sync by hand with `contracts::routes()` (mirrors the
    /// MUTATING_ROUTES pattern). Covers all three sensitive read prefixes plus a
    /// spread of ordinary reads. The walk test below pins the read tier and the
    /// gate invariants against every entry.
    const GET_ROUTES: &[&str] = &[
        // requester-owned plus ordinary audit reads.
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
        "/api/audit/log/verify/00000000-0000-0000-0000-000000000000",
        "/api/ops/runbook/catalog",
        "/api/ops/incident/active",
        "/api/observe/logs/coverage",
        "/api/cmdb/export",
        "/api/analytics/capacity",
        "/api/network/dns/records",
        "/api/datacenter/storage/arrays",
        "/api/datacenter/network/readiness",
        "/api/datacenter/network/capacity",
        "/api/datacenter/network/ports",
        "/api/datacenter/network/vlans",
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

    /// `read_permission_for` returns the exact closed read class: self-owned
    /// request reads, ordinary audit reads, approver/operator data, or
    /// sensitive admin.
    #[test]
    fn test_read_permission_tier() {
        // self-owned/requester read
        assert_eq!(read_permission_for("/api/requests"), "request");
        assert_eq!(
            read_permission_for("/api/requests/00000000-0000-0000-0000-000000000000"),
            "request"
        );
        // ordinary read defaults to audit
        assert_eq!(read_permission_for("/api/ops/runbook/catalog"), "audit");
        assert_eq!(read_permission_for("/api/approvals/pending"), "approve");
        assert_eq!(
            read_permission_for("/api/ops/scheduler/schedules"),
            "execute"
        );
        assert_eq!(
            read_permission_for("/api/ops/scheduler/executions"),
            "execute"
        );
        // each sensitive prefix root + a sub-path under it
        assert_eq!(read_permission_for("/api/protect/secrets"), "admin");
        assert_eq!(read_permission_for("/api/protect/secrets/s1"), "admin");
        assert_eq!(read_permission_for("/api/ops/emergency"), "admin");
        assert_eq!(read_permission_for("/api/ops/emergency/history"), "admin");
        assert_eq!(read_permission_for("/api/admin"), "admin");
        assert_eq!(read_permission_for("/api/admin/tokens"), "admin");
        for path in [
            "/api/datacenter/network/readiness",
            "/api/datacenter/network/capacity",
            "/api/datacenter/network/ports",
            "/api/datacenter/network/vlans",
        ] {
            assert_eq!(read_permission_for(path), "admin", "{path}");
        }
        // a near-miss that is NOT a sensitive prefix stays audit
        assert_eq!(
            read_permission_for("/api/protect/repository-capacity"),
            "audit"
        );
        assert_eq!(
            read_permission_for("/api/totally-new/read-surface"),
            "audit",
            "new reads fail closed to audit"
        );
    }

    #[test]
    fn test_network_inventory_reads_are_admin_only_but_contract_stays_requester_readable() {
        let auditor = auditor_session();
        let principal_id = test_principal_id();
        let requester = AuthSession {
            display_user_id: principal_id.to_string(),
            principal_id: Some(principal_id),
            roles: vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()],
            token_valid: true,
            actor_class: ryuki_engine::auth::ActorClass::VerifiedHuman,
            provider_mode: "persisted-session".into(),
            ..Default::default()
        };
        let admin = AuthSession::static_dry_run();

        for path in [
            "/api/datacenter/network/readiness",
            "/api/datacenter/network/capacity",
            "/api/datacenter/network/ports",
            "/api/datacenter/network/vlans",
        ] {
            assert_eq!(read_permission_for(path), "admin", "{path}");
            assert!(!read_authorized(&auditor, path), "auditor refused {path}");
            assert!(
                !read_authorized(&requester, path),
                "requester refused {path}"
            );
            assert!(read_authorized(&admin, path), "admin reads {path}");
        }

        let contract = "/api/datacenter/network-contract";
        assert_eq!(read_permission_for(contract), "request");
        assert!(read_authorized(&requester, contract));
    }

    #[test]
    fn test_requester_read_manifest_is_closed_and_shape_exact() {
        let principal_id = test_principal_id();
        let requester = AuthSession {
            display_user_id: principal_id.to_string(),
            principal_id: Some(principal_id),
            roles: vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()],
            token_valid: true,
            actor_class: ryuki_engine::auth::ActorClass::VerifiedHuman,
            provider_mode: "persisted-session".into(),
            ..Default::default()
        };
        let id = "00000000-0000-0000-0000-000000000000";

        for path in [
            "/api/requests".to_string(),
            "/api/auth/local/roles".to_string(),
            "/api/auth/local/me".to_string(),
            "/api/auth/local/decision".to_string(),
            format!("/api/requests/{id}"),
            format!("/api/requests/{id}/policy-eval"),
            format!("/api/requests/{id}/execution-job"),
            "/api/catalog/categories".to_string(),
            "/api/catalog/offerings-contract".to_string(),
            "/api/catalog/recommendations-contract".to_string(),
            "/api/requests/intake-support-contract".to_string(),
            "/api/metrics/series".to_string(),
            "/api/events".to_string(),
            "/api/operations/failure-patterns".to_string(),
            "/api/observe/monitoring-review-queue".to_string(),
            "/api/notifications".to_string(),
            "/api/notifications/unread-count".to_string(),
            "/api/notifications/read-all".to_string(),
            "/api/notifications/n-1/read".to_string(),
            "/api/operations/runbook-launch-contract".to_string(),
        ] {
            assert_eq!(read_permission_for(&path), "request", "{path}");
            assert!(read_authorized(&requester, &path), "{path}");
        }

        for path in [
            format!("/api/requests/{id}/audit"),
            format!("/api/requests/{id}/evidence"),
            format!("/api/requests/{id}/approval-decisions"),
            format!("/api/requests/{id}/policy-eval/extra"),
            "/api/events/alerts".to_string(),
            "/api/observe/oncall/contacts".to_string(),
            "/api/identity/access-review/due".to_string(),
            "/api/identity/shares/stale-owners".to_string(),
            "/api/audit/compliance/findings".to_string(),
            "/api/audit/compliance/reports/00000000-0000-0000-0000-000000000000".to_string(),
            "/api/ops/runbook/executions".to_string(),
            "/api/ops/incident/active".to_string(),
            "/api/network/dns/records".to_string(),
            "/api/datacenter/storage/arrays".to_string(),
            "/api/notifications/n-1".to_string(),
            "/api/notifications/n-1/private".to_string(),
            "/api/catalog/future-sensitive".to_string(),
            "/api/metrics/future-sensitive".to_string(),
            "/api/future-sensitive-contract".to_string(),
            "/api/totally-new/read-surface".to_string(),
        ] {
            assert_ne!(read_permission_for(&path), "request", "{path}");
            assert!(!read_authorized(&requester, &path), "{path}");
        }
    }

    #[test]
    fn test_requester_contract_manifest_matches_current_static_contracts() {
        let manifest: std::collections::HashSet<_> =
            REQUESTER_CONTRACT_PATHS.iter().copied().collect();
        assert_eq!(
            manifest.len(),
            REQUESTER_CONTRACT_PATHS.len(),
            "duplicate entries obscure review of the exact Requester contract surface"
        );
        let routed: std::collections::HashSet<_> = include_str!("contracts.rs")
            .split('"')
            .filter(|value| value.starts_with("/api/") && value.ends_with("-contract"))
            .collect();
        assert_eq!(
            manifest, routed,
            "a static contract route was added or removed without reviewing its Requester tier"
        );
    }

    /// The shift queue is operator working data: its per-item reads require the
    /// `execute` tier at the CENTRAL gate (open-item descriptions + assignees must
    /// not be `audit`/`request`-readable). The static contract advertisement (not
    /// under `/shift/`) stays ordinary-readable.
    #[test]
    fn test_shift_queue_reads_require_execute() {
        let role = |r: &str| {
            let principal_id = test_principal_id();
            AuthSession {
                display_user_id: principal_id.to_string(),
                principal_id: Some(principal_id),
                display_name: "u".into(),
                roles: vec![r.to_string()],
                token_valid: true,
                actor_class: ryuki_engine::auth::ActorClass::VerifiedHuman,
                provider_mode: "persisted-session".into(),
                ..Default::default()
            }
        };
        let operator = role(ryuki_engine::auth::APP_ROLE_VMWARE_OPERATOR); // holds execute
        let auditor = auditor_session(); // holds audit, not execute
        let requester = role(ryuki_engine::auth::APP_ROLE_REQUESTER); // holds request only
        for path in [
            "/api/ops/shift/summary",
            "/api/ops/shift/handover",
            "/api/ops/shift/my-items",
            "/api/ops/shift/stale",
            "/api/ops/shift/items",
        ] {
            assert_eq!(
                read_permission_for(path),
                "execute",
                "{path} is execute-tier"
            );
            assert!(read_authorized(&operator, path), "operator reads {path}");
            assert!(!read_authorized(&auditor, path), "auditor refused {path}");
            assert!(
                !read_authorized(&requester, path),
                "requester refused {path}"
            );
        }
        // The exact static contract advertisement is Requester-readable; a
        // nested near-miss is unclassified and therefore defaults to audit.
        assert_eq!(read_permission_for("/api/ops/shift-contract"), "request");
        assert_eq!(read_permission_for("/api/ops/shift-contract/foo"), "audit");
        assert!(read_authorized(&auditor, "/api/ops/shift-contract"));
        assert!(read_authorized(&auditor, "/api/ops/shift-contract/foo"));
        // The exact family root IS execute-gated.
        assert_eq!(read_permission_for("/api/ops/shift"), "execute");
        // admin superuser still reads everything.
        assert!(read_authorized(
            &AuthSession::static_dry_run(),
            "/api/ops/shift/items"
        ));
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
                ["request", "audit", "admin"].contains(&required),
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

            // A Requester (holds only `request`) reads only explicitly
            // classified self-owned/static surfaces. Unclassified operational
            // reads fail closed to audit.
            let principal_id = test_principal_id();
            let requester = AuthSession {
                display_user_id: principal_id.to_string(),
                principal_id: Some(principal_id),
                display_name: "Requester One".into(),
                roles: vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()],
                token_valid: true,
                actor_class: ryuki_engine::auth::ActorClass::VerifiedHuman,
                provider_mode: "persisted-session".into(),
                ..Default::default()
            };
            if required != "request" || is_audit_read_path(path) {
                assert!(
                    !read_authorized(&requester, path),
                    "requester must be refused non-request GET {path}"
                );
            } else {
                assert!(
                    read_authorized(&requester, path),
                    "requester must pass explicitly classified GET {path}"
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
        // The approval ledger + quorum reads are audit-grade too (2nd-swarm hardening).
        assert!(is_audit_read_path(
            "/api/requests/00000000-0000-0000-0000-000000000000/approval-decisions"
        ));
        assert!(is_audit_read_path(
            "/api/requests/00000000-0000-0000-0000-000000000000/approval-quorum"
        ));
        assert!(!is_audit_read_path(
            "/api/requests/00000000-0000-0000-0000-000000000000"
        ));
        assert!(!is_audit_read_path("/api/requests"));
        assert!(!is_audit_read_path("/api/activity"));

        let auditor = auditor_session();
        let principal_id = test_principal_id();
        let requester = AuthSession {
            display_user_id: principal_id.to_string(),
            principal_id: Some(principal_id),
            display_name: "Requester One".into(),
            roles: vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()],
            token_valid: true,
            actor_class: ryuki_engine::auth::ActorClass::VerifiedHuman,
            provider_mode: "persisted-session".into(),
            ..Default::default()
        };
        for path in [
            "/api/activity/audit",
            "/api/requests/00000000-0000-0000-0000-000000000000/audit",
            "/api/requests/00000000-0000-0000-0000-000000000000/evidence",
            "/api/requests/00000000-0000-0000-0000-000000000000/approval-decisions",
            "/api/requests/00000000-0000-0000-0000-000000000000/approval-quorum",
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
            // approve-live-apply mints a CP-signed grant authorising live
            // infrastructure mutation — it MUST resolve to admin, not fall back
            // to execute. Pinned so a gate-resolver refactor can't silently
            // downgrade the most-privileged request-family branch.
            (format!("/api/requests/{id}/approve-live-apply"), "admin"),
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

    #[test]
    fn non_entra_startup_cannot_leave_external_authenticator_paths_active() {
        let source = include_str!("main.rs");
        let disable = ["disable_current_authenticator", "_runtimes"].concat();
        let call = source
            .find(disable.as_str())
            .expect("non-Entra startup must durably disable external authenticator paths");
        let branch = source[..call]
            .rfind("(false, None) => {")
            .expect("disable call must be in the non-Entra/no-R branch");
        let prewarm_needle = ["session_lookup_admission::", "prewarm"].concat();
        let prewarm = source[call..]
            .find(prewarm_needle.as_str())
            .map(|offset| call + offset)
            .expect("session prewarm must remain after external-path disable");
        assert!(branch < call && call < prewarm);

        let fail_closed = &source[branch..prewarm];
        assert!(fail_closed.contains("if let Err(error)"));
        assert!(fail_closed.contains("std::process::exit(1)"));
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
        assert!(
            count.0 >= 9,
            "platform_config must retain at least the original 9 seeded settings; got {}",
            count.0
        );

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
