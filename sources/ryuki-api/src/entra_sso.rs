//! Entra ID browser SSO — OIDC authorization-code + PKCE (S256) sign-in.
//!
//! This module owns the interactive Entra ID sign-in flow for `AuthMode::EntraId`
//! deployments. It complements (never replaces) the existing bearer-token path:
//! `entra_auth::EntraTokenValidator` keeps validating `Authorization: Bearer`
//! JWTs for API callers, while this flow lets a BROWSER sign in and ride the
//! same persisted-session + mode-selected cookie machinery the local login
//! uses (`__Host-ryuki_session` for HTTPS, unprefixed only for explicit
//! non-Secure loopback development/test configuration). In EntraId mode the
//! session resolver honors ONLY the validated SSO
//! providers (`entra-id` and the generic `oidc` flow), never a stale
//! local/dry-run session — mirroring the symmetric restriction Local mode
//! already applies.
//!
//! # Endpoints
//! - `GET /api/auth/entra/authorize-url` — generates `state`/`nonce`/PKCE
//!   verifier (all CSPRNG), persists them via the existing single-use
//!   `oidc_login_states` store (10-minute TTL), and returns the tenant
//!   authorize URL as JSON for the portal server function to navigate to.
//! - `GET /api/auth/entra/callback` — redeems the single-use state, exchanges
//!   the code at the tenant token endpoint (PKCE public client — NO client
//!   secret), validates the returned id_token (RS256 + iss/aud/exp/nbf + nonce
//!   via the existing [`OidcIdTokenValidator`]), mints the SAME persisted
//!   session + cookie shape local login mints, and 302-redirects to `/`.
//!
//! Both endpoints are gated on `auth_mode == entra-id` (400 for any other mode,
//! mirroring `mock_login_gate`'s wrong-mode shape) and on the SSO config being
//! complete (tenant + client + redirect URI).
//!
//! # Endpoint derivation
//! Microsoft Entra publishes fixed per-tenant URL patterns, so endpoints are
//! DERIVED from `entra_authority` + `entra_tenant_id` exactly like
//! `EntraTokenValidator` derives its JWKS URI (no discovery-document fetch):
//! - authorize: `{authority}/{tenant}/oauth2/v2.0/authorize`
//! - token:     `{authority}/{tenant}/oauth2/v2.0/token`
//! - JWKS:      `{authority}/{tenant}/discovery/v2.0/keys`
//! - issuer:    `{authority}/{tenant}/v2.0`
//!
//! Pointing `RYUKI_ENTRA_AUTHORITY` at a local stub IdP that serves those
//! paths exercises the FULL production network path in tests.
//!
//! # Security properties
//! - `state` is single-use (atomic `DELETE .. RETURNING`) and expires in 10
//!   minutes; `nonce` is compared against the id_token claim AFTER signature
//!   validation; the PKCE verifier never leaves the server except to the token
//!   endpoint over the exchange itself.
//! - Per-browser CSRF binding: the authorize-url response carries a `binding`
//!   value (also set as a mode-selected HttpOnly binding cookie) that must
//!   match the cookie presented to the callback, so a state minted in an
//!   attacker's own flow cannot be redeemed in a victim's browser
//!   (login-CSRF defense — same design as the generic OIDC flow).
//! - Public client: the token exchange sends NO `client_secret` field.
//!   Confidential-client deployments are served by the generic `oidc.*` flow.
//! - Session cookies are emitted only through the retained Entra issuer
//!   capability; no weaker Entra-specific policy exists.
//! - No token material, code, verifier, or session id is ever logged; id_token
//!   failures log only the validator's safe reason string.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Query, Request};
use axum::http::header::LOCATION;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::oidc_callback::{
    OidcCallbackQuery, OidcIdTokenValidator, ReqwestTokenExchanger, TokenExchanger, TokenRequest,
};

/// Entra ID app roles are always issued in the `roles` claim (same claim the
/// bearer-token validator's `EntraClaims` consumes).
const ENTRA_ROLES_CLAIM: &str = "roles";

/// Scopes requested for the browser sign-in. `openid` is mandatory for an
/// id_token; profile/email populate display identity claims.
const ENTRA_SCOPES: &str = "openid profile email";

/// Derived per-tenant endpoints (see module docs for the fixed URL patterns).
struct EntraEndpoints {
    authorize: String,
    token: String,
    jwks: String,
    issuer: String,
}

fn derive_entra_endpoints(authority: &str, tenant_id: &str) -> EntraEndpoints {
    let authority = authority.trim_end_matches('/');
    EntraEndpoints {
        authorize: format!("{authority}/{tenant_id}/oauth2/v2.0/authorize"),
        token: format!("{authority}/{tenant_id}/oauth2/v2.0/token"),
        jwks: format!("{authority}/{tenant_id}/discovery/v2.0/keys"),
        issuer: format!("{authority}/{tenant_id}/v2.0"),
    }
}

/// All Entra-SSO dependencies, injected as a single axum `Extension` (the
/// `OidcCallbackDeps` pattern). Built ONCE at startup from the app config;
/// tests build it against a local stub authority through the same
/// constructor, so they exercise the production exchanger + JWKS validator.
///
/// Config values are CARRIED here rather than re-read from
/// `config_store::get_app_config()` in the handlers: the config store is a
/// process-global set-once `OnceLock`, so deps-carried config is equivalent in
/// production (config is immutable for the process lifetime) and is the only
/// way tests can pin `auth_mode = entra-id` deterministically.
pub struct EntraSsoDeps {
    /// `auth_mode == AuthMode::EntraId` at startup.
    mode_is_entra: bool,
    /// Retained only so `configured()` can reject an empty tenant — the tenant
    /// is otherwise baked into the derived endpoint URLs at build time.
    tenant_id: String,
    client_id: String,
    redirect_uri: String,
    authorize_endpoint: String,
    issuer: String,
    session: ryuki_core::config::SessionConfig,
    trusted_proxies: Vec<ryuki_core::config::TrustedProxyNetwork>,
    exchanger: Arc<dyn TokenExchanger + Send + Sync>,
    validator: Arc<OidcIdTokenValidator>,
}

impl EntraSsoDeps {
    /// Test convenience constructor that wires the real `ReqwestTokenExchanger`
    /// and network-JWKS `OidcIdTokenValidator` against derived tenant endpoints.
    #[cfg(test)]
    pub fn build(
        mode_is_entra: bool,
        tenant_id: &str,
        client_id: &str,
        authority: &str,
        redirect_uri: &str,
        leeway_secs: u64,
        session: ryuki_core::config::SessionConfig,
    ) -> Arc<Self> {
        Self::build_with_trusted_proxies(
            mode_is_entra,
            tenant_id,
            client_id,
            authority,
            redirect_uri,
            leeway_secs,
            session,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_with_trusted_proxies(
        mode_is_entra: bool,
        tenant_id: &str,
        client_id: &str,
        authority: &str,
        redirect_uri: &str,
        leeway_secs: u64,
        session: ryuki_core::config::SessionConfig,
        trusted_proxies: Vec<ryuki_core::config::TrustedProxyNetwork>,
    ) -> Arc<Self> {
        let endpoints = derive_entra_endpoints(authority, tenant_id);
        let exchanger: Arc<dyn TokenExchanger + Send + Sync> =
            Arc::new(ReqwestTokenExchanger::new(endpoints.token));
        // The id_token audience is the BARE client id (unlike access tokens,
        // Entra never issues id_tokens with the api:// audience form).
        let validator = Arc::new(OidcIdTokenValidator::new(
            endpoints.jwks,
            endpoints.issuer.clone(),
            client_id.to_string(),
            leeway_secs,
        ));
        Arc::new(Self {
            mode_is_entra,
            tenant_id: tenant_id.to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            authorize_endpoint: endpoints.authorize,
            issuer: endpoints.issuer,
            session,
            trusted_proxies,
            exchanger,
            validator,
        })
    }

    /// Production constructor, called once at startup. When the auth mode is
    /// not EntraId the handlers reject before touching the network deps, so
    /// the placeholder endpoints derived from a possibly-empty tenant are
    /// never dereferenced.
    pub fn from_app_config(cfg: &ryuki_core::config::RyukiConfig) -> Arc<Self> {
        let trusted_proxies = cfg
            .rate_limit
            .parsed_trusted_proxies()
            .unwrap_or_else(|error| {
                // Startup config validation rejects this condition. Retaining
                // an empty trust set here is fail-safe if a test or future
                // embedder bypasses validation: forwarded identity is ignored.
                tracing::error!(error = %error, "invalid Entra login trusted-proxy configuration");
                Vec::new()
            });
        Self::build_with_trusted_proxies(
            cfg.auth_mode == ryuki_core::config::AuthMode::EntraId,
            &cfg.entra_tenant_id,
            &cfg.entra_client_id,
            &cfg.entra_authority,
            &cfg.entra_redirect_uri,
            cfg.entra_leeway_secs,
            cfg.session.clone(),
            trusted_proxies,
        )
    }

    fn configured(&self) -> bool {
        // All three are load-bearing: the authorize/token URLs embed the tenant,
        // so an empty tenant yields a malformed IdP URL. The gate must require
        // everything the ENTRA_SSO_NOT_CONFIGURED message claims it does.
        !self.tenant_id.is_empty() && !self.client_id.is_empty() && !self.redirect_uri.is_empty()
    }
}

/// Mode + config gate for BOTH Entra SSO endpoints.
///
/// Mirrors `mock_login_gate`'s wrong-mode shape: 400, not 5xx — the rejection
/// is a permanent property of the configured auth mode / process config, and a
/// 5xx would invite load-balancer retries of a request that can never succeed.
fn entra_sso_gate(deps: &EntraSsoDeps) -> Result<(), (StatusCode, Json<Value>)> {
    if !deps.mode_is_entra {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "ENTRA_AUTH_DISABLED",
                "message": "Entra ID sign-in requires auth_mode entra-id"
            })),
        ));
    }
    if !deps.configured() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "ENTRA_SSO_NOT_CONFIGURED",
                "message": "Entra ID SSO is not fully configured (tenant id, client id, and redirect URI are required)"
            })),
        ));
    }
    Ok(())
}

/// GET /api/auth/entra/authorize-url — begins a browser sign-in.
///
/// Persists `(state, nonce, pkce_verifier, binding)` via the single-use
/// `oidc_login_states` store, then returns the tenant authorize URL plus the
/// per-browser binding as JSON. The binding is ALSO set as the HttpOnly
/// mode-selected binding cookie for direct same-origin browser callers; the
/// portal server function (which cannot forward upstream Set-Cookie headers)
/// reads the JSON field and sets an identical cookie on its own response. The
/// binding value never reaches page JavaScript either way. Mandatory shared
/// source/global admission precedes PostgreSQL; serialized DB-time cleanup and
/// provider/global quotas precede entropy generation. A 429 carries a bounded
/// `Retry-After` response header.
pub(crate) async fn entra_authorize_url(
    Extension(deps): Extension<Arc<EntraSsoDeps>>,
    request: Request,
) -> Result<Response, (StatusCode, Json<Value>)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use url::Url;

    entra_sso_gate(&deps)?;

    // Mandatory shared login admission precedes database acquisition. The
    // server-inserted TCP peer is required; forwarded identity is honored only
    // through the immutable trusted-proxy configuration carried in these deps.
    let peer_addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0);
    let _admission_permit = if request
        .extensions()
        .get::<crate::repos::oidc_login_states::LoginInitiationPreAdmitted>()
        .is_some()
    {
        None
    } else {
        Some(
            crate::repos::oidc_login_states::admit_public_login_initiation(
                peer_addr,
                request.headers(),
                &deps.trusted_proxies,
            )
            .map_err(crate::contracts::login_initiation_admission_error)?,
        )
    };

    // A DB is required to persist the single-use state.
    let pool = crate::database::get_db().ok_or_else(crate::contracts::status_503_no_db)?;

    // Shared DB admission runs before protocol material is generated and keeps
    // generation + insertion inside the same serialized transaction.
    let material = crate::repos::oidc_login_states::create(
        pool,
        crate::repos::oidc_login_states::LoginFlow::Entra,
    )
    .await
    .map_err(crate::contracts::login_state_insert_error)?;
    let state = material.state.as_str();
    let nonce = material.nonce.as_str();
    let pkce_verifier = material.pkce_verifier.as_str();
    let binding = material.binding.as_str();
    // PKCE S256: code_challenge = BASE64URL(SHA-256(ASCII(code_verifier))).
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.as_bytes()));

    // All parameter values are percent-encoded by Url::parse_with_params, so
    // nothing can inject into the query string.
    let params: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", &deps.client_id),
        ("redirect_uri", &deps.redirect_uri),
        ("response_mode", "query"),
        ("scope", ENTRA_SCOPES),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", "S256"),
    ];
    let authorize_url = Url::parse_with_params(&deps.authorize_endpoint, &params).map_err(|e| {
        tracing::error!(error = %e, "failed to build Entra authorize URL");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "ENTRA_AUTHORIZE_URL_FAILED", "message": "failed to build authorization URL"})),
        )
    })?;

    // Only the retained Entra binding issuer can project this cookie policy.
    // The capability validates the generated 256-bit binding profile before
    // any credential-bearing response field is emitted.
    let cookie_runtime = crate::config_store::get_api_cookie_runtime();
    let binding_cookie = cookie_runtime
        .entra_binding_issuer()
        .issue(binding)
        .map_err(|error| {
            tracing::error!(error = %error, "Entra binding cookie field creation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "ENTRA_AUTHORIZE_URL_FAILED",
                    "message": "cookie encoding failed"
                })),
            )
        })?;

    let mut response = (
        StatusCode::OK,
        Json(json!({
            "authorize_url": authorize_url.as_str(),
            "binding": binding,
        })),
    )
        .into_response();
    binding_cookie.append_to(&mut response);
    Ok(response)
}

fn invalid_state_problem() -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "ENTRA_INVALID_STATE",
            "message": "Login state is missing, expired, or already used"
        })),
    )
}

/// GET /api/auth/entra/callback — completes a browser sign-in.
///
/// Flow (mirrors the generic OIDC callback):
/// 1. Gate on auth mode + SSO config, then on DB availability.
/// 2. If the IdP returned `?error=`, redirect to `/?auth_error=1` (the error
///    text is never forwarded).
/// 3. Require `code` and `state`.
/// 4. Consume the state row (single-use, expiry-checked) and verify the
///    per-browser binding cookie.
/// 5. Exchange the code (PKCE public client — no secret).
/// 6. Validate the id_token (RS256 sig + iss/aud/exp/nbf + nonce) and extract
///    identity + `roles`.
/// 7. Mint the SAME persisted session shape local login mints (aligned
///    row-expiry and cookie Max-Age), set the mode-selected session cookie, and
///    302-redirect to `/` (hardcoded — no open-redirect surface).
pub(crate) async fn entra_callback(
    Extension(deps): Extension<Arc<EntraSsoDeps>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<OidcCallbackQuery>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    entra_sso_gate(&deps)?;

    let pool = crate::database::get_db().ok_or_else(crate::contracts::status_503_no_db)?;

    // IdP returned an error — redirect without minting a session. The error
    // text is NEVER forwarded (info-disclosure + header-injection risk).
    if params.error.is_some() {
        tracing::warn!("entra callback: IdP returned an error, redirecting to auth_error page");
        let location = axum::http::HeaderValue::from_static("/?auth_error=1");
        return Ok((StatusCode::FOUND, [(LOCATION, location)]).into_response());
    }

    let code_val = params.code.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "ENTRA_INVALID_REQUEST",
                "message": "Missing authorization code"
            })),
        )
    })?;
    let state_val = params.state.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "ENTRA_INVALID_REQUEST",
                "message": "Missing state parameter"
            })),
        )
    })?;

    // Consume the state row — single-use, expiry-checked, atomic.
    let (nonce, pkce_verifier, binding) =
        match crate::repos::oidc_login_states::take(pool, &state_val)
            .await
            .map_err(crate::contracts::db_error)?
        {
            Some(row) => row,
            None => return Err(invalid_state_problem()),
        };

    // Login-CSRF / session-swapping defense: the state is redeemable only by
    // the browser that initiated the login (it holds the matching
    // mode-selected binding cookie). Both values are single-use,
    // server-generated 256-bit strings, so a simple compare suffices.
    let cookie_runtime = crate::config_store::get_api_cookie_runtime();
    let cookie_binding = match cookie_runtime.entra_binding_parser().parse(&headers) {
        crate::cookie_runtime::CookieEvidence::Value(value) => value,
        crate::cookie_runtime::CookieEvidence::Absent
        | crate::cookie_runtime::CookieEvidence::Invalid => return Err(invalid_state_problem()),
    };
    if binding.is_empty() || cookie_binding != binding {
        tracing::warn!("entra callback: login-state browser binding mismatch");
        return Err(invalid_state_problem());
    }

    // Token exchange — PKCE public client: NO client_secret is sent.
    // NEVER log code, pkce_verifier, or the resulting tokens.
    let token_resp = deps
        .exchanger
        .exchange(&TokenRequest {
            code: code_val,
            redirect_uri: deps.redirect_uri.clone(),
            client_id: deps.client_id.clone(),
            client_secret: None,
            pkce_verifier,
        })
        .await
        .map_err(|_| {
            tracing::error!("entra token exchange failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "ENTRA_TOKEN_EXCHANGE_FAILED"})),
            )
        })?;

    // Validate the id_token; log only the safe reason string.
    let claims = deps
        .validator
        .validate_entra_id_token(&token_resp.id_token, &nonce, ENTRA_ROLES_CLAIM)
        .await
        .map_err(|reason| {
            tracing::warn!(reason, "entra id_token validation failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "ENTRA_TOKEN_INVALID"})),
            )
        })?;

    // Mint unrelated management and authentication values. Only the keyed
    // verifier crosses into PostgreSQL; the bearer crosses only into Set-Cookie.
    let session_record_id = Uuid::new_v4();
    let credential =
        crate::session_credentials::issue_session_credential(&deps.session).map_err(|error| {
            tracing::error!(reason = %error, "entra session credential issuance failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "AUTH_SESSION_PERSISTENCE_FAILED"})),
            )
        })?;
    crate::contracts::map_auth_session_persistence_result(
        crate::identity_authority::create_federated_session(
            pool,
            "entra-id",
            &deps.issuer,
            &claims.user_id,
            &claims.display_name,
            claims.email.as_deref(),
            &claims.roles,
            session_record_id,
            credential.verifier().as_slice(),
            deps.session.cookie_max_age_secs,
            &deps.session,
        )
        .await,
        "create",
    )
    .map_err(|(status, Json(api_err))| {
        (
            status,
            Json(
                serde_json::to_value(&api_err)
                    .unwrap_or_else(|_| json!({"error": "AUTH_SESSION_PERSISTENCE_FAILED"})),
            ),
        )
    })?;

    // Never log the bearer, verifier, or management UUID.
    tracing::info!("entra login session created");

    // The issuer handle retains the exact startup cookie authority; the
    // redirect target is hardcoded.
    let cookies = cookie_runtime
        .entra_session_issuer()
        .issue(credential.bearer())
        .map_err(|error| {
            tracing::error!(error = %error, "Entra session cookie field creation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "ENTRA_COOKIE_ENCODING_FAILED"})),
            )
        })?;
    let binding_retirement = cookie_runtime
        .entra_binding_issuer()
        .retire()
        .map_err(|error| {
            tracing::error!(error = %error, "Entra binding cookie retirement failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "ENTRA_COOKIE_ENCODING_FAILED"})),
            )
        })?;
    let location = axum::http::HeaderValue::from_static("/");

    let mut response = (
        StatusCode::FOUND,
        [
            (LOCATION, location),
            (
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            ),
        ],
    )
        .into_response();
    cookies.append_to(&mut response);
    binding_retirement.append_to(&mut response);
    Ok(response)
}

// ─── Unit tests (no DB, no network) ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn deps(mode_is_entra: bool, client_id: &str, redirect_uri: &str) -> Arc<EntraSsoDeps> {
        EntraSsoDeps::build(
            mode_is_entra,
            "test-tenant",
            client_id,
            "https://login.microsoftonline.example",
            redirect_uri,
            60,
            ryuki_core::config::SessionConfig::default(),
        )
    }

    #[test]
    fn test_endpoint_derivation_matches_entra_patterns() {
        let endpoints = derive_entra_endpoints("https://login.microsoftonline.example/", "t-1");
        assert_eq!(
            endpoints.authorize,
            "https://login.microsoftonline.example/t-1/oauth2/v2.0/authorize"
        );
        assert_eq!(
            endpoints.token,
            "https://login.microsoftonline.example/t-1/oauth2/v2.0/token"
        );
        assert_eq!(
            endpoints.jwks,
            "https://login.microsoftonline.example/t-1/discovery/v2.0/keys"
        );
        assert_eq!(
            endpoints.issuer,
            "https://login.microsoftonline.example/t-1/v2.0"
        );
    }

    #[test]
    fn test_gate_rejects_non_entra_mode_with_400() {
        let wrong_mode = deps(
            false,
            "client-1",
            "http://localhost/api/auth/entra/callback",
        );
        let Err((status, Json(body))) = entra_sso_gate(&wrong_mode) else {
            panic!("non-entra mode must be rejected");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "ENTRA_AUTH_DISABLED");
    }

    #[test]
    fn test_gate_rejects_incomplete_config_with_400() {
        // Entra mode but no redirect URI configured.
        let no_redirect = deps(true, "client-1", "");
        let Err((status, Json(body))) = entra_sso_gate(&no_redirect) else {
            panic!("incomplete config must be rejected");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "ENTRA_SSO_NOT_CONFIGURED");

        // Entra mode but no client id configured.
        let no_client = deps(true, "", "http://localhost/api/auth/entra/callback");
        let Err((status, Json(body))) = entra_sso_gate(&no_client) else {
            panic!("incomplete config must be rejected");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "ENTRA_SSO_NOT_CONFIGURED");

        // Entra mode but no TENANT configured: the tenant is embedded in the
        // authorize/token URLs, so an empty tenant is as incomplete as a
        // missing client/redirect and must be rejected (the message claims it).
        let no_tenant = EntraSsoDeps::build(
            true,
            "",
            "client-1",
            "https://login.microsoftonline.example",
            "http://localhost/api/auth/entra/callback",
            60,
            ryuki_core::config::SessionConfig::default(),
        );
        let Err((status, Json(body))) = entra_sso_gate(&no_tenant) else {
            panic!("empty tenant must be rejected");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "ENTRA_SSO_NOT_CONFIGURED");
    }

    #[test]
    fn test_gate_accepts_configured_entra_mode() {
        let configured = deps(true, "client-1", "http://localhost/api/auth/entra/callback");
        assert!(entra_sso_gate(&configured).is_ok());
    }

    #[tokio::test]
    async fn authorize_url_fails_closed_without_tcp_peer_before_db() {
        let configured = deps(true, "client-1", "http://localhost/api/auth/entra/callback");
        let request = Request::builder()
            .uri("/api/auth/entra/authorize-url")
            .body(axum::body::Body::empty())
            .expect("request");
        let Err((status, Json(body))) = entra_authorize_url(Extension(configured), request).await
        else {
            panic!("missing TCP peer must fail closed before database acquisition");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "LOGIN_ADMISSION_CONTEXT_UNAVAILABLE");
    }
}

// ─── DB tests — full flow against a LOCAL stub OIDC IdP ─────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api --bin ryuki-api entra_sso -- --test-threads=1
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.
//
// The stub IdP is a real axum server on 127.0.0.1:0 that serves the three
// derived Entra paths (`/.well-known/openid-configuration` is served too, for
// discovery-shape realism) with a per-test RSA keypair; `EntraSsoDeps::build`
// is pointed at it as the authority, so the PRODUCTION ReqwestTokenExchanger
// and network-JWKS OidcIdTokenValidator run end-to-end with zero real Entra.

#[cfg(test)]
mod entra_sso_db_tests {
    use super::*;
    use crate::test_crypto;
    use axum::body::Body;
    use axum::extract::Form;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use jsonwebtoken::{Algorithm, Header};
    use sqlx::PgPool;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tower::ServiceExt;

    const TEST_TENANT: &str = "stub-tenant";
    const TEST_CLIENT: &str = "entra-sso-client-test";
    const TEST_REDIRECT: &str = "http://127.0.0.1:9/api/auth/entra/callback";
    const TEST_KID: &str = "entra-sso-test-kid";
    const OTHER_TEST_BINDING: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    fn authorize_request() -> Request<Body> {
        Request::builder()
            .uri("/api/auth/entra/authorize-url")
            .extension(ConnectInfo(
                "127.0.0.1:40101".parse::<SocketAddr>().expect("test peer"),
            ))
            .body(Body::empty())
            .expect("authorize request")
    }

    fn test_session_config() -> ryuki_core::config::SessionConfig {
        ryuki_core::config::SessionConfig {
            credential_hmac_key: "k".repeat(32),
            ..Default::default()
        }
    }

    // ─── DB pool gate (mirrors the oidc_callback db-test pattern) ─────────

    async fn global_pool() -> Option<&'static PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("entra_sso_db_tests: RYUKI_DATABASE_URL not set — skipping DB tests");
                return None;
            }
        };
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()?;
        crate::database::run_migrations(pool).await.ok()?;
        let cfg = ryuki_core::config::RyukiConfig {
            auth_mode: ryuki_core::config::AuthMode::EntraId,
            entra_tenant_id: TEST_TENANT.into(),
            entra_client_id: TEST_CLIENT.into(),
            session: test_session_config(),
            ..Default::default()
        };
        crate::config_store::init_with_config("entra-sso-test-config.json", &cfg);
        Some(pool)
    }

    // ─── Stub IdP ──────────────────────────────────────────────────────────

    /// What the stub token endpoint should embed in the id_token it issues.
    /// Tests mutate this AFTER extracting the real nonce from the authorize
    /// URL (the way a real IdP would echo the nonce back).
    struct IssueSpec {
        nonce: String,
        aud: String,
        iss: String,
        /// exp = now + offset (negative → already expired).
        exp_offset: i64,
        /// When true, the token endpoint answers 500.
        fail_with_500: bool,
    }

    struct StubIdp {
        /// `http://127.0.0.1:{port}` — pass as the Entra authority.
        base_url: String,
        issue: Arc<Mutex<IssueSpec>>,
        /// Form params the token endpoint last received, for PKCE assertions.
        seen_token_form: Arc<Mutex<Option<HashMap<String, String>>>>,
    }

    impl StubIdp {
        fn set_nonce(&self, issued_nonce: &str) {
            self.issue.lock().unwrap().nonce = issued_nonce.to_string();
        }
        fn set_aud(&self, aud: &str) {
            self.issue.lock().unwrap().aud = aud.to_string();
        }
        fn set_exp_offset(&self, offset: i64) {
            self.issue.lock().unwrap().exp_offset = offset;
        }
        fn set_fail_with_500(&self, fail: bool) {
            self.issue.lock().unwrap().fail_with_500 = fail;
        }
        fn last_token_form(&self) -> Option<HashMap<String, String>> {
            self.seen_token_form.lock().unwrap().clone()
        }
    }

    fn b64url(bytes: Vec<u8>) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn now() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Starts the stub IdP on an ephemeral port with a fresh RSA-2048 keypair.
    /// Serves the derived Entra paths: discovery doc (realism), JWKS, token.
    async fn start_stub_idp() -> StubIdp {
        let keypair = test_crypto::make_rsa_keypair();
        let encoding = Arc::new(keypair.encoding);
        let jwk_n = keypair.modulus_b64;
        let jwk_e = keypair.exponent_b64;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("stub idp bind");
        let port = listener.local_addr().expect("stub idp addr").port();
        let base_url = format!("http://127.0.0.1:{port}");

        let issue = Arc::new(Mutex::new(IssueSpec {
            nonce: String::new(),
            aud: TEST_CLIENT.to_string(),
            iss: format!("{base_url}/{TEST_TENANT}/v2.0"),
            exp_offset: 3600,
            fail_with_500: false,
        }));
        let seen_token_form: Arc<Mutex<Option<HashMap<String, String>>>> =
            Arc::new(Mutex::new(None));

        let jwks_body = json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": TEST_KID,
                "n": jwk_n,
                "e": jwk_e,
            }]
        });
        let discovery_body = json!({
            "issuer": format!("{base_url}/{TEST_TENANT}/v2.0"),
            "authorization_endpoint": format!("{base_url}/{TEST_TENANT}/oauth2/v2.0/authorize"),
            "token_endpoint": format!("{base_url}/{TEST_TENANT}/oauth2/v2.0/token"),
            "jwks_uri": format!("{base_url}/{TEST_TENANT}/discovery/v2.0/keys"),
        });

        let issue_for_token = issue.clone();
        let seen_for_token = seen_token_form.clone();
        let encoding_for_token = encoding.clone();

        let app = Router::new()
            .route(
                &format!("/{TEST_TENANT}/v2.0/.well-known/openid-configuration"),
                get(move || {
                    let body = discovery_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                &format!("/{TEST_TENANT}/discovery/v2.0/keys"),
                get(move || {
                    let body = jwks_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                &format!("/{TEST_TENANT}/oauth2/v2.0/token"),
                post(move |Form(form): Form<HashMap<String, String>>| {
                    let issue = issue_for_token.clone();
                    let seen = seen_for_token.clone();
                    let encoding = encoding_for_token.clone();
                    async move {
                        *seen.lock().unwrap() = Some(form);
                        let spec = issue.lock().unwrap();
                        if spec.fail_with_500 {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({"error": "server_error"})),
                            );
                        }
                        let claims = json!({
                            "iss": spec.iss,
                            "aud": spec.aud,
                            "sub": "entra-sub-1",
                            "oid": "entra-oid-1",
                            "name": "Entra Test User",
                            "preferred_username": "entra.user@stub.example",
                            "email": "entra.user@stub.example",
                            "nonce": spec.nonce,
                            "roles": ["PlatformAdmin"],
                            "exp": now() + spec.exp_offset,
                            "nbf": now() - 60,
                        });
                        let mut header = Header::new(Algorithm::RS256);
                        header.kid = Some(TEST_KID.to_string());
                        let id_token = jsonwebtoken::encode(&header, &claims, &encoding)
                            .expect("stub id_token sign");
                        (
                            StatusCode::OK,
                            Json(json!({
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "access_token": "stub-access-token",
                                "id_token": id_token,
                            })),
                        )
                    }
                }),
            );

        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        StubIdp {
            base_url,
            issue,
            seen_token_form,
        }
    }

    // ─── Test router over the REAL handlers + PRODUCTION deps ─────────────

    fn stub_deps(stub: &StubIdp) -> Arc<EntraSsoDeps> {
        EntraSsoDeps::build(
            true,
            TEST_TENANT,
            TEST_CLIENT,
            &stub.base_url,
            TEST_REDIRECT,
            60,
            test_session_config(),
        )
    }

    fn test_router(deps: Arc<EntraSsoDeps>) -> Router {
        Router::new()
            .route("/api/auth/entra/authorize-url", get(entra_authorize_url))
            .route("/api/auth/entra/callback", get(entra_callback))
            .layer(Extension(deps))
    }

    async fn provision_global_assignment(
        pool: &PgPool,
        provider: &str,
        issuer: &str,
        subject: &str,
        roles: &[String],
    ) {
        crate::human_authority::persist_governed_assignment(
            pool,
            provider,
            issuer,
            subject,
            crate::human_authority::HumanAuthorityAssignmentSpec::test_global(roles),
        )
        .await
        .expect("seed Entra human authority");
    }

    async fn body_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    /// Drives GET /api/auth/entra/authorize-url and returns
    /// `(state, nonce, code_challenge, binding)` extracted the way the real
    /// IdP + browser would see them.
    async fn begin_login(app: &Router) -> (String, String, String, String) {
        let resp = app
            .clone()
            .oneshot(authorize_request())
            .await
            .expect("authorize-url request");
        assert_eq!(resp.status(), StatusCode::OK);
        let set_cookie = resp
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            set_cookie.starts_with("__Host-entra_login_csrf="),
            "authorize-url must set the binding cookie, got: {set_cookie}"
        );
        assert!(set_cookie.contains("HttpOnly"));

        let body = body_json(resp).await;
        let authorize_url = body["authorize_url"].as_str().expect("authorize_url");
        let binding = body["binding"].as_str().expect("binding").to_string();

        let parsed = url::Url::parse(authorize_url).expect("parse authorize url");
        let params: HashMap<String, String> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        (
            params["state"].clone(),
            params["nonce"].clone(),
            params["code_challenge"].clone(),
            binding,
        )
    }

    fn callback_req(state: &str, binding: &str) -> Request<Body> {
        Request::builder()
            .uri(format!(
                "/api/auth/entra/callback?code=stub-code&state={state}"
            ))
            .header(
                axum::http::header::COOKIE,
                format!("__Host-entra_login_csrf={binding}"),
            )
            .body(Body::empty())
            .unwrap()
    }

    // ─── Tests ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_authorize_url_shape_and_state_persisted() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

        let resp = app
            .clone()
            .oneshot(authorize_request())
            .await
            .expect("request");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let authorize_url = body["authorize_url"].as_str().expect("authorize_url");

        let parsed = url::Url::parse(authorize_url).expect("authorize url parses");
        assert!(
            authorize_url.starts_with(&format!(
                "{}/{TEST_TENANT}/oauth2/v2.0/authorize?",
                stub.base_url
            )),
            "authorize URL must target the tenant authorize endpoint, got {authorize_url}"
        );
        let params: HashMap<String, String> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["client_id"], TEST_CLIENT);
        assert_eq!(params["redirect_uri"], TEST_REDIRECT);
        assert_eq!(params["code_challenge_method"], "S256");
        assert!(params["scope"].contains("openid"));
        assert!(!params["state"].is_empty());
        assert!(!params["nonce"].is_empty());
        assert!(!params["code_challenge"].is_empty());

        // The persisted row must carry the SAME nonce the URL carries, and the
        // stored verifier must hash (S256) to the URL's code_challenge.
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT nonce, pkce_verifier, binding FROM oidc_login_states WHERE state = $1",
        )
        .bind(&params["state"])
        .fetch_optional(pool)
        .await
        .expect("state row query");
        let (db_nonce, db_verifier, db_binding) = row.expect("state row must be persisted");
        assert_eq!(db_nonce, params["nonce"]);
        assert_eq!(
            b64url(Sha256::digest(db_verifier.as_bytes()).to_vec()),
            params["code_challenge"],
            "stored PKCE verifier must hash to the code_challenge in the URL"
        );
        assert_eq!(db_binding, body["binding"].as_str().unwrap());

        // The verifier itself must NOT appear anywhere in the authorize URL.
        assert!(
            !authorize_url.contains(&db_verifier),
            "PKCE verifier must never leave the server via the authorize URL"
        );

        // Cleanup the unconsumed row.
        let _ = sqlx::query("DELETE FROM oidc_login_states WHERE state = $1")
            .bind(&params["state"])
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn test_full_flow_happy_path_mints_entra_session() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let deps = stub_deps(&stub);
        provision_global_assignment(
            pool,
            "entra-id",
            &deps.issuer,
            "entra-oid-1",
            &["PlatformAdmin".to_string()],
        )
        .await;
        let app = test_router(deps);

        let (state, nonce, code_challenge, binding) = begin_login(&app).await;
        // A real IdP echoes the request nonce into the id_token.
        stub.set_nonce(&nonce);

        let resp = app
            .clone()
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("callback request");
        assert_eq!(resp.status(), StatusCode::FOUND, "must redirect on success");
        assert_eq!(
            resp.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            "/",
            "must redirect to the portal root"
        );
        let cookie_fields = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().expect("session cookie is text"))
            .collect::<Vec<_>>();
        assert_eq!(
            cookie_fields.len(),
            3,
            "Set-Cookie fields must stay separate"
        );
        let cookie = cookie_fields[0];
        assert!(cookie.starts_with("__Host-ryuki_session="), "got: {cookie}");
        assert!(cookie.contains("HttpOnly"));
        assert_eq!(
            cookie_fields[1],
            "ryuki_session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax; Secure"
        );
        assert_eq!(
            cookie_fields[2],
            "__Host-entra_login_csrf=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax; Secure"
        );

        // The minted session row: provider entra-id, identity from the id_token.
        let session_bearer = cookie
            .split(';')
            .next()
            .and_then(|kv| kv.strip_prefix("__Host-ryuki_session="))
            .expect("session bearer in cookie");
        assert!(crate::session_credentials::is_well_formed_session_bearer(
            session_bearer
        ));
        let verifier = crate::session_credentials::session_bearer_verifier(
            session_bearer,
            &test_session_config(),
        )
        .expect("test verifier");
        let row: (Uuid, String, String, Vec<String>, String) = sqlx::query_as(
            "SELECT session_record_id, user_id, display_name, roles, provider FROM sessions \
             WHERE bearer_verifier = $1 AND expires_at > NOW()",
        )
        .bind(verifier.as_slice())
        .fetch_one(pool)
        .await
        .expect("session row");
        assert_eq!(row.1, "entra-oid-1");
        assert_eq!(row.2, "Entra Test User");
        assert_eq!(row.3, vec!["PlatformAdmin".to_string()]);
        assert_eq!(row.4, "entra-id");

        // The token exchange must have been a PKCE PUBLIC client exchange:
        // grant/code/redirect/client + a verifier that hashes to the
        // challenge, and NO client_secret field at all.
        let form = stub.last_token_form().expect("token endpoint was called");
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "stub-code");
        assert_eq!(form["redirect_uri"], TEST_REDIRECT);
        assert_eq!(form["client_id"], TEST_CLIENT);
        assert_eq!(
            b64url(Sha256::digest(form["code_verifier"].as_bytes()).to_vec()),
            code_challenge,
            "the exchanged verifier must match the authorize-URL challenge"
        );
        assert!(
            !form.contains_key("client_secret"),
            "public-client exchange must not send a client_secret field"
        );

        // Cleanup the minted session row.
        let _ = sqlx::query("DELETE FROM sessions WHERE session_record_id = $1")
            .bind(row.0)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn test_callback_unknown_state_returns_400() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

        let resp = app
            .oneshot(callback_req("never-issued-state", "any-binding"))
            .await
            .expect("request");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "ENTRA_INVALID_STATE");
    }

    #[tokio::test]
    async fn test_callback_replayed_state_returns_400_and_no_cookie() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let deps = stub_deps(&stub);
        provision_global_assignment(
            pool,
            "entra-id",
            &deps.issuer,
            "entra-oid-1",
            &["PlatformAdmin".to_string()],
        )
        .await;
        let app = test_router(deps);

        let (state, nonce, _challenge, binding) = begin_login(&app).await;
        stub.set_nonce(&nonce);

        // First redemption succeeds.
        let first = app
            .clone()
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("first callback");
        assert_eq!(first.status(), StatusCode::FOUND);

        // Replay of the SAME state must fail: single-use.
        let second = app
            .clone()
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("second callback");
        assert_eq!(
            second.status(),
            StatusCode::BAD_REQUEST,
            "a replayed state must be rejected"
        );
        assert!(
            !second.headers().contains_key("set-cookie"),
            "no session cookie may be set on a replayed state"
        );
    }

    #[tokio::test]
    async fn test_callback_binding_mismatch_returns_400() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

        let (state, nonce, _challenge, binding) = begin_login(&app).await;
        stub.set_nonce(&nonce);

        // A DIFFERENT browser (wrong binding cookie) presents a valid state.
        let resp = app
            .clone()
            .oneshot(callback_req(&state, OTHER_TEST_BINDING))
            .await
            .expect("callback");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            !resp.headers().contains_key("set-cookie"),
            "no session cookie may be set on a binding mismatch"
        );

        let retry = app
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("retry callback");
        assert_eq!(
            retry.status(),
            StatusCode::BAD_REQUEST,
            "binding rejection must still consume the single-use state"
        );
        assert!(!retry.headers().contains_key("set-cookie"));
    }

    #[tokio::test]
    async fn test_callback_duplicate_binding_cookies_return_400() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

        let (state, nonce, _challenge, binding) = begin_login(&app).await;
        stub.set_nonce(&nonce);
        let mut request = callback_req(&state, &binding);
        request.headers_mut().append(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_static(
                "other=value; __Host-entra_login_csrf=attacker-binding",
            ),
        );

        let resp = app.oneshot(request).await.expect("callback");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            !resp.headers().contains_key("set-cookie"),
            "ambiguous binding evidence must never mint a session cookie"
        );
        let body = body_json(resp).await;
        assert_eq!(body["error"], "ENTRA_INVALID_STATE");
    }

    #[tokio::test]
    async fn test_callback_wrong_nonce_returns_401() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

        let (state, nonce, _challenge, binding) = begin_login(&app).await;
        // The stub issues an id_token with a DIFFERENT nonce.
        let mismatched_nonce = loop {
            let candidate = Uuid::new_v4().to_string();
            if candidate != nonce {
                break candidate;
            }
        };
        stub.set_nonce(&mismatched_nonce);

        let resp = app
            .clone()
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("callback");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "ENTRA_TOKEN_INVALID");
    }

    #[tokio::test]
    async fn test_callback_wrong_audience_returns_401() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

        let (state, nonce, _challenge, binding) = begin_login(&app).await;
        stub.set_nonce(&nonce);
        stub.set_aud("some-other-client");

        let resp = app
            .clone()
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("callback");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "ENTRA_TOKEN_INVALID");
    }

    #[tokio::test]
    async fn test_callback_expired_id_token_returns_401() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

        let (state, nonce, _challenge, binding) = begin_login(&app).await;
        stub.set_nonce(&nonce);
        stub.set_exp_offset(-3600); // already expired

        let resp = app
            .clone()
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("callback");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_callback_token_endpoint_500_returns_502() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

        let (state, nonce, _challenge, binding) = begin_login(&app).await;
        stub.set_nonce(&nonce);
        stub.set_fail_with_500(true);

        let resp = app
            .clone()
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("callback");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "a failing token endpoint must surface as 502"
        );
        let body = body_json(resp).await;
        assert_eq!(body["error"], "ENTRA_TOKEN_EXCHANGE_FAILED");
    }

    #[tokio::test]
    async fn test_callback_idp_error_redirects_to_auth_error() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/auth/entra/callback?error=access_denied&error_description=User+denied")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request");
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            "/?auth_error=1"
        );
        assert!(!resp.headers().contains_key("set-cookie"));
    }

    #[tokio::test]
    async fn test_wrong_mode_rejects_both_endpoints_with_400() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        // Same full config, but the auth mode is NOT entra-id.
        let deps = EntraSsoDeps::build(
            false,
            TEST_TENANT,
            TEST_CLIENT,
            &stub.base_url,
            TEST_REDIRECT,
            60,
            ryuki_core::config::SessionConfig::default(),
        );
        let app = test_router(deps);

        let authorize = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/auth/entra/authorize-url")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("authorize-url request");
        assert_eq!(authorize.status(), StatusCode::BAD_REQUEST);
        let body = body_json(authorize).await;
        assert_eq!(body["error"], "ENTRA_AUTH_DISABLED");

        let callback = app
            .clone()
            .oneshot(callback_req("any-state", "any-binding"))
            .await
            .expect("callback request");
        assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
        let body = body_json(callback).await;
        assert_eq!(body["error"], "ENTRA_AUTH_DISABLED");
    }

    /// Security regression: in EntraId mode the session resolver must honor
    /// ONLY validated-SSO provider sessions ('entra-id'/'oidc'), never a stale
    /// 'local'/dry-run session — otherwise a leftover admin cookie from a prior
    /// deployment mode would authenticate against the SSO deployment.
    #[tokio::test]
    async fn entra_mode_rejects_non_sso_provider_sessions() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        // Seed one session per provider, all non-expired, all admin-privileged.
        let seed = |provider: &'static str| {
            let record_id = Uuid::new_v4();
            async move {
                let credential =
                    crate::session_credentials::issue_session_credential(&test_session_config())
                        .expect("test session credential");
                let issuer = if provider == "local" {
                    crate::identity_authority::LOCAL_ISSUER
                } else {
                    "https://login.microsoftonline.example/test-tenant/v2.0"
                };
                let digest = Sha256::digest(format!("entra-mode-test\0{provider}\0{issuer}"));
                let mut identity_tx = pool.begin().await.expect("begin Entra test identity seed");
                crate::human_authority::prepare_writer_tx(
                    &mut identity_tx,
                    provider,
                    issuer,
                    "admin",
                )
                .await
                .expect("prepare Entra test identity writer");
                crate::human_authority::mark_governed_identity_reactivation_tx(&mut identity_tx)
                    .await
                    .expect("mark Entra test identity reactivation");
                let epoch = sqlx::query_scalar::<_, i64>(
                    "INSERT INTO identity_authorities \
                     (provider, issuer, subject, authority_epoch, authority_digest, authority_status, \
                      last_asserted_at) \
                     VALUES ($1, $2, 'admin', 1, $3, 'active-scoped-v2', NOW()) \
                     ON CONFLICT (provider, issuer, subject) DO UPDATE SET \
                       authority_epoch = CASE \
                         WHEN identity_authorities.authority_status <> 'active-scoped-v2' \
                           OR identity_authorities.authority_digest <> EXCLUDED.authority_digest \
                         THEN identity_authorities.authority_epoch + 1 \
                         ELSE identity_authorities.authority_epoch \
                       END, \
                       authority_digest = EXCLUDED.authority_digest, \
                       authority_status = 'active-scoped-v2', last_asserted_at = NOW() \
                     RETURNING authority_epoch",
                )
                .bind(provider)
                .bind(issuer)
                .bind(digest.as_slice())
                .fetch_one(&mut *identity_tx)
                .await
                .expect("seed identity authority");
                identity_tx
                    .commit()
                    .await
                    .expect("commit Entra test identity seed");
                crate::human_authority::persist_governed_assignment(
                    pool,
                    provider,
                    issuer,
                    "admin",
                    crate::human_authority::HumanAuthorityAssignmentSpec::test_global(&[
                        "PlatformAdmin".to_string(),
                    ]),
                )
                .await
                .expect("seed human authority assignment");
                let authority_version: i64 = sqlx::query_scalar(
                    "SELECT assignment_version FROM human_authority_assignments \
                     WHERE provider = $1 AND issuer = $2 AND subject = 'admin'",
                )
                .bind(provider)
                .bind(issuer)
                .fetch_one(pool)
                .await
                .expect("read human authority version");
                let mut session_tx = pool.begin().await.expect("begin Entra test session seed");
                crate::human_authority::prepare_writer_tx(
                    &mut session_tx,
                    provider,
                    issuer,
                    "admin",
                )
                .await
                .expect("prepare Entra test session writer");
                sqlx::query(
                    "INSERT INTO sessions \
                     (session_record_id, bearer_verifier, user_id, display_name, email, roles, provider, \
                      identity_issuer, identity_subject, identity_authority_epoch, human_authority_version, \
                      site_authority_mode, site_scope, environment_authority_mode, environment_scope, expires_at) \
                     VALUES ($1, $2, 'admin', 'Admin', NULL, $3, $4, $5, 'admin', $6, $7, \
                             'global', ARRAY[]::TEXT[], 'global', ARRAY[]::TEXT[], \
                             NOW() + INTERVAL '1 hour')",
                )
                .bind(record_id)
                .bind(credential.verifier().as_slice())
                .bind(&["PlatformAdmin".to_string()] as &[String])
                .bind(provider)
                .bind(issuer)
                .bind(epoch)
                .bind(authority_version)
                .execute(&mut *session_tx)
                .await
                .expect("seed session");
                session_tx
                    .commit()
                    .await
                    .expect("commit Entra test session seed");
                (record_id, credential.bearer().to_string())
            }
        };
        let (local_id, local_bearer) = seed("local").await;
        let (entra_id, entra_bearer) = seed("entra-id").await;
        let (oidc_id, oidc_bearer) = seed("oidc").await;

        let resolve = |session_bearer: String, tenant_id: &'static str, oidc_enabled: bool| async move {
            let session_config = test_session_config();
            let mut resolution_config = ryuki_core::config::RyukiConfig {
                auth_mode: ryuki_core::config::AuthMode::EntraId,
                entra_authority: "https://login.microsoftonline.example".to_string(),
                entra_tenant_id: tenant_id.to_string(),
                session: session_config,
                ..Default::default()
            };
            resolution_config.oidc.enabled = oidc_enabled;
            resolution_config.oidc.issuer =
                "https://login.microsoftonline.example/test-tenant/v2.0".to_string();
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::COOKIE,
                format!("__Host-ryuki_session={session_bearer}")
                    .parse()
                    .unwrap(),
            );
            // Each policy variant gets an isolated admission cache. A policy
            // rejection is intentionally negative-cached by bearer, so sharing
            // the process-global cache here would make the enabled assertion
            // depend on which variant the test exercised first.
            let admission =
                crate::session_lookup_admission::SessionLookupAdmission::for_tests(8, 8, 1, 8);
            crate::auth_session_from_persisted_session_with_admission(
                &headers,
                None,
                &resolution_config,
                &admission,
                None,
            )
            .await
            .expect("resolver returns Some")
            .0
        };

        // The stale local session must NOT authenticate: no roles, not valid.
        let local = resolve(local_bearer, "test-tenant", false).await;
        assert!(!local.token_valid, "stale local session must not be valid");
        assert!(
            local.roles.is_empty(),
            "stale local session grants no roles"
        );
        // The entra-id session resolves with its identity + roles.
        let entra = resolve(entra_bearer.clone(), "test-tenant", false).await;
        assert_eq!(entra.user_id, "admin");
        assert_eq!(entra.roles, vec!["PlatformAdmin".to_string()]);
        let rotated_tenant = resolve(entra_bearer, "rotated-tenant", false).await;
        assert!(
            !rotated_tenant.token_valid,
            "an Entra authority/tenant change must reject sessions from the old issuer"
        );

        let disabled_oidc = resolve(oidc_bearer.clone(), "test-tenant", false).await;
        assert!(
            !disabled_oidc.token_valid,
            "disabling generic OIDC must reject its persisted sessions"
        );
        let enabled_oidc = resolve(oidc_bearer, "test-tenant", true).await;
        assert!(enabled_oidc.token_valid);

        sqlx::query("DELETE FROM sessions WHERE session_record_id = ANY($1)")
            .bind(&[local_id, entra_id, oidc_id] as &[Uuid])
            .execute(pool)
            .await
            .ok();
    }
}
