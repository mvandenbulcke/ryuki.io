//! Entra ID browser SSO — OIDC authorization-code + PKCE (S256) sign-in.
//!
//! This module owns the interactive Entra ID sign-in flow for `AuthMode::EntraId`
//! deployments. It complements (never replaces) the existing bearer-token path:
//! `entra_auth::EntraTokenValidator` keeps validating `Authorization: Bearer`
//! JWTs for API callers, while this flow lets a BROWSER sign in and ride the
//! same persisted-session + `ryuki_session` cookie machinery the local login
//! uses. In EntraId mode the session resolver honors ONLY the validated SSO
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
//!   value (also set as the HttpOnly `entra_login_csrf` cookie) that must match
//!   the cookie presented to the callback, so a state minted in an attacker's
//!   own flow cannot be redeemed in a victim's browser (login-CSRF defense —
//!   same design as the generic OIDC flow's `oidc_login_csrf`).
//! - Public client: the token exchange sends NO `client_secret` field.
//!   Confidential-client deployments are served by the generic `oidc.*` flow.
//! - Session cookie flags come from `session_cookie_set_header` — identical to
//!   the local-login cookie.
//! - No token material, code, verifier, or session id is ever logged; id_token
//!   failures log only the validator's safe reason string.

use std::sync::Arc;

use axum::extract::Query;
use axum::http::header::{LOCATION, SET_COOKIE};
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

/// Name of the per-browser CSRF-binding cookie for the Entra flow. Distinct
/// from the generic flow's `oidc_login_csrf` so the two flows can never
/// clobber each other's binding.
pub(crate) const ENTRA_BINDING_COOKIE: &str = "entra_login_csrf";

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
    session: ryuki_core::config::SessionConfig,
    exchanger: Arc<dyn TokenExchanger + Send + Sync>,
    validator: Arc<OidcIdTokenValidator>,
}

impl EntraSsoDeps {
    /// Shared constructor for production (`from_app_config`) and tests: wires
    /// the real `ReqwestTokenExchanger` and network-JWKS `OidcIdTokenValidator`
    /// against the derived tenant endpoints.
    pub fn build(
        mode_is_entra: bool,
        tenant_id: &str,
        client_id: &str,
        authority: &str,
        redirect_uri: &str,
        leeway_secs: u64,
        session: ryuki_core::config::SessionConfig,
    ) -> Arc<Self> {
        let endpoints = derive_entra_endpoints(authority, tenant_id);
        let exchanger: Arc<dyn TokenExchanger + Send + Sync> =
            Arc::new(ReqwestTokenExchanger::new(endpoints.token));
        // The id_token audience is the BARE client id (unlike access tokens,
        // Entra never issues id_tokens with the api:// audience form).
        let validator = Arc::new(OidcIdTokenValidator::new(
            endpoints.jwks,
            endpoints.issuer,
            client_id.to_string(),
            leeway_secs,
        ));
        Arc::new(Self {
            mode_is_entra,
            tenant_id: tenant_id.to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            authorize_endpoint: endpoints.authorize,
            session,
            exchanger,
            validator,
        })
    }

    /// Production constructor, called once at startup. When the auth mode is
    /// not EntraId the handlers reject before touching the network deps, so
    /// the placeholder endpoints derived from a possibly-empty tenant are
    /// never dereferenced.
    pub fn from_app_config(cfg: &ryuki_core::config::RyukiConfig) -> Arc<Self> {
        Self::build(
            cfg.auth_mode == ryuki_core::config::AuthMode::EntraId,
            &cfg.entra_tenant_id,
            &cfg.entra_client_id,
            &cfg.entra_authority,
            &cfg.entra_redirect_uri,
            cfg.entra_leeway_secs,
            cfg.session.clone(),
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

/// Builds the `Set-Cookie` value for the per-browser CSRF-binding cookie.
/// SameSite=Lax is REQUIRED so the browser sends it on the top-level redirect
/// BACK from the IdP to the callback (a cross-site navigation); HttpOnly
/// always; Secure follows the session cookie policy; Max-Age matches the
/// 10-minute state TTL.
fn entra_binding_cookie_header(binding: &str, cookie_secure: bool) -> String {
    format!(
        "{ENTRA_BINDING_COOKIE}={binding}; Path=/; HttpOnly; Max-Age=600; SameSite=Lax{}",
        if cookie_secure { "; Secure" } else { "" }
    )
}

/// 32 CSPRNG bytes (OsRng / getrandom) as base64url — ≥256-bit entropy, the
/// same recipe as the generic OIDC flow's state/nonce/verifier values.
fn random_b64url_256() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// GET /api/auth/entra/authorize-url — begins a browser sign-in.
///
/// Persists `(state, nonce, pkce_verifier, binding)` via the single-use
/// `oidc_login_states` store, then returns the tenant authorize URL plus the
/// per-browser binding as JSON. The binding is ALSO set as the HttpOnly
/// `entra_login_csrf` cookie for direct same-origin browser callers; the
/// portal server function (which cannot forward upstream Set-Cookie headers)
/// reads the JSON field and sets an identical cookie on its own response. The
/// binding value never reaches page JavaScript either way.
pub(crate) async fn entra_authorize_url(
    Extension(deps): Extension<Arc<EntraSsoDeps>>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use url::Url;

    entra_sso_gate(&deps)?;

    // A DB is required to persist the single-use state.
    let pool = crate::database::get_db().ok_or_else(crate::contracts::status_503_no_db)?;

    let state = random_b64url_256();
    let nonce = random_b64url_256();
    let pkce_verifier = random_b64url_256();
    // PKCE S256: code_challenge = BASE64URL(SHA-256(ASCII(code_verifier))).
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.as_bytes()));
    let binding = random_b64url_256();

    crate::repos::oidc_login_states::insert(pool, &state, &nonce, &pkce_verifier, &binding)
        .await
        .map_err(crate::contracts::db_error)?;

    // Opportunistic, probabilistic sweep of expired rows (~1/64 of requests),
    // same as the generic OIDC login initiation. Failure is non-fatal.
    if rand::random::<u8>() < 4 {
        let _ = crate::repos::oidc_login_states::cleanup_expired(pool).await;
    }

    // All parameter values are percent-encoded by Url::parse_with_params, so
    // nothing can inject into the query string.
    let params: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", &deps.client_id),
        ("redirect_uri", &deps.redirect_uri),
        ("response_mode", "query"),
        ("scope", ENTRA_SCOPES),
        ("state", &state),
        ("nonce", &nonce),
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

    let cookie = entra_binding_cookie_header(&binding, deps.session.cookie_secure);
    let cookie_hv = axum::http::HeaderValue::from_str(&cookie).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({"error": "ENTRA_AUTHORIZE_URL_FAILED", "message": "cookie encoding failed"}),
            ),
        )
    })?;

    Ok((
        StatusCode::OK,
        [(SET_COOKIE, cookie_hv)],
        Json(json!({
            "authorize_url": authorize_url.as_str(),
            "binding": binding,
        })),
    )
        .into_response())
}

/// Extract a single cookie value by exact name from the request `Cookie`
/// header (same matcher as the generic OIDC callback).
fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        pair.trim()
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
            .map(|val| val.to_string())
    })
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
///    row-expiry and cookie Max-Age), set the `ryuki_session` cookie, and
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
    // `entra_login_csrf` cookie). Both values are single-use, server-generated
    // 256-bit strings, so a simple compare suffices.
    let cookie_binding = cookie_value(&headers, ENTRA_BINDING_COOKIE).unwrap_or_default();
    if binding.is_empty() || cookie_binding.is_empty() || cookie_binding != binding {
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
        .validate_id_token(&token_resp.id_token, &nonce, ENTRA_ROLES_CLAIM)
        .await
        .map_err(|reason| {
            tracing::warn!(reason, "entra id_token validation failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "ENTRA_TOKEN_INVALID"})),
            )
        })?;

    // Mint the persisted session — same shape as local login: server-generated
    // id (session-fixation defense) and a row expiry aligned with the cookie
    // Max-Age, plus the identity fields the Entra id_token carries.
    let session_id = Uuid::new_v4();
    crate::contracts::map_auth_session_persistence_result(
        sqlx::query(
            "INSERT INTO sessions (id, user_id, display_name, email, roles, provider, expires_at) \
             VALUES ($1, $2, $3, $4, $5, 'entra-id', NOW() + make_interval(secs => $6))",
        )
        .bind(session_id)
        .bind(&claims.user_id)
        .bind(&claims.display_name)
        .bind(&claims.email)
        .bind(&claims.roles as &[String])
        .bind(deps.session.cookie_max_age_secs as f64)
        .execute(pool)
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

    // Never log the session id — it IS the bearer cookie credential.
    tracing::info!("entra login session created");

    // Session cookie flags are IDENTICAL to the local-login cookie
    // (session_cookie_set_header); redirect target is hardcoded.
    let cookie =
        crate::contracts::session_cookie_set_header(&session_id.to_string(), &deps.session);
    let cookie_hv = axum::http::HeaderValue::from_str(&cookie).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "ENTRA_COOKIE_ENCODING_FAILED"})),
        )
    })?;
    let location = axum::http::HeaderValue::from_static("/");

    Ok((
        StatusCode::FOUND,
        [(SET_COOKIE, cookie_hv), (LOCATION, location)],
    )
        .into_response())
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

    #[test]
    fn test_binding_cookie_header_flags() {
        let plain = entra_binding_cookie_header("abc", false);
        assert_eq!(
            plain,
            "entra_login_csrf=abc; Path=/; HttpOnly; Max-Age=600; SameSite=Lax"
        );
        let secure = entra_binding_cookie_header("abc", true);
        assert!(secure.ends_with("; Secure"));
    }

    #[test]
    fn test_random_b64url_is_unique_and_url_safe() {
        let a = random_b64url_256();
        let b = random_b64url_256();
        assert_ne!(a, b);
        // 32 bytes -> 43 base64url chars, no padding.
        assert_eq!(a.len(), 43);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
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
    use axum::body::Body;
    use axum::extract::Form;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sqlx::PgPool;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tower::ServiceExt;

    const TEST_TENANT: &str = "stub-tenant";
    const TEST_CLIENT: &str = "entra-sso-client-test";
    const TEST_REDIRECT: &str = "http://127.0.0.1:9/api/auth/entra/callback";
    const TEST_KID: &str = "entra-sso-test-kid";

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
        fn set_nonce(&self, nonce: &str) {
            self.issue.lock().unwrap().nonce = nonce.to_string();
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
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let public = RsaPublicKey::from(&private);
        let der = private.to_pkcs1_der().expect("pkcs1 der");
        let encoding = Arc::new(EncodingKey::from_rsa_der(der.as_bytes()));
        let jwk_n = b64url(public.n().to_bytes_be());
        let jwk_e = b64url(public.e().to_bytes_be());

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
            ryuki_core::config::SessionConfig::default(),
        )
    }

    fn test_router(deps: Arc<EntraSsoDeps>) -> Router {
        Router::new()
            .route("/api/auth/entra/authorize-url", get(entra_authorize_url))
            .route("/api/auth/entra/callback", get(entra_callback))
            .layer(Extension(deps))
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
            .oneshot(
                Request::builder()
                    .uri("/api/auth/entra/authorize-url")
                    .body(Body::empty())
                    .unwrap(),
            )
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
            set_cookie.starts_with("entra_login_csrf="),
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
                format!("{ENTRA_BINDING_COOKIE}={binding}"),
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
            .oneshot(
                Request::builder()
                    .uri("/api/auth/entra/authorize-url")
                    .body(Body::empty())
                    .unwrap(),
            )
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
        let app = test_router(stub_deps(&stub));

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
        let cookie = resp
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .expect("session cookie");
        assert!(cookie.contains("ryuki_session="), "got: {cookie}");
        assert!(cookie.contains("HttpOnly"));

        // The minted session row: provider entra-id, identity from the id_token.
        let session_id = cookie
            .split(';')
            .next()
            .and_then(|kv| kv.strip_prefix("ryuki_session="))
            .expect("session id in cookie");
        let session_uuid = Uuid::parse_str(session_id).expect("session id is a uuid");
        let row: (String, String, Vec<String>, String) = sqlx::query_as(
            "SELECT user_id, display_name, roles, provider FROM sessions \
             WHERE id = $1 AND expires_at > NOW()",
        )
        .bind(session_uuid)
        .fetch_one(pool)
        .await
        .expect("session row");
        assert_eq!(row.0, "entra-oid-1");
        assert_eq!(row.1, "Entra Test User");
        assert_eq!(row.2, vec!["PlatformAdmin".to_string()]);
        assert_eq!(row.3, "entra-id");

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
        let _ = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(session_uuid)
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
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

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

        let (state, nonce, _challenge, _binding) = begin_login(&app).await;
        stub.set_nonce(&nonce);

        // A DIFFERENT browser (wrong binding cookie) presents a valid state.
        let resp = app
            .clone()
            .oneshot(callback_req(&state, "attacker-different-binding"))
            .await
            .expect("callback");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            !resp.headers().contains_key("set-cookie"),
            "no session cookie may be set on a binding mismatch"
        );
    }

    #[tokio::test]
    async fn test_callback_wrong_nonce_returns_401() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(stub_deps(&stub));

        let (state, _nonce, _challenge, binding) = begin_login(&app).await;
        // The stub issues an id_token with a DIFFERENT nonce.
        stub.set_nonce("a-nonce-that-was-never-requested");

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
            let id = Uuid::new_v4();
            async move {
                sqlx::query(
                    "INSERT INTO sessions (id, user_id, display_name, email, roles, provider, \
                     expires_at) VALUES ($1, 'admin', 'Admin', NULL, $2, $3, NOW() + INTERVAL '1 hour')",
                )
                .bind(id)
                .bind(&["PlatformAdmin".to_string()] as &[String])
                .bind(provider)
                .execute(pool)
                .await
                .expect("seed session");
                id
            }
        };
        let local_id = seed("local").await;
        let entra_id = seed("entra-id").await;

        let resolve = |session_id: Uuid| async move {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::COOKIE,
                format!("ryuki_session={session_id}").parse().unwrap(),
            );
            crate::auth_session_from_persisted_session(
                &headers,
                None,
                &ryuki_core::config::AuthMode::EntraId,
            )
            .await
            .expect("resolver returns Some")
            .0
        };

        // The stale local session must NOT authenticate: no roles, not valid.
        let local = resolve(local_id).await;
        assert!(!local.token_valid, "stale local session must not be valid");
        assert!(
            local.roles.is_empty(),
            "stale local session grants no roles"
        );
        // The entra-id session resolves with its identity + roles.
        let entra = resolve(entra_id).await;
        assert_eq!(entra.user_id, "admin");
        assert_eq!(entra.roles, vec!["PlatformAdmin".to_string()]);

        sqlx::query("DELETE FROM sessions WHERE id = ANY($1)")
            .bind(&[local_id, entra_id] as &[Uuid])
            .execute(pool)
            .await
            .ok();
    }
}
