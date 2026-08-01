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
//! browser-authenticator origins and their canonical provider IDs, never a
//! carrier-family alias or stale local/dry-run session — mirroring the
//! symmetric restriction Local mode already applies.
//!
//! # Endpoints
//! - `GET /api/auth/entra/authorize-url` — generates `state`/`nonce`/PKCE
//!   verifier (all CSPRNG), persists them via the existing single-use
//!   `oidc_login_states_v3` store (10-minute TTL), and returns the tenant
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
//! - The Entra provider key is the canonical lowercase, hyphenated `oid`; it
//!   never falls back to `sub`. Identity authority resolves that external key
//!   to the opaque internal principal persisted with the session.
//! - No token material, code, verifier, or session id is ever logged; id_token
//!   failures log only the validator's safe reason string.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Query, Request};
use axum::http::header::{CACHE_CONTROL, LOCATION};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::oidc_callback::{
    OidcCallbackQuery, OidcIdTokenValidator, OidcIdTokenValidatorRuntimeObservation,
    OidcTokenExchangerRuntimeObservation, ReqwestTokenExchanger, TokenExchanger, TokenRequest,
    TokenResponse, ValidatedOidcClaims,
};
use crate::security_contracts::ResolvedAuthenticatorBrowserLimits;
use ryuki_core::security_profile::AuthenticatorBrowserClientAuthentication;

/// Entra ID app roles are always issued in the `roles` claim (same claim the
/// bearer-token validator's `EntraClaims` consumes).
const ENTRA_ROLES_CLAIM: &str = "roles";

/// Scopes requested for the browser sign-in. `openid` is mandatory for an
/// id_token; profile/email populate display identity claims.
const ENTRA_SCOPES: &str = "openid profile email";

const ENTRA_SSO_RUNTIME_OBSERVATION_DIGEST_CONTRACT: &[u8] =
    b"ryuki-entra-sso-runtime-observation-leaf-v1";
const ENTRA_AUTHORIZE_ENDPOINT_BINDING_DOMAIN: &[u8] = b"entra-authorize-endpoint";
const ENTRA_REDIRECT_URI_BINDING_DOMAIN: &[u8] = b"entra-redirect-uri";
const ENTRA_CLIENT_ID_BINDING_DOMAIN: &[u8] = b"entra-client-id";
const ENTRA_SCOPES_BINDING_DOMAIN: &[u8] = b"entra-scopes";
const ENTRA_BROWSER_JWKS_KEY_SOURCE_BINDING_DOMAIN: &[u8] = b"entra-browser-jwks-key-source";

fn entra_sso_runtime_binding_digest(domain: &[u8], value: &[u8]) -> String {
    entra_sso_runtime_binding_digest_fields(domain, &[value])
}

fn entra_sso_runtime_binding_digest_fields(domain: &[u8], values: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for field in [ENTRA_SSO_RUNTIME_OBSERVATION_DIGEST_CONTRACT, domain] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(*value);
    }
    let digest = digest.finalize();
    format!("sha256:{digest:x}")
}

fn entra_browser_jwks_key_source_binding_digest(
    validator: &OidcIdTokenValidatorRuntimeObservation,
) -> String {
    let jwks = validator
        .network_jwks()
        .expect("Entra browser validator must retain network JWKS");
    let endpoint_https_only = jwks.endpoint_https_only().to_string();
    let redirects_allowed = jwks.redirects_allowed().to_string();
    let ambient_proxy_allowed = jwks.ambient_proxy_allowed().to_string();
    let connect_timeout_milliseconds = jwks.connect_timeout().as_millis().to_string();
    let request_timeout_milliseconds = jwks.request_timeout().as_millis().to_string();
    let cache_ttl_milliseconds = jwks.cache_ttl().as_millis().to_string();
    let refresh_cooldown_milliseconds = jwks.refresh_cooldown().as_millis().to_string();
    let maximum_cached_keys = jwks.maximum_cached_keys().to_string();
    let maximum_response_bytes = jwks.maximum_response_bytes().to_string();
    entra_sso_runtime_binding_digest_fields(
        ENTRA_BROWSER_JWKS_KEY_SOURCE_BINDING_DOMAIN,
        &[
            b"network-jwks",
            jwks.endpoint_binding_digest().as_bytes(),
            endpoint_https_only.as_bytes(),
            redirects_allowed.as_bytes(),
            ambient_proxy_allowed.as_bytes(),
            connect_timeout_milliseconds.as_bytes(),
            request_timeout_milliseconds.as_bytes(),
            cache_ttl_milliseconds.as_bytes(),
            refresh_cooldown_milliseconds.as_bytes(),
            maximum_cached_keys.as_bytes(),
            maximum_response_bytes.as_bytes(),
        ],
    )
}

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

/// Closed public-client browser-flow capability retained by the Entra SSO
/// dependencies and used directly by both handlers. Keeping protocol choices
/// behind this private type makes the observation causal: callback code cannot
/// independently select client-secret authentication, a weaker PKCE mode, a
/// nonce-free validation entry point, or a different provider-subject mapping.
struct EntraBrowserFlowRuntime {
    client_authentication: AuthenticatorBrowserClientAuthentication,
    client_credential_present: bool,
    pkce_method: &'static str,
    pkce_wire_method: &'static str,
    nonce_required: bool,
    browser_binding_required: bool,
    id_token_required: bool,
    provider_tokens_persisted: bool,
    provider_tokens_exposed: bool,
    accepted_algorithm_ids: [&'static str; 1],
    required_claim_ids: [&'static str; 7],
    provider_subject_claim_id: &'static str,
    expiration_required: bool,
    not_before_required: bool,
    issued_at_required: bool,
}

impl EntraBrowserFlowRuntime {
    fn public_client() -> Arc<Self> {
        Arc::new(Self {
            client_authentication: AuthenticatorBrowserClientAuthentication::None,
            client_credential_present: false,
            pkce_method: "s256",
            pkce_wire_method: "S256",
            nonce_required: true,
            browser_binding_required: true,
            id_token_required: true,
            provider_tokens_persisted: false,
            provider_tokens_exposed: false,
            accepted_algorithm_ids: ["rs256"],
            required_claim_ids: ["aud", "exp", "iss", "nbf", "nonce", "oid", "sub"],
            provider_subject_claim_id: "oid",
            expiration_required: true,
            not_before_required: true,
            issued_at_required: false,
        })
    }

    fn verify_integrity(&self) -> bool {
        self.client_authentication == AuthenticatorBrowserClientAuthentication::None
            && !self.client_credential_present
            && self.pkce_method == "s256"
            && self.pkce_wire_method == "S256"
            && self.nonce_required
            && self.browser_binding_required
            && self.id_token_required
            && !self.provider_tokens_persisted
            && !self.provider_tokens_exposed
            && self.accepted_algorithm_ids == ["rs256"]
            && self.required_claim_ids == ["aud", "exp", "iss", "nbf", "nonce", "oid", "sub"]
            && self.provider_subject_claim_id == "oid"
            && self.expiration_required
            && self.not_before_required
            && !self.issued_at_required
    }

    fn pkce_code_challenge(&self, verifier: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        debug_assert!(self.verify_integrity());
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    fn required_nonce<'a>(&self, nonce: &'a str) -> &'a str {
        debug_assert!(self.verify_integrity());
        nonce
    }

    fn token_request(
        &self,
        code: String,
        redirect_uri: String,
        client_id: String,
        pkce_verifier: String,
    ) -> TokenRequest {
        debug_assert!(self.verify_integrity());
        TokenRequest {
            code,
            redirect_uri,
            client_id,
            client_secret: None,
            pkce_verifier,
        }
    }

    fn browser_binding_matches(&self, persisted: &str, presented: &str) -> bool {
        self.browser_binding_required && !persisted.is_empty() && persisted == presented
    }

    async fn validate_token_response(
        &self,
        validator: &OidcIdTokenValidator,
        response: TokenResponse,
        expected_nonce: &str,
    ) -> Result<ValidatedOidcClaims, &'static str> {
        if !self.verify_integrity() {
            return Err("invalid-entra-browser-flow-runtime");
        }
        // `TokenResponse` exposes only the mandatory id_token; access/refresh
        // tokens are dropped inside the exchanger's private wire decoder.
        validator
            .validate_entra_id_token(&response.id_token, expected_nonce, ENTRA_ROLES_CLAIM)
            .await
    }
}

/// Value-free measurement of the exact retained Entra browser SSO runtime.
///
/// Construction is private to [`EntraSsoDeps`]. Identity, endpoint, redirect,
/// client, and scope values are represented only by independently
/// domain-separated digests. The nested observations are themselves produced
/// from the concrete exchanger, validator, session-credential, and cookie
/// runtime allocations retained by the dependencies. `Debug` deliberately
/// reveals neither raw values nor their equality-capable digests.
pub(crate) struct EntraSsoRuntimeObservation {
    mode_is_entra: bool,
    configured: bool,
    authorization_endpoint_binding_digest: String,
    authorization_endpoint_https_only: bool,
    redirect_uri_binding_digest: String,
    redirect_uri_https_only: bool,
    client_id_binding_digest: String,
    scopes_binding_digest: String,
    token_exchanger: OidcTokenExchangerRuntimeObservation,
    id_token_validator: OidcIdTokenValidatorRuntimeObservation,
    key_source_binding_digest: String,
    accepted_algorithm_ids: [&'static str; 1],
    required_claim_ids: [&'static str; 7],
    provider_subject_claim_id: &'static str,
    expiration_required: bool,
    not_before_required: bool,
    issued_at_required: bool,
    client_authentication: AuthenticatorBrowserClientAuthentication,
    client_credential_present: bool,
    pkce_method: &'static str,
    nonce_required: bool,
    browser_binding_required: bool,
    id_token_required: bool,
    provider_tokens_persisted: bool,
    provider_tokens_exposed: bool,
    redirects_allowed: bool,
    clock_skew_limit_id: Option<String>,
    maximum_clock_skew_seconds: Option<u64>,
    session_credentials: crate::session_credentials::DerivedSessionRuntimeObservation,
    cookie_runtime: crate::cookie_runtime::ApiCookieRuntimeObservation,
    retained_flow_runtime: Arc<EntraBrowserFlowRuntime>,
    retained_exchanger: Arc<ReqwestTokenExchanger>,
    retained_validator: Arc<OidcIdTokenValidator>,
    retained_browser_limits: Option<Arc<ResolvedAuthenticatorBrowserLimits>>,
    retained_session_credentials: Arc<crate::session_credentials::DerivedSessionCredentialRuntime>,
}

impl fmt::Debug for EntraSsoRuntimeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntraSsoRuntimeObservation")
            .field("mode_is_entra", &self.mode_is_entra)
            .field("configured", &self.configured)
            .field("identity_bindings", &"[REDACTED]")
            .field("redirect_uri_https_only", &self.redirect_uri_https_only)
            .field("token_exchanger", &self.token_exchanger)
            .field("id_token_validator", &self.id_token_validator)
            .field("key_source_binding", &"[REDACTED]")
            .field("verifier_policy", &"[RETAINED]")
            .field("client_authentication", &self.client_authentication)
            .field("client_credential_present", &self.client_credential_present)
            .field("pkce_method", &self.pkce_method)
            .field("nonce_required", &self.nonce_required)
            .field("browser_binding_required", &self.browser_binding_required)
            .field("id_token_required", &self.id_token_required)
            .field("provider_tokens_persisted", &self.provider_tokens_persisted)
            .field("provider_tokens_exposed", &self.provider_tokens_exposed)
            .field("redirects_allowed", &self.redirects_allowed)
            .field("browser_limit_authority", &"[RETAINED]")
            .field("session_credentials", &"[RETAINED]")
            .field("cookie_runtime", &"[RETAINED]")
            .finish()
    }
}

impl EntraSsoRuntimeObservation {
    pub(crate) fn mode_is_entra(&self) -> bool {
        self.mode_is_entra
    }

    pub(crate) fn configured(&self) -> bool {
        self.configured
    }

    pub(crate) fn authorization_endpoint_binding_digest(&self) -> &str {
        &self.authorization_endpoint_binding_digest
    }

    pub(crate) fn authorization_endpoint_https_only(&self) -> bool {
        self.authorization_endpoint_https_only
    }

    pub(crate) fn redirect_uri_binding_digest(&self) -> &str {
        &self.redirect_uri_binding_digest
    }

    pub(crate) fn redirect_uri_https_only(&self) -> bool {
        self.redirect_uri_https_only
    }

    pub(crate) fn client_id_binding_digest(&self) -> &str {
        &self.client_id_binding_digest
    }

    pub(crate) fn scopes_binding_digest(&self) -> &str {
        &self.scopes_binding_digest
    }

    pub(crate) fn token_exchanger(&self) -> &OidcTokenExchangerRuntimeObservation {
        &self.token_exchanger
    }

    pub(crate) fn id_token_validator(&self) -> &OidcIdTokenValidatorRuntimeObservation {
        &self.id_token_validator
    }

    pub(crate) fn key_source_binding_digest(&self) -> &str {
        &self.key_source_binding_digest
    }

    pub(crate) fn accepted_algorithm_ids(&self) -> &[&str] {
        &self.accepted_algorithm_ids
    }

    pub(crate) fn required_claim_ids(&self) -> &[&str] {
        &self.required_claim_ids
    }

    pub(crate) fn provider_subject_claim_id(&self) -> &str {
        self.provider_subject_claim_id
    }

    pub(crate) fn expiration_required(&self) -> bool {
        self.expiration_required
    }

    pub(crate) fn not_before_required(&self) -> bool {
        self.not_before_required
    }

    pub(crate) fn issued_at_required(&self) -> bool {
        self.issued_at_required
    }

    pub(crate) fn client_authentication(&self) -> AuthenticatorBrowserClientAuthentication {
        self.client_authentication
    }

    pub(crate) fn client_credential_present(&self) -> bool {
        self.client_credential_present
    }

    pub(crate) fn pkce_method(&self) -> &str {
        self.pkce_method
    }

    pub(crate) fn nonce_required(&self) -> bool {
        self.nonce_required
    }

    pub(crate) fn browser_binding_required(&self) -> bool {
        self.browser_binding_required
    }

    pub(crate) fn id_token_required(&self) -> bool {
        self.id_token_required
    }

    pub(crate) fn provider_tokens_persisted(&self) -> bool {
        self.provider_tokens_persisted
    }

    pub(crate) fn provider_tokens_exposed(&self) -> bool {
        self.provider_tokens_exposed
    }

    pub(crate) fn redirects_allowed(&self) -> bool {
        self.redirects_allowed
    }

    pub(crate) fn clock_skew_limit_id(&self) -> Option<&str> {
        self.clock_skew_limit_id.as_deref()
    }

    pub(crate) fn maximum_clock_skew_seconds(&self) -> Option<u64> {
        self.maximum_clock_skew_seconds
    }

    pub(crate) fn session_credentials(
        &self,
    ) -> &crate::session_credentials::DerivedSessionRuntimeObservation {
        &self.session_credentials
    }

    pub(crate) fn cookie_runtime(&self) -> &crate::cookie_runtime::ApiCookieRuntimeObservation {
        &self.cookie_runtime
    }
}

fn entra_sso_is_configured(
    tenant_id: &str,
    client_id: &str,
    redirect_uri: &str,
    browser_limits: Option<&Arc<ResolvedAuthenticatorBrowserLimits>>,
) -> bool {
    !tenant_id.is_empty()
        && !client_id.is_empty()
        && !redirect_uri.is_empty()
        && browser_limits.is_some()
}

/// All base Entra-SSO dependencies, retained inside the single post-seal
/// [`crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps`] extension.
/// Built ONCE at startup from the app config;
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
    browser_limits: Option<Arc<ResolvedAuthenticatorBrowserLimits>>,
    session_credentials: Arc<crate::session_credentials::DerivedSessionCredentialRuntime>,
    cookie_runtime: Arc<crate::cookie_runtime::ApiCookieRuntime>,
    trusted_proxies: Vec<ryuki_core::config::TrustedProxyNetwork>,
    flow_runtime: Arc<EntraBrowserFlowRuntime>,
    exchanger: Arc<ReqwestTokenExchanger>,
    validator: Arc<OidcIdTokenValidator>,
    runtime_observation: Arc<EntraSsoRuntimeObservation>,
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
        let mut config = ryuki_core::config::RyukiConfig {
            session,
            ..ryuki_core::config::RyukiConfig::default()
        };
        if !config.session.cookie_secure {
            config.server.bind_address = "127.0.0.1:0".to_string();
        }
        let session_credentials =
            crate::session_credentials::DerivedSessionCredentialRuntime::from_admitted_config(
                &config.session,
            )
            .expect("test config must construct session credential runtime");
        let cookie_runtime =
            crate::cookie_runtime::ApiCookieRuntime::from_admitted_config(&config, false)
                .expect("test config must construct cookie runtime");
        let browser_limits = Some(
            ResolvedAuthenticatorBrowserLimits::fixture_with_session_policy(
                leeway_secs,
                config.session.cookie_max_age_secs,
                config.session.federated_authority_max_staleness_secs,
            ),
        );
        Self::build_with_trusted_proxies(
            mode_is_entra,
            tenant_id,
            client_id,
            authority,
            redirect_uri,
            browser_limits,
            session_credentials,
            cookie_runtime,
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
        browser_limits: Option<Arc<ResolvedAuthenticatorBrowserLimits>>,
        session_credentials: Arc<crate::session_credentials::DerivedSessionCredentialRuntime>,
        cookie_runtime: Arc<crate::cookie_runtime::ApiCookieRuntime>,
        trusted_proxies: Vec<ryuki_core::config::TrustedProxyNetwork>,
    ) -> Arc<Self> {
        let endpoints = derive_entra_endpoints(authority, tenant_id);
        let flow_runtime = EntraBrowserFlowRuntime::public_client();
        let exchanger = Arc::new(ReqwestTokenExchanger::new(endpoints.token));
        // The id_token audience is the BARE client id (unlike access tokens,
        // Entra never issues id_tokens with the api:// audience form).
        let validator = Arc::new(OidcIdTokenValidator::new(
            endpoints.jwks,
            endpoints.issuer.clone(),
            client_id.to_string(),
            browser_limits
                .as_deref()
                .map(ResolvedAuthenticatorBrowserLimits::maximum_clock_skew_seconds)
                .unwrap_or(0),
        ));
        let authorize_endpoint = endpoints.authorize;
        let authorize_url = crate::oidc_callback::parse_identity_endpoint(&authorize_endpoint)
            .expect("derived Entra authorize endpoint must retain the admitted identity transport");
        let token_exchanger_observation = exchanger.runtime_observation();
        let id_token_validator_observation = validator.runtime_observation();
        let key_source_binding_digest =
            entra_browser_jwks_key_source_binding_digest(&id_token_validator_observation);
        let redirects_allowed = token_exchanger_observation.redirects_allowed()
            || id_token_validator_observation
                .network_jwks()
                .is_none_or(|jwks| jwks.redirects_allowed());
        let runtime_observation = Arc::new(EntraSsoRuntimeObservation {
            mode_is_entra,
            configured: entra_sso_is_configured(
                tenant_id,
                client_id,
                redirect_uri,
                browser_limits.as_ref(),
            ),
            authorization_endpoint_binding_digest: entra_sso_runtime_binding_digest(
                ENTRA_AUTHORIZE_ENDPOINT_BINDING_DOMAIN,
                authorize_endpoint.as_bytes(),
            ),
            authorization_endpoint_https_only: authorize_url.scheme() == "https",
            redirect_uri_binding_digest: entra_sso_runtime_binding_digest(
                ENTRA_REDIRECT_URI_BINDING_DOMAIN,
                redirect_uri.as_bytes(),
            ),
            redirect_uri_https_only: url::Url::parse(redirect_uri)
                .is_ok_and(|redirect| redirect.scheme() == "https"),
            client_id_binding_digest: entra_sso_runtime_binding_digest(
                ENTRA_CLIENT_ID_BINDING_DOMAIN,
                client_id.as_bytes(),
            ),
            scopes_binding_digest: entra_sso_runtime_binding_digest(
                ENTRA_SCOPES_BINDING_DOMAIN,
                ENTRA_SCOPES.as_bytes(),
            ),
            token_exchanger: token_exchanger_observation,
            id_token_validator: id_token_validator_observation,
            key_source_binding_digest,
            accepted_algorithm_ids: flow_runtime.accepted_algorithm_ids,
            required_claim_ids: flow_runtime.required_claim_ids,
            provider_subject_claim_id: flow_runtime.provider_subject_claim_id,
            expiration_required: flow_runtime.expiration_required,
            not_before_required: flow_runtime.not_before_required,
            issued_at_required: flow_runtime.issued_at_required,
            client_authentication: flow_runtime.client_authentication,
            client_credential_present: flow_runtime.client_credential_present,
            pkce_method: flow_runtime.pkce_method,
            nonce_required: flow_runtime.nonce_required,
            browser_binding_required: flow_runtime.browser_binding_required,
            id_token_required: flow_runtime.id_token_required,
            provider_tokens_persisted: flow_runtime.provider_tokens_persisted,
            provider_tokens_exposed: flow_runtime.provider_tokens_exposed,
            redirects_allowed,
            clock_skew_limit_id: browser_limits
                .as_deref()
                .map(ResolvedAuthenticatorBrowserLimits::clock_skew_limit_id)
                .map(str::to_owned),
            maximum_clock_skew_seconds: browser_limits
                .as_deref()
                .map(ResolvedAuthenticatorBrowserLimits::maximum_clock_skew_seconds),
            session_credentials: session_credentials.runtime_observation(),
            cookie_runtime: cookie_runtime
                .live_observation()
                .expect("admitted Entra cookie runtime must remain measurable"),
            retained_flow_runtime: Arc::clone(&flow_runtime),
            retained_exchanger: Arc::clone(&exchanger),
            retained_validator: Arc::clone(&validator),
            retained_browser_limits: browser_limits.as_ref().map(Arc::clone),
            retained_session_credentials: Arc::clone(&session_credentials),
        });
        Arc::new(Self {
            mode_is_entra,
            tenant_id: tenant_id.to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            authorize_endpoint,
            issuer: endpoints.issuer,
            browser_limits,
            session_credentials,
            cookie_runtime,
            trusted_proxies,
            flow_runtime,
            exchanger,
            validator,
            runtime_observation,
        })
    }

    /// Production constructor, called once at startup. When the auth mode is
    /// not EntraId the handlers reject before touching the network deps, so
    /// the placeholder endpoints derived from a possibly-empty tenant are
    /// never dereferenced.
    pub fn from_app_config(
        cfg: &ryuki_core::config::RyukiConfig,
        browser_limits: Option<Arc<ResolvedAuthenticatorBrowserLimits>>,
        session_credentials: Arc<crate::session_credentials::DerivedSessionCredentialRuntime>,
        cookie_runtime: Arc<crate::cookie_runtime::ApiCookieRuntime>,
    ) -> Arc<Self> {
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
            browser_limits,
            session_credentials,
            cookie_runtime,
            trusted_proxies,
        )
    }

    /// The exact live measurement retained at construction. A caller cannot
    /// construct this observation from declaration or configuration data.
    pub(crate) fn runtime_observation(&self) -> Arc<EntraSsoRuntimeObservation> {
        Arc::clone(&self.runtime_observation)
    }

    pub(crate) fn retains_runtime_observation(
        &self,
        observation: &Arc<EntraSsoRuntimeObservation>,
    ) -> bool {
        Arc::ptr_eq(&self.runtime_observation, observation)
    }

    #[cfg(test)]
    pub(crate) fn token_exchanger(&self) -> Arc<ReqwestTokenExchanger> {
        Arc::clone(&self.exchanger)
    }

    #[cfg(test)]
    pub(crate) fn id_token_validator(&self) -> Arc<OidcIdTokenValidator> {
        Arc::clone(&self.validator)
    }

    #[cfg(test)]
    pub(crate) fn retains_token_exchanger(&self, exchanger: &Arc<ReqwestTokenExchanger>) -> bool {
        Arc::ptr_eq(&self.exchanger, exchanger)
    }

    #[cfg(test)]
    pub(crate) fn retains_id_token_validator(&self, validator: &Arc<OidcIdTokenValidator>) -> bool {
        Arc::ptr_eq(&self.validator, validator)
    }

    /// Re-measure every immutable leaf and verify that the cookie observation
    /// still retains the exact cookie runtime and secure-policy allocations.
    pub(crate) fn remeasures_runtime_observation(&self) -> bool {
        let observation = self.runtime_observation.as_ref();
        let authorize_url =
            crate::oidc_callback::parse_identity_endpoint(self.authorize_endpoint.as_str()).ok();
        let browser_limit_integrity = self
            .browser_limits
            .as_deref()
            .map(ResolvedAuthenticatorBrowserLimits::verify_integrity)
            .transpose()
            .is_ok();
        let retains_browser_limits = match (
            observation.retained_browser_limits.as_ref(),
            self.browser_limits.as_ref(),
        ) {
            (Some(retained), Some(candidate)) => Arc::ptr_eq(retained, candidate),
            (None, None) => true,
            _ => false,
        };

        browser_limit_integrity
            && self.flow_runtime.verify_integrity()
            && Arc::ptr_eq(&observation.retained_flow_runtime, &self.flow_runtime)
            && Arc::ptr_eq(&observation.retained_exchanger, &self.exchanger)
            && Arc::ptr_eq(&observation.retained_validator, &self.validator)
            && retains_browser_limits
            && Arc::ptr_eq(
                &observation.retained_session_credentials,
                &self.session_credentials,
            )
            && observation.mode_is_entra == self.mode_is_entra
            && observation.configured == self.configured()
            && observation.authorization_endpoint_binding_digest
                == entra_sso_runtime_binding_digest(
                    ENTRA_AUTHORIZE_ENDPOINT_BINDING_DOMAIN,
                    self.authorize_endpoint.as_bytes(),
                )
            && observation.authorization_endpoint_https_only
                == authorize_url
                    .as_ref()
                    .is_some_and(|endpoint| endpoint.scheme() == "https")
            && observation.redirect_uri_binding_digest
                == entra_sso_runtime_binding_digest(
                    ENTRA_REDIRECT_URI_BINDING_DOMAIN,
                    self.redirect_uri.as_bytes(),
                )
            && observation.redirect_uri_https_only
                == url::Url::parse(&self.redirect_uri)
                    .is_ok_and(|redirect| redirect.scheme() == "https")
            && observation.client_id_binding_digest
                == entra_sso_runtime_binding_digest(
                    ENTRA_CLIENT_ID_BINDING_DOMAIN,
                    self.client_id.as_bytes(),
                )
            && observation.scopes_binding_digest
                == entra_sso_runtime_binding_digest(
                    ENTRA_SCOPES_BINDING_DOMAIN,
                    ENTRA_SCOPES.as_bytes(),
                )
            && observation.token_exchanger == self.exchanger.runtime_observation()
            && observation.id_token_validator == self.validator.runtime_observation()
            && observation.key_source_binding_digest
                == entra_browser_jwks_key_source_binding_digest(
                    &self.validator.runtime_observation(),
                )
            && observation.accepted_algorithm_ids == self.flow_runtime.accepted_algorithm_ids
            && observation.required_claim_ids == self.flow_runtime.required_claim_ids
            && observation.provider_subject_claim_id == self.flow_runtime.provider_subject_claim_id
            && observation.expiration_required == self.flow_runtime.expiration_required
            && observation.not_before_required == self.flow_runtime.not_before_required
            && observation.issued_at_required == self.flow_runtime.issued_at_required
            && observation.client_authentication == self.flow_runtime.client_authentication
            && observation.client_credential_present == self.flow_runtime.client_credential_present
            && observation.pkce_method == self.flow_runtime.pkce_method
            && observation.nonce_required == self.flow_runtime.nonce_required
            && observation.browser_binding_required == self.flow_runtime.browser_binding_required
            && observation.id_token_required == self.flow_runtime.id_token_required
            && observation.provider_tokens_persisted == self.flow_runtime.provider_tokens_persisted
            && observation.provider_tokens_exposed == self.flow_runtime.provider_tokens_exposed
            && observation.redirects_allowed
                == (self.exchanger.runtime_observation().redirects_allowed()
                    || self
                        .validator
                        .runtime_observation()
                        .network_jwks()
                        .is_none_or(|jwks| jwks.redirects_allowed()))
            && observation.clock_skew_limit_id.as_deref()
                == self
                    .browser_limits
                    .as_deref()
                    .map(ResolvedAuthenticatorBrowserLimits::clock_skew_limit_id)
            && observation.maximum_clock_skew_seconds
                == self
                    .browser_limits
                    .as_deref()
                    .map(ResolvedAuthenticatorBrowserLimits::maximum_clock_skew_seconds)
            && observation.session_credentials == self.session_credentials.runtime_observation()
            && observation
                .cookie_runtime
                .verify_retained_runtime(&self.cookie_runtime)
                .is_ok()
    }

    pub(crate) fn retains_session_credentials(
        &self,
        runtime: &Arc<crate::session_credentials::DerivedSessionCredentialRuntime>,
    ) -> bool {
        Arc::ptr_eq(&self.session_credentials, runtime)
    }

    pub(crate) fn retains_browser_limits(
        &self,
        limits: &Option<Arc<ResolvedAuthenticatorBrowserLimits>>,
    ) -> bool {
        match (&self.browser_limits, limits) {
            (Some(retained), Some(candidate)) => Arc::ptr_eq(retained, candidate),
            (None, None) => true,
            _ => false,
        }
    }

    pub(crate) fn retains_cookie_runtime(
        &self,
        runtime: &Arc<crate::cookie_runtime::ApiCookieRuntime>,
    ) -> bool {
        Arc::ptr_eq(&self.cookie_runtime, runtime)
    }

    fn configured(&self) -> bool {
        // All three are load-bearing: the authorize/token URLs embed the tenant,
        // so an empty tenant yields a malformed IdP URL. The gate must require
        // everything the ENTRA_SSO_NOT_CONFIGURED message claims it does.
        entra_sso_is_configured(
            &self.tenant_id,
            &self.client_id,
            &self.redirect_uri,
            self.browser_limits.as_ref(),
        )
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

fn entra_runtime_authority_unavailable() -> (StatusCode, Json<Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": "ENTRA_AUTHORITY_UNAVAILABLE",
            "message": "Entra ID sign-in authority is unavailable"
        })),
    )
}

type VerifiedEntraHandlerAuthority = (
    Arc<EntraSsoDeps>,
    Arc<crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin>,
);

fn verified_entra_handler_authority(
    handler: &Arc<crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps>,
) -> Result<VerifiedEntraHandlerAuthority, (StatusCode, Json<Value>)> {
    handler.verify_integrity().map_err(|error| {
        tracing::error!(error = %error, "retained Entra SSO handler authority failed integrity verification");
        entra_runtime_authority_unavailable()
    })?;
    Ok((Arc::clone(handler.base()), Arc::clone(handler.origin())))
}

/// Converts an authentication payload or redirect into a response that no
/// browser, intermediary, or idempotency layer may retain. Authentication
/// handlers use one helper so one-time URLs and session-bearing redirects
/// cannot drift onto different cache policies.
fn auth_response_no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// GET /api/auth/entra/authorize-url — begins a browser sign-in.
///
/// Persists `(state, nonce, pkce_verifier, binding)` via the single-use
/// `oidc_login_states_v3` store, then returns the tenant authorize URL plus the
/// per-browser binding as JSON. The binding is ALSO set as the HttpOnly
/// mode-selected binding cookie for direct same-origin browser callers; the
/// portal server function (which cannot forward upstream Set-Cookie headers)
/// reads the JSON field and sets an identical cookie on its own response. The
/// binding value never reaches page JavaScript either way. Mandatory shared
/// source/global admission precedes PostgreSQL; serialized DB-time cleanup and
/// provider/global quotas precede entropy generation. A 429 carries a bounded
/// `Retry-After` response header.
pub(crate) async fn entra_authorize_url(
    Extension(handler): Extension<Arc<crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps>>,
    request: Request,
) -> Result<Response, (StatusCode, Json<Value>)> {
    use url::Url;

    let (deps, authenticator_origin) = verified_entra_handler_authority(&handler)?;
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

    // Startup alone advances the durable current-path pointer. Shared DB
    // admission locks and verifies this exact active browser origin before it
    // generates or inserts protocol material, preventing request-time rollback.
    let material = crate::repos::oidc_login_states::create(
        pool,
        authenticator_origin.origin_binding_digest_bytes(),
    )
    .await
    .map_err(crate::contracts::login_state_insert_error)?;
    let state = material.state.as_str();
    let nonce = material.nonce.as_str();
    let pkce_verifier = material.pkce_verifier.as_str();
    let binding = material.binding.as_str();
    // PKCE S256: code_challenge = BASE64URL(SHA-256(ASCII(code_verifier))).
    let code_challenge = deps.flow_runtime.pkce_code_challenge(pkce_verifier);

    // All parameter values are percent-encoded by Url::parse_with_params, so
    // nothing can inject into the query string.
    let params: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", &deps.client_id),
        ("redirect_uri", &deps.redirect_uri),
        ("response_mode", "query"),
        ("scope", ENTRA_SCOPES),
        ("state", state),
        ("nonce", deps.flow_runtime.required_nonce(nonce)),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", deps.flow_runtime.pkce_wire_method),
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
    let cookie_runtime = Arc::clone(&deps.cookie_runtime);
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

    let mut response = auth_response_no_store((
        StatusCode::OK,
        Json(json!({
            "authorize_url": authorize_url.as_str(),
            "binding": binding,
        })),
    ));
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
    Extension(handler): Extension<Arc<crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<OidcCallbackQuery>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let (deps, authenticator_origin) = verified_entra_handler_authority(&handler)?;
    entra_sso_gate(&deps)?;

    let pool = crate::database::get_db().ok_or_else(crate::contracts::status_503_no_db)?;

    // IdP returned an error — redirect without minting a session. The error
    // text is NEVER forwarded (info-disclosure + header-injection risk).
    if params.error.is_some() {
        tracing::warn!("entra callback: IdP returned an error, redirecting to auth_error page");
        let location = axum::http::HeaderValue::from_static("/?auth_error=1");
        return Ok(auth_response_no_store((
            StatusCode::FOUND,
            [(LOCATION, location)],
        )));
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
    let (nonce, pkce_verifier, binding) = match crate::repos::oidc_login_states::take(
        pool,
        &state_val,
        authenticator_origin.origin_binding_digest_bytes(),
    )
    .await
    .map_err(crate::contracts::db_error)?
    {
        crate::repos::oidc_login_states::LoginStateTakeOutcome::Redeemed {
            nonce,
            pkce_verifier,
            binding,
        } => (nonce, pkce_verifier, binding),
        crate::repos::oidc_login_states::LoginStateTakeOutcome::OriginMismatch
        | crate::repos::oidc_login_states::LoginStateTakeOutcome::Expired
        | crate::repos::oidc_login_states::LoginStateTakeOutcome::Absent => {
            return Err(invalid_state_problem());
        }
    };

    // Login-CSRF / session-swapping defense: the state is redeemable only by
    // the browser that initiated the login (it holds the matching
    // mode-selected binding cookie). Both values are single-use,
    // server-generated 256-bit strings, so a simple compare suffices.
    let cookie_runtime = Arc::clone(&deps.cookie_runtime);
    let cookie_binding = match cookie_runtime.entra_binding_parser().parse(&headers) {
        crate::cookie_runtime::CookieEvidence::Value(value) => value,
        crate::cookie_runtime::CookieEvidence::Absent
        | crate::cookie_runtime::CookieEvidence::Invalid => return Err(invalid_state_problem()),
    };
    if !deps
        .flow_runtime
        .browser_binding_matches(&binding, cookie_binding)
    {
        tracing::warn!("entra callback: login-state browser binding mismatch");
        return Err(invalid_state_problem());
    }

    // Token exchange — PKCE public client: NO client_secret is sent.
    // NEVER log code, pkce_verifier, or the resulting tokens.
    let token_request = deps.flow_runtime.token_request(
        code_val,
        deps.redirect_uri.clone(),
        deps.client_id.clone(),
        pkce_verifier,
    );
    let token_resp = deps.exchanger.exchange(&token_request).await.map_err(|_| {
        tracing::error!("entra token exchange failed");
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "ENTRA_TOKEN_EXCHANGE_FAILED"})),
        )
    })?;

    // Validate the id_token; log only the safe reason string.
    let claims = deps
        .flow_runtime
        .validate_token_response(&deps.validator, token_resp, &nonce)
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
    let credential = deps.session_credentials.issue().map_err(|error| {
        tracing::error!(reason = %error, "entra session credential issuance failed");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "AUTH_SESSION_PERSISTENCE_FAILED"})),
        )
    })?;
    crate::contracts::map_auth_session_persistence_result(
        crate::identity_authority::create_federated_session(
            pool,
            &authenticator_origin,
            &deps.issuer,
            &claims.provider_subject,
            &claims.display_name,
            claims.email.as_deref(),
            &claims.roles,
            session_record_id,
            credential.verifier().as_slice(),
            deps.session_credentials.maximum_session_age_seconds(),
            deps.session_credentials.as_ref(),
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

    let mut response = auth_response_no_store((StatusCode::FOUND, [(LOCATION, location)]));
    cookies.append_to(&mut response);
    binding_retirement.append_to(&mut response);
    Ok(response)
}

// ─── Unit tests (no DB, no network) ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_response_helper_overwrites_weaker_cache_policy() {
        let response =
            auth_response_no_store((StatusCode::OK, [(CACHE_CONTROL, "private, max-age=60")]));

        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }

    fn handler_deps(
        base: Arc<EntraSsoDeps>,
        label: &str,
    ) -> Arc<crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps> {
        crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps::fixture(
            base,
            crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin::fixture(label),
        )
    }

    fn deps(mode_is_entra: bool, client_id: &str, redirect_uri: &str) -> Arc<EntraSsoDeps> {
        deps_with_authority_and_limits(
            mode_is_entra,
            client_id,
            "https://login.microsoftonline.example",
            redirect_uri,
            60,
        )
    }

    fn deps_with_authority_and_limits(
        mode_is_entra: bool,
        client_id: &str,
        authority: &str,
        redirect_uri: &str,
        leeway_secs: u64,
    ) -> Arc<EntraSsoDeps> {
        EntraSsoDeps::build(
            mode_is_entra,
            "test-tenant",
            client_id,
            authority,
            redirect_uri,
            leeway_secs,
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
    fn runtime_observation_measures_the_exact_closed_browser_authority() {
        let configured = deps(
            true,
            "client-runtime-observation",
            "https://portal.example/api/auth/entra/callback",
        );
        let observation = configured.runtime_observation();

        assert!(observation.mode_is_entra());
        assert!(observation.configured());
        assert!(observation.authorization_endpoint_https_only());
        assert!(observation.redirect_uri_https_only());
        assert_eq!(
            observation.client_authentication(),
            AuthenticatorBrowserClientAuthentication::None
        );
        assert!(!observation.client_credential_present());
        assert_eq!(observation.pkce_method(), "s256");
        assert!(observation.nonce_required());
        assert!(observation.browser_binding_required());
        assert!(observation.id_token_required());
        assert!(!observation.provider_tokens_persisted());
        assert!(!observation.provider_tokens_exposed());
        assert!(!observation.redirects_allowed());
        assert_eq!(observation.accepted_algorithm_ids(), ["rs256"]);
        assert_eq!(
            observation.required_claim_ids(),
            ["aud", "exp", "iss", "nbf", "nonce", "oid", "sub"]
        );
        assert_eq!(observation.provider_subject_claim_id(), "oid");
        assert!(observation.expiration_required());
        assert!(observation.not_before_required());
        assert!(!observation.issued_at_required());
        assert!(observation
            .key_source_binding_digest()
            .starts_with("sha256:"));
        assert_eq!(observation.maximum_clock_skew_seconds(), Some(60));
        assert!(observation.clock_skew_limit_id().is_some());
        assert!(
            observation
                .session_credentials()
                .maximum_session_age_seconds()
                > 0
        );
        assert!(observation
            .cookie_runtime()
            .policy_inventory_digest()
            .is_some());

        let exchanger = observation.token_exchanger();
        assert!(exchanger.endpoint_https_only());
        assert!(!exchanger.redirects_allowed());
        assert!(!exchanger.ambient_proxy_allowed());
        assert_eq!(exchanger.grant_type(), "authorization_code");
        assert!(exchanger.pkce_verifier_included());
        assert!(exchanger.redirect_uri_bound());
        assert!(exchanger.client_id_bound());
        assert!(exchanger.client_secret_form_parameter_optional());
        assert_eq!(
            exchanger.connect_timeout(),
            crate::oidc_callback::identity_connect_timeout()
        );
        assert_eq!(
            exchanger.request_timeout(),
            crate::oidc_callback::identity_request_timeout()
        );
        assert!(exchanger.maximum_response_bytes() > 0);

        let validator = observation.id_token_validator();
        assert!(validator.issuer_https_only());
        assert!(validator.nonce_required());
        assert_eq!(validator.leeway_seconds(), 60);
        let jwks = validator
            .network_jwks()
            .expect("Entra browser validator must retain network JWKS");
        assert!(jwks.endpoint_https_only());
        assert!(!jwks.redirects_allowed());
        assert!(!jwks.ambient_proxy_allowed());
        assert_eq!(
            jwks.connect_timeout(),
            crate::oidc_callback::identity_connect_timeout()
        );
        assert_eq!(
            jwks.request_timeout(),
            crate::oidc_callback::identity_request_timeout()
        );
        assert!(jwks.maximum_response_bytes() > 0);

        assert!(configured.retains_runtime_observation(&observation));
        assert!(configured.remeasures_runtime_observation());
        let concrete_exchanger = configured.token_exchanger();
        let concrete_validator = configured.id_token_validator();
        assert!(configured.retains_token_exchanger(&concrete_exchanger));
        assert!(configured.retains_id_token_validator(&concrete_validator));
    }

    #[test]
    fn runtime_observation_mutates_every_identity_and_limit_binding() {
        let baseline = deps_with_authority_and_limits(
            true,
            "client-runtime-baseline",
            "https://login.microsoftonline.example",
            "https://portal.example/api/auth/entra/callback",
            60,
        );
        let changed_client = deps_with_authority_and_limits(
            true,
            "client-runtime-changed",
            "https://login.microsoftonline.example",
            "https://portal.example/api/auth/entra/callback",
            60,
        );
        let changed_redirect = deps_with_authority_and_limits(
            true,
            "client-runtime-baseline",
            "https://login.microsoftonline.example",
            "https://portal.example/api/auth/entra/other-callback",
            60,
        );
        let changed_authority = deps_with_authority_and_limits(
            true,
            "client-runtime-baseline",
            "https://login.changed.example",
            "https://portal.example/api/auth/entra/callback",
            60,
        );
        let changed_limit = deps_with_authority_and_limits(
            true,
            "client-runtime-baseline",
            "https://login.microsoftonline.example",
            "https://portal.example/api/auth/entra/callback",
            61,
        );

        let baseline = baseline.runtime_observation();
        let changed_client = changed_client.runtime_observation();
        let changed_redirect = changed_redirect.runtime_observation();
        let changed_authority = changed_authority.runtime_observation();
        let changed_limit = changed_limit.runtime_observation();
        assert_ne!(
            baseline.client_id_binding_digest(),
            changed_client.client_id_binding_digest()
        );
        assert_ne!(
            baseline.id_token_validator().audience_binding_digest(),
            changed_client
                .id_token_validator()
                .audience_binding_digest()
        );
        assert_ne!(
            baseline.redirect_uri_binding_digest(),
            changed_redirect.redirect_uri_binding_digest()
        );
        assert_ne!(
            baseline.authorization_endpoint_binding_digest(),
            changed_authority.authorization_endpoint_binding_digest()
        );
        assert_ne!(
            baseline.token_exchanger().token_endpoint_binding_digest(),
            changed_authority
                .token_exchanger()
                .token_endpoint_binding_digest()
        );
        assert_ne!(
            baseline.id_token_validator().issuer_binding_digest(),
            changed_authority
                .id_token_validator()
                .issuer_binding_digest()
        );
        assert_ne!(
            baseline
                .id_token_validator()
                .network_jwks()
                .unwrap()
                .endpoint_binding_digest(),
            changed_authority
                .id_token_validator()
                .network_jwks()
                .unwrap()
                .endpoint_binding_digest()
        );
        assert_ne!(
            baseline.key_source_binding_digest(),
            changed_authority.key_source_binding_digest()
        );
        assert_ne!(
            baseline.maximum_clock_skew_seconds(),
            changed_limit.maximum_clock_skew_seconds()
        );
        assert_ne!(
            baseline.id_token_validator().leeway_seconds(),
            changed_limit.id_token_validator().leeway_seconds()
        );
        assert_ne!(
            baseline.scopes_binding_digest(),
            entra_sso_runtime_binding_digest(
                ENTRA_REDIRECT_URI_BINDING_DOMAIN,
                ENTRA_SCOPES.as_bytes(),
            )
        );
    }

    #[test]
    fn equal_looking_substitutes_fail_exact_arc_retention() {
        let first = deps(
            true,
            "client-runtime-substitution",
            "https://portal.example/api/auth/entra/callback",
        );
        let substitute = deps(
            true,
            "client-runtime-substitution",
            "https://portal.example/api/auth/entra/callback",
        );
        let first_observation = first.runtime_observation();
        let substitute_observation = substitute.runtime_observation();
        let substitute_exchanger = substitute.token_exchanger();
        let substitute_validator = substitute.id_token_validator();

        assert!(!first.retains_runtime_observation(&substitute_observation));
        assert!(!first.retains_token_exchanger(&substitute_exchanger));
        assert!(!first.retains_id_token_validator(&substitute_validator));
        assert!(!first.retains_session_credentials(&substitute.session_credentials));
        assert!(!first.retains_cookie_runtime(&substitute.cookie_runtime));
        assert!(!first.retains_browser_limits(&substitute.browser_limits));
        assert!(first_observation
            .cookie_runtime()
            .verify_retained_runtime(&first.cookie_runtime)
            .is_ok());
        assert!(first_observation
            .cookie_runtime()
            .verify_retained_runtime(&substitute.cookie_runtime)
            .is_err());
        assert!(first.remeasures_runtime_observation());
        assert!(substitute.remeasures_runtime_observation());
    }

    #[test]
    fn session_key_and_cookie_policy_mutations_change_retained_observations() {
        let mut baseline_session = ryuki_core::config::SessionConfig {
            credential_hmac_key: Uuid::new_v4().to_string(),
            ..Default::default()
        };
        let mut changed_key_session = baseline_session.clone();
        changed_key_session.credential_hmac_key = Uuid::new_v4().to_string();
        let baseline = EntraSsoDeps::build(
            true,
            "test-tenant",
            "client-session-observation",
            "https://login.microsoftonline.example",
            "https://portal.example/api/auth/entra/callback",
            60,
            baseline_session.clone(),
        );
        let changed_key = EntraSsoDeps::build(
            true,
            "test-tenant",
            "client-session-observation",
            "https://login.microsoftonline.example",
            "https://portal.example/api/auth/entra/callback",
            60,
            changed_key_session,
        );
        baseline_session.cookie_max_age_secs -= 1;
        let changed_policy = EntraSsoDeps::build(
            true,
            "test-tenant",
            "client-session-observation",
            "https://login.microsoftonline.example",
            "https://portal.example/api/auth/entra/callback",
            60,
            baseline_session,
        );

        let baseline = baseline.runtime_observation();
        let changed_key = changed_key.runtime_observation();
        let changed_policy = changed_policy.runtime_observation();
        assert_ne!(
            baseline.session_credentials().key_identity_binding_digest(),
            changed_key
                .session_credentials()
                .key_identity_binding_digest()
        );
        assert_ne!(
            baseline.session_credentials().maximum_session_age_seconds(),
            changed_policy
                .session_credentials()
                .maximum_session_age_seconds()
        );
        assert_ne!(
            baseline.cookie_runtime().policy_inventory_digest(),
            changed_policy.cookie_runtime().policy_inventory_digest()
        );
    }

    #[test]
    fn runtime_observation_debug_redacts_identity_and_secret_values() {
        let client_id = "client-debug-must-not-appear";
        let redirect_uri = "https://portal.example/debug-must-not-appear";
        let authority = "https://authority-debug-must-not-appear.example";
        let configured =
            deps_with_authority_and_limits(true, client_id, authority, redirect_uri, 60);
        let rendered = format!("{:?}", configured.runtime_observation());

        for forbidden in [client_id, redirect_uri, authority, ENTRA_SCOPES] {
            assert!(
                !rendered.contains(forbidden),
                "runtime observation Debug leaked {forbidden}"
            );
        }
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("[RETAINED]"));
    }

    #[tokio::test]
    async fn authorize_url_fails_closed_without_tcp_peer_before_db() {
        let configured = deps(true, "client-1", "http://localhost/api/auth/entra/callback");
        let handler = handler_deps(configured, "entra-unit-peer");
        let request = Request::builder()
            .uri("/api/auth/entra/authorize-url")
            .body(axum::body::Body::empty())
            .expect("request");
        let Err((status, Json(body))) = entra_authorize_url(Extension(handler), request).await
        else {
            panic!("missing TCP peer must fail closed before database acquisition");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "LOGIN_ADMISSION_CONTEXT_UNAVAILABLE");
    }

    #[test]
    fn verified_handler_authority_returns_only_the_exact_wrapped_arcs() {
        let base = deps(
            true,
            "client-handler-retention",
            "https://portal.example/api/auth/entra/callback",
        );
        let substitute_base = deps(
            true,
            "client-handler-retention",
            "https://portal.example/api/auth/entra/callback",
        );
        let origin = crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin::fixture(
            "entra-unit-origin",
        );
        let substitute_origin =
            crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin::fixture(
                "entra-unit-origin",
            );
        let handler = crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps::fixture(
            Arc::clone(&base),
            Arc::clone(&origin),
        );

        let (returned_base, returned_origin) =
            verified_entra_handler_authority(&handler).expect("fixture wrapper integrity");
        assert!(Arc::ptr_eq(&returned_base, &base));
        assert!(Arc::ptr_eq(&returned_origin, &origin));
        assert!(!Arc::ptr_eq(&returned_base, &substitute_base));
        assert!(!Arc::ptr_eq(&returned_origin, &substitute_origin));
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
    use rand::{rngs::OsRng, RngCore};
    use sqlx::PgPool;
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    use tower::ServiceExt;

    const TEST_TENANT: &str = "stub-tenant";
    const TEST_CLIENT: &str = "entra-sso-client-test";
    const TEST_REDIRECT: &str = "http://127.0.0.1:9/api/auth/entra/callback";
    const TEST_KID: &str = "entra-sso-test-kid";
    const TEST_ENTRA_OID: &str = "11111111-2222-4333-8444-555555555555";
    static TEST_SESSION_HMAC_KEY: LazyLock<String> = LazyLock::new(|| {
        let mut key = [0_u8; 32];
        OsRng.fill_bytes(&mut key);
        b64url(key.to_vec())
    });

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
            credential_hmac_key: TEST_SESSION_HMAC_KEY.clone(),
            ..Default::default()
        }
    }

    fn other_test_binding(binding: &str) -> String {
        loop {
            let mut bytes = [0_u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let candidate = b64url(bytes.to_vec());
            if candidate != binding {
                return candidate;
            }
        }
    }

    fn canonical_protocol_value() -> String {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        b64url(bytes.to_vec())
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
        /// Exact Entra directory object identifier to include. `None` omits
        /// the claim so the callback's no-fallback policy can be exercised.
        oid: Option<String>,
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
        fn set_oid(&self, oid: Option<&str>) {
            self.issue.lock().unwrap().oid = oid.map(str::to_string);
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
            oid: Some(TEST_ENTRA_OID.to_string()),
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
                        let mut claims = json!({
                            "iss": spec.iss,
                            "aud": spec.aud,
                            "sub": "entra-sub-1",
                            "name": "Entra Test User",
                            "preferred_username": "entra.user@stub.example",
                            "email": "entra.user@stub.example",
                            "nonce": spec.nonce,
                            "roles": ["PlatformAdmin"],
                            "exp": now() + spec.exp_offset,
                            "nbf": now() - 60,
                        });
                        if let Some(oid) = &spec.oid {
                            claims["oid"] = json!(oid);
                        }
                        let mut header = Header::new(Algorithm::RS256);
                        header.kid = Some(TEST_KID.to_string());
                        let id_token = jsonwebtoken::encode(&header, &claims, &encoding)
                            .expect("stub id_token sign");
                        (
                            StatusCode::OK,
                            Json(json!({
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "access_token": Uuid::new_v4().to_string(),
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

    fn stub_handler_deps(
        stub: &StubIdp,
    ) -> Arc<crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps> {
        crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps::fixture(
            stub_deps(stub),
            crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin::fixture(
                "entra-sso-db",
            ),
        )
    }

    async fn test_router(
        pool: &PgPool,
        dependencies: Arc<crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps>,
    ) -> Router {
        crate::identity_authority::reconcile_test_authenticator_runtime(
            pool,
            dependencies.origin(),
        )
        .await
        .expect("reconcile the synthetic paired test authenticator runtime");
        Router::new()
            .route("/api/auth/entra/authorize-url", get(entra_authorize_url))
            .route("/api/auth/entra/callback", get(entra_callback))
            .layer(Extension(dependencies))
    }

    async fn provision_global_assignment(
        pool: &PgPool,
        browser_authenticator_origin: &Arc<
            crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin,
        >,
        issuer: &str,
        subject: &str,
        roles: &[String],
    ) {
        crate::identity_authority::reconcile_test_authenticator_runtime(
            pool,
            browser_authenticator_origin,
        )
        .await
        .expect("reconcile the synthetic paired test authenticator runtime");
        crate::identity_authority::provision_test_authenticator_assignment(
            pool,
            browser_authenticator_origin,
            issuer,
            subject,
            roles,
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
        assert_eq!(
            resp.headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "one-time authorize URLs must never be cacheable"
        );
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
        let handler = stub_handler_deps(&stub);
        let origin = Arc::clone(handler.origin());
        let app = test_router(pool, handler).await;

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
        for value in [
            params["state"].as_str(),
            params["nonce"].as_str(),
            params["code_challenge"].as_str(),
            body["binding"].as_str().expect("binding"),
        ] {
            assert_eq!(value.len(), 43);
            assert!(value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
        }

        // The persisted row must carry the SAME nonce the URL carries, and the
        // stored verifier must hash (S256) to the URL's code_challenge.
        let row: Option<(String, String, String, Vec<u8>)> = sqlx::query_as(
            "SELECT nonce, pkce_verifier, binding, authenticator_origin_binding_digest \
             FROM oidc_login_states_v3 WHERE state = $1",
        )
        .bind(&params["state"])
        .fetch_optional(pool)
        .await
        .expect("state row query");
        let (db_nonce, db_verifier, db_binding, db_origin) =
            row.expect("state row must be persisted");
        assert_eq!(db_nonce, params["nonce"]);
        assert_eq!(
            b64url(Sha256::digest(db_verifier.as_bytes()).to_vec()),
            params["code_challenge"],
            "stored PKCE verifier must hash to the code_challenge in the URL"
        );
        assert_eq!(db_binding, body["binding"].as_str().unwrap());
        assert_eq!(db_origin, origin.origin_binding_digest_bytes().as_slice());

        // The verifier itself must NOT appear anywhere in the authorize URL.
        assert!(
            !authorize_url.contains(&db_verifier),
            "PKCE verifier must never leave the server via the authorize URL"
        );

        // Cleanup the unconsumed row.
        let cleanup = crate::repos::oidc_login_states::take(
            pool,
            &params["state"],
            origin.origin_binding_digest_bytes(),
        )
        .await
        .expect("v3 state cleanup");
        assert!(matches!(
            cleanup,
            crate::repos::oidc_login_states::LoginStateTakeOutcome::Redeemed { .. }
        ));
    }

    #[tokio::test]
    async fn test_full_flow_happy_path_mints_entra_session() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let handler = stub_handler_deps(&stub);
        let deps = Arc::clone(handler.base());
        let origin = Arc::clone(handler.origin());
        let origin_digest = handler.origin().origin_binding_digest_bytes().to_vec();
        let expected_issuer = deps.issuer.clone();
        provision_global_assignment(
            pool,
            &origin,
            &deps.issuer,
            TEST_ENTRA_OID,
            &["PlatformAdmin".to_string()],
        )
        .await;
        let app = test_router(pool, handler).await;

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

        // The minted session row retains the exact canonical origin provider,
        // never a carrier-family alias such as `entra-id`.
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
        #[derive(sqlx::FromRow)]
        struct PersistedEntraSessionRow {
            session_record_id: Uuid,
            principal_id: Uuid,
            display_name: String,
            roles: Vec<String>,
            provider_id: String,
            issuer: String,
            subject: String,
            authenticator_origin_binding_digest: Vec<u8>,
        }

        let row: PersistedEntraSessionRow = sqlx::query_as(
            "SELECT s.session_record_id, s.principal_id, s.display_name, s.roles, \
                    k.provider_id, k.issuer, k.subject, \
                    s.authenticator_origin_binding_digest \
             FROM sessions s \
             JOIN principal_keys k ON k.principal_key_id = s.principal_key_id \
             WHERE s.session_bearer_verifier_v3 = $1 AND s.expires_at > NOW()",
        )
        .bind(verifier.as_slice())
        .fetch_one(pool)
        .await
        .expect("session row");
        assert_ne!(
            row.principal_id,
            Uuid::nil(),
            "the persisted session must use a registry-issued opaque principal id"
        );
        assert_eq!(row.display_name, "Entra Test User");
        assert_eq!(row.roles, vec!["PlatformAdmin".to_string()]);
        assert_eq!(row.provider_id, origin.provider_id());
        assert_eq!(row.issuer, expected_issuer);
        assert_eq!(row.subject, TEST_ENTRA_OID);
        assert_eq!(row.authenticator_origin_binding_digest, origin_digest);

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
            .bind(row.session_record_id)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn test_callback_missing_oid_rejects_without_sub_fallback() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let handler = stub_handler_deps(&stub);
        let deps = Arc::clone(handler.base());
        let origin = Arc::clone(handler.origin());
        // Make the signed `sub` fully admissible as an authority key. If the
        // callback ever restores oid→sub fallback, this request would mint a
        // session and the regression would fail.
        provision_global_assignment(
            pool,
            &origin,
            &deps.issuer,
            "entra-sub-1",
            &["PlatformAdmin".to_string()],
        )
        .await;
        let app = test_router(pool, handler).await;

        let (state, nonce, _code_challenge, binding) = begin_login(&app).await;
        stub.set_nonce(&nonce);
        stub.set_oid(None);

        let response = app
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("callback request");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            response
                .headers()
                .get_all("set-cookie")
                .iter()
                .next()
                .is_none(),
            "an Entra assertion without oid must never mint a session cookie"
        );
        let body = body_json(response).await;
        assert_eq!(body["error"], "ENTRA_TOKEN_INVALID");
    }

    #[tokio::test]
    async fn test_callback_unknown_state_returns_400() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(pool, stub_handler_deps(&stub)).await;

        let resp = app
            .oneshot(callback_req(
                &canonical_protocol_value(),
                &canonical_protocol_value(),
            ))
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
        let handler = stub_handler_deps(&stub);
        let deps = Arc::clone(handler.base());
        let origin = Arc::clone(handler.origin());
        provision_global_assignment(
            pool,
            &origin,
            &deps.issuer,
            TEST_ENTRA_OID,
            &["PlatformAdmin".to_string()],
        )
        .await;
        let app = test_router(pool, handler).await;

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
    async fn substituted_origin_wrapper_burns_state_before_exchange() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let base = stub_deps(&stub);
        let initiating_origin =
            crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin::fixture(
                "entra-origin-a",
            );
        let substituted_origin =
            crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin::fixture(
                "entra-origin-b",
            );
        let initiating_handler = crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps::fixture(
            Arc::clone(&base),
            Arc::clone(&initiating_origin),
        );
        let substituted_handler =
            crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps::fixture(
                base,
                Arc::clone(&substituted_origin),
            );
        assert!(!Arc::ptr_eq(
            initiating_handler.origin(),
            substituted_handler.origin()
        ));
        let initiating_app = test_router(pool, initiating_handler).await;
        let substituted_app = test_router(pool, substituted_handler).await;

        let (state, nonce, _challenge, binding) = begin_login(&initiating_app).await;
        stub.set_nonce(&nonce);
        let mismatched = substituted_app
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("substituted-origin callback");
        assert_eq!(mismatched.status(), StatusCode::BAD_REQUEST);
        assert!(
            stub.last_token_form().is_none(),
            "origin mismatch must burn state before token exchange"
        );

        let retry = initiating_app
            .oneshot(callback_req(&state, &binding))
            .await
            .expect("initiating-origin retry");
        assert_eq!(retry.status(), StatusCode::BAD_REQUEST);
        assert!(
            stub.last_token_form().is_none(),
            "mismatched redemption must consume the state permanently"
        );
    }

    #[tokio::test]
    async fn test_callback_binding_mismatch_returns_400() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(pool, stub_handler_deps(&stub)).await;

        let (state, nonce, _challenge, binding) = begin_login(&app).await;
        stub.set_nonce(&nonce);

        // A DIFFERENT browser (wrong binding cookie) presents a valid state.
        let resp = app
            .clone()
            .oneshot(callback_req(&state, &other_test_binding(&binding)))
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
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(pool, stub_handler_deps(&stub)).await;

        let (state, nonce, _challenge, binding) = begin_login(&app).await;
        stub.set_nonce(&nonce);
        let mut request = callback_req(&state, &binding);
        request.headers_mut().append(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&format!(
                "other=value; __Host-entra_login_csrf={}",
                canonical_protocol_value()
            ))
            .expect("canonical duplicate binding cookie"),
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
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(pool, stub_handler_deps(&stub)).await;

        let (state, nonce, _challenge, binding) = begin_login(&app).await;
        // The stub issues an id_token with a DIFFERENT nonce.
        let mismatched_nonce = loop {
            let candidate = canonical_protocol_value();
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
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(pool, stub_handler_deps(&stub)).await;

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
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(pool, stub_handler_deps(&stub)).await;

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
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(pool, stub_handler_deps(&stub)).await;

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
        let Some(pool) = global_pool().await else {
            return;
        };

        let stub = start_stub_idp().await;
        let app = test_router(pool, stub_handler_deps(&stub)).await;

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
        let Some(pool) = global_pool().await else {
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
        let handler = crate::authenticator_runtime::VerifiedEntraSsoHandlerDeps::fixture(
            deps,
            crate::authenticator_runtime::VerifiedBrowserAuthenticatorOrigin::fixture(
                "entra-wrong-mode",
            ),
        );
        let app = test_router(pool, handler).await;

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
            .oneshot(callback_req(
                &canonical_protocol_value(),
                &canonical_protocol_value(),
            ))
            .await
            .expect("callback request");
        assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
        let body = body_json(callback).await;
        assert_eq!(body["error"], "ENTRA_AUTH_DISABLED");
    }
}
