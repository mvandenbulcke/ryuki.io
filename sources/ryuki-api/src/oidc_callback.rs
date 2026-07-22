//! OIDC authorization-code callback handler — slice 2.
//!
//! This module owns all OIDC-callback-specific machinery:
//! - Token exchange with the IdP (authorization-code → id_token)
//! - RS256 id_token validation (sig + iss + aud + exp + nbf + nonce)
//! - Session minting and the session cookie redirect
//!
//! # Security properties
//! - RS256 ONLY: alg-confusion defense enforced in the header check AND by
//!   `Validation::new(Algorithm::RS256)`.
//! - iss / aud / exp / nbf: pinned via `set_issuer`, `set_audience`,
//!   `set_required_spec_claims`, `validate_exp`, `validate_nbf`.
//! - nonce: stored server-side in `oidc_login_states`, compared to the
//!   id_token `nonce` claim AFTER signature validation.
//! - state single-use: `take()` is called before the token exchange; a missing
//!   or already-consumed state returns 400.
//! - No open redirect: post-login redirect is always `"/"`, IdP-error redirect
//!   is always `"/?auth_error=1"`.  Neither comes from user input.
//! - Secrets never logged: `client_secret`, `code`, `pkce_verifier`, `id_token`,
//!   `access_token` are NEVER passed to any `tracing::*` call.
//! - Roles from validated claims only, via the `roles_claim` config key.
//! - Validated provider subjects remain external lookup evidence. Identity
//!   authority resolves the exact provider/issuer/subject tuple to a random,
//!   opaque internal principal before persisting a session.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;
use url::{Host, Position, Url};
use uuid::Uuid;

// ─── Token exchange ───────────────────────────────────────────────────────────

const IDENTITY_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IDENTITY_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const fn identity_connect_timeout() -> Duration {
    IDENTITY_CONNECT_TIMEOUT
}

pub(crate) const fn identity_request_timeout() -> Duration {
    IDENTITY_REQUEST_TIMEOUT
}

/// Upper bound on a token-endpoint response. ID tokens are normally only a few
/// KiB; one MiB leaves ample interoperability headroom without allowing a
/// chunked response to grow the callback process's buffer without bound.
const MAX_TOKEN_RESPONSE_BYTES: usize = 1 << 20;

/// Parse an identity-provider URL and enforce the transport boundary shared by
/// token and JWKS clients. Production and developer binaries require HTTPS for
/// every endpoint. Unit tests alone may use plain HTTP with a literal loopback
/// address so closed local fixtures can exercise the real client path.
/// Redirects are disabled separately, so even a test request cannot escape its
/// originally admitted endpoint.
pub(crate) fn parse_identity_endpoint(raw: &str) -> Result<Url, &'static str> {
    parse_identity_endpoint_with_policy(raw, cfg!(test))
}

fn parse_identity_endpoint_with_policy(
    raw: &str,
    allow_loopback_http: bool,
) -> Result<Url, &'static str> {
    // `url` intentionally normalizes several special-scheme spellings (for
    // example a single slash or a backslash) and strips surrounding ASCII
    // whitespace/control characters. Identity endpoints are trust anchors, so
    // require one canonical raw spelling before parsing rather than admitting
    // a value whose security-relevant authority changes during normalization.
    if raw.chars().any(char::is_whitespace)
        || raw.bytes().any(|byte| byte.is_ascii_control())
        || raw.contains('\\')
    {
        return Err("invalid-url");
    }
    let authority_start = if raw
        .get(.."https://".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    {
        "https://".len()
    } else if raw
        .get(.."http://".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
    {
        "http://".len()
    } else {
        return Err("invalid-url");
    };

    // The URL parser normalizes an explicit empty userinfo marker
    // (`https://@host`) away. Reject every raw authority containing `@` before
    // parsing so that ambiguous empty credentials fail closed too.
    let raw_authority = raw[authority_start..]
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty())
        .ok_or("missing-host")?;
    if raw_authority.contains('@') {
        return Err("userinfo-not-allowed");
    }
    let url = Url::parse(raw).map_err(|_| "invalid-url")?;
    if url.host().is_none() {
        return Err("missing-host");
    }
    // Slicing the complete userinfo region also catches an explicit empty
    // username (`https://@host`), which `Url::username()` alone represents as
    // the same empty string as an absent username.
    if !url[Position::BeforeUsername..Position::BeforeHost].is_empty() {
        return Err("userinfo-not-allowed");
    }
    if url.fragment().is_some() {
        return Err("fragment-not-allowed");
    }

    match url.scheme() {
        "https" => Ok(url),
        "http" if allow_loopback_http && identity_endpoint_is_loopback(&url) => Ok(url),
        _ => Err("https-required"),
    }
}

fn identity_endpoint_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    }
}

/// Build an HTTP client for one already-validated identity endpoint. Every
/// credential/trust-bearing request has a connect deadline, an end-to-end
/// deadline, and a no-redirect policy. HTTPS-only is additionally enabled for
/// non-loopback endpoints as a second enforcement layer.
pub(crate) fn identity_http_client(endpoint: &Url) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(IDENTITY_CONNECT_TIMEOUT)
        .timeout(IDENTITY_REQUEST_TIMEOUT)
        // Identity credentials and signing trust must never traverse an
        // ambient HTTP(S)/ALL_PROXY route selected outside the reviewed IdP
        // configuration. This also keeps the test-only loopback exception
        // local instead of allowing a proxy hop.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(endpoint.scheme() == "https")
        .build()
        .expect("identity HTTP client build should not fail with static policy")
}

/// Deserialize a JSON response without ever buffering more than `limit`
/// bytes. Checking `Content-Length` alone is insufficient because HTTP/1.1
/// chunked and HTTP/2 responses can omit it.
pub(crate) async fn bounded_json_response<T: DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<T, ()> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(());
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        let new_len = body.len().checked_add(chunk.len()).ok_or(())?;
        if new_len > limit {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| ())
}

/// Parameters for the authorization-code → token exchange.
pub struct TokenRequest {
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    /// `Some` for confidential clients (the generic OIDC flow, which requires
    /// a secret when enabled); `None` for public clients (the Entra ID browser
    /// SSO flow, which is PKCE-only — no `client_secret` form field is sent at
    /// all, since Entra rejects the parameter from public-client app
    /// registrations). NEVER log.
    pub client_secret: Option<String>, // secret-scan-allow: field name, not a literal secret
    pub pkce_verifier: String,
}

/// Relevant fields from a token endpoint response.
pub struct TokenResponse {
    pub id_token: String,
    #[allow(dead_code)]
    pub access_token: Option<String>, // secret-scan-allow: field name, not a literal secret
}

/// Errors that can occur during the token exchange.
pub enum OidcError {
    /// Network or HTTP-level failure. No secret detail surfaced.
    Transport,
    /// IdP returned a non-success status.
    IdpError,
    /// The response body did not contain an `id_token` field.
    MissingIdToken,
    /// The response body could not be deserialized.
    Deserialize,
}

/// Object-safe async token exchanger.  The `Pin<Box<dyn Future>>` return lets
/// implementations be stored as `Arc<dyn TokenExchanger>` without `async-trait`.
pub trait TokenExchanger: Send + Sync {
    fn exchange<'a>(
        &'a self,
        req: &'a TokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TokenResponse, OidcError>> + Send + 'a>>;
}

// Raw token-endpoint response shape (private to this module).
#[derive(Deserialize)]
struct RawTokenResponse {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    access_token: Option<String>, // secret-scan-allow: field name, not a literal secret
}

/// Production exchanger: a `reqwest::Client` with a 10-second timeout and
/// rustls TLS, pointed at the configured `token_endpoint`.
pub struct ReqwestTokenExchanger {
    client: reqwest::Client,
    token_endpoint: Url,
}

impl ReqwestTokenExchanger {
    pub fn new(token_endpoint: impl Into<String>) -> Self {
        let token_endpoint = token_endpoint.into();
        let token_endpoint = parse_identity_endpoint(&token_endpoint).expect(
            "OIDC token endpoint must be a parsed HTTPS URL (loopback HTTP is unit-test only)",
        );
        let client = identity_http_client(&token_endpoint);
        Self {
            client,
            token_endpoint,
        }
    }
}

impl TokenExchanger for ReqwestTokenExchanger {
    fn exchange<'a>(
        &'a self,
        req: &'a TokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TokenResponse, OidcError>> + Send + 'a>> {
        Box::pin(async move {
            // Build the form body.  `client_secret` is sent in the body (never
            // in a URL or log line), and ONLY for confidential clients — a
            // public (PKCE-only) client omits the field entirely.
            let mut form: Vec<(&str, &str)> = vec![
                ("grant_type", "authorization_code"),
                ("code", &req.code),
                ("redirect_uri", &req.redirect_uri),
                ("client_id", &req.client_id),
                ("code_verifier", &req.pkce_verifier),
            ];
            if let Some(secret) = req.client_secret.as_deref() {
                form.push(("client_secret", secret));
            }

            let resp = self
                .client
                .post(self.token_endpoint.clone())
                .form(&form)
                .send()
                .await
                .map_err(|_| OidcError::Transport)?;

            if !resp.status().is_success() {
                return Err(OidcError::IdpError);
            }

            let raw: RawTokenResponse = bounded_json_response(resp, MAX_TOKEN_RESPONSE_BYTES)
                .await
                .map_err(|_| OidcError::Deserialize)?;
            let id_token = raw.id_token.ok_or(OidcError::MissingIdToken)?;

            Ok(TokenResponse {
                id_token,
                access_token: raw.access_token, // secret-scan-allow: moving parsed field, not a literal secret
            })
        })
    }
}

// ─── JWKS cache (same pattern as entra_auth.rs, separate type) ───────────────

struct JwksState {
    keys: HashMap<String, DecodingKey>,
    /// Absolute monotonic deadline for this complete cache generation. A key
    /// can never become usable again after the deadline, including when the
    /// next refresh fails or is inside the retry cooldown.
    valid_until: Option<Instant>,
    last_refresh_attempt: Option<Instant>,
    /// Monotonic publication token. A slow/cancelled refresh can never
    /// overwrite a generation elected by a later refresh attempt.
    refresh_generation: u64,
}

const REFRESH_COOLDOWN: Duration = Duration::from_secs(300);

/// Upper bound on cached JWKS signing keys. A real IdP publishes a small handful
/// (current + rotating); this caps the retained key set.
const MAX_JWKS_KEYS: usize = 32;

/// Upper bound on the actual streamed JWKS response body. A declared length is
/// only an early rejection hint; the cumulative bytes remain authoritative.
const MAX_JWKS_BYTES: usize = 1 << 20;

struct JwksCache {
    http: reqwest::Client,
    jwks_uri: Url,
    ttl: Duration,
    inner: RwLock<JwksState>,
}

#[derive(Debug, Deserialize)]
struct OidcJwk {
    kid: String,
    n: String,
    e: String,
    #[serde(default)]
    kty: Option<String>,
    #[serde(default, rename = "use")]
    use_: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcJwksDocument {
    keys: Vec<OidcJwk>,
}

impl JwksCache {
    fn new(http: reqwest::Client, jwks_uri: Url, ttl: Duration) -> Self {
        Self {
            http,
            jwks_uri,
            ttl,
            inner: RwLock::new(JwksState {
                keys: HashMap::new(),
                valid_until: None,
                last_refresh_attempt: None,
                refresh_generation: 0,
            }),
        }
    }

    /// Resolves a signing key only from a cache generation that is still
    /// within its configured TTL. Once the absolute deadline passes, failed
    /// refreshes and retry cooldowns clear the retired generation rather than
    /// leaving it available to any later lookup branch.
    async fn decoding_key_for_kid(&self, kid: &str) -> Option<DecodingKey> {
        // Fast path.
        {
            let state = self.inner.read().await;
            if let Some(key) = state.keys.get(kid) {
                if Self::fresh(&state) {
                    return Some(key.clone());
                }
            }
        }

        // Slow path: elect one cooldown-bounded refresher under the write lock,
        // then release the lock before any network transfer or JSON work. Known
        // kids from a still-fresh generation therefore remain non-blocking.
        let refresh_generation = {
            let mut state = self.inner.write().await;
            if let Some(key) = state.keys.get(kid) {
                if Self::fresh(&state) {
                    return Some(key.clone());
                }
            }

            let now = Instant::now();
            let cooled_down = state
                .last_refresh_attempt
                .map(|t| now.duration_since(t) >= REFRESH_COOLDOWN)
                .unwrap_or(true);
            if !cooled_down {
                return Self::resolved_key_or_expire(&mut state, kid);
            }

            let Some(next_generation) = state.refresh_generation.checked_add(1) else {
                return Self::resolved_key_or_expire(&mut state, kid);
            };
            state.last_refresh_attempt = Some(now);
            state.refresh_generation = next_generation;
            next_generation
        };

        let fetched = self.fetch_keys().await;
        let mut state = self.inner.write().await;
        if state.refresh_generation == refresh_generation {
            if let Ok(keys) = fetched {
                // Convert the configured relative TTL to one absolute,
                // monotonic deadline before publishing the generation.
                if let Some(valid_until) = Instant::now().checked_add(self.ttl) {
                    state.keys = keys;
                    state.valid_until = Some(valid_until);
                } else {
                    state.keys.clear();
                    state.valid_until = None;
                }
            }
        }
        Self::resolved_key_or_expire(&mut state, kid)
    }

    fn fresh(state: &JwksState) -> bool {
        state
            .valid_until
            .is_some_and(|deadline| Instant::now() < deadline)
    }

    fn resolved_key_or_expire(state: &mut JwksState, kid: &str) -> Option<DecodingKey> {
        if Self::fresh(state) {
            state.keys.get(kid).cloned()
        } else {
            state.keys.clear();
            state.valid_until = None;
            None
        }
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, DecodingKey>, ()> {
        let resp = self
            .http
            .get(self.jwks_uri.clone())
            .send()
            .await
            .map_err(|_| ())?;
        if !resp.status().is_success() {
            return Err(());
        }
        let doc: OidcJwksDocument = bounded_json_response(resp, MAX_JWKS_BYTES).await?;
        let mut keys = HashMap::new();
        for jwk in doc.keys {
            // Bound the retained cache: a real signing JWKS holds a handful of
            // keys; cap the long-lived key set.
            if keys.len() >= MAX_JWKS_KEYS {
                break;
            }
            // `kty` is REQUIRED (RFC 7517 §4.1); only RSA keys are usable for the
            // RS256 we enforce. Reject a key that omits it or is non-RSA — never
            // build a decoding key from an untyped JWK.
            if jwk.kty.as_deref() != Some("RSA") {
                continue;
            }
            // `use` is OPTIONAL (RFC 7517 §4.2); when present it must be "sig".
            if let Some(u) = &jwk.use_ {
                if u != "sig" {
                    continue;
                }
            }
            if let Ok(key) = DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
                keys.insert(jwk.kid, key);
            }
        }
        if keys.is_empty() {
            // A syntactically valid document with no usable RS256 signing key
            // is not a new trust generation. Treat it exactly like a failed
            // refresh so a still-valid generation is not replaced by outage.
            Err(())
        } else {
            Ok(keys)
        }
    }
}

// ─── Injectable key source ────────────────────────────────────────────────────

#[allow(dead_code)]
enum KeySource {
    Network(JwksCache),
    Static(HashMap<String, DecodingKey>),
}

// ─── id_token validator ───────────────────────────────────────────────────────

/// Validated identity extracted from an OIDC id_token.
pub struct ValidatedOidcClaims {
    /// External provider-subject evidence selected by the explicit validator
    /// policy. This value is lookup material for the opaque principal registry;
    /// it is never an internal principal identifier. Generic OIDC uses `sub`,
    /// while the Entra-specific entry point requires canonical `oid`.
    pub provider_subject: String,
    /// `name` → `preferred_username` → provider-subject fallback chain.
    pub display_name: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
}

#[derive(Clone, Copy)]
enum SubjectMapping {
    StandardSub,
    EntraCanonicalOid,
}

/// Return the exact canonical Entra directory object identifier.
///
/// Entra `oid` values are UUIDs. Accepting an alternate UUID spelling,
/// surrounding whitespace, or `sub` as a fallback would let one directory
/// object enter the principal registry under multiple provider keys.
fn canonical_entra_oid(value: Option<&str>) -> Option<&str> {
    let value = value?;
    let parsed = Uuid::parse_str(value).ok()?;
    (parsed.hyphenated().to_string() == value).then_some(value)
}

/// RS256 id_token validator.  Built once from OIDC config (or injected with
/// static keys in tests).
pub struct OidcIdTokenValidator {
    issuer: String,
    audience: String,
    keys: KeySource,
    leeway_secs: u64,
}

impl OidcIdTokenValidator {
    /// Production constructor: network-backed JWKS cache.
    pub fn new(
        jwks_uri: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        leeway_secs: u64,
    ) -> Self {
        let jwks_uri = jwks_uri.into();
        let jwks_uri = parse_identity_endpoint(&jwks_uri).expect(
            "OIDC JWKS endpoint must be a parsed HTTPS URL (loopback HTTP is unit-test only)",
        );
        let issuer = issuer.into();
        parse_identity_endpoint(&issuer)
            .expect("OIDC issuer must be a parsed HTTPS URL (loopback HTTP is unit-test only)");
        let http = identity_http_client(&jwks_uri);
        let cache = JwksCache::new(
            http,
            jwks_uri,
            Duration::from_secs(3600), // 1-hour TTL; typical for OIDC JWKS
        );
        Self {
            issuer,
            audience: audience.into(),
            keys: KeySource::Network(cache),
            leeway_secs,
        }
    }

    /// Test constructor: pre-built key map, no network.
    #[cfg(test)]
    pub fn with_static_keys(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        keys: HashMap<String, DecodingKey>,
    ) -> Self {
        let issuer = issuer.into();
        parse_identity_endpoint(&issuer)
            .expect("OIDC issuer must be a parsed HTTPS URL (loopback HTTP is unit-test only)");
        Self {
            issuer,
            audience: audience.into(),
            keys: KeySource::Static(keys),
            leeway_secs: 60,
        }
    }

    async fn resolve_key(&self, kid: &str) -> Option<DecodingKey> {
        match &self.keys {
            KeySource::Static(map) => map.get(kid).cloned(),
            KeySource::Network(cache) => cache.decoding_key_for_kid(kid).await,
        }
    }

    /// Validate an RS256 id_token, verify the nonce, and extract identity.
    ///
    /// Returns a safe `&'static str` reason on any failure path.  The token
    /// itself is NEVER included in any error or log message.
    ///
    /// # Steps
    /// 1. Decode JOSE header — check `alg == RS256`, extract `kid`.
    /// 2. Resolve the signing key.
    /// 3. `jsonwebtoken::decode` with RS256 + pinned iss/aud/exp/nbf.
    /// 4. Check `nonce` claim matches `expected_nonce`.
    /// 5. Extract identity fields and roles.
    pub async fn validate_id_token(
        &self,
        token: &str,
        expected_nonce: &str,
        roles_claim: &str,
    ) -> Result<ValidatedOidcClaims, &'static str> {
        self.validate_id_token_with_subject_mapping(
            token,
            expected_nonce,
            roles_claim,
            SubjectMapping::StandardSub,
        )
        .await
    }

    /// Entra browser SSO uses the tenant object id as its durable provider
    /// subject. The object id must use its canonical lowercase, hyphenated UUID
    /// spelling and never falls back to `sub`. Keeping this policy behind an
    /// explicit entry point prevents a vendor claim from changing generic OIDC
    /// identity semantics.
    pub(crate) async fn validate_entra_id_token(
        &self,
        token: &str,
        expected_nonce: &str,
        roles_claim: &str,
    ) -> Result<ValidatedOidcClaims, &'static str> {
        self.validate_id_token_with_subject_mapping(
            token,
            expected_nonce,
            roles_claim,
            SubjectMapping::EntraCanonicalOid,
        )
        .await
    }

    async fn validate_id_token_with_subject_mapping(
        &self,
        token: &str,
        expected_nonce: &str,
        roles_claim: &str,
        subject_mapping: SubjectMapping,
    ) -> Result<ValidatedOidcClaims, &'static str> {
        // Step 1: decode header only — check alg and get kid.
        let header = decode_header(token).map_err(|_| "bad-token-header")?;
        if header.alg != Algorithm::RS256 {
            return Err("wrong-algorithm");
        }
        let kid = header.kid.as_deref().ok_or("missing-kid")?;

        // Step 2: resolve signing key.
        let decoding_key = self.resolve_key(kid).await.ok_or("unknown-kid")?;

        // Step 3: validate signature + standard claims.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(std::slice::from_ref(&self.issuer));
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = self.leeway_secs;

        let data =
            decode::<Value>(token, &decoding_key, &validation).map_err(|_| "validation-failed")?;
        let claims = data.claims;

        // Step 4: verify nonce.
        let token_nonce = claims
            .get("nonce")
            .and_then(|v| v.as_str())
            .ok_or("missing-nonce")?;
        // Constant-time comparison would be ideal, but nonces are single-use
        // server-generated values; timing attacks here give no meaningful
        // advantage.  We still use `==` to avoid introducing dependencies.
        if token_nonce != expected_nonce {
            return Err("nonce-mismatch");
        }

        // Step 5: extract identity.
        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .filter(|subject| !subject.trim().is_empty())
            .ok_or("missing-sub")?;
        let provider_subject = match subject_mapping {
            SubjectMapping::StandardSub => sub,
            SubjectMapping::EntraCanonicalOid => {
                canonical_entra_oid(claims.get("oid").and_then(|value| value.as_str()))
                    .ok_or("invalid-token")?
            }
        }
        .to_string();

        let display_name = claims
            .get("name")
            .and_then(|v| v.as_str())
            .or_else(|| claims.get("preferred_username").and_then(|v| v.as_str()))
            .unwrap_or(&provider_subject)
            .to_string();

        let email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let roles: Vec<String> = claims
            .get(roles_claim)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        Ok(ValidatedOidcClaims {
            provider_subject,
            display_name,
            email,
            roles,
        })
    }
}

// ─── Dependency bundle ────────────────────────────────────────────────────────

/// All OIDC-callback dependencies injected as a single axum `Extension`.
/// In production, built once at startup from config.
/// In tests, built with a `StubTokenExchanger` and a static-key validator.
pub struct OidcCallbackDeps {
    pub exchanger: Arc<dyn TokenExchanger + Send + Sync>,
    pub validator: Arc<OidcIdTokenValidator>,
}

// ─── Handler ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct OidcCallbackQuery {
    /// Authorization code returned by the identity provider; required together
    /// with `state` on the successful callback path.
    pub code: Option<String>,
    /// Single-use state returned by the identity provider; required together
    /// with `code` on the successful callback path.
    pub state: Option<String>,
    /// Identity-provider error code. When present, the callback follows the
    /// sanitized error-redirect path instead of the code-exchange path.
    pub error: Option<String>,
    #[allow(dead_code)]
    /// Optional provider error detail. It is accepted for protocol compatibility
    /// but is never forwarded to the browser.
    pub error_description: Option<String>,
}

fn invalid_state_problem() -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "OIDC_INVALID_STATE",
            "message": "Login state is missing, expired, or already used"
        })),
    )
}

/// OIDC authorization-code callback handler.
///
/// Full flow (matches the spec):
/// 1. Gate on `oidc.enabled`.
/// 2. Gate on DB availability.
/// 3. If the IdP returned `?error=`, redirect to `/?auth_error=1`.
/// 4. Require `code` and `state`.
/// 5. Consume the state row (single-use, expiry-checked).
/// 6. Exchange the code for an id_token.
/// 7. Validate the id_token (sig + claims + nonce).
/// 8. Mint a session row.
/// 9. Set the session cookie and redirect to `/`.
pub(crate) async fn oidc_callback(
    Extension(deps): Extension<Arc<OidcCallbackDeps>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<OidcCallbackQuery>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    use axum::http::header::LOCATION;

    let cfg = crate::config_store::get_app_config();

    // Gate 1: OIDC enabled.
    if !cfg.oidc.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "OIDC login is not enabled"})),
        ));
    }

    // Gate 2: DB available.
    let pool = crate::database::get_db().ok_or_else(crate::contracts::status_503_no_db)?;

    // Gate 3: IdP returned an error — redirect without minting a session.
    // The error text is NEVER forwarded (open-info-disclosure + injection risk).
    if params.error.is_some() {
        tracing::warn!("oidc callback: IdP returned an error, redirecting to auth_error page");
        let location = axum::http::HeaderValue::from_static("/?auth_error=1");
        return Ok((StatusCode::FOUND, [(LOCATION, location)]).into_response());
    }

    // Gate 4: require code and state.
    let code_val = params.code.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "OIDC_INVALID_REQUEST",
                "message": "Missing authorization code"
            })),
        )
    })?;
    let state_val = params.state.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "OIDC_INVALID_REQUEST",
                "message": "Missing state parameter"
            })),
        )
    })?;

    // Step 5: consume the state row (single-use, expiry-checked).
    let (nonce, pkce_verifier, binding) =
        match crate::repos::oidc_login_states::take(pool, &state_val)
            .await
            .map_err(crate::contracts::db_error)?
        {
            Some(row) => row,
            None => {
                return Err(invalid_state_problem());
            }
        };

    // Step 5b: login-CSRF / session-swapping defense. The state is redeemable
    // only by the SAME browser that initiated the login: that browser holds the
    // mode-selected login-CSRF cookie whose value equals the binding stored
    // with the state. HTTPS uses a browser-enforced `__Host-` name. A `state`
    // obtained from an attacker's own flow carries a different binding, so a
    // victim's browser cannot redeem it. Constant-time compare is unnecessary:
    // both values are single-use, server-generated 256-bit values.
    let cookie_runtime = crate::config_store::get_api_cookie_runtime();
    let cookie_binding = match cookie_runtime.oidc_binding_parser().parse(&headers) {
        crate::cookie_runtime::CookieEvidence::Value(value) => value,
        crate::cookie_runtime::CookieEvidence::Absent
        | crate::cookie_runtime::CookieEvidence::Invalid => return Err(invalid_state_problem()),
    };
    if binding.is_empty() || cookie_binding != binding {
        tracing::warn!("oidc callback: login-state browser binding mismatch");
        return Err(invalid_state_problem());
    }

    // Step 6: token exchange.
    // NEVER log code, pkce_verifier, client_secret, or the resulting id_token.
    let token_resp = deps
        .exchanger
        .exchange(&TokenRequest {
            code: code_val,
            redirect_uri: cfg.oidc.redirect_uri.clone(),
            client_id: cfg.oidc.client_id.clone(),
            // The generic OIDC flow is a confidential client: config validation
            // requires the secret when oidc.enabled, so it is always sent here.
            client_secret: Some(cfg.oidc.client_secret.clone()), // secret-scan-allow: passing config ref, not a hardcoded secret
            pkce_verifier,
        })
        .await
        .map_err(|_| {
            tracing::error!("oidc token exchange failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "OIDC_TOKEN_EXCHANGE_FAILED"})),
            )
        })?;

    // Step 7: validate id_token.
    // Log only the safe reason string, never the token itself.
    let claims = deps
        .validator
        .validate_id_token(&token_resp.id_token, &nonce, &cfg.oidc.roles_claim)
        .await
        .map_err(|reason| {
            tracing::warn!(reason, "oidc id_token validation failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "OIDC_TOKEN_INVALID"})),
            )
        })?;

    // Step 8: mint unrelated management and authentication values. Only the
    // keyed verifier is persisted; the plaintext bearer is cookie-only.
    let session_record_id = Uuid::new_v4();
    let credential =
        crate::session_credentials::issue_session_credential(&cfg.session).map_err(|error| {
            tracing::error!(reason = %error, "oidc session credential issuance failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "AUTH_SESSION_PERSISTENCE_FAILED"})),
            )
        })?;
    crate::contracts::map_auth_session_persistence_result(
        crate::identity_authority::create_federated_session(
            pool,
            "oidc",
            &cfg.oidc.issuer,
            &claims.provider_subject,
            &claims.display_name,
            claims.email.as_deref(),
            &claims.roles,
            session_record_id,
            credential.verifier().as_slice(),
            cfg.session.cookie_max_age_secs,
            &cfg.session,
        )
        .await,
        "create",
    )
    .map_err(|(status, Json(api_err))| {
        (
            status,
            Json(serde_json::to_value(&api_err).unwrap_or_else(
                |_| serde_json::json!({"error": "AUTH_SESSION_PERSISTENCE_FAILED"}),
            )),
        )
    })?;

    // Do not log the bearer, verifier, or management UUID.
    tracing::info!("oidc login session created");

    // Step 9: set the session cookie and redirect to the portal root. The
    // issuer handle retains the exact startup cookie authority. The redirect
    // target is hardcoded, so there is no open-redirect risk.
    let cookies = cookie_runtime
        .oidc_session_issuer()
        .issue(credential.bearer())
        .map_err(|error| {
            tracing::error!(error = %error, "OIDC session cookie field creation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "cookie header encoding failed"})),
            )
        })?;
    let binding_retirement = cookie_runtime
        .oidc_binding_issuer()
        .retire()
        .map_err(|error| {
            tracing::error!(error = %error, "OIDC binding cookie retirement failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "cookie header encoding failed"})),
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

// ─── DB tests ─────────────────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api --bins oidc_callback -- --test-threads=1
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.

#[cfg(test)]
mod oidc_callback_db_tests {
    use super::*;
    use crate::test_crypto;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;
    use sqlx::PgPool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tower::ServiceExt;

    // ─── Helper: RYUKI_DATABASE_URL gate ──────────────────────────────────
    //
    // Mirrors the contracts DB test pattern exactly: uses `try_connect_with_url`
    // to populate the process-global pool (a `OnceLock`) and returns a
    // reference to it. Subsequent calls in the same process are a no-op on
    // the OnceLock and re-use the existing pool.

    async fn global_pool() -> Option<&'static PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("oidc_callback_db_tests: RYUKI_DATABASE_URL not set — skipping DB tests");
                return None;
            }
        };
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()?;
        crate::database::run_migrations(pool).await.ok()?;
        Some(pool)
    }

    // ─── Crypto helpers (same pattern as entra_auth.rs tests) ─────────────

    const TEST_KID: &str = "oidc-test-kid-1";
    const TEST_ISS: &str = "https://idp.example.com";
    const TEST_AUD: &str = "oidc-client-test";
    const TEST_ENTRA_OID: &str = "11111111-2222-4333-8444-555555555555";
    const TEST_BINDING: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OTHER_TEST_BINDING: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    async fn read_test_http_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let count = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer))
                .await
                .expect("test request read timed out")
                .expect("test request read failed");
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);

            let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
        request
    }

    fn test_jwks_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(250))
            .timeout(Duration::from_secs(3))
            .build()
            .expect("build loopback-only JWKS test client")
    }

    async fn loopback_jwks_listener() -> (tokio::net::TcpListener, Url) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback JWKS test endpoint");
        let address = listener.local_addr().expect("JWKS test endpoint address");
        let url =
            Url::parse(&format!("http://{address}/jwks")).expect("parse loopback JWKS test URL");
        (listener, url)
    }

    async fn seed_jwks_cache(
        cache: &JwksCache,
        kid: &str,
        key: DecodingKey,
        valid_until: Instant,
        last_refresh_attempt: Option<Instant>,
    ) {
        let mut state = cache.inner.write().await;
        state.keys.insert(kid.to_string(), key);
        state.valid_until = Some(valid_until);
        state.last_refresh_attempt = last_refresh_attempt;
    }

    #[test]
    fn test_identity_endpoint_policy_requires_https_except_literal_loopback_tests() {
        assert!(parse_identity_endpoint("https://idp.example/token").is_ok());
        assert_eq!(
            parse_identity_endpoint("HTTPS://idp.example/token")
                .expect("URL schemes are case-insensitive")
                .scheme(),
            "https"
        );
        assert!(
            parse_identity_endpoint("https://idp.example/path/@team?email=a@b").is_ok(),
            "an at-sign outside the authority is ordinary path/query data"
        );
        assert!(parse_identity_endpoint("http://127.0.0.1:8080/token").is_ok());
        assert!(parse_identity_endpoint("http://[::1]:8080/jwks").is_ok());
        assert_eq!(
            parse_identity_endpoint_with_policy("http://127.0.0.1:8080/token", false).unwrap_err(),
            "https-required",
            "all non-test binaries must disable the loopback HTTP exception"
        );

        for endpoint in [
            "http://idp.example/token",
            "http://localhost:8080/token",
            "http://127.0.0.1.example/token",
            "http://10.0.0.1/token",
            "http://0.0.0.0/token",
        ] {
            assert_eq!(
                parse_identity_endpoint(endpoint).unwrap_err(),
                "https-required"
            );
        }
        assert_eq!(
            parse_identity_endpoint("https://operator@idp.example/token").unwrap_err(),
            "userinfo-not-allowed"
        );
        assert_eq!(
            parse_identity_endpoint("https://@idp.example/token").unwrap_err(),
            "userinfo-not-allowed"
        );
        assert_eq!(
            parse_identity_endpoint("HTTPS://@idp.example/token").unwrap_err(),
            "userinfo-not-allowed"
        );
        assert_eq!(
            parse_identity_endpoint("https://idp.example/token#fragment").unwrap_err(),
            "fragment-not-allowed"
        );
        for malformed in [
            "not a URL",
            "//idp.example/token",
            "https:/@idp.example/token",
            "https:///idp.example/token",
            "https:////idp.example/token",
            r"https:\@idp.example/token",
            r"https:\\@idp.example/token",
            " https://idp.example/token",
            "https://idp.example/token\n",
            "https://idp.example:invalid/token",
            "https-evil://idp.example/token",
        ] {
            assert!(
                parse_identity_endpoint(malformed).is_err(),
                "malformed or lookalike endpoint must fail: {malformed}"
            );
        }
    }

    #[tokio::test]
    async fn test_generic_jwks_fresh_cached_key_is_returned_without_refresh() {
        let keypair = test_crypto::make_rsa_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = JwksCache::new(test_jwks_client(), url, Duration::from_secs(60));
        seed_jwks_cache(
            &cache,
            TEST_KID,
            keypair.decoding,
            Instant::now()
                .checked_add(Duration::from_secs(60))
                .expect("represent a fresh cache deadline"),
            None,
        )
        .await;
        let unexpected_refresh = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_ok()
        });

        assert!(cache.decoding_key_for_kid(TEST_KID).await.is_some());
        assert!(
            !unexpected_refresh.await.expect("JWKS probe task"),
            "a fresh cached key must not trigger a refresh"
        );
        assert!(
            cache.inner.read().await.last_refresh_attempt.is_none(),
            "the fresh-cache fast path must not stamp a refresh attempt"
        );
    }

    #[tokio::test]
    async fn test_generic_jwks_known_key_remains_nonblocking_during_unknown_kid_refresh() {
        let keypair = test_crypto::make_rsa_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = Arc::new(JwksCache::new(
            test_jwks_client(),
            url,
            Duration::from_secs(60),
        ));
        seed_jwks_cache(
            &cache,
            TEST_KID,
            keypair.decoding,
            Instant::now()
                .checked_add(Duration::from_secs(60))
                .expect("represent a fresh cache deadline"),
            None,
        )
        .await;

        let (refresh_started_tx, refresh_started_rx) = tokio::sync::oneshot::channel();
        let (release_refresh_tx, release_refresh_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept JWKS refresh request");
            let _request = read_test_http_request(&mut stream).await;
            refresh_started_tx
                .send(())
                .expect("signal that the refresh request is held open");
            release_refresh_rx
                .await
                .expect("release the held JWKS refresh response");
            let body = r#"{"keys":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write empty JWKS refresh response");
        });

        let refresh_cache = Arc::clone(&cache);
        let refresh = tokio::spawn(async move {
            refresh_cache
                .decoding_key_for_kid("never-published-kid")
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), refresh_started_rx)
            .await
            .expect("unknown-kid refresh must reach the fixture")
            .expect("refresh-start signal must remain live");

        let known_key =
            tokio::time::timeout(Duration::from_secs(1), cache.decoding_key_for_kid(TEST_KID))
                .await
                .expect("a fresh known key must not wait behind network refresh");
        assert!(known_key.is_some());

        release_refresh_tx
            .send(())
            .expect("release the unknown-kid refresh fixture");
        assert!(refresh
            .await
            .expect("unknown-kid refresh task must complete")
            .is_none());
        server.await.expect("held JWKS server task");
        assert!(
            cache.decoding_key_for_kid(TEST_KID).await.is_some(),
            "an empty refresh document must not replace a still-valid generation"
        );
    }

    #[tokio::test]
    async fn test_generic_jwks_expired_key_is_rejected_during_refresh_cooldown() {
        let keypair = test_crypto::make_rsa_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = JwksCache::new(test_jwks_client(), url, Duration::from_secs(1));
        let now = Instant::now();
        seed_jwks_cache(
            &cache,
            TEST_KID,
            keypair.decoding,
            now.checked_sub(Duration::from_secs(1))
                .expect("represent an expired cache deadline"),
            Some(now),
        )
        .await;
        let unexpected_refresh = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_ok()
        });

        assert!(cache.decoding_key_for_kid(TEST_KID).await.is_none());
        assert!(
            !unexpected_refresh.await.expect("JWKS probe task"),
            "refresh cooldown must remain effective"
        );
        assert!(
            !cache.inner.read().await.keys.contains_key(TEST_KID),
            "an expired key must be removed even while refresh is cooling down"
        );
    }

    #[tokio::test]
    async fn test_generic_jwks_expired_key_is_rejected_when_refresh_fails() {
        let keypair = test_crypto::make_rsa_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = JwksCache::new(test_jwks_client(), url, Duration::from_secs(1));
        seed_jwks_cache(
            &cache,
            TEST_KID,
            keypair.decoding,
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("represent an expired cache deadline"),
            None,
        )
        .await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .expect("JWKS refresh request deadline")
                .expect("accept JWKS refresh request");
            let _request = read_test_http_request(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write failed JWKS refresh response");
        });

        assert!(cache.decoding_key_for_kid(TEST_KID).await.is_none());
        server.await.expect("JWKS failure server task");
        let state = cache.inner.read().await;
        assert!(state.last_refresh_attempt.is_some());
        assert!(
            !state.keys.contains_key(TEST_KID),
            "refresh failure must remove the retired cache generation"
        );
    }

    #[tokio::test]
    async fn test_generic_jwks_expired_cache_uses_only_refreshed_generation() {
        const ROTATED_KID: &str = "oidc-test-kid-rotated";

        let old_keypair = test_crypto::make_rsa_keypair();
        let rotated_keypair = test_crypto::make_rsa_keypair();
        let jwks = json!({
            "keys": [{
                "kid": ROTATED_KID,
                "kty": "RSA",
                "use": "sig",
                "n": rotated_keypair.modulus_b64,
                "e": rotated_keypair.exponent_b64,
            }]
        })
        .to_string();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = JwksCache::new(test_jwks_client(), url, Duration::from_secs(1));
        seed_jwks_cache(
            &cache,
            TEST_KID,
            old_keypair.decoding,
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("represent an expired cache deadline"),
            None,
        )
        .await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept JWKS refresh request");
            let _request = read_test_http_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                jwks.len(),
                jwks
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write rotated JWKS response");
        });

        assert!(cache.decoding_key_for_kid(TEST_KID).await.is_none());
        server.await.expect("rotated JWKS server task");
        assert!(cache.decoding_key_for_kid(ROTATED_KID).await.is_some());
        let state = cache.inner.read().await;
        assert!(state.keys.contains_key(ROTATED_KID));
        assert!(!state.keys.contains_key(TEST_KID));
        assert!(JwksCache::fresh(&state));
    }

    #[tokio::test]
    async fn test_token_exchange_accepts_loopback_endpoint_and_small_json() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback test endpoint");
        let address = listener.local_addr().expect("test endpoint address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept token request");
            let _request = read_test_http_request(&mut stream).await;
            let body = r#"{"id_token":"fixture-id-token"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write token response");
        });

        let exchanger = ReqwestTokenExchanger::new(format!("http://{address}/token"));
        let response = match exchanger
            .exchange(&TokenRequest {
                code: "fixture-code".to_string(),
                redirect_uri: "http://localhost/callback".to_string(),
                client_id: "fixture-client".to_string(),
                client_secret: None,
                pkce_verifier: "fixture-verifier".to_string(),
            })
            .await
        {
            Ok(response) => response,
            Err(_) => panic!("small loopback token response should be accepted"),
        };
        assert_eq!(response.id_token, "fixture-id-token");
        server.await.expect("test token server task");
    }

    #[tokio::test]
    async fn test_token_exchange_never_replays_form_across_any_redirect_status() {
        // Redirect policy is unconditional and shared by production HTTPS and
        // unit-test loopback clients. Exercise every redirect status that an
        // HTTP stack might otherwise follow, with both same-origin and
        // cross-origin cleartext destinations.
        for (status_line, same_origin) in [
            ("301 Moved Permanently", true),
            ("302 Found", false),
            ("303 See Other", true),
            ("307 Temporary Redirect", false),
            ("308 Permanent Redirect", true),
        ] {
            let source_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind token-origin test endpoint");
            let source_address = source_listener
                .local_addr()
                .expect("token-origin test address");
            let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind redirect-target test endpoint");
            let target_address = target_listener
                .local_addr()
                .expect("redirect-target test address");
            let location = if same_origin {
                format!("http://{source_address}/captured")
            } else {
                format!("http://{target_address}/captured")
            };

            let source = tokio::spawn(async move {
                let (mut stream, _) = source_listener
                    .accept()
                    .await
                    .expect("accept token-origin request");
                let request = read_test_http_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write token redirect response");

                let same_origin_replay =
                    tokio::time::timeout(Duration::from_millis(250), source_listener.accept())
                        .await
                        .is_ok();
                (request, same_origin_replay)
            });
            let target = tokio::spawn(async move {
                let accepted =
                    tokio::time::timeout(Duration::from_millis(250), target_listener.accept())
                        .await;
                let Ok(Ok((mut stream, _))) = accepted else {
                    return false;
                };
                let _request = read_test_http_request(&mut stream).await;
                true
            });

            let exchanger = ReqwestTokenExchanger::new(format!("http://{source_address}/token"));
            let result = exchanger
                .exchange(&TokenRequest {
                    code: "fixture-code".to_string(),
                    redirect_uri: "http://localhost/callback".to_string(),
                    client_id: "fixture-client".to_string(),
                    client_secret: Some("fixture-credential".to_string()), // secret-scan-allow: non-secret redirect fixture
                    pkce_verifier: "fixture-verifier".to_string(),
                })
                .await;
            assert!(
                matches!(result, Err(OidcError::IdpError)),
                "redirect response must surface as an IdP error: {status_line}"
            );

            let (source_request, same_origin_replay) =
                source.await.expect("token-origin server task");
            let request = String::from_utf8_lossy(&source_request);
            assert!(request.contains("code=fixture-code"));
            assert!(request.contains("code_verifier=fixture-verifier"));
            assert!(request.contains("client_secret=fixture-credential")); // secret-scan-allow: non-secret redirect fixture
            assert!(
                !same_origin_replay,
                "same-origin redirect must not receive a second request: {status_line}"
            );
            assert!(
                !target.await.expect("redirect-target server task"),
                "cross-origin redirect must not receive the credential form: {status_line}"
            );
        }
    }

    #[tokio::test]
    async fn test_token_exchange_rejects_oversized_response_without_length() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind oversized-response test endpoint");
        let address = listener.local_addr().expect("test endpoint address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept token request");
            let _request = read_test_http_request(&mut stream).await;
            let oversized_valid_json = format!(
                "{{\"id_token\":\"{}\"}}",
                "a".repeat(MAX_TOKEN_RESPONSE_BYTES)
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write response headers");
            let _ = stream.write_all(oversized_valid_json.as_bytes()).await;
        });

        let exchanger = ReqwestTokenExchanger::new(format!("http://{address}/token"));
        let result = exchanger
            .exchange(&TokenRequest {
                code: "fixture-code".to_string(),
                redirect_uri: "http://localhost/callback".to_string(),
                client_id: "fixture-client".to_string(),
                client_secret: None,
                pkce_verifier: "fixture-verifier".to_string(),
            })
            .await;
        assert!(matches!(result, Err(OidcError::Deserialize)));
        server.await.expect("oversized-response test server task");
    }

    /// Build a callback GET request carrying the matching secure binding cookie.
    /// Tests that should proceed past the browser-binding check use this.
    fn callback_req(uri: String) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header(
                axum::http::header::COOKIE,
                format!("__Host-oidc_login_csrf={TEST_BINDING}"),
            )
            .body(Body::empty())
            .unwrap()
    }

    fn now() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Generates an RSA-2048 keypair.  Returns (EncodingKey, DecodingKey).
    fn make_keypair() -> (EncodingKey, DecodingKey) {
        let keypair = test_crypto::make_rsa_keypair();
        (keypair.encoding, keypair.decoding)
    }

    /// Signs a JSON claims object as RS256 under TEST_KID.
    fn sign_id_token(encoding: &EncodingKey, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        jsonwebtoken::encode(&header, &claims, encoding).expect("sign id_token")
    }

    /// Returns a valid id_token claims set with the expected callback nonce.
    fn valid_id_token_claims(claim_nonce: &str) -> serde_json::Value {
        json!({
            "iss": TEST_ISS,
            "aud": TEST_AUD,
            "sub": "sub-test-1",
            "oid": TEST_ENTRA_OID,
            "name": "Test User",
            "preferred_username": "test@example.com",
            "email": "test@example.com",
            "nonce": claim_nonce,
            "roles": ["PlatformAdmin"],
            "exp": now() + 3600,
            "nbf": now() - 60,
        })
    }

    // ─── Stub token exchangers ────────────────────────────────────────────

    struct StubTokenExchanger {
        id_token: String,
    }

    impl TokenExchanger for StubTokenExchanger {
        fn exchange<'a>(
            &'a self,
            _req: &'a TokenRequest,
        ) -> Pin<Box<dyn Future<Output = Result<TokenResponse, OidcError>> + Send + 'a>> {
            let id_token = self.id_token.clone();
            Box::pin(async move {
                Ok(TokenResponse {
                    id_token,
                    access_token: None,
                })
            })
        }
    }

    struct FailingTokenExchanger;

    impl TokenExchanger for FailingTokenExchanger {
        fn exchange<'a>(
            &'a self,
            _req: &'a TokenRequest,
        ) -> Pin<Box<dyn Future<Output = Result<TokenResponse, OidcError>> + Send + 'a>> {
            Box::pin(async move { Err(OidcError::IdpError) })
        }
    }

    // ─── Per-test config bootstrap ────────────────────────────────────────

    fn ensure_config() {
        let mut cfg = ryuki_core::config::RyukiConfig::default();
        cfg.oidc.enabled = true;
        cfg.oidc.issuer = TEST_ISS.to_string();
        cfg.oidc.client_id = TEST_AUD.to_string();
        cfg.oidc.client_secret = "test-secret".to_string(); // secret-scan-allow: test fixture
        cfg.oidc.redirect_uri = "http://localhost:8080/api/auth/oidc/callback".to_string();
        cfg.oidc.roles_claim = "roles".to_string();
        // Deliberately shorter than the schema's 24-hour default so the happy
        // path proves server-side expiry follows the configured cookie lifetime.
        cfg.session.cookie_max_age_secs = 600;
        cfg.session.credential_hmac_key = "k".repeat(32);
        crate::config_store::init_with_config("oidc-callback-test-config.json", &cfg);
    }

    // ─── Test router builder ──────────────────────────────────────────────

    /// Builds a minimal axum test router for `/api/auth/oidc/callback`.
    /// The handler reads the GLOBAL pool via `get_db()` — the pool is
    /// initialized by `global_pool()` before this is called.
    fn test_router(
        exchanger: Arc<dyn TokenExchanger + Send + Sync>,
        validator: Arc<OidcIdTokenValidator>,
    ) -> axum::Router {
        ensure_config();
        let deps = Arc::new(OidcCallbackDeps {
            exchanger,
            validator,
        });
        axum::Router::new()
            .route("/api/auth/oidc/callback", axum::routing::get(oidc_callback))
            .layer(Extension(deps))
    }

    /// Inserts a login-state row for test setup using the static pool.
    async fn insert_test_state(
        pool: &'static PgPool,
        state: &str,
        login_nonce: &str,
    ) -> Result<(), sqlx::Error> {
        crate::repos::oidc_login_states::insert_test_material(
            pool,
            crate::repos::oidc_login_states::LoginFlow::GenericOidc,
            state,
            login_nonce,
            "test-pkce-verifier",
            TEST_BINDING,
        )
        .await
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
        .expect("seed OIDC human authority");
    }

    // ─── Tests ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_callback_happy_path_mints_session_and_redirects() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        provision_global_assignment(
            pool,
            "oidc",
            TEST_ISS,
            "sub-test-1",
            &["PlatformAdmin".to_string()],
        )
        .await;

        let (enc, dec) = make_keypair();
        let nonce = "test-nonce-happy";
        let state = format!("st-happy-{}", Uuid::new_v4());

        insert_test_state(pool, &state, nonce)
            .await
            .expect("insert state");

        let id_token = sign_id_token(&enc, valid_id_token_claims(nonce));

        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);

        let exchanger: Arc<dyn TokenExchanger + Send + Sync> =
            Arc::new(StubTokenExchanger { id_token });
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map,
        ));

        let app = test_router(exchanger, validator);

        let req = callback_req(format!(
            "/api/auth/oidc/callback?code=test-code&state={}",
            state
        ));

        let resp = app.clone().oneshot(req).await.expect("request");
        assert_eq!(
            resp.status(),
            StatusCode::FOUND,
            "should redirect on success"
        );
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(location, "/", "should redirect to portal root");
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
        assert!(
            cookie.starts_with("__Host-ryuki_session="),
            "HTTPS cookie must carry the __Host-ryuki_session name"
        );
        assert!(cookie.contains("HttpOnly"), "cookie must be HttpOnly");
        assert!(cookie.contains("Max-Age=600"));
        assert_eq!(
            cookie_fields[1],
            "ryuki_session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax; Secure"
        );
        assert_eq!(
            cookie_fields[2],
            "__Host-oidc_login_csrf=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax; Secure"
        );

        let session_bearer = cookie
            .split(';')
            .next()
            .and_then(|pair| pair.strip_prefix("__Host-ryuki_session="))
            .expect("session cookie contains an opaque bearer");
        assert!(crate::session_credentials::is_well_formed_session_bearer(
            session_bearer
        ));
        let verifier = crate::session_credentials::session_bearer_verifier(
            session_bearer,
            &crate::config_store::get_app_config().session,
        )
        .expect("test verifier");
        let (
            record_id,
            principal_id,
            persisted_provider,
            persisted_issuer,
            persisted_subject,
            remaining_secs,
        ): (Uuid, Uuid, String, String, String, f64) = sqlx::query_as(
            "SELECT s.session_record_id, s.principal_id, k.provider_id, k.issuer, k.subject, \
                    EXTRACT(EPOCH FROM s.expires_at - NOW())::double precision \
             FROM sessions s \
             JOIN principal_keys k ON k.principal_key_id = s.principal_key_id \
             WHERE s.bearer_verifier = $1",
        )
        .bind(verifier.as_slice())
        .fetch_one(pool)
        .await
        .expect("load persisted OIDC session expiry");
        assert_ne!(
            principal_id,
            Uuid::nil(),
            "the persisted session must use a registry-issued opaque principal id"
        );
        assert_eq!(persisted_provider, "oidc");
        assert_eq!(
            persisted_issuer, TEST_ISS,
            "the exact validated issuer remains provider-key provenance"
        );
        assert_eq!(persisted_subject, "sub-test-1");
        assert!(
            (590.0..=600.0).contains(&remaining_secs),
            "server expiry must align with the configured 600-second cookie lifetime; got {remaining_secs}"
        );
        sqlx::query("DELETE FROM sessions WHERE session_record_id = $1")
            .bind(record_id)
            .execute(pool)
            .await
            .ok();
    }

    /// Login-CSRF / session-swapping defense: a VALID, unused state plus a fully
    /// valid id_token are STILL rejected when the browser does not present the
    /// matching `__Host-oidc_login_csrf` cookie. This blocks the attack where a victim's
    /// browser is fed a `state` obtained from the attacker's own OIDC flow.
    #[tokio::test]
    async fn test_callback_browser_binding_mismatch_returns_400() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let (enc, dec) = make_keypair();
        let nonce = "test-nonce-binding";
        let state = format!("st-binding-{}", Uuid::new_v4());
        insert_test_state(pool, &state, nonce)
            .await
            .expect("insert state");

        let id_token = sign_id_token(&enc, valid_id_token_claims(nonce));
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);
        let exchanger: Arc<dyn TokenExchanger + Send + Sync> =
            Arc::new(StubTokenExchanger { id_token });
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map,
        ));
        let app = test_router(exchanger, validator);

        // WRONG binding cookie — does not match the TEST_BINDING stored with the
        // state, so the callback must reject before exchanging or minting.
        let req = Request::builder()
            .uri(format!(
                "/api/auth/oidc/callback?code=test-code&state={}",
                state
            ))
            .header(
                axum::http::header::COOKIE,
                format!("__Host-oidc_login_csrf={OTHER_TEST_BINDING}"),
            )
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.expect("request");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a browser-binding mismatch must be rejected"
        );
        assert!(
            !resp.headers().contains_key("set-cookie"),
            "no session cookie may be set on a binding mismatch"
        );

        let retry = app
            .oneshot(callback_req(format!(
                "/api/auth/oidc/callback?code=test-code&state={state}"
            )))
            .await
            .expect("retry request");
        assert_eq!(
            retry.status(),
            StatusCode::BAD_REQUEST,
            "binding failure must consume the single-use state before retry"
        );
    }

    #[tokio::test]
    async fn test_callback_idp_error_redirects_to_auth_error() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let (_, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);

        let exchanger: Arc<dyn TokenExchanger + Send + Sync> = Arc::new(FailingTokenExchanger);
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map,
        ));

        let app = test_router(exchanger, validator);

        let req = Request::builder()
            .uri("/api/auth/oidc/callback?error=access_denied&error_description=User+denied+access")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.expect("request");
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(location, "/?auth_error=1");
        assert!(
            !resp.headers().contains_key("set-cookie"),
            "should NOT set a session cookie on IdP error"
        );
    }

    #[tokio::test]
    async fn test_callback_missing_code_returns_400() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let (_, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);

        let exchanger: Arc<dyn TokenExchanger + Send + Sync> = Arc::new(FailingTokenExchanger);
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map,
        ));

        let app = test_router(exchanger, validator);

        let req = Request::builder()
            .uri("/api/auth/oidc/callback?state=some-state")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.expect("request");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_missing_state_returns_400() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let (_, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);

        let exchanger: Arc<dyn TokenExchanger + Send + Sync> = Arc::new(FailingTokenExchanger);
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map,
        ));

        let app = test_router(exchanger, validator);

        let req = Request::builder()
            .uri("/api/auth/oidc/callback?code=some-code")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.expect("request");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_invalid_state_returns_400() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(_pool) = global_pool().await else {
            return;
        };

        let (_, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);

        let exchanger: Arc<dyn TokenExchanger + Send + Sync> = Arc::new(FailingTokenExchanger);
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map,
        ));

        let app = test_router(exchanger, validator);

        // Use a state value that was never inserted.
        let req = Request::builder()
            .uri("/api/auth/oidc/callback?code=some-code&state=nonexistent-state-xyz")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.expect("request");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 16_384)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "OIDC_INVALID_STATE");
    }

    #[tokio::test]
    async fn test_callback_state_single_use() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        provision_global_assignment(
            pool,
            "oidc",
            TEST_ISS,
            "sub-test-1",
            &["PlatformAdmin".to_string()],
        )
        .await;

        let (enc, dec) = make_keypair();
        let nonce = "test-nonce-su";
        let state = format!("st-su2-{}", Uuid::new_v4());

        insert_test_state(pool, &state, nonce)
            .await
            .expect("insert state");

        let id_token = sign_id_token(&enc, valid_id_token_claims(nonce));

        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec.clone());

        let exchanger: Arc<dyn TokenExchanger + Send + Sync> = Arc::new(StubTokenExchanger {
            id_token: id_token.clone(),
        });
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS,
            TEST_AUD,
            key_map.clone(),
        ));

        let app = test_router(exchanger, validator);

        // First request: succeeds.
        let req1 = callback_req(format!(
            "/api/auth/oidc/callback?code=code1&state={}",
            state
        ));
        let resp1 = app.oneshot(req1).await.expect("first request");
        assert_eq!(resp1.status(), StatusCode::FOUND);

        // Second request with the same state: must fail (state consumed).
        let exchanger2: Arc<dyn TokenExchanger + Send + Sync> =
            Arc::new(StubTokenExchanger { id_token });
        let mut key_map2 = HashMap::new();
        key_map2.insert(TEST_KID.to_string(), dec);
        let validator2 = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map2,
        ));
        let app2 = test_router(exchanger2, validator2);

        let req2 = Request::builder()
            .uri(format!(
                "/api/auth/oidc/callback?code=code2&state={}",
                state
            ))
            .body(Body::empty())
            .unwrap();
        let resp2 = app2.oneshot(req2).await.expect("second request");
        assert_eq!(
            resp2.status(),
            StatusCode::BAD_REQUEST,
            "second use of same state must be rejected"
        );
    }

    #[tokio::test]
    async fn test_callback_nonce_mismatch_returns_401() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let (enc, dec) = make_keypair();
        let stored_nonce = "stored-nonce-abc";
        let token_nonce = "DIFFERENT-nonce-xyz"; // mismatch
        let state = format!("st-nonce-{}", Uuid::new_v4());

        insert_test_state(pool, &state, stored_nonce)
            .await
            .expect("insert state");

        // Token carries a different nonce from what is stored.
        let id_token = sign_id_token(&enc, valid_id_token_claims(token_nonce));

        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);

        let exchanger: Arc<dyn TokenExchanger + Send + Sync> =
            Arc::new(StubTokenExchanger { id_token });
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map,
        ));

        let app = test_router(exchanger, validator);

        let req = callback_req(format!("/api/auth/oidc/callback?code=code&state={}", state));

        let resp = app.oneshot(req).await.expect("request");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "nonce mismatch must return 401"
        );
        let body = axum::body::to_bytes(resp.into_body(), 16_384)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "OIDC_TOKEN_INVALID");
    }

    #[tokio::test]
    async fn test_callback_token_exchange_failure_returns_502() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let (_, dec) = make_keypair();
        let nonce = "test-nonce-502";
        let state = format!("st-502-{}", Uuid::new_v4());

        insert_test_state(pool, &state, nonce)
            .await
            .expect("insert state");

        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);

        let exchanger: Arc<dyn TokenExchanger + Send + Sync> = Arc::new(FailingTokenExchanger);
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map,
        ));

        let app = test_router(exchanger, validator);

        let req = callback_req(format!("/api/auth/oidc/callback?code=code&state={}", state));

        let resp = app.oneshot(req).await.expect("request");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "token exchange failure should return 502"
        );
        let body = axum::body::to_bytes(resp.into_body(), 16_384)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "OIDC_TOKEN_EXCHANGE_FAILED");
    }

    #[tokio::test]
    async fn test_callback_wrong_algorithm_returns_401() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let nonce = Uuid::new_v4().to_string();
        let state = format!("st-alg-{}", Uuid::new_v4());

        insert_test_state(pool, &state, &nonce)
            .await
            .expect("insert state");

        // Sign with HS256 instead of RS256.
        let claims = valid_id_token_claims(&nonce);
        let hs_secret = Uuid::new_v4().to_string();
        let hs_key = EncodingKey::from_secret(hs_secret.as_bytes());
        let hs_token =
            jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &hs_key).unwrap();

        let (_, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);

        let exchanger: Arc<dyn TokenExchanger + Send + Sync> =
            Arc::new(StubTokenExchanger { id_token: hs_token });
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map,
        ));

        let app = test_router(exchanger, validator);

        let req = callback_req(format!("/api/auth/oidc/callback?code=code&state={}", state));

        let resp = app.oneshot(req).await.expect("request");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_callback_expired_id_token_returns_401() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

        let (enc, dec) = make_keypair();
        let nonce = "test-nonce-exp";
        let state = format!("st-exp2-{}", Uuid::new_v4());

        insert_test_state(pool, &state, nonce)
            .await
            .expect("insert state");

        let mut claims = valid_id_token_claims(nonce);
        claims["exp"] = json!(now() - 3600); // already expired
        let id_token = sign_id_token(&enc, claims);

        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);

        let exchanger: Arc<dyn TokenExchanger + Send + Sync> =
            Arc::new(StubTokenExchanger { id_token });
        let validator = Arc::new(OidcIdTokenValidator::with_static_keys(
            TEST_ISS, TEST_AUD, key_map,
        ));

        let app = test_router(exchanger, validator);

        let req = callback_req(format!("/api/auth/oidc/callback?code=code&state={}", state));

        let resp = app.oneshot(req).await.expect("request");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ─── Validator unit tests (no DB needed) ──────────────────────────────

    #[tokio::test]
    async fn test_validator_rejects_wrong_issuer() {
        let (enc, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);
        let validator = OidcIdTokenValidator::with_static_keys(TEST_ISS, TEST_AUD, key_map);

        let mut claims = valid_id_token_claims("nonce-1");
        claims["iss"] = json!("https://evil.example.com");
        let token = sign_id_token(&enc, claims);

        let result = validator
            .validate_id_token(&token, "nonce-1", "roles")
            .await;
        assert!(result.is_err(), "wrong issuer must be rejected");
    }

    #[tokio::test]
    async fn test_validator_rejects_wrong_audience() {
        let (enc, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);
        let validator = OidcIdTokenValidator::with_static_keys(TEST_ISS, TEST_AUD, key_map);

        let mut claims = valid_id_token_claims("nonce-2");
        claims["aud"] = json!("some-other-client");
        let token = sign_id_token(&enc, claims);

        let result = validator
            .validate_id_token(&token, "nonce-2", "roles")
            .await;
        assert!(result.is_err(), "wrong audience must be rejected");
    }

    #[tokio::test]
    async fn test_validator_identity_fields() {
        let (enc, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);
        let validator = OidcIdTokenValidator::with_static_keys(TEST_ISS, TEST_AUD, key_map);

        let nonce = "nonce-id";
        let token = sign_id_token(&enc, valid_id_token_claims(nonce));

        let claims = validator
            .validate_id_token(&token, nonce, "roles")
            .await
            .expect("should succeed");
        assert_eq!(claims.provider_subject, "sub-test-1");
        assert_eq!(claims.display_name, "Test User");
        assert_eq!(claims.email.as_deref(), Some("test@example.com"));
        assert_eq!(claims.roles, vec!["PlatformAdmin"]);
    }

    #[tokio::test]
    async fn test_generic_oidc_keeps_sub_semantics_without_entra_oid() {
        let (enc, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);
        let validator = OidcIdTokenValidator::with_static_keys(TEST_ISS, TEST_AUD, key_map);

        let nonce = "nonce-standard-sub";
        let mut claims = valid_id_token_claims(nonce);
        claims
            .as_object_mut()
            .expect("claims fixture is an object")
            .remove("oid");
        let token = sign_id_token(&enc, claims);

        let claims = validator
            .validate_id_token(&token, nonce, "roles")
            .await
            .expect("generic OIDC requires sub, not the Entra-only oid claim");
        assert_eq!(claims.provider_subject, "sub-test-1");
    }

    #[tokio::test]
    async fn test_validator_requires_nonblank_sub_even_when_oid_is_present() {
        let (enc, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);
        let validator = OidcIdTokenValidator::with_static_keys(TEST_ISS, TEST_AUD, key_map);

        for (label, subject) in [
            ("missing", None),
            ("empty", Some("")),
            ("blank", Some("   ")),
        ] {
            let nonce = format!("nonce-{label}");
            let mut claims = valid_id_token_claims(&nonce);
            match subject {
                Some(subject) => claims["sub"] = json!(subject),
                None => {
                    claims
                        .as_object_mut()
                        .expect("claims fixture is an object")
                        .remove("sub");
                }
            }
            let token = sign_id_token(&enc, claims);
            assert!(
                validator
                    .validate_id_token(&token, &nonce, "roles")
                    .await
                    .is_err(),
                "{label} sub must fail closed even when oid is present"
            );
        }
    }

    #[tokio::test]
    async fn test_entra_subject_mapping_requires_canonical_oid_without_sub_fallback() {
        let (enc, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);
        let validator = OidcIdTokenValidator::with_static_keys(TEST_ISS, TEST_AUD, key_map);

        let oid_nonce = Uuid::new_v4().to_string();
        let mut oid_token_claims = valid_id_token_claims(&oid_nonce);
        oid_token_claims["oid"] = json!(TEST_ENTRA_OID);
        let oid_token = sign_id_token(&enc, oid_token_claims);
        let oid_claims = validator
            .validate_entra_id_token(&oid_token, &oid_nonce, "roles")
            .await
            .expect("Entra token with oid is valid");
        assert_eq!(oid_claims.provider_subject, TEST_ENTRA_OID);

        let display_fallback_nonce = "nonce-entra-display-fallback";
        let mut display_fallback_claims = valid_id_token_claims(display_fallback_nonce);
        for claim in ["name", "preferred_username"] {
            display_fallback_claims
                .as_object_mut()
                .expect("claims fixture is an object")
                .remove(claim);
        }
        let display_fallback_token = sign_id_token(&enc, display_fallback_claims);
        let display_fallback = validator
            .validate_entra_id_token(&display_fallback_token, display_fallback_nonce, "roles")
            .await
            .expect("canonical Entra oid remains a valid display-name fallback");
        assert_eq!(display_fallback.display_name, TEST_ENTRA_OID);

        for (label, oid) in [
            ("missing", None),
            ("empty", Some("")),
            ("blank", Some("   ")),
            ("uppercase", Some("11111111-2222-4333-8444-55555555555A")),
            ("compact", Some("11111111222243338444555555555555")),
            ("provider-subject", Some("sub-test-1")),
        ] {
            let nonce = format!("nonce-entra-oid-{label}");
            let mut claims = valid_id_token_claims(&nonce);
            match oid {
                Some(oid) => claims["oid"] = json!(oid),
                None => {
                    claims
                        .as_object_mut()
                        .expect("claims fixture is an object")
                        .remove("oid");
                }
            }
            let token = sign_id_token(&enc, claims);
            let reason = validator
                .validate_entra_id_token(&token, &nonce, "roles")
                .await
                .err()
                .expect("noncanonical Entra oid must be rejected");
            assert_eq!(
                reason, "invalid-token",
                "{label} oid must fail closed rather than falling back to sub"
            );
        }
    }

    #[tokio::test]
    async fn test_validator_dynamic_roles_claim() {
        let (enc, dec) = make_keypair();
        let mut key_map = HashMap::new();
        key_map.insert(TEST_KID.to_string(), dec);
        let validator = OidcIdTokenValidator::with_static_keys(TEST_ISS, TEST_AUD, key_map);

        let nonce = "nonce-rc";
        let mut claims_json = valid_id_token_claims(nonce);
        claims_json["groups"] = json!(["Operator", "Viewer"]);
        let token = sign_id_token(&enc, claims_json);

        let claims = validator
            .validate_id_token(&token, nonce, "groups") // dynamic claim key
            .await
            .expect("should succeed");
        assert_eq!(claims.roles, vec!["Operator", "Viewer"]);
    }
}
