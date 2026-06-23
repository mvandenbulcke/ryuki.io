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
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;
use uuid::Uuid;

// ─── Token exchange ───────────────────────────────────────────────────────────

/// Parameters for the authorization-code → token exchange.
pub struct TokenRequest {
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    /// NEVER log.
    pub client_secret: String,
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
    token_endpoint: String,
}

impl ReqwestTokenExchanger {
    pub fn new(token_endpoint: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client build should not fail with valid config");
        Self {
            client,
            token_endpoint: token_endpoint.into(),
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
            // in a URL or log line).
            let form = [
                ("grant_type", "authorization_code"),
                ("code", &req.code),
                ("redirect_uri", &req.redirect_uri),
                ("client_id", &req.client_id),
                ("client_secret", &req.client_secret),
                ("code_verifier", &req.pkce_verifier),
            ];

            let resp = self
                .client
                .post(&self.token_endpoint)
                .form(&form)
                .send()
                .await
                .map_err(|_| OidcError::Transport)?;

            if !resp.status().is_success() {
                return Err(OidcError::IdpError);
            }

            let raw: RawTokenResponse = resp.json().await.map_err(|_| OidcError::Deserialize)?;
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
    fetched_at: Option<Instant>,
    last_refresh_attempt: Option<Instant>,
}

const REFRESH_COOLDOWN: Duration = Duration::from_secs(300);

struct JwksCache {
    http: reqwest::Client,
    jwks_uri: String,
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
    fn new(http: reqwest::Client, jwks_uri: String, ttl: Duration) -> Self {
        Self {
            http,
            jwks_uri,
            ttl,
            inner: RwLock::new(JwksState {
                keys: HashMap::new(),
                fetched_at: None,
                last_refresh_attempt: None,
            }),
        }
    }

    async fn decoding_key_for_kid(&self, kid: &str) -> Option<DecodingKey> {
        // Fast path.
        {
            let state = self.inner.read().await;
            if let Some(key) = state.keys.get(kid) {
                if Self::fresh(&state, self.ttl) {
                    return Some(key.clone());
                }
            }
        }

        // Slow path: double-checked locking.
        let mut state = self.inner.write().await;
        if let Some(key) = state.keys.get(kid) {
            if Self::fresh(&state, self.ttl) {
                return Some(key.clone());
            }
        }

        let now = Instant::now();
        let cooled_down = state
            .last_refresh_attempt
            .map(|t| now.duration_since(t) >= REFRESH_COOLDOWN)
            .unwrap_or(true);

        if cooled_down {
            state.last_refresh_attempt = Some(now);
            if let Ok(keys) = self.fetch_keys().await {
                state.keys = keys;
                state.fetched_at = Some(Instant::now());
            }
        }

        state.keys.get(kid).cloned()
    }

    fn fresh(state: &JwksState, ttl: Duration) -> bool {
        state.fetched_at.map(|t| t.elapsed() < ttl).unwrap_or(false)
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, DecodingKey>, ()> {
        let resp = self.http.get(&self.jwks_uri).send().await.map_err(|_| ())?;
        if !resp.status().is_success() {
            return Err(());
        }
        let doc: OidcJwksDocument = resp.json().await.map_err(|_| ())?;
        let mut keys = HashMap::new();
        for jwk in doc.keys {
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
        Ok(keys)
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
    /// `oid` if present, otherwise `sub`.
    pub user_id: String,
    /// `name` → `preferred_username` → `user_id` fallback chain.
    pub display_name: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
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
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client build should not fail");
        let cache = JwksCache::new(
            http,
            jwks_uri.into(),
            Duration::from_secs(3600), // 1-hour TTL; typical for OIDC JWKS
        );
        Self {
            issuer: issuer.into(),
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
        Self {
            issuer: issuer.into(),
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
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud"]);
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
        let user_id = claims
            .get("oid")
            .and_then(|v| v.as_str())
            .or_else(|| claims.get("sub").and_then(|v| v.as_str()))
            .ok_or("missing-sub")?
            .to_string();

        let display_name = claims
            .get("name")
            .and_then(|v| v.as_str())
            .or_else(|| claims.get("preferred_username").and_then(|v| v.as_str()))
            .unwrap_or(&user_id)
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
            user_id,
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
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    #[allow(dead_code)]
    pub error_description: Option<String>,
}

/// Extract a single cookie value by exact name from the request `Cookie` header.
/// Returns `None` if the header is absent/non-UTF-8 or the named cookie is not
/// present. Matches `{name}=` exactly (a longer cookie name is not a match).
fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        pair.trim()
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
            .map(|val| val.to_string())
    })
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
    use axum::http::header::SET_COOKIE;

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
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "OIDC_INVALID_STATE",
                        "message": "Login state is missing, expired, or already used"
                    })),
                ));
            }
        };

    // Step 5b: login-CSRF / session-swapping defense. The state is redeemable
    // only by the SAME browser that initiated the login: that browser holds the
    // `oidc_login_csrf` cookie whose value equals the binding stored with the
    // state. A `state` obtained from an attacker's own flow carries a different
    // binding, so a victim's browser (with a different/absent cookie) cannot
    // redeem it. Constant-time compare not needed: both are single-use,
    // server-generated 256-bit values.
    let cookie_binding = cookie_value(&headers, "oidc_login_csrf").unwrap_or_default();
    if binding.is_empty() || cookie_binding.is_empty() || cookie_binding != binding {
        tracing::warn!("oidc callback: login-state browser binding mismatch");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "OIDC_INVALID_STATE",
                "message": "Login state is missing, expired, or already used"
            })),
        ));
    }

    // Step 6: token exchange.
    // NEVER log code, pkce_verifier, client_secret, or the resulting id_token.
    let token_resp = deps
        .exchanger
        .exchange(&TokenRequest {
            code: code_val,
            redirect_uri: cfg.oidc.redirect_uri.clone(),
            client_id: cfg.oidc.client_id.clone(),
            client_secret: cfg.oidc.client_secret.clone(), // secret-scan-allow: passing config ref, not a hardcoded secret
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

    // Step 8: mint a persisted session.
    // Session-fixation defense: id is always server-generated.
    let session_id = Uuid::new_v4();
    crate::contracts::map_auth_session_persistence_result(
        sqlx::query(
            "INSERT INTO sessions (id, user_id, display_name, email, roles, provider) \
             VALUES ($1, $2, $3, $4, $5, 'oidc')",
        )
        .bind(session_id)
        .bind(&claims.user_id)
        .bind(&claims.display_name)
        .bind(&claims.email)
        .bind(&claims.roles as &[String])
        .execute(pool)
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

    // Do NOT log the session id — it is the bearer credential (the cookie value).
    // A non-secret event line is enough for audit/observability.
    tracing::info!("oidc login session created");

    // Step 9: set the session cookie and redirect to the portal root.
    // Cookie attributes (HttpOnly, Secure conditional, SameSite) come from
    // `session_cookie_set_header`.  The redirect target is hardcoded — no
    // open-redirect risk.
    let cookie = crate::contracts::session_cookie_set_header(&session_id.to_string(), &cfg.session);
    let cookie_hv = axum::http::HeaderValue::from_str(&cookie).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "cookie header encoding failed"})),
        )
    })?;
    let location = axum::http::HeaderValue::from_static("/");

    Ok((
        StatusCode::FOUND,
        [(SET_COOKIE, cookie_hv), (LOCATION, location)],
    )
        .into_response())
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
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use jsonwebtoken::{EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;
    use sqlx::PgPool;
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
    const TEST_BINDING: &str = "test-csrf-binding-value";

    /// Build a callback GET request carrying the matching `oidc_login_csrf`
    /// cookie (the per-browser binding the login handler sets). Tests that should
    /// proceed PAST the browser-binding check use this.
    fn callback_req(uri: String) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header(
                axum::http::header::COOKIE,
                format!("oidc_login_csrf={TEST_BINDING}"),
            )
            .body(Body::empty())
            .unwrap()
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

    /// Generates an RSA-2048 keypair.  Returns (EncodingKey, DecodingKey).
    fn make_keypair() -> (EncodingKey, DecodingKey) {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let public = RsaPublicKey::from(&private);
        let der = private.to_pkcs1_der().expect("pkcs1 der");
        let encoding = EncodingKey::from_rsa_der(der.as_bytes());
        let n = b64url(public.n().to_bytes_be());
        let e = b64url(public.e().to_bytes_be());
        let decoding = DecodingKey::from_rsa_components(&n, &e).expect("decoding key");
        (encoding, decoding)
    }

    /// Signs a JSON claims object as RS256 under TEST_KID.
    fn sign_id_token(encoding: &EncodingKey, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        jsonwebtoken::encode(&header, &claims, encoding).expect("sign id_token")
    }

    /// Returns a valid id_token claims set with the given nonce.
    fn valid_id_token_claims(nonce: &str) -> serde_json::Value {
        json!({
            "iss": TEST_ISS,
            "aud": TEST_AUD,
            "sub": "sub-test-1",
            "oid": "oid-test-1",
            "name": "Test User",
            "preferred_username": "test@example.com",
            "email": "test@example.com",
            "nonce": nonce,
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

    // ─── Config bootstrap (runs at most once per process) ─────────────────

    static CONFIG_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();

    fn ensure_config() {
        CONFIG_INIT.get_or_init(|| {
            let mut cfg = ryuki_core::config::RyukiConfig::default();
            cfg.oidc.enabled = true;
            cfg.oidc.issuer = TEST_ISS.to_string();
            cfg.oidc.client_id = TEST_AUD.to_string();
            cfg.oidc.client_secret = "test-secret".to_string();
            cfg.oidc.redirect_uri = "http://localhost:8080/api/auth/oidc/callback".to_string();
            cfg.oidc.roles_claim = "roles".to_string();
            // init_with_config panics if called twice; we guard it with the
            // OnceLock.  If another test already called it, we lose the set
            // (the OnceLock guards ensure we only try once from this module).
            let _ = std::panic::catch_unwind(|| {
                crate::config_store::init_with_config("oidc-callback-test-config.json", &cfg);
            });
        });
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
        nonce: &str,
    ) -> Result<(), sqlx::Error> {
        crate::repos::oidc_login_states::insert(
            pool,
            state,
            nonce,
            "test-pkce-verifier",
            TEST_BINDING,
        )
        .await
    }

    // ─── Tests ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_callback_happy_path_mints_session_and_redirects() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            return;
        };

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

        let resp = app.oneshot(req).await.expect("request");
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
        assert!(
            resp.headers().contains_key("set-cookie"),
            "should set the session cookie"
        );
        let cookie = resp.headers()["set-cookie"].to_str().unwrap();
        assert!(
            cookie.contains("ryuki_session="),
            "cookie must carry ryuki_session"
        );
        assert!(cookie.contains("HttpOnly"), "cookie must be HttpOnly");
    }

    /// Login-CSRF / session-swapping defense: a VALID, unused state plus a fully
    /// valid id_token are STILL rejected when the browser does not present the
    /// matching `oidc_login_csrf` cookie. This blocks the attack where a victim's
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
                "oidc_login_csrf=attacker-different-binding",
            )
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.expect("request");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a browser-binding mismatch must be rejected"
        );
        assert!(
            !resp.headers().contains_key("set-cookie"),
            "no session cookie may be set on a binding mismatch"
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

        let nonce = "test-nonce-alg";
        let state = format!("st-alg-{}", Uuid::new_v4());

        insert_test_state(pool, &state, nonce)
            .await
            .expect("insert state");

        // Sign with HS256 instead of RS256.
        let claims = valid_id_token_claims(nonce);
        let hs_key = EncodingKey::from_secret(b"test-secret");
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
        assert_eq!(claims.user_id, "oid-test-1");
        assert_eq!(claims.display_name, "Test User");
        assert_eq!(claims.email.as_deref(), Some("test@example.com"));
        assert_eq!(claims.roles, vec!["PlatformAdmin"]);
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
