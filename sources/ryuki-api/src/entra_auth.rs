//! Entra ID (Azure AD) JWT bearer-token validation.
//!
//! This module owns the entire Entra token-validation path for the API. The
//! `ryuki-engine` crate is a pure, I/O-free domain crate and is intentionally
//! NOT touched: its `validate_token` stub stays as-is and the API stops calling
//! it. We reuse the engine's `AuthSession` / `unverified_entra()` / `EntraConfig`
//! types (not fork them) and construct verified sessions here from claims that
//! `jsonwebtoken` has cryptographically validated.
//!
//! Security model:
//! - RS256 is the ONLY accepted signature algorithm (alg-confusion defense).
//!   `Validation::new(Algorithm::RS256)` constrains `decode` to RS256, so
//!   `alg=none` and any `HS*` token is rejected outright. We additionally assert
//!   `header.alg == RS256` defensively before key lookup.
//! - Signature, issuer, audience, exp and nbf are verified atomically by
//!   `jsonwebtoken::decode`.
//! - Every failure path is FAIL-CLOSED: it returns `AuthSession::unverified_entra()`
//!   (token_valid=false, zero roles, provider_mode="entra-id-unverified"), which
//!   the downstream RBAC / verified-admin gates already reject.
//! - Only an error-variant string is ever logged, NEVER the token, claims, oid,
//!   or header bytes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use ryuki_engine::auth::{get_entra_config_from_env, AuthSession, EntraConfig};
use serde::Deserialize;
use tokio::sync::RwLock;

/// Cooldown between JWKS refresh attempts. Prevents a stream of bad-`kid`
/// tokens from hammering Entra's discovery endpoint.
const REFRESH_COOLDOWN: Duration = Duration::from_secs(300);

/// Claims we extract from a validated Entra token. All identity fields except
/// `sub` are optional; `roles` defaults to empty (a valid identity with zero
/// app permissions). `jsonwebtoken` validates iss/aud/exp/nbf separately via
/// `Validation`, so they are not modeled here.
#[derive(Debug, Deserialize)]
struct EntraClaims {
    sub: String,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
}

/// The injectable key-resolution seam.
///
/// `Network` is the production path: signing keys are fetched from Entra's JWKS
/// endpoint over reqwest and cached. `Static` is the test path: callers feed a
/// pre-built `kid -> DecodingKey` map (e.g. from a locally generated RSA
/// keypair) so tests verify the full pipeline with zero network. The enum keeps
/// the validator `Send + Sync` with no trait objects.
enum KeySource {
    Network(JwksCache),
    Static(HashMap<String, DecodingKey>),
}

/// Mutable JWKS state guarded by the cache's `RwLock`.
struct JwksState {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
    last_refresh_attempt: Option<Instant>,
}

/// Network JWKS cache. The `reqwest::Client` is created once and cloned
/// cheaply; the keyset lives behind an `RwLock` so the validator handle itself
/// stays immutable shared state (no global mutable state).
struct JwksCache {
    http: reqwest::Client,
    jwks_uri: String,
    ttl: Duration,
    inner: RwLock<JwksState>,
}

/// A single RSA JWK from the discovery document. We only consume RS256 signing
/// keys (`kty=RSA`, `use=sig`), keyed by `kid`, using the base64url `n`/`e`
/// components. `use` is a Rust keyword, so the field is renamed.
#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
    #[serde(default)]
    kty: Option<String>,
    #[serde(default, rename = "use")]
    use_: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
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

    /// Resolves the `DecodingKey` for `kid`, refreshing the keyset on an unknown
    /// `kid` (signing-key rotation) or an expired TTL, subject to a refresh
    /// cooldown. On fetch failure the stale keyset is kept; fail-closed happens
    /// at validate time if the `kid` still cannot be found.
    async fn decoding_key_for_kid(&self, kid: &str) -> Option<DecodingKey> {
        // Fast path: shared read lock. Hit only when the kid is present AND the
        // keyset is still within its TTL.
        {
            let state = self.inner.read().await;
            if let Some(key) = state.keys.get(kid) {
                if Self::fresh(&state, self.ttl) {
                    return Some(key.clone());
                }
            }
        }

        // Slow path: exclusive write lock + double-checked locking.
        let mut state = self.inner.write().await;
        if let Some(key) = state.keys.get(kid) {
            if Self::fresh(&state, self.ttl) {
                return Some(key.clone());
            }
        }

        // Only attempt a network refresh if we have not attempted recently.
        let now = Instant::now();
        let cooled_down = state
            .last_refresh_attempt
            .map(|t| now.duration_since(t) >= REFRESH_COOLDOWN)
            .unwrap_or(true);

        if cooled_down {
            // Stamp BEFORE the await so concurrent writers see the attempt and
            // the cooldown is honored even if the fetch is slow.
            state.last_refresh_attempt = Some(now);
            match self.fetch_keys().await {
                Ok(keys) => {
                    state.keys = keys;
                    state.fetched_at = Some(Instant::now());
                }
                Err(_) => {
                    // Keep the stale map. Fail-closed at validate time.
                }
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
        let doc: JwksDocument = resp.json().await.map_err(|_| ())?;
        let mut keys = HashMap::new();
        for jwk in doc.keys {
            if let Some(kty) = &jwk.kty {
                if kty != "RSA" {
                    continue;
                }
            }
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

/// Maps a `jsonwebtoken` error variant to a stable, low-cardinality reason
/// string for SAFE logging. Never includes token bytes, claims, or header data.
fn failure_reason(err: &jsonwebtoken::errors::Error) -> &'static str {
    use jsonwebtoken::errors::ErrorKind;
    match err.kind() {
        ErrorKind::ExpiredSignature => "expired",
        ErrorKind::ImmatureSignature => "not-yet-valid",
        ErrorKind::InvalidSignature => "bad-signature",
        ErrorKind::InvalidIssuer => "wrong-issuer",
        ErrorKind::InvalidAudience => "wrong-audience",
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => "wrong-algorithm",
        _ => "invalid-token",
    }
}

/// Outcome of a validation attempt. The session is what callers consume; the
/// reason is for safe logging only and is `None` on success.
pub struct ValidationOutcome {
    pub session: AuthSession,
    pub failure_reason: Option<&'static str>,
}

impl ValidationOutcome {
    fn unverified(reason: &'static str) -> Self {
        Self {
            session: AuthSession::unverified_entra(),
            failure_reason: Some(reason),
        }
    }
}

/// Validates Entra ID bearer tokens. Built ONCE at startup from
/// `config_store::get_app_config()` and shared as an `Arc` extension/state.
/// `issuer` and `audiences` are precomputed at construction; only the JWKS
/// keyset (behind its own lock) mutates at runtime.
pub struct EntraTokenValidator {
    config: EntraConfig,
    issuer: String,
    audiences: Vec<String>,
    keys: KeySource,
    leeway_secs: u64,
}

impl EntraTokenValidator {
    /// Production constructor: derives `EntraConfig` from the app config values
    /// (so `enabled` is computed consistently with every other Entra consumer)
    /// and wires up a network-backed JWKS cache.
    pub fn from_app_config(
        tenant_id: &str,
        client_id: &str,
        instance: &str,
        jwks_ttl_secs: u64,
        leeway_secs: u64,
    ) -> Self {
        let config = get_entra_config_from_env(tenant_id, client_id, instance);
        let (issuer, audiences) = Self::derive_issuer_and_audiences(&config);
        let instance_trimmed = config.instance.trim_end_matches('/');
        let jwks_uri = format!(
            "{}/{}/discovery/v2.0/keys",
            instance_trimmed, config.tenant_id
        );
        let http = reqwest::Client::new();
        let cache = JwksCache::new(http, jwks_uri, Duration::from_secs(jwks_ttl_secs));
        Self {
            config,
            issuer,
            audiences,
            keys: KeySource::Network(cache),
            leeway_secs,
        }
    }

    /// Test/injection constructor: a pre-built `kid -> DecodingKey` keyset with
    /// no network. `config` is supplied directly so tests can pin a known
    /// tenant/client/authority.
    #[allow(dead_code)]
    pub fn with_static_keys(config: EntraConfig, keys: HashMap<String, DecodingKey>) -> Self {
        let (issuer, audiences) = Self::derive_issuer_and_audiences(&config);
        Self {
            config,
            issuer,
            audiences,
            keys: KeySource::Static(keys),
            leeway_secs: 60,
        }
    }

    /// Issuer = `{authority}/{tenant}/v2.0`; audiences accept both the bare
    /// client id and the `api://{client_id}` form Entra issues for app APIs.
    fn derive_issuer_and_audiences(config: &EntraConfig) -> (String, Vec<String>) {
        let authority = config.instance.trim_end_matches('/');
        let issuer = format!("{}/{}/v2.0", authority, config.tenant_id);
        let audiences = vec![
            config.client_id.clone(),
            format!("api://{}", config.client_id),
        ];
        (issuer, audiences)
    }

    async fn resolve_key(&self, kid: &str) -> Option<DecodingKey> {
        match &self.keys {
            KeySource::Static(map) => map.get(kid).cloned(),
            KeySource::Network(cache) => cache.decoding_key_for_kid(kid).await,
        }
    }

    /// Validates a raw `Authorization` header value, returning an `AuthSession`.
    /// Convenience wrapper over [`Self::validate_with_reason`] for callers that
    /// do not need the (safe) failure-reason string.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn validate(&self, raw_authorization_header: &str) -> AuthSession {
        self.validate_with_reason(raw_authorization_header)
            .await
            .session
    }

    /// Validates a raw `Authorization` header value, returning the session plus
    /// a safe failure-reason string (for logging) on any failure path.
    pub async fn validate_with_reason(&self, raw_authorization_header: &str) -> ValidationOutcome {
        // Short-circuit when Entra is not configured/enabled.
        if !self.config.enabled {
            return ValidationOutcome::unverified("disabled");
        }

        // Strip the `Bearer ` prefix (same semantics as the API's bearer_value
        // helper). Empty/missing -> unverified.
        let token = match raw_authorization_header
            .trim()
            .strip_prefix("Bearer ")
            .map(str::trim)
        {
            Some(t) if !t.is_empty() => t,
            _ => return ValidationOutcome::unverified("missing-bearer"),
        };

        // Step 1: decode JOSE header only to read alg + kid. kid is mandatory.
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(e) => return ValidationOutcome::unverified(failure_reason(&e)),
        };
        let kid = match header.kid {
            Some(k) => k,
            None => return ValidationOutcome::unverified("missing-kid"),
        };

        // Step 2: algorithm pinning. Defensive check before key lookup; decode
        // is additionally constrained to RS256 below.
        if header.alg != Algorithm::RS256 {
            return ValidationOutcome::unverified("wrong-algorithm");
        }

        // Step 3: resolve the decoding key for this kid (refresh-on-unknown-kid
        // in the network path). Missing after refresh -> fail closed.
        let decoding_key = match self.resolve_key(&kid).await {
            Some(k) => k,
            None => return ValidationOutcome::unverified("unknown-kid"),
        };

        // Step 4: configure validation. RS256 only; issuer/audience pinned;
        // exp (default on) and nbf enforced with a small leeway.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(std::slice::from_ref(&self.issuer));
        validation.set_audience(&self.audiences);
        validation.leeway = self.leeway_secs;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // Demand the pinned claims are PRESENT, not merely correct-when-present.
        // jsonwebtoken's default `required_spec_claims` is only {"exp"}, so a
        // token that simply OMITS iss/aud/nbf would otherwise slip past the
        // issuer/audience pins. Entra ID always issues all four. This call
        // REPLACES the default set, so "exp" must be listed too.
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud"]);

        // Step 5: verify signature + iss/aud/exp/nbf atomically.
        let data = match decode::<EntraClaims>(token, &decoding_key, &validation) {
            Ok(d) => d,
            Err(e) => return ValidationOutcome::unverified(failure_reason(&e)),
        };

        // Step 6: map claims into a verified session.
        let claims = data.claims;
        let user_id = claims.oid.clone().unwrap_or_else(|| claims.sub.clone());
        let display_name = claims
            .name
            .clone()
            .or_else(|| claims.preferred_username.clone())
            .unwrap_or_else(|| user_id.clone());

        ValidationOutcome {
            session: AuthSession {
                user_id,
                display_name,
                roles: claims.roles,
                token_valid: true,
                provider_mode: "entra-id".to_string(),
            },
            failure_reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;

    const TEST_TENANT: &str = "contoso-tenant-0000";
    const TEST_CLIENT: &str = "ryuki-app-client-0000";
    const TEST_AUTHORITY: &str = "https://login.microsoftonline.com";
    const TEST_KID: &str = "test-kid-1";

    fn test_config(enabled: bool) -> EntraConfig {
        EntraConfig {
            tenant_id: TEST_TENANT.to_string(),
            client_id: TEST_CLIENT.to_string(),
            instance: TEST_AUTHORITY.to_string(),
            enabled,
        }
    }

    fn expected_issuer() -> String {
        format!("{}/{}/v2.0", TEST_AUTHORITY, TEST_TENANT)
    }

    /// Generates a throwaway RSA-2048 keypair and derives both the signing
    /// `EncodingKey` (PKCS#8 DER) and a verifying `DecodingKey` (RSA n/e
    /// components). No PEM is ever produced, so the secret scan stays clean.
    fn make_keypair() -> (EncodingKey, DecodingKey, RsaPublicKey) {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        let public = RsaPublicKey::from(&private);

        // jsonwebtoken's `from_rsa_der` feeds bytes to ring's
        // `RsaKeyPair::from_der`, which expects PKCS#1 (RSAPrivateKey) DER.
        let der = private.to_pkcs1_der().expect("pkcs1 der");
        let encoding = EncodingKey::from_rsa_der(der.as_bytes());

        let n = b64url(public.n().to_bytes_be());
        let e = b64url(public.e().to_bytes_be());
        let decoding = DecodingKey::from_rsa_components(&n, &e).expect("decoding key");

        (encoding, decoding, public)
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

    /// Builds a validator with a single static key under TEST_KID.
    fn static_validator(decoding: DecodingKey, enabled: bool) -> EntraTokenValidator {
        let mut map = HashMap::new();
        map.insert(TEST_KID.to_string(), decoding);
        EntraTokenValidator::with_static_keys(test_config(enabled), map)
    }

    /// Signs a claims object with RS256 under TEST_KID using `encoding`.
    fn sign(encoding: &EncodingKey, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        jsonwebtoken::encode(&header, &claims, encoding).expect("sign")
    }

    fn auth(token: &str) -> String {
        format!("Bearer {token}")
    }

    fn valid_claims() -> serde_json::Value {
        json!({
            "iss": expected_issuer(),
            "aud": TEST_CLIENT,
            "sub": "subject-1",
            "oid": "object-id-1",
            "name": "Ada Admin",
            "preferred_username": "ada@contoso.example",
            "exp": now() + 3600,
            "nbf": now() - 60,
            "roles": ["PlatformAdmin"],
        })
    }

    #[tokio::test]
    async fn test_valid_token_yields_verified_session() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let token = sign(&enc, valid_claims());

        let session = validator.validate(&auth(&token)).await;
        assert!(session.token_valid);
        assert_eq!(session.provider_mode, "entra-id");
        assert_eq!(session.roles, vec!["PlatformAdmin"]);
        // oid preferred over sub.
        assert_eq!(session.user_id, "object-id-1");
        // name preferred for display.
        assert_eq!(session.display_name, "Ada Admin");
    }

    #[tokio::test]
    async fn test_valid_token_alt_audience_accepted() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims["aud"] = json!(format!("api://{}", TEST_CLIENT));
        let token = sign(&enc, claims);

        let session = validator.validate(&auth(&token)).await;
        assert!(session.token_valid);
        assert_eq!(session.provider_mode, "entra-id");
    }

    #[tokio::test]
    async fn test_expired_token_rejected() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims["exp"] = json!(now() - 3600);
        let token = sign(&enc, claims);

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.session.provider_mode, "entra-id-unverified");
        assert!(outcome.session.roles.is_empty());
        assert_eq!(outcome.failure_reason, Some("expired"));
    }

    #[tokio::test]
    async fn test_not_yet_valid_token_rejected() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims["nbf"] = json!(now() + 3600);
        let token = sign(&enc, claims);

        let session = validator.validate(&auth(&token)).await;
        assert!(!session.token_valid);
        assert_eq!(session.provider_mode, "entra-id-unverified");
    }

    #[tokio::test]
    async fn test_wrong_audience_rejected() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims["aud"] = json!("some-other-client");
        let token = sign(&enc, claims);

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("wrong-audience"));
    }

    #[tokio::test]
    async fn test_wrong_issuer_rejected() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims["iss"] = json!(format!("{}/{}/v2.0", TEST_AUTHORITY, "different-tenant"));
        let token = sign(&enc, claims);

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("wrong-issuer"));
    }

    // A token that simply OMITS a pinned claim must be rejected just like one
    // that carries a wrong value — otherwise the issuer/audience pins are
    // bypassable by dropping the claim. jsonwebtoken's default
    // `required_spec_claims` is only {"exp"}, so iss/aud/nbf presence must be
    // demanded explicitly (see `set_required_spec_claims` in the validator).
    #[tokio::test]
    async fn test_missing_audience_rejected() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("aud");
        let token = sign(&enc, claims);

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(
            !outcome.session.token_valid,
            "a token with no aud claim must not pass the audience pin"
        );
    }

    #[tokio::test]
    async fn test_missing_issuer_rejected() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("iss");
        let token = sign(&enc, claims);

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(
            !outcome.session.token_valid,
            "a token with no iss claim must not pass the issuer pin"
        );
    }

    #[tokio::test]
    async fn test_missing_nbf_rejected() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("nbf");
        let token = sign(&enc, claims);

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(
            !outcome.session.token_valid,
            "a token with no nbf claim must not pass when nbf is required"
        );
    }

    #[tokio::test]
    async fn test_bad_signature_rejected() {
        // Keyset holds the FIRST public key under TEST_KID, but the token is
        // signed with a SECOND, unrelated private key.
        let (_enc1, dec1, _) = make_keypair();
        let (enc2, _dec2, _) = make_keypair();
        let validator = static_validator(dec1, true);
        let token = sign(&enc2, valid_claims());

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("bad-signature"));
    }

    #[tokio::test]
    async fn test_alg_none_rejected() {
        let (_enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        // Hand-assemble an unsigned token with alg=none.
        let header = b64url(br#"{"alg":"none","kid":"test-kid-1"}"#.to_vec());
        let payload = b64url(serde_json::to_vec(&valid_claims()).unwrap());
        let token = format!("{header}.{payload}.");

        let session = validator.validate(&auth(&token)).await;
        assert!(!session.token_valid);
        assert_eq!(session.provider_mode, "entra-id-unverified");
    }

    #[tokio::test]
    async fn test_alg_confusion_hs256_rejected() {
        // Sign an HS256 token using the RSA public key bytes as the HMAC secret.
        let (_enc, dec, public) = make_keypair();
        let validator = static_validator(dec, true);

        let public_der = public.to_pkcs1_der().expect("pkcs1 der");
        let hmac_key = EncodingKey::from_secret(public_der.as_bytes());
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(TEST_KID.to_string());
        let claims = valid_claims();
        let token = jsonwebtoken::encode(&header, &claims, &hmac_key).expect("hs256 sign");

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.session.provider_mode, "entra-id-unverified");
        // Rejected at the defensive alg check before key lookup.
        assert_eq!(outcome.failure_reason, Some("wrong-algorithm"));
    }

    #[tokio::test]
    async fn test_unknown_kid_rejected() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        // Sign under a kid the static keyset does not hold.
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("missing-kid".to_string());
        let token = jsonwebtoken::encode(&h, &valid_claims(), &enc).expect("sign");

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("unknown-kid"));
    }

    #[tokio::test]
    async fn test_disabled_config_always_unverified() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, false);
        let token = sign(&enc, valid_claims());

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.session.provider_mode, "entra-id-unverified");
        assert_eq!(outcome.failure_reason, Some("disabled"));
    }

    #[tokio::test]
    async fn test_valid_token_without_roles_has_empty_roles() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("roles");
        let token = sign(&enc, claims);

        let session = validator.validate(&auth(&token)).await;
        assert!(session.token_valid);
        assert_eq!(session.provider_mode, "entra-id");
        assert!(session.roles.is_empty());
    }

    #[tokio::test]
    async fn test_user_id_falls_back_to_sub_when_oid_absent() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("oid");
        let token = sign(&enc, claims);

        let session = validator.validate(&auth(&token)).await;
        assert!(session.token_valid);
        assert_eq!(session.user_id, "subject-1");
    }

    #[tokio::test]
    async fn test_display_name_falls_back_to_preferred_username_then_user_id() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);

        // name absent -> preferred_username.
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("name");
        let token = sign(&enc, claims);
        let session = validator.validate(&auth(&token)).await;
        assert_eq!(session.display_name, "ada@contoso.example");

        // name + preferred_username absent -> user_id (oid here).
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("name");
        claims.as_object_mut().unwrap().remove("preferred_username");
        let token = sign(&enc, claims);
        let session = validator.validate(&auth(&token)).await;
        assert_eq!(session.display_name, "object-id-1");
    }

    #[tokio::test]
    async fn test_missing_bearer_prefix_unverified() {
        let (_enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let outcome = validator.validate_with_reason("not-a-bearer-header").await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("missing-bearer"));
    }

    #[tokio::test]
    async fn test_empty_bearer_unverified() {
        let (_enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let outcome = validator.validate_with_reason("Bearer ").await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("missing-bearer"));
    }

    #[tokio::test]
    async fn test_issuer_and_audiences_precomputed() {
        let (_enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        assert_eq!(validator.issuer, expected_issuer());
        assert_eq!(
            validator.audiences,
            vec![TEST_CLIENT.to_string(), format!("api://{}", TEST_CLIENT)]
        );
    }
}
