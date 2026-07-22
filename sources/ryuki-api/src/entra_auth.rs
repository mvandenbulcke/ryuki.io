//! Entra ID (Azure AD) JWT bearer-token validation.
//!
//! This module owns the entire Entra token-validation path for the API. The
//! `ryuki-engine` crate is a pure, I/O-free domain crate; we reuse its
//! `AuthSession` / `unverified_entra()` / `EntraConfig` types (not fork them) and
//! construct verified sessions here from claims that `jsonwebtoken` has
//! cryptographically validated. (The engine's dead `validate_token` stub — which
//! the API never called — has been removed.)
//!
//! Security model:
//! - RS256 is the ONLY accepted signature algorithm (alg-confusion defense).
//!   `Validation::new(Algorithm::RS256)` constrains `decode` to RS256, so
//!   `alg=none` and any `HS*` token is rejected outright. We additionally assert
//!   `header.alg == RS256` defensively before key lookup.
//! - Signature, issuer, audience, exp and nbf are verified atomically by
//!   `jsonwebtoken::decode`.
//! - The exact registered bearer limits retained by the validator supply JWT
//!   clock skew and bound `exp - iat`; non-positive lifetimes and issued-at
//!   timestamps beyond `now + skew` fail closed with checked arithmetic.
//! - Every failure path is FAIL-CLOSED: it returns `AuthSession::unverified_entra()`
//!   (token_valid=false, zero roles, provider_mode="entra-id-unverified"), which
//!   the downstream RBAC / verified-admin gates already reject.
//! - Only an error-variant string is ever logged, NEVER the token, claims, oid,
//!   or header bytes.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use ryuki_engine::auth::{get_entra_config_from_env, ActorClass, AuthSession, EntraConfig};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Cooldown between JWKS refresh attempts. Prevents a stream of bad-`kid`
/// tokens from hammering Entra's discovery endpoint.
const REFRESH_COOLDOWN: Duration = Duration::from_secs(300);

/// Upper bound on cached JWKS signing keys. A real IdP publishes a small handful
/// (current + rotating); this caps the retained key set.
const MAX_JWKS_KEYS: usize = 32;

/// Upper bound on the actual streamed JWKS response body. A declared length is
/// only an early rejection hint; the cumulative bytes remain authoritative.
const MAX_JWKS_BYTES: usize = 1 << 20;

const AUTHENTICATOR_LEAF_DIGEST_CONTRACT: &[u8] = b"ryuki-authenticator-runtime-leaf-binding-v1";
const ENTRA_ISSUER_AUTHORITY_BINDING_DOMAIN: &[u8] = b"entra-issuer-authority-binding";
const ENTRA_AUDIENCE_CLIENT_BINDING_DOMAIN: &[u8] = b"entra-audience-client-binding";
const ENTRA_JWKS_KEY_SOURCE_BINDING_DOMAIN: &[u8] = b"entra-jwks-key-source-binding";
const ENTRA_REQUIRED_CLAIM_IDS: [&str; 6] = ["aud", "exp", "iat", "iss", "nbf", "sub"];

/// Claims we extract from a validated Entra token. `sub` remains a required
/// signed OIDC claim, while `oid` is the canonical Entra account key selected
/// after signature validation. `roles` defaults to empty (a valid identity with
/// zero app permissions). `jsonwebtoken` validates iss/aud/exp/nbf separately
/// via `Validation`, so they are not modeled here.
#[derive(Debug, Deserialize)]
struct EntraClaims {
    iss: String,
    aud: EntraAudience,
    exp: i64,
    nbf: i64,
    iat: i64,
    sub: String,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    /// Optional Entra credential-kind marker. `app` is an application actor;
    /// `user` is accepted as human only alongside delegated scopes.
    #[serde(default)]
    idtyp: Option<String>,
    /// Delegated OAuth scopes. A non-empty `scp` is the provider-neutral proof
    /// that the access token represents a user-delegated authorization.
    #[serde(default)]
    scp: Option<String>,
    /// Client-application identifiers are recorded only to classify a
    /// scope-less bearer as workload/ambiguous; they never prove a human.
    #[serde(default)]
    appid: Option<String>,
    #[serde(default)]
    azp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EntraAudience {
    One(String),
    Many(Vec<String>),
}

impl EntraAudience {
    fn canonical_values(&self) -> Option<Vec<&str>> {
        let mut values = match self {
            Self::One(value) => vec![value.as_str()],
            Self::Many(values) => values.iter().map(String::as_str).collect(),
        };
        if values.is_empty()
            || values
                .iter()
                .any(|value| value.is_empty() || value.trim() != *value)
        {
            return None;
        }
        values.sort_unstable();
        values.dedup();
        Some(values)
    }
}

fn classify_entra_actor(claims: &EntraClaims) -> ActorClass {
    let has_delegated_scope = claims
        .scp
        .as_deref()
        .is_some_and(|scope| scope.split_ascii_whitespace().next().is_some());
    match (claims.idtyp.as_deref(), has_delegated_scope) {
        (Some("app"), _) => ActorClass::Workload,
        (Some("user"), true) | (None, true) => ActorClass::VerifiedHuman,
        (Some(_), _) => ActorClass::Unknown,
        (None, false) if claims.appid.is_some() || claims.azp.is_some() => ActorClass::Workload,
        (None, false) => ActorClass::Unknown,
    }
}

/// Select the exact Entra directory object identifier used as the account key.
///
/// Entra `oid` values are UUIDs. Accepting another UUID spelling, surrounding
/// whitespace, or `sub` as a fallback would let the same directory object enter
/// the authority registry under more than one key. Requiring the canonical
/// lowercase, hyphenated spelling keeps principal-key selection singular.
fn canonical_entra_oid(value: Option<&str>) -> Option<&str> {
    let value = value?;
    let parsed = Uuid::parse_str(value).ok()?;
    (parsed.hyphenated().to_string() == value).then_some(value)
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
    #[cfg(test)]
    Static(HashMap<String, DecodingKey>),
}

#[derive(Clone)]
struct ResolvedDecodingKey {
    key: DecodingKey,
    /// Digest of the exact RSA public-key material accepted from the resolved
    /// JWKS generation. A reused `kid` cannot alias a rotated key.
    material_digest: [u8; 32],
}

/// Mutable JWKS state guarded by the cache's `RwLock`.
struct JwksState {
    keys: HashMap<String, ResolvedDecodingKey>,
    /// Absolute monotonic deadline for this complete cache generation. A
    /// generation is cleared, not merely hidden, after this deadline whenever
    /// a lookup observes expiry.
    valid_until: Option<Instant>,
    last_refresh_attempt: Option<Instant>,
    /// Monotonic publication token. A slow/cancelled refresh cannot overwrite
    /// a generation elected by a later refresh attempt.
    refresh_generation: u64,
}

/// Network JWKS cache. The `reqwest::Client` is created once and cloned
/// cheaply; the keyset lives behind an `RwLock` so the validator handle itself
/// stays immutable shared state (no global mutable state).
struct JwksCache {
    http: reqwest::Client,
    jwks_uri: reqwest::Url,
    ttl: Duration,
    inner: RwLock<JwksState>,
}

/// Closed classification of the exact signing-key source retained by an Entra
/// bearer validator. The static variant exists only in unit-test builds and
/// can never be projected as production JWKS authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntraBearerKeySourceKind {
    NetworkJwks,
    #[cfg(test)]
    StaticTestOnly,
}

/// Value-free measurement of one exact retained Entra bearer validator.
///
/// This is deliberately produced by [`EntraTokenValidator::runtime_observation`]
/// from the validator's private fields and its concrete `JwksCache`. Callers
/// cannot construct it from expected contract data or from a parallel config
/// snapshot. Identity and endpoint values are retained only as domain-separated
/// digests, and `Debug` never exposes them.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EntraBearerRuntimeObservation {
    issuer_authority_binding_digest: String,
    audience_client_binding_digest: String,
    key_source_kind: EntraBearerKeySourceKind,
    key_source_binding_digest: String,
    jwks_ttl_seconds: Option<u64>,
    clock_skew_limit_id: String,
    maximum_clock_skew_seconds: u64,
    credential_lifetime_limit_id: String,
    maximum_credential_lifetime_seconds: u64,
    accepted_algorithm_ids: [&'static str; 1],
    required_claim_ids: [&'static str; 6],
    provider_subject_claim_id: &'static str,
    expiration_required: bool,
    not_before_required: bool,
    issued_at_required: bool,
    nonce_required: bool,
    redirects_allowed: bool,
}

impl fmt::Debug for EntraBearerRuntimeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntraBearerRuntimeObservation")
            .field("identity_bindings", &"[REDACTED]")
            .field("key_source_kind", &self.key_source_kind)
            .field("key_source_binding", &"[REDACTED]")
            .field("verifier_policy", &"[RETAINED]")
            .finish()
    }
}

impl EntraBearerRuntimeObservation {
    pub(crate) fn issuer_authority_binding_digest(&self) -> &str {
        &self.issuer_authority_binding_digest
    }

    pub(crate) fn audience_client_binding_digest(&self) -> &str {
        &self.audience_client_binding_digest
    }

    pub(crate) fn key_source_kind(&self) -> EntraBearerKeySourceKind {
        self.key_source_kind
    }

    pub(crate) fn key_source_binding_digest(&self) -> &str {
        &self.key_source_binding_digest
    }

    pub(crate) fn jwks_ttl_seconds(&self) -> Option<u64> {
        self.jwks_ttl_seconds
    }

    pub(crate) fn clock_skew_limit_id(&self) -> &str {
        &self.clock_skew_limit_id
    }

    pub(crate) fn maximum_clock_skew_seconds(&self) -> u64 {
        self.maximum_clock_skew_seconds
    }

    /// Compatibility name for test projections of the validator's JWT leeway.
    /// The value is the exact registered clock-skew limit rather than an
    /// independent runtime knob.
    #[cfg(test)]
    pub(crate) fn validation_leeway_seconds(&self) -> u64 {
        self.maximum_clock_skew_seconds
    }

    pub(crate) fn credential_lifetime_limit_id(&self) -> &str {
        &self.credential_lifetime_limit_id
    }

    pub(crate) fn maximum_credential_lifetime_seconds(&self) -> u64 {
        self.maximum_credential_lifetime_seconds
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

    pub(crate) fn nonce_required(&self) -> bool {
        self.nonce_required
    }

    pub(crate) fn redirects_allowed(&self) -> bool {
        self.redirects_allowed
    }
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
    fn new(http: reqwest::Client, jwks_uri: reqwest::Url, ttl: Duration) -> Self {
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

    /// Resolves the `DecodingKey` for `kid`, refreshing the keyset on an unknown
    /// `kid` (signing-key rotation) or an expired TTL, subject to a refresh
    /// cooldown. Once the absolute deadline passes, a failed refresh or active
    /// retry cooldown clears the retired generation. Unknown-kid refresh
    /// failures preserve only a still-fresh generation for legitimate callers.
    async fn decoding_key_for_kid(&self, kid: &str) -> Option<ResolvedDecodingKey> {
        // Fast path: shared read lock. Hit only when the kid is present AND the
        // keyset is still within its TTL.
        {
            let state = self.inner.read().await;
            if let Some(key) = state.keys.get(kid) {
                if Self::fresh(&state) {
                    return Some(key.clone());
                }
            }
        }

        // Elect one cooldown-bounded refresher under the write lock, then drop
        // the lock before network transfer and JSON parsing. A still-fresh
        // known key remains available while an unknown kid is being refreshed.
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

    fn resolved_key_or_expire(state: &mut JwksState, kid: &str) -> Option<ResolvedDecodingKey> {
        if Self::fresh(state) {
            state.keys.get(kid).cloned()
        } else {
            state.keys.clear();
            state.valid_until = None;
            None
        }
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, ResolvedDecodingKey>, ()> {
        let resp = self
            .http
            .get(self.jwks_uri.clone())
            .send()
            .await
            .map_err(|_| ())?;
        if !resp.status().is_success() {
            return Err(());
        }
        let doc: JwksDocument =
            crate::oidc_callback::bounded_json_response(resp, MAX_JWKS_BYTES).await?;
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
                let material_digest = request_read_digest(
                    b"ryuki-request-read-entra-rsa-jwk-v1",
                    &[b"RS256", jwk.n.as_bytes(), jwk.e.as_bytes()],
                );
                keys.insert(
                    jwk.kid,
                    ResolvedDecodingKey {
                        key,
                        material_digest,
                    },
                );
            }
        }
        if keys.is_empty() {
            // Never publish an empty or entirely unusable document as a new
            // trust generation. It is a refresh failure, not key rotation.
            Err(())
        } else {
            Ok(keys)
        }
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

/// Enforce the registered reusable-bearer validity interval after the token's
/// signature and standard JWT claims have been verified. Every arithmetic edge
/// is checked: malformed or unrepresentable intervals fail closed instead of
/// wrapping into an apparently short-lived credential.
fn registered_credential_window_is_valid(
    issued_at: i64,
    expires_at: i64,
    now: i64,
    limits: &crate::security_contracts::ResolvedAuthenticatorBearerLimits,
) -> bool {
    let Ok(maximum_lifetime) = i64::try_from(limits.maximum_credential_lifetime_seconds()) else {
        return false;
    };
    let Some(lifetime) = expires_at.checked_sub(issued_at) else {
        return false;
    };
    if lifetime <= 0 || lifetime > maximum_lifetime {
        return false;
    }

    let Ok(clock_skew) = i64::try_from(limits.maximum_clock_skew_seconds()) else {
        return false;
    };
    now.checked_add(clock_skew)
        .is_some_and(|latest_issued_at| issued_at <= latest_issued_at)
}

fn authenticator_leaf_binding_digest(domain: &[u8], values: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for value in std::iter::once(AUTHENTICATOR_LEAF_DIGEST_CONTRACT)
        .chain(std::iter::once(domain))
        .chain(values.iter().copied())
    {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    let digest = digest.finalize();
    format!("sha256:{digest:x}")
}

/// Outcome of a validation attempt. The session is what callers consume; the
/// reason is for safe logging only and is `None` on success.
pub struct ValidationOutcome {
    pub session: AuthSession,
    pub failure_reason: Option<&'static str>,
    /// Canonical provider subject proven by this validation attempt. This is
    /// lookup provenance for the principal registry, not an authorization ID.
    /// It is populated only after signature, issuer, audience, lifetime, and
    /// canonical Entra object-ID validation all succeed.
    pub(crate) external_subject: Option<String>,
    pub(crate) request_read_credential: Option<crate::request_authority::DirectFederatedCredential>,
}

impl ValidationOutcome {
    fn unverified(reason: &'static str) -> Self {
        Self {
            session: AuthSession::unverified_entra(),
            failure_reason: Some(reason),
            external_subject: None,
            request_read_credential: None,
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
    bearer_limits: Arc<crate::security_contracts::ResolvedAuthenticatorBearerLimits>,
}

impl EntraTokenValidator {
    /// Production constructor: derives `EntraConfig` from the app config values
    /// (so `enabled` is computed consistently with every other Entra consumer)
    /// and wires up a network-backed JWKS cache.
    pub(crate) fn from_app_config(
        tenant_id: &str,
        client_id: &str,
        instance: &str,
        jwks_ttl_secs: u64,
        bearer_limits: Arc<crate::security_contracts::ResolvedAuthenticatorBearerLimits>,
    ) -> Self {
        let config = get_entra_config_from_env(tenant_id, client_id, instance);
        let (issuer, audiences, jwks_uri) = Self::derive_identity_endpoints(&config)
            .expect("Entra authority must be a parsed HTTPS URL (loopback HTTP is unit-test only)");
        // A bounded timeout is essential even though refresh elects its
        // publication generation under the cache lock and performs network
        // I/O after releasing it. It bounds the individual unknown-kid caller
        // and refresh resource use against a slow/black-holed endpoint.
        // (Mirrors the OIDC id-token validator's client.)
        let http = crate::oidc_callback::identity_http_client(&jwks_uri);
        let cache = JwksCache::new(http, jwks_uri, Duration::from_secs(jwks_ttl_secs));
        Self {
            config,
            issuer,
            audiences,
            keys: KeySource::Network(cache),
            bearer_limits,
        }
    }

    /// Independently measure the immutable verifier and key-source policy from
    /// this exact retained object. No caller-provided expected value or config
    /// projection participates in the result.
    pub(crate) fn runtime_observation(&self) -> EntraBearerRuntimeObservation {
        let mut audiences = self
            .audiences
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        audiences.sort_unstable();
        audiences.dedup();
        let audience_bytes = audiences
            .iter()
            .map(|audience| audience.as_bytes())
            .collect::<Vec<_>>();

        let issuer_authority_binding_digest = authenticator_leaf_binding_digest(
            ENTRA_ISSUER_AUTHORITY_BINDING_DOMAIN,
            &[self.issuer.as_bytes()],
        );
        let audience_client_binding_digest = authenticator_leaf_binding_digest(
            ENTRA_AUDIENCE_CLIENT_BINDING_DOMAIN,
            &audience_bytes,
        );

        let (key_source_kind, key_source_binding_digest, jwks_ttl_seconds) = match &self.keys {
            KeySource::Network(cache) => {
                let ttl_seconds = cache.ttl.as_secs();
                let ttl = ttl_seconds.to_string();
                let refresh_cooldown = REFRESH_COOLDOWN.as_secs().to_string();
                let maximum_keys = MAX_JWKS_KEYS.to_string();
                let maximum_response_bytes = MAX_JWKS_BYTES.to_string();
                let connect_timeout = crate::oidc_callback::identity_connect_timeout()
                    .as_millis()
                    .to_string();
                let request_timeout = crate::oidc_callback::identity_request_timeout()
                    .as_millis()
                    .to_string();
                let https_only = (cache.jwks_uri.scheme() == "https").to_string();
                let digest = authenticator_leaf_binding_digest(
                    ENTRA_JWKS_KEY_SOURCE_BINDING_DOMAIN,
                    &[
                        b"jwt-jwks",
                        cache.jwks_uri.as_str().as_bytes(),
                        ttl.as_bytes(),
                        refresh_cooldown.as_bytes(),
                        maximum_keys.as_bytes(),
                        maximum_response_bytes.as_bytes(),
                        connect_timeout.as_bytes(),
                        request_timeout.as_bytes(),
                        https_only.as_bytes(),
                        b"no-proxy",
                        b"redirects-disabled",
                    ],
                );
                (
                    EntraBearerKeySourceKind::NetworkJwks,
                    digest,
                    Some(ttl_seconds),
                )
            }
            #[cfg(test)]
            KeySource::Static(keys) => {
                let key_count = keys.len().to_string();
                (
                    EntraBearerKeySourceKind::StaticTestOnly,
                    authenticator_leaf_binding_digest(
                        ENTRA_JWKS_KEY_SOURCE_BINDING_DOMAIN,
                        &[b"static-test-only", key_count.as_bytes()],
                    ),
                    None,
                )
            }
        };

        EntraBearerRuntimeObservation {
            issuer_authority_binding_digest,
            audience_client_binding_digest,
            key_source_kind,
            key_source_binding_digest,
            jwks_ttl_seconds,
            clock_skew_limit_id: self.bearer_limits.clock_skew_limit_id().to_owned(),
            maximum_clock_skew_seconds: self.bearer_limits.maximum_clock_skew_seconds(),
            credential_lifetime_limit_id: self
                .bearer_limits
                .credential_lifetime_limit_id()
                .to_owned(),
            maximum_credential_lifetime_seconds: self
                .bearer_limits
                .maximum_credential_lifetime_seconds(),
            accepted_algorithm_ids: ["rs256"],
            required_claim_ids: ENTRA_REQUIRED_CLAIM_IDS,
            provider_subject_claim_id: "oid",
            expiration_required: true,
            not_before_required: true,
            issued_at_required: true,
            nonce_required: false,
            redirects_allowed: false,
        }
    }

    /// Return the exact registered limits retained by this validator. Runtime
    /// composition may clone this Arc, but cannot substitute another allocation
    /// without failing [`Self::retains_bearer_limits`].
    #[cfg(test)]
    pub(crate) fn bearer_limits(
        &self,
    ) -> Arc<crate::security_contracts::ResolvedAuthenticatorBearerLimits> {
        Arc::clone(&self.bearer_limits)
    }

    pub(crate) fn retains_bearer_limits(
        &self,
        limits: &Arc<crate::security_contracts::ResolvedAuthenticatorBearerLimits>,
    ) -> bool {
        Arc::ptr_eq(&self.bearer_limits, limits)
    }

    #[cfg(test)]
    fn with_static_keys_and_limits(
        config: EntraConfig,
        keys: HashMap<String, DecodingKey>,
        bearer_limits: Arc<crate::security_contracts::ResolvedAuthenticatorBearerLimits>,
    ) -> Self {
        let (issuer, audiences, _) = Self::derive_identity_endpoints(&config)
            .expect("Entra authority must be a parsed HTTPS URL (loopback HTTP is unit-test only)");
        Self {
            config,
            issuer,
            audiences,
            keys: KeySource::Static(keys),
            bearer_limits,
        }
    }

    /// Issuer = `{authority}/{tenant}/v2.0`; audiences accept both the bare
    /// client id and the `api://{client_id}` form Entra issues for app APIs.
    fn derive_identity_endpoints(
        config: &EntraConfig,
    ) -> Result<(String, Vec<String>, reqwest::Url), &'static str> {
        let authority = crate::oidc_callback::parse_identity_endpoint(&config.instance)?;
        if authority.query().is_some() {
            return Err("authority-query-not-allowed");
        }

        let issuer = Self::append_authority_segments(
            authority.clone(),
            &[config.tenant_id.as_str(), "v2.0"],
        )?;
        let jwks_uri = Self::append_authority_segments(
            authority,
            &[config.tenant_id.as_str(), "discovery", "v2.0", "keys"],
        )?;
        let audiences = vec![
            config.client_id.clone(),
            format!("api://{}", config.client_id),
        ];
        Ok((issuer.to_string(), audiences, jwks_uri))
    }

    fn append_authority_segments(
        mut authority: reqwest::Url,
        segments: &[&str],
    ) -> Result<reqwest::Url, &'static str> {
        let mut path = authority
            .path_segments_mut()
            .map_err(|_| "authority-cannot-be-base")?;
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
        drop(path);
        Ok(authority)
    }

    async fn resolve_key(&self, kid: &str) -> Option<ResolvedDecodingKey> {
        match &self.keys {
            KeySource::Network(cache) => cache.decoding_key_for_kid(kid).await,
            #[cfg(test)]
            KeySource::Static(map) => map.get(kid).cloned().map(|key| ResolvedDecodingKey {
                key,
                // Static keys are a unit-test-only injection seam and cannot
                // produce production request authority.
                material_digest: request_read_digest(
                    b"ryuki-request-read-entra-static-test-key-v1",
                    &[kid.as_bytes()],
                ),
            }),
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
        let resolved_key = match self.resolve_key(&kid).await {
            Some(k) => k,
            None => return ValidationOutcome::unverified("unknown-kid"),
        };

        // Step 4: configure validation. RS256 only; issuer/audience pinned;
        // exp (default on) and nbf enforced with a small leeway.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(std::slice::from_ref(&self.issuer));
        validation.set_audience(&self.audiences);
        validation.leeway = self.bearer_limits.maximum_clock_skew_seconds();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // Demand the pinned claims and signed OIDC subject are PRESENT, not
        // merely correct-when-present. jsonwebtoken's default
        // `required_spec_claims` is only {"exp"}, so this call REPLACES that set
        // and must retain "exp" explicitly. `sub` remains required signed input
        // even though only canonical Entra `oid` is selected as the account key.
        validation.set_required_spec_claims(&["exp", "nbf", "iat", "iss", "aud", "sub"]);

        // Step 5: verify signature + iss/aud/exp/nbf atomically.
        let data = match decode::<EntraClaims>(token, &resolved_key.key, &validation) {
            Ok(d) => d,
            Err(e) => return ValidationOutcome::unverified(failure_reason(&e)),
        };

        // Step 6: map claims into a verified session.
        let claims = data.claims;
        if !registered_credential_window_is_valid(
            claims.iat,
            claims.exp,
            chrono::Utc::now().timestamp(),
            &self.bearer_limits,
        ) {
            return ValidationOutcome::unverified("invalid-token");
        }
        if claims.sub.is_empty() {
            return ValidationOutcome::unverified("invalid-token");
        }
        if claims.iss != self.issuer {
            return ValidationOutcome::unverified("wrong-issuer");
        }
        let Some(audiences) = claims.aud.canonical_values() else {
            return ValidationOutcome::unverified("wrong-audience");
        };
        let Some(authenticated_at) = chrono::DateTime::from_timestamp(claims.iat, 0) else {
            return ValidationOutcome::unverified("invalid-token");
        };
        let Some(not_before) = chrono::DateTime::from_timestamp(claims.nbf, 0) else {
            return ValidationOutcome::unverified("invalid-token");
        };
        let Some(expires_at) = chrono::DateTime::from_timestamp(claims.exp, 0) else {
            return ValidationOutcome::unverified("invalid-token");
        };
        let Some(entra_account_key) = canonical_entra_oid(claims.oid.as_deref()) else {
            return ValidationOutcome::unverified("invalid-token");
        };
        let entra_account_key = entra_account_key.to_string();
        let request_read_credential = (|| {
            let window = crate::request_authority::RequestReadCredentialWindow::new(
                1,
                authenticated_at,
                not_before,
                expires_at,
                ryuki_engine::authorization::AssuranceLevel::SingleFactor,
                expires_at,
            )?;
            let credential_id =
                request_read_digest(b"ryuki-request-read-entra-token-v1", &[token.as_bytes()]);
            let audience_parts = audiences
                .iter()
                .map(|value| value.as_bytes())
                .collect::<Vec<_>>();
            let digests = crate::request_authority::RequestReadCredentialDigests::new(
                credential_id,
                request_read_digest(b"ryuki-request-read-entra-audience-v1", &audience_parts),
                resolved_key.material_digest,
            )?;
            crate::request_authority::DirectFederatedCredential::new(
                window,
                digests,
                "entra-id".to_string(),
                claims.iss.clone(),
                entra_account_key.clone(),
            )
        })();
        // The normal authentication semantics keep jsonwebtoken's bounded
        // leeway. A token accepted only because of that leeway may authenticate
        // existing routes but receives no fresh request-read authority: permit
        // issuance requires a currently valid, internally ordered interval.
        let request_read_credential = request_read_credential.ok();
        let actor_class = classify_entra_actor(&claims);
        let external_subject = entra_account_key;
        let display_name = claims
            .name
            .clone()
            .or_else(|| claims.preferred_username.clone())
            .unwrap_or_else(|| external_subject.clone());

        ValidationOutcome {
            session: AuthSession {
                display_user_id: external_subject.clone(),
                // Raw provider validation proves a provider-qualified key, not
                // an internal principal. Registry admission below this seam is
                // the only code allowed to populate principal_id.
                principal_id: None,
                display_name,
                roles: claims.roles,
                token_valid: true,
                actor_class,
                provider_mode: "entra-id".to_string(),
                // Entra/OIDC sessions are not scope-restricted (#2).
                ..Default::default()
            },
            failure_reason: None,
            external_subject: Some(external_subject),
            request_read_credential,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_crypto;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_TENANT: &str = "contoso-tenant-0000";
    const TEST_CLIENT: &str = "ryuki-app-client-0000";
    const TEST_AUTHORITY: &str = "https://login.microsoftonline.com";
    const TEST_KID: &str = "test-kid-1";
    const TEST_OBJECT_ID: &str = "11111111-2222-4333-8444-555555555555";

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

    #[test]
    fn test_entra_identity_endpoints_are_parsed_and_secure() {
        let (issuer, audiences, jwks_uri) =
            EntraTokenValidator::derive_identity_endpoints(&test_config(true))
                .expect("HTTPS Entra authority should be accepted");
        assert_eq!(issuer, expected_issuer());
        assert_eq!(
            jwks_uri.as_str(),
            format!("{}/{}/discovery/v2.0/keys", TEST_AUTHORITY, TEST_TENANT)
        );
        assert_eq!(
            audiences,
            vec![TEST_CLIENT.to_string(), format!("api://{TEST_CLIENT}")]
        );

        let mut remote_cleartext = test_config(true);
        remote_cleartext.instance = "http://idp.example".to_string();
        assert_eq!(
            EntraTokenValidator::derive_identity_endpoints(&remote_cleartext).unwrap_err(),
            "https-required"
        );

        let mut loopback = test_config(true);
        loopback.instance = "http://127.0.0.1:8080".to_string();
        assert!(EntraTokenValidator::derive_identity_endpoints(&loopback).is_ok());

        let mut authority_with_query = test_config(true);
        authority_with_query.instance = "https://idp.example?alternate=origin".to_string();
        assert_eq!(
            EntraTokenValidator::derive_identity_endpoints(&authority_with_query).unwrap_err(),
            "authority-query-not-allowed"
        );
    }

    /// Generates a throwaway RSA-2048 keypair through the production AWS-LC
    /// crypto provider. No PEM or persistent private key is produced.
    fn make_keypair() -> (EncodingKey, DecodingKey, Vec<u8>) {
        let keypair = test_crypto::make_rsa_keypair();
        (keypair.encoding, keypair.decoding, keypair.public_der)
    }

    fn test_jwks_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(250))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build loopback-only JWKS test client")
    }

    async fn loopback_jwks_listener() -> (tokio::net::TcpListener, reqwest::Url) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback JWKS test endpoint");
        let address = listener.local_addr().expect("JWKS test endpoint address");
        let url = reqwest::Url::parse(&format!("http://{address}/jwks"))
            .expect("parse loopback JWKS test URL");
        (listener, url)
    }

    async fn read_jwks_test_request(stream: &mut tokio::net::TcpStream) {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut chunk))
                .await
                .expect("JWKS request read deadline")
                .expect("read JWKS request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            assert!(
                request.len() <= 8192,
                "JWKS test request headers are bounded"
            );
            if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                break;
            }
        }
    }

    fn padded_jwks_body(target_len: usize, modulus: &str, exponent: &str) -> Vec<u8> {
        let prefix = format!(
            r#"{{"keys":[{{"kid":"{TEST_KID}","kty":"RSA","use":"sig","n":"{modulus}","e":"{exponent}"}}],"padding":""#
        );
        const SUFFIX: &[u8] = b"\"}";
        assert!(target_len >= prefix.len() + SUFFIX.len());

        let mut body = Vec::with_capacity(target_len);
        body.extend_from_slice(prefix.as_bytes());
        body.resize(target_len - SUFFIX.len(), b'a');
        body.extend_from_slice(SUFFIX);
        assert_eq!(body.len(), target_len);
        body
    }

    async fn serve_chunked_jwks(listener: tokio::net::TcpListener, body: Vec<u8>) {
        let (mut stream, _) = listener.accept().await.expect("accept JWKS request");
        read_jwks_test_request(&mut stream).await;
        if stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .is_err()
        {
            return;
        }

        let chunk_size = (body.len() / 2).max(1);
        for chunk in body.chunks(chunk_size) {
            let frame = format!("{:X}\r\n", chunk.len());
            if stream.write_all(frame.as_bytes()).await.is_err()
                || stream.write_all(chunk).await.is_err()
                || stream.write_all(b"\r\n").await.is_err()
            {
                return;
            }
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
    }

    #[tokio::test]
    async fn test_entra_jwks_accepts_chunked_body_at_exact_stream_limit() {
        let keypair = test_crypto::make_rsa_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = JwksCache::new(test_jwks_client(), url, Duration::from_secs(60));
        let server = tokio::spawn(serve_chunked_jwks(
            listener,
            padded_jwks_body(MAX_JWKS_BYTES, &keypair.modulus_b64, &keypair.exponent_b64),
        ));

        let keys = cache
            .fetch_keys()
            .await
            .expect("an exact-limit chunked JWKS document should be accepted");
        assert!(keys.contains_key(TEST_KID));
        server.await.expect("exact-limit JWKS server task");
    }

    #[tokio::test]
    async fn test_entra_jwks_rejects_chunked_body_crossing_stream_limit() {
        let keypair = test_crypto::make_rsa_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = JwksCache::new(test_jwks_client(), url, Duration::from_secs(60));
        let server = tokio::spawn(serve_chunked_jwks(
            listener,
            padded_jwks_body(
                MAX_JWKS_BYTES + 1,
                &keypair.modulus_b64,
                &keypair.exponent_b64,
            ),
        ));

        assert!(cache.fetch_keys().await.is_err());
        server.await.expect("oversized JWKS server task");
    }

    #[tokio::test]
    async fn test_entra_jwks_never_follows_cross_origin_redirect() {
        let (source_listener, source_url) = loopback_jwks_listener().await;
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind JWKS redirect target");
        let target_address = target_listener
            .local_addr()
            .expect("JWKS redirect-target address");
        let source = tokio::spawn(async move {
            let (mut stream, _) = source_listener
                .accept()
                .await
                .expect("accept original JWKS request");
            read_jwks_test_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_address}/captured\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write JWKS redirect response");
        });
        let target = tokio::spawn(async move {
            let accepted =
                tokio::time::timeout(Duration::from_millis(500), target_listener.accept()).await;
            let Ok(Ok((mut stream, _))) = accepted else {
                return false;
            };
            read_jwks_test_request(&mut stream).await;
            let body = r#"{"keys":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            true
        });

        let client = crate::oidc_callback::identity_http_client(&source_url);
        let cache = JwksCache::new(client, source_url, Duration::from_secs(60));
        assert!(cache.fetch_keys().await.is_err());
        source.await.expect("original JWKS server task");
        assert!(
            !target.await.expect("JWKS redirect-target task"),
            "a redirect target must never receive a signing-key request"
        );
    }

    async fn seed_network_cache(
        cache: &JwksCache,
        key: DecodingKey,
        valid_until: Instant,
        last_refresh_attempt: Option<Instant>,
    ) {
        let mut state = cache.inner.write().await;
        state.keys.insert(
            TEST_KID.to_string(),
            ResolvedDecodingKey {
                key,
                material_digest: request_read_digest(
                    b"ryuki-request-read-entra-seeded-test-key-v1",
                    &[TEST_KID.as_bytes()],
                ),
            },
        );
        state.valid_until = Some(valid_until);
        state.last_refresh_attempt = last_refresh_attempt;
    }

    fn network_validator(cache: JwksCache) -> EntraTokenValidator {
        EntraTokenValidator {
            config: test_config(true),
            issuer: expected_issuer(),
            audiences: vec![TEST_CLIENT.to_string(), format!("api://{TEST_CLIENT}")],
            keys: KeySource::Network(cache),
            bearer_limits: crate::security_contracts::ResolvedAuthenticatorBearerLimits::fixture(
                60, 3_600,
            ),
        }
    }

    #[tokio::test]
    async fn test_jwks_fresh_cached_key_is_returned_without_refresh() {
        let (_enc, dec, _) = make_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = JwksCache::new(test_jwks_client(), url, Duration::from_secs(60));
        seed_network_cache(
            &cache,
            dec,
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
    }

    #[tokio::test]
    async fn test_entra_jwks_known_key_remains_nonblocking_during_unknown_kid_refresh() {
        let (_enc, dec, _) = make_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = std::sync::Arc::new(JwksCache::new(
            test_jwks_client(),
            url,
            Duration::from_secs(60),
        ));
        seed_network_cache(
            &cache,
            dec,
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
            read_jwks_test_request(&mut stream).await;
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

        let refresh_cache = std::sync::Arc::clone(&cache);
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
    async fn test_jwks_unknown_kid_fails_closed_when_refresh_fails() {
        let (_enc, dec, _) = make_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = JwksCache::new(test_jwks_client(), url, Duration::from_secs(60));
        seed_network_cache(
            &cache,
            dec,
            Instant::now()
                .checked_add(Duration::from_secs(60))
                .expect("represent a fresh cache deadline"),
            None,
        )
        .await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept JWKS refresh request");
            read_jwks_test_request(&mut stream).await;
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

        assert!(cache
            .decoding_key_for_kid("never-published-kid")
            .await
            .is_none());
        server.await.expect("unknown-kid JWKS server task");
        assert!(
            cache.decoding_key_for_kid(TEST_KID).await.is_some(),
            "a failed unknown-kid refresh must not let the attacker retire a still-valid generation"
        );
    }

    #[tokio::test]
    async fn test_jwks_expired_key_is_rejected_during_refresh_cooldown() {
        let (enc, dec, _) = make_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = JwksCache::new(test_jwks_client(), url, Duration::from_secs(1));
        let now = Instant::now();
        seed_network_cache(
            &cache,
            dec,
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
        let validator = network_validator(cache);
        let token = sign(&enc, valid_claims());

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("unknown-kid"));
        assert!(
            !unexpected_refresh.await.expect("JWKS probe task"),
            "refresh cooldown must remain effective"
        );
    }

    #[tokio::test]
    async fn test_jwks_expired_key_is_rejected_when_refresh_fails() {
        let (enc, dec, _) = make_keypair();
        let (listener, url) = loopback_jwks_listener().await;
        let cache = JwksCache::new(test_jwks_client(), url, Duration::from_secs(1));
        seed_network_cache(
            &cache,
            dec,
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
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write failed JWKS refresh response");
        });
        let validator = network_validator(cache);
        let token = sign(&enc, valid_claims());

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("unknown-kid"));
        server.await.expect("JWKS failure server task");
        let KeySource::Network(cache) = &validator.keys else {
            panic!("test validator must use the network cache");
        };
        assert!(
            !cache.inner.read().await.keys.contains_key(TEST_KID),
            "refresh failure must remove the retired Entra key generation"
        );
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
        static_validator_with_leeway(decoding, enabled, 60)
    }

    fn static_validator_with_leeway(
        decoding: DecodingKey,
        enabled: bool,
        leeway_secs: u64,
    ) -> EntraTokenValidator {
        static_validator_with_limits(decoding, enabled, leeway_secs, 3_600)
    }

    fn static_validator_with_limits(
        decoding: DecodingKey,
        enabled: bool,
        clock_skew_seconds: u64,
        maximum_credential_lifetime_seconds: u64,
    ) -> EntraTokenValidator {
        let mut map = HashMap::new();
        map.insert(TEST_KID.to_string(), decoding);
        EntraTokenValidator::with_static_keys_and_limits(
            test_config(enabled),
            map,
            crate::security_contracts::ResolvedAuthenticatorBearerLimits::fixture(
                clock_skew_seconds,
                maximum_credential_lifetime_seconds,
            ),
        )
    }

    #[test]
    fn retained_bearer_limits_are_observable_and_identity_checked() {
        let (_encoding, decoding, _) = make_keypair();
        let retained =
            crate::security_contracts::ResolvedAuthenticatorBearerLimits::fixture(17, 1_700);
        let mut keys = HashMap::new();
        keys.insert(TEST_KID.to_string(), decoding);
        let validator = EntraTokenValidator::with_static_keys_and_limits(
            test_config(true),
            keys,
            Arc::clone(&retained),
        );

        let observed = validator.runtime_observation();
        assert_eq!(
            observed.clock_skew_limit_id(),
            retained.clock_skew_limit_id()
        );
        assert_eq!(observed.maximum_clock_skew_seconds(), 17);
        assert_eq!(
            observed.credential_lifetime_limit_id(),
            retained.credential_lifetime_limit_id()
        );
        assert_eq!(observed.maximum_credential_lifetime_seconds(), 1_700);

        let accessor_clone = validator.bearer_limits();
        assert!(Arc::ptr_eq(&accessor_clone, &retained));
        assert!(validator.retains_bearer_limits(&retained));
        let equal_but_distinct =
            crate::security_contracts::ResolvedAuthenticatorBearerLimits::fixture(17, 1_700);
        assert!(!validator.retains_bearer_limits(&equal_but_distinct));
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
        let reference_time = now();
        json!({
            "iss": expected_issuer(),
            "aud": TEST_CLIENT,
            "sub": "subject-1",
            "oid": TEST_OBJECT_ID,
            "name": "Ada Admin",
            "preferred_username": "ada@contoso.example",
            "exp": reference_time + 3540,
            "nbf": reference_time - 60,
            "iat": reference_time - 60,
            "roles": ["PlatformAdmin"],
            "idtyp": "user",
            "scp": "user_impersonation",
            "azp": TEST_CLIENT,
        })
    }

    #[tokio::test]
    async fn test_valid_token_yields_validated_but_unbound_session() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let token = sign(&enc, valid_claims());

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert_eq!(outcome.failure_reason, None);
        assert_eq!(outcome.external_subject.as_deref(), Some(TEST_OBJECT_ID));
        assert!(outcome.request_read_credential.is_some());
        assert!(outcome.session.token_valid);
        assert_eq!(
            outcome.session.actor_class,
            ryuki_engine::auth::ActorClass::VerifiedHuman
        );
        assert_eq!(outcome.session.principal_id, None);
        assert!(!outcome.session.is_verified_human());
        assert_eq!(outcome.session.provider_mode, "entra-id");
        assert_eq!(outcome.session.roles, vec!["PlatformAdmin"]);
        assert_eq!(outcome.session.display_user_id, TEST_OBJECT_ID);
        // name preferred for display.
        assert_eq!(outcome.session.display_name, "Ada Admin");

        // The credential's Debug projection is safe if it reaches diagnostic
        // logging: neither the reusable bearer nor signed identity claims are
        // rendered.
        let credential_debug = format!("{:?}", outcome.request_read_credential);
        assert!(!credential_debug.contains(&token));
        assert!(!credential_debug.contains(TEST_OBJECT_ID));
        assert!(!credential_debug.contains("subject-1"));
    }

    #[tokio::test]
    async fn service_principal_and_ambiguous_bearers_are_not_humans() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);

        let mut application = valid_claims();
        application["idtyp"] = json!("app");
        application.as_object_mut().unwrap().remove("scp");
        application["appid"] = json!(TEST_CLIENT);
        let application = validator.validate(&auth(&sign(&enc, application))).await;
        assert!(
            application.token_valid,
            "the JWT itself remains cryptographically valid"
        );
        assert_eq!(application.actor_class, ActorClass::Workload);
        assert!(!application.is_verified_human());

        let mut ambiguous = valid_claims();
        ambiguous.as_object_mut().unwrap().remove("idtyp");
        ambiguous.as_object_mut().unwrap().remove("scp");
        ambiguous.as_object_mut().unwrap().remove("appid");
        ambiguous.as_object_mut().unwrap().remove("azp");
        let ambiguous = validator.validate(&auth(&sign(&enc, ambiguous))).await;
        assert!(ambiguous.token_valid);
        assert_eq!(ambiguous.actor_class, ActorClass::Unknown);
        assert!(!ambiguous.is_verified_human());
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
    async fn test_max_admitted_leeway_remains_a_bounded_token_time_window() {
        const MAX_ADMITTED_LEEWAY_SECS: u64 = 300;

        let (enc, dec, _) = make_keypair();
        let validator = static_validator_with_leeway(dec, true, MAX_ADMITTED_LEEWAY_SECS);
        let reference_time = now();

        let mut within_window = valid_claims();
        within_window["exp"] = json!(reference_time - 240);
        within_window["nbf"] = json!(reference_time + 240);
        within_window["iat"] = json!(reference_time - 3_600);
        let token = sign(&enc, within_window);
        assert!(
            validator.validate(&auth(&token)).await.token_valid,
            "the reviewed maximum leeway should accommodate timestamps inside five minutes"
        );

        let mut too_expired = valid_claims();
        too_expired["exp"] = json!(reference_time - 360);
        let token = sign(&enc, too_expired);
        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("expired"));

        let mut too_early = valid_claims();
        too_early["nbf"] = json!(reference_time + 360);
        let token = sign(&enc, too_early);
        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("not-yet-valid"));
    }

    #[tokio::test]
    async fn registered_bearer_lifetime_accepts_the_exact_boundary() {
        const MAXIMUM_LIFETIME_SECONDS: u64 = 1_800;

        let (enc, dec, _) = make_keypair();
        let validator = static_validator_with_limits(dec, true, 60, MAXIMUM_LIFETIME_SECONDS);
        let issued_at = now() - 30;
        let mut claims = valid_claims();
        claims["iat"] = json!(issued_at);
        claims["nbf"] = json!(issued_at);
        claims["exp"] = json!(issued_at + MAXIMUM_LIFETIME_SECONDS as i64);

        let outcome = validator
            .validate_with_reason(&auth(&sign(&enc, claims)))
            .await;
        assert_eq!(outcome.failure_reason, None);
        assert!(outcome.session.token_valid);
    }

    #[tokio::test]
    async fn registered_bearer_lifetime_rejects_boundary_plus_one() {
        const MAXIMUM_LIFETIME_SECONDS: u64 = 1_800;

        let (enc, dec, _) = make_keypair();
        let validator = static_validator_with_limits(dec, true, 60, MAXIMUM_LIFETIME_SECONDS);
        let issued_at = now() - 30;
        let mut claims = valid_claims();
        claims["iat"] = json!(issued_at);
        claims["nbf"] = json!(issued_at);
        claims["exp"] = json!(issued_at + MAXIMUM_LIFETIME_SECONDS as i64 + 1);

        let outcome = validator
            .validate_with_reason(&auth(&sign(&enc, claims)))
            .await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("invalid-token"));
    }

    #[tokio::test]
    async fn registered_bearer_lifetime_rejects_expiration_at_or_before_issuance() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator_with_limits(dec, true, 60, 1_800);
        let issued_at = now() + 30;

        for expires_at in [issued_at, issued_at - 1] {
            let mut claims = valid_claims();
            claims["iat"] = json!(issued_at);
            claims["nbf"] = json!(now() - 30);
            claims["exp"] = json!(expires_at);

            let outcome = validator
                .validate_with_reason(&auth(&sign(&enc, claims)))
                .await;
            assert!(!outcome.session.token_valid);
            assert_eq!(outcome.failure_reason, Some("invalid-token"));
        }
    }

    #[tokio::test]
    async fn registered_bearer_lifetime_rejects_future_issued_at_beyond_clock_skew() {
        const CLOCK_SKEW_SECONDS: u64 = 60;

        let (enc, dec, _) = make_keypair();
        let validator = static_validator_with_limits(dec, true, CLOCK_SKEW_SECONDS, 1_800);
        let issued_at = now() + CLOCK_SKEW_SECONDS as i64 + 30;
        let mut claims = valid_claims();
        claims["iat"] = json!(issued_at);
        claims["nbf"] = json!(now() - 30);
        claims["exp"] = json!(issued_at + 1_800);

        let outcome = validator
            .validate_with_reason(&auth(&sign(&enc, claims)))
            .await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.failure_reason, Some("invalid-token"));
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
        let (_enc, dec, public_der) = make_keypair();
        let validator = static_validator(dec, true);

        let hmac_key = EncodingKey::from_secret(&public_der);
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
    async fn test_missing_oid_rejected_without_sub_fallback_or_sensitive_log_reason() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);
        let mut claims = valid_claims();
        claims["sub"] = json!("signed-sub-must-not-become-the-account-key");
        claims.as_object_mut().unwrap().remove("oid");
        let token = sign(&enc, claims);

        let outcome = validator.validate_with_reason(&auth(&token)).await;
        assert!(!outcome.session.token_valid);
        assert_eq!(outcome.session.provider_mode, "entra-id-unverified");
        assert_ne!(
            outcome.session.display_user_id,
            "signed-sub-must-not-become-the-account-key"
        );
        assert!(outcome.external_subject.is_none());
        assert!(outcome.request_read_credential.is_none());
        assert_eq!(outcome.failure_reason, Some("invalid-token"));
        let log_reason = outcome.failure_reason.unwrap_or_default();
        assert!(!log_reason.contains(&token));
        assert!(!log_reason.contains("signed-sub-must-not-become-the-account-key"));
    }

    #[tokio::test]
    async fn test_blank_or_noncanonical_oid_rejected() {
        let (enc, dec, _) = make_keypair();
        let validator = static_validator(dec, true);

        for oid in [
            "",
            "   ",
            "11111111222243338444555555555555",
            "11111111-2222-4333-8444-555555555555 ",
            "11111111-2222-4333-8444-55555555555A",
        ] {
            let mut claims = valid_claims();
            claims["oid"] = json!(oid);
            let token = sign(&enc, claims);

            let outcome = validator.validate_with_reason(&auth(&token)).await;
            assert!(!outcome.session.token_valid, "oid={oid:?}");
            assert!(outcome.request_read_credential.is_none(), "oid={oid:?}");
            assert_eq!(outcome.failure_reason, Some("invalid-token"));
            let log_reason = outcome.failure_reason.unwrap_or_default();
            assert!(!log_reason.contains(&token));
            if !oid.is_empty() {
                assert!(!log_reason.contains(oid));
            }
        }
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

        // name + preferred_username absent -> canonical oid.
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("name");
        claims.as_object_mut().unwrap().remove("preferred_username");
        let token = sign(&enc, claims);
        let session = validator.validate(&auth(&token)).await;
        assert_eq!(session.display_name, TEST_OBJECT_ID);
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
