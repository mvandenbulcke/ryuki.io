//! Opaque persisted-session bearer issuance and verification.
//!
//! A session row has two unrelated identifiers:
//! - session_record_id: a non-authenticating UUID used by administrative
//!   list/get/revoke APIs and audit records;
//! - a rys_ bearer disclosed only at login/cookie issuance.
//!
//! PostgreSQL stores only HMAC-SHA256(bearer), keyed by a dedicated
//! deployment secret. The control-plane signing key is deliberately not reused
//! across this trust domain.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use ryuki_core::config::{LocalAuthUser, SessionConfig};

pub const SESSION_BEARER_PREFIX: &str = "rys_";
const SESSION_BEARER_RANDOM_BYTES: usize = 32;
const SESSION_BEARER_PAYLOAD_LEN: usize = 43;
pub const SESSION_BEARER_LEN: usize = SESSION_BEARER_PREFIX.len() + SESSION_BEARER_PAYLOAD_LEN;
const SESSION_VERIFIER_DOMAIN: &[u8] = b"ryuki/session-bearer/verifier/v1\0";
const IDENTITY_AUTHORITY_DOMAIN: &[u8] = b"ryuki/identity-authority/v1\0";
const SESSION_RUNTIME_KEY_IDENTITY_DOMAIN: &[u8] =
    b"ryuki/derived-session-runtime/key-identity/v1\0";
pub const SESSION_VERIFIER_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCredentialError {
    MissingVerifierKey,
    VerifierKeyTooShort,
    MalformedVerifierKey,
    MalformedBearer,
    InvalidMaximumAge,
    InvalidFederatedAuthorityStaleness,
}

impl std::fmt::Display for SessionCredentialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MissingVerifierKey => "session credential verifier key is not configured",
            Self::VerifierKeyTooShort => "session credential verifier key is too short",
            Self::MalformedVerifierKey => "session credential verifier key is malformed",
            Self::MalformedBearer => "session bearer is malformed",
            Self::InvalidMaximumAge => "session credential maximum age must be positive",
            Self::InvalidFederatedAuthorityStaleness => {
                "federated session authority staleness must be positive"
            }
        })
    }
}

impl std::error::Error for SessionCredentialError {}

/// A newly issued bearer plus the only representation persisted in PostgreSQL.
/// The custom Debug implementation prevents accidental plaintext disclosure.
pub struct IssuedSessionCredential {
    plaintext: Zeroizing<String>,
    verifier: [u8; SESSION_VERIFIER_LEN],
}

impl std::fmt::Debug for IssuedSessionCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedSessionCredential")
            .field("bearer", &"[redacted]")
            .field("verifier", &"[redacted]")
            .finish()
    }
}

impl IssuedSessionCredential {
    /// Plaintext access is intentionally narrow: callers use it only for the
    /// one-time login response or Set-Cookie header.
    pub fn bearer(&self) -> &str {
        self.plaintext.as_str()
    }

    /// The keyed verifier is bound directly as BYTEA and is never serialized,
    /// returned, or logged.
    pub fn verifier(&self) -> &[u8; SESSION_VERIFIER_LEN] {
        &self.verifier
    }
}

/// Value-free measurement of the exact derived-session credential authority.
/// The key itself is never exposed; its identity is a domain-separated keyed
/// digest suitable only for equality and substitution detection.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DerivedSessionRuntimeObservation {
    enabled: bool,
    key_identity_binding_digest: Option<String>,
    maximum_session_age_seconds: u64,
    federated_authority_max_staleness_seconds: u64,
    credential_format_id: &'static str,
    verifier_algorithm_id: &'static str,
    credential_random_bytes: u32,
    database_representation_id: &'static str,
}

impl fmt::Debug for DerivedSessionRuntimeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedSessionRuntimeObservation")
            .field("enabled", &self.enabled)
            .field("key_identity_binding", &"[REDACTED]")
            .field(
                "maximum_session_age_seconds",
                &self.maximum_session_age_seconds,
            )
            .field(
                "federated_authority_max_staleness_seconds",
                &self.federated_authority_max_staleness_seconds,
            )
            .field("credential_policy", &"[RETAINED]")
            .finish()
    }
}

impl DerivedSessionRuntimeObservation {
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn key_identity_binding_digest(&self) -> Option<&str> {
        self.key_identity_binding_digest.as_deref()
    }

    pub(crate) fn maximum_session_age_seconds(&self) -> u64 {
        self.maximum_session_age_seconds
    }

    pub(crate) fn federated_authority_max_staleness_seconds(&self) -> u64 {
        self.federated_authority_max_staleness_seconds
    }

    pub(crate) fn credential_format_id(&self) -> &str {
        self.credential_format_id
    }

    pub(crate) fn verifier_algorithm_id(&self) -> &str {
        self.verifier_algorithm_id
    }

    pub(crate) fn credential_random_bytes(&self) -> u32 {
        self.credential_random_bytes
    }

    pub(crate) fn database_representation_id(&self) -> &str {
        self.database_representation_id
    }
}

/// One immutable owner for browser/local session credential issuance,
/// verification, and identity-authority derivation.
///
/// Production retains one instance under `ApiAuthenticatorRuntime` and every
/// credential-bearing consumer receives an `Arc` cloned from that owner. An
/// empty key is representable only so credential-free development modes can
/// construct the complete runtime graph; all credential operations then fail
/// closed with `MissingVerifierKey`.
pub(crate) struct DerivedSessionCredentialRuntime {
    credential_hmac_key: Option<Zeroizing<String>>,
    maximum_session_age_seconds: u64,
    federated_authority_max_staleness_seconds: u64,
}

impl DerivedSessionCredentialRuntime {
    pub(crate) fn from_admitted_config(
        session: &SessionConfig,
    ) -> Result<Arc<Self>, SessionCredentialError> {
        if session.cookie_max_age_secs == 0 {
            return Err(SessionCredentialError::InvalidMaximumAge);
        }
        if session.federated_authority_max_staleness_secs == 0 {
            return Err(SessionCredentialError::InvalidFederatedAuthorityStaleness);
        }
        let credential_hmac_key = if session.credential_hmac_key.is_empty() {
            None
        } else {
            verifier_key(session)?;
            Some(Zeroizing::new(session.credential_hmac_key.clone()))
        };
        Ok(Arc::new(Self {
            credential_hmac_key,
            maximum_session_age_seconds: session.cookie_max_age_secs,
            federated_authority_max_staleness_seconds: session
                .federated_authority_max_staleness_secs,
        }))
    }

    fn key(&self) -> Result<&[u8], SessionCredentialError> {
        self.credential_hmac_key
            .as_deref()
            .map(|key| key.as_bytes())
            .ok_or(SessionCredentialError::MissingVerifierKey)
    }

    pub(crate) fn enabled(&self) -> bool {
        self.credential_hmac_key.is_some()
    }

    pub(crate) fn maximum_session_age_seconds(&self) -> u64 {
        self.maximum_session_age_seconds
    }

    pub(crate) fn federated_authority_max_staleness_seconds(&self) -> u64 {
        self.federated_authority_max_staleness_seconds
    }

    pub(crate) fn issue(&self) -> Result<IssuedSessionCredential, SessionCredentialError> {
        let plaintext = generate_session_bearer();
        let verifier = session_bearer_verifier_with_key(plaintext.as_str(), self.key()?)?;
        Ok(IssuedSessionCredential {
            plaintext,
            verifier,
        })
    }

    pub(crate) fn verifier(
        &self,
        session_token: &str,
    ) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
        session_bearer_verifier_with_key(session_token, self.key()?)
    }

    pub(crate) fn local_identity_authority_digest(
        &self,
        user: &LocalAuthUser,
    ) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
        Ok(user.session_authority_digest(self.key()?))
    }

    pub(crate) fn identity_authority_digest(
        &self,
        provider: &str,
        issuer: &str,
        subject: &str,
        roles: &[String],
    ) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
        identity_authority_digest_with_key(provider, issuer, subject, roles, self.key()?)
    }

    pub(crate) fn runtime_observation(&self) -> DerivedSessionRuntimeObservation {
        let key_identity_binding_digest = self.credential_hmac_key.as_ref().map(|key| {
            let mut mac =
                HmacSha256::new_from_slice(key.as_bytes()).expect("validated HMAC-SHA256 key");
            mac.update(SESSION_RUNTIME_KEY_IDENTITY_DOMAIN);
            let keyed_identity = mac.finalize().into_bytes();
            let mut digest = Sha256::new();
            digest.update((SESSION_RUNTIME_KEY_IDENTITY_DOMAIN.len() as u64).to_be_bytes());
            digest.update(SESSION_RUNTIME_KEY_IDENTITY_DOMAIN);
            digest.update((keyed_identity.len() as u64).to_be_bytes());
            digest.update(keyed_identity);
            format!("sha256:{:x}", digest.finalize())
        });
        DerivedSessionRuntimeObservation {
            enabled: self.enabled(),
            key_identity_binding_digest,
            maximum_session_age_seconds: self.maximum_session_age_seconds,
            federated_authority_max_staleness_seconds: self
                .federated_authority_max_staleness_seconds,
            credential_format_id: "session-credential:opaque-random-v1",
            verifier_algorithm_id: "hmac-sha256",
            credential_random_bytes: SESSION_BEARER_RANDOM_BYTES as u32,
            database_representation_id: "session-verifier:keyed-digest-only-v1",
        }
    }
}

impl fmt::Debug for DerivedSessionCredentialRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedSessionCredentialRuntime")
            .field("credential_hmac_key", &"[REDACTED]")
            .field(
                "maximum_session_age_seconds",
                &self.maximum_session_age_seconds,
            )
            .field(
                "federated_authority_max_staleness_seconds",
                &self.federated_authority_max_staleness_seconds,
            )
            .finish()
    }
}

/// Common authority surface accepted by identity persistence. Tests may use a
/// `SessionConfig` directly; production passes the exact retained runtime.
mod sealed {
    pub trait Sealed {}

    impl Sealed for super::DerivedSessionCredentialRuntime {}

    #[cfg(test)]
    impl Sealed for ryuki_core::config::SessionConfig {}
}

pub(crate) trait SessionCredentialAuthority: sealed::Sealed {
    fn maximum_session_age_seconds(&self) -> u64;

    fn local_authority_digest(
        &self,
        user: &LocalAuthUser,
    ) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError>;

    fn federated_authority_digest(
        &self,
        provider: &str,
        issuer: &str,
        subject: &str,
        roles: &[String],
    ) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError>;
}

impl SessionCredentialAuthority for DerivedSessionCredentialRuntime {
    fn maximum_session_age_seconds(&self) -> u64 {
        self.maximum_session_age_seconds()
    }

    fn local_authority_digest(
        &self,
        user: &LocalAuthUser,
    ) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
        self.local_identity_authority_digest(user)
    }

    fn federated_authority_digest(
        &self,
        provider: &str,
        issuer: &str,
        subject: &str,
        roles: &[String],
    ) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
        self.identity_authority_digest(provider, issuer, subject, roles)
    }
}

#[cfg(test)]
impl SessionCredentialAuthority for SessionConfig {
    fn maximum_session_age_seconds(&self) -> u64 {
        self.cookie_max_age_secs
    }

    fn local_authority_digest(
        &self,
        user: &LocalAuthUser,
    ) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
        local_identity_authority_digest(user, self)
    }

    fn federated_authority_digest(
        &self,
        provider: &str,
        issuer: &str,
        subject: &str,
        roles: &[String],
    ) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
        identity_authority_digest(provider, issuer, subject, roles, self)
    }
}

fn verifier_key(session: &SessionConfig) -> Result<&[u8], SessionCredentialError> {
    let key = session.credential_hmac_key.as_bytes();
    if key.is_empty() {
        return Err(SessionCredentialError::MissingVerifierKey);
    }
    if key.len() < 32 {
        return Err(SessionCredentialError::VerifierKeyTooShort);
    }
    if session.credential_hmac_key.trim() != session.credential_hmac_key
        || key.iter().any(u8::is_ascii_control)
    {
        return Err(SessionCredentialError::MalformedVerifierKey);
    }
    Ok(key)
}

/// Validate the exact canonical wire shape without retaining decoded secret
/// material: rys_ plus the unpadded base64url encoding of exactly 32 bytes.
pub fn is_well_formed_session_bearer(candidate: &str) -> bool {
    if candidate.len() != SESSION_BEARER_LEN {
        return false;
    }
    let Some(payload) = candidate.strip_prefix(SESSION_BEARER_PREFIX) else {
        return false;
    };
    if payload.len() != SESSION_BEARER_PAYLOAD_LEN {
        return false;
    }

    let Ok(decoded) = URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    let mut decoded = Zeroizing::new(decoded);
    if decoded.len() != SESSION_BEARER_RANDOM_BYTES {
        return false;
    }
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
    let valid = canonical.as_str() == payload;
    decoded.as_mut_slice().zeroize();
    valid
}

/// Generate a 256-bit opaque session bearer. This helper does not persist or
/// authenticate it; credential-bearing auth modes call issue_session_credential
/// so a keyed verifier is produced at the same time. Static/mock mode may use
/// this shape as non-authorizing UI state.
pub fn generate_session_bearer() -> Zeroizing<String> {
    let mut random = Zeroizing::new([0_u8; SESSION_BEARER_RANDOM_BYTES]);
    OsRng.fill_bytes(random.as_mut());
    let payload = Zeroizing::new(URL_SAFE_NO_PAD.encode(random.as_slice()));
    let plaintext = Zeroizing::new(format!("{SESSION_BEARER_PREFIX}{}", payload.as_str()));
    random.as_mut_slice().zeroize();
    plaintext
}

/// Compute the keyed verifier for a canonical plaintext bearer.
#[cfg(test)]
pub fn session_bearer_verifier(
    session_token: &str,
    session: &SessionConfig,
) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
    let key = verifier_key(session)?;
    session_bearer_verifier_with_key(session_token, key)
}

fn session_bearer_verifier_with_key(
    session_token: &str,
    key: &[u8],
) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
    if !is_well_formed_session_bearer(session_token) {
        return Err(SessionCredentialError::MalformedBearer);
    }
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of every length");
    mac.update(SESSION_VERIFIER_DOMAIN);
    mac.update(session_token.as_bytes());
    let output = mac.finalize().into_bytes();
    let mut verifier = [0_u8; SESSION_VERIFIER_LEN];
    verifier.copy_from_slice(&output);
    Ok(verifier)
}

#[cfg(test)]
pub fn issue_session_credential(
    session: &SessionConfig,
) -> Result<IssuedSessionCredential, SessionCredentialError> {
    let plaintext = generate_session_bearer();
    let verifier = session_bearer_verifier(plaintext.as_str(), session)?;
    Ok(IssuedSessionCredential {
        plaintext,
        verifier,
    })
}

fn update_length_prefixed(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

/// Computes the keyed authorization digest for a configured local account
/// without exposing its password outside `ryuki-core`.
#[cfg(test)]
pub fn local_identity_authority_digest(
    user: &LocalAuthUser,
    session: &SessionConfig,
) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
    let key = verifier_key(session)?;
    Ok(user.session_authority_digest(key))
}

/// Computes a provider-neutral authorization digest for a validated external
/// identity assertion. The digest binds the provider namespace, canonical
/// issuer, stable subject, and effective role set; display names and email
/// addresses are deliberately excluded because they are not identity keys.
#[cfg(test)]
pub fn identity_authority_digest(
    provider: &str,
    issuer: &str,
    subject: &str,
    roles: &[String],
    session: &SessionConfig,
) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
    identity_authority_digest_with_key(provider, issuer, subject, roles, verifier_key(session)?)
}

fn identity_authority_digest_with_key(
    provider: &str,
    issuer: &str,
    subject: &str,
    roles: &[String],
    key: &[u8],
) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of every length");
    mac.update(IDENTITY_AUTHORITY_DOMAIN);
    update_length_prefixed(&mut mac, provider.as_bytes());
    update_length_prefixed(&mut mac, issuer.as_bytes());
    update_length_prefixed(&mut mac, subject.as_bytes());

    let mut roles: Vec<&str> = roles.iter().map(String::as_str).collect();
    roles.sort_unstable();
    roles.dedup();
    mac.update(&(roles.len() as u64).to_be_bytes());
    for role in roles {
        update_length_prefixed(&mut mac, role.as_bytes());
    }

    Ok(mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(key_byte: u8) -> SessionConfig {
        SessionConfig {
            credential_hmac_key: char::from(key_byte).to_string().repeat(32),
            ..Default::default()
        }
    }

    #[test]
    fn generated_bearers_have_exact_canonical_shape_and_are_unique() {
        let first = generate_session_bearer();
        let second = generate_session_bearer();
        assert_eq!(first.len(), SESSION_BEARER_LEN);
        assert!(is_well_formed_session_bearer(first.as_str()));
        assert!(is_well_formed_session_bearer(second.as_str()));
        assert_ne!(first.as_str(), second.as_str());
    }

    #[test]
    fn bearer_shape_rejects_management_ids_padding_and_noncanonical_base64url() {
        for malformed in [
            "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b",
            "rys_",
            "rys_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "rys_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
            "rys_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        ] {
            assert!(
                !is_well_formed_session_bearer(malformed),
                "{malformed} must be rejected"
            );
        }
    }

    #[test]
    fn verifier_is_stable_keyed_and_fixed_width() {
        let session_token = generate_session_bearer();
        let first = session_bearer_verifier(session_token.as_str(), &config(b'a')).unwrap();
        let again = session_bearer_verifier(session_token.as_str(), &config(b'a')).unwrap();
        let other_key = session_bearer_verifier(session_token.as_str(), &config(b'b')).unwrap();
        assert_eq!(first.len(), SESSION_VERIFIER_LEN);
        assert_eq!(first, again);
        assert_ne!(first, other_key);
    }

    #[test]
    fn missing_short_and_malformed_keys_fail_closed() {
        let session_token = generate_session_bearer();
        let missing = SessionConfig::default();
        assert_eq!(
            session_bearer_verifier(session_token.as_str(), &missing),
            Err(SessionCredentialError::MissingVerifierKey)
        );

        let short = SessionConfig {
            credential_hmac_key: "x".repeat(31),
            ..Default::default()
        };
        assert_eq!(
            session_bearer_verifier(session_token.as_str(), &short),
            Err(SessionCredentialError::VerifierKeyTooShort)
        );

        let malformed = SessionConfig {
            credential_hmac_key: format!("{}\n", "x".repeat(32)),
            ..Default::default()
        };
        assert_eq!(
            session_bearer_verifier(session_token.as_str(), &malformed),
            Err(SessionCredentialError::MalformedVerifierKey)
        );
    }

    #[test]
    fn issued_credential_debug_output_is_redacted() {
        let credential = issue_session_credential(&config(b'k')).unwrap();
        let rendered = format!("{credential:?}");
        assert!(!rendered.contains(credential.bearer()));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn retained_runtime_issues_verifies_and_measures_exact_policy() {
        let mut session = config(b'k');
        session.cookie_max_age_secs = 600;
        session.federated_authority_max_staleness_secs = 300;
        let runtime = DerivedSessionCredentialRuntime::from_admitted_config(&session).unwrap();
        let credential = runtime.issue().unwrap();

        assert_eq!(
            runtime.verifier(credential.bearer()).unwrap(),
            *credential.verifier()
        );
        assert_eq!(runtime.maximum_session_age_seconds(), 600);
        assert_eq!(runtime.federated_authority_max_staleness_seconds(), 300);

        let observation = runtime.runtime_observation();
        assert!(observation.enabled());
        assert_eq!(observation.maximum_session_age_seconds(), 600);
        assert_eq!(observation.federated_authority_max_staleness_seconds(), 300);
        assert!(observation
            .key_identity_binding_digest()
            .is_some_and(|digest| digest.starts_with("sha256:")));
        assert_eq!(
            observation.credential_format_id(),
            "session-credential:opaque-random-v1"
        );
        assert_eq!(observation.verifier_algorithm_id(), "hmac-sha256");
        assert_eq!(observation.credential_random_bytes(), 32);
        assert_eq!(
            observation.database_representation_id(),
            "session-verifier:keyed-digest-only-v1"
        );
    }

    #[test]
    fn retained_runtime_rejects_disabled_credential_operations_and_substitution() {
        let disabled =
            DerivedSessionCredentialRuntime::from_admitted_config(&SessionConfig::default())
                .unwrap();
        assert!(!disabled.enabled());
        assert_eq!(
            disabled.issue().unwrap_err(),
            SessionCredentialError::MissingVerifierKey
        );
        assert!(disabled
            .runtime_observation()
            .key_identity_binding_digest()
            .is_none());

        let first = DerivedSessionCredentialRuntime::from_admitted_config(&config(b'a')).unwrap();
        let second = DerivedSessionCredentialRuntime::from_admitted_config(&config(b'b')).unwrap();
        let issued = first.issue().unwrap();
        assert_ne!(
            first.runtime_observation(),
            second.runtime_observation(),
            "a lookalike runtime with another key must measure differently"
        );
        assert_ne!(
            first.verifier(issued.bearer()).unwrap(),
            second.verifier(issued.bearer()).unwrap()
        );

        let rendered = format!("{first:?}");
        assert!(!rendered.contains(&"a".repeat(32)));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn retained_runtime_rejects_invalid_lifetimes() {
        let mut invalid = config(b'k');
        invalid.cookie_max_age_secs = 0;
        assert!(matches!(
            DerivedSessionCredentialRuntime::from_admitted_config(&invalid),
            Err(SessionCredentialError::InvalidMaximumAge)
        ));

        let mut invalid = config(b'k');
        invalid.federated_authority_max_staleness_secs = 0;
        assert!(matches!(
            DerivedSessionCredentialRuntime::from_admitted_config(&invalid),
            Err(SessionCredentialError::InvalidFederatedAuthorityStaleness)
        ));
    }

    #[test]
    fn identity_authority_digest_is_namespaced_and_role_order_independent() {
        let session = config(b'k');
        let roles = vec!["PlatformAdmin".to_string(), "Auditor".to_string()];
        let reversed = vec!["Auditor".to_string(), "PlatformAdmin".to_string()];
        let baseline = identity_authority_digest(
            "oidc",
            "https://identity.example.test",
            "subject-1",
            &roles,
            &session,
        )
        .unwrap();

        assert_eq!(
            baseline,
            identity_authority_digest(
                "oidc",
                "https://identity.example.test",
                "subject-1",
                &reversed,
                &session,
            )
            .unwrap()
        );
        assert_ne!(
            baseline,
            identity_authority_digest(
                "oidc",
                "https://other-identity.example.test",
                "subject-1",
                &roles,
                &session,
            )
            .unwrap()
        );
        assert_ne!(
            baseline,
            identity_authority_digest(
                "oidc",
                "https://identity.example.test",
                "subject-1",
                &["Auditor".to_string()],
                &session,
            )
            .unwrap()
        );
    }

    #[test]
    fn migration_invalidates_legacy_rows_and_fences_old_binaries() {
        let migration = include_str!("../../../migrations/159_session_bearer_verifiers.sql");
        let delete = migration.find("DELETE FROM sessions").unwrap();
        let rename = migration
            .find("RENAME COLUMN id TO session_record_id")
            .unwrap();
        let verifier = migration.find("bearer_verifier BYTEA NOT NULL").unwrap();
        assert!(delete < rename && rename < verifier);
        assert!(migration.contains("CHECK (octet_length(bearer_verifier) = 32)"));
        assert!(migration.contains("CREATE UNIQUE INDEX sessions_bearer_verifier_uidx"));
        assert!(
            !migration.contains("bearer_verifier BYTEA NOT NULL DEFAULT"),
            "old writers must fail instead of inheriting a verifier default"
        );
    }
}
