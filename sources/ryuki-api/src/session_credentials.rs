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
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use ryuki_core::config::{LocalAuthUser, SessionConfig};

pub const SESSION_BEARER_PREFIX: &str = "rys_";
const SESSION_BEARER_RANDOM_BYTES: usize = 32;
const SESSION_BEARER_PAYLOAD_LEN: usize = 43;
pub const SESSION_BEARER_LEN: usize = SESSION_BEARER_PREFIX.len() + SESSION_BEARER_PAYLOAD_LEN;
const SESSION_VERIFIER_DOMAIN: &[u8] = b"ryuki/session-bearer/verifier/v1\0";
const IDENTITY_AUTHORITY_DOMAIN: &[u8] = b"ryuki/identity-authority/v1\0";
pub const SESSION_VERIFIER_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCredentialError {
    MissingVerifierKey,
    VerifierKeyTooShort,
    MalformedVerifierKey,
    MalformedBearer,
}

impl std::fmt::Display for SessionCredentialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MissingVerifierKey => "session credential verifier key is not configured",
            Self::VerifierKeyTooShort => "session credential verifier key is too short",
            Self::MalformedVerifierKey => "session credential verifier key is malformed",
            Self::MalformedBearer => "session bearer is malformed",
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
pub fn session_bearer_verifier(
    session_token: &str,
    session: &SessionConfig,
) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
    if !is_well_formed_session_bearer(session_token) {
        return Err(SessionCredentialError::MalformedBearer);
    }
    let key = verifier_key(session)?;
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of every length");
    mac.update(SESSION_VERIFIER_DOMAIN);
    mac.update(session_token.as_bytes());
    let output = mac.finalize().into_bytes();
    let mut verifier = [0_u8; SESSION_VERIFIER_LEN];
    verifier.copy_from_slice(&output);
    Ok(verifier)
}

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
pub fn identity_authority_digest(
    provider: &str,
    issuer: &str,
    subject: &str,
    roles: &[String],
    session: &SessionConfig,
) -> Result<[u8; SESSION_VERIFIER_LEN], SessionCredentialError> {
    let key = verifier_key(session)?;
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
