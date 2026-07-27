//! Control-plane Ed25519 grant keyring.
//!
//! The CP's signing key is used to produce [`VerifiedLiveContext`] grants that authorise
//! `LiveApply` jobs. Agents verify each grant against the CP public key before executing a
//! mutating apply.
//!
//! ## Development persistence compatibility
//!
//! The 32-byte raw Ed25519 secret seed (`SigningKey::to_bytes()`) is written **as-is** (binary)
//! to the key file, create-only at mode **0600**. This mirrors the pattern used in
//! `ryuki-agent`'s `identity.rs`; see that module for the rationale (no base64, owner-only,
//! atomic create).
//!
//! Production admission must inject externally resolved, version-pinned key
//! material. The local load-or-generate path remains a development compatibility
//! seam and is not evidence for `ExternalSigningKeyMaterial`.
//!
//! ## Process global
//!
//! `init_cp_key` / `cp_signing_key` / `cp_public_keyset` mirror the `database` module's
//! `OnceLock` pattern so that:
//! - The key is loaded exactly once at startup and cached forever.
//! - Handlers call `cp_signing_key()` / `cp_public_keyset()` without any runtime I/O.
//! - Tests that exercise DB behaviour pass the `SigningKey` explicitly to
//!   `create_live_apply_job` and do not rely on the global lock (the OnceLock is not
//!   idempotent-settable under `cargo test`'s parallel runner).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;

use ryuki_protocol::{
    control_plane_grant_key_id, control_plane_grant_verifying_key, generate_keypair,
    validate_control_plane_grant_keyset, verify_vlc_with_keyset, ControlPlaneGrantKeyDisposition,
    ControlPlaneGrantKeyset, VerifyError,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum CpKeyError {
    #[error("I/O error for CP key file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("CP key file at {path} has wrong length (got {got} bytes, expected exactly 32)")]
    BadLength { path: String, got: usize },
    #[error("invalid CP signing keyring: {0}")]
    InvalidKeyring(String),
}

/// Stable result categories for grant verification at the HTTP boundary.
/// `Display` is deliberately value-free so request-controlled grant material is
/// never reflected into logs or response bodies.
#[derive(Debug, Error)]
pub(crate) enum CpGrantVerificationError {
    #[error("CP signing keyring is unavailable")]
    Unavailable,
    #[error("CP grant verification failed")]
    Invalid(#[source] VerifyError),
}

// ---------------------------------------------------------------------------
// Load-or-generate
// ---------------------------------------------------------------------------

/// Load the CP Ed25519 signing key from `path` if it exists, or generate a
/// fresh one and persist it create-only at mode **0600**.
///
/// ## Atomicity
///
/// On first boot the file does not exist: `generate_keypair` is called, then the
/// 32-byte seed is written with `create_new(true)` + `mode(0600)`. The `create_new`
/// flag causes the `open` syscall to fail if another process (or a race) already
/// created the file — in that case we return an `Io` error rather than silently
/// clobber the existing key. Key rotation is an explicit operator action; it is
/// never triggered by a startup race.
///
/// On subsequent boots the file exists: it is read, length-checked (must be
/// exactly 32 bytes), and reconstructed into a `SigningKey`.
pub fn load_or_generate_cp_key(path: &Path) -> Result<SigningKey, CpKeyError> {
    let path_str = path.display().to_string();

    if path.exists() {
        // Load the existing key.
        let bytes = std::fs::read(path).map_err(|e| CpKeyError::Io {
            path: path_str.clone(),
            source: e,
        })?;

        if bytes.len() != 32 {
            return Err(CpKeyError::BadLength {
                path: path_str,
                got: bytes.len(),
            });
        }

        let seed: [u8; 32] = bytes[..32]
            .try_into()
            .expect("slice of exactly 32 bytes always converts");
        return Ok(SigningKey::from_bytes(&seed));
    }

    // Generate a fresh key and persist it atomically, create-only.
    let key = generate_keypair(&mut OsRng);
    let bytes = key.to_bytes(); // [u8; 32]

    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| CpKeyError::Io {
        path: path_str.clone(),
        source: e,
    })?;
    file.write_all(&bytes).map_err(|e| CpKeyError::Io {
        path: path_str,
        source: e,
    })?;

    Ok(key)
}

// ---------------------------------------------------------------------------
// Process-global cached key
//
// Mirrors `database::POOL` (OnceLock<Option<…>>).  The Option encodes
// "key not yet initialised" (None) so that handlers can return 503 rather than
// panicking when the global is absent — which only happens in unit tests that
// do not call `init_cp_key`.
// ---------------------------------------------------------------------------

/// Bounded active/verify-only grant keyring. Private material exists only for
/// the one active member; overlap keys retain public material only.
pub(crate) struct CpSigningKeyring {
    keyset: ControlPlaneGrantKeyset,
    active_signing_key: SigningKey,
    verifying_keys: BTreeMap<String, VerifyingKey>,
}

impl std::fmt::Debug for CpSigningKeyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CpSigningKeyring")
            .field("keyset_version", &self.keyset.keyset_version)
            .field("active_key_id", &self.keyset.active_key_id)
            .field("key_count", &self.keyset.keys.len())
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl CpSigningKeyring {
    pub(crate) fn new(
        keyset_version: u64,
        active_signing_key: SigningKey,
        verify_only_keys: impl IntoIterator<Item = VerifyingKey>,
    ) -> Result<Self, CpKeyError> {
        let active_verifying_key = active_signing_key.verifying_key();
        let active_key_id = control_plane_grant_key_id(&active_verifying_key);
        let mut verifying_keys = BTreeMap::new();
        verifying_keys.insert(active_key_id.clone(), active_verifying_key);
        for verifying_key in verify_only_keys {
            let key_id = control_plane_grant_key_id(&verifying_key);
            if verifying_keys.insert(key_id, verifying_key).is_some() {
                return Err(CpKeyError::InvalidKeyring(
                    "duplicate active or verify-only public key".to_string(),
                ));
            }
        }
        let keys = verifying_keys
            .iter()
            .map(|(key_id, verifying_key)| {
                let disposition = if key_id == &active_key_id {
                    ControlPlaneGrantKeyDisposition::Active
                } else {
                    ControlPlaneGrantKeyDisposition::VerifyOnly
                };
                control_plane_grant_verifying_key(verifying_key, disposition)
            })
            .collect();
        let keyset = ControlPlaneGrantKeyset {
            keyset_version,
            active_key_id,
            keys,
        };
        validate_control_plane_grant_keyset(&keyset)
            .map_err(|error| CpKeyError::InvalidKeyring(error.to_string()))?;
        Ok(Self {
            keyset,
            active_signing_key,
            verifying_keys,
        })
    }

    pub(crate) fn public_keyset(&self) -> ControlPlaneGrantKeyset {
        self.keyset.clone()
    }

    pub(crate) fn active_signing_key(&self) -> &SigningKey {
        &self.active_signing_key
    }

    pub(crate) fn verify_grant(
        &self,
        grant: &ryuki_protocol::VerifiedLiveContext,
    ) -> Result<(), ryuki_protocol::VerifyError> {
        if !self.verifying_keys.contains_key(&grant.signing_key_id) {
            return Err(ryuki_protocol::VerifyError::UnknownControlPlaneGrantKey);
        }
        verify_vlc_with_keyset(grant, &self.keyset)
    }
}

static CP_KEYRING: OnceLock<CpSigningKeyring> = OnceLock::new();

fn install_cp_keyring(
    lock: &OnceLock<CpSigningKeyring>,
    keyring: CpSigningKeyring,
) -> Result<(), CpKeyError> {
    match lock.set(keyring) {
        Ok(()) => Ok(()),
        Err(candidate) => {
            let existing = lock
                .get()
                .expect("OnceLock contains the winning keyring after set fails");
            if existing.keyset == candidate.keyset
                && existing.active_signing_key.to_bytes() == candidate.active_signing_key.to_bytes()
            {
                Ok(())
            } else {
                Err(CpKeyError::InvalidKeyring(
                    "a different keyring is already initialized".to_string(),
                ))
            }
        }
    }
}

/// Store the loaded key in the process global.  Must be called once at startup,
/// before any handler accesses `cp_signing_key()`.
///
/// Safe to call more than once only when the complete value is identical. A
/// different re-initialization is an explicit error rather than a silently
/// discarded configuration change.
pub fn init_cp_key(key: SigningKey) -> Result<(), CpKeyError> {
    let keyring = CpSigningKeyring::new(1, key, std::iter::empty())
        .expect("one valid Ed25519 key always forms a valid CP keyring");
    init_cp_keyring(keyring)
}

/// Install an already resolved versioned keyring. Production will call this
/// only after the external-signing runtime guard has admitted the exact Vault
/// material and inventory; this foundation does not itself perform admission.
pub(crate) fn init_cp_keyring(keyring: CpSigningKeyring) -> Result<(), CpKeyError> {
    install_cp_keyring(&CP_KEYRING, keyring)
}

/// Access the process-global signing key.  Returns `None` if `init_cp_key` has
/// not been called (e.g. during unit tests that do not exercise the pubkey endpoint).
pub fn cp_signing_key() -> Option<&'static SigningKey> {
    CP_KEYRING.get().map(CpSigningKeyring::active_signing_key)
}

/// Versioned active/verify-only public keyset exposed to agents.
pub(crate) fn cp_public_keyset() -> Option<ControlPlaneGrantKeyset> {
    CP_KEYRING.get().map(CpSigningKeyring::public_keyset)
}

/// Verify a stored grant against the exact retained keyring. A key removed by
/// revocation is absent and therefore rejected as an unknown `kid`.
pub(crate) fn verify_cp_grant(
    grant: &ryuki_protocol::VerifiedLiveContext,
) -> Result<(), CpGrantVerificationError> {
    let keyring = CP_KEYRING
        .get()
        .ok_or(CpGrantVerificationError::Unavailable)?;
    keyring
        .verify_grant(grant)
        .map_err(CpGrantVerificationError::Invalid)
}

// ---------------------------------------------------------------------------
// Test-only helpers
// ---------------------------------------------------------------------------

/// Initialise the process global with an arbitrary key for tests that exercise
/// the pubkey HTTP endpoint.  The OnceLock's single-write semantic means only
/// the FIRST call in the process takes effect; design tests that need the
/// global to be set before any other test that calls `init_cp_key` in the same
/// binary, or accept that the stored value may already be set.
#[cfg(test)]
pub fn init_cp_key_for_test(key: SigningKey) {
    // The global is shared across parallel tests; fixtures intentionally keep
    // first-write semantics while production callers handle re-init errors.
    let _ = init_cp_key(key);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ryuki_protocol::{crypto::verify_vlc, encode_verifying_key, VerifiedLiveContext};
    use tempfile::TempDir;

    fn tmp_key_path(dir: &TempDir) -> std::path::PathBuf {
        dir.path().join("cp.key")
    }

    // ── generate → persist → load roundtrip yields the same public key ────────

    #[test]
    fn generate_persist_load_same_pubkey() {
        let dir = TempDir::new().expect("tempdir");
        let path = tmp_key_path(&dir);

        // First call generates and persists.
        let generated = load_or_generate_cp_key(&path).expect("generate");
        let generated_pub = encode_verifying_key(&generated.verifying_key());

        // Second call loads from disk.
        let loaded = load_or_generate_cp_key(&path).expect("load");
        let loaded_pub = encode_verifying_key(&loaded.verifying_key());

        assert_eq!(
            generated_pub, loaded_pub,
            "loaded key must reproduce the same public key"
        );
    }

    // ── saved file must be mode 0600 ─────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn saved_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("tempdir");
        let path = tmp_key_path(&dir);

        load_or_generate_cp_key(&path).expect("generate");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "CP key file must be mode 0600");
    }

    // ── load rejects a file with wrong length ─────────────────────────────────

    #[test]
    fn load_rejects_wrong_length() {
        let dir = TempDir::new().expect("tempdir");
        let path = tmp_key_path(&dir);

        // Write random bytes with an invalid length so the fixture cannot be
        // mistaken for embedded signing material by static analysis.
        let short_bytes = (0..10).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        std::fs::write(&path, short_bytes).expect("write");
        let result = load_or_generate_cp_key(&path);
        assert!(
            matches!(result, Err(CpKeyError::BadLength { got: 10, .. })),
            "short file must return BadLength"
        );

        // Overwrite with random bytes that are too long.
        let long_bytes = (0..64).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        std::fs::write(&path, long_bytes).expect("write");
        let result = load_or_generate_cp_key(&path);
        assert!(
            matches!(result, Err(CpKeyError::BadLength { got: 64, .. })),
            "oversized file must return BadLength"
        );
    }

    // ── sign_vlc with the loaded key verifies with its public key ────────────

    #[test]
    fn loaded_key_can_sign_and_verify_vlc() {
        use chrono::Utc;
        use ryuki_protocol::crypto::sign_vlc;
        use uuid::Uuid;

        let dir = TempDir::new().expect("tempdir");
        let path = tmp_key_path(&dir);

        let key = load_or_generate_cp_key(&path).expect("generate");
        let vk = key.verifying_key();

        let unsigned = VerifiedLiveContext {
            request_id: Uuid::new_v4(),
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("test resource version is positive"),
            platform: "defra".to_string(),
            job_spec_digest: ryuki_protocol::sha256_hex(b"job-spec"),
            approved_plan_digest: "abc123".to_string(),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-test".to_string(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            step_job_id: None,
            execution_authority: ryuki_protocol::LiveExecutionAuthority {
                assigned_agent_id: "agent-test".to_string(),
                assigned_agent_enrollment_id: Uuid::nil(),
                assigned_agent_key_fingerprint: "sha256:test".to_string(),
                execution_trust_profile_digest: ryuki_protocol::sha256_hex(b"profile"),
            },
            signing_key_id: String::new(),
            signature: String::new(),
        };
        let signed = sign_vlc(unsigned, &key);
        assert!(
            verify_vlc(&signed, &vk).is_ok(),
            "VLC signed with the loaded CP key must verify"
        );
    }

    fn unsigned_test_grant() -> VerifiedLiveContext {
        use chrono::Utc;
        use uuid::Uuid;

        VerifiedLiveContext {
            request_id: Uuid::new_v4(),
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("test resource version is positive"),
            platform: "defra".to_string(),
            job_spec_digest: ryuki_protocol::sha256_hex(Uuid::new_v4().as_bytes()),
            approved_plan_digest: ryuki_protocol::sha256_hex(Uuid::new_v4().as_bytes()),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-test".to_string(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            step_job_id: None,
            execution_authority: ryuki_protocol::LiveExecutionAuthority {
                assigned_agent_id: "agent-test".to_string(),
                assigned_agent_enrollment_id: Uuid::new_v4(),
                assigned_agent_key_fingerprint: format!("sha256:{}", Uuid::new_v4().simple()),
                execution_trust_profile_digest: ryuki_protocol::sha256_hex(
                    Uuid::new_v4().as_bytes(),
                ),
            },
            signing_key_id: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn keyring_rotation_overlap_revocation_and_debug_output_are_safe() {
        use ryuki_protocol::{sign_vlc, ControlPlaneGrantKeyDisposition, VerifyError};

        let old = generate_keypair(&mut OsRng);
        let active = generate_keypair(&mut OsRng);
        let active_seed_debug = format!("{:?}", active.to_bytes());
        let old_grant = sign_vlc(unsigned_test_grant(), &old);
        let active_grant = sign_vlc(unsigned_test_grant(), &active);

        let overlap = CpSigningKeyring::new(2, active.clone(), [old.verifying_key()])
            .expect("one active and one verify-only key form a valid overlap keyring");
        let keyset = overlap.public_keyset();
        validate_control_plane_grant_keyset(&keyset).expect("published keyset is canonical");
        assert!(keyset
            .keys
            .windows(2)
            .all(|pair| pair[0].key_id < pair[1].key_id));
        assert_eq!(
            keyset
                .keys
                .iter()
                .filter(|key| key.disposition == ControlPlaneGrantKeyDisposition::Active)
                .count(),
            1
        );
        assert_eq!(
            keyset
                .keys
                .iter()
                .filter(|key| key.disposition == ControlPlaneGrantKeyDisposition::VerifyOnly)
                .count(),
            1
        );
        overlap
            .verify_grant(&old_grant)
            .expect("verify-only overlap key verifies an existing grant");
        overlap
            .verify_grant(&active_grant)
            .expect("active key verifies a newly issued grant");

        let debug = format!("{overlap:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&active_seed_debug));

        let revoked = CpSigningKeyring::new(3, active, std::iter::empty())
            .expect("active-only keyring is valid after overlap revocation");
        let error = revoked
            .verify_grant(&old_grant)
            .expect_err("a removed key id must fail closed");
        assert!(matches!(error, VerifyError::UnknownControlPlaneGrantKey));
        assert!(!error.to_string().contains(&old_grant.signing_key_id));
    }

    #[test]
    fn keyring_install_is_idempotent_only_for_the_exact_same_value() {
        let lock = OnceLock::new();
        let first = generate_keypair(&mut OsRng);
        let same = first.clone();
        install_cp_keyring(
            &lock,
            CpSigningKeyring::new(1, first, std::iter::empty()).expect("initial keyring is valid"),
        )
        .expect("first initialization succeeds");
        install_cp_keyring(
            &lock,
            CpSigningKeyring::new(1, same, std::iter::empty()).expect("identical keyring is valid"),
        )
        .expect("an exact repeat is idempotent");

        let different = CpSigningKeyring::new(2, generate_keypair(&mut OsRng), std::iter::empty())
            .expect("different keyring is structurally valid");
        let error = install_cp_keyring(&lock, different)
            .expect_err("a different re-initialization must fail closed");
        assert!(matches!(&error, CpKeyError::InvalidKeyring(_)));
        assert_eq!(
            error.to_string(),
            "invalid CP signing keyring: a different keyring is already initialized"
        );
    }
}
