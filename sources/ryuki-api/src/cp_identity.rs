//! Control-plane Ed25519 identity — key generation, persistence, and process-global state.
//!
//! The CP's signing key is used to produce [`VerifiedLiveContext`] grants that authorise
//! `LiveApply` jobs. Agents verify each grant against the CP public key before executing a
//! mutating apply.
//!
//! ## Persistence format
//!
//! The 32-byte raw Ed25519 secret seed (`SigningKey::to_bytes()`) is written **as-is** (binary)
//! to the key file, create-only at mode **0600**. This mirrors the pattern used in
//! `ryuki-agent`'s `identity.rs`; see that module for the rationale (no base64, owner-only,
//! atomic create).
//!
//! ## Process global
//!
//! `init_cp_key` / `cp_signing_key` / `cp_public_key_b64` mirror the `database` module's
//! `OnceLock` pattern so that:
//! - The key is loaded exactly once at startup and cached forever.
//! - Handlers call `cp_signing_key()` / `cp_public_key_b64()` without any runtime I/O.
//! - Tests that exercise DB behaviour pass the `SigningKey` explicitly to
//!   `create_live_apply_job` and do not rely on the global lock (the OnceLock is not
//!   idempotent-settable under `cargo test`'s parallel runner).

use std::path::Path;
use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use thiserror::Error;

use ryuki_protocol::{encode_verifying_key, generate_keypair};

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

static CP_KEY: OnceLock<SigningKey> = OnceLock::new();

/// Store the loaded key in the process global.  Must be called once at startup,
/// before any handler accesses `cp_signing_key()`.
///
/// Safe to call more than once if the value is identical (OnceLock ignores the
/// second call); if a genuinely different key is supplied on a re-call the
/// second value is silently dropped — the first write wins.  In production
/// `init_cp_key` is called once; the multi-call path only arises in tests.
pub fn init_cp_key(key: SigningKey) {
    // OnceLock::set returns Err(value) if already set; we discard it intentionally.
    let _ = CP_KEY.set(key);
}

/// Access the process-global signing key.  Returns `None` if `init_cp_key` has
/// not been called (e.g. during unit tests that do not exercise the pubkey endpoint).
pub fn cp_signing_key() -> Option<&'static SigningKey> {
    CP_KEY.get()
}

/// Base64-encoded compressed Ed25519 public key for the CP's signing key.
/// Returns `None` if the key has not been initialised.
pub fn cp_public_key_b64() -> Option<String> {
    cp_signing_key().map(|k| encode_verifying_key(&k.verifying_key()))
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
    // Same as init_cp_key — OnceLock drops duplicates silently.
    let _ = CP_KEY.set(key);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ryuki_protocol::{crypto::verify_vlc, VerifiedLiveContext};
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

        // Write 10 bytes — too short.
        std::fs::write(&path, [0u8; 10]).expect("write");
        let result = load_or_generate_cp_key(&path);
        assert!(
            matches!(result, Err(CpKeyError::BadLength { got: 10, .. })),
            "short file must return BadLength"
        );

        // Overwrite with 64 bytes — too long.
        std::fs::write(&path, [7u8; 64]).expect("write");
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
            signature: String::new(),
        };
        let signed = sign_vlc(unsigned, &key);
        assert!(
            verify_vlc(&signed, &vk).is_ok(),
            "VLC signed with the loaded CP key must verify"
        );
    }
}
