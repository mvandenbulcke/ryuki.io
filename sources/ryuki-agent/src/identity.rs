//! Agent Ed25519 identity — key generation, persistence, and public-key encoding.
//!
//! ## Persistence format
//!
//! The 32-byte raw secret seed (`SigningKey::to_bytes()`) is written **as-is** (binary)
//! to the key file.  Raw bytes were chosen over base64 because:
//! - No extra dependency / decode step.
//! - The file is always 0600 (owner-only); no human ever reads it manually.
//!
//! File permissions: **0600** (owner read/write only; group/other get nothing).
//! The save implementation writes the bytes first, then sets permissions atomically
//! on the same path — same pattern as `ryuki-runner`'s `write_file_0600`.
//!
//! ## key_id derivation
//!
//! `key_id` = `ryuki_protocol::encode_verifying_key(&signing_key.verifying_key())`
//! = standard base64 (STANDARD engine) of the 32-byte compressed public key point.
//! This is BOTH:
//! - The `public_key` field in `AgentRegistration` (sent to the CP on enroll).
//! - The `key_id` field in every `SignedEnvelope` (lets the CP look up the enrolled key).

use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use thiserror::Error;

use ryuki_protocol::{encode_verifying_key, generate_keypair};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("I/O error for key file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("key file at {path} has wrong length (got {got} bytes, expected exactly 32)")]
    BadLength { path: String, got: usize },
    #[allow(dead_code)] // reserved for future ed25519_dalek::SigningKey::from_bytes error path
    #[error("ed25519 key material is invalid: {0}")]
    KeyMaterial(String),
}

// ---------------------------------------------------------------------------
// AgentIdentity
// ---------------------------------------------------------------------------

/// Holds the agent's Ed25519 signing key.
///
/// The private key is held in memory only for the lifetime of this struct.
/// It is never logged or serialised as part of any struct that leaves the process.
pub struct AgentIdentity {
    signing_key: SigningKey,
}

impl AgentIdentity {
    // ------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------

    /// Generate a fresh random Ed25519 identity using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = generate_keypair(&mut rng);
        Self { signing_key }
    }

    /// Construct directly from an existing `SigningKey` (test helper).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    /// Persist the 32-byte secret seed to a NEW file at `path`, mode **0600**.
    ///
    /// `save` is **create-only**: it uses `create_new`, so it refuses to
    /// overwrite an existing key (an `AlreadyExists` I/O error). This eliminates
    /// the overwrite secret-exposure window entirely — on Unix the file is
    /// created with 0600 atomically in a single `open` (via `OpenOptionsExt::mode`),
    /// so the seed is never momentarily world-readable. The signing key is the
    /// root of the whole result-signing trust model, so a brief 0644 window on a
    /// shared host would be a real key-exposure bug. Key ROTATION is a separate,
    /// explicit operation (S5) — never a silent overwrite here.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        let bytes = self.signing_key.to_bytes(); // [u8; 32]
        let path_str = path.display().to_string();

        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path).map_err(|e| IdentityError::Io {
            path: path_str.clone(),
            source: e,
        })?;
        file.write_all(&bytes).map_err(|e| IdentityError::Io {
            path: path_str,
            source: e,
        })?;

        Ok(())
    }

    /// Load a previously-saved identity from `path`.
    ///
    /// Reads exactly 32 bytes (the raw secret seed) and reconstructs the key.
    /// Returns an error if the file is missing, unreadable, or the wrong length.
    ///
    /// Permission enforcement: we do NOT check current perms and reject (that would
    /// be a TOCTOU anyway).  We simply read the file; if the OS denies access, the
    /// Io error propagates naturally.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let path_str = path.display().to_string();
        let bytes = std::fs::read(path).map_err(|e| IdentityError::Io {
            path: path_str.clone(),
            source: e,
        })?;

        // Must be EXACTLY 32 bytes. A longer file would otherwise silently use
        // its first 32 bytes as the seed, yielding a different key than intended.
        if bytes.len() != 32 {
            return Err(IdentityError::BadLength {
                path: path_str,
                got: bytes.len(),
            });
        }

        let seed: [u8; 32] = bytes[..32]
            .try_into()
            .expect("slice of exactly 32 bytes always converts");

        let signing_key = SigningKey::from_bytes(&seed);

        Ok(Self { signing_key })
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Base64-encoded compressed Ed25519 public key.
    ///
    /// Used as:
    /// - `AgentRegistration::public_key` (sent to the CP at enroll time).
    /// - `SignedEnvelope::key_id` (lets the CP look up the enrolled verifying key).
    pub fn public_key_b64(&self) -> String {
        encode_verifying_key(&self.signing_key.verifying_key())
    }

    /// Borrow the raw `SigningKey` — used to sign result envelopes.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_key_path(dir: &TempDir) -> std::path::PathBuf {
        dir.path().join("agent.key")
    }

    #[test]
    fn generate_save_load_same_public_key() {
        let dir = TempDir::new().expect("tempdir");
        let path = tmp_key_path(&dir);

        let original = AgentIdentity::generate();
        let original_pub = original.public_key_b64();

        original.save(&path).expect("save must succeed");
        let loaded = AgentIdentity::load(&path).expect("load must succeed");

        assert_eq!(
            original_pub,
            loaded.public_key_b64(),
            "loaded public key must match the saved one"
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("tempdir");
        let path = tmp_key_path(&dir);

        let id = AgentIdentity::generate();
        id.save(&path).expect("save");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        // Lower 9 bits only.
        assert_eq!(mode & 0o777, 0o600, "key file must be mode 0600");
    }

    #[test]
    fn load_corrupt_file_returns_error() {
        let dir = TempDir::new().expect("tempdir");
        let path = tmp_key_path(&dir);

        // Write only 10 bytes — too short to be a valid seed.
        std::fs::write(&path, [0u8; 10]).expect("write");

        let result = AgentIdentity::load(&path);
        assert!(
            matches!(result, Err(IdentityError::BadLength { .. })),
            "corrupt (short) file must return BadLength error"
        );
    }

    #[test]
    fn save_refuses_to_overwrite_existing_key() {
        let dir = TempDir::new().expect("tempdir");
        let path = tmp_key_path(&dir);

        AgentIdentity::generate().save(&path).expect("first save");
        // A second save to the same path must fail (create-only); the original
        // key must not be silently clobbered.
        let second = AgentIdentity::generate().save(&path);
        assert!(
            matches!(second, Err(IdentityError::Io { .. })),
            "save must refuse to overwrite an existing key file"
        );
    }

    #[test]
    fn load_oversized_file_returns_error() {
        let dir = TempDir::new().expect("tempdir");
        let path = tmp_key_path(&dir);

        // 64 bytes — too long; must be rejected, not silently truncated to 32.
        std::fs::write(&path, [7u8; 64]).expect("write");

        let result = AgentIdentity::load(&path);
        assert!(
            matches!(result, Err(IdentityError::BadLength { got: 64, .. })),
            "oversized file must return BadLength error, not load the first 32 bytes"
        );
    }

    #[test]
    fn load_missing_file_returns_io_error() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("nonexistent.key");

        let result = AgentIdentity::load(&path);
        assert!(
            matches!(result, Err(IdentityError::Io { .. })),
            "missing file must return Io error"
        );
    }

    #[test]
    fn public_key_b64_is_deterministic() {
        let dir = TempDir::new().expect("tempdir");
        let path = tmp_key_path(&dir);

        let id = AgentIdentity::generate();
        id.save(&path).expect("save");

        let loaded = AgentIdentity::load(&path).expect("load");
        // Calling public_key_b64 twice on the same key must give the same result.
        assert_eq!(loaded.public_key_b64(), loaded.public_key_b64());
    }
}
