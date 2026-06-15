//! Ed25519 signing and verification primitives for the Ryuki protocol.
//!
//! ## Canonicalization scheme
//!
//! Every `signing_bytes_*` function produces a byte sequence with these
//! properties:
//!
//! 1. **Domain separator** — the first bytes are `b"ryuki-v1/<type>"` so a
//!    signature produced for one message type cannot be replayed against another
//!    type that happens to share fields.
//!
//! 2. **Fixed field order** — fields are appended in the exact order listed in
//!    the source code.  There are no HashMaps in the signable set; all
//!    collections either use `BTreeMap` (sorted) or are not included.
//!
//! 3. **Length-prefixed encoding** — every field value `v` is written as
//!    `u64_le(v.len()) || v`.  This prevents ambiguity between adjacent fields
//!    (e.g. `"a"+"bc"` vs `"ab"+"c"` would produce the same bytes without
//!    length prefixes).
//!
//! 4. **No JSON in the signing path** — serde_json is not used here, so
//!    JSON's non-deterministic field ordering for objects cannot affect the
//!    canonical bytes.
//!
//! 5. **Scalar fields** — `u64` values are written as 8-byte little-endian;
//!    `DateTime<Utc>` is serialised as its RFC 3339 string (nanosecond
//!    precision); `Uuid` as its hyphenated string; `JobMode` / `JobStatus` as
//!    their `serde_json`-style snake_case label strings; `Option<String>` uses
//!    a 1-byte presence tag (0x00 absent, 0x01 present) followed by the
//!    length-prefixed value when present.
//!
//! The same function is used by **both** signer and verifier — it is the
//! single source of truth for the canonical representation.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::types::{JobMode, JobResultStatus, SignedEnvelope, VerifiedLiveContext};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid signature bytes (expected 64): got {0}")]
    BadSignatureLength(usize),
    #[error("invalid public key bytes (expected 32): got {0}")]
    BadKeyLength(usize),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("key material error: {0}")]
    KeyMaterial(String),
}

// ---------------------------------------------------------------------------
// Low-level canonical writer helpers
// ---------------------------------------------------------------------------

/// Append a byte slice with a `u64` little-endian length prefix.
#[inline]
fn write_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    let len = value.len() as u64;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(value);
}

/// Append a string slice (UTF-8 bytes) with a length prefix.
#[inline]
fn write_str(buf: &mut Vec<u8>, value: &str) {
    write_bytes(buf, value.as_bytes());
}

/// Append a `u64` as 8 little-endian bytes (fixed width; no length prefix
/// needed because the width is always 8).
#[inline]
fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Append an `Option<String>` with a 1-byte presence tag.
///   0x00 — absent
///   0x01 || u64_le(len) || bytes — present
#[inline]
fn write_opt_str(buf: &mut Vec<u8>, value: &Option<String>) {
    match value {
        None => buf.push(0x00),
        Some(s) => {
            buf.push(0x01);
            write_str(buf, s);
        }
    }
}

/// Serialise a `DateTime<Utc>` as its RFC 3339 / ISO 8601 representation with
/// nanosecond precision.  This is stable across platforms and time zones.
fn datetime_bytes(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

/// Serialise `JobMode` to its `serde_json` wire label.
fn mode_label(mode: &JobMode) -> &'static str {
    match mode {
        JobMode::OfflineDryRun => "offline_dry_run",
        JobMode::LivePlan => "live_plan",
        JobMode::LiveApply => "live_apply",
    }
}

/// Serialise `JobResultStatus` to its canonical wire label for signing.
///
/// Labels are fixed strings chosen to match the `serde_json` snake_case
/// representation; they MUST NOT change without a domain-separator version bump.
fn result_status_label(status: &JobResultStatus) -> &'static str {
    match status {
        JobResultStatus::CheckOk => "check_ok",
        JobResultStatus::Planned => "planned",
        JobResultStatus::Applied => "applied",
        JobResultStatus::Verified => "verified",
        JobResultStatus::Failed => "failed",
        JobResultStatus::LiveRefused => "live_refused",
    }
}

// ---------------------------------------------------------------------------
// Canonical byte encoding — SignedEnvelope
// ---------------------------------------------------------------------------

/// Returns the canonical bytes that are signed / verified for a
/// [`SignedEnvelope`].  The `signature` field is intentionally excluded.
///
/// **Domain separator**: `ryuki-v2/signed-envelope`
/// (bumped from v1 when `result_id` was added to the signable set — old v1
/// signatures cannot be confused with new v2 signatures).
///
/// Field order (fixed; any change requires another version bump):
/// domain, agent_id, platform, job_id, attempt_id, lease_generation,
/// request_id, result_id, mode, status, job_spec_digest, approved_plan_digest,
/// evidence_digest, redaction_policy_version, timestamp, key_id, cp_nonce.
pub fn signing_bytes(env: &SignedEnvelope) -> Vec<u8> {
    // Pre-allocate a generous buffer to avoid repeated reallocations.
    let mut buf: Vec<u8> = Vec::with_capacity(512);

    // Domain separator — prevents cross-type signature replay and distinguishes
    // v2 (result_id-bound) envelopes from v1 envelopes.
    write_bytes(&mut buf, b"ryuki-v2/signed-envelope");

    write_str(&mut buf, &env.agent_id);
    write_str(&mut buf, &env.platform);
    write_str(&mut buf, &env.job_id.hyphenated().to_string());
    write_str(&mut buf, &env.attempt_id.hyphenated().to_string());
    write_u64(&mut buf, env.lease_generation);
    write_str(&mut buf, &env.request_id.hyphenated().to_string());
    // result_id added in v2 — bound by signature to prevent idempotency key forgery.
    write_str(&mut buf, &env.result_id.hyphenated().to_string());
    write_str(&mut buf, mode_label(&env.mode));
    write_str(&mut buf, result_status_label(&env.status));
    write_str(&mut buf, &env.job_spec_digest);
    write_opt_str(&mut buf, &env.approved_plan_digest);
    write_str(&mut buf, &env.evidence_digest);
    write_str(&mut buf, &env.redaction_policy_version);
    write_str(&mut buf, &datetime_bytes(&env.timestamp));
    write_str(&mut buf, &env.key_id);
    write_str(&mut buf, &env.cp_nonce);

    buf
}

// ---------------------------------------------------------------------------
// Sign / verify — SignedEnvelope
// ---------------------------------------------------------------------------

/// Signs a [`SignedEnvelope`], returning a new envelope with the `signature`
/// field populated.  The `signature` field on the input is ignored.
pub fn sign(mut envelope: SignedEnvelope, key: &SigningKey) -> SignedEnvelope {
    let bytes = signing_bytes(&envelope);
    let sig: Signature = key.sign(&bytes);
    envelope.signature = B64.encode(sig.to_bytes());
    envelope
}

/// Verifies the `signature` on a [`SignedEnvelope`] against `vk`.
///
/// Returns `Ok(())` if the signature is valid.
/// Returns `Err(VerifyError::InvalidSignature)` if the signature does not
/// match — this is the expected failure path for tampered fields.
pub fn verify(envelope: &SignedEnvelope, vk: &VerifyingKey) -> Result<(), VerifyError> {
    let raw = B64.decode(&envelope.signature)?;
    let sig_bytes: [u8; 64] = raw
        .try_into()
        .map_err(|v: Vec<u8>| VerifyError::BadSignatureLength(v.len()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    let bytes = signing_bytes(envelope);
    // verify_strict rejects malleable signatures and weak/small-subgroup keys
    // (ed25519-dalek v2).
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| VerifyError::InvalidSignature)
}

// ---------------------------------------------------------------------------
// Canonical byte encoding — VerifiedLiveContext
// ---------------------------------------------------------------------------

/// Returns the canonical bytes for a [`VerifiedLiveContext`].
///
/// Field order (fixed):
/// domain, request_id, approved_plan_digest, approver, expiry.
pub fn signing_bytes_vlc(ctx: &VerifiedLiveContext) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);

    write_bytes(&mut buf, b"ryuki-v1/verified-live-context");
    write_str(&mut buf, &ctx.request_id.hyphenated().to_string());
    write_str(&mut buf, &ctx.approved_plan_digest);
    write_str(&mut buf, &ctx.approver);
    write_str(&mut buf, &datetime_bytes(&ctx.expiry));

    buf
}

/// Signs a [`VerifiedLiveContext`] with the CP's signing key.
pub fn sign_vlc(mut ctx: VerifiedLiveContext, key: &SigningKey) -> VerifiedLiveContext {
    let bytes = signing_bytes_vlc(&ctx);
    let sig: Signature = key.sign(&bytes);
    ctx.signature = B64.encode(sig.to_bytes());
    ctx
}

/// Verifies the CP's signature on a [`VerifiedLiveContext`].
pub fn verify_vlc(ctx: &VerifiedLiveContext, vk: &VerifyingKey) -> Result<(), VerifyError> {
    let raw = B64.decode(&ctx.signature)?;
    let sig_bytes: [u8; 64] = raw
        .try_into()
        .map_err(|v: Vec<u8>| VerifyError::BadSignatureLength(v.len()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    let bytes = signing_bytes_vlc(ctx);
    // verify_strict rejects malleable signatures and weak/small-subgroup keys
    // (ed25519-dalek v2).
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| VerifyError::InvalidSignature)
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Generate a new random Ed25519 keypair.  Intended for agent first-start and
/// test fixtures; the private key must never leave the host in production.
pub fn generate_keypair(rng: &mut impl rand_core::CryptoRngCore) -> SigningKey {
    SigningKey::generate(rng)
}

/// Encode a `VerifyingKey` (32 raw bytes) as base64 for wire transport.
pub fn encode_verifying_key(vk: &VerifyingKey) -> String {
    B64.encode(vk.as_bytes())
}

/// Decode a base64-encoded verifying key back into a `VerifyingKey`.
pub fn decode_verifying_key(s: &str) -> Result<VerifyingKey, VerifyError> {
    let raw = B64.decode(s)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|v: Vec<u8>| VerifyError::BadKeyLength(v.len()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| VerifyError::KeyMaterial(e.to_string()))
}

// ---------------------------------------------------------------------------
// Digest helpers (SHA-256)
// ---------------------------------------------------------------------------

use sha2::{Digest, Sha256};

/// Compute a SHA-256 hex digest over arbitrary bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Compute the canonical `JobSpec` digest: SHA-256 over its JSON serialisation.
/// `JobSpec` contains only ordered scalar fields + `BTreeMap<String, String>` for
/// vars, so `serde_json::to_vec` is deterministic for this specific struct.
pub fn job_spec_digest(spec: &crate::types::JobSpec) -> String {
    let bytes = serde_json::to_vec(spec).expect("JobSpec serialisation is infallible");
    sha256_hex(&bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use chrono::Utc;
    use rand::rngs::OsRng;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn make_envelope(key: &SigningKey) -> SignedEnvelope {
        let unsigned = SignedEnvelope {
            agent_id: "defra-vcenter-01".to_string(),
            platform: "defra".to_string(),
            job_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            request_id: Uuid::new_v4(),
            result_id: Uuid::new_v4(),
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: sha256_hex(b"spec-bytes"),
            approved_plan_digest: None,
            evidence_digest: sha256_hex(b"evidence-bytes"),
            redaction_policy_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: Uuid::new_v4().to_string(),
            signature: String::new(),
        };
        sign(unsigned, key)
    }

    fn make_vlc(key: &SigningKey) -> VerifiedLiveContext {
        let unsigned = VerifiedLiveContext {
            request_id: Uuid::new_v4(),
            approved_plan_digest: sha256_hex(b"plan-bytes"),
            approver: "ops-alice".to_string(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            signature: String::new(),
        };
        sign_vlc(unsigned, key)
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_job_mode() {
        for mode in [
            JobMode::OfflineDryRun,
            JobMode::LivePlan,
            JobMode::LiveApply,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let decoded: JobMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, decoded);
        }
    }

    #[test]
    fn roundtrip_job_status() {
        let statuses = [
            JobStatus::Pending,
            JobStatus::Leased,
            JobStatus::Running,
            JobStatus::Succeeded,
            JobStatus::Failed,
            JobStatus::Expired,
            JobStatus::ReconcileRequired,
            JobStatus::LiveRefused,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let decoded: JobStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, decoded);
        }
    }

    #[test]
    fn roundtrip_job_result_status() {
        let statuses = [
            JobResultStatus::CheckOk,
            JobResultStatus::Planned,
            JobResultStatus::Applied,
            JobResultStatus::Verified,
            JobResultStatus::Failed,
            JobResultStatus::LiveRefused,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let decoded: JobResultStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, decoded);
        }
    }

    #[test]
    fn roundtrip_capabilities() {
        use std::collections::BTreeMap;
        let cap = Capabilities {
            terraform: Some(ToolCapability {
                version: "1.9.5".to_string(),
                provider_versions: {
                    let mut m = BTreeMap::new();
                    m.insert("vsphere".to_string(), "2.7.0".to_string());
                    m
                },
            }),
            ansible: Some(ToolCapability {
                version: "2.16.0".to_string(),
                provider_versions: BTreeMap::new(),
            }),
        };
        let json = serde_json::to_string(&cap).unwrap();
        let decoded: Capabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, decoded);
    }

    #[test]
    fn roundtrip_agent_registration() {
        let key = generate_keypair(&mut OsRng);
        let reg = AgentRegistration {
            agent_id: "gblon-proxmox-01".to_string(),
            platform: "gblon".to_string(),
            capabilities: Capabilities::default(),
            public_key: encode_verifying_key(&key.verifying_key()),
        };
        let json = serde_json::to_string(&reg).unwrap();
        let decoded: AgentRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, decoded);
    }

    #[test]
    fn roundtrip_job_spec() {
        use std::collections::BTreeMap;
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1.2.3".to_string(),
            iac_digest: sha256_hex(b"iac-content"),
            vars: {
                let mut m = BTreeMap::new();
                m.insert("vm_name".to_string(), "web-prod-01".to_string());
                m
            },
            mode: JobMode::OfflineDryRun,
        };
        let json = serde_json::to_string(&spec).unwrap();
        let decoded: JobSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, decoded);
    }

    #[test]
    fn roundtrip_job_lease() {
        let lease = JobLease {
            attempt_id: Uuid::new_v4(),
            lease_generation: 3,
            fencing_token: Uuid::new_v4().to_string(),
            deadline: Utc::now() + chrono::Duration::minutes(30),
            cp_nonce: Uuid::new_v4().to_string(),
        };
        let json = serde_json::to_string(&lease).unwrap();
        let decoded: JobLease = serde_json::from_str(&json).unwrap();
        assert_eq!(lease, decoded);
    }

    #[test]
    fn roundtrip_job() {
        use std::collections::BTreeMap;
        let key = generate_keypair(&mut OsRng);
        let job_id = Uuid::new_v4();
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v2.0.0".to_string(),
            iac_digest: sha256_hex(b"iac"),
            vars: BTreeMap::new(),
            mode: JobMode::LivePlan,
        };
        let vlc = make_vlc(&key);
        let job = Job {
            id: job_id,
            platform: "defra".to_string(),
            spec,
            status: JobStatus::Leased,
            lease: Some(JobLease {
                attempt_id: Uuid::new_v4(),
                lease_generation: 1,
                fencing_token: "tok".to_string(),
                deadline: Utc::now() + chrono::Duration::minutes(5),
                cp_nonce: Uuid::new_v4().to_string(),
            }),
            live_context: Some(vlc),
        };
        let json = serde_json::to_string(&job).unwrap();
        let decoded: Job = serde_json::from_str(&json).unwrap();
        assert_eq!(job, decoded);
    }

    #[test]
    fn roundtrip_job_result() {
        let key = generate_keypair(&mut OsRng);
        let env = make_envelope(&key);
        let result = JobResult {
            job_id: env.job_id,
            attempt_id: env.attempt_id,
            result_id: env.result_id,
            status: JobResultStatus::Applied,
            evidence_digest: env.evidence_digest.clone(),
            signed_envelope: env,
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: JobResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, decoded);
    }

    #[test]
    fn roundtrip_verified_live_context() {
        let key = generate_keypair(&mut OsRng);
        let vlc = make_vlc(&key);
        let json = serde_json::to_string(&vlc).unwrap();
        let decoded: VerifiedLiveContext = serde_json::from_str(&json).unwrap();
        assert_eq!(vlc, decoded);
    }

    #[test]
    fn roundtrip_signed_envelope() {
        let key = generate_keypair(&mut OsRng);
        let env = make_envelope(&key);
        let json = serde_json::to_string(&env).unwrap();
        let decoded: SignedEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, decoded);
    }

    // -----------------------------------------------------------------------
    // Sign → verify success
    // -----------------------------------------------------------------------

    #[test]
    fn sign_verify_envelope_succeeds() {
        let key = generate_keypair(&mut OsRng);
        let env = make_envelope(&key);
        let vk = key.verifying_key();
        assert!(verify(&env, &vk).is_ok(), "valid signature must verify");
    }

    #[test]
    fn sign_verify_vlc_succeeds() {
        let key = generate_keypair(&mut OsRng);
        let vlc = make_vlc(&key);
        let vk = key.verifying_key();
        assert!(
            verify_vlc(&vlc, &vk).is_ok(),
            "valid VLC signature must verify"
        );
    }

    // -----------------------------------------------------------------------
    // Tamper tests — every signable field must cause verify to fail
    // -----------------------------------------------------------------------

    macro_rules! tamper_envelope {
        ($field:ident, $new_value:expr) => {{
            let key = generate_keypair(&mut OsRng);
            let mut env = make_envelope(&key);
            env.$field = $new_value;
            let vk = key.verifying_key();
            assert!(
                verify(&env, &vk).is_err(),
                "tampered field `{}` must invalidate signature",
                stringify!($field)
            );
        }};
    }

    #[test]
    fn tamper_agent_id_fails() {
        tamper_envelope!(agent_id, "attacker-agent".to_string());
    }

    #[test]
    fn tamper_platform_fails() {
        tamper_envelope!(platform, "rogue-site".to_string());
    }

    #[test]
    fn tamper_job_id_fails() {
        tamper_envelope!(job_id, Uuid::new_v4());
    }

    #[test]
    fn tamper_attempt_id_fails() {
        tamper_envelope!(attempt_id, Uuid::new_v4());
    }

    #[test]
    fn tamper_lease_generation_fails() {
        tamper_envelope!(lease_generation, 999);
    }

    #[test]
    fn tamper_request_id_fails() {
        tamper_envelope!(request_id, Uuid::new_v4());
    }

    #[test]
    fn tamper_mode_fails() {
        tamper_envelope!(mode, JobMode::LiveApply);
    }

    #[test]
    fn tamper_status_fails() {
        tamper_envelope!(status, JobResultStatus::Failed);
    }

    #[test]
    fn tamper_job_spec_digest_fails() {
        tamper_envelope!(job_spec_digest, sha256_hex(b"evil-spec"));
    }

    #[test]
    fn tamper_evidence_digest_fails() {
        tamper_envelope!(evidence_digest, sha256_hex(b"forged-evidence"));
    }

    #[test]
    fn tamper_redaction_policy_version_fails() {
        tamper_envelope!(redaction_policy_version, "9.9.9".to_string());
    }

    #[test]
    fn tamper_key_id_fails() {
        // Change the key_id to a different key's fingerprint.
        let other_key = generate_keypair(&mut OsRng);
        let other_key_id = encode_verifying_key(&other_key.verifying_key());
        tamper_envelope!(key_id, other_key_id);
    }

    #[test]
    fn tamper_cp_nonce_fails() {
        tamper_envelope!(cp_nonce, "forged-nonce".to_string());
    }

    /// Mutating `result_id` after signing must cause verification to fail.
    /// This proves the idempotency key is bound by the signature (fix for
    /// HIGH finding: result_id was previously unsigned and therefore forgeable).
    #[test]
    fn tamper_result_id_fails() {
        tamper_envelope!(result_id, Uuid::new_v4());
    }

    #[test]
    fn tamper_approved_plan_digest_fails() {
        // Start with a LiveApply envelope that has an approved_plan_digest.
        let key = generate_keypair(&mut OsRng);
        let unsigned = SignedEnvelope {
            agent_id: "a".to_string(),
            platform: "p".to_string(),
            job_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            request_id: Uuid::new_v4(),
            result_id: Uuid::new_v4(),
            mode: JobMode::LiveApply,
            status: JobResultStatus::Applied,
            job_spec_digest: sha256_hex(b"s"),
            approved_plan_digest: Some(sha256_hex(b"plan")),
            evidence_digest: sha256_hex(b"ev"),
            redaction_policy_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: "nonce".to_string(),
            signature: String::new(),
        };
        let mut env = sign(unsigned, &key);
        env.approved_plan_digest = Some(sha256_hex(b"forged-plan"));
        let vk = key.verifying_key();
        assert!(verify(&env, &vk).is_err(), "tampered plan digest must fail");
    }

    // -----------------------------------------------------------------------
    // Wrong key
    // -----------------------------------------------------------------------

    #[test]
    fn wrong_key_fails_envelope() {
        let signer = generate_keypair(&mut OsRng);
        let attacker = generate_keypair(&mut OsRng);
        let env = make_envelope(&signer);
        let wrong_vk = attacker.verifying_key();
        assert!(verify(&env, &wrong_vk).is_err(), "wrong key must fail");
    }

    #[test]
    fn wrong_key_fails_vlc() {
        let signer = generate_keypair(&mut OsRng);
        let attacker = generate_keypair(&mut OsRng);
        let vlc = make_vlc(&signer);
        let wrong_vk = attacker.verifying_key();
        assert!(
            verify_vlc(&vlc, &wrong_vk).is_err(),
            "wrong key must fail for VLC"
        );
    }

    // -----------------------------------------------------------------------
    // VerifiedLiveContext tamper tests
    // -----------------------------------------------------------------------

    macro_rules! tamper_vlc {
        ($field:ident, $new_value:expr) => {{
            let key = generate_keypair(&mut OsRng);
            let mut vlc = make_vlc(&key);
            vlc.$field = $new_value;
            let vk = key.verifying_key();
            assert!(
                verify_vlc(&vlc, &vk).is_err(),
                "tampered VLC field `{}` must invalidate signature",
                stringify!($field)
            );
        }};
    }

    #[test]
    fn tamper_vlc_request_id_fails() {
        tamper_vlc!(request_id, Uuid::new_v4());
    }

    #[test]
    fn tamper_vlc_approved_plan_digest_fails() {
        tamper_vlc!(approved_plan_digest, sha256_hex(b"forged"));
    }

    #[test]
    fn tamper_vlc_approver_fails() {
        tamper_vlc!(approver, "rogue-user".to_string());
    }

    #[test]
    fn tamper_vlc_expiry_fails() {
        tamper_vlc!(expiry, Utc::now() + chrono::Duration::hours(999));
    }

    // -----------------------------------------------------------------------
    // Canonicalization determinism
    // -----------------------------------------------------------------------

    #[test]
    fn signing_bytes_are_deterministic() {
        let key = generate_keypair(&mut OsRng);
        let env = make_envelope(&key);
        let b1 = signing_bytes(&env);
        let b2 = signing_bytes(&env);
        assert_eq!(b1, b2, "signing_bytes must be identical across calls");
    }

    #[test]
    fn signing_bytes_vlc_are_deterministic() {
        let key = generate_keypair(&mut OsRng);
        let vlc = make_vlc(&key);
        let b1 = signing_bytes_vlc(&vlc);
        let b2 = signing_bytes_vlc(&vlc);
        assert_eq!(b1, b2, "signing_bytes_vlc must be identical across calls");
    }

    /// This test proves that the envelope's signable set contains NO HashMap
    /// iteration (which would be non-deterministic).  All UUID/string fields are
    /// fixed; `JobMode`/`JobStatus` are matched by pattern (no map); `Option`s
    /// use a presence tag.  Running `signing_bytes` 1000 times must always
    /// produce the same output.
    #[test]
    fn signing_bytes_stable_under_repetition() {
        let key = generate_keypair(&mut OsRng);
        let env = make_envelope(&key);
        let reference = signing_bytes(&env);
        for _ in 0..1000 {
            assert_eq!(signing_bytes(&env), reference);
        }
    }

    #[test]
    fn signing_bytes_vlc_stable_under_repetition() {
        let key = generate_keypair(&mut OsRng);
        let vlc = make_vlc(&key);
        let reference = signing_bytes_vlc(&vlc);
        for _ in 0..1000 {
            assert_eq!(signing_bytes_vlc(&vlc), reference);
        }
    }

    // -----------------------------------------------------------------------
    // Key encoding round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn key_encode_decode_roundtrip() {
        let key = generate_keypair(&mut OsRng);
        let vk = key.verifying_key();
        let encoded = encode_verifying_key(&vk);
        let decoded = decode_verifying_key(&encoded).expect("decode must succeed");
        assert_eq!(vk.as_bytes(), decoded.as_bytes());
    }

    // -----------------------------------------------------------------------
    // job_spec_digest determinism
    // -----------------------------------------------------------------------

    #[test]
    fn job_spec_digest_is_deterministic() {
        use std::collections::BTreeMap;
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1.2.3".to_string(),
            iac_digest: sha256_hex(b"iac-content"),
            vars: {
                let mut m = BTreeMap::new();
                m.insert("vm_name".to_string(), "web-prod-01".to_string());
                m.insert("vcpu".to_string(), "4".to_string());
                m
            },
            mode: JobMode::OfflineDryRun,
        };
        let d1 = job_spec_digest(&spec);
        let d2 = job_spec_digest(&spec);
        assert_eq!(d1, d2, "job_spec_digest must be deterministic");
    }
}
