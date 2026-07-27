//! Ed25519 signing and verification primitives for the Ryuki protocol.
//!
//! ## Canonicalization scheme
//!
//! Every `signing_bytes_*` function produces a byte sequence with these
//! properties:
//!
//! 1. **Domain separator** — the first bytes are a versioned
//!    `b"ryuki-vN/<type>"` value, so a signature produced for one message type
//!    or signed layout cannot be replayed against another.
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
//! 5. **Scalar fields** — `u64` values (including positive request resource
//!    versions) are written as 8-byte little-endian;
//!    `DateTime<Utc>` is serialised as its RFC 3339 string (nanosecond
//!    precision); `Uuid` as its hyphenated string; `JobMode` / `JobStatus` as
//!    their `serde_json`-style snake_case label strings; `Option<String>` uses
//!    a 1-byte presence tag (0x00 absent, 0x01 present) followed by the
//!    length-prefixed value when present (see `write_opt_str`).
//!
//! 6. **Additive-optional fields (backward compatibility)** — optional fields
//!    added to an EXISTING signed type after its first release (e.g.
//!    `VerifiedLiveContext::step_job_id`, #42 slice A, and
//!    `SignedEnvelope::raw_plan_digest`) use an ASYMMETRIC
//!    encoding instead of the presence-tag scheme in (5): `None` contributes
//!    ZERO bytes; `Some` contributes `0x01 || length-prefixed value` (see
//!    `write_opt_uuid` / `write_additive_opt_str`). This is deliberate and
//!    different from optional fields that were part of the type's ORIGINAL
//!    signable set (which use the
//!    symmetric presence tag and, if added later, pair with a domain-separator
//!    bump instead — see `SignedEnvelope::approved_plan_digest` / the `v1`→`v2`
//!    bump). The asymmetric encoding exists SPECIFICALLY so that a value of
//!    `None` reproduces byte-for-byte the exact signing bytes that existed
//!    before the field was added, without any domain bump — i.e. it is the
//!    mechanism for extending an already-deployed signed type in a way that
//!    keeps every previously-issued signature (with the old, implicit `None`)
//!    verifying unchanged. Only use this pattern when that exact backward-
//!    compatibility guarantee is the explicit goal; a symmetric presence tag
//!    is preferred for any field present in a type's ORIGINAL release.
//!
//! The same function is used by **both** signer and verifier — it is the
//! single source of truth for the canonical representation.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::types::{
    ControlPlaneGrantKeyDisposition, ControlPlaneGrantKeyset, ControlPlaneGrantVerifyingKey,
    ExecutionTrustProfile, JobMode, JobResultStatus, MAX_CONTROL_PLANE_GRANT_KEYS, SignedEnvelope,
    VerifiedLiveContext,
};

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
    #[error("control-plane grant key id is invalid")]
    InvalidControlPlaneGrantKeyId,
    #[error("control-plane grant keyset is invalid: {0}")]
    InvalidControlPlaneGrantKeyset(&'static str),
    #[error("control-plane grant references an unknown or revoked key id")]
    UnknownControlPlaneGrantKey,
    #[error("control-plane grant keyset version rolled back from {current} to {candidate}")]
    ControlPlaneGrantKeysetRollback { current: u64, candidate: u64 },
    #[error("control-plane grant keyset version {0} was reused for different content")]
    ControlPlaneGrantKeysetVersionReuse(u64),
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

/// Append an additive `Option<String>` to the end of an existing signed layout.
/// `None` contributes zero bytes so signatures issued before the field existed
/// remain byte-for-byte valid; `Some` is unambiguous and signature-bound.
#[inline]
fn write_additive_opt_str(buf: &mut Vec<u8>, value: &Option<String>) {
    if let Some(value) = value {
        buf.push(0x01);
        write_str(buf, value);
    }
}

#[inline]
fn write_opt_execution_trust_profile(buf: &mut Vec<u8>, value: &Option<ExecutionTrustProfile>) {
    match value {
        None => buf.push(0x00),
        Some(profile) => {
            buf.push(0x01);
            write_str(buf, &execution_trust_profile_digest(profile));
        }
    }
}

/// Canonical, length-prefixed encoding of the non-secret execution trust
/// profile. This deliberately never serializes backend HCL or credential data.
pub fn execution_trust_profile_bytes(profile: &ExecutionTrustProfile) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    write_bytes(&mut buf, b"ryuki-v2/execution-trust-profile");
    write_str(&mut buf, &profile.schema_version);
    write_str(&mut buf, &profile.allowlist_version);
    write_str(&mut buf, &profile.platform);
    write_str(&mut buf, &profile.offering);
    write_str(&mut buf, &profile.runner_kind);
    write_str(&mut buf, &profile.provider_source);
    write_str(&mut buf, &profile.provider_version);
    write_str(&mut buf, &profile.provider_authority_id);
    write_str(&mut buf, &profile.provider_authority_version);
    write_str(&mut buf, &profile.backend_kind);
    write_str(&mut buf, &profile.backend_credential_authority_id);
    write_str(&mut buf, &profile.backend_credential_authority_revision);
    write_str(&mut buf, &profile.backend_authority_digest);
    write_str(&mut buf, &profile.executable_kind);
    write_str(&mut buf, &profile.executable_path);
    write_str(&mut buf, &profile.executable_version);
    write_opt_str(&mut buf, &profile.executable_sha256);
    write_str(&mut buf, &profile.executable_provenance_policy_version);
    write_str(&mut buf, &profile.provider_credential_authority_mode);
    write_str(&mut buf, &profile.backend_credential_authority_mode);
    write_str(&mut buf, &profile.containment_policy_version);
    write_str(&mut buf, &profile.iac_digest);
    write_str(&mut buf, &profile.state_key);
    buf
}

/// SHA-256 of [`execution_trust_profile_bytes`].
pub fn execution_trust_profile_digest(profile: &ExecutionTrustProfile) -> String {
    sha256_hex(&execution_trust_profile_bytes(profile))
}

/// Append an `Option<Uuid>` to the VLC signing buffer using the established
/// asymmetric step-binding encoding:
///
///   `None`    → appends NOTHING (zero bytes).
///   `Some(u)` → `0x01 || u64_le(len) || hyphenated-uuid-bytes`.
///
/// `None` contributes no trailing bytes; `Some(u)` begins with `0x01`, so a
/// step-bound v2 grant cannot be confused with a whole-request v2 grant. The
/// v2 VLC domain separately prevents compatibility with pre-v2 grants.
#[inline]
fn write_opt_uuid(buf: &mut Vec<u8>, value: &Option<uuid::Uuid>) {
    if let Some(u) = value {
        buf.push(0x01);
        write_str(buf, &u.hyphenated().to_string());
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
        JobMode::LiveDestroy => "live_destroy",
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
// Canonical byte encoding — agent enrollment proof of possession
// ---------------------------------------------------------------------------

/// Returns the canonical bytes signed by an agent when consuming a trusted,
/// preprovisioned enrollment challenge.
///
/// The challenge is a one-time bootstrap credential, while the existing
/// Ed25519 key remains the durable workload identity. Binding both here means
/// a leaked agent id cannot be squatted and a stolen challenge cannot be used
/// with a substituted key. The v1 domain is independent of all job/result
/// signing domains, so an enrollment signature cannot be replayed elsewhere.
pub fn signing_bytes_agent_enrollment_proof(
    challenge_id: uuid::Uuid,
    challenge: &str,
    agent_id: &str,
    platform: &str,
    public_key: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(320);
    write_bytes(&mut buf, b"ryuki-v1/agent-enrollment-proof");
    write_str(&mut buf, &challenge_id.hyphenated().to_string());
    write_str(&mut buf, challenge);
    write_str(&mut buf, agent_id);
    write_str(&mut buf, platform);
    write_str(&mut buf, public_key);
    buf
}

/// Sign a one-time enrollment claim with the agent's existing workload key.
pub fn sign_agent_enrollment_proof(
    challenge_id: uuid::Uuid,
    challenge: &str,
    agent_id: &str,
    platform: &str,
    public_key: &str,
    key: &SigningKey,
) -> String {
    let bytes = signing_bytes_agent_enrollment_proof(
        challenge_id,
        challenge,
        agent_id,
        platform,
        public_key,
    );
    B64.encode(key.sign(&bytes).to_bytes())
}

/// Verify an enrollment proof against the exact preprovisioned workload key.
pub fn verify_agent_enrollment_proof(
    challenge_id: uuid::Uuid,
    challenge: &str,
    agent_id: &str,
    platform: &str,
    public_key: &str,
    signature: &str,
    key: &VerifyingKey,
) -> Result<(), VerifyError> {
    let raw = B64.decode(signature)?;
    let sig_bytes: [u8; 64] = raw
        .try_into()
        .map_err(|v: Vec<u8>| VerifyError::BadSignatureLength(v.len()))?;
    let signature = Signature::from_bytes(&sig_bytes);
    let bytes = signing_bytes_agent_enrollment_proof(
        challenge_id,
        challenge,
        agent_id,
        platform,
        public_key,
    );
    key.verify_strict(&bytes, &signature)
        .map_err(|_| VerifyError::InvalidSignature)
}

// ---------------------------------------------------------------------------
// Canonical byte encoding — SignedEnvelope
// ---------------------------------------------------------------------------

/// Returns the canonical bytes that are signed / verified for a
/// [`SignedEnvelope`].  The `signature` field is intentionally excluded.
///
/// **Domain separator**: `ryuki-v5/signed-envelope`
/// (bumped from v4 when the required request resource version was added).
///
/// Field order (fixed; except for an explicitly asymmetric trailing optional,
/// any change requires another version bump):
/// domain, agent_id, agent_enrollment_id, platform, job_id, attempt_id, lease_generation,
/// request_id, request_resource_version, result_id, mode, status, job_spec_digest, approved_plan_digest,
/// execution_trust_profile, evidence_digest, redaction_policy_version,
/// timestamp, key_id, cp_nonce, raw_plan_digest (additive-optional trailing
/// field).
pub fn signing_bytes(env: &SignedEnvelope) -> Vec<u8> {
    // Pre-allocate a generous buffer to avoid repeated reallocations.
    let mut buf: Vec<u8> = Vec::with_capacity(512);

    // Domain separator — prevents cross-type signature replay and distinguishes
    // v5 request-version-bound envelopes cannot be confused with legacy v4
    // results, even when every other field has the same value.
    write_bytes(&mut buf, b"ryuki-v5/signed-envelope");

    write_str(&mut buf, &env.agent_id);
    write_str(&mut buf, &env.agent_enrollment_id.hyphenated().to_string());
    write_str(&mut buf, &env.platform);
    write_str(&mut buf, &env.job_id.hyphenated().to_string());
    write_str(&mut buf, &env.attempt_id.hyphenated().to_string());
    write_u64(&mut buf, env.lease_generation);
    write_str(&mut buf, &env.request_id.hyphenated().to_string());
    write_u64(&mut buf, env.request_resource_version.get());
    // result_id added in v2 — bound by signature to prevent idempotency key forgery.
    write_str(&mut buf, &env.result_id.hyphenated().to_string());
    write_str(&mut buf, mode_label(&env.mode));
    write_str(&mut buf, result_status_label(&env.status));
    write_str(&mut buf, &env.job_spec_digest);
    write_opt_str(&mut buf, &env.approved_plan_digest);
    write_opt_execution_trust_profile(&mut buf, &env.execution_trust_profile);
    write_str(&mut buf, &env.evidence_digest);
    write_str(&mut buf, &env.redaction_policy_version);
    write_str(&mut buf, &datetime_bytes(&env.timestamp));
    write_str(&mut buf, &env.key_id);
    write_str(&mut buf, &env.cp_nonce);
    write_additive_opt_str(&mut buf, &env.raw_plan_digest);

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
/// domain, request_id, request_resource_version, platform, job_spec_digest, approved_plan_digest,
/// approved plan job/attempt, approver, expiry, step_job_id, assigned
/// agent/enrollment/key/profile.
///
/// The v8 domain binds the exact key id selected from the versioned CP keyset.
/// A legacy v7 grant cannot be reinterpreted as keyring-aware authority.
pub fn signing_bytes_vlc(ctx: &VerifiedLiveContext) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);

    write_bytes(&mut buf, b"ryuki-v8/verified-live-context");
    write_str(&mut buf, &ctx.request_id.hyphenated().to_string());
    write_u64(&mut buf, ctx.request_resource_version.get());
    write_str(&mut buf, &ctx.platform);
    write_str(&mut buf, &ctx.job_spec_digest);
    write_str(&mut buf, &ctx.approved_plan_digest);
    write_str(&mut buf, &ctx.approved_plan_job_id.hyphenated().to_string());
    write_str(
        &mut buf,
        &ctx.approved_plan_attempt_id.hyphenated().to_string(),
    );
    write_str(&mut buf, &ctx.approver);
    write_str(&mut buf, &datetime_bytes(&ctx.expiry));
    write_opt_uuid(&mut buf, &ctx.step_job_id);
    write_str(&mut buf, &ctx.execution_authority.assigned_agent_id);
    write_str(
        &mut buf,
        &ctx.execution_authority
            .assigned_agent_enrollment_id
            .hyphenated()
            .to_string(),
    );
    write_str(
        &mut buf,
        &ctx.execution_authority.assigned_agent_key_fingerprint,
    );
    write_str(
        &mut buf,
        &ctx.execution_authority.execution_trust_profile_digest,
    );
    write_str(&mut buf, &ctx.signing_key_id);

    buf
}

/// Signs a [`VerifiedLiveContext`] with the CP's signing key.
pub fn sign_vlc(mut ctx: VerifiedLiveContext, key: &SigningKey) -> VerifiedLiveContext {
    ctx.signing_key_id = control_plane_grant_key_id(&key.verifying_key());
    let bytes = signing_bytes_vlc(&ctx);
    let sig: Signature = key.sign(&bytes);
    ctx.signature = B64.encode(sig.to_bytes());
    ctx
}

/// Verifies the CP's signature on a [`VerifiedLiveContext`].
pub fn verify_vlc(ctx: &VerifiedLiveContext, vk: &VerifyingKey) -> Result<(), VerifyError> {
    if ctx.signing_key_id != control_plane_grant_key_id(vk) {
        return Err(VerifyError::UnknownControlPlaneGrantKey);
    }
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

/// Deterministic, non-secret `kid` for one Ed25519 control-plane grant key.
/// Binding the id to the canonical wire public key prevents key/id substitution
/// even before a signature is checked.
pub fn control_plane_grant_key_id(vk: &VerifyingKey) -> String {
    format!(
        "signing-key:sha256-{}",
        sha256_hex(encode_verifying_key(vk).as_bytes())
    )
}

/// Build one canonical public keyset entry from an Ed25519 verifying key.
pub fn control_plane_grant_verifying_key(
    vk: &VerifyingKey,
    disposition: ControlPlaneGrantKeyDisposition,
) -> ControlPlaneGrantVerifyingKey {
    ControlPlaneGrantVerifyingKey {
        key_id: control_plane_grant_key_id(vk),
        public_key: encode_verifying_key(vk),
        disposition,
    }
}

/// Validate the closed, bounded public keyset and every key-id/public-key
/// cross-binding. Entries must be strictly sorted so all consumers see one
/// canonical representation.
pub fn validate_control_plane_grant_keyset(
    keyset: &ControlPlaneGrantKeyset,
) -> Result<(), VerifyError> {
    if keyset.keyset_version == 0 {
        return Err(VerifyError::InvalidControlPlaneGrantKeyset(
            "keyset_version must be positive",
        ));
    }
    if keyset.keys.is_empty() || keyset.keys.len() > MAX_CONTROL_PLANE_GRANT_KEYS {
        return Err(VerifyError::InvalidControlPlaneGrantKeyset(
            "key count is outside the bounded nonempty range",
        ));
    }
    if !keyset
        .keys
        .windows(2)
        .all(|pair| pair[0].key_id < pair[1].key_id)
    {
        return Err(VerifyError::InvalidControlPlaneGrantKeyset(
            "keys must be strictly sorted and unique",
        ));
    }

    let mut active_count = 0usize;
    for entry in &keyset.keys {
        let verifying_key = decode_verifying_key(&entry.public_key)?;
        if encode_verifying_key(&verifying_key) != entry.public_key
            || control_plane_grant_key_id(&verifying_key) != entry.key_id
        {
            return Err(VerifyError::InvalidControlPlaneGrantKeyId);
        }
        if entry.disposition == ControlPlaneGrantKeyDisposition::Active {
            active_count += 1;
            if entry.key_id != keyset.active_key_id {
                return Err(VerifyError::InvalidControlPlaneGrantKeyset(
                    "active entry differs from active_key_id",
                ));
            }
        } else if entry.key_id == keyset.active_key_id {
            return Err(VerifyError::InvalidControlPlaneGrantKeyset(
                "active_key_id names a verify-only key",
            ));
        }
    }
    if active_count != 1 {
        return Err(VerifyError::InvalidControlPlaneGrantKeyset(
            "exactly one key must be active",
        ));
    }
    Ok(())
}

/// Validate a newly observed keyset relative to the currently pinned set.
/// Lower versions are rollback; equal versions must be byte-for-byte equal.
pub fn validate_control_plane_grant_keyset_update(
    current: &ControlPlaneGrantKeyset,
    candidate: &ControlPlaneGrantKeyset,
) -> Result<(), VerifyError> {
    validate_control_plane_grant_keyset(current)?;
    validate_control_plane_grant_keyset(candidate)?;
    if candidate.keyset_version < current.keyset_version {
        return Err(VerifyError::ControlPlaneGrantKeysetRollback {
            current: current.keyset_version,
            candidate: candidate.keyset_version,
        });
    }
    if candidate.keyset_version == current.keyset_version && candidate != current {
        return Err(VerifyError::ControlPlaneGrantKeysetVersionReuse(
            candidate.keyset_version,
        ));
    }
    Ok(())
}

/// Select the exact public key named by the signed grant and verify it. Missing
/// keys—including keys removed by revocation—fail closed as unknown `kid`s.
pub fn verify_vlc_with_keyset(
    ctx: &VerifiedLiveContext,
    keyset: &ControlPlaneGrantKeyset,
) -> Result<(), VerifyError> {
    validate_control_plane_grant_keyset(keyset)?;
    let entry = keyset
        .keys
        .iter()
        .find(|entry| entry.key_id == ctx.signing_key_id)
        .ok_or(VerifyError::UnknownControlPlaneGrantKey)?;
    let verifying_key = decode_verifying_key(&entry.public_key)?;
    verify_vlc(ctx, &verifying_key)
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

/// Stable non-secret fingerprint used by enrollment review and live grants.
/// It intentionally matches the control plane's historical fingerprint of the
/// canonical base64 wire key, rather than silently changing that identity.
pub fn public_key_fingerprint(public_key: &str) -> String {
    format!("sha256:{}", sha256_hex(public_key.trim().as_bytes()))
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

/// Return whether `value` is the canonical lowercase hexadecimal encoding of
/// one SHA-256 digest.
pub fn sha256_digest_is_canonical(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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

    fn request_version(value: u64) -> RequestResourceVersion {
        RequestResourceVersion::new(value).expect("test request version must be positive")
    }

    fn assert_request_version_is_required_and_positive<T>(value: &T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let current = serde_json::to_value(value).expect("protocol fixture must serialize");
        assert!(
            current
                .get("request_resource_version")
                .is_some_and(|version| version.as_u64() == Some(7)),
            "the request version must be a numeric JSON field"
        );

        let mut missing = current.clone();
        missing
            .as_object_mut()
            .expect("protocol fixture must be an object")
            .remove("request_resource_version");
        assert!(
            serde_json::from_value::<T>(missing).is_err(),
            "an omitted request_resource_version must fail closed"
        );

        let mut zero = current;
        zero.as_object_mut()
            .expect("protocol fixture must be an object")
            .insert("request_resource_version".to_string(), serde_json::json!(0));
        assert!(
            serde_json::from_value::<T>(zero).is_err(),
            "request_resource_version zero must fail closed"
        );
    }

    fn make_envelope(key: &SigningKey) -> SignedEnvelope {
        let unsigned = SignedEnvelope {
            agent_id: "defra-vcenter-01".to_string(),
            agent_enrollment_id: Uuid::new_v4(),
            platform: "defra".to_string(),
            job_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            request_id: Uuid::new_v4(),
            request_resource_version: request_version(7),
            result_id: Uuid::new_v4(),
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: sha256_hex(b"spec-bytes"),
            approved_plan_digest: None,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: sha256_hex(b"evidence-bytes"),
            redaction_policy_version: crate::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: Uuid::new_v4().to_string(),
            signature: String::new(),
        };
        sign(unsigned, key)
    }

    fn test_execution_authority() -> LiveExecutionAuthority {
        LiveExecutionAuthority {
            assigned_agent_id: "agent-test".to_string(),
            assigned_agent_enrollment_id: Uuid::nil(),
            assigned_agent_key_fingerprint: "sha256:test".to_string(),
            execution_trust_profile_digest: sha256_hex(b"profile"),
        }
    }

    fn test_execution_trust_profile() -> ExecutionTrustProfile {
        ExecutionTrustProfile {
            schema_version: EXECUTION_TRUST_PROFILE_SCHEMA_VERSION.to_string(),
            allowlist_version: EXECUTION_TRUST_PROFILE_ALLOWLIST_VERSION.to_string(),
            platform: "defra".to_string(),
            offering: "linux-server-deployment".to_string(),
            runner_kind: "terraform".to_string(),
            provider_source: "registry.terraform.io/vmware/vsphere".to_string(),
            provider_version: "2.16.1".to_string(),
            provider_authority_id: "provider-authority/vsphere/test-fixture".to_string(),
            provider_authority_version: "v1".to_string(),
            backend_kind: "local".to_string(),
            backend_credential_authority_id:
                "backend-credential-authority/local/test-fixture".to_string(),
            backend_credential_authority_revision: "v1".to_string(),
            backend_authority_digest: sha256_hex(b"backend-authority"),
            executable_kind: "terraform".to_string(),
            executable_path: "/usr/local/bin/terraform".to_string(),
            executable_version: "1.13.0".to_string(),
            executable_sha256: None,
            executable_provenance_policy_version:
                EXECUTABLE_PROVENANCE_POLICY_VERSION.to_string(),
            provider_credential_authority_mode:
                PROVIDER_CREDENTIAL_AUTHORITY_MODE.to_string(),
            backend_credential_authority_mode:
                "ryuki.closed-schema-inline-scalars-no-file-ambient-metadata-cli-workload-in-cluster-no-remote-execution.v1"
                    .to_string(),
            containment_policy_version:
                "per-command-attach-before-exec-kill-all-wait-empty-v1+ryuki.terraform-isolated-state-key.v1"
                    .to_string(),
            iac_digest: sha256_hex(b"iac"),
            state_key: "request-test".to_string(),
        }
    }

    fn make_vlc(key: &SigningKey) -> VerifiedLiveContext {
        let unsigned = VerifiedLiveContext {
            request_id: Uuid::new_v4(),
            request_resource_version: request_version(7),
            platform: "defra".to_string(),
            job_spec_digest: sha256_hex(b"job-spec"),
            approved_plan_digest: sha256_hex(b"plan-bytes"),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-alice".to_string(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            step_job_id: None,
            execution_authority: test_execution_authority(),
            signing_key_id: String::new(),
            signature: String::new(),
        };
        sign_vlc(unsigned, key)
    }

    fn grant_keyset(
        keyset_version: u64,
        active: &SigningKey,
        verify_only: &[&SigningKey],
    ) -> ControlPlaneGrantKeyset {
        let active_key_id = control_plane_grant_key_id(&active.verifying_key());
        let mut keys = vec![control_plane_grant_verifying_key(
            &active.verifying_key(),
            ControlPlaneGrantKeyDisposition::Active,
        )];
        keys.extend(verify_only.iter().map(|key| {
            control_plane_grant_verifying_key(
                &key.verifying_key(),
                ControlPlaneGrantKeyDisposition::VerifyOnly,
            )
        }));
        keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        ControlPlaneGrantKeyset {
            keyset_version,
            active_key_id,
            keys,
        }
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
        let challenge_id = Uuid::new_v4();
        let challenge = "ryc_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let agent_id = "gblon-proxmox-01";
        let platform = "gblon";
        let public_key = encode_verifying_key(&key.verifying_key());
        let reg = AgentRegistration {
            enrollment_challenge_id: challenge_id,
            enrollment_challenge: challenge.to_string(),
            agent_id: agent_id.to_string(),
            platform: platform.to_string(),
            capabilities: Capabilities::default(),
            public_key: public_key.clone(),
            enrollment_proof: sign_agent_enrollment_proof(
                challenge_id,
                challenge,
                agent_id,
                platform,
                &public_key,
                &key,
            ),
        };
        let json = serde_json::to_string(&reg).unwrap();
        let decoded: AgentRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, decoded);
        let debug = format!("{reg:?}");
        assert!(!debug.contains(challenge));
        assert!(!debug.contains(&reg.enrollment_proof));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn enrollment_proof_binds_challenge_identity_platform_and_key() {
        let key = generate_keypair(&mut OsRng);
        let other_key = generate_keypair(&mut OsRng);
        let challenge_id = Uuid::new_v4();
        let challenge = "ryc_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let public_key = encode_verifying_key(&key.verifying_key());
        let signature = sign_agent_enrollment_proof(
            challenge_id,
            challenge,
            "agent-01",
            "site-a",
            &public_key,
            &key,
        );

        verify_agent_enrollment_proof(
            challenge_id,
            challenge,
            "agent-01",
            "site-a",
            &public_key,
            &signature,
            &key.verifying_key(),
        )
        .expect("the exact admitted identity must verify");

        for changed in [
            (
                Uuid::new_v4(),
                challenge,
                "agent-01",
                "site-a",
                public_key.as_str(),
            ),
            (
                challenge_id,
                "ryc_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "agent-01",
                "site-a",
                public_key.as_str(),
            ),
            (
                challenge_id,
                challenge,
                "agent-02",
                "site-a",
                public_key.as_str(),
            ),
            (
                challenge_id,
                challenge,
                "agent-01",
                "site-b",
                public_key.as_str(),
            ),
            (
                challenge_id,
                challenge,
                "agent-01",
                "site-a",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ),
        ] {
            assert!(
                verify_agent_enrollment_proof(
                    changed.0,
                    changed.1,
                    changed.2,
                    changed.3,
                    changed.4,
                    &signature,
                    &key.verifying_key(),
                )
                .is_err(),
                "changing any enrollment field must invalidate the proof"
            );
        }
        assert!(
            verify_agent_enrollment_proof(
                challenge_id,
                challenge,
                "agent-01",
                "site-a",
                &public_key,
                &signature,
                &other_key.verifying_key(),
            )
            .is_err(),
            "a different workload key must not verify the proof"
        );
    }

    #[test]
    fn enrollment_proof_encoding_is_length_prefixed_and_domain_separated() {
        let challenge_id = Uuid::nil();
        let a = signing_bytes_agent_enrollment_proof(challenge_id, "ab", "c", "site", "key");
        let b = signing_bytes_agent_enrollment_proof(challenge_id, "a", "bc", "site", "key");
        assert_ne!(a, b, "adjacent enrollment fields must not be ambiguous");
        assert_ne!(
            a,
            signing_bytes_vlc(&VerifiedLiveContext {
                request_id: challenge_id,
                request_resource_version: request_version(7),
                platform: "defra".to_owned(),
                job_spec_digest: "ab".to_owned(),
                approved_plan_digest: "c".to_owned(),
                approved_plan_job_id: Uuid::new_v4(),
                approved_plan_attempt_id: Uuid::new_v4(),
                approver: "site".to_owned(),
                expiry: Utc::now(),
                step_job_id: None,
                execution_authority: test_execution_authority(),
                signing_key_id: String::new(),
                signature: String::new(),
            }),
            "enrollment proofs must not share another protocol signing domain"
        );
    }

    #[test]
    fn roundtrip_job_spec() {
        use std::collections::BTreeMap;
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            request_resource_version: request_version(7),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1.2.3".to_string(),
            iac_digest: sha256_hex(b"iac-content"),
            vars: {
                let mut m = BTreeMap::new();
                m.insert("vm_name".to_string(), "web-prod-01".to_string());
                m
            },
            state_key: Some(format!("request-{}", Uuid::new_v4())),
            mode: JobMode::OfflineDryRun,
        };
        let json = serde_json::to_string(&spec).unwrap();
        let decoded: JobSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, decoded);
    }

    #[test]
    fn job_spec_without_state_key_still_decodes_when_request_version_is_present() {
        let request_id = Uuid::new_v4();
        let offering_id = Uuid::new_v4();
        let json = serde_json::json!({
            "request_id": request_id,
            "request_resource_version": 7,
            "offering_id": offering_id,
            "iac_ref": "request-preflight@v1",
            "iac_digest": sha256_hex(b"iac"),
            "mode": "live_plan"
        });

        let decoded: JobSpec = serde_json::from_value(json).expect("current wire decode");
        assert_eq!(decoded.request_id, request_id);
        assert_eq!(decoded.request_resource_version.get(), 7);
        assert_eq!(decoded.offering_id, offering_id);
        assert_eq!(decoded.state_key, None);
    }

    #[test]
    fn state_key_safety_accepts_generated_keys_and_rejects_injection() {
        assert!(is_safe_state_key(
            "request-123e4567-e89b-12d3-a456-426614174000"
        ));
        assert!(is_safe_state_key(
            "step-123e4567-e89b-12d3-a456-426614174000"
        ));
        for unsafe_key in ["", "../shared", "request/a", "quoted\"key", "space key"] {
            assert!(!is_safe_state_key(unsafe_key), "accepted {unsafe_key:?}");
        }
        assert!(!is_safe_state_key(&"a".repeat(129)));
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
            request_resource_version: request_version(7),
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v2.0.0".to_string(),
            iac_digest: sha256_hex(b"iac"),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{}", Uuid::new_v4())),
            mode: JobMode::LivePlan,
        };
        let vlc = make_vlc(&key);
        let job = Job {
            id: job_id,
            agent_enrollment_id: Uuid::new_v4(),
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
            raw_plan_digest: env.raw_plan_digest.clone(),
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

    #[test]
    fn request_resource_version_is_required_positive_and_numeric_across_the_wire() {
        let key = generate_keypair(&mut OsRng);
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            request_resource_version: request_version(7),
            offering_id: Uuid::new_v4(),
            iac_ref: "request-preflight@v1".to_string(),
            iac_digest: sha256_hex(b"iac"),
            vars: std::collections::BTreeMap::new(),
            state_key: None,
            mode: JobMode::OfflineDryRun,
        };

        assert_request_version_is_required_and_positive(&spec);
        assert_request_version_is_required_and_positive(&make_vlc(&key));
        assert_request_version_is_required_and_positive(&make_envelope(&key));
        assert!(RequestResourceVersion::try_from(0_u64).is_err());
        assert!(RequestResourceVersion::try_from(0_i64).is_err());
        assert!(RequestResourceVersion::try_from(-1_i64).is_err());
    }

    #[test]
    fn protocol_v8_is_the_only_accepted_wire_contract() {
        assert_eq!(PROTOCOL_VERSION, 8);
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS, &[8]);
        assert!(!SUPPORTED_PROTOCOL_VERSIONS.contains(&7));
    }

    #[test]
    fn grant_keyset_rotation_overlap_revocation_and_rollback_fail_closed() {
        let old = generate_keypair(&mut OsRng);
        let active = generate_keypair(&mut OsRng);
        let current = grant_keyset(7, &old, &[]);
        let overlap = grant_keyset(8, &active, &[&old]);
        let revoked = grant_keyset(9, &active, &[]);

        validate_control_plane_grant_keyset_update(&current, &overlap)
            .expect("a higher-version overlap keyset is valid");
        validate_control_plane_grant_keyset_update(&overlap, &revoked)
            .expect("a higher-version revocation keyset is valid");

        let old_grant = make_vlc(&old);
        let active_grant = make_vlc(&active);
        verify_vlc_with_keyset(&old_grant, &overlap)
            .expect("verify-only overlap key must validate existing grants");
        verify_vlc_with_keyset(&active_grant, &overlap)
            .expect("active overlap key must validate new grants");
        assert!(matches!(
            verify_vlc_with_keyset(&old_grant, &revoked),
            Err(VerifyError::UnknownControlPlaneGrantKey)
        ));
        assert!(matches!(
            validate_control_plane_grant_keyset_update(&overlap, &current),
            Err(VerifyError::ControlPlaneGrantKeysetRollback { .. })
        ));

        let reused_version = grant_keyset(overlap.keyset_version, &active, &[]);
        assert!(matches!(
            validate_control_plane_grant_keyset_update(&overlap, &reused_version),
            Err(VerifyError::ControlPlaneGrantKeysetVersionReuse(8))
        ));
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
    fn absent_raw_plan_digest_preserves_the_v5_canonical_layout() {
        let key = generate_keypair(&mut OsRng);
        let env = make_envelope(&key);
        assert!(env.raw_plan_digest.is_none());

        let mut canonical_bytes = Vec::new();
        write_bytes(&mut canonical_bytes, b"ryuki-v5/signed-envelope");
        write_str(&mut canonical_bytes, &env.agent_id);
        write_str(
            &mut canonical_bytes,
            &env.agent_enrollment_id.hyphenated().to_string(),
        );
        write_str(&mut canonical_bytes, &env.platform);
        write_str(&mut canonical_bytes, &env.job_id.hyphenated().to_string());
        write_str(
            &mut canonical_bytes,
            &env.attempt_id.hyphenated().to_string(),
        );
        write_u64(&mut canonical_bytes, env.lease_generation);
        write_str(
            &mut canonical_bytes,
            &env.request_id.hyphenated().to_string(),
        );
        write_u64(&mut canonical_bytes, env.request_resource_version.get());
        write_str(
            &mut canonical_bytes,
            &env.result_id.hyphenated().to_string(),
        );
        write_str(&mut canonical_bytes, mode_label(&env.mode));
        write_str(&mut canonical_bytes, result_status_label(&env.status));
        write_str(&mut canonical_bytes, &env.job_spec_digest);
        write_opt_str(&mut canonical_bytes, &env.approved_plan_digest);
        write_opt_execution_trust_profile(&mut canonical_bytes, &env.execution_trust_profile);
        write_str(&mut canonical_bytes, &env.evidence_digest);
        write_str(&mut canonical_bytes, &env.redaction_policy_version);
        write_str(&mut canonical_bytes, &datetime_bytes(&env.timestamp));
        write_str(&mut canonical_bytes, &env.key_id);
        write_str(&mut canonical_bytes, &env.cp_nonce);

        assert_eq!(signing_bytes(&env), canonical_bytes);
    }

    #[test]
    fn legacy_v4_envelope_without_request_version_is_rejected_by_the_v5_domain() {
        let key = generate_keypair(&mut OsRng);
        let mut legacy = make_envelope(&key);
        legacy.signature.clear();

        // Reconstruct the complete v4 layout. It includes immutable enrollment
        // identity but predates the request resource version. A genuine old
        // signature must never be reinterpreted as v5 version-bound authority.
        let mut legacy_bytes = Vec::new();
        write_bytes(&mut legacy_bytes, b"ryuki-v4/signed-envelope");
        write_str(&mut legacy_bytes, &legacy.agent_id);
        write_str(
            &mut legacy_bytes,
            &legacy.agent_enrollment_id.hyphenated().to_string(),
        );
        write_str(&mut legacy_bytes, &legacy.platform);
        write_str(&mut legacy_bytes, &legacy.job_id.hyphenated().to_string());
        write_str(
            &mut legacy_bytes,
            &legacy.attempt_id.hyphenated().to_string(),
        );
        write_u64(&mut legacy_bytes, legacy.lease_generation);
        write_str(
            &mut legacy_bytes,
            &legacy.request_id.hyphenated().to_string(),
        );
        write_str(
            &mut legacy_bytes,
            &legacy.result_id.hyphenated().to_string(),
        );
        write_str(&mut legacy_bytes, mode_label(&legacy.mode));
        write_str(&mut legacy_bytes, result_status_label(&legacy.status));
        write_str(&mut legacy_bytes, &legacy.job_spec_digest);
        write_opt_str(&mut legacy_bytes, &legacy.approved_plan_digest);
        write_opt_execution_trust_profile(&mut legacy_bytes, &legacy.execution_trust_profile);
        write_str(&mut legacy_bytes, &legacy.evidence_digest);
        write_str(&mut legacy_bytes, &legacy.redaction_policy_version);
        write_str(&mut legacy_bytes, &datetime_bytes(&legacy.timestamp));
        write_str(&mut legacy_bytes, &legacy.key_id);
        write_str(&mut legacy_bytes, &legacy.cp_nonce);

        legacy.signature = B64.encode(key.sign(&legacy_bytes).to_bytes());
        assert!(verify(&legacy, &key.verifying_key()).is_err());
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
    fn tamper_agent_enrollment_id_fails() {
        tamper_envelope!(agent_enrollment_id, Uuid::new_v4());
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
    fn tamper_request_resource_version_fails() {
        tamper_envelope!(request_resource_version, request_version(8));
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
    fn tamper_raw_plan_digest_fails() {
        let key = generate_keypair(&mut OsRng);
        let mut unsigned = make_envelope(&key);
        unsigned.signature.clear();
        unsigned.mode = JobMode::LivePlan;
        unsigned.status = JobResultStatus::Planned;
        unsigned.raw_plan_digest = Some(sha256_hex(b"canonical-raw-plan"));
        let mut envelope = sign(unsigned, &key);
        envelope.raw_plan_digest = Some(sha256_hex(b"different-raw-plan"));

        assert!(
            verify(&envelope, &key.verifying_key()).is_err(),
            "the raw plan commitment must be signature-bound"
        );
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

    #[test]
    fn execution_trust_profile_digest_is_deterministic_and_binds_policy() {
        let profile = test_execution_trust_profile();
        assert_eq!(
            execution_trust_profile_digest(&profile),
            execution_trust_profile_digest(&profile.clone())
        );
        let mut mutated = profile.clone();
        mutated.containment_policy_version = "different-containment-v1".to_string();
        assert_ne!(
            execution_trust_profile_digest(&profile),
            execution_trust_profile_digest(&mutated)
        );
        let mut mutated = profile.clone();
        mutated.backend_credential_authority_mode = "ambient-default-chain".to_string();
        assert_ne!(
            execution_trust_profile_digest(&profile),
            execution_trust_profile_digest(&mutated)
        );
        let mut mutated = profile.clone();
        mutated.backend_credential_authority_id =
            "backend-credential-authority/local/other-fixture".to_string();
        assert_ne!(
            execution_trust_profile_digest(&profile),
            execution_trust_profile_digest(&mutated)
        );
        let mut mutated = profile.clone();
        mutated.backend_credential_authority_revision = "v2".to_string();
        assert_ne!(
            execution_trust_profile_digest(&profile),
            execution_trust_profile_digest(&mutated)
        );
        let mut mutated = profile.clone();
        mutated.provider_authority_version = "v2".to_string();
        assert_ne!(
            execution_trust_profile_digest(&profile),
            execution_trust_profile_digest(&mutated)
        );
        let mut mutated = profile.clone();
        mutated.backend_authority_digest = sha256_hex(b"other-backend-authority");
        assert_ne!(
            execution_trust_profile_digest(&profile),
            execution_trust_profile_digest(&mutated)
        );
    }

    #[test]
    fn tamper_signed_execution_trust_profile_fails() {
        let key = generate_keypair(&mut OsRng);
        let mut unsigned = make_envelope(&key);
        unsigned.signature.clear();
        unsigned.execution_trust_profile = Some(test_execution_trust_profile());
        let mut signed = sign(unsigned, &key);
        signed
            .execution_trust_profile
            .as_mut()
            .expect("profile")
            .backend_kind = "s3".to_string();
        assert!(verify(&signed, &key.verifying_key()).is_err());
    }

    #[test]
    fn tamper_vlc_plan_owner_or_profile_fails() {
        let key = generate_keypair(&mut OsRng);
        let mut grant = make_vlc(&key);
        grant.execution_authority.assigned_agent_enrollment_id = Uuid::new_v4();
        assert!(verify_vlc(&grant, &key.verifying_key()).is_err());

        let mut grant = make_vlc(&key);
        grant.execution_authority.execution_trust_profile_digest = sha256_hex(b"other");
        assert!(verify_vlc(&grant, &key.verifying_key()).is_err());
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
            agent_enrollment_id: Uuid::new_v4(),
            platform: "p".to_string(),
            job_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            request_id: Uuid::new_v4(),
            request_resource_version: request_version(7),
            result_id: Uuid::new_v4(),
            mode: JobMode::LiveApply,
            status: JobResultStatus::Applied,
            job_spec_digest: sha256_hex(b"s"),
            approved_plan_digest: Some(sha256_hex(b"plan")),
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: sha256_hex(b"ev"),
            redaction_policy_version: crate::REDACTION_POLICY_VERSION.to_string(),
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

    #[test]
    fn canonical_sha256_digest_requires_lowercase_exact_width() {
        assert!(sha256_digest_is_canonical(&sha256_hex(b"input")));
        assert!(!sha256_digest_is_canonical(&"A".repeat(64)));
        assert!(!sha256_digest_is_canonical(&"0".repeat(63)));
        assert!(!sha256_digest_is_canonical(&"0".repeat(65)));
        assert!(!sha256_digest_is_canonical(&format!("{}g", "0".repeat(63))));
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
    fn tamper_vlc_request_resource_version_fails() {
        tamper_vlc!(request_resource_version, request_version(8));
    }

    #[test]
    fn tamper_vlc_platform_fails() {
        tamper_vlc!(platform, "another-platform".to_string());
    }

    #[test]
    fn tamper_vlc_job_spec_digest_fails() {
        tamper_vlc!(job_spec_digest, sha256_hex(b"different-job-spec"));
    }

    #[test]
    fn tamper_vlc_approved_plan_digest_fails() {
        tamper_vlc!(approved_plan_digest, sha256_hex(b"forged"));
    }

    #[test]
    fn tamper_vlc_approved_plan_job_id_fails() {
        tamper_vlc!(approved_plan_job_id, Uuid::new_v4());
    }

    #[test]
    fn tamper_vlc_approved_plan_attempt_id_fails() {
        tamper_vlc!(approved_plan_attempt_id, Uuid::new_v4());
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
    // v8 grant layout, legacy fencing, key selection, and step binding
    // -----------------------------------------------------------------------

    /// Pin the v8 signing layout, including request version, exact plan-row,
    /// execution authority, and key id.
    #[test]
    fn vlc_v8_signing_bytes_bind_request_version_plan_authority_and_key_id() {
        let request_id = Uuid::new_v4();
        let request_resource_version = request_version(7);
        let platform = "defra".to_string();
        let job_spec_digest = sha256_hex(b"job-spec");
        let approved_plan_digest = sha256_hex(b"plan-bytes");
        let approved_plan_job_id = Uuid::new_v4();
        let approved_plan_attempt_id = Uuid::new_v4();
        let approver = "ops-alice".to_string();
        let expiry = Utc::now() + chrono::Duration::hours(1);

        let vlc = VerifiedLiveContext {
            request_id,
            request_resource_version,
            platform: platform.clone(),
            job_spec_digest: job_spec_digest.clone(),
            approved_plan_digest: approved_plan_digest.clone(),
            approved_plan_job_id,
            approved_plan_attempt_id,
            approver: approver.clone(),
            expiry,
            step_job_id: None,
            execution_authority: test_execution_authority(),
            signing_key_id: "signing-key:sha256-test-fixture".to_string(),
            signature: String::new(),
        };

        // Hand-roll the canonical v8 field order to catch accidental drift.
        let mut baseline: Vec<u8> = Vec::new();
        write_bytes(&mut baseline, b"ryuki-v8/verified-live-context");
        write_str(&mut baseline, &request_id.hyphenated().to_string());
        write_u64(&mut baseline, request_resource_version.get());
        write_str(&mut baseline, &platform);
        write_str(&mut baseline, &job_spec_digest);
        write_str(&mut baseline, &approved_plan_digest);
        write_str(
            &mut baseline,
            &approved_plan_job_id.hyphenated().to_string(),
        );
        write_str(
            &mut baseline,
            &approved_plan_attempt_id.hyphenated().to_string(),
        );
        write_str(&mut baseline, &approver);
        write_str(&mut baseline, &datetime_bytes(&expiry));
        write_opt_uuid(&mut baseline, &vlc.step_job_id);
        write_str(&mut baseline, &vlc.execution_authority.assigned_agent_id);
        write_str(
            &mut baseline,
            &vlc.execution_authority
                .assigned_agent_enrollment_id
                .hyphenated()
                .to_string(),
        );
        write_str(
            &mut baseline,
            &vlc.execution_authority.assigned_agent_key_fingerprint,
        );
        write_str(
            &mut baseline,
            &vlc.execution_authority.execution_trust_profile_digest,
        );
        write_str(&mut baseline, &vlc.signing_key_id);

        assert_eq!(
            signing_bytes_vlc(&vlc),
            baseline,
            "v8 signing bytes must include the request version, exact plan row, destination, spec, authority, and key id"
        );
    }

    #[test]
    fn legacy_v6_vlc_without_request_version_is_rejected_by_the_v8_domain() {
        let key = generate_keypair(&mut OsRng);
        let mut legacy = make_vlc(&key);
        let mut legacy_bytes = Vec::new();
        write_bytes(&mut legacy_bytes, b"ryuki-v6/verified-live-context");
        write_str(
            &mut legacy_bytes,
            &legacy.request_id.hyphenated().to_string(),
        );
        write_str(&mut legacy_bytes, &legacy.platform);
        write_str(&mut legacy_bytes, &legacy.job_spec_digest);
        write_str(&mut legacy_bytes, &legacy.approved_plan_digest);
        write_str(
            &mut legacy_bytes,
            &legacy.approved_plan_job_id.hyphenated().to_string(),
        );
        write_str(
            &mut legacy_bytes,
            &legacy.approved_plan_attempt_id.hyphenated().to_string(),
        );
        write_str(&mut legacy_bytes, &legacy.approver);
        write_str(&mut legacy_bytes, &datetime_bytes(&legacy.expiry));
        write_opt_uuid(&mut legacy_bytes, &legacy.step_job_id);
        write_str(
            &mut legacy_bytes,
            &legacy.execution_authority.assigned_agent_id,
        );
        write_str(
            &mut legacy_bytes,
            &legacy
                .execution_authority
                .assigned_agent_enrollment_id
                .hyphenated()
                .to_string(),
        );
        write_str(
            &mut legacy_bytes,
            &legacy.execution_authority.assigned_agent_key_fingerprint,
        );
        write_str(
            &mut legacy_bytes,
            &legacy.execution_authority.execution_trust_profile_digest,
        );
        legacy.signature = B64.encode(key.sign(&legacy_bytes).to_bytes());

        assert!(
            verify_vlc(&legacy, &key.verifying_key()).is_err(),
            "a legacy v6 grant without a request version must not verify under the v8 domain"
        );
    }

    #[test]
    fn legacy_v7_vlc_without_signing_key_id_is_rejected_by_the_v8_domain() {
        let key = generate_keypair(&mut OsRng);
        let mut legacy = make_vlc(&key);
        let mut legacy_bytes = Vec::new();
        write_bytes(&mut legacy_bytes, b"ryuki-v7/verified-live-context");
        write_str(
            &mut legacy_bytes,
            &legacy.request_id.hyphenated().to_string(),
        );
        write_u64(&mut legacy_bytes, legacy.request_resource_version.get());
        write_str(&mut legacy_bytes, &legacy.platform);
        write_str(&mut legacy_bytes, &legacy.job_spec_digest);
        write_str(&mut legacy_bytes, &legacy.approved_plan_digest);
        write_str(
            &mut legacy_bytes,
            &legacy.approved_plan_job_id.hyphenated().to_string(),
        );
        write_str(
            &mut legacy_bytes,
            &legacy.approved_plan_attempt_id.hyphenated().to_string(),
        );
        write_str(&mut legacy_bytes, &legacy.approver);
        write_str(&mut legacy_bytes, &datetime_bytes(&legacy.expiry));
        write_opt_uuid(&mut legacy_bytes, &legacy.step_job_id);
        write_str(
            &mut legacy_bytes,
            &legacy.execution_authority.assigned_agent_id,
        );
        write_str(
            &mut legacy_bytes,
            &legacy
                .execution_authority
                .assigned_agent_enrollment_id
                .hyphenated()
                .to_string(),
        );
        write_str(
            &mut legacy_bytes,
            &legacy.execution_authority.assigned_agent_key_fingerprint,
        );
        write_str(
            &mut legacy_bytes,
            &legacy.execution_authority.execution_trust_profile_digest,
        );
        legacy.signature = B64.encode(key.sign(&legacy_bytes).to_bytes());

        assert!(
            verify_vlc(&legacy, &key.verifying_key()).is_err(),
            "a legacy v7 grant without the signed key id must not verify under the v8 domain"
        );
    }

    #[test]
    fn tampered_vlc_signing_key_id_fails_without_exposing_the_id() {
        let key = generate_keypair(&mut OsRng);
        let mut grant = make_vlc(&key);
        grant.signing_key_id =
            control_plane_grant_key_id(&generate_keypair(&mut OsRng).verifying_key());

        let error = verify_vlc(&grant, &key.verifying_key())
            .expect_err("a substituted key id must fail before signature verification");
        assert!(matches!(error, VerifyError::UnknownControlPlaneGrantKey));
        assert!(!error.to_string().contains(&grant.signing_key_id));
    }

    #[test]
    fn legacy_vlc_without_platform_does_not_deserialize() {
        let key = generate_keypair(&mut OsRng);
        let current = make_vlc(&key);
        let mut json = serde_json::to_value(current).expect("VLC JSON");
        json.as_object_mut().expect("VLC object").remove("platform");
        assert!(
            serde_json::from_value::<VerifiedLiveContext>(json).is_err(),
            "platform is required on the current wire; legacy grants fail closed"
        );
    }

    #[test]
    fn legacy_vlc_without_exact_plan_identity_does_not_deserialize() {
        let key = generate_keypair(&mut OsRng);
        let current = make_vlc(&key);
        let mut json = serde_json::to_value(current).expect("VLC JSON");
        let object = json.as_object_mut().expect("VLC object");
        object.remove("approved_plan_job_id");
        object.remove("approved_plan_attempt_id");
        assert!(
            serde_json::from_value::<VerifiedLiveContext>(json).is_err(),
            "exact approved-plan job and attempt are required on the v7 wire"
        );
    }

    /// A whole-request grant omits the optional step binding from JSON.
    #[test]
    fn vlc_none_step_job_id_omitted_from_json() {
        let key = generate_keypair(&mut OsRng);
        let vlc = make_vlc(&key);
        assert_eq!(vlc.step_job_id, None);

        let json = serde_json::to_string(&vlc).expect("serialise");
        assert!(
            !json.contains("step_job_id"),
            "step_job_id key must be entirely absent from JSON when None, got: {json}"
        );

        // And it still verifies — signing/verifying a None-step_job_id grant
        // is unaffected by the new field's presence in the struct.
        let vk = key.verifying_key();
        assert!(
            verify_vlc(&vlc, &vk).is_ok(),
            "a None step_job_id grant must still verify"
        );
    }

    /// A grant with `step_job_id: Some(id)` signs and verifies successfully —
    /// the new field does not break the happy path for step-scoped grants.
    #[test]
    fn vlc_some_step_job_id_signs_and_verifies() {
        let key = generate_keypair(&mut OsRng);
        let step_job_id = Uuid::new_v4();
        let unsigned = VerifiedLiveContext {
            request_id: Uuid::new_v4(),
            request_resource_version: request_version(7),
            platform: "defra".to_string(),
            job_spec_digest: sha256_hex(b"job-spec"),
            approved_plan_digest: sha256_hex(b"plan-bytes"),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-alice".to_string(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            step_job_id: Some(step_job_id),
            execution_authority: test_execution_authority(),
            signing_key_id: String::new(),
            signature: String::new(),
        };
        let vlc = sign_vlc(unsigned, &key);
        let vk = key.verifying_key();
        assert!(
            verify_vlc(&vlc, &vk).is_ok(),
            "a Some(step_job_id) grant must verify with a matching signature"
        );

        // And the JSON DOES carry the key when Some.
        let json = serde_json::to_string(&vlc).expect("serialise");
        assert!(
            json.contains("step_job_id"),
            "step_job_id key must be present in JSON when Some, got: {json}"
        );
    }

    /// TAMPER: the signature covers `step_job_id`. Signing a grant bound to
    /// step A, then swapping in a DIFFERENT step id B before verification,
    /// must fail — this is what prevents a step-scoped grant from being
    /// replayed against a different step job.
    #[test]
    fn tamper_vlc_step_job_id_fails() {
        let key = generate_keypair(&mut OsRng);
        let step_a = Uuid::new_v4();
        let step_b = Uuid::new_v4();
        assert_ne!(step_a, step_b);

        let unsigned = VerifiedLiveContext {
            request_id: Uuid::new_v4(),
            request_resource_version: request_version(7),
            platform: "defra".to_string(),
            job_spec_digest: sha256_hex(b"job-spec"),
            approved_plan_digest: sha256_hex(b"plan-bytes"),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-alice".to_string(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            step_job_id: Some(step_a),
            execution_authority: test_execution_authority(),
            signing_key_id: String::new(),
            signature: String::new(),
        };
        let mut vlc = sign_vlc(unsigned, &key);
        vlc.step_job_id = Some(step_b); // tamper AFTER signing
        let vk = key.verifying_key();
        assert!(
            verify_vlc(&vlc, &vk).is_err(),
            "swapping step_job_id after signing must invalidate the signature"
        );
    }

    /// TAMPER: stripping step_job_id entirely (Some -> None) after signing
    /// must also fail — an attacker cannot downgrade a step-scoped grant into
    /// an (apparently) unbound legacy grant by dropping the field, because
    /// doing so changes the signed bytes (Some contributes bytes; None
    /// contributes none).
    #[test]
    fn tamper_vlc_step_job_id_stripped_fails() {
        let key = generate_keypair(&mut OsRng);
        let step_a = Uuid::new_v4();

        let unsigned = VerifiedLiveContext {
            request_id: Uuid::new_v4(),
            request_resource_version: request_version(7),
            platform: "defra".to_string(),
            job_spec_digest: sha256_hex(b"job-spec"),
            approved_plan_digest: sha256_hex(b"plan-bytes"),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-alice".to_string(),
            expiry: Utc::now() + chrono::Duration::hours(1),
            step_job_id: Some(step_a),
            execution_authority: test_execution_authority(),
            signing_key_id: String::new(),
            signature: String::new(),
        };
        let mut vlc = sign_vlc(unsigned, &key);
        vlc.step_job_id = None; // tamper: attempt to strip the binding
        let vk = key.verifying_key();
        assert!(
            verify_vlc(&vlc, &vk).is_err(),
            "stripping step_job_id after signing must invalidate the signature"
        );
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
            request_resource_version: request_version(7),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1.2.3".to_string(),
            iac_digest: sha256_hex(b"iac-content"),
            vars: {
                let mut m = BTreeMap::new();
                m.insert("vm_name".to_string(), "web-prod-01".to_string());
                m.insert("vcpu".to_string(), "4".to_string());
                m
            },
            state_key: Some(format!("request-{}", Uuid::new_v4())),
            mode: JobMode::OfflineDryRun,
        };
        let d1 = job_spec_digest(&spec);
        let d2 = job_spec_digest(&spec);
        assert_eq!(d1, d2, "job_spec_digest must be deterministic");

        let mut newer_request = spec.clone();
        newer_request.request_resource_version = request_version(8);
        assert_ne!(
            d1,
            job_spec_digest(&newer_request),
            "the canonical JobSpec digest must bind the request resource version"
        );
    }
}
