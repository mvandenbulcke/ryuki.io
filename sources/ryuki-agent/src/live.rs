//! Agent-side live-execution trust gate (S5b-1).
//!
//! ## Responsibility
//!
//! Before the agent mutates any real infrastructure it calls
//! [`evaluate_live_execution`].  That function is **pure** (no I/O, no
//! network) and is the single choke-point for every live-execution safety
//! invariant:
//!
//! 1. `OfflineDryRun` — always allowed (no platform contact, no grant needed).
//! 2. `LivePlan` — allowed iff `allow_live` is set (reads live state; no
//!    mutation, no grant needed).
//! 3. `LiveApply` — allowed iff ALL of:
//!    - `allow_live` is true (operator must explicitly enable live execution),
//!    - the job carries a CP-signed [`VerifiedLiveContext`] grant,
//!    - the grant's signature verifies against the **pinned** CP verifying key
//!      (the agent independently trusts only the signed grant, never the bare
//!      `mode` field),
//!    - `grant.request_id == job.spec.request_id` (the grant is for THIS job),
//!    - `grant.expiry > Utc::now()` (the grant has not expired), and
//!    - `replanned_plan_digest == Some(grant.approved_plan_digest)` (the plan
//!      the agent just produced matches the plan an operator reviewed and the
//!      CP signed off on — plan-then-apply; never apply an unreviewed plan).
//!
//! A [`LiveDecision::Refused`] carries the human-readable reason for the
//! refusal.  The caller (S5b-2) maps a refused decision to a
//! [`JobResultStatus::LiveRefused`] signed result and POSTs it back to the CP so
//! the CP records the refusal.
//!
//! NOTE for S5b-2 (CP-side gap): the current CP `LiveApply` result verifier
//! requires a present, valid, matching, unexpired grant BEFORE it records any
//! result. A refusal whose CAUSE is a missing/forged/expired/mismatched grant
//! would therefore be rejected by that path rather than recorded as
//! `LiveRefused`. S5b-2 must add a CP-side `LiveRefused` acceptance branch that
//! records the refusal (and its reason) WITHOUT requiring grant validity — the
//! refusal is itself the report that the grant was unusable.
//!
//! ## TOFU note for `pin_cp_key`
//!
//! [`pin_cp_key`] wraps [`ryuki_protocol::decode_verifying_key`].  The fetched
//! key is only as trustworthy as the transport used to retrieve it.  In
//! production the CP URL MUST use HTTPS (TLS chain verified against a trusted
//! CA, or certificate-pinned).  Fetching over plain `http://` exposes the key
//! to a MITM who can substitute their own key and forge grants; the agent logs
//! a warning when the CP URL is `http://`.  Operators who need stronger
//! bootstrapping guarantees should pin the CP public key via the agent's config
//! file rather than relying solely on the TOFU fetch.

use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use ryuki_protocol::{
    crypto::{decode_verifying_key, verify_vlc, VerifyError},
    Job, JobMode,
};

// ---------------------------------------------------------------------------
// Error type for key pinning
// ---------------------------------------------------------------------------

/// Error returned by [`pin_cp_key`] when the supplied base64 cannot be
/// decoded into a valid Ed25519 verifying key.
#[derive(Debug, Error)]
#[error("failed to pin CP public key: {0}")]
pub struct PinKeyError(#[from] VerifyError);

// ---------------------------------------------------------------------------
// LiveDecision
// ---------------------------------------------------------------------------

/// The outcome of [`evaluate_live_execution`].
///
/// The caller must act on `Refused` BEFORE performing any mutating step.
/// S5b-2 wires `Refused` → a [`ryuki_protocol::JobResultStatus::LiveRefused`]
/// signed result that is POSTed back to the CP.
#[derive(Debug, PartialEq, Eq)]
pub enum LiveDecision {
    /// The job may proceed to the next stage.
    Proceed,
    /// The agent refuses to execute — the contained string is a human-readable
    /// reason suitable for inclusion in the signed result's evidence.
    Refused(String),
}

// ---------------------------------------------------------------------------
// evaluate_live_execution — the core trust gate (pure, no I/O)
// ---------------------------------------------------------------------------

/// Decide whether a job may proceed to its next mutating step.
///
/// # Arguments
///
/// - `job` — the leased job received from the control plane.
/// - `cp_verifying_key` — the **pinned** CP Ed25519 verifying key; obtained
///   once at startup via [`pin_cp_key`] (wrapping `fetch_cp_public_key`).
///   The gate verifies the [`VerifiedLiveContext`] grant's signature against
///   this key so it cannot trust a tampered or forged grant.
/// - `allow_live` — the value of [`crate::config::AgentConfig::allow_live`];
///   must be `true` for any job that contacts real infrastructure.
/// - `replanned_plan_digest` — the SHA-256 hex digest of the plan the agent
///   just produced (plan-then-apply contract).  `None` means no plan was
///   produced yet (or the plan step was skipped), which causes `LiveApply` to
///   be refused.
///
/// # Rule order (fail-closed)
///
/// Every check that fails immediately returns `Refused` — the agent never
/// proceeds past a failed check.  Checks are evaluated in the order listed
/// below; the first failure wins.
///
/// `OfflineDryRun` → `Proceed` unconditionally.
/// `LivePlan` → `Proceed` iff `allow_live`; else `Refused`.
/// `LiveApply` → `Proceed` iff ALL of (checked in order):
///   1. `allow_live` is `true`
///   2. `job.live_context` is `Some(grant)`
///   3. `verify_vlc(grant, cp_verifying_key)` succeeds
///   4. `grant.request_id == job.spec.request_id`
///   5. `grant.expiry > Utc::now()`
///   6. `replanned_plan_digest == Some(&grant.approved_plan_digest)`
///
/// Any failure → `Refused` with a specific reason string.
pub fn evaluate_live_execution(
    job: &Job,
    cp_verifying_key: &VerifyingKey,
    allow_live: bool,
    replanned_plan_digest: Option<&str>,
) -> LiveDecision {
    match job.spec.mode {
        // OfflineDryRun never touches a platform and never requires a grant.
        // allow_live is irrelevant for this path.
        JobMode::OfflineDryRun => LiveDecision::Proceed,

        // LivePlan reads live state but does not mutate.  No grant required,
        // but live access (credentials + network path to the platform) must
        // be explicitly enabled.
        JobMode::LivePlan => {
            if allow_live {
                LiveDecision::Proceed
            } else {
                LiveDecision::Refused("LivePlan requires --allow-live".to_owned())
            }
        }

        // LiveApply mutates.  Every safety invariant must hold.
        JobMode::LiveApply => {
            evaluate_live_apply(job, cp_verifying_key, allow_live, replanned_plan_digest)
        }
    }
}

/// Inner decision function for `LiveApply` — extracted to keep the match arm
/// readable.  Checks in strict order; the first failure returns `Refused`.
fn evaluate_live_apply(
    job: &Job,
    cp_verifying_key: &VerifyingKey,
    allow_live: bool,
    replanned_plan_digest: Option<&str>,
) -> LiveDecision {
    // Check 1: operator must explicitly enable live execution.
    if !allow_live {
        return LiveDecision::Refused("LiveApply requires --allow-live".to_owned());
    }

    // Check 2: the job MUST carry a CP-signed grant.
    let grant = match job.live_context.as_ref() {
        Some(g) => g,
        None => {
            return LiveDecision::Refused("LiveApply requires a control-plane grant".to_owned());
        }
    };

    // Check 3: the grant's signature must verify against the PINNED CP key.
    // This is the agent's independent trust check — it does NOT trust the bare
    // `mode` field or the grant fields without cryptographic proof.
    if verify_vlc(grant, cp_verifying_key).is_err() {
        return LiveDecision::Refused("grant signature is not from the control plane".to_owned());
    }

    // Check 4: the grant must be for THIS job's request.
    if grant.request_id != job.spec.request_id {
        return LiveDecision::Refused("grant is for a different request".to_owned());
    }

    // Check 5: the grant must not be expired.
    if grant.expiry <= Utc::now() {
        return LiveDecision::Refused("grant has expired".to_owned());
    }

    // Check 6: plan-then-apply — the plan the agent just produced must match
    // the plan an operator reviewed and the CP signed off on.
    match replanned_plan_digest {
        None => LiveDecision::Refused("no plan digest available".to_owned()),
        Some(digest) => {
            if digest == grant.approved_plan_digest {
                LiveDecision::Proceed
            } else {
                LiveDecision::Refused(
                    "the plan the agent produced does not match the approved plan".to_owned(),
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// pin_cp_key — decode and pin the CP verifying key at startup
// ---------------------------------------------------------------------------

/// Decode a base64-encoded CP Ed25519 verifying key returned by
/// `fetch_cp_public_key` into a [`VerifyingKey`] suitable for passing to
/// [`evaluate_live_execution`].
///
/// Call this **once at startup** and hold the result for the lifetime of the
/// process.  A successful return means the key is structurally valid; it does
/// not guarantee it is the legitimate CP key (see the TOFU note in the module
/// doc comment).
///
/// # Errors
///
/// Returns [`PinKeyError`] if the string is not valid base64, if the decoded
/// bytes are not 32 bytes, or if the bytes do not form a valid Ed25519 point.
pub fn pin_cp_key(b64: &str) -> Result<VerifyingKey, PinKeyError> {
    Ok(decode_verifying_key(b64)?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use rand::rngs::OsRng;
    use ryuki_protocol::{
        crypto::{encode_verifying_key, generate_keypair, sha256_hex, sign_vlc},
        Job, JobLease, JobMode, JobSpec, JobStatus, VerifiedLiveContext,
    };
    use std::collections::BTreeMap;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------------

    /// Generate a fresh CP keypair for a single test (parallel-safe: no global
    /// state).
    fn cp_keypair() -> (ed25519_dalek::SigningKey, VerifyingKey) {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    /// Build a valid, signed [`VerifiedLiveContext`] grant for `request_id`
    /// using `cp_sk`.  The grant is valid for 1 hour from now.
    fn make_valid_grant(
        cp_sk: &ed25519_dalek::SigningKey,
        request_id: Uuid,
        approved_plan_digest: &str,
    ) -> VerifiedLiveContext {
        let unsigned = VerifiedLiveContext {
            request_id,
            approved_plan_digest: approved_plan_digest.to_owned(),
            approver: "ops-alice".to_owned(),
            expiry: Utc::now() + Duration::hours(1),
            signature: String::new(),
        };
        sign_vlc(unsigned, cp_sk)
    }

    /// Build a [`Job`] with the given mode, request_id, and optional grant.
    fn make_job(mode: JobMode, request_id: Uuid, live_context: Option<VerifiedLiveContext>) -> Job {
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1.0.0".to_owned(),
            iac_digest: sha256_hex(b"iac-content"),
            vars: BTreeMap::new(),
            mode,
        };
        Job {
            id: Uuid::new_v4(),
            platform: "defra".to_owned(),
            spec,
            status: JobStatus::Running,
            lease: Some(JobLease {
                attempt_id: Uuid::new_v4(),
                lease_generation: 1,
                fencing_token: Uuid::new_v4().to_string(),
                deadline: Utc::now() + Duration::minutes(5),
                cp_nonce: Uuid::new_v4().to_string(),
            }),
            live_context,
        }
    }

    // -----------------------------------------------------------------------
    // OfflineDryRun — always Proceed
    // -----------------------------------------------------------------------

    #[test]
    fn offline_dry_run_proceeds_allow_live_false() {
        let (_, vk) = cp_keypair();
        let job = make_job(JobMode::OfflineDryRun, Uuid::new_v4(), None);
        assert_eq!(
            evaluate_live_execution(&job, &vk, false, None),
            LiveDecision::Proceed,
            "OfflineDryRun must Proceed regardless of allow_live"
        );
    }

    #[test]
    fn offline_dry_run_proceeds_allow_live_true() {
        let (_, vk) = cp_keypair();
        let job = make_job(JobMode::OfflineDryRun, Uuid::new_v4(), None);
        assert_eq!(
            evaluate_live_execution(&job, &vk, true, None),
            LiveDecision::Proceed,
            "OfflineDryRun must Proceed regardless of allow_live"
        );
    }

    // -----------------------------------------------------------------------
    // LivePlan
    // -----------------------------------------------------------------------

    #[test]
    fn live_plan_allow_live_true_proceeds() {
        let (_, vk) = cp_keypair();
        let job = make_job(JobMode::LivePlan, Uuid::new_v4(), None);
        assert_eq!(
            evaluate_live_execution(&job, &vk, true, None),
            LiveDecision::Proceed,
            "LivePlan with allow_live=true must Proceed"
        );
    }

    #[test]
    fn live_plan_allow_live_false_refused() {
        let (_, vk) = cp_keypair();
        let job = make_job(JobMode::LivePlan, Uuid::new_v4(), None);
        assert_eq!(
            evaluate_live_execution(&job, &vk, false, None),
            LiveDecision::Refused("LivePlan requires --allow-live".to_owned()),
            "LivePlan with allow_live=false must be Refused"
        );
    }

    // -----------------------------------------------------------------------
    // LiveApply — happy path
    // -----------------------------------------------------------------------

    #[test]
    fn live_apply_happy_path_proceeds() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"the-plan");
        let grant = make_valid_grant(&cp_sk, request_id, &plan_digest);
        let job = make_job(JobMode::LiveApply, request_id, Some(grant));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&plan_digest)),
            LiveDecision::Proceed,
            "LiveApply happy path must Proceed"
        );
    }

    // -----------------------------------------------------------------------
    // LiveApply — each refusal path
    // -----------------------------------------------------------------------

    #[test]
    fn live_apply_refused_allow_live_false() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"plan");
        let grant = make_valid_grant(&cp_sk, request_id, &plan_digest);
        let job = make_job(JobMode::LiveApply, request_id, Some(grant));

        assert_eq!(
            evaluate_live_execution(&job, &vk, false, Some(&plan_digest)),
            LiveDecision::Refused("LiveApply requires --allow-live".to_owned()),
        );
    }

    #[test]
    fn live_apply_refused_no_grant() {
        let (_, vk) = cp_keypair();
        let job = make_job(JobMode::LiveApply, Uuid::new_v4(), None);

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some("digest")),
            LiveDecision::Refused("LiveApply requires a control-plane grant".to_owned()),
        );
    }

    #[test]
    fn live_apply_refused_wrong_signing_key() {
        // Grant is signed by a DIFFERENT key (attacker key), not the CP key.
        let (cp_sk_real, vk_real) = cp_keypair();
        let (attacker_sk, _) = cp_keypair();

        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"plan");

        // Sign with the attacker key — verify_vlc against the real CP vk must fail.
        let unsigned = VerifiedLiveContext {
            request_id,
            approved_plan_digest: plan_digest.clone(),
            approver: "attacker".to_owned(),
            expiry: Utc::now() + Duration::hours(1),
            signature: String::new(),
        };
        let forged_grant = sign_vlc(unsigned, &attacker_sk);
        let job = make_job(JobMode::LiveApply, request_id, Some(forged_grant));

        let _ = cp_sk_real; // unused after vk_real extracted above

        assert_eq!(
            evaluate_live_execution(&job, &vk_real, true, Some(&plan_digest)),
            LiveDecision::Refused("grant signature is not from the control plane".to_owned()),
        );
    }

    #[test]
    fn live_apply_refused_request_id_mismatch() {
        let (cp_sk, vk) = cp_keypair();
        let grant_request_id = Uuid::new_v4();
        let job_request_id = Uuid::new_v4(); // deliberately different
        let plan_digest = sha256_hex(b"plan");
        let grant = make_valid_grant(&cp_sk, grant_request_id, &plan_digest);
        // Job carries a request_id that does NOT match the grant.
        let job = make_job(JobMode::LiveApply, job_request_id, Some(grant));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&plan_digest)),
            LiveDecision::Refused("grant is for a different request".to_owned()),
        );
    }

    #[test]
    fn live_apply_refused_expired_grant() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"plan");
        // Build and sign a grant that is already expired.
        let unsigned = VerifiedLiveContext {
            request_id,
            approved_plan_digest: plan_digest.clone(),
            approver: "ops-alice".to_owned(),
            expiry: Utc::now() - Duration::seconds(1), // in the past
            signature: String::new(),
        };
        let expired_grant = sign_vlc(unsigned, &cp_sk);
        let job = make_job(JobMode::LiveApply, request_id, Some(expired_grant));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&plan_digest)),
            LiveDecision::Refused("grant has expired".to_owned()),
        );
    }

    #[test]
    fn live_apply_refused_no_plan_digest() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"plan");
        let grant = make_valid_grant(&cp_sk, request_id, &plan_digest);
        let job = make_job(JobMode::LiveApply, request_id, Some(grant));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, None),
            LiveDecision::Refused("no plan digest available".to_owned()),
        );
    }

    #[test]
    fn live_apply_refused_plan_digest_mismatch() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let approved_digest = sha256_hex(b"approved-plan");
        let replanned_digest = sha256_hex(b"diverged-plan"); // different!
        let grant = make_valid_grant(&cp_sk, request_id, &approved_digest);
        let job = make_job(JobMode::LiveApply, request_id, Some(grant));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&replanned_digest)),
            LiveDecision::Refused(
                "the plan the agent produced does not match the approved plan".to_owned()
            ),
        );
    }

    // -----------------------------------------------------------------------
    // pin_cp_key — roundtrip and rejection of malformed input
    // -----------------------------------------------------------------------

    #[test]
    fn pin_cp_key_roundtrip() {
        let (_, vk) = cp_keypair();
        let b64 = encode_verifying_key(&vk);
        let pinned = pin_cp_key(&b64).expect("pin must succeed for a valid key");
        assert_eq!(
            pinned.as_bytes(),
            vk.as_bytes(),
            "pinned key bytes must match the original"
        );
    }

    #[test]
    fn pin_cp_key_rejects_malformed_base64() {
        let result = pin_cp_key("not-valid-base64!!!");
        assert!(
            result.is_err(),
            "malformed base64 must return an error from pin_cp_key"
        );
    }

    #[test]
    fn pin_cp_key_rejects_wrong_length() {
        // A valid base64 string that decodes to only 10 bytes — not a 32-byte key.
        // base64(b"\x00" * 10) = "AAAAAAAAAAAAAAAA" (16 chars, no padding because
        // 10 % 3 == 1 → 2 padding chars: "AAAAAAAAAAAAAA==").
        let short = "AAAAAAAAAAAAAA==";
        let result = pin_cp_key(short);
        assert!(
            result.is_err(),
            "base64 with wrong key length must return an error"
        );
    }
}
