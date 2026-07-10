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
//!    provider-resource mutation, though backend lock/state metadata may
//!    change; no grant needed).
//! 3. `LiveApply` — allowed iff ALL of:
//!    - `allow_live` is true (operator must explicitly enable live execution),
//!    - the job carries a CP-signed [`VerifiedLiveContext`] grant,
//!    - the grant's signature verifies against the **pinned** CP verifying key
//!      (the agent independently trusts only the signed grant, never the bare
//!      `mode` field),
//!    - `grant.job_spec_digest == job_spec_digest(job.spec)` (the grant binds
//!      the exact mode, IaC, variables, and Terraform state key),
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
//! The CP records a signed `LiveRefused` result without requiring the unusable
//! grant to pass validation; every non-refusal mutation result still requires
//! the complete grant checks.
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
    crypto::{decode_verifying_key, job_spec_digest, verify_vlc, VerifyError},
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
///   4. `grant.job_spec_digest == job_spec_digest(job.spec)`
///   5. `grant.request_id == job.spec.request_id`
///   6. (#42 slice A) if `grant.step_job_id` is `Some(bound_id)`, then
///      `bound_id == job.id` — a step-scoped grant only authorises the ONE
///      dispatched step job it was minted for, preventing replay across
///      steps and across re-dispatches (a re-dispatch mints a fresh job id).
///      `None` is the legacy/whole-request grant and is UNCHANGED: this check
///      is skipped entirely.
///   7. `grant.expiry > Utc::now()`
///   8. `replanned_plan_digest == Some(&grant.approved_plan_digest)`
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

        // LivePlan does not mutate provider resources, but Terraform may update
        // backend lock/state metadata. No grant is required, while live access
        // (credentials + network path to the platform) remains explicit.
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

        // LiveDestroy also mutates (it DESTROYS the step's applied resources for
        // #42's auto compensating teardown). It requires the SAME step-bound,
        // CP-signed grant as LiveApply (checks 1-6), but has NO plan-then-apply
        // digest match (check 7): a destroy removes the step's own isolated
        // workspace state, not a pre-approved plan. `replanned_plan_digest` is
        // therefore irrelevant here.
        JobMode::LiveDestroy => evaluate_live_destroy(job, cp_verifying_key, allow_live),
    }
}

/// Verify all mutation authority that is independent of Terraform output.
/// LiveApply callers run this before `plan()` so a bad/expired/tampered grant
/// cannot trigger backend or provider contact, then run
/// [`evaluate_live_execution`] again with the fresh plan digest immediately
/// before mutation. LiveDestroy has no plan digest and uses the same authority
/// checks directly at its mutation boundary.
pub fn evaluate_live_authority(
    job: &Job,
    cp_verifying_key: &VerifyingKey,
    allow_live: bool,
) -> LiveDecision {
    let (mode, require_step_bound) = match job.spec.mode {
        JobMode::LiveApply => ("LiveApply", false),
        JobMode::LiveDestroy => ("LiveDestroy", true),
        _ => {
            return LiveDecision::Refused(
                "live mutation authority requested for a non-mutating mode".to_owned(),
            );
        }
    };
    match verify_live_grant(job, cp_verifying_key, allow_live, mode, require_step_bound) {
        Ok(_) => LiveDecision::Proceed,
        Err(refused) => refused,
    }
}

/// Shared grant checks for the mutating live modes (`LiveApply` /
/// `LiveDestroy`) — checks 1-6, in strict order; the first failure returns a
/// `Refused` decision. Returns the verified grant so the caller can apply its
/// mode-specific final check (LiveApply's plan-then-apply digest match, check
/// 7). Extracted so LiveApply and LiveDestroy share IDENTICAL grant rigor:
/// signature, request binding, step binding, and expiry.
fn verify_live_grant<'g>(
    job: &'g Job,
    cp_verifying_key: &VerifyingKey,
    allow_live: bool,
    mode: &str,
    require_step_bound: bool,
) -> Result<&'g ryuki_protocol::VerifiedLiveContext, LiveDecision> {
    // Check 1: operator must explicitly enable live execution.
    if !allow_live {
        return Err(LiveDecision::Refused(format!(
            "{mode} requires --allow-live"
        )));
    }

    // Check 2: the job MUST carry a CP-signed grant.
    let grant = match job.live_context.as_ref() {
        Some(g) => g,
        None => {
            return Err(LiveDecision::Refused(format!(
                "{mode} requires a control-plane grant"
            )));
        }
    };

    // Check 3: the grant's signature must verify against the PINNED CP key.
    // This is the agent's independent trust check — it does NOT trust the bare
    // `mode` field or the grant fields without cryptographic proof.
    if verify_vlc(grant, cp_verifying_key).is_err() {
        return Err(LiveDecision::Refused(
            "grant signature is not from the control plane".to_owned(),
        ));
    }

    // Check 4: the signed grant must authorize this EXACT canonical JobSpec.
    // This binds mode, IaC, variables, and state_key before apply/destroy can
    // run. The CP's later result-digest verification is too late to prevent a
    // mutation, so the agent must enforce this independently up front.
    if grant.job_spec_digest != job_spec_digest(&job.spec) {
        return Err(LiveDecision::Refused(
            "grant is for a different job specification".to_owned(),
        ));
    }

    // Check 5: the grant must be for THIS job's request.
    if grant.request_id != job.spec.request_id {
        return Err(LiveDecision::Refused(
            "grant is for a different request".to_owned(),
        ));
    }

    // Check 6 (#42 slice A / B2): the grant's step binding.
    //
    // A step-scoped grant (`step_job_id: Some`) may only be used against the ONE
    // dispatched step job it was minted for — closing cross-step replay (a grant
    // for step N presented alongside step M's job) and re-dispatch replay (a
    // re-dispatched step gets a fresh job id; a grant bound to the OLD id must
    // not authorise it).
    //
    // `require_step_bound` (LiveDestroy, #42 B2) additionally rejects a
    // whole-request `None` grant. The signed JobSpec digest already binds mode;
    // this separate policy ensures every destructive rollback is also tied to
    // one dispatched orchestration step.
    match grant.step_job_id {
        Some(bound_id) if bound_id != job.id => {
            return Err(LiveDecision::Refused(
                "grant is bound to a different step job".to_owned(),
            ));
        }
        Some(_) => {}
        None => {
            if require_step_bound {
                return Err(LiveDecision::Refused(format!(
                    "{mode} requires a step-bound grant"
                )));
            }
        }
    }

    // Check 7: the grant must not be expired.
    if grant.expiry <= Utc::now() {
        return Err(LiveDecision::Refused("grant has expired".to_owned()));
    }

    Ok(grant)
}

/// Inner decision function for `LiveApply` — extracted to keep the match arm
/// readable.  Checks in strict order; the first failure returns `Refused`.
fn evaluate_live_apply(
    job: &Job,
    cp_verifying_key: &VerifyingKey,
    allow_live: bool,
    replanned_plan_digest: Option<&str>,
) -> LiveDecision {
    // Checks 1-6: the shared grant rigor. LiveApply tolerates a legacy
    // whole-request (`None`) grant, so require_step_bound = false.
    let grant = match verify_live_grant(job, cp_verifying_key, allow_live, "LiveApply", false) {
        Ok(g) => g,
        Err(refused) => return refused,
    };

    // Check 8: plan-then-apply — the plan the agent just produced must match
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

/// Inner decision function for `LiveDestroy` (#42 auto compensating teardown).
/// Applies the SAME step-bound, CP-signed grant checks as `LiveApply` (checks
/// 1-6 via [`verify_live_grant`]), but NOT the plan-then-apply digest match
/// (check 7): a destroy removes the step's OWN isolated `terraform` workspace
/// state — that isolation is the bound — rather than applying a pre-approved
/// plan, so there is no approved-plan digest to compare against. The grant is
/// still step-scoped (it authorises destroying exactly the resources THIS step
/// applied), signature-verified, request-bound, and expiry-checked.
fn evaluate_live_destroy(
    job: &Job,
    cp_verifying_key: &VerifyingKey,
    allow_live: bool,
) -> LiveDecision {
    // require_step_bound = true: a destroy's safety bound IS the step binding,
    // so an unbound (legacy whole-request) grant must never authorise it.
    match verify_live_grant(job, cp_verifying_key, allow_live, "LiveDestroy", true) {
        Ok(_) => LiveDecision::Proceed,
        Err(refused) => refused,
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
    /// using `cp_sk`.  The grant is valid for 1 hour from now.  `step_job_id`
    /// is `None` — a legacy/whole-request grant (unchanged single-job trust
    /// model). Use [`make_valid_step_grant`] for a step-scoped grant.
    fn make_valid_grant(
        cp_sk: &ed25519_dalek::SigningKey,
        request_id: Uuid,
        approved_plan_digest: &str,
        spec: &JobSpec,
    ) -> VerifiedLiveContext {
        let unsigned = VerifiedLiveContext {
            request_id,
            job_spec_digest: job_spec_digest(spec),
            approved_plan_digest: approved_plan_digest.to_owned(),
            approver: "ops-alice".to_owned(),
            expiry: Utc::now() + Duration::hours(1),
            step_job_id: None,
            signature: String::new(),
        };
        sign_vlc(unsigned, cp_sk)
    }

    /// Build a valid, signed [`VerifiedLiveContext`] grant bound to
    /// `step_job_id` — #42 slice A's step-scoped grant. Otherwise identical to
    /// [`make_valid_grant`].
    fn make_valid_step_grant(
        cp_sk: &ed25519_dalek::SigningKey,
        request_id: Uuid,
        approved_plan_digest: &str,
        step_job_id: Uuid,
        spec: &JobSpec,
    ) -> VerifiedLiveContext {
        let unsigned = VerifiedLiveContext {
            request_id,
            job_spec_digest: job_spec_digest(spec),
            approved_plan_digest: approved_plan_digest.to_owned(),
            approver: "ops-alice".to_owned(),
            expiry: Utc::now() + Duration::hours(1),
            step_job_id: Some(step_job_id),
            signature: String::new(),
        };
        sign_vlc(unsigned, cp_sk)
    }

    /// Build a [`Job`] with the given mode, request_id, and optional grant.
    /// The job's own `id` is a fresh random UUID — use [`make_job_with_id`]
    /// when the test needs to control (or later assert against) the job id,
    /// e.g. for #42 slice A step-scoped grant binding tests.
    fn make_job(mode: JobMode, request_id: Uuid, live_context: Option<VerifiedLiveContext>) -> Job {
        make_job_with_id(Uuid::new_v4(), mode, request_id, live_context)
    }

    /// Build a [`Job`] with an explicit `id`, mode, request_id, and optional
    /// grant. See [`make_job`] for the common case where the id doesn't
    /// matter to the test.
    fn make_job_with_id(
        id: Uuid,
        mode: JobMode,
        request_id: Uuid,
        live_context: Option<VerifiedLiveContext>,
    ) -> Job {
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1.0.0".to_owned(),
            iac_digest: sha256_hex(b"iac-content"),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode,
        };
        Job {
            id,
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
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        job.live_context = Some(make_valid_grant(
            &cp_sk,
            request_id,
            &plan_digest,
            &job.spec,
        ));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&plan_digest)),
            LiveDecision::Proceed,
            "LiveApply happy path must Proceed"
        );
    }

    #[test]
    fn live_grant_refuses_state_key_tamper_before_mutation() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"the-plan");
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        job.live_context = Some(make_valid_grant(
            &cp_sk,
            request_id,
            &plan_digest,
            &job.spec,
        ));
        job.spec.state_key = Some("request-another-state".to_string());

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&plan_digest)),
            LiveDecision::Refused("grant is for a different job specification".to_owned())
        );
    }

    #[test]
    fn live_grant_refuses_mode_tamper_before_destroy() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"the-plan");
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        job.live_context = Some(make_valid_grant(
            &cp_sk,
            request_id,
            &plan_digest,
            &job.spec,
        ));
        job.spec.mode = JobMode::LiveDestroy;

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, None),
            LiveDecision::Refused("grant is for a different job specification".to_owned())
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
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        job.live_context = Some(make_valid_grant(
            &cp_sk,
            request_id,
            &plan_digest,
            &job.spec,
        ));

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
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        let unsigned = VerifiedLiveContext {
            request_id,
            job_spec_digest: job_spec_digest(&job.spec),
            approved_plan_digest: plan_digest.clone(),
            approver: "attacker".to_owned(),
            expiry: Utc::now() + Duration::hours(1),
            step_job_id: None,
            signature: String::new(),
        };
        let forged_grant = sign_vlc(unsigned, &attacker_sk);
        job.live_context = Some(forged_grant);

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
        // Job carries a request_id that does NOT match the grant, while the
        // grant still binds the exact JobSpec so this test reaches that check.
        let mut job = make_job(JobMode::LiveApply, job_request_id, None);
        job.live_context = Some(make_valid_grant(
            &cp_sk,
            grant_request_id,
            &plan_digest,
            &job.spec,
        ));

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
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        let unsigned = VerifiedLiveContext {
            request_id,
            job_spec_digest: job_spec_digest(&job.spec),
            approved_plan_digest: plan_digest.clone(),
            approver: "ops-alice".to_owned(),
            expiry: Utc::now() - Duration::seconds(1), // in the past
            step_job_id: None,
            signature: String::new(),
        };
        let expired_grant = sign_vlc(unsigned, &cp_sk);
        job.live_context = Some(expired_grant);

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
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        job.live_context = Some(make_valid_grant(
            &cp_sk,
            request_id,
            &plan_digest,
            &job.spec,
        ));

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
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        job.live_context = Some(make_valid_grant(
            &cp_sk,
            request_id,
            &approved_digest,
            &job.spec,
        ));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&replanned_digest)),
            LiveDecision::Refused(
                "the plan the agent produced does not match the approved plan".to_owned()
            ),
        );
    }

    // -----------------------------------------------------------------------
    // LiveApply — #42 slice A: step-scoped grant binding
    // -----------------------------------------------------------------------

    /// A step-scoped grant (`step_job_id: Some(bound_id)`) whose `bound_id`
    /// matches the leased job's own `id` must Proceed (all other checks
    /// passing) — the happy path for the new binding.
    #[test]
    fn live_apply_step_grant_matching_job_id_proceeds() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let step_job_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"the-plan");
        let mut job = make_job_with_id(step_job_id, JobMode::LiveApply, request_id, None);
        job.live_context = Some(make_valid_step_grant(
            &cp_sk,
            request_id,
            &plan_digest,
            step_job_id,
            &job.spec,
        ));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&plan_digest)),
            LiveDecision::Proceed,
            "a step grant bound to the leased job's own id must Proceed"
        );
    }

    /// A step-scoped grant bound to a DIFFERENT job id than the one actually
    /// leased must Refuse — this is the replay defence: neither a
    /// cross-step nor a re-dispatched (new job id) presentation of the grant
    /// can be used.
    #[test]
    fn live_apply_step_grant_wrong_job_id_refused() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let bound_step_job_id = Uuid::new_v4();
        let actual_leased_job_id = Uuid::new_v4(); // deliberately different
        assert_ne!(bound_step_job_id, actual_leased_job_id);
        let plan_digest = sha256_hex(b"the-plan");
        let mut job = make_job_with_id(actual_leased_job_id, JobMode::LiveApply, request_id, None);
        job.live_context = Some(make_valid_step_grant(
            &cp_sk,
            request_id,
            &plan_digest,
            bound_step_job_id,
            &job.spec,
        ));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&plan_digest)),
            LiveDecision::Refused("grant is bound to a different step job".to_owned()),
        );
    }

    // -- #42 slice B2-1: LiveDestroy gate -----------------------------------

    /// LiveDestroy proceeds under a valid step-bound grant WITHOUT any
    /// replanned plan digest — a destroy removes the step's own applied state,
    /// so there is no plan-then-apply digest to match (the key difference from
    /// LiveApply). It still requires --allow-live, a CP-signed grant, the right
    /// request, the right step-job binding, and an unexpired grant.
    #[test]
    fn live_destroy_valid_step_grant_proceeds_without_digest() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        let mut job = make_job_with_id(job_id, JobMode::LiveDestroy, request_id, None);
        job.live_context = Some(make_valid_step_grant(
            &cp_sk,
            request_id,
            &sha256_hex(b"plan"),
            job_id,
            &job.spec,
        ));

        // No plan digest supplied — LiveDestroy must still Proceed.
        assert_eq!(
            evaluate_live_execution(&job, &vk, true, None),
            LiveDecision::Proceed,
        );
    }

    /// A LiveDestroy grant bound to a DIFFERENT step job is refused (the same
    /// step-binding rigor as LiveApply).
    #[test]
    fn live_destroy_step_grant_wrong_job_id_refused() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let bound = Uuid::new_v4();
        let leased = Uuid::new_v4();
        assert_ne!(bound, leased);
        let mut job = make_job_with_id(leased, JobMode::LiveDestroy, request_id, None);
        job.live_context = Some(make_valid_step_grant(
            &cp_sk,
            request_id,
            &sha256_hex(b"plan"),
            bound,
            &job.spec,
        ));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, None),
            LiveDecision::Refused("grant is bound to a different step job".to_owned()),
        );
    }

    /// LiveDestroy requires --allow-live.
    #[test]
    fn live_destroy_refused_allow_live_false() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        let mut job = make_job_with_id(job_id, JobMode::LiveDestroy, request_id, None);
        job.live_context = Some(make_valid_step_grant(
            &cp_sk,
            request_id,
            &sha256_hex(b"plan"),
            job_id,
            &job.spec,
        ));

        assert_eq!(
            evaluate_live_execution(&job, &vk, false, None),
            LiveDecision::Refused("LiveDestroy requires --allow-live".to_owned()),
        );
    }

    /// SECURITY (#42 B2, Codex finding): a LiveDestroy must be refused if the
    /// grant is UNBOUND (`step_job_id: None`, a whole-request grant). The
    /// JobSpec digest binds mode, while this additional policy ensures a destroy
    /// is also tied to one dispatched orchestration step.
    #[test]
    fn live_destroy_unbound_grant_refused() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        // make_valid_grant mints an UNBOUND grant (step_job_id: None) for the
        // request — exactly a legacy whole-request LiveApply grant.
        let mut job = make_job_with_id(Uuid::new_v4(), JobMode::LiveDestroy, request_id, None);
        job.live_context = Some(make_valid_grant(
            &cp_sk,
            request_id,
            &sha256_hex(b"plan"),
            &job.spec,
        ));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, None),
            LiveDecision::Refused("LiveDestroy requires a step-bound grant".to_owned()),
        );
    }

    /// A `step_job_id: None` grant (the legacy/whole-request grant) is
    /// UNCHANGED by this slice: it Proceeds regardless of which job id it is
    /// presented alongside, exactly as it did before `step_job_id` existed.
    #[test]
    fn live_apply_none_step_job_id_unaffected_by_job_id() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"the-plan");
        // Use an arbitrary job id — a None grant must not care what it is.
        let mut job = make_job_with_id(Uuid::new_v4(), JobMode::LiveApply, request_id, None);
        let grant = make_valid_grant(&cp_sk, request_id, &plan_digest, &job.spec);
        assert_eq!(grant.step_job_id, None);
        job.live_context = Some(grant);

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&plan_digest)),
            LiveDecision::Proceed,
            "a None step_job_id grant must Proceed regardless of the job's id (unchanged behavior)"
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
