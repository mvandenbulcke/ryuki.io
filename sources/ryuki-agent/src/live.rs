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
//!    - the signed deployment and trust-domain identifiers exactly match the
//!      canonical scope pinned by this agent at startup,
//!    - `grant.job_spec_digest == job_spec_digest(job.spec)` (the grant binds
//!      the exact mode, IaC, variables, and Terraform state key),
//!    - `grant.request_id == job.spec.request_id` (the grant is for THIS job),
//!    - `grant.request_resource_version == job.spec.request_resource_version`
//!      (the grant is for the exact monotonic request state that was leased),
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
//! ## Bootstrap note for `pin_cp_grant_authority`
//!
//! [`pin_cp_grant_authority`] validates the closed keyset structure and binds it
//! to the agent's canonical deployment/trust-domain scope. The fetched keyset is
//! only as trustworthy as the transport used to retrieve it. Production CP URLs
//! therefore require HTTPS; plain HTTP is restricted to an explicit loopback
//! development policy. This build pins the authority once at startup and does
//! not refresh it while running. A published rotation or revocation takes effect
//! for an agent only after its next successful restart/bootstrap; runtime keyset
//! refresh and monotonic update enforcement remain future work.

use chrono::Utc;
use thiserror::Error;

use ryuki_protocol::{
    crypto::{
        control_plane_grant_verifying_key, decode_verifying_key, execution_trust_profile_digest,
        job_spec_digest, public_key_fingerprint, validate_control_plane_grant_keyset,
        verify_vlc_with_keyset, VerifyError,
    },
    ControlPlaneGrantKeyDisposition, ControlPlaneGrantKeyset, ControlPlaneGrantScope,
    ExecutionTrustProfile, Job, JobMode,
};

// ---------------------------------------------------------------------------
// Error type for key pinning
// ---------------------------------------------------------------------------

/// Error returned when a CP verification key or keyset cannot be pinned.
#[derive(Debug, Error)]
#[error("failed to pin CP public key: {0}")]
pub struct PinKeyError(#[from] VerifyError);

/// Startup-pinned authority for every control-plane live grant.
///
/// The verification keyset and canonical deployment/trust-domain scope form
/// one trust decision. Keeping them in one value prevents a call site from
/// signature-verifying a grant without also enforcing the local replay scope.
#[derive(Clone)]
pub struct PinnedControlPlaneGrantAuthority {
    keyset: ControlPlaneGrantKeyset,
    scope: ControlPlaneGrantScope,
}

impl std::fmt::Debug for PinnedControlPlaneGrantAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedControlPlaneGrantAuthority")
            .field("keyset_version", &self.keyset.keyset_version)
            .field("key_count", &self.keyset.keys.len())
            // Avoid exposing deployment topology in routine diagnostics.
            .field("scope", &"<configured>")
            .finish()
    }
}

impl PinnedControlPlaneGrantAuthority {
    pub fn keyset(&self) -> &ControlPlaneGrantKeyset {
        &self.keyset
    }

    pub fn scope(&self) -> &ControlPlaneGrantScope {
        &self.scope
    }
}

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

/// Evaluate the live-read admission shared by the pure gate and the pull-loop.
/// LivePlan does not consume a mutation grant, so this check remains usable
/// when control-plane authority bootstrap is unavailable.
pub fn evaluate_live_plan_admission(allow_live: bool) -> LiveDecision {
    if allow_live {
        LiveDecision::Proceed
    } else {
        LiveDecision::Refused("LivePlan requires --allow-live".to_owned())
    }
}

/// Compare the locally authenticated agent key and the execution profile
/// recomputed from current local configuration with the CP-signed successful-
/// plan authority. Callers run this only after the VLC signature gate, and
/// before any Terraform init/plan/backend/provider contact.
pub fn evaluate_execution_trust_binding(
    job: &Job,
    agent_id: &str,
    agent_public_key: &str,
    current_profile: &ExecutionTrustProfile,
) -> LiveDecision {
    let Some(grant) = job.live_context.as_ref() else {
        return LiveDecision::Refused("live execution requires a control-plane grant".to_string());
    };
    let authority = &grant.execution_authority;
    if authority.assigned_agent_id != agent_id {
        return LiveDecision::Refused(
            "grant is assigned to a different planning agent".to_string(),
        );
    }
    if authority.assigned_agent_enrollment_id != job.agent_enrollment_id {
        return LiveDecision::Refused(
            "grant is assigned to a different immutable enrollment".to_string(),
        );
    }
    if authority.assigned_agent_key_fingerprint != public_key_fingerprint(agent_public_key) {
        return LiveDecision::Refused(
            "grant is assigned to a different enrollment key".to_string(),
        );
    }
    if authority.execution_trust_profile_digest != execution_trust_profile_digest(current_profile) {
        return LiveDecision::Refused(
            "current execution trust profile differs from the approved plan".to_string(),
        );
    }
    LiveDecision::Proceed
}

// ---------------------------------------------------------------------------
// evaluate_live_execution — the core trust gate (pure, no I/O)
// ---------------------------------------------------------------------------

/// Decide whether a job may proceed to its next mutating step.
///
/// # Arguments
///
/// - `job` — the leased job received from the control plane.
/// - `cp_grant_authority` — the **pinned** CP Ed25519 verification keyset and
///   canonical deployment/trust-domain scope; obtained once at startup via
///   [`pin_cp_grant_authority`] (wrapping
///   `fetch_cp_keyset_response`).
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
///   3. `verify_vlc_with_keyset(grant, cp_grant_authority.keyset())` succeeds
///   4. `grant.deployment_id == cp_grant_authority.scope().deployment_id()`
///   5. `grant.trust_domain_id == cp_grant_authority.scope().trust_domain_id()`
///   6. `grant.platform == job.platform`
///   7. `grant.job_spec_digest == job_spec_digest(job.spec)`
///   8. `grant.request_id == job.spec.request_id`
///   9. `grant.request_resource_version == job.spec.request_resource_version`
///   10. (#42 slice A) if `grant.step_job_id` is `Some(bound_id)`, then
///       `bound_id == job.id` — a step-scoped grant only authorises the ONE
///       dispatched step job it was minted for, preventing replay across
///       steps and across re-dispatches (a re-dispatch mints a fresh job id).
///       `None` is the whole-request grant shape, so the step-id comparison is
///       skipped.
///   11. `grant.expiry > Utc::now()`
///   12. `replanned_plan_digest == Some(&grant.approved_plan_digest)`
///
/// Any failure → `Refused` with a specific reason string.
pub fn evaluate_live_execution(
    job: &Job,
    cp_grant_authority: &PinnedControlPlaneGrantAuthority,
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
        JobMode::LivePlan => evaluate_live_plan_admission(allow_live),

        // LiveApply mutates.  Every safety invariant must hold.
        JobMode::LiveApply => {
            evaluate_live_apply(job, cp_grant_authority, allow_live, replanned_plan_digest)
        }

        // LiveDestroy also mutates (it DESTROYS the step's applied resources for
        // #42's auto compensating teardown). It requires the SAME step-bound,
        // CP-signed grant rigor as LiveApply, but has NO plan-then-apply digest
        // match: a destroy removes the step's own isolated
        // workspace state, not a pre-approved plan. `replanned_plan_digest` is
        // therefore irrelevant here.
        JobMode::LiveDestroy => evaluate_live_destroy(job, cp_grant_authority, allow_live),
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
    cp_grant_authority: &PinnedControlPlaneGrantAuthority,
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
    match verify_live_grant(
        job,
        cp_grant_authority,
        allow_live,
        mode,
        require_step_bound,
    ) {
        Ok(_) => LiveDecision::Proceed,
        Err(refused) => refused,
    }
}

/// Shared grant checks for the mutating live modes (`LiveApply` /
/// `LiveDestroy`) — checks 1-11, in strict order; the first failure returns a
/// `Refused` decision. Returns the verified grant so the caller can apply its
/// mode-specific final check (LiveApply's plan-then-apply digest match, check
/// 12). Extracted so LiveApply and LiveDestroy share IDENTICAL grant rigor:
/// signature, deployment/trust-domain scope, platform/request binding, step
/// binding, and expiry.
fn verify_live_grant<'g>(
    job: &'g Job,
    cp_grant_authority: &PinnedControlPlaneGrantAuthority,
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
    if verify_vlc_with_keyset(grant, cp_grant_authority.keyset()).is_err() {
        return Err(LiveDecision::Refused(
            "grant signature is not from the control plane".to_owned(),
        ));
    }

    // Check 4: the signed grant must belong to this exact deployment. This is
    // checked only after signature verification so untrusted scope strings do
    // not influence policy, and before the platform comparison so a valid grant
    // cannot cross a deployment boundary even when site names are reused.
    if grant.deployment_id != cp_grant_authority.scope().deployment_id() {
        return Err(LiveDecision::Refused(
            "grant is for a different deployment".to_owned(),
        ));
    }

    // Check 5: the signed grant must belong to this exact trust domain. Shared
    // key material or a matching deployment label in another trust domain does
    // not make the authority interchangeable.
    if grant.trust_domain_id != cp_grant_authority.scope().trust_domain_id() {
        return Err(LiveDecision::Refused(
            "grant is for a different trust domain".to_owned(),
        ));
    }

    // Check 6: the signed grant must authorize this EXACT destination. A grant
    // for another platform remains invalid even when it has a genuine CP
    // signature and an otherwise identical JobSpec.
    if grant.platform != job.platform {
        return Err(LiveDecision::Refused(
            "grant is for a different platform".to_owned(),
        ));
    }

    // Check 7: the signed grant must authorize this EXACT canonical JobSpec.
    // This binds mode, IaC, variables, and state_key before apply/destroy can
    // run. The CP's later result-digest verification is too late to prevent a
    // mutation, so the agent must enforce this independently up front.
    if grant.job_spec_digest != job_spec_digest(&job.spec) {
        return Err(LiveDecision::Refused(
            "grant is for a different job specification".to_owned(),
        ));
    }

    // Check 8: the grant must be for THIS job's request.
    if grant.request_id != job.spec.request_id {
        return Err(LiveDecision::Refused(
            "grant is for a different request".to_owned(),
        ));
    }

    // Check 9: the signed grant and leased spec must name the exact same
    // monotonic request state. The JobSpec digest also commits to this field,
    // but the explicit equality check keeps the freshness fence fail-closed at
    // the live-execution boundary and prevents future digest-shape drift from
    // silently weakening it.
    if grant.request_resource_version != job.spec.request_resource_version {
        return Err(LiveDecision::Refused(
            "grant is for a different request resource version".to_owned(),
        ));
    }

    // Check 10 (#42 slice A / B2): the grant's step binding.
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

    // Check 11: the grant must not be expired.
    if grant.expiry <= Utc::now() {
        return Err(LiveDecision::Refused("grant has expired".to_owned()));
    }

    Ok(grant)
}

/// Inner decision function for `LiveApply` — extracted to keep the match arm
/// readable.  Checks in strict order; the first failure returns `Refused`.
fn evaluate_live_apply(
    job: &Job,
    cp_grant_authority: &PinnedControlPlaneGrantAuthority,
    allow_live: bool,
    replanned_plan_digest: Option<&str>,
) -> LiveDecision {
    // Checks 1-11: the shared grant rigor. LiveApply permits the whole-request
    // (`None`) grant shape, so require_step_bound = false.
    let grant = match verify_live_grant(job, cp_grant_authority, allow_live, "LiveApply", false) {
        Ok(g) => g,
        Err(refused) => return refused,
    };

    // Check 12: plan-then-apply — the plan the agent just produced must match
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
/// Applies the SAME step-bound, CP-signed grant checks as `LiveApply` via
/// [`verify_live_grant`], but NOT the plan-then-apply digest match: a destroy
/// removes the step's OWN isolated `terraform` workspace
/// state — that isolation is the bound — rather than applying a pre-approved
/// plan, so there is no approved-plan digest to compare against. The grant is
/// still step-scoped (it authorises destroying exactly the resources THIS step
/// applied), signature-verified, request/version-bound, and expiry-checked.
fn evaluate_live_destroy(
    job: &Job,
    cp_grant_authority: &PinnedControlPlaneGrantAuthority,
    allow_live: bool,
) -> LiveDecision {
    // require_step_bound = true: a destroy's safety bound IS the step binding,
    // so an unbound whole-request grant must never authorise it.
    match verify_live_grant(job, cp_grant_authority, allow_live, "LiveDestroy", true) {
        Ok(_) => LiveDecision::Proceed,
        Err(refused) => refused,
    }
}

// ---------------------------------------------------------------------------
// pin_cp_keyset — validate and pin the CP verification keyset at startup
// ---------------------------------------------------------------------------

/// Validate the versioned CP Ed25519 keyset returned by
/// `fetch_cp_keyset_response` for use by [`evaluate_live_execution`].
///
/// Call this **once at startup** and hold the result for the lifetime of the
/// process.  A successful return means the key is structurally valid; it does
/// not guarantee it is the legitimate CP keyset (see the bootstrap note in the
/// module doc comment). This function does not refresh the pinned publication
/// at runtime; restart/bootstrap is currently required for rotation or
/// revocation to take effect.
///
/// # Errors
///
/// Returns [`PinKeyError`] if the keyset is malformed, non-canonical, empty,
/// oversized, or contains an invalid Ed25519 public key/id binding.
pub fn pin_cp_keyset(
    keyset: ControlPlaneGrantKeyset,
) -> Result<ControlPlaneGrantKeyset, PinKeyError> {
    validate_control_plane_grant_keyset(&keyset)?;
    Ok(keyset)
}

/// Validate and pin a CP verification keyset together with the only canonical
/// deployment/trust-domain scope this process will accept.
pub fn pin_cp_grant_authority(
    keyset: ControlPlaneGrantKeyset,
    scope: ControlPlaneGrantScope,
) -> Result<PinnedControlPlaneGrantAuthority, PinKeyError> {
    Ok(PinnedControlPlaneGrantAuthority {
        keyset: pin_cp_keyset(keyset)?,
        scope,
    })
}

/// Development compatibility helper for tests and explicitly pinned legacy
/// configuration. Production fetches the complete versioned keyset.
pub fn pin_cp_key(b64: &str) -> Result<ControlPlaneGrantKeyset, PinKeyError> {
    let verifying_key = decode_verifying_key(b64)?;
    let entry =
        control_plane_grant_verifying_key(&verifying_key, ControlPlaneGrantKeyDisposition::Active);
    pin_cp_keyset(ControlPlaneGrantKeyset {
        keyset_version: 1,
        active_key_id: entry.key_id.clone(),
        keys: vec![entry],
    })
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
        ControlPlaneGrantScope, Job, JobLease, JobMode, JobSpec, JobStatus, LiveExecutionAuthority,
        VerifiedLiveContext,
    };
    use std::collections::BTreeMap;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------------

    /// Generate a fresh CP keypair for a single test (parallel-safe: no global
    /// state).
    fn test_scope() -> ControlPlaneGrantScope {
        ControlPlaneGrantScope::new(
            "deployment:test-eu1".to_owned(),
            "trust-domain:ryuki.test".to_owned(),
        )
        .expect("canonical test grant scope")
    }

    fn cp_keypair() -> (ed25519_dalek::SigningKey, PinnedControlPlaneGrantAuthority) {
        let sk = generate_keypair(&mut OsRng);
        let entry = control_plane_grant_verifying_key(
            &sk.verifying_key(),
            ControlPlaneGrantKeyDisposition::Active,
        );
        let keyset = ControlPlaneGrantKeyset {
            keyset_version: 1,
            active_key_id: entry.key_id.clone(),
            keys: vec![entry],
        };
        let authority = pin_cp_grant_authority(keyset, test_scope())
            .expect("valid test keyset and canonical scope must pin");
        (sk, authority)
    }

    fn test_execution_authority() -> LiveExecutionAuthority {
        LiveExecutionAuthority {
            assigned_agent_id: "agent-test".to_string(),
            assigned_agent_enrollment_id: Uuid::nil(),
            assigned_agent_key_fingerprint: "sha256:test".to_string(),
            execution_trust_profile_digest: sha256_hex(b"profile"),
        }
    }

    /// Build a valid, signed [`VerifiedLiveContext`] grant for `request_id`
    /// using `cp_sk`. The grant is valid for 1 hour from now and is bound to
    /// the fixture's `defra` destination. `step_job_id` is `None`; use
    /// [`make_valid_step_grant`] for a step-scoped grant.
    fn make_valid_grant(
        cp_sk: &ed25519_dalek::SigningKey,
        request_id: Uuid,
        approved_plan_digest: &str,
        spec: &JobSpec,
    ) -> VerifiedLiveContext {
        let unsigned = VerifiedLiveContext {
            request_id,
            request_resource_version: spec.request_resource_version,
            deployment_id: test_scope().deployment_id().to_owned(),
            trust_domain_id: test_scope().trust_domain_id().to_owned(),
            platform: "defra".to_owned(),
            job_spec_digest: job_spec_digest(spec),
            approved_plan_digest: approved_plan_digest.to_owned(),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-alice".to_owned(),
            expiry: Utc::now() + Duration::hours(1),
            step_job_id: None,
            execution_authority: test_execution_authority(),
            signing_key_id: String::new(),
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
            request_resource_version: spec.request_resource_version,
            deployment_id: test_scope().deployment_id().to_owned(),
            trust_domain_id: test_scope().trust_domain_id().to_owned(),
            platform: "defra".to_owned(),
            job_spec_digest: job_spec_digest(spec),
            approved_plan_digest: approved_plan_digest.to_owned(),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-alice".to_owned(),
            expiry: Utc::now() + Duration::hours(1),
            step_job_id: Some(step_job_id),
            execution_authority: test_execution_authority(),
            signing_key_id: String::new(),
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
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("positive request resource version"),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1.0.0".to_owned(),
            iac_digest: sha256_hex(b"iac-content"),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode,
        };
        Job {
            id,
            agent_enrollment_id: Uuid::nil(),
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

    #[test]
    fn execution_trust_binding_rejects_owner_enrollment_key_and_profile_drift() {
        use crate::live_exec::{LiveExecutor, StubLiveExecutor};

        let (cp_sk, _) = cp_keypair();
        let agent_key = generate_keypair(&mut OsRng);
        let agent_public_key = encode_verifying_key(&agent_key.verifying_key());
        let agent_id = "agent-test";
        let request_id = Uuid::new_v4();
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        let profile =
            StubLiveExecutor::with_plan(b"plan", ryuki_engine::runners::RunStatus::Applied)
                .execution_trust_profile(&job.spec, &job.platform)
                .expect("stub profile");
        let mut grant = make_valid_grant(&cp_sk, request_id, &sha256_hex(b"plan"), &job.spec);
        grant.execution_authority = LiveExecutionAuthority {
            assigned_agent_id: agent_id.to_string(),
            assigned_agent_enrollment_id: job.agent_enrollment_id,
            assigned_agent_key_fingerprint: public_key_fingerprint(&agent_public_key),
            execution_trust_profile_digest: execution_trust_profile_digest(&profile),
        };
        grant.signature.clear();
        job.live_context = Some(sign_vlc(grant, &cp_sk));

        assert_eq!(
            evaluate_execution_trust_binding(&job, agent_id, &agent_public_key, &profile),
            LiveDecision::Proceed
        );
        assert!(matches!(
            evaluate_execution_trust_binding(&job, "other-agent", &agent_public_key, &profile),
            LiveDecision::Refused(_)
        ));
        let mut wrong_enrollment = job.clone();
        wrong_enrollment.agent_enrollment_id = Uuid::new_v4();
        assert!(matches!(
            evaluate_execution_trust_binding(
                &wrong_enrollment,
                agent_id,
                &agent_public_key,
                &profile
            ),
            LiveDecision::Refused(_)
        ));
        let other_key = generate_keypair(&mut OsRng);
        assert!(matches!(
            evaluate_execution_trust_binding(
                &job,
                agent_id,
                &encode_verifying_key(&other_key.verifying_key()),
                &profile
            ),
            LiveDecision::Refused(_)
        ));
        let mut changed_profile = profile.clone();
        changed_profile.containment_policy_version = "changed".to_string();
        assert!(matches!(
            evaluate_execution_trust_binding(&job, agent_id, &agent_public_key, &changed_profile),
            LiveDecision::Refused(_)
        ));
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
    fn live_grant_refuses_validly_signed_cross_platform_replay() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"the-plan");
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        let mut grant = make_valid_grant(&cp_sk, request_id, &plan_digest, &job.spec);
        grant.platform = "another-platform".to_owned();
        grant.signature.clear();
        job.live_context = Some(sign_vlc(grant, &cp_sk));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&plan_digest)),
            LiveDecision::Refused("grant is for a different platform".to_owned())
        );
    }

    #[test]
    fn live_grant_refuses_validly_signed_cross_deployment_replay() {
        let (cp_sk, authority) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"the-plan");
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        let mut grant = make_valid_grant(&cp_sk, request_id, &plan_digest, &job.spec);
        grant.deployment_id = "deployment:other-eu1".to_owned();
        grant.signature.clear();
        job.live_context = Some(sign_vlc(grant, &cp_sk));

        assert_eq!(
            evaluate_live_execution(&job, &authority, true, Some(&plan_digest)),
            LiveDecision::Refused("grant is for a different deployment".to_owned())
        );
    }

    #[test]
    fn live_grant_refuses_validly_signed_cross_trust_domain_replay() {
        let (cp_sk, authority) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"the-plan");
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        let mut grant = make_valid_grant(&cp_sk, request_id, &plan_digest, &job.spec);
        grant.trust_domain_id = "trust-domain:other.example".to_owned();
        grant.signature.clear();
        job.live_context = Some(sign_vlc(grant, &cp_sk));

        assert_eq!(
            evaluate_live_execution(&job, &authority, true, Some(&plan_digest)),
            LiveDecision::Refused("grant is for a different trust domain".to_owned())
        );
    }

    #[test]
    fn live_grant_scope_tamper_is_rejected_as_invalid_signature() {
        let (cp_sk, authority) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"the-plan");
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        let mut grant = make_valid_grant(&cp_sk, request_id, &plan_digest, &job.spec);
        // Change a signed field without re-signing. Signature rejection must
        // dominate the local scope comparison.
        grant.deployment_id = "deployment:other-eu1".to_owned();
        job.live_context = Some(grant);

        assert_eq!(
            evaluate_live_execution(&job, &authority, true, Some(&plan_digest)),
            LiveDecision::Refused("grant signature is not from the control plane".to_owned())
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
            request_resource_version: job.spec.request_resource_version,
            deployment_id: test_scope().deployment_id().to_owned(),
            trust_domain_id: test_scope().trust_domain_id().to_owned(),
            platform: "defra".to_owned(),
            job_spec_digest: job_spec_digest(&job.spec),
            approved_plan_digest: plan_digest.clone(),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "attacker".to_owned(),
            expiry: Utc::now() + Duration::hours(1),
            step_job_id: None,
            execution_authority: test_execution_authority(),
            signing_key_id: String::new(),
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
    fn live_apply_refused_request_resource_version_mismatch() {
        let (cp_sk, vk) = cp_keypair();
        let request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(b"plan");
        let mut job = make_job(JobMode::LiveApply, request_id, None);
        let mut grant = make_valid_grant(&cp_sk, request_id, &plan_digest, &job.spec);
        grant.request_resource_version = ryuki_protocol::RequestResourceVersion::new(2)
            .expect("positive request resource version");
        grant.signature.clear();
        job.live_context = Some(sign_vlc(grant, &cp_sk));

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, Some(&plan_digest)),
            LiveDecision::Refused("grant is for a different request resource version".to_owned(),),
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
            request_resource_version: job.spec.request_resource_version,
            deployment_id: test_scope().deployment_id().to_owned(),
            trust_domain_id: test_scope().trust_domain_id().to_owned(),
            platform: "defra".to_owned(),
            job_spec_digest: job_spec_digest(&job.spec),
            approved_plan_digest: plan_digest.clone(),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-alice".to_owned(),
            expiry: Utc::now() - Duration::seconds(1), // in the past
            step_job_id: None,
            execution_authority: test_execution_authority(),
            signing_key_id: String::new(),
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
        let key = generate_keypair(&mut OsRng);
        let vk = key.verifying_key();
        let b64 = encode_verifying_key(&vk);
        let pinned = pin_cp_key(&b64).expect("pin must succeed for a valid key");
        assert_eq!(
            pinned.keys[0].public_key, b64,
            "pinned keyset must contain the original public key"
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
