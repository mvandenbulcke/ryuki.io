//! Signed result production — the security core of the agent.
//!
//! `build_signed_result` constructs a `ResultBody` whose `SignedEnvelope` passes
//! ALL 9 steps of the CP verifier (`post_job_result_with_pool` in
//! `ryuki-api/src/agents.rs`).
//!
//! ## Field-source table (mirror of verifier checks)
//!
//! | Envelope field          | Source                                                         | Verifier step |
//! |-------------------------|----------------------------------------------------------------|---------------|
//! | `agent_id`              | `agent_id` arg (== token identity)                             | Step 1        |
//! | `platform`              | `job.platform`                                                 | Fix 3a        |
//! | `job_id`                | `job.id`                                                       | Step 4        |
//! | `attempt_id`            | `job.lease.attempt_id`                                         | Step 4        |
//! | `lease_generation`      | `job.lease.lease_generation`                                   | Step 4        |
//! | `cp_nonce`              | `job.lease.cp_nonce`                                           | Step 4 (CT)   |
//! | `request_id`            | `job.spec.request_id`                                          | Fix 3b        |
//! | `result_id`             | `Uuid::new_v4()` — generated once, outbox-stable               | Step 5        |
//! | `mode`                  | `job.spec.mode`                                                | Fix 3a        |
//! | `status`                | mapped from `RunStatus` → `JobResultStatus`                    | Step 5        |
//! | `job_spec_digest`       | `ryuki_protocol::job_spec_digest(&job.spec)`                   | Step 7        |
//! | `approved_plan_digest`  | `None` for non-LiveApply; `Some(d)` for LiveApply+Applied      | Step 8        |
//! | `evidence_digest`       | `sha256_hex(&evidence.evidence_bytes)`                         | Step 6        |
//! | `redaction_policy_version` | `REDACTION_POLICY_VERSION` constant                         | Stored        |
//! | `timestamp`             | `Utc::now()`                                                   | Stored        |
//! | `key_id`                | `identity.public_key_b64()`                                    | Step 3        |
//! | `signature`             | `ryuki_protocol::sign(envelope, signing_key)`                  | Step 3        |
//!
//! The `JobResult` outer fields are then set to EQUAL the signed envelope fields
//! (verifier step 5 checks all five equality constraints).

use chrono::Utc;
use ryuki_engine::runners::RunStatus;
use ryuki_protocol::{
    job_spec_digest, sha256_hex, sign, Job, JobMode, JobResult, JobResultStatus, SignedEnvelope,
};
use thiserror::Error;
use uuid::Uuid;

use crate::executor::Evidence;
use crate::identity::AgentIdentity;

// ---------------------------------------------------------------------------
// ResultBody — mirrors ryuki-api/src/agents.rs exactly
// ---------------------------------------------------------------------------

/// Body posted to `POST /api/agents/{id}/jobs/{job}/result`.
///
/// This is a LOCAL mirror of the CP-side `ResultBody` struct in
/// `ryuki-api/src/agents.rs`.  The shapes MUST match exactly (same field
/// names, same types) because the CP deserialises this JSON directly.
///
/// `evidence` is a `Vec<u8>` serialised as a JSON byte array by serde.
/// The CP recomputes `sha256_hex(evidence)` and checks it against
/// `job_result.evidence_digest`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResultBody {
    pub job_result: JobResult,
    /// Raw scrubbed evidence bytes.  SHA-256 of this MUST equal
    /// `job_result.evidence_digest` and `job_result.signed_envelope.evidence_digest`.
    #[serde(default)]
    pub evidence: Vec<u8>,
    /// Optional structured evidence (stored as JSONB).
    #[serde(default)]
    pub evidence_json: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Redaction policy version
// ---------------------------------------------------------------------------

/// Identifier (opaque slug, not a semver number) for the redaction policy this
/// agent applies. Bound into the signed envelope so the CP can track which
/// scrubbing rules were applied — and the CP only accepts results under a policy
/// it recognises. Re-exported from `ryuki_protocol` so agent emission and CP
/// acceptance ([`ryuki_protocol::SUPPORTED_REDACTION_POLICY_VERSIONS`]) share one
/// source of truth and cannot drift. Bump the protocol constant when the
/// scrubbing ruleset changes.
pub const REDACTION_POLICY_VERSION: &str = ryuki_protocol::REDACTION_POLICY_VERSION;

// ---------------------------------------------------------------------------
// RunStatus → JobResultStatus mapping
// ---------------------------------------------------------------------------

/// Map a runner `RunStatus` to the `JobResultStatus` the agent may report.
///
/// Mapping table:
///
/// | RunStatus            | JobResultStatus |
/// |----------------------|-----------------|
/// | Validated            | CheckOk         |
/// | CheckOk              | CheckOk         |
/// | Planned              | Planned         |
/// | Failed               | Failed          |
/// | RunnerUnavailable    | Failed          |
/// | WorkspaceError       | Failed          |
/// | Applied (live, S5b)  | Applied         |
/// | Changed  (live, S5b) | Applied         |
pub fn map_run_status(status: &RunStatus) -> JobResultStatus {
    match status {
        RunStatus::Validated | RunStatus::CheckOk => JobResultStatus::CheckOk,
        RunStatus::Planned => JobResultStatus::Planned,
        RunStatus::Failed | RunStatus::RunnerUnavailable | RunStatus::WorkspaceError => {
            JobResultStatus::Failed
        }
        // Applied / Changed are live-mode outcomes; the executor guards against
        // these being returned for OfflineDryRun, but map defensively anyway.
        RunStatus::Applied | RunStatus::Changed => JobResultStatus::Applied,
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ResultError {
    #[error("job has no active lease — cannot build result without attempt_id / cp_nonce")]
    NoLease,
    #[error(
        "refusing to sign a live-mutation status ({status:?}) for non-live job mode ({mode:?}) — \
         a dry-run/plan must never report Applied"
    )]
    LiveStatusInNonLiveMode {
        mode: JobMode,
        status: JobResultStatus,
    },
    #[error(
        "approved_plan_digest must be None for non-LiveApply mode ({mode:?}) — \
         the CP rejects non-live results that carry a plan digest"
    )]
    PlanDigestOnNonLive { mode: JobMode },
    #[error(
        "LiveApply result MUST carry approved_plan_digest — the CP live-apply gate \
         requires the digest to check equality with the grant (a refusal uses \
         build_refused_result instead)"
    )]
    MissingPlanDigestForLiveApply,
    #[error("serialisation error: {0}")]
    Serialise(String),
}

// ---------------------------------------------------------------------------
// build_signed_result — the signing core
// ---------------------------------------------------------------------------

/// Construct a fully-signed `ResultBody` ready to POST to the CP.
///
/// ## `approved_plan_digest` rules (fail-closed)
///
/// - `OfflineDryRun` or `LivePlan`: MUST be `None` — else `PlanDigestOnNonLive`.
/// - `LiveApply` (ANY status — Applied or Failed): MUST be `Some(d)` — else
///   `MissingPlanDigestForLiveApply`.  `d` is the SHA-256 hex of the plan the
///   agent re-ran and confirmed matches the grant's `approved_plan_digest`. Every
///   non-refusal LiveApply result goes through the CP's grant-checked branch,
///   which requires the digest; a refusal uses `build_refused_result` instead.
///
/// The mode/status consistency guard (non-live mode producing `Applied` →
/// `LiveStatusInNonLiveMode`) runs BEFORE the digest checks.
///
/// ## Idempotency
/// `result_id` is generated with `Uuid::new_v4()` INSIDE this function.  The
/// caller MUST persist the returned `ResultBody` to the durable outbox BEFORE
/// making the network POST so that retries reuse the same `result_id`.
///
/// ## Panics
/// None — the function is fail-closed via `Result`.
pub fn build_signed_result(
    identity: &AgentIdentity,
    agent_id: &str,
    job: &Job,
    evidence: &Evidence,
    approved_plan_digest: Option<String>,
) -> Result<ResultBody, ResultError> {
    // Require an active lease — cannot sign without attempt_id and cp_nonce.
    let lease = job.lease.as_ref().ok_or(ResultError::NoLease)?;

    // Generate the idempotency key once.  The outbox persists it so retries
    // replay the same result_id rather than producing duplicates.
    let result_id = Uuid::new_v4();

    // Map runner outcome to the protocol status the CP accepts.
    let result_status = map_run_status(&evidence.status);

    // FAIL CLOSED: a non-live job (OfflineDryRun / LivePlan) must NEVER report a
    // live-mutation status. Applied/Changed from a dry-run means the runner
    // mutated something it must not have — refuse to sign rather than let the CP
    // record it as Succeeded.
    if matches!(job.spec.mode, JobMode::OfflineDryRun | JobMode::LivePlan)
        && matches!(result_status, JobResultStatus::Applied)
    {
        return Err(ResultError::LiveStatusInNonLiveMode {
            mode: job.spec.mode.clone(),
            status: result_status,
        });
    }

    // FAIL CLOSED: validate the approved_plan_digest caller contract.
    //
    // Non-live modes (OfflineDryRun / LivePlan) must NOT carry a plan digest.
    // The CP step 8 rejects non-LiveApply results that include this field.
    //
    // LiveApply + Applied MUST carry a plan digest: the CP equality-checks it
    // against the grant's approved_plan_digest (step 8 live-apply gate).
    let envelope_plan_digest = match &job.spec.mode {
        // LiveDestroy carries NO approved_plan_digest (#42 B2): a destroy has no
        // plan-then-apply match — it removes the step's own applied state — so
        // its result must not include a digest, same as the non-apply modes.
        JobMode::OfflineDryRun | JobMode::LivePlan | JobMode::LiveDestroy => {
            if approved_plan_digest.is_some() {
                return Err(ResultError::PlanDigestOnNonLive {
                    mode: job.spec.mode.clone(),
                });
            }
            None
        }
        JobMode::LiveApply => {
            // EVERY non-refusal LiveApply result (Applied, or Failed after a
            // matching-plan apply) goes through the CP's grant-checked branch,
            // which REQUIRES approved_plan_digest and equality with the grant.
            // build_signed_result never produces a refusal (that is
            // build_refused_result), and a LiveApply only reaches this point
            // AFTER the agent's gate matched the plan digest — so the digest is
            // always available. Require it.
            match approved_plan_digest {
                Some(d) => Some(d),
                None => return Err(ResultError::MissingPlanDigestForLiveApply),
            }
        }
    };

    // Compute the two digests that the CP will recompute and check.
    let evidence_digest = sha256_hex(&evidence.evidence_bytes);
    let spec_digest = job_spec_digest(&job.spec);

    // Build the envelope with all fields that will be signed.
    // `signature` is filled by `sign()`; we set it to empty here.
    let unsigned_envelope = SignedEnvelope {
        agent_id: agent_id.to_string(),
        platform: job.platform.clone(),
        job_id: job.id,
        attempt_id: lease.attempt_id,
        lease_generation: lease.lease_generation,
        request_id: job.spec.request_id,
        result_id,
        mode: job.spec.mode.clone(),
        status: result_status.clone(),
        job_spec_digest: spec_digest,
        approved_plan_digest: envelope_plan_digest,
        evidence_digest: evidence_digest.clone(),
        redaction_policy_version: REDACTION_POLICY_VERSION.to_string(),
        timestamp: Utc::now(),
        key_id: identity.public_key_b64(),
        cp_nonce: lease.cp_nonce.clone(),
        signature: String::new(), // filled by sign()
    };

    // Sign the envelope.  This fills `signature` with the Ed25519 signature
    // over the canonical bytes of all other fields.
    let signed_envelope = sign(unsigned_envelope, identity.signing_key());

    // Outer JobResult: every field MUST equal the corresponding envelope field.
    // The CP equality-checks all five (verifier step 5).
    let job_result = JobResult {
        job_id: signed_envelope.job_id,
        attempt_id: signed_envelope.attempt_id,
        result_id: signed_envelope.result_id,
        status: signed_envelope.status.clone(),
        evidence_digest: signed_envelope.evidence_digest.clone(),
        signed_envelope,
    };

    Ok(ResultBody {
        job_result,
        evidence: evidence.evidence_bytes.clone(),
        evidence_json: evidence.evidence_json.clone(),
    })
}

// ---------------------------------------------------------------------------
// build_refused_result — the LiveRefused path
// ---------------------------------------------------------------------------

/// Construct a signed `ResultBody` for a `LiveRefused` outcome.
///
/// Used when the agent declines to execute a `LiveApply` (missing or invalid
/// grant, plan divergence, missing `--allow-live` flag, etc.).  The CP records
/// this WITHOUT running the grant equality checks (the refusal may be *because*
/// the grant was invalid), and transitions the job to `LiveRefused` status.
///
/// ## Contract
///
/// - `status` = `JobResultStatus::LiveRefused`.
/// - `approved_plan_digest` = `None` — a refusal applied nothing; the CP step 8
///   rejects a `LiveRefused` result that carries a digest.
/// - `evidence_bytes` = `reason.as_bytes()` (the human-readable refusal reason;
///   MUST be scrubbed — no secret material).
/// - `evidence_digest` = `sha256_hex(reason.as_bytes())`.
/// - All lease fields, `request_id`, `job_spec_digest`, `key_id`, `cp_nonce`,
///   and signature follow exactly the same rules as `build_signed_result`.
///
/// ## Works for any leased mode
///
/// A refusal can occur for `LivePlan` OR `LiveApply` — both can be leased
/// before the agent discovers a problem.  The CP records `LiveRefused`
/// terminally for both.
///
/// ## Panics
/// None — fail-closed via `Result`.
pub fn build_refused_result(
    identity: &AgentIdentity,
    agent_id: &str,
    job: &Job,
    reason: &str,
) -> Result<ResultBody, ResultError> {
    // Require an active lease — cannot sign without attempt_id and cp_nonce.
    let lease = job.lease.as_ref().ok_or(ResultError::NoLease)?;

    let result_id = Uuid::new_v4();

    // Evidence is the scrubbed refusal reason (plain text, no secrets).
    let evidence_bytes = reason.as_bytes().to_vec();
    let evidence_json = Some(serde_json::json!({"refused": reason}));
    let evidence_digest = sha256_hex(&evidence_bytes);
    let spec_digest = job_spec_digest(&job.spec);

    let unsigned_envelope = SignedEnvelope {
        agent_id: agent_id.to_string(),
        platform: job.platform.clone(),
        job_id: job.id,
        attempt_id: lease.attempt_id,
        lease_generation: lease.lease_generation,
        request_id: job.spec.request_id,
        result_id,
        mode: job.spec.mode.clone(),
        status: JobResultStatus::LiveRefused,
        job_spec_digest: spec_digest,
        // A refusal applied nothing — the CP rejects LiveRefused with a digest.
        approved_plan_digest: None,
        evidence_digest: evidence_digest.clone(),
        redaction_policy_version: REDACTION_POLICY_VERSION.to_string(),
        timestamp: Utc::now(),
        key_id: identity.public_key_b64(),
        cp_nonce: lease.cp_nonce.clone(),
        signature: String::new(), // filled by sign()
    };

    let signed_envelope = sign(unsigned_envelope, identity.signing_key());

    let job_result = JobResult {
        job_id: signed_envelope.job_id,
        attempt_id: signed_envelope.attempt_id,
        result_id: signed_envelope.result_id,
        status: signed_envelope.status.clone(),
        evidence_digest: signed_envelope.evidence_digest.clone(),
        signed_envelope,
    };

    Ok(ResultBody {
        job_result,
        evidence: evidence_bytes,
        evidence_json,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ryuki_engine::runners::RunStatus;
    use ryuki_protocol::{
        decode_verifying_key, job_spec_digest, sha256_hex, verify, Job, JobLease, JobMode, JobSpec,
        JobStatus,
    };
    use std::collections::BTreeMap;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn make_identity() -> AgentIdentity {
        AgentIdentity::generate()
    }

    fn make_leased_job(mode: JobMode) -> Job {
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v1.0.0".to_string(),
            iac_digest: sha256_hex(b"iac-bytes"),
            vars: BTreeMap::new(),
            mode,
        };
        let lease = JobLease {
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            fencing_token: Uuid::new_v4().to_string(),
            deadline: Utc::now() + chrono::Duration::minutes(5),
            cp_nonce: Uuid::new_v4().to_string(),
        };
        Job {
            id: Uuid::new_v4(),
            platform: "defra".to_string(),
            spec,
            status: JobStatus::Running,
            lease: Some(lease),
            live_context: None,
        }
    }

    fn make_evidence(status: RunStatus) -> Evidence {
        let evidence_bytes = b"stub evidence: check ok".to_vec();
        Evidence {
            status,
            evidence_bytes,
            evidence_json: Some(serde_json::json!({"stub": true})),
        }
    }

    // -----------------------------------------------------------------------
    // Positive: sign → verify roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn sign_verify_roundtrip_succeeds() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let body = build_signed_result(&identity, "defra-agent-01", &job, &evidence, None)
            .expect("build_signed_result must succeed");

        // Decode the enrolled verifying key from the identity.
        let vk = decode_verifying_key(&identity.public_key_b64()).expect("decode vk");

        // The signature on the signed envelope MUST verify against the identity key.
        verify(&body.job_result.signed_envelope, &vk).expect("Ed25519 signature must verify");
    }

    // -----------------------------------------------------------------------
    // Outer JobResult fields must EQUAL signed envelope fields (step 5)
    // -----------------------------------------------------------------------

    #[test]
    fn outer_fields_equal_envelope_fields() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("must succeed");

        let result = &body.job_result;
        let env = &result.signed_envelope;

        assert_eq!(result.job_id, env.job_id, "job_id must equal envelope");
        assert_eq!(
            result.attempt_id, env.attempt_id,
            "attempt_id must equal envelope"
        );
        assert_eq!(
            result.result_id, env.result_id,
            "result_id must equal envelope"
        );
        assert_eq!(result.status, env.status, "status must equal envelope");
        assert_eq!(
            result.evidence_digest, env.evidence_digest,
            "evidence_digest must equal envelope"
        );
    }

    // -----------------------------------------------------------------------
    // evidence_digest must equal sha256_hex(evidence_bytes) (step 6)
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_digest_matches_evidence_bytes() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("must succeed");

        let expected_digest = sha256_hex(&body.evidence);
        assert_eq!(
            body.job_result.evidence_digest, expected_digest,
            "outer evidence_digest must equal sha256_hex(evidence_bytes)"
        );
        assert_eq!(
            body.job_result.signed_envelope.evidence_digest, expected_digest,
            "envelope evidence_digest must also equal sha256_hex(evidence_bytes)"
        );
    }

    // -----------------------------------------------------------------------
    // approved_plan_digest must be None for OfflineDryRun (step 8)
    // -----------------------------------------------------------------------

    #[test]
    fn approved_plan_digest_is_none_for_offline_dry_run() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("must succeed");

        assert!(
            body.job_result
                .signed_envelope
                .approved_plan_digest
                .is_none(),
            "OfflineDryRun must NOT carry approved_plan_digest"
        );
    }

    // -----------------------------------------------------------------------
    // job_spec_digest must equal ryuki_protocol::job_spec_digest(&spec) (step 7)
    // -----------------------------------------------------------------------

    #[test]
    fn job_spec_digest_matches_spec() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("must succeed");

        let expected = job_spec_digest(&job.spec);
        assert_eq!(
            body.job_result.signed_envelope.job_spec_digest, expected,
            "job_spec_digest must equal ryuki_protocol::job_spec_digest(&spec)"
        );
    }

    // -----------------------------------------------------------------------
    // cp_nonce / attempt_id / lease_generation copied from lease (step 4)
    // -----------------------------------------------------------------------

    #[test]
    fn lease_fields_copied_correctly() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let lease = job.lease.as_ref().unwrap();
        let evidence = make_evidence(RunStatus::CheckOk);

        let body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("must succeed");

        let env = &body.job_result.signed_envelope;
        assert_eq!(env.attempt_id, lease.attempt_id, "attempt_id from lease");
        assert_eq!(
            env.lease_generation, lease.lease_generation,
            "lease_generation from lease"
        );
        assert_eq!(env.cp_nonce, lease.cp_nonce, "cp_nonce from lease");
    }

    // -----------------------------------------------------------------------
    // key_id must equal identity.public_key_b64() (step 3)
    // -----------------------------------------------------------------------

    #[test]
    fn key_id_matches_identity_public_key() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("must succeed");

        assert_eq!(
            body.job_result.signed_envelope.key_id,
            identity.public_key_b64(),
            "key_id must equal identity.public_key_b64()"
        );
    }

    // -----------------------------------------------------------------------
    // Negative: no lease → error
    // -----------------------------------------------------------------------

    #[test]
    fn no_lease_returns_error() {
        let identity = make_identity();
        let mut job = make_leased_job(JobMode::OfflineDryRun);
        job.lease = None; // strip the lease
        let evidence = make_evidence(RunStatus::CheckOk);

        let result = build_signed_result(&identity, "test-agent", &job, &evidence, None);
        assert!(
            matches!(result, Err(ResultError::NoLease)),
            "missing lease must return ResultError::NoLease"
        );
    }

    // -----------------------------------------------------------------------
    // Negative: a live-mutation status for an OfflineDryRun job is refused
    // -----------------------------------------------------------------------

    #[test]
    fn applied_status_rejected_for_offline_dry_run() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        // An OfflineDryRun that somehow yields Applied (RunStatus::Applied → Applied)
        // must NOT be signed — the agent fails closed.
        let evidence = make_evidence(RunStatus::Applied);

        let result = build_signed_result(&identity, "test-agent", &job, &evidence, None);
        assert!(
            matches!(
                result,
                Err(ResultError::LiveStatusInNonLiveMode {
                    mode: JobMode::OfflineDryRun,
                    status: JobResultStatus::Applied,
                })
            ),
            "OfflineDryRun producing Applied must be refused, not signed"
        );
    }

    // -----------------------------------------------------------------------
    // Negative tamper: mutating one evidence byte makes digest mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn tampered_evidence_digest_mismatch() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let mut body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("must succeed");

        // Tamper one byte of the evidence.
        body.evidence[0] ^= 0xFF;

        // Recompute the digest over the tampered bytes.
        let tampered_digest = sha256_hex(&body.evidence);

        // The envelope's evidence_digest must NO LONGER match.
        assert_ne!(
            body.job_result.signed_envelope.evidence_digest, tampered_digest,
            "tampered evidence must not match the signed digest"
        );
        // This proves the digest BINDS the evidence: a tampered evidence pack
        // cannot be passed off as matching the signed envelope.
    }

    // -----------------------------------------------------------------------
    // RunStatus → JobResultStatus mapping table
    // -----------------------------------------------------------------------

    #[test]
    fn run_status_mapping_table() {
        assert_eq!(
            map_run_status(&RunStatus::Validated),
            JobResultStatus::CheckOk
        );
        assert_eq!(
            map_run_status(&RunStatus::CheckOk),
            JobResultStatus::CheckOk
        );
        assert_eq!(
            map_run_status(&RunStatus::Planned),
            JobResultStatus::Planned
        );
        assert_eq!(map_run_status(&RunStatus::Failed), JobResultStatus::Failed);
        assert_eq!(
            map_run_status(&RunStatus::RunnerUnavailable),
            JobResultStatus::Failed
        );
        assert_eq!(
            map_run_status(&RunStatus::WorkspaceError),
            JobResultStatus::Failed
        );
    }

    // -----------------------------------------------------------------------
    // Verify that tampering the signed envelope itself fails ed25519 verify
    // -----------------------------------------------------------------------

    #[test]
    fn tampered_envelope_field_fails_verify() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let mut body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("must succeed");

        // Tamper the envelope's evidence_digest field.
        body.job_result.signed_envelope.evidence_digest =
            sha256_hex(b"forged-evidence").to_string();

        let vk = decode_verifying_key(&identity.public_key_b64()).expect("decode vk");
        assert!(
            verify(&body.job_result.signed_envelope, &vk).is_err(),
            "tampered envelope must fail Ed25519 verification"
        );
    }

    // -----------------------------------------------------------------------
    // platform and agent_id propagated from job / arg
    // -----------------------------------------------------------------------

    #[test]
    fn platform_and_agent_id_set_correctly() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let body = build_signed_result(&identity, "my-agent-01", &job, &evidence, None)
            .expect("must succeed");

        let env = &body.job_result.signed_envelope;
        assert_eq!(env.agent_id, "my-agent-01");
        assert_eq!(env.platform, job.platform);
    }

    // -----------------------------------------------------------------------
    // result_id is a fresh Uuid (not nil, not the job_id)
    // -----------------------------------------------------------------------

    #[test]
    fn result_id_is_fresh_uuid() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("must succeed");

        let result_id = body.job_result.signed_envelope.result_id;
        assert_ne!(result_id, Uuid::nil(), "result_id must not be nil");
        assert_ne!(result_id, job.id, "result_id must be different from job_id");
    }

    // -----------------------------------------------------------------------
    // Two calls produce distinct result_ids (idempotency: outbox persists the first)
    // -----------------------------------------------------------------------

    #[test]
    fn two_calls_produce_different_result_ids() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let body1 = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("first call");
        let body2 = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("second call");

        assert_ne!(
            body1.job_result.result_id, body2.job_result.result_id,
            "each call generates a fresh result_id; the outbox ensures the FIRST one is retried"
        );
    }

    // -----------------------------------------------------------------------
    // request_id bound from spec, not from job.id
    // -----------------------------------------------------------------------

    #[test]
    fn request_id_from_spec() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);

        let body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("must succeed");

        assert_eq!(
            body.job_result.signed_envelope.request_id, job.spec.request_id,
            "envelope.request_id must come from spec.request_id (Fix 3b)"
        );
    }

    // -----------------------------------------------------------------------
    // S5b-2b-i: LiveApply + Applied + Some(digest) → Ok; digest propagated
    // -----------------------------------------------------------------------

    #[test]
    fn live_apply_applied_with_digest_succeeds() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::LiveApply);
        let evidence = make_evidence(RunStatus::Applied);
        let plan_digest = sha256_hex(b"canonical-plan-bytes");

        let body = build_signed_result(
            &identity,
            "test-agent",
            &job,
            &evidence,
            Some(plan_digest.clone()),
        )
        .expect("LiveApply + Applied + Some(digest) must succeed");

        let env = &body.job_result.signed_envelope;

        // approved_plan_digest must equal what was passed in.
        assert_eq!(
            env.approved_plan_digest,
            Some(plan_digest),
            "envelope must carry the approved_plan_digest"
        );

        // Status must be Applied.
        assert_eq!(env.status, JobResultStatus::Applied);

        // Outer must equal envelope (step 5).
        assert_eq!(body.job_result.status, env.status);
        assert_eq!(body.job_result.result_id, env.result_id);
        assert_eq!(body.job_result.evidence_digest, env.evidence_digest);

        // evidence_digest = sha256(evidence_bytes).
        let expected = sha256_hex(&body.evidence);
        assert_eq!(
            env.evidence_digest, expected,
            "evidence_digest must equal sha256(evidence_bytes)"
        );

        // Sign → verify must pass.
        let vk = decode_verifying_key(&identity.public_key_b64()).expect("decode vk");
        verify(env, &vk).expect("Ed25519 signature on LiveApply+Applied must verify");
    }

    // -----------------------------------------------------------------------
    // S5b-2b-i negative: any non-refusal LiveApply result with None →
    // MissingPlanDigestForLiveApply (the CP requires the digest for both
    // Applied and Failed — a refusal uses build_refused_result instead).
    // -----------------------------------------------------------------------

    #[test]
    fn live_apply_applied_without_digest_is_rejected() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::LiveApply);
        let evidence = make_evidence(RunStatus::Applied);

        let result = build_signed_result(&identity, "test-agent", &job, &evidence, None);
        assert!(
            matches!(result, Err(ResultError::MissingPlanDigestForLiveApply)),
            "LiveApply + Applied + None must return MissingPlanDigestForLiveApply, got {:?}",
            result
        );
    }

    #[test]
    fn live_apply_failed_without_digest_is_rejected() {
        // A LiveApply that ran the approved plan then failed still goes through
        // the CP's grant-checked branch, so it MUST carry the digest.
        let identity = make_identity();
        let job = make_leased_job(JobMode::LiveApply);
        let evidence = make_evidence(RunStatus::Failed);

        let result = build_signed_result(&identity, "test-agent", &job, &evidence, None);
        assert!(
            matches!(result, Err(ResultError::MissingPlanDigestForLiveApply)),
            "LiveApply + Failed + None must also require the digest, got {:?}",
            result
        );
    }

    #[test]
    fn live_apply_failed_with_digest_carries_it() {
        // A failed LiveApply with the matching digest is a valid report (the CP
        // records it Failed after the verify_vlc + equality checks pass).
        let identity = make_identity();
        let job = make_leased_job(JobMode::LiveApply);
        let evidence = make_evidence(RunStatus::Failed);
        let digest = sha256_hex(b"the-approved-plan");

        let body = build_signed_result(
            &identity,
            "test-agent",
            &job,
            &evidence,
            Some(digest.clone()),
        )
        .expect("LiveApply + Failed + Some(digest) must succeed");
        assert_eq!(
            body.job_result.signed_envelope.approved_plan_digest,
            Some(digest),
            "a failed LiveApply must still carry the approved plan digest"
        );
    }

    // -----------------------------------------------------------------------
    // S5b-2b-i negative: OfflineDryRun + Some(digest) → PlanDigestOnNonLive
    // -----------------------------------------------------------------------

    #[test]
    fn offline_dry_run_with_digest_is_rejected() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::OfflineDryRun);
        let evidence = make_evidence(RunStatus::CheckOk);
        let plan_digest = sha256_hex(b"some-plan");

        let result =
            build_signed_result(&identity, "test-agent", &job, &evidence, Some(plan_digest));
        assert!(
            matches!(
                result,
                Err(ResultError::PlanDigestOnNonLive {
                    mode: JobMode::OfflineDryRun
                })
            ),
            "OfflineDryRun + Some(digest) must return PlanDigestOnNonLive, got {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // S5b-2b-i: LivePlan + Planned + None → Ok, no approved_plan_digest
    // -----------------------------------------------------------------------

    #[test]
    fn live_plan_planned_no_digest_succeeds() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::LivePlan);
        let evidence = make_evidence(RunStatus::Planned);

        let body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("LivePlan + Planned + None must succeed");

        let env = &body.job_result.signed_envelope;
        assert_eq!(env.status, JobResultStatus::Planned);
        assert!(
            env.approved_plan_digest.is_none(),
            "LivePlan must NOT carry approved_plan_digest"
        );

        // Sign → verify passes.
        let vk = decode_verifying_key(&identity.public_key_b64()).expect("decode vk");
        verify(env, &vk).expect("signature must verify for LivePlan+Planned");
    }

    // -----------------------------------------------------------------------
    // S5b-2b-i: LivePlan + Some(digest) → PlanDigestOnNonLive
    //
    // LivePlan is NOT LiveApply — the CP step 8 rejects non-LiveApply results
    // that carry approved_plan_digest.
    // -----------------------------------------------------------------------

    #[test]
    fn live_plan_with_digest_is_rejected() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::LivePlan);
        let evidence = make_evidence(RunStatus::Planned);
        let plan_digest = sha256_hex(b"plan-bytes");

        let result =
            build_signed_result(&identity, "test-agent", &job, &evidence, Some(plan_digest));
        assert!(
            matches!(
                result,
                Err(ResultError::PlanDigestOnNonLive {
                    mode: JobMode::LivePlan
                })
            ),
            "LivePlan + Some(digest) must return PlanDigestOnNonLive, got {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // S5b-2b-i: build_refused_result — positive
    // -----------------------------------------------------------------------

    #[test]
    fn build_refused_result_positive() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::LiveApply);
        let reason = "grant expired before apply could start";

        let body = build_refused_result(&identity, "test-agent", &job, reason)
            .expect("build_refused_result must succeed");

        let env = &body.job_result.signed_envelope;

        // Status must be LiveRefused.
        assert_eq!(env.status, JobResultStatus::LiveRefused);
        assert_eq!(body.job_result.status, JobResultStatus::LiveRefused);

        // No approved_plan_digest — a refusal applied nothing.
        assert!(
            env.approved_plan_digest.is_none(),
            "LiveRefused must NOT carry approved_plan_digest"
        );

        // evidence_digest = sha256(reason bytes).
        let expected_digest = sha256_hex(reason.as_bytes());
        assert_eq!(
            env.evidence_digest, expected_digest,
            "evidence_digest must equal sha256(reason bytes)"
        );
        assert_eq!(
            body.job_result.evidence_digest, expected_digest,
            "outer evidence_digest must equal sha256(reason bytes)"
        );
        assert_eq!(
            body.evidence,
            reason.as_bytes(),
            "evidence bytes must equal reason bytes"
        );

        // Outer must equal envelope (step 5).
        assert_eq!(body.job_result.job_id, env.job_id);
        assert_eq!(body.job_result.attempt_id, env.attempt_id);
        assert_eq!(body.job_result.result_id, env.result_id);

        // Sign → verify must pass.
        let vk = decode_verifying_key(&identity.public_key_b64()).expect("decode vk");
        verify(env, &vk).expect("Ed25519 signature on LiveRefused must verify");
    }

    // -----------------------------------------------------------------------
    // S5b-2b-i: build_refused_result — NoLease when lease absent
    // -----------------------------------------------------------------------

    #[test]
    fn build_refused_result_no_lease() {
        let identity = make_identity();
        let mut job = make_leased_job(JobMode::LiveApply);
        job.lease = None;

        let result = build_refused_result(&identity, "test-agent", &job, "no grant");
        assert!(
            matches!(result, Err(ResultError::NoLease)),
            "build_refused_result without lease must return NoLease"
        );
    }

    // -----------------------------------------------------------------------
    // S5b-2b-i: build_refused_result works for LivePlan too
    // -----------------------------------------------------------------------

    #[test]
    fn build_refused_result_for_live_plan() {
        let identity = make_identity();
        let job = make_leased_job(JobMode::LivePlan);
        let reason = "live credentials unavailable";

        let body = build_refused_result(&identity, "test-agent", &job, reason)
            .expect("refused result for LivePlan must succeed");

        assert_eq!(body.job_result.status, JobResultStatus::LiveRefused);
        assert!(body
            .job_result
            .signed_envelope
            .approved_plan_digest
            .is_none());

        let vk = decode_verifying_key(&identity.public_key_b64()).expect("decode vk");
        verify(&body.job_result.signed_envelope, &vk)
            .expect("signature must verify for LivePlan refused result");
    }
}
