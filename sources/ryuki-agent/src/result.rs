//! Signed result production — the security core of the agent.
//!
//! `build_signed_result` constructs a `ResultBody` whose `SignedEnvelope` passes
//! ALL 9 steps of the CP verifier (`post_job_result_with_pool` in
//! `ryuki-api/src/agents.rs`).
//!
//! ## Field-source table (mirror of verifier checks)
//!
//! | Envelope field          | Source                                         | Verifier step |
//! |-------------------------|------------------------------------------------|---------------|
//! | `agent_id`              | `agent_id` arg (== token identity)             | Step 1        |
//! | `platform`              | `job.platform`                                 | Fix 3a        |
//! | `job_id`                | `job.id`                                       | Step 4        |
//! | `attempt_id`            | `job.lease.attempt_id`                         | Step 4        |
//! | `lease_generation`      | `job.lease.lease_generation`                   | Step 4        |
//! | `cp_nonce`              | `job.lease.cp_nonce`                           | Step 4 (CT)   |
//! | `request_id`            | `job.spec.request_id`                          | Fix 3b        |
//! | `result_id`             | `Uuid::new_v4()` — generated once, outbox-stable | Step 5      |
//! | `mode`                  | `job.spec.mode`                                | Fix 3a        |
//! | `status`                | mapped from `RunStatus` → `JobResultStatus`    | Step 5        |
//! | `job_spec_digest`       | `ryuki_protocol::job_spec_digest(&job.spec)`   | Step 7        |
//! | `approved_plan_digest`  | `None` — OfflineDryRun must NOT carry it       | Step 8        |
//! | `evidence_digest`       | `sha256_hex(&evidence.evidence_bytes)`         | Step 6        |
//! | `redaction_policy_version` | `REDACTION_POLICY_VERSION` constant         | Stored        |
//! | `timestamp`             | `Utc::now()`                                   | Stored        |
//! | `key_id`                | `identity.public_key_b64()`                    | Step 3        |
//! | `signature`             | `ryuki_protocol::sign(envelope, signing_key)`  | Step 3        |
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

/// Semver label for the redaction policy applied by this agent.
/// Bound into the signed envelope so the CP can track which scrubbing rules
/// were applied.  Bump when the scrubbing ruleset changes.
pub const REDACTION_POLICY_VERSION: &str = "ryuki-redaction-v1";

// ---------------------------------------------------------------------------
// RunStatus → JobResultStatus mapping
// ---------------------------------------------------------------------------

/// Map a runner `RunStatus` to the `JobResultStatus` the agent may report.
///
/// Mapping table (S4b scope — OfflineDryRun only):
///
/// | RunStatus            | JobResultStatus |
/// |----------------------|-----------------|
/// | Validated            | CheckOk         |
/// | CheckOk              | CheckOk         |
/// | Planned              | Planned         |
/// | Failed               | Failed          |
/// | RunnerUnavailable    | Failed          |
/// | WorkspaceError       | Failed          |
/// | Applied (live, S5)   | not produced    |
/// | Changed  (live, S5)  | not produced    |
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
    #[error("serialisation error: {0}")]
    Serialise(String),
}

// ---------------------------------------------------------------------------
// build_signed_result — the signing core
// ---------------------------------------------------------------------------

/// Construct a fully-signed `ResultBody` ready to POST to the CP.
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
    // record it as Succeeded. (LiveApply is rejected earlier in the pipeline.)
    if matches!(job.spec.mode, JobMode::OfflineDryRun | JobMode::LivePlan)
        && matches!(result_status, JobResultStatus::Applied)
    {
        return Err(ResultError::LiveStatusInNonLiveMode {
            mode: job.spec.mode.clone(),
            status: result_status,
        });
    }

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
        // OfflineDryRun and LivePlan MUST NOT carry approved_plan_digest.
        // The CP rejects non-LiveApply results that include this field (step 8).
        approved_plan_digest: match &job.spec.mode {
            JobMode::LiveApply => {
                // S5: approved_plan_digest comes from VerifiedLiveContext.
                // For now we never reach this path (executor rejects LiveApply).
                None
            }
            _ => None,
        },
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

        let body = build_signed_result(&identity, "defra-agent-01", &job, &evidence)
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

        let body =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("must succeed");

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

        let body =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("must succeed");

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

        let body =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("must succeed");

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

        let body =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("must succeed");

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

        let body =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("must succeed");

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

        let body =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("must succeed");

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

        let result = build_signed_result(&identity, "test-agent", &job, &evidence);
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

        let result = build_signed_result(&identity, "test-agent", &job, &evidence);
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

        let mut body =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("must succeed");

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

        let mut body =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("must succeed");

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

        let body =
            build_signed_result(&identity, "my-agent-01", &job, &evidence).expect("must succeed");

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

        let body =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("must succeed");

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

        let body1 =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("first call");
        let body2 =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("second call");

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

        let body =
            build_signed_result(&identity, "test-agent", &job, &evidence).expect("must succeed");

        assert_eq!(
            body.job_result.signed_envelope.request_id, job.spec.request_id,
            "envelope.request_id must come from spec.request_id (Fix 3b)"
        );
    }
}
