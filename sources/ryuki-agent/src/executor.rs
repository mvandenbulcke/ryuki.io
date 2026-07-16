//! Job executor abstraction (dependency-inversion layer for S4b).
//!
//! ## Design
//!
//! `JobExecutor` decouples the result-signing logic from the runner so that:
//! - Tests can use `StubExecutor` without requiring terraform/ansible binaries.
//! - S4c wires `RunnerExecutor` into the pull-loop; tests wire `StubExecutor`.
//!
//! ## Evidence format
//!
//! `Evidence.evidence_bytes` are the SCRUBBED bytes stored in `ResultBody.evidence`
//! and hashed into `evidence_digest`.  They MUST NOT contain secret material;
//! the runner's built-in scrubbing pass is the first layer, and this module
//! does not re-inject anything secret.
//!
//! `Evidence.evidence_json` is an optional structured view (stored as JSONB on
//! the CP) — never used for auth decisions, only for human-readable queries.

use ryuki_engine::runners::{RunMode, RunStatus, RunnerKind};
use ryuki_protocol::{JobMode, JobSpec};
use serde_json::Value;
use thiserror::Error;

use crate::identity::AgentIdentity;

// ---------------------------------------------------------------------------
// Evidence — the scrubbed output of one job execution
// ---------------------------------------------------------------------------

/// Scrubbed, digest-ready evidence from a single job execution.
///
/// # Security
/// `evidence_bytes` MUST be pre-scrubbed of any secret material before this
/// struct is constructed.  The SHA-256 digest computed over these bytes is
/// what the CP verifies and stores; any secret that leaks here is persisted
/// permanently.
#[derive(Debug, Clone)]
pub struct Evidence {
    /// Final `RunStatus` from the runner.
    pub status: RunStatus,
    /// Scrubbed, truncated runner output.  The SHA-256 of these bytes is the
    /// `evidence_digest` in the signed envelope.  MUST be secret-free.
    pub evidence_bytes: Vec<u8>,
    /// Optional structured evidence (e.g. parsed plan JSON).  Stored as JSONB
    /// on the CP; never trusted for auth decisions.
    pub evidence_json: Option<Value>,
}

// ---------------------------------------------------------------------------
// ExecError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ExecError {
    #[error(
        "job mode {0:?} is not supported by this executor — only OfflineDryRun is supported in S4b"
    )]
    UnsupportedMode(JobMode),
    #[error("runner error: {0}")]
    Runner(#[from] ryuki_engine::runners::RunnerError),
    #[error("cannot build run plan: {0}")]
    PlanBuild(String),
}

// ---------------------------------------------------------------------------
// JobExecutor trait
// ---------------------------------------------------------------------------

/// Execute a `JobSpec` and return scrubbed `Evidence`.
///
/// The trait is object-safe so callers can hold a `Box<dyn JobExecutor>` for
/// test injection without generic parameters propagating everywhere.
pub trait JobExecutor: Send + Sync {
    fn execute(&self, spec: &JobSpec) -> Result<Evidence, ExecError>;

    /// Execute while observing the authoritative job-lifecycle cancellation
    /// signal. Test/stub implementations retain compatibility through this
    /// default; the production runner overrides it for in-flight propagation.
    fn execute_with_cancellation(
        &self,
        spec: &JobSpec,
        cancellation: &ryuki_runner::CommandCancellation,
    ) -> Result<Evidence, ExecError> {
        if cancellation.is_cancelled() {
            return Err(ExecError::Runner(
                ryuki_engine::runners::RunnerError::Cancelled,
            ));
        }
        self.execute(spec)
    }
}

// ---------------------------------------------------------------------------
// RunnerExecutor — production implementation
// ---------------------------------------------------------------------------

/// Production executor: maps `JobSpec` → `RunPlan` → `run_offline_dry_run`.
///
/// Only `JobMode::OfflineDryRun` is accepted; `LivePlan` and `LiveApply` are
/// S5 and return `ExecError::UnsupportedMode`.
///
/// # iac_ref → offering_id slug
///
/// `JobSpec.iac_ref` is a string like `"linux-server-deployment@v1.2.3"`.
/// The offering_id slug (used to locate embedded IaC) is the portion before
/// `@`.  `JobSpec.offering_id` is a `Uuid` that identifies the catalog entry;
/// the human-readable slug that the runner needs comes from `iac_ref`.
pub struct RunnerExecutor {
    // Retained for S5: live-mode credential injection will use the identity
    // to sign credential requests or decrypt vault tokens.
    #[allow(dead_code)]
    identity: std::sync::Arc<AgentIdentity>,
}

impl RunnerExecutor {
    /// Construct with a shared identity reference.
    ///
    /// `Arc<AgentIdentity>` allows the executor to be cloned cheaply across
    /// the pull-loop and heartbeat task without copying the signing key.
    pub fn new(identity: std::sync::Arc<AgentIdentity>) -> Self {
        Self { identity }
    }
}

impl RunnerExecutor {
    fn execute_inner(
        &self,
        spec: &JobSpec,
        cancellation: Option<&ryuki_runner::CommandCancellation>,
    ) -> Result<Evidence, ExecError> {
        // Only OfflineDryRun in S4b.
        if spec.mode != JobMode::OfflineDryRun {
            return Err(ExecError::UnsupportedMode(spec.mode.clone()));
        }

        // Derive the offering_id slug from iac_ref: strip the `@<version>` suffix.
        let offering_slug = spec
            .iac_ref
            .split('@')
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ExecError::PlanBuild(format!(
                    "could not derive offering slug from iac_ref {:?}",
                    spec.iac_ref
                ))
            })?
            .to_string();

        // Determine runner_kind from the offering slug.
        // Convention: Ansible playbooks are identified by known slug patterns.
        // All others default to Terraform.
        let runner_kind = offering_kind_from_slug(&offering_slug);

        // Integrity gate: the IaC the runner is about to resolve and run must
        // match the content digest the control plane approved. A real (non-stub)
        // iac_digest that does not match the locally embedded bundle means a
        // tampered or version-skewed bundle — refuse rather than run (and sign)
        // IaC the CP did not approve. An all-zero stub means "nothing to verify".
        if let Some(approved) = real_iac_digest(&spec.iac_digest) {
            let resolved = ryuki_runner::iac::offering_iac_digest(&offering_slug);
            if resolved.as_deref() != Some(approved) {
                return Err(ExecError::PlanBuild(format!(
                    "IaC digest mismatch for offering {offering_slug:?}: approved {approved} but \
                     the locally resolved bundle does not match — refusing to run unapproved IaC"
                )));
            }
        }

        // Build the run plan.  Non-secret vars from spec; no secrets for S4b
        // (credential injection is a separate concern resolved by the runner
        // from its own environment — empty material here means no TF_VAR_ injection).
        let plan = ryuki_engine::runners::RunPlan {
            runner_kind,
            mode: RunMode::DryRun,
            offering_id: offering_slug,
            vars: spec.vars.clone(),
            secret_var_names: vec![],
        };

        // Empty credentials — OfflineDryRun does not require live provider access.
        // The runner may inject credential-shaped env vars if secret_var_names is
        // non-empty, but here we have no names so the credential material is unused.
        let creds = ryuki_runner::ResolvedCredentials {
            material: vec![],
            descriptor: "offline-dry-run:no-creds".to_string(),
        };

        let outcome = match cancellation {
            Some(cancellation) => {
                ryuki_runner::run_offline_dry_run_with_cancellation(&plan, &creds, cancellation)?
            }
            None => ryuki_runner::run_offline_dry_run(&plan, &creds)?,
        };

        // Build evidence bytes: JSON-serialised RunOutcome (already scrubbed by
        // the runner).  Using JSON gives the CP a readable, diffable evidence
        // artifact without re-introducing any secret material.
        let evidence_bytes =
            serde_json::to_vec(&outcome).map_err(|e| ExecError::PlanBuild(e.to_string()))?;

        let evidence_json = serde_json::to_value(&outcome).ok().filter(|v| !v.is_null());

        Ok(Evidence {
            status: outcome.status,
            evidence_bytes,
            evidence_json,
        })
    }
}

impl JobExecutor for RunnerExecutor {
    fn execute(&self, spec: &JobSpec) -> Result<Evidence, ExecError> {
        self.execute_inner(spec, None)
    }

    fn execute_with_cancellation(
        &self,
        spec: &JobSpec,
        cancellation: &ryuki_runner::CommandCancellation,
    ) -> Result<Evidence, ExecError> {
        self.execute_inner(spec, Some(cancellation))
    }
}

// ---------------------------------------------------------------------------
// StubExecutor — deterministic test seam
// ---------------------------------------------------------------------------

/// A canned executor that returns deterministic `Evidence` without running any
/// binary.  Used in unit tests for `result.rs` and `outbox.rs`, and will be
/// the seam for S4c e2e tests that run without terraform installed.
pub struct StubExecutor {
    status: RunStatus,
    evidence_bytes: Vec<u8>,
    evidence_json: Option<Value>,
}

impl StubExecutor {
    /// Create a stub that always returns `CheckOk` with the given payload.
    pub fn new(status: RunStatus, evidence_bytes: Vec<u8>, evidence_json: Option<Value>) -> Self {
        Self {
            status,
            evidence_bytes,
            evidence_json,
        }
    }

    /// Convenience: a minimal `CheckOk` stub with empty evidence (for signing tests).
    pub fn check_ok() -> Self {
        Self::new(
            RunStatus::CheckOk,
            b"stub: check ok".to_vec(),
            Some(serde_json::json!({"stub": true, "status": "check_ok"})),
        )
    }
}

impl JobExecutor for StubExecutor {
    fn execute(&self, _spec: &JobSpec) -> Result<Evidence, ExecError> {
        Ok(Evidence {
            status: self.status.clone(),
            evidence_bytes: self.evidence_bytes.clone(),
            evidence_json: self.evidence_json.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the approved IaC digest to verify against, or `None` when there is
/// nothing to check. A real digest is canonical lowercase-hex SHA-256 (exactly
/// 64 chars, `0-9a-f`) and not the all-zero stub. The stub *and* any malformed /
/// non-hex value yield `None` — we degrade to running without the check rather
/// than refusing a legitimate job because of a corrupt `iac_digest` field (the
/// digest is set by the trusted control plane, so a bad value is a CP bug, not
/// an attack). `bundle_digest` always emits lowercase hex, so a genuine approved
/// digest always satisfies this.
pub(crate) fn real_iac_digest(digest: &str) -> Option<&str> {
    let is_lower_hex = digest.len() == 64
        && digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if is_lower_hex && digest.bytes().any(|b| b != b'0') {
        Some(digest)
    } else {
        None
    }
}

/// Infer `RunnerKind` from an offering slug.
///
/// The convention in this codebase: maintenance / onboarding / monitoring /
/// ITSM playbooks use Ansible; everything else uses Terraform.
/// This mirrors `ryuki_engine::runners::classify` but operates on a slug string
/// rather than an `AdapterType`, since the agent only sees the slug from `iac_ref`.
pub(crate) fn offering_kind_from_slug(slug: &str) -> RunnerKind {
    // Ansible offerings: known by slug keyword patterns.
    const ANSIBLE_KEYWORDS: &[&str] = &[
        "patch-maintenance",
        "zabbix-onboarding",
        "controlled-restore-request",
        "linux-server-deployment-playbook",
        "windows-server-deployment-playbook",
    ];
    if ANSIBLE_KEYWORDS.contains(&slug) {
        return RunnerKind::Ansible;
    }
    // All others default to Terraform.
    RunnerKind::Terraform
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ryuki_protocol::{JobMode, JobSpec};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn make_spec(mode: JobMode) -> JobSpec {
        JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v1.0.0".to_string(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some("request-test".to_string()),
            mode,
        }
    }

    // --- StubExecutor ---

    #[test]
    fn stub_executor_returns_canned_evidence() {
        let stub = StubExecutor::check_ok();
        let spec = make_spec(JobMode::OfflineDryRun);
        let evidence = stub.execute(&spec).expect("stub must succeed");
        assert_eq!(evidence.status, RunStatus::CheckOk);
        assert!(!evidence.evidence_bytes.is_empty());
        assert!(evidence.evidence_json.is_some());
    }

    #[test]
    fn stub_executor_accepts_any_mode() {
        // StubExecutor does not validate mode — it's a test seam.
        let stub = StubExecutor::check_ok();
        for mode in [
            JobMode::OfflineDryRun,
            JobMode::LivePlan,
            JobMode::LiveApply,
        ] {
            let spec = make_spec(mode);
            assert!(
                stub.execute(&spec).is_ok(),
                "StubExecutor must succeed for any mode"
            );
        }
    }

    // --- RunnerExecutor mode guard ---

    #[test]
    fn runner_executor_rejects_live_plan() {
        use std::sync::Arc;
        let identity = Arc::new(crate::identity::AgentIdentity::generate());
        let executor = RunnerExecutor::new(identity);
        let spec = make_spec(JobMode::LivePlan);
        let result = executor.execute(&spec);
        assert!(
            matches!(result, Err(ExecError::UnsupportedMode(JobMode::LivePlan))),
            "RunnerExecutor must reject LivePlan"
        );
    }

    #[test]
    fn runner_executor_rejects_live_apply() {
        use std::sync::Arc;
        let identity = Arc::new(crate::identity::AgentIdentity::generate());
        let executor = RunnerExecutor::new(identity);
        let spec = make_spec(JobMode::LiveApply);
        let result = executor.execute(&spec);
        assert!(
            matches!(result, Err(ExecError::UnsupportedMode(JobMode::LiveApply))),
            "RunnerExecutor must reject LiveApply"
        );
    }

    // --- IaC digest integrity gate ---

    #[test]
    fn real_iac_digest_recognizes_stub_and_real() {
        assert!(
            real_iac_digest(&"0".repeat(64)).is_none(),
            "the all-zero stub is not a real digest"
        );
        assert!(
            real_iac_digest("abc").is_none(),
            "a wrong-length value is not a real digest"
        );
        assert!(
            real_iac_digest(&"z".repeat(64)).is_none(),
            "a 64-char non-hex value is not a real digest"
        );
        assert!(
            real_iac_digest(&"A".repeat(64)).is_none(),
            "uppercase hex is not canonical (bundle_digest emits lowercase)"
        );
        let real = "a".repeat(64);
        assert_eq!(real_iac_digest(&real), Some(real.as_str()));
    }

    #[test]
    fn runner_executor_refuses_iac_digest_mismatch() {
        use std::sync::Arc;
        let identity = Arc::new(crate::identity::AgentIdentity::generate());
        let executor = RunnerExecutor::new(identity);
        // A real (non-stub) digest that does NOT match patch-maintenance's bundle
        // — the agent must refuse before running any IaC.
        let mut spec = make_spec(JobMode::OfflineDryRun);
        spec.iac_digest = "a".repeat(64);
        match executor.execute(&spec) {
            Err(ExecError::PlanBuild(msg)) => assert!(
                msg.contains("digest mismatch"),
                "must refuse with a digest-mismatch message, got: {msg}"
            ),
            other => panic!("expected a digest-mismatch refusal, got: {other:?}"),
        }
    }

    #[test]
    fn runner_executor_accepts_matching_iac_digest() {
        use std::sync::Arc;
        let identity = Arc::new(crate::identity::AgentIdentity::generate());
        let executor = RunnerExecutor::new(identity);
        // The REAL digest of patch-maintenance's bundle: the gate must pass. The
        // run may then succeed or report RunnerUnavailable if terraform is
        // absent, but it must NEVER fail with a digest mismatch.
        let mut spec = make_spec(JobMode::OfflineDryRun);
        spec.iac_digest = ryuki_runner::iac::offering_iac_digest("patch-maintenance")
            .expect("patch-maintenance has embedded IaC");
        if let Err(ExecError::PlanBuild(msg)) = &executor.execute(&spec) {
            assert!(
                !msg.contains("digest mismatch"),
                "a matching digest must not be refused, got: {msg}"
            );
        }
    }

    #[test]
    fn runner_executor_matches_digest_across_versioned_iac_ref() {
        use std::sync::Arc;
        let identity = Arc::new(crate::identity::AgentIdentity::generate());
        let executor = RunnerExecutor::new(identity);
        // This proves CP/agent slug equality across the `@version` strip: the CP
        // computes the digest from the bare slug (resolve_offering_id, which
        // never adds a version) and stores it in iac_ref; the agent strips
        // `@version` from iac_ref before recomputing. A VERSIONED iac_ref with
        // the bare-slug digest must therefore PASS, and a wrong digest on the
        // same versioned ref must be REFUSED.
        let bare_digest = ryuki_runner::iac::offering_iac_digest("patch-maintenance").unwrap();

        let mut ok = make_spec(JobMode::OfflineDryRun);
        ok.iac_ref = "patch-maintenance@v9.9.9".to_string();
        ok.iac_digest = bare_digest.clone();
        if let Err(ExecError::PlanBuild(msg)) = &executor.execute(&ok) {
            assert!(
                !msg.contains("digest mismatch"),
                "versioned iac_ref with the bare-slug digest must not be refused: {msg}"
            );
        }

        let mut bad = make_spec(JobMode::OfflineDryRun);
        bad.iac_ref = "patch-maintenance@v9.9.9".to_string();
        bad.iac_digest = "b".repeat(64); // real-looking but wrong
        match executor.execute(&bad) {
            Err(ExecError::PlanBuild(msg)) => assert!(
                msg.contains("digest mismatch"),
                "a wrong digest on a versioned ref must be refused: {msg}"
            ),
            other => panic!("expected a digest-mismatch refusal, got: {other:?}"),
        }
    }

    #[test]
    fn runner_executor_allows_stub_digest() {
        use std::sync::Arc;
        let identity = Arc::new(crate::identity::AgentIdentity::generate());
        let executor = RunnerExecutor::new(identity);
        // The legacy all-zero stub means "nothing to verify" — never a refusal.
        let spec = make_spec(JobMode::OfflineDryRun); // iac_digest is the stub
        if let Err(ExecError::PlanBuild(msg)) = &executor.execute(&spec) {
            assert!(
                !msg.contains("digest mismatch"),
                "the stub digest must not trigger a mismatch refusal, got: {msg}"
            );
        }
    }

    #[test]
    fn runner_executor_offline_dry_run_does_not_error() {
        // When terraform is unavailable the runner returns Ok(RunnerUnavailable),
        // which the executor wraps into Ok(Evidence {status: RunnerUnavailable}).
        // This test proves the executor never panics or returns Err for a valid
        // OfflineDryRun spec (it degrades gracefully when terraform is absent).
        use std::sync::Arc;
        let identity = Arc::new(crate::identity::AgentIdentity::generate());
        let executor = RunnerExecutor::new(identity);
        let spec = make_spec(JobMode::OfflineDryRun);
        let result = executor.execute(&spec);
        assert!(
            result.is_ok(),
            "RunnerExecutor must not return Err for OfflineDryRun (binary absence → Ok)"
        );
    }

    // --- offering_kind_from_slug ---

    #[test]
    fn patch_maintenance_is_ansible() {
        assert_eq!(
            offering_kind_from_slug("patch-maintenance"),
            RunnerKind::Ansible
        );
    }

    #[test]
    fn unknown_slug_defaults_to_terraform() {
        assert_eq!(
            offering_kind_from_slug("linux-server-deployment"),
            RunnerKind::Terraform
        );
        assert_eq!(
            offering_kind_from_slug("windows-server-deployment"),
            RunnerKind::Terraform
        );
        assert_eq!(
            offering_kind_from_slug("request-preflight"),
            RunnerKind::Terraform
        );
    }
}
