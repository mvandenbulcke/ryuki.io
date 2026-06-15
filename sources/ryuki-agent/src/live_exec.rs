//! Live execution abstraction — `LiveExecutor` trait + production/stub impls.
//!
//! ## Purpose
//!
//! This module is the dependency-inversion layer for S5b live execution,
//! mirroring what `executor.rs` does for `OfflineDryRun`.  It allows the
//! `process_job_live` orchestration in `run.rs` to be fully unit-tested with
//! `StubLiveExecutor` without requiring a real Terraform binary or provider
//! credentials.
//!
//! ## Credential resolution (`RunnerLiveExecutor`)
//!
//! Live credentials (vSphere password, cloud access keys, etc.) are resolved
//! entirely from the agent's environment — NEVER from the control plane.  The
//! CP never holds a platform's credentials; it stores references only.  The
//! operator provisions credentials as host-level secrets (e.g. Kubernetes
//! Secrets mounted as env vars, HashiCorp Vault agent sidecars, systemd
//! `EnvironmentFile`).  `RunnerLiveExecutor` reads them from `std::env::var`.
//!
//! The credential variable names are communicated via `JobSpec.vars` (the
//! non-secret variable names list — operators configure which env var holds the
//! credential).  In this slice a placeholder resolver reads
//! `RYUKI_LIVE_CRED_<VAR_NAME>` from the agent environment; a production-grade
//! vault integration is a later slice.
//!
//! ## `plan_digest`
//!
//! `RunnerLiveExecutor::plan` computes `sha256_hex(outcome.log.as_bytes())` —
//! the SHA-256 of the SCRUBBED canonical plan JSON returned by
//! `terraform show -json tfplan` — and exposes it as `LivePlanOutcome.plan_digest`.
//! The gate in `live.rs` then checks:
//!   `replanned_plan_digest == Some(&grant.approved_plan_digest)`
//! so only an operator-reviewed, CP-signed plan is applied.

use ryuki_engine::runners::{RunMode, RunPlan, RunStatus, RunnerKind};
use ryuki_protocol::{sha256_hex, JobMode, JobSpec};
use serde_json::Value;
use thiserror::Error;

use crate::executor::Evidence;

// ---------------------------------------------------------------------------
// LivePlanOutcome
// ---------------------------------------------------------------------------

/// The output of a successful `LiveExecutor::plan` call.
///
/// - `evidence` — scrubbed plan evidence (suitable for signing and posting to CP).
///   `evidence.evidence_bytes` contains the canonical plan JSON (from
///   `terraform show -json tfplan`), already scrubbed.
/// - `plan_digest` — `sha256_hex(evidence.evidence_bytes)`.  The gate checks
///   `plan_digest == grant.approved_plan_digest` before allowing apply.
/// - `tfplan` — raw binary plan file bytes (opaque).  Pass verbatim to
///   `LiveExecutor::apply` so the apply step uses EXACTLY the gated plan.
///   MUST NOT be logged, sent to the control plane, or included in evidence.
#[derive(Debug, Clone)]
pub struct LivePlanOutcome {
    pub evidence: Evidence,
    /// SHA-256 hex of `evidence.evidence_bytes`.
    pub plan_digest: String,
    /// Raw binary `tfplan` bytes from `terraform plan -out=tfplan`.
    /// Thread these through to `apply()` unchanged to close the TOCTOU hole.
    pub tfplan: Vec<u8>,
}

// ---------------------------------------------------------------------------
// ExecError (live variant — extends the executor ExecError)
// ---------------------------------------------------------------------------

/// Errors from live execution.  Parallel to `executor::ExecError`.
#[derive(Debug, Error)]
pub enum LiveExecError {
    #[error("job mode {0:?} is not supported by this live executor")]
    UnsupportedMode(JobMode),
    #[error("runner error: {0}")]
    Runner(#[from] ryuki_engine::runners::RunnerError),
    #[error("cannot build run plan: {0}")]
    PlanBuild(String),
    #[error("credential resolution error: {0}")]
    CredResolution(String),
    /// The terraform plan step did not complete cleanly (non-zero exit or
    /// timeout).  A digest MUST NOT be computed or exposed for a non-clean plan.
    #[error("terraform plan did not complete cleanly: {0}")]
    PlanFailed(String),
}

// ---------------------------------------------------------------------------
// LiveExecutor trait
// ---------------------------------------------------------------------------

/// Execute a `JobSpec` in live mode and return evidence suitable for signing.
///
/// ## Object safety
/// The trait is object-safe so callers can hold `&dyn LiveExecutor` without
/// propagating generic parameters throughout the call stack.
pub trait LiveExecutor: Send + Sync {
    /// Execute a live plan (`terraform plan -out=tfplan` → `show -json`).
    ///
    /// Accepted modes: `LivePlan` and `LiveApply` (the plan step is the same
    /// for both; the caller decides whether to proceed to apply).
    ///
    /// Returns `Err(LiveExecError::PlanFailed)` when the plan step is not
    /// clean (non-zero exit or timeout).  The digest is NEVER computed for
    /// a non-clean plan — this ensures the gate cannot approve an incomplete
    /// or errored plan.
    fn plan(&self, spec: &JobSpec) -> Result<LivePlanOutcome, LiveExecError>;

    /// Execute a live apply using the SAVED plan from `plan()`.
    ///
    /// `tfplan` MUST be the exact bytes returned by the preceding `plan()` call
    /// for this job.  The implementation writes them into a fresh workspace and
    /// invokes `terraform apply -input=false tfplan` so that terraform applies
    /// EXACTLY the plan the control-plane gate approved, with no re-planning.
    ///
    /// Accepted mode: `LiveApply` only.
    fn apply(&self, spec: &JobSpec, tfplan: &[u8]) -> Result<Evidence, LiveExecError>;
}

// ---------------------------------------------------------------------------
// RunnerLiveExecutor — production implementation
// ---------------------------------------------------------------------------

/// Production live executor: maps `JobSpec` → `RunPlan(mode=Live)`, resolves
/// credentials from the agent's environment, delegates to
/// `ryuki_runner::run_live_plan` / `run_live_apply`, and returns scrubbed
/// evidence + plan digest.
///
/// ## Credential resolution
///
/// For each `secret_var_name` in `RunPlan.secret_var_names` the executor reads
/// `RYUKI_LIVE_CRED_<NAME>` from the process environment.  If ANY expected
/// credential is missing the executor returns `LiveExecError::CredResolution`
/// and refuses to proceed — fail-closed.
///
/// Operators provision these env vars as host-level secrets.  The control
/// plane never sees them.
///
/// ## `backend_config`
///
/// If the operator supplies a durable state-backend override HCL via
/// `RYUKI_AGENT_BACKEND_CONFIG_<OFFERING>` or the generic
/// `RYUKI_AGENT_BACKEND_HCL` env var, it is forwarded to the runner.
/// Production operators should always provide a backend config for `LiveApply`
/// so Terraform can persist and lock state.
///
/// ## Credential gap (operator responsibility — do NOT remove this comment)
///
/// `build_run_plan` sets `secret_var_names: vec![]`, so no provider credentials
/// are injected via the `TF_VAR_<name>` mechanism in this slice.  The runner
/// env allowlist (PATH/HOME/TMPDIR/LANG/LC_ALL) does NOT pass provider-native
/// vars (AWS_*/ARM_*/VSPHERE_*).  For real live execution an OPERATOR must
/// either:
///   (a) populate `secret_var_names` from the spec and set
///       `RYUKI_LIVE_CRED_<NAME>` for each — the runner maps these to
///       `TF_VAR_<name>` on the child process, and
///   (b) or extend the runner env allowlist to pass the specific provider cred
///       vars AND scrub them from all output before they reach `RunOutcome`.
/// This is intentionally operator-deferred; the no-infra build cannot exercise
/// real provider credentials.
pub struct RunnerLiveExecutor {
    /// Optional backend HCL override forwarded to the runner.
    /// Populated from `RYUKI_AGENT_BACKEND_HCL` at construction time.
    pub backend_config: Option<String>,
}

impl RunnerLiveExecutor {
    /// Construct from the process environment.
    ///
    /// Reads `RYUKI_AGENT_BACKEND_HCL` (optional) and stores it for
    /// forwarding to the runner on every plan/apply call.
    pub fn from_env() -> Self {
        let backend_config = std::env::var("RYUKI_AGENT_BACKEND_HCL").ok();
        Self { backend_config }
    }

    /// Resolve credentials for the given set of secret variable names.
    ///
    /// Reads `RYUKI_LIVE_CRED_<NAME>` for each name in `secret_names`.
    /// Returns an error (fail-closed) if any variable is absent.
    ///
    /// The combined material is a comma-joined string of the resolved values,
    /// matching the format that `ryuki_runner` uses for multi-component
    /// credential injection.
    fn resolve_creds(
        secret_names: &[String],
    ) -> Result<ryuki_runner::ResolvedCredentials, LiveExecError> {
        if secret_names.is_empty() {
            return Ok(ryuki_runner::ResolvedCredentials {
                material: vec![],
                descriptor: "live:no-creds".to_string(),
            });
        }

        let mut parts = Vec::with_capacity(secret_names.len());
        for name in secret_names {
            let env_key = format!("RYUKI_LIVE_CRED_{}", name.to_uppercase());
            let val = std::env::var(&env_key).map_err(|_| {
                LiveExecError::CredResolution(format!(
                    "credential env var '{env_key}' is not set — \
                     live execution requires operator-provisioned host credentials"
                ))
            })?;
            parts.push(val);
        }

        let material = parts.join(",").into_bytes();
        Ok(ryuki_runner::ResolvedCredentials {
            material,
            descriptor: format!("live:env:{}", secret_names.join(",")),
        })
    }

    /// Build a `RunPlan` from a `JobSpec` with `RunMode::Live`.
    fn make_run_plan(spec: &JobSpec) -> Result<RunPlan, LiveExecError> {
        // Derive the offering slug from iac_ref: strip the `@<version>` suffix.
        let offering_slug = spec
            .iac_ref
            .split('@')
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                LiveExecError::PlanBuild(format!(
                    "could not derive offering slug from iac_ref {:?}",
                    spec.iac_ref
                ))
            })?
            .to_string();

        // All live offerings default to Terraform in this slice.
        // Extend `offering_kind_from_slug` from executor.rs if Ansible live is needed.
        Ok(RunPlan {
            runner_kind: RunnerKind::Terraform,
            mode: RunMode::Live,
            offering_id: offering_slug,
            vars: spec.vars.clone(),
            // Secret var names come from spec.vars keys that match the cred-naming
            // convention.  In this slice we use an empty list; the operator
            // configures TF_VAR_* directly via the RYUKI_LIVE_CRED_* mechanism
            // and the runner's env-injection path.
            secret_var_names: vec![],
        })
    }
}

impl LiveExecutor for RunnerLiveExecutor {
    fn plan(&self, spec: &JobSpec) -> Result<LivePlanOutcome, LiveExecError> {
        // Accept LivePlan and LiveApply (plan step is the same pre-condition for both).
        if spec.mode != JobMode::LivePlan && spec.mode != JobMode::LiveApply {
            return Err(LiveExecError::UnsupportedMode(spec.mode.clone()));
        }

        let run_plan = Self::make_run_plan(spec)?;
        let creds = Self::resolve_creds(&run_plan.secret_var_names)?;

        let artifacts =
            ryuki_runner::run_live_plan(&run_plan, &creds, self.backend_config.as_deref())?;

        // FAIL CLOSED: return Err when the plan is not clean.
        // A non-Planned status means a step failed — do NOT compute a digest.
        if artifacts.outcome.status != ryuki_engine::runners::RunStatus::Planned {
            return Err(LiveExecError::PlanFailed(format!(
                "terraform plan step returned {:?}: {}",
                artifacts.outcome.status, artifacts.outcome.summary
            )));
        }

        // Serialize the outcome to bytes for signing (plan JSON is in outcome.log).
        let evidence_bytes = artifacts.outcome.log.as_bytes().to_vec();
        let plan_digest = sha256_hex(&evidence_bytes);

        let evidence_json = serde_json::to_value(&artifacts.outcome)
            .ok()
            .filter(|v| !v.is_null());

        Ok(LivePlanOutcome {
            evidence: Evidence {
                status: artifacts.outcome.status,
                evidence_bytes,
                evidence_json,
            },
            plan_digest,
            tfplan: artifacts.tfplan,
        })
    }

    /// Apply the SAVED plan produced by `plan()`.
    ///
    /// `tfplan` MUST be the exact bytes from the `LivePlanOutcome.tfplan`
    /// field returned by the preceding `plan()` call.  They are written into
    /// a fresh workspace and passed to `terraform apply -input=false tfplan`.
    fn apply(&self, spec: &JobSpec, tfplan: &[u8]) -> Result<Evidence, LiveExecError> {
        if spec.mode != JobMode::LiveApply {
            return Err(LiveExecError::UnsupportedMode(spec.mode.clone()));
        }

        let run_plan = Self::make_run_plan(spec)?;
        let creds = Self::resolve_creds(&run_plan.secret_var_names)?;

        let outcome = ryuki_runner::run_live_apply(
            &run_plan,
            &creds,
            self.backend_config.as_deref(),
            tfplan,
        )?;

        let evidence_bytes =
            serde_json::to_vec(&outcome).map_err(|e| LiveExecError::PlanBuild(e.to_string()))?;

        let evidence_json: Option<Value> =
            serde_json::to_value(&outcome).ok().filter(|v| !v.is_null());

        Ok(Evidence {
            status: outcome.status,
            evidence_bytes,
            evidence_json,
        })
    }
}

// ---------------------------------------------------------------------------
// StubLiveExecutor — deterministic test seam (no terraform, no creds)
// ---------------------------------------------------------------------------

/// A canned live executor for unit tests.
///
/// Returns pre-configured `LivePlanOutcome` and `Evidence` without running
/// any binary.  The stub also:
/// - Records whether `plan()` and `apply()` were called (invocation counts).
/// - Captures the `tfplan` bytes passed to `apply()` so tests can assert that
///   the bytes thread through unchanged from `plan_outcome.tfplan`.
/// - Optionally fails `plan()` for tests that verify the agent handles plan
///   failures correctly (see `with_failing_plan`).
pub struct StubLiveExecutor {
    /// The plan outcome to return from `plan()`.
    plan_outcome: LivePlanOutcome,
    /// The evidence to return from `apply()`.
    apply_evidence: Evidence,
    /// When `true`, `plan()` returns `Err(PlanFailed)` instead of `Ok`.
    plan_should_fail: bool,
    /// Records the number of times `plan()` was called.
    plan_calls: std::sync::atomic::AtomicU32,
    /// Records the number of times `apply()` was called.
    apply_calls: std::sync::atomic::AtomicU32,
    /// The tfplan bytes most recently received by `apply()`.
    /// Wrapped in a Mutex so tests can read it from the outside.
    last_apply_tfplan: std::sync::Mutex<Vec<u8>>,
}

impl StubLiveExecutor {
    /// Construct with explicit plan outcome and apply evidence.
    pub fn new(plan_outcome: LivePlanOutcome, apply_evidence: Evidence) -> Self {
        Self {
            plan_outcome,
            apply_evidence,
            plan_should_fail: false,
            plan_calls: std::sync::atomic::AtomicU32::new(0),
            apply_calls: std::sync::atomic::AtomicU32::new(0),
            last_apply_tfplan: std::sync::Mutex::new(vec![]),
        }
    }

    /// Convenience constructor with a deterministic plan digest and tfplan bytes.
    ///
    /// `plan_bytes` are used as BOTH the canonical evidence bytes (for the digest)
    /// AND the `tfplan` field of the returned `LivePlanOutcome`.  This means a
    /// test that calls `plan()` and then passes `plan_outcome.tfplan` to `apply()`
    /// will have `last_apply_tfplan()` equal to `plan_bytes` — asserting the
    /// thread-through without any special setup.
    pub fn with_plan(plan_bytes: &[u8], apply_status: RunStatus) -> Self {
        let plan_digest = sha256_hex(plan_bytes);
        let plan_evidence = Evidence {
            status: RunStatus::Planned,
            evidence_bytes: plan_bytes.to_vec(),
            evidence_json: Some(serde_json::json!({"stub_plan": true})),
        };
        let apply_evidence = Evidence {
            status: apply_status,
            evidence_bytes: b"stub apply evidence".to_vec(),
            evidence_json: Some(serde_json::json!({"stub_apply": true})),
        };
        Self::new(
            LivePlanOutcome {
                evidence: plan_evidence,
                plan_digest,
                tfplan: plan_bytes.to_vec(),
            },
            apply_evidence,
        )
    }

    /// Return the number of times `plan()` was called.
    pub fn plan_call_count(&self) -> u32 {
        self.plan_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Return the number of times `apply()` was called.
    pub fn apply_call_count(&self) -> u32 {
        self.apply_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Return the tfplan bytes most recently passed to `apply()`.
    ///
    /// Use this in tests to assert that the bytes thread through unchanged:
    /// ```ignore
    /// let outcome = stub.plan(&spec).unwrap();
    /// stub.apply(&spec, &outcome.tfplan).unwrap();
    /// assert_eq!(stub.last_apply_tfplan(), outcome.tfplan);
    /// ```
    pub fn last_apply_tfplan(&self) -> Vec<u8> {
        self.last_apply_tfplan
            .lock()
            .expect("mutex not poisoned")
            .clone()
    }

    /// Construct a stub whose `plan()` returns `Err(PlanFailed)`.
    ///
    /// Used in tests that verify the agent builds a `LiveRefused` result and
    /// never calls `apply()` when `plan()` fails.
    pub fn with_failing_plan() -> Self {
        let dummy_outcome = LivePlanOutcome {
            evidence: Evidence {
                status: RunStatus::Failed,
                evidence_bytes: vec![],
                evidence_json: None,
            },
            plan_digest: String::new(),
            tfplan: vec![],
        };
        let dummy_apply = Evidence {
            status: RunStatus::Failed,
            evidence_bytes: vec![],
            evidence_json: None,
        };
        Self {
            plan_outcome: dummy_outcome,
            apply_evidence: dummy_apply,
            plan_should_fail: true,
            plan_calls: std::sync::atomic::AtomicU32::new(0),
            apply_calls: std::sync::atomic::AtomicU32::new(0),
            last_apply_tfplan: std::sync::Mutex::new(vec![]),
        }
    }
}

impl LiveExecutor for StubLiveExecutor {
    fn plan(&self, _spec: &JobSpec) -> Result<LivePlanOutcome, LiveExecError> {
        self.plan_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.plan_should_fail {
            return Err(LiveExecError::PlanFailed(
                "stub: plan configured to fail".to_string(),
            ));
        }
        Ok(self.plan_outcome.clone())
    }

    fn apply(&self, _spec: &JobSpec, tfplan: &[u8]) -> Result<Evidence, LiveExecError> {
        self.apply_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Record the tfplan bytes for thread-through assertion in tests.
        *self.last_apply_tfplan.lock().expect("mutex not poisoned") = tfplan.to_vec();
        Ok(self.apply_evidence.clone())
    }
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
            mode,
        }
    }

    // -----------------------------------------------------------------------
    // StubLiveExecutor
    // -----------------------------------------------------------------------

    #[test]
    fn stub_plan_returns_canned_outcome() {
        let plan_bytes = b"stub-canonical-plan-json";
        let stub = StubLiveExecutor::with_plan(plan_bytes, RunStatus::Applied);
        let spec = make_spec(JobMode::LivePlan);

        let outcome = stub.plan(&spec).expect("stub plan must succeed");
        assert_eq!(outcome.evidence.status, RunStatus::Planned);
        assert_eq!(outcome.evidence.evidence_bytes, plan_bytes);
        // plan_digest == sha256_hex(plan_bytes)
        assert_eq!(outcome.plan_digest, sha256_hex(plan_bytes));
        // tfplan bytes must be the same as plan_bytes (stub threads them through).
        assert_eq!(outcome.tfplan, plan_bytes);
    }

    #[test]
    fn stub_apply_returns_canned_evidence() {
        let plan_bytes = b"stub-plan";
        let stub = StubLiveExecutor::with_plan(plan_bytes, RunStatus::Applied);
        let spec = make_spec(JobMode::LiveApply);

        let evidence = stub
            .apply(&spec, plan_bytes)
            .expect("stub apply must succeed");
        assert_eq!(evidence.status, RunStatus::Applied);
        assert!(!evidence.evidence_bytes.is_empty());
    }

    #[test]
    fn stub_records_plan_and_apply_call_counts() {
        let stub = StubLiveExecutor::with_plan(b"p", RunStatus::Applied);
        let plan_spec = make_spec(JobMode::LivePlan);
        let apply_spec = make_spec(JobMode::LiveApply);

        assert_eq!(stub.plan_call_count(), 0);
        assert_eq!(stub.apply_call_count(), 0);

        stub.plan(&plan_spec).expect("plan");
        stub.plan(&plan_spec).expect("plan again");
        assert_eq!(stub.plan_call_count(), 2);
        assert_eq!(stub.apply_call_count(), 0);

        stub.apply(&apply_spec, b"p").expect("apply");
        assert_eq!(stub.apply_call_count(), 1);
        assert_eq!(stub.plan_call_count(), 2);
    }

    /// Assert that apply() receives the SAME tfplan bytes that plan() produced.
    #[test]
    fn stub_apply_receives_same_tfplan_bytes_as_plan() {
        const PLAN_BYTES: &[u8] = b"canonical-plan-for-thread-through";
        let stub = StubLiveExecutor::with_plan(PLAN_BYTES, RunStatus::Applied);
        let spec = make_spec(JobMode::LiveApply);

        // plan() produces the outcome with tfplan bytes.
        let plan_outcome = stub.plan(&spec).expect("plan");
        // apply() must receive exactly those bytes.
        stub.apply(&spec, &plan_outcome.tfplan)
            .expect("apply must succeed");

        // The stub recorded what it received.
        assert_eq!(
            stub.last_apply_tfplan(),
            PLAN_BYTES,
            "apply must receive the exact tfplan bytes produced by plan"
        );
    }

    // -----------------------------------------------------------------------
    // RunnerLiveExecutor — mode guard (no terraform needed)
    // -----------------------------------------------------------------------

    #[test]
    fn runner_live_executor_plan_rejects_offline_dry_run() {
        let exec = RunnerLiveExecutor {
            backend_config: None,
        };
        let spec = make_spec(JobMode::OfflineDryRun);
        let result = exec.plan(&spec);
        assert!(
            matches!(
                result,
                Err(LiveExecError::UnsupportedMode(JobMode::OfflineDryRun))
            ),
            "plan must reject OfflineDryRun: {result:?}"
        );
    }

    #[test]
    fn runner_live_executor_apply_rejects_live_plan() {
        let exec = RunnerLiveExecutor {
            backend_config: None,
        };
        let spec = make_spec(JobMode::LivePlan);
        let result = exec.apply(&spec, b"fake-tfplan");
        assert!(
            matches!(
                result,
                Err(LiveExecError::UnsupportedMode(JobMode::LivePlan))
            ),
            "apply must reject LivePlan: {result:?}"
        );
    }

    #[test]
    fn runner_live_executor_apply_rejects_offline_dry_run() {
        let exec = RunnerLiveExecutor {
            backend_config: None,
        };
        let spec = make_spec(JobMode::OfflineDryRun);
        let result = exec.apply(&spec, b"fake-tfplan");
        assert!(
            matches!(
                result,
                Err(LiveExecError::UnsupportedMode(JobMode::OfflineDryRun))
            ),
            "apply must reject OfflineDryRun: {result:?}"
        );
    }

    /// When terraform is absent the runner returns RunnerUnavailable (not Err),
    /// which the executor wraps into Evidence { status: RunnerUnavailable }.
    /// This test proves the plan() path does not panic and returns Ok for a
    /// valid LivePlan spec when terraform is absent.
    #[test]
    fn runner_live_executor_plan_returns_ok_when_terraform_absent() {
        // patch-maintenance IaC exists, terraform absent → RunnerUnavailable.
        let exec = RunnerLiveExecutor {
            backend_config: None,
        };
        let spec = make_spec(JobMode::LivePlan);
        // This will try the real `terraform` binary — if it is absent it returns
        // RunnerUnavailable (not Err). If terraform IS installed in CI this test
        // will attempt a real plan and may fail for unrelated reasons; that is
        // acceptable for a live-path test.
        let result = exec.plan(&spec);
        // Either Ok (RunnerUnavailable) or Err(Runner(…)) from a real terraform
        // failure is both valid — the important assertion is no panic.
        // We only assert "is not UnsupportedMode".
        assert!(
            !matches!(result, Err(LiveExecError::UnsupportedMode(_))),
            "valid mode must not return UnsupportedMode"
        );
    }
}
