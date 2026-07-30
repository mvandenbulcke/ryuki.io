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
//! The credential variable names come from the OFFERING'S OWN DECLARATION
//! (`ryuki_runner::iac::live_secret_var_names`) — e.g. the vSphere
//! server-deployment offerings declare `VSPHERE_USER` / `VSPHERE_PASSWORD` /
//! `VSPHERE_SERVER`.  For each declared `<NAME>` the resolver reads
//! `RYUKI_LIVE_CRED_<NAME>` from the agent environment and fails closed —
//! naming the missing VARIABLE, never a value — BEFORE any runner/terraform
//! invocation when one is absent.  The control plane never carries the names
//! or the values; both sides derive the names from the same embedded registry.
//!
//! ## `raw_plan_digest`
//!
//! For Terraform, the runner computes SHA-256 over the complete canonical raw
//! `terraform show -json tfplan` plan before redaction and exposes that value as
//! `LivePlanOutcome.raw_plan_digest`. Durable evidence retains only this digest and
//! an allowlisted safe projection. The full plan stays process-local.
//! The gate in `live.rs` then checks:
//!   `replanned_plan_digest == Some(&grant.approved_plan_digest)`
//! so only an operator-reviewed, CP-signed plan is applied.

#[cfg(any(test, feature = "test-fixtures"))]
use ryuki_engine::runners::RunStatus;
use ryuki_engine::runners::{RunMode, RunPlan, RunnerKind};
use ryuki_protocol::{
    sha256_hex, ExecutionTrustProfile, JobMode, JobSpec, EXECUTABLE_PROVENANCE_POLICY_VERSION,
    EXECUTION_TRUST_PROFILE_ALLOWLIST_VERSION, EXECUTION_TRUST_PROFILE_SCHEMA_VERSION,
    PROVIDER_CREDENTIAL_AUTHORITY_MODE, TERRAFORM_STATE_ISOLATION_POLICY_VERSION,
};
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
/// - `raw_plan_digest` — for Terraform, SHA-256 of the complete canonical raw plan
///   before redaction; the gate checks it against the approved grant before
///   allowing apply. Ansible retains its evidence-byte digest contract.
/// - `tfplan` — raw binary plan file bytes (opaque).  Pass verbatim to
///   `LiveExecutor::apply` so the apply step uses EXACTLY the gated plan.
///   MUST NOT be logged, sent to the control plane, or included in evidence.
#[derive(Debug, Clone)]
pub struct LivePlanOutcome {
    pub evidence: Evidence,
    /// Canonical lowercase SHA-256 commitment used for plan approval. For
    /// Terraform this commits to the complete canonical raw plan before
    /// redaction; Ansible retains its check-output commitment contract.
    pub raw_plan_digest: String,
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
    #[error("Terraform state isolation error: {0}")]
    BackendIsolation(String),
    /// The plan step did not complete cleanly (non-zero exit or timeout).
    /// A digest MUST NOT be computed or exposed for a non-clean plan.
    /// Applies to both Terraform (`terraform plan`) and Ansible (`--check`).
    #[error("plan step did not complete cleanly: {0}")]
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
    /// Recompute the complete non-secret execution identity from the exact
    /// local configuration that the next live operation will use. Production
    /// implementations must validate backend isolation, embedded IaC/provider
    /// provenance, and executable admission without contacting a backend or
    /// provider.
    fn execution_trust_profile(
        &self,
        spec: &JobSpec,
        platform: &str,
    ) -> Result<ExecutionTrustProfile, LiveExecError>;

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

    fn plan_with_cancellation(
        &self,
        spec: &JobSpec,
        cancellation: &ryuki_runner::CommandCancellation,
    ) -> Result<LivePlanOutcome, LiveExecError> {
        if cancellation.is_cancelled() {
            return Err(cancelled_live_execution());
        }
        self.plan(spec)
    }

    /// Execute a live apply using the SAVED plan from `plan()`.
    ///
    /// `tfplan` MUST be the exact bytes returned by the preceding `plan()` call
    /// for this job.  The implementation writes them into a fresh workspace and
    /// invokes `terraform apply -input=false tfplan` so that terraform applies
    /// EXACTLY the plan the control-plane gate approved, with no re-planning.
    ///
    /// Accepted mode: `LiveApply` only.
    fn apply(&self, spec: &JobSpec, tfplan: &[u8]) -> Result<Evidence, LiveExecError>;

    fn apply_with_cancellation(
        &self,
        spec: &JobSpec,
        tfplan: &[u8],
        cancellation: &ryuki_runner::CommandCancellation,
    ) -> Result<Evidence, LiveExecError> {
        if cancellation.is_cancelled() {
            return Err(cancelled_live_execution());
        }
        self.apply(spec, tfplan)
    }

    /// Execute a live destroy of the step's applied resources (#42 B2-3).
    ///
    /// There is NO saved-plan artifact for a destroy: the implementation
    /// reconstructs the SAME workspace/backend the step's apply used (offering
    /// IaC bundle + operator backend HCL + job vars) and runs `terraform
    /// destroy -input=false -auto-approve` — the destruction set comes from
    /// the STATE the apply wrote into the durable backend, which is the source
    /// of truth for what this step created.
    ///
    /// Callers MUST invoke this ONLY after `evaluate_live_execution` returned
    /// `Proceed` for the `LiveDestroy` job (step-bound, CP-signed grant) — the
    /// gate is the sole authorisation for a destroy; `-auto-approve` inside the
    /// runner is a terraform mechanic, not an approval.
    ///
    /// Accepted mode: `LiveDestroy` only.
    fn destroy(&self, spec: &JobSpec) -> Result<Evidence, LiveExecError>;

    fn destroy_with_cancellation(
        &self,
        spec: &JobSpec,
        cancellation: &ryuki_runner::CommandCancellation,
    ) -> Result<Evidence, LiveExecError> {
        if cancellation.is_cancelled() {
            return Err(cancelled_live_execution());
        }
        self.destroy(spec)
    }
}

fn cancelled_live_execution() -> LiveExecError {
    LiveExecError::Runner(ryuki_engine::runners::RunnerError::Cancelled)
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
/// The operator must supply a durable state-backend HCL template through
/// `RYUKI_AGENT_BACKEND_HCL`. The template must contain the exact
/// `{STATE_KEY}` token. Before every Terraform live operation, the executor
/// replaces that token with `JobSpec.state_key`; a missing template, missing
/// key, unsafe key, or missing placeholder fails closed before Terraform.
///
/// ## Credential seam (wired — operator provisions the values)
///
/// `make_run_plan` populates `secret_var_names` from the offering's declaration
/// (`ryuki_runner::iac::live_secret_var_names`) for every LIVE mode.  For each
/// declared `<NAME>` (e.g. `VSPHERE_USER`) the operator provisions
/// `RYUKI_LIVE_CRED_<NAME>` on the agent host; `resolve_creds` reads them in
/// declared order and the runner injects `<NAME>` (provider-native) plus
/// `TF_VAR_<lowercased name>` on the terraform child — LIVE modes only.  The
/// runner env allowlist (PATH/HOME/TMPDIR/LANG/LC_ALL) still never passes
/// provider-native vars from the HOST env; only declared, resolved values
/// reach the child, scrubbed from all output.  A missing `RYUKI_LIVE_CRED_*`
/// fails closed BEFORE terraform with the variable name (never a value) in the
/// refusal. Trusted provisioning also supplies a canonical non-secret backend
/// credential-authority id/revision for the backend template. These values are
/// separate environment reads today; a future typed secret-manager adapter must
/// co-resolve backend credentials and authority metadata atomically. The
/// offline dry-run path keeps an empty declaration and empty material — it
/// never sees credentials.
pub struct RunnerLiveExecutor {
    /// Backend HCL template populated from `RYUKI_AGENT_BACKEND_HCL`.
    /// Terraform live jobs require it to contain `{STATE_KEY}`.
    pub backend_config: Option<String>,
    /// Canonical private root required for the local backend. The runner
    /// performs descriptor-bound ownership, mode, and no-follow checks.
    pub local_state_root: Option<std::path::PathBuf>,
    /// Unit tests may bypass only this crate's early availability check so
    /// pure mode/backend/credential preflights remain covered. The runner is a
    /// normal dependency in those tests and still refuses every subprocess at
    /// its sealed containment boundary.
    #[cfg(test)]
    controlled_agent_preflight: Option<ControlledAgentPreflight>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct ControlledAgentPreflight;

/// One resolver return packages provider credential material with the
/// non-secret authority record that is intended to version it. The current
/// inputs are still separate process-environment reads, and each operation may
/// resolve them again; this shape is fail-closed plumbing, not proof that both
/// came atomically from one immutable secret record.
#[derive(Debug)]
struct ResolvedLiveCredentialBundle {
    credentials: ryuki_runner::ResolvedCredentials,
    provider_authority: Option<(String, String)>,
}

impl RunnerLiveExecutor {
    fn require_descendant_containment(&self) -> Result<(), LiveExecError> {
        #[cfg(test)]
        if self.controlled_agent_preflight.is_some() {
            return Ok(());
        }
        if !ryuki_runner::external_subprocess_containment_available() {
            return Err(LiveExecError::PlanBuild(format!(
                "external subprocess descendant containment is unavailable under policy {}",
                ryuki_runner::exec::RUNNER_CONTAINMENT_POLICY_VERSION,
            )));
        }
        Ok(())
    }

    fn provider_authority_reference(
        secret_var_names: &[String],
    ) -> Result<(String, String), LiveExecError> {
        // The vSphere provider destination and account are part of the exact
        // declared credential set. Their raw values stay secret; trusted
        // provisioning supplies one stable public reference and an immutable
        // version that must rotate whenever any member changes.
        let reviewed_set = ["VSPHERE_USER", "VSPHERE_PASSWORD", "VSPHERE_SERVER"];
        if secret_var_names.len() != reviewed_set.len()
            || !secret_var_names
                .iter()
                .zip(reviewed_set)
                .all(|(actual, expected)| actual.as_str() == expected)
        {
            return Err(LiveExecError::CredResolution(
                "reviewed provider authority requires the exact ordered vSphere credential set"
                    .to_string(),
            ));
        }
        let id = std::env::var("RYUKI_LIVE_PROVIDER_AUTHORITY_ID").map_err(|_| {
            LiveExecError::CredResolution(
                "RYUKI_LIVE_PROVIDER_AUTHORITY_ID is required for live execution".to_string(),
            )
        })?;
        let version = std::env::var("RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION").map_err(|_| {
            LiveExecError::CredResolution(
                "RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION is required for live execution".to_string(),
            )
        })?;
        if !ryuki_protocol::provider_authority_reference_is_canonical(&id, &version) {
            return Err(LiveExecError::CredResolution(
                "provider authority reference is malformed; expected a canonical non-secret provider-authority/vsphere/... id and v-prefixed version"
                    .to_string(),
            ));
        }
        Ok((id, version))
    }

    fn backend_credential_authority_reference(
        backend_kind: &str,
    ) -> Result<(String, String), LiveExecError> {
        // This is deliberately a non-secret provisioning reference, not a
        // hash or serialization of backend credentials. The environment seam
        // is a trusted-access compatibility boundary until a pluggable typed
        // secret-manager adapter returns credential material and immutable
        // authority metadata in one atomic resolution result.
        let id = std::env::var("RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_ID").map_err(|_| {
            LiveExecError::CredResolution(
                "RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_ID is required for live execution"
                    .to_string(),
            )
        })?;
        let revision =
            std::env::var("RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION").map_err(|_| {
                LiveExecError::CredResolution(
                    "RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION is required for live execution"
                        .to_string(),
                )
            })?;
        if !ryuki_protocol::backend_credential_authority_reference_is_canonical(
            backend_kind,
            &id,
            &revision,
        ) {
            return Err(LiveExecError::CredResolution(
                "backend credential authority reference is malformed; expected a canonical non-secret backend-credential-authority/<backend-kind>/... id and v-prefixed revision"
                    .to_string(),
            ));
        }
        Ok((id, revision))
    }

    fn build_execution_trust_profile(
        &self,
        spec: &JobSpec,
        platform: &str,
    ) -> Result<ExecutionTrustProfile, LiveExecError> {
        self.require_descendant_containment()?;
        let run_plan = Self::make_run_plan(spec)?;
        if run_plan.runner_kind != RunnerKind::Terraform {
            return Err(LiveExecError::PlanBuild(
                "reviewed live execution requires the Terraform runner".to_string(),
            ));
        }
        let backend = self.isolated_backend(spec)?;
        let (backend_credential_authority_id, backend_credential_authority_revision) =
            Self::backend_credential_authority_reference(backend.backend_kind())?;
        let (provider_source, provider_version) =
            ryuki_runner::iac::reviewed_live_provider_identity(&run_plan.offering_id).ok_or_else(
                || {
                    LiveExecError::PlanBuild(format!(
                        "offering {:?} has no unambiguous reviewed provider lock",
                        run_plan.offering_id
                    ))
                },
            )?;
        // Admit the exact executable before reading raw provider credentials
        // into process memory. The runner repeats this check at command
        // construction, so capability loss still fails closed at spawn.
        let executable = ryuki_runner::approved_terraform_executable_provenance()?;
        let resolved = Self::resolve_creds(&run_plan.secret_var_names)?;
        let (provider_authority_id, provider_authority_version) =
            resolved.provider_authority.ok_or_else(|| {
                LiveExecError::CredResolution(
                    "reviewed live provider has no credential authority record".to_string(),
                )
            })?;

        Ok(ExecutionTrustProfile {
            schema_version: EXECUTION_TRUST_PROFILE_SCHEMA_VERSION.to_string(),
            allowlist_version: EXECUTION_TRUST_PROFILE_ALLOWLIST_VERSION.to_string(),
            platform: platform.to_string(),
            offering: run_plan.offering_id,
            runner_kind: "terraform".to_string(),
            provider_source,
            provider_version,
            provider_authority_id,
            provider_authority_version,
            backend_kind: backend.backend_kind().to_string(),
            backend_credential_authority_id,
            backend_credential_authority_revision,
            backend_authority_digest: backend.backend_authority_digest().to_string(),
            executable_kind: "terraform".to_string(),
            executable_path: executable.canonical_path,
            executable_version: executable.expected_version,
            executable_sha256: executable.expected_sha256,
            executable_provenance_policy_version: EXECUTABLE_PROVENANCE_POLICY_VERSION.to_string(),
            provider_credential_authority_mode: PROVIDER_CREDENTIAL_AUTHORITY_MODE.to_string(),
            backend_credential_authority_mode:
                ryuki_runner::live::BACKEND_CREDENTIAL_AUTHORITY_POLICY_VERSION.to_string(),
            containment_policy_version: format!(
                "{}+{}",
                ryuki_runner::exec::RUNNER_CONTAINMENT_POLICY_VERSION,
                TERRAFORM_STATE_ISOLATION_POLICY_VERSION,
            ),
            iac_digest: spec.iac_digest.clone(),
            state_key: backend.state_key().to_string(),
        })
    }

    /// Construct from the process environment.
    ///
    /// Reads `RYUKI_AGENT_BACKEND_HCL` and the optional
    /// `RYUKI_AGENT_LOCAL_STATE_ROOT`; a local backend requires the latter and
    /// the runner validates it before every Terraform phase.
    pub fn from_env() -> Self {
        let backend_config = std::env::var("RYUKI_AGENT_BACKEND_HCL").ok();
        let local_state_root = std::env::var("RYUKI_AGENT_LOCAL_STATE_ROOT")
            .ok()
            .map(std::path::PathBuf::from);
        Self {
            backend_config,
            local_state_root,
            #[cfg(test)]
            controlled_agent_preflight: None,
        }
    }

    #[cfg(test)]
    fn for_controlled_test_harness(backend_config: Option<String>) -> Self {
        Self {
            backend_config,
            local_state_root: None,
            controlled_agent_preflight: Some(ControlledAgentPreflight),
        }
    }

    #[cfg(test)]
    fn for_controlled_test_harness_with_local_state_root(
        backend_config: String,
        local_state_root: std::path::PathBuf,
    ) -> Self {
        Self {
            backend_config: Some(backend_config),
            local_state_root: Some(local_state_root),
            controlled_agent_preflight: Some(ControlledAgentPreflight),
        }
    }

    /// Resolve one credential-and-authority snapshot for the given secret
    /// variable names.
    ///
    /// Reads `RYUKI_LIVE_CRED_<NAME>` for each name in `secret_names`.
    /// Returns an error (fail-closed) if any credential or its provider
    /// authority reference is absent or malformed.
    ///
    /// The combined material is a comma-joined string of the resolved values,
    /// matching the format that `ryuki_runner` uses for multi-component
    /// credential injection.
    fn resolve_creds(
        secret_names: &[String],
    ) -> Result<ResolvedLiveCredentialBundle, LiveExecError> {
        if secret_names.is_empty() {
            return Ok(ResolvedLiveCredentialBundle {
                credentials: ryuki_runner::ResolvedCredentials {
                    material: vec![],
                    descriptor: "live:no-creds".to_string(),
                },
                provider_authority: None,
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
            // FAIL CLOSED on values the transport cannot carry — the messages
            // name the VARIABLE only, never the value.
            if val.is_empty() {
                return Err(LiveExecError::CredResolution(format!(
                    "credential env var '{env_key}' is set but EMPTY — \
                     refusing live execution with a blank credential"
                )));
            }
            if val.contains(',') {
                return Err(LiveExecError::CredResolution(format!(
                    "credential env var '{env_key}' contains a comma, which the \
                     comma-joined credential transport cannot carry — refusing live \
                     execution rather than mis-pairing credentials"
                )));
            }
            parts.push(val);
        }

        let material = parts.join(",").into_bytes();
        let provider_authority = Self::provider_authority_reference(secret_names)?;
        Ok(ResolvedLiveCredentialBundle {
            credentials: ryuki_runner::ResolvedCredentials {
                material,
                descriptor: format!("live:env:{}", secret_names.join(",")),
            },
            provider_authority: Some(provider_authority),
        })
    }

    /// Instantiate the operator backend template for this spec's CP-owned key.
    fn isolated_backend(
        &self,
        spec: &JobSpec,
    ) -> Result<ryuki_runner::IsolatedBackendConfig, LiveExecError> {
        let template = self.backend_config.as_deref().ok_or_else(|| {
            LiveExecError::BackendIsolation(
                "RYUKI_AGENT_BACKEND_HCL is not set; live Terraform requires an isolated \
                 durable backend template containing {STATE_KEY}"
                    .to_string(),
            )
        })?;
        let state_key = spec.state_key.as_deref().ok_or_else(|| {
            LiveExecError::BackendIsolation(
                "job spec has no state_key (legacy specs may decode but cannot execute live \
                 Terraform)"
                    .to_string(),
            )
        })?;
        ryuki_runner::IsolatedBackendConfig::from_template_with_local_state_root(
            template,
            state_key,
            self.local_state_root.as_deref(),
        )
        .map_err(|e| LiveExecError::BackendIsolation(e.to_string()))
    }

    /// Build a `RunPlan` from a `JobSpec` with `RunMode::Live`.
    ///
    /// The `runner_kind` is derived from the offering slug via
    /// `crate::executor::offering_kind_from_slug` — the same classification
    /// used by the offline dry-run path.  Ansible offerings (patch-maintenance,
    /// zabbix-onboarding, …) get `RunnerKind::Ansible`; everything else gets
    /// `RunnerKind::Terraform`.
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

        // Live provider execution has no digest compatibility fallback. The
        // exact embedded bundle must match the CP-authored JobSpec before the
        // agent resolves credentials or invokes any runner. This blocks stale
        // or tampered agent binaries from executing different IaC than the CP
        // dispatched and approved.
        let approved_digest =
            crate::executor::real_iac_digest(&spec.iac_digest).ok_or_else(|| {
                LiveExecError::PlanBuild(
                    "live execution requires a non-zero lowercase SHA-256 IaC digest".to_string(),
                )
            })?;
        let resolved_digest = ryuki_runner::iac::offering_iac_digest(&offering_slug);
        if resolved_digest.as_deref() != Some(approved_digest) {
            return Err(LiveExecError::PlanBuild(format!(
                "IaC digest mismatch for live offering {offering_slug:?}; refusing provider execution"
            )));
        }

        // Classify runner kind from the offering slug — Ansible keywords resolve
        // to RunnerKind::Ansible, everything else to RunnerKind::Terraform.
        let runner_kind = crate::executor::offering_kind_from_slug(&offering_slug);

        // Secret var names come from the OFFERING'S OWN DECLARATION in the
        // embedded IaC registry — never from the control plane, never from
        // spec.vars.  The vSphere server-deployment offerings declare
        // VSPHERE_USER / VSPHERE_PASSWORD / VSPHERE_SERVER; offerings without
        // provider credentials declare nothing (empty list → no resolution,
        // no injection).  This function is only used by the LIVE paths; the
        // offline dry-run executor builds its own plan with an empty list.
        let secret_var_names: Vec<String> =
            ryuki_runner::iac::live_secret_var_names(&offering_slug)
                .iter()
                .map(|s| s.to_string())
                .collect();

        Ok(RunPlan {
            runner_kind,
            mode: RunMode::Live,
            offering_id: offering_slug,
            vars: spec.vars.clone(),
            secret_var_names,
        })
    }
}

impl RunnerLiveExecutor {
    fn plan_inner(
        &self,
        spec: &JobSpec,
        cancellation: Option<&ryuki_runner::CommandCancellation>,
    ) -> Result<LivePlanOutcome, LiveExecError> {
        self.require_descendant_containment()?;
        // Accept LivePlan and LiveApply (plan step is the same pre-condition for both).
        if spec.mode != JobMode::LivePlan && spec.mode != JobMode::LiveApply {
            return Err(LiveExecError::UnsupportedMode(spec.mode.clone()));
        }

        let run_plan = Self::make_run_plan(spec)?;
        let backend = match run_plan.runner_kind {
            RunnerKind::Terraform => Some(self.isolated_backend(spec)?),
            RunnerKind::Ansible => None,
        };
        let creds = Self::resolve_creds(&run_plan.secret_var_names)?;

        match run_plan.runner_kind {
            RunnerKind::Terraform => {
                let backend = backend.as_ref().expect("Terraform branch builds backend");
                let artifacts = match cancellation {
                    Some(cancellation) => ryuki_runner::run_live_plan_with_cancellation(
                        &run_plan,
                        &creds.credentials,
                        backend,
                        cancellation,
                    )?,
                    None => ryuki_runner::run_live_plan(&run_plan, &creds.credentials, backend)?,
                };

                // FAIL CLOSED: return Err when the plan is not clean.
                // A non-Planned status means a step failed — do NOT compute a digest.
                if artifacts.outcome.status != ryuki_engine::runners::RunStatus::Planned {
                    return Err(LiveExecError::PlanFailed(format!(
                        "terraform plan step returned {:?}: {}",
                        artifacts.outcome.status, artifacts.outcome.summary
                    )));
                }

                // The runner computed this digest over the complete canonical
                // raw plan before any redaction. Evidence below contains only
                // the digest plus an allowlisted safe projection.
                let raw_plan_digest = artifacts.raw_plan_digest.ok_or_else(|| {
                    LiveExecError::PlanFailed(
                        "planned Terraform outcome omitted its raw-plan commitment".to_string(),
                    )
                })?;
                let evidence_bytes = artifacts.outcome.log.as_bytes().to_vec();

                let evidence_json = serde_json::to_value(&artifacts.outcome)
                    .ok()
                    .filter(|v| !v.is_null());

                Ok(LivePlanOutcome {
                    evidence: Evidence {
                        status: artifacts.outcome.status,
                        evidence_bytes,
                        evidence_json,
                    },
                    raw_plan_digest,
                    // Raw tfplan bytes passed to apply() unchanged — closes TOCTOU hole.
                    tfplan: artifacts.tfplan,
                })
            }

            RunnerKind::Ansible => {
                // Ansible plan = `ansible-playbook --check --diff`.
                // No saved plan artifact — see live_ansible.rs module docs.
                let outcome = match cancellation {
                    Some(cancellation) => ryuki_runner::run_ansible_live_plan_with_cancellation(
                        &run_plan,
                        &creds.credentials,
                        cancellation,
                    )?,
                    None => ryuki_runner::run_ansible_live_plan(&run_plan, &creds.credentials)?,
                };

                // FAIL CLOSED: only Planned is acceptable.
                if outcome.status != ryuki_engine::runners::RunStatus::Planned {
                    return Err(LiveExecError::PlanFailed(format!(
                        "ansible --check step returned {:?}: {}",
                        outcome.status, outcome.summary
                    )));
                }

                // Digest = sha256(scrubbed --check --diff output).
                // This is NOT byte-locked like a tfplan, but the gate still requires
                // the CP-signed grant to carry `approved_plan_digest == sha256(check_output)`.
                let evidence_bytes = outcome.log.as_bytes().to_vec();
                let raw_plan_digest = sha256_hex(&evidence_bytes);

                let evidence_json = serde_json::to_value(&outcome).ok().filter(|v| !v.is_null());

                Ok(LivePlanOutcome {
                    evidence: Evidence {
                        status: outcome.status,
                        evidence_bytes,
                        evidence_json,
                    },
                    raw_plan_digest,
                    // Ansible has no saved plan artifact — tfplan is empty.
                    // apply() re-runs the same playbook + vars (AWX model).
                    tfplan: vec![],
                })
            }
        }
    }

    /// Apply the plan produced by `plan()`.
    ///
    /// For **Terraform**: `tfplan` MUST be the exact bytes from `LivePlanOutcome.tfplan`.
    /// They are written into a fresh workspace and passed to `terraform apply
    /// -input=false tfplan` — applies EXACTLY the plan the gate approved.
    ///
    /// For **Ansible**: `tfplan` is IGNORED (it will be an empty `Vec` from
    /// `plan()`).  Ansible is not plan-byte-locked; the apply step re-runs
    /// `ansible-playbook --diff` against live infrastructure.  This is the
    /// correct AWX model: Ansible playbooks are idempotent by design and
    /// `--check` is a best-effort preview, not a cryptographic commitment to
    /// exact mutations.
    fn apply_inner(
        &self,
        spec: &JobSpec,
        tfplan: &[u8],
        cancellation: Option<&ryuki_runner::CommandCancellation>,
    ) -> Result<Evidence, LiveExecError> {
        self.require_descendant_containment()?;
        if spec.mode != JobMode::LiveApply {
            return Err(LiveExecError::UnsupportedMode(spec.mode.clone()));
        }

        let run_plan = Self::make_run_plan(spec)?;
        let backend = match run_plan.runner_kind {
            RunnerKind::Terraform => Some(self.isolated_backend(spec)?),
            RunnerKind::Ansible => None,
        };
        let creds = Self::resolve_creds(&run_plan.secret_var_names)?;

        let outcome = match run_plan.runner_kind {
            RunnerKind::Terraform => {
                let backend = backend.as_ref().expect("Terraform branch builds backend");
                match cancellation {
                    Some(cancellation) => ryuki_runner::run_live_apply_with_cancellation(
                        &run_plan,
                        &creds.credentials,
                        backend,
                        tfplan,
                        cancellation,
                    )?,
                    None => ryuki_runner::run_live_apply(
                        &run_plan,
                        &creds.credentials,
                        backend,
                        tfplan,
                    )?,
                }
            }

            RunnerKind::Ansible => {
                // Ansible is not plan-byte-locked — the tfplan arg is intentionally
                // ignored here.  Apply re-runs the same playbook + vars (AWX model).
                // The gate integrity is provided by the CP-signed grant whose
                // approved_plan_digest was verified against the --check output.
                match cancellation {
                    Some(cancellation) => ryuki_runner::run_ansible_live_apply_with_cancellation(
                        &run_plan,
                        &creds.credentials,
                        cancellation,
                    )?,
                    None => ryuki_runner::run_ansible_live_apply(&run_plan, &creds.credentials)?,
                }
            }
        };

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

    /// Destroy the step's applied resources (#42 B2-3).
    ///
    /// Forwards the SAME `backend_config` used by `plan()`/`apply()` (read once
    /// from `RYUKI_AGENT_BACKEND_HCL` at construction), so the runner's fresh
    /// workspace re-attaches to the state lineage the step's apply wrote — the
    /// state decides what gets destroyed. Evidence follows the apply
    /// conventions: the scrubbed `RunOutcome` serialised as bytes (digest
    /// input) plus the structured JSON mirror.
    fn destroy_inner(
        &self,
        spec: &JobSpec,
        cancellation: Option<&ryuki_runner::CommandCancellation>,
    ) -> Result<Evidence, LiveExecError> {
        self.require_descendant_containment()?;
        if spec.mode != JobMode::LiveDestroy {
            return Err(LiveExecError::UnsupportedMode(spec.mode.clone()));
        }

        let run_plan = Self::make_run_plan(spec)?;
        let backend = match run_plan.runner_kind {
            RunnerKind::Terraform => Some(self.isolated_backend(spec)?),
            RunnerKind::Ansible => None,
        };
        let creds = Self::resolve_creds(&run_plan.secret_var_names)?;

        let outcome = match run_plan.runner_kind {
            RunnerKind::Terraform => {
                let backend = backend.as_ref().expect("Terraform branch builds backend");
                match cancellation {
                    Some(cancellation) => ryuki_runner::run_live_destroy_with_cancellation(
                        &run_plan,
                        &creds.credentials,
                        backend,
                        cancellation,
                    )?,
                    None => ryuki_runner::run_live_destroy(&run_plan, &creds.credentials, backend)?,
                }
            }

            RunnerKind::Ansible => {
                // FAIL CLOSED: Ansible offerings have no terraform state and no
                // generic inverse playbook — there is nothing state-driven to
                // destroy. Refuse rather than fake a teardown; the CP-side
                // lease-expiry sweep halts the rollback for the unexecuted job.
                return Err(LiveExecError::PlanBuild(format!(
                    "LiveDestroy is not supported for Ansible offering '{}' — \
                     playbooks have no terraform state to destroy",
                    run_plan.offering_id
                )));
            }
        };

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

impl LiveExecutor for RunnerLiveExecutor {
    fn execution_trust_profile(
        &self,
        spec: &JobSpec,
        platform: &str,
    ) -> Result<ExecutionTrustProfile, LiveExecError> {
        self.build_execution_trust_profile(spec, platform)
    }

    fn plan(&self, spec: &JobSpec) -> Result<LivePlanOutcome, LiveExecError> {
        self.plan_inner(spec, None)
    }

    fn plan_with_cancellation(
        &self,
        spec: &JobSpec,
        cancellation: &ryuki_runner::CommandCancellation,
    ) -> Result<LivePlanOutcome, LiveExecError> {
        self.plan_inner(spec, Some(cancellation))
    }

    fn apply(&self, spec: &JobSpec, tfplan: &[u8]) -> Result<Evidence, LiveExecError> {
        self.apply_inner(spec, tfplan, None)
    }

    fn apply_with_cancellation(
        &self,
        spec: &JobSpec,
        tfplan: &[u8],
        cancellation: &ryuki_runner::CommandCancellation,
    ) -> Result<Evidence, LiveExecError> {
        self.apply_inner(spec, tfplan, Some(cancellation))
    }

    fn destroy(&self, spec: &JobSpec) -> Result<Evidence, LiveExecError> {
        self.destroy_inner(spec, None)
    }

    fn destroy_with_cancellation(
        &self,
        spec: &JobSpec,
        cancellation: &ryuki_runner::CommandCancellation,
    ) -> Result<Evidence, LiveExecError> {
        self.destroy_inner(spec, Some(cancellation))
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
#[cfg(any(test, feature = "test-fixtures"))]
pub struct StubLiveExecutor {
    /// The plan outcome to return from `plan()`.
    plan_outcome: LivePlanOutcome,
    /// The evidence to return from `apply()`.
    apply_evidence: Evidence,
    /// The evidence to return from `destroy()` (#42 B2-3).
    destroy_evidence: Evidence,
    /// When `true`, `plan()` returns `Err(PlanFailed)` instead of `Ok`.
    plan_should_fail: bool,
    /// Records the number of times `plan()` was called.
    plan_calls: std::sync::atomic::AtomicU32,
    /// Records the number of times `apply()` was called.
    apply_calls: std::sync::atomic::AtomicU32,
    /// Records the number of times `destroy()` was called.
    destroy_calls: std::sync::atomic::AtomicU32,
    /// The tfplan bytes most recently received by `apply()`.
    /// Wrapped in a Mutex so tests can read it from the outside.
    last_apply_tfplan: std::sync::Mutex<Vec<u8>>,
}

#[cfg(any(test, feature = "test-fixtures"))]
impl StubLiveExecutor {
    /// Construct with explicit plan outcome and apply evidence.
    ///
    /// `destroy()` returns canned evidence with the SAME status as
    /// `apply_evidence` — one "mutating outcome" knob drives both, since a
    /// given test exercises either the apply or the destroy path.
    pub fn new(plan_outcome: LivePlanOutcome, apply_evidence: Evidence) -> Self {
        let destroy_evidence = Evidence {
            status: apply_evidence.status.clone(),
            evidence_bytes: b"stub destroy evidence".to_vec(),
            evidence_json: Some(serde_json::json!({"stub_destroy": true})),
        };
        Self {
            plan_outcome,
            apply_evidence,
            destroy_evidence,
            plan_should_fail: false,
            plan_calls: std::sync::atomic::AtomicU32::new(0),
            apply_calls: std::sync::atomic::AtomicU32::new(0),
            destroy_calls: std::sync::atomic::AtomicU32::new(0),
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
        let raw_plan_digest = sha256_hex(plan_bytes);
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
                raw_plan_digest,
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

    /// Return the number of times `destroy()` was called.
    pub fn destroy_call_count(&self) -> u32 {
        self.destroy_calls.load(std::sync::atomic::Ordering::SeqCst)
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
            raw_plan_digest: String::new(),
            tfplan: vec![],
        };
        let dummy_apply = Evidence {
            status: RunStatus::Failed,
            evidence_bytes: vec![],
            evidence_json: None,
        };
        let dummy_destroy = Evidence {
            status: RunStatus::Failed,
            evidence_bytes: vec![],
            evidence_json: None,
        };
        Self {
            plan_outcome: dummy_outcome,
            apply_evidence: dummy_apply,
            destroy_evidence: dummy_destroy,
            plan_should_fail: true,
            plan_calls: std::sync::atomic::AtomicU32::new(0),
            apply_calls: std::sync::atomic::AtomicU32::new(0),
            destroy_calls: std::sync::atomic::AtomicU32::new(0),
            last_apply_tfplan: std::sync::Mutex::new(vec![]),
        }
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl LiveExecutor for StubLiveExecutor {
    fn execution_trust_profile(
        &self,
        spec: &JobSpec,
        platform: &str,
    ) -> Result<ExecutionTrustProfile, LiveExecError> {
        Ok(ExecutionTrustProfile {
            schema_version: EXECUTION_TRUST_PROFILE_SCHEMA_VERSION.to_string(),
            allowlist_version: EXECUTION_TRUST_PROFILE_ALLOWLIST_VERSION.to_string(),
            platform: platform.to_string(),
            offering: spec
                .iac_ref
                .split('@')
                .next()
                .unwrap_or_default()
                .to_string(),
            runner_kind: "terraform".to_string(),
            provider_source: "registry.terraform.io/vmware/vsphere".to_string(),
            provider_version: "2.16.1".to_string(),
            provider_authority_id: "provider-authority/vsphere/stub-fixture".to_string(),
            provider_authority_version: "v1".to_string(),
            backend_kind: "local".to_string(),
            backend_credential_authority_id: "backend-credential-authority/local/stub-fixture"
                .to_string(),
            backend_credential_authority_revision: "v1".to_string(),
            backend_authority_digest: sha256_hex(
                format!(
                    "stub-local-backend-authority:{}",
                    spec.state_key.as_deref().unwrap_or_default()
                )
                .as_bytes(),
            ),
            executable_kind: "terraform".to_string(),
            executable_path: "/test/terraform".to_string(),
            executable_version: "test".to_string(),
            executable_sha256: None,
            executable_provenance_policy_version: EXECUTABLE_PROVENANCE_POLICY_VERSION.to_string(),
            provider_credential_authority_mode: PROVIDER_CREDENTIAL_AUTHORITY_MODE.to_string(),
            backend_credential_authority_mode:
                ryuki_runner::live::BACKEND_CREDENTIAL_AUTHORITY_POLICY_VERSION.to_string(),
            containment_policy_version: format!(
                "{}+{}",
                ryuki_runner::exec::RUNNER_CONTAINMENT_POLICY_VERSION,
                TERRAFORM_STATE_ISOLATION_POLICY_VERSION,
            ),
            iac_digest: spec.iac_digest.clone(),
            state_key: spec.state_key.clone().unwrap_or_default(),
        })
    }

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

    fn destroy(&self, _spec: &JobSpec) -> Result<Evidence, LiveExecError> {
        self.destroy_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.destroy_evidence.clone())
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
        let iac_digest = ryuki_runner::iac::offering_iac_digest("patch-maintenance")
            .expect("test offering has embedded IaC");
        JobSpec {
            request_id: Uuid::new_v4(),
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("positive request resource version"),
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v1.0.0".to_string(),
            iac_digest,
            vars: BTreeMap::new(),
            state_key: Some("request-test".to_string()),
            mode,
        }
    }

    fn private_local_backend_fixture() -> (tempfile::TempDir, std::path::PathBuf, String) {
        let root = tempfile::tempdir().expect("private agent state root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private agent state root permissions");
        }
        let canonical_root =
            std::fs::canonicalize(root.path()).expect("canonical agent state root");
        let state_path = canonical_root.join("ryuki-agent-terraform-{STATE_KEY}.tfstate");
        let template = format!(
            "terraform {{\n  backend \"local\" {{\n    path = \"{}\"\n  }}\n}}",
            state_path.display()
        );
        (root, canonical_root, template)
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
        // raw_plan_digest == sha256_hex(plan_bytes)
        assert_eq!(outcome.raw_plan_digest, sha256_hex(plan_bytes));
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

    #[test]
    fn cancelled_live_lifecycle_never_enters_plan_apply_or_destroy() {
        let stub = StubLiveExecutor::with_plan(b"p", RunStatus::Applied);
        let cancellation = ryuki_runner::CommandCancellation::new();
        cancellation.cancel();

        assert!(stub
            .plan_with_cancellation(&make_spec(JobMode::LivePlan), &cancellation)
            .is_err());
        assert!(stub
            .apply_with_cancellation(&make_spec(JobMode::LiveApply), b"p", &cancellation,)
            .is_err());
        assert!(stub
            .destroy_with_cancellation(&make_spec(JobMode::LiveDestroy), &cancellation)
            .is_err());
        assert_eq!(stub.plan_call_count(), 0);
        assert_eq!(stub.apply_call_count(), 0);
        assert_eq!(stub.destroy_call_count(), 0);
    }

    #[test]
    fn cancellation_between_live_plan_and_apply_prevents_mutation() {
        let stub = StubLiveExecutor::with_plan(b"approved-plan", RunStatus::Applied);
        let spec = make_spec(JobMode::LiveApply);
        let cancellation = ryuki_runner::CommandCancellation::new();

        let plan = stub
            .plan_with_cancellation(&spec, &cancellation)
            .expect("plan completes before lease loss");
        cancellation.cancel();
        let error = stub
            .apply_with_cancellation(&spec, &plan.tfplan, &cancellation)
            .expect_err("lease loss between phases must prevent apply");
        assert!(error.to_string().contains("cancelled"));
        assert_eq!(stub.plan_call_count(), 1);
        assert_eq!(stub.apply_call_count(), 0);
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

    /// destroy() returns the canned evidence and increments its own counter
    /// (independently of plan/apply counters).
    #[test]
    fn stub_destroy_returns_canned_evidence_and_counts() {
        let stub = StubLiveExecutor::with_plan(b"p", RunStatus::Applied);
        let spec = make_spec(JobMode::LiveDestroy);

        assert_eq!(stub.destroy_call_count(), 0);
        let evidence = stub.destroy(&spec).expect("stub destroy must succeed");
        assert_eq!(evidence.status, RunStatus::Applied);
        assert!(!evidence.evidence_bytes.is_empty());
        assert_eq!(stub.destroy_call_count(), 1);
        assert_eq!(stub.plan_call_count(), 0, "plan counter untouched");
        assert_eq!(stub.apply_call_count(), 0, "apply counter untouched");
    }

    // -----------------------------------------------------------------------
    // RunnerLiveExecutor — mode guard (no terraform needed)
    // -----------------------------------------------------------------------

    #[test]
    fn production_shaped_executor_refuses_without_descendant_containment() {
        assert!(
            !ryuki_runner::external_subprocess_containment_available(),
            "the dependency build must not inherit this crate's test cfg"
        );
        let executor = RunnerLiveExecutor::from_env();
        let error = executor
            .plan(&make_spec(JobMode::LivePlan))
            .expect_err("an executor without the private test witness must fail closed");
        let LiveExecError::PlanBuild(message) = error else {
            panic!("containment refusal must be a PlanBuild error: {error:?}");
        };
        assert!(
            message.contains(ryuki_runner::exec::RUNNER_CONTAINMENT_POLICY_VERSION),
            "containment refusal must pin the active policy: {message}"
        );
    }

    #[test]
    fn runner_live_executor_plan_rejects_offline_dry_run() {
        let exec = RunnerLiveExecutor::for_controlled_test_harness(None);
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
    fn terraform_live_jobs_fail_closed_without_isolated_backend_inputs() {
        let (_state_root, canonical_root, valid_template) = private_local_backend_fixture();

        let mut missing_key = make_spec_with_iac_ref(JobMode::LivePlan, "request-preflight@v1.0.0");
        missing_key.state_key = None;
        let exec = RunnerLiveExecutor::for_controlled_test_harness_with_local_state_root(
            valid_template.clone(),
            canonical_root,
        );
        assert!(matches!(
            exec.plan(&missing_key),
            Err(LiveExecError::BackendIsolation(_))
        ));

        let valid_spec = make_spec_with_iac_ref(JobMode::LivePlan, "request-preflight@v1.0.0");
        let missing_local_root =
            RunnerLiveExecutor::for_controlled_test_harness(Some(valid_template.clone()));
        assert!(matches!(
            missing_local_root.isolated_backend(&valid_spec),
            Err(LiveExecError::BackendIsolation(_))
        ));
        let no_template = RunnerLiveExecutor::for_controlled_test_harness(None);
        assert!(matches!(
            no_template.plan(&valid_spec),
            Err(LiveExecError::BackendIsolation(_))
        ));

        let fixed_template = RunnerLiveExecutor::for_controlled_test_harness(Some(
            "# fixed shared backend".to_string(),
        ));
        assert!(matches!(
            fixed_template.plan(&valid_spec),
            Err(LiveExecError::BackendIsolation(_))
        ));

        let mut unsafe_key = valid_spec;
        unsafe_key.state_key = Some("../shared".to_string());
        assert!(matches!(
            exec.plan(&unsafe_key),
            Err(LiveExecError::BackendIsolation(_))
        ));
    }

    #[test]
    fn executor_preserves_control_plane_state_key_when_rendering_backend() {
        let (_state_root, canonical_root, template) = private_local_backend_fixture();
        let exec = RunnerLiveExecutor::for_controlled_test_harness_with_local_state_root(
            template,
            canonical_root,
        );
        let mut request_a = make_spec_with_iac_ref(JobMode::LivePlan, "request-preflight@v1.0.0");
        request_a.state_key = Some("request-a".to_string());
        let mut request_b = request_a.clone();
        request_b.request_id = Uuid::new_v4();
        request_b.state_key = Some("request-b".to_string());

        let backend_a = exec
            .isolated_backend(&request_a)
            .expect("request A backend");
        let backend_b = exec
            .isolated_backend(&request_b)
            .expect("request B backend");
        assert_eq!(backend_a.state_key(), "request-a");
        assert_eq!(backend_b.state_key(), "request-b");
        assert_ne!(backend_a.state_key(), backend_b.state_key());
    }

    #[test]
    fn runner_live_executor_apply_rejects_live_plan() {
        let exec = RunnerLiveExecutor::for_controlled_test_harness(None);
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
        let exec = RunnerLiveExecutor::for_controlled_test_harness(None);
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

    // -- #42 B2-3: destroy() mode + runner-kind guards -----------------------

    #[test]
    fn runner_live_executor_destroy_rejects_live_apply_and_dry_run_modes() {
        let exec = RunnerLiveExecutor::for_controlled_test_harness(None);
        for mode in [
            JobMode::LiveApply,
            JobMode::LivePlan,
            JobMode::OfflineDryRun,
        ] {
            let spec = make_spec(mode.clone());
            let result = exec.destroy(&spec);
            assert!(
                matches!(result, Err(LiveExecError::UnsupportedMode(ref m)) if *m == mode),
                "destroy must reject {mode:?}: {result:?}"
            );
        }
    }

    /// FAIL CLOSED: an Ansible offering has no terraform state — destroy()
    /// must refuse with a clear error, never pretend to tear down.
    #[test]
    fn runner_live_executor_destroy_fails_closed_for_ansible_offering() {
        let exec = RunnerLiveExecutor::for_controlled_test_harness(None);
        // patch-maintenance is an Ansible offering (offering_kind_from_slug).
        let spec = make_spec_with_iac_ref(JobMode::LiveDestroy, "patch-maintenance@v1.0.0");
        let result = exec.destroy(&spec);
        match result {
            Err(LiveExecError::PlanBuild(msg)) => {
                assert!(
                    msg.contains("not supported for Ansible"),
                    "error must explain the Ansible limitation: {msg}"
                );
            }
            other => panic!("Ansible destroy must fail closed with PlanBuild: {other:?}"),
        }
    }

    /// Terraform-offering destroy path reaches the backend-isolation gate and
    /// never falls back to shared/local state when the template is missing.
    #[test]
    fn runner_live_executor_destroy_routes_terraform_offering() {
        let exec = RunnerLiveExecutor::for_controlled_test_harness(None);
        let spec = make_spec_with_iac_ref(JobMode::LiveDestroy, "request-preflight@v1.0.0");
        let result = exec.destroy(&spec);
        assert!(matches!(result, Err(LiveExecError::BackendIsolation(_))));
    }

    /// A Terraform live plan without the operator template fails closed before
    /// checking whether Terraform is installed.
    #[test]
    fn runner_live_executor_plan_rejects_missing_backend_template() {
        let exec = RunnerLiveExecutor::for_controlled_test_harness(None);
        let spec = make_spec_with_iac_ref(JobMode::LivePlan, "request-preflight@v1.0.0");
        let result = exec.plan(&spec);
        assert!(matches!(result, Err(LiveExecError::BackendIsolation(_))));
    }

    // -----------------------------------------------------------------------
    // make_run_plan — offering_kind_from_slug routing (S6)
    // -----------------------------------------------------------------------

    fn make_spec_with_iac_ref(mode: JobMode, iac_ref: &str) -> JobSpec {
        let offering_slug = iac_ref.split('@').next().unwrap_or_default();
        let iac_digest =
            ryuki_runner::iac::offering_iac_digest(offering_slug).unwrap_or_else(|| "0".repeat(64));
        JobSpec {
            request_id: Uuid::new_v4(),
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("positive request resource version"),
            offering_id: Uuid::new_v4(),
            iac_ref: iac_ref.to_string(),
            iac_digest,
            vars: BTreeMap::new(),
            state_key: Some("request-test".to_string()),
            mode,
        }
    }

    /// Ansible slugs must produce RunnerKind::Ansible in the built RunPlan.
    #[test]
    fn make_run_plan_ansible_slug_yields_ansible_runner_kind() {
        let spec = make_spec_with_iac_ref(JobMode::LivePlan, "patch-maintenance@v1.0.0");
        let run_plan = RunnerLiveExecutor::make_run_plan(&spec).expect("must build");
        assert_eq!(
            run_plan.runner_kind,
            RunnerKind::Ansible,
            "patch-maintenance slug must produce RunnerKind::Ansible; got {:?}",
            run_plan.runner_kind
        );
    }

    /// Non-ansible slugs must produce RunnerKind::Terraform in the built RunPlan.
    #[test]
    fn make_run_plan_terraform_slug_yields_terraform_runner_kind() {
        // request-preflight is NOT in ANSIBLE_KEYWORDS → Terraform.
        let tf_spec = make_spec_with_iac_ref(JobMode::LivePlan, "request-preflight@v1.0.0");
        let tf_plan = RunnerLiveExecutor::make_run_plan(&tf_spec).expect("must build");
        assert_eq!(
            tf_plan.runner_kind,
            RunnerKind::Terraform,
            "request-preflight must produce RunnerKind::Terraform; got {:?}",
            tf_plan.runner_kind
        );

        // linux-server-deployment is NOT in ANSIBLE_KEYWORDS (the keyword is
        // linux-server-deployment-playbook) → Terraform.
        let lsd_spec = make_spec_with_iac_ref(JobMode::LivePlan, "linux-server-deployment@v1.0.0");
        let lsd_plan = RunnerLiveExecutor::make_run_plan(&lsd_spec).expect("must build");
        assert_eq!(
            lsd_plan.runner_kind,
            RunnerKind::Terraform,
            "linux-server-deployment must produce RunnerKind::Terraform (keyword is linux-server-deployment-playbook); got {:?}",
            lsd_plan.runner_kind
        );
    }

    #[test]
    fn make_run_plan_refuses_missing_or_mismatched_iac_digest() {
        let mut spec = make_spec_with_iac_ref(JobMode::LivePlan, "linux-server-deployment@v1.0.0");

        spec.iac_digest = "0".repeat(64);
        let missing = RunnerLiveExecutor::make_run_plan(&spec)
            .expect_err("a live job cannot use the all-zero digest placeholder");
        assert!(missing.to_string().contains("requires a non-zero"));

        spec.iac_digest = "a".repeat(64);
        let mismatch = RunnerLiveExecutor::make_run_plan(&spec)
            .expect_err("a live job cannot execute a different embedded bundle");
        assert!(mismatch.to_string().contains("IaC digest mismatch"));
    }

    // -----------------------------------------------------------------------
    // Credential seam: declaration plumbing + fail-closed missing credentials
    // -----------------------------------------------------------------------

    /// Serializes the tests that mutate the process-global RYUKI_LIVE_CRED_*
    /// environment (std::env is process-wide; parallel mutation would race).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const VSPHERE_CRED_KEYS: [&str; 3] = [
        "RYUKI_LIVE_CRED_VSPHERE_USER",
        "RYUKI_LIVE_CRED_VSPHERE_PASSWORD",
        "RYUKI_LIVE_CRED_VSPHERE_SERVER",
    ];

    fn clear_vsphere_cred_env() {
        for key in VSPHERE_CRED_KEYS {
            std::env::remove_var(key);
        }
        std::env::remove_var("RYUKI_LIVE_PROVIDER_AUTHORITY_ID");
        std::env::remove_var("RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION");
        std::env::remove_var("RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_ID");
        std::env::remove_var("RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION");
    }

    /// Live plans for the vSphere server-deployment offerings must carry the
    /// registry-declared secret var names; non-provider offerings carry none.
    /// The declaration comes from the embedded IaC registry — never the CP.
    #[test]
    fn make_run_plan_populates_declared_secret_vars_for_live_modes() {
        for iac_ref in [
            "linux-server-deployment@v1.0.0",
            "windows-server-deployment@v1.0.0",
        ] {
            let spec = make_spec_with_iac_ref(JobMode::LivePlan, iac_ref);
            let run_plan = RunnerLiveExecutor::make_run_plan(&spec).expect("must build");
            assert_eq!(
                run_plan.secret_var_names,
                vec![
                    "VSPHERE_USER".to_string(),
                    "VSPHERE_PASSWORD".to_string(),
                    "VSPHERE_SERVER".to_string()
                ],
                "{iac_ref} must declare the vsphere provider env vars in pairing order"
            );
        }
        for iac_ref in [
            "patch-maintenance@v1.0.0",
            "request-preflight@v1.0.0",
            "zabbix-onboarding@v1.0.0",
        ] {
            let spec = make_spec_with_iac_ref(JobMode::LiveApply, iac_ref);
            let run_plan = RunnerLiveExecutor::make_run_plan(&spec).expect("must build");
            assert!(
                run_plan.secret_var_names.is_empty(),
                "{iac_ref} declares no provider credentials"
            );
        }
    }

    #[test]
    fn provider_authority_requires_the_exact_ordered_reviewed_credential_set() {
        for names in [
            vec!["VSPHERE_USER".to_string(), "VSPHERE_SERVER".to_string()],
            vec![
                "VSPHERE_SERVER".to_string(),
                "VSPHERE_PASSWORD".to_string(),
                "VSPHERE_USER".to_string(),
            ],
            vec![
                "VSPHERE_USER".to_string(),
                "VSPHERE_PASSWORD".to_string(),
                "VSPHERE_SERVER".to_string(),
                "UNREVIEWED_EXTRA".to_string(),
            ],
        ] {
            let err = RunnerLiveExecutor::provider_authority_reference(&names)
                .expect_err("non-canonical credential set must fail closed");
            assert!(matches!(err, LiveExecError::CredResolution(_)));
        }
    }

    #[test]
    fn backend_credential_authority_is_required_and_backend_kind_scoped() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_vsphere_cred_env();

        let missing = RunnerLiveExecutor::backend_credential_authority_reference("local")
            .expect_err("missing backend credential authority must fail closed");
        assert!(missing
            .to_string()
            .contains("RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_ID"));

        std::env::set_var(
            "RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_ID",
            "backend-credential-authority/http/live-exec-test-fixture",
        );
        std::env::set_var("RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION", "v1");
        let wrong_kind = RunnerLiveExecutor::backend_credential_authority_reference("local")
            .expect_err("an authority id for another backend kind must fail closed");
        assert!(wrong_kind.to_string().contains("malformed"));

        std::env::set_var(
            "RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_ID",
            "backend-credential-authority/local/live-exec-test-fixture",
        );
        std::env::remove_var("RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION");
        let missing_revision = RunnerLiveExecutor::backend_credential_authority_reference("local")
            .expect_err("missing backend credential authority revision must fail closed");
        assert!(missing_revision
            .to_string()
            .contains("RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION"));

        std::env::set_var("RYUKI_LIVE_BACKEND_CREDENTIAL_AUTHORITY_REVISION", "v7");
        assert_eq!(
            RunnerLiveExecutor::backend_credential_authority_reference("local")
                .expect("canonical backend credential authority"),
            (
                "backend-credential-authority/local/live-exec-test-fixture".to_string(),
                "v7".to_string(),
            )
        );

        clear_vsphere_cred_env();
    }

    /// FAIL CLOSED BEFORE TERRAFORM: a live job whose declared credential is
    /// missing from the agent environment must be refused with the exact
    /// VARIABLE NAME (and no value) — on plan, apply, AND destroy. The error
    /// variant is `CredResolution`, which only `resolve_creds` produces, and
    /// `resolve_creds` runs before any `ryuki_runner::run_live_*` call — so
    /// this refusal provably happens before terraform could ever start.
    #[test]
    fn live_paths_fail_closed_before_terraform_when_declared_credential_missing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_vsphere_cred_env();
        // Two of three provisioned — the THIRD (server) is the one missing.
        std::env::set_var("RYUKI_LIVE_CRED_VSPHERE_USER", "it-user-value");
        std::env::set_var("RYUKI_LIVE_CRED_VSPHERE_PASSWORD", "it-pass-value");

        let (_state_root, canonical_root, template) = private_local_backend_fixture();
        let exec = RunnerLiveExecutor::for_controlled_test_harness_with_local_state_root(
            template,
            canonical_root,
        );
        let cases: [(JobMode, &str); 3] = [
            (JobMode::LivePlan, "plan"),
            (JobMode::LiveApply, "apply"),
            (JobMode::LiveDestroy, "destroy"),
        ];
        for (mode, label) in cases {
            let spec = make_spec_with_iac_ref(mode.clone(), "linux-server-deployment@v1.0.0");
            let result = match mode {
                JobMode::LivePlan => exec.plan(&spec).map(|_| ()),
                JobMode::LiveApply => exec.apply(&spec, b"fake-tfplan").map(|_| ()),
                JobMode::LiveDestroy => exec.destroy(&spec).map(|_| ()),
                _ => unreachable!(),
            };
            match result {
                Err(LiveExecError::CredResolution(msg)) => {
                    assert!(
                        msg.contains("RYUKI_LIVE_CRED_VSPHERE_SERVER"),
                        "{label}: refusal must name the missing variable: {msg}"
                    );
                    assert!(
                        !msg.contains("it-user-value") && !msg.contains("it-pass-value"),
                        "{label}: refusal must never carry a credential value: {msg}"
                    );
                }
                other => panic!(
                    "{label}: missing credential must produce CredResolution before \
                     terraform; got {other:?}"
                ),
            }
        }

        clear_vsphere_cred_env();
    }

    /// Values the comma-joined transport cannot carry are refused with the
    /// VARIABLE NAME only — an empty value and a comma-containing value.
    #[test]
    fn resolve_creds_fails_closed_on_empty_and_comma_values() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_vsphere_cred_env();
        let names = vec!["VSPHERE_USER".to_string()];

        std::env::set_var("RYUKI_LIVE_CRED_VSPHERE_USER", "");
        let empty_err =
            RunnerLiveExecutor::resolve_creds(&names).expect_err("empty value must fail closed");
        assert!(
            empty_err
                .to_string()
                .contains("RYUKI_LIVE_CRED_VSPHERE_USER")
                && empty_err.to_string().contains("EMPTY"),
            "empty-value refusal must name the variable: {empty_err}"
        );

        std::env::set_var("RYUKI_LIVE_CRED_VSPHERE_USER", "with,comma");
        let comma_err =
            RunnerLiveExecutor::resolve_creds(&names).expect_err("comma value must fail closed");
        let msg = comma_err.to_string();
        assert!(
            msg.contains("RYUKI_LIVE_CRED_VSPHERE_USER") && msg.contains("comma"),
            "comma refusal must name the variable and the reason: {msg}"
        );
        assert!(
            !msg.contains("with,comma"),
            "comma refusal must never carry the value: {msg}"
        );

        clear_vsphere_cred_env();
    }

    /// The profile and runner must consume one resolution event: having every
    /// declared credential is insufficient when its non-secret authority
    /// reference is absent. The refusal names configuration fields only.
    #[test]
    fn resolve_creds_fails_closed_when_provider_authority_is_missing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_vsphere_cred_env();
        std::env::set_var("RYUKI_LIVE_CRED_VSPHERE_USER", "authority-test-user");
        std::env::set_var(
            "RYUKI_LIVE_CRED_VSPHERE_PASSWORD",
            "authority-test-password",
        );
        std::env::set_var("RYUKI_LIVE_CRED_VSPHERE_SERVER", "authority-test-server");

        let names: Vec<String> =
            ryuki_runner::iac::live_secret_var_names("linux-server-deployment")
                .iter()
                .map(|s| s.to_string())
                .collect();
        let err = RunnerLiveExecutor::resolve_creds(&names)
            .expect_err("credentials without authority must fail closed");
        let msg = err.to_string();
        assert!(
            matches!(err, LiveExecError::CredResolution(_))
                && msg.contains("RYUKI_LIVE_PROVIDER_AUTHORITY_ID"),
            "refusal must identify the missing authority field: {msg}"
        );
        for value in [
            "authority-test-user",
            "authority-test-password",
            "authority-test-server",
        ] {
            assert!(
                !msg.contains(value),
                "authority refusal must never carry a credential value: {msg}"
            );
        }

        clear_vsphere_cred_env();
    }

    /// Happy path: all declared credentials provisioned → material is the
    /// comma-joined values in DECLARED order (the runner's pairing contract),
    /// and the descriptor names the variables but never the values.
    #[test]
    fn resolve_creds_joins_values_in_declared_order_and_redacts_descriptor() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_vsphere_cred_env();
        std::env::set_var("RYUKI_LIVE_CRED_VSPHERE_USER", "u-val");
        std::env::set_var("RYUKI_LIVE_CRED_VSPHERE_PASSWORD", "p-val");
        std::env::set_var("RYUKI_LIVE_CRED_VSPHERE_SERVER", "s-val");
        std::env::set_var(
            "RYUKI_LIVE_PROVIDER_AUTHORITY_ID",
            "provider-authority/vsphere/live-exec-test-fixture",
        );
        std::env::set_var("RYUKI_LIVE_PROVIDER_AUTHORITY_VERSION", "v1");

        let names: Vec<String> =
            ryuki_runner::iac::live_secret_var_names("linux-server-deployment")
                .iter()
                .map(|s| s.to_string())
                .collect();
        let creds = RunnerLiveExecutor::resolve_creds(&names).expect("all creds provisioned");
        assert_eq!(
            creds.credentials.material, b"u-val,p-val,s-val",
            "material must be comma-joined in declared order"
        );
        assert!(
            creds.credentials.descriptor.contains("VSPHERE_USER"),
            "descriptor names the variables: {}",
            creds.credentials.descriptor
        );
        for value in ["u-val", "p-val", "s-val"] {
            assert!(
                !creds.credentials.descriptor.contains(value),
                "descriptor must never carry a value: {}",
                creds.credentials.descriptor
            );
        }
        assert_eq!(
            creds.provider_authority,
            Some((
                "provider-authority/vsphere/live-exec-test-fixture".to_string(),
                "v1".to_string(),
            )),
        );

        clear_vsphere_cred_env();
    }

    /// plan() for an Ansible offering routes to ansible live plan (absent binary
    /// → RunnerUnavailable wrapped in PlanFailed, not UnsupportedMode, not panic).
    #[test]
    fn runner_live_executor_plan_routes_ansible_offering_to_ansible_path() {
        let exec = RunnerLiveExecutor::for_controlled_test_harness(None);
        // patch-maintenance is an Ansible offering.
        let spec = make_spec_with_iac_ref(JobMode::LivePlan, "patch-maintenance@v1.0.0");
        let result = exec.plan(&spec);
        // ansible-playbook is likely absent in CI → RunnerUnavailable → PlanFailed.
        // The important assertions: not UnsupportedMode, not panic.
        assert!(
            !matches!(result, Err(LiveExecError::UnsupportedMode(_))),
            "ansible offering must not return UnsupportedMode: {result:?}"
        );
    }

    /// apply() for an Ansible offering routes to ansible live apply (absent binary
    /// → RunnerUnavailable mapped to Failed outcome with no Err, no panic).
    #[test]
    fn runner_live_executor_apply_routes_ansible_offering_to_ansible_path() {
        let exec = RunnerLiveExecutor::for_controlled_test_harness(None);
        let spec = make_spec_with_iac_ref(JobMode::LiveApply, "patch-maintenance@v1.0.0");
        // Pass an empty tfplan — Ansible ignores it.
        let result = exec.apply(&spec, &[]);
        assert!(
            !matches!(result, Err(LiveExecError::UnsupportedMode(_))),
            "ansible offering apply must not return UnsupportedMode: {result:?}"
        );
    }
}
