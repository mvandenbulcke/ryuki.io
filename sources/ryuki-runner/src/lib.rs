//! Runner module — process spawning for Terraform and Ansible.
//!
//! This crate implements the I/O side of the runner abstraction defined in
//! `ryuki_engine::runners`. It is responsible for:
//! - Creating and managing an isolated per-run workspace (RAII TempDir).
//! - Writing non-secret input files into the workspace.
//! - Injecting resolved credentials via the child process environment and/or
//!   0600 files — NEVER on the command-line argv.
//! - Spawning the binary under one timeout/cancellation supervisor with hard
//!   per-stream and combined stdout/stderr limits.
//! - Scrubbing credential values from captured output before constructing
//!   `RunOutcome`.
//! - Mapping binary exit codes to `RunStatus`.
//!
//! # Security invariants (MUST hold at all times)
//! - Top-level Terraform and Ansible CLIs are selected by configured absolute,
//!   canonical paths and admitted through filesystem plus identity/version
//!   validation before any credential-bearing command is constructed.
//! - Secret material is NEVER passed as a command-line argument.
//! - Secret material is injected into the child process environment only
//!   (not the parent process env) and/or written to 0600 files in the
//!   workspace, which is removed on drop.
//! - Output is scrubbed for known secret values before being placed into
//!   `RunOutcome.log` or `RunOutcome.summary`.
//! - Subprocess output overflow fails closed and kills/reaps the process group;
//!   truncation is never used as a substitute for bounded capture.
//! - The workspace TempDir is removed on drop, including on panic.
//! - `ResolvedCredentials` is zeroized on drop immediately after the child
//!   process is configured — no long-lived reference is kept.
//! - `TF_LOG` is never set to `trace` or `debug`. Ansible `-vvv` is never
//!   passed.

pub mod ansible;
pub mod exec;
mod executable;
pub mod iac;
pub mod live;
pub mod live_ansible;
pub mod scrub;
pub mod terraform;
pub mod workspace;

use ryuki_engine::runners::{RunMode, RunOutcome, RunPlan, RunnerError, RunnerKind};

pub use exec::{
    external_subprocess_containment_available, CommandCancellation,
    RUNNER_CONTAINMENT_POLICY_VERSION,
};
pub use executable::{approved_terraform_executable_provenance, ApprovedExecutableProvenance};
pub use live::{
    run_live_apply, run_live_apply_with_cancellation, run_live_destroy,
    run_live_destroy_with_cancellation, run_live_plan, run_live_plan_with_cancellation,
    IsolatedBackendConfig, LivePlanArtifacts, ZeroizingTfPlan, STATE_KEY_PLACEHOLDER,
};
pub use live_ansible::{
    run_ansible_live_apply, run_ansible_live_apply_with_cancellation, run_ansible_live_plan,
    run_ansible_live_plan_with_cancellation,
};
pub use ryuki_engine::runners::ResolvedCredentials;

/// The `Runner` trait defines the interface that both `TerraformRunner` and
/// `AnsibleRunner` implement.
///
/// Test builds can point concrete runners at deterministic shims. Production
/// builds expose no raw binary-path injection and require approved executable
/// configuration.
pub trait Runner {
    /// Returns `true` if the configured runner binary is locally approved and
    /// its bounded availability probe succeeds.
    ///
    /// Returns `false` gracefully (never panics) when configuration,
    /// provenance, identity/version, or availability validation fails.
    fn available(&self) -> bool;

    /// Execute a dry-run (plan or check). No changes are made.
    ///
    /// # Arguments
    /// * `plan` — describes what to run (vars, offering, mode).
    /// * `creds` — resolved credentials; injected into child env/files,
    ///   NEVER on argv. Dropped immediately after child is configured.
    ///
    /// # Returns
    /// `Ok(RunOutcome)` with scrubbed log on success or non-zero exit.
    /// `Err(RunnerError)` for workspace, spawn, or credential-injection
    /// failures.
    fn run_dry(
        &self,
        plan: &RunPlan,
        creds: &ResolvedCredentials,
    ) -> Result<RunOutcome, RunnerError>;
}

// ---------------------------------------------------------------------------
// Public dispatcher — S4b entry point
// ---------------------------------------------------------------------------

/// Dispatch an offline dry-run to the appropriate runner (Terraform or Ansible).
///
/// # Errors
/// - `RunnerError::Spawn` if `plan.mode` is not `RunMode::DryRun` — live
///   execution is S5 and is intentionally rejected here.
/// - Any error propagated from the selected runner's `run_dry` implementation.
///
/// # IaC files — FAIL CLOSED on missing IaC
/// The dispatcher wires the embedded IaC via `iac::resolve` / `iac::resolve_ansible`.
/// If NO embedded IaC exists for the requested offering, this returns an error
/// rather than running an empty workspace. Running an empty workspace would let
/// `terraform`/`ansible` treat it as a no-op success — which the agent would then
/// sign and the control plane would record as `Succeeded`, a false positive. An
/// agent that cannot resolve the approved IaC for an offering must refuse the job.
///
/// IaC-digest integrity is enforced one level up, in the agent's
/// `RunnerExecutor::execute`: it recomputes `iac::offering_iac_digest(offering)`
/// and refuses the job when a real (non-stub) `JobSpec.iac_digest` does not
/// match, before this function is ever called. The control plane sets that
/// digest at dispatch via `iac::offering_iac_digest`. This function therefore
/// runs the bundle it resolves; the approval check has already passed.
pub fn run_offline_dry_run(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
) -> Result<RunOutcome, RunnerError> {
    run_offline_dry_run_inner(plan, creds, None)
}

/// Cancellation-aware offline entry point. One signal is propagated through
/// the version probe and every subprocess phase in the selected runner.
pub fn run_offline_dry_run_with_cancellation(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    cancellation: &exec::CommandCancellation,
) -> Result<RunOutcome, RunnerError> {
    run_offline_dry_run_inner(plan, creds, Some(cancellation))
}

fn run_offline_dry_run_inner(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    cancellation: Option<&exec::CommandCancellation>,
) -> Result<RunOutcome, RunnerError> {
    if plan.mode != RunMode::DryRun {
        return Err(RunnerError::Spawn(format!(
            "run_offline_dry_run only accepts RunMode::DryRun; got {:?} — live execution is S5",
            plan.mode
        )));
    }
    // Dry-runs are credential-free BY CONTRACT (they run with no live access
    // whatsoever). Enforce it at this API boundary, not just at the agent
    // call site: a caller handing secret material to a dry-run is a bug and
    // must fail loudly, never inject silently. Names only in the error.
    if !plan.secret_var_names.is_empty() || !creds.material.is_empty() {
        return Err(RunnerError::Spawn(format!(
            "dry-run refuses credential material: {} secret var(s) declared \
             ({:?}) — offline dry-runs are credential-free by contract",
            plan.secret_var_names.len(),
            plan.secret_var_names
        )));
    }

    match plan.runner_kind {
        RunnerKind::Terraform => {
            let iac_files = iac::resolve(&plan.offering_id).ok_or_else(|| {
                RunnerError::Spawn(format!(
                    "no embedded Terraform IaC for offering '{}' — refusing to run an empty \
                     workspace (a no-op must not be signed as a successful result)",
                    plan.offering_id
                ))
            })?;
            let mut runner = terraform::TerraformRunner::new().with_iac(iac_files);
            if let Some(cancellation) = cancellation {
                runner = runner.with_cancellation(cancellation);
            }
            runner.run_dry(plan, creds)
        }
        RunnerKind::Ansible => {
            let iac_files = iac::resolve_ansible(&plan.offering_id).ok_or_else(|| {
                RunnerError::Spawn(format!(
                    "no embedded Ansible IaC for offering '{}' — refusing to run an empty \
                     workspace (a no-op must not be signed as a successful result)",
                    plan.offering_id
                ))
            })?;
            let mut runner = ansible::AnsibleRunner::new().with_iac(iac_files);
            if let Some(cancellation) = cancellation {
                runner = runner.with_cancellation(cancellation);
            }
            runner.run_dry(plan, creds)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ryuki_engine::runners::RunnerKind;
    use std::collections::BTreeMap;

    fn dummy_creds() -> ResolvedCredentials {
        ResolvedCredentials {
            material: vec![],
            descriptor: "test:dummy".to_string(),
        }
    }

    /// The dry-run API boundary itself refuses credential material, so no
    /// future caller can contaminate an offline run (defense-in-depth beyond
    /// the agent call site, which already passes empty). Error carries names
    /// only, never values.
    #[test]
    fn dry_run_refuses_credential_material_at_the_boundary() {
        let mut plan = make_plan(RunnerKind::Terraform, RunMode::DryRun);
        plan.secret_var_names = vec!["VSPHERE_PASSWORD".to_string()];
        let creds = ResolvedCredentials {
            material: b"super-secret-value".to_vec(),
            descriptor: "test:leaky".to_string(),
        };
        let err = run_offline_dry_run(&plan, &creds).expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("credential-free by contract"), "got: {msg}");
        assert!(msg.contains("VSPHERE_PASSWORD"), "names allowed: {msg}");
        assert!(!msg.contains("super-secret-value"), "values NEVER: {msg}");
    }

    fn make_plan(runner_kind: RunnerKind, mode: RunMode) -> RunPlan {
        RunPlan {
            runner_kind,
            mode,
            offering_id: "patch-maintenance".to_string(),
            vars: BTreeMap::new(),
            secret_var_names: vec![],
        }
    }

    #[test]
    fn run_offline_dry_run_rejects_live_mode() {
        let plan = make_plan(RunnerKind::Terraform, RunMode::Live);
        let creds = dummy_creds();
        let result = run_offline_dry_run(&plan, &creds);
        assert!(
            result.is_err(),
            "run_offline_dry_run must reject RunMode::Live"
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("DryRun") || msg.contains("live"),
            "error must mention mode constraint; got: {msg}"
        );
    }

    #[test]
    fn run_offline_dry_run_rejects_live_mode_for_ansible() {
        let plan = make_plan(RunnerKind::Ansible, RunMode::Live);
        let creds = dummy_creds();
        let result = run_offline_dry_run(&plan, &creds);
        assert!(
            result.is_err(),
            "run_offline_dry_run must reject RunMode::Live for Ansible too"
        );
    }

    #[test]
    fn run_offline_dry_run_accepts_dryrun_terraform() {
        // When terraform is not installed this returns Ok(RunnerUnavailable), never Err.
        let plan = make_plan(RunnerKind::Terraform, RunMode::DryRun);
        let creds = dummy_creds();
        let result = run_offline_dry_run(&plan, &creds);
        assert!(
            result.is_ok(),
            "DryRun dispatch must not error — runner unavailable is Ok(outcome)"
        );
    }

    #[test]
    fn run_offline_dry_run_accepts_dryrun_ansible() {
        // When ansible-playbook is not installed this returns Ok(RunnerUnavailable).
        let plan = make_plan(RunnerKind::Ansible, RunMode::DryRun);
        let creds = dummy_creds();
        let result = run_offline_dry_run(&plan, &creds);
        assert!(
            result.is_ok(),
            "DryRun dispatch must not error for Ansible either"
        );
    }

    #[test]
    fn run_offline_dry_run_rejects_unknown_offering() {
        // FAIL CLOSED: an offering with no embedded IaC must error, NOT run an
        // empty workspace that a binary could report as a no-op success.
        let mut plan = make_plan(RunnerKind::Terraform, RunMode::DryRun);
        plan.offering_id = "no-such-offering-xyz".to_string();
        let creds = dummy_creds();
        let result = run_offline_dry_run(&plan, &creds);
        assert!(
            result.is_err(),
            "unknown offering (no embedded IaC) must fail closed, not run empty"
        );

        // Same for Ansible.
        let mut aplan = make_plan(RunnerKind::Ansible, RunMode::DryRun);
        aplan.offering_id = "no-such-offering-xyz".to_string();
        assert!(
            run_offline_dry_run(&aplan, &creds).is_err(),
            "unknown Ansible offering must fail closed"
        );
    }
}
