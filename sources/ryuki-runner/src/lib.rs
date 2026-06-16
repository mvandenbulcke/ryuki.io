//! Runner module — process spawning for Terraform and Ansible.
//!
//! This crate implements the I/O side of the runner abstraction defined in
//! `ryuki_engine::runners`. It is responsible for:
//! - Creating and managing an isolated per-run workspace (RAII TempDir).
//! - Writing non-secret input files into the workspace.
//! - Injecting resolved credentials via the child process environment and/or
//!   0600 files — NEVER on the command-line argv.
//! - Spawning the binary, capturing stdout/stderr.
//! - Scrubbing credential values from captured output before constructing
//!   `RunOutcome`.
//! - Mapping binary exit codes to `RunStatus`.
//!
//! # Security invariants (MUST hold at all times)
//! - Secret material is NEVER passed as a command-line argument.
//! - Secret material is injected into the child process environment only
//!   (not the parent process env) and/or written to 0600 files in the
//!   workspace, which is removed on drop.
//! - Output is scrubbed for known secret values before being placed into
//!   `RunOutcome.log` or `RunOutcome.summary`.
//! - The workspace TempDir is removed on drop, including on panic.
//! - `ResolvedCredentials` is zeroized on drop immediately after the child
//!   process is configured — no long-lived reference is kept.
//! - `TF_LOG` is never set to `trace` or `debug`. Ansible `-vvv` is never
//!   passed.

pub mod ansible;
pub mod exec;
pub mod iac;
pub mod live;
pub mod live_ansible;
pub mod scrub;
pub mod terraform;
pub mod workspace;

use ryuki_engine::runners::{RunMode, RunOutcome, RunPlan, RunnerError, RunnerKind};

pub use live::{run_live_apply, run_live_plan, LivePlanArtifacts};
pub use live_ansible::{run_ansible_live_apply, run_ansible_live_plan};
pub use ryuki_engine::runners::ResolvedCredentials;

/// The `Runner` trait defines the interface that both `TerraformRunner` and
/// `AnsibleRunner` implement.
///
/// # Binary injection
/// The `binary_path` is injectable so that tests can point it at a fake shim
/// instead of requiring a real terraform/ansible installation.
pub trait Runner {
    /// Returns `true` if the runner binary is present and executable.
    ///
    /// This is a lightweight probe — it does not verify version or
    /// compatibility, only presence. Returns `false` gracefully (never panics)
    /// when the binary is absent.
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
/// NOTE (S5): this does not yet verify the resolved bundle against
/// `JobSpec.iac_digest` (the digest is currently a stub with no producer). Once a
/// real job-dispatch path computes `iac_digest`, the dispatcher must additionally
/// reject a bundle whose digest does not match the approved digest.
pub fn run_offline_dry_run(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
) -> Result<RunOutcome, RunnerError> {
    if plan.mode != RunMode::DryRun {
        return Err(RunnerError::Spawn(format!(
            "run_offline_dry_run only accepts RunMode::DryRun; got {:?} — live execution is S5",
            plan.mode
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
            let runner = terraform::TerraformRunner::new().with_iac(iac_files);
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
            let runner = ansible::AnsibleRunner::new().with_iac(iac_files);
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
