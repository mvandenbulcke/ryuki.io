//! Runner module — process spawning for Terraform and Ansible.
//!
//! This module implements the I/O side of the runner abstraction defined in
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
pub mod scrub;
pub mod terraform;
pub mod workspace;

use ryuki_engine::runners::{RunOutcome, RunPlan, RunnerError};

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
        creds: &crate::integration::ResolvedCredentials,
    ) -> Result<RunOutcome, RunnerError>;
}
