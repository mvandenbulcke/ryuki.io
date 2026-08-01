//! Live Ansible driver — `ansible-playbook --check --diff` (plan) + `ansible-playbook --diff` (apply).
//!
//! ## Mode contract
//!
//! Both functions require `plan.mode == RunMode::Live`.  Callers that hold a
//! `RunMode::DryRun` plan must call `run_offline_dry_run` in `lib.rs` instead.
//!
//! ## No saved-plan artifact (AWX model)
//!
//! Unlike Terraform, Ansible has NO saved plan artifact.  The model mirrors AWX:
//!
//! - **Plan** = `ansible-playbook --check --diff` (preview, no mutation).
//!   The caller uses the scrubbed `--check` output to compute the `plan_digest`.
//! - **Apply** = `ansible-playbook --diff` (no `--check`; re-runs the same
//!   playbook + vars).
//!
//! This is intentional and correct.  Ansible's `--check` mode is advisory and
//! does not produce a binary artifact that can be "locked" the way Terraform's
//! `tfplan` can.  The gate still requires a CP-signed grant whose
//! `approved_plan_digest` matches `sha256_hex(scrubbed_check_output)`.  Apply
//! re-runs the playbook against live infrastructure — Ansible's idempotency
//! guarantee makes this safe.
//!
//! The `tfplan` field in `LivePlanArtifacts` is set to an **empty
//! `ZeroizingTfPlan`**
//! for ansible plans.  Callers of `run_ansible_live_apply` MUST NOT pass a
//! `tfplan` byte buffer and instead just re-run the playbook.
//!
//! ## Executable approval and absence
//!
//! Production entry points require `RYUKI_ANSIBLE_PLAYBOOK_EXECUTABLE` and
//! `RYUKI_ANSIBLE_PLAYBOOK_EXPECTED_VERSION`. The absolute canonical
//! executable must pass ownership/mode, identity/version, and optional
//! SHA-256 validation before secrets are processed. Invalid or missing
//! approval configuration is an error; if an approved executable disappears
//! before the availability probe, the outcome is `RunnerUnavailable`.
//!
//! ## Credential gap (operator responsibility)
//!
//! Secrets are passed via a 0600 `--extra-vars @<file>` JSON file in the
//! workspace — NEVER on the command-line argv and NEVER as arbitrary env vars.
//! This mirrors the dry-run `AnsibleRunner` contract from `ansible.rs`.
//! For real live execution an OPERATOR must set `RYUKI_LIVE_CRED_<NAME>` for
//! each `secret_var_name` in the `RunPlan`; the runner maps those to JSON
//! entries in the secrets extra-vars file.
//!
//! ## Security invariants (MUST hold — same as `live.rs` and `ansible.rs`)
//!
//! - The top-level Ansible CLI is locally approved before credentials are
//!   processed or attached; inherited `PATH` never selects it.
//! - Secret material is NEVER passed as a command-line argument.
//! - Secrets are written to a 0600 `--extra-vars @<file>` JSON file only.
//! - Output is scrubbed via `scrub_output` before placement in `RunOutcome.log` / `.summary`.
//! - Workspace `TempDir` is removed on drop.
//! - `-vvv` (verbose) is never passed.
//! - `ANSIBLE_VERBOSITY` is explicitly removed from the child environment.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ryuki_engine::runners::{
    ResolvedCredentials, RunMode, RunOutcome, RunPlan, RunStatus, RunnerError, RunnerKind,
};
use zeroize::Zeroizing;

use super::{
    ansible::secrets_to_json,
    exec::{run_command_with_optional_cancellation, run_version_probe, CommandCancellation},
    executable::{ApprovedExecutable, ApprovedTool},
    iac,
    scrub::scrub_captured_output,
    terraform::{
        credential_components, pin_home_tmpdir_to_workspace, validate_offering_slug,
        validate_var_name, ENV_ALLOWLIST,
    },
    workspace::Workspace,
};

/// Per-subprocess timeout for each ansible-playbook invocation in a live run.
const LIVE_ANSIBLE_TIMEOUT: Duration = Duration::from_secs(600); // 10 min per step

/// Additional blocked prefix specific to Ansible: prevent hijacking Ansible
/// configuration via extra-vars names.
const ANSIBLE_BLOCKED_PREFIX: &str = "ANSIBLE_";

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Execute a live Ansible plan: `ansible-playbook --check --diff`.
///
/// Returns `Ok(RunOutcome)` with `status = Planned` on a clean exit (exit 0).
/// Any non-zero exit code returns `status = Failed`.
/// `RunnerUnavailable` is returned (not `Err`) when the binary is absent.
///
/// The `plan_digest` used by the gate is computed by the caller as
/// `sha256_hex(outcome.log.as_bytes())` — i.e. the SHA-256 of the scrubbed
/// `--check --diff` output.
///
/// There is no saved plan artifact for Ansible (unlike Terraform's `tfplan`).
/// The `LivePlanArtifacts.tfplan` field is always an empty `ZeroizingTfPlan`.
///
/// # Errors
///
/// - `RunnerError::Spawn` if `plan.mode != RunMode::Live`.
/// - `RunnerError::Spawn` if no Ansible IaC is found for the offering.
/// - `RunnerError::Spawn` if the configured Ansible executable does not pass
///   path provenance and identity/version approval.
/// - `RunnerError::CredInjection` if any secret variable name is invalid.
/// - `RunnerError::WorkspaceSetup` if workspace initialisation fails.
/// - `RunnerError::Timeout` if the subprocess exceeds `LIVE_ANSIBLE_TIMEOUT`.
pub fn run_ansible_live_plan(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
) -> Result<RunOutcome, RunnerError> {
    if plan.mode != RunMode::Live {
        return Err(RunnerError::Spawn(format!(
            "run_ansible_live_plan only accepts RunMode::Live; got {:?}",
            plan.mode
        )));
    }

    let executable = ApprovedExecutable::configured(ApprovedTool::AnsiblePlaybook, None)?;
    live_ansible_plan_inner(&executable, plan, creds, None)
}

/// Cancellation-aware live Ansible check entry point.
pub fn run_ansible_live_plan_with_cancellation(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    cancellation: &CommandCancellation,
) -> Result<RunOutcome, RunnerError> {
    if plan.mode != RunMode::Live {
        return Err(RunnerError::Spawn(format!(
            "run_ansible_live_plan only accepts RunMode::Live; got {:?}",
            plan.mode
        )));
    }
    let executable =
        ApprovedExecutable::configured(ApprovedTool::AnsiblePlaybook, Some(cancellation))?;
    live_ansible_plan_inner(&executable, plan, creds, Some(cancellation))
}

/// Execute a live Ansible apply: `ansible-playbook --diff` (no `--check`).
///
/// Unlike Terraform's `run_live_apply`, this function does NOT accept a saved
/// plan artifact.  Ansible re-runs the same playbook + vars against live
/// infrastructure.  The gate's integrity guarantee is provided by the
/// `approved_plan_digest == sha256_hex(check_output)` check, which was
/// validated before this function is called.
///
/// Note: Ansible is not plan-byte-locked (unlike `terraform apply tfplan`).
/// The AWX model accepts this: Ansible playbooks are idempotent by design,
/// and the `--check` preview is a best-effort prediction, not a cryptographic
/// commitment to an exact set of mutations.
///
/// Returns `Ok(RunOutcome)` with `status = Applied` on exit 0,
/// `Failed` on non-zero exit, or `RunnerUnavailable` when the binary is absent.
///
/// # Errors
///
/// Same conditions as `run_ansible_live_plan`.
pub fn run_ansible_live_apply(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
) -> Result<RunOutcome, RunnerError> {
    if plan.mode != RunMode::Live {
        return Err(RunnerError::Spawn(format!(
            "run_ansible_live_apply only accepts RunMode::Live; got {:?}",
            plan.mode
        )));
    }

    let executable = ApprovedExecutable::configured(ApprovedTool::AnsiblePlaybook, None)?;
    live_ansible_apply_inner(&executable, plan, creds, None)
}

/// Cancellation-aware live Ansible apply entry point.
pub fn run_ansible_live_apply_with_cancellation(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    cancellation: &CommandCancellation,
) -> Result<RunOutcome, RunnerError> {
    if plan.mode != RunMode::Live {
        return Err(RunnerError::Spawn(format!(
            "run_ansible_live_apply only accepts RunMode::Live; got {:?}",
            plan.mode
        )));
    }
    let executable =
        ApprovedExecutable::configured(ApprovedTool::AnsiblePlaybook, Some(cancellation))?;
    live_ansible_apply_inner(&executable, plan, creds, Some(cancellation))
}

// ---------------------------------------------------------------------------
// Approved internal implementations plus test-only shim adapters
// ---------------------------------------------------------------------------

/// Test seam for plan command-behavior coverage.
///
/// Runs `ansible-playbook --check --diff <playbook>` in an isolated workspace
/// with extra-vars files for non-secret and secret vars.
#[cfg(test)]
pub(crate) fn live_ansible_plan(
    binary: &str,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
) -> Result<RunOutcome, RunnerError> {
    let executable = ApprovedExecutable::for_test(binary);
    live_ansible_plan_inner(&executable, plan, creds, None)
}

fn live_ansible_plan_inner(
    executable: &ApprovedExecutable,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    cancellation: Option<&CommandCancellation>,
) -> Result<RunOutcome, RunnerError> {
    let binary = executable.path();
    // Validate inputs before any workspace or process creation.
    validate_offering_slug(&plan.offering_id)?;
    for name in &plan.secret_var_names {
        validate_ansible_var_name(name)?;
    }

    // Resolve Ansible IaC — FAIL CLOSED on missing IaC.
    let iac_files = iac::resolve_ansible(&plan.offering_id).ok_or_else(|| {
        RunnerError::Spawn(format!(
            "no embedded Ansible IaC for offering '{}' — \
             refusing to run an empty live workspace",
            plan.offering_id
        ))
    })?;

    // #11 policy gate: refuse unsafe playbook constructs BEFORE any --check run.
    if let Some(refusal) =
        crate::live::iac_policy_refusal(&iac_files, RunnerKind::Ansible, plan.mode)
    {
        return Ok(refusal);
    }

    // Build secret components for scrubbing.
    let components = Zeroizing::new(credential_components(creds.material.as_slice()));
    let secret_refs: Vec<&[u8]> = components.iter().map(|v| v.as_slice()).collect();

    // Binary availability check — ansible-absent-safe.
    if !binary_available(binary, cancellation)? {
        return Ok(RunOutcome {
            runner_kind: RunnerKind::Ansible,
            mode: plan.mode,
            status: RunStatus::RunnerUnavailable,
            summary: format!(
                "runner unavailable: ansible-playbook binary not found at {:?}",
                binary
            ),
            log: String::new(),
            exit_code: None,
            post_apply: None,
        });
    }

    let ws = Workspace::new()?;

    // Write IaC files (playbook + any supporting files).
    for (filename, content) in &iac_files {
        ws.write_file(filename, content.as_bytes())?;
    }

    // Build the command with extra-vars files.
    let playbook_ref = format!("{}.yml", plan.offering_id);
    let (vars_arg, secrets_arg) =
        write_extra_vars_files(&ws, &plan.vars, &plan.secret_var_names, creds)?;

    let mut cmd = build_ansible_command(binary, &playbook_ref, ws.path(), &vars_arg, &secrets_arg);
    cmd.arg("--check").arg("--diff");

    let mut output =
        run_command_with_optional_cancellation(cmd, LIVE_ANSIBLE_TIMEOUT, cancellation)?;

    let scrubbed_log =
        scrub_captured_output(&mut output.stdout, &mut output.stderr, &secret_refs, true);

    let (status, summary) = match output.status.code() {
        Some(0) => (
            RunStatus::Planned,
            extract_ansible_summary(&scrubbed_log, "check"),
        ),
        code => (
            RunStatus::Failed,
            format!(
                "ansible-playbook --check failed (exit {})",
                code.unwrap_or(-1)
            ),
        ),
    };

    Ok(RunOutcome {
        runner_kind: RunnerKind::Ansible,
        mode: plan.mode,
        status,
        summary,
        log: scrubbed_log,
        exit_code: output.status.code(),
        post_apply: None,
    })
}

/// Test seam for apply command-behavior coverage.
///
/// Runs `ansible-playbook --diff <playbook>` (no `--check`) in a fresh isolated
/// workspace.  This re-runs the playbook + vars against live infrastructure.
///
/// See module-level docs for the rationale behind Ansible's no-saved-plan model.
#[cfg(test)]
pub(crate) fn live_ansible_apply(
    binary: &str,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
) -> Result<RunOutcome, RunnerError> {
    let executable = ApprovedExecutable::for_test(binary);
    live_ansible_apply_inner(&executable, plan, creds, None)
}

fn live_ansible_apply_inner(
    executable: &ApprovedExecutable,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    cancellation: Option<&CommandCancellation>,
) -> Result<RunOutcome, RunnerError> {
    let binary = executable.path();
    // Validate inputs.
    validate_offering_slug(&plan.offering_id)?;
    for name in &plan.secret_var_names {
        validate_ansible_var_name(name)?;
    }

    // Resolve Ansible IaC — FAIL CLOSED.
    let iac_files = iac::resolve_ansible(&plan.offering_id).ok_or_else(|| {
        RunnerError::Spawn(format!(
            "no embedded Ansible IaC for offering '{}' — \
             refusing to run an empty live workspace",
            plan.offering_id
        ))
    })?;

    // #11 policy gate: refuse unsafe playbook constructs BEFORE any live apply.
    if let Some(refusal) =
        crate::live::iac_policy_refusal(&iac_files, RunnerKind::Ansible, plan.mode)
    {
        return Ok(refusal);
    }

    // Secret scrubbing components.
    let components = Zeroizing::new(credential_components(creds.material.as_slice()));
    let secret_refs: Vec<&[u8]> = components.iter().map(|v| v.as_slice()).collect();

    // Binary availability check.
    if !binary_available(binary, cancellation)? {
        return Ok(RunOutcome {
            runner_kind: RunnerKind::Ansible,
            mode: plan.mode,
            status: RunStatus::RunnerUnavailable,
            summary: format!(
                "runner unavailable: ansible-playbook binary not found at {:?}",
                binary
            ),
            log: String::new(),
            exit_code: None,
            post_apply: None,
        });
    }

    // Fresh workspace for apply — no state carried over from the plan workspace.
    let ws = Workspace::new()?;

    for (filename, content) in &iac_files {
        ws.write_file(filename, content.as_bytes())?;
    }

    let playbook_ref = format!("{}.yml", plan.offering_id);
    let (vars_arg, secrets_arg) =
        write_extra_vars_files(&ws, &plan.vars, &plan.secret_var_names, creds)?;

    // Apply: --diff only, no --check.
    let mut cmd = build_ansible_command(binary, &playbook_ref, ws.path(), &vars_arg, &secrets_arg);
    cmd.arg("--diff");

    let mut output =
        run_command_with_optional_cancellation(cmd, LIVE_ANSIBLE_TIMEOUT, cancellation)?;

    let scrubbed_log =
        scrub_captured_output(&mut output.stdout, &mut output.stderr, &secret_refs, true);

    let (status, summary) = match output.status.code() {
        Some(0) => (
            RunStatus::Applied,
            extract_ansible_summary(&scrubbed_log, "apply"),
        ),
        code => (
            RunStatus::Failed,
            format!(
                "ansible-playbook apply failed (exit {})",
                code.unwrap_or(-1)
            ),
        ),
    };

    Ok(RunOutcome {
        runner_kind: RunnerKind::Ansible,
        mode: plan.mode,
        status,
        summary,
        log: scrubbed_log,
        exit_code: output.status.code(),
        post_apply: None,
    })
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Lightweight availability probe: runs `ansible-playbook --version` and checks exit 0.
/// Returns `false` when the binary is missing — never panics.
fn binary_available(
    binary: &Path,
    cancellation: Option<&CommandCancellation>,
) -> Result<bool, RunnerError> {
    let mut cmd = Command::new(binary);
    apply_env_allowlist(&mut cmd);
    cmd.arg("--version");
    run_version_probe(cmd, cancellation)
}

/// Populate a `Command` with only the allowed parent environment variables.
fn apply_env_allowlist(cmd: &mut Command) {
    cmd.env_clear();
    for key in ENV_ALLOWLIST {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }
}

/// Validate a variable name for Ansible extra-vars injection.
///
/// Applies the shared identifier/blocked-prefix checks from
/// `terraform::validate_var_name`, then additionally rejects names starting
/// with `ANSIBLE_` to prevent hijacking Ansible configuration via extra-vars.
fn validate_ansible_var_name(name: &str) -> Result<(), RunnerError> {
    validate_var_name(name)?;
    if name.starts_with(ANSIBLE_BLOCKED_PREFIX) {
        return Err(RunnerError::CredInjection(format!(
            "variable name '{name}' starts with reserved Ansible prefix '{ANSIBLE_BLOCKED_PREFIX}'"
        )));
    }
    Ok(())
}

/// Write non-secret and secret extra-vars to 0600 JSON files in the workspace.
///
/// Returns `(Option<String>, Option<String>)` where each `Some` is a
/// `@<path>` argument suitable for passing to `--extra-vars`.
///
/// Secrets are written to a SEPARATE 0600 file so that:
/// - A var named `ANSIBLE_CONFIG` becomes a playbook variable, not an env var.
/// - Secret material never appears in argv.
fn write_extra_vars_files(
    ws: &Workspace,
    vars: &std::collections::BTreeMap<String, String>,
    secret_var_names: &[String],
    creds: &ResolvedCredentials,
) -> Result<(Option<String>, Option<String>), RunnerError> {
    let vars_arg = if !vars.is_empty() {
        let json = vars_to_json(vars);
        let path = ws.write_file_0600("ryuki-vars.json", json.as_bytes())?;
        Some(format!("@{}", path.to_string_lossy()))
    } else {
        None
    };

    let secrets_arg = if !secret_var_names.is_empty() {
        let cred_str = Zeroizing::new(
            std::str::from_utf8(creds.material.as_slice())
                .map(str::to_owned)
                .unwrap_or_default(),
        );
        let json = secrets_to_json(secret_var_names, &cred_str)?;
        let path = ws.write_file_0600("ryuki-secrets.json", json.as_slice())?;
        Some(format!("@{}", path.to_string_lossy()))
    } else {
        None
    };

    Ok((vars_arg, secrets_arg))
}

/// Build an `ansible-playbook` `Command` with the env allowlist applied and
/// security-relevant env vars set.
///
/// Caller must add mode flags (`--check --diff` or `--diff`) after this call.
fn build_ansible_command(
    binary: &Path,
    playbook_ref: &str,
    ws_path: &std::path::Path,
    vars_arg: &Option<String>,
    secrets_arg: &Option<String>,
) -> Command {
    let mut cmd = Command::new(binary);
    apply_env_allowlist(&mut cmd);
    pin_home_tmpdir_to_workspace(&mut cmd, ws_path);
    cmd.arg(playbook_ref)
        .current_dir(ws_path)
        .env("ANSIBLE_LOCAL_TEMP", ws_path)
        .env("ANSIBLE_HOST_KEY_CHECKING", "False")
        .env("PYTHONWARNINGS", "ignore")
        .env_remove("ANSIBLE_VERBOSITY");

    if let Some(ref arg) = vars_arg {
        cmd.args(["--extra-vars", arg]);
    }
    if let Some(ref arg) = secrets_arg {
        cmd.args(["--extra-vars", arg]);
    }

    cmd
}

/// Serialize non-secret vars to JSON for `--extra-vars @file.json`.
fn vars_to_json(vars: &std::collections::BTreeMap<String, String>) -> String {
    let map: serde_json::Map<String, serde_json::Value> = vars
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    serde_json::to_string_pretty(&map).unwrap_or_else(|_| "{}".to_string())
}

/// Extract a one-line summary from scrubbed ansible output.
///
/// Looks for the PLAY RECAP block first; falls back to a generic message.
/// `phase` is "check" or "apply" and is embedded in the fallback message.
fn extract_ansible_summary(log: &str, phase: &str) -> String {
    let mut in_recap = false;
    for line in log.lines() {
        if line.contains("PLAY RECAP") {
            in_recap = true;
            continue;
        }
        if in_recap {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                return format!("{phase}: {trimmed}");
            }
        }
    }
    format!("ansible-playbook --{phase} completed")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn dummy_creds() -> ResolvedCredentials {
        ResolvedCredentials {
            material: vec![],
            descriptor: "test:dummy".to_string(),
        }
    }

    fn live_ansible_plan_spec(offering_id: &str) -> RunPlan {
        RunPlan {
            runner_kind: RunnerKind::Ansible,
            mode: RunMode::Live,
            offering_id: offering_id.to_string(),
            vars: BTreeMap::new(),
            secret_var_names: vec![],
        }
    }

    // -----------------------------------------------------------------------
    // Mode guard
    // -----------------------------------------------------------------------

    #[test]
    fn run_ansible_live_plan_rejects_dry_run_mode() {
        let mut plan = live_ansible_plan_spec("patch-maintenance");
        plan.mode = RunMode::DryRun;
        let result = run_ansible_live_plan(&plan, &dummy_creds());
        assert!(
            result.is_err(),
            "run_ansible_live_plan must reject RunMode::DryRun"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Live") || msg.contains("DryRun"),
            "error must mention mode; got: {msg}"
        );
    }

    #[test]
    fn run_ansible_live_apply_rejects_dry_run_mode() {
        let mut plan = live_ansible_plan_spec("patch-maintenance");
        plan.mode = RunMode::DryRun;
        let result = run_ansible_live_apply(&plan, &dummy_creds());
        assert!(
            result.is_err(),
            "run_ansible_live_apply must reject RunMode::DryRun"
        );
    }

    // -----------------------------------------------------------------------
    // Missing IaC — fail closed
    // -----------------------------------------------------------------------

    #[test]
    fn run_ansible_live_plan_fails_closed_on_missing_iac() {
        let plan = live_ansible_plan_spec("no-such-offering-xyz");
        let result = live_ansible_plan("ansible-playbook", &plan, &dummy_creds());
        assert!(
            result.is_err(),
            "run_ansible_live_plan must fail closed when IaC is missing"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no embedded") || msg.contains("IaC"),
            "error must mention missing IaC; got: {msg}"
        );
    }

    #[test]
    fn run_ansible_live_apply_fails_closed_on_missing_iac() {
        let plan = live_ansible_plan_spec("no-such-offering-xyz");
        let result = live_ansible_apply("ansible-playbook", &plan, &dummy_creds());
        assert!(
            result.is_err(),
            "run_ansible_live_apply must fail closed when IaC is missing"
        );
    }

    // -----------------------------------------------------------------------
    // ansible-playbook absent → RunnerUnavailable (not Err, not panic)
    // -----------------------------------------------------------------------

    #[test]
    fn run_ansible_live_plan_absent_returns_unavailable() {
        let plan = live_ansible_plan_spec("patch-maintenance");
        let result = live_ansible_plan(
            "/nonexistent/ansible-playbook-fake-live",
            &plan,
            &dummy_creds(),
        );
        assert!(result.is_ok(), "absent binary must not return Err");
        let outcome = result.unwrap();
        assert_eq!(
            outcome.status,
            RunStatus::RunnerUnavailable,
            "absent binary must return RunnerUnavailable; got: {:?}",
            outcome.status
        );
    }

    #[test]
    fn run_ansible_live_apply_absent_returns_unavailable() {
        let plan = live_ansible_plan_spec("patch-maintenance");
        let result = live_ansible_apply(
            "/nonexistent/ansible-playbook-fake-live-apply",
            &plan,
            &dummy_creds(),
        );
        assert!(
            result.is_ok(),
            "absent binary must not return Err for apply"
        );
        let outcome = result.unwrap();
        assert_eq!(
            outcome.status,
            RunStatus::RunnerUnavailable,
            "absent binary must return RunnerUnavailable for apply; got: {:?}",
            outcome.status
        );
    }

    // -----------------------------------------------------------------------
    // Secrets NEVER in argv
    // -----------------------------------------------------------------------

    #[test]
    fn live_ansible_plan_secret_not_in_argv() {
        let ws = Workspace::new().expect("test workspace");
        let shim = ws.path().join("fake-ans-plan-argv");
        let script = "#!/bin/sh\necho \"ARGV: $@\"\nexit 0\n";
        std::fs::write(&shim, script).expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let mut plan = live_ansible_plan_spec("patch-maintenance");
        plan.secret_var_names = vec!["api_key".to_string()];

        let creds = ResolvedCredentials {
            material: b"SUPER-SECRET-LIVE-ANSIBLE".to_vec(),
            descriptor: "test:live".to_string(),
        };

        let result = live_ansible_plan(&shim.to_string_lossy(), &plan, &creds);
        assert!(result.is_ok(), "plan shim must not error: {result:?}");
        let outcome = result.unwrap();
        // The shim echoes argv — secret must not appear there.
        assert!(
            !outcome.log.contains("SUPER-SECRET-LIVE-ANSIBLE"),
            "secret must not be in argv; log: {:?}",
            outcome.log
        );
    }

    // -----------------------------------------------------------------------
    // Output is scrubbed
    // -----------------------------------------------------------------------

    #[test]
    fn live_ansible_plan_scrubs_secret_from_output() {
        // Shim cats any @<file> args (simulating a leaky playbook).
        let ws_shim = Workspace::new().expect("ws");
        let shim = ws_shim.path().join("fake-ans-plan-scrub");
        let script = "#!/bin/sh\n\
                      for arg in \"$@\"; do\n\
                        case \"$arg\" in @*)\n\
                          cat \"${arg#@}\"\n\
                        ;;\n\
                        esac\n\
                      done\n\
                      exit 0\n";
        std::fs::write(&shim, script).expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let mut plan = live_ansible_plan_spec("patch-maintenance");
        plan.secret_var_names = vec!["vault_pass".to_string()];

        let secret = "LIVE-ANSIBLE-SECRET-VALUE";
        let creds = ResolvedCredentials {
            material: secret.as_bytes().to_vec(),
            descriptor: "test:live".to_string(),
        };

        let result = live_ansible_plan(&shim.to_string_lossy(), &plan, &creds);
        assert!(result.is_ok(), "scrub test must not error: {result:?}");
        let outcome = result.unwrap();
        assert!(
            !outcome.log.contains(secret),
            "secret must be scrubbed from log; got: {:?}",
            outcome.log
        );
        assert!(
            !outcome.summary.contains(secret),
            "secret must be scrubbed from summary"
        );
    }

    // -----------------------------------------------------------------------
    // Shim that exits 0 → Planned (plan) / Applied (apply)
    // -----------------------------------------------------------------------

    #[test]
    fn live_ansible_plan_exit_zero_yields_planned() {
        let ws = Workspace::new().expect("ws");
        let shim = ws.path().join("fake-ans-plan-ok");
        // --version exits 0, everything else exits 0.
        std::fs::write(&shim, "#!/bin/sh\nexit 0\n").expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_ansible_plan_spec("patch-maintenance");
        let result = live_ansible_plan(&shim.to_string_lossy(), &plan, &dummy_creds());
        assert!(result.is_ok(), "shim plan must not error: {result:?}");
        assert_eq!(
            result.unwrap().status,
            RunStatus::Planned,
            "exit 0 must yield Planned"
        );
    }

    #[test]
    fn live_ansible_apply_exit_zero_yields_applied() {
        let ws = Workspace::new().expect("ws");
        let shim = ws.path().join("fake-ans-apply-ok");
        std::fs::write(&shim, "#!/bin/sh\nexit 0\n").expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_ansible_plan_spec("patch-maintenance");
        let result = live_ansible_apply(&shim.to_string_lossy(), &plan, &dummy_creds());
        assert!(result.is_ok(), "shim apply must not error: {result:?}");
        assert_eq!(
            result.unwrap().status,
            RunStatus::Applied,
            "exit 0 must yield Applied"
        );
    }

    // -----------------------------------------------------------------------
    // Non-zero exit → Failed (not Planned/Applied)
    // -----------------------------------------------------------------------

    #[test]
    fn live_ansible_plan_nonzero_exit_yields_failed() {
        let ws = Workspace::new().expect("ws");
        let shim = ws.path().join("fake-ans-plan-fail");
        // --version exits 0 (so binary_available passes), everything else exits 2.
        std::fs::write(
            &shim,
            "#!/bin/sh\ncase \"$1\" in --version) exit 0;; *) exit 2;; esac\n",
        )
        .expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_ansible_plan_spec("patch-maintenance");
        let result = live_ansible_plan(&shim.to_string_lossy(), &plan, &dummy_creds());
        assert!(
            result.is_ok(),
            "non-zero exit must not return Err: {result:?}"
        );
        assert_eq!(
            result.unwrap().status,
            RunStatus::Failed,
            "non-zero exit must yield Failed"
        );
    }

    // -----------------------------------------------------------------------
    // apply does NOT pass --check (verifiable via shim)
    // -----------------------------------------------------------------------

    #[test]
    fn live_ansible_apply_does_not_pass_check_flag() {
        let ws = Workspace::new().expect("ws");
        let shim = ws.path().join("fake-ans-apply-nocheck");
        // Fail if --check appears in argv.
        let script = r#"#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "--check" ]; then
    echo "FAIL: --check must not be passed to apply" >&2
    exit 99
  fi
done
exit 0
"#;
        std::fs::write(&shim, script).expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_ansible_plan_spec("patch-maintenance");
        let result = live_ansible_apply(&shim.to_string_lossy(), &plan, &dummy_creds());
        assert!(result.is_ok(), "apply must not error: {result:?}");
        let outcome = result.unwrap();
        assert_eq!(
            outcome.status,
            RunStatus::Applied,
            "apply shim without --check must yield Applied; log: {}",
            outcome.log
        );
    }

    // -----------------------------------------------------------------------
    // plan passes both --check AND --diff (verifiable via shim)
    // -----------------------------------------------------------------------

    #[test]
    fn live_ansible_plan_passes_check_and_diff_flags() {
        let ws = Workspace::new().expect("ws");
        let shim = ws.path().join("fake-ans-plan-flags");
        // Exit 0 for --version (binary_available probe).
        // Fail if either --check or --diff is absent on the actual playbook invocation.
        let script = r#"#!/bin/sh
# Pass the binary_available probe.
for arg in "$@"; do
  [ "$arg" = "--version" ] && exit 0
done
has_check=0
has_diff=0
for arg in "$@"; do
  [ "$arg" = "--check" ] && has_check=1
  [ "$arg" = "--diff" ]  && has_diff=1
done
if [ "$has_check" = "0" ] || [ "$has_diff" = "0" ]; then
  echo "FAIL: plan must pass both --check and --diff" >&2
  exit 99
fi
exit 0
"#;
        std::fs::write(&shim, script).expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_ansible_plan_spec("patch-maintenance");
        let result = live_ansible_plan(&shim.to_string_lossy(), &plan, &dummy_creds());
        assert!(result.is_ok(), "plan flags test must not error: {result:?}");
        assert_eq!(
            result.unwrap().status,
            RunStatus::Planned,
            "plan with --check --diff shim must yield Planned"
        );
    }

    // -----------------------------------------------------------------------
    // Helper unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_ansible_summary_finds_recap() {
        let log =
            "PLAY [all] ****\nTASK [check] ****\n\nPLAY RECAP ****\nlocalhost : ok=1 changed=0\n";
        let summary = extract_ansible_summary(log, "check");
        assert!(
            summary.contains("ok=1"),
            "recap line must be captured; got: {summary}"
        );
    }

    #[test]
    fn extract_ansible_summary_fallback() {
        let log = "some ansible output without recap";
        let summary = extract_ansible_summary(log, "apply");
        assert!(
            summary.contains("apply"),
            "fallback must mention phase; got: {summary}"
        );
    }

    #[test]
    fn validate_ansible_var_name_rejects_ansible_prefix() {
        assert!(validate_ansible_var_name("ANSIBLE_CONFIG").is_err());
        assert!(validate_ansible_var_name("ANSIBLE_VAULT_PASSWORD_FILE").is_err());
    }

    #[test]
    fn validate_ansible_var_name_rejects_tf_log() {
        assert!(validate_ansible_var_name("TF_LOG").is_err());
    }

    #[test]
    fn validate_ansible_var_name_accepts_safe_names() {
        assert!(validate_ansible_var_name("api_key").is_ok());
        assert!(validate_ansible_var_name("vault_pass").is_ok());
        assert!(validate_ansible_var_name("_private").is_ok());
    }
}
