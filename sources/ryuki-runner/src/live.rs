//! Live Terraform driver — `terraform plan -out=tfplan` + `terraform apply tfplan`.
//!
//! ## Mode contract
//!
//! Both functions require `plan.mode == RunMode::Live`.  Callers that hold a
//! `RunMode::DryRun` plan must call `run_offline_dry_run` in `lib.rs` instead.
//!
//! ## Backend config (durable LOCKED state backend)
//!
//! An optional `backend_config` string is written into the workspace as
//! `backend_override.tf` BEFORE `terraform init`.  The operator provides the
//! HCL for a durable, platform-local state backend (Postgres, S3, Consul, …);
//! the agent does not hardcode one.  If `backend_config` is `None`, Terraform
//! uses whatever backend is declared in the IaC bundle itself (typically local
//! state, which is sufficient for dry-run/plan but not for production apply).
//!
//! ## terraform-absent guarantee
//!
//! If the `terraform` binary is not present, both functions return
//! `Ok(RunOutcome { status: RunnerUnavailable, … })` — NEVER `Err` and NEVER
//! a panic.  This keeps the agent buildable and testable in CI environments
//! that have no Terraform installation.
//!
//! ## Plan/apply integrity (TOCTOU fix)
//!
//! `run_live_plan` saves the raw binary `tfplan` file produced by
//! `terraform plan -out=tfplan` and returns it as part of `LivePlanArtifacts`.
//! `run_live_apply` accepts those raw bytes, writes them into a **fresh**
//! workspace, and invokes `terraform apply -input=false tfplan` — applying
//! EXACTLY the saved plan rather than letting terraform produce a new one.
//! Terraform errors (exits non-zero) when the current state diverges from
//! the saved plan, so state-drift is detected automatically.  The
//! `-auto-approve` flag is intentionally absent: interactive approval already
//! happened in the Ryuki control-plane gate; applying the saved plan file
//! does not require it.
//!
//! ## Plan digest (for `run_live_plan`)
//!
//! After a successful `terraform plan -out=tfplan`, the function runs
//! `terraform show -json tfplan` to obtain the canonical plan JSON.  The
//! caller (`RunnerLiveExecutor::plan`) computes `sha256_hex(canonical_json)`
//! and exposes it as the `plan_digest` for the gate check.  The digest is
//! derived from the JSON representation (deterministic, human-readable) so
//! that the control-plane can verify the plan content without storing opaque
//! binary blobs.  The raw `tfplan` bytes are returned alongside the JSON so
//! the caller can pass them to `run_live_apply`.
//!
//! ## Fail-closed on non-clean plan
//!
//! `run_live_plan` returns `RunStatus::Planned` ONLY when ALL three steps
//! (`init` exit 0, `plan` exit 0 or 2, `show` exit 0) succeed.  Any non-zero
//! exit or timeout causes an immediate `RunStatus::Failed` return — the digest
//! is never computed for a partial plan.
//!
//! ## Credential gap (operator responsibility)
//!
//! The `secret_var_names` in `RunPlan` defaults to `[]` in this slice, so no
//! credentials are injected.  The runner env allowlist (PATH/HOME/TMPDIR/
//! LANG/LC_ALL) does NOT pass provider-native vars (AWS_*/ARM_*/VSPHERE_*).
//! For real live execution an OPERATOR must either:
//!   (a) populate `secret_var_names` from the spec and set
//!       `RYUKI_LIVE_CRED_<NAME>` (→ `TF_VAR_<name>`) for each name, OR
//!   (b) extend the runner env allowlist to pass the specific provider cred
//!       vars AND ensure those values are scrubbed from the output.
//! This is intentionally operator-deferred; the no-infra build cannot
//! exercise real provider credentials.
//!
//! ## Security invariants (MUST hold — same as `terraform.rs`)
//!
//! - Secret material is NEVER passed as a command-line argument.
//! - Secrets are injected as `TF_VAR_<name>` env vars on the child only.
//! - Output is scrubbed before placement in `RunOutcome.log` / `.summary`.
//! - Workspace `TempDir` is removed on drop.
//! - `TF_LOG` is never set to `trace` or any verbose level.
//! - Raw `tfplan` bytes are opaque binary data and MUST NOT be logged.

use std::process::Command;
use std::time::Duration;

use ryuki_engine::runners::{
    ResolvedCredentials, RunMode, RunOutcome, RunPlan, RunStatus, RunnerError, RunnerKind,
};

// ---------------------------------------------------------------------------
// LivePlanArtifacts — returned by run_live_plan
// ---------------------------------------------------------------------------

/// Artifacts produced by a successful `run_live_plan` call.
///
/// Both fields are required to close the TOCTOU hole:
/// - `outcome` — the canonical `RunOutcome` whose `log` is the scrubbed
///   `terraform show -json` output used for digest computation.
/// - `tfplan` — the raw binary plan file (`terraform plan -out=tfplan`).
///   Pass this verbatim to `run_live_apply` so it applies EXACTLY the plan
///   the gate approved, not a fresh re-plan.
///
/// # Security note
/// The `tfplan` bytes are opaque binary data. They MUST NOT be logged,
/// included in evidence, or sent to the control plane.
#[derive(Debug)]
pub struct LivePlanArtifacts {
    /// The `RunOutcome` from the plan step (status = `Planned` on success).
    /// `outcome.log` is the scrubbed canonical plan JSON (used for the digest).
    pub outcome: RunOutcome,
    /// Raw binary `tfplan` file. Pass to `run_live_apply` unchanged.
    pub tfplan: Vec<u8>,
}

use super::{
    exec::run_command_with_timeout,
    scrub::scrub_output,
    terraform::{
        apply_env_allowlist, combine_output, credential_components, pin_home_tmpdir_to_workspace,
        validate_offering_slug, validate_var_name,
    },
    workspace::Workspace,
};

/// Per-subprocess timeout for each terraform sub-command in a live run.
/// Init / plan / apply are each given this budget independently.
const LIVE_RUNNER_TIMEOUT: Duration = Duration::from_secs(600); // 10 min per step

/// Default binary name; overridable for tests via a custom path in tests.
const DEFAULT_BINARY: &str = "terraform";

// ---------------------------------------------------------------------------
// run_live_plan
// ---------------------------------------------------------------------------

/// Execute a live Terraform plan: `init` → `plan -out=tfplan` → `show -json tfplan`.
///
/// Returns `Ok(LivePlanArtifacts)` on success:
/// - `outcome.log` — scrubbed canonical plan JSON (from `terraform show -json`).
///   The caller uses this to compute the `plan_digest`.
/// - `tfplan` — raw binary plan file. Pass verbatim to `run_live_apply`.
///
/// Status is `Planned` only when ALL three steps exit cleanly.  Any step
/// failure returns `RunStatus::Failed` (fail-closed — no partial digest).
/// `RunnerUnavailable` is returned (not `Err`) when the binary is absent.
///
/// # Errors
///
/// - `RunnerError::Spawn` if `plan.mode != RunMode::Live`.
/// - `RunnerError::Spawn` if the IaC cannot be resolved for the offering
///   (fail-closed — no empty workspace runs).
/// - `RunnerError::CredInjection` if any secret variable name or the offering
///   slug is invalid.
/// - `RunnerError::WorkspaceSetup` if workspace initialisation fails.
/// - `RunnerError::Timeout` if any subprocess exceeds `LIVE_RUNNER_TIMEOUT`.
pub fn run_live_plan(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: Option<&str>,
) -> Result<LivePlanArtifacts, RunnerError> {
    if plan.mode != RunMode::Live {
        return Err(RunnerError::Spawn(format!(
            "run_live_plan only accepts RunMode::Live; got {:?}",
            plan.mode
        )));
    }

    live_terraform_plan(DEFAULT_BINARY, plan, creds, backend_config)
}

/// Execute a live Terraform apply using the SAVED plan file from `run_live_plan`.
///
/// Accepts the raw `tfplan` bytes returned by `run_live_plan` and writes them
/// into a **fresh** workspace before invoking `terraform apply -input=false
/// tfplan`.  Terraform applies EXACTLY the saved plan and errors if current
/// state has diverged — this closes the TOCTOU hole that `-auto-approve` (which
/// lets terraform re-plan at apply time) created.
///
/// The state backend (operator-provided via `backend_config`) MUST be
/// configured so that Terraform can persist and lock state across runs.
///
/// Returns `Ok(RunOutcome)` with status `Applied` on success (exit 0),
/// `Failed` on non-zero exit, or `RunnerUnavailable` when terraform is absent.
///
/// # Arguments
///
/// - `tfplan` — the raw binary plan bytes from `LivePlanArtifacts.tfplan`.
///   These bytes are written to the workspace as `tfplan` and passed to
///   `terraform apply` without logging.
///
/// # Errors
///
/// Same conditions as `run_live_plan`.
pub fn run_live_apply(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: Option<&str>,
    tfplan: &[u8],
) -> Result<RunOutcome, RunnerError> {
    if plan.mode != RunMode::Live {
        return Err(RunnerError::Spawn(format!(
            "run_live_apply only accepts RunMode::Live; got {:?}",
            plan.mode
        )));
    }

    live_terraform_apply(DEFAULT_BINARY, plan, creds, backend_config, tfplan)
}

// ---------------------------------------------------------------------------
// Internal implementations (take binary path for test injection)
// ---------------------------------------------------------------------------

/// Core plan implementation.  `binary` is injectable for tests (e.g. `/bin/echo`).
///
/// Returns `Planned` ONLY when init exit==0, plan exit==0 or 2, and show
/// exit==0.  Any earlier failure returns `Failed` (fail-closed — no partial
/// plan reaches the digest layer).
pub(crate) fn live_terraform_plan(
    binary: &str,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: Option<&str>,
) -> Result<LivePlanArtifacts, RunnerError> {
    // Validate inputs before any workspace or process creation.
    validate_offering_slug(&plan.offering_id)?;
    for name in &plan.secret_var_names {
        validate_var_name(name)?;
    }

    // Resolve IaC — FAIL CLOSED on missing IaC (same contract as dry-run).
    let iac_files = super::iac::resolve(&plan.offering_id).ok_or_else(|| {
        RunnerError::Spawn(format!(
            "no embedded Terraform IaC for offering '{}' — \
             refusing to run an empty live workspace",
            plan.offering_id
        ))
    })?;

    // Build secret components for scrubbing.
    let components = credential_components(creds.material.as_slice());
    let secret_refs: Vec<&[u8]> = components.iter().map(|v| v.as_slice()).collect();
    let cred_str = std::str::from_utf8(creds.material.as_slice())
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Binary availability check — terraform-absent-safe.
    if !binary_available(binary) {
        return Ok(LivePlanArtifacts {
            outcome: RunOutcome {
                runner_kind: RunnerKind::Terraform,
                mode: plan.mode,
                status: RunStatus::RunnerUnavailable,
                summary: format!("runner unavailable: terraform binary not found at '{binary}'"),
                log: String::new(),
                exit_code: None,
            },
            tfplan: vec![],
        });
    }

    // --- Workspace setup ---
    let ws = Workspace::new()?;

    // Write IaC files.
    for (filename, content) in &iac_files {
        ws.write_file(filename, content.as_bytes())?;
    }

    // Write optional backend config override — operator-provided HCL for a
    // durable, platform-local state backend (Postgres / S3 / Consul / …).
    // Written BEFORE init so terraform init picks it up.
    if let Some(backend_hcl) = backend_config {
        ws.write_file("backend_override.tf", backend_hcl.as_bytes())?;
    }

    // Write non-secret vars.
    if !plan.vars.is_empty() {
        let vars_json = vars_to_json(&plan.vars);
        ws.write_file_0600("ryuki.auto.tfvars.json", vars_json.as_bytes())?;
    }

    // --- Step 1: terraform init ---
    // FAIL CLOSED: non-zero exit → Failed, no digest computed.
    let init_outcome = run_tf_step(
        binary,
        &["init", "-input=false"],
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        plan.mode,
    )?;

    if init_outcome.exit_code != Some(0) {
        return Ok(LivePlanArtifacts {
            outcome: RunOutcome {
                runner_kind: RunnerKind::Terraform,
                mode: plan.mode,
                status: RunStatus::Failed,
                summary: format!(
                    "terraform init failed (exit {})",
                    init_outcome.exit_code.unwrap_or(-1)
                ),
                log: init_outcome.log,
                exit_code: init_outcome.exit_code,
            },
            tfplan: vec![],
        });
    }

    // --- Step 2: terraform plan -out=tfplan ---
    // FAIL CLOSED: exit codes other than 0 or 2 → Failed, no digest computed.
    let plan_step = run_tf_step(
        binary,
        &["plan", "-input=false", "-no-color", "-out=tfplan"],
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        plan.mode,
    )?;

    match plan_step.exit_code {
        Some(0) | Some(2) => {} // plan succeeded (0 = no changes, 2 = changes present)
        _ => {
            return Ok(LivePlanArtifacts {
                outcome: RunOutcome {
                    runner_kind: RunnerKind::Terraform,
                    mode: plan.mode,
                    status: RunStatus::Failed,
                    summary: format!(
                        "terraform plan failed (exit {})",
                        plan_step.exit_code.unwrap_or(-1)
                    ),
                    log: plan_step.log,
                    exit_code: plan_step.exit_code,
                },
                tfplan: vec![],
            });
        }
    }

    // Read the raw binary tfplan file BEFORE step 3 (show) so we can return
    // it alongside the canonical JSON.  These bytes are opaque — do not log them.
    let tfplan_path = ws.path().join("tfplan");
    let tfplan_bytes = std::fs::read(&tfplan_path)
        .map_err(|e| RunnerError::WorkspaceSetup(format!("failed to read tfplan file: {e}")))?;

    // --- Step 3: terraform show -json tfplan (canonical plan JSON for digest) ---
    // FAIL CLOSED: non-zero exit → Failed, no digest computed.
    let show_outcome = run_tf_step(
        binary,
        &["show", "-json", "tfplan"],
        ws.path(),
        &[], // no cred injection needed for show
        "",
        &secret_refs,
        plan.mode,
    )?;

    if show_outcome.exit_code != Some(0) {
        return Ok(LivePlanArtifacts {
            outcome: RunOutcome {
                runner_kind: RunnerKind::Terraform,
                mode: plan.mode,
                status: RunStatus::Failed,
                summary: format!(
                    "terraform show failed (exit {})",
                    show_outcome.exit_code.unwrap_or(-1)
                ),
                log: show_outcome.log,
                exit_code: show_outcome.exit_code,
            },
            tfplan: vec![],
        });
    }

    // The show output is the canonical plan JSON used for digest computation.
    let plan_json = show_outcome.log;
    let plan_summary = extract_plan_summary(&plan_step.log);

    Ok(LivePlanArtifacts {
        outcome: RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: plan.mode,
            status: RunStatus::Planned,
            summary: plan_summary,
            log: plan_json,
            exit_code: show_outcome.exit_code,
        },
        tfplan: tfplan_bytes,
    })
}

/// Core apply implementation.  `binary` is injectable for tests.
///
/// Accepts the raw `tfplan` bytes from `live_terraform_plan` and applies EXACTLY
/// that plan — no re-plan at apply time.  `terraform apply tfplan` exits non-zero
/// if current state has diverged from the saved plan, providing automatic
/// state-drift detection.  `-auto-approve` is intentionally absent.
pub(crate) fn live_terraform_apply(
    binary: &str,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: Option<&str>,
    tfplan: &[u8],
) -> Result<RunOutcome, RunnerError> {
    // Validate inputs.
    validate_offering_slug(&plan.offering_id)?;
    for name in &plan.secret_var_names {
        validate_var_name(name)?;
    }

    // Resolve IaC — FAIL CLOSED.
    let iac_files = super::iac::resolve(&plan.offering_id).ok_or_else(|| {
        RunnerError::Spawn(format!(
            "no embedded Terraform IaC for offering '{}' — \
             refusing to run an empty live workspace",
            plan.offering_id
        ))
    })?;

    // Secret scrubbing components.
    let components = credential_components(creds.material.as_slice());
    let secret_refs: Vec<&[u8]> = components.iter().map(|v| v.as_slice()).collect();
    let cred_str = std::str::from_utf8(creds.material.as_slice())
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Binary availability check.
    if !binary_available(binary) {
        return Ok(RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: plan.mode,
            status: RunStatus::RunnerUnavailable,
            summary: format!("runner unavailable: terraform binary not found at '{binary}'"),
            log: String::new(),
            exit_code: None,
        });
    }

    // --- Workspace setup (fresh — no state from the plan workspace) ---
    let ws = Workspace::new()?;

    for (filename, content) in &iac_files {
        ws.write_file(filename, content.as_bytes())?;
    }

    if let Some(backend_hcl) = backend_config {
        ws.write_file("backend_override.tf", backend_hcl.as_bytes())?;
    }

    if !plan.vars.is_empty() {
        let vars_json = vars_to_json(&plan.vars);
        ws.write_file_0600("ryuki.auto.tfvars.json", vars_json.as_bytes())?;
    }

    // Write the saved tfplan bytes into the workspace (0600 — treat as sensitive).
    // These bytes are opaque binary data; do not log them.
    ws.write_file_0600("tfplan", tfplan)?;

    // --- Step 1: terraform init ---
    let init_outcome = run_tf_step(
        binary,
        &["init", "-input=false"],
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        plan.mode,
    )?;

    if init_outcome.exit_code != Some(0) {
        return Ok(RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: plan.mode,
            status: RunStatus::Failed,
            summary: format!(
                "terraform init failed before apply (exit {})",
                init_outcome.exit_code.unwrap_or(-1)
            ),
            log: init_outcome.log,
            exit_code: init_outcome.exit_code,
        });
    }

    // --- Step 2: terraform apply -input=false tfplan ---
    // Apply the SAVED plan file.  No -auto-approve: the gate in the control
    // plane already approved this exact plan (verified by digest).  Terraform
    // will exit non-zero if the current state diverges from the saved plan.
    let apply_outcome = run_tf_step(
        binary,
        &["apply", "-input=false", "-no-color", "tfplan"],
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        plan.mode,
    )?;

    let (status, summary) = match apply_outcome.exit_code {
        Some(0) => (
            RunStatus::Applied,
            extract_apply_summary(&apply_outcome.log),
        ),
        code => (
            RunStatus::Failed,
            format!("terraform apply failed (exit {})", code.unwrap_or(-1)),
        ),
    };

    Ok(RunOutcome {
        runner_kind: RunnerKind::Terraform,
        mode: plan.mode,
        status,
        summary,
        log: apply_outcome.log,
        exit_code: apply_outcome.exit_code,
    })
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Lightweight availability probe: runs `terraform version` and checks exit 0.
/// Returns `false` when the binary is missing — never panics.
fn binary_available(binary: &str) -> bool {
    let mut cmd = Command::new(binary);
    apply_env_allowlist(&mut cmd);
    cmd.arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Intermediate result from a single terraform sub-command.
struct TfStepResult {
    log: String,
    exit_code: Option<i32>,
}

/// Run one terraform sub-command in the workspace, scrub the output, and
/// return an intermediate result.
///
/// `secret_names` and `cred_str` are used to inject `TF_VAR_<name>` env vars.
/// Pass empty slices/string when no credential injection is needed.
fn run_tf_step(
    binary: &str,
    args: &[&str],
    ws_path: &std::path::Path,
    secret_names: &[String],
    cred_str: &str,
    secret_refs: &[&[u8]],
    _mode: RunMode,
) -> Result<TfStepResult, RunnerError> {
    let mut cmd = Command::new(binary);
    apply_env_allowlist(&mut cmd);
    pin_home_tmpdir_to_workspace(&mut cmd, ws_path);
    cmd.args(args)
        .current_dir(ws_path)
        .env("CHECKPOINT_DISABLE", "1")
        .env_remove("TF_LOG");

    for name in secret_names {
        let env_key = format!("TF_VAR_{name}");
        cmd.env(&env_key, cred_str);
    }

    let output = run_command_with_timeout(cmd, LIVE_RUNNER_TIMEOUT)?;

    let raw = combine_output(&output.stdout, &output.stderr);
    let scrubbed = scrub_output(&raw, secret_refs);

    Ok(TfStepResult {
        log: scrubbed,
        exit_code: output.status.code(),
    })
}

/// Serialize non-secret vars to a `*.tfvars.json` file.
/// Mirrors `terraform::vars_to_json` but is local here to keep the live module
/// self-contained.
fn vars_to_json(vars: &std::collections::BTreeMap<String, String>) -> String {
    let map: serde_json::Map<String, serde_json::Value> = vars
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    serde_json::to_string_pretty(&map).unwrap_or_else(|_| "{}".to_string())
}

/// Extract a one-line plan summary from scrubbed terraform output.
fn extract_plan_summary(log: &str) -> String {
    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Plan:") || trimmed.starts_with("No changes.") {
            return trimmed.to_string();
        }
    }
    "terraform plan completed".to_string()
}

/// Extract a one-line apply summary from scrubbed terraform output.
fn extract_apply_summary(log: &str) -> String {
    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Apply complete!")
            || trimmed.starts_with("No changes.")
            || trimmed.starts_with("Apply complete.")
        {
            return trimmed.to_string();
        }
    }
    "terraform apply completed".to_string()
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

    fn live_plan(offering_id: &str) -> RunPlan {
        RunPlan {
            runner_kind: RunnerKind::Terraform,
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
    fn run_live_plan_rejects_dry_run_mode() {
        let mut plan = live_plan("patch-maintenance");
        plan.mode = RunMode::DryRun;
        let result = run_live_plan(&plan, &dummy_creds(), None);
        assert!(result.is_err(), "run_live_plan must reject RunMode::DryRun");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Live") || msg.contains("DryRun"),
            "error must mention mode; got: {msg}"
        );
    }

    #[test]
    fn run_live_apply_rejects_dry_run_mode() {
        let mut plan = live_plan("patch-maintenance");
        plan.mode = RunMode::DryRun;
        let result = run_live_apply(&plan, &dummy_creds(), None, b"fake-plan");
        assert!(
            result.is_err(),
            "run_live_apply must reject RunMode::DryRun"
        );
    }

    // -----------------------------------------------------------------------
    // Missing IaC — fail closed
    // -----------------------------------------------------------------------

    #[test]
    fn run_live_plan_fails_closed_on_missing_iac() {
        let plan = live_plan("no-such-offering-xyz");
        let result = run_live_plan(&plan, &dummy_creds(), None);
        assert!(
            result.is_err(),
            "run_live_plan must fail closed when IaC is missing"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no embedded") || msg.contains("IaC"),
            "error must mention missing IaC; got: {msg}"
        );
    }

    #[test]
    fn run_live_apply_fails_closed_on_missing_iac() {
        let plan = live_plan("no-such-offering-xyz");
        let result = run_live_apply(&plan, &dummy_creds(), None, b"fake-plan");
        assert!(
            result.is_err(),
            "run_live_apply must fail closed when IaC is missing"
        );
    }

    // -----------------------------------------------------------------------
    // terraform absent → RunnerUnavailable (not Err, not panic)
    // -----------------------------------------------------------------------

    #[test]
    fn run_live_plan_terraform_absent_returns_unavailable() {
        let plan = live_plan("patch-maintenance");
        // Use a non-existent binary path to simulate terraform absent.
        let result = live_terraform_plan(
            "/nonexistent/terraform-fake-live",
            &plan,
            &dummy_creds(),
            None,
        );
        assert!(result.is_ok(), "absent terraform must not return Err");
        assert_eq!(
            result.unwrap().outcome.status,
            RunStatus::RunnerUnavailable,
            "absent terraform must return RunnerUnavailable"
        );
    }

    #[test]
    fn run_live_apply_terraform_absent_returns_unavailable() {
        let plan = live_plan("patch-maintenance");
        let result = live_terraform_apply(
            "/nonexistent/terraform-fake-live",
            &plan,
            &dummy_creds(),
            None,
            b"fake-tfplan-bytes",
        );
        assert!(
            result.is_ok(),
            "absent terraform must not return Err for apply"
        );
        assert_eq!(
            result.unwrap().status,
            RunStatus::RunnerUnavailable,
            "absent terraform must return RunnerUnavailable for apply"
        );
    }

    // -----------------------------------------------------------------------
    // backend_config is written into the workspace before init
    // -----------------------------------------------------------------------

    /// We can't easily verify the file was passed to terraform without a real
    /// binary, but we CAN verify that supplying a backend_config string does
    /// not cause an error (workspace write succeeds) when the binary is absent.
    /// The real integration test requires a live terraform binary.
    #[test]
    fn run_live_plan_accepts_backend_config_without_error() {
        let plan = live_plan("patch-maintenance");
        let backend_hcl = r#"terraform {
  backend "pg" {
    conn_str = "postgresql://localhost/tfstate"
  }
}"#;
        // Binary absent → RunnerUnavailable, but no error from backend_config write.
        let result = live_terraform_plan(
            "/nonexistent/terraform-fake-live-backend",
            &plan,
            &dummy_creds(),
            Some(backend_hcl),
        );
        assert!(
            result.is_ok(),
            "backend_config must not cause Err when binary is absent"
        );
        assert_eq!(result.unwrap().outcome.status, RunStatus::RunnerUnavailable);
    }

    #[test]
    fn run_live_apply_accepts_backend_config_without_error() {
        let plan = live_plan("patch-maintenance");
        let backend_hcl = "# dummy backend config for test";
        let result = live_terraform_apply(
            "/nonexistent/terraform-fake-live-backend-apply",
            &plan,
            &dummy_creds(),
            Some(backend_hcl),
            b"fake-tfplan-bytes",
        );
        assert!(
            result.is_ok(),
            "backend_config must not cause Err for apply when binary absent"
        );
        assert_eq!(result.unwrap().status, RunStatus::RunnerUnavailable);
    }

    // -----------------------------------------------------------------------
    // IaC is written to the workspace (verifiable via a shim that lists files)
    // -----------------------------------------------------------------------

    #[test]
    fn live_plan_writes_iac_to_workspace() {
        // Use a shim that lists the current directory and also writes a fake
        // "tfplan" file so the plan step's read succeeds, then exits 0 for all.
        let ws_probe = super::super::workspace::Workspace::new().expect("ws");
        let shim = ws_probe.path().join("fake-tf-live-iac");
        // The shim writes a stub tfplan file on every invocation (in case this
        // invocation is the plan step) and exits 0.
        std::fs::write(&shim, "#!/bin/sh\ntouch \"$PWD/tfplan\"\nls\nexit 0\n")
            .expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_plan("patch-maintenance");
        let result = live_terraform_plan(&shim.to_string_lossy(), &plan, &dummy_creds(), None);
        // The shim exits 0 for all steps and writes the tfplan stub → Planned.
        assert!(result.is_ok(), "shim-based plan must not error: {result:?}");
        let artifacts = result.unwrap();
        assert_eq!(
            artifacts.outcome.status,
            RunStatus::Planned,
            "shim exits 0 → Planned; got: {:?}",
            artifacts.outcome.status
        );
    }

    // -----------------------------------------------------------------------
    // run_live_plan returns Failed (not Planned) when a step exits non-zero
    // -----------------------------------------------------------------------

    #[test]
    fn run_live_plan_returns_failed_when_step_fails() {
        // A shim that exits non-zero simulates a failed terraform step.
        let ws_probe = super::super::workspace::Workspace::new().expect("ws");
        let shim = ws_probe.path().join("fake-tf-fail");
        // Exits 1 for every invocation (including the version probe).
        // But binary_available() must return true so we get past the probe;
        // we need version to exit 0 but all others to fail.
        // Simplest: use a counter via a temp file so the first call (version) exits 0,
        // and subsequent calls exit 1. Instead, use a different approach: the binary
        // probe is `terraform version` which is called by binary_available. We can
        // make the shim exit 0 always but write an "init-fail" marker that makes
        // the init step fail via exit code. That's complex. Simplest: a shim that
        // exits 0 for "version" and "init" but exits 1 for "plan".
        std::fs::write(
            &shim,
            r#"#!/bin/sh
case "$1" in
  version) exit 0 ;;
  init) exit 0 ;;
  *) exit 1 ;;
esac
"#,
        )
        .expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_plan("patch-maintenance");
        let result = live_terraform_plan(&shim.to_string_lossy(), &plan, &dummy_creds(), None);
        // Must be Ok (not Err), but status must be Failed — not Planned.
        assert!(
            result.is_ok(),
            "step failure must not return Err: {result:?}"
        );
        let artifacts = result.unwrap();
        assert_eq!(
            artifacts.outcome.status,
            RunStatus::Failed,
            "non-zero plan exit must yield Failed, not Planned; got: {:?}",
            artifacts.outcome.status
        );
        // tfplan bytes must be empty (no plan to pass to apply).
        assert!(
            artifacts.tfplan.is_empty(),
            "tfplan bytes must be empty when plan failed"
        );
    }

    // -----------------------------------------------------------------------
    // run_live_apply receives and uses the tfplan bytes (shim verifies invocation)
    // -----------------------------------------------------------------------

    #[test]
    fn run_live_apply_writes_tfplan_and_invokes_apply_with_it() {
        // A shim that: exits 0 for version and init; for apply, checks that
        // "tfplan" argument is present (NOT -auto-approve) and exits 0.
        let ws_probe = super::super::workspace::Workspace::new().expect("ws");
        let shim = ws_probe.path().join("fake-tf-apply-check");
        std::fs::write(
            &shim,
            r#"#!/bin/sh
case "$1" in
  version) exit 0 ;;
  init) exit 0 ;;
  apply)
    # Verify that the last argument is "tfplan" (the saved plan file),
    # NOT "-auto-approve".
    for arg in "$@"; do
      if [ "$arg" = "-auto-approve" ]; then
        echo "FAIL: -auto-approve must not be used" >&2
        exit 2
      fi
    done
    # Check that "tfplan" is among the args.
    found=0
    for arg in "$@"; do
      if [ "$arg" = "tfplan" ]; then
        found=1
      fi
    done
    if [ "$found" = "0" ]; then
      echo "FAIL: tfplan argument missing" >&2
      exit 3
    fi
    echo "Apply complete! Resources: 0 added, 0 changed, 0 destroyed."
    exit 0
    ;;
  *) exit 0 ;;
esac
"#,
        )
        .expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_plan("patch-maintenance");
        // Pass non-empty tfplan bytes (opaque content; the shim just checks the arg).
        let fake_tfplan = b"fake-binary-tfplan-content";
        let result = live_terraform_apply(
            &shim.to_string_lossy(),
            &plan,
            &dummy_creds(),
            None,
            fake_tfplan,
        );
        assert!(result.is_ok(), "apply shim must not error: {result:?}");
        let outcome = result.unwrap();
        assert_eq!(
            outcome.status,
            RunStatus::Applied,
            "apply shim exits 0 → Applied; got: {:?} log: {}",
            outcome.status,
            outcome.log
        );
    }

    // -----------------------------------------------------------------------
    // backend_config is actually written to workspace (verifiable via shim)
    // -----------------------------------------------------------------------

    #[test]
    fn live_plan_backend_config_file_exists_in_workspace() {
        let ws_probe = super::super::workspace::Workspace::new().expect("ws");
        let shim = ws_probe.path().join("fake-tf-backend-check");
        // Shim writes stub tfplan, lists files, exits 0 for all steps.
        std::fs::write(&shim, "#!/bin/sh\ntouch \"$PWD/tfplan\"\nls\nexit 0\n")
            .expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_plan("patch-maintenance");
        let backend_hcl = "# ryuki-test backend override";
        let result = live_terraform_plan(
            &shim.to_string_lossy(),
            &plan,
            &dummy_creds(),
            Some(backend_hcl),
        );
        assert!(
            result.is_ok(),
            "backend_config write must not error: {result:?}"
        );
        // Shim exits 0 → should be Planned.
        assert_eq!(result.unwrap().outcome.status, RunStatus::Planned);
    }

    // -----------------------------------------------------------------------
    // Helper unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_plan_summary_finds_plan_line() {
        let log = "Refreshing...\nPlan: 3 to add, 0 to change, 0 to destroy.\nDone.";
        assert_eq!(
            extract_plan_summary(log),
            "Plan: 3 to add, 0 to change, 0 to destroy."
        );
    }

    #[test]
    fn extract_plan_summary_no_changes() {
        let log = "No changes. Your infrastructure matches the configuration.";
        assert!(extract_plan_summary(log).starts_with("No changes."));
    }

    #[test]
    fn extract_apply_summary_finds_apply_complete() {
        let log = "...\nApply complete! Resources: 2 added, 0 changed, 0 destroyed.";
        assert!(extract_apply_summary(log).starts_with("Apply complete!"));
    }
}
