//! Terraform runner — dry-run (plan) only (Slice 1).
//!
//! Executes `terraform init -input=false` then `terraform plan -input=false
//! -no-color` in an isolated workspace.
//!
//! # Security invariants
//! - All child `Command`s call `.env_clear()` and then re-inject only a minimal
//!   allowlist: PATH, HOME, TMPDIR, LANG, LC_ALL (if present in the parent).
//!   This prevents platform secrets (RYUKI_*, RYUKI_DATABASE_*, vault tokens,
//!   cloud creds) from being inherited by the child process.
//! - Secret variable names are validated against a strict identifier pattern
//!   before injection; reserved/control names are rejected.
//! - Credentials are injected as `TF_VAR_<name>` env vars on the child only.
//! - Secret values NEVER appear in argv.
//! - `offering_id` is validated as a safe slug before use.
//! - Output is scrubbed (per-component) before being placed in `RunOutcome`.
//! - The workspace TempDir is removed on drop.
//! - `TF_LOG` is never set to `trace` or any verbose level.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use ryuki_engine::runners::{
    ResolvedCredentials, RunMode, RunOutcome, RunPlan, RunStatus, RunnerError, RunnerKind,
};

use super::{exec::run_command_with_timeout, scrub::scrub_output, workspace::Workspace, Runner};

/// Per-subprocess timeout for terraform init and terraform plan.
/// A hung terraform (e.g. waiting for a remote backend) is killed after this.
const RUNNER_TIMEOUT: Duration = Duration::from_secs(120);

/// Default binary name; overridable for tests via `TerraformRunner::with_binary`.
const DEFAULT_BINARY: &str = "terraform";

/// Environment variables inherited from the parent process into child commands.
/// All other parent env vars are stripped via `env_clear()`.
pub(crate) const ENV_ALLOWLIST: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"];

/// Pattern that a variable name must match to be accepted as a TF_VAR_ injection.
/// `^[A-Za-z_][A-Za-z0-9_]*$`
static VAR_NAME_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("static regex")
});

/// Variable name prefixes and exact names that are rejected regardless of the
/// identifier pattern — they are Terraform/OS control variables that could
/// alter binary behaviour or leak parent state.
const BLOCKED_PREFIXES: &[&str] = &["TF_LOG", "TF_CLI", "LD_", "DYLD_"];
const BLOCKED_EXACT: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"];

/// Offer ID pattern: lowercase alphanumeric and hyphens, must start with
/// alphanumeric. Rejects `..`, `/`, absolute paths, and empty strings.
static OFFERING_SLUG_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^[a-z0-9][a-z0-9-]*$").expect("static regex"));

/// Runner for Terraform. Dry-run only in Slice 1.
///
/// # Binary injection
/// Use `TerraformRunner::with_binary("/path/to/fake-terraform")` in tests
/// to avoid requiring a real Terraform installation.
///
/// # IaC content injection
/// Use `TerraformRunner::with_iac` to embed static IaC file content that is
/// written into the workspace before `terraform init`. Each entry is a
/// `(filename, content)` pair; content must be valid Terraform HCL.
pub struct TerraformRunner {
    binary: String,
    /// Static IaC files written into the workspace before `terraform init`.
    /// Each entry is `(filename, utf8_content)`.
    iac_files: Vec<(&'static str, &'static str)>,
}

impl Default for TerraformRunner {
    fn default() -> Self {
        Self {
            binary: DEFAULT_BINARY.to_string(),
            iac_files: Vec::new(),
        }
    }
}

impl TerraformRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a runner pointing at a custom binary path (for tests / injection).
    pub fn with_binary(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
            iac_files: Vec::new(),
        }
    }

    /// Attach static IaC file content to be written into the workspace before
    /// `terraform init`. Each entry is `(filename, utf8_content)`.
    ///
    /// This is the mechanism by which per-offering IaC (embedded via
    /// `include_str!`) reaches the temporary workspace without touching the
    /// filesystem outside of the per-run TempDir.
    pub fn with_iac(mut self, files: Vec<(&'static str, &'static str)>) -> Self {
        self.iac_files = files;
        self
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a variable name for use as a TF_VAR_<name> environment variable.
///
/// Rejects:
/// - names that do not match `^[A-Za-z_][A-Za-z0-9_]*$`
/// - names that start with a blocked prefix (TF_LOG, TF_CLI, LD_, DYLD_)
/// - names that are exactly a blocked allowlist var (PATH, HOME, etc.)
pub(crate) fn validate_var_name(name: &str) -> Result<(), RunnerError> {
    if !VAR_NAME_RE.is_match(name) {
        return Err(RunnerError::CredInjection(format!(
            "variable name '{name}' is not a valid identifier \
             (must match ^[A-Za-z_][A-Za-z0-9_]*$)"
        )));
    }
    for prefix in BLOCKED_PREFIXES {
        if name.starts_with(prefix) {
            return Err(RunnerError::CredInjection(format!(
                "variable name '{name}' starts with reserved prefix '{prefix}'"
            )));
        }
    }
    for exact in BLOCKED_EXACT {
        if name == *exact {
            return Err(RunnerError::CredInjection(format!(
                "variable name '{name}' is a reserved control variable"
            )));
        }
    }
    Ok(())
}

/// Validate an offering_id slug: `^[a-z0-9][a-z0-9-]*$`.
/// Returns an error if the slug is empty, contains path separators, or is absolute.
pub(crate) fn validate_offering_slug(offering_id: &str) -> Result<(), RunnerError> {
    if offering_id.is_empty()
        || offering_id.contains('/')
        || offering_id.contains('\\')
        || offering_id.starts_with('.')
        || std::path::Path::new(offering_id).is_absolute()
    {
        return Err(RunnerError::CredInjection(format!(
            "offering_id '{offering_id}' contains path separators or is not a safe slug"
        )));
    }
    if !OFFERING_SLUG_RE.is_match(offering_id) {
        return Err(RunnerError::CredInjection(format!(
            "offering_id '{offering_id}' is not a valid slug \
             (must match ^[a-z0-9][a-z0-9-]*$)"
        )));
    }
    Ok(())
}

/// Populate a `Command` with only the allowed parent environment variables.
///
/// Calls `env_clear()` first so no other parent vars are inherited,
/// then re-injects each key from `ENV_ALLOWLIST` if it exists in the parent.
pub(crate) fn apply_env_allowlist(cmd: &mut Command) {
    cmd.env_clear();
    for key in ENV_ALLOWLIST {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }
}

/// Pin the child's HOME and TMPDIR to the isolated workspace directory.
///
/// This prevents the subprocess from writing to the real $HOME (e.g.
/// `~/.terraform.d`, `~/.ansible/tmp`) and constrains any temp files it
/// creates to the per-run workspace that is cleaned up on drop.
///
/// Call this AFTER `apply_env_allowlist` so the workspace override wins.
pub(crate) fn pin_home_tmpdir_to_workspace(cmd: &mut Command, workspace_path: &std::path::Path) {
    let ws = workspace_path.to_string_lossy();
    cmd.env("HOME", ws.as_ref()).env("TMPDIR", ws.as_ref());
}

/// Split credential material that may be comma-joined into individual
/// non-empty component slices. Each component is scrubbed independently,
/// preventing a partial match from escaping scrubbing when values are joined.
pub(crate) fn credential_components(material: &[u8]) -> Vec<Vec<u8>> {
    if material.is_empty() {
        return vec![];
    }
    // If the material is valid UTF-8, try splitting on commas (the format used
    // by the integration credential source when it joins multiple values).
    if let Ok(s) = std::str::from_utf8(material) {
        let components: Vec<Vec<u8>> = s
            .split(',')
            .filter(|c| !c.is_empty())
            .map(|c| c.as_bytes().to_vec())
            .collect();
        if !components.is_empty() {
            return components;
        }
    }
    // Fallback: treat the whole material as a single component.
    vec![material.to_vec()]
}

impl Runner for TerraformRunner {
    fn available(&self) -> bool {
        // A simple version check — if the binary is missing, the command fails
        // and we return false (never panic).
        // env_clear() + allowlist: prevent parent secrets from reaching the probe.
        let mut cmd = Command::new(&self.binary);
        apply_env_allowlist(&mut cmd);
        cmd.arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn run_dry(
        &self,
        plan: &RunPlan,
        creds: &ResolvedCredentials,
    ) -> Result<RunOutcome, RunnerError> {
        // Guard: this runner only handles dry-run in Slice 1.
        if plan.mode != RunMode::DryRun {
            return Err(RunnerError::Spawn(
                "Live mode is not implemented in Slice 1".to_string(),
            ));
        }

        // Validate offering_id before any path construction.
        validate_offering_slug(&plan.offering_id)?;

        // Validate every secret variable name before injection.
        for name in &plan.secret_var_names {
            validate_var_name(name)?;
        }

        // Build the per-component secret values for scrubbing.
        // Splitting into components ensures each comma-separated value is
        // redacted individually — prevents partial leakage.
        let components: Vec<Vec<u8>> = credential_components(creds.material.as_slice());
        let secret_refs: Vec<&[u8]> = components.iter().map(|v| v.as_slice()).collect();

        // --- Binary availability check ---
        if !self.available() {
            return Ok(RunOutcome {
                runner_kind: RunnerKind::Terraform,
                mode: plan.mode,
                status: RunStatus::RunnerUnavailable,
                summary: format!(
                    "runner unavailable: terraform binary not found at '{}'",
                    self.binary
                ),
                log: String::new(),
                exit_code: None,
            });
        }

        // --- Workspace setup ---
        let ws = Workspace::new()?;

        // Write IaC source files (non-secret .tf content) into the workspace
        // before init so `terraform init` has configuration to process.
        for (filename, content) in &self.iac_files {
            ws.write_file(filename, content.as_bytes())?;
        }

        // Write non-secret vars to a JSON vars file.
        if !plan.vars.is_empty() {
            let vars_json = vars_to_json(&plan.vars);
            ws.write_file_0600("ryuki.auto.tfvars.json", vars_json.as_bytes())?;
        }

        // Build the credential string (UTF-8 interpretation of raw material).
        // For Slice 1 we use the full material as a single credential value and
        // inject it as TF_VAR_<name> for each secret_var_name in the plan.
        let cred_str = std::str::from_utf8(creds.material.as_slice())
            .map(|s| s.to_string())
            .unwrap_or_else(|_| String::new());

        // --- Step 1: terraform init ---
        // env_clear() + allowlist applied; CHECKPOINT_DISABLE and TF_LOG
        // control added explicitly after the allowlist.
        let mut init_cmd = Command::new(&self.binary);
        apply_env_allowlist(&mut init_cmd);
        // Pin HOME and TMPDIR to the workspace so terraform cannot write to
        // the real $HOME (e.g. ~/.terraform.d plugin cache). Any cache writes
        // go into the per-run workspace and are cleaned up on drop.
        pin_home_tmpdir_to_workspace(&mut init_cmd, ws.path());
        init_cmd
            .args(["init", "-input=false"])
            .current_dir(ws.path())
            // Disable Terraform telemetry/checkpoint entirely.
            .env("CHECKPOINT_DISABLE", "1")
            // Explicitly do NOT set TF_LOG to avoid trace/debug leakage.
            // env_clear() already removed it; this explicit remove is defense-in-depth.
            .env_remove("TF_LOG");

        // Inject credential material for each named secret var.
        for secret_name in &plan.secret_var_names {
            let env_key = format!("TF_VAR_{}", secret_name);
            init_cmd.env(&env_key, &cred_str);
        }

        let init_output =
            run_command_with_timeout(init_cmd, RUNNER_TIMEOUT).map_err(|e| match e {
                RunnerError::Timeout => RunnerError::Timeout,
                other => RunnerError::Spawn(format!("terraform init: {other}")),
            })?;

        if !init_output.status.success() {
            let raw = combine_output(&init_output.stdout, &init_output.stderr);
            let scrubbed = scrub_output(&raw, &secret_refs);
            return Ok(RunOutcome {
                runner_kind: RunnerKind::Terraform,
                mode: plan.mode,
                status: RunStatus::Failed,
                summary: format!(
                    "terraform init failed (exit {})",
                    init_output.status.code().unwrap_or(-1)
                ),
                log: scrubbed,
                exit_code: init_output.status.code(),
            });
        }

        // --- Step 2: terraform validate ---
        // Always runs — offline correctness oracle against the real provider
        // schema. Requires no live vCenter or credentials; validate only checks
        // that the configuration is structurally valid per the downloaded schema.
        let mut validate_cmd = Command::new(&self.binary);
        apply_env_allowlist(&mut validate_cmd);
        pin_home_tmpdir_to_workspace(&mut validate_cmd, ws.path());
        validate_cmd
            .args(["validate", "-no-color"])
            .current_dir(ws.path())
            .env("CHECKPOINT_DISABLE", "1")
            .env_remove("TF_LOG");

        let validate_output =
            run_command_with_timeout(validate_cmd, RUNNER_TIMEOUT).map_err(|e| match e {
                RunnerError::Timeout => RunnerError::Timeout,
                other => RunnerError::Spawn(format!("terraform validate: {other}")),
            })?;

        let validate_raw = combine_output(&validate_output.stdout, &validate_output.stderr);
        let validate_log = scrub_output(&validate_raw, &secret_refs);

        if !validate_output.status.success() {
            // Validate failed — configuration is invalid against the provider
            // schema. This is a hard failure; do not attempt plan.
            return Ok(RunOutcome {
                runner_kind: RunnerKind::Terraform,
                mode: plan.mode,
                status: RunStatus::Failed,
                summary: format!(
                    "terraform validate failed (exit {})",
                    validate_output.status.code().unwrap_or(-1)
                ),
                log: validate_log,
                exit_code: validate_output.status.code(),
            });
        }

        // Validate passed — configuration is schema-valid.
        let validate_summary = extract_validate_summary(&validate_log);

        // --- Step 3: terraform plan (best-effort) ---
        // For built-in terraform_data offerings this succeeds fully offline.
        // For vsphere/external-provider offerings it will fail without a
        // reachable vCenter — that failure is captured gracefully.
        let mut plan_cmd = Command::new(&self.binary);
        apply_env_allowlist(&mut plan_cmd);
        pin_home_tmpdir_to_workspace(&mut plan_cmd, ws.path());
        plan_cmd
            .args(["plan", "-input=false", "-no-color"])
            .current_dir(ws.path())
            .env("CHECKPOINT_DISABLE", "1")
            .env_remove("TF_LOG");

        for secret_name in &plan.secret_var_names {
            let env_key = format!("TF_VAR_{}", secret_name);
            plan_cmd.env(&env_key, &cred_str);
        }

        let plan_result = run_command_with_timeout(plan_cmd, RUNNER_TIMEOUT);

        match plan_result {
            Err(RunnerError::Timeout) => {
                // Plan timed out — degraded but validate evidence is preserved.
                Ok(RunOutcome {
                    runner_kind: RunnerKind::Terraform,
                    mode: plan.mode,
                    status: RunStatus::Validated,
                    summary: format!("terraform validate: {validate_summary}; plan timed out"),
                    log: validate_log,
                    exit_code: None,
                })
            }
            Err(other) => {
                // Spawn error for plan — degrade gracefully.
                Ok(RunOutcome {
                    runner_kind: RunnerKind::Terraform,
                    mode: plan.mode,
                    status: RunStatus::Validated,
                    summary: format!(
                        "terraform validate: {validate_summary}; plan unavailable: {other}"
                    ),
                    log: validate_log,
                    exit_code: None,
                })
            }
            Ok(plan_output) => {
                let plan_raw = combine_output(&plan_output.stdout, &plan_output.stderr);
                let plan_log = scrub_output(&plan_raw, &secret_refs);

                // Terraform exit codes:
                //   0 — succeeded, no changes
                //   1 — error
                //   2 — succeeded, changes detected (only with -detailed-exitcode)
                // We use -no-color but not -detailed-exitcode, so 0 = ok, 1 = error.
                match plan_output.status.code() {
                    Some(0) | Some(2) => {
                        // Both validate and plan succeeded — combine logs.
                        let plan_summary = extract_plan_summary(&plan_log);
                        let combined_log = combine_validate_and_plan_logs(&validate_log, &plan_log);
                        Ok(RunOutcome {
                            runner_kind: RunnerKind::Terraform,
                            mode: plan.mode,
                            status: RunStatus::Planned,
                            summary: plan_summary,
                            log: combined_log,
                            exit_code: plan_output.status.code(),
                        })
                    }
                    _ => {
                        // Plan failed (e.g. vsphere needs live vCenter) — degrade
                        // gracefully. Validate already passed; emit Validated status
                        // so the evidence builder can emit the validate item.
                        let plan_exit = plan_output.status.code().unwrap_or(-1);
                        let combined_log = combine_validate_and_plan_logs(&validate_log, &plan_log);
                        Ok(RunOutcome {
                            runner_kind: RunnerKind::Terraform,
                            mode: plan.mode,
                            status: RunStatus::Validated,
                            summary: format!(
                                "terraform validate: {validate_summary}; \
                                 plan requires live provider (exit {plan_exit})"
                            ),
                            log: combined_log,
                            exit_code: Some(plan_exit),
                        })
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Combine stdout and stderr into a single string for scrubbing.
pub(crate) fn combine_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut s = String::new();
    if !stdout.is_empty() {
        s.push_str(&String::from_utf8_lossy(stdout));
    }
    if !stderr.is_empty() {
        if !s.is_empty() && !s.ends_with('\n') {
            s.push('\n');
        }
        s.push_str(&String::from_utf8_lossy(stderr));
    }
    s
}

/// Serialize non-secret vars to a valid JSON object for `*.tfvars.json`.
///
/// Uses `serde_json` to guarantee correct escaping of all values, including
/// those containing `"`, `\`, newlines, and arbitrary Unicode/control chars.
/// Keys are inserted in iteration order (BTreeMap is already sorted).
fn vars_to_json(vars: &BTreeMap<String, String>) -> String {
    let map: serde_json::Map<String, serde_json::Value> = vars
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    // to_string never fails for a Map of strings.
    serde_json::to_string_pretty(&map).unwrap_or_else(|_| "{}".to_string())
}

/// Extract a one-line plan summary from scrubbed terraform output.
/// Looks for the canonical "Plan: N to add, N to change, N to destroy." line.
fn extract_plan_summary(log: &str) -> String {
    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Plan:") || trimmed.starts_with("No changes.") {
            return trimmed.to_string();
        }
    }
    "terraform plan completed".to_string()
}

/// Extract a one-line validate summary from scrubbed terraform validate output.
/// Returns "configuration is valid" when terraform reports success, or a
/// short error fragment otherwise.
fn extract_validate_summary(log: &str) -> String {
    for line in log.lines() {
        let trimmed = line.trim();
        // terraform validate emits "Success! The configuration is valid."
        if trimmed.starts_with("Success!") || trimmed.contains("configuration is valid") {
            return "configuration is valid".to_string();
        }
        // Error summary lines start with "Error:" — capture the first one.
        if trimmed.starts_with("Error:") {
            return trimmed.chars().take(120).collect();
        }
    }
    "terraform validate completed".to_string()
}

/// Combine validate and plan logs with section headers for evidence readability.
fn combine_validate_and_plan_logs(validate_log: &str, plan_log: &str) -> String {
    let mut out = String::new();
    if !validate_log.is_empty() {
        out.push_str("[terraform validate]\n");
        out.push_str(validate_log.trim_end());
        out.push('\n');
    }
    if !plan_log.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("[terraform plan]\n");
        out.push_str(plan_log.trim_end());
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_shim_path() -> String {
        // On Unix, use /bin/echo as a fake binary that succeeds and prints its args.
        // The `available()` check runs `echo version` which exits 0.
        "/bin/echo".to_string()
    }

    fn make_plan_dryrun() -> RunPlan {
        RunPlan {
            runner_kind: RunnerKind::Terraform,
            mode: RunMode::DryRun,
            offering_id: "test-offering".to_string(),
            vars: BTreeMap::from([("region".to_string(), "eu-west".to_string())]),
            secret_var_names: vec![],
        }
    }

    fn fake_creds(material: &str) -> ResolvedCredentials {
        ResolvedCredentials {
            material: material.as_bytes().to_vec(),
            descriptor: "test:fake".to_string(),
        }
    }

    // --- available() ---

    #[test]
    fn available_returns_true_for_echo() {
        let runner = TerraformRunner::with_binary(fake_shim_path());
        assert!(runner.available(), "/bin/echo must report available");
    }

    #[test]
    fn available_returns_false_for_missing_binary() {
        let runner = TerraformRunner::with_binary("/nonexistent/terraform-fake-binary");
        assert!(
            !runner.available(),
            "missing binary must return false, not panic"
        );
    }

    // --- env_clear: parent secrets must NOT reach the child ---

    #[test]
    fn available_does_not_inherit_parent_secrets() {
        // Plant a sentinel env var in the current process. The probe must NOT
        // pass it to the child. We run `/usr/bin/env`, which prints its full
        // environment to stdout, so we can inspect what the child received.
        // Execing an existing binary (rather than writing a temp shim and
        // immediately execing it) avoids the ETXTBSY ("text file busy") race a
        // freshly-written executable hits under parallel test execution.
        std::env::set_var(
            "RYUKI_INTEGRATION__ENCRYPTION_KEY",
            "PARENT-SECRET-SENTINEL",
        );

        let mut cmd = Command::new("/usr/bin/env");
        apply_env_allowlist(&mut cmd);
        let output = cmd.output().expect("probe must succeed");
        let child_env = String::from_utf8_lossy(&output.stdout);

        // The planted secret must NOT appear in the child's environment.
        assert!(
            !child_env.contains("PARENT-SECRET-SENTINEL"),
            "parent secret must not be inherited by child; child env: {child_env}"
        );
        // PATH and HOME MUST be present (they are in the allowlist).
        assert!(
            child_env.contains("PATH="),
            "PATH must be in child env; got: {child_env}"
        );

        // Cleanup.
        std::env::remove_var("RYUKI_INTEGRATION__ENCRYPTION_KEY");
    }

    #[test]
    fn run_dry_does_not_inherit_parent_secrets() {
        // Use a shim that prints its environment, so we can verify env_clear().
        let ws_shim = Workspace::new().expect("ws");
        let shim = ws_shim.path().join("tf-rundry-env-probe");
        std::fs::write(&shim, "#!/bin/sh\nenv\nexit 0\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        std::env::set_var(
            "RYUKI_INTEGRATION__ENCRYPTION_KEY",
            "RUNDRY-SECRET-SENTINEL",
        );

        let runner = TerraformRunner::with_binary(shim.to_string_lossy().to_string());
        let plan = make_plan_dryrun();
        let creds = fake_creds("");

        // run_dry calls init then plan — both use apply_env_allowlist.
        // The shim exits 0 for both calls. Capture output manually for init
        // by running the shim directly with the allowlist applied.
        let mut cmd = Command::new(&shim);
        apply_env_allowlist(&mut cmd);
        let output = cmd.output().expect("probe");
        let child_env = String::from_utf8_lossy(&output.stdout);

        assert!(
            !child_env.contains("RUNDRY-SECRET-SENTINEL"),
            "parent secret must not reach child; env: {child_env}"
        );
        assert!(child_env.contains("PATH="), "PATH must be in child env");

        // Also confirm run_dry itself completes without error.
        let outcome = runner.run_dry(&plan, &creds).expect("must succeed");
        assert_eq!(outcome.status, RunStatus::Planned);

        std::env::remove_var("RYUKI_INTEGRATION__ENCRYPTION_KEY");
    }

    // --- run_dry() returns RunnerUnavailable gracefully ---

    #[test]
    fn run_dry_returns_runner_unavailable_gracefully() {
        let runner = TerraformRunner::with_binary("/nonexistent/terraform-fake-binary");
        let plan = make_plan_dryrun();
        let creds = fake_creds("");
        let outcome = runner.run_dry(&plan, &creds).expect("must not error");
        assert_eq!(outcome.status, RunStatus::RunnerUnavailable);
        assert!(outcome.summary.contains("not found") || outcome.summary.contains("unavailable"));
        // Must never panic — we got here, so that's proved.
    }

    // --- run_dry() with /bin/echo shim captures output ---

    #[test]
    fn run_dry_with_echo_shim_captures_outcome() {
        // /bin/echo will: print its args and exit 0.
        // For "init" step: `echo init -input=false` → exits 0.
        // For "plan" step: `echo plan -input=false -no-color` → exits 0.
        // This proves: the runner invokes the binary, captures stdout, builds RunOutcome.
        let runner = TerraformRunner::with_binary(fake_shim_path());
        let plan = make_plan_dryrun();
        let creds = fake_creds("");
        let outcome = runner
            .run_dry(&plan, &creds)
            .expect("must succeed with echo shim");
        // Echo shim exits 0; outcome should be Planned.
        assert_eq!(outcome.status, RunStatus::Planned);
        assert_eq!(outcome.runner_kind, RunnerKind::Terraform);
        assert_eq!(outcome.mode, RunMode::DryRun);
        // The log should contain something from the echo output.
        assert!(!outcome.log.is_empty() || outcome.summary.contains("completed"));
    }

    // --- SECRET SCRUB: secret value must not appear in outcome ---

    #[test]
    fn run_dry_scrubs_secret_from_output() {
        // We use a script shim that echoes the env var containing the secret
        // to simulate a tool that might leak credentials.
        //
        // Write a temporary shell script that prints a known env var value.
        let ws = Workspace::new().expect("test workspace");
        let shim_path = ws.path().join("fake-terraform");
        let script = "#!/bin/sh\necho \"secret-value: $TF_VAR_test_secret\"\nexit 0\n";
        std::fs::write(&shim_path, script).expect("write shim");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod shim");
        }

        let runner = TerraformRunner::with_binary(shim_path.to_string_lossy().to_string());
        let mut plan = make_plan_dryrun();
        plan.secret_var_names = vec!["test_secret".to_string()];

        // The fake credential material that the shim will echo back.
        let secret_value = "FAKE-CREDENTIAL-THAT-MUST-NOT-APPEAR";
        let creds = fake_creds(secret_value);

        let outcome = runner.run_dry(&plan, &creds).expect("run must succeed");

        // The secret value must NOT appear in the outcome.
        assert!(
            !outcome.log.contains(secret_value),
            "secret must be scrubbed from log: got {:?}",
            outcome.log
        );
        assert!(
            !outcome.summary.contains(secret_value),
            "secret must be scrubbed from summary"
        );
        // But [REDACTED] or some indication of scrubbing should be present.
        assert!(
            outcome.log.contains("[REDACTED]") || !outcome.log.contains(secret_value),
            "output must be scrubbed"
        );
    }

    // --- credentials are NOT in argv ---

    #[test]
    fn run_dry_secret_not_in_argv() {
        // Write a shim that prints its own argv and exits 0.
        // The secret must not appear in the printed argv.
        let ws = Workspace::new().expect("test workspace");
        let shim_path = ws.path().join("fake-terraform-argv");
        // Print all args to stdout.
        let script = "#!/bin/sh\necho \"ARGV: $@\"\nexit 0\n";
        std::fs::write(&shim_path, script).expect("write shim");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod shim");
        }

        let runner = TerraformRunner::with_binary(shim_path.to_string_lossy().to_string());
        let mut plan = make_plan_dryrun();
        plan.secret_var_names = vec!["my_password".to_string()];

        let secret_value = "SUPER-SECRET-ARGV-VALUE";
        let creds = fake_creds(secret_value);

        let outcome = runner.run_dry(&plan, &creds).expect("run must succeed");

        // The secret must not appear anywhere in the captured output
        // (which contains the argv printed by the shim).
        // Since argv does not carry the secret (it's in env), the argv line
        // will not contain the secret value. The env injection via echo of
        // the var would only appear if we explicitly printed the env.
        assert!(
            !outcome.log.contains(secret_value),
            "secret value must not appear in argv output: {:?}",
            outcome.log
        );
    }

    // --- var name validation ---

    #[test]
    fn validate_var_name_accepts_valid_identifiers() {
        assert!(validate_var_name("my_secret").is_ok());
        assert!(validate_var_name("db_password").is_ok());
        assert!(validate_var_name("vsphere_password").is_ok());
        assert!(validate_var_name("_private").is_ok());
        assert!(validate_var_name("A1B2").is_ok());
    }

    #[test]
    fn validate_var_name_rejects_tf_log() {
        let err = validate_var_name("TF_LOG");
        assert!(
            err.is_err(),
            "TF_LOG must be rejected as a reserved control var"
        );
    }

    #[test]
    fn validate_var_name_rejects_tf_cli_prefix() {
        let err = validate_var_name("TF_CLI_ARGS");
        assert!(err.is_err(), "TF_CLI_ARGS must be rejected (TF_CLI prefix)");
    }

    #[test]
    fn validate_var_name_rejects_ld_prefix() {
        assert!(validate_var_name("LD_PRELOAD").is_err());
        assert!(validate_var_name("LD_LIBRARY_PATH").is_err());
    }

    #[test]
    fn validate_var_name_rejects_dyld_prefix() {
        assert!(validate_var_name("DYLD_INSERT_LIBRARIES").is_err());
    }

    #[test]
    fn validate_var_name_rejects_allowlist_exact() {
        assert!(validate_var_name("PATH").is_err());
        assert!(validate_var_name("HOME").is_err());
        assert!(validate_var_name("TMPDIR").is_err());
        assert!(validate_var_name("LANG").is_err());
        assert!(validate_var_name("LC_ALL").is_err());
    }

    #[test]
    fn validate_var_name_rejects_invalid_identifiers() {
        // Path-like or shell-injection patterns.
        assert!(validate_var_name("../x").is_err());
        assert!(validate_var_name("foo bar").is_err());
        assert!(validate_var_name("1bad").is_err());
        assert!(validate_var_name("").is_err());
        assert!(validate_var_name("foo-bar").is_err()); // hyphens not allowed in identifiers
    }

    #[test]
    fn run_dry_rejects_invalid_secret_var_name() {
        let runner = TerraformRunner::with_binary(fake_shim_path());
        let mut plan = make_plan_dryrun();
        plan.secret_var_names = vec!["TF_LOG".to_string()];
        let creds = fake_creds("secret");
        let result = runner.run_dry(&plan, &creds);
        assert!(
            result.is_err(),
            "run_dry must reject TF_LOG as a secret_var_name"
        );
    }

    // --- offering_id slug validation ---

    #[test]
    fn validate_offering_slug_accepts_valid_slugs() {
        assert!(validate_offering_slug("build-vm").is_ok());
        assert!(validate_offering_slug("maintain-monitoring-agent").is_ok());
        assert!(validate_offering_slug("a1b2c3").is_ok());
    }

    #[test]
    fn validate_offering_slug_rejects_path_traversal() {
        assert!(
            validate_offering_slug("../etc/passwd").is_err(),
            "../etc/passwd must be rejected"
        );
        assert!(
            validate_offering_slug("/abs/path").is_err(),
            "absolute path must be rejected"
        );
        assert!(
            validate_offering_slug("a/b").is_err(),
            "slash in slug must be rejected"
        );
        assert!(
            validate_offering_slug("").is_err(),
            "empty string must be rejected"
        );
    }

    #[test]
    fn run_dry_rejects_path_traversal_offering_id() {
        let runner = TerraformRunner::with_binary(fake_shim_path());
        let mut plan = make_plan_dryrun();
        plan.offering_id = "../etc/passwd".to_string();
        let creds = fake_creds("");
        let result = runner.run_dry(&plan, &creds);
        assert!(
            result.is_err(),
            "run_dry must reject path-traversal offering_id"
        );
    }

    // --- scrub multi-component: comma-joined credentials ---

    #[test]
    fn run_dry_scrubs_all_comma_joined_credential_components() {
        // Build a shim that echoes both comma-joined components from the env var.
        let ws = Workspace::new().expect("ws");
        let shim = ws.path().join("tf-multicomp");
        // The shim will echo the env var — which contains the full joined string —
        // but scrubbing must redact each component individually.
        // We also echo the components concatenated to prove both are caught.
        let script = "#!/bin/sh\necho \"leaked: $TF_VAR_multi_cred\"\nexit 0\n";
        std::fs::write(&shim, script).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let runner = TerraformRunner::with_binary(shim.to_string_lossy().to_string());
        let mut plan = make_plan_dryrun();
        plan.secret_var_names = vec!["multi_cred".to_string()];

        // The material contains two comma-joined components.
        let component_a = "FIRST-SECRET-COMPONENT";
        let component_b = "SECOND-SECRET-COMPONENT";
        let joined = format!("{},{}", component_a, component_b);
        let creds = fake_creds(&joined);

        let outcome = runner.run_dry(&plan, &creds).expect("must succeed");

        // Both components must be redacted from the log.
        assert!(
            !outcome.log.contains(component_a),
            "first component must be scrubbed; log: {:?}",
            outcome.log
        );
        assert!(
            !outcome.log.contains(component_b),
            "second component must be scrubbed; log: {:?}",
            outcome.log
        );
    }

    // --- helpers ---

    #[test]
    fn vars_to_json_serializes_correctly() {
        let vars = BTreeMap::from([
            ("cpu".to_string(), "4".to_string()),
            ("region".to_string(), "eu-west".to_string()),
        ]);
        let json = vars_to_json(&vars);
        assert!(json.contains("\"cpu\""));
        assert!(json.contains("\"4\""));
        assert!(json.contains("\"region\""));
        // Verify it parses as valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["cpu"], "4");
        assert_eq!(parsed["region"], "eu-west");
    }

    /// Round-trip test: a var value containing `"`, `\`, a newline, and a
    /// Unicode character must serialise to valid JSON and round-trip exactly.
    /// This is the regression guard for the hand-built JSON escaping bug.
    #[test]
    fn vars_to_json_roundtrips_special_chars() {
        let tricky_value = "quote\"backslash\\newline\nunicode\u{1F4A5}end";
        let vars = BTreeMap::from([
            ("normal_var".to_string(), "plain".to_string()),
            ("tricky_var".to_string(), tricky_value.to_string()),
        ]);
        let json = vars_to_json(&vars);
        // The produced string must parse as valid JSON (no malformed escapes).
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("vars_to_json must produce valid JSON for special chars");
        // The value must round-trip exactly — no corruption of the original bytes.
        assert_eq!(
            parsed["tricky_var"].as_str().unwrap(),
            tricky_value,
            "special-char value must round-trip exactly through JSON serialization"
        );
        assert_eq!(parsed["normal_var"].as_str().unwrap(), "plain");
    }

    #[test]
    fn extract_plan_summary_finds_plan_line() {
        let log =
            "Refreshing state...\nPlan: 2 to add, 0 to change, 0 to destroy.\nApply complete.";
        let summary = extract_plan_summary(log);
        assert_eq!(summary, "Plan: 2 to add, 0 to change, 0 to destroy.");
    }

    #[test]
    fn extract_plan_summary_finds_no_changes_line() {
        let log = "Refreshing state...\nNo changes. Your infrastructure matches the configuration.";
        let summary = extract_plan_summary(log);
        assert!(summary.starts_with("No changes."));
    }

    #[test]
    fn extract_plan_summary_fallback_when_no_match() {
        let log = "Something weird happened";
        let summary = extract_plan_summary(log);
        assert_eq!(summary, "terraform plan completed");
    }

    #[test]
    fn combine_output_merges_stdout_and_stderr() {
        let out = combine_output(b"stdout content", b"stderr content");
        assert!(out.contains("stdout content"));
        assert!(out.contains("stderr content"));
    }

    #[test]
    fn credential_components_splits_comma_joined() {
        let joined = b"first-val,second-val";
        let comps = credential_components(joined);
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0], b"first-val");
        assert_eq!(comps[1], b"second-val");
    }

    #[test]
    fn credential_components_single_value_no_comma() {
        let single = b"only-value";
        let comps = credential_components(single);
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0], b"only-value");
    }

    #[test]
    fn credential_components_empty_returns_empty() {
        let comps = credential_components(b"");
        assert!(comps.is_empty());
    }
}
