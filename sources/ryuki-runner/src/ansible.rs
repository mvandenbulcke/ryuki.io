//! Ansible runner — dry-run (--check) only (Slice 1).
//!
//! Executes `ansible-playbook --check` in an isolated workspace.
//!
//! # Security invariants
//! - The top-level Ansible CLI is an approved absolute canonical executable;
//!   inherited `PATH` is never used to select it.
//! - All child `Command`s call `.env_clear()` and then re-inject only a minimal
//!   allowlist: PATH, HOME, TMPDIR, LANG, LC_ALL (if present in the parent).
//!   This prevents platform secrets (RYUKI_*, RYUKI_DATABASE_*, vault tokens,
//!   cloud creds) from being inherited by the child process.
//! - Secret variable names are validated against a strict identifier pattern
//!   before injection; reserved/control names (ANSIBLE_*, LD_*, DYLD_*, etc.)
//!   are rejected.
//! - Ansible secrets are written to a 0600 `--extra-vars @<file>` JSON file
//!   inside the workspace, NOT injected as arbitrary environment variables.
//!   This prevents a var named `ANSIBLE_CONFIG` from becoming an env var.
//! - Non-secret vars are also written to a 0600 extra-vars file.
//! - Secret values NEVER appear in argv.
//! - `offering_id` is validated as a safe slug before use.
//! - Output is scrubbed (per-component) before being placed in `RunOutcome`.
//! - The workspace TempDir is removed on drop.
//! - `-vvv` (verbose) is never passed.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use ryuki_engine::runners::{
    ResolvedCredentials, RunMode, RunOutcome, RunPlan, RunStatus, RunnerError, RunnerKind,
};

use super::{
    exec::{run_command_with_optional_cancellation, run_version_probe, CommandCancellation},
    executable::{ApprovedExecutable, ApprovedTool},
    scrub::scrub_output,
    terraform::{
        credential_components, pin_home_tmpdir_to_workspace, validate_offering_slug,
        validate_var_name, ENV_ALLOWLIST,
    },
    workspace::Workspace,
    Runner,
};

/// Per-subprocess timeout for ansible-playbook --check.
/// A hung ansible (e.g. waiting for an unreachable host) is killed after this.
const RUNNER_TIMEOUT: Duration = Duration::from_secs(120);

/// Preserve authoritative terminal supervisor outcomes while adding Ansible
/// phase context to ordinary setup failures.
fn ansible_check_error(error: RunnerError) -> RunnerError {
    match error {
        terminal @ (RunnerError::Timeout
        | RunnerError::Cancelled
        | RunnerError::OutputLimitExceeded { .. }) => terminal,
        other => RunnerError::Spawn(format!("ansible-playbook --check: {other}")),
    }
}

/// Variable name prefixes that are specifically blocked for Ansible in addition
/// to the shared BLOCKED_PREFIXES in terraform.rs.
const ANSIBLE_BLOCKED_PREFIXES: &[&str] = &["ANSIBLE_"];

/// Runner for Ansible. Dry-run (--check) only in Slice 1.
///
/// # Executable approval
/// Production runs require `RYUKI_ANSIBLE_PLAYBOOK_EXECUTABLE` and
/// `RYUKI_ANSIBLE_PLAYBOOK_EXPECTED_VERSION`. The configured CLI is admitted
/// through the shared approved-executable boundary before command construction.
///
/// # IaC embedding
/// Use `AnsibleRunner::with_iac(files)` to embed static playbook content that is
/// written into the workspace before `ansible-playbook --check` is invoked.
/// This mirrors the `TerraformRunner::with_iac` pattern.
#[derive(Default)]
pub struct AnsibleRunner {
    executable: Option<ApprovedExecutable>,
    iac_files: Vec<(&'static str, &'static str)>,
    cancellation: Option<CommandCancellation>,
}

impl AnsibleRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a runner pointing at a test shim without requiring a real
    /// Ansible installation. This bypass is absent from production builds.
    #[cfg(test)]
    pub fn with_binary(binary: impl Into<String>) -> Self {
        let binary: String = binary.into();
        Self {
            executable: Some(ApprovedExecutable::for_test(binary)),
            iac_files: Vec::new(),
            cancellation: None,
        }
    }

    /// Attach static IaC files (playbook + any supporting files) to this runner.
    ///
    /// The files are written into the workspace by `run_dry` BEFORE invoking
    /// `ansible-playbook --check`. Each entry is `(filename, utf8_content)`.
    /// The playbook must be named `<offering_id>.yml` to match the command-line
    /// reference built by `run_dry`.
    pub fn with_iac(mut self, files: Vec<(&'static str, &'static str)>) -> Self {
        self.iac_files = files;
        self
    }

    /// Attach one cancellation signal to the entire logical run, including
    /// the version probe and the actual `--check` subprocess.
    pub fn with_cancellation(mut self, cancellation: &CommandCancellation) -> Self {
        self.cancellation = Some(cancellation.clone());
        self
    }

    fn approved_executable(&self) -> Result<ApprovedExecutable, RunnerError> {
        match &self.executable {
            Some(executable) => Ok(executable.clone()),
            None => ApprovedExecutable::configured(
                ApprovedTool::AnsiblePlaybook,
                self.cancellation.as_ref(),
            ),
        }
    }

    fn probe_available(&self, executable: &ApprovedExecutable) -> Result<bool, RunnerError> {
        let mut cmd = Command::new(executable.path());
        apply_env_allowlist(&mut cmd);
        cmd.arg("--version");
        run_version_probe(cmd, self.cancellation.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Ansible-specific name validation
// ---------------------------------------------------------------------------

/// Validate a variable name for Ansible extra-vars injection.
///
/// In addition to the shared identifier/blocked-prefix checks from
/// `terraform::validate_var_name`, also rejects names starting with `ANSIBLE_`
/// to prevent hijacking Ansible configuration via extra-vars.
fn validate_ansible_var_name(name: &str) -> Result<(), RunnerError> {
    // Apply the shared validation first.
    validate_var_name(name)?;
    // Then apply Ansible-specific blocked prefixes.
    for prefix in ANSIBLE_BLOCKED_PREFIXES {
        if name.starts_with(prefix) {
            return Err(RunnerError::CredInjection(format!(
                "variable name '{name}' starts with reserved Ansible prefix '{prefix}'"
            )));
        }
    }
    Ok(())
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn combine_output(stdout: &[u8], stderr: &[u8]) -> String {
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

/// Serialize vars to valid JSON for `--extra-vars @file.json`.
///
/// Uses `serde_json` to guarantee correct escaping of all values, including
/// those containing `"`, `\`, newlines, and arbitrary Unicode/control chars.
fn vars_to_json(vars: &BTreeMap<String, String>) -> String {
    let map: serde_json::Map<String, serde_json::Value> = vars
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    serde_json::to_string_pretty(&map).unwrap_or_else(|_| "{}".to_string())
}

/// Serialize secret vars (name → value) to valid JSON for `--extra-vars @<secrets-file>`.
/// This is a separate file written at 0600; the values are the resolved credential
/// material mapped to each secret_var_name in the plan.
///
/// Uses `serde_json` to guarantee correct escaping of all values, including
/// credential material containing `"`, `\`, newlines, and arbitrary Unicode/control chars.
///
/// For Slice 1 all secret vars share the same credential material. A future slice
/// with per-name credentials will extend this mapping.
fn secrets_to_json(secret_var_names: &[String], cred_str: &str) -> String {
    let map: serde_json::Map<String, serde_json::Value> = secret_var_names
        .iter()
        .map(|name| {
            (
                name.clone(),
                serde_json::Value::String(cred_str.to_string()),
            )
        })
        .collect();
    serde_json::to_string_pretty(&map).unwrap_or_else(|_| "{}".to_string())
}

/// Extract a one-line summary from scrubbed ansible output.
/// Looks for the PLAY RECAP summary block.
fn extract_ansible_summary(log: &str) -> String {
    // Try to find a PLAY RECAP line.
    let mut in_recap = false;
    for line in log.lines() {
        if line.contains("PLAY RECAP") {
            in_recap = true;
            continue;
        }
        if in_recap {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                return format!("check: {trimmed}");
            }
        }
    }
    "ansible-playbook --check completed".to_string()
}

// ---------------------------------------------------------------------------
// Runner implementation
// ---------------------------------------------------------------------------

impl Runner for AnsibleRunner {
    fn available(&self) -> bool {
        self.approved_executable()
            .and_then(|executable| self.probe_available(&executable))
            .unwrap_or(false)
    }

    fn run_dry(
        &self,
        plan: &RunPlan,
        creds: &ResolvedCredentials,
    ) -> Result<RunOutcome, RunnerError> {
        // Guard: only dry-run in Slice 1.
        if plan.mode != RunMode::DryRun {
            return Err(RunnerError::Spawn(
                "Live mode is not implemented in Slice 1".to_string(),
            ));
        }

        // Validate offering_id before any path construction.
        validate_offering_slug(&plan.offering_id)?;

        // Validate every secret variable name with Ansible-specific rules.
        // This also catches ANSIBLE_CONFIG, ANSIBLE_VAULT_PASSWORD_FILE, etc.
        for name in &plan.secret_var_names {
            validate_ansible_var_name(name)?;
        }

        // Establish executable provenance before credential material is even
        // split or written and before any credential-bearing Command exists.
        let executable = match self.approved_executable() {
            Ok(executable) => executable,
            Err(error) => {
                if matches!(&error, RunnerError::Cancelled) {
                    return Err(error);
                }
                return Ok(RunOutcome {
                    runner_kind: RunnerKind::Ansible,
                    mode: plan.mode,
                    status: RunStatus::RunnerUnavailable,
                    summary:
                        "runner unavailable: configured ansible-playbook executable was not approved"
                            .to_string(),
                    log: String::new(),
                    exit_code: None,
                    post_apply: None,
                });
            }
        };

        // Build per-component secret values for scrubbing.
        let components: Vec<Vec<u8>> = credential_components(creds.material.as_slice());
        let secret_refs: Vec<&[u8]> = components.iter().map(|v| v.as_slice()).collect();

        // --- Binary availability check ---
        if !self.probe_available(&executable)? {
            return Ok(RunOutcome {
                runner_kind: RunnerKind::Ansible,
                mode: plan.mode,
                status: RunStatus::RunnerUnavailable,
                summary: format!(
                    "runner unavailable: ansible-playbook binary not found at {:?}",
                    executable.path()
                ),
                log: String::new(),
                exit_code: None,
                post_apply: None,
            });
        }

        // --- Workspace setup ---
        let ws = Workspace::new()?;

        // Write embedded IaC files (playbook, support files) into the workspace
        // BEFORE invoking ansible-playbook. This mirrors TerraformRunner::with_iac.
        for (filename, content) in &self.iac_files {
            ws.write_file(filename, content.as_bytes())?;
        }

        // Write non-secret extra-vars to a 0600 JSON file.
        // Passed as `--extra-vars @ryuki-vars.json` — never inline on argv.
        let vars_file_arg: Option<String> = if !plan.vars.is_empty() {
            let vars_json = vars_to_json(&plan.vars);
            let vars_path = ws.write_file_0600("ryuki-vars.json", vars_json.as_bytes())?;
            Some(format!("@{}", vars_path.to_string_lossy()))
        } else {
            None
        };

        // Write SECRET extra-vars to a separate 0600 JSON file.
        // This is the critical change vs. the previous implementation:
        // secrets are NEVER injected as arbitrary environment variables.
        // Using an extra-vars file means a var named `ANSIBLE_CONFIG` becomes
        // a playbook variable, not an env var that overrides Ansible's config.
        let secrets_file_arg: Option<String> = if !plan.secret_var_names.is_empty() {
            let cred_str = std::str::from_utf8(creds.material.as_slice())
                .map(|s| s.to_string())
                .unwrap_or_else(|_| String::new());
            let secrets_json = secrets_to_json(&plan.secret_var_names, &cred_str);
            let secrets_path = ws.write_file_0600("ryuki-secrets.json", secrets_json.as_bytes())?;
            Some(format!("@{}", secrets_path.to_string_lossy()))
        } else {
            None
        };

        // Use the offering_id (already slug-validated) as the playbook reference.
        // In a real deployment, this resolves to a path under deploy/ansible/.
        // The slug validation above ensures no path traversal is possible.
        let playbook_ref = format!("{}.yml", plan.offering_id);

        // --- Build command ---
        // NEVER pass: -vvv (verbose), --vault-password-file with secret on argv.
        // env_clear() + allowlist applied; then explicit Ansible control vars added.
        let mut cmd = Command::new(executable.path());
        apply_env_allowlist(&mut cmd);
        // Pin HOME and TMPDIR to the workspace so ansible cannot write to
        // the real $HOME (e.g. ~/.ansible/tmp). Also set ANSIBLE_LOCAL_TEMP
        // so ansible's internal temp dir stays inside the per-run workspace.
        pin_home_tmpdir_to_workspace(&mut cmd, ws.path());
        cmd.arg("--check")
            .arg(&playbook_ref)
            .current_dir(ws.path())
            // Redirect ansible temp files into the workspace.
            .env("ANSIBLE_LOCAL_TEMP", ws.path())
            // Disable host key checking for the check run.
            .env("ANSIBLE_HOST_KEY_CHECKING", "False")
            // Suppress Python warnings that would pollute output.
            .env("PYTHONWARNINGS", "ignore")
            // env_clear() already removed ANSIBLE_VERBOSITY; this is defense-in-depth.
            .env_remove("ANSIBLE_VERBOSITY");

        // Inject non-secret extra-vars file if present.
        if let Some(ref vars_arg) = vars_file_arg {
            cmd.args(["--extra-vars", vars_arg]);
        }

        // Inject secret extra-vars file if present.
        // IMPORTANT: secrets go through a 0600 file, NOT as env vars.
        if let Some(ref secrets_arg) = secrets_file_arg {
            cmd.args(["--extra-vars", secrets_arg]);
        }

        // Execute with bounded timeout. A hung ansible (unreachable host, etc.)
        // is killed and returns Err(RunnerError::Timeout) to the caller.
        let output =
            run_command_with_optional_cancellation(cmd, RUNNER_TIMEOUT, self.cancellation.as_ref())
                .map_err(ansible_check_error)?;

        let raw = combine_output(&output.stdout, &output.stderr);
        let scrubbed_log = scrub_output(&raw, &secret_refs);

        // Ansible exit codes:
        //   0 — success (no changes in --check mode)
        //   1 — error
        //   2 — one or more host failed
        //   4 — unreachable hosts
        //   8 — parse error in playbook
        //   with --check: 0 = no changes needed; non-0 = issues found
        let (status, summary) = match output.status.code() {
            Some(0) => (RunStatus::CheckOk, extract_ansible_summary(&scrubbed_log)),
            Some(code) => (
                RunStatus::Failed,
                format!("ansible-playbook --check failed (exit {code})"),
            ),
            None => (
                RunStatus::Failed,
                "ansible-playbook killed by signal".to_string(),
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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_plan_dryrun() -> RunPlan {
        RunPlan {
            runner_kind: RunnerKind::Ansible,
            mode: RunMode::DryRun,
            offering_id: "maintain-monitoring-agent".to_string(),
            vars: BTreeMap::from([("target_host".to_string(), "srv-01.example.com".to_string())]),
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
    fn available_returns_true_for_echo_shim() {
        // /bin/echo --version exits 0.
        let runner = AnsibleRunner::with_binary("/bin/echo");
        assert!(runner.available());
    }

    #[test]
    fn available_returns_false_for_missing_binary() {
        let runner = AnsibleRunner::with_binary("/nonexistent/ansible-playbook-fake");
        assert!(
            !runner.available(),
            "missing binary must return false, not panic"
        );
    }

    // --- env_clear: parent secrets must NOT reach the child ---

    #[test]
    fn available_does_not_inherit_parent_secrets() {
        std::env::set_var("RYUKI_INTEGRATION__ENCRYPTION_KEY", "ANS-PARENT-SECRET");

        // Probe the allowlist by running `/usr/bin/env`, which prints the child
        // environment. Execing an existing binary (rather than writing a temp
        // shim and immediately execing it) avoids the ETXTBSY ("text file busy")
        // race a freshly-written executable hits under parallel test execution,
        // where a concurrent test's fork transiently holds a write fd to it.
        let mut cmd = Command::new("/usr/bin/env");
        apply_env_allowlist(&mut cmd);
        let output = cmd.output().expect("probe must succeed");
        let child_env = String::from_utf8_lossy(&output.stdout);

        assert!(
            !child_env.contains("ANS-PARENT-SECRET"),
            "parent secret must not reach child; env: {child_env}"
        );
        assert!(
            child_env.contains("PATH="),
            "PATH must be in child env; got: {child_env}"
        );

        std::env::remove_var("RYUKI_INTEGRATION__ENCRYPTION_KEY");
    }

    // --- run_dry() returns RunnerUnavailable gracefully ---

    #[test]
    fn run_dry_returns_runner_unavailable_gracefully() {
        let runner = AnsibleRunner::with_binary("/nonexistent/ansible-playbook-fake");
        let plan = make_plan_dryrun();
        let creds = fake_creds("");
        let outcome = runner.run_dry(&plan, &creds).expect("must not error");
        assert_eq!(outcome.status, RunStatus::RunnerUnavailable);
        assert!(outcome.summary.contains("not found") || outcome.summary.contains("unavailable"));
    }

    // --- run_dry() with /bin/echo shim captures output ---

    #[test]
    fn run_dry_with_echo_shim_captures_outcome() {
        let runner = AnsibleRunner::with_binary("/bin/echo");
        let plan = make_plan_dryrun();
        let creds = fake_creds("");
        let outcome = runner
            .run_dry(&plan, &creds)
            .expect("must succeed with echo shim");
        assert_eq!(outcome.runner_kind, RunnerKind::Ansible);
        assert_eq!(outcome.mode, RunMode::DryRun);
        // Echo exits 0 → CheckOk.
        assert_eq!(outcome.status, RunStatus::CheckOk);
    }

    #[test]
    fn check_cancellation_preserves_exact_terminal_variant() {
        let ws = Workspace::new().expect("workspace");
        let started = ws.path().join("ansible-check-started");
        let shim = ws.path().join("cancellable-ansible");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then exit 0; fi\ntouch '{}'\nsleep 30\n",
            started.display()
        );
        std::fs::write(&shim, script).expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
                .expect("chmod shim");
        }

        let cancellation = CommandCancellation::new();
        let runner =
            AnsibleRunner::with_binary(shim.to_string_lossy()).with_cancellation(&cancellation);
        let worker =
            std::thread::spawn(move || runner.run_dry(&make_plan_dryrun(), &fake_creds("")));
        assert!(
            (0..500).any(|_| {
                if started.exists() {
                    true
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                    false
                }
            }),
            "fake Ansible check must start"
        );
        cancellation.cancel();
        let error = worker
            .join()
            .expect("runner thread must not panic")
            .expect_err("cancelled Ansible check must be terminal");
        assert_eq!(error, RunnerError::Cancelled);
    }

    #[test]
    fn check_capture_overflow_preserves_exact_terminal_variant() {
        let ws = Workspace::new().expect("workspace");
        let shim = ws.path().join("overflowing-ansible-check");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then exit 0; fi\nyes x | head -c {}\n",
            crate::exec::MAX_CAPTURE_BYTES_PER_STREAM + 1
        );
        std::fs::write(&shim, script).expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
                .expect("chmod shim");
        }

        let error = AnsibleRunner::with_binary(shim.to_string_lossy())
            .run_dry(&make_plan_dryrun(), &fake_creds(""))
            .expect_err("oversized Ansible check output must be terminal");
        assert!(matches!(
            error,
            RunnerError::OutputLimitExceeded { ref scope, limit }
                if scope == "stdout" && limit == crate::exec::MAX_CAPTURE_BYTES_PER_STREAM
        ));
    }

    // --- SECRET SCRUB ---

    #[test]
    fn run_dry_scrubs_secret_from_output() {
        // This test confirms the scrubbing layer works even though secrets now
        // go through a file rather than env vars. The shim prints its argv
        // (which includes the --extra-vars @<path> argument); the content of
        // the secrets file is NOT echoed, but if the binary ever leaked the
        // file path that contains the secret, scrubbing must still redact it.
        //
        // We construct a shim that cats the secrets file (simulating
        // a misbehaving playbook) and verify the output is scrubbed.
        let ws_shim = Workspace::new().expect("ws");
        let shim = ws_shim.path().join("fake-ansible-scrub");
        // The shim reads its last argument (the @<file> path), strips the '@',
        // and cats the secrets file — simulating a tool that leaks the file.
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

        let runner = AnsibleRunner::with_binary(shim.to_string_lossy().to_string());
        let mut plan = make_plan_dryrun();
        plan.secret_var_names = vec!["api_key".to_string()];

        let secret_value = "FAKE-ANSIBLE-SECRET-CREDENTIAL";
        let creds = fake_creds(secret_value);

        let outcome = runner.run_dry(&plan, &creds).expect("run must succeed");

        assert!(
            !outcome.log.contains(secret_value),
            "secret must be scrubbed from log: got {:?}",
            outcome.log
        );
        assert!(!outcome.summary.contains(secret_value));
    }

    // --- ansible secrets go to file, NOT arbitrary env vars ---

    #[test]
    fn run_dry_ansible_secrets_written_to_file_not_env() {
        // This is the critical regression guard for Issue 2 (Ansible):
        // secrets must appear in the --extra-vars file, NOT as env vars
        // in the child process. A shim that prints its full environment must
        // NOT contain the secret value.
        let ws_shim = Workspace::new().expect("ws");
        let shim = ws_shim.path().join("ans-env-check");
        // Print the full environment — if secrets were injected as env vars,
        // the value would appear here.
        let script = "#!/bin/sh\nenv\nexit 0\n";
        std::fs::write(&shim, script).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let runner = AnsibleRunner::with_binary(shim.to_string_lossy().to_string());
        let mut plan = make_plan_dryrun();
        plan.secret_var_names = vec!["api_key".to_string()];

        let secret_value = "ANSIBLE-ENV-INJECTION-TEST-SECRET";
        let creds = fake_creds(secret_value);

        let outcome = runner.run_dry(&plan, &creds).expect("must succeed");

        // The secret must NOT appear in the child's environment output.
        // (It goes to a file via --extra-vars @file, not an env var.)
        assert!(
            !outcome.log.contains(secret_value),
            "secret must NOT be in child env (secrets go to --extra-vars file): {:?}",
            outcome.log
        );
    }

    // --- credentials are NOT in argv ---

    #[test]
    fn run_dry_secret_not_in_argv() {
        // Shim prints its argv — secret must not appear there.
        let ws = Workspace::new().expect("test workspace");
        let shim_path = ws.path().join("fake-ansible-argv");
        let script = "#!/bin/sh\necho \"ARGV: $@\"\nexit 0\n";
        std::fs::write(&shim_path, script).expect("write shim");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
        }

        let runner = AnsibleRunner::with_binary(shim_path.to_string_lossy().to_string());
        let mut plan = make_plan_dryrun();
        plan.secret_var_names = vec!["api_key".to_string()];

        let secret_value = "SUPER-SECRET-ANSIBLE-KEY";
        let creds = fake_creds(secret_value);

        let outcome = runner.run_dry(&plan, &creds).expect("run must succeed");

        // The argv output must not contain the secret (it's in a file).
        assert!(
            !outcome.log.contains(secret_value),
            "secret must not be in argv: {:?}",
            outcome.log
        );
    }

    // --- var name validation (Ansible-specific: ANSIBLE_ prefix blocked) ---

    #[test]
    fn validate_ansible_var_name_rejects_ansible_config() {
        let err = validate_ansible_var_name("ANSIBLE_CONFIG");
        assert!(
            err.is_err(),
            "ANSIBLE_CONFIG must be rejected (ANSIBLE_ prefix)"
        );
    }

    #[test]
    fn validate_ansible_var_name_rejects_ansible_vault() {
        assert!(validate_ansible_var_name("ANSIBLE_VAULT_PASSWORD_FILE").is_err());
    }

    #[test]
    fn validate_ansible_var_name_rejects_tf_log() {
        assert!(validate_ansible_var_name("TF_LOG").is_err());
    }

    #[test]
    fn validate_ansible_var_name_rejects_ld_preload() {
        assert!(validate_ansible_var_name("LD_PRELOAD").is_err());
    }

    #[test]
    fn validate_ansible_var_name_rejects_path_allowlist() {
        assert!(validate_ansible_var_name("PATH").is_err());
        assert!(validate_ansible_var_name("HOME").is_err());
    }

    #[test]
    fn validate_ansible_var_name_accepts_safe_names() {
        assert!(validate_ansible_var_name("api_key").is_ok());
        assert!(validate_ansible_var_name("zabbix_password").is_ok());
        assert!(validate_ansible_var_name("_private_var").is_ok());
    }

    #[test]
    fn run_dry_rejects_ansible_config_as_secret_var_name() {
        let runner = AnsibleRunner::with_binary("/bin/echo");
        let mut plan = make_plan_dryrun();
        plan.secret_var_names = vec!["ANSIBLE_CONFIG".to_string()];
        let creds = fake_creds("anything");
        let result = runner.run_dry(&plan, &creds);
        assert!(
            result.is_err(),
            "run_dry must reject ANSIBLE_CONFIG as a secret_var_name"
        );
    }

    // --- offering_id slug validation ---

    #[test]
    fn run_dry_rejects_path_traversal_offering_id() {
        let runner = AnsibleRunner::with_binary("/bin/echo");
        let mut plan = make_plan_dryrun();
        plan.offering_id = "../etc/passwd".to_string();
        let creds = fake_creds("");
        let result = runner.run_dry(&plan, &creds);
        assert!(
            result.is_err(),
            "run_dry must reject path-traversal offering_id"
        );
    }

    #[test]
    fn run_dry_rejects_absolute_offering_id() {
        let runner = AnsibleRunner::with_binary("/bin/echo");
        let mut plan = make_plan_dryrun();
        plan.offering_id = "/abs/path".to_string();
        let creds = fake_creds("");
        assert!(runner.run_dry(&plan, &creds).is_err());
    }

    #[test]
    fn run_dry_rejects_slash_in_offering_id() {
        let runner = AnsibleRunner::with_binary("/bin/echo");
        let mut plan = make_plan_dryrun();
        plan.offering_id = "a/b".to_string();
        let creds = fake_creds("");
        assert!(runner.run_dry(&plan, &creds).is_err());
    }

    // --- scrub multi-component: comma-joined credentials ---

    #[test]
    fn run_dry_scrubs_all_comma_joined_credential_components() {
        // Build a shim that cats the secrets file (simulating credential leakage).
        let ws_shim = Workspace::new().expect("ws");
        let shim = ws_shim.path().join("ans-multicomp-scrub");
        let script = "#!/bin/sh\n\
                      for arg in \"$@\"; do\n\
                        case \"$arg\" in @*)\n\
                          cat \"${arg#@}\"\n\
                        ;;\n\
                        esac\n\
                      done\n\
                      exit 0\n";
        std::fs::write(&shim, script).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let runner = AnsibleRunner::with_binary(shim.to_string_lossy().to_string());
        let mut plan = make_plan_dryrun();
        plan.secret_var_names = vec!["multi_cred".to_string()];

        let component_a = "FIRST-ANS-SECRET-COMPONENT";
        let component_b = "SECOND-ANS-SECRET-COMPONENT";
        let joined = format!("{},{}", component_a, component_b);
        let creds = fake_creds(&joined);

        let outcome = runner.run_dry(&plan, &creds).expect("must succeed");

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
    fn extract_ansible_summary_finds_recap() {
        let log =
            "PLAY [all] ****\nTASK [check] ****\n\nPLAY RECAP ****\nlocalhost : ok=1 changed=0\n";
        let summary = extract_ansible_summary(log);
        assert!(summary.contains("ok=1"), "got: {summary}");
    }

    #[test]
    fn extract_ansible_summary_fallback() {
        let log = "some ansible output without recap";
        let summary = extract_ansible_summary(log);
        assert_eq!(summary, "ansible-playbook --check completed");
    }

    #[test]
    fn secrets_to_json_contains_secret_value() {
        let names = vec!["api_key".to_string(), "db_pass".to_string()];
        let json = secrets_to_json(&names, "s3cr3t");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["api_key"], "s3cr3t");
        assert_eq!(parsed["db_pass"], "s3cr3t");
    }

    /// Round-trip test: an ansible extra-var value containing `"`, `\`, a
    /// newline, and a Unicode character must serialise to valid JSON and
    /// round-trip exactly. Regression guard for the hand-built JSON escaping bug.
    #[test]
    fn vars_to_json_roundtrips_special_chars() {
        let tricky_value = "quote\"backslash\\newline\nunicode\u{1F4A5}end";
        let vars = BTreeMap::from([
            ("normal_var".to_string(), "plain".to_string()),
            ("tricky_var".to_string(), tricky_value.to_string()),
        ]);
        let json = vars_to_json(&vars);
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("vars_to_json must produce valid JSON for special chars");
        assert_eq!(
            parsed["tricky_var"].as_str().unwrap(),
            tricky_value,
            "special-char value must round-trip exactly through ansible vars JSON"
        );
        assert_eq!(parsed["normal_var"].as_str().unwrap(), "plain");
    }

    /// Round-trip test: a secret credential value containing `"`, `\`, a
    /// newline, and a Unicode character must serialise to valid JSON and
    /// round-trip exactly. Regression guard for the hand-built JSON escaping bug.
    #[test]
    fn secrets_to_json_roundtrips_special_chars() {
        let tricky_cred = "cred\"with\\newline\nunicode\u{1F525}end";
        let names = vec!["api_key".to_string(), "db_pass".to_string()];
        let json = secrets_to_json(&names, tricky_cred);
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("secrets_to_json must produce valid JSON for special chars");
        assert_eq!(
            parsed["api_key"].as_str().unwrap(),
            tricky_cred,
            "special-char secret must round-trip exactly for api_key"
        );
        assert_eq!(
            parsed["db_pass"].as_str().unwrap(),
            tricky_cred,
            "special-char secret must round-trip exactly for db_pass"
        );
    }
}
