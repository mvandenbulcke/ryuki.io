//! Live Terraform driver — `terraform plan -out=tfplan` + `terraform apply tfplan`.
//!
//! ## Mode contract
//!
//! Both functions require `plan.mode == RunMode::Live`.  Callers that hold a
//! `RunMode::DryRun` plan must call `run_offline_dry_run` in `lib.rs` instead.
//!
//! ## Backend config (durable LOCKED state backend)
//!
//! An [`IsolatedBackendConfig`] is written into the workspace as
//! `backend_override.tf` BEFORE `terraform init`. The config can only be built
//! from an operator template containing the exact `{STATE_KEY}` placeholder
//! and a validated control-plane state key. Live Terraform has no unisolated
//! fallback: missing templates, missing placeholders, and unsafe keys fail
//! before any Terraform subprocess is invoked.
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
//! ## Credential seam (wired via per-offering declarations)
//!
//! `RunPlan.secret_var_names` is populated by the agent from the offering's
//! declaration in `iac::live_secret_var_names` (e.g. the vSphere
//! server-deployment offerings declare `VSPHERE_USER` / `VSPHERE_PASSWORD` /
//! `VSPHERE_SERVER`).  The agent resolves each declared name from
//! `RYUKI_LIVE_CRED_<NAME>` in its own environment — failing closed with the
//! VARIABLE NAME only, BEFORE the runner is invoked, when one is missing —
//! and passes the values comma-joined in declared order as
//! `ResolvedCredentials.material`.  For LIVE modes only, `run_tf_step` injects
//! each declared name verbatim (the provider-native env var) plus its
//! `TF_VAR_<lowercased name>` terraform-variable alias on the child process.
//! The parent env allowlist (PATH/HOME/TMPDIR/LANG/LC_ALL) still never passes
//! provider-native vars from the HOST environment — only declared, resolved
//! values reach the child, and every value is scrubbed from all output.  A
//! declared-vs-resolved arity mismatch fails closed (`CredInjection`) before
//! any terraform subprocess is spawned.  The offline dry-run path
//! (`run_offline_dry_run`) never receives credentials: the agent always builds
//! it with an empty `secret_var_names` list and empty credential material.
//!
//! ## Security invariants (MUST hold — same as `terraform.rs`)
//!
//! - Secret material is NEVER passed as a command-line argument.
//! - Secrets are injected as `TF_VAR_<name>` env vars on the child only.
//! - Output is scrubbed before placement in `RunOutcome.log` / `.summary`.
//! - Workspace `TempDir` is removed on drop.
//! - `TF_LOG` is never set to `trace` or any verbose level.
//! - Raw `tfplan` bytes are opaque binary data and MUST NOT be logged.

use std::path::Path;
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
    scrub::{scrub, scrub_output, truncate_log},
    terraform::{
        apply_env_allowlist, combine_output, credential_components, pin_home_tmpdir_to_workspace,
        validate_offering_slug, validate_var_name, TERRAFORM_INIT_ARGS,
    },
    workspace::Workspace,
};

/// Per-subprocess timeout for each terraform sub-command in a live run.
/// Init / plan / apply are each given this budget independently.
const LIVE_RUNNER_TIMEOUT: Duration = Duration::from_secs(600); // 10 min per step

/// Default binary name; overridable for tests via a custom path in tests.
const DEFAULT_BINARY: &str = "terraform";

/// Exact token an operator backend template must contain.
pub const STATE_KEY_PLACEHOLDER: &str = "{STATE_KEY}";

#[derive(Debug, Clone, PartialEq, Eq)]
enum BackendHclToken {
    Ident(String),
    Quoted(String),
    Equals,
    OpenBrace,
    CloseBrace,
}

fn tokenize_backend_hcl(template: &str) -> Result<Vec<BackendHclToken>, RunnerError> {
    let bytes = template.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        match bytes[index] {
            b'#' => {
                index += 1;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                let mut closed = false;
                while index + 1 < bytes.len() {
                    if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                        index += 2;
                        closed = true;
                        break;
                    }
                    index += 1;
                }
                if !closed {
                    return Err(RunnerError::Spawn(
                        "live Terraform backend template has an unterminated block comment"
                            .to_string(),
                    ));
                }
            }
            b'"' => {
                index += 1;
                let start = index;
                let mut closed = false;
                while index < bytes.len() {
                    match bytes[index] {
                        b'\\' => index = (index + 2).min(bytes.len()),
                        b'"' => {
                            tokens
                                .push(BackendHclToken::Quoted(template[start..index].to_string()));
                            index += 1;
                            closed = true;
                            break;
                        }
                        _ => index += 1,
                    }
                }
                if !closed {
                    return Err(RunnerError::Spawn(
                        "live Terraform backend template has an unterminated quoted string"
                            .to_string(),
                    ));
                }
            }
            b'{' => {
                tokens.push(BackendHclToken::OpenBrace);
                index += 1;
            }
            b'}' => {
                tokens.push(BackendHclToken::CloseBrace);
                index += 1;
            }
            b'=' => {
                tokens.push(BackendHclToken::Equals);
                index += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'-'))
                {
                    index += 1;
                }
                tokens.push(BackendHclToken::Ident(template[start..index].to_string()));
            }
            _ => index += 1,
        }
    }

    Ok(tokens)
}

fn matching_hcl_brace(tokens: &[BackendHclToken], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token {
            BackendHclToken::OpenBrace => depth += 1,
            BackendHclToken::CloseBrace => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn direct_attribute_contains(
    tokens: &[BackendHclToken],
    open: usize,
    close: usize,
    attribute_names: &[&str],
) -> bool {
    let mut depth = 0usize;
    let mut index = open + 1;
    while index < close {
        if depth == 0 {
            if let (
                Some(BackendHclToken::Ident(name)),
                Some(BackendHclToken::Equals),
                Some(BackendHclToken::Quoted(value)),
            ) = (
                tokens.get(index),
                tokens.get(index + 1),
                tokens.get(index + 2),
            ) {
                if attribute_names.contains(&name.as_str()) && value.contains(STATE_KEY_PLACEHOLDER)
                {
                    return true;
                }
            }
        }

        match &tokens[index] {
            BackendHclToken::OpenBrace => depth += 1,
            BackendHclToken::CloseBrace => depth = depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    false
}

fn direct_attribute_value<'a>(
    tokens: &'a [BackendHclToken],
    open: usize,
    close: usize,
    attribute_name: &str,
) -> Option<&'a str> {
    let mut depth = 0usize;
    let mut index = open + 1;
    while index < close {
        if depth == 0
            && matches!(tokens.get(index), Some(BackendHclToken::Ident(name)) if name == attribute_name)
            && matches!(tokens.get(index + 1), Some(BackendHclToken::Equals))
        {
            if let Some(BackendHclToken::Quoted(value)) = tokens.get(index + 2) {
                return Some(value);
            }
        }

        match &tokens[index] {
            BackendHclToken::OpenBrace => depth += 1,
            BackendHclToken::CloseBrace => depth = depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    None
}

fn remote_workspace_contains_state_key(
    tokens: &[BackendHclToken],
    open: usize,
    close: usize,
) -> bool {
    let mut depth = 0usize;
    let mut index = open + 1;
    while index < close {
        if depth == 0
            && matches!(tokens.get(index), Some(BackendHclToken::Ident(name)) if name == "workspaces")
            && matches!(tokens.get(index + 1), Some(BackendHclToken::OpenBrace))
        {
            if let Some(workspaces_close) = matching_hcl_brace(tokens, index + 1) {
                return direct_attribute_contains(
                    tokens,
                    index + 1,
                    workspaces_close,
                    &["name", "prefix"],
                );
            }
        }

        match &tokens[index] {
            BackendHclToken::OpenBrace => depth += 1,
            BackendHclToken::CloseBrace => depth = depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    false
}

fn backend_location_contains_state_key(
    backend_type: &str,
    tokens: &[BackendHclToken],
    open: usize,
    close: usize,
) -> Option<bool> {
    let direct_attributes: &[&str] = match backend_type {
        "local" => &["path"],
        "s3" | "azurerm" | "oss" | "cos" => &["key"],
        "gcs" | "etcdv3" => &["prefix"],
        "consul" => &["path"],
        "pg" => &["schema_name"],
        "kubernetes" => &["secret_suffix"],
        "http" => &["address"],
        "remote" => return Some(remote_workspace_contains_state_key(tokens, open, close)),
        _ => return None,
    };
    Some(direct_attribute_contains(
        tokens,
        open,
        close,
        direct_attributes,
    ))
}

fn validate_backend_template(template: &str) -> Result<(), RunnerError> {
    let tokens = tokenize_backend_hcl(template)?;
    let mut backends = Vec::new();
    let mut index = 0usize;
    let mut root_depth = 0usize;

    while index + 1 < tokens.len() {
        let is_terraform = root_depth == 0
            && matches!(&tokens[index], BackendHclToken::Ident(name) if name == "terraform")
            && matches!(tokens.get(index + 1), Some(BackendHclToken::OpenBrace));
        if !is_terraform {
            match &tokens[index] {
                BackendHclToken::OpenBrace => root_depth += 1,
                BackendHclToken::CloseBrace => root_depth = root_depth.saturating_sub(1),
                _ => {}
            }
            index += 1;
            continue;
        }

        let terraform_open = index + 1;
        let terraform_close = matching_hcl_brace(&tokens, terraform_open).ok_or_else(|| {
            RunnerError::Spawn(
                "live Terraform backend template has an unterminated terraform block".to_string(),
            )
        })?;
        let mut depth = 0usize;
        let mut cursor = terraform_open + 1;
        while cursor < terraform_close {
            if depth == 0 {
                if let (
                    Some(BackendHclToken::Ident(name)),
                    Some(BackendHclToken::Quoted(backend_type)),
                    Some(BackendHclToken::OpenBrace),
                ) = (
                    tokens.get(cursor),
                    tokens.get(cursor + 1),
                    tokens.get(cursor + 2),
                ) {
                    if name == "backend" {
                        let backend_open = cursor + 2;
                        let backend_close = matching_hcl_brace(&tokens, backend_open).ok_or_else(
                            || {
                                RunnerError::Spawn(
                                    "live Terraform backend template has an unterminated backend block"
                                        .to_string(),
                                )
                            },
                        )?;
                        backends.push((backend_type.clone(), backend_open, backend_close));
                        cursor = backend_close + 1;
                        continue;
                    }
                }
            }

            match &tokens[cursor] {
                BackendHclToken::OpenBrace => depth += 1,
                BackendHclToken::CloseBrace => depth = depth.saturating_sub(1),
                _ => {}
            }
            cursor += 1;
        }
        index = terraform_close + 1;
    }

    let [(backend_type, open, close)] = backends.as_slice() else {
        return Err(RunnerError::Spawn(
            "live Terraform backend template must contain exactly one active terraform backend block"
                .to_string(),
        ));
    };

    if backend_type == "local" {
        let Some(path) = direct_attribute_value(&tokens, *open, *close, "path") else {
            return Err(RunnerError::Spawn(format!(
                "live Terraform {backend_type:?} backend state-location attribute must contain the exact {STATE_KEY_PLACEHOLDER} placeholder"
            )));
        };
        if !path.contains(STATE_KEY_PLACEHOLDER) {
            return Err(RunnerError::Spawn(format!(
                "live Terraform {backend_type:?} backend state-location attribute must contain the exact {STATE_KEY_PLACEHOLDER} placeholder"
            )));
        }
        if !Path::new(path).is_absolute() {
            return Err(RunnerError::Spawn(
                "live Terraform \"local\" backend path must be absolute so state persists across fresh workspaces"
                    .to_string(),
            ));
        }
        return Ok(());
    }

    match backend_location_contains_state_key(backend_type, &tokens, *open, *close) {
        Some(true) => Ok(()),
        Some(false) => Err(RunnerError::Spawn(format!(
            "live Terraform {backend_type:?} backend state-location attribute must contain the exact {STATE_KEY_PLACEHOLDER} placeholder"
        ))),
        None => Err(RunnerError::Spawn(format!(
            "live Terraform backend type {backend_type:?} is unsupported because its state-location attribute cannot be proven isolated"
        ))),
    }
}

/// A backend HCL config whose state-key placeholder has been safely rendered.
///
/// The fields stay private so live Terraform callers cannot bypass
/// [`IsolatedBackendConfig::from_template`] with arbitrary shared backend HCL.
pub struct IsolatedBackendConfig {
    hcl: String,
    state_key: String,
}

impl IsolatedBackendConfig {
    /// Render an operator backend-HCL template for one control-plane state key.
    ///
    /// The key is deliberately restricted to an ASCII identifier alphabet so
    /// substitution is safe inside a quoted HCL path/key/schema value. The
    /// backend's active state-location attribute must contain the exact
    /// placeholder; comments and unrelated attributes do not establish isolation.
    /// A local backend path must also be absolute so it survives the separate
    /// temporary workspaces used by plan, apply, and destroy.
    pub fn from_template(template: &str, state_key: &str) -> Result<Self, RunnerError> {
        validate_state_key(state_key)?;
        validate_backend_template(template)?;

        Ok(Self {
            hcl: template.replace(STATE_KEY_PLACEHOLDER, state_key),
            state_key: state_key.to_string(),
        })
    }

    /// The validated control-plane key represented by this backend config.
    pub fn state_key(&self) -> &str {
        &self.state_key
    }
}

fn validate_state_key(state_key: &str) -> Result<(), RunnerError> {
    let safe = !state_key.is_empty()
        && state_key.len() <= 128
        && state_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if !safe {
        return Err(RunnerError::Spawn(
            "live Terraform state key must be 1..=128 ASCII letters, digits, '-' or '_'; \
             refusing unsafe backend substitution"
                .to_string(),
        ));
    }
    Ok(())
}

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
    backend_config: &IsolatedBackendConfig,
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
    backend_config: &IsolatedBackendConfig,
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

/// Execute a live Terraform destroy of a step's applied resources (#42 B2-3).
///
/// ## Workspace/state reconstruction — which resources get destroyed
///
/// A destroy has NO saved plan artifact. `terraform destroy` computes the
/// destruction set from the STATE, so this function must attach to exactly the
/// state the step's apply produced. It does that by reconstructing the SAME
/// workspace inputs `run_live_apply` used: the offering's embedded IaC bundle,
/// the operator's `backend_config` HCL (written as `backend_override.tf`
/// before init), and the job vars. `terraform init` with the same backend HCL
/// connects to the same durable state backend — the state, not the (ephemeral
/// TempDir) workspace, is the source of truth for what exists and therefore
/// for what gets destroyed.
///
/// The agent instantiates the same backend template with the step's stable
/// state key for plan, apply, and destroy, so every phase attaches to exactly
/// one state lineage. This API requires an [`IsolatedBackendConfig`]; there is
/// no local-state fallback for live Terraform.
///
/// ## `-auto-approve` — deliberate difference from apply
///
/// `run_live_apply` intentionally omits `-auto-approve`: it applies a SAVED,
/// digest-gated `tfplan` file, which terraform applies without prompting.
/// Destroy has no saved plan to hand terraform, so `terraform destroy` re-plans
/// the destruction at run time and — without `-auto-approve` — prompts for
/// interactive confirmation, which `-input=false` turns into a hard failure.
/// `-auto-approve` is therefore REQUIRED here. It does not bypass any Ryuki
/// gate: the human-approval equivalent for a destroy is the CP-signed,
/// step-bound `LiveDestroy` grant that the agent gate (`evaluate_live_destroy`)
/// verifies BEFORE this function is ever invoked. Callers MUST keep that gate
/// as the only path to this function.
///
/// Returns `Ok(RunOutcome)` with status `Applied` on success (exit 0 — the
/// protocol has no dedicated "Destroyed" status; the job MODE `LiveDestroy`
/// identifies the operation and the CP maps a successful result to the step
/// status `ToreDown`), `Failed` on non-zero exit, or `RunnerUnavailable` when
/// terraform is absent.
///
/// # Errors
///
/// Same conditions as `run_live_plan` / `run_live_apply` (mode guard, missing
/// IaC, invalid slug/var names, workspace setup, subprocess timeout).
pub fn run_live_destroy(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
) -> Result<RunOutcome, RunnerError> {
    if plan.mode != RunMode::Live {
        return Err(RunnerError::Spawn(format!(
            "run_live_destroy only accepts RunMode::Live; got {:?}",
            plan.mode
        )));
    }

    live_terraform_destroy(DEFAULT_BINARY, plan, creds, backend_config)
}

// ---------------------------------------------------------------------------
// Internal implementations (take binary path for test injection)
// ---------------------------------------------------------------------------

/// Canonicalize `terraform show -json` output so its SHA-256 digest is DETERMINISTIC
/// across re-plans of identical config.
///
/// `terraform show -json` embeds a top-level `"timestamp"` (the moment the plan was
/// generated). Two `plan` runs of byte-identical config therefore produce different
/// JSON and different digests. Because the LiveApply gate re-plans and compares its
/// digest to the LivePlan's operator-approved digest, that non-determinism makes EVERY
/// live apply refuse ("plan does not match approved plan") even when nothing changed —
/// live-apply is unusable without this normalization.
///
/// We strip ONLY the top-level `timestamp` (which has no bearing on WHAT terraform will
/// apply). Every semantic field — `resource_changes`, `planned_values`, `configuration`,
/// `variables`, `output_changes`, … — stays in the digest, so the plan-integrity
/// guarantee is fully preserved (a real change to the plan still changes the digest).
///
/// The values are kept as `RawValue` (their exact original JSON bytes) rather than parsed
/// into `serde_json::Value`: reparsing numbers into `Value` (without `arbitrary_precision`)
/// can collapse distinct high-precision JSON numbers to the same `f64`, which would let two
/// plans that differ only in such a value canonicalize to the SAME digest — WEAKENING the
/// gate. `RawValue` is lossless. The top-level keys are ordered by `BTreeMap`, which makes
/// the output deterministic regardless of terraform's emission order.
///
/// Returns `None` when the input is not valid JSON. The caller treats that as a
/// hard `Failed` (fail-closed): a non-canonical plan must never reach the digest
/// layer, because digesting raw bytes would either be non-deterministic (the
/// un-stripped `timestamp` differs on every re-plan, so every apply is refused)
/// or — for output that was truncated before it arrived — collide across plans
/// that differ only past the cut point.
fn canonicalize_plan_json(raw: &str) -> Option<String> {
    use serde_json::value::RawValue;
    use std::collections::BTreeMap;
    match serde_json::from_str::<BTreeMap<String, &RawValue>>(raw) {
        Ok(mut members) => {
            members.remove("timestamp");
            serde_json::to_string(&members).ok()
        }
        Err(_) => None,
    }
}

/// Pre-execution policy gate (#11): refuse a LIVE run whose resolved IaC bundle
/// contains constructs that are unsafe even under `plan`/`--check` — Terraform
/// provisioners and `data "external"` (arbitrary code at plan time), Ansible
/// `check_mode: false` / `raw` / `script`, or content the scanner cannot attribute.
///
/// Returns `Some(refusal outcome)` to short-circuit BEFORE any workspace, init,
/// or provider contact, or `None` when the bundle is clean. The digest/tfplan are
/// never produced for a refused bundle. `OfflineDryRun` is never gated (it
/// configures no providers and touches nothing), so this is only invoked from the
/// live paths. Modelled as `Failed` (the run did not proceed); the summary carries
/// the policy version + the specific violations for evidence.
pub(crate) fn iac_policy_refusal(
    iac_files: &super::iac::IacBundle,
    runner_kind: RunnerKind,
    mode: RunMode,
) -> Option<RunOutcome> {
    let violations = ryuki_engine::iac_policy::evaluate_iac_bundle(iac_files.iter().copied());
    if violations.is_empty() {
        return None;
    }
    let detail = violations
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    Some(RunOutcome {
        runner_kind,
        mode,
        status: RunStatus::Failed,
        summary: format!(
            "POLICY-REFUSED ({}): unsafe IaC construct(s) forbidden before live execution: {detail}",
            ryuki_engine::iac_policy::IAC_POLICY_VERSION
        ),
        log: String::new(),
        exit_code: None,
        post_apply: None,
    })
}

/// Core plan implementation.  `binary` is injectable for tests (e.g. `/bin/echo`).
///
/// Returns `Planned` ONLY when init exit==0, plan exit==0 or 2, and show
/// exit==0.  Any earlier failure returns `Failed` (fail-closed — no partial
/// plan reaches the digest layer).
pub(crate) fn live_terraform_plan(
    binary: &str,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
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

    // #11 policy gate: refuse unsafe constructs BEFORE init/providers/plan.
    if let Some(refusal) = iac_policy_refusal(&iac_files, RunnerKind::Terraform, plan.mode) {
        return Ok(LivePlanArtifacts {
            outcome: refusal,
            tfplan: vec![],
        });
    }

    // Build secret components for scrubbing.
    let components = credential_components(creds.material.as_slice());

    // FAIL CLOSED: declared secret vars must pair 1:1 with resolved components
    // BEFORE any workspace or terraform subprocess exists.
    if let Some(err) = credential_arity_error(plan, &components) {
        return Err(err);
    }

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
                post_apply: None,
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

    // 0600: backend HCL routinely carries state-backend credentials
    // (Postgres DSN, S3/Consul tokens) — owner-only, like the vars file.
    ws.write_file_0600("backend_override.tf", backend_config.hcl.as_bytes())?;

    // Write non-secret vars.
    if !plan.vars.is_empty() {
        let vars_json = vars_to_json(&plan.vars);
        ws.write_file_0600("ryuki.auto.tfvars.json", vars_json.as_bytes())?;
    }

    // --- Step 1: terraform init ---
    // FAIL CLOSED: non-zero exit → Failed, no digest computed.
    let init_outcome = run_tf_step(
        binary,
        TERRAFORM_INIT_ARGS,
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        true,
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
                post_apply: None,
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
        true,
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
                    post_apply: None,
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
        false, // digest input — must NOT be truncated
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
                post_apply: None,
            },
            tfplan: vec![],
        });
    }

    // The show output is the canonical plan JSON used for digest computation.
    // Canonicalize FIRST (strip terraform's non-deterministic `timestamp`) so a
    // LiveApply re-plan of identical config produces the SAME digest as the approved
    // LivePlan — without this the plan-integrity gate refuses every live apply.
    // `show_outcome.log` is UNtruncated (step 3 passed `truncate=false`) so the
    // digest covers the whole plan; unparseable JSON fails closed rather than
    // digesting non-canonical bytes.
    let plan_json = match canonicalize_plan_json(&show_outcome.log) {
        Some(json) => json,
        None => {
            return Ok(LivePlanArtifacts {
                outcome: RunOutcome {
                    runner_kind: RunnerKind::Terraform,
                    mode: plan.mode,
                    status: RunStatus::Failed,
                    summary: "terraform show produced non-canonical plan JSON — \
                              refusing to derive a plan-integrity digest"
                        .to_string(),
                    // Truncate the (untruncated) show output for the failure log
                    // only — it is diagnostic here, not a digest input.
                    log: truncate_log(&show_outcome.log),
                    exit_code: show_outcome.exit_code,
                    post_apply: None,
                },
                tfplan: vec![],
            });
        }
    };
    let plan_summary = extract_plan_summary(&plan_step.log);

    Ok(LivePlanArtifacts {
        outcome: RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: plan.mode,
            status: RunStatus::Planned,
            summary: plan_summary,
            log: plan_json,
            exit_code: show_outcome.exit_code,
            post_apply: None,
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
    backend_config: &IsolatedBackendConfig,
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

    // #11 policy gate: refuse unsafe constructs BEFORE init/providers/apply.
    if let Some(refusal) = iac_policy_refusal(&iac_files, RunnerKind::Terraform, plan.mode) {
        return Ok(refusal);
    }

    // Secret scrubbing components.
    let components = credential_components(creds.material.as_slice());

    // FAIL CLOSED: declared secret vars must pair 1:1 with resolved components
    // BEFORE any workspace or terraform subprocess exists.
    if let Some(err) = credential_arity_error(plan, &components) {
        return Err(err);
    }

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
            post_apply: None,
        });
    }

    // --- Workspace setup (fresh — no state from the plan workspace) ---
    let ws = Workspace::new()?;

    for (filename, content) in &iac_files {
        ws.write_file(filename, content.as_bytes())?;
    }

    // 0600: backend HCL routinely carries state-backend credentials
    // (Postgres DSN, S3/Consul tokens) — owner-only, like the vars file.
    ws.write_file_0600("backend_override.tf", backend_config.hcl.as_bytes())?;

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
        TERRAFORM_INIT_ARGS,
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        true,
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
            post_apply: None,
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
        true,
    )?;

    let (status, summary, post_apply) = match apply_outcome.exit_code {
        Some(0) => {
            let base = extract_apply_summary(&apply_outcome.log);
            // #43 post-apply verification: re-plan in the SAME (post-apply)
            // workspace and classify convergence. A converged apply re-plans to
            // "No changes"; a pending change is drift (the apply did not fully
            // take). This is ADVISORY — the apply already succeeded, so status
            // stays Applied and a re-plan failure never downgrades it; the verdict
            // is surfaced in the summary for humans AND carried as a structured
            // field for the CP to act on (transition to Verified / emit a drift
            // event) without string-parsing.
            let verdict = post_apply_verdict(
                binary,
                ws.path(),
                &plan.secret_var_names,
                &cred_str,
                &secret_refs,
            );
            (
                RunStatus::Applied,
                format!("{base} | post-apply: {}", post_apply_label(verdict)),
                Some(verdict),
            )
        }
        code => (
            RunStatus::Failed,
            format!("terraform apply failed (exit {})", code.unwrap_or(-1)),
            None,
        ),
    };

    Ok(RunOutcome {
        runner_kind: RunnerKind::Terraform,
        mode: plan.mode,
        status,
        summary,
        log: apply_outcome.log,
        exit_code: apply_outcome.exit_code,
        post_apply,
    })
}

/// Run a post-apply `terraform plan` in the applied workspace and classify
/// convergence via the pure engine core. A plan that cannot run (non-zero exit,
/// spawn error) yields `Inconclusive` — never a false `Verified`. `terraform
/// plan` (no `-detailed-exitcode`) exits 0 whether or not changes are pending, so
/// the verdict is read from the plan SUMMARY, not the exit code.
fn post_apply_verdict(
    binary: &str,
    ws_path: &std::path::Path,
    secret_names: &[String],
    cred_str: &str,
    secret_refs: &[&[u8]],
) -> ryuki_engine::post_apply::PostApplyOutcome {
    use ryuki_engine::post_apply::{classify_post_apply, PostApplyOutcome};
    match run_tf_step(
        binary,
        &["plan", "-input=false", "-no-color"],
        ws_path,
        secret_names,
        cred_str,
        secret_refs,
        true,
    ) {
        Ok(re) if re.exit_code == Some(0) => classify_post_apply(&extract_plan_summary(&re.log)),
        _ => PostApplyOutcome::Inconclusive,
    }
}

/// Human-readable label for a post-apply verdict, folded into the apply summary.
fn post_apply_label(verdict: ryuki_engine::post_apply::PostApplyOutcome) -> &'static str {
    use ryuki_engine::post_apply::PostApplyOutcome;
    match verdict {
        PostApplyOutcome::Verified => "verified (converged)",
        PostApplyOutcome::DriftDetected => "drift detected",
        PostApplyOutcome::Inconclusive => "inconclusive",
    }
}

/// Core destroy implementation (#42 B2-3).  `binary` is injectable for tests.
///
/// Mirrors `live_terraform_apply`'s structure step for step (validation → IaC
/// resolve → #11 policy gate → availability probe → workspace → init → run),
/// with two deliberate differences documented on `run_live_destroy`:
/// no saved-plan artifact (the destruction set comes from the backend STATE the
/// step's apply wrote) and `-auto-approve` on the destroy step (required —
/// there is no plan file to carry the approval; the Ryuki approval is the
/// step-bound CP grant checked by the agent gate before this runs).
///
/// The #11 policy gate stays in force for destroy: `terraform destroy` still
/// evaluates the configuration, and `when = destroy` provisioners execute
/// during it — an unsafe bundle must be refused before init, exactly as on the
/// plan/apply paths.
pub(crate) fn live_terraform_destroy(
    binary: &str,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
) -> Result<RunOutcome, RunnerError> {
    // Validate inputs before any workspace or process creation.
    validate_offering_slug(&plan.offering_id)?;
    for name in &plan.secret_var_names {
        validate_var_name(name)?;
    }

    // Resolve IaC — FAIL CLOSED. The destroy needs the SAME configuration the
    // apply ran (providers, backend, variable declarations) so terraform can
    // evaluate it against the state; an unresolvable bundle must refuse rather
    // than destroy from an empty workspace.
    let iac_files = super::iac::resolve(&plan.offering_id).ok_or_else(|| {
        RunnerError::Spawn(format!(
            "no embedded Terraform IaC for offering '{}' — \
             refusing to run an empty live workspace",
            plan.offering_id
        ))
    })?;

    // #11 policy gate: refuse unsafe constructs BEFORE init/providers/destroy.
    if let Some(refusal) = iac_policy_refusal(&iac_files, RunnerKind::Terraform, plan.mode) {
        return Ok(refusal);
    }

    // Secret scrubbing components.
    let components = credential_components(creds.material.as_slice());

    // FAIL CLOSED: declared secret vars must pair 1:1 with resolved components
    // BEFORE any workspace or terraform subprocess exists.
    if let Some(err) = credential_arity_error(plan, &components) {
        return Err(err);
    }

    let secret_refs: Vec<&[u8]> = components.iter().map(|v| v.as_slice()).collect();
    let cred_str = std::str::from_utf8(creds.material.as_slice())
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Binary availability check — terraform-absent-safe.
    if !binary_available(binary) {
        return Ok(RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: plan.mode,
            status: RunStatus::RunnerUnavailable,
            summary: format!("runner unavailable: terraform binary not found at '{binary}'"),
            log: String::new(),
            exit_code: None,
            post_apply: None,
        });
    }

    // --- Workspace setup (fresh TempDir — the state lives in the backend) ---
    // Reconstruct the SAME workspace inputs the apply used: IaC bundle +
    // operator backend HCL + job vars. `terraform init` with the same backend
    // attaches to the same state — that state defines what gets destroyed.
    let ws = Workspace::new()?;

    for (filename, content) in &iac_files {
        ws.write_file(filename, content.as_bytes())?;
    }

    // 0600: backend HCL routinely carries state-backend credentials
    // (Postgres DSN, S3/Consul tokens) — owner-only, like the vars file.
    ws.write_file_0600("backend_override.tf", backend_config.hcl.as_bytes())?;

    if !plan.vars.is_empty() {
        let vars_json = vars_to_json(&plan.vars);
        ws.write_file_0600("ryuki.auto.tfvars.json", vars_json.as_bytes())?;
    }

    // --- Step 1: terraform init ---
    // FAIL CLOSED: non-zero exit → Failed, destroy is never attempted.
    let init_outcome = run_tf_step(
        binary,
        TERRAFORM_INIT_ARGS,
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        true,
    )?;

    if init_outcome.exit_code != Some(0) {
        return Ok(RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: plan.mode,
            status: RunStatus::Failed,
            summary: format!(
                "terraform init failed before destroy (exit {})",
                init_outcome.exit_code.unwrap_or(-1)
            ),
            log: init_outcome.log,
            exit_code: init_outcome.exit_code,
            post_apply: None,
        });
    }

    // --- Step 2: terraform destroy -input=false -auto-approve ---
    // `-auto-approve` is REQUIRED here and is a deliberate difference from the
    // apply step: apply consumes a saved, digest-gated tfplan file (terraform
    // does not prompt for a saved plan, so apply omits the flag); destroy has
    // no plan artifact — terraform re-plans the destruction from state and,
    // without the flag, demands interactive confirmation, which `-input=false`
    // turns into a hard failure. The approval for a destroy is NOT this flag:
    // it is the CP-signed, step-bound LiveDestroy grant the agent gate verified
    // before invoking the runner.
    let destroy_outcome = run_tf_step(
        binary,
        &["destroy", "-input=false", "-no-color", "-auto-approve"],
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        true,
    )?;

    // Exit 0 → Applied (the protocol has no dedicated "Destroyed" run status;
    // the LiveDestroy job MODE identifies the operation, and the CP maps a
    // successful LiveDestroy result to step status `ToreDown`). Non-zero →
    // Failed, which HALTS the CP-side teardown cascade. No post-apply verdict:
    // that re-plan convergence check is an apply-specific (#43) concern.
    let (status, summary) = match destroy_outcome.exit_code {
        Some(0) => (
            RunStatus::Applied,
            extract_destroy_summary(&destroy_outcome.log),
        ),
        code => (
            RunStatus::Failed,
            format!("terraform destroy failed (exit {})", code.unwrap_or(-1)),
        ),
    };

    Ok(RunOutcome {
        runner_kind: RunnerKind::Terraform,
        mode: plan.mode,
        status,
        summary,
        log: destroy_outcome.log,
        exit_code: destroy_outcome.exit_code,
        post_apply: None,
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
        .stderr(std::process::Stdio::null());
    // Retry the probe on transient ETXTBSY: tests probe a just-written shim, and
    // a concurrent fork() can briefly hold a write fd to it (see exec.rs).
    crate::exec::retry_on_etxtbsy(|| cmd.status())
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Intermediate result from a single terraform sub-command.
struct TfStepResult {
    log: String,
    exit_code: Option<i32>,
}

/// Map each DECLARED secret var name to the env vars injected on the child.
///
/// `secret_names` come from the offering's declaration
/// (`iac::live_secret_var_names`); `cred_str` is the comma-joined resolved
/// material in DECLARED ORDER (the encoding `resolve_creds` produces and
/// `credential_components` splits for scrubbing). Pass empty slices/string
/// when no credential injection is needed.
///
/// For every `(name_i, value_i)` pair this yields TWO env entries carrying the
/// SAME value:
/// - `<NAME>` verbatim — the provider-native env var the offering declared
///   (e.g. `VSPHERE_USER`, which the terraform vsphere provider reads);
/// - `TF_VAR_<name lowercased>` — the terraform input-variable form for
///   bundles that route the credential through a declared `variable` block
///   (the vsphere bundles reference `var.vsphere_user` / `var.vsphere_password`
///   / `var.vsphere_server` in the provider block, so this alias is the
///   load-bearing one there).
///
/// Both names derive strictly from the declaration — no undeclared credential
/// can flow — and both values are scrubbed from all output. Callers enforce
/// name↔component arity up front (`credential_arity_error`), so the zip here
/// can never mis-pair; a var with no matching component would be left unset
/// and terraform would fail closed on the missing required variable.
///
/// BUG FIXED (historical): earlier code set `TF_VAR_<name> = <whole joined
/// string>` for EVERY name, so a multi-credential offering got ALL credentials
/// concatenated into EVERY var. The zip maps each name to ITS OWN value.
fn secret_env_pairs(secret_names: &[String], cred_str: &str) -> Vec<(String, String)> {
    if secret_names.is_empty() || cred_str.is_empty() {
        return Vec::new();
    }
    let mut pairs = Vec::with_capacity(secret_names.len() * 2);
    for (name, value) in secret_names.iter().zip(cred_str.split(',')) {
        pairs.push((name.clone(), value.to_string()));
        pairs.push((format!("TF_VAR_{}", name.to_lowercase()), value.to_string()));
    }
    pairs
}

/// FAIL-CLOSED credential arity gate: a live run whose offering declares
/// secret vars must receive EXACTLY one resolved credential component per
/// declared name, or terraform is never invoked.
///
/// Without this, a partially-resolved credential string would silently leave
/// trailing declared vars unset (or mis-pair values) and terraform would reach
/// out to the real provider with wrong/absent credentials. The error message
/// carries the VARIABLE NAMES and counts only — NEVER a credential value.
fn credential_arity_error(plan: &RunPlan, components: &[Vec<u8>]) -> Option<RunnerError> {
    if plan.secret_var_names.is_empty() || components.len() == plan.secret_var_names.len() {
        return None;
    }
    Some(RunnerError::CredInjection(format!(
        "live run for offering '{}' declares {} secret var(s) [{}] but the resolved \
         credential material has {} component(s) — refusing to invoke terraform with \
         mis-paired credentials",
        plan.offering_id,
        plan.secret_var_names.len(),
        plan.secret_var_names.join(", "),
        components.len()
    )))
}

fn run_tf_step(
    binary: &str,
    args: &[&str],
    ws_path: &std::path::Path,
    secret_names: &[String],
    cred_str: &str,
    secret_refs: &[&[u8]],
    truncate: bool,
) -> Result<TfStepResult, RunnerError> {
    let mut cmd = Command::new(binary);
    apply_env_allowlist(&mut cmd);
    pin_home_tmpdir_to_workspace(&mut cmd, ws_path);
    cmd.args(args)
        .current_dir(ws_path)
        .env("CHECKPOINT_DISABLE", "1")
        .env_remove("TF_LOG");

    for (env_key, value) in secret_env_pairs(secret_names, cred_str) {
        cmd.env(&env_key, value);
    }

    let output = run_command_with_timeout(cmd, LIVE_RUNNER_TIMEOUT)?;

    let raw = combine_output(&output.stdout, &output.stderr);
    // Human-readable diagnostic logs (init/plan/apply) are truncated to bound
    // evidence size. The `terraform show -json` step passes `truncate=false`
    // because its output is the plan-integrity digest input — truncating it
    // would let two plans differing only past 32 KiB collide (see
    // `live_terraform_plan` step 3).
    let scrubbed = if truncate {
        scrub_output(&raw, secret_refs)
    } else {
        scrub(&raw, secret_refs)
    };

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

/// Extract a one-line destroy summary from scrubbed terraform output.
/// Terraform prints `Destroy complete! Resources: N destroyed.` on success;
/// an already-empty state yields either `No changes.` or `Destroy complete!
/// Resources: 0 destroyed.` depending on the terraform version.
fn extract_destroy_summary(log: &str) -> String {
    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Destroy complete!") || trimmed.starts_with("No changes.") {
            return trimmed.to_string();
        }
    }
    "terraform destroy completed".to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_STATE_KEY: AtomicU64 = AtomicU64::new(1);

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

    fn test_backend() -> IsolatedBackendConfig {
        let key = format!("test-{}", NEXT_STATE_KEY.fetch_add(1, Ordering::Relaxed));
        let template = format!(
            "terraform {{\n  backend \"local\" {{\n    path = \"{}/ryuki-runner-state-{{STATE_KEY}}.tfstate\"\n  }}\n}}",
            std::env::temp_dir().display()
        );
        IsolatedBackendConfig::from_template(&template, &key)
            .expect("test backend template is valid")
    }

    // -----------------------------------------------------------------------
    // #11 IaC policy gate
    // -----------------------------------------------------------------------

    #[test]
    fn iac_policy_refusal_none_for_clean_bundle() {
        let clean: super::super::iac::IacBundle =
            vec![("main.tf", "resource \"null_resource\" \"ok\" {}\n")];
        assert!(
            iac_policy_refusal(&clean, RunnerKind::Terraform, RunMode::Live).is_none(),
            "a clean bundle must not be refused"
        );
    }

    #[test]
    fn iac_policy_refusal_blocks_provisioner_bundle() {
        let dirty: super::super::iac::IacBundle = vec![(
            "main.tf",
            "resource \"null_resource\" \"x\" {\n  provisioner \"local-exec\" { command = \"id\" }\n}\n",
        )];
        let refusal = iac_policy_refusal(&dirty, RunnerKind::Terraform, RunMode::Live)
            .expect("a provisioner bundle must be refused");
        assert_eq!(refusal.status, RunStatus::Failed);
        assert!(
            refusal.summary.contains("POLICY-REFUSED"),
            "refusal summary must be tagged: {}",
            refusal.summary
        );
        assert!(
            refusal.summary.contains("provisioner"),
            "refusal summary must name the violation: {}",
            refusal.summary
        );
        // Fail-closed: no plan/tfplan bytes are produced for a refused bundle.
        assert!(refusal.log.is_empty());
        assert!(refusal.exit_code.is_none());
    }

    // -----------------------------------------------------------------------
    // Real-terraform end-to-end (skipped when the binary is absent)
    // -----------------------------------------------------------------------

    /// Drives the REAL `terraform` binary through the live PLAN path on the
    /// provider-less `request-preflight` bundle (terraform_data only, no network,
    /// no external infra). Validates, end-to-end on genuine terraform output:
    /// (1) the #11 policy gate lets a clean bundle through (Planned, not
    /// POLICY-REFUSED); (2) the slice-1 digest fix — the canonical digest input is
    /// the FULL show-json with the non-deterministic top-level `timestamp`
    /// stripped, so two re-plans of identical config produce an IDENTICAL digest
    /// input (the property the live-apply gate relies on). Apply is not exercised
    /// here: `terraform apply tfplan` needs plan and apply to share a durable
    /// backend (state lineage), which is the operator-provided backend_config in
    /// production, not a hermetic unit test.
    #[test]
    fn real_terraform_live_plan_e2e_is_deterministic_and_gate_clean() {
        if !binary_available("terraform") {
            eprintln!("SKIP: terraform binary not found");
            return;
        }
        let plan = live_plan("request-preflight");
        let backend = test_backend();
        let a1 = live_terraform_plan("terraform", &plan, &dummy_creds(), &backend)
            .expect("live plan must not error");
        if a1.outcome.status == RunStatus::RunnerUnavailable {
            eprintln!("SKIP: terraform reported unavailable");
            return;
        }
        assert_eq!(
            a1.outcome.status,
            RunStatus::Planned,
            "clean bundle must pass the gate and plan cleanly; summary: {}",
            a1.outcome.summary
        );
        assert!(
            !a1.outcome.summary.contains("POLICY-REFUSED"),
            "clean bundle must not be policy-refused"
        );
        assert!(!a1.tfplan.is_empty(), "a saved tfplan must be produced");

        // The digest input is the FULL canonical plan JSON (slice-1 fix).
        let parsed: serde_json::Value =
            serde_json::from_str(&a1.outcome.log).expect("canonical plan JSON must parse");
        assert!(
            parsed.get("timestamp").is_none(),
            "the non-deterministic top-level timestamp must be stripped"
        );
        assert!(
            a1.outcome.log.contains("resource_changes"),
            "semantic plan content must be preserved in the digest input"
        );

        // Determinism: a second identical plan yields the SAME canonical digest
        // input despite terraform stamping a fresh timestamp each run.
        let a2 = live_terraform_plan("terraform", &plan, &dummy_creds(), &backend)
            .expect("second live plan must not error");
        assert_eq!(
            a1.outcome.log, a2.outcome.log,
            "canonical digest input must be identical across re-plans of identical config"
        );
    }

    // -----------------------------------------------------------------------
    // Mode guard
    // -----------------------------------------------------------------------

    #[test]
    fn run_live_plan_rejects_dry_run_mode() {
        let mut plan = live_plan("patch-maintenance");
        plan.mode = RunMode::DryRun;
        let result = run_live_plan(&plan, &dummy_creds(), &test_backend());
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
        let result = run_live_apply(&plan, &dummy_creds(), &test_backend(), b"fake-plan");
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
        let result = run_live_plan(&plan, &dummy_creds(), &test_backend());
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
        let result = run_live_apply(&plan, &dummy_creds(), &test_backend(), b"fake-plan");
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
            &test_backend(),
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
            &test_backend(),
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

    #[test]
    fn backend_template_renders_distinct_keys_and_reuses_one_key_exactly() {
        let template =
            "terraform { backend \"local\" { path = \"/var/lib/ryuki/terraform-{STATE_KEY}.tfstate\" } }";
        let request_a = IsolatedBackendConfig::from_template(template, "request-a").unwrap();
        let request_b = IsolatedBackendConfig::from_template(template, "request-b").unwrap();
        assert_ne!(request_a.hcl, request_b.hcl);
        assert!(request_a.hcl.contains("terraform-request-a.tfstate"));
        assert!(request_b.hcl.contains("terraform-request-b.tfstate"));

        let plan = IsolatedBackendConfig::from_template(template, "step-one").unwrap();
        let apply = IsolatedBackendConfig::from_template(template, "step-one").unwrap();
        let destroy = IsolatedBackendConfig::from_template(template, "step-one").unwrap();
        assert_eq!(plan.hcl, apply.hcl);
        assert_eq!(apply.hcl, destroy.hcl);
        assert_eq!(plan.state_key(), "step-one");
        assert!(!plan.hcl.contains(STATE_KEY_PLACEHOLDER));
    }

    #[test]
    fn backend_template_fails_closed_without_placeholder_or_with_unsafe_key() {
        let fixed = "terraform { backend \"local\" { path = \"shared.tfstate\" } }";
        assert!(IsolatedBackendConfig::from_template(fixed, "request-a").is_err());

        let template = "# state {STATE_KEY}";
        for unsafe_key in ["", "../shared", "request/a", "quoted\"key", "space key"] {
            assert!(
                IsolatedBackendConfig::from_template(template, unsafe_key).is_err(),
                "unsafe state key must be rejected: {unsafe_key:?}"
            );
        }
    }

    #[test]
    fn backend_template_ignores_placeholders_outside_active_location() {
        let in_comment = r#"terraform {
  # path = "state-{STATE_KEY}.tfstate"
  backend "local" { path = "shared.tfstate" }
}"#;
        let unrelated_attribute = r#"terraform {
  backend "local" {
    path = "shared.tfstate"
    description = "state-{STATE_KEY}"
  }
}"#;
        let sibling_block = r#"terraform {
  backend "local" { path = "shared.tfstate" }
}
resource "terraform_data" "decoy" {
  input = "{STATE_KEY}"
}"#;

        for template in [in_comment, unrelated_attribute, sibling_block] {
            assert!(
                IsolatedBackendConfig::from_template(template, "request-a").is_err(),
                "non-location placeholder must not prove isolation: {template}"
            );
        }
    }

    #[test]
    fn backend_template_accepts_backend_specific_state_locations() {
        let local = r#"terraform { backend "local" { path = "/var/lib/ryuki/state-{STATE_KEY}.tfstate" } }"#;
        let s3 = r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" region = "eu-west-1" } }"#;
        let pg = r#"terraform { backend "pg" { conn_str = "postgresql://localhost/state" schema_name = "{STATE_KEY}" } }"#;
        let remote = r#"terraform { backend "remote" { organization = "example" workspaces { name = "{STATE_KEY}" } } }"#;

        for template in [local, s3, pg, remote] {
            assert!(
                IsolatedBackendConfig::from_template(template, "request-a").is_ok(),
                "active backend location should prove isolation: {template}"
            );
        }
    }

    #[test]
    fn backend_template_rejects_relative_local_state_paths() {
        for path in [
            "state-{STATE_KEY}.tfstate",
            "./state-{STATE_KEY}.tfstate",
            "states/{STATE_KEY}.tfstate",
        ] {
            let template = format!(r#"terraform {{ backend "local" {{ path = "{path}" }} }}"#);
            let error = match IsolatedBackendConfig::from_template(&template, "request-a") {
                Ok(_) => panic!("relative local state path must be rejected: {path}"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains("must be absolute"),
                "error must explain the persistence requirement: {error}"
            );
        }
    }

    #[test]
    fn backend_template_rejects_unknown_backend_and_multiple_backends() {
        let unknown = r#"terraform { backend "future" { path = "state-{STATE_KEY}.tfstate" } }"#;
        let nested_decoy = r#"
resource "terraform_data" "decoy" {
  terraform { backend "local" { path = "state-{STATE_KEY}.tfstate" } }
}
"#;
        let multiple = r#"
terraform { backend "local" { path = "one-{STATE_KEY}.tfstate" } }
terraform { backend "local" { path = "two-{STATE_KEY}.tfstate" } }
"#;
        assert!(IsolatedBackendConfig::from_template(unknown, "request-a").is_err());
        assert!(IsolatedBackendConfig::from_template(nested_decoy, "request-a").is_err());
        assert!(IsolatedBackendConfig::from_template(multiple, "request-a").is_err());
    }

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
    schema_name = "{STATE_KEY}"
  }
}"#;
        let backend = IsolatedBackendConfig::from_template(backend_hcl, "request-test")
            .expect("backend template");
        // Binary absent → RunnerUnavailable, but no error from backend_config write.
        let result = live_terraform_plan(
            "/nonexistent/terraform-fake-live-backend",
            &plan,
            &dummy_creds(),
            &backend,
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
        let backend = test_backend();
        let result = live_terraform_apply(
            "/nonexistent/terraform-fake-live-backend-apply",
            &plan,
            &dummy_creds(),
            &backend,
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
        let probe_dir = ws_probe.path().to_string_lossy();
        // The shim writes a stub tfplan file on every invocation (in case this
        // invocation is the plan step) and exits 0.
        // `show -json` must emit valid JSON — the digest layer now fails closed
        // on non-canonical plan output. Other steps just list files and exit 0.
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{probe_dir}/args-$1\"\nif [ \"$1\" = show ]; then echo '{{\"format_version\":\"1.2\",\"resource_changes\":[]}}'; exit 0; fi\ntouch \"$PWD/tfplan\"\nls\nexit 0\n"
            ),
        )
        .expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_plan("patch-maintenance");
        let result = live_terraform_plan(
            &shim.to_string_lossy(),
            &plan,
            &dummy_creds(),
            &test_backend(),
        );
        // The shim exits 0 for all steps and writes the tfplan stub → Planned.
        assert!(result.is_ok(), "shim-based plan must not error: {result:?}");
        let artifacts = result.unwrap();
        assert_eq!(
            artifacts.outcome.status,
            RunStatus::Planned,
            "shim exits 0 → Planned; got: {:?}",
            artifacts.outcome.status
        );
        let init_args = std::fs::read_to_string(ws_probe.path().join("args-init"))
            .expect("live init argv must be captured");
        assert_eq!(
            init_args.lines().collect::<Vec<_>>(),
            ["init", "-input=false", "-lockfile=readonly"]
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
        let result = live_terraform_plan(
            &shim.to_string_lossy(),
            &plan,
            &dummy_creds(),
            &test_backend(),
        );
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
            &test_backend(),
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
    // #43 post-apply verification: the post-apply re-plan verdict is folded into
    // the apply summary (Applied either way; verdict is advisory).
    // -----------------------------------------------------------------------

    #[test]
    fn apply_folds_post_apply_verdict_into_summary() {
        // A shim whose post-apply `plan` output is parameterized by env so one
        // helper drives both the converged (verified) and drift verdicts.
        let build = |plan_output: &str, tag: &str| {
            let ws_probe = super::super::workspace::Workspace::new().expect("ws");
            let shim = ws_probe.path().join(format!("fake-tf-postapply-{tag}"));
            std::fs::write(
                &shim,
                format!(
                    "#!/bin/sh\ncase \"$1\" in\n  version|init) exit 0 ;;\n  apply) echo 'Apply complete! Resources: 1 added, 0 changed, 0 destroyed.'; exit 0 ;;\n  plan) echo '{plan_output}'; exit 0 ;;\n  *) exit 0 ;;\nesac\n"
                ),
            )
            .expect("write shim");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
                    .expect("chmod");
            }
            let plan = live_plan("patch-maintenance");
            let out = live_terraform_apply(
                &shim.to_string_lossy(),
                &plan,
                &dummy_creds(),
                &test_backend(),
                b"fake-tfplan",
            )
            .expect("apply must not error");
            (
                ws_probe, // keep the tempdir alive until asserts run
                out,
            )
        };

        // Converged: the post-apply re-plan reports no changes → verified.
        let (_ws, verified) = build(
            "No changes. Your infrastructure matches the configuration.",
            "ok",
        );
        assert_eq!(verified.status, RunStatus::Applied);
        assert!(
            verified
                .summary
                .contains("post-apply: verified (converged)"),
            "converged re-plan must verify: {}",
            verified.summary
        );

        // Pending change: the post-apply re-plan still wants a change → drift.
        let (_ws2, drift) = build("Plan: 1 to add, 0 to change, 0 to destroy.", "drift");
        assert_eq!(
            drift.status,
            RunStatus::Applied,
            "post-apply drift is advisory — the apply still succeeded"
        );
        assert!(
            drift.summary.contains("post-apply: drift detected"),
            "pending-change re-plan must flag drift: {}",
            drift.summary
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
        // `show -json` must emit valid JSON — the digest layer now fails closed
        // on non-canonical plan output. Other steps just list files and exit 0.
        std::fs::write(
            &shim,
            "#!/bin/sh\nif [ \"$1\" = show ]; then echo '{\"format_version\":\"1.2\",\"resource_changes\":[]}'; exit 0; fi\ntouch \"$PWD/tfplan\"\nls\nexit 0\n",
        )
        .expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let plan = live_plan("patch-maintenance");
        let backend = test_backend();
        let result = live_terraform_plan(&shim.to_string_lossy(), &plan, &dummy_creds(), &backend);
        assert!(
            result.is_ok(),
            "backend_config write must not error: {result:?}"
        );
        // Shim exits 0 → should be Planned.
        assert_eq!(result.unwrap().outcome.status, RunStatus::Planned);
    }

    // -----------------------------------------------------------------------
    // #42 B2-3: run_live_destroy — mode guard / missing IaC / absent binary
    // -----------------------------------------------------------------------

    #[test]
    fn run_live_destroy_rejects_dry_run_mode() {
        let mut plan = live_plan("patch-maintenance");
        plan.mode = RunMode::DryRun;
        let result = run_live_destroy(&plan, &dummy_creds(), &test_backend());
        assert!(
            result.is_err(),
            "run_live_destroy must reject RunMode::DryRun"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Live") || msg.contains("DryRun"),
            "error must mention mode; got: {msg}"
        );
    }

    #[test]
    fn run_live_destroy_fails_closed_on_missing_iac() {
        let plan = live_plan("no-such-offering-xyz");
        let result = run_live_destroy(&plan, &dummy_creds(), &test_backend());
        assert!(
            result.is_err(),
            "run_live_destroy must fail closed when IaC is missing"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no embedded") || msg.contains("IaC"),
            "error must mention missing IaC; got: {msg}"
        );
    }

    #[test]
    fn run_live_destroy_terraform_absent_returns_unavailable() {
        let plan = live_plan("patch-maintenance");
        let result = live_terraform_destroy(
            "/nonexistent/terraform-fake-live-destroy",
            &plan,
            &dummy_creds(),
            &test_backend(),
        );
        assert!(
            result.is_ok(),
            "absent terraform must not return Err for destroy"
        );
        assert_eq!(
            result.unwrap().status,
            RunStatus::RunnerUnavailable,
            "absent terraform must return RunnerUnavailable for destroy"
        );
    }

    #[test]
    fn run_live_destroy_accepts_backend_config_without_error() {
        let plan = live_plan("patch-maintenance");
        let backend = test_backend();
        let result = live_terraform_destroy(
            "/nonexistent/terraform-fake-live-backend-destroy",
            &plan,
            &dummy_creds(),
            &backend,
        );
        assert!(
            result.is_ok(),
            "backend_config must not cause Err for destroy when binary absent"
        );
        assert_eq!(result.unwrap().status, RunStatus::RunnerUnavailable);
    }

    // -----------------------------------------------------------------------
    // #42 B2-3: destroy invocation shape — -auto-approve + -input=false,
    // and NO tfplan argument (there is no saved plan for a destroy)
    // -----------------------------------------------------------------------

    #[test]
    fn live_destroy_invokes_destroy_with_auto_approve_and_no_tfplan() {
        let ws_probe = super::super::workspace::Workspace::new().expect("ws");
        let shim = ws_probe.path().join("fake-tf-destroy-check");
        std::fs::write(
            &shim,
            r#"#!/bin/sh
case "$1" in
  version) exit 0 ;;
  init) exit 0 ;;
  destroy)
    found_auto=0
    found_input=0
    for arg in "$@"; do
      if [ "$arg" = "-auto-approve" ]; then found_auto=1; fi
      if [ "$arg" = "-input=false" ]; then found_input=1; fi
      if [ "$arg" = "tfplan" ]; then
        echo "FAIL: tfplan must not be passed to destroy" >&2
        exit 3
      fi
    done
    if [ "$found_auto" = "0" ]; then
      echo "FAIL: -auto-approve is REQUIRED for destroy (no saved plan)" >&2
      exit 2
    fi
    if [ "$found_input" = "0" ]; then
      echo "FAIL: -input=false missing" >&2
      exit 4
    fi
    echo "Destroy complete! Resources: 1 destroyed."
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
        let result = live_terraform_destroy(
            &shim.to_string_lossy(),
            &plan,
            &dummy_creds(),
            &test_backend(),
        );
        assert!(result.is_ok(), "destroy shim must not error: {result:?}");
        let outcome = result.unwrap();
        assert_eq!(
            outcome.status,
            RunStatus::Applied,
            "destroy shim exits 0 → Applied (success); got {:?} log: {}",
            outcome.status,
            outcome.log
        );
        assert_eq!(
            outcome.summary, "Destroy complete! Resources: 1 destroyed.",
            "summary must be the extracted destroy line"
        );
        assert_eq!(outcome.exit_code, Some(0));
    }

    // -----------------------------------------------------------------------
    // #42 B2-3: destroy failure paths — non-zero destroy exit and failed init
    // -----------------------------------------------------------------------

    #[test]
    fn live_destroy_returns_failed_when_destroy_exits_nonzero() {
        let ws_probe = super::super::workspace::Workspace::new().expect("ws");
        let shim = ws_probe.path().join("fake-tf-destroy-fail");
        std::fs::write(
            &shim,
            r#"#!/bin/sh
case "$1" in
  version) exit 0 ;;
  init) exit 0 ;;
  destroy) echo 'Error: provider refused deletion' >&2; exit 1 ;;
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
        let outcome = live_terraform_destroy(
            &shim.to_string_lossy(),
            &plan,
            &dummy_creds(),
            &test_backend(),
        )
        .expect("shim destroy failure must not be Err");
        assert_eq!(
            outcome.status,
            RunStatus::Failed,
            "non-zero destroy exit must yield Failed (the CP HALTS the cascade)"
        );
        assert!(
            outcome.summary.contains("terraform destroy failed"),
            "summary must name the failed step: {}",
            outcome.summary
        );
        assert_eq!(outcome.exit_code, Some(1));
    }

    #[test]
    fn live_destroy_returns_failed_when_init_fails_destroy_never_runs() {
        let ws_probe = super::super::workspace::Workspace::new().expect("ws");
        let shim = ws_probe.path().join("fake-tf-destroy-init-fail");
        // init exits 1; destroy would SUCCEED (exit 0 + success line) — so if
        // the outcome were Applied, destroy wrongly ran after a failed init.
        std::fs::write(
            &shim,
            r#"#!/bin/sh
case "$1" in
  version) exit 0 ;;
  init) echo 'Error: backend unreachable' >&2; exit 1 ;;
  destroy) echo 'Destroy complete! Resources: 1 destroyed.'; exit 0 ;;
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
        let outcome = live_terraform_destroy(
            &shim.to_string_lossy(),
            &plan,
            &dummy_creds(),
            &test_backend(),
        )
        .expect("init failure must not be Err");
        assert_eq!(
            outcome.status,
            RunStatus::Failed,
            "failed init must fail closed — destroy must never run; got {:?}",
            outcome.status
        );
        assert!(
            outcome.summary.contains("init failed before destroy"),
            "summary must attribute the failure to init: {}",
            outcome.summary
        );
    }

    // -----------------------------------------------------------------------
    // #42 B2-3: REAL-terraform end-to-end — apply a step into a shared durable
    // (local-path) backend, then destroy from a THIRD fresh workspace and
    // prove the state is the source of truth (skipped when terraform absent).
    // -----------------------------------------------------------------------

    /// Drives the REAL `terraform` binary through plan → apply → destroy on the
    /// provider-less `request-preflight` bundle (terraform_data only — builtin
    /// provider, no registry egress). Each phase runs in its OWN fresh runner
    /// workspace, exactly like production (plan job / apply job / destroy job
    /// are separate processes); the operator `backend_config` (here a
    /// `backend "local"` pointing at a shared absolute path) is what carries
    /// the state lineage across them. Asserts: (1) the apply records the
    /// resource in the shared state; (2) `run_live_destroy`'s workspace
    /// reconstruction attaches to that SAME state and destroys it (Applied +
    /// "Destroy complete!"); (3) the state afterwards holds zero resources.
    #[test]
    fn real_terraform_live_destroy_e2e_applies_then_destroys_shared_state() {
        if !binary_available("terraform") {
            eprintln!("SKIP: terraform binary not found");
            return;
        }

        // Shared durable state location (outlives all three run workspaces).
        let state_dir = super::super::workspace::Workspace::new().expect("state dir");
        let state_path = state_dir.path().join("terraform-step-e2e.tfstate");
        let backend_template = format!(
            "terraform {{\n  backend \"local\" {{\n    path = \"{}\"\n  }}\n}}\n",
            state_dir
                .path()
                .join("terraform-{STATE_KEY}.tfstate")
                .display()
        );
        let backend = IsolatedBackendConfig::from_template(&backend_template, "step-e2e")
            .expect("isolated backend");

        let plan = live_plan("request-preflight");

        // Phase 1: live plan (fresh workspace #1) — produces the saved tfplan.
        let artifacts = live_terraform_plan("terraform", &plan, &dummy_creds(), &backend)
            .expect("live plan must not error");
        if artifacts.outcome.status == RunStatus::RunnerUnavailable {
            eprintln!("SKIP: terraform reported unavailable");
            return;
        }
        assert_eq!(
            artifacts.outcome.status,
            RunStatus::Planned,
            "plan phase: {}",
            artifacts.outcome.summary
        );
        assert!(!artifacts.tfplan.is_empty(), "saved tfplan must exist");

        // Phase 2: live apply of the SAVED plan (fresh workspace #2) — the
        // resource lands in the shared backend state.
        let applied = live_terraform_apply(
            "terraform",
            &plan,
            &dummy_creds(),
            &backend,
            &artifacts.tfplan,
        )
        .expect("live apply must not error");
        assert_eq!(
            applied.status,
            RunStatus::Applied,
            "apply phase: {} log: {}",
            applied.summary,
            applied.log
        );
        let state_after_apply: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&state_path).expect("state file must exist after apply"),
        )
        .expect("state JSON must parse");
        assert!(
            !state_after_apply["resources"]
                .as_array()
                .expect("resources array")
                .is_empty(),
            "apply must record the resource in the shared state"
        );

        // Phase 3: live destroy (fresh workspace #3) — reconstructs the same
        // IaC + backend, attaches to the SAME state, destroys what it holds.
        let destroyed = live_terraform_destroy("terraform", &plan, &dummy_creds(), &backend)
            .expect("live destroy must not error");
        assert_eq!(
            destroyed.status,
            RunStatus::Applied,
            "destroy phase must succeed: {} log: {}",
            destroyed.summary,
            destroyed.log
        );
        assert!(
            destroyed.summary.starts_with("Destroy complete!"),
            "summary must be the real terraform destroy line: {}",
            destroyed.summary
        );
        assert!(
            destroyed.log.contains("Destroy complete!"),
            "scrubbed evidence log must carry the destroy proof"
        );
        assert_eq!(destroyed.exit_code, Some(0));

        // The state — the source of truth — now holds NOTHING.
        let state_after_destroy: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&state_path).expect("state file must exist after destroy"),
        )
        .expect("state JSON must parse after destroy");
        assert!(
            state_after_destroy["resources"]
                .as_array()
                .expect("resources array")
                .is_empty(),
            "destroy must remove every resource from the shared state"
        );
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

    #[test]
    fn extract_destroy_summary_finds_destroy_complete() {
        let log = "terraform_data.x: Destroying...\nDestroy complete! Resources: 3 destroyed.";
        assert_eq!(
            extract_destroy_summary(log),
            "Destroy complete! Resources: 3 destroyed."
        );
        // Empty-state destroy variants.
        assert!(
            extract_destroy_summary("No changes. No objects need to be destroyed.")
                .starts_with("No changes.")
        );
        // Fallback when terraform output has neither line.
        assert_eq!(
            extract_destroy_summary("something else"),
            "terraform destroy completed"
        );
    }

    #[test]
    fn canonicalize_plan_json_strips_timestamp_for_a_deterministic_digest() {
        // Two identical plans that differ ONLY in terraform's non-deterministic
        // top-level `timestamp` must canonicalize to the SAME bytes (equal digest).
        let plan_a = r#"{"format_version":"1.2","timestamp":"2026-07-01T05:30:04Z","resource_changes":[{"address":"terraform_data.x","change":{"actions":["create"]}}]}"#;
        let plan_b = r#"{"format_version":"1.2","timestamp":"2026-07-01T05:30:06Z","resource_changes":[{"address":"terraform_data.x","change":{"actions":["create"]}}]}"#;
        let ca = canonicalize_plan_json(plan_a).unwrap();
        let cb = canonicalize_plan_json(plan_b).unwrap();
        assert_eq!(
            ca, cb,
            "plans differing only by timestamp must be equal after canonicalization"
        );
        assert!(
            !ca.contains("timestamp"),
            "timestamp must be stripped from the digest input"
        );
        assert!(
            ca.contains("resource_changes"),
            "semantic plan content must be preserved"
        );

        // Deterministic regardless of top-level key emission order (BTreeMap).
        let reordered = r#"{"resource_changes":[{"address":"terraform_data.x","change":{"actions":["create"]}}],"timestamp":"2026-07-01T09:00:00Z","format_version":"1.2"}"#;
        assert_eq!(
            ca,
            canonicalize_plan_json(reordered).unwrap(),
            "key order must not affect the digest"
        );

        // A REAL plan change must still change the canonical form — the plan-integrity
        // guarantee is preserved (the gate must reject a plan that differs semantically).
        let plan_c = r#"{"format_version":"1.2","timestamp":"2026-07-01T05:30:04Z","resource_changes":[{"address":"terraform_data.x","change":{"actions":["delete"]}}]}"#;
        assert_ne!(
            ca,
            canonicalize_plan_json(plan_c).unwrap(),
            "a real change to resource_changes MUST change the digest input"
        );

        // INTEGRITY / losslessness: two plans differing ONLY in a high-precision numeric
        // value (beyond f64 exact range) MUST canonicalize DIFFERENTLY. A Value-based
        // canonicalizer would collapse both to the same f64 → same digest → the gate would
        // wrongly accept an apply whose planned value differs. RawValue preserves the exact
        // bytes, so the digests differ (codex-flagged regression guard).
        // Both integers exceed u64::MAX (18446744073709551615), so a Value-based parser
        // without arbitrary_precision would parse BOTH as the same f64 (2^64) — collapsing
        // them. RawValue keeps the exact bytes, so the canonical forms differ.
        let big_1 =
            r#"{"timestamp":"2026-07-01T05:30:04Z","planned_values":{"n":18446744073709551616}}"#;
        let big_2 =
            r#"{"timestamp":"2026-07-01T05:30:06Z","planned_values":{"n":18446744073709551617}}"#;
        assert_ne!(
            canonicalize_plan_json(big_1).unwrap(),
            canonicalize_plan_json(big_2).unwrap(),
            "high-precision numeric differences MUST survive canonicalization (no f64 collapse)"
        );

        // Fail-CLOSED: non-JSON input yields no digest (the caller returns Failed
        // rather than digesting non-canonical bytes).
        assert!(
            canonicalize_plan_json("not json").is_none(),
            "unparseable plan JSON must fail closed (no digest)"
        );
    }

    #[test]
    fn canonicalize_plan_json_covers_the_full_plan_past_32_kib() {
        // Regression for the truncated-digest bug: two plans identical in their
        // first 32 KiB but differing in a tail resource must canonicalize to
        // DIFFERENT bytes. This only holds because the show output reaches
        // `canonicalize_plan_json` UNtruncated (run_tf_step truncate=false).
        let filler = "x".repeat(crate::scrub::MAX_LOG_BYTES);
        let plan_a = format!(
            r#"{{"timestamp":"2026-07-01T05:30:04Z","pad":"{filler}","tail":{{"address":"aws_instance.a","action":"create"}}}}"#
        );
        let plan_b = format!(
            r#"{{"timestamp":"2026-07-01T05:30:06Z","pad":"{filler}","tail":{{"address":"aws_instance.b","action":"create"}}}}"#
        );
        assert!(plan_a.len() > crate::scrub::MAX_LOG_BYTES);
        let ca = canonicalize_plan_json(&plan_a).unwrap();
        let cb = canonicalize_plan_json(&plan_b).unwrap();
        assert_ne!(
            ca, cb,
            "plans differing only past 32 KiB MUST produce different canonical digests"
        );

        // And a large plan differing ONLY by timestamp still canonicalizes equal
        // (the availability half — every large live apply would otherwise refuse).
        let plan_c = format!(
            r#"{{"timestamp":"2026-07-01T23:59:59Z","pad":"{filler}","tail":{{"address":"aws_instance.a","action":"create"}}}}"#
        );
        assert_eq!(
            ca,
            canonicalize_plan_json(&plan_c).unwrap(),
            "a large plan differing only by timestamp must remain digest-stable"
        );
    }

    #[test]
    fn secret_env_pairs_maps_each_name_to_native_and_tf_var_forms() {
        // Each declared name yields its verbatim provider-native env var AND the
        // TF_VAR_<lowercase> terraform-variable alias, each with ITS OWN value
        // (multi-credential mis-pairing bug guard).
        let names = vec!["VSPHERE_USER".to_string(), "VSPHERE_PASSWORD".to_string()];
        assert_eq!(
            secret_env_pairs(&names, "admin@vsphere.local,hunter2"),
            vec![
                (
                    "VSPHERE_USER".to_string(),
                    "admin@vsphere.local".to_string()
                ),
                (
                    "TF_VAR_vsphere_user".to_string(),
                    "admin@vsphere.local".to_string()
                ),
                ("VSPHERE_PASSWORD".to_string(), "hunter2".to_string()),
                ("TF_VAR_vsphere_password".to_string(), "hunter2".to_string()),
            ]
        );
        // A lowercase declared name still gets both forms (verbatim + alias).
        assert_eq!(
            secret_env_pairs(&["token".to_string()], "abc123"),
            vec![
                ("token".to_string(), "abc123".to_string()),
                ("TF_VAR_token".to_string(), "abc123".to_string()),
            ]
        );
        // No names, or no creds → nothing injected.
        assert!(secret_env_pairs(&[], "abc").is_empty());
        assert!(secret_env_pairs(&["x".to_string()], "").is_empty());
    }

    // -----------------------------------------------------------------------
    // Credential seam: declaration plumbing + fail-closed arity + injection
    // -----------------------------------------------------------------------

    /// FAIL CLOSED: a live run whose offering declares secret vars but whose
    /// resolved material does not pair 1:1 must be refused with the VARIABLE
    /// NAMES (never values) BEFORE any terraform subprocess — on ALL THREE
    /// live paths. The binary path is nonexistent on purpose: getting Err
    /// (not Ok(RunnerUnavailable)) proves the gate fires before the
    /// availability probe, i.e. before anything could spawn.
    #[test]
    fn live_paths_fail_closed_on_credential_arity_mismatch() {
        let mut plan = live_plan("linux-server-deployment");
        plan.secret_var_names = crate::iac::live_secret_var_names("linux-server-deployment")
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(plan.secret_var_names.len(), 3, "declaration plumbing");
        // One component for three declared names.
        let creds = ResolvedCredentials {
            material: b"only-one-value".to_vec(),
            descriptor: "test:mismatch".to_string(),
        };

        let assert_refused = |result: Result<RunOutcome, RunnerError>, path: &str| {
            let err = result.expect_err(&format!("{path} must fail closed on arity mismatch"));
            let msg = err.to_string();
            assert!(
                msg.contains("VSPHERE_USER")
                    && msg.contains("VSPHERE_PASSWORD")
                    && msg.contains("VSPHERE_SERVER"),
                "{path} error must name the declared variables: {msg}"
            );
            assert!(
                msg.contains("3") && msg.contains("1"),
                "{path} error must carry the counts: {msg}"
            );
            assert!(
                !msg.contains("only-one-value"),
                "{path} error must NEVER carry a credential value: {msg}"
            );
        };

        assert_refused(
            live_terraform_plan(
                "/nonexistent/terraform-arity",
                &plan,
                &creds,
                &test_backend(),
            )
            .map(|a| a.outcome),
            "plan",
        );
        assert_refused(
            live_terraform_apply(
                "/nonexistent/terraform-arity",
                &plan,
                &creds,
                &test_backend(),
                b"tfplan",
            ),
            "apply",
        );
        assert_refused(
            live_terraform_destroy(
                "/nonexistent/terraform-arity",
                &plan,
                &creds,
                &test_backend(),
            ),
            "destroy",
        );
    }

    /// End-to-end injection proof on the LIVE path: the terraform child sees
    /// exactly the DECLARED vsphere env vars (provider-native + TF_VAR alias),
    /// each paired with its own value — and nothing else credential-shaped:
    /// no RYUKI_LIVE_CRED_* passthrough and no undeclared parent env leakage.
    #[test]
    fn live_plan_injects_declared_secret_env_vars_and_only_those() {
        let ws_probe = super::super::workspace::Workspace::new().expect("ws");
        let probe_dir = ws_probe.path().to_string_lossy().to_string();
        let shim = ws_probe.path().join("fake-tf-env-dump");
        // The shim dumps its environment per step, emits valid JSON for `show`,
        // and writes the stub tfplan for the plan step.
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\nenv > \"{probe_dir}/env-$1\"\nif [ \"$1\" = show ]; then echo '{{\"format_version\":\"1.2\",\"resource_changes\":[]}}'; exit 0; fi\ntouch \"$PWD/tfplan\"\nexit 0\n"
            ),
        )
        .expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        // Poison the PARENT environment: neither the operator-side cred var nor
        // an arbitrary parent secret may reach the child (env_clear allowlist).
        std::env::set_var("RYUKI_LIVE_CRED_VSPHERE_USER", "parent-cred-canary");
        std::env::set_var("RYUKI_TEST_PARENT_SECRET", "parent-secret-canary");

        // Declaration plumbing: names come from the OFFERINGS registry.
        let mut plan = live_plan("linux-server-deployment");
        plan.secret_var_names = crate::iac::live_secret_var_names("linux-server-deployment")
            .iter()
            .map(|s| s.to_string())
            .collect();
        // Resolved material in declared order: USER, PASSWORD, SERVER.
        let creds = ResolvedCredentials {
            material: b"user-value-a,pass-value-b,vcenter.test.invalid".to_vec(),
            descriptor: "test:vsphere".to_string(),
        };

        let result = live_terraform_plan(&shim.to_string_lossy(), &plan, &creds, &test_backend())
            .expect("env-dump shim plan must not error");
        assert_eq!(result.outcome.status, RunStatus::Planned);

        for step in ["init", "plan"] {
            let dump = std::fs::read_to_string(ws_probe.path().join(format!("env-{step}")))
                .unwrap_or_else(|e| panic!("env dump for {step} must exist: {e}"));
            // Declared provider-native vars, each with ITS OWN value.
            assert!(dump.contains("VSPHERE_USER=user-value-a"), "{step}: {dump}");
            assert!(
                dump.contains("VSPHERE_PASSWORD=pass-value-b"), // secret-scan-allow: fixture value, not a credential
                "{step}: {dump}"
            );
            assert!(
                dump.contains("VSPHERE_SERVER=vcenter.test.invalid"),
                "{step}: {dump}"
            );
            // Terraform-variable aliases for the bundle's `var.vsphere_*` refs.
            assert!(
                dump.contains("TF_VAR_vsphere_user=user-value-a"),
                "{step}: {dump}"
            );
            assert!(
                dump.contains("TF_VAR_vsphere_password=pass-value-b"), // secret-scan-allow: fixture value, not a credential
                "{step}: {dump}"
            );
            assert!(
                dump.contains("TF_VAR_vsphere_server=vcenter.test.invalid"),
                "{step}: {dump}"
            );
            // The agent-side env var namespace must NOT pass through, and the
            // poisoned parent env must not leak (allowlist + env_clear).
            assert!(
                !dump.contains("RYUKI_LIVE_CRED"),
                "{step}: RYUKI_LIVE_CRED_* must never reach the terraform child: {dump}"
            );
            assert!(
                !dump.contains("parent-cred-canary") && !dump.contains("parent-secret-canary"),
                "{step}: parent env must not leak into the terraform child: {dump}"
            );
        }

        // The `show` step gets NO credential injection (it only renders the
        // saved plan file — no provider contact).
        let show_dump = std::fs::read_to_string(ws_probe.path().join("env-show"))
            .expect("env dump for show must exist");
        assert!(
            !show_dump.contains("VSPHERE_") && !show_dump.contains("TF_VAR_"),
            "show step must not receive credentials: {show_dump}"
        );

        // The credential values must be scrubbed from the returned evidence.
        for value in ["user-value-a", "pass-value-b", "vcenter.test.invalid"] {
            assert!(
                !result.outcome.log.contains(value) && !result.outcome.summary.contains(value),
                "credential value {value:?} must be scrubbed from evidence"
            );
        }

        std::env::remove_var("RYUKI_LIVE_CRED_VSPHERE_USER");
        std::env::remove_var("RYUKI_TEST_PARENT_SECRET");
    }
}
