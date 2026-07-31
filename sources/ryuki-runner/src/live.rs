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
//! `ryuki_backend.tf` BEFORE `terraform init`. The config can only be built
//! from an operator template containing the exact `{STATE_KEY}` placeholder
//! and a validated control-plane state key. Live Terraform has no unisolated
//! fallback: missing templates, missing placeholders, and unsafe keys fail
//! before any Terraform subprocess is invoked.
//!
//! ## Executable approval and absence
//!
//! Production entry points require `RYUKI_TERRAFORM_EXECUTABLE` and
//! `RYUKI_TERRAFORM_EXPECTED_VERSION`. The absolute canonical executable must
//! pass ownership/mode, identity/version, and optional SHA-256 validation
//! before credentials are processed. Invalid or missing approval
//! configuration is an error; if an already-approved executable disappears
//! before the availability probe, the outcome is `RunnerUnavailable`.
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
//! `terraform show -json tfplan`, canonicalizes the complete plan, and hashes
//! every canonical byte. The durable `RunOutcome.log` is a small allowlisted
//! evidence envelope containing that content hash plus only the fields needed
//! for server-side approval review. The caller's existing evidence digest
//! therefore still commits to the full plan while raw provider/state semantics
//! never cross into durable evidence. The raw `tfplan` bytes remain
//! process-local and are returned only for exact saved-plan apply.
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
//! any credential-bearing Terraform phase is spawned.  The offline dry-run path
//! (`run_offline_dry_run`) never receives credentials: the agent always builds
//! it with an empty `secret_var_names` list and empty credential material.
//!
//! ## Security invariants (MUST hold — same as `terraform.rs`)
//!
//! - The top-level Terraform CLI is locally approved before credentials are
//!   processed or attached; inherited `PATH` never selects it.
//! - Secret material is NEVER passed as a command-line argument.
//! - Secrets are injected as `TF_VAR_<name>` env vars on the child only.
//! - Output is scrubbed before placement in `RunOutcome.log` / `.summary`.
//! - Workspace `TempDir` is removed on drop.
//! - `TF_LOG` is never set to `trace` or any verbose level.
//! - Raw `tfplan` bytes are opaque binary data and MUST NOT be logged.

use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ryuki_engine::runners::{
    ResolvedCredentials, RunMode, RunOutcome, RunPlan, RunStatus, RunnerError, RunnerKind,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ---------------------------------------------------------------------------
// LivePlanArtifacts — returned by run_live_plan
// ---------------------------------------------------------------------------

/// Artifacts produced by a successful `run_live_plan` call.
///
/// Both fields are required to close the TOCTOU hole:
/// - `outcome` — the canonical `RunOutcome` whose `log` is the safe plan
///   evidence envelope. Its nested content hash commits to the full plan.
/// - `tfplan` — the raw binary plan file (`terraform plan -out=tfplan`).
///   Pass this verbatim to `run_live_apply` so it applies EXACTLY the plan
///   the gate approved, not a fresh re-plan.
///
/// # Security note
/// The `tfplan` bytes are opaque binary data. They MUST NOT be logged,
/// included in evidence, or sent to the control plane.
pub struct LivePlanArtifacts {
    /// The `RunOutcome` from the plan step (status = `Planned` on success).
    /// `outcome.log` is the allowlisted, integrity-committing evidence envelope.
    pub outcome: RunOutcome,
    /// Direct SHA-256 of the complete canonical raw plan, computed before any
    /// redaction. Present only when `outcome.status == Planned`.
    pub raw_plan_digest: Option<String>,
    /// Raw binary `tfplan` file. Pass to `run_live_apply` unchanged.
    pub tfplan: Vec<u8>,
}

impl std::fmt::Debug for LivePlanArtifacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LivePlanArtifacts")
            .field("outcome", &self.outcome)
            .field("raw_plan_digest", &self.raw_plan_digest)
            .field(
                "tfplan",
                &format_args!("<redacted:{} bytes>", self.tfplan.len()),
            )
            .finish()
    }
}

use super::{
    exec::{run_command_with_optional_cancellation, run_version_probe, CommandCancellation},
    executable::{ApprovedExecutable, ApprovedTool},
    scrub::{append_go_json_escape_variants, basic_auth_canonical_variants, scrub, scrub_output},
    terraform::{
        apply_env_allowlist, combine_output, credential_components, pin_home_tmpdir_to_workspace,
        validate_offering_slug, validate_var_name, TERRAFORM_INIT_ARGS,
    },
    workspace::Workspace,
};

/// Per-subprocess timeout for each terraform sub-command in a live run.
/// Init / plan / apply are each given this budget independently.
const LIVE_RUNNER_TIMEOUT: Duration = Duration::from_secs(600); // 10 min per step

/// Saved plan files are process-local integrity artifacts, never evidence.
/// Bound their allocation independently from subprocess output capture.
const MAX_TFPLAN_BYTES: usize = 64 * 1024 * 1024;

/// Exact token an operator backend template must contain.
pub const STATE_KEY_PLACEHOLDER: &str = "{STATE_KEY}";

/// Stable identifier for the backend credential-authority contract.
///
/// This policy admits only closed-schema, exact inline scalar credentials. It
/// rejects credential files and ambient, metadata, CLI, workload-identity, and
/// in-cluster credential discovery before Terraform can be spawned.
pub const BACKEND_CREDENTIAL_AUTHORITY_POLICY_VERSION: &str = "ryuki.closed-schema-inline-scalars-no-file-ambient-metadata-cli-workload-in-cluster-no-remote-execution.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
enum BackendHclToken {
    Ident(String),
    Quoted(String),
    Equals,
    OpenBrace,
    CloseBrace,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendSecretKind {
    Opaque,
    AccessKey,
    Token,
    Password,
    User,
    BasicAuth,
    ConnectionString,
    PrivateKey,
    Certificate,
}

fn backend_secret_kind(backend_type: &str, attribute: &str) -> Option<BackendSecretKind> {
    use BackendSecretKind as Kind;
    match (backend_type, attribute) {
        ("s3", "access_key" | "secret_key") => Some(Kind::AccessKey),
        ("s3", "token" | "web_identity_token") => Some(Kind::Token),
        ("s3", "sse_customer_key") => Some(Kind::PrivateKey),
        ("azurerm", "access_key") => Some(Kind::AccessKey),
        ("azurerm", "sas_token") => Some(Kind::Token),
        ("azurerm", "client_secret" | "client_certificate_password") => Some(Kind::Password),
        ("azurerm", "client_certificate") => Some(Kind::Certificate),
        ("oss", "access_key" | "secret_key") => Some(Kind::AccessKey),
        ("oss", "security_token") => Some(Kind::Token),
        ("cos", "secret_id" | "secret_key") => Some(Kind::AccessKey),
        ("cos", "security_token") => Some(Kind::Token),
        ("gcs", "access_token") => Some(Kind::Token),
        ("etcdv3", "username") => Some(Kind::User),
        ("etcdv3", "password") => Some(Kind::Password),
        ("consul", "access_token") => Some(Kind::Token),
        ("consul", "http_auth") => Some(Kind::BasicAuth),
        ("pg", "conn_str") => Some(Kind::ConnectionString),
        ("kubernetes", "username") => Some(Kind::User),
        ("kubernetes", "password") => Some(Kind::Password),
        ("kubernetes", "token") => Some(Kind::Token),
        ("kubernetes", "client_key") => Some(Kind::PrivateKey),
        ("kubernetes", "client_certificate") => Some(Kind::Certificate),
        ("http", "username") => Some(Kind::User),
        ("http", "password") => Some(Kind::Password),
        ("http", "client_certificate_pem") => Some(Kind::Certificate),
        ("http", "client_private_key_pem") => Some(Kind::PrivateKey),
        _ => None,
    }
}

fn backend_public_attributes(backend_type: &str) -> Option<&'static [&'static str]> {
    let attributes: &[&str] = match backend_type {
        "local" => &["path", "workspace_dir"],
        "s3" => &[
            "bucket",
            "key",
            "region",
            "allowed_account_ids",
            "dynamodb_endpoint",
            "endpoint",
            "endpoints",
            "forbidden_account_ids",
            "iam_endpoint",
            "sts_endpoint",
            "sts_region",
            "encrypt",
            "acl",
            "kms_key_id",
            "dynamodb_table",
            "use_lockfile",
            "retry_mode",
            "skip_credentials_validation",
            "skip_requesting_account_id",
            "skip_metadata_api_check",
            "skip_region_validation",
            "skip_s3_checksum",
            "workspace_key_prefix",
            "force_path_style",
            "use_path_style",
            "max_retries",
            "http_proxy",
            "https_proxy",
            "no_proxy",
            "insecure",
            "use_fips_endpoint",
            "use_dualstack_endpoint",
        ],
        "azurerm" => &[
            "subscription_id",
            "resource_group_name",
            "storage_account_name",
            "container_name",
            "key",
            "lookup_blob_endpoint",
            "snapshot",
            "environment",
            "tenant_id",
            "client_id",
            "use_cli",
            "use_msi",
            "use_oidc",
            "use_aks_workload_identity",
            "use_azuread_auth",
        ],
        "oss" => &[
            "ecs_role_name",
            "region",
            "sts_endpoint",
            "tablestore_endpoint",
            "endpoint",
            "bucket",
            "prefix",
            "key",
            "tablestore_instance_name",
            "tablestore_table",
            "encrypt",
            "acl",
        ],
        "cos" => &[
            "region",
            "bucket",
            "endpoint",
            "domain",
            "prefix",
            "key",
            "encrypt",
            "acl",
            "accelerate",
        ],
        "gcs" => &[
            "bucket",
            "prefix",
            "kms_encryption_key",
            "storage_custom_endpoint",
        ],
        "etcdv3" => &["endpoints", "prefix", "lock"],
        "consul" => &["path", "address", "scheme", "datacenter", "gzip", "lock"],
        "pg" => &[
            "schema_name",
            "skip_schema_creation",
            "skip_table_creation",
            "skip_index_creation",
        ],
        "kubernetes" => &[
            "secret_suffix",
            "labels",
            "namespace",
            "in_cluster_config",
            "load_config_file",
            "host",
            "insecure",
            "cluster_ca_certificate",
            "proxy_url",
        ],
        "http" => &[
            "address",
            "update_method",
            "lock_address",
            "unlock_address",
            "lock_method",
            "unlock_method",
            "skip_cert_verification",
            "retry_max",
            "retry_wait_min",
            "retry_wait_max",
            "client_ca_certificate_pem",
        ],
        _ => return None,
    };
    Some(attributes)
}

fn backend_sensitive_structure(backend_type: &str, attribute: &str) -> bool {
    matches!(
        (backend_type, attribute),
        (
            "s3",
            "endpoints" | "assume_role" | "assume_role_with_web_identity"
        ) | ("kubernetes", "labels")
    )
}

fn backend_nested_attribute_allowed(backend_type: &str, structure: &str, attribute: &str) -> bool {
    match (backend_type, structure) {
        ("s3", "endpoints") => matches!(attribute, "s3" | "dynamodb" | "iam" | "sts"),
        ("s3", "assume_role") => matches!(
            attribute,
            "role_arn"
                | "duration"
                | "external_id"
                | "policy"
                | "policy_arns"
                | "session_name"
                | "source_identity"
                | "tags"
                | "transitive_tag_keys"
        ),
        ("s3", "assume_role_with_web_identity") => matches!(
            attribute,
            "role_arn"
                | "duration"
                | "policy"
                | "policy_arns"
                | "session_name"
                | "web_identity_token"
                | "web_identity_token_file"
        ),
        ("kubernetes", "labels") => true,
        _ => false,
    }
}

fn backend_nested_public_unquoted(backend_type: &str, structure: &str, attribute: &str) -> bool {
    matches!(
        (backend_type, structure, attribute),
        (
            "s3",
            "assume_role" | "assume_role_with_web_identity",
            "duration" | "policy_arns" | "tags" | "transitive_tag_keys"
        )
    )
}

fn backend_credential_file_attribute(backend_type: &str, attribute: &str) -> bool {
    matches!(
        (backend_type, attribute),
        (
            "s3",
            "shared_config_files"
                | "shared_credentials_file"
                | "shared_credentials_files"
                | "custom_ca_bundle"
                | "web_identity_token_file"
        ) | (
            "azurerm",
            "client_id_file_path"
                | "client_certificate_path"
                | "client_secret_file_path"
                | "oidc_token_file_path"
        ) | ("oss", "shared_credentials_file")
            | ("cos", "shared_credentials_dir")
            | ("gcs", "credentials" | "encryption_key")
            | ("etcdv3", "cacert_path" | "cert_path" | "key_path")
            | ("consul", "ca_file" | "cert_file" | "key_file")
            | ("kubernetes", "config_path" | "config_paths")
    )
}

fn backend_implicit_credential_attribute(backend_type: &str, attribute: &str) -> bool {
    matches!(
        (backend_type, attribute),
        (
            "s3",
            "profile"
                | "ec2_metadata_service_endpoint"
                | "ec2_metadata_service_endpoint_mode"
                | "assume_role"
                | "assume_role_with_web_identity"
        ) | (
            "azurerm",
            "msi_endpoint"
                | "endpoint"
                | "metadata_host"
                | "ado_pipeline_service_connection_id"
                | "oidc_request_url"
                | "oidc_request_token"
                | "oidc_token"
        ) | (
            "oss",
            "ecs_role_name"
                | "profile"
                | "assume_role"
                | "assume_role_role_arn"
                | "assume_role_session_name"
                | "assume_role_policy"
                | "assume_role_session_expiration"
        ) | ("cos", "cam_role_name" | "profile" | "assume_role")
            | (
                "gcs",
                "impersonate_service_account" | "impersonate_service_account_delegates"
            )
            | (
                "kubernetes",
                "config_context" | "config_context_auth_info" | "config_context_cluster" | "exec"
            )
    )
}

fn backend_public_url_attribute(backend_type: &str, attribute: &str) -> bool {
    matches!(
        (backend_type, attribute),
        (
            "s3",
            "dynamodb_endpoint"
                | "endpoint"
                | "iam_endpoint"
                | "sts_endpoint"
                | "http_proxy"
                | "https_proxy"
        ) | ("oss", "endpoint" | "sts_endpoint" | "tablestore_endpoint")
            | ("cos", "endpoint")
            | ("gcs", "storage_custom_endpoint")
            | ("consul", "address")
            | ("kubernetes", "host" | "proxy_url")
            | ("http", "address" | "lock_address" | "unlock_address")
    )
}

fn backend_redaction_values(
    rendered_hcl: &str,
    backend_type: &str,
) -> Result<Vec<Vec<u8>>, RunnerError> {
    let tokens = tokenize_backend_hcl(rendered_hcl)?;
    let (located_backend_type, open, close) = locate_backend_block(&tokens)?;
    if located_backend_type != backend_type {
        return Err(RunnerError::Spawn(
            "live Terraform backend type changed while rendering the state key".to_string(),
        ));
    }
    let public_attributes = backend_public_attributes(backend_type).ok_or_else(|| {
        RunnerError::Spawn(format!(
            "live Terraform backend type {backend_type:?} has no approved attribute schema"
        ))
    })?;
    let mut values = Vec::new();
    let mut depth = 0usize;
    let mut index = open + 1;
    while index < close {
        let (BackendHclToken::Ident(attribute), Some(BackendHclToken::Equals)) =
            (&tokens[index], tokens.get(index + 1))
        else {
            if depth == 0 {
                if let (BackendHclToken::Ident(attribute), Some(BackendHclToken::OpenBrace)) =
                    (&tokens[index], tokens.get(index + 1))
                {
                    if backend_sensitive_structure(backend_type, attribute) {
                        let nested_close = matching_hcl_brace(&tokens, index + 1).ok_or_else(|| {
                            RunnerError::Spawn(format!(
                                "live Terraform {backend_type:?} backend attribute {attribute:?} has an unterminated object"
                            ))
                        })?;
                        append_sensitive_structure_values(
                            &mut values,
                            backend_type,
                            attribute,
                            &tokens,
                            index + 1,
                            nested_close,
                        )?;
                    }
                    if backend_implicit_credential_attribute(backend_type, attribute) {
                        return Err(backend_implicit_credential_error(backend_type, attribute));
                    }
                    if !public_attributes.contains(&attribute.as_str()) {
                        return Err(unknown_backend_attribute(backend_type, attribute));
                    }
                }
            }
            match &tokens[index] {
                BackendHclToken::OpenBrace => depth += 1,
                BackendHclToken::CloseBrace => depth = depth.saturating_sub(1),
                _ => {}
            }
            index += 1;
            continue;
        };

        if depth == 0 {
            if backend_credential_file_attribute(backend_type, attribute) {
                return Err(backend_credential_file_error(backend_type, attribute));
            } else if backend_implicit_credential_attribute(backend_type, attribute) {
                if backend_sensitive_structure(backend_type, attribute)
                    && matches!(tokens.get(index + 2), Some(BackendHclToken::OpenBrace))
                {
                    let nested_close = matching_hcl_brace(&tokens, index + 2).ok_or_else(|| {
                        RunnerError::Spawn(format!(
                            "live Terraform {backend_type:?} backend attribute {attribute:?} has an unterminated object"
                        ))
                    })?;
                    append_sensitive_structure_values(
                        &mut values,
                        backend_type,
                        attribute,
                        &tokens,
                        index + 2,
                        nested_close,
                    )?;
                }
                return Err(backend_implicit_credential_error(backend_type, attribute));
            } else if let Some(secret_kind) = backend_secret_kind(backend_type, attribute) {
                let Some(BackendHclToken::Quoted(value)) = tokens.get(index + 2) else {
                    return Err(unquoted_backend_secret(backend_type, attribute));
                };
                if !quoted_backend_scalar_is_complete(&tokens, index + 2) {
                    return Err(complex_backend_scalar(backend_type, attribute));
                }
                append_backend_secret_value(&mut values, value, secret_kind);
            } else if !public_attributes.contains(&attribute.as_str()) {
                return Err(unknown_backend_attribute(backend_type, attribute));
            } else if let Some(BackendHclToken::Quoted(value)) = tokens.get(index + 2) {
                if !quoted_backend_scalar_is_complete(&tokens, index + 2) {
                    return Err(complex_backend_scalar(backend_type, attribute));
                }
                if backend_public_url_attribute(backend_type, attribute) {
                    append_backend_secret_value(&mut values, value, BackendSecretKind::Opaque);
                }
            } else if backend_sensitive_structure(backend_type, attribute)
                && matches!(tokens.get(index + 2), Some(BackendHclToken::OpenBrace))
            {
                let nested_close = matching_hcl_brace(&tokens, index + 2).ok_or_else(|| {
                    RunnerError::Spawn(format!(
                        "live Terraform {backend_type:?} backend attribute {attribute:?} has an unterminated object"
                    ))
                })?;
                append_sensitive_structure_values(
                    &mut values,
                    backend_type,
                    attribute,
                    &tokens,
                    index + 2,
                    nested_close,
                )?;
            }
        }
        match &tokens[index] {
            BackendHclToken::OpenBrace => depth += 1,
            BackendHclToken::CloseBrace => depth = depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    for (index, token) in tokens.iter().enumerate().take(close).skip(open + 1) {
        if let BackendHclToken::Quoted(value) = token {
            let decoded_value = decode_backend_quoted_value(value);
            if let Ok(parsed) = url::Url::parse(&decoded_value) {
                let direct_secret = direct_backend_attribute_for_value(&tokens, open, index)
                    .and_then(|attribute| backend_secret_kind(backend_type, attribute));
                if direct_secret.is_none()
                    && (!parsed.username().is_empty()
                        || parsed.password().is_some()
                        || parsed.query().is_some()
                        || parsed.fragment().is_some())
                {
                    return Err(RunnerError::Spawn(format!(
                        "live Terraform {backend_type:?} backend public URL values cannot contain userinfo, query parameters, or fragments"
                    )));
                }
                append_backend_secret_value(&mut values, value, BackendSecretKind::Opaque);
            }
        }
    }
    let username = direct_attribute_value(&tokens, open, close, "username");
    let password = direct_attribute_value(&tokens, open, close, "password"); // secret-scan-allow: parsed credential reference, not a literal
    if username.is_some() || password.is_some() {
        append_basic_auth_variants(&mut values, username, password);
        let decoded_username = username.map(decode_backend_quoted_value);
        let decoded_password = password.map(decode_backend_quoted_value); // secret-scan-allow: parsed credential reference, not a literal
        append_basic_auth_variants(
            &mut values,
            decoded_username.as_deref(),
            decoded_password.as_deref(),
        );
    }
    validate_backend_credential_authority(backend_type, &tokens, open, close)?;
    values.sort_unstable();
    values.dedup();
    Ok(values)
}

fn direct_backend_attribute_for_value(
    tokens: &[BackendHclToken],
    backend_open: usize,
    value_index: usize,
) -> Option<&str> {
    let attribute_index = value_index.checked_sub(2)?;
    if !matches!(tokens.get(value_index - 1), Some(BackendHclToken::Equals)) {
        return None;
    }
    let Some(BackendHclToken::Ident(attribute)) = tokens.get(attribute_index) else {
        return None;
    };
    let mut depth = 0usize;
    for token in &tokens[backend_open + 1..attribute_index] {
        match token {
            BackendHclToken::OpenBrace => depth += 1,
            BackendHclToken::CloseBrace => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    (depth == 0).then_some(attribute.as_str())
}

fn unknown_backend_attribute(backend_type: &str, attribute: &str) -> RunnerError {
    RunnerError::Spawn(format!(
        "live Terraform {backend_type:?} backend attribute {attribute:?} is not in the approved schema; refusing because its sensitivity is unknown"
    ))
}

fn unquoted_backend_secret(backend_type: &str, attribute: &str) -> RunnerError {
    RunnerError::Spawn(format!(
        "live Terraform {backend_type:?} backend sensitive attribute {attribute:?} must be a quoted scalar so evidence redaction is complete"
    ))
}

fn complex_backend_scalar(backend_type: &str, attribute: &str) -> RunnerError {
    RunnerError::Spawn(format!(
        "live Terraform {backend_type:?} backend attribute {attribute:?} must be one exact scalar, not an expression"
    ))
}

fn backend_credential_file_error(backend_type: &str, attribute: &str) -> RunnerError {
    RunnerError::Spawn(format!(
        "live Terraform {backend_type:?} backend credential-file attribute {attribute:?} is forbidden; credentials must be resolved through the typed secret manager"
    ))
}

fn backend_implicit_credential_error(backend_type: &str, attribute: &str) -> RunnerError {
    RunnerError::Spawn(format!(
        "live Terraform {backend_type:?} backend implicit credential source {attribute:?} is forbidden; use exact inline scalar credentials from the typed secret manager"
    ))
}

fn append_sensitive_structure_values(
    values: &mut Vec<Vec<u8>>,
    backend_type: &str,
    structure: &str,
    tokens: &[BackendHclToken],
    open: usize,
    close: usize,
) -> Result<(), RunnerError> {
    for token in &tokens[open + 1..close] {
        if let BackendHclToken::Quoted(value) = token {
            append_backend_secret_value(values, value, BackendSecretKind::Opaque);
        }
    }
    for index in open + 1..close.saturating_sub(1) {
        if !matches!(tokens.get(index + 1), Some(BackendHclToken::Equals)) {
            continue;
        }
        let attribute = match &tokens[index] {
            BackendHclToken::Ident(attribute) => attribute.as_str(),
            BackendHclToken::Quoted(attribute)
                if backend_type == "kubernetes" && structure == "labels" =>
            {
                attribute.as_str()
            }
            BackendHclToken::Quoted(attribute) => {
                return Err(unknown_nested_backend_attribute(
                    backend_type,
                    structure,
                    attribute,
                ));
            }
            _ => continue,
        };
        if !backend_nested_attribute_allowed(backend_type, structure, attribute) {
            return Err(unknown_nested_backend_attribute(
                backend_type,
                structure,
                attribute,
            ));
        }
        if backend_credential_file_attribute(backend_type, attribute) {
            return Err(backend_credential_file_error(backend_type, attribute));
        }
        if backend_implicit_credential_attribute(backend_type, attribute) {
            return Err(backend_implicit_credential_error(backend_type, attribute));
        }
        if backend_secret_kind(backend_type, attribute).is_some()
            && !matches!(tokens.get(index + 2), Some(BackendHclToken::Quoted(_)))
        {
            return Err(unquoted_backend_secret(backend_type, attribute));
        }
        if matches!(tokens.get(index + 2), Some(BackendHclToken::Quoted(_)))
            && !quoted_backend_scalar_is_complete(tokens, index + 2)
        {
            return Err(complex_backend_scalar(backend_type, attribute));
        }
        let exact_quoted = matches!(tokens.get(index + 2), Some(BackendHclToken::Quoted(_)))
            && quoted_backend_scalar_is_complete(tokens, index + 2);
        if matches!(
            (backend_type, structure),
            ("s3", "endpoints") | ("kubernetes", "labels")
        ) && !exact_quoted
        {
            return Err(complex_backend_scalar(backend_type, attribute));
        }
        if !matches!(
            tokens.get(index + 2),
            Some(BackendHclToken::Quoted(_) | BackendHclToken::OpenBrace)
        ) && !backend_nested_public_unquoted(backend_type, structure, attribute)
        {
            return Err(unquoted_backend_secret(backend_type, attribute));
        }
    }
    Ok(())
}

fn unknown_nested_backend_attribute(
    backend_type: &str,
    structure: &str,
    attribute: &str,
) -> RunnerError {
    RunnerError::Spawn(format!(
        "live Terraform {backend_type:?} backend nested attribute {structure}.{attribute} is not in the approved closed schema"
    ))
}

fn validate_backend_credential_authority(
    backend_type: &str,
    tokens: &[BackendHclToken],
    open: usize,
    close: usize,
) -> Result<(), RunnerError> {
    let has = |attribute: &str| {
        direct_attribute_occurrences(tokens, open, close, attribute) == 1
            && direct_attribute_value(tokens, open, close, attribute)
                .is_some_and(|value| !value.is_empty())
    };
    let exact_bool = |attribute: &str, value: &str| {
        direct_attribute_occurrences(tokens, open, close, attribute) == 1
            && direct_identifier_attribute_value(tokens, open, close, attribute) == Some(value)
    };
    let admitted = match backend_type {
        "s3" => {
            if !exact_bool("skip_metadata_api_check", "true") {
                return Err(backend_credential_authority_error(
                    backend_type,
                    "skip_metadata_api_check must be the exact bare value true",
                ));
            }
            has("access_key") && has("secret_key")
        }
        "azurerm" => {
            for flag in [
                "use_cli",
                "use_msi",
                "use_oidc",
                "use_aks_workload_identity",
            ] {
                if !exact_bool(flag, "false") {
                    return Err(backend_credential_authority_error(
                        backend_type,
                        &format!("{flag} must be the exact bare value false"),
                    ));
                }
            }
            if direct_attribute_occurrences(tokens, open, close, "lookup_blob_endpoint") > 0
                && !exact_bool("lookup_blob_endpoint", "false")
            {
                return Err(backend_credential_authority_error(
                    backend_type,
                    "lookup_blob_endpoint must be absent or the exact bare value false",
                ));
            }
            let azuread_mode_absent_or_false =
                direct_attribute_occurrences(tokens, open, close, "use_azuread_auth") == 0
                    || exact_bool("use_azuread_auth", "false");
            let shared_key = (has("access_key") ^ has("sas_token"))
                && !has("client_secret")
                && !has("client_certificate")
                && azuread_mode_absent_or_false;
            let service_principal = exact_bool("use_azuread_auth", "true")
                && (has("client_secret") ^ has("client_certificate"))
                && has("client_id")
                && has("tenant_id")
                && !has("access_key")
                && !has("sas_token");
            shared_key || service_principal
        }
        "oss" => has("access_key") && has("secret_key"),
        "cos" => has("secret_id") && has("secret_key"),
        "gcs" => has("access_token"),
        "etcdv3" => has("username") && has("password"),
        "kubernetes" => {
            if !exact_bool("load_config_file", "false") || !exact_bool("in_cluster_config", "false")
            {
                return Err(backend_credential_authority_error(
                    backend_type,
                    "load_config_file and in_cluster_config must both be the exact bare value false",
                ));
            }
            let token = has("token");
            let username = has("username");
            let password = has("password");
            let certificate = has("client_certificate");
            let private_key = has("client_key");
            let basic = username && password;
            let mtls = certificate && private_key;
            has("host")
                && username == password
                && certificate == private_key
                && (token as u8) + (basic as u8) + (mtls as u8) == 1
        }
        _ => true,
    };
    if admitted {
        Ok(())
    } else {
        Err(backend_credential_authority_error(
            backend_type,
            "a complete approved inline credential set is required",
        ))
    }
}

fn backend_credential_authority_error(backend_type: &str, requirement: &str) -> RunnerError {
    RunnerError::Spawn(format!(
        "live Terraform {backend_type:?} backend cannot use ambient or default credential authority; {requirement}"
    ))
}

fn append_backend_secret_value(
    values: &mut Vec<Vec<u8>>,
    value: &str,
    secret_kind: BackendSecretKind,
) {
    if value.is_empty() {
        return;
    }
    values.push(value.as_bytes().to_vec());
    append_go_json_escape_variants(values, value.as_bytes());
    append_backend_secret_components(values, value, secret_kind);
    let quoted_json = format!("\"{value}\"");
    if let Ok(decoded) = serde_json::from_str::<String>(&quoted_json) {
        if !decoded.is_empty() && decoded.as_bytes() != value.as_bytes() {
            append_backend_secret_components(values, &decoded, secret_kind);
            append_go_json_escape_variants(values, decoded.as_bytes());
            values.push(decoded.into_bytes());
        }
    }
}

fn append_backend_secret_components(
    values: &mut Vec<Vec<u8>>,
    value: &str,
    secret_kind: BackendSecretKind,
) {
    if matches!(
        secret_kind,
        BackendSecretKind::ConnectionString | BackendSecretKind::Opaque
    ) {
        append_connection_string_components(values, value);
    }
    if secret_kind == BackendSecretKind::Token && value.contains('=') {
        append_query_string_components(values, value);
    }
    if secret_kind == BackendSecretKind::BasicAuth {
        if let Some((username, password)) = value.split_once(':') {
            append_basic_auth_variants(values, Some(username), Some(password));
        }
    }
}

fn append_connection_string_components(values: &mut Vec<Vec<u8>>, connection_string: &str) {
    let Ok(parsed) = url::Url::parse(connection_string) else {
        return;
    };
    if !parsed.username().is_empty() {
        values.push(parsed.username().as_bytes().to_vec());
        let decoded = percent_decode_url_component(parsed.username());
        if decoded.as_slice() != parsed.username().as_bytes() {
            values.push(decoded);
        }
    }
    if let Some(password) = parsed.password().filter(|value| !value.is_empty()) {
        values.push(password.as_bytes().to_vec());
        let decoded = percent_decode_url_component(password);
        if decoded.as_slice() != password.as_bytes() {
            values.push(decoded);
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        let raw_username = parsed.username();
        let raw_password = parsed.password(); // secret-scan-allow: parsed credential reference, not a literal
        append_basic_auth_variants(values, Some(raw_username), raw_password);
        let decoded_username = percent_decode_url_component(raw_username);
        let decoded_password = raw_password.map(percent_decode_url_component); // secret-scan-allow: parsed credential reference, not a literal
        if let (Ok(decoded_username), Ok(decoded_password)) = (
            std::str::from_utf8(&decoded_username),
            decoded_password
                .as_deref()
                .map(std::str::from_utf8)
                .transpose(),
        ) {
            append_basic_auth_variants(values, Some(decoded_username), decoded_password);
        }
    }
    if let Some(query) = parsed.query() {
        append_query_string_components(values, query);
    }
}

fn append_query_string_components(values: &mut Vec<Vec<u8>>, query: &str) {
    let query = query.strip_prefix('?').unwrap_or(query);
    for pair in query.split('&') {
        let Some((_, raw_value)) = pair.split_once('=') else {
            continue;
        };
        if raw_value.is_empty() {
            continue;
        }
        values.push(raw_value.as_bytes().to_vec());
        append_go_json_escape_variants(values, raw_value.as_bytes());
        let decoded = percent_decode_url_component(raw_value);
        if decoded.as_slice() != raw_value.as_bytes() {
            append_go_json_escape_variants(values, &decoded);
            values.push(decoded);
        }
    }
    for (_, decoded_value) in url::form_urlencoded::parse(query.as_bytes()) {
        if !decoded_value.is_empty() {
            append_go_json_escape_variants(values, decoded_value.as_bytes());
            values.push(decoded_value.as_bytes().to_vec());
        }
    }
}

fn append_basic_auth_variants(
    values: &mut Vec<Vec<u8>>,
    username: Option<&str>,
    password_value: Option<&str>,
) {
    let username = username.filter(|value| !value.is_empty());
    let password_value = password_value.filter(|value| !value.is_empty());
    if username.is_none() && password_value.is_none() {
        return;
    }
    if let Some(username) = username {
        values.push(username.as_bytes().to_vec());
        append_go_json_escape_variants(values, username.as_bytes());
    }
    if let Some(password_value) = password_value {
        values.push(password_value.as_bytes().to_vec());
        append_go_json_escape_variants(values, password_value.as_bytes());
    }
    if let Some(variants) = basic_auth_canonical_variants(
        username.map(str::as_bytes),
        password_value.map(str::as_bytes),
    ) {
        values.extend(variants);
    }
}

fn percent_decode_url_component(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = (
                bytes.get(index + 1).and_then(|byte| hex_value(*byte)),
                bytes.get(index + 2).and_then(|byte| hex_value(*byte)),
            );
            if let (Some(high), Some(low)) = pair {
                decoded.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    decoded
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
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
            b'<' if bytes.get(index + 1) == Some(&b'<') => {
                return Err(RunnerError::Spawn(
                    "live Terraform backend heredoc expressions are unsupported; use an exact quoted scalar"
                        .to_string(),
                ));
            }
            b'"' => {
                index += 1;
                let start = index;
                let mut closed = false;
                while index < bytes.len() {
                    match bytes[index] {
                        b'\\' => index = (index + 2).min(bytes.len()),
                        b'"' => {
                            let value = &template[start..index];
                            validate_backend_quoted_syntax(value)?;
                            tokens.push(BackendHclToken::Quoted(value.to_string()));
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
            byte if byte.is_ascii_whitespace() => index += 1,
            _ => {
                // Preserve every non-whitespace syntax character so an exact
                // scalar cannot be mistaken for the leading token of an HCL
                // expression merely because its operators were skipped.
                tokens.push(BackendHclToken::Other(bytes[index]));
                index += 1;
            }
        }
    }

    Ok(tokens)
}

fn validate_backend_quoted_syntax(value: &str) -> Result<(), RunnerError> {
    if value.contains("${") || value.contains("%{") || value.contains("\\U") {
        return Err(RunnerError::Spawn(
            "live Terraform backend quoted values cannot use HCL templates or unsupported Unicode escapes"
                .to_string(),
        ));
    }
    if value.contains('\\') {
        let quoted_json = format!("\"{value}\"");
        if serde_json::from_str::<String>(&quoted_json).is_err() {
            return Err(RunnerError::Spawn(
                "live Terraform backend quoted value uses an unsupported escape sequence"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn quoted_backend_scalar_is_complete(tokens: &[BackendHclToken], value_index: usize) -> bool {
    match tokens.get(value_index + 1) {
        None | Some(BackendHclToken::CloseBrace) => true,
        Some(BackendHclToken::Ident(_)) => matches!(
            tokens.get(value_index + 2),
            Some(BackendHclToken::Equals | BackendHclToken::OpenBrace)
        ),
        _ => false,
    }
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
                if attribute_names.contains(&name.as_str())
                    && quoted_backend_scalar_is_complete(tokens, index + 2)
                    && value.contains(STATE_KEY_PLACEHOLDER)
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
                if quoted_backend_scalar_is_complete(tokens, index + 2) {
                    return Some(value);
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
    None
}

fn direct_identifier_attribute_value<'a>(
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
            if let Some(BackendHclToken::Ident(value)) = tokens.get(index + 2) {
                if quoted_backend_scalar_is_complete(tokens, index + 2) {
                    return Some(value);
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
    None
}

fn direct_attribute_occurrences(
    tokens: &[BackendHclToken],
    open: usize,
    close: usize,
    attribute_name: &str,
) -> usize {
    let mut occurrences = 0usize;
    let mut depth = 0usize;
    let mut index = open + 1;
    while index < close {
        if depth == 0
            && matches!(tokens.get(index), Some(BackendHclToken::Ident(name)) if name == attribute_name)
            && matches!(
                tokens.get(index + 1),
                Some(BackendHclToken::Equals | BackendHclToken::OpenBrace)
            )
        {
            occurrences += 1;
        }

        match &tokens[index] {
            BackendHclToken::OpenBrace => depth += 1,
            BackendHclToken::CloseBrace => depth = depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    occurrences
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

fn locate_backend_block(tokens: &[BackendHclToken]) -> Result<(String, usize, usize), RunnerError> {
    let invalid_shape = || {
        RunnerError::Spawn(
            "live Terraform backend template must be exactly one root terraform block containing exactly one backend block"
                .to_string(),
        )
    };
    if !matches!(tokens.first(), Some(BackendHclToken::Ident(name)) if name == "terraform")
        || !matches!(tokens.get(1), Some(BackendHclToken::OpenBrace))
    {
        return Err(invalid_shape());
    }
    let terraform_close = matching_hcl_brace(tokens, 1).ok_or_else(invalid_shape)?;
    if terraform_close + 1 != tokens.len() {
        return Err(invalid_shape());
    }
    let (
        Some(BackendHclToken::Ident(backend)),
        Some(BackendHclToken::Quoted(backend_type)),
        Some(BackendHclToken::OpenBrace),
    ) = (tokens.get(2), tokens.get(3), tokens.get(4))
    else {
        return Err(invalid_shape());
    };
    if backend != "backend" {
        return Err(invalid_shape());
    }
    let backend_close = matching_hcl_brace(tokens, 4).ok_or_else(invalid_shape)?;
    if backend_close + 1 != terraform_close {
        return Err(invalid_shape());
    }
    Ok((backend_type.clone(), 4, backend_close))
}

fn compute_backend_authority_digest(
    rendered_hcl: &str,
    expected_backend_type: &str,
) -> Result<String, RunnerError> {
    const DIGEST_SCHEMA: &str = "ryuki.backend-authority-token-stream.v1";

    let tokens = tokenize_backend_hcl(rendered_hcl)?;
    let (backend_type, backend_open, _) = locate_backend_block(&tokens)?;
    if backend_type != expected_backend_type {
        return Err(RunnerError::Spawn(
            "live Terraform backend type changed before authority digesting".to_string(),
        ));
    }

    let mut canonical = Vec::new();
    append_backend_authority_component(&mut canonical, b'V', DIGEST_SCHEMA.as_bytes());
    append_backend_authority_component(
        &mut canonical,
        b'P',
        BACKEND_CREDENTIAL_AUTHORITY_POLICY_VERSION.as_bytes(),
    );
    append_backend_authority_component(&mut canonical, b'B', backend_type.as_bytes());

    for (index, token) in tokens.iter().enumerate() {
        match token {
            BackendHclToken::Ident(value) => {
                append_backend_authority_component(&mut canonical, b'I', value.as_bytes());
            }
            BackendHclToken::Quoted(value) => {
                let decoded = decode_backend_quoted_value(value);
                let attribute = direct_backend_attribute_for_value(&tokens, backend_open, index);
                if let Some(attribute) = attribute {
                    if let Some(secret_kind) = backend_secret_kind(&backend_type, attribute) {
                        if secret_kind == BackendSecretKind::ConnectionString {
                            if let Some(sanitized) = sanitized_backend_url_authority(&decoded) {
                                append_backend_authority_component(
                                    &mut canonical,
                                    b'U',
                                    &sanitized,
                                );
                            } else {
                                append_backend_secret_authority_marker(
                                    &mut canonical,
                                    &backend_type,
                                    attribute,
                                    secret_kind,
                                );
                            }
                        } else {
                            append_backend_secret_authority_marker(
                                &mut canonical,
                                &backend_type,
                                attribute,
                                secret_kind,
                            );
                        }
                        continue;
                    }
                }
                if let Some(sanitized) = sanitized_backend_url_authority(&decoded) {
                    append_backend_authority_component(&mut canonical, b'U', &sanitized);
                } else {
                    append_backend_authority_component(&mut canonical, b'Q', decoded.as_bytes());
                }
            }
            BackendHclToken::Equals => {
                append_backend_authority_component(&mut canonical, b'=', &[]);
            }
            BackendHclToken::OpenBrace => {
                append_backend_authority_component(&mut canonical, b'{', &[]);
            }
            BackendHclToken::CloseBrace => {
                append_backend_authority_component(&mut canonical, b'}', &[]);
            }
            BackendHclToken::Other(value) => {
                append_backend_authority_component(&mut canonical, b'O', &[*value]);
            }
        }
    }
    Ok(sha256_hex(&canonical))
}

fn append_backend_authority_component(canonical: &mut Vec<u8>, tag: u8, value: &[u8]) {
    canonical.push(tag);
    canonical.extend_from_slice(&(value.len() as u64).to_be_bytes());
    canonical.extend_from_slice(value);
}

fn append_backend_secret_authority_marker(
    canonical: &mut Vec<u8>,
    backend_type: &str,
    attribute: &str,
    kind: BackendSecretKind,
) {
    append_backend_authority_component(canonical, b'S', backend_type.as_bytes());
    append_backend_authority_component(canonical, b'A', attribute.as_bytes());
    append_backend_authority_component(canonical, b'K', backend_secret_kind_name(kind).as_bytes());
    append_backend_authority_component(canonical, b'R', b"validated-inline-scalar");
}

fn backend_secret_kind_name(kind: BackendSecretKind) -> &'static str {
    match kind {
        BackendSecretKind::Opaque => "opaque",
        BackendSecretKind::AccessKey => "access-key",
        BackendSecretKind::Token => "token",
        BackendSecretKind::Password => "password",
        BackendSecretKind::User => "user",
        BackendSecretKind::BasicAuth => "basic-auth",
        BackendSecretKind::ConnectionString => "connection-string",
        BackendSecretKind::PrivateKey => "private-key",
        BackendSecretKind::Certificate => "certificate",
    }
}

fn decode_backend_quoted_value(value: &str) -> String {
    if value.contains('\\') {
        let quoted_json = format!("\"{value}\"");
        if let Ok(decoded) = serde_json::from_str::<String>(&quoted_json) {
            return decoded;
        }
    }
    value.to_string()
}

fn sanitized_backend_url_authority(value: &str) -> Option<Vec<u8>> {
    let parsed = url::Url::parse(value).ok()?;
    let mut canonical = Vec::new();
    append_backend_authority_component(&mut canonical, b'S', parsed.scheme().as_bytes());
    if !parsed.username().is_empty() {
        append_backend_authority_component(&mut canonical, b'U', b"secret-userinfo");
    }
    if parsed.password().is_some() {
        append_backend_authority_component(&mut canonical, b'W', b"secret-password");
    }
    if let Some(host) = parsed.host_str() {
        append_backend_authority_component(&mut canonical, b'H', host.as_bytes());
    }
    if let Some(port) = parsed.port() {
        append_backend_authority_component(&mut canonical, b'P', &port.to_be_bytes());
    }
    append_backend_authority_component(&mut canonical, b'/', parsed.path().as_bytes());
    for (name, _) in parsed.query_pairs() {
        append_backend_authority_component(&mut canonical, b'N', name.as_bytes());
        append_backend_authority_component(&mut canonical, b'V', b"secret-query-value");
    }
    if parsed.fragment().is_some() {
        append_backend_authority_component(&mut canonical, b'F', b"redacted-fragment");
    }
    Some(canonical)
}

fn validate_backend_template(template: &str) -> Result<(String, usize, usize), RunnerError> {
    let tokens = tokenize_backend_hcl(template)?;
    let (backend_type, open, close) = locate_backend_block(&tokens)?;

    if backend_type == "remote" {
        return Err(RunnerError::Spawn(
            "live Terraform remote backend execution is forbidden by the local runner containment policy"
                .to_string(),
        ));
    }
    if backend_type == "pg" {
        return Err(RunnerError::Spawn(
            "live Terraform pg backend is forbidden because libpq can load ambient OS-home TLS client identity"
                .to_string(),
        ));
    }

    if backend_type == "local" {
        if direct_attribute_occurrences(&tokens, open, close, "workspace_dir") != 0 {
            return Err(RunnerError::Spawn(
                "live Terraform \"local\" backend workspace_dir is unsupported; every state artifact must remain one direct child of the configured agent-owned root"
                    .to_string(),
            ));
        }
        let Some(path) = direct_attribute_value(&tokens, open, close, "path") else {
            return Err(RunnerError::Spawn(format!(
                "live Terraform {backend_type:?} backend state-location attribute must contain the exact {STATE_KEY_PLACEHOLDER} placeholder"
            )));
        };
        if !path.contains(STATE_KEY_PLACEHOLDER) {
            return Err(RunnerError::Spawn(format!(
                "live Terraform {backend_type:?} backend state-location attribute must contain the exact {STATE_KEY_PLACEHOLDER} placeholder"
            )));
        }
        let decoded_path = decode_backend_quoted_value(path);
        if !Path::new(&decoded_path).is_absolute() {
            return Err(RunnerError::Spawn(
                "live Terraform \"local\" backend path must be absolute so state persists across fresh workspaces"
                    .to_string(),
            ));
        }
        validate_canonical_local_state_path(&decoded_path)?;
        backend_redaction_values(template, &backend_type)?;
        return Ok((backend_type, open, close));
    }

    if backend_type == "http" {
        let Some(address) = direct_attribute_value(&tokens, open, close, "address") else {
            return Err(RunnerError::Spawn(format!(
                "live Terraform {backend_type:?} backend state-location attribute must contain the exact {STATE_KEY_PLACEHOLDER} placeholder"
            )));
        };
        validate_canonical_http_state_address(&decode_backend_quoted_value(address))?;
        backend_redaction_values(template, &backend_type)?;
        validate_http_locking_contract(&tokens, open, close)?;
        return Ok((backend_type, open, close));
    }

    match backend_location_contains_state_key(&backend_type, &tokens, open, close) {
        Some(true) => {
            backend_redaction_values(template, &backend_type)?;
            if backend_type == "s3" {
                validate_s3_locking_contract(&tokens, open, close)?;
            }
            Ok((backend_type, open, close))
        }
        Some(false) => Err(RunnerError::Spawn(format!(
            "live Terraform {backend_type:?} backend state-location attribute must contain the exact {STATE_KEY_PLACEHOLDER} placeholder"
        ))),
        None => Err(RunnerError::Spawn(format!(
            "live Terraform backend type {backend_type:?} is unsupported because its state-location attribute cannot be proven isolated"
        ))),
    }
}

fn validate_s3_locking_contract(
    tokens: &[BackendHclToken],
    open: usize,
    close: usize,
) -> Result<(), RunnerError> {
    let use_lockfile_count = direct_attribute_occurrences(tokens, open, close, "use_lockfile");
    let lockfile_enabled = use_lockfile_count == 1
        && direct_identifier_attribute_value(tokens, open, close, "use_lockfile") == Some("true");
    if use_lockfile_count > 1
        || (use_lockfile_count == 1
            && direct_identifier_attribute_value(tokens, open, close, "use_lockfile")
                != Some("true"))
    {
        return Err(RunnerError::Spawn(
            "live Terraform \"s3\" backend use_lockfile must be the exact bare value true when present"
                .to_string(),
        ));
    }

    let dynamodb_count = direct_attribute_occurrences(tokens, open, close, "dynamodb_table");
    let dynamodb_lock = if dynamodb_count == 1 {
        direct_attribute_value(tokens, open, close, "dynamodb_table").is_some_and(|table| {
            (3..=255).contains(&table.len())
                && table
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    } else {
        false
    };
    if dynamodb_count > 1 || (dynamodb_count == 1 && !dynamodb_lock) {
        return Err(RunnerError::Spawn(
            "live Terraform \"s3\" backend dynamodb_table must be one canonical non-empty table name"
                .to_string(),
        ));
    }
    if lockfile_enabled || dynamodb_lock {
        Ok(())
    } else {
        Err(RunnerError::Spawn(
            "live Terraform \"s3\" backend requires reviewed state locking: use_lockfile = true or one canonical dynamodb_table"
                .to_string(),
        ))
    }
}

fn validate_http_locking_contract(
    tokens: &[BackendHclToken],
    open: usize,
    close: usize,
) -> Result<(), RunnerError> {
    let one_quoted = |attribute: &str| {
        (direct_attribute_occurrences(tokens, open, close, attribute) == 1)
            .then(|| direct_attribute_value(tokens, open, close, attribute))
            .flatten()
    };
    let lock_address = one_quoted("lock_address").ok_or_else(|| {
        RunnerError::Spawn(
            "live Terraform \"http\" backend requires exactly one quoted lock_address".to_string(),
        )
    })?;
    let unlock_address = one_quoted("unlock_address").ok_or_else(|| {
        RunnerError::Spawn(
            "live Terraform \"http\" backend requires exactly one quoted unlock_address"
                .to_string(),
        )
    })?;
    let lock_method = one_quoted("lock_method");
    let unlock_method = one_quoted("unlock_method");
    if lock_method != Some("LOCK") || unlock_method != Some("UNLOCK") {
        return Err(RunnerError::Spawn(
            "live Terraform \"http\" backend requires lock_method = \"LOCK\" and unlock_method = \"UNLOCK\""
                .to_string(),
        ));
    }

    let lock_address = decode_backend_quoted_value(lock_address);
    let unlock_address = decode_backend_quoted_value(unlock_address);
    validate_canonical_http_state_address(&lock_address)?;
    validate_canonical_http_state_address(&unlock_address)?;
    let state_address = direct_attribute_value(tokens, open, close, "address")
        .map(decode_backend_quoted_value)
        .ok_or_else(|| {
            RunnerError::Spawn(
                "live Terraform \"http\" backend requires exactly one quoted address".to_string(),
            )
        })?;
    let state = url::Url::parse(&state_address).map_err(|_| {
        RunnerError::Spawn("live Terraform \"http\" backend address is invalid".to_string())
    })?;
    for (label, endpoint) in [("lock", &lock_address), ("unlock", &unlock_address)] {
        let endpoint = url::Url::parse(endpoint).map_err(|_| {
            RunnerError::Spawn(format!(
                "live Terraform \"http\" backend {label}_address is invalid"
            ))
        })?;
        if endpoint.scheme() != state.scheme()
            || endpoint.host_str() != state.host_str()
            || endpoint.port_or_known_default() != state.port_or_known_default()
        {
            return Err(RunnerError::Spawn(format!(
                "live Terraform \"http\" backend {label}_address must use the exact state endpoint origin"
            )));
        }
    }
    Ok(())
}

fn validate_canonical_local_state_path(path: &str) -> Result<(), RunnerError> {
    use std::path::Component;

    let canonical_text = !path.ends_with('/')
        && !path.contains("//")
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path.matches(STATE_KEY_PLACEHOLDER).count() == 1
        && path[1..]
            .split('/')
            .all(|component| !matches!(component, "." | ".."));
    let mut placeholder_component = false;
    let canonical_components = Path::new(path)
        .components()
        .all(|component| match component {
            Component::RootDir => true,
            Component::Normal(component) => {
                let Some(component) = component.to_str() else {
                    return false;
                };
                let safe = component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'{' | b'}')
                });
                if component.contains(STATE_KEY_PLACEHOLDER) {
                    placeholder_component = true;
                }
                safe && component != "." && component != ".."
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => false,
        });
    if canonical_text && canonical_components && placeholder_component {
        Ok(())
    } else {
        Err(RunnerError::Spawn(
            "live Terraform \"local\" backend path must be a canonical absolute path with one placeholder-bearing component and no traversal, aliases, backslashes, or controls"
                .to_string(),
        ))
    }
}

fn validate_canonical_http_state_address(address: &str) -> Result<(), RunnerError> {
    let parsed = url::Url::parse(address).map_err(|_| {
        RunnerError::Spawn(
            "live Terraform \"http\" backend address must be an absolute canonical HTTP(S) URL"
                .to_string(),
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(RunnerError::Spawn(
            "live Terraform \"http\" backend address must be an absolute canonical HTTP(S) URL"
                .to_string(),
        ));
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(RunnerError::Spawn(
            "live Terraform \"http\" backend public URL values cannot contain userinfo, query parameters, or fragments"
                .to_string(),
        ));
    }
    let scheme_end = address.find("://").ok_or_else(|| {
        RunnerError::Spawn(
            "live Terraform \"http\" backend address must be an absolute canonical HTTP(S) URL"
                .to_string(),
        )
    })?;
    let authority_and_path = &address[scheme_end + 3..];
    let raw_path = authority_and_path
        .find('/')
        .map_or("/", |path_start| &authority_and_path[path_start..]);
    let decoded_normalized_path = percent_decode_url_component(parsed.path());
    let decoded_normalized_path = std::str::from_utf8(&decoded_normalized_path).map_err(|_| {
        RunnerError::Spawn(
            "live Terraform \"http\" backend address path must be canonical UTF-8".to_string(),
        )
    })?;
    if canonical_http_state_path(raw_path) && canonical_http_state_path(decoded_normalized_path) {
        Ok(())
    } else {
        Err(RunnerError::Spawn(
            "live Terraform \"http\" backend address path must be canonical, unescaped, traversal-free, and contain the exact state placeholder as one server-visible segment"
                .to_string(),
        ))
    }
}

fn canonical_http_state_path(path: &str) -> bool {
    if !path.starts_with('/')
        || path == "/"
        || path.ends_with('/')
        || path.contains("//")
        || path.contains('%')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return false;
    }
    let mut placeholder_segments = 0usize;
    for segment in path[1..].split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return false;
        }
        if segment == STATE_KEY_PLACEHOLDER {
            placeholder_segments += 1;
            continue;
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return false;
        }
    }
    placeholder_segments == 1
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct LocalStateAuthority {
    root: String,
    target: String,
    root_device: u64,
    root_inode: u64,
}

impl LocalStateAuthority {
    fn new(root: &Path, target: &Path) -> Result<Self, RunnerError> {
        let (root, root_device, root_inode) = validate_private_local_state_root(root)?;
        if target.parent() != Some(root.as_path()) || target.file_name().is_none() {
            return Err(RunnerError::Spawn(
                "live Terraform \"local\" backend state must be a direct child of RYUKI_AGENT_LOCAL_STATE_ROOT"
                    .to_string(),
            ));
        }
        let target = target.to_str().ok_or_else(|| {
            RunnerError::Spawn(
                "live Terraform \"local\" backend state path must be canonical UTF-8".to_string(),
            )
        })?;
        let authority = Self {
            root: root.to_string_lossy().into_owned(),
            target: target.to_string(),
            root_device,
            root_inode,
        };
        authority.revalidate()?;
        Ok(authority)
    }

    fn revalidate(&self) -> Result<(), RunnerError> {
        let (root, device, inode) = validate_private_local_state_root(Path::new(&self.root))?;
        if device != self.root_device || inode != self.root_inode {
            return Err(RunnerError::Spawn(
                "live Terraform local state root identity changed after admission".to_string(),
            ));
        }
        let target = Path::new(&self.target);
        if target.parent() != Some(root.as_path()) {
            return Err(RunnerError::Spawn(
                "live Terraform local state target escaped its admitted root".to_string(),
            ));
        }
        validate_private_local_state_artifact(target)?;
        let backup = std::path::PathBuf::from(format!("{}.backup", self.target));
        validate_private_local_state_artifact(&backup)?;
        let file_name = target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| RunnerError::Spawn("local state filename is invalid".to_string()))?;
        let lock = root.join(format!(".{file_name}.lock.info"));
        validate_private_local_state_artifact(&lock)?;
        Ok(())
    }
}

#[cfg(unix)]
fn validate_private_local_state_root(
    root: &Path,
) -> Result<(std::path::PathBuf, u64, u64), RunnerError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if !root.is_absolute() {
        return Err(RunnerError::Spawn(
            "RYUKI_AGENT_LOCAL_STATE_ROOT must be an absolute path".to_string(),
        ));
    }
    let canonical = std::fs::canonicalize(root).map_err(|error| {
        RunnerError::Spawn(format!(
            "cannot resolve RYUKI_AGENT_LOCAL_STATE_ROOT: {error}"
        ))
    })?;
    if canonical != root {
        return Err(RunnerError::Spawn(
            "RYUKI_AGENT_LOCAL_STATE_ROOT must already be canonical and contain no symlink component"
                .to_string(),
        ));
    }
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&canonical)
        .map_err(|error| {
            RunnerError::Spawn(format!(
                "cannot open RYUKI_AGENT_LOCAL_STATE_ROOT without following links: {error}"
            ))
        })?;
    let metadata = handle.metadata().map_err(|error| {
        RunnerError::Spawn(format!(
            "cannot inspect RYUKI_AGENT_LOCAL_STATE_ROOT: {error}"
        ))
    })?;
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 {
        return Err(RunnerError::Spawn(
            "RYUKI_AGENT_LOCAL_STATE_ROOT must be an agent-owned directory with no group/other permissions"
                .to_string(),
        ));
    }
    Ok((canonical, metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn validate_private_local_state_root(
    _root: &Path,
) -> Result<(std::path::PathBuf, u64, u64), RunnerError> {
    Err(RunnerError::Spawn(
        "live Terraform local backend requires a reviewed no-follow ownership adapter on this platform"
            .to_string(),
    ))
}

#[cfg(unix)]
fn validate_private_local_state_artifact(path: &Path) -> Result<(), RunnerError> {
    use std::io::ErrorKind;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let link_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(RunnerError::Spawn(format!(
                "cannot inspect local state artifact {:?}: {error}",
                path
            )));
        }
    };
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(RunnerError::Spawn(format!(
            "local state artifact {:?} must be one regular non-symlink file",
            path
        )));
    }
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            RunnerError::Spawn(format!(
                "cannot open local state artifact {:?} without following links: {error}",
                path
            ))
        })?;
    let metadata = handle.metadata().map_err(|error| {
        RunnerError::Spawn(format!(
            "cannot inspect local state artifact {:?}: {error}",
            path
        ))
    })?;
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.dev() != link_metadata.dev()
        || metadata.ino() != link_metadata.ino()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(RunnerError::Spawn(format!(
            "local state artifact {:?} changed during admission or is not an agent-owned private regular file",
            path
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_local_state_artifact(_path: &Path) -> Result<(), RunnerError> {
    Err(RunnerError::Spawn(
        "live Terraform local backend requires a reviewed no-follow ownership adapter on this platform"
            .to_string(),
    ))
}

/// A backend HCL config whose state-key placeholder has been safely rendered.
///
/// The fields stay private so live Terraform callers cannot bypass
/// [`IsolatedBackendConfig::from_template`] with arbitrary shared backend HCL.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IsolatedBackendConfig {
    hcl: String,
    state_key: String,
    backend_kind: String,
    backend_authority_digest: String,
    redaction_values: Vec<Vec<u8>>,
    local_state_authority: Option<LocalStateAuthority>,
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
        Self::from_template_with_local_state_root(template, state_key, None)
    }

    /// Render a backend template while binding a local backend to one
    /// configured, descriptor-validated agent-owned root. Non-local backends
    /// ignore `local_state_root`; a local backend always requires it.
    pub fn from_template_with_local_state_root(
        template: &str,
        state_key: &str,
        local_state_root: Option<&Path>,
    ) -> Result<Self, RunnerError> {
        validate_state_key(state_key)?;
        let (backend_type, _, _) = validate_backend_template(template)?;

        let hcl = template.replace(STATE_KEY_PLACEHOLDER, state_key);
        // Re-tokenize and re-locate the single active backend after rendering;
        // no pre-render token position is trusted across substitution.
        let redaction_values = backend_redaction_values(&hcl, &backend_type)?;
        let backend_authority_digest = compute_backend_authority_digest(&hcl, &backend_type)?;
        let local_state_authority = if backend_type == "local" {
            let root = local_state_root.ok_or_else(|| {
                RunnerError::Spawn(
                    "live Terraform \"local\" backend requires RYUKI_AGENT_LOCAL_STATE_ROOT"
                        .to_string(),
                )
            })?;
            let rendered_tokens = tokenize_backend_hcl(&hcl)?;
            let (_, open, close) = locate_backend_block(&rendered_tokens)?;
            let target = direct_attribute_value(&rendered_tokens, open, close, "path")
                .map(decode_backend_quoted_value)
                .ok_or_else(|| {
                    RunnerError::Spawn(
                        "live Terraform \"local\" backend requires one quoted state path"
                            .to_string(),
                    )
                })?;
            Some(LocalStateAuthority::new(root, Path::new(&target))?)
        } else {
            None
        };

        Ok(Self {
            hcl,
            state_key: state_key.to_string(),
            backend_kind: backend_type,
            backend_authority_digest,
            redaction_values,
            local_state_authority,
        })
    }

    /// The validated control-plane key represented by this backend config.
    pub fn state_key(&self) -> &str {
        &self.state_key
    }

    /// Backend type parsed from the single active, isolation-validated backend
    /// block (for example `s3`, `azurerm`, or `local`). No HCL values are exposed.
    pub fn backend_kind(&self) -> &str {
        &self.backend_kind
    }

    /// SHA-256 commitment to the validated backend authority and destination.
    /// Sensitive scalar values are represented only by typed policy markers,
    /// so credential rotation does not change this non-secret digest.
    pub fn backend_authority_digest(&self) -> &str {
        &self.backend_authority_digest
    }

    fn redaction_values(&self) -> &[Vec<u8>] {
        &self.redaction_values
    }

    fn revalidate_local_state_authority(&self) -> Result<(), RunnerError> {
        if let Some(authority) = &self.local_state_authority {
            authority.revalidate()?;
        }
        Ok(())
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
/// - `outcome.log` — allowlisted plan evidence with a full canonical-plan hash.
///   The caller uses these deterministic bytes to compute the existing gate
///   digest without persisting the full plan.
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
/// - `RunnerError::Spawn` if the configured Terraform executable does not pass
///   path provenance and identity/version approval.
/// - `RunnerError::CredInjection` if any secret variable name or the offering
///   slug is invalid.
/// - `RunnerError::WorkspaceSetup` if workspace initialisation fails.
/// - `RunnerError::Timeout` if any subprocess exceeds `LIVE_RUNNER_TIMEOUT`.
pub fn run_live_plan(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
) -> Result<LivePlanArtifacts, RunnerError> {
    run_live_plan_inner(plan, creds, backend_config, None)
}

/// Cancellation-aware live plan entry point. The same signal covers the
/// version probe and every Terraform phase.
pub fn run_live_plan_with_cancellation(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
    cancellation: &CommandCancellation,
) -> Result<LivePlanArtifacts, RunnerError> {
    run_live_plan_inner(plan, creds, backend_config, Some(cancellation))
}

fn run_live_plan_inner(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
    cancellation: Option<&CommandCancellation>,
) -> Result<LivePlanArtifacts, RunnerError> {
    if plan.mode != RunMode::Live {
        return Err(RunnerError::Spawn(format!(
            "run_live_plan only accepts RunMode::Live; got {:?}",
            plan.mode
        )));
    }

    // Resolve and verify the top-level CLI before credential material reaches
    // a command-construction path. Bare/PATH-selected binaries never cross
    // this boundary.
    let executable = ApprovedExecutable::configured(ApprovedTool::Terraform, cancellation)?;
    live_terraform_plan_inner(&executable, plan, creds, backend_config, cancellation)
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
    run_live_apply_inner(plan, creds, backend_config, tfplan, None)
}

/// Cancellation-aware saved-plan apply entry point.
pub fn run_live_apply_with_cancellation(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
    tfplan: &[u8],
    cancellation: &CommandCancellation,
) -> Result<RunOutcome, RunnerError> {
    run_live_apply_inner(plan, creds, backend_config, tfplan, Some(cancellation))
}

fn run_live_apply_inner(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
    tfplan: &[u8],
    cancellation: Option<&CommandCancellation>,
) -> Result<RunOutcome, RunnerError> {
    if plan.mode != RunMode::Live {
        return Err(RunnerError::Spawn(format!(
            "run_live_apply only accepts RunMode::Live; got {:?}",
            plan.mode
        )));
    }

    let executable = ApprovedExecutable::configured(ApprovedTool::Terraform, cancellation)?;
    live_terraform_apply_inner(
        &executable,
        plan,
        creds,
        backend_config,
        tfplan,
        cancellation,
    )
}

/// Execute a live Terraform destroy of a step's applied resources (#42 B2-3).
///
/// ## Workspace/state reconstruction — which resources get destroyed
///
/// A destroy has NO saved plan artifact. `terraform destroy` computes the
/// destruction set from the STATE, so this function must attach to exactly the
/// state the step's apply produced. It does that by reconstructing the SAME
/// workspace inputs `run_live_apply` used: the offering's embedded IaC bundle,
/// the operator's `backend_config` HCL (written as `ryuki_backend.tf`
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
    run_live_destroy_inner(plan, creds, backend_config, None)
}

/// Cancellation-aware state-driven destroy entry point.
pub fn run_live_destroy_with_cancellation(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
    cancellation: &CommandCancellation,
) -> Result<RunOutcome, RunnerError> {
    run_live_destroy_inner(plan, creds, backend_config, Some(cancellation))
}

fn run_live_destroy_inner(
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
    cancellation: Option<&CommandCancellation>,
) -> Result<RunOutcome, RunnerError> {
    if plan.mode != RunMode::Live {
        return Err(RunnerError::Spawn(format!(
            "run_live_destroy only accepts RunMode::Live; got {:?}",
            plan.mode
        )));
    }

    let executable = ApprovedExecutable::configured(ApprovedTool::Terraform, cancellation)?;
    live_terraform_destroy_inner(&executable, plan, creds, backend_config, cancellation)
}

// ---------------------------------------------------------------------------
// Approved internal implementations plus test-only shim adapters
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

/// Convert the full canonical Terraform plan into the only representation
/// allowed to cross the durable evidence boundary.
///
/// The envelope commits to every canonical plan byte through
/// `canonical_plan_sha256`, so the existing outer evidence digest still changes
/// for any semantic plan change. Only the small server-approval allowlist is
/// retained in `resource_changes`; unknown or malformed changes become a
/// constant rejection sentinel rather than raw provider data. `Err` carries
/// that safe envelope so the caller can persist a diagnostic without ever
/// treating an incomplete projection as an approvable plan.
fn project_plan_evidence(canonical_plan: &str, plan: &RunPlan) -> Result<String, String> {
    let canonical_plan_sha256 = sha256_hex(canonical_plan.as_bytes());
    let parsed = serde_json::from_str::<serde_json::Value>(canonical_plan).ok();
    let raw_changes = parsed
        .as_ref()
        .and_then(|value| value.get("resource_changes"))
        .and_then(serde_json::Value::as_array);

    let mut projection_complete = raw_changes.is_some();
    let mut projected_changes = Vec::new();
    if let Some(raw_changes) = raw_changes {
        for change in raw_changes {
            match project_resource_change(change, plan) {
                Some(projected) => projected_changes.push(projected),
                None => {
                    projection_complete = false;
                    projected_changes.push(unsupported_resource_change());
                }
            }
        }
    } else {
        projected_changes.push(unsupported_resource_change());
    }

    let evidence = serde_json::json!({
        "schema_version": ryuki_protocol::TERRAFORM_LIVE_PLAN_EVIDENCE_SCHEMA_VERSION,
        "canonical_plan_sha256": canonical_plan_sha256,
        "projection_complete": projection_complete,
        "resource_changes": projected_changes,
    })
    .to_string();
    if projection_complete {
        Ok(evidence)
    } else {
        Err(evidence)
    }
}

fn sha256_hex(value: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(value);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn supported_plan_actions(change: &serde_json::Value) -> Option<Vec<serde_json::Value>> {
    let actions = change.get("actions")?.as_array()?;
    let labels: Option<Vec<&str>> = actions.iter().map(serde_json::Value::as_str).collect();
    let labels = labels?;
    match labels.as_slice() {
        ["no-op"]
        | ["read"]
        | ["create"]
        | ["update"]
        | ["delete"]
        | ["delete", "create"]
        | ["create", "delete"] => Some(
            labels
                .into_iter()
                .map(|label| serde_json::Value::String(label.to_string()))
                .collect(),
        ),
        _ => None,
    }
}

fn safe_plan_var<'a>(plan: &'a RunPlan, name: &str) -> Option<&'a str> {
    let value = plan.vars.get(name)?.trim();
    if value.is_empty()
        || value.len() > 160
        || !value.is_ascii()
        || value.chars().any(char::is_control)
        || value.contains("://")
    {
        return None;
    }
    Some(value)
}

fn project_resource_change(
    resource: &serde_json::Value,
    plan: &RunPlan,
) -> Option<serde_json::Value> {
    let mode = resource.get("mode")?.as_str()?;
    let resource_type = resource.get("type")?.as_str()?;
    let logical_name = resource.get("name")?.as_str()?;
    let change = resource.get("change")?;
    let actions = supported_plan_actions(change)?;
    let after = change.get("after")?;

    if mode == "data" {
        let variable = match (resource_type, logical_name) {
            ("vsphere_datacenter", "dc") => "datacenter",
            ("vsphere_compute_cluster", "cluster") => "cluster",
            ("vsphere_datastore", "ds") => "datastore",
            ("vsphere_network", "net") => "network",
            ("vsphere_virtual_machine", "template") => "template",
            _ => return None,
        };
        let expected = safe_plan_var(plan, variable)?;
        if after.get("name")?.as_str()? != expected {
            return None;
        }
        return Some(serde_json::json!({
            "mode": "data",
            "type": resource_type,
            "name": logical_name,
            "change": {
                "actions": actions,
                "after": { "name": expected },
            },
        }));
    }

    let expected_logical_name = match plan.offering_id.as_str() {
        "linux-server-deployment" => "linux_server",
        "windows-server-deployment" => "windows_server",
        _ => return None,
    };
    if mode != "managed"
        || resource_type != "vsphere_virtual_machine"
        || logical_name != expected_logical_name
    {
        return None;
    }

    let expected_name = safe_plan_var(plan, "vm_name")?;
    let expected_cpu = safe_plan_var(plan, "num_cpus")?.parse::<u64>().ok()?;
    let expected_memory = safe_plan_var(plan, "memory_mb")?.parse::<u64>().ok()?;
    let expected_disk = safe_plan_var(plan, "disk_size_gb")?.parse::<u64>().ok()?;
    if after.get("name")?.as_str()? != expected_name
        || after.get("num_cpus")?.as_u64()? != expected_cpu
        || after.get("memory")?.as_u64()? != expected_memory
    {
        return None;
    }
    let disks = after.get("disk")?.as_array()?;
    let [disk] = disks.as_slice() else {
        return None;
    };
    if disk.get("label")?.as_str()? != "disk0" || disk.get("size")?.as_u64()? != expected_disk {
        return None;
    }

    Some(serde_json::json!({
        "mode": "managed",
        "type": "vsphere_virtual_machine",
        "name": expected_logical_name,
        "change": {
            "actions": actions,
            "after": {
                "name": expected_name,
                "num_cpus": expected_cpu,
                "memory": expected_memory,
                "disk": [{ "label": "disk0", "size": expected_disk }],
            },
        },
    }))
}

fn unsupported_resource_change() -> serde_json::Value {
    serde_json::json!({
        "mode": "unsupported",
        "type": "unsupported",
        "name": "unsupported",
        "change": {
            "actions": ["unsupported"],
            "after": {},
        },
    })
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

/// Test seam for command-behavior coverage. The raw shim path is converted to
/// a test-only capability that does not exist in production builds.
///
/// Returns `Planned` ONLY when init exit==0, plan exit==0 or 2, and show
/// exit==0.  Any earlier failure returns `Failed` (fail-closed — no partial
/// plan reaches the digest layer).
#[cfg(test)]
pub(crate) fn live_terraform_plan(
    binary: &str,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
) -> Result<LivePlanArtifacts, RunnerError> {
    let executable = ApprovedExecutable::for_test(binary);
    live_terraform_plan_inner(&executable, plan, creds, backend_config, None)
}

fn live_terraform_plan_inner(
    executable: &ApprovedExecutable,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
    cancellation: Option<&CommandCancellation>,
) -> Result<LivePlanArtifacts, RunnerError> {
    let binary = executable.path();
    // Validate inputs before any workspace or process creation.
    validate_offering_slug(&plan.offering_id)?;
    for name in &plan.secret_var_names {
        validate_var_name(name)?;
    }
    backend_config.revalidate_local_state_authority()?;

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
            raw_plan_digest: None,
            tfplan: vec![],
        });
    }

    // Build secret components for scrubbing.
    let components = Zeroizing::new(credential_components(creds.material.as_slice()));

    // FAIL CLOSED: declared secret vars must pair 1:1 with resolved components
    // BEFORE any workspace or terraform subprocess exists.
    if let Some(err) = credential_arity_error(plan, components.as_slice()) {
        return Err(err);
    }

    let redaction_values = combined_secret_redaction_values(
        &plan.secret_var_names,
        components.as_slice(),
        backend_config,
    )?;
    let secret_refs = redaction_values.refs();
    let cred_str = credential_env_string(creds)?;

    // Binary availability check — terraform-absent-safe.
    if !binary_available(binary, cancellation)? {
        return Ok(LivePlanArtifacts {
            outcome: RunOutcome {
                runner_kind: RunnerKind::Terraform,
                mode: plan.mode,
                status: RunStatus::RunnerUnavailable,
                summary: format!(
                    "runner unavailable: terraform binary not found at {:?}",
                    binary
                ),
                log: String::new(),
                exit_code: None,
                post_apply: None,
            },
            raw_plan_digest: None,
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
    ws.write_file_0600("ryuki_backend.tf", backend_config.hcl.as_bytes())?;

    // Write non-secret vars.
    if !plan.vars.is_empty() {
        let vars_json = vars_to_json(&plan.vars);
        ws.write_file_0600("ryuki.auto.tfvars.json", vars_json.as_bytes())?;
    }

    // --- Step 1: terraform init ---
    // FAIL CLOSED: non-zero exit → Failed, no digest computed.
    backend_config.revalidate_local_state_authority()?;
    let init_outcome = run_tf_step(
        binary,
        TERRAFORM_INIT_ARGS,
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        TfStepControl {
            truncate: true,
            cancellation,
        },
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
            raw_plan_digest: None,
            tfplan: vec![],
        });
    }

    // --- Step 2: terraform plan -out=tfplan ---
    // FAIL CLOSED: exit codes other than 0 or 2 → Failed, no digest computed.
    backend_config.revalidate_local_state_authority()?;
    let plan_step = run_tf_step(
        binary,
        &["plan", "-input=false", "-no-color", "-out=tfplan"],
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        TfStepControl {
            truncate: true,
            cancellation,
        },
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
                raw_plan_digest: None,
                tfplan: vec![],
            });
        }
    }

    // Read the raw binary tfplan file BEFORE step 3 (show) so we can return
    // it alongside the canonical JSON.  These bytes are opaque — do not log them.
    let tfplan_path = ws.path().join("tfplan");
    let tfplan_bytes = read_bounded_tfplan(&tfplan_path)?;

    // --- Step 3: terraform show -json tfplan (canonical plan JSON for digest) ---
    // FAIL CLOSED: non-zero exit → Failed, no digest computed.
    backend_config.revalidate_local_state_authority()?;
    let show_outcome = run_tf_show_json_step(binary, ws.path(), cancellation)?;

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
                log: scrub_output(&show_outcome.raw, &secret_refs),
                exit_code: show_outcome.exit_code,
                post_apply: None,
            },
            raw_plan_digest: None,
            tfplan: vec![],
        });
    }

    // Canonicalize FIRST (strip terraform's non-deterministic `timestamp`) so a
    // LiveApply re-plan of identical config produces the SAME commitment as the
    // approved LivePlan. The complete canonical form remains process-local; the
    // durable value below is an allowlisted projection carrying its SHA-256.
    // `show_outcome.raw` is complete and has not passed through the
    // non-injective redactor. The raw and canonical strings are process-local
    // zeroizing buffers; only the digest and allowlisted projection below may
    // cross the durable evidence boundary.
    let canonical_plan = match canonicalize_plan_json(&show_outcome.raw) {
        Some(json) => Zeroizing::new(json),
        None => {
            return Ok(LivePlanArtifacts {
                outcome: RunOutcome {
                    runner_kind: RunnerKind::Terraform,
                    mode: plan.mode,
                    status: RunStatus::Failed,
                    summary: "terraform show produced non-canonical plan JSON — \
                              refusing to derive a plan-integrity digest"
                        .to_string(),
                    // Redact and truncate the raw output for the failure log
                    // only — it is diagnostic here, not a digest input.
                    log: scrub_output(&show_outcome.raw, &secret_refs),
                    exit_code: show_outcome.exit_code,
                    post_apply: None,
                },
                raw_plan_digest: None,
                tfplan: vec![],
            });
        }
    };
    let raw_plan_digest = sha256_hex(canonical_plan.as_bytes());
    let plan_summary = extract_plan_summary(&plan_step.log);
    let evidence_projection = match project_plan_evidence(&canonical_plan, plan) {
        Ok(evidence) => evidence,
        Err(safe_rejection) => {
            return Ok(LivePlanArtifacts {
                outcome: RunOutcome {
                    runner_kind: RunnerKind::Terraform,
                    mode: plan.mode,
                    status: RunStatus::Failed,
                    summary: "terraform plan contains unsupported or malformed resource semantics — refusing live approval".to_string(),
                    log: safe_rejection,
                    exit_code: show_outcome.exit_code,
                    post_apply: None,
                },
                raw_plan_digest: None,
                tfplan: vec![],
            });
        }
    };

    Ok(LivePlanArtifacts {
        outcome: RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: plan.mode,
            status: RunStatus::Planned,
            summary: plan_summary,
            log: evidence_projection,
            exit_code: show_outcome.exit_code,
            post_apply: None,
        },
        raw_plan_digest: Some(raw_plan_digest),
        tfplan: tfplan_bytes,
    })
}

/// Test seam for apply command-behavior coverage.
///
/// Accepts the raw `tfplan` bytes from `live_terraform_plan` and applies EXACTLY
/// that plan — no re-plan at apply time.  `terraform apply tfplan` exits non-zero
/// if current state has diverged from the saved plan, providing automatic
/// state-drift detection.  `-auto-approve` is intentionally absent.
#[cfg(test)]
pub(crate) fn live_terraform_apply(
    binary: &str,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
    tfplan: &[u8],
) -> Result<RunOutcome, RunnerError> {
    let executable = ApprovedExecutable::for_test(binary);
    live_terraform_apply_inner(&executable, plan, creds, backend_config, tfplan, None)
}

fn live_terraform_apply_inner(
    executable: &ApprovedExecutable,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
    tfplan: &[u8],
    cancellation: Option<&CommandCancellation>,
) -> Result<RunOutcome, RunnerError> {
    let binary = executable.path();
    // Validate inputs.
    validate_offering_slug(&plan.offering_id)?;
    if tfplan.len() > MAX_TFPLAN_BYTES {
        return Err(RunnerError::WorkspaceSetup(format!(
            "tfplan exceeds safe artifact limit ({MAX_TFPLAN_BYTES} bytes)"
        )));
    }
    for name in &plan.secret_var_names {
        validate_var_name(name)?;
    }
    backend_config.revalidate_local_state_authority()?;

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
    let components = Zeroizing::new(credential_components(creds.material.as_slice()));

    // FAIL CLOSED: declared secret vars must pair 1:1 with resolved components
    // BEFORE any workspace or terraform subprocess exists.
    if let Some(err) = credential_arity_error(plan, components.as_slice()) {
        return Err(err);
    }

    let redaction_values = combined_secret_redaction_values(
        &plan.secret_var_names,
        components.as_slice(),
        backend_config,
    )?;
    let secret_refs = redaction_values.refs();
    let cred_str = credential_env_string(creds)?;

    // Binary availability check.
    if !binary_available(binary, cancellation)? {
        return Ok(RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: plan.mode,
            status: RunStatus::RunnerUnavailable,
            summary: format!(
                "runner unavailable: terraform binary not found at {:?}",
                binary
            ),
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
    ws.write_file_0600("ryuki_backend.tf", backend_config.hcl.as_bytes())?;

    if !plan.vars.is_empty() {
        let vars_json = vars_to_json(&plan.vars);
        ws.write_file_0600("ryuki.auto.tfvars.json", vars_json.as_bytes())?;
    }

    // Write the saved tfplan bytes into the workspace (0600 — treat as sensitive).
    // These bytes are opaque binary data; do not log them.
    ws.write_file_0600("tfplan", tfplan)?;

    // --- Step 1: terraform init ---
    backend_config.revalidate_local_state_authority()?;
    let init_outcome = run_tf_step(
        binary,
        TERRAFORM_INIT_ARGS,
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        TfStepControl {
            truncate: true,
            cancellation,
        },
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
    backend_config.revalidate_local_state_authority()?;
    let apply_outcome = run_tf_step(
        binary,
        &["apply", "-input=false", "-no-color", "tfplan"],
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        TfStepControl {
            truncate: true,
            cancellation,
        },
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
            backend_config.revalidate_local_state_authority()?;
            let verdict = post_apply_verdict(
                binary,
                ws.path(),
                &plan.secret_var_names,
                &cred_str,
                &secret_refs,
                cancellation,
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
    binary: &Path,
    ws_path: &std::path::Path,
    secret_names: &[String],
    cred_str: &str,
    secret_refs: &[&[u8]],
    cancellation: Option<&CommandCancellation>,
) -> ryuki_engine::post_apply::PostApplyOutcome {
    use ryuki_engine::post_apply::{classify_post_apply, PostApplyOutcome};
    match run_tf_step(
        binary,
        &["plan", "-input=false", "-no-color"],
        ws_path,
        secret_names,
        cred_str,
        secret_refs,
        TfStepControl {
            truncate: true,
            cancellation,
        },
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

/// Test seam for destroy command-behavior coverage (#42 B2-3).
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
#[cfg(test)]
pub(crate) fn live_terraform_destroy(
    binary: &str,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
) -> Result<RunOutcome, RunnerError> {
    let executable = ApprovedExecutable::for_test(binary);
    live_terraform_destroy_inner(&executable, plan, creds, backend_config, None)
}

fn live_terraform_destroy_inner(
    executable: &ApprovedExecutable,
    plan: &RunPlan,
    creds: &ResolvedCredentials,
    backend_config: &IsolatedBackendConfig,
    cancellation: Option<&CommandCancellation>,
) -> Result<RunOutcome, RunnerError> {
    let binary = executable.path();
    // Validate inputs before any workspace or process creation.
    validate_offering_slug(&plan.offering_id)?;
    for name in &plan.secret_var_names {
        validate_var_name(name)?;
    }
    backend_config.revalidate_local_state_authority()?;

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
    let components = Zeroizing::new(credential_components(creds.material.as_slice()));

    // FAIL CLOSED: declared secret vars must pair 1:1 with resolved components
    // BEFORE any workspace or terraform subprocess exists.
    if let Some(err) = credential_arity_error(plan, components.as_slice()) {
        return Err(err);
    }

    let redaction_values = combined_secret_redaction_values(
        &plan.secret_var_names,
        components.as_slice(),
        backend_config,
    )?;
    let secret_refs = redaction_values.refs();
    let cred_str = credential_env_string(creds)?;

    // Binary availability check — terraform-absent-safe.
    if !binary_available(binary, cancellation)? {
        return Ok(RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: plan.mode,
            status: RunStatus::RunnerUnavailable,
            summary: format!(
                "runner unavailable: terraform binary not found at {:?}",
                binary
            ),
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
    ws.write_file_0600("ryuki_backend.tf", backend_config.hcl.as_bytes())?;

    if !plan.vars.is_empty() {
        let vars_json = vars_to_json(&plan.vars);
        ws.write_file_0600("ryuki.auto.tfvars.json", vars_json.as_bytes())?;
    }

    // --- Step 1: terraform init ---
    // FAIL CLOSED: non-zero exit → Failed, destroy is never attempted.
    backend_config.revalidate_local_state_authority()?;
    let init_outcome = run_tf_step(
        binary,
        TERRAFORM_INIT_ARGS,
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        TfStepControl {
            truncate: true,
            cancellation,
        },
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
    backend_config.revalidate_local_state_authority()?;
    let destroy_outcome = run_tf_step(
        binary,
        &["destroy", "-input=false", "-no-color", "-auto-approve"],
        ws.path(),
        &plan.secret_var_names,
        &cred_str,
        &secret_refs,
        TfStepControl {
            truncate: true,
            cancellation,
        },
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
fn binary_available(
    binary: &Path,
    cancellation: Option<&CommandCancellation>,
) -> Result<bool, RunnerError> {
    let mut cmd = Command::new(binary);
    apply_env_allowlist(&mut cmd);
    cmd.arg("version");
    run_version_probe(cmd, cancellation)
}

fn read_bounded_tfplan(path: &Path) -> Result<Vec<u8>, RunnerError> {
    read_bounded_file(path, MAX_TFPLAN_BYTES, "tfplan")
}

fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    artifact_name: &str,
) -> Result<Vec<u8>, RunnerError> {
    let file = std::fs::File::open(path).map_err(|error| {
        RunnerError::WorkspaceSetup(format!("failed to open {artifact_name}: {error}"))
    })?;
    let declared_len = file
        .metadata()
        .map_err(|error| {
            RunnerError::WorkspaceSetup(format!("failed to inspect {artifact_name}: {error}"))
        })?
        .len();
    if declared_len > max_bytes as u64 {
        return Err(RunnerError::WorkspaceSetup(format!(
            "{artifact_name} exceeds safe artifact limit ({max_bytes} bytes)"
        )));
    }

    let mut bytes = Vec::with_capacity(declared_len as usize);
    file.take((max_bytes as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            RunnerError::WorkspaceSetup(format!("failed to read {artifact_name}: {error}"))
        })?;
    if bytes.len() > max_bytes {
        return Err(RunnerError::WorkspaceSetup(format!(
            "{artifact_name} exceeds safe artifact limit ({max_bytes} bytes)"
        )));
    }
    Ok(bytes)
}

/// Intermediate result from a single terraform sub-command.
struct TfStepResult {
    log: String,
    exit_code: Option<i32>,
}

/// Process-local, secret-bearing `terraform show -json` output. This type is
/// deliberately separate from `TfStepResult`: raw plan semantics must be
/// canonicalized and committed before any redaction, but must never be
/// mistaken for a durable diagnostic log.
struct RawTfShowResult {
    raw: Zeroizing<String>,
    exit_code: Option<i32>,
}

#[derive(Clone, Copy)]
struct TfStepControl<'a> {
    truncate: bool,
    cancellation: Option<&'a CommandCancellation>,
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
fn secret_env_pairs(secret_names: &[String], cred_str: &str) -> Vec<(String, Zeroizing<String>)> {
    if secret_names.is_empty() || cred_str.is_empty() {
        return Vec::new();
    }
    let mut pairs = Vec::with_capacity(secret_names.len() * 2);
    for (name, value) in secret_names.iter().zip(cred_str.split(',')) {
        pairs.push((name.clone(), Zeroizing::new(value.to_string())));
        pairs.push((
            format!("TF_VAR_{}", name.to_lowercase()),
            Zeroizing::new(value.to_string()),
        ));
    }
    pairs
}

/// Process-local scrub registry for one live Terraform operation.
///
/// `registered` borrows already-owned provider/backend values. `derived`
/// contains only the two canonical Basic-auth values for the explicitly typed
/// provider username/password pair and is zeroized when the operation ends.
/// Deliberately no `Debug`: even redaction values must never enter logs.
struct SecretRedactionValues<'a> {
    registered: Vec<&'a [u8]>,
    derived: Vec<Zeroizing<Vec<u8>>>,
}

impl SecretRedactionValues<'_> {
    fn refs(&self) -> Vec<&[u8]> {
        self.registered
            .iter()
            .copied()
            .chain(self.derived.iter().map(|value| value.as_slice()))
            .collect()
    }
}

fn combined_secret_redaction_values<'a>(
    provider_names: &[String],
    provider_components: &'a [Vec<u8>],
    backend_config: &'a IsolatedBackendConfig,
) -> Result<SecretRedactionValues<'a>, RunnerError> {
    let registered = provider_components
        .iter()
        .chain(backend_config.redaction_values().iter())
        .map(Vec::as_slice)
        .collect();
    let derived = provider_basic_auth_redaction_values(provider_names, provider_components)?;
    Ok(SecretRedactionValues {
        registered,
        derived,
    })
}

fn provider_basic_auth_redaction_values(
    provider_names: &[String],
    provider_components: &[Vec<u8>],
) -> Result<Vec<Zeroizing<Vec<u8>>>, RunnerError> {
    fn unique_index(names: &[String], wanted: &str) -> Result<Option<usize>, RunnerError> {
        let mut found = None;
        for (index, name) in names.iter().enumerate() {
            if name == wanted && found.replace(index).is_some() {
                return Err(RunnerError::CredInjection(format!(
                    "live Terraform provider redaction schema declares {wanted} more than once"
                )));
            }
        }
        Ok(found)
    }

    let username_index = unique_index(provider_names, "VSPHERE_USER")?;
    let password_index = unique_index(provider_names, "VSPHERE_PASSWORD")?;
    let (Some(username_index), Some(password_index)) = (username_index, password_index) else {
        if username_index.is_some() || password_index.is_some() {
            return Err(RunnerError::CredInjection(
                "live Terraform provider redaction requires VSPHERE_USER and VSPHERE_PASSWORD to be declared together"
                    .to_string(),
            ));
        }
        return Ok(Vec::new());
    };
    let username = provider_components.get(username_index).ok_or_else(|| {
        RunnerError::CredInjection(
            "live Terraform provider username is missing from the redaction registry".to_string(),
        )
    })?;
    let password_component = provider_components.get(password_index).ok_or_else(|| {
        RunnerError::CredInjection(
            "live Terraform provider password is missing from the redaction registry".to_string(),
        )
    })?;
    if username.is_empty() || password_component.is_empty() {
        return Err(RunnerError::CredInjection(
            "live Terraform provider Basic-auth redaction requires non-empty typed components"
                .to_string(),
        ));
    }

    let variants = basic_auth_canonical_variants(Some(username), Some(password_component))
        .ok_or_else(|| {
            RunnerError::CredInjection(
                "live Terraform provider Basic-auth redaction could not derive canonical variants"
                    .to_string(),
            )
        })?;
    Ok(variants.into_iter().map(Zeroizing::new).collect())
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

fn credential_env_string(creds: &ResolvedCredentials) -> Result<Zeroizing<String>, RunnerError> {
    std::str::from_utf8(creds.material.as_slice())
        .map(|value| Zeroizing::new(value.to_owned()))
        .map_err(|_| {
            RunnerError::CredInjection(
                "live Terraform credential material must be UTF-8 for typed environment injection"
                    .to_string(),
            )
        })
}

fn is_backend_credential_env_name(env_key: &str) -> bool {
    let env_key = env_key.to_ascii_uppercase();
    [
        "AWS_",
        "ARM_",
        "AZURE_",
        "GOOGLE_",
        "CLOUDSDK_",
        "GCLOUD_",
        "ALICLOUD_",
        "ALIBABA_CLOUD_",
        "OSS_",
        "TENCENTCLOUD_",
        "COS_",
        "CONSUL_",
        "PG",
        "KUBE_",
        "KUBERNETES_",
        "ETCDCTL_",
        "ETCDV3_",
        "TF_HTTP_",
        "TF_TOKEN_",
        "TF_CLI_",
        "TF_CLOUD_",
        "TFE_",
    ]
    .iter()
    .any(|prefix| env_key.starts_with(prefix))
        || matches!(env_key.as_str(), "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY")
}

fn run_tf_step(
    binary: &Path,
    args: &[&str],
    ws_path: &std::path::Path,
    secret_names: &[String],
    cred_str: &str,
    secret_refs: &[&[u8]],
    control: TfStepControl<'_>,
) -> Result<TfStepResult, RunnerError> {
    let mut cmd = Command::new(binary);
    apply_env_allowlist(&mut cmd);
    pin_home_tmpdir_to_workspace(&mut cmd, ws_path);
    cmd.args(args)
        .current_dir(ws_path)
        .env("CHECKPOINT_DISABLE", "1")
        .env_remove("TF_LOG");

    for (env_key, value) in secret_env_pairs(secret_names, cred_str) {
        if is_backend_credential_env_name(&env_key) {
            return Err(RunnerError::CredInjection(format!(
                "live Terraform credential env {env_key:?} overlaps a backend credential source; backend authority must remain in validated inline HCL"
            )));
        }
        if !secret_refs.contains(&value.as_bytes()) {
            return Err(RunnerError::CredInjection(format!(
                "live Terraform credential env {env_key:?} is not registered in the output redactor; refusing to spawn"
            )));
        }
        cmd.env(&env_key, value.as_str());
    }

    let mut output =
        run_command_with_optional_cancellation(cmd, LIVE_RUNNER_TIMEOUT, control.cancellation)?;

    let raw = Zeroizing::new(combine_output(&output.stdout, &output.stderr));
    output.stdout.zeroize();
    output.stderr.zeroize();
    // Human-readable diagnostic logs are scrubbed and normally truncated to
    // bound evidence size. Raw `terraform show -json` never enters this type;
    // its dedicated zeroizing path commits before redaction.
    let scrubbed = if control.truncate {
        scrub_output(&raw, secret_refs)
    } else {
        scrub(&raw, secret_refs)
    };

    Ok(TfStepResult {
        log: scrubbed,
        exit_code: output.status.code(),
    })
}

/// Capture the complete raw plan JSON for the in-memory commitment boundary.
/// No credential environment variables are injected for `terraform show`.
/// Both the supervisor buffers and the returned string are explicitly
/// zeroized after use; callers may persist only a digest and safe projection.
fn run_tf_show_json_step(
    binary: &Path,
    ws_path: &Path,
    cancellation: Option<&CommandCancellation>,
) -> Result<RawTfShowResult, RunnerError> {
    let mut cmd = Command::new(binary);
    apply_env_allowlist(&mut cmd);
    pin_home_tmpdir_to_workspace(&mut cmd, ws_path);
    cmd.args(["show", "-json", "tfplan"])
        .current_dir(ws_path)
        .env("CHECKPOINT_DISABLE", "1")
        .env_remove("TF_LOG");

    let mut output =
        run_command_with_optional_cancellation(cmd, LIVE_RUNNER_TIMEOUT, cancellation)?;
    let raw = combine_output(&output.stdout, &output.stderr);
    output.stdout.zeroize();
    output.stderr.zeroize();
    Ok(RawTfShowResult {
        raw: Zeroizing::new(raw),
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

    fn server_deployment_plan() -> RunPlan {
        let mut plan = live_plan("linux-server-deployment");
        for (key, value) in [
            ("vm_name", "vm-test-01"),
            ("num_cpus", "4"),
            ("memory_mb", "8192"),
            ("disk_size_gb", "120"),
            ("datacenter", "dc-a"),
            ("cluster", "cluster-a"),
            ("datastore", "datastore-a"),
            ("network", "network-a"),
            ("template", "template-a"),
        ] {
            plan.vars.insert(key.to_string(), value.to_string());
        }
        plan
    }

    struct TestBackend {
        _root: tempfile::TempDir,
        config: IsolatedBackendConfig,
    }

    impl std::ops::Deref for TestBackend {
        type Target = IsolatedBackendConfig;

        fn deref(&self) -> &Self::Target {
            &self.config
        }
    }

    fn private_test_root() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().expect("private local state root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private local state root permissions");
        }
        let canonical = std::fs::canonicalize(root.path()).expect("canonical test state root");
        (root, canonical)
    }

    fn test_backend() -> TestBackend {
        let key = format!("test-{}", NEXT_STATE_KEY.fetch_add(1, Ordering::Relaxed));
        let (root, canonical_root) = private_test_root();
        let state_path = canonical_root.join("ryuki-runner-state-{STATE_KEY}.tfstate");
        let template = format!(
            "terraform {{\n  backend \"local\" {{\n    path = \"{}\"\n  }}\n}}",
            state_path.display()
        );
        let config = IsolatedBackendConfig::from_template_with_local_state_root(
            &template,
            &key,
            Some(&canonical_root),
        )
        .expect("test backend template is valid");
        TestBackend {
            _root: root,
            config,
        }
    }

    /// Build process-local plan bytes for the state-lineage apply/destroy test
    /// without pretending the provider-less `terraform_data` change is an
    /// approvable server projection. Production LivePlan continues to reject
    /// that unsupported durable evidence shape.
    fn execution_e2e_tfplan(plan: &RunPlan, backend: &IsolatedBackendConfig) -> Vec<u8> {
        assert_eq!(plan.offering_id, "request-preflight");
        let iac_files = super::super::iac::resolve(&plan.offering_id)
            .expect("request-preflight IaC must be embedded");
        assert!(
            iac_policy_refusal(&iac_files, RunnerKind::Terraform, plan.mode).is_none(),
            "the provider-less execution fixture must pass the IaC policy gate"
        );

        let workspace = Workspace::new().expect("execution e2e workspace");
        for (filename, content) in &iac_files {
            workspace
                .write_file(filename, content.as_bytes())
                .expect("write execution e2e IaC");
        }
        workspace
            .write_file_0600("ryuki_backend.tf", backend.hcl.as_bytes())
            .expect("write execution e2e backend");
        if !plan.vars.is_empty() {
            workspace
                .write_file_0600(
                    "ryuki.auto.tfvars.json",
                    vars_to_json(&plan.vars).as_bytes(),
                )
                .expect("write execution e2e vars");
        }

        let redaction_values =
            combined_secret_redaction_values(&[], &[], backend).expect("empty provider registry");
        let secret_refs = redaction_values.refs();
        let init = run_tf_step(
            Path::new("terraform"),
            TERRAFORM_INIT_ARGS,
            workspace.path(),
            &[],
            "",
            &secret_refs,
            TfStepControl {
                truncate: true,
                cancellation: None,
            },
        )
        .expect("execution e2e terraform init");
        assert_eq!(
            init.exit_code,
            Some(0),
            "execution e2e init failed: {}",
            init.log
        );

        let planned = run_tf_step(
            Path::new("terraform"),
            &["plan", "-input=false", "-no-color", "-out=tfplan"],
            workspace.path(),
            &[],
            "",
            &secret_refs,
            TfStepControl {
                truncate: true,
                cancellation: None,
            },
        )
        .expect("execution e2e terraform plan");
        assert!(
            matches!(planned.exit_code, Some(0) | Some(2)),
            "execution e2e plan failed: {}",
            planned.log
        );
        read_bounded_tfplan(&workspace.path().join("tfplan"))
            .expect("read bounded execution e2e tfplan")
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
    /// provider-less `request-preflight` bundle. Its `terraform_data` change is
    /// deliberately outside the closed server-approval projection, so genuine
    /// Terraform output must produce a deterministic safe refusal: no raw plan,
    /// no saved plan bytes, and only the constant unsupported sentinel plus the
    /// complete canonical-plan commitment.
    #[test]
    fn real_terraform_live_plan_e2e_is_deterministic_and_projection_fail_closed() {
        if !binary_available(Path::new("terraform"), None).unwrap_or(false) {
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
            RunStatus::Failed,
            "unreviewed resource semantics must fail closed"
        );
        assert_eq!(
            a1.outcome.summary,
            "terraform plan contains unsupported or malformed resource semantics — refusing live approval"
        );
        assert!(
            !a1.outcome.summary.contains("POLICY-REFUSED"),
            "the embedded IaC itself remains policy-clean"
        );
        assert!(
            a1.tfplan.is_empty(),
            "an unreviewable plan must release no apply artifact"
        );

        // Durable failure evidence is still a bounded, deterministic envelope.
        let parsed: serde_json::Value =
            serde_json::from_str(&a1.outcome.log).expect("plan evidence JSON must parse");
        assert!(
            parsed.get("timestamp").is_none(),
            "the non-deterministic top-level timestamp must be stripped"
        );
        assert_eq!(parsed["projection_complete"], false);
        assert_eq!(
            parsed["resource_changes"][0],
            unsupported_resource_change(),
            "unsupported semantics must collapse to the constant sentinel"
        );
        assert!(
            !a1.outcome.log.contains("terraform_data")
                && !a1.outcome.log.contains("request_preflight_plan"),
            "raw resource identity must not cross into refusal evidence"
        );
        assert_eq!(
            parsed["canonical_plan_sha256"]
                .as_str()
                .expect("full-plan commitment")
                .len(),
            64
        );

        // A second identical plan yields the same safe envelope despite
        // Terraform stamping a fresh timestamp on the full plan.
        let a2 = live_terraform_plan("terraform", &plan, &dummy_creds(), &backend)
            .expect("second live plan must not error");
        assert_eq!(a2.outcome.status, RunStatus::Failed);
        assert!(a2.tfplan.is_empty());
        assert_eq!(
            a1.outcome.log, a2.outcome.log,
            "safe refusal evidence must be identical across equivalent replans"
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
        let result = live_terraform_plan("terraform", &plan, &dummy_creds(), &test_backend());
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
        let result = live_terraform_apply(
            "terraform",
            &plan,
            &dummy_creds(),
            &test_backend(),
            b"fake-plan",
        );
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
        let (_root, canonical_root) = private_test_root();
        let template = format!(
            "terraform {{ backend \"local\" {{ path = \"{}/terraform-{{STATE_KEY}}.tfstate\" }} }}",
            canonical_root.display()
        );
        let build = |state_key| {
            IsolatedBackendConfig::from_template_with_local_state_root(
                &template,
                state_key,
                Some(&canonical_root),
            )
            .unwrap()
        };
        let request_a = build("request-a");
        let request_b = build("request-b");
        assert_ne!(request_a.hcl, request_b.hcl);
        assert!(request_a.hcl.contains("terraform-request-a.tfstate"));
        assert!(request_b.hcl.contains("terraform-request-b.tfstate"));

        let plan = build("step-one");
        let apply = build("step-one");
        let destroy = build("step-one");
        assert_eq!(plan.hcl, apply.hcl);
        assert_eq!(apply.hcl, destroy.hcl);
        assert_eq!(plan.state_key(), "step-one");
        assert!(!plan.hcl.contains(STATE_KEY_PLACEHOLDER));
    }

    #[test]
    fn backend_authority_digest_tracks_authority_not_secret_rotation_or_layout() {
        let template_a = r#"terraform {
  backend "s3" {
    bucket = "state-a"
    key = "jobs/{STATE_KEY}.tfstate"
    region = "eu-west-1"
    allowed_account_ids = ["111111111111"]
    endpoint = "https://api-a.invalid"
    access_key = "access-a" # secret-scan-allow: inert unit-test fixture
    secret_key = "secret-a" # secret-scan-allow: inert unit-test fixture
    skip_metadata_api_check = true
    use_lockfile = true
  }
}"#; // secret-scan-allow: inert unit-test fixture
        let template_rotated = r#"# layout and comments are not authority
terraform { backend "s3" {
  bucket="state-a"
  key="jobs/{STATE_KEY}.tfstate"
  region="eu-west-1"
  allowed_account_ids=["111111111111"]
  endpoint="https://api-a.invalid"
  access_key="access-b" # secret-scan-allow: inert unit-test fixture
  secret_key="secret-b" # secret-scan-allow: inert unit-test fixture
  skip_metadata_api_check=true
  use_lockfile=true
} }"#; // secret-scan-allow: inert unit-test fixture

        let authority_a = IsolatedBackendConfig::from_template(template_a, "digest-state")
            .expect("first backend authority");
        let rotated = IsolatedBackendConfig::from_template(template_rotated, "digest-state")
            .expect("rotated backend authority");
        assert_eq!(
            authority_a.backend_authority_digest(),
            rotated.backend_authority_digest(),
            "secret rotation and layout must not change backend authority"
        );
        assert_eq!(authority_a.backend_authority_digest().len(), 64);
        assert!(authority_a
            .backend_authority_digest()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));

        for drifted in [
            template_a.replace("state-a", "state-b"),
            template_a.replace("api-a.invalid", "api-b.invalid"),
            template_a.replace("111111111111", "222222222222"),
        ] {
            let drifted = IsolatedBackendConfig::from_template(&drifted, "digest-state")
                .expect("same-kind drifted backend");
            assert_ne!(
                authority_a.backend_authority_digest(),
                drifted.backend_authority_digest(),
                "bucket, endpoint, and account drift must change authority"
            );
        }
        let different_state = IsolatedBackendConfig::from_template(template_a, "other-state")
            .expect("different state authority");
        assert_ne!(
            authority_a.backend_authority_digest(),
            different_state.backend_authority_digest()
        );
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
        let (_root, canonical_root) = private_test_root();
        let local = format!(
            r#"terraform {{ backend "local" {{ path = "{}/state-{{STATE_KEY}}.tfstate" }} }}"#,
            canonical_root.display()
        );
        let s3 = r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" region = "eu-west-1" access_key = "location-access" secret_key = "location-secret" skip_metadata_api_check = true use_lockfile = true } }"#; // secret-scan-allow: inert unit-test fixture

        IsolatedBackendConfig::from_template_with_local_state_root(
            &local,
            "request-a",
            Some(&canonical_root),
        )
        .expect("private local backend location");
        IsolatedBackendConfig::from_template(s3, "request-a").expect("locked S3 backend location");
    }

    #[test]
    fn s3_backend_requires_an_explicit_reviewed_locking_mechanism() {
        let unlocked = r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" region = "eu-west-1" access_key = "lock-access" secret_key = "lock-secret" skip_metadata_api_check = true } }"#; // secret-scan-allow: inert unit-test fixture
        let error = IsolatedBackendConfig::from_template(unlocked, "lock-test")
            .err()
            .expect("an unlocked S3 backend must fail closed")
            .to_string();
        assert!(error.contains("requires reviewed state locking"), "{error}");

        for locked in [
            unlocked.replace(
                "skip_metadata_api_check = true",
                "skip_metadata_api_check = true use_lockfile = true",
            ),
            unlocked.replace(
                "skip_metadata_api_check = true",
                "skip_metadata_api_check = true dynamodb_table = \"ryuki-state-locks\"",
            ),
        ] {
            IsolatedBackendConfig::from_template(&locked, "lock-test")
                .expect("reviewed S3 locking contract");
        }
        let false_lock = unlocked.replace(
            "skip_metadata_api_check = true",
            "skip_metadata_api_check = true use_lockfile = false",
        );
        assert!(IsolatedBackendConfig::from_template(&false_lock, "lock-test").is_err());
    }

    #[test]
    fn http_backend_requires_complete_canonical_lock_and_unlock_contract() {
        let base = r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}" username = "lock-user" } }"#; // secret-scan-allow: inert unit-test fixture
        for partial in [
            base.to_string(),
            base.replace(
                "username",
                "lock_address = \"https://state.invalid/{STATE_KEY}/lock\" username",
            ),
            base.replace(
                "username",
                "lock_address = \"https://state.invalid/{STATE_KEY}/lock\" unlock_address = \"https://state.invalid/{STATE_KEY}/lock\" lock_method = \"POST\" unlock_method = \"DELETE\" username",
            ),
            base.replace(
                "username",
                "lock_address = \"https://other.invalid/{STATE_KEY}/lock\" unlock_address = \"https://state.invalid/{STATE_KEY}/lock\" lock_method = \"LOCK\" unlock_method = \"UNLOCK\" username",
            ),
        ] {
            assert!(
                IsolatedBackendConfig::from_template(&partial, "http-lock-test").is_err(),
                "partial or cross-origin HTTP locking must fail closed: {partial}"
            );
        }

        let complete = base.replace(
            "username",
            "lock_address = \"https://state.invalid/{STATE_KEY}/lock\" unlock_address = \"https://state.invalid/{STATE_KEY}/lock\" lock_method = \"LOCK\" unlock_method = \"UNLOCK\" username",
        );
        IsolatedBackendConfig::from_template(&complete, "http-lock-test")
            .expect("complete canonical HTTP locking contract");
    }

    #[test]
    fn backend_config_tracks_only_typed_secret_attributes_for_redaction() {
        let template = r#"terraform {
  backend "s3" {
    bucket = "non-secret-bucket"
    key = "jobs/{STATE_KEY}.tfstate"
    region = "eu-west-1"
    access_key = "backend-access-canary" # secret-scan-allow: inert unit-test fixture
    secret_key = "backend-secret-canary" # secret-scan-allow: inert unit-test fixture
    token = "backend-token-canary" # secret-scan-allow: inert unit-test fixture
    skip_metadata_api_check = true
    use_lockfile = true
  }
}"#;
        let backend = IsolatedBackendConfig::from_template(template, "request-a")
            .expect("typed backend config");
        let values: Vec<&[u8]> = backend
            .redaction_values()
            .iter()
            .map(Vec::as_slice)
            .collect();
        assert!(values.contains(&b"backend-access-canary".as_slice()));
        assert!(values.contains(&b"backend-secret-canary".as_slice()));
        assert!(values.contains(&b"backend-token-canary".as_slice()));
        assert!(!values.contains(&b"non-secret-bucket".as_slice()));
        assert!(!values
            .iter()
            .any(|value| value.windows(9).any(|part| part == b"request-a")));

        let kubernetes = IsolatedBackendConfig::from_template(
            r#"terraform { backend "kubernetes" { secret_suffix = "{STATE_KEY}" host = "https://kubernetes.invalid" load_config_file = false in_cluster_config = false client_certificate = "backend-client-cert-canary" client_key = "backend-client-key-canary" } }"#, // secret-scan-allow: inert unit-test fixture
            "request-k8s",
        )
        .expect("Kubernetes backend");
        assert!(kubernetes
            .redaction_values()
            .iter()
            .any(|value| value == b"backend-client-key-canary"));
    }

    #[test]
    fn backend_redaction_decomposes_sas_and_signed_url_credentials() {
        let azure = IsolatedBackendConfig::from_template(
            r#"terraform { backend "azurerm" { storage_account_name = "state" container_name = "tfstate" key = "jobs/{STATE_KEY}.tfstate" use_cli = false use_msi = false use_oidc = false use_aks_workload_identity = false sas_token = "?sv=1&sig=sas%2Dsignature" } }"#, // secret-scan-allow: inert unit-test fixture
            "sas-test",
        )
        .expect("Azure SAS backend");
        assert!(azure
            .redaction_values()
            .iter()
            .any(|value| value == b"sas%2Dsignature"));
        assert!(azure
            .redaction_values()
            .iter()
            .any(|value| value == b"sas-signature"));

        let mut signed_url_values = Vec::new();
        append_connection_string_components(
            &mut signed_url_values,
            "https://signed-user:signed-pass@state.invalid/state?X-Amz-Signature=aws%2Dsignature", // secret-scan-allow: inert unit-test fixture
        );
        for expected in [
            "signed-user",
            "signed-pass",
            "aws%2Dsignature",
            "aws-signature",
        ] {
            assert!(
                signed_url_values
                    .iter()
                    .any(|value| value == expected.as_bytes()),
                "missing signed URL redaction component {expected}"
            );
        }
    }

    #[test]
    fn backend_redaction_covers_basic_auth_and_go_json_wire_variants() {
        let consul = IsolatedBackendConfig::from_template(
            r#"terraform { backend "consul" { address = "https://consul.invalid" path = "jobs/{STATE_KEY}" http_auth = "basic-user:basic-pass" } }"#, // secret-scan-allow: inert unit-test fixture
            "basic-auth-test",
        )
        .expect("Consul basic-auth backend");
        assert!(consul
            .redaction_values()
            .iter()
            .any(|value| value == b"YmFzaWMtdXNlcjpiYXNpYy1wYXNz"));

        let username_only = IsolatedBackendConfig::from_template(
            r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}" lock_address = "https://state.invalid/{STATE_KEY}/lock" unlock_address = "https://state.invalid/{STATE_KEY}/lock" lock_method = "LOCK" unlock_method = "UNLOCK" username = "basic-user" } }"#, // secret-scan-allow: inert unit-test fixture
            "empty-basic-password-test",
        )
        .expect("HTTP username-only basic auth backend");
        assert!(username_only
            .redaction_values()
            .iter()
            .any(|value| value == b"YmFzaWMtdXNlcjo="));

        let http = IsolatedBackendConfig::from_template(
            "terraform { backend \"http\" { address = \"https://state.invalid/{STATE_KEY}\" lock_address = \"https://state.invalid/{STATE_KEY}/lock\" unlock_address = \"https://state.invalid/{STATE_KEY}/lock\" lock_method = \"LOCK\" unlock_method = \"UNLOCK\" password = \"<>&\u{2028}\u{2029}\" } }", // secret-scan-allow: inert unit-test fixture
            "go-json-test",
        )
        .expect("HTTP Go-JSON backend");
        assert!(http
            .redaction_values()
            .iter()
            .any(|value| value == br"\u003c\u003e\u0026\u2028\u2029"));

        let mut mixed_variants = Vec::new();
        append_go_json_escape_variants(
            &mut mixed_variants,
            "p\"\\\n<>&\u{2028}\u{2029}".as_bytes(),
        );
        assert!(mixed_variants
            .iter()
            .any(|value| value == br#"p\"\\\n\u003c\u003e\u0026\u2028\u2029"#));
        assert!(mixed_variants
            .iter()
            .any(|value| value == br#"p\"\\\n<>&\u2028\u2029"#));

        let mut invalid_percent_variants = Vec::new();
        append_query_string_components(
            &mut invalid_percent_variants,
            "signature=provider-%FF-canary",
        );
        assert!(invalid_percent_variants
            .iter()
            .any(|value| value == br"provider-\ufffd-canary"));
        let invalid_percent_refs: Vec<&[u8]> =
            invalid_percent_variants.iter().map(Vec::as_slice).collect();
        assert_eq!(
            scrub(
                r#"diagnostic=provider-\ufffd-canary status=failed"#,
                &invalid_percent_refs,
            ),
            "diagnostic=[REDACTED] status=failed"
        );
        assert_eq!(
            scrub(
                "diagnostic=provider-\u{fffd}-canary status=failed",
                &invalid_percent_refs,
            ),
            "diagnostic=[REDACTED] status=failed"
        );
    }

    #[test]
    fn backend_schema_rejects_unknown_and_unquoted_sensitive_attributes() {
        let unknown = r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" api_key = "unknown-backend-canary" } }"#; // secret-scan-allow: inert unit-test fixture
        let error = IsolatedBackendConfig::from_template(unknown, "request-a")
            .err()
            .expect("unknown backend attribute must fail closed")
            .to_string();
        assert!(error.contains("not in the approved schema"), "{error}");

        let unquoted = r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}" password = file("credential-path") } }"#;
        let error = IsolatedBackendConfig::from_template(unquoted, "request-a")
            .err()
            .expect("non-scalar backend secret must fail closed")
            .to_string();
        assert!(error.contains("must be a quoted scalar"), "{error}");
    }

    #[test]
    fn backend_schema_rejects_expression_and_hcl_string_parser_bypasses() {
        let cases = [
            r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}" password = "selector" == "real-secret" ? "real-secret" : "decoy" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" secret_key = "secret" skip_metadata_api_check = true endpoints = { sts = "selector" == "real-secret" ? "real-secret" : "decoy" } } }"#, // secret-scan-allow: inert unit-test fixture
            "terraform { backend \"http\" { address = \"https://state.invalid/{STATE_KEY}\" password = <<EOF\nheredoc-secret\n}\nEOF\napi_key = \"after-heredoc-secret\"\n} }", // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}" password = "secret\U0001F642" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}" password = "$${template-secret}" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}" password = "%%{ if true }template-secret%%{ endif }" } }"#, // secret-scan-allow: inert unit-test fixture
        ];

        for template in cases {
            assert!(
                IsolatedBackendConfig::from_template(template, "parser-test").is_err(),
                "backend parser bypass must fail closed: {template}"
            );
        }
    }

    #[test]
    fn backend_template_rejects_extra_root_or_terraform_configuration() {
        let cases = [
            r#"terraform { backend "local" { path = "/var/lib/ryuki/{STATE_KEY}.tfstate" } } resource "terraform_data" "injected" {}"#,
            r#"terraform { required_version = ">= 1.0" backend "local" { path = "/var/lib/ryuki/{STATE_KEY}.tfstate" } }"#,
        ];
        for template in cases {
            let error = IsolatedBackendConfig::from_template(template, "shape-test")
                .err()
                .expect("extra HCL configuration must fail closed")
                .to_string();
            assert!(
                error.contains("exactly one root terraform block"),
                "{error}"
            );
        }
    }

    #[test]
    fn backend_public_urls_reject_unbound_userinfo_query_and_fragment_authority() {
        let cases = [
            r#"terraform { backend "http" { address = "https://state.invalid/shared?tenant=A&key={STATE_KEY}" } }"#,
            r#"terraform { backend "http" { address = "https://state.invalid/shared?tenant=B&key={STATE_KEY}" } }"#,
            r#"terraform { backend "http" { address = "https://state.invalid/shared#{STATE_KEY}" } }"#,
            r#"terraform { backend "http" { address = "https://{STATE_KEY}:password@state.invalid/shared" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "http" { address = "https://state.invalid/shared\u0023{STATE_KEY}" } }"#,
            r#"terraform { backend "http" { address = "https://state.invalid/shared\u003ftenant=A&key={STATE_KEY}" } }"#,
            r#"terraform { backend "http" { address = "https://{STATE_KEY}\u003apassword\u0040state.invalid/shared" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" region = "eu-west-1" endpoint = "https://api.invalid?tenant=A" access_key = "access" secret_key = "secret" skip_metadata_api_check = true } }"#, // secret-scan-allow: inert unit-test fixture
        ];
        for template in cases {
            let error = IsolatedBackendConfig::from_template(template, "url-authority-test")
                .err()
                .expect("unbound public URL authority must fail closed")
                .to_string();
            assert!(
                error.contains("public URL values cannot contain"),
                "{error}"
            );
        }
    }

    #[test]
    fn backend_nested_schema_rejects_unknown_and_implicit_sources() {
        let cases = [
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" region = "eu-west-1" access_key = "access" secret_key = "secret" skip_metadata_api_check = true endpoints = { future_credential_source = "ambient" } } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" region = "eu-west-1" access_key = "access" secret_key = "secret" skip_metadata_api_check = true endpoints = { profile = "ambient-profile" } } }"#, // secret-scan-allow: inert unit-test fixture
        ];
        for template in cases {
            assert!(
                IsolatedBackendConfig::from_template(template, "nested-test").is_err(),
                "unknown nested credential authority must fail closed"
            );
        }
    }

    #[test]
    fn backend_authority_rejects_ambient_metadata_cli_and_default_config_sources() {
        let cases = [
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" secret_key = "secret" skip_metadata_api_check = true profile = "ambient-profile" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" secret_key = "secret" skip_metadata_api_check = true ec2_metadata_service_endpoint = "http://metadata.invalid" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "azurerm" { storage_account_name = "state" container_name = "tfstate" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" use_cli = true use_msi = false use_oidc = false use_aks_workload_identity = false } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "oss" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" secret_key = "secret" profile = "ambient-profile" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "cos" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" secret_id = "id" secret_key = "secret" cam_role_name = "metadata-role" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "gcs" { bucket = "state" prefix = "jobs/{STATE_KEY}" access_token = "token" impersonate_service_account = "ambient@example.invalid" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "kubernetes" { secret_suffix = "{STATE_KEY}" host = "https://kubernetes.invalid" token = "token" load_config_file = true in_cluster_config = false } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "kubernetes" { secret_suffix = "{STATE_KEY}" host = "https://kubernetes.invalid" token = "token" load_config_file = false in_cluster_config = false config_context = "ambient-context" } }"#, // secret-scan-allow: inert unit-test fixture
        ];

        for template in cases {
            let error = IsolatedBackendConfig::from_template(template, "authority-test")
                .err()
                .expect("implicit backend credential authority must fail closed")
                .to_string();
            assert!(
                error.contains("implicit credential source")
                    || error.contains("ambient or default credential authority"),
                "{error}"
            );
        }
    }

    #[test]
    fn backend_authority_requires_complete_inline_credentials_and_exact_boolean_gates() {
        let cases = [
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" secret_key = "secret" } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" secret_key = "secret" skip_metadata_api_check = false } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" secret_key = "secret" skip_metadata_api_check = true || false } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" secret_key = "secret" skip_metadata_api_check = true && 2 > 3 } }"#, // secret-scan-allow: inert unit-test fixture
            r#"terraform { backend "azurerm" { storage_account_name = "state" container_name = "tfstate" key = "jobs/{STATE_KEY}.tfstate" use_cli = false use_msi = false use_oidc = false use_aks_workload_identity = false } }"#,
            r#"terraform { backend "azurerm" { storage_account_name = "state" container_name = "tfstate" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" use_cli = false ? true : false use_msi = false use_oidc = false use_aks_workload_identity = false } }"#,
            r#"terraform { backend "azurerm" { storage_account_name = "state" container_name = "tfstate" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" use_cli = false || 1 < 2 use_msi = false use_oidc = false use_aks_workload_identity = false } }"#,
            r#"terraform { backend "oss" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" access_key = "access" } }"#,
            r#"terraform { backend "cos" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" secret_id = "id" } }"#,
            r#"terraform { backend "gcs" { bucket = "state" prefix = "jobs/{STATE_KEY}" } }"#,
            r#"terraform { backend "kubernetes" { secret_suffix = "{STATE_KEY}" host = "https://kubernetes.invalid" load_config_file = false in_cluster_config = false } }"#,
        ];

        for template in cases {
            let error = IsolatedBackendConfig::from_template(template, "authority-test")
                .err()
                .expect("missing inline backend credentials must fail closed")
                .to_string();
            assert!(
                error.contains("ambient or default credential authority"),
                "{error}"
            );
        }
    }

    #[test]
    fn backend_credential_authority_policy_version_is_stable_and_specific() {
        assert_eq!(
            BACKEND_CREDENTIAL_AUTHORITY_POLICY_VERSION,
            "ryuki.closed-schema-inline-scalars-no-file-ambient-metadata-cli-workload-in-cluster-no-remote-execution.v1"
        );
    }

    #[test]
    fn backend_remote_execution_is_rejected_by_local_containment_policy() {
        let template = r#"terraform { backend "remote" { hostname = "app.terraform.io" organization = "example" token = "remote-token" workspaces { name = "{STATE_KEY}" } } }"#; // secret-scan-allow: inert unit-test fixture
        let error = IsolatedBackendConfig::from_template(template, "remote-test")
            .err()
            .expect("remote execution backend must fail closed")
            .to_string();
        assert!(
            error.contains("remote backend execution is forbidden"),
            "{error}"
        );
    }

    #[test]
    fn backend_pg_is_rejected_for_ambient_os_home_client_identity() {
        let template = r#"terraform { backend "pg" { conn_str = "postgresql://user:pass@state.invalid/db" schema_name = "{STATE_KEY}" } }"#; // secret-scan-allow: inert unit-test fixture
        let error = IsolatedBackendConfig::from_template(template, "pg-test")
            .err()
            .expect("PG ambient client identity must fail closed")
            .to_string();
        assert!(
            error.contains("ambient OS-home TLS client identity"),
            "{error}"
        );
    }

    #[test]
    fn backend_schema_rejects_credential_file_sources_for_every_live_operation() {
        let cases = [
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" shared_credentials_file = "/credential-file" } }"#,
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" assume_role_with_web_identity = { role_arn = "role" web_identity_token_file = "/credential-file" } } }"#,
            r#"terraform { backend "azurerm" { storage_account_name = "state" container_name = "tfstate" key = "jobs/{STATE_KEY}.tfstate" client_certificate_path = "/credential-file" } }"#,
            r#"terraform { backend "oss" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" shared_credentials_file = "/credential-file" } }"#,
            r#"terraform { backend "cos" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" shared_credentials_dir = "/credential-dir" } }"#,
            r#"terraform { backend "gcs" { bucket = "state" prefix = "jobs/{STATE_KEY}" credentials = "/credential-file" } }"#,
            r#"terraform { backend "gcs" { bucket = "state" prefix = "jobs/{STATE_KEY}" encryption_key = "/credential-file" } }"#,
            r#"terraform { backend "etcdv3" { endpoints = ["etcd.invalid:2379"] prefix = "jobs/{STATE_KEY}" key_path = "/credential-file" } }"#,
            r#"terraform { backend "consul" { address = "consul.invalid" path = "jobs/{STATE_KEY}" key_file = "/credential-file" } }"#,
            r#"terraform { backend "kubernetes" { secret_suffix = "{STATE_KEY}" config_path = "/credential-file" } }"#,
        ];

        // Plan, apply, and destroy all require the same unforgeable typed
        // backend constructor, so rejecting here closes the source before any
        // of the three execution paths can create a workspace or subprocess.
        for operation in ["plan", "apply", "destroy"] {
            for template in &cases {
                let error = IsolatedBackendConfig::from_template(template, "request-a")
                    .err()
                    .unwrap_or_else(|| {
                        panic!("{operation} admitted a backend credential-file source")
                    })
                    .to_string();
                assert!(
                    error.contains("credential-file attribute"),
                    "{operation}: {error}"
                );
            }
        }
    }

    #[test]
    fn backend_schema_covers_every_supported_backend_and_public_scalar_type() {
        let (_root, canonical_root) = private_test_root();
        let local = format!(
            r#"terraform {{ backend "local" {{ path = "{}/schema-{{STATE_KEY}}.tfstate" }} }}"#,
            canonical_root.display()
        );
        IsolatedBackendConfig::from_template_with_local_state_root(
            &local,
            "schema-test",
            Some(&canonical_root),
        )
        .expect("private local backend schema");

        let cases = [
            (
                r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" region = "eu-west-1" encrypt = true access_key = "schema-s3-access-canary" secret_key = "schema-s3-secret-canary" skip_metadata_api_check = true use_lockfile = true } }"#, // secret-scan-allow: inert unit-test fixture
                Some("schema-s3-access-canary"),
            ),
            (
                r#"terraform { backend "azurerm" { storage_account_name = "state" container_name = "tfstate" key = "jobs/{STATE_KEY}.tfstate" use_cli = false use_msi = false use_oidc = false use_aks_workload_identity = false sas_token = "schema-azure-canary" } }"#, // secret-scan-allow: inert unit-test fixture
                Some("schema-azure-canary"),
            ),
            (
                r#"terraform { backend "oss" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" encrypt = true access_key = "schema-oss-access-canary" secret_key = "schema-oss-secret-canary" security_token = "schema-oss-canary" } }"#, // secret-scan-allow: inert unit-test fixture
                Some("schema-oss-canary"),
            ),
            (
                r#"terraform { backend "cos" { region = "eu" bucket = "state" key = "jobs/{STATE_KEY}.tfstate" accelerate = false secret_id = "schema-cos-id-canary" secret_key = "schema-cos-key-canary" security_token = "schema-cos-canary" } }"#, // secret-scan-allow: inert unit-test fixture
                Some("schema-cos-canary"),
            ),
            (
                r#"terraform { backend "gcs" { bucket = "state" prefix = "jobs/{STATE_KEY}" access_token = "schema-gcs-canary" } }"#, // secret-scan-allow: inert unit-test fixture
                Some("schema-gcs-canary"),
            ),
            (
                r#"terraform { backend "etcdv3" { endpoints = ["etcd.invalid:2379"] prefix = "jobs/{STATE_KEY}" lock = true username = "schema-etcd-user-canary" password = "schema-etcd-canary" } }"#, // secret-scan-allow: inert unit-test fixture
                Some("schema-etcd-canary"),
            ),
            (
                r#"terraform { backend "consul" { address = "consul.invalid" path = "jobs/{STATE_KEY}" gzip = true access_token = "schema-consul-canary" } }"#, // secret-scan-allow: inert unit-test fixture
                Some("schema-consul-canary"),
            ),
            (
                r#"terraform { backend "kubernetes" { secret_suffix = "{STATE_KEY}" host = "https://kubernetes.invalid" load_config_file = false in_cluster_config = false insecure = false client_certificate = "schema-k8s-cert-canary" client_key = "schema-k8s-canary" } }"#, // secret-scan-allow: inert unit-test fixture
                Some("schema-k8s-canary"),
            ),
            (
                r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}" lock_address = "https://state.invalid/{STATE_KEY}/lock" unlock_address = "https://state.invalid/{STATE_KEY}/lock" lock_method = "LOCK" unlock_method = "UNLOCK" retry_max = 2 password = "schema-http-canary" } }"#, // secret-scan-allow: inert unit-test fixture
                Some("schema-http-canary"),
            ),
        ];

        for (template, expected_secret) in cases {
            let backend = IsolatedBackendConfig::from_template(template, "schema-test")
                .unwrap_or_else(|error| panic!("supported backend schema rejected: {error}"));
            if let Some(expected_secret) = expected_secret {
                assert!(
                    backend
                        .redaction_values()
                        .iter()
                        .any(|value| value == expected_secret.as_bytes()),
                    "backend secret was not admitted to the redaction set"
                );
            }
        }
    }

    #[test]
    fn live_apply_and_destroy_scrub_transformed_backend_secrets() {
        let ws_probe = super::super::workspace::Workspace::new().expect("ws");
        let shim = ws_probe.path().join("fake-tf-backend-redaction");
        std::fs::write(
            &shim,
            r#"#!/bin/sh
case "$1" in
  version) exit 0 ;;
  init) echo init-ok; exit 0 ;;
  apply) echo 'backend%20marker%2F%2B'; echo 'Apply complete! Resources: 1 added, 0 changed, 0 destroyed.'; exit 0 ;;
  plan) echo 'No changes. Your infrastructure matches the configuration.'; exit 0 ;;
  destroy) echo 'backend marker/+'; echo 'Destroy complete! Resources: 1 destroyed.'; exit 0 ;;
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

        let backend = IsolatedBackendConfig::from_template(
            r#"terraform { backend "s3" { bucket = "state" key = "jobs/{STATE_KEY}.tfstate" region = "eu-west-1" access_key = "backend-access" secret_key = "backend marker/+" skip_metadata_api_check = true use_lockfile = true } }"#, // secret-scan-allow: inert unit-test fixture
            "redaction-test",
        )
        .expect("backend");
        let plan = live_plan("patch-maintenance");
        let applied = live_terraform_apply(
            &shim.to_string_lossy(),
            &plan,
            &dummy_creds(),
            &backend,
            b"fake-plan",
        )
        .expect("apply");
        assert_eq!(applied.status, RunStatus::Applied);
        assert!(!applied.log.contains("backend%20marker%2F%2B"));
        assert!(!applied.log.contains("backend marker/+"));
        assert!(applied.log.contains("[REDACTED]"));

        let destroyed =
            live_terraform_destroy(&shim.to_string_lossy(), &plan, &dummy_creds(), &backend)
                .expect("destroy");
        assert_eq!(destroyed.status, RunStatus::Applied);
        assert!(!destroyed.log.contains("backend marker/+"));
        assert!(destroyed.log.contains("[REDACTED]"));
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

    #[cfg(unix)]
    #[test]
    fn local_backend_is_bound_to_private_owned_root_and_rechecked_no_follow() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (_root, canonical_root) = private_test_root();
        let template = format!(
            r#"terraform {{ backend "local" {{ path = "{}/state-{{STATE_KEY}}.tfstate" }} }}"#,
            canonical_root.display()
        );
        let missing_root = IsolatedBackendConfig::from_template(&template, "root-test")
            .err()
            .expect("local backend without configured root must fail")
            .to_string();
        assert!(missing_root.contains("RYUKI_AGENT_LOCAL_STATE_ROOT"));

        let outside = canonical_root
            .parent()
            .expect("test root parent")
            .join("outside-{STATE_KEY}.tfstate");
        let outside_template = format!(
            r#"terraform {{ backend "local" {{ path = "{}" }} }}"#,
            outside.display()
        );
        assert!(
            IsolatedBackendConfig::from_template_with_local_state_root(
                &outside_template,
                "root-test",
                Some(&canonical_root),
            )
            .is_err(),
            "local state outside the admitted root must fail"
        );

        let backend = IsolatedBackendConfig::from_template_with_local_state_root(
            &template,
            "root-test",
            Some(&canonical_root),
        )
        .expect("private local backend");
        let target = canonical_root.join("state-root-test.tfstate");
        let symlink_target = canonical_root.join("symlink-target");
        std::fs::write(&symlink_target, b"not-state").expect("write symlink target");
        symlink(&symlink_target, &target).expect("install state symlink");
        assert!(
            backend.revalidate_local_state_authority().is_err(),
            "a final state symlink introduced after admission must fail"
        );
        std::fs::remove_file(&target).expect("remove state symlink");

        std::fs::write(&target, b"{}").expect("write state fixture");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
            .expect("make state fixture non-private");
        assert!(
            backend.revalidate_local_state_authority().is_err(),
            "a state file with group/other permissions must fail recheck"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_backend_rejects_symlinked_or_nonprivate_root() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (root, canonical_root) = private_test_root();
        let alias_parent = tempfile::tempdir().expect("alias parent");
        let alias = alias_parent.path().join("state-root-link");
        symlink(&canonical_root, &alias).expect("root symlink");
        let linked_template = format!(
            r#"terraform {{ backend "local" {{ path = "{}/state-{{STATE_KEY}}.tfstate" }} }}"#,
            alias.display()
        );
        assert!(
            IsolatedBackendConfig::from_template_with_local_state_root(
                &linked_template,
                "root-test",
                Some(&alias),
            )
            .is_err(),
            "a symlinked root must fail"
        );

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755))
            .expect("make root non-private");
        let template = format!(
            r#"terraform {{ backend "local" {{ path = "{}/state-{{STATE_KEY}}.tfstate" }} }}"#,
            canonical_root.display()
        );
        assert!(
            IsolatedBackendConfig::from_template_with_local_state_root(
                &template,
                "root-test",
                Some(&canonical_root),
            )
            .is_err(),
            "a group/world-accessible root must fail"
        );
    }

    #[test]
    fn backend_state_locations_reject_decoded_and_encoded_path_aliases() {
        let cases = [
            r#"terraform { backend "local" { path = "/var/lib/ryuki/{STATE_KEY}/../shared.tfstate" } }"#,
            r#"terraform { backend "local" { path = "/var/lib/ryuki/{STATE_KEY}/./shared.tfstate" } }"#,
            r#"terraform { backend "local" { path = "/var/lib/ryuki/{STATE_KEY}\u002f\u002e\u002e\u002fshared.tfstate" } }"#,
            r#"terraform { backend "local" { path = "/var/lib/ryuki/{STATE_KEY}\\..\\shared.tfstate" } }"#,
            r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}/../shared.tfstate" } }"#,
            r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}\u002f\u002e\u002e\u002fshared.tfstate" } }"#,
            r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}/%2e%2e/shared.tfstate" } }"#,
            r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}/%252e%252e/shared.tfstate" } }"#,
            r#"terraform { backend "http" { address = "https://state.invalid/{STATE_KEY}/%5c../shared.tfstate" } }"#,
        ];
        for template in cases {
            assert!(
                IsolatedBackendConfig::from_template(template, "alias-test").is_err(),
                "state-location alias must fail closed: {template}"
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
        let (_root, canonical_root) = private_test_root();
        let backend_hcl = format!(
            r#"terraform {{
  backend "local" {{
    path = "{}/test-{{STATE_KEY}}.tfstate"
  }}
}}"#,
            canonical_root.display()
        );
        let backend = IsolatedBackendConfig::from_template_with_local_state_root(
            &backend_hcl,
            "request-test",
            Some(&canonical_root),
        )
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
        let result = live_terraform_destroy("terraform", &plan, &dummy_creds(), &test_backend());
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
    /// provider, no registry egress). Each command phase runs in its OWN fresh
    /// runner workspace; plan-byte construction uses the test-only helper
    /// because production correctly rejects this non-server approval shape.
    /// The operator `backend_config` (here a `backend "local"` pointing at a
    /// shared absolute path) carries state lineage across the isolated phases.
    /// Asserts: (1) apply records the resource; (2) destroy reconstructs the
    /// same state authority and succeeds; (3) the state then has no resources.
    #[test]
    fn real_terraform_live_destroy_e2e_applies_then_destroys_shared_state() {
        if !binary_available(Path::new("terraform"), None).unwrap_or(false) {
            eprintln!("SKIP: terraform binary not found");
            return;
        }

        // Shared durable state location (outlives all three run workspaces).
        let state_dir = super::super::workspace::Workspace::new().expect("state dir");
        let canonical_state_dir =
            std::fs::canonicalize(state_dir.path()).expect("canonical state dir");
        let state_path = canonical_state_dir.join("terraform-step-e2e.tfstate");
        let backend_template = format!(
            "terraform {{\n  backend \"local\" {{\n    path = \"{}\"\n  }}\n}}\n",
            canonical_state_dir
                .join("terraform-{STATE_KEY}.tfstate")
                .display()
        );
        let backend = IsolatedBackendConfig::from_template_with_local_state_root(
            &backend_template,
            "step-e2e",
            Some(&canonical_state_dir),
        )
        .expect("isolated backend");

        let plan = live_plan("request-preflight");

        // Phase 1: produce process-local plan bytes in fresh workspace #1.
        // The production LivePlan path correctly refuses request-preflight's
        // non-server projection; this test-only helper exercises state lineage
        // without manufacturing approvable evidence.
        let tfplan = execution_e2e_tfplan(&plan, &backend);
        assert!(!tfplan.is_empty(), "saved tfplan must exist");

        // Phase 2: live apply of the SAVED plan (fresh workspace #2) — the
        // resource lands in the shared backend state.
        let applied = live_terraform_apply("terraform", &plan, &dummy_creds(), &backend, &tfplan)
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
    fn plan_evidence_projection_keeps_only_the_approval_allowlist() {
        let plan = server_deployment_plan();
        let raw = serde_json::json!({
            "timestamp": "2026-07-01T05:30:04Z",
            "planned_values": {
                "provider_private_field": "raw-provider-sentinel-a"
            },
            "configuration": {
                "provider_config": "raw-configuration-sentinel"
            },
            "resource_changes": [
                {"address":"data.vsphere_datacenter.dc","mode":"data","type":"vsphere_datacenter","name":"dc","change":{"actions":["read"],"after":{"name":"dc-a","provider_id":"raw-dc-id"}}},
                {"address":"data.vsphere_compute_cluster.cluster","mode":"data","type":"vsphere_compute_cluster","name":"cluster","change":{"actions":["read"],"after":{"name":"cluster-a","provider_id":"raw-cluster-id"}}},
                {"address":"data.vsphere_datastore.ds","mode":"data","type":"vsphere_datastore","name":"ds","change":{"actions":["read"],"after":{"name":"datastore-a","provider_id":"raw-datastore-id"}}},
                {"address":"data.vsphere_network.net","mode":"data","type":"vsphere_network","name":"net","change":{"actions":["read"],"after":{"name":"network-a","provider_id":"raw-network-id"}}},
                {"address":"data.vsphere_virtual_machine.template","mode":"data","type":"vsphere_virtual_machine","name":"template","change":{"actions":["read"],"after":{"name":"template-a","provider_id":"raw-template-id"}}},
                {"address":"vsphere_virtual_machine.linux_server","mode":"managed","type":"vsphere_virtual_machine","name":"linux_server","change":{"actions":["create"],"after":{"name":"vm-test-01","num_cpus":4,"memory":8192,"disk":[{"label":"disk0","size":120,"provider_path":"raw-disk-path"}],"opaque_private":"raw-managed-sentinel"}}}
            ]
        });
        let canonical = canonicalize_plan_json(&raw.to_string()).expect("canonical plan");
        let evidence = project_plan_evidence(&canonical, &plan)
            .expect("the complete vSphere projection must be approvable");
        let projected: serde_json::Value =
            serde_json::from_str(&evidence).expect("projected evidence JSON");

        assert_eq!(
            projected["schema_version"],
            "ryuki.terraform.live-plan-evidence.v1"
        );
        assert_eq!(projected["projection_complete"], true);
        assert_eq!(
            projected["canonical_plan_sha256"]
                .as_str()
                .expect("digest")
                .len(),
            64
        );
        assert_eq!(
            projected["resource_changes"]
                .as_array()
                .expect("safe changes")
                .len(),
            6
        );
        for forbidden in [
            "raw-provider-sentinel-a",
            "raw-configuration-sentinel",
            "raw-dc-id",
            "raw-cluster-id",
            "raw-datastore-id",
            "raw-network-id",
            "raw-template-id",
            "raw-disk-path",
            "raw-managed-sentinel",
            "address",
        ] {
            assert!(
                !evidence.contains(forbidden),
                "raw plan field {forbidden:?} must not enter durable evidence"
            );
        }
    }

    #[test]
    fn hidden_plan_changes_affect_integrity_digest_without_entering_evidence() {
        let plan = server_deployment_plan();
        let make_plan = |hidden: &str| {
            serde_json::json!({
                "planned_values": { "hidden": hidden },
                "resource_changes": [{
                    "mode":"managed",
                    "type":"vsphere_virtual_machine",
                    "name":"linux_server",
                    "change": {
                        "actions":["create"],
                        "after": {
                            "name":"vm-test-01",
                            "num_cpus":4,
                            "memory":8192,
                            "disk":[{"label":"disk0","size":120}]
                        }
                    }
                }]
            })
            .to_string()
        };
        let first: serde_json::Value = serde_json::from_str(
            &project_plan_evidence(&make_plan("hidden-a"), &plan).expect("safe projection"),
        )
        .unwrap();
        let second: serde_json::Value = serde_json::from_str(
            &project_plan_evidence(&make_plan("hidden-b"), &plan).expect("safe projection"),
        )
        .unwrap();
        assert_eq!(first["resource_changes"], second["resource_changes"]);
        assert_ne!(
            first["canonical_plan_sha256"], second["canonical_plan_sha256"],
            "the safe envelope must still commit to hidden semantic changes"
        );
        assert!(!first.to_string().contains("hidden-a"));
        assert!(!second.to_string().contains("hidden-b"));
    }

    #[test]
    fn raw_secret_changes_do_not_collide_when_redacted_projections_match() {
        let plan = server_deployment_plan();
        let make_plan = |secret: &str| {
            serde_json::json!({
                "planned_values": {"provider_private": secret},
                "resource_changes": [{
                    "mode":"managed",
                    "type":"vsphere_virtual_machine",
                    "name":"linux_server",
                    "change": {
                        "actions":["create"],
                        "after": {
                            "name":"vm-test-01",
                            "num_cpus":4,
                            "memory":8192,
                            "disk":[{"label":"disk0","size":120}]
                        }
                    }
                }]
            })
            .to_string()
        };
        let first_raw = make_plan("provider-secret-alpha");
        let second_raw = make_plan("provider-secret-bravo");
        assert_eq!(
            scrub(&first_raw, &[b"provider-secret-alpha"]),
            scrub(&second_raw, &[b"provider-secret-bravo"]),
            "the regression fixture must collide after value redaction"
        );

        let first_canonical = canonicalize_plan_json(&first_raw).expect("first canonical plan");
        let second_canonical = canonicalize_plan_json(&second_raw).expect("second canonical plan");
        let first = project_plan_evidence(&first_canonical, &plan).expect("first safe projection");
        let second =
            project_plan_evidence(&second_canonical, &plan).expect("second safe projection");
        let first: serde_json::Value = serde_json::from_str(&first).expect("first evidence");
        let second: serde_json::Value = serde_json::from_str(&second).expect("second evidence");
        assert_eq!(first["resource_changes"], second["resource_changes"]);
        assert_ne!(
            first["canonical_plan_sha256"], second["canonical_plan_sha256"],
            "the commitment must be computed before non-injective redaction"
        );
        for evidence in [first.to_string(), second.to_string()] {
            assert!(!evidence.contains("provider-secret-alpha"));
            assert!(!evidence.contains("provider-secret-bravo"));
        }
    }

    #[test]
    fn unknown_plan_changes_fail_closed_without_echoing_raw_fields() {
        let plan = server_deployment_plan();
        let canonical = serde_json::json!({
            "resource_changes": [{
                "mode": "managed",
                "type": "raw-unknown-provider-type",
                "name": "raw-unknown-resource-name",
                "change": {"actions": ["create"], "after": {"opaque": "raw-private-value"}}
            }]
        })
        .to_string();
        let evidence = project_plan_evidence(&canonical, &plan)
            .expect_err("an unknown resource must make the plan non-approvable");
        let projected: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        assert_eq!(projected["projection_complete"], false);
        assert_eq!(
            projected["resource_changes"][0]["change"]["actions"][0],
            "unsupported"
        );
        assert!(!evidence.contains("raw-unknown-provider-type"));
        assert!(!evidence.contains("raw-unknown-resource-name"));
        assert!(!evidence.contains("raw-private-value"));
    }

    #[test]
    fn unsupported_actions_and_missing_changes_fail_closed() {
        let plan = server_deployment_plan();
        let unsupported_action = serde_json::json!({
            "resource_changes": [{
                "mode": "managed",
                "type": "vsphere_virtual_machine",
                "name": "linux_server",
                "change": {"actions": ["create", "update"], "after": {}}
            }]
        })
        .to_string();

        for canonical in [unsupported_action.as_str(), "{\"planned_values\":{}}"] {
            let evidence = project_plan_evidence(canonical, &plan)
                .expect_err("unsupported or missing change semantics must fail closed");
            let projected: serde_json::Value = serde_json::from_str(&evidence).unwrap();
            assert_eq!(projected["projection_complete"], false);
            assert_eq!(
                projected["resource_changes"][0]["change"]["actions"][0],
                "unsupported"
            );
        }
    }

    #[test]
    fn bounded_tfplan_reader_accepts_exact_limit_and_rejects_overflow() {
        let ws = super::super::workspace::Workspace::new().expect("workspace");
        let exact = ws.path().join("exact-plan");
        std::fs::write(&exact, vec![b'x'; 16]).expect("write exact fixture");
        assert_eq!(
            read_bounded_file(&exact, 16, "test plan").expect("exact limit"),
            vec![b'x'; 16]
        );

        let over = ws.path().join("over-plan");
        std::fs::write(&over, vec![b'y'; 17]).expect("write over fixture");
        let error = read_bounded_file(&over, 16, "test plan").expect_err("must reject overflow");
        assert!(error.to_string().contains("safe artifact limit"));
    }

    #[test]
    fn live_plan_artifacts_debug_never_prints_raw_tfplan_bytes() {
        let artifacts = LivePlanArtifacts {
            outcome: RunOutcome {
                runner_kind: RunnerKind::Terraform,
                mode: RunMode::Live,
                status: RunStatus::Planned,
                summary: "safe".to_string(),
                log: "{}".to_string(),
                exit_code: Some(0),
                post_apply: None,
            },
            raw_plan_digest: Some(sha256_hex(b"canonical-plan")),
            tfplan: b"raw-tfplan-debug-sentinel".to_vec(),
        };
        let debug = format!("{artifacts:?}");
        assert!(!debug.contains("raw-tfplan-debug-sentinel"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn secret_env_pairs_maps_each_name_to_native_and_tf_var_forms() {
        // Each declared name yields its verbatim provider-native env var AND the
        // TF_VAR_<lowercase> terraform-variable alias, each with ITS OWN value
        // (multi-credential mis-pairing bug guard).
        let names = vec!["VSPHERE_USER".to_string(), "VSPHERE_PASSWORD".to_string()];
        let pairs = secret_env_pairs(&names, "admin@vsphere.local,hunter2");
        let projected: Vec<(String, String)> = pairs
            .iter()
            .map(|(name, value)| (name.clone(), value.as_str().to_string()))
            .collect();
        assert_eq!(
            projected,
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
        let lowercase_pairs = secret_env_pairs(&["token".to_string()], "abc123");
        let lowercase_projected: Vec<(String, String)> = lowercase_pairs
            .iter()
            .map(|(name, value)| (name.clone(), value.as_str().to_string()))
            .collect();
        assert_eq!(
            lowercase_projected,
            vec![
                ("token".to_string(), "abc123".to_string()),
                ("TF_VAR_token".to_string(), "abc123".to_string()),
            ]
        );
        // No names, or no creds → nothing injected.
        assert!(secret_env_pairs(&[], "abc").is_empty());
        assert!(secret_env_pairs(&["x".to_string()], "").is_empty());
    }

    #[test]
    fn provider_basic_auth_redaction_pairs_only_explicit_declared_names() {
        // Deliberately reorder the components: the typed names, not adjacency
        // or a Cartesian guess, establish the one approved Basic-auth pair.
        let names = vec![
            "VSPHERE_PASSWORD".to_string(),
            "VSPHERE_SERVER".to_string(),
            "VSPHERE_USER".to_string(),
        ];
        let components = vec![
            b"typed-pass-canary".to_vec(),
            b"vcenter.test.invalid".to_vec(),
            b"typed-user-canary".to_vec(),
        ];
        let derived =
            provider_basic_auth_redaction_values(&names, &components).expect("typed pair");
        assert_eq!(derived.len(), 2, "canonical expansion stays bounded");
        assert!(derived
            .iter()
            .any(|value| value.as_slice() == b"typed-user-canary:typed-pass-canary"));
        assert!(derived.iter().any(|value| {
            value.as_slice() == b"dHlwZWQtdXNlci1jYW5hcnk6dHlwZWQtcGFzcy1jYW5hcnk="
        }));

        let unrelated_names = vec!["API_USER".to_string(), "API_TOKEN".to_string()];
        assert!(
            provider_basic_auth_redaction_values(&unrelated_names, &components[..2])
                .expect("unrelated schema")
                .is_empty(),
            "untyped components must not be combined"
        );
    }

    #[test]
    fn provider_basic_auth_redaction_rejects_ambiguous_schema_without_secret_echo() {
        let components = vec![
            b"never-echo-user-canary".to_vec(),
            b"never-echo-pass-canary".to_vec(),
        ];
        let partial = provider_basic_auth_redaction_values(
            &["VSPHERE_USER".to_string(), "OTHER".to_string()],
            &components,
        )
        .expect_err("partial typed pair must fail closed")
        .to_string();
        assert!(partial.contains("declared together"));
        assert!(!partial.contains("never-echo"));

        let duplicate = provider_basic_auth_redaction_values(
            &[
                "VSPHERE_USER".to_string(),
                "VSPHERE_USER".to_string(),
                "VSPHERE_PASSWORD".to_string(),
            ],
            &[
                b"never-echo-user-a".to_vec(),
                b"never-echo-user-b".to_vec(),
                b"never-echo-pass".to_vec(),
            ],
        )
        .expect_err("duplicate typed name must fail closed")
        .to_string();
        assert!(duplicate.contains("more than once"));
        assert!(!duplicate.contains("never-echo"));
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

    #[test]
    fn live_step_refuses_unregistered_credential_env_value_before_spawn() {
        let ws = super::super::workspace::Workspace::new().expect("ws");
        let names = vec!["PROVIDER_TOKEN".to_string()];
        let error = match run_tf_step(
            Path::new("/nonexistent/terraform-unregistered-secret"),
            &["plan"],
            ws.path(),
            &names,
            "unregistered-value",
            &[],
            TfStepControl {
                truncate: true,
                cancellation: None,
            },
        ) {
            Ok(_) => panic!("unregistered credential env value reached the spawn boundary"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("not registered in the output redactor"),
            "{error}"
        );
        assert!(!error.contains("unregistered-value"), "{error}");
    }

    #[test]
    fn live_step_refuses_provider_env_names_that_overlap_backend_credentials() {
        for env_name in [
            "AWS_SECRET_ACCESS_KEY",
            "ARM_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "ALIBABA_CLOUD_SECURITY_TOKEN",
            "CONSUL_HTTP_TOKEN",
            "PGPASSWORD",
            "KUBE_TOKEN",
            "ETCDV3_PASSWORD",
            "TF_HTTP_PASSWORD",
            "TF_TOKEN_app_terraform_io",
        ] {
            let ws = super::super::workspace::Workspace::new().expect("ws");
            let names = vec![env_name.to_string()];
            let error = run_tf_step(
                Path::new("/nonexistent/terraform-backend-env-overlap"),
                &["plan"],
                ws.path(),
                &names,
                "registered-test-value",
                &[b"registered-test-value".as_slice()],
                TfStepControl {
                    truncate: true,
                    cancellation: None,
                },
            )
            .err()
            .expect("backend credential env overlap must fail before spawn")
            .to_string();
            assert!(
                error.contains("overlaps a backend credential source"),
                "{error}"
            );
            assert!(!error.contains("registered-test-value"), "{error}");
        }
        assert!(!is_backend_credential_env_name("VSPHERE_PASSWORD"));
    }

    /// End-to-end injection proof on the LIVE path: the terraform child sees
    /// exactly the DECLARED vsphere env vars (provider-native + TF_VAR alias),
    /// each paired with its own value — and nothing else credential-shaped:
    /// no RYUKI_LIVE_CRED_* passthrough and no undeclared parent env leakage.
    #[test]
    fn live_operations_inject_only_registered_secret_env_vars() {
        let ws_probe = super::super::workspace::Workspace::new().expect("ws");
        let probe_dir = ws_probe.path().to_string_lossy().to_string();
        let shim = ws_probe.path().join("fake-tf-env-dump");
        let provider_user = "user-value-a";
        let provider_password = "pass-value-b"; // secret-scan-allow: inert unit-test fixture
        let provider_server = "vcenter<\u{2028}canary";
        let [_, basic_auth_encoded] = basic_auth_canonical_variants(
            Some(provider_user.as_bytes()),
            Some(provider_password.as_bytes()),
        )
        .expect("typed Basic-auth fixture");
        let basic_auth_encoded = String::from_utf8(basic_auth_encoded).expect("Base64 is ASCII");
        let go_json_default = r"vcenter\u003c\u2028canary";
        let go_json_no_html = r"vcenter<\u2028canary";
        let encoded_diagnostic = format!(
            "basic={basic_auth_encoded} go-default={go_json_default} go-no-html={go_json_no_html}"
        );

        // The shim dumps its environment per step, emits transformed provider
        // credentials through the real stdout scrub boundary, emits valid JSON
        // for `show`, and writes the stub tfplan for the plan step.
        std::fs::write(
            &shim,
            format!(
                r#"#!/bin/sh
if [ "$1" = version ]; then exit 0; fi
env > "{probe_dir}/env-$1"
if [ "$1" = show ]; then
  echo '{{"format_version":"1.2","resource_changes":[]}}'
  exit 0
fi
case "$1" in
  plan) printf '%s\n' 'Plan: {encoded_diagnostic}' ;;
  apply) printf '%s\n' 'Apply complete! {encoded_diagnostic}' ;;
  destroy) printf '%s\n' 'Destroy complete! {encoded_diagnostic}' ;;
  *) printf '%s\n' 'diagnostic={encoded_diagnostic}' ;;
esac
touch "$PWD/tfplan"
exit 0
"#
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
            material: format!("{provider_user},{provider_password},{provider_server}").into_bytes(),
            descriptor: "test:vsphere".to_string(),
        };

        let backend = test_backend();
        let result = live_terraform_plan(&shim.to_string_lossy(), &plan, &creds, &backend)
            .expect("env-dump shim plan must not error");
        assert_eq!(result.outcome.status, RunStatus::Planned);

        let applied = live_terraform_apply(
            &shim.to_string_lossy(),
            &plan,
            &creds,
            &backend,
            &result.tfplan,
        )
        .expect("env-dump shim apply must not error");
        assert_eq!(applied.status, RunStatus::Applied);

        let destroyed = live_terraform_destroy(&shim.to_string_lossy(), &plan, &creds, &backend)
            .expect("env-dump shim destroy must not error");
        assert_eq!(destroyed.status, RunStatus::Applied);

        for step in ["init", "plan", "apply", "destroy"] {
            let dump = std::fs::read_to_string(ws_probe.path().join(format!("env-{step}")))
                .unwrap_or_else(|e| panic!("env dump for {step} must exist: {e}"));
            // Declared provider-native vars, each with ITS OWN value.
            assert!(
                dump.contains(&format!("VSPHERE_USER={provider_user}")),
                "{step}: {dump}"
            );
            assert!(
                dump.contains(&format!("VSPHERE_PASSWORD={provider_password}")), // secret-scan-allow: fixture value, not a credential
                "{step}: {dump}"
            );
            assert!(
                dump.contains(&format!("VSPHERE_SERVER={provider_server}")),
                "{step}: {dump}"
            );
            // Terraform-variable aliases for the bundle's `var.vsphere_*` refs.
            assert!(
                dump.contains(&format!("TF_VAR_vsphere_user={provider_user}")),
                "{step}: {dump}"
            );
            assert!(
                dump.contains(&format!("TF_VAR_vsphere_password={provider_password}")), // secret-scan-allow: fixture value, not a credential
                "{step}: {dump}"
            );
            assert!(
                dump.contains(&format!("TF_VAR_vsphere_server={provider_server}")),
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
        for value in [provider_user, provider_password, provider_server] {
            assert!(
                !result.outcome.log.contains(value)
                    && !result.outcome.summary.contains(value)
                    && !applied.log.contains(value)
                    && !applied.summary.contains(value)
                    && !destroyed.log.contains(value)
                    && !destroyed.summary.contains(value),
                "credential value {value:?} must be scrubbed from evidence"
            );
        }
        for transformed in [
            basic_auth_encoded.as_str(),
            go_json_default,
            go_json_no_html,
        ] {
            assert!(
                !result.outcome.log.contains(transformed)
                    && !result.outcome.summary.contains(transformed)
                    && !applied.log.contains(transformed)
                    && !applied.summary.contains(transformed)
                    && !destroyed.log.contains(transformed)
                    && !destroyed.summary.contains(transformed),
                "transformed credential {transformed:?} must be scrubbed on every live operation"
            );
        }
        assert!(result.outcome.summary.contains("[REDACTED]"));
        assert!(applied.log.contains("[REDACTED]"));
        assert!(destroyed.log.contains("[REDACTED]"));

        std::env::remove_var("RYUKI_LIVE_CRED_VSPHERE_USER");
        std::env::remove_var("RYUKI_TEST_PARENT_SECRET");
    }
}
