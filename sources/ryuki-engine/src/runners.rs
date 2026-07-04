//! Runner shapes (pure, no I/O).
//!
//! This module defines the pure data types that describe a runner invocation
//! and its result. No process-spawning, no filesystem access, no network.
//! The API/runner crate consumes these shapes to do the actual work.

use crate::models::AdapterType;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// ResolvedCredentials — resolved secret material (zeroized on drop)
// ---------------------------------------------------------------------------

/// Resolved credential material for a single runner invocation.
///
/// # Security
/// - Does NOT implement Serialize — cannot be accidentally written to an HTTP response.
/// - Debug output is REDACTED — safe to include in trace logs without leaking secrets.
/// - MUST be kept short-lived. Never stored in a static or long-lived structure.
/// - Material is zeroized on drop so secrets do not linger in heap memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ResolvedCredentials {
    /// Opaque resolved material — interpretation depends on CredentialSource.
    /// For DbEncrypted: the decrypted plaintext (zeroized on drop).
    /// For EnvVar: the concatenated env var values.
    /// For Vault/MockVault: an opaque marker (real client is a later slice).
    pub material: Vec<u8>,
    /// Human-readable descriptor for tracing (MUST NOT contain secret material).
    pub descriptor: String,
}

// Custom Debug: ALWAYS redacted — never print the material.
impl std::fmt::Debug for ResolvedCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ResolvedCredentials {{ descriptor: {:?}, material: [REDACTED {} bytes] }}",
            self.descriptor,
            self.material.len()
        )
    }
}

// ---------------------------------------------------------------------------
// RunnerKind — which tool executes this run
// ---------------------------------------------------------------------------

/// Which execution tool handles the request.
/// Build operations use Terraform; Maintain operations use Ansible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerKind {
    Terraform,
    Ansible,
}

impl RunnerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::Ansible => "ansible",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "terraform" => Ok(Self::Terraform),
            "ansible" => Ok(Self::Ansible),
            other => Err(format!(
                "Invalid RunnerKind '{other}'. Expected: terraform, ansible"
            )),
        }
    }
}

impl std::fmt::Display for RunnerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RunMode — per-invocation intent (dry-run vs live)
// ---------------------------------------------------------------------------

/// Whether this specific invocation makes changes or only plans/checks.
///
/// This is distinct from `ExecutionMode` (which is a per-connection capability
/// flag). `RunMode::Live` is only reachable when the connection permits it AND
/// the global kill-switch is enabled AND the request is fully approved.
/// Slice 1 only uses `DryRun`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunMode {
    /// No changes are made. Terraform plan / ansible-playbook --check.
    DryRun,
    /// Changes are applied. Requires approval + kill-switch + Live connection.
    /// NOT implemented in Slice 1.
    Live,
}

impl RunMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DryRun => "dry-run",
            Self::Live => "live",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "dry-run" => Ok(Self::DryRun),
            "live" => Ok(Self::Live),
            other => Err(format!(
                "Invalid RunMode '{other}'. Expected: dry-run, live"
            )),
        }
    }
}

impl std::fmt::Display for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RunPlan — what to run (no secrets)
// ---------------------------------------------------------------------------

/// Describes a planned runner invocation built from offering + request inputs.
///
/// # Security
/// - MUST NOT carry secret material. Credentials are injected separately by
///   the runner at execution time from `ResolvedCredentials`.
/// - `vars` holds non-secret Terraform variables or Ansible extra-vars.
/// - `secret_var_names` lists which var names expect credential values
///   (the runner injects those from `ResolvedCredentials`, never from `vars`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunPlan {
    /// Which tool runs this plan.
    pub runner_kind: RunnerKind,
    /// Whether to plan/check only (Slice 1) or apply/run (Slice 2+).
    pub mode: RunMode,
    /// Offering identifier — used to locate the module/playbook.
    pub offering_id: String,
    /// Non-secret Terraform variables or Ansible extra-vars.
    /// Written to a vars file in the isolated workspace.
    pub vars: BTreeMap<String, String>,
    /// Names of vars whose values come from `ResolvedCredentials`, not `vars`.
    /// The runner uses this list to inject secrets securely and never puts
    /// their values in `vars` or on the command line.
    pub secret_var_names: Vec<String>,
}

// ---------------------------------------------------------------------------
// RunStatus — outcome classification
// ---------------------------------------------------------------------------

/// High-level status of a completed runner invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    /// Terraform plan completed with no errors (may have planned changes).
    Planned,
    /// Terraform apply completed successfully (changes were made).
    Applied,
    /// Ansible --check completed with no changes needed.
    CheckOk,
    /// Ansible --check or run completed; changes were found or applied.
    Changed,
    /// The runner binary exited with a non-zero code.
    Failed,
    /// The binary is not present or not executable; no run was attempted.
    RunnerUnavailable,
    /// Workspace setup failed before the binary was invoked.
    WorkspaceError,
    /// `terraform validate` passed (configuration is schema-valid) but
    /// `terraform plan` was not attempted or failed gracefully because a live
    /// provider endpoint (e.g. vCenter) is not reachable offline. The IaC is
    /// confirmed correct against the real provider schema; live planning
    /// requires a reachable provider.
    Validated,
}

impl RunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Applied => "applied",
            Self::CheckOk => "check-ok",
            Self::Changed => "changed",
            Self::Failed => "failed",
            Self::RunnerUnavailable => "runner-unavailable",
            Self::WorkspaceError => "workspace-error",
            Self::Validated => "validated",
        }
    }
}

impl std::fmt::Display for RunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RunOutcome — returned to lifecycle after a run
// ---------------------------------------------------------------------------

/// The result of a runner invocation — safe to store as evidence.
///
/// # Security
/// - `summary` and `log` MUST be pre-scrubbed of secret values before
///   construction. The runner pre-scrubs; `evidence_pipeline::redact_evidence`
///   applies a second pattern-based redaction as defense-in-depth.
/// - This struct may be serialized into stage evidence; secrets MUST NOT
///   appear in any field, even in a truncated or encoded form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunOutcome {
    pub runner_kind: RunnerKind,
    pub mode: RunMode,
    pub status: RunStatus,
    /// Human-readable one-line summary (scrubbed). E.g. "Plan: +2 ~0 -0" or
    /// "runner unavailable: terraform binary not found at /usr/bin/terraform".
    pub summary: String,
    /// Scrubbed, truncated stdout/stderr excerpt for evidence.
    pub log: String,
    /// Process exit code, if the binary was invoked.
    pub exit_code: Option<i32>,
    /// #43 post-apply verification verdict. `Some` only for a live `terraform apply`
    /// that ran the post-apply re-plan; `None` for every other outcome (dry-run,
    /// plan, ansible, error paths). Rides in the serialized evidence to the CP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_apply: Option<crate::post_apply::PostApplyOutcome>,
}

// ---------------------------------------------------------------------------
// RunnerError — non-secret error type
// ---------------------------------------------------------------------------

/// Errors from runner setup or invocation.
///
/// # Security
/// No variant carries secret material. `WorkspaceSetup` and `Spawn` carry
/// only OS error descriptions (paths, errno). `NonZeroExit` carries only the
/// exit code and a pre-scrubbed stderr excerpt.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunnerError {
    #[error("runner binary not found: {0}")]
    BinaryNotFound(String),
    #[error("workspace setup failed: {0}")]
    WorkspaceSetup(String),
    #[error("failed to spawn runner process: {0}")]
    Spawn(String),
    #[error("runner exited with code {code}: {scrubbed_stderr}")]
    NonZeroExit {
        code: i32,
        /// Pre-scrubbed stderr excerpt — MUST NOT contain secret material.
        scrubbed_stderr: String,
    },
    #[error("runner timed out")]
    Timeout,
    #[error("credential injection failed: {0}")]
    CredInjection(String),
}

// ---------------------------------------------------------------------------
// classify — vendor taxonomy → RunnerKind (pure)
// ---------------------------------------------------------------------------

/// Map a vendor adapter type to the runner kind that handles it.
///
/// Convention (from the execution model):
/// - **Terraform**: BUILD operations — hypervisors, cloud platforms, storage
///   provisioning, network infrastructure (VMware, Hyper-V, Proxmox, etc.)
/// - **Ansible**: MAINTAIN operations — day-2 configuration, monitoring
///   agents, backup clients, ITSM integrations (Zabbix, Veeam, ServiceNow, etc.)
///
/// This mapping is intentionally coarse: the exact module/playbook is resolved
/// from the offering catalog. The runner kind tells the lifecycle which tool to
/// invoke; the offering tells it what to run.
pub fn classify(vendor_type: &AdapterType) -> RunnerKind {
    match vendor_type {
        // Hypervisors and compute platforms → Terraform (BUILD)
        AdapterType::VMware
        | AdapterType::HyperV
        | AdapterType::Proxmox
        | AdapterType::NutanixAhv
        | AdapterType::Xen
        | AdapterType::Kvm => RunnerKind::Terraform,

        // Backup and data protection agents → Ansible (MAINTAIN)
        AdapterType::Veeam
        | AdapterType::VeeamOne
        | AdapterType::Commvault
        | AdapterType::Rubrik
        | AdapterType::Cohesity
        | AdapterType::NetBackup => RunnerKind::Ansible,

        // Monitoring and observability agents → Ansible (MAINTAIN)
        AdapterType::Zabbix
        | AdapterType::Prometheus
        | AdapterType::Datadog
        | AdapterType::Grafana
        | AdapterType::SolarWinds => RunnerKind::Ansible,

        // ITSM and workflow integrations → Ansible (MAINTAIN)
        AdapterType::ServiceNow => RunnerKind::Ansible,
    }
}

// ---------------------------------------------------------------------------
// build_run_plan — construct a RunPlan from offering + request inputs (pure)
// ---------------------------------------------------------------------------

/// Build a `RunPlan` from offering metadata and non-secret request inputs.
///
/// # Arguments
/// * `vendor_type` — vendor adapter type used to select the runner kind.
/// * `offering_id` — offering identifier; used to locate the module/playbook.
/// * `mode` — `DryRun` (plan/check) or `Live` (apply/run, Slice 2+).
/// * `vars` — non-secret input variables from the request (caller ensures
///   no secret material is included here).
/// * `secret_var_names` — names of vars whose values come from credentials.
///
/// # Security
/// The caller is responsible for ensuring `vars` does not contain secret
/// material. Secret values are never part of `RunPlan`; only their names are
/// listed in `secret_var_names` so the runner can inject them from
/// `ResolvedCredentials` at execution time.
pub fn build_run_plan(
    vendor_type: &AdapterType,
    offering_id: &str,
    mode: RunMode,
    vars: BTreeMap<String, String>,
    secret_var_names: Vec<String>,
) -> RunPlan {
    RunPlan {
        runner_kind: classify(vendor_type),
        mode,
        offering_id: offering_id.to_string(),
        vars,
        secret_var_names,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- RunnerKind ---

    #[test]
    fn runner_kind_as_str_and_parse_roundtrip() {
        assert_eq!(RunnerKind::Terraform.as_str(), "terraform");
        assert_eq!(RunnerKind::Ansible.as_str(), "ansible");
        assert_eq!(
            RunnerKind::parse("terraform").unwrap(),
            RunnerKind::Terraform
        );
        assert_eq!(RunnerKind::parse("ansible").unwrap(), RunnerKind::Ansible);
    }

    #[test]
    fn runner_kind_parse_rejects_unknown() {
        assert!(RunnerKind::parse("puppet").is_err());
        assert!(RunnerKind::parse("").is_err());
    }

    #[test]
    fn runner_kind_display_matches_as_str() {
        assert_eq!(RunnerKind::Terraform.to_string(), "terraform");
        assert_eq!(RunnerKind::Ansible.to_string(), "ansible");
    }

    // --- RunMode ---

    #[test]
    fn run_mode_as_str_and_parse_roundtrip() {
        assert_eq!(RunMode::DryRun.as_str(), "dry-run");
        assert_eq!(RunMode::Live.as_str(), "live");
        assert_eq!(RunMode::parse("dry-run").unwrap(), RunMode::DryRun);
        assert_eq!(RunMode::parse("live").unwrap(), RunMode::Live);
    }

    #[test]
    fn run_mode_parse_rejects_unknown() {
        assert!(RunMode::parse("plan").is_err());
        assert!(RunMode::parse("").is_err());
    }

    // --- RunStatus ---

    #[test]
    fn run_status_as_str_all_variants() {
        assert_eq!(RunStatus::Planned.as_str(), "planned");
        assert_eq!(RunStatus::Applied.as_str(), "applied");
        assert_eq!(RunStatus::CheckOk.as_str(), "check-ok");
        assert_eq!(RunStatus::Changed.as_str(), "changed");
        assert_eq!(RunStatus::Failed.as_str(), "failed");
        assert_eq!(RunStatus::RunnerUnavailable.as_str(), "runner-unavailable");
        assert_eq!(RunStatus::WorkspaceError.as_str(), "workspace-error");
        assert_eq!(RunStatus::Validated.as_str(), "validated");
    }

    #[test]
    fn run_status_validated_serde_roundtrip() {
        let status = RunStatus::Validated;
        let json = serde_json::to_string(&status).expect("serialize");
        assert_eq!(json, "\"validated\"");
        let back: RunStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, RunStatus::Validated);
    }

    // --- classify ---

    #[test]
    fn classify_hypervisors_are_terraform() {
        use AdapterType::*;
        let hypervisors = [VMware, HyperV, Proxmox, NutanixAhv, Xen, Kvm];
        for vendor in &hypervisors {
            assert_eq!(
                classify(vendor),
                RunnerKind::Terraform,
                "{vendor} should map to Terraform"
            );
        }
    }

    #[test]
    fn classify_backup_agents_are_ansible() {
        use AdapterType::*;
        let backup = [Veeam, VeeamOne, Commvault, Rubrik, Cohesity, NetBackup];
        for vendor in &backup {
            assert_eq!(
                classify(vendor),
                RunnerKind::Ansible,
                "{vendor} should map to Ansible"
            );
        }
    }

    #[test]
    fn classify_monitoring_and_itsm_are_ansible() {
        use AdapterType::*;
        let monitoring = [Zabbix, Prometheus, Datadog, Grafana, SolarWinds, ServiceNow];
        for vendor in &monitoring {
            assert_eq!(
                classify(vendor),
                RunnerKind::Ansible,
                "{vendor} should map to Ansible"
            );
        }
    }

    // --- build_run_plan ---

    #[test]
    fn build_run_plan_vmware_produces_terraform_dryrun() {
        let vars = BTreeMap::from([
            ("vm_name".to_string(), "web-01".to_string()),
            ("cpu_count".to_string(), "4".to_string()),
        ]);
        let plan = build_run_plan(
            &AdapterType::VMware,
            "build-vm-standard",
            RunMode::DryRun,
            vars.clone(),
            vec!["vsphere_password".to_string()],
        );

        assert_eq!(plan.runner_kind, RunnerKind::Terraform);
        assert_eq!(plan.mode, RunMode::DryRun);
        assert_eq!(plan.offering_id, "build-vm-standard");
        assert_eq!(plan.vars, vars);
        assert_eq!(plan.secret_var_names, vec!["vsphere_password".to_string()]);
    }

    #[test]
    fn build_run_plan_zabbix_produces_ansible_dryrun() {
        let vars = BTreeMap::from([("target_host".to_string(), "srv-01.example.com".to_string())]);
        let plan = build_run_plan(
            &AdapterType::Zabbix,
            "maintain-monitoring-agent",
            RunMode::DryRun,
            vars.clone(),
            vec!["zabbix_api_token".to_string()],
        );

        assert_eq!(plan.runner_kind, RunnerKind::Ansible);
        assert_eq!(plan.mode, RunMode::DryRun);
        assert_eq!(plan.offering_id, "maintain-monitoring-agent");
        assert_eq!(plan.vars, vars);
        assert_eq!(plan.secret_var_names, vec!["zabbix_api_token".to_string()]);
    }

    #[test]
    fn build_run_plan_empty_vars_is_valid() {
        let plan = build_run_plan(
            &AdapterType::ServiceNow,
            "maintain-itsm-sync",
            RunMode::DryRun,
            BTreeMap::new(),
            vec![],
        );
        assert_eq!(plan.runner_kind, RunnerKind::Ansible);
        assert!(plan.vars.is_empty());
        assert!(plan.secret_var_names.is_empty());
    }

    // --- RunnerError ---

    #[test]
    fn runner_error_display_binary_not_found() {
        let err = RunnerError::BinaryNotFound("terraform".to_string());
        let msg = err.to_string();
        assert!(msg.contains("terraform"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn runner_error_non_zero_exit_does_not_expose_secrets() {
        // A non-zero exit error only carries the exit code and a scrubbed stderr.
        // Verify the Display does not accidentally include a secret placeholder.
        let err = RunnerError::NonZeroExit {
            code: 1,
            scrubbed_stderr: "Error: provider configuration is invalid".to_string(),
        };
        let msg = err.to_string();
        // Must contain exit code and scrubbed message.
        assert!(msg.contains("1"));
        assert!(msg.contains("provider configuration"));
        // The secret value itself must not appear (it was never put in the error).
        assert!(!msg.contains("FAKE_SECRET_VALUE"));
    }

    // --- serde roundtrips ---

    #[test]
    fn run_plan_serde_roundtrip() {
        let plan = build_run_plan(
            &AdapterType::VMware,
            "build-vm",
            RunMode::DryRun,
            BTreeMap::from([("region".to_string(), "eu-west".to_string())]),
            vec!["vcenter_password".to_string()],
        );
        let json = serde_json::to_string(&plan).expect("serialize");
        let back: RunPlan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(plan, back);
    }

    #[test]
    fn run_outcome_serde_roundtrip() {
        let outcome = RunOutcome {
            runner_kind: RunnerKind::Terraform,
            mode: RunMode::DryRun,
            status: RunStatus::Planned,
            summary: "Plan: +1 ~0 -0".to_string(),
            log: "Refreshing state...\nPlan: 1 to add.".to_string(),
            exit_code: Some(2),
            post_apply: None,
        };
        let json = serde_json::to_string(&outcome).expect("serialize");
        let back: RunOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, back);
    }
}
