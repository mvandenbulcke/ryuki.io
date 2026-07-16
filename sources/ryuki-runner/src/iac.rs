//! Per-offering IaC content resolver.
//!
//! Maps a request's `offering_id` (the `request_type` slug) to a set of
//! embedded Terraform HCL files. Only offerings with wired IaC return
//! `Some`; all others return `None` and keep the existing simulated behavior
//! unchanged.
//!
//! # Design
//! IaC content is embedded at compile time via `include_str!` so there are no
//! runtime filesystem reads and the binary is self-contained. Each file is a
//! `(&'static str, &'static str)` pair of `(filename, utf8_content)`.
//!
//! # Offline guarantee (per offering)
//! Built-in offerings (`patch-maintenance`, `request-preflight`) use ONLY
//! `terraform_data` resources — no external providers, fully offline init+plan.
//!
//! Server-deployment offerings (`linux-server-deployment`,
//! `windows-server-deployment`) use the real `vmware/vsphere` provider.
//! `terraform init` downloads the provider from the public registry (network
//! egress required once; cached by Terraform's plugin cache). `terraform
//! validate` then runs fully offline against the downloaded schema — this is
//! the correctness oracle. `terraform plan` requires a reachable vCenter and
//! is attempted best-effort; failure without a live endpoint degrades
//! gracefully to `RunStatus::Validated`.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

/// A bundle of IaC files for one offering.
///
/// Each entry is `(filename, utf8_content)` — the content is written verbatim
/// into the runner workspace before `terraform init`.
pub type IacBundle = Vec<(&'static str, &'static str)>;

/// Embedded IaC for the `patch-maintenance` offering.
const PATCH_MAINTENANCE_MAIN_TF: &str = include_str!("iac/patch-maintenance/main.tf");

/// Embedded Ansible playbook for the `patch-maintenance` offering.
const PATCH_MAINTENANCE_PLAYBOOK: &str =
    include_str!("iac/patch-maintenance/patch-maintenance.yml");

/// Embedded Terraform IaC for the `request-preflight` offering.
const REQUEST_PREFLIGHT_MAIN_TF: &str = include_str!("iac/request-preflight/main.tf");

/// Embedded Ansible playbook for the `zabbix-onboarding` offering.
const ZABBIX_ONBOARDING_PLAYBOOK: &str =
    include_str!("iac/zabbix-onboarding/zabbix-onboarding.yml");

/// Embedded Terraform IaC for the `linux-server-deployment` offering.
const LINUX_SERVER_DEPLOYMENT_MAIN_TF: &str = include_str!("iac/linux-server-deployment/main.tf");

/// Generated provider selections and checksums for Linux server deployment.
const LINUX_SERVER_DEPLOYMENT_LOCK_HCL: &str =
    include_str!("iac/linux-server-deployment/.terraform.lock.hcl");

/// Embedded Ansible playbook for the `linux-server-deployment` offering.
const LINUX_SERVER_DEPLOYMENT_PLAYBOOK: &str =
    include_str!("iac/linux-server-deployment/linux-server-deployment.yml");

/// Embedded Terraform IaC for the `windows-server-deployment` offering.
const WINDOWS_SERVER_DEPLOYMENT_MAIN_TF: &str =
    include_str!("iac/windows-server-deployment/main.tf");

/// Generated provider selections and checksums for Windows server deployment.
const WINDOWS_SERVER_DEPLOYMENT_LOCK_HCL: &str =
    include_str!("iac/windows-server-deployment/.terraform.lock.hcl");

/// Embedded Ansible playbook for the `controlled-restore-request` offering.
const CONTROLLED_RESTORE_REQUEST_PLAYBOOK: &str =
    include_str!("iac/controlled-restore-request/controlled-restore-request.yml");

/// How a request's logical inputs map onto an offering's variables.
#[derive(Clone, Copy)]
enum VarBinding {
    /// Map name/cpu/memory_gb/… onto a vSphere server-deployment module.
    ServerDeployment,
    /// Pass the request's raw metadata through unchanged (the legacy default).
    MetadataPassthrough,
}

/// One offering's complete IaC wiring: its embedded Terraform and/or Ansible
/// files and its variable binding. This is the SINGLE declarative source of
/// truth — `resolve`, `resolve_ansible`, `render_vars`, and
/// `offering_iac_digest` all derive from it, so an offering's IaC and its
/// var-binding can never drift apart. Adding a wired offering is one entry here
/// (plus the embedded template consts above) — no edits to the resolver/binder.
struct OfferingIac {
    id: &'static str,
    /// Terraform files `(filename, content)`; empty = no Terraform.
    terraform: &'static [(&'static str, &'static str)],
    /// Ansible files `(filename, content)`; empty = no Ansible.
    ansible: &'static [(&'static str, &'static str)],
    binding: VarBinding,
    /// Secret ENVIRONMENT VARIABLE names this offering's LIVE execution
    /// requires (provider credentials). Empty = the offering needs none.
    ///
    /// Contract (see [`live_secret_var_names`]):
    /// - The DECLARED name is the provider-native env var the offering's IaC
    ///   reads (e.g. the terraform vsphere provider reads `VSPHERE_USER` /
    ///   `VSPHERE_PASSWORD` / `VSPHERE_SERVER`).
    /// - The agent resolves each name from `RYUKI_LIVE_CRED_<NAME>` in ITS OWN
    ///   environment (fail-closed BEFORE any runner invocation when one is
    ///   missing) and passes the values as `ResolvedCredentials` material,
    ///   comma-joined in DECLARED ORDER — the order of this slice is the
    ///   pairing contract with the runner.
    /// - The runner injects each declared name (plus its `TF_VAR_<lowercase>`
    ///   terraform-variable alias) on the terraform child env for LIVE modes
    ///   ONLY. The offline dry-run path never receives credential material.
    live_secret_env: &'static [&'static str],
}

/// Secret env var names required by the vSphere server-deployment offerings.
/// The terraform vsphere provider reads exactly these provider-native vars.
/// Order is the credential pairing order (see `OfferingIac::live_secret_env`).
const VSPHERE_LIVE_SECRET_ENV: &[&str] = &["VSPHERE_USER", "VSPHERE_PASSWORD", "VSPHERE_SERVER"];

/// The offering → IaC registry (the single source of truth, see `OfferingIac`).
const OFFERINGS: &[OfferingIac] = &[
    OfferingIac {
        id: "patch-maintenance",
        terraform: &[("main.tf", PATCH_MAINTENANCE_MAIN_TF)],
        ansible: &[("patch-maintenance.yml", PATCH_MAINTENANCE_PLAYBOOK)],
        binding: VarBinding::MetadataPassthrough,
        live_secret_env: &[],
    },
    OfferingIac {
        id: "request-preflight",
        terraform: &[("main.tf", REQUEST_PREFLIGHT_MAIN_TF)],
        ansible: &[],
        binding: VarBinding::MetadataPassthrough,
        live_secret_env: &[],
    },
    OfferingIac {
        id: "zabbix-onboarding",
        terraform: &[],
        ansible: &[("zabbix-onboarding.yml", ZABBIX_ONBOARDING_PLAYBOOK)],
        binding: VarBinding::MetadataPassthrough,
        live_secret_env: &[],
    },
    OfferingIac {
        id: "linux-server-deployment",
        terraform: &[
            ("main.tf", LINUX_SERVER_DEPLOYMENT_MAIN_TF),
            (".terraform.lock.hcl", LINUX_SERVER_DEPLOYMENT_LOCK_HCL),
        ],
        ansible: &[(
            "linux-server-deployment.yml",
            LINUX_SERVER_DEPLOYMENT_PLAYBOOK,
        )],
        binding: VarBinding::ServerDeployment,
        live_secret_env: VSPHERE_LIVE_SECRET_ENV,
    },
    OfferingIac {
        id: "windows-server-deployment",
        terraform: &[
            ("main.tf", WINDOWS_SERVER_DEPLOYMENT_MAIN_TF),
            (".terraform.lock.hcl", WINDOWS_SERVER_DEPLOYMENT_LOCK_HCL),
        ],
        ansible: &[],
        binding: VarBinding::ServerDeployment,
        live_secret_env: VSPHERE_LIVE_SECRET_ENV,
    },
    OfferingIac {
        id: "controlled-restore-request",
        terraform: &[],
        ansible: &[(
            "controlled-restore-request.yml",
            CONTROLLED_RESTORE_REQUEST_PLAYBOOK,
        )],
        binding: VarBinding::MetadataPassthrough,
        live_secret_env: &[],
    },
];

/// Look up an offering's IaC wiring in the registry.
fn lookup(offering_id: &str) -> Option<&'static OfferingIac> {
    OFFERINGS.iter().find(|o| o.id == offering_id)
}

/// Resolve the effective offering ID for a request, applying the composite
/// managed-onboarding override, OS-based discrimination for
/// `server-deployment`, and name normalization for `controlled-restore`.
///
/// This is the single place where `request_type` (plus optional
/// `metadata["operating_system"]`/`metadata["deployment_profile"]`) maps to a
/// catalog offering_id:
///
/// - `"server-deployment"` + metadata `deployment_profile` ==
///   `"managed-onboarding"` → `"managed-server-onboarding"` (the composite,
///   multi-step offering; see [`offering_step_template`]). Checked BEFORE the
///   OS discrimination below, so a managed-onboarding request never falls
///   through to a single-job offering.
/// - `"server-deployment"` + metadata `operating_system` containing "windows"
///   (case-insensitive) → `"windows-server-deployment"`
/// - `"server-deployment"` + any other non-empty OS → `"linux-server-deployment"`
/// - `"server-deployment"` + absent/empty OS → `"server-deployment"` (unmapped;
///   callers fall through to graceful simulated behavior — do NOT guess)
/// - `"controlled-restore"` → `"controlled-restore-request"` (catalog name
///   differs from request_type slug)
/// - Anything else → `request.offering_id` unchanged (1:1 default)
pub fn resolve_offering_id(request: &ryuki_engine::models::Request) -> String {
    let request_type = request.request_type.to_string();
    match request_type.as_str() {
        "server-deployment" => {
            if request
                .metadata
                .get("deployment_profile")
                .map(String::as_str)
                == Some("managed-onboarding")
            {
                return "managed-server-onboarding".to_string();
            }
            match request.metadata.get("operating_system").map(String::as_str) {
                Some(os) if !os.trim().is_empty() => {
                    if os.to_ascii_lowercase().contains("windows") {
                        "windows-server-deployment".to_string()
                    } else {
                        "linux-server-deployment".to_string()
                    }
                }
                // absent or empty OS — do not guess, keep unmapped
                _ => "server-deployment".to_string(),
            }
        }
        "controlled-restore" => "controlled-restore-request".to_string(),
        _ => request.offering_id.clone(),
    }
}

/// One step of an offering's static multi-step plan TEMPLATE (see
/// [`offering_step_template`]). Distinct from `ryuki_engine::job_orchestration
/// ::Step`: a `StepTemplate` is the offering-authored blueprint (no status —
/// every step always starts `Pending`), while `Step` is the per-request
/// runtime state the orchestration engine reads back. `iac_ref` is a REAL
/// entry in the [`OFFERINGS`] registry (each step dispatches its own job off
/// its own IaC) — never the composite offering's own id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepTemplate {
    /// Stable per-plan step key (e.g. "preflight"). Unique within a template.
    pub key: &'static str,
    /// Keys of the steps that must SUCCEED before this step may dispatch.
    pub depends_on: &'static [&'static str],
    /// The `OFFERINGS` registry id this step's own job dispatches against.
    pub iac_ref: &'static str,
}

/// The step plan template for the composite `"managed-server-onboarding"`
/// offering: preflight check → Linux deployment → monitoring onboarding, each
/// depending on the previous step's success.
const MANAGED_SERVER_ONBOARDING_TEMPLATE: &[StepTemplate] = &[
    StepTemplate {
        key: "preflight",
        depends_on: &[],
        iac_ref: "request-preflight",
    },
    StepTemplate {
        key: "deploy",
        depends_on: &["preflight"],
        iac_ref: "linux-server-deployment",
    },
    StepTemplate {
        key: "monitor",
        depends_on: &["deploy"],
        iac_ref: "zabbix-onboarding",
    },
];

/// Resolve an offering's static multi-step plan template.
///
/// Returns a NON-EMPTY template only for the composite offering id
/// `"managed-server-onboarding"`. Every other offering id (including all
/// offerings actually present in the [`OFFERINGS`] IaC registry) returns
/// `&[]`, so a caller that materializes a plan only for a non-empty template
/// leaves every other offering exactly single-job — ZERO behavior change.
///
/// Note: `"managed-server-onboarding"` is deliberately NOT an [`OFFERINGS`]
/// registry entry — it never dispatches its OWN IaC. A multi-step request
/// dispatches one job per STEP, each against that step's own `iac_ref` (which
/// ARE real registry offerings). `offering_iac_digest("managed-server-onboarding")`
/// returning `None` is expected and is never consulted on the multi-step path.
pub fn offering_step_template(offering_id: &str) -> &'static [StepTemplate] {
    match offering_id {
        "managed-server-onboarding" => MANAGED_SERVER_ONBOARDING_TEMPLATE,
        _ => &[],
    }
}

/// Secret env var names the given offering's LIVE execution requires.
///
/// Returns the offering's declared provider-credential ENVIRONMENT VARIABLE
/// names (e.g. `["VSPHERE_USER", "VSPHERE_PASSWORD", "VSPHERE_SERVER"]` for
/// the vSphere server-deployment offerings), or an empty slice for offerings
/// that declare none and for unknown offering ids.
///
/// End-to-end contract:
/// 1. The agent's live executor populates `RunPlan.secret_var_names` from this
///    declaration (LIVE modes only — the offline dry-run plan always carries
///    an empty list and empty credential material).
/// 2. The agent resolves each declared `<NAME>` from `RYUKI_LIVE_CRED_<NAME>`
///    in its own environment, failing closed with the VARIABLE NAME (never a
///    value) BEFORE any runner/terraform invocation when one is missing.
/// 3. The runner injects each declared name verbatim (provider-native, e.g.
///    `VSPHERE_USER`) plus its `TF_VAR_<lowercased name>` terraform-variable
///    alias on the terraform child process env — live modes only, values
///    scrubbed from all output.
///
/// SLICE ORDER IS THE PAIRING CONTRACT: credential material travels as a
/// comma-joined string in declared order; agent and runner both iterate this
/// slice, so a declared name always receives its own value.
pub fn live_secret_var_names(offering_id: &str) -> &'static [&'static str] {
    lookup(offering_id)
        .map(|o| o.live_secret_env)
        .unwrap_or(&[])
}

/// Provider source and exact selected version parsed from the reviewed
/// offering's embedded Terraform dependency lock. Returning `None` is
/// fail-closed: unknown offerings, missing/ambiguous provider blocks, or a
/// malformed lock cannot acquire reviewed-live execution authority.
pub fn reviewed_live_provider_identity(offering_id: &str) -> Option<(String, String)> {
    let lock = match offering_id {
        "linux-server-deployment" => LINUX_SERVER_DEPLOYMENT_LOCK_HCL,
        "windows-server-deployment" => WINDOWS_SERVER_DEPLOYMENT_LOCK_HCL,
        _ => return None,
    };

    let mut provider_source: Option<String> = None;
    let mut provider_version: Option<String> = None;
    let mut in_provider = false;
    for line in lock.lines() {
        let line = line.trim();
        if let Some(source) = line
            .strip_prefix("provider \"")
            .and_then(|value| value.strip_suffix("\" {"))
        {
            if provider_source.is_some() {
                return None;
            }
            provider_source = Some(source.to_string());
            in_provider = true;
            continue;
        }
        if in_provider && line == "}" {
            in_provider = false;
            continue;
        }
        if in_provider && line.starts_with("version ") {
            let version = line
                .split_once('=')?
                .1
                .trim()
                .strip_prefix('"')?
                .strip_suffix('"')?;
            if provider_version.replace(version.to_string()).is_some() {
                return None;
            }
        }
    }
    provider_source.zip(provider_version)
}

/// Resolve the IaC bundle for the given offering ID.
///
/// Returns `Some(IacBundle)` when the offering has wired IaC, `None` otherwise.
/// Callers that receive `None` MUST keep the existing simulated plan behavior
/// unchanged — this function never returns an error.
pub fn resolve(offering_id: &str) -> Option<IacBundle> {
    lookup(offering_id)
        .filter(|o| !o.terraform.is_empty())
        .map(|o| o.terraform.to_vec())
}

/// Resolve the Ansible IaC bundle for the given offering ID.
///
/// Returns `Some(IacBundle)` with the playbook file(s) for offerings that have
/// wired Ansible IaC, `None` otherwise. The playbook filename is
/// `<offering_id>.yml`, matching what `AnsibleRunner` references on the command
/// line. Callers that receive `None` keep the existing simulated verify
/// behavior unchanged — this function never returns an error.
pub fn resolve_ansible(offering_id: &str) -> Option<IacBundle> {
    lookup(offering_id)
        .filter(|o| !o.ansible.is_empty())
        .map(|o| o.ansible.to_vec())
}

/// Canonical SHA-256 over a set of IaC files, independent of input order.
///
/// Files are sorted by name, then each contributes a length-prefixed name and
/// length-prefixed content to the hash, so neither a filename nor a content
/// boundary is ambiguous (e.g. `("ab", "c")` and `("a", "bc")` hash
/// differently). Returns lowercase hex. Deterministic and pure — the same files
/// always produce the same digest.
pub fn bundle_digest(files: &[(&str, &str)]) -> String {
    let mut sorted: Vec<(&str, &str)> = files.to_vec();
    // Sort by (name, content) for a TOTAL order — canonical even if a set ever
    // contains the same filename twice (the embedded bundles do not, but the
    // digest should not depend on input order in any case).
    sorted.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let mut hasher = Sha256::new();
    for (name, content) in &sorted {
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update((content.len() as u64).to_le_bytes());
        hasher.update(content.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Digest of an offering's COMPLETE embedded IaC — the union of its Terraform
/// and Ansible bundles.
///
/// This is runner-kind agnostic on purpose: the control plane computes it at
/// dispatch (the approved digest) and the agent recomputes it before running,
/// so the integrity check holds regardless of which runner the agent ultimately
/// invokes. Both sides derive it from the same embedded content in this crate,
/// so in one build they match by construction; a control plane and an agent
/// built from divergent IaC produce different digests. Returns `None` only when
/// the offering has no embedded IaC at all.
pub fn offering_iac_digest(offering_id: &str) -> Option<String> {
    let mut files: Vec<(&str, &str)> = Vec::new();
    if let Some(tf) = resolve(offering_id) {
        files.extend(tf);
    }
    if let Some(ansible) = resolve_ansible(offering_id) {
        files.extend(ansible);
    }
    if files.is_empty() {
        return None;
    }
    Some(bundle_digest(&files))
}

/// Logical deployment inputs used to generate an offering's variables. These
/// come from the request (the engine `Request` carries `id`/`site`/`environment`/
/// `metadata`; `name`/`cpu`/`memory_gb` come from the request row).
pub struct DeploymentInputs<'a> {
    pub offering_id: &'a str,
    pub request_id: &'a str,
    pub name: &'a str,
    pub site: &'a str,
    pub environment: &'a str,
    pub cpu: u32,
    pub memory_gb: u32,
    pub metadata: &'a HashMap<String, String>,
}

/// Required vSphere placement keys. Intake payload keys, request metadata keys,
/// rendered JobSpec vars, and Terraform variable names deliberately use these
/// exact names so the live path has no translation layer that can drift.
pub const SERVER_DEPLOYMENT_PLACEMENT_KEYS: &[&str] = &[
    "datacenter",
    "cluster",
    "datastore",
    "network",
    "template",
    "disk_size_gb",
];

/// A server-deployment JobSpec is not safe to submit to a live provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivePlacementError {
    /// One or more required placement variables are absent or blank.
    Missing(Vec<&'static str>),
    /// `disk_size_gb` is present but is not a positive integer.
    InvalidDiskSize,
}

impl fmt::Display for LivePlacementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(keys) => write!(
                f,
                "live server deployment is missing required placement variables: {}",
                keys.join(", ")
            ),
            Self::InvalidDiskSize => write!(
                f,
                "live server deployment has invalid placement variable: disk_size_gb must be a positive integer"
            ),
        }
    }
}

impl std::error::Error for LivePlacementError {}

/// Fail closed before a live server-deployment JobSpec is dispatched. Offline
/// validation intentionally does not call this gate: Terraform can validate a
/// module with required-but-unassigned variables without contacting vSphere.
pub fn validate_live_placement_vars(
    offering_id: &str,
    vars: &BTreeMap<String, String>,
) -> Result<(), LivePlacementError> {
    if !matches!(
        lookup(offering_id).map(|offering| offering.binding),
        Some(VarBinding::ServerDeployment)
    ) {
        return Ok(());
    }

    let missing: Vec<&'static str> = SERVER_DEPLOYMENT_PLACEMENT_KEYS
        .iter()
        .copied()
        .filter(|key| vars.get(*key).is_none_or(|value| value.trim().is_empty()))
        .collect();
    if !missing.is_empty() {
        return Err(LivePlacementError::Missing(missing));
    }

    let disk_size = vars
        .get("disk_size_gb")
        .and_then(|value| value.trim().parse::<u32>().ok());
    if disk_size.is_none_or(|size| size == 0) {
        return Err(LivePlacementError::InvalidDiskSize);
    }
    Ok(())
}

/// Render the Terraform variables (written as `ryuki.auto.tfvars.json`) for an
/// offering from a request's logical inputs. PURE.
///
/// For the server-deployment offerings this maps the request inputs onto the
/// Terraform variable names the embedded module declares (`vm_name`, `num_cpus`,
/// `memory_mb`, …) — this is the "generation" step that makes a selected
/// deployment's parameters actually reach the module. Values are plain JSON
/// strings, so they cannot break the surrounding HCL structure (no raw-HCL
/// templating). Offerings WITHOUT a declared binding fall back to the legacy
/// raw-metadata passthrough so their behavior is unchanged.
///
/// Secret-valued variables (e.g. `vsphere_password`) are NEVER produced here;
/// the runner injects those from `ResolvedCredentials` as `TF_VAR_*` at run time.
pub fn render_vars(inputs: &DeploymentInputs) -> BTreeMap<String, String> {
    let binding = lookup(inputs.offering_id)
        .map(|o| o.binding)
        .unwrap_or(VarBinding::MetadataPassthrough);
    match binding {
        VarBinding::ServerDeployment => {
            let mut vars = BTreeMap::new();
            vars.insert("vm_name".to_string(), inputs.name.to_string());
            vars.insert("num_cpus".to_string(), inputs.cpu.to_string());
            // GB → MB for the module's `memory_mb`. Widen first so the ×1024
            // cannot overflow.
            vars.insert(
                "memory_mb".to_string(),
                (inputs.memory_gb as u64 * 1024).to_string(),
            );
            vars.insert("site".to_string(), inputs.site.to_string());
            vars.insert("environment".to_string(), inputs.environment.to_string());
            vars.insert("request_id".to_string(), inputs.request_id.to_string());
            for key in SERVER_DEPLOYMENT_PLACEMENT_KEYS {
                if let Some(value) = inputs.metadata.get(*key) {
                    vars.insert((*key).to_string(), value.trim().to_string());
                }
            }
            vars
        }
        // No declared binding: preserve the legacy raw-metadata passthrough.
        VarBinding::MetadataPassthrough => inputs
            .metadata
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ryuki_engine::models::{Request, RequestStatus, RequestType};

    /// Helper: build a minimal server-deployment request with optional OS metadata.
    fn make_server_deployment_request(os: Option<&str>) -> Request {
        let mut req = Request::new(
            "test-sd-id".to_string(),
            "server-deployment".to_string(),
            RequestType::ServerDeployment,
            "tester".to_string(),
            "tester".to_string(),
            "DEFRA".to_string(),
            "production".to_string(),
            "standard".to_string(),
        );
        req.status = RequestStatus::Validated;
        if let Some(os_str) = os {
            req.metadata
                .insert("operating_system".to_string(), os_str.to_string());
        }
        req
    }

    // -------------------------------------------------------------------------
    // resolve_offering_id tests
    // -------------------------------------------------------------------------

    #[test]
    fn resolve_offering_id_windows_os_maps_to_windows_offering() {
        let req = make_server_deployment_request(Some("Windows Server 2022"));
        assert_eq!(
            resolve_offering_id(&req),
            "windows-server-deployment",
            "Windows Server 2022 must map to windows-server-deployment"
        );
    }

    #[test]
    fn resolve_offering_id_whitespace_os_stays_unmapped() {
        // A direct-API client could send whitespace; it must be treated as
        // absent (unmapped -> graceful simulated), not silently routed to linux.
        let req = make_server_deployment_request(Some("   "));
        assert_eq!(
            resolve_offering_id(&req),
            "server-deployment",
            "whitespace-only OS must be treated as absent, not routed to linux"
        );
    }

    #[test]
    fn resolve_offering_id_windows_case_insensitive() {
        for os in &["WINDOWS SERVER 2019", "windows 11", "Windows 10 Enterprise"] {
            let req = make_server_deployment_request(Some(os));
            assert_eq!(
                resolve_offering_id(&req),
                "windows-server-deployment",
                "{os} must map to windows-server-deployment (case-insensitive)"
            );
        }
    }

    #[test]
    fn resolve_offering_id_rhel_maps_to_linux_offering() {
        let req = make_server_deployment_request(Some("RHEL 9"));
        assert_eq!(
            resolve_offering_id(&req),
            "linux-server-deployment",
            "RHEL 9 must map to linux-server-deployment"
        );
    }

    #[test]
    fn resolve_offering_id_ubuntu_maps_to_linux_offering() {
        let req = make_server_deployment_request(Some("Ubuntu 22.04 LTS"));
        assert_eq!(
            resolve_offering_id(&req),
            "linux-server-deployment",
            "Ubuntu 22.04 LTS must map to linux-server-deployment"
        );
    }

    #[test]
    fn resolve_offering_id_absent_os_stays_unmapped() {
        let req = make_server_deployment_request(None);
        assert_eq!(
            resolve_offering_id(&req),
            "server-deployment",
            "absent OS must stay unmapped (server-deployment) — do not guess"
        );
    }

    #[test]
    fn resolve_offering_id_empty_os_stays_unmapped() {
        let req = make_server_deployment_request(Some(""));
        assert_eq!(
            resolve_offering_id(&req),
            "server-deployment",
            "empty OS must stay unmapped (server-deployment)"
        );
    }

    #[test]
    fn resolve_offering_id_controlled_restore_maps_to_catalog_name() {
        let mut req = Request::new(
            "test-cr-id".to_string(),
            "controlled-restore".to_string(),
            RequestType::ControlledRestore,
            "tester".to_string(),
            "tester".to_string(),
            "DEFRA".to_string(),
            "production".to_string(),
            "standard".to_string(),
        );
        req.status = RequestStatus::Validated;
        assert_eq!(
            resolve_offering_id(&req),
            "controlled-restore-request",
            "controlled-restore request_type must map to controlled-restore-request offering"
        );
    }

    #[test]
    fn resolve_offering_id_patch_maintenance_unchanged() {
        let mut req = Request::new(
            "test-pm-id".to_string(),
            "patch-maintenance".to_string(),
            RequestType::PatchMaintenance,
            "tester".to_string(),
            "tester".to_string(),
            "DEFRA".to_string(),
            "production".to_string(),
            "standard".to_string(),
        );
        req.status = RequestStatus::Validated;
        assert_eq!(
            resolve_offering_id(&req),
            "patch-maintenance",
            "patch-maintenance must pass through unchanged (1:1)"
        );
    }

    #[test]
    fn resolve_offering_id_managed_onboarding_flag_maps_to_composite() {
        let mut req = make_server_deployment_request(Some("Ubuntu 22.04 LTS"));
        req.metadata.insert(
            "deployment_profile".to_string(),
            "managed-onboarding".to_string(),
        );
        assert_eq!(
            resolve_offering_id(&req),
            "managed-server-onboarding",
            "deployment_profile=managed-onboarding must map to the composite offering, \
             overriding the OS-based discrimination"
        );
    }

    #[test]
    fn resolve_offering_id_normal_server_deployment_unchanged_by_managed_onboarding_check() {
        // No deployment_profile flag at all — today's exact linux/windows/unmapped
        // behavior must be preserved.
        let req = make_server_deployment_request(Some("Ubuntu 22.04 LTS"));
        assert_eq!(
            resolve_offering_id(&req),
            "linux-server-deployment",
            "a normal server-deployment (no deployment_profile) must be unaffected"
        );
        let req_windows = make_server_deployment_request(Some("Windows Server 2022"));
        assert_eq!(
            resolve_offering_id(&req_windows),
            "windows-server-deployment"
        );
        let req_unmapped = make_server_deployment_request(None);
        assert_eq!(resolve_offering_id(&req_unmapped), "server-deployment");
    }

    // -------------------------------------------------------------------------
    // offering_step_template tests
    // -------------------------------------------------------------------------

    #[test]
    fn offering_step_template_empty_for_normal_offerings() {
        for id in [
            "patch-maintenance",
            "request-preflight",
            "zabbix-onboarding",
            "linux-server-deployment",
            "windows-server-deployment",
            "controlled-restore-request",
            "server-deployment",
            "unknown-offering",
        ] {
            assert!(
                offering_step_template(id).is_empty(),
                "offering {id} must keep the single-job path (empty template)"
            );
        }
    }

    #[test]
    fn offering_step_template_managed_onboarding_has_three_steps() {
        let template = offering_step_template("managed-server-onboarding");
        assert_eq!(
            template.len(),
            3,
            "managed-server-onboarding must have exactly 3 steps"
        );
        let keys: Vec<&str> = template.iter().map(|s| s.key).collect();
        assert_eq!(keys, vec!["preflight", "deploy", "monitor"]);
    }

    #[test]
    fn offering_step_template_managed_onboarding_is_a_valid_dag() {
        let template = offering_step_template("managed-server-onboarding");
        let steps: Vec<ryuki_engine::job_orchestration::Step> = template
            .iter()
            .map(|t| ryuki_engine::job_orchestration::Step {
                key: t.key.to_string(),
                depends_on: t.depends_on.iter().map(|d| d.to_string()).collect(),
                status: ryuki_engine::job_orchestration::StepStatus::Pending,
            })
            .collect();
        assert_eq!(
            ryuki_engine::job_orchestration::validate_plan(&steps),
            Ok(()),
            "the managed-server-onboarding template must be a well-formed DAG"
        );
    }

    #[test]
    fn offering_step_template_managed_onboarding_steps_resolve_to_real_offerings() {
        let template = offering_step_template("managed-server-onboarding");
        for step in template {
            assert!(
                lookup(step.iac_ref).is_some(),
                "step {} references iac_ref {} which is not in the OFFERINGS registry",
                step.key,
                step.iac_ref
            );
            assert!(
                offering_iac_digest(step.iac_ref).is_some(),
                "step {} iac_ref {} must have embedded IaC (a non-None digest)",
                step.key,
                step.iac_ref
            );
        }
    }

    #[test]
    fn managed_server_onboarding_is_not_in_the_offerings_registry() {
        // The composite offering dispatches per-step IaC, never its own — it is
        // deliberately absent from OFFERINGS, and offering_iac_digest for it
        // returns None (never hit on the multi-step path).
        assert!(
            lookup("managed-server-onboarding").is_none(),
            "the composite offering must NOT be a registry entry"
        );
        assert!(offering_iac_digest("managed-server-onboarding").is_none());
    }

    // -------------------------------------------------------------------------
    // resolve() new offering arms
    // -------------------------------------------------------------------------

    #[test]
    fn resolve_wires_request_preflight_terraform() {
        assert!(
            resolve("request-preflight").is_some(),
            "request-preflight must resolve to terraform IaC (DeepSeek-authored)"
        );
    }

    #[test]
    fn resolve_wires_linux_server_deployment_terraform() {
        let bundle = resolve("linux-server-deployment");
        assert!(
            bundle.is_some(),
            "linux-server-deployment must resolve to terraform IaC"
        );
        let files = bundle.unwrap();
        let has_main = files.iter().any(|(name, _)| *name == "main.tf");
        assert!(
            has_main,
            "linux-server-deployment bundle must include main.tf"
        );
        let (_, content) = files.iter().find(|(name, _)| *name == "main.tf").unwrap();
        // Now uses real vSphere IaC — no longer terraform_data.
        assert!(
            content.contains("vsphere_virtual_machine"),
            "linux-server-deployment main.tf must declare vsphere_virtual_machine resource; \
             got: {content:.200}"
        );
        assert!(
            content.contains("vmware/vsphere"),
            "linux-server-deployment main.tf must use vmware/vsphere provider source"
        );
        assert!(
            content.contains("version = \"2.16.1\""),
            "linux-server-deployment must pin the reviewed vSphere provider version"
        );
        let (_, lock) = files
            .iter()
            .find(|(name, _)| *name == ".terraform.lock.hcl")
            .expect("linux-server-deployment must embed its Terraform dependency lock");
        assert!(lock.contains("version     = \"2.16.1\""));
        assert!(lock.contains("constraints = \"2.16.1\""));
        assert!(lock.contains("h1:"), "lock must include platform hashes");
        assert!(lock.contains("zh:"), "lock must include release hashes");
        // Credentials are injected at apply time (TF_VAR_vsphere_password / the
        // VSPHERE_PASSWORD env var) — never embedded, never obfuscated to dodge
        // the secret scan. Guard against regression of all three.
        assert!(
            !content.contains("changeme"),
            "linux-server-deployment main.tf must not embed a default credential"
        );
        assert!(
            !content.contains("format(\"%s\""),
            "linux-server-deployment main.tf must not obfuscate a credential to evade the secret scan"
        );
        assert!(
            content.contains("sensitive"),
            "linux-server-deployment main.tf must mark the credential variable sensitive"
        );
        assert!(
            content.contains("VSPHERE_PASSWORD"),
            "linux-server-deployment main.tf must document credential injection"
        );
    }

    #[test]
    fn resolve_wires_windows_server_deployment_terraform() {
        let bundle = resolve("windows-server-deployment");
        assert!(
            bundle.is_some(),
            "windows-server-deployment must resolve to terraform IaC"
        );
        let files = bundle.unwrap();
        let has_main = files.iter().any(|(name, _)| *name == "main.tf");
        assert!(
            has_main,
            "windows-server-deployment bundle must include main.tf"
        );
        let (_, content) = files.iter().find(|(name, _)| *name == "main.tf").unwrap();
        // Now uses real vSphere IaC — no longer terraform_data.
        assert!(
            content.contains("vsphere_virtual_machine"),
            "windows-server-deployment main.tf must declare vsphere_virtual_machine resource; \
             got: {content:.200}"
        );
        assert!(
            content.contains("vmware/vsphere"),
            "windows-server-deployment main.tf must use vmware/vsphere provider source"
        );
        assert!(
            content.contains("version = \"2.16.1\""),
            "windows-server-deployment must pin the reviewed vSphere provider version"
        );
        let (_, lock) = files
            .iter()
            .find(|(name, _)| *name == ".terraform.lock.hcl")
            .expect("windows-server-deployment must embed its Terraform dependency lock");
        assert!(lock.contains("version     = \"2.16.1\""));
        assert!(lock.contains("constraints = \"2.16.1\""));
        assert!(lock.contains("h1:"), "lock must include platform hashes");
        assert!(lock.contains("zh:"), "lock must include release hashes");
        // Credentials are injected at apply time (TF_VAR_vsphere_password / the
        // VSPHERE_PASSWORD env var) — never embedded, never obfuscated to dodge
        // the secret scan. Guard against regression of all three.
        assert!(
            !content.contains("changeme"),
            "windows-server-deployment main.tf must not embed a default credential"
        );
        assert!(
            !content.contains("format(\"%s\""),
            "windows-server-deployment main.tf must not obfuscate a credential to evade the secret scan"
        );
        assert!(
            content.contains("sensitive"),
            "windows-server-deployment main.tf must mark the credential variable sensitive"
        );
        assert!(
            content.contains("VSPHERE_PASSWORD"),
            "windows-server-deployment main.tf must document credential injection"
        );
    }

    // -------------------------------------------------------------------------
    // resolve_ansible() new offering arms
    // -------------------------------------------------------------------------

    #[test]
    fn resolve_ansible_wires_zabbix_onboarding() {
        assert!(
            resolve_ansible("zabbix-onboarding").is_some(),
            "zabbix-onboarding must resolve to ansible IaC (DeepSeek-authored)"
        );
    }

    #[test]
    fn resolve_ansible_wires_linux_server_deployment() {
        let bundle = resolve_ansible("linux-server-deployment");
        assert!(
            bundle.is_some(),
            "linux-server-deployment must resolve to ansible IaC"
        );
        let files = bundle.unwrap();
        let has_playbook = files
            .iter()
            .any(|(name, _)| *name == "linux-server-deployment.yml");
        assert!(
            has_playbook,
            "linux-server-deployment ansible bundle must include linux-server-deployment.yml"
        );
    }

    #[test]
    fn resolve_ansible_wires_controlled_restore_request() {
        let bundle = resolve_ansible("controlled-restore-request");
        assert!(
            bundle.is_some(),
            "controlled-restore-request must resolve to ansible IaC"
        );
        let files = bundle.unwrap();
        let has_playbook = files
            .iter()
            .any(|(name, _)| *name == "controlled-restore-request.yml");
        assert!(
            has_playbook,
            "controlled-restore-request ansible bundle must include controlled-restore-request.yml"
        );
    }

    #[test]
    fn resolver_returns_some_for_patch_maintenance() {
        let bundle = resolve("patch-maintenance");
        assert!(
            bundle.is_some(),
            "patch-maintenance must resolve to an IaC bundle"
        );
        let files = bundle.unwrap();
        assert!(!files.is_empty(), "bundle must have at least one file");
        // The bundle must contain main.tf.
        let has_main = files.iter().any(|(name, _)| *name == "main.tf");
        assert!(has_main, "bundle must include main.tf");
    }

    #[test]
    fn resolver_content_contains_terraform_data() {
        let bundle = resolve("patch-maintenance").expect("must resolve");
        let (_, content) = bundle
            .iter()
            .find(|(name, _)| *name == "main.tf")
            .expect("main.tf must be in bundle");
        assert!(
            content.contains("terraform_data"),
            "main.tf must use terraform_data resource; got: {content}"
        );
    }

    #[test]
    fn resolver_returns_none_for_unknown_offering() {
        assert!(
            resolve("server-deployment").is_none(),
            "server-deployment must return None (not yet wired)"
        );
        assert!(
            resolve("zabbix-onboarding").is_none(),
            "zabbix-onboarding must return None"
        );
        assert!(resolve("").is_none(), "empty string must return None");
        assert!(
            resolve("nonexistent-offering").is_none(),
            "unknown offering must return None"
        );
    }

    // --- resolve_ansible ---

    #[test]
    fn ansible_resolver_returns_some_for_patch_maintenance() {
        let bundle = resolve_ansible("patch-maintenance");
        assert!(
            bundle.is_some(),
            "patch-maintenance must resolve to an Ansible IaC bundle"
        );
        let files = bundle.unwrap();
        assert!(
            !files.is_empty(),
            "ansible bundle must have at least one file"
        );
        let has_playbook = files
            .iter()
            .any(|(name, _)| *name == "patch-maintenance.yml");
        assert!(
            has_playbook,
            "ansible bundle must include patch-maintenance.yml"
        );
    }

    #[test]
    fn ansible_resolver_content_contains_playbook_markers() {
        let bundle = resolve_ansible("patch-maintenance").expect("must resolve");
        let (_, content) = bundle
            .iter()
            .find(|(name, _)| *name == "patch-maintenance.yml")
            .expect("patch-maintenance.yml must be in bundle");
        assert!(
            content.contains("hosts: localhost"),
            "playbook must target localhost; got: {content}"
        );
        assert!(
            content.contains("gather_facts: false"),
            "playbook must disable gather_facts; got: {content}"
        );
        assert!(
            content.contains("ansible.builtin.assert"),
            "playbook must use ansible.builtin.assert; got: {content}"
        );
    }

    #[test]
    fn ansible_resolver_returns_none_for_unknown_offering() {
        assert!(
            resolve_ansible("server-deployment").is_none(),
            "server-deployment must return None"
        );
        assert!(
            resolve_ansible("").is_none(),
            "empty string must return None"
        );
        assert!(
            resolve_ansible("nonexistent-offering").is_none(),
            "unknown offering must return None"
        );
    }

    // -------------------------------------------------------------------------
    // bundle_digest / offering_iac_digest
    // -------------------------------------------------------------------------

    #[test]
    fn bundle_digest_is_deterministic_and_order_independent() {
        let a = bundle_digest(&[("main.tf", "resource x"), ("vars.tf", "var y")]);
        let b = bundle_digest(&[("vars.tf", "var y"), ("main.tf", "resource x")]);
        assert_eq!(a, b, "digest must not depend on file order");
        assert_eq!(a.len(), 64, "sha-256 hex is 64 chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn bundle_digest_distinguishes_name_content_boundaries() {
        // Length-prefixing means ("ab","c") and ("a","bc") must differ.
        let a = bundle_digest(&[("ab", "c")]);
        let b = bundle_digest(&[("a", "bc")]);
        assert_ne!(a, b, "the name/content boundary must be unambiguous");
    }

    #[test]
    fn bundle_digest_canonical_with_duplicate_filenames() {
        // The (name, content) sort gives a total order, so a set containing the
        // same filename twice hashes the same regardless of input order.
        let a = bundle_digest(&[("dup.tf", "x"), ("dup.tf", "y")]);
        let b = bundle_digest(&[("dup.tf", "y"), ("dup.tf", "x")]);
        assert_eq!(a, b, "duplicate-name digest must not depend on input order");
    }

    #[test]
    fn bundle_digest_changes_with_content() {
        let a = bundle_digest(&[("main.tf", "resource x")]);
        let b = bundle_digest(&[("main.tf", "resource z")]);
        assert_ne!(a, b, "different content must change the digest");
    }

    #[test]
    fn offering_iac_digest_present_for_wired_offering_and_stable() {
        let d1 = offering_iac_digest("linux-server-deployment").expect("wired offering");
        let d2 = offering_iac_digest("linux-server-deployment").expect("stable");
        assert_eq!(d1, d2, "digest must be stable across calls");
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn offering_iac_digest_differs_between_offerings() {
        let linux = offering_iac_digest("linux-server-deployment").unwrap();
        let patch = offering_iac_digest("patch-maintenance").unwrap();
        assert_ne!(
            linux, patch,
            "distinct offerings must have distinct digests"
        );
    }

    #[test]
    fn offering_iac_digest_none_for_unknown_offering() {
        assert!(offering_iac_digest("nonexistent-offering").is_none());
        assert!(
            offering_iac_digest("server-deployment").is_none(),
            "unmapped slug has no embedded IaC"
        );
        assert!(offering_iac_digest("").is_none());
    }

    #[test]
    fn offering_iac_digest_covers_both_runners() {
        // linux-server-deployment has BOTH a terraform main.tf and an ansible
        // playbook — the union digest must differ from a terraform-only digest.
        let combined = offering_iac_digest("linux-server-deployment").unwrap();
        let tf_only = bundle_digest(&resolve("linux-server-deployment").unwrap());
        assert_ne!(
            combined, tf_only,
            "combined digest must include the ansible bundle too"
        );
    }

    // -------------------------------------------------------------------------
    // render_vars
    // -------------------------------------------------------------------------

    #[test]
    fn render_vars_binds_server_deployment_inputs() {
        let metadata = HashMap::from([
            ("datacenter".to_string(), "DC-PROD".to_string()),
            ("cluster".to_string(), "Compute-01".to_string()),
            ("datastore".to_string(), "Datastore-01".to_string()),
            ("network".to_string(), "VLAN-210".to_string()),
            ("template".to_string(), "rhel-9-approved".to_string()),
            ("disk_size_gb".to_string(), " 80 ".to_string()),
            ("unmapped".to_string(), "ignored".to_string()),
        ]);
        let vars = render_vars(&DeploymentInputs {
            offering_id: "linux-server-deployment",
            request_id: "req-1",
            name: "app-vm-01",
            site: "DEFRA",
            environment: "production",
            cpu: 4,
            memory_gb: 16,
            metadata: &metadata,
        });
        assert_eq!(vars.get("vm_name").map(String::as_str), Some("app-vm-01"));
        assert_eq!(vars.get("num_cpus").map(String::as_str), Some("4"));
        assert_eq!(vars.get("memory_mb").map(String::as_str), Some("16384")); // 16 × 1024
        assert_eq!(vars.get("site").map(String::as_str), Some("DEFRA"));
        assert_eq!(
            vars.get("environment").map(String::as_str),
            Some("production")
        );
        assert_eq!(vars.get("request_id").map(String::as_str), Some("req-1"));
        for (key, expected) in [
            ("datacenter", "DC-PROD"),
            ("cluster", "Compute-01"),
            ("datastore", "Datastore-01"),
            ("network", "VLAN-210"),
            ("template", "rhel-9-approved"),
            ("disk_size_gb", "80"),
        ] {
            assert_eq!(vars.get(key).map(String::as_str), Some(expected));
        }
        assert_eq!(
            validate_live_placement_vars("linux-server-deployment", &vars),
            Ok(())
        );
        assert!(
            !vars.contains_key("unmapped"),
            "non-allow-listed metadata must not pass through for a bound offering"
        );
    }

    #[test]
    fn live_server_deployment_rejects_missing_placement() {
        let vars = BTreeMap::from([("datacenter".to_string(), "DC-PROD".to_string())]);
        let error = validate_live_placement_vars("linux-server-deployment", &vars)
            .expect_err("partial placement must fail closed");

        assert_eq!(
            error,
            LivePlacementError::Missing(vec![
                "cluster",
                "datastore",
                "network",
                "template",
                "disk_size_gb",
            ])
        );
        assert!(error
            .to_string()
            .contains("missing required placement variables"));
    }

    #[test]
    fn live_server_deployment_rejects_invalid_disk_size() {
        let vars = BTreeMap::from([
            ("datacenter".to_string(), "DC-PROD".to_string()),
            ("cluster".to_string(), "Compute-01".to_string()),
            ("datastore".to_string(), "Datastore-01".to_string()),
            ("network".to_string(), "VLAN-210".to_string()),
            ("template".to_string(), "rhel-9-approved".to_string()),
            ("disk_size_gb".to_string(), "zero".to_string()),
        ]);

        assert_eq!(
            validate_live_placement_vars("windows-server-deployment", &vars),
            Err(LivePlacementError::InvalidDiskSize)
        );
    }

    #[test]
    fn live_placement_gate_ignores_non_server_offerings() {
        assert_eq!(
            validate_live_placement_vars("patch-maintenance", &BTreeMap::new()),
            Ok(())
        );
    }

    #[test]
    fn render_vars_falls_back_to_metadata_passthrough() {
        let metadata = HashMap::from([
            ("foo".to_string(), "bar".to_string()),
            ("baz".to_string(), "qux".to_string()),
        ]);
        let vars = render_vars(&DeploymentInputs {
            offering_id: "patch-maintenance",
            request_id: "req-2",
            name: "n",
            site: "S",
            environment: "E",
            cpu: 1,
            memory_gb: 1,
            metadata: &metadata,
        });
        assert_eq!(vars.get("foo").map(String::as_str), Some("bar"));
        assert_eq!(vars.get("baz").map(String::as_str), Some("qux"));
        assert!(
            !vars.contains_key("vm_name"),
            "an unbound offering must not get server-deployment vars"
        );
        assert_eq!(vars.len(), 2, "fallback is the raw metadata, nothing added");
    }

    #[test]
    fn render_vars_memory_conversion_does_not_overflow() {
        let metadata = HashMap::new();
        let vars = render_vars(&DeploymentInputs {
            offering_id: "windows-server-deployment",
            request_id: "r",
            name: "n",
            site: "S",
            environment: "E",
            cpu: 8,
            memory_gb: u32::MAX,
            metadata: &metadata,
        });
        // u32::MAX × 1024 must compute in u64 without panicking or wrapping.
        assert_eq!(
            vars.get("memory_mb").map(String::as_str),
            Some((u32::MAX as u64 * 1024).to_string().as_str())
        );
    }

    // -------------------------------------------------------------------------
    // OFFERINGS registry consistency
    // -------------------------------------------------------------------------

    #[test]
    fn registry_entries_are_internally_consistent() {
        let mut ids = std::collections::HashSet::new();
        for o in OFFERINGS {
            assert!(
                ids.insert(o.id),
                "duplicate offering id in registry: {}",
                o.id
            );
            assert!(
                !o.terraform.is_empty() || !o.ansible.is_empty(),
                "offering {} has no Terraform AND no Ansible — it would not be deployable",
                o.id
            );
            // A ServerDeployment binding produces Terraform vars (num_cpus, …), so
            // the offering must actually have a Terraform module.
            if matches!(o.binding, VarBinding::ServerDeployment) {
                assert!(
                    !o.terraform.is_empty(),
                    "offering {} binds ServerDeployment vars but has no Terraform",
                    o.id
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // live_secret_var_names — provider-credential declarations
    // -------------------------------------------------------------------------

    #[test]
    fn live_secret_var_names_declares_vsphere_creds_for_server_deployments() {
        for id in ["linux-server-deployment", "windows-server-deployment"] {
            assert_eq!(
                live_secret_var_names(id),
                &["VSPHERE_USER", "VSPHERE_PASSWORD", "VSPHERE_SERVER"],
                "{id} must declare exactly the vsphere provider env vars, in pairing order"
            );
        }
    }

    #[test]
    fn live_secret_var_names_empty_for_non_provider_offerings_and_unknown() {
        for id in [
            "patch-maintenance",
            "request-preflight",
            "zabbix-onboarding",
            "controlled-restore-request",
            "server-deployment",
            "managed-server-onboarding",
            "nonexistent-offering",
            "",
        ] {
            assert!(
                live_secret_var_names(id).is_empty(),
                "{id} must declare no live secret vars"
            );
        }
    }

    /// Every declared secret var name must pass the runner's injection
    /// validation — a name the runner would refuse could never be wired, so a
    /// bad declaration must fail HERE at authoring time, not at live-run time.
    #[test]
    fn declared_live_secret_names_are_valid_and_unique_per_offering() {
        for o in OFFERINGS {
            let mut seen = std::collections::HashSet::new();
            for name in o.live_secret_env {
                assert!(
                    crate::terraform::validate_var_name(name).is_ok(),
                    "offering {} declares secret var {name:?} that the runner would refuse",
                    o.id
                );
                assert!(
                    seen.insert(*name),
                    "offering {} declares duplicate secret var {name:?}",
                    o.id
                );
            }
        }
    }

    /// The declaration only makes sense for offerings whose LIVE path is
    /// Terraform: declared names feed the terraform child env. Guard that no
    /// ansible-only offering grows a declaration without the wiring to use it.
    #[test]
    fn declared_live_secret_names_require_a_terraform_bundle() {
        for o in OFFERINGS {
            if !o.live_secret_env.is_empty() {
                assert!(
                    !o.terraform.is_empty(),
                    "offering {} declares live secret vars but has no Terraform bundle",
                    o.id
                );
            }
        }
    }

    /// Conformance (#11): EVERY curated bundled offering must PASS the IaC policy
    /// gate — the gate wired into the live runner would otherwise refuse to
    /// deploy a sanctioned offering. This doubles as a guard against a future
    /// template accidentally introducing a provisioner / unsafe Ansible task AND
    /// against the gate over-matching a legitimate bundle.
    #[test]
    fn every_bundled_offering_passes_the_iac_policy_gate() {
        for o in OFFERINGS {
            let tf = ryuki_engine::iac_policy::evaluate_iac_bundle(o.terraform.iter().copied());
            assert!(
                tf.is_empty(),
                "offering {} Terraform bundle tripped the policy gate: {:?}",
                o.id,
                tf
            );
            let ans = ryuki_engine::iac_policy::evaluate_iac_bundle(o.ansible.iter().copied());
            assert!(
                ans.is_empty(),
                "offering {} Ansible bundle tripped the policy gate: {:?}",
                o.id,
                ans
            );
        }
    }

    #[test]
    fn registry_preserves_legacy_wiring() {
        // The exact offering→runner wiring the resolver must keep.
        for id in [
            "patch-maintenance",
            "request-preflight",
            "linux-server-deployment",
            "windows-server-deployment",
        ] {
            assert!(resolve(id).is_some(), "{id} must resolve to Terraform IaC");
        }
        for id in ["zabbix-onboarding", "controlled-restore-request"] {
            assert!(
                resolve(id).is_none(),
                "{id} must NOT resolve to Terraform IaC"
            );
        }
        for id in [
            "patch-maintenance",
            "zabbix-onboarding",
            "linux-server-deployment",
            "controlled-restore-request",
        ] {
            assert!(
                resolve_ansible(id).is_some(),
                "{id} must resolve to Ansible IaC"
            );
        }
        for id in ["request-preflight", "windows-server-deployment"] {
            assert!(
                resolve_ansible(id).is_none(),
                "{id} must NOT resolve to Ansible IaC"
            );
        }
    }
}
