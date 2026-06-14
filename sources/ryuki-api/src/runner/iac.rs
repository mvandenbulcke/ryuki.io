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
//! # Offline guarantee
//! Every embedded `.tf` file uses ONLY built-in Terraform resources
//! (`terraform_data`, variables, outputs) — no providers, no
//! `required_providers`, no cloud calls. `terraform init` + `terraform plan`
//! run fully offline.

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

/// Embedded Ansible playbook for the `linux-server-deployment` offering.
const LINUX_SERVER_DEPLOYMENT_PLAYBOOK: &str =
    include_str!("iac/linux-server-deployment/linux-server-deployment.yml");

/// Embedded Terraform IaC for the `windows-server-deployment` offering.
const WINDOWS_SERVER_DEPLOYMENT_MAIN_TF: &str =
    include_str!("iac/windows-server-deployment/main.tf");

/// Embedded Ansible playbook for the `controlled-restore-request` offering.
const CONTROLLED_RESTORE_REQUEST_PLAYBOOK: &str =
    include_str!("iac/controlled-restore-request/controlled-restore-request.yml");

/// Resolve the effective offering ID for a request, applying OS-based
/// discrimination for `server-deployment` and name normalization for
/// `controlled-restore`.
///
/// This is the single place where `request_type` (plus optional
/// `metadata["operating_system"]`) maps to a catalog offering_id:
///
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

/// Resolve the IaC bundle for the given offering ID.
///
/// Returns `Some(IacBundle)` when the offering has wired IaC, `None` otherwise.
/// Callers that receive `None` MUST keep the existing simulated plan behavior
/// unchanged — this function never returns an error.
pub fn resolve(offering_id: &str) -> Option<IacBundle> {
    match offering_id {
        "patch-maintenance" => Some(vec![("main.tf", PATCH_MAINTENANCE_MAIN_TF)]),
        "request-preflight" => Some(vec![("main.tf", REQUEST_PREFLIGHT_MAIN_TF)]),
        "linux-server-deployment" => Some(vec![("main.tf", LINUX_SERVER_DEPLOYMENT_MAIN_TF)]),
        "windows-server-deployment" => Some(vec![("main.tf", WINDOWS_SERVER_DEPLOYMENT_MAIN_TF)]),
        _ => None,
    }
}

/// Resolve the Ansible IaC bundle for the given offering ID.
///
/// Returns `Some(IacBundle)` with the playbook file(s) for offerings that have
/// wired Ansible IaC, `None` otherwise. The playbook filename is
/// `<offering_id>.yml`, matching what `AnsibleRunner` references on the command
/// line. Callers that receive `None` keep the existing simulated verify
/// behavior unchanged — this function never returns an error.
pub fn resolve_ansible(offering_id: &str) -> Option<IacBundle> {
    match offering_id {
        "patch-maintenance" => Some(vec![("patch-maintenance.yml", PATCH_MAINTENANCE_PLAYBOOK)]),
        "zabbix-onboarding" => Some(vec![("zabbix-onboarding.yml", ZABBIX_ONBOARDING_PLAYBOOK)]),
        "linux-server-deployment" => Some(vec![(
            "linux-server-deployment.yml",
            LINUX_SERVER_DEPLOYMENT_PLAYBOOK,
        )]),
        "controlled-restore-request" => Some(vec![(
            "controlled-restore-request.yml",
            CONTROLLED_RESTORE_REQUEST_PLAYBOOK,
        )]),
        _ => None,
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
        assert!(
            content.contains("terraform_data"),
            "linux-server-deployment main.tf must use terraform_data"
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
        assert!(
            content.contains("terraform_data"),
            "windows-server-deployment main.tf must use terraform_data"
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
}
