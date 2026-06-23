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
}
