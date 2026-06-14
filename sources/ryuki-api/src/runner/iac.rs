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

/// Resolve the IaC bundle for the given offering ID.
///
/// Returns `Some(IacBundle)` when the offering has wired IaC, `None` otherwise.
/// Callers that receive `None` MUST keep the existing simulated plan behavior
/// unchanged — this function never returns an error.
pub fn resolve(offering_id: &str) -> Option<IacBundle> {
    match offering_id {
        "patch-maintenance" => Some(vec![("main.tf", PATCH_MAINTENANCE_MAIN_TF)]),
        "request-preflight" => Some(vec![("main.tf", REQUEST_PREFLIGHT_MAIN_TF)]),
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
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_wires_request_preflight_terraform() {
        assert!(
            resolve("request-preflight").is_some(),
            "request-preflight must resolve to terraform IaC (DeepSeek-authored)"
        );
    }

    #[test]
    fn resolve_ansible_wires_zabbix_onboarding() {
        assert!(
            resolve_ansible("zabbix-onboarding").is_some(),
            "zabbix-onboarding must resolve to ansible IaC (DeepSeek-authored)"
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
