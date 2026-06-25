//! Per-vendor integration capability catalog (#51).
//!
//! Reports which integration vendor types the platform supports, grouped by
//! category, plus the framework operations every adapter implements. The vendor
//! list is the real [`AdapterType`] enum (the source of truth for supported
//! providers) and the categories are factual product classifications — NOT
//! invented capability data. Every adapter implements the same `ProviderAdapter`
//! contract, so the operations are uniform and run in DRY-RUN in this build.
//! Pure: no IO.

use crate::models::AdapterType;
use serde::Serialize;
use strum::IntoEnumIterator;

/// Product category of an integration vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorCategory {
    /// Hypervisor / virtualization platforms.
    Virtualization,
    /// Backup & recovery products.
    Backup,
    /// Monitoring / observability products.
    Monitoring,
    /// IT service management.
    Itsm,
}

impl VendorCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            VendorCategory::Virtualization => "virtualization",
            VendorCategory::Backup => "backup",
            VendorCategory::Monitoring => "monitoring",
            VendorCategory::Itsm => "itsm",
        }
    }
}

/// The framework operations EVERY adapter implements (the `ProviderAdapter`
/// trait). Uniform across vendors; DRY-RUN in this build.
pub const OPERATIONS: &[&str] = &[
    "connect",
    "health_check",
    "sync_inventory",
    "execute",
    "disconnect",
];

/// One vendor's catalog entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VendorCapability {
    /// Canonical vendor key (the [`AdapterType`] `Display` string, e.g. `veeam`).
    pub vendor_type: String,
    /// Human-readable product name.
    pub label: &'static str,
    pub category: VendorCategory,
}

/// Factual product category per vendor. Exhaustive — a new [`AdapterType`]
/// variant will not compile until categorised here.
fn category_of(t: &AdapterType) -> VendorCategory {
    match t {
        AdapterType::VMware
        | AdapterType::HyperV
        | AdapterType::Proxmox
        | AdapterType::NutanixAhv
        | AdapterType::Xen
        | AdapterType::Kvm => VendorCategory::Virtualization,
        AdapterType::Veeam
        | AdapterType::Commvault
        | AdapterType::Rubrik
        | AdapterType::Cohesity
        | AdapterType::NetBackup => VendorCategory::Backup,
        // VeeamOne (Veeam ONE) is a MONITORING & analytics product — categorised
        // by product function, per the missing-features.md roadmap recommendation
        // ("complete it as a monitoring-category adapter"). This is a different
        // axis from runners.rs, which groups it with the data-protection
        // ecosystem for automation-runner selection.
        AdapterType::VeeamOne
        | AdapterType::Zabbix
        | AdapterType::Prometheus
        | AdapterType::Datadog
        | AdapterType::Grafana
        | AdapterType::SolarWinds => VendorCategory::Monitoring,
        AdapterType::ServiceNow => VendorCategory::Itsm,
    }
}

/// Human label per vendor. Exhaustive (same compile guarantee as `category_of`).
fn label_of(t: &AdapterType) -> &'static str {
    match t {
        AdapterType::VMware => "VMware vSphere",
        AdapterType::HyperV => "Microsoft Hyper-V",
        AdapterType::Proxmox => "Proxmox VE",
        AdapterType::NutanixAhv => "Nutanix AHV",
        AdapterType::Xen => "Citrix XenServer",
        AdapterType::Kvm => "KVM / libvirt",
        AdapterType::Veeam => "Veeam Backup & Replication",
        AdapterType::VeeamOne => "Veeam ONE",
        AdapterType::Commvault => "Commvault",
        AdapterType::Rubrik => "Rubrik",
        AdapterType::Cohesity => "Cohesity",
        AdapterType::NetBackup => "Veritas NetBackup",
        AdapterType::Zabbix => "Zabbix",
        AdapterType::Prometheus => "Prometheus",
        AdapterType::Datadog => "Datadog",
        AdapterType::Grafana => "Grafana",
        AdapterType::SolarWinds => "SolarWinds",
        AdapterType::ServiceNow => "ServiceNow",
    }
}

fn entry(t: &AdapterType) -> VendorCapability {
    VendorCapability {
        vendor_type: t.to_string(),
        label: label_of(t),
        category: category_of(t),
    }
}

/// The full vendor capability catalog, in `AdapterType` declaration order.
/// Built by iterating EVERY enum variant (`strum::EnumIter`), so a new vendor
/// is automatically included — it cannot be silently omitted.
pub fn catalog() -> Vec<VendorCapability> {
    AdapterType::iter().map(|t| entry(&t)).collect()
}

/// Look up one vendor's capability by its canonical key (case-insensitive).
pub fn capability_for(vendor_type: &str) -> Option<VendorCapability> {
    let key = vendor_type.trim();
    AdapterType::iter()
        .find(|t| t.to_string().eq_ignore_ascii_case(key))
        .map(|t| entry(&t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_matches_independent_expectation() {
        // The catalog is now built from AdapterType::iter() (strum), so EVERY
        // variant is automatically present — completeness is structural, not
        // test-enforced. This INDEPENDENT hand-maintained expectation additionally
        // pins each vendor's CATEGORY and key: a miscategorisation, a Display-key
        // typo, or an unexpected count (a new variant) fails the test, prompting a
        // deliberate update here.
        let expected: &[(&str, &str)] = &[
            ("vmware", "virtualization"),
            ("hyperv", "virtualization"),
            ("proxmox", "virtualization"),
            ("nutanix-ahv", "virtualization"),
            ("xen", "virtualization"),
            ("kvm", "virtualization"),
            ("veeam", "backup"),
            ("commvault", "backup"),
            ("rubrik", "backup"),
            ("cohesity", "backup"),
            ("netbackup", "backup"),
            ("veeam-one", "monitoring"),
            ("zabbix", "monitoring"),
            ("prometheus", "monitoring"),
            ("datadog", "monitoring"),
            ("grafana", "monitoring"),
            ("solarwinds", "monitoring"),
            ("servicenow", "itsm"),
        ];
        let cat = catalog();
        assert_eq!(
            cat.len(),
            expected.len(),
            "catalog size diverged from the independent expectation — update both"
        );
        let actual: std::collections::BTreeMap<&str, &str> = cat
            .iter()
            .map(|c| (c.vendor_type.as_str(), c.category.as_str()))
            .collect();
        assert_eq!(actual.len(), cat.len(), "vendor_type keys must be unique");
        for (vt, cat_str) in expected {
            assert_eq!(
                actual.get(vt),
                Some(cat_str),
                "{vt} must be catalogued as {cat_str}"
            );
            assert!(
                capability_for(vt).is_some(),
                "{vt} must resolve via capability_for"
            );
        }
    }

    #[test]
    fn lookup_is_case_insensitive_and_404_safe() {
        assert_eq!(
            capability_for("VEEAM").map(|c| c.category),
            Some(VendorCategory::Backup)
        );
        assert_eq!(
            capability_for("zabbix").map(|c| c.category),
            Some(VendorCategory::Monitoring)
        );
        assert_eq!(capability_for("not-a-vendor"), None);
        assert_eq!(capability_for(""), None);
    }

    #[test]
    fn categories_are_as_expected() {
        let by = |k: &str| capability_for(k).unwrap().category;
        assert_eq!(by("vmware"), VendorCategory::Virtualization);
        assert_eq!(by("netbackup"), VendorCategory::Backup);
        assert_eq!(by("veeam-one"), VendorCategory::Monitoring);
        assert_eq!(by("servicenow"), VendorCategory::Itsm);
    }
}
