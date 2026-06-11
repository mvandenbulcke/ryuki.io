use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SupportStatus {
    Supported,
    Expiring,
    Expired,
}

impl std::fmt::Display for SupportStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupportStatus::Supported => write!(f, "Supported"),
            SupportStatus::Expiring => write!(f, "Expiring"),
            SupportStatus::Expired => write!(f, "Expired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LifecycleStatus {
    Production,
    Extended,
    Retiring,
    Retired,
}

impl std::fmt::Display for LifecycleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LifecycleStatus::Production => write!(f, "Production"),
            LifecycleStatus::Extended => write!(f, "Extended"),
            LifecycleStatus::Retiring => write!(f, "Retiring"),
            LifecycleStatus::Retired => write!(f, "Retired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Vendor {
    HPE,
    Lenovo,
}

impl std::fmt::Display for Vendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Vendor::HPE => write!(f, "HPE"),
            Vendor::Lenovo => write!(f, "Lenovo"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAsset {
    pub id: String,
    pub vendor: Vendor,
    pub model: String,
    pub serial_number: String,
    pub site: String,
    pub cluster: String,
    pub warranty_expiry: String,
    pub firmware_baseline: String,
    pub firmware_installed: String,
    pub support_status: SupportStatus,
    pub lifecycle_status: LifecycleStatus,
    pub last_health_check: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareRecord {
    pub id: String,
    pub asset_id: String,
    pub version: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareComplianceCheck {
    pub asset_id: String,
    pub model: String,
    pub site: String,
    pub baseline: String,
    pub installed: String,
    pub compliant: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportRiskEntry {
    pub asset_id: String,
    pub vendor: String,
    pub model: String,
    pub serial_number: String,
    pub site: String,
    pub support_status: String,
    pub warranty_expiry: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshPlanEntry {
    pub asset_id: String,
    pub vendor: String,
    pub model: String,
    pub serial_number: String,
    pub site: String,
    pub warranty_expiry: String,
    pub lifecycle_status: String,
    pub age_years: f64,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleReport {
    pub site: String,
    pub total: usize,
    pub production: usize,
    pub extended: usize,
    pub retiring: usize,
    pub retired: usize,
    pub supported: usize,
    pub expiring: usize,
    pub expired: usize,
    pub firmware_compliant: usize,
    pub firmware_gaps: usize,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn seed_assets() -> Vec<HardwareAsset> {
    let now = chrono::Utc::now();
    vec![
        HardwareAsset {
            id: Uuid::new_v4().to_string(),
            vendor: Vendor::HPE,
            model: "DL360 Gen10".into(),
            serial_number: "HPE-DL360-001".into(),
            site: "GBLON".into(),
            cluster: "gblon-prod-cluster-a".into(),
            warranty_expiry: (now + chrono::Duration::days(45)).to_rfc3339(),
            firmware_baseline: "2.94".into(),
            firmware_installed: "2.92".into(),
            support_status: SupportStatus::Expiring,
            lifecycle_status: LifecycleStatus::Production,
            last_health_check: now.to_rfc3339(),
        },
        HardwareAsset {
            id: Uuid::new_v4().to_string(),
            vendor: Vendor::HPE,
            model: "DL380 Gen10".into(),
            serial_number: "HPE-DL380-001".into(),
            site: "GBLON".into(),
            cluster: "gblon-prod-cluster-a".into(),
            warranty_expiry: (now + chrono::Duration::days(730)).to_rfc3339(),
            firmware_baseline: "2.94".into(),
            firmware_installed: "2.94".into(),
            support_status: SupportStatus::Supported,
            lifecycle_status: LifecycleStatus::Production,
            last_health_check: now.to_rfc3339(),
        },
        HardwareAsset {
            id: Uuid::new_v4().to_string(),
            vendor: Vendor::Lenovo,
            model: "SR635".into(),
            serial_number: "LNV-SR635-001".into(),
            site: "GBLON".into(),
            cluster: "gblon-storage-cluster-b".into(),
            warranty_expiry: (now - chrono::Duration::days(120)).to_rfc3339(),
            firmware_baseline: "3.20".into(),
            firmware_installed: "3.10".into(),
            support_status: SupportStatus::Expired,
            lifecycle_status: LifecycleStatus::Extended,
            last_health_check: (now - chrono::Duration::days(30)).to_rfc3339(),
        },
        HardwareAsset {
            id: Uuid::new_v4().to_string(),
            vendor: Vendor::HPE,
            model: "DL360 Gen10".into(),
            serial_number: "HPE-DL360-002".into(),
            site: "FRPAR".into(),
            cluster: "frpar-prod-cluster-a".into(),
            warranty_expiry: (now + chrono::Duration::days(60)).to_rfc3339(),
            firmware_baseline: "2.94".into(),
            firmware_installed: "2.94".into(),
            support_status: SupportStatus::Expiring,
            lifecycle_status: LifecycleStatus::Production,
            last_health_check: now.to_rfc3339(),
        },
        HardwareAsset {
            id: Uuid::new_v4().to_string(),
            vendor: Vendor::Lenovo,
            model: "SR635".into(),
            serial_number: "LNV-SR635-002".into(),
            site: "FRPAR".into(),
            cluster: "frpar-storage-cluster-b".into(),
            warranty_expiry: (now + chrono::Duration::days(1095)).to_rfc3339(),
            firmware_baseline: "3.20".into(),
            firmware_installed: "3.20".into(),
            support_status: SupportStatus::Supported,
            lifecycle_status: LifecycleStatus::Production,
            last_health_check: now.to_rfc3339(),
        },
        HardwareAsset {
            id: Uuid::new_v4().to_string(),
            vendor: Vendor::HPE,
            model: "DL380 Gen9".into(),
            serial_number: "HPE-DL380-002".into(),
            site: "FRPAR".into(),
            cluster: "frpar-test-cluster-c".into(),
            warranty_expiry: (now - chrono::Duration::days(500)).to_rfc3339(),
            firmware_baseline: "2.94".into(),
            firmware_installed: "2.80".into(),
            support_status: SupportStatus::Expired,
            lifecycle_status: LifecycleStatus::Retiring,
            last_health_check: (now - chrono::Duration::days(90)).to_rfc3339(),
        },
    ]
}

static ASSET_STORE: std::sync::LazyLock<Mutex<Vec<HardwareAsset>>> =
    std::sync::LazyLock::new(|| Mutex::new(seed_assets()));

static FIRMWARE_HISTORY: std::sync::LazyLock<Mutex<Vec<FirmwareRecord>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

pub fn get_inventory(site: &str) -> Vec<HardwareAsset> {
    let store = ASSET_STORE.lock().unwrap();
    if site.is_empty() {
        store.clone()
    } else {
        store.iter().filter(|a| a.site == site).cloned().collect()
    }
}

pub fn get_warranty_expiring() -> Vec<HardwareAsset> {
    let now = chrono::Utc::now();
    let threshold = now + chrono::Duration::days(90);
    let store = ASSET_STORE.lock().unwrap();
    store
        .iter()
        .filter(|a| {
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(&a.warranty_expiry) {
                let expiry_utc = expiry.with_timezone(&chrono::Utc);
                expiry_utc <= threshold && expiry_utc > now
            } else {
                false
            }
        })
        .cloned()
        .collect()
}

pub fn check_firmware_compliance(asset_id: &str) -> Result<FirmwareComplianceCheck, String> {
    let store = ASSET_STORE.lock().unwrap();
    let asset = store
        .iter()
        .find(|a| a.id == asset_id)
        .ok_or_else(|| format!("Asset {asset_id} not found"))?;
    Ok(FirmwareComplianceCheck {
        asset_id: asset.id.clone(),
        model: asset.model.clone(),
        site: asset.site.clone(),
        baseline: asset.firmware_baseline.clone(),
        installed: asset.firmware_installed.clone(),
        compliant: asset.firmware_installed == asset.firmware_baseline,
    })
}

pub fn get_firmware_gaps(site: &str) -> Vec<FirmwareComplianceCheck> {
    let store = ASSET_STORE.lock().unwrap();
    store
        .iter()
        .filter(|a| {
            let site_match = site.is_empty() || a.site == site;
            site_match && a.firmware_installed != a.firmware_baseline
        })
        .map(|a| FirmwareComplianceCheck {
            asset_id: a.id.clone(),
            model: a.model.clone(),
            site: a.site.clone(),
            baseline: a.firmware_baseline.clone(),
            installed: a.firmware_installed.clone(),
            compliant: false,
        })
        .collect()
}

pub fn get_support_risk(site: &str) -> Vec<SupportRiskEntry> {
    let store = ASSET_STORE.lock().unwrap();
    store
        .iter()
        .filter(|a| {
            let site_match = site.is_empty() || a.site == site;
            site_match && a.support_status == SupportStatus::Expired
        })
        .map(|a| SupportRiskEntry {
            asset_id: a.id.clone(),
            vendor: a.vendor.to_string(),
            model: a.model.clone(),
            serial_number: a.serial_number.clone(),
            site: a.site.clone(),
            support_status: a.support_status.to_string(),
            warranty_expiry: a.warranty_expiry.clone(),
        })
        .collect()
}

pub fn get_refresh_plan(site: &str) -> Vec<RefreshPlanEntry> {
    let now = chrono::Utc::now();
    let store = ASSET_STORE.lock().unwrap();
    store
        .iter()
        .filter(|a| site.is_empty() || a.site == site)
        .filter(|a| {
            a.lifecycle_status == LifecycleStatus::Extended
                || a.lifecycle_status == LifecycleStatus::Retiring
                || a.support_status == SupportStatus::Expired
                || a.support_status == SupportStatus::Expiring
        })
        .map(|a| {
            let age_days =
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(&a.warranty_expiry) {
                    let expiry_utc = expiry.with_timezone(&chrono::Utc);
                    let duration = now.signed_duration_since(expiry_utc);
                    let age_seconds = duration.num_seconds() as f64;
                    (age_seconds / 86400.0).max(0.0)
                } else {
                    0.0
                };
            let age_years = age_days / 365.25;
            let action = if a.support_status == SupportStatus::Expired {
                "Immediate replacement recommended"
            } else if a.lifecycle_status == LifecycleStatus::Retiring {
                "Schedule decommission within 30 days"
            } else if a.lifecycle_status == LifecycleStatus::Extended {
                "Budget for replacement within 12 months"
            } else {
                "Monitor warranty and plan refresh"
            };
            RefreshPlanEntry {
                asset_id: a.id.clone(),
                vendor: a.vendor.to_string(),
                model: a.model.clone(),
                serial_number: a.serial_number.clone(),
                site: a.site.clone(),
                warranty_expiry: a.warranty_expiry.clone(),
                lifecycle_status: a.lifecycle_status.to_string(),
                age_years,
                recommended_action: action.to_string(),
            }
        })
        .collect()
}

pub fn get_lifecycle_report(site: &str) -> LifecycleReport {
    let store = ASSET_STORE.lock().unwrap();
    let filtered: Vec<&HardwareAsset> = if site.is_empty() {
        store.iter().collect()
    } else {
        store.iter().filter(|a| a.site == site).collect()
    };
    let report_site = if site.is_empty() { "All" } else { site };
    LifecycleReport {
        site: report_site.to_string(),
        total: filtered.len(),
        production: filtered
            .iter()
            .filter(|a| a.lifecycle_status == LifecycleStatus::Production)
            .count(),
        extended: filtered
            .iter()
            .filter(|a| a.lifecycle_status == LifecycleStatus::Extended)
            .count(),
        retiring: filtered
            .iter()
            .filter(|a| a.lifecycle_status == LifecycleStatus::Retiring)
            .count(),
        retired: filtered
            .iter()
            .filter(|a| a.lifecycle_status == LifecycleStatus::Retired)
            .count(),
        supported: filtered
            .iter()
            .filter(|a| a.support_status == SupportStatus::Supported)
            .count(),
        expiring: filtered
            .iter()
            .filter(|a| a.support_status == SupportStatus::Expiring)
            .count(),
        expired: filtered
            .iter()
            .filter(|a| a.support_status == SupportStatus::Expired)
            .count(),
        firmware_compliant: filtered
            .iter()
            .filter(|a| a.firmware_installed == a.firmware_baseline)
            .count(),
        firmware_gaps: filtered
            .iter()
            .filter(|a| a.firmware_installed != a.firmware_baseline)
            .count(),
    }
}

pub fn add_asset(
    vendor: &str,
    model: &str,
    site: &str,
    cluster: &str,
    serial: &str,
    warranty_expiry: &str,
) -> Result<HardwareAsset, String> {
    if vendor.is_empty() || model.is_empty() || site.is_empty() || serial.is_empty() {
        return Err("vendor, model, site, and serial are required".into());
    }
    let vendor_enum = match vendor {
        "HPE" => Vendor::HPE,
        "Lenovo" => Vendor::Lenovo,
        _ => return Err(format!("Unknown vendor: {vendor}. Must be HPE or Lenovo")),
    };
    let asset = HardwareAsset {
        id: Uuid::new_v4().to_string(),
        vendor: vendor_enum,
        model: model.to_string(),
        serial_number: serial.to_string(),
        site: site.to_string(),
        cluster: cluster.to_string(),
        warranty_expiry: warranty_expiry.to_string(),
        firmware_baseline: "pending".into(),
        firmware_installed: "pending".into(),
        support_status: SupportStatus::Supported,
        lifecycle_status: LifecycleStatus::Production,
        last_health_check: now_iso(),
    };
    ASSET_STORE.lock().unwrap().push(asset.clone());
    Ok(asset)
}

pub fn update_firmware(asset_id: &str, version: &str) -> Result<HardwareAsset, String> {
    if version.is_empty() {
        return Err("version cannot be empty".into());
    }
    let mut store = ASSET_STORE.lock().unwrap();
    let asset = store
        .iter_mut()
        .find(|a| a.id == asset_id)
        .ok_or_else(|| format!("Asset {asset_id} not found"))?;
    asset.firmware_installed = version.to_string();
    let record = FirmwareRecord {
        id: Uuid::new_v4().to_string(),
        asset_id: asset_id.to_string(),
        version: version.to_string(),
        updated_at: now_iso(),
    };
    FIRMWARE_HISTORY.lock().unwrap().push(record);
    Ok(asset.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_inventory_returns_seeded_assets() {
        let inventory = get_inventory("");
        assert!(inventory.len() >= 6);

        let gblon = get_inventory("GBLON");
        assert!(gblon.len() >= 3);

        let frpar = get_inventory("FRPAR");
        assert_eq!(frpar.len(), 3);
    }

    #[test]
    fn test_get_inventory_unknown_site_returns_empty() {
        let result = get_inventory("NONEXISTENT");
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_warranty_expiring() {
        let expiring = get_warranty_expiring();
        assert!(!expiring.is_empty());
        for asset in &expiring {
            let now = chrono::Utc::now();
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(&asset.warranty_expiry) {
                let expiry_utc = expiry.with_timezone(&chrono::Utc);
                let threshold = now + chrono::Duration::days(90);
                assert!(expiry_utc <= threshold);
                assert!(expiry_utc > now);
            }
        }
    }

    #[test]
    fn test_check_firmware_compliance_noncompliant() {
        let inventory = get_inventory("");
        let asset = inventory
            .iter()
            .find(|a| a.firmware_installed != a.firmware_baseline)
            .unwrap();
        let result = check_firmware_compliance(&asset.id).unwrap();
        assert!(!result.compliant);
        assert_eq!(result.installed, asset.firmware_installed);
        assert_eq!(result.baseline, asset.firmware_baseline);
    }

    #[test]
    fn test_check_firmware_compliance_not_found() {
        assert!(check_firmware_compliance("nonexistent-id").is_err());
    }

    #[test]
    fn test_get_firmware_gaps() {
        let gaps = get_firmware_gaps("");
        assert!(!gaps.is_empty());
        for gap in &gaps {
            assert!(!gap.compliant);
            assert_ne!(gap.installed, gap.baseline);
        }
    }

    #[test]
    fn test_get_support_risk() {
        let risks = get_support_risk("");
        assert!(!risks.is_empty());
        for risk in &risks {
            assert_eq!(risk.support_status, "Expired");
        }
    }

    #[test]
    fn test_get_refresh_plan() {
        let plan = get_refresh_plan("");
        assert!(!plan.is_empty());
        for entry in &plan {
            assert!(!entry.recommended_action.is_empty());
        }
    }

    #[test]
    fn test_get_lifecycle_report() {
        let report = get_lifecycle_report("");
        assert!(report.total >= 6);

        let gblon_report = get_lifecycle_report("GBLON");
        assert!(gblon_report.total >= 3);
    }

    #[test]
    fn test_add_asset_succeeds() {
        let asset = add_asset(
            "HPE",
            "DL360 Gen11",
            "GBLON",
            "gblon-new-cluster",
            "HPE-DL360-003",
            "2028-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(asset.vendor, Vendor::HPE);
        assert_eq!(asset.model, "DL360 Gen11");
        assert_eq!(asset.site, "GBLON");
        assert_eq!(asset.serial_number, "HPE-DL360-003");

        let inventory = get_inventory("");
        assert!(inventory.len() >= 7);
    }

    #[test]
    fn test_add_asset_invalid_vendor() {
        let result = add_asset(
            "Dell",
            "PowerEdge",
            "GBLON",
            "cluster",
            "DELL-001",
            "2028-01-01T00:00:00Z",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_add_asset_empty_fields() {
        assert!(
            add_asset(
                "",
                "model",
                "site",
                "cluster",
                "serial",
                "2028-01-01T00:00:00Z"
            )
            .is_err()
        );
        assert!(
            add_asset(
                "HPE",
                "",
                "site",
                "cluster",
                "serial",
                "2028-01-01T00:00:00Z"
            )
            .is_err()
        );
        assert!(
            add_asset(
                "HPE",
                "model",
                "",
                "cluster",
                "serial",
                "2028-01-01T00:00:00Z"
            )
            .is_err()
        );
        assert!(
            add_asset(
                "HPE",
                "model",
                "site",
                "cluster",
                "",
                "2028-01-01T00:00:00Z"
            )
            .is_err()
        );
    }

    #[test]
    fn test_update_firmware_succeeds() {
        let inventory = get_inventory("");
        let asset = inventory
            .iter()
            .find(|a| a.firmware_installed != a.firmware_baseline)
            .unwrap();
        let baseline = asset.firmware_baseline.clone();
        let updated = update_firmware(&asset.id, &baseline).unwrap();
        assert_eq!(updated.firmware_installed, baseline);

        let check = check_firmware_compliance(&asset.id).unwrap();
        assert!(check.compliant);
    }

    #[test]
    fn test_update_firmware_empty_version() {
        let inventory = get_inventory("");
        let asset = inventory.first().unwrap();
        assert!(update_firmware(&asset.id, "").is_err());
    }

    #[test]
    fn test_update_firmware_not_found() {
        assert!(update_firmware("nonexistent-id", "1.0").is_err());
    }

    #[test]
    fn test_support_status_display() {
        assert_eq!(SupportStatus::Supported.to_string(), "Supported");
        assert_eq!(SupportStatus::Expiring.to_string(), "Expiring");
        assert_eq!(SupportStatus::Expired.to_string(), "Expired");
    }

    #[test]
    fn test_lifecycle_status_display() {
        assert_eq!(LifecycleStatus::Production.to_string(), "Production");
        assert_eq!(LifecycleStatus::Extended.to_string(), "Extended");
        assert_eq!(LifecycleStatus::Retiring.to_string(), "Retiring");
        assert_eq!(LifecycleStatus::Retired.to_string(), "Retired");
    }

    #[test]
    fn test_vendor_display() {
        assert_eq!(Vendor::HPE.to_string(), "HPE");
        assert_eq!(Vendor::Lenovo.to_string(), "Lenovo");
    }

    #[test]
    fn test_firmware_gaps_by_site() {
        let gblon_gaps = get_firmware_gaps("GBLON");
        let frpar_gaps = get_firmware_gaps("FRPAR");
        assert!(!gblon_gaps.is_empty() || !frpar_gaps.is_empty());
    }

    #[test]
    fn test_support_risk_empty_site() {
        let risk = get_support_risk("");
        assert!(!risk.is_empty());
    }
}
