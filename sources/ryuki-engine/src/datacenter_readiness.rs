use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteReadiness {
    pub site: String,
    pub checks: Vec<ReadinessCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadinessCheck {
    pub id: String,
    pub site: String,
    pub check_type: CheckType,
    pub status: CheckStatus,
    pub last_checked: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CheckType {
    Power,
    Cooling,
    RackSpace,
    Switchport,
    Firmware,
    Capacity,
}

impl std::fmt::Display for CheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckType::Power => write!(f, "power"),
            CheckType::Cooling => write!(f, "cooling"),
            CheckType::RackSpace => write!(f, "rack-space"),
            CheckType::Switchport => write!(f, "switchport"),
            CheckType::Firmware => write!(f, "firmware"),
            CheckType::Capacity => write!(f, "capacity"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CheckStatus {
    Passed,
    Failed,
    Warning,
    NotChecked,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckStatus::Passed => write!(f, "passed"),
            CheckStatus::Failed => write!(f, "failed"),
            CheckStatus::Warning => write!(f, "warning"),
            CheckStatus::NotChecked => write!(f, "not-checked"),
        }
    }
}

type ReadinessStore = Vec<SiteReadiness>;

static READINESS_STORE: OnceLock<Mutex<ReadinessStore>> = OnceLock::new();

fn readiness_store() -> &'static Mutex<ReadinessStore> {
    READINESS_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> ReadinessStore {
    let sites = crate::site_registry::get_active_site_codes()
        .unwrap_or_else(|_| vec!["DEFRA".into(), "GBLON".into(), "FRPAR".into()]);
    let s0 = sites.first().map(|s| s.as_str()).unwrap_or("DEFRA");
    let s1 = sites.get(1).map(|s| s.as_str()).unwrap_or("GBLON");
    let s2 = sites.get(2).map(|s| s.as_str()).unwrap_or("FRPAR");

    vec![
        SiteReadiness {
            site: s0.into(),
            checks: vec![
                ReadinessCheck {
                    id: format!("dc-check-{}-power", s0.to_lowercase()),
                    site: s0.into(),
                    check_type: CheckType::Power,
                    status: CheckStatus::Passed,
                    last_checked: "2026-06-11T10:00:00Z".into(),
                    details: "PDU A+B redundant, UPS load 62% with 28 min runtime".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-cooling", s0.to_lowercase()),
                    site: s0.into(),
                    check_type: CheckType::Cooling,
                    status: CheckStatus::Passed,
                    last_checked: "2026-06-11T10:00:00Z".into(),
                    details: "CRAC units nominal, return air 22 C, supply 16 C".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-rack", s0.to_lowercase()),
                    site: s0.into(),
                    check_type: CheckType::RackSpace,
                    status: CheckStatus::Warning,
                    last_checked: "2026-06-11T10:00:00Z".into(),
                    details: "12 rack units free across 3 racks (limited headroom)".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-switchport", s0.to_lowercase()),
                    site: s0.into(),
                    check_type: CheckType::Switchport,
                    status: CheckStatus::Passed,
                    last_checked: "2026-06-11T10:00:00Z".into(),
                    details: "18 switchports available across prod/dmz/mgmt VLANs".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-firmware", s0.to_lowercase()),
                    site: s0.into(),
                    check_type: CheckType::Firmware,
                    status: CheckStatus::Warning,
                    last_checked: "2026-06-11T10:00:00Z".into(),
                    details: "2 PDUs on firmware v2.8 (current v3.1), SFP modules current".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-capacity", s0.to_lowercase()),
                    site: s0.into(),
                    check_type: CheckType::Capacity,
                    status: CheckStatus::Passed,
                    last_checked: "2026-06-11T10:00:00Z".into(),
                    details: "Compute 78% allocated, storage 64%, network fabric 42%".into(),
                },
            ],
        },
        SiteReadiness {
            site: s1.into(),
            checks: vec![
                ReadinessCheck {
                    id: format!("dc-check-{}-power", s1.to_lowercase()),
                    site: s1.into(),
                    check_type: CheckType::Power,
                    status: CheckStatus::Failed,
                    last_checked: "2026-06-11T09:30:00Z".into(),
                    details: "UPS-B in bypass mode, PDU-3 overload alarm at 91%".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-cooling", s1.to_lowercase()),
                    site: s1.into(),
                    check_type: CheckType::Cooling,
                    status: CheckStatus::Warning,
                    last_checked: "2026-06-11T09:30:00Z".into(),
                    details: "CRAC-2 compressor cycling, return air 26 C (threshold 24 C)".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-rack", s1.to_lowercase()),
                    site: s1.into(),
                    check_type: CheckType::RackSpace,
                    status: CheckStatus::Failed,
                    last_checked: "2026-06-11T09:30:00Z".into(),
                    details: "Zero rack units free, 2 racks over-populated (48U in 42U)".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-switchport", s1.to_lowercase()),
                    site: s1.into(),
                    check_type: CheckType::Switchport,
                    status: CheckStatus::Passed,
                    last_checked: "2026-06-11T09:30:00Z".into(),
                    details: "22 switchports available, fabric links healthy".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-firmware", s1.to_lowercase()),
                    site: s1.into(),
                    check_type: CheckType::Firmware,
                    status: CheckStatus::Failed,
                    last_checked: "2026-06-11T09:30:00Z".into(),
                    details: "Core switch firmware EOL 2025-Q3, CRAC controller behind 3 revs"
                        .into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-capacity", s1.to_lowercase()),
                    site: s1.into(),
                    check_type: CheckType::Capacity,
                    status: CheckStatus::Warning,
                    last_checked: "2026-06-11T09:30:00Z".into(),
                    details: "Compute 94% allocated (critical), storage 88%, network 71%".into(),
                },
            ],
        },
        SiteReadiness {
            site: s2.into(),
            checks: vec![
                ReadinessCheck {
                    id: format!("dc-check-{}-power", s2.to_lowercase()),
                    site: s2.into(),
                    check_type: CheckType::Power,
                    status: CheckStatus::Passed,
                    last_checked: "2026-06-11T08:00:00Z".into(),
                    details: "PDU A+B nominal, UPS load 45%, generator tested 2026-06-09".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-cooling", s2.to_lowercase()),
                    site: s2.into(),
                    check_type: CheckType::Cooling,
                    status: CheckStatus::Passed,
                    last_checked: "2026-06-11T08:00:00Z".into(),
                    details: "All CRAC units healthy, supply temp 15 C per ASHRAE A1".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-rack", s2.to_lowercase()),
                    site: s2.into(),
                    check_type: CheckType::RackSpace,
                    status: CheckStatus::Passed,
                    last_checked: "2026-06-11T08:00:00Z".into(),
                    details: "42 rack units free across 7 empty racks (new buildout)".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-switchport", s2.to_lowercase()),
                    site: s2.into(),
                    check_type: CheckType::Switchport,
                    status: CheckStatus::NotChecked,
                    last_checked: "2026-06-11T08:00:00Z".into(),
                    details: "Switch fabric not yet provisioned, awaiting L2 install".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-firmware", s2.to_lowercase()),
                    site: s2.into(),
                    check_type: CheckType::Firmware,
                    status: CheckStatus::NotChecked,
                    last_checked: "2026-06-11T08:00:00Z".into(),
                    details: "Hardware not yet racked, firmware baseline pending".into(),
                },
                ReadinessCheck {
                    id: format!("dc-check-{}-capacity", s2.to_lowercase()),
                    site: s2.into(),
                    check_type: CheckType::Capacity,
                    status: CheckStatus::Passed,
                    last_checked: "2026-06-11T08:00:00Z".into(),
                    details: "Greenfield site, 100% free across compute/storage/network".into(),
                },
            ],
        },
    ]
}

pub fn check_power(site: &str) -> Result<Value, String> {
    let store = readiness_store().lock().unwrap();
    let entry = store
        .iter()
        .find(|s| s.site == site)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    let check = entry
        .checks
        .iter()
        .find(|c| c.check_type == CheckType::Power)
        .unwrap();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "check_id": check.id,
        "status": check.status.to_string(),
        "details": check.details,
        "last_checked": check.last_checked,
        "dry_run": true
    }))
}

pub fn check_cooling(site: &str) -> Result<Value, String> {
    let store = readiness_store().lock().unwrap();
    let entry = store
        .iter()
        .find(|s| s.site == site)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    let check = entry
        .checks
        .iter()
        .find(|c| c.check_type == CheckType::Cooling)
        .unwrap();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "check_id": check.id,
        "status": check.status.to_string(),
        "details": check.details,
        "last_checked": check.last_checked,
        "dry_run": true
    }))
}

pub fn check_rack_space(site: &str) -> Result<Value, String> {
    let store = readiness_store().lock().unwrap();
    let entry = store
        .iter()
        .find(|s| s.site == site)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    let check = entry
        .checks
        .iter()
        .find(|c| c.check_type == CheckType::RackSpace)
        .unwrap();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "check_id": check.id,
        "status": check.status.to_string(),
        "details": check.details,
        "last_checked": check.last_checked,
        "dry_run": true
    }))
}

pub fn check_switchports(site: &str) -> Result<Value, String> {
    let store = readiness_store().lock().unwrap();
    let entry = store
        .iter()
        .find(|s| s.site == site)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    let check = entry
        .checks
        .iter()
        .find(|c| c.check_type == CheckType::Switchport)
        .unwrap();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "check_id": check.id,
        "status": check.status.to_string(),
        "details": check.details,
        "last_checked": check.last_checked,
        "dry_run": true
    }))
}

pub fn run_full_readiness(site: &str) -> Result<Value, String> {
    let store = readiness_store().lock().unwrap();
    let entry = store
        .iter()
        .find(|s| s.site == site)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    let results: Vec<Value> = entry
        .checks
        .iter()
        .map(|c| {
            json!({
                "check_type": c.check_type.to_string(),
                "status": c.status.to_string(),
                "details": c.details,
                "last_checked": c.last_checked,
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "checks_run": results.len(),
        "results": results,
        "dry_run": true
    }))
}

pub fn get_readiness_score(site: &str) -> Result<Value, String> {
    let store = readiness_store().lock().unwrap();
    let entry = store
        .iter()
        .find(|s| s.site == site)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    let total = entry.checks.len() as f64;
    let passed = entry
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Passed)
        .count() as f64;
    let warnings = entry
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warning)
        .count() as f64;

    let score = ((passed * 1.0 + warnings * 0.5) / total * 100.0).round() as u32;

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "readiness_score_pct": score,
        "total_checks": total as u32,
        "passed": passed as u32,
        "warnings": warnings as u32,
        "failed": entry.checks.iter().filter(|c| c.status == CheckStatus::Failed).count() as u32,
        "not_checked": entry.checks.iter().filter(|c| c.status == CheckStatus::NotChecked).count() as u32,
        "dry_run": true
    }))
}

pub fn get_site_report(site: &str) -> Result<Value, String> {
    let store = readiness_store().lock().unwrap();
    let entry = store
        .iter()
        .find(|s| s.site == site)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    let score = {
        let total = entry.checks.len() as f64;
        let passed = entry
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Passed)
            .count() as f64;
        let warnings = entry
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Warning)
            .count() as f64;
        ((passed * 1.0 + warnings * 0.5) / total * 100.0).round() as u32
    };

    let checks_detail: Vec<Value> = entry
        .checks
        .iter()
        .map(|c| {
            json!({
                "check_type": c.check_type.to_string(),
                "status": c.status.to_string(),
                "details": c.details,
                "last_checked": c.last_checked,
            })
        })
        .collect();

    let overall = if score >= 90 {
        "healthy"
    } else if score >= 60 {
        "degraded"
    } else {
        "critical"
    };

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "overall_status": overall,
        "readiness_score_pct": score,
        "checks": checks_detail,
        "dry_run": true
    }))
}

pub fn get_failing_checks() -> Result<Value, String> {
    let store = readiness_store().lock().unwrap();

    let mut failing: Vec<Value> = Vec::new();
    for site_entry in store.iter() {
        for check in site_entry.checks.iter() {
            if check.status == CheckStatus::Failed {
                failing.push(json!({
                    "site": site_entry.site,
                    "check_type": check.check_type.to_string(),
                    "details": check.details,
                    "last_checked": check.last_checked,
                }));
            }
        }
    }

    Ok(json!({
        "source": "dry-run",
        "failing_count": failing.len(),
        "failing_checks": failing,
        "dry_run": true
    }))
}

pub fn get_sites() -> Result<Value, String> {
    let store = readiness_store().lock().unwrap();

    let sites: Vec<Value> = store
        .iter()
        .map(|entry| {
            let passed = entry
                .checks
                .iter()
                .filter(|c| c.status == CheckStatus::Passed)
                .count();
            let failed = entry
                .checks
                .iter()
                .filter(|c| c.status == CheckStatus::Failed)
                .count();
            json!({
                "site": entry.site,
                "total_checks": entry.checks.len(),
                "passed": passed,
                "failed": failed,
                "not_checked": entry.checks.iter().filter(|c| c.status == CheckStatus::NotChecked).count(),
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "sites": sites,
        "dry_run": true
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sites() -> Vec<String> {
        crate::site_registry::get_active_site_codes()
            .unwrap_or_else(|_| vec!["DEFRA".into(), "GBLON".into(), "FRPAR".into()])
    }

    fn s0() -> String {
        sites()[0].clone()
    }
    fn s1() -> String {
        sites()[1].clone()
    }
    fn s2() -> String {
        sites()[2].clone()
    }

    #[test]
    fn test_check_power_healthy_site() {
        let site = s0();
        let result = check_power(&site).unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["site"], site);
        assert_eq!(result["status"], "passed");
        assert!(result["details"].as_str().unwrap().contains("PDU"));
    }

    #[test]
    fn test_check_power_failing_site() {
        let site = s1();
        let result = check_power(&site).unwrap();
        assert_eq!(result["status"], "failed");
        assert!(result["details"].as_str().unwrap().contains("UPS-B"));
    }

    #[test]
    fn test_check_power_site_not_found() {
        assert!(check_power("NONEXISTENT").is_err());
    }

    #[test]
    fn test_run_full_readiness_first_site() {
        let site = s0();
        let result = run_full_readiness(&site).unwrap();
        assert_eq!(result["site"], site);
        assert_eq!(result["checks_run"], 6);
        assert!(!result["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_get_readiness_score_healthy_site() {
        let site = s0();
        let result = get_readiness_score(&site).unwrap();
        let score = result["readiness_score_pct"].as_u64().unwrap();
        assert!(score > 50);
        assert!(score <= 100);
        assert_eq!(result["total_checks"], 6);
    }

    #[test]
    fn test_get_readiness_score_failing_site() {
        let site = s1();
        let result = get_readiness_score(&site).unwrap();
        let score = result["readiness_score_pct"].as_u64().unwrap();
        assert!(score < 60);
    }

    #[test]
    fn test_get_site_report_first_site() {
        let site = s0();
        let result = get_site_report(&site).unwrap();
        assert_eq!(result["site"], site);
        assert!(!result["overall_status"].as_str().unwrap().is_empty());
        assert_eq!(result["checks"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn test_get_failing_checks_has_entries() {
        let result = get_failing_checks().unwrap();
        assert!(result["failing_count"].as_u64().unwrap() > 0);
        assert!(!result["failing_checks"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_get_sites_returns_configured_count() {
        let result = get_sites().unwrap();
        let site_list = result["sites"].as_array().unwrap();
        assert_eq!(site_list.len(), 3);
    }

    #[test]
    fn test_check_switchports_greenfield_not_checked() {
        let site = s2();
        let result = check_switchports(&site).unwrap();
        assert_eq!(result["status"], "not-checked");
        assert!(
            result["details"]
                .as_str()
                .unwrap()
                .contains("not yet provisioned")
        );
    }

    #[test]
    fn test_readiness_score_greenfield_low() {
        let site = s2();
        let result = get_readiness_score(&site).unwrap();
        let score = result["readiness_score_pct"].as_u64().unwrap();
        assert!(score < 100);
        assert_eq!(result["not_checked"], 2);
    }
}
