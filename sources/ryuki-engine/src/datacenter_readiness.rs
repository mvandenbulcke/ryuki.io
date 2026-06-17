use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

// ─── Pure engine functions ────────────────────────────────────────────────────
//
// All functions below are pure over passed-in slices; they do not read any
// process-global state. The API layer (contracts.rs) loads checks from the
// DB via the repo and passes them here.

/// Find a single check of the given type for the given site.
fn find_check<'a>(
    checks: &'a [ReadinessCheck],
    site: &str,
    check_type: &CheckType,
) -> Option<&'a ReadinessCheck> {
    checks
        .iter()
        .find(|c| c.site == site && &c.check_type == check_type)
}

pub fn check_power(checks: &[ReadinessCheck], site: &str) -> Result<Value, String> {
    let check = find_check(checks, site, &CheckType::Power)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    Ok(json!({
        "source": "db",
        "site": site,
        "check_id": check.id,
        "status": check.status.to_string(),
        "details": check.details,
        "last_checked": check.last_checked,
    }))
}

pub fn check_cooling(checks: &[ReadinessCheck], site: &str) -> Result<Value, String> {
    let check = find_check(checks, site, &CheckType::Cooling)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    Ok(json!({
        "source": "db",
        "site": site,
        "check_id": check.id,
        "status": check.status.to_string(),
        "details": check.details,
        "last_checked": check.last_checked,
    }))
}

pub fn check_rack_space(checks: &[ReadinessCheck], site: &str) -> Result<Value, String> {
    let check = find_check(checks, site, &CheckType::RackSpace)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    Ok(json!({
        "source": "db",
        "site": site,
        "check_id": check.id,
        "status": check.status.to_string(),
        "details": check.details,
        "last_checked": check.last_checked,
    }))
}

pub fn check_switchports(checks: &[ReadinessCheck], site: &str) -> Result<Value, String> {
    let check = find_check(checks, site, &CheckType::Switchport)
        .ok_or_else(|| format!("Site not found: {}", site))?;

    Ok(json!({
        "source": "db",
        "site": site,
        "check_id": check.id,
        "status": check.status.to_string(),
        "details": check.details,
        "last_checked": check.last_checked,
    }))
}

pub fn run_full_readiness(checks: &[ReadinessCheck], site: &str) -> Result<Value, String> {
    let site_checks: Vec<&ReadinessCheck> = checks.iter().filter(|c| c.site == site).collect();

    if site_checks.is_empty() {
        return Err(format!("Site not found: {}", site));
    }

    let results: Vec<Value> = site_checks
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
        "source": "db",
        "site": site,
        "checks_run": results.len(),
        "results": results,
    }))
}

pub fn get_readiness_score(checks: &[ReadinessCheck], site: &str) -> Result<Value, String> {
    let site_checks: Vec<&ReadinessCheck> = checks.iter().filter(|c| c.site == site).collect();

    if site_checks.is_empty() {
        return Err(format!("Site not found: {}", site));
    }

    let count_status = |s: CheckStatus| site_checks.iter().filter(|c| c.status == s).count();
    let total_n = site_checks.len();
    let passed_n = count_status(CheckStatus::Passed);
    let warnings_n = count_status(CheckStatus::Warning);
    let failed_n = count_status(CheckStatus::Failed);
    let not_checked_n = count_status(CheckStatus::NotChecked);

    // Counts are small in practice, but honour the integer-width contract:
    // saturate rather than silently truncate via `as`.
    let to_u32 = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);

    // Score is a bounded 0..=100 percentage. `total_n > 0` is guaranteed by the
    // empty-site Err guard above, so the division is always well-defined.
    let score =
        ((passed_n as f64 + warnings_n as f64 * 0.5) / total_n as f64 * 100.0).round() as u32;

    Ok(json!({
        "source": "db",
        "site": site,
        "readiness_score_pct": score,
        "total_checks": to_u32(total_n),
        "passed": to_u32(passed_n),
        "warnings": to_u32(warnings_n),
        "failed": to_u32(failed_n),
        "not_checked": to_u32(not_checked_n),
    }))
}

pub fn get_site_report(checks: &[ReadinessCheck], site: &str) -> Result<Value, String> {
    let site_checks: Vec<&ReadinessCheck> = checks.iter().filter(|c| c.site == site).collect();

    if site_checks.is_empty() {
        return Err(format!("Site not found: {}", site));
    }

    let total = site_checks.len() as f64;
    let passed = site_checks
        .iter()
        .filter(|c| c.status == CheckStatus::Passed)
        .count() as f64;
    let warnings = site_checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warning)
        .count() as f64;
    let score = ((passed * 1.0 + warnings * 0.5) / total * 100.0).round() as u32;

    let checks_detail: Vec<Value> = site_checks
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
        "source": "db",
        "site": site,
        "overall_status": overall,
        "readiness_score_pct": score,
        "checks": checks_detail,
    }))
}

pub fn get_failing_checks(checks: &[ReadinessCheck]) -> Result<Value, String> {
    let failing: Vec<Value> = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Failed)
        .map(|c| {
            json!({
                "site": c.site,
                "check_type": c.check_type.to_string(),
                "details": c.details,
                "last_checked": c.last_checked,
            })
        })
        .collect();

    Ok(json!({
        "source": "db",
        "failing_count": failing.len(),
        "failing_checks": failing,
    }))
}

pub fn get_sites(checks: &[ReadinessCheck]) -> Result<Value, String> {
    // Collect unique sites in order of first appearance.
    let mut seen_sites: Vec<&str> = Vec::new();
    for c in checks {
        if !seen_sites.contains(&c.site.as_str()) {
            seen_sites.push(&c.site);
        }
    }

    let sites: Vec<Value> = seen_sites
        .iter()
        .map(|site| {
            let site_checks: Vec<&ReadinessCheck> =
                checks.iter().filter(|c| &c.site == site).collect();
            let passed = site_checks
                .iter()
                .filter(|c| c.status == CheckStatus::Passed)
                .count();
            let failed = site_checks
                .iter()
                .filter(|c| c.status == CheckStatus::Failed)
                .count();
            let not_checked = site_checks
                .iter()
                .filter(|c| c.status == CheckStatus::NotChecked)
                .count();
            json!({
                "site": site,
                "total_checks": site_checks.len(),
                "passed": passed,
                "failed": failed,
                "not_checked": not_checked,
            })
        })
        .collect();

    Ok(json!({
        "source": "db",
        "sites": sites,
    }))
}

// ─── Test fixture ─────────────────────────────────────────────────────────────
//
// `seed_data` is kept as a test-only fixture so that unit tests of the pure
// engine functions do not require a database connection.

#[cfg(test)]
pub fn seed_data() -> Vec<ReadinessCheck> {
    let sites = crate::site_registry::get_active_site_codes()
        .unwrap_or_else(|_| vec!["DEFRA".into(), "GBLON".into(), "FRPAR".into()]);
    let s0 = sites.first().map(|s| s.as_str()).unwrap_or("DEFRA");
    let s1 = sites.get(1).map(|s| s.as_str()).unwrap_or("GBLON");
    let s2 = sites.get(2).map(|s| s.as_str()).unwrap_or("FRPAR");

    vec![
        ReadinessCheck {
            id: format!("dc-check-{}-power", s0.to_lowercase()),
            site: s0.into(),
            check_type: CheckType::Power,
            status: CheckStatus::Passed,
            last_checked: "2026-06-11T10:00:00+00:00".into(),
            details: "PDU A+B redundant, UPS load 62% with 28 min runtime".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-cooling", s0.to_lowercase()),
            site: s0.into(),
            check_type: CheckType::Cooling,
            status: CheckStatus::Passed,
            last_checked: "2026-06-11T10:00:00+00:00".into(),
            details: "CRAC units nominal, return air 22 C, supply 16 C".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-rack", s0.to_lowercase()),
            site: s0.into(),
            check_type: CheckType::RackSpace,
            status: CheckStatus::Warning,
            last_checked: "2026-06-11T10:00:00+00:00".into(),
            details: "12 rack units free across 3 racks (limited headroom)".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-switchport", s0.to_lowercase()),
            site: s0.into(),
            check_type: CheckType::Switchport,
            status: CheckStatus::Passed,
            last_checked: "2026-06-11T10:00:00+00:00".into(),
            details: "18 switchports available across prod/dmz/mgmt VLANs".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-firmware", s0.to_lowercase()),
            site: s0.into(),
            check_type: CheckType::Firmware,
            status: CheckStatus::Warning,
            last_checked: "2026-06-11T10:00:00+00:00".into(),
            details: "2 PDUs on firmware v2.8 (current v3.1), SFP modules current".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-capacity", s0.to_lowercase()),
            site: s0.into(),
            check_type: CheckType::Capacity,
            status: CheckStatus::Passed,
            last_checked: "2026-06-11T10:00:00+00:00".into(),
            details: "Compute 78% allocated, storage 64%, network fabric 42%".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-power", s1.to_lowercase()),
            site: s1.into(),
            check_type: CheckType::Power,
            status: CheckStatus::Failed,
            last_checked: "2026-06-11T09:30:00+00:00".into(),
            details: "UPS-B in bypass mode, PDU-3 overload alarm at 91%".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-cooling", s1.to_lowercase()),
            site: s1.into(),
            check_type: CheckType::Cooling,
            status: CheckStatus::Warning,
            last_checked: "2026-06-11T09:30:00+00:00".into(),
            details: "CRAC-2 compressor cycling, return air 26 C (threshold 24 C)".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-rack", s1.to_lowercase()),
            site: s1.into(),
            check_type: CheckType::RackSpace,
            status: CheckStatus::Failed,
            last_checked: "2026-06-11T09:30:00+00:00".into(),
            details: "Zero rack units free, 2 racks over-populated (48U in 42U)".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-switchport", s1.to_lowercase()),
            site: s1.into(),
            check_type: CheckType::Switchport,
            status: CheckStatus::Passed,
            last_checked: "2026-06-11T09:30:00+00:00".into(),
            details: "22 switchports available, fabric links healthy".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-firmware", s1.to_lowercase()),
            site: s1.into(),
            check_type: CheckType::Firmware,
            status: CheckStatus::Failed,
            last_checked: "2026-06-11T09:30:00+00:00".into(),
            details: "Core switch firmware EOL 2025-Q3, CRAC controller behind 3 revs".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-capacity", s1.to_lowercase()),
            site: s1.into(),
            check_type: CheckType::Capacity,
            status: CheckStatus::Warning,
            last_checked: "2026-06-11T09:30:00+00:00".into(),
            details: "Compute 94% allocated (critical), storage 88%, network 71%".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-power", s2.to_lowercase()),
            site: s2.into(),
            check_type: CheckType::Power,
            status: CheckStatus::Passed,
            last_checked: "2026-06-11T08:00:00+00:00".into(),
            details: "PDU A+B nominal, UPS load 45%, generator tested 2026-06-09".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-cooling", s2.to_lowercase()),
            site: s2.into(),
            check_type: CheckType::Cooling,
            status: CheckStatus::Passed,
            last_checked: "2026-06-11T08:00:00+00:00".into(),
            details: "All CRAC units healthy, supply temp 15 C per ASHRAE A1".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-rack", s2.to_lowercase()),
            site: s2.into(),
            check_type: CheckType::RackSpace,
            status: CheckStatus::Passed,
            last_checked: "2026-06-11T08:00:00+00:00".into(),
            details: "42 rack units free across 7 empty racks (new buildout)".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-switchport", s2.to_lowercase()),
            site: s2.into(),
            check_type: CheckType::Switchport,
            status: CheckStatus::NotChecked,
            last_checked: "2026-06-11T08:00:00+00:00".into(),
            details: "Switch fabric not yet provisioned, awaiting L2 install".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-firmware", s2.to_lowercase()),
            site: s2.into(),
            check_type: CheckType::Firmware,
            status: CheckStatus::NotChecked,
            last_checked: "2026-06-11T08:00:00+00:00".into(),
            details: "Hardware not yet racked, firmware baseline pending".into(),
        },
        ReadinessCheck {
            id: format!("dc-check-{}-capacity", s2.to_lowercase()),
            site: s2.into(),
            check_type: CheckType::Capacity,
            status: CheckStatus::Passed,
            last_checked: "2026-06-11T08:00:00+00:00".into(),
            details: "Greenfield site, 100% free across compute/storage/network".into(),
        },
    ]
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
        let checks = seed_data();
        let site = s0();
        let result = check_power(&checks, &site).unwrap();
        assert_eq!(result["source"], "db");
        assert_eq!(result["site"], site);
        assert_eq!(result["status"], "passed");
        assert!(result["details"].as_str().unwrap().contains("PDU"));
    }

    #[test]
    fn test_check_power_failing_site() {
        let checks = seed_data();
        let site = s1();
        let result = check_power(&checks, &site).unwrap();
        assert_eq!(result["status"], "failed");
        assert!(result["details"].as_str().unwrap().contains("UPS-B"));
    }

    #[test]
    fn test_check_power_site_not_found() {
        let checks = seed_data();
        assert!(check_power(&checks, "NONEXISTENT").is_err());
    }

    #[test]
    fn test_run_full_readiness_first_site() {
        let checks = seed_data();
        let site = s0();
        let result = run_full_readiness(&checks, &site).unwrap();
        assert_eq!(result["site"], site);
        assert_eq!(result["checks_run"], 6);
        assert!(!result["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_get_readiness_score_healthy_site() {
        let checks = seed_data();
        let site = s0();
        let result = get_readiness_score(&checks, &site).unwrap();
        let score = result["readiness_score_pct"].as_u64().unwrap();
        assert!(score > 50);
        assert!(score <= 100);
        assert_eq!(result["total_checks"], 6);
    }

    #[test]
    fn test_get_readiness_score_failing_site() {
        let checks = seed_data();
        let site = s1();
        let result = get_readiness_score(&checks, &site).unwrap();
        let score = result["readiness_score_pct"].as_u64().unwrap();
        assert!(score < 60);
    }

    #[test]
    fn test_get_site_report_first_site() {
        let checks = seed_data();
        let site = s0();
        let result = get_site_report(&checks, &site).unwrap();
        assert_eq!(result["site"], site);
        assert!(!result["overall_status"].as_str().unwrap().is_empty());
        assert_eq!(result["checks"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn test_get_failing_checks_has_entries() {
        let checks = seed_data();
        let result = get_failing_checks(&checks).unwrap();
        assert!(result["failing_count"].as_u64().unwrap() > 0);
        assert!(!result["failing_checks"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_get_sites_returns_configured_count() {
        let checks = seed_data();
        let result = get_sites(&checks).unwrap();
        let site_list = result["sites"].as_array().unwrap();
        assert_eq!(site_list.len(), 3);
    }

    #[test]
    fn test_check_switchports_greenfield_not_checked() {
        let checks = seed_data();
        let site = s2();
        let result = check_switchports(&checks, &site).unwrap();
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
        let checks = seed_data();
        let site = s2();
        let result = get_readiness_score(&checks, &site).unwrap();
        let score = result["readiness_score_pct"].as_u64().unwrap();
        assert!(score < 100);
        assert_eq!(result["not_checked"], 2);
    }
}
