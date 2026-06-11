use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineCheck {
    pub id: String,
    pub check_name: String,
    pub category: BaselineCategory,
    pub expected_value: String,
    pub severity: BaselineSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BaselineCategory {
    Security,
    Patching,
    Monitoring,
    Agent,
    Tools,
    Configuration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BaselineSeverity {
    Critical,
    High,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineResult {
    pub server_name: String,
    pub check_id: String,
    pub compliant: bool,
    pub actual_value: String,
    pub last_checked: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteComplianceSummary {
    pub site: String,
    pub total_servers: usize,
    pub total_checks: usize,
    pub compliant_checks: usize,
    pub noncompliant_checks: usize,
    pub compliance_percentage: f64,
    pub servers: Vec<BaselineResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoncompliantServer {
    pub server_name: String,
    pub site: String,
    pub critical_failures: Vec<BaselineResult>,
    pub total_failures: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTrendPoint {
    pub month: String,
    pub compliance_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckCoverage {
    pub check_id: String,
    pub check_name: String,
    pub category: BaselineCategory,
    pub severity: BaselineSeverity,
    pub applied_to: Vec<String>,
}

static CHECK_STORE: OnceLock<Mutex<Vec<BaselineCheck>>> = OnceLock::new();
static RESULT_STORE: OnceLock<Mutex<Vec<BaselineResult>>> = OnceLock::new();

fn ensure_seeded() {
    let _ = CHECK_STORE.get_or_init(|| {
        Mutex::new(vec![
            BaselineCheck {
                id: "bc-001".into(),
                check_name: "CrowdStrike Falcon Agent".into(),
                category: BaselineCategory::Security,
                expected_value: "running".into(),
                severity: BaselineSeverity::Critical,
            },
            BaselineCheck {
                id: "bc-002".into(),
                check_name: "VMware Tools".into(),
                category: BaselineCategory::Tools,
                expected_value: "running, current".into(),
                severity: BaselineSeverity::High,
            },
            BaselineCheck {
                id: "bc-003".into(),
                check_name: "Zabbix Agent".into(),
                category: BaselineCategory::Monitoring,
                expected_value: "running, v6.4+".into(),
                severity: BaselineSeverity::High,
            },
            BaselineCheck {
                id: "bc-004".into(),
                check_name: "Windows Firewall".into(),
                category: BaselineCategory::Configuration,
                expected_value: "enabled, domain profile".into(),
                severity: BaselineSeverity::Critical,
            },
        ])
    });
    let _ = RESULT_STORE.get_or_init(|| {
        let mut results = Vec::new();
        let servers = [
            ("srv-defra-dc01", "DEFRA"),
            ("srv-defra-web01", "DEFRA"),
            ("srv-gblon-db01", "GBLON"),
            ("srv-frpar-app01", "FRPAR"),
            ("srv-nlams-fs01", "NLAMS"),
        ];
        let checks = CHECK_STORE.get().unwrap().lock().unwrap();
        let now = Utc::now().to_rfc3339();
        for (server_name, _site) in &servers {
            for check in checks.iter() {
                let compliant = !(server_name.contains("db") && check.id == "bc-004"
                    || server_name.contains("app") && check.id == "bc-001"
                    || server_name.contains("fs") && check.id == "bc-003");
                let actual_value = if compliant {
                    check.expected_value.clone()
                } else {
                    match check.id.as_str() {
                        "bc-001" => "not installed".into(),
                        "bc-003" => "stopped".into(),
                        "bc-004" => "disabled".into(),
                        _ => "unknown".into(),
                    }
                };
                results.push(BaselineResult {
                    server_name: (*server_name).into(),
                    check_id: check.id.clone(),
                    compliant,
                    actual_value,
                    last_checked: now.clone(),
                });
            }
        }
        Mutex::new(results)
    });
}

fn check_store() -> &'static Mutex<Vec<BaselineCheck>> {
    ensure_seeded();
    CHECK_STORE.get().unwrap()
}

fn result_store() -> &'static Mutex<Vec<BaselineResult>> {
    ensure_seeded();
    RESULT_STORE.get().unwrap()
}

fn server_site(server_name: &str) -> &str {
    match server_name {
        n if n.contains("defra") => "DEFRA",
        n if n.contains("gblon") => "GBLON",
        n if n.contains("frpar") => "FRPAR",
        n if n.contains("nlams") => "NLAMS",
        n if n.contains("deber") => "DEBER",
        _ => "UNKNOWN",
    }
}

pub fn check_server_compliance(server_name: &str) -> Vec<BaselineResult> {
    let results = result_store().lock().unwrap();
    results
        .iter()
        .filter(|r| r.server_name == server_name)
        .cloned()
        .collect()
}

pub fn check_site_compliance(site: &str) -> Result<SiteComplianceSummary, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }
    let results = result_store().lock().unwrap();

    let site_results: Vec<BaselineResult> = results
        .iter()
        .filter(|r| server_site(&r.server_name) == site)
        .cloned()
        .collect();

    let server_names: std::collections::HashSet<String> =
        site_results.iter().map(|r| r.server_name.clone()).collect();

    let total_checks = site_results.len();
    let compliant_checks = site_results.iter().filter(|r| r.compliant).count();
    let noncompliant_checks = total_checks - compliant_checks;

    let compliance_percentage = if total_checks > 0 {
        (compliant_checks as f64 / total_checks as f64) * 100.0
    } else {
        0.0
    };

    Ok(SiteComplianceSummary {
        site: site.to_string(),
        total_servers: server_names.len(),
        total_checks,
        compliant_checks,
        noncompliant_checks,
        compliance_percentage,
        servers: site_results,
    })
}

pub fn get_noncompliant(site: &str) -> Result<Vec<NoncompliantServer>, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }
    let results = result_store().lock().unwrap();
    let checks = check_store().lock().unwrap();

    let critical_check_ids: std::collections::HashSet<String> = checks
        .iter()
        .filter(|c| c.severity == BaselineSeverity::Critical)
        .map(|c| c.id.clone())
        .collect();

    let site_results: Vec<&BaselineResult> = results
        .iter()
        .filter(|r| server_site(&r.server_name) == site && !r.compliant)
        .collect();

    let server_names: std::collections::HashSet<String> =
        site_results.iter().map(|r| r.server_name.clone()).collect();

    let mut servers = Vec::new();
    for server_name in server_names {
        let failures: Vec<BaselineResult> = site_results
            .iter()
            .filter(|r| r.server_name == server_name)
            .cloned()
            .cloned()
            .collect();
        let critical_failures: Vec<BaselineResult> = failures
            .iter()
            .filter(|r| critical_check_ids.contains(&r.check_id))
            .cloned()
            .collect();
        servers.push(NoncompliantServer {
            server_name,
            site: site.to_string(),
            critical_failures,
            total_failures: failures.len(),
        });
    }

    Ok(servers)
}

pub fn get_compliance_trend(site: &str) -> Result<Vec<ComplianceTrendPoint>, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    Ok(vec![
        ComplianceTrendPoint {
            month: "2026-01".into(),
            compliance_percentage: 72.5,
        },
        ComplianceTrendPoint {
            month: "2026-02".into(),
            compliance_percentage: 75.0,
        },
        ComplianceTrendPoint {
            month: "2026-03".into(),
            compliance_percentage: 78.3,
        },
        ComplianceTrendPoint {
            month: "2026-04".into(),
            compliance_percentage: 81.0,
        },
        ComplianceTrendPoint {
            month: "2026-05".into(),
            compliance_percentage: 85.0,
        },
        ComplianceTrendPoint {
            month: "2026-06".into(),
            compliance_percentage: 88.5,
        },
    ])
}

pub fn get_check_coverage() -> Vec<CheckCoverage> {
    let checks = check_store().lock().unwrap();
    let results = result_store().lock().unwrap();

    checks
        .iter()
        .map(|check| {
            let applied_to: Vec<String> = results
                .iter()
                .filter(|r| r.check_id == check.id)
                .map(|r| r.server_name.clone())
                .collect();
            CheckCoverage {
                check_id: check.id.clone(),
                check_name: check.check_name.clone(),
                category: check.category.clone(),
                severity: check.severity.clone(),
                applied_to,
            }
        })
        .collect()
}

pub fn remediate_finding(server_name: &str, check_id: &str) -> Result<Value, String> {
    let mut results = result_store().lock().unwrap();

    let idx = results
        .iter()
        .position(|r| r.server_name == server_name && r.check_id == check_id)
        .ok_or_else(|| {
            format!(
                "No finding for check {} on server {}",
                check_id, server_name
            )
        })?;

    let check = {
        let checks = check_store().lock().unwrap();
        checks.iter().find(|c| c.id == check_id).cloned()
    };

    let now = Utc::now().to_rfc3339();
    results[idx].compliant = true;
    results[idx].actual_value = check
        .map(|c| c.expected_value)
        .unwrap_or_else(|| "remediated".into());
    results[idx].last_checked = now.clone();

    Ok(json!({
        "source": "dry-run",
        "server_name": server_name,
        "check_id": check_id,
        "remediated": true,
        "remediated_at": now,
        "dry_run": true
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_server_compliance_returns_results() {
        let results = check_server_compliance("srv-defra-dc01");
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|r| r.compliant));
    }

    #[test]
    fn test_check_site_compliance_valid_site() {
        let summary = check_site_compliance("DEFRA").unwrap();
        assert_eq!(summary.site, "DEFRA");
        assert_eq!(summary.total_servers, 2);
        assert_eq!(summary.total_checks, 8);
        assert!(summary.compliance_percentage > 0.0);
    }

    #[test]
    fn test_check_site_compliance_unknown_site() {
        assert!(check_site_compliance("UNKNOWN").is_err());
    }

    #[test]
    fn test_get_noncompliant_returns_failures() {
        let noncompliant = get_noncompliant("GBLON").unwrap();
        let db_server = noncompliant
            .iter()
            .find(|s| s.server_name == "srv-gblon-db01");
        assert!(db_server.is_some());
        assert!(db_server.unwrap().total_failures > 0);
    }

    #[test]
    fn test_get_compliance_trend() {
        let trend = get_compliance_trend("DEFRA").unwrap();
        assert_eq!(trend.len(), 6);
        assert!(trend.last().unwrap().compliance_percentage > 80.0);
    }

    #[test]
    fn test_get_check_coverage() {
        let coverage = get_check_coverage();
        assert_eq!(coverage.len(), 4);
        for c in &coverage {
            assert_eq!(c.applied_to.len(), 5);
        }
    }

    #[test]
    fn test_remediate_finding() {
        let result = remediate_finding("srv-frpar-app01", "bc-001").unwrap();
        assert_eq!(result["remediated"], true);
        assert_eq!(result["check_id"], "bc-001");
        assert_eq!(result["dry_run"], true);

        let updated = check_server_compliance("srv-frpar-app01");
        let fixed = updated.iter().find(|r| r.check_id == "bc-001").unwrap();
        assert!(fixed.compliant);
    }

    #[test]
    fn test_remediate_finding_not_found() {
        assert!(remediate_finding("nonexistent", "bc-001").is_err());
    }

    #[test]
    fn test_get_noncompliant_empty_for_compliant_site() {
        let noncompliant = get_noncompliant("DEFRA").unwrap();
        let dc_server = noncompliant
            .iter()
            .find(|s| s.server_name == "srv-defra-dc01");
        assert!(dc_server.is_none());
    }

    #[test]
    fn test_server_site_mapping() {
        assert_eq!(server_site("srv-defra-dc01"), "DEFRA");
        assert_eq!(server_site("srv-gblon-db01"), "GBLON");
        assert_eq!(server_site("srv-frpar-app01"), "FRPAR");
        assert_eq!(server_site("srv-nlams-fs01"), "NLAMS");
        assert_eq!(server_site("unknown-server"), "UNKNOWN");
    }
}
