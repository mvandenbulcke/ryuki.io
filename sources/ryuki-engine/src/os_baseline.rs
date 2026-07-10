use crate::site_registry;
use serde::{Deserialize, Serialize};

fn active_site_code(site: &str) -> Result<String, String> {
    let code = site_registry::normalize_site_code_for_lookup(site)?;
    if site_registry::is_valid_site(&code) {
        Ok(code)
    } else {
        Err(format!("Unknown site: {code}"))
    }
}

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
    pub site: String,
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

/// Returns all compliance results for a single server, from the provided slice.
pub fn check_server_compliance<'r>(
    results: &'r [BaselineResult],
    server_name: &str,
) -> Vec<&'r BaselineResult> {
    results
        .iter()
        .filter(|r| r.server_name == server_name)
        .collect()
}

/// Summarises compliance for all servers in `site`, from the provided slices.
///
/// Returns `Err` when `site` is not active in the governed registry.
pub fn check_site_compliance(
    results: &[BaselineResult],
    site: &str,
) -> Result<SiteComplianceSummary, String> {
    let site = active_site_code(site)?;

    let site_results: Vec<BaselineResult> =
        results.iter().filter(|r| r.site == site).cloned().collect();

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
        site,
        total_servers: server_names.len(),
        total_checks,
        compliant_checks,
        noncompliant_checks,
        compliance_percentage,
        servers: site_results,
    })
}

/// Returns all noncompliant servers in `site`, with their critical failures.
///
/// Returns `Err` when `site` is not active in the governed registry.
pub fn get_noncompliant(
    checks: &[BaselineCheck],
    results: &[BaselineResult],
    site: &str,
) -> Result<Vec<NoncompliantServer>, String> {
    let site = active_site_code(site)?;

    let critical_check_ids: std::collections::HashSet<&str> = checks
        .iter()
        .filter(|c| c.severity == BaselineSeverity::Critical)
        .map(|c| c.id.as_str())
        .collect();

    let site_noncompliant: Vec<&BaselineResult> = results
        .iter()
        .filter(|r| r.site == site && !r.compliant)
        .collect();

    let server_names: std::collections::HashSet<String> = site_noncompliant
        .iter()
        .map(|r| r.server_name.clone())
        .collect();

    let mut servers = Vec::new();
    for server_name in server_names {
        let failures: Vec<BaselineResult> = site_noncompliant
            .iter()
            .filter(|r| r.server_name == server_name)
            .map(|r| (*r).clone())
            .collect();
        let critical_failures: Vec<BaselineResult> = failures
            .iter()
            .filter(|r| critical_check_ids.contains(r.check_id.as_str()))
            .cloned()
            .collect();
        servers.push(NoncompliantServer {
            server_name,
            site: site.clone(),
            critical_failures,
            total_failures: failures.len(),
        });
    }

    Ok(servers)
}

/// Shapes repo trend points into `ComplianceTrendPoint` values.
///
/// The handler calls `compliance_trend_for_site` on the repo, then passes the
/// resulting `(month, pct)` pairs here so the engine stays I/O-free.
/// When no DB is available the handler passes an empty slice; this function
/// returns an empty Vec (honest real data, not the old hardcoded 6-month vector).
pub fn get_compliance_trend(
    trend_points: &[(String, f64)],
    site: &str,
) -> Result<Vec<ComplianceTrendPoint>, String> {
    let _site = active_site_code(site)?;

    Ok(trend_points
        .iter()
        .map(|(month, pct)| ComplianceTrendPoint {
            month: month.clone(),
            compliance_percentage: *pct,
        })
        .collect())
}

/// Returns coverage information for every check across the provided results.
pub fn get_check_coverage(
    checks: &[BaselineCheck],
    results: &[BaselineResult],
) -> Vec<CheckCoverage> {
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

/// Computes the remediated `BaselineResult` for a given (server, check_id) pair.
///
/// Returns `None` when the check is not found in `checks`.
/// The caller is responsible for persisting the returned row via the repo.
pub fn remediate_finding(
    checks: &[BaselineCheck],
    server_name: &str,
    check_id: &str,
    last_checked: String,
) -> Option<BaselineResult> {
    let check = checks.iter().find(|c| c.id == check_id)?;
    Some(BaselineResult {
        server_name: server_name.to_string(),
        check_id: check_id.to_string(),
        compliant: true,
        actual_value: check.expected_value.clone(),
        last_checked,
        site: String::new(), // filled in by the handler from the DB row
    })
}

// ─── Test fixtures ────────────────────────────────────────────────────────────

#[cfg(test)]
pub fn seeded_checks() -> Vec<BaselineCheck> {
    vec![
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
    ]
}

#[cfg(test)]
pub fn seeded_results() -> Vec<BaselineResult> {
    use chrono::Utc;
    let now = Utc::now().to_rfc3339();
    let checks = seeded_checks();
    let servers = [
        ("srv-defra-dc01", "DEFRA"),
        ("srv-defra-web01", "DEFRA"),
        ("srv-gblon-db01", "GBLON"),
        ("srv-frpar-app01", "FRPAR"),
        ("srv-nlams-fs01", "NLAMS"),
    ];
    let mut results = Vec::new();
    for (server_name, site) in &servers {
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
                site: (*site).into(),
            });
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_server_compliance_returns_results() {
        let checks = seeded_checks();
        let results = seeded_results();
        let server_results = check_server_compliance(&results, "srv-defra-dc01");
        assert_eq!(server_results.len(), checks.len());
        assert!(server_results.iter().all(|r| r.compliant));
    }

    #[test]
    fn test_check_site_compliance_valid_site() {
        let results = seeded_results();
        let summary = check_site_compliance(&results, "DEFRA").unwrap();
        assert_eq!(summary.site, "DEFRA");
        assert_eq!(summary.total_servers, 2);
        assert_eq!(summary.total_checks, 8);
        assert!(summary.compliance_percentage > 0.0);
    }

    #[test]
    fn test_check_site_compliance_unknown_site() {
        let results = seeded_results();
        assert!(check_site_compliance(&results, "UNKNOWN").is_err());
    }

    #[test]
    fn test_get_noncompliant_returns_failures() {
        let checks = seeded_checks();
        let results = seeded_results();
        let noncompliant = get_noncompliant(&checks, &results, "GBLON").unwrap();
        let db_server = noncompliant
            .iter()
            .find(|s| s.server_name == "srv-gblon-db01");
        assert!(db_server.is_some());
        assert!(db_server.unwrap().total_failures > 0);
    }

    #[test]
    fn test_get_compliance_trend_hardcoded() {
        // With no DB points, returns empty (honest real data).
        let trend = get_compliance_trend(&[], "DEFRA").unwrap();
        assert!(trend.is_empty());
    }

    #[test]
    fn test_get_compliance_trend_with_points() {
        let points = vec![
            ("2026-01".to_string(), 72.5_f64),
            ("2026-02".to_string(), 75.0_f64),
        ];
        let trend = get_compliance_trend(&points, "DEFRA").unwrap();
        assert_eq!(trend.len(), 2);
        assert_eq!(trend[0].month, "2026-01");
        assert!((trend[0].compliance_percentage - 72.5).abs() < 0.01);
    }

    #[test]
    fn test_get_compliance_trend_unknown_site() {
        assert!(get_compliance_trend(&[], "UNKNOWN").is_err());
    }

    #[test]
    fn test_get_check_coverage() {
        let checks = seeded_checks();
        let results = seeded_results();
        let coverage = get_check_coverage(&checks, &results);
        assert_eq!(coverage.len(), 4);
        for c in &coverage {
            assert_eq!(c.applied_to.len(), 5);
        }
    }

    #[test]
    fn test_remediate_finding() {
        let checks = seeded_checks();
        let now = chrono::Utc::now().to_rfc3339();
        let result = remediate_finding(&checks, "srv-frpar-app01", "bc-001", now.clone());
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.compliant);
        assert_eq!(r.check_id, "bc-001");
        assert_eq!(r.actual_value, "running");
    }

    #[test]
    fn test_remediate_finding_unknown_check() {
        let checks = seeded_checks();
        let now = chrono::Utc::now().to_rfc3339();
        let result = remediate_finding(&checks, "srv-defra-dc01", "bc-999", now);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_noncompliant_empty_for_compliant_site() {
        let checks = seeded_checks();
        let results = seeded_results();
        let noncompliant = get_noncompliant(&checks, &results, "DEFRA").unwrap();
        let dc_server = noncompliant
            .iter()
            .find(|s| s.server_name == "srv-defra-dc01");
        assert!(dc_server.is_none());
    }
}
