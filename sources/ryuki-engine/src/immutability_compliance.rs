use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RepositoryType {
    StoreOnce,
    HardenedLinux,
    ObjectStorage,
}

impl std::fmt::Display for RepositoryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepositoryType::StoreOnce => write!(f, "StoreOnce"),
            RepositoryType::HardenedLinux => write!(f, "HardenedLinux"),
            RepositoryType::ObjectStorage => write!(f, "ObjectStorage"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStatus {
    Compliant,
    AtRisk,
    NonCompliant,
}

impl std::fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceStatus::Compliant => write!(f, "Compliant"),
            ComplianceStatus::AtRisk => write!(f, "AtRisk"),
            ComplianceStatus::NonCompliant => write!(f, "NonCompliant"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutabilityCheck {
    pub id: String,
    pub repository_name: String,
    pub repository_type: RepositoryType,
    pub site: String,
    pub immutability_enabled: bool,
    pub retention_lock_set: bool,
    pub min_retention_days: u32,
    pub last_verified: String,
    pub status: ComplianceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub site: String,
    pub total_repositories: usize,
    pub compliant: usize,
    pub at_risk: usize,
    pub non_compliant: usize,
    pub checks: Vec<ImmutabilityCheck>,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub repository_id: String,
    pub repository_name: String,
    pub current_status: ComplianceStatus,
    pub issues: Vec<String>,
    pub suggested_actions: Vec<String>,
    pub priority: String,
    pub estimated_effort: String,
}

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

/// Test fixture: returns a set of seed repositories for use in unit tests.
/// Production code loads from the database via the repo layer.
#[cfg(test)]
pub fn seed_repositories() -> Vec<ImmutabilityCheck> {
    let now = chrono::Utc::now();
    vec![
        ImmutabilityCheck {
            id: "imm-00000000-0000-0000-0000-000000000001".into(),
            repository_name: "repo-defra-storeonce-01".into(),
            repository_type: RepositoryType::StoreOnce,
            site: "DEFRA".into(),
            immutability_enabled: true,
            retention_lock_set: true,
            min_retention_days: 90,
            last_verified: (now - chrono::Duration::days(2)).to_rfc3339(),
            status: ComplianceStatus::Compliant,
        },
        ImmutabilityCheck {
            id: "imm-00000000-0000-0000-0000-000000000002".into(),
            repository_name: "repo-gblon-hlr-01".into(),
            repository_type: RepositoryType::HardenedLinux,
            site: "GBLON".into(),
            immutability_enabled: true,
            retention_lock_set: false,
            min_retention_days: 30,
            last_verified: (now - chrono::Duration::days(7)).to_rfc3339(),
            status: ComplianceStatus::AtRisk,
        },
        ImmutabilityCheck {
            id: "imm-00000000-0000-0000-0000-000000000003".into(),
            repository_name: "repo-frpar-objstore-01".into(),
            repository_type: RepositoryType::ObjectStorage,
            site: "FRPAR".into(),
            immutability_enabled: false,
            retention_lock_set: false,
            min_retention_days: 0,
            last_verified: (now - chrono::Duration::days(14)).to_rfc3339(),
            status: ComplianceStatus::NonCompliant,
        },
        ImmutabilityCheck {
            id: "imm-00000000-0000-0000-0000-000000000004".into(),
            repository_name: "repo-nlams-storeonce-02".into(),
            repository_type: RepositoryType::StoreOnce,
            site: "NLAMS".into(),
            immutability_enabled: true,
            retention_lock_set: true,
            min_retention_days: 60,
            last_verified: (now - chrono::Duration::days(1)).to_rfc3339(),
            status: ComplianceStatus::Compliant,
        },
    ]
}

/// Check immutability status for a single repository. Looks up the check by
/// `repository_id` in the provided slice, updates `last_verified` to now, and
/// recomputes `status` based on `immutability_enabled`.
///
/// Returns `Err` when the slice contains no matching id, or when `repository_id`
/// is empty. The caller is responsible for loading the slice from the DB.
pub fn check_immutability(
    repository_id: &str,
    checks: &[ImmutabilityCheck],
) -> Result<ImmutabilityCheck, String> {
    if repository_id.is_empty() {
        return Err("repository_id cannot be empty".into());
    }
    let repo = checks
        .iter()
        .find(|r| r.id == repository_id)
        .ok_or_else(|| format!("Repository {} not found", repository_id))?;

    let mut updated = repo.clone();
    updated.last_verified = chrono::Utc::now().to_rfc3339();
    if !updated.immutability_enabled {
        updated.status = ComplianceStatus::NonCompliant;
    }

    Ok(updated)
}

/// Check retention lock status for a single repository. Looks up the check by
/// `repository_id` in the provided slice, updates `last_verified` to now, and
/// recomputes `status` based on `retention_lock_set` and `immutability_enabled`.
///
/// Returns `Err` when the slice contains no matching id, or when `repository_id`
/// is empty.
pub fn check_retention_lock(
    repository_id: &str,
    checks: &[ImmutabilityCheck],
) -> Result<ImmutabilityCheck, String> {
    if repository_id.is_empty() {
        return Err("repository_id cannot be empty".into());
    }
    let repo = checks
        .iter()
        .find(|r| r.id == repository_id)
        .ok_or_else(|| format!("Repository {} not found", repository_id))?;

    let mut updated = repo.clone();
    updated.last_verified = chrono::Utc::now().to_rfc3339();
    if !updated.retention_lock_set {
        updated.status = if updated.immutability_enabled {
            ComplianceStatus::AtRisk
        } else {
            ComplianceStatus::NonCompliant
        };
    }

    Ok(updated)
}

/// Check air-gap eligibility for a single repository. Looks up the check by
/// `repository_id` in the provided slice, updates `last_verified` to now, and
/// sets `status` to `AtRisk` when the repository type is not air-gap-eligible.
///
/// Returns `Err` when the slice contains no matching id, or when `repository_id`
/// is empty.
pub fn check_air_gap(
    repository_id: &str,
    checks: &[ImmutabilityCheck],
) -> Result<ImmutabilityCheck, String> {
    if repository_id.is_empty() {
        return Err("repository_id cannot be empty".into());
    }
    let repo = checks
        .iter()
        .find(|r| r.id == repository_id)
        .ok_or_else(|| format!("Repository {} not found", repository_id))?;

    let mut updated = repo.clone();
    updated.last_verified = chrono::Utc::now().to_rfc3339();

    let air_gap_eligible = matches!(
        updated.repository_type,
        RepositoryType::HardenedLinux | RepositoryType::ObjectStorage
    );
    if !air_gap_eligible {
        updated.status = ComplianceStatus::AtRisk;
    }

    Ok(updated)
}

/// Verify all repositories for the given `site`. Filters the provided slice to
/// the site's repositories, updates `last_verified` to now on each, and returns
/// the results.
///
/// Returns `Err` when `site` is empty or unknown.
pub fn verify_all_repositories(
    site: &str,
    checks: &[ImmutabilityCheck],
) -> Result<Vec<ImmutabilityCheck>, String> {
    if site.is_empty() {
        return Err("site cannot be empty".into());
    }
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let results: Vec<ImmutabilityCheck> = checks
        .iter()
        .filter(|r| r.site == site)
        .map(|r| {
            let mut updated = r.clone();
            updated.last_verified = chrono::Utc::now().to_rfc3339();
            updated
        })
        .collect();

    Ok(results)
}

/// Generate a compliance report for the given `site`. Filters the provided
/// slice to the site's repositories and aggregates counts by status.
///
/// Returns `Err` when `site` is empty or unknown.
pub fn get_compliance_report(
    site: &str,
    checks: &[ImmutabilityCheck],
) -> Result<ComplianceReport, String> {
    if site.is_empty() {
        return Err("site cannot be empty".into());
    }
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let site_repos: Vec<ImmutabilityCheck> =
        checks.iter().filter(|r| r.site == site).cloned().collect();

    let total = site_repos.len();
    let compliant = site_repos
        .iter()
        .filter(|r| r.status == ComplianceStatus::Compliant)
        .count();
    let non_compliant = site_repos
        .iter()
        .filter(|r| r.status == ComplianceStatus::NonCompliant)
        .count();
    let at_risk = site_repos
        .iter()
        .filter(|r| r.status == ComplianceStatus::AtRisk)
        .count();

    Ok(ComplianceReport {
        site: site.to_string(),
        total_repositories: total,
        compliant,
        at_risk,
        non_compliant,
        checks: site_repos,
        generated_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Return all non-compliant repositories from the provided slice.
pub fn get_noncompliant(checks: &[ImmutabilityCheck]) -> Vec<ImmutabilityCheck> {
    checks
        .iter()
        .filter(|r| r.status == ComplianceStatus::NonCompliant)
        .cloned()
        .collect()
}

/// Return all repositories at retention risk from the provided slice.
/// A repository is at risk when its status is not Compliant AND either
/// `min_retention_days < 30` or `retention_lock_set` is false.
pub fn get_retention_risk(checks: &[ImmutabilityCheck]) -> Vec<ImmutabilityCheck> {
    checks
        .iter()
        .filter(|r| {
            r.status != ComplianceStatus::Compliant
                && (r.min_retention_days < 30 || !r.retention_lock_set)
        })
        .cloned()
        .collect()
}

/// Generate a remediation plan for a single repository. Looks up the check by
/// `repository_id` in the provided slice and returns a plan describing the
/// issues and suggested actions.
///
/// Returns `Err` when the slice contains no matching id, or when `repository_id`
/// is empty.
pub fn get_remediation_plan(
    repository_id: &str,
    checks: &[ImmutabilityCheck],
) -> Result<RemediationPlan, String> {
    if repository_id.is_empty() {
        return Err("repository_id cannot be empty".into());
    }
    let repo = checks
        .iter()
        .find(|r| r.id == repository_id)
        .ok_or_else(|| format!("Repository {} not found", repository_id))?;

    let mut issues: Vec<String> = Vec::new();
    let mut actions: Vec<String> = Vec::new();

    if !repo.immutability_enabled {
        issues.push("Immutability is not enabled on this repository".into());
        actions.push(
            "DRY-RUN: Enable immutability on repository via provider console (simulated)".into(),
        );
    }
    if !repo.retention_lock_set {
        issues.push("Retention lock is not configured".into());
        actions.push(
            "DRY-RUN: Configure retention lock policy with minimum retention days (simulated)"
                .into(),
        );
    }
    if repo.min_retention_days < 30 {
        issues.push(format!(
            "Minimum retention ({}) days is below recommended threshold of 30 days",
            repo.min_retention_days
        ));
        actions.push(
            "DRY-RUN: Increase minimum retention period to at least 30 days (simulated)".into(),
        );
    }
    if matches!(repo.repository_type, RepositoryType::StoreOnce) {
        issues.push("StoreOnce repository — consider migration to Hardened Linux Repository for stronger immutability guarantees".into());
        actions.push(
            "DRY-RUN: Plan migration to Hardened Linux Repository per 2027 roadmap (simulated)"
                .into(),
        );
    }

    let priority = if repo.status == ComplianceStatus::NonCompliant {
        "P1 — Critical"
    } else {
        "P2 — Scheduled"
    }
    .into();

    Ok(RemediationPlan {
        repository_id: repo.id.clone(),
        repository_name: repo.repository_name.clone(),
        current_status: repo.status.clone(),
        issues,
        suggested_actions: actions,
        priority,
        estimated_effort: "2-4 hours per repository — DRY-RUN simulation only".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_immutability_compliant() {
        let repos = seed_repositories();
        let result = check_immutability("imm-00000000-0000-0000-0000-000000000001", &repos)
            .expect("should find repo");
        assert_eq!(result.repository_name, "repo-defra-storeonce-01");
        assert!(result.immutability_enabled);
        assert_eq!(result.status, ComplianceStatus::Compliant);
    }

    #[test]
    fn test_check_immutability_noncompliant() {
        let repos = seed_repositories();
        let result = check_immutability("imm-00000000-0000-0000-0000-000000000003", &repos)
            .expect("should find repo");
        assert_eq!(result.status, ComplianceStatus::NonCompliant);
    }

    #[test]
    fn test_check_immutability_not_found() {
        let repos = seed_repositories();
        let result = check_immutability("nonexistent-id", &repos);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_check_immutability_empty_id() {
        let repos = seed_repositories();
        let result = check_immutability("", &repos);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_retention_lock_at_risk() {
        let repos = seed_repositories();
        let result = check_retention_lock("imm-00000000-0000-0000-0000-000000000002", &repos)
            .expect("should find repo");
        assert!(!result.retention_lock_set);
        assert_eq!(result.status, ComplianceStatus::AtRisk);
    }

    #[test]
    fn test_check_air_gap_storeonce_at_risk() {
        let repos = seed_repositories();
        let result = check_air_gap("imm-00000000-0000-0000-0000-000000000001", &repos)
            .expect("should find repo");
        assert_eq!(result.status, ComplianceStatus::AtRisk);
    }

    #[test]
    fn test_verify_all_repositories_for_site() {
        let repos = seed_repositories();
        let results = verify_all_repositories("DEFRA", &repos).expect("should return results");
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.site == "DEFRA"));
    }

    #[test]
    fn test_verify_all_repositories_unknown_site() {
        let repos = seed_repositories();
        let result = verify_all_repositories("UNKNOWN", &repos);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown site"));
    }

    #[test]
    fn test_verify_all_repositories_empty_site() {
        let repos = seed_repositories();
        let result = verify_all_repositories("", &repos);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_compliance_report() {
        let repos = seed_repositories();
        let report = get_compliance_report("DEFRA", &repos).expect("should generate report");
        assert_eq!(report.site, "DEFRA");
        assert!(report.total_repositories > 0);
        assert!(
            report.compliant + report.at_risk + report.non_compliant == report.total_repositories
        );
    }

    #[test]
    fn test_get_compliance_report_unknown_site() {
        let repos = seed_repositories();
        let result = get_compliance_report("UNKNOWN", &repos);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_noncompliant() {
        let repos = seed_repositories();
        let noncompliant = get_noncompliant(&repos);
        assert!(!noncompliant.is_empty());
        assert!(
            noncompliant
                .iter()
                .all(|r| r.status == ComplianceStatus::NonCompliant)
        );
        let frpar_repo = noncompliant
            .iter()
            .find(|r| r.repository_name == "repo-frpar-objstore-01");
        assert!(frpar_repo.is_some());
    }

    #[test]
    fn test_get_retention_risk() {
        let repos = seed_repositories();
        let at_risk = get_retention_risk(&repos);
        assert!(!at_risk.is_empty());
        assert!(
            at_risk
                .iter()
                .all(|r| r.status != ComplianceStatus::Compliant)
        );
    }

    #[test]
    fn test_get_remediation_plan_noncompliant() {
        let repos = seed_repositories();
        let plan = get_remediation_plan("imm-00000000-0000-0000-0000-000000000003", &repos)
            .expect("should return plan");
        assert_eq!(plan.current_status, ComplianceStatus::NonCompliant);
        assert!(plan.priority.contains("P1"));
        assert!(!plan.issues.is_empty());
        assert!(!plan.suggested_actions.is_empty());
        assert!(
            plan.issues
                .iter()
                .any(|i| i.contains("Immutability is not enabled"))
        );
    }

    #[test]
    fn test_get_remediation_plan_at_risk() {
        let repos = seed_repositories();
        let plan = get_remediation_plan("imm-00000000-0000-0000-0000-000000000002", &repos)
            .expect("should return plan");
        assert_eq!(plan.current_status, ComplianceStatus::AtRisk);
        assert!(
            plan.issues
                .iter()
                .any(|i| i.contains("Retention lock is not configured"))
        );
    }

    #[test]
    fn test_get_remediation_plan_not_found() {
        let repos = seed_repositories();
        let result = get_remediation_plan("nonexistent-id", &repos);
        assert!(result.is_err());
    }

    #[test]
    fn test_seed_has_four_repositories() {
        let repos = seed_repositories();
        assert_eq!(repos.len(), 4);
        let sites: std::collections::HashSet<String> =
            repos.iter().map(|r| r.site.clone()).collect();
        assert!(sites.len() >= 3);
    }

    #[test]
    fn test_repository_type_display() {
        assert_eq!(RepositoryType::StoreOnce.to_string(), "StoreOnce");
        assert_eq!(RepositoryType::HardenedLinux.to_string(), "HardenedLinux");
        assert_eq!(RepositoryType::ObjectStorage.to_string(), "ObjectStorage");
    }

    #[test]
    fn test_compliance_status_display() {
        assert_eq!(ComplianceStatus::Compliant.to_string(), "Compliant");
        assert_eq!(ComplianceStatus::AtRisk.to_string(), "AtRisk");
        assert_eq!(ComplianceStatus::NonCompliant.to_string(), "NonCompliant");
    }
}
