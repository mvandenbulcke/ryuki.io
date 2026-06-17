//! Pure engine for repository capacity forecasting.
//!
//! All functions are pure over `&[Repository]` (or individual `&Repository`).
//! No global state lives here — the in-memory `OnceLock` has been removed.
//! Callers (handlers in `contracts.rs`) supply the data from the repository
//! layer.
//!
//! # Derived fields
//! `days_until_full` and `status` are NOT stored on `Repository`; they are
//! COMPUTED by `repo_days` / `repo_status` on every call.  The persistence
//! layer writes denormalized copies of these computed values to the
//! `backup_repositories` table, but the engine struct intentionally omits them
//! to keep the truth source (total, used, growth) as the single-source-of-truth.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ─── Domain types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub id: String,
    pub name: String,
    pub repository_type: RepositoryType,
    pub site: String,
    pub total_capacity_tb: f64,
    pub used_capacity_tb: f64,
    pub growth_rate_gb_per_day: f64,
    pub last_forecast: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RepositoryType {
    StoreOnce,
    DataDomain,
    ObjectStorage,
    HardenedLinux,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CapacityStatus {
    Healthy,
    Warning,
    Critical,
}

// ─── Pure computation helpers ─────────────────────────────────────────────────

fn compute_status(days_until_full: f64) -> CapacityStatus {
    if days_until_full < 7.0 {
        CapacityStatus::Critical
    } else if days_until_full < 30.0 {
        CapacityStatus::Warning
    } else {
        CapacityStatus::Healthy
    }
}

fn effective_days_until_full(total_tb: f64, used_tb: f64, growth_gb_per_day: f64) -> f64 {
    let free_tb = total_tb - used_tb;
    if growth_gb_per_day <= 0.0 {
        999.0
    } else {
        ((free_tb * 1000.0) / growth_gb_per_day * 10.0).round() / 10.0
    }
}

/// Compute the days until this repository is full given its current state.
pub fn repo_days(repo: &Repository) -> f64 {
    effective_days_until_full(
        repo.total_capacity_tb,
        repo.used_capacity_tb,
        repo.growth_rate_gb_per_day,
    )
}

/// Compute the capacity status for this repository.
pub fn repo_status(repo: &Repository) -> CapacityStatus {
    compute_status(repo_days(repo))
}

fn repo_to_json(repo: &Repository) -> Value {
    json!({
        "id": repo.id,
        "name": repo.name,
        "repository_type": repo.repository_type,
        "site": repo.site,
        "total_capacity_tb": repo.total_capacity_tb,
        "used_capacity_tb": repo.used_capacity_tb,
        "growth_rate_gb_per_day": repo.growth_rate_gb_per_day,
        "days_until_full": repo_days(repo),
        "last_forecast": repo.last_forecast,
        "status": repo_status(repo)
    })
}

// ─── Pure domain functions ────────────────────────────────────────────────────

/// Return all repositories for the given site as a JSON value.
/// Returns an empty repositories list (not an error) when no rows match.
pub fn get_repositories(repos: &[Repository], site: &str) -> Value {
    let site_repos: Vec<&Repository> = repos.iter().filter(|r| r.site == site).collect();

    let repo_list: Vec<Value> = site_repos.iter().map(|r| repo_to_json(r)).collect();

    json!({
        "site": site,
        "repository_count": repo_list.len(),
        "repositories": repo_list
    })
}

/// Return the capacity forecast for a single repository.
///
/// Returns `None` when `repository_id` does not match any repo in `repos`.
pub fn forecast_capacity(repos: &[Repository], repository_id: &str, days: u32) -> Option<Value> {
    let repo = repos.iter().find(|r| r.id == repository_id)?;

    let projected_used_gb =
        repo.used_capacity_tb * 1000.0 + repo.growth_rate_gb_per_day * days as f64;
    let projected_used_tb = (projected_used_gb / 1000.0 * 100.0).round() / 100.0;
    let projected_pct = if repo.total_capacity_tb > 0.0 {
        (projected_used_tb / repo.total_capacity_tb * 100.0 * 10.0).round() / 10.0
    } else {
        0.0
    };
    let projected_days = effective_days_until_full(
        repo.total_capacity_tb,
        projected_used_tb,
        repo.growth_rate_gb_per_day,
    );
    let projected_status = compute_status(projected_days);

    Some(json!({
        "repository_id": repo.id,
        "name": repo.name,
        "site": repo.site,
        "repository_type": repo.repository_type,
        "forecast_days": days,
        "current": {
            "used_capacity_tb": repo.used_capacity_tb,
            "utilization_pct": ((repo.used_capacity_tb / repo.total_capacity_tb * 100.0) * 10.0).round() / 10.0,
            "days_until_full": repo_days(repo),
            "status": repo_status(repo)
        },
        "projected": {
            "used_capacity_tb": projected_used_tb,
            "utilization_pct": projected_pct,
            "days_until_full": projected_days,
            "status": projected_status
        }
    }))
}

/// Return all at-risk repositories (days_until_full < 30.0).
pub fn get_at_risk(repos: &[Repository]) -> Value {
    let at_risk: Vec<Value> = repos
        .iter()
        .filter(|r| repo_days(r) < 30.0)
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "site": r.site,
                "repository_type": r.repository_type,
                "days_until_full": repo_days(r),
                "status": repo_status(r),
                "growth_rate_gb_per_day": r.growth_rate_gb_per_day,
                "used_capacity_tb": r.used_capacity_tb,
                "total_capacity_tb": r.total_capacity_tb
            })
        })
        .collect();

    json!({
        "at_risk_count": at_risk.len(),
        "repositories": at_risk
    })
}

/// Return the capacity report for all repositories at the given site.
/// When `site` is empty, aggregate over all repositories.
pub fn get_capacity_report(repos: &[Repository], site: &str) -> Value {
    let site_repos: Vec<&Repository> = if site.is_empty() {
        repos.iter().collect()
    } else {
        repos.iter().filter(|r| r.site == site).collect()
    };

    let total_tb: f64 = site_repos.iter().map(|r| r.total_capacity_tb).sum();
    let used_tb: f64 = site_repos.iter().map(|r| r.used_capacity_tb).sum();
    let overall_pct = if total_tb > 0.0 {
        (used_tb / total_tb * 100.0 * 10.0).round() / 10.0
    } else {
        0.0
    };
    let critical_count = site_repos
        .iter()
        .filter(|r| repo_status(r) == CapacityStatus::Critical)
        .count();
    let warning_count = site_repos
        .iter()
        .filter(|r| repo_status(r) == CapacityStatus::Warning)
        .count();
    let healthy_count = site_repos
        .iter()
        .filter(|r| repo_status(r) == CapacityStatus::Healthy)
        .count();
    let total_growth_gb_per_day: f64 = site_repos.iter().map(|r| r.growth_rate_gb_per_day).sum();

    let repo_list: Vec<Value> = site_repos.iter().map(|r| repo_to_json(r)).collect();

    json!({
        "site": site,
        "total_capacity_tb": (total_tb * 100.0).round() / 100.0,
        "used_capacity_tb": (used_tb * 100.0).round() / 100.0,
        "utilization_pct": overall_pct,
        "repository_count": site_repos.len(),
        "healthy_count": healthy_count,
        "warning_count": warning_count,
        "critical_count": critical_count,
        "total_growth_gb_per_day": (total_growth_gb_per_day * 100.0).round() / 100.0,
        "repositories": repo_list
    })
}

/// Return recommendations for a single repository.
///
/// Returns `None` when `repository_id` does not match any repo in `repos`.
pub fn get_recommendations(repos: &[Repository], repository_id: &str) -> Option<Value> {
    let repo = repos.iter().find(|r| r.id == repository_id)?;

    let mut recommendations: Vec<Value> = Vec::new();
    let days_left = repo_days(repo);
    let utilization_pct = if repo.total_capacity_tb > 0.0 {
        repo.used_capacity_tb / repo.total_capacity_tb * 100.0
    } else {
        0.0
    };

    if days_left < 7.0 {
        recommendations.push(json!({
            "priority": "critical",
            "action": "Add storage capacity immediately",
            "detail": format!(
                "{} TB free ({}% utilization), {} days remaining at current growth rate",
                ((repo.total_capacity_tb - repo.used_capacity_tb) * 100.0).round() / 100.0,
                (utilization_pct * 10.0).round() / 10.0,
                days_left
            ),
            "estimated_effort": "emergency",
            "lead_time_days": 0
        }));
    } else if days_left < 30.0 {
        recommendations.push(json!({
            "priority": "high",
            "action": "Add storage capacity within 2 weeks",
            "detail": format!(
                "{} days until full at {} GB/day growth rate",
                days_left,
                repo.growth_rate_gb_per_day
            ),
            "estimated_effort": "planned",
            "lead_time_days": 14
        }));
    }

    if repo.growth_rate_gb_per_day > 3.0 {
        recommendations.push(json!({
            "priority": "medium",
            "action": "Adjust backup retention policy",
            "detail": format!(
                "Growth rate of {} GB/day is above threshold — review retention settings to reduce churn",
                repo.growth_rate_gb_per_day
            ),
            "estimated_effort": "policy-review",
            "lead_time_days": 7
        }));
    }

    if utilization_pct > 70.0 && repo.repository_type != RepositoryType::ObjectStorage {
        recommendations.push(json!({
            "priority": "medium",
            "action": "Tier older backups to object storage",
            "detail": "Archive backups older than 90 days to object storage tier to free primary capacity",
            "estimated_effort": "configuration",
            "lead_time_days": 14
        }));
    }

    if utilization_pct > 85.0 {
        recommendations.push(json!({
            "priority": "high",
            "action": "Enable deduplication and compression review",
            "detail": "Verify deduplication ratios and compression settings are optimal",
            "estimated_effort": "operational-review",
            "lead_time_days": 3
        }));
    }

    if repo.repository_type == RepositoryType::HardenedLinux && days_left > 90.0 {
        recommendations.push(json!({
            "priority": "low",
            "action": "Review immutability period alignment",
            "detail": "With ample headroom, consider extending immutability window for compliance",
            "estimated_effort": "compliance-review",
            "lead_time_days": 30
        }));
    }

    Some(json!({
        "repository_id": repo.id,
        "name": repo.name,
        "repository_type": repo.repository_type,
        "site": repo.site,
        "utilization_pct": (utilization_pct * 10.0).round() / 10.0,
        "days_until_full": days_left,
        "recommendation_count": recommendations.len(),
        "recommendations": recommendations
    }))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_repos() -> Vec<Repository> {
        vec![
            Repository {
                id: "repo-001".into(),
                name: "defra-storeonce-01".into(),
                repository_type: RepositoryType::StoreOnce,
                site: "DEFRA".into(),
                total_capacity_tb: 200.0,
                used_capacity_tb: 198.74,
                growth_rate_gb_per_day: 200.0,
                last_forecast: "2026-06-11T08:00:00Z".into(),
            },
            Repository {
                id: "repo-002".into(),
                name: "defra-datadomain-01".into(),
                repository_type: RepositoryType::DataDomain,
                site: "DEFRA".into(),
                total_capacity_tb: 150.0,
                used_capacity_tb: 147.0,
                growth_rate_gb_per_day: 210.0,
                last_forecast: "2026-06-11T08:00:00Z".into(),
            },
            Repository {
                id: "repo-003".into(),
                name: "gblon-storeonce-01".into(),
                repository_type: RepositoryType::StoreOnce,
                site: "GBLON".into(),
                total_capacity_tb: 250.0,
                used_capacity_tb: 230.0,
                growth_rate_gb_per_day: 600.0,
                last_forecast: "2026-06-11T08:00:00Z".into(),
            },
            Repository {
                id: "repo-004".into(),
                name: "gblon-hardened-01".into(),
                repository_type: RepositoryType::HardenedLinux,
                site: "GBLON".into(),
                total_capacity_tb: 500.0,
                used_capacity_tb: 120.0,
                growth_rate_gb_per_day: 4200.0,
                last_forecast: "2026-06-11T08:00:00Z".into(),
            },
        ]
    }

    #[test]
    fn test_get_repositories_defra() {
        let repos = seed_repos();
        let result = get_repositories(&repos, "DEFRA");
        assert_eq!(result["site"], "DEFRA");
        assert_eq!(result["repository_count"].as_u64().unwrap(), 2);
        let repo_list = result["repositories"].as_array().unwrap();
        assert_eq!(repo_list.len(), 2);
    }

    #[test]
    fn test_get_repositories_gblon() {
        let repos = seed_repos();
        let result = get_repositories(&repos, "GBLON");
        assert_eq!(result["site"], "GBLON");
        assert_eq!(result["repository_count"].as_u64().unwrap(), 2);
    }

    #[test]
    fn test_get_repositories_unknown_site_returns_empty() {
        let repos = seed_repos();
        let result = get_repositories(&repos, "NONEXISTENT");
        assert_eq!(result["repository_count"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_forecast_capacity() {
        let repos = seed_repos();
        let result = forecast_capacity(&repos, "repo-002", 30).unwrap();
        assert_eq!(result["repository_id"], "repo-002");
        assert_eq!(result["forecast_days"].as_u64().unwrap(), 30);
        let projected_pct = result["projected"]["utilization_pct"].as_f64().unwrap();
        let current_pct = result["current"]["utilization_pct"].as_f64().unwrap();
        assert!(
            projected_pct >= current_pct,
            "projected utilization ({}%) must be >= current ({}%)",
            projected_pct,
            current_pct
        );
    }

    #[test]
    fn test_forecast_capacity_not_found() {
        let repos = seed_repos();
        assert!(forecast_capacity(&repos, "repo-999", 30).is_none());
    }

    #[test]
    fn test_get_at_risk() {
        let repos = seed_repos();
        let result = get_at_risk(&repos);
        let at_risk = result["repositories"].as_array().unwrap();
        assert!(
            !at_risk.is_empty(),
            "should have at least one at-risk repository"
        );
        assert!(
            at_risk.iter().any(|r| r["id"] == "repo-001"),
            "repo-001 should always be at risk"
        );
    }

    #[test]
    fn test_get_capacity_report() {
        let repos = seed_repos();
        let result = get_capacity_report(&repos, "DEFRA");
        assert_eq!(result["site"], "DEFRA");
        assert!(result["total_capacity_tb"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn test_get_recommendations_not_found() {
        let repos = seed_repos();
        assert!(get_recommendations(&repos, "repo-999").is_none());
    }

    #[test]
    fn test_get_recommendations_healthy() {
        let repos = seed_repos();
        // repo-004 is healthy
        let result = get_recommendations(&repos, "repo-004").unwrap();
        assert!(result["recommendation_count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_repo_days_zero_growth() {
        let repo = Repository {
            id: "r".into(),
            name: "test".into(),
            repository_type: RepositoryType::StoreOnce,
            site: "X".into(),
            total_capacity_tb: 100.0,
            used_capacity_tb: 50.0,
            growth_rate_gb_per_day: 0.0,
            last_forecast: "2026-06-11T08:00:00Z".into(),
        };
        assert_eq!(repo_days(&repo), 999.0);
        assert_eq!(repo_status(&repo), CapacityStatus::Healthy);
    }
}
