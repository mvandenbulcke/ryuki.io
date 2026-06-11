use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize)]
struct Repository {
    id: String,
    name: String,
    repository_type: RepositoryType,
    site: String,
    total_capacity_tb: f64,
    used_capacity_tb: f64,
    growth_rate_gb_per_day: f64,
    days_until_full: f64,
    last_forecast: String,
    status: CapacityStatus,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum RepositoryType {
    StoreOnce,
    DataDomain,
    ObjectStorage,
    HardenedLinux,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum CapacityStatus {
    Healthy,
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
struct UsageHistoryPoint {
    date: String,
    used_tb: f64,
}

type RepoStore = Vec<Repository>;

static REPO_STORE: OnceLock<Mutex<RepoStore>> = OnceLock::new();

fn repo_store() -> &'static Mutex<RepoStore> {
    REPO_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> RepoStore {
    vec![
        Repository {
            id: "repo-001".into(),
            name: "love-storeonce-01".into(),
            repository_type: RepositoryType::StoreOnce,
            site: "LOVE".into(),
            total_capacity_tb: 200.0,
            used_capacity_tb: 178.0,
            growth_rate_gb_per_day: 3.5,
            days_until_full: 6.3,
            last_forecast: "2026-06-11T08:00:00Z".into(),
            status: CapacityStatus::Critical,
        },
        Repository {
            id: "repo-002".into(),
            name: "love-datadomain-01".into(),
            repository_type: RepositoryType::DataDomain,
            site: "LOVE".into(),
            total_capacity_tb: 150.0,
            used_capacity_tb: 120.0,
            growth_rate_gb_per_day: 2.1,
            days_until_full: 14.3,
            last_forecast: "2026-06-11T08:00:00Z".into(),
            status: CapacityStatus::Warning,
        },
        Repository {
            id: "repo-003".into(),
            name: "bur1-storeonce-01".into(),
            repository_type: RepositoryType::StoreOnce,
            site: "BUR1".into(),
            total_capacity_tb: 250.0,
            used_capacity_tb: 190.0,
            growth_rate_gb_per_day: 1.8,
            days_until_full: 33.3,
            last_forecast: "2026-06-11T08:00:00Z".into(),
            status: CapacityStatus::Healthy,
        },
        Repository {
            id: "repo-004".into(),
            name: "bur1-hardened-01".into(),
            repository_type: RepositoryType::HardenedLinux,
            site: "BUR1".into(),
            total_capacity_tb: 500.0,
            used_capacity_tb: 120.0,
            growth_rate_gb_per_day: 4.2,
            days_until_full: 90.5,
            last_forecast: "2026-06-11T08:00:00Z".into(),
            status: CapacityStatus::Healthy,
        },
    ]
}

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

pub fn get_repositories(site: &str) -> Result<Value, String> {
    let store = repo_store().lock().map_err(|e| e.to_string())?;
    let repos: Vec<&Repository> = store.iter().filter(|r| r.site == site).collect();

    if repos.is_empty() {
        return Err(format!("Site '{}' not found", site));
    }

    let repo_list: Vec<Value> = repos
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "repository_type": r.repository_type,
                "site": r.site,
                "total_capacity_tb": r.total_capacity_tb,
                "used_capacity_tb": r.used_capacity_tb,
                "growth_rate_gb_per_day": r.growth_rate_gb_per_day,
                "days_until_full": r.days_until_full,
                "last_forecast": r.last_forecast,
                "status": r.status
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "repository_count": repo_list.len(),
        "repositories": repo_list
    }))
}

pub fn update_usage(repository_id: &str, used_tb: f64) -> Result<Value, String> {
    let mut store = repo_store().lock().map_err(|e| e.to_string())?;
    let repo = store
        .iter_mut()
        .find(|r| r.id == repository_id)
        .ok_or_else(|| format!("Repository '{}' not found", repository_id))?;

    repo.used_capacity_tb = used_tb;
    repo.days_until_full = effective_days_until_full(repo.total_capacity_tb, used_tb, repo.growth_rate_gb_per_day);
    repo.status = compute_status(repo.days_until_full);
    repo.last_forecast = chrono::Utc::now().to_rfc3339();

    Ok(json!({
        "source": "dry-run",
        "repository_id": repo.id,
        "name": repo.name,
        "used_capacity_tb": repo.used_capacity_tb,
        "days_until_full": repo.days_until_full,
        "status": repo.status
    }))
}

pub fn forecast_capacity(repository_id: &str, days: u32) -> Result<Value, String> {
    let store = repo_store().lock().map_err(|e| e.to_string())?;
    let repo = store
        .iter()
        .find(|r| r.id == repository_id)
        .ok_or_else(|| format!("Repository '{}' not found", repository_id))?;

    let projected_used_gb = repo.used_capacity_tb * 1000.0 + repo.growth_rate_gb_per_day * days as f64;
    let projected_used_tb = (projected_used_gb / 1000.0 * 100.0).round() / 100.0;
    let projected_pct = if repo.total_capacity_tb > 0.0 {
        (projected_used_tb / repo.total_capacity_tb * 100.0 * 10.0).round() / 10.0
    } else {
        0.0
    };
    let projected_days_until_full = if repo.growth_rate_gb_per_day > 0.0 {
        ((repo.total_capacity_tb * 1000.0 - projected_used_tb * 1000.0) / repo.growth_rate_gb_per_day * 10.0).round() / 10.0
    } else {
        999.0
    };
    let projected_status = compute_status(projected_days_until_full);

    Ok(json!({
        "source": "dry-run",
        "repository_id": repo.id,
        "name": repo.name,
        "site": repo.site,
        "repository_type": repo.repository_type,
        "forecast_days": days,
        "current": {
            "used_capacity_tb": repo.used_capacity_tb,
            "utilization_pct": ((repo.used_capacity_tb / repo.total_capacity_tb * 100.0) * 10.0).round() / 10.0,
            "days_until_full": repo.days_until_full,
            "status": repo.status
        },
        "projected": {
            "used_capacity_tb": projected_used_tb,
            "utilization_pct": projected_pct,
            "days_until_full": projected_days_until_full,
            "status": projected_status
        }
    }))
}

pub fn get_at_risk() -> Result<Value, String> {
    let store = repo_store().lock().map_err(|e| e.to_string())?;
    let at_risk: Vec<&Repository> = store.iter().filter(|r| r.days_until_full < 30.0).collect();

    let repo_list: Vec<Value> = at_risk
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "site": r.site,
                "repository_type": r.repository_type,
                "days_until_full": r.days_until_full,
                "status": r.status,
                "growth_rate_gb_per_day": r.growth_rate_gb_per_day,
                "used_capacity_tb": r.used_capacity_tb,
                "total_capacity_tb": r.total_capacity_tb
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "at_risk_count": repo_list.len(),
        "repositories": repo_list
    }))
}

pub fn get_capacity_report(site: &str) -> Result<Value, String> {
    let store = repo_store().lock().map_err(|e| e.to_string())?;
    let repos: Vec<&Repository> = store.iter().filter(|r| r.site == site).collect();

    if repos.is_empty() {
        return Err(format!("Site '{}' not found", site));
    }

    let total_tb: f64 = repos.iter().map(|r| r.total_capacity_tb).sum();
    let used_tb: f64 = repos.iter().map(|r| r.used_capacity_tb).sum();
    let overall_pct = if total_tb > 0.0 {
        (used_tb / total_tb * 100.0 * 10.0).round() / 10.0
    } else {
        0.0
    };
    let critical_count = repos.iter().filter(|r| r.status == CapacityStatus::Critical).count();
    let warning_count = repos.iter().filter(|r| r.status == CapacityStatus::Warning).count();
    let healthy_count = repos.iter().filter(|r| r.status == CapacityStatus::Healthy).count();
    let total_growth_gb_per_day: f64 = repos.iter().map(|r| r.growth_rate_gb_per_day).sum();

    let repo_list: Vec<Value> = repos
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "repository_type": r.repository_type,
                "total_capacity_tb": r.total_capacity_tb,
                "used_capacity_tb": r.used_capacity_tb,
                "utilization_pct": ((r.used_capacity_tb / r.total_capacity_tb * 100.0) * 10.0).round() / 10.0,
                "days_until_full": r.days_until_full,
                "status": r.status
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "total_capacity_tb": (total_tb * 100.0).round() / 100.0,
        "used_capacity_tb": (used_tb * 100.0).round() / 100.0,
        "utilization_pct": overall_pct,
        "repository_count": repos.len(),
        "healthy_count": healthy_count,
        "warning_count": warning_count,
        "critical_count": critical_count,
        "total_growth_gb_per_day": (total_growth_gb_per_day * 100.0).round() / 100.0,
        "repositories": repo_list
    }))
}

pub fn get_trend(repository_id: &str, months: u32) -> Result<Value, String> {
    let store = repo_store().lock().map_err(|e| e.to_string())?;
    let repo = store
        .iter()
        .find(|r| r.id == repository_id)
        .ok_or_else(|| format!("Repository '{}' not found", repository_id))?;

    let now = chrono::Utc::now();
    let data_points: Vec<Value> = (0..=(months * 4))
        .map(|i| {
            let date = now - chrono::Duration::weeks(i as i64);
            let weeks_ago = i as f64;
            let jitter = (weeks_ago * 0.3).sin() * repo.total_capacity_tb * 0.02;
            let simulated_used = (repo.used_capacity_tb
                - (weeks_ago * repo.growth_rate_gb_per_day * 7.0 / 1000.0)
                + jitter)
                .max(0.0);

            json!({
                "date": date.format("%Y-%m-%d").to_string(),
                "used_capacity_tb": (simulated_used * 100.0).round() / 100.0,
                "utilization_pct": ((simulated_used / repo.total_capacity_tb * 100.0) * 10.0).round() / 10.0
            })
        })
        .rev()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "repository_id": repo.id,
        "name": repo.name,
        "site": repo.site,
        "repository_type": repo.repository_type,
        "months": months,
        "growth_rate_gb_per_day": repo.growth_rate_gb_per_day,
        "data_points": data_points
    }))
}

pub fn get_recommendations(repository_id: &str) -> Result<Value, String> {
    let store = repo_store().lock().map_err(|e| e.to_string())?;
    let repo = store
        .iter()
        .find(|r| r.id == repository_id)
        .ok_or_else(|| format!("Repository '{}' not found", repository_id))?;

    let mut recommendations: Vec<Value> = Vec::new();
    let utilization_pct = if repo.total_capacity_tb > 0.0 {
        repo.used_capacity_tb / repo.total_capacity_tb * 100.0
    } else {
        0.0
    };

    if repo.days_until_full < 7.0 {
        recommendations.push(json!({
            "priority": "critical",
            "action": "Add storage capacity immediately",
            "detail": format!(
                "{} TB free ({}%), {} days remaining at current growth rate",
                (repo.total_capacity_tb - repo.used_capacity_tb * 100.0).round() / 100.0,
                (100.0 - utilization_pct * 10.0).round() / 10.0,
                repo.days_until_full
            ),
            "estimated_effort": "emergency",
            "lead_time_days": 0
        }));
    } else if repo.days_until_full < 30.0 {
        recommendations.push(json!({
            "priority": "high",
            "action": "Add storage capacity within 2 weeks",
            "detail": format!(
                "{} days until full at {} GB/day growth rate",
                repo.days_until_full,
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

    if repo.repository_type == RepositoryType::HardenedLinux && repo.days_until_full > 90.0 {
        recommendations.push(json!({
            "priority": "low",
            "action": "Review immutability period alignment",
            "detail": "With ample headroom, consider extending immutability window for compliance",
            "estimated_effort": "compliance-review",
            "lead_time_days": 30
        }));
    }

    Ok(json!({
        "source": "dry-run",
        "repository_id": repo.id,
        "name": repo.name,
        "repository_type": repo.repository_type,
        "site": repo.site,
        "utilization_pct": (utilization_pct * 10.0).round() / 10.0,
        "days_until_full": repo.days_until_full,
        "recommendation_count": recommendations.len(),
        "recommendations": recommendations
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_repositories_love() {
        let result = get_repositories("LOVE").unwrap();
        assert_eq!(result["site"], "LOVE");
        assert_eq!(result["repository_count"].as_u64().unwrap(), 2);
        let repos = result["repositories"].as_array().unwrap();
        assert_eq!(repos.len(), 2);
    }

    #[test]
    fn test_get_repositories_bur1() {
        let result = get_repositories("BUR1").unwrap();
        assert_eq!(result["site"], "BUR1");
        assert_eq!(result["repository_count"].as_u64().unwrap(), 2);
    }

    #[test]
    fn test_update_usage() {
        let result = update_usage("repo-001", 185.0).unwrap();
        assert_eq!(result["repository_id"], "repo-001");
        assert_eq!(result["used_capacity_tb"].as_f64().unwrap(), 185.0);
        assert!(result["days_until_full"].as_f64().unwrap() < 5.0);
        assert_eq!(result["status"], "critical");
    }

    #[test]
    fn test_forecast_capacity() {
        let result = forecast_capacity("repo-002", 30).unwrap();
        assert_eq!(result["repository_id"], "repo-002");
        assert_eq!(result["forecast_days"].as_u64().unwrap(), 30);
        let projected_pct = result["projected"]["utilization_pct"].as_f64().unwrap();
        let current_pct = result["current"]["utilization_pct"].as_f64().unwrap();
        assert!(projected_pct > current_pct);
    }

    #[test]
    fn test_get_at_risk() {
        let result = get_at_risk().unwrap();
        let repos = result["repositories"].as_array().unwrap();
        assert!(repos.len() >= 2);
        assert!(repos.iter().any(|r| r["id"] == "repo-001"));
        assert!(repos.iter().any(|r| r["id"] == "repo-002"));
    }

    #[test]
    fn test_get_capacity_report() {
        let result = get_capacity_report("LOVE").unwrap();
        assert_eq!(result["site"], "LOVE");
        assert!(result["total_capacity_tb"].as_f64().unwrap() > 0.0);
        assert!(result["critical_count"].as_u64().unwrap() >= 1);
        assert!(result["warning_count"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_get_trend() {
        let result = get_trend("repo-003", 3).unwrap();
        assert_eq!(result["months"].as_u64().unwrap(), 3);
        let points = result["data_points"].as_array().unwrap();
        assert_eq!(points.len(), 13); // 3 months * 4 + 1
        assert!(points[0]["date"].as_str().is_some());
    }

    #[test]
    fn test_get_recommendations() {
        let result = get_recommendations("repo-001").unwrap();
        assert!(result["recommendation_count"].as_u64().unwrap() > 0);
        let recs = result["recommendations"].as_array().unwrap();
        assert!(recs[0]["priority"].as_str().is_some());
        assert!(recs[0]["action"].as_str().is_some());
    }

    #[test]
    fn test_get_recommendations_healthy() {
        let result = get_recommendations("repo-004").unwrap();
        assert!(result["recommendation_count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_site_not_found() {
        assert!(get_repositories("NONEXISTENT").is_err());
        assert!(get_capacity_report("NONEXISTENT").is_err());
    }

    #[test]
    fn test_repository_not_found() {
        assert!(update_usage("repo-999", 100.0).is_err());
        assert!(forecast_capacity("repo-999", 30).is_err());
        assert!(get_trend("repo-999", 3).is_err());
        assert!(get_recommendations("repo-999").is_err());
    }

    #[test]
    fn test_forecast_capacity_bur1() {
        let result = forecast_capacity("repo-003", 90).unwrap();
        assert_eq!(result["forecast_days"].as_u64().unwrap(), 90);
        assert!(result["projected"]["utilization_pct"].as_f64().unwrap() > 0.0);
    }
}
