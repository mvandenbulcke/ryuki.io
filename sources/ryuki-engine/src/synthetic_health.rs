use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use uuid::Uuid;

fn seeded_u64(seed: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    Utc::now().timestamp_millis().hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckType {
    Http,
    Tcp,
    Dns,
    Certificate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckResultStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthCheck {
    pub id: String,
    pub name: String,
    pub check_type: CheckType,
    pub endpoint: String,
    pub expected_status: u16,
    pub expected_body_contains: Option<String>,
    pub interval_seconds: u32,
    pub site: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    pub id: String,
    pub check_id: String,
    pub status: CheckResultStatus,
    pub latency_ms: u64,
    pub message: String,
    pub executed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardSummary {
    pub site: String,
    pub total_checks: usize,
    pub passing: usize,
    pub failing: usize,
    pub avg_latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutageEntry {
    pub check_id: String,
    pub check_name: String,
    pub check_type: String,
    pub endpoint: String,
    pub last_result: CheckResult,
    pub failing_since: String,
    pub message: String,
}

fn seed_checks() -> Vec<HealthCheck> {
    vec![
        HealthCheck {
            id: Uuid::new_v4().to_string(),
            name: "portal-web-endpoint".into(),
            check_type: CheckType::Http,
            endpoint: "portal.ryuki.io".into(),
            expected_status: 200,
            expected_body_contains: Some("Ryuki Infrastructure Platform".into()),
            interval_seconds: 60,
            site: "DEFRA".into(),
            enabled: true,
        },
        HealthCheck {
            id: Uuid::new_v4().to_string(),
            name: "api-health-endpoint".into(),
            check_type: CheckType::Http,
            endpoint: "api.ryuki.io".into(),
            expected_status: 200,
            expected_body_contains: None,
            interval_seconds: 30,
            site: "DEFRA".into(),
            enabled: true,
        },
        HealthCheck {
            id: Uuid::new_v4().to_string(),
            name: "payment-dns-resolution".into(),
            check_type: CheckType::Dns,
            endpoint: "payment-service.ryuki.io".into(),
            expected_status: 0,
            expected_body_contains: None,
            interval_seconds: 120,
            site: "DEFRA".into(),
            enabled: true,
        },
        HealthCheck {
            id: Uuid::new_v4().to_string(),
            name: "db-tcp-connectivity".into(),
            check_type: CheckType::Tcp,
            endpoint: "db.ryuki.io:5432".into(),
            expected_status: 0,
            expected_body_contains: None,
            interval_seconds: 30,
            site: "GBLON".into(),
            enabled: true,
        },
        HealthCheck {
            id: Uuid::new_v4().to_string(),
            name: "api-cert-expiry".into(),
            check_type: CheckType::Certificate,
            endpoint: "api.ryuki.io:443".into(),
            expected_status: 0,
            expected_body_contains: None,
            interval_seconds: 3600,
            site: "GBLON".into(),
            enabled: true,
        },
    ]
}

static CHECK_STORE: std::sync::LazyLock<Mutex<Vec<HealthCheck>>> =
    std::sync::LazyLock::new(|| Mutex::new(seed_checks()));

static RESULT_STORE: std::sync::LazyLock<Mutex<Vec<CheckResult>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

pub fn run_check(check_id: &str) -> CheckResult {
    let store = CHECK_STORE.lock().unwrap();
    let check = store
        .iter()
        .find(|c| c.id == check_id && c.enabled)
        .cloned();

    let (status, latency_ms, message) = match check {
        Some(ref c) => {
            let latency = (seeded_u64(&c.id) % 200) + 1;
            let pass = seeded_u64(&format!("pass-{}", c.id)) % 100 > 15;
            if pass {
                (
                    CheckResultStatus::Pass,
                    latency,
                    format!(
                        "DRY-RUN: {} check {} against {} passed - mock latency {}ms",
                        match c.check_type {
                            CheckType::Http => "HTTP",
                            CheckType::Tcp => "TCP",
                            CheckType::Dns => "DNS",
                            CheckType::Certificate => "Certificate",
                        },
                        c.name,
                        c.endpoint,
                        latency,
                    ),
                )
            } else {
                (
                    CheckResultStatus::Fail,
                    latency + 500,
                    format!(
                        "DRY-RUN: {} check {} against {} returned simulated failure - mock latency {}ms",
                        match c.check_type {
                            CheckType::Http => "HTTP",
                            CheckType::Tcp => "TCP",
                            CheckType::Dns => "DNS",
                            CheckType::Certificate => "Certificate",
                        },
                        c.name,
                        c.endpoint,
                        latency + 500,
                    ),
                )
            }
        }
        None => (
            CheckResultStatus::Fail,
            0,
            format!(
                "DRY-RUN: Check {} not found or disabled. No live provider probe executed.",
                check_id
            ),
        ),
    };

    let result = CheckResult {
        id: Uuid::new_v4().to_string(),
        check_id: check_id.to_string(),
        status,
        latency_ms,
        message,
        executed_at: Utc::now().to_rfc3339(),
    };

    RESULT_STORE.lock().unwrap().push(result.clone());
    result
}

pub fn run_all_checks(site: &str) -> Vec<CheckResult> {
    let check_ids: Vec<String> = CHECK_STORE
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c.site == site && c.enabled)
        .map(|c| c.id.clone())
        .collect();

    check_ids.iter().map(|id| run_check(id)).collect()
}

pub fn get_check_status(check_id: &str) -> Option<CheckResult> {
    RESULT_STORE
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|r| r.check_id == check_id)
        .cloned()
}

pub fn get_dashboard(site: &str) -> DashboardSummary {
    let checks = CHECK_STORE.lock().unwrap();
    let results = RESULT_STORE.lock().unwrap();

    let site_checks: Vec<&HealthCheck> = checks
        .iter()
        .filter(|c| c.site == site && c.enabled)
        .collect();

    let total = site_checks.len();
    let mut passing = 0;
    let mut failing = 0;
    let mut total_latency = 0u64;
    let mut result_count = 0u64;

    for check in &site_checks {
        if let Some(latest) = results.iter().rev().find(|r| r.check_id == check.id) {
            total_latency += latest.latency_ms;
            result_count += 1;
            if latest.status == CheckResultStatus::Pass {
                passing += 1;
            } else {
                failing += 1;
            }
        }
        // checks without results yet are not counted in pass/fail
    }

    let avg_latency = total_latency.checked_div(result_count).unwrap_or(0);

    DashboardSummary {
        site: site.to_string(),
        total_checks: total,
        passing,
        failing,
        avg_latency_ms: avg_latency,
    }
}

pub fn get_outage_report(site: &str) -> Vec<OutageEntry> {
    let checks = CHECK_STORE.lock().unwrap();
    let results = RESULT_STORE.lock().unwrap();
    let now = Utc::now();
    let threshold = chrono::Duration::minutes(5);

    let mut outages = Vec::new();

    for check in checks.iter().filter(|c| c.site == site && c.enabled) {
        let recent_fails: Vec<&CheckResult> = results
            .iter()
            .rev()
            .filter(|r| r.check_id == check.id && r.status == CheckResultStatus::Fail)
            .collect();

        if let Some(first_fail) = recent_fails.last()
            && let Ok(executed) = chrono::DateTime::parse_from_rfc3339(&first_fail.executed_at)
        {
            let duration = now.signed_duration_since(executed);
            if duration > threshold {
                let check_type_str = match check.check_type {
                    CheckType::Http => "HTTP",
                    CheckType::Tcp => "TCP",
                    CheckType::Dns => "DNS",
                    CheckType::Certificate => "Certificate",
                };

                outages.push(OutageEntry {
                        check_id: check.id.clone(),
                        check_name: check.name.clone(),
                        check_type: check_type_str.to_string(),
                        endpoint: check.endpoint.clone(),
                        last_result: recent_fails.first().cloned().unwrap().clone(),
                        failing_since: first_fail.executed_at.clone(),
                        message: format!(
                            "DRY-RUN: Check {} has been failing since {}. No live provider actions taken.",
                            check.name, first_fail.executed_at
                        ),
                    });
            }
        }
    }

    outages
}

pub fn list_checks(site: Option<&str>) -> Vec<HealthCheck> {
    let store = CHECK_STORE.lock().unwrap();
    match site {
        Some(s) => store.iter().filter(|c| c.site == s).cloned().collect(),
        None => store.clone(),
    }
}

pub fn get_check(check_id: &str) -> Option<HealthCheck> {
    CHECK_STORE
        .lock()
        .unwrap()
        .iter()
        .find(|c| c.id == check_id)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_check_returns_result() {
        let checks = list_checks(None);
        let check = &checks[0];
        let result = run_check(&check.id);
        assert_eq!(result.check_id, check.id);
        assert!(!result.id.is_empty());
        assert!(!result.executed_at.is_empty());
        assert!(result.message.contains("DRY-RUN"));
        assert!(result.message.contains(&check.name));
    }

    #[test]
    fn test_run_check_not_found() {
        let result = run_check("nonexistent-id");
        assert_eq!(result.status, CheckResultStatus::Fail);
        assert!(result.message.contains("not found"));
        assert!(result.message.contains("DRY-RUN"));
    }

    #[test]
    fn test_run_all_checks_for_site() {
        let results = run_all_checks("DEFRA");
        assert!(!results.is_empty());
        for result in &results {
            assert!(result.message.contains("DRY-RUN"));
        }
    }

    #[test]
    fn test_get_check_status_retrieves_latest() {
        let checks = list_checks(None);
        let check = &checks[0];
        run_check(&check.id);
        let status = get_check_status(&check.id);
        assert!(status.is_some());
        assert_eq!(status.unwrap().check_id, check.id);
    }

    #[test]
    fn test_get_check_status_none_for_no_runs() {
        let status = get_check_status("never-run-id");
        assert!(status.is_none());
    }

    #[test]
    fn test_get_dashboard_returns_summary() {
        run_all_checks("DEFRA");
        let dashboard = get_dashboard("DEFRA");
        assert_eq!(dashboard.site, "DEFRA");
        assert!(dashboard.total_checks > 0);
        assert!(dashboard.passing + dashboard.failing <= dashboard.total_checks);
    }

    #[test]
    fn test_get_dashboard_empty_site() {
        let dashboard = get_dashboard("NONEXISTENT");
        assert_eq!(dashboard.total_checks, 0);
        assert_eq!(dashboard.passing, 0);
        assert_eq!(dashboard.failing, 0);
    }

    #[test]
    fn test_get_outage_report_no_runs() {
        let outages = get_outage_report("DEFRA");
        // With no results or fresh results, nothing should be in outage
        assert!(outages.is_empty());
    }

    #[test]
    fn test_seed_checks_have_all_types() {
        let checks = list_checks(None);
        assert!(checks.len() >= 5);
        let types: std::collections::HashSet<String> = checks
            .iter()
            .map(|c| serde_json::to_string(&c.check_type).unwrap())
            .collect();
        assert!(types.len() >= 4);
    }

    #[test]
    fn test_run_check_messages_no_secrets() {
        let checks = list_checks(None);
        for check in &checks {
            let result = run_check(&check.id);
            let lower = result.message.to_lowercase();
            assert!(!lower.contains("password"));
            assert!(!lower.contains("secret"));
            assert!(!lower.contains("token"));
            assert!(!lower.contains("credential"));
            assert!(!lower.contains("api_key"));
        }
    }

    #[test]
    fn test_no_live_endpoint_urls_in_seed_data() {
        let checks = list_checks(None);
        for check in &checks {
            assert!(!check.endpoint.contains("://"));
        }
    }

    #[test]
    fn test_health_check_serialization() {
        let checks = list_checks(None);
        let check = &checks[0];
        let json = serde_json::to_string(check).expect("serialize");
        let deserialized: HealthCheck = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(check.id, deserialized.id);
        assert_eq!(check.name, deserialized.name);
        assert_eq!(check.site, deserialized.site);
    }
}
