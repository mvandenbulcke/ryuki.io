use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
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

/// Simulate running a single health check against the given `check` definition.
/// The function is pure: it takes the check by reference, generates a
/// pseudo-random pass/fail outcome, and returns a new `CheckResult` without
/// touching any store or performing I/O.
pub fn run_check(check: &HealthCheck) -> CheckResult {
    let latency = (seeded_u64(&check.id) % 200) + 1;
    let pass = seeded_u64(&format!("pass-{}", check.id)) % 100 > 15;

    let (status, latency_ms, message) = if pass {
        (
            CheckResultStatus::Pass,
            latency,
            format!(
                "DRY-RUN: {} check {} against {} passed - mock latency {}ms",
                match check.check_type {
                    CheckType::Http => "HTTP",
                    CheckType::Tcp => "TCP",
                    CheckType::Dns => "DNS",
                    CheckType::Certificate => "Certificate",
                },
                check.name,
                check.endpoint,
                latency,
            ),
        )
    } else {
        (
            CheckResultStatus::Fail,
            latency + 500,
            format!(
                "DRY-RUN: {} check {} against {} returned simulated failure - mock latency {}ms",
                match check.check_type {
                    CheckType::Http => "HTTP",
                    CheckType::Tcp => "TCP",
                    CheckType::Dns => "DNS",
                    CheckType::Certificate => "Certificate",
                },
                check.name,
                check.endpoint,
                latency + 500,
            ),
        )
    };

    CheckResult {
        id: Uuid::new_v4().to_string(),
        check_id: check.id.clone(),
        status,
        latency_ms,
        message,
        executed_at: Utc::now().to_rfc3339(),
    }
}

/// Run every check in `checks` and collect the results, preserving input order.
/// The function is pure: it delegates to [`run_check`] for each definition and
/// performs no I/O. The caller loads the check definitions (e.g. from the
/// database) and is responsible for persisting the returned results.
pub fn run_all_checks(checks: &[HealthCheck]) -> Vec<CheckResult> {
    checks.iter().map(run_check).collect()
}

/// Find the most recent result for `check_id` in the provided slice.
/// Returns `None` if no result exists for the given check id.
pub fn get_check_status<'a>(results: &'a [CheckResult], check_id: &str) -> Option<&'a CheckResult> {
    results.iter().rev().find(|r| r.check_id == check_id)
}

/// Compute a dashboard summary for `site` from the provided checks and their
/// latest results. Only enabled checks for the site are counted. Checks without
/// any result yet are excluded from pass/fail tallies.
pub fn get_dashboard(
    checks: &[HealthCheck],
    latest_results: &[CheckResult],
    site: &str,
) -> DashboardSummary {
    let site_checks: Vec<&HealthCheck> = checks
        .iter()
        .filter(|c| c.site == site && c.enabled)
        .collect();

    let total = site_checks.len();
    let mut passing = 0usize;
    let mut failing = 0usize;
    let mut total_latency = 0u64;
    let mut result_count = 0u64;

    for check in &site_checks {
        if let Some(latest) = latest_results.iter().find(|r| r.check_id == check.id) {
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

/// Compute outage entries for `site` from the provided checks and their FULL
/// result history. A check is reported as an outage only if it is CURRENTLY
/// failing (its most recent result is a `Fail`) AND the current consecutive
/// failure streak began more than 5 minutes ago. Callers must pass the complete
/// result history (not the latest result per check), or an outage that started
/// minutes ago would be missed.
pub fn get_outage_report(
    checks: &[HealthCheck],
    all_results: &[CheckResult],
    site: &str,
) -> Vec<OutageEntry> {
    let now = Utc::now();
    let threshold = chrono::Duration::minutes(5);

    let mut outages = Vec::new();

    for check in checks.iter().filter(|c| c.site == site && c.enabled) {
        // Parseable results for this check, newest first.
        let mut results: Vec<(&CheckResult, chrono::DateTime<Utc>)> = all_results
            .iter()
            .filter(|r| r.check_id == check.id)
            .filter_map(|r| {
                chrono::DateTime::parse_from_rfc3339(&r.executed_at)
                    .ok()
                    .map(|dt| (r, dt.with_timezone(&Utc)))
            })
            .collect();
        results.sort_by_key(|e| std::cmp::Reverse(e.1));

        // Only a check whose most recent result is a Fail is currently down.
        let Some((latest, _)) = results.first() else {
            continue;
        };
        if latest.status != CheckResultStatus::Fail {
            continue;
        }

        // Walk back through the consecutive failures to the start of the streak.
        let mut streak_start = &results[0];
        for entry in &results {
            if entry.0.status == CheckResultStatus::Fail {
                streak_start = entry;
            } else {
                break;
            }
        }

        if now.signed_duration_since(streak_start.1) > threshold {
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
                last_result: (*latest).clone(),
                failing_since: streak_start.0.executed_at.clone(),
                message: format!(
                    "DRY-RUN: Check {} has been failing since {}. No live provider actions taken.",
                    check.name, streak_start.0.executed_at
                ),
            });
        }
    }

    outages
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_check(id: &str, name: &str, site: &str) -> HealthCheck {
        HealthCheck {
            id: id.to_string(),
            name: name.to_string(),
            check_type: CheckType::Http,
            endpoint: "api.ryuki.io".to_string(),
            expected_status: 200,
            expected_body_contains: None,
            interval_seconds: 60,
            site: site.to_string(),
            enabled: true,
        }
    }

    #[test]
    fn test_run_check_returns_result() {
        let check = make_check("check-1", "portal-web-endpoint", "DEFRA");
        let result = run_check(&check);
        assert_eq!(result.check_id, check.id);
        assert!(!result.id.is_empty());
        assert!(!result.executed_at.is_empty());
        assert!(result.message.contains("DRY-RUN"));
        assert!(result.message.contains(&check.name));
    }

    #[test]
    fn test_run_check_messages_no_secrets() {
        let check = make_check("check-sec", "api-health-endpoint", "DEFRA");
        let result = run_check(&check);
        let lower = result.message.to_lowercase();
        assert!(!lower.contains("password"));
        assert!(!lower.contains("secret"));
        assert!(!lower.contains("token"));
        assert!(!lower.contains("credential"));
        assert!(!lower.contains("api_key"));
    }

    #[test]
    fn test_no_live_endpoint_urls_in_seed_data() {
        let checks = vec![
            make_check("c1", "portal", "DEFRA"),
            make_check("c2", "api", "GBLON"),
        ];
        for check in &checks {
            assert!(!check.endpoint.contains("://"));
        }
    }

    #[test]
    fn test_get_check_status_retrieves_latest() {
        let check = make_check("check-status", "portal", "DEFRA");
        let result = run_check(&check);
        let results = vec![result.clone()];
        let found = get_check_status(&results, &check.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().check_id, check.id);
    }

    #[test]
    fn test_get_check_status_none_for_no_runs() {
        let results: Vec<CheckResult> = vec![];
        let status = get_check_status(&results, "never-run-id");
        assert!(status.is_none());
    }

    #[test]
    fn test_get_dashboard_returns_summary() {
        let checks = vec![
            make_check("dash-1", "portal", "DEFRA"),
            make_check("dash-2", "api", "DEFRA"),
        ];
        let results: Vec<CheckResult> = checks.iter().map(run_check).collect();
        let dashboard = get_dashboard(&checks, &results, "DEFRA");
        assert_eq!(dashboard.site, "DEFRA");
        assert_eq!(dashboard.total_checks, 2);
        assert!(dashboard.passing + dashboard.failing <= dashboard.total_checks);
    }

    #[test]
    fn test_get_dashboard_empty_site() {
        let checks: Vec<HealthCheck> = vec![];
        let results: Vec<CheckResult> = vec![];
        let dashboard = get_dashboard(&checks, &results, "NONEXISTENT");
        assert_eq!(dashboard.total_checks, 0);
        assert_eq!(dashboard.passing, 0);
        assert_eq!(dashboard.failing, 0);
    }

    #[test]
    fn test_get_outage_report_no_runs() {
        let checks = vec![make_check("out-1", "portal", "DEFRA")];
        let results: Vec<CheckResult> = vec![];
        let outages = get_outage_report(&checks, &results, "DEFRA");
        assert!(outages.is_empty());
    }

    fn make_result(
        check_id: &str,
        status: CheckResultStatus,
        executed_at: chrono::DateTime<Utc>,
    ) -> CheckResult {
        CheckResult {
            id: format!("res-{}", executed_at.to_rfc3339()),
            check_id: check_id.to_string(),
            status,
            latency_ms: 10,
            message: "DRY-RUN".to_string(),
            executed_at: executed_at.to_rfc3339(),
        }
    }

    #[test]
    fn test_outage_reported_for_old_failing_streak() {
        let checks = vec![make_check("out-fail", "portal", "DEFRA")];
        let now = Utc::now();
        // Consecutive failures from 10 minutes ago through now.
        let results = vec![
            make_result(
                "out-fail",
                CheckResultStatus::Fail,
                now - chrono::Duration::minutes(10),
            ),
            make_result(
                "out-fail",
                CheckResultStatus::Fail,
                now - chrono::Duration::minutes(5),
            ),
            make_result(
                "out-fail",
                CheckResultStatus::Fail,
                now - chrono::Duration::seconds(30),
            ),
        ];
        let outages = get_outage_report(&checks, &results, "DEFRA");
        assert_eq!(outages.len(), 1, "an old failing streak must be reported");
        let since = chrono::DateTime::parse_from_rfc3339(&outages[0].failing_since)
            .expect("failing_since must be RFC-3339");
        assert!(
            (now - since.with_timezone(&Utc)).num_minutes() >= 9,
            "failing_since must be the oldest consecutive failure (~10 min ago)"
        );
    }

    #[test]
    fn test_no_outage_when_currently_passing() {
        let checks = vec![make_check("out-pass", "portal", "DEFRA")];
        let now = Utc::now();
        // Old failures, but the most recent result is a pass → healthy now.
        let results = vec![
            make_result(
                "out-pass",
                CheckResultStatus::Fail,
                now - chrono::Duration::minutes(20),
            ),
            make_result(
                "out-pass",
                CheckResultStatus::Fail,
                now - chrono::Duration::minutes(15),
            ),
            make_result(
                "out-pass",
                CheckResultStatus::Pass,
                now - chrono::Duration::minutes(1),
            ),
        ];
        let outages = get_outage_report(&checks, &results, "DEFRA");
        assert!(
            outages.is_empty(),
            "a currently-passing check must not be an outage"
        );
    }

    #[test]
    fn test_no_outage_when_streak_too_recent() {
        let checks = vec![make_check("out-new", "portal", "DEFRA")];
        let now = Utc::now();
        // Failing, but only for ~1 minute (< 5 min threshold).
        let results = vec![
            make_result(
                "out-new",
                CheckResultStatus::Pass,
                now - chrono::Duration::minutes(10),
            ),
            make_result(
                "out-new",
                CheckResultStatus::Fail,
                now - chrono::Duration::seconds(60),
            ),
        ];
        let outages = get_outage_report(&checks, &results, "DEFRA");
        assert!(
            outages.is_empty(),
            "a fresh failure (<5min) is not yet an outage"
        );
    }

    #[test]
    fn test_health_check_serialization() {
        let check = make_check("ser-1", "portal", "DEFRA");
        let json = serde_json::to_string(&check).expect("serialize");
        let deserialized: HealthCheck = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(check.id, deserialized.id);
        assert_eq!(check.name, deserialized.name);
        assert_eq!(check.site, deserialized.site);
    }
}
