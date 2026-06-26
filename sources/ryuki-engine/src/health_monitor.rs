use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HealthSource {
    Simulated,
    DependencyBacked,
    Unavailable,
}

impl std::fmt::Display for HealthSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthSource::Simulated => write!(f, "simulated"),
            HealthSource::DependencyBacked => write!(f, "dependency-backed"),
            HealthSource::Unavailable => write!(f, "unavailable"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthCheck {
    pub name: String,
    pub component: String,
    pub status: HealthStatus,
    pub source: HealthSource,
    pub last_check: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformHealth {
    pub overall_status: HealthStatus,
    pub components: Vec<String>,
    pub checks: Vec<HealthCheck>,
    pub timestamp: String,
    pub source: HealthSource,
}

pub fn run_all_checks() -> PlatformHealth {
    let checks = vec![
        check_api_health(),
        check_portal_health(),
        check_validator_health(),
        check_kubernetes_health(),
        check_vault_health(),
        check_database_health(),
    ];

    let components: Vec<String> = checks.iter().map(|c| c.component.clone()).collect();

    PlatformHealth {
        overall_status: aggregate_status(&checks),
        components,
        source: aggregate_source(&checks),
        checks,
        timestamp: Utc::now().to_rfc3339(),
    }
}

/// Aggregate per-check statuses into one verdict: healthy only when ALL are
/// healthy; any unhealthy wins; otherwise any degraded; else unknown.
fn aggregate_status(checks: &[HealthCheck]) -> HealthStatus {
    if checks.iter().all(|c| c.status == HealthStatus::Healthy) {
        HealthStatus::Healthy
    } else if checks.iter().any(|c| c.status == HealthStatus::Unhealthy) {
        HealthStatus::Unhealthy
    } else if checks.iter().any(|c| c.status == HealthStatus::Degraded) {
        HealthStatus::Degraded
    } else {
        HealthStatus::Unknown
    }
}

/// Aggregate per-check provenance: the board counts as `DependencyBacked` as
/// soon as ANY check is a real probe, so a consumer can tell a board that
/// contains live evidence apart from a fully simulated one.
fn aggregate_source(checks: &[HealthCheck]) -> HealthSource {
    if checks
        .iter()
        .any(|c| c.source == HealthSource::DependencyBacked)
    {
        HealthSource::DependencyBacked
    } else if checks.iter().any(|c| c.source == HealthSource::Simulated) {
        HealthSource::Simulated
    } else {
        HealthSource::Unavailable
    }
}

/// Build a database health check from a REAL connectivity probe result.
///
/// Unlike [`check_database_health`] — a dry-run placeholder that always reports
/// healthy — this reflects an actual dependency probe: `probe_ok` is true only
/// when the caller confirmed the database answered a liveness query. The source
/// is [`HealthSource::DependencyBacked`] so consumers can tell it apart from the
/// simulated checks, and a failed probe reports [`HealthStatus::Unhealthy`] —
/// never silently healthy.
pub fn database_health_from_probe(probe_ok: bool) -> HealthCheck {
    HealthCheck {
        name: "db-connection".into(),
        component: "platform-db".into(),
        status: if probe_ok {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        },
        source: HealthSource::DependencyBacked,
        last_check: Utc::now().to_rfc3339(),
        message: if probe_ok {
            "Database connectivity probe succeeded".into()
        } else {
            "Database connectivity probe FAILED - database is unreachable".into()
        },
    }
}

/// Replace the check whose component matches `replacement.component` with
/// `replacement`, then recompute the aggregate status and source. Used by the
/// API layer to fold a REAL dependency probe (e.g. live database connectivity)
/// into the otherwise-simulated board, so both the aggregate verdict and the
/// per-component gauge reflect reality for dependencies we can actually probe.
/// No-op for the component lookup if no check matches (aggregates still recomputed).
pub fn override_check(health: &mut PlatformHealth, replacement: HealthCheck) {
    if let Some(slot) = health
        .checks
        .iter_mut()
        .find(|c| c.component == replacement.component)
    {
        *slot = replacement;
    }
    health.overall_status = aggregate_status(&health.checks);
    health.source = aggregate_source(&health.checks);
}

pub fn check_api_health() -> HealthCheck {
    HealthCheck {
        name: "api-liveness".into(),
        component: "platform-api".into(),
        status: HealthStatus::Healthy,
        source: HealthSource::Simulated,
        last_check: Utc::now().to_rfc3339(),
        message: "DRY-RUN: API health check simulated - platform-api is healthy".into(),
    }
}

pub fn check_portal_health() -> HealthCheck {
    HealthCheck {
        name: "portal-liveness".into(),
        component: "portal-ui".into(),
        status: HealthStatus::Healthy,
        source: HealthSource::Simulated,
        last_check: Utc::now().to_rfc3339(),
        message: "DRY-RUN: Portal health check simulated - portal-ui is healthy".into(),
    }
}

pub fn check_validator_health() -> HealthCheck {
    HealthCheck {
        name: "validator-readiness".into(),
        component: "platform-validator".into(),
        status: HealthStatus::Healthy,
        source: HealthSource::Simulated,
        last_check: Utc::now().to_rfc3339(),
        message: "DRY-RUN: Validator health check simulated - all validators pass".into(),
    }
}

pub fn check_kubernetes_health() -> HealthCheck {
    HealthCheck {
        name: "kubernetes-components".into(),
        component: "kubernetes".into(),
        status: HealthStatus::Healthy,
        source: HealthSource::Simulated,
        last_check: Utc::now().to_rfc3339(),
        message: "DRY-RUN: Kubernetes health check simulated - all components healthy".into(),
    }
}

pub fn check_vault_health() -> HealthCheck {
    HealthCheck {
        name: "vault-seal-status".into(),
        component: "platform-vault".into(),
        status: HealthStatus::Healthy,
        source: HealthSource::Simulated,
        last_check: Utc::now().to_rfc3339(),
        message: "DRY-RUN: Vault health check simulated - vault is unsealed and healthy".into(),
    }
}

pub fn check_database_health() -> HealthCheck {
    HealthCheck {
        name: "db-connection".into(),
        component: "platform-db".into(),
        status: HealthStatus::Healthy,
        source: HealthSource::Simulated,
        last_check: Utc::now().to_rfc3339(),
        message: "DRY-RUN: Database health check simulated - database is responsive".into(),
    }
}

pub fn check_adapter_health(adapter: &str) -> HealthCheck {
    let component = format!("{}-adapter", adapter);
    HealthCheck {
        name: format!("adapter-{}-health", adapter),
        component,
        status: HealthStatus::Healthy,
        source: HealthSource::Simulated,
        last_check: Utc::now().to_rfc3339(),
        message: format!(
            "DRY-RUN: {} adapter health check simulated - adapter is connected and healthy",
            adapter
        ),
    }
}

pub fn metrics_text() -> String {
    metrics_text_with_api_requests(0)
}

pub fn metrics_text_with_api_requests(total_api_requests: u64) -> String {
    metrics_text_from_health(&run_all_checks(), total_api_requests)
}

/// Render Prometheus exposition text for a SPECIFIC platform-health board.
///
/// Callers that hold a real dependency probe (e.g. live database connectivity)
/// pass a board built via [`override_check`] so the `ryuki_platform_health`
/// gauge reflects reality instead of the simulated placeholder. Each series
/// carries a `source` label (`simulated` vs `dependency-backed`) so an alert can
/// scope to dependency-backed signals and never be lulled by a simulated `1`.
pub fn metrics_text_from_health(health: &PlatformHealth, total_api_requests: u64) -> String {
    let mut out = String::new();

    out.push_str(
        "# HELP ryuki_platform_health Platform component health (1=healthy, 0=unhealthy)\n",
    );
    out.push_str("# TYPE ryuki_platform_health gauge\n");
    for check in &health.checks {
        let value = match check.status {
            HealthStatus::Healthy => 1,
            _ => 0,
        };
        out.push_str(&format!(
            "ryuki_platform_health{{component=\"{}\",source=\"{}\"}} {}\n",
            check.component, check.source, value
        ));
    }

    out.push_str("# HELP ryuki_api_requests_total Total API requests\n");
    out.push_str("# TYPE ryuki_api_requests_total counter\n");
    out.push_str(&format!(
        "ryuki_api_requests_total{{method=\"ALL\",path=\"ALL\",status=\"ALL\"}} {}\n",
        total_api_requests
    ));

    out.push_str("# HELP ryuki_platform_info Platform version info\n");
    out.push_str("# TYPE ryuki_platform_info gauge\n");
    out.push_str("ryuki_platform_info{version=\"0.1.0\"} 1\n");

    out
}

/// Appends Prometheus summary metrics for API request duration.
///
/// Generates `ryuki_api_request_duration_milliseconds` with quantiles estimated
/// from the stored min/max/avg, plus `_sum` and `_count` lines.
/// All metrics use the stable label set `{method="ALL",path="ALL"}`.
pub fn append_duration_metrics(
    text: &mut String,
    count: u64,
    sum_ms: f64,
    min_ms: f64,
    max_ms: f64,
    avg_ms: f64,
) {
    text.push_str(
        "# HELP ryuki_api_request_duration_milliseconds API request duration in milliseconds\n",
    );
    text.push_str("# TYPE ryuki_api_request_duration_milliseconds summary\n");

    let labels = "method=\"ALL\",path=\"ALL\"";

    // Estimate quantiles using min, avg, and max:
    // p50 ≈ (min + 2·avg) / 3  (biased toward central tendency)
    // p95 ≈ avg + 0.94·(max - avg)
    // p99 ≈ max
    let p50 = (min_ms + 2.0 * avg_ms) / 3.0;
    let p95 = avg_ms + (max_ms - avg_ms) * 0.94;
    let p99 = max_ms;

    text.push_str(&format!(
        "ryuki_api_request_duration_milliseconds{{quantile=\"0.5\",{labels}}} {p50:.3}\n"
    ));
    text.push_str(&format!(
        "ryuki_api_request_duration_milliseconds{{quantile=\"0.95\",{labels}}} {p95:.3}\n"
    ));
    text.push_str(&format!(
        "ryuki_api_request_duration_milliseconds{{quantile=\"0.99\",{labels}}} {p99:.3}\n"
    ));
    text.push_str(&format!(
        "ryuki_api_request_duration_milliseconds_sum{{{labels}}} {sum_ms:.3}\n"
    ));
    text.push_str(&format!(
        "ryuki_api_request_duration_milliseconds_count{{{labels}}} {count}\n"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_checks_healthy_in_dry_run() {
        let checks = vec![
            check_api_health(),
            check_portal_health(),
            check_validator_health(),
            check_kubernetes_health(),
            check_vault_health(),
            check_database_health(),
        ];
        for check in &checks {
            assert_eq!(check.status, HealthStatus::Healthy);
            assert_eq!(check.source, HealthSource::Simulated);
            assert!(check.message.contains("DRY-RUN"));
        }
    }

    #[test]
    fn test_platform_health_aggregates_correctly() {
        let health = run_all_checks();
        assert_eq!(health.overall_status, HealthStatus::Healthy);
        assert_eq!(health.source, HealthSource::Simulated);
        assert_eq!(health.checks.len(), 6);
        assert!(!health.timestamp.is_empty());
        assert!(health.components.contains(&"platform-api".to_string()));
        assert!(health.components.contains(&"portal-ui".to_string()));
        assert!(health.components.contains(&"platform-vault".to_string()));
    }

    #[test]
    fn test_adapter_health_check_works_for_each_adapter_type() {
        let adapters = vec![
            "vmware",
            "hyperv",
            "proxmox",
            "nutanix",
            "xen",
            "kvm",
            "veeam",
            "zabbix",
            "prometheus",
            "datadog",
            "grafana",
            "solarwinds",
            "servicenow",
            "commvault",
            "rubrik",
            "cohesity",
            "netbackup",
        ];
        for adapter in &adapters {
            let check = check_adapter_health(adapter);
            assert_eq!(check.status, HealthStatus::Healthy);
            assert_eq!(check.source, HealthSource::Simulated);
            assert!(check.message.contains("DRY-RUN"));
            assert!(check.message.contains(adapter));
            assert!(check.component.ends_with("-adapter"));
            assert!(check.name.contains(&format!("adapter-{}-health", adapter)));
        }
    }

    #[test]
    fn test_health_check_serialization() {
        let check = check_api_health();
        let json = serde_json::to_string(&check).expect("Failed to serialize HealthCheck");
        let deserialized: HealthCheck =
            serde_json::from_str(&json).expect("Failed to deserialize HealthCheck");
        assert_eq!(check.name, deserialized.name);
        assert_eq!(check.component, deserialized.component);
        assert_eq!(check.status, deserialized.status);
        assert_eq!(check.source, deserialized.source);
        assert_eq!(check.message, deserialized.message);
    }

    #[test]
    fn test_platform_health_serialization() {
        let health = run_all_checks();
        let json = serde_json::to_string(&health).expect("Failed to serialize PlatformHealth");
        let deserialized: PlatformHealth =
            serde_json::from_str(&json).expect("Failed to deserialize PlatformHealth");
        assert_eq!(health.overall_status, deserialized.overall_status);
        assert_eq!(health.checks.len(), deserialized.checks.len());
        assert_eq!(health.source, deserialized.source);
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
        assert_eq!(HealthStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_health_source_display() {
        assert_eq!(HealthSource::Simulated.to_string(), "simulated");
        assert_eq!(
            HealthSource::DependencyBacked.to_string(),
            "dependency-backed"
        );
        assert_eq!(HealthSource::Unavailable.to_string(), "unavailable");
    }

    #[test]
    fn test_all_checks_contain_dry_run_marker() {
        let health = run_all_checks();
        for check in &health.checks {
            assert!(
                check.message.contains("DRY-RUN"),
                "Check {} should contain DRY-RUN marker",
                check.name
            );
        }
    }

    #[test]
    fn test_metrics_text_contains_expected_families() {
        let metrics = metrics_text();
        assert!(metrics.contains("ryuki_platform_health"));
        assert!(metrics.contains("ryuki_api_requests_total"));
        assert!(metrics.contains("ryuki_platform_info"));
        assert!(metrics.contains("version=\"0.1.0\""));
        assert!(metrics.contains("component=\"platform-api\""));
    }

    #[test]
    fn database_health_from_probe_reflects_real_state() {
        // A successful probe is dependency-backed and healthy.
        let ok = database_health_from_probe(true);
        assert_eq!(ok.status, HealthStatus::Healthy);
        assert_eq!(ok.source, HealthSource::DependencyBacked);
        assert_eq!(ok.component, "platform-db");
        assert!(!ok.message.contains("DRY-RUN"));

        // A failed probe is UNHEALTHY — never silently healthy. This is the
        // anti-false-healthy invariant the whole change exists to guarantee.
        let down = database_health_from_probe(false);
        assert_eq!(down.status, HealthStatus::Unhealthy);
        assert_eq!(down.source, HealthSource::DependencyBacked);
    }

    #[test]
    fn override_check_folds_real_probe_into_board() {
        let mut health = run_all_checks();
        // Baseline: simulated board is all-healthy + simulated.
        assert_eq!(health.overall_status, HealthStatus::Healthy);
        assert_eq!(health.source, HealthSource::Simulated);

        // Fold in a FAILED real database probe.
        override_check(&mut health, database_health_from_probe(false));

        // The db component is now the real (unhealthy, dependency-backed) check.
        let db = health
            .checks
            .iter()
            .find(|c| c.component == "platform-db")
            .expect("platform-db check present");
        assert_eq!(db.status, HealthStatus::Unhealthy);
        assert_eq!(db.source, HealthSource::DependencyBacked);

        // Aggregates recomputed: any unhealthy => overall unhealthy; any real
        // probe => board is dependency-backed.
        assert_eq!(health.overall_status, HealthStatus::Unhealthy);
        assert_eq!(health.source, HealthSource::DependencyBacked);
        // The check count is unchanged — override replaces, never appends.
        assert_eq!(health.checks.len(), 6);
    }

    #[test]
    fn metrics_gauge_reflects_real_db_outage_with_source_label() {
        let mut health = run_all_checks();
        override_check(&mut health, database_health_from_probe(false));
        let metrics = metrics_text_from_health(&health, 7);

        // The dangerous false-healthy signal is gone: the db gauge reads 0 when
        // the real probe failed, and is tagged dependency-backed.
        assert!(metrics.contains(
            "ryuki_platform_health{component=\"platform-db\",source=\"dependency-backed\"} 0"
        ));
        // Simulated components still carry their honest source label.
        assert!(
            metrics.contains(
                "ryuki_platform_health{component=\"platform-api\",source=\"simulated\"} 1"
            )
        );
        // A healthy probe flips the same series to 1.
        let mut healthy = run_all_checks();
        override_check(&mut healthy, database_health_from_probe(true));
        let metrics_ok = metrics_text_from_health(&healthy, 7);
        assert!(metrics_ok.contains(
            "ryuki_platform_health{component=\"platform-db\",source=\"dependency-backed\"} 1"
        ));
    }

    #[test]
    fn test_metrics_text_no_secrets() {
        let metrics = metrics_text();
        assert!(!metrics.contains("password"));
        assert!(!metrics.contains("secret"));
        assert!(!metrics.contains("token"));
        assert!(!metrics.contains("credential"));
        assert!(!metrics.contains("api_key"));
    }

    #[test]
    fn test_metrics_text_with_api_requests_injects_counter_value() {
        let metrics = metrics_text_with_api_requests(42);
        assert!(
            metrics.contains(
                "ryuki_api_requests_total{method=\"ALL\",path=\"ALL\",status=\"ALL\"} 42"
            )
        );
        // Ensure we still have the expected families and no duplicate HELP/TYPE blocks.
        assert!(metrics.contains("ryuki_platform_health"));
        assert!(metrics.contains("ryuki_platform_info"));
        let help_count = metrics.matches("# HELP ryuki_api_requests_total").count();
        assert_eq!(help_count, 1, "must not duplicate HELP block");
        let type_count = metrics.matches("# TYPE ryuki_api_requests_total").count();
        assert_eq!(type_count, 1, "must not duplicate TYPE block");
    }

    #[test]
    fn test_no_credentials_or_secrets_exposed() {
        let health = run_all_checks();
        let json = serde_json::to_string(&health).expect("Failed to serialize");
        assert!(!json.contains("password"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("token"));
        assert!(!json.contains("credential"));
        assert!(!json.contains("api_key"));
    }
}
