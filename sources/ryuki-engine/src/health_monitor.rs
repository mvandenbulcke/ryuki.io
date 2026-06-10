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

    let overall_status = if checks.iter().all(|c| c.status == HealthStatus::Healthy) {
        HealthStatus::Healthy
    } else if checks.iter().any(|c| c.status == HealthStatus::Unhealthy) {
        HealthStatus::Unhealthy
    } else if checks.iter().any(|c| c.status == HealthStatus::Degraded) {
        HealthStatus::Degraded
    } else {
        HealthStatus::Unknown
    };

    let overall_source = if checks
        .iter()
        .any(|c| c.source == HealthSource::DependencyBacked)
    {
        HealthSource::DependencyBacked
    } else if checks.iter().any(|c| c.source == HealthSource::Simulated) {
        HealthSource::Simulated
    } else {
        HealthSource::Unavailable
    };

    PlatformHealth {
        overall_status,
        components,
        checks,
        timestamp: Utc::now().to_rfc3339(),
        source: overall_source,
    }
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
    let health = run_all_checks();
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
            "ryuki_platform_health{{component=\"{}\"}} {}\n",
            check.component, value
        ));
    }

    out.push_str("# HELP ryuki_api_requests_total Total API requests\n");
    out.push_str("# TYPE ryuki_api_requests_total counter\n");
    out.push_str("ryuki_api_requests_total{method=\"GET\",path=\"/metrics\",status=\"200\"} 0\n");

    out.push_str("# HELP ryuki_platform_info Platform version info\n");
    out.push_str("# TYPE ryuki_platform_info gauge\n");
    out.push_str("ryuki_platform_info{version=\"0.1.0\"} 1\n");

    out
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
            "veeam",
            "zabbix",
            "servicenow",
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
    fn test_metrics_text_no_secrets() {
        let metrics = metrics_text();
        assert!(!metrics.contains("password"));
        assert!(!metrics.contains("secret"));
        assert!(!metrics.contains("token"));
        assert!(!metrics.contains("credential"));
        assert!(!metrics.contains("api_key"));
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
