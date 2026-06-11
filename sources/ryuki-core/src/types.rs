use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiError {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ApiError {
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(
        error: impl Into<String>,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
            detail: Some(detail.into()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidationResult {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PlatformError {
    pub code: String,
    pub message: String,
    pub path: Option<String>,
    pub line: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum ExecutionMode {
    StaticDryRun,
    LiveProvider,
    Mock,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct BoundaryStatus {
    pub http_request_allowed: bool,
    pub provider_calls_allowed: bool,
    pub live_execution_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
    pub execution_mode: ExecutionMode,
}

impl Default for BoundaryStatus {
    fn default() -> Self {
        Self {
            http_request_allowed: false,
            provider_calls_allowed: false,
            live_execution_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
            execution_mode: ExecutionMode::StaticDryRun,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PlatformConfig {
    #[serde(default)]
    pub entra_tenant_id: String,
    #[serde(default)]
    pub entra_client_id: String,
    #[serde(default = "default_entra_authority")]
    pub entra_authority: String,
    #[serde(default = "default_auth_mode")]
    pub auth_mode: String,
    #[serde(default = "default_database_provider")]
    pub database_provider: String,
    #[serde(default = "default_platform_name")]
    pub platform_name: String,
    #[serde(default = "default_platform_url")]
    pub platform_url: String,
    #[serde(default = "default_secret_provider")]
    pub secret_provider: String,
    #[serde(default = "default_kubernetes_runtime")]
    pub kubernetes_runtime: String,
    #[serde(default = "default_monitoring_provider")]
    pub monitoring_provider: String,
    #[serde(default = "default_backup_provider")]
    pub backup_provider: String,
    #[serde(default = "default_hypervisor_provider")]
    pub hypervisor_provider: String,
}

fn default_entra_authority() -> String {
    "https://login.microsoftonline.com".to_string()
}

fn default_auth_mode() -> String {
    "mock-dry-run".to_string()
}

fn default_database_provider() -> String {
    "cloudnativepg".to_string()
}

fn default_platform_name() -> String {
    "Ryuki Infrastructure Platform".to_string()
}

fn default_platform_url() -> String {
    "http://localhost:18080".to_string()
}

fn default_secret_provider() -> String {
    "hashicorp-vault".to_string()
}

fn default_kubernetes_runtime() -> String {
    "vsphere-vks".to_string()
}

fn default_monitoring_provider() -> String {
    "zabbix".to_string()
}

fn default_backup_provider() -> String {
    "veeam".to_string()
}

fn default_hypervisor_provider() -> String {
    "vmware".to_string()
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            entra_tenant_id: String::new(),
            entra_client_id: String::new(),
            entra_authority: default_entra_authority(),
            auth_mode: default_auth_mode(),
            database_provider: default_database_provider(),
            platform_name: default_platform_name(),
            platform_url: default_platform_url(),
            secret_provider: default_secret_provider(),
            kubernetes_runtime: default_kubernetes_runtime(),
            monitoring_provider: default_monitoring_provider(),
            backup_provider: default_backup_provider(),
            hypervisor_provider: default_hypervisor_provider(),
        }
    }
}

/// Validates a PlatformConfig for correctness.
/// Returns a list of validation errors (empty = valid).
pub fn validate_platform_config(config: &PlatformConfig) -> Vec<String> {
    let mut errors = Vec::new();

    let valid_auth_modes = ["mock-dry-run", "static-dry-run", "entra-id", "local"];
    if !valid_auth_modes.contains(&config.auth_mode.as_str()) {
        errors.push(format!(
            "invalid auth_mode '{}': must be one of {:?}",
            config.auth_mode, valid_auth_modes
        ));
    }

    let valid_db_providers = [
        "cloudnativepg",
        "postgres-local",
        "aws-rds",
        "azure-postgresql",
        "gcp-cloud-sql",
    ];
    if !valid_db_providers.contains(&config.database_provider.as_str()) {
        errors.push(format!(
            "invalid database_provider '{}': must be one of {:?}",
            config.database_provider, valid_db_providers
        ));
    }

    let valid_secret_providers = [
        "hashicorp-vault",
        "aws-secrets-manager",
        "azure-key-vault",
        "gcp-secret-manager",
        "none",
    ];
    if !valid_secret_providers.contains(&config.secret_provider.as_str()) {
        errors.push(format!(
            "invalid secret_provider '{}': must be one of {:?}",
            config.secret_provider, valid_secret_providers
        ));
    }

    let valid_k8s_runtimes = [
        "vsphere-vks",
        "docker-compose",
        "aks",
        "eks",
        "gke",
        "openshift",
        "rancher",
        "none",
    ];
    if !valid_k8s_runtimes.contains(&config.kubernetes_runtime.as_str()) {
        errors.push(format!(
            "invalid kubernetes_runtime '{}': must be one of {:?}",
            config.kubernetes_runtime, valid_k8s_runtimes
        ));
    }

    let valid_mon_providers = [
        "zabbix",
        "prometheus",
        "datadog",
        "grafana",
        "solarwinds",
        "none",
    ];
    if !valid_mon_providers.contains(&config.monitoring_provider.as_str()) {
        errors.push(format!(
            "invalid monitoring_provider '{}': must be one of {:?}",
            config.monitoring_provider, valid_mon_providers
        ));
    }

    let valid_backup_providers = [
        "veeam",
        "commvault",
        "rubrik",
        "cohesity",
        "netbackup",
        "none",
    ];
    if !valid_backup_providers.contains(&config.backup_provider.as_str()) {
        errors.push(format!(
            "invalid backup_provider '{}': must be one of {:?}",
            config.backup_provider, valid_backup_providers
        ));
    }

    let valid_hypervisor_providers = [
        "vmware",
        "hyperv",
        "proxmox",
        "nutanix-ahv",
        "xen",
        "kvm",
        "none",
    ];
    if !valid_hypervisor_providers.contains(&config.hypervisor_provider.as_str()) {
        errors.push(format!(
            "invalid hypervisor_provider '{}': must be one of {:?}",
            config.hypervisor_provider, valid_hypervisor_providers
        ));
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_serialization_without_detail() {
        let err = ApiError::new("VALIDATION_FAILED", "Slice name required");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("VALIDATION_FAILED"));
        assert!(json.contains("Slice name required"));
        assert!(!json.contains("detail"));
        let restored: ApiError = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.error, "VALIDATION_FAILED");
        assert_eq!(restored.message, "Slice name required");
        assert_eq!(restored.detail, None);
    }

    #[test]
    fn api_error_serialization_with_detail() {
        let err = ApiError::with_detail(
            "HEALTH_CHECK_FAILED",
            "Platform health check failed",
            "Simulated error for testing ProblemDetails contract",
        );
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("HEALTH_CHECK_FAILED"));
        assert!(json.contains("Platform health check failed"));
        assert!(json.contains("detail"));
        assert!(json.contains("Simulated error for testing"));
        let restored: ApiError = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.error, "HEALTH_CHECK_FAILED");
        assert_eq!(restored.message, "Platform health check failed");
        assert_eq!(
            restored.detail,
            Some("Simulated error for testing ProblemDetails contract".into())
        );
    }

    #[test]
    fn api_error_clone() {
        let err = ApiError::with_detail("E001", "msg", "det");
        let err2 = err.clone();
        assert_eq!(err2.error, err.error);
        assert_eq!(err2.message, err.message);
        assert_eq!(err2.detail, err.detail);
    }

    #[test]
    fn boundary_status_default_all_disabled() {
        let bs = BoundaryStatus::default();
        assert!(!bs.http_request_allowed);
        assert!(!bs.provider_calls_allowed);
        assert!(!bs.live_execution_allowed);
        assert!(!bs.raw_payload_allowed);
        assert!(!bs.secret_values_allowed);
        assert!(!bs.customer_identifiers_allowed);
        assert!(matches!(bs.execution_mode, ExecutionMode::StaticDryRun));
    }

    #[test]
    fn execution_mode_serialization_roundtrip() {
        let modes = vec![
            ExecutionMode::StaticDryRun,
            ExecutionMode::LiveProvider,
            ExecutionMode::Mock,
        ];
        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let restored: ExecutionMode = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&restored).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn execution_mode_variant_names() {
        let json = serde_json::to_string(&ExecutionMode::StaticDryRun).unwrap();
        assert!(json.contains("StaticDryRun"));
        let json = serde_json::to_string(&ExecutionMode::LiveProvider).unwrap();
        assert!(json.contains("LiveProvider"));
        let json = serde_json::to_string(&ExecutionMode::Mock).unwrap();
        assert!(json.contains("Mock"));
    }

    #[test]
    fn validation_result_json_roundtrip() {
        let vr = ValidationResult {
            errors: vec!["error1".into(), "error2".into()],
            warnings: vec!["warn1".into()],
        };
        let json = serde_json::to_string(&vr).unwrap();
        let restored: ValidationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(vr.errors, restored.errors);
        assert_eq!(vr.warnings, restored.warnings);
    }

    #[test]
    fn validation_result_empty() {
        let vr = ValidationResult {
            errors: Vec::new(),
            warnings: Vec::new(),
        };
        let json = serde_json::to_string(&vr).unwrap();
        let restored: ValidationResult = serde_json::from_str(&json).unwrap();
        assert!(restored.errors.is_empty());
        assert!(restored.warnings.is_empty());
    }

    #[test]
    fn platform_error_creation_and_serialization() {
        let err = PlatformError {
            code: "E001".into(),
            message: "something failed".into(),
            path: Some("test.yaml".into()),
            line: Some(42),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("E001"));
        assert!(json.contains("something failed"));
        assert!(json.contains("test.yaml"));
        assert!(json.contains("42"));

        let restored: PlatformError = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.code, "E001");
        assert_eq!(restored.message, "something failed");
        assert_eq!(restored.path, Some("test.yaml".into()));
        assert_eq!(restored.line, Some(42));
    }

    #[test]
    fn platform_error_no_path_or_line() {
        let err = PlatformError {
            code: "E002".into(),
            message: "generic error".into(),
            path: None,
            line: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: PlatformError = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.path, None);
        assert_eq!(restored.line, None);
    }

    #[test]
    fn boundary_status_clone() {
        let bs = BoundaryStatus::default();
        let bs2 = bs.clone();
        assert_eq!(bs2.http_request_allowed, bs.http_request_allowed);
        assert!(matches!(bs2.execution_mode, ExecutionMode::StaticDryRun));
    }

    #[test]
    fn validation_result_clone() {
        let vr = ValidationResult {
            errors: vec!["e1".into()],
            warnings: vec!["w1".into()],
        };
        let vr2 = vr.clone();
        assert_eq!(vr2.errors, vr.errors);
        assert_eq!(vr2.warnings, vr.warnings);
    }

    #[test]
    fn validate_platform_config_all_valid() {
        let config = PlatformConfig::default();
        let errors = validate_platform_config(&config);
        assert!(errors.is_empty(), "expected no errors, got: {:?}", errors);
    }

    #[test]
    fn validate_platform_config_invalid_auth_mode() {
        let mut config = PlatformConfig::default();
        config.auth_mode = "ldap".into();
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("auth_mode")));
    }

    #[test]
    fn validate_platform_config_invalid_database_provider() {
        let mut config = PlatformConfig::default();
        config.database_provider = "mysql".into();
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("database_provider")));
    }

    #[test]
    fn validate_platform_config_invalid_secret_provider() {
        let mut config = PlatformConfig::default();
        config.secret_provider = "azure-keyvault-private".into();
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("secret_provider")));
    }

    #[test]
    fn validate_platform_config_invalid_kubernetes_runtime() {
        let mut config = PlatformConfig::default();
        config.kubernetes_runtime = "pks".into();
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("kubernetes_runtime")));
    }

    #[test]
    fn validate_platform_config_invalid_monitoring_provider() {
        let mut config = PlatformConfig::default();
        config.monitoring_provider = "splunk".into();
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("monitoring_provider")));
    }

    #[test]
    fn validate_platform_config_invalid_backup_provider() {
        let mut config = PlatformConfig::default();
        config.backup_provider = "acronis".into();
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("backup_provider")));
    }

    #[test]
    fn validate_platform_config_invalid_hypervisor_provider() {
        let mut config = PlatformConfig::default();
        config.hypervisor_provider = "virtualbox".into();
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("hypervisor_provider")));
    }

    #[test]
    fn validate_platform_config_mock_dry_run_auth_valid() {
        let mut config = PlatformConfig::default();
        config.auth_mode = "mock-dry-run".into();
        let errors = validate_platform_config(&config);
        assert!(
            errors.is_empty(),
            "mock-dry-run should be valid, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_platform_config_entra_id_auth_valid() {
        let mut config = PlatformConfig::default();
        config.auth_mode = "entra-id".into();
        let errors = validate_platform_config(&config);
        assert!(
            errors.is_empty(),
            "entra-id should be valid, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_platform_config_provider_none_valid() {
        let mut config = PlatformConfig::default();
        config.secret_provider = "none".into();
        let errors = validate_platform_config(&config);
        assert!(
            errors.is_empty(),
            "none should be valid for secret_provider, got: {:?}",
            errors
        );
    }

    #[test]
    fn platform_config_default_has_all_provider_fields() {
        let config = PlatformConfig::default();
        assert_eq!(config.database_provider, "cloudnativepg");
        assert_eq!(config.secret_provider, "hashicorp-vault");
        assert_eq!(config.kubernetes_runtime, "vsphere-vks");
        assert_eq!(config.monitoring_provider, "zabbix");
        assert_eq!(config.backup_provider, "veeam");
        assert_eq!(config.hypervisor_provider, "vmware");
    }
}
