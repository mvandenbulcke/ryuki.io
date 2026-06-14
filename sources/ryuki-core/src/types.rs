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
#[serde(default)]
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
    #[serde(default = "default_storage_provider")]
    pub storage_provider: String,
    #[serde(default = "default_dns_provider")]
    pub dns_provider: String,
    #[serde(default = "default_ipam_provider")]
    pub ipam_provider: String,
    #[serde(default = "default_load_balancer_provider")]
    pub load_balancer_provider: String,
    #[serde(default = "default_firewall_provider")]
    pub firewall_provider: String,
    #[serde(default = "default_build_provider")]
    pub build_provider: String,
    #[serde(default = "default_network_provider")]
    pub network_provider: String,
    #[serde(default = "default_retention_daily_val")]
    pub retention_daily_backups: u32,
    #[serde(default = "default_retention_weekly_val")]
    pub retention_weekly_backups: u32,
    #[serde(default = "default_retention_monthly_val")]
    pub retention_monthly_backups: u32,
    #[serde(default = "default_retention_yearly_val")]
    pub retention_yearly_backups: u32,
    #[serde(default = "default_mw_day")]
    pub maintenance_window_day: String,
    #[serde(default = "default_mw_start")]
    pub maintenance_window_start_hour: u8,
    #[serde(default = "default_mw_duration")]
    pub maintenance_window_duration_hours: u8,
    #[serde(default = "default_keep_alive_timeout")]
    pub keep_alive_timeout_secs: u64,
    #[serde(default = "default_max_connections")]
    pub max_concurrent_connections: u64,
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

fn default_storage_provider() -> String {
    "none".to_string()
}

fn default_dns_provider() -> String {
    "none".to_string()
}

fn default_ipam_provider() -> String {
    "none".to_string()
}

fn default_load_balancer_provider() -> String {
    "none".to_string()
}

fn default_firewall_provider() -> String {
    "none".to_string()
}

fn default_build_provider() -> String {
    "none".to_string()
}

fn default_network_provider() -> String {
    "none".to_string()
}

fn default_retention_daily_val() -> u32 {
    30
}

fn default_retention_weekly_val() -> u32 {
    12
}

fn default_retention_monthly_val() -> u32 {
    12
}

fn default_retention_yearly_val() -> u32 {
    7
}

fn default_mw_day() -> String {
    "sunday".to_string()
}

fn default_mw_start() -> u8 {
    2
}

fn default_mw_duration() -> u8 {
    4
}

fn default_keep_alive_timeout() -> u64 {
    75
}

fn default_max_connections() -> u64 {
    512
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
            storage_provider: default_storage_provider(),
            dns_provider: default_dns_provider(),
            ipam_provider: default_ipam_provider(),
            load_balancer_provider: default_load_balancer_provider(),
            firewall_provider: default_firewall_provider(),
            build_provider: default_build_provider(),
            network_provider: default_network_provider(),
            retention_daily_backups: default_retention_daily_val(),
            retention_weekly_backups: default_retention_weekly_val(),
            retention_monthly_backups: default_retention_monthly_val(),
            retention_yearly_backups: default_retention_yearly_val(),
            maintenance_window_day: default_mw_day(),
            maintenance_window_start_hour: default_mw_start(),
            maintenance_window_duration_hours: default_mw_duration(),
            keep_alive_timeout_secs: default_keep_alive_timeout(),
            max_concurrent_connections: default_max_connections(),
        }
    }
}

/// Validates a PlatformConfig for correctness.
/// Returns a list of validation errors (empty = valid).
pub fn validate_platform_config(config: &PlatformConfig) -> Vec<String> {
    let mut errors = Vec::new();

    if config.platform_name.trim().is_empty() {
        errors.push("platform_name is required".into());
    }

    if config.platform_url.trim().is_empty() {
        errors.push("platform_url is required".into());
    } else if !config.platform_url.starts_with("http://")
        && !config.platform_url.starts_with("https://")
    {
        errors.push(format!(
            "platform_url '{}' must start with http:// or https://",
            config.platform_url
        ));
    }

    if !config.entra_authority.trim().is_empty()
        && !config.entra_authority.starts_with("http://")
        && !config.entra_authority.starts_with("https://")
    {
        errors.push(format!(
            "entra_authority '{}' must start with http:// or https://",
            config.entra_authority
        ));
    }

    let valid_auth_modes = ["mock-dry-run", "static-dry-run", "entra-id", "local"];
    if !valid_auth_modes.contains(&config.auth_mode.as_str()) {
        errors.push(format!(
            "invalid auth_mode '{}': must be one of {:?}",
            config.auth_mode, valid_auth_modes
        ));
    }

    if config.auth_mode == "entra-id" {
        if config.entra_tenant_id.trim().is_empty() {
            errors.push("entra_tenant_id is required when auth_mode is entra-id".into());
        }
        if config.entra_client_id.trim().is_empty() {
            errors.push("entra_client_id is required when auth_mode is entra-id".into());
        }
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
        "bitwarden-secrets-manager",
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

    let valid_storage_providers = [
        "netapp",
        "pure-storage",
        "dell-powerstore",
        "hpe-alletra",
        "azure-blob",
        "none",
    ];
    if !valid_storage_providers.contains(&config.storage_provider.as_str()) {
        errors.push(format!(
            "invalid storage_provider '{}'",
            config.storage_provider
        ));
    }

    let valid_dns_providers = ["infoblox", "bluecat", "windows-dns", "route53", "none"];
    if !valid_dns_providers.contains(&config.dns_provider.as_str()) {
        errors.push(format!("invalid dns_provider '{}'", config.dns_provider));
    }

    let valid_ipam_providers = ["infoblox", "phpipam", "netbox", "none"];
    if !valid_ipam_providers.contains(&config.ipam_provider.as_str()) {
        errors.push(format!("invalid ipam_provider '{}'", config.ipam_provider));
    }

    let valid_lb_providers = ["f5-bigip", "citrix-adc", "haproxy", "nginx", "none"];
    if !valid_lb_providers.contains(&config.load_balancer_provider.as_str()) {
        errors.push(format!(
            "invalid load_balancer_provider '{}'",
            config.load_balancer_provider
        ));
    }

    let valid_fw_providers = ["palo-alto", "checkpoint", "fortinet", "cisco-asa", "none"];
    if !valid_fw_providers.contains(&config.firewall_provider.as_str()) {
        errors.push(format!(
            "invalid firewall_provider '{}'",
            config.firewall_provider
        ));
    }

    let valid_build_providers = [
        "jenkins",
        "github-actions",
        "azure-devops",
        "argocd",
        "none",
    ];
    if !valid_build_providers.contains(&config.build_provider.as_str()) {
        errors.push(format!(
            "invalid build_provider '{}'",
            config.build_provider
        ));
    }

    let valid_network_providers = ["cisco-aci", "vmware-nsx", "evpn", "none"];
    if !valid_network_providers.contains(&config.network_provider.as_str()) {
        errors.push(format!(
            "invalid network_provider '{}'",
            config.network_provider
        ));
    }

    if config.retention_daily_backups == 0 {
        errors.push("retention_daily_backups must be greater than 0".into());
    }
    if config.retention_weekly_backups == 0 {
        errors.push("retention_weekly_backups must be greater than 0".into());
    }
    if config.retention_monthly_backups == 0 {
        errors.push("retention_monthly_backups must be greater than 0".into());
    }
    if config.retention_yearly_backups == 0 {
        errors.push("retention_yearly_backups must be greater than 0".into());
    }

    let valid_days = [
        "sunday",
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
    ];
    if !config.maintenance_window_day.trim().is_empty()
        && !valid_days.contains(&config.maintenance_window_day.as_str())
    {
        errors.push(format!(
            "maintenance_window_day must be one of: {:?}",
            valid_days
        ));
    }

    if config.maintenance_window_start_hour >= 24 {
        errors.push("maintenance_window_start_hour must be 0-23".into());
    }
    if config.maintenance_window_duration_hours == 0 {
        errors.push("maintenance_window_duration_hours must be greater than 0".into());
    }
    if config.keep_alive_timeout_secs == 0 {
        errors.push("keep_alive_timeout_secs must be greater than 0".into());
    }
    if config.max_concurrent_connections == 0 {
        errors.push("max_concurrent_connections must be greater than 0".into());
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
        let config = PlatformConfig {
            auth_mode: "ldap".into(),
            ..Default::default()
        };
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("auth_mode")));
    }

    #[test]
    fn validate_platform_config_invalid_database_provider() {
        let config = PlatformConfig {
            database_provider: "mysql".into(),
            ..Default::default()
        };
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("database_provider")));
    }

    #[test]
    fn validate_platform_config_invalid_secret_provider() {
        let config = PlatformConfig {
            secret_provider: "azure-keyvault-private".into(),
            ..Default::default()
        };
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("secret_provider")));
    }

    #[test]
    fn validate_platform_config_invalid_kubernetes_runtime() {
        let config = PlatformConfig {
            kubernetes_runtime: "pks".into(),
            ..Default::default()
        };
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("kubernetes_runtime")));
    }

    #[test]
    fn validate_platform_config_invalid_monitoring_provider() {
        let config = PlatformConfig {
            monitoring_provider: "splunk".into(),
            ..Default::default()
        };
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("monitoring_provider")));
    }

    #[test]
    fn validate_platform_config_invalid_backup_provider() {
        let config = PlatformConfig {
            backup_provider: "acronis".into(),
            ..Default::default()
        };
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("backup_provider")));
    }

    #[test]
    fn validate_platform_config_invalid_hypervisor_provider() {
        let config = PlatformConfig {
            hypervisor_provider: "virtualbox".into(),
            ..Default::default()
        };
        let errors = validate_platform_config(&config);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("hypervisor_provider")));
    }

    #[test]
    fn validate_platform_config_mock_dry_run_auth_valid() {
        let config = PlatformConfig {
            auth_mode: "mock-dry-run".into(),
            ..Default::default()
        };
        let errors = validate_platform_config(&config);
        assert!(
            errors.is_empty(),
            "mock-dry-run should be valid, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_platform_config_entra_id_auth_valid() {
        let config = PlatformConfig {
            auth_mode: "entra-id".into(),
            entra_tenant_id: "tenant-id".into(),
            entra_client_id: "client-id".into(),
            ..Default::default()
        };
        let errors = validate_platform_config(&config);
        assert!(
            errors.is_empty(),
            "entra-id should be valid, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_platform_config_provider_none_valid() {
        let config = PlatformConfig {
            secret_provider: "none".into(),
            ..Default::default()
        };
        let errors = validate_platform_config(&config);
        assert!(
            errors.is_empty(),
            "none should be valid for secret_provider, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_platform_config_rejects_blank_identity_fields() {
        let config = PlatformConfig {
            platform_name: "   ".into(),
            platform_url: "   ".into(),
            auth_mode: "entra-id".into(),
            entra_tenant_id: "   ".into(),
            entra_client_id: "".into(),
            ..Default::default()
        };

        let errors = validate_platform_config(&config);

        assert!(errors.iter().any(|e| e.contains("platform_name")));
        assert!(errors.iter().any(|e| e.contains("platform_url")));
        assert!(errors.iter().any(|e| e.contains("entra_tenant_id")));
        assert!(errors.iter().any(|e| e.contains("entra_client_id")));
    }

    #[test]
    fn validate_platform_config_rejects_invalid_urls() {
        let config = PlatformConfig {
            platform_url: "ftp://ryuki.local".into(),
            entra_authority: "login.microsoftonline.com".into(),
            ..Default::default()
        };

        let errors = validate_platform_config(&config);

        assert!(errors.iter().any(|e| e.contains("platform_url")));
        assert!(errors.iter().any(|e| e.contains("entra_authority")));
    }

    #[test]
    fn validate_platform_config_allows_empty_entra_authority() {
        let config = PlatformConfig {
            entra_authority: "".into(),
            ..Default::default()
        };

        let errors = validate_platform_config(&config);

        assert!(errors.is_empty(), "expected no errors, got: {:?}", errors);
    }

    #[test]
    fn validate_platform_config_rejects_zero_retention_values() {
        let config = PlatformConfig {
            retention_daily_backups: 0,
            retention_weekly_backups: 0,
            retention_monthly_backups: 0,
            retention_yearly_backups: 0,
            ..Default::default()
        };

        let errors = validate_platform_config(&config);

        assert!(errors.iter().any(|e| e.contains("retention_daily_backups")));
        assert!(
            errors
                .iter()
                .any(|e| e.contains("retention_weekly_backups"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("retention_monthly_backups"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("retention_yearly_backups"))
        );
    }

    #[test]
    fn validate_platform_config_rejects_invalid_maintenance_values() {
        let config = PlatformConfig {
            maintenance_window_day: "funday".into(),
            maintenance_window_start_hour: 24,
            maintenance_window_duration_hours: 0,
            ..Default::default()
        };

        let errors = validate_platform_config(&config);

        assert!(errors.iter().any(|e| e.contains("maintenance_window_day")));
        assert!(
            errors
                .iter()
                .any(|e| e.contains("maintenance_window_start_hour"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("maintenance_window_duration_hours"))
        );
    }

    #[test]
    fn validate_platform_config_rejects_zero_server_limits() {
        let config = PlatformConfig {
            keep_alive_timeout_secs: 0,
            max_concurrent_connections: 0,
            ..Default::default()
        };

        let errors = validate_platform_config(&config);

        assert!(errors.iter().any(|e| e.contains("keep_alive_timeout_secs")));
        assert!(
            errors
                .iter()
                .any(|e| e.contains("max_concurrent_connections"))
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
