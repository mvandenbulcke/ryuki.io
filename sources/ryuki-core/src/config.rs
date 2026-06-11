use figment::{
    Figment,
    providers::{Env, Format, Json, Toml},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    #[default]
    MockDryRun,
    StaticDryRun,
    EntraId,
    Local,
}

impl AuthMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mock-dry-run" => Some(Self::MockDryRun),
            "static-dry-run" => Some(Self::StaticDryRun),
            "entra-id" => Some(Self::EntraId),
            "local" => Some(Self::Local),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MockDryRun => "mock-dry-run",
            Self::StaticDryRun => "static-dry-run",
            Self::EntraId => "entra-id",
            Self::Local => "local",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseProvider {
    #[default]
    #[serde(alias = "cloudnativepg")]
    CloudNativePg,
    #[serde(alias = "postgres-local")]
    PostgresLocal,
}

impl DatabaseProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cloudnativepg" => Some(Self::CloudNativePg),
            "postgres-local" => Some(Self::PostgresLocal),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SecretProvider {
    #[default]
    HashicorpVault,
    None,
}

impl SecretProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hashicorp-vault" => Some(Self::HashicorpVault),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum KubernetesRuntime {
    #[default]
    VsphereVks,
    DockerCompose,
    None,
}

impl KubernetesRuntime {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "vsphere-vks" => Some(Self::VsphereVks),
            "docker-compose" => Some(Self::DockerCompose),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MonitoringProvider {
    #[default]
    Zabbix,
    None,
}

impl MonitoringProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "zabbix" => Some(Self::Zabbix),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BackupProvider {
    #[default]
    Veeam,
    None,
}

impl BackupProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "veeam" => Some(Self::Veeam),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogConfig {
    #[serde(default)]
    pub level: LogLevel,
    #[serde(default)]
    pub format: LogFormat,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
}

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_shutdown_timeout() -> u64 {
    30
}

fn default_request_timeout() -> u64 {
    30
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            shutdown_timeout_secs: default_shutdown_timeout(),
            request_timeout_secs: default_request_timeout(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CorsConfig {
    #[serde(default = "default_allowed_origins")]
    pub allowed_origins: Vec<String>,
}

fn default_allowed_origins() -> Vec<String> {
    vec![
        "http://localhost:3000".to_string(),
        "http://127.0.0.1:3000".to_string(),
    ]
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: default_allowed_origins(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u64,
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,
}

fn default_rate_limit_enabled() -> bool {
    false
}

fn default_requests_per_second() -> u64 {
    50
}

fn default_burst_size() -> u32 {
    100
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            requests_per_second: default_requests_per_second(),
            burst_size: default_burst_size(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RyukiConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default = "default_database_url")]
    pub database_url: String,
    #[serde(default)]
    pub auth_mode: AuthMode,
    #[serde(default)]
    pub entra_tenant_id: String,
    #[serde(default)]
    pub entra_client_id: String,
    #[serde(default = "default_entra_authority")]
    pub entra_authority: String,
    #[serde(default = "default_platform_name")]
    pub platform_name: String,
    #[serde(default = "default_platform_url")]
    pub platform_url: String,
    #[serde(default)]
    pub database_provider: DatabaseProvider,
    #[serde(default)]
    pub secret_provider: SecretProvider,
    #[serde(default)]
    pub kubernetes_runtime: KubernetesRuntime,
    #[serde(default)]
    pub monitoring_provider: MonitoringProvider,
    #[serde(default)]
    pub backup_provider: BackupProvider,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub logging: LogConfig,
}

fn default_database_url() -> String {
    "postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform".to_string()
}

fn default_entra_authority() -> String {
    "https://login.microsoftonline.com".to_string()
}

fn default_platform_name() -> String {
    "Ryuki Infrastructure Platform".to_string()
}

fn default_platform_url() -> String {
    "http://localhost:18080".to_string()
}

impl Default for RyukiConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database_url: default_database_url(),
            auth_mode: AuthMode::default(),
            entra_tenant_id: String::new(),
            entra_client_id: String::new(),
            entra_authority: default_entra_authority(),
            platform_name: default_platform_name(),
            platform_url: default_platform_url(),
            database_provider: DatabaseProvider::default(),
            secret_provider: SecretProvider::default(),
            kubernetes_runtime: KubernetesRuntime::default(),
            monitoring_provider: MonitoringProvider::default(),
            backup_provider: BackupProvider::default(),
            cors: CorsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            logging: LogConfig::default(),
        }
    }
}

fn merge_file(figment: Figment, path: &str) -> Figment {
    if path.ends_with(".toml") {
        figment.merge(Toml::file(path))
    } else {
        figment.merge(Json::file(path))
    }
}

impl RyukiConfig {
    /// Load config from multiple sources with priority:
    /// 1. Environment variables (highest priority)
    /// 2. Config file (ryuki.toml, ryuki.json, platform-config.json)
    /// 3. Default values (lowest priority)
    #[allow(clippy::result_large_err)]
    pub fn load() -> Result<Self, figment::Error> {
        let mut figment = Figment::new().merge(figment::providers::Serialized::defaults(
            RyukiConfig::default(),
        ));

        for path in &["ryuki.toml", "ryuki.json", "platform-config.json"] {
            if std::path::Path::new(path).exists() {
                figment = merge_file(figment, path);
            }
        }

        figment.merge(Env::prefixed("RYUKI_").split("__")).extract()
    }

    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.database_url.is_empty() {
            errors.push("database_url is required".into());
        }

        if self.server.bind_address.is_empty() {
            errors.push("server.bind_address is required".into());
        }

        if self.platform_name.is_empty() {
            errors.push("platform_name is required".into());
        }

        if self.platform_url.is_empty() {
            errors.push("platform_url is required".into());
        } else if !self.platform_url.starts_with("http") {
            errors.push(format!(
                "platform_url '{}' must start with http:// or https://",
                self.platform_url
            ));
        }

        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_mode_parse() {
        assert_eq!(AuthMode::parse("mock-dry-run"), Some(AuthMode::MockDryRun));
        assert_eq!(
            AuthMode::parse("static-dry-run"),
            Some(AuthMode::StaticDryRun)
        );
        assert_eq!(AuthMode::parse("entra-id"), Some(AuthMode::EntraId));
        assert_eq!(AuthMode::parse("local"), Some(AuthMode::Local));
        assert_eq!(AuthMode::parse("invalid"), None);
    }

    #[test]
    fn test_default_ryuki_config() {
        let config = RyukiConfig::default();
        assert_eq!(config.auth_mode, AuthMode::MockDryRun);
        assert_eq!(config.database_provider, DatabaseProvider::CloudNativePg);
        assert_eq!(config.secret_provider, SecretProvider::HashicorpVault);
        assert_eq!(config.kubernetes_runtime, KubernetesRuntime::VsphereVks);
        assert_eq!(config.monitoring_provider, MonitoringProvider::Zabbix);
        assert_eq!(config.backup_provider, BackupProvider::Veeam);
        assert_eq!(config.logging.level, LogLevel::Info);
        assert_eq!(config.logging.format, LogFormat::Text);
        assert!(!config.rate_limit.enabled);
        assert_eq!(config.rate_limit.requests_per_second, 50);
        assert_eq!(config.server.shutdown_timeout_secs, 30);
    }

    #[test]
    fn test_validate_ryuki_config_valid() {
        let config = RyukiConfig::default();
        let errors = config.validate();
        assert!(errors.is_empty(), "expected no errors, got: {:?}", errors);
    }

    #[test]
    fn test_validate_ryuki_config_invalid_url() {
        let mut config = RyukiConfig::default();
        config.platform_url = "invalid-url".into();
        let errors = config.validate();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("platform_url")));
    }

    #[test]
    fn test_validate_ryuki_config_empty_database() {
        let mut config = RyukiConfig::default();
        config.database_url = String::new();
        let errors = config.validate();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("database_url")));
    }

    #[test]
    fn test_auth_mode_serde_roundtrip() {
        let mode = AuthMode::EntraId;
        let json = serde_json::to_string(&mode).unwrap();
        assert!(json.contains("entra-id"));
        let restored: AuthMode = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, AuthMode::EntraId);
    }

    #[test]
    fn test_provider_serde_roundtrip() {
        let provider = DatabaseProvider::CloudNativePg;
        let json = serde_json::to_string(&provider).unwrap();
        assert!(json.contains("cloud-native-pg"));
        let restored: DatabaseProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, DatabaseProvider::CloudNativePg);
    }

    #[test]
    fn test_auth_mode_as_str() {
        assert_eq!(AuthMode::MockDryRun.as_str(), "mock-dry-run");
        assert_eq!(AuthMode::EntraId.as_str(), "entra-id");
        assert_eq!(AuthMode::Local.as_str(), "local");
    }

    #[test]
    fn test_cors_config_default_origins() {
        let cors = CorsConfig::default();
        assert_eq!(cors.allowed_origins.len(), 2);
        assert!(
            cors.allowed_origins
                .contains(&"http://localhost:3000".to_string())
        );
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let rl = RateLimitConfig::default();
        assert!(!rl.enabled);
        assert_eq!(rl.requests_per_second, 50);
        assert_eq!(rl.burst_size, 100);
    }
}
