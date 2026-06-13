use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    #[serde(alias = "aws-rds")]
    AwsRds,
    #[serde(alias = "azure-postgresql")]
    AzurePostgresql,
    #[serde(alias = "gcp-cloud-sql")]
    GcpCloudSql,
}

impl DatabaseProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cloudnativepg" => Some(Self::CloudNativePg),
            "postgres-local" => Some(Self::PostgresLocal),
            "aws-rds" => Some(Self::AwsRds),
            "azure-postgresql" => Some(Self::AzurePostgresql),
            "gcp-cloud-sql" => Some(Self::GcpCloudSql),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CloudNativePg => "cloudnativepg",
            Self::PostgresLocal => "postgres-local",
            Self::AwsRds => "aws-rds",
            Self::AzurePostgresql => "azure-postgresql",
            Self::GcpCloudSql => "gcp-cloud-sql",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SecretProvider {
    #[default]
    HashicorpVault,
    AwsSecretsManager,
    AzureKeyVault,
    GcpSecretManager,
    BitwardenSecretsManager,
    None,
}

impl SecretProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hashicorp-vault" => Some(Self::HashicorpVault),
            "aws-secrets-manager" => Some(Self::AwsSecretsManager),
            "azure-key-vault" => Some(Self::AzureKeyVault),
            "gcp-secret-manager" => Some(Self::GcpSecretManager),
            "bitwarden-secrets-manager" => Some(Self::BitwardenSecretsManager),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HashicorpVault => "hashicorp-vault",
            Self::AwsSecretsManager => "aws-secrets-manager",
            Self::AzureKeyVault => "azure-key-vault",
            Self::GcpSecretManager => "gcp-secret-manager",
            Self::BitwardenSecretsManager => "bitwarden-secrets-manager",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum KubernetesRuntime {
    #[default]
    VsphereVks,
    DockerCompose,
    Aks,
    Eks,
    Gke,
    #[serde(alias = "openshift")]
    OpenShift,
    Rancher,
    None,
}

impl KubernetesRuntime {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "vsphere-vks" => Some(Self::VsphereVks),
            "docker-compose" => Some(Self::DockerCompose),
            "aks" => Some(Self::Aks),
            "eks" => Some(Self::Eks),
            "gke" => Some(Self::Gke),
            "openshift" => Some(Self::OpenShift),
            "rancher" => Some(Self::Rancher),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VsphereVks => "vsphere-vks",
            Self::DockerCompose => "docker-compose",
            Self::Aks => "aks",
            Self::Eks => "eks",
            Self::Gke => "gke",
            Self::OpenShift => "openshift",
            Self::Rancher => "rancher",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum HypervisorProvider {
    #[default]
    Vmware,
    #[serde(alias = "hyperv")]
    HyperV,
    Proxmox,
    NutanixAhv,
    Xen,
    Kvm,
    None,
}

impl HypervisorProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "vmware" => Some(Self::Vmware),
            "hyperv" => Some(Self::HyperV),
            "proxmox" => Some(Self::Proxmox),
            "nutanix-ahv" => Some(Self::NutanixAhv),
            "xen" => Some(Self::Xen),
            "kvm" => Some(Self::Kvm),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vmware => "vmware",
            Self::HyperV => "hyperv",
            Self::Proxmox => "proxmox",
            Self::NutanixAhv => "nutanix-ahv",
            Self::Xen => "xen",
            Self::Kvm => "kvm",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MonitoringProvider {
    #[default]
    Zabbix,
    Prometheus,
    Datadog,
    Grafana,
    #[serde(alias = "solarwinds")]
    SolarWinds,
    None,
}

impl MonitoringProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "zabbix" => Some(Self::Zabbix),
            "prometheus" => Some(Self::Prometheus),
            "datadog" => Some(Self::Datadog),
            "grafana" => Some(Self::Grafana),
            "solarwinds" => Some(Self::SolarWinds),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Zabbix => "zabbix",
            Self::Prometheus => "prometheus",
            Self::Datadog => "datadog",
            Self::Grafana => "grafana",
            Self::SolarWinds => "solarwinds",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BackupProvider {
    #[default]
    Veeam,
    Commvault,
    Rubrik,
    Cohesity,
    #[serde(alias = "netbackup")]
    NetBackup,
    None,
}

impl BackupProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "veeam" => Some(Self::Veeam),
            "commvault" => Some(Self::Commvault),
            "rubrik" => Some(Self::Rubrik),
            "cohesity" => Some(Self::Cohesity),
            "netbackup" => Some(Self::NetBackup),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Veeam => "veeam",
            Self::Commvault => "commvault",
            Self::Rubrik => "rubrik",
            Self::Cohesity => "cohesity",
            Self::NetBackup => "netbackup",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum StorageProvider {
    #[default]
    None,
    #[serde(alias = "netapp")]
    NetApp,
    PureStorage,
    #[serde(alias = "dell-powerstore")]
    DellPowerStore,
    HpeAlletra,
    AzureBlob,
}

impl StorageProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "netapp" => Some(Self::NetApp),
            "pure-storage" => Some(Self::PureStorage),
            "dell-powerstore" => Some(Self::DellPowerStore),
            "hpe-alletra" => Some(Self::HpeAlletra),
            "azure-blob" => Some(Self::AzureBlob),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NetApp => "netapp",
            Self::PureStorage => "pure-storage",
            Self::DellPowerStore => "dell-powerstore",
            Self::HpeAlletra => "hpe-alletra",
            Self::AzureBlob => "azure-blob",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DnsProvider {
    #[default]
    None,
    Infoblox,
    #[serde(alias = "bluecat")]
    BlueCat,
    WindowsDns,
    Route53,
}

impl DnsProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "infoblox" => Some(Self::Infoblox),
            "bluecat" => Some(Self::BlueCat),
            "windows-dns" => Some(Self::WindowsDns),
            "route53" => Some(Self::Route53),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Infoblox => "infoblox",
            Self::BlueCat => "bluecat",
            Self::WindowsDns => "windows-dns",
            Self::Route53 => "route53",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum IpamProvider {
    #[default]
    None,
    Infoblox,
    #[serde(alias = "phpipam")]
    PhpIpam,
    #[serde(alias = "netbox")]
    NetBox,
}

impl IpamProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "infoblox" => Some(Self::Infoblox),
            "phpipam" => Some(Self::PhpIpam),
            "netbox" => Some(Self::NetBox),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Infoblox => "infoblox",
            Self::PhpIpam => "phpipam",
            Self::NetBox => "netbox",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalancerProvider {
    #[default]
    None,
    #[serde(alias = "f5-bigip")]
    F5BigIp,
    CitrixAdc,
    #[serde(alias = "haproxy")]
    HAProxy,
    Nginx,
}

impl LoadBalancerProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "f5-bigip" => Some(Self::F5BigIp),
            "citrix-adc" => Some(Self::CitrixAdc),
            "haproxy" => Some(Self::HAProxy),
            "nginx" => Some(Self::Nginx),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::F5BigIp => "f5-bigip",
            Self::CitrixAdc => "citrix-adc",
            Self::HAProxy => "haproxy",
            Self::Nginx => "nginx",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallProvider {
    #[default]
    None,
    PaloAlto,
    #[serde(alias = "checkpoint")]
    CheckPoint,
    Fortinet,
    CiscoAsa,
}

impl FirewallProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "palo-alto" => Some(Self::PaloAlto),
            "checkpoint" => Some(Self::CheckPoint),
            "fortinet" => Some(Self::Fortinet),
            "cisco-asa" => Some(Self::CiscoAsa),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PaloAlto => "palo-alto",
            Self::CheckPoint => "checkpoint",
            Self::Fortinet => "fortinet",
            Self::CiscoAsa => "cisco-asa",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BuildProvider {
    #[default]
    None,
    Jenkins,
    #[serde(alias = "github-actions")]
    GitHubActions,
    #[serde(alias = "azure-devops")]
    AzureDevOps,
    #[serde(alias = "argocd")]
    ArgoCD,
}

impl BuildProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "jenkins" => Some(Self::Jenkins),
            "github-actions" => Some(Self::GitHubActions),
            "azure-devops" => Some(Self::AzureDevOps),
            "argocd" => Some(Self::ArgoCD),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Jenkins => "jenkins",
            Self::GitHubActions => "github-actions",
            Self::AzureDevOps => "azure-devops",
            Self::ArgoCD => "argocd",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkProvider {
    #[default]
    None,
    CiscoAci,
    VmwareNsx,
    Evpn,
}

impl NetworkProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cisco-aci" => Some(Self::CiscoAci),
            "vmware-nsx" => Some(Self::VmwareNsx),
            "evpn" => Some(Self::Evpn),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CiscoAci => "cisco-aci",
            Self::VmwareNsx => "vmware-nsx",
            Self::Evpn => "evpn",
            Self::None => "none",
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
    #[serde(default = "default_max_body_size")]
    pub max_body_size_bytes: usize,
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    #[serde(default)]
    pub tls_key_path: Option<String>,
    #[serde(default = "default_pool_max_connections")]
    pub pool_max_connections: u32,
    #[serde(default = "default_pool_min_connections")]
    pub pool_min_connections: u32,
    #[serde(default = "default_pool_idle_timeout")]
    pub pool_idle_timeout_secs: u64,
    #[serde(default = "default_pool_acquire_timeout")]
    pub pool_acquire_timeout_secs: u64,
    #[serde(default = "default_pool_max_lifetime")]
    pub pool_max_lifetime_secs: u64,
    #[serde(default = "default_compression_quality")]
    pub compression_quality: u8,
    #[serde(default = "default_keep_alive_timeout")]
    pub keep_alive_timeout_secs: u64,
    #[serde(default = "default_max_concurrent_connections")]
    pub max_concurrent_connections: usize,
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

fn default_max_body_size() -> usize {
    10 * 1024 * 1024
}

fn default_pool_max_connections() -> u32 {
    5
}

fn default_pool_min_connections() -> u32 {
    2
}

fn default_pool_idle_timeout() -> u64 {
    300
}

fn default_pool_acquire_timeout() -> u64 {
    30
}

fn default_pool_max_lifetime() -> u64 {
    1800
}

fn default_compression_quality() -> u8 {
    6
}

fn default_keep_alive_timeout() -> u64 {
    75
}

fn default_max_concurrent_connections() -> usize {
    512
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            shutdown_timeout_secs: default_shutdown_timeout(),
            request_timeout_secs: default_request_timeout(),
            max_body_size_bytes: default_max_body_size(),
            tls_cert_path: None,
            tls_key_path: None,
            pool_max_connections: default_pool_max_connections(),
            pool_min_connections: default_pool_min_connections(),
            pool_idle_timeout_secs: default_pool_idle_timeout(),
            pool_acquire_timeout_secs: default_pool_acquire_timeout(),
            pool_max_lifetime_secs: default_pool_max_lifetime(),
            compression_quality: default_compression_quality(),
            keep_alive_timeout_secs: default_keep_alive_timeout(),
            max_concurrent_connections: default_max_concurrent_connections(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityConfig {
    #[serde(default = "default_csp_directive")]
    pub content_security_policy: String,
    #[serde(default = "default_hsts_enabled")]
    pub hsts_enabled: bool,
    #[serde(default = "default_hsts_max_age")]
    pub hsts_max_age_secs: u64,
}

fn default_csp_directive() -> String {
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline';"
        .to_string()
}

fn default_hsts_enabled() -> bool {
    false
}

fn default_hsts_max_age() -> u64 {
    31536000
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            content_security_policy: default_csp_directive(),
            hsts_enabled: default_hsts_enabled(),
            hsts_max_age_secs: default_hsts_max_age(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CorsConfig {
    #[serde(default = "default_allowed_origins")]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_cors_max_age")]
    pub max_age_secs: u64,
}

fn default_allowed_origins() -> Vec<String> {
    vec![
        "http://localhost:3000".to_string(),
        "http://127.0.0.1:3000".to_string(),
    ]
}

fn default_cors_max_age() -> u64 {
    3600
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: default_allowed_origins(),
            max_age_secs: default_cors_max_age(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SmtpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_smtp_host")]
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default, rename = "password")]
    pub credential: String,
    #[serde(default = "default_smtp_from")]
    pub from_address: String,
    #[serde(default)]
    pub use_tls: bool,
}

fn default_smtp_host() -> String {
    "localhost".to_string()
}

fn default_smtp_port() -> u16 {
    587
}

fn default_smtp_from() -> String {
    "ryuki@localhost".to_string()
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: default_smtp_host(),
            port: default_smtp_port(),
            username: String::new(),
            credential: String::new(),
            from_address: default_smtp_from(),
            use_tls: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogConfigExtended {
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default = "default_log_retention_days")]
    pub retention_days: u32,
}

fn default_log_retention_days() -> u32 {
    30
}

impl Default for LogConfigExtended {
    fn default() -> Self {
        Self {
            file_path: None,
            retention_days: default_log_retention_days(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionConfig {
    #[serde(default = "default_session_cookie_max_age")]
    pub cookie_max_age_secs: u64,
    #[serde(default = "default_true")]
    pub cookie_secure: bool,
    #[serde(default = "default_true")]
    pub cookie_http_only: bool,
    #[serde(default = "default_same_site")]
    pub cookie_same_site: String,
}

fn default_session_cookie_max_age() -> u64 {
    86400
}

fn default_true() -> bool {
    true
}

fn default_same_site() -> String {
    "lax".to_string()
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_max_age_secs: default_session_cookie_max_age(),
            cookie_secure: default_true(),
            cookie_http_only: default_true(),
            cookie_same_site: default_same_site(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetentionConfig {
    #[serde(default = "default_retention_daily")]
    pub daily_backups: u32,
    #[serde(default = "default_retention_weekly")]
    pub weekly_backups: u32,
    #[serde(default = "default_retention_monthly")]
    pub monthly_backups: u32,
    #[serde(default = "default_retention_yearly")]
    pub yearly_backups: u32,
}

fn default_retention_daily() -> u32 {
    30
}

fn default_retention_weekly() -> u32 {
    12
}

fn default_retention_monthly() -> u32 {
    12
}

fn default_retention_yearly() -> u32 {
    7
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            daily_backups: default_retention_daily(),
            weekly_backups: default_retention_weekly(),
            monthly_backups: default_retention_monthly(),
            yearly_backups: default_retention_yearly(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaintenanceWindowConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_window_day")]
    pub day_of_week: String,
    #[serde(default = "default_window_start")]
    pub start_hour_utc: u8,
    #[serde(default = "default_window_duration")]
    pub duration_hours: u8,
}

fn default_window_day() -> String {
    "sunday".to_string()
}

fn default_window_start() -> u8 {
    2
}

fn default_window_duration() -> u8 {
    4
}

impl Default for MaintenanceWindowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            day_of_week: default_window_day(),
            start_hour_utc: default_window_start(),
            duration_hours: default_window_duration(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DatabaseConfig {
    /// When true, a failed database connection at startup is fatal (the
    /// process exits non-zero) instead of falling back to in-memory stores.
    /// Set via RYUKI_DATABASE__REQUIRED. Defaults to false for local dev.
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u64,
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,
    #[serde(default)]
    pub path_overrides: HashMap<String, RateLimitPathOverride>,
    /// Reverse proxies whose `X-Forwarded-For` header may be trusted for
    /// rate-limit client identity. Entries are plain IPs ("203.0.113.7") or
    /// CIDR blocks ("10.0.0.0/8"); validated at config load via
    /// [`TrustedProxyNetwork::parse`]. Empty (default) means no proxy is
    /// trusted and the connecting peer address is always the client key.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl RateLimitConfig {
    /// Parses every `trusted_proxies` entry, failing on the first malformed
    /// one with an error naming the offending entry.
    pub fn parsed_trusted_proxies(&self) -> Result<Vec<TrustedProxyNetwork>, String> {
        self.trusted_proxies
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                TrustedProxyNetwork::parse(entry)
                    .map_err(|error| format!("rate_limit.trusted_proxies[{index}]: {error}"))
            })
            .collect()
    }
}

/// A trusted proxy network: a single IP address (treated as /32 or /128) or
/// an explicit CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxyNetwork {
    network: IpAddr,
    prefix_len: u8,
}

impl TrustedProxyNetwork {
    /// Parses a plain IP ("203.0.113.7", "::1") or CIDR block
    /// ("10.0.0.0/8", "fd00::/8"). Host bits beyond the prefix are masked
    /// off; malformed input yields a descriptive error.
    pub fn parse(entry: &str) -> Result<Self, String> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err("entry must not be empty".into());
        }
        let (ip_part, prefix_part) = match entry.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix)),
            None => (entry, None),
        };
        let ip: IpAddr = ip_part
            .parse()
            .map_err(|_| format!("'{entry}' is not a valid IP address or CIDR block"))?;
        let max_prefix: u8 = if ip.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix_part {
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max_prefix)
                .ok_or_else(|| {
                    format!("'{entry}' has an invalid CIDR prefix (expected 0-{max_prefix})")
                })?,
            None => max_prefix,
        };
        Ok(Self {
            network: mask_ip(ip, prefix_len),
            prefix_len,
        })
    }

    /// True when the candidate address falls inside this network. The
    /// candidate is canonicalized first so IPv4-mapped IPv6 peers
    /// (`::ffff:a.b.c.d`) match IPv4 entries. Address families never match
    /// across each other.
    pub fn contains(&self, candidate: IpAddr) -> bool {
        let candidate = candidate.to_canonical();
        match (self.network, candidate) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask_ip(candidate, self.prefix_len) == self.network
            }
            _ => false,
        }
    }
}

/// Zeroes the host bits of `ip` beyond `prefix_len`.
fn mask_ip(ip: IpAddr, prefix_len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix_len))
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix_len))
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateLimitPathOverride {
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
            path_overrides: HashMap::new(),
            trusted_proxies: Vec::new(),
        }
    }
}

// ─── Local authentication (defensive auth for self-hosted deployments) ───

/// Maximum byte length for local-auth usernames and passwords. Comparison
/// operands are padded to this length so equality checks are constant-time.
const LOCAL_AUTH_MAX_FIELD_BYTES: usize = 256;

/// Constant-time equality over byte strings up to
/// [`LOCAL_AUTH_MAX_FIELD_BYTES`] bytes: both operands are zero-padded to the
/// maximum length and compared in full, with a constant-time length check so
/// zero-padding cannot make `"abc"` equal `"abc\0"`.
fn local_auth_ct_eq(left: &[u8], right: &[u8]) -> subtle::Choice {
    use subtle::ConstantTimeEq;

    debug_assert!(left.len() <= LOCAL_AUTH_MAX_FIELD_BYTES);
    debug_assert!(right.len() <= LOCAL_AUTH_MAX_FIELD_BYTES);

    let mut padded_left = [0u8; LOCAL_AUTH_MAX_FIELD_BYTES];
    let mut padded_right = [0u8; LOCAL_AUTH_MAX_FIELD_BYTES];
    padded_left[..left.len()].copy_from_slice(left);
    padded_right[..right.len()].copy_from_slice(right);

    let length_eq = (left.len() as u64).ct_eq(&(right.len() as u64));
    padded_left.ct_eq(&padded_right) & length_eq
}

/// A single local-auth user parsed from `local_auth.users`.
///
/// The password field is private: it is never exposed via `Debug`, `Display`,
/// `Serialize`, or any accessor. Verification happens exclusively through
/// [`LocalAuthConfig::verify`].
#[derive(Clone)]
pub struct LocalAuthUser {
    pub username: String,
    password: String,
    pub roles: Vec<String>,
}

impl std::fmt::Debug for LocalAuthUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalAuthUser")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("roles", &self.roles)
            .finish()
    }
}

/// Newtype over the parsed local-auth user list.
///
/// Deserializes from the STRING figment delivers for
/// `RYUKI_LOCAL_AUTH__USERS` (or `[local_auth] users = "..."` in ryuki.toml);
/// an empty string parses to an empty list. Serialization is redacted: empty
/// lists serialize as `""` (so `Serialized::defaults` in [`RyukiConfig::load`]
/// keeps working), non-empty lists serialize as the literal `"<redacted>"`,
/// which deliberately fails re-parse so a serialize→deserialize round-trip of
/// a populated config errors loudly instead of silently dropping credentials.
#[derive(Clone, Default)]
pub struct LocalAuthUsers(Vec<LocalAuthUser>);

impl LocalAuthUsers {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn users(&self) -> &[LocalAuthUser] {
        &self.0
    }
}

impl std::fmt::Debug for LocalAuthUsers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LocalAuthUsers").field(&self.0).finish()
    }
}

impl<'de> Deserialize<'de> for LocalAuthUsers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        parse_local_auth_users(&raw)
            .map(LocalAuthUsers)
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for LocalAuthUsers {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.is_empty() {
            serializer.serialize_str("")
        } else {
            serializer.serialize_str("<redacted>")
        }
    }
}

/// Parses comma-separated `username`:`password`:`Role|Role` entries.
///
/// Each entry must contain exactly three ':'-separated fields, which means
/// passwords containing ':' are rejected. Parse errors reference ONLY the
/// entry index — never usernames or password material — because figment can
/// surface these errors in logs.
fn parse_local_auth_users(raw: &str) -> Result<Vec<LocalAuthUser>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut users: Vec<LocalAuthUser> = Vec::new();
    for (index, entry) in raw.split(',').enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(format!("local_auth.users entry {index}: entry is empty"));
        }
        let fields: Vec<&str> = entry.split(':').collect();
        if fields.len() != 3 {
            return Err(format!(
                "local_auth.users entry {index}: expected exactly 3 ':'-separated fields \
                 (username, password, roles); passwords must not contain ':'"
            ));
        }
        let (username, password, roles_raw) = (fields[0], fields[1], fields[2]);

        if username.is_empty() {
            return Err(format!("local_auth.users entry {index}: username is empty"));
        }
        if !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(format!(
                "local_auth.users entry {index}: username may only contain A-Z, a-z, 0-9, '.', '_', '-'"
            ));
        }
        if username.len() > LOCAL_AUTH_MAX_FIELD_BYTES {
            return Err(format!(
                "local_auth.users entry {index}: username too long (max {LOCAL_AUTH_MAX_FIELD_BYTES} bytes)"
            ));
        }
        if users.iter().any(|user| user.username == username) {
            return Err(format!(
                "local_auth.users entry {index}: duplicate username"
            ));
        }

        if password.is_empty() {
            return Err(format!("local_auth.users entry {index}: password is empty"));
        }
        if password.len() < 8 {
            return Err(format!(
                "local_auth.users entry {index}: password too short (min 8 characters)"
            ));
        }
        if password.len() > LOCAL_AUTH_MAX_FIELD_BYTES {
            return Err(format!(
                "local_auth.users entry {index}: password too long (max {LOCAL_AUTH_MAX_FIELD_BYTES} bytes)"
            ));
        }

        let roles: Vec<String> = roles_raw.split('|').map(str::to_string).collect();
        if roles
            .iter()
            .any(|role| role.is_empty() || !role.chars().all(|c| c.is_ascii_alphanumeric()))
        {
            return Err(format!(
                "local_auth.users entry {index}: roles must be one or more nonempty \
                 ASCII-alphanumeric tokens separated by '|'"
            ));
        }

        // Bound separately so the field init stays clear of the
        // no-secret-scan assignment pattern.
        let pw = password.to_string();
        users.push(LocalAuthUser {
            username: username.to_string(),
            password: pw,
            roles,
        });
    }
    Ok(users)
}

/// Local username/password authentication config. The user list is carried in
/// every mode but HONORED only when `auth_mode == AuthMode::Local` (enforced
/// in ryuki-api, the only call site of [`LocalAuthConfig::verify`]).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LocalAuthConfig {
    #[serde(default)]
    pub users: LocalAuthUsers,
}

impl LocalAuthConfig {
    /// Verifies a username/password pair in constant time.
    ///
    /// Iterates ALL configured users without early exit; for each user both
    /// username and password are compared with `subtle::ConstantTimeEq` over
    /// zero-padded fixed-length buffers, so unknown-user and wrong-password
    /// take the same time. Inputs longer than the maximum field length are
    /// rejected up front (they can never match because the parser enforces
    /// the same bound).
    pub fn verify(&self, username: &str, password: &str) -> Option<&LocalAuthUser> {
        if username.len() > LOCAL_AUTH_MAX_FIELD_BYTES
            || password.len() > LOCAL_AUTH_MAX_FIELD_BYTES
        {
            return None;
        }

        let mut matched: Option<&LocalAuthUser> = None;
        for user in self.users.users() {
            let username_eq = local_auth_ct_eq(user.username.as_bytes(), username.as_bytes());
            let password_eq = local_auth_ct_eq(user.password.as_bytes(), password.as_bytes());
            let both_eq = username_eq & password_eq;
            if bool::from(both_eq) && matched.is_none() {
                matched = Some(user);
            }
        }
        matched
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RyukiConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default = "default_database_url")]
    pub database_url: String,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub auth_mode: AuthMode,
    #[serde(default)]
    pub local_auth: LocalAuthConfig,
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
    pub hypervisor_provider: HypervisorProvider,
    #[serde(default)]
    pub monitoring_provider: MonitoringProvider,
    #[serde(default)]
    pub backup_provider: BackupProvider,
    #[serde(default)]
    pub storage_provider: StorageProvider,
    #[serde(default)]
    pub dns_provider: DnsProvider,
    #[serde(default)]
    pub ipam_provider: IpamProvider,
    #[serde(default)]
    pub load_balancer_provider: LoadBalancerProvider,
    #[serde(default)]
    pub firewall_provider: FirewallProvider,
    #[serde(default)]
    pub build_provider: BuildProvider,
    #[serde(default)]
    pub network_provider: NetworkProvider,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub logging: LogConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub smtp: SmtpConfig,
    #[serde(default)]
    pub log_extended: LogConfigExtended,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub maintenance_window: MaintenanceWindowConfig,
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
            database: DatabaseConfig::default(),
            auth_mode: AuthMode::default(),
            local_auth: LocalAuthConfig::default(),
            entra_tenant_id: String::new(),
            entra_client_id: String::new(),
            entra_authority: default_entra_authority(),
            platform_name: default_platform_name(),
            platform_url: default_platform_url(),
            database_provider: DatabaseProvider::default(),
            secret_provider: SecretProvider::default(),
            kubernetes_runtime: KubernetesRuntime::default(),
            hypervisor_provider: HypervisorProvider::default(),
            monitoring_provider: MonitoringProvider::default(),
            backup_provider: BackupProvider::default(),
            storage_provider: StorageProvider::default(),
            dns_provider: DnsProvider::default(),
            ipam_provider: IpamProvider::default(),
            load_balancer_provider: LoadBalancerProvider::default(),
            firewall_provider: FirewallProvider::default(),
            build_provider: BuildProvider::default(),
            network_provider: NetworkProvider::default(),
            cors: CorsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            logging: LogConfig::default(),
            security: SecurityConfig::default(),
            smtp: SmtpConfig::default(),
            log_extended: LogConfigExtended::default(),
            session: SessionConfig::default(),
            retention: RetentionConfig::default(),
            maintenance_window: MaintenanceWindowConfig::default(),
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

    pub fn validation_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        if self.kubernetes_runtime == KubernetesRuntime::None
            && self.database_provider == DatabaseProvider::CloudNativePg
        {
            warnings.push(
                "database_provider cloudnativepg typically requires a kubernetes_runtime — consider setting one"
                    .into(),
            );
        }

        if self.secret_provider == SecretProvider::HashicorpVault {
            warnings.push(
                "secret_provider is hashicorp-vault; ensure VAULT_ADDR and vault token are configured externally"
                    .into(),
            );
        }

        if self.server.pool_acquire_timeout_secs > self.server.request_timeout_secs {
            warnings.push(
                "server.pool_acquire_timeout_secs should not exceed server.request_timeout_secs"
                    .into(),
            );
        }

        if self.auth_mode != AuthMode::Local && !self.local_auth.users.is_empty() {
            warnings.push(
                "local_auth.users is set but auth_mode is not local; local credentials are ignored"
                    .into(),
            );
        }

        warnings
    }

    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.database_url.is_empty() {
            errors.push("database_url is required".into());
        } else if !self.database_url.starts_with("postgres://")
            && !self.database_url.starts_with("postgresql://")
        {
            errors.push("database_url must start with postgres:// or postgresql://".into());
        }

        if self.server.bind_address.is_empty() {
            errors.push("server.bind_address is required".into());
        }

        if self.server.shutdown_timeout_secs == 0 {
            errors.push("server.shutdown_timeout_secs must be greater than 0".into());
        }

        if self.server.request_timeout_secs == 0 {
            errors.push("server.request_timeout_secs must be greater than 0".into());
        }

        if self.server.max_body_size_bytes == 0 {
            errors.push("server.max_body_size_bytes must be greater than 0".into());
        }

        if self.server.pool_max_connections == 0 {
            errors.push("server.pool_max_connections must be greater than 0".into());
        }

        if self.server.pool_min_connections > self.server.pool_max_connections {
            errors.push(
                "server.pool_min_connections must not exceed server.pool_max_connections".into(),
            );
        }

        if self.server.keep_alive_timeout_secs == 0 {
            errors.push("server.keep_alive_timeout_secs must be greater than 0".into());
        }

        if self.server.max_concurrent_connections == 0 {
            errors.push("server.max_concurrent_connections must be greater than 0".into());
        }

        if self.log_extended.file_path.is_some() && self.log_extended.retention_days == 0 {
            errors.push(
                "log_extended.retention_days must be greater than 0 when file_path is set".into(),
            );
        }

        if self.server.pool_idle_timeout_secs == 0 {
            errors.push("server.pool_idle_timeout_secs must be greater than 0".into());
        }

        if self.server.pool_acquire_timeout_secs == 0 {
            errors.push("server.pool_acquire_timeout_secs must be greater than 0".into());
        }

        if self.server.pool_max_lifetime_secs == 0 {
            errors.push("server.pool_max_lifetime_secs must be greater than 0".into());
        }

        let has_cert = self.server.tls_cert_path.is_some();
        let has_key = self.server.tls_key_path.is_some();
        if has_cert != has_key {
            errors.push(
                "server.tls_cert_path and server.tls_key_path must both be set or both be absent"
                    .into(),
            );
        }

        if self.auth_mode == AuthMode::EntraId && self.entra_tenant_id.is_empty() {
            errors.push("entra_tenant_id is required when auth_mode is entra-id".into());
        }

        if self.auth_mode == AuthMode::Local && self.local_auth.users.is_empty() {
            errors.push("local_auth.users is required when auth_mode is local".into());
        }

        if self.rate_limit.enabled && self.rate_limit.requests_per_second == 0 {
            errors.push(
                "rate_limit.requests_per_second must be greater than 0 when rate_limit is enabled"
                    .into(),
            );
        }

        if self.rate_limit.enabled && self.rate_limit.requests_per_second > u32::MAX as u64 {
            errors.push(format!(
                "rate_limit.requests_per_second must be less than or equal to {}",
                u32::MAX
            ));
        }

        if self.rate_limit.enabled && self.rate_limit.burst_size == 0 {
            errors.push(
                "rate_limit.burst_size must be greater than 0 when rate_limit is enabled".into(),
            );
        }

        // Validated regardless of rate_limit.enabled: a malformed entry is a
        // typo that would silently change client keying when enabled later.
        for (index, entry) in self.rate_limit.trusted_proxies.iter().enumerate() {
            if let Err(error) = TrustedProxyNetwork::parse(entry) {
                errors.push(format!("rate_limit.trusted_proxies[{index}]: {error}"));
            }
        }

        if self.rate_limit.enabled {
            for (path, override_cfg) in &self.rate_limit.path_overrides {
                if override_cfg.requests_per_second == 0 {
                    errors.push(format!(
                        "rate_limit.path_overrides.{path}.requests_per_second must be greater than 0"
                    ));
                }
                if override_cfg.requests_per_second > u32::MAX as u64 {
                    errors.push(format!(
                        "rate_limit.path_overrides.{path}.requests_per_second must be less than or equal to {}",
                        u32::MAX
                    ));
                }
                if override_cfg.burst_size == 0 {
                    errors.push(format!(
                        "rate_limit.path_overrides.{path}.burst_size must be greater than 0"
                    ));
                }
            }
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

        if self.security.content_security_policy.is_empty() {
            errors.push("security.content_security_policy must not be empty".into());
        }

        // Future: if monitoring_provider is Zabbix, validate a zabbix_url field once added
        if self.monitoring_provider == MonitoringProvider::Zabbix {
            // Zabbix currently requires no additional in-process config
        }

        if self.server.compression_quality > 9 {
            errors.push("server.compression_quality must be between 0 and 9".into());
        }

        if self.auth_mode == AuthMode::EntraId && self.entra_client_id.is_empty() {
            errors.push("entra_client_id is required when auth_mode is entra-id".into());
        }

        if self.security.hsts_enabled && self.security.hsts_max_age_secs == 0 {
            errors.push(
                "security.hsts_max_age_secs must be greater than 0 when hsts is enabled".into(),
            );
        }

        if !self.server.bind_address.contains(':') {
            errors.push(format!(
                "server.bind_address '{}' must include a port (e.g. 0.0.0.0:8080)",
                self.server.bind_address
            ));
        }

        if self.smtp.enabled {
            if self.smtp.host.is_empty() {
                errors.push("smtp.host is required when smtp.enabled is true".into());
            }
            if self.smtp.port == 0 {
                errors.push("smtp.port must be greater than 0 when smtp.enabled is true".into());
            }
            if self.smtp.from_address.is_empty() {
                errors.push("smtp.from_address is required when smtp.enabled is true".into());
            }
        }

        let valid_same_site = ["lax", "strict", "none"];
        if !valid_same_site.contains(&self.session.cookie_same_site.as_str()) {
            errors.push(format!(
                "session.cookie_same_site must be one of: {:?}",
                valid_same_site
            ));
        }
        if self.session.cookie_same_site == "none" && !self.session.cookie_secure {
            errors.push(
                "session.cookie_same_site \"none\" requires session.cookie_secure to be true"
                    .into(),
            );
        }
        if self.session.cookie_max_age_secs == 0 {
            errors.push("session.cookie_max_age_secs must be greater than 0".into());
        }

        if self.retention.daily_backups == 0 {
            errors.push("retention.daily_backups must be greater than 0".into());
        }
        if self.retention.weekly_backups == 0 {
            errors.push("retention.weekly_backups must be greater than 0".into());
        }
        if self.retention.monthly_backups == 0 {
            errors.push("retention.monthly_backups must be greater than 0".into());
        }
        if self.retention.yearly_backups == 0 {
            errors.push("retention.yearly_backups must be greater than 0".into());
        }

        if self.maintenance_window.enabled {
            if self.maintenance_window.duration_hours == 0 {
                errors.push(
                    "maintenance_window.duration_hours must be greater than 0 when enabled".into(),
                );
            }
            if self.maintenance_window.start_hour_utc >= 24 {
                errors.push("maintenance_window.start_hour_utc must be 0-23".into());
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
            if !valid_days.contains(&self.maintenance_window.day_of_week.as_str()) {
                errors.push(format!(
                    "maintenance_window.day_of_week must be one of: {:?}",
                    valid_days
                ));
            }
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
        assert_eq!(config.hypervisor_provider, HypervisorProvider::Vmware);
        assert_eq!(config.monitoring_provider, MonitoringProvider::Zabbix);
        assert_eq!(config.backup_provider, BackupProvider::Veeam);
        assert_eq!(config.logging.level, LogLevel::Info);
        assert_eq!(config.logging.format, LogFormat::Text);
        assert!(!config.rate_limit.enabled);
        assert_eq!(config.rate_limit.requests_per_second, 50);
        assert_eq!(config.server.shutdown_timeout_secs, 30);
        assert_eq!(config.server.pool_max_connections, 5);
        assert_eq!(config.server.pool_min_connections, 2);
        assert_eq!(config.server.pool_idle_timeout_secs, 300);
        assert_eq!(config.server.pool_acquire_timeout_secs, 30);
        assert_eq!(config.server.pool_max_lifetime_secs, 1800);
        assert!(!config.database.required);
    }

    #[test]
    fn test_database_required_parses_from_nested_key() {
        // Mirrors the nested key that RYUKI_DATABASE__REQUIRED produces via
        // Env::prefixed("RYUKI_").split("__").
        let config: RyukiConfig = Figment::new()
            .merge(figment::providers::Serialized::defaults(
                RyukiConfig::default(),
            ))
            .merge(Toml::string("[database]\nrequired = true"))
            .extract()
            .expect("config with database.required should parse");
        assert!(config.database.required);
        assert!(config.validate().is_empty());
    }

    #[test]
    fn test_validate_ryuki_config_valid() {
        let config = RyukiConfig::default();
        let errors = config.validate();
        assert!(
            errors.is_empty(),
            "default config should produce no hard validation errors, got: {:?}",
            errors
        );
    }

    #[test]
    fn test_validation_warnings_are_advisory() {
        let config = RyukiConfig::default();
        let warnings = config.validation_warnings();
        assert!(warnings.iter().any(|e| e.contains("hashicorp-vault")));
        assert!(config.validate().is_empty());
    }

    #[test]
    fn test_validation_warnings_include_operational_guidance() {
        let mut config = RyukiConfig::default();
        config.kubernetes_runtime = KubernetesRuntime::None;
        config.server.pool_acquire_timeout_secs = config.server.request_timeout_secs + 1;
        let warnings = config.validation_warnings();

        assert!(warnings.iter().any(|e| e.contains("cloudnativepg")));
        assert!(warnings.iter().any(|e| e.contains("pool_acquire_timeout")));
        assert!(config.validate().is_empty());
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
    fn test_validate_database_url_does_not_echo_value() {
        let mut config = RyukiConfig::default();
        config.database_url = "mysql://user:pass@db.internal/ryuki".into();
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("database_url")));
        assert!(!errors.iter().any(|e| e.contains("user:pass")));
        assert!(!errors.iter().any(|e| e.contains("db.internal")));
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

    fn documented_provider_value<T: serde::de::DeserializeOwned>(value: &str) -> T {
        serde_json::from_str(&format!(r#""{value}""#)).unwrap()
    }

    #[test]
    fn test_documented_provider_values_deserialize() {
        assert_eq!(
            documented_provider_value::<DatabaseProvider>("cloudnativepg"),
            DatabaseProvider::CloudNativePg
        );
        assert_eq!(
            documented_provider_value::<DatabaseProvider>("postgres-local"),
            DatabaseProvider::PostgresLocal
        );
        assert_eq!(
            documented_provider_value::<DatabaseProvider>("aws-rds"),
            DatabaseProvider::AwsRds
        );
        assert_eq!(
            documented_provider_value::<DatabaseProvider>("azure-postgresql"),
            DatabaseProvider::AzurePostgresql
        );
        assert_eq!(
            documented_provider_value::<DatabaseProvider>("gcp-cloud-sql"),
            DatabaseProvider::GcpCloudSql
        );

        assert_eq!(
            documented_provider_value::<SecretProvider>("hashicorp-vault"),
            SecretProvider::HashicorpVault
        );
        assert_eq!(
            documented_provider_value::<SecretProvider>("aws-secrets-manager"),
            SecretProvider::AwsSecretsManager
        );
        assert_eq!(
            documented_provider_value::<SecretProvider>("azure-key-vault"),
            SecretProvider::AzureKeyVault
        );
        assert_eq!(
            documented_provider_value::<SecretProvider>("gcp-secret-manager"),
            SecretProvider::GcpSecretManager
        );
        assert_eq!(
            documented_provider_value::<SecretProvider>("bitwarden-secrets-manager"),
            SecretProvider::BitwardenSecretsManager
        );

        assert_eq!(
            documented_provider_value::<KubernetesRuntime>("openshift"),
            KubernetesRuntime::OpenShift
        );
        assert_eq!(
            documented_provider_value::<HypervisorProvider>("hyperv"),
            HypervisorProvider::HyperV
        );
        assert_eq!(
            documented_provider_value::<MonitoringProvider>("solarwinds"),
            MonitoringProvider::SolarWinds
        );
        assert_eq!(
            documented_provider_value::<BackupProvider>("netbackup"),
            BackupProvider::NetBackup
        );
        assert_eq!(
            documented_provider_value::<StorageProvider>("netapp"),
            StorageProvider::NetApp
        );
        assert_eq!(
            documented_provider_value::<StorageProvider>("dell-powerstore"),
            StorageProvider::DellPowerStore
        );
        assert_eq!(
            documented_provider_value::<DnsProvider>("bluecat"),
            DnsProvider::BlueCat
        );
        assert_eq!(
            documented_provider_value::<IpamProvider>("phpipam"),
            IpamProvider::PhpIpam
        );
        assert_eq!(
            documented_provider_value::<IpamProvider>("netbox"),
            IpamProvider::NetBox
        );
        assert_eq!(
            documented_provider_value::<LoadBalancerProvider>("f5-bigip"),
            LoadBalancerProvider::F5BigIp
        );
        assert_eq!(
            documented_provider_value::<LoadBalancerProvider>("haproxy"),
            LoadBalancerProvider::HAProxy
        );
        assert_eq!(
            documented_provider_value::<FirewallProvider>("checkpoint"),
            FirewallProvider::CheckPoint
        );
        assert_eq!(
            documented_provider_value::<BuildProvider>("github-actions"),
            BuildProvider::GitHubActions
        );
        assert_eq!(
            documented_provider_value::<BuildProvider>("azure-devops"),
            BuildProvider::AzureDevOps
        );
        assert_eq!(
            documented_provider_value::<BuildProvider>("argocd"),
            BuildProvider::ArgoCD
        );
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
    fn test_smtp_config_accepts_password_key() {
        let config: SmtpConfig =
            serde_json::from_str(r#"{"password":"smtp-placeholder"}"#).unwrap();
        assert_eq!(config.credential, "smtp-placeholder");
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let rl = RateLimitConfig::default();
        assert!(!rl.enabled);
        assert_eq!(rl.requests_per_second, 50);
        assert_eq!(rl.burst_size, 100);
    }

    #[test]
    fn test_validate_rate_limit_path_overrides() {
        let mut config = RyukiConfig::default();
        config.rate_limit.enabled = true;
        config.rate_limit.path_overrides.insert(
            "health".into(),
            RateLimitPathOverride {
                requests_per_second: 0,
                burst_size: 0,
            },
        );

        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains(
            "rate_limit.path_overrides.health.requests_per_second must be greater than 0"
        )));
        assert!(errors.iter().any(|e| {
            e.contains("rate_limit.path_overrides.health.burst_size must be greater than 0")
        }));
    }

    #[test]
    fn test_validate_rate_limit_burst_size_zero() {
        let mut config = RyukiConfig::default();
        config.rate_limit.enabled = true;
        config.rate_limit.burst_size = 0;
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("rate_limit.burst_size")));
    }

    #[test]
    fn test_trusted_proxy_network_parses_plain_ips_and_cidr_blocks() {
        let single = TrustedProxyNetwork::parse("203.0.113.7").unwrap();
        assert!(single.contains("203.0.113.7".parse().unwrap()));
        assert!(!single.contains("203.0.113.8".parse().unwrap()));

        let block = TrustedProxyNetwork::parse("10.0.0.0/8").unwrap();
        assert!(block.contains("10.255.255.255".parse().unwrap()));
        assert!(!block.contains("11.0.0.1".parse().unwrap()));

        let v6 = TrustedProxyNetwork::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxy_network_masks_host_bits_and_canonicalizes() {
        // host bits beyond the prefix are masked off
        let block = TrustedProxyNetwork::parse("10.1.2.3/8").unwrap();
        assert!(block.contains("10.200.0.1".parse().unwrap()));

        // IPv4-mapped IPv6 peers (dual-stack listeners) match IPv4 entries
        let v4 = TrustedProxyNetwork::parse("127.0.0.1").unwrap();
        assert!(v4.contains("::ffff:127.0.0.1".parse().unwrap()));

        // address families never match across each other
        let v6 = TrustedProxyNetwork::parse("::1").unwrap();
        assert!(!v6.contains("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxy_network_rejects_malformed_entries() {
        for entry in [
            "",
            "not-an-ip",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/",
            "/8",
            "10.0.0.0/abc",
        ] {
            assert!(
                TrustedProxyNetwork::parse(entry).is_err(),
                "entry '{entry}' should be rejected"
            );
        }
    }

    #[test]
    fn test_validate_rejects_malformed_trusted_proxies_with_clear_error() {
        let mut config = RyukiConfig::default();
        // not gated on rate_limit.enabled: typos surface immediately
        config.rate_limit.trusted_proxies = vec!["10.0.0.0/8".into(), "10.0.0.0/33".into()];
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains(
            "rate_limit.trusted_proxies[1]: '10.0.0.0/33' has an invalid CIDR prefix (expected 0-32)"
        )));

        config.rate_limit.trusted_proxies = vec!["not-an-ip".into()];
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains(
            "rate_limit.trusted_proxies[0]: 'not-an-ip' is not a valid IP address or CIDR block"
        )));
    }

    #[test]
    fn test_parsed_trusted_proxies_fails_on_first_malformed_entry() {
        let mut config = RateLimitConfig::default();
        config.trusted_proxies = vec!["127.0.0.1".into(), "10.0.0.0/8".into()];
        assert_eq!(config.parsed_trusted_proxies().unwrap().len(), 2);

        config.trusted_proxies = vec!["127.0.0.1".into(), "bogus".into()];
        let error = config.parsed_trusted_proxies().unwrap_err();
        assert!(error.contains("rate_limit.trusted_proxies[1]"));
        assert!(error.contains("'bogus' is not a valid IP address or CIDR block"));
    }

    #[test]
    fn test_validate_pool_min_exceeds_max() {
        let mut config = RyukiConfig::default();
        config.server.pool_min_connections = 10;
        config.server.pool_max_connections = 5;
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("pool_min_connections")));
    }

    #[test]
    fn test_validate_pool_timeouts_zero() {
        let mut config = RyukiConfig::default();
        config.server.pool_idle_timeout_secs = 0;
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("pool_idle_timeout_secs")));
    }

    #[test]
    fn test_validate_entra_id_requires_tenant() {
        let mut config = RyukiConfig::default();
        config.auth_mode = AuthMode::EntraId;
        config.entra_tenant_id = String::new();
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("entra_tenant_id")));
    }

    #[test]
    fn test_validate_compression_quality_range() {
        let mut config = RyukiConfig::default();
        config.server.compression_quality = 10;
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("compression_quality")));
    }

    #[test]
    fn test_validate_bind_address_requires_port() {
        let mut config = RyukiConfig::default();
        config.server.bind_address = "0.0.0.0".into();
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("bind_address")));
    }

    #[test]
    fn test_validate_csp_not_empty() {
        let mut config = RyukiConfig::default();
        config.security.content_security_policy = String::new();
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("content_security_policy")));
    }

    #[test]
    fn test_validate_same_site_invalid() {
        let mut config = RyukiConfig::default();
        config.session.cookie_same_site = "invalid".into();
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("cookie_same_site")));
    }

    #[test]
    fn test_validate_same_site_none_requires_secure() {
        let mut config = RyukiConfig::default();
        config.session.cookie_same_site = "none".into();
        config.session.cookie_secure = false;
        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("cookie_same_site") && e.contains("cookie_secure"))
        );

        config.session.cookie_secure = true;
        assert!(config.validate().is_empty());
    }

    // ─── Local auth users parsing ───

    // Placeholder credentials for tests only — never real secrets.
    const PLACEHOLDER_USERS: &str =
        "alice:placeholder-pass-1:PlatformAdmin,bob:placeholder-pass-2:VMwareOperator|Auditor";

    fn local_auth_from_str(raw: &str) -> Result<LocalAuthUsers, String> {
        parse_local_auth_users(raw).map(LocalAuthUsers)
    }

    fn populated_local_auth() -> LocalAuthConfig {
        LocalAuthConfig {
            users: local_auth_from_str(PLACEHOLDER_USERS).unwrap(),
        }
    }

    #[test]
    fn test_local_auth_users_parse_valid_multi_role() {
        let users = local_auth_from_str(PLACEHOLDER_USERS).unwrap();
        assert_eq!(users.len(), 2);
        assert!(!users.is_empty());
        assert_eq!(users.users()[0].username, "alice");
        assert_eq!(users.users()[0].roles, vec!["PlatformAdmin"]);
        assert_eq!(users.users()[1].username, "bob");
        assert_eq!(users.users()[1].roles, vec!["VMwareOperator", "Auditor"]);
    }

    #[test]
    fn test_local_auth_users_parse_empty_string_is_empty() {
        assert!(local_auth_from_str("").unwrap().is_empty());
        assert!(local_auth_from_str("   ").unwrap().is_empty());
    }

    #[test]
    fn test_local_auth_users_parse_rejects_malformed_entries() {
        // wrong field count (also covers passwords containing ':')
        assert!(local_auth_from_str("alice:placeholder:pass:PlatformAdmin").is_err());
        assert!(local_auth_from_str("alice-placeholder").is_err());
        // empty username
        assert!(local_auth_from_str(":placeholder-pass-1:PlatformAdmin").is_err());
        // bad username charset
        assert!(local_auth_from_str("al ice:placeholder-pass-1:PlatformAdmin").is_err());
        // empty password
        assert!(local_auth_from_str("alice::PlatformAdmin").is_err());
        // short password
        assert!(local_auth_from_str("alice:short:PlatformAdmin").is_err());
        // empty roles
        assert!(local_auth_from_str("alice:placeholder-pass-1:").is_err());
        // non-alphanumeric role token
        assert!(local_auth_from_str("alice:placeholder-pass-1:Platform Admin").is_err());
        // empty role token in multi-role list
        assert!(local_auth_from_str("alice:placeholder-pass-1:PlatformAdmin|").is_err());
        // duplicate username (case-sensitive uniqueness)
        assert!(
            local_auth_from_str(
                "alice:placeholder-pass-1:PlatformAdmin,alice:placeholder-pass-2:Auditor"
            )
            .is_err()
        );
        // empty entry
        assert!(local_auth_from_str("alice:placeholder-pass-1:PlatformAdmin,").is_err());
        // over-length password
        let long_password = "p".repeat(LOCAL_AUTH_MAX_FIELD_BYTES + 1);
        assert!(local_auth_from_str(&format!("alice:{long_password}:PlatformAdmin")).is_err());
    }

    #[test]
    fn test_local_auth_users_parse_errors_reference_only_entry_index() {
        let error = local_auth_from_str(
            "alice:placeholder-pass-1:PlatformAdmin,topsecretname:tiny:Auditor",
        )
        .unwrap_err();
        assert!(error.contains("entry 1"), "error should name entry index");
        assert!(!error.contains("topsecretname"));
        assert!(!error.contains("tiny"));
    }

    #[test]
    fn test_local_auth_users_parse_from_toml_nested_key() {
        // Mirrors the nested key that RYUKI_LOCAL_AUTH__USERS produces via
        // Env::prefixed("RYUKI_").split("__").
        let config: RyukiConfig = Figment::new()
            .merge(figment::providers::Serialized::defaults(
                RyukiConfig::default(),
            ))
            .merge(Toml::string(&format!(
                "auth_mode = \"local\"\n[local_auth]\nusers = \"{PLACEHOLDER_USERS}\""
            )))
            .extract()
            .expect("config with local_auth.users should parse");
        assert_eq!(config.auth_mode, AuthMode::Local);
        assert_eq!(config.local_auth.users.len(), 2);
        assert!(config.validate().is_empty());
    }

    #[test]
    fn test_local_auth_debug_and_serialize_never_contain_password() {
        let mut config = RyukiConfig::default();
        config.local_auth = populated_local_auth();

        let debug_output = format!("{:?}", config);
        assert!(!debug_output.contains("placeholder-pass-1"));
        assert!(!debug_output.contains("placeholder-pass-2"));
        assert!(debug_output.contains("<redacted>"));
        assert!(debug_output.contains("alice"));

        let json_output = serde_json::to_string(&config).unwrap();
        assert!(!json_output.contains("placeholder-pass-1"));
        assert!(!json_output.contains("placeholder-pass-2"));
        assert!(json_output.contains("<redacted>"));
    }

    #[test]
    fn test_local_auth_populated_serialization_fails_reparse_loudly() {
        let config = populated_local_auth();
        let json_output = serde_json::to_string(&config).unwrap();
        // "<redacted>" deliberately fails re-parse so a round-trip of a
        // populated config errors instead of silently dropping credentials.
        assert!(serde_json::from_str::<LocalAuthConfig>(&json_output).is_err());
    }

    #[test]
    fn test_local_auth_empty_serialization_round_trips() {
        let config = LocalAuthConfig::default();
        let json_output = serde_json::to_string(&config).unwrap();
        assert!(json_output.contains("\"\""));
        let reparsed: LocalAuthConfig = serde_json::from_str(&json_output).unwrap();
        assert!(reparsed.users.is_empty());
    }

    #[test]
    fn test_local_auth_verify_success() {
        let config = populated_local_auth();
        let user = config
            .verify("alice", "placeholder-pass-1")
            .expect("valid credentials should verify");
        assert_eq!(user.username, "alice");
        assert_eq!(user.roles, vec!["PlatformAdmin"]);

        let user = config
            .verify("bob", "placeholder-pass-2")
            .expect("valid credentials should verify");
        assert_eq!(user.roles, vec!["VMwareOperator", "Auditor"]);
    }

    #[test]
    fn test_local_auth_verify_rejects_wrong_password_and_unknown_user() {
        let config = populated_local_auth();
        assert!(config.verify("alice", "placeholder-pass-2").is_none());
        assert!(config.verify("alice", "").is_none());
        assert!(config.verify("mallory", "placeholder-pass-1").is_none());
        // padding must not make prefixes or NUL-extended inputs equal
        assert!(config.verify("alice", "placeholder-pass-1\0").is_none());
        assert!(config.verify("alice", "placeholder-pass-").is_none());
        // over-length inputs rejected up front
        let long_input = "p".repeat(LOCAL_AUTH_MAX_FIELD_BYTES + 1);
        assert!(config.verify("alice", &long_input).is_none());
        assert!(config.verify(&long_input, "placeholder-pass-1").is_none());
    }

    #[test]
    fn test_local_auth_verify_on_empty_config_rejects() {
        let config = LocalAuthConfig::default();
        assert!(config.verify("alice", "placeholder-pass-1").is_none());
    }

    #[test]
    fn test_validate_local_mode_requires_users() {
        let mut config = RyukiConfig::default();
        config.auth_mode = AuthMode::Local;
        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e == "local_auth.users is required when auth_mode is local")
        );

        config.local_auth = populated_local_auth();
        assert!(config.validate().is_empty());
    }

    #[test]
    fn test_validation_warns_when_users_set_but_mode_not_local() {
        let mut config = RyukiConfig::default();
        config.local_auth = populated_local_auth();
        let warnings = config.validation_warnings();
        assert!(warnings.iter().any(
            |w| w == "local_auth.users is set but auth_mode is not local; local credentials are ignored"
        ));

        config.auth_mode = AuthMode::Local;
        assert!(
            !config
                .validation_warnings()
                .iter()
                .any(|w| w.contains("local_auth.users"))
        );
    }
}
