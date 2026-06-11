use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogSourceType {
    WindowsEventLog,
    Syslog,
    Auditd,
    IIS,
    Apache,
}

impl std::fmt::Display for LogSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogSourceType::WindowsEventLog => write!(f, "windows-event-log"),
            LogSourceType::Syslog => write!(f, "syslog"),
            LogSourceType::Auditd => write!(f, "auditd"),
            LogSourceType::IIS => write!(f, "iis"),
            LogSourceType::Apache => write!(f, "apache"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ForwardingStatus {
    NotConfigured,
    Configured,
    Active,
    Failed,
}

impl std::fmt::Display for ForwardingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardingStatus::NotConfigured => write!(f, "not-configured"),
            ForwardingStatus::Configured => write!(f, "configured"),
            ForwardingStatus::Active => write!(f, "active"),
            ForwardingStatus::Failed => write!(f, "failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub id: String,
    pub hostname: String,
    pub source_type: LogSourceType,
    pub site: String,
    pub status: ForwardingStatus,
    pub log_volume_per_day_mb: u32,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingResult {
    pub success: bool,
    pub hostname: String,
    pub site: String,
    pub configured_sources: Vec<LogSourceType>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigValidationResult {
    pub valid: bool,
    pub hostname: String,
    pub configured_sources: Vec<LogSourceType>,
    pub missing_sources: Vec<LogSourceType>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verified: bool,
    pub hostname: String,
    pub siem_received: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostVolume {
    pub hostname: String,
    pub volume_mb_per_day: u32,
    pub source_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub site: String,
    pub total_hosts: usize,
    pub hosts_with_forwarding: usize,
    pub hosts_without_forwarding: usize,
    pub coverage_percentage: f64,
    pub hosts: Vec<LogSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapReport {
    pub site: String,
    pub required_sources: Vec<LogSourceType>,
    pub collected_sources: Vec<LogSourceType>,
    pub missing_sources: Vec<LogSourceType>,
    pub hosts_with_gaps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeReport {
    pub site: String,
    pub hosts: Vec<HostVolume>,
    pub total_volume_mb_per_day: u32,
    pub top_talkers: Vec<HostVolume>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionHost {
    pub hostname: String,
    pub retention_days: u32,
    pub configured_days: u32,
    pub at_risk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionStatus {
    pub site: String,
    pub hosts_at_risk: Vec<RetentionHost>,
    pub hosts_approaching_limit: Vec<RetentionHost>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableResult {
    pub success: bool,
    pub hostname: String,
    pub disabled_sources: Vec<LogSourceType>,
    pub message: String,
}

pub fn seed_hosts() -> Vec<LogSource> {
    vec![
        LogSource {
            id: "ls-00000000-0000-0000-0000-000000000001".into(),
            hostname: "srv-defra-01.ryuki.local".into(),
            source_type: LogSourceType::WindowsEventLog,
            site: "DEFRA".into(),
            status: ForwardingStatus::Active,
            log_volume_per_day_mb: 450,
            retention_days: 90,
        },
        LogSource {
            id: "ls-00000000-0000-0000-0000-000000000002".into(),
            hostname: "srv-defra-02.ryuki.local".into(),
            source_type: LogSourceType::Syslog,
            site: "DEFRA".into(),
            status: ForwardingStatus::Active,
            log_volume_per_day_mb: 120,
            retention_days: 90,
        },
        LogSource {
            id: "ls-00000000-0000-0000-0000-000000000003".into(),
            hostname: "srv-gblon-01.ryuki.local".into(),
            source_type: LogSourceType::WindowsEventLog,
            site: "GBLON".into(),
            status: ForwardingStatus::Configured,
            log_volume_per_day_mb: 380,
            retention_days: 60,
        },
        LogSource {
            id: "ls-00000000-0000-0000-0000-000000000004".into(),
            hostname: "srv-frpar-web.ryuki.local".into(),
            source_type: LogSourceType::IIS,
            site: "FRPAR".into(),
            status: ForwardingStatus::Failed,
            log_volume_per_day_mb: 2100,
            retention_days: 30,
        },
        LogSource {
            id: "ls-00000000-0000-0000-0000-000000000005".into(),
            hostname: "srv-nlams-lnx.ryuki.local".into(),
            source_type: LogSourceType::Auditd,
            site: "NLAMS".into(),
            status: ForwardingStatus::NotConfigured,
            log_volume_per_day_mb: 85,
            retention_days: 90,
        },
        LogSource {
            id: "ls-00000000-0000-0000-0000-000000000006".into(),
            hostname: "srv-defra-web.ryuki.local".into(),
            source_type: LogSourceType::IIS,
            site: "DEFRA".into(),
            status: ForwardingStatus::Active,
            log_volume_per_day_mb: 3200,
            retention_days: 90,
        },
        LogSource {
            id: "ls-00000000-0000-0000-0000-000000000007".into(),
            hostname: "srv-gblon-lnx.ryuki.local".into(),
            source_type: LogSourceType::Syslog,
            site: "GBLON".into(),
            status: ForwardingStatus::Active,
            log_volume_per_day_mb: 90,
            retention_days: 90,
        },
    ]
}

pub fn onboard_host(
    hostname: &str,
    source_types: &[LogSourceType],
    site: &str,
) -> Result<OnboardingResult, String> {
    if hostname.is_empty() {
        return Err("hostname cannot be empty".into());
    }
    if source_types.is_empty() {
        return Err("source_types cannot be empty".into());
    }
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let configured_sources = source_types.to_vec();
    Ok(OnboardingResult {
        success: true,
        hostname: hostname.into(),
        site: site.into(),
        configured_sources,
        message: format!(
            "DRY-RUN: Agent installed and {} source(s) configured on {} (site: {}). No live agent deployment performed.",
            source_types.len(),
            hostname,
            site
        ),
    })
}

pub fn validate_config(hostname: &str) -> Result<ConfigValidationResult, String> {
    if hostname.is_empty() {
        return Err("hostname cannot be empty".into());
    }

    let seeds = seed_hosts();
    let host_sources: Vec<&LogSource> = seeds.iter().filter(|hs| hs.hostname == hostname).collect();

    if host_sources.is_empty() {
        return Ok(ConfigValidationResult {
            valid: false,
            hostname: hostname.into(),
            configured_sources: vec![],
            missing_sources: vec![LogSourceType::WindowsEventLog, LogSourceType::Syslog],
            errors: vec![format!(
                "DRY-RUN: No log forwarding configuration found for {}",
                hostname
            )],
        });
    }

    let configured: Vec<LogSourceType> = host_sources
        .iter()
        .filter(|hs| {
            hs.status == ForwardingStatus::Configured || hs.status == ForwardingStatus::Active
        })
        .map(|hs| hs.source_type.clone())
        .collect();

    let expected_types = if hostname.contains("lnx") || hostname.contains("linux") {
        vec![LogSourceType::Syslog, LogSourceType::Auditd]
    } else if hostname.contains("web") {
        vec![LogSourceType::IIS, LogSourceType::WindowsEventLog]
    } else {
        vec![LogSourceType::WindowsEventLog]
    };

    let missing: Vec<LogSourceType> = expected_types
        .iter()
        .filter(|et| !configured.contains(et))
        .cloned()
        .collect();

    let failed_sources: Vec<&LogSource> = host_sources
        .iter()
        .filter(|hs| hs.status == ForwardingStatus::Failed)
        .copied()
        .collect();

    let mut errors: Vec<String> = Vec::new();
    if !missing.is_empty() {
        errors.push(format!(
            "DRY-RUN: Missing expected sources on {}: {:?}",
            hostname, missing
        ));
    }
    for fs in &failed_sources {
        errors.push(format!(
            "DRY-RUN: Source {} on {} is in Failed state",
            fs.source_type, hostname
        ));
    }

    Ok(ConfigValidationResult {
        valid: missing.is_empty() && failed_sources.is_empty(),
        hostname: hostname.into(),
        configured_sources: configured,
        missing_sources: missing,
        errors,
    })
}

pub fn verify_forwarding(hostname: &str) -> Result<VerificationResult, String> {
    if hostname.is_empty() {
        return Err("hostname cannot be empty".into());
    }

    let seeds = seed_hosts();
    let host_sources: Vec<&LogSource> = seeds.iter().filter(|hs| hs.hostname == hostname).collect();

    if host_sources.is_empty() {
        return Ok(VerificationResult {
            verified: false,
            hostname: hostname.into(),
            siem_received: false,
            message: format!(
                "DRY-RUN: No log sources found for {}. SIEM verification skipped.",
                hostname
            ),
        });
    }

    let active_count = host_sources
        .iter()
        .filter(|hs| hs.status == ForwardingStatus::Active)
        .count();
    let siem_received = active_count > 0;

    Ok(VerificationResult {
        verified: siem_received,
        hostname: hostname.into(),
        siem_received,
        message: format!(
            "DRY-RUN: SIEM verification simulated. {} log source(s) actively forwarding from {}.",
            active_count, hostname
        ),
    })
}

pub fn get_coverage_report(site: &str) -> Result<CoverageReport, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let seeds = seed_hosts();
    let site_hosts: Vec<LogSource> = seeds.into_iter().filter(|hs| hs.site == site).collect();

    let total_hosts = site_hosts.len();
    let hosts_with_forwarding: Vec<&LogSource> = site_hosts
        .iter()
        .filter(|hs| hs.status == ForwardingStatus::Active)
        .collect();
    let hosts_without_forwarding: Vec<&LogSource> = site_hosts
        .iter()
        .filter(|hs| hs.status != ForwardingStatus::Active)
        .collect();

    let coverage_percentage = if total_hosts > 0 {
        (hosts_with_forwarding.len() as f64 / total_hosts as f64) * 100.0
    } else {
        0.0
    };

    Ok(CoverageReport {
        site: site.into(),
        total_hosts,
        hosts_with_forwarding: hosts_with_forwarding.len(),
        hosts_without_forwarding: hosts_without_forwarding.len(),
        coverage_percentage,
        hosts: site_hosts,
    })
}

pub fn get_gap_report(site: &str) -> Result<GapReport, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let seeds = seed_hosts();
    let site_hosts: Vec<LogSource> = seeds.iter().filter(|hs| hs.site == site).cloned().collect();

    let required_sources = vec![
        LogSourceType::WindowsEventLog,
        LogSourceType::Syslog,
        LogSourceType::Auditd,
        LogSourceType::IIS,
        LogSourceType::Apache,
    ];

    let collected_sources: Vec<LogSourceType> = site_hosts
        .iter()
        .filter(|hs| {
            hs.status == ForwardingStatus::Active || hs.status == ForwardingStatus::Configured
        })
        .map(|hs| hs.source_type.clone())
        .collect();

    let missing_sources: Vec<LogSourceType> = required_sources
        .iter()
        .filter(|rs| !collected_sources.contains(rs))
        .cloned()
        .collect();

    let hosts_with_gaps: Vec<String> = site_hosts
        .iter()
        .filter(|hs| {
            hs.status == ForwardingStatus::NotConfigured || hs.status == ForwardingStatus::Failed
        })
        .map(|hs| hs.hostname.clone())
        .collect();

    Ok(GapReport {
        site: site.into(),
        required_sources,
        collected_sources,
        missing_sources,
        hosts_with_gaps,
    })
}

pub fn get_volume_report(site: &str) -> Result<VolumeReport, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let seeds = seed_hosts();
    let site_hosts: Vec<LogSource> = seeds.iter().filter(|hs| hs.site == site).cloned().collect();

    let mut host_map: HashMap<String, HostVolume> = HashMap::new();
    for hs in &site_hosts {
        let entry = host_map.entry(hs.hostname.clone()).or_insert(HostVolume {
            hostname: hs.hostname.clone(),
            volume_mb_per_day: 0,
            source_count: 0,
        });
        entry.volume_mb_per_day += hs.log_volume_per_day_mb;
        entry.source_count += 1;
    }

    let mut hosts: Vec<HostVolume> = host_map.into_values().collect();
    hosts.sort_by(|a, b| b.volume_mb_per_day.cmp(&a.volume_mb_per_day));

    let total_volume_mb_per_day: u32 = hosts.iter().map(|h| h.volume_mb_per_day).sum();
    let top_talkers: Vec<HostVolume> = hosts.iter().take(3).cloned().collect();

    Ok(VolumeReport {
        site: site.into(),
        hosts,
        total_volume_mb_per_day,
        top_talkers,
    })
}

pub fn get_retention_status(site: &str) -> Result<RetentionStatus, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let seeds = seed_hosts();
    let retention_limit_days: u32 = 90;

    let mut hosts_at_risk: Vec<RetentionHost> = Vec::new();
    let mut hosts_approaching_limit: Vec<RetentionHost> = Vec::new();

    let site_hosts: Vec<LogSource> = seeds.into_iter().filter(|hs| hs.site == site).collect();

    let mut host_retention: HashMap<String, u32> = HashMap::new();
    for hs in &site_hosts {
        let entry = host_retention
            .entry(hs.hostname.clone())
            .or_insert(hs.retention_days);
        if hs.retention_days < *entry {
            *entry = hs.retention_days;
        }
    }

    for hs in &site_hosts {
        let configured = host_retention
            .get(&hs.hostname)
            .copied()
            .unwrap_or(hs.retention_days);
        if configured >= retention_limit_days {
            hosts_at_risk.push(RetentionHost {
                hostname: hs.hostname.clone(),
                retention_days: retention_limit_days,
                configured_days: configured,
                at_risk: true,
            });
        } else if configured >= retention_limit_days * 80 / 100 {
            hosts_approaching_limit.push(RetentionHost {
                hostname: hs.hostname.clone(),
                retention_days: retention_limit_days,
                configured_days: configured,
                at_risk: false,
            });
        }
    }

    hosts_at_risk.sort_by(|a, b| b.configured_days.cmp(&a.configured_days));
    hosts_approaching_limit.sort_by(|a, b| b.configured_days.cmp(&a.configured_days));

    Ok(RetentionStatus {
        site: site.into(),
        hosts_at_risk,
        hosts_approaching_limit,
    })
}

pub fn disable_forwarding(hostname: &str) -> Result<DisableResult, String> {
    if hostname.is_empty() {
        return Err("hostname cannot be empty".into());
    }

    let seeds = seed_hosts();
    let host_sources: Vec<&LogSource> = seeds.iter().filter(|hs| hs.hostname == hostname).collect();

    if host_sources.is_empty() {
        return Ok(DisableResult {
            success: true,
            hostname: hostname.into(),
            disabled_sources: vec![],
            message: format!(
                "DRY-RUN: No active log sources found for {}. Nothing to disable.",
                hostname
            ),
        });
    }

    let disabled_sources: Vec<LogSourceType> = host_sources
        .iter()
        .map(|hs| hs.source_type.clone())
        .collect();

    Ok(DisableResult {
        success: true,
        hostname: hostname.into(),
        disabled_sources,
        message: format!(
            "DRY-RUN: Log forwarding disabled for {} source(s) on {}. No live agent changes performed.",
            host_sources.len(),
            hostname
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onboard_host_success() {
        let result = onboard_host(
            "srv-new.ryuki.local",
            &[LogSourceType::WindowsEventLog, LogSourceType::Syslog],
            "DEFRA",
        )
        .expect("onboard should succeed");
        assert!(result.success);
        assert_eq!(result.hostname, "srv-new.ryuki.local");
        assert_eq!(result.site, "DEFRA");
        assert_eq!(result.configured_sources.len(), 2);
        assert!(result.message.contains("DRY-RUN"));
    }

    #[test]
    fn test_onboard_host_empty_hostname() {
        let result = onboard_host("", &[LogSourceType::WindowsEventLog], "DEFRA");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("hostname"));
    }

    #[test]
    fn test_onboard_host_empty_sources() {
        let result = onboard_host("srv-test.ryuki.local", &[], "DEFRA");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("source_types"));
    }

    #[test]
    fn test_onboard_host_invalid_site() {
        let result = onboard_host(
            "srv-test.ryuki.local",
            &[LogSourceType::WindowsEventLog],
            "INVALID",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown site"));
    }

    #[test]
    fn test_validate_config_known_host() {
        let result = validate_config("srv-defra-01.ryuki.local")
            .expect("validate should succeed for known host");
        assert!(result.valid);
        assert_eq!(result.hostname, "srv-defra-01.ryuki.local");
        assert!(!result.configured_sources.is_empty());
    }

    #[test]
    fn test_validate_config_unknown_host() {
        let result = validate_config("srv-unknown.ryuki.local")
            .expect("validate should succeed for unknown host");
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_verify_forwarding_active_host() {
        let result = verify_forwarding("srv-defra-01.ryuki.local").expect("verify should succeed");
        assert!(result.verified);
        assert!(result.siem_received);
        assert!(result.message.contains("DRY-RUN"));
    }

    #[test]
    fn test_verify_forwarding_unknown_host() {
        let result = verify_forwarding("srv-unknown.ryuki.local").expect("verify should succeed");
        assert!(!result.verified);
        assert!(!result.siem_received);
    }

    #[test]
    fn test_get_coverage_report_valid_site() {
        let result = get_coverage_report("DEFRA").expect("coverage report should succeed");
        assert_eq!(result.site, "DEFRA");
        assert!(result.total_hosts > 0);
    }

    #[test]
    fn test_get_coverage_report_invalid_site() {
        let result = get_coverage_report("INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_gap_report() {
        let result = get_gap_report("FRPAR").expect("gap report should succeed");
        assert_eq!(result.site, "FRPAR");
        assert!(!result.required_sources.is_empty());
    }

    #[test]
    fn test_get_volume_report() {
        let result = get_volume_report("DEFRA").expect("volume report should succeed");
        assert_eq!(result.site, "DEFRA");
        assert!(result.total_volume_mb_per_day > 0);
        assert!(!result.top_talkers.is_empty());
    }

    #[test]
    fn test_get_retention_status() {
        let result = get_retention_status("GBLON").expect("retention status should succeed");
        assert_eq!(result.site, "GBLON");
    }

    #[test]
    fn test_disable_forwarding_known_host() {
        let result =
            disable_forwarding("srv-defra-01.ryuki.local").expect("disable should succeed");
        assert!(result.success);
        assert!(result.message.contains("DRY-RUN"));
    }

    #[test]
    fn test_disable_forwarding_unknown_host() {
        let result = disable_forwarding("srv-unknown.ryuki.local").expect("disable should succeed");
        assert!(result.success);
        assert!(result.disabled_sources.is_empty());
    }

    #[test]
    fn test_seed_hosts_has_five_example_hosts() {
        let hosts = seed_hosts();
        let unique_hostnames: std::collections::HashSet<&str> =
            hosts.iter().map(|h| h.hostname.as_str()).collect();
        assert!(
            unique_hostnames.len() >= 5,
            "expected at least 5 unique hostnames"
        );
    }

    #[test]
    fn test_seed_hosts_has_mixed_statuses() {
        let hosts = seed_hosts();
        let has_active = hosts.iter().any(|h| h.status == ForwardingStatus::Active);
        let has_configured = hosts
            .iter()
            .any(|h| h.status == ForwardingStatus::Configured);
        let has_failed = hosts.iter().any(|h| h.status == ForwardingStatus::Failed);
        let has_not_configured = hosts
            .iter()
            .any(|h| h.status == ForwardingStatus::NotConfigured);
        assert!(has_active);
        assert!(has_configured);
        assert!(has_failed);
        assert!(has_not_configured);
    }

    #[test]
    fn test_log_source_type_display() {
        assert_eq!(
            LogSourceType::WindowsEventLog.to_string(),
            "windows-event-log"
        );
        assert_eq!(LogSourceType::Syslog.to_string(), "syslog");
        assert_eq!(LogSourceType::Auditd.to_string(), "auditd");
        assert_eq!(LogSourceType::IIS.to_string(), "iis");
        assert_eq!(LogSourceType::Apache.to_string(), "apache");
    }

    #[test]
    fn test_forwarding_status_display() {
        assert_eq!(
            ForwardingStatus::NotConfigured.to_string(),
            "not-configured"
        );
        assert_eq!(ForwardingStatus::Configured.to_string(), "configured");
        assert_eq!(ForwardingStatus::Active.to_string(), "active");
        assert_eq!(ForwardingStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn test_onboard_result_serialization() {
        let result = OnboardingResult {
            success: true,
            hostname: "srv-test.ryuki.local".into(),
            site: "DEFRA".into(),
            configured_sources: vec![LogSourceType::WindowsEventLog],
            message: "DRY-RUN: done".into(),
        };
        let json = serde_json::to_string(&result).expect("serialization should work");
        assert!(json.contains("srv-test.ryuki.local"));
        assert!(json.contains("DEFRA"));
        let deserialized: OnboardingResult =
            serde_json::from_str(&json).expect("deserialization should work");
        assert!(deserialized.success);
    }
}
