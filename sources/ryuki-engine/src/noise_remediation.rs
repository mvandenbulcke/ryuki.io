use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NoiseStatus {
    Active,
    UnderReview,
    Suppressed,
    Resolved,
}

impl std::fmt::Display for NoiseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoiseStatus::Active => write!(f, "Active"),
            NoiseStatus::UnderReview => write!(f, "UnderReview"),
            NoiseStatus::Suppressed => write!(f, "Suppressed"),
            NoiseStatus::Resolved => write!(f, "Resolved"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NoisyTrigger {
    pub id: String,
    pub trigger_name: String,
    pub host: String,
    pub severity: String,
    pub event_count_last_24h: u32,
    pub avg_interval_minutes: f64,
    pub flapping: bool,
    pub suggested_action: String,
    pub status: NoiseStatus,
    pub suppress_until: Option<String>,
    pub suppress_reason: Option<String>,
    pub resolution: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

static NOISE_STORE: OnceLock<Mutex<Vec<NoisyTrigger>>> = OnceLock::new();

fn noise_store() -> &'static Mutex<Vec<NoisyTrigger>> {
    NOISE_STORE.get_or_init(|| {
        let now = chrono::Utc::now().to_rfc3339();
        Mutex::new(vec![
            NoisyTrigger {
                id: "noise-001".into(),
                trigger_name: "High CPU utilization".into(),
                host: "srv-love-app01.corp.local".into(),
                severity: "warning".into(),
                event_count_last_24h: 47,
                avg_interval_minutes: 30.6,
                flapping: false,
                suggested_action: "Adjust threshold from 80% to 90% for this host class".into(),
                status: NoiseStatus::Active,
                suppress_until: None,
                suppress_reason: None,
                resolution: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            },
            NoisyTrigger {
                id: "noise-002".into(),
                trigger_name: "ICMP ping loss".into(),
                host: "srv-bur1-net01.corp.local".into(),
                severity: "disaster".into(),
                event_count_last_24h: 183,
                avg_interval_minutes: 7.8,
                flapping: true,
                suggested_action: "Correlate with known network maintenance window BUR1-SW-UPGRADE".into(),
                status: NoiseStatus::Active,
                suppress_until: None,
                suppress_reason: None,
                resolution: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            },
            NoisyTrigger {
                id: "noise-003".into(),
                trigger_name: "Disk space low".into(),
                host: "srv-tor1-fs01.corp.local".into(),
                severity: "average".into(),
                event_count_last_24h: 12,
                avg_interval_minutes: 120.0,
                flapping: false,
                suggested_action: "Add maintenance window for scheduled log rotation".into(),
                status: NoiseStatus::UnderReview,
                suppress_until: None,
                suppress_reason: None,
                resolution: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            },
            NoisyTrigger {
                id: "noise-004".into(),
                trigger_name: "Service port flapping".into(),
                host: "srv-ccss-web01.corp.local".into(),
                severity: "high".into(),
                event_count_last_24h: 89,
                avg_interval_minutes: 4.2,
                flapping: true,
                suggested_action: "Adjust threshold sensitivity for port availability check".into(),
                status: NoiseStatus::Suppressed,
                suppress_until: Some("2026-06-15T12:00:00+00:00".into()),
                suppress_reason: Some("Known intermittent issue during LB migration; suppressed for 48h".into()),
                resolution: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            },
            NoisyTrigger {
                id: "noise-005".into(),
                trigger_name: "SSL certificate expiry warning".into(),
                host: "srv-love-lb01.corp.local".into(),
                severity: "warning".into(),
                event_count_last_24h: 1,
                avg_interval_minutes: 1440.0,
                flapping: false,
                suggested_action: "Correlate with certificate lifecycle management — cert renewed, trigger auto-resolved".into(),
                status: NoiseStatus::Resolved,
                suppress_until: None,
                suppress_reason: None,
                resolution: Some("Certificate renewed on 2026-06-10; trigger cleared after next Zabbix discovery cycle".into()),
                created_at: now.clone(),
                updated_at: now,
            },
        ])
    })
}

const VALID_SITES: &[&str] = &[
    "LOVE", "BUR1", "CCSS", "TOR1", "TRUJ", "VILL", "ALBI", "AOST", "MACL", "SSYM", "WIJH", "RMA1",
    "PITE",
];

fn site_from_host(host: &str) -> &str {
    for site in VALID_SITES {
        if host.to_lowercase().contains(&site.to_lowercase()) {
            return site;
        }
    }
    "LOVE"
}

pub fn detect_noise(site: &str) -> Result<Vec<NoisyTrigger>, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }
    let store = noise_store().lock().map_err(|e| e.to_string())?;
    let noisy: Vec<NoisyTrigger> = store
        .iter()
        .filter(|t| site_from_host(&t.host) == site && t.event_count_last_24h > 10)
        .cloned()
        .collect();
    Ok(noisy)
}

pub fn detect_flapping(site: &str) -> Result<Vec<NoisyTrigger>, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }
    let store = noise_store().lock().map_err(|e| e.to_string())?;
    let flapping: Vec<NoisyTrigger> = store
        .iter()
        .filter(|t| site_from_host(&t.host) == site && t.flapping)
        .cloned()
        .collect();
    Ok(flapping)
}

pub fn suggest_remediation(trigger_id: &str) -> Result<Value, String> {
    let store = noise_store().lock().map_err(|e| e.to_string())?;
    let trigger = store
        .iter()
        .find(|t| t.id == trigger_id)
        .cloned()
        .ok_or_else(|| format!("Trigger not found: {}", trigger_id))?;

    let suggestions = if trigger.flapping {
        vec![
            "Add maintenance window to suppress during known change windows".to_string(),
            "Increase trigger fire threshold or adjust sensitivity".to_string(),
            "Correlate with CMDB for associated change records".to_string(),
        ]
    } else if trigger.event_count_last_24h > 50 {
        vec![
            "Escalate to service owner for threshold review".to_string(),
            "Check if monitoring template needs recalibration".to_string(),
            "Add maintenance window during peak hours if expected".to_string(),
        ]
    } else {
        vec![
            "Adjust threshold to reduce non-actionable alerts".to_string(),
            "Add maintenance window for scheduled activity".to_string(),
            "Correlate with known issue in CMDB".to_string(),
        ]
    };

    Ok(json!({
        "trigger_id": trigger.id,
        "trigger_name": trigger.trigger_name,
        "host": trigger.host,
        "current_action": trigger.suggested_action,
        "suggestions": suggestions,
        "flapping": trigger.flapping,
        "event_count_last_24h": trigger.event_count_last_24h,
    }))
}

pub fn suppress_trigger(
    trigger_id: &str,
    duration_minutes: u32,
    reason: &str,
) -> Result<NoisyTrigger, String> {
    let mut store = noise_store().lock().map_err(|e| e.to_string())?;
    let trigger = store
        .iter_mut()
        .find(|t| t.id == trigger_id)
        .ok_or_else(|| format!("Trigger not found: {}", trigger_id))?;

    if trigger.status == NoiseStatus::Suppressed {
        return Err("Trigger is already suppressed".into());
    }

    let until = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(duration_minutes as i64))
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    trigger.status = NoiseStatus::Suppressed;
    trigger.suppress_until = Some(until);
    trigger.suppress_reason = Some(reason.to_string());
    trigger.updated_at = chrono::Utc::now().to_rfc3339();

    Ok(trigger.clone())
}

pub fn resolve_noise(trigger_id: &str, resolution: &str) -> Result<NoisyTrigger, String> {
    let mut store = noise_store().lock().map_err(|e| e.to_string())?;
    let trigger = store
        .iter_mut()
        .find(|t| t.id == trigger_id)
        .ok_or_else(|| format!("Trigger not found: {}", trigger_id))?;

    trigger.status = NoiseStatus::Resolved;
    trigger.resolution = Some(resolution.to_string());
    trigger.updated_at = chrono::Utc::now().to_rfc3339();

    Ok(trigger.clone())
}

pub fn get_noise_report(site: &str) -> Result<Value, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }
    let store = noise_store().lock().map_err(|e| e.to_string())?;
    let site_triggers: Vec<&NoisyTrigger> = store
        .iter()
        .filter(|t| site_from_host(&t.host) == site)
        .collect();

    let active = site_triggers.iter().filter(|t| t.status == NoiseStatus::Active).count();
    let under_review = site_triggers.iter().filter(|t| t.status == NoiseStatus::UnderReview).count();
    let suppressed = site_triggers.iter().filter(|t| t.status == NoiseStatus::Suppressed).count();
    let resolved = site_triggers.iter().filter(|t| t.status == NoiseStatus::Resolved).count();
    let flapping = site_triggers.iter().filter(|t| t.flapping).count();
    let noisy = site_triggers.iter().filter(|t| t.event_count_last_24h > 10).count();

    Ok(json!({
        "site": site,
        "total_triggers": site_triggers.len(),
        "noisy": noisy,
        "flapping": flapping,
        "active": active,
        "under_review": under_review,
        "suppressed": suppressed,
        "resolved": resolved,
        "dry_run": true,
    }))
}

pub fn get_suppressed_triggers() -> Result<Vec<NoisyTrigger>, String> {
    let store = noise_store().lock().map_err(|e| e.to_string())?;
    let suppressed: Vec<NoisyTrigger> = store
        .iter()
        .filter(|t| t.status == NoiseStatus::Suppressed)
        .cloned()
        .collect();
    Ok(suppressed)
}

pub fn get_noise_contract() -> Value {
    json!({
        "source": "static-seed",
        "providerCallsEnabled": false,
        "liveSuppressionEnabled": false,
        "dryRunRequired": true,
        "noiseThreshold": 10,
        "flappingThreshold": 5,
        "flappingWindowMinutes": 60,
        "statuses": ["Active", "UnderReview", "Suppressed", "Resolved"],
        "suggestedActions": [
            "adjust threshold",
            "add maintenance window",
            "correlate with known issue",
            "escalate to service owner",
            "recalibrate monitoring template"
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_noise_returns_noisy_triggers() {
        let results = detect_noise("LOVE").unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().all(|t| t.event_count_last_24h > 10));
    }

    #[test]
    fn test_detect_noise_unknown_site_fails() {
        assert!(detect_noise("UNKNOWN").is_err());
    }

    #[test]
    fn test_detect_flapping_returns_flapping_triggers() {
        let results = detect_flapping("BUR1").unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().all(|t| t.flapping));
    }

    #[test]
    fn test_detect_flapping_unknown_site_fails() {
        assert!(detect_flapping("NOWHERE").is_err());
    }

    #[test]
    fn test_suggest_remediation_for_noisy_trigger() {
        let suggestion = suggest_remediation("noise-002").unwrap();
        assert_eq!(suggestion["trigger_id"], "noise-002");
        assert!(suggestion["flapping"].as_bool().unwrap());
        assert!(suggestion["suggestions"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn test_suggest_remediation_not_found() {
        assert!(suggest_remediation("nonexistent").is_err());
    }

    #[test]
    fn test_suppress_trigger() {
        let result = suppress_trigger("noise-001", 120, "Testing suppression").unwrap();
        assert_eq!(result.status, NoiseStatus::Suppressed);
        assert_eq!(result.suppress_reason, Some("Testing suppression".into()));
        assert!(result.suppress_until.is_some());
    }

    #[test]
    fn test_suppress_already_suppressed_fails() {
        assert!(suppress_trigger("noise-004", 60, "already suppressed").is_err());
    }

    #[test]
    fn test_resolve_noise() {
        let result = resolve_noise("noise-003", "Fixed via log rotation expansion").unwrap();
        assert_eq!(result.status, NoiseStatus::Resolved);
        assert_eq!(result.resolution, Some("Fixed via log rotation expansion".into()));
    }

    #[test]
    fn test_resolve_noise_not_found() {
        assert!(resolve_noise("nonexistent", "fixed").is_err());
    }

    #[test]
    fn test_get_noise_report_for_site() {
        let report = get_noise_report("LOVE").unwrap();
        assert_eq!(report["site"], "LOVE");
        assert!(report["total_triggers"].as_u64().unwrap() >= 1);
        assert!(report["dry_run"].as_bool().unwrap());
    }

    #[test]
    fn test_get_noise_report_unknown_site_fails() {
        assert!(get_noise_report("UNKNOWN").is_err());
    }

    #[test]
    fn test_get_suppressed_triggers() {
        let suppressed = get_suppressed_triggers().unwrap();
        assert!(!suppressed.is_empty());
        assert!(suppressed.iter().all(|t| t.status == NoiseStatus::Suppressed));
    }

    #[test]
    fn test_get_noise_contract() {
        let contract = get_noise_contract();
        assert_eq!(contract["source"], "static-seed");
        assert_eq!(contract["noiseThreshold"], 10);
        assert_eq!(contract["flappingThreshold"], 5);
    }
}
