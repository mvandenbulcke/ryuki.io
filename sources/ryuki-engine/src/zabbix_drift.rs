use crate::models::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

const VALID_SITES: &[&str] = &[
    "LOVE", "BUR1", "CCSS", "TOR1", "TRUJ", "VILL", "ALBI", "AOST", "MACL", "SSYM", "WIJH", "RMA1",
    "PITE",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftReport {
    pub id: String,
    pub host_id: String,
    pub hostname: String,
    pub site: String,
    pub expected_group: String,
    pub actual_group: String,
    pub expected_template: String,
    pub actual_template: String,
    pub expected_proxy: String,
    pub actual_proxy: String,
    pub drift_severity: DriftSeverity,
    pub status: DriftStatus,
    pub remediation_steps: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DriftSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for DriftSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriftSeverity::Critical => write!(f, "critical"),
            DriftSeverity::High => write!(f, "high"),
            DriftSeverity::Medium => write!(f, "medium"),
            DriftSeverity::Low => write!(f, "low"),
            DriftSeverity::Info => write!(f, "info"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DriftStatus {
    Detected,
    Planned,
    Validated,
    Remediated,
    Verified,
    Failed,
}

impl std::fmt::Display for DriftStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriftStatus::Detected => write!(f, "detected"),
            DriftStatus::Planned => write!(f, "planned"),
            DriftStatus::Validated => write!(f, "validated"),
            DriftStatus::Remediated => write!(f, "remediated"),
            DriftStatus::Verified => write!(f, "verified"),
            DriftStatus::Failed => write!(f, "failed"),
        }
    }
}

static DRIFT_STORE: OnceLock<Mutex<Vec<DriftReport>>> = OnceLock::new();

fn drift_store() -> &'static Mutex<Vec<DriftReport>> {
    DRIFT_STORE.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn detect_drift(site: &str) -> Result<Vec<DriftReport>, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let drift_entries = vec![
        DriftReport {
            id: format!(
                "zdr-{}",
                Uuid::new_v4()
                    .to_string()
                    .split('-')
                    .next()
                    .unwrap_or("unknown")
            ),
            host_id: format!("host-{}-srv-01", site.to_lowercase()),
            hostname: format!("{}-srv-01.contoso.com", site.to_lowercase()),
            site: site.to_string(),
            expected_group: format!("{}-Production-Servers", site),
            actual_group: format!("{}-Discovered-Hosts", site),
            expected_template: "Template-OS-Windows-Server-2022".into(),
            actual_template: "Template-OS-Windows-Server-2019".into(),
            expected_proxy: format!("zabbix-proxy-{}", site.to_lowercase()),
            actual_proxy: format!("zabbix-proxy-{}", site.to_lowercase()),
            drift_severity: DriftSeverity::High,
            status: DriftStatus::Detected,
            remediation_steps: Vec::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            metadata: HashMap::from([
                ("drift_type".into(), "host-group-template".into()),
                ("dry_run".into(), "true".into()),
            ]),
        },
        DriftReport {
            id: format!(
                "zdr-{}",
                Uuid::new_v4()
                    .to_string()
                    .split('-')
                    .next()
                    .unwrap_or("unknown")
            ),
            host_id: format!("host-{}-srv-02", site.to_lowercase()),
            hostname: format!("{}-srv-02.contoso.com", site.to_lowercase()),
            site: site.to_string(),
            expected_group: format!("{}-Production-Servers", site),
            actual_group: format!("{}-Production-Servers", site),
            expected_template: "Template-OS-Linux-RHEL-9".into(),
            actual_template: "Template-OS-Linux-RHEL-8".into(),
            expected_proxy: format!("zabbix-proxy-{}", site.to_lowercase()),
            actual_proxy: format!("zabbix-proxy-{}", site.to_lowercase()),
            drift_severity: DriftSeverity::Medium,
            status: DriftStatus::Detected,
            remediation_steps: Vec::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            metadata: HashMap::from([
                ("drift_type".into(), "template-only".into()),
                ("dry_run".into(), "true".into()),
            ]),
        },
        DriftReport {
            id: format!(
                "zdr-{}",
                Uuid::new_v4()
                    .to_string()
                    .split('-')
                    .next()
                    .unwrap_or("unknown")
            ),
            host_id: format!("host-{}-srv-03", site.to_lowercase()),
            hostname: format!("{}-srv-03.contoso.com", site.to_lowercase()),
            site: site.to_string(),
            expected_group: format!("{}-DMZ-Servers", site),
            actual_group: format!("{}-Production-Servers", site),
            expected_template: "Template-OS-Windows-Server-2022".into(),
            actual_template: "Template-OS-Windows-Server-2022".into(),
            expected_proxy: format!("zabbix-proxy-{}", site.to_lowercase()),
            actual_proxy: "zabbix-proxy-default".into(),
            drift_severity: DriftSeverity::Critical,
            status: DriftStatus::Detected,
            remediation_steps: Vec::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            metadata: HashMap::from([
                ("drift_type".into(), "group-proxy".into()),
                ("dry_run".into(), "true".into()),
            ]),
        },
        DriftReport {
            id: format!(
                "zdr-{}",
                Uuid::new_v4()
                    .to_string()
                    .split('-')
                    .next()
                    .unwrap_or("unknown")
            ),
            host_id: format!("host-{}-srv-04", site.to_lowercase()),
            hostname: format!("{}-srv-04.contoso.com", site.to_lowercase()),
            site: site.to_string(),
            expected_group: format!("{}-Production-Servers", site),
            actual_group: format!("{}-Production-Servers", site),
            expected_template: "Template-OS-Windows-Server-2022".into(),
            actual_template: "Template-OS-Windows-Server-2022".into(),
            expected_proxy: format!("zabbix-proxy-{}", site.to_lowercase()),
            actual_proxy: format!("zabbix-proxy-{}", site.to_lowercase()),
            drift_severity: DriftSeverity::Medium,
            status: DriftStatus::Detected,
            remediation_steps: Vec::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            metadata: HashMap::from([
                ("drift_type".into(), "maintenance-window-only".into()),
                ("dry_run".into(), "true".into()),
            ]),
        },
    ];

    {
        let mut store = drift_store().lock().unwrap();
        for entry in &drift_entries {
            if !store.iter().any(|e| e.id == entry.id) {
                store.push(entry.clone());
            }
        }
    }

    Ok(drift_entries)
}

pub fn plan_remediation(drift_id: &str) -> Result<DriftReport, String> {
    let mut store = drift_store().lock().unwrap();
    let idx = store
        .iter()
        .position(|d| d.id == drift_id)
        .ok_or_else(|| format!("Drift report not found: {}", drift_id))?;

    let mut drift = store[idx].clone();

    if drift.status != DriftStatus::Detected {
        return Err(format!(
            "Cannot plan remediation for drift in status {:?}. Must be Detected first.",
            drift.status
        ));
    }

    let drift_type = drift
        .metadata
        .get("drift_type")
        .cloned()
        .unwrap_or_default();

    drift.remediation_steps = match drift_type.as_str() {
        "host-group-template" => vec![
            format!(
                "DRY-RUN: Move host {} from {} to {} in Zabbix (simulated)",
                drift.hostname, drift.actual_group, drift.expected_group
            ),
            format!(
                "DRY-RUN: Unlink template {} and link template {} (simulated)",
                drift.actual_template, drift.expected_template
            ),
            "DRY-RUN: Verify host availability after group and template change (simulated)".into(),
        ],
        "template-only" => vec![
            format!(
                "DRY-RUN: Unlink stale template {} from host {} (simulated)",
                drift.actual_template, drift.hostname
            ),
            format!(
                "DRY-RUN: Link correct template {} to host {} (simulated)",
                drift.expected_template, drift.hostname
            ),
            "DRY-RUN: Trigger template cache flush on proxy (simulated)".into(),
        ],
        "group-proxy" => vec![
            format!(
                "DRY-RUN: Reassign host {} from group {} to {} (simulated)",
                drift.hostname, drift.actual_group, drift.expected_group
            ),
            format!(
                "DRY-RUN: Reassign host {} from proxy {} to {} (simulated)",
                drift.hostname, drift.actual_proxy, drift.expected_proxy
            ),
            "DRY-RUN: Validate proxy reachability after reassignment (simulated)".into(),
        ],
        "maintenance-window-only" => vec![
            format!(
                "DRY-RUN: Extend maintenance window assignment for host {} (simulated)",
                drift.hostname
            ),
            "DRY-RUN: Verify maintenance window inheritance from host group (simulated)".into(),
        ],
        _ => vec![
            "DRY-RUN: Generic drift remediation — review host mapping (simulated)".into(),
            "DRY-RUN: Align host group, template, and proxy to expected configuration (simulated)"
                .into(),
        ],
    };

    drift.status = DriftStatus::Planned;
    drift.updated_at = chrono::Utc::now().to_rfc3339();
    drift.metadata.insert(
        "remediation_planned_at".into(),
        chrono::Utc::now().to_rfc3339(),
    );

    store[idx] = drift.clone();
    Ok(drift)
}

pub fn validate_remediation(drift_id: &str) -> Result<ValidationResult, String> {
    let store = drift_store().lock().unwrap();
    let drift = store
        .iter()
        .find(|d| d.id == drift_id)
        .ok_or_else(|| format!("Drift report not found: {}", drift_id))?;

    if drift.status != DriftStatus::Planned {
        return Err(format!(
            "Cannot validate remediation for drift in status {:?}. Must be Planned first.",
            drift.status
        ));
    }

    if drift.remediation_steps.is_empty() {
        return Err(format!(
            "Drift {} has no remediation steps planned",
            drift_id
        ));
    }

    let warnings: Vec<String> = vec![
        "DRY-RUN: Host identity confirmed (simulated)".into(),
        "DRY-RUN: Target host group capacity checked (simulated)".into(),
        "DRY-RUN: Template version compatibility verified (simulated)".into(),
        "DRY-RUN: Proxy connectivity confirmed (simulated)".into(),
        "DRY-RUN: Maintenance window overlap checked (simulated)".into(),
    ];

    Ok(ValidationResult {
        passed: true,
        errors: Vec::new(),
        warnings,
        failed_rules: Vec::new(),
        remediation: Vec::new(),
    })
}

pub fn execute_remediation(drift_id: &str) -> Result<Vec<EvidenceItem>, String> {
    let mut store = drift_store().lock().unwrap();
    let idx = store
        .iter()
        .position(|d| d.id == drift_id)
        .ok_or_else(|| format!("Drift report not found: {}", drift_id))?;

    let mut drift = store[idx].clone();

    if drift.status != DriftStatus::Planned {
        return Err(format!(
            "Cannot execute remediation for drift in status {:?}. Must be Planned first.",
            drift.status
        ));
    }

    let mut evidence: Vec<EvidenceItem> = Vec::new();

    evidence.push(EvidenceItem {
        key: "pre-remediation-snapshot".into(),
        value: format!(
            "DRY-RUN: Host {} configuration snapshot captured before remediation (simulated)",
            drift.hostname
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    for (i, step) in drift.remediation_steps.iter().enumerate() {
        evidence.push(EvidenceItem {
            key: format!("remediation-step-{}", i + 1),
            value: step.clone(),
            redacted_value: Some("***DRY-RUN SIMULATION***".into()),
            redacted: true,
            evidence_type: EvidenceType::ExecutionLog,
        });
    }

    evidence.push(EvidenceItem {
        key: "post-remediation-verify".into(),
        value: format!(
            "DRY-RUN: Host {} group, template, and proxy updated to expected configuration (simulated)",
            drift.hostname
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    drift.status = DriftStatus::Remediated;
    drift.updated_at = chrono::Utc::now().to_rfc3339();
    drift
        .metadata
        .insert("remediated_at".into(), chrono::Utc::now().to_rfc3339());

    store[idx] = drift;

    Ok(evidence)
}

pub fn verify_remediation(drift_id: &str) -> Result<ValidationResult, String> {
    let store = drift_store().lock().unwrap();
    let idx = store
        .iter()
        .position(|d| d.id == drift_id)
        .ok_or_else(|| format!("Drift report not found: {}", drift_id))?;

    let drift = &store[idx];

    if drift.status != DriftStatus::Remediated {
        return Err(format!(
            "Cannot verify remediation for drift in status {:?}. Must be Remediated first.",
            drift.status
        ));
    }

    let mut warnings: Vec<String> = Vec::new();
    warnings.push(format!(
        "DRY-RUN: Host {} group '{}' matches expected (simulated)",
        drift.hostname, drift.expected_group
    ));
    warnings.push(format!(
        "DRY-RUN: Host {} template '{}' matches expected (simulated)",
        drift.hostname, drift.expected_template
    ));
    warnings.push(format!(
        "DRY-RUN: Host {} proxy '{}' matches expected (simulated)",
        drift.hostname, drift.expected_proxy
    ));
    warnings.push("DRY-RUN: Monitoring data flowing on expected template (simulated)".into());
    warnings.push("DRY-RUN: No new alerts generated after drift remediation (simulated)".into());

    Ok(ValidationResult {
        passed: true,
        errors: Vec::new(),
        warnings,
        failed_rules: Vec::new(),
        remediation: Vec::new(),
    })
}

pub fn get_drift_summary(site: &str) -> Result<Value, String> {
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let reports = detect_drift(site)?;

    let total = reports.len();
    let critical = reports
        .iter()
        .filter(|r| r.drift_severity == DriftSeverity::Critical)
        .count();
    let high = reports
        .iter()
        .filter(|r| r.drift_severity == DriftSeverity::High)
        .count();
    let medium = reports
        .iter()
        .filter(|r| r.drift_severity == DriftSeverity::Medium)
        .count();

    let drift_types: Vec<String> = {
        let mut types: Vec<String> = reports
            .iter()
            .filter_map(|r| r.metadata.get("drift_type").cloned())
            .collect();
        types.sort();
        types.dedup();
        types
    };

    Ok(json!({
        "source": "dry-run",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "site": site,
        "total_drift_reports": total,
        "by_severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": 0,
            "info": 0
        },
        "drift_types": drift_types,
        "remediable": total,
        "dry_run": true
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_drift_returns_entries() {
        let reports = detect_drift("LOVE").unwrap();
        assert!(reports.len() >= 4);
        assert!(
            reports
                .iter()
                .any(|r| r.drift_severity == DriftSeverity::Critical)
        );
        assert!(
            reports
                .iter()
                .any(|r| r.drift_severity == DriftSeverity::High)
        );
    }

    #[test]
    fn test_detect_drift_unknown_site_fails() {
        assert!(detect_drift("UNKNOWN").is_err());
    }

    #[test]
    fn test_plan_remediation_generates_steps() {
        let reports = detect_drift("BUR1").unwrap();
        let first_id = reports[0].id.clone();

        let planned = plan_remediation(&first_id).unwrap();
        assert_eq!(planned.status, DriftStatus::Planned);
        assert!(!planned.remediation_steps.is_empty());
    }

    #[test]
    fn test_plan_remediation_not_found() {
        assert!(plan_remediation("zdr-nonexistent").is_err());
    }

    #[test]
    fn test_validate_remediation_passes() {
        let reports = detect_drift("TOR1").unwrap();
        let first_id = reports[0].id.clone();

        plan_remediation(&first_id).unwrap();
        let result = validate_remediation(&first_id).unwrap();
        assert!(result.passed);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_execute_remediation_returns_evidence() {
        let reports = detect_drift("VILL").unwrap();
        let first_id = reports[0].id.clone();

        plan_remediation(&first_id).unwrap();
        let evidence = execute_remediation(&first_id).unwrap();
        assert!(evidence.len() >= 3);
        assert!(evidence.iter().any(|e| e.key == "pre-remediation-snapshot"));
        assert!(evidence.iter().any(|e| e.key == "post-remediation-verify"));
    }

    #[test]
    fn test_verify_remediation_passes() {
        let reports = detect_drift("AOST").unwrap();
        let first_id = reports[0].id.clone();

        plan_remediation(&first_id).unwrap();
        execute_remediation(&first_id).unwrap();
        let result = verify_remediation(&first_id).unwrap();
        assert!(result.passed);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("matches expected"))
        );
    }

    #[test]
    fn test_verify_remediation_not_remediated_fails() {
        let reports = detect_drift("SSYM").unwrap();
        let first_id = reports[0].id.clone();

        assert!(verify_remediation(&first_id).is_err());
    }

    #[test]
    fn test_get_drift_summary() {
        let summary = get_drift_summary("LOVE").unwrap();
        assert_eq!(summary["source"], "dry-run");
        assert_eq!(summary["dry_run"], true);
        assert_eq!(summary["site"], "LOVE");
        assert!(summary["total_drift_reports"].as_u64().unwrap() >= 4);
    }

    #[test]
    fn test_get_drift_summary_unknown_site_fails() {
        assert!(get_drift_summary("UNKNOWN").is_err());
    }

    #[test]
    fn test_plan_remediation_already_planned_fails() {
        let reports = detect_drift("MACL").unwrap();
        let first_id = reports[0].id.clone();

        plan_remediation(&first_id).unwrap();
        assert!(plan_remediation(&first_id).is_err());
    }
}
