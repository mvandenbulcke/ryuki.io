use crate::{models::*, site_registry};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

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
        write!(f, "{}", self.as_str())
    }
}

impl DriftSeverity {
    /// Canonical PascalCase variant name — matches DB CHECK constraint values.
    pub fn as_str(&self) -> &'static str {
        match self {
            DriftSeverity::Critical => "Critical",
            DriftSeverity::High => "High",
            DriftSeverity::Medium => "Medium",
            DriftSeverity::Low => "Low",
            DriftSeverity::Info => "Info",
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
        write!(f, "{}", self.as_str())
    }
}

impl DriftStatus {
    /// Canonical PascalCase variant name — matches DB CHECK constraint values.
    pub fn as_str(&self) -> &'static str {
        match self {
            DriftStatus::Detected => "Detected",
            DriftStatus::Planned => "Planned",
            DriftStatus::Validated => "Validated",
            DriftStatus::Remediated => "Remediated",
            DriftStatus::Verified => "Verified",
            DriftStatus::Failed => "Failed",
        }
    }
}

// ─── Pure engine functions ────────────────────────────────────────────────────

/// Fabricate synthetic drift rows for `site`. This is a PURE function with no
/// side effects: it does not assign ids (id is left as empty String; the repo's
/// RETURNING clause assigns the real UUID on INSERT) and does not touch any
/// global store.
pub fn detect_drift(site: &str) -> Result<Vec<DriftReport>, String> {
    if !site_registry::is_valid_site(site) {
        return Err(format!("Unknown site: {}", site));
    }

    let now = chrono::Utc::now().to_rfc3339();

    let drift_entries = vec![
        DriftReport {
            id: String::new(),
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
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: HashMap::from([
                ("drift_type".into(), "host-group-template".into()),
                ("dry_run".into(), "true".into()),
            ]),
        },
        DriftReport {
            id: String::new(),
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
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: HashMap::from([
                ("drift_type".into(), "template-only".into()),
                ("dry_run".into(), "true".into()),
            ]),
        },
        DriftReport {
            id: String::new(),
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
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: HashMap::from([
                ("drift_type".into(), "group-proxy".into()),
                ("dry_run".into(), "true".into()),
            ]),
        },
        DriftReport {
            id: String::new(),
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
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: HashMap::from([
                ("drift_type".into(), "maintenance-window-only".into()),
                ("dry_run".into(), "true".into()),
            ]),
        },
    ];

    Ok(drift_entries)
}

/// Compute remediation steps for `drift` and return them. PURE — no I/O.
///
/// The caller (handler) must:
/// 1. Load the report from the repo.
/// 2. Call this to compute steps.
/// 3. Call `repo::transition(Detected → Planned, steps)`.
///
/// Returns `Err` if the report is not in `Detected` status.
pub fn plan_remediation(drift: &DriftReport) -> Result<Vec<String>, String> {
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

    let steps = match drift_type.as_str() {
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

    Ok(steps)
}

/// Guard: report must be in `Planned` status. PURE — no I/O.
///
/// Returns `Ok(())` when the guard passes. The handler then calls
/// `repo::transition(Planned → Validated)`.
pub fn validate_remediation(drift: &DriftReport) -> Result<ValidationResult, String> {
    if drift.status != DriftStatus::Planned {
        return Err(format!(
            "Cannot validate remediation for drift in status {:?}. Must be Planned first.",
            drift.status
        ));
    }

    if drift.remediation_steps.is_empty() {
        return Err(format!(
            "Drift {} has no remediation steps planned",
            drift.id
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

/// Guard + evidence fabrication: report must be in `Validated` status. PURE.
///
/// Returns evidence items. The handler then calls
/// `repo::transition(Validated → Remediated)`.
pub fn execute_remediation(drift: &DriftReport) -> Result<Vec<EvidenceItem>, String> {
    if drift.status != DriftStatus::Validated {
        return Err(format!(
            "Cannot execute remediation for drift in status {:?}. Must be Validated first.",
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

    Ok(evidence)
}

/// Guard: report must be in `Remediated` status. PURE.
///
/// Returns a `ValidationResult`. The handler then calls
/// `repo::transition(Remediated → Verified)` to persist the status change.
///
/// BUG FIX: previously this function read from the global store but never wrote
/// the `Verified` status back. The repo now owns persistence; this function is
/// purely a guard + result constructor.
pub fn verify_remediation(drift: &DriftReport) -> Result<ValidationResult, String> {
    if drift.status != DriftStatus::Remediated {
        return Err(format!(
            "Cannot verify remediation for drift in status {:?}. Must be Remediated first.",
            drift.status
        ));
    }

    let warnings: Vec<String> = vec![
        format!(
            "DRY-RUN: Host {} group '{}' matches expected (simulated)",
            drift.hostname, drift.expected_group
        ),
        format!(
            "DRY-RUN: Host {} template '{}' matches expected (simulated)",
            drift.hostname, drift.expected_template
        ),
        format!(
            "DRY-RUN: Host {} proxy '{}' matches expected (simulated)",
            drift.hostname, drift.expected_proxy
        ),
        "DRY-RUN: Monitoring data flowing on expected template (simulated)".into(),
        "DRY-RUN: No new alerts generated after drift remediation (simulated)".into(),
    ];

    Ok(ValidationResult {
        passed: true,
        errors: Vec::new(),
        warnings,
        failed_rules: Vec::new(),
        remediation: Vec::new(),
    })
}

/// PURE read summary built from `reports` (already loaded from the DB).
///
/// Previously this called `detect_drift` (a side-effectful mutation). Now the
/// caller loads reports from `repo::list_by_site` and passes them in.
pub fn drift_summary_from_reports(site: &str, reports: &[DriftReport]) -> Value {
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
    let low = reports
        .iter()
        .filter(|r| r.drift_severity == DriftSeverity::Low)
        .count();
    let info = reports
        .iter()
        .filter(|r| r.drift_severity == DriftSeverity::Info)
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

    json!({
        "source": "postgres",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "site": site,
        "total_drift_reports": total,
        "by_severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info
        },
        "drift_types": drift_types,
        "remediable": total,
        "dry_run": true
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    fn make_detected(site: &str, host_suffix: &str, drift_type: &str) -> DriftReport {
        let now = chrono::Utc::now().to_rfc3339();
        DriftReport {
            id: format!("test-id-{}", host_suffix),
            host_id: format!("host-{}-{}", site.to_lowercase(), host_suffix),
            hostname: format!("{}-{}.contoso.com", site.to_lowercase(), host_suffix),
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
            created_at: now.clone(),
            updated_at: now,
            metadata: HashMap::from([
                ("drift_type".into(), drift_type.into()),
                ("dry_run".into(), "true".into()),
            ]),
        }
    }

    #[test]
    fn test_detect_drift_returns_entries() {
        let reports = detect_drift("DEFRA").unwrap();
        assert_eq!(reports.len(), 4);
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
    fn test_detect_drift_ids_empty() {
        let reports = detect_drift("DEFRA").unwrap();
        for r in &reports {
            assert!(r.id.is_empty(), "engine must not assign ids — repo does");
        }
    }

    #[test]
    fn test_detect_drift_unknown_site_fails() {
        assert!(detect_drift("UNKNOWN").is_err());
    }

    #[test]
    fn test_plan_remediation_generates_steps() {
        let drift = make_detected("DEFRA", "srv-01", "host-group-template");
        let steps = plan_remediation(&drift).unwrap();
        assert!(!steps.is_empty());
    }

    #[test]
    fn test_plan_remediation_wrong_status_fails() {
        let mut drift = make_detected("DEFRA", "srv-01", "host-group-template");
        drift.status = DriftStatus::Planned;
        assert!(plan_remediation(&drift).is_err());
    }

    #[test]
    fn test_validate_remediation_passes() {
        let mut drift = make_detected("DEFRA", "srv-01", "template-only");
        drift.status = DriftStatus::Planned;
        drift.remediation_steps = vec!["step 1".into()];
        let result = validate_remediation(&drift).unwrap();
        assert!(result.passed);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_validate_remediation_wrong_status_fails() {
        let drift = make_detected("DEFRA", "srv-01", "template-only");
        // status is Detected, not Planned
        assert!(validate_remediation(&drift).is_err());
    }

    #[test]
    fn test_validate_remediation_no_steps_fails() {
        let mut drift = make_detected("DEFRA", "srv-01", "template-only");
        drift.status = DriftStatus::Planned;
        // remediation_steps is empty
        assert!(validate_remediation(&drift).is_err());
    }

    #[test]
    fn test_execute_remediation_returns_evidence() {
        let mut drift = make_detected("DEFRA", "srv-01", "group-proxy");
        drift.status = DriftStatus::Validated;
        drift.remediation_steps = vec!["step 1".into(), "step 2".into()];
        let evidence = execute_remediation(&drift).unwrap();
        assert!(evidence.len() >= 3);
        assert!(evidence.iter().any(|e| e.key == "pre-remediation-snapshot"));
        assert!(evidence.iter().any(|e| e.key == "post-remediation-verify"));
    }

    #[test]
    fn test_execute_remediation_requires_validated() {
        let mut drift = make_detected("DEFRA", "srv-01", "group-proxy");
        drift.status = DriftStatus::Planned;
        drift.remediation_steps = vec!["step 1".into()];
        assert!(execute_remediation(&drift).is_err());
    }

    #[test]
    fn test_verify_remediation_passes() {
        let mut drift = make_detected("DEFRA", "srv-01", "maintenance-window-only");
        drift.status = DriftStatus::Remediated;
        let result = verify_remediation(&drift).unwrap();
        assert!(result.passed);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("matches expected"))
        );
    }

    #[test]
    fn test_verify_remediation_wrong_status_fails() {
        let drift = make_detected("DEFRA", "srv-01", "maintenance-window-only");
        // status is Detected
        assert!(verify_remediation(&drift).is_err());
    }

    #[test]
    fn test_drift_summary_from_reports() {
        let reports = detect_drift("DEFRA").unwrap();
        let summary = drift_summary_from_reports("DEFRA", &reports);
        assert_eq!(summary["source"], "postgres");
        assert_eq!(summary["site"], "DEFRA");
        assert_eq!(summary["total_drift_reports"], 4);
    }

    #[test]
    fn test_severity_str_pascal_case() {
        assert_eq!(DriftSeverity::Critical.as_str(), "Critical");
        assert_eq!(DriftSeverity::High.as_str(), "High");
        assert_eq!(DriftSeverity::Medium.as_str(), "Medium");
        assert_eq!(DriftSeverity::Low.as_str(), "Low");
        assert_eq!(DriftSeverity::Info.as_str(), "Info");
    }

    #[test]
    fn test_status_str_pascal_case() {
        assert_eq!(DriftStatus::Detected.as_str(), "Detected");
        assert_eq!(DriftStatus::Planned.as_str(), "Planned");
        assert_eq!(DriftStatus::Validated.as_str(), "Validated");
        assert_eq!(DriftStatus::Remediated.as_str(), "Remediated");
        assert_eq!(DriftStatus::Verified.as_str(), "Verified");
        assert_eq!(DriftStatus::Failed.as_str(), "Failed");
    }
}
