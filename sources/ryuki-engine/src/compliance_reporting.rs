use chrono::{Days, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ControlStatus {
    Compliant,
    NonCompliant,
    NotApplicable,
}

impl std::fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlStatus::Compliant => write!(f, "Compliant"),
            ControlStatus::NonCompliant => write!(f, "NonCompliant"),
            ControlStatus::NotApplicable => write!(f, "NotApplicable"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OverallStatus {
    Compliant,
    NonCompliant,
    AtRisk,
}

impl std::fmt::Display for OverallStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverallStatus::Compliant => write!(f, "Compliant"),
            OverallStatus::NonCompliant => write!(f, "NonCompliant"),
            OverallStatus::AtRisk => write!(f, "AtRisk"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Critical => write!(f, "Critical"),
            FindingSeverity::High => write!(f, "High"),
            FindingSeverity::Medium => write!(f, "Medium"),
            FindingSeverity::Low => write!(f, "Low"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FindingStatus {
    Open,
    InProgress,
    Resolved,
    Waived,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingStatus::Open => write!(f, "Open"),
            FindingStatus::InProgress => write!(f, "InProgress"),
            FindingStatus::Resolved => write!(f, "Resolved"),
            FindingStatus::Waived => write!(f, "Waived"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFramework {
    pub id: String,
    pub name: String,
    pub version: String,
    pub last_assessed: String,
    pub next_assessment_due: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub id: String,
    pub framework_id: String,
    pub control_id: String,
    pub title: String,
    pub description: String,
    pub status: ControlStatus,
    pub evidence_ref: Option<String>,
    pub assessed_by: Option<String>,
    pub assessed_at: Option<String>,
    pub site: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub id: String,
    pub framework_id: String,
    pub site: String,
    pub generated_at: String,
    pub overall_status: OverallStatus,
    pub compliant_controls: usize,
    pub total_controls: usize,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub control_id: String,
    pub severity: FindingSeverity,
    pub description: String,
    pub remediation: String,
    pub status: FindingStatus,
}

type ComplianceStore = (
    Vec<ComplianceFramework>,
    Vec<ComplianceControl>,
    Vec<ComplianceReport>,
);

static COMPLIANCE_STORE: OnceLock<Mutex<ComplianceStore>> = OnceLock::new();

fn compliance_store() -> &'static Mutex<ComplianceStore> {
    COMPLIANCE_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn parse_control_status(status: &str) -> Result<ControlStatus, String> {
    match status {
        "Compliant" => Ok(ControlStatus::Compliant),
        "NonCompliant" => Ok(ControlStatus::NonCompliant),
        "NotApplicable" => Ok(ControlStatus::NotApplicable),
        other => Err(format!(
            "Invalid control status: {}. Must be Compliant, NonCompliant, or NotApplicable",
            other
        )),
    }
}

fn parse_severity(severity: &str) -> Result<FindingSeverity, String> {
    match severity {
        "Critical" => Ok(FindingSeverity::Critical),
        "High" => Ok(FindingSeverity::High),
        "Medium" => Ok(FindingSeverity::Medium),
        "Low" => Ok(FindingSeverity::Low),
        other => Err(format!(
            "Invalid finding severity: {}. Must be Critical, High, Medium, or Low",
            other
        )),
    }
}

fn summarize_controls(controls: &[ComplianceControl]) -> (usize, usize, OverallStatus) {
    let total = controls.len();
    let compliant = controls
        .iter()
        .filter(|c| c.status == ControlStatus::Compliant)
        .count();
    let non_compliant = controls
        .iter()
        .filter(|c| c.status == ControlStatus::NonCompliant)
        .count();
    let status = if non_compliant > 0 {
        OverallStatus::NonCompliant
    } else if compliant == total && total > 0 {
        OverallStatus::Compliant
    } else {
        OverallStatus::AtRisk
    };

    (compliant, total, status)
}

#[allow(clippy::too_many_arguments)]
fn control(
    id: &str,
    framework_id: &str,
    control_id: &str,
    title: &str,
    description: &str,
    status: ControlStatus,
    site: &str,
    days_ago: i64,
) -> ComplianceControl {
    let now = Utc::now();
    let evidence_ref = if status == ControlStatus::NotApplicable {
        None
    } else {
        Some(format!("ev-{}", id))
    };
    let assessor = if status == ControlStatus::NotApplicable {
        None
    } else {
        Some("static.auditor".into())
    };
    let assessed_at = if status == ControlStatus::NotApplicable {
        None
    } else {
        Some((now - Days::new(days_ago as u64)).to_rfc3339())
    };

    ComplianceControl {
        id: id.into(),
        framework_id: framework_id.into(),
        control_id: control_id.into(),
        title: title.into(),
        description: description.into(),
        status,
        evidence_ref,
        assessed_by: assessor,
        assessed_at,
        site: site.into(),
    }
}

fn seed_data() -> ComplianceStore {
    let now = Utc::now();
    let frameworks = vec![
        ComplianceFramework {
            id: "cf-pci-dss".into(),
            name: "PCI-DSS".into(),
            version: "4.0".into(),
            last_assessed: (now - Days::new(60)).to_rfc3339(),
            next_assessment_due: (now + Days::new(305)).to_rfc3339(),
        },
        ComplianceFramework {
            id: "cf-soc2".into(),
            name: "SOC2".into(),
            version: "2022".into(),
            last_assessed: (now - Days::new(35)).to_rfc3339(),
            next_assessment_due: (now + Days::new(330)).to_rfc3339(),
        },
        ComplianceFramework {
            id: "cf-iso27001".into(),
            name: "ISO27001".into(),
            version: "2022".into(),
            last_assessed: (now - Days::new(90)).to_rfc3339(),
            next_assessment_due: (now + Days::new(275)).to_rfc3339(),
        },
    ];

    let controls = vec![
        control(
            "cc-pci-001",
            "cf-pci-dss",
            "PCI-1.1",
            "Firewall configuration standards",
            "Maintain documented firewall and router configuration standards.",
            ControlStatus::Compliant,
            "DEFRA",
            30,
        ),
        control(
            "cc-pci-002",
            "cf-pci-dss",
            "PCI-3.4",
            "Protect stored cardholder data",
            "Render sensitive data unreadable wherever stored.",
            ControlStatus::NonCompliant,
            "DEFRA",
            28,
        ),
        control(
            "cc-pci-003",
            "cf-pci-dss",
            "PCI-6.3",
            "Secure software development",
            "Develop software using secure coding practices.",
            ControlStatus::Compliant,
            "DEFRA",
            27,
        ),
        control(
            "cc-pci-004",
            "cf-pci-dss",
            "PCI-8.2",
            "User identification",
            "Assign unique IDs before allowing access to system components.",
            ControlStatus::Compliant,
            "GBLON",
            26,
        ),
        control(
            "cc-pci-005",
            "cf-pci-dss",
            "PCI-10.2",
            "Audit logging",
            "Implement automated audit trails for all system components.",
            ControlStatus::NonCompliant,
            "GBLON",
            25,
        ),
        control(
            "cc-soc2-001",
            "cf-soc2",
            "CC1.1",
            "Integrity and ethical values",
            "Demonstrate commitment to integrity and ethical values.",
            ControlStatus::Compliant,
            "DEFRA",
            20,
        ),
        control(
            "cc-soc2-002",
            "cf-soc2",
            "CC2.1",
            "Communication of objectives",
            "Communicate quality information to support internal controls.",
            ControlStatus::Compliant,
            "DEFRA",
            19,
        ),
        control(
            "cc-soc2-003",
            "cf-soc2",
            "CC6.1",
            "Logical access controls",
            "Implement logical access security software and infrastructure.",
            ControlStatus::NonCompliant,
            "GBLON",
            18,
        ),
        control(
            "cc-soc2-004",
            "cf-soc2",
            "CC7.2",
            "Security monitoring",
            "Monitor system components for anomalies and events.",
            ControlStatus::Compliant,
            "GBLON",
            17,
        ),
        control(
            "cc-soc2-005",
            "cf-soc2",
            "CC8.1",
            "Change management",
            "Authorize, design, develop, and implement changes.",
            ControlStatus::NotApplicable,
            "FRPAR",
            16,
        ),
        control(
            "cc-iso-001",
            "cf-iso27001",
            "A.5.1",
            "Information security policies",
            "Define, approve, publish, and review security policies.",
            ControlStatus::Compliant,
            "DEFRA",
            15,
        ),
        control(
            "cc-iso-002",
            "cf-iso27001",
            "A.8.9",
            "Configuration management",
            "Establish and maintain secure configurations.",
            ControlStatus::NonCompliant,
            "FRPAR",
            14,
        ),
        control(
            "cc-iso-003",
            "cf-iso27001",
            "A.8.15",
            "Logging",
            "Produce, store, protect, and analyze logs.",
            ControlStatus::Compliant,
            "GBLON",
            13,
        ),
        control(
            "cc-iso-004",
            "cf-iso27001",
            "A.8.16",
            "Monitoring activities",
            "Monitor networks, systems, and applications for anomalous behavior.",
            ControlStatus::Compliant,
            "GBLON",
            12,
        ),
        control(
            "cc-iso-005",
            "cf-iso27001",
            "A.8.24",
            "Use of cryptography",
            "Define and implement rules for cryptography and key management.",
            ControlStatus::Compliant,
            "DEFRA",
            11,
        ),
    ];

    let reports = vec![
        ComplianceReport {
            id: "cr-defra-pci-001".into(),
            framework_id: "cf-pci-dss".into(),
            site: "DEFRA".into(),
            generated_at: (now - Days::new(7)).to_rfc3339(),
            overall_status: OverallStatus::NonCompliant,
            compliant_controls: 2,
            total_controls: 3,
            findings: vec![
                Finding {
                    id: "cr-find-001".into(),
                    control_id: "cc-pci-002".into(),
                    severity: FindingSeverity::High,
                    description: "Stored sensitive data evidence is incomplete for DEFRA.".into(),
                    remediation: "Attach encrypted-storage evidence and key-management review."
                        .into(),
                    status: FindingStatus::Open,
                },
                Finding {
                    id: "cr-find-002".into(),
                    control_id: "cc-pci-002".into(),
                    severity: FindingSeverity::Medium,
                    description: "Data retention exception lacks current owner sign-off.".into(),
                    remediation: "Renew owner approval and add expiry to the retention exception."
                        .into(),
                    status: FindingStatus::InProgress,
                },
            ],
        },
        ComplianceReport {
            id: "cr-gblon-soc2-001".into(),
            framework_id: "cf-soc2".into(),
            site: "GBLON".into(),
            generated_at: (now - Days::new(4)).to_rfc3339(),
            overall_status: OverallStatus::NonCompliant,
            compliant_controls: 1,
            total_controls: 2,
            findings: vec![
                Finding {
                    id: "cr-find-003".into(),
                    control_id: "cc-soc2-003".into(),
                    severity: FindingSeverity::Critical,
                    description: "Privileged access review evidence is missing.".into(),
                    remediation: "Complete privileged access recertification and attach evidence."
                        .into(),
                    status: FindingStatus::Open,
                },
                Finding {
                    id: "cr-find-004".into(),
                    control_id: "cc-soc2-003".into(),
                    severity: FindingSeverity::Low,
                    description: "Access control procedure references an old support group.".into(),
                    remediation: "Update procedure owner and support group reference.".into(),
                    status: FindingStatus::Open,
                },
            ],
        },
    ];

    (frameworks, controls, reports)
}

pub fn list_frameworks() -> Result<Value, String> {
    let store = compliance_store().lock().unwrap();
    Ok(json!({ "source": "static-seed", "dry_run": true, "frameworks": store.0 }))
}

pub fn get_framework(id: &str) -> Result<Value, String> {
    let store = compliance_store().lock().unwrap();
    let framework = store
        .0
        .iter()
        .find(|f| f.id == id)
        .ok_or_else(|| format!("Compliance framework '{}' not found", id))?;
    Ok(json!({ "source": "static-seed", "dry_run": true, "framework": framework }))
}

pub fn list_controls(framework_id: &str, site: &str) -> Result<Value, String> {
    let store = compliance_store().lock().unwrap();
    let controls: Vec<ComplianceControl> = store
        .1
        .iter()
        .filter(|c| framework_id.is_empty() || c.framework_id == framework_id)
        .filter(|c| site.is_empty() || c.site == site)
        .cloned()
        .collect();
    Ok(
        json!({ "source": "static-seed", "dry_run": true, "framework_id": framework_id, "site": site, "controls": controls }),
    )
}

pub fn get_control(id: &str) -> Result<Value, String> {
    let store = compliance_store().lock().unwrap();
    let control = store
        .1
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| format!("Compliance control '{}' not found", id))?;
    Ok(json!({ "source": "static-seed", "dry_run": true, "control": control }))
}

pub fn assess_control(
    control_id: &str,
    status: &str,
    assessed_by: &str,
    evidence_ref: &str,
) -> Result<Value, String> {
    if assessed_by.trim().is_empty() {
        return Err("assessed_by cannot be empty".into());
    }
    if evidence_ref.trim().is_empty() {
        return Err("evidence_ref cannot be empty".into());
    }

    let status = parse_control_status(status)?;
    let mut store = compliance_store().lock().unwrap();
    let control = store
        .1
        .iter_mut()
        .find(|c| c.id == control_id)
        .ok_or_else(|| format!("Compliance control '{}' not found", control_id))?;
    control.status = status;
    control.assessed_by = Some(assessed_by.into());
    control.evidence_ref = Some(evidence_ref.into());
    control.assessed_at = Some(now_iso());
    Ok(json!({ "source": "dry-run", "control": control }))
}

pub fn generate_report(framework_id: &str, site: &str) -> Result<Value, String> {
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }

    let mut store = compliance_store().lock().unwrap();
    if !store.0.iter().any(|f| f.id == framework_id) {
        return Err(format!("Compliance framework '{}' not found", framework_id));
    }

    let matching_controls: Vec<ComplianceControl> = store
        .1
        .iter()
        .filter(|c| c.framework_id == framework_id && c.site == site)
        .cloned()
        .collect();
    if matching_controls.is_empty() {
        return Err(format!(
            "No controls found for framework '{}' at site '{}'",
            framework_id, site
        ));
    }

    let (compliant_controls, total_controls, overall_status) =
        summarize_controls(&matching_controls);
    let suffix = Uuid::new_v4().to_string();
    let short_id = suffix.split('-').next().unwrap_or("unknown");
    let findings: Vec<Finding> = matching_controls
        .iter()
        .filter(|c| c.status == ControlStatus::NonCompliant)
        .map(|c| Finding {
            id: format!(
                "cr-find-{}",
                Uuid::new_v4()
                    .to_string()
                    .split('-')
                    .next()
                    .unwrap_or("unknown")
            ),
            control_id: c.id.clone(),
            severity: FindingSeverity::High,
            description: format!("Control {} is non-compliant at {}", c.control_id, site),
            remediation: "Review control evidence, remediate the gap, and reassess the control."
                .into(),
            status: FindingStatus::Open,
        })
        .collect();
    let report = ComplianceReport {
        id: format!(
            "cr-{}-{}-{}",
            site.to_lowercase(),
            framework_id.trim_start_matches("cf-"),
            short_id
        ),
        framework_id: framework_id.into(),
        site: site.into(),
        generated_at: now_iso(),
        overall_status,
        compliant_controls,
        total_controls,
        findings,
    };
    store.2.push(report.clone());
    Ok(json!({ "source": "dry-run", "report": report }))
}

pub fn get_report(id: &str) -> Result<Value, String> {
    let store = compliance_store().lock().unwrap();
    let report = store
        .2
        .iter()
        .find(|r| r.id == id)
        .ok_or_else(|| format!("Compliance report '{}' not found", id))?;
    Ok(json!({ "source": "static-seed", "dry_run": true, "report": report }))
}

pub fn list_findings(site: &str, severity: &str) -> Result<Value, String> {
    let severity_filter = if severity.is_empty() {
        None
    } else {
        Some(parse_severity(severity)?)
    };
    let store = compliance_store().lock().unwrap();
    let findings: Vec<Value> = store
        .2
        .iter()
        .filter(|r| site.is_empty() || r.site == site)
        .flat_map(|r| {
            r.findings.iter().filter_map(|f| {
                if severity_filter.as_ref().is_none_or(|severity| f.severity == *severity) {
                    Some(json!({ "report_id": r.id, "framework_id": r.framework_id, "site": r.site, "finding": f }))
                } else {
                    None
                }
            })
        })
        .collect();
    Ok(
        json!({ "source": "static-seed", "dry_run": true, "site": site, "severity": severity, "findings": findings }),
    )
}

pub fn resolve_finding(id: &str, resolution: &str) -> Result<Value, String> {
    if resolution.trim().is_empty() {
        return Err("resolution cannot be empty".into());
    }

    let mut store = compliance_store().lock().unwrap();
    for report in &mut store.2 {
        if let Some(finding) = report.findings.iter_mut().find(|f| f.id == id) {
            finding.status = FindingStatus::Resolved;
            finding.remediation = format!("{} Resolution: {}", finding.remediation, resolution);
            return Ok(json!({ "source": "dry-run", "report_id": report.id, "finding": finding }));
        }
    }
    Err(format!("Finding '{}' not found", id))
}

pub fn create_waiver(
    finding_id: &str,
    reason: &str,
    approved_by: &str,
    expiry: &str,
) -> Result<Value, String> {
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }
    if approved_by.trim().is_empty() {
        return Err("approved_by cannot be empty".into());
    }
    if chrono::DateTime::parse_from_rfc3339(expiry).is_err() {
        return Err(format!("Invalid waiver expiry: {}", expiry));
    }

    let mut store = compliance_store().lock().unwrap();
    for report in &mut store.2 {
        if let Some(finding) = report.findings.iter_mut().find(|f| f.id == finding_id) {
            finding.status = FindingStatus::Waived;
            finding.remediation = format!(
                "Waived until {} by {}. Reason: {}",
                expiry, approved_by, reason
            );
            return Ok(json!({
                "source": "dry-run",
                "waiver": { "finding_id": finding_id, "reason": reason, "approved_by": approved_by, "expiry": expiry, "created_at": now_iso() },
                "finding": finding
            }));
        }
    }
    Err(format!("Finding '{}' not found", finding_id))
}

pub fn get_compliance_summary(site: &str) -> Result<Value, String> {
    let store = compliance_store().lock().unwrap();
    let summaries: Vec<Value> = store
        .0
        .iter()
        .filter_map(|framework| {
            let controls: Vec<ComplianceControl> = store
                .1
                .iter()
                .filter(|c| c.framework_id == framework.id)
                .filter(|c| site.is_empty() || c.site == site)
                .cloned()
                .collect();
            if controls.is_empty() {
                return None;
            }
            let (compliant_controls, total_controls, overall_status) =
                summarize_controls(&controls);
            let open_findings = store
                .2
                .iter()
                .filter(|r| r.framework_id == framework.id)
                .filter(|r| site.is_empty() || r.site == site)
                .flat_map(|r| r.findings.iter())
                .filter(|f| {
                    f.status == FindingStatus::Open || f.status == FindingStatus::InProgress
                })
                .count();
            let pass_rate = (compliant_controls as f64 / total_controls as f64) * 100.0;
            Some(json!({
                "framework_id": framework.id,
                "framework_name": framework.name,
                "site": site,
                "overall_status": overall_status,
                "compliant_controls": compliant_controls,
                "total_controls": total_controls,
                "pass_rate": pass_rate,
                "open_findings": open_findings
            }))
        })
        .collect();
    Ok(json!({ "source": "static-seed", "dry_run": true, "site": site, "frameworks": summaries }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_frameworks() {
        let result = list_frameworks().unwrap();
        assert_eq!(result["source"], "static-seed");
        assert_eq!(result["frameworks"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_list_and_assess_control() {
        let controls = list_controls("cf-soc2", "FRPAR").unwrap();
        assert_eq!(controls["controls"].as_array().unwrap().len(), 1);
        let assessed = assess_control(
            "cc-soc2-005",
            "Compliant",
            "dana.auditor",
            "ev-soc2-change-005",
        )
        .unwrap();
        assert_eq!(assessed["source"], "dry-run");
        assert_eq!(assessed["control"]["status"], "compliant");
        assert_eq!(assessed["control"]["assessed_by"], "dana.auditor");
    }

    #[test]
    fn test_generate_report() {
        let report = generate_report("cf-iso27001", "FRPAR").unwrap();
        assert_eq!(report["source"], "dry-run");
        assert_eq!(report["report"]["framework_id"], "cf-iso27001");
        assert_eq!(report["report"]["site"], "FRPAR");
        assert_eq!(report["report"]["total_controls"], 1);
        assert_eq!(report["report"]["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_list_findings_by_severity() {
        let findings = list_findings("GBLON", "Critical").unwrap();
        let items = findings["findings"].as_array().unwrap();
        assert!(!items.is_empty());
        assert!(items.iter().all(|f| f["site"] == "GBLON"));
        assert!(items.iter().all(|f| f["finding"]["severity"] == "critical"));
    }

    #[test]
    fn test_resolve_finding() {
        let report = generate_report("cf-pci-dss", "DEFRA").unwrap();
        let finding_id = report["report"]["findings"][0]["id"].as_str().unwrap();
        let resolved = resolve_finding(finding_id, "Encryption evidence attached").unwrap();
        assert_eq!(resolved["finding"]["status"], "resolved");
        assert!(
            resolved["finding"]["remediation"]
                .as_str()
                .unwrap()
                .contains("Encryption evidence attached")
        );
    }

    #[test]
    fn test_create_waiver() {
        let report = generate_report("cf-soc2", "GBLON").unwrap();
        let finding_id = report["report"]["findings"][0]["id"].as_str().unwrap();
        let waiver = create_waiver(
            finding_id,
            "Compensating monitoring control approved",
            "eve.risk",
            "2026-12-31T23:59:59Z",
        )
        .unwrap();
        assert_eq!(waiver["finding"]["status"], "waived");
        assert_eq!(waiver["waiver"]["approved_by"], "eve.risk");
    }

    #[test]
    fn test_compliance_summary() {
        let summary = get_compliance_summary("DEFRA").unwrap();
        let frameworks = summary["frameworks"].as_array().unwrap();
        assert!(!frameworks.is_empty());
        assert!(frameworks.iter().any(|f| f["framework_id"] == "cf-pci-dss"));
        assert!(frameworks.iter().all(|f| f["pass_rate"].is_number()));
    }
}
