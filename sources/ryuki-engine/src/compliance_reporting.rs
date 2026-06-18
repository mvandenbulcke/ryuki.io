use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub fn parse_control_status(status: &str) -> Result<ControlStatus, String> {
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

pub fn parse_severity(severity: &str) -> Result<FindingSeverity, String> {
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

/// Compute (compliant_count, total_count, overall_status) from a slice of controls.
/// NotApplicable controls are excluded from the compliant count but counted in total.
pub fn summarize_controls(controls: &[ComplianceControl]) -> (usize, usize, OverallStatus) {
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

/// Builder for a ComplianceControl used by seed/test helpers.
#[allow(clippy::too_many_arguments)]
pub fn control(
    id: &str,
    framework_id: &str,
    control_id: &str,
    title: &str,
    description: &str,
    status: ControlStatus,
    site: &str,
    days_ago: i64,
) -> ComplianceControl {
    use chrono::Days;
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

// ─── Degraded fallbacks (no DB available) ─────────────────────────────────────
// These functions are called by handlers when get_db() returns None.
// They return empty/error responses so the API degrades gracefully.

pub fn list_frameworks() -> Result<Value, String> {
    Ok(json!({ "source": "static-seed", "dry_run": true, "frameworks": [] }))
}

pub fn get_framework(id: &str) -> Result<Value, String> {
    Err(format!("Compliance framework '{}' not found", id))
}

pub fn list_controls(framework_id: &str, site: &str) -> Result<Value, String> {
    Ok(json!({
        "source": "static-seed",
        "dry_run": true,
        "framework_id": framework_id,
        "site": site,
        "controls": []
    }))
}

pub fn get_control(id: &str) -> Result<Value, String> {
    Err(format!("Compliance control '{}' not found", id))
}

pub fn assess_control(
    _control_id: &str,
    _status: &str,
    _assessed_by: &str,
    _evidence_ref: &str,
) -> Result<Value, String> {
    Err("no database: this operation requires persistence".into())
}

pub fn generate_report(framework_id: &str, site: &str) -> Result<Value, String> {
    // Generate a dry-run report shell — no persistence.
    let suffix = Uuid::new_v4().to_string();
    let short_id = suffix.split('-').next().unwrap_or("unknown");
    Ok(json!({
        "source": "dry-run",
        "dry_run": true,
        "report": {
            "id": format!("cr-{}-{}-{}", site.to_lowercase(), framework_id.trim_start_matches("cf-"), short_id),
            "framework_id": framework_id,
            "site": site,
            "generated_at": now_iso(),
            "overall_status": "non-compliant",
            "compliant_controls": 0,
            "total_controls": 0,
            "findings": []
        }
    }))
}

pub fn get_report(id: &str) -> Result<Value, String> {
    Err(format!("Compliance report '{}' not found", id))
}

pub fn list_findings(site: &str, severity: &str) -> Result<Value, String> {
    Ok(json!({
        "source": "static-seed",
        "dry_run": true,
        "site": site,
        "severity": severity,
        "findings": []
    }))
}

pub fn resolve_finding(id: &str, _resolution: &str) -> Result<Value, String> {
    Err(format!("Finding '{}' not found", id))
}

pub fn create_waiver(
    finding_id: &str,
    _reason: &str,
    _approved_by: &str,
    _expiry: &str,
) -> Result<Value, String> {
    Err(format!("Finding '{}' not found", finding_id))
}

pub fn get_compliance_summary(site: &str) -> Result<Value, String> {
    Ok(json!({
        "source": "static-seed",
        "dry_run": true,
        "site": site,
        "frameworks": []
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_control_status_valid() {
        assert_eq!(
            parse_control_status("Compliant").unwrap(),
            ControlStatus::Compliant
        );
        assert_eq!(
            parse_control_status("NonCompliant").unwrap(),
            ControlStatus::NonCompliant
        );
        assert_eq!(
            parse_control_status("NotApplicable").unwrap(),
            ControlStatus::NotApplicable
        );
    }

    #[test]
    fn test_parse_control_status_invalid() {
        assert!(parse_control_status("compliant").is_err());
        assert!(parse_control_status("non-compliant").is_err());
        assert!(parse_control_status("").is_err());
    }

    #[test]
    fn test_parse_severity_valid() {
        assert_eq!(
            parse_severity("Critical").unwrap(),
            FindingSeverity::Critical
        );
        assert_eq!(parse_severity("High").unwrap(), FindingSeverity::High);
        assert_eq!(parse_severity("Medium").unwrap(), FindingSeverity::Medium);
        assert_eq!(parse_severity("Low").unwrap(), FindingSeverity::Low);
    }

    #[test]
    fn test_parse_severity_invalid() {
        assert!(parse_severity("critical").is_err());
        assert!(parse_severity("CRITICAL").is_err());
        assert!(parse_severity("").is_err());
    }

    #[test]
    fn test_summarize_controls_all_compliant() {
        let controls = vec![
            control(
                "c1",
                "fw",
                "X.1",
                "t",
                "d",
                ControlStatus::Compliant,
                "SITE",
                1,
            ),
            control(
                "c2",
                "fw",
                "X.2",
                "t",
                "d",
                ControlStatus::Compliant,
                "SITE",
                1,
            ),
        ];
        let (compliant, total, status) = summarize_controls(&controls);
        assert_eq!(compliant, 2);
        assert_eq!(total, 2);
        assert_eq!(status, OverallStatus::Compliant);
    }

    #[test]
    fn test_summarize_controls_non_compliant() {
        let controls = vec![
            control(
                "c1",
                "fw",
                "X.1",
                "t",
                "d",
                ControlStatus::Compliant,
                "SITE",
                1,
            ),
            control(
                "c2",
                "fw",
                "X.2",
                "t",
                "d",
                ControlStatus::NonCompliant,
                "SITE",
                1,
            ),
        ];
        let (compliant, total, status) = summarize_controls(&controls);
        assert_eq!(compliant, 1);
        assert_eq!(total, 2);
        assert_eq!(status, OverallStatus::NonCompliant);
    }

    #[test]
    fn test_summarize_controls_at_risk() {
        // All NotApplicable → compliant==0 < total, no non-compliant → AtRisk
        let controls = vec![control(
            "c1",
            "fw",
            "X.1",
            "t",
            "d",
            ControlStatus::NotApplicable,
            "SITE",
            1,
        )];
        let (compliant, total, status) = summarize_controls(&controls);
        assert_eq!(compliant, 0);
        assert_eq!(total, 1);
        assert_eq!(status, OverallStatus::AtRisk);
    }

    #[test]
    fn test_now_iso_non_empty() {
        let ts = now_iso();
        assert!(!ts.is_empty());
        // Must parse as RFC 3339
        assert!(chrono::DateTime::parse_from_rfc3339(&ts).is_ok());
    }

    #[test]
    fn test_generate_report_no_db_returns_ok() {
        // In degraded mode generate_report returns a dry-run shell
        let result = generate_report("cf-pci-dss", "DEFRA");
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v["source"], "dry-run");
        assert_eq!(v["dry_run"], true);
    }

    #[test]
    fn test_resolve_finding_no_db_returns_err() {
        let result = resolve_finding("cr-find-001", "fixed it");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cr-find-001"));
    }
}
