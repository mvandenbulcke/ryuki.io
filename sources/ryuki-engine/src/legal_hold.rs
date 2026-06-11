use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HoldType {
    Investigation,
    Litigation,
    Compliance,
    Retention,
}

impl std::fmt::Display for HoldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HoldType::Investigation => write!(f, "investigation"),
            HoldType::Litigation => write!(f, "litigation"),
            HoldType::Compliance => write!(f, "compliance"),
            HoldType::Retention => write!(f, "retention"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HoldStatus {
    Active,
    Released,
    Expired,
}

impl std::fmt::Display for HoldStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HoldStatus::Active => write!(f, "active"),
            HoldStatus::Released => write!(f, "released"),
            HoldStatus::Expired => write!(f, "expired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub by: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHold {
    pub id: String,
    pub server_or_app_name: String,
    pub hold_type: HoldType,
    pub reason: String,
    pub initiated_by: String,
    pub initiated_date: String,
    pub expiry_date: String,
    pub status: HoldStatus,
    pub affected_backups: Vec<String>,
    pub site: String,
    pub released_by: Option<String>,
    pub released_date: Option<String>,
    pub audit_trail: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub server_name: String,
    pub under_hold: bool,
    pub active_holds: Vec<LegalHold>,
    pub message: String,
}

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];

fn seed_holds() -> Vec<LegalHold> {
    let now = chrono::Utc::now();
    vec![
        LegalHold {
            id: "lh-00000000-0000-0000-0000-000000000001".into(),
            server_or_app_name: "srv-defra-finance.ryuki.local".into(),
            hold_type: HoldType::Litigation,
            reason: "DRY-RUN: Regulatory investigation Q2-2026 — financial audit trail preservation required".into(),
            initiated_by: "compliance-team".into(),
            initiated_date: (now - chrono::Duration::days(45)).to_rfc3339(),
            expiry_date: (now + chrono::Duration::days(135)).to_rfc3339(),
            status: HoldStatus::Active,
            affected_backups: vec![
                "backup-srv-defra-finance-20260601".into(),
                "backup-srv-defra-finance-20260515".into(),
                "backup-srv-defra-finance-20260501".into(),
            ],
            site: "DEFRA".into(),
            released_by: None,
            released_date: None,
            audit_trail: vec![
                AuditEntry {
                    timestamp: (now - chrono::Duration::days(45)).to_rfc3339(),
                    action: "hold_placed".into(),
                    by: "compliance-team".into(),
                    detail: "DRY-RUN: Hold placed for Q2 regulatory investigation".into(),
                },
            ],
        },
        LegalHold {
            id: "lh-00000000-0000-0000-0000-000000000002".into(),
            server_or_app_name: "srv-gblon-erp.ryuki.local".into(),
            hold_type: HoldType::Compliance,
            reason: "DRY-RUN: SOX compliance extended retention — 7-year archive mandate".into(),
            initiated_by: "audit-team".into(),
            initiated_date: (now - chrono::Duration::days(365)).to_rfc3339(),
            expiry_date: (now + chrono::Duration::days(2190)).to_rfc3339(),
            status: HoldStatus::Active,
            affected_backups: vec![
                "backup-srv-gblon-erp-20260301".into(),
                "backup-srv-gblon-erp-20251201".into(),
                "backup-srv-gblon-erp-20250901".into(),
                "backup-srv-gblon-erp-20250601".into(),
            ],
            site: "GBLON".into(),
            released_by: None,
            released_date: None,
            audit_trail: vec![
                AuditEntry {
                    timestamp: (now - chrono::Duration::days(365)).to_rfc3339(),
                    action: "hold_placed".into(),
                    by: "audit-team".into(),
                    detail: "DRY-RUN: SOX compliance retention hold activated".into(),
                },
            ],
        },
        LegalHold {
            id: "lh-00000000-0000-0000-0000-000000000003".into(),
            server_or_app_name: "srv-frpar-hr.ryuki.local".into(),
            hold_type: HoldType::Investigation,
            reason: "DRY-RUN: HR data integrity investigation — access logs and backup retention".into(),
            initiated_by: "security-team".into(),
            initiated_date: (now - chrono::Duration::days(15)).to_rfc3339(),
            expiry_date: (now + chrono::Duration::days(15)).to_rfc3339(),
            status: HoldStatus::Active,
            affected_backups: vec![
                "backup-srv-frpar-hr-20260605".into(),
                "backup-srv-frpar-hr-20260525".into(),
            ],
            site: "FRPAR".into(),
            released_by: None,
            released_date: None,
            audit_trail: vec![
                AuditEntry {
                    timestamp: (now - chrono::Duration::days(15)).to_rfc3339(),
                    action: "hold_placed".into(),
                    by: "security-team".into(),
                    detail: "DRY-RUN: HR investigation hold activated, backup scope defined".into(),
                },
            ],
        },
    ]
}

static HOLD_STORE: std::sync::LazyLock<Mutex<Vec<LegalHold>>> =
    std::sync::LazyLock::new(|| Mutex::new(seed_holds()));

pub fn place_hold(
    target: &str,
    hold_type: HoldType,
    reason: &str,
    by: &str,
    site: &str,
) -> Result<LegalHold, String> {
    if target.is_empty() {
        return Err("target (server_or_app_name) cannot be empty".into());
    }
    if reason.is_empty() {
        return Err("reason cannot be empty".into());
    }
    if by.is_empty() {
        return Err("initiated_by cannot be empty".into());
    }
    if !VALID_SITES.contains(&site) {
        return Err(format!("Unknown site: {}", site));
    }

    let now = chrono::Utc::now();
    let id = format!(
        "lh-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );

    let hold = LegalHold {
        id: id.clone(),
        server_or_app_name: target.to_string(),
        hold_type: hold_type.clone(),
        reason: reason.to_string(),
        initiated_by: by.to_string(),
        initiated_date: now.to_rfc3339(),
        expiry_date: (now + chrono::Duration::days(365)).to_rfc3339(),
        status: HoldStatus::Active,
        affected_backups: vec![format!(
            "DRY-RUN:backup-{}-{}",
            target.replace('.', "-"),
            now.format("%Y%m%d")
        )],
        site: site.to_string(),
        released_by: None,
        released_date: None,
        audit_trail: vec![AuditEntry {
            timestamp: now.to_rfc3339(),
            action: "hold_placed".into(),
            by: by.to_string(),
            detail: format!(
                "DRY-RUN: Legal hold placed on {} (type: {}, reason: {}). No provider calls made.",
                target, hold_type, reason
            ),
        }],
    };

    let mut store = HOLD_STORE.lock().unwrap();
    store.push(hold.clone());
    Ok(hold)
}

pub fn validate_hold(hold_id: &str) -> Result<super::models::ValidationResult, String> {
    if hold_id.is_empty() {
        return Err("hold_id cannot be empty".into());
    }

    let store = HOLD_STORE.lock().unwrap();
    let hold = store
        .iter()
        .find(|h| h.id == hold_id)
        .ok_or_else(|| format!("Legal hold {} not found", hold_id))?;

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if hold.server_or_app_name.is_empty() {
        errors.push("Missing server or application name".into());
        failed_rules.push("p0-target-required".into());
        remediation.push("Provide a valid target name.".into());
    }

    if hold.reason.is_empty() {
        errors.push("Missing hold reason".into());
        failed_rules.push("p0-reason-required".into());
        remediation.push("Provide a business reason for the hold.".into());
    }

    if hold.expiry_date.is_empty() {
        warnings.push("No expiry date set on hold".into());
        failed_rules.push("p1-expiry-required".into());
        remediation.push("Set an expiry date for the hold.".into());
    }

    if hold.affected_backups.is_empty() {
        warnings.push("No affected backups documented".into());
    }

    warnings.push("DRY-RUN: Backup integrity check simulated".into());
    warnings.push("DRY-RUN: Provider hold state verification simulated".into());

    Ok(super::models::ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn extend_hold(hold_id: &str, new_expiry: &str) -> Result<LegalHold, String> {
    if hold_id.is_empty() {
        return Err("hold_id cannot be empty".into());
    }
    if new_expiry.is_empty() {
        return Err("new_expiry cannot be empty".into());
    }

    let now = chrono::Utc::now();
    let mut store = HOLD_STORE.lock().unwrap();
    let hold = store
        .iter_mut()
        .find(|h| h.id == hold_id)
        .ok_or_else(|| format!("Legal hold {} not found", hold_id))?;

    if hold.status != HoldStatus::Active {
        return Err(format!(
            "Cannot extend hold in status {}. Only Active holds can be extended.",
            hold.status
        ));
    }

    hold.expiry_date = new_expiry.to_string();
    hold.audit_trail.push(AuditEntry {
        timestamp: now.to_rfc3339(),
        action: "hold_extended".into(),
        by: "system".into(),
        detail: format!(
            "DRY-RUN: Hold expiry extended to {}. No provider calls made.",
            new_expiry
        ),
    });

    Ok(hold.clone())
}

pub fn release_hold(hold_id: &str, released_by: &str) -> Result<LegalHold, String> {
    if hold_id.is_empty() {
        return Err("hold_id cannot be empty".into());
    }
    if released_by.is_empty() {
        return Err("released_by cannot be empty".into());
    }

    let now = chrono::Utc::now();
    let mut store = HOLD_STORE.lock().unwrap();
    let hold = store
        .iter_mut()
        .find(|h| h.id == hold_id)
        .ok_or_else(|| format!("Legal hold {} not found", hold_id))?;

    if hold.status != HoldStatus::Active {
        return Err(format!(
            "Cannot release hold in status {}. Only Active holds can be released.",
            hold.status
        ));
    }

    hold.status = HoldStatus::Released;
    hold.released_by = Some(released_by.to_string());
    hold.released_date = Some(now.to_rfc3339());
    hold.audit_trail.push(AuditEntry {
        timestamp: now.to_rfc3339(),
        action: "hold_released".into(),
        by: released_by.to_string(),
        detail: "DRY-RUN: Hold released. No provider calls made.".into(),
    });

    Ok(hold.clone())
}

pub fn get_active_holds(site: &str) -> Vec<LegalHold> {
    let store = HOLD_STORE.lock().unwrap();
    store
        .iter()
        .filter(|h| {
            h.status == HoldStatus::Active && (site.is_empty() || h.site == site)
        })
        .cloned()
        .collect()
}

pub fn get_expiring_holds() -> Vec<LegalHold> {
    let now = chrono::Utc::now();
    let threshold = now + chrono::Duration::days(30);
    let store = HOLD_STORE.lock().unwrap();
    store
        .iter()
        .filter(|h| {
            if h.status != HoldStatus::Active {
                return false;
            }
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(&h.expiry_date) {
                let expiry_utc = expiry.with_timezone(&chrono::Utc);
                expiry_utc <= threshold
            } else {
                false
            }
        })
        .cloned()
        .collect()
}

pub fn get_hold_evidence(hold_id: &str) -> Result<Vec<AuditEntry>, String> {
    if hold_id.is_empty() {
        return Err("hold_id cannot be empty".into());
    }
    let store = HOLD_STORE.lock().unwrap();
    let hold = store
        .iter()
        .find(|h| h.id == hold_id)
        .ok_or_else(|| format!("Legal hold {} not found", hold_id))?;
    Ok(hold.audit_trail.clone())
}

pub fn check_compliance(server_name: &str) -> Result<ComplianceResult, String> {
    if server_name.is_empty() {
        return Err("server_name cannot be empty".into());
    }

    let store = HOLD_STORE.lock().unwrap();
    let active_holds: Vec<LegalHold> = store
        .iter()
        .filter(|h| {
            h.status == HoldStatus::Active
                && h.server_or_app_name
                    .to_lowercase()
                    .contains(&server_name.to_lowercase())
        })
        .cloned()
        .collect();

    let under_hold = !active_holds.is_empty();

    Ok(ComplianceResult {
        server_name: server_name.to_string(),
        under_hold,
        active_holds: active_holds.clone(),
        message: if under_hold {
            format!(
                "DRY-RUN: {} is under {} active legal hold(s). Backup deletion blocked. Decommission suspended. No provider calls made.",
                server_name,
                active_holds.len()
            )
        } else {
            format!(
                "DRY-RUN: No active legal holds found for {}. Normal operations permitted.",
                server_name
            )
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_place_hold_success() {
        let result = place_hold(
            "srv-test.ryuki.local",
            HoldType::Litigation,
            "Test hold for validation",
            "test-user",
            "DEFRA",
        )
        .expect("place_hold should succeed");
        assert!(result.id.starts_with("lh-"));
        assert_eq!(result.status, HoldStatus::Active);
        assert_eq!(result.hold_type, HoldType::Litigation);
        assert!(!result.affected_backups.is_empty());
        assert_eq!(result.released_by, None);
        assert_eq!(result.audit_trail.len(), 1);
    }

    #[test]
    fn test_place_hold_empty_target_fails() {
        let result = place_hold("", HoldType::Compliance, "reason", "user", "DEFRA");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("target"));
    }

    #[test]
    fn test_place_hold_invalid_site_fails() {
        let result = place_hold(
            "srv-test.ryuki.local",
            HoldType::Retention,
            "reason",
            "user",
            "INVALID",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown site"));
    }

    #[test]
    fn test_validate_hold_active_hold_passes() {
        let hold = place_hold(
            "srv-validate.ryuki.local",
            HoldType::Investigation,
            "Validation test",
            "test-user",
            "GBLON",
        )
        .unwrap();
        let result = validate_hold(&hold.id).expect("validate should succeed");
        assert!(result.passed);
        assert!(result.errors.is_empty());
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_validate_hold_not_found() {
        let result = validate_hold("nonexistent-id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_extend_hold_updates_expiry() {
        let hold = place_hold(
            "srv-extend.ryuki.local",
            HoldType::Retention,
            "Extend test",
            "test-user",
            "DEFRA",
        )
        .unwrap();
        let new_expiry = "2028-12-31T23:59:59Z";
        let extended = extend_hold(&hold.id, new_expiry).expect("extend should succeed");
        assert_eq!(extended.expiry_date, new_expiry);
        assert_eq!(extended.audit_trail.len(), 2);
        assert!(extended
            .audit_trail
            .iter()
            .any(|e| e.action == "hold_extended"));
    }

    #[test]
    fn test_extend_hold_not_found() {
        let result = extend_hold("nonexistent-id", "2028-01-01T00:00:00Z");
        assert!(result.is_err());
    }

    #[test]
    fn test_release_hold() {
        let hold = place_hold(
            "srv-release.ryuki.local",
            HoldType::Litigation,
            "Release test",
            "test-user",
            "GBLON",
        )
        .unwrap();
        let released = release_hold(&hold.id, "compliance-officer").expect("release should succeed");
        assert_eq!(released.status, HoldStatus::Released);
        assert_eq!(released.released_by, Some("compliance-officer".into()));
        assert!(released.released_date.is_some());
        assert!(released
            .audit_trail
            .iter()
            .any(|e| e.action == "hold_released"));
    }

    #[test]
    fn test_release_hold_already_released_fails() {
        let hold = place_hold(
            "srv-already.ryuki.local",
            HoldType::Investigation,
            "Already released test",
            "test-user",
            "DEFRA",
        )
        .unwrap();
        release_hold(&hold.id, "user").unwrap();
        let result = release_hold(&hold.id, "user");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot release"));
    }

    #[test]
    fn test_get_active_holds_filters_by_site() {
        let holds = get_active_holds("DEFRA");
        assert!(!holds.is_empty());
        assert!(holds.iter().all(|h| h.site == "DEFRA"));
        assert!(holds.iter().all(|h| h.status == HoldStatus::Active));
    }

    #[test]
    fn test_get_active_holds_empty_site_returns_all() {
        let holds = get_active_holds("");
        assert!(!holds.is_empty());
        assert!(holds.iter().all(|h| h.status == HoldStatus::Active));
    }

    #[test]
    fn test_get_expiring_holds_finds_near_expiry() {
        let expiring = get_expiring_holds();
        // At least the seed hold lh-...003 with 15 days to expiry should be found
        let frpar_hold = expiring
            .iter()
            .find(|h| h.site == "FRPAR");
        assert!(frpar_hold.is_some(), "Expected FRPAR investigation hold to be expiring within 30 days");
    }

    #[test]
    fn test_get_hold_evidence_returns_audit_trail() {
        let hold = place_hold(
            "srv-evidence.ryuki.local",
            HoldType::Compliance,
            "Evidence test",
            "test-user",
            "NLAMS",
        )
        .unwrap();
        let evidence = get_hold_evidence(&hold.id).expect("evidence should be found");
        assert!(!evidence.is_empty());
        assert_eq!(evidence[0].action, "hold_placed");
    }

    #[test]
    fn test_check_compliance_server_under_hold() {
        let result = check_compliance("srv-defra-finance")
            .expect("compliance check should succeed");
        assert!(result.under_hold);
        assert!(!result.active_holds.is_empty());
        assert!(result.message.contains("under"));
    }

    #[test]
    fn test_check_compliance_server_not_under_hold() {
        let result = check_compliance("srv-nonexistent")
            .expect("compliance check should succeed");
        assert!(!result.under_hold);
        assert!(result.active_holds.is_empty());
        assert!(result.message.contains("No active legal holds"));
    }

    #[test]
    fn test_hold_type_display() {
        assert_eq!(HoldType::Investigation.to_string(), "investigation");
        assert_eq!(HoldType::Litigation.to_string(), "litigation");
        assert_eq!(HoldType::Compliance.to_string(), "compliance");
        assert_eq!(HoldType::Retention.to_string(), "retention");
    }

    #[test]
    fn test_hold_status_display() {
        assert_eq!(HoldStatus::Active.to_string(), "active");
        assert_eq!(HoldStatus::Released.to_string(), "released");
        assert_eq!(HoldStatus::Expired.to_string(), "expired");
    }

    #[test]
    fn test_seed_holds_has_three_entries() {
        let holds = seed_holds();
        assert_eq!(holds.len(), 3);
        let types: std::collections::HashSet<String> = holds
            .iter()
            .map(|h| h.hold_type.to_string())
            .collect();
        assert!(types.len() >= 3_i32.try_into().unwrap_or(1));
    }

    #[test]
    fn test_extend_hold_empty_expiry_fails() {
        let result = extend_hold("lh-test", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_release_hold_empty_by_fails() {
        let result = release_hold("lh-test", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_compliance_empty_server_fails() {
        let result = check_compliance("");
        assert!(result.is_err());
    }
}
