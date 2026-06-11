use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

type EmergencyStore = Vec<EmergencyChange>;

static EMERGENCY_STORE: OnceLock<Mutex<EmergencyStore>> = OnceLock::new();

fn emergency_store() -> &'static Mutex<EmergencyStore> {
    EMERGENCY_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> EmergencyStore {
    let now = Utc::now();
    vec![
        EmergencyChange {
            id: "emg-love-001".into(),
            change_description: "Urgent firewall rule change for DB replication recovery".into(),
            affected_systems: vec!["love-db-cluster".into(), "love-fw-edge".into()],
            initiated_by: "alice.operator".into(),
            reason_override: "Incident INC-2025-0042 — replication lag exceeds SLA".into(),
            approved_by: Some("EMERGENCY — auto-approved per break-glass policy".into()),
            executed_at: Some((now - chrono::Duration::hours(3)).to_rfc3339()),
            status: EmergencyChangeStatus::Verified,
            audit_evidence: vec![
                "FW rule diff applied to love-fw-edge-01".into(),
                "DB replication caught up within 12min of change".into(),
                "Post-change verification: all replicas in sync".into(),
            ],
            site: "LOVE".into(),
            created_at: (now - chrono::Duration::hours(4)).to_rfc3339(),
            updated_at: (now - chrono::Duration::hours(2)).to_rfc3339(),
            post_review_notes: Some(
                "Reviewed by SOC lead. Emergency justified. No process gap.".into(),
            ),
        },
        EmergencyChange {
            id: "emg-bur1-001".into(),
            change_description: "Emergency storage capacity expansion — datastore at 97%"
                .into(),
            affected_systems: vec!["bur1-vsan-cluster".into(), "bur1-datastore-prod".into()],
            initiated_by: "bob.engineer".into(),
            reason_override: "Capacity alert BUR1-DS-PROD-001 — risk of VM outage".into(),
            approved_by: Some("EMERGENCY — auto-approved per break-glass policy".into()),
            executed_at: Some((now - chrono::Duration::hours(1)).to_rfc3339()),
            status: EmergencyChangeStatus::Executed,
            audit_evidence: vec![
                "Added 2TB to bur1-datastore-prod".into(),
                "No VM disruption observed".into(),
                "Post-expand usage: 72%".into(),
            ],
            site: "BUR1".into(),
            created_at: (now - chrono::Duration::hours(2)).to_rfc3339(),
            updated_at: (now - chrono::Duration::hours(1)).to_rfc3339(),
            post_review_notes: None,
        },
        EmergencyChange {
            id: "emg-love-002".into(),
            change_description: "Emergency certificate renewal — wildcard expired on love-lb-01"
                .into(),
            affected_systems: vec!["love-lb-01".into(), "love-ingress".into()],
            initiated_by: "carol.security".into(),
            reason_override: "TLS cert expiry causing user-facing errors on portal".into(),
            approved_by: Some("EMERGENCY — auto-approved per break-glass policy".into()),
            executed_at: None,
            status: EmergencyChangeStatus::Approved,
            audit_evidence: vec![],
            site: "LOVE".into(),
            created_at: (now - chrono::Duration::minutes(30)).to_rfc3339(),
            updated_at: (now - chrono::Duration::minutes(15)).to_rfc3339(),
            post_review_notes: None,
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmergencyChange {
    pub id: String,
    pub change_description: String,
    pub affected_systems: Vec<String>,
    pub initiated_by: String,
    pub reason_override: String,
    pub approved_by: Option<String>,
    pub executed_at: Option<String>,
    pub status: EmergencyChangeStatus,
    pub audit_evidence: Vec<String>,
    pub site: String,
    pub created_at: String,
    pub updated_at: String,
    pub post_review_notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EmergencyChangeStatus {
    Initiated,
    Approved,
    Executed,
    Verified,
    Closed,
}

impl std::fmt::Display for EmergencyChangeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmergencyChangeStatus::Initiated => write!(f, "Initiated"),
            EmergencyChangeStatus::Approved => write!(f, "Approved"),
            EmergencyChangeStatus::Executed => write!(f, "Executed"),
            EmergencyChangeStatus::Verified => write!(f, "Verified"),
            EmergencyChangeStatus::Closed => write!(f, "Closed"),
        }
    }
}

pub fn initiate_emergency(
    description: &str,
    systems: Vec<String>,
    initiated_by: &str,
    reason: &str,
    site: &str,
) -> Result<Value, String> {
    if description.is_empty() || initiated_by.is_empty() || reason.is_empty() || site.is_empty() {
        return Err("description, initiated_by, reason, and site are required".into());
    }

    let now = Utc::now();
    let change = EmergencyChange {
        id: format!("emg-{}", Uuid::new_v4().to_string().split('-').next().unwrap()),
        change_description: description.into(),
        affected_systems: systems,
        initiated_by: initiated_by.into(),
        reason_override: reason.into(),
        approved_by: None,
        executed_at: None,
        status: EmergencyChangeStatus::Initiated,
        audit_evidence: vec![],
        site: site.into(),
        created_at: now.to_rfc3339(),
        updated_at: now.to_rfc3339(),
        post_review_notes: None,
    };

    let response = json!({
        "source": "dry-run",
        "change_id": change.id,
        "status": change.status.to_string(),
        "initiated_by": change.initiated_by,
        "site": change.site,
        "created_at": change.created_at,
        "dry_run": true
    });

    let mut store = emergency_store().lock().unwrap();
    store.push(change);

    Ok(response)
}

pub fn auto_approve(change_id: &str) -> Result<Value, String> {
    let mut store = emergency_store().lock().unwrap();
    let change = store
        .iter_mut()
        .find(|e| e.id == change_id)
        .ok_or_else(|| format!("Emergency change {} not found", change_id))?;

    if change.status != EmergencyChangeStatus::Initiated {
        return Err(format!(
            "Cannot approve change in {} status",
            change.status
        ));
    }

    let now = Utc::now();
    change.status = EmergencyChangeStatus::Approved;
    change.approved_by = Some("EMERGENCY — auto-approved per break-glass policy".into());
    change.updated_at = now.to_rfc3339();
    change
        .audit_evidence
        .push(format!("EMERGENCY flag — auto-approved at {}", now.to_rfc3339()));

    Ok(json!({
        "source": "dry-run",
        "change_id": change_id,
        "status": "Approved",
        "approved_by": "EMERGENCY — auto-approved per break-glass policy",
        "approved_at": now.to_rfc3339(),
        "dry_run": true
    }))
}

pub fn execute_emergency(change_id: &str) -> Result<Value, String> {
    let mut store = emergency_store().lock().unwrap();
    let change = store
        .iter_mut()
        .find(|e| e.id == change_id)
        .ok_or_else(|| format!("Emergency change {} not found", change_id))?;

    if change.status != EmergencyChangeStatus::Approved {
        return Err(format!(
            "Cannot execute change in {} status — approval required",
            change.status
        ));
    }

    let now = Utc::now();
    change.status = EmergencyChangeStatus::Executed;
    change.executed_at = Some(now.to_rfc3339());
    change.updated_at = now.to_rfc3339();
    change.audit_evidence.push(format!(
        "[REDACTED] Dry-run mock execution completed at {}",
        now.to_rfc3339()
    ));
    change.audit_evidence.push(format!(
        "[REDACTED] Affected systems: {}",
        change.affected_systems.join(", ")
    ));

    Ok(json!({
        "source": "dry-run",
        "change_id": change_id,
        "status": "Executed",
        "executed_at": now.to_rfc3339(),
        "affected_systems": change.affected_systems,
        "audit_evidence": change.audit_evidence,
        "dry_run": true
    }))
}

pub fn verify_emergency(change_id: &str) -> Result<Value, String> {
    let mut store = emergency_store().lock().unwrap();
    let change = store
        .iter_mut()
        .find(|e| e.id == change_id)
        .ok_or_else(|| format!("Emergency change {} not found", change_id))?;

    if change.status != EmergencyChangeStatus::Executed {
        return Err(format!(
            "Cannot verify change in {} status — execution required",
            change.status
        ));
    }

    let now = Utc::now();
    change.status = EmergencyChangeStatus::Verified;
    change.updated_at = now.to_rfc3339();
    change.audit_evidence.push(format!(
        "[REDACTED] Post-execution verification passed at {}",
        now.to_rfc3339()
    ));

    Ok(json!({
        "source": "dry-run",
        "change_id": change_id,
        "status": "Verified",
        "verified_at": now.to_rfc3339(),
        "audit_evidence": change.audit_evidence,
        "dry_run": true
    }))
}

pub fn close_emergency(change_id: &str, post_review_notes: &str) -> Result<Value, String> {
    let mut store = emergency_store().lock().unwrap();
    let change = store
        .iter_mut()
        .find(|e| e.id == change_id)
        .ok_or_else(|| format!("Emergency change {} not found", change_id))?;

    if change.status != EmergencyChangeStatus::Verified {
        return Err(format!(
            "Cannot close change in {} status — verification required",
            change.status
        ));
    }

    let now = Utc::now();
    change.status = EmergencyChangeStatus::Closed;
    change.post_review_notes = Some(post_review_notes.into());
    change.updated_at = now.to_rfc3339();
    change.audit_evidence.push(format!(
        "Post-mortem review completed at {}",
        now.to_rfc3339()
    ));

    Ok(json!({
        "source": "dry-run",
        "change_id": change_id,
        "status": "Closed",
        "closed_at": now.to_rfc3339(),
        "post_review_notes": post_review_notes,
        "dry_run": true
    }))
}

pub fn get_active_emergencies() -> Result<Value, String> {
    let store = emergency_store().lock().unwrap();
    let active: Vec<&EmergencyChange> = store
        .iter()
        .filter(|e| e.status != EmergencyChangeStatus::Closed)
        .collect();

    Ok(json!({
        "source": "dry-run",
        "count": active.len(),
        "emergencies": active.iter().map(|e| json!({
            "id": e.id,
            "change_description": e.change_description,
            "affected_systems": e.affected_systems,
            "initiated_by": e.initiated_by,
            "reason_override": e.reason_override,
            "approved_by": e.approved_by,
            "executed_at": e.executed_at,
            "status": e.status.to_string(),
            "site": e.site,
            "created_at": e.created_at,
            "updated_at": e.updated_at,
            "audit_evidence_count": e.audit_evidence.len(),
        })).collect::<Vec<_>>(),
        "dry_run": true
    }))
}

pub fn get_emergency_history(site: &str) -> Result<Value, String> {
    let store = emergency_store().lock().unwrap();
    let history: Vec<&EmergencyChange> = if site.is_empty() {
        store.iter().collect()
    } else {
        store.iter().filter(|e| e.site == site).collect()
    };

    Ok(json!({
        "source": "dry-run",
        "site": if site.is_empty() { "all" } else { site },
        "count": history.len(),
        "history": history.iter().map(|e| json!({
            "id": e.id,
            "change_description": e.change_description,
            "affected_systems": e.affected_systems,
            "initiated_by": e.initiated_by,
            "reason_override": e.reason_override,
            "approved_by": e.approved_by,
            "executed_at": e.executed_at,
            "status": e.status.to_string(),
            "site": e.site,
            "created_at": e.created_at,
            "updated_at": e.updated_at,
            "post_review_notes": e.post_review_notes,
            "audit_evidence": e.audit_evidence,
        })).collect::<Vec<_>>(),
        "dry_run": true
    }))
}

pub fn get_emergency_stats(site: &str) -> Result<Value, String> {
    let store = emergency_store().lock().unwrap();
    let changes: Vec<&EmergencyChange> = if site.is_empty() {
        store.iter().collect()
    } else {
        store.iter().filter(|e| e.site == site).collect()
    };

    let mut by_month: HashMap<String, usize> = HashMap::new();
    let mut initiator_counts: HashMap<String, usize> = HashMap::new();

    for change in &changes {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&change.created_at) {
            let month_key = dt.format("%Y-%m").to_string();
            *by_month.entry(month_key).or_insert(0) += 1;
        }
        *initiator_counts
            .entry(change.initiated_by.clone())
            .or_insert(0) += 1;
    }

    let mut top_initiators: Vec<(String, usize)> = initiator_counts.into_iter().collect();
    top_initiators.sort_by(|a, b| b.1.cmp(&a.1));
    let top_initiators: Vec<Value> = top_initiators
        .into_iter()
        .map(|(name, count)| {
            json!({ "initiator": name, "count": count })
        })
        .collect();

    let mut monthly: Vec<Value> = by_month
        .into_iter()
        .map(|(month, count)| json!({ "month": month, "count": count }))
        .collect();
    monthly.sort_by(|a, b| a["month"].as_str().cmp(&b["month"].as_str()));

    Ok(json!({
        "source": "dry-run",
        "site": if site.is_empty() { "all" } else { site },
        "total": changes.len(),
        "by_month": monthly,
        "top_initiators": top_initiators,
        "dry_run": true
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_data_has_base_changes() {
        let store = emergency_store().lock().unwrap();
        assert!(store.len() >= 3);
    }

    #[test]
    fn test_initiate_emergency_creates_change() {
        let result = initiate_emergency(
            "Urgent DNS config fix",
            vec!["dns-primary".into()],
            "test.user",
            "Outage mitigation",
            "LOVE",
        )
        .unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["status"], "Initiated");
        assert_eq!(result["site"], "LOVE");
        assert!(result["change_id"].as_str().unwrap().starts_with("emg-"));
    }

    #[test]
    fn test_initiate_emergency_rejects_empty_fields() {
        assert!(initiate_emergency("", vec!["s".into()], "u", "r", "s").is_err());
        assert!(initiate_emergency("d", vec!["s".into()], "", "r", "s").is_err());
    }

    #[test]
    fn test_initiate_and_approve_workflow() {
        let init = initiate_emergency(
            "config change",
            vec!["system-a".into()],
            "alice",
            "outage",
            "LOVE",
        )
        .unwrap();
        let id = init["change_id"].as_str().unwrap();

        let result = auto_approve(id).unwrap();
        assert_eq!(result["status"], "Approved");
        assert!(result["approved_by"]
            .as_str()
            .unwrap()
            .contains("EMERGENCY"));
    }

    #[test]
    fn test_cannot_approve_non_initiated() {
        let emg = "emg-love-001";
        let result = auto_approve(emg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot approve"));
    }

    #[test]
    fn test_full_workflow_through_close() {
        let init = initiate_emergency(
            "patch emergency",
            vec!["host-a".into()],
            "bob",
            "zero-day",
            "BUR1",
        )
        .unwrap();
        let id = init["change_id"].as_str().unwrap();

        auto_approve(id).unwrap();
        let exec = execute_emergency(id).unwrap();
        assert_eq!(exec["status"], "Executed");

        let ver = verify_emergency(id).unwrap();
        assert_eq!(ver["status"], "Verified");

        let cls = close_emergency(id, "Post-mortem: justified").unwrap();
        assert_eq!(cls["status"], "Closed");
        assert_eq!(cls["post_review_notes"], "Post-mortem: justified");
    }

    #[test]
    fn test_cannot_execute_without_approval() {
        let init = initiate_emergency(
            "unapproved change",
            vec!["h".into()],
            "c",
            "r",
            "LOVE",
        )
        .unwrap();
        let id = init["change_id"].as_str().unwrap();
        let result = execute_emergency(id);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_verify_without_execution() {
        let init = initiate_emergency(
            "early verify",
            vec!["h".into()],
            "d",
            "r",
            "LOVE",
        )
        .unwrap();
        let id = init["change_id"].as_str().unwrap();
        auto_approve(id).unwrap();
        let result = verify_emergency(id);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_active_emergencies() {
        let result = get_active_emergencies().unwrap();
        assert_eq!(result["source"], "dry-run");
        let count = result["count"].as_u64().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_get_emergency_history_by_site() {
        let result = get_emergency_history("LOVE").unwrap();
        assert_eq!(result["site"], "LOVE");
        assert!(result["count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_get_emergency_history_all() {
        let result = get_emergency_history("").unwrap();
        assert_eq!(result["site"], "all");
        assert!(result["count"].as_u64().unwrap() >= 3);
    }

    #[test]
    fn test_get_emergency_stats() {
        let result = get_emergency_stats("").unwrap();
        assert_eq!(result["source"], "dry-run");
        assert!(result["total"].as_u64().unwrap() >= 3);
        assert!(!result["by_month"].as_array().unwrap().is_empty());
        assert!(!result["top_initiators"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_not_found_returns_error() {
        assert!(auto_approve("nonexistent").is_err());
        assert!(execute_emergency("nonexistent").is_err());
        assert!(verify_emergency("nonexistent").is_err());
        assert!(close_emergency("nonexistent", "n").is_err());
    }

    #[test]
    fn test_get_emergency_stats_by_site() {
        let result = get_emergency_stats("BUR1").unwrap();
        assert_eq!(result["site"], "BUR1");
        assert!(result["total"].as_u64().unwrap() >= 1);
    }
}
