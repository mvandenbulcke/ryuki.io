use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShiftItem {
    pub id: String,
    pub item_type: ShiftItemType,
    pub title: String,
    pub description: String,
    pub priority: Priority,
    pub assigned_to: Option<String>,
    pub created_at: String,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<String>,
    pub resolved: bool,
    pub resolution: Option<String>,
    pub resolved_at: Option<String>,
    pub escalated: bool,
    pub escalation_reason: Option<String>,
    pub escalated_at: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShiftItemType {
    FailedOperation,
    BlockedRequest,
    PendingApproval,
    ActiveIncident,
    VeeamFailure,
    ZabbixProblem,
    ExpiringCert,
}

impl std::fmt::Display for ShiftItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShiftItemType::FailedOperation => write!(f, "failed-operation"),
            ShiftItemType::BlockedRequest => write!(f, "blocked-request"),
            ShiftItemType::PendingApproval => write!(f, "pending-approval"),
            ShiftItemType::ActiveIncident => write!(f, "active-incident"),
            ShiftItemType::VeeamFailure => write!(f, "veeam-failure"),
            ShiftItemType::ZabbixProblem => write!(f, "zabbix-problem"),
            ShiftItemType::ExpiringCert => write!(f, "expiring-cert"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    P1,
    P2,
    P3,
    P4,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::P1 => write!(f, "P1"),
            Priority::P2 => write!(f, "P2"),
            Priority::P3 => write!(f, "P3"),
            Priority::P4 => write!(f, "P4"),
        }
    }
}

impl Priority {
    #[allow(dead_code)]
    fn as_int(&self) -> u8 {
        match self {
            Priority::P1 => 1,
            Priority::P2 => 2,
            Priority::P3 => 3,
            Priority::P4 => 4,
        }
    }
}

static SHIFT_STORE: OnceLock<Mutex<Vec<ShiftItem>>> = OnceLock::new();

fn shift_store() -> &'static Mutex<Vec<ShiftItem>> {
    SHIFT_STORE.get_or_init(|| Mutex::new(seed_shift_items()))
}

fn seed_shift_items() -> Vec<ShiftItem> {
    let now = Utc::now();
    vec![
        ShiftItem {
            id: "shift-001".into(),
            item_type: ShiftItemType::FailedOperation,
            title: "SQL patching wave failed on sql-love-01".into(),
            description: "Patch wave wave-sql-001 failed during execution step with exit code 3. Rollback completed, server is operational but unpatched.".into(),
            priority: Priority::P2,
            assigned_to: Some("ops-lead".into()),
            created_at: (now - Duration::hours(1)).to_rfc3339(),
            acknowledged: true,
            acknowledged_by: Some("ops-lead".into()),
            acknowledged_at: Some((now - Duration::minutes(30)).to_rfc3339()),
            resolved: false,
            resolution: None,
            resolved_at: None,
            escalated: false,
            escalation_reason: None,
            escalated_at: None,
            metadata: HashMap::from([
                ("site".into(), "LOVE".into()),
                ("wave_id".into(), "wave-sql-001".into()),
            ]),
        },
        ShiftItem {
            id: "shift-002".into(),
            item_type: ShiftItemType::BlockedRequest,
            title: "Linux deployment request blocked awaiting VLAN approval".into(),
            description: "Request req-lnx-042 for RHEL deployment at BUR1 is blocked. VLAN 210 approval from network team is pending for 6 hours.".into(),
            priority: Priority::P3,
            assigned_to: None,
            created_at: (now - Duration::hours(6)).to_rfc3339(),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
            resolved: false,
            resolution: None,
            resolved_at: None,
            escalated: false,
            escalation_reason: None,
            escalated_at: None,
            metadata: HashMap::from([
                ("site".into(), "BUR1".into()),
                ("request_id".into(), "req-lnx-042".into()),
                ("vlan".into(), "210".into()),
            ]),
        },
        ShiftItem {
            id: "shift-003".into(),
            item_type: ShiftItemType::PendingApproval,
            title: "Decommission request awaiting final approval".into(),
            description: "Server srv-legacy-19 at CCSS is ready for decommission. Quarantine period of 7 days completed. Awaiting infra manager approval.".into(),
            priority: Priority::P3,
            assigned_to: Some("infra-lead".into()),
            created_at: (now - Duration::hours(12)).to_rfc3339(),
            acknowledged: true,
            acknowledged_by: Some("infra-lead".into()),
            acknowledged_at: Some((now - Duration::hours(10)).to_rfc3339()),
            resolved: false,
            resolution: None,
            resolved_at: None,
            escalated: false,
            escalation_reason: None,
            escalated_at: None,
            metadata: HashMap::from([
                ("site".into(), "CCSS".into()),
                ("decommission_id".into(), "dec-019".into()),
            ]),
        },
        ShiftItem {
            id: "shift-004".into(),
            item_type: ShiftItemType::ActiveIncident,
            title: "Storage latency spike on esx-bur1-02 datastore".into(),
            description: "Active incident: datastore ds-bur1-prod-03 showing 45ms latency (threshold 20ms). 6 VMs affected. Storage team investigating.".into(),
            priority: Priority::P1,
            assigned_to: Some("storage-lead".into()),
            created_at: (now - Duration::minutes(45)).to_rfc3339(),
            acknowledged: true,
            acknowledged_by: Some("ops-lead".into()),
            acknowledged_at: Some((now - Duration::minutes(40)).to_rfc3339()),
            resolved: false,
            resolution: None,
            resolved_at: None,
            escalated: true,
            escalation_reason: Some("P1 incident affecting production storage".into()),
            escalated_at: Some((now - Duration::minutes(30)).to_rfc3339()),
            metadata: HashMap::from([
                ("site".into(), "BUR1".into()),
                ("datastore".into(), "ds-bur1-prod-03".into()),
                ("incident_id".into(), "INC-2026-0042".into()),
            ]),
        },
        ShiftItem {
            id: "shift-005".into(),
            item_type: ShiftItemType::VeeamFailure,
            title: "Veeam backup job failed for file server fs-tor1-01".into(),
            description: "Last night backup job Backup-FS-TOR1 failed with VSS writer error. No successful backup in 36 hours. Retry attempted 3 times.".into(),
            priority: Priority::P2,
            assigned_to: Some("backup-eng".into()),
            created_at: (now - Duration::hours(3)).to_rfc3339(),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
            resolved: false,
            resolution: None,
            resolved_at: None,
            escalated: false,
            escalation_reason: None,
            escalated_at: None,
            metadata: HashMap::from([
                ("site".into(), "TOR1".into()),
                ("job_name".into(), "Backup-FS-TOR1".into()),
                ("server".into(), "fs-tor1-01".into()),
            ]),
        },
        ShiftItem {
            id: "shift-006".into(),
            item_type: ShiftItemType::ExpiringCert,
            title: "SSL certificate for portal.ryuki.io expiring in 7 days".into(),
            description: "Wildcard certificate *.ryuki.io expires on 2026-06-18. Auto-renewal job cert-renew-portal failed 2 consecutive runs. Manual intervention required.".into(),
            priority: Priority::P2,
            assigned_to: Some("sec-team".into()),
            created_at: (now - Duration::hours(24)).to_rfc3339(),
            acknowledged: true,
            acknowledged_by: Some("sec-team".into()),
            acknowledged_at: Some((now - Duration::hours(20)).to_rfc3339()),
            resolved: false,
            resolution: None,
            resolved_at: None,
            escalated: false,
            escalation_reason: None,
            escalated_at: None,
            metadata: HashMap::from([
                ("cert_name".into(), "*.ryuki.io".into()),
                ("expiry_date".into(), "2026-06-18".into()),
            ]),
        },
    ]
}

pub fn get_shift_summary() -> Value {
    seed_shift_items_if_empty();
    let store = shift_store().lock().unwrap();
    let open: Vec<&ShiftItem> = store.iter().filter(|i| !i.resolved).collect();

    let mut by_type: HashMap<String, Value> = HashMap::new();
    for item in &open {
        let key = item.item_type.to_string();
        let entry = by_type.entry(key).or_insert_with(|| json!({
            "count": 0,
            "items": [],
            "p1_count": 0,
            "p2_count": 0,
            "unacknowledged": 0,
        }));
        let obj = entry.as_object_mut().unwrap();
        obj["count"] = json!(obj["count"].as_u64().unwrap() + 1);
        if item.priority == Priority::P1 {
            obj["p1_count"] = json!(obj["p1_count"].as_u64().unwrap() + 1);
        }
        if item.priority == Priority::P2 {
            obj["p2_count"] = json!(obj["p2_count"].as_u64().unwrap() + 1);
        }
        if !item.acknowledged {
            obj["unacknowledged"] = json!(obj["unacknowledged"].as_u64().unwrap() + 1);
        }
        obj["items"].as_array_mut().unwrap().push(json!({
            "id": item.id,
            "title": item.title,
            "priority": item.priority.to_string(),
            "assigned_to": item.assigned_to,
            "acknowledged": item.acknowledged,
            "escalated": item.escalated,
            "created_at": item.created_at,
        }));
    }

    json!({
        "source": "static-dry-run",
        "total_open": open.len(),
        "p1_open": open.iter().filter(|i| i.priority == Priority::P1).count(),
        "p2_open": open.iter().filter(|i| i.priority == Priority::P2).count(),
        "unacknowledged": open.iter().filter(|i| !i.acknowledged).count(),
        "by_type": by_type,
    })
}

pub fn acknowledge_item(item_id: &str, user: &str) -> Result<Value, String> {
    let mut store = shift_store().lock().unwrap();
    let item = store
        .iter_mut()
        .find(|i| i.id == item_id)
        .ok_or_else(|| format!("Shift item not found: {}", item_id))?;

    if item.resolved {
        return Err("Cannot acknowledge a resolved item".into());
    }
    if item.acknowledged {
        return Err(format!("Item {} is already acknowledged", item_id));
    }

    let now = Utc::now().to_rfc3339();
    item.acknowledged = true;
    item.acknowledged_by = Some(user.to_string());
    item.acknowledged_at = Some(now);

    Ok(json!({
        "status": "acknowledged",
        "id": item.id,
        "acknowledged_by": user,
        "acknowledged_at": item.acknowledged_at,
        "source": "static-dry-run",
    }))
}

pub fn assign_item(item_id: &str, user: &str) -> Result<Value, String> {
    let mut store = shift_store().lock().unwrap();
    let item = store
        .iter_mut()
        .find(|i| i.id == item_id)
        .ok_or_else(|| format!("Shift item not found: {}", item_id))?;

    if item.resolved {
        return Err("Cannot assign a resolved item".into());
    }

    item.assigned_to = Some(user.to_string());

    Ok(json!({
        "status": "assigned",
        "id": item.id,
        "assigned_to": user,
        "source": "static-dry-run",
    }))
}

pub fn escalate_item(item_id: &str, reason: &str) -> Result<Value, String> {
    let mut store = shift_store().lock().unwrap();
    let item = store
        .iter_mut()
        .find(|i| i.id == item_id)
        .ok_or_else(|| format!("Shift item not found: {}", item_id))?;

    if item.resolved {
        return Err("Cannot escalate a resolved item".into());
    }
    if item.escalated {
        return Err(format!("Item {} is already escalated", item_id));
    }

    let now = Utc::now().to_rfc3339();
    item.escalated = true;
    item.escalation_reason = Some(reason.to_string());
    item.escalated_at = Some(now);

    Ok(json!({
        "status": "escalated",
        "id": item.id,
        "reason": reason,
        "escalated_at": item.escalated_at,
        "source": "static-dry-run",
    }))
}

pub fn resolve_item(item_id: &str, resolution: &str) -> Result<Value, String> {
    let mut store = shift_store().lock().unwrap();
    let item = store
        .iter_mut()
        .find(|i| i.id == item_id)
        .ok_or_else(|| format!("Shift item not found: {}", item_id))?;

    if item.resolved {
        return Err(format!("Item {} is already resolved", item_id));
    }

    let now = Utc::now().to_rfc3339();
    item.resolved = true;
    item.resolution = Some(resolution.to_string());
    item.resolved_at = Some(now);

    Ok(json!({
        "status": "resolved",
        "id": item.id,
        "resolution": resolution,
        "resolved_at": item.resolved_at,
        "source": "static-dry-run",
    }))
}

pub fn get_handover_report() -> Value {
    seed_shift_items_if_empty();
    let store = shift_store().lock().unwrap();
    let open: Vec<&ShiftItem> = store.iter().filter(|i| !i.resolved).collect();

    let mut open_items: Vec<Value> = Vec::new();
    for item in &open {
        open_items.push(json!({
            "id": item.id,
            "item_type": item.item_type.to_string(),
            "title": item.title,
            "description": item.description,
            "priority": item.priority.to_string(),
            "assigned_to": item.assigned_to,
            "acknowledged": item.acknowledged,
            "escalated": item.escalated,
            "escalation_reason": item.escalation_reason,
            "created_at": item.created_at,
        }));
    }

    let mut recently_resolved: Vec<Value> = Vec::new();
    let cutoff = Utc::now() - Duration::hours(12);
    for item in store.iter().filter(|i| i.resolved) {
        if let Ok(ts) = DateTime::parse_from_rfc3339(&item.resolved_at.clone().unwrap_or_default()) {
            if ts >= cutoff {
                recently_resolved.push(json!({
                    "id": item.id,
                    "title": item.title,
                    "resolution": item.resolution,
                    "resolved_at": item.resolved_at,
                }));
            }
        }
    }

    json!({
        "source": "static-dry-run",
        "generated_at": Utc::now().to_rfc3339(),
        "shift_summary": {
            "total_open": open.len(),
            "p1_count": open.iter().filter(|i| i.priority == Priority::P1).count(),
            "p2_count": open.iter().filter(|i| i.priority == Priority::P2).count(),
            "unacknowledged_count": open.iter().filter(|i| !i.acknowledged).count(),
            "escalated_count": open.iter().filter(|i| i.escalated).count(),
        },
        "open_items": open_items,
        "recently_resolved": recently_resolved,
        "handover_notes": vec![
            "P1 incident INC-2026-0042 is active — storage team owns it, ops-lead should monitor",
            "Veeam failure for fs-tor1-01 is unacknowledged — needs immediate triage",
            "Cert expiry for *.ryuki.io in 7 days — sec-team assigned",
            "Blocked Linux deployment req-lnx-042 needs network team escalation",
        ],
    })
}

pub fn get_my_items(user: &str) -> Value {
    seed_shift_items_if_empty();
    let store = shift_store().lock().unwrap();
    let mine: Vec<&ShiftItem> = store
        .iter()
        .filter(|i| !i.resolved && i.assigned_to.as_deref() == Some(user))
        .collect();

    let items: Vec<Value> = mine
        .iter()
        .map(|item| {
            json!({
                "id": item.id,
                "item_type": item.item_type.to_string(),
                "title": item.title,
                "priority": item.priority.to_string(),
                "acknowledged": item.acknowledged,
                "escalated": item.escalated,
                "created_at": item.created_at,
            })
        })
        .collect();

    json!({
        "source": "static-dry-run",
        "user": user,
        "count": items.len(),
        "items": items,
    })
}

pub fn get_stale_items() -> Value {
    seed_shift_items_if_empty();
    let store = shift_store().lock().unwrap();
    let cutoff = Utc::now() - Duration::hours(4);

    let stale: Vec<&ShiftItem> = store
        .iter()
        .filter(|i| {
            if i.resolved || i.acknowledged {
                return false;
            }
            DateTime::parse_from_rfc3339(&i.created_at)
                .map(|ts| ts < cutoff)
                .unwrap_or(false)
        })
        .collect();

    let items: Vec<Value> = stale
        .iter()
        .map(|item| {
            json!({
                "id": item.id,
                "item_type": item.item_type.to_string(),
                "title": item.title,
                "priority": item.priority.to_string(),
                "assigned_to": item.assigned_to,
                "created_at": item.created_at,
                "hours_stale": (Utc::now() - DateTime::parse_from_rfc3339(&item.created_at).unwrap().with_timezone(&Utc)).num_hours(),
            })
        })
        .collect();

    json!({
        "source": "static-dry-run",
        "stale_threshold_hours": 4,
        "count": items.len(),
        "items": items,
    })
}

fn seed_shift_items_if_empty() {
    let mut store = shift_store().lock().unwrap();
    if store.is_empty() {
        *store = seed_shift_items();
    }
}

pub fn get_shift_contract() -> Value {
    seed_shift_items_if_empty();
    json!({
        "source": "static-seed",
        "queueMode": "aggregate-safe",
        "providerCallsEnabled": false,
        "liveExecutionAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "queueSources": [
            "failed-operation",
            "blocked-request",
            "pending-approval",
            "active-incident",
            "veeam-failure",
            "zabbix-problem",
            "expiring-cert",
            "handover-note"
        ],
        "queueStates": [
            "new",
            "triage",
            "owner-assigned",
            "waiting-approval",
            "waiting-dependency",
            "ready-for-handover",
            "closed"
        ],
        "requiredInputs": [
            "queueItemSource",
            "severity",
            "owner",
            "supportGroup",
            "safeNextAction",
            "handoverNotes",
            "evidenceManifest"
        ],
        "requiredGuards": [
            "owner-known",
            "support-group-known",
            "severity-assigned",
            "safe-next-action-set",
            "evidence-redacted",
            "stale-data-marked"
        ],
        "blockedReasons": [
            "owner-unknown",
            "support-group-unknown",
            "missing-safe-next-action",
            "approval-pending",
            "dependency-unhealthy",
            "stale-data",
            "evidence-not-redacted"
        ],
        "requiredEvidence": [
            "Queue item summary",
            "Owner assignment",
            "Safe next action",
            "Approval state",
            "Dependency health",
            "Handover notes",
            "Evidence references"
        ],
        "rules": [
            {
                "id": "no-raw-provider-payloads",
                "decision": "block",
                "requirement": "Shift queue items summarize provider state without exposing raw provider payloads.",
                "evidence": "Queue item summary"
            },
            {
                "id": "safe-next-action-required",
                "decision": "block",
                "requirement": "Every visible queue item must include a safe next action for the assigned team.",
                "evidence": "Safe next action"
            },
            {
                "id": "owner-and-support-required",
                "decision": "block",
                "requirement": "Owner and support group must be known before a queue item can leave triage.",
                "evidence": "Owner assignment"
            },
            {
                "id": "handover-evidence-required",
                "decision": "block",
                "requirement": "Queue items that cross shifts must keep handover notes and evidence references.",
                "evidence": "Handover notes"
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_store() {
        let mut guard = shift_store().lock().unwrap();
        *guard = seed_shift_items();
    }

    #[test]
    fn test_get_shift_summary_returns_open_items() {
        fresh_store();
        let summary = get_shift_summary();
        assert_eq!(summary["source"], "static-dry-run");
        assert!(summary["total_open"].as_u64().is_some());
        assert!(summary["by_type"].as_object().unwrap().contains_key("active-incident"));
    }

    #[test]
    fn test_acknowledge_item_marks_as_seen() {
        fresh_store();
        let result = acknowledge_item("shift-002", "ops-lead").unwrap();
        assert_eq!(result["status"], "acknowledged");
        assert_eq!(result["acknowledged_by"], "ops-lead");
        assert!(result["acknowledged_at"].as_str().is_some());
    }

    #[test]
    fn test_acknowledge_already_acknowledged_fails() {
        fresh_store();
        assert!(acknowledge_item("shift-001", "someone").is_err());
    }

    #[test]
    fn test_acknowledge_resolved_fails() {
        fresh_store();
        resolve_item("shift-003", "Done").unwrap();
        assert!(acknowledge_item("shift-003", "someone").is_err());
    }

    #[test]
    fn test_assign_item_updates_owner() {
        fresh_store();
        let result = assign_item("shift-002", "network-team").unwrap();
        assert_eq!(result["status"], "assigned");
        assert_eq!(result["assigned_to"], "network-team");
    }

    #[test]
    fn test_escalate_item_flags_and_logs_reason() {
        fresh_store();
        let result = escalate_item("shift-005", "No backup for 36 hours — critical gap").unwrap();
        assert_eq!(result["status"], "escalated");
        assert!(result["reason"].as_str().unwrap().contains("critical"));
        assert!(result["escalated_at"].as_str().is_some());
    }

    #[test]
    fn test_escalate_already_escalated_fails() {
        fresh_store();
        assert!(escalate_item("shift-004", "double escalate").is_err());
    }

    #[test]
    fn test_resolve_item_marks_as_done() {
        fresh_store();
        let result = resolve_item("shift-006", "Manual cert renewal completed, auto-renewal job fixed").unwrap();
        assert_eq!(result["status"], "resolved");
        assert_eq!(result["resolution"], "Manual cert renewal completed, auto-renewal job fixed");
        assert!(result["resolved_at"].as_str().is_some());
    }

    #[test]
    fn test_get_handover_report_includes_open_and_recently_resolved() {
        fresh_store();
        resolve_item("shift-003", "Approval obtained, decommission in progress").unwrap();
        let report = get_handover_report();
        assert_eq!(report["source"], "static-dry-run");
        assert!(report["generated_at"].as_str().is_some());
        assert!(report["shift_summary"]["total_open"].as_u64().is_some());
        assert!(!report["handover_notes"].as_array().unwrap().is_empty());
        assert!(report["recently_resolved"].as_array().is_some());
    }

    #[test]
    fn test_get_my_items_filters_by_user() {
        fresh_store();
        let my = get_my_items("ops-lead");
        assert_eq!(my["user"], "ops-lead");
        let items = my["items"].as_array().unwrap();
        let has_shift_001 = items.iter().any(|i| i["id"] == "shift-001");
        assert!(has_shift_001);
    }

    #[test]
    fn test_get_my_items_returns_empty_for_unknown_user() {
        fresh_store();
        let my = get_my_items("nonexistent-user");
        assert_eq!(my["count"].as_u64().unwrap(), 0);
        assert!(my["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_get_stale_items_finds_unacknowledged_old_items() {
        fresh_store();
        let stale = get_stale_items();
        assert_eq!(stale["source"], "static-dry-run");
        assert_eq!(stale["stale_threshold_hours"].as_u64().unwrap(), 4);
        let items = stale["items"].as_array().unwrap();
        let has_shift_002 = items.iter().any(|i| i["id"] == "shift-002");
        assert!(has_shift_002);
    }

    #[test]
    fn test_get_shift_contract_returns_valid_structure() {
        fresh_store();
        let contract = get_shift_contract();
        assert_eq!(contract["source"], "static-seed");
        assert_eq!(contract["queueMode"], "aggregate-safe");
        assert_eq!(contract["providerCallsEnabled"], false);
        assert!(contract["rules"].as_array().unwrap().len() >= 4);
    }

    #[test]
    fn test_shift_item_type_display() {
        assert_eq!(ShiftItemType::FailedOperation.to_string(), "failed-operation");
        assert_eq!(ShiftItemType::BlockedRequest.to_string(), "blocked-request");
        assert_eq!(ShiftItemType::ActiveIncident.to_string(), "active-incident");
        assert_eq!(ShiftItemType::VeeamFailure.to_string(), "veeam-failure");
        assert_eq!(ShiftItemType::ZabbixProblem.to_string(), "zabbix-problem");
        assert_eq!(ShiftItemType::ExpiringCert.to_string(), "expiring-cert");
        assert_eq!(ShiftItemType::PendingApproval.to_string(), "pending-approval");
    }

    #[test]
    fn test_priority_display_and_ordering() {
        assert_eq!(Priority::P1.to_string(), "P1");
        assert!(Priority::P1 < Priority::P2);
        assert!(Priority::P2 < Priority::P3);
        assert_eq!(Priority::P1.as_int(), 1);
        assert_eq!(Priority::P4.as_int(), 4);
    }

    #[test]
    fn test_item_not_found_errors() {
        fresh_store();
        assert!(acknowledge_item("shift-999", "user").is_err());
        assert!(assign_item("shift-999", "user").is_err());
        assert!(escalate_item("shift-999", "reason").is_err());
        assert!(resolve_item("shift-999", "done").is_err());
    }

    #[test]
    fn test_resolve_already_resolved_fails() {
        fresh_store();
        {
            let mut guard = shift_store().lock().unwrap();
            let item = guard.iter_mut().find(|i| i.id == "shift-003").unwrap();
            item.resolved = true;
        }
        assert!(resolve_item("shift-003", "Done again").is_err());
    }
}
