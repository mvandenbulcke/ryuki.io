use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceNowRequest {
    pub id: String,
    pub request_type: ServiceNowRequestType,
    pub external_ref: String,
    pub status: ServiceNowSubmissionStatus,
    pub ci_name: String,
    pub payload_summary: String,
    pub created_at: String,
    pub submitted_at: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceNowRequestType {
    Incident,
    Change,
    Request,
    Knowledge,
}

impl std::fmt::Display for ServiceNowRequestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceNowRequestType::Incident => write!(f, "incident"),
            ServiceNowRequestType::Change => write!(f, "change"),
            ServiceNowRequestType::Request => write!(f, "request"),
            ServiceNowRequestType::Knowledge => write!(f, "knowledge"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceNowSubmissionStatus {
    Draft,
    Ready,
    Pending,
    Submitted,
    Failed,
}

impl std::fmt::Display for ServiceNowSubmissionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceNowSubmissionStatus::Draft => write!(f, "Draft"),
            ServiceNowSubmissionStatus::Ready => write!(f, "Ready"),
            ServiceNowSubmissionStatus::Pending => write!(f, "Pending"),
            ServiceNowSubmissionStatus::Submitted => write!(f, "Submitted"),
            ServiceNowSubmissionStatus::Failed => write!(f, "Failed"),
        }
    }
}

static SN_STORE: OnceLock<Mutex<Vec<ServiceNowRequest>>> = OnceLock::new();

fn sn_store() -> &'static Mutex<Vec<ServiceNowRequest>> {
    SN_STORE.get_or_init(|| Mutex::new(seed_requests()))
}

fn seed_requests() -> Vec<ServiceNowRequest> {
    let now = Utc::now().to_rfc3339();
    vec![
        ServiceNowRequest {
            id: "sn-req-001".into(),
            request_type: ServiceNowRequestType::Incident,
            external_ref: "INC-2026-0042".into(),
            status: ServiceNowSubmissionStatus::Submitted,
            ci_name: "srv-love-web01.corp.local".into(),
            payload_summary: "High CPU alert — incident created, ops-lead assigned".into(),
            created_at: now.clone(),
            submitted_at: Some(now.clone()),
            metadata: HashMap::from([
                ("urgency".into(), "2".into()),
                ("assignment_group".into(), "Wintel-Operations".into()),
                ("site".into(), "LOVE".into()),
            ]),
        },
        ServiceNowRequest {
            id: "sn-req-002".into(),
            request_type: ServiceNowRequestType::Change,
            external_ref: "CHG-2026-0127".into(),
            status: ServiceNowSubmissionStatus::Ready,
            ci_name: "srv-bur1-db01.corp.local".into(),
            payload_summary: "Planned memory upgrade from 64 GB to 128 GB — maintenance window 2026-06-15 02:00-04:00 UTC".into(),
            created_at: now.clone(),
            submitted_at: None,
            metadata: HashMap::from([
                ("change_type".into(), "Standard".into()),
                ("risk".into(), "Low".into()),
                ("planned_start".into(), "2026-06-15T02:00:00Z".into()),
                ("planned_end".into(), "2026-06-15T04:00:00Z".into()),
                ("site".into(), "BUR1".into()),
            ]),
        },
        ServiceNowRequest {
            id: "sn-req-003".into(),
            request_type: ServiceNowRequestType::Request,
            external_ref: "REQ-2026-0399".into(),
            status: ServiceNowSubmissionStatus::Draft,
            ci_name: "srv-tor1-mon01.corp.local".into(),
            payload_summary: "Request for Zabbix agent upgrade on monitoring server — pending validation".into(),
            created_at: now.clone(),
            submitted_at: None,
            metadata: HashMap::from([
                ("request_type".into(), "software-upgrade".into()),
                ("site".into(), "TOR1".into()),
            ]),
        },
        ServiceNowRequest {
            id: "sn-req-004".into(),
            request_type: ServiceNowRequestType::Knowledge,
            external_ref: "KB-2026-0182".into(),
            status: ServiceNowSubmissionStatus::Pending,
            ci_name: "srv-wijh-fs01.corp.local".into(),
            payload_summary: "VSS writer recovery procedure for file server backup failures — draft KB article".into(),
            created_at: now.clone(),
            submitted_at: None,
            metadata: HashMap::from([
                ("knowledge_base".into(), "Operations".into()),
                ("site".into(), "WIJH".into()),
            ]),
        },
    ]
}

fn seed_requests_if_empty() {
    let mut store = sn_store().lock().unwrap();
    if store.is_empty() {
        *store = seed_requests();
    }
}

fn new_request(
    request_type: ServiceNowRequestType,
    ci_name: &str,
    payload_summary: &str,
    metadata: HashMap<String, String>,
) -> ServiceNowRequest {
    let now = Utc::now().to_rfc3339();
    ServiceNowRequest {
        id: Uuid::new_v4().to_string(),
        request_type,
        external_ref: String::new(),
        status: ServiceNowSubmissionStatus::Draft,
        ci_name: ci_name.to_string(),
        payload_summary: payload_summary.to_string(),
        created_at: now,
        submitted_at: None,
        metadata,
    }
}

pub fn prepare_incident(
    ci_name: &str,
    description: &str,
    urgency: &str,
    assignment_group: &str,
) -> Result<Value, String> {
    seed_requests_if_empty();
    if ci_name.is_empty() {
        return Err("ci_name is required".into());
    }
    if description.is_empty() {
        return Err("description is required".into());
    }
    let mut meta = HashMap::new();
    meta.insert("urgency".into(), urgency.to_string());
    meta.insert("assignment_group".into(), assignment_group.to_string());
    let req = new_request(ServiceNowRequestType::Incident, ci_name, description, meta);
    let result = json!({
        "id": req.id,
        "request_type": req.request_type.to_string(),
        "ci_name": req.ci_name,
        "status": req.status.to_string(),
        "payload_summary": req.payload_summary,
        "created_at": req.created_at,
        "source": "static-dry-run",
    });
    sn_store().lock().unwrap().push(req);
    Ok(result)
}

pub fn prepare_change(
    ci_name: &str,
    change_type: &str,
    description: &str,
    planned_start: &str,
    planned_end: &str,
    risk: &str,
) -> Result<Value, String> {
    seed_requests_if_empty();
    if ci_name.is_empty() {
        return Err("ci_name is required".into());
    }
    if description.is_empty() {
        return Err("description is required".into());
    }
    if planned_start.is_empty() || planned_end.is_empty() {
        return Err("planned_start and planned_end are required".into());
    }
    let mut meta = HashMap::new();
    meta.insert("change_type".into(), change_type.to_string());
    meta.insert("risk".into(), risk.to_string());
    meta.insert("planned_start".into(), planned_start.to_string());
    meta.insert("planned_end".into(), planned_end.to_string());
    let req = new_request(ServiceNowRequestType::Change, ci_name, description, meta);
    let result = json!({
        "id": req.id,
        "request_type": req.request_type.to_string(),
        "ci_name": req.ci_name,
        "status": req.status.to_string(),
        "payload_summary": req.payload_summary,
        "created_at": req.created_at,
        "source": "static-dry-run",
    });
    sn_store().lock().unwrap().push(req);
    Ok(result)
}

pub fn prepare_request(
    ci_name: &str,
    request_type: &str,
    description: &str,
) -> Result<Value, String> {
    seed_requests_if_empty();
    if ci_name.is_empty() {
        return Err("ci_name is required".into());
    }
    if description.is_empty() {
        return Err("description is required".into());
    }
    let mut meta = HashMap::new();
    meta.insert("request_type".into(), request_type.to_string());
    let req = new_request(ServiceNowRequestType::Request, ci_name, description, meta);
    let result = json!({
        "id": req.id,
        "request_type": req.request_type.to_string(),
        "ci_name": req.ci_name,
        "status": req.status.to_string(),
        "payload_summary": req.payload_summary,
        "created_at": req.created_at,
        "source": "static-dry-run",
    });
    sn_store().lock().unwrap().push(req);
    Ok(result)
}

pub fn validate_request(request_id: &str) -> Result<Value, String> {
    seed_requests_if_empty();
    let mut store = sn_store().lock().unwrap();
    let req = store
        .iter_mut()
        .find(|r| r.id == request_id)
        .ok_or_else(|| format!("ServiceNow request not found: {}", request_id))?;

    if req.status != ServiceNowSubmissionStatus::Draft {
        return Err(format!(
            "Request {} is not in Draft status (current: {})",
            request_id,
            req.status.to_string()
        ));
    }

    if req.ci_name.is_empty() {
        return Err("ci_name is missing".into());
    }
    if req.payload_summary.is_empty() {
        return Err("payload_summary is missing".into());
    }

    let errors: Vec<String> = vec![];
    Ok(json!({
        "id": req.id,
        "status": "validated",
        "passed": errors.is_empty(),
        "errors": errors,
        "warnings": vec!["DRY-RUN: static validation only — no live ServiceNow connectivity check"],
        "source": "static-dry-run",
    }))
}

pub fn approve_request(request_id: &str) -> Result<Value, String> {
    seed_requests_if_empty();
    let mut store = sn_store().lock().unwrap();
    let req = store
        .iter_mut()
        .find(|r| r.id == request_id)
        .ok_or_else(|| format!("ServiceNow request not found: {}", request_id))?;

    if req.status == ServiceNowSubmissionStatus::Submitted {
        return Err("Cannot approve — already submitted".into());
    }
    if req.status == ServiceNowSubmissionStatus::Failed {
        return Err("Cannot approve — request has failed".into());
    }

    let now = Utc::now().to_rfc3339();
    Ok(json!({
        "id": req.id,
        "status": "approved",
        "approved_at": now,
        "source": "static-dry-run",
        "note": "DRY-RUN: approval recorded locally — live ServiceNow API is pending approval",
    }))
}

pub fn queue_for_submission(request_id: &str) -> Result<Value, String> {
    seed_requests_if_empty();
    let mut store = sn_store().lock().unwrap();
    let req = store
        .iter_mut()
        .find(|r| r.id == request_id)
        .ok_or_else(|| format!("ServiceNow request not found: {}", request_id))?;

    if req.status == ServiceNowSubmissionStatus::Submitted {
        return Err("Already submitted".into());
    }
    if req.status == ServiceNowSubmissionStatus::Failed {
        return Err("Cannot queue — request has failed".into());
    }
    if req.status != ServiceNowSubmissionStatus::Ready && req.status != ServiceNowSubmissionStatus::Pending {
        req.status = ServiceNowSubmissionStatus::Ready;
    }

    req.status = ServiceNowSubmissionStatus::Pending;
    let now = Utc::now().to_rfc3339();
    Ok(json!({
        "id": req.id,
        "status": req.status.to_string(),
        "queued_at": now,
        "source": "static-dry-run",
        "note": "DRY-RUN: submission queued locally — live ServiceNow submission is disabled pending API approval",
    }))
}

pub fn get_submission_status(request_id: &str) -> Result<Value, String> {
    seed_requests_if_empty();
    let store = sn_store().lock().unwrap();
    let req = store
        .iter()
        .find(|r| r.id == request_id)
        .ok_or_else(|| format!("ServiceNow request not found: {}", request_id))?;

    Ok(json!({
        "id": req.id,
        "request_type": req.request_type.to_string(),
        "ci_name": req.ci_name,
        "status": req.status.to_string(),
        "external_ref": req.external_ref,
        "payload_summary": req.payload_summary,
        "created_at": req.created_at,
        "submitted_at": req.submitted_at,
        "source": "static-dry-run",
    }))
}

pub fn get_pending_submissions() -> Value {
    seed_requests_if_empty();
    let store = sn_store().lock().unwrap();
    let pending: Vec<&ServiceNowRequest> = store
        .iter()
        .filter(|r| {
            r.status == ServiceNowSubmissionStatus::Pending
                || r.status == ServiceNowSubmissionStatus::Ready
        })
        .collect();

    let items: Vec<Value> = pending
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "request_type": r.request_type.to_string(),
                "ci_name": r.ci_name,
                "status": r.status.to_string(),
                "payload_summary": r.payload_summary,
                "created_at": r.created_at,
            })
        })
        .collect();

    json!({
        "source": "static-dry-run",
        "count": items.len(),
        "items": items,
    })
}

pub fn cancel_request(request_id: &str) -> Result<Value, String> {
    seed_requests_if_empty();
    let mut store = sn_store().lock().unwrap();
    let req = store
        .iter_mut()
        .find(|r| r.id == request_id)
        .ok_or_else(|| format!("ServiceNow request not found: {}", request_id))?;

    if req.status == ServiceNowSubmissionStatus::Submitted {
        return Err("Cannot cancel — request has already been submitted".into());
    }

    req.status = ServiceNowSubmissionStatus::Failed;

    Ok(json!({
        "id": req.id,
        "status": "cancelled",
        "cancelled_at": Utc::now().to_rfc3339(),
        "source": "static-dry-run",
    }))
}

pub fn get_submission_history(ci_name: &str) -> Value {
    seed_requests_if_empty();
    let store = sn_store().lock().unwrap();
    let items: Vec<&ServiceNowRequest> = store
        .iter()
        .filter(|r| r.ci_name == ci_name)
        .collect();

    let entries: Vec<Value> = items
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "request_type": r.request_type.to_string(),
                "external_ref": r.external_ref,
                "status": r.status.to_string(),
                "payload_summary": r.payload_summary,
                "created_at": r.created_at,
                "submitted_at": r.submitted_at,
            })
        })
        .collect();

    json!({
        "source": "static-dry-run",
        "ci_name": ci_name,
        "count": entries.len(),
        "items": entries,
    })
}

pub fn get_snow_contract() -> Value {
    seed_requests_if_empty();
    json!({
        "source": "static-seed",
        "queueMode": "aggregate-safe",
        "providerCallsEnabled": false,
        "liveExecutionAllowed": false,
        "rawProviderPayloadsAllowed": false,
        "liveApiDisabled": true,
        "note": "Live ServiceNow API is pending approval. All submissions are mock/dry-run.",
        "requestTypes": [
            "incident",
            "change",
            "request",
            "knowledge"
        ],
        "submissionStates": [
            "Draft",
            "Ready",
            "Pending",
            "Submitted",
            "Failed"
        ],
        "requiredInputs": [
            "ci_name",
            "description",
            "urgency",
            "assignment_group",
            "change_type",
            "planned_start",
            "planned_end",
            "risk",
            "request_type"
        ],
        "requiredGuards": [
            "ci-name-known",
            "description-provided",
            "urgency-assigned",
            "assignment-group-known",
            "change-type-known",
            "maintenance-window-provided",
            "risk-assessed",
            "evidence-redacted"
        ],
        "blockedReasons": [
            "live-api-disabled",
            "provider-calls-disabled",
            "request-callbacks-disabled",
            "change-callbacks-disabled",
            "cmdb-updates-disabled",
            "import-set-writes-disabled",
            "status-sync-disabled",
            "table-api-calls-disabled",
            "credential-values-disabled",
            "instance-identifiers-disabled",
            "table-identifiers-disabled",
            "sys-identifiers-disabled",
            "raw-request-payloads-disabled",
            "raw-response-payloads-disabled",
            "raw-ticket-data-disabled",
            "raw-recipient-data-disabled",
            "raw-provider-payloads-disabled",
            "approval-missing",
            "secret-reference-missing",
            "table-mapping-missing",
            "payload-redaction-missing",
            "rollback-plan-missing",
            "evidence-not-redacted"
        ],
        "rules": [
            {
                "id": "no-live-api-execution",
                "decision": "block",
                "requirement": "ServiceNow API integration runs in mock/dry-run mode only. Live API callbacks, table writes, import sets, and status sync are disabled pending approval.",
                "evidence": "Submission summary"
            },
            {
                "id": "no-raw-provider-payloads",
                "decision": "block",
                "requirement": "ServiceNow integration summaries must not expose raw request payloads, response payloads, ticket data, recipient data, or provider payloads.",
                "evidence": "Payload summary"
            },
            {
                "id": "ci-name-and-description-required",
                "decision": "block",
                "requirement": "Every ServiceNow request must include a known CI name and description before submission.",
                "evidence": "CI identity summary"
            },
            {
                "id": "approval-gate-required",
                "decision": "block",
                "requirement": "Requests must pass local approval before being queued for submission.",
                "evidence": "Approval decision"
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_store() {
        let mut guard = sn_store().lock().unwrap();
        *guard = seed_requests();
    }

    #[test]
    fn test_seed_requests_populates_store() {
        fresh_store();
        let store = sn_store().lock().unwrap();
        assert_eq!(store.len(), 4);
        assert!(store.iter().any(|r| r.id == "sn-req-001"));
        assert!(store.iter().any(|r| r.id == "sn-req-002"));
        assert!(store.iter().any(|r| r.id == "sn-req-003"));
        assert!(store.iter().any(|r| r.id == "sn-req-004"));
    }

    #[test]
    fn test_prepare_incident_creates_draft() {
        fresh_store();
        let result = prepare_incident(
            "srv-love-app01.corp.local",
            "Disk space critical — 95% used on C:",
            "1",
            "Wintel-Operations",
        )
        .unwrap();
        assert_eq!(result["request_type"], "incident");
        assert_eq!(result["ci_name"], "srv-love-app01.corp.local");
        assert_eq!(result["status"], "Draft");
        assert_eq!(result["source"], "static-dry-run");
        assert!(result["id"].as_str().is_some());

        let store = sn_store().lock().unwrap();
        assert_eq!(store.len(), 5);
    }

    #[test]
    fn test_prepare_change_requires_planned_window() {
        fresh_store();
        assert!(prepare_change(
            "srv-bur1-db01.corp.local",
            "Normal",
            "",
            "2026-06-15T02:00:00Z",
            "2026-06-15T04:00:00Z",
            "Low"
        )
        .is_err());

        assert!(prepare_change(
            "srv-bur1-db01.corp.local",
            "Normal",
            "Memory upgrade",
            "",
            "",
            "Low"
        )
        .is_err());
    }

    #[test]
    fn test_validate_request_checks_required_fields() {
        fresh_store();
        let result = validate_request("sn-req-003").unwrap();
        assert_eq!(result["status"], "validated");
        assert!(result["passed"].as_bool().unwrap());
        assert!(result["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("DRY-RUN")));
    }

    #[test]
    fn test_approve_request_gates_pending() {
        fresh_store();
        let result = approve_request("sn-req-004").unwrap();
        assert_eq!(result["status"], "approved");
        assert_eq!(result["source"], "static-dry-run");
        assert!(result["note"]
            .as_str()
            .unwrap()
            .contains("pending approval"));
    }

    #[test]
    fn test_cannot_approve_already_submitted() {
        fresh_store();
        assert!(approve_request("sn-req-001").is_err());
    }

    #[test]
    fn test_queue_for_submission_marks_pending() {
        fresh_store();
        let result = queue_for_submission("sn-req-002").unwrap();
        assert_eq!(result["status"], "Pending");
        assert_eq!(result["source"], "static-dry-run");
        assert!(result["note"].as_str().unwrap().contains("disabled"));

        let store = sn_store().lock().unwrap();
        let req = store.iter().find(|r| r.id == "sn-req-002").unwrap();
        assert_eq!(req.status, ServiceNowSubmissionStatus::Pending);
    }

    #[test]
    fn test_cancel_request_marks_failed() {
        fresh_store();
        let result = cancel_request("sn-req-003").unwrap();
        assert_eq!(result["status"], "cancelled");
        assert_eq!(result["source"], "static-dry-run");

        let store = sn_store().lock().unwrap();
        let req = store.iter().find(|r| r.id == "sn-req-003").unwrap();
        assert_eq!(req.status, ServiceNowSubmissionStatus::Failed);
    }

    #[test]
    fn test_cannot_cancel_already_submitted() {
        fresh_store();
        assert!(cancel_request("sn-req-001").is_err());
    }

    #[test]
    fn test_get_pending_submissions_filters_correctly() {
        fresh_store();
        let pending = get_pending_submissions();
        assert_eq!(pending["source"], "static-dry-run");
        assert!(pending["count"].as_u64().unwrap() >= 1);
        let items = pending["items"].as_array().unwrap();
        let has_sn_002 = items.iter().any(|i| i["id"] == "sn-req-002");
        assert!(has_sn_002);
    }

    #[test]
    fn test_get_submission_history_by_ci() {
        fresh_store();
        let history = get_submission_history("srv-love-web01.corp.local");
        assert_eq!(history["ci_name"], "srv-love-web01.corp.local");
        assert_eq!(history["count"].as_u64().unwrap(), 1);
        let items = history["items"].as_array().unwrap();
        assert_eq!(items[0]["id"], "sn-req-001");
    }

    #[test]
    fn test_get_submission_history_empty_for_unknown_ci() {
        fresh_store();
        let history = get_submission_history("nonexistent.ci.local");
        assert_eq!(history["count"].as_u64().unwrap(), 0);
        assert!(history["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_request_not_found_errors() {
        fresh_store();
        assert!(validate_request("sn-req-999").is_err());
        assert!(approve_request("sn-req-999").is_err());
        assert!(queue_for_submission("sn-req-999").is_err());
        assert!(cancel_request("sn-req-999").is_err());
        assert!(get_submission_status("sn-req-999").is_err());
    }

    #[test]
    fn test_get_submission_status_returns_full_detail() {
        fresh_store();
        let status = get_submission_status("sn-req-001").unwrap();
        assert_eq!(status["id"], "sn-req-001");
        assert_eq!(status["request_type"], "incident");
        assert_eq!(status["status"], "Submitted");
        assert_eq!(status["external_ref"], "INC-2026-0042");
        assert_eq!(status["source"], "static-dry-run");
    }

    #[test]
    fn test_service_now_request_type_display() {
        assert_eq!(ServiceNowRequestType::Incident.to_string(), "incident");
        assert_eq!(ServiceNowRequestType::Change.to_string(), "change");
        assert_eq!(ServiceNowRequestType::Request.to_string(), "request");
        assert_eq!(ServiceNowRequestType::Knowledge.to_string(), "knowledge");
    }

    #[test]
    fn test_service_now_submission_status_display() {
        assert_eq!(ServiceNowSubmissionStatus::Draft.to_string(), "Draft");
        assert_eq!(ServiceNowSubmissionStatus::Ready.to_string(), "Ready");
        assert_eq!(ServiceNowSubmissionStatus::Pending.to_string(), "Pending");
        assert_eq!(
            ServiceNowSubmissionStatus::Submitted.to_string(),
            "Submitted"
        );
        assert_eq!(ServiceNowSubmissionStatus::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_get_snow_contract_returns_valid_structure() {
        fresh_store();
        let contract = get_snow_contract();
        assert_eq!(contract["source"], "static-seed");
        assert_eq!(contract["queueMode"], "aggregate-safe");
        assert_eq!(contract["providerCallsEnabled"], false);
        assert_eq!(contract["liveApiDisabled"], true);
        assert!(contract["rules"].as_array().unwrap().len() >= 4);
        assert!(contract["blockedReasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap() == "live-api-disabled"));
    }
}
