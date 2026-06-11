use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Runbook {
    pub id: String,
    pub name: String,
    pub category: String,
    pub steps: Vec<RunbookStep>,
    pub approval_required: bool,
    pub rollback_plan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookStep {
    pub order: u32,
    pub name: String,
    pub description: String,
    pub expected_outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionStatus {
    Draft,
    Approved,
    Running,
    Completed,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookExecution {
    pub id: String,
    pub runbook_id: String,
    pub status: ExecutionStatus,
    pub site: String,
    pub started_by: String,
    pub steps_results: Vec<StepResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_order: u32,
    pub status: StepStatus,
    pub output: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

type ExecutionStore = Vec<RunbookExecution>;

static EXECUTION_STORE: OnceLock<Mutex<ExecutionStore>> = OnceLock::new();

fn execution_store() -> &'static Mutex<ExecutionStore> {
    EXECUTION_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn seed_data() -> ExecutionStore {
    vec![
        RunbookExecution {
            id: "rbx-love-001".into(),
            runbook_id: "patch-windows-server".into(),
            status: ExecutionStatus::Draft,
            site: "LOVE".into(),
            started_by: "alice.engineer".into(),
            steps_results: vec![pending_step(1), pending_step(2), pending_step(3)],
        },
        RunbookExecution {
            id: "rbx-bur1-001".into(),
            runbook_id: "restart-service".into(),
            status: ExecutionStatus::Approved,
            site: "BUR1".into(),
            started_by: "bob.engineer".into(),
            steps_results: vec![pending_step(1), pending_step(2), pending_step(3)],
        },
        RunbookExecution {
            id: "rbx-madr-001".into(),
            runbook_id: "certificate-renewal".into(),
            status: ExecutionStatus::Completed,
            site: "MADR".into(),
            started_by: "carla.engineer".into(),
            steps_results: vec![completed_step(1), completed_step(2), completed_step(3)],
        },
    ]
}

fn pending_step(step_order: u32) -> StepResult {
    StepResult {
        step_order,
        status: StepStatus::Pending,
        output: "Pending dry-run execution".into(),
        started_at: None,
        completed_at: None,
    }
}

fn completed_step(step_order: u32) -> StepResult {
    let timestamp = now_iso();
    StepResult {
        step_order,
        status: StepStatus::Completed,
        output: format!("Step {} completed in dry-run mode", step_order),
        started_at: Some(timestamp.clone()),
        completed_at: Some(timestamp),
    }
}

fn runbook_catalog() -> Vec<Runbook> {
    vec![
        Runbook {
            id: "patch-windows-server".into(),
            name: "Patch Windows Server".into(),
            category: "maintenance".into(),
            steps: vec![
                RunbookStep {
                    order: 1,
                    name: "Pre-check server health".into(),
                    description: "Validate disk, CPU, memory, and pending reboot state.".into(),
                    expected_outcome: "Server is healthy enough to patch.".into(),
                },
                RunbookStep {
                    order: 2,
                    name: "Apply approved updates".into(),
                    description: "Install approved Windows updates in dry-run mode.".into(),
                    expected_outcome: "Updates are reported as installed.".into(),
                },
                RunbookStep {
                    order: 3,
                    name: "Validate post-patch services".into(),
                    description: "Confirm required services and monitoring checks are green."
                        .into(),
                    expected_outcome: "Server returns to normal service.".into(),
                },
            ],
            approval_required: true,
            rollback_plan: "Restore from pre-patch snapshot and mark server for manual review."
                .into(),
        },
        Runbook {
            id: "restart-service".into(),
            name: "Restart Service".into(),
            category: "operations".into(),
            steps: vec![
                RunbookStep {
                    order: 1,
                    name: "Check service dependencies".into(),
                    description: "Inspect dependent services and active sessions.".into(),
                    expected_outcome: "No blocking dependencies are present.".into(),
                },
                RunbookStep {
                    order: 2,
                    name: "Restart target service".into(),
                    description: "Simulate a controlled restart of the selected service.".into(),
                    expected_outcome: "Service reaches running state.".into(),
                },
                RunbookStep {
                    order: 3,
                    name: "Verify service endpoint".into(),
                    description: "Run synthetic health checks against the service endpoint.".into(),
                    expected_outcome: "Endpoint health checks pass.".into(),
                },
            ],
            approval_required: false,
            rollback_plan: "Start the previous service instance and escalate to on-call.".into(),
        },
        Runbook {
            id: "certificate-renewal".into(),
            name: "Certificate Renewal".into(),
            category: "security".into(),
            steps: vec![
                RunbookStep {
                    order: 1,
                    name: "Validate certificate request".into(),
                    description: "Check SANs, expiration date, and ownership metadata.".into(),
                    expected_outcome: "Certificate request is approved for renewal.".into(),
                },
                RunbookStep {
                    order: 2,
                    name: "Stage renewed certificate".into(),
                    description: "Simulate staging the renewed certificate on target systems."
                        .into(),
                    expected_outcome: "Certificate is staged without replacing live material."
                        .into(),
                },
                RunbookStep {
                    order: 3,
                    name: "Validate TLS chain".into(),
                    description: "Verify chain, issuer, key usage, and expiry.".into(),
                    expected_outcome: "TLS validation succeeds.".into(),
                },
            ],
            approval_required: true,
            rollback_plan: "Keep the current certificate active and open a security review.".into(),
        },
        Runbook {
            id: "dns-record-update".into(),
            name: "DNS Record Update".into(),
            category: "network".into(),
            steps: vec![
                RunbookStep {
                    order: 1,
                    name: "Validate zone ownership".into(),
                    description: "Confirm the requested record belongs to a managed zone.".into(),
                    expected_outcome: "Zone and record ownership are verified.".into(),
                },
                RunbookStep {
                    order: 2,
                    name: "Simulate record change".into(),
                    description: "Apply the DNS change to a dry-run plan.".into(),
                    expected_outcome: "Record diff is generated.".into(),
                },
                RunbookStep {
                    order: 3,
                    name: "Check propagation plan".into(),
                    description: "Validate TTL and propagation window.".into(),
                    expected_outcome: "Propagation plan is safe.".into(),
                },
            ],
            approval_required: true,
            rollback_plan: "Reapply the previous DNS record value from the dry-run diff.".into(),
        },
        Runbook {
            id: "firewall-rule-change".into(),
            name: "Firewall Rule Change".into(),
            category: "network-security".into(),
            steps: vec![
                RunbookStep {
                    order: 1,
                    name: "Validate rule request".into(),
                    description:
                        "Check source, destination, port, protocol, and business justification."
                            .into(),
                    expected_outcome: "Rule request passes policy validation.".into(),
                },
                RunbookStep {
                    order: 2,
                    name: "Run policy simulation".into(),
                    description: "Simulate the rule against existing policy and deny lists.".into(),
                    expected_outcome: "No unintended exposure is detected.".into(),
                },
                RunbookStep {
                    order: 3,
                    name: "Prepare change summary".into(),
                    description: "Generate a dry-run change summary for review.".into(),
                    expected_outcome: "Summary is ready for approval.".into(),
                },
            ],
            approval_required: true,
            rollback_plan:
                "Disable the proposed firewall rule and restore the previous policy revision."
                    .into(),
        },
    ]
}

fn valid_site(site: &str) -> bool {
    matches!(site, "LOVE" | "BUR1" | "MADR")
}

fn find_runbook(runbook_id: &str) -> Option<Runbook> {
    runbook_catalog().into_iter().find(|r| r.id == runbook_id)
}

fn make_execution_id(site: &str) -> String {
    format!(
        "rbx-{}-{}",
        site.to_lowercase(),
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    )
}

fn is_terminal(status: &ExecutionStatus) -> bool {
    matches!(
        status,
        ExecutionStatus::Completed | ExecutionStatus::Failed | ExecutionStatus::RolledBack
    )
}

pub fn list_runbooks() -> Result<Value, String> {
    Ok(json!({
        "source": "dry-run",
        "runbooks": runbook_catalog()
    }))
}

pub fn start_runbook(runbook_id: &str, site: &str, started_by: &str) -> Result<Value, String> {
    if !valid_site(site) {
        return Err(format!(
            "Unsupported site '{}'. Must be LOVE, BUR1, or MADR",
            site
        ));
    }
    if started_by.trim().is_empty() {
        return Err("started_by cannot be empty".into());
    }

    let runbook =
        find_runbook(runbook_id).ok_or_else(|| format!("Runbook '{}' not found", runbook_id))?;
    let execution = RunbookExecution {
        id: make_execution_id(site),
        runbook_id: runbook.id.clone(),
        status: ExecutionStatus::Draft,
        site: site.into(),
        started_by: started_by.into(),
        steps_results: runbook
            .steps
            .iter()
            .map(|step| pending_step(step.order))
            .collect(),
    };

    execution_store().lock().unwrap().push(execution.clone());

    Ok(json!({
        "source": "dry-run",
        "execution": execution
    }))
}

pub fn get_execution(id: &str) -> Result<Value, String> {
    let store = execution_store().lock().unwrap();
    let execution = store
        .iter()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("Execution '{}' not found", id))?;

    Ok(json!({
        "source": "dry-run",
        "execution": execution
    }))
}

pub fn execute_step(execution_id: &str, step_order: u32) -> Result<Value, String> {
    let mut store = execution_store().lock().unwrap();
    let execution = store
        .iter_mut()
        .find(|e| e.id == execution_id)
        .ok_or_else(|| format!("Execution '{}' not found", execution_id))?;

    if is_terminal(&execution.status) {
        return Err(format!("Execution '{}' is terminal", execution_id));
    }

    let step = execution
        .steps_results
        .iter_mut()
        .find(|s| s.step_order == step_order)
        .ok_or_else(|| format!("Step {} not found", step_order))?;
    let timestamp = now_iso();

    step.status = StepStatus::Completed;
    step.output = format!("Step {} completed successfully in dry-run mode", step_order);
    step.started_at = Some(timestamp.clone());
    step.completed_at = Some(timestamp);
    execution.status = ExecutionStatus::Running;

    Ok(json!({
        "source": "dry-run",
        "execution_id": execution.id,
        "status": execution.status,
        "step_result": step
    }))
}

pub fn approve_execution(id: &str, approver: &str) -> Result<Value, String> {
    if approver.trim().is_empty() {
        return Err("approver cannot be empty".into());
    }

    let mut store = execution_store().lock().unwrap();
    let execution = store
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("Execution '{}' not found", id))?;

    execution.status = ExecutionStatus::Approved;

    Ok(json!({
        "source": "dry-run",
        "execution": execution,
        "approved_by": approver,
        "approved_at": now_iso()
    }))
}

pub fn complete_execution(id: &str) -> Result<Value, String> {
    let mut store = execution_store().lock().unwrap();
    let execution = store
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("Execution '{}' not found", id))?;

    execution.status = ExecutionStatus::Completed;

    Ok(json!({
        "source": "dry-run",
        "execution": execution,
        "completed_at": now_iso()
    }))
}

pub fn fail_execution(id: &str, reason: &str) -> Result<Value, String> {
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }

    let mut store = execution_store().lock().unwrap();
    let execution = store
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("Execution '{}' not found", id))?;
    let timestamp = now_iso();

    execution.status = ExecutionStatus::Failed;
    execution.steps_results.push(StepResult {
        step_order: 0,
        status: StepStatus::Failed,
        output: reason.into(),
        started_at: Some(timestamp.clone()),
        completed_at: Some(timestamp),
    });

    Ok(json!({
        "source": "dry-run",
        "execution": execution,
        "reason": reason,
        "failed_at": now_iso()
    }))
}

pub fn rollback_execution(id: &str) -> Result<Value, String> {
    let mut store = execution_store().lock().unwrap();
    let execution = store
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("Execution '{}' not found", id))?;

    execution.status = ExecutionStatus::RolledBack;

    Ok(json!({
        "source": "dry-run",
        "execution": execution,
        "rolled_back_at": now_iso()
    }))
}

pub fn list_executions(site: Option<&str>) -> Result<Value, String> {
    let store = execution_store().lock().unwrap();
    let executions: Vec<RunbookExecution> = store
        .iter()
        .filter(|e| site.is_none_or(|s| e.site == s))
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "executions": executions
    }))
}

pub fn get_active_executions() -> Result<Value, String> {
    let store = execution_store().lock().unwrap();
    let executions: Vec<RunbookExecution> = store
        .iter()
        .filter(|e| !is_terminal(&e.status))
        .cloned()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "executions": executions
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_runbooks_returns_at_least_five() {
        let result = list_runbooks().unwrap();
        assert!(result["runbooks"].as_array().unwrap().len() >= 5);
        assert_eq!(result["source"], "dry-run");
    }

    #[test]
    fn test_start_runbook_creates_execution_in_draft_status() {
        let result = start_runbook("restart-service", "LOVE", "test.engineer").unwrap();

        assert_eq!(result["execution"]["runbook_id"], "restart-service");
        assert_eq!(result["execution"]["site"], "LOVE");
        assert_eq!(result["execution"]["status"], "draft");
    }

    #[test]
    fn test_approve_and_complete_flow() {
        let result = start_runbook("dns-record-update", "BUR1", "test.engineer").unwrap();
        let id = result["execution"]["id"].as_str().unwrap();

        let approved = approve_execution(id, "change.manager").unwrap();
        assert_eq!(approved["execution"]["status"], "approved");

        let completed = complete_execution(id).unwrap();
        assert_eq!(completed["execution"]["status"], "completed");
    }

    #[test]
    fn test_execute_step_updates_result() {
        let result = start_runbook("certificate-renewal", "MADR", "test.engineer").unwrap();
        let id = result["execution"]["id"].as_str().unwrap();

        let executed = execute_step(id, 1).unwrap();

        assert_eq!(executed["status"], "running");
        assert_eq!(executed["step_result"]["step_order"], 1);
        assert_eq!(executed["step_result"]["status"], "completed");
        assert!(executed["step_result"]["completed_at"].as_str().is_some());
    }

    #[test]
    fn test_fail_execution_records_reason() {
        let result = start_runbook("firewall-rule-change", "LOVE", "test.engineer").unwrap();
        let id = result["execution"]["id"].as_str().unwrap();

        let failed = fail_execution(id, "Policy simulation detected unintended exposure").unwrap();

        assert_eq!(failed["execution"]["status"], "failed");
        assert_eq!(
            failed["reason"],
            "Policy simulation detected unintended exposure"
        );
        assert!(
            failed["execution"]["steps_results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["output"] == "Policy simulation detected unintended exposure")
        );
    }

    #[test]
    fn test_list_executions_filters_by_site() {
        let _ = start_runbook("restart-service", "MADR", "test.engineer").unwrap();

        let result = list_executions(Some("MADR")).unwrap();
        let executions = result["executions"].as_array().unwrap();

        assert!(!executions.is_empty());
        assert!(executions.iter().all(|e| e["site"] == "MADR"));
    }
}
