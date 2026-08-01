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
    /// Exact durable site-registry authority epoch captured when this
    /// execution is persisted. Pure dry-run projections remain unbound until
    /// the durable repository admits them against the canonical site row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_authority_epoch: Option<i64>,
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
            id: "rbx-defra-001".into(),
            runbook_id: "patch-windows-server".into(),
            status: ExecutionStatus::Draft,
            site: "DEFRA".into(),
            site_authority_epoch: None,
            started_by: "alice.engineer".into(),
            steps_results: vec![pending_step(1), pending_step(2), pending_step(3)],
        },
        RunbookExecution {
            id: "rbx-gblon-001".into(),
            runbook_id: "restart-service".into(),
            status: ExecutionStatus::Approved,
            site: "GBLON".into(),
            site_authority_epoch: None,
            started_by: "bob.engineer".into(),
            steps_results: vec![pending_step(1), pending_step(2), pending_step(3)],
        },
        RunbookExecution {
            id: "rbx-deber-001".into(),
            runbook_id: "certificate-renewal".into(),
            status: ExecutionStatus::Completed,
            site: "DEBER".into(),
            site_authority_epoch: None,
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

/// Validate the complete execution snapshot before any transition or durable
/// write. Required catalog steps must appear exactly once, in their declared
/// order; a non-pending step requires every predecessor to be completed; status
/// and timestamp shapes must agree; and Completed means every required step is
/// actually complete.
pub fn validate_execution_invariants(exec: &RunbookExecution) -> Result<(), String> {
    if exec.site_authority_epoch.is_some_and(|epoch| epoch <= 0) {
        return Err(format!(
            "Execution '{}' carries an invalid site authority epoch",
            exec.id
        ));
    }

    let runbook = find_runbook(&exec.runbook_id)
        .ok_or_else(|| format!("Runbook '{}' not found", exec.runbook_id))?;
    let expected_orders: Vec<u32> = runbook.steps.iter().map(|step| step.order).collect();
    let mut persisted_orders: Vec<u32> = exec
        .steps_results
        .iter()
        .filter(|step| step.step_order > 0)
        .map(|step| step.step_order)
        .collect();
    persisted_orders.sort_unstable();
    if persisted_orders != expected_orders {
        return Err(format!(
            "Execution '{}' must contain each required runbook step exactly once in order",
            exec.id
        ));
    }

    let failure_markers: Vec<&StepResult> = exec
        .steps_results
        .iter()
        .filter(|step| step.step_order == 0)
        .collect();
    if exec.status == ExecutionStatus::Failed {
        if failure_markers.len() != 1 || failure_markers[0].status != StepStatus::Failed {
            return Err(format!(
                "Execution '{}' must carry exactly one failure reason marker",
                exec.id
            ));
        }
    } else if !failure_markers.is_empty() {
        return Err(format!(
            "Execution '{}' carries a failure marker outside Failed status",
            exec.id
        ));
    }

    for step in &exec.steps_results {
        match step.status {
            StepStatus::Pending => {
                if step.started_at.is_some() || step.completed_at.is_some() {
                    return Err(format!(
                        "Pending step {} cannot carry execution timestamps",
                        step.step_order
                    ));
                }
            }
            StepStatus::Running => {
                if step.started_at.is_none() || step.completed_at.is_some() {
                    return Err(format!(
                        "Running step {} requires only a start timestamp",
                        step.step_order
                    ));
                }
            }
            StepStatus::Completed | StepStatus::Failed => {
                if step.started_at.is_none() || step.completed_at.is_none() {
                    return Err(format!(
                        "Terminal step {} requires start and completion timestamps",
                        step.step_order
                    ));
                }
            }
        }

        if step.step_order > 0 && step.status != StepStatus::Pending {
            let predecessors_complete = exec.steps_results.iter().all(|candidate| {
                candidate.step_order == 0
                    || candidate.step_order >= step.step_order
                    || candidate.status == StepStatus::Completed
            });
            if !predecessors_complete {
                return Err(format!(
                    "Step {} cannot advance before every predecessor is completed",
                    step.step_order
                ));
            }
        }
    }

    let required_steps = exec.steps_results.iter().filter(|step| step.step_order > 0);
    match exec.status {
        ExecutionStatus::Draft | ExecutionStatus::Approved => {
            if !required_steps
                .clone()
                .all(|step| step.status == StepStatus::Pending)
            {
                return Err(format!(
                    "Execution '{}' cannot have advanced steps before Running",
                    exec.id
                ));
            }
        }
        ExecutionStatus::Running => {
            if !required_steps
                .clone()
                .any(|step| step.status != StepStatus::Pending)
                || required_steps
                    .clone()
                    .any(|step| step.status == StepStatus::Failed)
            {
                return Err(format!(
                    "Running execution '{}' requires an advanced, non-failed step",
                    exec.id
                ));
            }
        }
        ExecutionStatus::Completed => {
            if !required_steps
                .clone()
                .all(|step| step.status == StepStatus::Completed)
            {
                return Err(format!(
                    "Execution '{}' cannot complete while a required step is unfinished",
                    exec.id
                ));
            }
        }
        ExecutionStatus::Failed | ExecutionStatus::RolledBack => {}
    }

    Ok(())
}

// ─── Pure constructors and transition functions ────────────────────────────────

/// Pure constructor: validates and canonicalizes inputs and builds a new
/// `RunbookExecution` without touching shared state. Stateful callers must
/// separately admit the canonical site against their current authority source;
/// the in-memory API uses the engine registry and the persisted API uses the
/// durable registry in its write transaction. Approval-required runbooks start
/// in `Draft`; explicitly no-approval runbooks start ready in `Approved`.
pub fn build_execution(
    runbook_id: &str,
    site: &str,
    started_by: &str,
) -> Result<RunbookExecution, String> {
    let site = crate::site_registry::normalize_site_code_for_lookup(site)?;
    if started_by.trim().is_empty() {
        return Err("started_by cannot be empty".into());
    }

    let runbook =
        find_runbook(runbook_id).ok_or_else(|| format!("Runbook '{}' not found", runbook_id))?;

    let initial_status = if runbook.approval_required {
        ExecutionStatus::Draft
    } else {
        ExecutionStatus::Approved
    };

    Ok(RunbookExecution {
        id: make_execution_id(&site),
        runbook_id: runbook.id.clone(),
        status: initial_status,
        site,
        site_authority_epoch: None,
        started_by: started_by.into(),
        steps_results: runbook
            .steps
            .iter()
            .map(|step| pending_step(step.order))
            .collect(),
    })
}

/// Attach the server-observed durable site authority to a newly constructed
/// execution. An execution can be bound once (or idempotently rebound to the
/// same value); callers cannot retarget it to a different site generation.
pub fn bind_site_authority_epoch(
    exec: &mut RunbookExecution,
    authority_epoch: i64,
) -> Result<(), String> {
    if authority_epoch <= 0 {
        return Err("site authority epoch must be positive".into());
    }
    if exec
        .site_authority_epoch
        .is_some_and(|bound| bound != authority_epoch)
    {
        return Err(format!(
            "Execution '{}' is already bound to a different site authority epoch",
            exec.id
        ));
    }
    exec.site_authority_epoch = Some(authority_epoch);
    validate_execution_invariants(exec)
}

/// Pure transition: approve an execution. Returns `Err` if the current status
/// is not `Draft` or the approver is the execution initiator. Returns a cloned
/// entity with `status = Approved`.
pub fn approve_execution_pure(
    exec: &RunbookExecution,
    approver: &str,
) -> Result<RunbookExecution, String> {
    validate_execution_invariants(exec)?;
    if approver.trim().is_empty() {
        return Err("approver cannot be empty".into());
    }
    if exec.status != ExecutionStatus::Draft {
        return Err(format!(
            "Execution '{}' must be in Draft status to approve (current: {:?})",
            exec.id, exec.status
        ));
    }
    if exec.started_by.trim() == approver.trim() {
        return Err(format!(
            "Execution '{}' requires an approver distinct from its initiator",
            exec.id
        ));
    }
    let mut updated = exec.clone();
    updated.status = ExecutionStatus::Approved;
    validate_execution_invariants(&updated)?;
    Ok(updated)
}

/// Pure transition: complete an execution. Completion is valid only after the
/// distinct approval boundary, either directly from `Approved` for a runbook
/// with no executable steps or from `Running` after step execution began.
pub fn complete_execution_pure(exec: &RunbookExecution) -> Result<RunbookExecution, String> {
    validate_execution_invariants(exec)?;
    if !matches!(
        exec.status,
        ExecutionStatus::Approved | ExecutionStatus::Running
    ) {
        return Err(format!(
            "Execution '{}' must be Approved or Running to complete (current: {:?})",
            exec.id, exec.status
        ));
    }
    if exec
        .steps_results
        .iter()
        .filter(|step| step.step_order > 0)
        .any(|step| step.status != StepStatus::Completed)
    {
        return Err(format!(
            "Execution '{}' cannot complete until every required step is completed",
            exec.id
        ));
    }
    let mut updated = exec.clone();
    updated.status = ExecutionStatus::Completed;
    validate_execution_invariants(&updated)?;
    Ok(updated)
}

/// Pure transition: fail an execution. Returns `Err` if the execution is
/// already terminal.
pub fn fail_execution_pure(
    exec: &RunbookExecution,
    reason: &str,
) -> Result<RunbookExecution, String> {
    validate_execution_invariants(exec)?;
    if reason.trim().is_empty() {
        return Err("reason cannot be empty".into());
    }
    if is_terminal(&exec.status) {
        return Err(format!(
            "Execution '{}' is already terminal ({:?})",
            exec.id, exec.status
        ));
    }
    let timestamp = now_iso();
    let mut updated = exec.clone();
    updated.status = ExecutionStatus::Failed;
    updated.steps_results.push(StepResult {
        step_order: 0,
        status: StepStatus::Failed,
        output: reason.into(),
        started_at: Some(timestamp.clone()),
        completed_at: Some(timestamp),
    });
    validate_execution_invariants(&updated)?;
    Ok(updated)
}

/// Pure transition: rollback an execution. Returns `Err` if the execution is
/// already terminal.
pub fn rollback_execution_pure(exec: &RunbookExecution) -> Result<RunbookExecution, String> {
    validate_execution_invariants(exec)?;
    if is_terminal(&exec.status) {
        return Err(format!(
            "Execution '{}' is already terminal ({:?})",
            exec.id, exec.status
        ));
    }
    let mut updated = exec.clone();
    updated.status = ExecutionStatus::RolledBack;
    validate_execution_invariants(&updated)?;
    Ok(updated)
}

/// Pure transition: execute a step. Step execution is valid only after the
/// distinct Draft-to-Approved transition and while the execution is Approved
/// or Running.
pub fn execute_step_pure(
    exec: &RunbookExecution,
    step_order: u32,
) -> Result<RunbookExecution, String> {
    validate_execution_invariants(exec)?;
    if !matches!(
        exec.status,
        ExecutionStatus::Approved | ExecutionStatus::Running
    ) {
        return Err(format!(
            "Execution '{}' must be Approved or Running to execute a step (current: {:?})",
            exec.id, exec.status
        ));
    }
    let step = exec
        .steps_results
        .iter()
        .find(|s| s.step_order == step_order)
        .ok_or_else(|| format!("Step {} not found", step_order))?;
    if step.status != StepStatus::Pending {
        return Err(format!(
            "Step {} is not Pending (current: {:?})",
            step_order, step.status
        ));
    }
    if exec.steps_results.iter().any(|candidate| {
        candidate.step_order > 0
            && candidate.step_order < step_order
            && candidate.status != StepStatus::Completed
    }) {
        return Err(format!(
            "Step {} cannot execute before every predecessor is completed",
            step_order
        ));
    }
    let timestamp = now_iso();
    let mut updated = exec.clone();
    updated.status = ExecutionStatus::Running;
    for step in &mut updated.steps_results {
        if step.step_order == step_order {
            step.status = StepStatus::Completed;
            step.output = format!("Step {} completed successfully in dry-run mode", step_order);
            step.started_at = Some(timestamp.clone());
            step.completed_at = Some(timestamp.clone());
        }
    }
    validate_execution_invariants(&updated)?;
    Ok(updated)
}

// ─── Public API ───────────────────────────────────────────────────────────────

pub fn list_runbooks() -> Result<Value, String> {
    Ok(json!({
        "source": "dry-run",
        "runbooks": runbook_catalog()
    }))
}

pub fn start_runbook(runbook_id: &str, site: &str, started_by: &str) -> Result<Value, String> {
    let execution = build_execution(runbook_id, site, started_by)?;
    let canonical_site = execution.site.clone();
    crate::site_registry::with_active_site_admission(&canonical_site, |_| {
        execution_store().lock().unwrap().push(execution.clone());
        Ok(json!({
            "source": "dry-run",
            "execution": execution
        }))
    })
}

fn with_active_execution_mutation<T>(
    execution_id: &str,
    operation: impl FnOnce(&mut RunbookExecution) -> Result<T, String>,
) -> Result<T, String> {
    let site = {
        let store = execution_store()
            .lock()
            .map_err(|error| error.to_string())?;
        store
            .iter()
            .find(|execution| execution.id == execution_id)
            .map(|execution| execution.site.clone())
            .ok_or_else(|| format!("Execution '{execution_id}' not found"))?
    };

    crate::site_registry::with_active_site_admission(&site, |canonical_site| {
        let mut store = execution_store()
            .lock()
            .map_err(|error| error.to_string())?;
        let execution = store
            .iter_mut()
            .find(|execution| execution.id == execution_id)
            .ok_or_else(|| format!("Execution '{execution_id}' not found"))?;
        if execution.site != canonical_site {
            return Err(format!(
                "Execution '{execution_id}' changed site authority while awaiting mutation"
            ));
        }
        operation(execution)
    })
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
    with_active_execution_mutation(execution_id, |execution| {
        let updated = execute_step_pure(execution, step_order)?;
        let step_result = updated
            .steps_results
            .iter()
            .find(|s| s.step_order == step_order)
            .cloned();
        *execution = updated;

        Ok(json!({
            "source": "dry-run",
            "execution_id": execution.id,
            "status": execution.status,
            "step_result": step_result
        }))
    })
}

pub fn approve_execution(id: &str, approver: &str) -> Result<Value, String> {
    with_active_execution_mutation(id, |execution| {
        let updated = approve_execution_pure(execution, approver)?;
        *execution = updated;

        Ok(json!({
            "source": "dry-run",
            "execution": execution,
            "approved_by": approver,
            "approved_at": now_iso()
        }))
    })
}

pub fn complete_execution(id: &str) -> Result<Value, String> {
    with_active_execution_mutation(id, |execution| {
        let updated = complete_execution_pure(execution)?;
        *execution = updated;

        Ok(json!({
            "source": "dry-run",
            "execution": execution,
            "completed_at": now_iso()
        }))
    })
}

pub fn fail_execution(id: &str, reason: &str) -> Result<Value, String> {
    let mut store = execution_store().lock().unwrap();
    let execution = store
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("Execution '{}' not found", id))?;

    let updated = fail_execution_pure(execution, reason)?;
    *execution = updated;

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

    let updated = rollback_execution_pure(execution)?;
    *execution = updated;

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
    fn approval_required_runbook_starts_in_draft_status() {
        let result = start_runbook("certificate-renewal", "DEFRA", "test.engineer").unwrap();

        assert_eq!(result["execution"]["runbook_id"], "certificate-renewal");
        assert_eq!(result["execution"]["site"], "DEFRA");
        assert_eq!(result["execution"]["status"], "draft");
    }

    #[test]
    fn no_approval_runbook_starts_ready_and_can_execute() {
        let ready = build_execution("restart-service", "DEFRA", "test.engineer").unwrap();

        assert_eq!(ready.status, ExecutionStatus::Approved);
        let running = execute_step_pure(&ready, 1)
            .expect("a catalog runbook that explicitly needs no approval stays executable");
        assert_eq!(running.status, ExecutionStatus::Running);
        assert_eq!(ready.status, ExecutionStatus::Approved);
    }

    #[test]
    fn durable_site_authority_binding_is_positive_and_immutable() {
        let mut execution = build_execution("restart-service", "DEFRA", "test.engineer").unwrap();
        assert_eq!(execution.site_authority_epoch, None);
        assert!(bind_site_authority_epoch(&mut execution, 0).is_err());
        bind_site_authority_epoch(&mut execution, 41).expect("bind positive canonical epoch");
        bind_site_authority_epoch(&mut execution, 41).expect("same binding is idempotent");
        assert_eq!(execution.site_authority_epoch, Some(41));
        assert!(
            bind_site_authority_epoch(&mut execution, 42).is_err(),
            "an existing execution cannot be rebound to a newer site lifetime"
        );
        assert_eq!(execution.site_authority_epoch, Some(41));
    }

    #[test]
    fn unknown_or_inactive_sites_cannot_start_or_advance_in_memory_lifecycle() {
        let suffix = Uuid::new_v4().simple().to_string();
        let site = format!("RB-R11-{}", &suffix[..8]).to_ascii_uppercase();
        crate::site_registry::upsert_site(
            crate::site_registry::SiteEntry {
                unlocode: site.clone(),
                name: "Runbook R11 test site".into(),
                country: "Test".into(),
                country_code: "ZZ".into(),
                timezone: "Etc/UTC".into(),
                active: true,
            },
            crate::site_registry::SiteCodeSystem::Custom,
        )
        .expect("register active runbook test site");

        let approval = build_execution("certificate-renewal", &site, "maker.approval").unwrap();
        let step = build_execution("restart-service", &site, "maker.step").unwrap();
        let complete_ready = build_execution("restart-service", &site, "maker.complete").unwrap();
        let complete_step_1 = execute_step_pure(&complete_ready, 1).unwrap();
        let complete_step_2 = execute_step_pure(&complete_step_1, 2).unwrap();
        let complete = execute_step_pure(&complete_step_2, 3).unwrap();
        let fail = build_execution("certificate-renewal", &site, "maker.fail").unwrap();
        let rollback = build_execution("certificate-renewal", &site, "maker.rollback").unwrap();

        execution_store().lock().unwrap().extend([
            approval.clone(),
            step.clone(),
            complete.clone(),
            fail.clone(),
            rollback.clone(),
        ]);
        crate::site_registry::deactivate_site(&site).expect("deactivate runbook test site");

        let inactive_start = start_runbook("restart-service", &site, "maker.start")
            .expect_err("an inactive site cannot start a runbook");
        assert!(inactive_start.contains("unknown or inactive"));
        let unknown_site = format!("RB-UNKNOWN-{}", &suffix[..8]).to_ascii_uppercase();
        let unknown_start = start_runbook("restart-service", &unknown_site, "maker.start")
            .expect_err("an unknown site cannot start a runbook");
        assert!(unknown_start.contains("unknown or inactive"));

        for error in [
            approve_execution(&approval.id, "checker.approval").unwrap_err(),
            execute_step(&step.id, 1).unwrap_err(),
            complete_execution(&complete.id).unwrap_err(),
        ] {
            assert!(
                error.contains("unknown or inactive"),
                "every forward lifecycle mutation must reject inactive authority: {error}"
            );
        }
        let failed = fail_execution(&fail.id, "controlled failure")
            .expect("protective failure remains available after site deactivation");
        let rolled_back = rollback_execution(&rollback.id)
            .expect("protective rollback remains available after site deactivation");
        assert_eq!(failed["execution"]["status"], "failed");
        assert_eq!(rolled_back["execution"]["status"], "rolled-back");

        assert_eq!(
            get_execution(&approval.id).unwrap()["execution"]["status"],
            "draft"
        );
        assert_eq!(
            get_execution(&step.id).unwrap()["execution"]["status"],
            "approved"
        );
        assert_eq!(
            get_execution(&complete.id).unwrap()["execution"]["status"],
            "running"
        );
        assert_eq!(
            get_execution(&fail.id).unwrap()["execution"]["status"],
            "failed"
        );
        assert_eq!(
            get_execution(&rollback.id).unwrap()["execution"]["status"],
            "rolled-back"
        );

        crate::site_registry::activate_site(&site).expect("reactivate runbook test site");
        let approved = approve_execution(&approval.id, "checker.approval")
            .expect("the same mutation remains supported for an active site");
        assert_eq!(approved["execution"]["status"], "approved");
    }

    #[test]
    fn test_approve_and_complete_flow() {
        let result = start_runbook("dns-record-update", "GBLON", "test.engineer").unwrap();
        let id = result["execution"]["id"].as_str().unwrap();

        let approved = approve_execution(id, "change.manager").unwrap();
        assert_eq!(approved["execution"]["status"], "approved");

        execute_step(id, 1).unwrap();
        execute_step(id, 2).unwrap();
        execute_step(id, 3).unwrap();
        let completed = complete_execution(id).unwrap();
        assert_eq!(completed["execution"]["status"], "completed");
    }

    #[test]
    fn initiator_cannot_approve_own_execution() {
        let draft = build_execution("dns-record-update", "GBLON", "same.principal").unwrap();

        let error = approve_execution_pure(&draft, " same.principal ")
            .expect_err("maker/checker approval must require a distinct principal");

        assert!(error.contains("approver distinct from its initiator"));
        assert_eq!(draft.status, ExecutionStatus::Draft);
    }

    #[test]
    fn distinct_principal_can_approve_execution() {
        let draft = build_execution("dns-record-update", "GBLON", "request.maker").unwrap();

        let approved = approve_execution_pure(&draft, "request.checker")
            .expect("a distinct approver must retain the supported approval flow");

        assert_eq!(approved.status, ExecutionStatus::Approved);
        assert_eq!(draft.status, ExecutionStatus::Draft);
    }

    #[test]
    fn test_execute_step_updates_result() {
        let result = start_runbook("certificate-renewal", "DEBER", "test.engineer").unwrap();
        let id = result["execution"]["id"].as_str().unwrap();

        approve_execution(id, "change.manager").unwrap();

        let executed = execute_step(id, 1).unwrap();

        assert_eq!(executed["status"], "running");
        assert_eq!(executed["step_result"]["step_order"], 1);
        assert_eq!(executed["step_result"]["status"], "completed");
        assert!(executed["step_result"]["completed_at"].as_str().is_some());
    }

    #[test]
    fn completed_step_cannot_be_executed_twice() {
        let draft = build_execution("certificate-renewal", "DEBER", "test.engineer").unwrap();
        let approved = approve_execution_pure(&draft, "change.manager").unwrap();
        let running = execute_step_pure(&approved, 1).expect("first execution");

        let error =
            execute_step_pure(&running, 1).expect_err("completed step retry must be a no-op");

        assert!(error.contains("not Pending"));
        assert_eq!(
            running
                .steps_results
                .iter()
                .find(|step| step.step_order == 1)
                .expect("step")
                .status,
            StepStatus::Completed
        );
    }

    #[test]
    fn later_steps_require_completed_predecessors() {
        let draft = build_execution("certificate-renewal", "DEBER", "test.engineer").unwrap();
        let approved = approve_execution_pure(&draft, "change.manager").unwrap();

        let error = execute_step_pure(&approved, 2)
            .expect_err("step 2 must not bypass its pending predecessor");

        assert!(error.contains("predecessor"));
        assert!(
            approved
                .steps_results
                .iter()
                .all(|step| step.status == StepStatus::Pending)
        );
    }

    #[test]
    fn completion_requires_every_required_step() {
        let ready = build_execution("restart-service", "DEFRA", "test.engineer").unwrap();
        let error = complete_execution_pure(&ready)
            .expect_err("Approved with pending required steps cannot complete");
        assert!(error.contains("every required step"));

        let one = execute_step_pure(&ready, 1).unwrap();
        assert!(complete_execution_pure(&one).is_err());
        let two = execute_step_pure(&one, 2).unwrap();
        let three = execute_step_pure(&two, 3).unwrap();
        assert_eq!(
            complete_execution_pure(&three).unwrap().status,
            ExecutionStatus::Completed
        );
    }

    #[test]
    fn malformed_required_step_projection_fails_closed() {
        let mut ready = build_execution("restart-service", "DEFRA", "test.engineer").unwrap();
        ready.steps_results.remove(1);
        assert!(validate_execution_invariants(&ready).is_err());

        let mut duplicate = build_execution("restart-service", "DEFRA", "test.engineer").unwrap();
        duplicate.steps_results[2].step_order = 2;
        assert!(validate_execution_invariants(&duplicate).is_err());
    }

    #[test]
    fn draft_execution_cannot_execute_a_step() {
        let draft = build_execution("certificate-renewal", "DEBER", "test.engineer").unwrap();

        let error = execute_step_pure(&draft, 1)
            .expect_err("Draft execution must cross the approval boundary first");

        assert!(error.contains("Approved or Running"));
        assert_eq!(draft.status, ExecutionStatus::Draft);
        assert!(
            draft
                .steps_results
                .iter()
                .all(|step| step.status == StepStatus::Pending)
        );
    }

    #[test]
    fn draft_execution_cannot_complete() {
        let draft = build_execution("dns-record-update", "GBLON", "test.engineer").unwrap();

        let error = complete_execution_pure(&draft)
            .expect_err("Draft execution must cross the approval boundary first");

        assert!(error.contains("Approved or Running"));
        assert_eq!(draft.status, ExecutionStatus::Draft);
    }

    #[test]
    fn test_fail_execution_records_reason() {
        let result = start_runbook("firewall-rule-change", "DEFRA", "test.engineer").unwrap();
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
        let _ = start_runbook("restart-service", "DEBER", "test.engineer").unwrap();

        let result = list_executions(Some("DEBER")).unwrap();
        let executions = result["executions"].as_array().unwrap();

        assert!(!executions.is_empty());
        assert!(executions.iter().all(|e| e["site"] == "DEBER"));
    }
}
