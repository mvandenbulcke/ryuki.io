use crate::models::*;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

const VALID_SITES: &[&str] = &["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"];
const VALID_ENVIRONMENTS: &[&str] = &["development", "test", "acceptance", "production"];
const BLOCKED_STATUSES: &[RequestStatus] = &[RequestStatus::Failed, RequestStatus::Completed];

fn has_completed_stage(request: &Request, name: &str) -> bool {
    request
        .stages
        .iter()
        .any(|stage| stage.name == name && stage.status == StageStatus::Completed)
}

fn require_completed_stage_for_transition(
    request: &Request,
    stage: &str,
    new_status: &RequestStatus,
) -> Result<(), String> {
    if !has_completed_stage(request, stage) {
        return Err(format!(
            "Cannot transition request to {:?} without a completed {} stage.",
            new_status, stage
        ));
    }
    Ok(())
}

pub fn create_request(
    offering_id: &str,
    request_type: RequestType,
    requester: &str,
    owner: &str,
    site: &str,
    environment: &str,
    criticality: &str,
) -> Result<Request, String> {
    if offering_id.is_empty() {
        return Err("offering_id cannot be empty".into());
    }
    if requester.is_empty() {
        return Err("requester cannot be empty".into());
    }
    if owner.is_empty() {
        return Err("owner cannot be empty".into());
    }
    if site.is_empty() {
        return Err("site cannot be empty".into());
    }
    if environment.is_empty() {
        return Err("environment cannot be empty".into());
    }
    if criticality.is_empty() {
        return Err("criticality cannot be empty".into());
    }

    let id = format!(
        "req-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    let mut request = Request::new(
        id,
        offering_id.to_string(),
        request_type,
        requester.to_string(),
        owner.to_string(),
        site.to_string(),
        environment.to_string(),
        criticality.to_string(),
    );

    request.status = RequestStatus::Intake;
    request.stages.push(Stage {
        name: "intake".into(),
        status: StageStatus::Completed,
        started_at: Some(request.created_at.clone()),
        completed_at: Some(Utc::now().to_rfc3339()),
        evidence: vec![EvidenceItem {
            key: "intake-summary".into(),
            value: format!("Request created for offering {}", offering_id),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::Summary,
        }],
        metadata: HashMap::new(),
    });

    request.updated_at = Utc::now().to_rfc3339();

    Ok(request)
}

pub fn validate_request(request: &Request) -> Result<ValidationResult, String> {
    if BLOCKED_STATUSES.contains(&request.status) {
        return Ok(ValidationResult {
            passed: false,
            errors: vec![format!(
                "Cannot validate request in status: {:?}",
                request.status
            )],
            warnings: Vec::new(),
            failed_rules: vec!["blocked-status".into()],
            remediation: vec!["Move request back to Draft or Intake before validation.".into()],
        });
    }

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut failed_rules: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();

    if request.owner.is_empty() {
        errors.push("Missing required field: owner".into());
        failed_rules.push("p0-preflight-required-fields".into());
        remediation.push("Add the request owner before validation.".into());
    }
    if request.site.is_empty() {
        errors.push("Missing required field: site".into());
        failed_rules.push("p0-preflight-required-fields".into());
        remediation.push("Add the target site before validation.".into());
    }
    if request.environment.is_empty() {
        errors.push("Missing required field: environment".into());
        failed_rules.push("p0-preflight-required-fields".into());
        remediation.push("Add the target environment before validation.".into());
    }
    if request.criticality.is_empty() {
        errors.push("Missing required field: criticality".into());
        failed_rules.push("p0-preflight-required-fields".into());
        remediation.push("Add the service criticality before validation.".into());
    }

    if !request.site.is_empty() && !VALID_SITES.contains(&request.site.as_str()) {
        errors.push(format!("Unknown site: {}", request.site));
        failed_rules.push("p0-site-ou-catalog-match".into());
        remediation.push(format!(
            "Select a known site. Valid sites: {:?}",
            VALID_SITES
        ));
    }

    if !request.environment.is_empty()
        && !VALID_ENVIRONMENTS.contains(&request.environment.as_str())
    {
        errors.push(format!("Unknown environment: {}", request.environment));
        failed_rules.push("p0-preflight-required-fields".into());
        remediation.push(format!(
            "Select a valid environment. Valid environments: {:?}",
            VALID_ENVIRONMENTS
        ));
    }

    if request.approval_route.is_empty()
        || !request
            .approval_route
            .contains(&"Datacenter Approver".to_string())
    {
        warnings.push("Approval route does not include Datacenter Approver".into());
        failed_rules.push("p0-approval-authority-required".into());
        remediation.push(
            "Include Datacenter Approver in the approval route for write-capable requests.".into(),
        );
    }

    if request.dry_run_required {
        let has_dry_run = request.stages.iter().any(|s| s.name == "plan");
        if !has_dry_run {
            warnings.push("Dry-run plan is required before approval".into());
            failed_rules.push("p0-dry-run-before-approval".into());
            remediation
                .push("Generate a provider-safe dry-run plan before seeking approval.".into());
        }
    }

    let has_evidence = request.evidence_manifest_id.is_some();
    if !has_evidence {
        warnings.push("Evidence manifest is not yet assigned".into());
    }

    Ok(ValidationResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        failed_rules,
        remediation,
    })
}

pub fn plan_request(request: &Request) -> Result<Vec<Stage>, String> {
    if request.status != RequestStatus::Validated {
        return Err(format!(
            "Cannot plan request in status {:?}. Request must be successfully validated first.",
            request.status
        ));
    }

    let mut stages: Vec<Stage> = Vec::new();

    stages.push(Stage {
        name: "validate".into(),
        status: StageStatus::Completed,
        started_at: Some(Utc::now().to_rfc3339()),
        completed_at: Some(Utc::now().to_rfc3339()),
        evidence: Vec::new(),
        metadata: HashMap::from([("step".into(), "1".into())]),
    });

    stages.push(Stage {
        name: "plan".into(),
        status: StageStatus::Completed,
        started_at: Some(Utc::now().to_rfc3339()),
        completed_at: Some(Utc::now().to_rfc3339()),
        evidence: vec![EvidenceItem {
            key: "dry-run-plan".into(),
            value: format!(
                "DRY-RUN: Planned execution for {} in site {} environment {} (simulated, no provider calls)",
                request.request_type, request.site, request.environment
            ),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::Plan,
        }],
        metadata: HashMap::from([
            ("step".into(), "2".into()),
            ("dry_run".into(), "true".into()),
        ]),
    });

    stages.push(Stage {
        name: "approve".into(),
        status: StageStatus::Pending,
        started_at: None,
        completed_at: None,
        evidence: Vec::new(),
        metadata: HashMap::from([("step".into(), "3".into())]),
    });

    stages.push(Stage {
        name: "lock".into(),
        status: StageStatus::Pending,
        started_at: None,
        completed_at: None,
        evidence: Vec::new(),
        metadata: HashMap::from([("step".into(), "4".into())]),
    });

    stages.push(Stage {
        name: "execute".into(),
        status: StageStatus::Pending,
        started_at: None,
        completed_at: None,
        evidence: vec![EvidenceItem {
            key: "execution-plan-note".into(),
            value: "Execution is simulated in dry-run mode. No provider calls will be made.".into(),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::ExecutionLog,
        }],
        metadata: HashMap::from([
            ("step".into(), "5".into()),
            ("dry_run".into(), "true".into()),
        ]),
    });

    stages.push(Stage {
        name: "verify".into(),
        status: StageStatus::Pending,
        started_at: None,
        completed_at: None,
        evidence: Vec::new(),
        metadata: HashMap::from([("step".into(), "6".into())]),
    });

    stages.push(Stage {
        name: "protect".into(),
        status: StageStatus::Pending,
        started_at: None,
        completed_at: None,
        evidence: Vec::new(),
        metadata: HashMap::from([("step".into(), "7".into())]),
    });

    stages.push(Stage {
        name: "publish".into(),
        status: StageStatus::Pending,
        started_at: None,
        completed_at: None,
        evidence: Vec::new(),
        metadata: HashMap::from([("step".into(), "8".into())]),
    });

    Ok(stages)
}

pub fn approve_request(request: &Request, approver: &str) -> Result<Request, String> {
    if request.status != RequestStatus::Planned {
        return Err(format!(
            "Cannot approve request in status {:?}. Request must have a successful dry-run plan first.",
            request.status
        ));
    }

    if !has_completed_stage(request, "plan") {
        return Err("Cannot approve request without a completed dry-run plan stage.".into());
    }

    let mut approved = request.clone();
    approved.status = RequestStatus::Approved;
    approved.updated_at = Utc::now().to_rfc3339();

    let has_approve_stage = approved.stages.iter().any(|s| s.name == "approve");
    if !has_approve_stage {
        approved.stages.push(Stage {
            name: "approve".into(),
            status: StageStatus::Completed,
            started_at: Some(Utc::now().to_rfc3339()),
            completed_at: Some(Utc::now().to_rfc3339()),
            evidence: vec![EvidenceItem {
                key: "approval-decision".into(),
                value: format!("Approved by {}", approver),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::ApprovalDecision,
            }],
            metadata: HashMap::from([("approver".into(), approver.to_string())]),
        });
    }

    if !approved.approval_route.contains(&approver.to_string()) {
        approved.approval_route.push(approver.to_string());
    }

    Ok(approved)
}

pub fn lock_request(request: &Request) -> Result<Request, String> {
    if request.status != RequestStatus::Approved {
        return Err(format!(
            "Cannot lock request in status {:?}. Request must be Approved first.",
            request.status
        ));
    }

    let mut locked = request.clone();
    locked.status = RequestStatus::Locked;
    locked.updated_at = Utc::now().to_rfc3339();

    let lock_id = format!(
        "lock-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    locked.stages.push(Stage {
        name: "lock".into(),
        status: StageStatus::Completed,
        started_at: Some(Utc::now().to_rfc3339()),
        completed_at: Some(Utc::now().to_rfc3339()),
        evidence: vec![EvidenceItem {
            key: "lock-record".into(),
            value: format!(
                "DRY-RUN: Lock {} acquired for request {} on site {} scope {} (simulated, no live lock)",
                lock_id, locked.id, locked.site, locked.environment
            ),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::LockRecord,
        }],
        metadata: HashMap::from([
            ("lock_id".into(), lock_id),
            ("scope".into(), format!("{}/{}", locked.site, locked.environment)),
        ]),
    });

    Ok(locked)
}

pub fn execute_request(request: &Request) -> Result<Request, String> {
    if request.status != RequestStatus::Locked {
        return Err(format!(
            "Cannot execute request in status {:?}. Request must be Locked first.",
            request.status
        ));
    }

    let mut executing = request.clone();
    executing.status = RequestStatus::Executing;
    executing.updated_at = Utc::now().to_rfc3339();

    let execute_stage = executing.stages.iter_mut().find(|s| s.name == "execute");

    if let Some(stage) = execute_stage {
        stage.status = StageStatus::Completed;
        stage.started_at = Some(Utc::now().to_rfc3339());
        stage.completed_at = Some(Utc::now().to_rfc3339());
        stage.evidence.push(EvidenceItem {
            key: "execution-log".into(),
            value: format!(
                "DRY-RUN: Simulated execution of {} for request {} (no provider operations performed)",
                request.request_type, request.id
            ),
            redacted_value: Some("***DRY-RUN SIMULATION***".into()),
            redacted: true,
            evidence_type: EvidenceType::ExecutionLog,
        });
    } else {
        executing.stages.push(Stage {
            name: "execute".into(),
            status: StageStatus::Completed,
            started_at: Some(Utc::now().to_rfc3339()),
            completed_at: Some(Utc::now().to_rfc3339()),
            evidence: vec![EvidenceItem {
                key: "execution-log".into(),
                value: format!(
                    "DRY-RUN: Simulated execution of {} for request {} (no provider operations performed)",
                    request.request_type, request.id
                ),
                redacted_value: Some("***DRY-RUN SIMULATION***".into()),
                redacted: true,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            metadata: HashMap::from([("dry_run".into(), "true".into())]),
        });
    }

    executing.status = RequestStatus::Verifying;

    Ok(executing)
}

pub fn verify_request(request: &Request) -> Result<Vec<EvidenceItem>, String> {
    if request.status != RequestStatus::Verifying {
        return Err(format!(
            "Cannot verify request in status {:?}. Request must be in Verifying state.",
            request.status
        ));
    }

    let mut evidence_items: Vec<EvidenceItem> = Vec::new();

    evidence_items.push(EvidenceItem {
        key: "verification-before-inventory".into(),
        value: format!(
            "DRY-RUN: Pre-execution inventory snapshot for site {} environment {} (simulated)",
            request.site, request.environment
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence_items.push(EvidenceItem {
        key: "verification-after-inventory".into(),
        value: format!(
            "DRY-RUN: Post-execution inventory snapshot for site {} environment {} (simulated)",
            request.site, request.environment
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::InventoryCheck,
    });

    evidence_items.push(EvidenceItem {
        key: "verification-service-health".into(),
        value: "DRY-RUN: Service health check passed (simulated)".into(),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    Ok(evidence_items)
}

pub fn transition_status(request: &Request, new_status: RequestStatus) -> Result<Request, String> {
    let valid_transitions: Vec<(RequestStatus, RequestStatus)> = vec![
        (RequestStatus::Draft, RequestStatus::Intake),
        (RequestStatus::Intake, RequestStatus::Validated),
        (RequestStatus::Validated, RequestStatus::Planned),
        (RequestStatus::Planned, RequestStatus::Approved),
        (RequestStatus::Approved, RequestStatus::Locked),
        (RequestStatus::Locked, RequestStatus::Executing),
        (RequestStatus::Executing, RequestStatus::Verifying),
        (RequestStatus::Verifying, RequestStatus::Completed),
    ];

    if !valid_transitions.contains(&(request.status.clone(), new_status.clone())) {
        return Err(format!(
            "Invalid transition from {:?} to {:?}",
            request.status, new_status
        ));
    }

    match (&request.status, &new_status) {
        (RequestStatus::Intake, RequestStatus::Validated) => {
            let result = validate_request(request)?;
            if !result.passed {
                return Err(format!(
                    "Cannot transition request to Validated until validation passes: {}",
                    result.errors.join("; ")
                ));
            }
        }
        (RequestStatus::Validated, RequestStatus::Planned) => {
            require_completed_stage_for_transition(request, "plan", &new_status)?;
        }
        (RequestStatus::Planned, RequestStatus::Approved) => {
            require_completed_stage_for_transition(request, "plan", &new_status)?;
            require_completed_stage_for_transition(request, "approve", &new_status)?;
        }
        (RequestStatus::Approved, RequestStatus::Locked) => {
            require_completed_stage_for_transition(request, "approve", &new_status)?;
        }
        (RequestStatus::Locked, RequestStatus::Executing) => {
            require_completed_stage_for_transition(request, "lock", &new_status)?;
        }
        (RequestStatus::Executing, RequestStatus::Verifying) => {
            require_completed_stage_for_transition(request, "execute", &new_status)?;
        }
        (RequestStatus::Verifying, RequestStatus::Completed) => {
            require_completed_stage_for_transition(request, "verify", &new_status)?;
        }
        _ => {}
    }

    let mut updated = request.clone();
    updated.status = new_status;
    updated.updated_at = Utc::now().to_rfc3339();

    Ok(updated)
}

pub fn fail_request(request: &Request, reason: &str) -> Result<Request, String> {
    if request.status == RequestStatus::Completed {
        return Err("Cannot fail a completed request.".into());
    }

    let mut failed = request.clone();
    failed.status = RequestStatus::Failed;
    failed.updated_at = Utc::now().to_rfc3339();
    failed
        .metadata
        .insert("failure_reason".into(), reason.to_string());

    Ok(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_request() -> Request {
        create_request(
            "windows-server-deployment",
            RequestType::ServerDeployment,
            "alice",
            "bob",
            "DEFRA",
            "production",
            "critical",
        )
        .unwrap()
    }

    #[test]
    fn test_create_request_returns_intake_status() {
        let req = make_test_request();
        assert_eq!(req.status, RequestStatus::Intake);
        assert!(req.stages.iter().any(|s| s.name == "intake"));
    }

    #[test]
    fn test_create_request_missing_fields_rejected() {
        assert!(
            create_request("", RequestType::ServerDeployment, "a", "b", "c", "d", "e").is_err()
        );
        assert!(
            create_request("x", RequestType::ServerDeployment, "", "b", "c", "d", "e").is_err()
        );
    }

    #[test]
    fn test_validate_request_passes_for_valid_request() {
        let mut req = make_test_request();
        req.approval_route.push("Datacenter Approver".into());
        let result = validate_request(&req).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_validate_request_detects_unknown_site() {
        let mut req = make_test_request();
        req.site = "INVALID".into();
        let result = validate_request(&req).unwrap();
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e.contains("Unknown site")));
    }

    #[test]
    fn test_validate_request_requires_datacenter_approver() {
        let req = make_test_request();
        let result = validate_request(&req).unwrap();
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("Datacenter Approver"))
        );
    }

    #[test]
    fn test_plan_request_generates_stages() {
        let req = make_validated_request();
        let stages = plan_request(&req).unwrap();
        let plan_stage = stages.iter().find(|s| s.name == "plan").unwrap();
        assert_eq!(plan_stage.status, StageStatus::Completed);
        assert!(stages.iter().any(|s| s.name == "execute"));
        assert!(stages.iter().any(|s| s.name == "verify"));
    }

    #[test]
    fn test_plan_request_requires_validated_status() {
        let req = make_test_request();
        let error = plan_request(&req).unwrap_err();
        assert!(error.contains("successfully validated"));
    }

    fn make_validated_request() -> Request {
        let req = make_test_request();
        transition_status(&req, RequestStatus::Validated).unwrap()
    }

    fn completed_test_stage(name: &str) -> Stage {
        Stage {
            name: name.into(),
            status: StageStatus::Completed,
            started_at: Some(Utc::now().to_rfc3339()),
            completed_at: Some(Utc::now().to_rfc3339()),
            evidence: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    fn make_planned_request() -> Request {
        let mut validated = make_validated_request();
        validated.stages = plan_request(&validated).unwrap();
        transition_status(&validated, RequestStatus::Planned).unwrap()
    }

    #[test]
    fn test_approve_request_from_planned() {
        let req = make_planned_request();
        let result = approve_request(&req, "Datacenter Approver").unwrap();
        assert_eq!(result.status, RequestStatus::Approved);
    }

    #[test]
    fn test_approve_request_from_validated_without_plan_fails() {
        let req = make_validated_request();
        let error = approve_request(&req, "Datacenter Approver").unwrap_err();
        assert!(error.contains("dry-run plan"));
    }

    #[test]
    fn test_approve_request_from_planned_without_completed_plan_fails() {
        let mut req = make_validated_request();
        req.status = RequestStatus::Planned;
        let error = approve_request(&req, "Datacenter Approver").unwrap_err();
        assert!(error.contains("completed dry-run plan"));
    }

    #[test]
    fn test_approve_request_from_draft_fails() {
        let mut req = make_test_request();
        req.status = RequestStatus::Draft;
        assert!(approve_request(&req, "Datacenter Approver").is_err());
    }

    #[test]
    fn test_lock_request_from_approved() {
        let req = make_planned_request();
        let approved = approve_request(&req, "Datacenter Approver").unwrap();
        let locked = lock_request(&approved).unwrap();
        assert_eq!(locked.status, RequestStatus::Locked);
        assert!(locked.stages.iter().any(|s| s.name == "lock"));
    }

    #[test]
    fn test_lock_request_from_non_approved_fails() {
        let req = make_test_request();
        assert!(lock_request(&req).is_err());
    }

    #[test]
    fn test_execute_request_produces_redacted_log() {
        let req = make_planned_request();
        let approved = approve_request(&req, "Datacenter Approver").unwrap();
        let locked = lock_request(&approved).unwrap();
        let executed = execute_request(&locked).unwrap();
        assert_eq!(executed.status, RequestStatus::Verifying);
        let exec_stage = executed
            .stages
            .iter()
            .find(|s| s.name == "execute")
            .unwrap();
        let log_item = exec_stage
            .evidence
            .iter()
            .find(|e| e.key == "execution-log")
            .unwrap();
        assert!(log_item.redacted);
        assert_eq!(
            log_item.redacted_value,
            Some("***DRY-RUN SIMULATION***".into())
        );
    }

    #[test]
    fn test_verify_request_collects_evidence() {
        let mut req = make_test_request();
        req.status = RequestStatus::Verifying;
        let evidence = verify_request(&req).unwrap();
        assert_eq!(evidence.len(), 3);
        assert!(
            evidence
                .iter()
                .any(|e| e.key == "verification-before-inventory")
        );
        assert!(
            evidence
                .iter()
                .any(|e| e.key == "verification-after-inventory")
        );
        assert!(
            evidence
                .iter()
                .any(|e| e.key == "verification-service-health")
        );
    }

    #[test]
    fn test_transition_status_valid_path() {
        let req = make_test_request();
        let validated = transition_status(&req, RequestStatus::Validated).unwrap();
        assert_eq!(validated.status, RequestStatus::Validated);
        let mut planned_ready = validated.clone();
        planned_ready.stages = plan_request(&validated).unwrap();
        let planned = transition_status(&planned_ready, RequestStatus::Planned).unwrap();
        assert_eq!(planned.status, RequestStatus::Planned);
    }

    #[test]
    fn test_transition_status_invalid_path_fails() {
        let req = make_test_request();
        assert!(transition_status(&req, RequestStatus::Completed).is_err());
    }

    #[test]
    fn test_transition_to_validated_requires_validation_success() {
        let mut req = make_test_request();
        req.site = "UNKNOWN".into();

        let error = transition_status(&req, RequestStatus::Validated).unwrap_err();
        assert!(error.contains("validation passes"));
        assert!(error.contains("Unknown site"));
    }

    #[test]
    fn test_transition_to_planned_requires_plan_stage() {
        let validated = make_validated_request();

        let error = transition_status(&validated, RequestStatus::Planned).unwrap_err();
        assert!(error.contains("completed plan stage"));
    }

    #[test]
    fn test_transition_to_completed_requires_verify_stage() {
        let mut req = make_test_request();
        req.status = RequestStatus::Verifying;

        let error = transition_status(&req, RequestStatus::Completed).unwrap_err();
        assert!(error.contains("completed verify stage"));

        req.stages.push(completed_test_stage("verify"));
        let completed = transition_status(&req, RequestStatus::Completed).unwrap();
        assert_eq!(completed.status, RequestStatus::Completed);
    }

    #[test]
    fn test_fail_request_sets_status_and_reason() {
        let req = make_test_request();
        let failed = fail_request(&req, "Validation failed: unknown site").unwrap();
        assert_eq!(failed.status, RequestStatus::Failed);
        assert_eq!(
            failed.metadata.get("failure_reason").unwrap(),
            "Validation failed: unknown site"
        );
    }

    #[test]
    fn test_fail_completed_request_fails() {
        let mut req = make_test_request();
        req.status = RequestStatus::Completed;
        assert!(fail_request(&req, "reason").is_err());
    }

    #[test]
    fn test_full_lifecycle_path() {
        let req = make_test_request();
        assert_eq!(req.status, RequestStatus::Intake);

        let validated = transition_status(&req, RequestStatus::Validated).unwrap();
        let mut planned_ready = validated.clone();
        planned_ready.stages = plan_request(&validated).unwrap();
        let planned = transition_status(&planned_ready, RequestStatus::Planned).unwrap();
        let approved = approve_request(&planned, "Datacenter Approver").unwrap();
        let locked = lock_request(&approved).unwrap();
        let executed = execute_request(&locked).unwrap();

        assert_eq!(executed.status, RequestStatus::Verifying);
    }
}
