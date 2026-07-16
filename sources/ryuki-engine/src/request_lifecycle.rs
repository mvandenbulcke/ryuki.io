use crate::models::*;
use crate::site_registry;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

const VALID_ENVIRONMENTS: &[&str] = &["development", "test", "acceptance", "production"];

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
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }
    let site = site_registry::normalize_site_code_for_lookup(site)?;
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
        site,
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
    // From-status precondition: validation is a Draft|Intake-only act. This
    // mirrors the from-status guards on plan/approve/lock/etc. and prevents a
    // later-stage request (Validated/Planned/Approved/Locked/Executing/
    // Verifying, or any terminal status) from being rewound to "validated".
    // A failed ValidationResult (passed:false) — not an Err — is returned so
    // the API maps it to a 400 validation_failed_response, and
    // transition_status's Intake->Validated arm turns !passed into an Err, so
    // terminal-rewind protection holds on both call paths.
    if !matches!(request.status, RequestStatus::Draft | RequestStatus::Intake) {
        return Ok(ValidationResult {
            passed: false,
            errors: vec![format!(
                "Cannot validate request in status {:?}. Validation is only allowed from Draft or Intake.",
                request.status
            )],
            warnings: Vec::new(),
            failed_rules: vec!["invalid-from-status".into()],
            remediation: vec!["Validation can only run on a Draft or Intake request.".into()],
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

    if !request.site.is_empty() && !site_registry::is_valid_site(&request.site) {
        errors.push(format!("Unknown site: {}", request.site));
        failed_rules.push("p0-site-ou-catalog-match".into());
        remediation.push(
            "Select an active registered site. UN/LOCODE is recommended; custom codes must be registered and activated by an administrator first."
                .into(),
        );
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

    // Complete the approve stage and record the decision evidence + approver.
    // plan_request seeds a PENDING "approve" stage, so find-and-update it (the
    // same pattern reject_request uses) — pushing only when absent would leave
    // the stage Pending and DROP the approval evidence/approver from the trail.
    let decision = EvidenceItem {
        key: "approval-decision".into(),
        value: format!("Approved by {}", approver),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::ApprovalDecision,
    };
    if let Some(stage) = approved.stages.iter_mut().find(|s| s.name == "approve") {
        stage.status = StageStatus::Completed;
        stage
            .started_at
            .get_or_insert_with(|| Utc::now().to_rfc3339());
        stage.completed_at = Some(Utc::now().to_rfc3339());
        stage.evidence.push(decision);
        stage
            .metadata
            .insert("approver".into(), approver.to_string());
    } else {
        approved.stages.push(Stage {
            name: "approve".into(),
            status: StageStatus::Completed,
            started_at: Some(Utc::now().to_rfc3339()),
            completed_at: Some(Utc::now().to_rfc3339()),
            evidence: vec![decision],
            metadata: HashMap::from([("approver".into(), approver.to_string())]),
        });
    }

    if !approved.approval_route.contains(&approver.to_string()) {
        approved.approval_route.push(approver.to_string());
    }

    Ok(approved)
}

/// Reject a request at the approval decision point. Valid ONLY from `Planned`
/// (the same state `approve_request` accepts) — it is the inverse approver act.
/// Returns a clone with status=Rejected (TERMINAL); records the rejection as a
/// failed `approve` stage carrying an ApprovalDecision evidence item, and stores
/// the mandatory reason in metadata. Pure: no I/O — ryuki-api persists.
pub fn reject_request(request: &Request, approver: &str, reason: &str) -> Result<Request, String> {
    if reason.trim().is_empty() {
        return Err("Rejection reason cannot be empty".into());
    }

    if request.status != RequestStatus::Planned {
        return Err(format!(
            "Cannot reject request in status {:?}. A request can only be rejected at the approval decision point (Planned).",
            request.status
        ));
    }

    let mut rejected = request.clone();
    rejected.status = RequestStatus::Rejected;
    rejected.updated_at = Utc::now().to_rfc3339();

    let decision = EvidenceItem {
        key: "approval-decision".into(),
        value: format!("Rejected by {approver}: {reason}"),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::ApprovalDecision,
    };
    let metadata = HashMap::from([
        ("approver".into(), approver.to_string()),
        ("reason".into(), reason.to_string()),
        ("decision".into(), "rejected".into()),
    ]);

    if let Some(stage) = rejected.stages.iter_mut().find(|s| s.name == "approve") {
        stage.status = StageStatus::Failed;
        stage.started_at = Some(Utc::now().to_rfc3339());
        stage.completed_at = Some(Utc::now().to_rfc3339());
        stage.evidence.push(decision);
        stage.metadata.extend(metadata);
    } else {
        rejected.stages.push(Stage {
            name: "approve".into(),
            status: StageStatus::Failed,
            started_at: Some(Utc::now().to_rfc3339()),
            completed_at: Some(Utc::now().to_rfc3339()),
            evidence: vec![decision],
            metadata,
        });
    }

    Ok(rejected)
}

/// Cancel a request before it begins executing. Valid from
/// Draft|Intake|Validated|Planned|Approved|Locked — NOT once Executing/Verifying
/// or already terminal (Completed/Failed/Rejected/Cancelled). Returns a clone
/// with status=Cancelled (TERMINAL); appends a completed `cancel` stage with a
/// Summary evidence item and stores the mandatory reason in metadata. Pure: no
/// I/O — ryuki-api persists.
pub fn cancel_request(request: &Request, actor: &str, reason: &str) -> Result<Request, String> {
    if reason.trim().is_empty() {
        return Err("Cancellation reason cannot be empty".into());
    }

    let cancellable = matches!(
        request.status,
        RequestStatus::Draft
            | RequestStatus::Intake
            | RequestStatus::Validated
            | RequestStatus::Planned
            | RequestStatus::Approved
            | RequestStatus::Locked
    );
    if !cancellable {
        return Err(format!(
            "Cannot cancel request in status {:?}. Cancellation is only allowed before execution begins.",
            request.status
        ));
    }

    let mut cancelled = request.clone();
    cancelled.status = RequestStatus::Cancelled;
    cancelled.updated_at = Utc::now().to_rfc3339();

    cancelled.stages.push(Stage {
        name: "cancel".into(),
        status: StageStatus::Completed,
        started_at: Some(Utc::now().to_rfc3339()),
        completed_at: Some(Utc::now().to_rfc3339()),
        evidence: vec![EvidenceItem {
            key: "cancellation-summary".into(),
            value: format!("Cancelled by {actor}: {reason}"),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::Summary,
        }],
        metadata: HashMap::from([
            ("actor".into(), actor.to_string()),
            ("reason".into(), reason.to_string()),
        ]),
    });

    Ok(cancelled)
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

/// Begin asynchronous execution: transition a Locked request to Executing and
/// mark the `execute` stage In-Progress, WITHOUT producing any simulated
/// evidence. Real execution is performed out-of-process by an execution agent
/// (terraform/ansible); the agent's signed result later completes the stage and
/// advances the request (the request -> agent_job bridge). Pure: no I/O, no
/// store. Use this instead of `execute_request` whenever a dispatch backend is
/// available; `execute_request` remains the in-process dry-run fallback.
pub fn begin_execution(request: &Request) -> Result<Request, String> {
    if request.status != RequestStatus::Locked {
        return Err(format!(
            "Cannot execute request in status {:?}. Request must be Locked first.",
            request.status
        ));
    }

    let mut executing = request.clone();
    executing.status = RequestStatus::Executing;
    executing.updated_at = Utc::now().to_rfc3339();

    if let Some(stage) = executing.stages.iter_mut().find(|s| s.name == "execute") {
        stage.status = StageStatus::InProgress;
        stage.started_at = Some(Utc::now().to_rfc3339());
        stage.completed_at = None;
        // Fresh execution attempt: drop any pre-seeded/simulated evidence so the
        // stage carries only the real evidence the agent will report.
        stage.evidence.clear();
    } else {
        executing.stages.push(Stage {
            name: "execute".into(),
            status: StageStatus::InProgress,
            started_at: Some(Utc::now().to_rfc3339()),
            completed_at: None,
            evidence: vec![],
            metadata: HashMap::new(),
        });
    }

    Ok(executing)
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

/// Produce the Protect-stage evidence for a `Completed` request (pure, dry-run).
/// Computes a backup-coverage summary for the delivered asset's site/environment.
/// Guards that the request is `Completed` and its `verify` stage finished; the
/// caller appends a completed `protect` stage with this evidence and transitions
/// the request to `Protecting`.
pub fn protect_request(request: &Request) -> Result<Vec<EvidenceItem>, String> {
    if request.status != RequestStatus::Completed {
        return Err(format!(
            "Cannot protect request in status {:?}. Request must be Completed first.",
            request.status
        ));
    }
    if !has_completed_stage(request, "verify") {
        return Err("Cannot protect a request without a completed verify stage.".into());
    }

    let report = crate::backup_engine::generate_backup_coverage_report(
        std::slice::from_ref(&request.site),
        std::slice::from_ref(&request.environment),
    )?;

    Ok(vec![EvidenceItem {
        key: "protection-policy-summary".into(),
        value: format!(
            "DRY-RUN: Backup coverage {:.1}% ({}/{} assets), {} critical gap(s) for site {} environment {}",
            report.coverage_percentage,
            report.covered_assets,
            report.total_assets,
            report.critical_gaps.len(),
            request.site,
            request.environment
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    }])
}

/// Produce the Publish-stage evidence for a `Protecting` request (pure, dry-run).
/// Imports the CI records and prepares the CMDB export representation. Guards that
/// the request is `Protecting` and its `protect` stage finished; the caller appends
/// a completed `publish` stage with this evidence and transitions to `Operational`.
pub fn publish_request(request: &Request) -> Result<Vec<EvidenceItem>, String> {
    if request.status != RequestStatus::Protecting {
        return Err(format!(
            "Cannot publish request in status {:?}. Request must be Protecting first.",
            request.status
        ));
    }
    if !has_completed_stage(request, "protect") {
        return Err("Cannot publish a request without a completed protect stage.".into());
    }

    let records = crate::cmdb_engine::import_cmdb_records("cmdb-excel-export")?;
    let export = crate::cmdb_engine::export_cmdb(&records, "json")?;

    Ok(vec![
        EvidenceItem {
            key: "publish-plan".into(),
            value: format!(
                "DRY-RUN: Publishing {} CI record(s) for request {} (site {}, environment {}) to the CMDB",
                records.len(),
                request.id,
                request.site,
                request.environment
            ),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::Summary,
        },
        EvidenceItem {
            key: "cmdb-export".into(),
            value: format!(
                "DRY-RUN: CMDB export prepared ({} records, json format, {} bytes)",
                records.len(),
                export.len()
            ),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::ExportPackage,
        },
    ])
}

/// Produce the Retire-stage evidence for an `Operational` request (pure,
/// dry-run). Computes a decommission plan (quarantine-first, rollback-capable)
/// for the delivered asset via the server_decommission engine. Guards that the
/// request is `Operational` and its `publish` stage finished; the caller appends
/// a completed `retire` stage with this evidence and transitions the request to
/// `Retired` (the governed end-of-life terminal).
pub fn retire_request(request: &Request) -> Result<Vec<EvidenceItem>, String> {
    if request.status != RequestStatus::Operational {
        return Err(format!(
            "Cannot retire request in status {:?}. Request must be Operational first.",
            request.status
        ));
    }
    if !has_completed_stage(request, "publish") {
        return Err("Cannot retire a request without a completed publish stage.".into());
    }

    let os_family = request
        .metadata
        .get("operating_system")
        .map(String::as_str)
        .unwrap_or("linux");
    let plan = crate::server_decommission::plan_decommission(
        &request.id,
        &request.site,
        os_family,
        ServerType::VM,
        "lifecycle retirement",
        true,
        30,
    )?;

    Ok(vec![EvidenceItem {
        key: "retirement-plan".into(),
        value: format!(
            "DRY-RUN: Retirement plan for request {} at site {} — {} dependency check(s), {}-day quarantine, final backup required",
            request.id,
            request.site,
            plan.dependencies_identified.len(),
            plan.quarantine_days,
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    }])
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
        // Post-completion governed lifecycle (Theme 8): operator-initiated.
        (RequestStatus::Completed, RequestStatus::Protecting),
        (RequestStatus::Protecting, RequestStatus::Operational),
        (RequestStatus::Operational, RequestStatus::Retired),
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
        (RequestStatus::Completed, RequestStatus::Protecting) => {
            require_completed_stage_for_transition(request, "verify", &new_status)?;
        }
        (RequestStatus::Protecting, RequestStatus::Operational) => {
            require_completed_stage_for_transition(request, "protect", &new_status)?;
        }
        (RequestStatus::Operational, RequestStatus::Retired) => {
            require_completed_stage_for_transition(request, "publish", &new_status)?;
        }
        _ => {}
    }

    let mut updated = request.clone();
    updated.status = new_status;
    updated.updated_at = Utc::now().to_rfc3339();

    Ok(updated)
}

pub fn fail_request(request: &Request, reason: &str) -> Result<Request, String> {
    // A request that has concluded — Completed, the post-completion lifecycle
    // (Protecting/Operational), or any terminal state — must not be failed.
    if request.status.is_concluded() {
        return Err("Cannot fail a request that has already concluded.".into());
    }

    let mut failed = request.clone();
    failed.status = RequestStatus::Failed;
    failed.updated_at = Utc::now().to_rfc3339();
    failed
        .metadata
        .insert("failure_reason".into(), reason.to_string());

    Ok(failed)
}

/// Send a request back to `Intake` for the requester to fix and re-submit — the
/// NON-terminal alternative to a `reject`. Valid only from the review/pre-exec
/// stages (Validated/Planned/Approved/Locked): a request still in Intake has
/// nothing to rework yet, and one already Executing/Verifying or concluded must
/// be `fail`ed or run its course, not bounced. Unlike reject there is no
/// separation-of-duties gate — rework concludes nothing (it returns to Intake),
/// so a reviewer bouncing their own request for more work is benign. Records the
/// reason in metadata. Pure: ryuki-api persists.
///
/// Prior derived artifacts (validation/plan/approval) are PRESERVED as history,
/// not cleared. The persistence boundary advances the request's approval epoch
/// atomically with this transition, so approval decisions from the prior plan
/// cannot satisfy the new cycle even though they remain available to auditors.
/// Reaching Approved again requires validate → plan → fresh current-epoch quorum.
pub fn rework_request(request: &Request, actor: &str, reason: &str) -> Result<Request, String> {
    if reason.trim().is_empty() {
        return Err("Rework reason cannot be empty".into());
    }
    if !matches!(
        request.status,
        RequestStatus::Validated
            | RequestStatus::Planned
            | RequestStatus::Approved
            | RequestStatus::Locked
    ) {
        return Err(format!(
            "Cannot rework a request in status {:?}. Rework is only valid from \
             Validated, Planned, Approved, or Locked.",
            request.status
        ));
    }

    let mut reworked = request.clone();
    reworked.status = RequestStatus::Intake;
    reworked.updated_at = Utc::now().to_rfc3339();
    reworked
        .metadata
        .insert("rework_reason".into(), reason.to_string());
    reworked
        .metadata
        .insert("reworked_by".into(), actor.to_string());

    Ok(reworked)
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
    fn test_validate_request_accepts_active_registered_custom_site() {
        let code = "TEST-REQUEST-SITE-01";
        let _ = site_registry::register_site(
            site_registry::SiteEntry {
                unlocode: code.into(),
                name: "Request lifecycle test site".into(),
                country: "Belgium".into(),
                country_code: "BE".into(),
                timezone: "Europe/Brussels".into(),
                active: true,
            },
            site_registry::SiteCodeSystem::Custom,
        );
        let mut req = create_request(
            "windows-server-deployment",
            RequestType::ServerDeployment,
            "alice",
            "bob",
            "test-request-site-01",
            "production",
            "critical",
        )
        .unwrap();
        req.approval_route.push("Datacenter Approver".into());
        assert_eq!(req.site, code);
        assert!(validate_request(&req).unwrap().passed);
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

    /// B1: validation may run only from Draft or Intake. A request already in a
    /// later (or terminal) status must be REFUSED with a non-passing
    /// ValidationResult tagged `invalid-from-status`, so it can never be rewound
    /// to "validated" by re-running validate.
    fn assert_validate_refused_from(status: RequestStatus) {
        let mut req = make_test_request();
        req.approval_route.push("Datacenter Approver".into());
        req.status = status.clone();
        let result = validate_request(&req).unwrap();
        assert!(
            !result.passed,
            "validate must refuse rewind from {:?}",
            status
        );
        assert!(
            result
                .failed_rules
                .iter()
                .any(|r| r == "invalid-from-status"),
            "failed_rule must be invalid-from-status for {:?}, got {:?}",
            status,
            result.failed_rules
        );
    }

    #[test]
    fn test_validate_request_refuses_rewind_from_validated() {
        assert_validate_refused_from(RequestStatus::Validated);
    }

    #[test]
    fn test_validate_request_refuses_rewind_from_planned() {
        assert_validate_refused_from(RequestStatus::Planned);
    }

    #[test]
    fn test_validate_request_refuses_rewind_from_approved() {
        assert_validate_refused_from(RequestStatus::Approved);
    }

    #[test]
    fn test_validate_request_refuses_rewind_from_locked() {
        assert_validate_refused_from(RequestStatus::Locked);
    }

    #[test]
    fn test_validate_request_refuses_rewind_from_executing() {
        assert_validate_refused_from(RequestStatus::Executing);
    }

    #[test]
    fn test_validate_request_refuses_rewind_from_verifying() {
        assert_validate_refused_from(RequestStatus::Verifying);
    }

    #[test]
    fn test_validate_request_allowed_from_draft() {
        let mut req = make_test_request();
        req.approval_route.push("Datacenter Approver".into());
        req.status = RequestStatus::Draft;
        // Draft is an allowed from-status: it passes the precondition and
        // reaches the field-level rules (which pass for a valid request).
        let result = validate_request(&req).unwrap();
        assert!(result.passed);
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
        // The approve stage that plan_request seeds (Pending) must be COMPLETED
        // and carry the approval decision + approver — not left Pending, and not
        // duplicated by a second pushed stage.
        let approve_stages: Vec<_> = result
            .stages
            .iter()
            .filter(|s| s.name == "approve")
            .collect();
        assert_eq!(approve_stages.len(), 1, "exactly one approve stage");
        let stage = approve_stages[0];
        assert_eq!(
            stage.status,
            StageStatus::Completed,
            "approve stage must be Completed"
        );
        assert_eq!(
            stage.metadata.get("approver").map(String::as_str),
            Some("Datacenter Approver"),
            "approver must be recorded on the stage"
        );
        assert!(
            stage
                .evidence
                .iter()
                .any(|e| e.value.contains("Approved by Datacenter Approver")),
            "the approval decision evidence must be on the stage"
        );
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
    fn test_begin_execution_dispatches_in_progress() {
        let req = make_planned_request();
        let approved = approve_request(&req, "Datacenter Approver").unwrap();
        let locked = lock_request(&approved).unwrap();
        let dispatched = begin_execution(&locked).unwrap();
        // Async dispatch: Executing with the execute stage In-Progress and NO
        // simulated evidence — the agent supplies the real evidence later.
        assert_eq!(dispatched.status, RequestStatus::Executing);
        let exec = dispatched
            .stages
            .iter()
            .find(|s| s.name == "execute")
            .expect("execute stage present");
        assert_eq!(exec.status, StageStatus::InProgress);
        assert!(exec.completed_at.is_none());
        assert!(
            exec.evidence.is_empty(),
            "begin_execution must not fabricate evidence"
        );
    }

    #[test]
    fn test_begin_execution_requires_locked() {
        // A Planned (not Locked) request cannot be dispatched.
        let req = make_planned_request();
        assert!(begin_execution(&req).is_err());
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
    fn test_rework_sends_back_to_intake_from_review_stages() {
        for from in [
            RequestStatus::Validated,
            RequestStatus::Planned,
            RequestStatus::Approved,
            RequestStatus::Locked,
        ] {
            let mut req = make_test_request();
            req.status = from.clone();
            let reworked = rework_request(&req, "carol", "missing change ticket").unwrap();
            assert_eq!(reworked.status, RequestStatus::Intake, "from {from:?}");
            assert_eq!(
                reworked.metadata.get("rework_reason").unwrap(),
                "missing change ticket"
            );
            assert_eq!(reworked.metadata.get("reworked_by").unwrap(), "carol");
        }
    }

    #[test]
    fn test_rework_rejects_invalid_states_and_empty_reason() {
        // Intake (nothing to rework yet), Executing (too late), and terminal
        // states cannot be reworked.
        for bad in [
            RequestStatus::Intake,
            RequestStatus::Executing,
            RequestStatus::Completed,
            RequestStatus::Rejected,
        ] {
            let mut req = make_test_request();
            req.status = bad.clone();
            assert!(rework_request(&req, "x", "reason").is_err(), "from {bad:?}");
        }
        // Empty reason is rejected even from a valid state.
        let mut req = make_test_request();
        req.status = RequestStatus::Planned;
        assert!(rework_request(&req, "x", "  ").is_err(), "empty reason");
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

    #[test]
    fn test_reject_request_from_planned_succeeds_and_is_terminal() {
        let req = make_planned_request();
        let rejected = reject_request(&req, "Datacenter Approver", "budget not approved").unwrap();
        assert_eq!(rejected.status, RequestStatus::Rejected);
        let approve_stage = rejected
            .stages
            .iter()
            .find(|s| s.name == "approve")
            .unwrap();
        assert_eq!(approve_stage.status, StageStatus::Failed);
        let decision = approve_stage
            .evidence
            .iter()
            .find(|e| e.key == "approval-decision")
            .unwrap();
        assert!(decision.value.contains("Rejected by Datacenter Approver"));
        assert!(decision.value.contains("budget not approved"));
        assert_eq!(decision.evidence_type, EvidenceType::ApprovalDecision);
        // Terminal: cannot validate/plan/approve a rejected request.
        let validation = validate_request(&rejected).unwrap();
        assert!(!validation.passed);
        assert!(reject_request(&rejected, "x", "again").is_err());
    }

    #[test]
    fn test_reject_request_from_intake_fails() {
        let req = make_test_request();
        assert_eq!(req.status, RequestStatus::Intake);
        let error = reject_request(&req, "Datacenter Approver", "no").unwrap_err();
        assert!(error.contains("approval decision point"));
    }

    #[test]
    fn test_reject_request_from_approved_fails() {
        let planned = make_planned_request();
        let approved = approve_request(&planned, "Datacenter Approver").unwrap();
        assert_eq!(approved.status, RequestStatus::Approved);
        assert!(reject_request(&approved, "Datacenter Approver", "too late").is_err());
    }

    #[test]
    fn test_reject_request_empty_reason_rejected() {
        let req = make_planned_request();
        assert!(reject_request(&req, "Datacenter Approver", "").is_err());
        assert!(reject_request(&req, "Datacenter Approver", "   ").is_err());
    }

    #[test]
    fn test_cancel_request_from_each_allowed_status_succeeds() {
        // Intake
        let intake = make_test_request();
        assert_eq!(
            cancel_request(&intake, "alice", "no longer needed")
                .unwrap()
                .status,
            RequestStatus::Cancelled
        );

        // Validated
        let validated = make_validated_request();
        assert_eq!(
            cancel_request(&validated, "alice", "scope changed")
                .unwrap()
                .status,
            RequestStatus::Cancelled
        );

        // Planned
        let planned = make_planned_request();
        let cancelled = cancel_request(&planned, "alice", "duplicate").unwrap();
        assert_eq!(cancelled.status, RequestStatus::Cancelled);
        let cancel_stage = cancelled
            .stages
            .iter()
            .find(|s| s.name == "cancel")
            .unwrap();
        assert_eq!(cancel_stage.status, StageStatus::Completed);
        assert!(
            cancel_stage
                .evidence
                .iter()
                .any(|e| e.value.contains("Cancelled by alice") && e.value.contains("duplicate"))
        );

        // Approved
        let approved = approve_request(&make_planned_request(), "Datacenter Approver").unwrap();
        assert_eq!(
            cancel_request(&approved, "alice", "withdrawn")
                .unwrap()
                .status,
            RequestStatus::Cancelled
        );

        // Locked
        let locked = lock_request(&approved).unwrap();
        assert_eq!(
            cancel_request(&locked, "alice", "withdrawn")
                .unwrap()
                .status,
            RequestStatus::Cancelled
        );

        // Draft
        let mut draft = make_test_request();
        draft.status = RequestStatus::Draft;
        assert_eq!(
            cancel_request(&draft, "alice", "abandoned").unwrap().status,
            RequestStatus::Cancelled
        );
    }

    #[test]
    fn test_cancel_request_from_executing_fails() {
        let approved = approve_request(&make_planned_request(), "Datacenter Approver").unwrap();
        let locked = lock_request(&approved).unwrap();
        let executing = execute_request(&locked).unwrap();
        // execute_request leaves the request in Verifying; force Executing too.
        let mut executing_state = executing.clone();
        executing_state.status = RequestStatus::Executing;
        assert!(cancel_request(&executing_state, "alice", "stop").is_err());
        assert!(cancel_request(&executing, "alice", "stop").is_err());
    }

    #[test]
    fn test_cancel_request_empty_reason_rejected() {
        let req = make_test_request();
        assert!(cancel_request(&req, "alice", "").is_err());
        assert!(cancel_request(&req, "alice", "   ").is_err());
    }

    // ── Post-completion lifecycle (Theme 8): protect / publish ───────────────

    fn completed_stage(name: &str) -> Stage {
        Stage {
            name: name.into(),
            status: StageStatus::Completed,
            started_at: None,
            completed_at: None,
            evidence: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    fn pending_stage(name: &str) -> Stage {
        Stage {
            name: name.into(),
            status: StageStatus::Pending,
            started_at: None,
            completed_at: None,
            evidence: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// A request that has reached `Completed` with a finished `verify` stage and
    /// the pending protect/publish stages `plan_request` seeds. Site DEFRA is a
    /// VALID_SITE so the backup-coverage report succeeds.
    fn make_completed_request() -> Request {
        let mut req = make_test_request();
        req.status = RequestStatus::Completed;
        req.stages = vec![
            completed_stage("verify"),
            pending_stage("protect"),
            pending_stage("publish"),
        ];
        req
    }

    #[test]
    fn test_protect_request_produces_backup_evidence() {
        let req = make_completed_request();
        let evidence =
            protect_request(&req).expect("protect should succeed for a completed request");
        assert!(
            evidence
                .iter()
                .any(|e| e.key == "protection-policy-summary")
        );
        assert!(evidence[0].value.contains("Backup coverage"));
    }

    #[test]
    fn test_protect_request_rejects_non_completed() {
        let mut req = make_completed_request();
        req.status = RequestStatus::Verifying;
        assert!(protect_request(&req).is_err());
    }

    #[test]
    fn test_protect_request_requires_completed_verify_stage() {
        let mut req = make_completed_request();
        req.stages = vec![pending_stage("protect")]; // no completed verify
        assert!(protect_request(&req).is_err());
    }

    #[test]
    fn test_publish_request_produces_cmdb_evidence() {
        let mut req = make_completed_request();
        req.status = RequestStatus::Protecting;
        req.stages = vec![
            completed_stage("verify"),
            completed_stage("protect"),
            pending_stage("publish"),
        ];
        let evidence =
            publish_request(&req).expect("publish should succeed for a protecting request");
        assert!(evidence.iter().any(|e| e.key == "publish-plan"));
        assert!(evidence.iter().any(|e| e.key == "cmdb-export"));
    }

    #[test]
    fn test_publish_request_rejects_non_protecting() {
        let req = make_completed_request(); // status Completed, not Protecting
        assert!(publish_request(&req).is_err());
    }

    #[test]
    fn test_publish_request_requires_completed_protect_stage() {
        let mut req = make_completed_request();
        req.status = RequestStatus::Protecting; // protect stage still pending
        assert!(publish_request(&req).is_err());
    }

    #[test]
    fn test_transition_completed_to_protecting_then_operational() {
        let req = make_completed_request();
        let protecting = transition_status(&req, RequestStatus::Protecting)
            .expect("Completed -> Protecting with a completed verify stage");
        assert_eq!(protecting.status, RequestStatus::Protecting);

        let mut ready = protecting.clone();
        ready.stages = vec![completed_stage("verify"), completed_stage("protect")];
        let operational = transition_status(&ready, RequestStatus::Operational)
            .expect("Protecting -> Operational with a completed protect stage");
        assert_eq!(operational.status, RequestStatus::Operational);
    }

    #[test]
    fn test_transition_protecting_to_operational_requires_protect_stage() {
        let mut req = make_completed_request();
        req.status = RequestStatus::Protecting; // protect not completed
        assert!(transition_status(&req, RequestStatus::Operational).is_err());
    }

    #[test]
    fn test_transition_completed_to_protecting_requires_verify_stage() {
        let mut req = make_completed_request();
        req.stages = vec![pending_stage("protect")]; // no completed verify
        assert!(transition_status(&req, RequestStatus::Protecting).is_err());
    }

    #[test]
    fn test_is_concluded_classification() {
        for s in [
            RequestStatus::Draft,
            RequestStatus::Intake,
            RequestStatus::Validated,
            RequestStatus::Planned,
            RequestStatus::Approved,
            RequestStatus::Locked,
            RequestStatus::Executing,
            RequestStatus::Verifying,
        ] {
            assert!(!s.is_concluded(), "{s:?} is active, not concluded");
        }
        for s in [
            RequestStatus::Completed,
            RequestStatus::Protecting,
            RequestStatus::Operational,
            RequestStatus::Retired,
            RequestStatus::Failed,
            RequestStatus::Rejected,
            RequestStatus::Cancelled,
        ] {
            assert!(s.is_concluded(), "{s:?} has concluded");
        }
    }

    #[test]
    fn test_fail_request_refuses_concluded_states() {
        for s in [
            RequestStatus::Completed,
            RequestStatus::Protecting,
            RequestStatus::Operational,
            RequestStatus::Retired,
        ] {
            let mut req = make_completed_request();
            req.status = s.clone();
            assert!(fail_request(&req, "x").is_err(), "{s:?} must be unfailable");
        }
        // An active (not yet concluded) request remains failable.
        let mut active = make_completed_request();
        active.status = RequestStatus::Executing;
        assert!(fail_request(&active, "boom").is_ok());
    }

    // ── Retire stage (Theme 8 slice 2) ───────────────────────────────────────

    /// An Operational request with the protect+publish stages finished — the
    /// state from which Retire is valid.
    fn make_operational_request() -> Request {
        let mut req = make_completed_request();
        req.status = RequestStatus::Operational;
        req.stages = vec![
            completed_stage("verify"),
            completed_stage("protect"),
            completed_stage("publish"),
        ];
        req
    }

    #[test]
    fn test_retire_request_produces_decommission_evidence() {
        let req = make_operational_request();
        let evidence =
            retire_request(&req).expect("retire should succeed for an operational request");
        assert!(evidence.iter().any(|e| e.key == "retirement-plan"));
        assert!(evidence[0].value.contains("quarantine"));
    }

    #[test]
    fn test_retire_request_rejects_non_operational() {
        let req = make_completed_request(); // Completed, not Operational
        assert!(retire_request(&req).is_err());
    }

    #[test]
    fn test_retire_request_requires_completed_publish_stage() {
        let mut req = make_operational_request();
        req.stages = vec![completed_stage("verify"), completed_stage("protect")]; // no publish
        assert!(retire_request(&req).is_err());
    }

    #[test]
    fn test_transition_operational_to_retired() {
        let req = make_operational_request();
        let retired = transition_status(&req, RequestStatus::Retired)
            .expect("Operational -> Retired with a completed publish stage");
        assert_eq!(retired.status, RequestStatus::Retired);
    }

    #[test]
    fn test_transition_operational_to_retired_requires_publish_stage() {
        let mut req = make_operational_request();
        req.stages = vec![completed_stage("verify"), completed_stage("protect")]; // no publish
        assert!(transition_status(&req, RequestStatus::Retired).is_err());
    }
}
