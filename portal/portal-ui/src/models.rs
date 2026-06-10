use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub id: String,
    pub decision: String,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyGuardrailSummary {
    pub guardrail: String,
    pub enforcement_state: String,
    pub aggregate_scope: String,
    pub execution_allowed: bool,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EvidenceSummary {
    pub state: String,
    pub redaction_required: bool,
    pub export_allowed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct OperationRunSummary {
    pub state: String,
    pub dry_run: bool,
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretReferenceCatalogStatus {
    pub source: String,
    pub primary_provider: String,
    pub management_cli: String,
    pub future_providers: Vec<String>,
    pub reference_kinds: Vec<String>,
    pub readiness_states: Vec<String>,
    pub rotation_policies: Vec<String>,
    pub configured_for_production: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SecretReferenceSummary {
    pub provider: String,
    pub management_cli: String,
    pub readiness_state: String,
    pub rotation_state: String,
    pub consumer_scope: String,
    pub live_cli_execution_allowed: bool,
    pub value_exposure_allowed: bool,
    pub provider_path_exposure_allowed: bool,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CmdbFileExchangeSummary {
    pub exchange: String,
    pub mapping_state: String,
    pub validation_state: String,
    pub evidence_state: String,
    pub file_import_execution_allowed: bool,
    pub file_export_execution_allowed: bool,
    pub live_api_allowed: bool,
    pub raw_cmdb_rows_allowed: bool,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CmdbReconciliationSummary {
    pub scope: String,
    pub reconciliation_state: String,
    pub review_state: String,
    pub evidence_state: String,
    pub cmdb_mutation_allowed: bool,
    pub raw_cmdb_rows_allowed: bool,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CmdbRelationshipSummary {
    pub graph_scope: String,
    pub relationship_state: String,
    pub dependency_quality_state: String,
    pub evidence_state: String,
    pub relationship_mutation_allowed: bool,
    pub raw_relationship_rows_allowed: bool,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ActivityQueueSummary {
    pub queue: String,
    pub queue_state: String,
    pub lock_state: String,
    pub retry_state: String,
    pub blocked_reason: String,
    pub handover_state: String,
    pub worker_execution_allowed: bool,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequestIntakeSummary {
    pub stage: String,
    pub validation_state: String,
    pub approval_state: String,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DryRunPlanSummary {
    pub workflow: String,
    pub dry_run: bool,
    pub execution_allowed: bool,
    pub required_gate: String,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct InventoryResourceSummary {
    pub view: String,
    pub freshness_state: String,
    pub coverage_state: String,
    pub evidence_state: String,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CapacityAdmissionSummary {
    pub scope: String,
    pub admission_state: String,
    pub headroom_state: String,
    pub execution_allowed: bool,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CatalogContractSummary {
    pub category: String,
    pub readiness_state: String,
    pub request_form_state: String,
    pub recommendation_state: String,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CatalogReadinessSummary {
    pub surface: String,
    pub readiness_state: String,
    pub site_binding_state: String,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuditWorkflowSummary {
    pub workflow: String,
    pub approval_state: String,
    pub queue_state: String,
    pub evidence_state: String,
    pub execution_allowed: bool,
    pub safe_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuditGateSummary {
    pub gate: String,
    pub readiness_state: String,
    pub emergency_state: String,
    pub handover_state: String,
    pub safe_summary: String,
}

pub fn request_intake_fallbacks() -> Vec<RequestIntakeSummary> {
    vec![
        RequestIntakeSummary {
            stage: "draft intake".to_string(),
            validation_state: "preflight required".to_string(),
            approval_state: "approval blocked".to_string(),
            safe_summary: "Required fields and policy checks must pass before approval."
                .to_string(),
        },
        RequestIntakeSummary {
            stage: "ready for review".to_string(),
            validation_state: "safe summary only".to_string(),
            approval_state: "separation check pending".to_string(),
            safe_summary:
                "Request status stays static until catalog, policy, and evidence gates pass."
                    .to_string(),
        },
    ]
}

pub fn dry_run_plan_fallbacks() -> Vec<DryRunPlanSummary> {
    vec![
        DryRunPlanSummary {
            workflow: "server lifecycle".to_string(),
            dry_run: true,
            execution_allowed: false,
            required_gate: "approval-lock-evidence".to_string(),
            safe_summary:
                "Provider-safe plan remains review-only until approval, lock, and evidence gates pass."
                    .to_string(),
        },
        DryRunPlanSummary {
            workflow: "controlled restore".to_string(),
            dry_run: true,
            execution_allowed: false,
            required_gate: "target-validation-redaction".to_string(),
            safe_summary: "Restore planning is blocked until target validation and redaction complete."
                .to_string(),
        },
    ]
}

pub fn inventory_resource_fallbacks() -> Vec<InventoryResourceSummary> {
    vec![
        InventoryResourceSummary {
            view: "site summary".to_string(),
            freshness_state: "stale marker review".to_string(),
            coverage_state: "coverage gaps present".to_string(),
            evidence_state: "evidence redacted".to_string(),
            safe_summary:
                "Aggregate inventory stays read-only until freshness, coverage, and CMDB review pass."
                    .to_string(),
        },
        InventoryResourceSummary {
            view: "protection and observability".to_string(),
            freshness_state: "current".to_string(),
            coverage_state: "coverage review".to_string(),
            evidence_state: "evidence redacted".to_string(),
            safe_summary:
                "Backup, monitoring, and ownership state are shown as safe summary categories."
                    .to_string(),
        },
    ]
}

pub fn capacity_admission_fallbacks() -> Vec<CapacityAdmissionSummary> {
    vec![
        CapacityAdmissionSummary {
            scope: "virtualization capacity".to_string(),
            admission_state: "blocked".to_string(),
            headroom_state: "headroom review required".to_string(),
            execution_allowed: false,
            safe_summary:
                "Capacity admission remains blocked until HA, storage, and reservation summaries pass."
                    .to_string(),
        },
        CapacityAdmissionSummary {
            scope: "repository capacity".to_string(),
            admission_state: "blocked".to_string(),
            headroom_state: "runway review required".to_string(),
            execution_allowed: false,
            safe_summary:
                "Backup repository runway must be reviewed before dependent workflow approval."
                    .to_string(),
        },
    ]
}

pub fn catalog_contract_fallbacks() -> Vec<CatalogContractSummary> {
    vec![
        CatalogContractSummary {
            category: "Build Maintain Protect".to_string(),
            readiness_state: "static catalog source".to_string(),
            request_form_state: "request forms aligned".to_string(),
            recommendation_state: "recommendations review-only".to_string(),
            safe_summary:
                "Catalog offerings stay tied to static request forms, approvals, and evidence gates."
                    .to_string(),
        },
        CatalogContractSummary {
            category: "Observe Operate Retire".to_string(),
            readiness_state: "static catalog source".to_string(),
            request_form_state: "workflow binding review".to_string(),
            recommendation_state: "role summaries only".to_string(),
            safe_summary:
                "Offering recommendations use aggregate role, application, and site summaries only."
                    .to_string(),
        },
    ]
}

pub fn catalog_readiness_fallbacks() -> Vec<CatalogReadinessSummary> {
    vec![
        CatalogReadinessSummary {
            surface: "site catalog".to_string(),
            readiness_state: "review required".to_string(),
            site_binding_state: "site bindings static".to_string(),
            safe_summary:
                "Site catalog readiness is static until placement and policy bindings pass review."
                    .to_string(),
        },
        CatalogReadinessSummary {
            surface: "policy metadata".to_string(),
            readiness_state: "review required".to_string(),
            site_binding_state: "policy bindings static".to_string(),
            safe_summary:
                "Policy and approval metadata remain safe summaries for request preflight."
                    .to_string(),
        },
    ]
}

pub fn audit_workflow_fallbacks() -> Vec<AuditWorkflowSummary> {
    vec![
        AuditWorkflowSummary {
            workflow: "approval readiness".to_string(),
            approval_state: "decision review required".to_string(),
            queue_state: "activity queue static".to_string(),
            evidence_state: "redacted evidence required".to_string(),
            execution_allowed: false,
            safe_summary:
                "Approval decisions stay review-only until route, authority, and evidence gates pass."
                    .to_string(),
        },
        AuditWorkflowSummary {
            workflow: "activity handover".to_string(),
            approval_state: "approval pending".to_string(),
            queue_state: "handover queue static".to_string(),
            evidence_state: "evidence references only".to_string(),
            execution_allowed: false,
            safe_summary:
                "Queued work is shown as safe summaries with locks, retries, blockers, and handover notes."
                    .to_string(),
        },
    ]
}

pub fn audit_gate_fallbacks() -> Vec<AuditGateSummary> {
    vec![
        AuditGateSummary {
            gate: "Activity queue".to_string(),
            readiness_state: "read-only".to_string(),
            emergency_state: "Emergency changes gated".to_string(),
            handover_state: "Shift handover ready".to_string(),
            safe_summary:
                "Activity, emergency, and shift views do not mutate decisions, queues, or workflows."
                    .to_string(),
        },
        AuditGateSummary {
            gate: "Approval gates".to_string(),
            readiness_state: "blocked".to_string(),
            emergency_state: "break-glass review".to_string(),
            handover_state: "audit notes required".to_string(),
            safe_summary:
                "Emergency handling remains blocked until approval, lock, verification, and audit evidence pass."
                    .to_string(),
        },
    ]
}

pub fn activity_queue_fallbacks() -> Vec<ActivityQueueSummary> {
    vec![
        ActivityQueueSummary {
            queue: "operation queue".to_string(),
            queue_state: "blocked".to_string(),
            lock_state: "lock review required".to_string(),
            retry_state: "retry disabled".to_string(),
            blocked_reason: "Approval, lock, and evidence gates are required before work can move."
                .to_string(),
            handover_state: "handover note required".to_string(),
            worker_execution_allowed: false,
            safe_summary:
                "Queued operations are shown as static safe summaries without worker execution."
                    .to_string(),
        },
        ActivityQueueSummary {
            queue: "child operations".to_string(),
            queue_state: "read-only".to_string(),
            lock_state: "parent lock pending".to_string(),
            retry_state: "retry plan blocked".to_string(),
            blocked_reason:
                "Child operation state remains read-only until parent run gates are satisfied."
                    .to_string(),
            handover_state: "shift handover ready".to_string(),
            worker_execution_allowed: false,
            safe_summary:
                "Child operation progress is summarized without raw logs or provider payloads."
                    .to_string(),
        },
    ]
}

pub fn secret_reference_catalog_fallback() -> SecretReferenceCatalogStatus {
    SecretReferenceCatalogStatus {
        source: "static-seed".to_string(),
        primary_provider: "vaultwarden".to_string(),
        management_cli: "vaultwarden-cli".to_string(),
        future_providers: Vec::new(),
        reference_kinds: vec![
            "adapter-credential".to_string(),
            "worker-credential".to_string(),
            "database-credential".to_string(),
            "object-storage-credential".to_string(),
            "pki-material".to_string(),
        ],
        readiness_states: vec![
            "missing".to_string(),
            "pending-approval".to_string(),
            "configured".to_string(),
            "rotation-due".to_string(),
            "blocked".to_string(),
        ],
        rotation_policies: vec![
            "deployment-managed".to_string(),
            "scheduled-rotation".to_string(),
            "emergency-rotation".to_string(),
            "manual-break-glass-review".to_string(),
        ],
        configured_for_production: false,
    }
}

pub fn secret_reference_fallbacks() -> Vec<SecretReferenceSummary> {
    vec![
        SecretReferenceSummary {
            provider: "vaultwarden".to_string(),
            management_cli: "vaultwarden-cli".to_string(),
            readiness_state: "pending-approval".to_string(),
            rotation_state: "rotation review required".to_string(),
            consumer_scope: "adapter and worker references".to_string(),
            live_cli_execution_allowed: false,
            value_exposure_allowed: false,
            provider_path_exposure_allowed: false,
            safe_summary:
                "Reference readiness is shown as catalog metadata only; automation remains disabled."
                    .to_string(),
        },
        SecretReferenceSummary {
            provider: "vaultwarden".to_string(),
            management_cli: "vaultwarden-cli".to_string(),
            readiness_state: "blocked".to_string(),
            rotation_state: "break-glass review required".to_string(),
            consumer_scope: "recovery and signing references".to_string(),
            live_cli_execution_allowed: false,
            value_exposure_allowed: false,
            provider_path_exposure_allowed: false,
            safe_summary:
                "Sensitive material stays runtime-resolved and never appears in the portal."
                    .to_string(),
        },
    ]
}

pub fn cmdb_file_exchange_fallbacks() -> Vec<CmdbFileExchangeSummary> {
    vec![
        CmdbFileExchangeSummary {
            exchange: "import preview".to_string(),
            mapping_state: "mapping review required".to_string(),
            validation_state: "validation blocked".to_string(),
            evidence_state: "redacted evidence required".to_string(),
            file_import_execution_allowed: false,
            file_export_execution_allowed: false,
            live_api_allowed: false,
            raw_cmdb_rows_allowed: false,
            safe_summary:
                "CMDB file import stays preview-only until mapping, validation, and evidence gates pass."
                    .to_string(),
        },
        CmdbFileExchangeSummary {
            exchange: "update export".to_string(),
            mapping_state: "reviewer approval required".to_string(),
            validation_state: "export package blocked".to_string(),
            evidence_state: "redacted references only".to_string(),
            file_import_execution_allowed: false,
            file_export_execution_allowed: false,
            live_api_allowed: false,
            raw_cmdb_rows_allowed: false,
            safe_summary:
                "CMDB update packages remain static summaries until reviewer approval is recorded."
                    .to_string(),
        },
    ]
}

pub fn cmdb_reconciliation_fallbacks() -> Vec<CmdbReconciliationSummary> {
    vec![
        CmdbReconciliationSummary {
            scope: "identity reconciliation".to_string(),
            reconciliation_state: "drift review required".to_string(),
            review_state: "accepted and rejected counts only".to_string(),
            evidence_state: "evidence redacted".to_string(),
            cmdb_mutation_allowed: false,
            raw_cmdb_rows_allowed: false,
            safe_summary:
                "Infrastructure CI reconciliation uses deterministic safe references without live CMDB mutation."
                    .to_string(),
        },
        CmdbReconciliationSummary {
            scope: "ownership and placement".to_string(),
            reconciliation_state: "review blocked".to_string(),
            review_state: "owner-domain summary only".to_string(),
            evidence_state: "export evidence pending".to_string(),
            cmdb_mutation_allowed: false,
            raw_cmdb_rows_allowed: false,
            safe_summary:
                "Ownership and placement drift routes to review before any update package can be accepted."
                    .to_string(),
        },
    ]
}

pub fn cmdb_relationship_fallbacks() -> Vec<CmdbRelationshipSummary> {
    vec![
        CmdbRelationshipSummary {
            graph_scope: "application dependency graph".to_string(),
            relationship_state: "relationship review required".to_string(),
            dependency_quality_state: "aggregate quality signal".to_string(),
            evidence_state: "relationship evidence redacted".to_string(),
            relationship_mutation_allowed: false,
            raw_relationship_rows_allowed: false,
            safe_summary:
                "Application, environment, workload, network, backup, and monitoring links stay review-only."
                    .to_string(),
        },
        CmdbRelationshipSummary {
            graph_scope: "incident context".to_string(),
            relationship_state: "read-only impact context".to_string(),
            dependency_quality_state: "safe next-action summary".to_string(),
            evidence_state: "context evidence redacted".to_string(),
            relationship_mutation_allowed: false,
            raw_relationship_rows_allowed: false,
            safe_summary:
                "Incident context shows aggregate dependency signals without raw relationship rows."
                    .to_string(),
        },
    ]
}

pub fn policy_outcome_fallbacks() -> Vec<PolicyOutcome> {
    vec![
        PolicyOutcome {
            id: "approval-route-ready".to_string(),
            decision: "block".to_string(),
            safe_summary:
                "Approval route and separation-of-duties checks must pass before execution."
                    .to_string(),
        },
        PolicyOutcome {
            id: "provider-safe-plan".to_string(),
            decision: "block".to_string(),
            safe_summary: "Dry-run execution planning is required before any provider-side action."
                .to_string(),
        },
    ]
}

pub fn policy_guardrail_fallbacks() -> Vec<PolicyGuardrailSummary> {
    vec![
        PolicyGuardrailSummary {
            guardrail: "request preflight".to_string(),
            enforcement_state: "blocking".to_string(),
            aggregate_scope: "required fields, owner, site, capacity, backup, and monitoring"
                .to_string(),
            execution_allowed: false,
            safe_summary:
                "Policy preflight stays server-side and blocks approval until aggregate gates pass."
                    .to_string(),
        },
        PolicyGuardrailSummary {
            guardrail: "provider action boundary".to_string(),
            enforcement_state: "dry-run only".to_string(),
            aggregate_scope: "approval, evidence, rollback, and execution readiness".to_string(),
            execution_allowed: false,
            safe_summary:
                "Provider actions remain disabled; only aggregate guardrail status is exposed."
                    .to_string(),
        },
    ]
}

pub fn evidence_summary_fallbacks() -> Vec<EvidenceSummary> {
    vec![
        EvidenceSummary {
            state: "redacted".to_string(),
            redaction_required: true,
            export_allowed: false,
        },
        EvidenceSummary {
            state: "manifest pending".to_string(),
            redaction_required: true,
            export_allowed: false,
        },
    ]
}

pub fn operation_run_fallbacks() -> Vec<OperationRunSummary> {
    vec![
        OperationRunSummary {
            state: "blocked".to_string(),
            dry_run: true,
            blocked_reason: Some(
                "Approval, lock, and evidence gates are still required.".to_string(),
            ),
        },
        OperationRunSummary {
            state: "planned".to_string(),
            dry_run: true,
            blocked_reason: Some(
                "Execution remains disabled in the static portal shell.".to_string(),
            ),
        },
    ]
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlatformHealth {
    pub overall_status: String,
    pub components: Vec<String>,
    pub checks: Vec<HealthCheck>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct HealthCheck {
    pub name: String,
    pub component: String,
    pub status: String,
    pub last_check: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BoundaryStatusSnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub http_request_allowed: bool,
    pub provider_calls_allowed: bool,
    pub live_execution_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthSession {
    pub user_id: String,
    pub display_name: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LoginResponse {
    pub session_id: String,
    pub user_id: String,
    pub display_name: String,
    pub email: String,
    pub roles: Vec<String>,
    pub success: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlatformStatus {
    pub api_status: String,
    pub portal_status: String,
    pub validator_status: String,
    pub boundary_mode: String,
}

pub fn platform_status_fallback() -> PlatformStatus {
    PlatformStatus {
        api_status: "healthy".to_string(),
        portal_status: "healthy".to_string(),
        validator_status: "passing".to_string(),
        boundary_mode: "static-dry-run".to_string(),
    }
}

pub fn platform_health_fallback() -> PlatformHealth {
    PlatformHealth {
        overall_status: "healthy".to_string(),
        components: vec![
            "portal".to_string(),
            "api".to_string(),
            "engine".to_string(),
            "validator".to_string(),
            "queue".to_string(),
            "database".to_string(),
            "ingress".to_string(),
        ],
        checks: health_check_fallbacks(),
        timestamp: "2025-01-01T00:00:00Z".to_string(),
    }
}

pub fn health_check_fallbacks() -> Vec<HealthCheck> {
    vec![
        HealthCheck {
            name: "portal-up".to_string(),
            component: "portal".to_string(),
            status: "healthy".to_string(),
            last_check: "2025-01-01T00:00:00Z".to_string(),
            message: "Portal serving static shell".to_string(),
        },
        HealthCheck {
            name: "api-gateway".to_string(),
            component: "api".to_string(),
            status: "healthy".to_string(),
            last_check: "2025-01-01T00:00:00Z".to_string(),
            message: "API gateway responding".to_string(),
        },
        HealthCheck {
            name: "engine-worker".to_string(),
            component: "engine".to_string(),
            status: "healthy".to_string(),
            last_check: "2025-01-01T00:00:00Z".to_string(),
            message: "Engine worker pool idle (dry-run)".to_string(),
        },
        HealthCheck {
            name: "validator-suite".to_string(),
            component: "validator".to_string(),
            status: "healthy".to_string(),
            last_check: "2025-01-01T00:00:00Z".to_string(),
            message: "Validator suite passing".to_string(),
        },
        HealthCheck {
            name: "queue-connectivity".to_string(),
            component: "queue".to_string(),
            status: "warning".to_string(),
            last_check: "2025-01-01T00:00:00Z".to_string(),
            message: "Queue connectivity check blocked (dry-run)".to_string(),
        },
        HealthCheck {
            name: "database-ping".to_string(),
            component: "database".to_string(),
            status: "warning".to_string(),
            last_check: "2025-01-01T00:00:00Z".to_string(),
            message: "Database ping blocked (dry-run)".to_string(),
        },
        HealthCheck {
            name: "ingress-tls".to_string(),
            component: "ingress".to_string(),
            status: "healthy".to_string(),
            last_check: "2025-01-01T00:00:00Z".to_string(),
            message: "TLS certificate check passing".to_string(),
        },
    ]
}

pub fn boundary_status_snapshot_fallback() -> BoundaryStatusSnapshot {
    BoundaryStatusSnapshot {
        api_boundary: "same-origin-platform-api".to_string(),
        execution_mode: "static-dry-run".to_string(),
        http_request_allowed: false,
        provider_calls_allowed: false,
        live_execution_allowed: false,
        raw_payload_allowed: false,
        secret_values_allowed: false,
        customer_identifiers_allowed: false,
    }
}

pub fn auth_session_fallback() -> AuthSession {
    AuthSession {
        user_id: "platform-engineer".to_string(),
        display_name: "Platform Engineer".to_string(),
        roles: vec!["PlatformAdmin".to_string()],
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RbacRoleSummary {
    pub name: String,
    pub description: String,
    pub note: String,
}

pub fn rbac_role_summary_fallbacks() -> Vec<RbacRoleSummary> {
    vec![
        RbacRoleSummary {
            name: "PlatformAdmin".to_string(),
            description:
                "Platform Admins — full platform administration, approval, and audit access"
                    .to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "DatacenterApprover".to_string(),
            description: "Approvers — datacenter-level approval and audit".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "VMwareOperator".to_string(),
            description: "VMware Operators — virtualization execution and audit".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "HyperVOperator".to_string(),
            description: "Hyper-V Operators — virtualization execution and audit".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "ProxmoxOperator".to_string(),
            description: "Proxmox Operators — virtualization execution and audit".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "WintelLinuxOperator".to_string(),
            description: "Wintel/Linux Operators — OS execution and audit".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "BackupOperator".to_string(),
            description: "Backup Operators — backup execution and audit".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "MonitoringOperator".to_string(),
            description: "Monitoring Operators — monitoring execution and audit".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "ServiceDesk".to_string(),
            description: "Service Desk — triage, request, and audit access".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "Auditor".to_string(),
            description: "Auditor — read-only audit access".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "Requester".to_string(),
            description: "Requester — request-only access".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
        RbacRoleSummary {
            name: "BreakGlassAdmin".to_string(),
            description: "Break-Glass — emergency administration and audit".to_string(),
            note: "Defined in Entra ID → App Registrations → App Roles".to_string(),
        },
    ]
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlatformSettingsSummary {
    pub entra_tenant_id: String,
    pub entra_client_id: String,
    pub entra_authority: String,
    pub auth_mode: String,
    pub database_provider: String,
}

pub fn platform_settings_summary_fallback() -> PlatformSettingsSummary {
    PlatformSettingsSummary {
        entra_tenant_id: String::new(),
        entra_client_id: String::new(),
        entra_authority: "https://login.microsoftonline.com".to_string(),
        auth_mode: "mock-dry-run".to_string(),
        database_provider: "cloudnativepg".to_string(),
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct SafeSummary {
    pub label: &'static str,
    pub value: &'static str,
    pub detail: &'static str,
    pub state: SummaryState,
    pub redaction_state: &'static str,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum SummaryState {
    Healthy,
    Warning,
    Failed,
    Stale,
    Neutral,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequestFormField {
    pub label: String,
    pub field_type: String,
    pub required: bool,
    pub options: Vec<String>,
    pub placeholder: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequestIntakeForm {
    pub title: String,
    pub description: String,
    pub fields: Vec<RequestFormField>,
}

pub fn request_intake_form_fallback() -> RequestIntakeForm {
    RequestIntakeForm {
        title: "Request Intake".to_string(),
        description: "Review-only preview — submission available in next release".to_string(),
        fields: vec![
            RequestFormField {
                label: "Request type".to_string(),
                field_type: "select".to_string(),
                required: true,
                options: vec![
                    "VM".to_string(),
                    "Application".to_string(),
                    "SQL".to_string(),
                    "Network".to_string(),
                    "Storage".to_string(),
                ],
                placeholder: "Select request type".to_string(),
            },
            RequestFormField {
                label: "Site".to_string(),
                field_type: "select".to_string(),
                required: true,
                options: vec!["site-alpha".to_string(), "site-bravo".to_string()],
                placeholder: "Select site".to_string(),
            },
            RequestFormField {
                label: "Environment".to_string(),
                field_type: "select".to_string(),
                required: true,
                options: vec![
                    "dev".to_string(),
                    "test".to_string(),
                    "staging".to_string(),
                    "prod".to_string(),
                ],
                placeholder: "Select environment".to_string(),
            },
            RequestFormField {
                label: "Server name".to_string(),
                field_type: "text".to_string(),
                required: true,
                options: vec![],
                placeholder: "e.g. srv-app-01".to_string(),
            },
            RequestFormField {
                label: "CPU cores".to_string(),
                field_type: "number".to_string(),
                required: true,
                options: vec![],
                placeholder: "e.g. 4".to_string(),
            },
            RequestFormField {
                label: "Memory GB".to_string(),
                field_type: "number".to_string(),
                required: true,
                options: vec![],
                placeholder: "e.g. 16".to_string(),
            },
            RequestFormField {
                label: "Business justification".to_string(),
                field_type: "text".to_string(),
                required: true,
                options: vec![],
                placeholder: "Brief business justification for this request".to_string(),
            },
        ],
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequestSummary {
    pub id: String,
    pub request_type: String,
    pub name: String,
    pub site: String,
    pub environment: String,
    pub status: String,
    pub stage: String,
    pub created: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequestDetail {
    pub id: String,
    pub request_type: String,
    pub name: String,
    pub site: String,
    pub environment: String,
    pub cpu: u32,
    pub memory: u32,
    pub justification: String,
    pub status: String,
    pub stage: String,
    pub created: String,
    pub updated: String,
    pub timeline: Vec<StageEvent>,
    pub actions_available: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StageEvent {
    pub stage: String,
    pub timestamp: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CreateRequestPayload {
    pub request_type: String,
    pub name: String,
    pub site: String,
    pub environment: String,
    pub cpu: u32,
    pub memory: u32,
    pub justification: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StageActionResponse {
    pub request_id: String,
    pub success: bool,
    pub new_stage: String,
    pub message: String,
}

pub fn request_summary_fallbacks() -> Vec<RequestSummary> {
    vec![
        RequestSummary {
            id: "REQ-001".to_string(),
            request_type: "VM".to_string(),
            name: "srv-app-01".to_string(),
            site: "site-alpha".to_string(),
            environment: "prod".to_string(),
            status: "intake".to_string(),
            stage: "intake".to_string(),
            created: "2026-06-01T10:00:00Z".to_string(),
        },
        RequestSummary {
            id: "REQ-002".to_string(),
            request_type: "Application".to_string(),
            name: "order-service".to_string(),
            site: "site-bravo".to_string(),
            environment: "staging".to_string(),
            status: "validated".to_string(),
            stage: "validated".to_string(),
            created: "2026-06-02T14:30:00Z".to_string(),
        },
        RequestSummary {
            id: "REQ-003".to_string(),
            request_type: "SQL".to_string(),
            name: "analytics-db".to_string(),
            site: "site-alpha".to_string(),
            environment: "prod".to_string(),
            status: "approved".to_string(),
            stage: "planned".to_string(),
            created: "2026-06-03T09:15:00Z".to_string(),
        },
        RequestSummary {
            id: "REQ-004".to_string(),
            request_type: "Network".to_string(),
            name: "vlan-backend".to_string(),
            site: "site-alpha".to_string(),
            environment: "dev".to_string(),
            status: "failed".to_string(),
            stage: "planning".to_string(),
            created: "2026-06-03T16:45:00Z".to_string(),
        },
        RequestSummary {
            id: "REQ-005".to_string(),
            request_type: "Storage".to_string(),
            name: "nfs-shared".to_string(),
            site: "site-bravo".to_string(),
            environment: "test".to_string(),
            status: "executed".to_string(),
            stage: "verified".to_string(),
            created: "2026-06-04T08:00:00Z".to_string(),
        },
    ]
}

pub fn request_detail_fallback(request_id: &str) -> RequestDetail {
    let summary = request_summary_fallbacks()
        .into_iter()
        .find(|r| r.id == request_id)
        .unwrap_or_else(|| RequestSummary {
            id: request_id.to_string(),
            request_type: "VM".to_string(),
            name: "unknown".to_string(),
            site: "site-alpha".to_string(),
            environment: "prod".to_string(),
            status: "intake".to_string(),
            stage: "intake".to_string(),
            created: "2026-06-01T00:00:00Z".to_string(),
        });

    let timeline = vec![
        StageEvent {
            stage: "intake".to_string(),
            timestamp: summary.created.clone(),
            description: "Request created and submitted for review".to_string(),
        },
        StageEvent {
            stage: "validated".to_string(),
            timestamp: "2026-06-05T10:00:00Z".to_string(),
            description: "Request fields validated against policy".to_string(),
        },
        StageEvent {
            stage: "planned".to_string(),
            timestamp: "2026-06-05T11:00:00Z".to_string(),
            description: "Dry-run execution plan generated".to_string(),
        },
        StageEvent {
            stage: "approved".to_string(),
            timestamp: "2026-06-05T12:00:00Z".to_string(),
            description: "Approval granted by datacenter approver".to_string(),
        },
        StageEvent {
            stage: "locked".to_string(),
            timestamp: "2026-06-05T12:30:00Z".to_string(),
            description: "Request locked for execution".to_string(),
        },
        StageEvent {
            stage: "executed".to_string(),
            timestamp: "2026-06-05T13:00:00Z".to_string(),
            description: "Execution completed successfully".to_string(),
        },
        StageEvent {
            stage: "verified".to_string(),
            timestamp: "2026-06-05T13:30:00Z".to_string(),
            description: "Post-execution verification passed".to_string(),
        },
    ];

    let actions_available = match summary.stage.as_str() {
        "intake" => vec!["validate".to_string()],
        "validated" => vec!["plan".to_string()],
        "planned" => vec!["approve".to_string(), "validate".to_string()],
        "approved" => vec!["lock".to_string()],
        "locked" => vec!["execute".to_string()],
        "executed" => vec!["verify".to_string()],
        "failed" => vec!["validate".to_string(), "plan".to_string()],
        _ => vec!["validate".to_string()],
    };

    RequestDetail {
        id: summary.id,
        request_type: summary.request_type,
        name: summary.name,
        site: summary.site,
        environment: summary.environment,
        cpu: 4,
        memory: 16,
        justification: "Business requirement for new service deployment".to_string(),
        status: summary.status,
        stage: summary.stage,
        created: summary.created,
        updated: "2026-06-05T12:00:00Z".to_string(),
        timeline,
        actions_available,
    }
}

pub const DASHBOARD_SUMMARIES: &[SafeSummary] = &[
    SafeSummary {
        label: "Platform health",
        value: "7 healthy / 2 warning",
        detail: "Portal, API, queue, workers, database, ingress, adapter readiness.",
        state: SummaryState::Healthy,
        redaction_state: "Safe summary",
    },
    SafeSummary {
        label: "Site readiness",
        value: "9 ready / 2 blocked",
        detail: "Capacity, network, placement, firmware, and support coverage.",
        state: SummaryState::Warning,
        redaction_state: "Safe summary",
    },
    SafeSummary {
        label: "Open requests",
        value: "31 open",
        detail: "6 awaiting approval, 4 at SLA risk, 1 emergency change.",
        state: SummaryState::Neutral,
        redaction_state: "Safe summary",
    },
    SafeSummary {
        label: "Failed operations",
        value: "5 failed / 2 retry-safe",
        detail: "Safe summaries only; evidence redacted before handover.",
        state: SummaryState::Failed,
        redaction_state: "Redacted",
    },
    SafeSummary {
        label: "Backup risk",
        value: "18 gaps / 3 critical",
        detail: "Repository pressure, replica gaps, app-aware checks, restore tests.",
        state: SummaryState::Warning,
        redaction_state: "Safe summary",
    },
    SafeSummary {
        label: "Monitoring gaps",
        value: "42 assets",
        detail: "Host, template, proxy, owner, and alert-route reviews.",
        state: SummaryState::Warning,
        redaction_state: "Safe summary",
    },
    SafeSummary {
        label: "Stale data",
        value: "4 sources tracked",
        detail: "Freshness state controls whether workflows stay read-only.",
        state: SummaryState::Stale,
        redaction_state: "Safe summary",
    },
];
