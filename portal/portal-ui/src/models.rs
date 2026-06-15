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

/// Mirrors the engine `health_monitor::PlatformHealth` JSON. Unknown fields
/// (such as the engine `source`) are tolerated; `components` is defaulted so
/// trimmed payloads still decode.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlatformHealth {
    pub overall_status: String,
    #[serde(default)]
    pub components: Vec<String>,
    pub checks: Vec<HealthCheck>,
    pub timestamp: String,
}

/// Mirrors the engine `health_monitor::HealthCheck` JSON; the extra engine
/// `source` field is ignored on decode.
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

/// Mirrors `ryuki_engine::auth::AuthSession` field-for-field. The portal
/// must not depend on ryuki-engine, so the shape is pinned by fixture tests
/// instead of a shared type.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthSession {
    pub user_id: String,
    pub display_name: String,
    pub roles: Vec<String>,
    pub token_valid: bool,
    pub provider_mode: String,
}

/// Canonical POST /api/auth/local/login response. The `session_id` stays on
/// the SSR side (portal cookie) and never reaches WASM.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApiLoginSession {
    pub session_id: String,
    pub user_id: String,
    pub display_name: String,
    pub roles: Vec<String>,
    pub token_valid: bool,
    pub provider_mode: String,
    #[serde(default)]
    pub expires_at: String,
}

impl From<ApiLoginSession> for AuthSession {
    fn from(login: ApiLoginSession) -> Self {
        Self {
            user_id: login.user_id,
            display_name: login.display_name,
            roles: login.roles,
            token_valid: login.token_valid,
            provider_mode: login.provider_mode,
        }
    }
}

/// Portal-facing platform summary for the dashboard/login context line.
/// Mapped from the nested camelCase `/api/platform/summary` payload via
/// [`ApiPlatformSummary`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlatformSummaryContext {
    pub product_name: String,
    pub authentication_mode: String,
    pub entra_groups_configured: bool,
}

/// Mirrors the `/api/platform/summary` JSON (camelCase, nested
/// `localAuthorization` object). Unknown fields are tolerated.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPlatformSummary {
    pub product_name: String,
    #[serde(default)]
    pub local_authorization: ApiLocalAuthorization,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiLocalAuthorization {
    #[serde(default)]
    pub authentication_mode: String,
    #[serde(default)]
    pub entra_groups_configured: bool,
}

impl From<ApiPlatformSummary> for PlatformSummaryContext {
    fn from(summary: ApiPlatformSummary) -> Self {
        Self {
            product_name: summary.product_name,
            authentication_mode: summary.local_authorization.authentication_mode,
            entra_groups_configured: summary.local_authorization.entra_groups_configured,
        }
    }
}

/// Static fallback for the platform summary context. Served verbatim in
/// static-dry-run mode and when the upstream API is unreachable in live mode.
pub fn platform_summary_context_fallback() -> PlatformSummaryContext {
    PlatformSummaryContext {
        product_name: "Ryuki Infrastructure Platform".to_string(),
        authentication_mode: "static-dry-run".to_string(),
        entra_groups_configured: false,
    }
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

/// Labeled synthetic session for the static-dry-run demo. The PlatformAdmin
/// grant survives only behind the static-mode branch in the server boundary.
pub fn auth_session_fallback() -> AuthSession {
    AuthSession {
        user_id: "platform-engineer".to_string(),
        display_name: "Platform Engineer".to_string(),
        roles: vec!["PlatformAdmin".to_string()],
        token_valid: false,
        provider_mode: "static-dry-run".to_string(),
    }
}

/// Zero-role placeholder session rendered while the upstream API is
/// unreachable in live mode; the shell shows it read-only with a banner.
pub fn degraded_auth_session() -> AuthSession {
    AuthSession {
        user_id: "degraded".to_string(),
        display_name: "Degraded read-only".to_string(),
        roles: vec![],
        token_valid: false,
        provider_mode: "degraded-static-fallback".to_string(),
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
    use crate::views::request_create::{ENVIRONMENT_OPTIONS, REQUEST_TYPE_OPTIONS, SITE_OPTIONS};

    RequestIntakeForm {
        title: "Request Intake".to_string(),
        description: "Review-only preview — submission available in next release".to_string(),
        fields: vec![
            RequestFormField {
                label: "Request type".to_string(),
                field_type: "select".to_string(),
                required: true,
                options: REQUEST_TYPE_OPTIONS
                    .iter()
                    .map(|(value, _)| value.to_string())
                    .collect(),
                placeholder: "Select request type".to_string(),
            },
            RequestFormField {
                label: "Site".to_string(),
                field_type: "select".to_string(),
                required: true,
                options: SITE_OPTIONS
                    .iter()
                    .map(|(value, _)| value.to_string())
                    .collect(),
                placeholder: "Select site".to_string(),
            },
            RequestFormField {
                label: "Environment".to_string(),
                field_type: "select".to_string(),
                required: true,
                options: ENVIRONMENT_OPTIONS
                    .iter()
                    .map(|(value, _)| value.to_string())
                    .collect(),
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

// ── Agent types ───────────────────────────────────────────────────────────
//
// These types mirror the `GET /api/admin/agents` API shape. The endpoint is
// admin-only (PlatformAdmin gate) and returns the {agents:[...], capped:bool}
// envelope. `last_seen_at` is nullable (agents that registered but have not
// checked in yet). `result_status` and `completed_at` on each job are also
// nullable (jobs still in-flight).
//
// Static/degraded mode returns an empty Vec — no synthetic agent rows are
// fabricated because synthetic agents with fake platforms or statuses would
// mislead operators about what is actually enrolled.

/// Portal-facing summary of one registered execution agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSummary {
    pub agent_id: String,
    pub platform: String,
    pub status: String,
    pub last_seen_at: Option<String>,
    pub created_at: String,
    pub jobs: Vec<AgentJobSummary>,
}

/// Portal-facing summary of one job associated with an agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentJobSummary {
    pub id: String,
    pub mode: String,
    pub status: String,
    pub result_status: Option<String>,
    pub completed_at: Option<String>,
}

// ── Integration types ─────────────────────────────────────────────────────
//
// These types mirror the Slice-1 API shape (`/api/integrations`). The
// `credential_ref` field in `IntegrationSummary` is `Option<String>`: for
// `db-encrypted` connections the server fn sets it to `None` (the opaque FK
// `is-{uuid}` is never useful to display and must not be exposed). For
// `vault` and `env-var` connections it carries the non-secret reference (path
// / key name) and may be shown.

/// Portal-facing view of one vendor integration connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationSummary {
    pub id: String,
    pub vendor_type: String,
    pub name: String,
    pub endpoint_url: String,
    pub site_scope: Option<String>,
    /// `"vault"` | `"db-encrypted"` | `"env-var"`
    pub credential_source: String,
    /// Non-secret reference (vault path or env key names). Always `None`
    /// for `db-encrypted` — the opaque FK is redacted by the server fn and
    /// never sent to the browser.
    pub credential_ref: Option<String>,
    pub status: String,
    pub readiness: String,
    pub execution_mode: String,
    pub last_test_at: Option<String>,
    pub last_test_result: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Result of a POST `/api/integrations/{id}/test` probe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationTestResult {
    pub connection_id: String,
    pub endpoint_status: String,
    pub endpoint_message: String,
    pub credential_status: String,
    pub credential_message: String,
    pub tested_at: String,
}

/// Request body for `POST /api/integrations`.
///
/// `inline_secret` is write-only and MUST NOT be logged. `Debug` is
/// implemented manually to redact it, mirroring `CreateConnectionRequest`
/// (FIX-5 in integration.rs).
#[derive(Clone, Serialize, Deserialize)]
pub struct CreateIntegrationPayload {
    pub vendor_type: String,
    pub name: String,
    pub endpoint_url: String,
    pub site_scope: Option<String>,
    /// `"vault"` | `"db-encrypted"` | `"env-var"`
    pub credential_source: String,
    /// Vault path or env key names. Empty string for `db-encrypted`.
    pub credential_ref: String,
    /// Write-only. `db-encrypted` secret value. REDACTED in `Debug`.
    pub inline_secret: String,
}

impl std::fmt::Debug for CreateIntegrationPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateIntegrationPayload")
            .field("vendor_type", &self.vendor_type)
            .field("name", &self.name)
            .field("endpoint_url", &self.endpoint_url)
            .field("site_scope", &self.site_scope)
            .field("credential_source", &self.credential_source)
            .field("credential_ref", &self.credential_ref)
            .field("inline_secret", &"[REDACTED]")
            .finish()
    }
}

/// Request body for `PUT /api/integrations/{id}`.
///
/// `credential_source` is intentionally absent — Slice-1 `HARDENING-1`
/// forbids changing the source on update. `inline_secret` is write-only and
/// MUST NOT be logged. `Debug` is implemented manually to redact it.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateIntegrationPayload {
    pub vendor_type: Option<String>,
    pub name: Option<String>,
    pub endpoint_url: Option<String>,
    pub site_scope: Option<String>,
    /// Vault path or env key names only. `None`/empty for `db-encrypted`.
    pub credential_ref: Option<String>,
    /// Write-only. Empty = keep existing secret (no re-encryption).
    pub inline_secret: String,
}

impl std::fmt::Debug for UpdateIntegrationPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateIntegrationPayload")
            .field("vendor_type", &self.vendor_type)
            .field("name", &self.name)
            .field("endpoint_url", &self.endpoint_url)
            .field("site_scope", &self.site_scope)
            .field("credential_ref", &self.credential_ref)
            .field("inline_secret", &"[REDACTED]")
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors one element of the `GET /api/requests` list JSON. The list DTO
/// omits `stage` and `environment`, so both are defaulted.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApiRequestSummary {
    pub request_id: String,
    pub request_type: String,
    pub status: String,
    #[serde(default)]
    pub stage: String,
    pub name: String,
    pub site: String,
    #[serde(default)]
    pub environment: String,
    pub created_at: String,
}

impl From<ApiRequestSummary> for RequestSummary {
    fn from(summary: ApiRequestSummary) -> Self {
        let stage = if summary.stage.is_empty() {
            // The list endpoint does not return the stage column; the status
            // is the closest honest signal for the stage badge.
            summary.status.clone()
        } else {
            normalize_api_stage(&summary.stage)
        };
        Self {
            id: summary.request_id,
            request_type: summary.request_type,
            name: summary.name,
            site: summary.site,
            environment: summary.environment,
            status: summary.status,
            stage,
            created: summary.created_at,
        }
    }
}

/// Mirrors the `GET /api/requests/{id}` detail JSON.
///
/// `cpu`/`memory_gb` are VM-shaped scalars; they default so non-VM request
/// types (patch-maintenance, controlled-restore, cmdb-import, ...) that omit
/// or zero them still decode. The persisted-state additions
/// (`criticality`/`requester`/`owner`/`stages`/`plan`/`validation_results`/
/// `payload`) are all `#[serde(default)]` and absent fields decode to their
/// defaults, so the portal continues to decode the older scalar-only detail
/// JSON unchanged (no `deny_unknown_fields`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApiRequestDetail {
    pub request_id: String,
    pub request_type: String,
    pub status: String,
    #[serde(default)]
    pub stage: String,
    pub site: String,
    #[serde(default)]
    pub environment: String,
    pub name: String,
    #[serde(default)]
    pub cpu: u32,
    #[serde(default)]
    pub memory_gb: u32,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    // --- Persisted request-state additions (all optional / defaulted) ---
    /// Service criticality (e.g. `critical`, `standard`); absent on the older
    /// scalar-only detail JSON.
    #[serde(default)]
    pub criticality: Option<String>,
    /// Verified requester principal (the durable `created_by`-derived owner of
    /// the request), distinct from the display `name`.
    #[serde(default)]
    pub requester: Option<String>,
    /// Accountable owner of the target resource.
    #[serde(default)]
    pub owner: Option<String>,
    /// The real, persisted dry-run plan. The API serializes this as the
    /// produced plan stages (a JSON array of Stage objects), or null until a
    /// request is planned — NOT a string. Kept as a raw Value (like `payload`
    /// /`validation_results`); the human-readable summary is extracted in the
    /// `From` impl from the plan stage's `dry-run-plan` evidence.
    #[serde(default)]
    pub plan: serde_json::Value,
    /// Persisted approval route (ordered approver roles/principals).
    #[serde(default)]
    pub approval_route: Vec<String>,
    /// Persisted lifecycle stages (name/status/timestamps), the request's own
    /// durable stage record rather than the satellite audit ledger.
    #[serde(default)]
    pub stages: Vec<ApiRequestStage>,
    /// Free-form validation results (rule outcomes); rendered as labelled
    /// key/value rows when present.
    #[serde(default)]
    pub validation_results: serde_json::Value,
    /// Per-type request payload (the ~14 non-VM request shapes). Rendered as
    /// generic key/value rows so non-VM types surface their real fields
    /// instead of assuming cpu/memory.
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// One evidence item on a lifecycle stage, as received from the API.
/// The API's `sanitize_stages_for_portal` ensures that when `redacted` is
/// `true`, `value` already holds the safe display form (the raw secret never
/// crosses the wire to the portal). The `redacted` flag is forwarded so the
/// portal can render a visual indicator for redacted items.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct StageEvidenceItem {
    pub key: String,
    /// Display value — safe for rendering. When `redacted` is `true` this is
    /// the placeholder sent by the API, never the original runner output.
    pub value: String,
    /// `true` when the API applied redaction to this item.
    #[serde(default)]
    pub redacted: bool,
    /// The engine `EvidenceType` discriminant as a string (`"Plan"`,
    /// `"Summary"`, etc.). Optional — older API responses may omit it.
    #[serde(default)]
    pub evidence_type: String,
}

/// Mirrors one persisted lifecycle stage as serialized by the API
/// (`ryuki_engine::models::Stage`). All fields default so an absent or partial
/// stage object still decodes.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApiRequestStage {
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
    /// Evidence items collected during this stage (e.g. "terraform-plan" on
    /// the plan stage, "ansible-check" on the verify stage). Defaults to
    /// empty so responses from older API versions still decode.
    #[serde(default)]
    pub evidence: Vec<StageEvidenceItem>,
}

impl From<ApiRequestDetail> for RequestDetail {
    fn from(detail: ApiRequestDetail) -> Self {
        // A terminal status overrides the stage column for display so a
        // rejected request (which keeps `stage='approve'`) renders as a
        // terminal "rejected" step rather than a still-open approval stage.
        let stage = match detail.status.as_str() {
            "rejected" => "rejected".to_string(),
            "cancelled" => "cancelled".to_string(),
            _ => normalize_api_stage(&detail.stage),
        };
        // The real trail is fetched separately via `get_request_audit`; this
        // single synthetic entry is a clearly-labeled SSR/unreachable
        // fallback only and is replaced by the persisted timeline in the view.
        let timeline = vec![StageEvent {
            stage: stage.clone(),
            timestamp: detail.updated_at.clone(),
            description: "Current lifecycle stage (audit trail loads separately)".to_string(),
        }];
        let actions_available = actions_for_stage(&stage);
        // Persisted stages map directly to display stages (normalizing the
        // action-name vocabulary onto the portal state vocabulary). Evidence
        // items are forwarded as-is — the API has already applied redaction so
        // the `value` field is safe for display.
        let stages = detail
            .stages
            .into_iter()
            .map(|s| PersistedStage {
                name: normalize_api_stage(&s.name),
                status: s.status,
                timestamp: s.completed_at.or(s.started_at).unwrap_or_default(),
                evidence: s.evidence,
            })
            .collect();
        // Flatten the per-type payload into display rows so non-VM request
        // types surface their real fields instead of assuming cpu/memory.
        let payload_fields = flatten_payload_fields(&detail.payload);
        // The API serializes `plan` as a Vec<Stage>; surface the human-readable
        // dry-run-plan evidence text (empty until the request is planned).
        let plan = plan_summary_text(&detail.plan);
        Self {
            id: detail.request_id,
            request_type: detail.request_type,
            name: detail.name,
            site: detail.site,
            environment: detail.environment,
            cpu: detail.cpu,
            memory: detail.memory_gb,
            justification: detail.justification.unwrap_or_default(),
            status: detail.status,
            stage,
            created: detail.created_at,
            updated: detail.updated_at,
            timeline,
            actions_available,
            criticality: detail.criticality.unwrap_or_default(),
            requester: detail.requester.unwrap_or_default(),
            owner: detail.owner.unwrap_or_default(),
            plan,
            approval_route: detail.approval_route,
            stages,
            payload_fields,
        }
    }
}

/// Extracts the human-readable dry-run plan summary from the API's persisted
/// `plan` value (a JSON array of Stage objects, or null until planned).
///
/// Key priority (first match wins):
/// 1. `"terraform-plan"` — real Terraform dry-run output (preferred; set by
///    the execution runner since the wiring wave).
/// 2. `"dry-run-plan"` — legacy simulated plan string (pre-runner requests).
///
/// Returns "" when the request is not yet planned or neither key is present.
/// Never assumes `plan` is a string (the API serializes it as `Vec<Stage>`).
pub fn plan_summary_text(plan: &serde_json::Value) -> String {
    let Some(stages) = plan.as_array() else {
        return String::new();
    };
    let evidence = stages
        .iter()
        .find(|stage| {
            stage.get("name").and_then(|n| n.as_str()) == Some("plan")
                || stage.get("name").and_then(|n| n.as_str()) == Some("dry-run-plan")
        })
        .and_then(|stage| stage.get("evidence").and_then(|e| e.as_array()));

    let Some(evidence) = evidence else {
        return String::new();
    };

    // Prefer the real terraform-plan output over the legacy simulated key.
    let find_by_key = |key: &str| {
        evidence
            .iter()
            .find(|item| item.get("key").and_then(|k| k.as_str()) == Some(key))
            .and_then(|item| item.get("value").and_then(|v| v.as_str()))
            .map(str::to_string)
    };
    find_by_key("terraform-plan")
        .or_else(|| find_by_key("dry-run-plan"))
        .unwrap_or_default()
}

/// Flattens a JSON request payload object into display rows. Object keys are
/// humanized (`snake_case` -> "Snake case"); nested objects/arrays are
/// rendered as compact JSON so no field is silently dropped. A non-object
/// payload (null / scalar / the older absent payload) yields no rows.
pub fn flatten_payload_fields(payload: &serde_json::Value) -> Vec<KeyValue> {
    let Some(map) = payload.as_object() else {
        return Vec::new();
    };
    map.iter()
        .map(|(key, value)| KeyValue {
            label: humanize_field_key(key),
            value: json_value_to_display(value),
        })
        .collect()
}

/// Humanizes a payload key for display: `requested_offering` -> "Requested
/// offering", `dryRunPlan` -> "Dry run plan".
/// Condenses an RFC3339 timestamp (`2026-06-13T14:57:20.6+00:00`) to a compact
/// `YYYY-MM-DD HH:MM` for display. Shared across the dashboard, request list,
/// activity feed, and audit trail so every timestamp reads the same and a raw
/// fractional-second value never overruns its cell. Honest: it only trims.
pub fn condense_timestamp(raw: &str) -> String {
    match raw.split_once('T') {
        Some((date, time)) => {
            let hm: String = time.chars().take(5).collect();
            format!("{date} {hm}")
        }
        None => raw.to_string(),
    }
}

fn humanize_field_key(key: &str) -> String {
    let spaced = key
        .chars()
        .flat_map(|c| {
            if c == '_' || c == '-' {
                vec![' ']
            } else if c.is_ascii_uppercase() {
                vec![' ', c.to_ascii_lowercase()]
            } else {
                vec![c]
            }
        })
        .collect::<String>();
    let trimmed = spaced.trim();
    let mut chars = trimmed.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Renders a JSON value as a compact display string. Strings drop their
/// quotes; objects/arrays serialize compactly so nested payload data is still
/// surfaced rather than dropped.
fn json_value_to_display(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Maps the API `requests.stage` column vocabulary (action names such as
/// `validate`) onto the portal display vocabulary (state names such as
/// `validated`). Values already in the portal vocabulary pass through.
pub fn normalize_api_stage(stage: &str) -> String {
    match stage {
        "validate" => "validated",
        "plan" => "planned",
        "approve" => "approved",
        "lock" => "locked",
        "execute" => "executed",
        "verify" => "verified",
        // The cancel transition stamps `stage='cancel'`; the rejected
        // transition reuses `stage='approve'` (the decision point), so the
        // terminal "rejected" display is driven by the request status rather
        // than the stage column (see `RequestDetail::from`).
        "cancel" => "cancelled",
        other => other,
    }
    .to_string()
}

/// Lifecycle actions the portal offers for a request in the given (portal
/// vocabulary) stage. Shared by the static fallback detail and the live
/// detail mapping.
pub fn actions_for_stage(stage: &str) -> Vec<String> {
    match stage {
        // `cancel` is offered on every non-terminal pre-execution stage so a
        // requester (or admin) can withdraw a request before it runs. `reject`
        // is the approver's "say no" at the approval decision point (planned).
        "draft" | "intake" => vec!["validate".to_string(), "cancel".to_string()],
        "validated" => vec!["plan".to_string(), "cancel".to_string()],
        "planned" => vec![
            "approve".to_string(),
            "validate".to_string(),
            "reject".to_string(),
            "cancel".to_string(),
        ],
        "approved" => vec!["lock".to_string(), "cancel".to_string()],
        "locked" => vec!["execute".to_string(), "cancel".to_string()],
        "executed" => vec!["verify".to_string()],
        "failed" => vec!["validate".to_string(), "plan".to_string()],
        // Terminal states offer no further lifecycle actions. `verified` is the
        // resting stage of a fully-completed request (verify is the last action,
        // stamped stage='verify' -> normalized 'verified'); `completed` covers a
        // status-driven completed display. Neither offers further actions —
        // without these arms they fell through to the wildcard and wrongly
        // offered "validate" on a finished request.
        "verified" | "completed" | "rejected" | "cancelled" => vec![],
        _ => vec!["validate".to_string()],
    }
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
    // --- Persisted request-state additions ---
    /// Service criticality; empty when the API did not supply it.
    pub criticality: String,
    /// Verified requester principal; empty when not supplied.
    pub requester: String,
    /// Accountable owner; empty when not supplied.
    pub owner: String,
    /// Real persisted dry-run plan text; empty when none has been generated
    /// yet (the view shows a "no plan" note rather than a fabricated string).
    pub plan: String,
    /// Persisted approval route (ordered).
    pub approval_route: Vec<String>,
    /// Persisted lifecycle stages, surfaced as a real stage record.
    pub stages: Vec<PersistedStage>,
    /// Per-type request payload flattened into display rows. Empty for VM-type
    /// requests whose fields are already covered by cpu/memory.
    pub payload_fields: Vec<KeyValue>,
}

/// A persisted lifecycle stage, projected for display.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PersistedStage {
    /// Portal-vocabulary stage name (already normalized).
    pub name: String,
    /// Stage status (`Completed`, `InProgress`, `Pending`, `Failed`,
    /// `Blocked`), passed through from the engine `StageStatus`.
    pub status: String,
    /// Best-available timestamp (completed, else started).
    pub timestamp: String,
    /// Evidence items collected during this stage (e.g. `terraform-plan`,
    /// `ansible-check`). Empty when the stage produced no evidence or the
    /// API response predates evidence forwarding.
    #[serde(default)]
    pub evidence: Vec<StageEvidenceItem>,
}

/// A flattened key/value row used to render per-type request payloads and
/// validation results generically.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct KeyValue {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StageEvent {
    pub stage: String,
    pub timestamp: String,
    pub description: String,
}

/// One row of the durable who-did-what-when trail, mirroring an `audit_log`
/// row as served by `GET /api/requests/{id}/audit`. The portal renders the
/// verified actor identity, the action, the resulting status, the
/// transition's stage, the timestamp, and a reason (for reject/cancel rows).
/// `durable` distinguishes a persisted DB row (`true`) from a process-local
/// dry-run entry (`false`), so the timeline can label non-durable trails.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuditEventRow {
    pub action: String,
    #[serde(default)]
    pub actor_display: String,
    #[serde(default)]
    pub actor_principal: String,
    #[serde(default)]
    pub from_stage: Option<String>,
    #[serde(default)]
    pub to_stage: String,
    #[serde(default)]
    pub to_status: String,
    pub occurred_at: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default = "default_durable")]
    pub durable: bool,
    /// Which request this row belongs to. Empty for the per-request trail
    /// (the request is already in context); carried by the global activity
    /// feed so each row can deep-link to `/requests/:id`.
    #[serde(default)]
    pub request_id: Option<String>,
    /// The verified roles the actor held at the time of the action.
    #[serde(default)]
    pub actor_roles: Vec<String>,
    /// The recorded outcome (`applied`, `denied`, …); shown by the global feed.
    #[serde(default)]
    pub outcome: Option<String>,
}

/// Audit rows are durable (DB-backed) unless the read endpoint explicitly
/// tags them `false` (dry-run / process-local trail). Defaulting to `true`
/// keeps the common DB path terse.
fn default_durable() -> bool {
    true
}

/// Mirrors the audit envelope served by both `GET /api/requests/{id}/audit`
/// and `GET /api/activity/audit`. The API serializes the rows under the
/// `entries` key; the `events` alias keeps older fixtures and any bare-array
/// shape decoding too, so the portal tolerates either shape.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ApiAuditTrail {
    Enveloped {
        #[serde(default = "default_durable")]
        durable: bool,
        #[serde(default, alias = "events")]
        entries: Vec<ApiAuditEventRow>,
    },
    Bare(Vec<ApiAuditEventRow>),
}

impl ApiAuditTrail {
    /// Flattens the wire shape into portal `AuditEventRow`s, stamping the
    /// envelope-level `durable` flag onto each row when present.
    pub fn into_rows(self) -> Vec<AuditEventRow> {
        match self {
            ApiAuditTrail::Enveloped { durable, entries } => entries
                .into_iter()
                .map(|row| row.into_audit_event(durable))
                .collect(),
            ApiAuditTrail::Bare(entries) => entries
                .into_iter()
                .map(|row| row.into_audit_event(true))
                .collect(),
        }
    }
}

/// Mirrors one `audit_log` row as serialized by the API. `detail` carries the
/// reason text for reject/cancel rows; the portal extracts `detail.reason`
/// into the rendered `AuditEventRow`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApiAuditEventRow {
    pub action: String,
    #[serde(default)]
    pub actor_display: Option<String>,
    #[serde(default)]
    pub actor_principal: String,
    #[serde(default)]
    pub actor_roles: Vec<String>,
    #[serde(default)]
    pub from_stage: Option<String>,
    #[serde(default)]
    pub to_stage: String,
    #[serde(default)]
    pub to_status: String,
    pub occurred_at: String,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub detail: serde_json::Value,
}

impl ApiAuditEventRow {
    fn into_audit_event(self, durable: bool) -> AuditEventRow {
        // The reason lives in the JSONB `detail.reason` for reject/cancel
        // rows; absent for the forward-only stage transitions.
        let reason = self
            .detail
            .get("reason")
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .filter(|reason| !reason.is_empty());
        AuditEventRow {
            action: self.action,
            actor_display: self.actor_display.unwrap_or_default(),
            actor_principal: self.actor_principal,
            from_stage: self.from_stage,
            to_stage: self.to_stage,
            to_status: self.to_status,
            occurred_at: self.occurred_at,
            reason,
            durable,
            request_id: self.request_id.filter(|id| !id.is_empty()),
            actor_roles: self.actor_roles,
            outcome: self.outcome.filter(|outcome| !outcome.is_empty()),
        }
    }
}

/// One redacted line of a compliance evidence pack, mirroring an engine
/// `EvidenceItem` as serialized by the API.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApiEvidenceItem {
    pub key: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub redacted_value: Option<String>,
    #[serde(default)]
    pub redacted: bool,
    #[serde(default)]
    pub evidence_type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct ApiEvidencePackBody {
    #[serde(default)]
    pub items: Vec<ApiEvidenceItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct ApiEvidenceContent {
    #[serde(default)]
    pub pack: ApiEvidencePackBody,
    #[serde(default)]
    pub audit_trail: Vec<serde_json::Value>,
}

/// Mirrors the `GET /api/requests/{id}/evidence` envelope: a digest-sealed,
/// redacted compliance pack (request evidence + the durable audit trail).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApiEvidencePack {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub generated_at: String,
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub durable: bool,
    #[serde(default)]
    pub item_count: usize,
    #[serde(default)]
    pub redacted: bool,
    #[serde(default)]
    pub content: ApiEvidenceContent,
}

/// One evidence item resolved for display — the redacted value is substituted
/// when present so a sensitive raw value is never shown.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EvidencePackItem {
    pub key: String,
    pub value: String,
    pub redacted: bool,
    pub evidence_type: String,
}

/// Portal view-model for an exported compliance evidence pack: the tamper-
/// evident digest seal, its metadata, the redacted items, and a pretty-printed
/// JSON copy for export. `durable=false` flags a static-preview pack that was
/// not sealed against persisted data.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EvidencePackExport {
    pub request_id: String,
    pub generated_at: String,
    pub algorithm: String,
    pub digest: String,
    pub durable: bool,
    pub item_count: usize,
    pub audit_count: usize,
    pub redacted: bool,
    pub items: Vec<EvidencePackItem>,
    pub pack_json: String,
}

impl ApiEvidencePack {
    /// Flattens the wire envelope into the display view-model, substituting the
    /// redacted value for any redacted item and carrying a pretty JSON copy.
    pub fn into_export(self, pack_json: String) -> EvidencePackExport {
        let items = self
            .content
            .pack
            .items
            .into_iter()
            .map(|item| {
                let value = if item.redacted {
                    item.redacted_value
                        .unwrap_or_else(|| "***REDACTED***".into())
                } else {
                    item.value
                };
                EvidencePackItem {
                    key: item.key,
                    value,
                    redacted: item.redacted,
                    evidence_type: item.evidence_type,
                }
            })
            .collect();
        EvidencePackExport {
            request_id: self.request_id,
            generated_at: self.generated_at,
            algorithm: self.algorithm,
            digest: self.digest,
            durable: self.durable,
            item_count: self.item_count,
            audit_count: self.content.audit_trail.len(),
            redacted: self.redacted,
            items,
            pack_json,
        }
    }
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
    /// Per-type intake fields (e.g. patch wave, restore point, runbook id). Keys
    /// are snake_case; they are merged into the persisted request payload JSONB
    /// by the API and surface on the request detail. Empty for types with no
    /// extra fields.
    #[serde(default)]
    pub fields: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StageActionResponse {
    pub request_id: String,
    pub success: bool,
    pub new_stage: String,
    pub message: String,
}

/// Canonical app roles assignable to an API token. Mirrors the engine's
/// `ALL_APP_ROLES`; kept in lockstep with `rbac_role_summary_fallbacks` so the
/// create-token role multiselect always offers the full set. The portal must
/// not depend on ryuki-engine, so the list is duplicated and pinned by a test.
pub const ALL_APP_ROLES: &[&str] = &[
    "PlatformAdmin",
    "DatacenterApprover",
    "VMwareOperator",
    "HyperVOperator",
    "ProxmoxOperator",
    "WintelLinuxOperator",
    "BackupOperator",
    "MonitoringOperator",
    "ServiceDesk",
    "Auditor",
    "Requester",
    "BreakGlassAdmin",
];

/// API token metadata as returned by `GET /api/admin/tokens` and echoed by the
/// create endpoint. The token hash is NEVER part of this shape: the API
/// redacts it (omitted or `null`) and the portal never deserializes, stores,
/// or renders it. Plaintext lives only in [`CreateTokenResult::token`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct AdminTokenSummary {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub owner_principal: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub site_scope: Option<String>,
    #[serde(default)]
    pub environment_scope: Option<String>,
    #[serde(default)]
    pub token_valid: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
}

/// Create-token request body for `POST /api/admin/tokens`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct CreateTokenPayload {
    pub name: String,
    pub owner_principal: String,
    pub roles: Vec<String>,
    pub site_scope: Option<String>,
    pub environment_scope: Option<String>,
    pub expires_at: Option<String>,
}

/// Result of a successful create. `token` is the one-time plaintext secret:
/// it is surfaced to the caller component exactly once and is never persisted
/// or re-fetched. `metadata` carries the redacted (hash-free) row.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CreateTokenResult {
    pub token: String,
    pub metadata: AdminTokenSummary,
}

/// Active session metadata as returned by `GET /api/admin/sessions`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct AdminSessionSummary {
    pub id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Result of a revoke (`DELETE` of a token or session). `id` echoes the
/// affected resource so the UI can prune the row optimistically.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RevokeResult {
    pub status: String,
    pub id: String,
}

/// Labeled synthetic token rows for static-dry-run mode. No plaintext, no
/// hash; `token_valid=false` reflects that no machine credential can execute
/// in preview mode.
pub fn admin_token_summary_fallbacks() -> Vec<AdminTokenSummary> {
    vec![
        AdminTokenSummary {
            id: "00000000-0000-4000-8000-000000000001".to_string(),
            name: "ci-deployer (preview)".to_string(),
            owner_principal: "svc:ci-pipeline".to_string(),
            roles: vec!["VMwareOperator".to_string()],
            site_scope: Some("DEBER".to_string()),
            environment_scope: Some("staging".to_string()),
            token_valid: false,
            created_at: Some("2026-06-13T09:00:00Z".to_string()),
            expires_at: Some("2026-09-13T09:00:00Z".to_string()),
            last_used_at: None,
            revoked_at: None,
        },
        AdminTokenSummary {
            id: "00000000-0000-4000-8000-000000000002".to_string(),
            name: "audit-export (preview)".to_string(),
            owner_principal: "svc:audit-export".to_string(),
            roles: vec!["Auditor".to_string()],
            site_scope: None,
            environment_scope: None,
            token_valid: false,
            created_at: Some("2026-05-01T09:00:00Z".to_string()),
            expires_at: None,
            last_used_at: Some("2026-06-12T18:30:00Z".to_string()),
            revoked_at: Some("2026-06-12T19:00:00Z".to_string()),
        },
    ]
}

/// Labeled synthetic active-session rows for static-dry-run mode.
pub fn admin_session_summary_fallbacks() -> Vec<AdminSessionSummary> {
    vec![AdminSessionSummary {
        id: "00000000-0000-4000-8000-0000000000a1".to_string(),
        user_id: "admin".to_string(),
        display_name: "Platform Admin (preview)".to_string(),
        roles: vec!["PlatformAdmin".to_string()],
        provider: Some("local".to_string()),
        created_at: Some("2026-06-13T08:00:00Z".to_string()),
        expires_at: Some("2026-06-14T08:00:00Z".to_string()),
    }]
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

    let actions_available = actions_for_stage(&summary.stage);

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
        criticality: "standard".to_string(),
        requester: "requester".to_string(),
        owner: "platform-team".to_string(),
        plan: "Provision VM with the requested CPU/memory, attach to the \
               environment network, register in CMDB."
            .to_string(),
        approval_route: vec!["datacenter-approver".to_string()],
        stages: Vec::new(),
        payload_fields: Vec::new(),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DatacenterReadinessScore {
    pub site: String,
    pub readiness_score_pct: u32,
    pub total_checks: u32,
    pub passed: u32,
    pub failed: u32,
    pub warnings: u32,
    pub not_checked: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DatacenterSiteReport {
    pub site: String,
    pub overall_status: String,
    pub readiness_score_pct: u32,
    pub checks: Vec<DatacenterCheckDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DatacenterCheckDetail {
    pub check_type: String,
    pub status: String,
    pub details: String,
    pub last_checked: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DatacenterFailingCheck {
    pub site: String,
    pub check_type: String,
    pub details: String,
    pub last_checked: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DatacenterFailingChecksSummary {
    pub failing_count: u32,
    pub failing_checks: Vec<DatacenterFailingCheck>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DatacenterSingleCheck {
    pub site: String,
    pub check_type: String,
    pub status: String,
    pub details: String,
    pub last_checked: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DatacenterFullReadiness {
    pub site: String,
    pub checks_run: u32,
    pub results: Vec<DatacenterCheckDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DatacenterSiteSummary {
    pub site: String,
    pub total_checks: u32,
    pub passed: u32,
    pub failed: u32,
    pub not_checked: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DatacenterSitesCatalog {
    pub sites: Vec<DatacenterSiteSummary>,
}

pub fn datacenter_readiness_score_fallback(site: &str) -> DatacenterReadinessScore {
    match site {
        "DEFRA" => DatacenterReadinessScore {
            site: "DEFRA".into(),
            readiness_score_pct: 83,
            total_checks: 6,
            passed: 4,
            failed: 0,
            warnings: 2,
            not_checked: 0,
        },
        "GBLON" => DatacenterReadinessScore {
            site: "GBLON".into(),
            readiness_score_pct: 25,
            total_checks: 6,
            passed: 1,
            failed: 3,
            warnings: 2,
            not_checked: 0,
        },
        _ => DatacenterReadinessScore {
            site: site.into(),
            readiness_score_pct: 50,
            total_checks: 6,
            passed: 3,
            failed: 0,
            warnings: 2,
            not_checked: 2,
        },
    }
}

pub fn datacenter_site_report_fallback(site: &str) -> DatacenterSiteReport {
    let check_type_details: Vec<(&str, &str, &str, &str)> = match site {
        "DEFRA" => vec![
            (
                "power",
                "passed",
                "PDU A+B redundant, UPS load 62% with 28 min runtime",
                "2026-06-11T10:00:00Z",
            ),
            (
                "cooling",
                "passed",
                "CRAC units nominal, return air 22 C, supply 16 C",
                "2026-06-11T10:00:00Z",
            ),
            (
                "rack-space",
                "warning",
                "12 rack units free across 3 racks (limited headroom)",
                "2026-06-11T10:00:00Z",
            ),
            (
                "switchport",
                "passed",
                "18 switchports available across prod/dmz/mgmt VLANs",
                "2026-06-11T10:00:00Z",
            ),
            (
                "firmware",
                "warning",
                "2 PDUs on firmware v2.8 (current v3.1), SFP modules current",
                "2026-06-11T10:00:00Z",
            ),
            (
                "capacity",
                "passed",
                "Compute 78% allocated, storage 64%, network fabric 42%",
                "2026-06-11T10:00:00Z",
            ),
        ],
        "GBLON" => vec![
            (
                "power",
                "failed",
                "UPS-B in bypass mode, PDU-3 overload alarm at 91%",
                "2026-06-11T09:30:00Z",
            ),
            (
                "cooling",
                "warning",
                "CRAC-2 compressor cycling, return air 26 C (threshold 24 C)",
                "2026-06-11T09:30:00Z",
            ),
            (
                "rack-space",
                "failed",
                "Zero rack units free, 2 racks over-populated (48U in 42U)",
                "2026-06-11T09:30:00Z",
            ),
            (
                "switchport",
                "passed",
                "22 switchports available, fabric links healthy",
                "2026-06-11T09:30:00Z",
            ),
            (
                "firmware",
                "failed",
                "Core switch firmware EOL 2025-Q3, CRAC controller behind 3 revs",
                "2026-06-11T09:30:00Z",
            ),
            (
                "capacity",
                "warning",
                "Compute 94% allocated (critical), storage 88%, network 71%",
                "2026-06-11T09:30:00Z",
            ),
        ],
        _ => vec![
            (
                "power",
                "passed",
                "PDU A+B nominal, UPS load 45%",
                "2026-06-11T08:00:00Z",
            ),
            (
                "cooling",
                "passed",
                "All CRAC units healthy, supply temp 15 C per ASHRAE A1",
                "2026-06-11T08:00:00Z",
            ),
            (
                "rack-space",
                "passed",
                "42 rack units free across 7 empty racks (new buildout)",
                "2026-06-11T08:00:00Z",
            ),
            (
                "switchport",
                "not-checked",
                "Switch fabric not yet provisioned, awaiting L2 install",
                "2026-06-11T08:00:00Z",
            ),
            (
                "firmware",
                "not-checked",
                "Hardware not yet racked, firmware baseline pending",
                "2026-06-11T08:00:00Z",
            ),
            (
                "capacity",
                "passed",
                "Greenfield site, 100% free across compute/storage/network",
                "2026-06-11T08:00:00Z",
            ),
        ],
    };

    let checks: Vec<DatacenterCheckDetail> = check_type_details
        .into_iter()
        .map(|(ct, s, d, l)| DatacenterCheckDetail {
            check_type: ct.into(),
            status: s.into(),
            details: d.into(),
            last_checked: l.into(),
        })
        .collect();

    let passed_count = checks.iter().filter(|c| c.status == "passed").count();
    let warnings_count = checks.iter().filter(|c| c.status == "warning").count();
    let score = ((passed_count as f64 * 1.0 + warnings_count as f64 * 0.5) / checks.len() as f64
        * 100.0)
        .round() as u32;
    let overall = if score >= 90 {
        "healthy"
    } else if score >= 60 {
        "degraded"
    } else {
        "critical"
    };

    DatacenterSiteReport {
        site: site.into(),
        overall_status: overall.into(),
        readiness_score_pct: score,
        checks,
    }
}

pub fn datacenter_failing_checks_fallback() -> DatacenterFailingChecksSummary {
    DatacenterFailingChecksSummary {
        failing_count: 3,
        failing_checks: vec![
            DatacenterFailingCheck {
                site: "GBLON".into(),
                check_type: "power".into(),
                details: "UPS-B in bypass mode, PDU-3 overload alarm at 91%".into(),
                last_checked: "2026-06-11T09:30:00Z".into(),
            },
            DatacenterFailingCheck {
                site: "GBLON".into(),
                check_type: "rack-space".into(),
                details: "Zero rack units free, 2 racks over-populated (48U in 42U)".into(),
                last_checked: "2026-06-11T09:30:00Z".into(),
            },
            DatacenterFailingCheck {
                site: "GBLON".into(),
                check_type: "firmware".into(),
                details: "Core switch firmware EOL 2025-Q3, CRAC controller behind 3 revs".into(),
                last_checked: "2026-06-11T09:30:00Z".into(),
            },
        ],
    }
}

pub fn datacenter_single_check_fallback(site: &str, check_type: &str) -> DatacenterSingleCheck {
    match (site, check_type) {
        ("DEFRA", "power") => DatacenterSingleCheck {
            site: "DEFRA".into(),
            check_type: "power".into(),
            status: "passed".into(),
            details: "PDU A+B redundant, UPS load 62% with 28 min runtime".into(),
            last_checked: "2026-06-11T10:00:00Z".into(),
        },
        ("DEFRA", "cooling") => DatacenterSingleCheck {
            site: "DEFRA".into(),
            check_type: "cooling".into(),
            status: "passed".into(),
            details: "CRAC units nominal, return air 22 C, supply 16 C".into(),
            last_checked: "2026-06-11T10:00:00Z".into(),
        },
        ("DEFRA", "rack-space") => DatacenterSingleCheck {
            site: "DEFRA".into(),
            check_type: "rack-space".into(),
            status: "warning".into(),
            details: "12 rack units free across 3 racks (limited headroom)".into(),
            last_checked: "2026-06-11T10:00:00Z".into(),
        },
        ("GBLON", "power") => DatacenterSingleCheck {
            site: "GBLON".into(),
            check_type: "power".into(),
            status: "failed".into(),
            details: "UPS-B in bypass mode, PDU-3 overload alarm at 91%".into(),
            last_checked: "2026-06-11T09:30:00Z".into(),
        },
        _ => DatacenterSingleCheck {
            site: site.into(),
            check_type: check_type.into(),
            status: "not-checked".into(),
            details: "Check not yet executed for this site".into(),
            last_checked: "2026-06-11T00:00:00Z".into(),
        },
    }
}

pub fn datacenter_full_readiness_fallback(site: &str) -> DatacenterFullReadiness {
    let report = datacenter_site_report_fallback(site);
    DatacenterFullReadiness {
        site: report.site,
        checks_run: report.checks.len() as u32,
        results: report.checks,
    }
}

pub fn datacenter_sites_catalog_fallback() -> DatacenterSitesCatalog {
    DatacenterSitesCatalog {
        sites: vec![
            DatacenterSiteSummary {
                site: "DEFRA".into(),
                total_checks: 6,
                passed: 4,
                failed: 0,
                not_checked: 0,
            },
            DatacenterSiteSummary {
                site: "GBLON".into(),
                total_checks: 6,
                passed: 1,
                failed: 3,
                not_checked: 0,
            },
            DatacenterSiteSummary {
                site: "FRPAR".into(),
                total_checks: 6,
                passed: 4,
                failed: 0,
                not_checked: 2,
            },
        ],
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

#[cfg(all(test, feature = "ssr"))]
mod ssr_tests {
    use super::*;

    #[test]
    fn intake_fallback_vocabulary_matches_canonical_request_create_lists() {
        use crate::views::request_create::{
            ENVIRONMENT_OPTIONS, REQUEST_TYPE_OPTIONS, SITE_OPTIONS,
        };
        let form = request_intake_form_fallback();
        let field = |label: &str| {
            form.fields
                .iter()
                .find(|f| f.label == label)
                .unwrap_or_else(|| panic!("fallback must have a {label} field"))
        };

        let rt: Vec<&str> = REQUEST_TYPE_OPTIONS.iter().map(|(v, _)| *v).collect();
        assert_eq!(
            field("Request type").options,
            rt,
            "fallback request types drifted from canonical"
        );

        let sites: Vec<&str> = SITE_OPTIONS.iter().map(|(v, _)| *v).collect();
        assert_eq!(
            field("Site").options,
            sites,
            "fallback sites drifted from canonical"
        );

        let envs: Vec<&str> = ENVIRONMENT_OPTIONS.iter().map(|(v, _)| *v).collect();
        assert_eq!(
            field("Environment").options,
            envs,
            "fallback environments drifted from canonical"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_login_session_decodes_canonical_local_login_response() {
        // Canonical POST /api/auth/local/login 200 body — the seam both the
        // API and the portal test against.
        let body = r#"{"session_id":"3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b","user_id":"admin","display_name":"admin","roles":["PlatformAdmin"],"token_valid":true,"provider_mode":"local","expires_at":"2026-06-13T12:00:00+00:00"}"#;
        let login: ApiLoginSession = serde_json::from_str(body).expect("login body must decode");

        assert_eq!(login.session_id, "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b");
        assert_eq!(login.user_id, "admin");
        assert_eq!(login.display_name, "admin");
        assert_eq!(login.roles, vec!["PlatformAdmin".to_string()]);
        assert!(login.token_valid);
        assert_eq!(login.provider_mode, "local");

        let session = AuthSession::from(login);
        assert_eq!(session.user_id, "admin");
        assert!(session.token_valid);
        assert_eq!(session.provider_mode, "local");
        // The session id must never cross into the AuthSession that reaches
        // WASM: AuthSession has no session_id field by construction.
        let serialized = serde_json::to_value(&session).expect("session must serialize");
        assert!(serialized.get("session_id").is_none());
    }

    #[test]
    fn auth_session_mirrors_engine_serialization_field_for_field() {
        // Engine ryuki_engine::auth::AuthSession JSON shape (GET /api/auth/session).
        let body = r#"{"user_id":"operator","display_name":"operator","roles":["VMwareOperator","WintelLinuxOperator"],"token_valid":true,"provider_mode":"persisted-session"}"#;
        let session: AuthSession = serde_json::from_str(body).expect("session must decode");

        assert_eq!(session.user_id, "operator");
        assert_eq!(session.roles.len(), 2);
        assert!(session.token_valid);
        assert_eq!(session.provider_mode, "persisted-session");
    }

    #[test]
    fn all_app_roles_matches_rbac_role_catalog() {
        // ALL_APP_ROLES must stay in lockstep with the displayed RBAC catalog
        // so the create-token multiselect never offers an unknown role (the
        // API rejects those with UNKNOWN_ROLE) nor omits an assignable one.
        let catalog: Vec<String> = rbac_role_summary_fallbacks()
            .into_iter()
            .map(|role| role.name)
            .collect();
        let app_roles: Vec<String> = ALL_APP_ROLES.iter().map(|r| r.to_string()).collect();
        assert_eq!(app_roles, catalog);
    }

    #[test]
    fn admin_token_summary_decodes_without_hash_field() {
        // GET /api/admin/tokens element: hash redacted (omitted entirely).
        let body = r#"{"id":"3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b","name":"ci-deployer","owner_principal":"svc:ci","roles":["VMwareOperator"],"site_scope":"DEBER","environment_scope":null,"token_valid":false,"created_at":"2026-06-13T10:00:00Z","expires_at":null,"last_used_at":null,"revoked_at":null}"#;
        let token: AdminTokenSummary = serde_json::from_str(body).expect("token row must decode");

        assert_eq!(token.id, "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b");
        assert_eq!(token.name, "ci-deployer");
        assert_eq!(token.owner_principal, "svc:ci");
        assert_eq!(token.roles, vec!["VMwareOperator".to_string()]);
        assert_eq!(token.site_scope.as_deref(), Some("DEBER"));
        assert!(!token.token_valid);

        // The portal type has no field that could carry a hash; even a body
        // that smuggled one in is dropped on deserialize.
        let with_hash = r#"{"id":"x","name":"n","token_hash":"deadbeef"}"#;
        let token: AdminTokenSummary = serde_json::from_str(with_hash).expect("decodes");
        let reserialized = serde_json::to_value(&token).expect("serializes");
        assert!(reserialized.get("token_hash").is_none());
    }

    #[test]
    fn create_token_result_carries_one_time_secret_and_redacted_metadata() {
        // Build the one-time secret at runtime from the bare prefix so no
        // full `ryk_…`-shaped literal is committed to the source tree.
        let token = format!("{}{}", "ryk_", "generated-at-runtime");
        let result = CreateTokenResult {
            token,
            metadata: AdminTokenSummary {
                id: "abc".to_string(),
                name: "ci-deployer".to_string(),
                token_valid: false,
                ..AdminTokenSummary::default()
            },
        };
        let value = serde_json::to_value(&result).expect("create result serializes");
        assert!(value.get("token").is_some());
        // The metadata sub-object never carries a hash field.
        assert!(value
            .get("metadata")
            .and_then(|m| m.get("token_hash"))
            .is_none());
    }

    #[test]
    fn admin_session_summary_decodes_active_session_row() {
        let body = r#"{"id":"3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b","user_id":"admin","display_name":"Admin","roles":["PlatformAdmin"],"provider":"local","created_at":"2026-06-13T10:00:00Z","expires_at":"2026-06-14T10:00:00Z"}"#;
        let session: AdminSessionSummary =
            serde_json::from_str(body).expect("session row must decode");

        assert_eq!(session.user_id, "admin");
        assert_eq!(session.provider.as_deref(), Some("local"));
        assert_eq!(session.roles, vec!["PlatformAdmin".to_string()]);
    }

    #[test]
    fn api_request_summary_decodes_list_dto_without_stage_or_environment() {
        // GET /api/requests element shape: no stage, no environment.
        let body = r#"{"request_id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","request_type":"VM","status":"intake","name":"srv-app-01","site":"site-alpha","created_at":"2026-06-12T10:00:00+00:00"}"#;
        let summary: ApiRequestSummary =
            serde_json::from_str(body).expect("list DTO must decode with defaults");

        assert_eq!(summary.stage, "");
        assert_eq!(summary.environment, "");

        let mapped = RequestSummary::from(summary);
        assert_eq!(mapped.id, "7c9e6679-7425-40de-944b-e07fc1f90ae7");
        // Missing stage falls back to the status signal.
        assert_eq!(mapped.stage, "intake");
        assert_eq!(mapped.created, "2026-06-12T10:00:00+00:00");
    }

    #[test]
    fn api_request_detail_maps_to_portal_detail_with_honest_timeline() {
        // GET /api/requests/{id} shape, including memory_gb and the API
        // stage vocabulary ("validate" rather than "validated").
        let body = r#"{"request_id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","request_type":"VM","status":"validated","stage":"validate","site":"site-alpha","environment":"prod","name":"srv-app-01","cpu":4,"memory_gb":16,"justification":"Need capacity","created_by":"admin","created_at":"2026-06-12T10:00:00+00:00","updated_at":"2026-06-12T11:00:00+00:00"}"#;
        let detail: ApiRequestDetail = serde_json::from_str(body).expect("detail must decode");
        let mapped = RequestDetail::from(detail);

        assert_eq!(mapped.memory, 16);
        assert_eq!(mapped.stage, "validated");
        assert_eq!(
            mapped.actions_available,
            vec!["plan".to_string(), "cancel".to_string()]
        );
        assert_eq!(mapped.timeline.len(), 1);
        assert_eq!(mapped.timeline[0].stage, "validated");
        assert_eq!(mapped.timeline[0].timestamp, "2026-06-12T11:00:00+00:00");
        assert_eq!(
            mapped.timeline[0].description,
            "Current lifecycle stage (audit trail loads separately)"
        );
    }

    #[test]
    fn api_request_detail_renders_terminal_states_from_status() {
        // A rejected request keeps stage='approve' but status='rejected'; the
        // portal must display the terminal stage and offer no further actions.
        let rejected = r#"{"request_id":"r1","request_type":"VM","status":"rejected","stage":"approve","site":"s","environment":"prod","name":"n","cpu":2,"memory_gb":8,"justification":null,"created_by":"req","created_at":"t","updated_at":"t2"}"#;
        let detail: ApiRequestDetail = serde_json::from_str(rejected).expect("decode");
        let mapped = RequestDetail::from(detail);
        assert_eq!(mapped.stage, "rejected");
        assert!(mapped.actions_available.is_empty());

        let cancelled = r#"{"request_id":"r2","request_type":"VM","status":"cancelled","stage":"cancel","site":"s","environment":"prod","name":"n","cpu":2,"memory_gb":8,"justification":null,"created_by":"req","created_at":"t","updated_at":"t2"}"#;
        let detail: ApiRequestDetail = serde_json::from_str(cancelled).expect("decode");
        let mapped = RequestDetail::from(detail);
        assert_eq!(mapped.stage, "cancelled");
        assert!(mapped.actions_available.is_empty());
    }

    #[test]
    fn actions_for_stage_offers_reject_at_decision_point_and_cancel_pre_execution() {
        // reject is only offered at the approval decision point.
        assert!(actions_for_stage("planned").contains(&"reject".to_string()));
        assert!(!actions_for_stage("intake").contains(&"reject".to_string()));
        assert!(!actions_for_stage("approved").contains(&"reject".to_string()));

        // cancel is offered on every non-terminal pre-execution stage.
        for stage in [
            "draft",
            "intake",
            "validated",
            "planned",
            "approved",
            "locked",
        ] {
            assert!(
                actions_for_stage(stage).contains(&"cancel".to_string()),
                "{stage} should offer cancel"
            );
        }
        // ...but not once executing/verifying or in a terminal state.
        assert!(!actions_for_stage("executed").contains(&"cancel".to_string()));
        assert!(actions_for_stage("rejected").is_empty());
        assert!(actions_for_stage("cancelled").is_empty());
        // A fully-verified/completed request is terminal: no stray actions.
        // Regression guard — these previously fell through to the wildcard and
        // wrongly offered "validate" on a finished request.
        assert!(actions_for_stage("verified").is_empty());
        assert!(actions_for_stage("completed").is_empty());
    }

    #[test]
    fn api_audit_trail_flattens_enveloped_and_bare_shapes() {
        // Enveloped dry-run trail: durable=false propagates to every row, and
        // the reject reason is lifted out of detail.reason.
        let enveloped = r#"{"durable":false,"source":"dry-run","events":[{"action":"request.reject","actor_display":"Approver","actor_principal":"approver","from_stage":"plan","to_stage":"approve","to_status":"rejected","occurred_at":"t","detail":{"reason":"insufficient capacity"}}]}"#;
        let trail: ApiAuditTrail = serde_json::from_str(enveloped).expect("decode envelope");
        let rows = trail.into_rows();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].durable);
        assert_eq!(rows[0].action, "request.reject");
        assert_eq!(rows[0].actor_display, "Approver");
        assert_eq!(rows[0].reason.as_deref(), Some("insufficient capacity"));

        // Bare array shape defaults durable=true and tolerates absent reason.
        let bare = r#"[{"action":"request.approve","actor_principal":"approver","to_stage":"approve","to_status":"approved","occurred_at":"t","detail":{}}]"#;
        let trail: ApiAuditTrail = serde_json::from_str(bare).expect("decode bare");
        let rows = trail.into_rows();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].durable);
        assert_eq!(rows[0].reason, None);
        assert_eq!(rows[0].actor_display, "");
    }

    #[test]
    fn api_audit_trail_decodes_real_entries_key_and_global_fields() {
        // REGRESSION: the API serializes the rows under `entries` (not the
        // legacy `events`); decoding the real envelope used to silently yield
        // an empty trail. It must now flatten the rows AND carry the global
        // activity-feed fields (request_id, actor_roles, outcome) so each row
        // can deep-link and show who acted under which roles.
        let real = r#"{"durable":true,"source":"database","limit":50,"offset":0,"total":1,"entries":[{"action":"request.lock","actor_display":"Approver DB","actor_principal":"approver-db","actor_roles":["DatacenterApprover"],"from_stage":"approve","to_stage":"lock","to_status":"locked","occurred_at":"t","request_id":"req-7","outcome":"applied","detail":{}}]}"#;
        let trail: ApiAuditTrail =
            serde_json::from_str(real).expect("decode real entries envelope");
        let rows = trail.into_rows();
        assert_eq!(rows.len(), 1, "entries key must flatten, not yield empty");
        assert!(rows[0].durable);
        assert_eq!(rows[0].action, "request.lock");
        assert_eq!(rows[0].request_id.as_deref(), Some("req-7"));
        assert_eq!(rows[0].actor_roles, vec!["DatacenterApprover".to_string()]);
        assert_eq!(rows[0].outcome.as_deref(), Some("applied"));
    }

    #[test]
    fn api_request_detail_tolerates_null_justification() {
        let body = r#"{"request_id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","request_type":"VM","status":"intake","stage":"intake","site":"site-alpha","environment":"dev","name":"srv-app-02","cpu":2,"memory_gb":8,"justification":null,"created_by":null,"created_at":"2026-06-12T10:00:00+00:00","updated_at":"2026-06-12T10:00:00+00:00"}"#;
        let detail: ApiRequestDetail = serde_json::from_str(body).expect("detail must decode");
        let mapped = RequestDetail::from(detail);

        assert_eq!(mapped.justification, "");
        assert_eq!(
            mapped.actions_available,
            vec!["validate".to_string(), "cancel".to_string()]
        );
    }

    #[test]
    fn api_request_detail_decodes_legacy_scalar_only_json() {
        // The older scalar-only detail JSON (no criticality/requester/owner/
        // stages/plan/payload) must still decode: the additive fields default
        // and cpu/memory remain present. This pins backward compatibility.
        let body = r#"{"request_id":"r1","request_type":"VM","status":"intake","stage":"intake","site":"s","environment":"prod","name":"n","cpu":4,"memory_gb":16,"justification":"j","created_by":"admin","created_at":"t","updated_at":"t2"}"#;
        let detail: ApiRequestDetail = serde_json::from_str(body).expect("legacy detail decodes");
        let mapped = RequestDetail::from(detail);

        assert_eq!(mapped.cpu, 4);
        assert_eq!(mapped.memory, 16);
        // Absent persisted-state fields surface as empty, never fabricated.
        assert_eq!(mapped.criticality, "");
        assert_eq!(mapped.requester, "");
        assert_eq!(mapped.owner, "");
        assert_eq!(mapped.plan, "");
        assert!(mapped.approval_route.is_empty());
        assert!(mapped.stages.is_empty());
        assert!(mapped.payload_fields.is_empty());
    }

    #[test]
    fn api_request_detail_surfaces_persisted_state() {
        // The now-real detail carries criticality/requester/owner, a real plan
        // (not the old fabricated DRY-RUN string), an ordered approval route,
        // and persisted stages with the API action-name vocabulary normalized.
        // `plan` is the API's REAL shape: a JSON array of Stage objects (the
        // produced plan), NOT a string. The portal extracts the human-readable
        // summary from the plan stage's `dry-run-plan` evidence. (Feeding a
        // string here previously masked a hard deserialization failure for any
        // planned-or-later request.)
        let body = r#"{"request_id":"r1","request_type":"server-deployment","status":"planned","stage":"plan","site":"s","environment":"prod","name":"srv-01","cpu":8,"memory_gb":32,"justification":"j","created_by":"requester","created_at":"t","updated_at":"t2","criticality":"critical","requester":"requester","owner":"platform-team","plan":[{"name":"plan","status":"Completed","started_at":"t1","completed_at":"t2","evidence":[{"key":"dry-run-plan","value":"Provision and register srv-01."}]}],"approval_route":["datacenter-approver","security"],"stages":[{"name":"validate","status":"Completed","started_at":"t0","completed_at":"t1"},{"name":"plan","status":"InProgress","started_at":"t2","completed_at":null}]}"#;
        let detail: ApiRequestDetail = serde_json::from_str(body).expect("detail decodes");
        let mapped = RequestDetail::from(detail);

        assert_eq!(mapped.criticality, "critical");
        assert_eq!(mapped.requester, "requester");
        assert_eq!(mapped.owner, "platform-team");
        assert_eq!(mapped.plan, "Provision and register srv-01.");
        assert_eq!(
            mapped.approval_route,
            vec!["datacenter-approver".to_string(), "security".to_string()]
        );
        assert_eq!(mapped.stages.len(), 2);
        // Action-name "validate" is normalized to the display state.
        assert_eq!(mapped.stages[0].name, "validated");
        assert_eq!(mapped.stages[0].status, "Completed");
        // The completed timestamp is preferred over the started timestamp.
        assert_eq!(mapped.stages[0].timestamp, "t1");
        // An in-progress stage with no completed_at falls back to started_at.
        assert_eq!(mapped.stages[1].name, "planned");
        assert_eq!(mapped.stages[1].timestamp, "t2");
    }

    #[test]
    fn api_request_detail_decodes_array_plan_and_null_plan() {
        // Regression: the API serializes `plan` as Vec<Stage> (array) or null,
        // never a string. Both must decode (a string-typed field would hard-
        // fail the whole detail). An un-planned request yields an empty plan.
        let unplanned = r#"{"request_id":"r2","request_type":"zabbix-onboarding","status":"intake","stage":"intake","site":"s","environment":"prod","name":"host-1","created_at":"t","updated_at":"t","plan":null}"#;
        let detail: ApiRequestDetail = serde_json::from_str(unplanned).expect("null plan decodes");
        assert_eq!(RequestDetail::from(detail).plan, "");

        // A planned request with the array shape extracts the evidence text.
        let planned = r#"{"request_id":"r3","request_type":"server-deployment","status":"planned","stage":"plan","site":"s","environment":"prod","name":"srv-9","created_at":"t","updated_at":"t","plan":[{"name":"plan","status":"Completed","evidence":[{"key":"dry-run-plan","value":"Provision srv-9."}]}]}"#;
        let detail: ApiRequestDetail = serde_json::from_str(planned).expect("array plan decodes");
        assert_eq!(RequestDetail::from(detail).plan, "Provision srv-9.");
    }

    #[test]
    fn plan_summary_text_handles_shapes() {
        assert_eq!(plan_summary_text(&serde_json::Value::Null), "");
        assert_eq!(plan_summary_text(&serde_json::json!([])), "");
        // No dry-run-plan evidence -> empty.
        assert_eq!(
            plan_summary_text(&serde_json::json!([{"name":"plan","evidence":[]}])),
            ""
        );
    }

    #[test]
    fn api_request_detail_flattens_non_vm_payload_fields() {
        // A non-VM request type (patch-maintenance) carries no cpu/memory but
        // a per-type payload; the portal flattens it into display rows so the
        // type surfaces its real fields instead of assuming the VM shape.
        let body = r#"{"request_id":"r1","request_type":"patch-maintenance","status":"intake","stage":"intake","site":"s","environment":"prod","name":"wave-7","created_at":"t","updated_at":"t2","payload":{"patch_baseline":"2026-06","maintenance_window":"02:00-04:00","reboot_required":true,"target_hosts":["h1","h2"]}}"#;
        let detail: ApiRequestDetail = serde_json::from_str(body).expect("detail decodes");
        // cpu/memory default to 0 for non-VM types.
        assert_eq!(detail.cpu, 0);
        assert_eq!(detail.memory_gb, 0);
        let mapped = RequestDetail::from(detail);

        // Keys are humanized and present (order follows the JSON map ordering).
        let labels: Vec<&str> = mapped
            .payload_fields
            .iter()
            .map(|f| f.label.as_str())
            .collect();
        assert!(labels.contains(&"Patch baseline"));
        assert!(labels.contains(&"Maintenance window"));
        assert!(labels.contains(&"Reboot required"));
        assert!(labels.contains(&"Target hosts"));

        let find = |label: &str| {
            mapped
                .payload_fields
                .iter()
                .find(|f| f.label == label)
                .map(|f| f.value.clone())
                .unwrap_or_default()
        };
        // String values drop their quotes; scalars/arrays render compactly.
        assert_eq!(find("Patch baseline"), "2026-06");
        assert_eq!(find("Reboot required"), "true");
        assert_eq!(find("Target hosts"), r#"["h1","h2"]"#);
    }

    #[test]
    fn flatten_payload_fields_ignores_non_object_payloads() {
        // The older absent payload (Null) and any scalar payload yield no rows
        // rather than panicking.
        assert!(flatten_payload_fields(&serde_json::Value::Null).is_empty());
        assert!(flatten_payload_fields(&serde_json::json!("scalar")).is_empty());
        assert!(flatten_payload_fields(&serde_json::json!(42)).is_empty());
    }

    #[test]
    fn normalize_api_stage_maps_action_names_to_display_states() {
        for (api, portal) in [
            ("intake", "intake"),
            ("validate", "validated"),
            ("plan", "planned"),
            ("approve", "approved"),
            ("lock", "locked"),
            ("execute", "executed"),
            ("verify", "verified"),
            ("validated", "validated"),
            ("failed", "failed"),
        ] {
            assert_eq!(normalize_api_stage(api), portal);
        }
    }

    /// Covers the "cancel" → "cancelled" mapping and the pass-through cases for
    /// already-normalized and terminal vocabulary values.  The function must be
    /// idempotent for any value that is already in portal vocabulary.
    #[test]
    fn normalize_api_stage_covers_cancel_and_pass_through_inputs() {
        // cancel is an action-name that must map to the portal vocabulary.
        assert_eq!(normalize_api_stage("cancel"), "cancelled");

        // Already-normalized portal vocabulary must pass through unchanged.
        for stage in [
            "intake",
            "completed",
            "rejected",
            "cancelled",
            "planned",
            "approved",
            "locked",
        ] {
            assert_eq!(
                normalize_api_stage(stage),
                stage,
                "normalize_api_stage({stage:?}) must pass through as-is"
            );
        }
    }

    #[test]
    fn platform_summary_context_decodes_nested_camel_case_payload() {
        // GET /api/platform/summary shape (nested localAuthorization block).
        let body = r#"{"productName":"Ryuki Infrastructure Platform","lifecycleStages":["intake"],"components":["portal-ui"],"browserIsolation":true,"localAuthorization":{"authenticationMode":"local","configuredForProduction":false,"entraGroupsConfigured":false,"roleHeader":"X-Ryuki-Local-Role","requiredProductionProvider":"Microsoft Entra ID"}}"#;
        let summary: ApiPlatformSummary =
            serde_json::from_str(body).expect("platform summary must decode");
        let context = PlatformSummaryContext::from(summary);

        assert_eq!(context.product_name, "Ryuki Infrastructure Platform");
        assert_eq!(context.authentication_mode, "local");
        assert!(!context.entra_groups_configured);
    }

    #[test]
    fn platform_summary_context_fallback_is_labeled_static() {
        let fallback = platform_summary_context_fallback();
        assert_eq!(fallback.authentication_mode, "static-dry-run");
        assert!(!fallback.entra_groups_configured);
    }

    #[test]
    fn platform_health_tolerates_engine_payload_shape() {
        // Engine health_monitor JSON: PascalCase status enums, extra `source`
        // fields, and (defensively) a missing `components` array.
        let body = r#"{"overall_status":"Healthy","checks":[{"name":"database","component":"platform-db","status":"Healthy","source":"dependency-backed","last_check":"2026-06-12T10:00:00+00:00","message":"Database reachable"}],"timestamp":"2026-06-12T10:00:00+00:00","source":"dependency-backed"}"#;
        let health: PlatformHealth =
            serde_json::from_str(body).expect("engine health payload must decode");

        assert_eq!(health.overall_status, "Healthy");
        assert!(health.components.is_empty());
        assert_eq!(health.checks.len(), 1);
        assert_eq!(health.checks[0].component, "platform-db");
    }

    #[test]
    fn request_detail_fallback_reuses_stage_action_mapping() {
        let detail = request_detail_fallback("REQ-001");
        assert_eq!(detail.stage, "intake");
        assert_eq!(detail.actions_available, actions_for_stage("intake"));
    }

    #[test]
    fn degraded_auth_session_grants_no_roles() {
        let session = degraded_auth_session();
        assert!(session.roles.is_empty());
        assert!(!session.token_valid);
        assert_eq!(session.provider_mode, "degraded-static-fallback");
    }

    // ─── Stage evidence mapping ───────────────────────────────────────────────

    /// `ApiRequestDetail::from` maps stage evidence into `PersistedStage.evidence`
    /// when the API payload includes evidence items.
    #[test]
    fn from_api_request_detail_maps_stage_evidence() {
        let body = r#"{
            "request_id":"r1","request_type":"server-deployment","status":"planned",
            "stage":"plan","site":"s","environment":"prod","name":"srv-01",
            "cpu":2,"memory_gb":4,"justification":"j","created_by":"op",
            "created_at":"t","updated_at":"t2",
            "stages":[
                {
                    "name":"plan","status":"Completed",
                    "started_at":"t1","completed_at":"t2",
                    "evidence":[
                        {"key":"terraform-plan","value":"Plan: 2 to add.","redacted":false,"evidence_type":"Plan"}
                    ]
                },
                {
                    "name":"verify","status":"Completed",
                    "started_at":"t3","completed_at":"t4",
                    "evidence":[
                        {"key":"ansible-check","value":"PLAY ok=3 changed=0","redacted":false,"evidence_type":"Summary"}
                    ]
                }
            ]
        }"#;
        let detail: ApiRequestDetail = serde_json::from_str(body).expect("detail must decode");
        let mapped = RequestDetail::from(detail);

        // The plan stage (normalized to "planned") must carry terraform-plan evidence.
        let plan_stage = mapped
            .stages
            .iter()
            .find(|s| s.name == "planned")
            .expect("planned stage must be present");
        assert_eq!(plan_stage.evidence.len(), 1);
        assert_eq!(plan_stage.evidence[0].key, "terraform-plan");
        assert_eq!(plan_stage.evidence[0].value, "Plan: 2 to add.");
        assert!(!plan_stage.evidence[0].redacted);

        // The verify stage must carry ansible-check evidence.
        let verify_stage = mapped
            .stages
            .iter()
            .find(|s| s.name == "verified")
            .expect("verified stage must be present");
        assert_eq!(verify_stage.evidence.len(), 1);
        assert_eq!(verify_stage.evidence[0].key, "ansible-check");
        assert_eq!(verify_stage.evidence[0].value, "PLAY ok=3 changed=0");
    }

    /// Redacted evidence items decode with `redacted: true` and carry the safe
    /// display value, never the raw secret.
    #[test]
    fn from_api_request_detail_maps_redacted_stage_evidence() {
        let body = r#"{
            "request_id":"r2","request_type":"server-deployment","status":"planned",
            "stage":"plan","site":"s","environment":"prod","name":"srv-02",
            "created_at":"t","updated_at":"t",
            "stages":[
                {
                    "name":"plan","status":"Completed",
                    "evidence":[
                        {"key":"terraform-plan","value":"***REDACTED***","redacted":true,"evidence_type":"Plan"}
                    ]
                }
            ]
        }"#;
        let detail: ApiRequestDetail = serde_json::from_str(body).expect("detail must decode");
        let mapped = RequestDetail::from(detail);

        let plan_stage = mapped
            .stages
            .iter()
            .find(|s| s.name == "planned")
            .expect("planned stage must be present");
        assert_eq!(plan_stage.evidence.len(), 1);
        let ev = &plan_stage.evidence[0];
        assert_eq!(ev.key, "terraform-plan");
        // The API already replaced the raw value with ***REDACTED***; the portal
        // must surface exactly what the API sent (the redacted form).
        assert_eq!(ev.value, "***REDACTED***");
        assert!(ev.redacted);
    }

    /// A detail with no stage evidence decodes cleanly — evidence defaults to
    /// empty Vec so older API responses without the field still work.
    #[test]
    fn from_api_request_detail_empty_evidence_defaults_ok() {
        // Existing test body from api_request_detail_maps_to_portal_detail_with_honest_timeline
        let body = r#"{"request_id":"r3","request_type":"VM","status":"validated","stage":"validate","site":"site-alpha","environment":"prod","name":"srv-app-01","cpu":4,"memory_gb":16,"justification":"Need capacity","created_by":"admin","created_at":"2026-06-12T10:00:00+00:00","updated_at":"2026-06-12T11:00:00+00:00"}"#;
        let detail: ApiRequestDetail = serde_json::from_str(body).expect("detail must decode");
        let mapped = RequestDetail::from(detail);
        // No stages in payload → stages is empty, no evidence.
        assert!(mapped.stages.is_empty());
    }

    /// `plan_summary_text` prefers the "terraform-plan" evidence key over the
    /// legacy "dry-run-plan" key when both are present.
    #[test]
    fn plan_summary_text_prefers_terraform_plan_key() {
        let plan = serde_json::json!([{
            "name": "plan",
            "evidence": [
                {"key": "dry-run-plan", "value": "SIMULATED"},
                {"key": "terraform-plan", "value": "Plan: 2 to add, 0 to change, 0 to destroy."}
            ]
        }]);
        let result = plan_summary_text(&plan);
        assert_eq!(
            result, "Plan: 2 to add, 0 to change, 0 to destroy.",
            "terraform-plan must be preferred over dry-run-plan"
        );
    }

    /// `plan_summary_text` falls back to "dry-run-plan" when "terraform-plan"
    /// is absent (backward compatibility with pre-runner requests).
    #[test]
    fn plan_summary_text_falls_back_to_dry_run_plan_key() {
        let plan = serde_json::json!([{
            "name": "plan",
            "evidence": [
                {"key": "dry-run-plan", "value": "Simulated plan output."}
            ]
        }]);
        let result = plan_summary_text(&plan);
        assert_eq!(result, "Simulated plan output.");
    }
}
