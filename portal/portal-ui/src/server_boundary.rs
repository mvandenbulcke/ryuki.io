use crate::api::{
    activity_operation_queue_path, admin_feature_flag_governance_path,
    admin_platform_settings_path, admin_rbac_roles_path, admin_worker_capability_path,
    approval_decision_readiness_path, auth_login_path, auth_logout_path, auth_session_path,
    auth_status_path, boundary_status_path, catalog_offerings_path, catalog_recommendations_path,
    catalog_request_form_path, cluster_capacity_admission_path, cmdb_file_exchange_path,
    cmdb_reconciliation_path, cmdb_relationship_graph_path, datacenter_check_cooling_path,
    datacenter_check_power_path, datacenter_check_rack_space_path,
    datacenter_check_switchports_path, datacenter_failing_checks_path,
    datacenter_full_readiness_path, datacenter_readiness_score_path, datacenter_site_report_path,
    datacenter_sites_path, dry_run_plan_path, emergency_change_path,
    evidence_compliance_dashboard_path, evidence_export_retention_path, evidence_summary_path,
    inventory_ownership_risk_path, inventory_resource_overview_path, operation_runs_path,
    operations_platform_health_path, operations_runbook_launch_path, platform_health_path,
    platform_status_path, platform_summary_path, policy_outcomes_path, request_approve_path,
    request_create_path, request_detail_path, request_execute_path,
    request_intake_form_preview_path, request_intake_path, request_list_path, request_lock_path,
    request_plan_path, request_preflight_path, request_validate_path, request_verify_path,
    same_origin_api_path, secret_references_path, shift_queue_path, site_catalog_path,
    ApiPathError,
};
use crate::api_client::{
    capacity_admission_resource, cmdb_file_exchange_resource, cmdb_reconciliation_resource,
    cmdb_relationship_graph_resource, dry_run_plan_resource, evidence_summary_resource,
    inventory_resource_overview_resource, operation_runs_resource, policy_outcomes_resource,
    request_intake_resource, secret_references_resource, ApiResource,
};
#[cfg(feature = "ssr")]
use crate::models::request_intake_form_fallback;
use crate::models::{
    activity_queue_fallbacks, capacity_admission_fallbacks, cmdb_file_exchange_fallbacks,
    cmdb_reconciliation_fallbacks, cmdb_relationship_fallbacks, datacenter_failing_checks_fallback,
    datacenter_full_readiness_fallback, datacenter_readiness_score_fallback,
    datacenter_single_check_fallback, datacenter_site_report_fallback,
    datacenter_sites_catalog_fallback, dry_run_plan_fallbacks, evidence_summary_fallbacks,
    inventory_resource_fallbacks, operation_run_fallbacks, policy_guardrail_fallbacks,
    policy_outcome_fallbacks, request_detail_fallback, request_intake_fallbacks,
    request_summary_fallbacks, secret_reference_catalog_fallback, secret_reference_fallbacks,
    ActivityQueueSummary, AuthSession, CapacityAdmissionSummary, CmdbFileExchangeSummary,
    CmdbReconciliationSummary, CmdbRelationshipSummary, CreateRequestPayload,
    DatacenterFailingChecksSummary, DatacenterFullReadiness, DatacenterReadinessScore,
    DatacenterSingleCheck, DatacenterSiteReport, DatacenterSitesCatalog, DryRunPlanSummary,
    EvidenceSummary, InventoryResourceSummary, LoginResponse, OperationRunSummary, PlatformHealth,
    PlatformSettingsSummary, PlatformStatus, PolicyGuardrailSummary, PolicyOutcome,
    RbacRoleSummary, RequestDetail, RequestIntakeForm, RequestIntakeSummary, RequestSummary,
    SecretReferenceSummary, StageActionResponse,
};
#[cfg(feature = "ssr")]
use crate::models::{
    auth_session_fallback, platform_health_fallback, platform_settings_summary_fallback,
    platform_status_fallback, rbac_role_summary_fallbacks,
};
use leptos::prelude::{server, ServerFnError};
use ryuki_core::types::{BoundaryStatus, ExecutionMode};
use serde::{Deserialize, Serialize};

pub const CORE_PLATFORM_READ_PLAN_LABELS: &[&str] = &[
    "request-intake",
    "dry-run-plan",
    "inventory-resource-overview",
    "capacity-admission",
    "secret-references",
    "policy-outcomes",
    "evidence-summary",
    "operation-runs",
];

pub const PORTAL_ROUTE_STATE_SERVER_FUNCTION_PATH: &str = "/portal/api/route-state";

const ALLOWED_PORTAL_API_PATHS: &[fn() -> &'static str] = &[
    platform_summary_path,
    request_intake_path,
    request_preflight_path,
    request_intake_form_preview_path,
    request_list_path,
    request_create_path,
    dry_run_plan_path,
    inventory_resource_overview_path,
    inventory_ownership_risk_path,
    cluster_capacity_admission_path,
    catalog_offerings_path,
    catalog_recommendations_path,
    catalog_request_form_path,
    site_catalog_path,
    approval_decision_readiness_path,
    activity_operation_queue_path,
    shift_queue_path,
    emergency_change_path,
    cmdb_file_exchange_path,
    cmdb_reconciliation_path,
    cmdb_relationship_graph_path,
    evidence_export_retention_path,
    evidence_compliance_dashboard_path,
    operations_runbook_launch_path,
    operations_platform_health_path,
    admin_worker_capability_path,
    admin_feature_flag_governance_path,
    admin_rbac_roles_path,
    admin_platform_settings_path,
    secret_references_path,
    policy_outcomes_path,
    evidence_summary_path,
    operation_runs_path,
    datacenter_readiness_score_path,
    datacenter_site_report_path,
    datacenter_failing_checks_path,
    datacenter_check_power_path,
    datacenter_check_cooling_path,
    datacenter_check_rack_space_path,
    datacenter_check_switchports_path,
    datacenter_full_readiness_path,
    datacenter_sites_path,
    boundary_status_path,
    platform_status_path,
    platform_health_path,
    auth_status_path,
    auth_login_path,
    auth_logout_path,
    auth_session_path,
];

fn execution_mode_label(mode: &ExecutionMode) -> &'static str {
    match mode {
        ExecutionMode::StaticDryRun => "static-dry-run",
        ExecutionMode::LiveProvider => "live-provider",
        ExecutionMode::Mock => "mock",
    }
}

fn is_allowed_request_lifecycle_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/requests/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let Some(request_id) = segments.next() else {
        return false;
    };
    if request_id.is_empty()
        || request_id == "."
        || request_id == ".."
        || request_id.contains("..")
        || request_id.contains("\\")
        || request_id.contains('?')
        || request_id.contains('#')
        || request_id.contains("://")
        || request_id.starts_with("//")
        || !request_id
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || matches!(char, '-' | '_'))
    {
        return false;
    }
    if matches!(
        request_id,
        "detail" | "validate" | "plan" | "approve" | "lock" | "execute" | "verify"
    ) {
        return false;
    }
    matches!(
        (segments.next(), segments.next()),
        (None, None)
            | (Some("validate"), None)
            | (Some("plan"), None)
            | (Some("approve"), None)
            | (Some("lock"), None)
            | (Some("execute"), None)
            | (Some("verify"), None)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalBoundaryError {
    ApiPath(ApiPathError),
    OutsidePortalAllowlist,
}

impl From<ApiPathError> for PortalBoundaryError {
    fn from(error: ApiPathError) -> Self {
        Self::ApiPath(error)
    }
}

impl std::fmt::Display for PortalBoundaryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiPath(_) => formatter.write_str("portal API path failed same-origin guard"),
            Self::OutsidePortalAllowlist => {
                formatter.write_str("portal API path is outside the server boundary allowlist")
            }
        }
    }
}

impl std::error::Error for PortalBoundaryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalServerBoundary {
    pub api_boundary: &'static str,
    pub boundary_status: BoundaryStatus,
}

impl PortalServerBoundary {
    pub fn static_dry_run() -> Self {
        Self {
            api_boundary: "same-origin-platform-api",
            boundary_status: BoundaryStatus::default(),
        }
    }

    pub fn validate_platform_api_path<'a>(
        &self,
        path: &'a str,
    ) -> Result<&'a str, PortalBoundaryError> {
        let guarded = same_origin_api_path(path)?;
        if ALLOWED_PORTAL_API_PATHS
            .iter()
            .any(|allowed| allowed() == guarded)
        {
            return Ok(guarded);
        }
        Err(PortalBoundaryError::OutsidePortalAllowlist)
    }

    pub fn validate_request_lifecycle_api_path<'a>(
        &self,
        path: &'a str,
    ) -> Result<&'a str, PortalBoundaryError> {
        let guarded = same_origin_api_path(path)?;
        if is_allowed_request_lifecycle_path(guarded) {
            return Ok(guarded);
        }
        Err(PortalBoundaryError::OutsidePortalAllowlist)
    }

    pub fn platform_api_config(&self) -> PortalPlatformApiConfig {
        PortalPlatformApiConfig {
            route_base: "/api/",
            source: "static-dry-run-config",
            external_base_allowed: false,
        }
    }

    pub fn plan_platform_api_read<T>(
        &self,
        resource: ApiResource<T>,
    ) -> Result<PortalPlatformReadPlan, PortalBoundaryError> {
        let path = self.validate_platform_api_path(resource.same_origin_path()?)?;
        let config = self.platform_api_config();
        Ok(PortalPlatformReadPlan {
            resource_label: resource.label(),
            path,
            route_base: config.route_base,
            config_source: config.source,
            api_boundary: self.api_boundary,
            execution_mode: execution_mode_label(&self.boundary_status.execution_mode),
            server_side_only: true,
            http_request_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
            safe_summary: "Portal platform API read is planned as static-dry-run metadata only",
        })
    }

    pub fn plan_core_platform_reads(
        &self,
    ) -> Result<[PortalPlatformReadPlan; 8], PortalBoundaryError> {
        Ok([
            self.plan_platform_api_read(request_intake_resource())?,
            self.plan_platform_api_read(dry_run_plan_resource())?,
            self.plan_platform_api_read(inventory_resource_overview_resource())?,
            self.plan_platform_api_read(capacity_admission_resource())?,
            self.plan_platform_api_read(secret_references_resource())?,
            self.plan_platform_api_read(policy_outcomes_resource())?,
            self.plan_platform_api_read(evidence_summary_resource())?,
            self.plan_platform_api_read(operation_runs_resource())?,
        ])
    }

    pub fn safe_failure_summary(&self) -> PortalSafeFailure {
        PortalSafeFailure {
            safe_summary: "Portal server boundary blocked unsafe data exposure",
            retry_allowed: false,
            evidence_export_allowed: false,
            raw_payload_allowed: false,
            stack_trace_allowed: false,
        }
    }

    pub fn static_read_plans() -> Result<[PortalPlatformReadPlan; 8], PortalBoundaryError> {
        Self::static_dry_run().plan_core_platform_reads()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalPlatformApiConfig {
    pub route_base: &'static str,
    pub source: &'static str,
    pub external_base_allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalPlatformReadPlan {
    pub resource_label: &'static str,
    pub path: &'static str,
    pub route_base: &'static str,
    pub config_source: &'static str,
    pub api_boundary: &'static str,
    pub execution_mode: &'static str,
    pub server_side_only: bool,
    pub http_request_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
    pub safe_summary: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalSafeFailure {
    pub safe_summary: &'static str,
    pub retry_allowed: bool,
    pub evidence_export_allowed: bool,
    pub raw_payload_allowed: bool,
    pub stack_trace_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalBoundaryReadPlanSnapshot {
    pub resource_label: String,
    pub path: String,
    pub route_base: String,
    pub api_boundary: String,
    pub execution_mode: String,
    pub server_side_only: bool,
    pub http_request_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
    pub safe_summary: String,
}

impl From<PortalPlatformReadPlan> for PortalBoundaryReadPlanSnapshot {
    fn from(plan: PortalPlatformReadPlan) -> Self {
        Self {
            resource_label: plan.resource_label.to_string(),
            path: plan.path.to_string(),
            route_base: plan.route_base.to_string(),
            api_boundary: plan.api_boundary.to_string(),
            execution_mode: plan.execution_mode.to_string(),
            server_side_only: plan.server_side_only,
            http_request_allowed: plan.http_request_allowed,
            raw_payload_allowed: plan.raw_payload_allowed,
            secret_values_allowed: plan.secret_values_allowed,
            customer_identifiers_allowed: plan.customer_identifiers_allowed,
            safe_summary: plan.safe_summary.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalBoundaryStatusSnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub read_plans: Vec<PortalBoundaryReadPlanSnapshot>,
    pub http_request_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

impl PortalBoundaryStatusSnapshot {
    pub fn static_dry_run() -> Result<Self, PortalBoundaryError> {
        let boundary = PortalServerBoundary::static_dry_run();
        let read_plans = boundary
            .plan_core_platform_reads()?
            .into_iter()
            .map(PortalBoundaryReadPlanSnapshot::from)
            .collect();

        Ok(Self {
            api_boundary: boundary.api_boundary.to_string(),
            execution_mode: execution_mode_label(&boundary.boundary_status.execution_mode)
                .to_string(),
            read_plans,
            http_request_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalRouteStateSnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub route_state_path: String,
    pub run_state_path: String,
    pub active_route: String,
    pub active_workspace: String,
    pub activity_route: String,
    pub activity_action_label: String,
    pub site_scope_label: String,
    pub environment_scope_label: String,
    pub role_scope_label: String,
    pub inventory_freshness_label: String,
    pub backup_freshness_label: String,
    pub monitoring_freshness_label: String,
    pub execution_authority_label: String,
    pub route_state: String,
    pub run_state: String,
    pub safe_summary: String,
    pub http_request_allowed: bool,
    pub provider_calls_allowed: bool,
    pub live_execution_allowed: bool,
    pub raw_route_state_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

impl PortalRouteStateSnapshot {
    pub fn static_dry_run() -> Result<Self, PortalBoundaryError> {
        let boundary = PortalServerBoundary::static_dry_run();
        let run_state_plan = boundary.plan_platform_api_read(operation_runs_resource())?;

        Ok(Self {
            api_boundary: boundary.api_boundary.to_string(),
            execution_mode: execution_mode_label(&boundary.boundary_status.execution_mode)
                .to_string(),
            route_state_path: PORTAL_ROUTE_STATE_SERVER_FUNCTION_PATH.to_string(),
            run_state_path: run_state_plan.path.to_string(),
            active_route: "#dashboard".to_string(),
            active_workspace: "dashboard".to_string(),
            activity_route: "#activity".to_string(),
            activity_action_label: "Open shift queue".to_string(),
            site_scope_label: "Site: Global".to_string(),
            environment_scope_label: "Env: Production".to_string(),
            role_scope_label: "Role: Platform Engineer".to_string(),
            inventory_freshness_label: "Inventory 6m ago".to_string(),
            backup_freshness_label: "Backup 14m ago".to_string(),
            monitoring_freshness_label: "Monitoring stale".to_string(),
            execution_authority_label: "Execution: dry-run only".to_string(),
            route_state: "static-shell-route".to_string(),
            run_state: "dry-run-only".to_string(),
            safe_summary: "Synthetic portal route state; static/dry-run only".to_string(),
            http_request_allowed: false,
            provider_calls_allowed: false,
            live_execution_allowed: false,
            raw_route_state_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalRequestPreflightSnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub request_intake_path: String,
    pub preflight_path: String,
    pub dry_run_plan_path: String,
    pub request_intake: Vec<RequestIntakeSummary>,
    pub dry_run_plans: Vec<DryRunPlanSummary>,
    pub preflight_gate_state: String,
    pub http_request_allowed: bool,
    pub provider_calls_allowed: bool,
    pub live_execution_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

impl PortalRequestPreflightSnapshot {
    pub fn static_dry_run() -> Result<Self, PortalBoundaryError> {
        let boundary = PortalServerBoundary::static_dry_run();
        let request_plan = boundary.plan_platform_api_read(request_intake_resource())?;
        let dry_run_plan = boundary.plan_platform_api_read(dry_run_plan_resource())?;
        let preflight_path = boundary.validate_platform_api_path(request_preflight_path())?;

        Ok(Self {
            api_boundary: boundary.api_boundary.to_string(),
            execution_mode: execution_mode_label(&boundary.boundary_status.execution_mode)
                .to_string(),
            request_intake_path: request_plan.path.to_string(),
            preflight_path: preflight_path.to_string(),
            dry_run_plan_path: dry_run_plan.path.to_string(),
            request_intake: request_intake_fallbacks(),
            dry_run_plans: dry_run_plan_fallbacks(),
            preflight_gate_state: "preflight required".to_string(),
            http_request_allowed: false,
            provider_calls_allowed: false,
            live_execution_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalInventoryCapacitySnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub inventory_resource_path: String,
    pub ownership_risk_path: String,
    pub capacity_admission_path: String,
    pub inventory_resources: Vec<InventoryResourceSummary>,
    pub capacity_admissions: Vec<CapacityAdmissionSummary>,
    pub inventory_read_only: bool,
    pub stale_data_blocks_execution: bool,
    pub capacity_execution_allowed: bool,
    pub http_request_allowed: bool,
    pub provider_calls_allowed: bool,
    pub raw_inventory_rows_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

impl PortalInventoryCapacitySnapshot {
    pub fn static_dry_run() -> Result<Self, PortalBoundaryError> {
        let boundary = PortalServerBoundary::static_dry_run();
        let inventory_plan =
            boundary.plan_platform_api_read(inventory_resource_overview_resource())?;
        let capacity_plan = boundary.plan_platform_api_read(capacity_admission_resource())?;
        let ownership_risk_path =
            boundary.validate_platform_api_path(inventory_ownership_risk_path())?;
        let capacity_admissions = capacity_admission_fallbacks();

        Ok(Self {
            api_boundary: boundary.api_boundary.to_string(),
            execution_mode: execution_mode_label(&boundary.boundary_status.execution_mode)
                .to_string(),
            inventory_resource_path: inventory_plan.path.to_string(),
            ownership_risk_path: ownership_risk_path.to_string(),
            capacity_admission_path: capacity_plan.path.to_string(),
            inventory_resources: inventory_resource_fallbacks(),
            capacity_execution_allowed: capacity_admissions
                .iter()
                .any(|admission| admission.execution_allowed),
            capacity_admissions,
            inventory_read_only: true,
            stale_data_blocks_execution: true,
            http_request_allowed: false,
            provider_calls_allowed: false,
            raw_inventory_rows_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalActivityRunStateSnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub activity_queue_path: String,
    pub shift_queue_path: String,
    pub run_state_path: String,
    pub activity_queue: Vec<ActivityQueueSummary>,
    pub operation_runs: Vec<OperationRunSummary>,
    pub queue_state: String,
    pub run_state: String,
    pub worker_execution_allowed: bool,
    pub retry_execution_allowed: bool,
    pub provider_calls_allowed: bool,
    pub live_execution_allowed: bool,
    pub raw_logs_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

impl PortalActivityRunStateSnapshot {
    pub fn static_dry_run() -> Result<Self, PortalBoundaryError> {
        let boundary = PortalServerBoundary::static_dry_run();
        let run_state_plan = boundary.plan_platform_api_read(operation_runs_resource())?;
        let activity_queue_path =
            boundary.validate_platform_api_path(activity_operation_queue_path())?;
        let shift_queue_path = boundary.validate_platform_api_path(shift_queue_path())?;
        let activity_queue = activity_queue_fallbacks();
        let operation_runs = operation_run_fallbacks();

        Ok(Self {
            api_boundary: boundary.api_boundary.to_string(),
            execution_mode: execution_mode_label(&boundary.boundary_status.execution_mode)
                .to_string(),
            activity_queue_path: activity_queue_path.to_string(),
            shift_queue_path: shift_queue_path.to_string(),
            run_state_path: run_state_plan.path.to_string(),
            queue_state: "blocked".to_string(),
            run_state: "dry-run-only".to_string(),
            worker_execution_allowed: activity_queue
                .iter()
                .any(|item| item.worker_execution_allowed),
            retry_execution_allowed: false,
            provider_calls_allowed: false,
            live_execution_allowed: false,
            raw_logs_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
            activity_queue,
            operation_runs,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalDatacenterReadinessSnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub readiness_score_path: String,
    pub site_report_path: String,
    pub failing_checks_path: String,
    pub check_power_path: String,
    pub check_cooling_path: String,
    pub check_rack_space_path: String,
    pub check_switchports_path: String,
    pub full_readiness_path: String,
    pub sites_path: String,
    pub readiness_score: DatacenterReadinessScore,
    pub site_report: DatacenterSiteReport,
    pub failing_checks: DatacenterFailingChecksSummary,
    pub check_power: DatacenterSingleCheck,
    pub check_cooling: DatacenterSingleCheck,
    pub check_rack_space: DatacenterSingleCheck,
    pub check_switchports: DatacenterSingleCheck,
    pub full_readiness: DatacenterFullReadiness,
    pub sites_catalog: DatacenterSitesCatalog,
    pub live_execution_allowed: bool,
    pub provider_calls_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

impl PortalDatacenterReadinessSnapshot {
    pub fn static_dry_run(site: &str) -> Result<Self, PortalBoundaryError> {
        let boundary = PortalServerBoundary::static_dry_run();
        let readiness_score_path =
            boundary.validate_platform_api_path(datacenter_readiness_score_path())?;
        let site_report_path = boundary.validate_platform_api_path(datacenter_site_report_path())?;
        let failing_checks_path =
            boundary.validate_platform_api_path(datacenter_failing_checks_path())?;
        let check_power_path = boundary.validate_platform_api_path(datacenter_check_power_path())?;
        let check_cooling_path =
            boundary.validate_platform_api_path(datacenter_check_cooling_path())?;
        let check_rack_space_path =
            boundary.validate_platform_api_path(datacenter_check_rack_space_path())?;
        let check_switchports_path =
            boundary.validate_platform_api_path(datacenter_check_switchports_path())?;
        let full_readiness_path =
            boundary.validate_platform_api_path(datacenter_full_readiness_path())?;
        let sites_path = boundary.validate_platform_api_path(datacenter_sites_path())?;

        Ok(Self {
            api_boundary: boundary.api_boundary.to_string(),
            execution_mode: execution_mode_label(&boundary.boundary_status.execution_mode)
                .to_string(),
            readiness_score_path: readiness_score_path.to_string(),
            site_report_path: site_report_path.to_string(),
            failing_checks_path: failing_checks_path.to_string(),
            check_power_path: check_power_path.to_string(),
            check_cooling_path: check_cooling_path.to_string(),
            check_rack_space_path: check_rack_space_path.to_string(),
            check_switchports_path: check_switchports_path.to_string(),
            full_readiness_path: full_readiness_path.to_string(),
            sites_path: sites_path.to_string(),
            readiness_score: datacenter_readiness_score_fallback(site),
            site_report: datacenter_site_report_fallback(site),
            failing_checks: datacenter_failing_checks_fallback(),
            check_power: datacenter_single_check_fallback(site, "power"),
            check_cooling: datacenter_single_check_fallback(site, "cooling"),
            check_rack_space: datacenter_single_check_fallback(site, "rack-space"),
            check_switchports: datacenter_single_check_fallback(site, "switchport"),
            full_readiness: datacenter_full_readiness_fallback(site),
            sites_catalog: datacenter_sites_catalog_fallback(),
            live_execution_allowed: false,
            provider_calls_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalEvidenceSummarySnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub evidence_summary_path: String,
    pub retention_path: String,
    pub evidence_summaries: Vec<EvidenceSummary>,
    pub redaction_required: bool,
    pub export_allowed: bool,
    pub evidence_export_allowed: bool,
    pub http_request_allowed: bool,
    pub provider_calls_allowed: bool,
    pub raw_evidence_payloads_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

impl PortalEvidenceSummarySnapshot {
    pub fn static_dry_run() -> Result<Self, PortalBoundaryError> {
        let boundary = PortalServerBoundary::static_dry_run();
        let evidence_plan = boundary.plan_platform_api_read(evidence_summary_resource())?;
        let retention_path =
            boundary.validate_platform_api_path(evidence_export_retention_path())?;
        let evidence_summaries = evidence_summary_fallbacks();

        Ok(Self {
            api_boundary: boundary.api_boundary.to_string(),
            execution_mode: execution_mode_label(&boundary.boundary_status.execution_mode)
                .to_string(),
            evidence_summary_path: evidence_plan.path.to_string(),
            retention_path: retention_path.to_string(),
            redaction_required: evidence_summaries
                .iter()
                .any(|summary| summary.redaction_required),
            export_allowed: evidence_summaries
                .iter()
                .any(|summary| summary.export_allowed),
            evidence_export_allowed: false,
            http_request_allowed: false,
            provider_calls_allowed: false,
            raw_evidence_payloads_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
            evidence_summaries,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalSecretReferenceSnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub secret_references_path: String,
    pub provider: String,
    pub management_cli: String,
    pub configured_for_production: bool,
    pub secret_references: Vec<SecretReferenceSummary>,
    pub readiness_state: String,
    pub live_cli_execution_allowed: bool,
    pub provider_calls_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub provider_paths_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

impl PortalSecretReferenceSnapshot {
    pub fn static_dry_run() -> Result<Self, PortalBoundaryError> {
        let boundary = PortalServerBoundary::static_dry_run();
        let reference_plan = boundary.plan_platform_api_read(secret_references_resource())?;
        let catalog_status = secret_reference_catalog_fallback();
        let secret_references = secret_reference_fallbacks();
        let readiness_state = secret_references
            .first()
            .map(|reference| reference.readiness_state.clone())
            .unwrap_or_else(|| "blocked".to_string());

        Ok(Self {
            api_boundary: boundary.api_boundary.to_string(),
            execution_mode: execution_mode_label(&boundary.boundary_status.execution_mode)
                .to_string(),
            secret_references_path: reference_plan.path.to_string(),
            provider: catalog_status.primary_provider,
            management_cli: catalog_status.management_cli,
            configured_for_production: catalog_status.configured_for_production,
            secret_references,
            readiness_state,
            live_cli_execution_allowed: false,
            provider_calls_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            provider_paths_allowed: false,
            customer_identifiers_allowed: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalCmdbWorkspaceSnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub file_exchange_path: String,
    pub reconciliation_path: String,
    pub relationship_graph_path: String,
    pub file_exchange: Vec<CmdbFileExchangeSummary>,
    pub reconciliation: Vec<CmdbReconciliationSummary>,
    pub relationships: Vec<CmdbRelationshipSummary>,
    pub file_import_execution_allowed: bool,
    pub file_export_execution_allowed: bool,
    pub live_api_allowed: bool,
    pub cmdb_mutation_allowed: bool,
    pub relationship_mutation_allowed: bool,
    pub provider_calls_allowed: bool,
    pub raw_cmdb_rows_allowed: bool,
    pub raw_relationship_rows_allowed: bool,
    pub evidence_redaction_required: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

impl PortalCmdbWorkspaceSnapshot {
    pub fn static_dry_run() -> Result<Self, PortalBoundaryError> {
        let boundary = PortalServerBoundary::static_dry_run();
        let file_exchange_plan = boundary.plan_platform_api_read(cmdb_file_exchange_resource())?;
        let reconciliation_plan = boundary.plan_platform_api_read(cmdb_reconciliation_resource())?;
        let relationship_plan =
            boundary.plan_platform_api_read(cmdb_relationship_graph_resource())?;
        let file_exchange = cmdb_file_exchange_fallbacks();
        let reconciliation = cmdb_reconciliation_fallbacks();
        let relationships = cmdb_relationship_fallbacks();

        Ok(Self {
            api_boundary: boundary.api_boundary.to_string(),
            execution_mode: execution_mode_label(&boundary.boundary_status.execution_mode)
                .to_string(),
            file_exchange_path: file_exchange_plan.path.to_string(),
            reconciliation_path: reconciliation_plan.path.to_string(),
            relationship_graph_path: relationship_plan.path.to_string(),
            file_import_execution_allowed: file_exchange
                .iter()
                .any(|exchange| exchange.file_import_execution_allowed),
            file_export_execution_allowed: file_exchange
                .iter()
                .any(|exchange| exchange.file_export_execution_allowed),
            live_api_allowed: file_exchange
                .iter()
                .any(|exchange| exchange.live_api_allowed),
            cmdb_mutation_allowed: reconciliation.iter().any(|item| item.cmdb_mutation_allowed),
            relationship_mutation_allowed: relationships
                .iter()
                .any(|item| item.relationship_mutation_allowed),
            provider_calls_allowed: false,
            raw_cmdb_rows_allowed: file_exchange
                .iter()
                .any(|exchange| exchange.raw_cmdb_rows_allowed)
                || reconciliation.iter().any(|item| item.raw_cmdb_rows_allowed),
            raw_relationship_rows_allowed: relationships
                .iter()
                .any(|item| item.raw_relationship_rows_allowed),
            evidence_redaction_required: true,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
            file_exchange,
            reconciliation,
            relationships,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalPolicyGuardrailsSnapshot {
    pub api_boundary: String,
    pub execution_mode: String,
    pub policy_outcomes_path: String,
    pub approval_readiness_path: String,
    pub policy_outcomes: Vec<PolicyOutcome>,
    pub guardrails: Vec<PolicyGuardrailSummary>,
    pub policy_gate_state: String,
    pub approval_required: bool,
    pub execution_allowed: bool,
    pub http_request_allowed: bool,
    pub provider_calls_allowed: bool,
    pub live_execution_allowed: bool,
    pub raw_policy_payloads_allowed: bool,
    pub raw_payload_allowed: bool,
    pub secret_values_allowed: bool,
    pub customer_identifiers_allowed: bool,
}

impl PortalPolicyGuardrailsSnapshot {
    pub fn static_dry_run() -> Result<Self, PortalBoundaryError> {
        let boundary = PortalServerBoundary::static_dry_run();
        let policy_plan = boundary.plan_platform_api_read(policy_outcomes_resource())?;
        let approval_readiness_path =
            boundary.validate_platform_api_path(approval_decision_readiness_path())?;
        let policy_outcomes = policy_outcome_fallbacks();
        let guardrails = policy_guardrail_fallbacks();

        Ok(Self {
            api_boundary: boundary.api_boundary.to_string(),
            execution_mode: execution_mode_label(&boundary.boundary_status.execution_mode)
                .to_string(),
            policy_outcomes_path: policy_plan.path.to_string(),
            approval_readiness_path: approval_readiness_path.to_string(),
            policy_gate_state: "guardrails blocking".to_string(),
            approval_required: true,
            execution_allowed: policy_outcomes
                .iter()
                .any(|outcome| outcome.decision == "allow")
                || guardrails
                    .iter()
                    .any(|guardrail| guardrail.execution_allowed),
            http_request_allowed: false,
            provider_calls_allowed: false,
            live_execution_allowed: false,
            raw_policy_payloads_allowed: false,
            raw_payload_allowed: false,
            secret_values_allowed: false,
            customer_identifiers_allowed: false,
            policy_outcomes,
            guardrails,
        })
    }
}

#[server(prefix = "/portal/api", endpoint = "boundary-status")]
pub async fn load_portal_boundary_status() -> Result<PortalBoundaryStatusSnapshot, ServerFnError> {
    PortalBoundaryStatusSnapshot::static_dry_run()
        .map_err(|_| ServerFnError::new("portal boundary status is unavailable"))
}

#[server(prefix = "/portal/api", endpoint = "route-state")]
pub async fn load_portal_route_state() -> Result<PortalRouteStateSnapshot, ServerFnError> {
    PortalRouteStateSnapshot::static_dry_run()
        .map_err(|_| ServerFnError::new("portal route state is unavailable"))
}

#[server(prefix = "/portal/api", endpoint = "request-preflight-status")]
pub async fn load_portal_request_preflight_status(
) -> Result<PortalRequestPreflightSnapshot, ServerFnError> {
    PortalRequestPreflightSnapshot::static_dry_run()
        .map_err(|_| ServerFnError::new("portal request preflight status is unavailable"))
}

#[server(prefix = "/portal/api", endpoint = "inventory-capacity-status")]
pub async fn load_portal_inventory_capacity_status(
) -> Result<PortalInventoryCapacitySnapshot, ServerFnError> {
    PortalInventoryCapacitySnapshot::static_dry_run()
        .map_err(|_| ServerFnError::new("portal inventory capacity status is unavailable"))
}

#[server(prefix = "/portal/api", endpoint = "activity-run-state")]
pub async fn load_portal_activity_run_state(
) -> Result<PortalActivityRunStateSnapshot, ServerFnError> {
    PortalActivityRunStateSnapshot::static_dry_run()
        .map_err(|_| ServerFnError::new("portal activity run state is unavailable"))
}

#[server(prefix = "/portal/api", endpoint = "evidence-summary-status")]
pub async fn load_portal_evidence_summary_status(
) -> Result<PortalEvidenceSummarySnapshot, ServerFnError> {
    PortalEvidenceSummarySnapshot::static_dry_run()
        .map_err(|_| ServerFnError::new("portal evidence summary status is unavailable"))
}

#[server(prefix = "/portal/api", endpoint = "secret-reference-status")]
pub async fn load_portal_secret_reference_status(
) -> Result<PortalSecretReferenceSnapshot, ServerFnError> {
    PortalSecretReferenceSnapshot::static_dry_run()
        .map_err(|_| ServerFnError::new("portal secret reference status is unavailable"))
}

#[server(prefix = "/portal/api", endpoint = "cmdb-workspace-status")]
pub async fn load_portal_cmdb_workspace_status(
) -> Result<PortalCmdbWorkspaceSnapshot, ServerFnError> {
    PortalCmdbWorkspaceSnapshot::static_dry_run()
        .map_err(|_| ServerFnError::new("portal CMDB workspace status is unavailable"))
}

#[server(prefix = "/portal/api", endpoint = "policy-guardrails-status")]
pub async fn load_portal_policy_guardrails_status(
) -> Result<PortalPolicyGuardrailsSnapshot, ServerFnError> {
    PortalPolicyGuardrailsSnapshot::static_dry_run()
        .map_err(|_| ServerFnError::new("portal policy guardrails status is unavailable"))
}

#[server(prefix = "/portal/api", endpoint = "platform-health")]
pub async fn get_platform_health() -> Result<PlatformHealth, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(platform_health_path())
        .map_err(|_| ServerFnError::new("platform health API path failed same-origin guard"))?;
    Ok(platform_health_fallback())
}

#[server(prefix = "/portal/api", endpoint = "boundary-status-check")]
pub async fn get_boundary_status() -> Result<BoundaryStatus, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(boundary_status_path())
        .map_err(|_| ServerFnError::new("boundary status API path failed same-origin guard"))?;
    Ok(boundary.boundary_status.clone())
}

#[server(prefix = "/portal/api", endpoint = "auth-session")]
pub async fn get_auth_session() -> Result<AuthSession, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(auth_status_path())
        .map_err(|_| ServerFnError::new("auth status API path failed same-origin guard"))?;
    Ok(auth_session_fallback())
}

#[server(prefix = "/portal/api", endpoint = "admin-rbac-roles")]
pub async fn get_admin_rbac_roles() -> Result<Vec<RbacRoleSummary>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(admin_rbac_roles_path())
        .map_err(|_| ServerFnError::new("admin rbac roles API path failed same-origin guard"))?;
    Ok(rbac_role_summary_fallbacks())
}

#[server(prefix = "/portal/api", endpoint = "admin-platform-settings")]
pub async fn get_admin_platform_settings() -> Result<PlatformSettingsSummary, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(admin_platform_settings_path())
        .map_err(|_| {
            ServerFnError::new("admin platform settings API path failed same-origin guard")
        })?;
    Ok(platform_settings_summary_fallback())
}

#[server(prefix = "/portal/api", endpoint = "admin-platform-settings-save")]
pub async fn save_platform_settings(
    settings: PlatformSettingsSummary,
) -> Result<PlatformSettingsSummary, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(admin_platform_settings_path())
        .map_err(|_| {
            ServerFnError::new("admin platform settings API path failed same-origin guard")
        })?;
    Ok(settings)
}

#[server(prefix = "/portal/api", endpoint = "admin-platform-settings-reset")]
pub async fn reset_platform_settings() -> Result<PlatformSettingsSummary, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(admin_platform_settings_path())
        .map_err(|_| {
            ServerFnError::new("admin platform settings API path failed same-origin guard")
        })?;
    Ok(platform_settings_summary_fallback())
}

#[server(prefix = "/portal/api", endpoint = "platform-status")]
pub async fn get_platform_status() -> Result<PlatformStatus, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(platform_status_path())
        .map_err(|_| ServerFnError::new("platform status API path failed same-origin guard"))?;
    Ok(platform_status_fallback())
}

#[server(prefix = "/portal/api", endpoint = "request-intake-form")]
pub async fn get_request_intake_form() -> Result<RequestIntakeForm, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(request_intake_form_preview_path())
        .map_err(|_| ServerFnError::new("request intake form API path failed same-origin guard"))?;
    Ok(request_intake_form_fallback())
}

#[server(prefix = "/portal/api", endpoint = "auth-login")]
pub async fn perform_login() -> Result<LoginResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(auth_login_path())
        .map_err(|_| ServerFnError::new("auth login API path failed same-origin guard"))?;
    Ok(LoginResponse {
        session_id: "mock-session-id".to_string(),
        user_id: "platform-engineer".to_string(),
        display_name: "Platform Engineer".to_string(),
        email: "platform-engineer@ryuki.local".to_string(),
        roles: vec![
            "platform-engineer".to_string(),
            "operator".to_string(),
            "viewer".to_string(),
        ],
        success: true,
    })
}

#[server(prefix = "/portal/api", endpoint = "auth-logout")]
pub async fn perform_logout() -> Result<LoginResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(auth_logout_path())
        .map_err(|_| ServerFnError::new("auth logout API path failed same-origin guard"))?;
    Ok(LoginResponse {
        session_id: String::new(),
        user_id: String::new(),
        display_name: String::new(),
        email: String::new(),
        roles: vec![],
        success: true,
    })
}

#[server(prefix = "/portal/api", endpoint = "request-list-data")]
pub async fn get_request_list() -> Result<Vec<RequestSummary>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(request_list_path())
        .map_err(|_| ServerFnError::new("request list API path failed same-origin guard"))?;
    Ok(request_summary_fallbacks())
}

#[server(prefix = "/portal/api", endpoint = "request-detail-data")]
pub async fn get_request_detail(request_id: String) -> Result<RequestDetail, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_detail_path(&request_id)
        .map_err(|_| ServerFnError::new("request detail API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request detail API path failed same-origin guard"))?;
    Ok(request_detail_fallback(&request_id))
}

#[server(prefix = "/portal/api", endpoint = "request-create-save")]
pub async fn create_request(payload: CreateRequestPayload) -> Result<RequestDetail, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(request_create_path())
        .map_err(|_| ServerFnError::new("request create API path failed same-origin guard"))?;
    let mut detail = request_detail_fallback("REQ-NEW");
    detail.request_type = payload.request_type;
    detail.name = payload.name;
    detail.site = payload.site;
    detail.environment = payload.environment;
    detail.cpu = payload.cpu;
    detail.memory = payload.memory;
    detail.justification = payload.justification;
    Ok(detail)
}

#[server(prefix = "/portal/api", endpoint = "request-validate")]
pub async fn validate_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_validate_path(&request_id)
        .map_err(|_| ServerFnError::new("request validate API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request validate API path failed same-origin guard"))?;
    Ok(StageActionResponse {
        request_id,
        success: true,
        new_stage: "validated".to_string(),
        message: "Request validated successfully.".to_string(),
    })
}

#[server(prefix = "/portal/api", endpoint = "request-plan")]
pub async fn plan_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_plan_path(&request_id)
        .map_err(|_| ServerFnError::new("request plan API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request plan API path failed same-origin guard"))?;
    Ok(StageActionResponse {
        request_id,
        success: true,
        new_stage: "planned".to_string(),
        message: "Dry-run plan generated successfully.".to_string(),
    })
}

#[server(prefix = "/portal/api", endpoint = "request-approve")]
pub async fn approve_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_approve_path(&request_id)
        .map_err(|_| ServerFnError::new("request approve API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request approve API path failed same-origin guard"))?;
    Ok(StageActionResponse {
        request_id,
        success: true,
        new_stage: "approved".to_string(),
        message: "Request approved by datacenter approver.".to_string(),
    })
}

#[server(prefix = "/portal/api", endpoint = "request-lock")]
pub async fn lock_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_lock_path(&request_id)
        .map_err(|_| ServerFnError::new("request lock API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request lock API path failed same-origin guard"))?;
    Ok(StageActionResponse {
        request_id,
        success: true,
        new_stage: "locked".to_string(),
        message: "Request locked for execution.".to_string(),
    })
}

#[server(prefix = "/portal/api", endpoint = "request-execute")]
pub async fn execute_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_execute_path(&request_id)
        .map_err(|_| ServerFnError::new("request execute API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request execute API path failed same-origin guard"))?;
    Ok(StageActionResponse {
        request_id,
        success: true,
        new_stage: "executed".to_string(),
        message: "Request executed successfully.".to_string(),
    })
}

#[server(prefix = "/portal/api", endpoint = "request-verify-stage")]
pub async fn verify_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_verify_path(&request_id)
        .map_err(|_| ServerFnError::new("request verify API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request verify API path failed same-origin guard"))?;
    Ok(StageActionResponse {
        request_id,
        success: true,
        new_stage: "verified".to_string(),
        message: "Request verification passed.".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_allows_only_same_origin_platform_contracts() {
        let boundary = PortalServerBoundary::static_dry_run();
        assert_eq!(
            boundary.validate_platform_api_path(request_intake_path()),
            Ok(request_intake_path())
        );
        assert_eq!(
            boundary.validate_platform_api_path("/api/requests/detail"),
            Err(PortalBoundaryError::OutsidePortalAllowlist)
        );
        assert_eq!(
            boundary.validate_platform_api_path("/api/not-allowlisted"),
            Err(PortalBoundaryError::OutsidePortalAllowlist)
        );
    }

    #[test]
    fn boundary_validates_generated_request_lifecycle_paths() {
        let boundary = PortalServerBoundary::static_dry_run();
        let request_id = "REQ-123";

        for path in [
            request_detail_path(request_id),
            request_validate_path(request_id),
            request_plan_path(request_id),
            request_approve_path(request_id),
            request_lock_path(request_id),
            request_execute_path(request_id),
            request_verify_path(request_id),
        ] {
            let path = path.expect("request lifecycle path must build");
            assert_eq!(
                boundary.validate_request_lifecycle_api_path(&path),
                Ok(path.as_str())
            );
        }

        for path in [
            "/api/requests/detail",
            "/api/requests/REQ-123/validate/extra",
            "/api/requests/REQ 123/validate",
            "/api/requests/REQ%2F123/validate",
            "/api/requests/REQ-123?stage=validate",
        ] {
            assert_eq!(
                boundary.validate_request_lifecycle_api_path(path),
                Err(PortalBoundaryError::OutsidePortalAllowlist)
            );
        }
    }

    #[test]
    fn platform_api_read_plan_is_static_and_redacted() {
        let boundary = PortalServerBoundary::static_dry_run();
        let plan = boundary
            .plan_platform_api_read(request_intake_resource())
            .expect("request intake resource must be allowlisted");

        assert_eq!(plan.resource_label, "request-intake");
        assert_eq!(plan.path, request_intake_path());
        assert_eq!(plan.route_base, "/api/");
        assert_eq!(plan.config_source, "static-dry-run-config");
        assert!(plan.server_side_only);
        assert!(!plan.http_request_allowed);
        assert!(!plan.raw_payload_allowed);
        assert!(!plan.secret_values_allowed);
        assert!(!plan.customer_identifiers_allowed);
    }

    #[test]
    fn core_platform_read_plans_cover_primary_control_plane_views() {
        let boundary = PortalServerBoundary::static_dry_run();
        let plans = boundary
            .plan_core_platform_reads()
            .expect("core portal resources must be allowlisted");
        let labels = plans
            .iter()
            .map(|plan| plan.resource_label)
            .collect::<Vec<_>>();

        assert_eq!(labels.as_slice(), CORE_PLATFORM_READ_PLAN_LABELS);
        for plan in plans {
            assert!(plan.path.starts_with("/api/"));
            assert!(plan.server_side_only);
            assert!(!plan.http_request_allowed);
            assert!(!plan.raw_payload_allowed);
            assert!(!plan.secret_values_allowed);
            assert!(!plan.customer_identifiers_allowed);
        }
    }

    #[test]
    fn safe_failure_blocks_retry_and_export() {
        let failure = PortalServerBoundary::static_dry_run().safe_failure_summary();
        assert!(!failure.retry_allowed);
        assert!(!failure.evidence_export_allowed);
        assert!(!failure.raw_payload_allowed);
        assert!(!failure.stack_trace_allowed);
    }

    #[test]
    fn boundary_status_snapshot_is_serializable_and_static() {
        let snapshot = PortalBoundaryStatusSnapshot::static_dry_run()
            .expect("portal boundary snapshot must be static and allowlisted");

        assert_eq!(snapshot.api_boundary, "same-origin-platform-api");
        assert_eq!(snapshot.execution_mode, "static-dry-run");
        assert_eq!(
            snapshot.read_plans.len(),
            CORE_PLATFORM_READ_PLAN_LABELS.len()
        );
        assert!(!snapshot.http_request_allowed);
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.customer_identifiers_allowed);
        assert!(snapshot.read_plans.iter().all(|plan| {
            plan.server_side_only
                && !plan.http_request_allowed
                && !plan.raw_payload_allowed
                && !plan.secret_values_allowed
                && !plan.customer_identifiers_allowed
                && plan.path.starts_with("/api/")
        }));

        serde_json::to_string(&snapshot)
            .expect("portal boundary snapshot must serialize for Leptos server function");
    }

    #[test]
    fn route_state_snapshot_is_serializable_static_and_synthetic() {
        let snapshot = PortalRouteStateSnapshot::static_dry_run()
            .expect("portal route state snapshot must be static and allowlisted");

        assert_eq!(snapshot.api_boundary, "same-origin-platform-api");
        assert_eq!(snapshot.execution_mode, "static-dry-run");
        assert_eq!(
            snapshot.route_state_path,
            PORTAL_ROUTE_STATE_SERVER_FUNCTION_PATH
        );
        assert_eq!(snapshot.run_state_path, operation_runs_path());
        assert_eq!(snapshot.active_route, "#dashboard");
        assert_eq!(snapshot.active_workspace, "dashboard");
        assert_eq!(snapshot.activity_route, "#activity");
        assert_eq!(snapshot.site_scope_label, "Site: Global");
        assert_eq!(snapshot.environment_scope_label, "Env: Production");
        assert_eq!(snapshot.role_scope_label, "Role: Platform Engineer");
        assert_eq!(snapshot.route_state, "static-shell-route");
        assert_eq!(snapshot.run_state, "dry-run-only");
        assert!(!snapshot.http_request_allowed);
        assert!(!snapshot.provider_calls_allowed);
        assert!(!snapshot.live_execution_allowed);
        assert!(!snapshot.raw_route_state_allowed);
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.customer_identifiers_allowed);

        serde_json::to_string(&snapshot)
            .expect("portal route state snapshot must serialize for Leptos server function");
    }

    #[test]
    fn request_preflight_snapshot_is_serializable_and_static() {
        let snapshot = PortalRequestPreflightSnapshot::static_dry_run()
            .expect("portal request preflight snapshot must be static and allowlisted");

        assert_eq!(snapshot.api_boundary, "same-origin-platform-api");
        assert_eq!(snapshot.execution_mode, "static-dry-run");
        assert_eq!(snapshot.request_intake_path, request_intake_path());
        assert_eq!(snapshot.preflight_path, request_preflight_path());
        assert_eq!(snapshot.dry_run_plan_path, dry_run_plan_path());
        assert_eq!(snapshot.request_intake.len(), 2);
        assert_eq!(snapshot.dry_run_plans.len(), 2);
        assert_eq!(snapshot.preflight_gate_state, "preflight required");
        assert!(!snapshot.http_request_allowed);
        assert!(!snapshot.provider_calls_allowed);
        assert!(!snapshot.live_execution_allowed);
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.customer_identifiers_allowed);
        assert!(snapshot
            .dry_run_plans
            .iter()
            .all(|plan| plan.dry_run && !plan.execution_allowed));

        serde_json::to_string(&snapshot)
            .expect("portal request preflight snapshot must serialize for Leptos server function");
    }

    #[test]
    fn inventory_capacity_snapshot_is_serializable_and_static() {
        let snapshot = PortalInventoryCapacitySnapshot::static_dry_run()
            .expect("portal inventory capacity snapshot must be static and allowlisted");

        assert_eq!(snapshot.api_boundary, "same-origin-platform-api");
        assert_eq!(snapshot.execution_mode, "static-dry-run");
        assert_eq!(
            snapshot.inventory_resource_path,
            inventory_resource_overview_path()
        );
        assert_eq!(
            snapshot.ownership_risk_path,
            inventory_ownership_risk_path()
        );
        assert_eq!(
            snapshot.capacity_admission_path,
            cluster_capacity_admission_path()
        );
        assert_eq!(snapshot.inventory_resources.len(), 2);
        assert_eq!(snapshot.capacity_admissions.len(), 2);
        assert!(snapshot.inventory_read_only);
        assert!(snapshot.stale_data_blocks_execution);
        assert!(!snapshot.capacity_execution_allowed);
        assert!(!snapshot.http_request_allowed);
        assert!(!snapshot.provider_calls_allowed);
        assert!(!snapshot.raw_inventory_rows_allowed);
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.customer_identifiers_allowed);
        assert!(snapshot
            .capacity_admissions
            .iter()
            .all(|admission| !admission.execution_allowed));

        serde_json::to_string(&snapshot)
            .expect("portal inventory capacity snapshot must serialize for Leptos server function");
    }

    #[test]
    fn activity_run_state_snapshot_is_serializable_and_static() {
        let snapshot = PortalActivityRunStateSnapshot::static_dry_run()
            .expect("portal activity run state snapshot must be static and allowlisted");

        assert_eq!(snapshot.api_boundary, "same-origin-platform-api");
        assert_eq!(snapshot.execution_mode, "static-dry-run");
        assert_eq!(
            snapshot.activity_queue_path,
            activity_operation_queue_path()
        );
        assert_eq!(snapshot.shift_queue_path, shift_queue_path());
        assert_eq!(snapshot.run_state_path, operation_runs_path());
        assert_eq!(snapshot.activity_queue.len(), 2);
        assert_eq!(snapshot.operation_runs.len(), 2);
        assert_eq!(snapshot.queue_state, "blocked");
        assert_eq!(snapshot.run_state, "dry-run-only");
        assert!(!snapshot.worker_execution_allowed);
        assert!(!snapshot.retry_execution_allowed);
        assert!(!snapshot.provider_calls_allowed);
        assert!(!snapshot.live_execution_allowed);
        assert!(!snapshot.raw_logs_allowed);
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.customer_identifiers_allowed);
        assert!(snapshot
            .activity_queue
            .iter()
            .all(|item| !item.worker_execution_allowed));
        assert!(snapshot
            .operation_runs
            .iter()
            .all(|run| run.dry_run && run.blocked_reason.is_some()));

        serde_json::to_string(&snapshot)
            .expect("portal activity run state snapshot must serialize for Leptos server function");
    }

    #[test]
    fn evidence_summary_snapshot_is_serializable_and_static() {
        let snapshot = PortalEvidenceSummarySnapshot::static_dry_run()
            .expect("portal evidence summary snapshot must be static and allowlisted");

        assert_eq!(snapshot.api_boundary, "same-origin-platform-api");
        assert_eq!(snapshot.execution_mode, "static-dry-run");
        assert_eq!(snapshot.evidence_summary_path, evidence_summary_path());
        assert_eq!(snapshot.retention_path, evidence_export_retention_path());
        assert_eq!(snapshot.evidence_summaries.len(), 2);
        assert!(snapshot.redaction_required);
        assert!(!snapshot.export_allowed);
        assert!(!snapshot.evidence_export_allowed);
        assert!(!snapshot.http_request_allowed);
        assert!(!snapshot.provider_calls_allowed);
        assert!(!snapshot.raw_evidence_payloads_allowed);
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.customer_identifiers_allowed);
        assert!(snapshot
            .evidence_summaries
            .iter()
            .all(|summary| summary.redaction_required && !summary.export_allowed));

        serde_json::to_string(&snapshot)
            .expect("portal evidence summary snapshot must serialize for Leptos server function");
    }

    #[test]
    fn secret_reference_snapshot_is_serializable_and_static() {
        let snapshot = PortalSecretReferenceSnapshot::static_dry_run()
            .expect("portal secret reference snapshot must be static and allowlisted");

        assert_eq!(snapshot.api_boundary, "same-origin-platform-api");
        assert_eq!(snapshot.execution_mode, "static-dry-run");
        assert_eq!(snapshot.secret_references_path, secret_references_path());
        let catalog_status = secret_reference_catalog_fallback();
        assert_eq!(snapshot.provider, catalog_status.primary_provider);
        assert_eq!(snapshot.management_cli, catalog_status.management_cli);
        assert_eq!(snapshot.secret_references.len(), 2);
        assert_eq!(snapshot.readiness_state, "pending-approval");
        assert!(!snapshot.configured_for_production);
        assert!(!snapshot.live_cli_execution_allowed);
        assert!(!snapshot.provider_calls_allowed);
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.provider_paths_allowed);
        assert!(!snapshot.customer_identifiers_allowed);
        assert!(snapshot.secret_references.iter().all(|reference| {
            !reference.live_cli_execution_allowed
                && !reference.value_exposure_allowed
                && !reference.provider_path_exposure_allowed
        }));

        serde_json::to_string(&snapshot)
            .expect("portal secret reference snapshot must serialize for Leptos server function");
    }

    #[test]
    fn cmdb_workspace_snapshot_is_serializable_and_static() {
        let snapshot = PortalCmdbWorkspaceSnapshot::static_dry_run()
            .expect("portal CMDB workspace snapshot must be static and allowlisted");

        assert_eq!(snapshot.api_boundary, "same-origin-platform-api");
        assert_eq!(snapshot.execution_mode, "static-dry-run");
        assert_eq!(snapshot.file_exchange_path, cmdb_file_exchange_path());
        assert_eq!(snapshot.reconciliation_path, cmdb_reconciliation_path());
        assert_eq!(
            snapshot.relationship_graph_path,
            cmdb_relationship_graph_path()
        );
        assert_eq!(snapshot.file_exchange.len(), 2);
        assert_eq!(snapshot.reconciliation.len(), 2);
        assert_eq!(snapshot.relationships.len(), 2);
        assert!(!snapshot.file_import_execution_allowed);
        assert!(!snapshot.file_export_execution_allowed);
        assert!(!snapshot.live_api_allowed);
        assert!(!snapshot.cmdb_mutation_allowed);
        assert!(!snapshot.relationship_mutation_allowed);
        assert!(!snapshot.provider_calls_allowed);
        assert!(!snapshot.raw_cmdb_rows_allowed);
        assert!(!snapshot.raw_relationship_rows_allowed);
        assert!(snapshot.evidence_redaction_required);
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.customer_identifiers_allowed);
        assert!(snapshot.file_exchange.iter().all(|exchange| {
            !exchange.file_import_execution_allowed
                && !exchange.file_export_execution_allowed
                && !exchange.live_api_allowed
                && !exchange.raw_cmdb_rows_allowed
        }));
        assert!(snapshot
            .reconciliation
            .iter()
            .all(|item| { !item.cmdb_mutation_allowed && !item.raw_cmdb_rows_allowed }));
        assert!(snapshot.relationships.iter().all(|item| {
            !item.relationship_mutation_allowed && !item.raw_relationship_rows_allowed
        }));

        serde_json::to_string(&snapshot)
            .expect("portal CMDB workspace snapshot must serialize for Leptos server function");
    }

    #[test]
    fn policy_guardrails_snapshot_is_serializable_and_static() {
        let snapshot = PortalPolicyGuardrailsSnapshot::static_dry_run()
            .expect("portal policy guardrails snapshot must be static and allowlisted");

        assert_eq!(snapshot.api_boundary, "same-origin-platform-api");
        assert_eq!(snapshot.execution_mode, "static-dry-run");
        assert_eq!(snapshot.policy_outcomes_path, policy_outcomes_path());
        assert_eq!(
            snapshot.approval_readiness_path,
            approval_decision_readiness_path()
        );
        assert_eq!(snapshot.policy_outcomes.len(), 2);
        assert_eq!(snapshot.guardrails.len(), 2);
        assert_eq!(snapshot.policy_gate_state, "guardrails blocking");
        assert!(snapshot.approval_required);
        assert!(!snapshot.execution_allowed);
        assert!(!snapshot.http_request_allowed);
        assert!(!snapshot.provider_calls_allowed);
        assert!(!snapshot.live_execution_allowed);
        assert!(!snapshot.raw_policy_payloads_allowed);
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.customer_identifiers_allowed);
        assert!(snapshot
            .policy_outcomes
            .iter()
            .all(|outcome| outcome.decision == "block" && !outcome.safe_summary.is_empty()));
        assert!(snapshot
            .guardrails
            .iter()
            .all(|guardrail| !guardrail.execution_allowed));

        serde_json::to_string(&snapshot)
            .expect("portal policy guardrails snapshot must serialize for Leptos server function");
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn boundary_status_server_function_registers_portal_route() {
        assert!(
            leptos::server_fn::axum::server_fn_paths()
                .any(|(path, _)| path == "/portal/api/boundary-status"),
            "boundary status server function must stay under the portal-owned route"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn route_state_server_function_registers_portal_route() {
        assert!(
            leptos::server_fn::axum::server_fn_paths()
                .any(|(path, _)| path == PORTAL_ROUTE_STATE_SERVER_FUNCTION_PATH),
            "route state server function must stay under the portal-owned route"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn request_preflight_server_function_registers_portal_route() {
        assert!(
            leptos::server_fn::axum::server_fn_paths()
                .any(|(path, _)| path == "/portal/api/request-preflight-status"),
            "request preflight server function must stay under the portal-owned route"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn inventory_capacity_server_function_registers_portal_route() {
        assert!(
            leptos::server_fn::axum::server_fn_paths()
                .any(|(path, _)| path == "/portal/api/inventory-capacity-status"),
            "inventory capacity server function must stay under the portal-owned route"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn activity_run_state_server_function_registers_portal_route() {
        assert!(
            leptos::server_fn::axum::server_fn_paths()
                .any(|(path, _)| path == "/portal/api/activity-run-state"),
            "activity run state server function must stay under the portal-owned route"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn evidence_summary_server_function_registers_portal_route() {
        assert!(
            leptos::server_fn::axum::server_fn_paths()
                .any(|(path, _)| path == "/portal/api/evidence-summary-status"),
            "evidence summary server function must stay under the portal-owned route"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn secret_reference_server_function_registers_portal_route() {
        assert!(
            leptos::server_fn::axum::server_fn_paths()
                .any(|(path, _)| path == "/portal/api/secret-reference-status"),
            "secret reference server function must stay under the portal-owned route"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn cmdb_workspace_server_function_registers_portal_route() {
        assert!(
            leptos::server_fn::axum::server_fn_paths()
                .any(|(path, _)| path == "/portal/api/cmdb-workspace-status"),
            "CMDB workspace server function must stay under the portal-owned route"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn policy_guardrails_server_function_registers_portal_route() {
        assert!(
            leptos::server_fn::axum::server_fn_paths()
                .any(|(path, _)| path == "/portal/api/policy-guardrails-status"),
            "policy guardrails server function must stay under the portal-owned route"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn request_intake_form_server_function_registers_portal_route() {
        assert!(
            leptos::server_fn::axum::server_fn_paths()
                .any(|(path, _)| path == "/portal/api/request-intake-form"),
            "request intake form server function must stay under the portal-owned route"
        );
    }
}
