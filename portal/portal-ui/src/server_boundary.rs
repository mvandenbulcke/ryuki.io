use crate::api::{
    activity_audit_feed_path, activity_operation_queue_path, admin_agents_path,
    admin_feature_flag_governance_path, admin_platform_settings_path,
    admin_platform_settings_reset_path, admin_rbac_roles_path, admin_sessions_path,
    admin_tokens_path, admin_worker_capability_path, approval_decision_readiness_path,
    approvals_pending_path, auth_local_login_path, auth_local_logout_path, auth_login_path,
    auth_logout_path, auth_session_path, auth_status_path, boundary_status_path,
    catalog_offerings_path, catalog_recommendations_path, catalog_request_form_path,
    cluster_capacity_admission_path, cmdb_export_path, cmdb_file_exchange_path, cmdb_import_path,
    cmdb_reconcile_path, cmdb_reconciliation_path, cmdb_relationship_graph_path,
    datacenter_check_cooling_path, datacenter_check_power_path, datacenter_check_rack_space_path,
    datacenter_check_switchports_path, datacenter_failing_checks_path,
    datacenter_full_readiness_path, datacenter_readiness_score_path, datacenter_site_report_path,
    datacenter_sites_path, dry_run_plan_path, emergency_change_path,
    evidence_compliance_dashboard_path, evidence_export_retention_path, evidence_summary_path,
    integrations_path, inventory_ownership_risk_path, inventory_resource_overview_path,
    notifications_path, notifications_read_all_path, notifications_unread_count_path,
    operation_runs_path, operations_platform_health_path, operations_runbook_launch_path,
    platform_health_path, platform_status_path, platform_summary_path, policy_outcomes_path,
    request_create_path, request_intake_form_preview_path, request_intake_path, request_list_path,
    request_preflight_path, same_origin_api_path, secret_references_path, shift_queue_path,
    site_catalog_path, ApiPathError,
};
#[cfg(any(feature = "ssr", test))]
use crate::api::{
    admin_agent_approve_path, admin_agent_revoke_path, admin_session_revoke_path,
    admin_token_revoke_path,
    notifications_read_path, request_approve_path, request_audit_path, request_cancel_path,
    request_detail_path, request_evidence_path, request_execute_path, request_lock_path,
    request_plan_path, request_protect_path, request_publish_path, request_reject_path,
    request_retire_path, request_validate_path, request_verify_path,
};
// Used only by `#[server]` (ssr-only) bodies; gating them to `ssr` keeps the
// `test` build (no ssr feature) free of unused-import warnings.
#[cfg(feature = "ssr")]
use crate::api::{
    integration_id_path, integration_test_path, request_approve_live_apply_path,
    request_execution_job_path,
};
use crate::api_client::{
    capacity_admission_resource, cmdb_file_exchange_resource, cmdb_reconciliation_resource,
    cmdb_relationship_graph_resource, dry_run_plan_resource, evidence_summary_resource,
    inventory_resource_overview_resource, operation_runs_resource, policy_outcomes_resource,
    request_intake_resource, secret_references_resource, ApiResource,
};
#[cfg(any(feature = "ssr", test))]
use crate::models::platform_settings_summary_fallback;
#[cfg(feature = "ssr")]
use crate::models::request_intake_form_fallback;
#[cfg(feature = "ssr")]
use crate::models::AgentJobSummary;
#[cfg(any(feature = "ssr", test))]
use crate::models::ALL_APP_ROLES;
#[cfg(feature = "ssr")]
use crate::models::{
    actions_for_stage, auth_session_fallback, platform_health_fallback, platform_status_fallback,
    platform_summary_context_fallback, rbac_role_summary_fallbacks, ApiAuditTrail, ApiEvidencePack,
    ApiExecutionJob, ApiLoginSession, ApiPlatformSummary, ApiRequestDetail, ApiRequestSummary,
};
use crate::models::{
    activity_queue_fallbacks, capacity_admission_fallbacks, cmdb_file_exchange_fallbacks,
    cmdb_reconciliation_fallbacks, cmdb_relationship_fallbacks, datacenter_failing_checks_fallback,
    datacenter_full_readiness_fallback, datacenter_readiness_score_fallback,
    datacenter_single_check_fallback, datacenter_site_report_fallback,
    datacenter_sites_catalog_fallback, dry_run_plan_fallbacks, evidence_summary_fallbacks,
    inventory_resource_fallbacks, operation_run_fallbacks, policy_guardrail_fallbacks,
    policy_outcome_fallbacks, request_intake_fallbacks, secret_reference_catalog_fallback,
    secret_reference_fallbacks, ActivityQueueSummary, AdminSessionSummary, AdminTokenSummary,
    AgentSummary, AuditEventRow, AuthSession, CapacityAdmissionSummary, CmdbActionResult,
    CmdbFileExchangeSummary, CmdbReconciliationSummary, CmdbRelationshipSummary,
    CreateIntegrationPayload, CreateRequestPayload, CreateTokenPayload, CreateTokenResult,
    DatacenterFailingChecksSummary, DatacenterFullReadiness, DatacenterReadinessScore,
    DatacenterSingleCheck, DatacenterSiteReport, DatacenterSitesCatalog, DryRunPlanSummary,
    EvidencePackExport, EvidenceSummary, ExecutionJob, IntegrationSummary, IntegrationTestResult,
    InventoryResourceSummary, NotificationSummary, OperationRunSummary, PlatformHealth,
    PlatformSettingsSummary, PlatformStatus, PlatformSummaryContext, PolicyGuardrailSummary,
    PolicyOutcome, RbacRoleSummary, RequestDetail, RequestIntakeForm, RequestIntakeSummary,
    RequestSummary, RevokeResult, SecretReferenceSummary, StageActionResponse,
    UpdateIntegrationPayload,
};
#[cfg(feature = "ssr")]
use crate::models::{admin_session_summary_fallbacks, admin_token_summary_fallbacks};
#[cfg(feature = "ssr")]
use crate::models::{request_detail_fallback, request_summary_fallbacks};
#[cfg(feature = "ssr")]
use crate::upstream::{
    clear_portal_session_cookie, cookie_max_age_from_expires_at, session_id_from_request,
    set_portal_session_cookie, UpstreamClient, UpstreamResponse,
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
    approvals_pending_path,
    notifications_path,
    notifications_unread_count_path,
    notifications_read_all_path,
    activity_operation_queue_path,
    activity_audit_feed_path,
    shift_queue_path,
    emergency_change_path,
    cmdb_file_exchange_path,
    cmdb_reconciliation_path,
    cmdb_relationship_graph_path,
    cmdb_import_path,
    cmdb_export_path,
    cmdb_reconcile_path,
    evidence_export_retention_path,
    evidence_compliance_dashboard_path,
    operations_runbook_launch_path,
    operations_platform_health_path,
    admin_worker_capability_path,
    admin_feature_flag_governance_path,
    admin_rbac_roles_path,
    admin_platform_settings_path,
    admin_platform_settings_reset_path,
    admin_tokens_path,
    admin_sessions_path,
    admin_agents_path,
    integrations_path,
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
    auth_local_login_path,
    auth_local_logout_path,
    auth_session_path,
];

/// Generic mutation failure when the upstream API is unreachable in live
/// mode. Mutations never degrade to static fallbacks.
#[cfg(feature = "ssr")]
const MUTATION_UNREACHABLE_MESSAGE: &str =
    "API unreachable; portal is in degraded static preview — no changes were made";

/// Shared substring present in BOTH static dry-run rejection messages (save
/// and reset).  Used by the UI helper to distinguish the expected preview
/// boundary from real failures (auth, validation, network, DB).
///
/// Both `reject_static_preview_platform_settings_save` and
/// `reject_static_preview_platform_settings_reset` embed this fragment, so a
/// single `contains` check is sufficient and robust to minor wording changes
/// in the non-sentinel parts of those messages.
pub(crate) const STATIC_PREVIEW_PLATFORM_SETTINGS_SENTINEL: &str =
    "preview-only in static dry-run mode";

/// Recovers the process-wide upstream client provided through Leptos context
/// by `main.rs`. Falls back to building one from the environment so SSR
/// renders outside the context-providing routes (for example the file/error
/// fallback handler) stay functional.
#[cfg(feature = "ssr")]
fn upstream_context() -> UpstreamClient {
    use leptos::prelude::use_context;

    use_context::<UpstreamClient>().unwrap_or_else(UpstreamClient::from_env)
}

/// Extracts the canonical `{"error","message"}` text from an upstream 4xx
/// body, falling back to the bare `error` field and then to a generic label.
/// Raw upstream payloads never pass through unparsed.
#[cfg(feature = "ssr")]
fn api_error_text(response: &UpstreamResponse, fallback: &str) -> String {
    response.api_error_message().unwrap_or_else(|| {
        serde_json::from_str::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|error| error.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| fallback.to_string())
    })
}

/// Lowercases the engine PascalCase health status enums so the portal badge
/// classes (which compare against lowercase labels) stay consistent.
#[cfg(feature = "ssr")]
fn normalize_platform_health(mut health: PlatformHealth) -> PlatformHealth {
    health.overall_status = health.overall_status.to_ascii_lowercase();
    for check in &mut health.checks {
        check.status = check.status.to_ascii_lowercase();
    }
    health
}

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
        "detail"
            | "validate"
            | "plan"
            | "approve"
            | "reject"
            | "cancel"
            | "lock"
            | "execute"
            | "verify"
            | "protect"
            | "publish"
            | "retire"
            | "audit"
            | "evidence"
    ) {
        return false;
    }
    matches!(
        (segments.next(), segments.next()),
        (None, None)
            | (Some("validate"), None)
            | (Some("plan"), None)
            | (Some("approve"), None)
            | (Some("reject"), None)
            | (Some("cancel"), None)
            | (Some("lock"), None)
            | (Some("execute"), None)
            | (Some("verify"), None)
            // Post-completion governed lifecycle (Theme 8).
            | (Some("protect"), None)
            | (Some("publish"), None)
            | (Some("retire"), None)
            | (Some("audit"), None)
            | (Some("evidence"), None)
            | (Some("execution-job"), None)
            | (Some("approve-live-apply"), None)
    )
}

/// Validates `/api/admin/tokens/{id}` and `/api/admin/sessions/{id}` — the
/// revoke paths that carry an id and so cannot live in the static allowlist.
/// Only a single safe id segment is accepted; the resource collection (no id)
/// is validated through the static allowlist instead.
fn is_allowed_admin_resource_revoke_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/admin/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let Some(resource) = segments.next() else {
        return false;
    };
    if !matches!(resource, "tokens" | "sessions") {
        return false;
    }
    let Some(id) = segments.next() else {
        return false;
    };
    if id.is_empty()
        || id == "."
        || id == ".."
        || id.contains("..")
        || id.contains('\\')
        || id.contains('?')
        || id.contains('#')
        || id.contains("://")
        || id.starts_with("//")
        || !id
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || matches!(char, '-' | '_'))
    {
        return false;
    }
    // Exactly `/{resource}/{id}` — no trailing segments.
    segments.next().is_none()
}

/// Validates `/api/admin/agents/{id}/approve` — the enrollment-approval path,
/// which carries an agent id and a static `approve` suffix and so cannot live
/// in the static allowlist. Only a single safe id segment is accepted, and the
/// suffix must be exactly `approve` with no trailing segments.
fn is_allowed_admin_agent_approve_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/admin/agents/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let Some(agent_id) = segments.next() else {
        return false;
    };
    if agent_id.is_empty()
        || agent_id == "."
        || agent_id == ".."
        || agent_id.contains("..")
        || agent_id.contains('\\')
        || agent_id.contains('?')
        || agent_id.contains('#')
        || agent_id.contains("://")
        || agent_id.starts_with("//")
        || !agent_id
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || matches!(char, '-' | '_'))
    {
        return false;
    }
    // Exactly `/agents/{id}/approve` — the suffix is `approve` and nothing else.
    matches!((segments.next(), segments.next()), (Some("approve"), None))
}

/// Validates `/api/admin/agents/{id}/revoke` — mirrors the approve-path guard with
/// a `revoke` suffix. Only a single safe id segment is accepted.
fn is_allowed_admin_agent_revoke_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/admin/agents/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let Some(agent_id) = segments.next() else {
        return false;
    };
    if agent_id.is_empty()
        || agent_id == "."
        || agent_id == ".."
        || agent_id.contains("..")
        || agent_id.contains('\\')
        || agent_id.contains('?')
        || agent_id.contains('#')
        || agent_id.contains("://")
        || agent_id.starts_with("//")
        || !agent_id
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || matches!(char, '-' | '_'))
    {
        return false;
    }
    // Exactly `/agents/{id}/revoke` — the suffix is `revoke` and nothing else.
    matches!((segments.next(), segments.next()), (Some("revoke"), None))
}

/// Validates `/api/notifications/{id}/read` — the per-item mark-read path, which
/// carries a notification id and a static `read` suffix and so cannot live in the
/// static allowlist. Only a single safe id segment is accepted, and the suffix
/// must be exactly `read` with no trailing segments.
fn is_allowed_notifications_read_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/notifications/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let Some(notification_id) = segments.next() else {
        return false;
    };
    if notification_id.is_empty()
        || notification_id == "."
        || notification_id == ".."
        || notification_id.contains("..")
        || notification_id.contains('\\')
        || notification_id.contains('?')
        || notification_id.contains('#')
        || notification_id.contains("://")
        || notification_id.starts_with("//")
        || !notification_id
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || matches!(char, '-' | '_'))
    {
        return false;
    }
    // Exactly `/notifications/{id}/read` — the suffix is `read` and nothing else.
    // Guard against the collection-level `read-all` route accidentally matching:
    // that path has no second segment, so it can never reach here as `{id}/read`.
    matches!((segments.next(), segments.next()), (Some("read"), None))
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

    /// Validates the id-bearing admin revoke paths (`/api/admin/tokens/{id}`,
    /// `/api/admin/sessions/{id}`) before a DELETE is dispatched.
    pub fn validate_admin_resource_revoke_path<'a>(
        &self,
        path: &'a str,
    ) -> Result<&'a str, PortalBoundaryError> {
        let guarded = same_origin_api_path(path)?;
        if is_allowed_admin_resource_revoke_path(guarded) {
            return Ok(guarded);
        }
        Err(PortalBoundaryError::OutsidePortalAllowlist)
    }

    /// Validates the id-bearing agent enrollment approval path
    /// (`/api/admin/agents/{id}/approve`) before a POST is dispatched.
    pub fn validate_admin_agent_approve_path<'a>(
        &self,
        path: &'a str,
    ) -> Result<&'a str, PortalBoundaryError> {
        let guarded = same_origin_api_path(path)?;
        if is_allowed_admin_agent_approve_path(guarded) {
            return Ok(guarded);
        }
        Err(PortalBoundaryError::OutsidePortalAllowlist)
    }

    /// Validates the id-bearing agent revocation path
    /// (`/api/admin/agents/{id}/revoke`) before a POST is dispatched.
    pub fn validate_admin_agent_revoke_path<'a>(
        &self,
        path: &'a str,
    ) -> Result<&'a str, PortalBoundaryError> {
        let guarded = same_origin_api_path(path)?;
        if is_allowed_admin_agent_revoke_path(guarded) {
            return Ok(guarded);
        }
        Err(PortalBoundaryError::OutsidePortalAllowlist)
    }

    /// Validates the id-bearing per-item notification read path
    /// (`/api/notifications/{id}/read`) before a POST is dispatched.
    pub fn validate_notifications_read_path<'a>(
        &self,
        path: &'a str,
    ) -> Result<&'a str, PortalBoundaryError> {
        let guarded = same_origin_api_path(path)?;
        if is_allowed_notifications_read_path(guarded) {
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
    /// "live" | "degraded-static" | "static-dry-run" — whether the data on
    /// screen reflects the live API, a degraded fallback, or the static demo.
    pub upstream_state: String,
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
            upstream_state: "static-dry-run".to_string(),
            route_state_path: PORTAL_ROUTE_STATE_SERVER_FUNCTION_PATH.to_string(),
            run_state_path: run_state_plan.path.to_string(),
            active_route: "/".to_string(),
            active_workspace: "dashboard".to_string(),
            activity_route: "/activity".to_string(),
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

    /// Route state when the portal runs in live-provider mode and the
    /// upstream API answered the reachability probe.
    pub fn live_provider() -> Result<Self, PortalBoundaryError> {
        let mut snapshot = Self::static_dry_run()?;
        snapshot.execution_mode = "live-provider".to_string();
        snapshot.upstream_state = "live".to_string();
        snapshot.execution_authority_label = "Execution: live provider (gated)".to_string();
        snapshot.route_state = "live-shell-route".to_string();
        snapshot.safe_summary = "Portal route state backed by the live platform API".to_string();
        Ok(snapshot)
    }

    /// Route state when live-provider mode is configured but the upstream API
    /// is unreachable: reads degrade to labeled static fallbacks and the
    /// shell repoints its context-strip labels.
    pub fn degraded_static_fallback() -> Result<Self, PortalBoundaryError> {
        let mut snapshot = Self::static_dry_run()?;
        snapshot.execution_mode = "degraded-static-fallback".to_string();
        snapshot.upstream_state = "degraded-static".to_string();
        snapshot.execution_authority_label = "Execution: blocked (API unreachable)".to_string();
        snapshot.inventory_freshness_label = "API unreachable — static preview".to_string();
        snapshot.backup_freshness_label = "API unreachable — static preview".to_string();
        snapshot.monitoring_freshness_label = "API unreachable — static preview".to_string();
        snapshot.safe_summary =
            "Upstream API unreachable; static preview shown read-only".to_string();
        Ok(snapshot)
    }

    /// Reports the requested path as the matched route. The path is resolved
    /// through the workspace catalog's route table, so unknown or unsafe
    /// client-supplied paths fall back to the dashboard route instead of
    /// being echoed into the snapshot.
    pub fn with_active_path(mut self, requested_path: &str) -> Self {
        let (active_route, active_workspace) =
            crate::workspace_catalog::match_portal_route(requested_path)
                .unwrap_or_else(|| ("/".to_string(), "dashboard"));
        self.active_route = active_route;
        self.active_workspace = active_workspace.to_string();
        self
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
pub async fn load_portal_route_state(
    active_path: String,
) -> Result<PortalRouteStateSnapshot, ServerFnError> {
    let unavailable = |_| ServerFnError::new("portal route state is unavailable");
    let upstream = upstream_context();
    let snapshot = if !upstream.live() {
        PortalRouteStateSnapshot::static_dry_run()
    } else {
        let boundary = PortalServerBoundary::static_dry_run();
        let probe_path = boundary
            .validate_platform_api_path(platform_summary_path())
            .map_err(unavailable)?;
        let session_id = session_id_from_request().await;
        match upstream.get(probe_path, session_id.as_deref()).await {
            Ok(_) => PortalRouteStateSnapshot::live_provider(),
            Err(_) => PortalRouteStateSnapshot::degraded_static_fallback(),
        }
    };
    snapshot
        .map(|snapshot| snapshot.with_active_path(&active_path))
        .map_err(unavailable)
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

/// Counts the `import_status` discriminants in a CMDB import/export record
/// array. The API serializes `ImportStatus` as the bare PascalCase variant
/// (`"Accepted"`, `"Rejected"`, `"PendingReview"`); unknown values are ignored
/// so a contract drift degrades the counts rather than the whole action.
#[cfg(any(feature = "ssr", test))]
fn count_cmdb_import_statuses(records: &serde_json::Value) -> (usize, usize, usize) {
    let mut accepted = 0;
    let mut rejected = 0;
    let mut pending = 0;
    if let Some(rows) = records.as_array() {
        for row in rows {
            match row.get("import_status").and_then(|s| s.as_str()) {
                Some("Accepted") => accepted += 1,
                Some("Rejected") => rejected += 1,
                Some("PendingReview") => pending += 1,
                _ => {}
            }
        }
    }
    (accepted, rejected, pending)
}

/// Extracts the matched (present-in-both) count from the reconciliation result
/// summary line `"... N item(s) reconciled (present in both)"`. Returns 0 when
/// the line is absent so a wording drift degrades gracefully.
#[cfg(any(feature = "ssr", test))]
fn cmdb_reconciled_matched_count(lines: &[String]) -> usize {
    lines
        .iter()
        .find_map(|line| {
            let marker = "item(s) reconciled (present in both)";
            if !line.contains(marker) {
                return None;
            }
            line.split_whitespace()
                .find_map(|token| token.parse::<usize>().ok())
        })
        .unwrap_or(0)
}

/// Import preview of a CMDB source (Theme: CMDB actions, #33). POST the
/// `{"source"}` body to the dry-run import executor and derive the
/// accepted/rejected/pending counts server-side. Defaults to the Excel export
/// source. Mirrors `create_integration`: static allowlist guard, live-only
/// dispatch, no raw payload leaks to the view.
#[server(prefix = "/portal/api", endpoint = "cmdb-import")]
pub async fn cmdb_import(source: String) -> Result<CmdbActionResult, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(cmdb_import_path())
        .map_err(|_| ServerFnError::new("CMDB import API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Err(ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE));
    }
    let source = {
        let trimmed = source.trim();
        if trimmed.is_empty() {
            "cmdb-excel-export".to_string()
        } else {
            trimmed.to_string()
        }
    };
    let body = serde_json::json!({ "source": source });
    let session_id = session_id_from_request().await;
    let response = upstream
        .post(cmdb_import_path(), Some(&body), session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Ok(CmdbActionResult {
            action: "Import preview".to_string(),
            success: false,
            accepted: 0,
            rejected: 0,
            pending: 0,
            matched: 0,
            message: api_error_text(&response, "CMDB import was rejected by the API"),
            lines: Vec::new(),
        });
    }
    let records: serde_json::Value = response
        .json()
        .map_err(|_| ServerFnError::new("CMDB import response was malformed"))?;
    let total = records.as_array().map(|rows| rows.len()).unwrap_or(0);
    let (accepted, rejected, pending) = count_cmdb_import_statuses(&records);
    Ok(CmdbActionResult {
        action: "Import preview".to_string(),
        success: true,
        accepted,
        rejected,
        pending,
        matched: total,
        message: format!("Imported {total} record(s) from {source}"),
        lines: Vec::new(),
    })
}

/// Export the CMDB records (Theme: CMDB actions, #33). GET the dry-run export
/// executor and surface the record count and format without exposing the raw
/// serialized payload to the browser. Mirrors the GET-fetch live pattern.
#[server(prefix = "/portal/api", endpoint = "cmdb-export")]
pub async fn cmdb_export() -> Result<CmdbActionResult, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(cmdb_export_path())
        .map_err(|_| ServerFnError::new("CMDB export API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Err(ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE));
    }
    let session_id = session_id_from_request().await;
    let response = upstream
        .get(cmdb_export_path(), session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Ok(CmdbActionResult {
            action: "Export".to_string(),
            success: false,
            accepted: 0,
            rejected: 0,
            pending: 0,
            matched: 0,
            message: api_error_text(&response, "CMDB export was rejected by the API"),
            lines: Vec::new(),
        });
    }
    let payload: serde_json::Value = response
        .json()
        .map_err(|_| ServerFnError::new("CMDB export response was malformed"))?;
    let format = payload
        .get("format")
        .and_then(|f| f.as_str())
        .unwrap_or("json")
        .to_string();
    // The `data` field is the serialized record set; count exported records
    // when it parses as a JSON array, otherwise fall back to byte size only.
    let data = payload.get("data").and_then(|d| d.as_str()).unwrap_or("");
    let exported = serde_json::from_str::<serde_json::Value>(data)
        .ok()
        .and_then(|value| value.as_array().map(|rows| rows.len()))
        .unwrap_or(0);
    let bytes = data.len();
    Ok(CmdbActionResult {
        action: "Export".to_string(),
        success: true,
        accepted: 0,
        rejected: 0,
        pending: 0,
        matched: exported,
        message: format!("Exported {exported} record(s) as {format} ({bytes} bytes)"),
        lines: Vec::new(),
    })
}

/// Run a CMDB reconciliation (Theme: CMDB actions, #33). POST the bodyless
/// dry-run reconciliation executor and surface the matched (present-in-both)
/// count plus the human-readable result lines. Mirrors the bodyless live POST
/// pattern (`verify_request`).
#[server(prefix = "/portal/api", endpoint = "cmdb-reconcile")]
pub async fn cmdb_reconcile() -> Result<CmdbActionResult, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(cmdb_reconcile_path())
        .map_err(|_| ServerFnError::new("CMDB reconcile API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Err(ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE));
    }
    let session_id = session_id_from_request().await;
    let response = upstream
        .post(cmdb_reconcile_path(), None, session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Ok(CmdbActionResult {
            action: "Reconciliation".to_string(),
            success: false,
            accepted: 0,
            rejected: 0,
            pending: 0,
            matched: 0,
            message: api_error_text(&response, "CMDB reconcile was rejected by the API"),
            lines: Vec::new(),
        });
    }
    let payload: serde_json::Value = response
        .json()
        .map_err(|_| ServerFnError::new("CMDB reconcile response was malformed"))?;
    let lines: Vec<String> = payload
        .get("reconciliation_results")
        .and_then(|r| r.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let matched = cmdb_reconciled_matched_count(&lines);
    Ok(CmdbActionResult {
        action: "Reconciliation".to_string(),
        success: true,
        accepted: 0,
        rejected: 0,
        pending: 0,
        matched,
        message: format!("Reconciliation complete: {matched} CI(s) present in both"),
        lines,
    })
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
    let path = boundary
        .validate_platform_api_path(platform_health_path())
        .map_err(|_| ServerFnError::new("platform health API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(platform_health_fallback());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let health: PlatformHealth = response
                .json()
                .map_err(|_| ServerFnError::new("platform health response was malformed"))?;
            Ok(normalize_platform_health(health))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "platform health fetch failed",
        ))),
        // Live mode never masks an unreachable API behind the static
        // fallback; the caller renders an explicit degraded state.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

#[server(prefix = "/portal/api", endpoint = "platform-summary")]
pub async fn get_platform_summary() -> Result<PlatformSummaryContext, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(platform_summary_path())
        .map_err(|_| ServerFnError::new("platform summary API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(platform_summary_context_fallback());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let summary: ApiPlatformSummary = response
                .json()
                .map_err(|_| ServerFnError::new("platform summary response was malformed"))?;
            Ok(PlatformSummaryContext::from(summary))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "platform summary fetch failed",
        ))),
        // Live mode surfaces the unreachable API as an error; the login
        // view maps it to the distinct "degraded" authentication mode
        // instead of the static-preview message.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

#[server(prefix = "/portal/api", endpoint = "boundary-status-check")]
pub async fn get_boundary_status() -> Result<BoundaryStatus, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(boundary_status_path())
        .map_err(|_| ServerFnError::new("boundary status API path failed same-origin guard"))?;
    Ok(boundary.boundary_status.clone())
}

/// Resolves the caller's session. `Ok(None)` means "not signed in" (no
/// cookie, or the upstream session is expired/invalid); `Err` means the
/// upstream API was unreachable in live mode (degraded shell). The synthetic
/// `auth_session_fallback()` PlatformAdmin grant survives ONLY behind the
/// static-mode branch.
#[server(prefix = "/portal/api", endpoint = "auth-session")]
pub async fn get_auth_session() -> Result<Option<AuthSession>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(auth_session_path())
        .map_err(|_| ServerFnError::new("auth session API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(Some(auth_session_fallback()));
    }
    let Some(session_id) = session_id_from_request().await else {
        return Ok(None);
    };
    let response = upstream
        .get(path, Some(&session_id))
        .await
        .map_err(|_| ServerFnError::new("API unreachable"))?;
    // Only a definitive upstream rejection of the session (401/403)
    // invalidates the portal cookie. Any other non-2xx is a degraded gate:
    // surface the error and keep the cookie so a transient API problem
    // cannot sign the user out.
    if matches!(response.status, 401 | 403) {
        clear_portal_session_cookie();
        return Ok(None);
    }
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "auth session fetch failed",
        )));
    }
    let session: AuthSession = response
        .json()
        .map_err(|_| ServerFnError::new("auth session response was malformed"))?;
    if session.token_valid {
        Ok(Some(session))
    } else {
        // Expired or unknown upstream session: clear the stale portal cookie.
        clear_portal_session_cookie();
        Ok(None)
    }
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
    let path = boundary
        .validate_platform_api_path(admin_platform_settings_path())
        .map_err(|_| {
            ServerFnError::new("admin platform settings API path failed same-origin guard")
        })?;
    let upstream = upstream_context();
    // Static-dry-run mode serves the labeled fallback; live mode reads the REAL
    // durable platform_config so the admin sees the actual auth mode, database,
    // and Entra wiring — never the static "mock-dry-run" placeholder.
    if !upstream.live() {
        return Ok(platform_settings_summary_fallback());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            // The API returns the full PlatformConfig; the summary is a subset
            // of its fields (extra fields are ignored by serde).
            let summary: PlatformSettingsSummary = response.json().map_err(|_| {
                ServerFnError::new("admin platform settings response was malformed")
            })?;
            Ok(summary)
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "admin platform settings fetch failed",
        ))),
        // Live mode surfaces an unreachable API as an error; the view renders a
        // labeled fallback rather than masking it as real durable config.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

#[cfg(any(feature = "ssr", test))]
fn reject_static_preview_platform_settings_save(
    settings: PlatformSettingsSummary,
) -> Result<PlatformSettingsSummary, ServerFnError> {
    let _ = settings;
    Err(ServerFnError::new(
        "Portal settings save is preview-only in static dry-run mode; no changes were persisted",
    ))
}

#[cfg(any(feature = "ssr", test))]
fn reject_static_preview_platform_settings_reset() -> Result<PlatformSettingsSummary, ServerFnError>
{
    Err(ServerFnError::new(
        "Portal settings reset is preview-only in static dry-run mode; no changes were persisted",
    ))
}

#[server(prefix = "/portal/api", endpoint = "admin-platform-settings-save")]
pub async fn save_platform_settings(
    settings: PlatformSettingsSummary,
) -> Result<PlatformSettingsSummary, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(admin_platform_settings_path())
        .map_err(|_| {
            ServerFnError::new("admin platform settings API path failed same-origin guard")
        })?;
    let upstream = upstream_context();
    // Static-dry-run is preview-only: writes never persist.
    if !upstream.live() {
        return reject_static_preview_platform_settings_save(settings);
    }
    let session_id = session_id_from_request().await;
    // Round-trip the FULL current config so editing the summary's five fields
    // never clobbers the ~20 other provider fields the API persists wholesale.
    let mut full: serde_json::Value = match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => response
            .json()
            .map_err(|_| ServerFnError::new("admin platform settings response was malformed"))?,
        Ok(response) => {
            return Err(ServerFnError::new(api_error_text(
                &response,
                "admin platform settings fetch failed",
            )))
        }
        Err(_) => return Err(ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE)),
    };
    // Merge the edited summary fields onto the full config by serializing the
    // typed summary (its serde definition supplies the field names, so no
    // provider field is named in this boundary code) and copying its keys over.
    let edited = serde_json::to_value(&settings)
        .map_err(|_| ServerFnError::new("admin platform settings payload was malformed"))?;
    if let (Some(full_object), Some(edited_object)) = (full.as_object_mut(), edited.as_object()) {
        for (key, value) in edited_object {
            full_object.insert(key.clone(), value.clone());
        }
    }
    match upstream.put(path, &full, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let updated: PlatformSettingsSummary = response.json().map_err(|_| {
                ServerFnError::new("admin platform settings update response was malformed")
            })?;
            Ok(updated)
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "platform settings save failed",
        ))),
        Err(_) => Err(ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE)),
    }
}

#[server(prefix = "/portal/api", endpoint = "admin-platform-settings-reset")]
pub async fn reset_platform_settings() -> Result<PlatformSettingsSummary, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(admin_platform_settings_reset_path())
        .map_err(|_| {
            ServerFnError::new("admin platform settings reset API path failed same-origin guard")
        })?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_platform_settings_reset();
    }
    let session_id = session_id_from_request().await;
    match upstream.post(path, None, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let updated: PlatformSettingsSummary = response.json().map_err(|_| {
                ServerFnError::new("admin platform settings reset response was malformed")
            })?;
            Ok(updated)
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "platform settings reset failed",
        ))),
        Err(_) => Err(ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE)),
    }
}

/// Validation message for an unknown role in the create-token form. The check
/// runs portal-side first (the API repeats it authoritatively) so the operator
/// gets immediate feedback without a round trip. Returns the offending role.
#[cfg(any(feature = "ssr", test))]
fn first_unknown_role(roles: &[String]) -> Option<String> {
    roles
        .iter()
        .find(|role| !ALL_APP_ROLES.contains(&role.as_str()))
        .cloned()
}

#[cfg(any(feature = "ssr", test))]
fn reject_static_preview_token_create(
    payload: &CreateTokenPayload,
) -> Result<CreateTokenResult, ServerFnError> {
    let _ = payload;
    Err(ServerFnError::new(
        "Portal token creation is preview-only in static dry-run mode; no token was minted",
    ))
}

#[cfg(any(feature = "ssr", test))]
fn reject_static_preview_revoke(action: &str) -> Result<RevokeResult, ServerFnError> {
    Err(ServerFnError::new(format!(
        "Portal {action} revoke is preview-only in static dry-run mode; nothing was revoked"
    )))
}

#[cfg(any(feature = "ssr", test))]
fn reject_static_preview_agent_approve() -> Result<RevokeResult, ServerFnError> {
    Err(ServerFnError::new(
        "Portal agent approval is preview-only in static dry-run mode; no agent was approved",
    ))
}

/// `GET /api/admin/tokens` — list API token metadata (hash redacted). The
/// handler still expects the API to gate on the `admin` permission; in static
/// mode it returns labeled synthetic rows.
#[server(prefix = "/portal/api", endpoint = "admin-tokens-list")]
pub async fn load_admin_tokens() -> Result<Vec<AdminTokenSummary>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(admin_tokens_path())
        .map_err(|_| ServerFnError::new("admin tokens API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(admin_token_summary_fallbacks());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let mut tokens: Vec<AdminTokenSummary> = response
                .json()
                .map_err(|_| ServerFnError::new("admin tokens response was malformed"))?;
            // Defense-in-depth: even if a future API leak attached a hash, the
            // portal type cannot carry it — but explicitly drop any scope
            // strings that are empty so the UI renders a clean "—".
            for token in &mut tokens {
                token.site_scope = token.site_scope.take().filter(|s| !s.is_empty());
                token.environment_scope = token.environment_scope.take().filter(|s| !s.is_empty());
            }
            Ok(tokens)
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "admin tokens fetch failed",
        ))),
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// `POST /api/admin/tokens` — mint a token. The 201 response carries the
/// one-time plaintext secret, which is returned to the caller component
/// exactly once and never persisted. Mutations never degrade to fallbacks.
#[server(prefix = "/portal/api", endpoint = "admin-tokens-create")]
pub async fn create_admin_token(
    payload: CreateTokenPayload,
) -> Result<CreateTokenResult, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(admin_tokens_path())
        .map_err(|_| ServerFnError::new("admin tokens API path failed same-origin guard"))?;
    if let Some(role) = first_unknown_role(&payload.roles) {
        return Err(ServerFnError::new(format!("Unknown role: {role}")));
    }
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_token_create(&payload);
    }
    let body = serde_json::json!({
        "name": payload.name,
        "owner_principal": payload.owner_principal,
        "roles": payload.roles,
        "site_scope": payload.site_scope,
        "environment_scope": payload.environment_scope,
        "expires_at": payload.expires_at,
    });
    let session_id = session_id_from_request().await;
    let response = upstream
        .post(path, Some(&body), session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "token creation was rejected by the API",
        )));
    }
    // The create body interleaves the row metadata with the one-time `token`.
    // Parse the metadata via the redacted type (so any hash is dropped) and
    // pull the plaintext out separately.
    let value: serde_json::Value = response
        .json()
        .map_err(|_| ServerFnError::new("token create response was malformed"))?;
    let token = value
        .get("token")
        .and_then(|token| token.as_str())
        .ok_or_else(|| ServerFnError::new("token create response did not include the secret"))?
        .to_string();
    let metadata: AdminTokenSummary = serde_json::from_value(value)
        .map_err(|_| ServerFnError::new("token create metadata was malformed"))?;
    Ok(CreateTokenResult { token, metadata })
}

/// `DELETE /api/admin/tokens/{id}` — revoke (soft-delete) a token.
#[server(prefix = "/portal/api", endpoint = "admin-tokens-revoke")]
pub async fn revoke_admin_token(token_id: String) -> Result<RevokeResult, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = admin_token_revoke_path(&token_id)
        .map_err(|_| ServerFnError::new("admin token revoke API path failed same-origin guard"))?;
    boundary
        .validate_admin_resource_revoke_path(&path)
        .map_err(|_| ServerFnError::new("admin token revoke API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_revoke("token");
    }
    let session_id = session_id_from_request().await;
    let response = upstream
        .delete(&path, session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "token revoke was rejected by the API",
        )));
    }
    Ok(RevokeResult {
        status: "revoked".to_string(),
        id: token_id,
    })
}

/// `GET /api/admin/sessions` — list active sessions. Static mode returns a
/// labeled synthetic row.
#[server(prefix = "/portal/api", endpoint = "admin-sessions-list")]
pub async fn load_admin_sessions() -> Result<Vec<AdminSessionSummary>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(admin_sessions_path())
        .map_err(|_| ServerFnError::new("admin sessions API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(admin_session_summary_fallbacks());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let sessions: Vec<AdminSessionSummary> = response
                .json()
                .map_err(|_| ServerFnError::new("admin sessions response was malformed"))?;
            Ok(sessions)
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "admin sessions fetch failed",
        ))),
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// `DELETE /api/admin/sessions/{id}` — admin revoke of ANY session (closes the
/// self-only `auth_logout` gap). Hard-delete server-side; mutation never
/// degrades.
#[server(prefix = "/portal/api", endpoint = "admin-sessions-revoke")]
pub async fn revoke_admin_session(
    session_target_id: String,
) -> Result<RevokeResult, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = admin_session_revoke_path(&session_target_id).map_err(|_| {
        ServerFnError::new("admin session revoke API path failed same-origin guard")
    })?;
    boundary
        .validate_admin_resource_revoke_path(&path)
        .map_err(|_| {
            ServerFnError::new("admin session revoke API path failed same-origin guard")
        })?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_revoke("session");
    }
    // Forward the caller's own session id so the API gate authenticates the
    // admin; the target session to delete is carried in the path.
    let session_id = session_id_from_request().await;
    let response = upstream
        .delete(&path, session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "session revoke was rejected by the API",
        )));
    }
    Ok(RevokeResult {
        status: "revoked".to_string(),
        id: session_target_id,
    })
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

/// Signs in against the upstream local-auth endpoint. The upstream
/// `session_id` is stored in the portal-origin `ryuki_session` cookie and
/// never reaches WASM; the browser only receives the [`AuthSession`]
/// identity fields.
#[server(prefix = "/portal/api", endpoint = "auth-login")]
pub async fn perform_login(
    username: String,
    password: String,
) -> Result<AuthSession, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(auth_local_login_path())
        .map_err(|_| ServerFnError::new("auth login API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        // Static demo: the auth gate is bypassed with the labeled synthetic
        // session; the credentials are intentionally ignored.
        let _ = (username, password);
        return Ok(auth_session_fallback());
    }
    let body = serde_json::json!({ "username": username, "password": password });
    let response = upstream
        .post(path, Some(&body), None)
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if response.status == 401 {
        // Deliberately generic: unknown user and wrong password are
        // indistinguishable (no account enumeration).
        return Err(ServerFnError::new("Invalid username or password"));
    }
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "Sign-in failed",
        )));
    }
    let login: ApiLoginSession = response
        .json()
        .map_err(|_| ServerFnError::new("Sign-in response was malformed"))?;
    // The cookie lifetime tracks the upstream session expiry, falling back
    // to one day when `expires_at` is absent or unparseable.
    set_portal_session_cookie(
        &login.session_id,
        cookie_max_age_from_expires_at(&login.expires_at),
    );
    Ok(AuthSession::from(login))
}

/// Signs out: best-effort upstream logout with the forwarded session header,
/// then clears the portal cookie regardless of the upstream outcome.
#[server(prefix = "/portal/api", endpoint = "auth-logout")]
pub async fn perform_logout() -> Result<(), ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(auth_local_logout_path())
        .map_err(|_| ServerFnError::new("auth logout API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if upstream.live() {
        let session_id = session_id_from_request().await;
        let _ = upstream.post(path, None, session_id.as_deref()).await;
    }
    clear_portal_session_cookie();
    Ok(())
}

/// Applies the request-list facets to the synthetic fallback rows so the
/// filter/sort UI stays interactive in static/degraded mode. Mirrors the
/// upstream semantics (commit fa1df10): case-insensitive exact match on
/// `status`/`site`, case-insensitive substring on the request `name` for `q`,
/// and `sort`+`direction` ordering. `created_at` maps to the `created` field.
///
/// Only compiled for the SSR (and test) builds: the sole caller lives inside
/// the `get_request_list` server-fn body, which the `#[server]` macro keeps
/// SSR-only — so the hydrate build would otherwise see it as dead code.
#[cfg(any(feature = "ssr", test))]
fn filter_request_summaries(
    rows: Vec<RequestSummary>,
    query: &crate::api::RequestListQuery,
) -> Vec<RequestSummary> {
    // Normalize each facet to a lowercased, non-empty needle (or None).
    let normalize = |value: &Option<String>| -> Option<String> {
        value
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_ascii_lowercase)
    };
    let status = normalize(&query.status);
    let site = normalize(&query.site);
    let needle = normalize(&query.q);
    let mut filtered: Vec<RequestSummary> = rows
        .into_iter()
        .filter(|row| match &status {
            Some(s) => row.status.to_ascii_lowercase() == *s,
            None => true,
        })
        .filter(|row| match &site {
            Some(s) => row.site.to_ascii_lowercase() == *s,
            None => true,
        })
        .filter(|row| match &needle {
            Some(n) => row.name.to_ascii_lowercase().contains(n),
            None => true,
        })
        .collect();

    if let Some(sort) = query
        .sort
        .as_deref()
        .filter(|s| crate::api::REQUEST_LIST_SORT_KEYS.contains(s))
    {
        filtered.sort_by(|a, b| {
            let key = |row: &RequestSummary| match sort {
                "name" => row.name.to_ascii_lowercase(),
                "status" => row.status.to_ascii_lowercase(),
                "site" => row.site.to_ascii_lowercase(),
                "request_type" => row.request_type.to_ascii_lowercase(),
                // `created_at`/`updated_at` both order by the only timestamp the
                // summary carries; the fallback rows have no separate update ts.
                _ => row.created.to_ascii_lowercase(),
            };
            key(a).cmp(&key(b))
        });
        if query.direction.as_deref() == Some("desc") {
            filtered.reverse();
        }
    }
    filtered
}

/// Faceted request-list read (#15). Optional `status`/`site`/`q` filters and
/// `sort`/`direction` ordering are forwarded to the upstream
/// `GET /api/requests` endpoint (API contract fa1df10). All-`None` arguments
/// reproduce the unfiltered default list, so existing call sites are
/// unaffected.
///
/// The same-origin allowlist validates the *base* path; the query suffix is
/// appended only after validation and carries solely allowlist-validated keys
/// and percent-encoded values (see `RequestListQuery::to_query_string`), so no
/// caller input ever reaches the upstream unescaped.
#[server(prefix = "/portal/api", endpoint = "request-list-data")]
pub async fn get_request_list(
    status: Option<String>,
    site: Option<String>,
    q: Option<String>,
    sort: Option<String>,
    direction: Option<String>,
) -> Result<Vec<RequestSummary>, ServerFnError> {
    use crate::api::{request_list_path_with_query, RequestListQuery};

    let boundary = PortalServerBoundary::static_dry_run();
    // Validate the base path against the same-origin allowlist BEFORE appending
    // the facet query string. The allowlist matches the path without a query.
    boundary
        .validate_platform_api_path(request_list_path())
        .map_err(|_| ServerFnError::new("request list API path failed same-origin guard"))?;
    let query = RequestListQuery {
        status,
        site,
        q,
        sort,
        direction,
        limit: None,
        offset: None,
    };
    let path = request_list_path_with_query(&query);
    let upstream = upstream_context();
    if !upstream.live() {
        // Static/degraded mode filters the synthetic fallback rows locally so
        // the facet UI stays interactive even without an upstream.
        let rows = request_summary_fallbacks();
        return Ok(filter_request_summaries(rows, &query));
    }
    let session_id = session_id_from_request().await;
    match upstream.get(&path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let list: Vec<ApiRequestSummary> = response
                .json()
                .map_err(|_| ServerFnError::new("request list response was malformed"))?;
            Ok(list.into_iter().map(RequestSummary::from).collect())
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "request list fetch failed",
        ))),
        // Live mode never substitutes demo rows for an unreachable API;
        // the list view renders an explicit unreachable state.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

#[server(prefix = "/portal/api", endpoint = "approvals-pending-data")]
pub async fn get_approvals_pending() -> Result<Vec<RequestSummary>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(approvals_pending_path())
        .map_err(|_| ServerFnError::new("approvals pending API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        // There is no honest synthetic per-approver demo set. Return an empty
        // queue in static/degraded mode — consistent with Slice 1's no-DB []
        // behavior and the Approvals inbox design (Risk #2).
        return Ok(Vec::new());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let list: Vec<ApiRequestSummary> = response
                .json()
                .map_err(|_| ServerFnError::new("approvals pending response was malformed"))?;
            Ok(list.into_iter().map(RequestSummary::from).collect())
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "approvals pending fetch failed",
        ))),
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Live GET of the current user's unread notification count. Returns 0 in
/// static/degraded mode (consistent with Slice 1's no-DB behavior). The API
/// returns a `{source, unread}` envelope, so we parse the wrapper.
#[server(prefix = "/portal/api", endpoint = "notifications-unread-count")]
pub async fn get_notifications_unread_count() -> Result<i64, ServerFnError> {
    #[derive(serde::Deserialize)]
    struct UnreadEnvelope {
        unread: i64,
    }
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(notifications_unread_count_path())
        .map_err(|_| {
            ServerFnError::new("notifications unread-count API path failed same-origin guard")
        })?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(0);
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let env: UnreadEnvelope = response.json().map_err(|_| {
                ServerFnError::new("notifications unread-count response was malformed")
            })?;
            Ok(env.unread)
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "notifications unread-count fetch failed",
        ))),
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Live GET of the current user's notification feed (newest first). Returns an
/// empty Vec in static/degraded mode. The API returns a `{source, notifications}`
/// envelope, so we parse the wrapper and return the inner list.
#[server(prefix = "/portal/api", endpoint = "notifications-list")]
pub async fn get_notifications() -> Result<Vec<NotificationSummary>, ServerFnError> {
    #[derive(serde::Deserialize)]
    struct ListEnvelope {
        notifications: Vec<NotificationSummary>,
    }
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(notifications_path())
        .map_err(|_| ServerFnError::new("notifications list API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(Vec::new());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let env: ListEnvelope = response
                .json()
                .map_err(|_| ServerFnError::new("notifications list response was malformed"))?;
            Ok(env.notifications)
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "notifications list fetch failed",
        ))),
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Live POST marking ALL of the current user's notifications read. Returns the
/// number marked (0 in static/degraded mode). The API returns a `{source, marked}`
/// envelope. Identity is server-derived; the API self-scopes to the caller.
#[server(prefix = "/portal/api", endpoint = "notifications-mark-all-read")]
pub async fn mark_all_notifications_read() -> Result<i64, ServerFnError> {
    #[derive(serde::Deserialize)]
    struct MarkedEnvelope {
        marked: i64,
    }
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(notifications_read_all_path())
        .map_err(|_| {
            ServerFnError::new("notifications read-all API path failed same-origin guard")
        })?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(0);
    }
    let session_id = session_id_from_request().await;
    match upstream.post(path, None, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let env: MarkedEnvelope = response
                .json()
                .map_err(|_| ServerFnError::new("notifications read-all response was malformed"))?;
            Ok(env.marked)
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "notifications read-all failed",
        ))),
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Live POST marking ONE of the current user's notifications read. Mirrors
/// `mark_all_notifications_read` but targets the id-bearing
/// `/api/notifications/{id}/read` path (validated through the dedicated
/// id allowlist, reusing the same id sanitisation as other id routes).
///
/// Returns `Ok(())` on success. The API self-scopes to the caller (404 for a
/// non-recipient — no existence leak), and the call is idempotent server-side.
/// In static/degraded mode there is nothing to mark, so this is a no-op `Ok(())`.
#[server(prefix = "/portal/api", endpoint = "notifications-mark-read")]
pub async fn mark_notification_read(id: String) -> Result<(), ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = notifications_read_path(&id)
        .map_err(|_| ServerFnError::new("notification read API path failed same-origin guard"))?;
    boundary
        .validate_notifications_read_path(&path)
        .map_err(|_| ServerFnError::new("notification read API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(());
    }
    let session_id = session_id_from_request().await;
    match upstream.post(&path, None, session_id.as_deref()).await {
        Ok(response) if response.is_success() => Ok(()),
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "notification mark-read failed",
        ))),
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Live GET of a single request detail through the allowlisted lifecycle
/// path; shared by detail reads, create follow-ups, and stage transitions.
#[cfg(feature = "ssr")]
async fn fetch_request_detail_live(
    upstream: &UpstreamClient,
    request_id: &str,
) -> Result<RequestDetail, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_detail_path(request_id)
        .map_err(|_| ServerFnError::new("request detail API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request detail API path failed same-origin guard"))?;
    let session_id = session_id_from_request().await;
    let response = upstream
        .get(&path, session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new("API unreachable"))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "request detail fetch failed",
        )));
    }
    let detail: ApiRequestDetail = response
        .json()
        .map_err(|_| ServerFnError::new("request detail response was malformed"))?;
    Ok(RequestDetail::from(detail))
}

#[server(prefix = "/portal/api", endpoint = "request-detail-data")]
pub async fn get_request_detail(request_id: String) -> Result<RequestDetail, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_detail_path(&request_id)
        .map_err(|_| ServerFnError::new("request detail API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request detail API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(request_detail_fallback(&request_id));
    }
    let session_id = session_id_from_request().await;
    match upstream.get(&path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let detail: ApiRequestDetail = response
                .json()
                .map_err(|_| ServerFnError::new("request detail response was malformed"))?;
            Ok(RequestDetail::from(detail))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "request detail fetch failed",
        ))),
        // Live mode never substitutes the demo detail for an unreachable
        // API; the detail view renders an explicit unreachable state.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Returns the execution-agent job for a request, or `None` when no job has
/// been dispatched yet (the API returns 404 in that case — not an error).
///
/// In static dry-run mode the upstream is not live so the function returns
/// `Ok(None)` immediately rather than attempting a real HTTP call.
#[server(prefix = "/portal/api", endpoint = "request-execution-job")]
pub async fn get_request_execution_job(
    request_id: String,
) -> Result<Option<ExecutionJob>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_execution_job_path(&request_id)
        .map_err(|_| ServerFnError::new("execution-job API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("execution-job API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(None);
    }
    let session_id = session_id_from_request().await;
    let response = upstream
        .get(&path, session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new("API unreachable"))?;
    if response.status == 404 {
        // No job dispatched for this request yet — not an error.
        return Ok(None);
    }
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "execution-job fetch failed",
        )));
    }
    let api_job: ApiExecutionJob = response
        .json()
        .map_err(|_| ServerFnError::new("execution-job response was malformed"))?;
    Ok(Some(ExecutionJob::from(api_job)))
}

#[cfg(any(feature = "ssr", test))]
fn reject_static_preview_request_create(
    payload: CreateRequestPayload,
) -> Result<RequestDetail, ServerFnError> {
    let _ = payload;
    Err(ServerFnError::new(
        "Portal request creation is preview-only in static dry-run mode; no request was persisted",
    ))
}

#[cfg(any(feature = "ssr", test))]
fn reject_static_preview_request_action(
    request_id: String,
    action: &str,
) -> Result<StageActionResponse, ServerFnError> {
    let _ = request_id;
    Err(ServerFnError::new(format!(
        "Portal request {action} is preview-only in static dry-run mode; no lifecycle state was changed"
    )))
}

#[server(prefix = "/portal/api", endpoint = "request-create-save")]
pub async fn create_request(payload: CreateRequestPayload) -> Result<RequestDetail, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(request_create_path())
        .map_err(|_| ServerFnError::new("request create API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_create(payload);
    }
    // The portal `memory` field maps to the API `memory_gb` field; `fields`
    // carries the per-type intake inputs the API merges into the request payload.
    let body = serde_json::json!({
        "request_type": payload.request_type,
        "name": payload.name,
        "site": payload.site,
        "environment": payload.environment,
        "cpu": payload.cpu,
        "memory_gb": payload.memory,
        "justification": payload.justification,
        "fields": payload.fields,
    });
    let session_id = session_id_from_request().await;
    let response = upstream
        .post(path, Some(&body), session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "request creation was rejected by the API",
        )));
    }
    let created: serde_json::Value = response
        .json()
        .map_err(|_| ServerFnError::new("request create response was malformed"))?;
    let request_id = created
        .get("id")
        .and_then(|id| id.as_str())
        .ok_or_else(|| ServerFnError::new("request create response did not include an id"))?
        .to_string();
    match fetch_request_detail_live(&upstream, &request_id).await {
        Ok(detail) => Ok(detail),
        // The request was created; if the follow-up read fails, return a
        // minimal detail so the UI can still navigate to the new request.
        Err(_) => Ok(RequestDetail {
            id: request_id,
            request_type: payload.request_type,
            name: payload.name,
            site: payload.site,
            environment: payload.environment,
            cpu: payload.cpu,
            memory: payload.memory,
            justification: payload.justification,
            status: "intake".to_string(),
            stage: "intake".to_string(),
            created: String::new(),
            updated: String::new(),
            timeline: Vec::new(),
            actions_available: actions_for_stage("intake"),
            // The follow-up read failed, so the persisted-state fields are not
            // yet known; leave them empty rather than fabricating values.
            criticality: String::new(),
            requester: String::new(),
            owner: String::new(),
            plan: String::new(),
            approval_route: Vec::new(),
            stages: Vec::new(),
            payload_fields: Vec::new(),
        }),
    }
}

/// Live POST of a lifecycle stage action. 2xx maps to an in-flow success
/// badge with the freshly fetched stage; 4xx (lifecycle guards, role
/// denials) maps to an in-flow failure badge carrying the API message;
/// transport failures and 5xx surface as errors — mutations never degrade.
#[cfg(feature = "ssr")]
async fn dispatch_stage_action_live(
    request_id: String,
    action: &str,
    path: &str,
) -> Result<StageActionResponse, ServerFnError> {
    let upstream = upstream_context();
    let session_id = session_id_from_request().await;
    let response = upstream
        .post(path, None, session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if response.is_success() {
        let new_stage = fetch_request_detail_live(&upstream, &request_id)
            .await
            .map(|detail| detail.stage)
            .unwrap_or_default();
        Ok(StageActionResponse {
            request_id,
            success: true,
            new_stage,
            message: format!("{action} completed"),
        })
    } else {
        Ok(StageActionResponse {
            request_id,
            success: false,
            new_stage: String::new(),
            message: api_error_text(&response, &format!("{action} was rejected by the API")),
        })
    }
}

#[server(prefix = "/portal/api", endpoint = "request-validate")]
pub async fn validate_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_validate_path(&request_id)
        .map_err(|_| ServerFnError::new("request validate API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request validate API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "validation");
    }
    dispatch_stage_action_live(request_id, "validation", &path).await
}

#[server(prefix = "/portal/api", endpoint = "request-plan")]
pub async fn plan_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_plan_path(&request_id)
        .map_err(|_| ServerFnError::new("request plan API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request plan API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "planning");
    }
    dispatch_stage_action_live(request_id, "planning", &path).await
}

#[server(prefix = "/portal/api", endpoint = "request-approve")]
pub async fn approve_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_approve_path(&request_id)
        .map_err(|_| ServerFnError::new("request approve API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request approve API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "approval");
    }
    dispatch_stage_action_live(request_id, "approval", &path).await
}

#[server(prefix = "/portal/api", endpoint = "request-lock")]
pub async fn lock_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_lock_path(&request_id)
        .map_err(|_| ServerFnError::new("request lock API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request lock API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "locking");
    }
    dispatch_stage_action_live(request_id, "locking", &path).await
}

#[server(prefix = "/portal/api", endpoint = "request-execute")]
pub async fn execute_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_execute_path(&request_id)
        .map_err(|_| ServerFnError::new("request execute API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request execute API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "execution");
    }
    dispatch_stage_action_live(request_id, "execution", &path).await
}

#[server(prefix = "/portal/api", endpoint = "request-execute-live-plan")]
pub async fn execute_request_live_plan(
    request_id: String,
) -> Result<StageActionResponse, ServerFnError> {
    // Validate the BASE execute path through the same allowlist guards used by
    // execute_request — the allowlist sees the plain ".../execute" suffix, not
    // the query string appended below.
    let boundary = PortalServerBoundary::static_dry_run();
    let base_path = request_execute_path(&request_id)
        .map_err(|_| ServerFnError::new("request execute API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&base_path)
        .map_err(|_| ServerFnError::new("request execute API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "live plan");
    }
    // Append the static mode query string AFTER the allowlist guard so that
    // the allowlist only ever sees the plain "/execute" suffix. The mode value
    // is a static string literal — no user input is interpolated here.
    let live_plan_path = format!("{base_path}?mode=live-plan");
    dispatch_stage_action_live(request_id, "live plan", &live_plan_path).await
}

/// Admin-gated action that mints a CP-signed LiveApply grant from the
/// request's completed LivePlan. Mirrors `execute_request_live_plan` exactly:
/// the allowlist sees the plain ".../approve-live-apply" suffix, which is
/// already registered in `is_allowed_request_lifecycle_path`. Static dry-run
/// mode rejects the action so no lifecycle state is changed in preview.
#[server(prefix = "/portal/api", endpoint = "request-approve-live-apply")]
pub async fn approve_live_apply_request(
    request_id: String,
) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_approve_live_apply_path(&request_id).map_err(|_| {
        ServerFnError::new("request approve-live-apply API path failed same-origin guard")
    })?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| {
            ServerFnError::new("request approve-live-apply API path failed same-origin guard")
        })?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "live apply");
    }
    dispatch_stage_action_live(request_id, "live apply", &path).await
}

#[server(prefix = "/portal/api", endpoint = "request-verify-stage")]
pub async fn verify_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_verify_path(&request_id)
        .map_err(|_| ServerFnError::new("request verify API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request verify API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "verification");
    }
    dispatch_stage_action_live(request_id, "verification", &path).await
}

/// Post-completion Protect stage (Theme 8). Bodyless POST gated server-side on
/// `execute`; valid only from a Completed request. Mirrors `verify_request`.
#[server(prefix = "/portal/api", endpoint = "request-protect")]
pub async fn protect_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_protect_path(&request_id)
        .map_err(|_| ServerFnError::new("request protect API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request protect API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "protection");
    }
    dispatch_stage_action_live(request_id, "protection", &path).await
}

/// Post-completion Publish stage (Theme 8). Bodyless POST gated server-side on
/// `execute`; valid only from a Protecting request. Mirrors `verify_request`.
#[server(prefix = "/portal/api", endpoint = "request-publish")]
pub async fn publish_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_publish_path(&request_id)
        .map_err(|_| ServerFnError::new("request publish API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request publish API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "publication");
    }
    dispatch_stage_action_live(request_id, "publication", &path).await
}

/// Post-completion Retire stage (Theme 8). Bodyless POST gated server-side on
/// `execute`; valid only from an Operational request. Note: unlike
/// reject/cancel, the API retire handler takes no reason body, so this mirrors
/// the bodyless `verify_request` path, not the reason-bearing decisions.
#[server(prefix = "/portal/api", endpoint = "request-retire")]
pub async fn retire_request(request_id: String) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_retire_path(&request_id)
        .map_err(|_| ServerFnError::new("request retire API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request retire API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "retirement");
    }
    dispatch_stage_action_live(request_id, "retirement", &path).await
}

/// Live POST of a reason-bearing lifecycle decision (reject/cancel). Unlike
/// `dispatch_stage_action_live` (which posts no body), this sends a
/// `{"reason": ...}` JSON body — these transitions are never bodyless. 2xx
/// maps to a success badge with the freshly fetched terminal stage; 4xx (the
/// 409 lifecycle guard, the 403 role/SoD denial, the 400 empty-reason guard)
/// maps to a failure badge carrying the API safe message; transport failures
/// and 5xx surface as errors so mutations never silently degrade.
#[cfg(feature = "ssr")]
async fn dispatch_reason_action_live(
    request_id: String,
    action: &str,
    reason: String,
    path: &str,
) -> Result<StageActionResponse, ServerFnError> {
    let upstream = upstream_context();
    let session_id = session_id_from_request().await;
    let body = serde_json::json!({ "reason": reason });
    let response = upstream
        .post(path, Some(&body), session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if response.is_success() {
        let new_stage = fetch_request_detail_live(&upstream, &request_id)
            .await
            .map(|detail| detail.stage)
            .unwrap_or_default();
        Ok(StageActionResponse {
            request_id,
            success: true,
            new_stage,
            message: format!("{action} completed"),
        })
    } else {
        Ok(StageActionResponse {
            request_id,
            success: false,
            new_stage: String::new(),
            message: api_error_text(&response, &format!("{action} was rejected by the API")),
        })
    }
}

/// Rejects an empty/whitespace reason before any upstream call, mirroring the
/// API's 400 guard so the user gets immediate, safe feedback.
#[cfg(any(feature = "ssr", test))]
fn require_reason(action: &str, reason: &str) -> Result<String, ServerFnError> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return Err(ServerFnError::new(format!(
            "A reason is required to {action} this request"
        )));
    }
    Ok(trimmed.to_string())
}

#[server(prefix = "/portal/api", endpoint = "request-reject")]
pub async fn reject_request(
    request_id: String,
    reason: String,
) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_reject_path(&request_id)
        .map_err(|_| ServerFnError::new("request reject API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request reject API path failed same-origin guard"))?;
    let reason = require_reason("reject", &reason)?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "rejection");
    }
    dispatch_reason_action_live(request_id, "rejection", reason, &path).await
}

#[server(prefix = "/portal/api", endpoint = "request-cancel")]
pub async fn cancel_request(
    request_id: String,
    reason: String,
) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_cancel_path(&request_id)
        .map_err(|_| ServerFnError::new("request cancel API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request cancel API path failed same-origin guard"))?;
    let reason = require_reason("cancel", &reason)?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_request_action(request_id, "cancellation");
    }
    dispatch_reason_action_live(request_id, "cancellation", reason, &path).await
}

/// Reads the durable who-did-what-when trail for a single request through the
/// allowlisted `GET /api/requests/{id}/audit` read endpoint (gated server-side
/// on the `audit` permission). Static mode serves a labeled, clearly
/// non-durable preview trail; a live API that is unreachable surfaces an
/// error so the timeline can fall back rather than show stale data.
#[server(prefix = "/portal/api", endpoint = "request-audit-trail")]
pub async fn get_request_audit(request_id: String) -> Result<Vec<AuditEventRow>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_audit_path(&request_id)
        .map_err(|_| ServerFnError::new("request audit API path failed same-origin guard"))?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request audit API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(static_preview_audit_trail(&request_id));
    }
    let session_id = session_id_from_request().await;
    match upstream.get(&path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let trail: ApiAuditTrail = response
                .json()
                .map_err(|_| ServerFnError::new("request audit response was malformed"))?;
            Ok(trail.into_rows())
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "request audit fetch failed",
        ))),
        // Live mode never substitutes the preview trail for an unreachable
        // API; the timeline renders the synthetic detail fallback instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Exports the tamper-evident compliance evidence pack for one request through
/// the allowlisted `GET /api/requests/{id}/evidence` read endpoint (gated
/// server-side on the `audit` permission). Static mode serves a labeled,
/// clearly non-durable preview pack; a live API that is unreachable surfaces an
/// error so the panel renders an explicit degraded state rather than a pack
/// that was never sealed against real data.
#[server(prefix = "/portal/api", endpoint = "request-evidence-pack")]
pub async fn get_request_evidence(request_id: String) -> Result<EvidencePackExport, ServerFnError> {
    let path = request_evidence_path(&request_id)
        .map_err(|_| ServerFnError::new("request evidence API path failed same-origin guard"))?;
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| ServerFnError::new("request evidence API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(static_preview_evidence_pack(&request_id));
    }
    let session_id = session_id_from_request().await;
    match upstream.get(&path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            // Pretty-print the canonical pack for the copy/export affordance
            // before consuming the typed view-model.
            let pretty = serde_json::from_str::<serde_json::Value>(&response.body)
                .ok()
                .and_then(|value| serde_json::to_string_pretty(&value).ok())
                .unwrap_or_else(|| response.body.clone());
            let pack: ApiEvidencePack = response
                .json()
                .map_err(|_| ServerFnError::new("request evidence response was malformed"))?;
            Ok(pack.into_export(pretty))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "request evidence fetch failed",
        ))),
        // Live mode never substitutes an unsealed preview for an unreachable
        // API; the panel renders an explicit degraded state instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Labeled, clearly non-durable preview evidence pack for static-dry-run mode.
/// `durable=false` and a non-sealed digest flag that nothing was sealed against
/// persisted data; the items are illustrative and already redacted.
#[cfg(any(feature = "ssr", test))]
#[allow(dead_code)]
fn static_preview_evidence_pack(request_id: &str) -> EvidencePackExport {
    let items = vec![
        crate::models::EvidencePackItem {
            key: "request-payload-summary".into(),
            value: format!(
                "Preview evidence for request {request_id} (static dry-run; not sealed against persisted data)"
            ),
            redacted: false,
            evidence_type: "Summary".into(),
        },
        crate::models::EvidencePackItem {
            key: "approval-route-entry".into(),
            value: "Approver role: DatacenterApprover".into(),
            redacted: false,
            evidence_type: "ApprovalDecision".into(),
        },
    ];
    let pack_json =
        "{\n  \"preview\": true,\n  \"note\": \"static dry-run preview — no persisted evidence\"\n}"
            .to_string();
    EvidencePackExport {
        request_id: request_id.to_string(),
        generated_at: "2026-06-13T08:00:00Z".into(),
        algorithm: "sha256".into(),
        digest: "sha256:preview-not-sealed".into(),
        durable: false,
        item_count: items.len(),
        audit_count: 0,
        redacted: true,
        items,
        pack_json,
        audit_rows: Vec::new(),
    }
}

/// Reads the global, newest-first governance audit feed across all requests
/// through the allowlisted `GET /api/activity/audit` read endpoint (gated
/// server-side on the `audit` permission). Static mode serves a labeled,
/// clearly non-durable preview feed; a live API that is unreachable surfaces an
/// error so the Activity view renders an explicit degraded state rather than
/// stale data.
#[server(prefix = "/portal/api", endpoint = "activity-audit-feed")]
pub async fn get_activity_audit_feed() -> Result<Vec<AuditEventRow>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(activity_audit_feed_path())
        .map_err(|_| ServerFnError::new("activity audit feed API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(static_preview_activity_feed());
    }
    // The feed shows the most recent governance actions; a generous page keeps
    // the timeline useful without unbounded payloads (the API caps at 200).
    let fetch_path = format!("{path}?limit=100");
    let session_id = session_id_from_request().await;
    match upstream.get(&fetch_path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let feed: ApiAuditTrail = response
                .json()
                .map_err(|_| ServerFnError::new("activity audit feed response was malformed"))?;
            Ok(feed.into_rows())
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "activity audit feed fetch failed",
        ))),
        // Live mode never substitutes preview rows for an unreachable API; the
        // Activity view renders an explicit degraded state instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Labeled, clearly non-durable preview feed for static-dry-run mode. Each row
/// is marked `durable=false` so the Activity timeline can flag that nothing was
/// persisted, and carries a `request_id` so the deep-links still resolve.
#[cfg(any(feature = "ssr", test))]
#[allow(dead_code)]
fn static_preview_activity_feed() -> Vec<AuditEventRow> {
    #[allow(clippy::too_many_arguments)]
    fn preview_row(
        action: &str,
        actor_display: &str,
        actor_principal: &str,
        roles: &[&str],
        from_stage: Option<&str>,
        to_stage: &str,
        to_status: &str,
        occurred_at: &str,
        request_id: &str,
    ) -> AuditEventRow {
        AuditEventRow {
            action: action.to_string(),
            actor_display: actor_display.to_string(),
            actor_principal: actor_principal.to_string(),
            from_stage: from_stage.map(str::to_string),
            to_stage: to_stage.to_string(),
            to_status: to_status.to_string(),
            occurred_at: occurred_at.to_string(),
            reason: None,
            durable: false,
            request_id: Some(request_id.to_string()),
            actor_roles: roles.iter().map(|role| role.to_string()).collect(),
            outcome: Some("applied".to_string()),
        }
    }
    vec![
        preview_row(
            "request.approve",
            "Datacenter Approver (preview)",
            "approver",
            &["DatacenterApprover"],
            Some("plan"),
            "approve",
            "approved",
            "2026-06-13T08:12:00Z",
            "PREVIEW-2",
        ),
        preview_row(
            "request.plan",
            "Platform Engineer (preview)",
            "platform-engineer",
            &["VMwareOperator"],
            Some("validate"),
            "plan",
            "planned",
            "2026-06-13T08:06:00Z",
            "PREVIEW-2",
        ),
        preview_row(
            "request.create",
            "Requester (preview)",
            "requester",
            &["Requester"],
            None,
            "intake",
            "intake",
            "2026-06-13T08:00:00Z",
            "PREVIEW-1",
        ),
    ]
}

/// Labeled, clearly non-durable preview trail for static-dry-run mode. Marks
/// `durable=false` so the timeline can flag that no row was persisted.
#[cfg(any(feature = "ssr", test))]
fn static_preview_audit_trail(request_id: &str) -> Vec<AuditEventRow> {
    let _ = request_id;
    vec![AuditEventRow {
        action: "request.create".to_string(),
        actor_display: "Platform Engineer (preview)".to_string(),
        actor_principal: "platform-engineer".to_string(),
        from_stage: None,
        to_stage: "intake".to_string(),
        to_status: "intake".to_string(),
        occurred_at: "2026-06-13T08:00:00Z".to_string(),
        reason: None,
        durable: false,
        request_id: None,
        actor_roles: vec![],
        outcome: None,
    }]
}

// ── Integration server functions ──────────────────────────────────────────
//
// The static collection path (`/api/integrations`) is in `ALLOWED_PORTAL_API_PATHS`.
// Dynamic id paths (`/api/integrations/{id}` and `/api/integrations/{id}/test`)
// are NOT in the static list — they are validated inline via
// `same_origin_api_path()` + `safe_integration_id()` inside each server fn,
// mirroring the request lifecycle path pattern exactly.

#[server(prefix = "/portal/api", endpoint = "integrations-list")]
pub async fn list_integrations() -> Result<Vec<IntegrationSummary>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(integrations_path())
        .map_err(|_| ServerFnError::new("integrations API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        // Honest empty list in static/no-DB mode — same pattern as
        // `get_approvals_pending` and the Slice-1 empty-list behavior.
        return Ok(Vec::new());
    }
    let session_id = session_id_from_request().await;
    match upstream
        .get(integrations_path(), session_id.as_deref())
        .await
    {
        Ok(response) if response.is_success() => {
            let raw: serde_json::Value = response
                .json()
                .map_err(|_| ServerFnError::new("integrations list response was malformed"))?;
            let connections = raw
                .get("connections")
                .and_then(|c| c.as_array())
                .cloned()
                .unwrap_or_default();
            let summaries = connections
                .into_iter()
                .filter_map(|item| {
                    let id = item.get("id")?.as_str()?.to_string();
                    let vendor_type = item.get("vendor_type")?.as_str()?.to_string();
                    let name = item.get("name")?.as_str()?.to_string();
                    let endpoint_url = item.get("endpoint_url")?.as_str()?.to_string();
                    let site_scope = item
                        .get("site_scope")
                        .and_then(|s| s.as_str())
                        .map(str::to_string);
                    let credential_source = item.get("credential_source")?.as_str()?.to_string();
                    // Redact the opaque FK for db-encrypted: never expose it.
                    let credential_ref = if credential_source == "db-encrypted" {
                        None
                    } else {
                        item.get("credential_ref")
                            .and_then(|r| r.as_str())
                            .map(str::to_string)
                    };
                    let status = item.get("status")?.as_str()?.to_string();
                    let readiness = item
                        .get("readiness")
                        .and_then(|r| r.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let execution_mode = item
                        .get("execution_mode")
                        .and_then(|m| m.as_str())
                        .unwrap_or("static-dry-run")
                        .to_string();
                    let last_test_at = item
                        .get("last_test_at")
                        .and_then(|t| t.as_str())
                        .map(str::to_string);
                    let last_test_result = item
                        .get("last_test_result")
                        .and_then(|r| r.as_str())
                        .map(str::to_string);
                    let created_by = item
                        .get("created_by")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    let created_at = item.get("created_at")?.as_str()?.to_string();
                    let updated_at = item.get("updated_at")?.as_str()?.to_string();
                    Some(IntegrationSummary {
                        id,
                        vendor_type,
                        name,
                        endpoint_url,
                        site_scope,
                        credential_source,
                        credential_ref,
                        status,
                        readiness,
                        execution_mode,
                        last_test_at,
                        last_test_result,
                        created_by,
                        created_at,
                        updated_at,
                    })
                })
                .collect();
            Ok(summaries)
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "integrations list fetch failed",
        ))),
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

// ── Agent server functions ────────────────────────────────────────────────

#[server(prefix = "/portal/api", endpoint = "admin-agents-list")]
pub async fn get_admin_agents() -> Result<Vec<AgentSummary>, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(admin_agents_path())
        .map_err(|_| ServerFnError::new("admin agents API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        // Honest empty list in static/degraded mode — no synthetic agent rows.
        // Fabricating agents with fake platforms or statuses would mislead
        // operators about what is actually enrolled.
        return Ok(Vec::new());
    }
    let session_id = session_id_from_request().await;
    match upstream
        .get(admin_agents_path(), session_id.as_deref())
        .await
    {
        Ok(response) if response.is_success() => {
            let raw: serde_json::Value = response
                .json()
                .map_err(|_| ServerFnError::new("admin agents response was malformed"))?;
            let agent_values = raw
                .get("agents")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            let agents = agent_values
                .into_iter()
                .filter_map(|item| {
                    let agent_id = item.get("agent_id")?.as_str()?.to_string();
                    let platform = item.get("platform")?.as_str()?.to_string();
                    let status = item.get("status")?.as_str()?.to_string();
                    let last_seen_at = item
                        .get("last_seen_at")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    let created_at = item.get("created_at")?.as_str()?.to_string();
                    let jobs = item
                        .get("jobs")
                        .and_then(|j| j.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|j| {
                                    let id = j.get("id")?.as_str()?.to_string();
                                    let mode = j.get("mode")?.as_str()?.to_string();
                                    let status = j.get("status")?.as_str()?.to_string();
                                    let result_status = j
                                        .get("result_status")
                                        .and_then(|r| r.as_str())
                                        .map(str::to_string);
                                    let completed_at = j
                                        .get("completed_at")
                                        .and_then(|c| c.as_str())
                                        .map(str::to_string);
                                    Some(AgentJobSummary {
                                        id,
                                        mode,
                                        status,
                                        result_status,
                                        completed_at,
                                    })
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    Some(AgentSummary {
                        agent_id,
                        platform,
                        status,
                        last_seen_at,
                        created_at,
                        jobs,
                    })
                })
                .collect();
            Ok(agents)
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "admin agents fetch failed",
        ))),
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// `POST /api/admin/agents/{id}/approve` — approve a pending agent enrollment.
///
/// The API's approve body REQUIRES an authoritative `platform`; the portal
/// re-affirms the agent's currently displayed platform so a PlatformAdmin can
/// approve in one click. Capabilities are intentionally omitted, so the API
/// resets them to empty (its documented secure default): the admin must grant
/// capabilities explicitly rather than trust the agent's self-declared set.
/// Mutations never degrade to a fallback — a static/unreachable upstream errors.
#[server(prefix = "/portal/api", endpoint = "admin-agents-approve")]
pub async fn approve_agent(
    agent_id: String,
    platform: String,
) -> Result<RevokeResult, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = admin_agent_approve_path(&agent_id)
        .map_err(|_| ServerFnError::new("admin agent approve API path failed same-origin guard"))?;
    boundary
        .validate_admin_agent_approve_path(&path)
        .map_err(|_| ServerFnError::new("admin agent approve API path failed same-origin guard"))?;
    if platform.trim().is_empty() {
        return Err(ServerFnError::new(
            "agent approval requires a non-empty platform",
        ));
    }
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_agent_approve();
    }
    let body = serde_json::json!({ "platform": platform });
    let session_id = session_id_from_request().await;
    let response = upstream
        .post(&path, Some(&body), session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "agent approval was rejected by the API",
        )));
    }
    Ok(RevokeResult {
        status: "approved".to_string(),
        id: agent_id,
    })
}

/// `POST /api/admin/agents/{id}/revoke` — take an enrolled agent offline. The API
/// sets status='revoked' (terminal) so the agent's token is refused on its next
/// call. No body. Mutations never degrade to a fallback — a static/unreachable
/// upstream errors.
#[server(prefix = "/portal/api", endpoint = "admin-agents-revoke")]
pub async fn revoke_agent(agent_id: String) -> Result<RevokeResult, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = admin_agent_revoke_path(&agent_id)
        .map_err(|_| ServerFnError::new("admin agent revoke API path failed same-origin guard"))?;
    boundary
        .validate_admin_agent_revoke_path(&path)
        .map_err(|_| ServerFnError::new("admin agent revoke API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_revoke("agent");
    }
    let session_id = session_id_from_request().await;
    let response = upstream
        .post(&path, None, session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "agent revocation was rejected by the API",
        )));
    }
    Ok(RevokeResult {
        status: "revoked".to_string(),
        id: agent_id,
    })
}

#[server(prefix = "/portal/api", endpoint = "integration-create")]
pub async fn create_integration(
    payload: CreateIntegrationPayload,
) -> Result<IntegrationSummary, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    boundary
        .validate_platform_api_path(integrations_path())
        .map_err(|_| ServerFnError::new("integrations API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Err(ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE));
    }
    // `inline_secret` is sent in the body but NEVER logged (no Debug derive
    // on the payload struct; the custom Debug impl redacts it).
    let body = serde_json::json!({
        "vendor_type": payload.vendor_type,
        "name": payload.name,
        "endpoint_url": payload.endpoint_url,
        "site_scope": payload.site_scope,
        "credential_source": payload.credential_source,
        "credential_ref": payload.credential_ref,
        "inline_secret": payload.inline_secret,
    });
    let session_id = session_id_from_request().await;
    let response = upstream
        .post(integrations_path(), Some(&body), session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "integration create was rejected by the API",
        )));
    }
    let raw: serde_json::Value = response
        .json()
        .map_err(|_| ServerFnError::new("integration create response was malformed"))?;
    let credential_source = raw
        .get("credential_source")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    // Redact opaque FK for db-encrypted even from the create response.
    let credential_ref = if credential_source == "db-encrypted" {
        None
    } else {
        raw.get("credential_ref")
            .and_then(|r| r.as_str())
            .map(str::to_string)
    };
    Ok(IntegrationSummary {
        id: raw
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        vendor_type: raw
            .get("vendor_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: raw
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        endpoint_url: raw
            .get("endpoint_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        site_scope: raw
            .get("site_scope")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        credential_source,
        credential_ref,
        status: raw
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        readiness: raw
            .get("readiness")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        execution_mode: raw
            .get("execution_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("static-dry-run")
            .to_string(),
        last_test_at: raw
            .get("last_test_at")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        last_test_result: raw
            .get("last_test_result")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        created_by: raw
            .get("created_by")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        created_at: raw
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        updated_at: raw
            .get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[server(prefix = "/portal/api", endpoint = "integration-update")]
pub async fn update_integration(
    id: String,
    payload: UpdateIntegrationPayload,
) -> Result<IntegrationSummary, ServerFnError> {
    // Dynamic path validated inline via safe_integration_id — not in the
    // static allowlist, mirroring the request lifecycle path pattern.
    let path = integration_id_path(&id)
        .map_err(|_| ServerFnError::new("integration id path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Err(ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE));
    }
    let body = serde_json::json!({
        "vendor_type": payload.vendor_type,
        "name": payload.name,
        "endpoint_url": payload.endpoint_url,
        "site_scope": payload.site_scope,
        "credential_ref": payload.credential_ref,
        // Empty inline_secret = keep existing (no re-encryption, per Slice-1).
        "inline_secret": payload.inline_secret,
    });
    let session_id = session_id_from_request().await;
    let response = upstream
        .put(&path, &body, session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "integration update was rejected by the API",
        )));
    }
    let raw: serde_json::Value = response
        .json()
        .map_err(|_| ServerFnError::new("integration update response was malformed"))?;
    let credential_source = raw
        .get("credential_source")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let credential_ref = if credential_source == "db-encrypted" {
        None
    } else {
        raw.get("credential_ref")
            .and_then(|r| r.as_str())
            .map(str::to_string)
    };
    Ok(IntegrationSummary {
        id: raw
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        vendor_type: raw
            .get("vendor_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: raw
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        endpoint_url: raw
            .get("endpoint_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        site_scope: raw
            .get("site_scope")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        credential_source,
        credential_ref,
        status: raw
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        readiness: raw
            .get("readiness")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        execution_mode: raw
            .get("execution_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("static-dry-run")
            .to_string(),
        last_test_at: raw
            .get("last_test_at")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        last_test_result: raw
            .get("last_test_result")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        created_by: raw
            .get("created_by")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        created_at: raw
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        updated_at: raw
            .get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[server(prefix = "/portal/api", endpoint = "integration-delete")]
pub async fn delete_integration(id: String) -> Result<String, ServerFnError> {
    // Dynamic path validated inline.
    let path = integration_id_path(&id)
        .map_err(|_| ServerFnError::new("integration id path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Err(ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE));
    }
    let session_id = session_id_from_request().await;
    let response = upstream
        .delete(&path, session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new(MUTATION_UNREACHABLE_MESSAGE))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "integration delete was rejected by the API",
        )));
    }
    Ok(id)
}

#[server(prefix = "/portal/api", endpoint = "integration-test")]
pub async fn test_integration(id: String) -> Result<IntegrationTestResult, ServerFnError> {
    // Dynamic path validated inline.
    let path = integration_test_path(&id)
        .map_err(|_| ServerFnError::new("integration test path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        // Honest "blocked" result in static mode — not an error, because
        // testing is a read-only probe. The operator sees what the result
        // means rather than a generic failure.
        return Ok(IntegrationTestResult {
            connection_id: id,
            endpoint_status: "blocked".to_string(),
            endpoint_message:
                "Portal is in static/no-DB mode — live connectivity test not available.".to_string(),
            credential_status: "blocked".to_string(),
            credential_message:
                "Portal is in static/no-DB mode — credential verification not available."
                    .to_string(),
            tested_at: String::new(),
        });
    }
    let session_id = session_id_from_request().await;
    let response = upstream
        .post(&path, None, session_id.as_deref())
        .await
        .map_err(|_| ServerFnError::new("API unreachable"))?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "integration test failed",
        )));
    }
    let raw: serde_json::Value = response
        .json()
        .map_err(|_| ServerFnError::new("integration test response was malformed"))?;
    Ok(IntegrationTestResult {
        connection_id: raw
            .get("connection_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&id)
            .to_string(),
        endpoint_status: raw
            .get("endpoint_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        endpoint_message: raw
            .get("endpoint_message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        credential_status: raw
            .get("credential_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        credential_message: raw
            .get("credential_message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        tested_at: raw
            .get("tested_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::RequestListQuery;

    fn summary_row(name: &str, site: &str, status: &str, created: &str) -> RequestSummary {
        RequestSummary {
            id: format!("REQ-{name}"),
            request_type: "server".to_string(),
            name: name.to_string(),
            site: site.to_string(),
            environment: "prod".to_string(),
            status: status.to_string(),
            stage: status.to_string(),
            created: created.to_string(),
        }
    }

    #[test]
    fn filter_request_summaries_empty_query_is_identity() {
        let rows = vec![
            summary_row("Web", "ams1", "intake", "2026-01-02"),
            summary_row("Db", "fra1", "approved", "2026-01-01"),
        ];
        let out = filter_request_summaries(rows.clone(), &RequestListQuery::default());
        assert_eq!(out, rows);
    }

    #[test]
    fn filter_request_summaries_applies_status_site_and_q_case_insensitively() {
        let rows = vec![
            summary_row("Web Server", "ams1", "approved", "2026-01-03"),
            summary_row("Web Cache", "fra1", "approved", "2026-01-02"),
            summary_row("Database", "ams1", "intake", "2026-01-01"),
        ];
        let query = RequestListQuery {
            status: Some("APPROVED".to_string()),
            site: Some("AMS1".to_string()),
            q: Some("web".to_string()),
            ..Default::default()
        };
        let out = filter_request_summaries(rows, &query);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "Web Server");
    }

    #[test]
    fn filter_request_summaries_sorts_by_name_with_direction() {
        let rows = vec![
            summary_row("Charlie", "ams1", "intake", "2026-01-01"),
            summary_row("alpha", "ams1", "intake", "2026-01-02"),
            summary_row("Bravo", "ams1", "intake", "2026-01-03"),
        ];
        let asc = filter_request_summaries(
            rows.clone(),
            &RequestListQuery {
                sort: Some("name".to_string()),
                direction: Some("asc".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(
            asc.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "Bravo", "Charlie"]
        );
        let desc = filter_request_summaries(
            rows,
            &RequestListQuery {
                sort: Some("name".to_string()),
                direction: Some("desc".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(
            desc.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["Charlie", "Bravo", "alpha"]
        );
    }

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
    fn boundary_allows_distinct_auth_status_and_session_routes() {
        let boundary = PortalServerBoundary::static_dry_run();

        assert_eq!(
            boundary.validate_platform_api_path(auth_status_path()),
            Ok("/api/auth/status")
        );
        assert_eq!(
            boundary.validate_platform_api_path(auth_session_path()),
            Ok("/api/auth/session")
        );
        assert_ne!(auth_status_path(), auth_session_path());
    }

    #[test]
    fn boundary_allows_local_auth_login_and_logout_routes() {
        let boundary = PortalServerBoundary::static_dry_run();

        assert_eq!(
            boundary.validate_platform_api_path(auth_local_login_path()),
            Ok("/api/auth/local/login")
        );
        assert_eq!(
            boundary.validate_platform_api_path(auth_local_logout_path()),
            Ok("/api/auth/local/logout")
        );
    }

    #[test]
    fn degraded_route_state_repoints_context_strip_labels() {
        let snapshot = PortalRouteStateSnapshot::degraded_static_fallback()
            .expect("degraded route state snapshot must build");

        assert_eq!(snapshot.upstream_state, "degraded-static");
        assert_eq!(snapshot.execution_mode, "degraded-static-fallback");
        assert_eq!(
            snapshot.execution_authority_label,
            "Execution: blocked (API unreachable)"
        );
        for label in [
            &snapshot.inventory_freshness_label,
            &snapshot.backup_freshness_label,
            &snapshot.monitoring_freshness_label,
        ] {
            assert_eq!(label, "API unreachable — static preview");
        }
        // Degradation never loosens the boundary flags.
        assert!(!snapshot.http_request_allowed);
        assert!(!snapshot.live_execution_allowed);
    }

    #[test]
    fn live_route_state_is_labeled_live_without_loosening_boundary_flags() {
        let snapshot = PortalRouteStateSnapshot::live_provider()
            .expect("live route state snapshot must build");

        assert_eq!(snapshot.upstream_state, "live");
        assert_eq!(snapshot.execution_mode, "live-provider");
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.customer_identifiers_allowed);
    }

    #[test]
    fn boundary_allows_admin_platform_settings_reset_route() {
        let boundary = PortalServerBoundary::static_dry_run();

        assert_eq!(
            boundary.validate_platform_api_path(admin_platform_settings_path()),
            Ok("/api/admin/platform-settings")
        );
        assert_eq!(
            boundary.validate_platform_api_path(admin_platform_settings_reset_path()),
            Ok("/api/admin/platform-settings/reset")
        );
        assert_ne!(
            admin_platform_settings_path(),
            admin_platform_settings_reset_path()
        );
    }

    #[test]
    fn boundary_allows_admin_token_and_session_collection_routes() {
        let boundary = PortalServerBoundary::static_dry_run();

        assert_eq!(
            boundary.validate_platform_api_path(crate::api::admin_tokens_path()),
            Ok("/api/admin/tokens")
        );
        assert_eq!(
            boundary.validate_platform_api_path(crate::api::admin_sessions_path()),
            Ok("/api/admin/sessions")
        );
    }

    #[test]
    fn boundary_validates_admin_revoke_paths_and_rejects_traversal() {
        let boundary = PortalServerBoundary::static_dry_run();
        let id = "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b";

        for path in [
            admin_token_revoke_path(id).expect("token revoke path must build"),
            admin_session_revoke_path(id).expect("session revoke path must build"),
        ] {
            assert_eq!(
                boundary.validate_admin_resource_revoke_path(&path),
                Ok(path.as_str())
            );
        }

        for path in [
            "/api/admin/tokens",
            "/api/admin/sessions",
            "/api/admin/tokens/",
            "/api/admin/tokens/../platform-settings",
            "/api/admin/tokens/id/extra",
            "/api/admin/rbac-roles/id",
            "/api/admin/sessions/id?x=1",
        ] {
            assert_eq!(
                boundary.validate_admin_resource_revoke_path(path),
                Err(PortalBoundaryError::OutsidePortalAllowlist),
                "path {path} must be rejected"
            );
        }
    }

    #[test]
    fn boundary_validates_admin_agent_approve_path_and_rejects_traversal() {
        let boundary = PortalServerBoundary::static_dry_run();
        let id = "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b";

        let path = admin_agent_approve_path(id).expect("agent approve path must build");
        assert_eq!(
            path,
            "/api/admin/agents/3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b/approve"
        );
        assert_eq!(
            boundary.validate_admin_agent_approve_path(&path),
            Ok(path.as_str())
        );

        for path in [
            "/api/admin/agents",
            "/api/admin/agents/id",
            "/api/admin/agents/id/revoke",
            "/api/admin/agents/id/approve/extra",
            "/api/admin/agents/../platform-settings/approve",
            "/api/admin/agents/id?x=1/approve",
            "/api/admin/tokens/id/approve",
        ] {
            assert_eq!(
                boundary.validate_admin_agent_approve_path(path),
                Err(PortalBoundaryError::OutsidePortalAllowlist),
                "path {path} must be rejected"
            );
        }

        // An empty / traversal id never even builds a path.
        assert!(admin_agent_approve_path("").is_err());
        assert!(admin_agent_approve_path("..").is_err());
        assert!(admin_agent_approve_path("a/b").is_err());
    }

    #[test]
    fn boundary_validates_admin_agent_revoke_path_and_rejects_traversal() {
        let boundary = PortalServerBoundary::static_dry_run();
        let id = "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b";

        let path = admin_agent_revoke_path(id).expect("agent revoke path must build");
        assert_eq!(
            path,
            "/api/admin/agents/3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b/revoke"
        );
        assert_eq!(
            boundary.validate_admin_agent_revoke_path(&path),
            Ok(path.as_str())
        );

        for path in [
            "/api/admin/agents",
            "/api/admin/agents/id",
            "/api/admin/agents/id/approve",
            "/api/admin/agents/id/revoke/extra",
            "/api/admin/agents/../platform-settings/revoke",
            "/api/admin/agents/id?x=1/revoke",
            "/api/admin/tokens/id/revoke",
        ] {
            assert_eq!(
                boundary.validate_admin_agent_revoke_path(path),
                Err(PortalBoundaryError::OutsidePortalAllowlist),
                "path {path} must be rejected"
            );
        }

        assert!(admin_agent_revoke_path("").is_err());
        assert!(admin_agent_revoke_path("..").is_err());
        assert!(admin_agent_revoke_path("a/b").is_err());
    }

    #[test]
    fn boundary_validates_notifications_read_path_and_rejects_traversal() {
        let boundary = PortalServerBoundary::static_dry_run();
        let id = "pn-3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b";

        let path = notifications_read_path(id).expect("notification read path must build");
        assert_eq!(
            path,
            "/api/notifications/pn-3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b/read"
        );
        assert_eq!(
            boundary.validate_notifications_read_path(&path),
            Ok(path.as_str())
        );

        // A path outside the `/api/` prefix is rejected by the same-origin guard
        // before the allowlist is even consulted (a different error variant).
        assert!(
            boundary.validate_notifications_read_path("/foo").is_err(),
            "path /foo must be rejected"
        );

        // In-prefix paths that are not exactly `/api/notifications/{id}/read`
        // fall through to the allowlist rejection.
        for path in [
            "/api/notifications",
            "/api/notifications/read-all",
            "/api/notifications/id",
            "/api/notifications/id/unread",
            "/api/notifications/id/read/extra",
            "/api/notifications/../platform-settings/read",
            "/api/notifications/id?x=1/read",
        ] {
            assert_eq!(
                boundary.validate_notifications_read_path(path),
                Err(PortalBoundaryError::OutsidePortalAllowlist),
                "path {path} must be rejected"
            );
        }

        // An empty / traversal id never even builds a path.
        assert!(notifications_read_path("").is_err());
        assert!(notifications_read_path("..").is_err());
        assert!(notifications_read_path("a/b").is_err());
    }

    #[test]
    fn agent_approve_refuses_static_preview_persistence() {
        let result = reject_static_preview_agent_approve();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("preview-only"));
    }

    #[test]
    fn create_admin_token_refuses_static_preview_persistence() {
        let payload = CreateTokenPayload {
            name: "ci-deployer".to_string(),
            owner_principal: "svc:ci".to_string(),
            roles: vec!["VMwareOperator".to_string()],
            site_scope: None,
            environment_scope: None,
            expires_at: None,
        };
        let result = reject_static_preview_token_create(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("preview-only"));
    }

    #[test]
    fn admin_revoke_refuses_static_preview_persistence() {
        for action in ["token", "session"] {
            let result = reject_static_preview_revoke(action);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("preview-only"));
        }
    }

    #[test]
    fn unknown_role_detection_matches_app_role_catalog() {
        assert_eq!(
            first_unknown_role(&["VMwareOperator".to_string(), "Auditor".to_string()]),
            None
        );
        assert_eq!(
            first_unknown_role(&["VMwareOperator".to_string(), "NotARole".to_string()]),
            Some("NotARole".to_string())
        );
    }

    #[test]
    fn save_platform_settings_refuses_static_preview_persistence() {
        let result =
            reject_static_preview_platform_settings_save(platform_settings_summary_fallback());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("preview-only"));
    }

    #[test]
    fn reset_platform_settings_refuses_static_preview_persistence() {
        let result = reject_static_preview_platform_settings_reset();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("preview-only"));
    }

    #[test]
    fn create_request_refuses_static_preview_persistence() {
        let payload = CreateRequestPayload {
            request_type: "server-deployment".to_string(),
            name: "srv-app-01".to_string(),
            site: "DEBER".to_string(),
            environment: "production".to_string(),
            cpu: 4,
            memory: 16,
            justification: "Need capacity".to_string(),
            fields: std::collections::BTreeMap::new(),
        };
        let result = reject_static_preview_request_create(payload);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("preview-only"));
    }

    #[test]
    fn request_lifecycle_actions_refuse_static_preview_persistence() {
        for action in [
            "validation",
            "planning",
            "approval",
            "rejection",
            "cancellation",
            "locking",
            "execution",
            "verification",
            "protection",
            "publication",
            "retirement",
        ] {
            let result = reject_static_preview_request_action("REQ-123".to_string(), action);

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("preview-only"));
        }
    }

    #[test]
    fn reason_actions_reject_empty_or_whitespace_reason_before_upstream() {
        for action in ["reject", "cancel"] {
            assert!(require_reason(action, "").is_err());
            assert!(require_reason(action, "   ").is_err());
            assert!(require_reason(action, "\t\n").is_err());
            // A real reason is trimmed and accepted.
            assert_eq!(
                require_reason(action, "  insufficient capacity  ").unwrap(),
                "insufficient capacity"
            );
        }
    }

    #[test]
    fn static_preview_audit_trail_is_labeled_non_durable() {
        let trail = static_preview_audit_trail("REQ-123");
        assert!(!trail.is_empty());
        assert!(
            trail.iter().all(|row| !row.durable),
            "preview trail must be flagged non-durable"
        );
        assert_eq!(trail[0].action, "request.create");
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
            request_reject_path(request_id),
            request_cancel_path(request_id),
            request_lock_path(request_id),
            request_execute_path(request_id),
            request_verify_path(request_id),
            request_protect_path(request_id),
            request_publish_path(request_id),
            request_retire_path(request_id),
            request_audit_path(request_id),
            request_evidence_path(request_id),
        ] {
            let path = path.expect("request lifecycle path must build");
            assert_eq!(
                boundary.validate_request_lifecycle_api_path(&path),
                Ok(path.as_str())
            );
        }

        for path in [
            "/api/requests/detail",
            "/api/requests/reject",
            "/api/requests/cancel",
            "/api/requests/audit",
            "/api/requests/evidence",
            "/api/requests/REQ-123/validate/extra",
            "/api/requests/REQ-123/reject/extra",
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
        assert_eq!(snapshot.upstream_state, "static-dry-run");
        assert_eq!(
            snapshot.route_state_path,
            PORTAL_ROUTE_STATE_SERVER_FUNCTION_PATH
        );
        assert_eq!(snapshot.run_state_path, operation_runs_path());
        assert_eq!(snapshot.active_route, "/");
        assert_eq!(snapshot.active_workspace, "dashboard");
        assert_eq!(snapshot.activity_route, "/activity");
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
    fn route_snapshot_reports_the_matched_route_path() {
        let snapshot = PortalRouteStateSnapshot::static_dry_run()
            .expect("portal route state snapshot must build")
            .with_active_path("/requests/req-1234");

        assert_eq!(snapshot.active_route, "/requests/req-1234");
        assert_eq!(snapshot.active_workspace, "requests");

        let snapshot = PortalRouteStateSnapshot::live_provider()
            .expect("live route state snapshot must build")
            .with_active_path("/admin");

        assert_eq!(snapshot.active_route, "/admin");
        assert_eq!(snapshot.active_workspace, "admin");
        // Reporting the matched route never loosens the boundary flags.
        assert!(!snapshot.http_request_allowed);
        assert!(!snapshot.raw_route_state_allowed);
    }

    #[test]
    fn route_snapshot_falls_back_to_dashboard_for_unknown_or_unsafe_paths() {
        for path in [
            "/not-a-workspace",
            "//evil.example",
            "https://evil.example/requests",
            "/requests/../admin",
            "/requests/<script>",
            "javascript:alert(1)",
        ] {
            let snapshot = PortalRouteStateSnapshot::static_dry_run()
                .expect("portal route state snapshot must build")
                .with_active_path(path);

            assert_eq!(snapshot.active_route, "/", "path {path} must fall back");
            assert_eq!(snapshot.active_workspace, "dashboard");
        }
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
    fn cmdb_action_server_functions_register_portal_routes() {
        let registered: Vec<&str> = leptos::server_fn::axum::server_fn_paths()
            .map(|(path, _)| path)
            .collect();
        for endpoint in [
            "/portal/api/cmdb-import",
            "/portal/api/cmdb-export",
            "/portal/api/cmdb-reconcile",
        ] {
            assert!(
                registered.contains(&endpoint),
                "{endpoint} must register under the portal-owned route"
            );
        }
    }

    #[test]
    fn cmdb_action_paths_are_in_allowlist() {
        let boundary = PortalServerBoundary::static_dry_run();
        for path in [
            cmdb_import_path(),
            cmdb_export_path(),
            cmdb_reconcile_path(),
        ] {
            assert_eq!(boundary.validate_platform_api_path(path), Ok(path));
        }
    }

    #[test]
    fn count_cmdb_import_statuses_tallies_each_discriminant() {
        let records = serde_json::json!([
            { "import_status": "Accepted" },
            { "import_status": "Accepted" },
            { "import_status": "Rejected" },
            { "import_status": "PendingReview" },
            { "import_status": "Unknown" },
            {},
        ]);
        assert_eq!(count_cmdb_import_statuses(&records), (2, 1, 1));
    }

    #[test]
    fn cmdb_reconciled_matched_count_reads_summary_line() {
        let lines = vec![
            "DRY-RUN: 1 item(s) in platform inventory but not in CMDB: [\"x\"]".to_string(),
            "DRY-RUN: 3 item(s) reconciled (present in both)".to_string(),
            "DRY-RUN: Import summary - 2 accepted, 1 rejected, 0 pending review".to_string(),
        ];
        assert_eq!(cmdb_reconciled_matched_count(&lines), 3);
        assert_eq!(cmdb_reconciled_matched_count(&[]), 0);
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

    #[cfg(feature = "ssr")]
    #[test]
    fn admin_token_and_session_server_functions_register_portal_routes() {
        let registered: Vec<&str> = leptos::server_fn::axum::server_fn_paths()
            .map(|(path, _)| path)
            .collect();
        for endpoint in [
            "/portal/api/admin-tokens-list",
            "/portal/api/admin-tokens-create",
            "/portal/api/admin-tokens-revoke",
            "/portal/api/admin-sessions-list",
            "/portal/api/admin-sessions-revoke",
        ] {
            assert!(
                registered.contains(&endpoint),
                "{endpoint} must register under the portal-owned route"
            );
        }
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn integration_server_functions_register_portal_routes() {
        let registered: Vec<&str> = leptos::server_fn::axum::server_fn_paths()
            .map(|(path, _)| path)
            .collect();
        for endpoint in [
            "/portal/api/integrations-list",
            "/portal/api/integration-create",
            "/portal/api/integration-update",
            "/portal/api/integration-delete",
            "/portal/api/integration-test",
        ] {
            assert!(
                registered.contains(&endpoint),
                "{endpoint} must register under the portal-owned route"
            );
        }
    }

    #[test]
    fn integrations_path_is_in_allowlist() {
        let boundary = PortalServerBoundary::static_dry_run();
        assert_eq!(
            boundary.validate_platform_api_path(integrations_path()),
            Ok(integrations_path())
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn admin_token_fallbacks_carry_no_executable_credential() {
        // Static-preview rows must never imply an executable machine
        // credential: token_valid is false for every synthetic row.
        for token in admin_token_summary_fallbacks() {
            assert!(
                !token.token_valid,
                "static token fallback must not be executable"
            );
        }
    }
}
