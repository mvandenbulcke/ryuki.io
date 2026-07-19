// This module is the portal's server-fn boundary. Leptos `#[server]` macros expand
// into functions whose signatures a fn-level `#[allow]` cannot reach (the lint fires
// on the macro-generated code, so an attribute placed either before or after the
// `#[server]` attribute is ineffective). Suppress `too_many_arguments` module-wide:
// these server fns legitimately mirror multi-field query/form inputs (e.g. a paginated
// list endpoint's filter set), and the arg count is inherent to the HTTP contract.
#![allow(clippy::too_many_arguments)]

use crate::api::{
    activity_audit_feed_path, activity_operation_queue_path, admin_agents_path,
    admin_feature_flag_governance_path, admin_platform_settings_path,
    admin_platform_settings_reset_path, admin_rbac_roles_path, admin_sessions_path,
    admin_tokens_path, admin_worker_capability_path, approval_decision_readiness_path,
    approvals_pending_path, auth_entra_authorize_url_path, auth_local_login_path,
    auth_local_logout_path, auth_login_path, auth_logout_path, auth_session_path, auth_status_path,
    boundary_status_path, catalog_offerings_path, catalog_recommendations_path,
    catalog_request_form_path, cluster_capacity_admission_path, cmdb_export_path,
    cmdb_file_exchange_path, cmdb_import_path, cmdb_reconcile_path, cmdb_reconciliation_path,
    cmdb_relationship_graph_path, datacenter_check_cooling_path, datacenter_check_power_path,
    datacenter_check_rack_space_path, datacenter_check_switchports_path,
    datacenter_failing_checks_path, datacenter_full_readiness_path,
    datacenter_readiness_score_path, datacenter_site_report_path, datacenter_sites_path,
    dry_run_plan_path, emergency_change_path, evidence_compliance_dashboard_path,
    evidence_export_retention_path, evidence_summary_path, hardware_inventory_path,
    integrations_path, inventory_ownership_risk_path, inventory_resource_overview_path,
    notifications_path, notifications_read_all_path, notifications_unread_count_path,
    operation_runs_path, operations_platform_health_path, operations_runbook_launch_path,
    platform_health_path, platform_status_path, platform_summary_path, policy_outcomes_path,
    request_create_path, request_intake_form_preview_path, request_intake_path, request_list_path,
    request_preflight_path, same_origin_api_path, secret_references_path, servicenow_pending_path,
    shift_items_path, shift_queue_path, shift_summary_path, site_catalog_path, ApiPathError,
};
#[cfg(any(feature = "ssr", test))]
use crate::api::{
    admin_agent_approve_path, admin_agent_revoke_path, admin_session_revoke_path,
    admin_token_revoke_path, notifications_read_path, request_approve_path, request_audit_path,
    request_cancel_path, request_detail_path, request_evidence_path, request_execute_path,
    request_lock_path, request_plan_path, request_protect_path, request_publish_path,
    request_reject_path, request_retire_path, request_step_approve_live_apply_path,
    request_validate_path, request_verify_path,
};
// Used only by `#[server]` (ssr-only) bodies; gating them to `ssr` keeps the
// `test` build (no ssr feature) free of unused-import warnings.
#[cfg(feature = "ssr")]
use crate::api::{
    admin_agent_job_result_path, integration_id_path, integration_test_path,
    request_approve_live_apply_path, request_execution_job_path,
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
#[cfg(any(feature = "ssr", test))]
use crate::models::ALL_APP_ROLES;
#[cfg(feature = "ssr")]
use crate::models::{
    actions_for_stage, auth_session_fallback, cmdb_reconciliation_report_fallback,
    evidence_compliance_fallback, evidence_pack_directory_from_rows, evidence_retention_fallback,
    hardware_inventory_fallback, offering_catalog_fallback, platform_health_fallback,
    platform_status_fallback, platform_summary_context_fallback, rbac_role_catalog_fallback,
    servicenow_queue_fallback, shift_queue_fallback, ApiAdminAgentJobResult, ApiAdminSessionList,
    ApiAdminTokenList, ApiAuditTrail, ApiCmdbReconcileReport, ApiEvidenceComplianceContract,
    ApiEvidencePack, ApiEvidenceRetentionContract, ApiExecutionJob, ApiLoginSession,
    ApiOfferingCatalog, ApiPlatformSummary, ApiRbacRole, ApiRequestDetail, ApiRequestSummary,
    ApiServiceNowQueue, ApiShiftItemsPage, ApiShiftSummary, HardwareAssetSummary,
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
    CmdbFileExchangeSummary, CmdbReconciliationSnapshot, CmdbReconciliationSummary,
    CmdbRelationshipSummary, CreateIntegrationPayload, CreateRequestPayload, CreateTokenPayload,
    CreateTokenResult, DatacenterFailingChecksSummary, DatacenterFullReadiness,
    DatacenterReadinessScore, DatacenterSingleCheck, DatacenterSiteReport, DatacenterSitesCatalog,
    DryRunPlanSummary, EvidenceComplianceSnapshot, EvidencePackDirectorySnapshot,
    EvidencePackExport, EvidenceRetentionSnapshot, EvidenceSummary, ExecutionJob,
    HardwareInventorySnapshot, IntegrationSummary, IntegrationTestResult, InventoryResourceSummary,
    NotificationSummary, OfferingCatalogSnapshot, OperationRunSummary, PlatformHealth,
    PlatformSettingsSummary, PlatformStatus, PlatformSummaryContext, PolicyGuardrailSummary,
    PolicyOutcome, RbacRoleCatalogSnapshot, RequestDetail, RequestIntakeForm, RequestIntakeSummary,
    RequestSummary, ReviewedLivePlanSelection, RevokeResult, SecretReferenceSummary,
    ServiceNowQueueSnapshot, ShiftQueueSnapshot, StageActionResponse, UpdateIntegrationPayload,
};
#[cfg(feature = "ssr")]
use crate::models::{admin_session_summary_fallbacks, admin_token_summary_fallbacks};
#[cfg(feature = "ssr")]
use crate::models::{request_detail_fallback, request_summary_fallbacks};
#[cfg(feature = "ssr")]
use crate::upstream::{
    clear_portal_session_cookie, cookie_max_age_from_expires_at,
    entra_login_binding_cookie_headers_are_unambiguous, session_id_from_request,
    set_entra_login_binding_cookie, set_portal_session_cookie, UpstreamClient, UpstreamResponse,
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
    hardware_inventory_path,
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
    shift_summary_path,
    shift_items_path,
    emergency_change_path,
    cmdb_file_exchange_path,
    cmdb_reconciliation_path,
    cmdb_relationship_graph_path,
    cmdb_import_path,
    cmdb_export_path,
    cmdb_reconcile_path,
    servicenow_pending_path,
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
    auth_entra_authorize_url_path,
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

    use_context::<UpstreamClient>().unwrap_or_else(|| {
        let public_origin = crate::security::PortalPublicOrigin::from_env()
            .expect("portal public origin must be validated during startup");
        UpstreamClient::from_env(&public_origin)
            .expect("portal upstream configuration must be validated during startup")
    })
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

#[cfg(any(feature = "ssr", test))]
enum LogoutUpstreamOutcome {
    Confirmed,
    Rejected(String),
    Unreachable,
}

/// Retires the portal-held credential before interpreting the authoritative
/// revocation result. Local browser state is therefore cleared on every
/// completed attempt, while only a confirmed upstream result may be projected
/// as successful logout.
#[cfg(any(feature = "ssr", test))]
fn finish_logout(
    outcome: LogoutUpstreamOutcome,
    clear_portal_credential: impl FnOnce(),
) -> Result<(), ServerFnError> {
    clear_portal_credential();
    match outcome {
        LogoutUpstreamOutcome::Confirmed => Ok(()),
        LogoutUpstreamOutcome::Rejected(message) => Err(ServerFnError::new(message)),
        LogoutUpstreamOutcome::Unreachable => Err(ServerFnError::new(
            "Browser credentials were cleared, but server-side session revocation could not be confirmed",
        )),
    }
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
            | "steps"
    ) {
        return false;
    }
    let second = segments.next();
    let third = segments.next();
    // Per-step live-apply approval (#42 slice B1b):
    // /api/requests/{id}/steps/{step_key}/approve-live-apply. The step key is
    // a dynamic segment validated with the same single-segment rules as the
    // request id; the suffix must be exactly `approve-live-apply`.
    if second == Some("steps") {
        let Some(step_key) = third else {
            return false;
        };
        if !is_safe_dynamic_path_segment(step_key) {
            return false;
        }
        return matches!(
            (segments.next(), segments.next()),
            (Some("approve-live-apply"), None)
        );
    }
    matches!(
        (second, third),
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

/// Single-segment safety rules shared by the dynamic (non-static) path
/// segments the lifecycle allowlist accepts — currently the step key of the
/// per-step live-apply approval path. Mirrors the request-id checks above:
/// no traversal, separators, query/fragment markers, or non-identifier bytes.
fn is_safe_dynamic_path_segment(segment: &str) -> bool {
    !(segment.is_empty()
        || segment == "."
        || segment == ".."
        || segment.contains("..")
        || segment.contains('\\')
        || segment.contains('?')
        || segment.contains('#')
        || segment.contains("://")
        || segment.starts_with("//")
        || !segment
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || matches!(char, '-' | '_')))
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

/// Validates `/api/admin/agents/jobs/{job_id}/result`. This read is used only
/// to hydrate the server-derived, digest-bound LivePlan projection; the portal
/// never requests raw evidence or accepts an arbitrary admin path.
fn is_allowed_admin_agent_job_result_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/admin/agents/jobs/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let Some(job_id) = segments.next() else {
        return false;
    };
    is_safe_dynamic_path_segment(job_id)
        && matches!((segments.next(), segments.next()), (Some("result"), None))
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

    /// Validates the admin-only safe job-result projection read.
    pub fn validate_admin_agent_job_result_path<'a>(
        &self,
        path: &'a str,
    ) -> Result<&'a str, PortalBoundaryError> {
        let guarded = same_origin_api_path(path)?;
        if is_allowed_admin_agent_job_result_path(guarded) {
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
        // The freshness/scope labels inherited from static_dry_run() are FIXTURES
        // (e.g. "Monitoring stale", "Site: Global"). Rendering them in live mode
        // presents fabricated operational state as real — including a false
        // staleness warning. Real freshness/scope is not yet wired to the API, so
        // show explicit "not yet wired" placeholders instead of fake data.
        snapshot.inventory_freshness_label = "Inventory freshness: not yet wired".to_string();
        snapshot.backup_freshness_label = "Backup freshness: not yet wired".to_string();
        snapshot.monitoring_freshness_label = "Monitoring freshness: not yet wired".to_string();
        snapshot.site_scope_label = "Site: not yet wired".to_string();
        snapshot.environment_scope_label = "Env: not yet wired".to_string();
        snapshot.role_scope_label = "Role: not yet wired".to_string();
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
    pub provider_model: String,
    pub management_interface: String,
    pub fallback_policy: String,
    pub admitted_provider_classes: Vec<String>,
    pub capability_interfaces: Vec<String>,
    pub secret_reference_kinds: Vec<String>,
    pub configured_for_production: bool,
    pub secret_references: Vec<SecretReferenceSummary>,
    pub readiness_state: String,
    pub live_provider_actions_allowed: bool,
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
            provider_model: catalog_status.provider_model,
            management_interface: catalog_status.management_interface,
            fallback_policy: catalog_status.fallback_policy,
            admitted_provider_classes: catalog_status.admitted_provider_classes,
            capability_interfaces: catalog_status.capability_interfaces,
            secret_reference_kinds: catalog_status.secret_reference_kinds,
            configured_for_production: catalog_status.configured_for_production,
            secret_references,
            readiness_state,
            live_provider_actions_allowed: false,
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
        clear_portal_session_cookie(upstream.cookie_secure());
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
        clear_portal_session_cookie(upstream.cookie_secure());
        Ok(None)
    }
}

/// Reads the role/tier catalog through the allowlisted
/// `GET /api/admin/rbac-roles` read endpoint. Live mode fetches and parses
/// the API's role list (name, description, permission tiers); static mode
/// serves a labeled preview without fabricated permission grants. A live API
/// that is unreachable surfaces an error so the Admin view renders an
/// explicit degraded state rather than a stale role catalog.
#[server(prefix = "/portal/api", endpoint = "admin-rbac-roles")]
pub async fn get_admin_rbac_roles() -> Result<RbacRoleCatalogSnapshot, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(admin_rbac_roles_path())
        .map_err(|_| ServerFnError::new("admin rbac roles API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(rbac_role_catalog_fallback());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let roles: Vec<ApiRbacRole> = response
                .json()
                .map_err(|_| ServerFnError::new("admin rbac roles response was malformed"))?;
            Ok(RbacRoleCatalogSnapshot::from_live(roles))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "admin rbac roles fetch failed",
        ))),
        // Live mode never substitutes the preview catalog for an unreachable
        // API; the Admin view renders an explicit degraded state instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
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
            )));
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
            // The paginated API (#14) envelopes the rows under `tokens`; the
            // untagged decode keeps a bare-array shape working too.
            let list: ApiAdminTokenList = response
                .json()
                .map_err(|_| ServerFnError::new("admin tokens response was malformed"))?;
            let mut tokens = list.into_rows();
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
            // The paginated API (#14) envelopes the rows under `sessions`;
            // the untagged decode keeps a bare-array shape working too.
            let list: ApiAdminSessionList = response
                .json()
                .map_err(|_| ServerFnError::new("admin sessions response was malformed"))?;
            Ok(list.into_rows())
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
/// session bearer is stored in the mode-selected portal-origin cookie
/// (`__Host-ryuki_session` on HTTPS, unprefixed only for explicit loopback
/// HTTP) and never reaches WASM; the browser only receives the [`AuthSession`]
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
        &login.session_token,
        cookie_max_age_from_expires_at(&login.expires_at),
        upstream.cookie_secure(),
    );
    Ok(AuthSession::from(login))
}

/// Payload of the upstream `GET /api/auth/entra/authorize-url`. `binding` is
/// consumed server-side ONLY — it becomes the mode-selected HttpOnly binding
/// cookie on the portal response and is never part of the value the browser
/// script receives, so page JavaScript can never read it.
#[cfg(feature = "ssr")]
#[derive(Deserialize)]
struct EntraAuthorizeUrlPayload {
    authorize_url: String,
    binding: String,
}

/// Begins the Entra ID browser sign-in (auth-code + PKCE): fetches the tenant
/// authorize URL from the upstream API (which persists the single-use
/// state/nonce/verifier server-side), re-issues the per-browser CSRF-binding
/// cookie on the portal response, and returns ONLY the authorize URL for the
/// client to navigate to. The IdP redirects back to the API callback directly
/// (same-origin deployment), which must mint the same mode-selected cookie the
/// portal session gate consumes. Production callbacks therefore use
/// `__Host-ryuki_session`; explicit loopback HTTP uses `ryuki_session`.
#[server(prefix = "/portal/api", endpoint = "auth-entra-authorize-url")]
pub async fn get_entra_authorize_url() -> Result<String, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(auth_entra_authorize_url_path())
        .map_err(|_| ServerFnError::new("entra authorize URL API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        // Static demo builds have no IdP to hand the browser to.
        return Err(ServerFnError::new(
            "Entra ID sign-in requires the live platform API",
        ));
    }
    let headers = leptos_axum::extract::<axum::http::HeaderMap>()
        .await
        .map_err(|_| ServerFnError::new("Entra login cookie evidence was unavailable"))?;
    let cookie_headers = headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .map(|value| value.to_str())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ServerFnError::new("Entra login cookie evidence was malformed"))?;
    if !entra_login_binding_cookie_headers_are_unambiguous(cookie_headers, upstream.cookie_secure())
    {
        return Err(ServerFnError::new(
            "Ambiguous Entra login cookie evidence was rejected",
        ));
    }
    let response = upstream.get(path, None).await.map_err(|_| {
        ServerFnError::new("API unreachable; Entra ID sign-in is unavailable right now")
    })?;
    if !response.is_success() {
        return Err(ServerFnError::new(api_error_text(
            &response,
            "Entra ID sign-in is unavailable",
        )));
    }
    let payload: EntraAuthorizeUrlPayload = response
        .json()
        .map_err(|_| ServerFnError::new("Entra authorize URL response was malformed"))?;
    // Defense-in-depth: only ever hand the browser an absolute http(s) URL.
    if !(payload.authorize_url.starts_with("https://")
        || payload.authorize_url.starts_with("http://"))
    {
        return Err(ServerFnError::new(
            "Entra authorize URL response was malformed",
        ));
    }
    set_entra_login_binding_cookie(&payload.binding, upstream.cookie_secure());
    Ok(payload.authorize_url)
}

/// Signs out through the authoritative API and clears the portal cookie for
/// every outcome. An upstream rejection or transport/server failure is surfaced
/// to the caller; the portal never claims that durable revocation succeeded
/// merely because its own cookie was retired.
#[server(prefix = "/portal/api", endpoint = "auth-logout")]
pub async fn perform_logout() -> Result<(), ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(auth_local_logout_path())
        .map_err(|_| ServerFnError::new("auth logout API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if upstream.live() {
        let session_id = session_id_from_request().await;
        let outcome = match upstream.post(path, None, session_id.as_deref()).await {
            Ok(response) if response.is_success() => LogoutUpstreamOutcome::Confirmed,
            Ok(response) => LogoutUpstreamOutcome::Rejected(api_error_text(
                &response,
                "Sign-out was rejected by the API",
            )),
            Err(_) => LogoutUpstreamOutcome::Unreachable,
        };
        return finish_logout(outcome, || {
            clear_portal_session_cookie(upstream.cookie_secure())
        });
    }
    clear_portal_session_cookie(upstream.cookie_secure());
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
    let environment = normalize(&query.environment);
    let request_type = normalize(&query.request_type);
    // `created_by` is forwarded verbatim to the upstream via the query string;
    // the local fallback row does not carry that field, so the normalized value
    // is intentionally unused here.
    let _created_by = normalize(&query.created_by);
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
        .filter(|row| match &environment {
            Some(e) => row.environment.to_ascii_lowercase() == *e,
            None => true,
        })
        .filter(|row| match &request_type {
            Some(t) => row.request_type.to_ascii_lowercase() == *t,
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

/// One page of the faceted request list (#15). Carries the page rows plus the
/// pagination cursor so the view can render Prev/Next without a separate total.
///
/// `has_next` is derived by over-fetching one row beyond `page_size`: when the
/// upstream returns more than a page, there is a next page. `total` carries the
/// exact filtered count when known (the upstream `X-Total-Count` header in live
/// mode, or the in-memory set length in static mode) so the view can render
/// "Showing X-Y of N"; it is DISPLAY-ONLY and `has_next` never depends on it, and
/// it falls back to a bare range when absent.
///
/// Serde-derived because `#[server]` return types cross the wire, matching the
/// snapshot structs in this file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestListPage {
    pub rows: Vec<RequestSummary>,
    pub offset: u32,
    pub page_size: u32,
    pub has_next: bool,
    /// Exact filtered total (from the upstream `X-Total-Count` header in live
    /// mode, or the full in-memory set length in static/degraded mode), when
    /// known. DISPLAY-ONLY: `has_next` is never recomputed from it. `None`
    /// falls back to a bare page range in the view.
    pub total: Option<u64>,
}

/// Build a page from an OVER-FETCHED row set (the upstream live branch asks for
/// `page_size + 1` rows): the presence of the extra row signals a next page
/// without an exact total. Truncates to `page_size`. Pure — unit-tested below.
// Only reached from the ssr-gated `get_request_list` server impl; the client
// (wasm) build compiles the fn but never calls it.
#[cfg_attr(not(feature = "ssr"), allow(dead_code))]
fn finalize_overfetched_page(
    mut rows: Vec<RequestSummary>,
    offset: u32,
    page_size: u32,
    total: Option<u64>,
) -> RequestListPage {
    let has_next = rows.len() as u32 > page_size;
    if has_next {
        rows.truncate(page_size as usize);
    }
    RequestListPage {
        rows,
        offset,
        page_size,
        has_next,
        total,
    }
}

/// Build a page from the FULL in-memory filtered set (static/degraded mode):
/// slice `[offset, offset + page_size)` and derive `has_next` from the true
/// total. Pure — unit-tested below.
#[cfg_attr(not(feature = "ssr"), allow(dead_code))]
fn paginate_in_memory(full: Vec<RequestSummary>, offset: u32, page_size: u32) -> RequestListPage {
    let total = full.len() as u32;
    let has_next = total > offset.saturating_add(page_size);
    let rows: Vec<RequestSummary> = full
        .into_iter()
        .skip(offset as usize)
        .take(page_size as usize)
        .collect();
    RequestListPage {
        rows,
        offset,
        page_size,
        has_next,
        // The full filtered set is held in memory, so the total is known exactly.
        total: Some(total as u64),
    }
}

/// Faceted request-list read (#15). Optional `status`/`site`/`environment`/
/// `request_type`/`created_by`/`q` filters and `sort`/`direction` ordering are
/// forwarded to the upstream `GET /api/requests` endpoint (API contract
/// fa1df10). All-`None` filter arguments with `offset = None` reproduce the
/// unfiltered first page, so existing call sites are unaffected.
///
/// Pagination is offset/limit based: the page size is fixed at `PAGE_SIZE` and
/// the upstream is asked for `PAGE_SIZE + 1` rows so the extra row signals a
/// next page without needing a total count.
///
/// The same-origin allowlist validates the *base* path; the query suffix is
/// appended only after validation and carries solely allowlist-validated keys
/// and percent-encoded values (see `RequestListQuery::to_query_string`), so no
/// caller input ever reaches the upstream unescaped.
#[server(prefix = "/portal/api", endpoint = "request-list-data")]
pub async fn get_request_list(
    status: Option<String>,
    site: Option<String>,
    environment: Option<String>,
    request_type: Option<String>,
    created_by: Option<String>,
    q: Option<String>,
    sort: Option<String>,
    direction: Option<String>,
    offset: Option<u32>,
) -> Result<RequestListPage, ServerFnError> {
    use crate::api::{request_list_path_with_query, RequestListQuery};

    // Fixed page size for the request list. Over-fetched by one (see `limit`)
    // so `has_next` can be derived without an exact total.
    const PAGE_SIZE: u32 = 25;
    // Ceiling on the caller-supplied offset (it arrives verbatim from the URL).
    // Well above any realistic list size, but bounded so a hostile deep link
    // (?offset=4294967295) cannot translate into an unbounded upstream OFFSET
    // (a cheap DB resource-amplification vector) or overflow the range label.
    const MAX_OFFSET: u32 = 1_000_000;

    let offset = offset.unwrap_or(0).min(MAX_OFFSET);
    let boundary = PortalServerBoundary::static_dry_run();
    // Validate the base path against the same-origin allowlist BEFORE appending
    // the facet query string. The allowlist matches the path without a query.
    boundary
        .validate_platform_api_path(request_list_path())
        .map_err(|_| ServerFnError::new("request list API path failed same-origin guard"))?;
    let query = RequestListQuery {
        status,
        site,
        environment,
        request_type,
        created_by,
        q,
        sort,
        direction,
        // Over-fetch by one row so a full page that has a successor is
        // distinguishable from the last page without an exact total.
        limit: Some(PAGE_SIZE + 1),
        offset: Some(offset),
    };
    let path = request_list_path_with_query(&query);
    let upstream = upstream_context();
    if !upstream.live() {
        // Static/degraded mode filters the synthetic fallback rows locally so
        // the facet UI stays interactive even without an upstream. It holds the
        // full filtered set in memory, so it can compute an honest page slice.
        let rows = request_summary_fallbacks();
        let full = filter_request_summaries(rows, &query);
        return Ok(paginate_in_memory(full, offset, PAGE_SIZE));
    }
    let session_id = session_id_from_request().await;
    match upstream.get(&path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let list: Vec<ApiRequestSummary> = response
                .json()
                .map_err(|_| ServerFnError::new("request list response was malformed"))?;
            let rows: Vec<RequestSummary> = list.into_iter().map(RequestSummary::from).collect();
            // The over-fetched extra row (if present) means there is a next page;
            // finalize_overfetched_page derives has_next and truncates to PAGE_SIZE.
            // The X-Total-Count header carries the real filtered total (pre-paging)
            // for display only — has_next stays over-fetch derived.
            Ok(finalize_overfetched_page(
                rows,
                offset,
                PAGE_SIZE,
                response.total_count,
            ))
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
    let job_id = api_job.agent_job_id.clone();
    let mut job = ExecutionJob::from(api_job);

    // The request-scoped read intentionally carries no plan body. For a
    // completed successful LivePlan, ask the admin-only result endpoint for its
    // safe server-derived projection. Any 403/404/malformed response leaves the
    // review absent, which also keeps live-apply approval hidden fail-closed.
    if job.is_successful_live_plan() {
        if let Ok(result_path) = admin_agent_job_result_path(&job_id) {
            if boundary
                .validate_admin_agent_job_result_path(&result_path)
                .is_ok()
            {
                if let Ok(result_response) = upstream.get(&result_path, session_id.as_deref()).await
                {
                    if result_response.is_success() {
                        if let Ok(result) = result_response.json::<ApiAdminAgentJobResult>() {
                            let reviewed = result.into_reviewed_live_plan(&job_id);
                            job = job.with_reviewed_live_plan(reviewed);
                        }
                    }
                }
            }
        }
    }

    Ok(Some(job))
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
            steps: Vec::new(),
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

/// Build the closed mutation body from the exact immutable plan snapshot that
/// accompanied the safe review. `approved_plan_digest` is the signed raw-plan
/// commitment, never the safe evidence digest. No request spec, placement,
/// provider value, or caller-selected platform is accepted through this boundary.
#[cfg(any(feature = "ssr", test))]
fn reviewed_plan_approval_body(
    selection: &ReviewedLivePlanSelection,
) -> Result<serde_json::Value, ServerFnError> {
    if !selection.is_canonical() {
        return Err(ServerFnError::new(
            "Live apply requires an exact canonical reviewed-plan selection",
        ));
    }
    Ok(serde_json::json!({
        "approved_plan_job_id": selection.approved_plan_job_id.as_str(),
        "approved_plan_attempt_id": selection.approved_plan_attempt_id.as_str(),
        "approved_plan_digest": selection.approved_plan_digest.as_str(),
    }))
}

/// Live POST for the mutation-authorizing approval endpoint. This deliberately
/// does not reuse the bodyless lifecycle helper: the exact reviewed selection
/// must cross the final server boundary unchanged.
#[cfg(feature = "ssr")]
async fn dispatch_reviewed_live_plan_action_live(
    request_id: String,
    selection: &ReviewedLivePlanSelection,
    path: &str,
) -> Result<StageActionResponse, ServerFnError> {
    let upstream = upstream_context();
    let session_id = session_id_from_request().await;
    let body = reviewed_plan_approval_body(selection)?;
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
            message: "live apply completed".to_string(),
        })
    } else {
        Ok(StageActionResponse {
            request_id,
            success: false,
            new_stage: String::new(),
            message: api_error_text(&response, "live apply was rejected by the API"),
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
    reviewed_plan: ReviewedLivePlanSelection,
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
    dispatch_reviewed_live_plan_action_live(request_id, &reviewed_plan, &path).await
}

/// Per-step mutation remains fail-closed until the portal can fetch and render
/// the exact safe review for each independently parked step. Keeping this
/// server endpoint as an explicit refusal prevents an older hydrated client or
/// a hand-crafted portal call from reaching the API's disabled route.
#[server(prefix = "/portal/api", endpoint = "request-step-approve-live-apply")]
pub async fn approve_step_live_apply(
    request_id: String,
    step_key: String,
    reviewed_plan: ReviewedLivePlanSelection,
) -> Result<StageActionResponse, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = request_step_approve_live_apply_path(&request_id, &step_key).map_err(|_| {
        ServerFnError::new("step approve-live-apply API path failed same-origin guard")
    })?;
    boundary
        .validate_request_lifecycle_api_path(&path)
        .map_err(|_| {
            ServerFnError::new("step approve-live-apply API path failed same-origin guard")
        })?;
    let _ = reviewed_plan_approval_body(&reviewed_plan)?;
    Err(ServerFnError::new(
        "Per-step live approval is disabled until an exact digest-bound step review is available",
    ))
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

// ── Catalog and inventory live-read server functions ───────────────────────

/// Reads the offering catalog through the allowlisted
/// `GET /api/catalog/offerings-contract` read endpoint. Live mode fetches and
/// parses the API's catalog envelope (source marker, categories, offerings);
/// static mode serves a labeled preview. A live API that is unreachable
/// surfaces an error so the Catalog view renders an explicit degraded state
/// rather than fabricated offerings.
#[server(prefix = "/portal/api", endpoint = "catalog-offerings-data")]
pub async fn get_catalog_offerings() -> Result<OfferingCatalogSnapshot, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(catalog_offerings_path())
        .map_err(|_| ServerFnError::new("catalog offerings API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(offering_catalog_fallback());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let catalog: ApiOfferingCatalog = response
                .json()
                .map_err(|_| ServerFnError::new("catalog offerings response was malformed"))?;
            Ok(OfferingCatalogSnapshot::from_live(catalog))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "catalog offerings fetch failed",
        ))),
        // Live mode never substitutes preview offerings for an unreachable
        // API; the Catalog view renders an explicit degraded state instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Reads the hardware asset list through the allowlisted
/// `GET /api/datacenter/hardware/inventory` read endpoint (DB-backed, paged;
/// the filtered total rides in `X-Total-Count`). Live mode fetches one
/// bounded page; static mode serves a labeled preview. A live API that is
/// unreachable surfaces an error so the Inventory view renders an explicit
/// degraded state rather than stale or fabricated assets.
#[server(prefix = "/portal/api", endpoint = "hardware-inventory-data")]
pub async fn get_hardware_inventory() -> Result<HardwareInventorySnapshot, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(hardware_inventory_path())
        .map_err(|_| ServerFnError::new("hardware inventory API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(hardware_inventory_fallback());
    }
    // One bounded page keeps the read-only table useful without unbounded
    // payloads (the API clamps limit to 1000); the filtered total still
    // arrives via the X-Total-Count header for the "N of M" display.
    let fetch_path = format!("{path}?limit=100");
    let session_id = session_id_from_request().await;
    match upstream.get(&fetch_path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let assets: Vec<HardwareAssetSummary> = response
                .json()
                .map_err(|_| ServerFnError::new("hardware inventory response was malformed"))?;
            let total = response.total_count.unwrap_or(assets.len() as u64);
            Ok(HardwareInventorySnapshot {
                live: true,
                total,
                assets,
            })
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "hardware inventory fetch failed",
        ))),
        // Live mode never substitutes preview assets for an unreachable API;
        // the Inventory view renders an explicit degraded state instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

// ── CMDB and shift-queue live-read server functions ────────────────────────

/// Reads the staged ServiceNow publish queue through the allowlisted
/// `GET /api/cmdb/servicenow/pending` read endpoint. These are dry-run
/// records staged locally — nothing reaches ServiceNow while the live
/// integration stays disabled, and the CMDB view labels them that way. Live
/// mode fetches and parses the queue envelope; static mode serves a labeled
/// preview. A live API that is unreachable surfaces an error so the view
/// renders an explicit degraded state rather than fabricated queue rows.
#[server(prefix = "/portal/api", endpoint = "servicenow-publish-queue")]
pub async fn get_servicenow_publish_queue() -> Result<ServiceNowQueueSnapshot, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(servicenow_pending_path())
        .map_err(|_| ServerFnError::new("ServiceNow queue API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(servicenow_queue_fallback());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let queue: ApiServiceNowQueue = response
                .json()
                .map_err(|_| ServerFnError::new("ServiceNow queue response was malformed"))?;
            Ok(ServiceNowQueueSnapshot::from_live(queue))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "ServiceNow queue fetch failed",
        ))),
        // Live mode never substitutes preview rows for an unreachable API;
        // the CMDB view renders an explicit degraded state instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Runs the dry-run CMDB reconciliation through the allowlisted
/// `POST /api/cmdb/reconcile` endpoint and reads its report. The API computes
/// the run on demand from the platform inventory and the CMDB import — it is
/// a pure read despite the POST verb (the response is always marked
/// `source: "dry-run"` and no CMDB record is mutated), so the CMDB view may
/// fetch it on load. Live mode parses the presence summary and the
/// attribute-drift entries; static mode serves a labeled preview. A live API
/// that is unreachable surfaces an error so the view renders an explicit
/// degraded state rather than a fabricated report.
#[server(prefix = "/portal/api", endpoint = "cmdb-reconciliation-report")]
pub async fn get_cmdb_reconciliation_report() -> Result<CmdbReconciliationSnapshot, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(cmdb_reconcile_path())
        .map_err(|_| ServerFnError::new("CMDB reconcile API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(cmdb_reconciliation_report_fallback());
    }
    let session_id = session_id_from_request().await;
    match upstream.post(path, None, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let report: ApiCmdbReconcileReport = response
                .json()
                .map_err(|_| ServerFnError::new("CMDB reconcile response was malformed"))?;
            Ok(CmdbReconciliationSnapshot::from_live(report))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "CMDB reconciliation fetch failed",
        ))),
        // Live mode never substitutes a preview report for an unreachable
        // API; the CMDB view renders an explicit degraded state instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Reads the shift queue through the allowlisted `GET /api/ops/shift/summary`
/// and `GET /api/ops/shift/items` read endpoints: real aggregate totals over
/// ALL open items plus one bounded page of open items for the triage table.
/// Operator-tier data — the API gates every shift read on the `execute`
/// permission, and the Operations view mirrors that gate. Live mode requires
/// BOTH reads to succeed (they cover the same queue; a half-loaded panel
/// would misstate the totals); static mode serves a labeled preview. A live
/// API that is unreachable surfaces an error so the view renders an explicit
/// degraded state rather than fabricated operator data.
#[server(prefix = "/portal/api", endpoint = "shift-queue-overview")]
pub async fn get_shift_queue_overview() -> Result<ShiftQueueSnapshot, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let summary_path = boundary
        .validate_platform_api_path(shift_summary_path())
        .map_err(|_| ServerFnError::new("shift summary API path failed same-origin guard"))?;
    let items_path = boundary
        .validate_platform_api_path(shift_items_path())
        .map_err(|_| ServerFnError::new("shift items API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(shift_queue_fallback());
    }
    let session_id = session_id_from_request().await;
    let summary_response = match upstream.get(summary_path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => response,
        Ok(response) => {
            return Err(ServerFnError::new(api_error_text(
                &response,
                "shift summary fetch failed",
            )));
        }
        // Live mode never substitutes preview items for an unreachable API;
        // the Operations view renders an explicit degraded state instead.
        Err(_) => return Err(ServerFnError::new("API unreachable")),
    };
    let summary: ApiShiftSummary = summary_response
        .json()
        .map_err(|_| ServerFnError::new("shift summary response was malformed"))?;
    // Open items only (`resolved=false`) — the same population the summary
    // counts. One bounded page keeps the triage table useful without
    // unbounded payloads (the API clamps limit to 200); `has_more` marks a
    // truncated page.
    let items_fetch_path = format!("{items_path}?resolved=false&limit=50");
    let page_response = match upstream.get(&items_fetch_path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => response,
        Ok(response) => {
            return Err(ServerFnError::new(api_error_text(
                &response,
                "shift items fetch failed",
            )));
        }
        Err(_) => return Err(ServerFnError::new("API unreachable")),
    };
    let page: ApiShiftItemsPage = page_response
        .json()
        .map_err(|_| ServerFnError::new("shift items response was malformed"))?;
    Ok(ShiftQueueSnapshot::from_live(summary, page))
}

// ── Evidence hub live-read server functions ────────────────────────────────

/// Builds the Evidence tab's pack directory from the allowlisted durable
/// audit feed (`GET /api/activity/audit`, newest first): one row per request
/// with its latest recorded action, deep-linking to the sealed per-request
/// evidence pack at `/requests/{id}`. Live mode fetches one bounded feed page
/// (the API caps `limit` at 200); static mode derives the directory from the
/// labeled preview feed. A live API that is unreachable surfaces an error so
/// the Evidence view renders an explicit degraded state rather than a stale
/// or fabricated directory.
#[server(prefix = "/portal/api", endpoint = "evidence-pack-directory")]
pub async fn get_evidence_pack_directory() -> Result<EvidencePackDirectorySnapshot, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(activity_audit_feed_path())
        .map_err(|_| ServerFnError::new("activity audit feed API path failed same-origin guard"))?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(evidence_pack_directory_from_rows(
            false,
            static_preview_activity_feed(),
        ));
    }
    // The widest page the API serves (it clamps limit to 200) so the
    // directory covers as much of the recent governance window as one read
    // allows; the panel states the scanned-action window honestly.
    let fetch_path = format!("{path}?limit=200");
    let session_id = session_id_from_request().await;
    match upstream.get(&fetch_path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let feed: ApiAuditTrail = response
                .json()
                .map_err(|_| ServerFnError::new("activity audit feed response was malformed"))?;
            Ok(evidence_pack_directory_from_rows(true, feed.into_rows()))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "evidence pack directory fetch failed",
        ))),
        // Live mode never substitutes the preview directory for an
        // unreachable API; the Evidence view renders an explicit degraded
        // state instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Reads the export/retention governance contract through the allowlisted
/// `GET /api/evidence/export-retention-contract` read endpoint. Live mode
/// fetches and parses the API's contract envelope (source marker, redaction
/// posture, state vocabularies); static mode serves a labeled preview. A live
/// API that is unreachable surfaces an error so the Evidence view renders an
/// explicit degraded state rather than a stale contract.
#[server(prefix = "/portal/api", endpoint = "evidence-retention-contract-data")]
pub async fn get_evidence_retention_contract() -> Result<EvidenceRetentionSnapshot, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(evidence_export_retention_path())
        .map_err(|_| {
            ServerFnError::new("evidence retention contract API path failed same-origin guard")
        })?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(evidence_retention_fallback());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let contract: ApiEvidenceRetentionContract = response.json().map_err(|_| {
                ServerFnError::new("evidence retention contract response was malformed")
            })?;
            Ok(EvidenceRetentionSnapshot::from_live(contract))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "evidence retention contract fetch failed",
        ))),
        // Live mode never substitutes the preview contract for an unreachable
        // API; the Evidence view renders an explicit degraded state instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

/// Reads the compliance-dashboard governance contract through the allowlisted
/// `GET /api/evidence/compliance-dashboard-contract` read endpoint. Live mode
/// fetches and parses the API's contract envelope (source marker, domains,
/// status bands, trend windows); static mode serves a labeled preview. A live
/// API that is unreachable surfaces an error so the Evidence view renders an
/// explicit degraded state rather than a stale contract.
#[server(prefix = "/portal/api", endpoint = "evidence-compliance-contract-data")]
pub async fn get_evidence_compliance_contract() -> Result<EvidenceComplianceSnapshot, ServerFnError>
{
    let boundary = PortalServerBoundary::static_dry_run();
    let path = boundary
        .validate_platform_api_path(evidence_compliance_dashboard_path())
        .map_err(|_| {
            ServerFnError::new("evidence compliance contract API path failed same-origin guard")
        })?;
    let upstream = upstream_context();
    if !upstream.live() {
        return Ok(evidence_compliance_fallback());
    }
    let session_id = session_id_from_request().await;
    match upstream.get(path, session_id.as_deref()).await {
        Ok(response) if response.is_success() => {
            let contract: ApiEvidenceComplianceContract = response.json().map_err(|_| {
                ServerFnError::new("evidence compliance contract response was malformed")
            })?;
            Ok(EvidenceComplianceSnapshot::from_live(contract))
        }
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "evidence compliance contract fetch failed",
        ))),
        // Live mode never substitutes the preview contract for an unreachable
        // API; the Evidence view renders an explicit degraded state instead.
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

// ── Integration server functions ──────────────────────────────────────────
//
// The static collection path (`/api/integrations`) is in `ALLOWED_PORTAL_API_PATHS`.
// Dynamic id paths (`/api/integrations/{id}` and `/api/integrations/{id}/test`)
// are NOT in the static list — they are validated inline via
// `same_origin_api_path()` + `safe_integration_id()` inside each server fn,
// mirroring the request lifecycle path pattern exactly.

/// Upstream-only integration row. This is deliberately distinct from the
/// browser-visible `IntegrationSummary`: current responses expose only the
/// locator-free `credential_configured` bit, while an N-1 `credential_ref` is
/// consumed as presence-only compatibility input and never allocated.
#[cfg(any(feature = "ssr", test))]
#[derive(Deserialize)]
struct ApiIntegrationConnection {
    id: String,
    vendor_type: String,
    name: String,
    endpoint_url: String,
    site_scope: Option<String>,
    credential_source: String,
    #[serde(default)]
    credential_configured: Option<bool>,
    #[serde(
        rename = "credential_ref",
        default,
        deserialize_with = "deserialize_legacy_credential_ref_presence"
    )]
    legacy_credential_ref_present: bool,
    status: String,
    readiness: String,
    execution_mode: String,
    last_test_at: Option<String>,
    last_test_result: Option<String>,
    created_by: String,
    created_at: String,
    updated_at: String,
}

#[cfg(any(feature = "ssr", test))]
fn deserialize_legacy_credential_ref_presence<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<serde::de::IgnoredAny>::deserialize(deserializer)?.is_some())
}

#[cfg(any(feature = "ssr", test))]
#[derive(Deserialize)]
struct ApiIntegrationListEnvelope {
    connections: Vec<ApiIntegrationConnection>,
}

#[cfg(any(feature = "ssr", test))]
#[derive(Deserialize)]
struct ApiIntegrationConnectionEnvelope {
    connection: ApiIntegrationConnection,
}

#[cfg(any(feature = "ssr", test))]
fn project_integration_connection(connection: ApiIntegrationConnection) -> IntegrationSummary {
    IntegrationSummary {
        id: connection.id,
        vendor_type: connection.vendor_type,
        name: connection.name,
        endpoint_url: connection.endpoint_url,
        site_scope: connection.site_scope,
        credential_source: connection.credential_source,
        credential_configured: connection
            .credential_configured
            .unwrap_or(connection.legacy_credential_ref_present),
        status: connection.status,
        readiness: connection.readiness,
        execution_mode: connection.execution_mode,
        last_test_at: connection.last_test_at,
        last_test_result: connection.last_test_result,
        created_by: connection.created_by,
        created_at: connection.created_at,
        updated_at: connection.updated_at,
    }
}

#[cfg(any(feature = "ssr", test))]
fn parse_integration_list_response(
    body: &str,
) -> Result<Vec<IntegrationSummary>, serde_json::Error> {
    let envelope: ApiIntegrationListEnvelope = serde_json::from_str(body)?;
    Ok(envelope
        .connections
        .into_iter()
        .map(project_integration_connection)
        .collect())
}

/// Create and update responses use the same required `{ connection: ... }`
/// envelope as the platform API. Missing or malformed envelopes fail closed;
/// they can no longer fabricate an all-empty successful summary.
#[cfg(any(feature = "ssr", test))]
fn parse_integration_connection_response(
    body: &str,
) -> Result<IntegrationSummary, serde_json::Error> {
    let envelope: ApiIntegrationConnectionEnvelope = serde_json::from_str(body)?;
    Ok(project_integration_connection(envelope.connection))
}

#[cfg(any(feature = "ssr", test))]
fn integration_create_request_body(
    payload: CreateIntegrationPayload,
) -> Result<serde_json::Value, &'static str> {
    if payload.credential_secret_ref.is_some() && !payload.credential_ref.is_empty() {
        return Err("integration credential request mixed current and legacy reference fields");
    }
    let mut body = serde_json::json!({
        "vendor_type": payload.vendor_type,
        "name": payload.name,
        "endpoint_url": payload.endpoint_url,
        "site_scope": payload.site_scope,
        "credential_source": payload.credential_source,
        "inline_secret": payload.inline_secret,
    });
    if let Some(secret_ref) = payload.credential_secret_ref {
        body["credential_secret_ref"] = secret_ref;
    } else {
        body["credential_ref"] = serde_json::Value::String(payload.credential_ref);
    }
    Ok(body)
}

#[cfg(any(feature = "ssr", test))]
fn integration_update_request_body(
    payload: UpdateIntegrationPayload,
) -> Result<serde_json::Value, &'static str> {
    if payload.credential_secret_ref.is_some() && payload.credential_ref.is_some() {
        return Err("integration credential request mixed current and legacy reference fields");
    }
    let mut body = serde_json::json!({
        "vendor_type": payload.vendor_type,
        "name": payload.name,
        "endpoint_url": payload.endpoint_url,
        "site_scope": payload.site_scope,
        // Empty inline_secret = keep existing (no re-encryption, per Slice-1).
        "inline_secret": payload.inline_secret,
    });
    if let Some(secret_ref) = payload.credential_secret_ref {
        body["credential_secret_ref"] = secret_ref;
    } else if let Some(credential_ref) = payload.credential_ref {
        body["credential_ref"] = serde_json::Value::String(credential_ref);
    }
    Ok(body)
}

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
        Ok(response) if response.is_success() => parse_integration_list_response(&response.body)
            .map_err(|_| ServerFnError::new("integrations list response was malformed")),
        Ok(response) => Err(ServerFnError::new(api_error_text(
            &response,
            "integrations list fetch failed",
        ))),
        Err(_) => Err(ServerFnError::new("API unreachable")),
    }
}

// ── Agent server functions ────────────────────────────────────────────────

#[cfg(any(feature = "ssr", test))]
#[derive(Debug, Deserialize)]
struct AdminAgentsEnvelope {
    agents: Vec<AgentSummary>,
    capped: bool,
}

#[cfg(any(feature = "ssr", test))]
#[derive(Debug, PartialEq, Eq)]
enum AdminAgentsResponseError {
    Malformed,
    Truncated,
}

/// Parse the admin roster through the portal-safe model. Both immutable review
/// fields are required, so an older or malformed API response cannot render an
/// approval button that falls back to agent-id-only authorization. Unknown
/// fields (including a mistakenly returned raw public key) are discarded rather
/// than copied into the server-function response.
#[cfg(any(feature = "ssr", test))]
fn parse_admin_agents_response(
    raw: serde_json::Value,
) -> Result<Vec<AgentSummary>, AdminAgentsResponseError> {
    let envelope = serde_json::from_value::<AdminAgentsEnvelope>(raw)
        .map_err(|_| AdminAgentsResponseError::Malformed)?;
    if envelope.capped {
        return Err(AdminAgentsResponseError::Truncated);
    }
    Ok(envelope.agents)
}

#[cfg(any(feature = "ssr", test))]
fn is_canonical_enrollment_id(value: &str) -> bool {
    let mut groups = value.split('-');
    [8, 4, 4, 4, 12].into_iter().all(|expected_len| {
        groups.next().is_some_and(|group| {
            group.len() == expected_len
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    }) && groups.next().is_none()
}

#[cfg(any(feature = "ssr", test))]
fn is_sha256_fingerprint(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Build the exact API approval payload from one reviewed roster snapshot.
/// Keeping this pure makes the stale-review contract explicit and testable: the
/// portal submits the snapshot's immutable values and lets the API reject them
/// with 409 if the enrollment changed before the click.
#[cfg(any(feature = "ssr", test))]
fn validate_agent_enrollment_binding(
    enrollment_id: &str,
    public_key_fingerprint: &str,
) -> Result<(), &'static str> {
    if !is_canonical_enrollment_id(enrollment_id) {
        return Err("agent operation requires a valid enrollment binding");
    }
    if !is_sha256_fingerprint(public_key_fingerprint) {
        return Err("agent operation requires a valid public-key fingerprint");
    }
    Ok(())
}

#[cfg(any(feature = "ssr", test))]
fn agent_approval_body(
    enrollment_id: &str,
    public_key_fingerprint: &str,
    platform: &str,
) -> Result<serde_json::Value, &'static str> {
    validate_agent_enrollment_binding(enrollment_id, public_key_fingerprint)?;
    if platform.trim().is_empty() {
        return Err("agent approval requires a non-empty platform");
    }
    Ok(serde_json::json!({
        "enrollment_id": enrollment_id,
        "public_key_fingerprint": public_key_fingerprint,
        "platform": platform,
    }))
}

/// Build the terminal-revocation payload from the same immutable roster binding
/// used by approval. A stale page therefore asks the API to revoke the reviewed
/// row, never whichever row currently happens to reuse the human-readable id.
#[cfg(any(feature = "ssr", test))]
fn agent_revocation_body(
    enrollment_id: &str,
    public_key_fingerprint: &str,
) -> Result<serde_json::Value, &'static str> {
    validate_agent_enrollment_binding(enrollment_id, public_key_fingerprint)?;
    Ok(serde_json::json!({
        "enrollment_id": enrollment_id,
        "public_key_fingerprint": public_key_fingerprint,
    }))
}

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
            match parse_admin_agents_response(raw) {
                Ok(agents) => Ok(agents),
                Err(AdminAgentsResponseError::Truncated) => Err(ServerFnError::new(
                    "Agent roster is truncated; review the complete enrollment inventory before approving or closing the enrollment cutover",
                )),
                Err(AdminAgentsResponseError::Malformed) => {
                    Err(ServerFnError::new("admin agents response was malformed"))
                }
            }
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
/// The API's approve body requires the immutable `enrollment_id`, the reviewed
/// non-secret `public_key_fingerprint`, and an authoritative `platform`. The
/// portal submits all three values from the same displayed roster snapshot so a
/// stale page cannot approve a replacement enrollment that reused an agent id.
/// Capabilities are intentionally omitted, so the API resets them to empty (its
/// documented secure default): the admin must grant capabilities explicitly
/// through the authoritative API rather than trust the agent's self-declared
/// set. The roster exposes the stored document's digest for review/audit.
/// Mutations never degrade to a fallback — a static/unreachable upstream errors.
#[server(prefix = "/portal/api", endpoint = "admin-agents-approve")]
pub async fn approve_agent(
    agent_id: String,
    enrollment_id: String,
    public_key_fingerprint: String,
    platform: String,
) -> Result<RevokeResult, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = admin_agent_approve_path(&agent_id)
        .map_err(|_| ServerFnError::new("admin agent approve API path failed same-origin guard"))?;
    boundary
        .validate_admin_agent_approve_path(&path)
        .map_err(|_| ServerFnError::new("admin agent approve API path failed same-origin guard"))?;
    let body = agent_approval_body(&enrollment_id, &public_key_fingerprint, &platform)
        .map_err(ServerFnError::new)?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_agent_approve();
    }
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

/// `POST /api/admin/agents/{id}/revoke` — take one exact enrolled agent offline.
/// The immutable enrollment id and reviewed key fingerprint are mandatory, so a
/// stale roster cannot revoke a replacement enrollment that reused the agent id.
/// The API sets status='revoked' (terminal) so the agent's token is refused on
/// its next call. Mutations never degrade to a fallback — a static/unreachable
/// upstream errors.
#[server(prefix = "/portal/api", endpoint = "admin-agents-revoke")]
pub async fn revoke_agent(
    agent_id: String,
    enrollment_id: String,
    public_key_fingerprint: String,
) -> Result<RevokeResult, ServerFnError> {
    let boundary = PortalServerBoundary::static_dry_run();
    let path = admin_agent_revoke_path(&agent_id)
        .map_err(|_| ServerFnError::new("admin agent revoke API path failed same-origin guard"))?;
    boundary
        .validate_admin_agent_revoke_path(&path)
        .map_err(|_| ServerFnError::new("admin agent revoke API path failed same-origin guard"))?;
    let body = agent_revocation_body(&enrollment_id, &public_key_fingerprint)
        .map_err(ServerFnError::new)?;
    let upstream = upstream_context();
    if !upstream.live() {
        return reject_static_preview_revoke("agent");
    }
    let session_id = session_id_from_request().await;
    let response = upstream
        .post(&path, Some(&body), session_id.as_deref())
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
    let body = integration_create_request_body(payload).map_err(ServerFnError::new)?;
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
    parse_integration_connection_response(&response.body)
        .map_err(|_| ServerFnError::new("integration create response was malformed"))
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
    let body = integration_update_request_body(payload).map_err(ServerFnError::new)?;
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
    parse_integration_connection_response(&response.body)
        .map_err(|_| ServerFnError::new("integration update response was malformed"))
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

    fn integration_response_row() -> serde_json::Value {
        serde_json::json!({
            "id": "integration-test",
            "vendor_type": "test-vendor",
            "name": "Test integration",
            "endpoint_url": "https://example.invalid",
            "site_scope": null,
            "credential_source": "secret-provider-ref",
            "credential_configured": true,
            "status": "configured",
            "readiness": "configured",
            "execution_mode": "static-dry-run",
            "last_test_at": null,
            "last_test_result": null,
            "created_by": "test-user",
            "created_at": "2026-07-19T00:00:00Z",
            "updated_at": "2026-07-19T00:00:00Z"
        })
    }

    #[test]
    fn integration_mutation_parser_requires_connection_envelope() {
        let flat = integration_response_row().to_string();
        assert!(parse_integration_connection_response(&flat).is_err());

        let wrapped = serde_json::json!({
            "source": "database",
            "connection": integration_response_row(),
        })
        .to_string();
        let summary = parse_integration_connection_response(&wrapped)
            .expect("required connection envelope must decode");
        assert_eq!(summary.id, "integration-test");
        assert!(summary.credential_configured);
    }

    #[test]
    fn integration_projection_discards_current_and_legacy_locator_fields() {
        let mut row = integration_response_row();
        row["credential_ref"] = serde_json::json!("legacy-locator-sentinel");
        row["credential_secret_ref"] = serde_json::json!({
            "opaqueLocator": "typed-locator-sentinel",
            "field_selector": "typed-field-sentinel",
        });
        let wrapped = serde_json::json!({"connection": row}).to_string();

        let summary = parse_integration_connection_response(&wrapped)
            .expect("safe current response must decode");
        let projected = serde_json::to_string(&summary).expect("summary must serialize");
        assert!(summary.credential_configured);
        assert!(!projected.contains("credential_ref"));
        assert!(!projected.contains("credential_secret_ref"));
        assert!(!projected.contains("legacy-locator-sentinel"));
        assert!(!projected.contains("typed-locator-sentinel"));
        assert!(!projected.contains("typed-field-sentinel"));
    }

    #[test]
    fn integration_projection_accepts_n_minus_one_reference_as_presence_only() {
        let mut row = integration_response_row();
        row.as_object_mut()
            .expect("row object")
            .remove("credential_configured");
        row["credential_source"] = serde_json::json!("vault");
        row["credential_ref"] = serde_json::json!("n-minus-one-locator-sentinel");
        let wrapped = serde_json::json!({"connection": row}).to_string();

        let summary = parse_integration_connection_response(&wrapped)
            .expect("N-1 response must remain readable");
        assert!(summary.credential_configured);
        let projected = serde_json::to_string(&summary).expect("summary must serialize");
        assert!(!projected.contains("n-minus-one-locator-sentinel"));
    }

    #[test]
    fn integration_projection_does_not_override_current_state_with_legacy_presence() {
        let mut row = integration_response_row();
        row["credential_configured"] = serde_json::json!(false);
        row["credential_ref"] = serde_json::json!("stale-legacy-locator-sentinel");
        let wrapped = serde_json::json!({"connection": row}).to_string();

        let summary = parse_integration_connection_response(&wrapped)
            .expect("current response must remain authoritative");
        assert!(!summary.credential_configured);
    }

    #[test]
    fn integration_list_uses_the_same_strict_locator_free_projector() {
        let list = serde_json::json!({
            "connections": [integration_response_row()],
        })
        .to_string();
        let summaries =
            parse_integration_list_response(&list).expect("valid list envelope must decode");
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].credential_configured);

        let malformed = serde_json::json!({
            "connections": [{"credential_source": "secret-provider-ref"}],
        })
        .to_string();
        assert!(parse_integration_list_response(&malformed).is_err());
    }

    #[test]
    fn integration_create_request_selects_exact_current_or_n_minus_one_shape() {
        let typed = integration_create_request_body(CreateIntegrationPayload {
            vendor_type: "test".to_string(),
            name: "typed".to_string(),
            endpoint_url: "https://example.invalid".to_string(),
            site_scope: None,
            credential_source: "secret-provider-ref".to_string(),
            credential_secret_ref: Some(serde_json::json!({
                "schemaVersion": 1,
                "opaqueLocator": "typed-locator-sentinel",
            })),
            credential_ref: String::new(),
            inline_secret: String::new(),
        })
        .expect("typed request must be admitted");
        assert!(typed.get("credential_secret_ref").is_some());
        assert!(typed.get("credential_ref").is_none());

        let legacy = integration_create_request_body(CreateIntegrationPayload {
            vendor_type: "test".to_string(),
            name: "legacy".to_string(),
            endpoint_url: "https://example.invalid".to_string(),
            site_scope: None,
            credential_source: "vault".to_string(),
            credential_secret_ref: None,
            credential_ref: "legacy-locator-sentinel".to_string(),
            inline_secret: String::new(),
        })
        .expect("N-1 request must remain admitted");
        assert!(legacy.get("credential_secret_ref").is_none());
        assert_eq!(legacy["credential_ref"], "legacy-locator-sentinel");
    }

    #[test]
    fn integration_requests_reject_mixed_current_and_legacy_references() {
        let create = CreateIntegrationPayload {
            vendor_type: "test".to_string(),
            name: "mixed".to_string(),
            endpoint_url: "https://example.invalid".to_string(),
            site_scope: None,
            credential_source: "secret-provider-ref".to_string(),
            credential_secret_ref: Some(serde_json::json!({"schemaVersion": 1})),
            credential_ref: "legacy-locator-sentinel".to_string(),
            inline_secret: String::new(),
        };
        assert!(integration_create_request_body(create).is_err());

        let update = UpdateIntegrationPayload {
            vendor_type: None,
            name: None,
            endpoint_url: None,
            site_scope: None,
            credential_secret_ref: Some(serde_json::json!({"schemaVersion": 1})),
            credential_ref: Some("legacy-locator-sentinel".to_string()),
            inline_secret: String::new(),
        };
        assert!(integration_update_request_body(update).is_err());
    }

    #[test]
    fn integration_update_without_credential_input_preserves_the_binding() {
        let body = integration_update_request_body(UpdateIntegrationPayload {
            vendor_type: None,
            name: Some("renamed".to_string()),
            endpoint_url: None,
            site_scope: None,
            credential_secret_ref: None,
            credential_ref: None,
            inline_secret: String::new(),
        })
        .expect("noncredential update must be admitted");
        assert!(body.get("credential_secret_ref").is_none());
        assert!(body.get("credential_ref").is_none());
    }

    #[test]
    fn reviewed_plan_approval_body_is_closed_and_exact() {
        let selection = ReviewedLivePlanSelection {
            approved_plan_job_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7".to_string(),
            approved_plan_attempt_id: "8d0f778a-8536-41ef-a55c-f18fd20a1bf8".to_string(),
            approved_plan_digest: "d".repeat(64),
        };
        let body = reviewed_plan_approval_body(&selection).expect("canonical selection");
        let keys = body.as_object().expect("approval object");
        assert_eq!(keys.len(), 3);
        assert_eq!(body["approved_plan_job_id"], selection.approved_plan_job_id);
        assert_eq!(
            body["approved_plan_attempt_id"],
            selection.approved_plan_attempt_id
        );
        assert_eq!(body["approved_plan_digest"], selection.approved_plan_digest);
        assert!(body.get("platform").is_none());
        assert!(body.get("spec").is_none());
    }

    #[test]
    fn reviewed_plan_approval_body_rejects_noncanonical_selection() {
        let selection = ReviewedLivePlanSelection {
            approved_plan_job_id: "not-a-job-id".to_string(),
            approved_plan_attempt_id: "8d0f778a-8536-41ef-a55c-f18fd20a1bf8".to_string(),
            approved_plan_digest: "D".repeat(64),
        };
        assert!(reviewed_plan_approval_body(&selection).is_err());
    }

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

    fn n_rows(n: usize) -> Vec<RequestSummary> {
        (0..n)
            .map(|i| summary_row(&format!("r{i}"), "ams1", "intake", "2026-01-01"))
            .collect()
    }

    #[test]
    fn finalize_overfetched_page_signals_next_only_when_over_fetched() {
        // Exactly page_size rows: no extra row → last page, kept intact.
        let p = finalize_overfetched_page(n_rows(25), 0, 25, None);
        assert_eq!(p.rows.len(), 25);
        assert!(!p.has_next);
        // Under a full page → last page.
        let p = finalize_overfetched_page(n_rows(24), 0, 25, None);
        assert_eq!(p.rows.len(), 24);
        assert!(!p.has_next);
        // page_size + 1: the extra row signals a next page and is truncated away.
        let p = finalize_overfetched_page(n_rows(26), 25, 25, None);
        assert_eq!(p.rows.len(), 25);
        assert!(p.has_next);
        assert_eq!(p.offset, 25);
        assert_eq!(p.page_size, 25);
    }

    #[test]
    fn finalize_overfetched_page_carries_total_without_touching_has_next() {
        // A supplied total is passed through for display only; has_next stays
        // over-fetch derived (no extra row here → false), independent of total.
        let page = finalize_overfetched_page(n_rows(25), 0, 25, Some(142));
        assert_eq!(page.total, Some(142));
        assert!(!page.has_next);
        // Absent header → None total, page still valid.
        let none = finalize_overfetched_page(n_rows(26), 0, 25, None);
        assert_eq!(none.total, None);
        assert!(none.has_next);
    }

    #[test]
    fn paginate_in_memory_slices_and_derives_has_next_at_boundaries() {
        // First page of 26 → 25 rows, more remain. Total is the full length.
        let first = paginate_in_memory(n_rows(26), 0, 25);
        assert_eq!(first.rows.len(), 25);
        assert!(first.has_next);
        assert_eq!(first.total, Some(26));
        // Exact last full page: total == offset + page_size → no next.
        let exact = paginate_in_memory(n_rows(50), 25, 25);
        assert_eq!(exact.rows.len(), 25);
        assert!(!exact.has_next);
        assert_eq!(exact.total, Some(50));
        // One beyond the exact page → next page exists.
        let beyond = paginate_in_memory(n_rows(51), 25, 25);
        assert_eq!(beyond.rows.len(), 25);
        assert!(beyond.has_next);
        // Partial last page.
        let partial = paginate_in_memory(n_rows(30), 25, 25);
        assert_eq!(partial.rows.len(), 5);
        assert!(!partial.has_next);
        // Offset past the end → empty page, no next, offset preserved, but the
        // total still reflects the full known set.
        let past = paginate_in_memory(n_rows(10), 100, 25);
        assert!(past.rows.is_empty());
        assert!(!past.has_next);
        assert_eq!(past.offset, 100);
        assert_eq!(past.total, Some(10));
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
    fn filter_request_summaries_applies_environment_case_insensitively() {
        let rows = vec![
            summary_row("Web", "ams1", "intake", "2026-01-01"),
            summary_row("Db", "fra1", "intake", "2026-01-02"),
        ];
        // summary_row sets environment = "prod" for all rows
        let query = RequestListQuery {
            environment: Some("PROD".to_string()),
            ..Default::default()
        };
        let out = filter_request_summaries(rows.clone(), &query);
        assert_eq!(
            out.len(),
            2,
            "all rows have environment=prod, PROD should match all"
        );

        let query_miss = RequestListQuery {
            environment: Some("staging".to_string()),
            ..Default::default()
        };
        let out_miss = filter_request_summaries(rows, &query_miss);
        assert!(out_miss.is_empty(), "no rows have environment=staging");
    }

    #[test]
    fn filter_request_summaries_applies_request_type_case_insensitively() {
        let rows = vec![
            summary_row("Web", "ams1", "intake", "2026-01-01"),
            summary_row("Db", "fra1", "intake", "2026-01-02"),
        ];
        // summary_row sets request_type = "server" for all rows
        let query = RequestListQuery {
            request_type: Some("SERVER".to_string()),
            ..Default::default()
        };
        let out = filter_request_summaries(rows.clone(), &query);
        assert_eq!(
            out.len(),
            2,
            "all rows have request_type=server, SERVER should match all"
        );

        let query_miss = RequestListQuery {
            request_type: Some("network".to_string()),
            ..Default::default()
        };
        let out_miss = filter_request_summaries(rows, &query_miss);
        assert!(out_miss.is_empty(), "no rows have request_type=network");
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
    fn logout_completion_clears_local_credential_before_success_or_failure() {
        use std::cell::Cell;

        for (outcome, succeeds) in [
            (LogoutUpstreamOutcome::Confirmed, true),
            (
                LogoutUpstreamOutcome::Rejected("Sign-out was rejected".to_string()),
                false,
            ),
            (LogoutUpstreamOutcome::Unreachable, false),
        ] {
            let cleared = Cell::new(false);
            let result = finish_logout(outcome, || cleared.set(true));
            assert!(cleared.get(), "portal credential must always be retired");
            assert_eq!(result.is_ok(), succeeds);
        }
    }

    #[test]
    fn logout_failure_projection_is_safe_and_distinguishes_rejection() {
        let rejected = finish_logout(
            LogoutUpstreamOutcome::Rejected("Canonical API rejection".to_string()),
            || {},
        )
        .unwrap_err()
        .to_string();
        assert!(rejected.contains("Canonical API rejection"));

        let unreachable = finish_logout(LogoutUpstreamOutcome::Unreachable, || {})
            .unwrap_err()
            .to_string();
        assert!(unreachable.contains("server-side session revocation could not be confirmed"));
        assert!(!unreachable.contains("connection refused"));
        assert!(!unreachable.contains("upstream returned status"));
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
    fn live_route_state_does_not_fabricate_freshness_or_scope() {
        // Regression: live_provider() must NOT inherit static_dry_run()'s fixture
        // freshness/scope labels (e.g. "Monitoring stale", "Site: Global"), which
        // would render fabricated operational state — a false staleness warning —
        // as if real. Until real freshness/scope is wired, show honest placeholders.
        let snapshot = PortalRouteStateSnapshot::live_provider()
            .expect("live route state snapshot must build");
        for label in [
            &snapshot.inventory_freshness_label,
            &snapshot.backup_freshness_label,
            &snapshot.monitoring_freshness_label,
            &snapshot.site_scope_label,
            &snapshot.environment_scope_label,
            &snapshot.role_scope_label,
        ] {
            assert!(
                label.contains("not yet wired"),
                "live-mode label must be an honest placeholder, got: {label}"
            );
        }
        assert!(
            !snapshot.monitoring_freshness_label.contains("stale"),
            "live mode must not show a fabricated staleness warning"
        );
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

    fn agent_roster_json(enrollment_id: &str, fingerprint: &str) -> serde_json::Value {
        serde_json::json!({
            "agents": [{
                "enrollment_id": enrollment_id,
                "cryptographically_admitted": true,
                "agent_id": "agent-review-01",
                "platform": "vmware",
                "status": "pending",
                "public_key_fingerprint": fingerprint,
                "capabilities_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                // Defense-in-depth regression fixture: even if an upstream bug
                // returns this field, the portal model must discard it.
                "public_key": "raw-public-key-must-not-cross-portal-boundary",
                "last_seen_at": null,
                "created_at": "2026-07-15T00:00:00Z",
                "jobs": []
            }],
            "capped": false
        })
    }

    #[test]
    fn agent_mutation_contract_preserves_reviewed_binding_without_raw_key() {
        let enrollment_id = "2f6cb8a7-c2c2-4c96-9f32-c80a2d329601";
        let fingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let agents = parse_admin_agents_response(agent_roster_json(enrollment_id, fingerprint))
            .expect("a complete roster binding must parse");
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].enrollment_id, enrollment_id);
        assert!(agents[0].cryptographically_admitted);
        assert_eq!(agents[0].public_key_fingerprint, fingerprint);
        assert!(is_sha256_fingerprint(&agents[0].capabilities_digest));

        let portal_json =
            serde_json::to_value(&agents[0]).expect("portal agent summary must serialize");
        assert!(
            portal_json.get("public_key").is_none(),
            "raw public-key bytes must be discarded at the typed portal boundary"
        );

        let body = agent_approval_body(
            &agents[0].enrollment_id,
            &agents[0].public_key_fingerprint,
            &agents[0].platform,
        )
        .expect("a complete reviewed binding must produce an approval body");
        assert_eq!(
            body,
            serde_json::json!({
                "enrollment_id": enrollment_id,
                "public_key_fingerprint": fingerprint,
                "platform": "vmware"
            })
        );

        let revoke_body =
            agent_revocation_body(&agents[0].enrollment_id, &agents[0].public_key_fingerprint)
                .expect("a complete reviewed binding must produce a revocation body");
        assert_eq!(
            revoke_body,
            serde_json::json!({
                "enrollment_id": enrollment_id,
                "public_key_fingerprint": fingerprint,
            })
        );
    }

    #[test]
    fn truncated_agent_roster_fails_closed_before_rendering_approval_actions() {
        let mut raw = agent_roster_json(
            "2f6cb8a7-c2c2-4c96-9f32-c80a2d329601",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        raw["capped"] = serde_json::json!(true);
        assert!(matches!(
            parse_admin_agents_response(raw),
            Err(AdminAgentsResponseError::Truncated)
        ));
    }

    #[test]
    fn agent_mutation_contract_keeps_stale_snapshot_for_api_conflict() {
        let reviewed_id = "2f6cb8a7-c2c2-4c96-9f32-c80a2d329601";
        let reviewed_fingerprint =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let replacement_id = "0190e17a-e9c3-7d8d-b7a9-933fc05cd53e";
        let replacement_fingerprint =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let reviewed =
            parse_admin_agents_response(agent_roster_json(reviewed_id, reviewed_fingerprint))
                .expect("reviewed snapshot must parse")
                .remove(0);
        let replacement =
            parse_admin_agents_response(agent_roster_json(replacement_id, replacement_fingerprint))
                .expect("replacement snapshot must parse")
                .remove(0);
        assert_eq!(reviewed.agent_id, replacement.agent_id);

        let stale_body = agent_approval_body(
            &reviewed.enrollment_id,
            &reviewed.public_key_fingerprint,
            &reviewed.platform,
        )
        .expect("the reviewed snapshot remains a well-formed request");
        assert_eq!(stale_body["enrollment_id"], reviewed_id);
        assert_eq!(stale_body["public_key_fingerprint"], reviewed_fingerprint);
        assert_ne!(
            stale_body["enrollment_id"].as_str(),
            Some(replacement.enrollment_id.as_str())
        );
        assert_ne!(
            stale_body["public_key_fingerprint"].as_str(),
            Some(replacement.public_key_fingerprint.as_str())
        );

        let stale_revoke_body =
            agent_revocation_body(&reviewed.enrollment_id, &reviewed.public_key_fingerprint)
                .expect("the reviewed snapshot remains a well-formed revoke request");
        assert_eq!(stale_revoke_body["enrollment_id"], reviewed_id);
        assert_eq!(
            stale_revoke_body["public_key_fingerprint"],
            reviewed_fingerprint
        );
        assert_ne!(
            stale_revoke_body["enrollment_id"].as_str(),
            Some(replacement.enrollment_id.as_str())
        );
        assert_ne!(
            stale_revoke_body["public_key_fingerprint"].as_str(),
            Some(replacement.public_key_fingerprint.as_str())
        );
    }

    #[test]
    fn agent_mutation_contract_rejects_missing_or_malformed_binding() {
        let enrollment_id = "2f6cb8a7-c2c2-4c96-9f32-c80a2d329601";
        let fingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        for missing_field in [
            "enrollment_id",
            "public_key_fingerprint",
            "capabilities_digest",
        ] {
            let mut raw = agent_roster_json(enrollment_id, fingerprint);
            raw["agents"][0]
                .as_object_mut()
                .expect("agent fixture must be an object")
                .remove(missing_field);
            assert!(
                parse_admin_agents_response(raw).is_err(),
                "a roster row missing {missing_field} must fail closed"
            );
        }

        assert!(agent_approval_body("", fingerprint, "vmware").is_err());
        assert!(agent_approval_body(enrollment_id, "", "vmware").is_err());
        assert!(agent_approval_body(enrollment_id, fingerprint, " ").is_err());
        assert!(agent_approval_body("not-a-uuid", fingerprint, "vmware").is_err());
        assert!(agent_approval_body(enrollment_id, "sha256:short", "vmware").is_err());
        assert!(agent_revocation_body("", fingerprint).is_err());
        assert!(agent_revocation_body(enrollment_id, "").is_err());
        assert!(agent_revocation_body("not-a-uuid", fingerprint).is_err());
        assert!(agent_revocation_body(enrollment_id, "sha256:short").is_err());
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
    fn boundary_allows_only_the_exact_admin_job_result_read() {
        let boundary = PortalServerBoundary::static_dry_run();
        let id = "3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b";
        let path =
            crate::api::admin_agent_job_result_path(id).expect("admin job result path must build");
        assert_eq!(
            boundary.validate_admin_agent_job_result_path(&path),
            Ok(path.as_str())
        );

        for unsafe_path in [
            "/api/admin/agents/jobs",
            "/api/admin/agents/jobs/id",
            "/api/admin/agents/jobs/id/state",
            "/api/admin/agents/jobs/id/result/extra",
            "/api/admin/agents/jobs/../result",
            "/api/admin/agents/jobs/id?x=1/result",
            "/api/admin/agents/id/result",
        ] {
            assert_eq!(
                boundary.validate_admin_agent_job_result_path(unsafe_path),
                Err(PortalBoundaryError::OutsidePortalAllowlist),
                "path {unsafe_path} must be rejected"
            );
        }
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

        // Per-step live-apply approval (#42 B1b): the step key is a dynamic
        // segment, so the generated path is validated shape-and-charset-wise.
        let step_path = request_step_approve_live_apply_path(request_id, "provision-vm")
            .expect("step approve-live-apply path must build");
        assert_eq!(
            boundary.validate_request_lifecycle_api_path(&step_path),
            Ok(step_path.as_str())
        );

        for path in [
            "/api/requests/detail",
            "/api/requests/reject",
            "/api/requests/cancel",
            "/api/requests/audit",
            "/api/requests/evidence",
            "/api/requests/steps",
            "/api/requests/REQ-123/validate/extra",
            "/api/requests/REQ-123/reject/extra",
            "/api/requests/REQ 123/validate",
            "/api/requests/REQ%2F123/validate",
            "/api/requests/REQ-123?stage=validate",
            // Step-path shapes that must stay outside the allowlist: missing
            // suffix, wrong suffix, trailing segments, unsafe step keys.
            "/api/requests/REQ-123/steps",
            "/api/requests/REQ-123/steps/provision-vm",
            "/api/requests/REQ-123/steps/provision-vm/execute",
            "/api/requests/REQ-123/steps/provision-vm/approve-live-apply/extra",
            "/api/requests/REQ-123/steps//approve-live-apply",
            "/api/requests/REQ-123/steps/../approve-live-apply",
            "/api/requests/REQ-123/steps/step key/approve-live-apply",
            "/api/requests/REQ-123/steps/step%2Fkey/approve-live-apply",
        ] {
            assert_eq!(
                boundary.validate_request_lifecycle_api_path(path),
                Err(PortalBoundaryError::OutsidePortalAllowlist),
                "path {path:?} must be rejected"
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
        assert_eq!(snapshot.provider_model, catalog_status.provider_model);
        assert_eq!(
            snapshot.management_interface,
            catalog_status.management_interface
        );
        assert_eq!(snapshot.fallback_policy, "disabled");
        assert_eq!(snapshot.admitted_provider_classes.len(), 5);
        assert_eq!(
            snapshot.capability_interfaces,
            vec!["resolve-read", "publish-version", "materialize-reload"]
        );
        assert_eq!(
            snapshot.secret_reference_kinds,
            vec![
                "adapter-credential",
                "worker-credential",
                "database-credential",
                "object-storage-credential",
                "pki-material",
                "recovery-material",
                "signing-material"
            ]
        );
        assert_eq!(snapshot.secret_references.len(), 3);
        assert_eq!(snapshot.readiness_state, "pending-approval");
        assert!(!snapshot.configured_for_production);
        assert!(!snapshot.live_provider_actions_allowed);
        assert!(!snapshot.provider_calls_allowed);
        assert!(!snapshot.raw_payload_allowed);
        assert!(!snapshot.secret_values_allowed);
        assert!(!snapshot.provider_paths_allowed);
        assert!(!snapshot.customer_identifiers_allowed);
        assert!(snapshot.secret_references.iter().all(|reference| {
            !reference.live_provider_actions_allowed
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
