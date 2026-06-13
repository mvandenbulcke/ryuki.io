pub const API_PREFIX: &str = "/api/";
const BOUNDARY_STATUS_PATH: &str = "/api/boundary/status";
const PLATFORM_STATUS_PATH: &str = "/api/platform/status";
const PLATFORM_HEALTH_PATH: &str = "/api/platform/health";
const AUTH_STATUS_PATH: &str = "/api/auth/status";
const AUTH_SESSION_PATH: &str = "/api/auth/session";
const PLATFORM_SUMMARY_PATH: &str = "/api/platform/summary";
const REQUEST_INTAKE_PATH: &str = "/api/requests/intake-support-contract";
const REQUEST_PREFLIGHT_PATH: &str = "/api/requests/preflight-contract";
const DRY_RUN_PLAN_PATH: &str = "/api/workflows/server-lifecycle/dry-run-contract";
const INVENTORY_RESOURCE_OVERVIEW_PATH: &str = "/api/inventory/resource-overview-contract";
const INVENTORY_OWNERSHIP_RISK_PATH: &str = "/api/inventory/ownership-risk-contract";
const CLUSTER_CAPACITY_ADMISSION_PATH: &str =
    "/api/integrations/vmware/cluster-capacity-admission-contract";
const CATALOG_OFFERINGS_PATH: &str = "/api/catalog/offerings-contract";
const CATALOG_RECOMMENDATIONS_PATH: &str = "/api/catalog/recommendations-contract";
const CATALOG_REQUEST_FORM_PATH: &str = "/api/catalog/request-form-contract";
const SITE_CATALOG_PATH: &str = "/api/catalog/site-catalog-contract";
const APPROVAL_DECISION_READINESS_PATH: &str = "/api/approvals/decision-readiness-contract";
const ACTIVITY_OPERATION_QUEUE_PATH: &str = "/api/operations/activity-queue-contract";
/// Global, newest-first governance audit feed across all requests.
const ACTIVITY_AUDIT_FEED_PATH: &str = "/api/activity/audit";
const SHIFT_QUEUE_PATH: &str = "/api/operations/shift-queue-contract";
const EMERGENCY_CHANGE_PATH: &str = "/api/operations/emergency-change-contract";
const CMDB_FILE_EXCHANGE_PATH: &str = "/api/integrations/servicenow/cmdb-file-contract";
const CMDB_RECONCILIATION_PATH: &str = "/api/cmdb/reconciliation-contract";
const CMDB_RELATIONSHIP_GRAPH_PATH: &str = "/api/cmdb/relationship-graph-contract";
const EVIDENCE_EXPORT_RETENTION_PATH: &str = "/api/evidence/export-retention-contract";
const EVIDENCE_COMPLIANCE_DASHBOARD_PATH: &str = "/api/evidence/compliance-dashboard-contract";
const OPERATIONS_RUNBOOK_LAUNCH_PATH: &str = "/api/operations/runbook-launch-contract";
const OPERATIONS_PLATFORM_HEALTH_PATH: &str = "/api/operations/platform-health-contract";
const ADMIN_WORKER_CAPABILITY_PATH: &str = "/api/admin/worker-capability-contract";
const ADMIN_FEATURE_FLAG_GOVERNANCE_PATH: &str = "/api/admin/feature-flag-governance-contract";
const ADMIN_RBAC_ROLES_PATH: &str = "/api/admin/rbac-roles";
const ADMIN_PLATFORM_SETTINGS_PATH: &str = "/api/admin/platform-settings";
const ADMIN_PLATFORM_SETTINGS_RESET_PATH: &str = "/api/admin/platform-settings/reset";
const ADMIN_TOKENS_PATH: &str = "/api/admin/tokens";
const ADMIN_SESSIONS_PATH: &str = "/api/admin/sessions";
const REQUEST_INTAKE_FORM_PREVIEW_PATH: &str = "/api/requests/intake-form";
const REQUEST_LIST_PATH: &str = "/api/requests";
const REQUEST_CREATE_PATH: &str = "/api/requests";
const SECRET_REFERENCES_PATH: &str = "/api/catalog/secret-references";
const POLICY_OUTCOMES_PATH: &str = "/api/catalog/policy-guardrails-contract";
const EVIDENCE_SUMMARY_PATH: &str = "/api/catalog/evidence-redaction-contract";
const OPERATION_RUNS_PATH: &str = "/api/operations/run-state-contract";
const DATACENTER_READINESS_SCORE_PATH: &str = "/api/datacenter/readiness-score-contract";
const DATACENTER_SITE_REPORT_PATH: &str = "/api/datacenter/site-report-contract";
const DATACENTER_FAILING_CHECKS_PATH: &str = "/api/datacenter/failing-checks-contract";
const DATACENTER_CHECK_POWER_PATH: &str = "/api/datacenter/check-power-contract";
const DATACENTER_CHECK_COOLING_PATH: &str = "/api/datacenter/check-cooling-contract";
const DATACENTER_CHECK_RACK_SPACE_PATH: &str = "/api/datacenter/check-rack-space-contract";
const DATACENTER_CHECK_SWITCHPORTS_PATH: &str = "/api/datacenter/check-switchports-contract";
const DATACENTER_FULL_READINESS_PATH: &str = "/api/datacenter/full-readiness-contract";
const DATACENTER_SITES_PATH: &str = "/api/datacenter/sites-contract";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiPathError {
    Empty,
    AbsoluteTarget,
    OutsideApiPrefix,
    Fragment,
    UnsafePathSegment,
}

pub fn same_origin_api_path(path: &str) -> Result<&str, ApiPathError> {
    if path.trim().is_empty() {
        return Err(ApiPathError::Empty);
    }
    if path.contains("://") || path.starts_with("//") {
        return Err(ApiPathError::AbsoluteTarget);
    }
    if path.contains('#') {
        return Err(ApiPathError::Fragment);
    }
    if !path.starts_with(API_PREFIX) {
        return Err(ApiPathError::OutsideApiPrefix);
    }
    Ok(path)
}

fn safe_request_id(request_id: &str) -> Result<&str, ApiPathError> {
    let request_id = request_id.trim();
    if request_id.is_empty() {
        return Err(ApiPathError::Empty);
    }
    if request_id.contains("://")
        || request_id.starts_with("//")
        || request_id.contains('/')
        || request_id.contains('\\')
        || request_id.contains('?')
        || request_id.contains('#')
        || request_id == "."
        || request_id == ".."
        || request_id.contains("..")
        || !request_id
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || matches!(char, '-' | '_'))
    {
        return Err(ApiPathError::UnsafePathSegment);
    }
    Ok(request_id)
}

fn request_lifecycle_path(request_id: &str, suffix: Option<&str>) -> Result<String, ApiPathError> {
    let request_id = safe_request_id(request_id)?;
    let path = match suffix {
        Some(suffix) => format!("/api/requests/{request_id}/{suffix}"),
        None => format!("/api/requests/{request_id}"),
    };
    same_origin_api_path(&path)?;
    Ok(path)
}

pub fn platform_summary_path() -> &'static str {
    PLATFORM_SUMMARY_PATH
}

pub fn request_intake_path() -> &'static str {
    REQUEST_INTAKE_PATH
}

pub fn request_preflight_path() -> &'static str {
    REQUEST_PREFLIGHT_PATH
}

pub fn dry_run_plan_path() -> &'static str {
    DRY_RUN_PLAN_PATH
}

pub fn inventory_resource_overview_path() -> &'static str {
    INVENTORY_RESOURCE_OVERVIEW_PATH
}

pub fn inventory_ownership_risk_path() -> &'static str {
    INVENTORY_OWNERSHIP_RISK_PATH
}

pub fn cluster_capacity_admission_path() -> &'static str {
    CLUSTER_CAPACITY_ADMISSION_PATH
}

pub fn catalog_offerings_path() -> &'static str {
    CATALOG_OFFERINGS_PATH
}

pub fn catalog_recommendations_path() -> &'static str {
    CATALOG_RECOMMENDATIONS_PATH
}

pub fn catalog_request_form_path() -> &'static str {
    CATALOG_REQUEST_FORM_PATH
}

pub fn site_catalog_path() -> &'static str {
    SITE_CATALOG_PATH
}

pub fn approval_decision_readiness_path() -> &'static str {
    APPROVAL_DECISION_READINESS_PATH
}

pub fn activity_operation_queue_path() -> &'static str {
    ACTIVITY_OPERATION_QUEUE_PATH
}

pub fn activity_audit_feed_path() -> &'static str {
    ACTIVITY_AUDIT_FEED_PATH
}

pub fn shift_queue_path() -> &'static str {
    SHIFT_QUEUE_PATH
}

pub fn emergency_change_path() -> &'static str {
    EMERGENCY_CHANGE_PATH
}

pub fn cmdb_file_exchange_path() -> &'static str {
    CMDB_FILE_EXCHANGE_PATH
}

pub fn cmdb_reconciliation_path() -> &'static str {
    CMDB_RECONCILIATION_PATH
}

pub fn cmdb_relationship_graph_path() -> &'static str {
    CMDB_RELATIONSHIP_GRAPH_PATH
}

pub fn evidence_export_retention_path() -> &'static str {
    EVIDENCE_EXPORT_RETENTION_PATH
}

pub fn evidence_compliance_dashboard_path() -> &'static str {
    EVIDENCE_COMPLIANCE_DASHBOARD_PATH
}

pub fn operations_runbook_launch_path() -> &'static str {
    OPERATIONS_RUNBOOK_LAUNCH_PATH
}

pub fn operations_platform_health_path() -> &'static str {
    OPERATIONS_PLATFORM_HEALTH_PATH
}

pub fn admin_worker_capability_path() -> &'static str {
    ADMIN_WORKER_CAPABILITY_PATH
}

pub fn admin_feature_flag_governance_path() -> &'static str {
    ADMIN_FEATURE_FLAG_GOVERNANCE_PATH
}

pub fn admin_rbac_roles_path() -> &'static str {
    ADMIN_RBAC_ROLES_PATH
}

pub fn admin_platform_settings_path() -> &'static str {
    ADMIN_PLATFORM_SETTINGS_PATH
}

pub fn admin_platform_settings_reset_path() -> &'static str {
    ADMIN_PLATFORM_SETTINGS_RESET_PATH
}

pub fn admin_tokens_path() -> &'static str {
    ADMIN_TOKENS_PATH
}

pub fn admin_sessions_path() -> &'static str {
    ADMIN_SESSIONS_PATH
}

/// Builds `/api/admin/tokens/{id}` after validating the id as a single safe
/// URL path segment (rejects traversal, slashes, query/fragment markers).
pub fn admin_token_revoke_path(token_id: &str) -> Result<String, ApiPathError> {
    admin_resource_revoke_path("tokens", token_id)
}

/// Builds `/api/admin/sessions/{id}` after validating the id as a single safe
/// URL path segment (rejects traversal, slashes, query/fragment markers).
pub fn admin_session_revoke_path(session_id: &str) -> Result<String, ApiPathError> {
    admin_resource_revoke_path("sessions", session_id)
}

fn admin_resource_revoke_path(resource: &str, id: &str) -> Result<String, ApiPathError> {
    let id = safe_request_id(id)?;
    let path = format!("/api/admin/{resource}/{id}");
    same_origin_api_path(&path)?;
    Ok(path)
}

pub fn request_intake_form_preview_path() -> &'static str {
    REQUEST_INTAKE_FORM_PREVIEW_PATH
}

pub fn secret_references_path() -> &'static str {
    SECRET_REFERENCES_PATH
}

pub fn policy_outcomes_path() -> &'static str {
    POLICY_OUTCOMES_PATH
}

pub fn evidence_summary_path() -> &'static str {
    EVIDENCE_SUMMARY_PATH
}

pub fn operation_runs_path() -> &'static str {
    OPERATION_RUNS_PATH
}

pub fn datacenter_readiness_score_path() -> &'static str {
    DATACENTER_READINESS_SCORE_PATH
}

pub fn datacenter_site_report_path() -> &'static str {
    DATACENTER_SITE_REPORT_PATH
}

pub fn datacenter_failing_checks_path() -> &'static str {
    DATACENTER_FAILING_CHECKS_PATH
}

pub fn datacenter_check_power_path() -> &'static str {
    DATACENTER_CHECK_POWER_PATH
}

pub fn datacenter_check_cooling_path() -> &'static str {
    DATACENTER_CHECK_COOLING_PATH
}

pub fn datacenter_check_rack_space_path() -> &'static str {
    DATACENTER_CHECK_RACK_SPACE_PATH
}

pub fn datacenter_check_switchports_path() -> &'static str {
    DATACENTER_CHECK_SWITCHPORTS_PATH
}

pub fn datacenter_full_readiness_path() -> &'static str {
    DATACENTER_FULL_READINESS_PATH
}

pub fn datacenter_sites_path() -> &'static str {
    DATACENTER_SITES_PATH
}

pub fn boundary_status_path() -> &'static str {
    BOUNDARY_STATUS_PATH
}

pub fn platform_status_path() -> &'static str {
    PLATFORM_STATUS_PATH
}

pub fn platform_health_path() -> &'static str {
    PLATFORM_HEALTH_PATH
}

pub fn auth_status_path() -> &'static str {
    AUTH_STATUS_PATH
}

const AUTH_LOGIN_PATH: &str = "/api/auth/login";
const AUTH_LOGOUT_PATH: &str = "/api/auth/logout";
const AUTH_LOCAL_LOGIN_PATH: &str = "/api/auth/local/login";
const AUTH_LOCAL_LOGOUT_PATH: &str = "/api/auth/local/logout";

pub fn auth_login_path() -> &'static str {
    AUTH_LOGIN_PATH
}

pub fn auth_logout_path() -> &'static str {
    AUTH_LOGOUT_PATH
}

pub fn auth_local_login_path() -> &'static str {
    AUTH_LOCAL_LOGIN_PATH
}

pub fn auth_local_logout_path() -> &'static str {
    AUTH_LOCAL_LOGOUT_PATH
}

pub fn auth_session_path() -> &'static str {
    AUTH_SESSION_PATH
}

pub fn request_list_path() -> &'static str {
    REQUEST_LIST_PATH
}

pub fn request_create_path() -> &'static str {
    REQUEST_CREATE_PATH
}

pub fn request_detail_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, None)
}

pub fn request_validate_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("validate"))
}

pub fn request_plan_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("plan"))
}

pub fn request_approve_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("approve"))
}

pub fn request_reject_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("reject"))
}

pub fn request_cancel_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("cancel"))
}

pub fn request_lock_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("lock"))
}

pub fn request_execute_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("execute"))
}

pub fn request_verify_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("verify"))
}

/// Read path for the persisted audit trail of a single request
/// (`GET /api/requests/{id}/audit`). Gated server-side on the `audit`
/// permission; carries no mutation.
pub fn request_audit_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("audit"))
}

pub fn request_evidence_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("evidence"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_lifecycle_paths_match_api_contract() {
        let request_id = "REQ-123";

        assert_eq!(
            request_detail_path(request_id),
            Ok("/api/requests/REQ-123".to_string())
        );
        assert_eq!(
            request_validate_path(request_id),
            Ok("/api/requests/REQ-123/validate".to_string())
        );
        assert_eq!(
            request_plan_path(request_id),
            Ok("/api/requests/REQ-123/plan".to_string())
        );
        assert_eq!(
            request_approve_path(request_id),
            Ok("/api/requests/REQ-123/approve".to_string())
        );
        assert_eq!(
            request_reject_path(request_id),
            Ok("/api/requests/REQ-123/reject".to_string())
        );
        assert_eq!(
            request_cancel_path(request_id),
            Ok("/api/requests/REQ-123/cancel".to_string())
        );
        assert_eq!(
            request_lock_path(request_id),
            Ok("/api/requests/REQ-123/lock".to_string())
        );
        assert_eq!(
            request_execute_path(request_id),
            Ok("/api/requests/REQ-123/execute".to_string())
        );
        assert_eq!(
            request_verify_path(request_id),
            Ok("/api/requests/REQ-123/verify".to_string())
        );
        assert_eq!(
            request_audit_path(request_id),
            Ok("/api/requests/REQ-123/audit".to_string())
        );
        assert_eq!(
            request_evidence_path(request_id),
            Ok("/api/requests/REQ-123/evidence".to_string())
        );
    }

    #[test]
    fn auth_paths_match_api_contract() {
        assert_eq!(auth_status_path(), "/api/auth/status");
        assert_eq!(auth_session_path(), "/api/auth/session");
        assert_ne!(auth_status_path(), auth_session_path());
    }

    #[test]
    fn local_auth_paths_match_api_contract() {
        assert_eq!(auth_local_login_path(), "/api/auth/local/login");
        assert_eq!(auth_local_logout_path(), "/api/auth/local/logout");
        assert_ne!(auth_local_login_path(), auth_local_logout_path());
        assert_ne!(auth_local_login_path(), auth_login_path());
        assert_ne!(auth_local_logout_path(), auth_logout_path());
    }

    #[test]
    fn admin_platform_settings_paths_match_api_contract() {
        assert_eq!(
            admin_platform_settings_path(),
            "/api/admin/platform-settings"
        );
        assert_eq!(
            admin_platform_settings_reset_path(),
            "/api/admin/platform-settings/reset"
        );
        assert_ne!(
            admin_platform_settings_path(),
            admin_platform_settings_reset_path()
        );
    }

    #[test]
    fn admin_token_and_session_paths_match_api_contract() {
        assert_eq!(admin_tokens_path(), "/api/admin/tokens");
        assert_eq!(admin_sessions_path(), "/api/admin/sessions");
        assert_eq!(
            admin_token_revoke_path("3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b"),
            Ok("/api/admin/tokens/3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b".to_string())
        );
        assert_eq!(
            admin_session_revoke_path("3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b"),
            Ok("/api/admin/sessions/3f2b8d44-9c1a-4e5f-8a2b-1c9d3e4f5a6b".to_string())
        );
    }

    #[test]
    fn admin_revoke_paths_reject_unsafe_ids() {
        for id in [
            "",
            "../tokens",
            "id/extra",
            r"id\extra",
            "id?x=1",
            "id#frag",
            "https://evil.test/id",
            "//evil.test",
            "..",
        ] {
            assert!(
                admin_token_revoke_path(id).is_err(),
                "{id} must be rejected"
            );
            assert!(
                admin_session_revoke_path(id).is_err(),
                "{id} must be rejected"
            );
        }
    }

    #[test]
    fn request_lifecycle_paths_reject_unsafe_request_ids() {
        for request_id in [
            "",
            "https://example.test/request",
            "//example.test/request",
            "REQ/123",
            r"REQ\123",
            "../REQ-123",
            "REQ 123",
            "REQ%2F123",
            "REQ-123?stage=validate",
            "REQ-123#validate",
        ] {
            assert!(request_detail_path(request_id).is_err());
        }
    }
}
