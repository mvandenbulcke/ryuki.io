pub const API_PREFIX: &str = "/api/";
const BOUNDARY_STATUS_PATH: &str = "/api/boundary/status";
const PLATFORM_STATUS_PATH: &str = "/api/platform/status";
const PLATFORM_HEALTH_PATH: &str = "/api/platform/health";
const AUTH_STATUS_PATH: &str = "/api/auth/status";
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
const REQUEST_INTAKE_FORM_PREVIEW_PATH: &str = "/api/requests/intake-form";
const REQUEST_LIST_PATH: &str = "/api/requests";
const REQUEST_CREATE_PATH: &str = "/api/requests";
const REQUEST_DETAIL_PATH: &str = "/api/requests/detail";
const REQUEST_VALIDATE_PATH: &str = "/api/requests/validate";
const REQUEST_PLAN_PATH: &str = "/api/requests/plan";
const REQUEST_APPROVE_PATH: &str = "/api/requests/approve";
const REQUEST_LOCK_PATH: &str = "/api/requests/lock";
const REQUEST_EXECUTE_PATH: &str = "/api/requests/execute";
const REQUEST_VERIFY_PATH: &str = "/api/requests/verify";
const SECRET_REFERENCES_PATH: &str = "/api/catalog/secret-references";
const POLICY_OUTCOMES_PATH: &str = "/api/catalog/policy-guardrails-contract";
const EVIDENCE_SUMMARY_PATH: &str = "/api/catalog/evidence-redaction-contract";
const OPERATION_RUNS_PATH: &str = "/api/operations/run-state-contract";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiPathError {
    Empty,
    AbsoluteTarget,
    OutsideApiPrefix,
    Fragment,
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

pub fn auth_login_path() -> &'static str {
    AUTH_LOGIN_PATH
}

pub fn auth_logout_path() -> &'static str {
    AUTH_LOGOUT_PATH
}

pub fn auth_session_path() -> &'static str {
    AUTH_STATUS_PATH
}

pub fn request_list_path() -> &'static str {
    REQUEST_LIST_PATH
}

pub fn request_create_path() -> &'static str {
    REQUEST_CREATE_PATH
}

pub fn request_detail_path() -> &'static str {
    REQUEST_DETAIL_PATH
}

pub fn request_validate_path() -> &'static str {
    REQUEST_VALIDATE_PATH
}

pub fn request_plan_path() -> &'static str {
    REQUEST_PLAN_PATH
}

pub fn request_approve_path() -> &'static str {
    REQUEST_APPROVE_PATH
}

pub fn request_lock_path() -> &'static str {
    REQUEST_LOCK_PATH
}

pub fn request_execute_path() -> &'static str {
    REQUEST_EXECUTE_PATH
}

pub fn request_verify_path() -> &'static str {
    REQUEST_VERIFY_PATH
}
