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
const APPROVALS_PENDING_PATH: &str = "/api/approvals/pending";
const NOTIFICATIONS_PATH: &str = "/api/notifications";
const NOTIFICATIONS_UNREAD_COUNT_PATH: &str = "/api/notifications/unread-count";
const NOTIFICATIONS_READ_ALL_PATH: &str = "/api/notifications/read-all";
const ACTIVITY_OPERATION_QUEUE_PATH: &str = "/api/operations/activity-queue-contract";
/// Global, newest-first governance audit feed across all requests.
const ACTIVITY_AUDIT_FEED_PATH: &str = "/api/activity/audit";
const SHIFT_QUEUE_PATH: &str = "/api/operations/shift-queue-contract";
const EMERGENCY_CHANGE_PATH: &str = "/api/operations/emergency-change-contract";
const CMDB_FILE_EXCHANGE_PATH: &str = "/api/integrations/servicenow/cmdb-file-contract";
const CMDB_RECONCILIATION_PATH: &str = "/api/cmdb/reconciliation-contract";
const CMDB_RELATIONSHIP_GRAPH_PATH: &str = "/api/cmdb/relationship-graph-contract";
/// Live CMDB engine actions (dry-run executors): import preview, export, and
/// reconciliation. Unlike the `*-contract` paths above (read-only metadata),
/// these back the admin-gated action buttons in the CMDB workspace.
const CMDB_IMPORT_PATH: &str = "/api/cmdb/import";
const CMDB_EXPORT_PATH: &str = "/api/cmdb/export";
const CMDB_RECONCILE_PATH: &str = "/api/cmdb/reconcile";
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

pub fn approvals_pending_path() -> &'static str {
    APPROVALS_PENDING_PATH
}

pub fn notifications_path() -> &'static str {
    NOTIFICATIONS_PATH
}

pub fn notifications_unread_count_path() -> &'static str {
    NOTIFICATIONS_UNREAD_COUNT_PATH
}

pub fn notifications_read_all_path() -> &'static str {
    NOTIFICATIONS_READ_ALL_PATH
}

/// Builds `/api/notifications/{id}/read` after validating the id as a single
/// safe URL path segment (rejects traversal, slashes, query/fragment markers).
/// Mirrors `admin_agent_approve_path` but carries the `read` suffix; backs the
/// per-item mark-read action from the notification bell.
pub fn notifications_read_path(id: &str) -> Result<String, ApiPathError> {
    let id = safe_request_id(id)?;
    let path = format!("/api/notifications/{id}/read");
    same_origin_api_path(&path)?;
    Ok(path)
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

pub fn cmdb_import_path() -> &'static str {
    CMDB_IMPORT_PATH
}

pub fn cmdb_export_path() -> &'static str {
    CMDB_EXPORT_PATH
}

pub fn cmdb_reconcile_path() -> &'static str {
    CMDB_RECONCILE_PATH
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

/// Sort keys the request-list endpoint accepts. Mirrors the API contract
/// (commit fa1df10): `GET /api/requests?sort=<key>`. The portal only ever
/// emits a key from this allowlist, so an out-of-range value can never reach
/// the upstream.
pub const REQUEST_LIST_SORT_KEYS: &[&str] = &[
    "created_at",
    "updated_at",
    "name",
    "status",
    "site",
    "request_type",
];

/// Sort directions the request-list endpoint accepts (`direction=asc|desc`).
pub const REQUEST_LIST_SORT_DIRECTIONS: &[&str] = &["asc", "desc"];

/// Faceted filter/sort/pagination inputs for `GET /api/requests`. Every field
/// is optional; an all-`None`/empty value reproduces the unfiltered default
/// list (backward compatible with the pre-facet behavior).
///
/// String facets (`status`, `site`, `environment`, `request_type`,
/// `created_by`, `q`) carry caller-supplied values and are percent-encoded
/// when serialized. `sort`/`direction` are validated against the API allowlists
/// and silently dropped when out of range, so a malformed value degrades to the
/// default ordering rather than reaching the upstream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestListQuery {
    pub status: Option<String>,
    pub site: Option<String>,
    pub environment: Option<String>,
    pub request_type: Option<String>,
    pub created_by: Option<String>,
    pub q: Option<String>,
    pub sort: Option<String>,
    pub direction: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

impl RequestListQuery {
    /// True when no facet narrows the list — the unfiltered default view.
    pub fn is_empty(&self) -> bool {
        self.normalized_status().is_none()
            && self.normalized_site().is_none()
            && self.normalized_environment().is_none()
            && self.normalized_request_type().is_none()
            && self.normalized_created_by().is_none()
            && self.normalized_q().is_none()
            && self.normalized_sort().is_none()
            && self.normalized_direction().is_none()
            && self.limit.is_none()
            && self.offset.is_none()
    }

    fn normalized_status(&self) -> Option<&str> {
        non_empty(self.status.as_deref())
    }

    fn normalized_site(&self) -> Option<&str> {
        non_empty(self.site.as_deref())
    }

    fn normalized_environment(&self) -> Option<&str> {
        non_empty(self.environment.as_deref())
    }

    fn normalized_request_type(&self) -> Option<&str> {
        non_empty(self.request_type.as_deref())
    }

    fn normalized_created_by(&self) -> Option<&str> {
        non_empty(self.created_by.as_deref())
    }

    fn normalized_q(&self) -> Option<&str> {
        non_empty(self.q.as_deref())
    }

    fn normalized_sort(&self) -> Option<&str> {
        non_empty(self.sort.as_deref()).filter(|v| REQUEST_LIST_SORT_KEYS.contains(v))
    }

    fn normalized_direction(&self) -> Option<&str> {
        non_empty(self.direction.as_deref()).filter(|v| REQUEST_LIST_SORT_DIRECTIONS.contains(v))
    }

    /// Builds the `?key=value&...` suffix for the request-list path. Returns an
    /// empty string when no facet is active so the path stays byte-identical to
    /// the default list endpoint. Reserved characters in caller-supplied values
    /// are percent-encoded; `sort`/`direction` outside the allowlists are
    /// dropped.
    pub fn to_query_string(&self) -> String {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        if let Some(status) = self.normalized_status() {
            pairs.push(("status", percent_encode_query_value(status)));
        }
        if let Some(site) = self.normalized_site() {
            pairs.push(("site", percent_encode_query_value(site)));
        }
        if let Some(environment) = self.normalized_environment() {
            pairs.push(("environment", percent_encode_query_value(environment)));
        }
        if let Some(request_type) = self.normalized_request_type() {
            pairs.push(("request_type", percent_encode_query_value(request_type)));
        }
        if let Some(created_by) = self.normalized_created_by() {
            pairs.push(("created_by", percent_encode_query_value(created_by)));
        }
        if let Some(q) = self.normalized_q() {
            pairs.push(("q", percent_encode_query_value(q)));
        }
        if let Some(sort) = self.normalized_sort() {
            pairs.push(("sort", sort.to_string()));
        }
        if let Some(direction) = self.normalized_direction() {
            pairs.push(("direction", direction.to_string()));
        }
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(offset) = self.offset {
            pairs.push(("offset", offset.to_string()));
        }
        if pairs.is_empty() {
            return String::new();
        }
        let mut out = String::from("?");
        for (index, (key, value)) in pairs.iter().enumerate() {
            if index > 0 {
                out.push('&');
            }
            out.push_str(key);
            out.push('=');
            out.push_str(value);
        }
        out
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

/// Percent-encodes every byte that is not an RFC 3986 unreserved character so a
/// caller-supplied facet value (e.g. a search term with spaces or `&`) cannot
/// inject extra query parameters or break the URL. Mirrors the download
/// encoder in `request_detail.rs`.
fn percent_encode_query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let b = *byte;
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            encoded.push(b as char);
        } else {
            encoded.push('%');
            encoded.push(
                char::from_digit((b >> 4) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
            encoded.push(
                char::from_digit((b & 0x0f) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
        }
    }
    encoded
}

/// Appends the validated facet query string to the request-list path. With an
/// empty query the result equals `request_list_path()`, keeping the default
/// (unfiltered) request identical to the pre-facet behavior.
pub fn request_list_path_with_query(query: &RequestListQuery) -> String {
    format!("{}{}", request_list_path(), query.to_query_string())
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

// Post-completion governed lifecycle (Theme 8). Each is a bodyless POST, gated
// server-side on the `execute` permission, valid only from its predecessor
// status: protect from Completed, publish from Protecting, retire from
// Operational.
pub fn request_protect_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("protect"))
}

pub fn request_publish_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("publish"))
}

pub fn request_retire_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("retire"))
}

const INTEGRATIONS_PATH: &str = "/api/integrations";

pub fn integrations_path() -> &'static str {
    INTEGRATIONS_PATH
}

const ADMIN_AGENTS_PATH: &str = "/api/admin/agents";

pub fn admin_agents_path() -> &'static str {
    ADMIN_AGENTS_PATH
}

/// Builds `/api/admin/agents/{id}/approve` after validating the id as a single
/// safe URL path segment (rejects traversal, slashes, query/fragment markers).
/// Mirrors `admin_resource_revoke_path` but carries the static `approve` suffix.
pub fn admin_agent_approve_path(agent_id: &str) -> Result<String, ApiPathError> {
    let agent_id = safe_request_id(agent_id)?;
    let path = format!("/api/admin/agents/{agent_id}/approve");
    same_origin_api_path(&path)?;
    Ok(path)
}

/// Builds `/api/admin/agents/{id}/revoke` after validating the id as a single safe
/// URL path segment. Mirrors `admin_agent_approve_path` with the `revoke` suffix.
pub fn admin_agent_revoke_path(agent_id: &str) -> Result<String, ApiPathError> {
    let agent_id = safe_request_id(agent_id)?;
    let path = format!("/api/admin/agents/{agent_id}/revoke");
    same_origin_api_path(&path)?;
    Ok(path)
}

fn safe_integration_id(integration_id: &str) -> Result<&str, ApiPathError> {
    let integration_id = integration_id.trim();
    if integration_id.is_empty() {
        return Err(ApiPathError::Empty);
    }
    if integration_id.contains("://")
        || integration_id.starts_with("//")
        || integration_id.contains('/')
        || integration_id.contains('\\')
        || integration_id.contains('?')
        || integration_id.contains('#')
        || integration_id == "."
        || integration_id == ".."
        || integration_id.contains("..")
        || !integration_id
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || matches!(char, '-' | '_'))
    {
        return Err(ApiPathError::UnsafePathSegment);
    }
    Ok(integration_id)
}

pub fn integration_id_path(id: &str) -> Result<String, ApiPathError> {
    let id = safe_integration_id(id)?;
    let path = format!("/api/integrations/{id}");
    same_origin_api_path(&path)?;
    Ok(path)
}

pub fn integration_test_path(id: &str) -> Result<String, ApiPathError> {
    let id = safe_integration_id(id)?;
    let path = format!("/api/integrations/{id}/test");
    same_origin_api_path(&path)?;
    Ok(path)
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

/// Builds `/api/requests/{id}/execution-job` — the read endpoint for the
/// execution-agent job dispatched for a request.
pub fn request_execution_job_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("execution-job"))
}

/// Builds `/api/requests/{id}/approve-live-apply` — the admin-gated endpoint
/// that mints a CP-signed LiveApply grant from the request's completed LivePlan.
pub fn request_approve_live_apply_path(request_id: &str) -> Result<String, ApiPathError> {
    request_lifecycle_path(request_id, Some("approve-live-apply"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approvals_pending_path_matches_api_contract() {
        assert_eq!(approvals_pending_path(), "/api/approvals/pending");
    }

    #[test]
    fn notifications_path_matches_api_contract() {
        assert_eq!(notifications_path(), "/api/notifications");
    }

    #[test]
    fn notifications_unread_count_path_matches_api_contract() {
        assert_eq!(
            notifications_unread_count_path(),
            "/api/notifications/unread-count"
        );
    }

    #[test]
    fn notifications_read_all_path_matches_api_contract() {
        assert_eq!(notifications_read_all_path(), "/api/notifications/read-all");
    }

    #[test]
    fn notifications_read_path_matches_api_contract_and_rejects_unsafe_ids() {
        assert_eq!(
            notifications_read_path("pn-7c9e6679").expect("safe id must build"),
            "/api/notifications/pn-7c9e6679/read"
        );
        // Traversal, slashes, and query markers never build a path.
        assert!(notifications_read_path("").is_err());
        assert!(notifications_read_path("..").is_err());
        assert!(notifications_read_path("a/b").is_err());
        assert!(notifications_read_path("pn-1?x=1").is_err());
    }

    #[test]
    fn cmdb_action_paths_match_api_contract() {
        assert_eq!(cmdb_import_path(), "/api/cmdb/import");
        assert_eq!(cmdb_export_path(), "/api/cmdb/export");
        assert_eq!(cmdb_reconcile_path(), "/api/cmdb/reconcile");
    }

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
            request_protect_path(request_id),
            Ok("/api/requests/REQ-123/protect".to_string())
        );
        assert_eq!(
            request_publish_path(request_id),
            Ok("/api/requests/REQ-123/publish".to_string())
        );
        assert_eq!(
            request_retire_path(request_id),
            Ok("/api/requests/REQ-123/retire".to_string())
        );
        assert_eq!(
            request_audit_path(request_id),
            Ok("/api/requests/REQ-123/audit".to_string())
        );
        assert_eq!(
            request_evidence_path(request_id),
            Ok("/api/requests/REQ-123/evidence".to_string())
        );
        assert_eq!(
            request_execution_job_path(request_id),
            Ok("/api/requests/REQ-123/execution-job".to_string())
        );
        assert_eq!(
            request_approve_live_apply_path(request_id),
            Ok("/api/requests/REQ-123/approve-live-apply".to_string())
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
    fn integrations_path_value_is_correct() {
        assert_eq!(integrations_path(), "/api/integrations");
    }

    #[test]
    fn safe_integration_id_rejects_unsafe() {
        // T6 from the test plan — valid ic-* style id is accepted
        assert!(
            integration_id_path("ic-vmware-abc123").is_ok(),
            "ic-vmware-abc123 must be accepted"
        );
        assert_eq!(
            integration_id_path("ic-vmware-abc123"),
            Ok("/api/integrations/ic-vmware-abc123".to_string())
        );
        assert_eq!(
            integration_test_path("ic-vmware-abc123"),
            Ok("/api/integrations/ic-vmware-abc123/test".to_string())
        );
        // Unsafe ids must be rejected
        for id in ["", "../admin", "a/b", "a?b=c", "a#b", "a\\b", ".."] {
            assert!(
                integration_id_path(id).is_err(),
                "{id:?} must be rejected by integration_id_path"
            );
            assert!(
                integration_test_path(id).is_err(),
                "{id:?} must be rejected by integration_test_path"
            );
        }
    }

    #[test]
    fn empty_request_list_query_reproduces_default_path() {
        let query = RequestListQuery::default();
        assert!(query.is_empty());
        assert_eq!(query.to_query_string(), "");
        assert_eq!(request_list_path_with_query(&query), "/api/requests");
    }

    #[test]
    fn blank_and_whitespace_facets_are_dropped() {
        let query = RequestListQuery {
            status: Some(String::new()),
            site: Some("   ".to_string()),
            q: Some("\t".to_string()),
            ..Default::default()
        };
        assert!(query.is_empty());
        assert_eq!(request_list_path_with_query(&query), "/api/requests");
    }

    #[test]
    fn request_list_query_serializes_facets_in_canonical_order() {
        let query = RequestListQuery {
            status: Some("approved".to_string()),
            site: Some("ams1".to_string()),
            q: Some("web".to_string()),
            sort: Some("name".to_string()),
            direction: Some("asc".to_string()),
            limit: Some(25),
            offset: Some(50),
            ..Default::default()
        };
        assert!(!query.is_empty());
        assert_eq!(
            query.to_query_string(),
            "?status=approved&site=ams1&q=web&sort=name&direction=asc&limit=25&offset=50"
        );
        assert_eq!(
            request_list_path_with_query(&query),
            "/api/requests?status=approved&site=ams1&q=web&sort=name&direction=asc&limit=25&offset=50"
        );
    }

    #[test]
    fn request_list_query_new_facets_serialize_in_canonical_order() {
        let query = RequestListQuery {
            environment: Some("prod".to_string()),
            request_type: Some("server deploy".to_string()),
            created_by: Some("alice@example.com".to_string()),
            ..Default::default()
        };
        assert!(!query.is_empty());
        assert_eq!(
            query.to_query_string(),
            "?environment=prod&request_type=server%20deploy&created_by=alice%40example.com"
        );
    }

    #[test]
    fn request_list_query_all_facets_canonical_order() {
        let query = RequestListQuery {
            status: Some("approved".to_string()),
            site: Some("ams1".to_string()),
            environment: Some("prod".to_string()),
            request_type: Some("server".to_string()),
            created_by: Some("bob".to_string()),
            q: Some("web".to_string()),
            sort: Some("name".to_string()),
            direction: Some("asc".to_string()),
            limit: None,
            offset: None,
        };
        assert!(!query.is_empty());
        assert_eq!(
            query.to_query_string(),
            "?status=approved&site=ams1&environment=prod&request_type=server&created_by=bob&q=web&sort=name&direction=asc"
        );
    }

    #[test]
    fn blank_new_facets_are_dropped() {
        let query = RequestListQuery {
            environment: Some("   ".to_string()),
            request_type: Some(String::new()),
            created_by: Some("\t".to_string()),
            ..Default::default()
        };
        assert!(query.is_empty());
        assert_eq!(query.to_query_string(), "");
    }

    #[test]
    fn request_list_query_percent_encodes_unsafe_facet_values() {
        // A search term with a space and an `&` must not inject extra params.
        let query = RequestListQuery {
            q: Some("web & db".to_string()),
            ..Default::default()
        };
        assert_eq!(query.to_query_string(), "?q=web%20%26%20db");
    }

    #[test]
    fn request_list_query_drops_out_of_range_sort_and_direction() {
        let query = RequestListQuery {
            sort: Some("'; DROP TABLE requests; --".to_string()),
            direction: Some("sideways".to_string()),
            ..Default::default()
        };
        // Invalid sort/direction are silently dropped — they never reach upstream.
        assert!(query.is_empty());
        assert_eq!(query.to_query_string(), "");
    }

    #[test]
    fn request_list_query_keeps_only_valid_sort_when_direction_invalid() {
        let query = RequestListQuery {
            sort: Some("status".to_string()),
            direction: Some("nope".to_string()),
            ..Default::default()
        };
        assert_eq!(query.to_query_string(), "?sort=status");
    }

    #[test]
    fn request_list_sort_allowlists_match_api_contract() {
        assert_eq!(
            REQUEST_LIST_SORT_KEYS,
            &[
                "created_at",
                "updated_at",
                "name",
                "status",
                "site",
                "request_type"
            ]
        );
        assert_eq!(REQUEST_LIST_SORT_DIRECTIONS, &["asc", "desc"]);
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
