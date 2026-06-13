use crate::api::{
    activity_operation_queue_path, admin_feature_flag_governance_path,
    admin_worker_capability_path, catalog_offerings_path, catalog_request_form_path,
    cmdb_reconciliation_path, cmdb_relationship_graph_path, dry_run_plan_path,
    evidence_compliance_dashboard_path, evidence_export_retention_path,
    inventory_ownership_risk_path, inventory_resource_overview_path,
    operations_platform_health_path, operations_runbook_launch_path, request_intake_path,
    shift_queue_path,
};
use crate::models::AuthSession;

pub type ApiPathFactory = fn() -> &'static str;
pub const WORKSPACE_API_BOUNDARY: &str = "same-origin-platform-api";
pub const WORKSPACE_EXECUTION_MODE: &str = "static-dry-run";

pub struct NavItem {
    pub label: &'static str,
    pub href: &'static str,
    pub required_role: Option<&'static str>,
}

pub struct WorkspaceDefinition {
    pub id: &'static str,
    pub href: &'static str,
    pub label: &'static str,
    pub title: &'static str,
    pub badge: &'static str,
    pub badge_class: &'static str,
    pub description: &'static str,
    pub points: &'static [&'static str],
    pub api_boundary: &'static str,
    pub execution_mode: &'static str,
    pub primary_api_path: ApiPathFactory,
    pub secondary_api_path: ApiPathFactory,
    pub required_role: Option<&'static str>,
}

/// Mirror of ryuki-engine `check_permission` (sources/ryuki-engine/src/auth.rs
/// `get_rbac_roles` / `check_permission`): a capability is held if any of the
/// session roles grants it, or the session holds the `admin` superuser perm.
/// The portal must not depend on ryuki-engine, so this role->permission table
/// is duplicated here; keep it in lockstep with `get_rbac_roles` so drift is
/// reviewable.
pub fn session_can(session: &AuthSession, capability: &str) -> bool {
    fn perms_for(role: &str) -> &'static [&'static str] {
        match role {
            "PlatformAdmin" => &["admin", "approve", "audit"],
            "BreakGlassAdmin" => &["admin", "audit"],
            "DatacenterApprover" => &["approve", "audit"],
            "VMwareOperator"
            | "HyperVOperator"
            | "ProxmoxOperator"
            | "WintelLinuxOperator"
            | "BackupOperator"
            | "MonitoringOperator" => &["execute", "audit"],
            "ServiceDesk" => &["request", "audit"],
            "Auditor" => &["audit"],
            "Requester" => &["request"],
            _ => &[],
        }
    }
    let mut held: bool = false;
    let mut is_admin = false;
    for role in &session.roles {
        for p in perms_for(role) {
            if *p == "admin" {
                is_admin = true;
            }
            if *p == capability {
                held = true;
            }
        }
    }
    is_admin || held
}

pub fn role_satisfies(session: &AuthSession, required_role: Option<&str>) -> bool {
    let Some(required) = required_role else {
        return true;
    };
    if required == "Requester" {
        return !session.roles.is_empty();
    }
    if session.roles.iter().any(|r| r == required) {
        return true;
    }
    if session.roles.iter().any(|r| r == "PlatformAdmin") {
        return true;
    }
    false
}

pub const PRIMARY_NAV_ITEMS: &[NavItem] = &[
    NavItem {
        label: "Dashboard",
        href: "/",
        required_role: None,
    },
    NavItem {
        label: "Catalog",
        href: "/catalog",
        required_role: Some("Requester"),
    },
    NavItem {
        label: "Requests",
        href: "/requests",
        required_role: Some("Requester"),
    },
    NavItem {
        label: "Activity",
        href: "/activity",
        required_role: Some("Requester"),
    },
    NavItem {
        label: "Inventory",
        href: "/inventory",
        required_role: Some("ServiceDesk"),
    },
    NavItem {
        label: "CMDB",
        href: "/cmdb",
        required_role: Some("ServiceDesk"),
    },
    NavItem {
        label: "Evidence",
        href: "/evidence",
        required_role: Some("Auditor"),
    },
    NavItem {
        label: "Operations",
        href: "/operations",
        required_role: Some("ServiceDesk"),
    },
    NavItem {
        label: "Admin",
        href: "/admin",
        required_role: Some("PlatformAdmin"),
    },
];

/// Route-derived nav highlighting: an item is active when the current
/// location is the item's path or one of its sub-paths. The dashboard at
/// `/` only matches exactly, so it never shadows the other workspaces.
pub fn nav_item_is_active(current_path: &str, href: &str) -> bool {
    let current = if current_path.len() > 1 {
        current_path.trim_end_matches('/')
    } else {
        current_path
    };
    if href == "/" {
        return current == "/";
    }
    current == href
        || current
            .strip_prefix(href)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Matches a requested path against the portal route table and returns the
/// `(active_route, workspace_id)` pair, or `None` when the path is not a
/// known portal route. Request detail ids are restricted to URL-safe
/// characters so client-controlled paths can never smuggle markup or
/// scheme-relative redirects into the route-state snapshot.
pub fn match_portal_route(path: &str) -> Option<(String, &'static str)> {
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("://")
        || path.contains('#')
        || path.contains('?')
    {
        return None;
    }
    let normalized = if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    };
    let workspace = match normalized {
        "/" => "dashboard",
        "/catalog" => "catalog",
        "/requests" | "/requests/new" => "requests",
        "/activity" => "activity",
        "/inventory" => "inventory",
        "/cmdb" => "cmdb",
        "/evidence" => "evidence",
        "/operations" => "operations",
        "/admin" => "admin",
        _ => {
            let request_id = normalized.strip_prefix("/requests/")?;
            let id_is_safe = !request_id.is_empty()
                && request_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            return id_is_safe.then(|| (normalized.to_string(), "requests"));
        }
    };
    Some((normalized.to_string(), workspace))
}

pub const PRIMARY_WORKSPACES: &[WorkspaceDefinition] = &[
    WorkspaceDefinition {
        id: "catalog",
        href: "/catalog",
        label: "Catalog",
        title: "Catalog workspace",
        badge: "Static/dry-run",
        badge_class: "badge neutral",
        description: "Build, maintain, protect, observe, operate, and retire offerings stay tied to safe request contracts and approval gates.",
        points: &[
            "Offering readiness",
            "Request form alignment",
            "Same-origin API only",
        ],
        api_boundary: WORKSPACE_API_BOUNDARY,
        execution_mode: WORKSPACE_EXECUTION_MODE,
        primary_api_path: catalog_offerings_path,
        secondary_api_path: catalog_request_form_path,
        required_role: Some("Requester"),
    },
    WorkspaceDefinition {
        id: "requests",
        href: "/requests",
        label: "Requests",
        title: "Requests workspace",
        badge: "Preflight",
        badge_class: "badge warn",
        description: "Intake, validation, approval, dry-run plan, timeline, and evidence state remain review-only until every gate passes.",
        points: &[
            "Duplicate detection",
            "Approval readiness",
            "Execution blocked by default",
        ],
        api_boundary: WORKSPACE_API_BOUNDARY,
        execution_mode: WORKSPACE_EXECUTION_MODE,
        primary_api_path: request_intake_path,
        secondary_api_path: dry_run_plan_path,
        required_role: Some("Requester"),
    },
    WorkspaceDefinition {
        id: "activity",
        href: "/activity",
        label: "Activity",
        title: "Activity workspace",
        badge: "Queue state",
        badge_class: "badge neutral",
        description: "Operation queue, child operations, locks, retries, and blocked reasons are summarized for handover without mutation.",
        points: &[
            "Retry-safe state",
            "Shift handover",
            "Blocked reason review",
        ],
        api_boundary: WORKSPACE_API_BOUNDARY,
        execution_mode: WORKSPACE_EXECUTION_MODE,
        primary_api_path: activity_operation_queue_path,
        secondary_api_path: shift_queue_path,
        required_role: Some("Requester"),
    },
    WorkspaceDefinition {
        id: "inventory",
        href: "/inventory",
        label: "Inventory",
        title: "Inventory workspace",
        badge: "Read-only",
        badge_class: "badge stale",
        description: "Sites, assets, clusters, networks, backup, monitoring, and CMDB status use freshness and coverage summaries before planning.",
        points: &[
            "Capacity context",
            "Coverage state",
            "Stale data blocks execution",
        ],
        api_boundary: WORKSPACE_API_BOUNDARY,
        execution_mode: WORKSPACE_EXECUTION_MODE,
        primary_api_path: inventory_resource_overview_path,
        secondary_api_path: inventory_ownership_risk_path,
        required_role: Some("ServiceDesk"),
    },
    WorkspaceDefinition {
        id: "cmdb",
        href: "/cmdb",
        label: "CMDB",
        title: "CMDB workspace",
        badge: "File exchange",
        badge_class: "badge warn",
        description: "Import preview, update export, CI reconciliation, relationship graph, and accepted or rejected counts stay controlled.",
        points: &[
            "Mapping preview",
            "Reconciliation state",
            "Relationship quality",
        ],
        api_boundary: WORKSPACE_API_BOUNDARY,
        execution_mode: WORKSPACE_EXECUTION_MODE,
        primary_api_path: cmdb_reconciliation_path,
        secondary_api_path: cmdb_relationship_graph_path,
        required_role: Some("ServiceDesk"),
    },
    WorkspaceDefinition {
        id: "evidence",
        href: "/evidence",
        label: "Evidence",
        title: "Evidence workspace",
        badge: "Redaction",
        badge_class: "badge warn",
        description: "Evidence packs, export readiness, retention state, and audit search summaries stay redacted before any release.",
        points: &[
            "Manifest status",
            "Export readiness",
            "Retention policy",
        ],
        api_boundary: WORKSPACE_API_BOUNDARY,
        execution_mode: WORKSPACE_EXECUTION_MODE,
        primary_api_path: evidence_export_retention_path,
        secondary_api_path: evidence_compliance_dashboard_path,
        required_role: Some("Auditor"),
    },
    WorkspaceDefinition {
        id: "operations",
        href: "/operations",
        label: "Operations",
        title: "Operations workspace",
        badge: "Runbooks",
        badge_class: "badge neutral",
        description: "Runbooks, incident context, shift queue, emergency change, and platform health views stay dry-run until approved.",
        points: &[
            "Incident context",
            "Platform health",
            "Emergency change gate",
        ],
        api_boundary: WORKSPACE_API_BOUNDARY,
        execution_mode: WORKSPACE_EXECUTION_MODE,
        primary_api_path: operations_runbook_launch_path,
        secondary_api_path: operations_platform_health_path,
        required_role: Some("ServiceDesk"),
    },
    WorkspaceDefinition {
        id: "admin",
        href: "/admin",
        label: "Admin",
        title: "Admin workspace",
        badge: "Guarded",
        badge_class: "badge bad",
        description: "RBAC, policy, adapter, site catalog, worker capability, approval group, and feature flag controls remain static summaries.",
        points: &[
            "Policy scope",
            "Worker capability",
            "Delegation boundary",
        ],
        api_boundary: WORKSPACE_API_BOUNDARY,
        execution_mode: WORKSPACE_EXECUTION_MODE,
        primary_api_path: admin_worker_capability_path,
        secondary_api_path: admin_feature_flag_governance_path,
        required_role: Some("PlatformAdmin"),
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AuthSession;

    fn session_with_roles(roles: &[&str]) -> AuthSession {
        AuthSession {
            user_id: "test".to_string(),
            display_name: "Test".to_string(),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            token_valid: true,
            provider_mode: "local".to_string(),
        }
    }

    #[test]
    fn session_can_platform_admin_is_superuser() {
        let session = session_with_roles(&["PlatformAdmin"]);
        for capability in ["request", "execute", "approve", "audit"] {
            assert!(
                session_can(&session, capability),
                "PlatformAdmin must hold {capability} via the admin superuser perm"
            );
        }
    }

    #[test]
    fn session_can_auditor_read_only() {
        let session = session_with_roles(&["Auditor"]);
        assert!(!session_can(&session, "request"));
        assert!(!session_can(&session, "execute"));
        assert!(!session_can(&session, "approve"));
        assert!(session_can(&session, "audit"));
    }

    #[test]
    fn session_can_requester_only_request() {
        let session = session_with_roles(&["Requester"]);
        assert!(session_can(&session, "request"));
        assert!(!session_can(&session, "execute"));
        assert!(!session_can(&session, "approve"));
        assert!(!session_can(&session, "audit"));
    }

    #[test]
    fn session_can_operator_holds_execute() {
        let session = session_with_roles(&["VMwareOperator"]);
        assert!(session_can(&session, "execute"));
        assert!(session_can(&session, "audit"));
        assert!(!session_can(&session, "approve"));
        assert!(!session_can(&session, "request"));
    }

    #[test]
    fn session_can_approver_holds_approve_not_execute() {
        let session = session_with_roles(&["DatacenterApprover"]);
        assert!(session_can(&session, "approve"));
        assert!(session_can(&session, "audit"));
        assert!(!session_can(&session, "execute"));
        assert!(!session_can(&session, "request"));
    }

    #[test]
    fn session_can_break_glass_admin_is_superuser() {
        let session = session_with_roles(&["BreakGlassAdmin"]);
        for capability in ["request", "execute", "approve", "audit"] {
            assert!(
                session_can(&session, capability),
                "BreakGlassAdmin must hold {capability} via the admin superuser perm"
            );
        }
    }

    #[test]
    fn session_can_empty_roles_holds_nothing() {
        let session = session_with_roles(&[]);
        for capability in ["request", "execute", "approve", "audit"] {
            assert!(!session_can(&session, capability));
        }
    }

    #[test]
    fn primary_nav_items_use_real_route_paths() {
        for item in PRIMARY_NAV_ITEMS {
            assert!(
                item.href.starts_with('/') && !item.href.contains('#'),
                "nav item {} must use a real route path, got {}",
                item.label,
                item.href
            );
            assert!(
                match_portal_route(item.href).is_some(),
                "nav href {} must resolve in the portal route table",
                item.href
            );
        }
    }

    #[test]
    fn workspace_definitions_route_to_their_nav_paths() {
        for workspace in PRIMARY_WORKSPACES {
            assert_eq!(workspace.href, format!("/{}", workspace.id));
            let (route, matched_workspace) =
                match_portal_route(workspace.href).expect("workspace href must match a route");
            assert_eq!(route, workspace.href);
            assert_eq!(matched_workspace, workspace.id);
        }
    }

    #[test]
    fn nav_active_state_is_route_derived() {
        assert!(nav_item_is_active("/", "/"));
        assert!(!nav_item_is_active("/requests", "/"));
        assert!(nav_item_is_active("/requests", "/requests"));
        assert!(nav_item_is_active("/requests/new", "/requests"));
        assert!(nav_item_is_active("/requests/req-123", "/requests"));
        assert!(nav_item_is_active("/requests/", "/requests"));
        assert!(!nav_item_is_active("/requestsarchive", "/requests"));
        assert!(!nav_item_is_active("/catalog", "/requests"));
    }

    #[test]
    fn route_matcher_resolves_every_workspace_route() {
        assert_eq!(
            match_portal_route("/"),
            Some(("/".to_string(), "dashboard"))
        );
        assert_eq!(
            match_portal_route("/requests"),
            Some(("/requests".to_string(), "requests"))
        );
        assert_eq!(
            match_portal_route("/requests/new"),
            Some(("/requests/new".to_string(), "requests"))
        );
        assert_eq!(
            match_portal_route("/requests/req-1234"),
            Some(("/requests/req-1234".to_string(), "requests"))
        );
        assert_eq!(
            match_portal_route("/operations/"),
            Some(("/operations".to_string(), "operations"))
        );
    }

    #[test]
    fn route_matcher_rejects_unknown_and_unsafe_paths() {
        for path in [
            "",
            "/nope",
            "relative",
            "//evil.example",
            "https://evil.example/requests",
            "/requests/../admin",
            "/requests/a/b",
            "/requests/<script>",
            "/requests/id?x=1",
            "/#dashboard",
            "javascript:alert(1)",
        ] {
            assert_eq!(
                match_portal_route(path),
                None,
                "path {path} must be rejected"
            );
        }
    }
}
