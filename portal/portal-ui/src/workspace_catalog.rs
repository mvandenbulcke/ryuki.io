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
    pub active: bool,
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
        href: "#dashboard",
        active: true,
        required_role: None,
    },
    NavItem {
        label: "Catalog",
        href: "#catalog",
        active: false,
        required_role: Some("Requester"),
    },
    NavItem {
        label: "Requests",
        href: "#requests",
        active: false,
        required_role: Some("Requester"),
    },
    NavItem {
        label: "Activity",
        href: "#activity",
        active: false,
        required_role: Some("Requester"),
    },
    NavItem {
        label: "Inventory",
        href: "#inventory",
        active: false,
        required_role: Some("ServiceDesk"),
    },
    NavItem {
        label: "CMDB",
        href: "#cmdb",
        active: false,
        required_role: Some("ServiceDesk"),
    },
    NavItem {
        label: "Evidence",
        href: "#evidence",
        active: false,
        required_role: Some("Auditor"),
    },
    NavItem {
        label: "Operations",
        href: "#operations",
        active: false,
        required_role: Some("ServiceDesk"),
    },
    NavItem {
        label: "Admin",
        href: "#admin",
        active: false,
        required_role: Some("PlatformAdmin"),
    },
];

pub const PRIMARY_WORKSPACES: &[WorkspaceDefinition] = &[
    WorkspaceDefinition {
        id: "catalog",
        href: "#catalog",
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
        href: "#requests",
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
        href: "#activity",
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
        href: "#inventory",
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
        href: "#cmdb",
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
        href: "#evidence",
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
        href: "#operations",
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
        href: "#admin",
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
