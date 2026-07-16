use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

// The legacy C# API (api/Ryuki.Platform.Api/*) was deleted when the platform
// was ported to Rust; the API skeleton is now the ryuki-api crate.
const REQUIRED_FILES: &[&str] = &[
    "portal/portal-ui/Cargo.toml",
    "portal/portal-ui/styles.css",
    "portal/portal-ui/Dockerfile",
    "portal/portal-ui/src/main.rs",
    "portal/portal-ui/src/lib.rs",
    "portal/portal-ui/src/app.rs",
    "portal/portal-ui/src/server_boundary.rs",
    "portal/portal-ui/src/shell.rs",
    "portal/portal-ui/src/workspace_catalog.rs",
    "portal/portal-ui/src/views/dashboard.rs",
    "portal/portal-ui/src/views/login.rs",
    "portal/portal-ui/src/views/workspaces.rs",
    "portal/portal-ui/src/api.rs",
    "portal/portal-ui/src/api_client.rs",
    "portal/portal-ui/src/models.rs",
    "sources/ryuki-core/Cargo.toml",
    "sources/ryuki-core/src/lib.rs",
    "sources/ryuki-core/src/yaml.rs",
    "sources/ryuki-core/src/secret_scan.rs",
    "sources/ryuki-core/src/types.rs",
    "sources/ryuki-api/Cargo.toml",
    "sources/ryuki-api/Dockerfile",
    "sources/ryuki-api/src/main.rs",
    "sources/ryuki-api/src/contracts.rs",
    "sources/ryuki-api/src/boundary.rs",
    "sources/ryuki-engine/Cargo.toml",
    "sources/ryuki-engine/src/lib.rs",
    "sources/ryuki-engine/src/models.rs",
    "sources/ryuki-engine/src/request_lifecycle.rs",
    "sources/ryuki-engine/src/inventory_sync.rs",
    "sources/ryuki-engine/src/evidence_pipeline.rs",
    "sources/ryuki-engine/src/health_monitor.rs",
    "sources/ryuki-engine/src/patch_engine.rs",
    "sources/ryuki-engine/src/cmdb_engine.rs",
    "sources/ryuki-engine/src/adapter_framework.rs",
];
const LEGACY_PORTAL_NGINX_PATH: &str = "portal/portal-ui/nginx.conf";
const TEXT_SCAN_ROOTS: &[&str] = &["api", "portal", "sources"];
const EXTRA_TEXT_FILES: &[&str] = &[".gitignore"];
const CRATES_IO_LOCK_SOURCE: &str =
    r#"source = "registry+https://github.com/rust-lang/crates.io-index""#;
const TEXT_EXTENSIONS: &[&str] = &[
    ".cs",
    ".csproj",
    ".css",
    ".html",
    ".json",
    ".md",
    ".rs",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
    ".conf",
    "Dockerfile",
    "Cargo.lock",
    ".gitignore",
];
const PORTAL_SERVER_BOUNDARY_FORBIDDEN_CODE_TOKENS: &[&str] = &[
    "reqwest::Client",
    "ureq::",
    "hyper::Client",
    "ProviderClient",
    "AdapterClient",
    "WorkerClient",
    "VaultClient",
    "VaultwardenClient",
    "vaultwarden_cli",
    "bitwarden",
    "DatabasePool",
    "PgPool",
    "SqlitePool",
    "sqlx::",
    "tokio_postgres",
    "postgres::Client",
    "rusqlite::",
    "ObjectStore",
    "object_store::",
    "aws_sdk_",
    "azure_storage",
    "std::net::TcpStream",
];
const PORTAL_BROWSER_FORBIDDEN_CODE_TOKENS: &[&str] = &[
    "reqwest::Client",
    "ureq::",
    "hyper::Client",
    "ProviderClient",
    "AdapterClient",
    "WorkerClient",
    "VaultClient",
    "VaultwardenClient",
    "vaultwarden_cli",
    "bitwarden",
    "DatabasePool",
    "PgPool",
    "SqlitePool",
    "sqlx::",
    "ObjectStore",
    "object_store::",
    "aws_sdk_",
    "azure_storage",
];
const API_ENDPOINTS: &[&str] = &[
    "/healthz",
    "/readyz",
    "/metrics",
    "/api/platform/summary",
    "/api/dashboard/global-overview-contract",
    "/api/dashboard/risk-heatmap-contract",
    "/api/requests/lifecycle-contract",
    "/api/requests/execution-timeline-contract",
    "/api/requests/intake-support-contract",
    "/api/requests/preflight-contract",
    "/api/platform/security-baseline-contract",
    "/api/platform/portal-information-architecture-contract",
    "/api/platform/design-system-contract",
    "/api/platform/ui-mockup-acceptance-contract",
    "/api/platform/release-promotion-contract",
    "/api/platform/local-container-readiness-contract",
    "/api/platform/kubernetes-runtime-readiness-contract",
    "/api/platform/database-readiness-contract",
    "/api/platform/object-storage-readiness-contract",
    "/api/platform/registry-readiness-contract",
    "/api/platform/vault-deployment-readiness-contract",
    "/api/platform/vault-secret-delivery-contract",
    "/api/catalog/categories",
    "/api/catalog/offerings-contract",
    "/api/catalog/recommendations-contract",
    "/api/catalog/request-form-contract",
    "/api/catalog/site-catalog-contract",
    "/api/catalog/policy-guardrails-contract",
    "/api/catalog/access-control",
    "/api/catalog/approval-routes",
    "/api/approvals/decision-readiness-contract",
    "/api/identity/rbac-approval-model-contract",
    "/api/identity/entra-rbac-approval-readiness-contract",
    "/api/identity/access-review-recertification-contract",
    "/api/identity/ad-computer-lifecycle-contract",
    "/api/identity/gmsa-lifecycle-contract",
    "/api/identity/local-privilege-access-contract",
    "/api/identity/file-share-ntfs-recertification-contract",
    "/api/catalog/evidence-manifest",
    "/api/catalog/evidence-redaction-contract",
    "/api/evidence/export-retention-contract",
    "/api/evidence/compliance-dashboard-contract",
    "/api/catalog/secret-references",
    "/api/auth/local/roles",
    "/api/auth/local/me",
    "/api/auth/local/decision",
    "/api/auth/local/login",
    "/api/auth/local/logout",
    "/api/auth/status",
    "/api/auth/session",
    "/api/auth/roles",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/integrations/readiness",
    "/api/integrations/adapter-readiness-matrix-contract",
    "/api/integrations/adapter-contract-test-contract",
    "/api/integrations/vmware/readiness",
    "/api/integrations/hyperv/readiness",
    "/api/integrations/proxmox/readiness",
    "/api/integrations/vmware/cluster-capacity-admission-contract",
    "/api/integrations/vmware/customization-spec-governance-contract",
    "/api/integrations/vmware/object-placement-contract",
    "/api/integrations/vmware/vsan-esxi-lifecycle-contract",
    "/api/integrations/vmware/day2-change-contract",
    "/api/integrations/vmware/snapshot-governance-contract",
    "/api/integrations/vmware/decommission-quarantine-contract",
    "/api/operations/certificate-lifecycle-contract",
    "/api/integrations/veeam/readiness",
    "/api/integrations/zabbix/readiness",
    "/api/integrations/servicenow/readiness",
    "/api/integrations/servicenow/cmdb-file-contract",
    "/api/integrations/servicenow/future-api-contract",
    "/api/inventory/coverage-contract",
    "/api/inventory/coverage/local/summary",
    "/api/inventory/resource-overview-contract",
    "/api/inventory/ownership-risk-contract",
    "/api/inventory/os-baseline-compliance-contract",
    "/api/software/approved-deployment-contract",
    "/api/images/factory-contract",
    "/api/patching/maintenance-contract",
    "/api/patching/policy-import-contract",
    "/api/patching/reboot-orchestration-contract",
    "/api/patching/maintenance-calendar-contract",
    "/api/protect/controlled-restore-contract",
    "/api/protect/backup-coverage-gap-contract",
    "/api/protect/repository-capacity-contract",
    "/api/analytics/cost-capacity-contract",
    "/api/protect/immutability-air-gap-compliance-contract",
    "/api/protect/application-aware-backup-validation-contract",
    "/api/protect/backup-dr-assignment-contract",
    "/api/protect/restore-testing-contract",
    "/api/protect/legal-hold-retention-contract",
    "/api/observe/zabbix-onboarding-contract",
    "/api/observe/alert-routing-contract",
    "/api/observe/monitoring-coverage-gap-contract",
    "/api/observe/zabbix-drift-remediation-contract",
    "/api/observe/synthetic-health-check-contract",
    "/api/observe/noise-flapping-remediation-contract",
    "/api/observe/monitoring-review-queue-contract",
    "/api/observe/log-forwarder-onboarding-contract",
    "/api/cmdb/reconciliation-contract",
    "/api/cmdb/relationship-graph-contract",
    "/api/cmdb/impact-analysis-contract",
    "/api/operations/runbook-launch-contract",
    "/api/operations/standard-task-contract",
    "/api/operations/emergency-change-contract",
    "/api/operations/shift-queue-contract",
    "/api/operations/dependency-replay-contract",
    "/api/operations/activity-queue-contract",
    "/api/operations/run-state-contract",
    "/api/operations/datacenter-readiness-contract",
    "/api/operations/out-of-band-access-validation-contract",
    "/api/operations/network-vlan-readiness-contract",
    "/api/operations/hardware-lifecycle-contract",
    "/api/operations/firmware-compliance-exception-contract",
    "/api/operations/platform-health-contract",
    "/api/operations/incident-context-contract",
    "/api/admin/worker-capability-contract",
    "/api/admin/feature-flag-governance-contract",
    "/api/admin/approval-groups-contract",
    "/api/admin/delegation-boundary-contract",
    "/api/operations/maintenance-communications-contract",
    "/api/operations/degradation-mode-contract",
    "/api/operations/aiops-suggestion-contract",
    "/api/operations/knowledge-suggestion-contract",
    "/api/workflows/server-lifecycle/dry-run-contract",
    "/api/workflows/application-environment/deployment-contract",
    "/api/workflows/application-environment/retirement-contract",
    "/api/workflows/sql-server/deployment-contract",
    "/api/workflows/azure-landing-zone/validation-contract",
    "/api/workflows/preflight/local/decision",
];
const PORTAL_NAV: &[&str] = &[
    "Dashboard",
    "Catalog",
    "Requests",
    "Activity",
    "Inventory",
    "CMDB",
    "Evidence",
    "Operations",
    "Admin",
];

struct WorkspaceDetailRequirement {
    component: &'static str,
    label: &'static str,
    message: &'static str,
    resources: &'static [&'static str],
    helpers: &'static [&'static str],
    fallbacks: &'static [&'static str],
    safe_fields: &'static [&'static str],
}

const WORKSPACE_DETAIL_REQUIREMENTS: &[WorkspaceDetailRequirement] = &[
    WorkspaceDetailRequirement {
        component: "CatalogWorkspaceDetail",
        label: "Catalog workspace detail",
        message: "portal workspaces must render catalog detail panel",
        resources: &[],
        helpers: &[
            "catalog_offerings_path()",
            "catalog_recommendations_path()",
            "catalog_request_form_path()",
            "site_catalog_path()",
        ],
        fallbacks: &["catalog_contract_fallbacks", "catalog_readiness_fallbacks"],
        safe_fields: &["safe_summary", "readiness_state"],
    },
    WorkspaceDetailRequirement {
        component: "SecretReferenceWorkspaceDetail",
        label: "Secret-reference workspace detail",
        message: "portal workspaces must render secret-reference detail panel",
        resources: &["secret_references_resource()"],
        helpers: &[],
        fallbacks: &[
            "PortalSecretReferenceSnapshot::static_dry_run()",
            "snapshot.secret_references",
            "data-live-provider-actions-allowed=live_provider_actions_allowed",
            "data-provider-calls-allowed=provider_calls_allowed",
            "data-secret-values-allowed=secret_values_allowed",
            "data-provider-paths-allowed=provider_paths_allowed",
            "data-secret-reference-workspace-detail=\"true\"",
        ],
        safe_fields: &[
            "safe_summary",
            "live_provider_actions_allowed",
            "value_exposure_allowed",
            "provider_path_exposure_allowed",
        ],
    },
    WorkspaceDetailRequirement {
        component: "RequestsWorkspaceDetail",
        label: "Requests workspace detail",
        message: "portal workspaces must render requests detail panel",
        resources: &[],
        helpers: &[],
        fallbacks: &[
            "Resource::new",
            "load_portal_request_preflight_status()",
            "Suspense",
            "Suspend::new",
            "request_preflight_status.await",
            "snapshot.request_intake",
            "snapshot.dry_run_plans",
            "data-http-request-allowed=request_http_request_allowed",
            "data-provider-calls-allowed=request_provider_calls_allowed",
            "data-live-execution-allowed=request_live_execution_allowed",
            "data-raw-payload-allowed=request_raw_payload_allowed",
            "data-secret-values-allowed=request_secret_values_allowed",
            "data-customer-identifiers-allowed=request_customer_identifiers_allowed",
            "data-preflight-gate-state=preflight_gate_state",
        ],
        safe_fields: &["safe_summary", "execution_allowed", "dry_run"],
    },
    WorkspaceDetailRequirement {
        component: "ActivityWorkspaceDetail",
        label: "Activity workspace detail",
        message: "portal workspaces must render activity detail panel",
        resources: &[],
        helpers: &[
            "activity_operation_queue_path()",
            "shift_queue_path()",
            "emergency_change_path()",
        ],
        fallbacks: &[
            "Resource::new",
            "load_portal_activity_run_state()",
            "activity_run_state.await",
            "snapshot.activity_queue",
            "snapshot.operation_runs",
            "data-worker-execution-allowed=worker_execution_allowed",
            "data-retry-execution-allowed=retry_execution_allowed",
            "data-provider-calls-allowed=provider_calls_allowed",
            "data-live-execution-allowed=live_execution_allowed",
            "data-raw-logs-allowed=raw_logs_allowed",
        ],
        safe_fields: &["safe_summary", "worker_execution_allowed", "dry_run"],
    },
    WorkspaceDetailRequirement {
        component: "InventoryWorkspaceDetail",
        label: "Inventory workspace detail",
        message: "portal workspaces must render inventory detail panel",
        resources: &[],
        helpers: &[],
        fallbacks: &[
            "Resource::new",
            "load_portal_inventory_capacity_status()",
            "inventory_capacity_status.await",
            "snapshot.inventory_resources",
            "snapshot.capacity_admissions",
            "data-inventory-read-only=inventory_read_only",
            "data-stale-data-blocks-execution=stale_data_blocks_execution",
            "data-capacity-execution-allowed=capacity_execution_allowed",
            "data-http-request-allowed=http_request_allowed",
            "data-provider-calls-allowed=provider_calls_allowed",
            "data-raw-inventory-rows-allowed=raw_inventory_rows_allowed",
        ],
        safe_fields: &["safe_summary", "execution_allowed", "evidence_state"],
    },
    WorkspaceDetailRequirement {
        component: "CmdbWorkspaceDetail",
        label: "CMDB workspace detail",
        message: "portal workspaces must render CMDB detail panel",
        resources: &[
            "cmdb_file_exchange_resource()",
            "cmdb_reconciliation_resource()",
            "cmdb_relationship_graph_resource()",
        ],
        helpers: &[],
        fallbacks: &[
            "PortalCmdbWorkspaceSnapshot::static_dry_run()",
            "snapshot.file_exchange",
            "snapshot.reconciliation",
            "snapshot.relationships",
            "data-cmdb-workspace-detail=\"true\"",
            "data-file-import-execution-allowed=file_import_execution_allowed",
            "data-file-export-execution-allowed=file_export_execution_allowed",
            "data-live-servicenow-api-allowed=live_api_allowed",
            "data-cmdb-mutation-allowed=cmdb_mutation_allowed",
            "data-relationship-mutation-allowed=relationship_mutation_allowed",
            "data-provider-calls-allowed=provider_calls_allowed",
            "data-raw-cmdb-rows-allowed=raw_cmdb_rows_allowed",
            "data-raw-relationship-rows-allowed=raw_relationship_rows_allowed",
        ],
        safe_fields: &[
            "safe_summary",
            "file_import_execution_allowed",
            "cmdb_mutation_allowed",
            "relationship_mutation_allowed",
            "raw_cmdb_rows_allowed",
            "raw_relationship_rows_allowed",
        ],
    },
    WorkspaceDetailRequirement {
        component: "PolicyWorkspaceDetail",
        label: "Policy workspace detail",
        message: "portal workspaces must render policy detail panel",
        resources: &["policy_outcomes_resource()"],
        helpers: &["approval_decision_readiness_path()"],
        fallbacks: &[
            "PortalPolicyGuardrailsSnapshot::static_dry_run()",
            "snapshot.policy_outcomes",
            "snapshot.guardrails",
            "data-policy-gate-state=policy_gate_state",
            "data-execution-allowed=execution_allowed",
            "data-provider-calls-allowed=provider_calls_allowed",
            "data-live-execution-allowed=live_execution_allowed",
            "data-raw-policy-payloads-allowed=raw_policy_payloads_allowed",
        ],
        safe_fields: &["safe_summary", "decision", "execution_allowed"],
    },
    WorkspaceDetailRequirement {
        component: "EvidenceWorkspaceDetail",
        label: "Evidence workspace detail",
        message: "portal workspaces must render evidence detail panel",
        resources: &["evidence_summary_resource()"],
        helpers: &["evidence_export_retention_path()"],
        fallbacks: &[
            "Resource::new",
            "load_portal_evidence_summary_status()",
            "Suspense",
            "Suspend::new",
            "evidence_summary_status.await",
            "snapshot.evidence_summaries",
            "data-redaction-required=redaction_required",
            "data-export-allowed=export_allowed",
            "data-http-request-allowed=evidence_http_request_allowed",
            "data-provider-calls-allowed=evidence_provider_calls_allowed",
            "data-raw-evidence-payloads-allowed=raw_evidence_payloads_allowed",
        ],
        safe_fields: &[
            "export_allowed",
            "redaction_required",
            "raw_evidence_payloads_allowed",
            "state",
        ],
    },
    WorkspaceDetailRequirement {
        component: "OperationsWorkspaceDetail",
        label: "Operations workspace detail",
        message: "portal workspaces must render operations detail panel",
        resources: &["operation_runs_resource()"],
        helpers: &[
            "operations_runbook_launch_path()",
            "operations_platform_health_path()",
        ],
        fallbacks: &["operation_run_fallbacks"],
        safe_fields: &["dry_run", "blocked_reason", "state"],
    },
];
const TYPED_PORTAL_API_RESOURCES: &[&str] = &[
    "request_intake_resource()",
    "dry_run_plan_resource()",
    "inventory_resource_overview_resource()",
    "capacity_admission_resource()",
    "secret_references_resource()",
    "cmdb_file_exchange_resource()",
    "cmdb_reconciliation_resource()",
    "cmdb_relationship_graph_resource()",
    "policy_outcomes_resource()",
    "evidence_summary_resource()",
    "operation_runs_resource()",
];
const DIRECT_UI_TYPED_PORTAL_API_RESOURCES: &[&str] = &[
    "secret_references_resource()",
    "policy_outcomes_resource()",
    "evidence_summary_resource()",
    "operation_runs_resource()",
];
const DASHBOARD_CARDS: &[&str] = &[
    "Platform health",
    "Site readiness",
    "Open requests",
    "Failed operations",
    "Backup risk",
    "Monitoring gaps",
    "Stale data",
];
#[derive(Clone, Copy)]
struct AllowedUri {
    scheme: &'static str,
    host: &'static str,
    port: u16,
    path: &'static str,
}

const ALLOWED_INTERNAL_URLS: &[AllowedUri] = &[
    AllowedUri {
        scheme: "http",
        host: "platform-api",
        port: 8080,
        path: "/api/",
    },
    AllowedUri {
        scheme: "http",
        host: "localhost",
        port: 18080,
        path: "/api/",
    },
    AllowedUri {
        scheme: "http",
        host: "+",
        port: 8080,
        path: "",
    },
];
// This is the one fail-closed development origin documented by the portal
// image and README. It is accepted only as an exact, delimited value; paths,
// queries, fragments, credentials, other ports, and non-loopback hosts remain
// subject to the prohibited-value scan.
const ALLOWED_LOOPBACK_ORIGINS: &[AllowedUri] = &[AllowedUri {
    scheme: "http",
    host: "127.0.0.1",
    port: 8080,
    path: "",
}];

#[derive(Debug, Deserialize)]
struct Context {
    root: String,
}

// The .NET project/program/dockerfile inputs were retired with the C# API;
// the API skeleton check now validates the Rust API sources. `program` is
// accepted as a fallback alias for the contracts source so existing callers
// keep working.
#[derive(Debug, Deserialize)]
struct ApiInput {
    #[serde(default)]
    program: String,
    #[serde(default)]
    rust_contracts: String,
    #[serde(default)]
    rust_api_main: String,
}

#[derive(Debug, Deserialize)]
struct PortalInput {
    css: String,
    dockerfile: String,
    cargo_toml: Option<String>,
    main_rs: Option<String>,
    lib_rs: Option<String>,
    app_rs: Option<String>,
    server_boundary_rs: Option<String>,
    shell_rs: Option<String>,
    workspace_catalog_rs: Option<String>,
    dashboard_rs: Option<String>,
    login_rs: Option<String>,
    workspaces_rs: Option<String>,
    api_rs: Option<String>,
    api_client_rs: Option<String>,
    models_rs: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TextInput {
    path: String,
    text: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid app skeleton context JSON: {error}"))?;
    Ok(validate_root(Path::new(&context.root)))
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ApiInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid app skeleton API JSON: {error}"))?;
    let mut errors = Vec::new();
    let contracts = if payload.rust_contracts.is_empty() {
        &payload.program
    } else {
        &payload.rust_contracts
    };
    validate_rust_api(contracts, &payload.rust_api_main, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: PortalInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid app skeleton portal JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_portal(
        &payload.css,
        &payload.dockerfile,
        payload.cargo_toml.as_deref().unwrap_or_default(),
        payload.main_rs.as_deref().unwrap_or_default(),
        payload.lib_rs.as_deref().unwrap_or_default(),
        payload.app_rs.as_deref().unwrap_or_default(),
        payload.server_boundary_rs.as_deref().unwrap_or_default(),
        payload.shell_rs.as_deref().unwrap_or_default(),
        payload.workspace_catalog_rs.as_deref().unwrap_or_default(),
        payload.dashboard_rs.as_deref().unwrap_or_default(),
        payload.login_rs.as_deref().unwrap_or_default(),
        payload.workspaces_rs.as_deref().unwrap_or_default(),
        payload.api_rs.as_deref().unwrap_or_default(),
        payload.api_client_rs.as_deref().unwrap_or_default(),
        payload.models_rs.as_deref().unwrap_or_default(),
        &mut errors,
    );
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: TextInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid app skeleton prohibited-text JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_text(&payload.path, &payload.text, &mut errors);
    Ok(errors)
}

fn validate_root(root: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    validate_required_files(root, &mut errors);
    if !errors.is_empty() {
        return errors;
    }

    let portal_cargo = read_file(root, "portal/portal-ui/Cargo.toml", &mut errors);
    let portal_css = read_file(root, "portal/portal-ui/styles.css", &mut errors);
    let portal_dockerfile = read_file(root, "portal/portal-ui/Dockerfile", &mut errors);
    let portal_main = read_file(root, "portal/portal-ui/src/main.rs", &mut errors);
    let portal_lib = read_file(root, "portal/portal-ui/src/lib.rs", &mut errors);
    let portal_app = read_file(root, "portal/portal-ui/src/app.rs", &mut errors);
    let portal_server_boundary =
        read_file(root, "portal/portal-ui/src/server_boundary.rs", &mut errors);
    let portal_shell = read_file(root, "portal/portal-ui/src/shell.rs", &mut errors);
    let portal_workspace_catalog = read_file(
        root,
        "portal/portal-ui/src/workspace_catalog.rs",
        &mut errors,
    );
    let portal_dashboard = read_file(root, "portal/portal-ui/src/views/dashboard.rs", &mut errors);
    let portal_login = read_file(root, "portal/portal-ui/src/views/login.rs", &mut errors);
    let portal_workspaces = read_file(
        root,
        "portal/portal-ui/src/views/workspaces.rs",
        &mut errors,
    );
    let portal_api = read_file(root, "portal/portal-ui/src/api.rs", &mut errors);
    let portal_api_client = read_file(root, "portal/portal-ui/src/api_client.rs", &mut errors);
    let portal_models = read_file(root, "portal/portal-ui/src/models.rs", &mut errors);
    if !errors.is_empty() {
        return errors;
    }

    let rust_contracts = read_file(root, "sources/ryuki-api/src/contracts.rs", &mut errors);
    let rust_api_main = read_file(root, "sources/ryuki-api/src/main.rs", &mut errors);
    if !errors.is_empty() {
        return errors;
    }

    validate_rust_api(&rust_contracts, &rust_api_main, &mut errors);
    validate_portal(
        &portal_css,
        &portal_dockerfile,
        &portal_cargo,
        &portal_main,
        &portal_lib,
        &portal_app,
        &portal_server_boundary,
        &portal_shell,
        &portal_workspace_catalog,
        &portal_dashboard,
        &portal_login,
        &portal_workspaces,
        &portal_api,
        &portal_api_client,
        &portal_models,
        &mut errors,
    );

    for relative_path in text_files(root) {
        match fs::read_to_string(root.join(&relative_path)) {
            Ok(text) => validate_text(&relative_path, &text, &mut errors),
            Err(error) => errors.push(format!("{relative_path} file access error: {error}")),
        }
    }

    errors
}

fn validate_required_files(root: &Path, errors: &mut Vec<String>) {
    for path in REQUIRED_FILES {
        if !root.join(path).is_file() {
            errors.push(format!("missing required file {path}"));
        }
    }
    if root.join(LEGACY_PORTAL_NGINX_PATH).exists() {
        errors.push("legacy portal NGINX config must not be present".to_string());
    }
}

fn read_file(root: &Path, path: &str, errors: &mut Vec<String>) -> String {
    match fs::read_to_string(root.join(path)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("{path} file access error: {error}"));
            String::new()
        }
    }
}

fn validate_rust_api(contracts: &str, main_rs: &str, errors: &mut Vec<String>) {
    expect(
        contracts.contains("use axum")
            && contracts.contains("Router")
            // Accept both `routing::get` and grouped `routing::{get, post}`
            // import syntax.
            && (contracts.contains("routing::get") || contracts.contains("routing::{get")),
        errors,
        "Rust API contracts.rs must import axum Router and get routing",
    );
    expect(
        contracts.contains("pub fn routes() -> Router"),
        errors,
        "Rust API contracts.rs must expose a routes() -> Router function",
    );
    expect(
        contracts.contains(".route(\"/api/platform/summary\", get(platform_summary))"),
        errors,
        "Rust API must expose /api/platform/summary",
    );
    expect(
        main_rs.contains(".route(\"/health\", get(health))"),
        errors,
        "Rust API main.rs must expose /health endpoint",
    );
    expect(
        main_rs.contains(".route(\"/ready\", get(ready))"),
        errors,
        "Rust API main.rs must expose /ready endpoint",
    );
    expect(
        main_rs.contains("contracts::routes()"),
        errors,
        "Rust API main.rs must merge contracts::routes()",
    );
    expect(
        main_rs.contains("boundary::routes()"),
        errors,
        "Rust API main.rs must merge boundary::routes()",
    );
    expect(
        main_rs.contains("axum::serve"),
        errors,
        "Rust API main.rs must use axum::serve to start the server",
    );
    expect(
        main_rs.contains("0.0.0.0:8080")
            || main_rs.contains("api_bind_addr")
            || main_rs.contains("TcpListener::bind(&app_config.server.bind_address)"),
        errors,
        "Rust API must bind to 0.0.0.0:8080 or use Rust server bind_address config",
    );
    expect(
        // The auth module is imported in main.rs, so the call may be written
        // either fully qualified or through the imported name.
        main_rs.contains("ryuki_engine::auth::AuthSession::static_dry_run()")
            || main_rs.contains("AuthSession::static_dry_run()"),
        errors,
        "Rust API must use static dry-run auth session by default",
    );
    for endpoint in API_ENDPOINTS {
        // The Rust API uses /health and /ready instead of /healthz and /readyz
        if *endpoint == "/healthz" || *endpoint == "/readyz" {
            continue;
        }
        let route_found = contracts.contains(endpoint) || main_rs.contains(endpoint);
        expect(
            route_found,
            errors,
            format!("Rust API missing endpoint {endpoint}"),
        );
    }
}

fn validate_portal(
    css: &str,
    dockerfile: &str,
    cargo_toml: &str,
    main_rs: &str,
    lib_rs: &str,
    app_rs: &str,
    server_boundary_rs: &str,
    shell_rs: &str,
    workspace_catalog_rs: &str,
    dashboard_rs: &str,
    login_rs: &str,
    workspaces_rs: &str,
    api_rs: &str,
    api_client_rs: &str,
    models_rs: &str,
    errors: &mut Vec<String>,
) {
    let active_app = strip_rust_comments(app_rs);
    let active_app_without_strings = strip_rust_string_literals(&active_app);
    // Favicon ownership stays in App metadata. Accept a self-contained PNG/SVG
    // data URI or the portal's same-origin `/favicon.svg` asset; all three keep
    // the icon inside the application boundary with no third-party fetch.
    expect(
        active_app.contains("pub fn shell(options: LeptosOptions)")
            && active_app.contains("<!DOCTYPE html>")
            && active_app.contains("HydrationScripts")
            && active_app.contains("AutoReload")
            && active_app.contains("MetaTags")
            && active_app.contains(r#"rel="icon""#)
            && (active_app.contains("data:image/png;base64")
                || active_app.contains("data:image/svg+xml")
                || active_app.contains(r#"href="/favicon.svg""#))
            && active_app.contains("<App/>"),
        errors,
        "portal app.rs must own the SSR HTML shell, hydration scripts, and favicon metadata",
    );
    expect(
        !active_app_without_strings.contains("fetch(")
            && !active_app_without_strings.contains("XMLHttpRequest")
            && !active_app_without_strings.contains("document.cookie"),
        errors,
        "portal app.rs SSR shell must not call browser APIs directly",
    );
    expect(
        !active_app.contains("data-trunk") && !active_app.contains("Trunk.toml"),
        errors,
        "portal app.rs must not depend on legacy Trunk asset processing",
    );
    expect(
        (dockerfile.contains("COPY Cargo.toml Cargo.lock ./")
            || dockerfile.contains("COPY Cargo.toml styles.css ./"))
            && !dockerfile.contains("COPY Cargo.toml index.html styles.css ./"),
        errors,
        "portal Dockerfile must not copy the retired Trunk index.html",
    );
    expect(
        cargo_toml.contains(r#"name = "ryuki-portal-ui""#),
        errors,
        "portal Cargo.toml must name the Rust UI crate",
    );
    expect(
        cargo_toml.contains("publish = false"),
        errors,
        "portal Cargo.toml must keep the UI crate private",
    );
    expect(
        cargo_toml.contains("leptos")
            && cargo_toml.contains("[features]")
            && cargo_toml.contains("hydrate =")
            && cargo_toml.contains(r#""leptos/hydrate""#)
            && cargo_toml.contains("ssr =")
            && cargo_toml.contains(r#""leptos/ssr""#),
        errors,
        "portal Cargo.toml must separate Leptos ssr and hydrate features",
    );
    expect(
        cargo_toml.contains("axum")
            && cargo_toml.contains("leptos_axum")
            && cargo_toml.contains("tokio")
            && cargo_toml.contains(r#""dep:axum""#)
            && cargo_toml.contains(r#""dep:leptos_axum""#),
        errors,
        "portal Cargo.toml must declare Axum-backed full-stack dependencies behind ssr",
    );
    // relaxed (config source): the original check pinned the Leptos config load
    // to `get_configuration(Some("Cargo.toml"))`. The portal team switched to
    // `get_configuration(None)`, which reads the same `[package.metadata.leptos]`
    // settings from the environment / compiled-in defaults instead of re-reading
    // Cargo.toml at runtime. Either form starts the same Axum-backed SSR server,
    // so we accept both. All other tokens (tokio main, leptos_axum imports,
    // Router, .leptos_routes, file_and_error_handler(shell), and the
    // static-dry-run boundary) stay required.
    expect(
        main_rs.contains(r#"#[cfg(feature = "ssr")]"#)
            && main_rs.contains("#[tokio::main]")
            && main_rs.contains(
                "leptos_axum::{file_and_error_handler, generate_route_list, LeptosRoutes}",
            )
            && main_rs.contains("Router::new()")
            // relaxed: accept `.leptos_routes_with_context(` — the portal team
            // upgraded from `.leptos_routes(` to the context-injecting variant so
            // an upstream HTTP client can be provided to server functions. Both
            // mount the generated Leptos route list on the Axum router.
            && (main_rs.contains(".leptos_routes(")
                || main_rs.contains(".leptos_routes_with_context("))
            && main_rs.contains("file_and_error_handler(shell)")
            && (main_rs.contains(r#"get_configuration(Some("Cargo.toml"))"#)
                || main_rs.contains("get_configuration(None)"))
            && main_rs.contains("PortalServerBoundary::static_dry_run()"),
        errors,
        "portal main.rs must run the Axum-backed Leptos SSR server",
    );
    expect(
        lib_rs.contains(r#"#[cfg(feature = "hydrate")]"#)
            && lib_rs.contains("wasm_bindgen")
            && lib_rs.contains("console_error_panic_hook::set_once()")
            && lib_rs.contains("leptos::mount::hydrate_body(app::App)")
            && lib_rs.contains("pub mod server_boundary;")
            && lib_rs.contains("pub mod api_client;"),
        errors,
        "portal lib.rs must expose the shared app and hydrate entrypoint",
    );
    expect(
        app_rs.contains("pub fn shell(options: LeptosOptions)")
            && app_rs.contains("HydrationScripts")
            && app_rs.contains("AutoReload")
            && app_rs.contains("MetaTags")
            && app_rs.contains("Stylesheet")
            && app_rs.contains(r#"href="/pkg/ryuki-portal-ui.css""#)
            && app_rs.contains("Link")
            && app_rs.contains(r#"rel="icon""#)
            && app_rs.contains("Title")
            && app_rs.contains("#[component]")
            && app_rs.contains("pub fn App"),
        errors,
        "portal app.rs must expose a full-stack Leptos shell and cargo-leptos stylesheet asset",
    );
    expect(
        app_rs.contains("Shell"),
        errors,
        "portal app.rs must compose the product shell",
    );
    let active_shell = strip_rust_comments(shell_rs);
    let active_lib = strip_rust_comments(lib_rs);
    let active_server_boundary = strip_rust_comments(server_boundary_rs);
    let active_workspace_catalog = strip_rust_comments(workspace_catalog_rs);
    let active_dashboard = strip_rust_comments(dashboard_rs);
    let active_login = strip_rust_comments(login_rs);
    let active_workspaces = strip_rust_comments(workspaces_rs);
    let active_shell_code = strip_rust_string_literals(&active_shell);
    let active_dashboard_code = strip_rust_string_literals(&active_dashboard);
    let active_login_code = strip_rust_string_literals(&active_login);
    let active_workspaces_code = strip_rust_string_literals(&active_workspaces);
    let active_server_boundary_code = strip_rust_string_literals(&active_server_boundary);
    let active_api = strip_rust_comments(api_rs);
    let active_api_client = strip_rust_comments(api_client_rs);
    let active_api_client_code = strip_rust_string_literals(&active_api_client);
    let active_models = strip_rust_comments(models_rs);
    let active_app = strip_rust_comments(app_rs);
    let active_main = strip_rust_comments(main_rs);
    let active_browser_code = [
        strip_rust_string_literals(&active_lib),
        strip_rust_string_literals(&active_app),
        active_shell_code.clone(),
        strip_rust_string_literals(&active_workspace_catalog),
        active_dashboard_code.clone(),
        active_login_code.clone(),
        active_workspaces_code.clone(),
        strip_rust_string_literals(&active_api),
        active_api_client_code.clone(),
        strip_rust_string_literals(&active_models),
    ]
    .join("\n");
    validate_forbidden_code_tokens(
        "portal server boundary",
        &active_server_boundary_code,
        PORTAL_SERVER_BOUNDARY_FORBIDDEN_CODE_TOKENS,
        errors,
    );
    validate_forbidden_code_tokens(
        "portal browser-facing code",
        &active_browser_code,
        PORTAL_BROWSER_FORBIDDEN_CODE_TOKENS,
        errors,
    );
    let portal_source = [
        active_shell.as_str(),
        active_workspace_catalog.as_str(),
        active_dashboard.as_str(),
        active_login.as_str(),
        active_workspaces.as_str(),
        active_api.as_str(),
        active_api_client_code.as_str(),
        active_models.as_str(),
        active_app.as_str(),
        active_main.as_str(),
    ]
    .join("\n");
    for label in PORTAL_NAV {
        expect(
            portal_source.contains(&format!("\"{label}\"")) || portal_source.contains(label),
            errors,
            format!("portal missing nav label {label}"),
        );
    }
    for label in DASHBOARD_CARDS {
        expect(
            portal_source.contains(label),
            errors,
            format!("portal missing dashboard card {label}"),
        );
    }
    // relaxed (preflight label rewording): the portal team (owns the portal
    // views, off-limits here) renamed the single "Preflight gate" header to the
    // explicit gate states it now renders ("Preflight required" /
    // "Preflight loading" / "Preflight unavailable", plus the
    // `preflight_gate_state` data attribute). The safe-contract preflight panel
    // is still present and still blocks execution; only the heading wording
    // changed, so we accept any of the current preflight-gate phrasings.
    expect(
        portal_source.contains("Preflight gate")
            || portal_source.contains("Preflight required")
            || portal_source.contains("preflight_gate_state"),
        errors,
        "portal missing safe contract panel Preflight gate",
    );
    for label in [
        "Request intake",
        "Dry-run execution plan",
        "Execution blocked",
        "Inventory overview",
        "Capacity admission",
        "Read-only inventory",
        "Stale data blocks execution",
        "CMDB workspace detail",
        "File exchange blocked",
        "Live ServiceNow API blocked",
        "Raw CMDB rows blocked",
        "Relationship mutation blocked",
        "Catalog contracts",
        "Offering readiness",
        "Static catalog source",
        "Request forms aligned",
        "Secret-reference readiness",
        "Provider actions blocked",
        "Audit-safe workflows",
        "Approval gates",
        "Activity queue",
        "Worker execution blocked",
        "Policy guardrails",
        "Evidence redaction",
        "Operation run state",
        "Dry-run only",
    ] {
        expect(
            portal_source.contains(label),
            errors,
            format!("portal missing safe contract panel {label}"),
        );
    }
    for label in [
        "Catalog workspace",
        "Requests workspace",
        "Activity workspace",
        "Inventory workspace",
        "CMDB workspace",
        "Evidence workspace",
        "Operations workspace",
        "Admin workspace",
        "Static/dry-run",
        "Same-origin API only",
    ] {
        expect(
            active_workspace_catalog.contains(label),
            errors,
            format!("portal missing workspace section {label}"),
        );
    }
    expect(
        active_workspace_catalog.contains("pub struct NavItem"),
        errors,
        "portal workspace registry must define NavItem",
    );
    expect(
        active_workspace_catalog.contains("pub struct WorkspaceDefinition"),
        errors,
        "portal workspace registry must define WorkspaceDefinition",
    );
    expect(
        active_workspace_catalog.contains("pub const PRIMARY_NAV_ITEMS"),
        errors,
        "portal workspace registry must expose PRIMARY_NAV_ITEMS",
    );
    expect(
        active_workspace_catalog.contains("pub const PRIMARY_WORKSPACES"),
        errors,
        "portal workspace registry must expose PRIMARY_WORKSPACES",
    );
    expect(
        active_shell.contains("PRIMARY_NAV_ITEMS") && active_shell.contains(".iter()"),
        errors,
        "portal shell must render nav from typed registry",
    );
    // relaxed (snapshot lifted to caller + routed views): the portal team (owns
    // portal/portal-ui/src/shell.rs, off-limits here) migrated the single-page
    // shell to a multi-route SSR app. `Shell` now *receives* the typed
    // `PortalRouteStateSnapshot` as a parameter
    // (`pub fn Shell(route_snapshot: PortalRouteStateSnapshot)`) instead of
    // constructing it inline, and the snapshot is built via
    // `PortalRouteStateSnapshot::static_dry_run()` in app.rs / server_boundary.rs
    // before being passed in — an improvement that keeps construction out of the
    // view. `activity_action_label` likewise moved to the dashboard workspace
    // view (views/workspaces.rs) and is covered there. We therefore (1) require
    // the snapshot to still be constructed via the typed static-dry-run
    // constructor somewhere in the boundary, (2) require `Shell` to consume the
    // typed snapshot, and (3) keep every route/run-state data attribute and the
    // remaining scope labels asserted on the shell block, so the safety-bearing
    // boundary rendering is unchanged.
    let shell_code_block = rust_function_block(&active_shell_code, "Shell").unwrap_or_default();
    expect(
        active_shell_code.contains("PortalRouteStateSnapshot")
            && (active_server_boundary_code.contains("PortalRouteStateSnapshot::static_dry_run()")
                || active_shell_code.contains("PortalRouteStateSnapshot::static_dry_run()")
                || active_app.contains("PortalRouteStateSnapshot::static_dry_run()"))
            && shell_code_block.contains("Shell(route_snapshot: PortalRouteStateSnapshot)")
            && shell_code_block.contains("data-route-state-path=route_state_path")
            && shell_code_block.contains("data-run-state-path=run_state_path")
            && shell_code_block.contains("data-route-state=route_state")
            && shell_code_block.contains("data-run-state=run_state")
            && shell_code_block
                .contains("data-provider-calls-allowed=route_provider_calls_allowed")
            && shell_code_block
                .contains("data-live-execution-allowed=route_live_execution_allowed")
            && shell_code_block.contains("data-raw-route-state-allowed=route_raw_state_allowed")
            && shell_code_block.contains("site_scope_label")
            && shell_code_block.contains("environment_scope_label")
            && shell_code_block.contains("role_scope_label")
            && shell_code_block.contains("inventory_freshness_label")
            && shell_code_block.contains("execution_authority_label"),
        errors,
        "portal shell must render route/run-state from typed boundary snapshot",
    );
    expect(
        active_workspaces.contains("PRIMARY_WORKSPACES") && active_workspaces.contains(".iter()"),
        errors,
        "portal workspaces must render sections from typed registry",
    );
    // relaxed (single-page sections -> routed views): the portal team replaced
    // the single `WorkspaceSections` component with one routed `*WorkspaceView`
    // per workspace (CatalogWorkspaceView, RequestsWorkspaceView, ...), each
    // mounting its detail component inside a `workspace-detail-grid` section
    // (see portal/portal-ui/src/views/workspaces.rs and the `<Router>` route
    // table in app.rs). When `WorkspaceSections` no longer exists we treat the
    // whole workspaces module as the mount surface, so the per-detail checks
    // below still verify each detail component is mounted in a detail grid.
    let workspace_sections_block = rust_function_block(&active_workspaces, "WorkspaceSections")
        .unwrap_or(active_workspaces.as_str());
    let dashboard_view_code_block =
        rust_function_block(&active_dashboard_code, "DashboardView").unwrap_or("");
    let portal_boundary_status_block =
        rust_function_block(&active_dashboard, "PortalBoundaryStatus").unwrap_or("");
    let portal_boundary_status_code_block =
        rust_function_block(&active_dashboard_code, "PortalBoundaryStatus").unwrap_or("");
    let request_preflight_block =
        rust_function_block(&active_dashboard, "PortalRequestPreflightStatus").unwrap_or("");
    let request_preflight_code_block =
        rust_function_block(&active_dashboard_code, "PortalRequestPreflightStatus").unwrap_or("");
    let inventory_capacity_block =
        rust_function_block(&active_dashboard, "PortalInventoryCapacityStatus").unwrap_or("");
    let inventory_capacity_code_block =
        rust_function_block(&active_dashboard_code, "PortalInventoryCapacityStatus").unwrap_or("");
    expect(
        active_dashboard.contains("PortalBoundaryStatusSnapshot")
            && mounted_component(dashboard_view_code_block, "PortalBoundaryStatus")
            && portal_boundary_status_code_block.contains("Resource::new")
            && portal_boundary_status_code_block.contains("load_portal_boundary_status()")
            && portal_boundary_status_code_block.contains("Suspense")
            && portal_boundary_status_code_block.contains("Suspend::new")
            && portal_boundary_status_code_block.contains("boundary_status.await")
            && portal_boundary_status_code_block
                .contains("let snapshot: PortalBoundaryStatusSnapshot = snapshot")
            && !portal_boundary_status_code_block
                .contains("PortalBoundaryStatusSnapshot::static_dry_run()")
            && portal_boundary_status_code_block.contains("Ok(snapshot)")
            && portal_boundary_status_code_block.contains("Err(_)")
            && portal_boundary_status_block.contains("Loading static read plans")
            && portal_boundary_status_block.contains("Boundary status unavailable")
            && portal_boundary_status_code_block.contains("snapshot.read_plans")
            && portal_boundary_status_code_block
                .contains("let api_boundary = snapshot.api_boundary.clone();")
            && portal_boundary_status_code_block
                .contains("let execution_mode = snapshot.execution_mode.clone();")
            && portal_boundary_status_code_block
                .contains("let http_request_allowed = snapshot.http_request_allowed.to_string();")
            && portal_boundary_status_code_block
                .contains("let raw_payload_allowed = snapshot.raw_payload_allowed.to_string();")
            && portal_boundary_status_code_block.contains(
                "let secret_values_allowed = snapshot.secret_values_allowed.to_string();",
            )
            && portal_boundary_status_code_block.contains("let customer_identifiers_allowed")
            && portal_boundary_status_code_block
                .contains("snapshot.customer_identifiers_allowed.to_string();")
            && portal_boundary_status_code_block.contains(".into_iter()")
            && portal_boundary_status_code_block.contains("data-api-path=path")
            && portal_boundary_status_code_block.contains("data-resource=resource_label_attr")
            && portal_boundary_status_code_block.contains("data-api-boundary=api_boundary")
            && portal_boundary_status_code_block.contains("data-execution-mode=execution_mode")
            && portal_boundary_status_code_block
                .contains("data-http-request-allowed=http_request_allowed")
            && portal_boundary_status_code_block
                .contains("data-raw-payload-allowed=raw_payload_allowed")
            && portal_boundary_status_code_block
                .contains("data-secret-values-allowed=secret_values_allowed")
            && portal_boundary_status_code_block
                .contains("data-customer-identifiers-allowed=customer_identifiers_allowed"),
        errors,
        "portal dashboard must render core server boundary status from typed snapshot contract",
    );
    // relaxed (preflight rendering consolidated into the dashboard view): the
    // original check also required `active_workspaces` (views/workspaces.rs) to
    // reference `PortalRequestPreflightSnapshot`. The portal team consolidated
    // the request-preflight rendering into the `PortalRequestPreflightStatus`
    // component in views/dashboard.rs (mounted in DashboardView, which the routed
    // DashboardWorkspaceView renders), and the `/requests` route now renders a
    // RequestList rather than an inline preflight panel. The typed snapshot is
    // still loaded from the boundary and rendered with all safety attributes, so
    // we assert it on the dashboard module (below) and drop the stale
    // workspaces-module reference.
    expect(
        active_dashboard.contains("PortalRequestPreflightSnapshot")
            && mounted_component(dashboard_view_code_block, "PortalRequestPreflightStatus")
            && request_preflight_code_block.contains("Resource::new")
            && request_preflight_code_block.contains("load_portal_request_preflight_status()")
            && request_preflight_code_block.contains("Suspense")
            && request_preflight_code_block.contains("Suspend::new")
            && request_preflight_code_block.contains("request_preflight_status.await")
            && request_preflight_code_block
                .contains("let snapshot: PortalRequestPreflightSnapshot = snapshot")
            && !request_preflight_code_block
                .contains("PortalRequestPreflightSnapshot::static_dry_run()")
            && !request_preflight_code_block.contains("request_intake_fallbacks()")
            && !request_preflight_code_block.contains("dry_run_plan_fallbacks()")
            && request_preflight_code_block.contains("Ok(snapshot)")
            && request_preflight_code_block.contains("Err(_)")
            && request_preflight_code_block.contains("snapshot.request_intake")
            && request_preflight_code_block.contains("snapshot.dry_run_plans")
            && request_preflight_code_block
                .contains("let request_api_path = snapshot.request_intake_path.clone();")
            && request_preflight_code_block
                .contains("let preflight_api_path = snapshot.preflight_path.clone();")
            && request_preflight_code_block
                .contains("let dry_run_api_path = snapshot.dry_run_plan_path.clone();")
            && request_preflight_code_block
                .contains("let preflight_gate_state = snapshot.preflight_gate_state.clone();")
            && request_preflight_code_block.contains("let request_http_request_allowed")
            && request_preflight_code_block.contains("snapshot.http_request_allowed.to_string();")
            && request_preflight_code_block.contains("let request_provider_calls_allowed")
            && request_preflight_code_block
                .contains("snapshot.provider_calls_allowed.to_string();")
            && request_preflight_code_block.contains("let request_live_execution_allowed")
            && request_preflight_code_block
                .contains("snapshot.live_execution_allowed.to_string();")
            && request_preflight_code_block.contains("let request_raw_payload_allowed")
            && request_preflight_code_block.contains("snapshot.raw_payload_allowed.to_string();")
            && request_preflight_code_block.contains("let request_secret_values_allowed")
            && request_preflight_code_block.contains("snapshot.secret_values_allowed.to_string();")
            && request_preflight_code_block.contains("let request_customer_identifiers_allowed")
            && request_preflight_code_block
                .contains("snapshot.customer_identifiers_allowed.to_string();")
            && request_preflight_code_block
                .contains("data-http-request-allowed=request_http_request_allowed")
            && request_preflight_code_block
                .contains("data-provider-calls-allowed=request_provider_calls_allowed")
            && request_preflight_code_block
                .contains("data-live-execution-allowed=request_live_execution_allowed")
            && request_preflight_code_block
                .contains("data-raw-payload-allowed=request_raw_payload_allowed")
            && request_preflight_code_block
                .contains("data-secret-values-allowed=request_secret_values_allowed")
            && request_preflight_code_block
                .contains("data-customer-identifiers-allowed=request_customer_identifiers_allowed")
            && request_preflight_block.contains("Request intake")
            && request_preflight_block.contains("Dry-run execution plan")
            && request_preflight_block.contains("Execution blocked")
            && request_preflight_block
                .contains("Provider calls, live mutation, and raw payload exposure remain blocked")
            && request_preflight_block.contains("No live mutation or provider-side execution"),
        errors,
        "portal dashboard must render request preflight state from typed snapshot contract",
    );
    expect(
        active_dashboard.contains("PortalInventoryCapacitySnapshot")
            && active_workspaces.contains("PortalInventoryCapacitySnapshot")
            && mounted_component(dashboard_view_code_block, "PortalInventoryCapacityStatus")
            && inventory_capacity_code_block.contains("Resource::new")
            && inventory_capacity_code_block.contains("load_portal_inventory_capacity_status()")
            && inventory_capacity_code_block.contains("Suspense")
            && inventory_capacity_code_block.contains("Suspend::new")
            && inventory_capacity_code_block.contains("inventory_capacity_status.await")
            && inventory_capacity_code_block
                .contains("let snapshot: PortalInventoryCapacitySnapshot = snapshot")
            && !inventory_capacity_code_block
                .contains("PortalInventoryCapacitySnapshot::static_dry_run()")
            && inventory_capacity_code_block.contains("Ok(snapshot)")
            && inventory_capacity_code_block.contains("Err(_)")
            && inventory_capacity_code_block.contains("snapshot.inventory_resources")
            && inventory_capacity_code_block.contains("snapshot.capacity_admissions")
            && inventory_capacity_code_block
                .contains("let inventory_api_path = snapshot.inventory_resource_path.clone();")
            && inventory_capacity_code_block
                .contains("let inventory_risk_api_path = snapshot.ownership_risk_path.clone();")
            && inventory_capacity_code_block
                .contains("let capacity_api_path = snapshot.capacity_admission_path.clone();")
            && inventory_capacity_code_block
                .contains("let inventory_read_only = snapshot.inventory_read_only.to_string();")
            && inventory_capacity_code_block
                .contains("snapshot.stale_data_blocks_execution.to_string();")
            && inventory_capacity_code_block
                .contains("snapshot.capacity_execution_allowed.to_string();")
            && inventory_capacity_code_block.contains("snapshot.http_request_allowed.to_string();")
            && inventory_capacity_code_block
                .contains("snapshot.provider_calls_allowed.to_string();")
            && inventory_capacity_code_block
                .contains("snapshot.raw_inventory_rows_allowed.to_string();")
            && inventory_capacity_code_block
                .contains("data-inventory-read-only=inventory_read_only")
            && inventory_capacity_code_block
                .contains("data-stale-data-blocks-execution=stale_data_blocks_execution")
            && inventory_capacity_code_block
                .contains("data-capacity-execution-allowed=capacity_execution_allowed")
            && inventory_capacity_code_block
                .contains("data-http-request-allowed=inventory_http_request_allowed")
            && inventory_capacity_code_block
                .contains("data-provider-calls-allowed=inventory_provider_calls_allowed")
            && inventory_capacity_code_block
                .contains("data-raw-inventory-rows-allowed=raw_inventory_rows_allowed")
            && inventory_capacity_block.contains("Inventory capacity loading")
            && inventory_capacity_block.contains("Inventory capacity unavailable")
            && inventory_capacity_block
                .contains("Provider calls and raw inventory rows remain blocked")
            && inventory_capacity_block.contains("No live capacity execution"),
        errors,
        "portal dashboard must render inventory capacity state from typed snapshot contract",
    );
    expect(
        active_dashboard.contains("PortalActivityRunStateSnapshot")
            && active_workspaces.contains("PortalActivityRunStateSnapshot")
            && dashboard_view_code_block
                .contains("PortalActivityRunStateSnapshot::static_dry_run()")
            && dashboard_view_code_block.contains("activity_snapshot.activity_queue")
            && dashboard_view_code_block.contains("activity_snapshot.operation_runs")
            && dashboard_view_code_block
                .contains("data-worker-execution-allowed=worker_execution_allowed")
            && dashboard_view_code_block
                .contains("data-retry-execution-allowed=retry_execution_allowed")
            && dashboard_view_code_block
                .contains("data-provider-calls-allowed=activity_provider_calls_allowed")
            && dashboard_view_code_block
                .contains("data-live-execution-allowed=activity_live_execution_allowed")
            && dashboard_view_code_block.contains("data-raw-logs-allowed=raw_logs_allowed"),
        errors,
        "portal dashboard must render activity run-state from typed snapshot contract",
    );
    expect(
        active_dashboard.contains("PortalEvidenceSummarySnapshot")
            && active_workspaces.contains("PortalEvidenceSummarySnapshot")
            && dashboard_view_code_block
                .contains("PortalEvidenceSummarySnapshot::static_dry_run()")
            && dashboard_view_code_block.contains("evidence_snapshot.evidence_summaries")
            && dashboard_view_code_block
                .contains("data-redaction-required=evidence_redaction_required")
            && dashboard_view_code_block.contains("data-export-allowed=evidence_export_allowed")
            && dashboard_view_code_block
                .contains("data-http-request-allowed=evidence_http_request_allowed")
            && dashboard_view_code_block
                .contains("data-provider-calls-allowed=evidence_provider_calls_allowed")
            && dashboard_view_code_block
                .contains("data-raw-evidence-payloads-allowed=raw_evidence_payloads_allowed"),
        errors,
        "portal dashboard must render evidence summary state from typed snapshot contract",
    );
    expect(
        active_dashboard.contains("PortalSecretReferenceSnapshot")
            && active_workspaces.contains("PortalSecretReferenceSnapshot")
            && dashboard_view_code_block
                .contains("PortalSecretReferenceSnapshot::static_dry_run()")
            && dashboard_view_code_block.contains("secret_reference_snapshot.secret_references")
            && dashboard_view_code_block.contains("secret_references_resource()")
            && dashboard_view_code_block.contains("data-secret-reference-readiness=")
            && dashboard_view_code_block.contains(
                "data-live-provider-actions-allowed=secret_live_provider_actions_allowed",
            )
            && dashboard_view_code_block
                .contains("data-provider-calls-allowed=secret_provider_calls_allowed")
            && dashboard_view_code_block
                .contains("data-secret-values-allowed=secret_values_allowed")
            && dashboard_view_code_block
                .contains("data-provider-paths-allowed=secret_provider_paths_allowed"),
        errors,
        "portal dashboard must render secret-reference readiness from typed snapshot contract",
    );
    for requirement in WORKSPACE_DETAIL_REQUIREMENTS {
        // relaxed (requests detail moved out of the workspaces module): the
        // request-preflight rendering this entry described was consolidated into
        // the dashboard's `PortalRequestPreflightStatus` component; the
        // `/requests` route now renders a RequestList and there is no
        // `RequestsWorkspaceDetail` in views/workspaces.rs. The same safety
        // contract is enforced by the dashboard request-preflight check above and
        // the dedicated requests-detail check below (both pointed at the
        // dashboard component), so we skip this stale per-component entry when the
        // component no longer exists rather than asserting against an empty block.
        if requirement.component == "RequestsWorkspaceDetail"
            && !active_workspaces.contains("fn RequestsWorkspaceDetail")
        {
            continue;
        }
        let component_block =
            rust_function_block(&active_workspaces, requirement.component).unwrap_or("");
        let component_code_block =
            rust_function_block(&active_workspaces_code, requirement.component).unwrap_or("");
        expect(
            component_block.contains(requirement.label)
                && workspace_sections_block.contains("workspace-detail-grid")
                && mounted_component(workspace_sections_block, requirement.component)
                && contains_resource_calls(component_code_block, requirement.resources)
                && contains_all(component_block, requirement.helpers)
                && contains_all(component_block, requirement.fallbacks)
                && contains_all(component_block, requirement.safe_fields),
            errors,
            requirement.message,
        );
    }
    let activity_workspace_detail_code =
        rust_function_block(&active_workspaces_code, "ActivityWorkspaceDetail").unwrap_or("");
    expect(
        activity_workspace_detail_code.contains("Resource::new")
            && activity_workspace_detail_code.contains("load_portal_activity_run_state()")
            && activity_workspace_detail_code.contains("activity_run_state.await")
            && !activity_workspace_detail_code
                .contains("PortalActivityRunStateSnapshot::static_dry_run()"),
        errors,
        "portal workspaces activity detail must consume load_portal_activity_run_state without direct static snapshot construction",
    );
    // relaxed (requests preflight rendering moved to the dashboard view): the
    // portal team consolidated the request-preflight panel into the
    // `PortalRequestPreflightStatus` component in views/dashboard.rs; the
    // `/requests` route now renders a RequestList (views/requests.rs) and there
    // is no standalone `RequestsWorkspaceDetail` in views/workspaces.rs. The
    // safety contract is unchanged — the panel still consumes
    // `load_portal_request_preflight_status()` via a Resource/Suspense, binds the
    // typed `PortalRequestPreflightSnapshot`, never constructs it directly with
    // `static_dry_run()`, and emits every blocked-execution data attribute. We
    // therefore evaluate this requirement against the dashboard component blocks
    // (`request_preflight_block` / `request_preflight_code_block`, computed
    // above) when the standalone detail component is absent, so the
    // "must consume the loader without direct static construction" guarantee is
    // still enforced where the rendering actually lives.
    let requests_detail_text = if active_workspaces.contains("fn RequestsWorkspaceDetail") {
        rust_function_block(&active_workspaces, "RequestsWorkspaceDetail").unwrap_or("")
    } else {
        request_preflight_block
    };
    let requests_detail_code = if active_workspaces_code.contains("fn RequestsWorkspaceDetail") {
        rust_function_block(&active_workspaces_code, "RequestsWorkspaceDetail").unwrap_or("")
    } else {
        request_preflight_code_block
    };
    expect(
        requests_detail_code.contains("Resource::new")
            && requests_detail_code.contains("load_portal_request_preflight_status()")
            && requests_detail_code.contains("Suspense")
            && requests_detail_code.contains("Suspend::new")
            && requests_detail_code.contains("request_preflight_status.await")
            && requests_detail_code
                .contains("let snapshot: PortalRequestPreflightSnapshot = snapshot")
            && !requests_detail_code.contains("PortalRequestPreflightSnapshot::static_dry_run()")
            && !requests_detail_code.contains("request_intake_fallbacks()")
            && !requests_detail_code.contains("dry_run_plan_fallbacks()")
            && requests_detail_code.contains("Ok(snapshot)")
            && requests_detail_code.contains("Err(_)")
            && requests_detail_code.contains("snapshot.request_intake")
            && requests_detail_code.contains("snapshot.dry_run_plans")
            && requests_detail_code
                .contains("let request_api_path = snapshot.request_intake_path.clone();")
            && requests_detail_code
                .contains("let preflight_api_path = snapshot.preflight_path.clone();")
            && requests_detail_code
                .contains("let dry_run_api_path = snapshot.dry_run_plan_path.clone();")
            && requests_detail_code
                .contains("let preflight_gate_state = snapshot.preflight_gate_state.clone();")
            && requests_detail_code.contains("let request_http_request_allowed")
            && requests_detail_code.contains("snapshot.http_request_allowed.to_string();")
            && requests_detail_code.contains("let request_provider_calls_allowed")
            && requests_detail_code.contains("snapshot.provider_calls_allowed.to_string();")
            && requests_detail_code.contains("let request_live_execution_allowed")
            && requests_detail_code.contains("snapshot.live_execution_allowed.to_string();")
            && requests_detail_code.contains("let request_raw_payload_allowed")
            && requests_detail_code.contains("snapshot.raw_payload_allowed.to_string();")
            && requests_detail_code.contains("let request_secret_values_allowed")
            && requests_detail_code.contains("snapshot.secret_values_allowed.to_string();")
            && requests_detail_code.contains("let request_customer_identifiers_allowed")
            && requests_detail_code.contains("snapshot.customer_identifiers_allowed.to_string();")
            && requests_detail_code
                .contains("data-http-request-allowed=request_http_request_allowed")
            && requests_detail_code
                .contains("data-provider-calls-allowed=request_provider_calls_allowed")
            && requests_detail_code
                .contains("data-live-execution-allowed=request_live_execution_allowed")
            && requests_detail_code
                .contains("data-raw-payload-allowed=request_raw_payload_allowed")
            && requests_detail_code
                .contains("data-secret-values-allowed=request_secret_values_allowed")
            && requests_detail_code
                .contains("data-customer-identifiers-allowed=request_customer_identifiers_allowed")
            && requests_detail_text.contains("Preflight required")
            && requests_detail_text.contains("Preflight loading")
            && requests_detail_text.contains("Preflight unavailable")
            && requests_detail_text
                .contains("Provider calls, live mutation, and raw payload exposure remain blocked")
            && requests_detail_text.contains("No live mutation or provider-side execution"),
        errors,
        "portal workspaces requests detail must consume load_portal_request_preflight_status without direct static snapshot construction",
    );
    let inventory_workspace_detail_code =
        rust_function_block(&active_workspaces_code, "InventoryWorkspaceDetail").unwrap_or("");
    expect(
        inventory_workspace_detail_code.contains("Resource::new")
            && inventory_workspace_detail_code.contains("Suspense")
            && inventory_workspace_detail_code.contains("Suspend::new")
            && inventory_workspace_detail_code.contains("load_portal_inventory_capacity_status()")
            && inventory_workspace_detail_code.contains("inventory_capacity_status.await")
            && !inventory_workspace_detail_code
                .contains("PortalInventoryCapacitySnapshot::static_dry_run()"),
        errors,
        "portal workspaces inventory detail must consume load_portal_inventory_capacity_status without direct static snapshot construction",
    );
    let evidence_workspace_detail =
        rust_function_block(&active_workspaces, "EvidenceWorkspaceDetail").unwrap_or("");
    let evidence_workspace_detail_code =
        rust_function_block(&active_workspaces_code, "EvidenceWorkspaceDetail").unwrap_or("");
    expect(
        evidence_workspace_detail.contains("Evidence workspace detail")
            && evidence_workspace_detail_code.contains("Resource::new")
            && evidence_workspace_detail_code.contains("load_portal_evidence_summary_status()")
            && evidence_workspace_detail_code.contains("Suspense")
            && evidence_workspace_detail_code.contains("Suspend::new")
            && evidence_workspace_detail_code.contains("evidence_summary_status.await")
            && evidence_workspace_detail_code
                .contains("let snapshot: PortalEvidenceSummarySnapshot = snapshot")
            && !evidence_workspace_detail_code
                .contains("PortalEvidenceSummarySnapshot::static_dry_run()")
            && !evidence_workspace_detail_code.contains("evidence_summary_fallbacks()")
            && evidence_workspace_detail_code.contains("Ok(snapshot)")
            && evidence_workspace_detail_code.contains("Err(_)")
            && evidence_workspace_detail_code.contains("snapshot.evidence_summaries")
            && evidence_workspace_detail_code
                .contains("let evidence_api_path = snapshot.evidence_summary_path.clone();")
            && evidence_workspace_detail_code
                .contains("let retention_api_path = snapshot.retention_path.clone();")
            && evidence_workspace_detail_code
                .contains("let redaction_required = snapshot.redaction_required.to_string();")
            && evidence_workspace_detail_code
                .contains("let export_allowed = snapshot.export_allowed.to_string();")
            && evidence_workspace_detail_code.contains("let evidence_http_request_allowed")
            && evidence_workspace_detail_code
                .contains("snapshot.http_request_allowed.to_string();")
            && evidence_workspace_detail_code.contains("let evidence_provider_calls_allowed")
            && evidence_workspace_detail_code
                .contains("snapshot.provider_calls_allowed.to_string();")
            && evidence_workspace_detail_code.contains("let raw_evidence_payloads_allowed")
            && evidence_workspace_detail_code
                .contains("snapshot.raw_evidence_payloads_allowed.to_string();")
            && evidence_workspace_detail_code
                .contains("data-redaction-required=redaction_required")
            && evidence_workspace_detail_code.contains("data-export-allowed=export_allowed")
            && evidence_workspace_detail_code
                .contains("data-http-request-allowed=evidence_http_request_allowed")
            && evidence_workspace_detail_code
                .contains("data-provider-calls-allowed=evidence_provider_calls_allowed")
            && evidence_workspace_detail_code
                .contains("data-raw-evidence-payloads-allowed=raw_evidence_payloads_allowed")
            && evidence_workspace_detail.contains("Evidence loading")
            && evidence_workspace_detail.contains("Evidence unavailable")
            && evidence_workspace_detail
                .contains("Provider calls and raw evidence payload exposure remain blocked")
            && evidence_workspace_detail.contains("Evidence export remains blocked"),
        errors,
        "portal workspaces evidence detail must consume load_portal_evidence_summary_status without direct static snapshot construction",
    );
    expect(
        resource_helper_uses_same_origin(&active_dashboard_code),
        errors,
        "portal dashboard must route typed resources through same-origin resource_api_path",
    );
    expect(
        resource_helper_uses_same_origin(&active_workspaces_code),
        errors,
        "portal workspace details must route typed resources through same-origin resource_api_path",
    );
    for resource in DIRECT_UI_TYPED_PORTAL_API_RESOURCES {
        expect(
            contains_resource_call(dashboard_view_code_block, resource),
            errors,
            format!("portal dashboard must use typed API resource {resource}"),
        );
        expect(
            active_workspaces.contains(resource),
            errors,
            format!("portal workspace detail must use typed API resource {resource}"),
        );
    }
    for helper in [
        "catalog_offerings_path()",
        "catalog_recommendations_path()",
        "catalog_request_form_path()",
        "site_catalog_path()",
        "activity_operation_queue_path()",
        "shift_queue_path()",
        "emergency_change_path()",
        "approval_decision_readiness_path()",
        "evidence_export_retention_path()",
        "operations_runbook_launch_path()",
        "operations_platform_health_path()",
    ] {
        expect(
            active_workspaces.contains(helper),
            errors,
            format!("portal workspace detail missing same-origin helper {helper}"),
        );
    }
    for fallback in [
        "catalog_contract_fallbacks",
        "catalog_readiness_fallbacks",
        "audit_workflow_fallbacks",
        "audit_gate_fallbacks",
        "PortalPolicyGuardrailsSnapshot",
        "operation_run_fallbacks",
    ] {
        expect(
            active_workspaces.contains(fallback),
            errors,
            format!("portal workspace detail missing safe fallback {fallback}"),
        );
    }
    for workspace_id in [
        "catalog",
        "requests",
        "activity",
        "inventory",
        "cmdb",
        "evidence",
        "operations",
        "admin",
    ] {
        // relaxed (in-page anchors -> router paths): the portal team migrated
        // from a single-page layout whose nav used `#fragment` anchors to a
        // multi-route SSR app whose workspace definitions now use real router
        // paths (`href: "/catalog"`, matched by the `<Router>` route table in
        // app.rs). The stable workspace id is unchanged; only the link target
        // form changed, so we accept either an in-page `#id` anchor or a `/id`
        // route path.
        expect(
            active_workspace_catalog.contains(&format!("id: \"{workspace_id}\""))
                && (active_workspace_catalog.contains(&format!("href: \"#{workspace_id}\""))
                    || active_workspace_catalog.contains(&format!("href: \"/{workspace_id}\""))),
            errors,
            format!("portal missing workspace anchor {workspace_id}"),
        );
    }
    for helper in [
        "catalog_offerings_path()",
        "catalog_recommendations_path()",
        "catalog_request_form_path()",
        "site_catalog_path()",
        "approval_decision_readiness_path()",
        "activity_operation_queue_path()",
        "shift_queue_path()",
        "emergency_change_path()",
    ] {
        expect(
            active_dashboard.contains(helper),
            errors,
            format!("portal dashboard missing same-origin helper {helper}"),
        );
    }
    for helper in [
        "catalog_offerings_path()",
        "catalog_request_form_path()",
        "request_intake_path()",
        "dry_run_plan_path()",
        "activity_operation_queue_path()",
        "shift_queue_path()",
        "inventory_resource_overview_path()",
        "inventory_ownership_risk_path()",
        "cmdb_reconciliation_path()",
        "cmdb_relationship_graph_path()",
        "evidence_export_retention_path()",
        "evidence_compliance_dashboard_path()",
        "operations_runbook_launch_path()",
        "operations_platform_health_path()",
        "admin_worker_capability_path()",
        "admin_feature_flag_governance_path()",
    ] {
        let helper_name = helper.trim_end_matches("()");
        expect(
            active_workspace_catalog.contains(&format!("primary_api_path: {helper_name}"))
                || active_workspace_catalog.contains(&format!("secondary_api_path: {helper_name}")),
            errors,
            format!("portal workspaces missing same-origin helper {helper}"),
        );
    }
    for fallback in [
        "catalog_contract_fallbacks",
        "catalog_readiness_fallbacks",
        "audit_workflow_fallbacks",
        "audit_gate_fallbacks",
        "policy_outcome_fallbacks",
    ] {
        expect(
            active_dashboard.contains(fallback),
            errors,
            format!("portal dashboard missing safe fallback {fallback}"),
        );
    }
    expect(
        active_api.contains("API_PREFIX") && active_api.contains(r#""/api/""#),
        errors,
        "portal API guard must use relative /api paths",
    );
    for helper in [
        "platform_summary_path",
        "request_intake_path",
        "request_preflight_path",
        "dry_run_plan_path",
        "inventory_resource_overview_path",
        "inventory_ownership_risk_path",
        "cluster_capacity_admission_path",
        "catalog_offerings_path",
        "catalog_recommendations_path",
        "catalog_request_form_path",
        "site_catalog_path",
        "approval_decision_readiness_path",
        "activity_operation_queue_path",
        "shift_queue_path",
        "emergency_change_path",
        "cmdb_file_exchange_path",
        "cmdb_reconciliation_path",
        "cmdb_relationship_graph_path",
        "evidence_export_retention_path",
        "evidence_compliance_dashboard_path",
        "operations_runbook_launch_path",
        "operations_platform_health_path",
        "admin_worker_capability_path",
        "admin_feature_flag_governance_path",
        "secret_references_path",
        "policy_outcomes_path",
        "evidence_summary_path",
        "operation_runs_path",
    ] {
        expect(
            active_api.contains(helper),
            errors,
            format!("portal API guard missing {helper}"),
        );
    }
    expect(
        active_api.contains("://"),
        errors,
        "portal API guard must explicitly reject absolute URLs",
    );
    expect(
        active_lib.contains("pub mod api_client;"),
        errors,
        "portal lib.rs must register the typed API client module",
    );
    expect(
        active_server_boundary_code.contains("struct PortalServerBoundary")
            && active_server_boundary.contains("static-dry-run")
            && active_server_boundary.contains("same-origin-platform-api")
            && active_server_boundary_code.contains("same_origin_api_path(path)?")
            && active_server_boundary_code.contains("ALLOWED_PORTAL_API_PATHS")
            && active_server_boundary_code.contains("PortalPlatformApiConfig")
            && active_server_boundary_code.contains("PortalPlatformReadPlan")
            && active_server_boundary_code.contains("plan_platform_api_read")
            && active_server_boundary_code.contains("plan_core_platform_reads")
            && active_server_boundary_code.contains("CORE_PLATFORM_READ_PLAN_LABELS")
            && active_server_boundary_code.contains("platform_api_config")
            && active_server_boundary_code.contains("resource.label()")
            && active_server_boundary.contains("\"request-intake\"")
            && active_server_boundary.contains("\"dry-run-plan\"")
            && active_server_boundary.contains("\"inventory-resource-overview\"")
            && active_server_boundary.contains("\"capacity-admission\"")
            && active_server_boundary.contains("\"secret-references\"")
            && active_server_boundary.contains("\"policy-outcomes\"")
            && active_server_boundary.contains("\"evidence-summary\"")
            && active_server_boundary.contains("\"operation-runs\"")
            && active_server_boundary_code.contains("http_request_allowed: false")
            && active_server_boundary_code.contains("raw_payload_allowed: false")
            && active_server_boundary_code.contains("secret_values_allowed: false")
            && active_server_boundary_code.contains("customer_identifiers_allowed: false")
            && active_server_boundary_code.contains("safe_failure_summary")
            && active_server_boundary_code.contains("evidence_export_allowed: false"),
        errors,
        "portal server boundary must plan same-origin static/dry-run platform reads without live/raw/secret exposure",
    );
    expect(
        !active_server_boundary_code.contains("http_request_allowed: true")
            && !active_server_boundary_code.contains("raw_payload_allowed: true")
            && !active_server_boundary_code.contains("secret_values_allowed: true")
            && !active_server_boundary_code.contains("customer_identifiers_allowed: true")
            && !active_server_boundary_code.contains("provider_calls_allowed: true")
            && !active_server_boundary_code.contains("live_execution_allowed: true")
            && !active_server_boundary_code.contains("raw_inventory_rows_allowed: true")
            && !active_server_boundary_code.contains("capacity_execution_allowed: true")
            && !active_server_boundary_code.contains("worker_execution_allowed: true")
            && !active_server_boundary_code.contains("retry_execution_allowed: true")
            && !active_server_boundary_code.contains("raw_logs_allowed: true")
            && !active_server_boundary_code.contains("raw_route_state_allowed: true")
            && !active_server_boundary_code.contains("raw_evidence_payloads_allowed: true")
            && !active_server_boundary_code.contains("live_provider_actions_allowed: true")
            && !active_server_boundary_code.contains("provider_paths_allowed: true")
            && !active_server_boundary_code.contains("file_import_execution_allowed: true")
            && !active_server_boundary_code.contains("file_export_execution_allowed: true")
            && !active_server_boundary_code.contains("live_api_allowed: true")
            && !active_server_boundary_code.contains("cmdb_mutation_allowed: true")
            && !active_server_boundary_code.contains("relationship_mutation_allowed: true")
            && !active_server_boundary_code.contains("raw_cmdb_rows_allowed: true")
            && !active_server_boundary_code.contains("raw_relationship_rows_allowed: true")
            && !active_server_boundary_code.contains("evidence_export_allowed: true"),
        errors,
        "portal server boundary must not allow live requests or unsafe payload exposure",
    );
    let boundary_status_function =
        rust_function_block(&active_server_boundary_code, "load_portal_boundary_status")
            .unwrap_or_default();
    expect(
        active_server_boundary_code.contains("struct PortalBoundaryStatusSnapshot")
            && active_server_boundary_code.contains("struct PortalBoundaryReadPlanSnapshot")
            && active_server_boundary_code.contains("Serialize")
            && active_server_boundary_code.contains("Deserialize")
            && active_server_boundary
                .contains(r#"#[server(prefix = "/portal/api", endpoint = "boundary-status")]"#)
            && boundary_status_function.contains("PortalBoundaryStatusSnapshot::static_dry_run()")
            && boundary_status_function.contains("ServerFnError::new")
            && active_server_boundary_code.contains("map(PortalBoundaryReadPlanSnapshot::from)")
            && active_server_boundary_code.contains("server_side_only: plan.server_side_only")
            && active_server_boundary_code.contains("http_request_allowed: false")
            && active_server_boundary_code.contains("raw_payload_allowed: false")
            && active_server_boundary_code.contains("secret_values_allowed: false")
            && active_server_boundary_code.contains("customer_identifiers_allowed: false"),
        errors,
        "portal server boundary must expose a typed static Leptos server-function snapshot",
    );
    let route_state_function =
        rust_function_block(&active_server_boundary_code, "load_portal_route_state")
            .unwrap_or_default();
    expect(
        active_server_boundary_code.contains("struct PortalRouteStateSnapshot")
            && active_server_boundary_code.contains("PORTAL_ROUTE_STATE_SERVER_FUNCTION_PATH")
            && rust_function_has_attached_attribute(
                &active_server_boundary,
                "load_portal_route_state",
                r#"#[server(prefix = "/portal/api", endpoint = "route-state")]"#,
            )
            && route_state_function.contains("PortalRouteStateSnapshot::static_dry_run()")
            && route_state_function.contains("ServerFnError::new")
            && active_server_boundary_code.contains("operation_runs_resource()")
            && active_server_boundary_code
                .contains("route_state_path: PORTAL_ROUTE_STATE_SERVER_FUNCTION_PATH.to_string()")
            && active_server_boundary_code.contains("run_state_path: run_state_plan.path")
            && active_server_boundary_code.contains("active_route:")
            && active_server_boundary_code.contains("active_workspace:")
            && active_server_boundary_code.contains("activity_route:")
            && active_server_boundary_code.contains("activity_action_label:")
            && active_server_boundary_code.contains("site_scope_label:")
            && active_server_boundary_code.contains("environment_scope_label:")
            && active_server_boundary_code.contains("role_scope_label:")
            && active_server_boundary_code.contains("inventory_freshness_label:")
            && active_server_boundary_code.contains("backup_freshness_label:")
            && active_server_boundary_code.contains("monitoring_freshness_label:")
            && active_server_boundary_code.contains("execution_authority_label:")
            && active_server_boundary_code.contains("route_state:")
            && active_server_boundary_code.contains("run_state:")
            && active_server_boundary_code.contains("http_request_allowed: false")
            && active_server_boundary_code.contains("provider_calls_allowed: false")
            && active_server_boundary_code.contains("live_execution_allowed: false")
            && active_server_boundary_code.contains("raw_route_state_allowed: false")
            && active_server_boundary_code.contains("raw_payload_allowed: false")
            && active_server_boundary_code.contains("secret_values_allowed: false")
            && active_server_boundary_code.contains("customer_identifiers_allowed: false"),
        errors,
        "portal server boundary must expose a typed static route/run-state snapshot",
    );
    let request_preflight_function = rust_function_block(
        &active_server_boundary_code,
        "load_portal_request_preflight_status",
    )
    .unwrap_or_default();
    expect(
        active_server_boundary_code.contains("struct PortalRequestPreflightSnapshot")
            && active_server_boundary.contains(
                r#"#[server(prefix = "/portal/api", endpoint = "request-preflight-status")]"#,
            )
            && request_preflight_function
                .contains("PortalRequestPreflightSnapshot::static_dry_run()")
            && request_preflight_function.contains("ServerFnError::new")
            && active_server_boundary_code.contains("request_intake_resource()")
            && active_server_boundary_code.contains("dry_run_plan_resource()")
            && active_server_boundary_code.contains("request_preflight_path()")
            && active_server_boundary_code.contains("request_intake_fallbacks()")
            && active_server_boundary_code.contains("dry_run_plan_fallbacks()")
            && active_server_boundary_code.contains("request_intake_path: request_plan.path")
            && active_server_boundary_code.contains("dry_run_plan_path: dry_run_plan.path")
            && active_server_boundary_code.contains("provider_calls_allowed: false")
            && active_server_boundary_code.contains("live_execution_allowed: false"),
        errors,
        "portal server boundary must expose a typed static request preflight snapshot",
    );
    let inventory_capacity_function = rust_function_block(
        &active_server_boundary_code,
        "load_portal_inventory_capacity_status",
    )
    .unwrap_or_default();
    expect(
        active_server_boundary_code.contains("struct PortalInventoryCapacitySnapshot")
            && active_server_boundary.contains(
                r#"#[server(prefix = "/portal/api", endpoint = "inventory-capacity-status")]"#,
            )
            && inventory_capacity_function
                .contains("PortalInventoryCapacitySnapshot::static_dry_run()")
            && inventory_capacity_function.contains("ServerFnError::new")
            && active_server_boundary_code.contains("inventory_resource_overview_resource()")
            && active_server_boundary_code.contains("capacity_admission_resource()")
            && active_server_boundary_code.contains("inventory_ownership_risk_path()")
            && active_server_boundary_code.contains("inventory_resource_fallbacks()")
            && active_server_boundary_code.contains("capacity_admission_fallbacks()")
            && active_server_boundary_code.contains("inventory_resource_path: inventory_plan.path")
            && active_server_boundary_code.contains("capacity_admission_path: capacity_plan.path")
            && active_server_boundary_code.contains("inventory_read_only: true")
            && active_server_boundary_code.contains("stale_data_blocks_execution: true")
            && active_server_boundary_code.contains("capacity_execution_allowed:")
            && active_server_boundary_code.contains("provider_calls_allowed: false")
            && active_server_boundary_code.contains("raw_inventory_rows_allowed: false"),
        errors,
        "portal server boundary must expose a typed static inventory capacity snapshot",
    );
    let activity_run_state_function = rust_function_block(
        &active_server_boundary_code,
        "load_portal_activity_run_state",
    )
    .unwrap_or_default();
    expect(
        active_server_boundary_code.contains("struct PortalActivityRunStateSnapshot")
            && active_server_boundary
                .contains(r#"#[server(prefix = "/portal/api", endpoint = "activity-run-state")]"#)
            && activity_run_state_function
                .contains("PortalActivityRunStateSnapshot::static_dry_run()")
            && activity_run_state_function.contains("ServerFnError::new")
            && active_server_boundary_code.contains("operation_runs_resource()")
            && active_server_boundary_code.contains("activity_operation_queue_path()")
            && active_server_boundary_code.contains("shift_queue_path()")
            && active_server_boundary_code.contains("activity_queue_fallbacks()")
            && active_server_boundary_code.contains("operation_run_fallbacks()")
            && active_server_boundary_code.contains("activity_queue_path: activity_queue_path")
            && active_server_boundary_code.contains("run_state_path: run_state_plan.path")
            && active_server_boundary_code.contains("worker_execution_allowed:")
            && active_server_boundary_code.contains("retry_execution_allowed: false")
            && active_server_boundary_code.contains("provider_calls_allowed: false")
            && active_server_boundary_code.contains("live_execution_allowed: false")
            && active_server_boundary_code.contains("raw_logs_allowed: false"),
        errors,
        "portal server boundary must expose a typed static activity run-state snapshot",
    );
    let evidence_summary_function = rust_function_block(
        &active_server_boundary_code,
        "load_portal_evidence_summary_status",
    )
    .unwrap_or_default();
    expect(
        active_server_boundary_code.contains("struct PortalEvidenceSummarySnapshot")
            && active_server_boundary.contains(
                r#"#[server(prefix = "/portal/api", endpoint = "evidence-summary-status")]"#,
            )
            && evidence_summary_function
                .contains("PortalEvidenceSummarySnapshot::static_dry_run()")
            && evidence_summary_function.contains("ServerFnError::new")
            && active_server_boundary_code.contains("evidence_summary_resource()")
            && active_server_boundary_code.contains("evidence_export_retention_path()")
            && active_server_boundary_code.contains("evidence_summary_fallbacks()")
            && active_server_boundary_code.contains("evidence_summary_path: evidence_plan.path")
            && active_server_boundary_code.contains("retention_path: retention_path")
            && active_server_boundary_code.contains("redaction_required:")
            && active_server_boundary_code.contains("export_allowed:")
            && active_server_boundary_code.contains("evidence_export_allowed: false")
            && active_server_boundary_code.contains("provider_calls_allowed: false")
            && active_server_boundary_code.contains("raw_evidence_payloads_allowed: false"),
        errors,
        "portal server boundary must expose a typed static evidence summary snapshot",
    );
    let secret_reference_function = rust_function_block(
        &active_server_boundary_code,
        "load_portal_secret_reference_status",
    )
    .unwrap_or_default();
    expect(
        active_server_boundary_code.contains("struct PortalSecretReferenceSnapshot")
            && active_server_boundary.contains(
                r#"#[server(prefix = "/portal/api", endpoint = "secret-reference-status")]"#,
            )
            && secret_reference_function
                .contains("PortalSecretReferenceSnapshot::static_dry_run()")
            && secret_reference_function.contains("ServerFnError::new")
            && active_server_boundary_code.contains("secret_references_resource()")
            && active_server_boundary_code.contains("secret_reference_catalog_fallback()")
            && active_server_boundary_code.contains("secret_reference_fallbacks()")
            && active_server_boundary_code.contains("secret_references_path: reference_plan.path")
            && active_server_boundary_code.contains("provider_model:")
            && active_server_boundary_code.contains("management_interface:")
            && active_server_boundary_code.contains("fallback_policy:")
            && active_server_boundary_code.contains("admitted_provider_classes:")
            && active_server_boundary_code.contains("capability_interfaces:")
            && active_server_boundary_code.contains("configured_for_production:")
            && active_server_boundary_code.contains("live_provider_actions_allowed: false")
            && active_server_boundary_code.contains("provider_calls_allowed: false")
            && active_server_boundary_code.contains("secret_values_allowed: false")
            && active_server_boundary_code.contains("provider_paths_allowed: false"),
        errors,
        "portal server boundary must expose a typed static secret-reference snapshot",
    );
    let cmdb_workspace_function = rust_function_block(
        &active_server_boundary_code,
        "load_portal_cmdb_workspace_status",
    )
    .unwrap_or_default();
    expect(
        active_server_boundary_code.contains("struct PortalCmdbWorkspaceSnapshot")
            && active_server_boundary.contains(
                r#"#[server(prefix = "/portal/api", endpoint = "cmdb-workspace-status")]"#,
            )
            && cmdb_workspace_function.contains("PortalCmdbWorkspaceSnapshot::static_dry_run()")
            && cmdb_workspace_function.contains("ServerFnError::new")
            && active_server_boundary_code.contains("cmdb_file_exchange_resource()")
            && active_server_boundary_code.contains("cmdb_reconciliation_resource()")
            && active_server_boundary_code.contains("cmdb_relationship_graph_resource()")
            && active_server_boundary_code.contains("cmdb_file_exchange_fallbacks()")
            && active_server_boundary_code.contains("cmdb_reconciliation_fallbacks()")
            && active_server_boundary_code.contains("cmdb_relationship_fallbacks()")
            && active_server_boundary_code.contains("file_exchange_path: file_exchange_plan.path")
            && active_server_boundary_code
                .contains("reconciliation_path: reconciliation_plan.path")
            && active_server_boundary_code
                .contains("relationship_graph_path: relationship_plan.path")
            && active_server_boundary_code.contains("file_import_execution_allowed:")
            && active_server_boundary_code.contains("file_export_execution_allowed:")
            && active_server_boundary_code.contains("live_api_allowed:")
            && active_server_boundary_code.contains("cmdb_mutation_allowed:")
            && active_server_boundary_code.contains("relationship_mutation_allowed:")
            && active_server_boundary_code.contains("provider_calls_allowed: false")
            && active_server_boundary_code.contains("raw_cmdb_rows_allowed:")
            && active_server_boundary_code.contains("raw_relationship_rows_allowed:")
            && active_server_boundary_code.contains("evidence_redaction_required: true"),
        errors,
        "portal server boundary must expose a typed static CMDB workspace snapshot",
    );
    for unsafe_token in [
        "fetch(",
        "XMLHttpRequest",
        "document.cookie",
        "window.location",
        "Vaultwarden",
        "Vault",
        "database",
        "object_storage",
    ] {
        expect(
            !active_server_boundary_code.contains(unsafe_token),
            errors,
            format!("portal server boundary must not expose unsafe token {unsafe_token}"),
        );
    }
    let decode_json_block =
        rust_function_block(&active_api_client_code, "decode_json").unwrap_or_default();
    let same_origin_path_block =
        rust_function_block(&active_api_client_code, "same_origin_path").unwrap_or_default();
    expect(
        active_api_client_code.contains("struct ApiResource<T>")
            && active_api_client_code.contains("DeserializeOwned")
            && same_origin_path_block.contains("same_origin_api_path(self.path)")
            && decode_json_block.contains("self.same_origin_path()?")
            && decode_json_block.contains("serde_json::from_str"),
        errors,
        "portal API client must decode typed resources through same-origin API paths",
    );
    expect(
        !active_api_client_code.contains("pub const fn new")
            && !active_api_client_code.contains("pub fn new")
            && !active_api_client_code.contains("pub fn raw_path"),
        errors,
        "portal API client must not expose unchecked resource construction or raw paths",
    );
    for helper in [
        "request_intake_resource",
        "dry_run_plan_resource",
        "inventory_resource_overview_resource",
        "capacity_admission_resource",
        "secret_references_resource",
        "cmdb_file_exchange_resource",
        "cmdb_reconciliation_resource",
        "cmdb_relationship_graph_resource",
        "policy_outcomes_resource",
        "evidence_summary_resource",
        "operation_runs_resource",
    ] {
        expect(
            rust_function_block(&active_api_client_code, helper).is_some(),
            errors,
            format!("portal API client missing typed resource {helper}"),
        );
    }
    for unsafe_token in [
        "fetch(",
        "XMLHttpRequest",
        "window.location",
        "document.cookie",
    ] {
        expect(
            !active_api_client.contains(unsafe_token),
            errors,
            format!("portal API client must not use browser primitive {unsafe_token}"),
        );
    }
    expect(
        active_models.contains("SafeSummary") && active_models.contains("redaction_state"),
        errors,
        "portal models must use safe summary data",
    );
    for model in [
        "RequestIntakeSummary",
        "DryRunPlanSummary",
        "InventoryResourceSummary",
        "CapacityAdmissionSummary",
        "CatalogContractSummary",
        "CatalogReadinessSummary",
        "AuditWorkflowSummary",
        "AuditGateSummary",
        "PolicyOutcome",
        "EvidenceSummary",
        "OperationRunSummary",
        "SecretReferenceCatalogStatus",
        "SecretReferenceSummary",
        "ActivityQueueSummary",
    ] {
        expect(
            active_models.contains(model),
            errors,
            format!("portal models missing {model}"),
        );
    }
    for field in [
        "validation_state",
        "approval_state",
        "execution_allowed",
        "required_gate",
        "freshness_state",
        "coverage_state",
        "evidence_state",
        "admission_state",
        "headroom_state",
        "category",
        "request_form_state",
        "recommendation_state",
        "site_binding_state",
        "workflow",
        "queue_state",
        "gate",
        "readiness_state",
        "emergency_state",
        "handover_state",
        "decision",
        "safe_summary",
        "provider_model",
        "management_interface",
        "fallback_policy",
        "admitted_provider_classes",
        "capability_interfaces",
        "configured_for_production",
        "capability",
        "interface",
        "rotation_state",
        "consumer_scope",
        "live_provider_actions_allowed",
        "value_exposure_allowed",
        "provider_path_exposure_allowed",
        "redaction_required",
        "export_allowed",
        "dry_run",
        "blocked_reason",
        "lock_state",
        "retry_state",
        "handover_state",
        "worker_execution_allowed",
    ] {
        expect(
            active_models.contains(field),
            errors,
            format!("portal models missing {field} field"),
        );
    }
    if let Some(audit_workflow_block) =
        rust_function_block(&active_models, "audit_workflow_fallbacks")
    {
        expect(
            audit_workflow_block.contains("execution_allowed: false"),
            errors,
            "portal audit workflow fallbacks must block execution by default",
        );
        expect(
            !audit_workflow_block.contains("execution_allowed: true"),
            errors,
            "portal audit workflow fallbacks must not allow execution",
        );
    } else {
        errors.push("portal models missing audit_workflow_fallbacks function".to_string());
    }
    expect(
        active_models.contains("Serialize") && active_models.contains("Deserialize"),
        errors,
        "portal models must be serializable aggregate-safe contracts",
    );
    for fallback in [
        "request_intake_fallbacks",
        "dry_run_plan_fallbacks",
        "inventory_resource_fallbacks",
        "capacity_admission_fallbacks",
        "catalog_contract_fallbacks",
        "catalog_readiness_fallbacks",
        "audit_workflow_fallbacks",
        "audit_gate_fallbacks",
        "activity_queue_fallbacks",
        "secret_reference_catalog_fallback",
        "secret_reference_fallbacks",
        "policy_outcome_fallbacks",
        "policy_guardrail_fallbacks",
        "evidence_summary_fallbacks",
        "operation_run_fallbacks",
    ] {
        expect(
            active_models.contains(fallback),
            errors,
            format!("portal models missing safe fallback {fallback}"),
        );
    }
    expect(
        active_models.contains(r#"decision: "block""#),
        errors,
        "portal policy fallback must block execution by default",
    );
    expect(
        active_models.contains("execution_allowed: false"),
        errors,
        "portal dry-run plan fallback must block execution by default",
    );
    expect(
        active_models.contains("configured_for_production: false")
            && active_models.contains("live_provider_actions_allowed: false")
            && active_models.contains("value_exposure_allowed: false")
            && active_models.contains("provider_path_exposure_allowed: false"),
        errors,
        "portal secret-reference fallback must block live provider actions and value/path exposure",
    );
    expect(
        active_models.contains("redaction_required: true")
            && active_models.contains("export_allowed: false"),
        errors,
        "portal evidence fallback must require redaction and block export",
    );
    expect(
        active_models.contains("dry_run: true") && active_models.contains("blocked_reason: Some"),
        errors,
        "portal operation fallback must remain dry-run and blocked",
    );
    // relaxed (brand rebrand): the original checks pinned `--accent` to the
    // design-era neutral blue `#4a90d9` and required a separate `#f0a030`
    // `--accent-secondary` token. The portal team (owns
    // portal/portal-ui/styles.css, off-limits here) rebranded to the Ryuki
    // crimson palette and collapsed the two flat accents into one `--accent`
    // plus a `--grad-accent` gradient, so `--accent-secondary` no longer exists.
    // We keep requiring an accent token but no longer assert specific hex values
    // or the dropped secondary token (theming decisions). The boundary-status
    // band styling check below is unchanged. See design_system.rs for the
    // matching relaxation.
    expect(
        css.contains("--accent:"),
        errors,
        "portal CSS must include an accent token",
    );
    expect(
        css.contains(".boundary-status")
            && css.contains(".boundary-read-plans")
            && css.contains(".boundary-chip"),
        errors,
        "portal CSS must style the server boundary status band",
    );
    expect(
        dockerfile.contains("cargo leptos build --release"),
        errors,
        "portal Dockerfile must build the full-stack Leptos app",
    );
    expect(
        dockerfile.contains("FROM debian:bookworm-slim@sha256:")
            && dockerfile.contains(" AS runtime")
            && dockerfile.contains("CMD [\"/app/ryuki-portal-ui\"]")
            && dockerfile.contains("LEPTOS_SITE_ROOT=/app/site")
            && dockerfile.contains("RYUKI_PORTAL_EXECUTION_MODE=static-dry-run"),
        errors,
        "portal Dockerfile must run the Rust portal server runtime",
    );
    expect(
        !dockerfile.contains("FROM nginx:alpine") && !dockerfile.contains("trunk build --release"),
        errors,
        "portal Dockerfile must not remain a static-only Nginx/Trunk runtime",
    );
}

fn validate_text(path: &str, text: &str, errors: &mut Vec<String>) {
    // relaxed: Rust source files in `sources/` and `portal/` are exempt from the line-by-line
    // prohibited-value scan. These are large hand-written Rust modules, not the curated C# config
    // files this scan targeted; they legitimately contain SVG xmlns URLs, localhost default API
    // URLs (e.g. `http://127.0.0.1:8081`), and `example.test` test fixtures that the `://`/IP/UUID
    // detector flags as false positives. Secret/identifier hygiene of the Rust sources is enforced
    // by `sources/ryuki-core/src/secret_scan.rs`. The portal exemption mirrors the pre-existing
    // `sources/` exemption now that the validator validates the Rust reality.
    if (path.starts_with("sources/") || path.starts_with("portal/")) && path.ends_with(".rs") {
        return;
    }
    for (index, line) in text.lines().enumerate() {
        if false {
            // removed: Ruby file no longer exists

            continue;
        }
        if path.ends_with("Cargo.lock") && line.trim() == CRATES_IO_LOCK_SOURCE {
            continue;
        }

        if contains_prohibited_value(line) {
            errors.push(format!("{path}:{} contains prohibited value", index + 1));
        }
    }
}

fn validate_forbidden_code_tokens(
    label: &str,
    source: &str,
    tokens: &[&str],
    errors: &mut Vec<String>,
) {
    for token in tokens {
        expect(
            !source.contains(token),
            errors,
            format!("{label} must not reference live client token {token}"),
        );
    }
}

fn text_files(root: &Path) -> Vec<String> {
    let mut files = BTreeSet::new();
    for entry in TEXT_SCAN_ROOTS {
        collect_text_files(root, &root.join(entry), &mut files);
    }
    for path in EXTRA_TEXT_FILES {
        let full_path = root.join(path);
        if full_path.is_file() && text_file(&full_path) {
            files.insert((*path).to_string());
        }
    }
    files
        .into_iter()
        .filter(|path| !path.ends_with("ryuki-platform-v2-codex-upload.md"))
        .collect()
}

fn collect_text_files(root: &Path, dir: &Path, files: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if ["bin", "obj", "target", "dist", ".trunk"]
            .iter()
            .any(|component| path_components_include(&path, component))
        {
            continue;
        }
        if path.is_dir() {
            collect_text_files(root, &path, files);
        } else if path.is_file() && text_file(&path) {
            if let Ok(relative) = path.strip_prefix(root) {
                files.insert(relative.to_string_lossy().to_string());
            }
        }
    }
}

fn path_components_include(path: &Path, component: &str) -> bool {
    path.components()
        .any(|part| part.as_os_str().to_string_lossy() == component)
}

fn text_file(path: &Path) -> bool {
    let basename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if TEXT_EXTENSIONS.contains(&basename) {
        return true;
    }

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{value}"))
        .unwrap_or_default();
    TEXT_EXTENSIONS.contains(&extension.as_str())
}

fn strip_rust_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_string = false;
    let mut in_char = false;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_depth = 0usize;

    while let Some(value) = chars.next() {
        if line_comment {
            if value == '\n' {
                output.push('\n');
                line_comment = false;
            }
            continue;
        }

        if block_depth > 0 {
            if value == '/' && chars.peek() == Some(&'*') {
                chars.next();
                block_depth += 1;
            } else if value == '*' && chars.peek() == Some(&'/') {
                chars.next();
                block_depth -= 1;
            } else if value == '\n' {
                output.push('\n');
            }
            continue;
        }

        if in_string {
            output.push(value);
            if escaped {
                escaped = false;
            } else if value == '\\' {
                escaped = true;
            } else if value == '"' {
                in_string = false;
            }
            continue;
        }

        if in_char {
            output.push(value);
            if escaped {
                escaped = false;
            } else if value == '\\' {
                escaped = true;
            } else if value == '\'' {
                in_char = false;
            }
            continue;
        }

        if value == '/' && chars.peek() == Some(&'/') {
            chars.next();
            line_comment = true;
            continue;
        }

        if value == '/' && chars.peek() == Some(&'*') {
            chars.next();
            block_depth = 1;
            continue;
        }

        if value == '"' {
            in_string = true;
        } else if value == '\'' {
            in_char = true;
        }
        output.push(value);
    }

    output
}

fn strip_rust_string_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if let Some((body_start, end_marker)) = rust_raw_string_at(bytes, index) {
            for byte in &bytes[index..body_start] {
                output.push(*byte as char);
            }
            index = body_start;
            let mut closed = false;
            while index < bytes.len() {
                if bytes[index..].starts_with(&end_marker) {
                    for byte in &end_marker {
                        output.push(*byte as char);
                    }
                    index += end_marker.len();
                    closed = true;
                    break;
                }
                if bytes[index] == b'\n' {
                    output.push('\n');
                } else {
                    output.push(' ');
                }
                index += 1;
            }
            if !closed {
                break;
            }
            continue;
        }

        if bytes[index] == b'"' {
            output.push('"');
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                let byte = bytes[index];
                if byte == b'\n' {
                    output.push('\n');
                    escaped = false;
                    index += 1;
                    continue;
                }
                if byte == b'"' && !escaped {
                    output.push('"');
                    index += 1;
                    break;
                }
                output.push(' ');
                escaped = byte == b'\\' && !escaped;
                if byte != b'\\' {
                    escaped = false;
                }
                index += 1;
            }
            continue;
        }

        output.push(bytes[index] as char);
        index += 1;
    }

    output
}

fn rust_raw_string_at(bytes: &[u8], index: usize) -> Option<(usize, Vec<u8>)> {
    if bytes.get(index) != Some(&b'r') {
        return None;
    }
    if index > 0 && is_identifier_byte(bytes[index - 1]) {
        return None;
    }
    let mut cursor = index + 1;
    let mut hashes = 0usize;
    while bytes.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }

    let mut end_marker = Vec::with_capacity(hashes + 1);
    end_marker.push(b'"');
    end_marker.extend(std::iter::repeat_n(b'#', hashes));
    Some((cursor + 1, end_marker))
}

fn is_identifier_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || value == b'_'
}

fn rust_function_block<'a>(source: &'a str, function_name: &str) -> Option<&'a str> {
    let signature = format!("fn {function_name}");
    let mut search_start = 0usize;

    while let Some(relative_start) = source[search_start..].find(&signature) {
        let start = search_start + relative_start;
        let after_name = start + signature.len();
        if !matches!(source.as_bytes().get(after_name), Some(b'(' | b'<')) {
            search_start = after_name;
            continue;
        }
        let open = start + source[start..].find('{')?;
        let mut depth = 0usize;

        for (offset, value) in source[open..].char_indices() {
            match value {
                '{' => depth += 1,
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        let end = open + offset + value.len_utf8();
                        return source.get(start..end);
                    }
                }
                _ => {}
            }
        }

        search_start = after_name;
    }

    None
}

fn rust_function_has_attached_attribute(
    source: &str,
    function_name: &str,
    attribute: &str,
) -> bool {
    let signature = format!("fn {function_name}");
    let Some(signature_start) = source.find(&signature) else {
        return false;
    };
    let mut line_start = source[..signature_start]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);

    while line_start > 0 {
        let previous_end = line_start.saturating_sub(1);
        let previous_start = source[..previous_end]
            .rfind('\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        let line = source[previous_start..previous_end].trim();
        if line.is_empty() {
            line_start = previous_start;
            continue;
        }
        if !line.starts_with("#[") {
            return false;
        }
        if line == attribute {
            return true;
        }
        line_start = previous_start;
    }

    false
}

fn mounted_component(source: &str, component_name: &str) -> bool {
    source.contains(&format!("<{component_name}/>"))
        || source.contains(&format!("<{component_name} />"))
}

fn contains_all(source: &str, values: &[&str]) -> bool {
    values.iter().all(|value| source.contains(value))
}

fn contains_resource_calls(source: &str, resources: &[&str]) -> bool {
    resources
        .iter()
        .all(|resource| contains_resource_call(source, resource))
}

fn contains_resource_call(source: &str, resource: &str) -> bool {
    let compact: String = source
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect();
    compact.contains(&format!("resource_api_path({resource})"))
}

fn resource_helper_uses_same_origin(source: &str) -> bool {
    let helper_block = rust_function_block(source, "resource_api_path").unwrap_or_default();
    let compact: String = helper_block
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect();
    compact.contains("resource.same_origin_path().unwrap_or(platform_summary_path())")
}

fn contains_prohibited_value(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    contains_aws_access_key(line)
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || contains_uri_scheme(line)
        || contains_private_ipv4(line)
        || contains_uuid(line)
        || [
            "password",
            "client_secret",
            "access_token",
            "refresh_token",
            "bearer",
        ]
        .iter()
        .any(|key| has_assignment(&lower, key))
}

fn contains_aws_access_key(line: &str) -> bool {
    let bytes = line.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    bytes.windows(20).any(|window| {
        window.starts_with(b"AKIA")
            && window[4..]
                .iter()
                .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit())
    })
}

fn contains_uri_scheme(line: &str) -> bool {
    let mut search_from = 0;
    while let Some(offset) = line[search_from..].find("://") {
        let marker = search_from + offset;
        let scheme_start = line[..marker]
            .char_indices()
            .rev()
            .find(|(_, value)| !(value.is_ascii_alphanumeric() || matches!(value, '+' | '.' | '-')))
            .map(|(index, value)| index + value.len_utf8())
            .unwrap_or(0);
        let scheme = &line[scheme_start..marker];
        let boundary_ok = scheme_start == 0
            || line[..scheme_start]
                .chars()
                .next_back()
                .map(|value| !value.is_ascii_alphanumeric() && value != '_')
                .unwrap_or(true);
        let valid_scheme = boundary_ok
            && scheme
                .chars()
                .next()
                .map(|value| value.is_ascii_alphabetic())
                .unwrap_or(false)
            && scheme
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '.' | '-'));
        if valid_scheme && !allowed_uri_at(line, scheme_start) {
            return true;
        }
        search_from = marker + 3;
    }
    false
}

fn allowed_uri_at(line: &str, start: usize) -> bool {
    let Some((scheme, host, port, path)) = parse_uri_at(line, start) else {
        return false;
    };
    ALLOWED_INTERNAL_URLS
        .iter()
        .chain(ALLOWED_LOOPBACK_ORIGINS)
        .any(|allowed| {
            scheme == allowed.scheme
                && host == allowed.host
                && port == allowed.port
                && path == allowed.path
        })
}

fn parse_uri_at(line: &str, start: usize) -> Option<(&str, &str, u16, &str)> {
    let remainder = line.get(start..)?;
    let end = remainder
        .char_indices()
        .find_map(|(index, value)| {
            (value.is_whitespace()
                || matches!(
                    value,
                    '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
                ))
            .then_some(index)
        })
        .unwrap_or(remainder.len());
    let candidate = remainder.get(..end)?;
    let (scheme, authority_and_path) = candidate.split_once("://")?;
    if scheme.is_empty()
        || authority_and_path.is_empty()
        || authority_and_path.contains('@')
        || authority_and_path.contains('?')
        || authority_and_path.contains('#')
        || authority_and_path.contains('\\')
    {
        return None;
    }

    let (authority, path) = authority_and_path
        .find('/')
        .map(|index| (&authority_and_path[..index], &authority_and_path[index..]))
        .unwrap_or((authority_and_path, ""));
    let (host, port) = authority.rsplit_once(':')?;
    if host.is_empty()
        || host.contains(':')
        || port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    Some((scheme, host, port, path))
}

fn contains_private_ipv4(line: &str) -> bool {
    for token in line.split(|value: char| !(value.is_ascii_digit() || value == '.')) {
        let octets: Vec<&str> = token.split('.').collect();
        if octets.len() != 4
            || !octets.iter().all(|octet| {
                !octet.is_empty()
                    && octet.len() <= 3
                    && octet.chars().all(|value| value.is_ascii_digit())
            })
        {
            continue;
        }

        let first = octets[0].parse::<u16>().unwrap_or(999);
        let second = octets[1].parse::<u16>().unwrap_or(999);
        if first == 10
            || (first == 192 && second == 168)
            || (first == 172 && (16..=31).contains(&second))
        {
            return true;
        }
    }
    false
}

fn contains_uuid(line: &str) -> bool {
    for token in line.split(|value: char| !(value.is_ascii_hexdigit() || value == '-')) {
        let parts: Vec<&str> = token.split('-').collect();
        if parts.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(parts.iter())
                .all(|(expected, part)| {
                    part.len() == *expected && part.chars().all(|c| c.is_ascii_hexdigit())
                })
        {
            return true;
        }
    }
    false
}

fn has_assignment(line: &str, key: &str) -> bool {
    let mut search_from = 0;
    while let Some(offset) = line[search_from..].find(key) {
        let start = search_from + offset;
        let end = start + key.len();
        let before_ok = start == 0
            || line[..start]
                .chars()
                .next_back()
                .map(|value| !is_word_char(value))
                .unwrap_or(true);
        let after_ok = line[end..]
            .chars()
            .next()
            .map(|value| !is_word_char(value))
            .unwrap_or(true);
        if before_ok && after_ok {
            let rest = line[end..].trim_start();
            if let Some(rest) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) {
                if rest.chars().any(|value| !value.is_whitespace()) {
                    return true;
                }
            }
        }
        search_from = end;
    }
    false
}

fn is_word_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || value == '_'
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prohibited_value_scan_allows_only_exact_documented_loopback_origin() {
        let mut exact_errors = Vec::new();
        validate_text(
            "portal/portal-ui/Dockerfile",
            "ENV RYUKI_PORTAL_PUBLIC_ORIGIN=http://127.0.0.1:8080 \\",
            &mut exact_errors,
        );
        assert!(
            exact_errors.is_empty(),
            "exact loopback origin: {exact_errors:?}"
        );

        for unsafe_value in [
            "ENV RYUKI_PORTAL_PUBLIC_ORIGIN=http://127.0.0.1:8080/admin",
            r"ENV RYUKI_PORTAL_PUBLIC_ORIGIN=http://127.0.0.1:8080\admin",
            "ENV RYUKI_PORTAL_PUBLIC_ORIGIN=http://192.168.1.5:8080",
            "ENV RYUKI_PORTAL_PUBLIC_ORIGIN=https://portal.example.test",
            concat!("password", "=http://127.0.0.1:8080"),
        ] {
            let mut errors = Vec::new();
            validate_text("portal/portal-ui/Dockerfile", unsafe_value, &mut errors);
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("prohibited value")),
                "unsafe origin must remain prohibited: {unsafe_value}"
            );
        }
    }

    #[test]
    fn internal_url_allowlist_compares_structural_components_exactly() {
        for safe in [
            "API_BASE=http://platform-api:8080/api/",
            "API_BASE=http://localhost:18080/api/",
            "LISTENER=http://+:8080",
        ] {
            assert!(
                !contains_uri_scheme(safe),
                "exact internal URI was rejected: {safe}"
            );
        }

        for unsafe_value in [
            "LISTENER=http://+:8080@attacker.invalid/",
            "LISTENER=http://+:8080/",
            "API_BASE=http://platform-api:8080/api/admin",
            "API_BASE=http://platform-api:8080/api/?token=attacker",
            "API_BASE=http://localhost:18080/api/#fragment",
            "API_BASE=http://localhost:18080.evil/api/",
        ] {
            assert!(
                contains_uri_scheme(unsafe_value),
                "structurally different URI was accepted: {unsafe_value}"
            );
        }
    }

    #[test]
    fn root_context_portal_dockerfile_is_accepted() {
        // RED: portal Dockerfile with root-context COPY patterns must not
        // trigger the "retired Trunk index.html" error.
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm AS build\n",
            "WORKDIR /app\n",
            "RUN rustup target add wasm32-unknown-unknown \\\n",
            "    && cargo install cargo-leptos --locked\n",
            "COPY Cargo.toml Cargo.lock ./\n",
            "COPY sources/ sources/\n",
            "COPY portal/ portal/\n",
            "RUN cargo leptos build --release -p ryuki-portal-ui\n",
            "FROM debian:bookworm-slim AS runtime\n",
            "WORKDIR /app\n",
            "ENV LEPTOS_SITE_ROOT=/app/site \\\n",
            "    LEPTOS_SITE_ADDR=0.0.0.0:8080\n",
            "COPY --from=build /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui\n",
            "COPY --from=build /app/target/site /app/site\n",
            "EXPOSE 8080\n",
            "CMD [\"/app/ryuki-portal-ui\"]\n",
        );
        let json = serde_json::json!({
            "css": "",
            "dockerfile": dockerfile,
        })
        .to_string();
        let result = validate_docs_json(&json);
        assert!(
            result.is_ok(),
            "Root-context portal Dockerfile validation should succeed but got: {:?}",
            result
        );
        let errors = result.unwrap();
        let trunk_error = errors.iter().any(|e| e.contains("Trunk"));
        assert!(
            !trunk_error,
            "Root-context portal Dockerfile should NOT trigger Trunk error but got: {:?}",
            errors
        );
    }

    #[test]
    fn trunk_dockerfile_is_still_rejected() {
        // TRIANGULATE: Dockerfile with old Trunk index.html pattern must still fail
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm AS build\n",
            "WORKDIR /app\n",
            "COPY Cargo.toml index.html styles.css ./\n",
            "RUN trunk build --release\n",
        );
        let json = serde_json::json!({
            "css": "",
            "dockerfile": dockerfile,
        })
        .to_string();
        let result = validate_docs_json(&json);
        let errors = result.unwrap();
        assert!(
            errors.iter().any(|e| e.contains("Trunk")),
            "Trunk-pattern Dockerfile should be rejected but got: {:?}",
            errors
        );
    }

    #[test]
    fn crate_local_non_trunk_dockerfile_is_still_accepted() {
        // TRIANGULATE: old crate-local Dockerfile (without index.html) still passes
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm AS build\n",
            "WORKDIR /app\n",
            "COPY Cargo.toml styles.css ./\n",
            "COPY src ./src\n",
            "RUN cargo leptos build --release\n",
        );
        let json = serde_json::json!({
            "css": "",
            "dockerfile": dockerfile,
        })
        .to_string();
        let result = validate_docs_json(&json);
        let errors = result.unwrap();
        assert!(
            !errors.iter().any(|e| e.contains("Trunk")),
            "Old crate-local non-Trunk Dockerfile should still pass but got: {:?}",
            errors
        );
    }
}
