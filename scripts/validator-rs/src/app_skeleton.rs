use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use syn::visit::Visit as _;

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
const PORTAL_CARGO_LEPTOS_INSTALL_INSTRUCTION: &str = r#"RUN ["/usr/local/cargo/bin/cargo", "install", "cargo-leptos", "--version", "0.3.7", "--locked", "--root", "/opt/ryuki-tools/cargo-leptos-0.3.7"]"#;
const PORTAL_CARGO_LEPTOS_BUILD_INSTRUCTION: &str = r#"RUN ["/opt/ryuki-tools/cargo-leptos-0.3.7/bin/cargo-leptos", "build", "--release", "-p", "ryuki-portal-ui"]"#;
const PORTAL_CARGO_LEPTOS_CRATE_BUILD_INSTRUCTION: &str =
    r#"RUN ["/opt/ryuki-tools/cargo-leptos-0.3.7/bin/cargo-leptos", "build", "--release"]"#;
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
    let portal_main = inspect_portal_main(main_rs);
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
        (dockerfile_has_active_instruction(
            dockerfile,
            "COPY --link --chown=10001:10001 Cargo.toml Cargo.lock ./",
        ) || dockerfile_has_active_instruction(
            dockerfile,
            "COPY --link --chown=10001:10001 Cargo.toml styles.css ./",
        )) && !dockerfile_has_active_instruction(
            dockerfile,
            "COPY --link --chown=10001:10001 Cargo.toml index.html styles.css ./",
        ) && !dockerfile_has_active_instruction(
            dockerfile,
            "COPY --link Cargo.toml index.html styles.css ./",
        ) && !dockerfile_has_active_instruction(
            dockerfile,
            "COPY Cargo.toml index.html styles.css ./",
        ),
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
    expect(
        portal_main.runs_axum_leptos_ssr,
        errors,
        "portal main.rs must run the Axum-backed Leptos SSR server",
    );
    expect(
        portal_main.exposes_health_routes,
        errors,
        "portal main.rs must expose exact GET /healthz and /readyz routes on the served router",
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
        dockerfile_has_active_instruction(dockerfile, PORTAL_CARGO_LEPTOS_INSTALL_INSTRUCTION)
            && (dockerfile_has_active_instruction(
                dockerfile,
                PORTAL_CARGO_LEPTOS_BUILD_INSTRUCTION,
            ) || dockerfile_has_active_instruction(
                dockerfile,
                PORTAL_CARGO_LEPTOS_CRATE_BUILD_INSTRUCTION,
            )),
        errors,
        "portal Dockerfile must build the full-stack Leptos app",
    );
    expect(
        dockerfile.contains("FROM debian:bookworm-slim@sha256:")
            && dockerfile.contains(" AS runtime")
            && dockerfile.contains("CMD [\"/app/ryuki-portal-ui\"]")
            && dockerfile.contains("LEPTOS_SITE_ROOT=/app/site")
            && dockerfile.contains("RYUKI_PORTAL_EXECUTION_MODE=static-dry-run")
            && dockerfile_has_active_instruction(
                dockerfile,
                "COPY --from=build --chown=10001:10001 /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui",
            )
            && dockerfile_has_active_instruction(
                dockerfile,
                "COPY --from=build --chown=10001:10001 /app/target/site /app/site",
            ),
        errors,
        "portal Dockerfile must run the Rust portal server runtime",
    );
    expect(
        !dockerfile.contains("FROM nginx:alpine") && !dockerfile.contains("trunk build --release"),
        errors,
        "portal Dockerfile must not remain a static-only Nginx/Trunk runtime",
    );
}

fn dockerfile_has_active_instruction(dockerfile: &str, expected: &str) -> bool {
    dockerfile.lines().any(|line| line.trim() == expected)
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

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PortalMainInspection {
    pub(crate) runs_axum_leptos_ssr: bool,
    pub(crate) plans_core_platform_reads: bool,
    pub(crate) exposes_health_routes: bool,
}

#[derive(Debug)]
struct RouterBinding {
    name: String,
    statement_index: usize,
    exposes_health_routes: bool,
}

type LocalValueLineage = usize;

#[derive(Debug)]
struct LeptosRouteBinding {
    options: String,
    context: LocalValueLineage,
}

const PORTAL_MAIN_TRUSTED_PATH_ROOTS: &[&str] =
    &["axum", "leptos", "leptos_axum", "ryuki_portal_ui", "tokio"];
const PORTAL_MAIN_WILDCARD_VALUES: &[&str] = &["get_configuration", "provide_context"];

pub(crate) fn inspect_portal_main(main_rs: &str) -> PortalMainInspection {
    let Ok(file) = syn::parse_file(main_rs) else {
        return PortalMainInspection::default();
    };
    if file.items.iter().any(|item| {
        PORTAL_MAIN_WILDCARD_VALUES
            .iter()
            .any(|name| item_binds_value_name(item, name))
            || PORTAL_MAIN_TRUSTED_PATH_ROOTS
                .iter()
                .any(|root| item_binds_type_root(item, root))
    }) {
        return PortalMainInspection::default();
    }
    let matching_mains: Vec<&syn::ItemFn> = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item_fn)
                if item_fn.sig.ident == "main"
                    && item_fn.sig.asyncness.is_some()
                    && item_fn.sig.inputs.is_empty()
                    && item_fn.sig.constness.is_none()
                    && item_fn.sig.unsafety.is_none()
                    && item_fn.sig.abi.is_none()
                    && item_fn.sig.variadic.is_none()
                    && item_fn.attrs.len() == 2
                    && item_fn.attrs.iter().any(attribute_is_cfg_ssr)
                    && item_fn.attrs.iter().any(attribute_is_tokio_main) =>
            {
                Some(item_fn)
            }
            _ => None,
        })
        .collect();
    let [main_fn] = matching_mains.as_slice() else {
        return PortalMainInspection::default();
    };

    inspect_portal_main_body(&main_fn.block)
}

fn inspect_portal_main_body(block: &syn::Block) -> PortalMainInspection {
    if block.stmts.iter().any(statement_has_attributes)
        || block.stmts.iter().any(statement_has_early_exit)
        || block.stmts.iter().any(|statement| match statement {
            syn::Stmt::Item(syn::Item::Use(item_use)) => use_tree_contains_rename(&item_use.tree),
            syn::Stmt::Item(_) | syn::Stmt::Macro(_) => true,
            _ => false,
        })
    {
        return PortalMainInspection::default();
    }
    let imports = collect_block_imports(block);
    if imports.iter().any(|path| {
        path.last()
            .is_some_and(|segment| segment == "get_configuration")
    }) || imports.iter().any(|path| {
        path.last()
            .is_some_and(|segment| segment == "provide_context")
            && !path_matches_segments(path, &["leptos", "prelude", "provide_context"])
    }) || !imported(&imports, &["axum", "Router"])
        || !imported(&imports, &["leptos_axum", "LeptosRoutes"])
        || !imported(&imports, &["leptos_axum", "generate_route_list"])
        || !imported(&imports, &["axum", "routing", "get"])
        || !imported(&imports, &["ryuki_portal_ui", "app", "App"])
        || !imported(&imports, &["ryuki_portal_ui", "app", "shell"])
        || !imported(
            &imports,
            &["ryuki_portal_ui", "server_boundary", "PortalServerBoundary"],
        )
        || !imported(&imports, &["leptos", "prelude", "*"])
    {
        return PortalMainInspection::default();
    }

    let has_context_handler = imported(
        &imports,
        &["leptos_axum", "file_and_error_handler_with_context"],
    );
    if !has_context_handler {
        return PortalMainInspection::default();
    }
    if block
        .stmts
        .iter()
        .any(|statement| statement_has_unrecognized_main_await(statement, &imports))
    {
        return PortalMainInspection::default();
    }

    let mut generated_routes = BTreeSet::new();
    let mut current_configurations = BTreeSet::new();
    let mut current_leptos_options = BTreeSet::new();
    let mut current_boundaries = BTreeSet::new();
    let mut current_public_origins = BTreeSet::new();
    let mut current_server_function_limits = BTreeSet::new();
    let mut current_server_function_routers = BTreeSet::new();
    let mut trusted_context_lineages = BTreeSet::new();
    // The canonical SSR router uses distinct clones for its route and fallback
    // callbacks. Preserve their common source binding so a valid fallback
    // cannot serve as a decoy for a different route context.
    let mut local_value_lineages = BTreeMap::new();
    let mut local_bindings = Vec::new();
    let mut routers = Vec::new();
    let mut listeners = Vec::new();
    let mut serves = Vec::new();
    let mut boundaries = Vec::new();
    let mut core_plans = Vec::new();

    for (statement_index, statement) in block.stmts.iter().enumerate() {
        if statement_assignment_targets(statement)
            .iter()
            .any(|name| local_value_lineages.contains_key(name))
        {
            return PortalMainInspection::default();
        }
        match statement {
            syn::Stmt::Local(local) => {
                let Some(name) = local_ident(&local.pat) else {
                    return PortalMainInspection::default();
                };
                if [
                    "App",
                    "Router",
                    "PortalServerBoundary",
                    "any",
                    "file_and_error_handler_with_context",
                    "generate_route_list",
                    "get",
                    "get_configuration",
                    "provide_context",
                    "protect_server_function_routes",
                    "shell",
                    "validate_live_provider_auth_posture",
                ]
                .contains(&name.as_str())
                {
                    return PortalMainInspection::default();
                }
                let Some(initializer) = local.init.as_ref().map(|init| init.expr.as_ref()) else {
                    generated_routes.remove(&name);
                    current_configurations.remove(&name);
                    current_leptos_options.remove(&name);
                    current_boundaries.remove(&name);
                    current_public_origins.remove(&name);
                    current_server_function_limits.remove(&name);
                    current_server_function_routers.remove(&name);
                    local_value_lineages.remove(&name);
                    local_bindings.push((name, statement_index));
                    continue;
                };

                let inherited_lineage = cloned_simple_ident(initializer)
                    .and_then(|source| local_value_lineages.get(&source))
                    .cloned();

                if expression_calls_core_plan(initializer, &current_boundaries) {
                    core_plans.push(statement_index);
                }
                if let Some(router) = inspect_router_initializer(
                    &name,
                    statement_index,
                    initializer,
                    &imports,
                    &generated_routes,
                    &current_leptos_options,
                    &local_value_lineages,
                    &trusted_context_lineages,
                    &current_server_function_routers,
                ) {
                    routers.push(router);
                }
                if expression_binds_tcp_listener(initializer) {
                    listeners.push((name.clone(), statement_index));
                }

                let generates_routes = expression_generates_app_routes(initializer, &imports);
                let loads_configuration = expression_loads_configuration(initializer);
                let derives_leptos_options =
                    expression_derives_leptos_options(initializer, &current_configurations);
                let creates_boundary = expression_creates_static_boundary(initializer, &imports);
                let creates_public_origin = expression_creates_public_origin(initializer, &imports);
                let creates_trusted_context = expression_creates_upstream_client(
                    initializer,
                    &imports,
                    &current_public_origins,
                );
                let creates_server_function_limits =
                    expression_creates_server_function_limits(initializer, &imports);
                let creates_server_function_router = expression_creates_server_function_router(
                    initializer,
                    &imports,
                    &current_public_origins,
                    &current_server_function_limits,
                    &local_value_lineages,
                    &trusted_context_lineages,
                );
                generated_routes.remove(&name);
                current_configurations.remove(&name);
                current_leptos_options.remove(&name);
                current_boundaries.remove(&name);
                current_public_origins.remove(&name);
                current_server_function_limits.remove(&name);
                current_server_function_routers.remove(&name);
                if generates_routes {
                    generated_routes.insert(name.clone());
                }
                if loads_configuration {
                    current_configurations.insert(name.clone());
                }
                if derives_leptos_options {
                    current_leptos_options.insert(name.clone());
                }
                if creates_boundary {
                    current_boundaries.insert(name.clone());
                    boundaries.push((name.clone(), statement_index));
                }
                if creates_public_origin {
                    current_public_origins.insert(name.clone());
                }
                if creates_trusted_context {
                    trusted_context_lineages.insert(statement_index);
                }
                if creates_server_function_limits {
                    current_server_function_limits.insert(name.clone());
                }
                if creates_server_function_router {
                    current_server_function_routers.insert(name.clone());
                }
                local_value_lineages
                    .insert(name.clone(), inherited_lineage.unwrap_or(statement_index));
                local_bindings.push((name, statement_index));
            }
            syn::Stmt::Expr(expression, _) => {
                if expression_calls_core_plan(expression, &current_boundaries) {
                    core_plans.push(statement_index);
                }
                if let Some((listener, router)) = expression_serves_router(expression) {
                    serves.push((listener, router, statement_index));
                }
            }
            syn::Stmt::Item(syn::Item::Use(_)) => {}
            syn::Stmt::Item(_) | syn::Stmt::Macro(_) => {
                return PortalMainInspection::default();
            }
        }
    }

    let mut valid_servers = Vec::new();
    for (listener_name, router_name, serve_index) in serves {
        let Some(router) = routers.iter().find(|router| {
            router.name == router_name
                && router.statement_index < serve_index
                && binding_is_current(
                    &local_bindings,
                    &router.name,
                    router.statement_index,
                    serve_index,
                )
        }) else {
            continue;
        };
        let Some((_, listener_index)) = listeners.iter().find(|(name, index)| {
            name == &listener_name
                && *index < serve_index
                && binding_is_current(&local_bindings, name, *index, serve_index)
        }) else {
            continue;
        };
        if *listener_index >= serve_index || !serve_has_success_tail(block, serve_index) {
            continue;
        }
        let has_boundary = boundaries
            .iter()
            .any(|(_, index)| *index < router.statement_index);
        if !has_boundary {
            continue;
        }

        valid_servers.push(PortalMainInspection {
            runs_axum_leptos_ssr: true,
            plans_core_platform_reads: core_plans
                .iter()
                .any(|index| *index < router.statement_index),
            exposes_health_routes: router.exposes_health_routes,
        });
    }
    match valid_servers.as_slice() {
        [inspection] => *inspection,
        _ => PortalMainInspection::default(),
    }
}

fn inspect_router_initializer(
    name: &str,
    statement_index: usize,
    initializer: &syn::Expr,
    imports: &[Vec<String>],
    generated_routes: &BTreeSet<String>,
    leptos_options: &BTreeSet<String>,
    local_value_lineages: &BTreeMap<String, LocalValueLineage>,
    trusted_context_lineages: &BTreeSet<LocalValueLineage>,
    server_function_routers: &BTreeSet<String>,
) -> Option<RouterBinding> {
    let mut methods = Vec::new();
    let mut cursor = strip_paren_group(initializer);
    while let syn::Expr::MethodCall(method) = cursor {
        methods.push(method);
        cursor = strip_paren_group(&method.receiver);
    }
    if !expression_is_router_new(cursor, imports) {
        return None;
    }
    methods.reverse();

    let mut leptos_route_index = None;
    let mut merge_index = None;
    let mut fallback_index = None;
    let mut state_index = None;
    let mut route_binding = None;
    let mut fallback_context = None;
    let mut state_options = None;
    let mut healthz_routes = 0usize;
    let mut readyz_routes = 0usize;
    let mut health_routes_are_get = true;
    for (index, method) in methods.iter().enumerate() {
        match method.method.to_string().as_str() {
            "leptos_routes_with_context" => {
                if leptos_route_index.is_some() {
                    return None;
                }
                route_binding = leptos_route_method_binding(
                    method,
                    imports,
                    generated_routes,
                    leptos_options,
                    local_value_lineages,
                    trusted_context_lineages,
                );
                route_binding.as_ref()?;
                leptos_route_index = Some(index);
            }
            "merge" => {
                if merge_index.is_some() || method.args.len() != 1 {
                    return None;
                }
                let merged = method.args.first().and_then(simple_ident)?;
                if !server_function_routers.contains(&merged) {
                    return None;
                }
                merge_index = Some(index);
            }
            "fallback" => {
                if fallback_index.is_some() || fallback_context.is_some() {
                    return None;
                }
                fallback_context = fallback_method_context(method, imports, local_value_lineages);
                fallback_context.as_ref()?;
                fallback_index = Some(index);
            }
            "with_state" => {
                if state_index.is_some() || method.args.len() != 1 {
                    return None;
                }
                state_options = method.args.first().and_then(cloned_or_simple_ident);
                state_index = Some(index);
            }
            "route" => {
                if method.args.len() != 2 {
                    return None;
                }
                if let Some(path) = method.args.first().and_then(string_literal) {
                    if path == "/healthz" {
                        healthz_routes += 1;
                        health_routes_are_get &= route_method_uses_get(method, imports);
                    } else if path == "/readyz" {
                        readyz_routes += 1;
                        health_routes_are_get &= route_method_uses_get(method, imports);
                    }
                }
            }
            "layer" => {
                if method.args.len() != 1 {
                    return None;
                }
            }
            _ => return None,
        }
    }

    let (Some(merge_index), Some(leptos_route_index), Some(fallback_index), Some(state_index)) =
        (merge_index, leptos_route_index, fallback_index, state_index)
    else {
        return None;
    };
    let route_binding = route_binding?;
    if merge_index >= leptos_route_index
        || leptos_route_index >= fallback_index
        || fallback_index >= state_index
        || state_index + 1 != methods.len()
        || Some(route_binding.options) != state_options
        || Some(route_binding.context) != fallback_context
    {
        return None;
    }

    Some(RouterBinding {
        name: name.to_string(),
        statement_index,
        exposes_health_routes: health_routes_are_get && healthz_routes == 1 && readyz_routes == 1,
    })
}

fn leptos_route_method_binding(
    method: &syn::ExprMethodCall,
    imports: &[Vec<String>],
    generated_routes: &BTreeSet<String>,
    leptos_options: &BTreeSet<String>,
    local_value_lineages: &BTreeMap<String, LocalValueLineage>,
    trusted_context_lineages: &BTreeSet<LocalValueLineage>,
) -> Option<LeptosRouteBinding> {
    if !imported(imports, &["leptos_axum", "LeptosRoutes"]) {
        return None;
    }
    if method.method != "leptos_routes_with_context" || method.args.len() != 4 {
        return None;
    }
    let routes_are_generated = method.args.iter().nth(1).is_some_and(|routes| {
        simple_ident(routes).is_some_and(|name| generated_routes.contains(&name))
            || expression_generates_app_routes(routes, imports)
    });
    if !routes_are_generated {
        return None;
    }
    let options = referenced_simple_ident(method.args.first()?)
        .filter(|name| leptos_options.contains(name))?;
    let context =
        context_provider_lineage(method.args.iter().nth(2)?, imports, local_value_lineages)?;
    if !trusted_context_lineages.contains(&context) {
        return None;
    }
    method
        .args
        .iter()
        .nth(3)
        .filter(|app| expression_is_context_shell_factory(app, &options, imports))?;
    Some(LeptosRouteBinding { options, context })
}

fn route_method_uses_get(method: &syn::ExprMethodCall, imports: &[Vec<String>]) -> bool {
    if method.args.len() != 2 {
        return false;
    }
    let Some(handler) = method.args.iter().nth(1).and_then(expression_call) else {
        return false;
    };
    expression_path(&handler.func)
        .is_some_and(|path| path_is_bound(path, "get", &["axum", "routing", "get"], imports))
        && handler.args.len() == 1
}

fn fallback_method_context(
    method: &syn::ExprMethodCall,
    imports: &[Vec<String>],
    local_value_lineages: &BTreeMap<String, LocalValueLineage>,
) -> Option<LocalValueLineage> {
    let handler = method.args.first().and_then(expression_call)?;
    if method.args.len() != 1 {
        return None;
    }
    let handler_path = expression_path(&handler.func)?;

    if !path_is_bound(
        handler_path,
        "file_and_error_handler_with_context",
        &["leptos_axum", "file_and_error_handler_with_context"],
        imports,
    ) || handler.args.len() != 2
        || !handler
            .args
            .iter()
            .nth(1)
            .is_some_and(|producer| expression_is_shell(producer, imports))
    {
        return None;
    }
    context_provider_lineage(handler.args.first()?, imports, local_value_lineages)
}

fn context_provider_lineage(
    expression: &syn::Expr,
    imports: &[Vec<String>],
    local_value_lineages: &BTreeMap<String, LocalValueLineage>,
) -> Option<LocalValueLineage> {
    let source = context_provider_source(expression, imports)?;
    local_value_lineages.get(&source).cloned()
}

fn context_provider_source(expression: &syn::Expr, imports: &[Vec<String>]) -> Option<String> {
    let syn::Expr::Closure(closure) = strip_paren_group(expression) else {
        return None;
    };
    if closure.capture.is_none() || closure.asyncness.is_some() || !closure.inputs.is_empty() {
        return None;
    }
    let call = expression_call(&closure.body)?;
    let function = expression_path(&call.func)?;
    let calls_leptos_context = path_matches(function, &["leptos", "prelude", "provide_context"])
        || (path_matches(function, &["provide_context"])
            && (imported(imports, &["leptos", "prelude", "provide_context"])
                || imported(imports, &["leptos", "prelude", "*"])));
    if !calls_leptos_context || call.args.len() != 1 {
        return None;
    }
    call.args.first().and_then(cloned_simple_ident)
}

fn expression_is_context_shell_factory(
    expression: &syn::Expr,
    options: &str,
    imports: &[Vec<String>],
) -> bool {
    let syn::Expr::Block(expression_block) = strip_paren_group(expression) else {
        return false;
    };
    if expression_block.label.is_some() || expression_block.block.stmts.len() != 2 {
        return false;
    }
    let syn::Stmt::Local(options_clone) = &expression_block.block.stmts[0] else {
        return false;
    };
    let Some(clone_name) = local_ident(&options_clone.pat) else {
        return false;
    };
    let Some(initializer) = &options_clone.init else {
        return false;
    };
    if initializer.diverge.is_some()
        || cloned_simple_ident(&initializer.expr).as_deref() != Some(options)
    {
        return false;
    }
    let syn::Stmt::Expr(tail, None) = &expression_block.block.stmts[1] else {
        return false;
    };
    let syn::Expr::Closure(closure) = strip_paren_group(tail) else {
        return false;
    };
    if closure.capture.is_none() || closure.asyncness.is_some() || !closure.inputs.is_empty() {
        return false;
    }
    let Some(call) = expression_call(&closure.body) else {
        return false;
    };
    call.args.len() == 1
        && expression_path(&call.func).is_some_and(|path| expression_path_is_shell(path, imports))
        && call.args.first().and_then(cloned_simple_ident).as_deref() == Some(clone_name.as_str())
}

fn expression_generates_app_routes(expression: &syn::Expr, imports: &[Vec<String>]) -> bool {
    let Some(call) = expression_call(strip_completion_wrappers(expression)) else {
        return false;
    };
    let Some(function) = expression_path(&call.func) else {
        return false;
    };
    path_is_bound(
        function,
        "generate_route_list",
        &["leptos_axum", "generate_route_list"],
        imports,
    ) && call.args.len() == 1
        && call
            .args
            .first()
            .is_some_and(|app| expression_is_app(app, imports))
}

fn expression_is_app(expression: &syn::Expr, imports: &[Vec<String>]) -> bool {
    expression_path(strip_paren_group(expression))
        .is_some_and(|path| path_is_bound(path, "App", &["ryuki_portal_ui", "app", "App"], imports))
}

fn expression_is_shell(expression: &syn::Expr, imports: &[Vec<String>]) -> bool {
    expression_path(strip_paren_group(expression))
        .is_some_and(|path| expression_path_is_shell(path, imports))
}

fn expression_path_is_shell(path: &syn::Path, imports: &[Vec<String>]) -> bool {
    path_is_bound(path, "shell", &["ryuki_portal_ui", "app", "shell"], imports)
}

fn expression_is_router_new(expression: &syn::Expr, imports: &[Vec<String>]) -> bool {
    let Some(call) = expression_call(expression) else {
        return false;
    };
    let Some(path) = expression_path(&call.func) else {
        return false;
    };
    call.args.is_empty()
        && ((path_matches(path, &["Router", "new"]) && imported(imports, &["axum", "Router"]))
            || path_matches(path, &["axum", "Router", "new"]))
}

fn expression_loads_configuration(expression: &syn::Expr) -> bool {
    let Some(call) = expression_call(strip_completion_wrappers(expression)) else {
        return false;
    };
    if !expression_path(&call.func).is_some_and(|path| path_matches(path, &["get_configuration"]))
        || call.args.len() != 1
    {
        return false;
    }
    call.args.first().is_some_and(|argument| {
        expression_path(argument).is_some_and(|path| path_matches(path, &["None"]))
            || expression_call(argument).is_some_and(|some| {
                expression_path(&some.func).is_some_and(|path| path_matches(path, &["Some"]))
                    && some.args.len() == 1
                    && some
                        .args
                        .first()
                        .and_then(string_literal)
                        .is_some_and(|value| value == "Cargo.toml")
            })
    })
}

fn expression_derives_leptos_options(
    expression: &syn::Expr,
    configurations: &BTreeSet<String>,
) -> bool {
    let syn::Expr::Field(field) = strip_completion_wrappers(expression) else {
        return false;
    };
    matches!(
        &field.member,
        syn::Member::Named(member) if member == "leptos_options"
    ) && simple_ident(&field.base).is_some_and(|name| configurations.contains(&name))
}

fn expression_creates_static_boundary(expression: &syn::Expr, imports: &[Vec<String>]) -> bool {
    let Some(call) = expression_call(strip_completion_wrappers(expression)) else {
        return false;
    };
    let Some(path) = expression_path(&call.func) else {
        return false;
    };
    call.args.is_empty()
        && ((path_matches(path, &["PortalServerBoundary", "static_dry_run"])
            && imported(
                imports,
                &["ryuki_portal_ui", "server_boundary", "PortalServerBoundary"],
            ))
            || path_matches(
                path,
                &[
                    "ryuki_portal_ui",
                    "server_boundary",
                    "PortalServerBoundary",
                    "static_dry_run",
                ],
            ))
}

fn expression_creates_public_origin(expression: &syn::Expr, imports: &[Vec<String>]) -> bool {
    let Some(call) = expression_call(strip_completion_wrappers(expression)) else {
        return false;
    };
    let Some(path) = expression_path(&call.func) else {
        return false;
    };
    call.args.is_empty()
        && ((path_matches(path, &["PortalPublicOrigin", "from_env"])
            && imported(
                imports,
                &["ryuki_portal_ui", "security", "PortalPublicOrigin"],
            ))
            || path_matches(
                path,
                &[
                    "ryuki_portal_ui",
                    "security",
                    "PortalPublicOrigin",
                    "from_env",
                ],
            ))
}

fn expression_creates_upstream_client(
    expression: &syn::Expr,
    imports: &[Vec<String>],
    public_origins: &BTreeSet<String>,
) -> bool {
    let Some(call) = expression_call(strip_completion_wrappers(expression)) else {
        return false;
    };
    let Some(path) = expression_path(&call.func) else {
        return false;
    };
    let calls_approved_constructor = (path_matches(path, &["UpstreamClient", "from_env"])
        && imported(imports, &["ryuki_portal_ui", "upstream", "UpstreamClient"]))
        || path_matches(
            path,
            &["ryuki_portal_ui", "upstream", "UpstreamClient", "from_env"],
        );
    calls_approved_constructor
        && call.args.len() == 1
        && call
            .args
            .first()
            .and_then(referenced_simple_ident)
            .is_some_and(|origin| public_origins.contains(&origin))
}

fn expression_creates_server_function_limits(
    expression: &syn::Expr,
    imports: &[Vec<String>],
) -> bool {
    let Some(call) = expression_call(strip_completion_wrappers(expression)) else {
        return false;
    };
    let Some(path) = expression_path(&call.func) else {
        return false;
    };
    call.args.is_empty()
        && ((path_matches(path, &["PortalServerFunctionLimits", "from_env"])
            && imported(
                imports,
                &["ryuki_portal_ui", "security", "PortalServerFunctionLimits"],
            ))
            || path_matches(
                path,
                &[
                    "ryuki_portal_ui",
                    "security",
                    "PortalServerFunctionLimits",
                    "from_env",
                ],
            ))
}

fn expression_creates_server_function_router(
    expression: &syn::Expr,
    imports: &[Vec<String>],
    public_origins: &BTreeSet<String>,
    server_function_limits: &BTreeSet<String>,
    local_value_lineages: &BTreeMap<String, LocalValueLineage>,
    trusted_context_lineages: &BTreeSet<LocalValueLineage>,
) -> bool {
    let Some(protected) = expression_call(strip_completion_wrappers(expression)) else {
        return false;
    };
    let Some(protect_path) = expression_path(&protected.func) else {
        return false;
    };
    if !path_is_bound(
        protect_path,
        "protect_server_function_routes",
        &[
            "ryuki_portal_ui",
            "security",
            "protect_server_function_routes",
        ],
        imports,
    ) || protected.args.len() != 3
        || !protected
            .args
            .iter()
            .nth(1)
            .and_then(simple_ident)
            .is_some_and(|origin| public_origins.contains(&origin))
        || !protected
            .args
            .iter()
            .nth(2)
            .and_then(simple_ident)
            .is_some_and(|limits| server_function_limits.contains(&limits))
    {
        return false;
    }

    let Some(syn::Expr::MethodCall(route)) = protected.args.first().map(strip_paren_group) else {
        return false;
    };
    if route.method != "route"
        || route.args.len() != 2
        || !expression_is_router_new(&route.receiver, imports)
        || route.args.first().and_then(string_literal).as_deref() != Some("/portal/api/{*fn_name}")
    {
        return false;
    }
    let Some(handler) = route.args.iter().nth(1).and_then(expression_call) else {
        return false;
    };
    if !expression_path(&handler.func)
        .is_some_and(|path| path_is_bound(path, "any", &["axum", "routing", "any"], imports))
        || handler.args.len() != 1
    {
        return false;
    }
    let Some(syn::Expr::Closure(request_handler)) = handler.args.first().map(strip_paren_group)
    else {
        return false;
    };
    if request_handler.capture.is_none()
        || request_handler.asyncness.is_some()
        || request_handler.inputs.len() != 1
    {
        return false;
    }
    let Some(syn::Pat::Type(request_pattern)) = request_handler.inputs.first() else {
        return false;
    };
    let Some(request_name) = local_ident(&request_pattern.pat) else {
        return false;
    };
    let syn::Type::Path(request_type) = request_pattern.ty.as_ref() else {
        return false;
    };
    if request_type.qself.is_some()
        || !path_matches(&request_type.path, &["axum", "extract", "Request"])
    {
        return false;
    }
    let syn::Expr::Block(handler_block) = strip_paren_group(&request_handler.body) else {
        return false;
    };
    if handler_block.label.is_some() {
        return false;
    }
    let [syn::Stmt::Local(context_clone), syn::Stmt::Expr(async_expression, None)] =
        handler_block.block.stmts.as_slice()
    else {
        return false;
    };
    let Some(context_name) = local_ident(&context_clone.pat) else {
        return false;
    };
    let Some(context_source) = context_clone
        .init
        .as_ref()
        .filter(|initializer| initializer.diverge.is_none())
        .and_then(|initializer| cloned_simple_ident(&initializer.expr))
    else {
        return false;
    };
    let Some(context_lineage) = local_value_lineages.get(&context_source) else {
        return false;
    };
    if !trusted_context_lineages.contains(context_lineage) {
        return false;
    }
    let syn::Expr::Async(async_block) = strip_paren_group(async_expression) else {
        return false;
    };
    if async_block.capture.is_none() {
        return false;
    }
    let [syn::Stmt::Expr(response, None)] = async_block.block.stmts.as_slice() else {
        return false;
    };
    let Some(server_function_call) = awaited_call(response) else {
        return false;
    };
    expression_path(&server_function_call.func)
        .is_some_and(|path| path_matches(path, &["leptos_axum", "handle_server_fns_with_context"]))
        && server_function_call.args.len() == 2
        && server_function_call
            .args
            .first()
            .and_then(|context| context_provider_source(context, imports))
            .as_deref()
            == Some(context_name.as_str())
        && server_function_call
            .args
            .iter()
            .nth(1)
            .and_then(simple_ident)
            .as_deref()
            == Some(request_name.as_str())
}

fn expression_calls_core_plan(
    expression: &syn::Expr,
    current_boundaries: &BTreeSet<String>,
) -> bool {
    let expression = strip_completion_wrappers(expression);
    let syn::Expr::MethodCall(method) = expression else {
        return false;
    };
    method.method == "plan_core_platform_reads"
        && method.args.is_empty()
        && simple_ident(&method.receiver).is_some_and(|name| current_boundaries.contains(&name))
}

fn expression_binds_tcp_listener(expression: &syn::Expr) -> bool {
    let Some(call) = awaited_call(expression) else {
        return false;
    };
    expression_path(&call.func)
        .is_some_and(|path| path_matches(path, &["tokio", "net", "TcpListener", "bind"]))
        && call.args.len() == 1
}

fn expression_serves_router(expression: &syn::Expr) -> Option<(String, String)> {
    let call = awaited_call(expression)?;
    let function = expression_path(&call.func)?;
    if !path_matches(function, &["axum", "serve"]) || call.args.len() != 2 {
        return None;
    }
    let listener = simple_ident(call.args.first()?)?;
    let service = strip_paren_group(call.args.iter().nth(1)?);
    let syn::Expr::MethodCall(into_make_service) = service else {
        return None;
    };
    if into_make_service.method != "into_make_service" || !into_make_service.args.is_empty() {
        return None;
    }
    let router = simple_ident(&into_make_service.receiver)?;
    Some((listener, router))
}

fn awaited_call(expression: &syn::Expr) -> Option<&syn::ExprCall> {
    let expression = strip_paren_group(expression);
    let expression = match expression {
        syn::Expr::Try(try_expression) => strip_paren_group(&try_expression.expr),
        expression => expression,
    };
    let syn::Expr::Await(await_expression) = expression else {
        return None;
    };
    expression_call(&await_expression.base)
}

fn binding_is_current(
    bindings: &[(String, usize)],
    name: &str,
    binding_index: usize,
    use_index: usize,
) -> bool {
    !bindings
        .iter()
        .any(|(candidate, index)| candidate == name && *index > binding_index && *index < use_index)
}

fn serve_has_success_tail(block: &syn::Block, serve_index: usize) -> bool {
    if serve_index + 2 != block.stmts.len() {
        return false;
    }
    let Some(syn::Stmt::Expr(expression, None)) = block.stmts.last() else {
        return false;
    };
    let Some(ok) = expression_call(expression) else {
        return false;
    };
    if !expression_path(&ok.func).is_some_and(|path| path_matches(path, &["Ok"]))
        || ok.args.len() != 1
    {
        return false;
    }
    matches!(
        ok.args.first().map(strip_paren_group),
        Some(syn::Expr::Tuple(tuple)) if tuple.elems.is_empty()
    )
}

#[derive(Default)]
struct AttributeDetector {
    found: bool,
}

impl<'ast> syn::visit::Visit<'ast> for AttributeDetector {
    fn visit_attribute(&mut self, _attribute: &'ast syn::Attribute) {
        self.found = true;
    }
}

fn statement_has_attributes(statement: &syn::Stmt) -> bool {
    let mut detector = AttributeDetector::default();
    match statement {
        syn::Stmt::Local(local) => detector.visit_local(local),
        syn::Stmt::Item(syn::Item::Use(item_use)) => detector.visit_item_use(item_use),
        syn::Stmt::Expr(expression, _) => detector.visit_expr(expression),
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => return true,
    }
    detector.found
}

#[derive(Default)]
struct EarlyExitDetector {
    found: bool,
}

impl<'ast> syn::visit::Visit<'ast> for EarlyExitDetector {
    fn visit_expr_return(&mut self, _expression: &'ast syn::ExprReturn) {
        self.found = true;
    }

    fn visit_expr_break(&mut self, _expression: &'ast syn::ExprBreak) {
        self.found = true;
    }

    fn visit_expr_continue(&mut self, _expression: &'ast syn::ExprContinue) {
        self.found = true;
    }

    fn visit_expr_loop(&mut self, _expression: &'ast syn::ExprLoop) {
        self.found = true;
    }

    fn visit_expr_while(&mut self, _expression: &'ast syn::ExprWhile) {
        self.found = true;
    }

    fn visit_expr_for_loop(&mut self, _expression: &'ast syn::ExprForLoop) {
        self.found = true;
    }

    fn visit_expr_yield(&mut self, _expression: &'ast syn::ExprYield) {
        self.found = true;
    }

    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        let diverges = expression_path(&expression.func).is_some_and(|path| {
            [
                &["std", "process", "exit"][..],
                &["std", "process", "abort"][..],
                &["process", "exit"][..],
                &["process", "abort"][..],
                &["core", "intrinsics", "abort"][..],
            ]
            .iter()
            .any(|candidate| path_matches(path, candidate))
        });
        if diverges {
            self.found = true;
        } else {
            syn::visit::visit_expr_call(self, expression);
        }
    }

    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        let diverges = expression.mac.path.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "panic" | "todo" | "unimplemented" | "unreachable"
            )
        });
        if diverges {
            self.found = true;
        } else {
            syn::visit::visit_expr_macro(self, expression);
        }
    }
}

fn statement_has_early_exit(statement: &syn::Stmt) -> bool {
    let mut detector = EarlyExitDetector::default();
    match statement {
        syn::Stmt::Local(local) => detector.visit_local(local),
        syn::Stmt::Expr(expression, _) => detector.visit_expr(expression),
        syn::Stmt::Item(syn::Item::Use(_)) => {}
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => return true,
    }
    detector.found
}

#[derive(Default)]
struct AssignmentTargetDetector {
    targets: BTreeSet<String>,
}

impl<'ast> syn::visit::Visit<'ast> for AssignmentTargetDetector {
    fn visit_expr_assign(&mut self, expression: &'ast syn::ExprAssign) {
        collect_assignment_target_names(&expression.left, &mut self.targets);
        syn::visit::visit_expr_assign(self, expression);
    }

    fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
        if matches!(
            &expression.op,
            syn::BinOp::AddAssign(_)
                | syn::BinOp::SubAssign(_)
                | syn::BinOp::MulAssign(_)
                | syn::BinOp::DivAssign(_)
                | syn::BinOp::RemAssign(_)
                | syn::BinOp::BitXorAssign(_)
                | syn::BinOp::BitAndAssign(_)
                | syn::BinOp::BitOrAssign(_)
                | syn::BinOp::ShlAssign(_)
                | syn::BinOp::ShrAssign(_)
        ) {
            collect_assignment_target_names(&expression.left, &mut self.targets);
        }
        syn::visit::visit_expr_binary(self, expression);
    }
}

fn statement_assignment_targets(statement: &syn::Stmt) -> BTreeSet<String> {
    let mut detector = AssignmentTargetDetector::default();
    match statement {
        syn::Stmt::Local(local) => detector.visit_local(local),
        syn::Stmt::Expr(expression, _) => detector.visit_expr(expression),
        syn::Stmt::Item(syn::Item::Use(_)) => {}
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => return detector.targets,
    }
    detector.targets
}

fn collect_assignment_target_names(expression: &syn::Expr, targets: &mut BTreeSet<String>) {
    match strip_paren_group(expression) {
        syn::Expr::Path(_) => {
            if let Some(name) = simple_ident(expression) {
                targets.insert(name);
            }
        }
        syn::Expr::Field(field) => collect_assignment_target_names(&field.base, targets),
        syn::Expr::Index(index) => collect_assignment_target_names(&index.expr, targets),
        syn::Expr::Unary(unary) if matches!(&unary.op, syn::UnOp::Deref(_)) => {
            collect_assignment_target_names(&unary.expr, targets);
        }
        syn::Expr::Reference(reference) => {
            collect_assignment_target_names(&reference.expr, targets);
        }
        // Tuple-struct and enum-variant destructuring assignees are parsed as
        // calls; their arguments, rather than the constructor path, are the
        // places whose values are replaced.
        syn::Expr::Call(call) => {
            for argument in &call.args {
                collect_assignment_target_names(argument, targets);
            }
        }
        syn::Expr::Tuple(tuple) => {
            for element in &tuple.elems {
                collect_assignment_target_names(element, targets);
            }
        }
        syn::Expr::Array(array) => {
            for element in &array.elems {
                collect_assignment_target_names(element, targets);
            }
        }
        syn::Expr::Struct(structure) => {
            for field in &structure.fields {
                collect_assignment_target_names(&field.expr, targets);
            }
            if let Some(rest) = &structure.rest {
                collect_assignment_target_names(rest, targets);
            }
        }
        _ => {}
    }
}

#[derive(Default)]
struct MainFlowAwaitDetector {
    count: usize,
}

impl<'ast> syn::visit::Visit<'ast> for MainFlowAwaitDetector {
    fn visit_expr_await(&mut self, expression: &'ast syn::ExprAwait) {
        self.count += 1;
        syn::visit::visit_expr_await(self, expression);
    }

    fn visit_expr_async(&mut self, _expression: &'ast syn::ExprAsync) {}

    fn visit_expr_closure(&mut self, _expression: &'ast syn::ExprClosure) {}
}

fn statement_has_unrecognized_main_await(statement: &syn::Stmt, imports: &[Vec<String>]) -> bool {
    let mut detector = MainFlowAwaitDetector::default();
    match statement {
        syn::Stmt::Local(local) => detector.visit_local(local),
        syn::Stmt::Expr(expression, _) => detector.visit_expr(expression),
        syn::Stmt::Item(syn::Item::Use(_)) => return false,
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => return true,
    }
    if detector.count == 0 {
        return false;
    }
    if detector.count != 1 {
        return true;
    }
    match statement {
        syn::Stmt::Local(local) => local
            .init
            .as_ref()
            .is_none_or(|init| !expression_binds_tcp_listener(&init.expr)),
        syn::Stmt::Expr(expression, _) => {
            expression_serves_router(expression).is_none()
                && !expression_validates_live_provider_auth(expression, imports)
        }
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => true,
    }
}

fn expression_validates_live_provider_auth(
    expression: &syn::Expr,
    imports: &[Vec<String>],
) -> bool {
    let Some(call) = awaited_call(expression) else {
        return false;
    };
    expression_path(&call.func).is_some_and(|path| {
        path_is_bound(
            path,
            "validate_live_provider_auth_posture",
            &[
                "ryuki_portal_ui",
                "startup",
                "validate_live_provider_auth_posture",
            ],
            imports,
        )
    }) && call.args.len() == 2
}

fn strip_paren_group(mut expression: &syn::Expr) -> &syn::Expr {
    loop {
        expression = match expression {
            syn::Expr::Paren(paren) => &paren.expr,
            syn::Expr::Group(group) => &group.expr,
            _ => return expression,
        };
    }
}

fn strip_completion_wrappers(mut expression: &syn::Expr) -> &syn::Expr {
    loop {
        expression = match strip_paren_group(expression) {
            syn::Expr::Try(try_expression) => &try_expression.expr,
            syn::Expr::Await(await_expression) => &await_expression.base,
            expression => return expression,
        };
    }
}

fn expression_call(expression: &syn::Expr) -> Option<&syn::ExprCall> {
    match strip_paren_group(expression) {
        syn::Expr::Call(call) => Some(call),
        _ => None,
    }
}

fn expression_path(expression: &syn::Expr) -> Option<&syn::Path> {
    match strip_paren_group(expression) {
        syn::Expr::Path(path) => Some(&path.path),
        _ => None,
    }
}

fn local_ident(pattern: &syn::Pat) -> Option<String> {
    match pattern {
        syn::Pat::Ident(ident)
            if ident.by_ref.is_none() && ident.mutability.is_none() && ident.subpat.is_none() =>
        {
            Some(ident.ident.to_string())
        }
        _ => None,
    }
}

fn simple_ident(expression: &syn::Expr) -> Option<String> {
    let path = expression_path(expression)?;
    if path.leading_colon.is_none() && path.segments.len() == 1 {
        path.segments
            .first()
            .map(|segment| segment.ident.to_string())
    } else {
        None
    }
}

fn referenced_simple_ident(expression: &syn::Expr) -> Option<String> {
    let syn::Expr::Reference(reference) = strip_paren_group(expression) else {
        return None;
    };
    if reference.mutability.is_some() {
        return None;
    }
    simple_ident(&reference.expr)
}

fn cloned_or_simple_ident(expression: &syn::Expr) -> Option<String> {
    if let Some(name) = simple_ident(expression) {
        return Some(name);
    }
    let syn::Expr::MethodCall(clone) = strip_paren_group(expression) else {
        return None;
    };
    if clone.method != "clone" || !clone.args.is_empty() {
        return None;
    }
    simple_ident(&clone.receiver)
}

fn cloned_simple_ident(expression: &syn::Expr) -> Option<String> {
    let syn::Expr::MethodCall(clone) = strip_paren_group(expression) else {
        return None;
    };
    if clone.method != "clone" || !clone.args.is_empty() {
        return None;
    }
    simple_ident(&clone.receiver)
}

fn string_literal(expression: &syn::Expr) -> Option<String> {
    match strip_paren_group(expression) {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(value),
            ..
        }) => Some(value.value()),
        _ => None,
    }
}

fn attribute_is_cfg_ssr(attribute: &syn::Attribute) -> bool {
    let syn::Meta::List(list) = &attribute.meta else {
        return false;
    };
    if !list.path.is_ident("cfg") {
        return false;
    }
    let Ok(syn::Meta::NameValue(feature)) = list.parse_args::<syn::Meta>() else {
        return false;
    };
    feature.path.is_ident("feature")
        && matches!(
            feature.value,
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(ref value),
                ..
            }) if value.value() == "ssr"
        )
}

fn attribute_is_tokio_main(attribute: &syn::Attribute) -> bool {
    path_matches(attribute.path(), &["tokio", "main"])
}

fn collect_block_imports(block: &syn::Block) -> Vec<Vec<String>> {
    let mut imports = Vec::new();
    for statement in &block.stmts {
        if let syn::Stmt::Item(syn::Item::Use(item_use)) = statement {
            collect_use_paths(&item_use.tree, &mut Vec::new(), &mut imports);
        }
    }
    imports
}

fn collect_use_paths(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    imports: &mut Vec<Vec<String>>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_paths(&path.tree, prefix, imports);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut path = prefix.clone();
            path.push(name.ident.to_string());
            imports.push(path);
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_paths(item, prefix, imports);
            }
        }
        syn::UseTree::Glob(_) => {
            let mut path = prefix.clone();
            path.push("*".to_string());
            imports.push(path);
        }
        syn::UseTree::Rename(_) => {}
    }
}

fn item_binds_value_name(item: &syn::Item, name: &str) -> bool {
    match item {
        syn::Item::Fn(function) => function.sig.ident == name,
        syn::Item::Const(constant) => constant.ident == name,
        syn::Item::Static(static_item) => static_item.ident == name,
        syn::Item::Struct(structure) => {
            structure.ident == name
                && matches!(
                    &structure.fields,
                    syn::Fields::Unnamed(_) | syn::Fields::Unit
                )
        }
        syn::Item::Use(item_use) => use_tree_binds_name_or_glob(&item_use.tree, name),
        syn::Item::ForeignMod(foreign) => foreign.items.iter().any(|item| match item {
            syn::ForeignItem::Fn(function) => function.sig.ident == name,
            syn::ForeignItem::Static(static_item) => static_item.ident == name,
            _ => false,
        }),
        // Item macros and unparsed future syntax can introduce value bindings
        // that Syn cannot resolve. Fail closed while this call remains
        // intentionally unqualified under the Leptos prelude glob.
        syn::Item::Macro(_) | syn::Item::Verbatim(_) => true,
        _ => false,
    }
}

fn item_binds_type_root(item: &syn::Item, name: &str) -> bool {
    match item {
        syn::Item::Enum(item) => item.ident == name,
        syn::Item::ExternCrate(item) => {
            item.rename
                .as_ref()
                .map(|(_, rename)| rename)
                .unwrap_or(&item.ident)
                == name
        }
        syn::Item::Mod(item) => item.ident == name,
        syn::Item::Struct(item) => item.ident == name,
        syn::Item::Trait(item) => item.ident == name,
        syn::Item::TraitAlias(item) => item.ident == name,
        syn::Item::Type(item) => item.ident == name,
        syn::Item::Union(item) => item.ident == name,
        syn::Item::Use(item_use) => use_tree_binds_name_or_glob(&item_use.tree, name),
        // These were already rejected by the value-binding proof, but keeping
        // the type-root proof independently fail-closed prevents future drift.
        syn::Item::Macro(_) | syn::Item::Verbatim(_) => true,
        _ => false,
    }
}

fn use_tree_binds_name_or_glob(tree: &syn::UseTree, name: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) => use_tree_binds_name_or_glob(&path.tree, name),
        syn::UseTree::Name(bound) => bound.ident == name,
        syn::UseTree::Rename(bound) => bound.rename == name,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_binds_name_or_glob(item, name)),
        syn::UseTree::Glob(_) => true,
    }
}

fn use_tree_contains_rename(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Path(path) => use_tree_contains_rename(&path.tree),
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_contains_rename),
        syn::UseTree::Rename(_) => true,
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => false,
    }
}

fn imported(imports: &[Vec<String>], expected: &[&str]) -> bool {
    imports.iter().any(|path| {
        path.len() == expected.len()
            && path
                .iter()
                .zip(expected)
                .all(|(actual, expected)| actual == *expected)
    })
}

fn path_is_bound(
    path: &syn::Path,
    unqualified: &str,
    qualified: &[&str],
    imports: &[Vec<String>],
) -> bool {
    path_matches(path, qualified)
        || (path_matches(path, &[unqualified]) && imported(imports, qualified))
}

fn path_matches(path: &syn::Path, expected: &[&str]) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == expected.len()
        && path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment.ident == *expected)
}

fn path_matches_segments(path: &[String], expected: &[&str]) -> bool {
    path.len() == expected.len()
        && path
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment == *expected)
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
    fn current_context_aware_portal_main_is_structurally_accepted() {
        let inspection = inspect_portal_main(include_str!("../../../portal/portal-ui/src/main.rs"));
        assert!(inspection.runs_axum_leptos_ssr);
        assert!(inspection.plans_core_platform_reads);
        assert!(inspection.exposes_health_routes);
    }

    #[test]
    fn context_aware_leptos_runtime_requires_shell_fallback_and_served_router() {
        let main_rs = context_aware_ssr_main();
        for invalid_main in [
            main_rs.replace(
                "move || provide_context(upstream_for_fallback.clone()),\n            shell,",
                "move || provide_context(upstream_for_fallback.clone()),\n            other_shell,",
            ),
            main_rs.replace("axum::serve(", "serve_without_axum("),
            main_rs.replace(
                "app.into_make_service()",
                "unrelated_router.into_make_service()",
            ),
        ] {
            assert_ne!(invalid_main, main_rs);
            assert!(!inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
        }
    }

    #[test]
    fn served_leptos_app_and_context_are_bound_to_the_approved_runtime() {
        let main_rs = context_aware_ssr_main();
        let attacker_context = main_rs
            .replace(
                "    let upstream_for_routes = upstream.clone();",
                concat!(
                    "    let upstream_for_routes = upstream.clone();\n",
                    "    let attacker_context = String::from(\"attacker\");"
                ),
            )
            .replace(
                "move || provide_context(upstream_for_routes.clone()),",
                "move || provide_context(attacker_context.clone()),",
            );
        let shared_attacker_context =
            attacker_context.replace("upstream_for_fallback.clone()", "attacker_context.clone()");
        let empty_context = main_rs.replace(
            "move || provide_context(upstream_for_routes.clone()),",
            "move || {},",
        );
        let attacker_app = main_rs.replace(
            "move || shell(leptos_options.clone())",
            "move || attacker_shell(leptos_options.clone())",
        );

        assert!(inspect_portal_main(&main_rs).runs_axum_leptos_ssr);
        for invalid_main in [
            attacker_context,
            shared_attacker_context,
            empty_context,
            attacker_app,
        ] {
            assert_ne!(invalid_main, main_rs);
            assert!(!inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
        }
    }

    #[test]
    fn trusted_portal_runtime_bindings_cannot_be_reassigned() {
        let main_rs = context_aware_ssr_main();
        let reassigned_origin = main_rs.replace(
            "    let upstream = UpstreamClient::from_env(&public_origin)?;",
            concat!(
                "    public_origin = PortalPublicOrigin::from_env()?;\n",
                "    let upstream = UpstreamClient::from_env(&public_origin)?;"
            ),
        );
        let reassigned_upstream = main_rs.replace(
            "    let upstream_for_routes = upstream.clone();",
            concat!(
                "    upstream = UpstreamClient::from_env(&public_origin)?;\n",
                "    let upstream_for_routes = upstream.clone();"
            ),
        );
        let reassigned_route_context = main_rs.replace(
            "    let app = Router::new()",
            concat!(
                "    upstream_for_routes = upstream.clone();\n",
                "    let app = Router::new()"
            ),
        );
        let nested_field_assignment = main_rs.replace(
            "    let app = Router::new()",
            concat!(
                "    let mutation = { upstream_for_routes.inner = upstream.clone(); };\n",
                "    let app = Router::new()"
            ),
        );

        assert!(inspect_portal_main(&main_rs).runs_axum_leptos_ssr);
        for invalid_main in [
            reassigned_origin,
            reassigned_upstream,
            reassigned_route_context,
            nested_field_assignment,
        ] {
            assert_ne!(invalid_main, main_rs);
            assert!(!inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
        }
    }

    #[test]
    fn assignment_targets_cover_indirect_destructuring_and_compound_forms() {
        let block: syn::Block = syn::parse_str(
            r#"{
                direct = replacement;
                tuple.field = replacement;
                indexed[0] = replacement;
                *pointer = replacement;
                (left, right) = (replacement, replacement);
                Wrapper(wrapped) = replacement;
                compound += 1;
                let nested_result = { nested = replacement; };
            }"#,
        )
        .expect("assignment fixture parses");
        let targets: BTreeSet<String> = block
            .stmts
            .iter()
            .flat_map(statement_assignment_targets)
            .collect();
        let expected: BTreeSet<String> = [
            "compound", "direct", "indexed", "left", "nested", "pointer", "right", "tuple",
            "wrapped",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();

        assert_eq!(targets, expected);
    }

    #[test]
    fn module_scope_context_provider_shadow_is_rejected() {
        let main_rs = context_aware_ssr_main();

        assert!(inspect_portal_main(&main_rs).runs_axum_leptos_ssr);
        for shadow in [
            "fn provide_context<T>(_value: T) {}",
            "const provide_context: fn(String) = |_| {};",
            "static provide_context: fn(String) = |_| {};",
            "struct provide_context<T>(T);",
            "use attacker::provide_context;",
            "use attacker::provider as provide_context;",
            "use attacker::*;",
            "unsafe extern \"Rust\" { fn provide_context(value: String); }",
            "include!(\"attacker.rs\");",
        ] {
            let shadowed_main = format!("{shadow}\n{main_rs}");
            assert!(
                !inspect_portal_main(&shadowed_main).runs_axum_leptos_ssr,
                "module-scope binding remained accepted: {shadow}"
            );
        }
    }

    #[test]
    fn trusted_crate_roots_cannot_be_shadowed() {
        let main_rs = context_aware_ssr_main();

        assert!(inspect_portal_main(&main_rs).runs_axum_leptos_ssr);
        for shadow in [
            "mod leptos { pub mod prelude {} }",
            "mod ryuki_portal_ui { pub mod security {} }",
            "extern crate attacker as axum;",
            "type leptos_axum = Attacker;",
            "struct tokio;",
            "use attacker as ryuki_portal_ui;",
        ] {
            let shadowed_main = format!("{shadow}\n{main_rs}");
            assert!(
                !inspect_portal_main(&shadowed_main).runs_axum_leptos_ssr,
                "trusted crate root remained shadowable: {shadow}"
            );
        }
    }

    #[test]
    fn served_router_requires_closed_chain_and_protected_server_functions() {
        let main_rs = context_aware_ssr_main();
        let unknown_tail = main_rs.replace(
            "        .with_state(leptos_options);",
            "        .with_state(leptos_options).replace_with_attacker();",
        );
        let recognized_tail = main_rs.replace(
            "        .with_state(leptos_options);",
            concat!(
                "        .with_state(leptos_options)\n",
                "        .route(\"/attacker\", get(|| async { \"attacker\" }));"
            ),
        );
        let missing_merge = main_rs.replace("        .merge(server_function_routes)\n", "");
        let attacker_merge = main_rs.replace(
            ".merge(server_function_routes)",
            ".merge(attacker_server_function_routes)",
        );
        let unprotected_routes = main_rs.replace(
            "protect_server_function_routes(",
            "attacker_server_function_routes(",
        );

        assert!(inspect_portal_main(&main_rs).runs_axum_leptos_ssr);
        for invalid_main in [
            unknown_tail,
            recognized_tail,
            missing_merge,
            attacker_merge,
            unprotected_routes,
        ] {
            assert_ne!(invalid_main, main_rs);
            assert!(!inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
        }
    }

    #[test]
    fn conditional_and_early_exit_server_decoys_are_rejected() {
        let main_rs = context_aware_ssr_main();
        for invalid_main in [
            main_rs.replace("#[tokio::main]", "#[tokio::main]\n#[cfg(any())]"),
            main_rs.replace(
                "    let routes = generate_route_list(App);",
                "    #[cfg(any())]\n    let routes = generate_route_list(App);",
            ),
            main_rs.replace(
                "    use leptos::prelude::*;",
                "    #[cfg(any())]\n    use leptos::prelude::*;",
            ),
            main_rs.replace(
                "    let configuration = get_configuration(None)?;",
                "    return Ok(());\n    let configuration = get_configuration(None)?;",
            ),
            main_rs.replace(
                "    let configuration = get_configuration(None)?;",
                "    std::process::exit(0);\n    let configuration = get_configuration(None)?;",
            ),
        ] {
            assert_ne!(invalid_main, main_rs);
            assert!(!inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
        }
    }

    #[test]
    fn health_routes_require_get_and_configuration_options_lineage() {
        let main_rs = context_aware_ssr_main();
        let non_get_health = main_rs.replace(
            ".route(\"/healthz\", get(|| async { \"ok\" }))",
            ".route(\"/healthz\", post(|| async { \"ok\" }))",
        );
        let arbitrary_configuration = main_rs.replace(
            "get_configuration(None)?",
            "get_configuration(Some(\"arbitrary\"))?",
        );
        let caller_options = main_rs.replace(
            "            &leptos_options,\n            routes,",
            "            &caller_options,\n            routes,",
        );
        for invalid_main in [non_get_health, arbitrary_configuration, caller_options] {
            assert_ne!(invalid_main, main_rs);
            let inspection = inspect_portal_main(&invalid_main);
            assert!(!(inspection.runs_axum_leptos_ssr && inspection.exposes_health_routes));
        }
    }

    #[test]
    fn unrecognized_pending_await_before_server_is_rejected() {
        let main_rs = context_aware_ssr_main();
        let invalid_main = main_rs.replace(
            "    let configuration = get_configuration(None)?;",
            concat!(
                "    std::future::pending::<()>().await;\n",
                "    let configuration = get_configuration(None)?;"
            ),
        );
        assert_ne!(invalid_main, main_rs);
        assert!(!inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
    }

    #[test]
    fn local_get_shadow_cannot_turn_health_routes_into_post_routes() {
        let main_rs = context_aware_ssr_main();
        let invalid_main = main_rs
            .replace(
                "    let configuration = get_configuration(None)?;",
                concat!(
                    "    let handler = || async { \"ok\" };\n",
                    "    let get = |handler| axum::routing::post(handler);\n",
                    "    let configuration = get_configuration(None)?;"
                ),
            )
            .replace("get(|| async { \"ok\" })", "get(handler)")
            .replace("get(|| async { \"ready\" })", "get(handler)");
        assert_ne!(invalid_main, main_rs);
        assert!(!inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
    }

    #[test]
    fn competing_explicit_configuration_import_is_rejected() {
        let main_rs = context_aware_ssr_main();
        let invalid_main = main_rs.replace(
            "    use leptos::prelude::*;",
            concat!(
                "    use leptos::prelude::*;\n",
                "    use evil::get_configuration;"
            ),
        );
        assert_ne!(invalid_main, main_rs);
        assert!(!inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
    }

    #[test]
    fn raw_string_and_unused_helper_decoys_are_rejected() {
        let raw_string_decoy = r##"#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::{routing::get, Router};
    use leptos::prelude::*;
    use leptos_axum::{
        file_and_error_handler_with_context, generate_route_list, LeptosRoutes,
    };
    use ryuki_portal_ui::app::{shell, App};
    use ryuki_portal_ui::server_boundary::PortalServerBoundary;
    let configuration = get_configuration(None)?;
    let leptos_options = configuration.leptos_options;
    let routes = generate_route_list(App);
    let boundary = PortalServerBoundary::static_dry_run();
    boundary.plan_core_platform_reads()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let decoy = r#"Router::new()
        .route("/healthz", get(handler))
        .route("/readyz", get(handler))
        .leptos_routes_with_context(&leptos_options, routes, context, shell)
        .fallback(file_and_error_handler_with_context(context, shell))
        .with_state(leptos_options);
        axum::serve(listener, app.into_make_service()).await?;"#;
}
"##;
        assert!(!inspect_portal_main(raw_string_decoy).runs_axum_leptos_ssr);

        let unused_helper_decoy = format!(
            "{}\n{}",
            context_aware_ssr_main().replace("async fn main()", "async fn unused_server()"),
            r#"#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {}"#
        );
        assert!(!inspect_portal_main(&unused_helper_decoy).runs_axum_leptos_ssr);
    }

    #[test]
    fn lifetime_and_comment_like_literal_cannot_hide_missing_serve() {
        let invalid_main = context_aware_ssr_main().replace(
            "    axum::serve(listener, app.into_make_service()).await?;",
            concat!(
                "    let marker: &'static str = ",
                "\"// axum::serve(listener, app.into_make_service()).await?;\";"
            ),
        );
        assert_ne!(invalid_main, context_aware_ssr_main());
        assert!(!inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
    }

    #[test]
    fn leptos_routes_and_fallback_on_disparate_router_chains_are_rejected() {
        let invalid_main = context_aware_ssr_main()
            .replace(
                "    let app = Router::new()",
                "    let routed = Router::new()",
            )
            .replace(
                "        .with_state(leptos_options);",
                concat!(
                    "        .with_state(leptos_options.clone());\n",
                    "    let app = Router::new()\n",
                    "        .fallback(file_and_error_handler_with_context(|| {}, shell))\n",
                    "        .with_state(leptos_options);"
                ),
            );
        assert_ne!(invalid_main, context_aware_ssr_main());
        assert!(!inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
    }

    #[test]
    fn root_context_portal_dockerfile_is_accepted() {
        // RED: portal Dockerfile with root-context COPY patterns must not
        // trigger the "retired Trunk index.html" error.
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm AS build\n",
            "RUN [\"/usr/local/cargo/bin/rustup\", \"target\", \"add\", \"wasm32-unknown-unknown\"]\n",
            "RUN [\"/usr/local/cargo/bin/cargo\", \"install\", \"cargo-leptos\", \"--version\", \"0.3.7\", \"--locked\", \"--root\", \"/opt/ryuki-tools/cargo-leptos-0.3.7\"]\n",
            "WORKDIR /app\n",
            "COPY --link --chown=10001:10001 Cargo.toml Cargo.lock ./\n",
            "COPY --link --chown=10001:10001 sources/ sources/\n",
            "COPY --link --chown=10001:10001 portal/ portal/\n",
            "RUN [\"/opt/ryuki-tools/cargo-leptos-0.3.7/bin/cargo-leptos\", \"build\", \"--release\", \"-p\", \"ryuki-portal-ui\"]\n",
            "FROM debian:bookworm-slim AS runtime\n",
            "WORKDIR /app\n",
            "ENV LEPTOS_SITE_ROOT=/app/site \\\n",
            "    LEPTOS_SITE_ADDR=0.0.0.0:8080\n",
            "COPY --from=build --chown=10001:10001 /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui\n",
            "COPY --from=build --chown=10001:10001 /app/target/site /app/site\n",
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
    fn linked_crate_local_non_trunk_dockerfile_is_still_accepted() {
        // TRIANGULATE: a crate-local Dockerfile without the retired index still passes.
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm AS build\n",
            "RUN [\"/usr/local/cargo/bin/cargo\", \"install\", \"cargo-leptos\", \"--version\", \"0.3.7\", \"--locked\", \"--root\", \"/opt/ryuki-tools/cargo-leptos-0.3.7\"]\n",
            "WORKDIR /app\n",
            "COPY --link --chown=10001:10001 Cargo.toml styles.css ./\n",
            "COPY --link --chown=10001:10001 src ./src\n",
            "RUN [\"/opt/ryuki-tools/cargo-leptos-0.3.7/bin/cargo-leptos\", \"build\", \"--release\"]\n",
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
            "Linked crate-local non-Trunk Dockerfile should still pass but got: {:?}",
            errors
        );
    }

    fn context_aware_ssr_main() -> String {
        r#"#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::{routing::{any, get}, Router};
    use leptos::prelude::*;
    use leptos_axum::{
        file_and_error_handler_with_context, generate_route_list, LeptosRoutes,
    };
    use ryuki_portal_ui::app::{shell, App};
    use ryuki_portal_ui::security::{
        protect_server_function_routes, PortalPublicOrigin, PortalServerFunctionLimits,
    };
    use ryuki_portal_ui::server_boundary::PortalServerBoundary;
    use ryuki_portal_ui::upstream::UpstreamClient;
    let configuration = get_configuration(None)?;
    let leptos_options = configuration.leptos_options;
    let address = leptos_options.site_addr;
    let routes = generate_route_list(App);
    let boundary = PortalServerBoundary::static_dry_run();
    boundary.plan_core_platform_reads()?;
    let public_origin = PortalPublicOrigin::from_env()?;
    let server_function_limits = PortalServerFunctionLimits::from_env()?;
    let upstream = UpstreamClient::from_env(&public_origin)?;
    let upstream_for_server_fns = upstream.clone();
    let upstream_for_routes = upstream.clone();
    let upstream_for_fallback = upstream.clone();
    let server_function_routes = protect_server_function_routes(
        Router::new().route(
            "/portal/api/{*fn_name}",
            any(move |request: axum::extract::Request| {
                let upstream = upstream_for_server_fns.clone();
                async move {
                    leptos_axum::handle_server_fns_with_context(
                        move || provide_context(upstream.clone()),
                        request,
                    )
                    .await
                }
            }),
        ),
        public_origin,
        server_function_limits,
    );
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ready" }))
        .merge(server_function_routes)
        .leptos_routes_with_context(
            &leptos_options,
            routes,
            move || provide_context(upstream_for_routes.clone()),
            {
                let leptos_options = leptos_options.clone();
                move || shell(leptos_options.clone())
            },
        )
        .fallback(file_and_error_handler_with_context(
            move || provide_context(upstream_for_fallback.clone()),
            shell,
        ))
        .with_state(leptos_options);
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
"#
        .to_string()
    }
}
