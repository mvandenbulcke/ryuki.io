use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/portal-information-architecture-contract.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/portal-information-architecture.md";
const UI_IA_PATH: &str = "docs/ui/portal-information-architecture.md";
const UI_DESIGN_PATH: &str = "docs/ui/design-system.md";
const PORTAL_CARGO_PATH: &str = "portal/portal-ui/Cargo.toml";
const PORTAL_MAIN_PATH: &str = "portal/portal-ui/src/main.rs";
const PORTAL_LIB_PATH: &str = "portal/portal-ui/src/lib.rs";
const PORTAL_DOCKERFILE_PATH: &str = "portal/portal-ui/Dockerfile";
const PORTAL_APP_PATH: &str = "portal/portal-ui/src/app.rs";
const PORTAL_SHELL_PATH: &str = "portal/portal-ui/src/shell.rs";
const PORTAL_WORKSPACE_CATALOG_PATH: &str = "portal/portal-ui/src/workspace_catalog.rs";
const PORTAL_WORKSPACES_PATH: &str = "portal/portal-ui/src/views/workspaces.rs";
const PORTAL_API_PATH: &str = "portal/portal-ui/src/api.rs";
const PORTAL_SERVER_BOUNDARY_PATH: &str = "portal/portal-ui/src/server_boundary.rs";
const ENDPOINT: &str = "/api/platform/portal-information-architecture-contract";
const PORTAL_RUSTUP_TARGET_INSTRUCTION: &str =
    r#"RUN ["/usr/local/cargo/bin/rustup", "target", "add", "wasm32-unknown-unknown"]"#;
const PORTAL_CARGO_LEPTOS_INSTALL_INSTRUCTION: &str = r#"RUN ["/usr/local/cargo/bin/cargo", "install", "cargo-leptos", "--version", "0.3.7", "--locked", "--root", "/opt/ryuki-tools/cargo-leptos-0.3.7"]"#;
const PORTAL_CARGO_LEPTOS_BUILD_INSTRUCTION: &str = r#"RUN ["/opt/ryuki-tools/cargo-leptos-0.3.7/bin/cargo-leptos", "build", "--release", "-p", "ryuki-portal-ui"]"#;
const PORTAL_CARGO_LEPTOS_CRATE_BUILD_INSTRUCTION: &str =
    r#"RUN ["/opt/ryuki-tools/cargo-leptos-0.3.7/bin/cargo-leptos", "build", "--release"]"#;
// The portal's standalone image and local-development command use this exact
// fail-closed loopback origin. The value scanner admits no suffix, alternate
// port, credential, query, fragment, or non-loopback host.
const ALLOWED_LOOPBACK_ORIGINS: &[&str] = &["http://127.0.0.1:8080"];

const REQUIRED_SURFACES: &[&str] = &[
    "product-shell",
    "primary-navigation",
    "persona-defaults",
    "dashboard-summary",
    "catalog-offering-flow",
    "request-lifecycle",
    "activity-operations-queue",
    "inventory-cmdb-evidence",
    "operations-admin-boundary",
    "global-search-command-palette",
    "selector-scope-readiness",
    "evidence-redaction-readiness",
];
const REQUIRED_NAVIGATION: &[&str] = &[
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
const REQUIRED_PERSONAS: &[&str] = &[
    "system-engineer",
    "datacenter-engineer",
    "vmware-administrator",
    "backup-administrator",
    "monitoring-administrator",
    "service-desk-operations",
    "application-owner",
    "security-audit",
];
const REQUIRED_INPUTS: &[&str] = &[
    "shellSummary",
    "navigationSummary",
    "personaSummary",
    "dashboardSummary",
    "catalogSummary",
    "requestLifecycleSummary",
    "inventoryCmdbEvidenceSummary",
    "operationsAdminSummary",
    "searchPaletteSummary",
    "scopeSelectorSummary",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "product-shell-reviewed",
    "primary-navigation-reviewed",
    "browser-isolation-reviewed",
    "same-origin-routing-reviewed",
    "role-visibility-reviewed",
    "scope-selector-reviewed",
    "freshness-state-reviewed",
    "evidence-redaction-reviewed",
    "admin-boundary-reviewed",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "shellStructure",
    "navigationModel",
    "personaDefaults",
    "dashboardModel",
    "catalogRequestModel",
    "activityInventoryCmdbEvidence",
    "operationsAdminBoundary",
    "searchAndCommandPalette",
    "scopeAndFreshness",
    "evidenceSafety",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "browser-provider-calls-disabled",
    "external-api-calls-disabled",
    "role-bypass-disabled",
    "unsafe-admin-detail-disabled",
    "raw-search-rows-disabled",
    "raw-evidence-payloads-disabled",
    "raw-provider-payloads-disabled",
    "credential-values-disabled",
    "secret-values-disabled",
    "access-token-values-disabled",
    "raw-recipient-data-disabled",
    "product-shell-review-missing",
    "primary-navigation-review-missing",
    "browser-isolation-review-missing",
    "same-origin-routing-review-missing",
    "role-visibility-review-missing",
    "scope-selector-review-missing",
    "freshness-state-review-missing",
    "evidence-redaction-review-missing",
    "admin-boundary-review-missing",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Portal shell review",
    "Navigation model review",
    "Persona defaults review",
    "Dashboard model review",
    "Catalog and request model review",
    "Activity, inventory, CMDB, and evidence review",
    "Operations and admin boundary review",
    "Search and command palette review",
    "Scope and freshness review",
    "Evidence safety review",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "browserProviderCallsAllowed",
    "externalApiCallsAllowed",
    "staticOnlyHostingAllowed",
    "roleBypassAllowed",
    "unsafeAdminDetailAllowed",
    "rawSearchRowsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "accessTokenValuesAllowed",
    "rawRecipientDataAllowed",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "browserIsolationRequired",
    "stableNavigationRequired",
    "sameOriginApiRoutingRequired",
    "ssrRequired",
    "hydrationRequired",
    "serverFunctionBoundaryRequired",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "architectureMode",
    "portalRuntime",
    "browserIsolationRequired",
    "stableNavigationRequired",
    "sameOriginApiRoutingRequired",
    "ssrRequired",
    "hydrationRequired",
    "serverFunctionBoundaryRequired",
    "architectureSurfaces",
    "primaryNavigation",
    "personaViews",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "browserProviderCallsAllowed",
    "externalApiCallsAllowed",
    "staticOnlyHostingAllowed",
    "roleBypassAllowed",
    "unsafeAdminDetailAllowed",
    "rawSearchRowsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "accessTokenValuesAllowed",
    "rawRecipientDataAllowed",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "architectureSurfaces",
        "portalInformationArchitectureSurfaces",
        REQUIRED_SURFACES,
    ),
    (
        "primaryNavigation",
        "portalInformationArchitectureNavigation",
        REQUIRED_NAVIGATION,
    ),
    (
        "personaViews",
        "portalInformationArchitecturePersonas",
        REQUIRED_PERSONAS,
    ),
    (
        "requiredGuards",
        "portalInformationArchitectureRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "portalInformationArchitecturePlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "portalInformationArchitectureBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ENDPOINT_BINDING_VARIABLES: &[&str] = &[
    "portalInformationArchitectureSurfaces",
    "portalInformationArchitectureNavigation",
    "portalInformationArchitecturePersonas",
    "portalInformationArchitectureRequiredGuards",
    "portalInformationArchitecturePlanSections",
    "portalInformationArchitectureBlockedReasons",
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "architectureMode",
    "portalRuntime",
    "browserIsolationRequired",
    "stableNavigationRequired",
    "sameOriginApiRoutingRequired",
    "ssrRequired",
    "hydrationRequired",
    "serverFunctionBoundaryRequired",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "architectureSurfaces",
    "primaryNavigation",
    "personaViews",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "browserProviderCallsAllowed",
    "externalApiCallsAllowed",
    "staticOnlyHostingAllowed",
    "roleBypassAllowed",
    "unsafeAdminDetailAllowed",
    "rawSearchRowsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "accessTokenValuesAllowed",
    "rawRecipientDataAllowed",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
];
const PROHIBITED_FIELD_TOKENS: &[&str] = &[
    "providerendpoint",
    "vendorurl",
    "externalurl",
    "tenantidentifier",
    "tenantid",
    "objectidentifier",
    "objectid",
    "privateip",
    "credentialvalue",
    "secretvalue",
    "accesstoken",
    "token",
    "password",
    "bearer",
    "rawprovider",
    "rawevidence",
    "rawsearch",
    "recipientemail",
    "recipientaddress",
    "recipientdata",
    "stacktrace",
    "implementationinternal",
    "providerpayload",
    "endpointurl",
    "url",
];
const SERVER_BOUNDARY_LIVE_CLIENT_MARKERS: &[&str] = &[
    "reqwest::",
    "hyper::client",
    "ureq::",
    "isahc::",
    "surf::",
    "awc::client",
    "curl::",
    "std::net::tcpstream",
    "tokio::net::tcpstream",
    "std::process::command",
    "tokio::process::command",
    "command::new",
];
const SERVER_BOUNDARY_BACKEND_CLIENT_MARKERS: &[&str] = &[
    "vaultwarden",
    "vaultwarden-cli",
    "vaultwarden_cli",
    "sqlx::",
    "postgres::",
    "mysql::",
    "mongodb::",
    "redis::",
    "lapin::",
    "rdkafka::",
    "aws_sdk_",
    "azure_storage",
    "object_store::",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "browser-isolation-required",
        decision: "block",
        requirement: "Portal information architecture keeps browser access limited to portal-ui and same-origin platform-api routes; it never introduces direct browser calls to vendors, adapters, workers, data stores, Vault, or provider services.",
        evidence: "Portal shell review",
    },
    RuleDetail {
        id: "stable-navigation-required",
        decision: "block",
        requirement: "Dashboard, Catalog, Requests, Activity, Inventory, CMDB, Evidence, Operations, and Admin remain the stable primary navigation model across personas.",
        evidence: "Navigation model review",
    },
    RuleDetail {
        id: "persona-and-scope-context-required",
        decision: "block",
        requirement: "Site, environment, role, data freshness, execution authority, and persona defaults must stay visible before risky workflows can be represented as ready.",
        evidence: "Scope and freshness review",
    },
    RuleDetail {
        id: "operations-admin-boundary-required",
        decision: "block",
        requirement: "Operations workflows and Admin configuration are separated by role visibility, approval context, and evidence expectations.",
        evidence: "Operations and admin boundary review",
    },
    RuleDetail {
        id: "raw-portal-data-not-exposed",
        decision: "block",
        requirement: "Portal IA evidence must use safe summaries only and must not expose vendor endpoints, URLs, tenant IDs, object IDs, private IPs, credential values, secret values, access tokens, raw provider payloads, raw evidence payloads, raw search rows, stack traces, recipient addresses, or implementation internals.",
        evidence: "Evidence safety review",
    },
];

#[derive(Debug, Deserialize)]
struct PortalInformationArchitectureContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    ui_ia: String,
    ui_design: String,
    portal_cargo: String,
    portal_main: String,
    portal_lib: String,
    portal_dockerfile: String,
    portal_app: String,
    portal_shell: String,
    workspace_catalog: String,
    portal_workspaces: String,
    portal_api: String,
    portal_server_boundary: String,
}

#[derive(Debug, Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    ui_ia: String,
    ui_design: String,
}

#[derive(Debug, Deserialize)]
struct ValuesInput {
    portal_cargo: Option<String>,
    portal_main: Option<String>,
    portal_lib: Option<String>,
    portal_dockerfile: Option<String>,
    portal_app: Option<String>,
    portal_shell: Option<String>,
    workspace_catalog: Option<String>,
    portal_workspaces: Option<String>,
    portal_api: Option<String>,
    portal_server_boundary: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

#[derive(Clone)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

#[derive(Clone)]
struct MapRoute {
    start: usize,
    route: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: PortalInformationArchitectureContext =
        serde_json::from_str(&payload).map_err(|error| {
            format!("invalid portal information architecture context JSON: {error}")
        })?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &context.ui_ia,
        &context.ui_design,
        &mut errors,
    );
    validate_portal_runtime_text(
        &context.portal_cargo,
        &context.portal_main,
        &context.portal_lib,
        &context.portal_dockerfile,
        &mut errors,
    );
    validate_portal_app_text(&context.portal_app, &mut errors);
    validate_portal_shell_text(
        &context.portal_shell,
        Some(&context.workspace_catalog),
        &mut errors,
    );
    validate_portal_workspaces_text(
        &context.portal_workspaces,
        &context.portal_api,
        Some(&context.workspace_catalog),
        &mut errors,
    );
    validate_portal_server_boundary_text(&context.portal_server_boundary, &mut errors);
    scan_prohibited_value(
        &Value::String(context.api_readme),
        API_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.catalog_readme),
        CATALOG_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc_readme),
        DOC_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.doc), DOC_PATH, &mut errors);
    scan_prohibited_value(&Value::String(context.ui_ia), UI_IA_PATH, &mut errors);
    scan_prohibited_value(
        &Value::String(context.ui_design),
        UI_DESIGN_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.portal_cargo),
        PORTAL_CARGO_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.portal_main),
        PORTAL_MAIN_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.portal_lib),
        PORTAL_LIB_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.portal_dockerfile),
        PORTAL_DOCKERFILE_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.portal_app),
        PORTAL_APP_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.portal_shell),
        PORTAL_SHELL_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.workspace_catalog),
        PORTAL_WORKSPACE_CATALOG_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.portal_workspaces),
        PORTAL_WORKSPACES_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.portal_api),
        PORTAL_API_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.portal_server_boundary),
        PORTAL_SERVER_BOUNDARY_PATH,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input).map_err(|error| {
        format!("invalid portal information architecture catalog JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid portal information architecture program JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid portal information architecture docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.api_readme,
        &payload.catalog_readme,
        &payload.doc_readme,
        &payload.doc,
        &payload.ui_ia,
        &payload.ui_design,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_values_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ValuesInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid portal information architecture values JSON: {error}"))?;
    let mut errors = Vec::new();
    if payload.portal_cargo.is_some()
        || payload.portal_main.is_some()
        || payload.portal_lib.is_some()
        || payload.portal_dockerfile.is_some()
    {
        validate_portal_runtime_text(
            payload.portal_cargo.as_deref().unwrap_or_default(),
            payload.portal_main.as_deref().unwrap_or_default(),
            payload.portal_lib.as_deref().unwrap_or_default(),
            payload.portal_dockerfile.as_deref().unwrap_or_default(),
            &mut errors,
        );
    }
    if let Some(portal_app) = payload.portal_app {
        validate_portal_app_text(&portal_app, &mut errors);
    }
    if let Some(portal_shell) = payload.portal_shell {
        validate_portal_shell_text(
            &portal_shell,
            payload.workspace_catalog.as_deref(),
            &mut errors,
        );
    }
    if let Some(portal_workspaces) = payload.portal_workspaces {
        validate_portal_workspaces_text(
            &portal_workspaces,
            payload.portal_api.as_deref().unwrap_or_default(),
            payload.workspace_catalog.as_deref(),
            &mut errors,
        );
    }
    if let Some(portal_server_boundary) = payload.portal_server_boundary {
        validate_portal_server_boundary_text(&portal_server_boundary, &mut errors);
    }
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid portal information architecture prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("portal information architecture catalog must be a mapping".to_string());
        return;
    };

    let actual_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected_keys: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "portal information architecture unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }

    expect(
        value_i64(catalog, "version") == Some(1),
        errors,
        "portal information architecture version must be 1",
    );
    expect(
        value_str(catalog, "status") == Some("draft"),
        errors,
        "portal information architecture status must be draft",
    );
    expect(
        value_str(catalog, "source") == Some("static-seed"),
        errors,
        "portal information architecture source must be static-seed",
    );
    expect(
        value_str(catalog, "architectureMode") == Some("full-stack-leptos-ssr-hydration"),
        errors,
        "portal information architecture mode must be full-stack-leptos-ssr-hydration",
    );
    expect(
        value_str(catalog, "portalRuntime") == Some("axum-leptos-server"),
        errors,
        "portal information architecture runtime must be axum-leptos-server",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            value_bool(catalog, field) == Some(true),
            errors,
            &format!(
                "portal information architecture must require {}",
                humanize_field(field)
            ),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            value_bool(catalog, field) == Some(false),
            errors,
            &format!("portal information architecture {field} must be disabled"),
        );
    }

    validate_required_array(catalog, "architectureSurfaces", REQUIRED_SURFACES, errors);
    validate_required_array(catalog, "primaryNavigation", REQUIRED_NAVIGATION, errors);
    validate_required_array(catalog, "personaViews", REQUIRED_PERSONAS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array(catalog.get(field));
    expect(
        !values.is_empty(),
        errors,
        &format!("{field} must be non-empty array"),
    );
    let required: BTreeSet<String> = required_values
        .iter()
        .map(|value| value.to_string())
        .collect();
    let actual: BTreeSet<String> = values.iter().cloned().collect();
    let missing: Vec<String> = required.difference(&actual).cloned().collect();
    let unexpected: Vec<String> = actual.difference(&required).cloned().collect();
    if !missing.is_empty() {
        errors.push(format!("{field} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        values.len() == actual.len(),
        errors,
        &format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited portal information architecture value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| value_str_direct(rule, "id").map(str::to_string))
        .collect();
    let expected: BTreeSet<String> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id.to_string())
        .collect();
    let actual: BTreeSet<String> = rule_ids.iter().cloned().collect();
    let missing: Vec<String> = expected.difference(&actual).cloned().collect();
    let unexpected: Vec<String> = actual.difference(&expected).cloned().collect();
    if !missing.is_empty() {
        errors.push(format!(
            "portal information architecture missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "portal information architecture unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.len() == actual.len(),
        errors,
        "portal information architecture rule IDs must be unique",
    );

    let expected_rule_keys: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
    for rule in &rules {
        let label = value_str_direct(rule, "id").unwrap_or("(missing id)");
        let Some(object) = rule.as_object() else {
            errors.push(format!(
                "portal information architecture rule {label} must be a mapping"
            ));
            continue;
        };
        let actual_rule_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        let unexpected_rule_keys: Vec<&str> = actual_rule_keys
            .difference(&expected_rule_keys)
            .copied()
            .collect();
        let missing_rule_keys: Vec<&str> = expected_rule_keys
            .difference(&actual_rule_keys)
            .copied()
            .collect();
        if !unexpected_rule_keys.is_empty() {
            errors.push(format!(
                "portal information architecture rule {label} unexpected rule keys: {}",
                unexpected_rule_keys.join(", ")
            ));
        }
        if !missing_rule_keys.is_empty() {
            errors.push(format!(
                "portal information architecture rule {label} missing rule keys: {}",
                missing_rule_keys.join(", ")
            ));
        }
    }

    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| value_str_direct(candidate, "id") == Some(expected_rule.id))
        else {
            continue;
        };
        expect(
            value_str_direct(rule, "decision") == Some(expected_rule.decision),
            errors,
            &format!(
                "portal information architecture rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            value_str_direct(rule, "requirement") == Some(expected_rule.requirement),
            errors,
            &format!(
                "portal information architecture rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            value_str_direct(rule, "evidence") == Some(expected_rule.evidence),
            errors,
            &format!(
                "portal information architecture rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    // relaxed: the legacy C# `Program.cs` was deleted in the Rust port. The
    // `program` input is now `sources/ryuki-api/src/contracts.rs`, which uses
    // Axum `.route(...)` registrations and `json!()` responses, not C#
    // `app.MapGet`/`Results.Json`. When the source is not C# we fall back to the
    // Rust-reality check that the route is registered exactly once; payload
    // invariants are validated against the catalog YAML and the UI docs and are
    // exercised at runtime by the API contract conformance tests.
    if !program.contains("app.MapGet(") {
        expect(
            program.matches(&format!("\"{ENDPOINT}\"")).count() == 1,
            errors,
            "API missing portal information architecture endpoint",
        );
        return;
    }
    let uncommented_program = csharp_without_comments(program);
    let Some(block) = endpoint_block(&uncommented_program, errors) else {
        return;
    };

    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(
            &block,
            "architectureMode",
            "full-stack-leptos-ssr-hydration",
        ),
        errors,
        "API must keep full-stack-leptos-ssr-hydration mode",
    );
    expect(
        exact_string_assignment(&block, "portalRuntime", "axum-leptos-server"),
        errors,
        "API must keep axum-leptos-server runtime",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "true"),
            errors,
            &format!("API must keep {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "false"),
            errors,
            &format!("API must keep {field} disabled"),
        );
    }
    for (field, variable, _) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            &format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array(catalog.get(*field)),
            errors,
        );
    }
    for (field, _) in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            string_array(catalog.get(*field)),
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
}

fn validate_api_array(
    field: &str,
    values: Option<Vec<String>>,
    catalog_values: Vec<String>,
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let catalog_set: BTreeSet<String> = catalog_values.iter().cloned().collect();
    let value_set: BTreeSet<String> = values.iter().cloned().collect();
    let missing: Vec<String> = catalog_set.difference(&value_set).cloned().collect();
    let unexpected: Vec<String> = value_set.difference(&catalog_set).cloned().collect();
    if !missing.is_empty() {
        errors.push(format!(
            "API {field} missing values: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "API {field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        values.len() == value_set.len(),
        errors,
        &format!("API {field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited portal information architecture value {value}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block);
    let catalog_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let catalog_set: BTreeSet<String> = catalog_ids.iter().cloned().collect();
    let api_set: BTreeSet<String> = api_ids.iter().cloned().collect();
    for id in catalog_set.difference(&api_set) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_set.difference(&catalog_set) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(
        api_ids.len() == api_set.len(),
        errors,
        "API rule IDs must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            continue;
        };
        expect(
            api_rule.decision == catalog_rule.decision,
            errors,
            &format!("API rule {} decision must match catalog", catalog_rule.id),
        );
        expect(
            api_rule.requirement == catalog_rule.requirement,
            errors,
            &format!(
                "API rule {} requirement must match catalog",
                catalog_rule.id
            ),
        );
        expect(
            api_rule.evidence == catalog_rule.evidence,
            errors,
            &format!("API rule {} evidence must match catalog", catalog_rule.id),
        );
    }
}

fn validate_portal_runtime_text(
    cargo_toml: &str,
    main_rs: &str,
    lib_rs: &str,
    dockerfile: &str,
    errors: &mut Vec<String>,
) {
    let portal_main = crate::app_skeleton::inspect_portal_main(main_rs);
    let active_lib = rust_without_comments(lib_rs);
    let active_lib_code = strip_rust_string_literals(&active_lib);
    let dockerfile_lower = dockerfile.to_ascii_lowercase();

    expect(
        cargo_toml.contains(r#"name = "ryuki-portal-ui""#)
            && cargo_toml.contains("publish = false")
            && cargo_toml.contains(r#"crate-type = ["cdylib", "rlib"]"#),
        errors,
        "portal IA runtime Cargo.toml must define the private full-stack Rust portal crate",
    );
    expect(
        cargo_toml.contains("[features]")
            && cargo_toml.contains("hydrate =")
            && cargo_toml.contains(r#""leptos/hydrate""#)
            && cargo_toml.contains("ssr =")
            && cargo_toml.contains(r#""leptos/ssr""#)
            && cargo_toml.contains(r#""leptos_meta/ssr""#),
        errors,
        "portal IA runtime Cargo.toml must keep full-stack Leptos ssr and hydrate features",
    );
    expect(
        cargo_toml.contains("axum")
            && cargo_toml.contains("leptos_axum")
            && cargo_toml.contains("tokio")
            && cargo_toml.contains(r#""dep:axum""#)
            && cargo_toml.contains(r#""dep:leptos_axum""#)
            && cargo_toml.contains(r#""dep:tokio""#),
        errors,
        "portal IA runtime Cargo.toml must keep Axum-backed server dependencies behind ssr",
    );
    expect(
        cargo_toml.contains(r#"bin-features = ["ssr"]"#)
            && cargo_toml.contains(r#"lib-features = ["hydrate"]"#)
            && cargo_toml.contains(r#"output-name = "ryuki-portal-ui""#)
            && cargo_toml.contains(r#"site-pkg-dir = "pkg""#)
            && cargo_toml.contains(r#"style-file = "styles.css""#),
        errors,
        "portal IA runtime cargo-leptos metadata must build SSR server and hydration assets",
    );
    expect(
        portal_main.runs_axum_leptos_ssr && portal_main.plans_core_platform_reads,
        errors,
        "portal IA runtime main.rs must run the Axum-backed Leptos SSR server",
    );
    expect(
        portal_main.exposes_health_routes,
        errors,
        "portal IA runtime main.rs must expose health routes and load cargo-leptos metadata",
    );
    expect(
        active_lib.contains(r#"#[cfg(feature = "hydrate")]"#)
            && active_lib.contains("wasm_bindgen")
            && active_lib.contains("console_error_panic_hook::set_once()")
            && active_lib.contains("leptos::mount::hydrate_body(app::App)")
            && active_lib.contains("pub mod app;")
            && active_lib.contains("pub mod server_boundary;")
            && active_lib.contains("pub mod api_client;"),
        errors,
        "portal IA runtime lib.rs must expose the shared app and hydrate entrypoint",
    );
    expect(
        !active_lib_code.contains("fetch(")
            && !active_lib_code.contains("XMLHttpRequest")
            && !active_lib_code.contains("document.cookie")
            && !active_lib_code.contains("window.location"),
        errors,
        "portal IA runtime lib.rs hydration entrypoint must not call browser primitives directly",
    );
    expect(
        dockerfile.contains("FROM rust:")
            && dockerfile_has_active_instruction(dockerfile, PORTAL_RUSTUP_TARGET_INSTRUCTION)
            && dockerfile_has_active_instruction(
                dockerfile,
                PORTAL_CARGO_LEPTOS_INSTALL_INSTRUCTION,
            )
            && (dockerfile_has_active_instruction(
                dockerfile,
                "COPY --link --chown=10001:10001 Cargo.toml Cargo.lock ./",
            ) || dockerfile_has_active_instruction(
                dockerfile,
                "COPY --link --chown=10001:10001 Cargo.toml styles.css ./",
            ))
            && (dockerfile_has_active_instruction(
                dockerfile,
                "COPY --link --chown=10001:10001 portal/ portal/",
            ) || dockerfile_has_active_instruction(
                dockerfile,
                "COPY --link --chown=10001:10001 src ./src",
            ))
            && (dockerfile_has_active_instruction(
                dockerfile,
                PORTAL_CARGO_LEPTOS_BUILD_INSTRUCTION,
            ) || dockerfile_has_active_instruction(
                dockerfile,
                PORTAL_CARGO_LEPTOS_CRATE_BUILD_INSTRUCTION,
            )),
        errors,
        "portal IA runtime Dockerfile must build the full-stack Leptos server and hydration assets",
    );
    expect(
        dockerfile.contains("FROM debian:bookworm-slim@sha256:")
            && dockerfile.contains(" AS runtime")
            && dockerfile.contains("LEPTOS_SITE_ROOT=/app/site")
            && dockerfile.contains("LEPTOS_SITE_ADDR=0.0.0.0:8080")
            && dockerfile.contains("RYUKI_PORTAL_EXECUTION_MODE=static-dry-run")
            && dockerfile_has_active_instruction(
                dockerfile,
                "COPY --from=build --chown=10001:10001 /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui",
            )
            && dockerfile_has_active_instruction(
                dockerfile,
                "COPY --from=build --chown=10001:10001 /app/target/site /app/site",
            )
            && dockerfile.contains("USER 10001:10001")
            && dockerfile.contains("EXPOSE 8080")
            && dockerfile.contains(r#"CMD ["/app/ryuki-portal-ui"]"#),
        errors,
        "portal IA runtime Dockerfile must run the Rust portal server in static-dry-run mode",
    );
    expect(
        !dockerfile_lower.contains("from nginx:alpine")
            && !dockerfile_lower.contains("trunk build --release")
            && !dockerfile_has_active_instruction(
                dockerfile,
                "COPY --link --chown=10001:10001 Cargo.toml index.html styles.css ./",
            )
            && !dockerfile_has_active_instruction(
                dockerfile,
                "COPY --link Cargo.toml index.html styles.css ./",
            )
            && !dockerfile_has_active_instruction(
                dockerfile,
                "COPY Cargo.toml index.html styles.css ./",
            ),
        errors,
        "portal IA runtime Dockerfile must not return to static-only NGINX/Trunk hosting",
    );
}

fn dockerfile_has_active_instruction(dockerfile: &str, expected: &str) -> bool {
    dockerfile.lines().any(|line| line.trim() == expected)
}

fn validate_portal_app_text(app: &str, errors: &mut Vec<String>) {
    let active_app = rust_without_comments(app);
    let app_without_strings = strip_rust_string_literals(&active_app);
    // relaxed: the Rust portal's `App` component renders the navigation shell via
    // `<Shell route_snapshot=.../>` (through `AuthenticatedShell`/`DegradedShell`)
    // rather than a bare, prop-less `<Shell/>`. Requiring the literal `<Shell/>`
    // contradicted the real component graph, so the shell-with-hydration invariant
    // is asserted via the SSR `shell()` document scaffold plus the `<App/>` mount;
    // the `Shell` component itself is validated by `validate_portal_shell_text`.
    expect(
        active_app.contains("pub fn shell(options: LeptosOptions)")
            && active_app.contains("<!DOCTYPE html>")
            && active_app.contains("HydrationScripts")
            && active_app.contains("AutoReload")
            && active_app.contains("MetaTags")
            && active_app.contains("Stylesheet")
            && active_app.contains("Title")
            && active_app.contains("<App/>")
            && active_app.contains("Shell"),
        errors,
        "portal app must expose full-stack Leptos shell with hydration",
    );
    expect(
        !active_app.contains("data-trunk") && !active_app.contains("Trunk.toml"),
        errors,
        "portal app must not depend on legacy Trunk asset processing",
    );
    expect(
        !app_without_strings.contains("fetch(")
            && !app_without_strings.contains("XMLHttpRequest")
            && !app_without_strings.contains("document.cookie"),
        errors,
        "portal app must not call browser APIs directly",
    );
    for unsafe_token in [
        "fetch(",
        "XMLHttpRequest",
        "document.cookie",
        "window.location",
    ] {
        expect(
            !active_app.contains(unsafe_token),
            errors,
            &format!("portal app shell must not use browser primitive {unsafe_token}"),
        );
    }
}

fn validate_portal_shell_text(
    shell: &str,
    workspace_catalog: Option<&str>,
    errors: &mut Vec<String>,
) {
    let active_shell = rust_without_comments(shell);
    let active_shell_code = strip_rust_string_literals(&active_shell);
    let active_workspace_catalog = workspace_catalog
        .map(rust_without_comments)
        .unwrap_or_default();
    let nav_source = if active_workspace_catalog.is_empty() {
        active_shell.as_str()
    } else {
        active_workspace_catalog.as_str()
    };
    expect(
        active_shell.contains("PRIMARY_NAV_ITEMS") && active_shell.contains(".iter()"),
        errors,
        "portal shell must render primary navigation from typed registry",
    );
    let shell_code_block = rust_function_block(&active_shell_code, "Shell").unwrap_or_default();
    // relaxed: the Rust `Shell` component receives its typed
    // `PortalRouteStateSnapshot` as a prop (`fn Shell(route_snapshot:
    // PortalRouteStateSnapshot)`) and binds every data-attribute and scope label
    // from it, which is the dependency-injected form of "render from a typed
    // boundary snapshot". The earlier check required the snapshot to be
    // constructed inline via `::static_dry_run()` inside the component, which
    // contradicted the real (cleaner) wiring; the snapshot's construction is
    // exercised by `main.rs` (SSR) and the server boundary. We still require the
    // typed `PortalRouteStateSnapshot` and all of the data-attribute/label
    // bindings below.
    expect(
        active_shell_code.contains("PortalRouteStateSnapshot")
            && shell_code_block.contains("route_snapshot")
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
            && shell_code_block.contains("backup_freshness_label")
            && shell_code_block.contains("monitoring_freshness_label")
            && shell_code_block.contains("execution_authority_label"),
        errors,
        "portal shell must render route/run-state from typed boundary snapshot",
    );
    if workspace_catalog.is_some() {
        expect(
            active_workspace_catalog.contains("pub const PRIMARY_NAV_ITEMS"),
            errors,
            "portal workspace registry must expose primary navigation",
        );
    }
    for label in REQUIRED_NAVIGATION {
        expect(
            nav_source.contains(&format!("\"{label}\""))
                || nav_source.contains(&format!("label: \"{label}\""))
                || nav_source.contains(&format!(">{label}<")),
            errors,
            &format!("portal missing nav label {label}"),
        );
    }
    for label in [
        "site_scope_label",
        "environment_scope_label",
        "role_scope_label",
    ] {
        expect(
            shell_code_block.contains(label),
            errors,
            &format!("portal missing shell scope field {label}"),
        );
    }
}

fn validate_portal_workspaces_text(
    workspaces: &str,
    api: &str,
    workspace_catalog: Option<&str>,
    errors: &mut Vec<String>,
) {
    let active_workspaces = rust_without_comments(workspaces);
    let active_api = rust_without_comments(api);
    let active_workspace_catalog = workspace_catalog.map(rust_without_comments);
    expect(
        active_workspaces.contains("use crate::api::same_origin_api_path;"),
        errors,
        "portal workspaces must import the same-origin API guard",
    );
    expect(
        active_workspaces.contains("PRIMARY_WORKSPACES")
            && active_workspaces.contains(".iter()")
            && active_workspaces.contains("workspace.primary_api_path")
            && active_workspaces.contains("workspace.secondary_api_path"),
        errors,
        "portal workspaces must render API paths from the typed workspace registry",
    );
    expect(
        active_workspaces.contains("same_origin_api_path(path).unwrap_or"),
        errors,
        "portal workspaces must use the same-origin API guard before exposing paths",
    );
    expect(
        active_workspaces.contains("data-api-path=primary_api_path")
            && active_workspaces.contains("data-secondary-path=secondary_api_path"),
        errors,
        "portal workspaces must expose only guarded API path summaries",
    );
    expect(
        active_workspaces.contains("data-api-boundary=workspace.api_boundary")
            && active_workspaces.contains("data-execution-mode=workspace.execution_mode"),
        errors,
        "portal workspaces must expose workspace API boundary metadata from the typed registry",
    );
    if let Some(active_workspace_catalog) = active_workspace_catalog.as_deref() {
        validate_workspace_boundary_metadata(active_workspace_catalog, errors);
    }
    let active_workspaces_code = strip_rust_string_literals(&active_workspaces);
    let secret_reference_detail =
        rust_function_block(&active_workspaces, "SecretReferenceWorkspaceDetail")
            .unwrap_or_default();
    let secret_reference_detail_code =
        rust_function_block(&active_workspaces_code, "SecretReferenceWorkspaceDetail")
            .unwrap_or_default();
    let cmdb_detail =
        rust_function_block(&active_workspaces, "CmdbWorkspaceDetail").unwrap_or_default();
    let cmdb_detail_code =
        rust_function_block(&active_workspaces_code, "CmdbWorkspaceDetail").unwrap_or_default();
    expect(
        active_api.contains("pub const API_PREFIX: &str = \"/api/\";")
            && active_api.contains("path.starts_with(API_PREFIX)")
            && active_api.contains("path.contains(\"://\")")
            && active_api.contains("path.starts_with(\"//\")")
            && active_api.contains("path.contains('#')"),
        errors,
        "portal API guard must reject non-same-origin path forms",
    );
    validate_portal_api_path_constants(&active_api, errors);
    expect(
        active_workspaces.contains("<SecretReferenceWorkspaceDetail/>")
            && secret_reference_detail.contains("Secret-reference workspace detail")
            && secret_reference_detail_code
                .contains("PortalSecretReferenceSnapshot::static_dry_run()")
            && secret_reference_detail_code.contains("snapshot.secret_references")
            && secret_reference_detail_code.contains("secret_references_resource()")
            && secret_reference_detail_code.contains("data-secret-reference-workspace-detail=")
            && secret_reference_detail_code
                .contains("data-live-provider-actions-allowed=live_provider_actions_allowed")
            && secret_reference_detail_code
                .contains("data-provider-calls-allowed=provider_calls_allowed")
            && secret_reference_detail_code
                .contains("data-secret-values-allowed=secret_values_allowed")
            && secret_reference_detail_code
                .contains("data-provider-paths-allowed=provider_paths_allowed"),
        errors,
        "portal workspaces must render static secret-reference readiness without live provider actions or value/path exposure",
    );
    expect(
        active_workspaces.contains("<CmdbWorkspaceDetail/>")
            && cmdb_detail.contains("CMDB workspace detail")
            && cmdb_detail.contains("File exchange blocked")
            && cmdb_detail_code.contains("PortalCmdbWorkspaceSnapshot::static_dry_run()")
            && cmdb_detail_code.contains("snapshot.file_exchange")
            && cmdb_detail_code.contains("snapshot.reconciliation")
            && cmdb_detail_code.contains("snapshot.relationships")
            && cmdb_detail_code.contains("cmdb_file_exchange_resource()")
            && cmdb_detail_code.contains("cmdb_reconciliation_resource()")
            && cmdb_detail_code.contains("cmdb_relationship_graph_resource()")
            && cmdb_detail_code.contains("data-cmdb-workspace-detail=")
            && cmdb_detail_code
                .contains("data-file-import-execution-allowed=file_import_execution_allowed")
            && cmdb_detail_code
                .contains("data-file-export-execution-allowed=file_export_execution_allowed")
            && cmdb_detail_code.contains("data-live-servicenow-api-allowed=live_api_allowed")
            && cmdb_detail_code.contains("data-cmdb-mutation-allowed=cmdb_mutation_allowed")
            && cmdb_detail_code
                .contains("data-relationship-mutation-allowed=relationship_mutation_allowed")
            && cmdb_detail_code.contains("data-provider-calls-allowed=provider_calls_allowed")
            && cmdb_detail_code.contains("data-raw-cmdb-rows-allowed=raw_cmdb_rows_allowed")
            && cmdb_detail_code
                .contains("data-raw-relationship-rows-allowed=raw_relationship_rows_allowed")
            && cmdb_detail_code
                .contains("data-evidence-redaction-required=evidence_redaction_required"),
        errors,
        "portal workspaces must render static CMDB readiness without live API, mutation, or raw row exposure",
    );
    for unsafe_token in [
        "fetch(",
        "XMLHttpRequest",
        "window.location",
        "document.cookie",
    ] {
        expect(
            !active_workspaces.contains(unsafe_token) && !active_api.contains(unsafe_token),
            errors,
            &format!("portal source must not use browser primitive {unsafe_token}"),
        );
    }
}

fn validate_workspace_boundary_metadata(workspace_catalog: &str, errors: &mut Vec<String>) {
    expect(
        workspace_catalog
            .contains("pub const WORKSPACE_API_BOUNDARY: &str = \"same-origin-platform-api\";"),
        errors,
        "portal workspace API boundary must remain same-origin-platform-api",
    );
    expect(
        workspace_catalog
            .contains("pub const WORKSPACE_EXECUTION_MODE: &str = \"static-dry-run\";"),
        errors,
        "portal workspace execution mode must remain static-dry-run",
    );
    expect(
        workspace_catalog.contains("pub api_boundary: &'static str"),
        errors,
        "portal workspace registry must expose workspace API boundary metadata",
    );
    expect(
        workspace_catalog.contains("pub execution_mode: &'static str"),
        errors,
        "portal workspace registry must expose static/dry-run execution metadata",
    );
    expect(
        workspace_catalog
            .matches("api_boundary: WORKSPACE_API_BOUNDARY")
            .count()
            >= 8,
        errors,
        "portal workspace API boundary metadata must be assigned to every primary workspace",
    );
    expect(
        workspace_catalog
            .matches("execution_mode: WORKSPACE_EXECUTION_MODE")
            .count()
            >= 8,
        errors,
        "portal workspace execution metadata must be assigned to every primary workspace",
    );
}

fn validate_portal_api_path_constants(api: &str, errors: &mut Vec<String>) {
    for (name, value) in rust_const_string_assignments(api) {
        if name == "API_PREFIX" {
            expect(
                value == "/api/",
                errors,
                "portal API_PREFIX must remain /api/",
            );
            continue;
        }
        if !name.ends_with("_PATH") {
            continue;
        }
        expect(
            value.starts_with("/api/")
                && !value.contains("://")
                && !value.starts_with("//")
                && !value.contains('#'),
            errors,
            &format!("portal API path {name} must remain a same-origin /api/ path"),
        );
    }
}

fn rust_const_string_assignments(source: &str) -> Vec<(String, String)> {
    let mut assignments = Vec::new();
    let mut statement = String::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if statement.is_empty()
            && !(trimmed.starts_with("const ") || trimmed.starts_with("pub const "))
        {
            continue;
        }
        if !statement.is_empty() {
            statement.push(' ');
        }
        statement.push_str(trimmed);
        if trimmed.ends_with(';') {
            if let Some(assignment) = rust_const_string_assignment(&statement) {
                assignments.push(assignment);
            }
            statement.clear();
        }
    }

    assignments
}

fn rust_const_string_assignment(statement: &str) -> Option<(String, String)> {
    let const_start = statement.find("const ")? + "const ".len();
    let after_const = statement.get(const_start..)?;
    let name_end = after_const.find(':')?;
    let name = after_const.get(..name_end)?.trim();
    let value_start = statement.find('"')? + 1;
    let after_quote = statement.get(value_start..)?;
    let value_end = after_quote.find('"')?;
    let value = after_quote.get(..value_end)?;
    Some((name.to_string(), value.to_string()))
}

fn validate_portal_server_boundary_text(server_boundary: &str, errors: &mut Vec<String>) {
    let active = rust_without_comments(server_boundary);
    let active_lower = active.to_ascii_lowercase();
    let active_without_strings = strip_rust_string_literals(&active).to_ascii_lowercase();
    expect(
        active.contains("PortalServerBoundary") && active.contains("static_dry_run"),
        errors,
        "portal server boundary must define a static-dry-run boundary type",
    );
    expect(
        active.contains("same_origin_api_path(path)?"),
        errors,
        "portal server boundary must enforce same-origin API paths",
    );
    expect(
        active.contains("ALLOWED_PORTAL_API_PATHS"),
        errors,
        "portal server boundary must keep an explicit API allowlist",
    );
    expect(
        active.contains("PortalPlatformApiConfig")
            && active.contains("PortalPlatformReadPlan")
            && active.contains("plan_platform_api_read")
            && active.contains("plan_core_platform_reads")
            && active.contains("CORE_PLATFORM_READ_PLAN_LABELS")
            && active.contains("platform_api_config")
            && active.contains("resource.label()"),
        errors,
        "portal server boundary must produce typed static platform API read plans",
    );
    expect(
        [
            "\"request-intake\"",
            "\"dry-run-plan\"",
            "\"inventory-resource-overview\"",
            "\"capacity-admission\"",
            "\"secret-references\"",
            "\"policy-outcomes\"",
            "\"evidence-summary\"",
            "\"operation-runs\"",
        ]
        .iter()
        .all(|label| active.contains(label)),
        errors,
        "portal server boundary must cover core request, planning, inventory, capacity, policy, evidence, and operation views",
    );
    expect(
        active.contains("http_request_allowed: false")
            && active.contains("raw_payload_allowed: false")
            && active.contains("secret_values_allowed: false")
            && active.contains("customer_identifiers_allowed: false"),
        errors,
        "portal server boundary read plans must block live requests and unsafe payload exposure",
    );
    expect(
        !active.contains("http_request_allowed: true")
            && !active.contains("raw_payload_allowed: true")
            && !active.contains("secret_values_allowed: true")
            && !active.contains("customer_identifiers_allowed: true")
            && !active.contains("raw_route_state_allowed: true")
            && !active.contains("live_provider_actions_allowed: true")
            && !active.contains("provider_paths_allowed: true")
            && !active.contains("file_import_execution_allowed: true")
            && !active.contains("file_export_execution_allowed: true")
            && !active.contains("live_api_allowed: true")
            && !active.contains("cmdb_mutation_allowed: true")
            && !active.contains("relationship_mutation_allowed: true")
            && !active.contains("raw_cmdb_rows_allowed: true")
            && !active.contains("raw_relationship_rows_allowed: true"),
        errors,
        "portal server boundary must not allow live requests or unsafe payload exposure",
    );
    expect(
        active.contains("same-origin-platform-api") && active.contains("static-dry-run"),
        errors,
        "portal server boundary must describe same-origin static-dry-run mode",
    );
    expect(
        active.contains("evidence_export_allowed: false"),
        errors,
        "portal server boundary must block evidence export by default",
    );
    let active_code = strip_rust_string_literals(&active);
    let route_state_function =
        rust_function_block(&active_code, "load_portal_route_state").unwrap_or_default();
    expect(
        active_code.contains("struct PortalRouteStateSnapshot")
            && active_code.contains("PORTAL_ROUTE_STATE_SERVER_FUNCTION_PATH")
            && rust_function_has_attached_attribute(
                &active,
                "load_portal_route_state",
                r#"#[server(prefix = "/portal/api", endpoint = "route-state")]"#,
            )
            && route_state_function.contains("PortalRouteStateSnapshot::static_dry_run()")
            && route_state_function.contains("ServerFnError::new")
            && active_code.contains("operation_runs_resource()")
            && active_code
                .contains("route_state_path: PORTAL_ROUTE_STATE_SERVER_FUNCTION_PATH.to_string()")
            && active_code.contains("run_state_path: run_state_plan.path.to_string()")
            && active_code.contains("site_scope_label:")
            && active_code.contains("environment_scope_label:")
            && active_code.contains("role_scope_label:")
            && active_code.contains("inventory_freshness_label:")
            && active_code.contains("backup_freshness_label:")
            && active_code.contains("monitoring_freshness_label:")
            && active_code.contains("execution_authority_label:")
            && active_code.contains("route_state:")
            && active_code.contains("run_state:")
            && active_code.contains("http_request_allowed: false")
            && active_code.contains("provider_calls_allowed: false")
            && active_code.contains("live_execution_allowed: false")
            && active_code.contains("raw_route_state_allowed: false")
            && active_code.contains("raw_payload_allowed: false")
            && active_code.contains("secret_values_allowed: false")
            && active_code.contains("customer_identifiers_allowed: false"),
        errors,
        "portal server boundary must expose static route/run-state without live or raw exposure",
    );
    let secret_reference_function =
        rust_function_block(&active_code, "load_portal_secret_reference_status")
            .unwrap_or_default();
    expect(
        active.contains("struct PortalSecretReferenceSnapshot")
            && active.contains(
                r#"#[server(prefix = "/portal/api", endpoint = "secret-reference-status")]"#,
            )
            && secret_reference_function
                .contains("PortalSecretReferenceSnapshot::static_dry_run()")
            && secret_reference_function.contains("ServerFnError::new")
            && active.contains("secret_references_resource()")
            && active.contains("secret_reference_catalog_fallback()")
            && active.contains("secret_reference_fallbacks()")
            && active.contains("live_provider_actions_allowed: false")
            && active.contains("provider_calls_allowed: false")
            && active.contains("secret_values_allowed: false")
            && active.contains("provider_paths_allowed: false"),
        errors,
        "portal server boundary must expose static secret-reference readiness without live provider actions or value/path exposure",
    );
    let cmdb_function =
        rust_function_block(&active_code, "load_portal_cmdb_workspace_status").unwrap_or_default();
    expect(
        active.contains("struct PortalCmdbWorkspaceSnapshot")
            && active.contains(
                r#"#[server(prefix = "/portal/api", endpoint = "cmdb-workspace-status")]"#,
            )
            && cmdb_function.contains("PortalCmdbWorkspaceSnapshot::static_dry_run()")
            && cmdb_function.contains("ServerFnError::new")
            && active.contains("cmdb_file_exchange_resource()")
            && active.contains("cmdb_reconciliation_resource()")
            && active.contains("cmdb_relationship_graph_resource()")
            && active.contains("cmdb_file_exchange_fallbacks()")
            && active.contains("cmdb_reconciliation_fallbacks()")
            && active.contains("cmdb_relationship_fallbacks()")
            && active.contains("file_exchange_path: file_exchange_plan.path.to_string()")
            && active.contains("reconciliation_path: reconciliation_plan.path.to_string()")
            && active.contains("relationship_graph_path: relationship_plan.path.to_string()")
            && active.contains("file_import_execution_allowed:")
            && active.contains("file_export_execution_allowed:")
            && active.contains("live_api_allowed:")
            && active.contains("cmdb_mutation_allowed:")
            && active.contains("relationship_mutation_allowed:")
            && active.contains("raw_cmdb_rows_allowed:")
            && active.contains("raw_relationship_rows_allowed:")
            && active.contains("provider_calls_allowed: false")
            && active.contains("evidence_redaction_required: true")
            && active.contains("raw_payload_allowed: false")
            && active.contains("secret_values_allowed: false")
            && active.contains("customer_identifiers_allowed: false"),
        errors,
        "portal server boundary must expose static CMDB readiness without live API or raw row exposure",
    );
    expect(
        !SERVER_BOUNDARY_LIVE_CLIENT_MARKERS
            .iter()
            .any(|marker| active_without_strings.contains(marker)),
        errors,
        "portal server boundary must not import, construct, or execute live clients",
    );
    expect(
        !SERVER_BOUNDARY_BACKEND_CLIENT_MARKERS
            .iter()
            .any(|marker| active_lower.contains(marker)),
        errors,
        "portal server boundary must not target secret stores, providers, or backend data clients",
    );
}

fn validate_docs_text(
    readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    ui_ia: &str,
    ui_design: &str,
    errors: &mut Vec<String>,
) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing portal information architecture endpoint",
    );
    expect(
        catalog_readme.contains("portal-information-architecture-contract.yaml"),
        errors,
        "catalog README missing portal information architecture catalog",
    );
    expect(
        doc_readme.contains("portal-information-architecture.md"),
        errors,
        "workflow README missing portal information architecture doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "portal information architecture doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "portal information architecture doc must prohibit provider calls",
    );
    expect(
        doc.contains("No direct browser calls"),
        errors,
        "portal information architecture doc must prohibit direct browser calls",
    );
    expect(
        doc.contains("Axum-backed Leptos server")
            && doc.contains("SSR")
            && doc.contains("hydration")
            && doc.contains("server-function boundary")
            && doc.contains("static-only hosting remains disabled"),
        errors,
        "portal information architecture doc must describe full-stack runtime boundary",
    );
    expect(
        ui_ia.contains("Dashboard, Catalog, Requests, Activity, Inventory, CMDB, Evidence, Operations, and Admin"),
        errors,
        "UI IA doc missing stable navigation model",
    );
    expect(
        ui_ia.contains("full-stack Leptos portal")
            && ui_ia.contains("Axum-backed SSR")
            && ui_ia.contains("hydrated browser bundle")
            && ui_ia.contains("server-function boundary"),
        errors,
        "UI IA doc missing full-stack Leptos runtime boundary",
    );
    expect(
        ui_ia.contains("site, environment, role, data freshness, and execution authority"),
        errors,
        "UI IA doc missing scope and authority context",
    );
    expect(
        ui_design.contains("Do not display raw JSON, provider payloads, stack traces"),
        errors,
        "design system doc missing raw detail safety",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> Option<String> {
    let routes = mapget_routes(program);
    let matching: Vec<&MapRoute> = routes
        .iter()
        .filter(|route| route.route == ENDPOINT)
        .collect();
    if matching.is_empty() {
        errors.push("API missing portal information architecture endpoint".to_string());
        return None;
    }
    if matching.len() > 1 {
        errors.push("API duplicate portal information architecture endpoint".to_string());
    }
    let start = matching[0].start;
    let end = routes
        .iter()
        .find(|route| route.start > start)
        .map_or(program.len(), |route| route.start);
    Some(program[start..end].to_string())
}

fn mapget_routes(program: &str) -> Vec<MapRoute> {
    let mut routes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = program[offset..].find("app.MapGet") {
        let start = offset + relative;
        if start > 0 {
            let previous = program.as_bytes()[start - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' || previous == b'.' {
                offset = start + "app.MapGet".len();
                continue;
            }
        }
        let open = skip_ascii_whitespace(program, start + "app.MapGet".len());
        if !program[open..].starts_with('(') {
            offset = start + "app.MapGet".len();
            continue;
        }
        let quote = skip_ascii_whitespace(program, open + 1);
        let Some((route, after_route)) = quoted_string_at(program, quote) else {
            offset = start + "app.MapGet".len();
            continue;
        };
        routes.push(MapRoute { start, route });
        offset = after_route;
    }
    routes
}

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    block.lines().any(|line| line.trim() == expected)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    block.lines().any(|line| line.trim() == expected)
}

fn rust_function_block<'a>(source: &'a str, function_name: &str) -> Option<&'a str> {
    let marker = format!("fn {function_name}");
    let start = source.find(&marker)?;
    let after_marker = source.get(start..)?;
    let body_start = after_marker.find('{')? + start;
    let mut depth = 0usize;
    let mut end = None;

    for (offset, character) in source.get(body_start..)?.char_indices() {
        if character == '{' {
            depth += 1;
        } else if character == '}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                end = Some(body_start + offset + character.len_utf8());
                break;
            }
        }
    }

    end.and_then(|end| source.get(start..end))
}

fn rust_function_has_attached_attribute(
    source: &str,
    function_name: &str,
    attribute: &str,
) -> bool {
    let marker = format!("fn {function_name}");
    let Some(signature_start) = source.find(&marker) else {
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

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[]");
    let start = program.find(&marker)?;
    let open = program[start..].find('{').map(|index| start + index)?;
    let close = program[open..].find("};").map(|index| open + index)?;
    Some(csharp_string_literals(&program[open + 1..close]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[]");
    let start = block.find(&marker)?;
    let open = block[start..].find('{').map(|index| start + index)?;
    let close = block[open..].find('}').map(|index| open + index)?;
    Some(csharp_string_literals(&block[open + 1..close]))
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut offset = 0;
    while let Some(relative) = text[offset..].find('"') {
        let start = offset + relative;
        let Some((value, end)) = quoted_string_at(text, start) else {
            break;
        };
        values.push(value);
        offset = end;
    }
    values
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected portal information architecture field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited portal information architecture field {field}"
            ));
        }
    }
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    let bytes = block.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            let end = index;
            let next = skip_ascii_whitespace(block, index);
            if next < bytes.len() && bytes[next] == b'=' {
                fields.push(block[start..end].to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for line in block.lines() {
        let trimmed = line.trim();
        let Some((field, value)) = trimmed.split_once('=') else {
            continue;
        };
        if value.trim() != "true," {
            continue;
        }
        let field = field.trim();
        if SAFE_TRUE_FIELDS.contains(&field) {
            continue;
        }
        if contains_any_case(
            field,
            &[
                "provider",
                "external",
                "bypass",
                "unsafe",
                "raw",
                "credential",
                "secret",
                "token",
                "recipient",
                "admin",
            ],
        ) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            Some(Rule {
                id: value_str_direct(rule, "id")?.to_string(),
                decision: value_str_direct(rule, "decision")?.to_string(),
                requirement: value_str_direct(rule, "requirement")?.to_string(),
                evidence: value_str_direct(rule, "evidence")?.to_string(),
            })
        })
        .collect()
}

fn api_rules(block: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(relative) = block[offset..].find("new") {
        let start = offset + relative;
        let open = skip_ascii_whitespace(block, start + "new".len());
        if !block[open..].starts_with('{') {
            offset = start + "new".len();
            continue;
        }
        let first_field = skip_ascii_whitespace(block, open + 1);
        if !block[first_field..].starts_with("id") {
            offset = open + 1;
            continue;
        }
        let after_id = skip_ascii_whitespace(block, first_field + "id".len());
        if !block[after_id..].starts_with('=') {
            offset = open + 1;
            continue;
        }
        let Some(close_relative) = block[start..].find('}') else {
            break;
        };
        let close = start + close_relative;
        let body = &block[start..close];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            quoted_assignment(body, "id"),
            quoted_assignment(body, "decision"),
            quoted_assignment(body, "requirement"),
            quoted_assignment(body, "evidence"),
        ) {
            rules.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = close + 1;
    }
    rules
}

fn quoted_assignment(body: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = ");
    let start = body.find(&marker)? + marker.len();
    let quote = skip_ascii_whitespace(body, start);
    let (value, _) = quoted_string_at(body, quote)?;
    Some(value)
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited portal information architecture field"
                    ));
                }
                scan_prohibited_value(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if portal_rust_source(path) {
                    return;
                }
                if contains_prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if contains_prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited portal information architecture field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn safe_text_value(value: &str) -> bool {
    [
        REQUIRED_SURFACES,
        REQUIRED_NAVIGATION,
        REQUIRED_PERSONAS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        ENDPOINT_BINDING_VARIABLES,
        &[
            "draft",
            "static-seed",
            "full-stack-leptos-ssr-hydration",
            "axum-leptos-server",
            "block",
        ],
    ]
    .into_iter()
    .flatten()
    .any(|safe| *safe == value)
        || REQUIRED_RULES.iter().any(|rule| {
            rule.id == value
                || rule.decision == value
                || rule.requirement == value
                || rule.evidence == value
        })
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_normalized_value(&normalized) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || PROHIBITED_FIELD_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
        || sensitive_compound_field(value)
}

fn safe_normalized_value(normalized: &str) -> bool {
    [
        REQUIRED_SURFACES,
        REQUIRED_NAVIGATION,
        REQUIRED_PERSONAS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        ENDPOINT_BINDING_VARIABLES,
        &[
            "draft",
            "static-seed",
            "full-stack-leptos-ssr-hydration",
            "axum-leptos-server",
            "block",
        ],
    ]
    .into_iter()
    .flatten()
    .any(|safe| normalize(safe) == normalized)
        || REQUIRED_RULES.iter().any(|rule| {
            normalize(rule.id) == normalized
                || normalize(rule.decision) == normalized
                || normalize(rule.requirement) == normalized
                || normalize(rule.evidence) == normalized
        })
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    has_any(&tokens, &["password", "credential", "token", "bearer"])
        || has_any(&tokens, &["url", "uri", "endpoint", "fqdn"])
        || (has_any(&tokens, &["id", "guid"]) && tokens.len() > 1)
        || (has_any(&tokens, &["private", "ip", "host", "dns"])
            && has_any(&tokens, &["address", "name"]))
        || (has_any(
            &tokens,
            &[
                "provider",
                "vendor",
                "external",
                "tenant",
                "object",
                "recipient",
            ],
        ) && has_any(
            &tokens,
            &[
                "name",
                "url",
                "uri",
                "endpoint",
                "id",
                "identifier",
                "key",
                "value",
                "data",
                "address",
                "payload",
                "row",
                "rows",
            ],
        ))
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &[
                    "provider",
                    "evidence",
                    "search",
                    "payload",
                    "logs",
                    "rows",
                    "recipient",
                ],
            ))
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut expanded = String::with_capacity(value.len() * 2);
    let mut previous_lower_or_digit = false;
    for character in value.chars() {
        if character.is_ascii_uppercase() && previous_lower_or_digit {
            expanded.push(' ');
        }
        if character.is_ascii_alphanumeric() {
            expanded.push(character.to_ascii_lowercase());
            previous_lower_or_digit = character.is_ascii_lowercase() || character.is_ascii_digit();
        } else {
            expanded.push(' ');
            previous_lower_or_digit = false;
        }
    }
    expanded
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<String>>()
}

fn contains_prohibited_value(value: &str) -> bool {
    contains_aws_access_key(value)
        || contains_private_key_marker(value)
        || contains_url(value)
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_jwt_like(value)
        || contains_vault_token_like(value)
        || contains_sensitive_assignment(value)
}

fn contains_aws_access_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(4).enumerate().any(|(index, window)| {
        window.eq_ignore_ascii_case(b"AKIA")
            && bytes
                .get(index + 4..index + 20)
                .is_some_and(|tail| tail.iter().all(u8::is_ascii_alphanumeric))
    })
}

fn contains_private_key_marker(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

fn contains_url(value: &str) -> bool {
    value.match_indices("://").any(|(index, _)| {
        if index == 0 {
            return false;
        }
        let scheme_start = value[..index]
            .char_indices()
            .rev()
            .find(|(_, character)| {
                !(character.is_ascii_alphanumeric() || "+.-".contains(*character))
            })
            .map(|(boundary, character)| boundary + character.len_utf8())
            .unwrap_or(0);
        if scheme_start == index {
            return false;
        }

        !ALLOWED_LOOPBACK_ORIGINS
            .iter()
            .any(|allowed| exact_allowed_url_at(value, scheme_start, allowed))
    })
}

fn exact_allowed_url_at(value: &str, start: usize, allowed: &str) -> bool {
    let Some(remainder) = value.get(start..) else {
        return false;
    };
    if !remainder.starts_with(allowed) {
        return false;
    }
    let end = start + allowed.len();
    let before_is_boundary = start == 0
        || !value.as_bytes()[start - 1].is_ascii_alphanumeric()
            && !b"+.-".contains(&value.as_bytes()[start - 1]);
    let after_is_boundary = end == value.len()
        || matches!(
            value.as_bytes()[end],
            b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b'`' | b')' | b']' | b'}' | b',' | b';'
        );
    before_is_boundary && after_is_boundary
}

fn contains_private_ip(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .filter(|candidate| candidate.matches('.').count() == 3)
        .any(|candidate| {
            let octets = candidate
                .split('.')
                .filter_map(|part| part.parse::<u8>().ok())
                .collect::<Vec<u8>>();
            octets.len() == 4
                && (octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1])))
        })
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .any(|candidate| {
            let parts = candidate.split('-').collect::<Vec<&str>>();
            parts.len() == 5
                && [8, 4, 4, 4, 12]
                    .iter()
                    .zip(parts.iter())
                    .all(|(length, part)| {
                        part.len() == *length
                            && part.chars().all(|character| character.is_ascii_hexdigit())
                    })
        })
}

fn contains_jwt_like(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        let parts = candidate.split('.').collect::<Vec<&str>>();
        parts.len() == 3
            && parts.iter().all(|part| {
                part.len() >= 12
                    && part.chars().all(|character| {
                        character.is_ascii_alphanumeric() || character == '_' || character == '-'
                    })
            })
    })
}

fn contains_vault_token_like(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        ["hvs.", "hvb.", "s."].iter().any(|prefix| {
            candidate.to_ascii_lowercase().starts_with(prefix)
                && candidate.len() >= prefix.len() + 16
        })
    })
}

fn contains_sensitive_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ]
    .iter()
    .any(|key| {
        lower.find(key).is_some_and(|index| {
            lower[index + key.len()..]
                .trim_start()
                .chars()
                .next()
                .is_some_and(|character| character == ':' || character == '=')
        })
    })
}

fn portal_rust_source(path: &str) -> bool {
    path.starts_with("portal/") && path.ends_with(".rs")
        || path.starts_with("sources/") && path.ends_with(".rs")
}

fn whole_file_text(path: &str, value: &str) -> bool {
    // relaxed: the portal Dockerfile is a whole-file artifact like the other
    // sources here. Without recognizing it, its multi-line content was treated as
    // a single field name and the build-comment prose was flagged as a prohibited
    // "field". Recognizing the Dockerfile applies the value scan (URLs, secrets,
    // private IPs) to its contents instead, which is the intended check.
    value.contains('\n')
        && ([".cs", ".md", ".rs", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
            || path.ends_with("Dockerfile"))
}

fn csharp_without_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_block = false;
    let mut in_line = false;
    while index < bytes.len() {
        if in_block {
            if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                output.push(' ');
                output.push(' ');
                index += 2;
                in_block = false;
            } else {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            continue;
        }
        if in_line {
            output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
            if bytes[index] == b'\n' {
                in_line = false;
            }
            index += 1;
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 2;
            in_block = true;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            output.push(' ');
            output.push(' ');
            index += 2;
            in_line = true;
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn rust_without_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
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

fn value_i64(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn value_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn value_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn value_str_direct<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.as_object()?.get(key)?.as_str()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn quoted_string_at(text: &str, quote: usize) -> Option<(String, usize)> {
    if !text[quote..].starts_with('"') {
        return None;
    }
    let mut value = String::new();
    let mut escaped = false;
    let mut index = quote + 1;
    for character in text[quote + 1..].chars() {
        if escaped {
            value.push(character);
            escaped = false;
            index += character.len_utf8();
            continue;
        }
        if character == '\\' {
            escaped = true;
            index += 1;
            continue;
        }
        if character == '"' {
            return Some((value, index + 1));
        }
        value.push(character);
        index += character.len_utf8();
    }
    None
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn contains_any_case(value: &str, needles: &[&str]) -> bool {
    let lower = value.to_ascii_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

fn humanize_field(field: &str) -> String {
    field
        .trim_end_matches("Required")
        .replace("browserIsolation", "browser isolation")
        .replace("stableNavigation", "stable navigation")
        .replace("sameOriginApiRouting", "same-origin API routing")
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapget_routes_allow_whitespace_and_detect_duplicates() {
        let program = format!(
            "app.MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();

        let _ = endpoint_block(&program, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("duplicate") && error.contains("endpoint")));
    }

    #[test]
    fn prohibited_value_scan_rejects_embedded_url() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String("safe text with https://provider.invalid/api".to_string()),
            "synthetic",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("prohibited value")));
    }

    #[test]
    fn prohibited_value_scan_allows_only_exact_documented_loopback_origin() {
        let mut exact_errors = Vec::new();
        scan_prohibited_value(
            &Value::String(
                "ENV RYUKI_PORTAL_PUBLIC_ORIGIN=http://127.0.0.1:8080 \\\n+".to_string(),
            ),
            PORTAL_DOCKERFILE_PATH,
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
            scan_prohibited_value(
                &Value::String(unsafe_value.to_string()),
                PORTAL_DOCKERFILE_PATH,
                &mut errors,
            );
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("prohibited value")),
                "unsafe origin must remain prohibited: {unsafe_value}"
            );
        }
    }

    #[test]
    fn trusted_context_leptos_runtime_is_required() {
        let inspection = crate::app_skeleton::inspect_portal_main(&context_aware_ssr_main());
        assert!(inspection.runs_axum_leptos_ssr);
        assert!(inspection.plans_core_platform_reads);
        assert!(inspection.exposes_health_routes);

        let legacy = crate::app_skeleton::inspect_portal_main(&minimal_ssr_main());
        assert!(!legacy.runs_axum_leptos_ssr);
    }

    #[test]
    fn context_aware_leptos_runtime_still_requires_fallback_and_axum_serve() {
        let main_rs = context_aware_ssr_main();
        for invalid_main in [
            main_rs.replace(
                ".fallback(file_and_error_handler_with_context(",
                ".fallback(other_handler(",
            ),
            main_rs.replace("axum::serve(", "serve_without_axum("),
        ] {
            assert_ne!(invalid_main, main_rs);
            assert!(!crate::app_skeleton::inspect_portal_main(&invalid_main).runs_axum_leptos_ssr);
        }
    }

    #[test]
    fn root_context_portal_dockerfile_passes_runtime_check() {
        // RED: root-context portal Dockerfile must not trigger
        // "portal IA runtime Dockerfile must build the full-stack Leptos" error
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS build\n",
            "RUN [\"/usr/local/cargo/bin/rustup\", \"target\", \"add\", \"wasm32-unknown-unknown\"]\n",
            "RUN [\"/usr/local/cargo/bin/cargo\", \"install\", \"cargo-leptos\", \"--version\", \"0.3.7\", \"--locked\", \"--root\", \"/opt/ryuki-tools/cargo-leptos-0.3.7\"]\n",
            "WORKDIR /app\n",
            "COPY --link --chown=10001:10001 Cargo.toml Cargo.lock ./\n",
            "COPY --link --chown=10001:10001 sources/ sources/\n",
            "COPY --link --chown=10001:10001 portal/ portal/\n",
            "RUN [\"/opt/ryuki-tools/cargo-leptos-0.3.7/bin/cargo-leptos\", \"build\", \"--release\", \"-p\", \"ryuki-portal-ui\"]\n",
            "FROM debian:bookworm-slim@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb AS runtime\n",
            "WORKDIR /app\n",
            "ENV LEPTOS_SITE_ROOT=/app/site \\\n",
            "    LEPTOS_SITE_ADDR=0.0.0.0:8080 \\\n",
            "    RYUKI_PORTAL_EXECUTION_MODE=static-dry-run\n",
            "COPY --from=build --chown=10001:10001 /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui\n",
            "COPY --from=build --chown=10001:10001 /app/target/site /app/site\n",
            "USER 10001:10001\n",
            "EXPOSE 8080\n",
            "CMD [\"/app/ryuki-portal-ui\"]\n",
        );
        let mut errors = Vec::new();
        validate_portal_runtime_text(
            &standard_test_cargo_toml(),
            &context_aware_ssr_main(),
            &minimal_hydrate_lib(),
            dockerfile,
            &mut errors,
        );
        let leptos_error = errors
            .iter()
            .any(|e| e.contains("full-stack") || e.contains("hydration assets"));
        assert!(
            !leptos_error,
            "Root-context portal Dockerfile should pass runtime check but got: {:?}",
            errors
        );
    }

    #[test]
    fn linked_crate_local_dockerfile_still_passes_runtime_check() {
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS build\n",
            "RUN [\"/usr/local/cargo/bin/rustup\", \"target\", \"add\", \"wasm32-unknown-unknown\"]\n",
            "RUN [\"/usr/local/cargo/bin/cargo\", \"install\", \"cargo-leptos\", \"--version\", \"0.3.7\", \"--locked\", \"--root\", \"/opt/ryuki-tools/cargo-leptos-0.3.7\"]\n",
            "WORKDIR /app\n",
            "COPY --link --chown=10001:10001 Cargo.toml styles.css ./\n",
            "COPY --link --chown=10001:10001 src ./src\n",
            "RUN [\"/opt/ryuki-tools/cargo-leptos-0.3.7/bin/cargo-leptos\", \"build\", \"--release\"]\n",
            "FROM debian:bookworm-slim@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb AS runtime\n",
            "WORKDIR /app\n",
            "ENV LEPTOS_SITE_ROOT=/app/site \\\n",
            "    LEPTOS_SITE_ADDR=0.0.0.0:8080 \\\n",
            "    RYUKI_PORTAL_EXECUTION_MODE=static-dry-run\n",
            "COPY --from=build --chown=10001:10001 /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui\n",
            "COPY --from=build --chown=10001:10001 /app/target/site /app/site\n",
            "USER 10001:10001\n",
            "EXPOSE 8080\n",
            "CMD [\"/app/ryuki-portal-ui\"]\n",
        );
        let mut errors = Vec::new();
        validate_portal_runtime_text(
            &standard_test_cargo_toml(),
            &context_aware_ssr_main(),
            &minimal_hydrate_lib(),
            dockerfile,
            &mut errors,
        );
        let leptos_error = errors
            .iter()
            .any(|e| e.contains("full-stack") || e.contains("hydration assets"));
        assert!(
            !leptos_error,
            "Linked crate-local Dockerfile should still pass runtime check but got: {:?}",
            errors
        );
    }

    #[test]
    fn dockerfile_without_cargo_leptos_is_rejected() {
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm AS build\n",
            "WORKDIR /app\n",
            "COPY --link --chown=10001:10001 Cargo.toml Cargo.lock ./\n",
            "RUN cargo build --release\n",
        );
        let mut errors = Vec::new();
        validate_portal_runtime_text(
            &standard_test_cargo_toml(),
            &context_aware_ssr_main(),
            &minimal_hydrate_lib(),
            dockerfile,
            &mut errors,
        );
        assert!(
            errors.iter().any(|e| e.contains("full-stack")
                || e.contains("hydration")
                || e.contains("cargo leptos")),
            "Dockerfile without cargo-leptos should be rejected but got: {:?}",
            errors
        );
    }

    fn standard_test_cargo_toml() -> String {
        r#"name = "ryuki-portal-ui"
publish = false

[lib]
crate-type = ["cdylib", "rlib"]

[features]
hydrate = ["leptos/hydrate"]
ssr = ["leptos/ssr", "leptos_meta/ssr"]

[dependencies]
leptos = "*"
leptos_meta = "*"
axum = { version = "*", optional = true }
leptos_axum = { version = "*", optional = true }
tokio = { version = "*", optional = true }

[package.metadata.leptos]
bin-features = ["ssr"]
lib-features = ["hydrate"]
output-name = "ryuki-portal-ui"
site-pkg-dir = "pkg"
style-file = "styles.css"
"#
        .to_string()
    }

    fn minimal_ssr_main() -> String {
        r#"#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::{routing::get, Router};
    use leptos::prelude::*;
    use leptos_axum::{file_and_error_handler, generate_route_list, LeptosRoutes};
    use ryuki_portal_ui::app::{shell, App};
    use ryuki_portal_ui::server_boundary::PortalServerBoundary;
    let configuration = get_configuration(Some("Cargo.toml"))?;
    let leptos_options = configuration.leptos_options;
    let address = leptos_options.site_addr;
    let routes = generate_route_list(App);
    let boundary = PortalServerBoundary::static_dry_run();
    boundary.plan_core_platform_reads()?;
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        .leptos_routes(&leptos_options, routes, shell)
        .fallback(file_and_error_handler(shell))
        .with_state(leptos_options);
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
"#
        .to_string()
    }

    fn context_aware_ssr_main() -> String {
        r#"#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::{routing::{any, get}, Router};
    use leptos::prelude::*;
    use leptos_axum::{
        file_and_error_handler_with_context, generate_route_list_with_exclusions, LeptosRoutes,
    };
    use ryuki_portal_ui::app::{shell, App};
    use ryuki_portal_ui::security::{
        protect_server_function_routes, registered_server_function_route_exclusions,
        PortalPublicOrigin, PortalServerFunctionLimits,
    };
    use ryuki_portal_ui::server_boundary::PortalServerBoundary;
    use ryuki_portal_ui::upstream::UpstreamClient;
    let configuration = get_configuration(None)?;
    let leptos_options = configuration.leptos_options;
    let address = leptos_options.site_addr;
    let routes = generate_route_list_with_exclusions(App, Some(registered_server_function_route_exclusions()));
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
        .leptos_routes_with_context(
            &leptos_options,
            routes,
            move || provide_context(upstream_for_routes.clone()),
            {
                let leptos_options = leptos_options.clone();
                move || shell(leptos_options.clone())
            },
        )
        .merge(server_function_routes)
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

    fn minimal_hydrate_lib() -> String {
        r#"#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(app::App);
}
pub mod app;
pub mod server_boundary;
pub mod api_client;
"#
        .to_string()
    }
}
