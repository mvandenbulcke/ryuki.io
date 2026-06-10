use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/local-container-readiness-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/local-container-readiness.md";
const PORTAL_DOCKERFILE_PATH: &str = "portal/portal-ui/Dockerfile";
const PORTAL_CARGO_PATH: &str = "portal/portal-ui/Cargo.toml";
const PORTAL_MAIN_PATH: &str = "portal/portal-ui/src/main.rs";
const PORTAL_SERVER_BOUNDARY_PATH: &str = "portal/portal-ui/src/server_boundary.rs";
const ENDPOINT: &str = "/api/platform/local-container-readiness-contract";

const REQUIRED_SURFACES: &[&str] = &[
    "compose-file-readiness",
    "service-topology-readiness",
    "build-context-readiness",
    "local-port-readiness",
    "network-boundary-readiness",
    "dependency-readiness",
    "portal-runtime-boundary-readiness",
    "excluded-runtime-readiness",
    "evidence-redaction-readiness",
];
const REQUIRED_INPUTS: &[&str] = &[
    "composeSummary",
    "serviceTopologySummary",
    "buildContextSummary",
    "localPortSummary",
    "networkBoundarySummary",
    "dependencySummary",
    "portalRuntimeSummary",
    "excludedRuntimeSummary",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "compose-file-reviewed",
    "service-topology-reviewed",
    "build-context-reviewed",
    "local-port-reviewed",
    "network-boundary-reviewed",
    "dependency-reviewed",
    "portal-runtime-boundary-reviewed",
    "excluded-runtime-reviewed",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "localRuntimeSummary",
    "composeFileReview",
    "serviceTopology",
    "buildContextReview",
    "localPortReview",
    "networkBoundaryReview",
    "dependencyReview",
    "portalRuntimeBoundaryReview",
    "excludedRuntimeReview",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "docker-compose-up-disabled",
    "docker-compose-build-disabled",
    "docker-run-disabled",
    "image-push-disabled",
    "registry-access-disabled",
    "service-mutation-disabled",
    "network-mutation-disabled",
    "port-binding-mutation-disabled",
    "environment-values-disabled",
    "env-file-disabled",
    "volume-mounts-disabled",
    "provider-service-disabled",
    "external-egress-disabled",
    "raw-runtime-payloads-disabled",
    "provider-returned-content-disabled",
    "sensitive-auth-values-disabled",
    "runtime-identifiers-disabled",
    "compose-file-review-missing",
    "service-topology-missing",
    "build-context-review-missing",
    "local-port-review-missing",
    "network-boundary-review-missing",
    "dependency-review-missing",
    "portal-runtime-boundary-review-missing",
    "excluded-runtime-review-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Local container readiness summary",
    "Compose file review",
    "Service topology review",
    "Build context review",
    "Local port review",
    "Network boundary review",
    "Dependency review",
    "Portal runtime boundary review",
    "Excluded runtime review",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "dockerComposeUpAllowed",
    "dockerComposeBuildAllowed",
    "dockerRunAllowed",
    "imagePushAllowed",
    "registryAccessAllowed",
    "serviceMutationAllowed",
    "networkMutationAllowed",
    "portBindingMutationAllowed",
    "environmentValuesAllowed",
    "envFileAllowed",
    "volumeMountsAllowed",
    "providerServiceAllowed",
    "externalEgressAllowed",
    "rawRuntimePayloadsAllowed",
    "providerReturnedContentAllowed",
    "sensitiveAuthValuesAllowed",
    "runtimeIdentifiersAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "readinessMode",
    "runtimeProvider",
    "deploymentTarget",
    "readinessSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "providerCallsEnabled",
    "dockerComposeUpAllowed",
    "dockerComposeBuildAllowed",
    "dockerRunAllowed",
    "imagePushAllowed",
    "registryAccessAllowed",
    "serviceMutationAllowed",
    "networkMutationAllowed",
    "portBindingMutationAllowed",
    "environmentValuesAllowed",
    "envFileAllowed",
    "volumeMountsAllowed",
    "providerServiceAllowed",
    "externalEgressAllowed",
    "rawRuntimePayloadsAllowed",
    "providerReturnedContentAllowed",
    "sensitiveAuthValuesAllowed",
    "runtimeIdentifiersAllowed",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("readinessSurfaces", "localContainerReadinessSurfaces"),
    ("requiredGuards", "localContainerReadinessRequiredGuards"),
    ("planSections", "localContainerReadinessPlanSections"),
    ("blockedReasons", "localContainerReadinessBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "readinessMode",
    "runtimeProvider",
    "deploymentTarget",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "readinessSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "providerCallsEnabled",
    "dockerComposeUpAllowed",
    "dockerComposeBuildAllowed",
    "dockerRunAllowed",
    "imagePushAllowed",
    "registryAccessAllowed",
    "serviceMutationAllowed",
    "networkMutationAllowed",
    "portBindingMutationAllowed",
    "environmentValuesAllowed",
    "envFileAllowed",
    "volumeMountsAllowed",
    "providerServiceAllowed",
    "externalEgressAllowed",
    "rawRuntimePayloadsAllowed",
    "providerReturnedContentAllowed",
    "sensitiveAuthValuesAllowed",
    "runtimeIdentifiersAllowed",
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Local container readiness seed data only. Do not add runtime endpoints, private network details, environment value material, registry material, organization-scope identifiers, provider-side identifiers, sensitive auth material, raw runtime payloads, or provider-returned content.",
    "# Local Container Readiness",
    "Endpoint: `/api/platform/local-container-readiness-contract`",
    "- Use static local container readiness summaries only.",
    "| `/api/platform/local-container-readiness-contract` | Static local Compose readiness contract; compose up, image build, registry access, and raw runtime payloads disabled. |",
    "| [Local Container Readiness Contract](local-container-readiness-contract.yaml) | Draft Compose file, service topology, build context, local port, network boundary, dependency, portal runtime boundary, excluded runtime, and redaction readiness contract. |",
    "| [Local Container Readiness](local-container-readiness.md) | Static Compose file, service topology, build context, local port, network boundary, dependency, portal runtime boundary, excluded runtime, and redaction readiness contract. |",
    "This slice adds a static readiness contract for the local Compose skeleton used to run Ryuki portal and API shells. It turns compose file shape, service topology, build context, local ports, bridge-network boundary, dependency order, full-stack portal runtime boundary, excluded runtime scope, and evidence posture into reviewable gates without running containers.",
    "- No compose up, image build, container run, image push, registry access, service mutation, network mutation, port-binding change, environment value material, local volume mount, provider-backed service, external egress, or runtime-state change.",
    "- No runtime endpoints, private network details, environment value material, registry material, organization-scope identifiers, provider-side identifiers, sensitive auth material, raw runtime payloads, or provider-returned content.",
    "The contract requires compose file review, service topology review, build context review, local port review, network boundary review, dependency review, portal runtime boundary review, excluded runtime review, and redacted evidence before local container readiness can be accepted.",
    "Future database, Vault, worker, adapter, registry, external egress, and local persistence additions must be approved separately and must keep concrete runtime details outside committed files.",
    "requirement: Local container readiness evidence must use safe summaries only and must not expose runtime endpoints, private network details, environment value material, registry material, organization-scope identifiers, provider-side identifiers, sensitive auth material, raw runtime payloads, or provider-returned content.",
];
const STATIC_SAFE_VALUES: &[&str] = &[
    ENDPOINT,
    "draft",
    "static-seed",
    "static-readiness",
    "Docker Compose",
    "local-compose-skeleton",
    "localContainerReadinessSurfaces",
    "localContainerReadinessRequiredGuards",
    "localContainerReadinessPlanSections",
    "localContainerReadinessBlockedReasons",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &["credential", "password", "bearer", "token", "value"];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-local-container-actions",
        decision: "block",
        requirement:
            "Local container readiness reports static readiness only and never calls providers, runs compose up, builds images, runs containers, pushes images, accesses registries, mutates services, mutates networks, changes local port bindings, enables environment value material, mounts volumes, creates provider-backed services, enables external egress, or changes runtime state.",
        evidence: "Local container readiness summary",
    },
    RuleDetail {
        id: "two-service-local-topology-required",
        decision: "block",
        requirement:
            "Local compose posture must keep the browser-facing portal and server-side API as the only active services until worker, adapter, database, and Vault bootstrap slices are approved.",
        evidence: "Service topology review",
    },
    RuleDetail {
        id: "local-routing-and-network-required",
        decision: "block",
        requirement:
            "Local port bindings, full-stack portal runtime boundary, service dependency order, and bridge-network boundary must be reviewed before local runtime readiness can be accepted.",
        evidence: "Network boundary review",
    },
    RuleDetail {
        id: "runtime-expansion-excluded",
        decision: "block",
        requirement:
            "Database, Vault, provider adapters, worker execution, provider-backed resources, environment value material, local volume mounts, registry access, and external egress must stay excluded from the local skeleton until separately approved.",
        evidence: "Excluded runtime review",
    },
    RuleDetail {
        id: "raw-local-runtime-data-not-exposed",
        decision: "block",
        requirement:
            "Local container readiness evidence must use safe summaries only and must not expose runtime endpoints, private network details, environment value material, registry material, organization-scope identifiers, provider-side identifiers, sensitive auth material, raw runtime payloads, or provider-returned content.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct LocalContainerReadinessContext {
    catalog_text: String,
    catalog: Value,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    portal_dockerfile: String,
    portal_cargo: String,
    portal_main: String,
    portal_server_boundary: String,
    compose: Value,
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
struct Route {
    start: usize,
    route: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: LocalContainerReadinessContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid local container readiness context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text.clone()),
        CATALOG_PATH,
        &mut errors,
    );
    validate_compose_boundary(&context.compose, &mut errors);
    validate_portal_runtime_boundary(
        &context.portal_dockerfile,
        &context.portal_cargo,
        &context.portal_main,
        &context.portal_server_boundary,
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
        &mut errors,
    );
    scan_prohibited_value(
        &serde_json::json!({
            API_README_PATH: context.api_readme,
            CATALOG_README_PATH: context.catalog_readme,
            DOC_README_PATH: context.doc_readme,
            DOC_PATH: context.doc,
        }),
        "local-container-readiness",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid local container readiness catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid local container readiness program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid local container readiness docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.api_readme,
        &payload.catalog_readme,
        &payload.doc_readme,
        &payload.doc,
        &mut errors,
    );
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid local container readiness prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("local container readiness catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "local container readiness version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "local container readiness status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "local container readiness source must be static-seed",
    );
    expect(
        string_value(catalog, "readinessMode") == Some("static-readiness"),
        errors,
        "local container readiness mode must be static-readiness",
    );
    expect(
        string_value(catalog, "runtimeProvider") == Some("Docker Compose"),
        errors,
        "local container runtime provider must be Docker Compose",
    );
    expect(
        string_value(catalog, "deploymentTarget") == Some("local-compose-skeleton"),
        errors,
        "local container deployment target must be local-compose-skeleton",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("local container readiness {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "readinessSurfaces", REQUIRED_SURFACES, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let required: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !required.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "local container readiness unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_like(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let required_set: BTreeSet<&str> = required.iter().copied().collect();
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|item| !value_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|item| !required_set.contains(item))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("{field} missing values: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!("{field} unexpected values: {}", unexpected.join(", ")),
    );
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited local container readiness value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = rules_from_catalog(catalog);
    let rule_ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let required_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_ids.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .copied()
        .filter(|id| !required_ids.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "local container readiness missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "local container readiness unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "local container readiness rule IDs must be unique",
    );

    if let Some(values) = catalog.get("rules").and_then(Value::as_array) {
        for rule in values {
            let keys: Vec<&str> = rule
                .as_object()
                .map(|map| map.keys().map(String::as_str).collect())
                .unwrap_or_default();
            let unexpected_keys: Vec<&str> = keys
                .iter()
                .copied()
                .filter(|key| !RULE_KEYS.contains(key))
                .collect();
            let missing_keys: Vec<&str> = RULE_KEYS
                .iter()
                .copied()
                .filter(|key| !keys.contains(key))
                .collect();
            let id = rule
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("(missing id)");
            if !unexpected_keys.is_empty() {
                errors.push(format!(
                    "local container readiness rule {id} unexpected rule keys: {}",
                    unexpected_keys.join(", ")
                ));
            }
            if !missing_keys.is_empty() {
                errors.push(format!(
                    "local container readiness rule {id} missing rule keys: {}",
                    missing_keys.join(", ")
                ));
            }
        }
    }

    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "local container readiness rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "local container readiness rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "local container readiness rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_compose_boundary(compose: &Value, errors: &mut Vec<String>) {
    let payload = serde_json::json!({ "compose": compose }).to_string();
    match crate::compose::validate_values_json(&payload) {
        Ok(mut compose_errors) => errors.append(&mut compose_errors),
        Err(error) => errors.push(format!("compose validation failed: {error}")),
    }
    let prohibited_payload = serde_json::json!({
        "value": compose,
        "path": "compose",
    })
    .to_string();
    match crate::compose::scan_prohibited_json(&prohibited_payload) {
        Ok(mut compose_errors) => errors.append(&mut compose_errors),
        Err(error) => errors.push(format!("compose prohibited scan failed: {error}")),
    }
    if let Some(services) = compose.get("services").and_then(Value::as_object) {
        for (service_name, service) in services {
            if let Some(map) = service.as_object() {
                if map.contains_key("provider") {
                    errors.push(format!(
                        "{service_name} must not define provider-backed service"
                    ));
                }
                if map.contains_key("external_links") {
                    errors.push(format!("{service_name} must not define external links"));
                }
                if map.contains_key("extra_hosts") {
                    errors.push(format!("{service_name} must not define extra hosts"));
                }
                if map.contains_key("environment")
                    && service_name != "platform-db"
                    && service_name != "platform-api"
                {
                    errors.push(format!(
                        "{service_name} must not expose environment value material"
                    ));
                }
                if map.contains_key("env_file") && service_name != "platform-api" {
                    errors.push(format!("{service_name} must not define env_file"));
                }
                if map.contains_key("volumes") && service_name != "platform-db" {
                    errors.push(format!("{service_name} must not mount volumes"));
                }
            }
        }
    }
}

fn validate_portal_runtime_boundary(
    dockerfile: &str,
    cargo_toml: &str,
    main_rs: &str,
    server_boundary_rs: &str,
    errors: &mut Vec<String>,
) {
    expect(
        dockerfile.contains("cargo leptos build --release"),
        errors,
        "portal Dockerfile must build the full-stack Leptos app",
    );
    expect(
        dockerfile.contains("FROM debian:bookworm-slim AS runtime"),
        errors,
        "portal Dockerfile must use a Rust portal server runtime stage",
    );
    expect(
        dockerfile.contains("LEPTOS_SITE_ROOT=/app/site"),
        errors,
        "portal Dockerfile must set Leptos site root",
    );
    expect(
        dockerfile.contains("LEPTOS_SITE_ADDR=0.0.0.0:8080"),
        errors,
        "portal Dockerfile must bind the Leptos server to container port 8080",
    );
    expect(
        dockerfile.contains("RYUKI_PORTAL_EXECUTION_MODE=static-dry-run"),
        errors,
        "portal Dockerfile must keep static-dry-run execution mode",
    );
    expect(
        dockerfile.contains("CMD [\"/app/ryuki-portal-ui\"]"),
        errors,
        "portal Dockerfile must run the Rust portal server",
    );
    expect(
        !dockerfile.contains("FROM nginx:alpine") && !dockerfile.contains("trunk build --release"),
        errors,
        "portal Dockerfile must not use the legacy static NGINX/Trunk runtime",
    );
    expect(
        cargo_toml.contains("leptos_axum")
            && cargo_toml.contains("\"leptos/ssr\"")
            && cargo_toml.contains("\"leptos/hydrate\""),
        errors,
        "portal Cargo.toml must keep full-stack Leptos SSR and hydrate features",
    );
    expect(
        main_rs.contains("PortalServerBoundary::static_dry_run()")
            && main_rs.contains(".leptos_routes("),
        errors,
        "portal main must route through the static-dry-run server boundary",
    );
    let active_boundary = rust_without_comments(server_boundary_rs);
    expect(
        active_boundary.contains("same_origin_api_path(path)?"),
        errors,
        "portal server boundary must enforce same-origin API paths",
    );
    expect(
        active_boundary.contains("ALLOWED_PORTAL_API_PATHS"),
        errors,
        "portal server boundary must keep an explicit API allowlist",
    );
    expect(
        active_boundary.contains("static-dry-run")
            && active_boundary.contains("same-origin-platform-api"),
        errors,
        "portal server boundary must describe static dry-run same-origin mode",
    );
    expect(
        active_boundary.contains("evidence_export_allowed: false"),
        errors,
        "portal server boundary must block evidence export by default",
    );
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let block = endpoint_block(program, errors);
    if block.is_empty() {
        return;
    }

    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "readinessMode", "static-readiness"),
        errors,
        "API must keep static-readiness mode",
    );
    expect(
        exact_string_assignment(&block, "runtimeProvider", "Docker Compose"),
        errors,
        "API must keep Docker Compose runtime provider",
    );
    expect(
        exact_string_assignment(&block, "deploymentTarget", "local-compose-skeleton"),
        errors,
        "API must keep local-compose-skeleton target",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array_like(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            string_array_like(catalog, field),
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_endpoint_string_literals(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_singleton_endpoint_assignments(&block, errors);
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
    let catalog_set: BTreeSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = catalog_values
        .iter()
        .map(String::as_str)
        .filter(|item| !value_set.contains(item))
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|item| !catalog_set.contains(item.as_str()))
        .map(|item| {
            if unsafe_literal(item) {
                "[redacted prohibited value]".to_string()
            } else {
                item.clone()
            }
        })
        .collect();
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
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited local container readiness value [redacted prohibited value]"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules_body) = endpoint_rules_body(block, errors) else {
        return;
    };
    let catalog_rules = rules_from_catalog(catalog);
    let api_rules = rules_from_csharp_array(&rules_body, errors);
    let catalog_rule_ids: Vec<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_rule_ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let catalog_id_set: BTreeSet<&str> = catalog_rule_ids.iter().copied().collect();
    let api_id_set: BTreeSet<&str> = api_rule_ids.iter().copied().collect();
    for id in catalog_rule_ids
        .iter()
        .copied()
        .filter(|id| !api_id_set.contains(id))
    {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_rule_ids
        .iter()
        .copied()
        .filter(|id| !catalog_id_set.contains(id))
    {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
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
            format!("API rule {} decision must match catalog", catalog_rule.id),
        );
        expect(
            api_rule.requirement == catalog_rule.requirement,
            errors,
            format!(
                "API rule {} requirement must match catalog",
                catalog_rule.id
            ),
        );
        expect(
            api_rule.evidence == catalog_rule.evidence,
            errors,
            format!("API rule {} evidence must match catalog", catalog_rule.id),
        );
    }
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let matches = assignment_occurrences(block, "rules")
        .into_iter()
        .filter_map(|start| {
            let rest = block.get(start..)?;
            let after_equals = rest.find('=')?;
            let value = rest.get((after_equals + 1)..)?.trim_start();
            if value.starts_with("new[]") {
                Some(start)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if matches.is_empty() {
        errors.push("API missing rules array".to_string());
        return None;
    }
    if matches.len() != 1 {
        errors.push("API rules array must be declared once".to_string());
        return None;
    }
    let open_brace = block
        .get(matches[0]..)?
        .find('{')
        .map(|offset| matches[0] + offset)?;
    let close_brace = matching_brace_index(block, open_brace)?;
    block.get((open_brace + 1)..close_brace).map(str::to_string)
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected local container readiness field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited local container readiness field {field}"
            ));
        }
    }
}

fn validate_endpoint_string_literals(block: &str, errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for literal in csharp_string_literals(block) {
        if !seen.insert(literal.clone()) {
            continue;
        }
        if !safe_text_value(&literal) && unsafe_literal(&literal) {
            errors.push("API endpoint contains unsafe string literal".to_string());
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in simple_assignments(block) {
        if value == "true" && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_singleton_endpoint_assignments(block: &str, errors: &mut Vec<String>) {
    let fields = singleton_endpoint_assignments();
    for field in fields {
        if endpoint_assignment_count(block, &field) != 1 {
            errors.push(format!("API {field} assignment must appear exactly once"));
        }
    }
}

fn validate_docs_text(
    api_readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    errors: &mut Vec<String>,
) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing local container readiness endpoint",
    );
    expect(
        catalog_readme.contains("local-container-readiness-contract.yaml"),
        errors,
        "catalog README missing local container readiness catalog",
    );
    expect(
        doc_readme.contains("local-container-readiness.md"),
        errors,
        "workflow README missing local container readiness doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "local container readiness doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "local container readiness doc must prohibit provider calls",
    );
    expect(
        doc.contains("No compose up"),
        errors,
        "local container readiness doc must prohibit compose up",
    );
    expect(
        doc.contains("Use static local container readiness summaries only."),
        errors,
        "local container readiness doc must require static summaries",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let uncommented_program = csharp_without_comments(program);
    let routes = mapget_routes(&uncommented_program);
    let endpoint_routes = routes
        .iter()
        .filter(|route| route.route == ENDPOINT)
        .collect::<Vec<_>>();
    if endpoint_routes.is_empty() {
        errors.push("API missing local container readiness endpoint".to_string());
        return String::new();
    }
    if endpoint_routes.len() != 1 {
        errors.push(format!(
            "API duplicate local container readiness endpoint {ENDPOINT}"
        ));
    }
    let start = endpoint_routes[0].start;
    let end = routes
        .iter()
        .filter(|route| route.start > start)
        .map(|route| route.start)
        .next()
        .unwrap_or(uncommented_program.len());
    uncommented_program
        .get(start..end)
        .map(str::to_string)
        .unwrap_or_default()
}

fn mapget_routes(program: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    let mut index = 0;
    while let Some(offset) = program
        .get(index..)
        .and_then(|text| text.find("app.MapGet"))
    {
        let start = index + offset;
        let mut cursor = start + "app.MapGet".len();
        cursor = skip_ws(program, cursor);
        if program.as_bytes().get(cursor) != Some(&b'(') {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor = skip_ws(program, cursor + 1);
        let Some((route, next_cursor)) = parse_csharp_string_literal_at(program, cursor) else {
            index = cursor.saturating_add(1);
            continue;
        };
        routes.push(Route { start, route });
        index = next_cursor;
    }
    routes
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut verbatim_string = false;
    let mut escaped = false;

    while index < bytes.len() {
        let ch = bytes[index] as char;
        let next = bytes.get(index + 1).copied().map(char::from);
        if in_line_comment {
            if ch == '\n' {
                result.push(ch);
                in_line_comment = false;
            } else {
                result.push(' ');
            }
        } else if in_block_comment {
            if ch == '*' && next == Some('/') {
                result.push_str("  ");
                index += 1;
                in_block_comment = false;
            } else if ch == '\n' {
                result.push(ch);
            } else {
                result.push(' ');
            }
        } else if in_string {
            result.push(ch);
            if verbatim_string {
                if ch == '"' && next == Some('"') {
                    result.push('"');
                    index += 1;
                } else if ch == '"' {
                    in_string = false;
                    verbatim_string = false;
                }
            } else if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '@' && next == Some('"') {
            result.push('@');
            result.push('"');
            index += 1;
            in_string = true;
            verbatim_string = true;
        } else if ch == '"' {
            result.push(ch);
            in_string = true;
            escaped = false;
        } else if ch == '/' && next == Some('/') {
            result.push_str("  ");
            index += 1;
            in_line_comment = true;
        } else if ch == '/' && next == Some('*') {
            result.push_str("  ");
            index += 1;
            in_block_comment = true;
        } else {
            result.push(ch);
        }
        index += 1;
    }
    result
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable}");
    let start = program.find(&marker)?;
    let rest = program.get(start..)?;
    let equals = rest.find('=')?;
    let value = rest.get((equals + 1)..)?.trim_start();
    if !value.starts_with("new[]") {
        return None;
    }
    let open = program
        .get(start..)?
        .find('{')
        .map(|offset| start + offset)?;
    let close = matching_brace_index(program, open)?;
    program.get((open + 1)..close).map(csharp_string_literals)
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    for start in assignment_occurrences(block, field) {
        let rest = block.get(start..)?;
        let equals = rest.find('=')?;
        let value = rest.get((equals + 1)..)?.trim_start();
        if !value.starts_with("new[]") {
            continue;
        }
        let open = block.get(start..)?.find('{').map(|offset| start + offset)?;
        let close = matching_brace_index(block, open)?;
        return block.get((open + 1)..close).map(csharp_string_literals);
    }
    None
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut index = 0;
    while index < text.len() {
        if text.as_bytes().get(index) != Some(&b'"') {
            index += 1;
            continue;
        }
        if let Some((literal, cursor)) = parse_csharp_string_literal_at(text, index) {
            literals.push(literal);
            index = cursor;
        } else {
            index += 1;
        }
    }
    literals
}

fn parse_csharp_string_literal_at(text: &str, start: usize) -> Option<(String, usize)> {
    if text.as_bytes().get(start) != Some(&b'"') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut literal = String::new();
    let mut cursor = start + 1;
    let mut escaped = false;
    while cursor < bytes.len() {
        let ch = bytes[cursor] as char;
        if escaped {
            literal.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some((literal, cursor + 1));
        } else {
            literal.push(ch);
        }
        cursor += 1;
    }
    None
}

fn matching_brace_index(source: &str, start_index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(start_index) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut index = start_index;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            in_string = true;
        } else if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    block.lines().any(|line| line.trim() == expected)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    block.lines().any(|line| line.trim() == expected)
}

fn simple_assignments(block: &str) -> Vec<(String, String)> {
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (field, rest) = trimmed.split_once('=')?;
            let field = field.trim();
            if !is_identifier(field) {
                return None;
            }
            let value = rest.trim().trim_end_matches(',').trim();
            Some((field.to_string(), value.to_string()))
        })
        .collect()
}

fn endpoint_assignment_count(block: &str, field: &str) -> usize {
    assignment_occurrences(block, field).len()
}

fn assignment_occurrences(block: &str, field: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let bytes = block.as_bytes();
    let field_bytes = field.as_bytes();
    let mut index = 0;
    while index + field_bytes.len() <= bytes.len() {
        if &bytes[index..index + field_bytes.len()] == field_bytes
            && (index == 0 || !is_ident_byte(bytes[index - 1]))
            && bytes
                .get(index + field_bytes.len())
                .map(|byte| !is_ident_byte(*byte))
                .unwrap_or(true)
        {
            let cursor = skip_ws(block, index + field_bytes.len());
            if bytes.get(cursor) == Some(&b'=') {
                starts.push(index);
            }
        }
        index += 1;
    }
    starts
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let bytes = block.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !is_ident_start_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_ident_byte(bytes[index]) {
            index += 1;
        }
        let end = index;
        let cursor = skip_ws(block, end);
        if bytes.get(cursor) == Some(&b'=') {
            if let Some(field) = block.get(start..end) {
                fields.push(field.to_string());
            }
        }
    }
    fields
}

fn rules_from_csharp_array(body: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut index = 0;
    while let Some(offset) = body.get(index..).and_then(|text| text.find("new")) {
        let start = index + offset;
        let cursor = skip_ws(body, start + "new".len());
        if body.as_bytes().get(cursor) != Some(&b'{') {
            index = cursor.saturating_add(1);
            continue;
        }
        let Some(close) = matching_brace_index(body, cursor) else {
            break;
        };
        if let Some(object_text) = body.get(cursor..=close) {
            let assignments = string_assignments(object_text);
            for field in assignments.keys() {
                if !RULE_KEYS.contains(&field.as_str()) {
                    errors.push(format!(
                        "API rule object has unexpected local container readiness field {field}"
                    ));
                }
            }
            if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
                assignments.get("id"),
                assignments.get("decision"),
                assignments.get("requirement"),
                assignments.get("evidence"),
            ) {
                rules.push(Rule {
                    id: id.clone(),
                    decision: decision.clone(),
                    requirement: requirement.clone(),
                    evidence: evidence.clone(),
                });
            }
        }
        index = close + 1;
    }
    rules
}

fn string_assignments(object_text: &str) -> BTreeMap<String, String> {
    let mut assignments = BTreeMap::new();
    let bytes = object_text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !is_ident_start_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_ident_byte(bytes[index]) {
            index += 1;
        }
        let Some(field) = object_text.get(start..index) else {
            continue;
        };
        let equals = skip_ws(object_text, index);
        if bytes.get(equals) != Some(&b'=') {
            continue;
        }
        let value_start = skip_ws(object_text, equals + 1);
        if let Some((value, next)) = parse_csharp_string_literal_at(object_text, value_start) {
            assignments.insert(field.to_string(), value);
            index = next;
        }
    }
    assignments
}

fn rules_from_catalog(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .map(|rule| Rule {
                    id: string_value_direct(rule, "id")
                        .unwrap_or_default()
                        .to_string(),
                    decision: string_value_direct(rule, "decision")
                        .unwrap_or_default()
                        .to_string(),
                    requirement: string_value_direct(rule, "requirement")
                        .unwrap_or_default()
                        .to_string(),
                    evidence: string_value_direct(rule, "evidence")
                        .unwrap_or_default()
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited local container readiness field"
                    ));
                }
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if local_container_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited local container readiness field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !local_container_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        for term in word_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited local container readiness field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn safe_text_value(value: &str) -> bool {
    STATIC_SAFE_VALUES.contains(&value)
        || REQUIRED_SURFACES.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || REQUIRED_CATALOG_KEYS.contains(&value)
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    if SAFE_TEXT_PROHIBITION_LINES.contains(&stripped) {
        return true;
    }
    let bullet = stripped.strip_prefix("- ").unwrap_or(stripped);
    if safe_text_value(bullet) {
        return true;
    }
    if let Some((key, value)) = yaml_key_value(stripped) {
        return !prohibited_field(key) && safe_text_value(value);
    }
    false
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_normalized_value(&normalized) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || contains_any(
            &normalized,
            &[
                "envfile",
                "environmentvalue",
                "volumemount",
                "providerendpoint",
                "registrycredential",
                "tenantidentifier",
                "objectidentifier",
                "privateip",
                "credential",
                "secretvalue",
                "token",
                "password",
                "bearer",
                "rawruntime",
                "runtimepayload",
                "providerpayload",
                "runtimeendpoint",
            ],
        )
        || sensitive_compound_field(value)
}

fn safe_normalized_value(normalized: &str) -> bool {
    safe_values_for_normalization()
        .into_iter()
        .map(|value| normalize(&value))
        .any(|safe| safe == normalized)
}

fn safe_values_for_normalization() -> Vec<String> {
    let mut values = Vec::new();
    for group in [
        STATIC_SAFE_VALUES,
        REQUIRED_SURFACES,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
    ] {
        values.extend(group.iter().map(|value| value.to_string()));
    }
    for rule in REQUIRED_RULES {
        values.push(rule.id.to_string());
        values.push(rule.decision.to_string());
        values.push(rule.requirement.to_string());
        values.push(rule.evidence.to_string());
    }
    values
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    has_any(
        &tokens,
        &["password", "credential", "token", "bearer", "value"],
    ) || has_any(&tokens, &["url", "uri", "endpoint", "fqdn"])
        || (has_any(&tokens, &["id", "guid"]) && tokens.len() > 1)
        || (has_any(&tokens, &["private", "ip", "host", "dns"])
            && has_any(&tokens, &["address", "name"]))
        || (has_any(
            &tokens,
            &[
                "compose",
                "docker",
                "runtime",
                "environment",
                "env",
                "volume",
                "registry",
                "provider",
                "tenant",
                "object",
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
                "path",
                "payload",
                "row",
                "rows",
                "token",
                "text",
                "material",
            ],
        ))
        || (tokens.contains(&"raw".to_string())
            && has_any(&tokens, &["runtime", "provider", "payload", "logs", "rows"]))
}

fn unsafe_literal(value: &str) -> bool {
    prohibited_value(value) || prohibited_field(value)
}

fn unsafe_true_field(field: &str) -> bool {
    let normalized = normalize(field);
    contains_any(
        &normalized,
        &[
            "live",
            "provider",
            "docker",
            "compose",
            "run",
            "image",
            "registry",
            "service",
            "network",
            "port",
            "environment",
            "env",
            "volume",
            "egress",
            "raw",
            "runtime",
            "identifier",
            "auth",
        ],
    )
}

fn prohibited_value(value: &str) -> bool {
    contains_url(value)
        || contains_private_ipv4(value)
        || contains_uuid(value)
        || contains_jwt_like(value)
        || contains_vault_token_like(value)
        || value.to_ascii_uppercase().contains("AKIA")
            && value
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .count()
                >= 20
        || value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----")
        || contains_secret_assignment(value)
}

fn contains_url(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|token| token.to_ascii_lowercase().contains("://"))
}

fn contains_private_ipv4(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|token| {
            let octets: Vec<&str> = token.split('.').collect();
            if octets.len() != 4 {
                return false;
            }
            let parsed: Option<Vec<u8>> = octets
                .iter()
                .map(|octet| octet.parse::<u8>().ok())
                .collect();
            let Some(parsed) = parsed else {
                return false;
            };
            parsed[0] == 10
                || (parsed[0] == 192 && parsed[1] == 168)
                || (parsed[0] == 172 && (16..=31).contains(&parsed[1]))
        })
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_hexdigit() && ch != '-')
        .any(|token| {
            token.len() == 36
                && token.as_bytes().get(8) == Some(&b'-')
                && token.as_bytes().get(13) == Some(&b'-')
                && token.as_bytes().get(18) == Some(&b'-')
                && token.as_bytes().get(23) == Some(&b'-')
                && token.chars().all(|ch| ch == '-' || ch.is_ascii_hexdigit())
        })
}

fn contains_jwt_like(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let parts: Vec<&str> = token.split('.').collect();
        parts.len() == 3
            && parts.iter().all(|part| {
                part.len() >= 12
                    && part
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            })
    })
}

fn contains_vault_token_like(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let lowered = token.to_ascii_lowercase();
        (lowered.starts_with("hvs.") || lowered.starts_with("hvb.") || lowered.starts_with("s."))
            && token.len() >= 18
    })
}

fn contains_secret_assignment(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ]
    .iter()
    .any(|key| lowered.contains(&format!("{key}:")) || lowered.contains(&format!("{key}=")))
}

fn rust_without_comments(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                result.push(ch);
                in_line_comment = false;
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            } else if ch == '\n' {
                result.push(ch);
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line_comment = true;
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
            continue;
        }
        result.push(ch);
    }
    result
}

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn string_value_direct<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn singleton_endpoint_assignments() -> Vec<String> {
    let mut fields = vec![
        "source".to_string(),
        "readinessMode".to_string(),
        "runtimeProvider".to_string(),
        "deploymentTarget".to_string(),
        "rules".to_string(),
    ];
    fields.extend(
        REQUIRED_DISABLED_FIELDS
            .iter()
            .map(|field| field.to_string()),
    );
    fields.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(field, _)| field.to_string()),
    );
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().map(|field| field.to_string()));
    fields
}

fn local_container_text_path(path: &str) -> bool {
    [
        CATALOG_PATH,
        DOC_PATH,
        API_README_PATH,
        CATALOG_README_PATH,
        DOC_README_PATH,
    ]
    .iter()
    .any(|text_path| path.ends_with(text_path))
}

fn local_container_text_line(path: &str, line: &str) -> bool {
    path.ends_with(CATALOG_PATH)
        || path.ends_with(DOC_PATH)
        || line.contains("local-container-readiness")
        || line.contains("Local container readiness")
        || line.contains("Local Container Readiness")
        || line.contains(ENDPOINT)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn yaml_key_value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    let key = key.trim();
    let value = value.trim();
    if key.is_empty()
        || value.is_empty()
        || key
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
    {
        return None;
    }
    Some((key, value))
}

fn word_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut current = String::new();
    for ch in line.chars() {
        if ch.is_ascii_alphabetic()
            || (!current.is_empty() && (ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        {
            current.push(ch);
        } else if !current.is_empty() {
            terms.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        terms.push(current);
    }
    terms
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut separated = String::with_capacity(value.len() * 2);
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            separated.push(' ');
        }
        if ch.is_ascii_alphanumeric() {
            separated.push(ch.to_ascii_lowercase());
            previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            separated.push(' ');
            previous_lower_or_digit = false;
        }
    }
    separated.split_whitespace().map(str::to_string).collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_ident_start_byte(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_ws(text: &str, mut index: usize) -> usize {
    while text
        .as_bytes()
        .get(index)
        .map(|byte| byte.is_ascii_whitespace())
        .unwrap_or(false)
    {
        index += 1;
    }
    index
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
    fn mapget_routes_accept_whitespace_before_open_paren() {
        let program = format!(
            "app.MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let routes = mapget_routes(&program);

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].route, ENDPOINT);
    }

    #[test]
    fn duplicate_endpoint_with_whitespace_is_rejected() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));\napp.MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();

        endpoint_block(&program, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("duplicate") && error.contains(ENDPOINT)));
    }
}
