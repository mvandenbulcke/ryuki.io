use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/ui-mockup-acceptance-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/ui-mockup-acceptance.md";
const UI_README_PATH: &str = "docs/ui/README.md";
const SHELL_MOCKUP_PATH: &str = "docs/ui/mockups-shell-dashboard.md";
const CATALOG_MOCKUP_PATH: &str = "docs/ui/mockups-catalog-requests.md";
const INVENTORY_MOCKUP_PATH: &str = "docs/ui/mockups-inventory-cmdb.md";
const EVIDENCE_MOCKUP_PATH: &str = "docs/ui/mockups-evidence-operations-admin.md";
const ACCESSIBILITY_PATH: &str = "docs/ui/accessibility-checklist.md";
const UI_IA_PATH: &str = "docs/ui/portal-information-architecture.md";
const UI_DESIGN_PATH: &str = "docs/ui/design-system.md";
const ENDPOINT: &str = "/api/platform/ui-mockup-acceptance-contract";

const REQUIRED_MOCKUP_DOCUMENTS: &[&str] = &[
    "shell-dashboard",
    "catalog-requests",
    "inventory-cmdb",
    "evidence-operations-admin",
];
const REQUIRED_SURFACES: &[&str] = &[
    "product-shell",
    "dashboard",
    "catalog",
    "request-detail",
    "inventory",
    "cmdb",
    "evidence",
    "operations",
    "admin",
    "accessibility-acceptance",
];
const REQUIRED_INPUTS: &[&str] = &[
    "shellDashboardReview",
    "catalogRequestReview",
    "inventoryCmdbReview",
    "evidenceOperationsAdminReview",
    "accessibilitySummary",
    "browserIsolationSummary",
    "evidenceSafetySummary",
    "statusBehaviorSummary",
    "themeSummary",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "shell-dashboard-reviewed",
    "catalog-requests-reviewed",
    "inventory-cmdb-reviewed",
    "evidence-operations-admin-reviewed",
    "browser-isolation-reviewed",
    "accessibility-reviewed",
    "status-behavior-reviewed",
    "evidence-redaction-reviewed",
    "raw-detail-exclusion-reviewed",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "shellDashboardMockup",
    "catalogRequestMockup",
    "inventoryCmdbMockup",
    "evidenceOperationsAdminMockup",
    "accessibilityAcceptance",
    "browserIsolationReview",
    "statusBehaviorReview",
    "themeBehaviorReview",
    "evidenceSafety",
    "rawDetailExclusion",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "live-ui-execution-disabled",
    "browser-provider-calls-disabled",
    "external-asset-fetch-disabled",
    "direct-vendor-api-disabled",
    "unsafe-debug-detail-disabled",
    "raw-mockup-rows-disabled",
    "raw-evidence-payloads-disabled",
    "raw-provider-payloads-disabled",
    "credential-values-disabled",
    "secret-values-disabled",
    "access-token-values-disabled",
    "raw-recipient-data-disabled",
    "shell-dashboard-review-missing",
    "catalog-requests-review-missing",
    "inventory-cmdb-review-missing",
    "evidence-operations-admin-review-missing",
    "browser-isolation-review-missing",
    "accessibility-review-missing",
    "status-behavior-review-missing",
    "evidence-redaction-review-missing",
    "raw-detail-exclusion-review-missing",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Shell and dashboard mockup review",
    "Catalog and request mockup review",
    "Inventory and CMDB mockup review",
    "Evidence operations and admin mockup review",
    "Accessibility acceptance review",
    "Browser isolation review",
    "Status behavior review",
    "Theme behavior review",
    "Evidence safety review",
    "Raw detail exclusion review",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveUiExecutionAllowed",
    "browserProviderCallsAllowed",
    "externalAssetFetchAllowed",
    "directVendorApiAllowed",
    "unsafeDebugDetailAllowed",
    "rawMockupRowsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "accessTokenValuesAllowed",
    "rawRecipientDataAllowed",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "mockupCoverageRequired",
    "accessibilityReviewRequired",
    "browserIsolationRequired",
    "evidenceSafetyRequired",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "acceptanceMode",
    "mockupCoverageRequired",
    "accessibilityReviewRequired",
    "browserIsolationRequired",
    "evidenceSafetyRequired",
    "mockupDocuments",
    "mockupSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "liveUiExecutionAllowed",
    "browserProviderCallsAllowed",
    "externalAssetFetchAllowed",
    "directVendorApiAllowed",
    "unsafeDebugDetailAllowed",
    "rawMockupRowsAllowed",
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
        "mockupDocuments",
        "uiMockupAcceptanceDocuments",
        REQUIRED_MOCKUP_DOCUMENTS,
    ),
    (
        "mockupSurfaces",
        "uiMockupAcceptanceSurfaces",
        REQUIRED_SURFACES,
    ),
    (
        "requiredGuards",
        "uiMockupAcceptanceRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "uiMockupAcceptancePlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "uiMockupAcceptanceBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ENDPOINT_BINDING_VARIABLES: &[&str] = &[
    "uiMockupAcceptanceDocuments",
    "uiMockupAcceptanceSurfaces",
    "uiMockupAcceptanceRequiredGuards",
    "uiMockupAcceptancePlanSections",
    "uiMockupAcceptanceBlockedReasons",
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "acceptanceMode",
    "mockupCoverageRequired",
    "accessibilityReviewRequired",
    "browserIsolationRequired",
    "evidenceSafetyRequired",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "mockupDocuments",
    "mockupSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "liveUiExecutionAllowed",
    "browserProviderCallsAllowed",
    "externalAssetFetchAllowed",
    "directVendorApiAllowed",
    "unsafeDebugDetailAllowed",
    "rawMockupRowsAllowed",
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
    "browserprovidercall",
    "directvendorapi",
    "externalasset",
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
    "rawmockup",
    "rawprovider",
    "rawevidence",
    "recipientemail",
    "recipientaddress",
    "recipientdata",
    "stacktrace",
    "unsafedebug",
    "implementationinternal",
    "providerpayload",
    "endpointurl",
    "url",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "batch-two-mockup-coverage-required",
        decision: "block",
        requirement: "Batch 2 UI acceptance requires shell, dashboard, catalog, request, inventory, CMDB, evidence, operations, and admin mockups before implementation readiness is accepted.",
        evidence: "Shell and dashboard mockup review",
    },
    RuleDetail {
        id: "browser-isolation-required",
        decision: "block",
        requirement: "Mockup acceptance keeps browser behavior limited to portal-ui and platform-api, with vendor and infrastructure access represented only as server-side platform summaries.",
        evidence: "Browser isolation review",
    },
    RuleDetail {
        id: "accessibility-status-required",
        decision: "block",
        requirement: "Mockups must show keyboard focus, contrast, non-color status signals, stale states, degraded states, blocked states, and safe error states before UI readiness is accepted.",
        evidence: "Accessibility acceptance review",
    },
    RuleDetail {
        id: "evidence-redaction-required",
        decision: "block",
        requirement: "Evidence and request mockups must show redaction state, export readiness, safe summaries, and controlled accepted or rejected counts before UI readiness is accepted.",
        evidence: "Evidence safety review",
    },
    RuleDetail {
        id: "raw-ui-mockup-data-not-exposed",
        decision: "block",
        requirement: "UI mockup acceptance evidence must use safe summaries only and must not expose direct vendor routes, external asset locations, organization-scope identifiers, provider-side identifiers, private network details, sensitive auth material, raw provider content, raw evidence content, raw mockup rows, stack traces, recipient details, or implementation internals.",
        evidence: "Raw detail exclusion review",
    },
];

#[derive(Debug, Deserialize)]
struct UiMockupAcceptanceContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    ui_readme: String,
    shell_mockup: String,
    catalog_mockup: String,
    inventory_mockup: String,
    evidence_mockup: String,
    accessibility: String,
    ui_ia: String,
    ui_design: String,
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
    ui_readme: String,
    shell_mockup: String,
    catalog_mockup: String,
    inventory_mockup: String,
    evidence_mockup: String,
    accessibility: String,
    ui_ia: String,
    ui_design: String,
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
    let context: UiMockupAcceptanceContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid ui mockup acceptance context JSON: {error}"))?;
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
        &context.ui_readme,
        &context.shell_mockup,
        &context.catalog_mockup,
        &context.inventory_mockup,
        &context.evidence_mockup,
        &context.accessibility,
        &context.ui_ia,
        &context.ui_design,
        &mut errors,
    );
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
    scan_prohibited_value(
        &Value::String(context.ui_readme),
        UI_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.shell_mockup),
        SHELL_MOCKUP_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.catalog_mockup),
        CATALOG_MOCKUP_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.inventory_mockup),
        INVENTORY_MOCKUP_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.evidence_mockup),
        EVIDENCE_MOCKUP_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.accessibility),
        ACCESSIBILITY_PATH,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.ui_ia), UI_IA_PATH, &mut errors);
    scan_prohibited_value(
        &Value::String(context.ui_design),
        UI_DESIGN_PATH,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid ui mockup acceptance catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid ui mockup acceptance program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid ui mockup acceptance docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.api_readme,
        &payload.catalog_readme,
        &payload.doc_readme,
        &payload.doc,
        &payload.ui_readme,
        &payload.shell_mockup,
        &payload.catalog_mockup,
        &payload.inventory_mockup,
        &payload.evidence_mockup,
        &payload.accessibility,
        &payload.ui_ia,
        &payload.ui_design,
        &mut errors,
    );
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid ui mockup acceptance prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("ui mockup acceptance catalog must be a mapping".to_string());
        return;
    };

    let actual_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected_keys: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "ui mockup acceptance unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }

    expect(
        value_i64(catalog, "version") == Some(1),
        errors,
        "ui mockup acceptance version must be 1",
    );
    expect(
        value_str(catalog, "status") == Some("draft"),
        errors,
        "ui mockup acceptance status must be draft",
    );
    expect(
        value_str(catalog, "source") == Some("static-seed"),
        errors,
        "ui mockup acceptance source must be static-seed",
    );
    expect(
        value_str(catalog, "acceptanceMode") == Some("static-ui-documentation"),
        errors,
        "ui mockup acceptance mode must be static-ui-documentation",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            value_bool(catalog, field) == Some(true),
            errors,
            &format!(
                "ui mockup acceptance must require {}",
                humanize_field(field)
            ),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            value_bool(catalog, field) == Some(false),
            errors,
            &format!("ui mockup acceptance {field} must be disabled"),
        );
    }

    validate_required_array(
        catalog,
        "mockupDocuments",
        REQUIRED_MOCKUP_DOCUMENTS,
        errors,
    );
    validate_required_array(catalog, "mockupSurfaces", REQUIRED_SURFACES, errors);
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
                "{field} contains prohibited ui mockup acceptance value {value}"
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
            "ui mockup acceptance missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "ui mockup acceptance unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.len() == actual.len(),
        errors,
        "ui mockup acceptance rule IDs must be unique",
    );

    let expected_rule_keys: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
    for rule in &rules {
        let label = value_str_direct(rule, "id").unwrap_or("(missing id)");
        let Some(object) = rule.as_object() else {
            errors.push(format!(
                "ui mockup acceptance rule {label} must be a mapping"
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
                "ui mockup acceptance rule {label} unexpected rule keys: {}",
                unexpected_rule_keys.join(", ")
            ));
        }
        if !missing_rule_keys.is_empty() {
            errors.push(format!(
                "ui mockup acceptance rule {label} missing rule keys: {}",
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
                "ui mockup acceptance rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            value_str_direct(rule, "requirement") == Some(expected_rule.requirement),
            errors,
            &format!(
                "ui mockup acceptance rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            value_str_direct(rule, "evidence") == Some(expected_rule.evidence),
            errors,
            &format!(
                "ui mockup acceptance rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
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
        exact_string_assignment(&block, "acceptanceMode", "static-ui-documentation"),
        errors,
        "API must keep static-ui-documentation mode",
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
                "API {field} contains prohibited ui mockup acceptance value {value}"
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

fn validate_docs_text(
    readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    ui_readme: &str,
    shell_mockup: &str,
    catalog_mockup: &str,
    inventory_mockup: &str,
    evidence_mockup: &str,
    accessibility: &str,
    ui_ia: &str,
    ui_design: &str,
    errors: &mut Vec<String>,
) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing ui mockup acceptance endpoint",
    );
    expect(
        catalog_readme.contains("ui-mockup-acceptance-contract.yaml"),
        errors,
        "catalog README missing ui mockup acceptance catalog",
    );
    expect(
        doc_readme.contains("ui-mockup-acceptance.md"),
        errors,
        "workflow README missing ui mockup acceptance doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "ui mockup acceptance doc missing endpoint",
    );
    expect(
        doc.contains("No live UI execution."),
        errors,
        "ui mockup acceptance doc must disable live UI execution",
    );
    expect(
        doc.contains("No browser provider calls."),
        errors,
        "ui mockup acceptance doc must disable browser provider calls",
    );
    expect(
        ui_readme.contains("Batch 2 product shell"),
        errors,
        "UI README missing Batch 2 scope",
    );
    expect(
        ui_readme.contains("mockups-shell-dashboard.md"),
        errors,
        "UI README missing shell mockup",
    );
    expect(
        shell_mockup.contains("Dashboard Overview Wireframe"),
        errors,
        "shell dashboard mockup missing dashboard overview",
    );
    expect(
        shell_mockup.contains("Light And Dark Mode Notes"),
        errors,
        "shell dashboard mockup missing theme notes",
    );
    expect(
        catalog_mockup.contains("Acceptance Checklist For Future UI Implementation"),
        errors,
        "catalog request mockup missing acceptance checklist",
    );
    expect(
        catalog_mockup.contains("Write-capable workflows block live execution"),
        errors,
        "catalog request mockup missing dry-run gate",
    );
    expect(
        inventory_mockup.contains("CMDB Import Wireframe"),
        errors,
        "inventory CMDB mockup missing import view",
    );
    expect(
        inventory_mockup.contains("CMDB Reconciliation And Export Wireframe"),
        errors,
        "inventory CMDB mockup missing export view",
    );
    expect(
        evidence_mockup.contains("browser-facing portal must remain"),
        errors,
        "evidence operations admin mockup missing browser isolation",
    );
    expect(
        evidence_mockup.contains("Acceptance Checklist For Future UI Implementation"),
        errors,
        "evidence operations admin mockup missing acceptance checklist",
    );
    expect(
        accessibility.contains("Batch 2 Acceptance"),
        errors,
        "accessibility checklist missing Batch 2 acceptance",
    );
    expect(
        accessibility.contains("Every status badge must include text, not color alone."),
        errors,
        "accessibility checklist missing non-color status rule",
    );
    expect(
        ui_ia.contains("First Mockup Priorities For Batch 2"),
        errors,
        "UI IA doc missing first mockup priorities",
    );
    expect(
        ui_design.contains("Light and dark mode are both first-class product requirements."),
        errors,
        "UI design system doc missing light/dark requirement",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> Option<String> {
    let routes = mapget_routes(program);
    let matching: Vec<&MapRoute> = routes
        .iter()
        .filter(|route| route.route == ENDPOINT)
        .collect();
    if matching.is_empty() {
        errors.push("API missing ui mockup acceptance endpoint".to_string());
        return None;
    }
    if matching.len() > 1 {
        errors.push("API duplicate ui mockup acceptance endpoint".to_string());
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
                "API endpoint has unexpected ui mockup acceptance field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited ui mockup acceptance field {field}"
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
                "live",
                "browser",
                "provider",
                "external",
                "direct",
                "unsafe",
                "raw",
                "credential",
                "secret",
                "token",
                "recipient",
                "asset",
                "vendor",
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
                        "{child_path} contains prohibited ui mockup acceptance field"
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
                    "{path} contains prohibited ui mockup acceptance field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn safe_text_value(value: &str) -> bool {
    [
        REQUIRED_MOCKUP_DOCUMENTS,
        REQUIRED_SURFACES,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        ENDPOINT_BINDING_VARIABLES,
        &["draft", "static-seed", "static-ui-documentation", "block"],
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
        REQUIRED_MOCKUP_DOCUMENTS,
        REQUIRED_SURFACES,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        ENDPOINT_BINDING_VARIABLES,
        &["draft", "static-seed", "static-ui-documentation", "block"],
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
                    "mockup",
                    "payload",
                    "logs",
                    "rows",
                    "recipient",
                ],
            ))
        || (tokens.iter().any(|token| token == "unsafe") && has_any(&tokens, &["debug", "detail"]))
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
    value.find("://").is_some_and(|index| {
        index > 0
            && value[..index]
                .chars()
                .rev()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || "+.-".contains(*character)
                })
                .count()
                > 0
    })
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

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
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
        .replace("mockupCoverage", "mockup coverage")
        .replace("accessibilityReview", "accessibility review")
        .replace("browserIsolation", "browser isolation")
        .replace("evidenceSafety", "evidence safety")
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
            &Value::String("safe text with https://ui.invalid/mockup".to_string()),
            "synthetic",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("prohibited value")));
    }
}
