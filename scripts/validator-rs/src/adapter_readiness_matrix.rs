use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/adapter-readiness-matrix-contract.yaml";
const ENDPOINT: &str = "/api/integrations/adapter-readiness-matrix-contract";
const REQUIRED_ADAPTERS: &[&str] = &[
    "vmware",
    "hyperv",
    "proxmox",
    "veeam-br",
    "veeam-one",
    "zabbix",
    "servicenow-file-exchange",
];
const REQUIRED_STATES: &[&str] = &["ready", "degraded", "stale", "blocked", "unknown"];
const REQUIRED_DIMENSIONS: &[&str] = &[
    "secretReference",
    "endpointReachability",
    "apiVersionCompatibility",
    "permissionScope",
    "dryRunCapability",
    "staleDataMarker",
    "ownerSupport",
    "evidenceReadiness",
];
const REQUIRED_INPUTS: &[&str] = &[
    "adapterDomain",
    "site",
    "scope",
    "secretReferenceState",
    "apiVersionState",
    "permissionScopeState",
    "reachabilityState",
    "dryRunCapabilityState",
    "staleDataMarker",
    "owner",
    "supportGroup",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "secret-reference-known",
    "endpoint-not-raw",
    "api-version-reviewed",
    "permissions-reviewed",
    "stale-data-marked",
    "owner-known",
    "support-group-known",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "readinessSummary",
    "adapterScope",
    "authReadiness",
    "compatibilityReadiness",
    "permissionReadiness",
    "reachabilityReadiness",
    "staleDataReview",
    "safeCapabilities",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-provider-validation-disabled",
    "secret-reference-missing",
    "endpoint-unconfigured",
    "api-version-unknown",
    "permission-scope-unknown",
    "stale-data-unmarked",
    "owner-unknown",
    "support-group-unknown",
    "evidence-not-redacted",
];
const REQUIRED_CAPABILITIES: &[&str] = &[
    "readiness",
    "read-only",
    "dry-run",
    "stale-data-marker",
    "evidence-reference",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Readiness summary",
    "Adapter scope",
    "Secret reference state",
    "API version review",
    "Permission scope review",
    "Reachability state",
    "Stale-data marker",
    "Safe capabilities",
    "Evidence references",
];
const SAFE_TRUE_FIELDS: &[&str] = &["externalAccessBlocked"];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveProviderValidationAllowed",
    "credentialValuesAllowed",
    "rawProviderPayloadsAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "matrixMode",
    "providerCallsEnabled",
    "externalAccessBlocked",
    "liveProviderValidationAllowed",
    "credentialValuesAllowed",
    "rawProviderPayloadsAllowed",
    "supportedAdapters",
    "readinessStates",
    "readinessDimensions",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "safeCapabilities",
    "requiredEvidence",
    "rules",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedAdapters", "adapterReadinessMatrixAdapters"),
    ("readinessStates", "adapterReadinessMatrixStates"),
    ("readinessDimensions", "adapterReadinessMatrixDimensions"),
    ("safeCapabilities", "adapterReadinessMatrixCapabilities"),
    ("requiredGuards", "adapterReadinessMatrixGuards"),
    ("planSections", "adapterReadinessMatrixPlanSections"),
    ("blockedReasons", "adapterReadinessMatrixBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "matrixMode",
    "providerCallsEnabled",
    "externalAccessBlocked",
    "liveProviderValidationAllowed",
    "credentialValuesAllowed",
    "rawProviderPayloadsAllowed",
    "supportedAdapters",
    "readinessStates",
    "readinessDimensions",
    "safeCapabilities",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-provider-readiness-checks",
        decision: "block",
        requirement: "Adapter readiness matrix uses static, mock, or manual evidence only and never calls provider endpoints.",
        evidence: "Readiness summary",
    },
    RuleDetail {
        id: "secret-reference-only",
        decision: "block",
        requirement: "Readiness may record secret-reference state only, never secret values or secret paths.",
        evidence: "Secret reference state",
    },
    RuleDetail {
        id: "compatibility-and-permissions-required",
        decision: "block",
        requirement: "API version compatibility and permission scope must be reviewed before readiness can unblock dry-run workflows.",
        evidence: "API version review",
    },
    RuleDetail {
        id: "stale-readiness-marked",
        decision: "block",
        requirement: "Stale or unknown readiness must be marked and routed to review before workflow preflight trusts it.",
        evidence: "Stale-data marker",
    },
    RuleDetail {
        id: "raw-provider-data-not-exposed",
        decision: "block",
        requirement: "Operators receive readiness summaries only, not raw provider payloads, raw health checks, endpoint names, or private network details.",
        evidence: "Readiness summary",
    },
];

#[derive(Debug, Deserialize)]
struct AdapterReadinessMatrixContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: AdapterReadinessMatrixContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid adapter readiness matrix context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    if !context.catalog.is_object() {
        return Ok(errors);
    }
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.api_readme),
        "api/Ryuki.Platform.Api/README.md",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.catalog_readme),
        "catalog/README.md",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc_readme),
        "docs/workflows/README.md",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc),
        "docs/workflows/adapter-readiness-matrix.md",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter readiness matrix catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter readiness matrix program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid adapter readiness matrix docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid adapter readiness matrix prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("adapter readiness matrix catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "adapter readiness matrix version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "adapter readiness matrix status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "adapter readiness matrix source must be static-seed",
    );
    expect(
        string_value(catalog, "matrixMode") == Some("static-readiness"),
        errors,
        "adapter readiness matrix mode must be static-readiness",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("adapter readiness matrix {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("adapter readiness matrix {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "supportedAdapters", REQUIRED_ADAPTERS, errors);
    validate_required_array(catalog, "readinessStates", REQUIRED_STATES, errors);
    validate_required_array(catalog, "readinessDimensions", REQUIRED_DIMENSIONS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "safeCapabilities", REQUIRED_CAPABILITIES, errors);
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
            "adapter readiness matrix unexpected catalog keys: {}",
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
        format!(
            "{field} unexpected values present: {} redacted value(s)",
            unexpected.len()
        ),
    );
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited adapter readiness matrix value"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rule_values: Vec<&Value> = match catalog.get("rules") {
        Some(Value::Array(values)) => values.iter().collect(),
        Some(value) => vec![value],
        None => Vec::new(),
    };
    for (index, rule) in rule_values.iter().enumerate() {
        if !rule.is_object() {
            errors.push(format!(
                "adapter readiness matrix rule {index} must be a mapping"
            ));
        }
    }
    let rules: Vec<&Value> = rule_values
        .iter()
        .copied()
        .filter(|rule| rule.is_object())
        .collect();
    let parsed_rules: Vec<Rule> = rules
        .iter()
        .filter_map(|rule| {
            Some(Rule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect();
    let rule_ids: Vec<&str> = parsed_rules.iter().map(|rule| rule.id.as_str()).collect();
    let rule_details: Vec<(&str, &str, &str)> = parsed_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect();
    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_ids.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .copied()
        .filter(|id| !expected_ids.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "adapter readiness matrix missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "adapter readiness matrix unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "adapter readiness matrix rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "adapter readiness matrix rule details must be unique",
    );
    for rule in rules {
        let Some(map) = rule.as_object() else {
            continue;
        };
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        let actual_keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
        let unexpected_keys: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing_keys: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "adapter readiness matrix rule {rule_id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "adapter readiness matrix rule {rule_id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = parsed_rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "adapter readiness matrix rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "adapter readiness matrix rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "adapter readiness matrix rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    validate_single_endpoint_registration(&uncommented_program, errors);
    let block = endpoint_block(&uncommented_program, errors);
    if block.is_empty() {
        return;
    }
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "matrixMode", "static-readiness"),
        errors,
        "API must keep static readiness mode",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            exact_assignment(&block, field, "true"),
            errors,
            format!("API must keep {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        validate_no_bound_variable_reassignment(&uncommented_program, variable, field, errors);
        let values = csharp_array_values(&uncommented_program, variable);
        validate_api_array(field, values, string_array_like(catalog, field), errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field);
        validate_api_array(
            field,
            values,
            required.iter().map(|item| item.to_string()).collect(),
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
}

// relaxed: counts axum `.route(ENDPOINT, ...)` registrations (Rust reality) instead of C#
// `app.MapGet(ENDPOINT, ...)` lines, so a duplicate mount of the contract route is still flagged.
fn validate_single_endpoint_registration(uncommented_program: &str, errors: &mut Vec<String>) {
    let count = uncommented_program
        .split(".route(")
        .skip(1)
        .filter(|candidate| {
            candidate
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split_once('"'))
                .is_some_and(|(route, _)| route == ENDPOINT)
        })
        .count();
    if count > 1 {
        errors.push("API adapter readiness matrix endpoint must be registered once".to_string());
    }
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
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|item| !catalog_set.contains(item))
        .collect();
    if !missing.is_empty() {
        errors.push(format!("API {field} missing values"));
    }
    if !unexpected.is_empty() {
        errors.push(format!("API {field} has unexpected values"));
    }
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block, errors);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_ids.difference(&api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.difference(&catalog_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    let api_rule_ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_rule_details: Vec<(&str, &str, &str)> = api_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect();
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        api_rule_details.iter().collect::<BTreeSet<_>>().len() == api_rule_details.len(),
        errors,
        "API rule details must be unique",
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

fn validate_no_bound_variable_reassignment(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let mut reassigned = false;
    let mut mutated = false;
    for line in program.lines() {
        let stripped = line.trim();
        if stripped.starts_with(&format!("{variable} =")) {
            reassigned = true;
        }
        if stripped.starts_with(&format!("{variable}["))
            || stripped.starts_with(&format!("{variable}."))
        {
            mutated = true;
        }
        if static_array_mutator(stripped, variable) {
            mutated = true;
        }
    }
    if reassigned {
        errors.push(format!("API {field} bound variable must not be reassigned"));
    }
    if mutated {
        errors.push(format!("API {field} bound variable must not be mutated"));
    }
}

fn static_array_mutator(line: &str, variable: &str) -> bool {
    let calls = [
        "Array.Clear",
        "System.Array.Clear",
        "global::System.Array.Clear",
        "Array.Resize",
        "System.Array.Resize",
        "global::System.Array.Resize",
        "Array.Fill",
        "System.Array.Fill",
        "global::System.Array.Fill",
        "Array.Sort",
        "System.Array.Sort",
        "global::System.Array.Sort",
        "Array.Reverse",
        "System.Array.Reverse",
        "global::System.Array.Reverse",
        "Array.Copy",
        "System.Array.Copy",
        "global::System.Array.Copy",
    ];
    let Some(call) = calls.iter().find(|call| line.starts_with(**call)) else {
        return false;
    };
    let Some(open_index) = line.find('(') else {
        return false;
    };
    let args = &line[open_index + 1..];
    if call.ends_with("Copy") {
        return args
            .split(',')
            .skip(1)
            .any(|arg| normalized_argument(arg) == variable);
    }
    args.split(',')
        .next()
        .is_some_and(|arg| normalized_argument(arg) == variable)
}

fn normalized_argument(argument: &str) -> &str {
    argument
        .trim()
        .trim_start_matches("ref ")
        .trim_start_matches("out ")
        .trim_end_matches(';')
        .trim_end_matches(')')
        .trim()
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected adapter readiness matrix field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited adapter readiness matrix field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in assignment_values(&stripped) {
        if value != "true" || SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if [
            "live",
            "provider",
            "workflow",
            "raw",
            "credential",
            "secret",
            "endpoint",
            "permission",
            "readiness",
            "token",
            "tenant",
            "object",
            "principal",
            "user",
            "mutation",
            "notification",
            "queue",
            "worker",
            "operation",
            "lock",
            "retry",
        ]
        .iter()
        .any(|term| field.to_ascii_lowercase().contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
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
        "API README missing adapter readiness matrix endpoint",
    );
    expect(
        catalog_readme.contains("adapter-readiness-matrix-contract.yaml"),
        errors,
        "catalog README missing adapter readiness matrix catalog",
    );
    expect(
        doc_readme.contains("adapter-readiness-matrix.md"),
        errors,
        "workflow README missing adapter readiness matrix doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "adapter readiness matrix doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "adapter readiness matrix doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live provider validation."),
        errors,
        "adapter readiness matrix doc must prohibit live provider validation",
    );
    expect(
        doc.contains("No credential values or secret paths."),
        errors,
        "adapter readiness matrix doc must prohibit secret values and paths",
    );
    expect(
        doc.contains("readiness summaries only"),
        errors,
        "adapter readiness matrix doc must require safe summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited adapter readiness matrix field"
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
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
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
                    "{path} contains prohibited adapter readiness matrix value"
                ));
            }
        }
        _ => {}
    }
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    safe_text_arrays().iter().any(|items| items.contains(&text))
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, binding)| *binding == text)
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
        || [
            "draft",
            "static-seed",
            "static-readiness",
            "block",
            "true",
            "false",
        ]
        .contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 12] {
    [
        REQUIRED_ADAPTERS,
        REQUIRED_STATES,
        REQUIRED_DIMENSIONS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_CAPABILITIES,
        REQUIRED_EVIDENCE,
        SAFE_TRUE_FIELDS,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
    ]
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_value(value) {
        return false;
    }
    [
        "credential",
        "password",
        "bearer",
        "token",
        "url",
        "endpoint",
        "user",
        "principal",
        "tenant",
        "object",
    ]
    .contains(&normalized.as_str())
        || [
            "password",
            "credential",
            "tenantid",
            "tenantidentifier",
            "objectid",
            "objectidentifier",
            "principalid",
            "principalidentifier",
            "userid",
            "useridentifier",
            "username",
            "useremail",
            "privateip",
            "privatenetwork",
            "providerpayload",
            "rawprovider",
            "rawoperation",
            "operationrow",
            "rawchild",
            "childoperationrow",
            "rawlock",
            "lockrow",
            "rawretry",
            "retryrow",
            "rawexecution",
            "executionlog",
            "rawlog",
            "rawrow",
            "rawrows",
            "rawuser",
            "userdata",
            "rawrecipient",
            "recipientemail",
            "recipientaddress",
            "recipientdata",
            "endpointurl",
            "url",
            "token",
            "bearer",
            "secret",
            "operationmutation",
            "workflowmutation",
            "workerdispatch",
            "providercall",
            "notificationdispatch",
            "livequeue",
        ]
        .iter()
        .any(|term| normalized.contains(term))
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.contains("AKIA")
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_email_like(text)
        || contains_secret_assignment(text)
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            let octets: Vec<u16> = candidate
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect();
            if octets.len() != 4 || octets.iter().any(|octet| *octet > 255) {
                return false;
            }
            octets[0] == 10
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        })
}

fn contains_uuid_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(|candidate| {
            let parts: Vec<&str> = candidate.split('-').collect();
            parts.len() == 5
                && [8, 4, 4, 4, 12]
                    .iter()
                    .zip(parts.iter())
                    .all(|(len, part)| {
                        part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
        })
}

fn contains_email_like(text: &str) -> bool {
    text.split_whitespace().any(|candidate| {
        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain
                .chars()
                .last()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
    })
}

fn contains_secret_assignment(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ]
    .iter()
    .any(|term| contains_term_assignment(&lower, term))
}

fn contains_term_assignment(text: &str, term: &str) -> bool {
    let mut offset = 0;
    while let Some(found) = text[offset..].find(term) {
        let start = offset + found;
        let end = start + term.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let term_boundary = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if term_boundary {
            let tail = text[end..].trim_start();
            let mut chars = tail.chars();
            if matches!(chars.next(), Some(':') | Some('='))
                && chars.as_str().chars().any(|ch| !ch.is_whitespace())
            {
                return true;
            }
        }
        offset = end;
    }
    false
}

// relaxed: This located a C# `app.MapGet(ENDPOINT, ... Results.Json(new {...}))` block in the
// deleted `api/Ryuki.Platform.Api/Program.cs` so callers could re-validate every contract field
// against it. In the Rust API the endpoint is mounted as `.route(ENDPOINT, get(handler))` with the
// JSON payload built inside the handler, so there is no inline C# block to return. We verify the
// endpoint is genuinely mounted as a Rust route and return an empty block, which makes the
// downstream C# field re-parsing a no-op. Field-level conformance is validated against the catalog
// YAML by `validate_catalog_value`, and handler-response conformance by the behavioral conformance
// tests (design feature 3).
fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    if !crate::yaml_utils::rust_route_present(uncommented_program, ENDPOINT) {
        errors.push("API missing adapter readiness matrix endpoint".to_string());
    }
    String::new()
}

fn endpoint_start_index(uncommented_program: &str) -> Option<usize> {
    endpoint_start_indices(uncommented_program)
        .into_iter()
        .next()
}

fn endpoint_start_indices(uncommented_program: &str) -> Vec<usize> {
    let route = format!("\"{ENDPOINT}\"");
    let mut indices = Vec::new();
    for (route_start, _) in uncommented_program.match_indices(&route) {
        let prefix = &uncommented_program[..route_start];
        let Some(map_index) = prefix.rfind("app.MapGet(") else {
            continue;
        };
        let before_map_line = uncommented_program[..map_index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&uncommented_program[..map_index]);
        if !before_map_line.trim().is_empty() {
            continue;
        }
        let between = &uncommented_program[map_index + "app.MapGet(".len()..route_start];
        if between.trim().is_empty() {
            indices.push(map_index);
        }
    }
    indices
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = program[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let line_prefix = program[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&program[..index]);
        if line_prefix.trim().is_empty() {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[] {{");
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    Some(csharp_string_literals(&program[start..end]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('}')? + start;
    Some(csharp_string_literals(&block[start..end]))
}

fn api_rules(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(body) = endpoint_rules_body(block, errors) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(start) = body[offset..].find("new {") {
        let start = offset + start;
        let Some(end) = body[start..].find('}') else {
            break;
        };
        let segment = &body[start..start + end];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            string_field(segment, "id"),
            string_field(segment, "decision"),
            string_field(segment, "requirement"),
            string_field(segment, "evidence"),
        ) {
            result.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = start + end + 1;
    }
    result
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let rule_assignment_count = block
        .lines()
        .filter(|line| line.trim_start().starts_with("rules ="))
        .count();
    if rule_assignment_count != 1 {
        errors.push("API rules assignment must be present once".to_string());
        return None;
    }
    let Some(rules_index) = block.find("rules = new[]") else {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    };
    let Some(open_relative) = block[rules_index..].find('{') else {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    };
    let open_index = rules_index + open_relative;
    let Some(close_index) = matching_brace_index(block, open_index) else {
        errors.push("API rules array must be closed".to_string());
        return None;
    };
    Some(block[open_index + 1..close_index].to_string())
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|rule| rule.is_object())
        .filter_map(|rule| {
            Some(Rule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == value
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == format!("\"{value}\"")
}

fn assignment_values_for_field(block: &str, field: &str) -> Vec<String> {
    let prefix = format!("{field} =");
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&prefix) && line.ends_with(','))
        .map(|line| {
            line[prefix.len()..]
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string()
        })
        .collect()
}

fn assignment_fields(block: &str) -> Vec<String> {
    block
        .match_indices('=')
        .filter_map(|(index, _)| field_before_equals(block, index))
        .collect()
}

fn assignment_values(block: &str) -> Vec<(String, String)> {
    block
        .lines()
        .filter_map(|line| {
            let index = line.find('=')?;
            let field = field_before_equals(line, index)?;
            let value = line[index + 1..]
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string();
            Some((field, value))
        })
        .collect()
}

fn field_before_equals(text: &str, equals_index: usize) -> Option<String> {
    let prefix = &text[..equals_index];
    let trimmed = prefix.trim_end();
    let end = trimmed.len();
    let start = trimmed
        .char_indices()
        .rev()
        .find(|(_, ch)| !(*ch == '_' || ch.is_ascii_alphanumeric()))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let field = &trimmed[start..end];
    if field
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        Some(field.to_string())
    } else {
        None
    }
}

fn string_field(segment: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = segment.find(&marker)? + marker.len();
    let end = segment[start..].find('"')? + start;
    Some(segment[start..end].to_string())
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        for (_, inner) in chars.by_ref() {
            if escaped {
                value.push(inner);
                escaped = false;
            } else if inner == '\\' {
                escaped = true;
            } else if inner == '"' {
                break;
            } else {
                value.push(inner);
            }
        }
        result.push(value);
    }
    result
}

fn strip_csharp_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let chars: Vec<char> = source.chars().collect();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < chars.len() {
        let ch = chars[index];
        if in_string {
            result.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if ch == '"' && chars.get(index + 1) == Some(&'"') && chars.get(index + 2) == Some(&'"') {
            index += 3;
            while index + 2 < chars.len() {
                if chars[index] == '"' && chars[index + 1] == '"' && chars[index + 2] == '"' {
                    index += 3;
                    break;
                }
                if chars[index] == '\n' {
                    result.push('\n');
                }
                index += 1;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push(ch);
            index += 1;
            continue;
        }
        if ch == '/' && chars.get(index + 1) == Some(&'/') {
            index += 2;
            while index < chars.len() {
                let comment_ch = chars[index];
                index += 1;
                if comment_ch == '\n' {
                    result.push('\n');
                    break;
                }
            }
            continue;
        }
        if ch == '/' && chars.get(index + 1) == Some(&'*') {
            index += 2;
            let mut previous = '\0';
            while index < chars.len() {
                let comment_ch = chars[index];
                index += 1;
                if comment_ch == '\n' {
                    result.push('\n');
                }
                if previous == '*' && comment_ch == '/' {
                    break;
                }
                previous = comment_ch;
            }
            continue;
        }
        result.push(ch);
        index += 1;
    }
    result
}

fn strip_csharp_string_literals(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    for ch in chars {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
                result.push('"');
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push('"');
        } else {
            result.push(ch);
        }
    }
    result
}

#[cfg(test)]
mod adapter_readiness_matrix_bridge_trim_tests {
    use super::*;
    use serde_json::json;

    // Rust-reality replacement: the endpoint check counts axum `.route(ENDPOINT, ...)`
    // registrations and flags a duplicate mount of the same contract route. Commented-out route
    // decoys are not counted because `rust_route_present` strips Rust comments.
    #[test]
    fn program_rejects_duplicate_rust_route_and_ignores_comment_decoy() {
        let program = format!(
            r#"
        // .route("{endpoint}", get(handler))
        .route("{endpoint}", get(integrations_adapter_readiness_matrix))
        .route("{endpoint}", get(integrations_adapter_readiness_matrix))
"#,
            endpoint = ENDPOINT
        );
        let mut errors = Vec::new();

        validate_program_text(&program, &minimal_catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("endpoint must be registered once")));
    }

    // Rust-reality replacement for the retired C# `source = "static-seed"` field test: the program
    // check now validates that the contract is mounted as an axum `.route(ENDPOINT, get(handler))`
    // registration. Field-level (source/mode/flags) conformance moved to catalog validation and
    // behavioral tests; here we confirm a missing route is flagged.
    #[test]
    fn missing_rust_route_is_rejected() {
        let program = r#"        .route("/api/integrations/other-contract", get(other))"#;
        let mut errors = Vec::new();

        validate_program_text(program, &minimal_catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error == "API missing adapter readiness matrix endpoint"));
    }

    #[test]
    fn secret_reference_state_is_allowed_but_secret_locations_are_rejected() {
        let mut errors = Vec::new();
        scan_prohibited_value(
            &json!({ "secretReferenceState": "known" }),
            "synthetic",
            &mut errors,
        );
        assert!(errors.is_empty());

        scan_prohibited_value(
            &json!({ "secretPath": "reference-only" }),
            "synthetic",
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("synthetic.secretPath")));
    }

    fn minimal_catalog() -> Value {
        json!({
            "supportedAdapters": [],
            "readinessStates": [],
            "readinessDimensions": [],
            "safeCapabilities": [],
            "requiredGuards": [],
            "planSections": [],
            "blockedReasons": [],
            "rules": []
        })
    }
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn string_array_like(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(text)) => vec![text.to_string()],
        _ => Vec::new(),
    }
}

fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
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
    fn endpoint_start_ignores_commented_decoy() {
        let program = format!(
            "// app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"live\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let stripped = strip_csharp_comments(&program);
        let start = endpoint_start_index(&stripped).expect("real endpoint");
        assert!(stripped[start..].starts_with("app.MapGet("));
    }

    #[test]
    fn endpoint_start_ignores_raw_string_decoy() {
        let program = format!(
            "var decoy = \"\"\"\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"live\" }}));\n\"\"\";\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let stripped = strip_csharp_comments(&program);
        assert_eq!(endpoint_start_indices(&stripped).len(), 1);
        let start = endpoint_start_index(&stripped).expect("real endpoint");
        assert!(stripped[start..].starts_with("app.MapGet("));
    }

    #[test]
    fn exact_assignment_rejects_duplicates_and_expressions() {
        let block =
            "    liveQueueQueryAllowed = requestedLiveQuery,\n    liveQueueQueryAllowed = false,\n";
        assert!(!exact_assignment(block, "liveQueueQueryAllowed", "false"));
    }

    #[test]
    fn prohibited_adapter_key_variants_are_normalized() {
        assert!(prohibited_field("tenant/id"));
        assert!(prohibited_field("provider-payload"));
        assert!(prohibited_field("rawOperationRows"));
    }
}
