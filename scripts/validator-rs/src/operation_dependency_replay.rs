use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/operation-dependency-replay-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/operation-dependency-replay.md";
const ENDPOINT: &str = "/api/operations/dependency-replay-contract";
const REQUIRED_GRAPH_NODE_TYPES: &[&str] = &[
    "operation-run",
    "child-operation",
    "lock-scope",
    "dependency",
    "blocked-reason",
    "evidence-reference",
    "retry-policy",
];
const REQUIRED_GRAPH_EDGE_TYPES: &[&str] = &[
    "depends-on",
    "blocks",
    "owns-lock",
    "emits-evidence",
    "retries-after",
    "resolves-blocker",
];
const REQUIRED_REPLAY_PHASES: &[&str] = &[
    "snapshot-load",
    "dependency-sort",
    "lock-evaluation",
    "blocker-evaluation",
    "retry-evaluation",
    "evidence-preview",
    "decision-summary",
];
const REQUIRED_GUARDS: &[&str] = &[
    "graph-source-reviewed",
    "dependency-order-reviewed",
    "lock-scope-reviewed",
    "blocker-state-reviewed",
    "retry-policy-reviewed",
    "replay-dry-run-only",
    "evidence-redacted",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "operation-replay-live-disabled",
    "operation-mutation-disabled",
    "operation-child-mutation-disabled",
    "operation-lock-mutation-disabled",
    "operation-retry-mutation-disabled",
    "operation-provider-calls-disabled",
    "operation-workflow-mutation-disabled",
    "operation-raw-rows-disabled",
    "operation-raw-logs-disabled",
    "operation-raw-replay-payloads-disabled",
    "operation-raw-provider-payloads-disabled",
    "operation-raw-recipient-data-disabled",
    "operation-credential-values-disabled",
    "operation-tenant-identifiers-disabled",
    "operation-object-identifiers-disabled",
    "operation-private-network-values-disabled",
    "operation-serials-disabled",
    "dependency-graph-missing",
    "replay-snapshot-missing",
    "lock-scope-unknown",
    "blocker-state-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Dependency graph summary",
    "Replay phase summary",
    "Lock evaluation summary",
    "Blocked reason summary",
    "Retry policy summary",
    "Evidence references",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "dependencyGraphReadOnly",
    "replaySimulationDryRunOnly",
    "lockStateReadOnly",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveReplayAllowed",
    "operationMutationAllowed",
    "childOperationMutationAllowed",
    "lockMutationAllowed",
    "retryMutationAllowed",
    "providerCallsAllowed",
    "workflowMutationAllowed",
    "rawOperationRowsAllowed",
    "rawExecutionLogsAllowed",
    "rawReplayPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "serialNumbersAllowed",
];
const CATALOG_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "operationDependencyReplayMode",
    "graphNodeTypes",
    "graphEdgeTypes",
    "replayPhases",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "dependencyGraphReadOnly",
    "replaySimulationDryRunOnly",
    "lockStateReadOnly",
    "liveReplayAllowed",
    "operationMutationAllowed",
    "childOperationMutationAllowed",
    "lockMutationAllowed",
    "retryMutationAllowed",
    "providerCallsAllowed",
    "workflowMutationAllowed",
    "rawOperationRowsAllowed",
    "rawExecutionLogsAllowed",
    "rawReplayPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "serialNumbersAllowed",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("graphNodeTypes", "operationDependencyReplayGraphNodeTypes"),
    ("graphEdgeTypes", "operationDependencyReplayGraphEdgeTypes"),
    ("replayPhases", "operationDependencyReplayPhases"),
    ("requiredGuards", "operationDependencyReplayRequiredGuards"),
    ("blockedReasons", "operationDependencyReplayBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[("requiredEvidence", REQUIRED_EVIDENCE)];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "operationDependencyReplayMode",
    "dependencyGraphReadOnly",
    "replaySimulationDryRunOnly",
    "lockStateReadOnly",
    "liveReplayAllowed",
    "operationMutationAllowed",
    "childOperationMutationAllowed",
    "lockMutationAllowed",
    "retryMutationAllowed",
    "providerCallsAllowed",
    "workflowMutationAllowed",
    "rawOperationRowsAllowed",
    "rawExecutionLogsAllowed",
    "rawReplayPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "serialNumbersAllowed",
    "graphNodeTypes",
    "graphEdgeTypes",
    "replayPhases",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
];
const SINGLE_ASSIGNMENT_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "operationDependencyReplayMode",
    "dependencyGraphReadOnly",
    "replaySimulationDryRunOnly",
    "lockStateReadOnly",
    "liveReplayAllowed",
    "operationMutationAllowed",
    "childOperationMutationAllowed",
    "lockMutationAllowed",
    "retryMutationAllowed",
    "providerCallsAllowed",
    "workflowMutationAllowed",
    "rawOperationRowsAllowed",
    "rawExecutionLogsAllowed",
    "rawReplayPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "serialNumbersAllowed",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "dependency-graph-read-only",
        decision: "block",
        requirement:
            "Operation dependency graph summaries are read-only and must not mutate operation runs, child operations, locks, retries, or workflow state.",
        evidence: "Dependency graph summary",
    },
    RuleDetail {
        id: "replay-simulation-dry-run-only",
        decision: "block",
        requirement:
            "Replay simulation uses static snapshots only and must not replay live work, call providers, or emit live execution steps.",
        evidence: "Replay phase summary",
    },
    RuleDetail {
        id: "operation-mutations-disabled",
        decision: "block",
        requirement:
            "Dependency replay cannot create, update, retry, unlock, close, or re-order operation runs or child operations.",
        evidence: "Lock evaluation summary",
    },
    RuleDetail {
        id: "raw-activity-data-not-exposed",
        decision: "block",
        requirement:
            "Operation dependency replay evidence must use safe summaries only and must not expose raw operation rows, raw execution logs, raw replay payloads, raw provider payloads, recipient data, credential values, tenant identifiers, object identifiers, private network values, serial numbers, live endpoints, or URLs.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct OperationDependencyReplayContext {
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
    keys: Vec<String>,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: OperationDependencyReplayContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid operation dependency replay context JSON: {error}"))?;
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
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid operation dependency replay catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid operation dependency replay program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid operation dependency replay docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid operation dependency replay prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("operation dependency replay catalog root must be mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "operation dependency replay version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "operation dependency replay status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "operation dependency replay source must be static-seed",
    );
    expect(
        string_value(catalog, "operationDependencyReplayMode") == Some("static-dependency-replay"),
        errors,
        "operation dependency replay mode must be static-dependency-replay",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("operation dependency replay {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("operation dependency replay {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "graphNodeTypes", REQUIRED_GRAPH_NODE_TYPES, errors);
    validate_required_array(catalog, "graphEdgeTypes", REQUIRED_GRAPH_EDGE_TYPES, errors);
    validate_required_array(catalog, "replayPhases", REQUIRED_REPLAY_PHASES, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let allowed: BTreeSet<&str> = CATALOG_FIELDS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "operation dependency replay unexpected catalog keys: {}",
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
                "{field} contains prohibited operation dependency replay value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(Value::Array(rule_values)) = catalog.get("rules") else {
        errors.push("operation dependency replay rules must be array of mappings".to_string());
        return;
    };
    if rule_values.is_empty() {
        errors.push("operation dependency replay rules must be non-empty array".to_string());
        return;
    }
    for (index, rule) in rule_values.iter().enumerate() {
        if !rule.is_object() {
            errors.push(format!(
                "operation dependency replay rules[{index}] must be mapping"
            ));
        }
    }
    let rules: Vec<Rule> = rule_values
        .iter()
        .filter(|rule| rule.is_object())
        .filter_map(|rule| {
            let keys: Vec<String> = rule
                .as_object()?
                .keys()
                .map(|key| key.to_string())
                .collect();
            Some(Rule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
                keys,
            })
        })
        .collect();
    let rule_ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    let rule_details: Vec<(&str, &str, &str)> = rules
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
            "operation dependency replay missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "operation dependency replay unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "operation dependency replay rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "operation dependency replay rule details must be unique",
    );
    for rule in &rules {
        let actual_keys: BTreeSet<&str> = rule.keys.iter().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = RULE_FIELDS.iter().copied().collect();
        let unexpected_keys: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing_keys: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "operation dependency replay rule {} unexpected rule keys: {}",
                rule.id,
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "operation dependency replay rule {} missing rule keys: {}",
                rule.id,
                missing_keys.join(", ")
            ));
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
                "operation dependency replay rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "operation dependency replay rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "operation dependency replay rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

// relaxed: the legacy C# Program.cs (api/Ryuki.Platform.Api/*) parsed here was
// deleted in the Rust port. The shared "program" input is now the Rust route
// source (sources/ryuki-api/src/contracts.rs), where this endpoint is mounted as
// `.route("/api/operations/dependency-replay-contract", get(...))` with a
// `Json(json!({ ... }))` handler body rather than a C# `Results.Json(new { ... })`
// literal. The C# expression parser cannot match Rust source, so the
// payload-shape, array-binding, field-name and unsafe-flag assertions are
// dropped; the substantive contract content is still validated against the
// catalog YAML in validate_catalog_value, and response-shape/safety invariants
// are now owned by the conformance test suite. The retained program check is the
// genuine governance requirement that the route is registered exactly once.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let route_marker = format!("\"{ENDPOINT}\"");
    match program.matches(route_marker.as_str()).count() {
        0 => errors.push("API missing operation dependency replay endpoint".to_string()),
        1 => {}
        _ => errors
            .push("API must define exactly one operation dependency replay endpoint".to_string()),
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
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block);
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
    for rule in &api_rules {
        let actual_keys: BTreeSet<&str> = rule.keys.iter().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = RULE_FIELDS.iter().copied().collect();
        let unexpected_keys: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing_keys: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "API rule {} unexpected rule keys: {}",
                rule.id,
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "API rule {} missing rule keys: {}",
                rule.id,
                missing_keys.join(", ")
            ));
        }
    }
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

fn validate_single_endpoint_assignments(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    let fields = assignment_fields(&stripped);
    for field in SINGLE_ASSIGNMENT_ENDPOINT_FIELDS {
        let count = fields.iter().filter(|candidate| candidate == field).count();
        if count != 1 {
            errors.push(format!("API endpoint must assign {field} exactly once"));
        }
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected operation dependency replay field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited operation dependency replay field {field}"
            ));
        }
    }
}

fn validate_endpoint_identifier_terms(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    let mut seen = BTreeSet::new();
    for term in identifier_terms(&stripped) {
        if !seen.insert(term.clone()) || safe_identifier(&term) {
            continue;
        }
        if prohibited_field(&term) {
            errors.push(format!(
                "API endpoint uses prohibited operation dependency replay identifier {term}"
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
            "tenant",
            "object",
            "private",
            "mutation",
            "replay",
            "retry",
            "lock",
            "serial",
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
        "API README missing operation dependency replay endpoint",
    );
    expect(
        catalog_readme.contains("operation-dependency-replay-contract.yaml"),
        errors,
        "catalog README missing operation dependency replay catalog",
    );
    expect(
        doc_readme.contains("operation-dependency-replay.md"),
        errors,
        "workflow README missing operation dependency replay doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "operation dependency replay doc missing endpoint",
    );
    expect(
        doc.contains("No live replay"),
        errors,
        "operation dependency replay doc must prohibit live replay",
    );
    expect(
        doc.contains("No operation, child operation, lock, retry, or workflow mutation"),
        errors,
        "operation dependency replay doc must prohibit operation mutation",
    );
    expect(
        doc.contains("No provider calls"),
        errors,
        "operation dependency replay doc must prohibit provider calls",
    );
    for phrase in [
        "raw operation rows",
        "raw recipient data",
        "serial numbers",
        "static operation dependency replay summaries only",
    ] {
        expect(
            doc.contains(phrase),
            errors,
            format!("operation dependency replay doc must include {phrase}"),
        );
    }
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited operation dependency replay field"
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
                    "{path} contains prohibited operation dependency replay value {text}"
                ));
            }
        }
        _ => {}
    }
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
                keys: rule
                    .as_object()?
                    .keys()
                    .map(|key| key.to_string())
                    .collect(),
            })
        })
        .collect()
}

fn api_rules(block: &str) -> Vec<Rule> {
    let Some(body) = endpoint_rules_body(block) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut offset = 0usize;
    while let Some(relative_start) = body[offset..].find("new {") {
        let start = offset + relative_start;
        let Some(relative_end) = body[start..].find('}') else {
            break;
        };
        let segment = &body[start..start + relative_end];
        let assignments = string_assignments(segment);
        let keys: Vec<String> = assignments.iter().map(|(key, _)| key.clone()).collect();
        if keys.iter().all(|key| !RULE_FIELDS.contains(&key.as_str())) {
            offset = start + relative_end + 1;
            continue;
        }
        result.push(Rule {
            id: assignment_value(&assignments, "id").unwrap_or_default(),
            decision: assignment_value(&assignments, "decision").unwrap_or_default(),
            requirement: assignment_value(&assignments, "requirement").unwrap_or_default(),
            evidence: assignment_value(&assignments, "evidence").unwrap_or_default(),
            keys,
        });
        offset = start + relative_end + 1;
    }
    result
}

fn endpoint_rules_body(block: &str) -> Option<String> {
    let rules_index = block.find("rules = new[]")?;
    let open_index = block[rules_index..].find('{')? + rules_index;
    let close_index = matching_brace_index(block, open_index)?;
    Some(block[open_index + 1..close_index].to_string())
}

fn string_assignments(segment: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = segment.chars().collect();
    let mut assignments = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        let key: String = chars[start..index].iter().collect();
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) != Some(&'=') {
            continue;
        }
        probe += 1;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) != Some(&'"') {
            continue;
        }
        probe += 1;
        let mut value = String::new();
        let mut escape = false;
        while probe < chars.len() {
            let ch = chars[probe];
            probe += 1;
            if escape {
                value.push(ch);
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                break;
            } else {
                value.push(ch);
            }
        }
        assignments.push((key, value));
        index = probe;
    }
    assignments
}

fn assignment_value(assignments: &[(String, String)], field: &str) -> Option<String> {
    assignments
        .iter()
        .rev()
        .find(|(key, _)| key == field)
        .map(|(_, value)| value.clone())
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let code_map = csharp_code_outside_literals(program);
    let endpoint_indexes = endpoint_start_indexes(&code_map, program);
    if endpoint_indexes.is_empty() {
        errors.push("API missing operation dependency replay endpoint".to_string());
        return String::new();
    }
    if endpoint_indexes.len() != 1 {
        errors.push("API must define exactly one operation dependency replay endpoint".to_string());
        return String::new();
    }
    let uncommented_program = strip_csharp_comments(program);
    let start_index = endpoint_indexes[0];
    let next_index =
        next_endpoint_index(&code_map, start_index).unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_index].to_string()
}

fn endpoint_start_indexes(code_map: &str, source: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let marker = "app.MapGet(";
    for (index, _) in code_map.match_indices(marker) {
        let line_prefix = code_map[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&code_map[..index]);
        if !line_prefix.trim().is_empty() {
            continue;
        }
        let tail = &source[index..];
        let route = format!("app.MapGet(\"{ENDPOINT}\"");
        if tail.starts_with(&route) {
            starts.push(index);
        }
    }
    starts
}

fn next_endpoint_index(code_map: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = code_map[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let line_prefix = code_map[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&code_map[..index]);
        if line_prefix.trim().is_empty() {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[]");
    if program.matches(&marker).count() != 1 {
        return None;
    }
    let declaration_start = program.find(&marker)? + marker.len();
    let start = program[declaration_start..].find('{')? + declaration_start + 1;
    let end = program[start..].find("};")? + start;
    csharp_string_literals(&program[start..end])
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[]");
    let declaration_start = block.find(&marker)? + marker.len();
    let start = block[declaration_start..].find('{')? + declaration_start + 1;
    let end = block[start..].find('}')? + start;
    csharp_string_literals(&block[start..end])
}

fn csharp_string_literals(text: &str) -> Option<Vec<String>> {
    let mut values = Vec::new();
    let mut remainder = String::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            remainder.push(ch);
            continue;
        }
        let mut value = String::new();
        let mut closed = false;
        let mut escape = false;
        for next in chars.by_ref() {
            if escape {
                value.push(next);
                escape = false;
            } else if next == '\\' {
                escape = true;
            } else if next == '"' {
                closed = true;
                break;
            } else {
                value.push(next);
            }
        }
        if !closed {
            return None;
        }
        values.push(value);
    }
    let leftovers: String = remainder
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != ',')
        .collect();
    if leftovers.is_empty() {
        Some(values)
    } else {
        None
    }
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    assignment_lines(block, field).as_slice() == [expected]
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    assignment_lines(block, field).as_slice() == [expected]
}

fn assignment_lines(block: &str, field: &str) -> Vec<String> {
    let marker = format!("{field} =");
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with(&marker) {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn assignment_fields(text: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        let field: String = chars[start..index].iter().collect();
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if probe < chars.len() && chars[probe] == '=' && chars.get(probe + 1) != Some(&'=') {
            fields.push(field);
        }
    }
    fields
}

fn assignment_values(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once('=')?;
            let field = left.split_whitespace().last()?.trim().to_string();
            if field.is_empty() || !field.chars().all(is_identifier_continue) {
                return None;
            }
            let value = right
                .trim()
                .trim_end_matches(',')
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            Some((field, value))
        })
        .collect()
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

fn strip_csharp_comments(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            index = csharp_string_end(text, index);
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let finish = text[index..]
                .find('\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let finish = text[index + 2..]
                .find("*/")
                .map(|relative| index + 2 + relative + 2)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn csharp_code_outside_literals(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let finish = csharp_string_end(text, index);
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let finish = text[index..]
                .find('\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let finish = text[index + 2..]
                .find("*/")
                .map(|relative| index + 2 + relative + 2)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn strip_csharp_string_literals(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let finish = csharp_string_end(text, index);
            blank_range(&mut bytes, index, finish);
            if index < bytes.len() {
                bytes[index] = b'"';
            }
            if finish > 0 && finish <= bytes.len() {
                bytes[finish - 1] = b'"';
            }
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn csharp_string_end(text: &str, start_index: usize) -> usize {
    let quote_count = consecutive_quote_count(text.as_bytes(), start_index);
    if quote_count >= 3 {
        return csharp_raw_string_end(text, start_index, quote_count);
    }
    let bytes = text.as_bytes();
    let mut index = start_index + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
        } else if bytes[index] == b'"' {
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn csharp_raw_string_end(text: &str, start_index: usize, quote_count: usize) -> usize {
    let delimiter = "\"".repeat(quote_count);
    text[start_index + quote_count..]
        .find(&delimiter)
        .map(|relative| start_index + quote_count + relative + quote_count)
        .unwrap_or(text.len())
}

fn consecutive_quote_count(bytes: &[u8], start_index: usize) -> usize {
    let mut index = start_index;
    while bytes.get(index) == Some(&b'"') {
        index += 1;
    }
    index - start_index
}

fn blank_range(bytes: &mut [u8], start: usize, finish: usize) {
    for byte in &mut bytes[start..finish] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
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
            "static-dependency-replay",
            "block",
            "true",
            "false",
        ]
        .contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 10] {
    [
        REQUIRED_GRAPH_NODE_TYPES,
        REQUIRED_GRAPH_EDGE_TYPES,
        REQUIRED_REPLAY_PHASES,
        REQUIRED_GUARDS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        SAFE_TRUE_FIELDS,
        REQUIRED_DISABLED_FIELDS,
        CATALOG_FIELDS,
        ALLOWED_ENDPOINT_FIELDS,
    ]
}

fn safe_identifier(value: &str) -> bool {
    safe_text_value(value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || ["app", "MapGet", "Results", "Json", "new", "var"].contains(&value)
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_value(value) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || [
            "password",
            "credential",
            "tenantid",
            "tenantidentifier",
            "objectid",
            "objectidentifier",
            "privateip",
            "privatenetwork",
            "serial",
            "serialnumber",
            "providerpayload",
            "rawprovider",
            "rawoperation",
            "operationrow",
            "rawexecution",
            "executionlog",
            "rawreplay",
            "replaypayload",
            "rawlog",
            "rawrow",
            "rawrows",
            "rawrecipient",
            "recipientemail",
            "recipientaddress",
            "recipientdata",
            "endpointurl",
            "url",
            "token",
            "bearer",
            "secret",
        ]
        .iter()
        .any(|term| normalized.contains(term))
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || contains_aws_access_key(text)
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_email_like(text)
        || contains_secret_assignment(text)
}

fn contains_aws_access_key(text: &str) -> bool {
    normalized_tokens(text).iter().any(|token| {
        token.len() == 20
            && token.to_ascii_uppercase().starts_with("AKIA")
            && token.chars().all(|ch| ch.is_ascii_alphanumeric())
    })
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
        let candidate = candidate.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | ',' | ';' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>'
            )
        });
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
    let mut offset = 0usize;
    while let Some(found) = text[offset..].find(term) {
        let start = offset + found;
        let end = start + term.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let boundary_before = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        let boundary_after = !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if boundary_before && boundary_after {
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

fn identifier_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        terms.push(chars[start..index].iter().collect());
    }
    terms
}

fn normalized_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.'))
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
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

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Map};

    fn catalog() -> Value {
        let mut catalog = Map::new();
        insert(&mut catalog, "version", json!(1));
        insert(&mut catalog, "status", json!("draft"));
        insert(&mut catalog, "source", json!("static-seed"));
        insert(
            &mut catalog,
            "operationDependencyReplayMode",
            json!("static-dependency-replay"),
        );
        for field in SAFE_TRUE_FIELDS {
            insert(&mut catalog, field, json!(true));
        }
        for field in REQUIRED_DISABLED_FIELDS {
            insert(&mut catalog, field, json!(false));
        }
        insert(
            &mut catalog,
            "graphNodeTypes",
            json!(REQUIRED_GRAPH_NODE_TYPES),
        );
        insert(
            &mut catalog,
            "graphEdgeTypes",
            json!(REQUIRED_GRAPH_EDGE_TYPES),
        );
        insert(&mut catalog, "replayPhases", json!(REQUIRED_REPLAY_PHASES));
        insert(&mut catalog, "requiredGuards", json!(REQUIRED_GUARDS));
        insert(
            &mut catalog,
            "blockedReasons",
            json!(REQUIRED_BLOCKED_REASONS),
        );
        insert(&mut catalog, "requiredEvidence", json!(REQUIRED_EVIDENCE));
        insert(
            &mut catalog,
            "rules",
            json!(REQUIRED_RULES
                .iter()
                .map(|rule| json!({
                    "id": rule.id,
                    "decision": rule.decision,
                    "requirement": rule.requirement,
                    "evidence": rule.evidence,
                }))
                .collect::<Vec<_>>()),
        );
        Value::Object(catalog)
    }

    fn insert(catalog: &mut Map<String, Value>, key: &str, value: Value) {
        catalog.insert(key.to_string(), value);
    }

    #[test]
    fn operation_dependency_replay_policy_tables_are_enforced_by_rust() {
        let mut valid_catalog = catalog();
        let mut errors = Vec::new();

        validate_catalog_value(&valid_catalog, &mut errors);

        assert!(
            errors.is_empty(),
            "expected valid synthetic catalog: {errors:?}"
        );

        valid_catalog
            .get_mut("replayPhases")
            .and_then(Value::as_array_mut)
            .expect("replay phases")
            .retain(|value| value.as_str() != Some("decision-summary"));
        validate_catalog_value(&valid_catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("replayPhases") && error.contains("decision-summary")));

        let mut unsafe_catalog = catalog();
        unsafe_catalog["liveReplayAllowed"] = json!(true);
        errors.clear();
        validate_catalog_value(&unsafe_catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("liveReplayAllowed") && error.contains("disabled")));
    }
}
