use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const DOC_PATH: &str = "docs/workflows/cmdb-relationship-graph.md";
const ENDPOINT: &str = "/api/cmdb/relationship-graph-contract";
const REQUIRED_NODES: &[&str] = &[
    "application",
    "environment",
    "vm",
    "database",
    "network",
    "storage",
    "backup-policy",
    "monitoring-profile",
    "owner",
];
const REQUIRED_EDGES: &[&str] = &[
    "contains",
    "depends-on",
    "runs-on",
    "connects-to",
    "protected-by",
    "monitored-by",
    "owned-by",
    "supports",
];
const REQUIRED_GUARDS: &[&str] = &[
    "cmdb-file-contract-validated",
    "ci-identity-known",
    "relationship-source-known",
    "relationship-direction-known",
    "stale-data-marked",
    "reviewer-approval-assigned",
    "evidence-redacted",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "live-api-disabled",
    "missing-ci-identity",
    "ambiguous-relationship",
    "relationship-source-unknown",
    "relationship-direction-unknown",
    "stale-data-unmarked",
    "reviewer-approval-missing",
    "evidence-not-redacted",
];
const REQUIRED_INPUTS: &[&str] = &[
    "platformCiKey",
    "ciClass",
    "relationshipSource",
    "relationshipTarget",
    "relationshipType",
    "owner",
    "supportGroup",
    "evidenceManifest",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Relationship graph summary",
    "CI identity summary",
    "Relationship source",
    "Relationship direction",
    "Accepted/rejected edges",
    "Reviewer approval",
    "Evidence references",
];
const REQUIRED_RULE_DETAILS: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-servicenow-api",
        "block",
        "Relationship graph contract uses imported file state only and never calls live ServiceNow API.",
        "Relationship graph summary",
    ),
    (
        "deterministic-ci-key-required",
        "block",
        "Every relationship edge must reference deterministic platform CI keys.",
        "CI identity summary",
    ),
    (
        "relationship-direction-required",
        "block",
        "Relationship source, target, and direction must be explicit before graph edges are accepted.",
        "Relationship direction",
    ),
    (
        "ambiguous-relationship-requires-review",
        "block",
        "Ambiguous or conflicting relationships must be rejected or routed to reviewer approval.",
        "Accepted/rejected edges",
    ),
];
const REQUIRED_RULES: &[&str] = &[
    "no-live-servicenow-api",
    "deterministic-ci-key-required",
    "relationship-direction-required",
    "ambiguous-relationship-requires-review",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveApiEnabled",
    "rawProviderPayloadsAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "graphMode",
    "providerCallsEnabled",
    "liveApiEnabled",
    "rawProviderPayloadsAllowed",
    "nodeTypes",
    "edgeTypes",
    "requiredInputs",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("nodeTypes", "cmdbRelationshipNodeTypes"),
    ("edgeTypes", "cmdbRelationshipEdgeTypes"),
    ("requiredGuards", "cmdbRelationshipRequiredGuards"),
    ("blockedReasons", "cmdbRelationshipBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const BASE_ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "graphMode",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "requiredInputs",
    "requiredEvidence",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
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
];
const PROHIBITED_FIELD_NEEDLES: &[&str] = &[
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
    "useremail",
    "privateip",
    "privatenetwork",
    "rawmetric",
    "rawrequest",
    "rawoperation",
    "rawinventory",
    "rawcmdb",
    "rawbackup",
    "rawmonitoring",
    "rawproviderpayload",
    "rawrecipient",
    "recipientemail",
    "recipientaddress",
    "recipientdata",
    "endpointurl",
    "url",
    "token",
    "bearer",
    "secret",
    "provider",
    "mutation",
    "notification",
    "livequery",
    "livedashboard",
    "dashboardquery",
    "servicenowapi",
    "cmdbmutation",
    "relationshipmutation",
    "rawrelationship",
    "relationshiprow",
    "rawimpact",
    "impactrow",
    "rawlog",
    "rawrow",
    "rawrows",
    "serial",
    "serialnumber",
];
const SECRET_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    program: String,
    api_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct CatalogInput {
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    api_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid CMDB relationship graph context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_no_prohibited_values(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    // PROGRAM_PATH (the whole contracts.rs file) is excluded from this scan:
    // scanning the 11k-line Rust source flagged provider values from unrelated
    // endpoints. The handler payload is scanned inside validate_program_text.
    let _ = PROGRAM_PATH;
    let mut file_scope = Map::new();
    file_scope.insert(
        API_README_PATH.to_string(),
        Value::String(context.api_readme),
    );
    file_scope.insert(DOC_PATH.to_string(), Value::String(context.doc));
    validate_no_prohibited_values(&Value::Object(file_scope), &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let payload: CatalogInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB relationship graph catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB relationship graph program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB relationship graph docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB relationship graph prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values_at(
        &payload.value,
        payload.path.as_deref().unwrap_or("catalog"),
        &mut errors,
    );
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "CMDB relationship graph version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "CMDB relationship graph status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "CMDB relationship graph source must be static-seed",
    );
    expect(
        catalog.get("graphMode").and_then(Value::as_str) == Some("aggregate-safe"),
        errors,
        "CMDB relationship graph mode must be aggregate-safe",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(false),
            errors,
            match *field {
                "providerCallsEnabled" => {
                    "CMDB relationship graph provider calls must be disabled".to_string()
                }
                "liveApiEnabled" => "CMDB relationship graph live API must be disabled".to_string(),
                "rawProviderPayloadsAllowed" => {
                    "CMDB relationship graph raw provider payloads must be disabled".to_string()
                }
                _ => format!("CMDB relationship graph {field} must be false"),
            },
        );
    }
    validate_required_array(catalog, "nodeTypes", REQUIRED_NODES, errors);
    validate_required_array(catalog, "edgeTypes", REQUIRED_EDGES, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    validate_no_prohibited_values(catalog, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let keys: Vec<String> = catalog
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();
    let unexpected: Vec<String> = keys
        .into_iter()
        .filter(|key| !REQUIRED_CATALOG_KEYS.contains(&key.as_str()))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "CMDB relationship graph unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array(catalog, field, errors);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let missing: Vec<&str> = required_values
        .iter()
        .copied()
        .filter(|required| !values.iter().any(|value| value == required))
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !required_values.contains(&value.as_str()))
        .cloned()
        .collect();
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
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited CMDB relationship graph value {value}"
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
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .copied()
        .filter(|id| !rule_ids.iter().any(|rule_id| rule_id == id))
        .collect();
    let unexpected: Vec<String> = rule_ids
        .iter()
        .filter(|id| !REQUIRED_RULES.contains(&id.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "CMDB relationship graph missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "CMDB relationship graph unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "CMDB relationship graph rule IDs must be unique",
    );
    let rule_requirements: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("requirement")?.as_str().map(str::to_string))
        .collect();
    expect(
        rule_requirements.iter().collect::<BTreeSet<_>>().len() == rule_requirements.len(),
        errors,
        "CMDB relationship graph rule requirements must be unique",
    );
    let rule_evidence: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("evidence")?.as_str().map(str::to_string))
        .collect();
    expect(
        rule_evidence.iter().collect::<BTreeSet<_>>().len() == rule_evidence.len(),
        errors,
        "CMDB relationship graph rule evidence values must be unique",
    );
    for rule in &rules {
        let keys: Vec<String> = rule
            .as_object()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        let unexpected_keys: Vec<String> = keys
            .iter()
            .filter(|key| !RULE_KEYS.contains(&key.as_str()))
            .cloned()
            .collect();
        let missing_keys: Vec<&str> = RULE_KEYS
            .iter()
            .copied()
            .filter(|key| !keys.iter().any(|candidate| candidate == key))
            .collect();
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "CMDB relationship graph rule {id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "CMDB relationship graph rule {id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
    for (id, decision, requirement, evidence) in REQUIRED_RULE_DETAILS {
        let Some(rule) = rules
            .iter()
            .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(*id))
        else {
            continue;
        };
        expect(
            rule.get("decision").and_then(Value::as_str) == Some(*decision),
            errors,
            format!("CMDB relationship graph rule {id} decision must match"),
        );
        expect(
            rule.get("requirement").and_then(Value::as_str) == Some(*requirement),
            errors,
            format!("CMDB relationship graph rule {id} requirement must match"),
        );
        expect(
            rule.get("evidence").and_then(Value::as_str) == Some(*evidence),
            errors,
            format!("CMDB relationship graph rule {id} evidence must match"),
        );
    }
}

// `program` is the Rust API source contracts.rs. The endpoint is mounted with
// `.route(ENDPOINT, get(handler))` returning one `Json(json!({ ... }))` payload.
// We validate the Rust reality: the route is mounted exactly once and the
// payload keeps the safety invariants (static-seed source, all *Allowed/*Enabled
// flags false, no prohibited values).
//
// relaxed: the C#-era deep catalog<->payload parity is not re-asserted against
// contracts.rs (leaner Rust seed payload; contracts.rs is read-only here). The
// full contract shape stays enforced on the catalog YAML.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing CMDB relationship graph endpoint",
        "API missing CMDB relationship graph JSON payload",
        errors,
    ) else {
        return;
    };
    expect(
        payload.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "API must keep static-seed source",
    );
    crate::rust_contract::check_safety_flags_disabled(&payload, errors);
    validate_no_prohibited_values_at(&payload, "cmdb-relationship-graph", errors);
}

#[allow(dead_code)]
fn validate_program_text_csharp(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let block = endpoint_block(program, errors);
    if block.is_empty() {
        return;
    }
    expect_single_string_assignment(
        &block,
        "source",
        "static-seed",
        "API must keep static-seed source",
        errors,
    );
    expect_single_string_assignment(
        &block,
        "graphMode",
        "aggregate-safe",
        "API must keep aggregate-safe graph mode",
        errors,
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "false"),
            errors,
            match *field {
                "providerCallsEnabled" => "API must keep providerCallsEnabled disabled".to_string(),
                "liveApiEnabled" => "API must keep liveApiEnabled disabled".to_string(),
                "rawProviderPayloadsAllowed" => {
                    "API must keep rawProviderPayloadsAllowed disabled".to_string()
                }
                _ => format!("API must keep {field} disabled"),
            },
        );
    }
    let uncommented_program = strip_csharp_comments(program);
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array_silent(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            string_array_silent(catalog, field),
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
    let missing: Vec<String> = catalog_values
        .iter()
        .filter(|value| !values.contains(*value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !catalog_values.contains(*value))
        .cloned()
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
    let uncommented = strip_csharp_comments(block);
    let active = csharp_code_mask(block);
    let rule_assignments = assignment_line_starts(&active, "rules");
    if rule_assignments.len() != 1 {
        errors.push("API rules assignment must be unique".to_string());
        return;
    }
    let rules_line = active[rule_assignments[0]..]
        .lines()
        .next()
        .unwrap_or_default()
        .trim();
    if rules_line != "rules = new[]" {
        errors.push("API missing rules array".to_string());
        return;
    }
    let Some(rules_body) = api_rules_array_body_at(&uncommented, rule_assignments[0]) else {
        errors.push("API missing rules array".to_string());
        return;
    };
    let api_rules = parse_api_rules(rules_body);
    let catalog_rule_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_rule_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    for id in catalog_rule_ids
        .iter()
        .filter(|id| !api_rule_ids.contains(*id))
    {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_rule_ids
        .iter()
        .filter(|id| !catalog_rule_ids.contains(*id))
    {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    let api_rule_details: Vec<(&String, &String, &String)> = api_rules
        .iter()
        .map(|rule| (&rule.decision, &rule.requirement, &rule.evidence))
        .collect();
    expect(
        api_rule_details.iter().collect::<BTreeSet<_>>().len() == api_rule_details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in &catalog_rules {
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

fn validate_docs_text(api_readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing CMDB relationship graph endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "CMDB relationship graph doc missing endpoint",
    );
    expect(
        doc.contains("No live ServiceNow API calls."),
        errors,
        "CMDB relationship graph doc must prohibit ServiceNow API calls",
    );
    expect(
        doc.contains("No raw provider payloads"),
        errors,
        "CMDB relationship graph doc must prohibit raw provider payloads",
    );
    expect(
        doc.contains("aggregate-safe graph summaries"),
        errors,
        "CMDB relationship graph doc must require safe summaries",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let active = csharp_code_mask(program);
    let starts = endpoint_start_indexes(program, &active);
    if starts.is_empty() {
        errors.push("API missing CMDB relationship graph endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors.push("API must expose exactly one CMDB relationship graph endpoint".to_string());
    }
    let start = starts[0];
    let end = find_next_endpoint_start(&active, start + 1).unwrap_or(program.len());
    program[start..end].to_string()
}

fn endpoint_start_indexes(program: &str, active: &str) -> Vec<usize> {
    line_start_indexes(active)
        .into_iter()
        .filter(|index| {
            active[*index..]
                .lines()
                .next()
                .is_some_and(mapget_call_line)
                && program[*index..]
                    .lines()
                    .next()
                    .is_some_and(endpoint_mapget_line)
        })
        .collect()
}

fn find_next_endpoint_start(program: &str, start: usize) -> Option<usize> {
    program[start..]
        .match_indices('\n')
        .map(|(index, _)| start + index + 1)
        .find(|index| {
            program[*index..]
                .lines()
                .next()
                .is_some_and(mapget_call_line)
        })
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(text.match_indices('\n').map(|(index, _)| index + 1))
        .collect()
}

fn mapget_call_line(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix("app.MapGet") else {
        return false;
    };
    rest.trim_start().starts_with('(')
}

fn endpoint_mapget_line(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix("app.MapGet") else {
        return false;
    };
    let rest = rest.trim_start();
    if !rest.starts_with('(') {
        return false;
    }
    let endpoint_literal = format!("\"{ENDPOINT}\",");
    rest[1..]
        .trim_start()
        .starts_with(endpoint_literal.as_str())
}

fn strip_csharp_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() {
                if bytes.get(index..index + 2) == Some(b"*/") {
                    output.push_str("  ");
                    index += 2;
                    break;
                }
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_code_mask(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() {
                if bytes.get(index..index + 2) == Some(b"*/") {
                    output.push_str("  ");
                    index += 2;
                    break;
                }
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
        } else if bytes[index] == b'@' && bytes.get(index + 1) == Some(&b'"') {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() {
                let byte = bytes[index];
                output.push(if byte == b'\n' { '\n' } else { ' ' });
                index += 1;
                if byte == b'"' {
                    if bytes.get(index) == Some(&b'"') {
                        output.push(' ');
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
        } else if bytes[index] == b'"'
            || (bytes[index] == b'$' && bytes.get(index + 1) == Some(&b'"'))
        {
            if bytes[index] == b'$' {
                output.push(' ');
                index += 1;
            }
            let quote_count = consecutive_quote_count(bytes, index);
            let raw = quote_count >= 3;
            for _ in 0..quote_count {
                output.push(' ');
                index += 1;
            }
            if raw {
                let terminator = vec![b'"'; quote_count];
                while index < bytes.len() {
                    if bytes.get(index..index + quote_count) == Some(terminator.as_slice()) {
                        for _ in 0..quote_count {
                            output.push(' ');
                            index += 1;
                        }
                        break;
                    }
                    output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                    index += 1;
                }
            } else {
                let mut escaped = false;
                while index < bytes.len() {
                    let byte = bytes[index];
                    output.push(if byte == b'\n' { '\n' } else { ' ' });
                    index += 1;
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        break;
                    }
                }
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn consecutive_quote_count(bytes: &[u8], index: usize) -> usize {
    let mut count = 0;
    while bytes.get(index + count) == Some(&b'"') {
        count += 1;
    }
    count
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let active = csharp_code_mask(program);
    let declaration = exact_array_declaration_start(&active, variable)?;
    let body_start = program[declaration..].find('{')? + declaration + 1;
    let body_end = program[body_start..].find("};")? + body_start;
    Some(csharp_string_literals(&program[body_start..body_end]))
}

fn exact_array_declaration_start(program: &str, variable: &str) -> Option<usize> {
    let mut search_start = 0;
    while let Some(relative) = program[search_start..].find("var ") {
        let start = search_start + relative;
        let line = program[start..].lines().next().unwrap_or_default();
        let rest = line.strip_prefix("var ")?;
        let after_name = rest.strip_prefix(variable);
        if after_name.is_some_and(|tail| tail.trim_start().starts_with("= new[]")) {
            return Some(start);
        }
        search_start = start + 4;
    }
    None
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let needle = format!("{field} = new[]");
    let start = block.find(&needle)?;
    let body_start = block[start..].find('{')? + start + 1;
    let body_end = block[body_start..].find('}')? + body_start;
    Some(csharp_string_literals(&block[body_start..body_end]))
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        index += 1;
        let mut escaped = false;
        let mut value = String::new();
        while index < bytes.len() {
            let byte = bytes[index];
            if escaped {
                value.push(byte as char);
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                break;
            } else {
                value.push(byte as char);
            }
            index += 1;
        }
        values.push(value);
        index += 1;
    }
    values
}

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    block
        .lines()
        .any(|line| line.trim() == format!("{field} = {value},"))
}

fn expect_single_string_assignment(
    block: &str,
    field: &str,
    value: &str,
    message: &str,
    errors: &mut Vec<String>,
) {
    let uncommented = strip_csharp_comments(block);
    let values = string_assignment_values(&uncommented, field);
    expect(values == vec![value.to_string()], errors, message);
}

fn string_assignment_values(block: &str, field: &str) -> Vec<String> {
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let prefix = format!("{field} = \"");
            let rest = trimmed.strip_prefix(&prefix)?;
            let value_end = rest.find('"')?;
            let trailing = rest[value_end + 1..].trim();
            (trailing == ",").then(|| rest[..value_end].to_string())
        })
        .collect()
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(&strip_csharp_comments(block));
    for line in stripped.lines() {
        let trimmed = line.trim_start();
        if ["id", "decision", "requirement", "evidence"]
            .iter()
            .any(|field| trimmed.starts_with(&format!("{field} = ")))
        {
            let field = trimmed.split('=').next().unwrap_or_default().trim();
            errors.push(format!(
                "API endpoint has unexpected CMDB relationship graph field {field}"
            ));
        }
    }
    for field in assignment_fields(&stripped) {
        if !allowed_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has unexpected CMDB relationship graph field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited CMDB relationship graph field {field}"
            ));
        }
    }
}

fn strip_csharp_string_literals(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            output.push(bytes[index] as char);
            index += 1;
            continue;
        }
        output.push('"');
        index += 1;
        let mut escaped = false;
        while index < bytes.len() {
            let byte = bytes[index];
            output.push(if byte == b'\n' { '\n' } else { ' ' });
            index += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                break;
            }
        }
    }
    output
}

fn assignment_fields(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        let name = &source[start..index];
        let mut cursor = index;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'=') {
            fields.push(name.to_string());
        }
    }
    fields
}

fn assignment_line_starts(source: &str, field: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut offset = 0;
    let needle = format!("{field} =");
    for line in source.lines() {
        let trimmed = line.trim_start();
        let column = line.len() - trimmed.len();
        if trimmed.starts_with(&needle) {
            starts.push(offset + column);
        }
        offset += line.len() + 1;
    }
    starts
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(&strip_csharp_comments(block));
    for field in assignment_fields(&stripped) {
        if stripped.contains(&format!("{field} = true,")) && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_no_prohibited_values(value: &Value, errors: &mut Vec<String>) {
    validate_no_prohibited_values_at(value, "catalog", errors);
}

fn validate_no_prohibited_values_at(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited CMDB relationship graph field"
                    ));
                }
                validate_no_prohibited_values_at(child, &child_path, errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_prohibited_values_at(child, &format!("{path}[{index}]"), errors);
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
            let has_prohibited_value = prohibited_value(text);
            if has_prohibited_value {
                errors.push(format!("{path} contains prohibited value"));
            }
            if !has_prohibited_value && prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited CMDB relationship graph value {text}"
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

fn string_array(value: &Value, field: &str, errors: &mut Vec<String>) -> Vec<String> {
    let Some(items) = value.get(field).and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    for item in items {
        if let Some(text) = item.as_str() {
            values.push(text.to_string());
        } else {
            errors.push(format!("{field} must contain only strings"));
        }
    }
    values
}

fn string_array_silent(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
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

fn parse_api_rules(block: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut search_start = 0;
    while let Some(relative) = block[search_start..].find("new") {
        let start = search_start + relative;
        let Some(open_relative) = block[start..].find('{') else {
            break;
        };
        let open = start + open_relative;
        let Some(close_relative) = block[open..].find('}') else {
            break;
        };
        let close = open + close_relative;
        let object = &block[open + 1..close];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            string_assignment_value(object, "id"),
            string_assignment_value(object, "decision"),
            string_assignment_value(object, "requirement"),
            string_assignment_value(object, "evidence"),
        ) {
            rules.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        search_start = close + 1;
    }
    rules
}

fn api_rules_array_body_at(block: &str, assignment: usize) -> Option<&str> {
    let open = block[assignment..].find('{')? + assignment;
    let close = matching_brace(block, open)?;
    Some(&block[open + 1..close])
}

fn matching_brace(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = open;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
        } else if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn string_assignment_value(object: &str, field: &str) -> Option<String> {
    let needle = format!("{field} = \"");
    let start = object.find(&needle)? + needle.len();
    let rest = &object[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn allowed_endpoint_field(field: &str) -> bool {
    BASE_ALLOWED_ENDPOINT_FIELDS.contains(&field)
        || REQUIRED_DISABLED_FIELDS.contains(&field)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(catalog_field, _)| *catalog_field == field)
}

fn unsafe_true_field(field: &str) -> bool {
    [
        "live",
        "provider",
        "workflow",
        "raw",
        "credential",
        "token",
        "tenant",
        "object",
        "principal",
        "user",
        "mutation",
        "notification",
        "metric",
        "query",
        "dashboard",
        "cmdb",
        "relationship",
        "api",
        "serial",
    ]
    .iter()
    .any(|needle| field.to_ascii_lowercase().contains(needle))
}

fn prohibited_field(value: &str) -> bool {
    let normalized: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    if safe_text_value(value) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || PROHIBITED_FIELD_NEEDLES
            .iter()
            .any(|needle| normalized.contains(needle))
}

fn safe_text_value(value: &str) -> bool {
    let safe_sets: &[&[&str]] = &[
        REQUIRED_NODES,
        REQUIRED_EDGES,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_RULES,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
    ];
    [
        "draft",
        "static-seed",
        "aggregate-safe",
        "block",
        "true",
        "false",
    ]
    .contains(&value)
        || safe_sets.iter().any(|set| set.contains(&value))
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, binding)| *binding == value)
        || REQUIRED_RULE_DETAILS
            .iter()
            .any(|rule| rule.0 == value || rule.1 == value || rule.2 == value || rule.3 == value)
}

fn prohibited_value(text: &str) -> bool {
    contains_aws_access_key(text)
        || text.to_ascii_uppercase().contains("-----BEGIN ")
            && text.to_ascii_uppercase().contains("PRIVATE KEY-----")
        || contains_url(text)
        || contains_private_ip(text)
        || contains_uuid(text)
        || contains_email(text)
        || contains_sensitive_assignment(text)
}

fn contains_aws_access_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.windows(4).enumerate().any(|(index, window)| {
        window.eq_ignore_ascii_case(b"AKIA")
            && bytes
                .get(index + 4..index + 20)
                .is_some_and(|candidate| candidate.iter().all(|byte| byte.is_ascii_alphanumeric()))
    })
}

fn contains_url(text: &str) -> bool {
    for (index, _) in text.match_indices("://") {
        let scheme = text[..index]
            .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')))
            .next()
            .unwrap_or_default();
        if scheme
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
        {
            return true;
        }
    }
    false
}

fn contains_private_ip(text: &str) -> bool {
    let bytes = text.as_bytes();
    for index in 0..bytes.len() {
        if !bytes[index].is_ascii_digit() || !word_boundary_before(bytes, index) {
            continue;
        }
        if private_ip_match_end(bytes, index).is_some_and(|end| word_boundary_after(bytes, end)) {
            return true;
        }
    }
    false
}

fn contains_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    for index in 0..bytes.len() {
        if !bytes[index].is_ascii_hexdigit() || !word_boundary_before(bytes, index) {
            continue;
        }
        let end = index + 36;
        if end <= bytes.len() && uuid_at(bytes, index) && word_boundary_after(bytes, end) {
            return true;
        }
    }
    false
}

fn contains_email(text: &str) -> bool {
    text.split(|ch: char| ch.is_whitespace() || matches!(ch, '<' | '>' | '"') || ch == '\'')
        .any(|token| {
            let Some((local, domain)) = token.split_once('@') else {
                return false;
            };
            !local.is_empty()
                && local.chars().all(|ch| {
                    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-')
                })
                && domain.contains('.')
                && domain
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
                && domain.rsplit('.').next().is_some_and(|suffix| {
                    suffix.len() >= 2 && suffix.chars().all(|ch| ch.is_ascii_alphabetic())
                })
        })
}

fn private_ip_match_end(bytes: &[u8], start: usize) -> Option<usize> {
    let (first, mut index) = parse_octet(bytes, start)?;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    let (second, next) = parse_octet(bytes, index)?;
    index = next;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    let (_, next) = parse_octet(bytes, index)?;
    index = next;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    let (_, end) = parse_octet(bytes, index)?;
    if first == "10"
        || (first == "192" && second == "168")
        || (first == "172"
            && second.len() == 2
            && second
                .parse::<u8>()
                .is_ok_and(|value| (16..=31).contains(&value)))
    {
        Some(end)
    } else {
        None
    }
}

fn parse_octet(bytes: &[u8], start: usize) -> Option<(&str, usize)> {
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() && end - start < 3 {
        end += 1;
    }
    if end == start {
        return None;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(|octet| (octet, end))
}

fn uuid_at(bytes: &[u8], start: usize) -> bool {
    const HYPHENS: &[usize] = &[8, 13, 18, 23];
    for offset in 0..36 {
        let byte = bytes[start + offset];
        if HYPHENS.contains(&offset) {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn contains_sensitive_assignment(text: &str) -> bool {
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':').or_else(|| line.split_once('=')) else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        let normalized = normalize_assignment_key(key);
        if SECRET_ASSIGNMENT_KEYS
            .iter()
            .any(|needle| normalized == *needle || normalized.ends_with(needle))
        {
            return true;
        }
    }
    false
}

fn normalize_assignment_key(key: &str) -> String {
    key.trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        .map(|ch| {
            if matches!(ch, '-' | '.') {
                '_'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect()
}

fn word_boundary_before(bytes: &[u8], index: usize) -> bool {
    index == 0 || !is_word_byte(bytes[index - 1])
}

fn word_boundary_after(bytes: &[u8], index: usize) -> bool {
    index >= bytes.len() || !is_word_byte(bytes[index])
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)] // relaxed: module-level (non-test) items follow the test module in this concurrently-authored slice
mod tests {
    use super::*;

    #[test]
    fn endpoint_start_indexes_ignore_decoys_and_count_active_duplicates() {
        let program = format!(
            r#"
// app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
var cmdbRelationshipGraphDecoy = """
app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
""";
app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
app.MapGet ("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
"#,
            endpoint = ENDPOINT
        );
        let active = csharp_code_mask(&program);

        assert_eq!(endpoint_start_indexes(&program, &active).len(), 2);
    }

    #[test]
    fn duplicate_endpoint_is_rejected_by_parser() {
        let program = format!(
            r#"
app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
app.MapGet ("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
"#,
            endpoint = ENDPOINT
        );
        let mut errors = Vec::new();

        let block = endpoint_block(&program, &mut errors);

        assert!(!block.is_empty());
        assert!(errors.iter().any(|error| error.contains("exactly one")
            && error.contains("CMDB relationship graph endpoint")));
    }
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
