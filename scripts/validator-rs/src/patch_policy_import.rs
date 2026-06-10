use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/patch-policy-import-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/patch-policy-import.md";
const ENDPOINT: &str = "/api/patching/policy-import-contract";

const REQUIRED_FIELDS: &[&str] = &[
    "platformCiKey",
    "patchGroup",
    "maintenanceWindow",
    "rebootPolicy",
    "blackoutDates",
    "owner",
    "supportGroup",
    "site",
    "environment",
    "application",
    "criticality",
    "dependencyGroup",
];
const REQUIRED_DECISIONS: &[&str] = &[
    "accept",
    "reject",
    "review",
    "normalize",
    "export-exception",
];
const REQUIRED_INPUTS: &[&str] = &[
    "importBatch",
    "headerMapping",
    "platformCiKey",
    "patchGroup",
    "maintenanceWindow",
    "rebootPolicy",
    "owner",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "cmdb-file-contract-validated",
    "header-mapping-complete",
    "ci-identity-known",
    "maintenance-window-known",
    "reboot-policy-known",
    "owner-known",
    "evidence-redacted",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "live-api-disabled",
    "missing-ci-identity",
    "missing-patch-group",
    "missing-maintenance-window",
    "ambiguous-reboot-policy",
    "blackout-window-conflict",
    "owner-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "File hash",
    "Header mapping",
    "Validation result",
    "Accepted/rejected policy rows",
    "Maintenance window summary",
    "Reboot policy summary",
    "Wave seed summary",
    "Evidence references",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const TOP_LEVEL_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "integrationMode",
    "providerCallsEnabled",
    "liveApiEnabled",
    "normalizedFields",
    "decisions",
    "requiredInputs",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "integrationMode",
    "providerCallsEnabled",
    "liveApiEnabled",
    "normalizedFields",
    "decisions",
    "requiredInputs",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("normalizedFields", "patchPolicyImportFields"),
    ("decisions", "patchPolicyImportDecisions"),
    ("requiredGuards", "patchPolicyImportRequiredGuards"),
    ("blockedReasons", "patchPolicyImportBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-servicenow-api",
        decision: "block",
        requirement:
            "Patch policy import uses file exports only and never calls live ServiceNow API.",
        evidence: "Validation result",
    },
    RuleDetail {
        id: "maintenance-window-required",
        decision: "block",
        requirement: "Accepted policy rows must include a normalized maintenance window.",
        evidence: "Maintenance window summary",
    },
    RuleDetail {
        id: "reboot-policy-required",
        decision: "block",
        requirement: "Reboot policy must be known before rows can seed patch waves.",
        evidence: "Reboot policy summary",
    },
    RuleDetail {
        id: "accepted-rows-seed-patch-waves",
        decision: "block",
        requirement: "Only accepted and normalized rows can seed patch wave planning.",
        evidence: "Wave seed summary",
    },
];

#[derive(Debug, Deserialize)]
struct PatchPolicyContext {
    catalog: Value,
    program: String,
    api_readme: String,
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
    let context: PatchPolicyContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid patch policy import context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_value(
        &serde_json::json!({
            CATALOG_PATH: context.catalog,
            PROGRAM_PATH: context.program,
            API_README_PATH: context.api_readme,
            DOC_PATH: context.doc,
        }),
        "patch-policy-import",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid patch policy import catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid patch policy import program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid patch policy import docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid patch policy import prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("patch policy import catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_field_names(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "patch policy import version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "patch policy import status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "patch policy import source must be static-seed",
    );
    expect(
        string_value(catalog, "integrationMode") == Some("file-based"),
        errors,
        "patch policy import mode must be file-based",
    );
    expect(
        bool_value(catalog, "providerCallsEnabled") == Some(false),
        errors,
        "patch policy import provider calls must be disabled",
    );
    expect(
        bool_value(catalog, "liveApiEnabled") == Some(false),
        errors,
        "patch policy import live API must be disabled",
    );
    validate_required_array(catalog, "normalizedFields", REQUIRED_FIELDS, errors);
    validate_required_array(catalog, "decisions", REQUIRED_DECISIONS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_catalog_rules(catalog, errors);
}

fn validate_catalog_field_names(value: &Value, errors: &mut Vec<String>) {
    validate_catalog_field_names_at(value, "catalog", errors);
}

fn validate_catalog_field_names_at(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                let top_level = path == "catalog";
                let allowed_top_level = top_level && TOP_LEVEL_FIELDS.contains(&key.as_str());
                if top_level && !allowed_top_level {
                    errors.push(format!(
                        "patch policy import catalog has unexpected field {key}"
                    ));
                }
                if rule_path(path) && !RULE_FIELDS.contains(&key.as_str()) {
                    errors.push(format!(
                        "{child_path} is unexpected patch policy import rule field"
                    ));
                }
                if !allowed_top_level && prohibited_field(key) {
                    errors.push(format!("{child_path} uses unsafe patch policy import key"));
                }
                if child == &Value::Bool(true) && unsafe_true_field(key) {
                    errors.push(format!("{child_path} is unsafe true flag"));
                }
                validate_catalog_field_names_at(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_catalog_field_names_at(child, &format!("{path}[{index}]"), errors);
            }
        }
        _ => {}
    }
}

fn rule_path(path: &str) -> bool {
    path.starts_with("catalog.rules[") && path.ends_with(']')
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
}

fn validate_catalog_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = rules_from_catalog(catalog);
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
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "patch policy import rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "patch policy import rule details must be unique",
    );
    expect(
        missing.is_empty(),
        errors,
        format!("patch policy import missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "patch policy import unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    for required in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == required.id) else {
            continue;
        };
        expect(
            rule.decision == required.decision,
            errors,
            format!(
                "patch policy import rule {} decision must match",
                required.id
            ),
        );
        expect(
            rule.requirement == required.requirement,
            errors,
            format!(
                "patch policy import rule {} requirement must match",
                required.id
            ),
        );
        expect(
            rule.evidence == required.evidence,
            errors,
            format!(
                "patch policy import rule {} evidence must match",
                required.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let endpoint = endpoint_block(program, errors);
    let block = endpoint_payload_block(&endpoint, errors);
    if block.is_empty() {
        return;
    }
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "integrationMode", "file-based"),
        errors,
        "API must keep file-based integration mode",
    );
    expect(
        exact_assignment(&block, "providerCallsEnabled", "false"),
        errors,
        "API must keep providerCallsEnabled disabled",
    );
    expect(
        exact_assignment(&block, "liveApiEnabled", "false"),
        errors,
        "API must keep liveApiEnabled disabled",
    );
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable, errors);
        validate_api_array(field, values, string_array_like(catalog, field), errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let mut array_errors = Vec::new();
        let values = endpoint_inline_array_values(&block, field, &mut array_errors);
        errors.extend(array_errors);
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
    let Some(rules_body) = endpoint_rules_array_body(block) else {
        errors.push("API rules must be a single top-level new[] array".to_string());
        return;
    };
    let api_rules = api_rule_objects(&rules_body, errors);
    let catalog_rules = rules_from_catalog(catalog);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_ids.difference(&api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.difference(&catalog_ids) {
        errors.push(format!("API has unexpected rule {id}"));
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

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let fields: Vec<String> = top_level_field_assignments(block)
        .into_iter()
        .map(|(field, _)| field)
        .collect();
    for field in fields
        .iter()
        .filter(|field| !ENDPOINT_FIELDS.contains(&field.as_str()))
    {
        errors.push(format!("API endpoint has unexpected field {field}"));
    }
    expect(
        fields.iter().collect::<BTreeSet<_>>().len() == fields.len(),
        errors,
        "API endpoint fields must be declared once",
    );
    for field in fields {
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint field {field} uses unsafe patch policy import identifier"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in top_level_field_assignments(block) {
        if value.trim() == "true" && unsafe_true_field(&field) {
            errors.push(format!("API endpoint field {field} is unsafe true flag"));
        }
    }
}

fn validate_docs_text(api_readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing patch policy import endpoint",
    );
    expect(
        api_readme.contains("Static file-based patch policy import contract"),
        errors,
        "API README must describe static file-based patch policy import",
    );
    expect(
        api_readme.contains("live ServiceNow API disabled"),
        errors,
        "API README must keep live ServiceNow API disabled",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "patch policy import doc missing endpoint",
    );
    expect(
        doc.contains("file-based patch policy import contract"),
        errors,
        "patch policy import doc must describe file-based contract",
    );
    expect(
        doc.contains("No live ServiceNow API calls."),
        errors,
        "patch policy import doc must prohibit ServiceNow API calls",
    );
    expect(
        doc.contains("No raw export rows"),
        errors,
        "patch policy import doc must prohibit raw rows",
    );
    expect(
        doc.contains("normalized policy summaries"),
        errors,
        "patch policy import doc must require safe summaries",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let uncommented_program = strip_csharp_comments(program);
    let start_indexes = endpoint_start_indexes(program);
    if start_indexes.is_empty() {
        errors.push("API missing patch policy import endpoint".to_string());
        return String::new();
    }
    if start_indexes.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let start_index = start_indexes[0];
    let next_endpoint_index = mapget_start_indexes(program)
        .into_iter()
        .find(|index| *index > start_index)
        .unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_endpoint_index].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    mapget_start_indexes(program)
        .into_iter()
        .filter(|start_index| {
            mapget_route_literal(program, *start_index).as_deref() == Some(ENDPOINT)
        })
        .collect()
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let json_indexes = results_json_indexes(endpoint);
    if json_indexes.is_empty() {
        errors.push("API missing patch policy import JSON payload".to_string());
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push("API must declare exactly one patch policy import JSON payload".to_string());
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start_relative) = endpoint[json_index..].find('{') else {
        errors.push("API patch policy import JSON payload must be a single object".to_string());
        return String::new();
    };
    let object_start = json_index + object_start_relative;
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API patch policy import JSON payload must be a single object".to_string());
        return String::new();
    };
    if endpoint[object_end + 1..].trim() != "));" {
        errors.push(
            "API patch policy import JSON payload must be static anonymous object with no extra JSON arguments"
                .to_string(),
        );
        return String::new();
    }
    endpoint[object_start..=object_end].to_string()
}

fn results_json_indexes(endpoint: &str) -> Vec<usize> {
    let masked = csharp_code_mask(endpoint);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(index) = find_results_json_new_object(&masked, offset) {
        if paren_depth_at(&masked, index) == 1 && brace_depth_at(&masked, index) == 0 {
            indexes.push(index);
        }
        offset = index + "Results".len();
    }
    indexes
}

fn find_results_json_new_object(text: &str, offset: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = offset;
    while let Some(relative) = text[index..].find("Results") {
        let start = index + relative;
        let mut cursor = start + "Results".len();
        cursor = skip_whitespace_bytes(bytes, cursor);
        if bytes.get(cursor) != Some(&b'.') {
            index = cursor;
            continue;
        }
        cursor = skip_whitespace_bytes(bytes, cursor + 1);
        if !starts_with_at(bytes, cursor, b"Json") {
            index = cursor;
            continue;
        }
        cursor = skip_whitespace_bytes(bytes, cursor + "Json".len());
        if bytes.get(cursor) != Some(&b'(') {
            index = cursor;
            continue;
        }
        cursor = skip_whitespace_bytes(bytes, cursor + 1);
        if starts_with_at(bytes, cursor, b"new") {
            cursor = skip_whitespace_bytes(bytes, cursor + "new".len());
            if bytes.get(cursor) == Some(&b'{') {
                return Some(start);
            }
        }
        index = cursor;
    }
    None
}

fn exact_string_assignment(block: &str, field: &str, expected: &str) -> bool {
    let values: Vec<String> = top_level_field_assignments(block)
        .into_iter()
        .filter(|(name, _)| name == field)
        .map(|(_, value)| value.trim().to_string())
        .collect();
    values.len() == 1 && values[0] == format!("\"{expected}\"")
}

fn exact_assignment(block: &str, field: &str, expected: &str) -> bool {
    let values: Vec<String> = top_level_field_assignments(block)
        .into_iter()
        .filter(|(name, _)| name == field)
        .map(|(_, value)| value.trim().to_string())
        .collect();
    values.len() == 1 && values[0] == expected
}

fn top_level_field_assignments(block: &str) -> Vec<(String, String)> {
    let masked = csharp_code_mask(block);
    let mut assignments = Vec::new();
    let mut offset = 0;
    while let Some((field, equals_index, end_index)) = next_assignment(&masked, offset) {
        if brace_depth_at(&masked, equals_index) == 1 {
            let value_start = end_index;
            let value_end = top_level_value_end(&masked, value_start);
            assignments.push((field, block[value_start..value_end].to_string()));
        }
        offset = end_index;
    }
    assignments
}

fn next_assignment(text: &str, offset: usize) -> Option<(String, usize, usize)> {
    let bytes = text.as_bytes();
    let mut cursor = offset;
    while cursor < bytes.len() {
        if !is_identifier_start(bytes[cursor]) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        while cursor < bytes.len() && is_identifier_continue(bytes[cursor]) {
            cursor += 1;
        }
        let field = &text[start..cursor];
        let after_field = skip_whitespace_bytes(bytes, cursor);
        if bytes.get(after_field) == Some(&b'=') {
            return Some((field.to_string(), after_field, after_field + 1));
        }
        cursor = after_field.saturating_add(1);
    }
    None
}

fn top_level_value_end(masked: &str, value_start: usize) -> usize {
    let bytes = masked.as_bytes();
    let mut index = value_start;
    while index < bytes.len() {
        if bytes[index] == b','
            && brace_depth_at(masked, index) == 1
            && bracket_depth_at(masked, index) == 0
            && paren_depth_at(masked, index) == 0
        {
            return index;
        }
        index += 1;
    }
    masked.len()
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let marker = format!("var {variable}");
    let Some(var_index) = program.find(&marker) else {
        errors.push(format!("API missing {variable} array"));
        return None;
    };
    let tail = &program[var_index + marker.len()..];
    let Some(equals_relative) = tail.find('=') else {
        errors.push(format!("API {variable} array is malformed"));
        return None;
    };
    let assignment_tail = &tail[equals_relative + 1..];
    let Some(body_start_relative) = assignment_tail.find('{') else {
        errors.push(format!("API {variable} array is malformed"));
        return None;
    };
    let body_start = var_index + marker.len() + equals_relative + 1 + body_start_relative;
    let Some(body_end) = matching_brace_index(program, body_start) else {
        errors.push(format!("API {variable} array is malformed"));
        return None;
    };
    parse_string_array_body(
        &program[body_start + 1..body_end],
        &format!("API {variable}"),
        errors,
    )
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let masked = csharp_code_mask(block);
    let pattern = format!("{field} = new[]");
    let start = masked.find(&pattern)?;
    if brace_depth_at(&masked, start) != 1 {
        return None;
    }
    let body_start = block[start..].find('{')? + start;
    let body_end = matching_brace_index(block, body_start)?;
    parse_string_array_body(
        &block[body_start + 1..body_end],
        &format!("API {field}"),
        errors,
    )
}

fn parse_string_array_body(
    body: &str,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let values = csharp_string_literals(body);
    let masked = strip_csharp_string_literals(body);
    if !masked.replace([',', ' ', '\n', '\t', '\r'], "").is_empty() {
        errors.push(format!("{label} array contains non-static values"));
    }
    Some(values)
}

fn endpoint_rules_array_body(block: &str) -> Option<String> {
    let masked = csharp_code_mask(block);
    let pattern = "rules = new[]";
    let start = masked.find(pattern)?;
    if brace_depth_at(&masked, start) != 1 {
        return None;
    }
    let body_start = block[start..].find('{')? + start;
    let body_end = matching_brace_index(block, body_start)?;
    Some(block[body_start + 1..body_end].to_string())
}

fn api_rule_objects(rules_body: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let masked = csharp_code_mask(rules_body);
    let mut object_ranges: Vec<(usize, usize)> = Vec::new();
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("new") {
        let start = offset + relative;
        let after_new = skip_whitespace_bytes(masked.as_bytes(), start + "new".len());
        if masked.as_bytes().get(after_new) != Some(&b'{') {
            offset = after_new.saturating_add(1);
            continue;
        }
        if brace_depth_at(&masked, start) == 0 {
            let Some(object_end) = matching_brace_index(&masked, after_new) else {
                errors.push("API rules contain malformed rule object".to_string());
                return rules;
            };
            let object = &rules_body[start..=object_end];
            object_ranges.push((start, object_end));
            if let Some(rule) = parse_api_rule_object(object, errors) {
                rules.push(rule);
            }
            offset = object_end + 1;
        } else {
            offset = after_new.saturating_add(1);
        }
    }
    let mut leftover = masked.into_bytes();
    for (start, end) in object_ranges {
        for byte in leftover.iter_mut().take(end + 1).skip(start) {
            *byte = b' ';
        }
    }
    let leftover_text = String::from_utf8(leftover).unwrap_or_default();
    if !leftover_text
        .replace([',', ' ', '\n', '\t', '\r'], "")
        .is_empty()
    {
        errors.push("API rules contain unexpected content".to_string());
    }
    rules
}

fn parse_api_rule_object(object: &str, errors: &mut Vec<String>) -> Option<Rule> {
    let assignments = object_field_assignments(object);
    let fields: Vec<&str> = assignments
        .iter()
        .map(|(field, _)| field.as_str())
        .collect();
    for field in fields
        .iter()
        .copied()
        .filter(|field| !RULE_FIELDS.contains(field))
    {
        errors.push(format!("API rule has unexpected field {field}"));
    }
    for field in RULE_FIELDS
        .iter()
        .copied()
        .filter(|field| !fields.contains(field))
    {
        errors.push(format!("API rule missing field {field}"));
    }
    expect(
        fields.iter().collect::<BTreeSet<_>>().len() == fields.len(),
        errors,
        "API rule fields must be unique",
    );
    if !api_rule_malformed_leftover(object).trim().is_empty() {
        errors.push("API rule contains malformed content".to_string());
    }
    let id = value_for_field(&assignments, "id")?;
    let decision = value_for_field(&assignments, "decision")?;
    let requirement = value_for_field(&assignments, "requirement")?;
    let evidence = value_for_field(&assignments, "evidence")?;
    Some(Rule {
        id,
        decision,
        requirement,
        evidence,
    })
}

fn object_field_assignments(object: &str) -> Vec<(String, String)> {
    object_field_ranges(object)
        .into_iter()
        .map(|(field, value, _, _)| (field, value))
        .collect()
}

fn object_field_ranges(object: &str) -> Vec<(String, String, usize, usize)> {
    let masked = csharp_code_mask(object);
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some((field, equals_index, value_start)) = next_assignment(&masked, offset) {
        let value_start = skip_whitespace_bytes(object.as_bytes(), value_start);
        if object.as_bytes().get(value_start) != Some(&b'"') {
            offset = value_start.saturating_add(1);
            continue;
        }
        let Some((value, value_end)) = csharp_string_literal_at(object, value_start) else {
            break;
        };
        result.push((
            field,
            value,
            field_start_before_equals(&masked, equals_index),
            value_end,
        ));
        offset = value_end;
    }
    result
}

fn api_rule_malformed_leftover(object: &str) -> String {
    let mut leftover = csharp_code_mask(object).into_bytes();
    if let Some(body_start) = object.find('{') {
        for byte in leftover.iter_mut().take(body_start) {
            *byte = b' ';
        }
    }
    for (_, _, start, end) in object_field_ranges(object) {
        for byte in leftover.iter_mut().take(end).skip(start) {
            *byte = b' ';
        }
    }
    for byte in &mut leftover {
        if matches!(*byte, b'{' | b'}' | b',' | b' ' | b'\n' | b'\t' | b'\r') {
            *byte = b' ';
        }
    }
    String::from_utf8(leftover).unwrap_or_default()
}

fn field_start_before_equals(text: &str, equals_index: usize) -> usize {
    let before = text[..equals_index].trim_end();
    let field_len = before
        .chars()
        .rev()
        .take_while(|ch| *ch == '_' || ch.is_ascii_alphanumeric())
        .map(char::len_utf8)
        .sum::<usize>();
    before.len().saturating_sub(field_len)
}

fn value_for_field(assignments: &[(String, String)], field: &str) -> Option<String> {
    assignments
        .iter()
        .find(|(name, _)| name == field)
        .map(|(_, value)| value.clone())
}

fn rules_from_catalog(catalog: &Value) -> Vec<Rule> {
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

fn mapget_start_indexes(program: &str) -> Vec<usize> {
    let masked = csharp_code_mask(program);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("app") {
        let start = offset + relative;
        if is_mapget_start(&masked, start) {
            indexes.push(start);
        }
        offset = start + "app".len();
    }
    indexes
}

fn is_mapget_start(text: &str, start: usize) -> bool {
    let bytes = text.as_bytes();
    if start > 0 && is_identifier_continue(bytes[start - 1]) {
        return false;
    }
    let mut cursor = start;
    if !starts_with_at(bytes, cursor, b"app") {
        return false;
    }
    cursor = skip_whitespace_bytes(bytes, cursor + "app".len());
    if bytes.get(cursor) != Some(&b'.') {
        return false;
    }
    cursor = skip_whitespace_bytes(bytes, cursor + 1);
    if !starts_with_at(bytes, cursor, b"MapGet") {
        return false;
    }
    cursor = skip_whitespace_bytes(bytes, cursor + "MapGet".len());
    bytes.get(cursor) == Some(&b'(')
}

fn mapget_route_literal(program: &str, start_index: usize) -> Option<String> {
    let open_paren = program[start_index..].find('(')? + start_index;
    let index = skip_whitespace_bytes(program.as_bytes(), open_paren + 1);
    let (literal, _) = csharp_string_literal_at(program, index)?;
    Some(literal)
}

fn csharp_code_mask(text: &str) -> String {
    let mut result = text.as_bytes().to_vec();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            let finish = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index..].starts_with(b"/*") {
            let finish = find_bytes(bytes, index + 2, b"*/")
                .map(|found| found + 2)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if raw_string_start(bytes, index) {
            let finish = raw_string_end_index(bytes, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index] == b'"' {
            let finish = quoted_string_end_index(bytes, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index] == b'\'' {
            let finish = char_end_index(bytes, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8(result).unwrap_or_default()
}

fn strip_csharp_comments(text: &str) -> String {
    let mut result = text.as_bytes().to_vec();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if raw_string_start(bytes, index) {
            index = raw_string_end_index(bytes, index);
        } else if bytes[index] == b'"' {
            index = quoted_string_end_index(bytes, index);
        } else if bytes[index] == b'\'' {
            index = char_end_index(bytes, index);
        } else if bytes[index..].starts_with(b"//") {
            let finish = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index..].starts_with(b"/*") {
            let finish = find_bytes(bytes, index + 2, b"*/")
                .map(|found| found + 2)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8(result).unwrap_or_default()
}

fn strip_csharp_string_literals(text: &str) -> String {
    csharp_code_mask(text)
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < text.len() {
        let Some(relative) = text[index..].find('"') else {
            break;
        };
        let start = index + relative;
        if let Some((literal, finish)) = csharp_string_literal_at(text, start) {
            values.push(literal);
            index = finish;
        } else {
            break;
        }
    }
    values
}

fn csharp_string_literal_at(text: &str, start_index: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(start_index) != Some(&b'"') {
        return None;
    }
    let finish = quoted_string_end_index(bytes, start_index);
    if finish <= start_index + 1 || finish > text.len() {
        return None;
    }
    let raw = &text[start_index + 1..finish - 1];
    Some((unescape_csharp_string(raw), finish))
}

fn unescape_csharp_string(text: &str) -> String {
    let mut value = String::new();
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            value.push(ch);
        }
    }
    value
}

fn mask_range(bytes: &mut [u8], start: usize, end: usize) {
    for byte in bytes.iter_mut().take(end).skip(start) {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn raw_string_start(bytes: &[u8], index: usize) -> bool {
    bytes.get(index..index + 3) == Some(b"\"\"\"") && (index == 0 || bytes[index - 1] != b'\\')
}

fn raw_string_end_index(bytes: &[u8], start: usize) -> usize {
    let mut quote_count = 0;
    while bytes.get(start + quote_count) == Some(&b'"') {
        quote_count += 1;
    }
    let delimiter = vec![b'"'; quote_count];
    find_bytes(bytes, start + quote_count, &delimiter)
        .map(|finish| finish + quote_count)
        .unwrap_or(bytes.len())
}

fn quoted_string_end_index(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn char_end_index(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'\'' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn find_bytes(haystack: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|relative| start + relative)
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let masked = csharp_code_mask(text);
    let bytes = masked.as_bytes();
    let mut depth = 0;
    let mut index = open_index;
    while index < bytes.len() {
        if bytes[index] == b'{' {
            depth += 1;
        } else if bytes[index] == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn brace_depth_at(text: &str, target_index: usize) -> i32 {
    let bytes = text.as_bytes();
    bytes[..target_index.min(bytes.len())]
        .iter()
        .fold(0, |depth, byte| match byte {
            b'{' => depth + 1,
            b'}' => depth - 1,
            _ => depth,
        })
}

fn paren_depth_at(text: &str, target_index: usize) -> i32 {
    let bytes = text.as_bytes();
    bytes[..target_index.min(bytes.len())]
        .iter()
        .fold(0, |depth, byte| match byte {
            b'(' => depth + 1,
            b')' => depth - 1,
            _ => depth,
        })
}

fn bracket_depth_at(text: &str, target_index: usize) -> i32 {
    let bytes = text.as_bytes();
    bytes[..target_index.min(bytes.len())]
        .iter()
        .fold(0, |depth, byte| match byte {
            b'[' => depth + 1,
            b']' => depth - 1,
            _ => depth,
        })
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited patch policy field"
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
        Value::String(text) if contains_prohibited_value(text) => {
            errors.push(format!("{path} contains prohibited value"));
        }
        _ => {}
    }
}

fn prohibited_field(field: &str) -> bool {
    let normalized = normalize(field);
    if safe_normalized_values().contains(&normalized) {
        return false;
    }
    [
        "servicenowsys",
        "servicenowrow",
        "servicenowpayload",
        "servicenowendpoint",
        "sysid",
        "cmdbci",
        "instance",
        "importset",
        "tableapi",
        "hostname",
        "username",
        "userid",
        "useridentifier",
        "credential",
        "secret",
        "token",
        "password",
        "tenantid",
        "tenantidentifier",
        "objectid",
        "objectidentifier",
        "endpointurl",
        "endpointname",
        "privateip",
        "privatenetwork",
        "serialnumber",
        "rawrow",
        "rawrows",
        "rowpayload",
        "providerpayload",
        "providerpayloads",
        "recipientdata",
        "ticketid",
        "changeid",
        "incidentid",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn unsafe_true_field(field: &str) -> bool {
    let normalized = normalize(field);
    [
        "live",
        "provider",
        "raw",
        "credential",
        "secret",
        "token",
        "tenant",
        "object",
        "endpoint",
        "private",
        "servicenow",
        "sys",
        "payload",
        "row",
        "identifier",
        "ticket",
        "incident",
        "change",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn safe_normalized_values() -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let safe_arrays: [&[&str]; 9] = [
        REQUIRED_FIELDS,
        REQUIRED_DECISIONS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        RULE_FIELDS,
        TOP_LEVEL_FIELDS,
        ENDPOINT_FIELDS,
    ];
    for items in safe_arrays {
        for item in items {
            values.insert(normalize(item));
        }
    }
    for (field, binding) in ENDPOINT_ARRAY_BINDINGS {
        values.insert(normalize(field));
        values.insert(normalize(binding));
    }
    for rule in REQUIRED_RULES {
        for item in [rule.id, rule.decision, rule.requirement, rule.evidence] {
            values.insert(normalize(item));
        }
    }
    for item in [
        "draft",
        "static-seed",
        "file-based",
        "true",
        "false",
        "block",
    ] {
        values.insert(normalize(item));
    }
    values
}

fn contains_prohibited_value(text: &str) -> bool {
    let normalized_slashes = text.replace("\\/", "/");
    normalized_slashes.contains("://")
        || normalized_slashes.contains("-----BEGIN ")
            && normalized_slashes.contains("PRIVATE KEY-----")
        || contains_aws_key(&normalized_slashes)
        || contains_private_ip(&normalized_slashes)
        || contains_uuid_like(&normalized_slashes)
        || contains_compact_hex_id(&normalized_slashes)
        || contains_email_like(&normalized_slashes)
        || contains_secret_assignment(&normalized_slashes)
        || contains_sensitive_assignment(&normalized_slashes)
}

fn contains_aws_key(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token.len() == 20 && token.starts_with("AKIA"))
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

fn contains_compact_hex_id(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_hexdigit())
        .any(|candidate| candidate.len() == 32)
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
    ]
    .iter()
    .any(|term| contains_term_assignment(&lower, term))
}

fn contains_sensitive_assignment(text: &str) -> bool {
    [
        "serviceNowSysId",
        "sys_id",
        "sysId",
        "tenantId",
        "objectId",
        "privateIp",
        "endpointUrl",
        "endpointName",
        "rawRow",
        "rawRows",
        "rowPayload",
        "providerPayload",
        "recipientData",
    ]
    .iter()
    .any(|term| contains_term_assignment(text, term))
}

fn contains_term_assignment(text: &str, term: &str) -> bool {
    let mut offset = 0;
    while let Some(found) = text[offset..].find(term) {
        let start = offset + found;
        let end = start + term.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let boundary = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if boundary {
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

fn skip_whitespace_bytes(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn starts_with_at(bytes: &[u8], index: usize, needle: &[u8]) -> bool {
    bytes.get(index..index + needle.len()) == Some(needle)
}

fn is_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
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
    fn parses_static_api_rule_object_without_malformed_leftover() {
        let mut errors = Vec::new();
        let rule =
            parse_api_rule_object(rule_object(), &mut errors).expect("expected static rule object");

        assert_eq!(rule.id, "no-live-servicenow-api");
        assert_eq!("", api_rule_malformed_leftover(rule_object()).trim());
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    fn rule_object() -> &'static str {
        r#"new { id = "no-live-servicenow-api", decision = "block", requirement = "Patch policy import uses file exports only and never calls live ServiceNow API.", evidence = "Validation result" }"#
    }
}
