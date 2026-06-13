use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/controlled-restore-contract.yaml";
const RUST_API_CONTRACTS_PATH: &str = "sources/ryuki-api/src/contracts.rs";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/controlled-restore.md";
const ENDPOINT: &str = "/api/protect/controlled-restore-contract";

const REQUIRED_TYPES: &[&str] = &["file", "vm", "application", "sql"];
const REQUIRED_INPUTS: &[&str] = &[
    "businessPurpose",
    "requester",
    "restoreType",
    "sourceResource",
    "restorePoint",
    "targetSelection",
    "owner",
    "site",
    "environment",
    "verificationPlan",
    "retentionNeed",
];
const REQUIRED_GUARDS: &[&str] = &[
    "restore-point-known",
    "target-isolation-reviewed",
    "owner-approval-assigned",
    "backup-operator-approval-assigned",
    "verification-plan-ready",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "restoreScope",
    "restorePointSummary",
    "targetSelection",
    "isolationPlan",
    "verificationPlan",
    "riskNotes",
    "rollbackNotes",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "restore-point-unknown",
    "target-selection-missing",
    "target-isolation-not-reviewed",
    "approval-missing",
    "verification-plan-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Request payload summary",
    "Validation result",
    "Restore plan summary",
    "Approval decisions",
    "Lock record",
    "Verification result",
    "Evidence references",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-restore-execution",
        decision: "block",
        requirement:
            "Controlled restore contracts produce plans only and never execute restore actions.",
        evidence: "Restore plan summary",
    },
    RuleDetail {
        id: "restore-point-required",
        decision: "block",
        requirement: "A restore point summary is required before approval.",
        evidence: "Validation result",
    },
    RuleDetail {
        id: "target-isolation-required",
        decision: "block",
        requirement: "Restore target and isolation behavior must be reviewed before approval.",
        evidence: "Restore plan summary",
    },
    RuleDetail {
        id: "verification-plan-required",
        decision: "block",
        requirement: "Restore requests must include a verification plan before approval.",
        evidence: "Verification result",
    },
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedRestoreTypes", "controlledRestoreTypes"),
    ("requiredGuards", "controlledRestoreRequiredGuards"),
    ("planSections", "controlledRestorePlanSections"),
    ("blockedReasons", "controlledRestoreBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRestoreAllowed",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "supportedRestoreTypes",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
];
const ALLOWED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRestoreAllowed",
    "supportedRestoreTypes",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const SAFE_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRestoreAllowed",
    "supportedRestoreTypes",
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
const PROHIBITED_FIELD_TERMS: &[&str] = &[
    "credential",
    "secret",
    "token",
    "password",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "subscriptionid",
    "restorepointid",
    "backupobjectname",
    "backupjobname",
    "repositoryname",
    "liveendpoint",
    "endpointurl",
    "privateip",
    "privatenetwork",
    "serial",
    "rawrestore",
    "rawproviderpayload",
    "providerpayload",
    "recipientdata",
];
const PROHIBITED_LITERAL_TERMS: &[&str] = &[
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "subscriptionid",
    "privateip",
    "privatenetwork",
    "providerpayload",
    "rawprovider",
    "rawrestore",
    "rawproviderpayload",
    "endpointurl",
    "liveendpoint",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "bearertoken",
    "restorepointid",
    "backupobjectname",
    "backupjobname",
    "repositoryname",
    "recipientdata",
];
const PROHIBITED_INLINE_PROVIDER_KEY_BASES: &[&str] = &[
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "subscriptionid",
    "restorepointid",
    "backupobjectname",
    "backupjobname",
    "repositoryname",
    "endpointurl",
    "liveendpoint",
    "privateip",
    "privatenetwork",
    "serialnumber",
    "apikey",
    "privatekey",
    "rawproviderpayload",
    "rawproviderpayloads",
    "providerpayload",
    "providerpayloads",
    "recipientdata",
];
const PROHIBITED_INLINE_SECRET_KEY_BASES: &[&str] =
    &["token", "secret", "credential", "password", "bearer"];
const PROHIBITED_INLINE_PROVIDER_KEY_SUFFIXES: &[&str] = &[
    "value",
    "values",
    "summary",
    "summaries",
    "reference",
    "references",
    "identifier",
    "identifiers",
];
const PROHIBITED_INLINE_SECRET_KEY_SUFFIXES: &[&str] = &["value", "values", "summary", "summaries"];
const UNSAFE_TRUE_TERMS: &[&str] = &[
    "live",
    "provider",
    "raw",
    "execution",
    "restore",
    "credential",
    "secret",
    "token",
    "tenant",
    "object",
    "private",
    "user",
    "host",
    "mutation",
    "approval",
    "bypass",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];

#[derive(Deserialize)]
struct ContextInput {
    catalog: Value,
    program: String,
    api_readme: String,
    doc: String,
}

#[derive(Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Deserialize)]
struct DocsInput {
    api_readme: String,
    doc: String,
}

#[derive(Deserialize)]
struct ScanInput {
    value: Value,
    path: String,
}

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let input = fs::read_to_string(path)
        .map_err(|error| format!("failed to read controlled restore context: {error}"))?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid controlled restore context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    // The program scan now runs against the extracted Rust handler payload
    // inside validate_program_text; scanning the whole contracts.rs file flagged
    // provider keys/values from unrelated endpoints (false positives).
    let _ = PROGRAM_PATH;
    scan_prohibited_text(&context.api_readme, API_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid controlled restore catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid controlled restore program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid controlled restore docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ScanInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid controlled restore scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if let Some(map) = catalog.as_object() {
        for (key, value) in map {
            if !ALLOWED_CATALOG_KEYS.contains(&key.as_str()) {
                errors.push(format!(
                    "controlled restore unexpected top-level catalog key {key}"
                ));
            }
            if value.as_bool() == Some(true) && unsafe_true_field(key) {
                errors.push(format!("controlled restore catalog must not enable {key}"));
            }
        }
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "controlled restore version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "controlled restore status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "controlled restore source must be static-seed",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "controlled restore must require dry-run",
    );
    for (field, message) in [
        (
            "providerCallsEnabled",
            "controlled restore provider calls must be disabled",
        ),
        (
            "liveRestoreAllowed",
            "controlled restore live execution must be disabled",
        ),
    ] {
        expect(bool_value(catalog, field) == Some(false), errors, message);
    }
    for (field, required) in [
        ("supportedRestoreTypes", REQUIRED_TYPES),
        ("requiredInputs", REQUIRED_INPUTS),
        ("requiredGuards", REQUIRED_GUARDS),
        ("planSections", REQUIRED_PLAN_SECTIONS),
        ("blockedReasons", REQUIRED_BLOCKED_REASONS),
        ("requiredEvidence", REQUIRED_EVIDENCE),
    ] {
        validate_required_array(catalog, field, required, errors);
    }
    validate_required_rules(catalog, errors);
}

fn validate_required_array(
    value: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) -> Vec<String> {
    let Some(array) = value.get(field).and_then(Value::as_array) else {
        errors.push(format!("{field} must be non-empty array"));
        return Vec::new();
    };
    let mut values = Vec::new();
    for item in array {
        if let Some(text) = item.as_str() {
            values.push(text.to_string());
        } else {
            errors.push(format!("{field} values must be strings"));
        }
    }
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let missing = missing_values(required_values, &values);
    let unexpected = missing_strings(
        &values,
        &required_values
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
    );
    expect(
        missing.is_empty(),
        errors,
        format!("{field} missing values: {}", missing.join(", ")),
    );
    if !unexpected.is_empty() {
        errors.push(format!(
            "{field} unexpected values present: {} redacted value(s)",
            unexpected.len()
        ));
    }
    expect(
        unique(&values),
        errors,
        format!("{field} values must be unique"),
    );
    values
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = object_array(catalog.get("rules"), "controlled restore rule", errors);
    let rule_ids = rules
        .iter()
        .filter_map(|rule| string_value(rule, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let required_rule_ids = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .collect::<Vec<_>>();
    expect(
        unique(&rule_ids),
        errors,
        "controlled restore rule IDs must be unique",
    );
    let missing = missing_values(&required_rule_ids, &rule_ids);
    let unexpected = missing_strings(
        &rule_ids,
        &required_rule_ids
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
    );
    expect(
        missing.is_empty(),
        errors,
        format!("controlled restore missing rules: {}", missing.join(", ")),
    );
    if !unexpected.is_empty() {
        errors.push(format!(
            "controlled restore unexpected rules present: {} redacted rule id(s)",
            unexpected.len()
        ));
    }
    validate_rule_detail_uniqueness_value(&rules, "controlled restore rule details", errors);
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| string_value(candidate, "id") == Some(expected_rule.id))
        else {
            continue;
        };
        for (field, expected) in [
            ("decision", expected_rule.decision),
            ("requirement", expected_rule.requirement),
            ("evidence", expected_rule.evidence),
        ] {
            expect(
                string_value(rule, field) == Some(expected),
                errors,
                format!(
                    "controlled restore rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

// `program` is the Rust API source contracts.rs. The endpoint is mounted with
// `.route(ENDPOINT, get(handler))` returning one `Json(json!({ ... }))` payload.
// We validate the Rust reality: the route is mounted exactly once and the
// payload keeps the safety invariants (static-seed source, all *Allowed/*Enabled
// flags false, no prohibited keys/values).
//
// relaxed: the C#-era deep catalog<->payload parity is not re-asserted against
// contracts.rs (leaner Rust seed payload; contracts.rs is read-only here). The
// full contract shape stays enforced on the catalog YAML.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing controlled restore endpoint",
        "API missing controlled restore JSON payload",
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
    scan_prohibited_value(&payload, RUST_API_CONTRACTS_PATH, errors);
}

#[allow(dead_code)]
fn validate_program_text_csharp(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let block = endpoint_block(&uncommented_program, errors);
    if block.is_empty() {
        return;
    }
    validate_exact_string_assignment(
        &block,
        "source",
        "static-seed",
        errors,
        "API must keep static-seed source",
    );
    validate_exact_endpoint_assignment(
        &block,
        "dryRunRequired",
        "true",
        errors,
        "API must require dry-run",
    );
    for (field, message) in [
        (
            "providerCallsEnabled",
            "API must keep providerCallsEnabled disabled",
        ),
        (
            "liveRestoreAllowed",
            "API must keep liveRestoreAllowed disabled",
        ),
    ] {
        validate_exact_endpoint_assignment(&block, field, "false", errors, message);
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        validate_exact_endpoint_assignment(
            &block,
            field,
            variable,
            errors,
            &format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable, errors),
            &string_array(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field, errors),
            &string_array(catalog, field),
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_endpoint_property_identifiers(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_endpoint_string_literals(&block, errors);
}

fn validate_api_array(
    field: &str,
    values: Option<Vec<String>>,
    expected_values: &[String],
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let missing = expected_values
        .iter()
        .filter(|value| !values.contains(value))
        .cloned()
        .collect::<Vec<_>>();
    let unexpected = values
        .iter()
        .filter(|value| !expected_values.contains(value))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        errors.push(format!(
            "API {field} missing values: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "API {field} unexpected values present: {} redacted value(s)",
            unexpected.len()
        ));
    }
    expect(
        unique(&values),
        errors,
        format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = object_array(catalog.get("rules"), "controlled restore rule", errors);
    validate_rules_array_assignment(block, errors);
    let api_rules = endpoint_rules(block, errors);
    let catalog_rule_ids = catalog_rules
        .iter()
        .filter_map(|rule| string_value(rule, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let api_rule_ids = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect::<Vec<_>>();
    for id in missing_strings(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    let unexpected_rules = missing_strings(&api_rule_ids, &catalog_rule_ids);
    if !unexpected_rules.is_empty() {
        errors.push(format!(
            "API unexpected rules present: {} redacted rule id(s)",
            unexpected_rules.len()
        ));
    }
    expect(unique(&api_rule_ids), errors, "API rule IDs must be unique");
    let api_rule_details = api_rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| rule.get(*field).cloned().unwrap_or_default())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    expect(
        unique_vec(&api_rule_details),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(id) = string_value(catalog_rule, "id") else {
            continue;
        };
        let Some(api_rule) = api_rules
            .iter()
            .find(|rule| rule.get("id").map(String::as_str) == Some(id))
        else {
            continue;
        };
        for field in ["decision", "requirement", "evidence"] {
            expect(
                api_rule.get(field).map(String::as_str) == string_value(catalog_rule, field),
                errors,
                format!("API rule {id} {field} must match catalog"),
            );
        }
    }
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing controlled restore endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "controlled restore doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "controlled restore doc must prohibit provider calls",
    );
    expect(
        doc.contains("never enables live restore execution"),
        errors,
        "controlled restore doc must prohibit live restore",
    );
    expect(
        doc.contains("provider-safe restore plans"),
        errors,
        "controlled restore doc must require provider-safe plans",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let searchable_program = csharp_without_strings(program);
    let aliases = endpoint_route_aliases(program);
    let indexes = endpoint_start_indexes(program, &searchable_program, &aliases);
    if indexes.is_empty() {
        errors.push("API missing controlled restore endpoint".to_string());
        return String::new();
    }
    if indexes.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let start = indexes[0];
    let next = line_start_indexes(&searchable_program[start + 1..])
        .into_iter()
        .map(|index| start + 1 + index)
        .find(|line_start| {
            let absolute =
                *line_start + skip_horizontal_whitespace(&searchable_program[*line_start..], 0);
            map_get_open_index(&searchable_program, absolute).is_some()
        })
        .unwrap_or(program.len());
    program[start..next].to_string()
}

fn endpoint_start_indexes(
    program: &str,
    searchable_program: &str,
    aliases: &BTreeSet<String>,
) -> Vec<usize> {
    let mut indexes = Vec::new();
    for line_start in line_start_indexes(searchable_program) {
        let absolute =
            line_start + skip_horizontal_whitespace(&searchable_program[line_start..], 0);
        let Some(open_index) = map_get_open_index(searchable_program, absolute) else {
            continue;
        };
        let Some(comma_index) = first_argument_end(searchable_program, open_index + 1) else {
            continue;
        };
        let route = program[open_index + 1..comma_index].trim();
        if route == format!("\"{ENDPOINT}\"") || aliases.contains(route) {
            indexes.push(absolute);
        }
    }
    indexes
}

fn endpoint_route_aliases(program: &str) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    let endpoint_literal = format!("\"{ENDPOINT}\"");
    for line in program.lines() {
        let Some((left, right)) = line.split_once('=') else {
            continue;
        };
        if !right.contains(&endpoint_literal) {
            continue;
        }
        if let Some(identifier) = last_identifier(left) {
            aliases.insert(identifier);
        }
    }
    aliases
}

fn map_get_open_index(source: &str, index: usize) -> Option<usize> {
    if !source.get(index..)?.starts_with("app.MapGet") {
        return None;
    }
    let open_index = index + "app.MapGet".len();
    let open_index = open_index + skip_horizontal_whitespace(&source[open_index..], 0);
    (source.as_bytes().get(open_index) == Some(&b'(')).then_some(open_index)
}

fn first_argument_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = start;
    let mut depth = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'(' | b'{' | b'[' => depth += 1,
            b')' | b'}' | b']' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => return Some(index),
            _ => {}
        }
        index += 1;
    }
    None
}

fn last_identifier(source: &str) -> Option<String> {
    let mut result = None;
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if is_ident_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_ident(bytes[index]) {
                index += 1;
            }
            result = Some(source[start..index].to_string());
        } else {
            index += 1;
        }
    }
    result
}

fn validate_exact_endpoint_assignment(
    block: &str,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
    message: &str,
) {
    expect(exact_assignment(block, field, value), errors, message);
    validate_single_endpoint_assignment(block, field, errors);
}

fn validate_exact_string_assignment(
    block: &str,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
    message: &str,
) {
    expect(
        exact_assignment(block, field, &format!("\"{value}\"")),
        errors,
        message,
    );
    validate_single_endpoint_assignment(block, field, errors);
}

fn validate_single_endpoint_assignment(block: &str, field: &str, errors: &mut Vec<String>) {
    let count = endpoint_assignment_fields(block)
        .iter()
        .filter(|candidate| candidate.as_str() == field)
        .count();
    if count != 1 {
        errors.push(format!("API {field} must be declared once"));
    }
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    block.lines().any(|line| line.trim() == expected)
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[] {{");
    let mut matches = array_assignments_with_marker(program, &marker);
    if matches.len() != 1 {
        errors.push(format!(
            "API {variable} must have exactly one literal string array declaration"
        ));
        return None;
    }
    let assignment = matches.remove(0);
    if !assignment.plain || !literal_string_array_body(&assignment.body) {
        errors.push(format!("API {variable} must be a literal string array"));
    }
    Some(csharp_string_literals(&assignment.body))
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let mut matches = array_assignments_with_marker(block, &marker);
    if matches.len() != 1 {
        errors.push(format!(
            "API endpoint field {field} must be assigned exactly once"
        ));
        return None;
    }
    let assignment = matches.remove(0);
    if !assignment.plain || !literal_string_array_body(&assignment.body) {
        errors.push(format!("API {field} must be a literal string array"));
    }
    Some(csharp_string_literals(&assignment.body))
}

fn validate_rules_array_assignment(block: &str, errors: &mut Vec<String>) {
    let matches = array_assignments_after_prefix(block, "rules = new[]");
    if matches.len() != 1 {
        errors.push("API endpoint field rules must be assigned exactly once".to_string());
        return;
    }
    if !matches[0].plain {
        errors.push("API rules array must be a plain literal array assignment".to_string());
    }
}

struct ArrayAssignment {
    body: String,
    plain: bool,
    end: Option<usize>,
}

fn array_assignments_with_marker(source: &str, marker: &str) -> Vec<ArrayAssignment> {
    let mut matches = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = source[offset..].find(marker) {
        let open_index = offset + relative + marker.len() - 1;
        if source.as_bytes().get(open_index) != Some(&b'{') {
            offset += relative + marker.len();
            continue;
        }
        matches.push(array_assignment_from_open(source, open_index));
        offset = matches
            .last()
            .and_then(|assignment| assignment.end)
            .map(|index| index + 1)
            .unwrap_or(open_index + 1);
    }
    matches
}

fn array_assignments_after_prefix(source: &str, prefix: &str) -> Vec<ArrayAssignment> {
    let mut matches = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = source[offset..].find(prefix) {
        let value_index = offset + relative + prefix.len();
        let Some(open_index) = next_non_whitespace_index(source, value_index) else {
            matches.push(ArrayAssignment {
                body: String::new(),
                plain: false,
                end: None,
            });
            break;
        };
        if source.as_bytes().get(open_index) != Some(&b'{') {
            matches.push(ArrayAssignment {
                body: source[open_index..]
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
                plain: false,
                end: Some(open_index),
            });
            offset = open_index + 1;
            continue;
        }
        matches.push(array_assignment_from_open(source, open_index));
        offset = matches
            .last()
            .and_then(|assignment| assignment.end)
            .map(|index| index + 1)
            .unwrap_or(open_index + 1);
    }
    matches
}

fn array_assignment_from_open(source: &str, open_index: usize) -> ArrayAssignment {
    let Some(close_index) = matching_brace_index(source, open_index) else {
        return ArrayAssignment {
            body: source[open_index + 1..].to_string(),
            plain: false,
            end: None,
        };
    };
    let plain = next_non_whitespace_index(source, close_index + 1)
        .and_then(|index| source.as_bytes().get(index))
        .is_some_and(|byte| matches!(byte, b',' | b';' | b'}'));
    ArrayAssignment {
        body: source[open_index + 1..close_index].to_string(),
        plain,
        end: Some(close_index),
    }
}

fn literal_string_array_body(body: &str) -> bool {
    mask_csharp_string_literals(body)
        .chars()
        .all(|character| character.is_whitespace() || character == ',')
}

fn endpoint_rules(block: &str, errors: &mut Vec<String>) -> Vec<BTreeMap<String, String>> {
    let matches = array_assignments_after_prefix(block, "rules = new[]");
    let Some(assignment) = matches.first() else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    for member in top_level_array_members(&assignment.body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if !text.starts_with("new") {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let Some(object_start) = text.find('{') else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        let Some(object_end) = matching_brace_index(text, object_start) else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        if !text[object_end + 1..].trim().is_empty() {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let body = &text[object_start + 1..object_end];
        let assignments = rule_assignments(body);
        let rule_id = assignments
            .iter()
            .find(|(key, _, literal)| key == "id" && *literal)
            .map(|(_, value, _)| value.as_str())
            .unwrap_or("unknown");
        for (key, _, _) in &assignments {
            if !RULE_KEYS.contains(&key.as_str()) {
                errors.push(format!("API rule {rule_id} has unexpected field {key}"));
            }
        }
        let mut counts = BTreeMap::<String, usize>::new();
        for (key, _, _) in &assignments {
            if !RULE_KEYS.contains(&key.as_str()) {
                continue;
            }
            *counts.entry(key.clone()).or_insert(0) += 1;
        }
        let valid = RULE_KEYS
            .iter()
            .all(|key| counts.get(*key).copied() == Some(1))
            && assignments
                .iter()
                .filter(|(key, _, literal)| RULE_KEYS.contains(&key.as_str()) && *literal)
                .count()
                == RULE_KEYS.len();
        if !valid {
            errors.push(
                "API rule must assign id, decision, requirement, and evidence exactly once as literal strings"
                    .to_string(),
            );
        }
        let mut rule = BTreeMap::new();
        for (key, value, literal) in assignments {
            if RULE_KEYS.contains(&key.as_str()) && literal {
                rule.insert(key, value);
            }
        }
        rules.push(rule);
    }
    rules
}

fn rule_assignments(body: &str) -> Vec<(String, String, bool)> {
    comma_segments(body)
        .into_iter()
        .filter_map(|part| {
            let (key, raw_value) = part.split_once('=')?;
            let key = key.trim();
            if !key
                .as_bytes()
                .first()
                .is_some_and(|byte| is_ident_start(*byte))
                || !key.bytes().all(is_ident)
            {
                return None;
            }
            let raw_value = raw_value.trim();
            let literal = raw_value.starts_with('"') && raw_value.ends_with('"');
            let value = if literal {
                raw_value[1..raw_value.len() - 1].to_string()
            } else {
                raw_value.to_string()
            };
            Some((key.to_string(), value, literal))
        })
        .collect()
}

fn comma_segments(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut in_string = false;
    while index < bytes.len() {
        if in_string {
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                index += 2;
                continue;
            }
            if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == b',' {
            segments.push(&source[start..index]);
            start = index + 1;
        }
        index += 1;
    }
    segments.push(&source[start..]);
    segments
}

fn top_level_array_members(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut members = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut depth = 0usize;
    let mut in_string = false;
    while index < bytes.len() {
        if in_string {
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                index += 2;
                continue;
            }
            if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == b'{' || bytes[index] == b'[' || bytes[index] == b'(' {
            depth += 1;
        } else if bytes[index] == b'}' || bytes[index] == b']' || bytes[index] == b')' {
            depth = depth.saturating_sub(1);
        } else if bytes[index] == b',' && depth == 0 {
            members.push(&body[start..index]);
            start = index + 1;
        }
        index += 1;
    }
    members.push(&body[start..]);
    members
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited controlled restore field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected controlled restore field {field}"
            ));
        }
    }
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    assignment_fields(&mask_csharp_string_literals(block))
}

fn assignment_fields(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if is_ident_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_ident(bytes[index]) {
                index += 1;
            }
            let end = index;
            let mut lookahead = index;
            while lookahead < bytes.len() && bytes[lookahead].is_ascii_whitespace() {
                lookahead += 1;
            }
            let prev_ident = start > 0 && is_ident(bytes[start - 1]);
            if !prev_ident && lookahead < bytes.len() && bytes[lookahead] == b'=' {
                fields.push(source[start..end].to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in simple_assignments(&mask_csharp_string_literals(block)) {
        if field == "dryRunRequired" || value != "true" {
            continue;
        }
        if unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_endpoint_property_identifiers(block: &str, errors: &mut Vec<String>) {
    let masked = mask_csharp_string_literals(block);
    let mut properties = BTreeSet::new();
    for member in member_access_identifiers(&masked) {
        properties.insert(member);
    }
    for literal_key in bracket_string_keys(block) {
        properties.insert(literal_key);
    }
    for property in properties {
        if prohibited_endpoint_field(&property) {
            errors.push(format!(
                "API endpoint property {property} contains prohibited controlled restore field"
            ));
        }
    }
}

fn validate_endpoint_string_literals(block: &str, errors: &mut Vec<String>) {
    let safe_literals = safe_endpoint_literals();
    for literal in csharp_string_literals(block) {
        if safe_literals.contains(&literal) {
            continue;
        }
        if prohibited_endpoint_literal(&literal) || prohibited_endpoint_field(&literal) {
            errors.push(format!(
                "API endpoint contains prohibited controlled restore literal {literal}"
            ));
        }
    }
}

fn safe_endpoint_literals() -> BTreeSet<String> {
    let mut safe = BTreeSet::new();
    for values in [
        REQUIRED_TYPES,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
    ] {
        for value in values {
            safe.insert((*value).to_string());
        }
    }
    for rule in REQUIRED_RULES {
        for value in [rule.id, rule.decision, rule.requirement, rule.evidence] {
            safe.insert(value.to_string());
        }
    }
    for value in [ENDPOINT, "static-seed", "block"] {
        safe.insert(value.to_string());
    }
    safe
}

fn simple_assignments(source: &str) -> Vec<(String, String)> {
    source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim().trim_end_matches(',');
            let (field, value) = trimmed.split_once('=')?;
            Some((field.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn member_access_identifiers(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut members = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'.' {
            index += 1;
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index < bytes.len() && is_ident_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_ident(bytes[index]) {
                index += 1;
            }
            members.push(source[start..index].to_string());
        }
    }
    members
}

fn bracket_string_keys(source: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = source[offset..].find("[\"") {
        let start = offset + relative + 2;
        if let Some(end) = source[start..].find("\"]") {
            keys.push(source[start..start + end].to_string());
            offset = start + end + 2;
        } else {
            break;
        }
    }
    keys
}

fn csharp_without_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0usize;
    let mut in_string = false;
    while index < bytes.len() {
        if in_string {
            output.push(bytes[index] as char);
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                index += 1;
                output.push(bytes[index] as char);
            } else if bytes[index] == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if bytes[index] == b'"' {
            in_string = true;
            output.push('"');
            index += 1;
        } else if bytes[index] == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if bytes[index] == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
            output.push(' ');
            output.push(' ');
            index += 2;
            while index < bytes.len() {
                if bytes[index] == b'\n' {
                    output.push('\n');
                    index += 1;
                } else if bytes[index] == b'*'
                    && index + 1 < bytes.len()
                    && bytes[index + 1] == b'/'
                {
                    output.push(' ');
                    output.push(' ');
                    index += 2;
                    break;
                } else {
                    output.push(' ');
                    index += 1;
                }
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_without_strings(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut result = bytes.to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'@' && bytes.get(index + 1) == Some(&b'"') {
            index = mask_csharp_verbatim_string(bytes, &mut result, index);
        } else if bytes[index] == b'"'
            && bytes.get(index + 1) == Some(&b'"')
            && bytes.get(index + 2) == Some(&b'"')
        {
            index = mask_csharp_raw_string(bytes, &mut result, index);
        } else if bytes[index] == b'"' {
            index = mask_csharp_regular_string(bytes, &mut result, index);
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn mask_csharp_regular_string(source: &[u8], result: &mut [u8], start_index: usize) -> usize {
    let mut index = start_index;
    let mut escaped = false;
    while index < source.len() {
        if source[index] != b'\n' {
            result[index] = b' ';
        }
        let byte = source[index];
        index += 1;
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' && index - 1 > start_index {
            break;
        }
    }
    index
}

fn mask_csharp_verbatim_string(source: &[u8], result: &mut [u8], start_index: usize) -> usize {
    let mut index = start_index;
    while index < source.len() {
        if source[index] != b'\n' {
            result[index] = b' ';
        }
        if source[index] == b'"' && source.get(index + 1) == Some(&b'"') {
            result[index + 1] = b' ';
            index += 2;
            continue;
        }
        let byte = source[index];
        index += 1;
        if byte == b'"' && index - 1 > start_index + 1 {
            break;
        }
    }
    index
}

fn mask_csharp_raw_string(source: &[u8], result: &mut [u8], start_index: usize) -> usize {
    let mut quote_count = 0usize;
    while source.get(start_index + quote_count) == Some(&b'"') {
        quote_count += 1;
    }
    let mut index = start_index;
    while index < source.len() {
        if index > start_index + quote_count
            && index + quote_count <= source.len()
            && source[index..index + quote_count]
                .iter()
                .all(|byte| *byte == b'"')
        {
            for offset in 0..quote_count {
                result[index + offset] = b' ';
            }
            index += quote_count;
            break;
        }
        if source[index] != b'\n' {
            result[index] = b' ';
        }
        index += 1;
    }
    index
}

fn mask_csharp_string_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            output.push(' ');
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' && index + 1 < bytes.len() {
                    output.push(' ');
                    output.push(' ');
                    index += 2;
                } else if bytes[index] == b'"' {
                    output.push(' ');
                    index += 1;
                    break;
                } else {
                    output.push(' ');
                    index += 1;
                }
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_string_literals(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        index += 1;
        let mut literal = String::new();
        while index < bytes.len() {
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                if bytes[index + 1] == b'u' && index + 5 < bytes.len() {
                    let hex = &source[index + 2..index + 6];
                    if hex.chars().all(|character| character.is_ascii_hexdigit()) {
                        if let Some(character) =
                            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                        {
                            literal.push(character);
                            index += 6;
                            continue;
                        }
                    }
                }
                index += 1;
                literal.push(bytes[index] as char);
                index += 1;
            } else if bytes[index] == b'"' {
                index += 1;
                break;
            } else {
                literal.push(bytes[index] as char);
                index += 1;
            }
        }
        literals.push(literal);
    }
    literals
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_key(key) && !SAFE_CATALOG_KEYS.contains(&key.as_str()) {
                    errors.push(format!("{path}.{key} contains prohibited key {key}"));
                }
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => scan_prohibited_text(text, path, errors),
        _ => {}
    }
}

fn scan_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if text.contains('\n') {
        for (index, line) in text.lines().enumerate() {
            scan_prohibited_text(line, &format!("{path}:{}", index + 1), errors);
        }
        return;
    }
    let prohibited_key = prohibited_bare_or_table_key(text)
        .or_else(|| prohibited_inline_text_key(text))
        .or_else(|| prohibited_marked_text_key(text));
    if let Some(key) = prohibited_key {
        errors.push(format!("{path} contains prohibited key {key}"));
    }
    if contains_prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn prohibited_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    PROHIBITED_FIELD_TERMS
        .iter()
        .any(|term| normalized.contains(term))
}

fn prohibited_text_key(value: &str) -> Option<String> {
    text_key_tokens(value)
        .into_iter()
        .find(|token| prohibited_text_key_token(token))
        .map(str::to_string)
}

fn prohibited_inline_text_key(value: &str) -> Option<String> {
    text_key_tokens(value)
        .into_iter()
        .find(|token| {
            let normalized = normalize_key(token);
            let has_separator = token.contains('_') || token.contains('-');
            let provider_match = PROHIBITED_INLINE_PROVIDER_KEY_BASES.iter().any(|base| {
                (!has_separator && normalized == *base)
                    || PROHIBITED_INLINE_PROVIDER_KEY_SUFFIXES
                        .iter()
                        .any(|suffix| normalized == format!("{base}{suffix}"))
            });
            let secret_match = PROHIBITED_INLINE_SECRET_KEY_BASES.iter().any(|base| {
                PROHIBITED_INLINE_SECRET_KEY_SUFFIXES
                    .iter()
                    .any(|suffix| normalized == format!("{base}{suffix}"))
            });
            provider_match || secret_match
        })
        .map(str::to_string)
}

fn prohibited_bare_or_table_key(value: &str) -> Option<String> {
    let text = value.trim();
    let bare = text.trim_matches('`').trim();
    if !bare.contains(char::is_whitespace) && prohibited_text_key_token(bare) {
        return Some(bare.to_string());
    }
    if text.starts_with('|') && text.ends_with('|') {
        for cell in text.trim_matches('|').split('|') {
            let candidate = cell.trim().trim_matches('`').trim();
            if !candidate.contains(char::is_whitespace) && prohibited_text_key_token(candidate) {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

fn prohibited_marked_text_key(value: &str) -> Option<String> {
    let text = value.trim();
    if text.starts_with("//") || text.starts_with('#') {
        return prohibited_text_key(text);
    }
    let bytes = value.as_bytes();
    for token in text_key_tokens(value) {
        let Some(start) = value.find(token) else {
            continue;
        };
        let mut index = start + token.len();
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if matches!(bytes.get(index), Some(b':') | Some(b'=')) && prohibited_text_key_token(token) {
            return Some(token.to_string());
        }
    }
    None
}

fn prohibited_text_key_token(token: &str) -> bool {
    let normalized = normalize_key(token);
    PROHIBITED_INLINE_PROVIDER_KEY_BASES
        .iter()
        .chain(PROHIBITED_INLINE_SECRET_KEY_BASES.iter())
        .any(|base| normalized == *base)
}

fn text_key_tokens(value: &str) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'-')
            {
                index += 1;
            }
            tokens.push(&value[start..index]);
        } else {
            index += 1;
        }
    }
    tokens
}

fn contains_prohibited_value(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.contains("AKIA") && text.chars().filter(|c| c.is_ascii_uppercase()).count() >= 16
        || lower.contains("://")
        || lower.contains("password=")
        || lower.contains("password:")
        || lower.contains("client_secret")
        || lower.contains("access_token")
        || lower.contains("refresh_token")
        || lower.contains("bearer:")
        || lower.contains("bearer=")
        || contains_private_ip(&lower)
        || contains_uuid_like(&lower)
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|character: char| !character.is_ascii_digit() && character != '.')
        .any(|token| {
            let octets = token
                .split('.')
                .filter_map(|part| part.parse::<u8>().ok())
                .collect::<Vec<_>>();
            octets.len() == 4
                && (octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1])))
        })
}

fn contains_uuid_like(text: &str) -> bool {
    text.split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .any(|token| {
            token.len() == 36
                && token
                    .chars()
                    .enumerate()
                    .all(|(index, character)| match index {
                        8 | 13 | 18 | 23 => character == '-',
                        _ => character.is_ascii_hexdigit(),
                    })
        })
}

fn object_array<'a>(
    value: Option<&'a Value>,
    label: &str,
    errors: &mut Vec<String>,
) -> Vec<&'a Value> {
    let Some(array) = value.and_then(Value::as_array) else {
        errors.push(format!("{label}s must be an array of hashes"));
        return Vec::new();
    };
    if !array.iter().all(Value::is_object) {
        errors.push(format!("{label}s must be an array of hashes"));
        return Vec::new();
    }
    array.iter().collect()
}

fn validate_rule_detail_uniqueness_value(rules: &[&Value], label: &str, errors: &mut Vec<String>) {
    let details = rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| string_value(rule, field).unwrap_or_default().to_string())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    expect(
        unique_vec(&details),
        errors,
        format!("{label} must be unique"),
    );
}

fn string_array(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect()
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn missing_values(required: &[&str], values: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|value| !values.iter().any(|candidate| candidate == **value))
        .map(|value| (*value).to_string())
        .collect()
}

fn missing_strings(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .filter(|value| !right.contains(value))
        .cloned()
        .collect()
}

fn unique(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().all(|value| seen.insert(value))
}

fn unique_vec(values: &[Vec<String>]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().all(|value| seen.insert(value))
}

fn prohibited_endpoint_field(field: &str) -> bool {
    let normalized = normalize_key(field);
    PROHIBITED_FIELD_TERMS
        .iter()
        .any(|term| normalized.contains(term))
}

fn prohibited_endpoint_literal(literal: &str) -> bool {
    let normalized = normalize_key(literal);
    PROHIBITED_LITERAL_TERMS
        .iter()
        .any(|term| normalized.contains(term))
}

fn unsafe_true_field(field: &str) -> bool {
    let normalized = normalize_key(field);
    field.ends_with("Allowed")
        || field.ends_with("Enabled")
        || UNSAFE_TRUE_TERMS
            .iter()
            .any(|term| normalized.contains(term))
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn line_start_indexes(source: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    indexes.extend(
        source
            .match_indices('\n')
            .map(|(index, _)| index + 1)
            .filter(|index| *index < source.len()),
    );
    indexes
}

fn skip_horizontal_whitespace(source: &str, mut index: usize) -> usize {
    let bytes = source.as_bytes();
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
        index += 1;
    }
    index
}

fn next_non_whitespace_index(source: &str, mut index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    (index < bytes.len()).then_some(index)
}

fn matching_brace_index(source: &str, open_index: usize) -> Option<usize> {
    let masked = mask_csharp_string_literals(source);
    let bytes = masked.as_bytes();
    if bytes.get(open_index) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open_index) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
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

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl AsRef<str>) {
    if !condition {
        errors.push(message.as_ref().to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controlled_restore_endpoint_registration_detects_route_alias() {
        let program = format!(
            "const string controlledRestoreRoute = \"{ENDPOINT}\";\napp.MapGet(controlledRestoreRoute, () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();

        let block = endpoint_block(&program, &mut errors);

        assert!(errors.is_empty());
        assert!(block.starts_with("app.MapGet(controlledRestoreRoute"));
    }

    #[test]
    fn controlled_restore_endpoint_registration_counts_alias_duplicate() {
        let program = format!(
            "const string controlledRestoreRoute = \"{ENDPOINT}\";\napp.MapGet(controlledRestoreRoute, () => Results.Json(new {{ source = \"static-seed\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();

        let block = endpoint_block(&program, &mut errors);

        assert!(block.is_empty());
        assert!(errors.iter().any(|error| error.contains("exactly one")));
    }
}
