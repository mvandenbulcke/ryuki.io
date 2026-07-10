use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/restore-testing-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/restore-testing.md";
const ENDPOINT: &str = "/api/protect/restore-testing-contract";

const REQUIRED_WORKFLOWS: &[&str] = &[
    "restore-test-schedule",
    "restore-point-validation",
    "verification-plan-review",
    "critical-app-cadence",
    "evidence-pack-review",
];
const REQUIRED_INPUTS: &[&str] = &[
    "application",
    "criticality",
    "backupPolicy",
    "restoreType",
    "restorePointSelection",
    "verificationPlan",
    "owner",
    "supportGroup",
    "testWindow",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "restore-point-known",
    "target-isolation-reviewed",
    "verification-plan-ready",
    "owner-approval-assigned",
    "backup-operator-approval-assigned",
    "schedule-window-known",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "testScope",
    "restorePointSummary",
    "isolationPlan",
    "verificationPlan",
    "scheduleCadence",
    "evidencePack",
    "approvalRoute",
    "handoverNotes",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-restore-disabled",
    "test-execution-disabled",
    "restore-point-unknown",
    "target-isolation-not-reviewed",
    "verification-plan-missing",
    "schedule-window-missing",
    "approval-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Restore test scope",
    "Restore point summary",
    "Isolation plan",
    "Verification plan",
    "Schedule cadence",
    "Approval decisions",
    "Evidence pack",
    "Evidence references",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-restore-test-execution",
        decision: "block",
        requirement: "Restore testing produces schedule, verification, and evidence plans only, never executing restores.",
        evidence: "Restore test scope",
    },
    RuleDetail {
        id: "restore-point-required",
        decision: "block",
        requirement: "Restore test plans require a known restore point selection.",
        evidence: "Restore point summary",
    },
    RuleDetail {
        id: "isolation-and-verification-required",
        decision: "block",
        requirement: "Target isolation and verification plans must be ready before approval.",
        evidence: "Verification plan",
    },
    RuleDetail {
        id: "cadence-required-for-critical-apps",
        decision: "block",
        requirement: "Critical applications require an explicit restore-test cadence.",
        evidence: "Schedule cadence",
    },
    RuleDetail {
        id: "evidence-pack-required",
        decision: "block",
        requirement: "Restore testing must produce a redacted evidence pack before completion.",
        evidence: "Evidence pack",
    },
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedWorkflows", "restoreTestingWorkflows"),
    ("requiredGuards", "restoreTestingRequiredGuards"),
    ("planSections", "restoreTestingPlanSections"),
    ("blockedReasons", "restoreTestingBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "testMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRestoreAllowed",
    "testExecutionAllowed",
    "rawRestoreLogsAllowed",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "supportedWorkflows",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
];
const PROHIBITED_FIELD_TERMS: &[&str] = &[
    "hostname",
    "hostidentifier",
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
    "liveendpoint",
    "endpointurl",
    "url",
    "privateip",
    "privatenetwork",
    "rawrestore",
    "rawrow",
    "providerpayload",
    "restorepointid",
    "restorejobid",
    "restoresessionid",
    "sessionid",
    "jobid",
];
const PROHIBITED_LITERAL_TERMS: &[&str] = &[
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "privateip",
    "privatenetwork",
    "providerpayload",
    "rawprovider",
    "rawrestore",
    "rawrow",
    "endpointurl",
    "hostname",
    "hostidentifier",
    "username",
    "userid",
    "useridentifier",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "bearertoken",
    "restorepointid",
    "restorejobid",
    "restoresessionid",
    "sessionid",
    "jobid",
];
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
        .map_err(|error| format!("failed to read restore testing context: {error}"))?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid restore testing context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    let uncommented_program = csharp_without_comments(&context.program);
    let mut endpoint_errors = Vec::new();
    let block = endpoint_block(&uncommented_program, &mut endpoint_errors);
    scan_prohibited_text(&block, PROGRAM_PATH, &mut errors);
    scan_prohibited_text(&context.api_readme, API_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid restore testing catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid restore testing program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid restore testing docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ScanInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid restore testing scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "restore testing version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "restore testing status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "restore testing source must be static-seed",
    );
    expect(
        string_value(catalog, "testMode") == Some("schedule-and-evidence"),
        errors,
        "restore testing mode must be schedule-and-evidence",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "restore testing must require dry-run",
    );
    for (field, message) in [
        (
            "providerCallsEnabled",
            "restore testing provider calls must be disabled",
        ),
        (
            "liveRestoreAllowed",
            "restore testing live restore must be disabled",
        ),
        (
            "testExecutionAllowed",
            "restore testing execution must be disabled",
        ),
        (
            "rawRestoreLogsAllowed",
            "restore testing raw restore logs must be disabled",
        ),
    ] {
        expect(bool_value(catalog, field) == Some(false), errors, message);
    }
    for (field, required) in [
        ("supportedWorkflows", REQUIRED_WORKFLOWS),
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
    expect(
        missing.is_empty(),
        errors,
        format!("{field} missing values: {}", missing.join(", ")),
    );
    expect(
        unique(&values),
        errors,
        format!("{field} values must be unique"),
    );
    values
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = object_array(catalog.get("rules"), "restore testing rule", errors);
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
        "restore testing rule IDs must be unique",
    );
    let missing = missing_values(&required_rule_ids, &rule_ids);
    expect(
        missing.is_empty(),
        errors,
        format!("restore testing missing rules: {}", missing.join(", ")),
    );
    validate_rule_detail_uniqueness_value(&rules, "restore testing rule details", errors);
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
                    "restore testing rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    // relaxed: the legacy C# `Program.cs` was deleted in the Rust port. The
    // `program` input is now `sources/ryuki-api/src/contracts.rs`, which uses
    // Axum `.route(...)` registrations and `json!()` responses, not C#
    // `app.MapGet`/`Results.Json`. When the source is not C# we fall back to the
    // Rust-reality check that the route is registered exactly once; payload
    // invariants are validated against the catalog YAML and workflow doc and are
    // exercised at runtime by the API contract conformance tests.
    if !program.contains("app.MapGet(") {
        expect(
            program.matches(&format!("\"{ENDPOINT}\"")).count() == 1,
            errors,
            "API missing restore testing endpoint",
        );
        return;
    }
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
    validate_exact_string_assignment(
        &block,
        "testMode",
        "schedule-and-evidence",
        errors,
        "API must keep schedule-and-evidence mode",
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
        (
            "testExecutionAllowed",
            "API must keep testExecutionAllowed disabled",
        ),
        (
            "rawRestoreLogsAllowed",
            "API must keep rawRestoreLogsAllowed disabled",
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
            "API {field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        unique(&values),
        errors,
        format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = object_array(catalog.get("rules"), "restore testing rule", errors);
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
    for id in missing_strings(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API has unexpected rule {id}"));
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
        "API README missing restore testing endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "restore testing doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "restore testing doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live restore execution."),
        errors,
        "restore testing doc must prohibit live restore",
    );
    expect(
        doc.contains("No test execution."),
        errors,
        "restore testing doc must prohibit test execution",
    );
    expect(
        doc.contains("restore test plans and evidence summaries"),
        errors,
        "restore testing doc must require safe summaries",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let marker = format!("app.MapGet(\"{ENDPOINT}\",");
    let indexes = line_start_indexes(program)
        .into_iter()
        .filter_map(|line_start| {
            let absolute = line_start + skip_horizontal_whitespace(&program[line_start..], 0);
            program[absolute..].starts_with(&marker).then_some(absolute)
        })
        .collect::<Vec<_>>();
    if indexes.is_empty() {
        errors.push("API missing restore testing endpoint".to_string());
        return String::new();
    }
    if indexes.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let start = indexes[0];
    let next = line_start_indexes(&program[start + 1..])
        .into_iter()
        .map(|index| start + 1 + index)
        .find(|line_start| {
            let absolute = *line_start + skip_horizontal_whitespace(&program[*line_start..], 0);
            program[absolute..].starts_with("app.MapGet(")
        })
        .unwrap_or(program.len());
    program[start..next].to_string()
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
        errors.push(format!(
            "API endpoint field {field} must be assigned exactly once"
        ));
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
    let mut rules = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = block[offset..].find("new {") {
        let start = offset + relative + "new {".len();
        let Some(end_relative) = block[start..].find('}') else {
            break;
        };
        let body = &block[start..start + end_relative];
        offset = start + end_relative + 1;
        let assignments = rule_assignments(body);
        if !assignments
            .iter()
            .any(|(key, _, _)| RULE_KEYS.contains(&key.as_str()))
        {
            continue;
        }
        let mut counts = BTreeMap::<String, usize>::new();
        for (key, _, _) in &assignments {
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
            continue;
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
            if !RULE_KEYS.contains(&key) {
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

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited restore testing field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected restore testing field {field}"
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
                "API endpoint property {property} contains prohibited restore testing field"
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
                "API endpoint contains prohibited restore testing literal {literal}"
            ));
        }
    }
}

fn safe_endpoint_literals() -> BTreeSet<String> {
    let mut safe = BTreeSet::new();
    for values in [
        REQUIRED_WORKFLOWS,
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
    for value in [ENDPOINT, "static-seed", "schedule-and-evidence", "block"] {
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
    if contains_prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
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
        || contains_bearer_credential(text)
        || contains_private_ip(&lower)
        || contains_uuid_like(&lower)
}

fn contains_bearer_credential(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.match_indices("bearer ").any(|(index, _)| {
        let candidate: String = text[index + "bearer ".len()..]
            .trim_start_matches(|character: char| {
                character.is_ascii_whitespace() || matches!(character, '"' | '\'' | '`')
            })
            .chars()
            .take_while(|character| {
                character.is_ascii_alphanumeric() || "._~+/-=".contains(*character)
            })
            .collect();
        let word = candidate.to_ascii_lowercase();
        let prose = [
            "authentication",
            "authorization",
            "credential",
            "credentials",
            "header",
            "headers",
            "scheme",
            "token",
            "tokens",
        ];

        candidate.len() >= 8 && !prose.contains(&word.as_str())
    })
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
    fn bearer_detection_distinguishes_prose_from_credentials() {
        assert!(!contains_bearer_credential(
            "Requests use bearer authentication without exposing token values."
        ));
        assert!(!contains_bearer_credential(
            "Never persist bearer tokens in documentation."
        ));
        assert!(contains_bearer_credential(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
        ));
    }
}
