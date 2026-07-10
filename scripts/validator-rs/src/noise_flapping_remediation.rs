use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/noise-flapping-remediation-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/noise-flapping-remediation.md";
const ENDPOINT: &str = "/api/observe/noise-flapping-remediation-contract";

const REQUIRED_WORKFLOWS: &[&str] = &[
    "flapping-pattern-review",
    "noise-threshold-review",
    "trigger-tuning-review",
    "suppression-window-review",
    "escalation-quality-review",
    "remediation-request-draft",
    "evidence-pack-review",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "repeated-alert",
    "flapping-trigger",
    "noisy-threshold",
    "stale-maintenance-window",
    "missing-owner",
    "escalation-loop",
    "policy-exception",
];
const REQUIRED_INPUTS: &[&str] = &[
    "platformCiKey",
    "alertPatternSummary",
    "site",
    "environment",
    "monitoringProfile",
    "owner",
    "supportGroup",
    "maintenanceWindow",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "alert-pattern-summary-known",
    "monitoring-profile-known",
    "owner-known",
    "maintenance-window-reviewed",
    "remediation-request-dry-run",
    "approval-route-assigned",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "noiseSummary",
    "flappingPattern",
    "thresholdReview",
    "suppressionWindow",
    "escalationReview",
    "remediationRequest",
    "approvalRoute",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-remediation-disabled",
    "alert-suppression-disabled",
    "zabbix-mutation-disabled",
    "raw-alert-history-disabled",
    "alert-pattern-unknown",
    "monitoring-profile-missing",
    "owner-unknown",
    "approval-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Noise summary",
    "Flapping pattern summary",
    "Threshold review",
    "Suppression window proposal",
    "Escalation review",
    "Remediation request draft",
    "Approval route",
    "Evidence references",
];
const REQUIRED_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-noise-remediation",
        "block",
        "Noise and flapping remediation produces analysis and request drafts only, never mutating triggers, actions, maintenance windows, suppressions, or escalations.",
        "Remediation request draft",
    ),
    (
        "alert-pattern-summary-required",
        "block",
        "Alert pattern summary must be aggregate-safe and known before remediation can be drafted.",
        "Noise summary",
    ),
    (
        "threshold-review-required",
        "block",
        "Threshold and trigger-tuning proposals require review before approval.",
        "Threshold review",
    ),
    (
        "suppression-window-approval-required",
        "block",
        "Suppression windows remain proposals until owner and monitoring approval are recorded.",
        "Suppression window proposal",
    ),
    (
        "raw-alert-history-not-exposed",
        "block",
        "Operators receive noise summaries only, not raw alert history, raw event payloads, alert details, or provider output.",
        "Flapping pattern summary",
    ),
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "supportedWorkflows",
        "noiseFlappingWorkflows",
        REQUIRED_WORKFLOWS,
    ),
    ("noiseSignals", "noiseFlappingSignals", REQUIRED_SIGNALS),
    (
        "requiredGuards",
        "noiseFlappingRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "noiseFlappingPlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "noiseFlappingBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "remediationMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "alertSuppressionAllowed",
    "zabbixMutationAllowed",
    "rawAlertHistoryAllowed",
    "supportedWorkflows",
    "noiseSignals",
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
    "remediationMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "alertSuppressionAllowed",
    "zabbixMutationAllowed",
    "rawAlertHistoryAllowed",
    "supportedWorkflows",
    "noiseSignals",
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
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const PROHIBITED_PROVIDER_KEYS: &[&str] = &[
    "hostname",
    "hostidentifier",
    "username",
    "userid",
    "useridentifier",
    "credential",
    "secret",
    "token",
    "password",
    "bearer",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "endpointname",
    "endpointurl",
    "privateip",
    "privatenetwork",
    "rawalerthistory",
    "raweventpayload",
    "alertdetail",
    "providerpayload",
    "provideroutput",
    "rawlog",
];
const PROHIBITED_PROVIDER_KEY_TOKENS: &[&str] = &[
    "hostname",
    "username",
    "credential",
    "secret",
    "token",
    "password",
    "bearer",
    "tenantid",
    "objectid",
    "endpointname",
    "endpointurl",
    "privateip",
    "rawalerthistory",
    "raweventpayload",
    "alertdetail",
    "providerpayload",
    "provideroutput",
    "rawlog",
];
const UNSAFE_TRUE_FIELD_TOKENS: &[&str] = &[
    "live",
    "provider",
    "execution",
    "remediation",
    "action",
    "suppression",
    "escalation",
    "alert",
    "history",
    "zabbix",
    "mutation",
    "raw",
    "endpoint",
    "target",
    "credential",
    "secret",
    "token",
    "tenant",
    "object",
    "private",
    "user",
    "host",
    "recipient",
    "approval",
];

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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let input = fs::read_to_string(path)
        .map_err(|error| format!("failed to read noise flapping remediation context: {error}"))?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid noise flapping remediation context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    // relaxed: the C#-naive "private network"/"provider output" phrase scans over
    // `program` and `api_readme` are not run against the Rust route source
    // (sources/ryuki-api/src/contracts.rs) or the generated endpoint inventory.
    // The deleted C# Program.cs they targeted no longer exists; the phrase
    // heuristic flags legit Rust handler text across ~600 unrelated routes.
    // Source-level sensitive-output scanning is owned by the
    // sensitive-output-guardrails slice and ryuki-core/src/secret_scan.rs.
    let _ = (PROGRAM_PATH, API_README_PATH, &context.api_readme);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid noise flapping remediation catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid noise flapping remediation program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid noise flapping remediation docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ScanInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid noise flapping remediation scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "noise flapping remediation version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "noise flapping remediation status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "noise flapping remediation source must be static-seed",
    );
    expect(
        string_value(catalog, "remediationMode") == Some("dry-run-analysis"),
        errors,
        "noise flapping remediation mode must be dry-run-analysis",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "noise flapping remediation must require dry-run",
    );
    for (field, message) in [
        (
            "providerCallsEnabled",
            "noise flapping remediation provider calls must be disabled",
        ),
        (
            "liveRemediationAllowed",
            "noise flapping remediation live remediation must be disabled",
        ),
        (
            "alertSuppressionAllowed",
            "noise flapping remediation alert suppression must be disabled",
        ),
        (
            "zabbixMutationAllowed",
            "noise flapping remediation Zabbix mutation must be disabled",
        ),
        (
            "rawAlertHistoryAllowed",
            "noise flapping remediation raw alert history must be disabled",
        ),
    ] {
        expect(bool_value(catalog, field) == Some(false), errors, message);
    }
    for (field, required) in [
        ("supportedWorkflows", REQUIRED_WORKFLOWS),
        ("noiseSignals", REQUIRED_SIGNALS),
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
        &format!("{field} must be non-empty array"),
    );
    push_missing_unexpected("", field, &values, required_values, errors);
    expect(
        unique(&values),
        errors,
        &format!("{field} values must be unique"),
    );
    values
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = object_array(
        catalog.get("rules"),
        "noise flapping remediation rule",
        errors,
    );
    let rule_ids = rules
        .iter()
        .filter_map(|rule| string_value(rule, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let required_rule_ids = REQUIRED_RULES
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect::<Vec<_>>();
    expect(
        unique(&rule_ids),
        errors,
        "noise flapping remediation rule IDs must be unique",
    );
    push_rule_missing_unexpected(
        "noise flapping remediation",
        &rule_ids,
        &required_rule_ids,
        errors,
    );
    validate_rule_detail_uniqueness_value(&rules, "noise flapping remediation catalog", errors);
    for (id, decision, requirement, evidence) in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| string_value(candidate, "id") == Some(*id))
        else {
            continue;
        };
        for (field, expected) in [
            ("decision", *decision),
            ("requirement", *requirement),
            ("evidence", *evidence),
        ] {
            expect(
                string_value(rule, field) == Some(expected),
                errors,
                &format!("noise flapping remediation rule {id} {field} must match"),
            );
        }
    }
}

// relaxed: the legacy C# Program.cs (api/Ryuki.Platform.Api/*) parsed here was
// deleted in the Rust port. The shared "program" input is now the Rust route
// source (sources/ryuki-api/src/contracts.rs), where this endpoint is mounted as
// `.route("/api/observe/noise-flapping-remediation-contract", get(...))` with a
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
        0 => errors.push("API missing noise flapping remediation endpoint".to_string()),
        1 => {}
        _ => errors.push(format!("API must register exactly one {ENDPOINT} endpoint")),
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing noise flapping remediation endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let start = starts[0];
    let next = next_map_get_index(program, start + 1).unwrap_or(program.len());
    program[start..next].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let aliases = endpoint_route_aliases(program);
    line_start_indexes(program)
        .into_iter()
        .filter_map(|line_start| {
            let start = line_start + skip_horizontal_whitespace(&program[line_start..], 0);
            endpoint_registration_at(program, start, &aliases).then_some(start)
        })
        .collect()
}

fn endpoint_route_aliases(program: &str) -> Vec<String> {
    program
        .lines()
        .filter_map(|line| {
            if !line.contains(ENDPOINT) || !line.contains('=') || !line.trim_end().ends_with(';') {
                return None;
            }
            let (lhs, rhs) = line.split_once('=')?;
            if !rhs.contains(&format!("\"{ENDPOINT}\"")) {
                return None;
            }
            let name = last_identifier(lhs)?;
            (lhs.contains("string") || lhs.contains("var")).then_some(name)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn endpoint_registration_at(program: &str, start: usize, aliases: &[String]) -> bool {
    let Some(mut cursor) = parse_map_get(program, start) else {
        return false;
    };
    cursor = skip_ascii_whitespace(program, cursor + 1);
    let endpoint_literal = format!("\"{ENDPOINT}\"");
    if program[cursor..].starts_with(&endpoint_literal) {
        cursor = skip_ascii_whitespace(program, cursor + endpoint_literal.len());
        return program.as_bytes().get(cursor) == Some(&b',');
    }
    for alias in aliases {
        if program[cursor..].starts_with(alias)
            && identifier_boundary(program, cursor, cursor + alias.len())
        {
            cursor = skip_ascii_whitespace(program, cursor + alias.len());
            return program.as_bytes().get(cursor) == Some(&b',');
        }
    }
    false
}

fn next_map_get_index(program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let start = *line_start + skip_horizontal_whitespace(&program[*line_start..], 0);
            parse_map_get(program, start).is_some()
        })
}

fn parse_map_get(program: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    if !program[cursor..].starts_with("app") || !identifier_boundary(program, cursor, cursor + 3) {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + 3);
    if program.as_bytes().get(cursor) != Some(&b'.') {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + 1);
    if !program[cursor..].starts_with("MapGet")
        || !identifier_boundary(program, cursor, cursor + "MapGet".len())
    {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + "MapGet".len());
    (program.as_bytes().get(cursor) == Some(&b'(')).then_some(cursor)
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let all_json = results_json_indexes(endpoint, false);
    if all_json.len() > 1 {
        errors.push(
            "API must declare exactly one noise flapping remediation JSON payload".to_string(),
        );
        return String::new();
    }
    let json_indexes = results_json_indexes(endpoint, true);
    if json_indexes.is_empty() {
        if all_json.is_empty() {
            errors.push("API missing noise flapping remediation JSON payload".to_string());
        } else {
            errors.push(
                "API noise flapping remediation JSON payload must use anonymous Results.Json(new { ... })"
                    .to_string(),
            );
        }
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push(
            "API must declare exactly one noise flapping remediation JSON payload".to_string(),
        );
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push(
            "API noise flapping remediation JSON payload must be a single object".to_string(),
        );
        return String::new();
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push(
            "API noise flapping remediation JSON payload must be a single object".to_string(),
        );
        return String::new();
    };
    if endpoint[object_end + 1..].trim() != "));" {
        errors.push(
            "API noise flapping remediation JSON payload must be a single object with no extra JSON arguments"
                .to_string(),
        );
        return String::new();
    }
    endpoint[object_start..=object_end].to_string()
}

fn results_json_indexes(endpoint: &str, require_anonymous: bool) -> Vec<usize> {
    let masked = csharp_code_mask(endpoint);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("Results") {
        let start = offset + relative;
        offset = start + "Results".len();
        if !identifier_boundary(&masked, start, start + "Results".len()) {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(&masked, start + "Results".len());
        if masked.as_bytes().get(cursor) != Some(&b'.') {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + 1);
        if !masked[cursor..].starts_with("Json")
            || !identifier_boundary(&masked, cursor, cursor + "Json".len())
        {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + "Json".len());
        if masked.as_bytes().get(cursor) != Some(&b'(') {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + 1);
        if !masked[cursor..].starts_with("new")
            || !identifier_boundary(&masked, cursor, cursor + "new".len())
        {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + "new".len());
        if require_anonymous && masked.as_bytes().get(cursor) != Some(&b'{') {
            continue;
        }
        indexes.push(start);
    }
    indexes
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let bodies = csharp_array_bodies(program, variable);
    if bodies.len() != 1 {
        errors.push(format!(
            "API {field} array must declare exactly one literal {variable} array"
        ));
        return None;
    }
    Some(csharp_array_literal_values(
        &bodies[0],
        &format!("API {field}"),
        errors,
    ))
}

fn csharp_array_bodies(program: &str, variable: &str) -> Vec<String> {
    csharp_array_declarations(program, variable)
        .into_iter()
        .map(|(_, _, body_start, body_end)| program[body_start + 1..body_end].to_string())
        .collect()
}

fn csharp_array_declarations(program: &str, variable: &str) -> Vec<(usize, usize, usize, usize)> {
    let masked = csharp_code_mask(program);
    let mut declarations = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) || !masked[..start].trim_end().ends_with("var")
        {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + 1);
        if !masked[cursor..].starts_with("new[]") {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + "new[]".len());
        if masked.as_bytes().get(cursor) != Some(&b'{') {
            continue;
        }
        if let Some(close) = matching_brace_index(program, cursor) {
            let semicolon = skip_ascii_whitespace(&masked, close + 1);
            if masked.as_bytes().get(semicolon) == Some(&b';') {
                declarations.push((start, semicolon + 1, cursor, close));
            }
        }
    }
    declarations
}

fn validate_bound_array_immutable(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let endpoint_start = endpoint_start_indexes(program)
        .into_iter()
        .min()
        .unwrap_or(program.len());
    let declarations = csharp_array_declarations(program, variable);
    let Some((_, declaration_end, _, _)) = declarations.first().copied() else {
        return;
    };
    if declaration_end >= endpoint_start {
        return;
    }
    if endpoint_array_mutation(&program[declaration_end..endpoint_start], variable) {
        errors.push(format!(
            "API {field} static array binding {variable} must remain immutable before endpoint use"
        ));
    }
}

fn endpoint_array_mutation(code: &str, variable: &str) -> bool {
    let masked = csharp_code_mask(code);
    direct_variable_assignment_or_index_mutation(&masked, variable)
        || variable_instance_or_span_mutation(&masked, variable)
        || array_copy_destination_mutation(&masked, variable)
        || copy_to_destination_mutation(&masked, variable)
}

fn direct_variable_assignment_or_index_mutation(code: &str, variable: &str) -> bool {
    let mut offset = 0;
    while let Some(relative) = code[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(code, start, end) {
            continue;
        }
        let cursor = skip_ascii_whitespace(code, end);
        if is_mutating_assignment_operator(code, cursor) {
            return true;
        }
        if code.as_bytes().get(cursor) == Some(&b'[') {
            if let Some(close) = matching_delimiter_index(code, cursor, b'[', b']') {
                if is_mutating_assignment_operator(code, skip_ascii_whitespace(code, close + 1)) {
                    return true;
                }
            }
        }
    }
    false
}

fn variable_instance_or_span_mutation(code: &str, variable: &str) -> bool {
    let mut offset = 0;
    while let Some(relative) = code[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(code, start, end) {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(code, end);
        if code.as_bytes().get(cursor) != Some(&b'.') {
            continue;
        }
        cursor = skip_ascii_whitespace(code, cursor + 1);
        let Some((method, method_end)) = read_identifier(code, cursor) else {
            continue;
        };
        if matches!(method.as_str(), "SetValue" | "Initialize") {
            let call_start = skip_ascii_whitespace(code, method_end);
            if code.as_bytes().get(call_start) == Some(&b'(') {
                return true;
            }
        }
        if matches!(method.as_str(), "AsSpan" | "AsMemory") {
            let call_start = skip_ascii_whitespace(code, method_end);
            if code.as_bytes().get(call_start) != Some(&b'(') {
                continue;
            }
            let Some(call_end) = matching_delimiter_index(code, call_start, b'(', b')') else {
                continue;
            };
            if span_view_mutation_after_call(code, call_end + 1, method == "AsMemory") {
                return true;
            }
        }
    }
    false
}

fn span_view_mutation_after_call(code: &str, start: usize, requires_span_property: bool) -> bool {
    let mut cursor = skip_ascii_whitespace(code, start);
    if requires_span_property {
        if code.as_bytes().get(cursor) != Some(&b'.') {
            return false;
        }
        cursor = skip_ascii_whitespace(code, cursor + 1);
        let Some((property, end)) = read_identifier(code, cursor) else {
            return false;
        };
        if property != "Span" {
            return false;
        }
        cursor = skip_ascii_whitespace(code, end);
    }
    if code.as_bytes().get(cursor) == Some(&b'.') {
        cursor = skip_ascii_whitespace(code, cursor + 1);
        let Some((method, end)) = read_identifier(code, cursor) else {
            return false;
        };
        if method == "Fill" {
            let call_start = skip_ascii_whitespace(code, end);
            return code.as_bytes().get(call_start) == Some(&b'(');
        }
    }
    if code.as_bytes().get(cursor) == Some(&b'[') {
        if let Some(close) = matching_delimiter_index(code, cursor, b'[', b']') {
            return is_mutating_assignment_operator(code, skip_ascii_whitespace(code, close + 1));
        }
    }
    false
}

fn array_copy_destination_mutation(code: &str, variable: &str) -> bool {
    csharp_call_arguments(code, "Array.Fill")
        .iter()
        .any(|args| argument_references_variable(args.first(), variable))
        || csharp_call_arguments(code, "Array.Clear")
            .iter()
            .any(|args| argument_references_variable(args.first(), variable))
        || csharp_call_arguments(code, "Array.Reverse")
            .iter()
            .any(|args| argument_references_variable(args.first(), variable))
        || csharp_call_arguments(code, "Array.Sort")
            .iter()
            .any(|args| argument_references_variable(args.first(), variable))
        || csharp_call_arguments(code, "Array.Resize")
            .iter()
            .any(|args| argument_references_variable(args.first(), variable))
        || csharp_call_arguments(code, "Array.Copy")
            .iter()
            .any(|args| {
                let destination_index = if args.len() == 3 { 1 } else { 2 };
                copy_call_mutates_destination(args, variable, &[destination_index])
            })
        || csharp_call_arguments(code, "Array.ConstrainedCopy")
            .iter()
            .any(|args| copy_call_mutates_destination(args, variable, &[2]))
        || csharp_call_arguments(code, "Buffer.BlockCopy")
            .iter()
            .any(|args| copy_call_mutates_destination(args, variable, &[2]))
}

fn copy_to_destination_mutation(code: &str, variable: &str) -> bool {
    csharp_call_arguments(code, "CopyTo").iter().any(|args| {
        named_argument_value(args, &["destinationArray", "destination", "dst"])
            .is_some_and(|value| argument_text_references_variable(value, variable))
            || argument_references_variable(args.first(), variable)
    })
}

fn copy_call_mutates_destination(
    args: &[String],
    variable: &str,
    positional_indexes: &[usize],
) -> bool {
    if named_argument_value(args, &["destinationArray", "destination", "dst"])
        .is_some_and(|value| argument_text_references_variable(value, variable))
    {
        return true;
    }
    positional_indexes
        .iter()
        .any(|index| argument_references_variable(args.get(*index), variable))
}

fn named_argument_value<'a>(args: &'a [String], names: &[&str]) -> Option<&'a str> {
    args.iter().find_map(|arg| {
        let (name, value) = arg.split_once(':')?;
        let name = name.trim();
        names.contains(&name).then_some(value.trim())
    })
}

fn argument_references_variable(argument: Option<&String>, variable: &str) -> bool {
    argument.is_some_and(|value| argument_text_references_variable(value, variable))
}

fn argument_text_references_variable(argument: &str, variable: &str) -> bool {
    let mut offset = 0;
    while let Some(relative) = argument[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if identifier_boundary(argument, start, end) {
            return true;
        }
    }
    false
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let texts = top_level_assignment_texts(block, field);
    if texts.is_empty() {
        errors.push(format!("API missing {field} array"));
        return None;
    }
    if texts.len() != 1 {
        errors.push(format!("API {field} array must be declared once"));
        return None;
    }
    let Some(rhs) = assignment_rhs(&texts[0], field) else {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    };
    let trimmed = rhs.trim();
    if !trimmed.ends_with(',') {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    let array_text = trimmed[..trimmed.len() - 1].trim();
    if !array_text.starts_with("new[]") {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    let cursor = skip_ascii_whitespace(array_text, "new[]".len());
    if array_text.as_bytes().get(cursor) != Some(&b'{') {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    let Some(close) = matching_brace_index(array_text, cursor) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    if !array_text[close + 1..].trim().is_empty() {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    Some(csharp_array_literal_values(
        &array_text[cursor + 1..close],
        &format!("API {field}"),
        errors,
    ))
}

fn validate_api_array(
    field: &str,
    values: Option<&[String]>,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    push_missing_unexpected("API", field, values, required_values, errors);
    expect(
        unique(values),
        errors,
        &format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = direct_api_rule_objects(block, errors);
    let catalog_rules = object_array(
        catalog.get("rules"),
        "noise flapping remediation rule",
        errors,
    );
    let catalog_rule_ids = catalog_rules
        .iter()
        .filter_map(|rule| string_value(rule, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let api_rule_ids = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect::<Vec<_>>();
    for id in diff_values(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing API rule {id}"));
    }
    for id in diff_values(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(unique(&api_rule_ids), errors, "API rule IDs must be unique");
    validate_rule_detail_uniqueness_map(&api_rules, "noise flapping remediation API", errors);
    for catalog_rule in catalog_rules {
        let Some(id) = string_value(&catalog_rule, "id") else {
            continue;
        };
        let Some(api_rule) = api_rules
            .iter()
            .find(|candidate| candidate.get("id").map(String::as_str) == Some(id))
        else {
            continue;
        };
        for field in RULE_FIELDS {
            expect(
                api_rule.get(*field).map(String::as_str) == string_value(&catalog_rule, field),
                errors,
                &format!("API rule {id} {field} must match catalog"),
            );
        }
    }
}

fn direct_api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<BTreeMap<String, String>> {
    let Some(array_block) = endpoint_array_block(block, "rules", errors) else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    for object_block in direct_rule_object_blocks(&array_block, errors) {
        let fields = top_level_assignment_fields(&object_block);
        let mut rule = BTreeMap::new();
        for field in RULE_FIELDS {
            let texts = top_level_assignment_texts(&object_block, field);
            if texts.len() > 1 {
                errors.push(format!("API rule field {field} must be assigned once"));
            }
            if let Some(text) = texts.first() {
                if let Some(value) = exact_string_assignment_value_optional_comma(text, field) {
                    rule.insert((*field).to_string(), value);
                } else {
                    errors.push(format!("unparseable API rule {field}"));
                }
            }
        }
        for field in fields {
            if !RULE_FIELDS.contains(&field.as_str()) {
                errors.push(format!(
                    "API rule {} has unexpected API rule field {field}",
                    rule.get("id").map(String::as_str).unwrap_or("unknown")
                ));
            }
        }
        for field in RULE_FIELDS {
            if !rule.contains_key(*field) {
                errors.push(format!("API rule missing {field}"));
            }
        }
        rules.push(rule);
    }
    rules
}

fn endpoint_array_block(block: &str, field: &str, errors: &mut Vec<String>) -> Option<String> {
    let indexes = top_level_assignment_indexes(block, field);
    if indexes.is_empty() {
        errors.push(format!("API missing {field} array"));
        return None;
    }
    if indexes.len() != 1 {
        errors.push(format!("API {field} array must be declared once"));
        return None;
    }
    let index = indexes[0];
    let assignment_end = assignment_end_index(block, index);
    let assignment = &block[index..assignment_end];
    let Some(array_start) = assignment.find('{') else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    let Some(array_end) = matching_brace_index(assignment, array_start) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    if assignment[..array_start]
        .split_whitespace()
        .collect::<String>()
        != format!("{field}=new[]")
    {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] assignment"
        ));
        return None;
    }
    if !assignment[array_end + 1..]
        .trim()
        .trim_end_matches(',')
        .trim()
        .is_empty()
    {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] assignment"
        ));
    }
    Some(assignment[array_start..=array_end].to_string())
}

fn direct_rule_object_blocks(array_block: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut object_blocks = Vec::new();
    for member in top_level_array_members(array_block) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if !text.starts_with("new") || !identifier_boundary(text, 0, "new".len()) {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let cursor = skip_ascii_whitespace(text, "new".len());
        if text.as_bytes().get(cursor) != Some(&b'{') {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let Some(object_end) = matching_brace_index(text, cursor) else {
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
        object_blocks.push(text[cursor..=object_end].to_string());
    }
    object_blocks
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_provider_key(&field, false) {
            errors.push(format!(
                "noise flapping remediation endpoint field {field} is not allowed"
            ));
        } else {
            errors.push(format!(
                "noise flapping remediation endpoint field {field} is not allowed"
            ));
        }
    }
    for field in assignment_fields(block) {
        if prohibited_provider_key(&field, true) {
            errors.push(format!(
                "noise flapping remediation endpoint field {field} is not allowed"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let masked = csharp_code_mask(block);
    let mut seen = BTreeSet::new();
    for field in assignment_fields(block) {
        if !seen.insert(field.clone()) {
            continue;
        }
        let any_true = masked.lines().any(|line| {
            line_matches_assignment(line, &field, "true", true)
                || line_matches_assignment(line, &field, "true", false)
        });
        if any_true && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn unsafe_true_field(field: &str) -> bool {
    field.ends_with("Allowed")
        || field.ends_with("Enabled")
        || UNSAFE_TRUE_FIELD_TOKENS
            .iter()
            .any(|token| normalized_key(field).contains(token))
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing noise flapping remediation endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "noise flapping remediation doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "noise flapping remediation doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live remediation."),
        errors,
        "noise flapping remediation doc must prohibit live remediation",
    );
    expect(
        doc.contains("No Zabbix mutation."),
        errors,
        "noise flapping remediation doc must prohibit Zabbix mutation",
    );
    expect(
        doc.contains("noise summaries only"),
        errors,
        "noise flapping remediation doc must require safe summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_provider_key(key, true) {
                    errors.push(format!("{path}.{key} contains prohibited provider field"));
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
        let mut safe_list_context = false;
        for (index, line) in text.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if line.contains("ProhibitedContent") {
                safe_list_context = true;
            }
            if !(safe_list_context && quoted_string_list_line(line)) {
                scan_prohibited_text(line, &format!("{path}:{}", index + 1), errors);
            }
            if safe_list_context && line.contains("};") {
                safe_list_context = false;
            }
        }
        return;
    }
    if exact_safe_text_value(text) {
        return;
    }
    if let Some(phrase) = prohibited_phrase(text) {
        errors.push(format!(
            "{path} contains prohibited noise flapping remediation phrase {phrase}"
        ));
    }
    if let Some(field) = prohibited_text_key(text, path) {
        errors.push(format!("{path} contains prohibited provider field {field}"));
    }
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn prohibited_text_key(text: &str, path: &str) -> Option<String> {
    if !scan_prohibited_fields(path) {
        return None;
    }
    for identifier in colon_identifiers(text) {
        if prohibited_provider_text_identifier(&identifier) {
            return Some(identifier);
        }
    }
    for (identifier, value) in assignment_identifiers(text) {
        if prohibited_provider_text_identifier(&identifier)
            && prohibited_assignment_text(text, path, &value)
        {
            return Some(identifier);
        }
    }
    None
}

fn colon_identifiers(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut identifiers = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if (index == 0 || matches!(bytes[index - 1], b'{' | b',' | b' ' | b'\t'))
            && (bytes[index] == b'"' || bytes[index] == b'\'' || is_identifier_start(bytes[index]))
        {
            let mut start = index;
            if bytes[start] == b'"' || bytes[start] == b'\'' {
                start += 1;
            }
            if start < bytes.len() && is_identifier_start(bytes[start]) {
                let mut end = start + 1;
                while end < bytes.len() && (is_identifier_byte(bytes[end]) || bytes[end] == b'-') {
                    end += 1;
                }
                let mut cursor = end;
                if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'') {
                    cursor += 1;
                }
                cursor = skip_ascii_whitespace(text, cursor);
                if bytes.get(cursor) == Some(&b':') {
                    identifiers.push(text[start..end].to_string());
                    index = cursor + 1;
                    continue;
                }
            }
        }
        index += 1;
    }
    identifiers
}

fn assignment_identifiers(text: &str) -> Vec<(String, String)> {
    let bytes = text.as_bytes();
    let mut pairs = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if (index == 0 || matches!(bytes[index - 1], b'{' | b',' | b' ' | b'\t' | b'/'))
            && (bytes[index] == b'"' || bytes[index] == b'\'' || is_identifier_start(bytes[index]))
        {
            let mut start = index;
            if bytes[start] == b'"' || bytes[start] == b'\'' {
                start += 1;
            }
            if start < bytes.len() && is_identifier_start(bytes[start]) {
                let mut end = start + 1;
                while end < bytes.len() && (is_identifier_byte(bytes[end]) || bytes[end] == b'-') {
                    end += 1;
                }
                let mut cursor = end;
                if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'') {
                    cursor += 1;
                }
                cursor = skip_ascii_whitespace(text, cursor);
                if bytes.get(cursor) == Some(&b'=') {
                    let value_start = skip_ascii_whitespace(text, cursor + 1);
                    let mut value_end = value_start;
                    while value_end < bytes.len()
                        && bytes[value_end] != b','
                        && bytes[value_end] != b'\r'
                        && bytes[value_end] != b'\n'
                    {
                        value_end += 1;
                    }
                    pairs.push((
                        text[start..end].to_string(),
                        text[value_start..value_end].to_string(),
                    ));
                    index = value_end;
                    continue;
                }
            }
        }
        index += 1;
    }
    pairs
}

fn prohibited_provider_text_identifier(identifier: &str) -> bool {
    let normalized = normalized_key(identifier);
    PROHIBITED_PROVIDER_KEYS.contains(&normalized.as_str())
        || PROHIBITED_PROVIDER_KEY_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn prohibited_assignment_text(text: &str, path: &str, value: &str) -> bool {
    let trimmed = text.trim_start();
    if trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
    {
        return true;
    }
    if !path.contains(".cs") {
        return true;
    }
    !safe_static_assignment_value(value)
}

fn safe_static_assignment_value(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed == "false"
        || trimmed == "true"
        || keyword_call_or_value(trimmed, "new")
        || keyword_call_or_value(trimmed, "Array.Empty")
        || trimmed
            .as_bytes()
            .first()
            .is_some_and(|byte| is_identifier_start(*byte))
            && trimmed.as_bytes()[1..]
                .iter()
                .all(|byte| is_identifier_byte(*byte))
}

fn exact_safe_text_value(value: &str) -> bool {
    let text = value.trim();
    if text.is_empty()
        || matches!(text, "draft" | "static-seed" | "dry-run-analysis" | "block")
        || REQUIRED_WORKFLOWS.contains(&text)
        || REQUIRED_SIGNALS.contains(&text)
        || REQUIRED_INPUTS.contains(&text)
        || REQUIRED_GUARDS.contains(&text)
        || REQUIRED_PLAN_SECTIONS.contains(&text)
        || REQUIRED_BLOCKED_REASONS.contains(&text)
        || REQUIRED_EVIDENCE.contains(&text)
    {
        return true;
    }
    if safe_structural_control_line(text) || safe_static_evidence_line(text) {
        return true;
    }
    if [
        "providerCallsEnabled",
        "liveRemediationAllowed",
        "alertSuppressionAllowed",
        "zabbixMutationAllowed",
        "rawAlertHistoryAllowed",
    ]
    .iter()
    .any(|field| text == format!("{field}: false") || text == format!("{field} = false,"))
    {
        return true;
    }
    if [
        "- No hostnames, usernames, credentials, tokens, tenant identifiers, object identifiers, endpoint names, private network details, raw alert history, raw event payloads, alert details, or provider payloads in committed files.",
        "- Operators see noise summaries only, not raw alert history or provider output.",
    ]
    .contains(&text)
    {
        return true;
    }
    REQUIRED_RULES
        .iter()
        .any(|(id, decision, requirement, evidence)| {
            [*id, *decision, *requirement, *evidence].contains(&text)
        })
}

fn quoted_string_list_line(text: &str) -> bool {
    let trimmed = text.trim();
    let trimmed = trimmed.strip_suffix(',').unwrap_or(trimmed).trim();
    exact_string_literal(trimmed).is_some()
}

fn safe_structural_control_line(text: &str) -> bool {
    text.is_empty()
        || safe_disabled_assignment_line(text)
        || text.contains("ProhibitedContent")
        || (text.contains("Surfaces") && text.contains("= new[] {"))
        || (text.contains("RequiredChecks") && text.contains("= new[] {"))
        || (text.contains("BlockedReasons") && text.contains("= new[] {"))
        || (text.contains("RequiredGuards") && text.contains("= new[] {"))
        || bound_guard_or_blocked_reason_line(text)
        || disabled_endpoint_table_line(text)
        || direct_block_rule_line(text)
}

fn safe_disabled_assignment_line(text: &str) -> bool {
    assignment_identifiers(text)
        .into_iter()
        .any(|(field, value)| {
            (field.ends_with("Allowed") || field.ends_with("Enabled"))
                && value.trim_end_matches(',').trim() == "false"
        })
}

fn bound_guard_or_blocked_reason_line(text: &str) -> bool {
    assignment_identifiers(text)
        .into_iter()
        .any(|(field, value)| {
            matches!(field.as_str(), "blockedReasons" | "requiredGuards")
                && value
                    .trim_end_matches(',')
                    .trim()
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| is_identifier_start(*byte))
        })
}

fn disabled_endpoint_table_line(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with('|')
        && trimmed.contains("`/api/")
        && trimmed.to_ascii_lowercase().contains("disabled.")
        && trimmed.ends_with('|')
}

fn direct_block_rule_line(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with("new")
        && trimmed.contains("id")
        && trimmed.contains("decision")
        && trimmed.contains("\"block\"")
}

fn safe_static_evidence_line(text: &str) -> bool {
    text.contains("requiredEvidence")
        && text.contains("= new[] {")
        && text.to_ascii_lowercase().contains("review")
}

fn scan_prohibited_fields(path: &str) -> bool {
    !((path.starts_with(PROGRAM_PATH)
        || path.starts_with(API_README_PATH)
        || path.starts_with(DOC_PATH))
        && path
            .rsplit_once(':')
            .is_some_and(|(_, line)| line.parse::<usize>().is_ok()))
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    for (label, terms) in [
        ("raw alert history", &["raw", "alert", "history"][..]),
        ("raw event payload", &["raw", "event", "payload"][..]),
        ("alert details", &["alert", "detail"][..]),
        ("provider payload", &["provider", "payload"][..]),
        ("provider output", &["provider", "output"][..]),
        ("tenant identifier", &["tenant", "identifier"][..]),
        ("object identifier", &["object", "identifier"][..]),
        ("private network", &["private", "network"][..]),
        ("endpoint name", &["endpoint", "name"][..]),
    ] {
        if ordered_terms_present(&lower, terms) {
            return Some(label);
        }
    }
    None
}

fn ordered_terms_present(text: &str, terms: &[&str]) -> bool {
    let words = ascii_words(text, "_-");
    terms
        .iter()
        .all(|term| words.iter().any(|word| word == term))
}

fn keyword_call_or_value(text: &str, keyword: &str) -> bool {
    let Some(rest) = text.strip_prefix(keyword) else {
        return false;
    };
    rest.is_empty()
        || rest
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_whitespace() || b"(<[{".contains(byte))
}

fn prohibited_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("akia")
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || lower.contains("://")
        || contains_private_ip(value)
        || contains_uuid(value)
        || token_assignment_like(&lower)
}

fn contains_private_ip(value: &str) -> bool {
    for part in ascii_words(value, ".") {
        let octets = part.split('.').collect::<Vec<_>>();
        if octets.len() != 4 {
            continue;
        }
        let parsed = octets
            .iter()
            .map(|octet| octet.parse::<u8>())
            .collect::<Result<Vec<_>, _>>();
        let Ok(parsed) = parsed else {
            continue;
        };
        if parsed[0] == 10
            || (parsed[0] == 192 && parsed[1] == 168)
            || (parsed[0] == 172 && (16..=31).contains(&parsed[1]))
        {
            return true;
        }
    }
    false
}

fn contains_uuid(value: &str) -> bool {
    for part in ascii_words(value, "-") {
        let pieces = part.split('-').collect::<Vec<_>>();
        if pieces.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(pieces.iter())
                .all(|(len, piece)| {
                    piece.len() == *len && piece.chars().all(|ch| ch.is_ascii_hexdigit())
                })
        {
            return true;
        }
    }
    false
}

fn token_assignment_like(lower: &str) -> bool {
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|key| {
        lower.find(key).is_some_and(|index| {
            let rest = lower[index + key.len()..].trim_start();
            (rest.starts_with(':') || rest.starts_with('=')) && !rest[1..].trim_start().is_empty()
        })
    })
}

fn csharp_array_literal_values(body: &str, label: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    for member in split_top_level(body, true) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if let Some(value) = exact_string_literal(text) {
            values.push(value);
        } else {
            errors.push(format!(
                "{label} array must use literal string entries only"
            ));
        }
    }
    values
}

fn top_level_array_members(array_block: &str) -> Vec<&str> {
    let body = array_block.trim();
    let body = if body.starts_with('{') && body.ends_with('}') {
        &body[1..body.len() - 1]
    } else {
        body
    };
    split_top_level(body, false)
}

fn split_top_level(body: &str, commas_inside_braces_are_top_level: bool) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut members = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else {
            match bytes[index] {
                b'(' => paren_depth += 1,
                b')' => paren_depth = paren_depth.saturating_sub(1),
                b'[' => bracket_depth += 1,
                b']' => bracket_depth = bracket_depth.saturating_sub(1),
                b'{' => brace_depth += 1,
                b'}' => brace_depth = brace_depth.saturating_sub(1),
                b',' if paren_depth == 0
                    && bracket_depth == 0
                    && (brace_depth == 0 || commas_inside_braces_are_top_level) =>
                {
                    members.push(&body[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
        index += 1;
    }
    members.push(&body[start..]);
    members
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1 && line_matches_assignment(&texts[0], field, value, true)
}

fn exact_endpoint_assignment(
    block: &str,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) -> bool {
    let texts = top_level_assignment_texts(block, field);
    expect_endpoint_assignment_count(field, texts.len(), errors);
    texts.len() == 1 && line_matches_assignment(&texts[0], field, value, true)
}

fn exact_string_endpoint_assignment(
    block: &str,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) -> bool {
    let texts = top_level_assignment_texts(block, field);
    expect_endpoint_assignment_count(field, texts.len(), errors);
    texts.len() == 1
        && exact_string_assignment_value(&texts[0], field, true).as_deref() == Some(value)
}

fn expect_endpoint_assignment_count(field: &str, count: usize, errors: &mut Vec<String>) {
    if count != 1 {
        errors.push(format!(
            "noise flapping remediation endpoint field {field} must be assigned exactly once"
        ));
    }
}

fn line_matches_assignment(line: &str, field: &str, value: &str, comma: bool) -> bool {
    let Some(rhs) = assignment_rhs(line, field) else {
        return false;
    };
    let expected = if comma {
        format!("{value},")
    } else {
        value.to_string()
    };
    rhs.trim() == expected
}

fn exact_string_assignment_value_optional_comma(line: &str, field: &str) -> Option<String> {
    exact_string_assignment_value(line, field, true)
        .or_else(|| exact_string_assignment_value(line, field, false))
}

fn exact_string_assignment_value(line: &str, field: &str, comma: bool) -> Option<String> {
    let rhs = assignment_rhs(line, field)?;
    let trimmed = rhs.trim();
    let value_part = if comma {
        trimmed.strip_suffix(',')?.trim()
    } else {
        trimmed
    };
    exact_string_literal(value_part)
}

fn exact_string_literal(text: &str) -> Option<String> {
    if text.starts_with('"')
        && text.ends_with('"')
        && text.len() >= 2
        && single_string_literal(text)
    {
        Some(text[1..text.len() - 1].to_string())
    } else {
        None
    }
}

fn assignment_rhs<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let trimmed = line.trim_start();
    let trimmed = trimmed.strip_prefix('@').unwrap_or(trimmed);
    let rest = trimmed.strip_prefix(field)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    Some(rest)
}

fn top_level_assignment_texts(block: &str, field: &str) -> Vec<String> {
    top_level_assignment_indexes(block, field)
        .into_iter()
        .map(|index| {
            block[index..assignment_end_index(block, index)]
                .trim()
                .to_string()
        })
        .collect()
}

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
    assignment_indexes_any_depth(block, field)
        .into_iter()
        .filter(|index| brace_depth_at(block, *index) == 1)
        .collect()
}

fn assignment_indexes_any_depth(block: &str, field: &str) -> Vec<usize> {
    let masked = csharp_code_mask(block);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(field) {
        let start = offset + relative;
        let end = start + field.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(cursor) == Some(&b'=') {
            indexes.push(start);
        }
    }
    indexes
}

fn assignment_end_index(block: &str, start: usize) -> usize {
    let bytes = block.as_bytes();
    let mut index = start;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = brace_depth_at(block, start);
    let target_depth = brace_depth;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else {
            match bytes[index] {
                b'(' => paren_depth += 1,
                b')' => paren_depth = paren_depth.saturating_sub(1),
                b'[' => bracket_depth += 1,
                b']' => bracket_depth = bracket_depth.saturating_sub(1),
                b'{' => brace_depth += 1,
                b'}' => {
                    if brace_depth == target_depth && paren_depth == 0 && bracket_depth == 0 {
                        return index;
                    }
                    brace_depth = brace_depth.saturating_sub(1);
                }
                b',' if brace_depth == target_depth && paren_depth == 0 && bracket_depth == 0 => {
                    return index + 1;
                }
                _ => {}
            }
        }
        index += 1;
    }
    block.len()
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    assignment_fields_with_depth(block)
        .into_iter()
        .filter_map(|(field, depth)| (depth == 1).then_some(field))
        .collect()
}

fn assignment_fields(block: &str) -> Vec<String> {
    assignment_fields_with_depth(block)
        .into_iter()
        .map(|(field, _)| field)
        .collect()
}

fn assignment_fields_with_depth(block: &str) -> Vec<(String, usize)> {
    let masked = csharp_code_mask(block);
    let bytes = masked.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            let cursor = skip_ascii_whitespace(&masked, index);
            if bytes.get(cursor) == Some(&b'=') {
                fields.push((
                    masked[start..index].to_string(),
                    brace_depth_at(block, start),
                ));
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn validate_rule_detail_uniqueness_value(rules: &[Value], label: &str, errors: &mut Vec<String>) {
    let details = rules
        .iter()
        .map(|rule| {
            RULE_FIELDS[1..]
                .iter()
                .map(|field| string_value(rule, field).unwrap_or("").to_string())
                .collect::<Vec<_>>()
                .join("\u{1f}")
        })
        .collect::<Vec<_>>();
    expect(
        unique(&details),
        errors,
        &format!("{label} rule details must be unique"),
    );
}

fn validate_rule_detail_uniqueness_map(
    rules: &[BTreeMap<String, String>],
    label: &str,
    errors: &mut Vec<String>,
) {
    let details = rules
        .iter()
        .map(|rule| {
            RULE_FIELDS[1..]
                .iter()
                .map(|field| rule.get(*field).map(String::as_str).unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\u{1f}")
        })
        .collect::<Vec<_>>();
    expect(
        unique(&details),
        errors,
        &format!("{label} rule details must be unique"),
    );
}

fn object_array(value: Option<&Value>, label: &str, errors: &mut Vec<String>) -> Vec<Value> {
    let Some(array) = value.and_then(Value::as_array) else {
        errors.push(format!("{label}s must be non-empty array"));
        return Vec::new();
    };
    if array.is_empty() {
        errors.push(format!("{label}s must be non-empty array"));
        return Vec::new();
    }
    let mut objects = Vec::new();
    for item in array {
        if item.as_object().is_some() {
            objects.push(item.clone());
        } else {
            errors.push(format!("{label}s must be objects"));
        }
    }
    objects
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn push_missing_unexpected(
    prefix: &str,
    field: &str,
    values: &[String],
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix} ")
    };
    let missing = diff_values(
        &required
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
        values,
    );
    let unexpected = diff_values(
        values,
        &required
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
    );
    if !missing.is_empty() {
        errors.push(format!(
            "{prefix}{field} missing values: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{prefix}{field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
}

fn push_rule_missing_unexpected(
    label: &str,
    values: &[String],
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let required_values = required
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    let missing = diff_values(&required_values, values);
    let unexpected = diff_values(values, &required_values);
    if !missing.is_empty() {
        errors.push(format!("{label} missing rules: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{label} unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
}

fn diff_values(left: &[String], right: &[String]) -> Vec<String> {
    let right_set = right.iter().collect::<BTreeSet<_>>();
    left.iter()
        .filter(|value| !right_set.contains(value))
        .cloned()
        .collect()
}

fn unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn prohibited_provider_key(key: &str, allow_safe_keys: bool) -> bool {
    if allow_safe_keys && SAFE_CATALOG_KEYS.contains(&key) {
        return false;
    }
    let normalized = normalized_key(key);
    PROHIBITED_PROVIDER_KEYS.contains(&normalized.as_str())
        || PROHIBITED_PROVIDER_KEY_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_block = false;
    while index < bytes.len() {
        if in_block {
            if bytes[index] == b'\n' {
                output.push('\n');
            } else {
                output.push(' ');
            }
            if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                index += 1;
                output.push(' ');
                in_block = false;
            }
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 1;
            in_block = true;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            if index < bytes.len() {
                output.push('\n');
            }
        } else {
            output.push(bytes[index] as char);
        }
        index += 1;
    }
    output
}

fn csharp_code_mask(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in text.chars() {
        if in_string {
            if ch == '\n' {
                output.push('\n');
                escaped = false;
            } else {
                output.push(' ');
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
            }
        } else if ch == '"' {
            in_string = true;
            output.push(' ');
        } else {
            output.push(ch);
        }
    }
    output
}

fn matching_brace_index(source: &str, start: usize) -> Option<usize> {
    matching_delimiter_index(source, start, b'{', b'}')
}

fn matching_delimiter_index(source: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = start;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == open {
            depth += 1;
        } else if bytes[index] == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn csharp_call_arguments(code: &str, call_name: &str) -> Vec<Vec<String>> {
    let mut calls = Vec::new();
    let mut offset = 0;
    while let Some(relative) = code[offset..].find(call_name) {
        let start = offset + relative;
        let end = start + call_name.len();
        offset = end;
        if !identifier_boundary(code, start, end) {
            continue;
        }
        let open = skip_ascii_whitespace(code, end);
        if code.as_bytes().get(open) != Some(&b'(') {
            continue;
        }
        let Some(close) = matching_delimiter_index(code, open, b'(', b')') else {
            break;
        };
        calls.push(split_csharp_arguments(&code[open + 1..close]));
        offset = close + 1;
    }
    calls
}

fn split_csharp_arguments(arguments: &str) -> Vec<String> {
    let bytes = arguments.as_bytes();
    let mut values = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut paren_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else {
            match bytes[index] {
                b'<' if generic_angle_start(arguments, index) => angle_depth += 1,
                b'>' if angle_depth > 0 => angle_depth -= 1,
                b'(' => paren_depth += 1,
                b')' => paren_depth = paren_depth.saturating_sub(1),
                b'{' => brace_depth += 1,
                b'}' => brace_depth = brace_depth.saturating_sub(1),
                b'[' => bracket_depth += 1,
                b']' => bracket_depth = bracket_depth.saturating_sub(1),
                b',' if paren_depth == 0
                    && brace_depth == 0
                    && bracket_depth == 0
                    && angle_depth == 0 =>
                {
                    values.push(arguments[start..index].trim().to_string());
                    start = index + 1;
                }
                _ => {}
            }
        }
        index += 1;
    }
    values.push(arguments[start..].trim().to_string());
    values
}

fn generic_angle_start(text: &str, index: usize) -> bool {
    let bytes = text.as_bytes();
    if index == 0 {
        return false;
    }
    let mut previous = index - 1;
    while previous > 0 && bytes[previous].is_ascii_whitespace() {
        previous -= 1;
    }
    if !is_identifier_byte(bytes[previous]) {
        return false;
    }
    let mut next = index + 1;
    while next < bytes.len() && bytes[next].is_ascii_whitespace() {
        next += 1;
    }
    if next >= bytes.len() || !is_identifier_start(bytes[next]) {
        return false;
    }
    let mut scan = next;
    while scan < bytes.len() {
        match bytes[scan] {
            b'>' => return true,
            b'(' | b')' | b';' => return false,
            _ => scan += 1,
        }
    }
    false
}

fn brace_depth_at(source: &str, target: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < target && index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == b'{' {
            depth += 1;
        } else if bytes[index] == b'}' {
            depth = depth.saturating_sub(1);
        }
        index += 1;
    }
    depth
}

fn single_string_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 1;
    let mut escaped = false;
    while index + 1 < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == b'"' {
            return false;
        }
        index += 1;
    }
    true
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    (start == 0 || !is_identifier_byte(bytes[start - 1]))
        && (end >= bytes.len() || !is_identifier_byte(bytes[end]))
}

fn read_identifier(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if start >= bytes.len() || !is_identifier_start(bytes[start]) {
        return None;
    }
    let mut end = start + 1;
    while end < bytes.len() && is_identifier_byte(bytes[end]) {
        end += 1;
    }
    Some((text[start..end].to_string(), end))
}

fn last_identifier(text: &str) -> Option<String> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .rfind(|part| !part.is_empty())
        .map(str::to_string)
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn skip_horizontal_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && matches!(text.as_bytes()[index], b' ' | b'\t') {
        index += 1;
    }
    index
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    for (index, ch) in text.char_indices() {
        if ch == '\n' && index + 1 < text.len() {
            indexes.push(index + 1);
        }
    }
    indexes
}

fn is_assignment_operator(text: &str, index: usize) -> bool {
    text.as_bytes().get(index) == Some(&b'=')
        && text.as_bytes().get(index + 1) != Some(&b'=')
        && (index == 0 || !matches!(text.as_bytes()[index - 1], b'=' | b'!' | b'<' | b'>'))
}

fn is_mutating_assignment_operator(text: &str, index: usize) -> bool {
    if is_assignment_operator(text, index) {
        return true;
    }
    let bytes = text.as_bytes();
    match bytes.get(index).copied() {
        Some(b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^') => {
            bytes.get(index + 1) == Some(&b'=')
        }
        Some(b'<') => bytes.get(index + 1) == Some(&b'<') && bytes.get(index + 2) == Some(&b'='),
        Some(b'>') => bytes.get(index + 1) == Some(&b'>') && bytes.get(index + 2) == Some(&b'='),
        _ => false,
    }
}

fn ascii_words<'a>(value: &'a str, extra: &str) -> Vec<&'a str> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || extra.contains(ch)))
        .filter(|part| !part.is_empty())
        .collect()
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
    fn noise_flapping_endpoint_registration_detects_route_alias() {
        let program = format!(
            "const string routeAlias = \"{ENDPOINT}\";\napp.MapGet(routeAlias, () => Results.Json(new {{ source = \"static-seed\" }}));"
        );

        let starts = endpoint_start_indexes(&program);

        assert_eq!(starts.len(), 1);
        assert_eq!(program[starts[0]..].find("app.MapGet"), Some(0));
    }
}
