use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/emergency-change-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/emergency-change.md";
const ENDPOINT: &str = "/api/operations/emergency-change-contract";

const REQUIRED_MODES: &[&str] = &[
    "break-glass",
    "urgent-remediation",
    "incident-containment",
    "service-restoration",
];
const REQUIRED_GUARDS: &[&str] = &[
    "emergency-role-authorized",
    "incident-or-ticket-linked",
    "emergency-approver-assigned",
    "scope-bounded",
    "dry-run-ready",
    "lock-record-ready",
    "evidence-redacted",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "live-execution-disabled",
    "privileged-worker-disabled",
    "role-not-authorized",
    "incident-context-missing",
    "approval-missing",
    "scope-too-broad",
    "lock-conflict",
    "evidence-not-redacted",
];
const REQUIRED_INPUTS: &[&str] = &[
    "ticketContext",
    "emergencyReason",
    "requester",
    "affectedService",
    "targetScope",
    "businessImpact",
    "approver",
    "owner",
    "rollbackPlan",
    "evidenceManifest",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "emergencySummary",
    "businessImpact",
    "targetScope",
    "riskJustification",
    "approvalPath",
    "rollbackNotes",
    "verificationPlan",
    "handoverNotes",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Emergency request summary",
    "Incident or ticket reference",
    "Approval decisions",
    "Delegated authority",
    "Scope and lock record",
    "Dry-run plan summary",
    "Verification result",
    "Privileged worker log reference",
    "Evidence references",
];

const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedModes", "emergencyChangeModes"),
    ("requiredGuards", "emergencyChangeRequiredGuards"),
    ("planSections", "emergencyChangePlanSections"),
    ("blockedReasons", "emergencyChangeBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_BASE_FIELDS: &[&str] = &[
    "source",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "privilegedWorkerAllowed",
    "rules",
];
const PROHIBITED_FIELD_TERMS: &[&str] = &[
    "password",
    "credential",
    "secret",
    "token",
    "bearer",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "principalid",
    "principalidentifier",
    "privateip",
    "privatenetwork",
    "serialnumber",
    "providerpayload",
    "rawprovider",
    "rawevidence",
    "rawlog",
    "rawinventory",
    "rawcmdb",
    "recipientemail",
    "recipientaddress",
    "recipientdata",
    "endpointurl",
    "url",
    "hostname",
    "hostidentifier",
    "username",
    "userid",
    "useridentifier",
];
const UNSAFE_TRUE_TERMS: &[&str] = &[
    "live",
    "provider",
    "raw",
    "dispatch",
    "secret",
    "credential",
    "token",
    "tenant",
    "object",
    "principal",
    "private",
    "user",
    "host",
    "execution",
    "mutation",
    "privileged",
    "approval",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-emergency-execution",
        decision: "block",
        requirement: "Emergency changes remain dry-run only until live execution is explicitly enabled by policy.",
        evidence: "Dry-run plan summary",
    },
    RuleDetail {
        id: "emergency-approval-required",
        decision: "block",
        requirement: "Emergency approval and delegated authority must be recorded before execution can be considered.",
        evidence: "Approval decisions",
    },
    RuleDetail {
        id: "bounded-scope-required",
        decision: "block",
        requirement: "Emergency scope must be bounded and locked to avoid uncontrolled blast radius.",
        evidence: "Scope and lock record",
    },
    RuleDetail {
        id: "audit-evidence-required",
        decision: "block",
        requirement: "Redacted evidence, verification, and privileged worker log references are mandatory for audit.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
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

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

#[derive(Debug)]
struct Assignment {
    value: String,
}

struct RouteRegistration {
    index: usize,
    method: String,
    route: String,
    close_paren: usize,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid emergency change context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    let scope = serde_json::json!({
        CATALOG_PATH: context.catalog,
        PROGRAM_PATH: context.program,
        API_README_PATH: context.api_readme,
        DOC_PATH: context.doc,
    });
    validate_no_prohibited_values(&scope, "emergency-change", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid emergency change catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid emergency change program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid emergency change docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid emergency change prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "emergency change version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "emergency change status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "emergency change source must be static-seed",
    );
    expect(
        catalog.get("dryRunRequired").and_then(Value::as_bool) == Some(true),
        errors,
        "emergency change must require dry-run",
    );
    for field in [
        "providerCallsEnabled",
        "liveExecutionAllowed",
        "privilegedWorkerAllowed",
    ] {
        expect(
            catalog.get(field).and_then(Value::as_bool) == Some(false),
            errors,
            format!("emergency change {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "supportedModes", REQUIRED_MODES, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = catalog_string_array(catalog, field, errors);
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
        unique_count(&values) == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("emergency change rules must be an array of hashes".to_string());
        return;
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("emergency change rules must be an array of hashes".to_string());
        return;
    }
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let required_ids: Vec<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing = missing_values(&required_ids, &rule_ids);
    expect(
        unique_count(&rule_ids) == rule_ids.len(),
        errors,
        "emergency change rule IDs must be unique",
    );
    let rule_details: Vec<Vec<String>> = rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| {
                    rule.get(*field)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .collect();
    expect(
        unique_count_vec(&rule_details) == rule_details.len(),
        errors,
        "emergency change rule details must be unique",
    );
    expect(
        missing.is_empty(),
        errors,
        format!("emergency change missing rules: {}", missing.join(", ")),
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|candidate| {
            candidate.get("id").and_then(Value::as_str) == Some(expected_rule.id)
        }) else {
            continue;
        };
        for (field, expected) in [
            ("decision", expected_rule.decision),
            ("requirement", expected_rule.requirement),
            ("evidence", expected_rule.evidence),
        ] {
            expect(
                rule.get(field).and_then(Value::as_str) == Some(expected),
                errors,
                format!(
                    "emergency change rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
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
        "API must keep dryRunRequired true",
    );
    for field in [
        "providerCallsEnabled",
        "liveExecutionAllowed",
        "privilegedWorkerAllowed",
    ] {
        validate_exact_endpoint_assignment(
            &block,
            field,
            "false",
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        validate_exact_endpoint_assignment(
            &block,
            field,
            variable,
            errors,
            format!("API must bind {field} to {variable}"),
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
    let missing: Vec<String> = expected_values
        .iter()
        .filter(|value| !values.contains(value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !expected_values.contains(value))
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
            "API {field} unexpected values present: {} redacted value(s)",
            unexpected.len()
        ));
    }
    expect(
        unique_count(&values) == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(catalog_rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("emergency change rules must be an array of hashes".to_string());
        return;
    };
    let Some(rules_body) = endpoint_rules_body(block, errors) else {
        return;
    };
    let api_rules = endpoint_rule_hashes(&rules_body, errors);
    let catalog_rule_ids: Vec<String> = catalog_rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let api_rule_ids: Vec<String> = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect();
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
    expect(
        unique_count(&api_rule_ids) == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    let rule_details: Vec<Vec<String>> = api_rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| rule.get(*field).cloned().unwrap_or_default())
                .collect()
        })
        .collect();
    expect(
        unique_count_vec(&rule_details) == rule_details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(id) = catalog_rule.get("id").and_then(Value::as_str) else {
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
                api_rule.get(field).map(String::as_str)
                    == catalog_rule.get(field).and_then(Value::as_str),
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
        "API README missing emergency change endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "emergency change doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "emergency change doc must prohibit provider calls",
    );
    expect(
        doc.contains("No privileged worker execution."),
        errors,
        "emergency change doc must prohibit privileged worker execution",
    );
    expect(
        doc.contains("must not bypass approval"),
        errors,
        "emergency change doc must preserve approval",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let matching_routes = endpoint_route_registrations(program);
    if matching_routes.is_empty() {
        errors.push("API missing emergency change endpoint".to_string());
        return String::new();
    };
    if matching_routes.len() != 1 {
        errors.push("API emergency change endpoint must have exactly one active route".to_string());
        return String::new();
    }
    let registration = matching_routes.first().expect("route length checked");
    if registration.method != "MapGet" || registration.route != ENDPOINT {
        errors
            .push("API emergency change endpoint route must be exact canonical MapGet".to_string());
        return String::new();
    }
    let next_endpoint = find_line_starting_with(program, "app.MapGet(", registration.index + 1);
    let call_tail = &program[registration.close_paren + 1..next_endpoint.unwrap_or(program.len())];
    if !call_tail.trim_start().starts_with(';') {
        errors
            .push("API emergency change endpoint must not use endpoint builder chains".to_string());
        return String::new();
    }

    program[registration.index..next_endpoint.unwrap_or(program.len())].to_string()
}

fn endpoint_route_registrations(program: &str) -> Vec<RouteRegistration> {
    let aliases = protected_route_aliases(program);
    let masked = mask_csharp_string_literals(program);
    let mut routes = Vec::new();
    let mut offset = 0usize;
    while let Some((method, method_start, method_end)) = next_identifier(&masked, offset) {
        if !matches!(method.as_str(), "MapGet" | "Map" | "MapMethods") {
            offset = method_end;
            continue;
        }
        let Some(open_paren) = next_non_whitespace_index(&masked, method_end) else {
            break;
        };
        if masked.as_bytes().get(open_paren) != Some(&b'(') {
            offset = method_end;
            continue;
        }
        let Some(close_paren) = matching_paren_index(&masked, open_paren) else {
            offset = open_paren + 1;
            continue;
        };
        let args = call_arguments(program, open_paren, close_paren);
        let receiver_style = masked[..method_start].trim_end().ends_with('.');
        let primary_route_arg = if receiver_style {
            args.first().copied()
        } else {
            args.get(1).copied()
        };
        let fallback_route_arg = if receiver_style {
            args.get(1).copied()
        } else {
            args.first().copied()
        };
        let route = primary_route_arg
            .and_then(|arg| route_expression_value(arg, &aliases))
            .or_else(|| fallback_route_arg.and_then(|arg| route_expression_value(arg, &aliases)));
        if let Some(mut route) = route {
            if receiver_style {
                if let Some(prefix) = group_prefix_before(program, method_start, &aliases) {
                    if route != "<nonliteral-emergency-route>" {
                        route = compose_routes(&prefix, &route);
                    }
                }
            }
            if route != ENDPOINT
                && normalize_route(&route) != normalize_route(ENDPOINT)
                && contains_emergency_route_terms(&route)
            {
                route = "<nonliteral-emergency-route>".to_string();
            }
            if route == ENDPOINT
                || normalize_route(&route) == normalize_route(ENDPOINT)
                || route == "<nonliteral-emergency-route>"
            {
                routes.push(RouteRegistration {
                    index: method_start,
                    method,
                    route,
                    close_paren,
                });
            }
        }
        offset = close_paren + 1;
    }
    routes
}

fn protected_route_aliases(program: &str) -> HashMap<String, String> {
    let mut assignments = Vec::new();
    for line in program.lines() {
        let Some(eq_index) = line.find('=') else {
            continue;
        };
        let masked_prefix = mask_csharp_string_literals(&line[..eq_index]);
        let mut last_identifier = None;
        let mut offset = 0usize;
        while let Some((identifier, _start, end)) = next_identifier(&masked_prefix, offset) {
            last_identifier = Some(identifier);
            offset = end;
        }
        let Some(identifier) = last_identifier else {
            continue;
        };
        let rhs = line[eq_index + 1..].trim().trim_end_matches(';').trim();
        assignments.push((identifier, rhs.to_string()));
    }
    let mut aliases = HashMap::new();
    for _ in 0..4 {
        let before = aliases.len();
        for (identifier, rhs) in &assignments {
            if let Some(value) = route_expression_value(rhs, &aliases) {
                aliases.insert(identifier.clone(), value);
            }
        }
        if aliases.len() == before {
            break;
        }
    }
    aliases
        .into_iter()
        .filter(|(_key, value)| {
            value == ENDPOINT
                || normalize_route(value) == normalize_route(ENDPOINT)
                || value == "<nonliteral-emergency-route>"
                || contains_emergency_route_terms(value)
        })
        .collect()
}

fn group_prefix_before(
    program: &str,
    method_start: usize,
    aliases: &HashMap<String, String>,
) -> Option<String> {
    let prefix = &program[..method_start];
    let map_group_index = prefix.rfind("MapGroup")?;
    let between = &prefix[map_group_index + "MapGroup".len()..];
    if between.contains(';') {
        return None;
    }
    let masked = mask_csharp_string_literals(program);
    let open_paren = next_non_whitespace_index(&masked, map_group_index + "MapGroup".len())?;
    if masked.as_bytes().get(open_paren) != Some(&b'(') {
        return None;
    }
    let close_paren = matching_paren_index(&masked, open_paren)?;
    if close_paren > method_start {
        return None;
    }
    let args = call_arguments(program, open_paren, close_paren);
    args.first()
        .and_then(|arg| route_expression_value(arg, aliases))
}

fn compose_routes(prefix: &str, child: &str) -> String {
    if child.is_empty() || child == "/" {
        return prefix.to_string();
    }
    format!(
        "{}/{}",
        prefix.trim_end_matches('/'),
        child.trim_start_matches('/')
    )
}

fn call_arguments(source: &str, open_paren: usize, close_paren: usize) -> Vec<&str> {
    let body = &source[open_paren + 1..close_paren];
    top_level_segments(body, b',')
}

fn route_expression_value(expr: &str, aliases: &HashMap<String, String>) -> Option<String> {
    let parts = top_level_segments(expr, b'+');
    let mut value = String::new();
    let mut saw_value = false;
    for part in parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.as_bytes().first() == Some(&b'"') {
            let (literal, end) = parse_csharp_string_literal_at(trimmed, 0)?;
            if !trimmed[end..].trim().is_empty() {
                return None;
            }
            value.push_str(&literal);
            saw_value = true;
            continue;
        }
        if let Some((identifier, _start, end)) = parse_identifier_at(trimmed, 0) {
            if !trimmed[end..].trim().is_empty() {
                return contains_emergency_route_terms(trimmed)
                    .then_some("<nonliteral-emergency-route>".to_string());
            }
            if let Some(alias) = aliases.get(&identifier) {
                value.push_str(alias);
                saw_value = true;
                continue;
            }
        }
        return contains_emergency_route_terms(trimmed)
            .then_some("<nonliteral-emergency-route>".to_string());
    }
    saw_value.then_some(value)
}

fn top_level_segments(source: &str, delimiter: u8) -> Vec<&str> {
    let masked = mask_csharp_string_literals(source);
    let bytes = masked.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            _ if *byte == delimiter
                && brace_depth == 0
                && paren_depth == 0
                && bracket_depth == 0 =>
            {
                segments.push(&source[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    segments.push(&source[start..]);
    segments
}

fn contains_emergency_route_terms(call: &str) -> bool {
    [
        "emergencyChange",
        "EmergencyChange",
        "liveExecutionAllowed",
        "privilegedWorkerAllowed",
        "providerCallsEnabled",
        "emergency-change-contract",
    ]
    .iter()
    .any(|term| call.contains(term))
}

fn normalize_route(route: &str) -> String {
    route.trim_matches('/').to_ascii_lowercase()
}

fn find_line_starting_with(source: &str, marker: &str, offset: usize) -> Option<usize> {
    let mut index = offset;
    while index < source.len() {
        let line_end = source[index..]
            .find('\n')
            .map(|relative| index + relative)
            .unwrap_or(source.len());
        let line = &source[index..line_end];
        let trimmed_len = line.len() - line.trim_start_matches([' ', '\t']).len();
        if line[trimmed_len..].starts_with(marker) {
            return Some(index + trimmed_len);
        }
        index = line_end.saturating_add(1);
    }
    None
}

fn validate_exact_string_assignment(
    block: &str,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
    message: &str,
) {
    validate_exact_endpoint_assignment(block, field, &format!("\"{value}\""), errors, message);
}

fn validate_exact_endpoint_assignment(
    block: &str,
    field: &str,
    expected: &str,
    errors: &mut Vec<String>,
    message: impl Into<String>,
) {
    let assignments = assignment_records_for_field(block, field);
    if assignments.len() != 1 {
        errors.push(format!(
            "API endpoint field {field} must be assigned exactly once"
        ));
        return;
    }
    expect(assignments[0].value == expected, errors, message);
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let bodies = array_bodies_for_variable(program, variable);
    if bodies.len() != 1 {
        errors.push(format!(
            "API {variable} must have exactly one literal string array declaration"
        ));
        return None;
    }
    let body = bodies.first().expect("body length checked");
    if !literal_string_array_body(body) {
        errors.push(format!("API {variable} must be a literal string array"));
    }
    Some(csharp_string_literals(body))
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let bodies = array_bodies_for_assignment(block, field);
    if bodies.len() != 1 {
        errors.push(format!(
            "API endpoint field {field} must be assigned exactly once"
        ));
        return None;
    }
    let body = bodies.first().expect("body length checked");
    if !literal_string_array_body(body) {
        errors.push(format!("API {field} must be a literal string array"));
    }
    Some(csharp_string_literals(body))
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let bodies = array_bodies_for_assignment(block, "rules");
    if bodies.len() != 1 {
        errors.push("API endpoint field rules must be assigned exactly once".to_string());
        return None;
    }
    bodies.into_iter().next()
}

fn endpoint_rule_hashes(body: &str, errors: &mut Vec<String>) -> Vec<HashMap<String, String>> {
    let mut rules = Vec::new();
    for element in top_level_array_elements(body) {
        let trimmed = element.trim();
        let Some(rule_body) = literal_rule_body(trimmed) else {
            errors.push(
                "API rule must assign id, decision, requirement, and evidence exactly once as literal strings"
                    .to_string(),
            );
            continue;
        };
        let parsed = parse_rule_assignments(rule_body);
        if parsed.valid {
            rules.push(parsed.values);
        } else {
            errors.push("API malformed API rule literal with redacted rule id".to_string());
            if parsed.values.contains_key("id") {
                rules.push(parsed.values);
            }
        }
    }
    rules
}

fn top_level_array_elements(body: &str) -> Vec<&str> {
    let masked = mask_csharp_string_literals(body);
    let bytes = masked.as_bytes();
    let mut elements = Vec::new();
    let mut start = 0usize;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b',' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                let element = &body[start..index];
                if !element.trim().is_empty() {
                    elements.push(element);
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    let element = &body[start..];
    if !element.trim().is_empty() {
        elements.push(element);
    }
    elements
}

fn literal_rule_body(element: &str) -> Option<&str> {
    let masked = mask_csharp_string_literals(element);
    if !starts_with_word(&masked, 0, "new") {
        return None;
    }
    let open_index = next_non_whitespace_index(&masked, "new".len())?;
    if masked.as_bytes().get(open_index) != Some(&b'{') {
        return None;
    }
    let close_index = matching_brace_index(element, open_index)?;
    if !masked[close_index + 1..].trim().is_empty() {
        return None;
    }
    Some(&element[open_index + 1..close_index])
}

struct ParsedRule {
    values: HashMap<String, String>,
    valid: bool,
}

fn parse_rule_assignments(body: &str) -> ParsedRule {
    let masked = mask_csharp_string_literals(body);
    let mut values = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut invalid_literal = false;
    let mut offset = 0usize;
    while let Some((field, _ident_start, ident_end)) = next_identifier(&masked, offset) {
        let Some(eq_index) = next_non_whitespace_index(&masked, ident_end) else {
            break;
        };
        if masked.as_bytes().get(eq_index) != Some(&b'=') {
            offset = ident_end;
            continue;
        }
        if !RULE_KEYS.contains(&field.as_str()) {
            invalid_literal = true;
            offset = ident_end;
            continue;
        }
        *counts.entry(field.clone()).or_insert(0) += 1;
        let Some(value_start) = next_non_whitespace_index(body, eq_index + 1) else {
            invalid_literal = true;
            break;
        };
        if body.as_bytes().get(value_start) == Some(&b'"') {
            if let Some((value, _end)) = parse_csharp_string_literal_at(body, value_start) {
                values.insert(field, value);
            } else {
                invalid_literal = true;
            }
        } else {
            invalid_literal = true;
        }
        offset = ident_end;
    }
    let valid = RULE_KEYS
        .iter()
        .all(|key| counts.get(*key).copied() == Some(1) && values.contains_key(*key))
        && !invalid_literal;
    ParsedRule { values, valid }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let block_without_rules = block_with_rules_body_masked(block);
    for field in endpoint_assignment_fields(&block_without_rules) {
        if RULE_KEYS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected emergency change field {field}"
            ));
            continue;
        }
        if allowed_endpoint_fields().contains(field.as_str()) {
            continue;
        }
        if prohibited_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited emergency change field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected emergency change field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let masked = mask_csharp_string_literals(block);
    let mut offset = 0usize;
    while let Some((field, _ident_start, ident_end)) = next_identifier(&masked, offset) {
        let Some(eq_index) = next_non_whitespace_index(&masked, ident_end) else {
            break;
        };
        if masked.as_bytes().get(eq_index) != Some(&b'=') {
            offset = ident_end;
            continue;
        }
        let Some(value_start) = next_non_whitespace_index(&masked, eq_index + 1) else {
            break;
        };
        if starts_with_word(&masked, value_start, "true") && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
        offset = ident_end;
    }
}

fn validate_endpoint_string_literals(block: &str, errors: &mut Vec<String>) {
    let safe = safe_endpoint_literals();
    for literal in csharp_string_literals(block) {
        if safe.contains(literal.as_str()) {
            continue;
        }
        if prohibited_endpoint_field(&literal) {
            errors.push(format!(
                "API endpoint contains prohibited emergency change literal {literal}"
            ));
        }
    }
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_endpoint_field(key) {
                    errors.push(format!("{path}.{key} contains prohibited provider field"));
                }
                validate_no_prohibited_values(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_prohibited_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) if contains_prohibited_value(text) => {
            errors.push(format!("{path} contains prohibited value"));
        }
        _ => {}
    }
}

fn assignment_records_for_field(block: &str, field: &str) -> Vec<Assignment> {
    let mut records = Vec::new();
    for line in block.lines() {
        let masked_line = mask_csharp_string_literals(line);
        let mut offset = 0usize;
        while let Some((identifier, _ident_start, ident_end)) =
            next_identifier(&masked_line, offset)
        {
            let Some(eq_index) = next_non_whitespace_index(&masked_line, ident_end) else {
                break;
            };
            if masked_line.as_bytes().get(eq_index) == Some(&b'=')
                && identifier == field
                && masked_line.as_bytes().get(eq_index + 1) != Some(&b'=')
            {
                let value = line[eq_index + 1..]
                    .trim()
                    .trim_end_matches(',')
                    .trim()
                    .to_string();
                records.push(Assignment { value });
                break;
            }
            offset = ident_end;
        }
    }
    records
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(block);
    let mut fields = Vec::new();
    let mut offset = 0usize;
    while let Some((identifier, _ident_start, ident_end)) = next_identifier(&masked, offset) {
        let Some(eq_index) = next_non_whitespace_index(&masked, ident_end) else {
            break;
        };
        if masked.as_bytes().get(eq_index) == Some(&b'=')
            && masked.as_bytes().get(eq_index + 1) != Some(&b'=')
        {
            fields.push(identifier);
        }
        offset = ident_end;
    }
    fields
}

fn array_bodies_for_variable(program: &str, variable: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(program);
    let mut bodies = Vec::new();
    let mut offset = 0usize;
    while let Some(index) = find_word(&masked, "var", offset) {
        let Some(name_start) = next_non_whitespace_index(&masked, index + "var".len()) else {
            break;
        };
        let Some((name, _start, name_end)) = parse_identifier_at(&masked, name_start) else {
            offset = index + "var".len();
            continue;
        };
        if name != variable {
            offset = name_end;
            continue;
        }
        if let Some(body) = array_body_after_assignment(program, &masked, name_end) {
            bodies.push(body);
        }
        offset = name_end;
    }
    bodies
}

fn array_bodies_for_assignment(block: &str, field: &str) -> Vec<String> {
    array_body_spans_for_assignment(block, field)
        .into_iter()
        .map(|(open_index, close_index)| block[open_index + 1..close_index].to_string())
        .collect()
}

fn array_body_spans_for_assignment(block: &str, field: &str) -> Vec<(usize, usize)> {
    let masked = mask_csharp_string_literals(block);
    let mut spans = Vec::new();
    let mut offset = 0usize;
    while let Some((identifier, _ident_start, ident_end)) = next_identifier(&masked, offset) {
        if identifier == field {
            if let Some(span) = array_body_span_after_assignment(block, &masked, ident_end) {
                spans.push(span);
            }
        }
        offset = ident_end;
    }
    spans
}

fn array_body_after_assignment(source: &str, masked: &str, name_end: usize) -> Option<String> {
    let (open_index, close_index) = array_body_span_after_assignment(source, masked, name_end)?;
    Some(source[open_index + 1..close_index].to_string())
}

fn array_body_span_after_assignment(
    source: &str,
    masked: &str,
    name_end: usize,
) -> Option<(usize, usize)> {
    let eq_index = next_non_whitespace_index(masked, name_end)?;
    if masked.as_bytes().get(eq_index) != Some(&b'=') {
        return None;
    }
    let value_start = next_non_whitespace_index(masked, eq_index + 1)?;
    if !masked[value_start..].starts_with("new[]") {
        return None;
    }
    let open_index = next_non_whitespace_index(masked, value_start + "new[]".len())?;
    if masked.as_bytes().get(open_index) != Some(&b'{') {
        return None;
    }
    let close_index = matching_brace_index(source, open_index)?;
    Some((open_index, close_index))
}

fn block_with_rules_body_masked(block: &str) -> String {
    let mut bytes = block.as_bytes().to_vec();
    for (open_index, close_index) in array_body_spans_for_assignment(block, "rules") {
        for byte in &mut bytes[open_index + 1..close_index] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).expect("source remains valid UTF-8")
}

fn literal_string_array_body(body: &str) -> bool {
    mask_csharp_string_literals(body)
        .chars()
        .all(|ch| ch.is_whitespace() || ch == ',')
}

fn allowed_endpoint_fields() -> HashSet<&'static str> {
    let mut fields: HashSet<&'static str> = ALLOWED_ENDPOINT_BASE_FIELDS.iter().copied().collect();
    fields.extend(ENDPOINT_ARRAY_BINDINGS.iter().map(|(field, _)| *field));
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().copied());
    fields
}

fn safe_endpoint_literals() -> HashSet<&'static str> {
    let mut values: HashSet<&'static str> = HashSet::new();
    values.extend(REQUIRED_MODES.iter().copied());
    values.extend(REQUIRED_GUARDS.iter().copied());
    values.extend(REQUIRED_BLOCKED_REASONS.iter().copied());
    values.extend(REQUIRED_INPUTS.iter().copied());
    values.extend(REQUIRED_PLAN_SECTIONS.iter().copied());
    values.extend(REQUIRED_EVIDENCE.iter().copied());
    values.extend(
        REQUIRED_RULES
            .iter()
            .flat_map(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence]),
    );
    values.extend(["static-seed", "block"]);
    values
}

fn prohibited_endpoint_field(field: &str) -> bool {
    let normalized = normalize_identifier(field);
    PROHIBITED_FIELD_TERMS
        .iter()
        .any(|term| normalized.contains(term))
}

fn unsafe_true_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    lower.ends_with("allowed")
        || lower.ends_with("enabled")
        || UNSAFE_TRUE_TERMS.iter().any(|term| lower.contains(term))
}

fn contains_prohibited_value(text: &str) -> bool {
    contains_aws_key(text)
        || text.to_ascii_lowercase().contains("-----begin ")
            && text.to_ascii_lowercase().contains("private key-----")
        || contains_url_scheme(text)
        || contains_private_ip(text)
        || contains_guid(text)
        || contains_secret_assignment(text)
}

fn contains_aws_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index + 20 <= bytes.len() {
        if bytes[index..].starts_with(b"AKIA")
            && bytes[index + 4..index + 20]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return true;
        }
        index += 1;
    }
    false
}

fn contains_url_scheme(text: &str) -> bool {
    let Some(separator) = text.find("://") else {
        return false;
    };
    let prefix = &text[..separator];
    let scheme_start = prefix
        .char_indices()
        .rev()
        .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let scheme = &prefix[scheme_start..];
    scheme
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
}

fn contains_private_ip(text: &str) -> bool {
    for token in text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            continue;
        }
        let octets: Option<Vec<u8>> = parts.iter().map(|part| part.parse::<u8>().ok()).collect();
        let Some(octets) = octets else {
            continue;
        };
        if octets[0] == 10
            || (octets[0] == 192 && octets[1] == 168)
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        {
            return true;
        }
    }
    false
}

fn contains_guid(text: &str) -> bool {
    let bytes = text.as_bytes();
    let groups = [8usize, 4, 4, 4, 12];
    for start in 0..bytes.len() {
        let mut index = start;
        let mut matched = true;
        for (group_index, len) in groups.iter().enumerate() {
            if index + len > bytes.len()
                || !bytes[index..index + len]
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                matched = false;
                break;
            }
            index += len;
            if group_index != groups.len() - 1 {
                if bytes.get(index) != Some(&b'-') {
                    matched = false;
                    break;
                }
                index += 1;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

fn contains_secret_assignment(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for term in [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ] {
        let mut offset = 0usize;
        while let Some(relative) = lower[offset..].find(term) {
            let index = offset + relative;
            let after = index + term.len();
            if !word_boundaries(&lower, index, after) {
                offset = after;
                continue;
            }
            let Some(separator) = next_non_whitespace_index(&lower, after) else {
                break;
            };
            if matches!(lower.as_bytes().get(separator), Some(b':' | b'=')) {
                let Some(value_index) = next_non_whitespace_index(&lower, separator + 1) else {
                    return false;
                };
                if lower[value_index..]
                    .chars()
                    .next()
                    .is_some_and(|ch| !ch.is_whitespace())
                {
                    return true;
                }
            }
            offset = after;
        }
    }
    false
}

fn csharp_string_literals(source: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        if let Some((value, end)) = parse_csharp_string_literal_at(source, index) {
            values.push(value);
            index = end;
        } else {
            index += 1;
        }
    }
    values
}

fn parse_csharp_string_literal_at(source: &str, quote_index: usize) -> Option<(String, usize)> {
    if source.as_bytes().get(quote_index) != Some(&b'"') {
        return None;
    }
    if source[quote_index..].starts_with("\"\"\"") {
        let content_start = quote_index + 3;
        let close_relative = source[content_start..].find("\"\"\"")?;
        let close_index = content_start + close_relative;
        return Some((
            source[content_start..close_index].to_string(),
            close_index + 3,
        ));
    }
    let mut value = String::new();
    let bytes = source.as_bytes();
    let mut index = quote_index + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                if let Some(next) = bytes.get(index + 1) {
                    match next {
                        b'u' if index + 5 < bytes.len() => {
                            if let Some(ch) = decode_hex_escape(&source[index + 2..index + 6]) {
                                value.push(ch);
                                index += 6;
                            } else {
                                value.push('u');
                                index += 2;
                            }
                        }
                        b'x' => {
                            let mut end = index + 2;
                            while end < bytes.len()
                                && end < index + 6
                                && bytes[end].is_ascii_hexdigit()
                            {
                                end += 1;
                            }
                            if end > index + 2 {
                                if let Some(ch) = decode_hex_escape(&source[index + 2..end]) {
                                    value.push(ch);
                                }
                                index = end;
                            } else {
                                value.push('x');
                                index += 2;
                            }
                        }
                        b'n' => {
                            value.push('\n');
                            index += 2;
                        }
                        b'r' => {
                            value.push('\r');
                            index += 2;
                        }
                        b't' => {
                            value.push('\t');
                            index += 2;
                        }
                        b'0' => {
                            value.push('\0');
                            index += 2;
                        }
                        b'\\' | b'"' => {
                            value.push(*next as char);
                            index += 2;
                        }
                        _ => {
                            value.push(*next as char);
                            index += 2;
                        }
                    }
                } else {
                    return None;
                }
            }
            b'"' => return Some((value, index + 1)),
            byte => {
                value.push(byte as char);
                index += 1;
            }
        }
    }
    None
}

fn decode_hex_escape(hex: &str) -> Option<char> {
    u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
}

fn mask_csharp_string_literals(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            output.push(bytes[index] as char);
            index += 1;
            continue;
        }
        output.push(' ');
        index += 1;
        while index < bytes.len() {
            let byte = bytes[index];
            output.push(if byte == b'\n' { '\n' } else { ' ' });
            index += 1;
            if byte == b'\\' {
                if let Some(next) = bytes.get(index) {
                    output.push(if *next == b'\n' { '\n' } else { ' ' });
                    index += 1;
                }
                continue;
            }
            if byte == b'"' {
                break;
            }
        }
    }
    output
}

fn strip_csharp_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut index = 0usize;
    let mut in_string = false;
    while index < bytes.len() {
        if in_string {
            output.push(bytes[index] as char);
            if bytes[index] == b'\\' {
                if let Some(next) = bytes.get(index + 1) {
                    output.push(*next as char);
                    index += 2;
                    continue;
                }
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
            continue;
        }
        if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            continue;
        }
        if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 2;
            while index < bytes.len() {
                if bytes.get(index) == Some(&b'*') && bytes.get(index + 1) == Some(&b'/') {
                    output.push(' ');
                    output.push(' ');
                    index += 2;
                    break;
                }
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            continue;
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let masked = mask_csharp_string_literals(text);
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

fn matching_paren_index(masked_text: &str, open_index: usize) -> Option<usize> {
    let bytes = masked_text.as_bytes();
    if bytes.get(open_index) != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open_index) {
        match byte {
            b'(' => depth += 1,
            b')' => {
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

fn next_identifier(source: &str, offset: usize) -> Option<(String, usize, usize)> {
    let bytes = source.as_bytes();
    let mut index = offset;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            return parse_identifier_at(source, index);
        }
        index += 1;
    }
    None
}

fn parse_identifier_at(source: &str, index: usize) -> Option<(String, usize, usize)> {
    let bytes = source.as_bytes();
    if !is_identifier_start(*bytes.get(index)?) {
        return None;
    }
    let mut end = index + 1;
    while end < bytes.len() && is_identifier_part(bytes[end]) {
        end += 1;
    }
    Some((source[index..end].to_string(), index, end))
}

fn find_word(source: &str, word: &str, offset: usize) -> Option<usize> {
    let mut search = offset;
    while let Some(relative) = source[search..].find(word) {
        let index = search + relative;
        if is_word_boundary(source, index, word) {
            return Some(index);
        }
        search = index + word.len();
    }
    None
}

fn starts_with_word(source: &str, index: usize, word: &str) -> bool {
    source[index..].starts_with(word) && is_word_boundary(source, index, word)
}

fn is_word_boundary(source: &str, start: usize, word: &str) -> bool {
    word_boundaries(source, start, start + word.len())
}

fn word_boundaries(source: &str, start: usize, end: usize) -> bool {
    let bytes = source.as_bytes();
    let before_ok = start == 0 || !is_identifier_part(bytes[start - 1]);
    let after_ok = end >= bytes.len() || !is_identifier_part(bytes[end]);
    before_ok && after_ok
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_part(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn next_non_whitespace_index(source: &str, offset: usize) -> Option<usize> {
    source[offset..]
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(index, _)| offset + index)
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(text)) => vec![text.to_string()],
        _ => Vec::new(),
    }
}

fn catalog_string_array(value: &Value, key: &str, errors: &mut Vec<String>) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(items)) => {
            if items.iter().any(|item| !item.is_string()) {
                errors.push(format!("{key} must contain only strings"));
            }
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        }
        Some(_) => {
            errors.push(format!("{key} must be an array"));
            Vec::new()
        }
        None => Vec::new(),
    }
}

fn missing_values(required: &[&str], values: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|value| !values.iter().any(|candidate| candidate == *value))
        .map(|value| (*value).to_string())
        .collect()
}

fn missing_strings(expected: &[String], actual: &[String]) -> Vec<String> {
    expected
        .iter()
        .filter(|value| !actual.contains(value))
        .cloned()
        .collect()
}

fn unique_count(values: &[String]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn unique_count_vec(values: &[Vec<String>]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
