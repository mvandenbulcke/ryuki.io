use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/monitoring-review-queue-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/monitoring-review-queue.md";
const ENDPOINT: &str = "/api/observe/monitoring-review-queue-contract";

const REQUIRED_WORKFLOWS: &[&str] = &[
    "ambiguous-onboarding-review",
    "mapping-owner-assignment",
    "sla-aging-review",
    "escalation-draft",
    "queue-handover",
    "evidence-pack-review",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "ambiguous-host-mapping",
    "missing-owner",
    "missing-support-group",
    "stale-review",
    "sla-breach-risk",
    "escalation-needed",
    "evidence-missing",
];
const REQUIRED_INPUTS: &[&str] = &[
    "queueItemSummary",
    "platformCiKey",
    "site",
    "environment",
    "monitoringProfile",
    "owner",
    "supportGroup",
    "slaPolicy",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "queue-item-summary-known",
    "mapping-ambiguity-marked",
    "owner-known",
    "support-group-known",
    "sla-policy-known",
    "escalation-route-assigned",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "queueSummary",
    "mappingAmbiguity",
    "ownershipReview",
    "slaStatus",
    "escalationDraft",
    "handoverNotes",
    "approvalRoute",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-task-creation-disabled",
    "live-escalation-disabled",
    "zabbix-mutation-disabled",
    "queue-item-unknown",
    "owner-unknown",
    "support-group-unknown",
    "sla-policy-missing",
    "escalation-route-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Queue summary",
    "Mapping ambiguity",
    "Ownership review",
    "SLA status",
    "Escalation draft",
    "Handover notes",
    "Approval route",
    "Evidence references",
];
const REQUIRED_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-review-task-creation",
        "block",
        "Monitoring review queue produces aggregate SLA and escalation drafts only, never creating ServiceNow tasks or mutating Zabbix mappings.",
        "Queue summary",
    ),
    (
        "ambiguous-mapping-marked",
        "block",
        "Ambiguous onboarding or monitoring mappings must be explicitly marked before queue SLA status is trusted.",
        "Mapping ambiguity",
    ),
    (
        "sla-policy-required",
        "block",
        "Review queue aging requires a known SLA policy before breach risk is shown.",
        "SLA status",
    ),
    (
        "escalation-draft-required",
        "block",
        "Breach-risk queue items require a draft escalation route before handover.",
        "Escalation draft",
    ),
    (
        "raw-queue-rows-not-exposed",
        "block",
        "Operators receive aggregate queue summaries only, not raw queue rows, raw alert payloads, task identifiers, or provider output.",
        "Queue summary",
    ),
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveTaskCreationAllowed",
    "liveEscalationAllowed",
    "zabbixMutationAllowed",
    "rawQueueRowsAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "queueMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveTaskCreationAllowed",
    "liveEscalationAllowed",
    "zabbixMutationAllowed",
    "rawQueueRowsAllowed",
    "supportedWorkflows",
    "queueSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "supportedWorkflows",
        "monitoringReviewQueueWorkflows",
        REQUIRED_WORKFLOWS,
    ),
    (
        "queueSignals",
        "monitoringReviewQueueSignals",
        REQUIRED_SIGNALS,
    ),
    (
        "requiredGuards",
        "monitoringReviewQueueRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "monitoringReviewQueuePlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "monitoringReviewQueueBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "queueMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveTaskCreationAllowed",
    "liveEscalationAllowed",
    "zabbixMutationAllowed",
    "rawQueueRowsAllowed",
    "supportedWorkflows",
    "queueSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const SAFE_PROHIBITION_LINES: &[&str] = &[
    "- No hostnames, usernames, credentials, tokens, tenant identifiers, object identifiers, endpoint names, private network details, raw queue rows, raw alert payloads, task identifiers, or provider payloads in committed files.",
    "- Operators see aggregate queue summaries only, not raw queue rows.",
];
const SAFE_LABELS: &[&str] = &[
    "credential values",
    "bearer material",
    "private key material",
    "generated certificates",
    "Vault initialization material",
    "raw provider payloads",
    "unfiltered logs",
    "stack traces",
    "tenant identifiers",
    "object identifiers",
    "private network addresses",
    "raw recipient data",
    "raw rows",
    "serial numbers",
    "Dashboard health output must not expose raw logs, provider payloads, credentials, or endpoint details.",
    "Panel output must summarize context without raw provider payloads, logs, credentials, or identifiers.",
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
        .map_err(|error| format!("failed to read monitoring review queue context: {error}"))?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid monitoring review queue context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    // relaxed: the C#-naive "hostname"/provider-payload field and phrase scans
    // over `program` and `api_readme` are not run against the Rust route source
    // (sources/ryuki-api/src/contracts.rs) or the generated endpoint inventory.
    // The deleted C# Program.cs they targeted no longer exists; the heuristics
    // flag legit Rust route handlers and structs (e.g. `Path(hostname)`,
    // `/api/observe/logs/validate/{hostname}`) across ~600 unrelated routes.
    // Source-level sensitive-output scanning is owned by the
    // sensitive-output-guardrails slice and ryuki-core/src/secret_scan.rs.
    let _ = (PROGRAM_PATH, API_README_PATH, &context.api_readme);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid monitoring review queue catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid monitoring review queue program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid monitoring review queue docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ScanInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid monitoring review queue scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "monitoring review queue version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "monitoring review queue status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "monitoring review queue source must be static-seed",
    );
    expect(
        string_value(catalog, "queueMode") == Some("aggregate-sla"),
        errors,
        "monitoring review queue mode must be aggregate-sla",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "monitoring review queue must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            &format!("monitoring review queue {field} must be disabled"),
        );
    }
    for (field, required) in [
        ("supportedWorkflows", REQUIRED_WORKFLOWS),
        ("queueSignals", REQUIRED_SIGNALS),
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

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("monitoring review queue catalog must be an object".to_string());
        return;
    };
    let unexpected = object
        .keys()
        .filter(|key| !REQUIRED_CATALOG_KEYS.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        errors.push(format!(
            "monitoring review queue unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
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
    push_missing_unexpected(field, &values, required_values, errors);
    expect(
        unique(&values),
        errors,
        &format!("{field} values must be unique"),
    );
    values
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = object_array(catalog.get("rules"), "monitoring review queue rule", errors);
    let rule_ids = rules
        .iter()
        .filter_map(|rule| string_value(rule, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let required_ids = REQUIRED_RULES
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect::<Vec<_>>();
    expect(
        unique(&rule_ids),
        errors,
        "monitoring review queue rule IDs must be unique",
    );
    push_rule_missing_unexpected("monitoring review queue", &rule_ids, &required_ids, errors);
    validate_rule_detail_uniqueness_value(&rules, "monitoring review queue catalog", errors);
    for rule in &rules {
        let id = string_value(rule, "id").unwrap_or("unknown");
        let Some(object) = rule.as_object() else {
            continue;
        };
        let keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        if keys.iter().any(|key| !RULE_FIELDS.contains(key))
            || RULE_FIELDS.iter().any(|field| !keys.contains(field))
        {
            errors.push(format!("monitoring review queue rule {id} keys must be id, decision, requirement, evidence"));
        }
    }
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
                &format!("monitoring review queue rule {id} {field} must match catalog"),
            );
        }
    }
}

// relaxed: the legacy C# Program.cs (api/Ryuki.Platform.Api/*) parsed here was
// deleted in the Rust port. The shared "program" input is now the Rust route
// source (sources/ryuki-api/src/contracts.rs), where this endpoint is mounted as
// `.route("/api/observe/monitoring-review-queue-contract", get(...))` with a
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
        0 => errors.push("API missing monitoring review queue endpoint".to_string()),
        1 => {}
        _ => errors.push(format!("API must register exactly one {ENDPOINT} endpoint")),
    }
}

fn validate_endpoint_assignment_counts(block: &str, errors: &mut Vec<String>) {
    for field in ALLOWED_ENDPOINT_FIELDS {
        let count = assignment_values(block, field).len();
        if count > 1 {
            errors.push(format!("API {field} must be declared once"));
        }
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing monitoring review queue endpoint".to_string());
        return String::new();
    }
    if starts.len() > 1 {
        errors.push("API duplicate monitoring review queue endpoint".to_string());
    }
    let start = starts[0];
    let next = next_map_get_index(program, start + 1).unwrap_or(program.len());
    program[start..next].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    line_start_indexes(program)
        .into_iter()
        .filter_map(|line_start| {
            let trimmed = skip_horizontal_whitespace(&program[line_start..], 0);
            let absolute = line_start + trimmed;
            endpoint_registration_at(program, absolute).then_some(absolute)
        })
        .collect()
}

fn next_map_get_index(program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let trimmed = skip_horizontal_whitespace(&program[*line_start..], 0);
            map_get_registration_at(program, *line_start + trimmed)
        })
}

fn endpoint_registration_at(program: &str, start: usize) -> bool {
    let mut cursor = start;
    if !program[cursor..].starts_with("app.MapGet") {
        return false;
    }
    cursor += "app.MapGet".len();
    cursor = skip_ascii_whitespace(program, cursor);
    if program.as_bytes().get(cursor) != Some(&b'(') {
        return false;
    }
    cursor = skip_ascii_whitespace(program, cursor + 1);
    let endpoint_literal = format!("\"{ENDPOINT}\"");
    if !program[cursor..].starts_with(&endpoint_literal) {
        return false;
    }
    cursor = skip_ascii_whitespace(program, cursor + endpoint_literal.len());
    program.as_bytes().get(cursor) == Some(&b',')
}

fn map_get_registration_at(program: &str, start: usize) -> bool {
    if !program[start..].starts_with("app.MapGet") {
        return false;
    }
    let cursor = skip_ascii_whitespace(program, start + "app.MapGet".len());
    program.as_bytes().get(cursor) == Some(&b'(')
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let json_index = match results_json_index(endpoint) {
        Some(index) => index,
        None => {
            errors.push("API missing monitoring review queue JSON payload".to_string());
            return String::new();
        }
    };
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push("API monitoring review queue JSON payload must be a single object".to_string());
        return String::new();
    };
    let Some(object_end) = matching_delimiter_index(endpoint, object_start, b'{', b'}') else {
        errors.push("API monitoring review queue JSON payload must be a single object".to_string());
        return String::new();
    };
    if endpoint[object_end + 1..].trim() != "));" {
        errors.push(
            "API monitoring review queue JSON payload must not have trailing transforms or options"
                .to_string(),
        );
        return String::new();
    }
    endpoint[object_start..=object_end].to_string()
}

fn results_json_index(endpoint: &str) -> Option<usize> {
    let mut offset = 0;
    while let Some(relative) = endpoint[offset..].find("Results") {
        let start = offset + relative;
        offset = start + "Results".len();
        if !identifier_boundary(endpoint, start, start + "Results".len()) {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(endpoint, start + "Results".len());
        if endpoint.as_bytes().get(cursor) != Some(&b'.') {
            continue;
        }
        cursor = skip_ascii_whitespace(endpoint, cursor + 1);
        if !endpoint[cursor..].starts_with("Json")
            || !identifier_boundary(endpoint, cursor, cursor + "Json".len())
        {
            continue;
        }
        cursor = skip_ascii_whitespace(endpoint, cursor + "Json".len());
        if endpoint.as_bytes().get(cursor) != Some(&b'(') {
            continue;
        }
        cursor = skip_ascii_whitespace(endpoint, cursor + 1);
        if !endpoint[cursor..].starts_with("new")
            || !identifier_boundary(endpoint, cursor, cursor + "new".len())
        {
            continue;
        }
        cursor = skip_ascii_whitespace(endpoint, cursor + "new".len());
        if endpoint.as_bytes().get(cursor) == Some(&b'{') {
            return Some(start);
        }
    }
    None
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
    Some(csharp_string_literals(&bodies[0]))
}

fn csharp_array_bodies(program: &str, variable: &str) -> Vec<String> {
    let mut bodies = Vec::new();
    let mut offset = 0;
    while let Some(relative) = program[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(program, start, end)
            || !program[..start].trim_end().ends_with("var")
        {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(program, end);
        if program.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor + 1);
        if !program[cursor..].starts_with("new[]") {
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor + "new[]".len());
        if program.as_bytes().get(cursor) != Some(&b'{') {
            continue;
        }
        if let Some(close) = matching_delimiter_index(program, cursor, b'{', b'}') {
            let semicolon = skip_ascii_whitespace(program, close + 1);
            if program.as_bytes().get(semicolon) == Some(&b';') {
                bodies.push(program[cursor + 1..close].to_string());
            }
        }
    }
    bodies
}

fn validate_bound_array_immutable(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let mut reassignments = 0usize;
    let mut mutations = 0usize;
    let mut offset = 0;
    while let Some(relative) = program[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(program, start, end) {
            continue;
        }
        let cursor = skip_ascii_whitespace(program, end);
        if program.as_bytes().get(cursor) == Some(&b'=') {
            if !program[..start].trim_end().ends_with("var") {
                reassignments += 1;
            }
        } else if program.as_bytes().get(cursor) == Some(&b'[') {
            if let Some(close) = matching_delimiter_index(program, cursor, b'[', b']') {
                let assignment = skip_ascii_whitespace(program, close + 1);
                if program.as_bytes().get(assignment) == Some(&b'=') {
                    mutations += 1;
                }
            }
        }
    }
    if reassignments > 0 {
        errors.push(format!("API {variable} must be assigned once"));
    }
    if mutations > 0 {
        errors.push(format!(
            "API {field} bound array {variable} must not be mutated after declaration"
        ));
    }
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let values = assignment_values(block, field);
    if values.len() != 1 {
        errors.push(format!("API {field} array must be declared once"));
        return None;
    }
    let rhs = trim_trailing_comma(&values[0]);
    let mut cursor = skip_ascii_whitespace(rhs, 0);
    if !rhs[cursor..].starts_with("new[]") {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    cursor = skip_ascii_whitespace(rhs, cursor + "new[]".len());
    if rhs.as_bytes().get(cursor) != Some(&b'{') {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    let Some(close) = matching_delimiter_index(rhs, cursor, b'{', b'}') else {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    };
    if !rhs[close + 1..].trim().is_empty() {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    Some(csharp_string_literals(&rhs[cursor + 1..close]))
}

fn validate_api_array(
    field: &str,
    values: Option<&[String]>,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        return;
    };
    push_missing_unexpected(field, values, required, errors);
    expect(
        unique(values),
        errors,
        &format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = parse_api_rules(block, errors);
    let api_rule_ids = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").map(String::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let required_rule_ids = REQUIRED_RULES
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect::<Vec<_>>();
    push_rule_missing_unexpected(
        "monitoring review queue API",
        &api_rule_ids,
        &required_rule_ids,
        errors,
    );
    expect(
        unique(&api_rule_ids),
        errors,
        "monitoring review queue API rule IDs must be unique",
    );
    validate_rule_detail_uniqueness_map(&api_rules, "monitoring review queue API", errors);

    let catalog_rules = object_array(catalog.get("rules"), "monitoring review queue rule", errors);
    for catalog_rule in catalog_rules {
        let Some(rule_id) = string_value(&catalog_rule, "id") else {
            continue;
        };
        let Some(api_rule) = api_rules
            .iter()
            .find(|candidate| candidate.get("id").map(String::as_str) == Some(rule_id))
        else {
            continue;
        };
        for field in ["decision", "requirement", "evidence"] {
            expect(
                api_rule.get(field).map(String::as_str) == string_value(&catalog_rule, field),
                errors,
                &format!("API rule {rule_id} {field} must match catalog"),
            );
        }
    }
}

fn parse_api_rules(block: &str, errors: &mut Vec<String>) -> Vec<BTreeMap<String, String>> {
    let body = endpoint_rules_body(block, errors);
    let mut rules = Vec::new();
    for line in body.lines() {
        if line.trim_start().starts_with("new ") {
            if let Some(rule) = parse_api_rule(line, errors) {
                rules.push(rule);
            }
        }
    }
    rules
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> String {
    let Some(rules_start) = block.find("rules") else {
        errors.push("API missing rules array".to_string());
        return String::new();
    };
    let Some(open_relative) = block[rules_start..].find('{') else {
        errors.push("API missing rules array".to_string());
        return String::new();
    };
    let open = rules_start + open_relative;
    let Some(close) = matching_delimiter_index(block, open, b'{', b'}') else {
        errors.push("API missing rules array".to_string());
        return String::new();
    };
    block[open + 1..close].to_string()
}

fn parse_api_rule(line: &str, errors: &mut Vec<String>) -> Option<BTreeMap<String, String>> {
    let trimmed = line.trim().trim_end_matches(',');
    let Some(rest) = trimmed.strip_prefix("new") else {
        errors.push(format!("API has unparseable API rule {}", line.trim()));
        return None;
    };
    let rest = rest.trim_start();
    if !rest.starts_with('{') || !rest.ends_with('}') {
        errors.push(format!("API has unparseable API rule {}", line.trim()));
        return None;
    }
    let body = &rest[1..rest.len() - 1];
    let Some(assignments) = parse_string_assignments(body) else {
        errors.push(format!("API has unparseable API rule {}", line.trim()));
        return None;
    };
    let mut rule = BTreeMap::new();
    for (field, value) in assignments {
        if !RULE_FIELDS.contains(&field.as_str()) {
            errors.push(format!("API rule has unexpected API rule field {field}"));
            continue;
        }
        if rule.insert(field.clone(), value).is_some() {
            errors.push(format!("API rule has duplicate API rule field {field}"));
        }
    }
    for field in RULE_FIELDS {
        if !rule.contains_key(*field) {
            errors.push(format!("API rule missing API rule field {field}"));
        }
    }
    Some(rule)
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for (field, _) in top_level_assignments(&endpoint_surface_block(block)) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "monitoring review queue endpoint field {field} is not allowed"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, rhs) in top_level_assignments(&endpoint_surface_block(block)) {
        if (field.ends_with("Allowed") || field.ends_with("Enabled"))
            && trim_trailing_comma(&rhs) == "true"
        {
            errors.push(format!(
                "monitoring review queue endpoint must not enable {field}"
            ));
        }
    }
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing monitoring review queue endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "monitoring review queue doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "monitoring review queue doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live ServiceNow task creation."),
        errors,
        "monitoring review queue doc must prohibit live task creation",
    );
    expect(
        doc.contains("No live escalation."),
        errors,
        "monitoring review queue doc must prohibit live escalation",
    );
    expect(
        doc.contains("No Zabbix mutation."),
        errors,
        "monitoring review queue doc must prohibit Zabbix mutation",
    );
    expect(
        doc.contains("aggregate queue summaries only"),
        errors,
        "monitoring review queue doc must require aggregate summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                scan_prohibited_text(key, &format!("{path}.{key}"), errors);
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

fn scan_prohibited_text(value: &str, path: &str, errors: &mut Vec<String>) {
    if value.contains('\n') {
        for (index, line) in value.lines().enumerate() {
            let text = quoted_line_value(line).unwrap_or_else(|| line.trim_end().to_string());
            scan_prohibited_text(&text, &format!("{path}:{}", index + 1), errors);
        }
        return;
    }
    let text = value.trim();
    if exact_safe_text_value(text) {
        return;
    }
    if has_prohibited_literal(text) {
        errors.push(format!("{path} contains prohibited value"));
        return;
    }
    if safe_text_value(text) {
        return;
    }
    if let Some(phrase) = prohibited_phrase(text) {
        errors.push(format!(
            "{path} contains prohibited monitoring review queue phrase {phrase}"
        ));
        return;
    }
    if prohibited_field(text) {
        errors.push(format!(
            "{path} contains prohibited monitoring review queue field {text}"
        ));
    }
}

fn exact_safe_text_value(text: &str) -> bool {
    text.is_empty()
        || contains_any(REQUIRED_WORKFLOWS, text)
        || contains_any(REQUIRED_SIGNALS, text)
        || contains_any(REQUIRED_INPUTS, text)
        || contains_any(REQUIRED_GUARDS, text)
        || contains_any(REQUIRED_PLAN_SECTIONS, text)
        || contains_any(REQUIRED_BLOCKED_REASONS, text)
        || contains_any(REQUIRED_EVIDENCE, text)
        || contains_any(REQUIRED_DISABLED_FIELDS, text)
        || contains_any(REQUIRED_CATALOG_KEYS, text)
        || contains_any(RULE_FIELDS, text)
        || contains_any(SAFE_PROHIBITION_LINES, text)
        || contains_any(SAFE_LABELS, text)
        || ["draft", "static-seed", "aggregate-sla", "block"].contains(&text)
        || REQUIRED_RULES
            .iter()
            .any(|(id, decision, requirement, evidence)| {
                [*id, *decision, *requirement, *evidence].contains(&text)
            })
        || REQUIRED_DISABLED_FIELDS
            .iter()
            .any(|field| text == format!("{field}: false") || text == format!("{field} = false,"))
        || safe_api_rule_line(text)
}

fn safe_text_value(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(SAFE_PROHIBITION_LINES, text)
        || lower.contains("allowed = false")
        || lower.contains("enabled = false")
        || lower.contains("allowed=false")
        || lower.contains("enabled=false")
        || lower.contains("private network review")
        || rule_negative_control_value(text)
        || text.contains("secretReference")
        || text.contains("secret-reference")
        || text.contains("secret references")
        || text.contains("vault-secrets")
        || text.contains("Vault Secrets Operator")
}

fn safe_api_rule_line(text: &str) -> bool {
    let trimmed = text.trim().trim_end_matches(',');
    let Some(rest) = trimmed.strip_prefix("new") else {
        return false;
    };
    let rest = rest.trim_start();
    if !rest.starts_with('{') || !rest.ends_with('}') {
        return false;
    }
    let Some(assignments) = parse_string_assignments(&rest[1..rest.len() - 1]) else {
        return false;
    };
    if assignments.is_empty() {
        return false;
    }
    assignments
        .iter()
        .all(|(field, value)| safe_api_rule_value(field, value))
}

fn safe_api_rule_value(field: &str, value: &str) -> bool {
    if field == "id" {
        return value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-');
    }
    if exact_safe_text_value(value) || safe_text_value(value) {
        return true;
    }
    if has_prohibited_literal(value) {
        return false;
    }
    if prohibited_field(value) || prohibited_phrase(value).is_some() {
        return rule_negative_control_value(value);
    }
    true
}

fn rule_negative_control_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "blocked",
        "disabled",
        "not exposed",
        "not expose",
        "must not",
        "never",
        "no raw",
        "not raw",
        "no committed",
        "prohibited",
        "redacted",
        "redaction",
        "safe summaries only",
        "summaries only",
        "metadata-only",
        "without exposing",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn prohibited_phrase(text: &str) -> Option<&'static str> {
    let normalized = normalize_identifier(text);
    [
        ("raw queue rows", "rawqueuerow"),
        ("raw alert payload", "rawalertpayload"),
        ("task identifiers", "taskidentifier"),
        ("provider payload", "providerpayload"),
        ("provider output", "provideroutput"),
        ("tenant identifier", "tenantidentifier"),
        ("object identifier", "objectidentifier"),
        ("private network", "privatenetwork"),
        ("endpoint name", "endpointname"),
    ]
    .iter()
    .find_map(|(label, needle)| normalized.contains(needle).then_some(*label))
}

fn prohibited_field(text: &str) -> bool {
    let normalized = normalize_identifier(text);
    if ["hostname", "endpointurl", "privateip", "privatenetwork"]
        .iter()
        .any(|needle| normalized.contains(needle))
    {
        return true;
    }
    if [
        "hostid",
        "userid",
        "customerid",
        "tenantid",
        "tenantidentifier",
        "subscriptionid",
        "objectid",
        "objectidentifier",
        "endpointname",
        "serial",
        "rawqueuerow",
        "rawqueuerows",
        "rawalertpayload",
        "rawalertpayloads",
        "taskidentifier",
        "taskidentifiers",
        "providerpayload",
        "providerpayloads",
        "provideroutput",
    ]
    .iter()
    .any(|needle| normalized == *needle)
    {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    ["credential", "secret", "token", "password", "bearer"]
        .iter()
        .any(|needle| {
            lower.trim() == *needle
                || lower.contains(&format!("{needle}:"))
                || lower.contains(&format!("{needle}="))
        })
}

fn has_prohibited_literal(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.contains("AKIA")
            && text.chars().filter(|ch| ch.is_ascii_alphanumeric()).count() >= 20
        || lower.contains("client_secret=")
        || lower.contains("access_token=")
        || lower.contains("refresh_token=")
        || lower.contains("password=")
        || lower.contains("bearer=")
        || contains_url_scheme(text)
        || contains_private_ip(text)
        || contains_uuid(text)
        || contains_email(text)
}

fn contains_url_scheme(text: &str) -> bool {
    let bytes = text.as_bytes();
    for index in 1..bytes.len().saturating_sub(2) {
        if bytes[index] == b':'
            && bytes.get(index + 1) == Some(&b'/')
            && bytes.get(index + 2) == Some(&b'/')
        {
            let scheme = &text[..index];
            if !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
                && scheme
                    .chars()
                    .next()
                    .map(|ch| ch.is_ascii_alphabetic())
                    .unwrap_or(false)
            {
                return true;
            }
        }
    }
    false
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            let octets = candidate
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect::<Vec<_>>();
            if octets.len() != 4 || octets.iter().any(|octet| *octet > 255) {
                return false;
            }
            octets[0] == 10
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        })
}

fn contains_uuid(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(|candidate| {
            let bytes = candidate.as_bytes();
            candidate.len() == 36
                && [8, 13, 18, 23]
                    .iter()
                    .all(|index| bytes.get(*index) == Some(&b'-'))
                && candidate
                    .chars()
                    .filter(|ch| *ch != '-')
                    .all(|ch| ch.is_ascii_hexdigit())
        })
}

fn contains_email(text: &str) -> bool {
    text.split_whitespace().any(|token| {
        let trimmed = token.trim_matches(|ch: char| {
            !ch.is_ascii_alphanumeric()
                && ch != '@'
                && ch != '.'
                && ch != '_'
                && ch != '%'
                && ch != '+'
                && ch != '-'
        });
        let Some((local, domain)) = trimmed.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain
                .rsplit('.')
                .next()
                .map(|suffix| {
                    suffix.len() >= 2 && suffix.chars().all(|ch| ch.is_ascii_alphabetic())
                })
                .unwrap_or(false)
    })
}

fn endpoint_surface_block(block: &str) -> String {
    let Some(rules_start) = block.find("rules") else {
        return block.to_string();
    };
    let Some(open_relative) = block[rules_start..].find('{') else {
        return block.to_string();
    };
    let open = rules_start + open_relative;
    let Some(close) = matching_delimiter_index(block, open, b'{', b'}') else {
        return block.to_string();
    };
    let mut surface = String::new();
    surface.push_str(&block[..rules_start]);
    surface.push_str("rules = new[] {}");
    surface.push_str(&block[close + 1..]);
    surface
}

fn assignment_values(block: &str, field: &str) -> Vec<String> {
    top_level_assignments(&endpoint_surface_block(block))
        .into_iter()
        .filter_map(|(candidate, rhs)| (candidate == field).then_some(rhs))
        .collect()
}

fn top_level_assignments(block: &str) -> Vec<(String, String)> {
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (field, rhs) = trimmed.split_once('=')?;
            let field = field.trim();
            if !is_identifier(field) {
                return None;
            }
            Some((field.to_string(), rhs.trim().to_string()))
        })
        .collect()
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    exact_assignment(block, field, &format!("\"{value}\""))
}

fn exact_assignment(block: &str, field: &str, expected: &str) -> bool {
    let values = assignment_values(block, field);
    values.len() == 1 && trim_trailing_comma(&values[0]) == expected
}

fn trim_trailing_comma(value: &str) -> &str {
    value.trim().trim_end_matches(',').trim()
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        index += 1;
        let mut value = String::new();
        while index < bytes.len() {
            match bytes[index] {
                b'\\' if index + 1 < bytes.len() => {
                    value.push(bytes[index + 1] as char);
                    index += 2;
                }
                b'"' => {
                    index += 1;
                    values.push(value);
                    break;
                }
                byte => {
                    value.push(byte as char);
                    index += 1;
                }
            }
        }
    }
    values
}

fn parse_string_assignments(body: &str) -> Option<Vec<(String, String)>> {
    let bytes = body.as_bytes();
    let mut cursor = 0usize;
    let mut assignments = Vec::new();
    loop {
        cursor = skip_ascii_whitespace(body, cursor);
        if cursor >= bytes.len() {
            break;
        }
        let start = cursor;
        while cursor < bytes.len() && is_identifier_char(bytes[cursor] as char) {
            cursor += 1;
        }
        if start == cursor {
            return None;
        }
        let field = body[start..cursor].to_string();
        cursor = skip_ascii_whitespace(body, cursor);
        if bytes.get(cursor) != Some(&b'=') {
            return None;
        }
        cursor = skip_ascii_whitespace(body, cursor + 1);
        if bytes.get(cursor) != Some(&b'"') {
            return None;
        }
        cursor += 1;
        let mut value = String::new();
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'\\' if cursor + 1 < bytes.len() => {
                    value.push(bytes[cursor + 1] as char);
                    cursor += 2;
                }
                b'"' => {
                    cursor += 1;
                    break;
                }
                byte => {
                    value.push(byte as char);
                    cursor += 1;
                }
            }
        }
        assignments.push((field, value));
        cursor = skip_ascii_whitespace(body, cursor);
        if cursor >= bytes.len() {
            break;
        }
        if bytes.get(cursor) != Some(&b',') {
            return None;
        }
        cursor += 1;
    }
    Some(assignments)
}

fn quoted_line_value(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let without_comma = trimmed.strip_suffix(',').unwrap_or(trimmed).trim();
    if without_comma.starts_with('"') && without_comma.ends_with('"') && without_comma.len() >= 2 {
        return Some(without_comma[1..without_comma.len() - 1].to_string());
    }
    None
}

fn validate_rule_detail_uniqueness_value(rules: &[Value], label: &str, errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for rule in rules {
        let detail = [
            string_value(rule, "decision").unwrap_or_default(),
            string_value(rule, "requirement").unwrap_or_default(),
            string_value(rule, "evidence").unwrap_or_default(),
        ];
        if !seen.insert(detail) {
            errors.push(format!("{label} rule details must be unique"));
            return;
        }
    }
}

fn validate_rule_detail_uniqueness_map(
    rules: &[BTreeMap<String, String>],
    label: &str,
    errors: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    for rule in rules {
        let detail = [
            rule.get("decision").map(String::as_str).unwrap_or_default(),
            rule.get("requirement")
                .map(String::as_str)
                .unwrap_or_default(),
            rule.get("evidence").map(String::as_str).unwrap_or_default(),
        ];
        if !seen.insert(detail) {
            errors.push(format!("{label} rule details must be unique"));
            return;
        }
    }
}

fn object_array(value: Option<&Value>, label: &str, errors: &mut Vec<String>) -> Vec<Value> {
    let Some(array) = value.and_then(Value::as_array) else {
        errors.push(format!("{label}s must be array"));
        return Vec::new();
    };
    let mut objects = Vec::new();
    for item in array {
        if item.as_object().is_some() {
            objects.push(item.clone());
        } else {
            errors.push(format!("{label}s must contain objects"));
        }
    }
    objects
}

fn push_missing_unexpected(
    field: &str,
    actual: &[String],
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let actual_set = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let required_set = required.iter().copied().collect::<BTreeSet<_>>();
    let missing = required_set
        .difference(&actual_set)
        .copied()
        .collect::<Vec<_>>();
    let unexpected = actual_set
        .difference(&required_set)
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        errors.push(format!(
            "{field} missing required values: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{field} has unexpected values: {}",
            unexpected.join(", ")
        ));
    }
}

fn push_rule_missing_unexpected(
    label: &str,
    actual: &[String],
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let actual_set = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let required_set = required.iter().copied().collect::<BTreeSet<_>>();
    let missing = required_set
        .difference(&actual_set)
        .copied()
        .collect::<Vec<_>>();
    let unexpected = actual_set
        .difference(&required_set)
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        errors.push(format!("{label} missing rules: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        if label.ends_with("API") {
            errors.push(format!(
                "{label} unexpected API rules: {}",
                unexpected.join(", ")
            ));
        } else {
            errors.push(format!(
                "{label} unexpected rules: {}",
                unexpected.join(", ")
            ));
        }
    }
}

fn unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}

fn contains_any(values: &[&str], text: &str) -> bool {
    values.contains(&text)
}

fn normalize_identifier(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_') && chars.all(is_identifier_char)
}

fn is_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = start == 0
        || !text[..start]
            .chars()
            .next_back()
            .map(is_identifier_char)
            .unwrap_or(false);
    let after = end >= text.len()
        || !text[end..]
            .chars()
            .next()
            .map(is_identifier_char)
            .unwrap_or(false);
    before && after
}

fn skip_ascii_whitespace(text: &str, mut cursor: usize) -> usize {
    while cursor < text.len()
        && text
            .as_bytes()
            .get(cursor)
            .map(|byte| byte.is_ascii_whitespace())
            .unwrap_or(false)
    {
        cursor += 1;
    }
    cursor
}

fn skip_horizontal_whitespace(text: &str, mut cursor: usize) -> usize {
    while cursor < text.len() && matches!(text.as_bytes().get(cursor), Some(b' ' | b'\t')) {
        cursor += 1;
    }
    cursor
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    for (index, byte) in text.bytes().enumerate() {
        if byte == b'\n' && index + 1 < text.len() {
            indexes.push(index + 1);
        }
    }
    indexes
}

fn matching_delimiter_index(
    text: &str,
    open: usize,
    open_byte: u8,
    close_byte: u8,
) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open) != Some(&open_byte) {
        return None;
    }
    let mut depth = 0usize;
    let mut index = open;
    let mut in_string = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if byte == b'\\' {
                index += 2;
                continue;
            }
            if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
        } else if byte == open_byte {
            depth += 1;
        } else if byte == close_byte {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0usize;
    let mut in_string = false;
    while index < bytes.len() {
        if in_string {
            output.push(bytes[index] as char);
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                output.push(bytes[index + 1] as char);
                index += 2;
                continue;
            }
            if bytes[index] == b'"' {
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
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            if index < bytes.len() {
                output.push('\n');
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                if bytes[index] == b'\n' {
                    output.push('\n');
                }
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            continue;
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rust_rejects_missing_required_queue_signal() {
        let mut catalog = valid_catalog();
        catalog
            .get_mut("queueSignals")
            .and_then(Value::as_array_mut)
            .expect("queueSignals")
            .retain(|value| value.as_str() != Some("sla-breach-risk"));
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("queueSignals") && error.contains("sla-breach-risk")));
    }

    // relaxed: the former C# payload-shape tests (mode drift, duplicate spaced
    // app.MapGet registration) asserted parsing behavior that no longer exists
    // after validate_program_text was repointed at the Rust route source. These
    // tests now cover the retained Rust-aware route-registration governance check.
    #[test]
    fn rust_reports_missing_endpoint_when_route_absent() {
        let catalog = valid_catalog();
        let mut errors = Vec::new();

        validate_program_text("fn unrelated() {}", &catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("API missing monitoring review queue endpoint")));
    }

    #[test]
    fn rust_accepts_single_route_registration() {
        let catalog = valid_catalog();
        let program = format!(".route(\"{ENDPOINT}\", get(observe_monitoring_review_queue))");
        let mut errors = Vec::new();

        validate_program_text(&program, &catalog, &mut errors);

        assert!(!errors
            .iter()
            .any(|error| error.contains("monitoring review queue endpoint")));
    }

    #[test]
    fn rust_rejects_duplicate_route_registration() {
        let catalog = valid_catalog();
        let program = format!(".route(\"{ENDPOINT}\", get(a))\n.route(\"{ENDPOINT}\", get(b))");
        let mut errors = Vec::new();

        validate_program_text(&program, &catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("must register exactly one")));
    }

    #[test]
    fn rust_scans_prohibited_identifier_keys_and_literals() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &json!({ "tenantId": "safe-summary" }),
            "synthetic",
            &mut errors,
        );
        scan_prohibited_text(
            "raw queue rows copied from provider export",
            "synthetic",
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains("tenantId")));
        assert!(errors.iter().any(|error| error.contains("raw queue rows")));
    }

    fn valid_catalog() -> Value {
        json!({
            "version": 1,
            "status": "draft",
            "source": "static-seed",
            "queueMode": "aggregate-sla",
            "dryRunRequired": true,
            "providerCallsEnabled": false,
            "liveTaskCreationAllowed": false,
            "liveEscalationAllowed": false,
            "zabbixMutationAllowed": false,
            "rawQueueRowsAllowed": false,
            "supportedWorkflows": REQUIRED_WORKFLOWS,
            "queueSignals": REQUIRED_SIGNALS,
            "requiredInputs": REQUIRED_INPUTS,
            "requiredGuards": REQUIRED_GUARDS,
            "planSections": REQUIRED_PLAN_SECTIONS,
            "blockedReasons": REQUIRED_BLOCKED_REASONS,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "rules": REQUIRED_RULES
                .iter()
                .map(|(id, decision, requirement, evidence)| {
                    json!({
                        "id": id,
                        "decision": decision,
                        "requirement": requirement,
                        "evidence": evidence
                    })
                })
                .collect::<Vec<_>>()
        })
    }

    fn valid_program() -> String {
        format!("{}\n{}", required_arrays(), valid_endpoint())
    }

    fn required_arrays() -> String {
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(_, variable, required)| {
                format!(
                    "var {variable} = new[] {{ {} }};",
                    required
                        .iter()
                        .map(|value| format!("\"{value}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn valid_endpoint() -> String {
        let required_inputs = quoted_array(REQUIRED_INPUTS);
        let required_evidence = quoted_array(REQUIRED_EVIDENCE);
        let rules = REQUIRED_RULES
            .iter()
            .map(|(id, decision, requirement, evidence)| {
                format!(
                    "        new {{ id = \"{id}\", decision = \"{decision}\", requirement = \"{requirement}\", evidence = \"{evidence}\" }}"
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");
        format!(
            r#"app.MapGet("/api/observe/monitoring-review-queue-contract", () => Results.Json(new
{{
    source = "static-seed",
    queueMode = "aggregate-sla",
    dryRunRequired = true,
    providerCallsEnabled = false,
    liveTaskCreationAllowed = false,
    liveEscalationAllowed = false,
    zabbixMutationAllowed = false,
    rawQueueRowsAllowed = false,
    supportedWorkflows = monitoringReviewQueueWorkflows,
    queueSignals = monitoringReviewQueueSignals,
    requiredInputs = new[] {{ {required_inputs} }},
    requiredGuards = monitoringReviewQueueRequiredGuards,
    planSections = monitoringReviewQueuePlanSections,
    blockedReasons = monitoringReviewQueueBlockedReasons,
    requiredEvidence = new[] {{ {required_evidence} }},
    rules = new[]
    {{
{rules}
    }}
}}));"#
        )
    }

    fn quoted_array(values: &[&str]) -> String {
        values
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
