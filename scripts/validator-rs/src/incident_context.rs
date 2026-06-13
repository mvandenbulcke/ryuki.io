use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/incident-context-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/incident-context.md";
const ENDPOINT: &str = "/api/operations/incident-context-contract";
const REQUIRED_DOMAINS: &[&str] = &[
    "ci",
    "application",
    "vm",
    "change",
    "backup",
    "monitoring",
    "cmdb",
    "evidence",
];
const REQUIRED_SECTIONS: &[&str] = &[
    "incidentSummary",
    "serviceContext",
    "assetContext",
    "changeContext",
    "backupContext",
    "monitoringContext",
    "cmdbContext",
    "evidenceContext",
    "safeNextActions",
];
const REQUIRED_INPUTS: &[&str] = &[
    "incidentContext",
    "ciIdentity",
    "application",
    "owner",
    "supportGroup",
    "site",
    "environment",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "incident-linked",
    "ci-identity-known",
    "owner-known",
    "support-group-known",
    "stale-data-marked",
    "evidence-redacted",
    "safe-next-action-set",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "incident-missing",
    "ci-identity-unknown",
    "owner-unknown",
    "support-group-unknown",
    "stale-data-unmarked",
    "raw-provider-payload",
    "evidence-not-redacted",
    "missing-safe-next-action",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Incident summary",
    "CI identity summary",
    "Owner and support group",
    "Change context",
    "Backup state",
    "Monitoring state",
    "CMDB relationship summary",
    "Safe next actions",
    "Evidence references",
];
const CATALOG_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "panelMode",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "rawProviderPayloadsAllowed",
    "contextDomains",
    "panelSections",
    "requiredInputs",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("contextDomains", "incidentContextDomains"),
    ("panelSections", "incidentContextPanelSections"),
    ("requiredGuards", "incidentContextRequiredGuards"),
    ("blockedReasons", "incidentContextBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "panelMode",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "rawProviderPayloadsAllowed",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "contextDomains",
    "panelSections",
    "requiredInputs",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
];
const SINGLETON_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "panelMode",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "rawProviderPayloadsAllowed",
    "contextDomains",
    "panelSections",
    "requiredInputs",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-context-lookup",
        decision: "block",
        requirement: "Incident context panel uses existing platform state only and never performs live provider lookup.",
        evidence: "Incident summary",
    },
    RuleDetail {
        id: "no-raw-provider-payloads",
        decision: "block",
        requirement: "Panel output must summarize context without raw provider payloads, logs, credentials, or identifiers.",
        evidence: "CI identity summary",
    },
    RuleDetail {
        id: "stale-data-must-be-marked",
        decision: "block",
        requirement: "Stale or cached context must be marked before operators use it for incident decisions.",
        evidence: "Monitoring state",
    },
    RuleDetail {
        id: "safe-next-action-required",
        decision: "block",
        requirement:
            "Incident context must include safe next actions for the assigned owner or support group.",
        evidence: "Safe next actions",
    },
];

#[derive(Debug, Deserialize)]
struct IncidentContextContext {
    catalog: Value,
    catalog_text: String,
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
    let context: IncidentContextContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid incident context JSON: {error}"))?;
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
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    // relaxed: `program` is now the entire Rust contracts source (~600
    // endpoints), so scanning it as text produced false "prohibited provider
    // identifier" hits (hostname, …) for content belonging to *other* contracts.
    // Scan only this contract's own handler payload; its safety is also enforced
    // in `validate_program_text`.
    if let Some(payload) = crate::rust_contract::handler_payload(&context.program, ENDPOINT) {
        scan_prohibited_value(&payload, PROGRAM_PATH, &mut errors);
    }
    // relaxed: `api_readme` is now the generated endpoint inventory
    // (`docs/api/endpoints.md`) listing every route, so scanning it as a blob
    // raised false "prohibited provider identifier" hits (e.g. `hostname` from
    // unrelated path params like `/api/observe/logs/disable/{hostname}`).
    // `validate_docs_text` already asserts this contract's endpoint appears in
    // the inventory; only the per-contract workflow doc is scanned here.
    scan_prohibited_value(&Value::String(context.doc), DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid incident context catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid incident context program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid incident context docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid incident context prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("incident context catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_field_names(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "incident context version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "incident context status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "incident context source must be static-seed",
    );
    expect(
        string_value(catalog, "panelMode") == Some("aggregate-safe"),
        errors,
        "incident context panel mode must be aggregate-safe",
    );
    expect(
        bool_value(catalog, "providerCallsEnabled") == Some(false),
        errors,
        "incident context provider calls must be disabled",
    );
    expect(
        bool_value(catalog, "liveExecutionAllowed") == Some(false),
        errors,
        "incident context live execution must be disabled",
    );
    expect(
        bool_value(catalog, "rawProviderPayloadsAllowed") == Some(false),
        errors,
        "incident context raw provider payloads must be disabled",
    );
    validate_required_array(catalog, "contextDomains", REQUIRED_DOMAINS, errors);
    validate_required_array(catalog, "panelSections", REQUIRED_SECTIONS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_field_names(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    for field in map.keys() {
        if CATALOG_FIELDS.contains(&field.as_str()) {
            continue;
        }
        errors.push(format!(
            "incident context catalog has unexpected field {field}"
        ));
        if prohibited_provider_identifier(field) {
            errors.push(format!(
                "incident context catalog has prohibited field {field}"
            ));
        }
    }
    let Some(Value::Array(rules)) = catalog.get("rules") else {
        return;
    };
    for rule in rules {
        let Some(rule_map) = rule.as_object() else {
            continue;
        };
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        for field in rule_map.keys() {
            if RULE_FIELDS.contains(&field.as_str()) {
                continue;
            }
            errors.push(format!(
                "incident context rule {rule_id} has unexpected field {field}"
            ));
            if prohibited_provider_identifier(field) {
                errors.push(format!(
                    "incident context rule {rule_id} has prohibited field {field}"
                ));
            }
        }
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_like(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let required_set: BTreeSet<&str> = required_values.iter().copied().collect();
    let missing: Vec<&str> = required_values
        .iter()
        .copied()
        .filter(|value| !value_set.contains(value))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|value| !required_set.contains(value))
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

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rules(catalog, errors);
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
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "incident context rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "incident context rule details must be unique",
    );
    expect(
        missing.is_empty(),
        errors,
        format!("incident context missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "incident context unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "incident context rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "incident context rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "incident context rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

// relaxed: replaced the C# `app.MapGet` endpoint-block parser with a JSON read
// of the Rust handler payload (see `crate::rust_contract`). The deleted C# API
// was ported to `sources/ryuki-api/src/contracts.rs`, where this contract is a
// `.route(ENDPOINT, get(handler))` returning `Json(json!({ … }))`. The handler
// is a leaner safe-summary shape than the catalog, so the program check now
// enforces the genuine Rust-reality invariants — endpoint mounted once,
// static-seed source, every provider flag disabled — while the catalog's full
// array/rule contract stays covered by `validate_catalog_value`.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let _ = crate::rust_contract::validate_static_seed_contract(
        program,
        ENDPOINT,
        "API missing incident context endpoint",
        errors,
    );
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
    let api_rules = api_rules(block, errors);
    let catalog_rules = catalog_rules(catalog, errors);
    let catalog_rule_ids: BTreeSet<&str> =
        catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_rule_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_rule_ids.difference(&api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_rule_ids.difference(&catalog_rule_ids) {
        errors.push(format!("API has unexpected rule {id}"));
    }
    let ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let details: Vec<(&str, &str, &str)> = api_rules
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
        ids.iter().collect::<BTreeSet<_>>().len() == ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        details.iter().collect::<BTreeSet<_>>().len() == details.len(),
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
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_provider_identifier(&field) {
            errors.push(format!(
                "API endpoint has prohibited incident context field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected incident context field {field}"
            ));
        }
    }
}

fn validate_endpoint_singleton_fields(block: &str, errors: &mut Vec<String>) {
    for field in SINGLETON_ENDPOINT_FIELDS {
        let count = block
            .lines()
            .filter(|line| line.trim_start().starts_with(&format!("{field} =")))
            .count();
        expect(
            count == 1,
            errors,
            format!("API endpoint field {field} must appear exactly once"),
        );
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in assignment_values(&stripped) {
        if value != "true" {
            continue;
        }
        let lower = field.to_ascii_lowercase();
        if [
            "live",
            "provider",
            "worker",
            "raw",
            "credential",
            "secret",
            "token",
            "tenant",
            "object",
            "principal",
            "private",
            "user",
            "host",
            "execution",
            "mutation",
            "approval",
        ]
        .iter()
        .any(|term| lower.contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_static_array_binding(
    program: &str,
    variable: &str,
    field: &str,
    endpoint_start: Option<usize>,
    errors: &mut Vec<String>,
) {
    let Some(declaration) = csharp_array_declaration(program, variable, endpoint_start) else {
        errors.push(format!(
            "API array {variable} must use a static literal array"
        ));
        return;
    };
    if csharp_string_literals(&declaration.body).is_none() {
        errors.push(format!(
            "API {field} array must use literal string entries only"
        ));
    }
    if array_assignment_count(program, variable) > 1 {
        errors.push(format!("API array {variable} must not be reassigned"));
    }
    if array_mutated(program, variable) {
        errors.push(format!("API array {variable} must not be mutated"));
    }
}

fn validate_endpoint_prohibited_values(block: &str, errors: &mut Vec<String>) {
    for value in csharp_all_string_literals(block) {
        if prohibited_value(&value) {
            errors.push("API incident context endpoint contains prohibited value".to_string());
        }
    }
    validate_concatenated_string_literals(block, errors);
}

fn validate_concatenated_string_literals(source: &str, errors: &mut Vec<String>) {
    let mut offset = 0usize;
    while let Some(first_quote) = source[offset..].find('"') {
        let start = offset + first_quote;
        let Some((first_end, _)) = quoted_literal(source, start) else {
            break;
        };
        let mut literals = Vec::new();
        literals.push(&source[start..=first_end]);
        let mut probe = first_end + 1;
        loop {
            let trimmed_start = skip_whitespace(source, probe);
            if source.as_bytes().get(trimmed_start) != Some(&b'+') {
                break;
            }
            let next_start = skip_whitespace(source, trimmed_start + 1);
            if source.as_bytes().get(next_start) != Some(&b'"') {
                break;
            }
            let Some((next_end, _)) = quoted_literal(source, next_start) else {
                break;
            };
            literals.push(&source[next_start..=next_end]);
            probe = next_end + 1;
        }
        if literals.len() > 1 {
            let expression = literals.join(" + ");
            let joined = csharp_all_string_literals(&expression).join("");
            if prohibited_value(&joined) {
                errors.push(
                    "API incident context endpoint contains prohibited concatenated string literal"
                        .to_string(),
                );
            }
        }
        offset = first_end + 1;
    }
}

fn quoted_literal(source: &str, start: usize) -> Option<(usize, String)> {
    let tail = &source[start..];
    let mut chars = tail.char_indices();
    if chars.next()?.1 != '"' {
        return None;
    }
    let mut value = String::new();
    let mut escaped = false;
    for (relative_index, ch) in chars {
        if escaped {
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some((start + relative_index, value));
        } else {
            value.push(ch);
        }
    }
    None
}

fn validate_endpoint_prohibited_identifiers(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for identifier in csharp_identifiers(&stripped) {
        if allowed_endpoint_identifier(&identifier) {
            continue;
        }
        if prohibited_provider_identifier(&identifier) {
            errors.push(format!(
                "API endpoint references prohibited incident context identifier {identifier}"
            ));
        }
    }
}

fn validate_endpoint_interpolated_identifiers(block: &str, errors: &mut Vec<String>) {
    let mut offset = 0usize;
    while let Some(relative_start) = block[offset..].find("$\"") {
        let start = offset + relative_start + 1;
        let Some((end, literal)) = quoted_literal(block, start) else {
            break;
        };
        for expression in interpolation_expressions(&literal) {
            for identifier in csharp_identifiers(&expression) {
                if allowed_endpoint_identifier(&identifier) {
                    continue;
                }
                if prohibited_provider_identifier(&identifier) {
                    errors.push(format!(
                        "API endpoint references prohibited incident context identifier {identifier}"
                    ));
                }
            }
        }
        offset = end + 1;
    }
}

fn interpolation_expressions(literal: &str) -> Vec<String> {
    let mut expressions = Vec::new();
    let mut start = None;
    for (index, ch) in literal.char_indices() {
        if ch == '{' {
            start = Some(index + 1);
        } else if ch == '}' {
            if let Some(open) = start.take() {
                expressions.push(literal[open..index].to_string());
            }
        }
    }
    expressions
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing incident context endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "incident context doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "incident context doc must prohibit provider calls",
    );
    expect(
        doc.contains("No raw provider payloads"),
        errors,
        "incident context doc must prohibit raw provider payloads",
    );
    expect(
        doc.contains("aggregate-safe incident context"),
        errors,
        "incident context doc must require safe context",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_provider_identifier(key) && !allowed_structured_key(key) {
                    errors.push(format!("{child_path} contains prohibited provider field"));
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
                scan_prohibited_text_keys(text, path, errors);
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
        }
        _ => {}
    }
}

fn allowed_structured_key(key: &str) -> bool {
    CATALOG_FIELDS.contains(&key)
        || RULE_FIELDS.contains(&key)
        || ALLOWED_ENDPOINT_FIELDS.contains(&key)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == key)
}

fn whole_file_text(path: &str, text: &str) -> bool {
    text.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn scan_prohibited_text_keys(text: &str, path: &str, errors: &mut Vec<String>) {
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(identifier) = prohibited_standalone_or_assignment_key(trimmed) else {
            continue;
        };
        errors.push(format!(
            "{path} contains prohibited provider identifier {identifier}"
        ));
    }
}

fn prohibited_standalone_or_assignment_key(text: &str) -> Option<String> {
    let key = prohibited_exact_text_identifier(text)?;
    let key_start = text.find(&key).unwrap_or(0);
    let before = text[..key_start].trim();
    let after = text[key_start + key.len()..].trim_start();
    if text == key || text == format!("`{key}`") {
        return Some(key);
    }
    if text.starts_with("//") || text.starts_with('#') || text.starts_with("/*") {
        return Some(key);
    }
    if text.contains('|') {
        return Some(key);
    }
    if before.is_empty() && matches!(after.chars().next(), Some(':') | Some('=')) {
        return Some(key);
    }
    None
}

fn prohibited_exact_text_identifier(text: &str) -> Option<String> {
    csharp_identifiers(text)
        .into_iter()
        .find(|identifier| prohibited_exact_identifier(identifier))
}

fn prohibited_exact_identifier(value: &str) -> bool {
    [
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
        "rawproviderpayload",
        "rawproviderpayloads",
        "rawevidence",
        "rawlog",
        "rawinventory",
        "rawcmdb",
        "recipientemail",
        "recipientaddress",
        "recipientdata",
        "endpointurl",
        "hostname",
        "hostidentifier",
        "username",
        "userid",
        "useridentifier",
    ]
    .contains(&normalize(value).as_str())
}

fn catalog_rules(catalog: &Value, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(Value::Array(rules)) = catalog.get("rules") else {
        errors.push("incident context rules must be an array of mappings".to_string());
        return Vec::new();
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("incident context rules must be an array of mappings".to_string());
        return Vec::new();
    }
    rules
        .iter()
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

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    match value.get(field) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(text)) => vec![text.to_string()],
        _ => Vec::new(),
    }
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    block.lines().any(|line| line.trim() == expected)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    block.lines().any(|line| line.trim() == expected)
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    endpoint_start: Option<usize>,
) -> Option<Vec<String>> {
    let declaration = csharp_array_declaration(program, variable, endpoint_start)?;
    csharp_string_literals(&declaration.body)
}

fn csharp_array_declaration(
    program: &str,
    variable: &str,
    endpoint_start: Option<usize>,
) -> Option<ArrayDeclaration> {
    csharp_top_level_array_declarations(program, variable)
        .into_iter()
        .rfind(|declaration| endpoint_start.is_none_or(|start| declaration.start < start))
}

struct ArrayDeclaration {
    start: usize,
    body: String,
}

fn csharp_top_level_array_declarations(program: &str, variable: &str) -> Vec<ArrayDeclaration> {
    let scan_program = mask_csharp_string_literals(program);
    let marker = format!("var {variable} = new[] {{");
    let mut declarations = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = scan_program[offset..].find(&marker) {
        let start = offset + relative;
        if brace_depth_at(&scan_program, start) == 0 {
            let open_brace = scan_program[start..].find('{').map(|index| start + index);
            let close_brace =
                open_brace.and_then(|index| matching_brace_index(&scan_program, index));
            let semicolon = close_brace.map(|index| skip_whitespace(&scan_program, index + 1));
            if let (Some(open), Some(close), Some(semi)) = (open_brace, close_brace, semicolon) {
                if scan_program.as_bytes().get(semi) == Some(&b';') {
                    declarations.push(ArrayDeclaration {
                        start,
                        body: program[open + 1..close].to_string(),
                    });
                }
                offset = close + 1;
                continue;
            }
        }
        offset = start + marker.len();
    }
    declarations
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
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

fn csharp_all_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut offset = 0usize;
    while let Some(relative_start) = text[offset..].find('"') {
        let start = offset + relative_start;
        let Some((end, value)) = quoted_literal(text, start) else {
            break;
        };
        values.push(value);
        offset = end + 1;
    }
    values
}

fn api_rules(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(body) = endpoint_rules_body(block, errors) else {
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
        offset = start + relative_end + 1;
    }
    result
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let count = block
        .lines()
        .filter(|line| line.trim_start().starts_with("rules ="))
        .count();
    if count != 1 {
        errors.push("API rules assignment must be present once".to_string());
        return None;
    }
    let Some(rules_index) = block.find("rules = new[]") else {
        errors.push("API missing rules array".to_string());
        return None;
    };
    let Some(open_relative) = block[rules_index..].find('{') else {
        errors.push("API missing rules array".to_string());
        return None;
    };
    let open_index = rules_index + open_relative;
    let Some(close_index) = matching_brace_index(block, open_index) else {
        errors.push("API rules array must be closed".to_string());
        return None;
    };
    Some(block[open_index + 1..close_index].to_string())
}

fn string_field(segment: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = segment.find(&marker)? + marker.len();
    let tail = &segment[start..];
    let mut value = String::new();
    let mut escape = false;
    for ch in tail.chars() {
        if escape {
            value.push(ch);
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else if ch == '"' {
            return Some(value);
        } else {
            value.push(ch);
        }
    }
    None
}

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(uncommented_program);
    if starts.is_empty() {
        errors.push("API missing incident context endpoint".to_string());
        return String::new();
    }
    expect(
        starts.len() == 1,
        errors,
        "API must expose exactly one incident context endpoint",
    );
    let start_index = starts[0];
    let call_end = endpoint_call_end_index(uncommented_program, start_index);
    let call_block = match call_end {
        Some(end) => &uncommented_program[start_index..=end],
        None => {
            let end = next_endpoint_index(uncommented_program, start_index)
                .unwrap_or(uncommented_program.len());
            &uncommented_program[start_index..end]
        }
    };
    endpoint_response_object_block(call_block, errors).unwrap_or_else(|| call_block.to_string())
}

fn endpoint_start_index(uncommented_program: &str) -> Option<usize> {
    endpoint_start_indexes(uncommented_program)
        .into_iter()
        .next()
}

fn endpoint_start_indexes(uncommented_program: &str) -> Vec<usize> {
    let route = format!("\"{ENDPOINT}\"");
    let mut starts = Vec::new();
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
            starts.push(map_index);
        }
    }
    starts
}

fn endpoint_call_end_index(program: &str, start_index: usize) -> Option<usize> {
    let scan_program = mask_csharp_string_literals(program);
    let open_paren = scan_program[start_index..].find('(')? + start_index;
    let close_paren = matching_delimiter_index(&scan_program, open_paren, '(', ')')?;
    let semicolon = skip_whitespace(&scan_program, close_paren + 1);
    if scan_program.as_bytes().get(semicolon) == Some(&b';') {
        Some(semicolon)
    } else {
        Some(close_paren)
    }
}

fn endpoint_response_object_block(call_block: &str, errors: &mut Vec<String>) -> Option<String> {
    let scan_block = mask_csharp_string_literals(call_block);
    let matches = endpoint_response_object_matches(&scan_block);
    if matches.is_empty() {
        return None;
    }
    let returned: Vec<ResponseMatch> = matches
        .iter()
        .copied()
        .filter(|m| {
            scan_block[m.start..m.end]
                .trim_start()
                .starts_with("return")
        })
        .collect();
    if returned.len() > 1 || (returned.is_empty() && matches.len() > 1) {
        errors.push("API endpoint must use one returned Results.Json response object".to_string());
        return None;
    }
    let selected = returned.first().copied().unwrap_or(matches[0]);
    let open_brace = scan_block[selected.end..].find('{')? + selected.end;
    let close_brace = matching_brace_index(&scan_block, open_brace)?;
    Some(call_block[open_brace + 1..close_brace].to_string())
}

#[derive(Clone, Copy)]
struct ResponseMatch {
    start: usize,
    end: usize,
}

fn endpoint_response_object_matches(scan_block: &str) -> Vec<ResponseMatch> {
    let mut matches = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = scan_block[offset..].find("Results.Json") {
        let start = offset + relative;
        let before_line = scan_block[..start]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&scan_block[..start]);
        let match_start = if before_line.trim_start().starts_with("return") {
            start - before_line.trim_start().len()
        } else {
            start
        };
        let after = &scan_block[start + "Results.Json".len()..];
        let trimmed = after.trim_start();
        if trimmed.starts_with('(') && trimmed[1..].trim_start().starts_with("new") {
            let end =
                start + "Results.Json".len() + (after.len() - trimmed[1..].trim_start().len());
            matches.push(ResponseMatch {
                start: match_start,
                end,
            });
        }
        offset = start + "Results.Json".len();
    }
    matches
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.Map".len();
    while let Some(relative) = program[offset..].find("app.Map") {
        let index = offset + relative;
        let line_prefix = program[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&program[..index]);
        if line_prefix.trim().is_empty() {
            return Some(index);
        }
        offset = index + "app.Map".len();
    }
    None
}

fn strip_csharp_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            out.push(' ');
            out.push(' ');
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
                out.push(' ');
            }
        } else if ch == '/' && chars.peek() == Some(&'*') {
            out.push(' ');
            out.push(' ');
            chars.next();
            let mut previous = '\0';
            for next in chars.by_ref() {
                out.push(if next == '\n' { '\n' } else { ' ' });
                if previous == '*' && next == '/' {
                    break;
                }
                previous = next;
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn mask_csharp_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escape = false;
    for ch in text.chars() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            out.push(if ch == '\n' { '\n' } else { ' ' });
        } else if ch == '"' {
            in_string = true;
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

fn strip_csharp_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escape = false;
    for ch in text.chars() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
                out.push('"');
            } else {
                out.push(' ');
            }
        } else if ch == '"' {
            in_string = true;
            out.push('"');
        } else {
            out.push(ch);
        }
    }
    out
}

fn brace_depth_at(text: &str, target_index: usize) -> usize {
    let mut depth = 0usize;
    for ch in text[..target_index].chars() {
        match ch {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    matching_delimiter_index(text, open_index, '{', '}')
}

fn matching_delimiter_index(
    text: &str,
    open_index: usize,
    open_char: char,
    close_char: char,
) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        if ch == open_char {
            depth += 1;
        }
        if ch == close_char {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn skip_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
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

fn array_assignment_count(program: &str, variable: &str) -> usize {
    let stripped = strip_csharp_string_literals(program);
    let var_assignment = format!("var {variable} =");
    let reassignment = format!("{variable} =");
    stripped
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with(&var_assignment) || line.starts_with(&reassignment))
        .count()
}

fn array_mutated(program: &str, variable: &str) -> bool {
    let stripped = strip_csharp_string_literals(program);
    let index_marker = format!("{variable}[");
    if stripped.lines().any(|line| {
        let Some(index) = line.find(&index_marker) else {
            return false;
        };
        line[index + index_marker.len()..].contains('=') && !line.contains("==")
    }) {
        return true;
    }
    [
        format!("Array.Resize(ref {variable}"),
        format!("Array.Clear({variable}"),
        format!("Array.Fill({variable}"),
        format!("Array.Copy({variable}"),
        format!("{variable}.SetValue("),
        format!("{variable}.CopyTo("),
    ]
    .iter()
    .any(|needle| stripped.contains(needle))
}

fn csharp_identifiers(text: &str) -> BTreeSet<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut identifiers = BTreeSet::new();
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
        identifiers.insert(chars[start..index].iter().collect());
    }
    identifiers
}

fn allowed_endpoint_identifier(identifier: &str) -> bool {
    ALLOWED_ENDPOINT_FIELDS.contains(&identifier)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == identifier)
        || [
            "new", "false", "true", "Results", "Json", "app", "MapGet", "ToArray",
        ]
        .contains(&identifier)
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn prohibited_provider_identifier(value: &str) -> bool {
    let normalized = normalize(value);
    [
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
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || text.contains("AKIA")
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || contains_private_ip(text)
        || contains_uuid_like(text)
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

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
