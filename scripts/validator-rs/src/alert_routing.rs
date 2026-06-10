use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/alert-routing-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const ENDPOINT: &str = "/api/observe/alert-routing-contract";
const REQUIRED_WORKFLOWS: &[&str] = &[
    "alert-routing-and-escalation",
    "zabbix-onboarding",
    "monitoring-coverage-gap-report",
];
const REQUIRED_DIMENSIONS: &[&str] = &[
    "site",
    "environment",
    "application",
    "criticality",
    "supportGroup",
    "maintenanceWindow",
    "alertSeverity",
    "ownershipState",
];
const REQUIRED_INPUTS: &[&str] = &[
    "alertSource",
    "site",
    "environment",
    "application",
    "criticality",
    "supportGroup",
    "maintenanceWindow",
    "escalationPolicy",
];
const REQUIRED_GUARDS: &[&str] = &[
    "owner-known",
    "support-group-known",
    "maintenance-window-known",
    "alert-template-mapped",
    "escalation-policy-assigned",
    "evidence-redacted",
];
const REQUIRED_STAGES: &[&str] = &[
    "suppress-during-maintenance",
    "notify-support-group",
    "escalate-critical-service",
    "create-review-task",
    "handover-unresolved",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "unknown-owner",
    "unknown-support-group",
    "missing-maintenance-window",
    "unmapped-alert-template",
    "escalation-policy-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Alert routing summary",
    "Validation result",
    "Support group mapping",
    "Maintenance window reference",
    "Escalation decision",
    "Handover notes",
    "Evidence references",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedWorkflows", "alertRoutingWorkflows"),
    ("routeDimensions", "alertRoutingDimensions"),
    ("requiredGuards", "alertRoutingRequiredGuards"),
    ("escalationStages", "alertRoutingEscalationStages"),
    ("blockedReasons", "alertRoutingBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRoutingAllowed",
    "supportedWorkflows",
    "routeDimensions",
    "requiredInputs",
    "requiredGuards",
    "escalationStages",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const PROHIBITED_KEYS: &[&str] = &[
    "alertid",
    "alertidentifier",
    "alertpayload",
    "vmname",
    "databasename",
    "hostname",
    "hostidentifier",
    "username",
    "userid",
    "useridentifier",
    "recipient",
    "email",
    "recipientemail",
    "credential",
    "credentials",
    "secret",
    "token",
    "password",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "liveendpoint",
    "endpointurl",
    "privateip",
    "privatenetwork",
    "rawalert",
    "rawevent",
    "providerpayload",
    "providerpayloads",
    "rawproviderpayload",
    "rawproviderpayloads",
    "sessionid",
    "problemid",
    "eventid",
];
const LOOSE_PROHIBITED_TEXT_IDENTIFIERS: &[&str] = &[
    "alertid",
    "alertidentifier",
    "alertpayload",
    "endpointurl",
    "eventid",
    "hostidentifier",
    "liveendpoint",
    "objectid",
    "objectidentifier",
    "privateip",
    "privatenetwork",
    "problemid",
    "providerpayload",
    "providerpayloads",
    "rawalert",
    "rawevent",
    "rawproviderpayload",
    "rawproviderpayloads",
    "sessionid",
    "tenantid",
    "tenantidentifier",
    "userid",
    "useridentifier",
    "vmname",
    "databasename",
    "hostname",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-alert-action",
        decision: "block",
        requirement: "Alert routing contracts produce routing plans only and never change Zabbix or ServiceNow actions.",
        evidence: "Alert routing summary",
    },
    RuleDetail {
        id: "support-group-required",
        decision: "block",
        requirement: "Alert routing requires a known support group before escalation can proceed.",
        evidence: "Support group mapping",
    },
    RuleDetail {
        id: "maintenance-window-respected",
        decision: "block",
        requirement: "Maintenance window state must be known before suppressing or escalating alerts.",
        evidence: "Maintenance window reference",
    },
    RuleDetail {
        id: "escalation-policy-required",
        decision: "block",
        requirement: "Critical service escalation requires an assigned escalation policy.",
        evidence: "Escalation decision",
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
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid alert routing context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_literals(&context.program, PROGRAM_PATH, &mut errors);
    if let Some(block) = raw_endpoint_block(&context.program) {
        scan_prohibited_text(&block, &format!("{PROGRAM_PATH}:{ENDPOINT}"), &mut errors);
    }
    scan_prohibited_text(
        &context.api_readme,
        "api/Ryuki.Platform.Api/README.md",
        &mut errors,
    );
    scan_prohibited_text(&context.doc, "docs/workflows/alert-routing.md", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid alert routing catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid alert routing program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid alert routing docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid alert routing prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("alert routing catalog must be a YAML mapping".to_string());
        return;
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "alert routing version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "alert routing status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "alert routing source must be static-seed",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "alert routing must require dry-run",
    );
    expect(
        bool_value(catalog, "providerCallsEnabled") == Some(false),
        errors,
        "alert routing provider calls must be disabled",
    );
    expect(
        bool_value(catalog, "liveRoutingAllowed") == Some(false),
        errors,
        "alert routing live routing must be disabled",
    );
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "routeDimensions", REQUIRED_DIMENSIONS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "escalationStages", REQUIRED_STAGES, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    for field in [
        "supportedWorkflows",
        "routeDimensions",
        "requiredInputs",
        "requiredGuards",
        "escalationStages",
        "blockedReasons",
    ] {
        for value in string_array_like(catalog, field) {
            if prohibited_provider_key(&value) {
                errors.push(format!(
                    "{field} contains prohibited alert routing field {value}"
                ));
            }
        }
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
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = object_rules(catalog.get("rules"));
    let parsed: Vec<Rule> = rules
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
    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let actual_ids: Vec<&str> = parsed.iter().map(|rule| rule.id.as_str()).collect();
    let actual_set: BTreeSet<&str> = actual_ids.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_set.contains(id))
        .collect();
    let unexpected: Vec<&str> = actual_ids
        .iter()
        .copied()
        .filter(|id| !expected_ids.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("alert routing missing rules: {}", missing.join(", ")),
    );
    if !unexpected.is_empty() {
        errors.push(format!(
            "alert routing unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        actual_ids.iter().collect::<BTreeSet<_>>().len() == actual_ids.len(),
        errors,
        "alert routing rule IDs must be unique",
    );
    let details: Vec<(&str, &str, &str)> = parsed
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
        details.iter().collect::<BTreeSet<_>>().len() == details.len(),
        errors,
        "alert routing catalog rule details must be unique",
    );
    for rule in rules {
        let Some(map) = rule.as_object() else {
            continue;
        };
        let id = rule.get("id").and_then(Value::as_str).unwrap_or("unknown");
        for key in map.keys() {
            if !RULE_KEYS.contains(&key.as_str()) {
                errors.push(format!("alert routing rule {id} unexpected field {key}"));
            }
        }
    }
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = parsed.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "alert routing rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "alert routing rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "alert routing rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(endpoint) = endpoint_block(program, errors) else {
        return;
    };
    let Some(block) = endpoint_payload_block(&endpoint, errors) else {
        return;
    };
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API dryRunRequired must require dry-run",
    );
    expect(
        exact_assignment(&block, "providerCallsEnabled", "false"),
        errors,
        "API providerCallsEnabled must stay disabled",
    );
    expect(
        exact_assignment(&block, "liveRoutingAllowed", "false"),
        errors,
        "API liveRoutingAllowed must stay disabled",
    );
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(program, variable, field, errors);
        validate_api_array(field, values, string_array_like(catalog, field), errors);
        validate_bound_array_not_reassigned(program, variable, field, errors);
        validate_bound_array_not_mutated(program, variable, field, errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field, errors);
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
    let catalog_rules = parsed_catalog_rules(catalog);
    let api_rules = direct_api_rule_objects(block, errors);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let missing: Vec<&str> = catalog_ids.difference(&api_ids).copied().collect();
    let unexpected: Vec<&str> = api_ids.difference(&catalog_ids).copied().collect();
    if !missing.is_empty() {
        errors.push(format!("API missing rules: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!("API unexpected rules: {}", unexpected.join(", ")));
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
    for field in top_level_assignment_fields(block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            if prohibited_provider_key(&field) {
                errors.push(format!(
                    "API endpoint has prohibited alert routing field {field}"
                ));
            } else {
                errors.push(format!(
                    "API endpoint has unexpected alert routing field {field}"
                ));
            }
        }
    }
    for field in assignment_fields(block) {
        if prohibited_provider_key(&field) {
            errors.push(format!(
                "API endpoint has prohibited alert routing field {field}"
            ));
        }
    }
    for field in top_level_projection_fields(block) {
        if prohibited_provider_key(&field) {
            errors.push(format!(
                "API endpoint has prohibited alert routing field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected alert routing projection {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in assignment_value_texts(block) {
        if compact(&value) != "true" || field == "dryRunRequired" {
            continue;
        }
        let lower = field.to_ascii_lowercase();
        if field.ends_with("Allowed")
            || field.ends_with("Enabled")
            || [
                "live",
                "provider",
                "raw",
                "execution",
                "routing",
                "action",
                "mutation",
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
                "payload",
            ]
            .iter()
            .any(|term| lower.contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_docs_text(api_readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing alert routing endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "alert routing doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "alert routing doc must prohibit provider calls",
    );
    expect(
        doc.contains("never enables live alert routing changes"),
        errors,
        "alert routing doc must prohibit live routing",
    );
    expect(
        doc.contains("provider-safe routing plans"),
        errors,
        "alert routing doc must require provider-safe plans",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> Option<String> {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing alert routing endpoint".to_string());
        return None;
    }
    if starts.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return None;
    }
    let start = starts[0];
    let next = mapget_start_indexes(program)
        .into_iter()
        .find(|index| *index > start)
        .unwrap_or(program.len());
    Some(program[start..next].to_string())
}

fn raw_endpoint_block(program: &str) -> Option<String> {
    let start = endpoint_start_indexes(program).first().copied()?;
    let next = mapget_start_indexes(program)
        .into_iter()
        .find(|index| *index > start)
        .unwrap_or(program.len());
    Some(program[start..next].to_string())
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    mapget_start_indexes(program)
        .into_iter()
        .filter(|start| mapget_route_literal(program, *start).as_deref() == Some(ENDPOINT))
        .collect()
}

fn mapget_start_indexes(program: &str) -> Vec<usize> {
    let masked = csharp_code_mask(program);
    find_all(&masked, "app.MapGet(")
}

fn mapget_route_literal(program: &str, start: usize) -> Option<String> {
    let open = program[start..].find('(')? + start;
    let index = skip_ws(program, open + 1);
    string_literal_at(program, index).map(|(value, _)| value)
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> Option<String> {
    let masked = csharp_code_mask(endpoint);
    let json_indexes = find_all(&masked, "Results.Json(new");
    if json_indexes.is_empty() {
        errors.push("API missing alert routing JSON payload".to_string());
        return None;
    }
    if json_indexes.len() != 1 {
        errors.push("API must declare exactly one alert routing JSON payload".to_string());
        return None;
    }
    let object_start = masked[json_indexes[0]..].find('{')? + json_indexes[0];
    let object_end = matching_brace_index(&masked, object_start)?;
    let suffix = masked[object_end + 1..].trim();
    if suffix != "));" {
        errors.push(
            "API alert routing JSON payload must be static anonymous object with no extra JSON arguments"
                .to_string(),
        );
        return None;
    }
    Some(endpoint[object_start..=object_end].to_string())
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
    csharp_array_literal_values(&bodies[0], &format!("API {field}"), errors)
}

fn csharp_array_bodies(program: &str, variable: &str) -> Vec<String> {
    let masked = csharp_code_mask(program);
    let pattern = format!("var {variable} = new[] {{");
    let mut bodies = Vec::new();
    let mut offset = 0;
    while let Some(found) = masked[offset..].find(&pattern) {
        let start = offset + found;
        let open = start + pattern.len() - 1;
        if let Some(close) = matching_brace_index(&masked, open) {
            let after = skip_ws(&masked, close + 1);
            if masked.as_bytes().get(after) == Some(&b';') {
                bodies.push(program[open + 1..close].to_string());
            }
            offset = close + 1;
        } else {
            offset = start + pattern.len();
        }
    }
    bodies
}

fn csharp_array_literal_values(
    body: &str,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let mut values = Vec::new();
    for member in split_top_level_members(body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        let Some((value, end)) = string_literal_at(text, 0) else {
            errors.push(format!(
                "{label} array must use literal string entries only"
            ));
            continue;
        };
        if !text[end..].trim().is_empty() {
            errors.push(format!(
                "{label} array must use literal string entries only"
            ));
            continue;
        }
        values.push(value);
    }
    Some(values)
}

fn validate_bound_array_not_reassigned(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let masked = csharp_code_mask(program);
    let mut assignments = Vec::new();
    for index in identifier_positions(&masked, variable) {
        let next = skip_ws(&masked, index + variable.len());
        if masked.as_bytes().get(next) == Some(&b'=') {
            assignments.push(is_var_declaration(&masked, index));
        }
    }
    if assignments.len() != 1 || assignments.iter().any(|declaration| !declaration) {
        errors.push(format!(
            "API {field} bound array {variable} must not be reassigned"
        ));
    }
}

fn validate_bound_array_not_mutated(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let masked = csharp_code_mask(program);
    for index in identifier_positions(&masked, variable) {
        let next = skip_ws(&masked, index + variable.len());
        if masked.as_bytes().get(next) == Some(&b'[') {
            let Some(close) = masked[next..].find(']').map(|found| next + found) else {
                continue;
            };
            let after = skip_ws(&masked, close + 1);
            if masked.as_bytes().get(after) == Some(&b'=') {
                errors.push(format!(
                    "API {field} bound array {variable} must not be mutated"
                ));
                return;
            }
        }
    }
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
    let text = texts[0].trim();
    let prefix = format!("{field} = new[] ");
    if !text.starts_with(&prefix) || !text.ends_with(',') {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    let open = text.find('{')?;
    let close = matching_brace_index(text, open)?;
    csharp_array_literal_values(&text[open + 1..close], &format!("API {field}"), errors)
}

fn direct_api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(array_block) = endpoint_array_block(block, "rules", errors) else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    for member in top_level_array_members(&array_block) {
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
        let Some(open) = text.find('{') else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        let Some(close) = matching_brace_index(&csharp_code_mask(text), open) else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        if !text[close + 1..].trim().is_empty() {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let object = &text[open..=close];
        let fields = top_level_assignment_fields(object);
        let rule = Rule {
            id: rule_string_field(object, "id").unwrap_or_default(),
            decision: rule_string_field(object, "decision").unwrap_or_default(),
            requirement: rule_string_field(object, "requirement").unwrap_or_default(),
            evidence: rule_string_field(object, "evidence").unwrap_or_default(),
        };
        for field in fields {
            if !RULE_KEYS.contains(&field.as_str()) {
                errors.push(format!(
                    "API rule {} has unexpected field {field}",
                    if rule.id.is_empty() {
                        "unknown"
                    } else {
                        &rule.id
                    }
                ));
            }
        }
        for (field, value) in [
            ("id", &rule.id),
            ("decision", &rule.decision),
            ("requirement", &rule.requirement),
            ("evidence", &rule.evidence),
        ] {
            if value.is_empty() {
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
    let start = indexes[0];
    let open = block[start..].find('{')? + start;
    let masked = csharp_code_mask(block);
    let close = matching_brace_index(&masked, open)?;
    if compact(&block[start..open]) != format!("{field}=new[]") {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] assignment"
        ));
        return None;
    }
    Some(block[open..=close].to_string())
}

fn rule_string_field(object: &str, field: &str) -> Option<String> {
    let texts = top_level_assignment_texts(object, field);
    if texts.len() != 1 {
        return None;
    }
    let text = texts[0].trim().trim_end_matches(',').trim();
    let eq = text.find('=')?;
    let rest = text[eq + 1..].trim_start();
    let (value, end) = string_literal_at(rest, 0)?;
    rest[end..].trim().is_empty().then_some(value)
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1 && compact(&texts[0]) == format!("{field}={value},")
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1 && compact(&texts[0]) == format!("{field}=\"{value}\",")
}

fn top_level_assignment_texts(block: &str, field: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    top_level_assignment_indexes(block, field)
        .into_iter()
        .map(|index| {
            block[index..assignment_end_index(&masked, index)]
                .trim()
                .to_string()
        })
        .collect()
}

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
    let masked = csharp_code_mask(block);
    identifier_positions(&masked, field)
        .into_iter()
        .filter(|index| {
            let next = skip_ws(&masked, index + field.len());
            masked.as_bytes().get(next) == Some(&b'=') && brace_depth_at(&masked, *index) == 1
        })
        .collect()
}

fn assignment_end_index(masked: &str, start: usize) -> usize {
    for index in start..masked.len() {
        let byte = masked.as_bytes()[index];
        if byte == b',' && brace_depth_at(masked, index) == 1 {
            return index + 1;
        }
        if byte == b'}' && brace_depth_at(masked, index) == 1 {
            return index;
        }
    }
    masked.len()
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let mut fields = Vec::new();
    for (field, index) in all_identifier_positions(&masked) {
        let next = skip_ws(&masked, index + field.len());
        if masked.as_bytes().get(next) == Some(&b'=') && brace_depth_at(&masked, index) == 1 {
            fields.push(field);
        }
    }
    fields
}

fn assignment_fields(block: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let mut fields = Vec::new();
    for (field, index) in all_identifier_positions(&masked) {
        let next = skip_ws(&masked, index + field.len());
        if masked.as_bytes().get(next) == Some(&b'=') {
            fields.push(field);
        }
    }
    fields
}

fn assignment_value_texts(block: &str) -> Vec<(String, String)> {
    let masked = csharp_code_mask(block);
    let mut values = Vec::new();
    for (field, index) in all_identifier_positions(&masked) {
        let next = skip_ws(&masked, index + field.len());
        if masked.as_bytes().get(next) == Some(&b'=') {
            let end = assignment_end_index(&masked, index);
            values.push((
                field,
                block[next + 1..end]
                    .trim()
                    .trim_end_matches(',')
                    .to_string(),
            ));
        }
    }
    values
}

fn top_level_projection_fields(block: &str) -> Vec<String> {
    top_level_object_members(block)
        .into_iter()
        .filter_map(|member| {
            let text = member.trim();
            if text.contains('=') || text.is_empty() {
                return None;
            }
            is_identifier(text).then_some(text.to_string())
        })
        .collect()
}

fn top_level_object_members(block: &str) -> Vec<String> {
    let text = block.trim();
    let body = if text.starts_with('{') && text.ends_with('}') {
        &text[1..text.len() - 1]
    } else {
        text
    };
    split_top_level_members(body)
}

fn top_level_array_members(array_block: &str) -> Vec<String> {
    top_level_object_members(array_block)
}

fn split_top_level_members(body: &str) -> Vec<String> {
    let masked = csharp_code_mask(body);
    let mut members = Vec::new();
    let mut start = 0;
    for index in 0..masked.len() {
        if masked.as_bytes()[index] == b',' && brace_depth_at(&masked, index) == 0 {
            members.push(body[start..index].to_string());
            start = index + 1;
        }
    }
    members.push(body[start..].to_string());
    members
}

fn parsed_catalog_rules(catalog: &Value) -> Vec<Rule> {
    object_rules(catalog.get("rules"))
        .into_iter()
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

fn object_rules(value: Option<&Value>) -> Vec<&Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect()
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_provider_key(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited alert routing field"
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
        Value::String(text) => scan_prohibited_text(text, path, errors),
        _ => {}
    }
}

fn scan_prohibited_literals(text: &str, path: &str, errors: &mut Vec<String>) {
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn scan_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
    let mut fields = BTreeSet::new();
    fields.extend(key_like_text_identifiers(text));
    fields.extend(
        text_identifiers(text)
            .into_iter()
            .filter(|field| loose_text_identifier_scan(path, field)),
    );
    for field in fields {
        if prohibited_provider_key(&field) {
            errors.push(format!(
                "{path} contains prohibited alert routing field {field}"
            ));
        }
    }
}

fn key_like_text_identifiers(text: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if is_ident_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'-')
            {
                index += 1;
            }
            let after = skip_ws(text, index);
            if matches!(bytes.get(after), Some(b':') | Some(b'=')) {
                identifiers.push(text[start..index].to_string());
            }
        } else {
            index += 1;
        }
    }
    identifiers
}

fn loose_text_identifier_scan(path: &str, field: &str) -> bool {
    path.contains(PROGRAM_PATH)
        || path.contains("synthetic")
        || has_lower_to_upper(field)
        || field.contains('_')
        || LOOSE_PROHIBITED_TEXT_IDENTIFIERS.contains(&normalize(field).as_str())
}

fn has_lower_to_upper(text: &str) -> bool {
    let mut previous_lower = false;
    for ch in text.chars() {
        if previous_lower && ch.is_ascii_uppercase() {
            return true;
        }
        previous_lower = ch.is_ascii_lowercase();
    }
    false
}

fn text_identifiers(text: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if is_ident_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'-')
            {
                index += 1;
            }
            identifiers.push(text[start..index].to_string());
        } else {
            index += 1;
        }
    }
    identifiers
}

fn prohibited_value(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("://")
        || lower.contains("-----begin ") && lower.contains("private key-----")
        || lower.contains("akia")
        || contains_private_ip(&lower)
        || contains_uuid_like(&lower)
        || contains_secret_assignment(&lower)
}

fn prohibited_provider_key(key: &str) -> bool {
    let normalized = normalize(key);
    PROHIBITED_KEYS
        .iter()
        .any(|term| normalized == *term || normalized.contains(term))
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            let octets: Vec<u16> = candidate
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect();
            octets.len() == 4
                && octets.iter().all(|octet| *octet <= 255)
                && (octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1])))
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
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|term| {
        let mut offset = 0;
        while let Some(found) = text[offset..].find(term) {
            let index = offset + found;
            let tail = text[index + term.len()..].trim_start();
            if matches!(tail.as_bytes().first(), Some(b':') | Some(b'='))
                && tail[1..].chars().any(|ch| !ch.is_whitespace())
            {
                return true;
            }
            offset = index + term.len();
        }
        false
    })
}

fn csharp_code_mask(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            let finish = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|found| index + found)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            let finish = find_bytes(text, "*/", index + 2)
                .map(|found| found + 2)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes.get(index..index + 3) == Some(br#"""""#) {
            let finish = raw_string_end(text, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index] == b'"' {
            let finish = quoted_end(bytes, index, b'"');
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index] == b'\'' {
            let finish = quoted_end(bytes, index, b'\'');
            mask_range(&mut result, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8(result).expect("mask keeps valid utf-8")
}

fn mask_range(bytes: &mut [u8], start: usize, finish: usize) {
    for byte in bytes.iter_mut().take(finish).skip(start) {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn raw_string_end(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut quotes = 0;
    while bytes.get(start + quotes) == Some(&b'"') {
        quotes += 1;
    }
    let delimiter = "\"".repeat(quotes);
    find_bytes(text, &delimiter, start + quotes)
        .map(|finish| finish + quotes)
        .unwrap_or(bytes.len())
}

fn quoted_end(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut index = start + 1;
    let mut escaped = false;
    while index < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == quote {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn string_literal_at(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut value = String::new();
    let mut index = start + 1;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            value.push(byte as char);
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Some((value, index + 1));
        } else {
            value.push(byte as char);
        }
        index += 1;
    }
    None
}

fn matching_brace_index(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0;
    for index in open..text.len() {
        match text.as_bytes()[index] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn brace_depth_at(text: &str, target: usize) -> i32 {
    let mut depth = 0;
    for byte in text.as_bytes().iter().take(target) {
        match byte {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
    }
    depth
}

fn identifier_positions(text: &str, needle: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut offset = 0;
    while let Some(found) = text[offset..].find(needle) {
        let start = offset + found;
        let end = start + needle.len();
        let before = start
            .checked_sub(1)
            .and_then(|index| text.as_bytes().get(index));
        let after = text.as_bytes().get(end);
        if !before.is_some_and(|byte| is_ident_continue(*byte))
            && !after.is_some_and(|byte| is_ident_continue(*byte))
        {
            positions.push(start);
        }
        offset = end;
    }
    positions
}

fn all_identifier_positions(text: &str) -> Vec<(String, usize)> {
    let mut items = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if is_ident_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_ident_continue(bytes[index]) {
                index += 1;
            }
            items.push((text[start..index].to_string(), start));
        } else {
            index += 1;
        }
    }
    items
}

fn is_var_declaration(masked: &str, index: usize) -> bool {
    let prefix = masked[..index].trim_end();
    prefix.ends_with("var")
        && prefix
            .as_bytes()
            .get(prefix.len().saturating_sub(4))
            .is_none_or(|byte| !is_ident_continue(*byte))
}

fn is_identifier(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && is_ident_start(bytes[0])
        && bytes.iter().skip(1).all(|byte| is_ident_continue(*byte))
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_ws(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn find_all(text: &str, needle: &str) -> Vec<usize> {
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(found) = text[offset..].find(needle) {
        let index = offset + found;
        indexes.push(index);
        offset = index + needle.len();
    }
    indexes
}

fn find_bytes(text: &str, needle: &str, start: usize) -> Option<usize> {
    text[start..].find(needle).map(|found| start + found)
}

fn compact(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
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

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_start_indexes_ignore_comment_and_raw_string_decoys() {
        let program = format!(
            r###"
// app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
var decoy = """
app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
""";
app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
"###,
            endpoint = ENDPOINT
        );

        assert_eq!(endpoint_start_indexes(&program).len(), 1);
    }

    #[test]
    fn prohibited_text_scan_flags_identifier_literals() {
        let mut errors = Vec::new();

        scan_prohibited_text(
            "recipientEmail: synthetic-placeholder",
            "synthetic-doc",
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains("recipientEmail")));
    }
}
