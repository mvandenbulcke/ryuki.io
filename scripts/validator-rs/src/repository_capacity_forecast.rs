use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/repository-capacity-forecast-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/repository-capacity-forecast.md";
const ENDPOINT: &str = "/api/protect/repository-capacity-contract";
const REQUIRED_WORKFLOWS: &[&str] = &[
    "capacity-forecast",
    "retention-risk-review",
    "growth-trend-review",
    "hub-spoke-capacity-review",
    "immutability-headroom-review",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "capacity-threshold-risk",
    "retention-risk",
    "growth-anomaly",
    "hub-capacity-risk",
    "stale-usage-data",
    "immutability-headroom-risk",
];
const REQUIRED_INPUTS: &[&str] = &[
    "repositoryScope",
    "site",
    "backupPolicy",
    "retentionPolicy",
    "growthTrend",
    "owner",
    "supportGroup",
    "forecastWindow",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "repository-summary-known",
    "retention-policy-known",
    "growth-trend-known",
    "backup-policy-known",
    "site-pairing-known",
    "forecast-window-set",
    "owner-known",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "capacitySummary",
    "growthTrend",
    "retentionRisk",
    "hubSpokeImpact",
    "immutabilityHeadroom",
    "remediationOptions",
    "approvalRoute",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-remediation-disabled",
    "repository-summary-missing",
    "retention-policy-missing",
    "growth-trend-unknown",
    "site-pairing-unknown",
    "forecast-window-missing",
    "owner-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Repository capacity summary",
    "Growth trend summary",
    "Retention risk",
    "Hub-spoke capacity impact",
    "Immutability headroom",
    "Remediation options",
    "Approval route",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "rawRepositoryRowsAllowed",
];
const REQUIRED_SCALAR_FIELDS: &[&str] = &[
    "source",
    "forecastMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "rawRepositoryRowsAllowed",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedWorkflows", "repositoryCapacityWorkflows"),
    ("forecastSignals", "repositoryCapacitySignals"),
    ("requiredGuards", "repositoryCapacityRequiredGuards"),
    ("planSections", "repositoryCapacityPlanSections"),
    ("blockedReasons", "repositoryCapacityBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "forecastMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "rawRepositoryRowsAllowed",
    "supportedWorkflows",
    "forecastSignals",
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
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-repository-remediation",
        decision: "block",
        requirement: "Repository capacity forecasting reports risk and options only, never mutating repositories or retention policy.",
        evidence: "Remediation options",
    },
    RuleDetail {
        id: "forecast-window-required",
        decision: "block",
        requirement: "Capacity decisions require a declared forecast window.",
        evidence: "Repository capacity summary",
    },
    RuleDetail {
        id: "retention-risk-required",
        decision: "block",
        requirement: "Retention risk must be evaluated before capacity status is trusted.",
        evidence: "Retention risk",
    },
    RuleDetail {
        id: "hub-spoke-impact-required",
        decision: "block",
        requirement: "GBLON hub-spoke capacity impact must be visible for shared target planning.",
        evidence: "Hub-spoke capacity impact",
    },
    RuleDetail {
        id: "raw-repository-rows-not-exposed",
        decision: "block",
        requirement: "Operators receive aggregate capacity summaries only, not raw repository rows or provider payloads.",
        evidence: "Repository capacity summary",
    },
];

#[derive(Debug, Deserialize)]
struct RepositoryCapacityContext {
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
    let context: RepositoryCapacityContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid repository capacity forecast context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
        true,
    );
    if !context.catalog.is_object() {
        return Ok(errors);
    }
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_value(
        &Value::String(context.program.clone()),
        PROGRAM_PATH,
        &mut errors,
        false,
    );
    scan_prohibited_value(
        &serde_json::json!({
            API_README_PATH: context.api_readme,
            DOC_PATH: context.doc,
        }),
        "repository-capacity-forecast",
        &mut errors,
        true,
    );
    for block in raw_endpoint_blocks(&context.program) {
        scan_prohibited_value(&Value::String(block), PROGRAM_PATH, &mut errors, true);
    }
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid repository capacity forecast catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid repository capacity forecast program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid repository capacity forecast docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid repository capacity forecast prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors, true);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("repository capacity forecast catalog must be a mapping".to_string());
        return;
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "repository capacity forecast version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "repository capacity forecast status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "repository capacity forecast source must be static-seed",
    );
    expect(
        string_value(catalog, "forecastMode") == Some("forecast-only"),
        errors,
        "repository capacity forecast mode must be forecast-only",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "repository capacity forecast must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("repository capacity forecast {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "forecastSignals", REQUIRED_SIGNALS, errors);
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
        if prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited repository capacity value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rule_values: Vec<&Value> = match catalog.get("rules") {
        Some(Value::Array(values)) => values.iter().collect(),
        Some(value) => vec![value],
        None => Vec::new(),
    };
    for (index, rule) in rule_values.iter().enumerate() {
        if !rule.is_object() {
            errors.push(format!(
                "repository capacity forecast rule {index} must be a mapping"
            ));
        }
    }
    let parsed_rules: Vec<Rule> = rule_values
        .iter()
        .filter(|rule| rule.is_object())
        .filter_map(|rule| {
            let map = rule.as_object()?;
            let rule_id = rule
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("(missing id)");
            for key in map.keys() {
                if !RULE_KEYS.contains(&key.as_str()) {
                    errors.push(format!(
                        "repository capacity forecast rule {rule_id} unexpected rule keys: {key}"
                    ));
                }
            }
            for key in RULE_KEYS {
                if !map.contains_key(*key) {
                    errors.push(format!(
                        "repository capacity forecast rule {rule_id} missing rule keys: {key}"
                    ));
                }
            }
            Some(Rule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect();
    let rule_ids: Vec<&str> = parsed_rules.iter().map(|rule| rule.id.as_str()).collect();
    let rule_details: Vec<(&str, &str, &str)> = parsed_rules
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
        "repository capacity forecast rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "repository capacity forecast rule details must be unique",
    );
    expect(
        missing.is_empty(),
        errors,
        format!(
            "repository capacity forecast missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "repository capacity forecast unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = parsed_rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "repository capacity forecast rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "repository capacity forecast rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "repository capacity forecast rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let blocks = endpoint_blocks(&uncommented_program, errors);
    if blocks.is_empty() {
        return;
    }
    let block = &blocks[0];
    validate_single_endpoint_assignments(block, errors);
    expect(
        exact_string_assignment(block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(block, "forecastMode", "forecast-only"),
        errors,
        "API must keep forecast-only mode",
    );
    expect(
        exact_assignment(block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    expect(
        exact_assignment(block, "providerCallsEnabled", "false"),
        errors,
        "API must keep providerCallsEnabled disabled",
    );
    expect(
        exact_assignment(block, "liveRemediationAllowed", "false"),
        errors,
        "API must keep liveRemediationAllowed disabled",
    );
    expect(
        exact_assignment(block, "rawRepositoryRowsAllowed", "false"),
        errors,
        "API must keep rawRepositoryRowsAllowed disabled",
    );
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable);
        validate_api_array(field, values, string_array_like(catalog, field), errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(block, field);
        validate_api_array(
            field,
            values,
            required.iter().map(|item| item.to_string()).collect(),
            errors,
        );
    }
    validate_api_rules(block, catalog, errors);
    validate_endpoint_field_names(block, errors);
    validate_no_unsafe_true_flags(block, errors);
}

fn validate_single_endpoint_assignments(block: &str, errors: &mut Vec<String>) {
    for field in REQUIRED_SCALAR_FIELDS {
        let values = assignment_values_for_field(block, field);
        expect(
            values.len() == 1,
            errors,
            format!("API must assign {field} exactly once at the endpoint top level"),
        );
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
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            if prohibited_field(&field) {
                errors.push(format!(
                    "API endpoint has prohibited repository capacity forecast field {field}"
                ));
            } else {
                errors.push(format!(
                    "API endpoint has unexpected repository capacity forecast field {field}"
                ));
            }
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in assignment_values(&stripped) {
        if value != "true" || field == "dryRunRequired" {
            continue;
        }
        if [
            "live",
            "provider",
            "raw",
            "remediation",
            "repository",
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
        ]
        .iter()
        .any(|term| field.to_ascii_lowercase().contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_docs_text(api_readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing repository capacity forecast endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "repository capacity forecast doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "repository capacity forecast doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live remediation."),
        errors,
        "repository capacity forecast doc must prohibit live remediation",
    );
    expect(
        doc.contains("No repository or retention mutation."),
        errors,
        "repository capacity forecast doc must prohibit repository mutation",
    );
    expect(
        doc.contains("aggregate forecast summaries"),
        errors,
        "repository capacity forecast doc must require aggregate summaries",
    );
}

fn scan_prohibited_value(
    value: &Value,
    path: &str,
    errors: &mut Vec<String>,
    scan_identifiers: bool,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited repository capacity field"
                    ));
                }
                scan_prohibited_value(child, &child_path, errors, scan_identifiers);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors, scan_identifiers);
            }
        }
        Value::String(text) => {
            let scan_text = if csharp_source_path(path) {
                strip_csharp_comments(text)
            } else {
                text.to_string()
            };
            if prohibited_value(&scan_text.replace("\\/", "/")) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if scan_identifiers && whole_file_text(path, text) {
                validate_text_identifiers(&scan_text, path, errors);
            }
        }
        _ => {}
    }
}

fn validate_text_identifiers(text: &str, path: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(text);
    for (index, line) in stripped.lines().enumerate() {
        for term in scan_text_identifier_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited repository capacity field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn scan_text_identifier_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    for delimiter in ['=', ':'] {
        for (index, _) in line.match_indices(delimiter) {
            if let Some(field) = field_before_equals(line, index) {
                terms.push(field);
            }
        }
    }
    terms.sort();
    terms.dedup();
    terms
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_normalized_values().contains(&normalized) {
        return false;
    }
    [
        "repositoryname",
        "repositoryid",
        "repositoryidentifier",
        "repoid",
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
        "rawrepository",
        "rawrow",
        "providerpayload",
        "serialnumber",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn safe_normalized_values() -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for items in [
        REQUIRED_WORKFLOWS,
        REQUIRED_SIGNALS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_SCALAR_FIELDS,
        ENDPOINT_INLINE_ARRAYS[0].1,
        ENDPOINT_INLINE_ARRAYS[1].1,
    ] {
        for item in items {
            values.insert(normalize(item));
        }
    }
    for (field, binding) in ENDPOINT_ARRAY_BINDINGS {
        values.insert(normalize(field));
        values.insert(normalize(binding));
    }
    for field in ALLOWED_ENDPOINT_FIELDS {
        values.insert(normalize(field));
    }
    for rule in REQUIRED_RULES {
        for item in [rule.id, rule.decision, rule.requirement, rule.evidence] {
            values.insert(normalize(item));
        }
    }
    for item in [
        "draft",
        "static-seed",
        "forecast-only",
        "true",
        "false",
        "block",
    ] {
        values.insert(normalize(item));
    }
    values
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.contains("AKIA")
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
    ]
    .iter()
    .any(|term| contains_term_assignment(&lower, term))
}

fn contains_term_assignment(text: &str, term: &str) -> bool {
    let mut offset = 0;
    while let Some(found) = text[offset..].find(term) {
        let start = offset + found;
        let end = start + term.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let term_boundary = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if term_boundary {
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

fn endpoint_blocks(uncommented_program: &str, errors: &mut Vec<String>) -> Vec<String> {
    let start_indexes = endpoint_start_indexes(uncommented_program);
    if start_indexes.is_empty() {
        errors.push("API missing repository capacity forecast endpoint".to_string());
        return Vec::new();
    }
    expect(
        start_indexes.len() == 1,
        errors,
        "API must register exactly one repository capacity forecast endpoint",
    );
    start_indexes
        .into_iter()
        .map(|start_index| {
            let next_index = next_endpoint_index(uncommented_program, start_index)
                .unwrap_or(uncommented_program.len());
            uncommented_program[start_index..next_index].to_string()
        })
        .collect()
}

fn raw_endpoint_blocks(program: &str) -> Vec<String> {
    let uncommented_program = strip_csharp_comments(program);
    endpoint_start_indexes(&uncommented_program)
        .into_iter()
        .map(|start_index| {
            let next_index =
                next_endpoint_index(&uncommented_program, start_index).unwrap_or(program.len());
            program[start_index..next_index].to_string()
        })
        .collect()
}

fn endpoint_start_indexes(uncommented_program: &str) -> Vec<usize> {
    let route = format!("\"{ENDPOINT}\"");
    let mut indexes = Vec::new();
    for (route_start, _) in uncommented_program.match_indices(&route) {
        let line_start = uncommented_program[..route_start]
            .rfind('\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        let line_to_route = &uncommented_program[line_start..route_start];
        let Some(map_index_in_line) = mapget_call_index_before_route(line_to_route) else {
            continue;
        };
        indexes.push(line_start + map_index_in_line);
    }
    indexes
}

fn mapget_call_index_before_route(line_to_route: &str) -> Option<usize> {
    let mut offset = 0;
    while let Some(relative) = line_to_route[offset..].find("app.MapGet") {
        let index = offset + relative;
        if !line_to_route[..index].trim().is_empty() {
            offset = index + "app.MapGet".len();
            continue;
        }
        let after_call = &line_to_route[index + "app.MapGet".len()..];
        let Some(open_index) = after_call.find('(') else {
            offset = index + "app.MapGet".len();
            continue;
        };
        if after_call[..open_index].trim().is_empty()
            && after_call[open_index + 1..].trim().is_empty()
        {
            return Some(index);
        }
        offset = index + "app.MapGet".len();
    }
    None
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.MapGet".len();
    while let Some(relative) = program[offset..].find("app.MapGet") {
        let index = offset + relative;
        if is_mapget_at_line_start(program, index) {
            return Some(index);
        }
        offset = index + "app.MapGet".len();
    }
    None
}

fn is_mapget_at_line_start(program: &str, index: usize) -> bool {
    let line_start = program[..index]
        .rfind('\n')
        .map(|line| line + 1)
        .unwrap_or(0);
    if !program[line_start..index].trim().is_empty() {
        return false;
    }
    let after_call = &program[index + "app.MapGet".len()..];
    after_call.trim_start().starts_with('(')
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    if program.match_indices(&format!("{variable} =")).count() != 1 {
        return None;
    }
    let marker = format!("var {variable} = new[] {{");
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    let body = &program[start..end];
    if contains_call_like_text(body) {
        return None;
    }
    Some(csharp_string_literals(body))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('}')? + start;
    let body = &block[start..end];
    if contains_call_like_text(body) {
        return None;
    }
    Some(csharp_string_literals(body))
}

fn contains_call_like_text(text: &str) -> bool {
    let stripped = strip_csharp_string_literals(text);
    stripped.contains('(')
}

fn api_rules(block: &str) -> Vec<Rule> {
    let masked = strip_csharp_string_literals(block);
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("new {") {
        let start = offset + relative;
        let Some(end_relative) = masked[start..].find('}') else {
            break;
        };
        let end = start + end_relative;
        let segment = &block[start..end];
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
        offset = end + 1;
    }
    result
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
            })
        })
        .collect()
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == value
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == format!("\"{value}\"")
}

fn assignment_values_for_field(block: &str, field: &str) -> Vec<String> {
    let prefix = format!("{field} =");
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&prefix) && line.ends_with(','))
        .map(|line| {
            line[prefix.len()..]
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string()
        })
        .collect()
}

fn assignment_fields(block: &str) -> Vec<String> {
    block
        .match_indices('=')
        .filter_map(|(index, _)| field_before_equals(block, index))
        .collect()
}

fn assignment_values(block: &str) -> Vec<(String, String)> {
    block
        .lines()
        .filter_map(|line| {
            let index = line.find('=')?;
            let field = field_before_equals(line, index)?;
            let value = line[index + 1..]
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string();
            Some((field, value))
        })
        .collect()
}

fn field_before_equals(text: &str, equals_index: usize) -> Option<String> {
    let prefix = &text[..equals_index];
    let trimmed = prefix.trim_end();
    let end = trimmed.len();
    let start = trimmed
        .char_indices()
        .rev()
        .find(|(_, ch)| !(*ch == '_' || *ch == '-' || ch.is_ascii_alphanumeric()))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let field = &trimmed[start..end];
    if field
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        Some(field.to_string())
    } else {
        None
    }
}

fn string_field(segment: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = segment.find(&marker)? + marker.len();
    let end = quoted_string_end(segment, start)?;
    Some(unescape_csharp_string(&segment[start..end]))
}

fn quoted_string_end(text: &str, start: usize) -> Option<usize> {
    let mut escaped = false;
    for (relative, ch) in text[start..].char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(start + relative);
        }
    }
    None
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

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(relative) = text[offset..].find('"') {
        let start = offset + relative + 1;
        let Some(end) = quoted_string_end(text, start) else {
            break;
        };
        result.push(unescape_csharp_string(&text[start..end]));
        offset = end + 1;
    }
    result
}

fn strip_csharp_comments(source: &str) -> String {
    let mut result = source.as_bytes().to_vec();
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if let Some((prefix_length, quote_count)) = csharp_raw_string_literal_prefix(bytes, index) {
            index = advance_csharp_raw_string(bytes, index, prefix_length, quote_count);
            continue;
        }
        if let Some((prefix_length, verbatim)) = csharp_string_literal_prefix(bytes, index) {
            index = advance_csharp_quoted_string(bytes, index, prefix_length, verbatim);
            continue;
        }
        if bytes[index..].starts_with(b"//") {
            let mut cursor = index;
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                result[cursor] = b' ';
                cursor += 1;
            }
            index = cursor;
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            let mut cursor = index;
            while cursor < bytes.len() {
                if bytes[cursor] != b'\n' {
                    result[cursor] = b' ';
                }
                if cursor > index && bytes[cursor - 1] == b'*' && bytes[cursor] == b'/' {
                    cursor += 1;
                    break;
                }
                cursor += 1;
            }
            index = cursor;
            continue;
        }
        index += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| source.to_string())
}

fn strip_csharp_string_literals(source: &str) -> String {
    let mut result = source.as_bytes().to_vec();
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if let Some((prefix_length, quote_count)) = csharp_raw_string_literal_prefix(bytes, index) {
            index = mask_csharp_raw_string(bytes, &mut result, index, prefix_length, quote_count);
            continue;
        }
        if let Some((prefix_length, verbatim)) = csharp_string_literal_prefix(bytes, index) {
            index = mask_csharp_quoted_string(bytes, &mut result, index, prefix_length, verbatim);
            continue;
        }
        index += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| source.to_string())
}

fn csharp_string_literal_prefix(bytes: &[u8], index: usize) -> Option<(usize, bool)> {
    if bytes.get(index..index + 3) == Some(b"$@\"") || bytes.get(index..index + 3) == Some(b"@$\"")
    {
        return Some((3, true));
    }
    if bytes.get(index..index + 2) == Some(b"@\"") {
        return Some((2, true));
    }
    if bytes.get(index..index + 2) == Some(b"$\"") {
        return Some((2, false));
    }
    if bytes.get(index) == Some(&b'"') {
        return Some((1, false));
    }
    None
}

fn csharp_raw_string_literal_prefix(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
    let mut cursor = index;
    while bytes.get(cursor) == Some(&b'$') {
        cursor += 1;
    }
    if bytes.get(cursor..cursor + 3) != Some(b"\"\"\"") {
        return None;
    }
    let mut quote_count = 0;
    while bytes.get(cursor + quote_count) == Some(&b'"') {
        quote_count += 1;
    }
    if quote_count < 3 {
        return None;
    }
    Some((cursor - index, quote_count))
}

fn advance_csharp_quoted_string(
    bytes: &[u8],
    start_index: usize,
    prefix_length: usize,
    verbatim: bool,
) -> usize {
    let quote_index = start_index + prefix_length - 1;
    let mut index = start_index;
    let mut escaped = false;
    while index < bytes.len() {
        let ch = bytes[index];
        index += 1;
        if index - 1 <= quote_index {
            continue;
        }
        if verbatim {
            if ch == b'"' && bytes.get(index) == Some(&b'"') {
                index += 1;
                continue;
            }
            if ch == b'"' {
                break;
            }
        } else if escaped {
            escaped = false;
        } else if ch == b'\\' {
            escaped = true;
        } else if ch == b'"' {
            break;
        }
    }
    index
}

fn advance_csharp_raw_string(
    bytes: &[u8],
    start_index: usize,
    prefix_length: usize,
    quote_count: usize,
) -> usize {
    let quote_start = start_index + prefix_length;
    let opening_end = quote_start + quote_count;
    let mut index = opening_end;
    while index + quote_count <= bytes.len() {
        if index >= opening_end
            && bytes[index..index + quote_count]
                .iter()
                .all(|ch| *ch == b'"')
        {
            return index + quote_count;
        }
        index += 1;
    }
    bytes.len()
}

fn mask_csharp_quoted_string(
    bytes: &[u8],
    result: &mut [u8],
    start_index: usize,
    prefix_length: usize,
    verbatim: bool,
) -> usize {
    let quote_index = start_index + prefix_length - 1;
    let mut index = start_index;
    let mut escaped = false;
    while index < bytes.len() {
        let ch = bytes[index];
        if ch != b'\n' {
            result[index] = b' ';
        }
        index += 1;
        if index - 1 <= quote_index {
            continue;
        }
        if verbatim {
            if ch == b'"' && bytes.get(index) == Some(&b'"') {
                result[index] = b' ';
                index += 1;
                continue;
            }
            if ch == b'"' {
                break;
            }
        } else if escaped {
            escaped = false;
        } else if ch == b'\\' {
            escaped = true;
        } else if ch == b'"' {
            break;
        }
    }
    index
}

fn mask_csharp_raw_string(
    bytes: &[u8],
    result: &mut [u8],
    start_index: usize,
    prefix_length: usize,
    quote_count: usize,
) -> usize {
    let quote_start = start_index + prefix_length;
    let opening_end = quote_start + quote_count;
    let mut index = start_index;
    while index < bytes.len() {
        if index >= opening_end
            && index + quote_count <= bytes.len()
            && bytes[index..index + quote_count]
                .iter()
                .all(|ch| *ch == b'"')
        {
            for offset in 0..quote_count {
                if bytes[index + offset] != b'\n' {
                    result[index + offset] = b' ';
                }
            }
            return index + quote_count;
        }
        if bytes[index] != b'\n' {
            result[index] = b' ';
        }
        index += 1;
    }
    index
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn csharp_source_path(path: &str) -> bool {
    path.ends_with(".cs")
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

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_start_indexes_ignore_commented_decoys_and_count_duplicates() {
        let uncommented = strip_csharp_comments(&format!(
            r#"
// app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
app.MapGet("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
app.MapGet ("{endpoint}", () => Results.Json(new {{ source = "static-seed" }}));
"#,
            endpoint = ENDPOINT
        ));

        assert_eq!(endpoint_start_indexes(&uncommented).len(), 2);
    }

    #[test]
    fn catalog_duplicate_rule_details_are_rejected_in_rust() {
        let mut catalog = serde_json::json!({
            "version": 1,
            "status": "draft",
            "source": "static-seed",
            "forecastMode": "forecast-only",
            "dryRunRequired": true,
            "providerCallsEnabled": false,
            "liveRemediationAllowed": false,
            "rawRepositoryRowsAllowed": false,
            "supportedWorkflows": REQUIRED_WORKFLOWS,
            "forecastSignals": REQUIRED_SIGNALS,
            "requiredInputs": REQUIRED_INPUTS,
            "requiredGuards": REQUIRED_GUARDS,
            "planSections": REQUIRED_PLAN_SECTIONS,
            "blockedReasons": REQUIRED_BLOCKED_REASONS,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "rules": REQUIRED_RULES
                .iter()
                .map(|rule| serde_json::json!({
                    "id": rule.id,
                    "decision": rule.decision,
                    "requirement": rule.requirement,
                    "evidence": rule.evidence,
                }))
                .collect::<Vec<_>>(),
        });
        let first = catalog["rules"][0].clone();
        catalog["rules"][1]["decision"] = first["decision"].clone();
        catalog["rules"][1]["requirement"] = first["requirement"].clone();
        catalog["rules"][1]["evidence"] = first["evidence"].clone();
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("rule details") && error.contains("unique")));
    }

    #[test]
    fn prohibited_identifier_scan_is_not_quoted_value_only() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String("new { tenantId = \"safe-summary\" }\n".to_string()),
            PROGRAM_PATH,
            &mut errors,
            true,
        );

        assert!(errors.iter().any(|error| error.contains("tenantId")));
    }
}
