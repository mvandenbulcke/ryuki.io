use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/aiops-suggestion-contract.yaml";
const ENDPOINT: &str = "/api/operations/aiops-suggestion-contract";
const REQUIRED_SOURCES: &[&str] = &[
    "operation-health-pattern",
    "platform-health-pattern",
    "incident-context-pattern",
    "shift-queue-pattern",
    "failed-run-pattern",
    "degradation-pattern",
    "evidence-gap-pattern",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "repeat-failure",
    "blocked-workflow",
    "correlated-degradation",
    "rising-risk",
    "stale-data",
    "evidence-gap",
    "owner-unknown",
];
const REQUIRED_INPUTS: &[&str] = &[
    "signalSummary",
    "affectedWorkflow",
    "healthDomain",
    "impactBand",
    "owner",
    "supportGroup",
    "reviewer",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "signal-summary-redacted",
    "correlation-static-only",
    "impact-band-known",
    "owner-route-known",
    "reviewer-assigned",
    "recommendation-redacted",
    "automation-disabled",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "signalSummary",
    "correlationSummary",
    "impactAssessment",
    "recommendationCandidate",
    "ownerRoute",
    "reviewRoute",
    "safeNextAction",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-correlation-disabled",
    "live-remediation-disabled",
    "live-ticket-mutation-disabled",
    "automation-dispatch-disabled",
    "raw-operation-rows-disabled",
    "raw-health-rows-disabled",
    "raw-log-payloads-disabled",
    "raw-user-data-disabled",
    "raw-recipient-data-disabled",
    "raw-provider-payloads-disabled",
    "signal-summary-missing",
    "reviewer-missing",
    "recommendation-not-redacted",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "AIOps signal summary",
    "Static correlation summary",
    "Impact assessment",
    "Recommendation candidate",
    "Owner route",
    "Review route",
    "Safe next action",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveCorrelationAllowed",
    "liveRemediationAllowed",
    "liveTicketMutationAllowed",
    "automationDispatchAllowed",
    "rawOperationRowsAllowed",
    "rawHealthRowsAllowed",
    "rawLogPayloadsAllowed",
    "rawUserDataAllowed",
    "rawRecipientDataAllowed",
    "rawProviderPayloadsAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "suggestionMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveCorrelationAllowed",
    "liveRemediationAllowed",
    "liveTicketMutationAllowed",
    "automationDispatchAllowed",
    "rawOperationRowsAllowed",
    "rawHealthRowsAllowed",
    "rawLogPayloadsAllowed",
    "rawUserDataAllowed",
    "rawRecipientDataAllowed",
    "rawProviderPayloadsAllowed",
    "suggestionSources",
    "suggestionSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("suggestionSources", "aiopsSuggestionSources"),
    ("suggestionSignals", "aiopsSuggestionSignals"),
    ("requiredGuards", "aiopsSuggestionRequiredGuards"),
    ("planSections", "aiopsSuggestionPlanSections"),
    ("blockedReasons", "aiopsSuggestionBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "suggestionMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveCorrelationAllowed",
    "liveRemediationAllowed",
    "liveTicketMutationAllowed",
    "automationDispatchAllowed",
    "rawOperationRowsAllowed",
    "rawHealthRowsAllowed",
    "rawLogPayloadsAllowed",
    "rawUserDataAllowed",
    "rawRecipientDataAllowed",
    "rawProviderPayloadsAllowed",
    "suggestionSources",
    "suggestionSignals",
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
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# AIOps suggestion seed data only. Do not add ticket IDs, incident IDs, change IDs, usernames, email addresses, credentials, tokens, tenant IDs, object IDs, live endpoints, private IPs, serial numbers, raw operation rows, raw health rows, raw logs, raw user data, raw recipient data, or provider payloads.",
    "- No raw operation rows, raw health rows, raw logs, raw user data, raw recipient data, ticket identifiers, incident identifiers, change identifiers, tenant identifiers, object identifiers, private network details, live endpoints, serial numbers, credentials, tokens, or provider payloads in committed files.",
    "| `/api/operations/aiops-suggestion-contract` | Static AIOps suggestion contract; live correlation, live remediation, automation dispatch, and raw health rows disabled. |",
    "requirement: AIOps suggestion evidence must use safe summaries only and must not expose raw operation rows, raw health rows, raw logs, raw user data, raw recipient data, ticket IDs, incident IDs, change IDs, tenant IDs, object IDs, private IPs, serial numbers, live endpoints, or provider payloads.",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-correlation",
        decision: "block",
        requirement: "AIOps suggestions use static, aggregate, or manually reviewed summaries only and never query live provider, ticket, monitoring, backup, inventory, or log systems.",
        evidence: "Static correlation summary",
    },
    RuleDetail {
        id: "no-live-remediation",
        decision: "block",
        requirement: "AIOps suggestions recommend safe next actions only and never dispatch workers, mutate workflows, suppress alerts, restart services, remediate providers, or create tickets.",
        evidence: "Safe next action",
    },
    RuleDetail {
        id: "reviewer-route-required",
        decision: "block",
        requirement: "Each suggestion requires a reviewer, owner route, support group, impact band, and redacted evidence before it can be exported or shown as actionable.",
        evidence: "Review route",
    },
    RuleDetail {
        id: "raw-aiops-data-not-exposed",
        decision: "block",
        requirement: "AIOps suggestion evidence must use safe summaries only and must not expose raw operation rows, raw health rows, raw logs, raw user data, raw recipient data, ticket IDs, incident IDs, change IDs, tenant IDs, object IDs, private IPs, serial numbers, live endpoints, or provider payloads.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct AiopsContext {
    catalog: Value,
    program: String,
    readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    readme: String,
    catalog_readme: String,
    doc_readme: String,
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
    let context: AiopsContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid AIOps suggestion context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc),
        "aiops-suggestion.docs/workflows/aiops-suggestion.md",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid AIOps suggestion catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid AIOps suggestion program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid AIOps suggestion docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.readme,
        &payload.catalog_readme,
        &payload.doc_readme,
        &payload.doc,
        &mut errors,
    );
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid AIOps suggestion prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "AIOps suggestion version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "AIOps suggestion status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "AIOps suggestion source must be static-seed",
    );
    expect(
        string_value(catalog, "suggestionMode") == Some("recommendation-only"),
        errors,
        "AIOps suggestion mode must be recommendation-only",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "AIOps suggestion must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("AIOps suggestion {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "suggestionSources", REQUIRED_SOURCES, errors);
    validate_required_array(catalog, "suggestionSignals", REQUIRED_SIGNALS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog_rules(catalog), errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("AIOps suggestion catalog must be an object".to_string());
        return;
    };
    let required: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !required.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "AIOps suggestion unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array(catalog, field);
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

fn validate_required_rules(rules: Vec<Rule>, errors: &mut Vec<String>) {
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
        missing.is_empty(),
        errors,
        format!("AIOps suggestion missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "AIOps suggestion unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "AIOps suggestion rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "AIOps suggestion rule details must be unique",
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "AIOps suggestion rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "AIOps suggestion rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "AIOps suggestion rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let block = endpoint_block(program, errors);
    if block.is_empty() {
        return;
    }

    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "suggestionMode", "recommendation-only"),
        errors,
        "API must keep recommendation-only mode",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable);
        validate_api_array(field, values, string_array(catalog, field), errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field);
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
    for value in values {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited AIOps suggestion value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited AIOps suggestion phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = api_rules(block);
    let catalog_rules = catalog_rules(catalog);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_ids.difference(&api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.difference(&catalog_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
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
    for field in assignment_fields(block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "AIOps suggestion endpoint field {field} is not allowed"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in assignment_values(block) {
        if value == "true" && (field.ends_with("Allowed") || field.ends_with("Enabled")) {
            errors.push(format!("AIOps suggestion endpoint must not enable {field}"));
        }
    }
}

fn validate_docs_text(
    readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    errors: &mut Vec<String>,
) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing AIOps suggestion endpoint",
    );
    expect(
        catalog_readme.contains("aiops-suggestion-contract.yaml"),
        errors,
        "catalog README missing AIOps suggestion catalog",
    );
    expect(
        doc_readme.contains("aiops-suggestion.md"),
        errors,
        "workflow README missing AIOps suggestion doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "AIOps suggestion doc missing endpoint",
    );
    expect(
        doc.contains(
            "AIOps suggestions use static, aggregate, or manually reviewed summaries only",
        ),
        errors,
        "AIOps suggestion doc must require static summaries",
    );
    expect(
        doc.contains("never dispatch workers"),
        errors,
        "AIOps suggestion doc must block worker dispatch",
    );
    expect(
        doc.contains("No raw operation rows"),
        errors,
        "AIOps suggestion doc must prohibit raw operation rows",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited AIOps suggestion field"
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
        Value::String(text) => {
            if text.contains('\n') {
                for (index, line) in text.lines().enumerate() {
                    scan_prohibited_string(line, &format!("{path}:{}", index + 1), errors);
                }
            } else {
                scan_prohibited_string(text, path, errors);
            }
        }
        _ => {}
    }
}

fn scan_prohibited_string(text: &str, path: &str, errors: &mut Vec<String>) {
    if safe_text_value(text) {
        return;
    }
    if prohibited_field(text) {
        errors.push(format!(
            "{path} contains prohibited AIOps suggestion field {text}"
        ));
    }
    if let Some(phrase) = prohibited_phrase(text) {
        errors.push(format!(
            "{path} contains prohibited AIOps suggestion phrase {phrase}"
        ));
    }
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    if SAFE_TEXT_PROHIBITION_LINES.contains(&text) {
        return true;
    }
    if REQUIRED_DISABLED_FIELDS
        .iter()
        .any(|field| text == format!("{field}: false"))
    {
        return true;
    }
    safe_text_arrays().iter().any(|items| items.contains(&text))
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
        || ["draft", "static-seed", "recommendation-only", "block"].contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 9] {
    [
        REQUIRED_SOURCES,
        REQUIRED_SIGNALS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
    ]
}

fn prohibited_field(value: &str) -> bool {
    if safe_text_value(value) {
        return false;
    }
    let normalized = normalize(value);
    [
        "ticketid",
        "incidentid",
        "changeid",
        "userid",
        "username",
        "emailaddress",
        "recipientemail",
        "tenantid",
        "tenantidentifier",
        "objectid",
        "objectidentifier",
        "serialnumber",
        "privateip",
        "endpointurl",
        "liveendpoint",
        "rawoperation",
        "rawhealth",
        "rawlog",
        "rawlogs",
        "rawuser",
        "userdata",
        "rawrecipient",
        "rawrecipientdata",
        "providerpayload",
        "credential",
        "secret",
        "token",
        "password",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    [
        ("raw operation rows", &["raw", "operation", "row"][..]),
        ("raw health rows", &["raw", "health", "row"]),
        ("raw logs", &["raw", "log"]),
        ("raw user data", &["raw", "user", "data"]),
        ("raw recipient data", &["raw", "recipient", "data"]),
        ("ticket ID", &["ticket", "id"]),
        ("incident ID", &["incident", "id"]),
        ("change ID", &["change", "id"]),
        ("tenant ID", &["tenant", "id"]),
        ("object ID", &["object", "id"]),
        ("private IP", &["private", "ip"]),
        ("serial number", &["serial", "number"]),
        ("live endpoint", &["live", "endpoint"]),
        ("provider payload", &["provider", "payload"]),
    ]
    .into_iter()
    .find(|(_, phrase)| phrase_tokens_match(value, phrase))
    .map(|(label, _)| label)
}

fn phrase_tokens_match(value: &str, phrase: &[&str]) -> bool {
    let words: Vec<String> = value
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_string)
        .collect();
    if phrase.is_empty() || words.len() < phrase.len() {
        return false;
    }
    words.windows(phrase.len()).any(|window| {
        phrase.iter().enumerate().all(|(index, expected)| {
            let word = window[index].as_str();
            word == *expected || word == format!("{expected}s")
        })
    })
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.contains("AKIA")
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_email_like(text)
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

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let uncommented = strip_csharp_comments(program);
    let marker = format!("app.MapGet(\"{ENDPOINT}\",");
    let Some(start_index) = uncommented.find(&marker) else {
        errors.push("API missing AIOps suggestion endpoint".to_string());
        return String::new();
    };
    let next_index = uncommented[start_index + marker.len()..]
        .find("\napp.MapGet(")
        .map(|index| start_index + marker.len() + index)
        .unwrap_or(uncommented.len());
    uncommented[start_index..next_index].to_string()
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[] {{");
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    Some(csharp_string_literals(&program[start..end]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('}')? + start;
    Some(csharp_string_literals(&block[start..end]))
}

fn api_rules(block: &str) -> Vec<Rule> {
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(start) = block[offset..].find("new {") {
        let start = offset + start;
        let Some(end) = block[start..].find('}') else {
            break;
        };
        let segment = &block[start..start + end];
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
        offset = start + end + 1;
    }
    result
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

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let lines = assignment_lines(block, field);
    lines.len() == 1 && lines[0] == format!("{field} = {value},")
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let lines = assignment_lines(block, field);
    lines.len() == 1 && lines[0] == format!("{field} = \"{value}\",")
}

fn assignment_lines(block: &str, field: &str) -> Vec<String> {
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&format!("{field} =")))
        .map(str::to_string)
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
        .find(|(_, ch)| !(*ch == '_' || ch.is_ascii_alphanumeric()))
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
    let end = segment[start..].find('"')? + start;
    Some(segment[start..end].to_string())
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        for (_, inner) in chars.by_ref() {
            if escaped {
                value.push(inner);
                escaped = false;
            } else if inner == '\\' {
                escaped = true;
            } else if inner == '"' {
                break;
            } else {
                value.push(inner);
            }
        }
        result.push(value);
    }
    result
}

fn strip_csharp_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            result.push(ch);
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
            result.push(ch);
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for comment_ch in chars.by_ref() {
                if comment_ch == '\n' {
                    result.push('\n');
                    break;
                }
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut previous = '\0';
            for comment_ch in chars.by_ref() {
                if comment_ch == '\n' {
                    result.push('\n');
                }
                if previous == '*' && comment_ch == '/' {
                    break;
                }
                previous = comment_ch;
            }
            continue;
        }
        result.push(ch);
    }
    result
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
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
    fn aiops_comment_decoy_is_ignored() {
        let program = format!(
            r#"
// app.MapGet("{ENDPOINT}", () => Results.Json(new {{ source = "static-seed", suggestionMode = "recommendation-only", }}));
app.MapGet("{ENDPOINT}", () => Results.Json(new {{
    source = "static-seed",
    suggestionMode = "live-correlation",
}}));
"#
        );
        let mut errors = Vec::new();
        let block = endpoint_block(&program, &mut errors);
        assert!(errors.is_empty());
        assert!(block.contains("live-correlation"));
        assert!(!block.contains("recommendation-only"));
    }

    #[test]
    fn aiops_phrase_variants_are_rejected() {
        assert_eq!(
            prohibited_phrase("raw_operation_rows"),
            Some("raw operation rows")
        );
        assert_eq!(prohibited_phrase("ticket IDs"), Some("ticket ID"));
        assert_eq!(
            prohibited_phrase("provider-payload"),
            Some("provider payload")
        );
    }
}
