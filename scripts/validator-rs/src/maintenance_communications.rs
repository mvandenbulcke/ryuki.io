use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/maintenance-communications-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/maintenance-communications.md";
const ENDPOINT: &str = "/api/operations/maintenance-communications-contract";

const REQUIRED_TYPES: &[&str] = &[
    "planned-maintenance",
    "outage-advisory",
    "degraded-service",
    "completion-notice",
    "extension-notice",
    "cancellation-notice",
];
const REQUIRED_CHANNELS: &[&str] = &[
    "portal-announcement",
    "email-draft",
    "service-desk-note",
    "handover-note",
    "cab-summary",
];
const REQUIRED_INPUTS: &[&str] = &[
    "maintenanceWindow",
    "affectedServices",
    "ciRelationshipSummary",
    "owner",
    "supportGroup",
    "audience",
    "messageType",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "maintenance-window-known",
    "affected-ci-known",
    "owner-known",
    "audience-approved",
    "message-template-approved",
    "approval-route-assigned",
    "evidence-redacted",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "maintenance-window-missing",
    "affected-ci-unknown",
    "owner-unknown",
    "audience-unapproved",
    "message-template-missing",
    "approval-missing",
    "raw-recipient-data",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Communication draft",
    "Affected CI summary",
    "Audience decision",
    "Owner approval",
    "Maintenance window",
    "Channel plan",
    "Handover notes",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveNotificationAllowed",
    "rawRecipientDataAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "communicationMode",
    "providerCallsEnabled",
    "liveNotificationAllowed",
    "rawRecipientDataAllowed",
    "messageTypes",
    "communicationChannels",
    "requiredInputs",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("messageTypes", "maintenanceCommunicationTypes"),
    ("communicationChannels", "maintenanceCommunicationChannels"),
    ("requiredGuards", "maintenanceCommunicationRequiredGuards"),
    ("blockedReasons", "maintenanceCommunicationBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "communicationMode",
    "rules",
    "providerCallsEnabled",
    "liveNotificationAllowed",
    "rawRecipientDataAllowed",
    "messageTypes",
    "communicationChannels",
    "requiredInputs",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Maintenance communication seed data only. Do not add hostnames, usernames, credentials, tokens, tenant IDs, object IDs, live endpoints, private IPs, raw recipient data, raw logs, or provider payloads.",
    "- No live provider calls.",
    "- No live notification send.",
    "- No raw recipient data, hostnames, usernames, credentials, tokens, tenant identifiers, object identifiers, endpoint names, private network details, raw logs, or provider payloads in committed files.",
    "This slice adds a draft-only maintenance and outage communications contract. It defines message types, channel plans, audience approval, affected CI summaries, maintenance-window evidence, and handover notes without sending live notifications or exposing raw recipient data.",
    "- Operators see approved drafts and affected service summaries, not raw recipient lists or provider details.",
    "| `/api/operations/maintenance-communications-contract` | Static maintenance communication draft contract; live notification disabled. |",
];
const STATIC_SAFE_VALUES: &[&str] = &["draft", "static-seed", "draft-only", "block"];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-notification-send",
        decision: "block",
        requirement: "Maintenance communication contract creates drafts only and never sends live notifications.",
        evidence: "Communication draft",
    },
    RuleDetail {
        id: "approved-audience-required",
        decision: "block",
        requirement: "Audience scope must be approved before communication can be published or exported.",
        evidence: "Audience decision",
    },
    RuleDetail {
        id: "affected-ci-summary-required",
        decision: "block",
        requirement: "Affected CI and application relationship summary must exist before message generation.",
        evidence: "Affected CI summary",
    },
    RuleDetail {
        id: "no-sensitive-recipient-data",
        decision: "block",
        requirement: "Drafts and channel plans must not expose raw recipient data, credentials, or provider payloads.",
        evidence: "Channel plan",
    },
];

#[derive(Debug, Deserialize)]
struct MaintenanceCommunicationsContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
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
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

#[derive(Clone)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

struct Route {
    start: usize,
    route: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: MaintenanceCommunicationsContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid maintenance communications context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.program), PROGRAM_PATH, &mut errors);
    scan_prohibited_value(
        &Value::String(context.api_readme),
        API_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.catalog_readme),
        CATALOG_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc_readme),
        DOC_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.doc), DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid maintenance communications catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid maintenance communications program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid maintenance communications docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.api_readme,
        &payload.catalog_readme,
        &payload.doc_readme,
        &payload.doc,
        &mut errors,
    );
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid maintenance communications prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("maintenance communications catalog must be a mapping".to_string());
        return;
    };
    let unexpected: Vec<String> = map
        .keys()
        .filter(|key| !REQUIRED_CATALOG_KEYS.contains(&key.as_str()))
        .cloned()
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "maintenance communications unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "maintenance communications version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "maintenance communications status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "maintenance communications source must be static-seed",
    );
    expect(
        string_value(catalog, "communicationMode") == Some("draft-only"),
        errors,
        "maintenance communications mode must be draft-only",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("maintenance communications {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "messageTypes", REQUIRED_TYPES, errors);
    validate_required_array(catalog, "communicationChannels", REQUIRED_CHANNELS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
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
    let required = required_values
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    let missing = required
        .iter()
        .filter(|value| !values.contains(value))
        .cloned()
        .collect::<Vec<_>>();
    let unexpected = values
        .iter()
        .filter(|value| !required.contains(value))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        errors.push(format!("{field} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        unique_len(&values) == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = rules_from_catalog(catalog);
    let rule_ids = rules.iter().map(|rule| rule.id.clone()).collect::<Vec<_>>();
    let required_ids = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id.to_string())
        .collect::<Vec<_>>();
    let missing = required_ids
        .iter()
        .filter(|id| !rule_ids.contains(id))
        .cloned()
        .collect::<Vec<_>>();
    let unexpected = rule_ids
        .iter()
        .filter(|id| !required_ids.contains(id))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        errors.push(format!(
            "maintenance communications missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "maintenance communications unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        unique_len(&rule_ids) == rule_ids.len(),
        errors,
        "maintenance communications rule IDs must be unique",
    );
    expect(
        unique_len(
            &rules
                .iter()
                .map(|rule| rule.requirement.clone())
                .collect::<Vec<_>>(),
        ) == rules.len(),
        errors,
        "maintenance communications rule requirements must be unique",
    );
    expect(
        unique_len(
            &rules
                .iter()
                .map(|rule| rule.evidence.clone())
                .collect::<Vec<_>>(),
        ) == rules.len(),
        errors,
        "maintenance communications rule evidence must be unique",
    );
    let details = rules
        .iter()
        .map(|rule| format!("{}|{}|{}", rule.decision, rule.requirement, rule.evidence))
        .collect::<Vec<_>>();
    expect(
        unique_len(&details) == rules.len(),
        errors,
        "maintenance communications rule details must be unique",
    );
    for expected in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|candidate| candidate.id == expected.id) else {
            continue;
        };
        expect(
            rule.decision == expected.decision,
            errors,
            format!(
                "maintenance communications rule {} decision must match",
                expected.id
            ),
        );
        expect(
            rule.requirement == expected.requirement,
            errors,
            format!(
                "maintenance communications rule {} requirement must match",
                expected.id
            ),
        );
        expect(
            rule.evidence == expected.evidence,
            errors,
            format!(
                "maintenance communications rule {} evidence must match",
                expected.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let block = endpoint_block(program, errors);
    if block.is_empty() {
        return;
    }
    let array_declarations = ENDPOINT_ARRAY_BINDINGS
        .iter()
        .flat_map(|(_, variable)| csharp_array_declarations(&uncommented_program, variable))
        .collect::<Vec<_>>()
        .join("\n");
    let raw_string_scope = format!("{block}\n{array_declarations}");
    if csharp_without_comments(&raw_string_scope).contains("\"\"\"") {
        errors.push(
            "API Program.cs must not use C# raw string literals in maintenance communications contract"
                .to_string(),
        );
    }
    validate_singleton_endpoint_assignments(&block, errors);
    expect(
        exact_string_assignment(&block, "source", "static-seed")
            && endpoint_assignment_count(&block, "source") == 1,
        errors,
        "API must keep exactly one static-seed source",
    );
    expect(
        exact_string_assignment(&block, "communicationMode", "draft-only")
            && endpoint_assignment_count(&block, "communicationMode") == 1,
        errors,
        "API must keep exactly one draft-only communication mode",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "false")
                && endpoint_assignment_count(&block, field) == 1,
            errors,
            format!("API must keep exactly one {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable)
                && endpoint_assignment_count(&block, field) == 1,
            errors,
            format!("API must bind exactly one {field} to {variable}"),
        );
        let values = csharp_array_values(
            &uncommented_program,
            variable,
            &format!("API {variable}"),
            errors,
        );
        validate_api_array(field, values, string_array_like(catalog, field), errors);
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field, &format!("API {field}"), errors);
        validate_api_array(field, values, string_array_like(catalog, field), errors);
    }
    validate_api_rule_fields_are_literals(&block, errors);
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_endpoint_no_prohibited_literals(&block, errors);
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
    let missing = catalog_values
        .iter()
        .filter(|value| !values.contains(value))
        .cloned()
        .collect::<Vec<_>>();
    let unexpected = values
        .iter()
        .filter(|value| !catalog_values.contains(value))
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
        unique_len(&values) == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
    for value in values {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited maintenance communications value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited maintenance communications phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = rules_from_catalog(catalog);
    let api_rules = rules_from_api(block);
    let catalog_ids = catalog_rules
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    let api_ids = api_rules
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    for id in catalog_ids.iter().filter(|id| !api_ids.contains(id)) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.iter().filter(|id| !catalog_ids.contains(id)) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(
        unique_len(&api_ids) == api_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        unique_len(
            &api_rules
                .iter()
                .map(|rule| rule.requirement.clone())
                .collect::<Vec<_>>(),
        ) == api_rules.len(),
        errors,
        "API rule requirements must be unique",
    );
    expect(
        unique_len(
            &api_rules
                .iter()
                .map(|rule| rule.evidence.clone())
                .collect::<Vec<_>>(),
        ) == api_rules.len(),
        errors,
        "API rule evidence must be unique",
    );
    let details = api_rules
        .iter()
        .map(|rule| format!("{}|{}|{}", rule.decision, rule.requirement, rule.evidence))
        .collect::<Vec<_>>();
    expect(
        unique_len(&details) == api_rules.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in &catalog_rules {
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

fn validate_api_rule_fields_are_literals(block: &str, errors: &mut Vec<String>) {
    let allowed_fields = ["id", "decision", "requirement", "evidence"];
    for body in rule_object_bodies(block) {
        for field in assignment_fields(&body) {
            if !allowed_fields.contains(&field.as_str()) {
                errors.push(format!("API rule has unexpected field {field}"));
            }
        }
        for field in allowed_fields {
            let Some(value) = assignment_value(&body, field) else {
                continue;
            };
            if !is_quoted_string_literal(value) || value.trim_start().starts_with('$') {
                errors.push(format!("API rule {field} must be a quoted string literal"));
            }
        }
    }
}

fn validate_singleton_endpoint_assignments(block: &str, errors: &mut Vec<String>) {
    let mut fields = vec![
        "source".to_string(),
        "communicationMode".to_string(),
        "rules".to_string(),
    ];
    fields.extend(
        REQUIRED_DISABLED_FIELDS
            .iter()
            .map(|field| field.to_string()),
    );
    fields.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(field, _)| field.to_string()),
    );
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().map(|field| field.to_string()));
    for field in fields {
        if endpoint_assignment_count(block, &field) != 1 {
            errors.push(format!("API {field} assignment must appear exactly once"));
        }
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let surface = endpoint_surface_block(block);
    for field in assignment_fields(&surface) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            if prohibited_field(&field) {
                errors.push(format!(
                    "API endpoint has prohibited maintenance communications field {field}"
                ));
            } else {
                errors.push(format!(
                    "API endpoint has unexpected maintenance communications field {field}"
                ));
            }
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited maintenance communications field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in simple_assignments(block) {
        if value == "true" && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_endpoint_no_prohibited_literals(block: &str, errors: &mut Vec<String>) {
    for value in csharp_string_literals(block) {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_value(&value) {
            errors.push("API endpoint contains prohibited literal value".to_string());
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API endpoint contains prohibited maintenance communications phrase {phrase}"
            ));
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API endpoint contains prohibited maintenance communications value {value}"
            ));
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
        "API README missing maintenance communications endpoint",
    );
    expect(
        catalog_readme.contains("maintenance-communications-contract.yaml"),
        errors,
        "catalog README missing maintenance communications catalog",
    );
    expect(
        doc_readme.contains("maintenance-communications.md"),
        errors,
        "workflow README missing maintenance communications doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "maintenance communications doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "maintenance communications doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live notification send."),
        errors,
        "maintenance communications doc must prohibit live sends",
    );
    expect(
        doc.contains("No raw recipient data"),
        errors,
        "maintenance communications doc must prohibit raw recipient data",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let uncommented = csharp_without_comments(program);
    let routes = mapget_routes(&uncommented);
    let matches = routes
        .iter()
        .filter(|route| route.route == ENDPOINT)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        errors.push("API missing maintenance communications endpoint".to_string());
        return String::new();
    }
    if matches.len() != 1 {
        errors.push(format!(
            "API must define exactly one active endpoint {ENDPOINT}; found {}",
            matches.len()
        ));
        return String::new();
    }
    let start = matches[0].start;
    let Some(end) = endpoint_call_end_index(&uncommented, start) else {
        errors.push(format!("API endpoint {ENDPOINT} block is incomplete"));
        return String::new();
    };
    uncommented
        .get(start..=end)
        .map(str::to_string)
        .unwrap_or_default()
}

fn mapget_routes(program: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    let mut index = 0;
    while let Some(offset) = program.get(index..).and_then(|text| text.find("app")) {
        let start = index + offset;
        if start > 0 && is_ident_byte(program.as_bytes()[start - 1]) {
            index = start + 3;
            continue;
        }
        let mut cursor = skip_ws(program, start + 3);
        if program.as_bytes().get(cursor) != Some(&b'.') {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor = skip_ws(program, cursor + 1);
        if !program
            .get(cursor..)
            .unwrap_or_default()
            .starts_with("MapGet")
        {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor += "MapGet".len();
        if program
            .as_bytes()
            .get(cursor)
            .map(|byte| is_ident_byte(*byte))
            .unwrap_or(false)
        {
            index = cursor + 1;
            continue;
        }
        cursor = skip_ws(program, cursor);
        if program.as_bytes().get(cursor) != Some(&b'(') {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor = skip_ws(program, cursor + 1);
        let Some((route, next_cursor)) = parse_csharp_string_literal_at(program, cursor) else {
            index = cursor.saturating_add(1);
            continue;
        };
        routes.push(Route { start, route });
        index = next_cursor;
    }
    routes
}

fn endpoint_call_end_index(program: &str, start: usize) -> Option<usize> {
    let scan_program = mask_csharp_string_literals(program);
    let open_paren = scan_program
        .get(start..)?
        .find('(')
        .map(|offset| start + offset)?;
    let close_paren = matching_delimiter_index(&scan_program, open_paren, b'(', b')')?;
    let semicolon = skip_ws(&scan_program, close_paren + 1);
    if scan_program.as_bytes().get(semicolon) == Some(&b';') {
        Some(semicolon)
    } else {
        Some(close_paren)
    }
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    context: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let declarations = csharp_array_declarations(program, variable);
    if declarations.len() != 1 {
        errors.push(format!(
            "API {variable} must have exactly one literal string array declaration"
        ));
        return None;
    }
    let declaration = &declarations[0];
    let scan_declaration = mask_csharp_string_literals(declaration);
    let open = scan_declaration.find('{')?;
    let close = matching_delimiter_index(&scan_declaration, open, b'{', b'}')?;
    declaration
        .get((open + 1)..close)
        .map(|body| csharp_string_array_values(body, context, errors))
}

fn csharp_array_declarations(program: &str, variable: &str) -> Vec<String> {
    let marker = format!("var {variable}");
    let scan_program = mask_csharp_string_literals(program);
    let mut declarations = Vec::new();
    let mut index = 0;
    while let Some(offset) = scan_program
        .get(index..)
        .and_then(|text| text.find(&marker))
    {
        let start = index + offset;
        let before = scan_program.as_bytes().get(start.wrapping_sub(1));
        let after = scan_program.as_bytes().get(start + marker.len());
        if before.map(|byte| is_ident_byte(*byte)).unwrap_or(false)
            || after.map(|byte| is_ident_byte(*byte)).unwrap_or(false)
        {
            index = start + marker.len();
            continue;
        }
        let Some(open) = scan_program
            .get(start..)
            .and_then(|text| text.find('{').map(|brace| start + brace))
        else {
            index = start + marker.len();
            continue;
        };
        let Some(close) = matching_delimiter_index(&scan_program, open, b'{', b'}') else {
            index = open + 1;
            continue;
        };
        let end = skip_ws(&scan_program, close + 1);
        let end = if scan_program.as_bytes().get(end) == Some(&b';') {
            end + 1
        } else {
            close + 1
        };
        if let Some(declaration) = program.get(start..end) {
            declarations.push(declaration.to_string());
        }
        index = end;
    }
    declarations
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    context: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let field_index = find_assignment_index(block, field)?;
    let scan_block = mask_csharp_string_literals(block);
    let open = scan_block
        .get(field_index..)?
        .find('{')
        .map(|offset| field_index + offset)?;
    let close = matching_delimiter_index(&scan_block, open, b'{', b'}')?;
    block
        .get((open + 1)..close)
        .map(|body| csharp_string_array_values(body, context, errors))
}

fn csharp_string_array_values(body: &str, context: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    let mut invalid_members = Vec::new();
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() || bytes[index] == b',' {
            index += 1;
            continue;
        }
        let member_start = index;
        let mut prefix = String::new();
        while matches!(bytes.get(index), Some(b'$' | b'@')) {
            prefix.push(bytes[index] as char);
            index += 1;
        }
        if bytes.get(index) == Some(&b'"') {
            if let Some((literal, cursor)) = parse_csharp_string_literal_at(body, index) {
                let member = body.get(member_start..cursor).unwrap_or_default().trim();
                if prefix.contains('$') {
                    invalid_members.push(member.to_string());
                } else {
                    values.push(literal);
                }
                index = cursor;
                continue;
            }
        }
        index += 1;
        while index < bytes.len() && bytes[index] != b',' {
            index += 1;
        }
        let member = body.get(member_start..index).unwrap_or_default().trim();
        if !member.is_empty() {
            invalid_members.push(member.to_string());
        }
    }
    for member in invalid_members {
        errors.push(format!(
            "{context} array has non-literal or interpolated member {member}"
        ));
    }
    values
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut index = 0;
    while index < text.len() {
        let cursor = skip_string_prefix(text, index);
        if text.as_bytes().get(cursor) != Some(&b'"') {
            index += 1;
            continue;
        }
        if let Some((literal, next)) = parse_csharp_string_literal_at(text, cursor) {
            literals.push(literal);
            index = next;
        } else {
            index += 1;
        }
    }
    literals
}

fn parse_csharp_string_literal_at(text: &str, start: usize) -> Option<(String, usize)> {
    if text.as_bytes().get(start) != Some(&b'"') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut literal = String::new();
    let mut cursor = start + 1;
    let mut escaped = false;
    while cursor < bytes.len() {
        let ch = bytes[cursor] as char;
        if escaped {
            literal.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some((literal, cursor + 1));
        } else {
            literal.push(ch);
        }
        cursor += 1;
    }
    None
}

fn skip_string_prefix(text: &str, mut index: usize) -> usize {
    while matches!(text.as_bytes().get(index), Some(b'$' | b'@')) {
        index += 1;
    }
    index
}

fn csharp_without_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut result = String::with_capacity(source.len());
    let mut index = 0;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut raw_quote_count = 0usize;
    let mut escaped = false;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        let next = bytes.get(index + 1).copied().map(char::from);
        if in_line_comment {
            if ch == '\n' {
                result.push(ch);
                in_line_comment = false;
            } else {
                result.push(' ');
            }
        } else if in_block_comment {
            if ch == '*' && next == Some('/') {
                result.push_str("  ");
                index += 1;
                in_block_comment = false;
            } else {
                result.push(if ch == '\n' { '\n' } else { ' ' });
            }
        } else if in_string {
            result.push(ch);
            if raw_quote_count >= 3 {
                if quote_run_at(source, index) >= raw_quote_count {
                    for _ in 1..raw_quote_count {
                        if index + 1 < bytes.len() {
                            index += 1;
                            result.push('"');
                        }
                    }
                    in_string = false;
                    raw_quote_count = 0;
                }
            } else if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            raw_quote_count = quote_run_at(source, index);
            result.push(ch);
            if raw_quote_count >= 3 {
                for _ in 1..raw_quote_count {
                    index += 1;
                    result.push('"');
                }
            } else {
                raw_quote_count = 1;
            }
            in_string = true;
            escaped = false;
        } else if ch == '/' && next == Some('/') {
            result.push_str("  ");
            index += 1;
            in_line_comment = true;
        } else if ch == '/' && next == Some('*') {
            result.push_str("  ");
            index += 1;
            in_block_comment = true;
        } else {
            result.push(ch);
        }
        index += 1;
    }
    result
}

fn mask_csharp_string_literals(source: &str) -> String {
    let mut masked = source.to_string();
    let mut index = 0;
    while index < source.len() {
        let quote = skip_string_prefix(source, index);
        if source.as_bytes().get(quote) == Some(&b'"') {
            let finish = csharp_string_end(source, quote);
            blank_range_preserving_newlines(&mut masked, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    masked
}

fn csharp_without_string_literals(source: &str) -> String {
    mask_csharp_string_literals(source)
}

fn csharp_string_end(source: &str, start: usize) -> usize {
    let quote_count = quote_run_at(source, start);
    if quote_count >= 3 {
        let delimiter = "\"".repeat(quote_count);
        return source
            .get((start + quote_count)..)
            .and_then(|tail| {
                tail.find(&delimiter)
                    .map(|offset| start + quote_count + offset + quote_count)
            })
            .unwrap_or(source.len());
    }
    let bytes = source.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
        } else if bytes[index] == b'"' {
            return index + 1;
        } else {
            index += 1;
        }
    }
    source.len()
}

fn blank_range_preserving_newlines(text: &mut String, start: usize, finish: usize) {
    let end = finish.min(text.len());
    let mut bytes = text.as_bytes().to_vec();
    for index in start..end {
        if bytes.get(index) != Some(&b'\n') {
            bytes[index] = b' ';
        }
    }
    if let Ok(masked) = String::from_utf8(bytes) {
        *text = masked;
    }
}

fn quote_run_at(source: &str, start: usize) -> usize {
    source
        .as_bytes()
        .iter()
        .skip(start)
        .take_while(|byte| **byte == b'"')
        .count()
}

fn matching_delimiter_index(
    source: &str,
    open_index: usize,
    open_char: u8,
    close_char: u8,
) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open_index) != Some(&open_char) {
        return None;
    }
    let mut depth = 0usize;
    let mut index = open_index;
    while index < bytes.len() {
        if bytes[index] == open_char {
            depth += 1;
        } else if bytes[index] == close_char {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn exact_endpoint_assignment(block: &str, field: &str, expected: &str) -> bool {
    let expected = format!("{field} = {expected},");
    block.lines().any(|line| line.trim() == expected)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    block.lines().any(|line| line.trim() == expected)
}

fn endpoint_assignment_count(block: &str, field: &str) -> usize {
    assignment_occurrences(&csharp_without_string_literals(block), field).len()
}

fn assignment_occurrences(block: &str, field: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let bytes = block.as_bytes();
    let field_bytes = field.as_bytes();
    let mut index = 0;
    while index + field_bytes.len() <= bytes.len() {
        if &bytes[index..index + field_bytes.len()] == field_bytes
            && (index == 0 || !is_ident_byte(bytes[index - 1]))
            && bytes
                .get(index + field_bytes.len())
                .map(|byte| !is_ident_byte(*byte))
                .unwrap_or(true)
        {
            let cursor = skip_ws(block, index + field_bytes.len());
            if bytes.get(cursor) == Some(&b'=') {
                starts.push(index);
            }
        }
        index += 1;
    }
    starts
}

fn assignment_fields(text: &str) -> Vec<String> {
    let masked = csharp_without_string_literals(text);
    let bytes = masked.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !is_ident_start_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_ident_byte(bytes[index]) {
            index += 1;
        }
        let cursor = skip_ws(&masked, index);
        if bytes.get(cursor) == Some(&b'=') {
            if let Some(field) = masked.get(start..index) {
                fields.push(field.to_string());
            }
        }
    }
    fields
}

fn assignment_value<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    let start = find_assignment_index(text, field)?;
    let masked = mask_csharp_string_literals(text);
    let equals = masked
        .get(start..)?
        .find('=')
        .map(|offset| start + offset)?;
    let after = skip_ws(text, equals + 1);
    let comma = masked
        .get(after..)
        .and_then(|rest| rest.find(',').map(|offset| after + offset));
    let close = masked
        .get(after..)
        .and_then(|rest| rest.find('}').map(|offset| after + offset));
    let end = match (comma, close) {
        (Some(comma), Some(close)) => comma.min(close),
        (Some(comma), None) => comma,
        (None, Some(close)) => close,
        (None, None) => text.len(),
    };
    text.get(after..end).map(str::trim)
}

fn find_assignment_index(text: &str, field: &str) -> Option<usize> {
    assignment_occurrences(&csharp_without_string_literals(text), field)
        .first()
        .copied()
}

fn is_quoted_string_literal(value: &str) -> bool {
    let trimmed = value.trim();
    let quote = skip_string_prefix(trimmed, 0);
    trimmed.as_bytes().get(quote) == Some(&b'"')
        && parse_csharp_string_literal_at(trimmed, quote)
            .map(|(_, end)| skip_ws(trimmed, end) == trimmed.len())
            .unwrap_or(false)
}

fn simple_assignments(block: &str) -> Vec<(String, String)> {
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (field, rest) = trimmed.split_once('=')?;
            let field = field.trim();
            if !is_identifier(field) {
                return None;
            }
            let value = rest.trim().trim_end_matches(',').trim();
            Some((field.to_string(), value.to_string()))
        })
        .collect()
}

fn endpoint_surface_block(block: &str) -> String {
    let Some(start) = find_assignment_index(block, "rules") else {
        return block.to_string();
    };
    let scan_block = mask_csharp_string_literals(block);
    let Some(open) = scan_block
        .get(start..)
        .and_then(|text| text.find('{').map(|offset| start + offset))
    else {
        return block.to_string();
    };
    let Some(close) = matching_delimiter_index(&scan_block, open, b'{', b'}') else {
        return block.to_string();
    };
    let mut surface = String::new();
    surface.push_str(block.get(..start).unwrap_or_default());
    surface.push_str("rules = new[] {}");
    surface.push_str(block.get((close + 1)..).unwrap_or_default());
    surface
}

fn rule_object_bodies(block: &str) -> Vec<String> {
    let Some(rules_body) = rules_array_body(block) else {
        return Vec::new();
    };
    let scan_body = mask_csharp_string_literals(&rules_body);
    let mut bodies = Vec::new();
    let mut index = 0;
    while let Some(offset) = scan_body.get(index..).and_then(|text| text.find("new")) {
        let start = index + offset;
        let cursor = skip_ws(&scan_body, start + 3);
        if scan_body.as_bytes().get(cursor) != Some(&b'{') {
            index = start + 3;
            continue;
        }
        let Some(close) = matching_delimiter_index(&scan_body, cursor, b'{', b'}') else {
            break;
        };
        if let Some(body) = rules_body.get((cursor + 1)..close) {
            bodies.push(body.to_string());
        }
        index = close + 1;
    }
    bodies
}

fn rules_array_body(block: &str) -> Option<String> {
    let start = find_assignment_index(block, "rules")?;
    let scan_block = mask_csharp_string_literals(block);
    let open = scan_block
        .get(start..)?
        .find('{')
        .map(|offset| start + offset)?;
    let close = matching_delimiter_index(&scan_block, open, b'{', b'}')?;
    block.get((open + 1)..close).map(str::to_string)
}

fn rules_from_api(block: &str) -> Vec<Rule> {
    rule_object_bodies(block)
        .into_iter()
        .filter_map(|body| {
            let id = literal_assignment(&body, "id")?;
            let decision = literal_assignment(&body, "decision")?;
            let requirement = literal_assignment(&body, "requirement")?;
            let evidence = literal_assignment(&body, "evidence")?;
            Some(Rule {
                id,
                decision,
                requirement,
                evidence,
            })
        })
        .collect()
}

fn literal_assignment(body: &str, field: &str) -> Option<String> {
    let value = assignment_value(body, field)?;
    let quote = skip_string_prefix(value, 0);
    parse_csharp_string_literal_at(value, quote).map(|(literal, _)| literal)
}

fn rules_from_catalog(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule.is_object())
                .map(|rule| Rule {
                    id: string_value(rule, "id").unwrap_or_default().to_string(),
                    decision: string_value(rule, "decision")
                        .unwrap_or_default()
                        .to_string(),
                    requirement: string_value(rule, "requirement")
                        .unwrap_or_default()
                        .to_string(),
                    evidence: string_value(rule, "evidence")
                        .unwrap_or_default()
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited maintenance communications field"
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
        Value::String(text) => {
            if whole_file_text(path, text) {
                validate_text_terms(text, path, errors);
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if let Some(phrase) = prohibited_phrase(text) {
                errors.push(format!(
                    "{path} contains prohibited maintenance communications phrase {phrase}"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited maintenance communications value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    if !maintenance_communications_text_path(path) {
        return;
    }
    for (index, line) in text.lines().enumerate() {
        if !maintenance_communications_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{path}:{} contains prohibited maintenance communications phrase {phrase}",
                index + 1
            ));
        }
        if prohibited_value(line) {
            errors.push(format!("{path}:{} contains prohibited value", index + 1));
        }
        for term in words(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited maintenance communications field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn maintenance_communications_text_path(path: &str) -> bool {
    [
        CATALOG_PATH,
        DOC_PATH,
        API_README_PATH,
        CATALOG_README_PATH,
        DOC_README_PATH,
    ]
    .iter()
    .any(|text_path| path.ends_with(text_path))
}

fn maintenance_communications_text_line(path: &str, line: &str) -> bool {
    path.ends_with(CATALOG_PATH)
        || path.ends_with(DOC_PATH)
        || line
            .to_ascii_lowercase()
            .contains("maintenance-communications")
        || line
            .to_ascii_lowercase()
            .contains("maintenance communications")
        || line.contains("L1/L2")
        || line.contains(ENDPOINT)
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet = stripped.strip_prefix("- ").unwrap_or(stripped);
    let id_value = stripped.strip_prefix("- id: ").unwrap_or(stripped);
    let requirement_value = stripped.strip_prefix("requirement: ").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped)
        || safe_disabled_assignment_line(stripped)
        || safe_text_value(bullet)
        || safe_text_value(id_value)
        || safe_text_value(requirement_value)
}

fn safe_disabled_assignment_line(line: &str) -> bool {
    REQUIRED_DISABLED_FIELDS
        .iter()
        .any(|field| line == format!("{field}: false"))
}

fn safe_text_value(value: &str) -> bool {
    STATIC_SAFE_VALUES.contains(&value)
        || REQUIRED_TYPES.contains(&value)
        || REQUIRED_CHANNELS.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || REQUIRED_CATALOG_KEYS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| value == *variable)
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_value(value) {
        return false;
    }
    contains_any(
        &normalized,
        &[
            "hostname",
            "hostid",
            "hostidentifier",
            "fqdn",
            "username",
            "userid",
            "useridentifier",
            "userprincipal",
            "principalname",
            "customerid",
            "customeridentifier",
            "subscriptionid",
            "subscriptionidentifier",
            "recipient",
            "email",
            "targetid",
            "targetidentifier",
            "serviceidentifier",
            "servicename",
            "volumename",
            "mountpath",
            "filepath",
            "rawlog",
            "logcontent",
            "rawtarget",
            "workerpayload",
            "rawworker",
            "providerpayload",
            "rawprovider",
            "providerresponse",
            "providerendpoint",
            "endpointurl",
            "endpointuri",
            "endpointname",
            "tenantid",
            "tenantidentifier",
            "objectid",
            "objectidentifier",
            "serialnumber",
            "privateip",
            "credentialvalue",
            "secretvalue",
            "accesstoken",
            "credential",
            "secret",
            "token",
            "password",
        ],
    ) || sensitive_compound_field(value)
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    has_any(
        &tokens,
        &["password", "credential", "token", "bearer", "secret"],
    ) || has_any(&tokens, &["url", "uri", "endpoint", "fqdn", "serial"])
        || (has_any(&tokens, &["id", "guid", "identifier"]) && tokens.len() > 1)
        || (has_any(
            &tokens,
            &[
                "private", "ip", "host", "dns", "service", "target", "mount", "file",
            ],
        ) && has_any(&tokens, &["address", "name", "path", "id", "identifier"]))
        || (has_any(
            &tokens,
            &[
                "provider",
                "tenant",
                "object",
                "customer",
                "subscription",
                "recipient",
                "user",
                "principal",
                "worker",
            ],
        ) && has_any(
            &tokens,
            &[
                "name",
                "url",
                "uri",
                "endpoint",
                "reference",
                "id",
                "identifier",
                "key",
                "value",
                "data",
                "address",
                "payload",
                "row",
                "rows",
                "content",
            ],
        ))
        || (tokens.contains(&"raw".to_string())
            && has_any(
                &tokens,
                &[
                    "target",
                    "worker",
                    "provider",
                    "log",
                    "logs",
                    "payload",
                    "rows",
                    "recipient",
                    "data",
                    "content",
                ],
            ))
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let normalized = value.to_ascii_lowercase().replace(['_', '-'], " ");
    let phrases = [
        "host name",
        "host id",
        "user name",
        "customer id",
        "subscription id",
        "recipient email",
        "recipient data",
        "target identifier",
        "service name",
        "serial number",
        "endpoint url",
        "mount path",
        "file path",
        "raw log content",
        "raw target data",
        "worker payload",
        "raw provider rows",
        "provider payload",
        "provider response",
        "tenant id",
        "object id",
        "private ip",
        "credential value",
        "secret value",
        "access token",
    ];
    phrases
        .iter()
        .find(|phrase| normalized.contains(**phrase))
        .copied()
}

fn prohibited_value(value: &str) -> bool {
    contains_url(value)
        || contains_email(value)
        || contains_private_ipv4(value)
        || contains_uuid(value)
        || contains_dns_name(value)
        || contains_absolute_path(value)
        || value.to_ascii_uppercase().contains("AKIA")
            && value
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .count()
                >= 20
        || value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----")
        || contains_secret_assignment(value)
}

fn unsafe_true_field(field: &str) -> bool {
    let normalized = normalize(field);
    contains_any(
        &normalized,
        &[
            "live",
            "provider",
            "worker",
            "raw",
            "payload",
            "service",
            "disk",
            "backup",
            "alert",
            "allowed",
            "enabled",
            "notification",
            "recipient",
            "send",
            "dispatch",
            "export",
        ],
    )
}

fn contains_url(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|token| token.to_ascii_lowercase().contains("://"))
}

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let Some((local, domain)) = token.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain.chars().any(|ch| ch.is_ascii_alphabetic())
    })
}

fn contains_private_ipv4(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|token| {
            let octets: Vec<&str> = token.split('.').collect();
            if octets.len() != 4 {
                return false;
            }
            let parsed: Option<Vec<u8>> = octets
                .iter()
                .map(|octet| octet.parse::<u8>().ok())
                .collect();
            let Some(parsed) = parsed else {
                return false;
            };
            parsed[0] == 10
                || (parsed[0] == 192 && parsed[1] == 168)
                || (parsed[0] == 172 && (16..=31).contains(&parsed[1]))
        })
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_hexdigit() && ch != '-')
        .any(|token| {
            token.len() == 36
                && token.as_bytes().get(8) == Some(&b'-')
                && token.as_bytes().get(13) == Some(&b'-')
                && token.as_bytes().get(18) == Some(&b'-')
                && token.as_bytes().get(23) == Some(&b'-')
                && token.chars().all(|ch| ch == '-' || ch.is_ascii_hexdigit())
        })
}

fn contains_dns_name(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-'))
        .any(|token| {
            token.matches('.').count() >= 2
                && token.chars().any(|ch| ch.is_ascii_alphabetic())
                && token.split('.').all(|part| {
                    !part.is_empty()
                        && part
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                })
        })
}

fn contains_absolute_path(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "/var/",
        "/etc/",
        "/home/",
        "/opt/",
        "/srv/",
        "/tmp/",
        "/usr/",
        "/windows/",
        "/programdata/",
        "/program files/",
    ]
    .iter()
    .any(|prefix| lowered.contains(prefix))
}

fn contains_secret_assignment(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ]
    .iter()
    .any(|key| lowered.contains(&format!("{key}:")) || lowered.contains(&format!("{key}=")))
}

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn unique_len(values: &[String]) -> usize {
    values.iter().collect::<BTreeSet<_>>().len()
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut separated = String::with_capacity(value.len() * 2);
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            separated.push(' ');
        }
        if ch.is_ascii_alphanumeric() {
            separated.push(ch.to_ascii_lowercase());
            previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            separated.push(' ');
            previous_lower_or_digit = false;
        }
    }
    separated.split_whitespace().map(str::to_string).collect()
}

fn words(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        .filter(|word| !word.is_empty())
        .map(str::to_string)
        .collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_ident_start_byte(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_ws(text: &str, mut index: usize) -> usize {
    while text
        .as_bytes()
        .get(index)
        .map(|byte| byte.is_ascii_whitespace())
        .unwrap_or(false)
    {
        index += 1;
    }
    index
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
    fn mapget_routes_accept_receiver_whitespace() {
        let program = format!(
            "app . MapGet ( \"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let routes = mapget_routes(&program);

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].route, ENDPOINT);
    }

    #[test]
    fn fake_receiver_is_not_endpoint() {
        let program = format!(
            "fakeapp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"spoofed\" }}));"
        );

        assert!(mapget_routes(&program).is_empty());
    }

    #[test]
    fn duplicate_endpoint_is_rejected() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));\napp.MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();

        let block = endpoint_block(&program, &mut errors);

        assert!(block.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.contains("endpoint") && error.contains("exactly one")));
    }

    #[test]
    fn rule_literal_assignments_are_parsed() {
        let body = r#" id = "no-live-notification-send", decision = "block", requirement = "One, two, three.", evidence = "Communication draft" "#;

        assert_eq!(
            assignment_value(body, "id"),
            Some(r#""no-live-notification-send""#)
        );
        assert_eq!(
            literal_assignment(body, "id").as_deref(),
            Some("no-live-notification-send")
        );
        assert_eq!(
            literal_assignment(body, "decision").as_deref(),
            Some("block")
        );
        assert_eq!(
            literal_assignment(body, "requirement").as_deref(),
            Some("One, two, three.")
        );
        assert_eq!(
            literal_assignment(body, "evidence").as_deref(),
            Some("Communication draft")
        );
    }

    #[test]
    fn raw_catalog_text_allows_expected_disabled_assignment_lines() {
        let catalog_text = REQUIRED_DISABLED_FIELDS
            .iter()
            .map(|field| format!("{field}: false"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut errors = Vec::new();

        scan_prohibited_value(&Value::String(catalog_text), CATALOG_PATH, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn raw_catalog_text_rejects_sensitive_identifier_fields() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String("customerIdentifier: safe-summary\n".to_string()),
            CATALOG_PATH,
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("customerIdentifier")));
    }
}
