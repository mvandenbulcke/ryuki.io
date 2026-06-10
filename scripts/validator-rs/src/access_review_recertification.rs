use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/access-review-recertification-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/access-review-recertification.md";
const ENDPOINT: &str = "/api/identity/access-review-recertification-contract";
const REQUIRED_SCOPES: &[&str] = &[
    "ownership-recertification",
    "support-group-recertification",
    "privileged-role-review",
    "service-account-review",
    "stale-access-review",
    "exception-review",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "owner-missing",
    "support-group-missing",
    "privileged-role-aging",
    "service-account-unknown",
    "orphaned-access",
    "recertification-overdue",
    "exception-expiring",
];
const REQUIRED_INPUTS: &[&str] = &[
    "reviewScopeSummary",
    "recertificationCycle",
    "accessScope",
    "roleProfile",
    "ownershipSummary",
    "supportGroup",
    "riskTier",
    "reviewCadence",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "review-scope-summarized",
    "owner-known",
    "support-group-known",
    "approval-route-assigned",
    "evidence-redacted",
    "raw-identity-data-blocked",
    "expiry-date-set",
    "remediation-plan-ready",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "reviewSummary",
    "scopeReview",
    "ownershipDecision",
    "privilegedAccessReview",
    "serviceAccountReview",
    "exceptionDecision",
    "remediationPlan",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-directory-change-disabled",
    "live-servicenow-change-disabled",
    "raw-user-data-disabled",
    "raw-group-data-disabled",
    "principal-identifiers-disabled",
    "tenant-identifiers-disabled",
    "object-identifiers-disabled",
    "raw-provider-payloads-disabled",
    "review-scope-missing",
    "owner-unknown",
    "support-group-unknown",
    "approval-missing",
    "expiry-missing",
    "remediation-plan-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Access review summary",
    "Scope review",
    "Ownership decision",
    "Privileged access review",
    "Service account review",
    "Exception decision",
    "Remediation plan",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveDirectoryChangesAllowed",
    "liveServiceNowChangesAllowed",
    "rawUserDataAllowed",
    "rawGroupDataAllowed",
    "principalIdentifiersAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "rawProviderPayloadsAllowed",
];
const CATALOG_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "reviewMode",
    "providerCallsEnabled",
    "liveDirectoryChangesAllowed",
    "liveServiceNowChangesAllowed",
    "rawUserDataAllowed",
    "rawGroupDataAllowed",
    "principalIdentifiersAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "rawProviderPayloadsAllowed",
    "reviewScopes",
    "reviewSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("reviewScopes", "accessReviewRecertificationScopes"),
    ("reviewSignals", "accessReviewRecertificationSignals"),
    (
        "requiredGuards",
        "accessReviewRecertificationRequiredGuards",
    ),
    ("planSections", "accessReviewRecertificationPlanSections"),
    (
        "blockedReasons",
        "accessReviewRecertificationBlockedReasons",
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "reviewMode",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "reviewScopes",
    "reviewSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "providerCallsEnabled",
    "liveDirectoryChangesAllowed",
    "liveServiceNowChangesAllowed",
    "rawUserDataAllowed",
    "rawGroupDataAllowed",
    "principalIdentifiersAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "rawProviderPayloadsAllowed",
];
const SINGLETON_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "reviewMode",
    "reviewScopes",
    "reviewSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "providerCallsEnabled",
    "liveDirectoryChangesAllowed",
    "liveServiceNowChangesAllowed",
    "rawUserDataAllowed",
    "rawGroupDataAllowed",
    "principalIdentifiersAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "rawProviderPayloadsAllowed",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-access-changes",
        decision: "block",
        requirement:
            "Access recertification reports review state only and never changes Entra groups, AD groups, ServiceNow records, local memberships, or provider state.",
        evidence: "Access review summary",
    },
    RuleDetail {
        id: "redacted-scope-required",
        decision: "block",
        requirement: "Review scope must be summarized before recertification can be accepted.",
        evidence: "Scope review",
    },
    RuleDetail {
        id: "ownership-and-approval-required",
        decision: "block",
        requirement:
            "Ownership, support group, approval route, expiry, and review cadence must be known before acceptance.",
        evidence: "Ownership decision",
    },
    RuleDetail {
        id: "privileged-access-reviewed",
        decision: "block",
        requirement:
            "Privileged access and service account scope must be reviewed before exception or remediation decisions.",
        evidence: "Privileged access review",
    },
    RuleDetail {
        id: "raw-identity-data-not-exposed",
        decision: "block",
        requirement:
            "Access recertification evidence must use safe summaries only and must not expose raw user records, group membership rows, principal IDs, tenant IDs, object IDs, account names, email addresses, or provider payloads.",
        evidence: "Evidence references",
    },
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Access review recertification seed data only. Do not add user names, account names, group names, email addresses, UPNs, principal IDs, tenant IDs, object IDs, raw membership rows, credentials, tokens, raw logs, ServiceNow payloads, Entra payloads, AD payloads, or provider payloads.",
    "- No raw user data, raw group data, group membership rows, principal identifiers, tenant identifiers, object identifiers, account names, email addresses, credentials, tokens, raw provider payloads, or ServiceNow/Entra/AD payloads in committed files.",
    "requirement: Access recertification evidence must use safe summaries only and must not expose raw user records, group membership rows, principal IDs, tenant IDs, object IDs, account names, email addresses, or provider payloads.",
];

#[derive(Debug, Deserialize)]
struct AccessReviewRecertificationContext {
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

#[derive(Debug, Deserialize)]
struct ControlsInput {
    block: String,
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
    let context: AccessReviewRecertificationContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid access review recertification context JSON: {error}"))?;
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
        .map_err(|error| format!("invalid access review recertification catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid access review recertification program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid access review recertification docs JSON: {error}"))?;
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
    let payload: ProhibitedInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid access review recertification prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

pub fn validate_controls_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ControlsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid access review recertification controls JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_unsafe_true_flags(&payload.block, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("access review recertification catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_field_names(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "access review recertification version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "access review recertification status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "access review recertification source must be static-seed",
    );
    expect(
        string_value(catalog, "reviewMode") == Some("review-only"),
        errors,
        "access review recertification mode must be review-only",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("access review recertification {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "reviewScopes", REQUIRED_SCOPES, errors);
    validate_required_array(catalog, "reviewSignals", REQUIRED_SIGNALS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_field_names(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|field| !CATALOG_FIELDS.contains(field))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "access review recertification unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
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
                "access review recertification rule {rule_id} has unexpected field {field}"
            ));
            if prohibited_field(field) {
                errors.push(format!(
                    "access review recertification rule {rule_id} has prohibited field {field}"
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
        missing.is_empty(),
        errors,
        format!(
            "access review recertification missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "access review recertification unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "access review recertification rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "access review recertification rule details must be unique",
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "access review recertification rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "access review recertification rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "access review recertification rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let block = endpoint_block(&uncommented_program, errors);
    if block.is_empty() {
        return;
    }

    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "reviewMode", "review-only"),
        errors,
        "API must keep review-only mode",
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
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array_like(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            string_array_like(catalog, field),
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_endpoint_singleton_fields(&block, errors);
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
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited identity phrase {phrase}"
            ));
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited identity value {value}"
            ));
        }
        if contains_provider_identifier(&value) {
            errors.push(format!(
                "API {field} contains prohibited provider-identifying value"
            ));
        }
    }
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
        errors.push(format!("API has unexpected API rule {id}"));
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
        errors.push(format!(
            "API endpoint has unexpected access review field {field}"
        ));
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited identity field {field}"
            ));
        }
    }
}

fn validate_endpoint_singleton_fields(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    let fields = assignment_fields(&stripped);
    for field in SINGLETON_ENDPOINT_FIELDS {
        let count = fields.iter().filter(|candidate| candidate == field).count();
        expect(
            count == 1,
            errors,
            format!("API endpoint field {field} must appear exactly once"),
        );
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !(field.ends_with("Allowed") || field.ends_with("Enabled")) {
            continue;
        }
        if REQUIRED_DISABLED_FIELDS.contains(&field.as_str())
            && exact_assignment(block, &field, "false")
        {
            continue;
        }
        errors.push(format!(
            "API endpoint has unsafe access review control {field}"
        ));
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
        "API README missing access review recertification endpoint",
    );
    expect(
        catalog_readme.contains(CATALOG_PATH.trim_start_matches("catalog/")),
        errors,
        "catalog README missing access review recertification catalog",
    );
    expect(
        doc_readme.contains(DOC_PATH.trim_start_matches("docs/workflows/")),
        errors,
        "workflow README missing access review recertification doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "access review recertification doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "access review recertification doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live directory changes."),
        errors,
        "access review recertification doc must prohibit directory changes",
    );
    expect(
        doc.contains("No live ServiceNow changes."),
        errors,
        "access review recertification doc must prohibit ServiceNow changes",
    );
    expect(
        doc.contains("safe access review summaries only"),
        errors,
        "access review recertification doc must require safe summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!("{child_path} contains prohibited identity field"));
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
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if contains_provider_identifier(text) {
                    errors.push(format!(
                        "{path} contains prohibited provider-identifying value"
                    ));
                }
                if access_review_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if contains_provider_identifier(text) {
                errors.push(format!(
                    "{path} contains prohibited provider-identifying value"
                ));
            }
            if let Some(phrase) = prohibited_phrase(text) {
                errors.push(format!(
                    "{path} contains prohibited identity phrase {phrase}"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!("{path} contains prohibited identity value {text}"));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !access_review_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{}:{} contains prohibited identity phrase {}",
                path,
                index + 1,
                phrase
            ));
        }
        if contains_provider_identifier(line) {
            errors.push(format!(
                "{}:{} contains prohibited provider-identifying value",
                path,
                index + 1
            ));
        }
        for term in identifier_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{}:{} contains prohibited identity field {}",
                    path,
                    index + 1,
                    term
                ));
            }
        }
    }
}

fn catalog_rules(catalog: &Value, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(Value::Array(rules)) = catalog.get("rules") else {
        errors.push("access review recertification rules must be an array of mappings".to_string());
        return Vec::new();
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("access review recertification rules must be an array of mappings".to_string());
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
    assignment_lines(block, field).as_slice() == [expected]
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    assignment_lines(block, field).as_slice() == [expected]
}

fn assignment_lines(block: &str, field: &str) -> Vec<String> {
    let marker = format!("{field} =");
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with(&marker) {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[] {{");
    if program.matches(&marker).count() != 1 {
        return None;
    }
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    csharp_string_literals(&program[start..end])
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
    let count = assignment_fields(&strip_csharp_string_literals(block))
        .iter()
        .filter(|field| field.as_str() == "rules")
        .count();
    if count != 1 {
        errors.push("API rules assignment must be present once".to_string());
        return None;
    }
    let Some(rules_index) = block.find("rules = new[]") else {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    };
    let Some(open_relative) = block[rules_index..].find('{') else {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    };
    let open_index = rules_index + open_relative;
    let Some(close_index) = matching_brace_index(block, open_index) else {
        errors.push("API rules array must be closed".to_string());
        return None;
    };
    Some(block[open_index + 1..close_index].to_string())
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
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
        errors.push("API missing access review recertification endpoint".to_string());
        return String::new();
    }
    expect(
        starts.len() == 1,
        errors,
        "API must expose exactly one access review recertification endpoint",
    );
    let start_index = starts[0];
    let next_index =
        next_endpoint_index(uncommented_program, start_index).unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_index].to_string()
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

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = program[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let line_prefix = program[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&program[..index]);
        if line_prefix.trim().is_empty() {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
}

fn strip_csharp_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
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

fn safe_text_value(value: &str) -> bool {
    REQUIRED_SCOPES.contains(&value)
        || REQUIRED_SIGNALS.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || CATALOG_FIELDS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || matches!(value, "draft" | "static-seed" | "review-only" | "block")
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    let id_value = stripped.strip_prefix("- id: ").unwrap_or(stripped);
    let requirement_value = stripped.strip_prefix("requirement: ").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped)
        || safe_text_value(bullet_value)
        || safe_text_value(id_value)
        || safe_text_value(requirement_value)
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_normalized(&normalized) {
        return false;
    }
    [
        "username",
        "userid",
        "useridentifier",
        "userprincipalname",
        "upn",
        "samaccountname",
        "mailaddress",
        "email",
        "accountname",
        "accountid",
        "accountidentifier",
        "groupname",
        "groupid",
        "groupidentifier",
        "principalid",
        "principalidentifier",
        "tenantid",
        "tenantidentifier",
        "objectid",
        "objectidentifier",
        "membershiprow",
        "rawmembership",
        "rawuser",
        "rawgroup",
        "providerpayload",
        "credential",
        "secret",
        "token",
        "password",
    ]
    .iter()
    .any(|fragment| normalized.contains(fragment))
}

fn safe_text_normalized(normalized: &str) -> bool {
    let mut values: Vec<&str> = Vec::new();
    values.extend_from_slice(REQUIRED_SCOPES);
    values.extend_from_slice(REQUIRED_SIGNALS);
    values.extend_from_slice(REQUIRED_INPUTS);
    values.extend_from_slice(REQUIRED_GUARDS);
    values.extend_from_slice(REQUIRED_PLAN_SECTIONS);
    values.extend_from_slice(REQUIRED_BLOCKED_REASONS);
    values.extend_from_slice(REQUIRED_EVIDENCE);
    values.extend_from_slice(REQUIRED_DISABLED_FIELDS);
    values.extend_from_slice(CATALOG_FIELDS);
    values.extend(["draft", "static-seed", "review-only", "block"]);
    values
        .into_iter()
        .any(|value| normalize(value) == normalized)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| normalize(variable) == normalized)
        || REQUIRED_RULES.iter().any(|rule| {
            normalize(rule.id) == normalized
                || normalize(rule.decision) == normalized
                || normalize(rule.requirement) == normalized
                || normalize(rule.evidence) == normalized
        })
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let tokens = phrase_tokens(value);
    [
        ("user name", &["user", "name"][..]),
        ("user ID", &["user", "id"][..]),
        ("user identifier", &["user", "identifier"][..]),
        ("raw user data", &["raw", "user", "data"][..]),
        ("raw user record", &["raw", "user", "record"][..]),
        ("raw group data", &["raw", "group", "data"][..]),
        ("group membership rows", &["group", "membership", "row"][..]),
        ("membership rows", &["membership", "row"][..]),
        ("principal ID", &["principal", "id"][..]),
        ("principal identifier", &["principal", "identifier"][..]),
        ("tenant ID", &["tenant", "id"][..]),
        ("tenant identifier", &["tenant", "identifier"][..]),
        ("object ID", &["object", "id"][..]),
        ("object identifier", &["object", "identifier"][..]),
        ("account name", &["account", "name"][..]),
        ("group name", &["group", "name"][..]),
        ("email address", &["email", "address"][..]),
        ("raw provider payload", &["raw", "provider", "payload"][..]),
        ("provider payload", &["provider", "payload"][..]),
    ]
    .iter()
    .find_map(|(label, phrase)| {
        if has_token_sequence(&tokens, phrase) {
            Some(*label)
        } else {
            None
        }
    })
}

fn phrase_tokens(value: &str) -> Vec<String> {
    identifier_terms(value)
        .into_iter()
        .map(|term| {
            let lower = term.to_ascii_lowercase();
            lower.strip_suffix('s').unwrap_or(&lower).to_string()
        })
        .collect()
}

fn has_token_sequence(tokens: &[String], phrase: &[&str]) -> bool {
    tokens.windows(phrase.len()).any(|window| {
        window
            .iter()
            .zip(phrase)
            .all(|(actual, expected)| actual == expected)
    })
}

fn access_review_text_path(path: &str) -> bool {
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

fn access_review_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(CATALOG_PATH) || path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("access-review")
        || lower.contains("access review")
        || lower.contains("recertification")
        || line.contains(ENDPOINT)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|extension| path.ends_with(extension))
}

fn prohibited_value(text: &str) -> bool {
    contains_aws_access_key(text)
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || text.contains("://")
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_email_like(text)
        || contains_domain_user_like(text)
        || contains_secret_assignment(text)
}

fn contains_provider_identifier(text: &str) -> bool {
    normalized_tokens(text)
        .iter()
        .any(|token| is_forty_hex(token) || is_serial_identifier(token))
}

fn contains_aws_access_key(text: &str) -> bool {
    normalized_tokens(text).iter().any(|token| {
        token.len() == 20
            && token.starts_with("AKIA")
            && token.chars().all(|ch| ch.is_ascii_alphanumeric())
    })
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
    raw_tokens(text).iter().any(|token| {
        let clean = token.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | ',' | ';' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>' | '`'
            )
        });
        let Some((local, domain)) = clean.split_once('@') else {
            return false;
        };
        !local.is_empty() && domain.contains('.') && domain.rsplit_once('.').is_some()
    })
}

fn contains_domain_user_like(text: &str) -> bool {
    raw_tokens(text).iter().any(|token| {
        let clean = token.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | ',' | ';' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>' | '`'
            )
        });
        let Some((left, right)) = clean.split_once('\\') else {
            return false;
        };
        !left.is_empty()
            && !right.is_empty()
            && left
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
            && right
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
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

fn is_forty_hex(token: &str) -> bool {
    token.len() == 40 && token.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn is_serial_identifier(token: &str) -> bool {
    let upper = token.to_ascii_uppercase();
    let Some(value) = upper
        .strip_prefix("SN-")
        .or_else(|| upper.strip_prefix("SN_"))
        .or_else(|| upper.strip_prefix("SERIAL-"))
        .or_else(|| upper.strip_prefix("SERIAL_"))
    else {
        return false;
    };
    value.len() >= 6
        && value.chars().all(|ch| ch.is_ascii_alphanumeric())
        && value.chars().any(|ch| ch.is_ascii_digit())
}

fn identifier_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !chars[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len()
            && (chars[index].is_ascii_alphanumeric() || chars[index] == '_' || chars[index] == '-')
        {
            index += 1;
        }
        terms.push(chars[start..index].iter().collect());
    }
    terms
}

fn raw_tokens(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_string).collect()
}

fn normalized_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| {
        !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '@' || ch == '.')
    })
    .filter(|token| !token.is_empty())
    .map(str::to_string)
    .collect()
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
