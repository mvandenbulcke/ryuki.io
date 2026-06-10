use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/evidence-compliance-dashboard-contract.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/evidence-compliance-dashboard.md";
const ENDPOINT: &str = "/api/evidence/compliance-dashboard-contract";

const REQUIRED_COMPLIANCE_DOMAINS: &[&str] = &[
    "security-baseline",
    "rbac-approvals",
    "evidence-redaction",
    "backup-coverage",
    "monitoring-coverage",
    "cmdb-readiness",
    "patch-readiness",
    "restore-testing",
];
const REQUIRED_STATUS_BANDS: &[&str] =
    &["compliant", "attention", "gap", "blocked", "not-assessed"];
const REQUIRED_GUARDS: &[&str] = &[
    "control-scope-known",
    "evidence-pack-referenced",
    "redaction-state-reviewed",
    "stale-data-marked",
    "owner-assigned",
    "live-evaluation-blocked",
    "evidence-redacted",
];
const REQUIRED_TREND_WINDOWS: &[&str] = &["current", "seven-day", "thirty-day", "quarterly"];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "compliance-live-evaluation-disabled",
    "compliance-evidence-mutation-disabled",
    "compliance-export-mutation-disabled",
    "compliance-retention-mutation-disabled",
    "compliance-workflow-mutation-disabled",
    "compliance-provider-calls-disabled",
    "compliance-notification-dispatch-disabled",
    "compliance-raw-evidence-payloads-disabled",
    "compliance-raw-control-rows-disabled",
    "compliance-raw-audit-logs-disabled",
    "compliance-raw-user-data-disabled",
    "compliance-raw-provider-payloads-disabled",
    "compliance-raw-recipient-data-disabled",
    "compliance-credential-values-disabled",
    "compliance-token-values-disabled",
    "compliance-tenant-identifiers-disabled",
    "compliance-object-identifiers-disabled",
    "compliance-principal-identifiers-disabled",
    "compliance-private-network-values-disabled",
    "control-scope-missing",
    "evidence-pack-missing",
    "redaction-state-unknown",
    "stale-data-unmarked",
    "owner-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Compliance dashboard summary",
    "Control status summary",
    "Evidence pack references",
    "Redaction summary",
    "Stale data summary",
    "Owner review summary",
    "Evidence references",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "complianceSummaryAggregateOnly",
    "controlStatusReadOnly",
    "evidencePackReferenceOnly",
    "auditTrendAggregateOnly",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveComplianceEvaluationAllowed",
    "evidenceMutationAllowed",
    "exportMutationAllowed",
    "retentionMutationAllowed",
    "workflowMutationAllowed",
    "providerCallsAllowed",
    "notificationDispatchAllowed",
    "rawEvidencePayloadsAllowed",
    "rawControlRowsAllowed",
    "rawAuditLogsAllowed",
    "rawUserDataAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "privateNetworkValuesAllowed",
];
const CATALOG_BASE_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "evidenceComplianceDashboardMode",
    "complianceDomains",
    "statusBands",
    "requiredGuards",
    "trendWindows",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("complianceDomains", "evidenceComplianceDashboardDomains"),
    ("statusBands", "evidenceComplianceDashboardStatusBands"),
    ("trendWindows", "evidenceComplianceDashboardTrendWindows"),
    (
        "requiredGuards",
        "evidenceComplianceDashboardRequiredGuards",
    ),
    (
        "blockedReasons",
        "evidenceComplianceDashboardBlockedReasons",
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredEvidence"];
const ENDPOINT_BASE_FIELDS: &[&str] = &[
    "source",
    "evidenceComplianceDashboardMode",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "complianceDomains",
    "statusBands",
    "requiredGuards",
    "trendWindows",
    "blockedReasons",
    "requiredEvidence",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
    "user",
    "principal",
    "tenant",
    "object",
];
const PROHIBITED_FIELD_TOKENS: &[&str] = &[
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
    "userid",
    "useridentifier",
    "username",
    "useremail",
    "privateip",
    "privatenetwork",
    "providerpayload",
    "rawprovider",
    "rawevidence",
    "evidencepayload",
    "rawcontrol",
    "controlrow",
    "rawaudit",
    "auditlog",
    "rawlog",
    "rawrow",
    "rawrows",
    "rawuser",
    "userdata",
    "rawrecipient",
    "recipientemail",
    "recipientaddress",
    "recipientdata",
    "endpointurl",
    "url",
    "livemutation",
    "evidencemutation",
    "exportmutation",
    "retentionmutation",
    "workflowmutation",
    "providercall",
    "notificationdispatch",
    "livecompliance",
];
const SECRET_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
    "credential",
    "secret",
    "token",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail { id: "aggregate-compliance-only", decision: "block", requirement: "Compliance dashboard summaries are aggregate-only and must not run live compliance evaluation or expose raw control rows.", evidence: "Compliance dashboard summary" },
    RuleDetail { id: "control-status-read-only", decision: "block", requirement: "Control status, trend windows, stale-data markers, and owner review summaries are read-only and must not mutate evidence, export, retention, or workflow state.", evidence: "Control status summary" },
    RuleDetail { id: "evidence-pack-reference-only", decision: "block", requirement: "Dashboard evidence uses evidence pack references and redaction summaries only; it must not copy raw evidence payloads or audit logs.", evidence: "Evidence pack references" },
    RuleDetail { id: "raw-compliance-data-not-exposed", decision: "block", requirement: "Evidence compliance dashboard evidence must not expose raw evidence payloads, raw control rows, raw audit logs, raw user data, raw provider payloads, recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.", evidence: "Evidence references" },
];

#[derive(Debug, Deserialize)]
struct Context {
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid evidence compliance dashboard context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_text(&context.api_readme, API_README_PATH, &mut errors);
    scan_prohibited_text(&context.catalog_readme, CATALOG_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc_readme, DOC_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence compliance dashboard catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence compliance dashboard program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence compliance dashboard docs JSON: {error}"))?;
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
        format!("invalid evidence compliance dashboard prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("evidence compliance dashboard catalog must be a mapping".to_string());
        return;
    };
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !catalog_key_allowed(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "evidence compliance dashboard unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "evidence compliance dashboard version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "evidence compliance dashboard status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "evidence compliance dashboard source must be static-seed",
    );
    expect(
        string_value(catalog, "evidenceComplianceDashboardMode")
            == Some("static-evidence-compliance-dashboard"),
        errors,
        "evidence compliance dashboard mode must be static-evidence-compliance-dashboard",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("evidence compliance dashboard {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("evidence compliance dashboard {field} must be disabled"),
        );
    }
    validate_required_array(
        catalog,
        "complianceDomains",
        REQUIRED_COMPLIANCE_DOMAINS,
        errors,
    );
    expect(
        value_string_array(catalog.get("complianceDomains"))
            == REQUIRED_COMPLIANCE_DOMAINS
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        errors,
        "complianceDomains must preserve canonical domain order",
    );
    validate_required_array(catalog, "statusBands", REQUIRED_STATUS_BANDS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "trendWindows", REQUIRED_TREND_WINDOWS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array(catalog.get(field), field, errors);
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
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited evidence compliance dashboard value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rule_hashes(catalog, errors);
    let rule_ids: Vec<String> = rules.iter().map(|rule| rule.id.clone()).collect();
    let id_set: BTreeSet<&str> = rule_ids.iter().map(String::as_str).collect();
    let required_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !id_set.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .map(String::as_str)
        .filter(|id| !required_ids.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "evidence compliance dashboard missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "evidence compliance dashboard unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "evidence compliance dashboard rule IDs must be unique",
    );
    expect_unique_rule_details(
        &rules,
        errors,
        "evidence compliance dashboard rule details must be unique",
    );
    for detail in REQUIRED_RULES {
        if let Some(rule) = rules.iter().find(|candidate| candidate.id == detail.id) {
            expect(
                rule.decision == detail.decision,
                errors,
                format!(
                    "evidence compliance dashboard rule {} decision must match",
                    detail.id
                ),
            );
            expect(
                rule.requirement == detail.requirement,
                errors,
                format!(
                    "evidence compliance dashboard rule {} requirement must match",
                    detail.id
                ),
            );
            expect(
                rule.evidence == detail.evidence,
                errors,
                format!(
                    "evidence compliance dashboard rule {} evidence must match",
                    detail.id
                ),
            );
        }
    }
}

fn catalog_rule_hashes(catalog: &Value, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(items) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("evidence compliance dashboard rules must be an array".to_string());
        return Vec::new();
    };
    let mut rules = Vec::new();
    for item in items {
        let Some(map) = item.as_object() else {
            errors.push("evidence compliance dashboard rule entry must be a mapping".to_string());
            continue;
        };
        let unexpected: Vec<&str> = map
            .keys()
            .map(String::as_str)
            .filter(|key| !RULE_KEYS.contains(key))
            .collect();
        let missing: Vec<&str> = RULE_KEYS
            .iter()
            .copied()
            .filter(|key| !map.contains_key(*key))
            .collect();
        let id = string_value(item, "id").unwrap_or("(missing id)");
        if !unexpected.is_empty() {
            errors.push(format!(
                "evidence compliance dashboard rule {id} unexpected rule keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "evidence compliance dashboard rule {id} missing rule keys: {}",
                missing.join(", ")
            ));
        }
        rules.push(Rule {
            id: string_value(item, "id").unwrap_or_default().to_string(),
            decision: string_value(item, "decision")
                .unwrap_or_default()
                .to_string(),
            requirement: string_value(item, "requirement")
                .unwrap_or_default()
                .to_string(),
            evidence: string_value(item, "evidence")
                .unwrap_or_default()
                .to_string(),
        });
    }
    rules
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
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
        exact_string_assignment(
            &block,
            "evidenceComplianceDashboardMode",
            "static-evidence-compliance-dashboard",
        ),
        errors,
        "API must keep static-evidence-compliance-dashboard mode",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "true"),
            errors,
            format!("API must keep {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            &value_string_array(catalog.get(*field)),
            errors,
        );
    }
    expect(
        csharp_array_values(&uncommented_program, "evidenceComplianceDashboardDomains")
            == Some(required_domain_strings()),
        errors,
        "API complianceDomains must preserve canonical domain order",
    );
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            &value_string_array(catalog.get(*field)),
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
    catalog_values: &[String],
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
    let catalog_rules = catalog_rule_hashes(catalog, errors);
    let api_rules = api_rule_hashes(block);
    let catalog_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let catalog_set: BTreeSet<&str> = catalog_ids.iter().map(String::as_str).collect();
    let api_set: BTreeSet<&str> = api_ids.iter().map(String::as_str).collect();
    for id in catalog_ids
        .iter()
        .filter(|id| !api_set.contains(id.as_str()))
    {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids
        .iter()
        .filter(|id| !catalog_set.contains(id.as_str()))
    {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(
        api_ids.iter().collect::<BTreeSet<_>>().len() == api_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect_unique_rule_details(&api_rules, errors, "API rule details must be unique");
    for catalog_rule in catalog_rules {
        if let Some(api_rule) = api_rules
            .iter()
            .find(|candidate| candidate.id == catalog_rule.id)
        {
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
}

fn api_rule_hashes(block: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(relative) = block[offset..].find("new") {
        let start = offset + relative;
        if block[start..].starts_with("new[]") {
            offset = start + 3;
            continue;
        }
        let Some(brace_relative) = block[start..].find('{') else {
            break;
        };
        let brace = start + brace_relative;
        let Some((body, _end)) = balanced_brace_body(block, brace) else {
            break;
        };
        if !body.contains("rules =") && body.contains("id") && body.contains("decision") {
            let rule = Rule {
                id: find_string_assignment(&body, "id").unwrap_or_default(),
                decision: find_string_assignment(&body, "decision").unwrap_or_default(),
                requirement: find_string_assignment(&body, "requirement").unwrap_or_default(),
                evidence: find_string_assignment(&body, "evidence").unwrap_or_default(),
            };
            if !(rule.id.is_empty()
                && rule.decision.is_empty()
                && rule.requirement.is_empty()
                && rule.evidence.is_empty())
            {
                rules.push(rule);
            }
        }
        offset = start + 3;
    }
    rules
}

fn validate_docs_text(
    api_readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    errors: &mut Vec<String>,
) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing evidence compliance dashboard endpoint",
    );
    expect(
        catalog_readme.contains("evidence-compliance-dashboard-contract.yaml"),
        errors,
        "catalog README missing evidence compliance dashboard catalog",
    );
    expect(
        doc_readme.contains("evidence-compliance-dashboard.md"),
        errors,
        "workflow README missing evidence compliance dashboard doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "evidence compliance dashboard doc missing endpoint",
    );
    expect(
        doc.contains("No live compliance evaluation"),
        errors,
        "evidence compliance dashboard doc must prohibit live compliance evaluation",
    );
    expect(
        doc.contains("No evidence, export, retention, or workflow mutation"),
        errors,
        "evidence compliance dashboard doc must prohibit mutation",
    );
    expect(
        doc.contains("No provider calls"),
        errors,
        "evidence compliance dashboard doc must prohibit provider calls",
    );
    expect(
        doc.contains("No notification dispatch"),
        errors,
        "evidence compliance dashboard doc must prohibit notification dispatch",
    );
    expect(
        doc.contains("raw evidence payloads"),
        errors,
        "evidence compliance dashboard doc must prohibit raw evidence payloads",
    );
    expect(
        doc.contains("raw control rows"),
        errors,
        "evidence compliance dashboard doc must prohibit raw control rows",
    );
    expect(
        doc.contains("raw audit logs"),
        errors,
        "evidence compliance dashboard doc must prohibit raw audit logs",
    );
    expect(
        doc.contains("raw user data"),
        errors,
        "evidence compliance dashboard doc must prohibit raw user data",
    );
    expect(
        doc.contains("tenant identifiers"),
        errors,
        "evidence compliance dashboard doc must prohibit tenant identifiers",
    );
    expect(
        doc.contains("static evidence compliance dashboard summaries only"),
        errors,
        "evidence compliance dashboard doc must require static summaries",
    );
}

fn required_domain_strings() -> Vec<String> {
    REQUIRED_COMPLIANCE_DOMAINS
        .iter()
        .map(|value| value.to_string())
        .collect()
}

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let needle = format!("app.MapGet(\"{ENDPOINT}\",");
    let mut offset = 0;
    let mut start = None;
    for line in uncommented_program.split_inclusive('\n') {
        if line.trim_start().starts_with(&needle) {
            start = Some(offset);
            break;
        }
        offset += line.len();
    }
    let Some(start) = start else {
        errors.push("API missing evidence compliance dashboard endpoint".to_string());
        return String::new();
    };
    let mut next = uncommented_program.len();
    let mut scan_offset = start + 1;
    for line in uncommented_program[start + 1..].split_inclusive('\n') {
        if line.trim_start().starts_with("app.MapGet(") {
            next = scan_offset;
            break;
        }
        scan_offset += line.len();
    }
    uncommented_program[start..next].to_string()
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let masked = strip_csharp_string_literals(program);
    let start = find_csharp_var_assignment(&masked, variable)?;
    let brace = program[start..].find('{')? + start;
    let (body, _) = balanced_brace_body(program, brace)?;
    Some(csharp_string_literals(&body))
}

fn find_csharp_var_assignment(source: &str, variable: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = 0;
    while let Some(relative) = source[index..].find("var") {
        let var_start = index + relative;
        let var_end = var_start + 3;
        if !identifier_boundary(bytes, var_start, var_end) {
            index = var_end;
            continue;
        }
        let Some(name_start) = next_non_whitespace(source, var_end) else {
            return None;
        };
        let Some((name, name_end)) = parse_identifier(source, name_start) else {
            index = var_end;
            continue;
        };
        if name != variable {
            index = name_end;
            continue;
        }
        let Some(eq_index) = next_non_whitespace(source, name_end) else {
            return None;
        };
        if bytes.get(eq_index) == Some(&b'=') && bytes.get(eq_index + 1) != Some(&b'=') {
            return Some(eq_index);
        }
        index = name_end;
    }
    None
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let needle = format!("{field} = new[]");
    let start = block.find(&needle)?;
    let brace = block[start..].find('{')? + start;
    let (body, _) = balanced_brace_body(block, brace)?;
    Some(csharp_string_literals(&body))
}

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    block.lines().any(|line| line.trim() == expected)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    block.lines().any(|line| line.trim() == expected)
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in assignment_fields(&strip_csharp_string_literals(block)) {
        if !endpoint_field_allowed(&field) {
            errors.push(format!(
                "API endpoint has unexpected evidence compliance dashboard field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited evidence compliance dashboard field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !SAFE_TRUE_FIELDS.contains(&field.as_str())
            && assignment_value_is_true(&stripped, &field)
            && unsafe_true_field(&field)
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited evidence compliance dashboard field"
                    ));
                }
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                scan_prohibited_text(text, path, errors);
            } else if !safe_text_value(text) {
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if prohibited_field(text) {
                    errors.push(format!(
                        "{path} contains prohibited evidence compliance dashboard value {text}"
                    ));
                }
            }
        }
        _ => {}
    }
}

fn scan_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn safe_text_value(value: &str) -> bool {
    [
        REQUIRED_COMPLIANCE_DOMAINS,
        REQUIRED_STATUS_BANDS,
        REQUIRED_GUARDS,
        REQUIRED_TREND_WINDOWS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        SAFE_TRUE_FIELDS,
        REQUIRED_DISABLED_FIELDS,
        CATALOG_BASE_KEYS,
        ENDPOINT_INLINE_ARRAYS,
    ]
    .iter()
    .any(|values| values.contains(&value))
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(field, variable)| value == *field || value == *variable)
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
        || matches!(
            value,
            "draft"
                | "static-seed"
                | "static-evidence-compliance-dashboard"
                | "block"
                | "true"
                | "false"
        )
}

fn prohibited_field(value: &str) -> bool {
    if safe_text_value(value) {
        return false;
    }
    let normalized: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || PROHIBITED_FIELD_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn prohibited_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    (lower.contains("-----begin ") && lower.contains("private key-----"))
        || contains_aws_access_key(value)
        || contains_url_scheme(value)
        || contains_private_ipv4(value)
        || contains_guid(value)
        || contains_vault_token(value)
        || contains_email(value)
        || contains_sensitive_assignment(value)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn catalog_key_allowed(key: &str) -> bool {
    CATALOG_BASE_KEYS.contains(&key)
        || SAFE_TRUE_FIELDS.contains(&key)
        || REQUIRED_DISABLED_FIELDS.contains(&key)
}

fn endpoint_field_allowed(field: &str) -> bool {
    ENDPOINT_BASE_FIELDS.contains(&field)
        || SAFE_TRUE_FIELDS.contains(&field)
        || REQUIRED_DISABLED_FIELDS.contains(&field)
}

fn unsafe_true_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    [
        "live",
        "provider",
        "worker",
        "workflow",
        "raw",
        "credential",
        "token",
        "tenant",
        "object",
        "principal",
        "user",
        "private",
        "mutation",
        "notification",
        "compliance",
        "evidence",
        "export",
        "retention",
        "retry",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn string_array(value: Option<&Value>, field: &str, errors: &mut Vec<String>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        errors.push(format!("{field} must be an array"));
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let text = item.as_str();
            if text.is_none() {
                errors.push(format!("{field} values must be strings"));
            }
            text.map(ToString::to_string)
        })
        .collect()
}

fn value_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

fn expect_unique_rule_details(rules: &[Rule], errors: &mut Vec<String>, message: &str) {
    let seen: BTreeSet<(&str, &str, &str)> = rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect();
    expect(seen.len() == rules.len(), errors, message);
}

fn assignment_fields(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut fields = Vec::new();
    for index in 0..bytes.len() {
        if bytes[index] == b'=' {
            let mut end = index;
            while end > 0 && bytes[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
            let mut start = end;
            while start > 0
                && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_')
            {
                start -= 1;
            }
            if start < end && bytes[start].is_ascii_alphabetic() {
                fields.push(source[start..end].to_string());
            }
        }
    }
    fields
}

fn assignment_value_is_true(source: &str, field: &str) -> bool {
    source.contains(&format!("{field} = true"))
}

fn find_string_assignment(body: &str, field: &str) -> Option<String> {
    let needle = format!("{field} = ");
    let start = body.find(&needle)? + needle.len();
    let rest = body[start..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    parse_csharp_string_at(rest, 0).map(|(value, _)| value)
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < text.len() {
        if text.as_bytes()[index] == b'"' {
            if let Some((value, end)) = parse_csharp_string_at(text, index) {
                values.push(value);
                index = end;
            }
        }
        index += 1;
    }
    values
}

fn parse_csharp_string_at(text: &str, quote: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let mut value = String::new();
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate().skip(quote + 1) {
        if escaped {
            value.push(*byte as char);
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            return Some((value, index));
        } else {
            value.push(*byte as char);
        }
    }
    None
}

fn balanced_brace_body(text: &str, open_brace: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(open_brace) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate().skip(open_brace) {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
        } else if *byte == b'"' {
            in_string = true;
        } else if *byte == b'{' {
            depth += 1;
        } else if *byte == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some((text[open_brace + 1..index].to_string(), index));
            }
        }
    }
    None
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_comment = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if line_comment {
            if byte == b'\n' {
                line_comment = false;
                out.push('\n');
            } else {
                out.push(' ');
            }
        } else if block_comment {
            if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                out.push_str("  ");
                index += 1;
                block_comment = false;
            } else if byte == b'\n' {
                out.push('\n');
            } else {
                out.push(' ');
            }
        } else if in_string {
            out.push(byte as char);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
            out.push('"');
        } else if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            out.push_str("  ");
            index += 1;
            line_comment = true;
        } else if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            out.push_str("  ");
            index += 1;
            block_comment = true;
        } else {
            out.push(byte as char);
        }
        index += 1;
    }
    out
}

fn strip_csharp_string_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
                out.push(' ');
            } else if *byte == b'\\' {
                escaped = true;
                out.push(' ');
            } else if *byte == b'"' {
                in_string = false;
                out.push('"');
            } else if *byte == b'\n' {
                out.push('\n');
            } else {
                out.push(' ');
            }
        } else if *byte == b'"' {
            in_string = true;
            out.push('"');
        } else {
            out.push(*byte as char);
        }
    }
    out
}

fn contains_aws_access_key(value: &str) -> bool {
    value.as_bytes().windows(20).any(|window| {
        window[0..4].eq_ignore_ascii_case(b"AKIA")
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn contains_url_scheme(value: &str) -> bool {
    let bytes = value.as_bytes();
    for index in 0..bytes.len().saturating_sub(2) {
        if &bytes[index..index + 3] == b"://" {
            let mut start = index;
            while start > 0
                && (bytes[start - 1].is_ascii_alphanumeric()
                    || matches!(bytes[start - 1], b'+' | b'.' | b'-'))
            {
                start -= 1;
            }
            if start < index && bytes[start].is_ascii_alphabetic() {
                return true;
            }
        }
    }
    false
}

fn contains_private_ipv4(value: &str) -> bool {
    for token in value.split(|c: char| !c.is_ascii_digit() && c != '.') {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            continue;
        }
        let octets: Option<Vec<u8>> = parts.iter().map(|part| part.parse::<u8>().ok()).collect();
        if let Some(octets) = octets {
            if octets[0] == 10
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            {
                return true;
            }
        }
    }
    false
}

fn contains_guid(value: &str) -> bool {
    value
        .split(|c: char| !c.is_ascii_hexdigit() && c != '-')
        .any(|token| {
            token.len() == 36
                && [8, 13, 18, 23]
                    .iter()
                    .all(|index| token.as_bytes().get(*index) == Some(&b'-'))
                && token
                    .chars()
                    .enumerate()
                    .all(|(index, c)| [8, 13, 18, 23].contains(&index) || c.is_ascii_hexdigit())
        })
}

fn contains_vault_token(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        ["hvs.", "hvb.", "s."]
            .iter()
            .any(|prefix| token.to_ascii_lowercase().starts_with(prefix))
            && token.len() >= 18
    })
}

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let trimmed = token.trim_matches(|c: char| {
            matches!(
                c,
                ',' | ';' | ':' | '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>' | '.' | '!' | '?'
            )
        });
        let Some((local, domain)) = trimmed.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && local
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-'))
            && domain
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
            && domain
                .rsplit('.')
                .next()
                .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic()))
    })
}

fn contains_sensitive_assignment(text: &str) -> bool {
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':').or_else(|| line.split_once('=')) else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        let normalized = normalize_assignment_key(key);
        if sensitive_assignment_key(&normalized) {
            return true;
        }
    }
    false
}

fn sensitive_assignment_key(normalized: &str) -> bool {
    SECRET_ASSIGNMENT_KEYS.iter().any(|needle| {
        normalized == *needle
            || normalized.ends_with(&format!("_{needle}"))
            || normalized.starts_with(&format!("{needle}_"))
            || normalized.contains(&format!("_{needle}_"))
    })
}

fn normalize_assignment_key(key: &str) -> String {
    key.trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        .map(|ch| {
            if matches!(ch, '-' | '.') {
                '_'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect()
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn identifier_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    (start == 0 || !is_word_byte(bytes[start - 1]))
        && (end >= bytes.len() || !is_word_byte(bytes[end]))
}

fn next_non_whitespace(source: &str, offset: usize) -> Option<usize> {
    source[offset..]
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(index, _)| offset + index)
}

fn parse_identifier(source: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    if !bytes
        .get(start)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    let mut end = start + 1;
    while end < bytes.len() && is_word_byte(bytes[end]) {
        end += 1;
    }
    Some((&source[start..end], end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program_errors(program: &str) -> Vec<String> {
        let catalog = serde_json::json!({});
        let mut errors = Vec::new();
        validate_program_text(program, &catalog, &mut errors);
        errors
    }

    #[test]
    fn comments_do_not_satisfy_endpoint_assignment() {
        let program = format!("app.MapGet(\"{ENDPOINT}\", () => Results.Json(new\n{{\n    // evidenceComplianceDashboardMode = \"static-evidence-compliance-dashboard\",\n    evidenceComplianceDashboardMode = \"live-evidence-compliance-dashboard\",\n}}));");
        let mut errors = Vec::new();
        let block = endpoint_block(&csharp_without_comments(&program), &mut errors);
        assert!(!exact_string_assignment(
            &block,
            "evidenceComplianceDashboardMode",
            "static-evidence-compliance-dashboard"
        ));
    }

    #[test]
    fn endpoint_field_scan_sees_identifiers_not_string_values() {
        let mut errors = Vec::new();
        validate_endpoint_field_names("rawControlRows = \"safe-summary\",", &mut errors);
        assert!(errors.iter().any(|error| error.contains("rawControlRows")));
    }

    #[test]
    fn prohibited_literal_scan_rejects_synthetic_values() {
        assert!(prohibited_value("token = unsafe-value"));
        assert!(prohibited_value("token_value = unsafe-value"));
        assert!(prohibited_value("credential: unsafe-value"));
        assert!(prohibited_value(
            "https://evidence-compliance-dashboard.invalid/run"
        ));
        assert!(prohibited_value("00000000-0000-0000-0000-000000000000"));
        assert!(prohibited_value("compliance.user@example.invalid."));
        assert!(prohibited_value("10.91.91.91"));
    }

    #[test]
    fn source_assignment_spoofing_is_rejected_by_program_validator() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new\n{{\n    // source = \"static-seed\",\n    source = \"static\" + \"-seed\",\n}}));"
        );
        let errors = program_errors(&program);
        assert!(errors
            .iter()
            .any(|error| error.contains("static-seed source")));
    }

    #[test]
    fn unsafe_allowed_suffix_field_is_rejected_by_program_validator() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new\n{{\n    providerCallsAllowed = false,\n    providerCallsAllowedBypass = true,\n}}));"
        );
        let errors = program_errors(&program);
        assert!(errors
            .iter()
            .any(|error| error.contains("providerCallsAllowedBypass")));
    }

    #[test]
    fn endpoint_array_transform_is_rejected_by_program_validator() {
        let program = format!(
            "var evidenceComplianceDashboardDomains = new[] {{ \"security-baseline\" }};\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new\n{{\n    complianceDomains = evidenceComplianceDashboardDomains.Concat(new[] {{ \"unsafe-domain\" }}),\n}}));"
        );
        let errors = program_errors(&program);
        assert!(errors
            .iter()
            .any(|error| error.contains("complianceDomains")));
    }

    #[test]
    fn mapget_string_value_decoy_does_not_truncate_endpoint_block() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new\n{{\n    decoy = \".MapGet(\\\"{ENDPOINT}\\\")\",\n    rawControlRowsAllowedBypass = true,\n}}));\napp.MapGet(\"/api/next\", () => Results.Ok());"
        );
        let errors = program_errors(&program);
        assert!(errors
            .iter()
            .any(|error| error.contains("rawControlRowsAllowedBypass")));
    }

    #[test]
    fn csharp_array_lookup_uses_exact_identifier() {
        let program = r#"
var evidenceComplianceDashboardRequiredGuardsShadow = new[] { "control-scope-known" };
var evidenceComplianceDashboardRequiredGuards = new[] { "unsafe-guard" };
"#;
        assert_eq!(
            csharp_array_values(program, "evidenceComplianceDashboardRequiredGuards"),
            Some(vec!["unsafe-guard".to_string()])
        );
    }
}
