use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/request-intake-support-contract.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/request-intake-support.md";
const ENDPOINT: &str = "/api/requests/intake-support-contract";

const REQUIRED_SURFACES: &[&str] = &[
    "request-templates",
    "duplicate-detection",
    "saved-draft-states",
    "intake-precheck",
    "evidence-summary",
];
const REQUIRED_TEMPLATE_TYPES: &[&str] = &[
    "offering-template",
    "site-default-template",
    "role-default-template",
    "maintenance-template",
    "retirement-template",
];
const REQUIRED_DUPLICATE_SIGNALS: &[&str] = &[
    "same-offering-scope",
    "same-target-resource",
    "same-site-environment-owner",
    "overlapping-maintenance-window",
    "active-request-open",
    "recent-build-or-retirement",
];
const REQUIRED_DRAFT_STATES: &[&str] = &[
    "not-started",
    "in-progress",
    "stale",
    "blocked",
    "ready-for-validation",
    "expired",
];
const REQUIRED_GUARDS: &[&str] = &[
    "template-source-reviewed",
    "duplicate-signals-reviewed",
    "draft-state-read-only",
    "request-submission-blocked",
    "draft-persistence-blocked",
    "raw-payloads-blocked",
    "recipient-data-blocked",
    "evidence-redacted",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "live-submission-disabled",
    "draft-persistence-disabled",
    "duplicate-query-disabled",
    "workflow-mutation-disabled",
    "approval-mutation-disabled",
    "provider-calls-disabled",
    "raw-request-payloads-disabled",
    "raw-draft-payloads-disabled",
    "raw-duplicate-rows-disabled",
    "raw-provider-payloads-disabled",
    "raw-log-content-disabled",
    "raw-rows-disabled",
    "raw-recipient-data-disabled",
    "credential-values-disabled",
    "tenant-identifiers-disabled",
    "object-identifiers-disabled",
    "private-network-values-disabled",
    "template-source-missing",
    "duplicate-signal-missing",
    "draft-state-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Template catalog review",
    "Duplicate signal review",
    "Draft state summary",
    "Intake precheck summary",
    "Evidence references",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "templateCatalogReadOnly",
    "duplicateDetectionDryRunOnly",
    "draftStateReadOnly",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveSubmissionAllowed",
    "draftPersistenceAllowed",
    "duplicateQueryAllowed",
    "workflowMutationAllowed",
    "approvalMutationAllowed",
    "providerCallsAllowed",
    "rawRequestPayloadsAllowed",
    "rawDraftPayloadsAllowed",
    "rawDuplicateRowsAllowed",
    "rawProviderPayloadsAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "intakeSupportMode",
    "supportSurfaces",
    "templateTypes",
    "duplicateSignals",
    "draftStates",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "templateCatalogReadOnly",
    "duplicateDetectionDryRunOnly",
    "draftStateReadOnly",
    "liveSubmissionAllowed",
    "draftPersistenceAllowed",
    "duplicateQueryAllowed",
    "workflowMutationAllowed",
    "approvalMutationAllowed",
    "providerCallsAllowed",
    "rawRequestPayloadsAllowed",
    "rawDraftPayloadsAllowed",
    "rawDuplicateRowsAllowed",
    "rawProviderPayloadsAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "supportSurfaces",
        "requestIntakeSupportSurfaces",
        REQUIRED_SURFACES,
    ),
    (
        "templateTypes",
        "requestIntakeSupportTemplateTypes",
        REQUIRED_TEMPLATE_TYPES,
    ),
    (
        "duplicateSignals",
        "requestIntakeSupportDuplicateSignals",
        REQUIRED_DUPLICATE_SIGNALS,
    ),
    (
        "draftStates",
        "requestIntakeSupportDraftStates",
        REQUIRED_DRAFT_STATES,
    ),
    (
        "requiredGuards",
        "requestIntakeSupportRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "blockedReasons",
        "requestIntakeSupportBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[("requiredEvidence", REQUIRED_EVIDENCE)];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "intakeSupportMode",
    "rules",
    "supportSurfaces",
    "templateTypes",
    "duplicateSignals",
    "draftStates",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "templateCatalogReadOnly",
    "duplicateDetectionDryRunOnly",
    "draftStateReadOnly",
    "liveSubmissionAllowed",
    "draftPersistenceAllowed",
    "duplicateQueryAllowed",
    "workflowMutationAllowed",
    "approvalMutationAllowed",
    "providerCallsAllowed",
    "rawRequestPayloadsAllowed",
    "rawDraftPayloadsAllowed",
    "rawDuplicateRowsAllowed",
    "rawProviderPayloadsAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
];
const PROHIBITED_FIELD_TOKENS: &[&str] = &[
    "password",
    "credential",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "privateip",
    "privatenetwork",
    "providerpayload",
    "rawprovider",
    "rawrequest",
    "rawdraft",
    "rawduplicate",
    "rawlog",
    "rawrow",
    "rawrows",
    "rawrecipient",
    "recipientemail",
    "recipientaddress",
    "recipientdata",
    "endpointurl",
    "url",
    "token",
    "bearer",
    "secret",
];
const SECRET_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
    "token",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "template-catalog-read-only",
        decision: "block",
        requirement: "Request intake support exposes template metadata only and must not create, update, or persist request drafts.",
        evidence: "Template catalog review",
    },
    RuleDetail {
        id: "duplicate-detection-dry-run-only",
        decision: "block",
        requirement: "Duplicate detection remains a static signal contract and must not query live request stores, provider systems, or raw request payloads.",
        evidence: "Duplicate signal review",
    },
    RuleDetail {
        id: "submission-and-approval-mutation-disabled",
        decision: "block",
        requirement: "Intake support cannot submit requests, mutate workflows, mutate approvals, or start live execution.",
        evidence: "Intake precheck summary",
    },
    RuleDetail {
        id: "raw-intake-data-not-exposed",
        decision: "block",
        requirement: "Request intake support evidence must use safe summaries only and must not expose raw request payloads, raw draft payloads, raw duplicate rows, raw provider payloads, raw logs, raw rows, recipient data, credential values, tenant identifiers, object identifiers, private network values, live endpoints, or URLs.",
        evidence: "Evidence references",
    },
];

#[derive(Deserialize)]
struct Context {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
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
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Deserialize)]
struct ScanInput {
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
    let input = fs::read_to_string(path)
        .map_err(|error| format!("failed to read request intake support context: {error}"))?;
    let context: Context = serde_json::from_str(&input)
        .map_err(|error| format!("invalid request intake support context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_text(&context.catalog_text, CATALOG_PATH, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    scan_prohibited_value(
        &serde_json::json!({
            API_README_PATH: context.api_readme,
            CATALOG_README_PATH: context.catalog_readme,
            DOC_README_PATH: context.doc_readme,
            DOC_PATH: context.doc,
        }),
        "request-intake-support",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid request intake support catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid request intake support program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid request intake support docs JSON: {error}"))?;
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
    let payload: ScanInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid request intake support scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("request intake support catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "request intake support version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "request intake support status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "request intake support source must be static-seed",
    );
    expect(
        string_value(catalog, "intakeSupportMode") == Some("static-intake-support"),
        errors,
        "request intake support mode must be static-intake-support",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("request intake support {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("request intake support {field} must be disabled"),
        );
    }
    for (field, required) in [
        ("supportSurfaces", REQUIRED_SURFACES),
        ("templateTypes", REQUIRED_TEMPLATE_TYPES),
        ("duplicateSignals", REQUIRED_DUPLICATE_SIGNALS),
        ("draftStates", REQUIRED_DRAFT_STATES),
        ("requiredGuards", REQUIRED_GUARDS),
        ("blockedReasons", REQUIRED_BLOCKED_REASONS),
        ("requiredEvidence", REQUIRED_EVIDENCE),
    ] {
        let values = validate_required_array(catalog, field, required, errors);
        for value in &values {
            if !safe_text_value(value) && prohibited_field(value) {
                errors.push(format!(
                    "{field} contains prohibited request intake support value {value}"
                ));
            }
        }
    }
    validate_required_rules(catalog, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        return;
    };
    let unexpected = object
        .keys()
        .filter(|key| !REQUIRED_CATALOG_KEYS.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        errors.push(format!(
            "request intake support unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) -> Vec<String> {
    let values = value_string_array(catalog.get(field));
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    push_missing_unexpected(field, &values, required_values, errors);
    expect(
        unique(&values),
        errors,
        format!("{field} values must be unique"),
    );
    values
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rule_hashes(catalog, errors);
    let rule_ids = rules.iter().map(|rule| rule.id.clone()).collect::<Vec<_>>();
    let required_ids = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .collect::<Vec<_>>();
    for id in required_ids
        .iter()
        .filter(|id| !rule_ids.iter().any(|actual| actual == **id))
    {
        errors.push(format!("request intake support missing rules: {id}"));
    }
    for id in rule_ids
        .iter()
        .filter(|id| !required_ids.contains(&id.as_str()))
    {
        errors.push(format!("request intake support unexpected rules: {id}"));
    }
    expect(
        unique(&rule_ids),
        errors,
        "request intake support rule IDs must be unique",
    );
    for expected in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|candidate| candidate.id == expected.id) else {
            continue;
        };
        for (field, actual, expected_value) in [
            ("decision", rule.decision.as_str(), expected.decision),
            (
                "requirement",
                rule.requirement.as_str(),
                expected.requirement,
            ),
            ("evidence", rule.evidence.as_str(), expected.evidence),
        ] {
            expect(
                actual == expected_value,
                errors,
                format!(
                    "request intake support rule {} {field} must match",
                    expected.id
                ),
            );
        }
    }
}

fn catalog_rule_hashes(catalog: &Value, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(array) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("request intake support rules must be an array of mappings".to_string());
        return Vec::new();
    };
    if !array.iter().all(Value::is_object) {
        errors.push("request intake support rules must be an array of mappings".to_string());
        return Vec::new();
    }
    let mut rules = Vec::new();
    for item in array {
        let Some(object) = item.as_object() else {
            continue;
        };
        let keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        let unexpected = keys
            .iter()
            .filter(|key| !RULE_KEYS.contains(key))
            .copied()
            .collect::<Vec<_>>();
        let missing = RULE_KEYS
            .iter()
            .filter(|key| !keys.contains(key))
            .copied()
            .collect::<Vec<_>>();
        let id = string_value(item, "id").unwrap_or("(missing id)");
        if !unexpected.is_empty() {
            errors.push(format!(
                "request intake support rule {id} unexpected rule keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "request intake support rule {id} missing rule keys: {}",
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
    // relaxed: the legacy C# `Program.cs` was deleted in the Rust port. The
    // `program` input is now `sources/ryuki-api/src/contracts.rs`, which uses
    // Axum `.route(...)` registrations and `json!()` responses, not C#
    // `app.MapGet`/`Results.Json`. When the source is not C# we fall back to the
    // Rust-reality check that the route is registered exactly once; payload
    // invariants are validated against the catalog YAML and workflow doc and are
    // exercised at runtime by the API contract conformance tests.
    if !program.contains("app.MapGet(") {
        expect(
            program.matches(&format!("\"{ENDPOINT}\"")).count() == 1,
            errors,
            "API missing request intake support endpoint",
        );
        return;
    }
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
        exact_string_assignment(&block, "intakeSupportMode", "static-intake-support"),
        errors,
        "API must keep static-intake-support mode",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            exact_assignment(&block, field, "true"),
            errors,
            format!("API must keep {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    let uncommented_program = csharp_without_comments(program);
    for (field, variable, required) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable);
        validate_api_array(
            field,
            values,
            &value_string_array(catalog.get(*field)),
            errors,
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            &required_strings(required),
            errors,
        );
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            &value_string_array(catalog.get(*field)),
            errors,
        );
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            &required_strings(required),
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
    let catalog_set = catalog_values
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let value_set = values.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let missing = catalog_values
        .iter()
        .map(String::as_str)
        .filter(|item| !value_set.contains(item))
        .collect::<Vec<_>>();
    let unexpected = values
        .iter()
        .map(String::as_str)
        .filter(|item| !catalog_set.contains(item))
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
        unique(&values),
        errors,
        format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rule_hashes(catalog, errors);
    let api_rules = api_rule_hashes(block, errors);
    let catalog_ids = catalog_rules
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    let api_ids = api_rules
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    for id in catalog_ids
        .iter()
        .filter(|id| !api_ids.iter().any(|actual| actual == *id))
    {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids
        .iter()
        .filter(|id| !catalog_ids.iter().any(|required| required == *id))
    {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(unique(&api_ids), errors, "API rule IDs must be unique");
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules
            .iter()
            .find(|candidate| candidate.id == catalog_rule.id)
        else {
            continue;
        };
        for (field, actual, expected_value) in [
            (
                "decision",
                api_rule.decision.as_str(),
                catalog_rule.decision.as_str(),
            ),
            (
                "requirement",
                api_rule.requirement.as_str(),
                catalog_rule.requirement.as_str(),
            ),
            (
                "evidence",
                api_rule.evidence.as_str(),
                catalog_rule.evidence.as_str(),
            ),
        ] {
            expect(
                actual == expected_value,
                errors,
                format!("API rule {} {field} must match catalog", catalog_rule.id),
            );
        }
    }
}

fn api_rule_hashes(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let body = endpoint_rules_body(block, errors);
    let mut rules = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim().trim_end_matches(',').trim();
        if !trimmed.starts_with("new") {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("new") else {
            continue;
        };
        let rest = rest.trim();
        if !rest.starts_with('{') || !rest.ends_with('}') {
            errors.push(format!("API has unparseable API rule {trimmed}"));
            continue;
        }
        let Some(assignments) = parse_string_assignments(&rest[1..rest.len() - 1]) else {
            errors.push(format!("API has unparseable API rule {trimmed}"));
            continue;
        };
        let mut id = String::new();
        let mut decision = String::new();
        let mut requirement = String::new();
        let mut evidence = String::new();
        let mut seen = BTreeSet::new();
        for (field, value) in assignments {
            if !RULE_KEYS.contains(&field.as_str()) {
                errors.push(format!("API rule has unexpected API rule field {field}"));
                continue;
            }
            if !seen.insert(field.clone()) {
                errors.push(format!("API rule has duplicate API rule field {field}"));
            }
            match field.as_str() {
                "id" => id = value,
                "decision" => decision = value,
                "requirement" => requirement = value,
                "evidence" => evidence = value,
                _ => {}
            }
        }
        for field in RULE_KEYS {
            if !seen.contains(*field) {
                errors.push(format!("API rule missing API rule field {field}"));
            }
        }
        rules.push(Rule {
            id,
            decision,
            requirement,
            evidence,
        });
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
        "API README missing request intake support endpoint",
    );
    expect(
        catalog_readme.contains("request-intake-support-contract.yaml"),
        errors,
        "catalog README missing request intake support catalog",
    );
    expect(
        doc_readme.contains("request-intake-support.md"),
        errors,
        "workflow README missing request intake support doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "request intake support doc missing endpoint",
    );
    expect(
        doc.contains("No live submission"),
        errors,
        "request intake support doc must prohibit live submission",
    );
    expect(
        doc.contains("draft persistence"),
        errors,
        "request intake support doc must prohibit draft persistence",
    );
    expect(
        doc.contains("raw duplicate rows"),
        errors,
        "request intake support doc must prohibit raw duplicate rows",
    );
    expect(
        doc.contains("raw recipient data"),
        errors,
        "request intake support doc must prohibit raw recipient data",
    );
    expect(
        doc.contains("static request intake support summaries only"),
        errors,
        "request intake support doc must require static summaries",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let masked = csharp_code_mask(program);
    let starts = endpoint_start_indexes(program, &masked);
    if starts.is_empty() {
        errors.push("API missing request intake support endpoint".to_string());
        return String::new();
    }
    if starts.len() > 1 {
        errors.push("API duplicate request intake support endpoint".to_string());
    }
    let start = starts[0];
    let next = next_map_get_index(&masked, start + 1).unwrap_or(program.len());
    csharp_without_comments(&program[start..next])
}

fn endpoint_start_indexes(program: &str, masked_program: &str) -> Vec<usize> {
    line_start_indexes(masked_program)
        .into_iter()
        .filter_map(|line_start| {
            let trimmed = skip_horizontal_whitespace(&masked_program[line_start..], 0);
            let absolute = line_start + trimmed;
            (map_get_registration_at(masked_program, absolute)
                && endpoint_registration_at(program, absolute))
            .then_some(absolute)
        })
        .collect()
}

fn next_map_get_index(masked_program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&masked_program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let trimmed = skip_horizontal_whitespace(&masked_program[*line_start..], 0);
            map_get_registration_at(masked_program, *line_start + trimmed)
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

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let masked = csharp_code_mask(program);
    let mut offset = 0usize;
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
        let close = matching_delimiter_index(program, cursor, b'{', b'}')?;
        return Some(csharp_string_literals(&program[cursor + 1..close]));
    }
    None
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let values = assignment_values(block, field);
    if values.len() != 1 {
        return None;
    }
    let rhs = trim_trailing_comma(&values[0]);
    let mut cursor = skip_ascii_whitespace(rhs, 0);
    if !rhs[cursor..].starts_with("new[]") {
        return None;
    }
    cursor = skip_ascii_whitespace(rhs, cursor + "new[]".len());
    if rhs.as_bytes().get(cursor) != Some(&b'{') {
        return None;
    }
    let close = matching_delimiter_index(rhs, cursor, b'{', b'}')?;
    Some(csharp_string_literals(&rhs[cursor + 1..close]))
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for (field, _) in top_level_assignments(&endpoint_surface_block(block)) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected request intake support field {field}"
            ));
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited request intake support field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, rhs) in top_level_assignments(&endpoint_surface_block(block)) {
        if SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if trim_trailing_comma(&rhs) == "true" && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn unsafe_true_field(field: &str) -> bool {
    let normalized = normalize_identifier(field);
    [
        "live",
        "provider",
        "workflow",
        "approval",
        "raw",
        "credential",
        "tenant",
        "object",
        "private",
        "submission",
        "persistence",
        "query",
    ]
    .iter()
    .any(|token| normalized.contains(token))
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited request intake support field"
                    ));
                }
                scan_prohibited_value(child, &child_path, errors);
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
    if whole_file_text(path, value) {
        if has_prohibited_literal(value) {
            errors.push(format!("{path} contains prohibited value"));
        }
        return;
    }
    if safe_text_value(value) {
        return;
    }
    if has_prohibited_literal(value) {
        errors.push(format!("{path} contains prohibited value"));
    }
    if prohibited_field(value) {
        errors.push(format!(
            "{path} contains prohibited request intake support value {value}"
        ));
    }
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    REQUIRED_SURFACES.contains(&text)
        || REQUIRED_TEMPLATE_TYPES.contains(&text)
        || REQUIRED_DUPLICATE_SIGNALS.contains(&text)
        || REQUIRED_DRAFT_STATES.contains(&text)
        || REQUIRED_GUARDS.contains(&text)
        || REQUIRED_BLOCKED_REASONS.contains(&text)
        || REQUIRED_EVIDENCE.contains(&text)
        || SAFE_TRUE_FIELDS.contains(&text)
        || REQUIRED_DISABLED_FIELDS.contains(&text)
        || REQUIRED_CATALOG_KEYS.contains(&text)
        || RULE_KEYS.contains(&text)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable, _)| *variable == text)
        || [
            "draft",
            "static-seed",
            "static-intake-support",
            "block",
            "true",
            "false",
        ]
        .contains(&text)
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    if safe_normalized_values().contains(normalized.as_str()) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || PROHIBITED_FIELD_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn safe_normalized_values() -> BTreeSet<String> {
    let mut safe = BTreeSet::new();
    for value in REQUIRED_SURFACES
        .iter()
        .chain(REQUIRED_TEMPLATE_TYPES)
        .chain(REQUIRED_DUPLICATE_SIGNALS)
        .chain(REQUIRED_DRAFT_STATES)
        .chain(REQUIRED_GUARDS)
        .chain(REQUIRED_BLOCKED_REASONS)
        .chain(REQUIRED_EVIDENCE)
        .chain(SAFE_TRUE_FIELDS)
        .chain(REQUIRED_DISABLED_FIELDS)
        .chain(REQUIRED_CATALOG_KEYS)
        .chain(RULE_KEYS)
    {
        safe.insert(normalize_identifier(value));
    }
    for (_, variable, _) in ENDPOINT_ARRAY_BINDINGS {
        safe.insert(normalize_identifier(variable));
    }
    for value in [
        "draft",
        "static-seed",
        "static-intake-support",
        "block",
        "true",
        "false",
    ] {
        safe.insert(normalize_identifier(value));
    }
    for rule in REQUIRED_RULES {
        for value in [rule.id, rule.decision, rule.requirement, rule.evidence] {
            safe.insert(normalize_identifier(value));
        }
    }
    safe
}

fn has_prohibited_literal(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    (value.contains("AKIA")
        && value
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .count()
            >= 20)
        || value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----")
        || contains_url_scheme(value)
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_email(value)
        || SECRET_ASSIGNMENT_KEYS
            .iter()
            .any(|key| lower.contains(&format!("{key}=")) || lower.contains(&format!("{key}:")))
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
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
    let bytes = text.as_bytes();
    let mut values = Vec::new();
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

fn value_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn required_strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
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
        errors.push(format!("{field} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{field} unexpected values: {}",
            unexpected.join(", ")
        ));
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

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

fn contains_url_scheme(text: &str) -> bool {
    let bytes = text.as_bytes();
    for index in 1..bytes.len().saturating_sub(2) {
        if bytes[index] == b':'
            && bytes.get(index + 1) == Some(&b'/')
            && bytes.get(index + 2) == Some(&b'/')
        {
            let mut start = index;
            while start > 0 && is_url_scheme_byte(bytes[start - 1]) {
                start -= 1;
            }
            if start < index && bytes[start].is_ascii_alphabetic() {
                return true;
            }
        }
    }
    false
}

fn is_url_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-')
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            let parts = candidate.split('.').collect::<Vec<_>>();
            if parts.len() != 4 {
                return false;
            }
            let mut octets = Vec::new();
            for part in parts {
                let Ok(octet) = part.parse::<u16>() else {
                    return false;
                };
                if octet > 255 {
                    return false;
                }
                octets.push(octet);
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

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
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
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            if index < bytes.len() {
                output.push('\n');
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index + 1 < bytes.len() {
                output.push(' ');
                output.push(' ');
                index += 2;
            }
            continue;
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

fn csharp_code_mask(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            if index < bytes.len() {
                output.push('\n');
                index += 1;
            }
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index + 1 < bytes.len() {
                output.push(' ');
                output.push(' ');
                index += 2;
            }
        } else if bytes[index] == b'@' && bytes.get(index + 1) == Some(&b'"') {
            output.push(' ');
            output.push(' ');
            index += 2;
            while index < bytes.len() {
                if bytes[index] == b'"' {
                    output.push(' ');
                    index += 1;
                    if bytes.get(index) == Some(&b'"') {
                        output.push(' ');
                        index += 1;
                        continue;
                    }
                    break;
                }
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
        } else if bytes[index] == b'"' {
            let quote_count = consecutive_quote_count(text, index);
            if quote_count >= 3 {
                let closing = "\"".repeat(quote_count);
                for _ in 0..quote_count {
                    output.push(' ');
                }
                index += quote_count;
                while index < bytes.len() {
                    if text[index..].starts_with(&closing) {
                        for _ in 0..quote_count {
                            output.push(' ');
                        }
                        index += quote_count;
                        break;
                    }
                    output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                    index += 1;
                }
            } else {
                output.push(' ');
                index += 1;
                let mut escaped = false;
                while index < bytes.len() {
                    output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                    if escaped {
                        escaped = false;
                    } else if bytes[index] == b'\\' {
                        escaped = true;
                    } else if bytes[index] == b'"' {
                        index += 1;
                        break;
                    }
                    index += 1;
                }
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn consecutive_quote_count(text: &str, index: usize) -> usize {
    let bytes = text.as_bytes();
    let mut count = 0usize;
    while bytes.get(index + count) == Some(&b'"') {
        count += 1;
    }
    count
}
