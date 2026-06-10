use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/request-form-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/request-form-contract.md";
const ENDPOINT: &str = "/api/catalog/request-form-contract";
const REQUIRED_FORM_SECTIONS: &[&str] = &[
    "requester-context",
    "scope-context",
    "business-context",
    "technical-plan",
    "protection-observe-cmdb",
    "evidence-approval",
];
const REQUIRED_INPUT_KINDS: &[&str] = &[
    "text",
    "textarea",
    "select",
    "multi-select",
    "reference-summary",
    "policy-reference",
    "schedule-summary",
    "evidence-reference",
];
const SAFE_TRUE_FIELDS: &[&str] = &["formSchemaReadOnly", "schemaDerivedFromOfferings"];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveRequestCreationAllowed",
    "formSubmissionAllowed",
    "approvalExecutionAllowed",
    "workflowMutationAllowed",
    "providerCallsAllowed",
    "rawRequestPayloadsAllowed",
    "rawFormSubmissionsAllowed",
    "rawProviderPayloadsAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "live-request-creation-disabled",
    "form-submission-disabled",
    "approval-execution-disabled",
    "workflow-mutation-disabled",
    "provider-calls-disabled",
    "raw-request-payloads-disabled",
    "raw-form-submissions-disabled",
    "raw-provider-payloads-disabled",
    "raw-log-content-disabled",
    "raw-rows-disabled",
    "raw-recipient-data-disabled",
    "credential-values-disabled",
    "tenant-identifiers-disabled",
    "object-identifiers-disabled",
    "private-network-values-disabled",
    "required-input-missing",
    "offering-catalog-drift",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Form schema review",
    "Offering input coverage review",
    "Static schema boundary",
    "Dry-run policy review",
    "Evidence references",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "formMode",
    "formSchemaReadOnly",
    "schemaDerivedFromOfferings",
    "formSections",
    "inputKinds",
    "requiredInputNames",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "liveRequestCreationAllowed",
    "formSubmissionAllowed",
    "approvalExecutionAllowed",
    "workflowMutationAllowed",
    "providerCallsAllowed",
    "rawRequestPayloadsAllowed",
    "rawFormSubmissionsAllowed",
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
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("formSections", "requestFormSections"),
    ("inputKinds", "requestFormInputKinds"),
    ("requiredInputNames", "requestFormRequiredInputNames"),
    ("offeringForms", "requestFormOfferings"),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "formMode",
    "formSchemaReadOnly",
    "schemaDerivedFromOfferings",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "liveRequestCreationAllowed",
    "formSubmissionAllowed",
    "approvalExecutionAllowed",
    "workflowMutationAllowed",
    "providerCallsAllowed",
    "rawRequestPayloadsAllowed",
    "rawFormSubmissionsAllowed",
    "rawProviderPayloadsAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "rawRecipientDataAllowed",
    "credentialValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "formSections",
    "inputKinds",
    "requiredInputNames",
    "offeringForms",
];
const OFFERING_FORM_FIELDS: &[&str] = &[
    "offeringId",
    "title",
    "category",
    "requiredInputNames",
    "dryRunRequired",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "offering-required-inputs-covered",
        decision: "block",
        requirement: "Request form schema readiness requires every catalog offering required input to be represented by the static form contract.",
        evidence: "Form schema review",
    },
    RuleDetail {
        id: "form-schema-read-only",
        decision: "block",
        requirement: "The request form contract is read-only metadata and cannot persist drafts, submit requests, mutate approvals, or start workflows.",
        evidence: "Static schema boundary",
    },
    RuleDetail {
        id: "dry-run-first-preserved",
        decision: "block",
        requirement: "Write-capable request forms must preserve dry-run-first workflow expectations before approval or execution readiness is represented.",
        evidence: "Dry-run policy review",
    },
    RuleDetail {
        id: "raw-form-data-not-exposed",
        decision: "block",
        requirement: "Request form schema evidence must use safe summaries only and must not expose raw request payloads, raw form submissions, raw provider payloads, raw logs, raw rows, recipient details, credential values, tenant identifiers, object identifiers, private network values, live endpoints, or URLs.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog_text: String,
    catalog: Value,
    offering_catalog: Value,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct CatalogInput {
    catalog: Value,
    offering_required_inputs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
    offering_catalog: Value,
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

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

struct Assignment {
    value: String,
    end: usize,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid request form contract context JSON: {error}"))?;
    let mut errors = Vec::new();
    let offering_required_inputs = required_inputs_from_offerings(&context.offering_catalog);
    validate_catalog_value(&context.catalog, &offering_required_inputs, &mut errors);
    validate_no_prohibited_values(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    validate_program_text(
        &context.program,
        &context.catalog,
        &context.offering_catalog,
        &mut errors,
    );
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    let docs_scope = serde_json::json!({
        API_README_PATH: context.api_readme,
        CATALOG_README_PATH: context.catalog_readme,
        DOC_README_PATH: context.doc_readme,
        DOC_PATH: context.doc,
    });
    validate_no_prohibited_values(&docs_scope, "request-form-contract", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let payload: CatalogInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid request form contract catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(
        &payload.catalog,
        &payload.offering_required_inputs,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid request form contract program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(
        &payload.program,
        &payload.catalog,
        &payload.offering_catalog,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid request form contract docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid request form contract prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(
    catalog: &Value,
    offering_required_inputs: &[String],
    errors: &mut Vec<String>,
) {
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "request form contract version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "request form contract status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "request form contract source must be static-seed",
    );
    expect(
        catalog.get("formMode").and_then(Value::as_str) == Some("static-request-form-schema"),
        errors,
        "request form mode must be static-request-form-schema",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(true),
            errors,
            format!("request form {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(false),
            errors,
            format!("request form {field} must be disabled"),
        );
    }
    validate_required_array(
        catalog,
        "formSections",
        REQUIRED_FORM_SECTIONS,
        false,
        errors,
    );
    validate_required_array(catalog, "inputKinds", REQUIRED_INPUT_KINDS, false, errors);
    validate_required_array_strings(
        catalog,
        "requiredInputNames",
        offering_required_inputs,
        true,
        errors,
    );
    validate_required_array(
        catalog,
        "blockedReasons",
        REQUIRED_BLOCKED_REASONS,
        false,
        errors,
    );
    validate_required_array(
        catalog,
        "requiredEvidence",
        REQUIRED_EVIDENCE,
        false,
        errors,
    );
    validate_required_rules(catalog, errors);
    validate_no_prohibited_values(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let keys: Vec<String> = catalog
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();
    let unexpected: Vec<String> = keys
        .into_iter()
        .filter(|key| !REQUIRED_CATALOG_KEYS.contains(&key.as_str()))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "request form unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    exact_order: bool,
    errors: &mut Vec<String>,
) {
    let required: Vec<String> = required_values
        .iter()
        .map(|value| value.to_string())
        .collect();
    validate_required_array_strings(catalog, field, &required, exact_order, errors);
}

fn validate_required_array_strings(
    catalog: &Value,
    field: &str,
    required_values: &[String],
    exact_order: bool,
    errors: &mut Vec<String>,
) {
    let values = string_array_like(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let missing = missing_values(required_values, &values);
    let extra = extra_values(&values, required_values);
    expect(
        missing.is_empty(),
        errors,
        format!("{field} missing values: {}", missing.join(", ")),
    );
    expect(
        extra.is_empty(),
        errors,
        format!("{field} unexpected values: {}", extra.join(", ")),
    );
    let unique: HashSet<&String> = values.iter().collect();
    expect(
        unique.len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
    if exact_order {
        expect(
            values == required_values,
            errors,
            format!("{field} must preserve canonical order"),
        );
    }
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited request form value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("request form rules must be an array of hashes".to_string());
        return;
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("request form rules must be an array of hashes".to_string());
        return;
    }

    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let required_ids: Vec<String> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id.to_string())
        .collect();
    let missing = missing_values(&required_ids, &rule_ids);
    let extra = extra_values(&rule_ids, &required_ids);
    expect(
        missing.is_empty(),
        errors,
        format!("request form missing rules: {}", missing.join(", ")),
    );
    expect(
        extra.is_empty(),
        errors,
        format!("request form unexpected rules: {}", extra.join(", ")),
    );
    let unique: HashSet<&String> = rule_ids.iter().collect();
    expect(
        unique.len() == rule_ids.len(),
        errors,
        "request form rule IDs must be unique",
    );
    for rule in rules {
        let keys: Vec<String> = rule
            .as_object()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        let unexpected: Vec<String> = keys
            .iter()
            .filter(|key| !RULE_KEYS.contains(&key.as_str()))
            .cloned()
            .collect();
        let missing_keys: Vec<String> = RULE_KEYS
            .iter()
            .filter(|key| !keys.iter().any(|actual| actual == **key))
            .map(|key| key.to_string())
            .collect();
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        if !unexpected.is_empty() {
            errors.push(format!(
                "request form rule {id} unexpected rule keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "request form rule {id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
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
                format!("request form rule {} {field} must match", expected_rule.id),
            );
        }
    }
}

fn validate_program_text(
    program: &str,
    catalog: &Value,
    offering_catalog: &Value,
    errors: &mut Vec<String>,
) {
    let uncommented_program = strip_csharp_comments(program);
    let block = endpoint_response_body(&uncommented_program, errors);
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
    validate_exact_string_assignment(
        &block,
        "formMode",
        "static-request-form-schema",
        errors,
        "API must keep static-request-form-schema mode",
    );
    for field in SAFE_TRUE_FIELDS {
        validate_exact_endpoint_assignment(
            &block,
            field,
            "true",
            errors,
            format!("API must keep {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
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
    }
    expect(
        csharp_array_values(&uncommented_program, "requestFormSections")
            == Some(string_array_like(catalog, "formSections")),
        errors,
        "API formSections must match catalog",
    );
    expect(
        csharp_array_values(&uncommented_program, "requestFormInputKinds")
            == Some(string_array_like(catalog, "inputKinds")),
        errors,
        "API inputKinds must match catalog",
    );
    expect(
        csharp_array_values(&uncommented_program, "requestFormRequiredInputNames")
            == Some(string_array_like(catalog, "requiredInputNames")),
        errors,
        "API requiredInputNames must match catalog",
    );
    expect(
        csharp_request_form_offerings(&uncommented_program)
            == Some(offering_form_entries(offering_catalog)),
        errors,
        "API offeringForms must match offering catalog required inputs",
    );
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_no_prohibited_values(&Value::String(block), PROGRAM_PATH, errors);
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(catalog_rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("request form rules must be an array of hashes".to_string());
        return;
    };
    if !catalog_rules.iter().all(Value::is_object) {
        errors.push("request form rules must be an array of hashes".to_string());
        return;
    }
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
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    for id in missing_values(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in extra_values(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    let unique: HashSet<&String> = api_rule_ids.iter().collect();
    expect(
        unique.len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(id) = catalog_rule.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(api_rule) = api_rules
            .iter()
            .find(|rule| rule.get("id").and_then(Value::as_str) == Some(id))
        else {
            continue;
        };
        for field in ["decision", "requirement", "evidence"] {
            expect(
                api_rule.get(field).and_then(Value::as_str)
                    == catalog_rule.get(field).and_then(Value::as_str),
                errors,
                format!("API rule {id} {field} must match catalog"),
            );
        }
    }
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
        "API README must document request form endpoint",
    );
    expect(
        catalog_readme.contains("request-form-contract.yaml"),
        errors,
        "catalog README must include request form catalog",
    );
    expect(
        doc_readme.contains("request-form-contract.md"),
        errors,
        "workflow README must include request form doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "request form doc must mention endpoint",
    );
    expect(
        doc.contains("No live request creation"),
        errors,
        "request form doc must prohibit live request creation",
    );
    expect(
        doc.contains("form submission"),
        errors,
        "request form doc must prohibit form submission",
    );
    expect(
        doc.contains("raw form submissions"),
        errors,
        "request form doc must prohibit raw form submissions",
    );
    expect(
        doc.contains("raw recipient data"),
        errors,
        "request form doc must prohibit raw recipient data",
    );
}

fn endpoint_response_body(program: &str, errors: &mut Vec<String>) -> String {
    let start_indexes = endpoint_start_indexes(program);
    if start_indexes.is_empty() {
        errors.push(format!("API missing endpoint {ENDPOINT}"));
        return String::new();
    }
    if start_indexes.len() != 1 {
        errors.push(format!(
            "API endpoint {ENDPOINT} must have exactly one active route"
        ));
        return String::new();
    }
    let start_index = start_indexes[0];
    let masked = mask_csharp_string_literals(program);
    let open_index = start_index + "app.MapGet".len();
    let Some(close_index) = matching_paren_index(&masked, open_index) else {
        errors.push(format!("API endpoint {ENDPOINT} block is incomplete"));
        return String::new();
    };
    let call = &program[start_index..=close_index];
    let masked_call = &masked[start_index..=close_index];
    if !validate_results_json_shape(masked_call, errors) {
        return String::new();
    }
    let marker_index = response_marker_indexes(masked_call, "Results.Json(new")[0];
    let Some(open_relative) = masked_call[marker_index..].find('{') else {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return object initializer"
        ));
        return String::new();
    };
    let open_index = marker_index + open_relative;
    let Some(close_index) = matching_brace_index(call, open_index) else {
        errors.push(format!("API endpoint {ENDPOINT} block is incomplete"));
        return String::new();
    };
    call[open_index + 1..close_index].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let masked = mask_csharp_string_literals(program);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let route_start = index + "app.MapGet(".len();
        if brace_depth_at(&masked, index) == 0
            && parse_csharp_string_literal_at(program, route_start)
                .is_some_and(|(route, _)| route == ENDPOINT)
        {
            indexes.push(index);
        }
        offset = index + "app.MapGet(".len();
    }
    indexes
}

fn validate_results_json_shape(masked_call: &str, errors: &mut Vec<String>) -> bool {
    let all_markers = response_marker_indexes(masked_call, "Results.Json(");
    let object_markers = response_marker_indexes(masked_call, "Results.Json(new");
    if object_markers.is_empty() {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return Results.Json object"
        ));
        return false;
    }
    if all_markers.len() != 1
        || object_markers.len() != 1
        || all_markers[0] != object_markers[0]
        || !response_marker_is_unconditional(masked_call, object_markers[0])
    {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return one unconditional Results.Json object"
        ));
        return false;
    }
    let marker_index = object_markers[0];
    let Some(open_relative) = masked_call[marker_index..].find('{') else {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return object initializer"
        ));
        return false;
    };
    let open_index = marker_index + open_relative;
    let Some(close_index) = matching_brace_index(masked_call, open_index) else {
        errors.push(format!("API endpoint {ENDPOINT} block is incomplete"));
        return false;
    };
    if !results_json_object_argument_is_exact(masked_call, marker_index, close_index) {
        errors.push(format!(
            "API endpoint {ENDPOINT} must return object initializer"
        ));
        return false;
    }
    true
}

fn response_marker_indexes(masked: &str, marker: &str) -> Vec<usize> {
    let Some(arrow_index) = masked.find("=>") else {
        return Vec::new();
    };
    let arrow_depth = brace_depth_at(masked, arrow_index);
    let Some(body_start) = next_non_whitespace_index(masked, arrow_index + "=>".len()) else {
        return Vec::new();
    };
    let accepts = |marker_index: usize| {
        if masked.as_bytes().get(body_start) == Some(&b'{') {
            brace_depth_at(masked, marker_index) == brace_depth_at(masked, body_start) + 1
        } else {
            brace_depth_at(masked, marker_index) == arrow_depth
        }
    };
    let mut indexes = Vec::new();
    let mut offset = body_start;
    while let Some(relative) = masked[offset..].find(marker) {
        let index = offset + relative;
        if accepts(index) {
            indexes.push(index);
        }
        offset = index + marker.len();
    }
    indexes
}

fn response_marker_is_unconditional(masked: &str, marker_index: usize) -> bool {
    let Some(arrow_index) = masked.find("=>") else {
        return false;
    };
    let Some(body_start) = next_non_whitespace_index(masked, arrow_index + "=>".len()) else {
        return false;
    };
    if masked.as_bytes().get(body_start) == Some(&b'{') {
        let Some(return_index) = return_keyword_start_before_marker(masked, marker_index) else {
            return false;
        };
        handler_prefix_allows_direct_return(masked, body_start, return_index)
    } else {
        body_start == marker_index
    }
}

fn return_keyword_start_before_marker(masked: &str, marker_index: usize) -> Option<usize> {
    let line_start = masked[..marker_index]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let line_prefix = &masked[line_start..marker_index];
    let trimmed_start = line_prefix
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(index, _)| index)?;
    (line_prefix[trimmed_start..].trim() == "return").then_some(line_start + trimmed_start)
}

fn handler_prefix_allows_direct_return(
    masked: &str,
    body_start: usize,
    return_index: usize,
) -> bool {
    let prefix = masked[body_start + 1..return_index].trim();
    prefix.is_empty() || prefix_contains_only_dead_false_blocks(prefix)
}

fn prefix_contains_only_dead_false_blocks(prefix: &str) -> bool {
    let mut offset = 0usize;
    while let Some(statement_start) = next_non_whitespace_index(prefix, offset) {
        if !prefix[statement_start..].starts_with("if")
            || !is_word_boundary(prefix, statement_start, "if")
        {
            return false;
        }
        let Some(open_paren) = next_non_whitespace_index(prefix, statement_start + "if".len())
        else {
            return false;
        };
        if prefix.as_bytes().get(open_paren) != Some(&b'(') {
            return false;
        }
        let Some(close_paren) = matching_paren_index(prefix, open_paren) else {
            return false;
        };
        if prefix[open_paren + 1..close_paren].trim() != "false" {
            return false;
        }
        let Some(open_brace) = next_non_whitespace_index(prefix, close_paren + 1) else {
            return false;
        };
        if prefix.as_bytes().get(open_brace) != Some(&b'{') {
            return false;
        }
        let Some(close_brace) = matching_brace_index(prefix, open_brace) else {
            return false;
        };
        offset = close_brace + 1;
    }
    true
}

fn results_json_object_argument_is_exact(
    masked: &str,
    marker_index: usize,
    object_close_index: usize,
) -> bool {
    let open_paren_index = marker_index + "Results.Json".len();
    if masked.as_bytes().get(open_paren_index) != Some(&b'(') {
        return false;
    }
    let Some(results_close_index) = matching_paren_index(masked, open_paren_index) else {
        return false;
    };
    if object_close_index >= results_close_index {
        return false;
    }
    if !masked[object_close_index + 1..results_close_index]
        .trim()
        .is_empty()
    {
        return false;
    }
    let tail = masked[results_close_index + 1..].trim_start();
    tail.starts_with(')') || tail.starts_with(';')
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
            "API endpoint {field} must have exactly one assignment"
        ));
        return;
    }
    expect(assignments[0].value == expected, errors, message);
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let assignments = assignment_records_for_field(block, "rules");
    if assignments.len() != 1 {
        errors.push("API endpoint rules must have exactly one assignment".to_string());
        return None;
    }
    if assignments[0].value != "new[]" {
        errors.push("API endpoint rules must be assigned to an inline new[] array".to_string());
        return None;
    }
    let rest = &block[assignments[0].end..];
    let Some(open_relative) = rest.find('{') else {
        errors.push("API endpoint rules array is incomplete".to_string());
        return None;
    };
    let open_index = assignments[0].end + open_relative;
    let Some(close_index) = matching_brace_index(block, open_index) else {
        errors.push("API endpoint rules array is incomplete".to_string());
        return None;
    };
    let tail = block[close_index + 1..].trim_start();
    if !(tail.is_empty() || tail.starts_with(',')) {
        errors.push("API endpoint rules must be assigned to an inline new[] array".to_string());
        return None;
    }
    Some(block[open_index + 1..close_index].to_string())
}

fn endpoint_rule_hashes(rules_body: &str, errors: &mut Vec<String>) -> Vec<Value> {
    let blocks = csharp_top_level_object_blocks(rules_body);
    if blocks.is_empty() {
        errors.push("API endpoint rules array must contain rule hashes".to_string());
    }
    let mut rules = Vec::new();
    for block in blocks {
        let fields = inline_object_string_fields(&block);
        if ["id", "decision", "requirement", "evidence"]
            .iter()
            .all(|field| fields.iter().any(|(key, _)| key == field))
        {
            rules.push(serde_json::json!({
                "id": field_value(&fields, "id"),
                "decision": field_value(&fields, "decision"),
                "requirement": field_value(&fields, "requirement"),
                "evidence": field_value(&fields, "evidence"),
            }));
        }
    }
    if rules.len() != csharp_top_level_object_blocks(rules_body).len() {
        errors.push("API endpoint rules array contains malformed rule hash".to_string());
    }
    rules
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected request form field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited request form field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if !exact_assignment(block, &field, "true") || SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        let lower = field.to_ascii_lowercase();
        if [
            "provider",
            "workflow",
            "live",
            "raw",
            "credential",
            "tenant",
            "object",
            "private",
            "submission",
            "approval",
        ]
        .iter()
        .any(|term| lower.contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn csharp_request_form_offerings(program: &str) -> Option<Vec<Value>> {
    let body = csharp_variable_body(program, "requestFormOfferings")?;
    let mut entries = Vec::new();
    for block in csharp_top_level_object_blocks(&body) {
        let fields = endpoint_assignment_fields(&block);
        let unexpected: Vec<Value> = fields
            .iter()
            .filter(|field| !OFFERING_FORM_FIELDS.contains(&field.as_str()))
            .cloned()
            .map(Value::String)
            .collect();
        if !unexpected.is_empty() {
            return Some(vec![serde_json::json!({ "unexpectedFields": unexpected })]);
        }
        entries.push(serde_json::json!({
            "offeringId": csharp_string_field(&block, "offeringId"),
            "title": csharp_string_field(&block, "title"),
            "category": csharp_string_field(&block, "category"),
            "requiredInputNames": csharp_array_field(&block, "requiredInputNames"),
            "dryRunRequired": csharp_bool_field(&block, "dryRunRequired"),
        }));
    }
    Some(entries)
}

fn offering_form_entries(offering_catalog: &Value) -> Vec<Value> {
    offering_catalog
        .get("offerings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|offering| {
            serde_json::json!({
                "offeringId": offering.get("id").and_then(Value::as_str),
                "title": offering.get("title").and_then(Value::as_str),
                "category": offering.get("category").and_then(Value::as_str),
                "requiredInputNames": string_array_like(offering, "requiredInputs"),
                "dryRunRequired": offering.get("dryRunRequired").and_then(Value::as_bool),
            })
        })
        .collect()
}

fn required_inputs_from_offerings(offering_catalog: &Value) -> Vec<String> {
    let mut values: Vec<String> = offering_catalog
        .get("offerings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|offering| string_array_like(offering, "requiredInputs"))
        .collect();
    values.sort();
    values.dedup();
    values
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    csharp_variable_body(program, variable).and_then(|body| csharp_array_literal_values(&body))
}

fn csharp_variable_body(program: &str, variable: &str) -> Option<String> {
    let bodies = csharp_variable_bodies(program, variable);
    if bodies.len() == 1 {
        bodies.into_iter().next()
    } else {
        None
    }
}

fn csharp_variable_bodies(program: &str, variable: &str) -> Vec<String> {
    let marker = format!("var {variable} = new[]");
    let masked = mask_csharp_string_literals(program);
    let mut bodies = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = masked[offset..].find(&marker) {
        let marker_index = offset + relative;
        if brace_depth_at(&masked, marker_index) != 0 {
            offset = marker_index + marker.len();
            continue;
        }
        let body_start = marker_index + marker.len();
        let Some(open_relative) = masked[body_start..].find('{') else {
            offset = marker_index + marker.len();
            continue;
        };
        let open_index = body_start + open_relative;
        let Some(close_index) = matching_brace_index(&masked, open_index) else {
            offset = marker_index + marker.len();
            continue;
        };
        if masked[close_index + 1..].trim_start().starts_with(';') {
            bodies.push(program[open_index + 1..close_index].to_string());
        }
        offset = close_index + 1;
    }
    bodies
}

fn csharp_array_literal_values(body: &str) -> Option<Vec<String>> {
    let mut values = Vec::new();
    for element in top_level_elements(body) {
        let trimmed = element.trim();
        let (value, end_index) = parse_csharp_string_literal_at(trimmed, 0)?;
        if !trimmed[end_index..].trim().is_empty() {
            return None;
        }
        values.push(value);
    }
    Some(values)
}

fn csharp_top_level_object_blocks(body: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(body);
    let mut blocks = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("new") {
        let index = offset + relative;
        let before_ok = index == 0
            || !masked.as_bytes()[index - 1].is_ascii_alphanumeric()
                && masked.as_bytes()[index - 1] != b'_';
        let after = index + "new".len();
        let after_ok = masked
            .as_bytes()
            .get(after)
            .is_some_and(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
        if before_ok && after_ok && brace_depth_at(&masked, index) == 0 {
            if let Some(open_index) = next_non_whitespace_index(&masked, after)
                .filter(|candidate| masked.as_bytes().get(*candidate) == Some(&b'{'))
            {
                if let Some(close_index) = matching_brace_index(body, open_index) {
                    blocks.push(body[index..=close_index].to_string());
                    offset = close_index + 1;
                    continue;
                }
            }
        }
        offset = after;
    }
    blocks
}

fn csharp_string_field(block: &str, field: &str) -> Value {
    assignment_records_for_field(block, field)
        .first()
        .and_then(|assignment| parse_quoted_value(&assignment.value))
        .map(Value::String)
        .unwrap_or(Value::Null)
}

fn csharp_bool_field(block: &str, field: &str) -> Value {
    match assignment_records_for_field(block, field)
        .first()
        .map(|assignment| assignment.value.as_str())
    {
        Some("true") => Value::Bool(true),
        Some("false") => Value::Bool(false),
        _ => Value::Null,
    }
}

fn csharp_array_field(block: &str, field: &str) -> Value {
    let assignments = assignment_records_for_field(block, field);
    if assignments.len() != 1 || assignments[0].value != "new[]" {
        return Value::Null;
    }
    let Some(open_index) = next_non_whitespace_index(block, assignments[0].end)
        .filter(|index| block.as_bytes().get(*index) == Some(&b'{'))
    else {
        return Value::Null;
    };
    let Some(close_index) = matching_brace_index(block, open_index) else {
        return Value::Null;
    };
    let tail = block[close_index + 1..].trim_start();
    if !(tail.is_empty() || tail.starts_with(',') || tail.starts_with('}')) {
        return Value::Null;
    }
    csharp_array_literal_values(&block[open_index + 1..close_index])
        .map(|values| Value::Array(values.into_iter().map(Value::String).collect()))
        .unwrap_or(Value::Null)
}

fn assignment_records_for_field(block: &str, field: &str) -> Vec<Assignment> {
    let masked = mask_csharp_string_literals(block);
    let mut assignments = Vec::new();
    let mut index = 0usize;
    while index < masked.len() {
        let Some(relative) = masked[index..].find('=') else {
            break;
        };
        let equals_index = index + relative;
        if assignment_field_before_equals(block, equals_index).as_deref() == Some(field) {
            if let Some(value_start) = next_non_whitespace_index(block, equals_index + 1) {
                let value_end = assignment_value_end(&masked, value_start);
                assignments.push(Assignment {
                    value: block[value_start..value_end].trim().to_string(),
                    end: value_end,
                });
            }
        }
        index = equals_index + 1;
    }
    assignments
}

fn assignment_value_end(masked: &str, start_index: usize) -> usize {
    if masked[start_index..].starts_with("new[]") {
        return start_index + "new[]".len();
    }
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (relative, ch) in masked[start_index..].char_indices() {
        let index = start_index + relative;
        match ch {
            '{' => brace_depth += 1,
            '}' => {
                if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 {
                    return index;
                }
                brace_depth = brace_depth.saturating_sub(1);
            }
            '(' => paren_depth += 1,
            ')' => {
                if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 {
                    return index;
                }
                paren_depth = paren_depth.saturating_sub(1);
            }
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => return index,
            _ => {}
        }
    }
    masked.len()
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let assignments = assignment_records_for_field(block, field);
    assignments.len() == 1 && assignments[0].value == value
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let masked = mask_csharp_string_literals(block);
    let mut index = 0;
    while index < masked.len() {
        let Some(relative) = masked[index..].find('=') else {
            break;
        };
        let equals_index = index + relative;
        if let Some(field) = assignment_field_before_equals(block, equals_index) {
            fields.push(field);
        }
        index = equals_index + 1;
    }
    fields
}

fn assignment_field_before_equals(block: &str, equals_index: usize) -> Option<String> {
    let prefix = &block[..equals_index];
    let trimmed = prefix.trim_end();
    let mut start = trimmed.len();
    for (index, ch) in trimmed.char_indices().rev() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            start = index;
        } else {
            break;
        }
    }
    let field = &trimmed[start..];
    if field.is_empty() || !is_identifier(field) {
        return None;
    }
    Some(field.to_string())
}

fn inline_object_string_fields(block: &str) -> Vec<(String, Value)> {
    let mut fields = Vec::new();
    let masked = mask_csharp_string_literals(block);
    let mut index = 0;
    while index < masked.len() {
        let Some(relative) = masked[index..].find('=') else {
            break;
        };
        let equals_index = index + relative;
        if let Some(field) = assignment_field_before_equals(block, equals_index) {
            if let Some(value_start) = next_non_whitespace_index(block, equals_index + 1) {
                if let Some((value, value_end)) = parse_csharp_string_literal_at(block, value_start)
                {
                    fields.push((field, Value::String(value)));
                    index = value_end;
                    continue;
                }
            }
        }
        index = equals_index + 1;
    }
    fields
}

fn field_value(fields: &[(String, Value)], field: &str) -> Value {
    fields
        .iter()
        .find(|(key, _)| key == field)
        .map(|(_, value)| value.clone())
        .unwrap_or(Value::Null)
}

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn missing_values(required_values: &[String], values: &[String]) -> Vec<String> {
    required_values
        .iter()
        .filter(|required| !values.contains(*required))
        .cloned()
        .collect()
}

fn extra_values(values: &[String], required_values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|value| !required_values.contains(*value))
        .cloned()
        .collect()
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited request form field"
                    ));
                }
                validate_no_prohibited_values(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_prohibited_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if prohibited_provider_identifier_value(text) {
                    errors.push(format!(
                        "{path} contains prohibited provider-identifying value"
                    ));
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_provider_identifier_value(text) {
                errors.push(format!(
                    "{path} contains prohibited provider-identifying value"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited request form field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || contains_private_key_like(text)
        || contains_aws_access_key_like(text)
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_secret_assignment(text)
}

fn prohibited_provider_identifier_value(text: &str) -> bool {
    contains_sha40_like(text) || contains_provider_serial_like(text)
}

fn contains_sha40_like(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_hexdigit())
        .any(|term| term.len() >= 40 && term.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn contains_provider_serial_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
        .any(|term| {
            let upper = term.to_ascii_uppercase();
            let Some(rest) = upper
                .strip_prefix("SN-")
                .or_else(|| upper.strip_prefix("SN_"))
                .or_else(|| upper.strip_prefix("SERIAL-"))
                .or_else(|| upper.strip_prefix("SERIAL_"))
            else {
                return false;
            };
            let payload: String = rest
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric())
                .collect();
            payload.len() >= 6
                && payload.chars().all(|ch| ch.is_ascii_alphanumeric())
                && payload.chars().any(|ch| ch.is_ascii_digit())
        })
}

fn contains_private_key_like(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

fn contains_aws_access_key_like(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.as_bytes().windows(20).any(|window| {
        window.starts_with(b"AKIA") && window[4..].iter().all(|byte| byte.is_ascii_alphanumeric())
    })
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            let octets: Vec<u16> = candidate
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect();
            octets.windows(4).any(|window| {
                window.iter().all(|octet| *octet <= 255)
                    && (window[0] == 10
                        || (window[0] == 192 && window[1] == 168)
                        || (window[0] == 172 && (16..=31).contains(&window[1])))
            })
        })
}

fn contains_uuid_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(|candidate| {
            let parts: Vec<&str> = candidate.split('-').collect();
            parts.windows(5).any(|window| {
                [8, 4, 4, 4, 12]
                    .iter()
                    .zip(window.iter())
                    .all(|(len, part)| {
                        part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
            })
        })
}

fn contains_secret_assignment(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for term in [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ] {
        let mut offset = 0;
        while let Some(relative) = lower[offset..].find(term) {
            let index = offset + relative + term.len();
            let tail = lower[index..].trim_start();
            if tail.starts_with(':') || tail.starts_with('=') {
                return true;
            }
            offset = index;
        }
    }
    false
}

fn safe_text_value(value: &str) -> bool {
    let safe_values = safe_text_values();
    safe_values.contains(&value)
}

fn safe_text_values() -> Vec<&'static str> {
    let mut values = Vec::new();
    values.extend(REQUIRED_FORM_SECTIONS);
    values.extend(REQUIRED_INPUT_KINDS);
    values.extend(REQUIRED_DISABLED_FIELDS);
    values.extend(SAFE_TRUE_FIELDS);
    values.extend(REQUIRED_BLOCKED_REASONS);
    values.extend(REQUIRED_EVIDENCE);
    values.extend(REQUIRED_RULES.iter().map(|rule| rule.id));
    values.extend(
        REQUIRED_RULES
            .iter()
            .flat_map(|rule| [rule.decision, rule.requirement, rule.evidence]),
    );
    values.extend(REQUIRED_CATALOG_KEYS);
    values.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(_, variable)| *variable),
    );
    values.extend([
        "draft",
        "static-seed",
        "static-request-form-schema",
        "block",
        "true",
        "false",
    ]);
    values
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    let safe_normalized: HashSet<String> = safe_text_values()
        .iter()
        .map(|safe| normalize_identifier(safe))
        .collect();
    if safe_normalized.contains(&normalized) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || [
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
            "rawform",
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
        ]
        .iter()
        .any(|term| normalized.contains(term))
        || sensitive_compound_field(value)
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    has_any(
        &tokens,
        &["password", "credential", "secret", "token", "bearer"],
    ) || has_any(&tokens, &["url", "uri", "endpoint"])
        || (has_any(&tokens, &["private", "ip"])
            && has_any(&tokens, &["address", "value", "network"]))
        || (has_any(&tokens, &["tenant", "object", "provider"])
            && has_any(
                &tokens,
                &["id", "identifier", "payload", "row", "rows", "value"],
            ))
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &[
                    "request",
                    "form",
                    "provider",
                    "recipient",
                    "payload",
                    "log",
                    "content",
                    "row",
                    "rows",
                    "data",
                    "submission",
                    "submissions",
                ],
            ))
        || tokens.iter().any(|token| token == "recipient")
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut expanded = String::new();
    let mut previous: Option<char> = None;
    for ch in value.chars() {
        if let Some(prev) = previous {
            if (prev.is_ascii_lowercase() || prev.is_ascii_digit()) && ch.is_ascii_uppercase() {
                expanded.push(' ');
            }
        }
        expanded.push(ch.to_ascii_lowercase());
        previous = Some(ch);
    }
    expanded
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn top_level_elements(body: &str) -> Vec<&str> {
    let masked = mask_csharp_string_literals(body);
    let mut elements = Vec::new();
    let mut start_index = 0usize;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, ch) in masked.char_indices() {
        match ch {
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                let element = body[start_index..index].trim();
                if !element.is_empty() {
                    elements.push(element);
                }
                start_index = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    let element = body[start_index..].trim();
    if !element.is_empty() {
        elements.push(element);
    }
    elements
}

fn parse_quoted_value(value: &str) -> Option<String> {
    parse_csharp_string_literal_at(value, 0).map(|(text, _)| text)
}

fn parse_csharp_string_literal_at(source: &str, quote_index: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let mut quote_index = quote_index;
    while quote_index < bytes.len() {
        let ch = source[quote_index..].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        quote_index += ch.len_utf8();
    }
    if bytes.get(quote_index) != Some(&b'"') {
        return None;
    }
    if quote_count_at(bytes, quote_index) >= 3 {
        return parse_raw_string_literal_at(
            source,
            quote_index,
            quote_count_at(bytes, quote_index),
        );
    }
    let mut value = String::new();
    let mut index = quote_index + 1;
    let mut escaped = false;
    while index < source.len() {
        let ch = source[index..].chars().next()?;
        if escaped {
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some((value, index + 1));
        } else {
            value.push(ch);
        }
        index += ch.len_utf8();
    }
    None
}

fn parse_raw_string_literal_at(
    source: &str,
    quote_start: usize,
    quote_count: usize,
) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let content_start = quote_start + quote_count;
    let mut cursor = content_start;
    while cursor + quote_count <= bytes.len() {
        if bytes[cursor..cursor + quote_count]
            .iter()
            .all(|byte| *byte == b'"')
        {
            return Some((
                source[content_start..cursor].to_string(),
                cursor + quote_count,
            ));
        }
        cursor += source[cursor..].chars().next()?.len_utf8();
    }
    None
}

fn mask_csharp_string_literals(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        if let Some(end) = csharp_string_end(source, index) {
            push_masked_source(&mut result, &source[index..end]);
            index = end;
            continue;
        }
        let ch = source[index..].chars().next().expect("valid char boundary");
        result.push(ch);
        index += ch.len_utf8();
    }
    result
}

fn csharp_string_end(source: &str, index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    match bytes.get(index).copied() {
        Some(b'$') => {
            let mut cursor = index;
            while bytes.get(cursor) == Some(&b'$') {
                cursor += 1;
            }
            if bytes.get(cursor) == Some(&b'@') && bytes.get(cursor + 1) == Some(&b'"') {
                verbatim_string_end(source, cursor + 1)
            } else if bytes.get(cursor) == Some(&b'"') {
                if quote_count_at(bytes, cursor) >= 3 {
                    raw_string_end(source, cursor, quote_count_at(bytes, cursor))
                } else {
                    normal_string_end(source, cursor)
                }
            } else {
                None
            }
        }
        Some(b'@') if bytes.get(index + 1) == Some(&b'"') => verbatim_string_end(source, index + 1),
        Some(b'"') => {
            if quote_count_at(bytes, index) >= 3 {
                raw_string_end(source, index, quote_count_at(bytes, index))
            } else {
                normal_string_end(source, index)
            }
        }
        _ => None,
    }
}

fn normal_string_end(source: &str, quote_index: usize) -> Option<usize> {
    let mut cursor = quote_index + 1;
    let mut escaped = false;
    while cursor < source.len() {
        let ch = source[cursor..].chars().next()?;
        cursor += ch.len_utf8();
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(cursor);
        }
    }
    Some(source.len())
}

fn verbatim_string_end(source: &str, quote_index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = quote_index + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            if bytes.get(cursor + 1) == Some(&b'"') {
                cursor += 2;
            } else {
                return Some(cursor + 1);
            }
        } else {
            cursor += source[cursor..].chars().next()?.len_utf8();
        }
    }
    Some(source.len())
}

fn raw_string_end(source: &str, quote_index: usize, quote_count: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = quote_index + quote_count;
    while cursor + quote_count <= bytes.len() {
        if bytes[cursor..cursor + quote_count]
            .iter()
            .all(|byte| *byte == b'"')
        {
            return Some(cursor + quote_count);
        }
        cursor += source[cursor..].chars().next()?.len_utf8();
    }
    Some(source.len())
}

fn quote_count_at(bytes: &[u8], index: usize) -> usize {
    let mut count = 0;
    while bytes.get(index + count) == Some(&b'"') {
        count += 1;
    }
    count
}

fn push_masked_source(result: &mut String, source: &str) {
    for ch in source.chars() {
        if ch == '\n' {
            result.push('\n');
        } else {
            for _ in 0..ch.len_utf8() {
                result.push(' ');
            }
        }
    }
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

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let masked = mask_csharp_string_literals(text);
    let mut depth = 0usize;
    for (relative, ch) in masked[open_index..].char_indices() {
        let index = open_index + relative;
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn matching_paren_index(masked_text: &str, open_index: usize) -> Option<usize> {
    if masked_text.as_bytes().get(open_index) != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    for (relative, ch) in masked_text[open_index..].char_indices() {
        let index = open_index + relative;
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn brace_depth_at(masked_text: &str, index: usize) -> usize {
    let mut depth = 0usize;
    for ch in masked_text[..index].chars() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
        }
    }
    depth
}

fn next_non_whitespace_index(text: &str, start: usize) -> Option<usize> {
    text[start..]
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(relative, _)| start + relative)
}

fn is_word_boundary(text: &str, start: usize, word: &str) -> bool {
    let end = start + word.len();
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {}
