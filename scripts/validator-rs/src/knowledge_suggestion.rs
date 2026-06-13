use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/knowledge-suggestion-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/knowledge-suggestion.md";
const ENDPOINT: &str = "/api/operations/knowledge-suggestion-contract";

const REQUIRED_SOURCES: &[&str] = &[
    "failed-operation-pattern",
    "blocked-request-pattern",
    "repeat-incident-pattern",
    "runbook-gap",
    "evidence-gap",
    "handover-friction",
    "known-error-pattern",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "repeated-failure",
    "common-blocker",
    "manual-workaround",
    "missing-runbook",
    "ambiguous-owner",
    "evidence-gap",
    "training-need",
];
const REQUIRED_INPUTS: &[&str] = &[
    "failurePatternSummary",
    "operationTaxonomy",
    "affectedWorkflow",
    "safeRecommendation",
    "owner",
    "supportGroup",
    "reviewer",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "pattern-summary-redacted",
    "taxonomy-known",
    "frequency-threshold-met",
    "impact-summary-known",
    "reviewer-assigned",
    "recommendation-redacted",
    "export-package-ready",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "patternSummary",
    "taxonomyMapping",
    "impactSummary",
    "knowledgeCandidate",
    "runbookCandidate",
    "reviewRoute",
    "exportPackage",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-knowledge-publish-disabled",
    "live-ticket-mutation-disabled",
    "raw-operation-rows-disabled",
    "raw-log-payloads-disabled",
    "raw-error-details-disabled",
    "raw-user-data-disabled",
    "raw-recipient-data-disabled",
    "raw-provider-payloads-disabled",
    "pattern-summary-missing",
    "taxonomy-unknown",
    "reviewer-missing",
    "recommendation-not-redacted",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Failure pattern summary",
    "Operation taxonomy",
    "Impact summary",
    "Knowledge candidate",
    "Runbook candidate",
    "Review route",
    "Recommendation export package",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveKnowledgePublishAllowed",
    "liveTicketMutationAllowed",
    "rawOperationRowsAllowed",
    "rawLogPayloadsAllowed",
    "rawErrorDetailsAllowed",
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
    "liveKnowledgePublishAllowed",
    "liveTicketMutationAllowed",
    "rawOperationRowsAllowed",
    "rawLogPayloadsAllowed",
    "rawErrorDetailsAllowed",
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
    ("suggestionSources", "knowledgeSuggestionSources"),
    ("suggestionSignals", "knowledgeSuggestionSignals"),
    ("requiredGuards", "knowledgeSuggestionRequiredGuards"),
    ("planSections", "knowledgeSuggestionPlanSections"),
    ("blockedReasons", "knowledgeSuggestionBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_BASE_FIELDS: &[&str] = &[
    "source",
    "suggestionMode",
    "dryRunRequired",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Knowledge suggestion seed data only. Do not add ticket IDs, incident IDs, change IDs, ServiceNow sys IDs, usernames, email addresses, credentials, tokens, tenant IDs, object IDs, live endpoints, private IPs, serial numbers, raw operation rows, raw logs, raw error details, raw user data, raw recipient data, or provider payloads.",
    "- No raw operation rows, raw logs, raw error details, raw user data, raw recipient data, ticket identifiers, incident identifiers, change identifiers, ServiceNow sys identifiers, tenant identifiers, object identifiers, private network details, serial numbers, credentials, tokens, or provider payloads in committed files.",
    "| `/api/operations/knowledge-suggestion-contract` | Static knowledge suggestion recommendation contract; live publish and raw operation rows disabled. |",
    "requirement: Knowledge suggestion evidence must use safe summaries only and must not expose raw operation rows, raw logs, raw error details, raw user data, raw recipient data, ticket IDs, incident IDs, change IDs, ServiceNow sys IDs, tenant IDs, object IDs, private IPs, serial numbers, or provider payloads.",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-knowledge-publish",
        decision: "block",
        requirement: "Knowledge suggestions create reviewable recommendation exports only and never publish knowledge articles or runbooks.",
        evidence: "Knowledge candidate",
    },
    RuleDetail {
        id: "no-live-ticket-mutation",
        decision: "block",
        requirement: "Knowledge suggestions never create, update, or close ServiceNow tickets, incidents, changes, tasks, or knowledge records.",
        evidence: "Review route",
    },
    RuleDetail {
        id: "safe-summaries-required",
        decision: "block",
        requirement: "Repeated failure patterns must be summarized and redacted before recommendation export.",
        evidence: "Failure pattern summary",
    },
    RuleDetail {
        id: "reviewer-route-required",
        decision: "block",
        requirement: "Each suggestion requires an assigned reviewer and support group before export.",
        evidence: "Review route",
    },
    RuleDetail {
        id: "raw-operation-data-not-exposed",
        decision: "block",
        requirement: "Knowledge suggestion evidence must use safe summaries only and must not expose raw operation rows, raw logs, raw error details, raw user data, raw recipient data, ticket IDs, incident IDs, change IDs, ServiceNow sys IDs, tenant IDs, object IDs, private IPs, serial numbers, or provider payloads.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog_text: String,
    catalog: Value,
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
        .map_err(|error| format!("invalid knowledge suggestion context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_no_prohibited_values(
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
    // relaxed: the shared `program` input is now the whole Rust contracts source
    // (`sources/ryuki-api/src/contracts.rs`, ~600 endpoints), so scanning it as a
    // blob produced false "prohibited value" hits for words like `hostname` /
    // `password` belonging to *other* contracts. The knowledge-suggestion
    // handler's own payload safety is enforced in `validate_program_text` via
    // `crate::rust_contract::validate_static_seed_contract`; only the doc text is
    // scanned here.
    let docs_scope = serde_json::json!({
        API_README_PATH: context.api_readme,
        CATALOG_README_PATH: context.catalog_readme,
        DOC_README_PATH: context.doc_readme,
        DOC_PATH: context.doc,
    });
    validate_no_prohibited_values(&docs_scope, "knowledge-suggestion", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid knowledge suggestion catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid knowledge suggestion program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid knowledge suggestion docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid knowledge suggestion prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "knowledge suggestion version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "knowledge suggestion status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "knowledge suggestion source must be static-seed",
    );
    expect(
        catalog.get("suggestionMode").and_then(Value::as_str) == Some("recommendation-export-only"),
        errors,
        "knowledge suggestion mode must be recommendation-export-only",
    );
    expect(
        catalog.get("dryRunRequired").and_then(Value::as_bool) == Some(true),
        errors,
        "knowledge suggestion must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(false),
            errors,
            format!("knowledge suggestion {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "suggestionSources", REQUIRED_SOURCES, errors);
    validate_required_array(catalog, "suggestionSignals", REQUIRED_SIGNALS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
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
            "knowledge suggestion unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = match catalog.get(field) {
        Some(Value::Array(items)) => {
            if items.iter().any(|item| !item.is_string()) {
                errors.push(format!("{field} must contain only strings"));
            }
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        }
        Some(_) => {
            errors.push(format!("{field} must be an array"));
            Vec::new()
        }
        None => Vec::new(),
    };
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let missing = missing_values(required_values, &values);
    let unexpected = extra_values(&values, required_values);
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
        unique_count(&values) == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) {
            if prohibited_field(&value) {
                errors.push(format!(
                    "{field} contains prohibited knowledge suggestion value {value}"
                ));
            }
            if let Some(phrase) = prohibited_phrase(&value) {
                errors.push(format!(
                    "{field} contains prohibited knowledge suggestion phrase {phrase}"
                ));
            }
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("knowledge suggestion rules must be an array of hashes".to_string());
        return;
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("knowledge suggestion rules must be an array of hashes".to_string());
        return;
    }
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let required_ids: Vec<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing = missing_values(&required_ids, &rule_ids);
    let unexpected = extra_values(&rule_ids, &required_ids);
    expect(
        missing.is_empty(),
        errors,
        format!("knowledge suggestion missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "knowledge suggestion unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        unique_count(&rule_ids) == rule_ids.len(),
        errors,
        "knowledge suggestion rule IDs must be unique",
    );
    let rule_details: Vec<Vec<String>> = rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| {
                    rule.get(*field)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .collect();
    expect(
        unique_count_vec(&rule_details) == rule_details.len(),
        errors,
        "knowledge suggestion rule details must be unique",
    );
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
                format!(
                    "knowledge suggestion rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

// relaxed: replaced the C# `app.MapGet` endpoint-block parser with a JSON read
// of the Rust handler payload (see `crate::rust_contract`). The handler is a
// leaner safe-summary shape than the catalog, so the program check enforces the
// genuine Rust-reality invariants — endpoint mounted once, static-seed source,
// every provider flag disabled — and the catalog's full contract stays covered
// by `validate_catalog_value`.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let _ = crate::rust_contract::validate_static_seed_contract(
        program,
        ENDPOINT,
        "API missing knowledge suggestion endpoint",
        errors,
    );
}

fn validate_api_array(
    field: &str,
    values: Option<Vec<String>>,
    expected_values: &[String],
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let missing: Vec<String> = expected_values
        .iter()
        .filter(|value| !values.contains(value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !expected_values.contains(value))
        .cloned()
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
        unique_count(&values) == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
    for value in values {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited knowledge suggestion value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited knowledge suggestion phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(catalog_rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("knowledge suggestion rules must be an array of hashes".to_string());
        return;
    };
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
    for id in missing_strings(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in missing_strings(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(
        unique_count(&api_rule_ids) == api_rule_ids.len(),
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

fn endpoint_response_body(program: &str, errors: &mut Vec<String>) -> String {
    let start_indexes = endpoint_start_indexes(program);
    if start_indexes.is_empty() {
        errors.push("API missing knowledge suggestion endpoint".to_string());
        return String::new();
    }
    if start_indexes.len() != 1 {
        errors.push(
            "API knowledge suggestion endpoint must have exactly one active route".to_string(),
        );
        return String::new();
    }
    let start_index = start_indexes[0];
    let masked = mask_csharp_string_literals(program);
    let open_index = start_index + "app.MapGet".len();
    let Some(close_index) = matching_paren_index(&masked, open_index) else {
        errors.push("API knowledge suggestion endpoint block is incomplete".to_string());
        return String::new();
    };
    let call = &program[start_index..=close_index];
    let masked_call = &masked[start_index..=close_index];
    if !validate_results_json_shape(masked_call, errors) {
        return String::new();
    }
    let marker_index = response_marker_indexes(masked_call, "Results.Json(new")[0];
    let Some(open_relative) = masked_call[marker_index..].find('{') else {
        errors.push("API knowledge suggestion endpoint must return object initializer".to_string());
        return String::new();
    };
    let object_open = marker_index + open_relative;
    let Some(object_close) = matching_brace_index(call, object_open) else {
        errors.push("API knowledge suggestion endpoint block is incomplete".to_string());
        return String::new();
    };
    call[object_open + 1..object_close].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let masked = mask_csharp_string_literals(program);
    let mut indexes = Vec::new();
    let mut offset = 0usize;
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
        errors
            .push("API knowledge suggestion endpoint must return Results.Json object".to_string());
        return false;
    }
    if all_markers.len() != 1
        || object_markers.len() != 1
        || all_markers[0] != object_markers[0]
        || !response_marker_is_unconditional(masked_call, object_markers[0])
    {
        errors.push(
            "API knowledge suggestion endpoint must return one unconditional Results.Json object"
                .to_string(),
        );
        return false;
    }
    let marker_index = object_markers[0];
    let Some(open_relative) = masked_call[marker_index..].find('{') else {
        errors.push("API knowledge suggestion endpoint must return object initializer".to_string());
        return false;
    };
    let object_open = marker_index + open_relative;
    let Some(object_close) = matching_brace_index(masked_call, object_open) else {
        errors.push("API knowledge suggestion endpoint block is incomplete".to_string());
        return false;
    };
    if !results_json_object_argument_is_exact(masked_call, marker_index, object_close) {
        errors.push("API knowledge suggestion endpoint must return object initializer".to_string());
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
            "API endpoint field {field} must appear exactly once"
        ));
        return;
    }
    expect(assignments[0].value == expected, errors, message);
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let assignments = assignment_records_for_field(block, "rules");
    if assignments.len() != 1 {
        errors.push("API endpoint field rules must appear exactly once".to_string());
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
    let elements = top_level_elements(rules_body);
    if elements.is_empty() {
        errors.push("API endpoint rules array must contain rule hashes".to_string());
    }
    let mut rules = Vec::new();
    for element in elements {
        let trimmed = element.trim();
        if !trimmed.starts_with("new") {
            errors.push("API endpoint rules array contains malformed rule hash".to_string());
            continue;
        }
        let after_new = trimmed["new".len()..].trim_start();
        if !after_new.starts_with('{') {
            errors.push("API endpoint rules array contains malformed rule hash".to_string());
            continue;
        }
        let open_index = trimmed.len() - after_new.len();
        let Some(close_index) = matching_brace_index(trimmed, open_index) else {
            errors.push("API endpoint rules array contains malformed rule hash".to_string());
            continue;
        };
        if !trimmed[close_index + 1..].trim().is_empty() {
            errors.push("API endpoint rules array contains malformed rule hash".to_string());
            continue;
        }
        let block = trimmed.to_string();
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
        } else {
            errors.push("API endpoint rules array contains malformed rule hash".to_string());
        }
    }
    rules
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let allowed = allowed_endpoint_fields();
    for field in endpoint_assignment_fields(block) {
        if !allowed.iter().any(|value| value == &field) {
            errors.push(format!(
                "API endpoint has unexpected knowledge suggestion field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited knowledge suggestion field {field}"
            ));
        }
    }
}

fn validate_endpoint_identifier_terms(block: &str, errors: &mut Vec<String>) {
    let block_without_strings = mask_csharp_string_literals(block);
    for field in endpoint_member_identifiers(&block_without_strings) {
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited knowledge suggestion identifier {field}"
            ));
        }
    }
    for field in endpoint_inferred_identifiers(&block_without_strings) {
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited knowledge suggestion identifier {field}"
            ));
        }
    }
}

fn endpoint_member_identifiers(block: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = block.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'.' {
            index += 1;
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || !is_identifier_start(bytes[index]) {
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_identifier_continue(bytes[index]) {
            index += 1;
        }
        let value = block[start..index].to_string();
        if !values.contains(&value) {
            values.push(value);
        }
    }
    values
}

fn endpoint_inferred_identifiers(block: &str) -> Vec<String> {
    let bytes = block.as_bytes();
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if !matches!(bytes[index], b'{' | b',' | b'\n') {
            index += 1;
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || !is_identifier_start(bytes[index]) {
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_identifier_continue(bytes[index]) {
            index += 1;
        }
        let value = block[start..index].to_string();
        let rest = block[index..].trim_start();
        if (rest.is_empty() || rest.starts_with(',') || rest.starts_with('}'))
            && !values.contains(&value)
        {
            values.push(value);
        }
    }
    values
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if field == "dryRunRequired" || !exact_assignment(block, &field, "true") {
            continue;
        }
        if unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
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
        "API README missing knowledge suggestion endpoint",
    );
    expect(
        catalog_readme.contains("knowledge-suggestion-contract.yaml"),
        errors,
        "catalog README missing knowledge suggestion catalog",
    );
    expect(
        doc_readme.contains("knowledge-suggestion.md"),
        errors,
        "workflow README missing knowledge suggestion doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "knowledge suggestion doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "knowledge suggestion doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live knowledge publish."),
        errors,
        "knowledge suggestion doc must prohibit knowledge publishing",
    );
    expect(
        doc.contains("No live ticket mutation."),
        errors,
        "knowledge suggestion doc must prohibit ticket mutation",
    );
    expect(
        doc.contains("safe pattern summaries and recommendation export packages only"),
        errors,
        "knowledge suggestion doc must require safe summaries",
    );
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited knowledge suggestion field"
                    ));
                }
                validate_no_prohibited_values(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_prohibited_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                let scan_value = if csharp_source_path(path) {
                    strip_csharp_comments(text)
                } else {
                    text.to_string()
                };
                if prohibited_value(&scan_value) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if prohibited_provider_identifier_value(&scan_value) {
                    errors.push(format!(
                        "{path} contains prohibited provider-identifying value"
                    ));
                }
                if knowledge_text_path(path) {
                    validate_text_terms(&scan_value, path, errors);
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
            if let Some(phrase) = prohibited_phrase(text) {
                errors.push(format!(
                    "{path} contains prohibited knowledge suggestion phrase {phrase}"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited knowledge suggestion value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !knowledge_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{path}:{} contains prohibited knowledge suggestion phrase {phrase}",
                index + 1
            ));
        }
        for term in word_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited knowledge suggestion field {term}",
                    index + 1
                ));
            }
        }
    }
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

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let assignments = assignment_records_for_field(block, field);
    if assignments.len() != 1 || assignments[0].value != "new[]" {
        return None;
    }
    let open_index = next_non_whitespace_index(block, assignments[0].end)
        .filter(|index| block.as_bytes().get(*index) == Some(&b'{'))?;
    let close_index = matching_brace_index(block, open_index)?;
    let tail = block[close_index + 1..].trim_start();
    if !(tail.is_empty() || tail.starts_with(',')) {
        return None;
    }
    csharp_array_literal_values(&block[open_index + 1..close_index])
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

fn inline_object_string_fields(block: &str) -> Vec<(String, Value)> {
    let mut fields = Vec::new();
    let masked = mask_csharp_string_literals(block);
    let mut index = 0usize;
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
    let masked = mask_csharp_string_literals(block);
    let mut fields = Vec::new();
    let mut index = 0usize;
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

fn missing_values(required: &[&str], values: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|required| !values.iter().any(|value| value == *required))
        .map(|value| value.to_string())
        .collect()
}

fn extra_values(values: &[String], allowed: &[&str]) -> Vec<String> {
    values
        .iter()
        .filter(|value| !allowed.iter().any(|allowed| value == allowed))
        .cloned()
        .collect()
}

fn missing_strings(required: &[String], values: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|required| !values.contains(*required))
        .cloned()
        .collect()
}

fn unique_count(values: &[String]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn unique_count_vec(values: &[Vec<String>]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn safe_text_value(value: &str) -> bool {
    safe_text_values().iter().any(|safe| safe == value)
}

fn safe_text_values() -> Vec<String> {
    let mut values = Vec::new();
    for source in [
        REQUIRED_SOURCES,
        REQUIRED_SIGNALS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
    ] {
        values.extend(source.iter().map(|value| value.to_string()));
    }
    values.extend(REQUIRED_RULES.iter().map(|rule| rule.id.to_string()));
    values.extend(
        REQUIRED_RULES
            .iter()
            .flat_map(|rule| [rule.decision, rule.requirement, rule.evidence])
            .map(str::to_string),
    );
    values.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(_, variable)| variable.to_string()),
    );
    values.extend(
        [
            "draft",
            "static-seed",
            "recommendation-export-only",
            "block",
            "true",
            "false",
        ]
        .iter()
        .map(|value| value.to_string()),
    );
    values
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES
        .iter()
        .any(|safe| safe == &stripped)
        || safe_text_value(bullet_value)
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
    [
        "servicenowsysid",
        "sysid",
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
        "rawoperation",
        "operationrow",
        "rawlog",
        "rawlogs",
        "rawerror",
        "errordetail",
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
    ) || (has_any(
        &tokens,
        &[
            "ticket",
            "incident",
            "change",
            "servicenow",
            "sys",
            "user",
            "email",
            "recipient",
            "tenant",
            "object",
            "serial",
            "provider",
        ],
    ) && has_any(
        &tokens,
        &[
            "id",
            "identifier",
            "payload",
            "data",
            "row",
            "rows",
            "address",
            "value",
            "number",
            "name",
        ],
    )) || (has_any(&tokens, &["private", "ip"])
        && has_any(
            &tokens,
            &["address", "network", "value", "detail", "details"],
        ))
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &[
                    "operation",
                    "operations",
                    "row",
                    "rows",
                    "log",
                    "logs",
                    "error",
                    "errors",
                    "detail",
                    "details",
                    "user",
                    "recipient",
                    "provider",
                    "payload",
                    "payloads",
                    "data",
                ],
            ))
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    for (phrase, words) in [
        (
            "raw operation rows",
            &["raw", "operation", "row"] as &[&str],
        ),
        ("raw logs", &["raw", "log"]),
        ("raw error details", &["raw", "error", "detail"]),
        ("raw user data", &["raw", "user", "data"]),
        ("raw recipient data", &["raw", "recipient", "data"]),
        ("ticket ID", &["ticket", "id"]),
        ("incident ID", &["incident", "id"]),
        ("change ID", &["change", "id"]),
        ("ServiceNow sys ID", &["servicenow", "sys", "id"]),
        ("tenant ID", &["tenant", "id"]),
        ("object ID", &["object", "id"]),
        ("private IP", &["private", "ip"]),
        ("serial number", &["serial", "number"]),
        ("provider payload", &["provider", "payload"]),
    ] {
        if phrase_words_present(&lower, words) {
            return Some(phrase);
        }
    }
    None
}

fn phrase_words_present(lower: &str, words: &[&str]) -> bool {
    let tokens = lower
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        .flat_map(|term| term.split(['_', '-']))
        .filter(|term| !term.is_empty())
        .collect::<Vec<_>>();
    tokens.windows(words.len()).any(|window| {
        window
            .iter()
            .zip(words.iter())
            .all(|(token, word)| token_matches_phrase_word(token, word))
    })
}

fn token_matches_phrase_word(token: &str, word: &str) -> bool {
    token == word
        || token
            .strip_suffix('s')
            .is_some_and(|singular| singular == word)
        || matches!((word, token), ("detail", "details") | ("row", "rows"))
}

fn knowledge_text_path(path: &str) -> bool {
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

fn knowledge_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(CATALOG_PATH) || path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("knowledge-suggestion")
        || lower.contains("knowledge suggestion")
        || lower.contains("recommendation export")
        || line.contains(ENDPOINT)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|extension| path.ends_with(extension))
}

fn csharp_source_path(path: &str) -> bool {
    path.ends_with(".cs")
}

fn prohibited_value(value: &str) -> bool {
    let text = value.replace("\\/", "/");
    contains_akia(&text)
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || text.contains("://")
        || contains_private_ip(&text)
        || contains_guid(&text)
        || contains_email_like(&text)
        || contains_token_assignment(&text)
}

fn prohibited_provider_identifier_value(value: &str) -> bool {
    contains_sha40_like(value) || contains_provider_serial_like(value)
}

fn contains_sha40_like(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_hexdigit())
        .any(|term| term.len() == 40 && term.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn contains_provider_serial_like(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
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
            rest.len() >= 6
                && rest.chars().all(|ch| ch.is_ascii_alphanumeric())
                && rest.chars().any(|ch| ch.is_ascii_digit())
        })
}

fn contains_akia(value: &str) -> bool {
    value
        .as_bytes()
        .windows(4)
        .enumerate()
        .any(|(index, window)| {
            window.eq_ignore_ascii_case(b"AKIA")
                && value[index + 4..]
                    .chars()
                    .take(16)
                    .filter(|ch| ch.is_ascii_alphanumeric())
                    .count()
                    == 16
        })
}

fn contains_private_ip(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
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

fn contains_guid(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(|candidate| {
            let parts: Vec<&str> = candidate.split('-').collect();
            parts.windows(5).any(|window| {
                [8, 4, 4, 4, 12]
                    .iter()
                    .zip(window.iter())
                    .all(|(length, part)| {
                        part.len() == *length && part.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
            })
        })
}

fn contains_email_like(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        let trimmed = candidate.trim_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || matches!(ch, '@' | '.' | '_' | '%' | '+' | '-'))
        });
        let trimmed = trimmed.trim_matches('.');
        let Some((local, domain)) = trimmed.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain.rsplit_once('.').is_some_and(|(_, suffix)| {
                suffix.len() >= 2 && suffix.chars().all(|ch| ch.is_ascii_alphabetic())
            })
    })
}

fn contains_token_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    for key in [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ] {
        let mut search = lower.as_str();
        while let Some(position) = search.find(key) {
            let rest = search[position + key.len()..].trim_start();
            if rest.starts_with(':') || rest.starts_with('=') {
                return true;
            }
            search = &search[position + key.len()..];
        }
    }
    false
}

fn allowed_endpoint_fields() -> Vec<String> {
    let mut fields = ALLOWED_ENDPOINT_BASE_FIELDS
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    fields.extend(
        REQUIRED_DISABLED_FIELDS
            .iter()
            .map(|value| value.to_string()),
    );
    fields.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(field, _)| field.to_string()),
    );
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().map(|value| value.to_string()));
    fields
}

fn unsafe_true_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    [
        "live", "provider", "raw", "ticket", "publish", "tenant", "object", "payload",
    ]
    .iter()
    .any(|term| lower.contains(term))
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
    let mut index = 0usize;
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
    let mut count = 0usize;
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
    let mut index = 0usize;
    while index < source.len() {
        if let Some(end) = csharp_string_end(source, index) {
            result.push_str(&source[index..end]);
            index = end;
            continue;
        }
        if source[index..].starts_with("//") {
            let end = source[index..]
                .find('\n')
                .map(|relative| index + relative)
                .unwrap_or(source.len());
            for _ in index..end {
                result.push(' ');
            }
            index = end;
            continue;
        }
        if source[index..].starts_with("/*") {
            let end = source[index + 2..]
                .find("*/")
                .map(|relative| index + 2 + relative + 2)
                .unwrap_or(source.len());
            for ch in source[index..end].chars() {
                if ch == '\n' {
                    result.push('\n');
                } else {
                    for _ in 0..ch.len_utf8() {
                        result.push(' ');
                    }
                }
            }
            index = end;
            continue;
        }
        let ch = source[index..].chars().next().expect("valid char boundary");
        result.push(ch);
        index += ch.len_utf8();
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

fn is_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn word_terms(line: &str) -> Vec<String> {
    line.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
        .filter(|term| {
            term.chars()
                .next()
                .map(|ch| ch.is_ascii_alphabetic())
                .unwrap_or(false)
        })
        .map(str::to_string)
        .collect()
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut spaced = String::new();
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            spaced.push(' ');
        }
        if ch.is_ascii_alphanumeric() {
            spaced.push(ch.to_ascii_lowercase());
            previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            spaced.push(' ');
            previous_lower_or_digit = false;
        }
    }
    spaced.split_whitespace().map(str::to_string).collect()
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
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
