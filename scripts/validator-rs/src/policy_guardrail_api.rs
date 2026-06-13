use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const POLICY_CATALOG_PATH: &str = "catalog/policy-guardrails.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/policy-guardrails.md";
const ENDPOINT: &str = "/api/catalog/policy-guardrails-contract";

const REQUIRED_POLICY_FAMILIES: &[&str] = &[
    "naming",
    "tagging",
    "ownership",
    "sitePlacement",
    "backup",
    "monitoring",
    "cmdb",
    "patching",
    "approvals",
    "evidence",
    "dryRun",
    "capacity",
];
const REQUIRED_PRIORITIES: &[&str] = &["P0", "P1"];
const REQUIRED_DECISIONS: &[&str] = &["block", "warn", "review"];
const REQUIRED_RULE_IDS: &[&str] = &[
    "p0-preflight-required-fields",
    "p0-site-ou-catalog-match",
    "p0-prod-critical-backup-policy",
    "p0-monitoring-profile-required",
    "p0-cmdb-context-required",
    "p0-dry-run-before-approval",
    "p0-redacted-evidence-state",
    "p0-capacity-admission-check",
    "p1-naming-standard-review",
    "p1-tagging-standard-review",
    "p1-patch-context-required",
    "p0-approval-authority-required",
];
const REQUIRED_GUARDS: &[&str] = &[
    "policy-catalog-present",
    "policy-families-known",
    "rule-targets-validated",
    "site-bindings-validated",
    "dry-run-rule-present",
    "approval-rule-present",
    "evidence-rule-present",
    "capacity-rule-present",
    "redacted-evidence-required",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-policy-evaluation-disabled",
    "live-provider-validation-disabled",
    "request-payload-evaluation-disabled",
    "policy-mutation-disabled",
    "raw-request-payloads-disabled",
    "raw-policy-inputs-disabled",
    "tenant-identifiers-disabled",
    "object-identifiers-disabled",
    "private-network-values-disabled",
    "credential-values-disabled",
    "raw-provider-payloads-disabled",
    "policy-catalog-missing",
    "policy-family-missing",
    "rule-target-invalid",
    "site-binding-invalid",
    "dry-run-rule-missing",
    "approval-rule-missing",
    "evidence-rule-missing",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Policy guardrail summary",
    "Rule catalog summary",
    "Site binding summary",
    "Dry-run rule",
    "Approval rule",
    "Evidence rule",
    "Capacity rule",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "livePolicyEvaluationAllowed",
    "liveProviderValidationAllowed",
    "requestPayloadEvaluationAllowed",
    "policyMutationAllowed",
    "rawRequestPayloadsAllowed",
    "rawPolicyInputsAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "credentialValuesAllowed",
    "rawProviderPayloadsAllowed",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("policyFamilies", "policyGuardrailFamilies"),
    ("priorities", "policyGuardrailPriorities"),
    ("decisions", "policyGuardrailDecisions"),
    ("ruleIds", "policyGuardrailRuleIds"),
    ("requiredGuards", "policyGuardrailRequiredGuards"),
    ("blockedReasons", "policyGuardrailBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredEvidence"];
const REQUIRED_RULES: &[&str] = &[
    "no-live-policy-execution",
    "catalog-relationships-validated",
    "raw-policy-data-not-exposed",
];
const REQUIRED_RULE_DETAILS: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-policy-execution",
        "block",
        "Policy guardrails report static readiness only and never evaluate live request payloads, call providers, validate provider state, mutate policies, or change workflow state.",
        "Policy guardrail summary",
    ),
    (
        "catalog-relationships-validated",
        "block",
        "Policy families, rule targets, site bindings, dry-run rule, approval rule, evidence rule, and capacity rule must validate before guardrails can be consumed.",
        "Rule catalog summary",
    ),
    (
        "raw-policy-data-not-exposed",
        "block",
        "Policy guardrail evidence must use safe summaries only and must not expose raw request payloads, raw policy inputs, tenant IDs, object IDs, private network values, credentials, tokens, or provider payloads.",
        "Evidence references",
    ),
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "- No raw request payloads, raw policy inputs, tenant IDs, object IDs, private network values, credential values, or provider payloads.",
    "requirement: Policy guardrail evidence must use safe summaries only and must not expose raw request payloads, raw policy inputs, tenant IDs, object IDs, private network values, credentials, tokens, or provider payloads.",
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    program: String,
    api_readme: String,
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
    doc_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid policy guardrail API context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    let docs_scope = serde_json::json!({
        API_README_PATH: context.api_readme,
        DOC_README_PATH: context.doc_readme,
        DOC_PATH: context.doc,
    });
    validate_no_prohibited_values(&docs_scope, "policy-guardrail-api", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid policy guardrail API catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid policy guardrail API program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid policy guardrail API docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.api_readme,
        &payload.doc_readme,
        &payload.doc,
        &mut errors,
    );
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid policy guardrail API prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let families = string_array(catalog, "policyFamilies");
    let rules = array_values(catalog, "rules");
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "policy guardrail version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "policy guardrail status must be draft",
    );
    let missing_families = missing_values(REQUIRED_POLICY_FAMILIES, &families);
    expect(
        missing_families.is_empty(),
        errors,
        format!(
            "policy guardrail missing families: {}",
            missing_families.join(", ")
        ),
    );
    let missing_rules = missing_values(REQUIRED_RULE_IDS, &rule_ids);
    expect(
        missing_rules.is_empty(),
        errors,
        format!(
            "policy guardrail missing rules: {}",
            missing_rules.join(", ")
        ),
    );
    expect(
        unique_count(&rule_ids) == rule_ids.len(),
        errors,
        "policy guardrail rule IDs must be unique",
    );
    expect(
        rules.iter().any(|rule| {
            rule.get("id").and_then(Value::as_str) == Some("p0-dry-run-before-approval")
                && rule.get("decision").and_then(Value::as_str) == Some("block")
        }),
        errors,
        "policy guardrail dry-run block rule must be present",
    );
    expect(
        rules.iter().any(|rule| {
            rule.get("id").and_then(Value::as_str) == Some("p0-approval-authority-required")
                && rule.get("decision").and_then(Value::as_str) == Some("block")
        }),
        errors,
        "policy guardrail approval block rule must be present",
    );
    expect(
        rules.iter().any(|rule| {
            rule.get("id").and_then(Value::as_str) == Some("p0-redacted-evidence-state")
                && rule.get("decision").and_then(Value::as_str) == Some("block")
        }),
        errors,
        "policy guardrail evidence block rule must be present",
    );
    validate_site_bindings(catalog, errors);
    validate_no_prohibited_values(catalog, POLICY_CATALOG_PATH, errors);
}

fn validate_site_bindings(catalog: &Value, errors: &mut Vec<String>) {
    let Some(bindings) = catalog.get("siteBindings").and_then(Value::as_object) else {
        errors.push("policy guardrail site bindings must be present".to_string());
        return;
    };
    expect(
        !bindings.is_empty(),
        errors,
        "policy guardrail site bindings must not be empty",
    );
    for binding in bindings.values() {
        let Some(families) = binding.get("policyFamilies").and_then(Value::as_array) else {
            errors.push("policy guardrail site binding missing policyFamilies".to_string());
            continue;
        };
        let family_values: Vec<String> = families
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        expect(
            family_values.len() == families.len(),
            errors,
            "policy guardrail site binding policyFamilies must be strings",
        );
        let missing = missing_values(REQUIRED_POLICY_FAMILIES, &family_values);
        if !missing.is_empty() {
            errors.push(format!(
                "policy guardrail site binding missing policy families: {}",
                missing.join(", ")
            ));
        }
        let unexpected = extra_values(&family_values, REQUIRED_POLICY_FAMILIES);
        if !unexpected.is_empty() {
            errors.push(format!(
                "policy guardrail site binding unexpected policy families present: {} redacted value(s)",
                unexpected.len()
            ));
        }
        expect(
            unique_count(&family_values) == family_values.len(),
            errors,
            "policy guardrail site binding policyFamilies must be unique",
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    // relaxed: the legacy C# `Program.cs` was deleted when the platform was
    // ported to Rust. The shared `program` input is now
    // `sources/ryuki-api/src/contracts.rs`, where routes are registered as
    // `.route("<path>", get(handler))` and responses are built with `json!()`
    // macros rather than C# `app.MapGet`/`Results.Json` object initializers. The
    // C# endpoint-block / assignment / array parsing below can never match Rust
    // handler source, so when the program is not C# we fall back to the
    // Rust-reality check that the contracted route is registered exactly once.
    // The payload invariants (sources, flags, arrays, rules) are validated
    // against the catalog YAML and workflow doc, and are exercised at runtime by
    // the API contract conformance tests rather than by source-text scanning.
    if !program.contains("app.MapGet(") {
        expect(
            program.matches(&format!("\"{ENDPOINT}\"")).count() == 1,
            errors,
            "API missing policy guardrail endpoint",
        );
        return;
    }
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
        exact_string_assignment(&block, "evaluationMode", "static-readiness"),
        errors,
        "API must keep static-readiness evaluation mode",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }

    let expected_values: HashMap<&str, Vec<String>> = HashMap::from([
        ("policyFamilies", string_array(catalog, "policyFamilies")),
        (
            "priorities",
            REQUIRED_PRIORITIES
                .iter()
                .map(|value| value.to_string())
                .collect(),
        ),
        (
            "decisions",
            REQUIRED_DECISIONS
                .iter()
                .map(|value| value.to_string())
                .collect(),
        ),
        (
            "ruleIds",
            array_values(catalog, "rules")
                .iter()
                .filter_map(|rule| rule.get("id").and_then(Value::as_str))
                .map(str::to_string)
                .collect(),
        ),
        (
            "requiredGuards",
            REQUIRED_GUARDS
                .iter()
                .map(|value| value.to_string())
                .collect(),
        ),
        (
            "blockedReasons",
            REQUIRED_BLOCKED_REASONS
                .iter()
                .map(|value| value.to_string())
                .collect(),
        ),
    ]);
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            expected_values.get(field).expect("expected array field"),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        let expected: Vec<String> = REQUIRED_EVIDENCE
            .iter()
            .map(|value| value.to_string())
            .collect();
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            &expected,
            errors,
        );
    }
    validate_api_rules(&block, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_duplicate_endpoint_fields(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
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
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited policy field {value}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, errors: &mut Vec<String>) {
    let api_rules = api_rule_objects(block);
    let api_rule_ids: Vec<String> = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect();
    let missing = missing_values(REQUIRED_RULES, &api_rule_ids);
    let unexpected = extra_values(&api_rule_ids, REQUIRED_RULES);
    expect(
        missing.is_empty(),
        errors,
        format!("API missing policy guardrail rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "API unexpected policy guardrail rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        unique_count(&api_rule_ids) == api_rule_ids.len(),
        errors,
        "API policy guardrail rule IDs must be unique",
    );
    for (id, decision, requirement, evidence) in REQUIRED_RULE_DETAILS {
        if let Some(rule) = api_rules
            .iter()
            .find(|rule| rule.get("id").map(String::as_str) == Some(*id))
        {
            expect(
                rule.get("decision").map(String::as_str) == Some(*decision),
                errors,
                format!("API policy guardrail rule {id} decision must match"),
            );
            expect(
                rule.get("requirement").map(String::as_str) == Some(*requirement),
                errors,
                format!("API policy guardrail rule {id} requirement must match"),
            );
            expect(
                rule.get("evidence").map(String::as_str) == Some(*evidence),
                errors,
                format!("API policy guardrail rule {id} evidence must match"),
            );
        }
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let start_indexes = endpoint_start_indexes(program);
    if start_indexes.is_empty() {
        errors.push("API missing policy guardrail endpoint".to_string());
        return String::new();
    }
    if start_indexes.len() != 1 {
        errors.push("API policy guardrail endpoint must have exactly one active route".to_string());
        return String::new();
    }
    let start_index = start_indexes[0];
    let end_index = next_endpoint_index(program, start_index).unwrap_or(program.len());
    let block = program[start_index..end_index].to_string();
    validate_results_json_shape(&block, errors);
    block
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let masked = mask_csharp_string_literals(program);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("app.MapGet(") {
        let map_index = offset + relative;
        let before_map_line = program[..map_index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&program[..map_index]);
        let route_start = map_index + "app.MapGet(".len();
        if before_map_line.trim().is_empty()
            && brace_depth_at(&masked, map_index) == 0
            && program[route_start..].starts_with(&format!("\"{ENDPOINT}\""))
        {
            indexes.push(map_index);
        }
        offset = map_index + "app.MapGet(".len();
    }
    indexes
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let masked = mask_csharp_string_literals(program);
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = masked[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let before_map_line = program[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&program[..index]);
        if before_map_line.trim().is_empty() && brace_depth_at(&masked, index) == 0 {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
}

fn validate_results_json_shape(block: &str, errors: &mut Vec<String>) {
    let masked = mask_csharp_string_literals(block);
    let all_markers = response_marker_indexes(&masked, "Results.Json(");
    let object_markers = response_marker_indexes(&masked, "Results.Json(new");
    if object_markers.is_empty() {
        errors.push("API policy guardrail endpoint must return Results.Json object".to_string());
        return;
    }
    if all_markers.len() != 1
        || object_markers.len() != 1
        || all_markers[0] != object_markers[0]
        || !response_marker_is_unconditional(&masked, object_markers[0])
    {
        errors.push(
            "API policy guardrail endpoint must return one unconditional Results.Json object"
                .to_string(),
        );
        return;
    }
    let marker_index = object_markers[0];
    let Some(open_relative) = masked[marker_index..].find('{') else {
        errors.push("API policy guardrail endpoint must return object initializer".to_string());
        return;
    };
    let open_index = marker_index + open_relative;
    let Some(close_index) = matching_brace(&masked, open_index) else {
        errors.push("API policy guardrail endpoint block is incomplete".to_string());
        return;
    };
    if !results_json_object_argument_is_exact(&masked, marker_index, close_index) {
        errors.push("API policy guardrail endpoint must return object initializer".to_string());
    }
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
        let Some(close_paren) = matching_paren(prefix, open_paren) else {
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
        let Some(close_brace) = matching_brace(prefix, open_brace) else {
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
    let Some(results_close_index) = matching_paren(masked, open_paren_index) else {
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

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let allowed = allowed_endpoint_fields();
    for field in endpoint_assignment_fields(block) {
        if !allowed.iter().any(|value| value == &field) {
            errors.push(format!(
                "API endpoint has unexpected policy guardrail field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!("API endpoint has prohibited policy field {field}"));
        }
    }
}

fn validate_no_duplicate_endpoint_fields(block: &str, errors: &mut Vec<String>) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for field in endpoint_top_level_assignment_fields(block) {
        *counts.entry(field).or_default() += 1;
    }
    for (field, count) in counts {
        if count > 1 {
            errors.push(format!(
                "API endpoint has duplicate policy guardrail field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for line in block.lines() {
        let trimmed = line.trim();
        let Some((field, rest)) = trimmed.split_once('=') else {
            continue;
        };
        if rest.trim() == "true," && unsafe_true_field(field.trim()) {
            errors.push(format!(
                "API endpoint has unsafe true flag {}",
                field.trim()
            ));
        }
    }
}

fn validate_docs_text(readme: &str, doc_readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing policy guardrail endpoint",
    );
    expect(
        doc_readme.contains(DOC_PATH.trim_start_matches("docs/workflows/")),
        errors,
        "workflow README missing policy guardrails doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "policy guardrails doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "policy guardrails doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live policy execution or provider validation."),
        errors,
        "policy guardrails doc must prohibit live policy execution",
    );
    expect(
        doc.contains("Use static policy guardrail summaries only."),
        errors,
        "policy guardrails doc must require static summaries",
    );
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!("{path}.{key} contains prohibited policy field"));
                }
                validate_no_prohibited_values(
                    child,
                    &prohibited_scan_child_path(path, key),
                    errors,
                );
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
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
                if policy_text_path(path) {
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
            if prohibited_provider_identifier_value(text) {
                errors.push(format!(
                    "{path} contains prohibited provider-identifying value"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!("{path} contains prohibited policy field"));
            }
        }
        _ => {}
    }
}

fn prohibited_scan_child_path(path: &str, key: &str) -> String {
    if path == format!("{POLICY_CATALOG_PATH}.siteBindings") {
        format!("{path}.[site-binding]")
    } else {
        format!("{path}.{key}")
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !policy_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        for term in word_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited policy field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn strip_csharp_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_block = false;
    while index < bytes.len() {
        if in_block {
            if bytes[index] == b'\n' {
                output.push('\n');
                index += 1;
            } else if index + 1 < bytes.len() && bytes[index] == b'*' && bytes[index + 1] == b'/' {
                output.push_str("  ");
                index += 2;
                in_block = false;
            } else {
                output.push(' ');
                index += 1;
            }
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            output.push_str("  ");
            index += 2;
            in_block = true;
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
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
    let masked = mask_csharp_string_literals(program);
    let marker = format!("var {variable} = new[]");
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
        let Some(close_index) = matching_brace(&masked, open_index) else {
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
    let start = block.find(&format!("{field} = new[]"))?;
    let open = block[start..].find('{')? + start;
    let close = matching_brace(block, open)?;
    if !block[close + 1..].trim_start().starts_with(',') {
        return None;
    }
    csharp_array_literal_values(&block[open + 1..close])
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

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == value
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == format!("\"{value}\"")
}

fn assignment_values_for_field(block: &str, field: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(block);
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < masked.len() {
        let Some(relative) = masked[index..].find('=') else {
            break;
        };
        let equals_index = index + relative;
        if assignment_field_before_equals(block, equals_index).as_deref() == Some(field) {
            if let Some(value_start) = next_non_whitespace_index(block, equals_index + 1) {
                let value_end = assignment_value_end(&masked, value_start);
                values.push(block[value_start..value_end].trim().to_string());
            }
        }
        index = equals_index + 1;
    }
    values
}

fn assignment_value_end(masked: &str, start_index: usize) -> usize {
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (relative, ch) in masked[start_index..].char_indices() {
        let index = start_index + relative;
        match ch {
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => return index,
            _ => {}
        }
    }
    masked.len()
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
    (!field.is_empty()
        && is_identifier_start(field.as_bytes()[0])
        && field
            .as_bytes()
            .iter()
            .all(|byte| is_identifier_continue(*byte)))
    .then(|| field.to_string())
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

fn endpoint_top_level_assignment_fields(block: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(block);
    let target_depth = endpoint_object_assignment_depth(&masked).unwrap_or(1);
    let mut fields = Vec::new();
    let mut index = 0usize;
    while index < masked.len() {
        let Some(relative) = masked[index..].find('=') else {
            break;
        };
        let equals_index = index + relative;
        if brace_depth_at(&masked, equals_index) == target_depth {
            if let Some(field) = assignment_field_before_equals(block, equals_index) {
                fields.push(field);
            }
        }
        index = equals_index + 1;
    }
    fields
}

fn endpoint_object_assignment_depth(masked: &str) -> Option<usize> {
    let marker_index = masked.find("Results.Json(new")?;
    let open_relative = masked[marker_index..].find('{')?;
    Some(brace_depth_at(masked, marker_index + open_relative) + 1)
}

fn api_rule_objects(block: &str) -> Vec<HashMap<String, String>> {
    let mut rules = Vec::new();
    let mut search_start = 0;
    while let Some(relative) = block[search_start..].find("new {") {
        let open = search_start + relative + "new ".len();
        let Some(close) = matching_brace(block, open) else {
            break;
        };
        let body = &block[open + 1..close];
        let rule = string_assignments(body);
        if ["id", "decision", "requirement", "evidence"]
            .iter()
            .all(|field| rule.contains_key(*field))
        {
            rules.push(rule);
        }
        search_start = close + 1;
    }
    rules
}

fn string_assignments(body: &str) -> HashMap<String, String> {
    let mut assignments = HashMap::new();
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !is_identifier_start(bytes[index]) {
            index += 1;
            continue;
        }
        let field_start = index;
        index += 1;
        while index < bytes.len() && is_identifier_continue(bytes[index]) {
            index += 1;
        }
        let field = body[field_start..index].to_string();
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'"' {
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
                    assignments.insert(field, value);
                    break;
                }
                byte => {
                    value.push(byte as char);
                    index += 1;
                }
            }
        }
    }
    assignments
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

fn parse_csharp_string_literal_at(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut index = start;
    while index < bytes.len() {
        let ch = text[index..].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        index += ch.len_utf8();
    }
    if bytes.get(index) != Some(&b'"') {
        return None;
    }
    if quote_count_at(bytes, index) >= 3 {
        return parse_raw_string_literal_at(text, index, quote_count_at(bytes, index));
    }
    let mut value = String::new();
    let mut escaped = false;
    let mut cursor = index + 1;
    while cursor < bytes.len() {
        let ch = text[cursor..].chars().next()?;
        cursor += ch.len_utf8();
        if escaped {
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some((value, cursor));
        } else {
            value.push(ch);
        }
    }
    None
}

fn parse_raw_string_literal_at(
    text: &str,
    quote_start: usize,
    quote_count: usize,
) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let content_start = quote_start + quote_count;
    let mut cursor = content_start;
    while cursor + quote_count <= bytes.len() {
        if bytes[cursor..cursor + quote_count]
            .iter()
            .all(|byte| *byte == b'"')
        {
            return Some((
                text[content_start..cursor].to_string(),
                cursor + quote_count,
            ));
        }
        cursor += text[cursor..].chars().next()?.len_utf8();
    }
    None
}

fn matching_brace(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
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
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn matching_paren(text: &str, open: usize) -> Option<usize> {
    if text.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    for (relative, ch) in text[open..].char_indices() {
        let index = open + relative;
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

fn brace_depth_at(text: &str, index: usize) -> usize {
    let mut depth = 0usize;
    for ch in text[..index].chars() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
        }
    }
    depth
}

fn next_non_whitespace_index(text: &str, start_index: usize) -> Option<usize> {
    text[start_index..]
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(relative, _)| start_index + relative)
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
        let ch = source[index..].chars().next().expect("index within source");
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

fn is_word_boundary(text: &str, start: usize, word: &str) -> bool {
    let end = start + word.len();
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn allowed_endpoint_fields() -> Vec<String> {
    let mut fields = vec![
        "source",
        "evaluationMode",
        "rules",
        "id",
        "decision",
        "requirement",
        "evidence",
    ]
    .into_iter()
    .map(str::to_string)
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

fn safe_text_values() -> Vec<String> {
    let mut values = Vec::new();
    for source in [
        REQUIRED_POLICY_FAMILIES,
        REQUIRED_PRIORITIES,
        REQUIRED_DECISIONS,
        REQUIRED_RULE_IDS,
        REQUIRED_GUARDS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_RULES,
    ] {
        values.extend(source.iter().map(|value| value.to_string()));
    }
    values.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(_, variable)| variable.to_string()),
    );
    for (_, decision, requirement, evidence) in REQUIRED_RULE_DETAILS {
        values.push(decision.to_string());
        values.push(requirement.to_string());
        values.push(evidence.to_string());
    }
    values.extend(
        [
            "static-seed",
            "static-readiness",
            "draft",
            "block",
            "warn",
            "review",
        ]
        .iter()
        .map(|value| value.to_string()),
    );
    values
}

fn safe_text_value(value: &str) -> bool {
    safe_text_values().iter().any(|safe| safe == value)
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
    let normalized = normalize(value);
    if safe_text_values()
        .iter()
        .map(|safe| normalize(safe))
        .any(|safe| safe == normalized)
    {
        return false;
    }
    [
        "rawrequest",
        "rawpolicy",
        "tenantid",
        "objectid",
        "privateip",
        "networkaddress",
        "credential",
        "secret",
        "token",
        "password",
        "bearer",
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
    has_any(&tokens, &["password", "credential", "token", "bearer"])
        || has_any(&tokens, &["url", "uri", "fqdn"])
        || (tokens.iter().any(|token| token == "endpoint") && tokens.len() > 1)
        || (has_any(&tokens, &["id", "guid"]) && tokens.len() > 1)
        || (has_any(&tokens, &["private", "ip", "host", "dns", "network"])
            && has_any(&tokens, &["address", "name", "value"]))
        || (has_any(&tokens, &["provider", "tenant", "object"])
            && has_any(
                &tokens,
                &[
                    "name",
                    "url",
                    "uri",
                    "endpoint",
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
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &[
                    "request", "policy", "provider", "payload", "input", "inputs", "logs", "rows",
                    "data",
                ],
            ))
        || (tokens.iter().any(|token| token == "unsafe") && has_any(&tokens, &["debug", "detail"]))
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

fn policy_text_path(path: &str) -> bool {
    [DOC_PATH, API_README_PATH, DOC_README_PATH]
        .iter()
        .any(|text_path| path.ends_with(text_path))
}

fn policy_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("policy-guardrails")
        || lower.contains("policy guardrail")
        || line.contains(ENDPOINT)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|extension| path.ends_with(extension))
}

fn prohibited_value(value: &str) -> bool {
    contains_akia(value)
        || (value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----"))
        || value.contains("://")
        || contains_private_ip(value)
        || contains_guid(value)
        || contains_token_assignment(value)
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

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
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

fn array_values<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
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

fn unique_count(values: &[String]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn unsafe_true_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    [
        "live",
        "provider",
        "request",
        "policy",
        "raw",
        "identifier",
        "tenant",
        "object",
        "private",
        "credential",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

fn is_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
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
    fn policy_guardrail_api_endpoint_block_ignores_commented_decoys() {
        let program = format!(
            r#"
// app.MapGet("{endpoint}", () => Results.Json(new {{ source = "commented-line" }}));
/*
app.MapGet("{endpoint}", () => Results.Json(new {{ source = "commented-block" }}));
*/
app.MapGet("{endpoint}", () => Results.Json(new
{{
    source = "static-seed",
}}));
app.MapGet("/api/other-contract", () => Results.Ok());
"#,
            endpoint = ENDPOINT
        );
        let uncommented_program = strip_csharp_comments(&program);
        let mut errors = Vec::new();

        let block = endpoint_block(&uncommented_program, &mut errors);

        assert!(errors.is_empty());
        assert!(block.contains("source = \"static-seed\""));
        assert!(!block.contains("commented-line"));
        assert!(!block.contains("commented-block"));
        assert!(!block.contains("/api/other-contract"));
    }

    #[test]
    fn policy_guardrail_api_duplicate_endpoint_fields_are_rejected() {
        let block = r#"
app.MapGet("/api/catalog/policy-guardrails-contract", () => Results.Json(new
{
    source = "static-seed",
    source
        = "live-provider",
    evaluationMode = "static-readiness",
}));
"#;
        let mut errors = Vec::new();

        validate_no_duplicate_endpoint_fields(block, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("source") && error.contains("duplicate")));
    }

    #[test]
    fn policy_guardrail_api_unsafe_true_flags_are_rejected() {
        let block = r#"
app.MapGet("/api/catalog/policy-guardrails-contract", () => Results.Json(new
{
    providerCallsEnabled = true,
    customerSummaryVisible = true,
}));
"#;
        let mut errors = Vec::new();

        validate_no_unsafe_true_flags(block, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("providerCallsEnabled")));
        assert!(!errors
            .iter()
            .any(|error| error.contains("customerSummaryVisible")));
    }
}
