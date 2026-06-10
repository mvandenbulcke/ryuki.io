use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/datacenter-readiness-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/datacenter-readiness.md";
const ENDPOINT: &str = "/api/operations/datacenter-readiness-contract";

const REQUIRED_DOMAINS: &[&str] = &[
    "rack-space",
    "power",
    "cooling",
    "switchport",
    "vlan",
    "storage-pathing",
    "firmware-baseline",
    "support-coverage",
    "site-capacity",
];
const REQUIRED_INPUTS: &[&str] = &[
    "site",
    "requester",
    "owner",
    "hardwareProfile",
    "clusterProfile",
    "networkScope",
    "storageScope",
    "capacityNeed",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "site-known",
    "owner-known",
    "rack-capacity-known",
    "power-cooling-reviewed",
    "network-readiness-known",
    "storage-readiness-known",
    "firmware-baseline-known",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "siteSummary",
    "capacityReadiness",
    "networkReadiness",
    "storageReadiness",
    "firmwareAndSupport",
    "riskNotes",
    "remediationPlan",
    "handoverNotes",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "site-unknown",
    "owner-unknown",
    "rack-capacity-unknown",
    "power-cooling-not-reviewed",
    "network-readiness-unknown",
    "storage-readiness-unknown",
    "firmware-baseline-unknown",
    "support-coverage-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Site readiness summary",
    "Rack and power review",
    "Cooling review",
    "Network readiness summary",
    "Storage readiness summary",
    "Firmware and support baseline",
    "Capacity decision",
    "Risk notes",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "rawInventoryRowsAllowed",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("readinessDomains", "datacenterReadinessDomains"),
    ("requiredGuards", "datacenterReadinessRequiredGuards"),
    ("planSections", "datacenterReadinessPlanSections"),
    ("blockedReasons", "datacenterReadinessBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const SINGLETON_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "readinessMode",
    "rules",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "rawInventoryRowsAllowed",
    "readinessDomains",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredInputs",
    "requiredEvidence",
];
const NESTED_FIELD_NAMES: &[&str] = &[
    "source",
    "readinessMode",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "rawInventoryRowsAllowed",
    "readinessDomains",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredInputs",
    "requiredEvidence",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const SAFE_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "readinessMode",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "rawInventoryRowsAllowed",
    "readinessDomains",
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
const SAFE_TEXT_EXTRA: &[&str] = &[
    "draft",
    "static-seed",
    "review-only",
    "false",
    "datacenterReadinessDomains",
    "datacenterReadinessRequiredGuards",
    "datacenterReadinessPlanSections",
    "datacenterReadinessBlockedReasons",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
    "secret",
];

#[derive(Deserialize)]
struct ContextInput {
    catalog: Value,
    program: String,
    api_readme: String,
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
    doc: String,
}

#[derive(Deserialize)]
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

const REQUIRED_RULE_DETAILS: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-datacenter-actions",
        decision: "block",
        requirement: "Datacenter readiness contracts report review state only and never execute provider, switch, storage, or hardware actions.",
        evidence: "Site readiness summary",
    },
    RuleDetail {
        id: "network-storage-readiness-required",
        decision: "block",
        requirement: "Network and storage readiness must be known before hardware or cluster work proceeds.",
        evidence: "Network readiness summary",
    },
    RuleDetail {
        id: "capacity-decision-required",
        decision: "block",
        requirement: "Capacity decision must show rack, power, cooling, and site headroom before approval.",
        evidence: "Capacity decision",
    },
    RuleDetail {
        id: "firmware-support-baseline-required",
        decision: "block",
        requirement: "Firmware and support baseline must be known before datacenter execution can be considered.",
        evidence: "Firmware and support baseline",
    },
];

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ContextInput = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid datacenter readiness context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    for block in endpoint_blocks_for_scan(&context.program) {
        scan_prohibited_value(&Value::String(block), PROGRAM_PATH, &mut errors);
    }
    scan_prohibited_value(
        &Value::String(context.api_readme),
        API_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.doc), DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid datacenter readiness catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid datacenter readiness program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid datacenter readiness docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid datacenter readiness prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("datacenter readiness catalog must be a mapping".to_string());
        return;
    };

    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "datacenter readiness version must be 1",
    );
    expect(
        string_field(catalog, "status") == Some("draft"),
        errors,
        "datacenter readiness status must be draft",
    );
    expect(
        string_field(catalog, "source") == Some("static-seed"),
        errors,
        "datacenter readiness source must be static-seed",
    );
    expect(
        string_field(catalog, "readinessMode") == Some("review-only"),
        errors,
        "datacenter readiness mode must be review-only",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_field(catalog, field) == Some(false),
            errors,
            &format!("datacenter readiness {field} must be disabled"),
        );
    }

    validate_required_array(catalog, "readinessDomains", REQUIRED_DOMAINS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);

    for key in map.keys() {
        if prohibited_field(key) && !SAFE_CATALOG_KEYS.contains(&key.as_str()) {
            errors.push(format!(
                "catalog/datacenter-readiness-contract.yaml.{key} contains prohibited datacenter readiness field"
            ));
        }
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_field(catalog, field);
    if values.is_empty() {
        errors.push(format!("{field} must be non-empty array"));
    }
    let required: BTreeSet<&str> = required_values.iter().copied().collect();
    let actual: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let missing = set_difference(&required, &actual);
    let unexpected = set_difference(&actual, &required);
    if !missing.is_empty() {
        errors.push(format!("{field} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    if actual.len() != values.len() {
        errors.push(format!("{field} values must be unique"));
    }
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited datacenter readiness value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| string_field(rule, "id").map(str::to_string))
        .collect();
    let rule_details: Vec<(String, String, String)> = rules
        .iter()
        .map(|rule| {
            (
                string_field(rule, "decision")
                    .unwrap_or_default()
                    .to_string(),
                string_field(rule, "requirement")
                    .unwrap_or_default()
                    .to_string(),
                string_field(rule, "evidence")
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect();
    let required_ids: BTreeSet<&str> = REQUIRED_RULE_DETAILS.iter().map(|rule| rule.id).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().map(String::as_str).collect();
    let missing = set_difference(&required_ids, &actual_ids);
    let unexpected = set_difference(&actual_ids, &required_ids);
    if !missing.is_empty() {
        errors.push(format!(
            "datacenter readiness missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "datacenter readiness unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    if actual_ids.len() != rule_ids.len() {
        errors.push("datacenter readiness rule IDs must be unique".to_string());
    }
    let unique_details: BTreeSet<(String, String, String)> = rule_details.iter().cloned().collect();
    if unique_details.len() != rule_details.len() {
        errors.push("datacenter readiness rule details must be unique".to_string());
    }
    for rule in &rules {
        let id = string_field(rule, "id").unwrap_or("(missing id)");
        let keys: Vec<String> = rule
            .as_object()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        let key_set: BTreeSet<&str> = keys.iter().map(String::as_str).collect();
        let expected_key_set: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
        let unexpected_keys = set_difference(&key_set, &expected_key_set);
        let missing_keys = set_difference(&expected_key_set, &key_set);
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "datacenter readiness rule {id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "datacenter readiness rule {id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
    for expected_rule in REQUIRED_RULE_DETAILS {
        let Some(rule) = rules
            .iter()
            .find(|candidate| string_field(candidate, "id") == Some(expected_rule.id))
        else {
            continue;
        };
        for (field, expected) in [
            ("decision", expected_rule.decision),
            ("requirement", expected_rule.requirement),
            ("evidence", expected_rule.evidence),
        ] {
            if string_field(rule, field) != Some(expected) {
                errors.push(format!(
                    "datacenter readiness rule {} {field} must match",
                    expected_rule.id
                ));
            }
        }
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let endpoint = endpoint_block(&uncommented_program, errors);
    for (_, variable) in ENDPOINT_ARRAY_BINDINGS {
        validate_bound_array_immutable(&uncommented_program, variable, errors);
    }
    if endpoint.is_empty() {
        return;
    }
    let block = endpoint_contract_body(&endpoint, errors);
    if block.is_empty() {
        return;
    }

    validate_endpoint_singleton_fields(&block, errors);
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "readinessMode", "review-only"),
        errors,
        "API must keep review-only readiness mode",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            &format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            &format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable, field, errors),
            string_array_field(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field, errors),
            string_array_field(catalog, field),
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_no_nested_endpoint_fields(&block, errors);
}

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let start_indexes = endpoint_start_indexes(uncommented_program);
    if start_indexes.is_empty() {
        errors.push("API missing datacenter readiness endpoint".to_string());
        return String::new();
    }
    if start_indexes.len() != 1 {
        errors.push("API must expose exactly one datacenter readiness endpoint".to_string());
        return String::new();
    }
    let start = start_indexes[0];
    let next = map_get_start_indexes(uncommented_program)
        .into_iter()
        .find(|index| *index > start)
        .unwrap_or(uncommented_program.len());
    uncommented_program[start..next].to_string()
}

fn endpoint_start_indexes(uncommented_program: &str) -> Vec<usize> {
    line_start_indexes(uncommented_program)
        .into_iter()
        .filter(|start| {
            uncommented_program[*start..]
                .lines()
                .next()
                .map(compact_whitespace)
                .is_some_and(|line| line.starts_with(&format!("app.MapGet(\"{ENDPOINT}\",")))
        })
        .collect()
}

fn map_get_start_indexes(uncommented_program: &str) -> Vec<usize> {
    line_start_indexes(uncommented_program)
        .into_iter()
        .filter(|start| {
            uncommented_program[*start..]
                .lines()
                .next()
                .map(compact_whitespace)
                .is_some_and(|line| line.starts_with("app.MapGet("))
        })
        .collect()
}

fn endpoint_blocks_for_scan(program: &str) -> Vec<String> {
    let uncommented_program = csharp_without_comments(program);
    endpoint_start_indexes(&uncommented_program)
        .into_iter()
        .map(|start| {
            let next = map_get_start_indexes(&uncommented_program)
                .into_iter()
                .find(|index| *index > start)
                .unwrap_or(uncommented_program.len());
            program[start..next].to_string()
        })
        .collect()
}

fn endpoint_contract_body(endpoint: &str, errors: &mut Vec<String>) -> String {
    let compact = compact_with_map(endpoint);
    let expected_prefix = format!("app.MapGet(\"{ENDPOINT}\",()=>Results.Json(new{{");
    if !compact.text.starts_with(&expected_prefix) {
        errors.push(
            "API endpoint must use a literal expression-bodied datacenter readiness contract response"
                .to_string(),
        );
        return String::new();
    }

    let json_indexes = compact_indexes(endpoint, "Results.Json(");
    if json_indexes.len() != 1 {
        errors.push(
            "API endpoint must include exactly one returned datacenter readiness contract object"
                .to_string(),
        );
        return String::new();
    }

    let object_compact_pos = expected_prefix.len() - 1;
    let object_start = compact.map[object_compact_pos];
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API endpoint returned contract object is incomplete".to_string());
        return String::new();
    };
    if compact_whitespace(&endpoint[(object_end + 1)..]) != "));" {
        errors.push("API datacenter readiness endpoint has unsafe response tail".to_string());
        return String::new();
    }

    endpoint[(object_start + 1)..object_end].to_string()
}

fn validate_endpoint_singleton_fields(block: &str, errors: &mut Vec<String>) {
    for field in SINGLETON_ENDPOINT_FIELDS {
        let count = top_level_assignment_positions(block, field).len();
        expect(
            count == 1,
            errors,
            &format!("API endpoint top-level field {field} must appear exactly once"),
        );
    }
}

fn exact_assignment(block: &str, field: &str, expected: &str) -> bool {
    let values = top_level_assignment_values(block, field);
    values.len() == 1 && values[0] == expected
}

fn exact_string_assignment(block: &str, field: &str, expected: &str) -> bool {
    exact_assignment(block, field, &format!("\"{expected}\""))
}

fn top_level_assignment_values(block: &str, field: &str) -> Vec<String> {
    top_level_assignment_positions(block, field)
        .into_iter()
        .filter_map(|position| assignment_value(block, position))
        .collect()
}

fn top_level_assignment_positions(block: &str, field: &str) -> Vec<usize> {
    let text = csharp_without_comments(block);
    let bytes = text.as_bytes();
    let mut positions = Vec::new();
    let mut index = 0;
    while index + field.len() <= text.len() {
        if &text[index..index + field.len()] == field
            && is_identifier_boundary(bytes, index, field.len())
        {
            let mut cursor = index + field.len();
            while cursor < text.len() && text.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < text.len()
                && text.as_bytes()[cursor] == b'='
                && brace_depth_at(&text, index) == 0
            {
                positions.push(index);
            }
        }
        index += 1;
    }
    positions
}

fn assignment_value(block: &str, field_start: usize) -> Option<String> {
    let bytes = block.as_bytes();
    let mut cursor = field_start;
    while cursor < block.len() && bytes[cursor] != b'=' {
        cursor += 1;
    }
    if cursor == block.len() {
        return None;
    }
    cursor += 1;
    let start = cursor;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    while cursor < block.len() {
        let byte = bytes[cursor];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b'{' || byte == b'(' || byte == b'[' {
            depth += 1;
        } else if byte == b'}' || byte == b')' || byte == b']' {
            if depth == 0 && byte == b'}' {
                return Some(block[start..cursor].trim().to_string());
            }
            if depth > 0 {
                depth -= 1;
            }
        } else if (byte == b',' || byte == b';') && depth == 0 {
            return Some(block[start..cursor].trim().to_string());
        }
        cursor += 1;
    }
    Some(block[start..].trim().to_string())
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    let text = csharp_without_comments(block);
    let bytes = text.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < text.len() {
        if bytes[index].is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < text.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            let field = &text[start..index];
            let mut cursor = index;
            while cursor < text.len() && text.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < text.len() && bytes[cursor] == b'=' && brace_depth_at(&text, start) == 0 {
                fields.push(field.to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let positions = variable_assignment_positions(program, variable);
    if positions.len() != 1 {
        errors.push(format!("API {variable} must be assigned once"));
        return None;
    }
    let value = assignment_value(program, positions[0])?;
    let Some(body) = braced_body_after_prefix(&value, "new[]") else {
        errors.push(format!("API {field} missing literal array"));
        return None;
    };
    Some(csharp_array_literal_values(
        body,
        &format!("API {field}"),
        errors,
    ))
}

fn variable_assignment_positions(program: &str, variable: &str) -> Vec<usize> {
    let text = csharp_without_comments(program);
    let bytes = text.as_bytes();
    let mut positions = Vec::new();
    let mut index = 0;
    while index + variable.len() <= text.len() {
        if &text[index..index + variable.len()] == variable
            && is_identifier_boundary(bytes, index, variable.len())
        {
            let mut cursor = index + variable.len();
            while cursor < text.len() && text.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < text.len() && text.as_bytes()[cursor] == b'=' {
                positions.push(index);
            }
        }
        index += 1;
    }
    positions
}

fn validate_bound_array_immutable(program: &str, variable: &str, errors: &mut Vec<String>) {
    let references = identifier_positions(program, variable).len();
    if references > 2 {
        errors.push(format!("API bound array {variable} must remain immutable"));
    }
}

fn identifier_positions(text: &str, identifier: &str) -> Vec<usize> {
    let scrubbed = strip_csharp_string_literals(text);
    let bytes = scrubbed.as_bytes();
    let mut positions = Vec::new();
    let mut index = 0;
    while index + identifier.len() <= scrubbed.len() {
        if &scrubbed[index..index + identifier.len()] == identifier
            && is_identifier_boundary(bytes, index, identifier.len())
        {
            positions.push(index);
        }
        index += 1;
    }
    positions
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let values = top_level_assignment_values(block, field);
    if values.len() != 1 {
        errors.push(format!("API missing {field} literal array"));
        return None;
    }
    let Some(body) = braced_body_after_prefix(&values[0], "new[]") else {
        errors.push(format!("API missing {field} literal array"));
        return None;
    };
    Some(csharp_array_literal_values(
        body,
        &format!("API {field}"),
        errors,
    ))
}

fn braced_body_after_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let trimmed = value.trim();
    if !compact_whitespace(trimmed).starts_with(prefix) {
        return None;
    }
    let start = trimmed.find('{')?;
    let end = matching_brace_index(trimmed, start)?;
    if !trimmed[(end + 1)..].trim().is_empty() {
        return None;
    }
    Some(&trimmed[(start + 1)..end])
}

fn csharp_array_literal_values(body: &str, label: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    for member in split_top_level_members(body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if let Some(value) = quoted_value(text) {
            values.push(value);
        } else {
            errors.push(format!(
                "{label} literal array must use literal string entries"
            ));
        }
    }
    values
}

fn validate_api_array(
    field: &str,
    values: Option<Vec<String>>,
    catalog_values: Vec<String>,
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} literal array"));
        return;
    };
    let actual: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let catalog: BTreeSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let missing = set_difference(&catalog, &actual);
    let unexpected = set_difference(&actual, &catalog);
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
    if actual.len() != values.len() {
        errors.push(format!("API {field} values must be unique"));
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules_body) = endpoint_rules_body(block, errors) else {
        return;
    };
    let api_rules = parse_api_rule_objects(&rules_body, errors);
    let catalog_rules = catalog_rules(catalog);
    let catalog_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let catalog_set: BTreeSet<&str> = catalog_ids.iter().map(String::as_str).collect();
    let api_set: BTreeSet<&str> = api_ids.iter().map(String::as_str).collect();
    for missing in set_difference(&catalog_set, &api_set) {
        errors.push(format!("API missing rule {missing}"));
    }
    for unexpected in set_difference(&api_set, &catalog_set) {
        errors.push(format!("API has unexpected rule {unexpected}"));
    }
    if api_set.len() != api_ids.len() {
        errors.push("API rule IDs must be unique".to_string());
    }
    let detail_count: BTreeSet<(String, String, String)> = api_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.clone(),
                rule.requirement.clone(),
                rule.evidence.clone(),
            )
        })
        .collect();
    if detail_count.len() != api_rules.len() {
        errors.push("API rule details must be unique".to_string());
    }
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            continue;
        };
        if api_rule.decision != catalog_rule.decision {
            errors.push(format!(
                "API rule {} decision must match catalog",
                catalog_rule.id
            ));
        }
        if api_rule.requirement != catalog_rule.requirement {
            errors.push(format!(
                "API rule {} requirement must match catalog",
                catalog_rule.id
            ));
        }
        if api_rule.evidence != catalog_rule.evidence {
            errors.push(format!(
                "API rule {} evidence must match catalog",
                catalog_rule.id
            ));
        }
    }
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let values = top_level_assignment_values(block, "rules");
    if values.len() != 1 {
        errors.push("API rules top-level field must appear exactly once".to_string());
        return None;
    }
    let value = values[0].trim();
    if !compact_whitespace(value).starts_with("new[]") {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    }
    let Some(start) = value.find('{') else {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    };
    let Some(end) = matching_brace_index(value, start) else {
        errors.push("API rules literal array is incomplete".to_string());
        return None;
    };
    if !value[(end + 1)..].trim().is_empty() {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    }
    Some(value[(start + 1)..end].to_string())
}

fn parse_api_rule_objects(rules_body: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let mut rules = Vec::new();
    for member in split_top_level_members(rules_body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if !compact_whitespace(text).starts_with("new{") {
            errors.push("API rules must contain only literal rule objects".to_string());
            continue;
        }
        let Some(start) = text.find('{') else {
            errors.push("API rules must contain only literal rule objects".to_string());
            continue;
        };
        let Some(end) = matching_brace_index(text, start) else {
            errors.push("API rules must contain only literal rule objects".to_string());
            continue;
        };
        if !text[(end + 1)..].trim().is_empty() {
            errors.push("API rules must contain only literal rule objects".to_string());
            continue;
        }
        let object = &text[(start + 1)..end];
        let fields = top_level_assignment_fields(object);
        let unique_fields: BTreeSet<&str> = fields.iter().map(String::as_str).collect();
        let duplicate_fields: Vec<&str> = unique_fields
            .iter()
            .copied()
            .filter(|field| fields.iter().filter(|item| item.as_str() == *field).count() > 1)
            .collect();
        if !duplicate_fields.is_empty() {
            errors.push(format!(
                "API rule object has duplicate rule fields: {}",
                duplicate_fields.join(", ")
            ));
        }
        for field in &fields {
            if !RULE_KEYS.contains(&field.as_str()) {
                errors.push(format!(
                    "API rule object has unexpected rule fields: {field}"
                ));
            }
        }
        for required in RULE_KEYS {
            if !fields.iter().any(|field| field == required) {
                errors.push(format!(
                    "API rule object has missing rule fields: {required}"
                ));
            }
        }
        rules.push(Rule {
            id: rule_string_field(object, "id").unwrap_or_default(),
            decision: rule_string_field(object, "decision").unwrap_or_default(),
            requirement: rule_string_field(object, "requirement").unwrap_or_default(),
            evidence: rule_string_field(object, "evidence").unwrap_or_default(),
        });
    }
    if rules.is_empty() {
        errors.push("API rules must include literal rule objects".to_string());
    }
    rules
}

fn rule_string_field(object_block: &str, field: &str) -> Option<String> {
    let values: Vec<String> = top_level_assignment_values(object_block, field)
        .into_iter()
        .filter_map(|value| quoted_value(&value))
        .collect();
    (values.len() == 1).then(|| values[0].clone())
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if SINGLETON_ENDPOINT_FIELDS.contains(&field.as_str()) {
            if prohibited_field(&field) && !SAFE_CATALOG_KEYS.contains(&field.as_str()) {
                errors.push(format!(
                    "API endpoint has prohibited top-level datacenter readiness field {field}"
                ));
            }
        } else {
            errors.push(format!(
                "API endpoint has unexpected top-level datacenter readiness field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        let values = top_level_assignment_values(block, &field);
        if values.len() != 1 || values[0] != "true" {
            continue;
        }
        if field.to_ascii_lowercase().contains("live")
            || field.to_ascii_lowercase().contains("provider")
            || field.to_ascii_lowercase().contains("worker")
            || field.to_ascii_lowercase().contains("raw")
            || field.to_ascii_lowercase().contains("credential")
            || field.to_ascii_lowercase().contains("tenant")
            || field.to_ascii_lowercase().contains("object")
            || field.to_ascii_lowercase().contains("private")
            || field.to_ascii_lowercase().contains("execution")
            || field.to_ascii_lowercase().contains("inventory")
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_no_nested_endpoint_fields(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if field == "rules" {
            continue;
        }
        for value in top_level_assignment_values(block, &field) {
            let stripped = strip_csharp_string_literals(&value);
            for nested in assignment_like_fields(&stripped) {
                if NESTED_FIELD_NAMES.contains(&nested.as_str()) {
                    errors.push(format!(
                        "API endpoint has nested datacenter readiness field {nested}; contract fields must be top-level"
                    ));
                }
            }
        }
    }
}

fn assignment_like_fields(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < text.len() {
        if bytes[index].is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < text.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            let field = &text[start..index];
            let mut cursor = index;
            while cursor < text.len() && text.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < text.len() && bytes[cursor] == b'=' {
                fields.push(field.to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing datacenter readiness endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "datacenter readiness doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "datacenter readiness doc must prohibit provider calls",
    );
    expect(
        doc.contains("No raw inventory rows"),
        errors,
        "datacenter readiness doc must prohibit raw inventory rows",
    );
    expect(
        doc.contains("site-safe readiness summaries"),
        errors,
        "datacenter readiness doc must require safe summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) && !SAFE_CATALOG_KEYS.contains(&key.as_str()) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited datacenter readiness field"
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
            if text.contains('\n') {
                if contains_prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
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
    if !safe_text_value(text) {
        if contains_prohibited_value(text) {
            errors.push(format!("{path} contains prohibited value"));
        }
        if prohibited_field(text) && text_key_like(text) {
            errors.push(format!(
                "{path} contains prohibited datacenter readiness value {text}"
            ));
        }
    }
    for term in scan_text_identifier_terms(text) {
        if prohibited_field(&term) {
            errors.push(format!(
                "{path} contains prohibited datacenter readiness field {term}"
            ));
        }
    }
}

fn scan_text_identifier_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    terms.extend(identifier_terms_before(line, '='));
    terms.extend(identifier_terms_before(line, ':'));
    terms.sort();
    terms.dedup();
    terms
}

fn identifier_terms_before(line: &str, separator: char) -> Vec<String> {
    let mut terms = Vec::new();
    for (index, ch) in line.char_indices() {
        if ch != separator {
            continue;
        }
        let left = line[..index]
            .trim()
            .trim_start_matches("//")
            .trim_start_matches('#')
            .trim()
            .trim_matches('`');
        if text_key_like(left) {
            terms.push(left.to_string());
        }
        if let Some(last) = left.split_whitespace().last() {
            if text_key_like(last) {
                terms.push(last.to_string());
            }
        }
    }
    terms
}

fn safe_text_value(value: &str) -> bool {
    REQUIRED_DOMAINS.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_RULE_DETAILS.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| value == *variable)
        || SAFE_TEXT_EXTRA.contains(&value)
}

fn contains_prohibited_value(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("://")
        || lower.contains("-----begin ")
        || lower.contains("client_secret")
        || lower.contains("access_token")
        || lower.contains("refresh_token")
        || lower.contains("bearer=")
        || lower.contains("bearer:")
        || lower.contains("password=")
        || lower.contains("password:")
        || contains_aws_key(text)
        || contains_private_ip(text)
        || contains_uuid(text)
        || contains_email(text)
}

fn contains_aws_key(text: &str) -> bool {
    text.as_bytes().windows(4).any(|window| window == b"AKIA")
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_digit() && ch != '.')
        .any(|part| {
            let octets: Vec<u8> = part
                .split('.')
                .filter_map(|octet| octet.parse::<u8>().ok())
                .collect();
            octets.len() == 4
                && (octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1])))
        })
}

fn contains_uuid(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_hexdigit() && ch != '-')
        .any(|part| {
            let bytes = part.as_bytes();
            bytes.len() == 36
                && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
                && bytes.iter().enumerate().all(|(index, byte)| {
                    [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit()
                })
        })
}

fn contains_email(text: &str) -> bool {
    text.split_whitespace().any(|part| {
        let trimmed = part.trim_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || matches!(ch, '@' | '.' | '_' | '%' | '+' | '-'))
        });
        let Some((local, domain)) = trimmed.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain.rsplit('.').next().is_some_and(|suffix| {
                suffix.len() >= 2 && suffix.chars().all(|ch| ch.is_ascii_alphabetic())
            })
    })
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize_key(value);
    if safe_normalized_values().contains(normalized.as_str()) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || [
            "password",
            "credential",
            "tenantid",
            "tenantidentifier",
            "subscriptionid",
            "subscriptionidentifier",
            "customerid",
            "customeridentifier",
            "objectid",
            "objectidentifier",
            "principalid",
            "principalidentifier",
            "hostid",
            "hostidentifier",
            "userid",
            "useridentifier",
            "privateip",
            "privatenetwork",
            "hostname",
            "fqdn",
            "providerpayload",
            "rawprovider",
            "rawinventory",
            "rawrow",
            "endpointurl",
            "token",
            "bearer",
            "secret",
            "serialnumber",
            "serial",
            "assettag",
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
        || (has_any(&tokens, &["id", "guid"]) && tokens.len() > 1)
        || (has_any(&tokens, &["private", "ip"])
            && has_any(&tokens, &["address", "value", "network"]))
        || (has_any(&tokens, &["tenant", "object", "provider"])
            && has_any(&tokens, &["id", "identifier", "payload", "value"]))
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &["provider", "inventory", "rows", "payload", "logs"],
            ))
        || tokens.iter().any(|token| token == "serial")
        || (tokens.iter().any(|token| token == "asset")
            && tokens.iter().any(|token| token == "tag"))
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut expanded = String::new();
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            expanded.push(' ');
        }
        expanded.push(ch);
        previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }
    expanded
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn safe_normalized_values() -> BTreeSet<String> {
    REQUIRED_DOMAINS
        .iter()
        .chain(REQUIRED_INPUTS)
        .chain(REQUIRED_GUARDS)
        .chain(REQUIRED_PLAN_SECTIONS)
        .chain(REQUIRED_BLOCKED_REASONS)
        .chain(REQUIRED_EVIDENCE)
        .chain(REQUIRED_DISABLED_FIELDS)
        .chain(SAFE_TEXT_EXTRA)
        .copied()
        .chain(
            REQUIRED_RULE_DETAILS
                .iter()
                .flat_map(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence]),
        )
        .chain(
            ENDPOINT_ARRAY_BINDINGS
                .iter()
                .map(|(_, variable)| *variable),
        )
        .map(normalize_key)
        .collect()
}

fn text_key_like(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch.is_whitespace())
}

fn normalize_key(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|rule| Rule {
            id: string_field(rule, "id").unwrap_or_default().to_string(),
            decision: string_field(rule, "decision")
                .unwrap_or_default()
                .to_string(),
            requirement: string_field(rule, "requirement")
                .unwrap_or_default()
                .to_string(),
            evidence: string_field(rule, "evidence")
                .unwrap_or_default()
                .to_string(),
        })
        .collect()
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_field(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn string_array_field(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn set_difference(left: &BTreeSet<&str>, right: &BTreeSet<&str>) -> Vec<String> {
    left.difference(right)
        .map(|value| (*value).to_string())
        .collect()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}

fn csharp_without_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            output.push(ch);
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
            output.push(ch);
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            output.push(' ');
            output.push(' ');
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    output.push('\n');
                    break;
                }
                output.push(' ');
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            output.push(' ');
            output.push(' ');
            chars.next();
            let mut previous = '\0';
            for next in chars.by_ref() {
                if next == '\n' {
                    output.push('\n');
                } else {
                    output.push(' ');
                }
                if previous == '*' && next == '/' {
                    break;
                }
                previous = next;
            }
            continue;
        }
        output.push(ch);
    }
    output
}

fn strip_csharp_string_literals(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let chars = source.chars();
    let mut in_string = false;
    let mut escaped = false;
    for ch in chars {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
                output.push('"');
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            output.push('"');
        } else {
            output.push(ch);
        }
    }
    output
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    indexes.extend(
        text.match_indices('\n')
            .map(|(index, _)| index + 1)
            .filter(|index| *index < text.len()),
    );
    indexes
}

struct CompactText {
    text: String,
    map: Vec<usize>,
}

fn compact_with_map(text: &str) -> CompactText {
    let mut compact = String::new();
    let mut map = Vec::new();
    for (index, ch) in text.char_indices() {
        if ch.is_whitespace() {
            continue;
        }
        compact.push(ch);
        map.push(index);
    }
    CompactText { text: compact, map }
}

fn compact_whitespace(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn compact_indexes(text: &str, needle: &str) -> Vec<usize> {
    let compact = compact_with_map(text);
    let compact_needle = compact_whitespace(needle);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = compact.text[offset..].find(&compact_needle) {
        let compact_index = offset + relative;
        indexes.push(compact.map[compact_index]);
        offset = compact_index + compact_needle.len();
    }
    indexes
}

fn matching_brace_index(source: &str, start_index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut index = start_index;
    let mut in_string = false;
    let mut escaped = false;
    while index < source.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
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

fn brace_depth_at(source: &str, target_index: usize) -> i32 {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < target_index && index < source.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
        }
        index += 1;
    }
    depth
}

fn split_top_level_members(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut members = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    while index < body.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b'{' || byte == b'(' || byte == b'[' {
            depth += 1;
        } else if byte == b'}' || byte == b')' || byte == b']' {
            if depth > 0 {
                depth -= 1;
            }
        } else if byte == b',' && depth == 0 {
            members.push(body[start..index].to_string());
            start = index + 1;
        }
        index += 1;
    }
    members.push(body[start..].to_string());
    members
}

fn quoted_value(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        Some(trimmed[1..trimmed.len() - 1].to_string())
    } else {
        None
    }
}

fn is_identifier_boundary(bytes: &[u8], start: usize, len: usize) -> bool {
    let before = start == 0 || !is_identifier_char(bytes[start - 1]);
    let after = start + len >= bytes.len() || !is_identifier_char(bytes[start + len]);
    before && after
}

fn is_identifier_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_indexes_include_spaced_mapget() {
        let program = format!(
            "app . MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );

        assert_eq!(endpoint_start_indexes(&program).len(), 1);
    }

    #[test]
    fn prohibited_shapes_are_detected() {
        let mut errors = Vec::new();
        scan_prohibited_value(
            &serde_json::json!({
                "tenantId": "safe-summary",
                "values": ["serial_number", "providerPayload"],
                "contactSummary": "site.owner@example.invalid"
            }),
            "synthetic",
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains("tenantId")));
        assert!(errors.iter().any(|error| error.contains("serial_number")));
        assert!(errors.iter().any(|error| error.contains("providerPayload")));
        assert!(errors.iter().any(|error| error.contains("contactSummary")));
    }
}
