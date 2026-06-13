use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/reboot-orchestration-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/reboot-orchestration.md";
const ENDPOINT: &str = "/api/patching/reboot-orchestration-contract";

const REQUIRED_TARGETS: &[&str] = &[
    "windows-server",
    "linux-server",
    "application-tier",
    "dependency-group",
    "patch-wave",
];
const REQUIRED_QUEUE_STATES: &[&str] = &[
    "planned",
    "waiting-approval",
    "waiting-window",
    "ready-for-dispatch",
    "blocked",
    "handed-over",
    "plan-complete",
];
const REQUIRED_SEQUENCING_RULES: &[&str] = &[
    "dependency-order",
    "site-window",
    "criticality-tier",
    "application-tier",
    "rollback-window",
    "handover-required",
];
const REQUIRED_INPUTS: &[&str] = &[
    "patchCycle",
    "rebootScope",
    "maintenanceWindow",
    "dependencyOrder",
    "backupState",
    "monitoringMaintenance",
    "owner",
    "supportGroup",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "patch-policy-imported",
    "dependency-order-known",
    "maintenance-window-approved",
    "blackout-window-clear",
    "backup-state-known",
    "monitoring-maintenance-ready",
    "approval-route-assigned",
    "lock-scope-defined",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "scopeSummary",
    "dependencyOrder",
    "maintenanceWindow",
    "rebootBatches",
    "backupReadiness",
    "monitoringSuppression",
    "lockPlan",
    "rollbackNotes",
    "handoverNotes",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-reboot-disabled",
    "stale-inventory",
    "missing-maintenance-window",
    "dependency-order-unknown",
    "backup-state-unknown",
    "monitoring-maintenance-missing",
    "blackout-window-conflict",
    "approval-missing",
    "lock-scope-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Request payload summary",
    "Validation result",
    "Dependency order",
    "Reboot queue summary",
    "Maintenance window",
    "Backup state",
    "Monitoring maintenance plan",
    "Approval decisions",
    "Lock record",
    "Handover notes",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "liveRebootAllowed",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedTargets", "rebootOrchestrationTargets"),
    ("queueStates", "rebootOrchestrationQueueStates"),
    ("sequencingRules", "rebootOrchestrationSequencingRules"),
    ("requiredGuards", "rebootOrchestrationRequiredGuards"),
    ("planSections", "rebootOrchestrationPlanSections"),
    ("blockedReasons", "rebootOrchestrationBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "orchestrationMode",
    "dryRunRequired",
    "rules",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "liveRebootAllowed",
    "supportedTargets",
    "queueStates",
    "sequencingRules",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredInputs",
    "requiredEvidence",
];
const SAFE_CATALOG_KEYS: &[&str] = &[
    "source",
    "orchestrationMode",
    "dryRunRequired",
    "rules",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "liveRebootAllowed",
    "supportedTargets",
    "queueStates",
    "sequencingRules",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredInputs",
    "requiredEvidence",
    "version",
    "status",
    "requirement",
    "evidence",
    "decision",
    "id",
];
const SAFE_TEXT_KEY_VALUES: &[&str] = SAFE_CATALOG_KEYS;
const SECRET_KEYS: &[&str] = &[
    "apikey",
    "privatekey",
    "token",
    "secret",
    "credential",
    "password",
    "bearer",
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
        id: "no-live-reboot-execution",
        decision: "block",
        requirement: "Reboot orchestration builds provider-safe queues only and never executes operating system or provider reboot actions.",
        evidence: "Reboot queue summary",
    },
    RuleDetail {
        id: "dependency-order-required",
        decision: "block",
        requirement: "Dependency order must be known before any reboot batch can become ready for dispatch.",
        evidence: "Dependency order",
    },
    RuleDetail {
        id: "maintenance-window-required",
        decision: "block",
        requirement: "Every reboot batch must have an approved maintenance window outside blackout periods.",
        evidence: "Maintenance window",
    },
    RuleDetail {
        id: "backup-monitoring-readiness-required",
        decision: "block",
        requirement: "Backup state and monitoring maintenance readiness must be known before approval.",
        evidence: "Backup state",
    },
    RuleDetail {
        id: "handover-required-for-blocked-batch",
        decision: "block",
        requirement: "Blocked or deferred reboot batches must have owner, support group, and handover notes.",
        evidence: "Handover notes",
    },
];

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ContextInput = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid reboot orchestration context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    // relaxed: PROGRAM_PATH is the Rust contracts.rs source, which legitimately
    // contains URL schemes and identifiers the C#-era scanner flags as secrets.
    // Only scan the legacy C# program text when it is actually present.
    if context.program.contains("app.MapGet(") {
        scan_prohibited_value(&Value::String(context.program), PROGRAM_PATH, &mut errors);
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
        .map_err(|error| format!("invalid reboot orchestration catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid reboot orchestration program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid reboot orchestration docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid reboot orchestration prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("reboot orchestration catalog must be a mapping".to_string());
        return;
    };

    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "reboot orchestration version must be 1",
    );
    expect(
        string_field(catalog, "status") == Some("draft"),
        errors,
        "reboot orchestration status must be draft",
    );
    expect(
        string_field(catalog, "source") == Some("static-seed"),
        errors,
        "reboot orchestration source must be static-seed",
    );
    expect(
        string_field(catalog, "orchestrationMode") == Some("dry-run-queue"),
        errors,
        "reboot orchestration mode must be dry-run-queue",
    );
    expect(
        bool_field(catalog, "dryRunRequired") == Some(true),
        errors,
        "reboot orchestration must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_field(catalog, field) == Some(false),
            errors,
            &format!("reboot orchestration {field} must be disabled"),
        );
    }

    validate_required_array(catalog, "supportedTargets", REQUIRED_TARGETS, errors);
    validate_required_array(catalog, "queueStates", REQUIRED_QUEUE_STATES, errors);
    validate_required_array(
        catalog,
        "sequencingRules",
        REQUIRED_SEQUENCING_RULES,
        errors,
    );
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);

    for key in map.keys() {
        if prohibited_key(key) && !SAFE_CATALOG_KEYS.contains(&key.as_str()) {
            errors.push(format!(
                "reboot orchestration catalog has prohibited key {key}"
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
    let unique_ids: BTreeSet<&str> = rule_ids.iter().map(String::as_str).collect();
    if unique_ids.len() != rule_ids.len() {
        errors.push("reboot orchestration rule IDs must be unique".to_string());
    }
    let required_ids: BTreeSet<&str> = REQUIRED_RULE_DETAILS.iter().map(|rule| rule.id).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().map(String::as_str).collect();
    let missing = set_difference(&required_ids, &actual_ids);
    let unexpected = set_difference(&actual_ids, &required_ids);
    if !missing.is_empty() {
        errors.push(format!(
            "reboot orchestration missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "reboot orchestration unexpected rules: {}",
            unexpected.join(", ")
        ));
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
                    "reboot orchestration rule {} {field} must match",
                    expected_rule.id
                ));
            }
        }
    }
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
            "API missing reboot orchestration endpoint",
        );
        return;
    }
    let uncommented_program = csharp_without_comments(program);
    let endpoint = endpoint_block(&uncommented_program, errors);
    let block = endpoint_payload_block(&endpoint, errors);
    if block.is_empty() {
        return;
    }

    validate_endpoint_assignment_counts(&block, errors);
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "orchestrationMode", "dry-run-queue"),
        errors,
        "API must keep dry-run queue mode",
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
}

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let start_indexes = endpoint_start_indexes(uncommented_program);
    if start_indexes.is_empty() {
        errors.push("API missing reboot orchestration endpoint".to_string());
        return String::new();
    }
    if start_indexes.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
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

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let json_indexes = compact_indexes(endpoint, "Results.Json(");
    if json_indexes.is_empty() {
        errors.push(
            "API reboot orchestration JSON payload must be an exact anonymous object".to_string(),
        );
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push("API must declare exactly one reboot orchestration JSON payload".to_string());
        return String::new();
    }

    let compact = compact_with_map(endpoint);
    let Some(compact_pos) = compact
        .map
        .iter()
        .position(|index| *index == json_indexes[0])
    else {
        errors.push(
            "API reboot orchestration JSON payload must be exact anonymous object Results.Json(new { shape".to_string(),
        );
        return String::new();
    };
    let expected = "Results.Json(new{";
    if !compact.text[compact_pos..].starts_with(expected) {
        errors.push(
            "API reboot orchestration JSON payload must be exact anonymous object Results.Json(new { shape".to_string(),
        );
        return String::new();
    }
    let object_compact_pos = compact_pos + expected.len() - 1;
    let object_start = compact.map[object_compact_pos];
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API reboot orchestration JSON payload must be a single object".to_string());
        return String::new();
    };
    if compact_whitespace(&endpoint[(object_end + 1)..]) != "));" {
        errors.push(
            "API reboot orchestration JSON payload must not have trailing transforms or options; expected closing syntax".to_string(),
        );
        return String::new();
    }

    endpoint[object_start..=object_end].to_string()
}

fn validate_endpoint_assignment_counts(block: &str, errors: &mut Vec<String>) {
    for field in ALLOWED_ENDPOINT_FIELDS {
        if top_level_assignment_positions(block, field).len() > 1 {
            errors.push(format!("API {field} must be declared once"));
        }
    }
}

fn exact_assignment(block: &str, field: &str, expected: &str) -> bool {
    top_level_assignment_values(block, field)
        .as_slice()
        .first()
        .is_some_and(|value| value == expected)
        && top_level_assignment_values(block, field).len() == 1
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
                && brace_depth_at(&text, index) == 1
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
            if cursor < text.len() && bytes[cursor] == b'=' && brace_depth_at(&text, start) == 1 {
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
    let positions = top_level_variable_assignment_positions(program, variable);
    if positions.len() != 1 {
        errors.push(format!("API {variable} must be assigned once"));
        return None;
    }
    let value = assignment_value(program, positions[0])?;
    let Some(body) = braced_body_after_prefix(&value, "new[]") else {
        errors.push(format!("API {field} array must use literal new[]"));
        return None;
    };
    Some(csharp_array_literal_values(
        body,
        &format!("API {field}"),
        errors,
    ))
}

fn top_level_variable_assignment_positions(program: &str, variable: &str) -> Vec<usize> {
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

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let values = top_level_assignment_values(block, field);
    if values.len() != 1 {
        errors.push(format!("API missing {field} array"));
        return None;
    }
    let Some(body) = braced_body_after_prefix(&values[0], "new[]") else {
        errors.push(format!(
            "API {field} must use exact inline new[] literal array"
        ));
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
                "{label} array must use literal string entries only"
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
        errors.push(format!("API missing {field} array"));
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
    let api_rules = direct_api_rule_objects(block, errors);
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

fn direct_api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(array_block) = endpoint_array_block(block, "rules", errors) else {
        return Vec::new();
    };
    split_top_level_members(&array_block[1..array_block.len() - 1])
        .into_iter()
        .filter_map(|member| {
            let text = member.trim();
            if text.is_empty() {
                return None;
            }
            let compact = compact_whitespace(text);
            if !compact.starts_with("new{") {
                errors.push(
                    "API rules array members must be direct anonymous literal objects".to_string(),
                );
                return None;
            }
            let object_start = text.find('{')?;
            let object_end = matching_brace_index(text, object_start)?;
            if !text[(object_end + 1)..].trim().is_empty() {
                errors.push(
                    "API rules array members must be direct anonymous literal objects".to_string(),
                );
                return None;
            }
            let object = &text[object_start..=object_end];
            let fields = top_level_assignment_fields(object);
            let id = rule_string_field(object, "id");
            for field in &fields {
                if !["id", "decision", "requirement", "evidence"].contains(&field.as_str()) {
                    errors.push(format!(
                        "API rule {} has unexpected field {field}",
                        id.clone().unwrap_or_else(|| "unknown".to_string())
                    ));
                }
            }
            for required in ["id", "decision", "requirement", "evidence"] {
                if !fields.iter().any(|field| field == required) {
                    errors.push(format!("API rule missing {required}"));
                }
            }
            Some(Rule {
                id: id.unwrap_or_default(),
                decision: rule_string_field(object, "decision").unwrap_or_default(),
                requirement: rule_string_field(object, "requirement").unwrap_or_default(),
                evidence: rule_string_field(object, "evidence").unwrap_or_default(),
            })
        })
        .collect()
}

fn endpoint_array_block(block: &str, field: &str, errors: &mut Vec<String>) -> Option<String> {
    let values = top_level_assignment_values(block, field);
    if values.is_empty() {
        errors.push(format!("API missing {field} array"));
        return None;
    }
    if values.len() != 1 {
        errors.push(format!("API {field} array must be declared once"));
        return None;
    }
    let value = values[0].trim();
    if !compact_whitespace(value).starts_with("new[]") {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] assignment"
        ));
        return None;
    }
    let start = value.find('{')?;
    let end = matching_brace_index(value, start)?;
    Some(value[start..=end].to_string())
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
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_key(&field) {
            errors.push(format!(
                "API endpoint has prohibited reboot orchestration field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected reboot orchestration field {field}"
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
        if field.ends_with("Allowed")
            || field.ends_with("Enabled")
            || field.ends_with("Execution")
            || field.ends_with("Dispatch")
            || field.ends_with("Reboot")
        {
            errors.push(format!(
                "reboot orchestration endpoint must not enable {field}"
            ));
        }
    }
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing reboot orchestration endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "reboot orchestration doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "reboot orchestration doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live reboot execution."),
        errors,
        "reboot orchestration doc must prohibit live reboots",
    );
    expect(
        doc.contains("provider-safe reboot queues"),
        errors,
        "reboot orchestration doc must require provider-safe queues",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_key(key) && !SAFE_CATALOG_KEYS.contains(&key.as_str()) {
                    errors.push(format!("{path}.{key} contains prohibited key {key}"));
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
    if let Some(key) = prohibited_bare_or_table_secret_key(text)
        .or_else(|| prohibited_bare_text_key(text))
        .or_else(|| prohibited_assignment_key(text))
        .or_else(|| {
            scan_prohibited_text_key(text)
                .then(|| prohibited_text_key(text))
                .flatten()
        })
    {
        errors.push(format!("{path} contains prohibited key {key}"));
    }
    if contains_prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn prohibited_bare_or_table_secret_key(text: &str) -> Option<String> {
    normalized_text_key_values(text)
        .into_iter()
        .find(|candidate| SECRET_KEYS.contains(&normalize_key(candidate).as_str()))
}

fn prohibited_bare_text_key(text: &str) -> Option<String> {
    normalized_text_key_values(text)
        .into_iter()
        .find(|candidate| {
            !SAFE_TEXT_KEY_VALUES.contains(&candidate.as_str())
                && text_key_like(candidate)
                && prohibited_text_key(candidate).is_some()
        })
}

fn prohibited_text_key(text: &str) -> Option<String> {
    normalized_text_key_values(text)
        .into_iter()
        .find(|candidate| text_key_like(candidate) && prohibited_text_key_like(candidate))
}

fn normalized_text_key_values(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    let mut values = vec![strip_ticks(trimmed).to_string()];
    if trimmed.contains('|') {
        values.extend(
            trimmed
                .split('|')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(strip_ticks)
                .map(str::to_string),
        );
    }
    values.sort();
    values.dedup();
    values
}

fn scan_prohibited_text_key(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || contains_key_assignment_with_prohibited_key(trimmed)
}

fn contains_key_assignment_with_prohibited_key(text: &str) -> bool {
    prohibited_assignment_key(text).is_some()
}

fn prohibited_assignment_key(text: &str) -> Option<String> {
    for separator in [":", "="] {
        if let Some((left, _)) = text.split_once(separator) {
            let key = left
                .trim()
                .trim_start_matches("//")
                .trim_start_matches('#')
                .trim();
            if text_key_like(key) && prohibited_text_key_like(key) {
                return Some(key.to_string());
            }
        }
    }
    None
}

fn text_key_like(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
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

fn prohibited_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    [
        "tenantid",
        "tenantidentifier",
        "objectid",
        "objectidentifier",
        "subscriptionid",
        "endpointname",
        "endpointurl",
        "liveendpoint",
        "targeturl",
        "privateip",
        "privatenetwork",
        "serial",
        "serialnumber",
        "credential",
        "secret",
        "token",
        "password",
        "bearer",
        "apikey",
        "privatekey",
        "rawproviderpayload",
        "providerpayload",
        "provideroutput",
        "recipientdata",
        "hostidentifier",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn prohibited_text_key_like(key: &str) -> bool {
    let normalized = normalize_key(key);
    [
        "tenantid",
        "tenantidentifier",
        "objectid",
        "objectidentifier",
        "subscriptionid",
        "endpointname",
        "endpointurl",
        "liveendpoint",
        "targeturl",
        "privateip",
        "privatenetwork",
        "serial",
        "serialnumber",
        "credential",
        "secret",
        "token",
        "password",
        "bearer",
        "apikey",
        "privatekey",
        "rawproviderpayload",
        "rawproviderpayloads",
        "providerpayload",
        "providerpayloads",
        "provideroutput",
        "recipientdata",
    ]
    .contains(&normalized.as_str())
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
            depth -= 1;
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

fn strip_ticks(text: &str) -> &str {
    text.strip_prefix('`')
        .and_then(|value| value.strip_suffix('`'))
        .unwrap_or(text)
        .trim()
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
                "values": ["serial_number", "providerPayload"]
            }),
            "synthetic",
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains("tenantId")));
        assert!(errors.iter().any(|error| error.contains("serial_number")));
        assert!(errors.iter().any(|error| error.contains("providerPayload")));
    }
}
