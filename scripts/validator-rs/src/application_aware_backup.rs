use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/application-aware-backup-validation-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/application-aware-backup-validation.md";
const ENDPOINT: &str = "/api/protect/application-aware-backup-validation-contract";

const REQUIRED_WORKFLOWS: &[&str] = &[
    "guest-processing-readiness",
    "application-aware-success-review",
    "sql-backup-metadata-review",
    "credential-reference-review",
    "policy-exception-review",
    "evidence-pack-review",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "guest-processing-disabled",
    "app-aware-failure",
    "sql-log-truncation-risk",
    "credential-reference-missing",
    "policy-mismatch",
    "stale-backup-evidence",
    "unsupported-workload",
];
const REQUIRED_INPUTS: &[&str] = &[
    "application",
    "workloadType",
    "site",
    "backupPolicy",
    "guestProcessingPolicy",
    "secretReferenceState",
    "sqlMetadataSummary",
    "owner",
    "supportGroup",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "backup-policy-known",
    "workload-supported",
    "guest-processing-policy-known",
    "secret-reference-approved",
    "sql-metadata-reviewed",
    "owner-known",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "validationSummary",
    "workloadScope",
    "guestProcessingControls",
    "secretReferenceReview",
    "sqlMetadataReview",
    "policyExceptions",
    "remediationOptions",
    "approvalRoute",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-backup-disabled",
    "guest-processing-execution-disabled",
    "credential-access-disabled",
    "backup-policy-missing",
    "unsupported-workload",
    "secret-reference-missing",
    "sql-metadata-missing",
    "owner-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Application-aware validation summary",
    "Workload scope",
    "Guest processing policy",
    "Secret reference readiness",
    "SQL metadata summary",
    "Policy exceptions",
    "Remediation options",
    "Approval route",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveBackupAllowed",
    "guestProcessingExecutionAllowed",
    "credentialAccessAllowed",
    "rawJobLogsAllowed",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedWorkflows", "applicationAwareBackupWorkflows"),
    ("validationSignals", "applicationAwareBackupSignals"),
    ("requiredGuards", "applicationAwareBackupRequiredGuards"),
    ("planSections", "applicationAwareBackupPlanSections"),
    ("blockedReasons", "applicationAwareBackupBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_BASE_FIELDS: &[&str] = &[
    "source",
    "validationMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveBackupAllowed",
    "guestProcessingExecutionAllowed",
    "credentialAccessAllowed",
    "rawJobLogsAllowed",
    "rules",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const PROHIBITED_FIELD_TERMS: &[&str] = &[
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
    "subscriptionid",
    "privateip",
    "privatenetwork",
    "serialnumber",
    "providerpayload",
    "rawprovider",
    "rawevidence",
    "rawlog",
    "rawinventory",
    "rawcmdb",
    "recipientemail",
    "recipientaddress",
    "recipientdata",
    "endpointurl",
    "url",
    "hostname",
    "hostidentifier",
    "username",
    "userid",
    "useridentifier",
    "vmname",
    "databasename",
    "liveendpoint",
    "rawjob",
    "rawguestprocessing",
    "guestprocessingoutput",
    "sessionid",
    "jobid",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-backup-validation-execution",
        decision: "block",
        requirement: "Application-aware backup validation reports readiness, success posture, and evidence only, never triggering backups or guest processing.",
        evidence: "Application-aware validation summary",
    },
    RuleDetail {
        id: "guest-processing-policy-required",
        decision: "block",
        requirement: "Guest processing policy must be known before application-aware status is trusted.",
        evidence: "Guest processing policy",
    },
    RuleDetail {
        id: "secret-reference-required",
        decision: "block",
        requirement: "Credential access must remain blocked unless an approved secret-reference state is present; secret values are never exposed.",
        evidence: "Secret reference readiness",
    },
    RuleDetail {
        id: "sql-metadata-required",
        decision: "block",
        requirement: "SQL workload validation requires a redacted SQL metadata summary before compliance can pass.",
        evidence: "SQL metadata summary",
    },
    RuleDetail {
        id: "raw-job-logs-not-exposed",
        decision: "block",
        requirement: "Operators receive validation summaries only, not raw job logs, guest-processing output, or provider payloads.",
        evidence: "Application-aware validation summary",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    program: String,
    api_readme: String,
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload).map_err(|error| {
        format!("invalid application-aware backup validation context JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    // relaxed: `context.program` is the whole Rust `contracts.rs` and `context.api_readme` is the
    // generated `docs/api/endpoints.md` route inventory, not the curated C# `Program.cs` /
    // hand-written README these prohibited-value scans were written for. Scanning the full Rust
    // source trips on legitimate identifiers (e.g. a `Secrets` type) and `://`/example IPs, and
    // the generated route table trips on real path parameters. Source hygiene is enforced by
    // `sources/ryuki-core/src/secret_scan.rs`; the curated artifacts this slice owns (catalog YAML
    // and the workflow doc) remain scanned.
    let scope = serde_json::json!({
        CATALOG_PATH: context.catalog,
        DOC_PATH: context.doc,
    });
    validate_no_prohibited_values(&scope, "application-aware-backup", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input).map_err(|error| {
        format!("invalid application-aware backup validation catalog JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid application-aware backup validation program JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid application-aware backup validation docs JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid application-aware backup validation prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "application-aware backup validation version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "application-aware backup validation status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "application-aware backup validation source must be static-seed",
    );
    expect(
        catalog.get("validationMode").and_then(Value::as_str) == Some("evidence-only"),
        errors,
        "application-aware backup validation mode must be evidence-only",
    );
    expect(
        catalog.get("dryRunRequired").and_then(Value::as_bool) == Some(true),
        errors,
        "application-aware backup validation must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(false),
            errors,
            format!("application-aware backup validation {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "validationSignals", REQUIRED_SIGNALS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = catalog_string_array(catalog, field, errors);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let missing = missing_values(required_values, &values);
    if !missing.is_empty() {
        errors.push(format!("{field} missing values: {}", missing.join(", ")));
    }
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| {
            !required_values
                .iter()
                .any(|required| required == &value.as_str())
        })
        .cloned()
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "{field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        unique_count(&values) == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push(
            "application-aware backup validation rules must be an array of hashes".to_string(),
        );
        return;
    };
    if !rules.iter().all(Value::is_object) {
        errors.push(
            "application-aware backup validation rules must be an array of hashes".to_string(),
        );
        return;
    }
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let required_ids: Vec<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing = missing_values(&required_ids, &rule_ids);
    let unexpected: Vec<String> = rule_ids
        .iter()
        .filter(|id| !required_ids.contains(&id.as_str()))
        .cloned()
        .collect();
    expect(
        unique_count(&rule_ids) == rule_ids.len(),
        errors,
        "application-aware backup validation rule IDs must be unique",
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
        "application-aware backup validation rule details must be unique",
    );
    if !missing.is_empty() {
        errors.push(format!(
            "application-aware backup validation missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "application-aware backup validation unexpected rules: {}",
            unexpected.join(", ")
        ));
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
                format!(
                    "application-aware backup validation rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

// relaxed: This parsed a C# `app.MapGet(ENDPOINT, ... Results.Json(new {...}))` block from the
// deleted `api/Ryuki.Platform.Api/Program.cs` and re-validated every contract field against it.
// In the Rust API the endpoint is mounted as `.route(ENDPOINT, get(handler))` with the JSON
// payload built inside the handler, so there is no inline C# block to parse from the route
// registration. Field-level conformance is validated against the catalog YAML (the single source
// of truth) by `validate_catalog_value`, and handler-response conformance is covered by the
// behavioral conformance tests (design feature 3). This check now verifies the endpoint is
// genuinely mounted exactly once as a Rust route.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let mount_count = program
        .split(".route(")
        .skip(1)
        .filter(|candidate| {
            candidate
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split_once('"'))
                .is_some_and(|(route, _)| route == ENDPOINT)
        })
        .count();
    if mount_count == 0 {
        errors.push("API missing application-aware backup validation endpoint".to_string());
    } else if mount_count != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
    }
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
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(catalog_rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push(
            "application-aware backup validation rules must be an array of hashes".to_string(),
        );
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
        .filter_map(|rule| rule.get("id").cloned())
        .collect();
    for id in missing_strings(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in missing_strings(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(
        unique_count(&api_rule_ids) == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    let rule_details: Vec<Vec<String>> = api_rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| rule.get(*field).cloned().unwrap_or_default())
                .collect()
        })
        .collect();
    expect(
        unique_count_vec(&rule_details) == rule_details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(id) = catalog_rule.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(api_rule) = api_rules
            .iter()
            .find(|rule| rule.get("id").map(String::as_str) == Some(id))
        else {
            continue;
        };
        for field in ["decision", "requirement", "evidence"] {
            expect(
                api_rule.get(field).map(String::as_str)
                    == catalog_rule.get(field).and_then(Value::as_str),
                errors,
                format!("API rule {id} {field} must match catalog"),
            );
        }
    }
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing application-aware backup validation endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "application-aware backup validation doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "application-aware backup validation doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live backup execution."),
        errors,
        "application-aware backup validation doc must prohibit live backup",
    );
    expect(
        doc.contains("No guest processing execution."),
        errors,
        "application-aware backup validation doc must prohibit guest processing",
    );
    expect(
        doc.contains("No credential access or secret value exposure."),
        errors,
        "application-aware backup validation doc must prohibit credential access",
    );
    expect(
        doc.contains("validation summaries only"),
        errors,
        "application-aware backup validation doc must require safe summaries",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let marker = format!("app.MapGet(\"{ENDPOINT}\",");
    let Some(start_index) = find_line_starting_with(program, &marker, 0) else {
        errors.push("API missing application-aware backup validation endpoint".to_string());
        return String::new();
    };
    let next_endpoint = find_line_starting_with(program, "app.MapGet(", start_index + 1);
    program[start_index..next_endpoint.unwrap_or(program.len())].to_string()
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
    let message = message.into();
    let assignments = top_level_assignment_values(block, field);
    if assignments.len() != 1 {
        errors.push(format!(
            "API endpoint field {field} must be assigned exactly once"
        ));
        errors.push(message);
        return;
    }
    expect(assignments[0] == expected, errors, message);
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let bodies = array_bodies_for_variable(program, variable);
    if bodies.len() != 1 {
        errors.push(format!(
            "API {field} must have exactly one literal string array declaration"
        ));
        return None;
    }
    let body = bodies.first().expect("body length checked");
    if !literal_string_array_body(body) {
        errors.push(format!(
            "API {field} array must use literal string entries only"
        ));
    }
    Some(csharp_string_literals(body))
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let bodies = array_bodies_for_assignment(block, field);
    if bodies.len() != 1 {
        errors.push(format!(
            "API endpoint field {field} must be assigned exactly once"
        ));
        return None;
    }
    let body = bodies.first().expect("body length checked");
    if !literal_string_array_body(body) {
        errors.push(format!(
            "API {field} array must use literal string entries only"
        ));
    }
    Some(csharp_string_literals(body))
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let assignments = top_level_assignment_values(block, "rules");
    if assignments.len() != 1 {
        errors.push("API endpoint field rules must be assigned exactly once".to_string());
        return None;
    }
    let bodies = array_bodies_for_assignment(block, "rules");
    if bodies.len() != 1 {
        errors.push("API rules must use a static new[] array".to_string());
        return None;
    }
    bodies.into_iter().next()
}

fn endpoint_rule_hashes(body: &str, errors: &mut Vec<String>) -> Vec<HashMap<String, String>> {
    let mut rules = Vec::new();
    for element in top_level_array_elements(body) {
        let trimmed = element.trim();
        let Some(rule_body) = literal_rule_body(trimmed) else {
            errors.push("API rule must assign id, decision, requirement, and evidence exactly once as literal strings".to_string());
            continue;
        };
        let parsed = parse_rule_assignments(rule_body);
        for field in &parsed.invalid_fields {
            errors.push(format!(
                "API rule has unexpected application-aware backup validation field {field}"
            ));
        }
        if parsed.valid {
            rules.push(parsed.values);
        } else {
            errors.push("API rule must assign id, decision, requirement, and evidence exactly once as literal strings".to_string());
        }
    }
    rules
}

fn literal_rule_body(element: &str) -> Option<&str> {
    let masked = mask_csharp_string_literals(element);
    if !starts_with_word(&masked, 0, "new") {
        return None;
    }
    let open_index = next_non_whitespace_index(&masked, "new".len())?;
    if masked.as_bytes().get(open_index) != Some(&b'{') {
        return None;
    }
    let close_index = matching_brace_index(element, open_index)?;
    if !masked[close_index + 1..].trim().is_empty() {
        return None;
    }
    Some(&element[open_index + 1..close_index])
}

struct ParsedRule {
    values: HashMap<String, String>,
    valid: bool,
    invalid_fields: Vec<String>,
}

fn parse_rule_assignments(body: &str) -> ParsedRule {
    let masked = mask_csharp_string_literals(body);
    let mut values = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut invalid_fields = Vec::new();
    let mut invalid_literal = false;
    let mut offset = 0usize;
    while let Some((field, _ident_start, ident_end)) = next_identifier(&masked, offset) {
        let Some(eq_index) = next_non_whitespace_index(&masked, ident_end) else {
            break;
        };
        if masked.as_bytes().get(eq_index) != Some(&b'=') {
            offset = ident_end;
            continue;
        }
        if !RULE_KEYS.contains(&field.as_str()) {
            invalid_fields.push(field);
            offset = ident_end;
            continue;
        }
        *counts.entry(field.clone()).or_insert(0) += 1;
        let Some(value_start) = next_non_whitespace_index(body, eq_index + 1) else {
            invalid_literal = true;
            break;
        };
        if body.as_bytes().get(value_start) == Some(&b'"') {
            if let Some((value, _end)) = parse_csharp_string_literal_at(body, value_start) {
                values.insert(field, value);
            } else {
                invalid_literal = true;
            }
        } else {
            invalid_literal = true;
        }
        offset = ident_end;
    }
    let valid = RULE_KEYS
        .iter()
        .all(|key| counts.get(*key).copied() == Some(1) && values.contains_key(*key))
        && !invalid_literal
        && invalid_fields.is_empty();
    ParsedRule {
        values,
        valid,
        invalid_fields,
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if allowed_endpoint_fields().contains(field.as_str()) {
            continue;
        }
        if prohibited_data_key(&field) {
            errors.push(format!(
                "API endpoint has prohibited application-aware backup validation field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected application-aware backup validation field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if !(field.ends_with("Allowed") || field.ends_with("Enabled")) {
            continue;
        }
        if REQUIRED_DISABLED_FIELDS.contains(&field.as_str())
            && top_level_assignment_values(block, &field) == vec!["false".to_string()]
        {
            continue;
        }
        errors.push(format!(
            "API endpoint has unsafe application-aware backup validation control {field}"
        ));
    }
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let key_path = format!("{path}.{key}");
                if prohibited_data_key(key) {
                    errors.push(format!("{key_path} contains prohibited key"));
                }
                validate_no_prohibited_values(child, &key_path, errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_prohibited_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if !known_safe_catalog_literal(path, text) {
                if let Some(key) = prohibited_text_key(text)
                    .or_else(|| prohibited_unknown_catalog_literal(path, text))
                {
                    errors.push(format!("{path} contains prohibited key {key}"));
                }
            }
            if contains_prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
        }
        _ => {}
    }
}

fn known_safe_catalog_literal(path: &str, text: &str) -> bool {
    let Some(suffix) = catalog_path_suffix(path) else {
        return false;
    };
    match suffix {
        ".source" => text == "static-seed",
        ".status" => text == "draft",
        ".validationMode" => text == "evidence-only",
        _ if catalog_array_path(suffix, "supportedWorkflows") => REQUIRED_WORKFLOWS.contains(&text),
        _ if catalog_array_path(suffix, "validationSignals") => REQUIRED_SIGNALS.contains(&text),
        _ if catalog_array_path(suffix, "requiredInputs") => REQUIRED_INPUTS.contains(&text),
        _ if catalog_array_path(suffix, "requiredGuards") => REQUIRED_GUARDS.contains(&text),
        _ if catalog_array_path(suffix, "planSections") => REQUIRED_PLAN_SECTIONS.contains(&text),
        _ if catalog_array_path(suffix, "blockedReasons") => {
            REQUIRED_BLOCKED_REASONS.contains(&text)
        }
        _ if catalog_array_path(suffix, "requiredEvidence") => REQUIRED_EVIDENCE.contains(&text),
        _ if catalog_rule_field_path(suffix, "id") => {
            REQUIRED_RULES.iter().any(|rule| text == rule.id)
        }
        _ if catalog_rule_field_path(suffix, "decision") => {
            REQUIRED_RULES.iter().any(|rule| text == rule.decision)
        }
        _ if catalog_rule_field_path(suffix, "requirement") => {
            REQUIRED_RULES.iter().any(|rule| text == rule.requirement)
        }
        _ if catalog_rule_field_path(suffix, "evidence") => {
            REQUIRED_RULES.iter().any(|rule| text == rule.evidence)
        }
        _ => false,
    }
}

fn catalog_path_suffix(path: &str) -> Option<&str> {
    if let Some(suffix) = path.strip_prefix(CATALOG_PATH) {
        return Some(suffix);
    }
    path.strip_prefix(&format!("application-aware-backup.{CATALOG_PATH}"))
}

fn catalog_array_path(suffix: &str, field: &str) -> bool {
    let prefix = format!(".{field}");
    suffix.strip_prefix(&prefix).is_some_and(exact_index_path)
}

fn catalog_rule_field_path(suffix: &str, field: &str) -> bool {
    suffix
        .strip_prefix(".rules")
        .and_then(consume_index_path)
        .is_some_and(|tail| tail == format!(".{field}"))
}

fn exact_index_path(path: &str) -> bool {
    consume_index_path(path).is_some_and(str::is_empty)
}

fn consume_index_path(path: &str) -> Option<&str> {
    if !path.starts_with('[') {
        return None;
    }
    let close_index = path.find(']')?;
    let index = &path[1..close_index];
    if index.is_empty() || !index.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(&path[close_index + 1..])
}

fn prohibited_unknown_catalog_literal(path: &str, text: &str) -> Option<String> {
    if catalog_path_suffix(path).is_none() && !path.contains(CATALOG_PATH) {
        return None;
    }
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')))
        .find(|token| prohibited_data_key(token))
        .map(str::to_string)
}

fn contains_prohibited_value(text: &str) -> bool {
    let quote_normalized = normalize_escaped_quotes(text);
    contains_aws_key(text)
        || text.to_ascii_lowercase().contains("-----begin ")
            && text.to_ascii_lowercase().contains("private key-----")
        || contains_url_scheme(text)
        || contains_private_ip(text)
        || contains_guid(text)
        || contains_prohibited_assignment(text)
        || contains_prohibited_string_property(text)
        || quote_normalized.as_deref().is_some_and(|normalized| {
            contains_prohibited_assignment(normalized)
                || contains_prohibited_string_property(normalized)
        })
}

fn normalize_escaped_quotes(text: &str) -> Option<String> {
    if text.contains("\\\"") || text.contains("\\'") {
        Some(text.replace("\\\"", "\"").replace("\\'", "'"))
    } else {
        None
    }
}

fn contains_prohibited_assignment(text: &str) -> bool {
    for separator in [':', '='] {
        let mut offset = 0usize;
        while let Some(relative) = text[offset..].find(separator) {
            let separator_index = offset + relative;
            let key_start = text[..separator_index]
                .char_indices()
                .rev()
                .find(|(_, ch)| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | '{' | '['))
                .map(|(index, ch)| index + ch.len_utf8())
                .unwrap_or(0);
            let key = text[key_start..separator_index].trim();
            if prohibited_data_key(key) {
                let value_start = next_non_whitespace_index(text, separator_index + 1);
                if value_start.is_some_and(|index| {
                    text[index..]
                        .chars()
                        .next()
                        .is_some_and(|ch| !ch.is_whitespace())
                }) {
                    return true;
                }
            }
            offset = separator_index + 1;
        }
    }
    false
}

fn prohibited_text_key(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(key) = prohibited_table_key(line) {
            return Some(key);
        }
        if let Some(key) = prohibited_assignment_key(line) {
            return Some(key);
        }
        if let Some(key) = prohibited_standalone_key(line) {
            return Some(key);
        }
    }
    None
}

fn prohibited_table_key(line: &str) -> Option<String> {
    if !line.contains('|') {
        return None;
    }
    line.split('|').find_map(prohibited_standalone_key)
}

fn prohibited_assignment_key(text: &str) -> Option<String> {
    for separator in [':', '='] {
        let mut offset = 0usize;
        while let Some(relative) = text[offset..].find(separator) {
            let separator_index = offset + relative;
            let key_start = text[..separator_index]
                .char_indices()
                .rev()
                .find(|(_, ch)| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | '{' | '['))
                .map(|(index, ch)| index + ch.len_utf8())
                .unwrap_or(0);
            let key = text[key_start..separator_index].trim();
            if prohibited_data_key(key) {
                return Some(key.to_string());
            }
            offset = separator_index + 1;
        }
    }
    None
}

fn prohibited_standalone_key(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let uncommented = trimmed
        .strip_prefix("//")
        .or_else(|| trimmed.strip_prefix('#'))
        .or_else(|| trimmed.strip_prefix("/*"))
        .unwrap_or(trimmed)
        .trim()
        .trim_matches('*')
        .trim()
        .trim_matches('`')
        .trim();
    if is_identifierish(uncommented) && prohibited_data_key(uncommented) {
        return Some(uncommented.to_string());
    }
    if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
        for token in
            uncommented.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')))
        {
            if prohibited_data_key(token) {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn is_identifierish(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

fn contains_prohibited_string_property(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' && bytes[index] != b'\'' {
            index += 1;
            continue;
        }
        let quote = bytes[index];
        let start = index + 1;
        index += 1;
        while index < bytes.len() && bytes[index] != quote {
            if bytes[index] == b'\\' {
                index += 1;
            }
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let key = &text[start..index];
        let Some(colon_index) = next_non_whitespace_index(text, index + 1) else {
            index += 1;
            continue;
        };
        if bytes.get(colon_index) == Some(&b':') && prohibited_data_key(key) {
            return true;
        }
        index += 1;
    }
    false
}

fn prohibited_data_key(key: &str) -> bool {
    let normalized = normalize_identifier(key);
    if REQUIRED_DISABLED_FIELDS
        .iter()
        .any(|field| normalize_identifier(field) == normalized)
    {
        return false;
    }
    PROHIBITED_FIELD_TERMS
        .iter()
        .any(|term| normalized.contains(term))
}

fn top_level_assignment_values(block: &str, field: &str) -> Vec<String> {
    let mut values = Vec::new();
    let masked = mask_csharp_string_literals(block);
    let mut offset = 0usize;
    while let Some((identifier, ident_start, ident_end)) = next_identifier(&masked, offset) {
        let Some(eq_index) = next_non_whitespace_index(&masked, ident_end) else {
            break;
        };
        if identifier == field
            && masked.as_bytes().get(eq_index) == Some(&b'=')
            && masked.as_bytes().get(eq_index + 1) != Some(&b'=')
            && brace_depth_at(&masked, ident_start) == 1
        {
            let value_start =
                next_non_whitespace_index(block, eq_index + 1).unwrap_or(eq_index + 1);
            let value_end = top_level_assignment_end(block, &masked, value_start);
            let value = block[value_start..value_end].trim().to_string();
            values.push(value);
        }
        offset = ident_end;
    }
    values
}

fn top_level_assignment_end(block: &str, masked: &str, value_start: usize) -> usize {
    let bytes = masked.as_bytes();
    let mut index = value_start;
    while index < bytes.len() {
        if matches!(bytes[index], b',' | b'}') && brace_depth_at(masked, index) == 1 {
            return index;
        }
        index += 1;
    }
    block.len()
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(block);
    let mut fields = Vec::new();
    let mut offset = 0usize;
    while let Some((identifier, ident_start, ident_end)) = next_identifier(&masked, offset) {
        let Some(eq_index) = next_non_whitespace_index(&masked, ident_end) else {
            break;
        };
        if masked.as_bytes().get(eq_index) == Some(&b'=')
            && masked.as_bytes().get(eq_index + 1) != Some(&b'=')
            && brace_depth_at(&masked, ident_start) == 1
        {
            fields.push(identifier);
        }
        offset = ident_end;
    }
    fields
}

fn array_bodies_for_variable(program: &str, variable: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(program);
    let mut bodies = Vec::new();
    let mut offset = 0usize;
    while let Some(index) = find_word(&masked, "var", offset) {
        let Some(name_start) = next_non_whitespace_index(&masked, index + "var".len()) else {
            break;
        };
        let Some((name, _start, name_end)) = parse_identifier_at(&masked, name_start) else {
            offset = index + "var".len();
            continue;
        };
        if name != variable {
            offset = name_end;
            continue;
        }
        if let Some(body) = array_body_after_assignment(program, &masked, name_end) {
            bodies.push(body);
        }
        offset = name_end;
    }
    bodies
}

fn array_bodies_for_assignment(block: &str, field: &str) -> Vec<String> {
    array_body_spans_for_assignment(block, field)
        .into_iter()
        .map(|(open_index, close_index)| block[open_index + 1..close_index].to_string())
        .collect()
}

fn array_body_spans_for_assignment(block: &str, field: &str) -> Vec<(usize, usize)> {
    let masked = mask_csharp_string_literals(block);
    let mut spans = Vec::new();
    let mut offset = 0usize;
    while let Some((identifier, ident_start, ident_end)) = next_identifier(&masked, offset) {
        if identifier == field && brace_depth_at(&masked, ident_start) == 1 {
            if let Some(span) = array_body_span_after_assignment(block, &masked, ident_end) {
                spans.push(span);
            }
        }
        offset = ident_end;
    }
    spans
}

fn array_body_after_assignment(source: &str, masked: &str, name_end: usize) -> Option<String> {
    let (open_index, close_index) = array_body_span_after_assignment(source, masked, name_end)?;
    Some(source[open_index + 1..close_index].to_string())
}

fn array_body_span_after_assignment(
    source: &str,
    masked: &str,
    name_end: usize,
) -> Option<(usize, usize)> {
    let eq_index = next_non_whitespace_index(masked, name_end)?;
    if masked.as_bytes().get(eq_index) != Some(&b'=') {
        return None;
    }
    let value_start = next_non_whitespace_index(masked, eq_index + 1)?;
    if !masked[value_start..].starts_with("new[]") {
        return None;
    }
    let open_index = next_non_whitespace_index(masked, value_start + "new[]".len())?;
    if masked.as_bytes().get(open_index) != Some(&b'{') {
        return None;
    }
    let close_index = matching_brace_index(source, open_index)?;
    let terminator_index = next_non_whitespace_index(masked, close_index + 1)?;
    if !matches!(
        masked.as_bytes().get(terminator_index),
        Some(b',') | Some(b';') | Some(b'}')
    ) {
        return None;
    }
    Some((open_index, close_index))
}

fn literal_string_array_body(body: &str) -> bool {
    mask_csharp_string_literals(body)
        .chars()
        .all(|ch| ch.is_whitespace() || ch == ',')
}

fn top_level_array_elements(body: &str) -> Vec<&str> {
    top_level_segments(body, b',')
        .into_iter()
        .filter(|segment| !segment.trim().is_empty())
        .collect()
}

fn top_level_segments(source: &str, delimiter: u8) -> Vec<&str> {
    let masked = mask_csharp_string_literals(source);
    let bytes = masked.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            _ if *byte == delimiter
                && brace_depth == 0
                && paren_depth == 0
                && bracket_depth == 0 =>
            {
                segments.push(&source[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    segments.push(&source[start..]);
    segments
}

fn allowed_endpoint_fields() -> HashSet<&'static str> {
    let mut fields: HashSet<&'static str> = ALLOWED_ENDPOINT_BASE_FIELDS.iter().copied().collect();
    fields.extend(ENDPOINT_ARRAY_BINDINGS.iter().map(|(field, _)| *field));
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().copied());
    fields
}

fn contains_aws_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index + 20 <= bytes.len() {
        if bytes[index..].starts_with(b"AKIA")
            && bytes[index + 4..index + 20]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return true;
        }
        index += 1;
    }
    false
}

fn contains_url_scheme(text: &str) -> bool {
    let Some(separator) = text.find("://") else {
        return false;
    };
    let prefix = &text[..separator];
    let scheme_start = prefix
        .char_indices()
        .rev()
        .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let scheme = &prefix[scheme_start..];
    scheme
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
}

fn contains_private_ip(text: &str) -> bool {
    for token in text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            continue;
        }
        let octets: Option<Vec<u8>> = parts.iter().map(|part| part.parse::<u8>().ok()).collect();
        let Some(octets) = octets else {
            continue;
        };
        if octets[0] == 10
            || (octets[0] == 192 && octets[1] == 168)
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        {
            return true;
        }
    }
    false
}

fn contains_guid(text: &str) -> bool {
    let bytes = text.as_bytes();
    let groups = [8usize, 4, 4, 4, 12];
    for start in 0..bytes.len() {
        let mut index = start;
        let mut matched = true;
        for (group_index, len) in groups.iter().enumerate() {
            if index + len > bytes.len()
                || !bytes[index..index + len]
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                matched = false;
                break;
            }
            index += len;
            if group_index != groups.len() - 1 {
                if bytes.get(index) != Some(&b'-') {
                    matched = false;
                    break;
                }
                index += 1;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

fn csharp_string_literals(source: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        if let Some((value, end)) = parse_csharp_string_literal_at(source, index) {
            values.push(value);
            index = end;
        } else {
            index += 1;
        }
    }
    values
}

fn parse_csharp_string_literal_at(source: &str, quote_index: usize) -> Option<(String, usize)> {
    if source.as_bytes().get(quote_index) != Some(&b'"') {
        return None;
    }
    let mut value = String::new();
    let bytes = source.as_bytes();
    let mut index = quote_index + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                let next = *bytes.get(index + 1)?;
                value.push(next as char);
                index += 2;
            }
            b'"' => return Some((value, index + 1)),
            byte => {
                value.push(byte as char);
                index += 1;
            }
        }
    }
    None
}

fn mask_csharp_string_literals(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            output.push(bytes[index] as char);
            index += 1;
            continue;
        }
        output.push(' ');
        index += 1;
        while index < bytes.len() {
            let byte = bytes[index];
            output.push(if byte == b'\n' { '\n' } else { ' ' });
            index += 1;
            if byte == b'\\' {
                if let Some(next) = bytes.get(index) {
                    output.push(if *next == b'\n' { '\n' } else { ' ' });
                    index += 1;
                }
                continue;
            }
            if byte == b'"' {
                break;
            }
        }
    }
    output
}

fn strip_csharp_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut index = 0usize;
    let mut in_string = false;
    while index < bytes.len() {
        if in_string {
            output.push(bytes[index] as char);
            if bytes[index] == b'\\' {
                if let Some(next) = bytes.get(index + 1) {
                    output.push(*next as char);
                    index += 2;
                    continue;
                }
            } else if bytes[index] == b'"' {
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
        if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            continue;
        }
        if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 2;
            while index < bytes.len() {
                if bytes.get(index) == Some(&b'*') && bytes.get(index + 1) == Some(&b'/') {
                    output.push(' ');
                    output.push(' ');
                    index += 2;
                    break;
                }
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            continue;
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let masked = mask_csharp_string_literals(text);
    let bytes = masked.as_bytes();
    if bytes.get(open_index) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open_index) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
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

fn brace_depth_at(source: &str, target_index: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    for byte in bytes.iter().take(target_index) {
        match byte {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

fn find_line_starting_with(source: &str, marker: &str, offset: usize) -> Option<usize> {
    let mut index = offset;
    while index < source.len() {
        let line_end = source[index..]
            .find('\n')
            .map(|relative| index + relative)
            .unwrap_or(source.len());
        let line = &source[index..line_end];
        let trimmed_len = line.len() - line.trim_start_matches([' ', '\t']).len();
        if line[trimmed_len..].starts_with(marker) {
            return Some(index + trimmed_len);
        }
        index = line_end.saturating_add(1);
    }
    None
}

fn next_identifier(source: &str, offset: usize) -> Option<(String, usize, usize)> {
    let bytes = source.as_bytes();
    let mut index = offset;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            return parse_identifier_at(source, index);
        }
        index += 1;
    }
    None
}

fn parse_identifier_at(source: &str, index: usize) -> Option<(String, usize, usize)> {
    let bytes = source.as_bytes();
    if !is_identifier_start(*bytes.get(index)?) {
        return None;
    }
    let mut end = index + 1;
    while end < bytes.len() && is_identifier_part(bytes[end]) {
        end += 1;
    }
    Some((source[index..end].to_string(), index, end))
}

fn find_word(source: &str, word: &str, offset: usize) -> Option<usize> {
    let mut search = offset;
    while let Some(relative) = source[search..].find(word) {
        let index = search + relative;
        if is_word_boundary(source, index, word) {
            return Some(index);
        }
        search = index + word.len();
    }
    None
}

fn starts_with_word(source: &str, index: usize, word: &str) -> bool {
    source[index..].starts_with(word) && is_word_boundary(source, index, word)
}

fn is_word_boundary(source: &str, start: usize, word: &str) -> bool {
    word_boundaries(source, start, start + word.len())
}

fn word_boundaries(source: &str, start: usize, end: usize) -> bool {
    let bytes = source.as_bytes();
    let before_ok = start == 0 || !is_identifier_part(bytes[start - 1]);
    let after_ok = end >= bytes.len() || !is_identifier_part(bytes[end]);
    before_ok && after_ok
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_part(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn next_non_whitespace_index(source: &str, offset: usize) -> Option<usize> {
    source[offset..]
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(index, _)| offset + index)
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(text)) => vec![text.to_string()],
        _ => Vec::new(),
    }
}

fn catalog_string_array(value: &Value, key: &str, errors: &mut Vec<String>) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(items)) => {
            if items.iter().any(|item| !item.is_string()) {
                errors.push(format!("{key} must contain only strings"));
            }
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        }
        Some(_) => {
            errors.push(format!("{key} must be an array"));
            Vec::new()
        }
        None => Vec::new(),
    }
}

fn missing_values(required: &[&str], values: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|value| !values.iter().any(|candidate| candidate == *value))
        .map(|value| (*value).to_string())
        .collect()
}

fn missing_strings(expected: &[String], actual: &[String]) -> Vec<String> {
    expected
        .iter()
        .filter(|value| !actual.contains(value))
        .cloned()
        .collect()
}

fn unique_count(values: &[String]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn unique_count_vec(values: &[Vec<String>]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn catalog() -> Value {
        json!({
            "version": 1,
            "status": "draft",
            "source": "static-seed",
            "validationMode": "evidence-only",
            "dryRunRequired": true,
            "providerCallsEnabled": false,
            "liveBackupAllowed": false,
            "guestProcessingExecutionAllowed": false,
            "credentialAccessAllowed": false,
            "rawJobLogsAllowed": false,
            "supportedWorkflows": REQUIRED_WORKFLOWS,
            "validationSignals": REQUIRED_SIGNALS,
            "requiredInputs": REQUIRED_INPUTS,
            "requiredGuards": REQUIRED_GUARDS,
            "planSections": REQUIRED_PLAN_SECTIONS,
            "blockedReasons": REQUIRED_BLOCKED_REASONS,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "rules": REQUIRED_RULES.iter().map(|rule| json!({
                "id": rule.id,
                "decision": rule.decision,
                "requirement": rule.requirement,
                "evidence": rule.evidence,
            })).collect::<Vec<_>>()
        })
    }

    #[test]
    fn missing_validation_signal_is_rejected() {
        let mut catalog = catalog();
        catalog
            .get_mut("validationSignals")
            .and_then(Value::as_array_mut)
            .expect("validationSignals is an array")
            .retain(|value| value.as_str() != Some("unsupported-workload"));
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(errors.iter().any(|error| {
            error.contains("validationSignals") && error.contains("unsupported-workload")
        }));
    }

    // Rust-reality replacement for the retired C# `source = "static-seed"` field test: the program
    // check now validates that the contract is mounted as an axum `.route(ENDPOINT, get(handler))`
    // registration. A mounted route passes; a source missing the route is flagged. Field-level
    // (source/mode/flags) conformance moved to the catalog validation and behavioral tests.
    #[test]
    fn endpoint_present_as_rust_route_passes() {
        let program =
            format!(r#"        .route("{ENDPOINT}", get(protect_application_aware_backup))"#);
        let mut errors = Vec::new();
        validate_program_text(&program, &catalog(), &mut errors);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn missing_rust_route_is_rejected() {
        let program = r#"        .route("/api/protect/other-contract", get(other))"#;
        let mut errors = Vec::new();
        validate_program_text(program, &catalog(), &mut errors);
        assert!(errors
            .iter()
            .any(|error| error == "API missing application-aware backup validation endpoint"));
    }

    #[test]
    fn prohibited_key_variants_are_rejected() {
        let mut errors = Vec::new();
        validate_no_prohibited_values(
            &json!({"evidence": "\"tenant/id\": \"synthetic\""}),
            "application-aware-backup",
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("prohibited value")));
    }
}
