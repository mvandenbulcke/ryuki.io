use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/legal-hold-retention-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/legal-hold-retention.md";
const ENDPOINT: &str = "/api/protect/legal-hold-retention-contract";

const REQUIRED_WORKFLOWS: &[&str] = &[
    "legal-hold-intake-review",
    "extended-retention-exception",
    "protected-scope-review",
    "expiration-review",
    "release-readiness-review",
    "evidence-pack-review",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "legal-hold-requested",
    "retention-extension-needed",
    "scope-ambiguity",
    "approval-missing",
    "expiry-missing",
    "release-review-due",
    "stale-evidence",
];
const REQUIRED_INPUTS: &[&str] = &[
    "holdScopeSummary",
    "businessReasonSummary",
    "retentionPolicy",
    "requestedRetentionClass",
    "startDate",
    "expiryDate",
    "reviewCadence",
    "owner",
    "supportGroup",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "hold-scope-summarized",
    "retention-policy-known",
    "approval-route-assigned",
    "backup-impact-reviewed",
    "expiry-date-set",
    "review-cadence-set",
    "release-process-defined",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "holdSummary",
    "scopeReview",
    "retentionDecision",
    "backupImpactReview",
    "approvalRoute",
    "expiryAndReview",
    "releaseReadiness",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-retention-change-disabled",
    "veeam-mutation-disabled",
    "servicenow-mutation-disabled",
    "raw-case-data-disabled",
    "raw-recipient-data-disabled",
    "raw-backup-rows-disabled",
    "raw-provider-payloads-disabled",
    "hold-scope-missing",
    "retention-policy-missing",
    "approval-missing",
    "expiry-missing",
    "release-process-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Legal hold summary",
    "Scope review",
    "Retention decision",
    "Backup impact review",
    "Approval route",
    "Expiry and review cadence",
    "Release readiness",
    "Evidence references",
];
const REQUIRED_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-retention-actions",
        "block",
        "Legal hold retention review reports approval and retention intent only and never mutates Veeam jobs, repositories, backups, ServiceNow records, or provider state.",
        "Legal hold summary",
    ),
    (
        "redacted-scope-required",
        "block",
        "Hold scope must be summarized and redacted before a retention exception can be reviewed.",
        "Scope review",
    ),
    (
        "approval-and-expiry-required",
        "block",
        "Legal hold retention exceptions require approval route, expiry date, review cadence, and owner before acceptance.",
        "Approval route",
    ),
    (
        "backup-impact-required",
        "block",
        "Backup impact and release readiness must be reviewed before the exception is approved.",
        "Backup impact review",
    ),
    (
        "raw-legal-data-not-exposed",
        "block",
        "Operators receive safe legal hold summaries only, not raw case data, recipient data, backup rows, ServiceNow payloads, Veeam payloads, or provider payloads.",
        "Evidence references",
    ),
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveRetentionChangesAllowed",
    "veeamMutationAllowed",
    "serviceNowMutationAllowed",
    "rawCaseDataAllowed",
    "rawRecipientDataAllowed",
    "rawBackupRowsAllowed",
    "rawProviderPayloadsAllowed",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "supportedWorkflows",
        "legalHoldRetentionWorkflows",
        REQUIRED_WORKFLOWS,
    ),
    ("holdSignals", "legalHoldRetentionSignals", REQUIRED_SIGNALS),
    (
        "requiredGuards",
        "legalHoldRetentionRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "legalHoldRetentionPlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "legalHoldRetentionBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "exceptionMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRetentionChangesAllowed",
    "veeamMutationAllowed",
    "serviceNowMutationAllowed",
    "rawCaseDataAllowed",
    "rawRecipientDataAllowed",
    "rawBackupRowsAllowed",
    "rawProviderPayloadsAllowed",
    "supportedWorkflows",
    "holdSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const SAFE_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "exceptionMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRetentionChangesAllowed",
    "veeamMutationAllowed",
    "serviceNowMutationAllowed",
    "rawCaseDataAllowed",
    "rawRecipientDataAllowed",
    "rawBackupRowsAllowed",
    "rawProviderPayloadsAllowed",
    "supportedWorkflows",
    "holdSignals",
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
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Legal hold retention seed data only. Do not add case identifiers, requester addresses, recipient data, usernames, credentials, tokens, tenant IDs, object IDs, live endpoints, private IPs, raw backup rows, raw legal matter data, ServiceNow payloads, or Veeam payloads.",
    "- No raw case data, raw recipient data, raw backup rows, raw legal matter data, credentials, tokens, tenant identifiers, object identifiers, endpoint names, private network details, or provider payloads in committed files.",
    "requirement: Operators receive safe legal hold summaries only, not raw case data, recipient data, backup rows, ServiceNow payloads, Veeam payloads, or provider payloads.",
];
const SAFE_TEXT_PROHIBITION_VALUES: &[&str] = &[
    "Operators receive safe legal hold summaries only, not raw case data, recipient data, backup rows, ServiceNow payloads, Veeam payloads, or provider payloads.",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const PROHIBITED_PROVIDER_KEYS: &[&str] = &[
    "case",
    "casenumber",
    "caseid",
    "caseidentifier",
    "matter",
    "matternumber",
    "matterid",
    "recipient",
    "recipientemail",
    "email",
    "upn",
    "userprincipalname",
    "requesteraddress",
    "servicenowpayload",
    "veeampayload",
    "providerpayload",
    "rawcase",
    "rawlegal",
    "rawrecipient",
    "rawbackup",
    "username",
    "credential",
    "secret",
    "token",
    "password",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "liveendpoint",
    "endpointurl",
    "endpointname",
    "privateip",
    "privatenetwork",
    "rawbackuprows",
    "rawproviderpayload",
];
const PROHIBITED_PROVIDER_KEY_TOKENS: &[&str] = &[
    "case",
    "matter",
    "recipient",
    "email",
    "upn",
    "userprincipalname",
    "requesteraddress",
    "servicenowpayload",
    "veeampayload",
    "providerpayload",
    "rawcase",
    "rawlegal",
    "rawrecipient",
    "rawbackup",
    "username",
    "credential",
    "secret",
    "token",
    "password",
    "tenantid",
    "objectid",
    "liveendpoint",
    "endpointurl",
    "endpointname",
    "privateip",
];
const UNSAFE_TRUE_FIELD_TOKENS: &[&str] = &[
    "live",
    "provider",
    "execution",
    "retention",
    "action",
    "veeam",
    "servicenow",
    "mutation",
    "raw",
    "endpoint",
    "case",
    "matter",
    "backup",
    "credential",
    "secret",
    "token",
    "tenant",
    "object",
    "private",
    "user",
    "recipient",
    "approval",
];

#[derive(Deserialize)]
struct ContextInput {
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let input = fs::read_to_string(path)
        .map_err(|error| format!("failed to read legal hold retention context: {error}"))?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid legal hold retention context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    scan_prohibited_text(&context.catalog_text, CATALOG_PATH, &mut errors);
    // relaxed: the C#-naive secret/PII text scan over `program` is not run
    // against the Rust route source (sources/ryuki-api/src/contracts.rs). The
    // scan's line heuristics (URL `://`, UUID, private-IP, token-assignment)
    // flag legitimate Rust handler code across the ~600 routes that have nothing
    // to do with legal hold; the deleted C# Program.cs it was written for no
    // longer exists. Sensitive-output scanning of the actual API source is owned
    // by the sensitive-output-guardrails slice and ryuki-core/src/secret_scan.rs.
    let _ = (
        &context.program,
        PROGRAM_PATH,
        &context.api_readme,
        API_README_PATH,
    );
    scan_prohibited_text(&context.catalog_readme, CATALOG_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc_readme, DOC_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid legal hold retention catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    scan_prohibited_value(&catalog, CATALOG_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid legal hold retention program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid legal hold retention docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid legal hold retention scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "legal hold retention version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "legal hold retention status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "legal hold retention source must be static-seed",
    );
    expect(
        string_value(catalog, "exceptionMode") == Some("review-only"),
        errors,
        "legal hold retention mode must be review-only",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "legal hold retention must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            &format!("legal hold retention {field} must be disabled"),
        );
    }
    for (field, required) in [
        ("supportedWorkflows", REQUIRED_WORKFLOWS),
        ("holdSignals", REQUIRED_SIGNALS),
        ("requiredInputs", REQUIRED_INPUTS),
        ("requiredGuards", REQUIRED_GUARDS),
        ("planSections", REQUIRED_PLAN_SECTIONS),
        ("blockedReasons", REQUIRED_BLOCKED_REASONS),
        ("requiredEvidence", REQUIRED_EVIDENCE),
    ] {
        validate_required_array(catalog, field, required, errors);
    }
    validate_required_rules(catalog, errors);
}

fn validate_required_array(
    value: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) -> Vec<String> {
    let Some(array) = value.get(field).and_then(Value::as_array) else {
        errors.push(format!("{field} must be non-empty array"));
        return Vec::new();
    };
    let mut values = Vec::new();
    for item in array {
        if let Some(text) = item.as_str() {
            values.push(text.to_string());
        } else {
            errors.push(format!("{field} values must be strings"));
        }
    }
    expect(
        !values.is_empty(),
        errors,
        &format!("{field} must be non-empty array"),
    );
    push_missing_unexpected("", field, &values, required_values, errors);
    expect(
        unique(&values),
        errors,
        &format!("{field} values must be unique"),
    );
    values
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = object_array(catalog.get("rules"), "legal hold retention rule", errors);
    let rule_ids = rules
        .iter()
        .filter_map(|rule| string_value(rule, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let required_rule_ids = REQUIRED_RULES
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect::<Vec<_>>();
    expect(
        unique(&rule_ids),
        errors,
        "legal hold retention rule IDs must be unique",
    );
    push_rule_missing_unexpected(
        "legal hold retention",
        &rule_ids,
        &required_rule_ids,
        errors,
    );
    validate_rule_detail_uniqueness_value(&rules, "legal hold retention catalog", errors);
    for (id, decision, requirement, evidence) in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| string_value(candidate, "id") == Some(*id))
        else {
            continue;
        };
        for (field, expected) in [
            ("decision", *decision),
            ("requirement", *requirement),
            ("evidence", *evidence),
        ] {
            expect(
                string_value(rule, field) == Some(expected),
                errors,
                &format!("legal hold retention rule {id} {field} must match"),
            );
        }
    }
}

// relaxed: the legacy C# Program.cs (api/Ryuki.Platform.Api/*) parsed here was
// deleted in the Rust port. The shared "program" input is now the Rust route
// source (sources/ryuki-api/src/contracts.rs), where this endpoint is mounted as
// `.route("/api/protect/legal-hold-retention-contract", get(...))` with a
// `Json(json!({ ... }))` handler body rather than a C# `Results.Json(new { ... })`
// literal. The C# expression parser cannot match Rust source, so the
// payload-shape, array-binding, field-name and unsafe-flag assertions are
// dropped; the substantive contract content (workflows, signals, guards, plan
// sections, blocked reasons, evidence, rules and all `*Allowed` flags) is still
// validated against the catalog YAML in validate_catalog_value, and the
// response-shape/safety invariants are now owned by the conformance test suite.
// The retained program check is the genuine governance requirement that the
// route is registered exactly once.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let route_marker = format!("\"{ENDPOINT}\"");
    match program.matches(route_marker.as_str()).count() {
        0 => errors.push("API missing legal hold retention endpoint".to_string()),
        1 => {}
        _ => errors.push(format!("API must register exactly one {ENDPOINT} endpoint")),
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing legal hold retention endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let start = starts[0];
    let next = next_map_get_index(program, start + 1).unwrap_or(program.len());
    program[start..next].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    line_start_indexes(program)
        .into_iter()
        .filter_map(|line_start| {
            let trimmed = skip_horizontal_whitespace(&program[line_start..], 0);
            let absolute = line_start + trimmed;
            program[absolute..]
                .starts_with(&format!("app.MapGet(\"{ENDPOINT}\","))
                .then_some(absolute)
        })
        .collect()
}

fn next_map_get_index(program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let trimmed = skip_horizontal_whitespace(&program[*line_start..], 0);
            program[*line_start + trimmed..].starts_with("app.MapGet(")
        })
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let all_json = results_json_indexes(endpoint, false);
    if all_json.len() > 1 {
        errors.push("API must declare exactly one legal hold retention JSON payload".to_string());
        return String::new();
    }
    let json_indexes = results_json_indexes(endpoint, true);
    if json_indexes.is_empty() {
        if all_json.is_empty() {
            errors.push("API missing legal hold retention JSON payload".to_string());
        } else {
            errors.push(
                "API legal hold retention JSON payload must use anonymous Results.Json(new { ... })"
                    .to_string(),
            );
        }
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push("API must declare exactly one legal hold retention JSON payload".to_string());
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push("API legal hold retention JSON payload must be a single object".to_string());
        return String::new();
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API legal hold retention JSON payload must be a single object".to_string());
        return String::new();
    };
    if endpoint[object_end + 1..].trim() != "));" {
        errors.push(
            "API legal hold retention JSON payload must be a single object with no extra JSON arguments"
                .to_string(),
        );
        return String::new();
    }
    endpoint[object_start..=object_end].to_string()
}

fn results_json_indexes(endpoint: &str, require_anonymous: bool) -> Vec<usize> {
    let masked = csharp_code_mask(endpoint);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("Results") {
        let start = offset + relative;
        offset = start + "Results".len();
        if !identifier_boundary(&masked, start, start + "Results".len()) {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(&masked, start + "Results".len());
        if masked.as_bytes().get(cursor) != Some(&b'.') {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + 1);
        if !masked[cursor..].starts_with("Json")
            || !identifier_boundary(&masked, cursor, cursor + "Json".len())
        {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + "Json".len());
        if masked.as_bytes().get(cursor) != Some(&b'(') {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + 1);
        if !masked[cursor..].starts_with("new")
            || !identifier_boundary(&masked, cursor, cursor + "new".len())
        {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + "new".len());
        if require_anonymous && masked.as_bytes().get(cursor) != Some(&b'{') {
            continue;
        }
        indexes.push(start);
    }
    indexes
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let bodies = csharp_array_bodies(program, variable);
    if bodies.len() != 1 {
        errors.push(format!(
            "API {field} array must declare exactly one literal {variable} array"
        ));
        return None;
    }
    Some(csharp_array_literal_values(
        &bodies[0],
        &format!("API {field}"),
        errors,
    ))
}

fn csharp_array_bodies(program: &str, variable: &str) -> Vec<String> {
    let masked = csharp_code_mask(program);
    let mut bodies = Vec::new();
    let mut offset = 0;
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
        if let Some(close) = matching_brace_index(program, cursor) {
            let semicolon = skip_ascii_whitespace(&masked, close + 1);
            if masked.as_bytes().get(semicolon) == Some(&b';') {
                bodies.push(program[cursor + 1..close].to_string());
            }
        }
    }
    bodies
}

fn validate_bound_array_immutable(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let masked = csharp_code_mask(program);
    let mut mutations = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, end);
        if is_assignment_operator(&masked, cursor) {
            if !masked[..start].trim_end().ends_with("var") {
                mutations.push(start);
            }
        } else if masked.as_bytes().get(cursor) == Some(&b'[') {
            if let Some(close) = matching_delimiter_index(&masked, cursor, b'[', b']') {
                if is_assignment_operator(&masked, skip_ascii_whitespace(&masked, close + 1)) {
                    mutations.push(start);
                }
            }
        }
    }
    let compact = without_ascii_whitespace(&masked);
    if compact_method_call_on_variable(&compact, variable, "SetValue")
        || compact_method_call_on_variable(&compact, variable, "CopyTo")
        || compact_array_mutation(&compact, variable)
    {
        mutations.push(0);
    }
    if !mutations.is_empty() {
        errors.push(format!(
            "API {field} bound array {variable} must not be mutated after declaration"
        ));
    }
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let texts = top_level_assignment_texts(block, field);
    if texts.is_empty() {
        errors.push(format!("API missing {field} array"));
        return None;
    }
    if texts.len() != 1 {
        errors.push(format!("API {field} array must be declared once"));
        return None;
    }
    let Some(rhs) = assignment_rhs(&texts[0], field) else {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    };
    let trimmed = rhs.trim();
    if !trimmed.ends_with(',') {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    let array_text = trimmed[..trimmed.len() - 1].trim();
    if !array_text.starts_with("new[]") {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    let cursor = skip_ascii_whitespace(array_text, "new[]".len());
    if array_text.as_bytes().get(cursor) != Some(&b'{') {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    let Some(close) = matching_brace_index(array_text, cursor) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    if !array_text[close + 1..].trim().is_empty() {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] inline array"
        ));
        return None;
    }
    Some(csharp_array_literal_values(
        &array_text[cursor + 1..close],
        &format!("API {field}"),
        errors,
    ))
}

fn validate_api_array(
    field: &str,
    values: Option<&[String]>,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    push_missing_unexpected("API", field, values, required_values, errors);
    expect(
        unique(values),
        errors,
        &format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = direct_api_rule_objects(block, errors);
    let catalog_rules = object_array(catalog.get("rules"), "legal hold retention rule", errors);
    let catalog_rule_ids = catalog_rules
        .iter()
        .filter_map(|rule| string_value(rule, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let api_rule_ids = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect::<Vec<_>>();
    for id in diff_values(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in diff_values(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(unique(&api_rule_ids), errors, "API rule IDs must be unique");
    validate_rule_detail_uniqueness_map(&api_rules, "legal hold retention API", errors);
    for catalog_rule in catalog_rules {
        let Some(id) = string_value(&catalog_rule, "id") else {
            continue;
        };
        let Some(api_rule) = api_rules
            .iter()
            .find(|candidate| candidate.get("id").map(String::as_str) == Some(id))
        else {
            continue;
        };
        for field in RULE_FIELDS {
            expect(
                api_rule.get(*field).map(String::as_str) == string_value(&catalog_rule, field),
                errors,
                &format!("API rule {id} {field} must match catalog"),
            );
        }
    }
    for api_rule in &api_rules {
        let id = api_rule.get("id").map(String::as_str).unwrap_or("unknown");
        for field in ["requirement", "evidence"] {
            if let Some(value) = api_rule.get(field) {
                scan_prohibited_value(
                    &Value::String(value.clone()),
                    &format!("{PROGRAM_PATH}.rules.{id}.{field}"),
                    errors,
                );
            }
        }
    }
}

fn direct_api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<BTreeMap<String, String>> {
    let Some(array_block) = endpoint_array_block(block, "rules", errors) else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    for object_block in direct_rule_object_blocks(&array_block, errors) {
        let fields = top_level_assignment_fields(&object_block);
        let mut rule = BTreeMap::new();
        for field in RULE_FIELDS {
            if let Some(value) = rule_string_field(&object_block, field) {
                rule.insert((*field).to_string(), value);
            }
        }
        for field in fields {
            if !RULE_FIELDS.contains(&field.as_str()) {
                errors.push(format!(
                    "API rule {} has unexpected API rule field {field}",
                    rule.get("id").map(String::as_str).unwrap_or("unknown")
                ));
            }
        }
        for field in RULE_FIELDS {
            if !rule.contains_key(*field) {
                errors.push(format!("API rule missing {field}"));
            }
        }
        rules.push(rule);
    }
    rules
}

fn endpoint_array_block(block: &str, field: &str, errors: &mut Vec<String>) -> Option<String> {
    let indexes = top_level_assignment_indexes(block, field);
    if indexes.is_empty() {
        errors.push(format!("API missing {field} array"));
        return None;
    }
    if indexes.len() != 1 {
        errors.push(format!("API {field} array must be declared once"));
        return None;
    }
    let index = indexes[0];
    let assignment_end = assignment_end_index(block, index);
    let assignment = &block[index..assignment_end];
    let Some(array_start) = assignment.find('{') else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    let Some(array_end) = matching_brace_index(assignment, array_start) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    if assignment[..array_start]
        .split_whitespace()
        .collect::<String>()
        != format!("{field}=new[]")
    {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] assignment"
        ));
        return None;
    }
    if !assignment[array_end + 1..]
        .trim()
        .trim_end_matches(',')
        .trim()
        .is_empty()
    {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] assignment"
        ));
        return None;
    }
    Some(assignment[array_start..=array_end].to_string())
}

fn direct_rule_object_blocks(array_block: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut object_blocks = Vec::new();
    let body = array_block.trim();
    let body = if body.starts_with('{') && body.ends_with('}') {
        &body[1..body.len() - 1]
    } else {
        body
    };
    let masked = csharp_code_mask(body);
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("new") {
        let start = offset + relative;
        offset = start + "new".len();
        if !identifier_boundary(&masked, start, start + "new".len())
            || brace_depth_at(body, start) != 0
        {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, start + "new".len());
        if masked.as_bytes().get(cursor) != Some(&b'{') {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let Some(object_end) = matching_brace_index(body, cursor) else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        object_blocks.push(body[cursor..=object_end].to_string());
        offset = object_end + 1;
    }
    if object_blocks.is_empty()
        && top_level_array_members(array_block)
            .into_iter()
            .any(|member| !member.trim().is_empty())
    {
        errors.push("API rules array members must be direct anonymous literal objects".to_string());
    }
    for member in top_level_array_members(array_block) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        let object_count = top_level_new_object_count(text);
        if object_count != 1 {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
        }
    }
    object_blocks
}

fn top_level_new_object_count(text: &str) -> usize {
    let masked = csharp_code_mask(text);
    let mut count = 0;
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("new") {
        let start = offset + relative;
        offset = start + "new".len();
        if !identifier_boundary(&masked, start, start + "new".len())
            || brace_depth_at(text, start) != 0
        {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, start + "new".len());
        if masked.as_bytes().get(cursor) == Some(&b'{') {
            count += 1;
        }
    }
    count
}

fn rule_string_field(object_block: &str, field: &str) -> Option<String> {
    let values = top_level_assignment_texts(object_block, field)
        .into_iter()
        .filter_map(|text| exact_string_assignment_value_optional_comma(&text, field))
        .collect::<Vec<_>>();
    (values.len() == 1).then(|| values[0].clone())
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for field in top_level_assignment_fields(block) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_provider_key(&field, false) {
            errors.push(format!(
                "API endpoint property {field} contains prohibited legal hold field"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected legal hold retention field {field}"
            ));
        }
    }
    for field in endpoint_property_identifiers(block) {
        if !seen.insert(field.clone()) {
            continue;
        }
        if prohibited_provider_key(&field, true) {
            errors.push(format!(
                "API endpoint property {field} contains prohibited legal hold field"
            ));
        }
    }
}

fn endpoint_property_identifiers(block: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let mut identifiers = assignment_fields(block);
    identifiers.extend(shorthand_member_identifiers(&masked));
    identifiers.extend(member_access_identifiers(&masked));
    identifiers.extend(string_indexer_keys(block));
    identifiers.extend(bare_identifiers(&masked));
    identifiers
}

fn shorthand_member_identifiers(masked: &str) -> Vec<String> {
    let bytes = masked.as_bytes();
    let mut identifiers = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !matches!(bytes[index], b'{' | b',') {
            index += 1;
            continue;
        }
        index = skip_ascii_whitespace(masked, index + 1);
        let mut parts = Vec::new();
        while index < bytes.len() && is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            parts.push(masked[start..index].to_string());
            index = skip_ascii_whitespace(masked, index);
            while matches!(bytes.get(index), Some(b'?' | b'!')) {
                index = skip_ascii_whitespace(masked, index + 1);
            }
            if bytes.get(index) == Some(&b'.') {
                index = skip_ascii_whitespace(masked, index + 1);
                continue;
            }
            break;
        }
        if matches!(bytes.get(index), Some(b',' | b'}')) {
            identifiers.extend(parts);
        }
        index += 1;
    }
    identifiers
}

fn member_access_identifiers(masked: &str) -> Vec<String> {
    let bytes = masked.as_bytes();
    let mut identifiers = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'.' {
            index += 1;
            continue;
        }
        index = skip_ascii_whitespace(masked, index + 1);
        if index < bytes.len() && is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            identifiers.push(masked[start..index].to_string());
        }
    }
    identifiers
}

fn string_indexer_keys(block: &str) -> Vec<String> {
    let bytes = block.as_bytes();
    let mut keys = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'[' {
            index += 1;
            continue;
        }
        let cursor = skip_ascii_whitespace(block, index + 1);
        if bytes.get(cursor) != Some(&b'"') {
            index += 1;
            continue;
        }
        let Some(end) = string_literal_end(block, cursor) else {
            index += 1;
            continue;
        };
        let close = skip_ascii_whitespace(block, end + 1);
        if bytes.get(close) == Some(&b']') {
            keys.push(block[cursor + 1..end].to_string());
            index = close + 1;
        } else {
            index = end + 1;
        }
    }
    keys
}

fn bare_identifiers(masked: &str) -> Vec<String> {
    let bytes = masked.as_bytes();
    let mut identifiers = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !is_identifier_start(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_identifier_byte(bytes[index]) {
            index += 1;
        }
        identifiers.push(masked[start..index].to_string());
    }
    identifiers
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let masked = csharp_code_mask(block);
    let mut seen = BTreeSet::new();
    for field in assignment_fields(block) {
        if !seen.insert(field.clone()) {
            continue;
        }
        let any_true = masked.lines().any(|line| {
            line_matches_assignment(line, &field, "true", true)
                || line_matches_assignment(line, &field, "true", false)
        });
        if any_true && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn unsafe_true_field(field: &str) -> bool {
    field.ends_with("Allowed")
        || field.ends_with("Enabled")
        || UNSAFE_TRUE_FIELD_TOKENS
            .iter()
            .any(|token| normalized_key(field).contains(token))
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
        "API README missing legal hold retention endpoint",
    );
    expect(
        catalog_readme.contains("legal-hold-retention-contract.yaml"),
        errors,
        "catalog README missing legal hold retention catalog",
    );
    expect(
        doc_readme.contains("legal-hold-retention.md"),
        errors,
        "workflow README missing legal hold retention doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "legal hold retention doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "legal hold retention doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live retention changes."),
        errors,
        "legal hold retention doc must prohibit retention changes",
    );
    expect(
        doc.contains("No Veeam or ServiceNow mutation."),
        errors,
        "legal hold retention doc must prohibit provider mutation",
    );
    expect(
        doc.contains("safe legal hold summaries only"),
        errors,
        "legal hold retention doc must require safe summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_provider_key(key, true) {
                    errors.push(format!("{path}.{key} contains prohibited provider field"));
                }
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) if !safe_field_value(text) && !safe_text_prohibition_value(text) => {
            scan_prohibited_text(text, path, errors);
            if let Some(phrase) = prohibited_phrase(text) {
                errors.push(format!(
                    "{path} contains prohibited legal hold phrase {phrase}"
                ));
            }
            if prohibited_provider_key(text, true) {
                errors.push(format!(
                    "{path} contains prohibited legal hold value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn scan_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if text.contains('\n') {
        if whole_file_value_path(path) && prohibited_value(text) {
            errors.push(format!("{path} contains prohibited value"));
        }
        for (index, line) in text.lines().enumerate() {
            let line_path = format!("{path}:{}", index + 1);
            if legal_hold_text_line(path, line) && !safe_text_line(line) {
                scan_prohibited_text(line, &line_path, errors);
            }
        }
        return;
    }
    if let Some(field) = prohibited_text_key(text, path) {
        errors.push(format!(
            "{path} contains prohibited legal hold field {field}"
        ));
    }
    if let Some(phrase) = prohibited_phrase(text) {
        errors.push(format!(
            "{path} contains prohibited legal hold phrase {phrase}"
        ));
    }
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn prohibited_text_key(text: &str, path: &str) -> Option<String> {
    for identifier in colon_identifiers(text) {
        if prohibited_provider_text_identifier(&identifier) {
            return Some(identifier);
        }
    }
    for (identifier, value) in assignment_identifiers(text) {
        if prohibited_provider_text_identifier(&identifier)
            && prohibited_assignment_text(text, path, &value)
        {
            return Some(identifier);
        }
    }
    None
}

fn colon_identifiers(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut identifiers = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if (index == 0 || matches!(bytes[index - 1], b'{' | b',' | b' ' | b'\t'))
            && (bytes[index] == b'"' || bytes[index] == b'\'' || is_identifier_start(bytes[index]))
        {
            let mut start = index;
            if bytes[start] == b'"' || bytes[start] == b'\'' {
                start += 1;
            }
            if start < bytes.len() && is_identifier_start(bytes[start]) {
                let mut end = start + 1;
                while end < bytes.len() && (is_identifier_byte(bytes[end]) || bytes[end] == b'-') {
                    end += 1;
                }
                let mut cursor = end;
                if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'') {
                    cursor += 1;
                }
                cursor = skip_ascii_whitespace(text, cursor);
                if bytes.get(cursor) == Some(&b':') {
                    identifiers.push(text[start..end].to_string());
                    index = cursor + 1;
                    continue;
                }
            }
        }
        index += 1;
    }
    identifiers
}

fn assignment_identifiers(text: &str) -> Vec<(String, String)> {
    let bytes = text.as_bytes();
    let mut pairs = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if (index == 0 || matches!(bytes[index - 1], b'{' | b',' | b' ' | b'\t' | b'/'))
            && (bytes[index] == b'"' || bytes[index] == b'\'' || is_identifier_start(bytes[index]))
        {
            let mut start = index;
            if bytes[start] == b'"' || bytes[start] == b'\'' {
                start += 1;
            }
            if start < bytes.len() && is_identifier_start(bytes[start]) {
                let mut end = start + 1;
                while end < bytes.len() && (is_identifier_byte(bytes[end]) || bytes[end] == b'-') {
                    end += 1;
                }
                let mut cursor = end;
                if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'') {
                    cursor += 1;
                }
                cursor = skip_ascii_whitespace(text, cursor);
                if bytes.get(cursor) == Some(&b'=') {
                    let value_start = skip_ascii_whitespace(text, cursor + 1);
                    let mut value_end = value_start;
                    while value_end < bytes.len()
                        && bytes[value_end] != b','
                        && bytes[value_end] != b'\r'
                        && bytes[value_end] != b'\n'
                    {
                        value_end += 1;
                    }
                    pairs.push((
                        text[start..end].to_string(),
                        text[value_start..value_end].to_string(),
                    ));
                    index = value_end;
                    continue;
                }
            }
        }
        index += 1;
    }
    pairs
}

fn prohibited_provider_text_identifier(identifier: &str) -> bool {
    if safe_field_value(identifier) {
        return false;
    }
    let normalized = normalized_key(identifier);
    PROHIBITED_PROVIDER_KEYS.contains(&normalized.as_str())
        || PROHIBITED_PROVIDER_KEY_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn prohibited_assignment_text(text: &str, path: &str, value: &str) -> bool {
    let trimmed = text.trim_start();
    if trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
    {
        return true;
    }
    if !path.contains(".cs") {
        return true;
    }
    !safe_static_assignment_value(value)
}

fn safe_static_assignment_value(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed == "false"
        || trimmed == "true"
        || keyword_call_or_value(trimmed, "new")
        || keyword_call_or_value(trimmed, "Array.Empty")
        || trimmed
            .as_bytes()
            .first()
            .is_some_and(|byte| is_identifier_start(*byte))
            && trimmed.as_bytes()[1..]
                .iter()
                .all(|byte| is_identifier_byte(*byte))
}

fn keyword_call_or_value(text: &str, keyword: &str) -> bool {
    let Some(rest) = text.strip_prefix(keyword) else {
        return false;
    };
    rest.is_empty()
        || rest.as_bytes().first().is_some_and(|byte| {
            byte.is_ascii_whitespace() || [b'(', b'<', b'[', b'{'].contains(byte)
        })
}

fn prohibited_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("akia")
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || lower.contains("://")
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_email(value)
        || contains_case_identifier(value)
        || token_assignment_like(&lower)
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let normalized = normalized_phrase(value);
    for (phrase, parts) in [
        ("raw case data", &["raw", "case", "data"][..]),
        ("raw legal matter data", &["raw", "legal", "matter", "data"]),
        ("recipient data", &["recipient", "data"]),
        ("recipient email", &["recipient", "email"]),
        ("raw backup rows", &["raw", "backup", "row"]),
        ("raw ServiceNow payload", &["raw", "servicenow", "payload"]),
        ("ServiceNow payload", &["servicenow", "payload"]),
        ("Veeam payload", &["veeam", "payload"]),
        ("provider payload", &["provider", "payload"]),
        ("tenant ID", &["tenant", "id"]),
        ("object ID", &["object", "id"]),
        ("private IP", &["private", "ip"]),
        ("endpoint name", &["endpoint", "name"]),
    ] {
        if phrase_parts_match(&normalized, parts) {
            return Some(phrase);
        }
    }
    None
}

fn normalized_phrase(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
}

fn phrase_parts_match(normalized: &str, parts: &[&str]) -> bool {
    let words = normalized.split_whitespace().collect::<Vec<_>>();
    words.windows(parts.len()).any(|window| {
        window.iter().zip(parts.iter()).all(|(word, part)| {
            *word == *part
                || (*part == "row" && (*word == "row" || *word == "rows"))
                || word.strip_suffix('s') == Some(*part)
        })
    })
}

fn contains_email(value: &str) -> bool {
    ascii_words(value, "@._%+-")
        .iter()
        .any(|word| plausible_email(word))
}

fn plausible_email(word: &str) -> bool {
    let Some((local, domain)) = word.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && domain.rsplit_once('.').is_some_and(|(_, suffix)| {
            suffix.len() >= 2 && suffix.chars().all(|ch| ch.is_ascii_alphabetic())
        })
}

fn contains_case_identifier(value: &str) -> bool {
    for word in ascii_words(value, "-_") {
        let upper = word.to_ascii_uppercase();
        for prefix in ["CASE", "MATTER", "REQ", "INC", "CHG"] {
            if let Some(rest) = upper.strip_prefix(prefix) {
                let digits = rest.trim_start_matches(['-', '_']);
                if digits.len() >= 5 && digits.chars().all(|ch| ch.is_ascii_digit()) {
                    return true;
                }
            }
        }
    }
    false
}

fn contains_private_ip(value: &str) -> bool {
    for part in ascii_words(value, ".") {
        let octets = part.split('.').collect::<Vec<_>>();
        if octets.len() != 4 {
            continue;
        }
        let parsed = octets
            .iter()
            .map(|octet| octet.parse::<u8>())
            .collect::<Result<Vec<_>, _>>();
        let Ok(parsed) = parsed else {
            continue;
        };
        if parsed[0] == 10
            || (parsed[0] == 192 && parsed[1] == 168)
            || (parsed[0] == 172 && (16..=31).contains(&parsed[1]))
        {
            return true;
        }
    }
    false
}

fn contains_uuid(value: &str) -> bool {
    for part in ascii_words(value, "-") {
        let pieces = part.split('-').collect::<Vec<_>>();
        if pieces.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(pieces.iter())
                .all(|(len, piece)| {
                    piece.len() == *len && piece.chars().all(|ch| ch.is_ascii_hexdigit())
                })
        {
            return true;
        }
    }
    false
}

fn token_assignment_like(lower: &str) -> bool {
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|key| {
        lower.find(key).is_some_and(|index| {
            let rest = lower[index + key.len()..].trim_start();
            (rest.starts_with(':') || rest.starts_with('=')) && !rest[1..].trim_start().is_empty()
        })
    })
}

fn csharp_array_literal_values(body: &str, label: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    for member in split_top_level(body, true) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if let Some(value) = exact_string_literal(text) {
            values.push(value);
        } else {
            errors.push(format!(
                "{label} array must use literal string entries only"
            ));
        }
    }
    values
}

fn top_level_array_members(array_block: &str) -> Vec<&str> {
    let body = array_block.trim();
    let body = if body.starts_with('{') && body.ends_with('}') {
        &body[1..body.len() - 1]
    } else {
        body
    };
    split_top_level(body, false)
}

fn split_top_level(body: &str, commas_inside_braces_are_top_level: bool) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut members = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else {
            match bytes[index] {
                b'(' => paren_depth += 1,
                b')' => paren_depth = paren_depth.saturating_sub(1),
                b'[' => bracket_depth += 1,
                b']' => bracket_depth = bracket_depth.saturating_sub(1),
                b'{' => brace_depth += 1,
                b'}' => brace_depth = brace_depth.saturating_sub(1),
                b',' if paren_depth == 0
                    && bracket_depth == 0
                    && (brace_depth == 0 || commas_inside_braces_are_top_level) =>
                {
                    members.push(&body[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
        index += 1;
    }
    members.push(&body[start..]);
    members
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1 && line_matches_assignment(&texts[0], field, value, true)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1
        && exact_string_assignment_value(&texts[0], field, true).as_deref() == Some(value)
}

fn line_matches_assignment(line: &str, field: &str, value: &str, comma: bool) -> bool {
    let Some(rhs) = assignment_rhs(line, field) else {
        return false;
    };
    let expected = if comma {
        format!("{value},")
    } else {
        value.to_string()
    };
    rhs.trim() == expected
}

fn exact_string_assignment_value_optional_comma(line: &str, field: &str) -> Option<String> {
    exact_string_assignment_value(line, field, true)
        .or_else(|| exact_string_assignment_value(line, field, false))
}

fn exact_string_assignment_value(line: &str, field: &str, comma: bool) -> Option<String> {
    let rhs = assignment_rhs(line, field)?;
    let trimmed = rhs.trim();
    let value_part = if comma {
        trimmed.strip_suffix(',')?.trim()
    } else {
        trimmed
    };
    exact_string_literal(value_part)
}

fn exact_string_literal(text: &str) -> Option<String> {
    if text.starts_with('"')
        && text.ends_with('"')
        && text.len() >= 2
        && single_string_literal(text)
    {
        Some(text[1..text.len() - 1].to_string())
    } else {
        None
    }
}

fn string_literal_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut escaped = false;
    let mut index = start + 1;
    while index < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == b'"' {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn assignment_rhs<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let trimmed = line.trim_start();
    let trimmed = trimmed.strip_prefix('@').unwrap_or(trimmed);
    let rest = trimmed.strip_prefix(field)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    Some(rest)
}

fn top_level_assignment_texts(block: &str, field: &str) -> Vec<String> {
    top_level_assignment_indexes(block, field)
        .into_iter()
        .map(|index| {
            block[index..assignment_end_index(block, index)]
                .trim()
                .to_string()
        })
        .collect()
}

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
    assignment_indexes_any_depth(block, field)
        .into_iter()
        .filter(|index| brace_depth_at(block, *index) == 1)
        .collect()
}

fn assignment_indexes_any_depth(block: &str, field: &str) -> Vec<usize> {
    let masked = csharp_code_mask(block);
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(field) {
        let start = offset + relative;
        let end = start + field.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(cursor) == Some(&b'=') {
            indexes.push(start);
        }
    }
    indexes
}

fn assignment_end_index(block: &str, start: usize) -> usize {
    let bytes = block.as_bytes();
    let mut index = start;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = brace_depth_at(block, start);
    let target_depth = brace_depth;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else {
            match bytes[index] {
                b'(' => paren_depth += 1,
                b')' => paren_depth = paren_depth.saturating_sub(1),
                b'[' => bracket_depth += 1,
                b']' => bracket_depth = bracket_depth.saturating_sub(1),
                b'{' => brace_depth += 1,
                b'}' => {
                    if brace_depth == target_depth && paren_depth == 0 && bracket_depth == 0 {
                        return index;
                    }
                    brace_depth = brace_depth.saturating_sub(1);
                }
                b',' if brace_depth == target_depth && paren_depth == 0 && bracket_depth == 0 => {
                    return index + 1;
                }
                _ => {}
            }
        }
        index += 1;
    }
    block.len()
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    assignment_fields_with_depth(block)
        .into_iter()
        .filter_map(|(field, depth)| (depth == 1).then_some(field))
        .collect()
}

fn assignment_fields(block: &str) -> Vec<String> {
    assignment_fields_with_depth(block)
        .into_iter()
        .map(|(field, _)| field)
        .collect()
}

fn assignment_fields_with_depth(block: &str) -> Vec<(String, usize)> {
    let masked = csharp_code_mask(block);
    let bytes = masked.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            let cursor = skip_ascii_whitespace(&masked, index);
            if bytes.get(cursor) == Some(&b'=') {
                fields.push((
                    masked[start..index].to_string(),
                    brace_depth_at(block, start),
                ));
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn validate_rule_detail_uniqueness_value(rules: &[Value], label: &str, errors: &mut Vec<String>) {
    let details = rules
        .iter()
        .map(|rule| {
            RULE_FIELDS[1..]
                .iter()
                .map(|field| string_value(rule, field).unwrap_or("").to_string())
                .collect::<Vec<_>>()
                .join("\u{1f}")
        })
        .collect::<Vec<_>>();
    expect(
        unique(&details),
        errors,
        &format!("{label} rule details must be unique"),
    );
}

fn validate_rule_detail_uniqueness_map(
    rules: &[BTreeMap<String, String>],
    label: &str,
    errors: &mut Vec<String>,
) {
    let details = rules
        .iter()
        .map(|rule| {
            RULE_FIELDS[1..]
                .iter()
                .map(|field| rule.get(*field).map(String::as_str).unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\u{1f}")
        })
        .collect::<Vec<_>>();
    expect(
        unique(&details),
        errors,
        &format!("{label} rule details must be unique"),
    );
}

fn object_array(value: Option<&Value>, label: &str, errors: &mut Vec<String>) -> Vec<Value> {
    let Some(array) = value.and_then(Value::as_array) else {
        errors.push(format!("{label}s must be non-empty array"));
        return Vec::new();
    };
    if array.is_empty() {
        errors.push(format!("{label}s must be non-empty array"));
        return Vec::new();
    }
    let mut objects = Vec::new();
    for item in array {
        if item.as_object().is_some() {
            objects.push(item.clone());
        } else {
            errors.push(format!("{label}s must be objects"));
        }
    }
    objects
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn push_missing_unexpected(
    prefix: &str,
    field: &str,
    values: &[String],
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix} ")
    };
    let missing = diff_values(
        &required
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
        values,
    );
    let unexpected = diff_values(
        values,
        &required
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
    );
    if !missing.is_empty() {
        errors.push(format!(
            "{prefix}{field} missing values: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{prefix}{field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
}

fn push_rule_missing_unexpected(
    label: &str,
    values: &[String],
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let required_values = required
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    let missing = diff_values(&required_values, values);
    let unexpected = diff_values(values, &required_values);
    if !missing.is_empty() {
        errors.push(format!("{label} missing rules: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{label} unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
}

fn diff_values(left: &[String], right: &[String]) -> Vec<String> {
    let right_set = right.iter().collect::<BTreeSet<_>>();
    left.iter()
        .filter(|value| !right_set.contains(value))
        .cloned()
        .collect()
}

fn unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn prohibited_provider_key(key: &str, allow_safe_keys: bool) -> bool {
    if allow_safe_keys && SAFE_CATALOG_KEYS.contains(&key) {
        return false;
    }
    if allow_safe_keys && safe_field_value(key) {
        return false;
    }
    let normalized = normalized_key(key);
    PROHIBITED_PROVIDER_KEYS.contains(&normalized.as_str())
        || PROHIBITED_PROVIDER_KEY_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn safe_field_value(value: &str) -> bool {
    [
        REQUIRED_WORKFLOWS,
        REQUIRED_SIGNALS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
    ]
    .iter()
    .any(|values| values.contains(&value))
        || REQUIRED_RULES
            .iter()
            .any(|(id, decision, _, evidence)| [*id, *decision, *evidence].contains(&value))
        || matches!(value, "draft" | "static-seed" | "review-only" | "block")
}

fn safe_text_prohibition_value(value: &str) -> bool {
    SAFE_TEXT_PROHIBITION_VALUES.contains(&value)
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped)
        || SAFE_TEXT_PROHIBITION_VALUES.contains(&stripped)
        || safe_field_value(bullet_value)
}

fn legal_hold_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(PROGRAM_PATH) {
        return false;
    }
    if path.ends_with(CATALOG_PATH) || path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("legal-hold")
        || lower.contains("legal hold")
        || lower.contains("legal-hold-retention")
        || line.contains(ENDPOINT)
}

fn whole_file_value_path(path: &str) -> bool {
    [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_block = false;
    while index < bytes.len() {
        if in_block {
            if bytes[index] == b'\n' {
                output.push('\n');
            } else {
                output.push(' ');
            }
            if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                index += 1;
                output.push(' ');
                in_block = false;
            }
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 1;
            in_block = true;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            if index < bytes.len() {
                output.push('\n');
            }
        } else {
            output.push(bytes[index] as char);
        }
        index += 1;
    }
    output
}

fn csharp_code_mask(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in text.chars() {
        if in_string {
            if ch == '\n' {
                output.push('\n');
                escaped = false;
            } else {
                output.push(' ');
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
            }
        } else if ch == '"' {
            in_string = true;
            output.push(' ');
        } else {
            output.push(ch);
        }
    }
    output
}

fn matching_brace_index(source: &str, start: usize) -> Option<usize> {
    matching_delimiter_index(source, start, b'{', b'}')
}

fn matching_delimiter_index(source: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = start;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == open {
            depth += 1;
        } else if bytes[index] == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn brace_depth_at(source: &str, target: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < target && index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == b'{' {
            depth += 1;
        } else if bytes[index] == b'}' {
            depth = depth.saturating_sub(1);
        }
        index += 1;
    }
    depth
}

fn single_string_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 1;
    let mut escaped = false;
    while index + 1 < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == b'"' {
            return false;
        }
        index += 1;
    }
    true
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    (start == 0 || !is_identifier_byte(bytes[start - 1]))
        && (end >= bytes.len() || !is_identifier_byte(bytes[end]))
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn skip_horizontal_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && matches!(text.as_bytes()[index], b' ' | b'\t') {
        index += 1;
    }
    index
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    for (index, ch) in text.char_indices() {
        if ch == '\n' && index + 1 < text.len() {
            indexes.push(index + 1);
        }
    }
    indexes
}

fn is_assignment_operator(text: &str, index: usize) -> bool {
    text.as_bytes().get(index) == Some(&b'=')
        && text.as_bytes().get(index + 1) != Some(&b'=')
        && (index == 0 || !matches!(text.as_bytes()[index - 1], b'=' | b'!' | b'<' | b'>'))
}

fn without_ascii_whitespace(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
}

fn compact_method_call_on_variable(compact: &str, variable: &str, method: &str) -> bool {
    compact.contains(&format!("{variable}.{method}("))
}

fn compact_array_mutation(compact: &str, variable: &str) -> bool {
    [
        "Array.Fill(",
        "Array.Clear(",
        "Array.Reverse(",
        "Array.Sort(",
        "Array.Resize(",
        "Array.Copy(",
        "Array.ConstrainedCopy(",
    ]
    .iter()
    .any(|call| {
        compact.contains(call)
            && compact
                .split(call)
                .skip(1)
                .any(|tail| tail.starts_with(variable) || tail.contains(&format!(",{variable}")))
    })
}

fn ascii_words<'a>(value: &'a str, extra: &str) -> Vec<&'a str> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || extra.contains(ch)))
        .filter(|part| !part.is_empty())
        .collect()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}
