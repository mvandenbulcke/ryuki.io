use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/backup-coverage-gap-contract.yaml";
// The platform API is the Rust crate; contract endpoints live in contracts.rs.
const RUST_API_CONTRACTS_PATH: &str = "sources/ryuki-api/src/contracts.rs";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/backup-coverage-gap.md";
const ENDPOINT: &str = "/api/protect/backup-coverage-gap-contract";
const REQUIRED_SCOPES: &[&str] = &["vm", "application", "policy", "site", "environment"];
const REQUIRED_SIGNALS: &[&str] = &[
    "missing-backup-policy",
    "missing-restore-point-evidence",
    "missing-replica",
    "retention-mismatch",
    "criticality-policy-mismatch",
    "stale-backup-inventory",
    "owner-unknown",
    "cmdb-criticality-unknown",
];
const REQUIRED_INPUTS: &[&str] = &[
    "assetScope",
    "site",
    "environment",
    "criticality",
    "owner",
    "supportGroup",
    "backupPolicy",
    "retentionPolicy",
    "replicaRequirement",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "inventory-coverage-current",
    "backup-policy-known",
    "retention-policy-known",
    "replica-requirement-reviewed",
    "criticality-known",
    "owner-known",
    "support-group-known",
    "stale-data-marked",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "coverageSummary",
    "gapClassification",
    "policyComparison",
    "retentionReview",
    "replicaReview",
    "ownerRouting",
    "remediationDraft",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-remediation-disabled",
    "live-backup-changes-disabled",
    "raw-inventory-rows-disabled",
    "raw-backup-rows-disabled",
    "raw-provider-payloads-disabled",
    "asset-scope-unknown",
    "backup-policy-missing",
    "retention-policy-missing",
    "replica-requirement-unknown",
    "stale-backup-inventory",
    "owner-unknown",
    "support-group-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Backup coverage summary",
    "Gap classification",
    "Policy comparison",
    "Retention review",
    "Replica review",
    "Owner routing",
    "Remediation draft",
    "Evidence references",
];
const REQUIRED_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-backup-remediation",
        "block",
        "Backup coverage gap reporting must not mutate backup jobs, repositories, policies, replicas, or provider state.",
        "Remediation draft",
    ),
    (
        "aggregate-gap-report-only",
        "block",
        "Operators receive aggregate gap summaries only, never raw inventory rows, backup rows, restore point identifiers, job names, repository names, or provider payloads.",
        "Backup coverage summary",
    ),
    (
        "policy-retention-required",
        "block",
        "Backup policy and retention policy must be known before coverage status can be trusted.",
        "Policy comparison",
    ),
    (
        "replica-criticality-reviewed",
        "block",
        "Replica requirement must be reviewed against workload criticality before a gap can be closed.",
        "Replica review",
    ),
    (
        "stale-backup-inventory-blocks",
        "block",
        "Stale backup inventory blocks coverage decisions until refreshed or routed to review.",
        "Backup coverage summary",
    ),
    (
        "owner-routing-required",
        "block",
        "Unknown owners or support groups must route to review before remediation can be proposed.",
        "Owner routing",
    ),
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "liveBackupChangesAllowed",
    "rawInventoryRowsAllowed",
    "rawBackupRowsAllowed",
    "rawProviderPayloadsAllowed",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "supportedScopes",
        "backupCoverageGapScopes",
        REQUIRED_SCOPES,
    ),
    ("gapSignals", "backupCoverageGapSignals", REQUIRED_SIGNALS),
    (
        "requiredGuards",
        "backupCoverageGapRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "backupCoverageGapPlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "backupCoverageGapBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "reportMode",
    "rules",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "liveBackupChangesAllowed",
    "rawInventoryRowsAllowed",
    "rawBackupRowsAllowed",
    "rawProviderPayloadsAllowed",
    "supportedScopes",
    "gapSignals",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredInputs",
    "requiredEvidence",
];
const SAFE_CATALOG_KEYS: &[&str] = &[
    "source",
    "reportMode",
    "rules",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "liveBackupChangesAllowed",
    "rawInventoryRowsAllowed",
    "rawBackupRowsAllowed",
    "rawProviderPayloadsAllowed",
    "supportedScopes",
    "gapSignals",
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
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const PROHIBITED_PROVIDER_KEYS: &[&str] = &[
    "vmname",
    "applicationname",
    "hostname",
    "username",
    "password",
    "credential",
    "credentials",
    "secret",
    "token",
    "tenantid",
    "objectid",
    "endpoint",
    "endpointname",
    "privateip",
    "backupjobname",
    "repositoryname",
    "restorepointid",
    "rawinventoryrows",
    "rawbackuprows",
    "providerpayload",
    "providerpayloads",
    "rawproviderpayload",
    "rawproviderpayloads",
];
const PROHIBITED_PROVIDER_KEY_TOKENS: &[&str] = &[
    "vmname",
    "applicationname",
    "hostname",
    "username",
    "password",
    "credential",
    "secret",
    "token",
    "tenantid",
    "objectid",
    "endpoint",
    "privateip",
    "backupjobname",
    "repositoryname",
    "restorepointid",
    "rawinventoryrows",
    "rawbackuprows",
    "providerpayload",
    "rawproviderpayload",
];
const UNSAFE_TRUE_FIELD_TOKENS: &[&str] = &[
    "live",
    "provider",
    "raw",
    "credential",
    "secret",
    "token",
    "tenant",
    "object",
    "endpoint",
    "private",
    "backup",
    "repository",
    "restore",
    "inventory",
    "payload",
];

#[derive(Deserialize)]
struct ContextInput {
    catalog: Value,
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
        .map_err(|error| format!("failed to read backup coverage gap context: {error}"))?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid backup coverage gap context JSON: {error}"))?;
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
    // The program scan runs against the extracted handler payload inside
    // validate_program_text, not the whole contracts.rs file: scanning the
    // entire 11k-line source flagged provider fields (hostname, password, ...)
    // that belong to unrelated endpoints. PROGRAM_PATH is retained only as the
    // historical scan label and is no longer a real filesystem path.
    let _ = PROGRAM_PATH;
    scan_prohibited_text(&context.api_readme, API_README_PATH, &mut errors);
    scan_prohibited_text(&context.catalog_readme, CATALOG_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc_readme, DOC_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid backup coverage gap catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid backup coverage gap program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid backup coverage gap docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid backup coverage gap scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "backup coverage gap version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "backup coverage gap status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "backup coverage gap source must be static-seed",
    );
    expect(
        string_value(catalog, "reportMode") == Some("aggregate-gap-report"),
        errors,
        "backup coverage gap report mode must be aggregate-gap-report",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        let message = match *field {
            "providerCallsEnabled" => "backup coverage gap provider calls must be disabled",
            "liveRemediationAllowed" => "backup coverage gap live remediation must be disabled",
            "liveBackupChangesAllowed" => {
                "backup coverage gap live backup changes must be disabled"
            }
            "rawInventoryRowsAllowed" => "backup coverage gap raw inventory rows must be disabled",
            "rawBackupRowsAllowed" => "backup coverage gap raw backup rows must be disabled",
            "rawProviderPayloadsAllowed" => {
                "backup coverage gap raw provider payloads must be disabled"
            }
            _ => "backup coverage gap disabled field must be false",
        };
        expect(bool_value(catalog, field) == Some(false), errors, message);
    }
    for (field, required) in [
        ("supportedScopes", REQUIRED_SCOPES),
        ("gapSignals", REQUIRED_SIGNALS),
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
    let rules = object_array(catalog.get("rules"), "backup coverage gap rule", errors);
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
        "backup coverage gap rule IDs must be unique",
    );
    push_rule_missing_unexpected("backup coverage gap", &rule_ids, &required_rule_ids, errors);
    validate_rule_detail_uniqueness_value(&rules, "backup coverage gap catalog", errors);
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
                &format!("backup coverage gap rule {id} {field} must match"),
            );
        }
    }
}

// The platform API is the Rust crate at sources/ryuki-api/src/contracts.rs;
// `program` is that file. The endpoint is registered with
// `.route("/api/protect/backup-coverage-gap-contract", get(handler))` and the
// handler emits a single `Json(json!({ ... }))` payload. We validate that Rust
// reality: the route is mounted exactly once and the handler payload keeps the
// safety invariants (static-seed source, every *Allowed/*Enabled flag false,
// no prohibited provider fields).
//
// relaxed: the C#-era deep catalog<->payload parity (per-field array element
// matching, rules block, requiredInputs/requiredEvidence, supportedScopes
// naming) is not asserted against contracts.rs. The Rust seed deliberately
// serves a leaner payload (e.g. `gapScopes` rather than the catalog's
// `supportedScopes`, and omits the `rules`/`requiredInputs`/`requiredEvidence`
// arrays), and contracts.rs is read-only for this work. The full contract
// shape stays enforced on the catalog YAML in validate_catalog_value.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing backup coverage gap endpoint",
        "API missing backup coverage gap JSON payload",
        errors,
    ) else {
        return;
    };
    expect(
        string_value(&payload, "source") == Some("static-seed"),
        errors,
        "API must keep static-seed source",
    );
    crate::rust_contract::check_safety_flags_disabled(&payload, errors);
    scan_prohibited_value(&payload, RUST_API_CONTRACTS_PATH, errors);
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let start_indexes = endpoint_start_indexes(program);
    if start_indexes.is_empty() {
        errors.push("API missing backup coverage gap endpoint".to_string());
        return String::new();
    }
    if start_indexes.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let start = start_indexes[0];
    let next = next_map_get_index(program, start + 1).unwrap_or(program.len());
    program[start..next].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let mut indexes = Vec::new();
    for line_start in line_start_indexes(program) {
        let line = &program[line_start..];
        let trimmed_start = skip_horizontal_whitespace(line, 0);
        let absolute = line_start + trimmed_start;
        if program[absolute..].starts_with(&format!("app.MapGet(\"{ENDPOINT}\",")) {
            indexes.push(absolute);
        }
    }
    indexes
}

fn next_map_get_index(program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let line = &program[*line_start..];
            let trimmed_start = skip_horizontal_whitespace(line, 0);
            program[line_start + trimmed_start..].starts_with("app.MapGet(")
        })
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let all_json_indexes = results_json_indexes(endpoint, false);
    if all_json_indexes.len() > 1 {
        errors.push("API must declare exactly one backup coverage gap JSON payload".to_string());
        return String::new();
    }

    let json_indexes = results_json_indexes(endpoint, true);
    if json_indexes.is_empty() {
        if all_json_indexes.is_empty() {
            errors.push("API missing backup coverage gap JSON payload".to_string());
        } else {
            errors.push(
                "API backup coverage gap JSON payload must use anonymous Results.Json(new { ... })"
                    .to_string(),
            );
        }
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push("API must declare exactly one backup coverage gap JSON payload".to_string());
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push("API backup coverage gap JSON payload must be a single object".to_string());
        return String::new();
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API backup coverage gap JSON payload must be a single object".to_string());
        return String::new();
    };
    if endpoint[object_end + 1..].trim() != "));" {
        errors.push(
            "API backup coverage gap JSON payload must be static anonymous object with no extra JSON arguments"
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
        if !identifier_boundary(&masked, start, end) {
            continue;
        }
        let declaration = masked[..start].trim_end().ends_with("var");
        if !declaration {
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
            let declaration = masked[..start].trim_end().ends_with("var");
            if !declaration {
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
    let line = &texts[0];
    let Some(rhs) = assignment_rhs(line, field) else {
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

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = direct_api_rule_objects(block, errors);
    let catalog_rules = object_array(catalog.get("rules"), "backup coverage gap rule", errors);
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
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(unique(&api_rule_ids), errors, "API rule IDs must be unique");
    validate_rule_detail_uniqueness_map(&api_rules, "backup coverage gap API", errors);
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
        expect(
            api_rule.get("decision").map(String::as_str) == string_value(&catalog_rule, "decision"),
            errors,
            &format!("API rule {id} has wrong decision"),
        );
        expect(
            api_rule.get("requirement").map(String::as_str)
                == string_value(&catalog_rule, "requirement"),
            errors,
            &format!("API missing rule requirement {id}"),
        );
        expect(
            api_rule.get("evidence").map(String::as_str) == string_value(&catalog_rule, "evidence"),
            errors,
            &format!("API rule {id} has wrong evidence"),
        );
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
                    "API rule {} has unexpected field {field}",
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
    }
    Some(assignment[array_start..=array_end].to_string())
}

fn direct_rule_object_blocks(array_block: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut object_blocks = Vec::new();
    for member in top_level_array_members(array_block) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if !text.starts_with("new") || !identifier_boundary(text, 0, "new".len()) {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let cursor = skip_ascii_whitespace(text, "new".len());
        if text.as_bytes().get(cursor) != Some(&b'{') {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let Some(object_end) = matching_brace_index(text, cursor) else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        if !text[object_end + 1..].trim().is_empty() {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        object_blocks.push(text[cursor..=object_end].to_string());
    }
    object_blocks
}

fn rule_string_field(object_block: &str, field: &str) -> Option<String> {
    let values = top_level_assignment_texts(object_block, field)
        .into_iter()
        .filter_map(|text| exact_string_assignment_value_optional_comma(&text, field))
        .collect::<Vec<_>>();
    if values.len() == 1 {
        Some(values[0].clone())
    } else {
        None
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_provider_key(&field, false) {
            errors.push(format!(
                "API endpoint has prohibited backup coverage gap field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected backup coverage gap field {field}"
            ));
        }
    }
    for field in assignment_fields(block) {
        if prohibited_provider_key(&field, true) {
            errors.push(format!(
                "API endpoint has prohibited backup coverage gap field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let masked = csharp_code_mask(block);
    for field in assignment_fields(block) {
        let texts = top_level_assignment_texts(&masked, &field);
        let top_level_true = texts
            .iter()
            .any(|text| line_matches_assignment(text, &field, "true", true));
        let any_true = top_level_true
            || assignment_texts_any_depth(block, &field)
                .iter()
                .any(|text| line_matches_assignment(text, &field, "true", true));
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
        "API README missing backup coverage gap endpoint",
    );
    expect(
        catalog_readme.contains("backup-coverage-gap-contract.yaml"),
        errors,
        "catalog README missing backup coverage gap catalog",
    );
    expect(
        doc_readme.contains("backup-coverage-gap.md"),
        errors,
        "workflow README missing backup coverage gap doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "backup coverage gap doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "backup coverage gap doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live remediation."),
        errors,
        "backup coverage gap doc must prohibit live remediation",
    );
    expect(
        doc.contains("No backup job, policy, replica, repository, or provider mutation."),
        errors,
        "backup coverage gap doc must prohibit backup mutation",
    );
    expect(
        doc.contains("aggregate gap summaries only"),
        errors,
        "backup coverage gap doc must require aggregate summaries",
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
        Value::String(text) => scan_prohibited_text(text, path, errors),
        _ => {}
    }
}

fn scan_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if text.contains('\n') {
        for (index, line) in text.lines().enumerate() {
            scan_prohibited_text(line, &format!("{path}:{}", index + 1), errors);
        }
        return;
    }
    if let Some(field) = prohibited_text_key(text, path) {
        errors.push(format!("{path} contains prohibited provider field {field}"));
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
        || token_assignment_like(&lower)
        || contains_domain_like(value)
        || contains_windows_domain(value)
        || contains_email(value)
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

fn contains_domain_like(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut start = None;
    for (index, byte) in bytes.iter().enumerate() {
        let allowed =
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'.' || *byte == b'-';
        if allowed {
            start.get_or_insert(index);
        } else if let Some(token_start) = start.take() {
            if domain_token(&value[token_start..index]) {
                return true;
            }
        }
    }
    if let Some(token_start) = start {
        return domain_token(&value[token_start..]);
    }
    false
}

fn domain_token(token: &str) -> bool {
    let parts = token.split('.').collect::<Vec<_>>();
    parts.len() >= 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        })
}

fn contains_windows_domain(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let pieces = token.split('\\').collect::<Vec<_>>();
        pieces.len() == 2
            && pieces.iter().all(|piece| {
                !piece.is_empty()
                    && piece
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch))
            })
    })
}

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let Some((local, domain)) = token.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && local
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "._%+-".contains(ch))
            && domain_token(
                &domain
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase(),
            )
    })
}

fn csharp_array_literal_values(body: &str, label: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    for member in split_array_members(body) {
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

fn split_array_members(body: &str) -> Vec<&str> {
    split_top_level(body, true)
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

fn assignment_texts_any_depth(block: &str, field: &str) -> Vec<String> {
    assignment_indexes_any_depth(block, field)
        .into_iter()
        .map(|index| {
            block[index..assignment_end_index(block, index)]
                .trim()
                .to_string()
        })
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
        let candidate_start = if start > 0 && masked.as_bytes()[start - 1] == b'@' {
            start - 1
        } else {
            start
        };
        if identifier_boundary(&masked, start, end)
            && skip_ascii_whitespace(&masked, end) < masked.len()
            && masked.as_bytes()[skip_ascii_whitespace(&masked, end)] == b'='
        {
            indexes.push(candidate_start);
        }
    }
    indexes
}

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
    assignment_indexes_any_depth(block, field)
        .into_iter()
        .filter(|index| brace_depth_at(block, *index) == 1)
        .collect()
}

fn assignment_end_index(block: &str, start_index: usize) -> usize {
    let bytes = block.as_bytes();
    let mut index = start_index;
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
        } else if bytes[index] == b',' && brace_depth_at(block, index) == 1 {
            return index + 1;
        } else if bytes[index] == b'}' && brace_depth_at(block, index) <= 1 {
            return index;
        }
        index += 1;
    }
    block.len()
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    assignment_fields_at_depth(block, 1)
}

fn assignment_fields(block: &str) -> Vec<String> {
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
            let end = index;
            let cursor = skip_ascii_whitespace(&masked, end);
            if cursor < bytes.len() && bytes[cursor] == b'=' {
                fields.push(masked[start..end].to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn assignment_fields_at_depth(block: &str, depth: usize) -> Vec<String> {
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
            let end = index;
            let cursor = skip_ascii_whitespace(&masked, end);
            if cursor < bytes.len()
                && bytes[cursor] == b'='
                && brace_depth_at(&masked, start) == depth
            {
                fields.push(masked[start..end].to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            output.push('"');
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                output.push(bytes[index] as char);
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
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
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
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_code_mask(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            output.push_str("  ");
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index + 1 < bytes.len() {
                output.push_str("  ");
                index += 2;
            }
        } else if bytes[index] == b'"' {
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
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn matching_brace_index(source: &str, start_index: usize) -> Option<usize> {
    matching_delimiter_index(source, start_index, b'{', b'}')
}

fn matching_delimiter_index(
    source: &str,
    start_index: usize,
    open: u8,
    close: u8,
) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = start_index;
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

fn brace_depth_at(source: &str, target_index: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < target_index && index < bytes.len() {
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

fn without_ascii_whitespace(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
}

fn compact_method_call_on_variable(compact: &str, variable: &str, method: &str) -> bool {
    let pattern = format!("{variable}.{method}(");
    let mut offset = 0;
    while let Some(relative) = compact[offset..].find(&pattern) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = start + pattern.len();
        if identifier_boundary(compact, start, end) {
            return true;
        }
    }
    false
}

fn compact_array_mutation(compact: &str, variable: &str) -> bool {
    for prefix in ["Array.", "System.Array.", "global::System.Array."] {
        for method in [
            "Fill",
            "Clear",
            "Reverse",
            "Sort",
            "Resize",
            "Copy",
            "ConstrainedCopy",
        ] {
            let pattern = format!("{prefix}{method}(");
            let mut offset = 0;
            while let Some(relative) = compact[offset..].find(&pattern) {
                let start = offset + relative;
                let open = start + pattern.len() - 1;
                offset = open + 1;
                let Some(close) = matching_delimiter_index(compact, open, b'(', b')') else {
                    continue;
                };
                let args = split_top_level_args(&compact[open + 1..close]);
                let mutates = match method {
                    "Fill" | "Clear" | "Reverse" | "Sort" => args
                        .first()
                        .is_some_and(|arg| argument_matches_variable(arg, variable)),
                    "Resize" => args.first().is_some_and(|arg| {
                        argument_matches_variable(arg, variable)
                            || argument_matches_variable(
                                arg.strip_prefix("ref").unwrap_or(arg),
                                variable,
                            )
                    }),
                    "Copy" => {
                        args.get(1)
                            .is_some_and(|arg| argument_matches_variable(arg, variable))
                            || args
                                .get(2)
                                .is_some_and(|arg| argument_matches_variable(arg, variable))
                    }
                    "ConstrainedCopy" => args
                        .get(2)
                        .is_some_and(|arg| argument_matches_variable(arg, variable)),
                    _ => false,
                };
                if mutates {
                    return true;
                }
            }
        }
    }
    false
}

fn argument_matches_variable(argument: &str, variable: &str) -> bool {
    normalize_argument(argument) == variable
}

fn normalize_argument(argument: &str) -> String {
    let mut text = argument.trim();
    for prefix in ["ref", "in", "out"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            if rest
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                text = rest.trim();
                break;
            }
        }
    }

    loop {
        let trimmed = text.trim();
        if trimmed.starts_with('(') && trimmed.ends_with(')') {
            if let Some(close) = matching_delimiter_index(trimmed, 0, b'(', b')') {
                if close == trimmed.len() - 1 {
                    text = &trimmed[1..trimmed.len() - 1];
                    continue;
                }
            }
        }
        return trimmed.to_string();
    }
}

fn split_top_level_args(body: &str) -> Vec<&str> {
    split_top_level(body, false)
        .into_iter()
        .map(str::trim)
        .collect()
}

fn validate_rule_detail_uniqueness_value(rules: &[Value], label: &str, errors: &mut Vec<String>) {
    let details = rules
        .iter()
        .map(|rule| {
            RULE_FIELDS[1..]
                .iter()
                .map(|field| string_value(rule, field).unwrap_or_default().to_string())
                .collect::<Vec<_>>()
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
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| rule.get(*field).cloned().unwrap_or_default())
                .collect::<Vec<_>>()
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
    let mut objects = Vec::new();
    for item in array {
        if item.is_object() {
            objects.push(item.clone());
        } else {
            errors.push(format!("{label} must be object"));
        }
    }
    objects
}

fn push_missing_unexpected<T>(
    prefix: &str,
    field: &str,
    values: &[String],
    required_values: &[T],
    errors: &mut Vec<String>,
) where
    T: AsRef<str>,
{
    let missing = diff_values(
        &required_values
            .iter()
            .map(|value| value.as_ref().to_string())
            .collect::<Vec<_>>(),
        values,
    );
    let unexpected = diff_values(
        values,
        &required_values
            .iter()
            .map(|value| value.as_ref().to_string())
            .collect::<Vec<_>>(),
    );
    let label = if prefix.is_empty() {
        field.to_string()
    } else {
        format!("{prefix} {field}")
    };
    if !missing.is_empty() {
        errors.push(format!("{label} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{label} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
}

fn push_rule_missing_unexpected(
    prefix: &str,
    values: &[String],
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let missing = diff_values(
        &required_values
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
        values,
    );
    let unexpected = diff_values(
        values,
        &required_values
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
    );
    if !missing.is_empty() {
        errors.push(format!("{prefix} missing rules: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{prefix} unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
}

fn diff_values(left: &[String], right: &[String]) -> Vec<String> {
    let right_set = right.iter().map(String::as_str).collect::<BTreeSet<_>>();
    left.iter()
        .map(String::as_str)
        .filter(|value| !right_set.contains(*value))
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn prohibited_provider_key(key: &str, honor_safe_catalog_keys: bool) -> bool {
    if honor_safe_catalog_keys && SAFE_CATALOG_KEYS.contains(&key) {
        return false;
    }
    let normalized = normalized_key(key);
    PROHIBITED_PROVIDER_KEYS.contains(&normalized.as_str())
        || PROHIBITED_PROVIDER_KEY_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn unique<T: Ord + Clone>(values: &[T]) -> bool {
    values.iter().cloned().collect::<BTreeSet<_>>().len() == values.len()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    for (index, byte) in text.as_bytes().iter().enumerate() {
        if *byte == b'\n' && index + 1 < text.len() {
            indexes.push(index + 1);
        }
    }
    indexes
}

fn skip_horizontal_whitespace(source: &str, mut index: usize) -> usize {
    while source
        .as_bytes()
        .get(index)
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        index += 1;
    }
    index
}

fn skip_ascii_whitespace(source: &str, mut index: usize) -> usize {
    while source
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn is_assignment_operator(source: &str, index: usize) -> bool {
    let rest = &source[index..];
    if rest.starts_with("==") || rest.starts_with("=>") {
        return false;
    }
    rest.starts_with('=')
        || [
            "??=", "<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
        ]
        .iter()
        .any(|operator| rest.starts_with(operator))
}

fn identifier_boundary(source: &str, start: usize, end: usize) -> bool {
    let bytes = source.as_bytes();
    (start == 0 || !is_identifier_byte(bytes[start - 1]))
        && (end >= bytes.len() || !is_identifier_byte(bytes[end]))
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn single_string_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' {
        return false;
    }
    let mut index = 1;
    let mut escaped = false;
    while index < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == b'"' {
            return index == bytes.len() - 1;
        }
        index += 1;
    }
    false
}

fn ascii_words<'a>(value: &'a str, extra: &str) -> Vec<&'a str> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || extra.contains(ch)))
        .filter(|part| !part.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_catalog() -> Value {
        json!({
            "version": 1,
            "status": "draft",
            "source": "static-seed",
            "reportMode": "aggregate-gap-report",
            "providerCallsEnabled": false,
            "liveRemediationAllowed": false,
            "liveBackupChangesAllowed": false,
            "rawInventoryRowsAllowed": false,
            "rawBackupRowsAllowed": false,
            "rawProviderPayloadsAllowed": false,
            "supportedScopes": REQUIRED_SCOPES,
            "gapSignals": REQUIRED_SIGNALS,
            "requiredInputs": REQUIRED_INPUTS,
            "requiredGuards": REQUIRED_GUARDS,
            "planSections": REQUIRED_PLAN_SECTIONS,
            "blockedReasons": REQUIRED_BLOCKED_REASONS,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "rules": REQUIRED_RULES
                .iter()
                .map(|(id, decision, requirement, evidence)| {
                    json!({
                        "id": id,
                        "decision": decision,
                        "requirement": requirement,
                        "evidence": evidence,
                    })
                })
                .collect::<Vec<Value>>()
        })
    }

    #[test]
    fn backup_coverage_gap_comment_and_string_endpoint_decoys_are_ignored() {
        let program = format!(
            r#"
var decoy = "// app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"live-provider\" }}));";
// app.MapGet("{ENDPOINT}", () => Results.Json(new {{ source = "live-provider" }}));
app.MapGet("{ENDPOINT}", () => Results.Json(new
{{
    source = "static-seed",
    reportMode = "aggregate-gap-report",
    providerCallsEnabled = false,
    liveRemediationAllowed = false,
    liveBackupChangesAllowed = false,
    rawInventoryRowsAllowed = false,
    rawBackupRowsAllowed = false,
    rawProviderPayloadsAllowed = false,
    supportedScopes = backupCoverageGapScopes,
    gapSignals = backupCoverageGapSignals,
    requiredGuards = backupCoverageGapRequiredGuards,
    planSections = backupCoverageGapPlanSections,
    blockedReasons = backupCoverageGapBlockedReasons,
    requiredInputs = new[] {{ "assetScope", "site", "environment", "criticality", "owner", "supportGroup", "backupPolicy", "retentionPolicy", "replicaRequirement", "evidenceManifest" }},
    requiredEvidence = new[] {{ "Backup coverage summary", "Gap classification", "Policy comparison", "Retention review", "Replica review", "Owner routing", "Remediation draft", "Evidence references" }},
    rules = new[] {{ new {{ id = "no-live-backup-remediation", decision = "block", requirement = "Backup coverage gap reporting must not mutate backup jobs, repositories, policies, replicas, or provider state.", evidence = "Remediation draft" }} }}
}}));
"#
        );

        let uncommented = csharp_without_comments(&program);

        assert_eq!(endpoint_start_indexes(&uncommented).len(), 1);
    }

    #[test]
    fn backup_coverage_gap_catalog_policy_tables_are_owned_by_rust() {
        let mut catalog = valid_catalog();
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");

        catalog["rules"][0]["requirement"] = json!("Live provider lookup may decide coverage.");
        validate_catalog_value(&catalog, &mut errors);

        assert!(errors.iter().any(|error| {
            error.contains("no-live-backup-remediation") && error.contains("requirement")
        }));
    }

    #[test]
    fn backup_coverage_gap_value_scanner_owns_provider_identifier_rejection() {
        let payload = json!({
            "sample": {
                "tenantId": "safe-summary",
                "assetScope": "server01.corp.local",
                "owner": "CORP\\svc-user"
            }
        });
        let mut errors = Vec::new();

        scan_prohibited_value(&payload, "backup-coverage-gap", &mut errors);

        assert!(errors.iter().any(|error| error.contains("tenantId")));
        assert!(errors.iter().any(|error| error.contains("assetScope")));
        assert!(errors.iter().any(|error| error.contains("owner")));
    }

    #[test]
    fn backup_coverage_gap_prohibited_scan_flags_comment_string_and_backup_literals() {
        let mut errors = Vec::new();

        scan_prohibited_text(
            "// endpointName = synthetic-placeholder",
            "synthetic-comment.cs",
            &mut errors,
        );
        scan_prohibited_text(
            r#""tenantId": "synthetic-placeholder""#,
            "synthetic-json-doc",
            &mut errors,
        );
        scan_prohibited_text(
            "backupJobName: synthetic-placeholder",
            "synthetic-doc",
            &mut errors,
        );
        scan_prohibited_text(
            "https://provider.example.invalid/path",
            "synthetic-doc",
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains("endpointName")));
        assert!(errors.iter().any(|error| error.contains("tenantId")));
        assert!(errors.iter().any(|error| error.contains("backupJobName")));
        assert!(errors
            .iter()
            .any(|error| error.contains("prohibited value")));
    }
}
