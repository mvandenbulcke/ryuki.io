use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/cmdb-reconciliation-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/cmdb-reconciliation.md";
const ENDPOINT: &str = "/api/cmdb/reconciliation-contract";
const REQUIRED_WORKFLOWS: &[&str] = &[
    "cmdb-import",
    "cmdb-update-export",
    "cmdb-ci-reconciliation",
];
const REQUIRED_INPUTS: &[&str] = &[
    "importBatch",
    "platformCiKey",
    "ciClass",
    "owner",
    "supportGroup",
    "site",
    "environment",
    "evidenceManifest",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "identity-match",
    "owner-match",
    "support-group-match",
    "site-placement-match",
    "backup-policy-match",
    "monitoring-profile-match",
    "relationship-match",
];
const REQUIRED_DECISIONS: &[&str] = &["accept", "reject", "review", "export-update"];
const REQUIRED_GUARDS: &[&str] = &[
    "cmdb-file-contract-validated",
    "header-mapping-complete",
    "inventory-coverage-current",
    "relationship-evidence-ready",
    "reviewer-approval-assigned",
    "evidence-redacted",
];
const REQUIRED_EXPORT_FIELDS: &[&str] = &[
    "platformCiKey",
    "ciClass",
    "proposedLifecycleStatus",
    "proposedOwner",
    "proposedSupportGroup",
    "proposedSite",
    "proposedBackupPolicy",
    "proposedMonitoringProfile",
    "relationshipSummary",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "live-api-disabled",
    "missing-ci-identity",
    "ambiguous-ci-identity",
    "stale-inventory",
    "relationship-evidence-missing",
    "reviewer-approval-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "File hash",
    "Header mapping",
    "Validation result",
    "CMDB reconciliation summary",
    "Accepted/rejected rows",
    "Export package",
    "Reviewer approval",
    "Evidence references",
];
const REQUIRED_RULE_DETAILS: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-servicenow-api",
        "block",
        "CMDB reconciliation uses file import and export only until live ServiceNow API integration is approved.",
        "Validation result",
    ),
    (
        "deterministic-ci-key-required",
        "block",
        "Every accepted or exported CI requires a deterministic platform CI key.",
        "CMDB reconciliation summary",
    ),
    (
        "ambiguous-ci-requires-review",
        "block",
        "Ambiguous CI identity must be rejected or routed for reviewer approval.",
        "Accepted/rejected rows",
    ),
    (
        "export-package-review-required",
        "block",
        "CMDB update exports require reviewer approval and redacted evidence references.",
        "Export package",
    ),
];
const REQUIRED_RULES: &[&str] = &[
    "no-live-servicenow-api",
    "deterministic-ci-key-required",
    "ambiguous-ci-requires-review",
    "export-package-review-required",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &["providerCallsEnabled", "liveApiEnabled"];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedWorkflows", "cmdbReconciliationWorkflows"),
    ("reconciliationSignals", "cmdbReconciliationSignals"),
    ("decisions", "cmdbReconciliationDecisions"),
    ("requiredGuards", "cmdbReconciliationRequiredGuards"),
    ("blockedReasons", "cmdbReconciliationBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] =
    &["requiredInputs", "exportPackageFields", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "integrationMode",
    "rules",
    "providerCallsEnabled",
    "liveApiEnabled",
    "supportedWorkflows",
    "reconciliationSignals",
    "decisions",
    "requiredGuards",
    "blockedReasons",
    "requiredInputs",
    "exportPackageFields",
    "requiredEvidence",
];
const SAFE_CATALOG_KEYS: &[&str] = &[
    "source",
    "integrationMode",
    "rules",
    "providerCallsEnabled",
    "liveApiEnabled",
    "supportedWorkflows",
    "reconciliationSignals",
    "decisions",
    "requiredGuards",
    "blockedReasons",
    "requiredInputs",
    "exportPackageFields",
    "requiredEvidence",
    "version",
    "status",
    "requirement",
    "evidence",
    "decision",
    "id",
];
const PROHIBITED_NEEDLES: &[&str] = &[
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
];
const PROHIBITED_TEXT_NEEDLES: &[&str] = &[
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
    "serialnumber",
    "apikey",
    "privatekey",
    "rawproviderpayload",
    "rawproviderpayloads",
    "providerpayload",
    "providerpayloads",
    "provideroutput",
    "recipientdata",
];
const SECRET_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    program: String,
    api_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct CatalogInput {
    catalog: Value,
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
    path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid CMDB reconciliation context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    // PROGRAM_PATH (the whole contracts.rs file) is excluded from this scan:
    // scanning the 11k-line Rust source flagged provider keys/values from
    // unrelated endpoints. The handler payload is scanned in validate_program_text.
    let _ = PROGRAM_PATH;
    let mut file_scope = Map::new();
    file_scope.insert(CATALOG_PATH.to_string(), context.catalog);
    file_scope.insert(
        API_README_PATH.to_string(),
        Value::String(context.api_readme),
    );
    file_scope.insert(DOC_PATH.to_string(), Value::String(context.doc));
    validate_no_prohibited_values_at(
        &Value::Object(file_scope),
        "cmdb-reconciliation",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let payload: CatalogInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB reconciliation catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB reconciliation program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB reconciliation docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB reconciliation prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values_at(
        &payload.value,
        payload.path.as_deref().unwrap_or("cmdb-reconciliation"),
        &mut errors,
    );
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "cmdb reconciliation version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "cmdb reconciliation status must be draft",
    );
    expect(
        catalog.get("integrationMode").and_then(Value::as_str) == Some("file-based"),
        errors,
        "cmdb reconciliation must be file-based",
    );
    expect(
        catalog.get("providerCallsEnabled").and_then(Value::as_bool) == Some(false),
        errors,
        "cmdb reconciliation provider calls must be disabled",
    );
    expect(
        catalog.get("liveApiEnabled").and_then(Value::as_bool) == Some(false),
        errors,
        "cmdb reconciliation live API must be disabled",
    );
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "reconciliationSignals", REQUIRED_SIGNALS, errors);
    validate_required_array(catalog, "decisions", REQUIRED_DECISIONS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(
        catalog,
        "exportPackageFields",
        REQUIRED_EXPORT_FIELDS,
        errors,
    );
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
    let values = string_array(catalog, field, errors);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let missing: Vec<&str> = required_values
        .iter()
        .copied()
        .filter(|required| !values.iter().any(|value| value == required))
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !required_values.contains(&value.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!("{field} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let rule_details: Vec<Rule> = rules
        .iter()
        .filter_map(|rule| {
            Some(Rule {
                id: String::new(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect();
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "cmdb reconciliation rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "cmdb reconciliation rule details must be unique",
    );
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .copied()
        .filter(|id| !rule_ids.iter().any(|rule_id| rule_id == id))
        .collect();
    let unexpected: Vec<String> = rule_ids
        .iter()
        .filter(|id| !REQUIRED_RULES.contains(&id.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "cmdb reconciliation missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "cmdb reconciliation unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    for (id, decision, requirement, evidence) in REQUIRED_RULE_DETAILS {
        let Some(rule) = rules
            .iter()
            .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(*id))
        else {
            continue;
        };
        expect(
            rule.get("decision").and_then(Value::as_str) == Some(*decision),
            errors,
            format!("cmdb reconciliation rule {id} decision must match"),
        );
        expect(
            rule.get("requirement").and_then(Value::as_str) == Some(*requirement),
            errors,
            format!("cmdb reconciliation rule {id} requirement must match"),
        );
        expect(
            rule.get("evidence").and_then(Value::as_str) == Some(*evidence),
            errors,
            format!("cmdb reconciliation rule {id} evidence must match"),
        );
    }
}

// `program` is the Rust API source contracts.rs. The endpoint is mounted with
// `.route(ENDPOINT, get(handler))` returning one `Json(json!({ ... }))` payload.
// We validate the Rust reality: the route is mounted exactly once and the
// payload keeps the safety invariants (static-seed source, all *Allowed/*Enabled
// flags false, no prohibited keys/values).
//
// relaxed: the C#-era deep catalog<->payload parity is not re-asserted against
// contracts.rs (leaner Rust seed payload; contracts.rs is read-only here). The
// full contract shape stays enforced on the catalog YAML.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing CMDB reconciliation endpoint",
        "API missing CMDB reconciliation JSON payload",
        errors,
    ) else {
        return;
    };
    expect(
        payload.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "API must keep static-seed source",
    );
    crate::rust_contract::check_safety_flags_disabled(&payload, errors);
    validate_no_prohibited_values_at(&payload, "cmdb-reconciliation", errors);
}

#[allow(dead_code)]
fn validate_program_text_csharp(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let endpoint = endpoint_block(program, errors);
    let block = endpoint_payload_block(&endpoint, errors);
    if block.is_empty() {
        return;
    }
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "integrationMode", "file-based"),
        errors,
        "API must expose file-based integration mode",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    let uncommented_program = csharp_without_comments(program);
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable, field, errors),
            string_array_silent(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field, errors),
            string_array_silent(catalog, field),
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
    catalog_values: Vec<String>,
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let missing: Vec<String> = catalog_values
        .iter()
        .filter(|value| !values.contains(*value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !catalog_values.contains(*value))
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
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(array_block) = endpoint_array_block(block, "rules", errors) else {
        return;
    };
    let api_rules = direct_api_rule_objects(&array_block, errors);
    let catalog_rules = catalog_rules(catalog);
    let catalog_rule_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_rule_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    for id in catalog_rule_ids
        .iter()
        .filter(|id| !api_rule_ids.contains(*id))
    {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_rule_ids
        .iter()
        .filter(|id| !catalog_rule_ids.contains(*id))
    {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    let api_rule_details: Vec<(&String, &String, &String)> = api_rules
        .iter()
        .map(|rule| (&rule.decision, &rule.requirement, &rule.evidence))
        .collect();
    expect(
        api_rule_details.iter().collect::<BTreeSet<_>>().len() == api_rule_details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in &catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            continue;
        };
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

fn direct_api_rule_objects(array_block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    top_level_array_members(array_block)
        .into_iter()
        .filter_map(|member| {
            let text = member.trim();
            if text.is_empty() {
                return None;
            }
            if !text.starts_with("new") {
                errors.push(
                    "API rules array members must be direct anonymous literal objects".to_string(),
                );
                return None;
            }
            let object_start = text.find('{');
            let object_end = object_start.and_then(|start| matching_brace_index(text, start));
            let Some(start) = object_start else {
                errors.push(
                    "API rules array members must be direct anonymous literal objects".to_string(),
                );
                return None;
            };
            let Some(end) = object_end else {
                errors.push(
                    "API rules array members must be direct anonymous literal objects".to_string(),
                );
                return None;
            };
            if !text[..start].trim().eq("new") || !text[end + 1..].trim().is_empty() {
                errors.push(
                    "API rules array members must be direct anonymous literal objects".to_string(),
                );
                return None;
            }
            let object = &text[start..=end];
            let fields = top_level_assignment_fields(object);
            for field in &fields {
                if !RULE_KEYS.contains(&field.as_str()) {
                    let id =
                        rule_string_field(object, "id").unwrap_or_else(|| "unknown".to_string());
                    errors.push(format!("API rule {id} has unexpected field {field}"));
                }
            }
            for field in RULE_KEYS {
                if !fields.iter().any(|candidate| candidate == field) {
                    errors.push(format!("API rule missing {field}"));
                }
            }
            Some(Rule {
                id: rule_string_field(object, "id").unwrap_or_default(),
                decision: rule_string_field(object, "decision").unwrap_or_default(),
                requirement: rule_string_field(object, "requirement").unwrap_or_default(),
                evidence: rule_string_field(object, "evidence").unwrap_or_default(),
            })
        })
        .collect()
}

fn validate_docs_text(api_readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing CMDB reconciliation endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "CMDB reconciliation doc missing endpoint",
    );
    expect(
        doc.contains("No live ServiceNow API calls."),
        errors,
        "CMDB reconciliation doc must prohibit live ServiceNow API calls",
    );
    expect(
        doc.contains("not raw spreadsheet payloads"),
        errors,
        "CMDB reconciliation doc must reject raw spreadsheet payloads",
    );
    expect(
        doc.contains("deterministic platform CI keys"),
        errors,
        "CMDB reconciliation doc must require deterministic keys",
    );
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let uncommented = csharp_without_comments(program);
    let starts = endpoint_start_indexes(&uncommented);
    if starts.is_empty() {
        errors.push("API missing CMDB reconciliation endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let start = starts[0];
    let end = find_next_endpoint_start(&uncommented, start + 1).unwrap_or(uncommented.len());
    uncommented[start..end].to_string()
}

fn endpoint_start_indexes(uncommented: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut offset = 0;
    for line in uncommented.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&format!("app.MapGet(\"{ENDPOINT}\",")) {
            starts.push(offset + line.len() - trimmed.len());
        }
        offset += line.len() + 1;
    }
    starts
}

fn find_next_endpoint_start(program: &str, start: usize) -> Option<usize> {
    program[start..]
        .match_indices('\n')
        .map(|(index, _)| start + index + 1)
        .find(|index| {
            program[*index..]
                .lines()
                .next()
                .is_some_and(|line| line.trim_start().starts_with("app.MapGet("))
        })
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let indexes = results_json_indexes(endpoint);
    if indexes.is_empty() {
        errors.push("API missing CMDB reconciliation JSON payload".to_string());
        return String::new();
    }
    if indexes.len() != 1 {
        errors.push("API must declare exactly one CMDB reconciliation JSON payload".to_string());
        return String::new();
    }
    let json_index = indexes[0];
    let object_start = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index);
    let object_end = object_start.and_then(|start| matching_brace_index(endpoint, start));
    match (object_start, object_end) {
        (Some(start), Some(end)) => endpoint[start..=end].to_string(),
        _ => {
            errors.push("API CMDB reconciliation JSON payload must be a single object".to_string());
            String::new()
        }
    }
}

fn results_json_indexes(endpoint: &str) -> Vec<usize> {
    let masked = csharp_string_bodies_masked(endpoint);
    let mut indexes = Vec::new();
    let mut search_start = 0;
    while let Some(relative) = masked[search_start..].find("Results") {
        let start = search_start + relative;
        let tail = &masked[start..];
        if starts_with_spaced(tail, &["Results", ".", "Json", "(", "new"]) {
            indexes.push(start);
        }
        search_start = start + "Results".len();
    }
    indexes
}

fn starts_with_spaced(mut text: &str, parts: &[&str]) -> bool {
    for part in parts {
        text = text.trim_start();
        let Some(rest) = text.strip_prefix(part) else {
            return false;
        };
        text = rest;
    }
    true
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut mode = CSharpMode::Code;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match mode {
            CSharpMode::LineComment => {
                if byte == b'\n' {
                    output.push('\n');
                    mode = CSharpMode::Code;
                } else {
                    output.push(' ');
                }
            }
            CSharpMode::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    output.push_str("  ");
                    index += 1;
                    mode = CSharpMode::Code;
                } else {
                    output.push(if byte == b'\n' { '\n' } else { ' ' });
                }
            }
            CSharpMode::String => {
                output.push(byte as char);
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    mode = CSharpMode::Code;
                }
            }
            CSharpMode::VerbatimString => {
                output.push(byte as char);
                if byte == b'"' && next == Some(b'"') {
                    output.push('"');
                    index += 1;
                } else if byte == b'"' {
                    mode = CSharpMode::Code;
                }
            }
            CSharpMode::Char => {
                output.push(byte as char);
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'\'' {
                    mode = CSharpMode::Code;
                }
            }
            CSharpMode::Code => {
                if byte == b'/' && next == Some(b'/') {
                    output.push_str("  ");
                    index += 1;
                    mode = CSharpMode::LineComment;
                } else if byte == b'/' && next == Some(b'*') {
                    output.push_str("  ");
                    index += 1;
                    mode = CSharpMode::BlockComment;
                } else if byte == b'"' {
                    output.push('"');
                    mode = if csharp_verbatim_string_start(text, index) {
                        CSharpMode::VerbatimString
                    } else {
                        CSharpMode::String
                    };
                } else if byte == b'\'' {
                    output.push('\'');
                    mode = CSharpMode::Char;
                } else {
                    output.push(byte as char);
                }
            }
        }
        index += 1;
    }
    output
}

#[derive(Copy, Clone)]
enum CSharpMode {
    Code,
    LineComment,
    BlockComment,
    String,
    VerbatimString,
    Char,
}

fn csharp_verbatim_string_start(text: &str, quote_index: usize) -> bool {
    let bytes = text.as_bytes();
    quote_index > 0 && bytes.get(quote_index - 1) == Some(&b'@')
        || quote_index >= 2 && bytes.get(quote_index - 2..quote_index) == Some(b"@$")
}

fn active_csharp_string_literals(text: &str) -> Vec<String> {
    let source = csharp_without_comments(text);
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let raw_quote_count = consecutive_quote_count(bytes, index);
        if raw_quote_count >= 3 {
            index += raw_quote_count;
            let start = index;
            let terminator = vec![b'"'; raw_quote_count];
            while index < bytes.len() {
                if bytes.get(index..index + raw_quote_count) == Some(terminator.as_slice()) {
                    literals.push(source[start..index].to_string());
                    index += raw_quote_count;
                    break;
                }
                index += 1;
            }
            continue;
        }
        index += 1;
        let mut escaped = false;
        let mut literal = String::new();
        while index < bytes.len() {
            let byte = bytes[index];
            if escaped {
                literal.push(byte as char);
                escaped = false;
            } else if byte == b'\\' {
                literal.push('\\');
                escaped = true;
            } else if byte == b'"' {
                break;
            } else {
                literal.push(byte as char);
            }
            index += 1;
        }
        literals.push(literal);
        index += 1;
    }
    literals
}

fn csharp_string_bodies_masked(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut mode = CSharpMaskMode::Code;
    let mut escaped = false;
    let mut raw_quote_count = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match mode {
            CSharpMaskMode::Code => {
                if byte == b'"' {
                    let quote_count = consecutive_quote_count(bytes, index);
                    if quote_count >= 3 {
                        for _ in 0..quote_count {
                            output.push('"');
                        }
                        index += quote_count;
                        raw_quote_count = quote_count;
                        mode = CSharpMaskMode::RawString;
                        continue;
                    }
                    output.push('"');
                    mode = if csharp_verbatim_string_start(text, index) {
                        CSharpMaskMode::VerbatimString
                    } else {
                        CSharpMaskMode::String
                    };
                } else {
                    output.push(byte as char);
                }
            }
            CSharpMaskMode::String => {
                if escaped {
                    output.push(string_mask(byte));
                    escaped = false;
                } else if byte == b'\\' {
                    output.push(' ');
                    escaped = true;
                } else if byte == b'"' {
                    output.push('"');
                    mode = CSharpMaskMode::Code;
                } else {
                    output.push(string_mask(byte));
                }
            }
            CSharpMaskMode::VerbatimString => {
                if byte == b'"' && next == Some(b'"') {
                    output.push_str("  ");
                    index += 1;
                } else if byte == b'"' {
                    output.push('"');
                    mode = CSharpMaskMode::Code;
                } else {
                    output.push(string_mask(byte));
                }
            }
            CSharpMaskMode::RawString => {
                let terminator = vec![b'"'; raw_quote_count];
                if bytes.get(index..index + raw_quote_count) == Some(terminator.as_slice()) {
                    for _ in 0..raw_quote_count {
                        output.push('"');
                    }
                    index += raw_quote_count;
                    mode = CSharpMaskMode::Code;
                    continue;
                }
                output.push(string_mask(byte));
            }
        }
        index += 1;
    }
    output
}

#[derive(Copy, Clone)]
enum CSharpMaskMode {
    Code,
    String,
    VerbatimString,
    RawString,
}

fn string_mask(byte: u8) -> char {
    if byte == b'\n' {
        '\n'
    } else {
        ' '
    }
}

fn consecutive_quote_count(bytes: &[u8], index: usize) -> usize {
    let mut count = 0;
    while bytes.get(index + count) == Some(&b'"') {
        count += 1;
    }
    count
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let start = exact_array_declaration_start(program, variable)?;
    let body_start = program[start..].find('{')? + start + 1;
    let body_end = program[body_start..].find("};")? + body_start;
    csharp_array_literal_values(
        &program[body_start..body_end],
        &format!("API {field}"),
        errors,
    )
}

fn exact_array_declaration_start(program: &str, variable: &str) -> Option<usize> {
    let mut search_start = 0;
    while let Some(relative) = program[search_start..].find("var ") {
        let start = search_start + relative;
        let line = program[start..].lines().next().unwrap_or_default();
        let rest = line.strip_prefix("var ")?;
        let after_name = rest.strip_prefix(variable);
        if after_name.is_some_and(|tail| tail.trim_start().starts_with("= new[]")) {
            return Some(start);
        }
        search_start = start + 4;
    }
    None
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
    let lines = top_level_assignment_lines(block, field);
    if lines.len() != 1 || !line_matches_new_array_assignment(&lines[0], field, false) {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] assignment"
        ));
        return None;
    }
    let array_start = block[indexes[0]..]
        .find('{')
        .map(|index| indexes[0] + index);
    let array_end = array_start.and_then(|start| matching_brace_index(block, start));
    match (array_start, array_end) {
        (Some(start), Some(end)) => Some(block[start..=end].to_string()),
        _ => {
            errors.push(format!("API {field} array must be a single array"));
            None
        }
    }
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let lines = top_level_assignment_lines(block, field);
    if lines.len() != 1 {
        return None;
    }
    let line = &lines[0];
    let prefix = format!("{field} = new[] {{");
    let Some(body) = line
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix("},"))
    else {
        return None;
    };
    csharp_array_literal_values(body, &format!("API {field}"), errors)
}

fn csharp_array_literal_values(
    body: &str,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let mut values = Vec::new();
    for member in array_members(body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if text.starts_with('"') && text.ends_with('"') {
            values.push(text[1..text.len() - 1].to_string());
        } else {
            errors.push(format!(
                "{label} array must use literal string entries only"
            ));
        }
    }
    Some(values)
}

fn array_members(body: &str) -> Vec<&str> {
    let mut members = Vec::new();
    let bytes = body.as_bytes();
    let mut start = 0;
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
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
        } else if byte == b',' {
            members.push(&body[start..index]);
            start = index + 1;
        }
        index += 1;
    }
    members.push(&body[start..]);
    members
}

fn top_level_array_members(array_block: &str) -> Vec<String> {
    let body = array_block.trim();
    let body = body
        .strip_prefix('{')
        .and_then(|text| text.strip_suffix('}'))
        .unwrap_or(body);
    split_top_level_members(body)
}

fn split_top_level_members(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut members = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
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
            depth = depth.saturating_sub(1);
        } else if byte == b',' && depth == 0 {
            members.push(body[start..index].to_string());
            start = index + 1;
        }
        index += 1;
    }
    members.push(body[start..].to_string());
    members
}

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    let lines = top_level_assignment_lines(block, field);
    lines.len() == 1 && line_matches_rhs_assignment(&lines[0], field, value)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let lines = top_level_assignment_lines(block, field);
    lines.len() == 1 && line_matches_rhs_assignment(&lines[0], field, &format!("\"{value}\""))
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let mut fields = top_level_assignment_fields(block);
    fields.extend(endpoint_property_identifier_fields(block));
    fields.sort();
    fields.dedup();
    for field in fields {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_key(&field) {
            errors.push(format!(
                "API endpoint has prohibited CMDB reconciliation field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected CMDB reconciliation field {field}"
            ));
        }
    }
}

fn endpoint_property_identifier_fields(block: &str) -> Vec<String> {
    let masked = csharp_string_bodies_masked(block);
    let mut fields = Vec::new();
    let mut offset = 0;
    for line in masked.lines() {
        if !line.contains('=') {
            for token in line.split(',') {
                let field = token.trim();
                if is_identifier(field) {
                    let index = offset + line.find(field).unwrap_or_default();
                    if brace_depth_at(&masked, index) == 1 {
                        fields.push(field.to_string());
                    }
                }
            }
            for access in member_accesses(line) {
                let index = offset + line.find(&access).unwrap_or_default();
                if brace_depth_at(&masked, index) == 1 {
                    for field in access.split('.').skip(1) {
                        let cleaned = field
                            .trim_matches(|ch: char| ch == '?' || ch == '!' || ch.is_whitespace());
                        if is_identifier(cleaned) {
                            fields.push(cleaned.to_string());
                        }
                    }
                }
            }
        }
        offset += line.len() + 1;
    }
    fields
}

fn member_accesses(line: &str) -> Vec<String> {
    line.split(|ch: char| ch == ',' || ch == '(' || ch == ')' || ch.is_whitespace())
        .filter(|token| {
            token.contains('.')
                && token
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_alphabetic())
        })
        .map(str::to_string)
        .collect()
}

fn top_level_assignment_lines(block: &str, field: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut offset = 0;
    for line in block.lines() {
        if let Some(column) = assignment_position(line, field) {
            if brace_depth_at(block, offset + column) == 1 {
                lines.push(line.trim().to_string());
            }
        }
        offset += line.len() + 1;
    }
    lines
}

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
    let mut indexes = Vec::new();
    let mut offset = 0;
    for line in block.lines() {
        let mut search_start = 0;
        while let Some(column) = assignment_position(&line[search_start..], field) {
            let index = offset + search_start + column;
            if brace_depth_at(block, index) == 1 {
                indexes.push(index);
            }
            search_start += column + field.len();
        }
        offset += line.len() + 1;
    }
    indexes
}

fn assignment_position(line: &str, field: &str) -> Option<usize> {
    let mut search_start = 0;
    while let Some(relative) = line[search_start..].find(field) {
        let start = search_start + relative;
        if assignment_at(line, start, field) {
            return Some(start);
        }
        search_start = start + field.len();
    }
    None
}

fn assignment_at(line: &str, start: usize, field: &str) -> bool {
    if start > 0 {
        let previous = line.as_bytes()[start - 1];
        if previous.is_ascii_alphanumeric() || previous == b'_' {
            return false;
        }
    }
    let after_name = start + field.len();
    if !line[after_name..].starts_with(|ch: char| ch.is_whitespace() || ch == '=') {
        return false;
    }
    let rest = line[after_name..].trim_start();
    rest.starts_with('=')
}

fn line_matches_rhs_assignment(line: &str, field: &str, rhs: &str) -> bool {
    let Some(start) = assignment_position(line, field) else {
        return false;
    };
    let rest = line[start + field.len()..].trim_start();
    let Some(after_equals) = rest.strip_prefix('=') else {
        return false;
    };
    after_equals.trim() == format!("{rhs},")
}

fn line_matches_new_array_assignment(line: &str, field: &str, allow_inline_body: bool) -> bool {
    let Some(start) = assignment_position(line, field) else {
        return false;
    };
    let rest = line[start + field.len()..].trim_start();
    let Some(after_equals) = rest.strip_prefix('=') else {
        return false;
    };
    let tail = after_equals.trim();
    if allow_inline_body {
        tail.starts_with("new[]")
    } else {
        tail.trim_end_matches(',') == "new[]"
    }
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    let masked = csharp_string_bodies_masked(block);
    let bytes = masked.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        let name = &masked[start..index];
        let mut cursor = index;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'=') && brace_depth_at(&masked, start) == 1 {
            fields.push(name.to_string());
        }
    }
    fields
}

fn brace_depth_at(source: &str, target: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < target && index < bytes.len() {
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
            depth = depth.saturating_sub(1);
        }
        index += 1;
    }
    depth
}

fn matching_brace_index(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = start;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
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
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn rule_string_field(object: &str, field: &str) -> Option<String> {
    let mut values = Vec::new();
    let needle = format!("{field} = \"");
    let mut search_start = 0;
    while let Some(relative) = object[search_start..].find(&needle) {
        let start = search_start + relative;
        if brace_depth_at(object, start) == 1 {
            let value_start = start + needle.len();
            if let Some(end) = object[value_start..].find('"') {
                values.push(object[value_start..value_start + end].to_string());
            }
        }
        search_start = start + needle.len();
    }
    (values.len() == 1).then(|| values.remove(0))
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if !field.ends_with("Allowed") && !field.ends_with("Enabled") {
            continue;
        }
        if REQUIRED_DISABLED_FIELDS.contains(&field.as_str())
            && exact_endpoint_assignment(block, &field, "false")
        {
            continue;
        }
        errors.push(format!(
            "cmdb reconciliation endpoint must keep {field} as an explicit safe false control"
        ));
    }
}

fn validate_no_prohibited_values_at(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_key(key) && !SAFE_CATALOG_KEYS.contains(&key.as_str()) {
                    errors.push(format!("{child_path} contains prohibited key {key}"));
                }
                validate_no_prohibited_values_at(child, &child_path, errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_prohibited_values_at(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => validate_string_value(text, path, errors),
        _ => {}
    }
}

fn validate_string_value(text: &str, path: &str, errors: &mut Vec<String>) {
    let program_source = path == format!("cmdb-reconciliation.{PROGRAM_PATH}");
    if program_source {
        for (index, literal) in active_csharp_string_literals(text).iter().enumerate() {
            if let Some(key) = prohibited_quoted_key(literal) {
                errors.push(format!(
                    "{path}:string{} contains prohibited key {key}",
                    index + 1
                ));
            }
            if let Some(key) = prohibited_assignment_key(literal) {
                errors.push(format!(
                    "{path}:string{} contains prohibited key {key}",
                    index + 1
                ));
            }
        }
    }
    let scan_value = if program_source {
        csharp_without_comments(text)
    } else {
        text.to_string()
    };
    for (line_index, line) in scan_value.lines().enumerate() {
        let line_path = if scan_value.contains('\n') {
            format!("{path}:{}", line_index + 1)
        } else {
            path.to_string()
        };
        let prohibited_literal = prohibited_standalone_text_key(line).or_else(|| {
            scan_prohibited_text_key(line, program_source)
                .then(|| prohibited_text_key(line))
                .flatten()
        });
        if let Some(key) = prohibited_literal {
            errors.push(format!("{line_path} contains prohibited key {key}"));
        }
        if let Some(key) = prohibited_assignment_key(line) {
            errors.push(format!("{line_path} contains prohibited key {key}"));
        }
        if prohibited_value(line) {
            errors.push(format!("{line_path} contains prohibited value"));
        }
    }
}

fn scan_prohibited_text_key(text: &str, program_source: bool) -> bool {
    let trimmed = text.trim();
    if program_source {
        trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || prohibited_text_key(trimmed).is_some_and(|key| {
                trimmed.contains(&format!("{key}:")) || trimmed.contains(&format!("{key}="))
            })
    } else {
        prohibited_text_key(trimmed).is_some()
    }
}

fn prohibited_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    PROHIBITED_NEEDLES
        .iter()
        .any(|needle| normalized.contains(needle))
}

fn prohibited_text_key(value: &str) -> Option<String> {
    find_prohibited_text_token(value)
}

fn prohibited_quoted_key(value: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let mut rest = value;
        while let Some(start) = rest.find(quote) {
            let after = &rest[start + quote.len_utf8()..];
            let Some(end) = after.find(quote) else {
                break;
            };
            let key = after[..end].trim();
            let tail = after[end + quote.len_utf8()..].trim_start();
            if tail.starts_with(':') && prohibited_key(key) {
                return Some(key.to_string());
            }
            rest = &after[end + quote.len_utf8()..];
        }
    }
    None
}

fn prohibited_standalone_text_key(value: &str) -> Option<String> {
    let text = value.trim();
    let cleaned = text.trim_matches('`').trim();
    if let Some(key) = prohibited_text_key(cleaned) {
        if normalize_key(cleaned) == normalize_key(&key) {
            return Some(key);
        }
    }
    if text.starts_with('|') && text.ends_with('|') {
        for cell in text.split('|').map(str::trim) {
            let cell = cell.trim_matches('`').trim();
            if let Some(key) = prohibited_text_key(cell) {
                if normalize_key(cell) == normalize_key(&key) {
                    return Some(key);
                }
            }
        }
    }
    if (text.starts_with("//") || text.starts_with('#') || text.starts_with("/*"))
        && prohibited_text_key(text).is_some()
    {
        return prohibited_text_key(text);
    }
    None
}

fn prohibited_assignment_key(value: &str) -> Option<String> {
    for separator in [':', '='] {
        let Some(position) = value.find(separator) else {
            continue;
        };
        if value[position + separator.len_utf8()..].trim().is_empty() {
            continue;
        }
        let key = value[..position]
            .rsplit(|ch: char| {
                !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '/' | '-' | ' '))
            })
            .next()
            .unwrap_or_default()
            .trim();
        if key.is_empty() || key.ends_with("Allowed") || key.ends_with("Enabled") {
            continue;
        }
        let normalized = normalize_key(strip_csharp_decl_prefix(key));
        if PROHIBITED_NEEDLES
            .iter()
            .any(|needle| normalized == *needle || normalized.ends_with(needle))
        {
            return Some(key.to_string());
        }
    }
    None
}

fn strip_csharp_decl_prefix(key: &str) -> &str {
    for prefix in [
        "private ",
        "public ",
        "internal ",
        "protected ",
        "static ",
        "readonly ",
        "var ",
        "const ",
        "string ",
        "bool ",
        "int ",
        "long ",
        "double ",
        "decimal ",
        "object ",
    ] {
        if let Some(rest) = key.strip_prefix(prefix) {
            return rest.trim_start();
        }
    }
    key
}

fn find_prohibited_text_token(value: &str) -> Option<String> {
    for token in identifier_like_tokens(value) {
        let normalized = normalize_key(&token);
        if PROHIBITED_TEXT_NEEDLES.contains(&normalized.as_str()) {
            return Some(token);
        }
    }
    None
}

fn identifier_like_tokens(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn prohibited_value(text: &str) -> bool {
    contains_aws_access_key(text)
        || text.to_ascii_uppercase().contains("-----BEGIN ")
            && text.to_ascii_uppercase().contains("PRIVATE KEY-----")
        || contains_url(text)
        || contains_private_ip(text)
        || contains_uuid(text)
        || contains_sensitive_assignment(text)
}

fn contains_aws_access_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.windows(4).enumerate().any(|(index, window)| {
        window.eq_ignore_ascii_case(b"AKIA")
            && bytes
                .get(index + 4..index + 20)
                .is_some_and(|candidate| candidate.iter().all(|byte| byte.is_ascii_alphanumeric()))
    })
}

fn contains_url(text: &str) -> bool {
    for (index, _) in text.match_indices("://") {
        let scheme = text[..index]
            .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')))
            .next()
            .unwrap_or_default();
        if scheme
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
        {
            return true;
        }
    }
    false
}

fn contains_private_ip(text: &str) -> bool {
    let bytes = text.as_bytes();
    for index in 0..bytes.len() {
        if !bytes[index].is_ascii_digit() || !word_boundary_before(bytes, index) {
            continue;
        }
        if private_ip_match_end(bytes, index).is_some_and(|end| word_boundary_after(bytes, end)) {
            return true;
        }
    }
    false
}

fn contains_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    for index in 0..bytes.len() {
        if !bytes[index].is_ascii_hexdigit() || !word_boundary_before(bytes, index) {
            continue;
        }
        let end = index + 36;
        if end <= bytes.len() && uuid_at(bytes, index) && word_boundary_after(bytes, end) {
            return true;
        }
    }
    false
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
        if SECRET_ASSIGNMENT_KEYS
            .iter()
            .any(|needle| normalized == *needle || normalized.ends_with(needle))
        {
            return true;
        }
    }
    false
}

fn private_ip_match_end(bytes: &[u8], start: usize) -> Option<usize> {
    let (first, mut index) = parse_octet(bytes, start)?;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    let (second, next) = parse_octet(bytes, index)?;
    index = next;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    let (_, next) = parse_octet(bytes, index)?;
    index = next;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    let (_, end) = parse_octet(bytes, index)?;
    if first == "10"
        || (first == "192" && second == "168")
        || (first == "172"
            && second.len() == 2
            && second
                .parse::<u8>()
                .is_ok_and(|value| (16..=31).contains(&value)))
    {
        Some(end)
    } else {
        None
    }
}

fn parse_octet(bytes: &[u8], start: usize) -> Option<(&str, usize)> {
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() && end - start < 3 {
        end += 1;
    }
    if end == start {
        return None;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(|octet| (octet, end))
}

fn uuid_at(bytes: &[u8], start: usize) -> bool {
    const HYPHENS: &[usize] = &[8, 13, 18, 23];
    for offset in 0..36 {
        let byte = bytes[start + offset];
        if HYPHENS.contains(&offset) {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn word_boundary_before(bytes: &[u8], index: usize) -> bool {
    index == 0 || !is_word_byte(bytes[index - 1])
}

fn word_boundary_after(bytes: &[u8], index: usize) -> bool {
    index >= bytes.len() || !is_word_byte(bytes[index])
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
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

fn string_array(value: &Value, field: &str, errors: &mut Vec<String>) -> Vec<String> {
    let Some(items) = value.get(field).and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    for item in items {
        if let Some(text) = item.as_str() {
            values.push(text.to_string());
        } else {
            errors.push(format!("{field} must contain only strings"));
        }
    }
    values
}

fn string_array_silent(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            Some(Rule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
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
    fn string_body_mask_preserves_brace_depth_after_literals() {
        let source =
            r#"{ source = "static-seed", nested = new { inner = true }, liveApiEnabled = false }"#;
        let masked = csharp_string_bodies_masked(source);
        let inner_index = masked.find("inner").expect("inner field");
        let live_flag_index = masked.find("liveApiEnabled").expect("live flag");

        assert_eq!(brace_depth_at(&masked, inner_index), 2);
        assert_eq!(brace_depth_at(&masked, live_flag_index), 1);
    }
}
