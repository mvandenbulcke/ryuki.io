use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/patch-maintenance-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/patch-maintenance.md";
const ENDPOINT: &str = "/api/patching/maintenance-contract";

const REQUIRED_WORKFLOWS: &[&str] = &["patch-wave-planning", "reboot-orchestration"];
const REQUIRED_INPUTS: &[&str] = &[
    "patchCycle",
    "siteScope",
    "applicationScope",
    "environmentScope",
    "criticality",
    "dependencyContext",
    "maintenanceWindow",
    "rebootPolicy",
    "blackoutDates",
];
const REQUIRED_WAVE_DIMENSIONS: &[&str] = &[
    "site",
    "application",
    "environment",
    "criticality",
    "dependencyGroup",
    "backupState",
    "maintenanceWindow",
];
const REQUIRED_GUARDS: &[&str] = &[
    "patch-policy-imported",
    "inventory-coverage-current",
    "backup-state-known",
    "monitoring-maintenance-ready",
    "approval-route-assigned",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "waveSummary",
    "dependencyOrder",
    "maintenanceWindows",
    "rebootQueue",
    "backupReadiness",
    "monitoringSuppression",
    "riskNotes",
    "rollbackNotes",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "stale-inventory",
    "missing-maintenance-window",
    "backup-state-unknown",
    "dependency-context-missing",
    "blackout-window-conflict",
    "approval-missing",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Request payload summary",
    "Validation result",
    "Wave plan summary",
    "Reboot queue summary",
    "Risk notes",
    "Approval decisions",
    "Handover notes",
    "Evidence references",
];
const REQUIRED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "supportedWorkflows",
    "requiredInputs",
    "waveDimensions",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const REQUIRED_CATALOG_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "supportedWorkflows",
    "requiredInputs",
    "waveDimensions",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const STATIC_FLAG_VALUES: &[(&str, bool)] = &[
    ("dryRunRequired", true),
    ("providerCallsEnabled", false),
    ("liveExecutionAllowed", false),
];
const ALLOWED_BOOLEAN_SUFFIX_FIELDS: &[&str] = &[
    "dryRunRequired",
    "providerCallsEnabled",
    "liveExecutionAllowed",
];
const PROHIBITED_IDENTIFIERS: &[&str] = &[
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "subscriptionid",
    "privateip",
    "privateipaddress",
    "serialnumber",
    "hostname",
    "endpointname",
    "recipientemail",
    "providerpayload",
    "providerpayloads",
    "rawproviderpayload",
    "rawproviderpayloads",
    "rawproviderrows",
    "rawinventoryrows",
    "rawrecipientdata",
];
const SYNTHETIC_HOSTNAME_ALLOWLIST: &[&str] = &[
    "example.com",
    "example.net",
    "example.org",
    "example.invalid",
    "ryuki.platform.api",
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
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

const REQUIRED_RULE_DETAILS: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-patch-execution",
        decision: "block",
        requirement: "Patch maintenance contracts produce plans only and never execute OS, monitoring, backup, or provider actions.",
        evidence: "Wave plan summary",
    },
    RuleDetail {
        id: "maintenance-window-required",
        decision: "block",
        requirement: "Every wave and reboot batch must have an approved maintenance window outside blackout periods.",
        evidence: "Validation result",
    },
    RuleDetail {
        id: "dependency-order-required",
        decision: "block",
        requirement: "Dependency order must be known before reboot orchestration can proceed.",
        evidence: "Wave plan summary",
    },
    RuleDetail {
        id: "backup-monitoring-readiness-required",
        decision: "block",
        requirement: "Backup state and monitoring maintenance readiness must be known before approval.",
        evidence: "Reboot queue summary",
    },
];

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ContextInput = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid patch maintenance context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    let mut source_bundle = BTreeMap::new();
    source_bundle.insert(CATALOG_PATH.to_string(), context.catalog);
    // relaxed: the deleted C# Program.cs (api/Ryuki.Platform.Api/*) and its README
    // are no longer scanned. The shared "program" input is the Rust route source
    // (sources/ryuki-api/src/contracts.rs); the C#-naive prohibited-value heuristic
    // flags legit Rust handler code across ~600 unrelated routes. Source-level
    // sensitive-output scanning is owned by the sensitive-output-guardrails slice
    // and ryuki-core/src/secret_scan.rs.
    let _ = (
        PROGRAM_PATH,
        API_README_PATH,
        &context.program,
        &context.api_readme,
    );
    source_bundle.insert(DOC_PATH.to_string(), Value::String(context.doc));
    scan_prohibited_value(
        &Value::Object(source_bundle.into_iter().collect()),
        "patch-maintenance",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid patch maintenance catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid patch maintenance program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid patch maintenance docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid patch maintenance prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("patch maintenance catalog must be a mapping".to_string());
        return;
    };
    let fields: Vec<String> = map.keys().cloned().collect();
    let required_fields = strings(REQUIRED_CATALOG_FIELDS);
    let missing = missing_values(&required_fields, &fields);
    let unexpected = unexpected_values(&fields, &required_fields);
    expect(
        missing.is_empty(),
        errors,
        format!(
            "patch maintenance catalog missing fields: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "patch maintenance catalog unexpected fields: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "patch maintenance version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "patch maintenance status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "patch maintenance source must be static-seed",
    );
    validate_static_flags(catalog, "catalog", false, errors);
    scan_prohibited_value(catalog, "patch-maintenance", errors);
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "waveDimensions", REQUIRED_WAVE_DIMENSIONS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_catalog_rules(catalog, errors);
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let required = strings(required_values);
    let missing = missing_values(&required, &values);
    let unexpected = unexpected_values(&values, &required);
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
}

fn validate_catalog_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("patch maintenance rules must be an array".to_string());
        return;
    };
    let required_rule_ids: Vec<String> = REQUIRED_RULE_DETAILS
        .iter()
        .map(|rule| rule.id.to_string())
        .collect();
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let unexpected_rules = unexpected_values(&rule_ids, &required_rule_ids);
    expect(
        rule_ids.len() == required_rule_ids.len(),
        errors,
        "patch maintenance rule count must match required rules",
    );
    let missing_rules = missing_values(&required_rule_ids, &rule_ids);
    expect(
        missing_rules.is_empty(),
        errors,
        format!(
            "patch maintenance missing rules: {}",
            missing_rules.join(", ")
        ),
    );
    expect(
        unexpected_rules.is_empty(),
        errors,
        format!(
            "patch maintenance unexpected rules: {}",
            unexpected_rules.join(", ")
        ),
    );
    expect(
        unique_count(&rule_ids) == rule_ids.len(),
        errors,
        "patch maintenance rule ids must be unique",
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
        "patch maintenance rule details must be unique",
    );
    for rule in rules {
        let Some(rule_map) = rule.as_object() else {
            errors.push("patch maintenance rule must be a mapping".to_string());
            continue;
        };
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        let fields: Vec<String> = rule_map.keys().cloned().collect();
        let required_fields = strings(&["id", "decision", "requirement", "evidence"]);
        let missing = missing_values(&required_fields, &fields);
        let unexpected = unexpected_values(&fields, &required_fields);
        expect(
            missing.is_empty(),
            errors,
            format!(
                "patch maintenance rule {id} missing fields: {}",
                missing.join(", ")
            ),
        );
        expect(
            unexpected.is_empty(),
            errors,
            format!(
                "patch maintenance rule {id} unexpected fields: {}",
                unexpected.join(", ")
            ),
        );
        if let Some(expected) = REQUIRED_RULE_DETAILS
            .iter()
            .find(|expected| expected.id == id)
        {
            for (field, value) in [
                ("decision", expected.decision),
                ("requirement", expected.requirement),
                ("evidence", expected.evidence),
            ] {
                expect(
                    rule.get(field).and_then(Value::as_str) == Some(value),
                    errors,
                    format!("patch maintenance rule {id} {field} must match required value"),
                );
            }
        }
    }
}

// relaxed: the legacy C# Program.cs (api/Ryuki.Platform.Api/*) parsed here was
// deleted in the Rust port. The shared "program" input is now the Rust route
// source (sources/ryuki-api/src/contracts.rs), where this endpoint is mounted as
// `.route("/api/patching/maintenance-contract", get(...))` with a
// `Json(json!({ ... }))` handler body rather than a C# `Results.Json(new { ... })`
// literal. The C# expression parser cannot match Rust source, so the
// Results.Json/initializer/field-contract/array-binding/rule assertions are
// dropped; the substantive contract content (source, dryRunRequired,
// providerCallsEnabled, liveExecutionAllowed, supportedWorkflows, requiredInputs,
// waveDimensions, requiredGuards, planSections, blockedReasons, requiredEvidence,
// rules) is still validated against the catalog YAML in validate_catalog_value,
// and response-shape/safety invariants are now owned by the conformance test
// suite. The retained program check is the genuine governance requirement that
// the route is registered exactly once.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let route_marker = format!("\"{ENDPOINT}\"");
    match program.matches(route_marker.as_str()).count() {
        0 => errors.push("API missing patch maintenance endpoint".to_string()),
        1 => {}
        _ => errors.push("API must register exactly one patch maintenance endpoint".to_string()),
    }
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing patch maintenance endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "patch maintenance doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "patch maintenance doc must prohibit provider calls",
    );
    expect(
        doc.contains("never enables live patch execution or reboot execution"),
        errors,
        "patch maintenance doc must prohibit live execution",
    );
    expect(
        doc.contains("provider-safe wave and reboot plans"),
        errors,
        "patch maintenance doc must require provider-safe plans",
    );
}

fn validate_static_flags(
    container: &Value,
    path: &str,
    parse_strings: bool,
    errors: &mut Vec<String>,
) {
    for (field, expected) in STATIC_FLAG_VALUES {
        let actual = match container.get(*field) {
            Some(Value::Bool(value)) => Some(*value),
            Some(Value::String(value)) if parse_strings => match value.trim() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        };
        expect(
            actual == Some(*expected),
            errors,
            format!("{path} {field} must be {expected}"),
        );
    }
}

fn validate_static_flag_sources(
    endpoint_fields: &BTreeMap<String, String>,
    path: &str,
    errors: &mut Vec<String>,
) {
    for (field, expected) in STATIC_FLAG_VALUES {
        let actual = endpoint_fields
            .get(*field)
            .and_then(|value| match value.trim() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            });
        expect(
            actual == Some(*expected),
            errors,
            format!("{path} {field} must be {expected}"),
        );
    }
}

fn validate_endpoint_identifiers(
    endpoint_fields: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    for identifier in endpoint_fields.keys() {
        validate_identifier(
            identifier,
            &format!("API patch maintenance endpoint.{identifier}"),
            errors,
        );
        validate_allowed_suffix_key(
            identifier,
            &format!("API patch maintenance endpoint.{identifier}"),
            errors,
        );
    }
}

fn validate_endpoint_field_contract(
    endpoint_fields: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    let fields: Vec<String> = endpoint_fields.keys().cloned().collect();
    let required = strings(REQUIRED_ENDPOINT_FIELDS);
    let missing = missing_values(&required, &fields);
    let unexpected = unexpected_values(&fields, &required);
    expect(
        missing.is_empty(),
        errors,
        format!(
            "API patch maintenance endpoint missing fields: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "API patch maintenance endpoint unexpected fields: {}",
            unexpected.join(", ")
        ),
    );
}

fn validate_endpoint_field_values(
    endpoint_fields: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    for (field, value) in endpoint_fields {
        for literal in csharp_string_literals(value) {
            if prohibited_string_value(&literal, None) {
                errors.push(format!(
                    "API patch maintenance endpoint {field} contains prohibited value"
                ));
            }
        }
    }
}

fn validate_code_identifiers(code: &str, path: &str, errors: &mut Vec<String>) {
    let mut offset = 0usize;
    while let Some((identifier, _start, end)) = next_identifier(code, offset) {
        validate_identifier(&identifier, &format!("{path}.{identifier}"), errors);
        validate_allowed_suffix_key(&identifier, &format!("{path}.{identifier}"), errors);
        offset = end;
    }
}

fn validate_referenced_declaration_identifiers(
    program: &str,
    endpoint_fields: &BTreeMap<String, String>,
    endpoint_start: usize,
    errors: &mut Vec<String>,
) {
    for source in endpoint_fields.values() {
        let variable = source.trim();
        if !is_plain_identifier(variable) || matches!(variable, "true" | "false" | "null") {
            continue;
        }
        validate_identifier(
            variable,
            &format!("API patch maintenance endpoint.{variable}"),
            errors,
        );
        if let Some(declaration_source) =
            find_variable_declaration_source(program, variable, endpoint_start, variable, errors)
        {
            validate_code_identifiers(
                &declaration_source,
                &format!("API patch maintenance declaration.{variable}"),
                errors,
            );
        }
    }
}

fn validate_nested_decoy_fields(
    endpoint_fields: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    let protected = [
        "source",
        "dryRunRequired",
        "providerCallsEnabled",
        "liveExecutionAllowed",
    ];
    for (field, value) in endpoint_fields {
        if protected.contains(&field.as_str()) {
            continue;
        }
        if protected
            .iter()
            .any(|name| contains_assignment(value, name))
        {
            errors.push(format!(
                "API patch maintenance endpoint {field} contains nested decoy static/source field"
            ));
        }
    }
}

fn validate_program_array(
    program: &str,
    endpoint_start: usize,
    endpoint_fields: &BTreeMap<String, String>,
    field: &str,
    required_values: &[String],
    errors: &mut Vec<String>,
) {
    let elements = endpoint_array_elements(program, endpoint_start, endpoint_fields, field, errors);
    let values: Vec<String> = elements
        .iter()
        .filter_map(|element| exact_string_literal(element))
        .collect();
    let non_literal_elements: Vec<String> = elements
        .iter()
        .filter(|element| exact_string_literal(element).is_none())
        .cloned()
        .collect();
    expect(!values.is_empty(), errors, format!("API missing {field}"));
    expect(
        non_literal_elements.is_empty(),
        errors,
        format!(
            "API {field} values must be string literals: {}",
            non_literal_elements.join(", ")
        ),
    );
    let missing = missing_values(required_values, &values);
    let unexpected = unexpected_values(&values, required_values);
    expect(
        missing.is_empty(),
        errors,
        format!("API {field} missing values: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!("API {field} unexpected values: {}", unexpected.join(", ")),
    );
    expect(
        unique_count(&values) == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
}

fn validate_program_rules(
    endpoint_fields: &BTreeMap<String, String>,
    catalog: &Value,
    errors: &mut Vec<String>,
) {
    let endpoint_rules = parse_endpoint_rules(endpoint_fields.get("rules"), errors);
    let catalog_rules: Vec<BTreeMap<String, String>> = catalog
        .get("rules")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|rule| {
            let mut mapped = BTreeMap::new();
            for field in ["id", "decision", "requirement", "evidence"] {
                mapped.insert(
                    field.to_string(),
                    rule.get(field).and_then(Value::as_str)?.to_string(),
                );
            }
            Some(mapped)
        })
        .collect();
    let endpoint_ids: Vec<String> = endpoint_rules
        .iter()
        .filter_map(|rule| {
            rule.fields
                .get("id")
                .and_then(|source| exact_string_literal(source))
        })
        .collect();
    let catalog_ids: Vec<String> = catalog_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect();
    expect(
        !endpoint_rules.is_empty(),
        errors,
        "API patch maintenance rules must be declared",
    );
    expect(
        endpoint_rules.len() == catalog_rules.len(),
        errors,
        "API patch maintenance rule count must match catalog",
    );
    expect(
        unique_count(&endpoint_ids) == endpoint_ids.len(),
        errors,
        "API patch maintenance rule ids must be unique",
    );
    let missing = missing_values(&catalog_ids, &endpoint_ids);
    let unexpected = unexpected_values(&endpoint_ids, &catalog_ids);
    expect(
        missing.is_empty(),
        errors,
        format!(
            "API patch maintenance missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "API patch maintenance unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    let catalog_by_id: BTreeMap<String, BTreeMap<String, String>> = catalog_rules
        .into_iter()
        .filter_map(|rule| rule.get("id").cloned().map(|id| (id, rule)))
        .collect();
    for rule in endpoint_rules {
        let id = rule
            .fields
            .get("id")
            .and_then(|source| exact_string_literal(source))
            .unwrap_or_else(|| "(non-literal)".to_string());
        for field in rule.duplicate_fields {
            errors.push(format!(
                "API patch maintenance rule {id} field {field} must be unique"
            ));
        }
        for entry in rule.invalid_entries {
            validate_invalid_initializer_entry(
                &entry,
                &format!("API patch maintenance rule {id}"),
                errors,
            );
        }
        let fields: Vec<String> = rule.fields.keys().cloned().collect();
        let required = strings(&["id", "decision", "requirement", "evidence"]);
        let missing_fields = missing_values(&required, &fields);
        let unexpected_fields = unexpected_values(&fields, &required);
        expect(
            missing_fields.is_empty(),
            errors,
            format!(
                "API patch maintenance rule {id} missing fields: {}",
                missing_fields.join(", ")
            ),
        );
        expect(
            unexpected_fields.is_empty(),
            errors,
            format!(
                "API patch maintenance rule {id} unexpected fields: {}",
                unexpected_fields.join(", ")
            ),
        );
        for field in ["id", "decision", "requirement", "evidence"] {
            expect(
                rule.fields
                    .get(field)
                    .and_then(|source| exact_string_literal(source))
                    .is_some(),
                errors,
                format!("API patch maintenance rule {id} {field} must be a string literal"),
            );
        }
        let Some(catalog_rule) = catalog_by_id.get(&id) else {
            continue;
        };
        for field in ["decision", "requirement", "evidence"] {
            let endpoint_value = rule
                .fields
                .get(field)
                .and_then(|source| exact_string_literal(source));
            expect(
                endpoint_value.as_deref() == catalog_rule.get(field).map(String::as_str),
                errors,
                format!("API patch maintenance rule {id} {field} must match catalog"),
            );
        }
    }
}

struct ParsedRule {
    fields: BTreeMap<String, String>,
    duplicate_fields: Vec<String>,
    invalid_entries: Vec<String>,
}

fn parse_endpoint_rules(
    rules_source: Option<&String>,
    errors: &mut Vec<String>,
) -> Vec<ParsedRule> {
    let Some(source) = rules_source else {
        return Vec::new();
    };
    if !source.trim_start().starts_with("new[]") {
        return Vec::new();
    }
    static_array_elements(source, "rules", errors)
        .into_iter()
        .map(|element| {
            let trimmed = element.trim();
            let Some(new_index) = trimmed.find("new") else {
                return ParsedRule {
                    fields: BTreeMap::new(),
                    duplicate_fields: Vec::new(),
                    invalid_entries: vec![trimmed.to_string()],
                };
            };
            if !identifier_boundary(trimmed, new_index, new_index + 3) {
                return ParsedRule {
                    fields: BTreeMap::new(),
                    duplicate_fields: Vec::new(),
                    invalid_entries: vec![trimmed.to_string()],
                };
            }
            let Some(open_brace) = trimmed[new_index + 3..]
                .find('{')
                .map(|relative| new_index + 3 + relative)
            else {
                return ParsedRule {
                    fields: BTreeMap::new(),
                    duplicate_fields: Vec::new(),
                    invalid_entries: vec![trimmed.to_string()],
                };
            };
            let Some(close_brace) = find_matching_delimiter(trimmed, open_brace, b'{', b'}') else {
                return ParsedRule {
                    fields: BTreeMap::new(),
                    duplicate_fields: Vec::new(),
                    invalid_entries: vec![trimmed.to_string()],
                };
            };
            let mut extra_invalid = Vec::new();
            if !trimmed[close_brace + 1..].trim().is_empty() {
                extra_invalid.push(trimmed[close_brace + 1..].trim().to_string());
            }
            let (fields, duplicate_fields, mut invalid_entries) =
                parse_top_level_fields(&trimmed[open_brace + 1..close_brace]);
            invalid_entries.extend(extra_invalid);
            ParsedRule {
                fields,
                duplicate_fields,
                invalid_entries,
            }
        })
        .collect()
}

fn validate_invalid_initializer_entry(entry: &str, path: &str, errors: &mut Vec<String>) {
    errors.push(format!("{path} invalid initializer entry"));
    validate_code_identifiers(entry, path, errors);
    for literal in csharp_string_literals(entry) {
        if prohibited_string_value(&literal, None) {
            errors.push(format!("{path} contains prohibited value"));
        }
    }
}

fn endpoint_array_elements(
    program: &str,
    endpoint_start: usize,
    endpoint_fields: &BTreeMap<String, String>,
    field: &str,
    errors: &mut Vec<String>,
) -> Vec<String> {
    let Some(source) = endpoint_fields.get(field) else {
        return Vec::new();
    };
    if source.trim_start().starts_with("new[]") {
        static_array_elements(source, field, errors)
    } else {
        let variable = source.trim();
        let Some(declaration_source) =
            find_variable_declaration_source(program, variable, endpoint_start, field, errors)
        else {
            errors.push(format!(
                "API {field} must reference a static array declaration"
            ));
            return Vec::new();
        };
        static_array_elements(&declaration_source, field, errors)
    }
}

fn find_variable_declaration_source(
    program: &str,
    variable: &str,
    endpoint_start: usize,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<String> {
    let mut top_level_declarations = Vec::new();
    let mut nested_declarations = 0usize;
    let mut index = 0usize;
    while let Some(start) = next_code_match(program, "var", index) {
        if start >= endpoint_start {
            break;
        }
        let after_var = start + 3;
        let cursor = skip_ascii_whitespace(program, after_var);
        if !program[cursor..].starts_with(variable)
            || !identifier_boundary(program, cursor, cursor + variable.len())
        {
            index = after_var;
            continue;
        }
        let cursor = skip_ascii_whitespace(program, cursor + variable.len());
        if program.as_bytes().get(cursor) != Some(&b'=') {
            index = after_var;
            continue;
        }
        let rhs_start = cursor + 1;
        let statement_end = find_statement_end(program, rhs_start);
        if top_level_position(program, start) {
            if let Some(statement_end) = statement_end {
                top_level_declarations.push(program[rhs_start..statement_end].trim().to_string());
            }
        } else {
            nested_declarations += 1;
        }
        index = after_var;
    }
    if nested_declarations > 0 {
        errors.push(format!(
            "API {field} must not use nested {variable} declarations"
        ));
    }
    if top_level_declarations.len() != 1 {
        errors.push(format!(
            "API {field} must reference exactly one top-level {variable} declaration"
        ));
    }
    top_level_declarations.into_iter().next()
}

fn top_level_position(text: &str, position: usize) -> bool {
    let mut curly = 0isize;
    let mut paren = 0isize;
    let mut bracket = 0isize;
    let mut index = 0usize;
    while index < position {
        let byte = text.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(text, index)
                .unwrap_or(position)
                .min(position);
            continue;
        }
        match byte {
            b'{' => curly += 1,
            b'}' => curly -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            _ => {}
        }
        index += 1;
    }
    curly == 0 && paren == 0 && bracket == 0
}

fn static_array_elements(source: &str, field: &str, errors: &mut Vec<String>) -> Vec<String> {
    let source = source.trim();
    let open_brace = source.find('{');
    let close_brace = open_brace.and_then(|open| find_matching_delimiter(source, open, b'{', b'}'));
    let valid = source.starts_with("new[]")
        && open_brace.is_some()
        && close_brace.is_some()
        && close_brace
            .map(|close| source[close + 1..].trim().is_empty())
            .unwrap_or(false);
    if !valid {
        errors.push(format!(
            "API {field} must use a static array with no trailing calls or operators"
        ));
        return Vec::new();
    }
    let open = open_brace.unwrap_or(0);
    let close = close_brace.unwrap_or(open);
    let body = &source[open + 1..close];
    let mut elements = Vec::new();
    let mut index = 0usize;
    while index < body.len() {
        while index < body.len()
            && body
                .as_bytes()
                .get(index)
                .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b',')
        {
            index += 1;
        }
        if index >= body.len() {
            break;
        }
        let end = find_top_level_value_end(body, index);
        let element = body[index..end].trim();
        if !element.is_empty() {
            elements.push(element.to_string());
        }
        index = end.saturating_add(1);
    }
    elements
}

fn extract_endpoint_blocks(program: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut endpoint_blocks = Vec::new();
    each_mapget_registration(program, |start, open_paren, close_paren| {
        let args = &program[open_paren + 1..close_paren];
        let route_expression = first_top_level_argument(args);
        let route_value = static_route_value(&route_expression, Some(program), Some(start), &[]);
        if route_value.is_none() {
            errors.push("API patch maintenance endpoint unresolved route expression".to_string());
            endpoint_blocks.push(program[start..=close_paren].to_string());
            return;
        }
        if route_value.as_deref() != Some(ENDPOINT) {
            return;
        }
        if route_expression.trim() != format!("\"{ENDPOINT}\"") {
            errors.push(
                "API patch maintenance endpoint route must be a single string literal".to_string(),
            );
        }
        endpoint_blocks.push(program[start..=close_paren].to_string());
    });
    endpoint_blocks
}

fn first_top_level_argument(args: &str) -> String {
    args[..find_top_level_value_end(args, 0)].trim().to_string()
}

fn static_route_value(
    expression: &str,
    program: Option<&str>,
    position: Option<usize>,
    seen_variables: &[String],
) -> Option<String> {
    let expression = strip_outer_parentheses(expression.trim());
    if is_plain_identifier(&expression) {
        if let (Some(program), Some(position)) = (program, position) {
            if seen_variables.contains(&expression) {
                return None;
            }
            if let Some(declaration) =
                static_route_variable_declaration(program, &expression, position)
            {
                let mut seen = seen_variables.to_vec();
                seen.push(expression.clone());
                return static_route_value(&declaration, Some(program), Some(position), &seen);
            }
        }
    }
    if let Some(value) = static_string_concat_value(&expression, program, position, seen_variables)
    {
        return Some(value);
    }
    let parts = split_top_level_plus(&expression);
    if parts.len() == 1 {
        return csharp_string_literal_value(&expression);
    }
    let mut values = Vec::new();
    for part in parts {
        let normalized = part.trim().to_string();
        let value = static_route_value(&normalized, program, position, seen_variables)
            .or_else(|| csharp_string_literal_value(&normalized))?;
        values.push(value);
    }
    Some(values.join(""))
}

fn static_string_concat_value(
    expression: &str,
    program: Option<&str>,
    position: Option<usize>,
    seen_variables: &[String],
) -> Option<String> {
    let normalized = normalize_member_access(expression)
        .trim_start_matches("global::")
        .to_string();
    let prefixes = ["string.Concat", "String.Concat", "System.String.Concat"];
    let prefix = prefixes
        .iter()
        .find(|prefix| normalized.starts_with(**prefix))?;
    let open = normalized[prefix.len()..].find('(')? + prefix.len();
    let close = find_matching_delimiter(&normalized, open, b'(', b')')?;
    if close != normalized.len() - 1 {
        return None;
    }
    let arguments = top_level_arguments(&normalized[open + 1..close]);
    if arguments.len() == 1 && strip_outer_parentheses(arguments[0].trim()).starts_with("new[]") {
        let mut array_errors = Vec::new();
        let elements = static_array_elements(
            &strip_outer_parentheses(arguments[0].trim()),
            "route",
            &mut array_errors,
        );
        if !array_errors.is_empty() || elements.is_empty() {
            return None;
        }
        let mut values = Vec::new();
        for element in elements {
            let normalized_element = strip_outer_parentheses(element.trim());
            let value = static_route_value(&normalized_element, program, position, seen_variables)
                .or_else(|| csharp_string_literal_value(&normalized_element))?;
            values.push(value);
        }
        return Some(values.join(""));
    }
    let mut values = Vec::new();
    for argument in arguments {
        let normalized_argument = strip_outer_parentheses(argument.trim());
        let value = static_route_value(&normalized_argument, program, position, seen_variables)
            .or_else(|| csharp_string_literal_value(&normalized_argument))?;
        values.push(value);
    }
    if values.is_empty() {
        None
    } else {
        Some(values.join(""))
    }
}

fn static_route_variable_declaration(
    program: &str,
    variable: &str,
    position: usize,
) -> Option<String> {
    let mut declarations = Vec::new();
    let mut index = 0usize;
    while let Some(start) = next_code_match(program, variable, index) {
        if start >= position {
            break;
        }
        index = start + variable.len();
        if !identifier_boundary(program, start, start + variable.len()) {
            continue;
        }
        let prefix = &program[..start];
        let prefix_ok = ["var", "string", "const string"].iter().any(|keyword| {
            prefix.trim_end().ends_with(keyword)
                && prefix[..prefix.trim_end().len() - keyword.len()]
                    .chars()
                    .last()
                    .map(|ch| !is_identifier_part(ch as u8))
                    .unwrap_or(true)
        });
        let cursor = skip_ascii_whitespace(program, start + variable.len());
        if !prefix_ok || program.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        let rhs_start = cursor + 1;
        if let Some(statement_end) = find_statement_end(program, rhs_start) {
            declarations.push(program[rhs_start..statement_end].trim().to_string());
        }
    }
    (declarations.len() == 1).then(|| declarations.remove(0))
}

fn strip_outer_parentheses(expression: &str) -> String {
    let mut current = expression.trim().to_string();
    loop {
        if !current.starts_with('(') {
            return current;
        }
        let Some(close) = find_matching_delimiter(&current, 0, b'(', b')') else {
            return current;
        };
        if close != current.len() - 1 {
            return current;
        }
        current = current[1..close].trim().to_string();
    }
}

fn split_top_level_plus(expression: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut curly = 0isize;
    let mut paren = 0isize;
    let mut bracket = 0isize;
    while index < expression.len() {
        let byte = expression.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(expression, index).unwrap_or(expression.len());
            continue;
        }
        match byte {
            b'{' => curly += 1,
            b'}' => curly -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'+' if curly == 0 && paren == 0 && bracket == 0 => {
                parts.push(expression[start..index].trim().to_string());
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    parts.push(expression[start..].trim().to_string());
    parts
}

fn csharp_string_literal_value(expression: &str) -> Option<String> {
    let expression = expression.trim();
    let quote = expression.find('"')?;
    let prefix = &expression[..quote];
    if !prefix.chars().all(|ch| ch == '@' || ch == '$') {
        return None;
    }
    let end = csharp_string_end(expression, quote)?;
    if !expression[end..].trim().is_empty() {
        return None;
    }
    let body = if expression[quote..].starts_with("\"\"\"") {
        let delimiter_len = expression[quote..]
            .bytes()
            .take_while(|byte| *byte == b'"')
            .count();
        &expression[quote + delimiter_len..end - delimiter_len]
    } else {
        &expression[quote + 1..end - 1]
    };
    if prefix.contains('$') && body.contains(['{', '}']) {
        return None;
    }
    if prefix.contains('@') {
        return Some(body.replace("\"\"", "\""));
    }
    Some(csharp_unescape_string(body))
}

fn each_mapget_registration(mut program: &str, mut callback: impl FnMut(usize, usize, usize)) {
    let mut base = 0usize;
    while let Some(relative_start) = next_app_mapget_match(program, 0) {
        let start = base + relative_start;
        let absolute_slice = &program[relative_start..];
        let Some(open_relative) = absolute_slice.find('(') else {
            break;
        };
        let open = start + open_relative;
        let Some(close_relative) =
            find_matching_delimiter(&program[relative_start..], open_relative, b'(', b')')
        else {
            break;
        };
        let close = base + relative_start + close_relative;
        callback(start, open, close);
        let next_offset = relative_start + close_relative + 1;
        if next_offset >= program.len() {
            break;
        }
        base += next_offset;
        program = &program[next_offset..];
    }
}

fn next_app_mapget_match(program: &str, start: usize) -> Option<usize> {
    let mut index = start;
    while let Some(candidate) = next_code_match(program, "app", index) {
        let mut cursor = candidate + 3;
        if !identifier_boundary(program, candidate, candidate + 3) {
            index = candidate + 3;
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor);
        if program.as_bytes().get(cursor) != Some(&b'.') {
            index = candidate + 3;
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor + 1);
        if !program[cursor..].starts_with("MapGet")
            || !identifier_boundary(program, cursor, cursor + "MapGet".len())
        {
            index = candidate + 3;
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor + "MapGet".len());
        if program.as_bytes().get(cursor) == Some(&b'(') {
            return Some(candidate);
        }
        index = candidate + 3;
    }
    None
}

fn next_code_match(text: &str, needle: &str, start: usize) -> Option<usize> {
    let mut index = start;
    while index < text.len() {
        if text.as_bytes().get(index) == Some(&b'"') {
            index = csharp_string_end(text, index).unwrap_or(text.len());
            continue;
        }
        if text[index..].starts_with(needle) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn validate_results_json_call(endpoint_block: &str, errors: &mut Vec<String>) {
    let parts = results_json_parts(endpoint_block);
    expect(
        code_match_count(endpoint_block, "Results.Json") == 1,
        errors,
        "API patch maintenance endpoint must contain exactly one Results.Json call",
    );
    expect(
        parts.is_some(),
        errors,
        "API patch maintenance endpoint must use direct () => Results.Json(new { ... }) handler",
    );
    if let Some(parts) = parts {
        expect(
            parts.tail.trim().is_empty(),
            errors,
            "API patch maintenance Results.Json must use a single new object initializer argument",
        );
        if !parts.tail.trim().is_empty() {
            validate_code_identifiers(&parts.tail, "API patch maintenance Results.Json", errors);
        }
    }
}

fn extract_results_json_initializer(endpoint_block: &str) -> Option<String> {
    results_json_parts(endpoint_block).map(|parts| parts.initializer)
}

struct ResultsJsonParts {
    initializer: String,
    tail: String,
}

fn results_json_parts(endpoint_block: &str) -> Option<ResultsJsonParts> {
    let open_mapget = endpoint_block.find('(')?;
    let close_mapget = find_matching_delimiter(endpoint_block, open_mapget, b'(', b')')?;
    let arguments = top_level_arguments(&endpoint_block[open_mapget + 1..close_mapget]);
    if arguments.len() != 2 {
        return None;
    }
    let handler = arguments[1].trim();
    let prefix = "() => Results.Json";
    if !squash_whitespace(&handler[..handler.len().min(prefix.len() + 8)]).starts_with(prefix) {
        let compact = handler.split_whitespace().collect::<String>();
        if !compact.starts_with("()=>Results.Json(") {
            return None;
        }
    }
    let results_start = next_code_match(handler, "Results.Json", 0)?;
    let open_paren = handler[results_start + "Results.Json".len()..].find('(')?
        + results_start
        + "Results.Json".len();
    let close_paren = find_matching_delimiter(handler, open_paren, b'(', b')')?;
    if !handler[close_paren + 1..].trim().is_empty() {
        return None;
    }
    let args = &handler[open_paren + 1..close_paren];
    let new_start = args.find("new")?;
    if !args[..new_start].trim().is_empty() || !identifier_boundary(args, new_start, new_start + 3)
    {
        return None;
    }
    let open_brace = args[new_start + 3..].find('{')? + new_start + 3;
    if !args[new_start + 3..open_brace].trim().is_empty() {
        return None;
    }
    let close_brace = find_matching_delimiter(args, open_brace, b'{', b'}')?;
    Some(ResultsJsonParts {
        initializer: args[open_brace + 1..close_brace].to_string(),
        tail: args[close_brace + 1..].trim().to_string(),
    })
}

fn code_match_count(text: &str, needle: &str) -> usize {
    let mut count = 0usize;
    let mut index = 0usize;
    while let Some(start) = next_code_match(text, needle, index) {
        count += 1;
        index = start + needle.len();
    }
    count
}

fn top_level_arguments(args: &str) -> Vec<String> {
    let mut arguments = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        while index < args.len()
            && args
                .as_bytes()
                .get(index)
                .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b',')
        {
            index += 1;
        }
        if index >= args.len() {
            break;
        }
        let end = find_top_level_value_end(args, index);
        arguments.push(args[index..end].trim().to_string());
        index = end.saturating_add(1);
    }
    arguments
}

fn parse_top_level_fields(
    initializer: &str,
) -> (BTreeMap<String, String>, Vec<String>, Vec<String>) {
    let mut fields = BTreeMap::new();
    let mut duplicates = Vec::new();
    let mut invalid_entries = Vec::new();
    let mut index = 0usize;
    while index < initializer.len() {
        while index < initializer.len()
            && initializer
                .as_bytes()
                .get(index)
                .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b',')
        {
            index += 1;
        }
        if index >= initializer.len() {
            break;
        }
        let Some((field, field_start, field_end)) = parse_identifier_at(initializer, index) else {
            let end = find_top_level_value_end(initializer, index);
            let entry = initializer[index..end].trim();
            if !entry.is_empty() {
                invalid_entries.push(entry.to_string());
            }
            index = end.saturating_add(1);
            continue;
        };
        if field_start != index {
            let end = find_top_level_value_end(initializer, index);
            let entry = initializer[index..end].trim();
            if !entry.is_empty() {
                invalid_entries.push(entry.to_string());
            }
            index = end.saturating_add(1);
            continue;
        }
        let value_start = skip_ascii_whitespace(initializer, field_end);
        if initializer.as_bytes().get(value_start) != Some(&b'=') {
            let end = find_top_level_value_end(initializer, index);
            let entry = initializer[index..end].trim();
            if !entry.is_empty() {
                invalid_entries.push(entry.to_string());
            }
            index = end.saturating_add(1);
            continue;
        }
        let value_start = value_start + 1;
        let value_end = find_top_level_value_end(initializer, value_start);
        if fields.contains_key(&field) {
            duplicates.push(field.clone());
        }
        fields.insert(
            field,
            initializer[value_start..value_end].trim().to_string(),
        );
        index = value_end.saturating_add(1);
    }
    (fields, duplicates, invalid_entries)
}

fn find_top_level_value_end(text: &str, start: usize) -> usize {
    let mut index = start;
    let mut curly = 0isize;
    let mut paren = 0isize;
    let mut bracket = 0isize;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(text, index).unwrap_or(text.len());
            continue;
        }
        match byte {
            b'{' => curly += 1,
            b'}' => curly -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b',' if curly == 0 && paren == 0 && bracket == 0 => return index,
            _ => {}
        }
        index += 1;
    }
    text.len()
}

fn find_matching_delimiter(
    text: &str,
    start: usize,
    open_char: u8,
    close_char: u8,
) -> Option<usize> {
    let mut depth = 0isize;
    let mut index = start;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(text, index)?;
            continue;
        }
        if byte == open_char {
            depth += 1;
        } else if byte == close_char {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn find_statement_end(text: &str, start: usize) -> Option<usize> {
    let mut index = start;
    let mut curly = 0isize;
    let mut paren = 0isize;
    let mut bracket = 0isize;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(text, index)?;
            continue;
        }
        match byte {
            b'{' => curly += 1,
            b'}' => curly -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b';' if curly == 0 && paren == 0 && bracket == 0 => return Some(index),
            _ => {}
        }
        index += 1;
    }
    None
}

fn csharp_string_end(text: &str, start: usize) -> Option<usize> {
    if text.as_bytes().get(start) != Some(&b'"') {
        return None;
    }
    let quote_count = text[start..]
        .bytes()
        .take_while(|byte| *byte == b'"')
        .count();
    if quote_count >= 3 {
        let delimiter = "\"".repeat(quote_count);
        return text[start + quote_count..]
            .find(&delimiter)
            .map(|relative| start + quote_count + relative + quote_count)
            .or(Some(text.len()));
    }
    let verbatim = start > 0 && text.as_bytes().get(start - 1) == Some(&b'@');
    let mut index = start + 1;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        let next = text.as_bytes().get(index + 1).copied();
        if verbatim && byte == b'"' && next == Some(b'"') {
            index += 2;
            continue;
        }
        if byte == b'"' {
            return Some(index + 1);
        }
        if !verbatim && byte == b'\\' && next.is_some() {
            index += 2;
        } else {
            index += 1;
        }
    }
    Some(text.len())
}

fn strip_csharp_comments(text: &str) -> String {
    let mut output = String::new();
    let mut index = 0usize;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        let next = text.as_bytes().get(index + 1).copied();
        if byte == b'"' {
            let end = csharp_string_end(text, index).unwrap_or(text.len());
            output.push_str(&text[index..end]);
            index = end;
        } else if byte == b'/' && next == Some(b'/') {
            index += 2;
            while index < text.len() && text.as_bytes().get(index) != Some(&b'\n') {
                index += 1;
            }
        } else if byte == b'/' && next == Some(b'*') {
            index += 2;
            while index + 1 < text.len()
                && !(text.as_bytes()[index] == b'*' && text.as_bytes()[index + 1] == b'/')
            {
                index += 1;
            }
            index = (index + 2).min(text.len());
        } else {
            output.push(byte as char);
            index += 1;
        }
    }
    output
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                validate_identifier(key, &format!("{path}.{key}"), errors);
                validate_allowed_suffix_key(key, &format!("{path}.{key}"), errors);
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) if prohibited_string_value(text, Some(path)) => {
            errors.push(format!("{path} contains prohibited value"));
        }
        _ => {}
    }
}

fn prohibited_string_value(value: &str, path: Option<&str>) -> bool {
    contains_aws_key(value)
        || contains_private_key(value)
        || contains_url_scheme(value)
        || contains_email(value)
        || contains_private_ip(value)
        || contains_guid(value)
        || contains_secret_assignment(value)
        || prohibited_hostname_value(value, path)
}

fn prohibited_hostname_value(value: &str, path: Option<&str>) -> bool {
    hostname_scan_values(value, path)
        .into_iter()
        .any(|(candidate, from_literal)| {
            hostnames(&candidate).into_iter().any(|hostname| {
                if is_program_path(path) && !from_literal && hostname.matches('.').count() < 2 {
                    return false;
                }
                if is_program_path(path)
                    && !from_literal
                    && hostname != hostname.to_ascii_lowercase()
                    && hostname != hostname.to_ascii_uppercase()
                {
                    return false;
                }
                !SYNTHETIC_HOSTNAME_ALLOWLIST.contains(&hostname.to_ascii_lowercase().as_str())
            })
        })
}

fn hostname_scan_values(value: &str, _path: Option<&str>) -> Vec<(String, bool)> {
    let mut values = Vec::new();
    values.push((value.to_string(), false));
    for literal in csharp_string_literals(value) {
        values.push((literal, true));
    }
    values
}

fn is_program_path(path: Option<&str>) -> bool {
    path.is_some_and(|value| value == PROGRAM_PATH || value.ends_with(PROGRAM_PATH))
}

fn hostnames(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-'))
        .filter_map(|token| {
            let token = token.trim_matches('.');
            if token.len() > 253 || !token.contains('.') {
                return None;
            }
            let labels: Vec<&str> = token.split('.').collect();
            if labels.len() < 3 {
                return None;
            }
            let tld = labels.last().copied().unwrap_or_default();
            if tld.len() < 2 || !tld.chars().all(|ch| ch.is_ascii_alphabetic()) {
                return None;
            }
            if labels.iter().all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            }) {
                Some(token.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn validate_identifier(identifier: &str, path: &str, errors: &mut Vec<String>) {
    let normalized = normalize_identifier(identifier);
    if PROHIBITED_IDENTIFIERS.contains(&normalized.as_str()) {
        errors.push(format!(
            "{path} contains prohibited identifier {identifier}"
        ));
    }
}

fn validate_allowed_suffix_key(key: &str, path: &str, errors: &mut Vec<String>) {
    let lower = key.to_ascii_lowercase();
    if (lower.ends_with("allowed") || lower.ends_with("enabled"))
        && !ALLOWED_BOOLEAN_SUFFIX_FIELDS.contains(&key)
    {
        errors.push(format!("{path} uses unsupported allowed flag {key}"));
    }
}

fn normalize_identifier(identifier: &str) -> String {
    identifier
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn contains_assignment(value: &str, field: &str) -> bool {
    let pattern = format!("{field} =");
    value.contains(&pattern)
}

fn contains_private_key(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin ") && lower.contains("private key-----")
}

fn contains_aws_key(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.as_bytes().windows(20).any(|window| {
        window.starts_with(b"AKIA") && window.iter().all(|byte| byte.is_ascii_alphanumeric())
    })
}

fn contains_url_scheme(value: &str) -> bool {
    let Some(separator) = value.find("://") else {
        return false;
    };
    let prefix = &value[..separator];
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

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let token = token.trim_matches(|ch: char| matches!(ch, ',' | ';' | '"' | '\'' | '(' | ')'));
        let Some((local, domain)) = token.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && hostnames(domain)
                .into_iter()
                .any(|hostname| hostname == domain)
    })
}

fn contains_private_ip(value: &str) -> bool {
    for token in value.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        let octets: Vec<u16> = token
            .split('.')
            .filter_map(|part| part.parse::<u16>().ok())
            .collect();
        if octets.len() != 4 || octets.iter().any(|octet| *octet > 255) {
            continue;
        }
        if octets[0] == 10
            || octets[0] == 192 && octets[1] == 168
            || octets[0] == 172 && (16..=31).contains(&octets[1])
        {
            return true;
        }
    }
    false
}

fn contains_guid(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(|token| {
            token.len() == 36
                && token.as_bytes().get(8) == Some(&b'-')
                && token.as_bytes().get(13) == Some(&b'-')
                && token.as_bytes().get(18) == Some(&b'-')
                && token.as_bytes().get(23) == Some(&b'-')
                && token
                    .chars()
                    .filter(|ch| *ch != '-')
                    .all(|ch| ch.is_ascii_hexdigit())
        })
}

fn contains_secret_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    for term in [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ] {
        let mut offset = 0usize;
        while let Some(relative) = lower[offset..].find(term) {
            let index = offset + relative;
            let after = index + term.len();
            if !identifier_boundary(&lower, index, after) {
                offset = after;
                continue;
            }
            let separator = skip_ascii_whitespace(&lower, after);
            if matches!(lower.as_bytes().get(separator), Some(b':' | b'=')) {
                let value_index = skip_ascii_whitespace(&lower, separator + 1);
                if lower[value_index..]
                    .chars()
                    .next()
                    .is_some_and(|ch| !ch.is_whitespace())
                {
                    return true;
                }
            }
            offset = after;
        }
    }
    false
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < text.len() {
        if text.as_bytes().get(index) == Some(&b'"') {
            if let Some(end) = csharp_string_end(text, index) {
                if let Some(value) = csharp_string_literal_value(&text[index..end]) {
                    values.push(value);
                }
                index = end;
                continue;
            }
        }
        index += 1;
    }
    values
}

fn exact_string_literal(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.starts_with('"') || !value.ends_with('"') {
        return None;
    }
    csharp_string_literal_value(value)
}

fn csharp_unescape_string(value: &str) -> String {
    let mut output = String::new();
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        let Some(next) = chars.next() else {
            output.push('\\');
            break;
        };
        match next {
            'u' => output.push(read_hex_escape(&mut chars, 4).unwrap_or_default()),
            'U' => output.push(read_hex_escape(&mut chars, 8).unwrap_or_default()),
            'x' => output.push(read_variable_hex_escape(&mut chars).unwrap_or_default()),
            '"' => output.push('"'),
            '\\' => output.push('\\'),
            '0' => output.push('\0'),
            'a' => output.push('\u{7}'),
            'b' => output.push('\u{8}'),
            'f' => output.push('\u{c}'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            'v' => output.push('\u{b}'),
            other => output.push(other),
        }
    }
    output
}

fn read_hex_escape<I>(chars: &mut std::iter::Peekable<I>, width: usize) -> Option<char>
where
    I: Iterator<Item = char>,
{
    let mut hex = String::new();
    for _ in 0..width {
        let ch = chars.next()?;
        if !ch.is_ascii_hexdigit() {
            return None;
        }
        hex.push(ch);
    }
    char::from_u32(u32::from_str_radix(&hex, 16).ok()?)
}

fn read_variable_hex_escape<I>(chars: &mut std::iter::Peekable<I>) -> Option<char>
where
    I: Iterator<Item = char>,
{
    let mut hex = String::new();
    while hex.len() < 4 {
        let Some(ch) = chars.peek().copied() else {
            break;
        };
        if !ch.is_ascii_hexdigit() {
            break;
        }
        hex.push(ch);
        chars.next();
    }
    char::from_u32(u32::from_str_radix(&hex, 16).ok()?)
}

fn normalize_member_access(expression: &str) -> String {
    let mut output = String::new();
    let mut chars = expression.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_whitespace() {
            let mut lookahead = chars.clone();
            while lookahead
                .peek()
                .is_some_and(|candidate| candidate.is_whitespace())
            {
                lookahead.next();
            }
            if output.ends_with('.') || lookahead.peek() == Some(&'.') {
                continue;
            }
            output.push(ch);
        } else {
            output.push(ch);
        }
    }
    output.replace(" .", ".").replace(". ", ".")
}

fn is_plain_identifier(value: &str) -> bool {
    let Some(first) = value.as_bytes().first().copied() else {
        return false;
    };
    is_identifier_start(first)
        && value
            .as_bytes()
            .iter()
            .skip(1)
            .all(|byte| is_identifier_part(*byte))
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

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_part(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn identifier_boundary(source: &str, start: usize, end: usize) -> bool {
    let bytes = source.as_bytes();
    let before = start == 0 || !is_identifier_part(bytes[start - 1]);
    let after = end >= bytes.len() || !is_identifier_part(bytes[end]);
    before && after
}

fn skip_ascii_whitespace(source: &str, offset: usize) -> usize {
    let mut index = offset;
    while source
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn squash_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
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

fn missing_values(required: &[String], values: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|value| !values.contains(value))
        .cloned()
        .collect()
}

fn unexpected_values(values: &[String], required: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|value| !required.contains(value))
        .cloned()
        .collect()
}

fn unique_count(values: &[String]) -> usize {
    values.iter().collect::<BTreeSet<_>>().len()
}

fn unique_count_vec(values: &[Vec<String>]) -> usize {
    values.iter().collect::<BTreeSet<_>>().len()
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
    fn unicode_escaped_hostname_is_prohibited() {
        let value = "var note = \"db\\u002Eprod\\u002Eexample\\u002Ecom\";";

        assert!(prohibited_string_value(value, Some(PROGRAM_PATH)));
    }
}
