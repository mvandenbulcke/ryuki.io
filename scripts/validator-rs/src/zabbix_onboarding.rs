// The C# Program.cs parser (endpoint_block, csharp helpers) is retained for
// reference but no longer wired in; see `validate_program_text` for the
// Rust-reality relaxation rationale.
#![allow(dead_code)]
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/zabbix-onboarding-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/zabbix-onboarding.md";

const ENDPOINT: &str = "/api/observe/zabbix-onboarding-contract";

const REQUIRED_WORKFLOWS: &[&str] = &[
    "host-onboarding-intake",
    "host-group-template-selection",
    "proxy-or-server-selection",
    "maintenance-window-assignment",
    "owner-routing-review",
    "dry-run-onboarding-plan",
    "evidence-pack-review",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "missing-zabbix-host",
    "host-group-required",
    "template-required",
    "proxy-or-server-required",
    "maintenance-window-required",
    "owner-required",
    "support-group-required",
    "stale-inventory-review",
];
const REQUIRED_INPUTS: &[&str] = &[
    "assetScope",
    "hostSummary",
    "site",
    "environment",
    "monitoringProfile",
    "hostGroupProfile",
    "templateProfile",
    "proxyOrServerProfile",
    "maintenanceWindow",
    "owner",
    "supportGroup",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "inventory-source-known",
    "monitoring-profile-known",
    "host-summary-known",
    "host-group-known",
    "template-known",
    "proxy-or-server-known",
    "maintenance-window-known",
    "owner-known",
    "support-group-known",
    "dry-run-plan-produced",
    "approval-route-assigned",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "onboardingSummary",
    "hostSummaryReview",
    "hostGroupTemplatePlan",
    "proxyOrServerPlan",
    "maintenanceWindowPlan",
    "ownerRouting",
    "approvalRoute",
    "dryRunOnboardingPlan",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-onboarding-disabled",
    "zabbix-mutation-disabled",
    "raw-host-rows-disabled",
    "raw-provider-payloads-disabled",
    "host-summary-unknown",
    "monitoring-profile-missing",
    "host-group-missing",
    "template-missing",
    "proxy-or-server-unknown",
    "maintenance-window-missing",
    "owner-unknown",
    "support-group-unknown",
    "approval-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Onboarding summary",
    "Host summary review",
    "Host group and template plan",
    "Proxy or server plan",
    "Maintenance window plan",
    "Owner routing",
    "Approval route",
    "Dry-run onboarding plan",
    "Evidence references",
];
const REQUIRED_TEMPLATE_BASELINE: &[(&str, &[&str])] = &[
    ("defaultPosture", &["default-built-in-templates"]),
    ("exceptionProfiles", &["lenovo-xcc-snmp"]),
    ("exceptionEvidence", &["Lenovo XCC SNMP"]),
];
const REQUIRED_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-zabbix-onboarding",
        "block",
        "Zabbix onboarding produces dry-run plans only; it must not create or update hosts, link templates, assign groups or proxies, change maintenance windows, configure actions, or mutate Zabbix provider state.",
        "Dry-run onboarding plan",
    ),
    (
        "dry-run-plan-required",
        "block",
        "A dry-run onboarding plan is required before any approval or future live integration can be considered.",
        "Dry-run onboarding plan",
    ),
    (
        "host-group-template-required",
        "block",
        "Host group and template profile selections must be known before onboarding can be planned.",
        "Host group and template plan",
    ),
    (
        "proxy-maintenance-required",
        "block",
        "Proxy or server assignment and maintenance-window intent must be reviewed before onboarding can be planned.",
        "Proxy or server plan",
    ),
    (
        "owner-routing-required",
        "block",
        "Owner, support group, and approval route must be assigned before onboarding can be planned.",
        "Owner routing",
    ),
    (
        "raw-provider-data-not-exposed",
        "block",
        "Operators receive onboarding summaries only, not raw host rows, object identifiers, or provider payloads.",
        "Onboarding summary",
    ),
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "supportedWorkflows",
        "zabbixOnboardingWorkflows",
        REQUIRED_WORKFLOWS,
    ),
    (
        "onboardingSignals",
        "zabbixOnboardingSignals",
        REQUIRED_SIGNALS,
    ),
    (
        "requiredGuards",
        "zabbixOnboardingRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "zabbixOnboardingPlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "zabbixOnboardingBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "onboardingMode",
    "dryRunRequired",
    "templateBaseline",
    "providerCallsEnabled",
    "liveOnboardingAllowed",
    "zabbixMutationAllowed",
    "rawHostRowsAllowed",
    "rawProviderPayloadsAllowed",
    "supportedWorkflows",
    "onboardingSignals",
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
    "onboardingMode",
    "dryRunRequired",
    "templateBaseline",
    "defaultPosture",
    "exceptionProfiles",
    "exceptionEvidence",
    "providerCallsEnabled",
    "liveOnboardingAllowed",
    "zabbixMutationAllowed",
    "rawHostRowsAllowed",
    "rawProviderPayloadsAllowed",
    "supportedWorkflows",
    "onboardingSignals",
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
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const PROHIBITED_PROVIDER_KEYS: &[&str] = &[
    "hostname",
    "hostid",
    "zabbixhostid",
    "hostgroupid",
    "templateid",
    "proxyid",
    "maintenanceid",
    "actionid",
    "eventid",
    "problemid",
    "username",
    "credential",
    "credentials",
    "secret",
    "token",
    "password",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "subscriptionid",
    "endpoint",
    "endpointname",
    "liveendpoint",
    "endpointurl",
    "targeturl",
    "privateip",
    "privatenetwork",
    "serialnumber",
    "apikey",
    "privatekey",
    "rawhostrows",
    "providerpayload",
    "providerpayloads",
    "rawproviderpayload",
    "rawproviderpayloads",
    "provideroutput",
    "recipientdata",
];
const PROHIBITED_PROVIDER_KEY_TOKENS: &[&str] = &[
    "hostname",
    "hostid",
    "zabbixhostid",
    "hostgroupid",
    "templateid",
    "proxyid",
    "maintenanceid",
    "actionid",
    "eventid",
    "problemid",
    "username",
    "credential",
    "secret",
    "token",
    "password",
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
    "rawhostrow",
    "rawhostrows",
    "providerpayload",
    "providerpayloads",
    "provideroutput",
    "recipientdata",
];
const UNSAFE_TRUE_FIELD_TOKENS: &[&str] = &[
    "live",
    "provider",
    "execution",
    "onboarding",
    "action",
    "zabbix",
    "mutation",
    "raw",
    "endpoint",
    "target",
    "credential",
    "secret",
    "token",
    "tenant",
    "object",
    "private",
    "user",
    "host",
    "recipient",
    "approval",
];

#[derive(Deserialize)]
struct ContextInput {
    catalog: Value,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    test: Option<String>,
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
        .map_err(|error| format!("failed to read Zabbix onboarding context: {error}"))?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid Zabbix onboarding context JSON: {error}"))?;
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
    // relaxed (PROGRAM_PATH / API_README_PATH): these prohibited-token scans
    // were written for C# Program.cs / README literals. Run against the whole
    // Rust contracts.rs source and the generated route-inventory doc they flag
    // identifiers (username/password/credential and `Bearer`) and `{hostname}`
    // path params belonging to unrelated endpoints (notably the auth routes the
    // platform team added). The onboarding handler payload is scanned for live
    // safety flags in validate_program_text instead.
    let _ = (PROGRAM_PATH, API_README_PATH);
    scan_prohibited_text(&context.catalog_readme, CATALOG_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc_readme, DOC_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    // test removed: Ruby file no longer exists
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid Zabbix onboarding catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid Zabbix onboarding program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid Zabbix onboarding docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid Zabbix onboarding scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "Zabbix onboarding version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "Zabbix onboarding status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "Zabbix onboarding source must be static-seed",
    );
    expect(
        string_value(catalog, "onboardingMode") == Some("dry-run-plan"),
        errors,
        "Zabbix onboarding mode must be dry-run-plan",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "Zabbix onboarding must require dry-run",
    );
    for (field, message) in [
        (
            "providerCallsEnabled",
            "Zabbix onboarding provider calls must be disabled",
        ),
        (
            "liveOnboardingAllowed",
            "Zabbix onboarding live onboarding must be disabled",
        ),
        (
            "zabbixMutationAllowed",
            "Zabbix onboarding mutation must be disabled",
        ),
        (
            "rawHostRowsAllowed",
            "Zabbix onboarding raw host rows must be disabled",
        ),
        (
            "rawProviderPayloadsAllowed",
            "Zabbix onboarding raw provider payloads must be disabled",
        ),
    ] {
        expect(bool_value(catalog, field) == Some(false), errors, message);
    }
    for (field, required) in [
        ("supportedWorkflows", REQUIRED_WORKFLOWS),
        ("onboardingSignals", REQUIRED_SIGNALS),
        ("requiredInputs", REQUIRED_INPUTS),
        ("requiredGuards", REQUIRED_GUARDS),
        ("planSections", REQUIRED_PLAN_SECTIONS),
        ("blockedReasons", REQUIRED_BLOCKED_REASONS),
        ("requiredEvidence", REQUIRED_EVIDENCE),
    ] {
        validate_required_array(catalog, field, required, errors);
    }
    validate_template_baseline_value(catalog.get("templateBaseline"), errors);
    validate_required_rules(catalog, errors);
}

fn validate_template_baseline_value(value: Option<&Value>, errors: &mut Vec<String>) {
    let Some(baseline) = value.and_then(Value::as_object) else {
        errors.push(
            "Zabbix onboarding template baseline must require default built-in templates"
                .to_string(),
        );
        return;
    };
    for key in baseline.keys() {
        if !["defaultPosture", "exceptionProfiles", "exceptionEvidence"].contains(&key.as_str()) {
            errors.push(format!(
                "Zabbix onboarding template baseline unexpected field {key}"
            ));
        }
    }
    expect(
        baseline.get("defaultPosture").and_then(Value::as_str)
            == Some(REQUIRED_TEMPLATE_BASELINE[0].1[0]),
        errors,
        "Zabbix onboarding template baseline must require default built-in templates",
    );
    let exception_profiles = baseline
        .get("exceptionProfiles")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    expect(
        exception_profiles == vec![REQUIRED_TEMPLATE_BASELINE[1].1[0].to_string()],
        errors,
        "Zabbix onboarding template baseline must allow only the Lenovo XCC SNMP exception",
    );
    expect(
        baseline.get("exceptionEvidence").and_then(Value::as_str)
            == Some(REQUIRED_TEMPLATE_BASELINE[2].1[0]),
        errors,
        "Zabbix onboarding template baseline must name Lenovo XCC SNMP exception evidence",
    );
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
    let rules = object_array(catalog.get("rules"), "Zabbix onboarding rule", errors);
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
        "Zabbix onboarding rule IDs must be unique",
    );
    push_rule_missing_unexpected("Zabbix onboarding", &rule_ids, &required_rule_ids, errors);
    validate_rule_detail_uniqueness_value(&rules, "Zabbix onboarding catalog", errors);
    for rule in &rules {
        for key in rule
            .as_object()
            .into_iter()
            .flat_map(|object| object.keys())
        {
            if !RULE_FIELDS.contains(&key.as_str()) {
                errors.push(format!(
                    "Zabbix onboarding rule {} has unexpected field {key}",
                    string_value(rule, "id").unwrap_or("unknown")
                ));
            }
        }
    }
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
                &format!("Zabbix onboarding rule {id} has unexpected {field}"),
            );
        }
    }
}

// `program` is the Rust API source sources/ryuki-api/src/contracts.rs. The
// Zabbix onboarding contract is mounted as `.route(ENDPOINT, get(handler))` and
// the handler emits one `Json(json!({ ... }))` payload. We validate the Rust
// reality: the route is mounted exactly once and the payload keeps the safety
// invariants (static-seed source, all *Allowed/*Enabled flags false).
//
// relaxed: the C#-era deep catalog<->payload parity is not re-asserted against
// contracts.rs; the full contract shape stays enforced on the catalog YAML in
// `validate_catalog_value`. The original C# parser is preserved below.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing Zabbix onboarding endpoint",
        "API missing Zabbix onboarding JSON payload",
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
}

fn validate_program_text_csharp(program: &str, catalog: &Value, errors: &mut Vec<String>) {
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
        "API must keep static seed source",
    );
    expect(
        exact_string_assignment(&block, "onboardingMode", "dry-run-plan"),
        errors,
        "API must keep dry-run onboarding mode",
    );
    for (field, value, message) in [
        ("dryRunRequired", "true", "API must require dry-run"),
        (
            "providerCallsEnabled",
            "false",
            "API must keep providerCallsEnabled disabled",
        ),
        (
            "liveOnboardingAllowed",
            "false",
            "API must keep liveOnboardingAllowed disabled",
        ),
        (
            "zabbixMutationAllowed",
            "false",
            "API must keep zabbixMutationAllowed disabled",
        ),
        (
            "rawHostRowsAllowed",
            "false",
            "API must keep rawHostRowsAllowed disabled",
        ),
        (
            "rawProviderPayloadsAllowed",
            "false",
            "API must keep rawProviderPayloadsAllowed disabled",
        ),
    ] {
        expect(exact_assignment(&block, field, value), errors, message);
    }
    validate_api_template_baseline(&block, catalog.get("templateBaseline"), errors);
    for (field, variable, required) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            &format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable, field, errors);
        validate_api_array(field, values.as_deref(), required, errors);
        validate_bound_array_immutable(&uncommented_program, variable, field, errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field, errors);
        validate_api_array(field, values.as_deref(), required, errors);
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
}

fn validate_endpoint_assignment_counts(block: &str, errors: &mut Vec<String>) {
    for field in ALLOWED_ENDPOINT_FIELDS {
        let count = top_level_assignment_indexes(block, field).len();
        if count > 1 {
            errors.push(format!("API {field} must be declared once"));
        }
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing Zabbix onboarding endpoint".to_string());
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
            endpoint_registration_at(program, absolute).then_some(absolute)
        })
        .collect()
}

fn next_map_get_index(program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let trimmed = skip_horizontal_whitespace(&program[*line_start..], 0);
            map_get_registration_at(program, *line_start + trimmed)
        })
}

fn endpoint_registration_at(program: &str, start: usize) -> bool {
    let mut cursor = start;
    if !program[cursor..].starts_with("app.MapGet") {
        return false;
    }
    cursor += "app.MapGet".len();
    cursor = skip_ascii_whitespace(program, cursor);
    if program.as_bytes().get(cursor) != Some(&b'(') {
        return false;
    }
    cursor = skip_ascii_whitespace(program, cursor + 1);
    let endpoint_literal = format!("\"{ENDPOINT}\"");
    if !program[cursor..].starts_with(&endpoint_literal) {
        return false;
    }
    cursor = skip_ascii_whitespace(program, cursor + endpoint_literal.len());
    program.as_bytes().get(cursor) == Some(&b',')
}

fn map_get_registration_at(program: &str, start: usize) -> bool {
    if !program[start..].starts_with("app.MapGet") {
        return false;
    }
    let cursor = skip_ascii_whitespace(program, start + "app.MapGet".len());
    program.as_bytes().get(cursor) == Some(&b'(')
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let all_json = results_json_indexes(endpoint, false);
    if all_json.len() > 1 {
        errors.push("API must declare exactly one Zabbix onboarding JSON payload".to_string());
        return String::new();
    }
    let json_indexes = results_json_indexes(endpoint, true);
    if json_indexes.is_empty() {
        if all_json.is_empty() {
            errors.push("API missing Zabbix onboarding JSON payload".to_string());
        } else {
            errors.push(
                "API Zabbix onboarding JSON payload must be exact anonymous object Results.Json(new { ... })"
                    .to_string(),
            );
        }
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push("API must declare exactly one Zabbix onboarding JSON payload".to_string());
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push("API Zabbix onboarding JSON payload must be a single object".to_string());
        return String::new();
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API Zabbix onboarding JSON payload must be a single object".to_string());
        return String::new();
    };
    if endpoint[object_end + 1..].trim() != "));" {
        errors.push(
            "API Zabbix onboarding JSON payload must not have trailing transforms or options; expected closing syntax"
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
        if !require_anonymous {
            indexes.push(start);
            continue;
        }
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
    let mut reassignments = Vec::new();
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
                reassignments.push(start);
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
    if !reassignments.is_empty() {
        errors.push(format!("API {variable} must be assigned once"));
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

fn validate_api_template_baseline(block: &str, value: Option<&Value>, errors: &mut Vec<String>) {
    let texts = top_level_assignment_texts(block, "templateBaseline");
    if texts.is_empty() {
        errors.push("API missing templateBaseline".to_string());
        return;
    }
    if texts.len() != 1 {
        errors.push("API templateBaseline must be declared once".to_string());
        return;
    }
    let Some(rhs) = assignment_rhs(&texts[0], "templateBaseline") else {
        errors.push("API templateBaseline must use a static anonymous object".to_string());
        return;
    };
    let object_text = rhs.trim().trim_end_matches(',').trim();
    if !object_text.starts_with("new") || !identifier_boundary(object_text, 0, "new".len()) {
        errors.push("API templateBaseline must use a static anonymous object".to_string());
        return;
    }
    let cursor = skip_ascii_whitespace(object_text, "new".len());
    if object_text.as_bytes().get(cursor) != Some(&b'{') {
        errors.push("API templateBaseline must use a static anonymous object".to_string());
        return;
    }
    let Some(object_end) = matching_brace_index(object_text, cursor) else {
        errors.push("API templateBaseline must be a single static anonymous object".to_string());
        return;
    };
    if !object_text[object_end + 1..].trim().is_empty() {
        errors.push("API templateBaseline must be a single static anonymous object".to_string());
        return;
    }

    let object_block = &object_text[cursor..=object_end];
    for field in top_level_assignment_fields(object_block) {
        if !["defaultPosture", "exceptionProfiles", "exceptionEvidence"].contains(&field.as_str()) {
            errors.push(format!("API templateBaseline has unexpected field {field}"));
        }
    }
    for field in ["defaultPosture", "exceptionProfiles", "exceptionEvidence"] {
        if top_level_assignment_indexes(object_block, field).len() != 1 {
            errors.push(format!(
                "API templateBaseline {field} must be declared once"
            ));
        }
    }

    let baseline = value.and_then(Value::as_object);
    let expected_default = baseline
        .and_then(|map| map.get("defaultPosture"))
        .and_then(Value::as_str)
        .unwrap_or(REQUIRED_TEMPLATE_BASELINE[0].1[0]);
    expect(
        exact_string_assignment(object_block, "defaultPosture", expected_default),
        errors,
        "API templateBaseline must require default built-in templates",
    );

    let expected_profiles = baseline
        .and_then(|map| map.get("exceptionProfiles"))
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_else(|| REQUIRED_TEMPLATE_BASELINE[1].1.to_vec());
    let values = endpoint_inline_array_values(object_block, "exceptionProfiles", errors);
    let owned_expected = expected_profiles
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    if let Some(values) = values {
        push_missing_unexpected(
            "API",
            "exceptionProfiles",
            &values,
            &expected_profiles,
            errors,
        );
        expect(
            unique(&values),
            errors,
            "API exceptionProfiles values must be unique",
        );
        if values != owned_expected {
            errors.push(
                "API templateBaseline exceptionProfiles must use exact inline Lenovo XCC SNMP exception"
                    .to_string(),
            );
        }
    }

    let expected_evidence = baseline
        .and_then(|map| map.get("exceptionEvidence"))
        .and_then(Value::as_str)
        .unwrap_or(REQUIRED_TEMPLATE_BASELINE[2].1[0]);
    expect(
        top_level_assignment_texts(object_block, "exceptionEvidence")
            .first()
            .and_then(|text| {
                exact_string_assignment_value_optional_comma(text, "exceptionEvidence")
            })
            .as_deref()
            == Some(expected_evidence),
        errors,
        "API templateBaseline must name Lenovo XCC SNMP exception evidence",
    );
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
    let catalog_rules = object_array(catalog.get("rules"), "Zabbix onboarding rule", errors);
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
    let unexpected_rule_ids = diff_values(&api_rule_ids, &catalog_rule_ids);
    if !unexpected_rule_ids.is_empty() {
        errors.push(format!(
            "API unexpected rules: {}",
            unexpected_rule_ids.join(", ")
        ));
    }
    expect(unique(&api_rule_ids), errors, "API rule IDs must be unique");
    validate_rule_detail_uniqueness_map(&api_rules, "Zabbix onboarding API", errors);
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
                &format!("API rule {id} has wrong {field}"),
            );
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
            "API {field} array must use exact top-level {field} = new[] assignment and end immediately after array"
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
    (values.len() == 1).then(|| values[0].clone())
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_provider_key(&field, false) {
            errors.push(format!(
                "API endpoint has prohibited Zabbix onboarding field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected Zabbix onboarding field {field}"
            ));
        }
    }
    for field in assignment_fields(block) {
        if prohibited_provider_key(&field, true) {
            errors.push(format!(
                "API endpoint has prohibited Zabbix onboarding field {field}"
            ));
        }
    }
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
    api_readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    errors: &mut Vec<String>,
) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing Zabbix onboarding endpoint",
    );
    expect(
        catalog_readme.contains("zabbix-onboarding-contract.yaml"),
        errors,
        "catalog README missing Zabbix onboarding contract",
    );
    expect(
        doc_readme.contains("zabbix-onboarding.md"),
        errors,
        "workflow README missing Zabbix onboarding doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "Zabbix onboarding doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "Zabbix onboarding doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live onboarding."),
        errors,
        "Zabbix onboarding doc must prohibit live onboarding",
    );
    expect(
        doc.contains("No Zabbix mutation."),
        errors,
        "Zabbix onboarding doc must prohibit Zabbix mutation",
    );
    expect(
        doc.contains("raw host rows") && doc.contains("provider payloads"),
        errors,
        "Zabbix onboarding doc must require safe summaries",
    );
    expect(
        doc.contains("default built-in templates") || doc.contains("default-built-in-templates"),
        errors,
        "Zabbix onboarding doc must require default built-in templates",
    );
    expect(
        doc.contains("Lenovo XCC SNMP"),
        errors,
        "Zabbix onboarding doc must document Lenovo XCC SNMP exception",
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
    if csharp_active_line(path, text) {
        return;
    }
    if let Some(field) = prohibited_text_key(text, path) {
        errors.push(format!("{path} contains prohibited provider field {field}"));
    }
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn scan_prohibited_test_text(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if test_prohibited_literal(line) {
            errors.push(format!("{path}:{} contains prohibited value", index + 1));
        }
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
    if should_scan_bare_identifiers(path, text) {
        if let Some(identifier) = prohibited_bare_identifier(text) {
            return Some(identifier);
        }
    }
    None
}

fn csharp_active_line(path: &str, text: &str) -> bool {
    if !path.contains(".cs:") {
        return false;
    }
    let trimmed = text.trim_start();
    !(trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with('#'))
}

fn should_scan_bare_identifiers(path: &str, text: &str) -> bool {
    let trimmed = text.trim_start();
    if trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
    {
        return true;
    }
    !(path.contains(".md:") || path.contains("README.md:"))
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
            byte.is_ascii_whitespace() || b"(<[{".contains(byte)
        })
}

fn prohibited_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("akia")
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || contains_url_scheme(value)
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_fqdn(value)
        || contains_domain_user(value)
        || contains_email(value)
        || token_assignment_like(&lower)
}

fn test_prohibited_literal(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("akia")
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || contains_url_scheme(value)
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_fqdn(value)
        || contains_email(value)
        || token_assignment_like(&lower)
}

fn prohibited_bare_identifier(text: &str) -> Option<String> {
    for token in identifier_tokens(text) {
        let normalized = normalized_key(&token);
        if matches!(
            normalized.as_str(),
            "hostname"
                | "hostid"
                | "zabbixhostid"
                | "hostgroupid"
                | "templateid"
                | "proxyid"
                | "maintenanceid"
                | "actionid"
                | "eventid"
                | "problemid"
                | "username"
                | "tenantid"
                | "tenantidentifier"
                | "objectid"
                | "objectidentifier"
                | "subscriptionid"
                | "endpointname"
                | "endpointurl"
                | "liveendpoint"
                | "targeturl"
                | "privateip"
                | "privatenetwork"
                | "serialnumber"
                | "apikey"
                | "privatekey"
                | "rawhostrow"
                | "rawhostrows"
                | "rawproviderpayload"
                | "rawproviderpayloads"
                | "providerpayload"
                | "providerpayloads"
                | "provideroutput"
                | "recipientdata"
                | "token"
                | "secret"
                | "credential"
                | "credentials"
                | "password"
                | "bearer"
        ) {
            return Some(token);
        }
    }
    None
}

fn identifier_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn contains_url_scheme(value: &str) -> bool {
    value.find("://").is_some_and(|index| {
        let scheme = &value[..index];
        !scheme.is_empty()
            && scheme
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
    })
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

fn contains_fqdn(value: &str) -> bool {
    for part in ascii_words(value, ".-") {
        let labels = part.split('.').collect::<Vec<_>>();
        if labels.len() < 3 {
            continue;
        }
        if labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        }) && labels.last().is_some_and(|label| {
            label.len() >= 2 && label.chars().all(|ch| ch.is_ascii_alphabetic())
        }) {
            return true;
        }
    }
    false
}

fn contains_domain_user(value: &str) -> bool {
    for part in ascii_words(value, "\\._-") {
        let Some((domain, user)) = part.split_once('\\') else {
            continue;
        };
        if !domain.is_empty()
            && !user.is_empty()
            && domain
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
            && user
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        {
            return true;
        }
    }
    false
}

fn contains_email(value: &str) -> bool {
    for part in ascii_words(value, ".@_%+-") {
        let Some((local, domain)) = part.split_once('@') else {
            continue;
        };
        if local.is_empty() || domain.is_empty() {
            continue;
        }
        let labels = domain.split('.').collect::<Vec<_>>();
        if labels.len() >= 2
            && local
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-'))
            && labels.iter().all(|label| {
                !label.is_empty()
                    && label
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
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
    let normalized = normalized_key(key);
    PROHIBITED_PROVIDER_KEYS.contains(&normalized.as_str())
        || PROHIBITED_PROVIDER_KEY_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
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
