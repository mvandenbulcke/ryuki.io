use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/firmware-compliance-exception-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/firmware-compliance-exception.md";

const ENDPOINT: &str = "/api/operations/firmware-compliance-exception-contract";
const REQUIRED_PROFILES: &[&str] = &[
    "hpe-dl360-msa",
    "hpe-simplivity-dl380",
    "lenovo-sr",
    "lenovo-vx",
    "lenovo-mx",
];
const REQUIRED_EXCEPTION_TYPES: &[&str] = &[
    "firmware-baseline-deviation",
    "driver-baseline-deviation",
    "hardware-support-deviation",
    "compatibility-evidence-gap",
    "maintenance-window-deferral",
    "vendor-baseline-pending",
];
const REQUIRED_RISK_LEVELS: &[&str] = &["low", "medium", "high", "emergency"];
const REQUIRED_INPUTS: &[&str] = &[
    "site",
    "hardwareProfile",
    "platformRole",
    "targetBaseline",
    "observedBaselineSummary",
    "exceptionReason",
    "clusterCriticality",
    "supportStatus",
    "remediationWindow",
    "expiryDate",
    "reviewCadence",
    "owner",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "site-known",
    "hardware-profile-known",
    "target-baseline-known",
    "observed-baseline-summarized",
    "compatibility-impact-reviewed",
    "support-risk-reviewed",
    "cluster-criticality-reviewed",
    "maintenance-window-known",
    "exception-owner-assigned",
    "expiry-date-set",
    "remediation-plan-ready",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "exceptionSummary",
    "baselineDecision",
    "compatibilityImpact",
    "supportRisk",
    "clusterCriticality",
    "remediationPlan",
    "approvalRoute",
    "expiryAndReview",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-firmware-change-disabled",
    "raw-inventory-rows-disabled",
    "host-identifiers-disabled",
    "serial-numbers-disabled",
    "exact-firmware-versions-disabled",
    "raw-vendor-payloads-disabled",
    "site-unknown",
    "hardware-profile-unknown",
    "target-baseline-missing",
    "observed-baseline-missing",
    "compatibility-impact-unknown",
    "support-risk-unknown",
    "cluster-criticality-unknown",
    "expiry-missing",
    "remediation-plan-missing",
    "approval-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Firmware exception summary",
    "Target baseline summary",
    "Observed baseline summary",
    "Compatibility impact review",
    "Support risk review",
    "Cluster criticality review",
    "Remediation plan",
    "Approval route",
    "Expiry and review date",
    "Evidence references",
];
const REQUIRED_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-firmware-actions",
        "block",
        "Firmware compliance exceptions report risk acceptance only and never patch firmware, remediate drivers, reconfigure hardware, or call live vendor tools.",
        "Firmware exception summary",
    ),
    (
        "baseline-evidence-required",
        "block",
        "Target and observed baseline evidence must be summarized before a firmware exception can be reviewed.",
        "Baseline summary",
    ),
    (
        "compatibility-support-risk-required",
        "block",
        "Compatibility impact, support status, and cluster criticality must be reviewed before exception approval.",
        "Support risk review",
    ),
    (
        "expiry-remediation-required",
        "block",
        "Exceptions require owner, expiry date, remediation window, and review cadence before acceptance.",
        "Expiry and review date",
    ),
    (
        "raw-firmware-inventory-not-exposed",
        "block",
        "Firmware exception evidence must use safe summaries only and must not expose host identifiers, endpoint names, private IPs, exact observed firmware versions, serials, asset tags, raw inventory rows, raw logs, or vendor payloads.",
        "Evidence references",
    ),
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "supportedProfiles",
        "firmwareComplianceExceptionProfiles",
        REQUIRED_PROFILES,
    ),
    (
        "exceptionTypes",
        "firmwareComplianceExceptionTypes",
        REQUIRED_EXCEPTION_TYPES,
    ),
    (
        "riskLevels",
        "firmwareComplianceRiskLevels",
        REQUIRED_RISK_LEVELS,
    ),
    (
        "requiredGuards",
        "firmwareComplianceRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "firmwareCompliancePlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "firmwareComplianceBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const DISABLED_FIELDS: &[(&str, &str)] = &[
    (
        "providerCallsEnabled",
        "API must keep providerCallsEnabled disabled",
    ),
    (
        "liveFirmwareChangesAllowed",
        "API must keep liveFirmwareChangesAllowed disabled",
    ),
    (
        "rawInventoryRowsAllowed",
        "API must keep rawInventoryRowsAllowed disabled",
    ),
    (
        "hostIdentifiersAllowed",
        "API must keep hostIdentifiersAllowed disabled",
    ),
    (
        "serialNumbersAllowed",
        "API must keep serialNumbersAllowed disabled",
    ),
    (
        "exactFirmwareVersionsAllowed",
        "API must keep exactFirmwareVersionsAllowed disabled",
    ),
    (
        "rawVendorPayloadsAllowed",
        "API must keep rawVendorPayloadsAllowed disabled",
    ),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "exceptionMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveFirmwareChangesAllowed",
    "rawInventoryRowsAllowed",
    "hostIdentifiersAllowed",
    "serialNumbersAllowed",
    "exactFirmwareVersionsAllowed",
    "rawVendorPayloadsAllowed",
    "supportedProfiles",
    "exceptionTypes",
    "riskLevels",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const SAFE_STRUCTURED_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "exceptionMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveFirmwareChangesAllowed",
    "rawInventoryRowsAllowed",
    "hostIdentifiersAllowed",
    "serialNumbersAllowed",
    "exactFirmwareVersionsAllowed",
    "rawVendorPayloadsAllowed",
    "supportedProfiles",
    "exceptionTypes",
    "riskLevels",
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
const SINGLETON_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "exceptionMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveFirmwareChangesAllowed",
    "rawInventoryRowsAllowed",
    "hostIdentifiersAllowed",
    "serialNumbersAllowed",
    "exactFirmwareVersionsAllowed",
    "rawVendorPayloadsAllowed",
    "supportedProfiles",
    "exceptionTypes",
    "riskLevels",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const PROHIBITED_FIELD_TOKENS: &[&str] = &[
    "hostname",
    "hostnames",
    "hostid",
    "hostids",
    "hostidentifier",
    "hostidentifiers",
    "username",
    "usernames",
    "userid",
    "useridentifier",
    "userprincipalname",
    "upn",
    "accountidentifier",
    "accountname",
    "owneremail",
    "recipientname",
    "recipientidentifier",
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
    "url",
    "privateip",
    "privatenetwork",
    "rawprovider",
    "providerpayload",
    "rawrow",
    "rawinventoryrow",
    "rawinventoryrows",
    "rawhardwareinventoryrow",
    "rawhardwareinventoryrows",
    "serialnumber",
    "serialnumbers",
    "serial",
    "endpointname",
    "rawinventory",
    "rawhardwareinventory",
    "firmwareversion",
    "firmwareversions",
    "exactfirmwareversion",
    "exactfirmwareversions",
    "vendorpayload",
    "vendorpayloads",
    "rawvendorpayload",
    "rawvendorpayloads",
    "assettag",
];
const UNSAFE_TRUE_TOKENS: &[&str] = &[
    "live",
    "provider",
    "raw",
    "credential",
    "secret",
    "token",
    "tenant",
    "object",
    "private",
    "execution",
    "action",
    "remediation",
    "firmware",
    "vendor",
];

#[derive(Deserialize)]
struct ContextInput {
    catalog: Value,
    catalog_text: Option<String>,
    program: String,
    api_readme: String,
    catalog_readme: Option<String>,
    doc_readme: Option<String>,
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
    catalog_readme: Option<String>,
    doc_readme: Option<String>,
    doc: String,
}

#[derive(Deserialize)]
struct ScanInput {
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let input = fs::read_to_string(path).map_err(|error| {
        format!("failed to read firmware compliance exception context: {error}")
    })?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid firmware compliance exception context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    if let Some(text) = context.catalog_text.as_deref() {
        validate_raw_catalog_text(text, CATALOG_PATH, &mut errors);
    }
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        context.catalog_readme.as_deref().unwrap_or_default(),
        context.doc_readme.as_deref().unwrap_or_default(),
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    scan_prohibited_text(&context.program, PROGRAM_PATH, &mut errors);
    scan_prohibited_text(&context.api_readme, API_README_PATH, &mut errors);
    if let Some(text) = context.catalog_readme.as_deref() {
        scan_prohibited_text(text, CATALOG_README_PATH, &mut errors);
    }
    if let Some(text) = context.doc_readme.as_deref() {
        scan_prohibited_text(text, DOC_README_PATH, &mut errors);
    }
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    // test removed: Ruby file no longer exists
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid firmware compliance exception catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    scan_prohibited_value(&catalog, "firmware-compliance-exception", &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid firmware compliance exception program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid firmware compliance exception docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.api_readme,
        payload.catalog_readme.as_deref().unwrap_or_default(),
        payload.doc_readme.as_deref().unwrap_or_default(),
        &payload.doc,
        &mut errors,
    );
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ScanInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid firmware compliance exception scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("firmware compliance exception catalog must be a YAML mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "firmware compliance exception version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "firmware compliance exception status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "firmware compliance exception source must be static-seed",
    );
    expect(
        string_value(catalog, "exceptionMode") == Some("review-only"),
        errors,
        "firmware compliance exception mode must be review-only",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "firmware compliance exception must require dry-run",
    );
    for (field, message) in DISABLED_FIELDS {
        expect(bool_value(catalog, field) == Some(false), errors, *message);
    }
    for (field, required) in [
        ("supportedProfiles", REQUIRED_PROFILES),
        ("exceptionTypes", REQUIRED_EXCEPTION_TYPES),
        ("riskLevels", REQUIRED_RISK_LEVELS),
        ("requiredInputs", REQUIRED_INPUTS),
        ("requiredGuards", REQUIRED_GUARDS),
        ("planSections", REQUIRED_PLAN_SECTIONS),
        ("blockedReasons", REQUIRED_BLOCKED_REASONS),
        ("requiredEvidence", REQUIRED_EVIDENCE),
    ] {
        validate_required_array(catalog, field, required, errors);
    }
    validate_no_prohibited_contract_terms(catalog, errors);
    validate_required_rules(catalog, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let unexpected = map
        .keys()
        .filter(|key| !SAFE_STRUCTURED_KEYS.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        errors.push(format!(
            "firmware compliance exception unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
    validate_no_unsafe_true_values(catalog, "catalog", errors);
}

fn validate_no_prohibited_contract_terms(catalog: &Value, errors: &mut Vec<String>) {
    for field in [
        "supportedProfiles",
        "exceptionTypes",
        "riskLevels",
        "requiredInputs",
        "requiredGuards",
        "planSections",
        "blockedReasons",
        "requiredEvidence",
    ] {
        if let Some(array) = catalog.get(field).and_then(Value::as_array) {
            for item in array {
                if let Some(text) = item.as_str() {
                    if !safe_firmware_text_value(text)
                        && (prohibited_field(text) || prohibited_firmware_phrase(text).is_some())
                    {
                        errors.push(format!("{field} contains prohibited firmware field {text}"));
                    }
                }
            }
        }
    }
}

fn validate_no_unsafe_true_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if child == &Value::Bool(true) && unsafe_true_field(key) {
                    errors.push(format!("{path} has unsafe true flag {key}"));
                }
                validate_no_unsafe_true_values(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_unsafe_true_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        _ => {}
    }
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
        format!("{field} must be non-empty array"),
    );
    push_missing_unexpected("", field, &values, required_values, errors);
    expect(
        unique(&values),
        errors,
        format!("{field} values must be unique"),
    );
    values
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = object_array(
        catalog.get("rules"),
        "firmware compliance exception rule",
        errors,
    );
    let parsed = rule_records(&rules, "firmware compliance exception catalog", errors);
    let expected_ids = REQUIRED_RULES
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect::<Vec<_>>();
    let rule_ids = parsed
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    expect(
        unique(&rule_ids),
        errors,
        "firmware compliance exception rule IDs must be unique",
    );
    push_missing_unexpected(
        "firmware compliance exception",
        "rules",
        &rule_ids,
        &expected_ids,
        errors,
    );
    let details = parsed
        .iter()
        .map(|rule| format!("{}\n{}\n{}", rule.decision, rule.requirement, rule.evidence))
        .collect::<Vec<_>>();
    expect(
        unique(&details),
        errors,
        "firmware compliance exception rule details must be unique",
    );
    for (id, decision, requirement, evidence) in REQUIRED_RULES {
        let Some(rule) = parsed.iter().find(|candidate| candidate.id == *id) else {
            continue;
        };
        for (field, actual, expected) in [
            ("decision", rule.decision.as_str(), *decision),
            ("requirement", rule.requirement.as_str(), *requirement),
            ("evidence", rule.evidence.as_str(), *evidence),
        ] {
            expect(
                actual == expected,
                errors,
                format!("firmware compliance exception rule {id} {field} must match"),
            );
        }
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let endpoint = endpoint_block(&uncommented_program, errors);
    let block = endpoint_payload_block(&endpoint, errors);
    if block.is_empty() {
        return;
    }
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static seed source",
    );
    expect(
        exact_string_assignment(&block, "exceptionMode", "review-only"),
        errors,
        "API must keep review-only exception mode",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    for (field, message) in DISABLED_FIELDS {
        expect(exact_assignment(&block, field, "false"), errors, *message);
    }
    for (field, variable, required) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
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
    validate_endpoint_singleton_fields(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    let raw_endpoint = raw_endpoint_block(program);
    validate_csharp_comment_terms(
        &raw_endpoint,
        "firmwareComplianceExceptionEndpoint",
        false,
        errors,
    );
    validate_csharp_string_terms(
        &raw_endpoint,
        "firmwareComplianceExceptionEndpoint",
        false,
        errors,
    );
    scan_endpoint_string_values(&block, "firmwareComplianceExceptionEndpoint", errors);
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing firmware compliance exception endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors
            .push("API must expose exactly one firmware compliance exception endpoint".to_string());
        return String::new();
    }
    let start = starts[0];
    let next = next_map_get_index(program, start + 1).unwrap_or(program.len());
    program[start..next].to_string()
}

fn raw_endpoint_block(program: &str) -> String {
    let uncommented = csharp_without_comments(program);
    let starts = endpoint_start_indexes(&uncommented);
    let Some(start) = starts.first().copied() else {
        return String::new();
    };
    let next = next_map_get_index(&uncommented, start + 1).unwrap_or(program.len());
    program[start..next].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    line_start_indexes(program)
        .into_iter()
        .filter_map(|line_start| {
            let trimmed = skip_horizontal_whitespace(program, line_start);
            program[trimmed..]
                .starts_with(&format!("app.MapGet(\"{ENDPOINT}\","))
                .then_some(trimmed)
        })
        .collect()
}

fn next_map_get_index(program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let trimmed = skip_horizontal_whitespace(program, *line_start);
            program[trimmed..].starts_with("app.MapGet(")
        })
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    if endpoint.is_empty() {
        return String::new();
    }
    let all_json_indexes = results_json_indexes(endpoint, false);
    if all_json_indexes.len() > 1 {
        errors.push(
            "API must declare exactly one firmware compliance exception JSON payload".to_string(),
        );
        return String::new();
    }
    let json_indexes = results_json_indexes(endpoint, true);
    if json_indexes.is_empty() {
        if all_json_indexes.is_empty() {
            errors.push("API missing firmware compliance exception JSON payload".to_string());
        } else {
            errors.push(
                "API firmware compliance exception JSON payload must use anonymous Results.Json(new { ... })"
                    .to_string(),
            );
        }
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push(
            "API must declare exactly one firmware compliance exception JSON payload".to_string(),
        );
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push(
            "API firmware compliance exception JSON payload must be a single object".to_string(),
        );
        return String::new();
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push(
            "API firmware compliance exception JSON payload must be a single object".to_string(),
        );
        return String::new();
    };
    if endpoint[object_end + 1..].trim() != "));" {
        errors.push(
            "API firmware compliance exception JSON payload must be static anonymous object with no extra JSON arguments"
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
    csharp_array_literal_values(&bodies[0], &format!("API {field}"), errors)
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
        if !masked[..start].trim_end().ends_with("var") {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(&masked, end);
        if !is_assignment_operator(&masked, cursor) {
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
        if let Some(close) = matching_delimiter_index(&masked, cursor, b'{', b'}') {
            let semicolon = skip_ascii_whitespace(&masked, close + 1);
            if masked.as_bytes().get(semicolon) == Some(&b';') {
                bodies.push(program[cursor + 1..close].to_string());
            }
        }
    }
    bodies
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
    csharp_array_literal_values(
        &array_text[cursor + 1..close],
        &format!("API {field}"),
        errors,
    )
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
        format!("API {field} values must be unique"),
    );
}

fn validate_bound_array_immutable(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let masked = csharp_code_mask(program);
    let mut mutated = false;
    let aliases = bound_array_aliases(&masked, variable);
    for alias in &aliases {
        if identifier_mutated(&masked, alias) {
            mutated = true;
        }
    }
    let compact = without_ascii_whitespace(&masked);
    let mutation_methods = [
        "Array.Fill(",
        "Array.Sort(",
        "Array.Reverse(",
        "Array.Clear(",
        "Array.Resize(",
        "Array.Copy(",
        "Array.ConstrainedCopy(",
        "System.Array.Fill(",
        "System.Array.Sort(",
        "System.Array.Resize(",
        "System.Array.Copy(",
        "System.Array.ConstrainedCopy(",
        "global::System.Array.Fill(",
        "global::System.Array.Sort(",
        "global::System.Array.Resize(",
        "global::System.Array.Copy(",
        "global::System.Array.ConstrainedCopy(",
    ];
    for alias in &aliases {
        if compact.contains(&format!("{alias}.SetValue("))
            || compact.contains(&format!("{alias}.CopyTo("))
            || compact.contains(&format!("{alias}.AsSpan()["))
            || compact.contains(&format!("MemoryExtensions.AsSpan({alias})["))
            || compact.contains(&format!("System.MemoryExtensions.AsSpan({alias})["))
            || compact.contains(&format!("global::System.MemoryExtensions.AsSpan({alias})["))
            || (mutation_methods
                .iter()
                .any(|method| compact.contains(method))
                && compact.contains(alias))
        {
            mutated = true;
        }
    }
    if mutated {
        errors.push(format!(
            "API {field} bound array {variable} must not be mutated after declaration"
        ));
    }
}

fn bound_array_aliases(masked: &str, variable: &str) -> BTreeSet<String> {
    let mut aliases = BTreeSet::from([variable.to_string()]);
    let mut changed = true;
    while changed {
        changed = false;
        for (alias, source) in var_alias_assignments(masked) {
            if aliases.contains(&source) && aliases.insert(alias) {
                changed = true;
            }
        }
    }
    aliases
}

fn var_alias_assignments(masked: &str) -> Vec<(String, String)> {
    let mut assignments = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = masked[offset..].find("var") {
        let start = offset + relative;
        offset = start + "var".len();
        if !identifier_boundary(masked, start, start + "var".len()) {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(masked, start + "var".len());
        let Some((alias, alias_end)) = read_identifier(masked, cursor) else {
            continue;
        };
        cursor = skip_ascii_whitespace(masked, alias_end);
        if !is_assignment_operator(masked, cursor) {
            continue;
        }
        cursor = skip_ascii_whitespace(masked, cursor + 1);
        let Some((source, source_end)) = read_identifier(masked, cursor) else {
            continue;
        };
        cursor = skip_ascii_whitespace(masked, source_end);
        if masked.as_bytes().get(cursor) == Some(&b';') {
            assignments.push((alias, source));
        }
    }
    assignments
}

fn identifier_mutated(masked: &str, name: &str) -> bool {
    let mut offset = 0usize;
    while let Some(relative) = masked[offset..].find(name) {
        let start = offset + relative;
        let end = start + name.len();
        offset = end;
        if !identifier_boundary(masked, start, end) {
            continue;
        }
        let cursor = skip_ascii_whitespace(masked, end);
        if is_assignment_operator(masked, cursor) {
            if !masked[..start].trim_end().ends_with("var") {
                return true;
            }
        } else if masked.as_bytes().get(cursor) == Some(&b'[') {
            if let Some(close) = matching_delimiter_index(masked, cursor, b'[', b']') {
                if is_assignment_operator(masked, skip_ascii_whitespace(masked, close + 1)) {
                    return true;
                }
            }
        }
    }
    false
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = api_rule_objects(block, errors);
    let catalog_rules = object_array(
        catalog.get("rules"),
        "firmware compliance exception rule",
        errors,
    );
    let parsed_catalog = rule_records(
        &catalog_rules,
        "firmware compliance exception catalog",
        errors,
    );
    let catalog_rule_ids = parsed_catalog
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    let api_rule_ids = api_rules
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    for id in diff_values(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in diff_values(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(unique(&api_rule_ids), errors, "API rule IDs must be unique");
    let details = api_rules
        .iter()
        .map(|rule| format!("{}\n{}\n{}", rule.decision, rule.requirement, rule.evidence))
        .collect::<Vec<_>>();
    expect(unique(&details), errors, "API rule details must be unique");
    for catalog_rule in parsed_catalog {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            continue;
        };
        for (field, actual, expected) in [
            (
                "decision",
                api_rule.decision.as_str(),
                catalog_rule.decision.as_str(),
            ),
            (
                "requirement",
                api_rule.requirement.as_str(),
                catalog_rule.requirement.as_str(),
            ),
            (
                "evidence",
                api_rule.evidence.as_str(),
                catalog_rule.evidence.as_str(),
            ),
        ] {
            expect(
                actual == expected,
                errors,
                format!("API rule {} {field} must match catalog", catalog_rule.id),
            );
        }
    }
}

fn api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(array_body) = endpoint_rules_array_body(block, errors) else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    let mut ranges = Vec::new();
    let masked = csharp_code_mask(&array_body);
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("new") {
        let start = offset + relative;
        offset = start + "new".len();
        if !identifier_boundary(&masked, start, start + "new".len())
            || brace_depth_at(&masked, start) != 0
        {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, start + "new".len());
        if masked.as_bytes().get(cursor) != Some(&b'{') {
            continue;
        }
        let Some(close) = matching_delimiter_index(&masked, cursor, b'{', b'}') else {
            errors.push("API rules contain malformed object".to_string());
            return rules;
        };
        let object = &array_body[start..=close];
        ranges.push(start..=close);
        if let Some(rule) = parse_rule_object(object, "API rules", errors) {
            rules.push(rule);
        }
        offset = close + 1;
    }
    let mut leftover = array_body.clone();
    for range in ranges.into_iter().rev() {
        for index in range {
            leftover.replace_range(index..=index, " ");
        }
    }
    if !leftover.chars().all(|ch| ch.is_whitespace() || ch == ',') {
        errors.push("API rules contain non-literal or unexpected content".to_string());
    }
    rules
}

fn endpoint_rules_array_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let texts = top_level_assignment_texts(block, "rules");
    if texts.len() != 1 {
        errors.push("API rules must be a single literal rules array".to_string());
        return None;
    }
    if !texts[0].trim_start().starts_with("rules") && !texts[0].trim_start().starts_with("@rules") {
        errors.push("API rules must be a single literal rules array".to_string());
        return None;
    }
    let Some(assignment_index) = block.find(&texts[0]) else {
        errors.push("API rules must be a single literal rules array".to_string());
        return None;
    };
    let Some(rhs) = assignment_rhs(&texts[0], "rules") else {
        errors.push("API rules must be a single literal rules array".to_string());
        return None;
    };
    if rhs.trim() != "new[]" {
        errors.push("API rules must be a single literal rules array".to_string());
        return None;
    }
    let Some(array_start) = block[assignment_index + texts[0].len()..]
        .find('{')
        .map(|index| assignment_index + texts[0].len() + index)
    else {
        errors.push("API rules must be a single literal rules array".to_string());
        return None;
    };
    let Some(array_end) = matching_brace_index(block, array_start) else {
        errors.push("API rules must be a single literal rules array".to_string());
        return None;
    };
    let tail = block[array_end + 1..].trim_start();
    if !(tail.starts_with(',') || tail.starts_with('}')) {
        errors.push("API rules must be a single literal rules array".to_string());
        return None;
    }
    Some(block[array_start + 1..array_end].to_string())
}

fn parse_rule_object(object: &str, label: &str, errors: &mut Vec<String>) -> Option<Rule> {
    let Some(open) = object.find('{') else {
        errors.push(format!("{label} rules contain malformed object"));
        return None;
    };
    let Some(close) = matching_brace_index(object, open) else {
        errors.push(format!("{label} rules contain malformed object"));
        return None;
    };
    let body = &object[open + 1..close];
    let mut values = BTreeMap::new();
    for member in split_top_level(body, false) {
        let member = member.trim();
        if member.is_empty() {
            continue;
        }
        let Some((field, rhs)) = assignment_member(member) else {
            errors.push("API rules contain non-literal or unexpected content".to_string());
            continue;
        };
        if !RULE_FIELDS.contains(&field.as_str()) {
            errors.push(format!("{label} rule unexpected field {field}"));
            continue;
        }
        let Some(value) = exact_string_literal(rhs.trim()) else {
            errors.push("API rules contain non-literal or unexpected content".to_string());
            continue;
        };
        if values.insert(field, value).is_some() {
            errors.push(format!("{label} rule duplicate field"));
        }
    }
    for field in RULE_FIELDS {
        if !values.contains_key(*field) {
            errors.push(format!("{label} rule missing {field}"));
        }
    }
    Some(Rule {
        id: values.get("id").cloned().unwrap_or_default(),
        decision: values.get("decision").cloned().unwrap_or_default(),
        requirement: values.get("requirement").cloned().unwrap_or_default(),
        evidence: values.get("evidence").cloned().unwrap_or_default(),
    })
}

fn assignment_member(member: &str) -> Option<(String, &str)> {
    let mut cursor = skip_ascii_whitespace(member, 0);
    if member.as_bytes().get(cursor) == Some(&b'@') {
        cursor += 1;
    }
    if !member
        .as_bytes()
        .get(cursor)
        .is_some_and(|byte| is_ident_start(*byte))
    {
        return None;
    }
    let field_start = cursor;
    cursor += 1;
    while member
        .as_bytes()
        .get(cursor)
        .is_some_and(|byte| is_ident_char(*byte))
    {
        cursor += 1;
    }
    let field = member[field_start..cursor].to_string();
    cursor = skip_ascii_whitespace(member, cursor);
    if !is_assignment_operator(member, cursor) {
        return None;
    }
    Some((field, &member[cursor + 1..]))
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for (field, depth) in assignment_field_depths(block) {
        if depth > 1 && RULE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if depth == 1 && ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited firmware compliance exception field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected firmware compliance exception field {field}"
            ));
        }
    }
}

fn validate_endpoint_singleton_fields(block: &str, errors: &mut Vec<String>) {
    for field in SINGLETON_ENDPOINT_FIELDS {
        let count = top_level_assignment_texts(block, field).len();
        expect(
            count == 1,
            errors,
            format!("API endpoint field {field} must appear exactly once"),
        );
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, rhs_start) in assignment_rhs_indexes(block) {
        if field == "dryRunRequired" {
            continue;
        }
        let rhs = &block[rhs_start..];
        let trimmed = rhs.trim_start();
        if trimmed.starts_with("true")
            && identifier_boundary(trimmed, 0, "true".len())
            && (prohibited_field(&field) || unsafe_true_field(&field))
        {
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
        "API README missing firmware compliance exception endpoint",
    );
    expect(
        catalog_readme.contains("firmware-compliance-exception-contract.yaml"),
        errors,
        "catalog README missing firmware compliance exception catalog",
    );
    expect(
        doc_readme.contains("firmware-compliance-exception.md"),
        errors,
        "workflow README missing firmware compliance exception doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "firmware compliance exception doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "firmware compliance exception doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live firmware"),
        errors,
        "firmware compliance exception doc must prohibit live firmware work",
    );
    expect(
        doc.contains("No raw inventory rows."),
        errors,
        "firmware compliance exception doc must prohibit raw inventory rows",
    );
    expect(
        doc.contains("No host identifiers"),
        errors,
        "firmware compliance exception doc must prohibit host identifiers",
    );
    expect(
        doc.contains("dry-run review artifact"),
        errors,
        "firmware compliance exception doc must require dry-run review artifacts",
    );
    expect(
        doc.contains("firmware-safe exception summaries only"),
        errors,
        "firmware compliance exception doc must require safe summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let key_path = format!("{path}.{key}");
                if prohibited_structured_key(key) {
                    errors.push(format!("{key_path} contains prohibited value"));
                }
                scan_prohibited_value(child, &key_path, errors);
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
    if safe_firmware_text_value(text) {
        return;
    }
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
    if whole_file_text(path, text) {
        validate_markdown_terms(text, path, errors);
        if path.ends_with(".cs") {
            validate_csharp_comment_terms(text, path, true, errors);
            validate_csharp_string_terms(text, path, true, errors);
        }
        return;
    }
    validate_text_line_terms(text, path, errors);
    validate_key_like_terms(text, path, errors);
}

fn validate_raw_catalog_text(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        let label = format!("{path}:{}", index + 1);
        if prohibited_value(line) {
            errors.push(format!("{label} contains prohibited value"));
        }
        validate_key_like_terms(line, &label, errors);
        let Some(comment) = trimmed_comment_text(line) else {
            continue;
        };
        if safe_raw_catalog_comment(&comment) {
            continue;
        }
        let scanned = comment.trim_start_matches("- ").trim();
        validate_text_line_terms(scanned, &label, errors);
    }
}

fn validate_no_prohibited_test_literals(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if prohibited_value(line) {
            errors.push(format!(
                "{path}:{} contains prohibited test literal",
                index + 1
            ));
        }
    }
}

fn validate_markdown_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    if !path.ends_with(".md") {
        return;
    }
    for (index, line) in text.lines().enumerate() {
        if !firmware_markdown_line_scope(path, line) || safe_text_prohibition_line(line) {
            continue;
        }
        let label = format!("{path}:{}", index + 1);
        validate_text_line_terms(line, &label, errors);
        validate_key_like_terms(line, &label, errors);
    }
}

fn validate_csharp_comment_terms(text: &str, label: &str, scoped: bool, errors: &mut Vec<String>) {
    let lines = text.lines().collect::<Vec<_>>();
    let mut index = 0usize;
    while let Some(relative) = text[index..].find("/*") {
        let start = index + relative;
        let line_number = text[..start].bytes().filter(|byte| *byte == b'\n').count() + 1;
        let end = text[start + 2..]
            .find("*/")
            .map(|offset| start + 2 + offset)
            .unwrap_or(text.len());
        let end_line = text[..end].bytes().filter(|byte| *byte == b'\n').count() + 1;
        if !scoped || firmware_csharp_block_scope(&lines, line_number - 1, end_line - 1) {
            validate_text_line_terms(
                &text[start + 2..end],
                &format!("{label}:{line_number}"),
                errors,
            );
        }
        index = end.saturating_add(2).min(text.len());
    }
    for (line_index, line) in lines.iter().enumerate() {
        if scoped && !firmware_csharp_line_scope(&lines, line_index) {
            continue;
        }
        if let Some(comment_index) = line.find("//") {
            validate_text_line_terms(
                &line[comment_index + 2..],
                &format!("{label}:{}", line_index + 1),
                errors,
            );
        }
    }
}

fn validate_csharp_string_terms(text: &str, label: &str, scoped: bool, errors: &mut Vec<String>) {
    let lines = text.lines().collect::<Vec<_>>();
    for (line_index, line) in lines.iter().enumerate() {
        if scoped && !firmware_csharp_line_scope(&lines, line_index) {
            continue;
        }
        for literal in csharp_line_string_literals(line) {
            if !safe_firmware_text_value(&literal) {
                validate_text_line_terms(&literal, &format!("{label}:{}", line_index + 1), errors);
            }
        }
    }
}

fn scan_endpoint_string_values(block: &str, label: &str, errors: &mut Vec<String>) {
    for literal in csharp_line_string_literals(block) {
        if !safe_firmware_text_value(&literal) {
            validate_text_line_terms(&literal, label, errors);
        }
    }
}

fn validate_text_line_terms(text: &str, label: &str, errors: &mut Vec<String>) {
    if let Some(phrase) = prohibited_firmware_phrase(text) {
        let message = format!("{label} contains prohibited firmware phrase {phrase}");
        if !errors.contains(&message) {
            errors.push(message);
        }
    }
    for (term, _) in word_spans(text) {
        if prohibited_field(&term) {
            let message = format!("{label} contains prohibited firmware field {term}");
            if !errors.contains(&message) {
                errors.push(message);
            }
        }
    }
}

fn validate_key_like_terms(text: &str, label: &str, errors: &mut Vec<String>) {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphabetic() && bytes[index] != b'_' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            index += 1;
        }
        let field = &text[start..index];
        let cursor = skip_ascii_whitespace(text, index);
        if matches!(bytes.get(cursor), Some(b':' | b'=')) && prohibited_field(field) {
            let message = format!("{label} contains prohibited firmware field {field}");
            if !errors.contains(&message) {
                errors.push(message);
            }
        }
    }
}

fn rule_records(values: &[&Value], label: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let mut parsed = Vec::new();
    for value in values {
        let Some(map) = value.as_object() else {
            errors.push(format!("{label} rule must be object"));
            continue;
        };
        for key in map.keys() {
            if !RULE_FIELDS.contains(&key.as_str()) {
                errors.push(format!("{label} rule unexpected field {key}"));
            }
        }
        let id = string_value(value, "id").unwrap_or_default().to_string();
        for field in RULE_FIELDS {
            if !value.get(*field).is_some_and(Value::is_string) {
                let id_label = if id.is_empty() {
                    "unknown"
                } else {
                    id.as_str()
                };
                errors.push(format!("{label} rule {id_label} missing {field}"));
            }
        }
        parsed.push(Rule {
            id,
            decision: string_value(value, "decision")
                .unwrap_or_default()
                .to_string(),
            requirement: string_value(value, "requirement")
                .unwrap_or_default()
                .to_string(),
            evidence: string_value(value, "evidence")
                .unwrap_or_default()
                .to_string(),
        });
    }
    parsed
}

fn object_array<'a>(
    value: Option<&'a Value>,
    label: &str,
    errors: &mut Vec<String>,
) -> Vec<&'a Value> {
    let Some(array) = value.and_then(Value::as_array) else {
        errors.push(format!("{label} must be non-empty array"));
        return Vec::new();
    };
    expect(
        !array.is_empty(),
        errors,
        format!("{label} must be non-empty array"),
    );
    array
        .iter()
        .filter_map(|item| {
            if item.is_object() {
                Some(item)
            } else {
                errors.push(format!("{label} must be object"));
                None
            }
        })
        .collect()
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
    actual: &[String],
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let actual_set = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let required_set = required.iter().copied().collect::<BTreeSet<_>>();
    let missing = required
        .iter()
        .copied()
        .filter(|item| !actual_set.contains(item))
        .collect::<Vec<_>>();
    let unexpected = actual
        .iter()
        .map(String::as_str)
        .filter(|item| !required_set.contains(item))
        .collect::<Vec<_>>();
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

fn diff_values(left: &[String], right: &[String]) -> Vec<String> {
    let right_set = right.iter().map(String::as_str).collect::<BTreeSet<_>>();
    left.iter()
        .filter(|value| !right_set.contains(value.as_str()))
        .cloned()
        .collect()
}

fn unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1
        && assignment_rhs(&texts[0], field).is_some_and(|rhs| rhs.trim() == format!("{value},"))
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1
        && assignment_rhs(&texts[0], field).is_some_and(|rhs| rhs.trim() == format!("\"{value}\","))
}

fn exact_string_literal(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return None;
    }
    let mut value = String::new();
    let mut index = 1;
    while index + 1 < bytes.len() {
        if bytes[index] == b'\\' {
            index += 1;
            if index + 1 >= bytes.len() {
                return None;
            }
            value.push(bytes[index] as char);
        } else if bytes[index] == b'"' {
            return None;
        } else {
            value.push(bytes[index] as char);
        }
        index += 1;
    }
    Some(value)
}

fn assignment_rhs<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let mut cursor = skip_ascii_whitespace(line, 0);
    if line.as_bytes().get(cursor) == Some(&b'@') {
        cursor += 1;
    }
    if !line[cursor..].starts_with(field)
        || !identifier_boundary(line, cursor, cursor + field.len())
    {
        return None;
    }
    cursor = skip_ascii_whitespace(line, cursor + field.len());
    if !is_assignment_operator(line, cursor) {
        return None;
    }
    Some(&line[cursor + 1..])
}

fn top_level_assignment_texts(block: &str, field: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let mut texts = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find(field) {
        let start = offset + relative;
        let end = start + field.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) || brace_depth_at(&masked, start) != 1 {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, end);
        if !is_assignment_operator(&masked, cursor) {
            continue;
        }
        let line_start = masked[..start]
            .rfind('\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        let line_end = masked[start..]
            .find('\n')
            .map(|index| start + index)
            .unwrap_or(masked.len());
        texts.push(block[line_start..line_end].to_string());
    }
    texts
}

fn assignment_rhs_indexes(block: &str) -> Vec<(String, usize)> {
    assignment_rhs_entries(block)
        .into_iter()
        .map(|(field, rhs_start, _)| (field, rhs_start))
        .collect()
}

fn assignment_field_depths(block: &str) -> Vec<(String, i32)> {
    assignment_rhs_entries(block)
        .into_iter()
        .map(|(field, _, depth)| (field, depth))
        .collect()
}

fn assignment_rhs_entries(block: &str) -> Vec<(String, usize, i32)> {
    let masked = csharp_code_mask(block);
    let bytes = masked.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let mut field_start = index;
        if bytes[index] == b'@'
            && bytes
                .get(index + 1)
                .is_some_and(|byte| is_ident_start(*byte))
        {
            field_start = index + 1;
        } else if !is_ident_start(bytes[index]) {
            index += 1;
            continue;
        }
        let mut end = field_start + 1;
        while end < bytes.len() && is_ident_char(bytes[end]) {
            end += 1;
        }
        let cursor = skip_ascii_whitespace(&masked, end);
        if is_assignment_operator(&masked, cursor) {
            fields.push((
                masked[field_start..end].to_string(),
                cursor + 1,
                brace_depth_at(&masked, field_start),
            ));
        }
        index = end;
    }
    fields
}

fn csharp_array_literal_values(
    body: &str,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let bytes = body.as_bytes();
    let mut values = Vec::new();
    let mut cursor = 0;
    loop {
        cursor = skip_ascii_whitespace(body, cursor);
        while bytes.get(cursor) == Some(&b',') {
            cursor = skip_ascii_whitespace(body, cursor + 1);
        }
        if cursor >= bytes.len() {
            break;
        }
        if bytes[cursor] != b'"' {
            errors.push(format!("{label} array must contain only string literals"));
            return Some(values);
        }
        let start = cursor;
        cursor += 1;
        let mut value = String::new();
        let mut closed = false;
        while cursor < bytes.len() {
            if bytes[cursor] == b'\\' {
                cursor += 1;
                if cursor >= bytes.len() {
                    break;
                }
                value.push(bytes[cursor] as char);
            } else if bytes[cursor] == b'"' {
                cursor += 1;
                closed = true;
                break;
            } else {
                value.push(bytes[cursor] as char);
            }
            cursor += 1;
        }
        if !closed {
            errors.push(format!("{label} array has unterminated string literal"));
            return Some(values);
        }
        if !body[start..cursor].starts_with('"') {
            errors.push(format!("{label} array must contain only string literals"));
        }
        values.push(value);
        cursor = skip_ascii_whitespace(body, cursor);
        if cursor < bytes.len() && bytes[cursor] != b',' {
            errors.push(format!("{label} array must contain only string literals"));
            return Some(values);
        }
    }
    Some(values)
}

fn csharp_without_comments(text: &str) -> String {
    mask_csharp(text, false)
}

fn csharp_code_mask(text: &str) -> String {
    mask_csharp(text, true)
}

fn mask_csharp(text: &str, mask_strings: bool) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            output.push(' ');
            output.push(' ');
            index += 2;
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
        } else if bytes.get(index..index + 3) == Some(br#"""""#) {
            let finish = raw_string_end(text, index);
            while index < finish {
                output.push(if mask_strings {
                    if bytes[index] == b'\n' {
                        '\n'
                    } else {
                        ' '
                    }
                } else {
                    bytes[index] as char
                });
                index += 1;
            }
        } else if bytes[index] == b'"' {
            output.push(if mask_strings { ' ' } else { '"' });
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    output.push(if mask_strings { ' ' } else { '\\' });
                    index += 1;
                    if index < bytes.len() {
                        output.push(if mask_strings {
                            ' '
                        } else {
                            bytes[index] as char
                        });
                        index += 1;
                    }
                } else if bytes[index] == b'"' {
                    output.push(if mask_strings { ' ' } else { '"' });
                    index += 1;
                    break;
                } else {
                    output.push(if mask_strings {
                        if bytes[index] == b'\n' {
                            '\n'
                        } else {
                            ' '
                        }
                    } else {
                        bytes[index] as char
                    });
                    index += 1;
                }
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let masked = csharp_code_mask(text);
    matching_delimiter_index(&masked, open_index, b'{', b'}')
}

fn matching_delimiter_index(text: &str, open_index: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open_index) != Some(&open) {
        return None;
    }
    let mut depth = 0;
    for (index, byte) in bytes.iter().enumerate().skip(open_index) {
        if *byte == open {
            depth += 1;
        } else if *byte == close {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn brace_depth_at(text: &str, index: usize) -> i32 {
    let mut depth = 0;
    for byte in text[..index].bytes() {
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
        }
    }
    depth
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    for (index, byte) in text.bytes().enumerate() {
        if byte == b'\n' && index + 1 < text.len() {
            indexes.push(index + 1);
        }
    }
    indexes
}

fn skip_horizontal_whitespace(text: &str, mut cursor: usize) -> usize {
    while matches!(text.as_bytes().get(cursor), Some(b' ' | b'\t')) {
        cursor += 1;
    }
    cursor
}

fn skip_ascii_whitespace(text: &str, mut cursor: usize) -> usize {
    while text
        .as_bytes()
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    cursor
}

fn without_ascii_whitespace(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
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

fn is_assignment_operator(text: &str, cursor: usize) -> bool {
    let bytes = text.as_bytes();
    bytes.get(cursor) == Some(&b'=')
        && bytes.get(cursor + 1) != Some(&b'=')
        && !matches!(
            cursor.checked_sub(1).and_then(|index| bytes.get(index)),
            Some(b'!' | b'<' | b'>' | b'=')
        )
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    let before = start == 0 || !is_ident_char(bytes[start - 1]);
    let after = end >= bytes.len() || !is_ident_char(bytes[end]);
    before && after
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn read_identifier(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if !bytes.get(start).is_some_and(|byte| is_ident_start(*byte)) {
        return None;
    }
    let mut end = start + 1;
    while bytes.get(end).is_some_and(|byte| is_ident_char(*byte)) {
        end += 1;
    }
    Some((text[start..end].to_string(), end))
}

fn prohibited_structured_key(key: &str) -> bool {
    if safe_structured_key(key) {
        return false;
    }
    prohibited_field(key)
}

fn safe_structured_key(key: &str) -> bool {
    SAFE_STRUCTURED_KEYS.contains(&key)
        || SINGLETON_ENDPOINT_FIELDS.contains(&key)
        || REQUIRED_PROFILES.contains(&key)
        || REQUIRED_EXCEPTION_TYPES.contains(&key)
        || REQUIRED_RISK_LEVELS.contains(&key)
        || REQUIRED_INPUTS.contains(&key)
        || REQUIRED_GUARDS.contains(&key)
        || REQUIRED_PLAN_SECTIONS.contains(&key)
        || REQUIRED_BLOCKED_REASONS.contains(&key)
        || REQUIRED_EVIDENCE.contains(&key)
        || REQUIRED_RULES.iter().any(|(id, _, _, _)| key == *id)
        || matches!(key, "version" | "status")
}

fn prohibited_field(field: &str) -> bool {
    if safe_firmware_text_value(field) {
        return false;
    }
    let normalized = normalized_key(field);
    if safe_firmware_guard_key(&normalized) {
        return false;
    }
    PROHIBITED_FIELD_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
}

fn unsafe_true_field(field: &str) -> bool {
    let normalized = normalized_key(field);
    UNSAFE_TRUE_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn prohibited_value(text: &str) -> bool {
    contains_akia_key(text)
        || contains_private_key_marker(text)
        || contains_url(text)
        || contains_email(text)
        || contains_private_ip(text)
        || contains_uuid(text)
        || contains_firmware_version(text)
        || contains_serial_like(text)
        || contains_asset_like(text)
        || contains_host_token(text)
        || contains_sensitive_assignment(text)
}

fn safe_firmware_text_value(value: &str) -> bool {
    REQUIRED_PROFILES.contains(&value)
        || REQUIRED_EXCEPTION_TYPES.contains(&value)
        || REQUIRED_RISK_LEVELS.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_RULES
            .iter()
            .any(|(id, decision, requirement, evidence)| {
                value == *id || value == *decision || value == *requirement || value == *evidence
            })
        || matches!(value, "draft" | "static-seed" | "review-only" | "block")
}

fn safe_firmware_guard_key(normalized: &str) -> bool {
    matches!(
        normalized,
        "providercallsenabled"
            | "livefirmwarechangesallowed"
            | "rawinventoryrowsallowed"
            | "hostidentifiersallowed"
            | "serialnumbersallowed"
            | "exactfirmwareversionsallowed"
            | "rawvendorpayloadsallowed"
            | "hostidentifiersdisabled"
            | "serialnumbersdisabled"
            | "exactfirmwareversionsdisabled"
            | "rawvendorpayloadsdisabled"
            | "rawinventoryrowsdisabled"
    )
}

fn prohibited_firmware_phrase(text: &str) -> Option<String> {
    for phrase in PROHIBITED_PHRASES {
        if let Some(found) = find_phrase(text, phrase) {
            return Some(found);
        }
    }
    None
}

const PROHIBITED_PHRASES: &[&str] = &[
    "raw vendor payload",
    "vendor payload",
    "vendor payloads",
    "provider payload",
    "raw vendor output",
    "vendor output",
    "provider output",
    "vendor log",
    "vendor report",
    "tenant ID",
    "tenant IDs",
    "tenant identifier",
    "tenant identifiers",
    "object ID",
    "object IDs",
    "object identifier",
    "object identifiers",
    "private IP",
    "private IPs",
    "private network details",
    "raw firmware inventory",
    "raw hardware inventory rows",
    "raw hardware inventory",
    "raw inventory rows",
    "raw host rows",
    "raw logs",
    "itemized hardware detail",
    "exact observed firmware versions",
    "observed firmware version",
    "observed firmware versions",
    "firmware version",
    "firmware versions",
    "host name",
    "host names",
    "host ID",
    "host IDs",
    "host identifier",
    "host identifiers",
    "user name",
    "user names",
    "serial number",
    "serial numbers",
    "asset identifier",
    "asset identifiers",
    "asset tag",
    "asset tags",
    "raw provider response",
    "vendor API output",
    "provider API output",
    "inventory export",
    "inventory record",
    "inventory data",
];

fn find_phrase(text: &str, phrase: &str) -> Option<String> {
    let tokens = word_spans(text);
    let words = phrase
        .split_whitespace()
        .map(|word| word.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if words.is_empty() || tokens.len() < words.len() {
        return None;
    }
    for window_start in 0..=tokens.len() - words.len() {
        let matched = words
            .iter()
            .enumerate()
            .all(|(offset, word)| tokens[window_start + offset].0.to_ascii_lowercase() == *word);
        if matched {
            let start = tokens[window_start].1 .0;
            let end = tokens[window_start + words.len() - 1].1 .1;
            return Some(text[start..end].to_string());
        }
    }
    None
}

fn word_spans(text: &str) -> Vec<(String, (usize, usize))> {
    let bytes = text.as_bytes();
    let mut words = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        while bytes
            .get(index)
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let start = index;
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        {
            index += 1;
        }
        words.push((text[start..index].to_string(), (start, index)));
    }
    words
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn firmware_markdown_line_scope(path: &str, line: &str) -> bool {
    path.ends_with(DOC_PATH) || line.to_ascii_lowercase().contains("firmware")
}

fn firmware_csharp_line_scope(lines: &[&str], index: usize) -> bool {
    let start = index.saturating_sub(1);
    let end = (index + 1).min(lines.len().saturating_sub(1));
    (start..=end).any(|candidate| lines[candidate].contains("firmwareCompliance"))
}

fn firmware_csharp_block_scope(lines: &[&str], start_index: usize, end_index: usize) -> bool {
    let start = start_index.saturating_sub(1);
    let end = (end_index + 1).min(lines.len().saturating_sub(1));
    (start..=end).any(|candidate| lines[candidate].contains("firmwareCompliance"))
}

fn safe_text_prohibition_line(line: &str) -> bool {
    matches!(
        line.trim(),
        "- No raw inventory rows."
            | "- No host identifiers, serial numbers, asset tags, endpoint names, usernames, credentials, tokens, tenant identifiers, object identifiers, private network details, exact observed firmware versions, raw logs, or vendor payloads in committed files."
    )
}

fn trimmed_comment_text(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    trimmed
        .strip_prefix('#')
        .map(|comment| comment.trim_start().to_string())
}

fn safe_raw_catalog_comment(comment: &str) -> bool {
    comment == "Firmware compliance exception seed data only. Do not add hostnames, usernames, credentials, tokens, tenant IDs, object IDs, endpoint names, private IPs, raw hardware inventory rows, exact observed firmware versions, serial numbers, asset tags, raw logs, or vendor payloads."
}

fn csharp_line_string_literals(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        if bytes.get(index..index + 3) == Some(br#"""""#) {
            let finish = raw_string_end(line, index);
            if finish >= index + 6 {
                literals.push(line[index + 3..finish.saturating_sub(3)].to_string());
            }
            index = finish;
            continue;
        }
        index += 1;
        let mut value = String::new();
        while index < bytes.len() {
            if bytes[index] == b'\\' {
                index += 1;
                if index < bytes.len() {
                    value.push(bytes[index] as char);
                    index += 1;
                }
            } else if bytes[index] == b'"' {
                index += 1;
                literals.push(value);
                break;
            } else {
                value.push(bytes[index] as char);
                index += 1;
            }
        }
    }
    literals
}

fn raw_string_end(text: &str, start: usize) -> usize {
    text[start + 3..]
        .find(r#"""""#)
        .map(|offset| start + 3 + offset + 3)
        .unwrap_or(text.len())
}

fn contains_akia_key(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut offset = 0;
    while let Some(relative) = upper[offset..].find("AKIA") {
        let start = offset + relative;
        let end = start + 20;
        if end <= bytes.len()
            && bytes[start + 4..end]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return true;
        }
        offset = start + 4;
    }
    false
}

fn contains_private_key_marker(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

fn contains_url(text: &str) -> bool {
    text.find("://").is_some_and(|index| {
        text[..index]
            .chars()
            .rev()
            .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
            .last()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
    })
}

fn contains_email(text: &str) -> bool {
    text.split(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                ',' | ';' | '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']'
            )
    })
    .any(|token| {
        let token = token.trim_matches(|ch: char| matches!(ch, '.' | ':' | '!' | '?'));
        let Some(at) = token.find('@') else {
            return false;
        };
        at > 0 && token[at + 1..].contains('.') && token[at + 1..].len() > 3
    })
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .filter(|token| token.matches('.').count() == 3)
        .any(|token| {
            let octets = token
                .split('.')
                .filter_map(|part| part.parse::<u8>().ok())
                .collect::<Vec<_>>();
            octets.len() == 4
                && (octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1])))
        })
}

fn contains_uuid(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(|token| {
            token.len() == 36
                && token.chars().enumerate().all(|(index, ch)| match index {
                    8 | 13 | 18 | 23 => ch == '-',
                    _ => ch.is_ascii_hexdigit(),
                })
        })
}

fn contains_firmware_version(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|token| {
            let parts = token.split('.').collect::<Vec<_>>();
            (2..=3).contains(&parts.len())
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
        })
}

fn contains_serial_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')))
        .any(|token| {
            let lower = token.to_ascii_lowercase();
            lower.starts_with("sn")
                && token.len() >= 5
                && token.chars().any(|ch| ch.is_ascii_digit())
        })
}

fn contains_asset_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')))
        .any(|token| {
            let lower = token.to_ascii_lowercase();
            lower.starts_with("asset")
                && token.len() >= 8
                && token.chars().any(|ch| ch.is_ascii_digit())
        })
}

fn contains_host_token(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
        .any(|token| {
            let lower = token.to_ascii_lowercase();
            (lower.starts_with("esx") || lower.starts_with("esxi") || lower.starts_with("host"))
                && token.chars().any(|ch| ch.is_ascii_digit())
                && token.len() >= 4
        })
}

fn contains_sensitive_assignment(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for keyword in [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ] {
        let mut offset = 0;
        while let Some(relative) = lower[offset..].find(keyword) {
            let start = offset + relative;
            let mut cursor = start + keyword.len();
            cursor = skip_ascii_whitespace(&lower, cursor);
            if matches!(lower.as_bytes().get(cursor), Some(b':' | b'=')) {
                cursor = skip_ascii_whitespace(&lower, cursor + 1);
                if lower
                    .as_bytes()
                    .get(cursor)
                    .is_some_and(|byte| !byte.is_ascii_whitespace())
                {
                    return true;
                }
            }
            offset = start + keyword.len();
        }
    }
    false
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
