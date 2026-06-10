use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/hardware-lifecycle-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/hardware-lifecycle.md";
const ENDPOINT: &str = "/api/operations/hardware-lifecycle-contract";

const REQUIRED_PROFILES: &[&str] = &[
    "hpe-dl360-msa",
    "hpe-simplivity-dl380",
    "lenovo-sr",
    "lenovo-vx",
    "lenovo-mx",
];
const REQUIRED_STATES: &[&str] = &[
    "planned",
    "ordered",
    "received",
    "staged",
    "in-service",
    "maintenance",
    "refresh-planned",
    "decommissioned",
];
const REQUIRED_INPUTS: &[&str] = &[
    "hardwareProfile",
    "lifecycleState",
    "site",
    "owner",
    "capacityRole",
    "supportStatus",
    "firmwareBaseline",
    "refreshWindow",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "model-known",
    "site-known",
    "support-status-known",
    "firmware-baseline-known",
    "capacity-role-known",
    "cmdb-owner-known",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "hardwareSummary",
    "lifecycleState",
    "sitePlacement",
    "firmwareAndSupport",
    "capacityRole",
    "riskNotes",
    "refreshPlan",
    "handoverNotes",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "model-unknown",
    "site-unknown",
    "support-status-unknown",
    "firmware-baseline-unknown",
    "capacity-role-unknown",
    "support-risk",
    "cmdb-owner-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Hardware lifecycle summary",
    "Site placement",
    "Support status",
    "Firmware baseline",
    "Capacity role",
    "Refresh decision",
    "Risk notes",
    "Evidence references",
];
const REQUIRED_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-hardware-actions",
        "block",
        "Hardware lifecycle contracts track metadata only and never execute vendor, out-of-band, storage, or cluster actions.",
        "Hardware lifecycle summary",
    ),
    (
        "no-serial-or-asset-identifiers",
        "block",
        "Committed hardware lifecycle metadata must not contain serial numbers, asset tags, or device identifiers.",
        "Hardware lifecycle summary",
    ),
    (
        "support-and-firmware-required",
        "block",
        "Support status and the approved N-1 firmware baseline strategy must be known before operational changes can be considered.",
        "Firmware baseline",
    ),
    (
        "refresh-risk-review-required",
        "block",
        "Hardware with support or capacity risk needs refresh review and owner evidence.",
        "Refresh decision",
    ),
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "serialNumbersAllowed",
];
const FIRMWARE_STRATEGY_FIELDS: &[&str] = &[
    "releaseTrainPolicy",
    "baselineReleaseTrain",
    "exactFirmwareVersionsAllowed",
    "liveProviderLookupsAllowed",
    "rawInventoryAllowed",
    "providerDataAllowed",
    "vendorRecommendationSets",
];
const VENDOR_RECOMMENDATION_FIELDS: &[&str] = &["appliesToProfiles", "recommendationSet"];
const HPE_RECOMMENDATION_SET: &[&str] = &[
    "prior-applicable-hpe-spp",
    "prior-applicable-hpe-msa",
    "prior-applicable-hpe-simplivity",
];
const LENOVO_RECOMMENDATION_SET: &[&str] = &[
    "prior-recommended-lenovo-sr-recipe",
    "prior-recommended-lenovo-vx-recipe",
    "prior-recommended-lenovo-mx-recipe",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "supportedProfiles",
        "hardwareLifecycleProfiles",
        REQUIRED_PROFILES,
    ),
    (
        "lifecycleStates",
        "hardwareLifecycleStates",
        REQUIRED_STATES,
    ),
    (
        "requiredGuards",
        "hardwareLifecycleRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "blockedReasons",
        "hardwareLifecycleBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("planSections", REQUIRED_PLAN_SECTIONS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "lifecycleMode",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "serialNumbersAllowed",
    "supportedProfiles",
    "lifecycleStates",
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
    "lifecycleMode",
    "providerCallsEnabled",
    "liveExecutionAllowed",
    "serialNumbersAllowed",
    "firmwareBaselineStrategy",
    "releaseTrainPolicy",
    "baselineReleaseTrain",
    "exactFirmwareVersionsAllowed",
    "liveProviderLookupsAllowed",
    "rawInventoryAllowed",
    "providerDataAllowed",
    "vendorRecommendationSets",
    "hpe",
    "lenovo",
    "appliesToProfiles",
    "recommendationSet",
    "supportedProfiles",
    "lifecycleStates",
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
const PROHIBITED_KEY_TOKENS: &[&str] = &[
    "hostname",
    "hostnames",
    "username",
    "usernames",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "endpointname",
    "endpointurl",
    "liveendpoint",
    "targeturl",
    "privateip",
    "privatenetwork",
    "credential",
    "secret",
    "token",
    "password",
    "bearer",
    "serialnumber",
    "serialnumbers",
    "assettag",
    "assettags",
    "deviceidentifier",
    "deviceidentifiers",
    "rawrow",
    "rawrows",
    "rawinventory",
    "rawpayload",
    "vendorpayload",
    "providerpayload",
    "recipientdata",
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ContextInput = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid hardware lifecycle context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_value(
        &Value::String(serde_json::to_string(&context.catalog).unwrap_or_default()),
        CATALOG_PATH,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.program), PROGRAM_PATH, &mut errors);
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
        .map_err(|error| format!("invalid hardware lifecycle catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid hardware lifecycle program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid hardware lifecycle docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid hardware lifecycle prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("hardware lifecycle catalog must be a mapping".to_string());
        return;
    }
    expect(
        value_i64(catalog, "version") == Some(1),
        errors,
        "hardware lifecycle version must be 1",
    );
    expect(
        value_str(catalog, "status") == Some("draft"),
        errors,
        "hardware lifecycle status must be draft",
    );
    expect(
        value_str(catalog, "source") == Some("static-seed"),
        errors,
        "hardware lifecycle catalog must keep static-seed source",
    );
    expect(
        value_str(catalog, "lifecycleMode") == Some("metadata-only"),
        errors,
        "hardware lifecycle mode must be metadata-only",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            value_bool(catalog, field) == Some(false),
            errors,
            &format!("hardware lifecycle {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "supportedProfiles", REQUIRED_PROFILES, errors);
    validate_required_array(catalog, "lifecycleStates", REQUIRED_STATES, errors);
    validate_firmware_baseline_strategy(catalog.get("firmwareBaselineStrategy"), errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_catalog_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array(catalog.get(field));
    expect(
        !values.is_empty(),
        errors,
        &format!("{field} must be non-empty array"),
    );
    let required = required_values
        .iter()
        .map(|value| value.to_string())
        .collect::<BTreeSet<_>>();
    let actual = values.iter().cloned().collect::<BTreeSet<_>>();
    let missing = required.difference(&actual).cloned().collect::<Vec<_>>();
    let unexpected = actual.difference(&required).cloned().collect::<Vec<_>>();
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
        values.len() == actual.len(),
        errors,
        &format!("{field} values must be unique"),
    );
}

fn validate_firmware_baseline_strategy(strategy: Option<&Value>, errors: &mut Vec<String>) {
    let Some(strategy) = strategy.and_then(Value::as_object) else {
        errors.push("firmwareBaselineStrategy must declare the approved N-1 policy".to_string());
        return;
    };
    let keys = strategy.keys().map(String::as_str).collect::<Vec<_>>();
    for field in FIRMWARE_STRATEGY_FIELDS {
        if !keys.contains(field) {
            errors.push(format!("firmwareBaselineStrategy missing fields: {field}"));
        }
    }
    let unexpected = keys
        .iter()
        .filter(|key| !FIRMWARE_STRATEGY_FIELDS.contains(key))
        .copied()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        errors.push(format!(
            "firmwareBaselineStrategy has unexpected fields; exact firmware versions are not allowed: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        strategy.get("releaseTrainPolicy").and_then(Value::as_str)
            == Some("prior-vendor-recommended-release-train"),
        errors,
        "firmwareBaselineStrategy releaseTrainPolicy must match approved N-1 policy",
    );
    expect(
        strategy.get("baselineReleaseTrain").and_then(Value::as_str) == Some("n-1"),
        errors,
        "firmwareBaselineStrategy baselineReleaseTrain must match approved N-1 policy",
    );
    for field in [
        "exactFirmwareVersionsAllowed",
        "liveProviderLookupsAllowed",
        "rawInventoryAllowed",
        "providerDataAllowed",
    ] {
        expect(
            strategy.get(field).and_then(Value::as_bool) == Some(false),
            errors,
            &format!(
                "firmwareBaselineStrategy {field} must be false; exact firmware versions and live provider data are not allowed"
            ),
        );
    }
    let Some(sets) = strategy
        .get("vendorRecommendationSets")
        .and_then(Value::as_object)
    else {
        errors.push(
            "firmwareBaselineStrategy vendorRecommendationSets must declare HPE and Lenovo profiles"
                .to_string(),
        );
        return;
    };
    for vendor in ["hpe", "lenovo"] {
        if !sets.contains_key(vendor) {
            errors.push(format!(
                "firmwareBaselineStrategy missing vendor recommendation sets: {vendor}"
            ));
        }
    }
    for vendor in sets.keys() {
        if !["hpe", "lenovo"].contains(&vendor.as_str()) {
            errors.push(format!(
                "firmwareBaselineStrategy unexpected vendor recommendation sets: {vendor}"
            ));
        }
    }
    validate_vendor_recommendation_set(
        sets.get("hpe"),
        REQUIRED_PROFILES[..2].to_vec().as_slice(),
        HPE_RECOMMENDATION_SET,
        "HPE",
        errors,
    );
    validate_vendor_recommendation_set(
        sets.get("lenovo"),
        REQUIRED_PROFILES[2..].to_vec().as_slice(),
        LENOVO_RECOMMENDATION_SET,
        "Lenovo",
        errors,
    );
}

fn validate_vendor_recommendation_set(
    actual: Option<&Value>,
    profiles: &[&str],
    recommendations: &[&str],
    label: &str,
    errors: &mut Vec<String>,
) {
    let Some(actual) = actual.and_then(Value::as_object) else {
        errors.push(format!(
            "firmwareBaselineStrategy {label} recommendation set must be declared"
        ));
        return;
    };
    for field in actual.keys() {
        if !VENDOR_RECOMMENDATION_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "firmwareBaselineStrategy {label} has unexpected fields: {field}"
            ));
        }
    }
    for field in VENDOR_RECOMMENDATION_FIELDS {
        if !actual.contains_key(*field) {
            errors.push(format!(
                "firmwareBaselineStrategy {label} missing fields: {field}"
            ));
        }
    }
    let actual_profiles = string_array(actual.get("appliesToProfiles"));
    let expected_profiles = profiles
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    expect(
        actual_profiles == expected_profiles,
        errors,
        &format!("firmwareBaselineStrategy {label} profiles must match approved N-1 policy"),
    );
    let actual_recommendations = string_array(actual.get("recommendationSet"));
    let expected_recommendations = recommendations
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    expect(
        actual_recommendations == expected_recommendations,
        errors,
        &format!(
            "firmwareBaselineStrategy {label} recommendation set must match approved N-1 policy"
        ),
    );
}

fn validate_catalog_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rule_ids = rules
        .iter()
        .filter_map(|rule| value_str_direct(rule, "id").map(str::to_string))
        .collect::<Vec<_>>();
    let required_ids = REQUIRED_RULES
        .iter()
        .map(|(id, _, _, _)| (*id).to_string())
        .collect::<BTreeSet<_>>();
    let actual_ids = rule_ids.iter().cloned().collect::<BTreeSet<_>>();
    let missing = required_ids
        .difference(&actual_ids)
        .cloned()
        .collect::<Vec<_>>();
    let unexpected = actual_ids
        .difference(&required_ids)
        .cloned()
        .collect::<Vec<_>>();
    expect(
        rule_ids.len() == actual_ids.len(),
        errors,
        "hardware lifecycle rule IDs must be unique",
    );
    let rule_details = rules
        .iter()
        .filter_map(|rule| {
            Some((
                value_str_direct(rule, "requirement")?.to_string(),
                value_str_direct(rule, "evidence")?.to_string(),
            ))
        })
        .collect::<Vec<_>>();
    let detail_set = rule_details.iter().cloned().collect::<BTreeSet<_>>();
    expect(
        rule_details.len() == detail_set.len(),
        errors,
        "hardware lifecycle rule details must be unique",
    );
    if !missing.is_empty() {
        errors.push(format!(
            "hardware lifecycle missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "hardware lifecycle unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    for (id, decision, requirement, evidence) in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| value_str_direct(candidate, "id") == Some(*id))
        else {
            continue;
        };
        for (field, expected) in [
            ("decision", *decision),
            ("requirement", *requirement),
            ("evidence", *evidence),
        ] {
            expect(
                value_str_direct(rule, field) == Some(expected),
                errors,
                &format!("hardware lifecycle rule {id} {field} must match"),
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

    validate_endpoint_assignment_counts(&block, errors);
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "lifecycleMode", "metadata-only"),
        errors,
        "API must keep metadata-only lifecycle mode",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            &format!("API must keep {field} disabled"),
        );
    }
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
    validate_endpoint_property_identifiers(&block, errors);
}

fn validate_endpoint_assignment_counts(block: &str, errors: &mut Vec<String>) {
    for field in ALLOWED_ENDPOINT_FIELDS {
        if top_level_assignment_indexes(block, field).len() > 1 {
            errors.push(format!("API {field} must be declared once"));
        }
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing hardware lifecycle endpoint".to_string());
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
    let aliases = endpoint_route_aliases(program);
    line_start_indexes(program)
        .into_iter()
        .filter_map(|line_start| {
            let start = line_start + skip_horizontal_whitespace(&program[line_start..], 0);
            endpoint_registration_at(program, start, &aliases).then_some(start)
        })
        .collect()
}

fn endpoint_route_aliases(program: &str) -> Vec<String> {
    program
        .lines()
        .filter_map(|line| {
            if !line.contains(ENDPOINT) || !line.contains('=') || !line.trim_end().ends_with(';') {
                return None;
            }
            let (lhs, rhs) = line.split_once('=')?;
            if !rhs.contains(&format!("\"{ENDPOINT}\"")) {
                return None;
            }
            let name = last_identifier(lhs)?;
            (lhs.contains("string") || lhs.contains("var")).then_some(name)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn endpoint_registration_at(program: &str, start: usize, aliases: &[String]) -> bool {
    let Some(mut cursor) = parse_map_get(program, start) else {
        return false;
    };
    cursor = skip_ascii_whitespace(program, cursor + 1);
    let endpoint_literal = format!("\"{ENDPOINT}\"");
    if program[cursor..].starts_with(&endpoint_literal) {
        cursor = skip_ascii_whitespace(program, cursor + endpoint_literal.len());
        return program.as_bytes().get(cursor) == Some(&b',');
    }
    for alias in aliases {
        if program[cursor..].starts_with(alias)
            && identifier_boundary(program, cursor, cursor + alias.len())
        {
            cursor = skip_ascii_whitespace(program, cursor + alias.len());
            return program.as_bytes().get(cursor) == Some(&b',');
        }
    }
    false
}

fn next_map_get_index(program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let start = *line_start + skip_horizontal_whitespace(&program[*line_start..], 0);
            parse_map_get(program, start).is_some()
        })
}

fn parse_map_get(program: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    if !program[cursor..].starts_with("app") || !identifier_boundary(program, cursor, cursor + 3) {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + 3);
    if program.as_bytes().get(cursor) != Some(&b'.') {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + 1);
    if !program[cursor..].starts_with("MapGet")
        || !identifier_boundary(program, cursor, cursor + "MapGet".len())
    {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + "MapGet".len());
    (program.as_bytes().get(cursor) == Some(&b'(')).then_some(cursor)
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> String {
    let json_indexes = results_json_indexes(endpoint);
    if json_indexes.is_empty() {
        errors.push("API missing hardware lifecycle JSON payload".to_string());
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push("API must declare exactly one hardware lifecycle JSON payload".to_string());
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push("API hardware lifecycle JSON payload must be a single object".to_string());
        return String::new();
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API hardware lifecycle JSON payload must be a single object".to_string());
        return String::new();
    };
    endpoint[object_start..=object_end].to_string()
}

fn results_json_indexes(endpoint: &str) -> Vec<usize> {
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
    let declarations = csharp_array_declarations(program, variable);
    if declarations.is_empty() {
        return None;
    }
    if declarations.len() != 1 {
        errors.push(format!(
            "API {field} array must have exactly one literal declaration"
        ));
        return None;
    }
    Some(csharp_array_literal_values(
        &declarations[0].body,
        &format!("API {field}"),
        errors,
    ))
}

struct ArrayDeclaration {
    body: String,
    end: usize,
}

fn csharp_array_declarations(program: &str, variable: &str) -> Vec<ArrayDeclaration> {
    let masked = csharp_code_mask(program);
    let mut declarations = Vec::new();
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
        let Some(close) = matching_brace_index(program, cursor) else {
            continue;
        };
        let semicolon = skip_ascii_whitespace(&masked, close + 1);
        if masked.as_bytes().get(semicolon) == Some(&b';') {
            declarations.push(ArrayDeclaration {
                body: program[cursor + 1..close].to_string(),
                end: semicolon + 1,
            });
        }
    }
    declarations
}

fn validate_bound_array_immutable(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let declarations = csharp_array_declarations(program, variable);
    let Some(declaration) = declarations.first() else {
        return;
    };
    let endpoint_start = endpoint_start_indexes(program)
        .into_iter()
        .next()
        .unwrap_or(program.len());
    if endpoint_start <= declaration.end {
        return;
    }
    let app_run = find_app_run(program, endpoint_start + 1).unwrap_or(program.len());
    let scan = &program[declaration.end..app_run];
    let compact = strip_ascii_whitespace(&csharp_code_mask(scan));
    let aliases = tracked_aliases(scan, variable);
    let mut mutated = false;
    let mut reassigned = false;
    for alias in aliases {
        if compact_contains_assignment(&compact, &alias) && alias == variable {
            reassigned = true;
        }
        if compact_contains_mutation(&compact, &alias) {
            mutated = true;
        }
    }
    if reassigned || mutated {
        errors.push(format!(
            "API {field} static array variable {variable} must remain immutable before endpoint use"
        ));
    }
}

fn find_app_run(program: &str, offset: usize) -> Option<usize> {
    line_start_indexes(&program[offset..])
        .into_iter()
        .map(|index| offset + index)
        .find(|line_start| {
            let start = *line_start + skip_horizontal_whitespace(&program[*line_start..], 0);
            program[start..].starts_with("app.Run")
        })
}

fn tracked_aliases(scan: &str, variable: &str) -> BTreeSet<String> {
    let mut aliases = BTreeSet::from([variable.to_string()]);
    loop {
        let before = aliases.len();
        for statement in scan.split(';') {
            let Some((lhs, rhs)) = statement.split_once('=') else {
                continue;
            };
            let rhs_compact = strip_ascii_whitespace(&csharp_code_mask(rhs));
            if aliases.iter().any(|alias| {
                rhs_compact == *alias
                    || rhs_compact.starts_with(&format!("{alias}.AsSpan("))
                    || rhs_compact.starts_with(&format!("{alias}.AsMemory("))
            }) {
                if let Some(alias) = last_identifier(lhs) {
                    aliases.insert(alias);
                }
            }
        }
        if aliases.len() == before {
            break;
        }
    }
    aliases
}

fn compact_contains_assignment(compact: &str, alias: &str) -> bool {
    compact.contains(&format!(";{alias}="))
        || compact.starts_with(&format!("{alias}="))
        || compact.contains(&format!("\n{alias}=new[]"))
}

fn compact_contains_mutation(compact: &str, alias: &str) -> bool {
    let methods = [
        "Append", "Concat", "Where", "Select", "Union", "Prepend", "SetValue", "Add", "Clear",
        "Fill", "Reverse", "Sort",
    ];
    if compact.contains(&format!("{alias}[")) && compact.contains("]=") {
        return true;
    }
    if methods
        .iter()
        .any(|method| compact.contains(&format!("{alias}.{method}(")))
    {
        return true;
    }
    if compact.contains(&format!("{alias}.AsSpan()[")) && compact.contains("]=") {
        return true;
    }
    if compact.contains(&format!("{alias}.AsSpan().Fill("))
        || compact.contains(&format!("{alias}.AsMemory().Span.Fill("))
    {
        return true;
    }
    if compact.contains(&format!("Array.Fill({alias},")) {
        return true;
    }
    false
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
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    let array_text = rhs.trim().trim_end_matches(',').trim();
    if !array_text.starts_with("new[]") {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    }
    let cursor = skip_ascii_whitespace(array_text, "new[]".len());
    if array_text.as_bytes().get(cursor) != Some(&b'{') {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    }
    let Some(close) = matching_brace_index(array_text, cursor) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    Some(csharp_array_literal_values(
        &array_text[cursor + 1..close],
        &format!("API {field}"),
        errors,
    ))
}

fn csharp_array_literal_values(body: &str, label: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    for member in top_level_array_members(body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if let Some((value, end)) = quoted_string_at(text, 0) {
            if end == text.len() {
                values.push(value);
                continue;
            }
        }
        errors.push(format!("{label} array contains non-static values"));
    }
    values
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
    let required = required_values
        .iter()
        .map(|value| value.to_string())
        .collect::<BTreeSet<_>>();
    let actual = values.iter().cloned().collect::<BTreeSet<_>>();
    let missing = required.difference(&actual).cloned().collect::<Vec<_>>();
    let unexpected = actual.difference(&required).cloned().collect::<Vec<_>>();
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
        values.len() == actual.len(),
        errors,
        &format!("API {field} values must be unique"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = direct_api_rule_objects(block, errors);
    let catalog_rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let catalog_ids = catalog_rules
        .iter()
        .filter_map(|rule| value_str_direct(rule, "id").map(str::to_string))
        .collect::<Vec<_>>();
    let api_ids = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect::<Vec<_>>();
    for id in diff_values(&catalog_ids, &api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in diff_values(&api_ids, &catalog_ids) {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(unique(&api_ids), errors, "API rule IDs must be unique");
    let details = api_rules
        .iter()
        .filter_map(|rule| {
            Some((
                rule.get("decision")?.clone(),
                rule.get("requirement")?.clone(),
                rule.get("evidence")?.clone(),
            ))
        })
        .collect::<Vec<_>>();
    let detail_set = details.iter().cloned().collect::<BTreeSet<_>>();
    expect(
        details.len() == detail_set.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(id) = value_str_direct(&catalog_rule, "id") else {
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
                api_rule.get(*field).map(String::as_str) == value_str_direct(&catalog_rule, field),
                errors,
                &format!("API rule {id} {field} must match catalog"),
            );
        }
    }
}

fn direct_api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<BTreeMap<String, String>> {
    let Some(array_block) = endpoint_array_block(block, "rules", errors) else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    for member in top_level_array_members(&array_block[1..array_block.len().saturating_sub(1)]) {
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
        let Some(close) = matching_brace_index(text, cursor) else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        let object_block = &text[cursor..=close];
        let fields = top_level_assignment_fields(object_block);
        let mut rule = BTreeMap::new();
        for field in RULE_FIELDS {
            if let Some(value) = rule_string_field(object_block, field) {
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
    let Some(open) = assignment.find('{') else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    let Some(close) = matching_brace_index(assignment, open) else {
        errors.push(format!("API {field} array must be a single array"));
        return None;
    };
    Some(assignment[open..=close].to_string())
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
        if prohibited_key(&field) {
            errors.push(format!(
                "API endpoint has prohibited hardware lifecycle field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected hardware lifecycle field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let masked = csharp_code_mask(block);
    let fields = assignment_fields(block);
    let mut seen = BTreeSet::new();
    for field in fields {
        if !seen.insert(field.clone()) {
            continue;
        }
        if assignment_has_value(&masked, &field, "true") && unsafe_true_field(&field) {
            errors.push(format!(
                "hardware lifecycle endpoint must not enable {field}"
            ));
        }
    }
}

fn validate_endpoint_property_identifiers(block: &str, errors: &mut Vec<String>) {
    let masked = csharp_code_mask(block);
    let mut index = 0;
    let mut identifiers = BTreeSet::new();
    while index < masked.len() {
        let byte = masked.as_bytes()[index];
        if !byte.is_ascii_alphabetic() && byte != b'_' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < masked.len()
            && (masked.as_bytes()[index].is_ascii_alphanumeric()
                || masked.as_bytes()[index] == b'_')
        {
            index += 1;
        }
        identifiers.insert(block[start..index].to_string());
    }
    for identifier in identifiers {
        if REQUIRED_DISABLED_FIELDS.contains(&identifier.as_str()) {
            continue;
        }
        if prohibited_key(&identifier) {
            errors.push(format!(
                "API endpoint property {identifier} contains prohibited hardware lifecycle identifier"
            ));
        }
    }
}

fn unsafe_true_field(field: &str) -> bool {
    field.ends_with("Allowed")
        || field.ends_with("Enabled")
        || [
            "live",
            "provider",
            "raw",
            "payload",
            "mutation",
            "execution",
            "serial",
            "asset",
            "device",
            "host",
            "user",
            "endpoint",
            "private",
            "identifier",
            "credential",
            "secret",
            "token",
            "password",
        ]
        .iter()
        .any(|token| normalized_key(field).contains(token))
}

fn validate_docs_text(api_readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing hardware lifecycle endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "hardware lifecycle doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "hardware lifecycle doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live execution."),
        errors,
        "hardware lifecycle doc must prohibit live execution",
    );
    expect(
        doc.contains("No serial numbers"),
        errors,
        "hardware lifecycle doc must prohibit serial numbers",
    );
    expect(
        doc.contains("metadata-only hardware lifecycle contract"),
        errors,
        "hardware lifecycle doc must describe metadata-only mode",
    );
    expect(
        doc.contains("prior vendor recommended release train (N-1)"),
        errors,
        "hardware lifecycle doc must describe N-1 firmware strategy",
    );
    expect(
        doc.contains(
            "HPE profiles use prior applicable SPP, MSA, and SimpliVity recommendation sets",
        ),
        errors,
        "hardware lifecycle doc must describe HPE recommendation sets",
    );
    expect(
        doc.contains("Lenovo SR, VX, and MX profiles use prior recommended recipes"),
        errors,
        "hardware lifecycle doc must describe Lenovo recipe scope",
    );
    expect(
        doc.contains("Evidence stays summary-only"),
        errors,
        "hardware lifecycle doc must require summary-only evidence",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_key(key) && !SAFE_CATALOG_KEYS.contains(&key.as_str()) {
                    errors.push(format!("{child_path} contains prohibited key"));
                }
                scan_prohibited_value(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) if contains_prohibited_value(text) => {
            errors.push(format!("{path} contains prohibited value"));
        }
        _ => {}
    }
}

fn contains_prohibited_value(value: &str) -> bool {
    contains_aws_access_key(value)
        || contains_private_key_marker(value)
        || contains_url(value)
        || contains_private_ipv4(value)
        || contains_uuid(value)
        || contains_sensitive_assignment(value)
}

fn contains_aws_access_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(4).enumerate().any(|(index, window)| {
        window.eq_ignore_ascii_case(b"AKIA")
            && bytes
                .get(index + 4..index + 20)
                .is_some_and(|tail| tail.iter().all(u8::is_ascii_alphanumeric))
    })
}

fn contains_private_key_marker(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

fn contains_url(value: &str) -> bool {
    value.find("://").is_some_and(|index| {
        index > 0
            && value[..index]
                .chars()
                .rev()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || "+.-".contains(*character)
                })
                .count()
                > 0
    })
}

fn contains_private_ipv4(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .filter(|candidate| candidate.matches('.').count() == 3)
        .any(|candidate| {
            let octets = candidate
                .split('.')
                .filter_map(|part| part.parse::<u8>().ok())
                .collect::<Vec<_>>();
            octets.len() == 4
                && (octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1])))
        })
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .any(|candidate| {
            let parts = candidate.split('-').collect::<Vec<_>>();
            parts.len() == 5
                && [8, 4, 4, 4, 12]
                    .iter()
                    .zip(parts.iter())
                    .all(|(length, part)| {
                        part.len() == *length
                            && part.chars().all(|character| character.is_ascii_hexdigit())
                    })
        })
}

fn contains_sensitive_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let compact = lower
        .chars()
        .filter(|character| !matches!(character, '"' | '\'' | '\\'))
        .collect::<String>();
    let sensitive_keys = [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "endpointurl",
        "endpointname",
        "privateip",
        "serialnumber",
        "assettag",
        "deviceidentifier",
        "hostname",
        "username",
        "tenantid",
        "objectid",
        "providerpayload",
        "vendorpayload",
        "rawpayload",
        "rawrow",
        "recipientdata",
        "serialnumberallowed",
    ];
    sensitive_keys.iter().any(|key| {
        compact.find(key).is_some_and(|index| {
            compact[index + key.len()..]
                .trim_start()
                .chars()
                .next()
                .is_some_and(|character| character == ':' || character == '=')
        })
    })
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1
        && assignment_rhs(&texts[0], field)
            .map(|rhs| rhs.trim().trim_end_matches(',').trim() == value)
            .unwrap_or(false)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1
        && exact_string_assignment_value_optional_comma(&texts[0], field).as_deref() == Some(value)
}

fn exact_string_assignment_value_optional_comma(text: &str, field: &str) -> Option<String> {
    let rhs = assignment_rhs(text, field)?
        .trim()
        .trim_end_matches(',')
        .trim();
    let (value, end) = quoted_string_at(rhs, 0)?;
    (end == rhs.len()).then_some(value)
}

fn assignment_rhs<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    let trimmed = text.trim();
    let rest = trimmed.strip_prefix(field)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    Some(rest)
}

fn top_level_assignment_texts(block: &str, field: &str) -> Vec<String> {
    top_level_assignment_indexes(block, field)
        .into_iter()
        .map(|index| {
            let end = assignment_end_index(block, index);
            block[index..end].trim().to_string()
        })
        .collect()
}

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
    let masked = csharp_code_mask(block);
    let mut indexes = Vec::new();
    let mut index = 0;
    while let Some(relative) = masked[index..].find(field) {
        let start = index + relative;
        let end = start + field.len();
        index = end;
        if !identifier_boundary(&masked, start, end) || brace_depth_at(&masked, start) != 1 {
            continue;
        }
        let cursor = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(cursor) == Some(&b'=') {
            indexes.push(start);
        }
    }
    indexes
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    assignment_fields(block)
        .into_iter()
        .filter(|field| {
            top_level_assignment_indexes(block, field)
                .into_iter()
                .next()
                .is_some()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn assignment_fields(block: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let mut fields = Vec::new();
    let mut index = 0;
    while index < masked.len() {
        if !masked.as_bytes()[index].is_ascii_alphabetic() && masked.as_bytes()[index] != b'_' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < masked.len()
            && (masked.as_bytes()[index].is_ascii_alphanumeric()
                || masked.as_bytes()[index] == b'_')
        {
            index += 1;
        }
        let end = index;
        let cursor = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(cursor) == Some(&b'=') {
            fields.push(block[start..end].to_string());
        }
    }
    fields
}

fn assignment_has_value(masked: &str, field: &str, value: &str) -> bool {
    let mut index = 0;
    while let Some(relative) = masked[index..].find(field) {
        let start = index + relative;
        let end = start + field.len();
        index = end;
        if !identifier_boundary(masked, start, end) {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(masked, end);
        if masked.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        cursor = skip_ascii_whitespace(masked, cursor + 1);
        if masked[cursor..].starts_with(value)
            && identifier_boundary(masked, cursor, cursor + value.len())
        {
            return true;
        }
    }
    false
}

fn assignment_end_index(block: &str, start: usize) -> usize {
    let bytes = block.as_bytes();
    let mut index = start;
    let mut depth = brace_depth_at(block, start);
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
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
        } else if byte == b'{' || byte == b'[' || byte == b'(' {
            depth += 1;
        } else if byte == b'}' || byte == b']' || byte == b')' {
            if depth == 1 {
                return index;
            }
            depth = depth.saturating_sub(1);
        } else if byte == b',' && depth == 1 {
            return index + 1;
        } else if byte == b';' && depth == 0 {
            return index + 1;
        }
        index += 1;
    }
    block.len()
}

fn top_level_array_members(body: &str) -> Vec<String> {
    let mut members = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let bytes = body.as_bytes();
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
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
        } else if byte == b'{' || byte == b'[' || byte == b'(' {
            depth += 1;
        } else if byte == b'}' || byte == b']' || byte == b')' {
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

fn matching_brace_index(text: &str, open: usize) -> Option<usize> {
    if text.as_bytes().get(open) != Some(&b'{') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut index = open;
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
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
        } else if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
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

fn csharp_without_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_block = false;
    let mut in_line = false;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            output.push(bytes[index] as char);
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if in_block {
            if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                output.push(' ');
                output.push(' ');
                index += 2;
                in_block = false;
            } else {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            continue;
        }
        if in_line {
            output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
            if bytes[index] == b'\n' {
                in_line = false;
            }
            index += 1;
            continue;
        }
        if bytes[index] == b'"' {
            in_string = true;
            output.push('"');
            index += 1;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 2;
            in_block = true;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            output.push(' ');
            output.push(' ');
            index += 2;
            in_line = true;
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_code_mask(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            output.push(' ');
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
            output.push(' ');
        } else {
            output.push(byte as char);
        }
        index += 1;
    }
    output
}

fn quoted_string_at(text: &str, quote: usize) -> Option<(String, usize)> {
    if text.as_bytes().get(quote) != Some(&b'"') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut value = String::new();
    let mut index = quote + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            return Some((value, index + 1));
        }
        if byte == b'\\' {
            index += 1;
            if index >= bytes.len() {
                return None;
            }
            value.push(bytes[index] as char);
            index += 1;
            continue;
        }
        value.push(byte as char);
        index += 1;
    }
    None
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn value_i64(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn value_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn value_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn value_str_direct<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.as_object()?.get(key)?.as_str()
}

fn diff_values(left: &[String], right: &[String]) -> Vec<String> {
    let left = left.iter().cloned().collect::<BTreeSet<_>>();
    let right = right.iter().cloned().collect::<BTreeSet<_>>();
    left.difference(&right).cloned().collect()
}

fn unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn prohibited_key(key: &str) -> bool {
    let normalized = normalized_key(key);
    PROHIBITED_KEY_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
}

fn normalized_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn skip_horizontal_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && matches!(text.as_bytes()[index], b' ' | b'\t' | b'\r') {
        index += 1;
    }
    index
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = start
        .checked_sub(1)
        .and_then(|index| text.as_bytes().get(index))
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
    let after = text
        .as_bytes()
        .get(end)
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
    before && after
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

fn last_identifier(text: &str) -> Option<String> {
    let mut result = None;
    let mut index = 0;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            index += 1;
            while index < text.len()
                && (text.as_bytes()[index].is_ascii_alphanumeric()
                    || text.as_bytes()[index] == b'_')
            {
                index += 1;
            }
            result = Some(text[start..index].to_string());
        } else {
            index += 1;
        }
    }
    result
}

fn strip_ascii_whitespace(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_registration_allows_spaced_receiver() {
        let program = format!(
            "app . MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let starts = endpoint_start_indexes(&program);

        assert_eq!(starts.len(), 1);
    }

    #[test]
    fn comment_stripper_preserves_url_inside_string_literal() {
        let text = r#"operatorNote = "https://provider.example.invalid/path", // comment"#;
        let stripped = csharp_without_comments(text);

        assert!(stripped.contains("https://provider.example.invalid/path"));
        assert!(!stripped.contains("comment"));
    }

    #[test]
    fn commented_endpoint_decoy_is_ignored() {
        let program = format!(
            "/*\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));\n*/"
        );
        let uncommented = csharp_without_comments(&program);

        assert!(endpoint_start_indexes(&uncommented).is_empty());
    }

    #[test]
    fn suffix_route_bypass_is_not_registered() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}-live\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );

        assert!(endpoint_start_indexes(&program).is_empty());
    }

    #[test]
    fn duplicate_active_endpoint_definition_is_rejected() {
        let endpoint = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let program = format!("{endpoint}\n{endpoint}");
        let mut errors = Vec::new();

        let _ = endpoint_block(&program, &mut errors);

        assert!(errors.iter().any(|error| error.contains("exactly one")));
    }

    #[test]
    fn duplicate_source_assignment_spoofing_is_rejected() {
        let block = r#"{ source = "static-seed", source = "live-provider" }"#;
        let mut errors = Vec::new();

        validate_endpoint_assignment_counts(block, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("source") && error.contains("once")));
    }

    #[test]
    fn endpoint_property_identifier_is_rejected() {
        let block = "{ supportedProfiles = safeSummary.endpointName }";
        let mut errors = Vec::new();

        validate_endpoint_property_identifiers(block, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("endpointName") && error.contains("prohibited")));
    }

    #[test]
    fn bound_array_reassignment_is_rejected() {
        let program = format!(
            "var hardwareLifecycleProfiles = new[] {{ \"hpe-dl360-msa\" }};\nhardwareLifecycleProfiles = LoadFromProvider();\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();

        validate_bound_array_immutable(
            &program,
            "hardwareLifecycleProfiles",
            "supportedProfiles",
            &mut errors,
        );

        assert!(errors.iter().any(
            |error| error.contains("hardwareLifecycleProfiles") && error.contains("immutable")
        ));
    }

    #[test]
    fn inline_array_expression_is_rejected() {
        let block = r#"{ requiredInputs = new[] { "hardwareProfile", "lifecycleState", LoadFromProvider() } }"#;
        let mut errors = Vec::new();

        let _ = endpoint_inline_array_values(block, "requiredInputs", &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("requiredInputs") && error.contains("non-static")));
    }

    #[test]
    fn quoted_broad_suffix_provider_literal_is_rejected() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String(r#""serialNumberAllowed": true"#.to_string()),
            "synthetic.notes",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("synthetic.notes") && error.contains("prohibited")));
    }
}
