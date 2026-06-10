use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/network-vlan-readiness-contract.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/network-vlan-readiness.md";

const ENDPOINT: &str = "/api/operations/network-vlan-readiness-contract";

const REQUIRED_WORKFLOWS: &[&str] = &[
    "host-network-readiness",
    "workload-vlan-readiness",
    "switchport-capacity-review",
    "portgroup-policy-review",
    "vlan-catalog-review",
    "network-exception-review",
];
const REQUIRED_DOMAINS: &[&str] = &[
    "switchport-capacity",
    "vlan-catalog",
    "portgroup-policy",
    "trunk-policy",
    "uplink-redundancy",
    "mtu-policy",
    "network-segmentation",
    "evidence-readiness",
];
const REQUIRED_INPUTS: &[&str] = &[
    "site",
    "networkScope",
    "workloadProfile",
    "platformProfile",
    "vlanPolicy",
    "portgroupPolicy",
    "redundancyRequirement",
    "maintenanceWindow",
    "owner",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "site-known",
    "network-scope-known",
    "vlan-catalog-reviewed",
    "portgroup-policy-reviewed",
    "switchport-capacity-reviewed",
    "uplink-redundancy-reviewed",
    "segmentation-reviewed",
    "maintenance-window-known",
    "owner-known",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "readinessSummary",
    "vlanPolicyReview",
    "portgroupPolicyReview",
    "switchportCapacityReview",
    "uplinkAndTrunkReview",
    "segmentationReview",
    "exceptionDecision",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-network-change-disabled",
    "raw-inventory-rows-disabled",
    "network-identifiers-disabled",
    "site-unknown",
    "network-scope-missing",
    "vlan-catalog-missing",
    "portgroup-policy-missing",
    "switchport-capacity-unknown",
    "uplink-redundancy-unknown",
    "segmentation-unknown",
    "maintenance-window-missing",
    "owner-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Readiness summary",
    "VLAN policy review",
    "Portgroup policy review",
    "Switchport capacity review",
    "Uplink and trunk review",
    "Segmentation review",
    "Exception decision",
    "Evidence references",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-network-changes",
        decision: "block",
        requirement: "Network and VLAN readiness contracts report review state only and never configure switches, port groups, VLANs, trunks, uplinks, or provider networking.",
        evidence: "Readiness summary",
    },
    RuleDetail {
        id: "vlan-catalog-required",
        decision: "block",
        requirement: "VLAN and port group policy decisions must come from reviewed catalog summaries before host or workload placement can proceed.",
        evidence: "VLAN policy review",
    },
    RuleDetail {
        id: "switchport-capacity-required",
        decision: "block",
        requirement: "Switchport capacity, uplink redundancy, and trunk policy summaries must be reviewed before network readiness can be accepted.",
        evidence: "Switchport capacity review",
    },
    RuleDetail {
        id: "segmentation-review-required",
        decision: "block",
        requirement: "Segmentation and environment policy decisions must be reviewed before readiness can be accepted.",
        evidence: "Segmentation review",
    },
    RuleDetail {
        id: "raw-network-inventory-not-exposed",
        decision: "block",
        requirement: "Network readiness evidence must use safe summaries only and must not expose switch IDs, switchport IDs, MAC addresses, VLAN IDs, endpoint names, private IPs, raw network inventory rows, serials, or provider payloads.",
        evidence: "Evidence references",
    },
];

const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "readinessMode",
    "providerCallsEnabled",
    "liveNetworkChangesAllowed",
    "rawInventoryRowsAllowed",
    "networkIdentifiersAllowed",
    "supportedWorkflows",
    "readinessDomains",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const REQUIRED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "readinessMode",
    "providerCallsEnabled",
    "liveNetworkChangesAllowed",
    "rawInventoryRowsAllowed",
    "networkIdentifiersAllowed",
    "supportedWorkflows",
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
const TOP_LEVEL_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "readinessMode",
    "providerCallsEnabled",
    "liveNetworkChangesAllowed",
    "rawInventoryRowsAllowed",
    "networkIdentifiersAllowed",
    "supportedWorkflows",
    "readinessDomains",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const REQUIRED_RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveNetworkChangesAllowed",
    "rawInventoryRowsAllowed",
    "networkIdentifiersAllowed",
];
const VARIABLE_ARRAYS: &[(&str, &str, &[&str])] = &[
    (
        "supportedWorkflows",
        "networkVlanReadinessWorkflows",
        REQUIRED_WORKFLOWS,
    ),
    (
        "readinessDomains",
        "networkVlanReadinessDomains",
        REQUIRED_DOMAINS,
    ),
    (
        "requiredGuards",
        "networkVlanReadinessRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "networkVlanReadinessPlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "networkVlanReadinessBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const SAFE_RAW_CATALOG_COMMENTS: &[&str] = &[
    "Network and VLAN readiness seed data only. Do not add hostnames, usernames, credentials, tokens, tenant IDs, switch IDs, switchport IDs, MAC addresses, VLAN IDs, endpoint names, private IPs, raw network inventory rows, serials, asset tags, raw logs, or provider payloads.",
];
const PROHIBITED_NETWORK_KEYS: &[&str] = &[
    "hostname",
    "hostnames",
    "username",
    "password",
    "credential",
    "credentials",
    "secret",
    "token",
    "tenantid",
    "switchid",
    "switchids",
    "switchportid",
    "switchportids",
    "portid",
    "portids",
    "mac",
    "macaddress",
    "vlanid",
    "vlanids",
    "endpoint",
    "endpointname",
    "endpointurl",
    "privateip",
    "rawinventoryrow",
    "rawinventoryrows",
    "rawnetworkinventoryrow",
    "rawnetworkinventoryrows",
    "providerpayload",
    "providerpayloads",
    "rawproviderpayload",
    "rawproviderpayloads",
    "serial",
    "serialnumber",
    "assettag",
];
const PROHIBITED_NETWORK_SUBSTRINGS: &[&str] = &[
    "hostname",
    "username",
    "password",
    "credential",
    "secret",
    "token",
    "tenantid",
    "switchid",
    "switchportid",
    "portid",
    "macaddress",
    "vlanid",
    "endpoint",
    "privateip",
    "rawinventory",
    "rawnetworkinventory",
    "providerpayload",
    "rawproviderpayload",
    "serial",
    "assettag",
];
const SAFE_NETWORK_GUARD_KEYS: &[&str] = &[
    "providercallsenabled",
    "livenetworkchangesallowed",
    "rawinventoryrowsallowed",
    "networkidentifiersallowed",
    "networkidentifiersdisabled",
    "rawinventoryrowsdisabled",
];

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

#[derive(Deserialize)]
struct NetworkVlanReadinessContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    test: String,
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
struct ProhibitedInput {
    value: Value,
    path: String,
    scan_kind: Option<String>,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: NetworkVlanReadinessContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid network VLAN readiness context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_raw_catalog_text(&context.catalog_text, CATALOG_PATH, &mut errors);
    if !context.catalog.is_object() {
        return Ok(errors);
    }
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    let mut source_bundle = BTreeMap::new();
    source_bundle.insert(CATALOG_PATH.to_string(), context.catalog);
    source_bundle.insert(PROGRAM_PATH.to_string(), Value::String(context.program));
    source_bundle.insert(
        API_README_PATH.to_string(),
        Value::String(context.api_readme),
    );
    source_bundle.insert(
        CATALOG_README_PATH.to_string(),
        Value::String(context.catalog_readme),
    );
    source_bundle.insert(
        DOC_README_PATH.to_string(),
        Value::String(context.doc_readme),
    );
    source_bundle.insert(DOC_PATH.to_string(), Value::String(context.doc));
    scan_prohibited_value(
        &map_to_value(source_bundle),
        "network-vlan-readiness",
        &mut errors,
    );
    // test removed: Ruby file no longer exists
    Ok(errors)
}

const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid network VLAN readiness catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid network VLAN readiness program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid network VLAN readiness docs JSON: {error}"))?;
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
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid network VLAN readiness prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    match payload.scan_kind.as_deref() {
        Some("raw-catalog-text") => {
            let text = payload.value.as_str().unwrap_or_default();
            validate_raw_catalog_text(text, &payload.path, &mut errors);
        }
        Some("test-literals") => {
            let text = payload.value.as_str().unwrap_or_default();
            validate_no_prohibited_test_literals(text, &payload.path, &mut errors);
        }
        _ => scan_prohibited_value(&payload.value, &payload.path, &mut errors),
    }
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("network and VLAN readiness catalog must be a mapping".to_string());
        return;
    };

    let keys: Vec<&str> = map.keys().map(String::as_str).collect();
    let unexpected: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|key| !REQUIRED_CATALOG_KEYS.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "network and VLAN readiness unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
    validate_no_unsafe_true_values(catalog, "catalog", errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "network and VLAN readiness version must be 1",
    );
    expect(
        string_field(catalog, "status") == Some("draft"),
        errors,
        "network and VLAN readiness status must be draft",
    );
    expect(
        string_field(catalog, "source") == Some("static-seed"),
        errors,
        "network and VLAN readiness source must be static-seed",
    );
    expect(
        string_field(catalog, "readinessMode") == Some("review-only"),
        errors,
        "network and VLAN readiness mode must be review-only",
    );
    for field in DISABLED_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(false),
            errors,
            &format!(
                "network and VLAN readiness {} must be disabled",
                field_label(field)
            ),
        );
    }
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "readinessDomains", REQUIRED_DOMAINS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    for field in [
        "supportedWorkflows",
        "readinessDomains",
        "requiredInputs",
        "requiredGuards",
        "planSections",
        "blockedReasons",
        "requiredEvidence",
    ] {
        for value in array_strings(catalog, field) {
            if prohibited_network_key(&value) {
                errors.push(format!("{field} contains prohibited network field {value}"));
            }
        }
    }
    validate_catalog_rules(catalog, errors);
}

fn field_label(field: &str) -> &'static str {
    match field {
        "providerCallsEnabled" => "provider calls",
        "liveNetworkChangesAllowed" => "live changes",
        "rawInventoryRowsAllowed" => "raw inventory rows",
        "networkIdentifiersAllowed" => "identifiers",
        _ => "field",
    }
}

fn validate_catalog_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| string_field(rule, "id").map(str::to_string))
        .collect();
    validate_id_set(
        &rule_ids,
        required_rule_ids(),
        "network and VLAN readiness",
        errors,
    );
    for required in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|rule| string_field(rule, "id") == Some(required.id))
        else {
            continue;
        };
        let Some(map) = rule.as_object() else {
            errors.push(format!(
                "network and VLAN readiness rule {} must be a mapping",
                required.id
            ));
            continue;
        };
        let unexpected: Vec<&str> = map
            .keys()
            .map(String::as_str)
            .filter(|key| !REQUIRED_RULE_KEYS.contains(key))
            .collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "network and VLAN readiness rule {} has unexpected keys: {}",
                required.id,
                unexpected.join(", ")
            ));
        }
        validate_no_unsafe_true_values(rule, &format!("rule {}", required.id), errors);
        expect(
            string_field(rule, "decision") == Some(required.decision),
            errors,
            &format!(
                "network and VLAN readiness rule {} has unexpected decision",
                required.id
            ),
        );
        expect(
            string_field(rule, "requirement") == Some(required.requirement),
            errors,
            &format!(
                "network and VLAN readiness rule {} has unexpected requirement",
                required.id
            ),
        );
        expect(
            string_field(rule, "evidence") == Some(required.evidence),
            errors,
            &format!(
                "network and VLAN readiness rule {} has unexpected evidence",
                required.id
            ),
        );
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = array_strings(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        &format!("{field} must be non-empty array"),
    );
    let required: Vec<String> = required_values
        .iter()
        .map(|value| value.to_string())
        .collect();
    let missing: Vec<String> = required
        .iter()
        .filter(|value| !values.contains(*value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !required.contains(*value))
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
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        errors.push(format!("{field} values must be unique"));
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented = csharp_without_comments(program);
    let block = endpoint_payload_block(&endpoint_block(&uncommented, errors), errors);
    if block.is_empty() {
        return;
    }

    validate_endpoint_assignment_counts(&block, errors);
    expect(
        literal_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static seed source as single literal static-seed assignment",
    );
    expect(
        literal_string_assignment(&block, "readinessMode", "review-only"),
        errors,
        "API must keep readinessMode single literal review-only assignment",
    );
    for field in DISABLED_FIELDS {
        expect(
            literal_false_assignment(&block, field),
            errors,
            &format!("API must keep {field} literal false assignment"),
        );
    }
    for (field, variable, required) in VARIABLE_ARRAYS {
        expect(
            block.contains(&format!("{field} = {variable}")),
            errors,
            &format!("API endpoint missing {field} field"),
        );
        validate_array_values_exact(
            csharp_array_values(&uncommented, variable, errors),
            &format!("API {field}"),
            required,
            errors,
        );
    }
    for (field, required) in INLINE_ARRAYS {
        validate_array_values_exact(
            api_array_values(&block, field),
            &format!("API {field}"),
            required,
            errors,
        );
    }
    let rule_blocks = api_rule_blocks(&block);
    let rule_ids: Vec<String> = rule_blocks
        .iter()
        .filter_map(|candidate| api_string_field(candidate, "id"))
        .collect();
    validate_api_rule_id_set(&rule_ids, errors);
    validate_no_prohibited_api_terms(
        &format!(
            "{}{}{}{}{}",
            csharp_array_assignment(&uncommented, "networkVlanReadinessWorkflows"),
            csharp_array_assignment(&uncommented, "networkVlanReadinessDomains"),
            csharp_array_assignment(&uncommented, "networkVlanReadinessRequiredGuards"),
            csharp_array_assignment(&uncommented, "networkVlanReadinessPlanSections"),
            csharp_array_assignment(&uncommented, "networkVlanReadinessBlockedReasons")
        ),
        "networkVlanReadinessArrays",
        errors,
    );
    validate_no_prohibited_api_field_names(&block, "networkVlanReadinessEndpoint", errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_no_prohibited_api_terms(&block, "networkVlanReadinessEndpoint", errors);
    validate_api_rules(&rule_blocks, catalog, errors);
}

fn validate_api_rules(rule_blocks: &[String], catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rule_ids = array_rule_ids(catalog);
    let api_rule_ids: Vec<String> = rule_blocks
        .iter()
        .filter_map(|candidate| api_string_field(candidate, "id"))
        .collect();
    let missing: Vec<String> = catalog_rule_ids
        .iter()
        .filter(|id| !api_rule_ids.contains(*id))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!("API missing rules: {}", missing.join(", ")));
    }
    let unexpected: Vec<String> = api_rule_ids
        .iter()
        .filter(|id| !catalog_rule_ids.contains(*id))
        .cloned()
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!("API unexpected rules: {}", unexpected.join(", ")));
    }
    if api_rule_ids.iter().collect::<BTreeSet<_>>().len() != api_rule_ids.len() {
        errors.push("API rule IDs must be unique".to_string());
    }

    for required in REQUIRED_RULES {
        let rule_block = rule_blocks
            .iter()
            .find(|candidate| api_string_field(candidate, "id").as_deref() == Some(required.id))
            .cloned()
            .unwrap_or_default();
        expect(
            !rule_block.is_empty(),
            errors,
            &format!("API missing rule {}", required.id),
        );
        expect(
            rule_block.contains(&format!("decision = \"{}\"", required.decision)),
            errors,
            &format!("API rule {} has wrong decision", required.id),
        );
        expect(
            rule_block.contains(&format!("requirement = \"{}\"", required.requirement)),
            errors,
            &format!("API missing rule requirement {}", required.id),
        );
        expect(
            rule_block.contains(&format!("evidence = \"{}\"", required.evidence)),
            errors,
            &format!("API rule {} has wrong evidence", required.id),
        );
    }
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
        "API README missing network and VLAN readiness endpoint",
    );
    expect(
        catalog_readme.contains("network-vlan-readiness-contract.yaml"),
        errors,
        "catalog README missing network and VLAN readiness catalog",
    );
    expect(
        doc_readme.contains("network-vlan-readiness.md"),
        errors,
        "workflow README missing network and VLAN readiness doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "network and VLAN readiness doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "network and VLAN readiness doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live network changes."),
        errors,
        "network and VLAN readiness doc must prohibit live network changes",
    );
    expect(
        doc.contains("No raw inventory rows."),
        errors,
        "network and VLAN readiness doc must prohibit raw inventory rows",
    );
    expect(
        doc.contains("No switch identifiers"),
        errors,
        "network and VLAN readiness doc must prohibit network identifiers",
    );
    expect(
        doc.contains("network-safe readiness summaries only"),
        errors,
        "network and VLAN readiness doc must require safe summaries",
    );
}

fn validate_endpoint_assignment_counts(block: &str, errors: &mut Vec<String>) {
    for field in TOP_LEVEL_ENDPOINT_FIELDS {
        if top_level_assignment_count(block, field) > 1 {
            errors.push(format!("API {field} must be declared once"));
        }
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing network and VLAN readiness endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors.push(
            "API network and VLAN readiness endpoint must be declared exactly once".to_string(),
        );
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
    if endpoint.is_empty() {
        return String::new();
    }
    let json_indexes = results_json_indexes(endpoint);
    if json_indexes.is_empty() {
        errors.push("API missing network and VLAN readiness JSON payload".to_string());
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors.push(
            "API must declare exactly one network and VLAN readiness JSON payload".to_string(),
        );
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push(
            "API network and VLAN readiness JSON payload must be a single object".to_string(),
        );
        return String::new();
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push(
            "API network and VLAN readiness JSON payload must be a single object".to_string(),
        );
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

fn csharp_array_values(program: &str, variable: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    let mut count = 0;
    let needle = format!("var {variable} = new[]");
    let mut offset = 0;
    while let Some(relative) = program[offset..].find(&needle) {
        count += 1;
        let start = offset + relative;
        offset = start + needle.len();
        let end = program[start..]
            .find(';')
            .map(|index| start + index)
            .unwrap_or(program.len());
        values = quoted_values(&program[start..end]);
    }
    if count == 0 {
        errors.push(format!("API missing {variable} declaration"));
    } else if count > 1 {
        errors.push(format!("API {variable} must have exactly one declaration"));
    }
    values
}

fn csharp_array_assignment(program: &str, variable: &str) -> String {
    let needle = format!("var {variable} = new[]");
    let Some(start) = program.find(&needle) else {
        return String::new();
    };
    let end = program[start..]
        .find(';')
        .map(|index| start + index)
        .unwrap_or(program.len());
    program[start..end].to_string()
}

fn api_array_values(block: &str, field: &str) -> Vec<String> {
    let assignment = api_array_assignment(block, field);
    quoted_values(&assignment)
}

fn api_array_assignment(block: &str, field: &str) -> String {
    let Some(field_index) = block.find(&format!("{field} = new[]")) else {
        return String::new();
    };
    let Some(brace_start) = block[field_index..]
        .find('{')
        .map(|index| field_index + index)
    else {
        return String::new();
    };
    let Some(brace_end) = matching_brace_index(block, brace_start) else {
        return String::new();
    };
    block[field_index..=brace_end].to_string()
}

fn api_rule_blocks(block: &str) -> Vec<String> {
    let rule_array = api_array_assignment(block, "rules");
    let mut objects = Vec::new();
    let mut index = rule_array.find('{').map(|start| start + 1).unwrap_or(0);
    while let Some(relative) = rule_array[index..].find("new") {
        let object_start = index + relative;
        if !identifier_boundary(&rule_array, object_start, object_start + 3) {
            index = object_start + 3;
            continue;
        }
        let cursor = skip_ascii_whitespace(&rule_array, object_start + 3);
        if rule_array.as_bytes().get(cursor) == Some(&b'[') {
            index = cursor + 1;
            continue;
        }
        let Some(brace_start) =
            (rule_array.as_bytes().get(cursor) == Some(&b'{')).then_some(cursor)
        else {
            break;
        };
        let Some(brace_end) = matching_brace_index(&rule_array, brace_start) else {
            break;
        };
        objects.push(rule_array[object_start..=brace_end].to_string());
        index = brace_end + 1;
    }
    objects
}

fn api_string_field(block: &str, field: &str) -> Option<String> {
    let needle = format!("{field} = \"");
    let start = block.find(&needle)? + needle.len();
    let rest = &block[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn literal_false_assignment(block: &str, field: &str) -> bool {
    let assignments: Vec<&str> = block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&format!("{field} =")))
        .collect();
    assignments.len() == 1 && assignments[0] == format!("{field} = false,")
}

fn literal_string_assignment(block: &str, field: &str, expected: &str) -> bool {
    let assignments: Vec<&str> = block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&format!("{field} =")))
        .collect();
    assignments.len() == 1 && assignments[0] == format!("{field} = \"{expected}\",")
}

fn top_level_assignment_count(block: &str, field: &str) -> usize {
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&format!("{field} =")))
        .count()
}

fn validate_array_values_exact(
    values: Vec<String>,
    label: &str,
    expected_values: &[&str],
    errors: &mut Vec<String>,
) {
    let expected: Vec<String> = expected_values
        .iter()
        .map(|value| value.to_string())
        .collect();
    let missing: Vec<String> = expected
        .iter()
        .filter(|value| !values.contains(*value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !expected.contains(*value))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!("{label} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{label} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        errors.push(format!("{label} values must be unique"));
    }
}

fn validate_id_set(ids: &[String], required: Vec<String>, label: &str, errors: &mut Vec<String>) {
    let missing: Vec<String> = required
        .iter()
        .filter(|value| !ids.contains(*value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = ids
        .iter()
        .filter(|value| !required.contains(*value))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!("{label} missing rules: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{label} unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        errors.push(format!("{label} rule IDs must be unique"));
    }
}

fn validate_api_rule_id_set(ids: &[String], errors: &mut Vec<String>) {
    let required = required_rule_ids();
    let missing: Vec<String> = required
        .iter()
        .filter(|value| !ids.contains(*value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = ids
        .iter()
        .filter(|value| !required.contains(*value))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!("API missing rules: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!("API unexpected rules: {}", unexpected.join(", ")));
    }
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        errors.push("API rule IDs must be unique".to_string());
    }
}

fn validate_no_prohibited_api_terms(text: &str, label: &str, errors: &mut Vec<String>) {
    for value in quoted_values(text) {
        if prohibited_network_key(&value) {
            errors.push(format!("{label} contains prohibited network field {value}"));
        }
    }
}

fn validate_no_prohibited_api_field_names(text: &str, label: &str, errors: &mut Vec<String>) {
    for field in assignment_field_names(text) {
        if prohibited_network_key(&field) {
            errors.push(format!("{label} contains prohibited network field {field}"));
        }
    }
}

fn validate_endpoint_field_names(text: &str, errors: &mut Vec<String>) {
    let fields = assignment_field_names(text);
    let unexpected: Vec<String> = fields
        .into_iter()
        .filter(|field| !REQUIRED_ENDPOINT_FIELDS.contains(&field.as_str()))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "API endpoint has unexpected network and VLAN readiness fields: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_no_unsafe_true_flags(text: &str, errors: &mut Vec<String>) {
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("= true") {
            continue;
        }
        let Some((field, _)) = trimmed.split_once('=') else {
            continue;
        };
        let field = field.trim();
        let lower = field.to_ascii_lowercase();
        if [
            "live",
            "provider",
            "execution",
            "action",
            "change",
            "config",
        ]
        .iter()
        .any(|token| lower.contains(token))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_network_key(key) {
                    errors.push(format!("{path}.{key} contains prohibited network field"));
                }
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if contains_prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if !whole_file_text(path, text) && prohibited_network_key(text) {
                errors.push(format!("{path} contains prohibited network value {text}"));
            }
        }
        _ => {}
    }
}

fn validate_no_unsafe_true_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if child.as_bool() == Some(true)
                    && [
                        "live",
                        "provider",
                        "execution",
                        "action",
                        "change",
                        "config",
                    ]
                    .iter()
                    .any(|token| lower.contains(token))
                {
                    errors.push(format!("{path} has unsafe true flag {key}"));
                }
                validate_no_unsafe_true_values(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_unsafe_true_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        _ => {}
    }
}

fn validate_raw_catalog_text(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if contains_prohibited_value(line) {
            errors.push(format!("{path}:{line_number} contains prohibited value"));
        }
        if let Some(key) = catalog_assignment_key(line) {
            if prohibited_network_key(&key) {
                errors.push(format!(
                    "{path}:{line_number} contains prohibited network field {key}"
                ));
            }
        }
        let Some(comment_text) = trimmed_comment_text(line) else {
            continue;
        };
        if SAFE_RAW_CATALOG_COMMENTS.contains(&comment_text.as_str()) {
            continue;
        }
        for term in words(comment_text.trim_start_matches("- ")) {
            let message = format!("{path}:{line_number} contains prohibited network field {term}");
            if prohibited_network_key(&term) && !errors.contains(&message) {
                errors.push(message);
            }
        }
    }
}

fn validate_no_prohibited_test_literals(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if contains_prohibited_test_literal(line) {
            errors.push(format!(
                "{path}:{} contains prohibited test literal",
                index + 1
            ));
        }
    }
}

fn prohibited_network_key(key: &str) -> bool {
    if safe_network_text_value(key) {
        return false;
    }
    let normalized = normalized_key(key);
    if SAFE_NETWORK_GUARD_KEYS.contains(&normalized.as_str()) {
        return false;
    }
    PROHIBITED_NETWORK_KEYS.contains(&normalized.as_str())
        || PROHIBITED_NETWORK_SUBSTRINGS
            .iter()
            .any(|token| normalized.contains(token))
}

fn safe_network_text_value(value: &str) -> bool {
    REQUIRED_WORKFLOWS.contains(&value)
        || REQUIRED_DOMAINS.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
        || ["draft", "static-seed", "review-only", "block"].contains(&value)
}

fn contains_prohibited_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    contains_akia(value)
        || lower.contains("-----begin ") && lower.contains("private key-----")
        || lower.contains("://")
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_mac(value)
        || contains_secret_assignment(&lower)
        || contains_fqdn(value)
        || contains_windows_account(value)
        || contains_email(value)
}

fn contains_prohibited_test_literal(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    contains_akia(value)
        || lower.contains("-----begin ") && lower.contains("private key-----")
        || lower.contains("://")
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_mac(value)
        || contains_secret_assignment(&lower)
        || contains_fqdn(value)
        || contains_double_backslash_account(value)
        || contains_email(value)
}

fn contains_akia(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.as_bytes().windows(20).any(|window| {
        window.starts_with(b"AKIA") && window.iter().all(|byte| byte.is_ascii_alphanumeric())
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

fn contains_uuid(value: &str) -> bool {
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

fn contains_mac(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let trimmed = token.trim_matches(|ch: char| !ch.is_ascii_hexdigit() && ch != ':');
        let parts: Vec<&str> = trimmed.split(':').collect();
        parts.len() == 6
            && parts
                .iter()
                .all(|part| part.len() == 2 && part.chars().all(|ch| ch.is_ascii_hexdigit()))
    })
}

fn contains_secret_assignment(lower: &str) -> bool {
    for term in [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ] {
        let mut offset = 0;
        while let Some(relative) = lower[offset..].find(term) {
            let mut cursor = offset + relative + term.len();
            cursor += lower[cursor..]
                .chars()
                .take_while(|ch| ch.is_ascii_whitespace())
                .map(char::len_utf8)
                .sum::<usize>();
            if matches!(lower.as_bytes().get(cursor), Some(b':') | Some(b'=')) {
                cursor += 1;
                cursor += lower[cursor..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_whitespace())
                    .map(char::len_utf8)
                    .sum::<usize>();
                if lower
                    .as_bytes()
                    .get(cursor)
                    .is_some_and(|byte| !byte.is_ascii_whitespace())
                {
                    return true;
                }
            }
            offset = cursor.min(lower.len());
        }
    }
    false
}

fn contains_fqdn(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let trimmed =
            token.trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '.'));
        let parts: Vec<&str> = trimmed.split('.').collect();
        parts.len() >= 3
            && parts.iter().all(|part| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
            })
            && parts.last().is_some_and(|part| part.len() >= 2)
    })
}

fn contains_windows_account(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let Some((left, right)) = token.split_once('\\') else {
            return false;
        };
        !left.is_empty()
            && !right.is_empty()
            && left.chars().all(windows_account_char)
            && right.chars().all(windows_account_char)
    })
}

fn contains_double_backslash_account(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let Some((left, right)) = token.split_once("\\\\") else {
            return false;
        };
        !left.is_empty()
            && !right.is_empty()
            && left.chars().all(windows_account_char)
            && right.chars().all(windows_account_char)
    })
}

fn windows_account_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')
}

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let trimmed = token.trim_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || matches!(ch, '@' | '.' | '_' | '%' | '+' | '-'))
        });
        let Some((local, domain)) = trimmed.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain.rsplit('.').next().is_some_and(|tld| tld.len() >= 2)
    })
}

fn catalog_assignment_key(line: &str) -> Option<String> {
    let mut text = line.trim_start();
    if let Some(rest) = text.strip_prefix('#') {
        text = rest.trim_start();
    }
    if let Some(rest) = text.strip_prefix('-') {
        text = rest.trim_start();
    }
    let key_len = text
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .map(char::len_utf8)
        .sum::<usize>();
    if key_len == 0 {
        return None;
    }
    let rest = text[key_len..].trim_start();
    (rest.starts_with(':') || rest.starts_with('=')).then(|| text[..key_len].to_string())
}

fn trimmed_comment_text(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix('#')?;
    Some(rest.trim_start().to_string())
}

fn assignment_field_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (field, _) = trimmed.split_once('=')?;
            let field = field.trim();
            (!field.is_empty()
                && field
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'))
            .then(|| field.to_string())
        })
        .collect()
}

fn csharp_without_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut state = CommentState::Code;
    let mut escaped = false;
    while index < bytes.len() {
        match state {
            CommentState::String => {
                output.push(bytes[index] as char);
                if escaped {
                    escaped = false;
                } else if bytes[index] == b'\\' {
                    escaped = true;
                } else if bytes[index] == b'"' {
                    state = CommentState::Code;
                }
                index += 1;
            }
            CommentState::Line => {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                if bytes[index] == b'\n' {
                    state = CommentState::Code;
                }
                index += 1;
            }
            CommentState::Block => {
                if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    output.push(' ');
                    output.push(' ');
                    index += 2;
                    state = CommentState::Code;
                } else {
                    output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
            CommentState::Code => {
                if bytes[index] == b'"' {
                    state = CommentState::String;
                    escaped = false;
                    output.push('"');
                    index += 1;
                } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
                    output.push(' ');
                    output.push(' ');
                    index += 2;
                    state = CommentState::Line;
                } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    output.push(' ');
                    output.push(' ');
                    index += 2;
                    state = CommentState::Block;
                } else {
                    output.push(bytes[index] as char);
                    index += 1;
                }
            }
        }
    }
    output
}

#[derive(Clone, Copy)]
enum CommentState {
    Code,
    String,
    Line,
    Block,
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

fn matching_brace_index(text: &str, brace_start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut index = brace_start;
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
            escaped = false;
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

fn quoted_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let start = index + 1;
        index = start;
        let mut value = String::new();
        let mut escaped = false;
        while index < bytes.len() {
            if escaped {
                value.push(bytes[index] as char);
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                values.push(value);
                index += 1;
                break;
            } else {
                value.push(bytes[index] as char);
            }
            index += 1;
        }
    }
    values
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

fn skip_horizontal_whitespace(text: &str, offset: usize) -> usize {
    text[offset..]
        .bytes()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count()
}

fn skip_ascii_whitespace(text: &str, mut offset: usize) -> usize {
    while text
        .as_bytes()
        .get(offset)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        offset += 1;
    }
    offset
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = start
        .checked_sub(1)
        .and_then(|index| text.as_bytes().get(index))
        .is_none_or(|byte| !identifier_byte(*byte));
    let after = text
        .as_bytes()
        .get(end)
        .is_none_or(|byte| !identifier_byte(*byte));
    before && after
}

fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn last_identifier(text: &str) -> Option<String> {
    let mut end = text.len();
    while end > 0
        && !text
            .as_bytes()
            .get(end - 1)
            .is_some_and(|byte| identifier_byte(*byte))
    {
        end -= 1;
    }
    let mut start = end;
    while start > 0
        && text
            .as_bytes()
            .get(start - 1)
            .is_some_and(|byte| identifier_byte(*byte))
    {
        start -= 1;
    }
    (start < end).then(|| text[start..end].to_string())
}

fn words(text: &str) -> Vec<String> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        .filter(|word| !word.is_empty())
        .map(str::to_string)
        .collect()
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn array_strings(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn array_rule_ids(catalog: &Value) -> Vec<String> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter_map(|rule| string_field(rule, "id"))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn required_rule_ids() -> Vec<String> {
    REQUIRED_RULES
        .iter()
        .map(|rule| rule.id.to_string())
        .collect()
}

fn map_to_value(map: BTreeMap<String, Value>) -> Value {
    Value::Object(map.into_iter().collect())
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
    fn network_vlan_readiness_endpoint_registration_detects_route_alias() {
        let program = format!(
            r#"
app.MapGet("{ENDPOINT}", () => Results.Json(new {{ source = "static-seed" }}));
const string routeAlias = "{ENDPOINT}";
app.MapGet(routeAlias, () => Results.Json(new {{ source = "static-seed" }}));
"#
        );

        let mut errors = Vec::new();
        let _ = endpoint_block(&csharp_without_comments(&program), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("endpoint must be declared exactly once")));
    }
}
