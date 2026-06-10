use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/inventory-coverage-contract.yaml";
const FIXTURE_PATH: &str = "fixtures/inventory/coverage-sample.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/inventory-coverage.md";
const ENDPOINT: &str = "/api/inventory/coverage-contract";
const SUMMARY_ENDPOINT: &str = "/api/inventory/coverage/local/summary";
const REQUIRED_DOMAINS: &[&str] = &[
    "vmware",
    "hyperv",
    "proxmox",
    "veeam",
    "zabbix",
    "servicenow-cmdb",
    "site-catalog",
    "policy-catalog",
];
const REQUIRED_FRESHNESS_STATES: &[&str] = &["current", "stale", "unknown", "blocked"];
const REQUIRED_GAP_TYPES: &[&str] = &[
    "backup-coverage-gap",
    "monitoring-coverage-gap",
    "cmdb-drift",
    "stale-data",
    "ownership-gap",
    "policy-gap",
];
const REQUIRED_DRIFT_SIGNALS: &[&str] = &[
    "identity-mismatch",
    "owner-mismatch",
    "backup-policy-mismatch",
    "monitoring-profile-mismatch",
    "site-placement-mismatch",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Inventory snapshot",
    "Coverage gap list",
    "Stale-data markers",
    "CMDB reconciliation summary",
    "Evidence references",
];
const REQUIRED_RULES: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-provider-inventory-sync",
        "block",
        "Inventory coverage contracts use static or fixture-safe snapshots until provider sync is approved.",
        "Inventory snapshot",
    ),
    (
        "stale-inventory-blocks-execution",
        "block",
        "Stale, unknown, or blocked inventory state prevents approval for live execution.",
        "Stale-data markers",
    ),
    (
        "backup-monitoring-gaps-require-review",
        "block",
        "Backup and monitoring coverage gaps require owner review before protect or observe workflows proceed.",
        "Coverage gap list",
    ),
    (
        "cmdb-drift-requires-reconciliation",
        "block",
        "CMDB identity, ownership, or placement drift routes to reconciliation before publish.",
        "CMDB reconciliation summary",
    ),
];
const REQUIRED_FIXTURE_GAPS: &[&str] = &[
    "backup-coverage-gap",
    "monitoring-coverage-gap",
    "cmdb-drift",
    "stale-data",
    "ownership-gap",
];
const SECRET_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
];
const CONTRACT_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "inventorySyncMode",
    "providerCallsEnabled",
    "externalAccessBlocked",
    "liveExecutionAllowed",
    "coverageDomains",
    "freshnessStates",
    "gapTypes",
    "driftSignals",
    "requiredEvidence",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
];
const SUMMARY_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "providerCallsEnabled",
    "externalAccessBlocked",
    "liveExecutionAllowed",
    "status",
    "summaryMode",
    "resourceCount",
    "gapSummary",
    "backupCoverageGaps",
    "monitoringCoverageGaps",
    "cmdbDrift",
    "staleData",
    "ownershipGaps",
    "policyGaps",
    "remediation",
    "evidence",
];
const ENDPOINT_BINDING_VARIABLES: &[&str] = &[
    "inventoryCoverageDomains",
    "inventoryFreshnessStates",
    "inventoryGapTypes",
    "inventoryDriftSignals",
    "inventoryEvidence",
];
const COMMON_ENDPOINT_IDENTIFIERS: &[&str] =
    &["app", "MapGet", "Results", "Json", "new", "true", "false"];
const PROHIBITED_IDENTIFIER_ALIASES: &[&str] = &[
    "tenantid",
    "tenantids",
    "objectid",
    "objectids",
    "userid",
    "userids",
    "username",
    "usernames",
    "hostname",
    "hostnames",
    "hostid",
    "hostids",
    "endpointname",
    "endpointurl",
    "privateip",
    "privateips",
    "serial",
    "serialnumber",
    "serialnumbers",
    "providerpayload",
    "providerpayloads",
    "rawproviderpayload",
    "rawproviderpayloads",
    "rawinventoryrow",
    "rawinventoryrows",
    "customerid",
    "customerids",
    "recipientdata",
];
const PROHIBITED_IDENTIFIER_TOKENS: &[&str] = &[
    "tenantid",
    "objectid",
    "userid",
    "username",
    "hostname",
    "hostid",
    "endpointname",
    "endpointurl",
    "privateip",
    "serialnumber",
    "providerpayload",
    "rawproviderpayload",
    "rawinventoryrow",
    "customerid",
    "recipientdata",
    "credential",
    "password",
    "secret",
    "token",
    "uuid",
    "moref",
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    fixture: Value,
    program: String,
    readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct CatalogInput {
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct FixtureInput {
    fixture: Value,
}

#[derive(Debug, Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
    fixture: Value,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
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
        .map_err(|error| format!("invalid inventory coverage context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_fixture_value(&context.fixture, &mut errors);
    validate_program_text(
        &context.program,
        &context.catalog,
        &context.fixture,
        &mut errors,
    );
    validate_docs_text(&context.readme, &context.doc, &mut errors);
    let mut values = Map::new();
    values.insert(CATALOG_PATH.to_string(), context.catalog);
    values.insert(FIXTURE_PATH.to_string(), context.fixture);
    values.insert(PROGRAM_PATH.to_string(), Value::String(context.program));
    values.insert(API_README_PATH.to_string(), Value::String(context.readme));
    values.insert(DOC_PATH.to_string(), Value::String(context.doc));
    scan_prohibited_value(&Value::Object(values), "inventory-coverage", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let payload: CatalogInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid inventory coverage catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_values_json(input: &str) -> Result<Vec<String>, String> {
    let payload: FixtureInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid inventory coverage fixture JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_fixture_value(&payload.fixture, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid inventory coverage program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(
        &payload.program,
        &payload.catalog,
        &payload.fixture,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid inventory coverage docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid inventory coverage prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    expect(
        i64_at(catalog, &["version"]) == Some(1),
        errors,
        "inventory coverage version must be 1",
    );
    expect(
        str_at(catalog, &["status"]) == Some("draft"),
        errors,
        "inventory coverage status must be draft",
    );
    expect(
        str_at(catalog, &["inventorySyncMode"]) == Some("mock-contract"),
        errors,
        "inventory sync mode must be mock-contract",
    );
    expect(
        bool_at(catalog, &["providerCallsEnabled"]) == Some(false),
        errors,
        "inventory coverage provider calls must be disabled",
    );
    expect(
        bool_at(catalog, &["externalAccessBlocked"]) == Some(true),
        errors,
        "inventory coverage external access must be blocked",
    );
    expect(
        bool_at(catalog, &["liveExecutionAllowed"]) == Some(false),
        errors,
        "inventory coverage live execution must be disabled",
    );
    validate_exact_array(catalog, "coverageDomains", REQUIRED_DOMAINS, errors);
    validate_required_array(
        catalog,
        "freshnessStates",
        REQUIRED_FRESHNESS_STATES,
        errors,
    );
    validate_required_array(catalog, "gapTypes", REQUIRED_GAP_TYPES, errors);
    validate_required_array(catalog, "driftSignals", REQUIRED_DRIFT_SIGNALS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_catalog_rules(catalog, errors);
}

fn validate_catalog_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = rules_at(catalog, &["rules"]);
    let rule_ids: Vec<String> = rules.iter().map(|rule| rule.id.clone()).collect();
    let rule_details: Vec<(String, String, String)> = rules
        .iter()
        .map(|rule| {
            (
                rule.decision.clone(),
                rule.requirement.clone(),
                rule.evidence.clone(),
            )
        })
        .collect();
    expect(
        unique_count(&rule_ids) == rule_ids.len(),
        errors,
        "inventory coverage rule IDs must be unique",
    );
    expect(
        unique_count(&rule_details) == rule_details.len(),
        errors,
        "inventory coverage rule details must be unique",
    );
    let required_ids: Vec<String> = REQUIRED_RULES
        .iter()
        .map(|(id, _, _, _)| id.to_string())
        .collect();
    let missing = missing_values(&required_ids, &rule_ids);
    let unexpected = missing_values(&rule_ids, &required_ids);
    expect(
        missing.is_empty(),
        errors,
        format!("inventory coverage missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "inventory coverage unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    for (id, decision, requirement, evidence) in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|candidate| candidate.id == *id) else {
            continue;
        };
        expect(
            rule.decision == *decision,
            errors,
            format!("inventory coverage rule {id} decision must match"),
        );
        expect(
            rule.requirement == *requirement,
            errors,
            format!("inventory coverage rule {id} requirement must match"),
        );
        expect(
            rule.evidence == *evidence,
            errors,
            format!("inventory coverage rule {id} evidence must match"),
        );
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_at(catalog, &[field]).unwrap_or_default();
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let required: Vec<String> = required_values
        .iter()
        .map(|value| value.to_string())
        .collect();
    let missing = missing_values(&required, &values);
    expect(
        missing.is_empty(),
        errors,
        format!("{field} missing values: {}", missing.join(", ")),
    );
    expect(
        unique_count(&values) == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

fn validate_exact_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_at(catalog, &[field]).unwrap_or_default();
    validate_required_array(catalog, field, required_values, errors);
    let required: Vec<String> = required_values
        .iter()
        .map(|value| value.to_string())
        .collect();
    let unexpected = missing_values(&values, &required);
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "{field} contains unexpected values: {}",
            unexpected.join(", ")
        ),
    );
}

fn validate_fixture_value(fixture: &Value, errors: &mut Vec<String>) {
    expect(
        i64_at(fixture, &["version"]) == Some(1),
        errors,
        "inventory fixture version must be 1",
    );
    expect(
        str_at(fixture, &["status"]) == Some("fixture"),
        errors,
        "inventory fixture status must be fixture",
    );
    expect(
        bool_at(fixture, &["providerCallsEnabled"]) == Some(false),
        errors,
        "inventory fixture provider calls must be disabled",
    );
    let resources = array_at(fixture, &["resources"]).unwrap_or_default();
    let ids: Vec<String> = resources
        .iter()
        .filter_map(|resource| str_at(resource, &["id"]).map(ToString::to_string))
        .collect();
    expect(
        !resources.is_empty(),
        errors,
        "inventory fixture resources must be non-empty",
    );
    expect(
        ids.len() == resources.len() && unique_count(&ids) == ids.len(),
        errors,
        "inventory fixture resource ids must be unique",
    );
    for (index, resource) in resources.iter().enumerate() {
        validate_fixture_resource(resource, index, errors);
    }
    let summary = gap_summary(fixture);
    let missing_gaps: Vec<&str> = REQUIRED_FIXTURE_GAPS
        .iter()
        .copied()
        .filter(|gap_type| summary.get(*gap_type).copied().unwrap_or(0) == 0)
        .collect();
    expect(
        missing_gaps.is_empty(),
        errors,
        format!(
            "inventory fixture missing expected gaps: {}",
            missing_gaps.join(", ")
        ),
    );
}

fn validate_fixture_resource(resource: &Value, index: usize, errors: &mut Vec<String>) {
    let prefix = format!("inventory fixture resources[{index}]");
    let id = str_at(resource, &["id"]).unwrap_or("");
    expect(
        synthetic_fixture_id(id),
        errors,
        format!("{prefix} id must be synthetic fixture id"),
    );
    expect(
        str_at(resource, &["site"]) == Some("SAMPLE"),
        errors,
        format!("{prefix} site must be SAMPLE"),
    );
    expect(
        str_at(resource, &["environment"]) == Some("production"),
        errors,
        format!("{prefix} environment must be production"),
    );
    expect(
        bool_at(resource, &["ownerPresent"]).is_some(),
        errors,
        format!("{prefix} ownerPresent must be boolean"),
    );
    let freshness_state = str_at(resource, &["freshnessState"]).unwrap_or("");
    expect(
        REQUIRED_FRESHNESS_STATES.contains(&freshness_state),
        errors,
        format!("{prefix} freshnessState is invalid"),
    );
    for field in [
        "expectedBackupPolicy",
        "actualBackupPolicy",
        "expectedMonitoringProfile",
        "actualMonitoringProfile",
        "cmdbStatus",
    ] {
        expect(
            str_at(resource, &[field])
                .map(|value| !value.is_empty())
                .unwrap_or(false),
            errors,
            format!("{prefix} {field} is required"),
        );
    }
}

fn validate_program_text(
    program: &str,
    catalog: &Value,
    fixture: &Value,
    errors: &mut Vec<String>,
) {
    let active_program = strip_csharp_comments(program);
    let contract_block = endpoint_block_from_active(&active_program, ENDPOINT);
    let summary_block = endpoint_block_from_active(&active_program, SUMMARY_ENDPOINT);
    expect(
        !contract_block.is_empty(),
        errors,
        "API missing inventory coverage endpoint",
    );
    expect(
        !summary_block.is_empty(),
        errors,
        "API missing inventory coverage summary endpoint",
    );
    expect(
        exact_string_assignment(&contract_block, "source", "static-seed"),
        errors,
        "API must expose static seed source",
    );
    expect(
        exact_string_assignment(&contract_block, "inventorySyncMode", "mock-contract"),
        errors,
        "API must expose mock inventory sync mode",
    );
    expect(
        exact_endpoint_assignment(&contract_block, "providerCallsEnabled", "false"),
        errors,
        "API must keep provider calls disabled",
    );
    expect(
        exact_endpoint_assignment(&contract_block, "externalAccessBlocked", "true"),
        errors,
        "API must keep external access blocked",
    );
    expect(
        exact_endpoint_assignment(&contract_block, "liveExecutionAllowed", "false"),
        errors,
        "API must keep live execution disabled",
    );
    validate_program_array(
        &active_program,
        &contract_block,
        "coverageDomains",
        "inventoryCoverageDomains",
        string_array_at(catalog, &["coverageDomains"]).unwrap_or_default(),
        errors,
    );
    validate_program_array(
        &active_program,
        &contract_block,
        "freshnessStates",
        "inventoryFreshnessStates",
        string_array_at(catalog, &["freshnessStates"]).unwrap_or_default(),
        errors,
    );
    validate_program_array(
        &active_program,
        &contract_block,
        "gapTypes",
        "inventoryGapTypes",
        string_array_at(catalog, &["gapTypes"]).unwrap_or_default(),
        errors,
    );
    validate_program_array(
        &active_program,
        &contract_block,
        "driftSignals",
        "inventoryDriftSignals",
        string_array_at(catalog, &["driftSignals"]).unwrap_or_default(),
        errors,
    );
    validate_program_array(
        &active_program,
        &contract_block,
        "requiredEvidence",
        "inventoryEvidence",
        string_array_at(catalog, &["requiredEvidence"]).unwrap_or_default(),
        errors,
    );
    let summary = gap_summary(fixture);
    let resources = array_at(fixture, &["resources"]).unwrap_or_default();
    expect(
        exact_string_assignment(&summary_block, "source", "local-mock"),
        errors,
        "API summary must expose local mock source",
    );
    expect(
        exact_endpoint_assignment(&summary_block, "providerCallsEnabled", "false"),
        errors,
        "API summary must keep provider calls disabled",
    );
    expect(
        exact_endpoint_assignment(&summary_block, "externalAccessBlocked", "true"),
        errors,
        "API summary must keep external access blocked",
    );
    expect(
        exact_endpoint_assignment(&summary_block, "liveExecutionAllowed", "false"),
        errors,
        "API summary must keep live execution disabled",
    );
    expect(
        exact_string_assignment(&summary_block, "summaryMode", "aggregate-only"),
        errors,
        "API summary must stay aggregate-only",
    );
    expect(
        summary_block.contains(&format!("resourceCount = {}", resources.len())),
        errors,
        "API summary resource count must match fixture",
    );
    expect(
        summary_block.contains(&format!(
            "backupCoverageGaps = {}",
            summary.get("backup-coverage-gap").copied().unwrap_or(0)
        )),
        errors,
        "API backup gap count must match fixture",
    );
    expect(
        summary_block.contains(&format!(
            "monitoringCoverageGaps = {}",
            summary.get("monitoring-coverage-gap").copied().unwrap_or(0)
        )),
        errors,
        "API monitoring gap count must match fixture",
    );
    expect(
        summary_block.contains(&format!(
            "cmdbDrift = {}",
            summary.get("cmdb-drift").copied().unwrap_or(0)
        )),
        errors,
        "API CMDB drift count must match fixture",
    );
    expect(
        summary_block.contains(&format!(
            "staleData = {}",
            summary.get("stale-data").copied().unwrap_or(0)
        )),
        errors,
        "API stale data count must match fixture",
    );
    expect(
        summary_block.contains(&format!(
            "ownershipGaps = {}",
            summary.get("ownership-gap").copied().unwrap_or(0)
        )),
        errors,
        "API ownership gap count must match fixture",
    );
    expect(
        summary_block.contains("evidence = inventoryEvidence"),
        errors,
        "API summary must use inventory evidence",
    );
    validate_api_rules(&active_program, catalog, errors);
    validate_endpoint_property_identifiers(
        &contract_block,
        CONTRACT_ENDPOINT_FIELDS,
        errors,
        "contract",
    );
    validate_endpoint_property_identifiers(
        &summary_block,
        SUMMARY_ENDPOINT_FIELDS,
        errors,
        "summary",
    );
    validate_no_unsafe_true_flags(&contract_block, errors);
    validate_no_unsafe_true_flags(&summary_block, errors);
}

fn validate_program_array(
    active_program: &str,
    contract_block: &str,
    property: &str,
    variable: &str,
    expected: Vec<String>,
    errors: &mut Vec<String>,
) {
    expect(
        exact_endpoint_assignment(contract_block, property, variable),
        errors,
        format!("API inventory coverage endpoint must return {property}"),
    );
    let actual = array_assignment_values(active_program, variable);
    let missing = missing_values(&expected, &actual);
    let unexpected = missing_values(&actual, &expected);
    expect(
        missing.is_empty(),
        errors,
        format!("API missing {property} values: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "API has unexpected {property} values: {}",
            unexpected.join(", ")
        ),
    );
}

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == value
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == format!("\"{value}\"")
}

fn assignment_values_for_field(block: &str, field: &str) -> Vec<String> {
    assignment_values(block)
        .into_iter()
        .filter_map(|(candidate, value)| (candidate == field).then_some(value))
        .collect()
}

fn assignment_values(block: &str) -> Vec<(String, String)> {
    block
        .lines()
        .filter_map(|line| {
            let index = line.find('=')?;
            let field = field_before_equals(line, index)?;
            let value = line[index + 1..]
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string();
            Some((field, value))
        })
        .collect()
}

fn field_before_equals(text: &str, equals_index: usize) -> Option<String> {
    let prefix = &text[..equals_index];
    let trimmed = prefix.trim_end();
    let end = trimmed.len();
    let start = trimmed
        .char_indices()
        .rev()
        .find(|(_, ch)| !(*ch == '_' || ch.is_ascii_alphanumeric()))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let field = &trimmed[start..end];
    if field
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        Some(field.to_string())
    } else {
        None
    }
}

fn validate_endpoint_property_identifiers(
    block: &str,
    expected_fields: &[&str],
    errors: &mut Vec<String>,
    label: &str,
) {
    for identifier in code_identifiers(block) {
        if expected_fields.contains(&identifier.as_str())
            || ENDPOINT_BINDING_VARIABLES.contains(&identifier.as_str())
            || COMMON_ENDPOINT_IDENTIFIERS.contains(&identifier.as_str())
        {
            continue;
        }
        if prohibited_inventory_identifier(&identifier) {
            errors.push(format!(
                "API inventory coverage {label} endpoint references prohibited identifier {identifier}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in assignment_values(block) {
        if value == "true" && unsafe_true_key(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn code_identifiers(text: &str) -> BTreeSet<String> {
    let mut identifiers = BTreeSet::new();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    let bytes = text.as_bytes();
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
            index += 1;
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            identifiers.insert(text[start..index].to_string());
        } else {
            index += 1;
        }
    }
    identifiers
}

fn validate_api_rules(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let block = endpoint_block_from_active(program, ENDPOINT);
    if block.is_empty() {
        errors.push("API missing inventory coverage endpoint".to_string());
        return;
    }
    let api_rules = parse_api_rules(&block);
    let catalog_rules = rules_at(catalog, &["rules"]);
    let catalog_rule_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_rule_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_rule_details: Vec<(String, String, String)> = api_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.clone(),
                rule.requirement.clone(),
                rule.evidence.clone(),
            )
        })
        .collect();
    for id in missing_values(&catalog_rule_ids, &api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in missing_values(&api_rule_ids, &catalog_rule_ids) {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(
        unique_count(&api_rule_ids) == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        unique_count(&api_rule_details) == api_rule_details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in catalog_rules {
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

fn endpoint_block_from_active(program: &str, endpoint: &str) -> String {
    let marker = format!("app.MapGet(\"{endpoint}\",");
    let Some(start_index) = program.find(&marker) else {
        return String::new();
    };
    let next_endpoint = program[start_index + 1..]
        .find("\napp.MapGet(")
        .map(|index| start_index + 1 + index)
        .unwrap_or(program.len());
    program[start_index..next_endpoint].to_string()
}

fn strip_csharp_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut in_char = false;
    let mut escaped = false;
    while let Some(current) = chars.next() {
        if in_string {
            output.push(current);
            escaped = !escaped && current == '\\';
            if current == '"' && !escaped {
                in_string = false;
            } else if current != '\\' {
                escaped = false;
            }
            continue;
        }
        if in_char {
            output.push(current);
            escaped = !escaped && current == '\\';
            if current == '\'' && !escaped {
                in_char = false;
            } else if current != '\\' {
                escaped = false;
            }
            continue;
        }
        match (current, chars.peek().copied()) {
            ('"', _) => {
                in_string = true;
                output.push(current);
            }
            ('\'', _) => {
                in_char = true;
                output.push(current);
            }
            ('/', Some('/')) => {
                chars.next();
                for value in chars.by_ref() {
                    if value == '\n' {
                        output.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut previous = '\0';
                for value in chars.by_ref() {
                    if value == '\n' {
                        output.push('\n');
                    }
                    if previous == '*' && value == '/' {
                        break;
                    }
                    previous = value;
                }
            }
            _ => output.push(current),
        }
    }
    output
}

fn array_assignment_values(program: &str, variable: &str) -> Vec<String> {
    let marker = format!("var {variable} = new[]");
    let Some(start) = program.find(&marker) else {
        return Vec::new();
    };
    let Some(open_offset) = program[start..].find('{') else {
        return Vec::new();
    };
    let open = start + open_offset;
    let Some(close_offset) = program[open..].find('}') else {
        return Vec::new();
    };
    string_literals(&program[open..open + close_offset])
}

fn string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((start, value)) = chars.next() {
        if value != '"' {
            continue;
        }
        let content_start = start + value.len_utf8();
        let mut escaped = false;
        for (index, candidate) in chars.by_ref() {
            if candidate == '"' && !escaped {
                values.push(text[content_start..index].to_string());
                break;
            }
            escaped = !escaped && candidate == '\\';
            if candidate != '\\' {
                escaped = false;
            }
        }
    }
    values
}

fn parse_api_rules(block: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let marker = "new { id = \"";
    let mut rest = block;
    while let Some(offset) = rest.find(marker) {
        rest = &rest[offset + marker.len()..];
        let Some((id, after_id)) = take_until_quote(rest) else {
            break;
        };
        let object_end = after_id.find('}').unwrap_or(after_id.len());
        let object = &after_id[..object_end];
        let Some(decision) = field_value(object, "decision") else {
            rest = &after_id[object_end..];
            continue;
        };
        let Some(requirement) = field_value(object, "requirement") else {
            rest = &after_id[object_end..];
            continue;
        };
        let Some(evidence) = field_value(object, "evidence") else {
            rest = &after_id[object_end..];
            continue;
        };
        rules.push(Rule {
            id: id.to_string(),
            decision,
            requirement,
            evidence,
        });
        rest = &after_id[object_end..];
    }
    rules
}

fn field_value(segment: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = segment.find(&marker)? + marker.len();
    take_until_quote(&segment[start..]).map(|(value, _)| value.to_string())
}

fn take_until_quote(value: &str) -> Option<(&str, &str)> {
    let end = value.find('"')?;
    Some((&value[..end], &value[end + 1..]))
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing inventory coverage endpoint",
    );
    expect(
        readme.contains(SUMMARY_ENDPOINT),
        errors,
        "API README missing inventory coverage summary endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "inventory coverage doc missing local endpoint",
    );
    expect(
        doc.contains(SUMMARY_ENDPOINT),
        errors,
        "inventory coverage doc missing summary endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "inventory coverage doc must prohibit provider calls",
    );
    expect(
        doc.contains("Stale data blocks execution"),
        errors,
        "inventory coverage doc must block stale data",
    );
    expect(
        doc.contains("not raw provider payloads"),
        errors,
        "inventory coverage doc must reject raw provider payloads",
    );
    expect(
        readme.contains("VMware, Hyper-V, and Proxmox domains"),
        errors,
        "API README missing hypervisor inventory coverage domains",
    );
    expect(
        doc.contains("VMware, Hyper-V, Proxmox"),
        errors,
        "inventory coverage doc missing hypervisor coverage domains",
    );
    expect(
        doc.contains(FIXTURE_PATH),
        errors,
        "inventory coverage doc missing fixture path",
    );
}

fn gap_summary(fixture: &Value) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for resource in array_at(fixture, &["resources"]).unwrap_or_default() {
        for gap_type in gap_types_for(resource) {
            *counts.entry(gap_type).or_insert(0) += 1;
        }
    }
    counts
}

fn gap_types_for(resource: &Value) -> Vec<String> {
    let mut gaps = Vec::new();
    if str_at(resource, &["freshnessState"]) != Some("current") {
        gaps.push("stale-data".to_string());
    }
    if bool_at(resource, &["ownerPresent"]) != Some(true) {
        gaps.push("ownership-gap".to_string());
    }
    if str_at(resource, &["expectedBackupPolicy"]) != str_at(resource, &["actualBackupPolicy"]) {
        gaps.push("backup-coverage-gap".to_string());
    }
    if str_at(resource, &["expectedMonitoringProfile"])
        != str_at(resource, &["actualMonitoringProfile"])
    {
        gaps.push("monitoring-coverage-gap".to_string());
    }
    if str_at(resource, &["cmdbStatus"]) != Some("matched") {
        gaps.push("cmdb-drift".to_string());
    }
    gaps
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_inventory_identifier(key) {
                    errors.push(format!("{child_path} contains prohibited inventory field"));
                }
                if child.as_bool() == Some(true) && unsafe_true_key(key) {
                    errors.push(format!("{child_path} has unsafe true flag {key}"));
                }
                scan_prohibited_value(child, &child_path, errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            let prohibited = if whole_file_text(path, text) {
                contains_prohibited_file_value(text)
                    || contains_prohibited_file_identifier_assignment(path, text)
            } else {
                contains_prohibited_value(text)
            };
            if prohibited {
                errors.push(format!("{path} contains prohibited value"));
            }
        }
        _ => {}
    }
}

fn contains_prohibited_value(text: &str) -> bool {
    contains_prohibited_file_value(text) || contains_prohibited_identifier_assignment(text)
}

fn contains_prohibited_file_value(text: &str) -> bool {
    contains_aws_access_key(text)
        || contains_private_key_header(text)
        || contains_url(text)
        || contains_private_ip(text)
        || contains_uuid(text)
        || SECRET_ASSIGNMENT_KEYS
            .iter()
            .any(|key| contains_assignment(text, key))
}

fn contains_prohibited_file_identifier_assignment(path: &str, text: &str) -> bool {
    if path.ends_with(PROGRAM_PATH) {
        [ENDPOINT, SUMMARY_ENDPOINT].iter().any(|endpoint| {
            let block = endpoint_block_from_active(text, endpoint);
            !block.is_empty() && contains_prohibited_identifier_assignment(&block)
        })
    } else {
        contains_prohibited_identifier_assignment(text)
    }
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn contains_aws_access_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    for window in bytes.windows(20) {
        if window[0..4].eq_ignore_ascii_case(b"AKIA")
            && window[4..20]
                .iter()
                .all(|value| value.is_ascii_digit() || value.is_ascii_uppercase())
        {
            return true;
        }
    }
    false
}

fn contains_private_key_header(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

fn contains_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(offset) = lower[search_from..].find("://") {
        let marker = search_from + offset;
        let scheme_start = lower[..marker]
            .char_indices()
            .rev()
            .find(|(_, value)| !(value.is_ascii_alphanumeric() || matches!(value, '+' | '.' | '-')))
            .map(|(index, value)| index + value.len_utf8())
            .unwrap_or(0);
        let scheme = &lower[scheme_start..marker];
        if scheme
            .chars()
            .next()
            .map(|value| value.is_ascii_alphabetic())
            .unwrap_or(false)
            && scheme
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '.' | '-'))
            && lower[marker + 3..]
                .chars()
                .next()
                .map(|value| !value.is_whitespace())
                .unwrap_or(false)
        {
            return true;
        }
        search_from = marker + 3;
    }
    false
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|value: char| !(value.is_ascii_digit() || value == '.'))
        .filter(|token| token.contains('.'))
        .any(|token| {
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() < 4 {
                return false;
            }
            parts.windows(4).any(|octets| {
                let parsed: Option<Vec<u8>> = octets
                    .iter()
                    .map(|octet| octet.parse::<u8>().ok())
                    .collect();
                let Some(octets) = parsed else {
                    return false;
                };
                octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            })
        })
}

fn contains_uuid(text: &str) -> bool {
    for token in text.split(|value: char| !(value.is_ascii_hexdigit() || value == '-')) {
        let parts: Vec<&str> = token.split('-').collect();
        if parts.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(parts.iter())
                .all(|(length, part)| {
                    part.len() == *length && part.chars().all(|c| c.is_ascii_hexdigit())
                })
        {
            return true;
        }
    }
    false
}

fn contains_assignment(text: &str, key: &str) -> bool {
    let normalized_key = normalize_key(key);
    for (separator, value) in text.char_indices() {
        if !matches!(value, ':' | '=') {
            continue;
        }
        let raw_key = assignment_key_before(&text[..separator]);
        let normalized = normalize_key(raw_key);
        if normalized.contains(&normalized_key)
            && !safe_assignment_key(&normalized, &text[separator + value.len_utf8()..])
            && !text[separator + value.len_utf8()..].trim_start().is_empty()
        {
            return true;
        }
    }
    false
}

fn contains_prohibited_identifier_assignment(text: &str) -> bool {
    for (separator, value) in text.char_indices() {
        if !matches!(value, ':' | '=') {
            continue;
        }
        let raw_key = assignment_key_before(&text[..separator]);
        if raw_key.is_empty() {
            continue;
        }
        if prohibited_inventory_identifier(raw_key)
            && !safe_assignment_key(
                &normalize_key(raw_key),
                &text[separator + value.len_utf8()..],
            )
            && !text[separator + value.len_utf8()..].trim_start().is_empty()
        {
            return true;
        }
    }
    false
}

fn is_key_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, '_' | '-')
}

fn assignment_key_before(text: &str) -> &str {
    let trimmed = text.trim_end();
    if let Some(before_quote) = trimmed.strip_suffix('"') {
        if let Some(start) = before_quote.rfind('"') {
            return &before_quote[start + 1..];
        }
    }
    let start = trimmed
        .char_indices()
        .rev()
        .find(|(_, value)| !is_key_char(*value))
        .map(|(index, value)| index + value.len_utf8())
        .unwrap_or(0);
    &trimmed[start..]
}

fn normalize_key(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|candidate| candidate.is_ascii_alphanumeric())
        .collect()
}

fn safe_assignment_key(normalized_key: &str, value: &str) -> bool {
    normalized_key.ends_with("allowed") && value.trim_start().starts_with("false")
}

fn unsafe_true_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    prohibited_inventory_identifier(key)
        || [
            "live",
            "providerpayload",
            "raw",
            "tenantid",
            "objectid",
            "privateip",
        ]
        .iter()
        .any(|term| normalized.contains(term))
}

fn prohibited_inventory_identifier(value: &str) -> bool {
    let normalized = normalize_key(value);
    if safe_inventory_identifier(&normalized) {
        return false;
    }
    PROHIBITED_IDENTIFIER_ALIASES.contains(&normalized.as_str())
        || PROHIBITED_IDENTIFIER_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn safe_inventory_identifier(normalized: &str) -> bool {
    [
        CONTRACT_ENDPOINT_FIELDS,
        SUMMARY_ENDPOINT_FIELDS,
        ENDPOINT_BINDING_VARIABLES,
        COMMON_ENDPOINT_IDENTIFIERS,
        REQUIRED_DOMAINS,
        REQUIRED_FRESHNESS_STATES,
        REQUIRED_GAP_TYPES,
        REQUIRED_DRIFT_SIGNALS,
        REQUIRED_EVIDENCE,
        &[
            "version",
            "status",
            "draft",
            "fixture",
            "source",
            "static-seed",
            "local-mock",
            "mock-contract",
            "aggregate-only",
            "block",
            "true",
            "false",
            "resources",
            "site",
            "sample",
            "environment",
            "production",
            "ownerpresent",
            "expectedbackuppolicy",
            "actualbackuppolicy",
            "expectedmonitoringprofile",
            "actualmonitoringprofile",
            "cmdbstatus",
            "freshnessstate",
            "matched",
            "current",
            "stale",
            "unknown",
            "blocked",
            "missing",
            "drift",
            "dailystandard",
            "goldretention",
            "linuxactiveagent",
            "databaseprofile",
            "windowsdefault",
        ],
    ]
    .into_iter()
    .flatten()
    .any(|safe| normalize_key(safe) == normalized)
        || REQUIRED_RULES
            .iter()
            .any(|(id, decision, requirement, evidence)| {
                [id, decision, requirement, evidence]
                    .iter()
                    .any(|safe| normalize_key(safe) == normalized)
            })
}

fn rules_at(value: &Value, path: &[&str]) -> Vec<Rule> {
    array_at(value, path)
        .unwrap_or_default()
        .iter()
        .map(|rule| Rule {
            id: str_at(rule, &["id"]).unwrap_or("").to_string(),
            decision: str_at(rule, &["decision"]).unwrap_or("").to_string(),
            requirement: str_at(rule, &["requirement"]).unwrap_or("").to_string(),
            evidence: str_at(rule, &["evidence"]).unwrap_or("").to_string(),
        })
        .collect()
}

fn synthetic_fixture_id(value: &str) -> bool {
    value
        .strip_prefix("fixture-")
        .map(|suffix| {
            !suffix.is_empty()
                && suffix.chars().all(|candidate| {
                    candidate.is_ascii_lowercase() || candidate.is_ascii_digit() || candidate == '-'
                })
        })
        .unwrap_or(false)
}

fn string_array_at(value: &Value, path: &[&str]) -> Option<Vec<String>> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    let items = current.as_array()?;
    items
        .iter()
        .map(|item| item.as_str().map(ToString::to_string))
        .collect()
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> Option<Vec<&'a Value>> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current.as_array()?.iter().collect())
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

fn i64_at(value: &Value, path: &[&str]) -> Option<i64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_i64()
}

fn missing_values(required: &[String], actual: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|value| !actual.contains(value))
        .cloned()
        .collect()
}

fn unique_count<T: Ord + Clone>(values: &[T]) -> usize {
    values.iter().cloned().collect::<BTreeSet<T>>().len()
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
            "inventorySyncMode": "mock-contract",
            "providerCallsEnabled": false,
            "externalAccessBlocked": true,
            "liveExecutionAllowed": false,
            "coverageDomains": REQUIRED_DOMAINS,
            "freshnessStates": REQUIRED_FRESHNESS_STATES,
            "gapTypes": REQUIRED_GAP_TYPES,
            "driftSignals": REQUIRED_DRIFT_SIGNALS,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "rules": REQUIRED_RULES.iter().map(|(id, decision, requirement, evidence)| json!({
                "id": id,
                "decision": decision,
                "requirement": requirement,
                "evidence": evidence,
            })).collect::<Vec<_>>()
        })
    }

    fn fixture() -> Value {
        json!({
            "version": 1,
            "status": "fixture",
            "providerCallsEnabled": false,
            "resources": [
                {
                    "id": "fixture-web-001",
                    "site": "SAMPLE",
                    "environment": "production",
                    "ownerPresent": true,
                    "expectedBackupPolicy": "daily-standard",
                    "actualBackupPolicy": "missing",
                    "expectedMonitoringProfile": "linux-active-agent",
                    "actualMonitoringProfile": "linux-active-agent",
                    "cmdbStatus": "matched",
                    "freshnessState": "current"
                },
                {
                    "id": "fixture-app-002",
                    "site": "SAMPLE",
                    "environment": "production",
                    "ownerPresent": true,
                    "expectedBackupPolicy": "daily-standard",
                    "actualBackupPolicy": "daily-standard",
                    "expectedMonitoringProfile": "linux-active-agent",
                    "actualMonitoringProfile": "missing",
                    "cmdbStatus": "matched",
                    "freshnessState": "current"
                },
                {
                    "id": "fixture-db-003",
                    "site": "SAMPLE",
                    "environment": "production",
                    "ownerPresent": false,
                    "expectedBackupPolicy": "gold-retention",
                    "actualBackupPolicy": "gold-retention",
                    "expectedMonitoringProfile": "database-profile",
                    "actualMonitoringProfile": "database-profile",
                    "cmdbStatus": "drift",
                    "freshnessState": "current"
                },
                {
                    "id": "fixture-ops-004",
                    "site": "SAMPLE",
                    "environment": "production",
                    "ownerPresent": true,
                    "expectedBackupPolicy": "daily-standard",
                    "actualBackupPolicy": "daily-standard",
                    "expectedMonitoringProfile": "windows-default",
                    "actualMonitoringProfile": "windows-default",
                    "cmdbStatus": "matched",
                    "freshnessState": "stale"
                }
            ]
        })
    }

    fn csharp_array(values: &[&str]) -> String {
        values
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn csharp_rules() -> String {
        REQUIRED_RULES
            .iter()
            .map(|(id, decision, requirement, evidence)| {
                format!(
                    "new {{ id = \"{id}\", decision = \"{decision}\", requirement = \"{requirement}\", evidence = \"{evidence}\" }}"
                )
            })
            .collect::<Vec<_>>()
            .join(",\n        ")
    }

    fn valid_program() -> String {
        format!(
            r#"var inventoryCoverageDomains = new[] {{ {} }};
var inventoryFreshnessStates = new[] {{ {} }};
var inventoryGapTypes = new[] {{ {} }};
var inventoryDriftSignals = new[] {{ {} }};
var inventoryEvidence = new[] {{ {} }};

app.MapGet("{ENDPOINT}", () => Results.Json(new
{{
    source = "static-seed",
    inventorySyncMode = "mock-contract",
    providerCallsEnabled = false,
    externalAccessBlocked = true,
    liveExecutionAllowed = false,
    coverageDomains = inventoryCoverageDomains,
    freshnessStates = inventoryFreshnessStates,
    gapTypes = inventoryGapTypes,
    driftSignals = inventoryDriftSignals,
    requiredEvidence = inventoryEvidence,
    rules = new[]
    {{
        {}
    }}
}}));

app.MapGet("{SUMMARY_ENDPOINT}", () => Results.Json(new
{{
    source = "local-mock",
    providerCallsEnabled = false,
    externalAccessBlocked = true,
    liveExecutionAllowed = false,
    status = "blocked",
    summaryMode = "aggregate-only",
    resourceCount = 4,
    gapSummary = new
    {{
        backupCoverageGaps = 1,
        monitoringCoverageGaps = 1,
        cmdbDrift = 1,
        staleData = 1,
        ownershipGaps = 1,
        policyGaps = 0
    }},
    remediation = "Refresh stale inventory and route coverage gaps to owner review before approval.",
    evidence = inventoryEvidence
}}));"#,
            csharp_array(REQUIRED_DOMAINS),
            csharp_array(REQUIRED_FRESHNESS_STATES),
            csharp_array(REQUIRED_GAP_TYPES),
            csharp_array(REQUIRED_DRIFT_SIGNALS),
            csharp_array(REQUIRED_EVIDENCE),
            csharp_rules()
        )
    }

    fn program_errors(program: &str) -> Vec<String> {
        let mut errors = Vec::new();
        validate_program_text(program, &catalog(), &fixture(), &mut errors);
        errors
    }

    #[test]
    fn comments_and_commented_valid_examples_are_ignored() {
        let program = valid_program().replacen(
            "source = \"static-seed\",",
            "// source = \"static-seed\",\n    source = \"live-provider\",",
            1,
        );
        let errors = program_errors(&program);

        assert!(errors
            .iter()
            .any(|error| error.contains("static seed source")));
    }

    #[test]
    fn endpoint_suffix_route_decoy_is_not_registered() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}-live\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let errors = program_errors(&program);

        assert!(errors
            .iter()
            .any(|error| error.contains("missing inventory coverage endpoint")));
    }

    #[test]
    fn duplicate_rule_ids_and_details_are_rejected() {
        let mut catalog = catalog();
        let duplicate_rule = catalog
            .get("rules")
            .and_then(Value::as_array)
            .and_then(|rules| rules.first())
            .cloned()
            .expect("catalog has rules");
        catalog
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("catalog rules are an array")
            .push(duplicate_rule);
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("rule IDs must be unique")));
        assert!(errors
            .iter()
            .any(|error| error.contains("rule details must be unique")));
    }

    #[test]
    fn source_assignment_spoofing_is_rejected() {
        let program = valid_program().replacen(
            "source = \"static-seed\",",
            "source = liveSource,\n    source = \"static-seed\",",
            1,
        );
        let errors = program_errors(&program);

        assert!(errors
            .iter()
            .any(|error| error.contains("static seed source")));
    }

    #[test]
    fn endpoint_property_identifier_scan_is_not_quoted_value_only() {
        let program = valid_program().replacen(
            "source = \"static-seed\",",
            "source = safeSummary.endpointName,",
            1,
        );
        let errors = program_errors(&program);

        assert!(errors.iter().any(|error| error.contains("endpointName")));
    }

    #[test]
    fn broad_suffix_provider_identifier_true_flag_is_rejected() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &json!({ "providerPayloadAllowed": true }),
            "synthetic",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("providerPayloadAllowed")));
    }

    #[test]
    fn unsafe_provider_identifying_literals_are_rejected() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String(r#""providerTenantId": "placeholder""#.to_string()),
            "synthetic.notes",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("synthetic.notes") && error.contains("prohibited")));
    }

    #[test]
    fn multiline_file_path_provider_identifier_assignments_are_rejected() {
        let mut errors = Vec::new();
        let program = format!(
            r#"app.MapGet("{ENDPOINT}", () => Results.Json(new
{{
    source = "static-seed",
    providerTenantId = "placeholder"
}}));"#
        );

        scan_prohibited_value(
            &Value::String(program),
            "inventory-coverage/api/Ryuki.Platform.Api/Program.cs",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("Program.cs") && error.contains("prohibited")));
    }
}
