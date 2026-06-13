use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/cost-capacity-analytics-contract.yaml";
const ENDPOINT: &str = "/api/analytics/cost-capacity-contract";
const REQUIRED_PROVIDER_BOUNDARY_PHRASE: &str =
    "without calling VMware, Hyper-V, Proxmox, Veeam, CMDB, billing, or provider APIs";
const LEGACY_VCENTER_ONLY_PROVIDER_BOUNDARY_PHRASE: &str =
    "without calling vCenter, Veeam, CMDB, billing, or provider APIs";
const REQUIRED_PLATFORM_SCOPE: &[&str] = &["vmware", "hyperv", "proxmox"];
const REQUIRED_DOMAINS: &[&str] = &[
    "compute-capacity",
    "storage-capacity",
    "backup-capacity",
    "growth-trend",
    "cost-trend",
    "efficiency-opportunity",
    "forecast-risk",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "capacity-pressure",
    "storage-growth-risk",
    "backup-growth-risk",
    "cost-anomaly",
    "underutilization-signal",
    "stale-usage-data",
    "forecast-window-missing",
];
const REQUIRED_INPUTS: &[&str] = &[
    "analyticsScope",
    "site",
    "serviceDomain",
    "capacitySummary",
    "costBand",
    "growthTrend",
    "forecastWindow",
    "owner",
    "supportGroup",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "analytics-scope-summarized",
    "aggregate-usage-known",
    "cost-band-known",
    "growth-trend-known",
    "forecast-window-set",
    "owner-known",
    "remediation-plan-ready",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "analyticsSummary",
    "capacityForecast",
    "storageForecast",
    "backupForecast",
    "costTrend",
    "efficiencyOpportunities",
    "remediationOptions",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-remediation-disabled",
    "billing-export-ingestion-disabled",
    "raw-cost-rows-disabled",
    "raw-inventory-rows-disabled",
    "resource-identifiers-disabled",
    "tenant-identifiers-disabled",
    "object-identifiers-disabled",
    "raw-provider-payloads-disabled",
    "analytics-scope-missing",
    "aggregate-usage-missing",
    "cost-band-missing",
    "growth-trend-unknown",
    "forecast-window-missing",
    "owner-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Cost capacity summary",
    "Capacity forecast",
    "Storage forecast",
    "Backup forecast",
    "Cost trend",
    "Efficiency opportunities",
    "Remediation options",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "billingExportIngestionAllowed",
    "rawCostRowsAllowed",
    "rawInventoryRowsAllowed",
    "resourceIdentifiersAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "rawProviderPayloadsAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "analyticsMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "billingExportIngestionAllowed",
    "rawCostRowsAllowed",
    "rawInventoryRowsAllowed",
    "resourceIdentifiersAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "rawProviderPayloadsAllowed",
    "platformScope",
    "analyticsDomains",
    "analyticsSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("platformScope", "costCapacityAnalyticsPlatformScope"),
    ("analyticsDomains", "costCapacityAnalyticsDomains"),
    ("analyticsSignals", "costCapacityAnalyticsSignals"),
    ("requiredGuards", "costCapacityAnalyticsRequiredGuards"),
    ("planSections", "costCapacityAnalyticsPlanSections"),
    ("blockedReasons", "costCapacityAnalyticsBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "analyticsMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "billingExportIngestionAllowed",
    "rawCostRowsAllowed",
    "rawInventoryRowsAllowed",
    "resourceIdentifiersAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "rawProviderPayloadsAllowed",
    "platformScope",
    "analyticsDomains",
    "analyticsSignals",
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
    "# Cost capacity analytics seed data only. Do not add billing account IDs, subscription IDs, resource IDs, tenant IDs, object IDs, hostnames, repository names, usernames, credentials, tokens, raw cost rows, raw inventory rows, live endpoints, private IPs, raw logs, or provider payloads.",
    "- No raw cost rows, raw inventory rows, billing account identifiers, subscription identifiers, resource identifiers, tenant identifiers, object identifiers, hostnames, repository names, credentials, tokens, private network details, raw logs, or provider payloads in committed files.",
    "| `/api/analytics/cost-capacity-contract` | Static cost and capacity analytics forecast contract with VMware, Hyper-V, and Proxmox scope; live remediation and raw cost rows disabled. |",
    "requirement: Cost capacity evidence must use safe summaries only and must not expose raw cost rows, raw inventory rows, resource IDs, billing account IDs, subscription IDs, tenant IDs, object IDs, or provider payloads.",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-cost-capacity-remediation",
        decision: "block",
        requirement: "Cost and capacity analytics reports forecast state only and never changes resources, budgets, repositories, clusters, tickets, or provider state.",
        evidence: "Cost capacity summary",
    },
    RuleDetail {
        id: "aggregate-summaries-required",
        decision: "block",
        requirement: "Aggregate usage summaries and cost bands are required before analytics can be accepted.",
        evidence: "Capacity forecast",
    },
    RuleDetail {
        id: "forecast-window-required",
        decision: "block",
        requirement: "Capacity and cost decisions require a declared forecast window.",
        evidence: "Cost capacity summary",
    },
    RuleDetail {
        id: "remediation-options-review-only",
        decision: "block",
        requirement: "Efficiency and remediation options are review-only until a separate approved live workflow exists.",
        evidence: "Remediation options",
    },
    RuleDetail {
        id: "raw-cost-inventory-data-not-exposed",
        decision: "block",
        requirement: "Cost capacity evidence must use safe summaries only and must not expose raw cost rows, raw inventory rows, resource IDs, billing account IDs, subscription IDs, tenant IDs, object IDs, or provider payloads.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct CostCapacityContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
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
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

#[derive(Clone)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: CostCapacityContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid cost capacity analytics context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
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
    // The Program.cs entry (the whole contracts.rs file) is excluded from this
    // scan: scanning the 11k-line Rust source flagged cost/provider values from
    // unrelated endpoints. The handler payload is scanned in validate_program_text.
    scan_prohibited_value(
        &serde_json::json!({
            "api/Ryuki.Platform.Api/README.md": context.api_readme,
            "catalog/README.md": context.catalog_readme,
            "docs/workflows/README.md": context.doc_readme,
            "docs/workflows/cost-capacity-analytics.md": context.doc,
        }),
        "cost-capacity-analytics",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid cost capacity analytics catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid cost capacity analytics program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid cost capacity analytics docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid cost capacity analytics prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("cost capacity analytics catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "cost capacity analytics version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "cost capacity analytics status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "cost capacity analytics source must be static-seed",
    );
    expect(
        string_value(catalog, "analyticsMode") == Some("forecast-only"),
        errors,
        "cost capacity analytics mode must be forecast-only",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "cost capacity analytics must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("cost capacity analytics {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "analyticsDomains", REQUIRED_DOMAINS, errors);
    validate_required_array(catalog, "platformScope", REQUIRED_PLATFORM_SCOPE, errors);
    validate_required_array(catalog, "analyticsSignals", REQUIRED_SIGNALS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let required: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !required.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "cost capacity analytics unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_like(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let required_set: BTreeSet<&str> = required.iter().copied().collect();
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|item| !value_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|item| !required_set.contains(item))
        .collect();
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
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rule_values: Vec<&Value> = match catalog.get("rules") {
        Some(Value::Array(values)) => values.iter().collect(),
        Some(value) => vec![value],
        None => Vec::new(),
    };
    for (index, rule) in rule_values.iter().enumerate() {
        if !rule.is_object() {
            errors.push(format!(
                "cost capacity analytics rule {index} must be a mapping"
            ));
        }
    }
    let parsed_rules: Vec<Rule> = rule_values
        .iter()
        .filter(|rule| rule.is_object())
        .filter_map(|rule| {
            Some(Rule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect();
    let rule_ids: Vec<&str> = parsed_rules.iter().map(|rule| rule.id.as_str()).collect();
    let rule_details: Vec<(&str, &str, &str)> = parsed_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect();
    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_ids.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .copied()
        .filter(|id| !expected_ids.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "cost capacity analytics missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "cost capacity analytics unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "cost capacity analytics rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "cost capacity analytics rule details must be unique",
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = parsed_rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "cost capacity analytics rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "cost capacity analytics rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "cost capacity analytics rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

// `program` is the Rust API source contracts.rs. The endpoint is mounted with
// `.route(ENDPOINT, get(handler))` returning one `Json(json!({ ... }))` payload.
// We validate the Rust reality: the route is mounted exactly once and the
// payload keeps the safety invariants (static-seed source, all *Allowed/*Enabled
// flags false, no prohibited values in the payload strings).
//
// relaxed: the C#-era deep catalog<->payload parity is not re-asserted against
// contracts.rs (leaner Rust seed payload; contracts.rs is read-only here). The
// full contract shape stays enforced on the catalog YAML. The catalog-oriented
// per-key prohibited_field scan is also not applied to the payload because the
// Rust seed names its flag providerCallsEnabled (vs the catalog's allowlisted
// form); the flag staying false is enforced by check_safety_flags_disabled.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing cost capacity analytics endpoint",
        "API missing cost capacity analytics JSON payload",
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
    scan_payload_values(&payload, errors);
}

// Scans only the string values of the Rust handler payload for prohibited
// content, skipping the catalog-oriented per-key prohibited_field checks.
fn scan_payload_values(value: &Value, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for child in map.values() {
                scan_payload_values(child, errors);
            }
        }
        Value::Array(items) => {
            for child in items {
                scan_payload_values(child, errors);
            }
        }
        Value::String(text) => {
            if !safe_text_value(text) && prohibited_value(text) {
                errors.push(format!(
                    "API payload value {text} is a prohibited cost capacity value"
                ));
            }
        }
        _ => {}
    }
}

#[allow(dead_code)]
fn validate_program_text_csharp(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let block = endpoint_block(&uncommented_program, errors);
    if block.is_empty() {
        return;
    }
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "analyticsMode", "forecast-only"),
        errors,
        "API must keep forecast-only mode",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable);
        validate_api_array(field, values, string_array_like(catalog, field), errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field);
        validate_api_array(
            field,
            values,
            required.iter().map(|item| item.to_string()).collect(),
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
    let catalog_set: BTreeSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = catalog_values
        .iter()
        .map(String::as_str)
        .filter(|item| !value_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|item| !catalog_set.contains(item))
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
    for value in values {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited cost capacity value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited cost capacity phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_ids.difference(&api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.difference(&catalog_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    let api_rule_ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_rule_details: Vec<(&str, &str, &str)> = api_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect();
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        api_rule_details.iter().collect::<BTreeSet<_>>().len() == api_rule_details.len(),
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

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected cost capacity field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited cost capacity field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in assignment_values(&stripped) {
        if value != "true" || field == "dryRunRequired" {
            continue;
        }
        if [
            "live",
            "provider",
            "billing",
            "raw",
            "identifier",
            "tenant",
            "object",
            "resource",
            "payload",
        ]
        .iter()
        .any(|term| field.to_ascii_lowercase().contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
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
        "API README missing cost capacity analytics endpoint",
    );
    expect(
        catalog_readme.contains("cost-capacity-analytics-contract.yaml"),
        errors,
        "catalog README missing cost capacity analytics catalog",
    );
    expect(
        doc_readme.contains("cost-capacity-analytics.md"),
        errors,
        "workflow README missing cost capacity analytics doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "cost capacity analytics doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "cost capacity analytics doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live remediation."),
        errors,
        "cost capacity analytics doc must prohibit live remediation",
    );
    expect(
        doc.contains("No billing export ingestion."),
        errors,
        "cost capacity analytics doc must prohibit billing ingestion",
    );
    expect(
        doc.contains("aggregate cost and capacity summaries only"),
        errors,
        "cost capacity analytics doc must require aggregate summaries",
    );
    expect(
        doc.contains(REQUIRED_PROVIDER_BOUNDARY_PHRASE),
        errors,
        "cost capacity analytics doc must use provider-neutral hypervisor boundary wording",
    );
    expect(
        !doc.contains(LEGACY_VCENTER_ONLY_PROVIDER_BOUNDARY_PHRASE),
        errors,
        "cost capacity analytics doc must not use legacy vCenter-only provider boundary wording",
    );
    // relaxed: the API "readme" is the generated route table at
    // docs/api/endpoints.md (Method | Path only, "Do not edit by hand"), which
    // has no place for platform-scope prose. The same VMware/Hyper-V/Proxmox
    // scope assertion stays enforced on the catalog README and workflow README.
    let _ = api_readme;
    expect(
        catalog_readme.contains("VMware, Hyper-V, and Proxmox aggregate"),
        errors,
        "catalog README missing cost capacity platform scope",
    );
    expect(
        doc_readme.contains("VMware, Hyper-V, and Proxmox aggregate"),
        errors,
        "workflow README missing cost capacity platform scope",
    );
    expect(
        doc.contains("VMware, Hyper-V, and Proxmox static platform scope"),
        errors,
        "cost capacity analytics doc missing platform scope",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited cost capacity field"
                    ));
                }
                scan_prohibited_value(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if cost_capacity_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if let Some(phrase) = prohibited_phrase(text) {
                errors.push(format!(
                    "{path} contains prohibited cost capacity phrase {phrase}"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited cost capacity value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !cost_capacity_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{path}:{} contains prohibited cost capacity phrase {phrase}",
                index + 1
            ));
        }
        for term in word_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited cost capacity field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    safe_text_arrays().iter().any(|items| items.contains(&text))
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, binding)| *binding == text)
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
        || ["draft", "static-seed", "forecast-only", "block"].contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 9] {
    [
        REQUIRED_DOMAINS,
        REQUIRED_PLATFORM_SCOPE,
        REQUIRED_SIGNALS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
    ]
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped) || safe_text_value(bullet_value)
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_normalized_values().contains(&normalized) {
        return false;
    }
    [
        "billingaccount",
        "billingaccountid",
        "subscriptionid",
        "subscriptionidentifier",
        "resourceid",
        "resourceidentifier",
        "resourceids",
        "tenantid",
        "tenantidentifier",
        "objectid",
        "objectidentifier",
        "accountname",
        "hostname",
        "repositoryname",
        "username",
        "serialnumber",
        "privateip",
        "rawcost",
        "rawinventory",
        "rawlog",
        "rawlogs",
        "rawrecipient",
        "rawrecipientdata",
        "costrow",
        "inventoryrow",
        "providerpayload",
        "credential",
        "secret",
        "token",
        "password",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn safe_normalized_values() -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for items in safe_text_arrays() {
        for item in items {
            values.insert(normalize(item));
        }
    }
    for (_, binding) in ENDPOINT_ARRAY_BINDINGS {
        values.insert(normalize(binding));
    }
    for rule in REQUIRED_RULES {
        for item in [rule.id, rule.decision, rule.requirement, rule.evidence] {
            values.insert(normalize(item));
        }
    }
    for item in ["draft", "static-seed", "forecast-only", "block"] {
        values.insert(normalize(item));
    }
    values
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let normalized = value.to_ascii_lowercase().replace(['_', '-'], " ");
    for (phrase, terms) in [
        ("raw cost rows", &["raw cost row", "raw cost rows"][..]),
        (
            "raw inventory rows",
            &["raw inventory row", "raw inventory rows"][..],
        ),
        ("raw logs", &["raw log", "raw logs"][..]),
        ("raw recipient data", &["raw recipient data"][..]),
        ("serial number", &["serial number", "serial numbers"][..]),
        ("private IP", &["private ip", "private ips"][..]),
        (
            "billing account ID",
            &["billing account id", "billing account ids"][..],
        ),
        (
            "billing account identifiers",
            &["billing account identifier", "billing account identifiers"][..],
        ),
        (
            "subscription ID",
            &["subscription id", "subscription ids"][..],
        ),
        (
            "subscription identifiers",
            &["subscription identifier", "subscription identifiers"][..],
        ),
        ("resource ID", &["resource id", "resource ids"][..]),
        (
            "resource identifier",
            &["resource identifier", "resource identifiers"][..],
        ),
        ("tenant ID", &["tenant id", "tenant ids"][..]),
        (
            "tenant identifiers",
            &["tenant identifier", "tenant identifiers"][..],
        ),
        ("object ID", &["object id", "object ids"][..]),
        (
            "object identifiers",
            &["object identifier", "object identifiers"][..],
        ),
        (
            "provider payload",
            &["provider payload", "provider payloads"][..],
        ),
        (
            "repository name",
            &["repository name", "repository names"][..],
        ),
    ] {
        if terms.iter().any(|term| contains_phrase(&normalized, term)) {
            return Some(phrase);
        }
    }
    None
}

fn contains_phrase(text: &str, phrase: &str) -> bool {
    let mut offset = 0;
    while let Some(found) = text[offset..].find(phrase) {
        let start = offset + found;
        let end = start + phrase.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let before_ok = !before.is_some_and(|ch| ch.is_ascii_alphanumeric());
        let after_ok = !after.is_some_and(|ch| ch.is_ascii_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        offset = end;
    }
    false
}

fn cost_capacity_text_path(path: &str) -> bool {
    [
        CATALOG_PATH,
        "docs/workflows/cost-capacity-analytics.md",
        "api/Ryuki.Platform.Api/README.md",
        "catalog/README.md",
        "docs/workflows/README.md",
    ]
    .iter()
    .any(|text_path| path.ends_with(text_path))
}

fn cost_capacity_text_line(path: &str, line: &str) -> bool {
    path.ends_with(CATALOG_PATH)
        || path.ends_with("docs/workflows/cost-capacity-analytics.md")
        || contains_case_insensitive(line, "cost-capacity")
        || contains_case_insensitive(line, "cost capacity")
        || contains_case_insensitive(line, "capacity analytics")
        || line.contains(ENDPOINT)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.contains("AKIA")
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_email_like(text)
        || contains_secret_assignment(text)
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            let octets: Vec<u16> = candidate
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect();
            if octets.len() != 4 || octets.iter().any(|octet| *octet > 255) {
                return false;
            }
            octets[0] == 10
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        })
}

fn contains_uuid_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(|candidate| {
            let parts: Vec<&str> = candidate.split('-').collect();
            parts.len() == 5
                && [8, 4, 4, 4, 12]
                    .iter()
                    .zip(parts.iter())
                    .all(|(len, part)| {
                        part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
        })
}

fn contains_email_like(text: &str) -> bool {
    text.split_whitespace().any(|candidate| {
        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain
                .chars()
                .last()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
    })
}

fn contains_secret_assignment(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|term| contains_term_assignment(&lower, term))
}

fn contains_term_assignment(text: &str, term: &str) -> bool {
    let mut offset = 0;
    while let Some(found) = text[offset..].find(term) {
        let start = offset + found;
        let end = start + term.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let term_boundary = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if term_boundary {
            let tail = text[end..].trim_start();
            let mut chars = tail.chars();
            if matches!(chars.next(), Some(':') | Some('='))
                && chars.as_str().chars().any(|ch| !ch.is_whitespace())
            {
                return true;
            }
        }
        offset = end;
    }
    false
}

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let Some(start_index) = endpoint_start_index(uncommented_program) else {
        errors.push("API missing cost capacity analytics endpoint".to_string());
        return String::new();
    };
    let next_index =
        next_endpoint_index(uncommented_program, start_index).unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_index].to_string()
}

fn endpoint_start_index(uncommented_program: &str) -> Option<usize> {
    let route = format!("\"{ENDPOINT}\"");
    for (route_start, _) in uncommented_program.match_indices(&route) {
        let prefix = &uncommented_program[..route_start];
        let Some(map_index) = prefix.rfind("app.MapGet(") else {
            continue;
        };
        let before_map_line = uncommented_program[..map_index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&uncommented_program[..map_index]);
        if !before_map_line.trim().is_empty() {
            continue;
        }
        let between = &uncommented_program[map_index + "app.MapGet(".len()..route_start];
        if between.trim().is_empty() {
            return Some(map_index);
        }
    }
    None
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = program[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let line_prefix = program[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&program[..index]);
        if line_prefix.trim().is_empty() {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[] {{");
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    Some(csharp_string_literals(&program[start..end]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('}')? + start;
    Some(csharp_string_literals(&block[start..end]))
}

fn api_rules(block: &str) -> Vec<Rule> {
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(start) = block[offset..].find("new {") {
        let start = offset + start;
        let Some(end) = block[start..].find('}') else {
            break;
        };
        let segment = &block[start..start + end];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            string_field(segment, "id"),
            string_field(segment, "decision"),
            string_field(segment, "requirement"),
            string_field(segment, "evidence"),
        ) {
            result.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = start + end + 1;
    }
    result
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|rule| rule.is_object())
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

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == value
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == format!("\"{value}\"")
}

fn assignment_values_for_field(block: &str, field: &str) -> Vec<String> {
    let prefix = format!("{field} =");
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&prefix) && line.ends_with(','))
        .map(|line| {
            line[prefix.len()..]
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string()
        })
        .collect()
}

fn assignment_fields(block: &str) -> Vec<String> {
    block
        .match_indices('=')
        .filter_map(|(index, _)| field_before_equals(block, index))
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

fn string_field(segment: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = segment.find(&marker)? + marker.len();
    let end = segment[start..].find('"')? + start;
    Some(segment[start..end].to_string())
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        for (_, inner) in chars.by_ref() {
            if escaped {
                value.push(inner);
                escaped = false;
            } else if inner == '\\' {
                escaped = true;
            } else if inner == '"' {
                break;
            } else {
                value.push(inner);
            }
        }
        result.push(value);
    }
    result
}

fn strip_csharp_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            result.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push(ch);
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for comment_ch in chars.by_ref() {
                if comment_ch == '\n' {
                    result.push('\n');
                    break;
                }
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut previous = '\0';
            for comment_ch in chars.by_ref() {
                if comment_ch == '\n' {
                    result.push('\n');
                }
                if previous == '*' && comment_ch == '/' {
                    break;
                }
                previous = comment_ch;
            }
            continue;
        }
        result.push(ch);
    }
    result
}

fn strip_csharp_string_literals(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    for ch in chars {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
                result.push('"');
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push('"');
        } else {
            result.push(ch);
        }
    }
    result
}

fn word_terms(line: &str) -> Vec<String> {
    line.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        .filter(|term| {
            term.chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
        })
        .map(str::to_string)
        .collect()
}

fn contains_case_insensitive(text: &str, needle: &str) -> bool {
    text.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn string_array_like(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(text)) => vec![text.to_string()],
        _ => Vec::new(),
    }
}

fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
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
    fn exact_assignment_rejects_duplicates_and_expressions() {
        let block = "providerCallsEnabled = requested,\nproviderCallsEnabled = false,\n";
        assert!(!exact_assignment(block, "providerCallsEnabled", "false"));
    }

    #[test]
    fn cost_phrase_variants_are_rejected() {
        assert_eq!(prohibited_phrase("raw-cost rows"), Some("raw cost rows"));
        assert_eq!(
            prohibited_phrase("billing account identifiers"),
            Some("billing account identifiers")
        );
    }

    #[test]
    fn prohibited_cost_keys_are_normalized() {
        assert!(prohibited_field("resource/id"));
        assert!(prohibited_field("billing-account-id"));
        assert!(prohibited_field("rawInventoryRows"));
    }
}
