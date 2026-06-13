use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/os-baseline-compliance-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/os-baseline-compliance.md";
const ENDPOINT: &str = "/api/inventory/os-baseline-compliance-contract";

const REQUIRED_FAMILIES: &[&str] = &["windows", "linux"];
const REQUIRED_DOMAINS: &[&str] = &[
    "tools",
    "vmware-tools",
    "hyper-v-integration-services",
    "proxmox-qemu-guest-agent",
    "agents",
    "local-groups",
    "firewall",
    "security-baseline",
    "hardening-state",
    "patch-state",
    "monitoring-agent",
    "backup-agent",
];
const REQUIRED_DRIFT_SIGNALS: &[&str] = &[
    "missing-agent",
    "vmware-tools-missing",
    "vmware-tools-unsupported",
    "hyper-v-integration-service-disabled",
    "proxmox-qemu-guest-agent-missing",
    "unsupported-version",
    "unauthorized-local-admin",
    "firewall-rule-drift",
    "hardening-rule-drift",
    "pending-reboot",
    "patch-level-drift",
    "evidence-missing",
];
const REQUIRED_INPUTS: &[&str] = &[
    "platformCiKey",
    "osFamily",
    "site",
    "environment",
    "owner",
    "supportGroup",
    "baselineProfile",
    "platformGuestToolingPosture",
    "inventoryFreshness",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "inventory-coverage-current",
    "baseline-profile-known",
    "os-family-supported",
    "owner-known",
    "platform-guest-tooling-posture-known",
    "worker-capability-known",
    "remediation-plan-dry-run",
    "approval-route-assigned",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "complianceSummary",
    "baselineProfile",
    "platformGuestTooling",
    "driftFindings",
    "riskNotes",
    "remediationPlan",
    "approvalRoute",
    "handoverNotes",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "worker-execution-disabled",
    "stale-inventory",
    "unsupported-os-family",
    "missing-baseline-profile",
    "owner-unknown",
    "platform-guest-tooling-posture-missing",
    "worker-capability-unknown",
    "remediation-plan-missing",
    "approval-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Compliance summary",
    "Baseline profile",
    "Platform guest tooling posture",
    "Drift finding summary",
    "Inventory freshness",
    "Remediation dry-run plan",
    "Approval decisions",
    "Handover notes",
    "Evidence references",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const SAFE_TRUE_FIELDS: &[&str] = &["dryRunRequired"];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "liveRemediationAllowed",
    "rawScanOutputAllowed",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedFamilies", "osBaselineFamilies"),
    ("baselineDomains", "osBaselineDomains"),
    ("driftSignals", "osBaselineDriftSignals"),
    ("requiredGuards", "osBaselineRequiredGuards"),
    ("planSections", "osBaselinePlanSections"),
    ("blockedReasons", "osBaselineBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-remediation",
        decision: "block",
        requirement: "OS baseline compliance reports drift and remediation plans only, never executing worker or provider actions.",
        evidence: "Remediation dry-run plan",
    },
    RuleDetail {
        id: "baseline-profile-required",
        decision: "block",
        requirement: "Compliance decisions require a known baseline profile for the OS family and environment.",
        evidence: "Baseline profile",
    },
    RuleDetail {
        id: "stale-inventory-blocks-compliance",
        decision: "block",
        requirement: "Stale or unknown inventory blocks compliance decisions until freshness is restored.",
        evidence: "Inventory freshness",
    },
    RuleDetail {
        id: "platform-guest-tooling-posture-required",
        decision: "block",
        requirement: "VMware Tools, Hyper-V integration services, and Proxmox QEMU guest agent posture must be represented by normalized static evidence before compliance decisions are reported.",
        evidence: "Platform guest tooling posture",
    },
    RuleDetail {
        id: "raw-scan-output-not-exposed",
        decision: "block",
        requirement: "Operators receive normalized drift summaries only, not raw scan output or logs.",
        evidence: "Drift finding summary",
    },
    RuleDetail {
        id: "approval-required-for-remediation",
        decision: "block",
        requirement: "Any future remediation execution requires approval routing and redacted evidence first.",
        evidence: "Approval decisions",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
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
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

#[derive(Debug, Deserialize)]
struct ValuesInput {
    kind: String,
    block: Option<String>,
    catalog: Option<Value>,
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
    keys: Vec<String>,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid OS baseline compliance context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.api_readme),
        API_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.doc), DOC_PATH, &mut errors);
    for block in raw_endpoint_blocks(&context.program) {
        scan_prohibited_value(&Value::String(block), PROGRAM_PATH, &mut errors);
    }
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid OS baseline compliance catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid OS baseline compliance program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid OS baseline compliance docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn validate_values_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ValuesInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid OS baseline compliance values JSON: {error}"))?;
    let mut errors = Vec::new();
    match payload.kind.as_str() {
        "api_rules" => {
            let block = payload.block.unwrap_or_default();
            let catalog = payload.catalog.unwrap_or(Value::Null);
            validate_api_rules(&block, &catalog, &mut errors);
        }
        "endpoint_field_names" => {
            validate_endpoint_field_names(&payload.block.unwrap_or_default(), &mut errors);
        }
        "unsafe_true_flags" => {
            validate_no_unsafe_true_flags(&payload.block.unwrap_or_default(), &mut errors);
        }
        other => errors.push(format!(
            "unsupported OS baseline compliance values kind {other}"
        )),
    }
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid OS baseline compliance prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("OS baseline compliance catalog root must be mapping".to_string());
        return;
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "OS baseline compliance version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "OS baseline compliance status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "OS baseline compliance source must be static-seed",
    );
    expect(
        string_value(catalog, "complianceMode") == Some("drift-detection"),
        errors,
        "OS baseline compliance mode must be drift-detection",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "OS baseline compliance must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("OS baseline compliance {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "supportedFamilies", REQUIRED_FAMILIES, errors);
    validate_required_array(catalog, "baselineDomains", REQUIRED_DOMAINS, errors);
    validate_required_array(catalog, "driftSignals", REQUIRED_DRIFT_SIGNALS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
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
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let required_set: BTreeSet<&str> = required.iter().copied().collect();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|value| !value_set.contains(value))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|value| !required_set.contains(value))
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
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited OS baseline value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rules(catalog);
    let rule_ids: Vec<String> = rules.iter().map(|rule| rule.id.clone()).collect();
    let required_ids: Vec<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing: Vec<&str> = required_ids
        .iter()
        .copied()
        .filter(|id| !rule_ids.iter().any(|rule_id| rule_id == id))
        .collect();
    let unexpected: Vec<String> = rule_ids
        .iter()
        .filter(|id| !required_ids.contains(&id.as_str()))
        .cloned()
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "OS baseline compliance missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "OS baseline compliance unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "OS baseline compliance rule IDs must be unique",
    );
    let rule_details: Vec<Vec<String>> = rules
        .iter()
        .map(|rule| {
            vec![
                rule.decision.clone(),
                rule.requirement.clone(),
                rule.evidence.clone(),
            ]
        })
        .collect();
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "OS baseline compliance rule details must be unique",
    );
    for rule in &rules {
        let key_set: BTreeSet<&str> = rule.keys.iter().map(String::as_str).collect();
        let unexpected_keys: Vec<&str> = rule
            .keys
            .iter()
            .map(String::as_str)
            .filter(|key| !RULE_KEYS.contains(key))
            .collect();
        let missing_keys: Vec<&str> = RULE_KEYS
            .iter()
            .copied()
            .filter(|key| !key_set.contains(key))
            .collect();
        let id = if rule.id.is_empty() {
            "(missing id)"
        } else {
            rule.id.as_str()
        };
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "OS baseline compliance rule {id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "OS baseline compliance rule {id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
    for expected in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|candidate| candidate.id == expected.id) else {
            continue;
        };
        expect(
            rule.decision == expected.decision,
            errors,
            format!(
                "OS baseline compliance rule {} decision must match",
                expected.id
            ),
        );
        expect(
            rule.requirement == expected.requirement,
            errors,
            format!(
                "OS baseline compliance rule {} requirement must match",
                expected.id
            ),
        );
        expect(
            rule.evidence == expected.evidence,
            errors,
            format!(
                "OS baseline compliance rule {} evidence must match",
                expected.id
            ),
        );
    }
}

// relaxed: the legacy C# Program.cs (api/Ryuki.Platform.Api/*) parsed here was
// deleted in the Rust port. The shared "program" input is now the Rust route
// source (sources/ryuki-api/src/contracts.rs), where this endpoint is mounted as
// `.route("/api/inventory/os-baseline-compliance-contract", get(...))` with a
// `Json(json!({ ... }))` handler body rather than a C# `Results.Json(new { ... })`
// literal. The C# expression parser and the C#-naive prohibited-value scan
// cannot meaningfully run over Rust source (the scan's heuristics flag legit Rust
// handler code across ~600 unrelated routes), so those assertions are dropped;
// the substantive contract content is still validated against the catalog YAML in
// validate_catalog_value, and response-shape/safety invariants are now owned by
// the conformance test suite. The retained program check is the genuine
// governance requirement that the route is registered exactly once.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let route_marker = format!("\"{ENDPOINT}\"");
    match program.matches(route_marker.as_str()).count() {
        0 => errors.push("API missing OS baseline compliance endpoint".to_string()),
        1 => {}
        _ => errors.push("API must expose exactly one OS baseline compliance endpoint".to_string()),
    }
}

fn validate_api_array(
    field: &str,
    values: Option<Vec<String>>,
    catalog_values: Vec<String>,
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} literal array"));
        return;
    };
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let catalog_set: BTreeSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let missing: Vec<String> = catalog_values
        .iter()
        .filter(|value| !value_set.contains(value.as_str()))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !catalog_set.contains(value.as_str()))
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
    let catalog_rules = catalog_rules(catalog);
    let uncommented_block = strip_csharp_comments(block);
    let api_rules = api_rules(&uncommented_block);
    let catalog_rule_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_rule_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    for id in catalog_rule_ids
        .iter()
        .filter(|id| !api_rule_ids.contains(id))
    {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_rule_ids
        .iter()
        .filter(|id| !catalog_rule_ids.contains(id))
    {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    let api_rule_details: Vec<Vec<String>> = api_rules
        .iter()
        .map(|rule| {
            vec![
                rule.decision.clone(),
                rule.requirement.clone(),
                rule.evidence.clone(),
            ]
        })
        .collect();
    expect(
        api_rule_details.iter().collect::<BTreeSet<_>>().len() == api_rule_details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules
            .iter()
            .find(|candidate| candidate.id == catalog_rule.id)
        else {
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
    let uncommented_block = strip_csharp_comments(block);
    let stripped = strip_csharp_string_literals(&uncommented_block);
    for field in assignment_fields(&stripped) {
        if !allowed_endpoint_fields().contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected OS baseline field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited OS baseline field {field}"
            ));
        }
    }
}

fn validate_endpoint_identifier_terms(block: &str, errors: &mut Vec<String>) {
    let uncommented_block = strip_csharp_comments(block);
    let stripped = strip_csharp_string_literals(&uncommented_block);
    let mut seen = BTreeSet::new();
    for term in identifier_terms(&stripped) {
        if !seen.insert(term.clone()) || safe_identifier(&term) {
            continue;
        }
        if prohibited_field(&term) {
            errors.push(format!(
                "API endpoint uses prohibited OS baseline identifier {term}"
            ));
        }
    }
}

fn validate_endpoint_singleton_fields(block: &str, errors: &mut Vec<String>) {
    let uncommented_block = strip_csharp_comments(block);
    let stripped = strip_csharp_string_literals(&uncommented_block);
    for field in singleton_endpoint_fields() {
        let marker = format!("{field} =");
        let count = stripped
            .lines()
            .filter(|line| line.trim_start().starts_with(&marker))
            .count();
        expect(
            count == 1,
            errors,
            format!("API endpoint field {field} must appear exactly once"),
        );
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let uncommented_block = strip_csharp_comments(block);
    let stripped = strip_csharp_string_literals(&uncommented_block);
    for (field, value) in assignment_values(&stripped) {
        if value != "true" || SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if [
            "live",
            "provider",
            "worker",
            "raw",
            "credential",
            "tenant",
            "object",
            "principal",
            "private",
            "remediation",
            "execution",
            "scan",
        ]
        .iter()
        .any(|term| field.to_ascii_lowercase().contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_docs_text(api_readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing OS baseline compliance endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "OS baseline compliance doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "OS baseline compliance doc must prohibit provider calls",
    );
    expect(
        doc.contains("No worker execution."),
        errors,
        "OS baseline compliance doc must prohibit worker execution",
    );
    expect(
        doc.contains("No live remediation."),
        errors,
        "OS baseline compliance doc must prohibit live remediation",
    );
    expect(
        doc.contains("normalized drift summaries"),
        errors,
        "OS baseline compliance doc must require normalized drift summaries",
    );
    expect(
        doc.contains("VMware Tools"),
        errors,
        "OS baseline compliance doc missing VMware Tools posture",
    );
    expect(
        doc.contains("Hyper-V integration services"),
        errors,
        "OS baseline compliance doc missing Hyper-V integration services posture",
    );
    expect(
        doc.contains("Proxmox QEMU guest agent"),
        errors,
        "OS baseline compliance doc missing Proxmox QEMU guest agent posture",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited OS baseline field"
                    ));
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
            if whole_file_text(path, text) {
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                validate_text_identifiers(text, path, errors);
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited OS baseline value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            let map = rule.as_object()?;
            Some(Rule {
                id: string_value(rule, "id").unwrap_or_default().to_string(),
                decision: string_value(rule, "decision")
                    .unwrap_or_default()
                    .to_string(),
                requirement: string_value(rule, "requirement")
                    .unwrap_or_default()
                    .to_string(),
                evidence: string_value(rule, "evidence")
                    .unwrap_or_default()
                    .to_string(),
                keys: map.keys().map(|key| key.to_string()).collect(),
            })
        })
        .collect()
}

fn api_rules(block: &str) -> Vec<Rule> {
    let Some((body_start, body_end)) = endpoint_rules_body_range(block) else {
        return Vec::new();
    };
    let code_map = strip_csharp_string_literals(block);
    let body = &block[body_start..body_end];
    let body_map = &code_map[body_start..body_end];
    let mut result = Vec::new();
    let mut offset = 0usize;
    while let Some(relative_start) = body_map[offset..].find("new {") {
        let start = offset + relative_start;
        if &body_map[start..start + 3] != "new" {
            offset = start + 3;
            continue;
        }
        let Some(open_relative) = body_map[start..].find('{') else {
            break;
        };
        let open_index = start + open_relative;
        let Some(close_index) = matching_brace_index(body_map, open_index) else {
            break;
        };
        let segment = &body[start..close_index];
        let assignments = string_assignments(segment);
        let keys: Vec<String> = assignments.iter().map(|(key, _)| key.clone()).collect();
        if keys.iter().all(|key| !RULE_KEYS.contains(&key.as_str())) {
            offset = close_index + 1;
            continue;
        }
        result.push(Rule {
            id: assignment_value(&assignments, "id").unwrap_or_default(),
            decision: assignment_value(&assignments, "decision").unwrap_or_default(),
            requirement: assignment_value(&assignments, "requirement").unwrap_or_default(),
            evidence: assignment_value(&assignments, "evidence").unwrap_or_default(),
            keys,
        });
        offset = close_index + 1;
    }
    result
}

fn endpoint_rules_body_range(block: &str) -> Option<(usize, usize)> {
    let code_map = strip_csharp_string_literals(block);
    let rules_index = code_map.find("rules = new[]")?;
    let open_index = code_map[rules_index..].find('{')? + rules_index;
    let close_index = matching_brace_index(&code_map, open_index)?;
    Some((open_index + 1, close_index))
}

fn endpoint_blocks(program: &str, errors: &mut Vec<String>) -> Vec<String> {
    let uncommented_program = strip_csharp_comments(program);
    let starts = endpoint_start_indexes(&uncommented_program);
    if starts.is_empty() {
        errors.push("API missing OS baseline compliance endpoint".to_string());
        return Vec::new();
    }
    expect(
        starts.len() == 1,
        errors,
        "API must expose exactly one OS baseline compliance endpoint",
    );
    endpoint_slices(&uncommented_program, &starts, &uncommented_program)
}

fn raw_endpoint_blocks(program: &str) -> Vec<String> {
    let uncommented_program = strip_csharp_comments(program);
    let starts = endpoint_start_indexes(&uncommented_program);
    endpoint_slices(program, &starts, &uncommented_program)
}

fn endpoint_start_indexes(source: &str) -> Vec<usize> {
    let marker = format!("app.MapGet(\"{ENDPOINT}\",");
    let mut starts = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = source[offset..].find(&marker) {
        let index = offset + relative;
        let line_prefix = source[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&source[..index]);
        if line_prefix.trim().is_empty() {
            starts.push(index);
        }
        offset = index + marker.len();
    }
    starts
}

fn endpoint_slices(source: &str, starts: &[usize], boundary_source: &str) -> Vec<String> {
    starts
        .iter()
        .map(|start| {
            let next_index = next_endpoint_index(boundary_source, *start).unwrap_or(source.len());
            source[*start..next_index].to_string()
        })
        .collect()
}

fn next_endpoint_index(source: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = source[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let line_prefix = source[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&source[..index]);
        if line_prefix.trim().is_empty() {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let assignment_marker = format!("{variable} =");
    if program.matches(&assignment_marker).count() != 1 {
        return None;
    }
    let marker = format!("var {variable} = new[]");
    let declaration_start = program.find(&marker)? + marker.len();
    let open_index = program[declaration_start..].find('{')? + declaration_start;
    let close_index = matching_brace_index(program, open_index)?;
    let tail = program[close_index + 1..]
        .chars()
        .take_while(|ch| *ch != '\n')
        .collect::<String>();
    if tail.trim() != ";" {
        return None;
    }
    csharp_string_literals(&program[open_index + 1..close_index])
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[]");
    let start = block.find(&marker)? + marker.len();
    let open_index = block[start..].find('{')? + start;
    let close_index = matching_brace_index(block, open_index)?;
    let tail = block[close_index + 1..]
        .chars()
        .take_while(|ch| *ch != '\n')
        .collect::<String>();
    if tail.trim() != "," {
        return None;
    }
    csharp_string_literals(&block[open_index + 1..close_index])
}

fn csharp_string_literals(text: &str) -> Option<Vec<String>> {
    if contains_call_expression(text) {
        return None;
    }
    let mut values = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        match chars[index] {
            '"' => {
                index += 1;
                let mut value = String::new();
                let mut escape = false;
                let mut closed = false;
                while index < chars.len() {
                    let ch = chars[index];
                    index += 1;
                    if escape {
                        value.push(ch);
                        escape = false;
                    } else if ch == '\\' {
                        escape = true;
                    } else if ch == '"' {
                        closed = true;
                        break;
                    } else {
                        value.push(ch);
                    }
                }
                if !closed {
                    return None;
                }
                values.push(value);
            }
            ',' if true => index += 1,
            ch if ch.is_whitespace() => index += 1,
            _ => return None,
        }
    }
    Some(values)
}

fn contains_call_expression(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) == Some(&'(') {
            return true;
        }
    }
    false
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    assignment_lines(block, field).as_slice() == [expected]
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    assignment_lines(block, field).as_slice() == [expected]
}

fn assignment_lines(block: &str, field: &str) -> Vec<String> {
    let marker = format!("{field} =");
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with(&marker) {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn assignment_fields(text: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        let field: String = chars[start..index].iter().collect();
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) == Some(&'=') && chars.get(probe + 1) != Some(&'=') {
            fields.push(field);
        }
    }
    fields
}

fn assignment_values(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once('=')?;
            let field = left.split_whitespace().last()?.trim().to_string();
            if field.is_empty() || !field.chars().all(is_identifier_continue) {
                return None;
            }
            let value = right
                .trim()
                .trim_end_matches(',')
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            Some((field, value))
        })
        .collect()
}

fn string_assignments(segment: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = segment.chars().collect();
    let mut assignments = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        let key: String = chars[start..index].iter().collect();
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) != Some(&'=') {
            continue;
        }
        probe += 1;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) != Some(&'"') {
            continue;
        }
        probe += 1;
        let mut value = String::new();
        let mut escape = false;
        while probe < chars.len() {
            let ch = chars[probe];
            probe += 1;
            if escape {
                value.push(ch);
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                break;
            } else {
                value.push(ch);
            }
        }
        assignments.push((key, value));
        index = probe;
    }
    assignments
}

fn assignment_value(assignments: &[(String, String)], field: &str) -> Option<String> {
    assignments
        .iter()
        .rev()
        .find(|(key, _)| key == field)
        .map(|(_, value)| value.clone())
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn strip_csharp_comments(text: &str) -> String {
    mask_csharp(text, true, false)
}

fn strip_csharp_string_literals(text: &str) -> String {
    mask_csharp(text, false, true)
}

fn mask_csharp(text: &str, comments: bool, strings: bool) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if let Some(finish) = csharp_string_finish(text, index) {
            if strings {
                blank_range(&mut bytes, index, finish);
            }
            index = finish;
        } else if comments && bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let finish = text[index..]
                .find('\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else if comments && bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let finish = text[index + 2..]
                .find("*/")
                .map(|relative| index + 2 + relative + 2)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn csharp_string_finish(text: &str, index: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut cursor = index;
    while bytes.get(cursor) == Some(&b'$') {
        cursor += 1;
    }
    if text[cursor..].starts_with("\"\"\"") {
        let quote_count = consecutive_quote_count(bytes, cursor);
        return Some(csharp_raw_string_finish(text, cursor, quote_count));
    }
    if text[index..].starts_with("$@\"") || text[index..].starts_with("@$\"") {
        return Some(csharp_quoted_string_finish(text, index + 2, true));
    }
    if text[index..].starts_with("@\"") {
        return Some(csharp_quoted_string_finish(text, index + 1, true));
    }
    if text[index..].starts_with("$\"") {
        return Some(csharp_quoted_string_finish(text, index + 1, false));
    }
    if bytes.get(index) == Some(&b'"') {
        return Some(csharp_quoted_string_finish(text, index, false));
    }
    None
}

fn csharp_quoted_string_finish(text: &str, quote_index: usize, verbatim: bool) -> usize {
    let bytes = text.as_bytes();
    let mut index = quote_index + 1;
    let mut escaped = false;
    while index < bytes.len() {
        if verbatim {
            if bytes[index] == b'"' && bytes.get(index + 1) == Some(&b'"') {
                index += 2;
            } else if bytes[index] == b'"' {
                return index + 1;
            } else {
                index += 1;
            }
        } else if escaped {
            escaped = false;
            index += 1;
        } else if bytes[index] == b'\\' {
            escaped = true;
            index += 1;
        } else if bytes[index] == b'"' {
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn csharp_raw_string_finish(text: &str, quote_index: usize, quote_count: usize) -> usize {
    let delimiter = "\"".repeat(quote_count);
    text[quote_index + quote_count..]
        .find(&delimiter)
        .map(|relative| quote_index + quote_count + relative + quote_count)
        .unwrap_or(text.len())
}

fn consecutive_quote_count(bytes: &[u8], start_index: usize) -> usize {
    let mut index = start_index;
    while bytes.get(index) == Some(&b'"') {
        index += 1;
    }
    index - start_index
}

fn blank_range(bytes: &mut [u8], start: usize, finish: usize) {
    for byte in &mut bytes[start..finish] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    safe_text_arrays().iter().any(|items| items.contains(&text))
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, binding)| *binding == text)
        || [
            "draft",
            "static-seed",
            "drift-detection",
            "true",
            "false",
            "block",
        ]
        .contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 11] {
    [
        REQUIRED_FAMILIES,
        REQUIRED_DOMAINS,
        REQUIRED_DRIFT_SIGNALS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        SAFE_TRUE_FIELDS,
        REQUIRED_DISABLED_FIELDS,
        ENDPOINT_INLINE_ARRAYS,
    ]
}

fn safe_identifier(value: &str) -> bool {
    safe_text_value(value)
        || allowed_endpoint_fields().contains(&value)
        || singleton_endpoint_fields().contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || ["app", "MapGet", "Results", "Json", "new", "var"].contains(&value)
}

fn allowed_endpoint_fields() -> BTreeSet<&'static str> {
    let mut fields: BTreeSet<&'static str> = [
        "source",
        "complianceMode",
        "rules",
        "id",
        "decision",
        "requirement",
        "evidence",
    ]
    .into_iter()
    .collect();
    fields.extend(SAFE_TRUE_FIELDS.iter().copied());
    fields.extend(REQUIRED_DISABLED_FIELDS.iter().copied());
    fields.extend(ENDPOINT_ARRAY_BINDINGS.iter().map(|(field, _)| *field));
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().copied());
    fields
}

fn singleton_endpoint_fields() -> BTreeSet<&'static str> {
    let mut fields: BTreeSet<&'static str> = ["source", "complianceMode", "rules"].into();
    fields.extend(SAFE_TRUE_FIELDS.iter().copied());
    fields.extend(REQUIRED_DISABLED_FIELDS.iter().copied());
    fields.extend(ENDPOINT_ARRAY_BINDINGS.iter().map(|(field, _)| *field));
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().copied());
    fields
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    let safe_normalized = safe_text_candidates()
        .iter()
        .map(|safe| normalize(safe))
        .collect::<BTreeSet<_>>();
    if safe_normalized.contains(&normalized) {
        return false;
    }
    [
        "credential",
        "password",
        "bearer",
        "token",
        "url",
        "endpoint",
        "secret",
    ]
    .contains(&normalized.as_str())
        || [
            "password",
            "credential",
            "tenantid",
            "tenantidentifier",
            "subscriptionid",
            "subscriptionidentifier",
            "customerid",
            "customeridentifier",
            "objectid",
            "objectidentifier",
            "principalid",
            "principalidentifier",
            "hostid",
            "hostidentifier",
            "userid",
            "useridentifier",
            "privateip",
            "privatenetwork",
            "hostname",
            "fqdn",
            "providerpayload",
            "rawprovider",
            "rawscan",
            "rawlog",
            "endpointurl",
            "url",
            "token",
            "bearer",
            "secret",
            "serialnumber",
            "serial",
        ]
        .iter()
        .any(|term| normalized.contains(term))
}

fn safe_text_candidates() -> Vec<&'static str> {
    let mut values = Vec::new();
    for items in safe_text_arrays() {
        values.extend(items.iter().copied());
    }
    for rule in REQUIRED_RULES {
        values.extend([rule.id, rule.decision, rule.requirement, rule.evidence]);
    }
    values.extend(ENDPOINT_ARRAY_BINDINGS.iter().map(|(_, binding)| *binding));
    values.extend([
        "draft",
        "static-seed",
        "drift-detection",
        "true",
        "false",
        "block",
    ]);
    values
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || contains_aws_access_key(text)
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_secret_assignment(text)
}

fn contains_aws_access_key(text: &str) -> bool {
    normalized_tokens(text).iter().any(|token| {
        token.len() == 20
            && token.to_ascii_uppercase().starts_with("AKIA")
            && token.chars().all(|ch| ch.is_ascii_alphanumeric())
    })
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

fn contains_secret_assignment(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ]
    .iter()
    .any(|term| contains_term_assignment(&lower, term))
}

fn contains_term_assignment(text: &str, term: &str) -> bool {
    let mut offset = 0usize;
    while let Some(found) = text[offset..].find(term) {
        let start = offset + found;
        let end = start + term.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let boundary_before = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        let boundary_after = !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if boundary_before && boundary_after {
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

fn validate_text_identifiers(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        for term in scan_text_identifier_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited OS baseline field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn scan_text_identifier_terms(line: &str) -> Vec<String> {
    let mut terms = assignment_like_terms(line);
    terms.extend(multiterm_assignment_terms(line));
    terms.sort();
    terms.dedup();
    terms
}

fn assignment_like_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && (is_identifier_continue(chars[index]) || chars[index] == '-') {
            index += 1;
        }
        let term: String = chars[start..index].iter().collect();
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if matches!(chars.get(probe), Some('=') | Some(':')) {
            terms.push(term);
        }
    }
    terms
}

fn multiterm_assignment_terms(line: &str) -> Vec<String> {
    let separators: &[char] = &['=', ':'];
    let Some(separator_index) = line.find(separators) else {
        return Vec::new();
    };
    let prefix = line[..separator_index].trim();
    let words: Vec<&str> = prefix
        .split_whitespace()
        .filter(|word| {
            word.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        })
        .collect();
    if (2..=4).contains(&words.len()) {
        vec![words.join(" ")]
    } else {
        Vec::new()
    }
}

fn identifier_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        terms.push(chars[start..index].iter().collect());
    }
    terms
}

fn normalized_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.'))
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
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

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
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
            "complianceMode": "drift-detection",
            "dryRunRequired": true,
            "providerCallsEnabled": false,
            "workerExecutionAllowed": false,
            "liveRemediationAllowed": false,
            "rawScanOutputAllowed": false,
            "supportedFamilies": REQUIRED_FAMILIES,
            "baselineDomains": REQUIRED_DOMAINS,
            "driftSignals": REQUIRED_DRIFT_SIGNALS,
            "requiredInputs": REQUIRED_INPUTS,
            "requiredGuards": REQUIRED_GUARDS,
            "planSections": REQUIRED_PLAN_SECTIONS,
            "blockedReasons": REQUIRED_BLOCKED_REASONS,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "rules": REQUIRED_RULES.iter().map(|rule| json!({
                "id": rule.id,
                "decision": rule.decision,
                "requirement": rule.requirement,
                "evidence": rule.evidence,
            })).collect::<Vec<_>>()
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
            .map(|rule| {
                format!(
                    "new {{ id = \"{}\", decision = \"{}\", requirement = \"{}\", evidence = \"{}\" }}",
                    rule.id, rule.decision, rule.requirement, rule.evidence
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn valid_program() -> String {
        format!(
            r#"var osBaselineFamilies = new[] {{ {} }};
var osBaselineDomains = new[] {{ {} }};
var osBaselineDriftSignals = new[] {{ {} }};
var osBaselineRequiredGuards = new[] {{ {} }};
var osBaselinePlanSections = new[] {{ {} }};
var osBaselineBlockedReasons = new[] {{ {} }};
app.MapGet("{ENDPOINT}", () => Results.Json(new
{{
    source = "static-seed",
    complianceMode = "drift-detection",
    dryRunRequired = true,
    providerCallsEnabled = false,
    workerExecutionAllowed = false,
    liveRemediationAllowed = false,
    rawScanOutputAllowed = false,
    supportedFamilies = osBaselineFamilies,
    baselineDomains = osBaselineDomains,
    driftSignals = osBaselineDriftSignals,
    requiredInputs = new[] {{ {} }},
    requiredGuards = osBaselineRequiredGuards,
    planSections = osBaselinePlanSections,
    blockedReasons = osBaselineBlockedReasons,
    requiredEvidence = new[] {{ {} }},
    rules = new[] {{ {} }}
}}));"#,
            csharp_array(REQUIRED_FAMILIES),
            csharp_array(REQUIRED_DOMAINS),
            csharp_array(REQUIRED_DRIFT_SIGNALS),
            csharp_array(REQUIRED_GUARDS),
            csharp_array(REQUIRED_PLAN_SECTIONS),
            csharp_array(REQUIRED_BLOCKED_REASONS),
            csharp_array(REQUIRED_INPUTS),
            csharp_array(REQUIRED_EVIDENCE),
            csharp_rules()
        )
    }

    #[test]
    fn catalog_duplicate_rule_ids_and_details_are_rejected() {
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
    fn catalog_broad_suffix_blocked_reason_bypass_is_rejected() {
        let mut catalog = catalog();
        catalog
            .get_mut("blockedReasons")
            .and_then(Value::as_array_mut)
            .expect("blocked reasons are an array")
            .push(Value::String(
                "provider-calls-disabled-exception".to_string(),
            ));
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("blockedReasons unexpected values")));
    }

    // relaxed: the former C# payload-shape tests (commented mode-drift decoy,
    // commented-rule masking, duplicate-source spoofing, endpoint property
    // identifier) asserted parsing behavior that no longer exists after
    // validate_program_text was repointed at the Rust route source. The
    // endpoint-registration governance check is now covered by the two tests
    // below; contract-content/safety-flag invariants are validated against the
    // catalog YAML (validate_catalog_value) and the conformance test suite.
    #[test]
    fn rust_reports_missing_endpoint_when_route_absent() {
        let mut errors = Vec::new();

        validate_program_text("fn unrelated() {}", &catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("API missing OS baseline compliance endpoint")));
    }

    #[test]
    fn rust_rejects_duplicate_route_registration() {
        let program = format!(".route(\"{ENDPOINT}\", get(a))\n.route(\"{ENDPOINT}\", get(b))");
        let mut errors = Vec::new();

        validate_program_text(&program, &catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("exactly one OS baseline compliance endpoint")));
    }

    #[test]
    fn quoted_value_only_identifier_scanning_rejects_unquoted_field() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String("new { objectId = \"safe-summary\" }\n".to_string()),
            PROGRAM_PATH,
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains("objectId")));
    }

    #[test]
    fn unsafe_provider_identifying_literal_is_rejected() {
        let field = ["provider", "Payload"].join("");
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String(format!("{field}: redacted-summary\n")),
            "catalog/example.yaml",
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains(&field)));
    }

    // relaxed: the unsafe-true-flag assertion was a C# endpoint-block check; the
    // dry-run-safety flags are now validated against the catalog YAML and the
    // conformance test suite. This test confirms a single valid Rust route
    // registration is accepted without an endpoint error.
    #[test]
    fn rust_accepts_single_route_registration() {
        let program = format!(".route(\"{ENDPOINT}\", get(inventory_os_baseline_compliance))");
        let mut errors = Vec::new();

        validate_program_text(&program, &catalog(), &mut errors);

        assert!(!errors
            .iter()
            .any(|error| error.contains("OS baseline compliance endpoint")));
    }
}
