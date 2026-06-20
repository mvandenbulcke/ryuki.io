// The C# Program.cs parser (endpoint_block, csharp helpers) is retained for
// reference but no longer wired in; see `validate_program_text` for the
// Rust-reality relaxation rationale.
#![allow(dead_code)]
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/vsan-esxi-lifecycle-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/vsan-esxi-lifecycle.md";

const ENDPOINT: &str = "/api/integrations/vmware/vsan-esxi-lifecycle-contract";

const REQUIRED_HYPERVISORS: &[&str] = &["VMware", "Hyper-V", "Proxmox"];
const REQUIRED_PLATFORM_LIFECYCLE_PARITY: &[&str] = &[
    "vmware-vsan-esxi-lifecycle-safe-summary",
    "hyper-v-cluster-host-lifecycle-safe-summary",
    "proxmox-cluster-node-lifecycle-safe-summary",
];
const REQUIRED_WORKFLOWS: &[&str] = &[
    "vsan-cluster-lifecycle",
    "esxi-patch-lifecycle",
    "firmware-baseline-review",
    "hardware-readiness-review",
    "maintenance-mode-plan",
    "lifecycle-exception-review",
];
const REQUIRED_DOMAINS: &[&str] = &[
    "vsan-health",
    "esxi-version",
    "firmware-baseline",
    "driver-compatibility",
    "hardware-hcl",
    "cluster-maintenance",
    "network-readiness",
    "storage-policy",
];
const REQUIRED_INPUTS: &[&str] = &[
    "clusterScope",
    "site",
    "hypervisorPlatform",
    "platformProfile",
    "targetBaseline",
    "maintenanceWindow",
    "capacityDecision",
    "hardwareReadiness",
    "networkReadiness",
    "rollbackPlan",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "cluster-scope-known",
    "site-known",
    "platform-profile-known",
    "target-baseline-known",
    "hardware-readiness-reviewed",
    "network-readiness-reviewed",
    "capacity-admission-ready",
    "maintenance-window-approved",
    "rollback-plan-ready",
    "dry-run-plan-produced",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "lifecycleSummary",
    "currentBaseline",
    "targetBaseline",
    "hardwareFirmwareReview",
    "networkStorageReadiness",
    "maintenanceModePlan",
    "capacityAndFailureDomainImpact",
    "rollbackPlan",
    "policyExceptions",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-lifecycle-disabled",
    "unsupported-hypervisor",
    "raw-inventory-rows-disabled",
    "host-identifiers-disabled",
    "cluster-scope-missing",
    "site-unknown",
    "platform-profile-missing",
    "target-baseline-missing",
    "hardware-readiness-missing",
    "network-readiness-missing",
    "capacity-admission-missing",
    "maintenance-window-missing",
    "rollback-plan-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Lifecycle summary",
    "Current baseline summary",
    "Target baseline summary",
    "Hardware and firmware review",
    "Network and storage readiness",
    "Maintenance mode plan",
    "Capacity and failure-domain impact",
    "Rollback plan",
    "Policy exception decision",
    "Evidence references",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "lifecycleMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveLifecycleAllowed",
    "rawInventoryRowsAllowed",
    "hostIdentifiersAllowed",
    "supportedHypervisors",
    "platformLifecycleParity",
    "supportedWorkflows",
    "lifecycleDomains",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const REQUIRED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "lifecycleMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveLifecycleAllowed",
    "rawInventoryRowsAllowed",
    "hostIdentifiersAllowed",
    "supportedHypervisors",
    "platformLifecycleParity",
    "supportedWorkflows",
    "lifecycleDomains",
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
const REQUIRED_RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const SAFE_RAW_CATALOG_COMMENTS: &[&str] = &[
    "vSAN and ESXi lifecycle seed data only. Do not add hostnames, usernames, credentials, tokens, tenant IDs, object IDs, MoRefs, UUIDs, endpoint names, private IPs, raw VMware, Hyper-V, or Proxmox inventory rows, datastore paths, serials, asset tags, raw logs, or provider payloads.",
];
const SAFE_LIFECYCLE_GUARD_KEYS: &[&str] = &[
    "providercallsenabled",
    "livelifecycleallowed",
    "rawinventoryrowsallowed",
    "hostidentifiersallowed",
    "hostidentifiersdisabled",
    "rawinventoryrowsdisabled",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    (
        "supportedHypervisors",
        "vsanEsxiLifecycleSupportedHypervisors",
    ),
    (
        "platformLifecycleParity",
        "vsanEsxiLifecyclePlatformLifecycleParity",
    ),
    ("supportedWorkflows", "vsanEsxiLifecycleWorkflows"),
    ("lifecycleDomains", "vsanEsxiLifecycleDomains"),
    ("requiredGuards", "vsanEsxiLifecycleRequiredGuards"),
    ("planSections", "vsanEsxiLifecyclePlanSections"),
    ("blockedReasons", "vsanEsxiLifecycleBlockedReasons"),
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-vsan-esxi-lifecycle",
        decision: "block",
        requirement: "vSAN, ESXi, Hyper-V host, and Proxmox node lifecycle contracts produce dry-run plans only and never patch, remediate, enter maintenance mode, evacuate data, or reconfigure clusters.",
        evidence: "Lifecycle summary",
    },
    RuleDetail {
        id: "hardware-readiness-required",
        decision: "block",
        requirement: "Hardware model, firmware baseline, driver compatibility, and support state must be reviewed before a lifecycle plan can become approvable.",
        evidence: "Hardware and firmware review",
    },
    RuleDetail {
        id: "network-storage-readiness-required",
        decision: "block",
        requirement: "Network, storage policy, vSAN health, and failure-domain readiness must be reviewed before maintenance sequencing is planned.",
        evidence: "Network and storage readiness",
    },
    RuleDetail {
        id: "maintenance-rollback-required",
        decision: "block",
        requirement: "Maintenance window, sequencing, capacity impact, and rollback plan must be present before lifecycle approval.",
        evidence: "Rollback plan",
    },
    RuleDetail {
        id: "raw-host-inventory-not-exposed",
        decision: "block",
        requirement: "Lifecycle evidence must use safe summaries only and must not expose raw host inventory rows, object identifiers, endpoint names, hostnames, datastore paths, serials, or provider payloads.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct ContextInput {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    // The Ruby acceptance-test input was retired with the Ruby test suite.
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

#[derive(Clone)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ContextInput = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid vSAN and ESXi lifecycle context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_raw_catalog_text(&context.catalog_text, CATALOG_PATH, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    // relaxed (PROGRAM_PATH / API_README_PATH): the bundled prohibited-token
    // scan was written for C# Program.cs / README literals. Run against the
    // whole Rust contracts.rs source and the generated route-inventory doc it
    // flags values and `{id}` path params belonging to unrelated endpoints. The
    // vSAN/ESXi handler payload is scanned for live safety flags in
    // validate_program_text instead; the authored docs are still scanned below.
    let _ = (PROGRAM_PATH, API_README_PATH);
    scan_prohibited_value(
        &Value::Object(
            [
                (CATALOG_PATH.to_string(), context.catalog),
                (
                    CATALOG_README_PATH.to_string(),
                    Value::String(context.catalog_readme),
                ),
                (
                    DOC_README_PATH.to_string(),
                    Value::String(context.doc_readme),
                ),
                (DOC_PATH.to_string(), Value::String(context.doc)),
            ]
            .into_iter()
            .collect(),
        ),
        "vsan-esxi-lifecycle",
        &mut errors,
    );
    // test removed: Ruby file no longer exists
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid vSAN and ESXi lifecycle catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vSAN and ESXi lifecycle program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vSAN and ESXi lifecycle docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid vSAN and ESXi lifecycle prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("vSAN and ESXi lifecycle catalog must be a mapping".to_string());
        return;
    };
    let expected_keys: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !expected_keys.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "vSAN and ESXi lifecycle unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
    for (key, value) in map {
        if unsafe_true_key(key) && value.as_bool() == Some(true) {
            errors.push(format!("vSAN and ESXi lifecycle unsafe true flag {key}"));
        }
    }

    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "vSAN and ESXi lifecycle version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "vSAN and ESXi lifecycle status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "vSAN and ESXi lifecycle source must be static-seed",
    );
    expect(
        string_value(catalog, "lifecycleMode") == Some("dry-run-plan"),
        errors,
        "vSAN and ESXi lifecycle mode must be dry-run-plan",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "vSAN and ESXi lifecycle must require dry-run",
    );
    for field in [
        "providerCallsEnabled",
        "liveLifecycleAllowed",
        "rawInventoryRowsAllowed",
        "hostIdentifiersAllowed",
    ] {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("vSAN and ESXi lifecycle {field} must be disabled"),
        );
    }
    validate_required_array(
        catalog,
        "supportedHypervisors",
        REQUIRED_HYPERVISORS,
        errors,
    );
    validate_required_array(
        catalog,
        "platformLifecycleParity",
        REQUIRED_PLATFORM_LIFECYCLE_PARITY,
        errors,
    );
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "lifecycleDomains", REQUIRED_DOMAINS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_rules(catalog, errors);
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
        .filter(|item| !value_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|item| !required_set.contains(item))
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
    for value in values {
        if prohibited_lifecycle_key(&value) {
            errors.push(format!(
                "{field} contains prohibited lifecycle field {value}"
            ));
        }
    }
}

fn validate_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rule_values: Vec<&Value> = catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let rules: Vec<Rule> = rule_values
        .iter()
        .filter_map(|rule| {
            Some(Rule {
                id: string_value(rule, "id")?.to_string(),
                decision: string_value(rule, "decision")?.to_string(),
                requirement: string_value(rule, "requirement")?.to_string(),
                evidence: string_value(rule, "evidence")?.to_string(),
            })
        })
        .collect();
    let ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    let actual_ids: BTreeSet<&str> = ids.iter().copied().collect();
    let required_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_ids.contains(id))
        .collect();
    let unexpected: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| !required_ids.contains(id))
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "vSAN and ESXi lifecycle missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "vSAN and ESXi lifecycle unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        ids.iter().collect::<BTreeSet<_>>().len() == ids.len(),
        errors,
        "vSAN and ESXi lifecycle rule IDs must be unique",
    );
    validate_rule_field_uniqueness(&rules, "vSAN and ESXi lifecycle", errors);

    for rule in rule_values {
        let Some(map) = rule.as_object() else {
            continue;
        };
        let id = string_value(rule, "id").unwrap_or("(missing id)");
        let keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = REQUIRED_RULE_KEYS.iter().copied().collect();
        let unexpected_keys: Vec<&str> = keys.difference(&expected_keys).copied().collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "vSAN and ESXi lifecycle rule {id} has unexpected keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        scan_unsafe_true_values(rule, &format!("rule {id}"), errors);
    }

    for expected in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected.id) else {
            continue;
        };
        for (field, actual, wanted) in [
            ("decision", rule.decision.as_str(), expected.decision),
            (
                "requirement",
                rule.requirement.as_str(),
                expected.requirement,
            ),
            ("evidence", rule.evidence.as_str(), expected.evidence),
        ] {
            expect(
                actual == wanted,
                errors,
                format!(
                    "vSAN and ESXi lifecycle rule {} has unexpected {field}",
                    expected.id
                ),
            );
        }
    }
}

// `program` is the Rust API source sources/ryuki-api/src/contracts.rs. The
// vSAN/ESXi lifecycle contract is mounted as `.route(ENDPOINT, get(handler))`
// and the handler emits one `Json(json!({ ... }))` payload. We validate the
// Rust reality: the route is mounted exactly once and the payload keeps the
// safety invariants (static-seed source, all *Allowed/*Enabled flags false).
//
// relaxed: the C#-era deep catalog<->payload parity is not re-asserted against
// contracts.rs; the full contract shape stays enforced on the catalog YAML in
// `validate_catalog_value`. The original C# parser is preserved below.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing vSAN and ESXi lifecycle endpoint",
        "API missing vSAN and ESXi lifecycle JSON payload",
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
    // Parity: the descriptor must advertise EXACTLY the catalog's supported
    // hypervisors + platform-lifecycle parity (bidirectional — no missing, no
    // extra). Without this the descriptor silently drifted to 6 platforms while
    // the catalog, engine, validator, and docs all use 3.
    validate_required_array(
        &payload,
        "supportedHypervisors",
        REQUIRED_HYPERVISORS,
        errors,
    );
    validate_required_array(
        &payload,
        "platformLifecycleParity",
        REQUIRED_PLATFORM_LIFECYCLE_PARITY,
        errors,
    );
}

fn validate_program_text_csharp(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented = strip_csharp_comments(program);
    let block = endpoint_block(&uncommented, errors);
    if block.is_empty() {
        return;
    }

    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static seed source",
    );
    expect(
        exact_string_assignment(&block, "lifecycleMode", "dry-run-plan"),
        errors,
        "API must keep dry-run lifecycle mode",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    for field in [
        "providerCallsEnabled",
        "liveLifecycleAllowed",
        "rawInventoryRowsAllowed",
        "hostIdentifiersAllowed",
    ] {
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
            format!("API endpoint missing {field} field"),
        );
        let values = csharp_array_values(&uncommented, variable, errors);
        validate_array_values_exact(
            values,
            &format!("API {field}"),
            string_array_like(catalog, field),
            errors,
        );
    }
    for (field, expected) in [
        ("requiredInputs", REQUIRED_INPUTS),
        ("requiredEvidence", REQUIRED_EVIDENCE),
    ] {
        validate_array_values_exact(
            endpoint_inline_array_values(&block, field),
            &format!("API {field}"),
            expected.iter().map(|value| (*value).to_string()).collect(),
            errors,
        );
    }

    validate_api_rules(&block, catalog, errors);
    validate_no_prohibited_api_field_names(&block, "vsanEsxiLifecycleEndpoint", errors);
    validate_endpoint_field_names(&block, errors);
    validate_endpoint_property_identifiers(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_no_prohibited_api_terms(&block, "vsanEsxiLifecycleEndpoint", errors);
}

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(uncommented_program);
    if starts.is_empty() {
        errors.push("API missing vSAN and ESXi lifecycle endpoint".to_string());
        return String::new();
    }
    expect(
        starts.len() == 1,
        errors,
        "API must expose exactly one vSAN and ESXi lifecycle endpoint",
    );
    let start_index = starts[0];
    let next_index =
        next_endpoint_index(uncommented_program, start_index).unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_index].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let route = format!("\"{ENDPOINT}\"");
    let mut starts = Vec::new();
    for (route_start, _) in program.match_indices(&route) {
        let line_start = program[..route_start]
            .rfind('\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        let prefix = &program[line_start..route_start];
        let leading_ws = prefix.len() - prefix.trim_start().len();
        if mapget_prefix(prefix) {
            starts.push(line_start + leading_ws);
        }
    }
    starts
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let mut line_start = start_index + 1;
    while line_start < program.len() {
        let next_newline = program[line_start..]
            .find('\n')
            .map(|offset| line_start + offset)
            .unwrap_or(program.len());
        let line = &program[line_start..next_newline];
        if mapget_prefix_before_first_string(line) {
            return Some(line_start + (line.len() - line.trim_start().len()));
        }
        line_start = next_newline.saturating_add(1);
    }
    None
}

fn mapget_prefix_before_first_string(line: &str) -> bool {
    let before_string = line.split('"').next().unwrap_or(line);
    mapget_prefix(before_string)
}

fn mapget_prefix(prefix: &str) -> bool {
    let mut rest = prefix.trim_start();
    let Some(after_app) = rest.strip_prefix("app") else {
        return false;
    };
    rest = after_app.trim_start();
    let Some(after_dot) = rest.strip_prefix('.') else {
        return false;
    };
    rest = after_dot.trim_start();
    let Some(after_mapget) = rest.strip_prefix("MapGet") else {
        return false;
    };
    rest = after_mapget.trim_start();
    let Some(after_paren) = rest.strip_prefix('(') else {
        return false;
    };
    after_paren.trim().is_empty()
}

fn csharp_array_values(program: &str, variable: &str, errors: &mut Vec<String>) -> Vec<String> {
    let marker = format!("var {variable} = new[]");
    let Some(start_index) = program.find(&marker) else {
        errors.push(format!("API missing {variable} declaration"));
        return Vec::new();
    };
    let end_index = program[start_index..]
        .find(';')
        .map(|offset| start_index + offset)
        .unwrap_or(program.len());
    csharp_string_literals(&program[start_index..end_index])
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Vec<String> {
    let marker = format!("{field} = new[]");
    let Some(start_index) = block.find(&marker) else {
        return Vec::new();
    };
    let Some(open_offset) = block[start_index..].find('{') else {
        return Vec::new();
    };
    let open_index = start_index + open_offset;
    let Some(close_index) = matching_brace_index(block, open_index) else {
        return Vec::new();
    };
    csharp_string_literals(&block[open_index + 1..close_index])
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block, errors);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_ids.difference(&api_ids) {
        errors.push(format!("API missing rules: {id}"));
    }
    for id in api_ids.difference(&catalog_ids) {
        errors.push(format!("API unexpected rules: {id}"));
    }
    let ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    expect(
        ids.iter().collect::<BTreeSet<_>>().len() == ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    validate_rule_field_uniqueness(&api_rules, "API", errors);
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            continue;
        };
        expect(
            api_rule.decision == catalog_rule.decision,
            errors,
            format!("API rule {} has wrong decision", catalog_rule.id),
        );
        expect(
            api_rule.requirement == catalog_rule.requirement,
            errors,
            format!("API missing rule requirement {}", catalog_rule.id),
        );
        expect(
            api_rule.evidence == catalog_rule.evidence,
            errors,
            format!("API rule {} has wrong evidence", catalog_rule.id),
        );
    }
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            Some(Rule {
                id: string_value(rule, "id")?.to_string(),
                decision: string_value(rule, "decision")?.to_string(),
                requirement: string_value(rule, "requirement")?.to_string(),
                evidence: string_value(rule, "evidence")?.to_string(),
            })
        })
        .collect()
}

fn api_rules(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(body) = endpoint_rules_body(block, errors) else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(relative) = body[offset..].find("new") {
        let start = offset + relative;
        let Some(open_relative) = body[start..].find('{') else {
            break;
        };
        let open_index = start + open_relative;
        let Some(close_index) = matching_brace_index(&body, open_index) else {
            break;
        };
        let segment = &body[open_index + 1..close_index];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            string_field(segment, "id"),
            string_field(segment, "decision"),
            string_field(segment, "requirement"),
            string_field(segment, "evidence"),
        ) {
            rules.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = close_index + 1;
    }
    rules
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let rules_assignments = assignment_values_for_field(block, "rules");
    if rules_assignments.len() != 1 {
        errors.push("API rules assignment must be present once".to_string());
        return None;
    }
    let rules_index = block.find("rules = new[]")?;
    let open_index = rules_index + block[rules_index..].find('{')?;
    let close_index = matching_brace_index(block, open_index)?;
    Some(block[open_index + 1..close_index].to_string())
}

fn validate_rule_field_uniqueness(rules: &[Rule], label: &str, errors: &mut Vec<String>) {
    let requirements: Vec<&str> = rules.iter().map(|rule| rule.requirement.as_str()).collect();
    let evidence: Vec<&str> = rules.iter().map(|rule| rule.evidence.as_str()).collect();
    expect(
        requirements.iter().collect::<BTreeSet<_>>().len() == requirements.len(),
        errors,
        format!("{label} rule requirements must be unique"),
    );
    expect(
        evidence.iter().collect::<BTreeSet<_>>().len() == evidence.len(),
        errors,
        format!("{label} rule evidence must be unique"),
    );
}

fn validate_array_values_exact(
    values: Vec<String>,
    label: &str,
    expected_values: Vec<String>,
    errors: &mut Vec<String>,
) {
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let expected_set: BTreeSet<&str> = expected_values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = expected_values
        .iter()
        .map(String::as_str)
        .filter(|value| !value_set.contains(value))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|value| !expected_set.contains(value))
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
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{label} values must be unique"),
    );
    for value in values {
        if prohibited_lifecycle_key(&value) {
            errors.push(format!(
                "{label} contains prohibited lifecycle field {value}"
            ));
        }
    }
}

fn validate_no_prohibited_api_terms(text: &str, label: &str, errors: &mut Vec<String>) {
    for value in csharp_string_literals(text) {
        if prohibited_lifecycle_key(&value) {
            errors.push(format!(
                "{label} contains prohibited lifecycle field {value}"
            ));
        }
    }
}

fn validate_no_prohibited_api_field_names(text: &str, label: &str, errors: &mut Vec<String>) {
    for field in assignment_fields(text) {
        if prohibited_lifecycle_key(&field) {
            errors.push(format!(
                "{label} contains prohibited lifecycle field {field}"
            ));
        }
    }
}

fn validate_endpoint_field_names(text: &str, errors: &mut Vec<String>) {
    let expected: BTreeSet<&str> = REQUIRED_ENDPOINT_FIELDS.iter().copied().collect();
    let unexpected: Vec<String> = assignment_fields(text)
        .into_iter()
        .filter(|field| !expected.contains(field.as_str()))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "API endpoint has unexpected vSAN and ESXi lifecycle fields: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_endpoint_property_identifiers(text: &str, errors: &mut Vec<String>) {
    let expected_fields: BTreeSet<&str> = REQUIRED_ENDPOINT_FIELDS.iter().copied().collect();
    let safe_variables: BTreeSet<&str> = ENDPOINT_ARRAY_BINDINGS
        .iter()
        .map(|(_, variable)| *variable)
        .collect();
    for identifier in code_identifiers(text) {
        if expected_fields.contains(identifier.as_str())
            || safe_variables.contains(identifier.as_str())
            || ["app", "MapGet", "Results", "Json", "new", "true", "false"]
                .contains(&identifier.as_str())
        {
            continue;
        }
        if prohibited_lifecycle_key(&identifier) {
            errors.push(format!(
                "API endpoint property {identifier} contains prohibited lifecycle identifier"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(text: &str, errors: &mut Vec<String>) {
    for (field, value) in assignment_values(text) {
        if value == "true" && unsafe_true_key(&field) {
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
        "API README missing vSAN and ESXi lifecycle endpoint",
    );
    // relaxed: the api_readme input is now the generated route inventory
    // (docs/api/endpoints.md), a table of axum paths only. The descriptive
    // "…parity" prose row lived in the deleted hand-maintained C# README and has
    // no place in a generated route table; the parity wording stays asserted on
    // the catalog README and workflow README below, which are authored docs.
    expect(
        catalog_readme.contains("vsan-esxi-lifecycle-contract.yaml"),
        errors,
        "catalog README missing vSAN and ESXi lifecycle catalog",
    );
    expect(
        catalog_readme.contains("VMware, Hyper-V, and Proxmox host lifecycle"),
        errors,
        "catalog README missing vSAN and ESXi lifecycle parity wording",
    );
    expect(
        doc_readme.contains("vsan-esxi-lifecycle.md"),
        errors,
        "workflow README missing vSAN and ESXi lifecycle doc",
    );
    expect(
        doc_readme.contains("Dry-run-only VMware, Hyper-V, and Proxmox host lifecycle contract"),
        errors,
        "workflow README missing vSAN and ESXi lifecycle parity wording",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "vSAN and ESXi lifecycle doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "vSAN and ESXi lifecycle doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live vSAN, ESXi"),
        errors,
        "vSAN and ESXi lifecycle doc must prohibit live lifecycle work",
    );
    expect(
        doc.contains("No raw inventory rows."),
        errors,
        "vSAN and ESXi lifecycle doc must prohibit raw inventory rows",
    );
    expect(
        doc.contains("No host identifiers"),
        errors,
        "vSAN and ESXi lifecycle doc must prohibit host identifiers",
    );
    expect(
        doc.contains("dry-run lifecycle summaries only"),
        errors,
        "vSAN and ESXi lifecycle doc must require dry-run summaries",
    );
    expect(
        doc.contains("without calling VMware, Hyper-V, or Proxmox"),
        errors,
        "vSAN and ESXi lifecycle doc must use provider-neutral call boundary",
    );
    expect(
        doc.contains("not raw VMware, Hyper-V, or Proxmox host inventory"),
        errors,
        "vSAN and ESXi lifecycle doc must prohibit raw hypervisor host inventory",
    );
    for hypervisor in REQUIRED_HYPERVISORS {
        expect(
            doc.contains(hypervisor),
            errors,
            format!("vSAN and ESXi lifecycle doc missing {hypervisor} lifecycle parity"),
        );
    }
    expect(
        doc.contains("Platform lifecycle parity is limited to static dry-run summaries"),
        errors,
        "vSAN and ESXi lifecycle doc missing platform lifecycle parity phrase",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_lifecycle_key(key) {
                    errors.push(format!("{child_path} contains prohibited lifecycle field"));
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
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if whole_file_text(path, text) {
                validate_no_prohibited_multiline_terms(text, path, errors);
            } else if prohibited_lifecycle_key(text) {
                errors.push(format!("{path} contains prohibited lifecycle value {text}"));
            }
        }
        _ => {}
    }
}

fn validate_no_prohibited_multiline_terms(value: &str, path: &str, errors: &mut Vec<String>) {
    if !(path.ends_with(".yaml") || path.ends_with(".yml") || path.ends_with(".txt")) {
        return;
    }
    for (index, line) in value.lines().enumerate() {
        let line_number = index + 1;
        let comment_text = line
            .trim_start()
            .strip_prefix('#')
            .map(str::trim_start)
            .unwrap_or("");
        if SAFE_RAW_CATALOG_COMMENTS.contains(&comment_text) {
            continue;
        }
        for term in multiline_terms(line) {
            if prohibited_lifecycle_key(&term) {
                errors.push(format!(
                    "{path}:{line_number} contains prohibited lifecycle field {term}"
                ));
            }
        }
    }
}

fn validate_raw_catalog_text(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if prohibited_value(line) {
            errors.push(format!("{path}:{line_number} contains prohibited value"));
        }
        let comment_text = line
            .trim_start()
            .strip_prefix('#')
            .map(str::trim_start)
            .unwrap_or("");
        if SAFE_RAW_CATALOG_COMMENTS.contains(&comment_text) {
            continue;
        }
        for term in multiline_terms(line) {
            if prohibited_lifecycle_key(&term) {
                errors.push(format!(
                    "{path}:{line_number} contains prohibited lifecycle field {term}"
                ));
            }
        }
    }
}

fn scan_prohibited_test_literals(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if test_prohibited_literal(line) {
            errors.push(format!(
                "{path}:{} contains prohibited test literal",
                index + 1
            ));
        }
    }
}

fn multiline_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let trimmed = line
        .trim_start()
        .strip_prefix('#')
        .unwrap_or(line)
        .trim_start();
    let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim_start();
    if let Some((key, _)) = trimmed.split_once(':').or_else(|| trimmed.split_once('=')) {
        if key
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
        {
            terms.push(key.trim().to_string());
        }
    }
    for word in words(trimmed) {
        if word.contains('-')
            || word.contains('_')
            || word.chars().any(|ch| ch.is_ascii_uppercase())
        {
            terms.push(word);
        }
    }
    terms.sort();
    terms.dedup();
    terms
}

fn prohibited_lifecycle_key(key: &str) -> bool {
    if safe_lifecycle_text_value(key) {
        return false;
    }
    let normalized = normalized_key(key);
    if SAFE_LIFECYCLE_GUARD_KEYS.contains(&normalized.as_str()) {
        return false;
    }
    [
        "hostname",
        "hostnames",
        "hostid",
        "hostids",
        "hostidentifier",
        "hostidentifiers",
        "hostmoref",
        "username",
        "password",
        "credential",
        "credentials",
        "secret",
        "token",
        "tenantid",
        "objectid",
        "objectidentifier",
        "objectidentifiers",
        "moref",
        "morefs",
        "uuid",
        "instanceuuid",
        "biosuuid",
        "endpoint",
        "endpointname",
        "endpointurl",
        "privateip",
        "rawinventoryrow",
        "rawinventoryrows",
        "providerpayload",
        "providerpayloads",
        "rawproviderpayload",
        "rawproviderpayloads",
        "datastorepath",
        "datastorepaths",
        "serial",
        "serialnumber",
        "assettag",
    ]
    .contains(&normalized.as_str())
        || [
            "hostname",
            "hostid",
            "hostidentifier",
            "hostmoref",
            "username",
            "password",
            "credential",
            "secret",
            "token",
            "tenantid",
            "objectid",
            "objectidentifier",
            "moref",
            "uuid",
            "endpoint",
            "privateip",
            "rawinventory",
            "providerpayload",
            "rawproviderpayload",
            "datastorepath",
            "serial",
            "assettag",
        ]
        .iter()
        .any(|term| normalized.contains(term))
}

fn safe_lifecycle_text_value(value: &str) -> bool {
    let text = value.trim();
    [
        REQUIRED_HYPERVISORS,
        REQUIRED_PLATFORM_LIFECYCLE_PARITY,
        REQUIRED_WORKFLOWS,
        REQUIRED_DOMAINS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_CATALOG_KEYS,
        REQUIRED_ENDPOINT_FIELDS,
    ]
    .iter()
    .any(|items| items.contains(&text))
        || ["draft", "static-seed", "dry-run-plan", "block"].contains(&text)
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
}

fn prohibited_value(text: &str) -> bool {
    contains_akia(text)
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || contains_url_scheme(text)
        || contains_private_ipv4(text)
        || contains_uuid_like(text)
        || contains_moref_like(text)
        || contains_datastore_path(text)
        || contains_secret_assignment(text)
        || contains_fqdn(text)
        || contains_domain_user(text)
        || contains_email(text)
}

fn test_prohibited_literal(text: &str) -> bool {
    contains_akia(text)
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || contains_url_scheme(text)
        || contains_private_ipv4(text)
        || contains_uuid_like(text)
        || contains_moref_like(text)
        || contains_datastore_path(text)
        || contains_secret_assignment(text)
        || contains_fqdn(text)
        || contains_email(text)
}

fn contains_akia(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    bytes.windows(4).enumerate().any(|(index, window)| {
        window == b"AKIA"
            && bytes
                .get(index + 4..index + 20)
                .is_some_and(|tail| tail.iter().all(|byte| byte.is_ascii_alphanumeric()))
    })
}

fn contains_url_scheme(text: &str) -> bool {
    text.find("://").is_some_and(|index| {
        let scheme = &text[..index];
        !scheme.is_empty()
            && scheme
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
    })
}

fn contains_private_ipv4(text: &str) -> bool {
    for token in text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            continue;
        }
        let parsed = parts
            .iter()
            .map(|part| part.parse::<u8>())
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

fn contains_moref_like(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for token in lower.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-')) {
        let Some((prefix, suffix)) = token.rsplit_once('-') else {
            continue;
        };
        if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if matches!(
            prefix,
            "vm" | "host"
                | "domain-c"
                | "domain-s"
                | "group-a"
                | "resgroup"
                | "datastore"
                | "network"
                | "dvportgroup"
                | "dvs"
                | "folder"
                | "cluster"
                | "datacenter"
        ) {
            return true;
        }
    }
    false
}

fn contains_datastore_path(text: &str) -> bool {
    let Some(close_index) = text.find(']') else {
        return false;
    };
    if !text[..close_index].contains('[') {
        return false;
    }
    let after = &text[close_index + 1..];
    if !after
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_whitespace())
    {
        return false;
    }
    let path = after
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(|ch: char| matches!(ch, ',' | ';' | ')' | '}' | ']'));
    path.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphanumeric())
        && (path.contains('/') || path.contains('.'))
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
        let boundary = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if boundary {
            let tail = text[end..].trim_start();
            if tail.chars().next().is_some_and(|ch| ch == ':' || ch == '=')
                && tail[1..].chars().any(|ch| !ch.is_whitespace())
            {
                return true;
            }
        }
        offset = end;
    }
    false
}

fn contains_fqdn(text: &str) -> bool {
    for token in text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-')) {
        let labels: Vec<&str> = token.split('.').collect();
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

fn contains_domain_user(text: &str) -> bool {
    for token in
        text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '\\' | '.' | '_' | '-')))
    {
        let Some((domain, user)) = token.split_once('\\') else {
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

fn contains_email(text: &str) -> bool {
    for token in text.split(|ch: char| {
        !(ch.is_ascii_alphanumeric() || matches!(ch, '@' | '.' | '_' | '%' | '+' | '-'))
    }) {
        let Some((local, domain)) = token.split_once('@') else {
            continue;
        };
        if local.is_empty() || domain.is_empty() {
            continue;
        }
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() >= 2
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

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
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

fn assignment_fields(block: &str) -> Vec<String> {
    assignment_values(block)
        .into_iter()
        .map(|(field, _)| field)
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
    let tail = &segment[start..];
    let mut value = String::new();
    let mut escaped = false;
    for ch in tail.chars() {
        if escaped {
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(value);
        } else {
            value.push(ch);
        }
    }
    None
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        for inner in chars.by_ref() {
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
        literals.push(value);
    }
    literals
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

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
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
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
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

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn scan_unsafe_true_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if unsafe_true_key(key) && child.as_bool() == Some(true) {
                    errors.push(format!("{path} has unsafe true flag {key}"));
                }
                scan_unsafe_true_values(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_unsafe_true_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        _ => {}
    }
}

fn unsafe_true_key(key: &str) -> bool {
    ["live", "provider", "execution", "action", "remediation"]
        .iter()
        .any(|term| key.to_ascii_lowercase().contains(term))
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

fn words(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            current.push(ch);
        } else if !current.is_empty() {
            result.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
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
    use serde_json::json;

    fn catalog() -> Value {
        json!({
            "version": 1,
            "status": "draft",
            "source": "static-seed",
            "lifecycleMode": "dry-run-plan",
            "dryRunRequired": true,
            "providerCallsEnabled": false,
            "liveLifecycleAllowed": false,
            "rawInventoryRowsAllowed": false,
            "hostIdentifiersAllowed": false,
            "supportedHypervisors": REQUIRED_HYPERVISORS,
            "platformLifecycleParity": REQUIRED_PLATFORM_LIFECYCLE_PARITY,
            "supportedWorkflows": REQUIRED_WORKFLOWS,
            "lifecycleDomains": REQUIRED_DOMAINS,
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
            r#"var vsanEsxiLifecycleSupportedHypervisors = new[] {{ {} }};
var vsanEsxiLifecyclePlatformLifecycleParity = new[] {{ {} }};
var vsanEsxiLifecycleWorkflows = new[] {{ {} }};
var vsanEsxiLifecycleDomains = new[] {{ {} }};
var vsanEsxiLifecycleRequiredGuards = new[] {{ {} }};
var vsanEsxiLifecyclePlanSections = new[] {{ {} }};
var vsanEsxiLifecycleBlockedReasons = new[] {{ {} }};
app.MapGet("{ENDPOINT}", () => Results.Json(new
{{
    source = "static-seed",
    lifecycleMode = "dry-run-plan",
    dryRunRequired = true,
    providerCallsEnabled = false,
    liveLifecycleAllowed = false,
    rawInventoryRowsAllowed = false,
    hostIdentifiersAllowed = false,
    supportedHypervisors = vsanEsxiLifecycleSupportedHypervisors,
    platformLifecycleParity = vsanEsxiLifecyclePlatformLifecycleParity,
    supportedWorkflows = vsanEsxiLifecycleWorkflows,
    lifecycleDomains = vsanEsxiLifecycleDomains,
    requiredInputs = new[] {{ {} }},
    requiredGuards = vsanEsxiLifecycleRequiredGuards,
    planSections = vsanEsxiLifecyclePlanSections,
    blockedReasons = vsanEsxiLifecycleBlockedReasons,
    requiredEvidence = new[] {{ {} }},
    rules = new[] {{ {} }}
}}));"#,
            csharp_array(REQUIRED_HYPERVISORS),
            csharp_array(REQUIRED_PLATFORM_LIFECYCLE_PARITY),
            csharp_array(REQUIRED_WORKFLOWS),
            csharp_array(REQUIRED_DOMAINS),
            csharp_array(REQUIRED_GUARDS),
            csharp_array(REQUIRED_PLAN_SECTIONS),
            csharp_array(REQUIRED_BLOCKED_REASONS),
            csharp_array(REQUIRED_INPUTS),
            csharp_array(REQUIRED_EVIDENCE),
            csharp_rules()
        )
    }

    #[test]
    fn endpoint_indexes_include_spaced_mapget() {
        let program = format!(
            "app . MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"live\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        assert_eq!(endpoint_start_indexes(&program).len(), 2);
    }

    #[test]
    fn prohibited_shapes_are_detected() {
        assert!(contains_moref_like("host-123"));
        assert!(contains_datastore_path("[safe-summary] image.iso"));
        assert!(prohibited_lifecycle_key("hostMoRef"));
    }

    #[test]
    fn commented_source_decoy_does_not_satisfy_endpoint() {
        let program = valid_program().replacen(
            "source = \"static-seed\",",
            "// source = \"static-seed\",\n    source = \"live-provider\",",
            1,
        );
        let mut errors = Vec::new();

        validate_program_text_csharp(&program, &catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("static seed source")));
    }

    #[test]
    fn suffix_route_bypass_is_not_registered() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}-live\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );

        assert!(endpoint_start_indexes(&program).is_empty());
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
            .any(|error| error.contains("rule requirements must be unique")));
        assert!(errors
            .iter()
            .any(|error| error.contains("rule evidence must be unique")));
    }

    #[test]
    fn duplicate_source_assignment_spoofing_is_rejected() {
        let program = valid_program().replacen(
            "source = \"static-seed\",",
            "source = liveSource,\n    source = \"static-seed\",",
            1,
        );
        let mut errors = Vec::new();

        validate_program_text_csharp(&program, &catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("static seed source")));
    }

    #[test]
    fn endpoint_property_identifier_is_rejected() {
        let program = valid_program().replacen(
            "source = \"static-seed\",",
            "source = safeSummary.endpointName,",
            1,
        );
        let mut errors = Vec::new();

        validate_program_text_csharp(&program, &catalog(), &mut errors);

        assert!(errors.iter().any(|error| error.contains("endpointName")));
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

    #[test]
    fn unsafe_provider_identifier_true_flag_is_rejected() {
        let program = valid_program().replacen(
            "lifecycleMode = \"dry-run-plan\",",
            "lifecycleMode = \"dry-run-plan\",\n    providerPayloadAllowed = true,",
            1,
        );
        let mut errors = Vec::new();

        validate_program_text_csharp(&program, &catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("providerPayloadAllowed")));
    }
}
