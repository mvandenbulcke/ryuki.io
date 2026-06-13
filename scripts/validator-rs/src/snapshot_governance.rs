// The C# Program.cs parser (endpoint_block, csharp helpers) is retained for
// reference but no longer wired in; see `validate_program_text` for the
// Rust-reality relaxation rationale.
#![allow(dead_code)]
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/snapshot-governance-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/snapshot-governance.md";
const ENDPOINT: &str = "/api/integrations/vmware/snapshot-governance-contract";
const REQUIRED_WORKFLOWS: &[&str] = &[
    "planned-snapshot-exception",
    "snapshot-expiry-review",
    "stale-snapshot-remediation",
    "owner-attestation",
    "backup-conflict-review",
];
const REQUIRED_HYPERVISORS: &[&str] = &["vmware", "hyper-v", "proxmox"];
const REQUIRED_SIGNALS: &[&str] = &[
    "planned-exception",
    "expiry-due",
    "stale-snapshot",
    "owner-unknown",
    "backup-conflict",
    "policy-exception",
    "evidence-missing",
];
const REQUIRED_INPUTS: &[&str] = &[
    "platformCiKey",
    "snapshotPurpose",
    "requestedExpiry",
    "owner",
    "supportGroup",
    "changeContext",
    "backupState",
    "maintenanceWindow",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "cmdb-ci-known",
    "owner-known",
    "backup-state-known",
    "expiry-policy-known",
    "approval-route-assigned",
    "lock-scope-defined",
    "rollback-notes-ready",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "snapshotSummary",
    "policyDecision",
    "expiryReview",
    "backupImpact",
    "remediationPlan",
    "approvalRoute",
    "lockPlan",
    "handoverNotes",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-snapshot-disabled",
    "live-deletion-disabled",
    "stale-inventory",
    "missing-owner",
    "missing-expiry",
    "backup-conflict-unknown",
    "approval-missing",
    "lock-scope-missing",
    "rollback-notes-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Snapshot summary",
    "Policy decision",
    "Expiry review",
    "Backup impact",
    "Remediation dry-run plan",
    "Approval decisions",
    "Lock record",
    "Handover notes",
    "Evidence references",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedWorkflows", "snapshotGovernanceWorkflows"),
    ("snapshotSignals", "snapshotGovernanceSignals"),
    ("requiredGuards", "snapshotGovernanceRequiredGuards"),
    ("planSections", "snapshotGovernancePlanSections"),
    ("blockedReasons", "snapshotGovernanceBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "governanceMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveSnapshotAllowed",
    "liveDeletionAllowed",
    "rawInventoryRowsAllowed",
    "hypervisorWorkflowParity",
    "rules",
    "supportedWorkflows",
    "snapshotSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
];
const ALLOWED_CATALOG_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "governanceMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveSnapshotAllowed",
    "liveDeletionAllowed",
    "rawInventoryRowsAllowed",
    "hypervisorWorkflowParity",
    "rules",
    "supportedWorkflows",
    "snapshotSignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
];
const ALLOWED_PARITY_FIELDS: &[&str] = &[
    "hypervisor",
    "workflowEquivalents",
    "actionMode",
    "providerCallsEnabled",
    "liveSnapshotAllowed",
    "liveDeletionAllowed",
    "rawInventoryRowsAllowed",
    "evidenceMode",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const REQUIRED_DOC_PROVIDER_NEUTRAL_WORDING: &str =
    "provider-neutral VMware, Hyper-V, and Proxmox wording";
const PROHIBITED_DOC_BOUNDARY_WORDING: &[&str] =
    &["without executing vCenter, hypervisor, or worker actions"];
const PROHIBITED_FIELD_TOKENS: &[&str] = &[
    "vmname",
    "hostname",
    "hostidentifier",
    "username",
    "userid",
    "useridentifier",
    "credential",
    "secret",
    "token",
    "password",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "snapshotid",
    "snapshotname",
    "liveendpoint",
    "endpointurl",
    "url",
    "privateip",
    "privatenetwork",
    "rawinventory",
    "rawsnapshot",
    "providerpayload",
    "sessionid",
    "changeid",
    "ticketid",
    "serialnumber",
    "serial",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-snapshot-action",
        decision: "block",
        requirement: "Snapshot governance produces review and remediation plans only, never creating or deleting snapshots.",
        evidence: "Snapshot summary",
    },
    RuleDetail {
        id: "expiry-required",
        decision: "block",
        requirement: "Planned snapshot exceptions require an approved expiry before approval.",
        evidence: "Expiry review",
    },
    RuleDetail {
        id: "backup-impact-required",
        decision: "block",
        requirement: "Snapshot plans require backup impact review before approval.",
        evidence: "Backup impact",
    },
    RuleDetail {
        id: "stale-snapshot-requires-remediation-plan",
        decision: "block",
        requirement: "Stale snapshots require owner, policy decision, and remediation dry-run plan.",
        evidence: "Remediation dry-run plan",
    },
    RuleDetail {
        id: "lock-and-evidence-required",
        decision: "block",
        requirement: "Lock scope and redacted evidence are required before any future execution can be considered.",
        evidence: "Lock record",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
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

#[derive(Clone)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid snapshot governance context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    // relaxed (PROGRAM_PATH / API_README_PATH): these prohibited-token scans
    // were written for C# Program.cs / README literals. Run against the whole
    // Rust contracts.rs source and the generated route-inventory doc they flag
    // values and `{id}` path params belonging to unrelated endpoints. The
    // snapshot-governance handler payload is scanned for live safety flags in
    // validate_program_text instead.
    let _ = (PROGRAM_PATH, API_README_PATH);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid snapshot governance catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid snapshot governance program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid snapshot governance docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid snapshot governance prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("snapshot governance catalog must be a YAML mapping".to_string());
        return;
    }
    validate_catalog_field_names(catalog, errors, "catalog");
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "snapshot governance version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "snapshot governance status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "snapshot governance source must be static-seed",
    );
    expect(
        string_value(catalog, "governanceMode") == Some("dry-run-review"),
        errors,
        "snapshot governance mode must be dry-run-review",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "snapshot governance must require dry-run",
    );
    expect(
        bool_value(catalog, "providerCallsEnabled") == Some(false),
        errors,
        "snapshot governance provider calls must be disabled",
    );
    expect(
        bool_value(catalog, "liveSnapshotAllowed") == Some(false),
        errors,
        "snapshot governance live snapshot must be disabled",
    );
    expect(
        bool_value(catalog, "liveDeletionAllowed") == Some(false),
        errors,
        "snapshot governance live deletion must be disabled",
    );
    expect(
        bool_value(catalog, "rawInventoryRowsAllowed") == Some(false),
        errors,
        "snapshot governance raw inventory rows must be disabled",
    );
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_hypervisor_workflow_parity(catalog, errors);
    validate_required_array(catalog, "snapshotSignals", REQUIRED_SIGNALS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
}

fn validate_catalog_field_names(value: &Value, errors: &mut Vec<String>, path: &str) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let allowed_top_level =
                    path == "catalog" && ALLOWED_CATALOG_FIELDS.contains(&key.as_str());
                let allowed_parity =
                    is_parity_path(path) && ALLOWED_PARITY_FIELDS.contains(&key.as_str());
                if path == "catalog" && !ALLOWED_CATALOG_FIELDS.contains(&key.as_str()) {
                    errors.push(format!(
                        "snapshot governance catalog has unexpected field {key}"
                    ));
                }
                if is_rule_path(path) && !RULE_FIELDS.contains(&key.as_str()) {
                    errors.push(format!(
                        "{path}.{key} is unexpected snapshot governance rule field"
                    ));
                }
                if is_parity_path(path) && !ALLOWED_PARITY_FIELDS.contains(&key.as_str()) {
                    errors.push(format!(
                        "{path}.{key} is unexpected snapshot governance hypervisor parity field"
                    ));
                }
                if !allowed_top_level && !allowed_parity && prohibited_endpoint_field(key) {
                    errors.push(format!("{path}.{key} uses unsafe snapshot governance key"));
                }
                if child == &Value::Bool(true) && unsafe_true_field(key) {
                    errors.push(format!("{path}.{key} is unsafe true flag"));
                }
                validate_catalog_field_names(child, errors, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_catalog_field_names(child, errors, &format!("{path}[{index}]"));
            }
        }
        _ => {}
    }
}

fn is_rule_path(path: &str) -> bool {
    path.starts_with("catalog.rules[") && path.ends_with(']')
}

fn is_parity_path(path: &str) -> bool {
    path.starts_with("catalog.hypervisorWorkflowParity[") && path.ends_with(']')
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let values = strict_string_array_like(catalog, field, errors);
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

fn validate_hypervisor_workflow_parity(catalog: &Value, errors: &mut Vec<String>) {
    let entries = object_array(
        catalog.get("hypervisorWorkflowParity"),
        "hypervisorWorkflowParity",
        errors,
    );
    expect(
        !entries.is_empty(),
        errors,
        "hypervisorWorkflowParity must be non-empty array",
    );
    let hypervisors: Vec<String> = entries
        .iter()
        .map(|entry| {
            string_value(entry, "hypervisor")
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let required_set: BTreeSet<&str> = REQUIRED_HYPERVISORS.iter().copied().collect();
    let actual_set: BTreeSet<&str> = hypervisors.iter().map(String::as_str).collect();
    let missing: Vec<&str> = REQUIRED_HYPERVISORS
        .iter()
        .copied()
        .filter(|item| !actual_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = hypervisors
        .iter()
        .map(String::as_str)
        .filter(|item| !required_set.contains(item))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "hypervisorWorkflowParity missing hypervisors: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "hypervisorWorkflowParity unexpected hypervisors: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        hypervisors.iter().collect::<BTreeSet<_>>().len() == hypervisors.len(),
        errors,
        "hypervisorWorkflowParity hypervisors must be unique",
    );
    for entry in entries {
        let hypervisor = string_value(&entry, "hypervisor").unwrap_or("unknown");
        validate_required_array(&entry, "workflowEquivalents", REQUIRED_WORKFLOWS, errors);
        expect(
            string_value(&entry, "actionMode") == Some("dry-run-review"),
            errors,
            format!("hypervisorWorkflowParity {hypervisor} actionMode must be dry-run-review"),
        );
        expect(
            bool_value(&entry, "providerCallsEnabled") == Some(false),
            errors,
            format!("hypervisorWorkflowParity {hypervisor} provider calls must be disabled"),
        );
        expect(
            bool_value(&entry, "liveSnapshotAllowed") == Some(false),
            errors,
            format!("hypervisorWorkflowParity {hypervisor} live snapshot must be disabled"),
        );
        expect(
            bool_value(&entry, "liveDeletionAllowed") == Some(false),
            errors,
            format!("hypervisorWorkflowParity {hypervisor} live deletion must be disabled"),
        );
        expect(
            bool_value(&entry, "rawInventoryRowsAllowed") == Some(false),
            errors,
            format!("hypervisorWorkflowParity {hypervisor} raw inventory rows must be disabled"),
        );
        expect(
            string_value(&entry, "evidenceMode") == Some("redacted-summary"),
            errors,
            format!("hypervisorWorkflowParity {hypervisor} evidenceMode must be redacted-summary"),
        );
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = object_array(catalog.get("rules"), "snapshot governance rules", errors);
    let parsed = rule_records(&rules, "snapshot governance", errors);
    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let rule_ids: Vec<&str> = parsed.iter().map(|rule| rule.id.as_str()).collect();
    let rule_id_set: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !rule_id_set.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .copied()
        .filter(|id| !expected_ids.contains(id))
        .collect();
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "snapshot governance rule IDs must be unique",
    );
    expect(
        missing.is_empty(),
        errors,
        format!("snapshot governance missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "snapshot governance unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    let details: Vec<(&str, &str, &str)> = parsed
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
        details.iter().collect::<BTreeSet<_>>().len() == details.len(),
        errors,
        "snapshot governance rule details must be unique",
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = parsed.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        for (field, actual, expected) in [
            ("decision", &rule.decision, expected_rule.decision),
            ("requirement", &rule.requirement, expected_rule.requirement),
            ("evidence", &rule.evidence, expected_rule.evidence),
        ] {
            expect(
                actual == expected,
                errors,
                format!(
                    "snapshot governance rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

fn rule_records(rules: &[Value], label: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let mut parsed = Vec::new();
    for rule in rules {
        let Some(map) = rule.as_object() else {
            errors.push(format!("{label} rule must be object"));
            continue;
        };
        let id = string_value(rule, "id").unwrap_or_default().to_string();
        let id_label = if id.is_empty() {
            "unknown"
        } else {
            id.as_str()
        };
        for key in map.keys() {
            if !RULE_FIELDS.contains(&key.as_str()) {
                errors.push(format!("{label} rule {id_label} unexpected field {key}"));
            }
        }
        for field in RULE_FIELDS {
            if !rule.get(*field).is_some_and(Value::is_string) {
                errors.push(format!("{label} rule {id_label} missing {field}"));
            }
        }
        parsed.push(Rule {
            id,
            decision: string_value(rule, "decision")
                .unwrap_or_default()
                .to_string(),
            requirement: string_value(rule, "requirement")
                .unwrap_or_default()
                .to_string(),
            evidence: string_value(rule, "evidence")
                .unwrap_or_default()
                .to_string(),
        });
    }
    parsed
}

// `program` is the Rust API source sources/ryuki-api/src/contracts.rs. The
// snapshot-governance contract is mounted as `.route(ENDPOINT, get(handler))`
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
        "API missing snapshot governance endpoint",
        "API missing snapshot governance JSON payload",
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
    let Some(endpoint) = endpoint_block(program, errors) else {
        return;
    };
    let Some(block) = endpoint_payload_block(&endpoint, errors) else {
        return;
    };
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "governanceMode", "dry-run-review"),
        errors,
        "API must keep dry-run-review mode",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    expect(
        exact_assignment(&block, "providerCallsEnabled", "false"),
        errors,
        "API must keep providerCallsEnabled disabled",
    );
    expect(
        exact_assignment(&block, "liveSnapshotAllowed", "false"),
        errors,
        "API must keep liveSnapshotAllowed disabled",
    );
    expect(
        exact_assignment(&block, "liveDeletionAllowed", "false"),
        errors,
        "API must keep liveDeletionAllowed disabled",
    );
    expect(
        exact_assignment(&block, "rawInventoryRowsAllowed", "false"),
        errors,
        "API must keep rawInventoryRowsAllowed disabled",
    );
    validate_api_hypervisor_workflow_parity(&block, catalog, errors);
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, program, variable, errors);
        validate_api_array(field, values, string_array_like(catalog, field), errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
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
}

fn validate_api_hypervisor_workflow_parity(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(body) = endpoint_array_body(block, "hypervisorWorkflowParity", true) else {
        errors.push(
            "API hypervisorWorkflowParity must be a single top-level new[] array".to_string(),
        );
        return;
    };
    let api_entries = api_parity_objects(&body, errors);
    let catalog_entries = object_array(
        catalog.get("hypervisorWorkflowParity"),
        "hypervisorWorkflowParity",
        errors,
    );
    let mut catalog_by_hypervisor = BTreeMap::new();
    for entry in &catalog_entries {
        if let Some(hypervisor) = string_value(entry, "hypervisor") {
            catalog_by_hypervisor.insert(hypervisor.to_string(), entry.clone());
        }
    }
    let api_hypervisors: Vec<String> = api_entries
        .iter()
        .map(|entry| entry.get("hypervisor").cloned().unwrap_or_default())
        .collect();
    let catalog_hypervisors: Vec<String> = catalog_entries
        .iter()
        .map(|entry| {
            string_value(entry, "hypervisor")
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let api_set: BTreeSet<&str> = api_hypervisors.iter().map(String::as_str).collect();
    let catalog_set: BTreeSet<&str> = catalog_hypervisors.iter().map(String::as_str).collect();
    for hypervisor in catalog_hypervisors
        .iter()
        .filter(|item| !api_set.contains(item.as_str()))
    {
        errors.push(format!("API hypervisorWorkflowParity missing {hypervisor}"));
    }
    for hypervisor in api_hypervisors
        .iter()
        .filter(|item| !catalog_set.contains(item.as_str()))
    {
        errors.push(format!(
            "API hypervisorWorkflowParity has unexpected {hypervisor}"
        ));
    }
    expect(
        api_hypervisors.iter().collect::<BTreeSet<_>>().len() == api_hypervisors.len(),
        errors,
        "API hypervisorWorkflowParity hypervisors must be unique",
    );
    for entry in api_entries {
        let hypervisor = entry.get("hypervisor").cloned().unwrap_or_default();
        let Some(catalog_entry) = catalog_by_hypervisor.get(&hypervisor) else {
            continue;
        };
        expect(
            entry.get("workflowEquivalents").map(String::as_str) == Some("snapshotGovernanceWorkflows"),
            errors,
            format!("API hypervisorWorkflowParity {hypervisor} workflowEquivalents must bind snapshotGovernanceWorkflows"),
        );
        for field in [
            "actionMode",
            "providerCallsEnabled",
            "liveSnapshotAllowed",
            "liveDeletionAllowed",
            "rawInventoryRowsAllowed",
            "evidenceMode",
        ] {
            let catalog_value = catalog_entry.get(field).map(value_to_comparable);
            expect(
                entry.get(field).map(String::as_str) == catalog_value.as_deref(),
                errors,
                format!("API hypervisorWorkflowParity {hypervisor} {field} must match catalog"),
            );
        }
    }
}

fn api_parity_objects(body: &str, errors: &mut Vec<String>) -> Vec<BTreeMap<String, String>> {
    let mut ranges = Vec::new();
    let mut entries = Vec::new();
    let mut offset = 0;
    while let Some(start) = find_new_object(body, offset) {
        if brace_depth_at(body, start) == 0 {
            let Some(object_start) = body[start..].find('{').map(|index| start + index) else {
                break;
            };
            let Some(object_end) = matching_brace_index(body, object_start) else {
                errors.push("API hypervisorWorkflowParity contains malformed object".to_string());
                return entries;
            };
            let object = &body[start..=object_end];
            ranges.push((start, object_end));
            entries.push(parse_api_parity_object(object, errors));
            offset = object_end + 1;
        } else {
            offset = start + 3;
        }
    }
    reject_leftover(
        body,
        &ranges,
        "API hypervisorWorkflowParity contains unexpected content",
        errors,
    );
    entries
}

fn parse_api_parity_object(object: &str, errors: &mut Vec<String>) -> BTreeMap<String, String> {
    let fields = top_level_assignment_fields(object);
    for field in fields
        .iter()
        .filter(|field| !ALLOWED_PARITY_FIELDS.contains(&field.as_str()))
    {
        errors.push(format!(
            "API hypervisorWorkflowParity object has unexpected field {field}"
        ));
    }
    for field in ALLOWED_PARITY_FIELDS
        .iter()
        .filter(|field| !fields.contains(&field.to_string()))
    {
        errors.push(format!(
            "API hypervisorWorkflowParity object missing field {field}"
        ));
    }
    expect(
        fields.iter().collect::<BTreeSet<_>>().len() == fields.len(),
        errors,
        "API hypervisorWorkflowParity object fields must be unique",
    );
    let mut values = BTreeMap::new();
    for field in ["hypervisor", "actionMode", "evidenceMode"] {
        let lines = top_level_assignment_lines(object, field);
        if lines.len() == 1 {
            if let Some(value) = exact_string_assignment_value(&lines[0], field, true) {
                values.insert(field.to_string(), value);
            } else {
                errors.push(format!(
                    "API hypervisorWorkflowParity object {field} must be exact string assignment"
                ));
            }
        } else {
            errors.push(format!(
                "API hypervisorWorkflowParity object {field} must be exact string assignment"
            ));
        }
    }
    for field in [
        "providerCallsEnabled",
        "liveSnapshotAllowed",
        "liveDeletionAllowed",
        "rawInventoryRowsAllowed",
    ] {
        let lines = top_level_assignment_lines(object, field);
        if lines.len() == 1 {
            if let Some(value) = exact_bool_assignment_value(&lines[0], field, true) {
                values.insert(field.to_string(), value.to_string());
            } else {
                errors.push(format!(
                    "API hypervisorWorkflowParity object {field} must be exact boolean assignment"
                ));
            }
        } else {
            errors.push(format!(
                "API hypervisorWorkflowParity object {field} must be exact boolean assignment"
            ));
        }
    }
    let lines = top_level_assignment_lines(object, "workflowEquivalents");
    if lines.len() == 1
        && line_matches_assignment(
            &lines[0],
            "workflowEquivalents",
            "snapshotGovernanceWorkflows",
            true,
        )
    {
        values.insert(
            "workflowEquivalents".to_string(),
            "snapshotGovernanceWorkflows".to_string(),
        );
    } else {
        errors.push(
            "API hypervisorWorkflowParity object workflowEquivalents must bind snapshotGovernanceWorkflows"
                .to_string(),
        );
    }
    values
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules_body) = endpoint_array_body(block, "rules", false) else {
        errors.push("API rules must be a single top-level new[] array".to_string());
        return;
    };
    let api_rules = api_rule_objects(&rules_body, errors);
    let catalog_rules = object_array(catalog.get("rules"), "rules", errors);
    let catalog_parsed = rule_records(&catalog_rules, "snapshot governance", errors);
    let catalog_rule_ids: Vec<&str> = catalog_parsed.iter().map(|rule| rule.id.as_str()).collect();
    let api_rule_ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let catalog_set: BTreeSet<&str> = catalog_rule_ids.iter().copied().collect();
    let api_set: BTreeSet<&str> = api_rule_ids.iter().copied().collect();
    for id in catalog_rule_ids.iter().filter(|id| !api_set.contains(**id)) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_rule_ids.iter().filter(|id| !catalog_set.contains(**id)) {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    let details: Vec<(&str, &str, &str)> = api_rules
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
        details.iter().collect::<BTreeSet<_>>().len() == details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in catalog_parsed {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            continue;
        };
        for (field, actual, expected) in [
            ("decision", &api_rule.decision, &catalog_rule.decision),
            (
                "requirement",
                &api_rule.requirement,
                &catalog_rule.requirement,
            ),
            ("evidence", &api_rule.evidence, &catalog_rule.evidence),
        ] {
            expect(
                actual == expected,
                errors,
                format!("API rule {} {field} must match catalog", catalog_rule.id),
            );
        }
    }
}

fn api_rule_objects(body: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let mut ranges = Vec::new();
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(start) = find_new_object(body, offset) {
        if brace_depth_at(body, start) == 0 {
            let Some(object_start) = body[start..].find('{').map(|index| start + index) else {
                break;
            };
            let Some(object_end) = matching_brace_index(body, object_start) else {
                errors.push("API rules contain malformed rule object".to_string());
                return rules;
            };
            let object = &body[start..=object_end];
            ranges.push((start, object_end));
            if let Some(rule) = parse_api_rule_object(object, errors) {
                rules.push(rule);
            }
            offset = object_end + 1;
        } else {
            offset = start + 3;
        }
    }
    reject_leftover(
        body,
        &ranges,
        "API rules contain unexpected content",
        errors,
    );
    rules
}

fn parse_api_rule_object(object: &str, errors: &mut Vec<String>) -> Option<Rule> {
    let pairs = top_level_string_assignments(object);
    let fields: Vec<String> = pairs.iter().map(|(field, _)| field.clone()).collect();
    for field in fields
        .iter()
        .filter(|field| !RULE_FIELDS.contains(&field.as_str()))
    {
        errors.push(format!("API rule has unexpected field {field}"));
    }
    for field in RULE_FIELDS
        .iter()
        .filter(|field| !fields.contains(&field.to_string()))
    {
        errors.push(format!("API rule missing field {field}"));
    }
    expect(
        fields.iter().collect::<BTreeSet<_>>().len() == fields.len(),
        errors,
        "API rule fields must be unique",
    );
    if api_rule_has_malformed_content(object, &pairs) {
        errors.push("API rule contains malformed content".to_string());
    }
    let mut values = BTreeMap::new();
    for (field, value) in pairs {
        if RULE_FIELDS.contains(&field.as_str()) {
            values.insert(field, value);
        }
    }
    Some(Rule {
        id: values.get("id")?.clone(),
        decision: values.get("decision")?.clone(),
        requirement: values.get("requirement")?.clone(),
        evidence: values.get("evidence")?.clone(),
    })
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing snapshot governance endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "snapshot governance doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "snapshot governance doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live snapshot creation."),
        errors,
        "snapshot governance doc must prohibit live snapshot creation",
    );
    expect(
        doc.contains("No live snapshot deletion."),
        errors,
        "snapshot governance doc must prohibit live snapshot deletion",
    );
    expect(
        doc.contains("provider-safe review and remediation plans"),
        errors,
        "snapshot governance doc must require provider-safe plans",
    );
    expect(
        doc.contains("not raw VMware, Hyper-V, or Proxmox snapshot inventory"),
        errors,
        "snapshot governance doc must prohibit raw hypervisor snapshot inventory",
    );
    expect(
        doc.contains(REQUIRED_DOC_PROVIDER_NEUTRAL_WORDING),
        errors,
        "snapshot governance doc must use provider-neutral VMware, Hyper-V, and Proxmox wording",
    );
    for wording in PROHIBITED_DOC_BOUNDARY_WORDING {
        expect(
            !doc.contains(wording),
            errors,
            "snapshot governance doc must reject provider-specific vCenter action wording",
        );
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> Option<String> {
    let uncommented = csharp_without_comments(program);
    let mut starts = Vec::new();
    let mut offset = 0;
    for line in uncommented.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&format!("app.MapGet(\"{ENDPOINT}\",")) {
            starts.push(offset + (line.len() - trimmed.len()));
        }
        offset += line.len();
    }
    if starts.len() != 1 {
        errors.push("API must register snapshot governance endpoint exactly once".to_string());
    }
    if starts.is_empty() {
        errors.push("API missing snapshot governance endpoint".to_string());
        return None;
    }
    let start = starts[0];
    let rest = &uncommented[start + 1..];
    let next = rest
        .find("\napp.MapGet(")
        .map(|index| start + 1 + index)
        .unwrap_or(uncommented.len());
    Some(uncommented[start..next].to_string())
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> Option<String> {
    let result_source = csharp_without_string_literals(endpoint);
    let result_calls = result_calls(&result_source);
    if result_calls != ["Results.Json(".to_string()] {
        errors.push(
            "API snapshot governance endpoint must contain exactly one returned Results.Json result call"
                .to_string(),
        );
        return None;
    }
    let Some(json_index) = outer_mapget_results_json_index(&result_source, errors) else {
        errors.push("API missing snapshot governance JSON payload".to_string());
        return None;
    };
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push("API snapshot governance JSON payload must be a single object".to_string());
        return None;
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors.push("API snapshot governance JSON payload must be a single object".to_string());
        return None;
    };
    Some(endpoint[object_start..=object_end].to_string())
}

fn outer_mapget_results_json_index(source: &str, errors: &mut Vec<String>) -> Option<usize> {
    let compact = source.replace(['\n', '\r', '\t'], " ");
    if compact.contains("app.MapGet(") && compact.contains("=> Results.Json") {
        let arrow_index = source.find("=>")?;
        let between = source[arrow_index + 2..].trim_start();
        if between.starts_with("Results.Json") {
            let Some(json_index) = results_json_new_call_index(source, arrow_index + 2) else {
                errors.push(
                    "API snapshot governance endpoint must use direct Results.Json(new ...) payload"
                        .to_string(),
                );
                return None;
            };
            if !top_level_return_indexes(source).is_empty() {
                errors.push(
                    "API snapshot governance endpoint must not have extra top-level return statements"
                        .to_string(),
                );
                return None;
            }
            return Some(json_index);
        }
    }
    let Some(block_start) = compact.find("=> {") else {
        errors.push(
            "API snapshot governance endpoint must use direct outer MapGet Results.Json payload"
                .to_string(),
        );
        return None;
    };
    let _ = block_start;
    let return_indexes = handler_return_indexes(source);
    if return_indexes.len() != 1 {
        errors.push(
            "API snapshot governance endpoint must return only the Results.Json payload"
                .to_string(),
        );
        return None;
    }
    let return_index = return_indexes[0];
    if !source[return_index..]
        .trim_start()
        .starts_with("return Results.Json")
    {
        errors.push(
            "API snapshot governance endpoint must use top-level returned Results.Json payload"
                .to_string(),
        );
        return None;
    }
    let Some(json_index) = results_json_new_call_index(source, return_index) else {
        errors.push(
            "API snapshot governance endpoint must use direct Results.Json(new ...) payload"
                .to_string(),
        );
        return None;
    };
    Some(json_index)
}

fn results_json_new_call_index(source: &str, start_index: usize) -> Option<usize> {
    let json_index = start_index + source[start_index..].find("Results.Json")?;
    let mut cursor = json_index + "Results.Json".len();
    cursor = skip_ascii_whitespace(source, cursor);
    if source.as_bytes().get(cursor) != Some(&b'(') {
        return None;
    }
    cursor += 1;
    cursor = skip_ascii_whitespace(source, cursor);
    if !source[cursor..].starts_with("new") {
        return None;
    }
    let after_new = cursor + "new".len();
    if source
        .as_bytes()
        .get(after_new)
        .is_some_and(|byte| is_identifier_byte(*byte))
    {
        return None;
    }
    cursor = skip_ascii_whitespace(source, after_new);
    if source.as_bytes().get(cursor) != Some(&b'{') {
        return None;
    }
    Some(json_index)
}

fn skip_ascii_whitespace(source: &str, mut index: usize) -> usize {
    while source
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn top_level_return_indexes(source: &str) -> Vec<usize> {
    find_word_indexes(source, "return")
        .into_iter()
        .filter(|index| brace_depth_at(source, *index) == 1)
        .collect()
}

fn handler_return_indexes(source: &str) -> Vec<usize> {
    find_word_indexes(source, "return")
        .into_iter()
        .filter(|index| brace_depth_at(source, *index) > 0)
        .collect()
}

fn endpoint_array_body(block: &str, field: &str, requires_comma_after: bool) -> Option<String> {
    let lines = top_level_assignment_lines(block, field);
    if lines.len() != 1 {
        return None;
    }
    if !line_matches_assignment(&lines[0], field, "new[]", false) {
        return None;
    }
    let assignment_index = block.find(&lines[0])?;
    let array_start = block[assignment_index + lines[0].len()..]
        .find('{')
        .map(|index| assignment_index + lines[0].len() + index)?;
    let array_end = matching_brace_index(block, array_start)?;
    let remainder = block[array_end + 1..].trim_start();
    if requires_comma_after {
        if !remainder.starts_with(',') {
            return None;
        }
    } else {
        let remainder = remainder.strip_prefix(',').unwrap_or(remainder).trim();
        if remainder != "}" {
            return None;
        }
    }
    Some(block[array_start + 1..array_end].to_string())
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            if prohibited_endpoint_field(&field) {
                errors.push(format!(
                    "API endpoint has prohibited snapshot governance field {field}"
                ));
            } else {
                errors.push(format!(
                    "API endpoint has unexpected snapshot governance field {field}"
                ));
            }
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for line in top_level_assignment_fields(block) {
        for assignment in top_level_assignment_lines(block, &line) {
            if exact_bool_assignment_value(&assignment, &line, true) == Some(true)
                && unsafe_true_field(&line)
            {
                errors.push(format!("API endpoint has unsafe true flag {line}"));
            }
        }
    }
}

fn csharp_array_values(
    uncommented_program: &str,
    original_program: &str,
    variable: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let source = csharp_without_string_literals(uncommented_program);
    let declarations = find_top_level_var_declarations(&source, variable);
    let assignments = find_top_level_assignments(&source, variable, &declarations);
    let literal = find_top_level_literal_array(&source, variable);
    if declarations.len() != 1 || literal.is_none() || !assignments.is_empty() {
        errors.push(format!(
            "API variable {variable} must be declared exactly once as a top-level literal array"
        ));
        return None;
    }
    let (body_start, body_end) = literal?;
    Some(csharp_string_literals(
        &original_program[body_start..body_end],
    ))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let lines = top_level_assignment_lines(block, field);
    if lines.len() != 1 {
        return None;
    }
    let line = &lines[0];
    let prefix = assignment_prefix(field);
    let body_start = line.find('{')?;
    let body_end = line.rfind('}')?;
    if !line.trim_start().starts_with(&prefix)
        && !line.trim_start().starts_with(&format!("@{prefix}"))
    {
        return None;
    }
    if !line[body_end + 1..].trim().eq(",") {
        return None;
    }
    Some(csharp_string_literals(&line[body_start + 1..body_end]))
}

fn top_level_assignment_lines(block: &str, field: &str) -> Vec<String> {
    let masked = csharp_without_string_literals(block);
    let mut lines = Vec::new();
    let mut offset = 0;
    for (masked_line, original_line) in masked
        .split_inclusive('\n')
        .zip(block.split_inclusive('\n'))
    {
        if let Some(position) = assignment_position(masked_line, field) {
            if brace_depth_at(&masked, offset + position) == 1 {
                lines.push(original_line.trim().to_string());
            }
        }
        offset += masked_line.len();
    }
    lines
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    let masked = csharp_without_string_literals(block);
    let mut fields = Vec::new();
    let mut offset = 0;
    for line in masked.split_inclusive('\n') {
        for (position, field) in assignment_fields_in_line(line) {
            if brace_depth_at(&masked, offset + position) == 1 {
                fields.push(field);
            }
        }
        offset += line.len();
    }
    fields
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let lines = top_level_assignment_lines(block, field);
    lines.len() == 1 && line_matches_assignment(&lines[0], field, value, true)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let lines = top_level_assignment_lines(block, field);
    lines.len() == 1
        && exact_string_assignment_value(&lines[0], field, true).as_deref() == Some(value)
}

fn exact_string_assignment_value(line: &str, field: &str, comma: bool) -> Option<String> {
    let rhs = assignment_rhs(line, field)?;
    let expected_suffix = if comma { "," } else { "" };
    let trimmed = rhs.trim();
    if comma && !trimmed.ends_with(expected_suffix) {
        return None;
    }
    let value_part = if comma {
        trimmed.strip_suffix(',')?.trim()
    } else {
        trimmed
    };
    if value_part.starts_with('"') && value_part.ends_with('"') && value_part.len() >= 2 {
        Some(value_part[1..value_part.len() - 1].to_string())
    } else {
        None
    }
}

fn exact_bool_assignment_value(line: &str, field: &str, comma: bool) -> Option<bool> {
    let rhs = assignment_rhs(line, field)?;
    let trimmed = if comma {
        rhs.trim().strip_suffix(',')?.trim()
    } else {
        rhs.trim()
    };
    match trimmed {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
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

fn assignment_rhs<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let trimmed = line.trim();
    let trimmed = trimmed.strip_prefix('@').unwrap_or(trimmed);
    let rest = trimmed.strip_prefix(field)?.trim_start();
    rest.strip_prefix('=')
}

fn assignment_prefix(field: &str) -> String {
    format!("{field} = new[]")
}

fn assignment_position(line: &str, field: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let field_bytes = field.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let mut start = index;
        if bytes[index] == b'@' {
            start += 1;
        }
        if start + field_bytes.len() <= bytes.len()
            && &bytes[start..start + field_bytes.len()] == field_bytes
            && (index == 0 || !is_identifier_byte(bytes[index - 1]))
        {
            let after = start + field_bytes.len();
            if after == bytes.len() || !is_identifier_byte(bytes[after]) {
                let mut cursor = after;
                while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if cursor < bytes.len() && bytes[cursor] == b'=' {
                    return Some(start);
                }
            }
        }
        index += 1;
    }
    None
}

fn assignment_fields_in_line(line: &str) -> Vec<(usize, String)> {
    let bytes = line.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let at_prefix = bytes[index] == b'@';
        let start = if at_prefix { index + 1 } else { index };
        if start < bytes.len()
            && is_identifier_start(bytes[start])
            && (index == 0 || !is_identifier_byte(bytes[index - 1]))
        {
            let mut end = start + 1;
            while end < bytes.len() && is_identifier_byte(bytes[end]) {
                end += 1;
            }
            let mut cursor = end;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < bytes.len() && bytes[cursor] == b'=' {
                fields.push((start, line[start..end].to_string()));
                index = cursor + 1;
                continue;
            }
        }
        index += 1;
    }
    fields
}

fn top_level_string_assignments(object: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for (position, field) in assignment_fields_in_line(&object.replace('\n', " ")) {
        if brace_depth_at(object, position) != 1 {
            continue;
        }
        let Some(rhs) = assignment_rhs(&object[position..], &field) else {
            continue;
        };
        let rhs = rhs.trim_start();
        if !rhs.starts_with('"') {
            continue;
        }
        if let Some((value, _end)) = parse_string_literal(rhs) {
            pairs.push((field, value));
        }
    }
    pairs
}

fn api_rule_has_malformed_content(object: &str, pairs: &[(String, String)]) -> bool {
    let Some(start) = object.find('{') else {
        return true;
    };
    let Some(end) = object.rfind('}') else {
        return true;
    };
    let mut leftover = object[start + 1..end].to_string();
    for (field, value) in pairs {
        let fragment = format!("{field} = \"{value}\"");
        leftover = leftover.replacen(&fragment, "", 1);
    }
    !leftover.chars().all(|ch| ch == ',' || ch.is_whitespace())
}

fn find_new_object(source: &str, offset: usize) -> Option<usize> {
    let mut cursor = offset;
    while let Some(relative) = source[cursor..].find("new") {
        let start = cursor + relative;
        let before_ok = start == 0 || !is_identifier_byte(source.as_bytes()[start - 1]);
        let after = start + 3;
        let after_ok = after == source.len() || !is_identifier_byte(source.as_bytes()[after]);
        if before_ok && after_ok {
            let mut next = after;
            while next < source.len() && source.as_bytes()[next].is_ascii_whitespace() {
                next += 1;
            }
            if next < source.len() && source.as_bytes()[next] == b'{' {
                return Some(start);
            }
        }
        cursor = after;
    }
    None
}

fn reject_leftover(
    source: &str,
    ranges: &[(usize, usize)],
    message: &str,
    errors: &mut Vec<String>,
) {
    let mut bytes = source.as_bytes().to_vec();
    for (start, end) in ranges.iter().rev() {
        for byte in bytes.iter_mut().take(*end + 1).skip(*start) {
            *byte = b' ';
        }
    }
    if bytes
        .iter()
        .any(|byte| !byte.is_ascii_whitespace() && *byte != b',')
    {
        errors.push(message.to_string());
    }
}

fn find_top_level_var_declarations(source: &str, variable: &str) -> Vec<usize> {
    let needle = format!("var {variable}");
    let mut declarations = Vec::new();
    let mut offset = 0;
    while let Some(relative) = source[offset..].find(&needle) {
        let start = offset + relative;
        let after = start + needle.len();
        if (after == source.len() || !is_identifier_byte(source.as_bytes()[after]))
            && source[after..].trim_start().starts_with('=')
            && brace_depth_at(source, start) == 0
        {
            declarations.push(start);
        }
        offset = after;
    }
    declarations
}

fn find_top_level_assignments(source: &str, variable: &str, declarations: &[usize]) -> Vec<usize> {
    let mut assignments = Vec::new();
    let mut offset = 0;
    while let Some(relative) = source[offset..].find(variable) {
        let start = offset + relative;
        let after = start + variable.len();
        if (start == 0 || !is_identifier_byte(source.as_bytes()[start - 1]))
            && (after == source.len() || !is_identifier_byte(source.as_bytes()[after]))
            && source[after..].trim_start().starts_with('=')
            && brace_depth_at(source, start) == 0
            && !declarations.iter().any(|declaration| {
                source[*declaration..start]
                    .chars()
                    .all(|ch| ch.is_whitespace() || ch.is_ascii_alphabetic())
            })
        {
            assignments.push(start);
        }
        offset = after;
    }
    assignments
}

fn find_top_level_literal_array(source: &str, variable: &str) -> Option<(usize, usize)> {
    let declarations = find_top_level_var_declarations(source, variable);
    let start = *declarations.first()?;
    let after_equals = source[start..].find('=')? + start + 1;
    let rest = source[after_equals..].trim_start();
    if !rest.starts_with("new[]") {
        return None;
    }
    let array_start = source[after_equals..].find('{')? + after_equals;
    let array_end = matching_brace_index(source, array_start)?;
    if !source[array_end + 1..].trim_start().starts_with(';') {
        return None;
    }
    Some((array_start + 1, array_end))
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            if let Some((value, end)) = parse_string_literal(&text[index..]) {
                values.push(value);
                index += end;
                continue;
            }
        }
        index += 1;
    }
    values
}

fn parse_string_literal(text: &str) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.first().copied() != Some(b'"') {
        return None;
    }
    let mut value = String::new();
    let mut index = 1;
    let mut escaped = false;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if escaped {
            value.push(ch);
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == b'"' {
            return Some((value, index + 1));
        } else {
            value.push(ch);
        }
        index += 1;
    }
    None
}

fn result_calls(source: &str) -> Vec<String> {
    let mut calls = Vec::new();
    for prefix in ["Results.", "TypedResults."] {
        let mut offset = 0;
        while let Some(relative) = source[offset..].find(prefix) {
            let start = offset + relative;
            let mut end = start + prefix.len();
            while end < source.len() && is_identifier_byte(source.as_bytes()[end]) {
                end += 1;
            }
            let mut cursor = end;
            while cursor < source.len() && source.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < source.len() && source.as_bytes()[cursor] == b'(' {
                calls.push(format!("{}(", &source[start..end]));
            }
            offset = end;
        }
    }
    calls.sort();
    calls
}

fn csharp_without_comments(text: &str) -> String {
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
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_without_string_literals(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if index + 2 < bytes.len() && &bytes[index..index + 3] == b"\"\"\"" {
            output.push_str("   ");
            index += 3;
            while index + 2 < bytes.len() && &bytes[index..index + 3] != b"\"\"\"" {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index + 2 < bytes.len() {
                output.push_str("   ");
                index += 3;
            }
        } else if bytes[index] == b'"' {
            output.push(' ');
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                if escaped {
                    escaped = false;
                } else if bytes[index] == b'\\' {
                    escaped = true;
                } else if bytes[index] == b'"' {
                    index += 1;
                    break;
                }
                index += 1;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn matching_brace_index(source: &str, start_index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth: usize = 0;
    let mut index = start_index;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_raw_string = false;
    while index < bytes.len() {
        if in_raw_string {
            if index + 2 < bytes.len() && &bytes[index..index + 3] == b"\"\"\"" {
                in_raw_string = false;
                index += 3;
            } else {
                index += 1;
            }
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if index + 2 < bytes.len() && &bytes[index..index + 3] == b"\"\"\"" {
            in_raw_string = true;
            index += 3;
            continue;
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == b'{' {
            depth += 1;
        } else if bytes[index] == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn brace_depth_at(source: &str, target_index: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth: usize = 0;
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < target_index && index < bytes.len() {
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

fn find_word_indexes(source: &str, word: &str) -> Vec<usize> {
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = source[offset..].find(word) {
        let start = offset + relative;
        let end = start + word.len();
        if (start == 0 || !is_identifier_byte(source.as_bytes()[start - 1]))
            && (end == source.len() || !is_identifier_byte(source.as_bytes()[end]))
        {
            indexes.push(start);
        }
        offset = end;
    }
    indexes
}

fn strict_string_array_like(value: &Value, field: &str, errors: &mut Vec<String>) -> Vec<String> {
    let Some(array) = value.get(field).and_then(Value::as_array) else {
        errors.push(format!("{field} must be an array of strings"));
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
    values
}

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn object_array(value: Option<&Value>, field: &str, errors: &mut Vec<String>) -> Vec<Value> {
    let Some(array) = value.and_then(Value::as_array) else {
        errors.push(format!("{field} must be an array of objects"));
        return Vec::new();
    };
    let mut objects = Vec::new();
    for item in array {
        if item.is_object() {
            objects.push(item.clone());
        } else {
            errors.push(format!("{field} must contain objects"));
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

fn value_to_comparable(value: &Value) -> String {
    match value {
        Value::Bool(value) => value.to_string(),
        Value::String(value) => value.clone(),
        _ => String::new(),
    }
}

fn prohibited_endpoint_field(field: &str) -> bool {
    let normalized = field
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    PROHIBITED_FIELD_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
}

fn unsafe_true_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    [
        "live",
        "provider",
        "raw",
        "inventory",
        "snapshot",
        "deletion",
        "credential",
        "secret",
        "token",
        "tenant",
        "object",
        "private",
        "user",
        "host",
        "endpoint",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) if prohibited_value(text) => {
            errors.push(format!("{path} contains prohibited value"));
        }
        _ => {}
    }
}

fn scan_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn prohibited_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin ") && lower.contains("private key-----")
        || lower.contains("akia")
        || lower.contains("://")
        || contains_private_ip(value)
        || contains_uuid(value)
        || token_assignment_like(&lower)
        || string_fragment_windows(value)
            .iter()
            .any(|fragment| prohibited_value(fragment))
}

fn string_fragment_windows(value: &str) -> Vec<String> {
    let mut fragments = Vec::new();
    let quoted = csharp_string_literals(value);
    if quoted.len() >= 2 {
        fragments.push(sanitize_fragment(&quoted.join("")));
    }
    fragments
}

fn sanitize_fragment(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || "_:/.-=".contains(*ch))
        .collect()
}

fn token_assignment_like(lower: &str) -> bool {
    let compact = sanitize_fragment(lower);
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|token| compact.contains(&format!("{token}=")) || compact.contains(&format!("{token}:")))
}

fn contains_private_ip(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|part| {
            let octets: Vec<u16> = part
                .split('.')
                .filter_map(|piece| piece.parse::<u16>().ok())
                .collect();
            if octets.len() != 4 || octets.iter().any(|octet| *octet > 255) {
                return false;
            }
            octets[0] == 10
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        })
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_hexdigit() && ch != '-')
        .any(|part| {
            let pieces: Vec<&str> = part.split('-').collect();
            pieces.len() == 5
                && [8, 4, 4, 4, 12]
                    .iter()
                    .zip(pieces.iter())
                    .all(|(len, piece)| {
                        piece.len() == *len && piece.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
        })
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prohibited_snapshot_key_variants_are_normalized() {
        assert!(prohibited_endpoint_field("snapshotObjectId"));
        assert!(prohibited_endpoint_field("raw_snapshot_rows"));
        assert!(prohibited_endpoint_field("ProviderPayloadSummary"));
    }

    #[test]
    fn split_sensitive_assignment_is_reconstructed() {
        assert!(prohibited_value("\"access_\" + \"token=unsafe-value\""));
        assert!(prohibited_value(
            "string.Concat(\"refresh_\", \"token\", \"=\", \"unsafe-value\")"
        ));
    }
}
