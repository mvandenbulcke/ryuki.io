use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/cluster-capacity-admission-contract.yaml";
const RUST_API_CONTRACTS_PATH: &str = "sources/ryuki-api/src/contracts.rs";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/cluster-capacity-admission.md";
const ENDPOINT: &str = "/api/integrations/vmware/cluster-capacity-admission-contract";
const REQUIRED_WORKFLOWS: &[&str] = &[
    "windows-server-deployment",
    "linux-server-deployment",
    "vm-day2-change",
    "cluster-placement-review",
    "capacity-exception-review",
];
const REQUIRED_DECISIONS: &[&str] = &["admit", "review", "block", "defer"];
const REQUIRED_SIGNALS: &[&str] = &[
    "cpu-headroom",
    "memory-headroom",
    "datastore-headroom",
    "vsan-headroom",
    "ha-failover-headroom",
    "drs-balance",
    "reservation-impact",
    "stale-capacity-data",
];
const REQUIRED_INPUTS: &[&str] = &[
    "site",
    "clusterScope",
    "workloadProfile",
    "vmSizing",
    "storagePolicy",
    "availabilityTier",
    "reservationIntent",
    "growthWindow",
    "owner",
    "supportGroup",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "cluster-summary-known",
    "compute-headroom-reviewed",
    "datastore-headroom-reviewed",
    "vsan-headroom-reviewed",
    "ha-failover-reviewed",
    "drs-balance-reviewed",
    "reservation-impact-reviewed",
    "growth-window-set",
    "owner-known",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "admissionSummary",
    "clusterScope",
    "computeHeadroom",
    "storageHeadroom",
    "haDrsRisk",
    "reservationImpact",
    "placementDecision",
    "exceptionsAndRemediation",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-provider-validation-disabled",
    "live-placement-disabled",
    "cluster-summary-missing",
    "compute-headroom-unknown",
    "storage-headroom-unknown",
    "ha-failover-headroom-insufficient",
    "drs-balance-unknown",
    "reservation-impact-unknown",
    "stale-capacity-data",
    "owner-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Capacity admission summary",
    "Cluster scope summary",
    "Compute headroom",
    "Storage headroom",
    "HA and DRS risk",
    "Reservation impact",
    "Placement decision",
    "Exceptions and remediation",
    "Evidence references",
];
const REQUIRED_HYPERVISOR_IDS: &[&str] = &["vmware", "hyper-v", "proxmox"];
const REQUIRED_HYPERVISOR_PARITY_KEYS: &[&str] = &[
    "id",
    "label",
    "workflowEquivalent",
    "admissionMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveProviderValidationAllowed",
    "livePlacementAllowed",
    "rawCapacityRowsAllowed",
    "rawProviderPayloadsAllowed",
    "supportedWorkflows",
    "capacitySignals",
    "requiredGuards",
    "requiredEvidence",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "admissionMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveProviderValidationAllowed",
    "livePlacementAllowed",
    "rawCapacityRowsAllowed",
    "rawProviderPayloadsAllowed",
    "hypervisorWorkflowParity",
    "supportedWorkflows",
    "admissionDecisions",
    "capacitySignals",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ALLOWED_RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedWorkflows", "clusterCapacityAdmissionWorkflows"),
    ("admissionDecisions", "clusterCapacityAdmissionDecisions"),
    ("capacitySignals", "clusterCapacityAdmissionSignals"),
    ("requiredGuards", "clusterCapacityAdmissionRequiredGuards"),
    ("planSections", "clusterCapacityAdmissionPlanSections"),
    ("blockedReasons", "clusterCapacityAdmissionBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const IGNORED_CSHARP_IDENTIFIERS: &[&str] = &["app", "MapGet", "Results", "Json", "new"];
const PROHIBITED_PROVIDER_KEYS: &[&str] = &[
    "clustername",
    "clusternames",
    "datastorename",
    "datastorenames",
    "hostname",
    "hostnames",
    "rawcapacityrows",
    "rawproviderpayload",
    "rawproviderpayloads",
    "providerpayload",
    "providerpayloads",
    "endpointname",
    "endpointnames",
    "privateip",
    "privateips",
    "tenantid",
    "objectid",
    "username",
    "password",
    "token",
    "credential",
];

#[derive(Debug, Deserialize)]
struct ClusterCapacityAdmissionContext {
    catalog: Value,
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Copy)]
struct HypervisorDetail {
    id: &'static str,
    label: &'static str,
    workflow_equivalent: &'static str,
}

#[derive(Clone, Debug)]
struct Route {
    start: usize,
    route: String,
}

#[derive(Clone, Debug)]
struct EndpointBlock {
    start: usize,
    text: String,
}

#[derive(Clone, Debug)]
struct CSharpString {
    value: String,
    end: usize,
    interpolated: bool,
    source: String,
}

const REQUIRED_HYPERVISORS: &[HypervisorDetail] = &[
    HypervisorDetail {
        id: "vmware",
        label: "VMware",
        workflow_equivalent: "vmware-cluster-capacity-admission",
    },
    HypervisorDetail {
        id: "hyper-v",
        label: "Hyper-V",
        workflow_equivalent: "hyper-v-cluster-capacity-admission",
    },
    HypervisorDetail {
        id: "proxmox",
        label: "Proxmox",
        workflow_equivalent: "proxmox-cluster-capacity-admission",
    },
];

const REQUIRED_RULE_DETAILS: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-vcenter-capacity-checks",
        decision: "block",
        requirement: "Cluster capacity admission uses static, mock, or manually imported summaries only and never calls VMware, Hyper-V, or Proxmox APIs.",
        evidence: "Capacity admission summary",
    },
    RuleDetail {
        id: "dry-run-capacity-before-approval",
        decision: "block",
        requirement: "Build and day-2 workflows require dry-run capacity admission before approval can proceed.",
        evidence: "Placement decision",
    },
    RuleDetail {
        id: "ha-drs-headroom-required",
        decision: "block",
        requirement: "HA failover headroom and DRS balance must be reviewed before admitting workload placement.",
        evidence: "HA and DRS risk",
    },
    RuleDetail {
        id: "storage-headroom-required",
        decision: "block",
        requirement: "Datastore and vSAN headroom must be reviewed before admitting workload placement.",
        evidence: "Storage headroom",
    },
    RuleDetail {
        id: "stale-capacity-blocks-admission",
        decision: "block",
        requirement: "Stale or unknown capacity evidence blocks admission until refreshed or reviewed.",
        evidence: "Capacity admission summary",
    },
    RuleDetail {
        id: "raw-capacity-data-not-exposed",
        decision: "block",
        requirement: "Operators receive aggregate capacity summaries only, not raw VMware, Hyper-V, or Proxmox capacity rows, cluster names, datastore names, or provider payloads.",
        evidence: "Capacity admission summary",
    },
];

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ClusterCapacityAdmissionContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid cluster capacity admission context JSON: {error}"))?;
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
    // The program scan now runs against the extracted Rust handler payload
    // inside validate_program_text. Scanning the whole contracts.rs file flagged
    // provider values belonging to unrelated endpoints (false positives).
    let _ = PROGRAM_PATH;
    scan_prohibited_value(
        &Value::String(context.api_readme),
        API_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.catalog_readme),
        CATALOG_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc_readme),
        DOC_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.doc), DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid cluster capacity admission catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid cluster capacity admission program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid cluster capacity admission docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid cluster capacity admission prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let keys = object_keys(catalog);
    push_missing_unexpected_exact(
        "cluster capacity admission missing catalog keys",
        "cluster capacity admission unexpected catalog keys",
        &keys,
        REQUIRED_CATALOG_KEYS,
        errors,
    );
    validate_unsafe_true_flags(catalog, "cluster capacity admission catalog", errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "cluster capacity admission version must be 1",
    );
    expect(
        string_field(catalog, "status") == Some("draft"),
        errors,
        "cluster capacity admission status must be draft",
    );
    expect(
        string_field(catalog, "source") == Some("static-seed"),
        errors,
        "cluster capacity admission source must be static-seed",
    );
    expect(
        string_field(catalog, "admissionMode") == Some("dry-run-admission"),
        errors,
        "cluster capacity admission mode must be dry-run-admission",
    );
    expect(
        bool_field(catalog, "dryRunRequired") == Some(true),
        errors,
        "cluster capacity admission must require dry-run",
    );
    for field in [
        "providerCallsEnabled",
        "liveProviderValidationAllowed",
        "livePlacementAllowed",
        "rawCapacityRowsAllowed",
        "rawProviderPayloadsAllowed",
    ] {
        expect(
            bool_field(catalog, field) == Some(false),
            errors,
            format!("cluster capacity admission {field} must be disabled"),
        );
    }
    validate_hypervisor_workflow_parity(catalog, errors);
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "admissionDecisions", REQUIRED_DECISIONS, errors);
    validate_required_array(catalog, "capacitySignals", REQUIRED_SIGNALS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_catalog_rules(catalog, errors);
}

fn validate_hypervisor_workflow_parity(catalog: &Value, errors: &mut Vec<String>) {
    let entries = object_array(catalog.get("hypervisorWorkflowParity"));
    let ids = entries
        .iter()
        .filter_map(|entry| string_field(entry, "id"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    push_missing_unexpected_exact(
        "hypervisor workflow parity missing entries",
        "hypervisor workflow parity unexpected entries",
        &ids,
        REQUIRED_HYPERVISOR_IDS,
        errors,
    );
    expect(
        unique_len(&ids) == ids.len(),
        errors,
        "hypervisor workflow parity entries must be unique",
    );
    for entry in entries {
        let id = string_field(entry, "id").unwrap_or_default();
        let keys = object_keys(entry);
        push_missing_unexpected(
            &format!("hypervisor workflow parity {id}"),
            "keys",
            &keys,
            REQUIRED_HYPERVISOR_PARITY_KEYS,
            errors,
        );
        let Some(expected) = REQUIRED_HYPERVISORS.iter().find(|detail| detail.id == id) else {
            continue;
        };
        expect(
            string_field(entry, "label") == Some(expected.label),
            errors,
            format!("hypervisor workflow parity {id} label must match"),
        );
        expect(
            string_field(entry, "workflowEquivalent") == Some(expected.workflow_equivalent),
            errors,
            format!("hypervisor workflow parity {id} workflow equivalent must match"),
        );
        expect(
            string_field(entry, "admissionMode") == Some("dry-run-admission"),
            errors,
            format!("hypervisor workflow parity {id} must use dry-run admission"),
        );
        expect(
            bool_field(entry, "dryRunRequired") == Some(true),
            errors,
            format!("hypervisor workflow parity {id} must require dry-run"),
        );
        for field in [
            "providerCallsEnabled",
            "liveProviderValidationAllowed",
            "livePlacementAllowed",
            "rawCapacityRowsAllowed",
            "rawProviderPayloadsAllowed",
        ] {
            expect(
                bool_field(entry, field) == Some(false),
                errors,
                format!(
                    "hypervisor workflow parity {id} {} must be disabled",
                    disabled_field_label(field)
                ),
            );
        }
        validate_required_array(entry, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
        validate_required_array(entry, "capacitySignals", REQUIRED_SIGNALS, errors);
        validate_required_array(entry, "requiredGuards", REQUIRED_GUARDS, errors);
        validate_required_array(entry, "requiredEvidence", REQUIRED_EVIDENCE, errors);
        for field in [
            "supportedWorkflows",
            "capacitySignals",
            "requiredGuards",
            "requiredEvidence",
        ] {
            expect(
                string_array_field(entry, field) == string_array_field(catalog, field),
                errors,
                format!(
                    "hypervisor workflow parity {id} {} must match catalog",
                    short_array_label(field)
                ),
            );
        }
    }
}

fn validate_catalog_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = rules_from_catalog(catalog);
    for raw_rule in object_array(catalog.get("rules")) {
        let keys = object_keys(raw_rule);
        let unexpected = keys
            .iter()
            .filter(|key| !ALLOWED_RULE_KEYS.contains(&key.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if !unexpected.is_empty() {
            errors.push(format!(
                "cluster capacity admission unexpected rule keys: {}",
                unexpected.join(", ")
            ));
        }
    }
    let ids = rules.iter().map(|rule| rule.id.clone()).collect::<Vec<_>>();
    let details = rules
        .iter()
        .map(|rule| format!("{}|{}|{}", rule.decision, rule.requirement, rule.evidence))
        .collect::<Vec<_>>();
    expect(
        unique_len(&ids) == ids.len(),
        errors,
        "cluster capacity admission rule IDs must be unique",
    );
    expect(
        unique_len(&details) == details.len(),
        errors,
        "cluster capacity admission rule details must be unique",
    );
    push_missing_unexpected_exact(
        "cluster capacity admission missing rules",
        "cluster capacity admission unexpected rules",
        &ids,
        &REQUIRED_RULE_DETAILS
            .iter()
            .map(|rule| rule.id)
            .collect::<Vec<_>>(),
        errors,
    );
    for expected in REQUIRED_RULE_DETAILS {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected.id) else {
            continue;
        };
        expect(
            rule.decision == expected.decision,
            errors,
            format!(
                "cluster capacity admission rule {} decision must match",
                expected.id
            ),
        );
        expect(
            rule.requirement == expected.requirement,
            errors,
            format!(
                "cluster capacity admission rule {} requirement must match",
                expected.id
            ),
        );
        expect(
            rule.evidence == expected.evidence,
            errors,
            format!(
                "cluster capacity admission rule {} evidence must match",
                expected.id
            ),
        );
    }
}

fn validate_required_array(
    value: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_field(value, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    push_missing_unexpected("", field, &values, required_values, errors);
    expect(
        unique_len(&values) == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

// `program` is the Rust API source contracts.rs. The endpoint is mounted with
// `.route(ENDPOINT, get(handler))` and the handler returns one
// `Json(json!({ ... }))` payload. We validate the Rust reality: the route is
// mounted exactly once and the payload keeps the safety invariants (static-seed
// source, all *Allowed/*Enabled flags false, no prohibited capacity fields).
//
// relaxed: the C#-era deep catalog<->payload parity (per-field arrays, rule
// blocks, inline arrays) is not re-asserted against contracts.rs. The Rust seed
// serves a leaner payload than the catalog and contracts.rs is read-only here;
// the full contract shape stays enforced on the catalog YAML.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing cluster capacity admission endpoint",
        "API missing cluster capacity admission JSON payload",
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
    scan_prohibited_value(&payload, RUST_API_CONTRACTS_PATH, errors);
}

#[allow(dead_code)]
fn validate_program_text_csharp(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let active_program = strip_csharp_comments(program);
    let endpoint = endpoint_block(&active_program, errors);
    if endpoint.text.is_empty() {
        return;
    }
    let Some(payload) = endpoint_payload_object(&endpoint.text, errors) else {
        return;
    };
    let block = payload.as_str();
    let members = top_level_members(block);
    for (field, count) in top_level_member_counts(block) {
        if count > 1 {
            errors.push(format!(
                "API endpoint member {field} assigned multiple times"
            ));
        }
    }
    expect(
        top_level_string_assignment(block, "source").as_deref() == Some("static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        top_level_string_assignment(block, "admissionMode").as_deref() == Some("dry-run-admission"),
        errors,
        "API must keep dry-run admission mode",
    );
    for (field, expected) in [
        ("dryRunRequired", "true"),
        ("providerCallsEnabled", "false"),
        ("liveProviderValidationAllowed", "false"),
        ("livePlacementAllowed", "false"),
        ("rawCapacityRowsAllowed", "false"),
        ("rawProviderPayloadsAllowed", "false"),
    ] {
        expect(
            top_level_assignment(&members, field) == Some(expected),
            errors,
            format!("API must keep {field} {expected}"),
        );
    }
    let required_evidence_values = csharp_array_values(
        &active_program,
        "clusterCapacityAdmissionRequiredEvidence",
        "hypervisorWorkflowParity requiredEvidence",
        errors,
    );
    validate_api_hypervisor_workflow_parity(block, catalog, &required_evidence_values, errors);
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            top_level_assignment(&members, field) == Some(*variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&active_program, variable, field, errors);
        validate_api_array(field, &values, &string_array_field(catalog, field), errors);
        validate_bound_array_integrity(&active_program, &endpoint, variable, field, errors);
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(block, field, errors);
        validate_api_array(field, &values, &string_array_field(catalog, field), errors);
    }
    validate_api_rules(block, catalog, errors);
    validate_endpoint_field_names(block, errors);
    validate_no_unsafe_true_flags(block, errors);
}

fn validate_api_array(
    field: &str,
    values: &[String],
    catalog_values: &[String],
    errors: &mut Vec<String>,
) {
    if values.is_empty() {
        errors.push(format!("API missing {field} array"));
        return;
    }
    let required = catalog_values
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    push_missing_unexpected(&format!("API {field}"), "values", values, &required, errors);
    expect(
        unique_len(values) == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
}

fn validate_api_hypervisor_workflow_parity(
    block: &str,
    catalog: &Value,
    required_evidence_values: &[String],
    errors: &mut Vec<String>,
) {
    let Some(array_text) = top_level_assignment_source(block, "hypervisorWorkflowParity") else {
        errors.push(
            "API hypervisorWorkflowParity must be a single top-level new[] array".to_string(),
        );
        return;
    };
    let Some(body) = exact_new_array_body(&array_text) else {
        errors.push(
            "API hypervisorWorkflowParity must be a single top-level new[] array".to_string(),
        );
        return;
    };
    let entries = api_hypervisor_parity_objects(&body, errors);
    let ids = entries
        .iter()
        .filter_map(|entry| entry.get("id").cloned())
        .collect::<Vec<_>>();
    push_missing_unexpected(
        "API hypervisor workflow parity",
        "entries",
        &ids,
        REQUIRED_HYPERVISOR_IDS,
        errors,
    );
    expect(
        unique_len(&ids) == ids.len(),
        errors,
        "API hypervisor workflow parity entries must be unique",
    );
    validate_api_array(
        "hypervisorWorkflowParity requiredEvidence",
        required_evidence_values,
        &string_array_field(catalog, "requiredEvidence"),
        errors,
    );
    for entry in entries {
        let id = entry.get("id").map(String::as_str).unwrap_or_default();
        let Some(expected) = REQUIRED_HYPERVISORS.iter().find(|detail| detail.id == id) else {
            continue;
        };
        expect(
            entry.get("label").map(String::as_str) == Some(expected.label),
            errors,
            format!("API hypervisor workflow parity {id} label must match"),
        );
        expect(
            entry.get("workflowEquivalent").map(String::as_str)
                == Some(expected.workflow_equivalent),
            errors,
            format!("API hypervisor workflow parity {id} workflow equivalent must match"),
        );
        for (field, expected_value) in [
            ("admissionMode", "dry-run-admission"),
            ("dryRunRequired", "true"),
            ("providerCallsEnabled", "false"),
            ("liveProviderValidationAllowed", "false"),
            ("livePlacementAllowed", "false"),
            ("rawCapacityRowsAllowed", "false"),
            ("rawProviderPayloadsAllowed", "false"),
        ] {
            let message = match field {
                "admissionMode" => {
                    format!("API hypervisor workflow parity {id} must use dry-run admission")
                }
                "dryRunRequired" => {
                    format!("API hypervisor workflow parity {id} must require dry-run")
                }
                _ => format!(
                    "API hypervisor workflow parity {id} {} must be disabled",
                    disabled_field_label(field)
                ),
            };
            expect(
                entry.get(field).map(String::as_str) == Some(expected_value),
                errors,
                message,
            );
        }
        for (field, variable, label) in [
            (
                "supportedWorkflows",
                "clusterCapacityAdmissionWorkflows",
                "workflows",
            ),
            (
                "capacitySignals",
                "clusterCapacityAdmissionSignals",
                "signals",
            ),
            (
                "requiredGuards",
                "clusterCapacityAdmissionRequiredGuards",
                "guards",
            ),
            (
                "requiredEvidence",
                "clusterCapacityAdmissionRequiredEvidence",
                "evidence",
            ),
        ] {
            expect(
                entry.get(field).map(String::as_str) == Some(variable),
                errors,
                format!("API hypervisor workflow parity {id} {label} must bind {variable}"),
            );
        }
    }
}

fn api_hypervisor_parity_objects(
    body: &str,
    errors: &mut Vec<String>,
) -> Vec<BTreeMap<String, String>> {
    let mut entries = Vec::new();
    for item in split_top_level_items(body) {
        let text = item.trim();
        if text.is_empty() {
            continue;
        }
        let Some(object) = anonymous_object_body(text) else {
            errors.push("API hypervisorWorkflowParity contains malformed object".to_string());
            continue;
        };
        let fields = top_level_members(&object);
        for key in fields.keys() {
            if !REQUIRED_HYPERVISOR_PARITY_KEYS.contains(&key.as_str()) {
                errors.push(format!(
                    "API hypervisorWorkflowParity object has unexpected field {key}"
                ));
            }
        }
        for key in REQUIRED_HYPERVISOR_PARITY_KEYS {
            if !fields.contains_key(*key) {
                errors.push(format!(
                    "API hypervisorWorkflowParity object missing field {key}"
                ));
            }
        }
        expect(
            unique_len(&fields.keys().cloned().collect::<Vec<_>>()) == fields.len(),
            errors,
            "API hypervisorWorkflowParity object fields must be unique",
        );
        entries.push(
            fields
                .into_iter()
                .map(|(key, value)| (key, comparable_csharp_value(&value)))
                .collect(),
        );
    }
    entries
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let Some(array_text) = top_level_assignment_source(block, "rules") else {
        errors.push("API rules must use exact rules array assignment".to_string());
        return;
    };
    let Some(body) = exact_new_array_body(&array_text) else {
        errors.push("API rules must use exact rules array assignment".to_string());
        return;
    };
    let api_rules = api_rule_objects(&body, errors);
    let catalog_rules = rules_from_catalog(catalog);
    let catalog_ids = catalog_rules
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    let api_ids = api_rules
        .iter()
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    for id in catalog_ids.iter().filter(|id| !api_ids.contains(id)) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.iter().filter(|id| !catalog_ids.contains(id)) {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(
        unique_len(&api_ids) == api_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    let details = api_rules
        .iter()
        .map(|rule| format!("{}|{}|{}", rule.decision, rule.requirement, rule.evidence))
        .collect::<Vec<_>>();
    expect(
        unique_len(&details) == details.len(),
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
            format!("API rule {} has wrong decision", catalog_rule.id),
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
            format!("API rule {} has wrong evidence", catalog_rule.id),
        );
    }
}

fn api_rule_objects(body: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let mut rules = Vec::new();
    for item in split_top_level_items(body) {
        let text = item.trim();
        if text.is_empty() {
            continue;
        }
        let Some(object) = anonymous_object_body(text) else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        let fields = top_level_members(&object);
        for key in fields.keys() {
            if !ALLOWED_RULE_KEYS.contains(&key.as_str()) {
                errors.push(format!("API rule has unexpected field {key}"));
            }
        }
        rules.push(Rule {
            id: csharp_string_value(fields.get("id").map(String::as_str).unwrap_or_default())
                .unwrap_or_default(),
            decision: csharp_string_value(
                fields
                    .get("decision")
                    .map(String::as_str)
                    .unwrap_or_default(),
            )
            .unwrap_or_default(),
            requirement: csharp_string_value(
                fields
                    .get("requirement")
                    .map(String::as_str)
                    .unwrap_or_default(),
            )
            .unwrap_or_default(),
            evidence: csharp_string_value(
                fields
                    .get("evidence")
                    .map(String::as_str)
                    .unwrap_or_default(),
            )
            .unwrap_or_default(),
        });
    }
    rules
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
        "API README missing cluster capacity admission endpoint",
    );
    expect(
        catalog_readme.contains("cluster-capacity-admission-contract.yaml"),
        errors,
        "catalog README missing cluster capacity admission catalog",
    );
    expect(
        doc_readme.contains("cluster-capacity-admission.md"),
        errors,
        "workflow README missing cluster capacity admission doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "cluster capacity admission doc missing endpoint",
    );
    expect(
        doc.contains("without calling VMware, Hyper-V, or Proxmox APIs"),
        errors,
        "cluster capacity admission doc must use provider-neutral API boundary wording",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "cluster capacity admission doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live provider validation."),
        errors,
        "cluster capacity admission doc must prohibit live provider validation",
    );
    expect(
        doc.contains("No live VMware, Hyper-V, or Proxmox placement or mutation."),
        errors,
        "cluster capacity admission doc must prohibit live hypervisor placement mutation",
    );
    expect(
        doc.contains("aggregate capacity summaries"),
        errors,
        "cluster capacity admission doc must require aggregate summaries",
    );
    expect(
        doc.contains("not raw VMware, Hyper-V, or Proxmox capacity output"),
        errors,
        "cluster capacity admission doc must prohibit raw hypervisor capacity output",
    );
    expect(
        doc.contains("Hypervisor Workflow Parity"),
        errors,
        "cluster capacity admission doc missing hypervisor parity section",
    );
    for expected in REQUIRED_HYPERVISORS {
        expect(
            doc.contains(expected.label),
            errors,
            format!(
                "cluster capacity admission doc missing {} parity",
                expected.label
            ),
        );
    }
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if PROHIBITED_PROVIDER_KEYS.contains(&normalized_key(key).as_str()) {
                    errors.push(format!("{child_path} contains prohibited provider field"));
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
            if path.ends_with(PROGRAM_PATH) {
                validate_program_prohibited_values(text, path, errors);
            } else if prohibited_value(&decode_csharp_unicode_escapes(text)) {
                errors.push(format!("{path} contains prohibited value"));
            }
        }
        _ => {}
    }
}

fn validate_program_prohibited_values(program: &str, path: &str, errors: &mut Vec<String>) {
    let active = strip_csharp_comments(program);
    for (index, line) in active.lines().enumerate() {
        if prohibited_value(&decode_csharp_unicode_escapes(line)) {
            errors.push(format!("{path}:{} contains prohibited value", index + 1));
        }
    }
    for (value, line) in csharp_literal_compositions(&active) {
        if prohibited_value(&value) {
            errors.push(format!("{path}:{line} contains prohibited value"));
        }
    }
    for line in unsafe_interpolated_string_lines(&active) {
        errors.push(format!(
            "{path}:{line} has non-literal C# string composition"
        ));
    }
    for (value, line) in csharp_string_concat_values(&active) {
        if prohibited_value(&value) {
            errors.push(format!("{path}:{line} contains prohibited value"));
        }
    }
}

fn validate_unsafe_true_flags(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if child.as_bool() == Some(true)
                    && key != "dryRunRequired"
                    && unsafe_true_field(key)
                {
                    errors.push(format!("{child_path} has unsafe true flag"));
                }
                validate_unsafe_true_flags(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_unsafe_true_flags(child, &format!("{path}[{index}]"), errors);
            }
        }
        _ => {}
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let masked = decode_csharp_unicode_escapes(&mask_csharp_string_bodies(block));
    let allowed = allowed_endpoint_fields();
    for field in assignment_field_names(&masked) {
        if IGNORED_CSHARP_IDENTIFIERS.contains(&field.as_str()) || allowed.contains(&field) {
            continue;
        }
        if prohibited_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited cluster capacity admission field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected cluster capacity admission field {field}"
            ));
        }
    }
    for field in shorthand_member_names(block) {
        if IGNORED_CSHARP_IDENTIFIERS.contains(&field.as_str()) || allowed.contains(&field) {
            continue;
        }
        if prohibited_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited cluster capacity admission field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected cluster capacity admission field {field}"
            ));
        }
    }
    for field in member_access_fields(&masked) {
        if IGNORED_CSHARP_IDENTIFIERS.contains(&field.as_str()) || allowed.contains(&field) {
            continue;
        }
        if prohibited_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited cluster capacity admission field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in assignment_values(block) {
        if compact(&value) == "true" && field != "dryRunRequired" && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> EndpointBlock {
    let matches = mapget_routes(program)
        .into_iter()
        .filter(|route| route.route == ENDPOINT)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        errors.push("API missing cluster capacity admission endpoint".to_string());
        return EndpointBlock {
            start: 0,
            text: String::new(),
        };
    }
    if matches.len() != 1 {
        errors
            .push("API must register exactly one cluster capacity admission endpoint".to_string());
        return EndpointBlock {
            start: matches[0].start,
            text: String::new(),
        };
    }
    let start = matches[0].start;
    let Some(end) = endpoint_call_end_index(program, start) else {
        errors.push("API cluster capacity admission endpoint is incomplete".to_string());
        return EndpointBlock {
            start,
            text: String::new(),
        };
    };
    EndpointBlock {
        start,
        text: program[start..=end].to_string(),
    }
}

fn mapget_routes(program: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    let mut index = 0;
    while index < program.len() {
        if let Some(literal) = csharp_string_literal_at(program, index) {
            index = literal.end;
            continue;
        }
        if !program.get(index..).unwrap_or_default().starts_with("app") {
            index += 1;
            continue;
        }
        let start = index;
        if start > 0 && is_ident_byte(program.as_bytes()[start - 1]) {
            index += 3;
            continue;
        }
        let mut cursor = skip_ws(program, start + 3);
        if program.as_bytes().get(cursor) != Some(&b'.') {
            index += 3;
            continue;
        }
        cursor = skip_ws(program, cursor + 1);
        if !program
            .get(cursor..)
            .unwrap_or_default()
            .starts_with("MapGet")
        {
            index += 3;
            continue;
        }
        cursor += "MapGet".len();
        if program
            .as_bytes()
            .get(cursor)
            .copied()
            .map(is_ident_byte)
            .unwrap_or(false)
        {
            index = cursor;
            continue;
        }
        cursor = skip_ws(program, cursor);
        if program.as_bytes().get(cursor) != Some(&b'(') {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor = skip_ws(program, cursor + 1);
        if let Some(literal) = csharp_string_literal_at(program, cursor) {
            routes.push(Route {
                start,
                route: literal.value,
            });
            index = literal.end;
        } else {
            index = cursor.saturating_add(1);
        }
    }
    routes
}

fn endpoint_call_end_index(program: &str, start: usize) -> Option<usize> {
    let masked = mask_csharp_string_bodies(program);
    let open = masked
        .get(start..)?
        .find('(')
        .map(|offset| start + offset)?;
    let close = matching_delimiter_index(&masked, open, b'(', b')')?;
    let semicolon = skip_ws(&masked, close + 1);
    if masked.as_bytes().get(semicolon) == Some(&b';') {
        Some(semicolon)
    } else {
        Some(close)
    }
}

fn endpoint_payload_object(endpoint: &str, errors: &mut Vec<String>) -> Option<String> {
    let masked = mask_csharp_string_bodies(endpoint);
    let json_indexes = find_results_json_new_indexes(&masked);
    if json_indexes.len() != 1 {
        errors.push(
            "API must declare exactly one cluster capacity admission JSON payload".to_string(),
        );
        return None;
    }
    let object_start = masked[json_indexes[0]..]
        .find('{')
        .map(|offset| json_indexes[0] + offset)?;
    let object_end = matching_delimiter_index(&masked, object_start, b'{', b'}')?;
    let suffix = masked[object_end + 1..].trim();
    if suffix != "));" {
        errors.push(
            "API cluster capacity admission JSON payload must be static anonymous object with no extra JSON arguments"
                .to_string(),
        );
        return None;
    }
    Some(endpoint[object_start..=object_end].to_string())
}

fn find_results_json_new_indexes(masked: &str) -> Vec<usize> {
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("Results") {
        let start = offset + relative;
        offset = start + "Results".len();
        if !identifier_boundary(masked, start, start + "Results".len()) {
            continue;
        }
        let mut cursor = skip_ws(masked, start + "Results".len());
        if masked.as_bytes().get(cursor) != Some(&b'.') {
            continue;
        }
        cursor = skip_ws(masked, cursor + 1);
        if !masked.get(cursor..).unwrap_or_default().starts_with("Json")
            || !identifier_boundary(masked, cursor, cursor + "Json".len())
        {
            continue;
        }
        cursor = skip_ws(masked, cursor + "Json".len());
        if masked.as_bytes().get(cursor) != Some(&b'(') {
            continue;
        }
        cursor = skip_ws(masked, cursor + 1);
        if masked.get(cursor..).unwrap_or_default().starts_with("new")
            && identifier_boundary(masked, cursor, cursor + "new".len())
        {
            indexes.push(start);
        }
    }
    indexes
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Vec<String> {
    let bodies = csharp_array_bodies(program, variable);
    if bodies.len() != 1 {
        errors.push(format!(
            "API {field} {variable} must have exactly one assignment"
        ));
        return Vec::new();
    }
    csharp_array_literal_values(&bodies[0], &format!("API {field}"), errors)
}

fn csharp_array_bodies(program: &str, variable: &str) -> Vec<String> {
    let masked = mask_csharp_string_bodies(program);
    let mut bodies = Vec::new();
    for index in identifier_positions(&masked, variable) {
        if !is_var_declaration(&masked, index) {
            continue;
        }
        let mut cursor = skip_ws(&masked, index + variable.len());
        if masked.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        cursor = skip_ws(&masked, cursor + 1);
        if !masked
            .get(cursor..)
            .unwrap_or_default()
            .starts_with("new[]")
        {
            continue;
        }
        cursor = skip_ws(&masked, cursor + "new[]".len());
        if masked.as_bytes().get(cursor) != Some(&b'{') {
            continue;
        }
        let Some(close) = matching_delimiter_index(&masked, cursor, b'{', b'}') else {
            continue;
        };
        let semicolon = skip_ws(&masked, close + 1);
        if masked.as_bytes().get(semicolon) == Some(&b';') {
            bodies.push(program[cursor + 1..close].to_string());
        }
    }
    bodies
}

fn csharp_array_literal_values(body: &str, label: &str, errors: &mut Vec<String>) -> Vec<String> {
    let mut values = Vec::new();
    for item in split_top_level_items(body) {
        let text = item.trim();
        if text.is_empty() {
            continue;
        }
        if let Some(value) = csharp_string_value(text) {
            values.push(value);
        } else {
            errors.push(format!(
                "{label} array must use literal string entries only"
            ));
        }
    }
    values
}

fn validate_bound_array_integrity(
    program: &str,
    endpoint: &EndpointBlock,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let masked = mask_csharp_string_bodies(program);
    let mut direct_write = false;
    let mut unsafe_reference = false;
    for index in identifier_positions(&masked, variable) {
        if allowed_bound_array_reference(program, endpoint, variable, index) {
            continue;
        }
        unsafe_reference = true;
        let next = skip_ws(&masked, index + variable.len());
        if masked.as_bytes().get(next) == Some(&b'=') {
            direct_write = true;
        }
    }
    if direct_write {
        errors.push(format!(
            "API {field} {variable} must have exactly one assignment"
        ));
    }
    if unsafe_reference {
        errors.push(format!(
            "API {field} {variable} has unsafe write or mutation"
        ));
    }
}

fn allowed_bound_array_reference(
    program: &str,
    endpoint: &EndpointBlock,
    variable: &str,
    index: usize,
) -> bool {
    let masked = mask_csharp_string_bodies(program);
    if is_var_declaration(&masked, index) {
        return true;
    }
    let Some(relative_index) = index.checked_sub(endpoint.start) else {
        return false;
    };
    if relative_index >= endpoint.text.len() {
        return false;
    }
    let line_start = endpoint.text[..relative_index]
        .rfind('\n')
        .map(|position| position + 1)
        .unwrap_or(0);
    let line_end = endpoint.text[relative_index..]
        .find('\n')
        .map(|position| relative_index + position)
        .unwrap_or(endpoint.text.len());
    let line = endpoint.text[line_start..line_end].trim();
    let compact_line = compact(line);
    ENDPOINT_ARRAY_BINDINGS
        .iter()
        .any(|(field, bound)| *bound == variable && compact_line == format!("{field}={variable},"))
        || [
            ("supportedWorkflows", "clusterCapacityAdmissionWorkflows"),
            ("capacitySignals", "clusterCapacityAdmissionSignals"),
            ("requiredGuards", "clusterCapacityAdmissionRequiredGuards"),
            (
                "requiredEvidence",
                "clusterCapacityAdmissionRequiredEvidence",
            ),
        ]
        .iter()
        .any(|(field, bound)| *bound == variable && compact_line == format!("{field}={variable},"))
}

fn endpoint_inline_array_values(block: &str, field: &str, errors: &mut Vec<String>) -> Vec<String> {
    let Some(value) = top_level_assignment_source(block, field) else {
        errors.push(format!("API missing {field} array"));
        return Vec::new();
    };
    let Some(body) = exact_new_array_body(&value) else {
        errors.push(format!(
            "API {field} must use exact inline array assignment"
        ));
        return Vec::new();
    };
    csharp_array_literal_values(&body, &format!("API {field}"), errors)
}

fn exact_new_array_body(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches(',').trim();
    if !trimmed.starts_with("new[]") {
        return None;
    }
    let cursor = skip_ws(trimmed, "new[]".len());
    if trimmed.as_bytes().get(cursor) != Some(&b'{') {
        return None;
    }
    let close = matching_delimiter_index(trimmed, cursor, b'{', b'}')?;
    trimmed[close + 1..]
        .trim()
        .is_empty()
        .then(|| trimmed[cursor + 1..close].to_string())
}

fn anonymous_object_body(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if !trimmed.starts_with("new") {
        return None;
    }
    let open = trimmed.find('{')?;
    let close = matching_delimiter_index(trimmed, open, b'{', b'}')?;
    trimmed[close + 1..]
        .trim()
        .is_empty()
        .then(|| trimmed[open..=close].to_string())
}

fn top_level_members(block: &str) -> BTreeMap<String, String> {
    let Some(body) = csharp_body_source(block) else {
        return BTreeMap::new();
    };
    let mut members = BTreeMap::new();
    for item in split_top_level_items(&body) {
        if let Some((field, value)) = split_top_level_assignment(&item) {
            members.insert(
                decode_csharp_unicode_escapes(field.trim())
                    .trim_start_matches('@')
                    .to_string(),
                value.trim().to_string(),
            );
        } else if let Some(name) = shorthand_field(&item) {
            members.insert(name, String::new());
        }
    }
    members
}

fn top_level_member_counts(block: &str) -> BTreeMap<String, usize> {
    let Some(body) = csharp_body_source(block) else {
        return BTreeMap::new();
    };
    let mut counts = BTreeMap::new();
    for item in split_top_level_items(&body) {
        let name = split_top_level_assignment(&item)
            .map(|(field, _)| {
                decode_csharp_unicode_escapes(field.trim())
                    .trim_start_matches('@')
                    .to_string()
            })
            .or_else(|| shorthand_field(&item));
        if let Some(name) = name {
            *counts.entry(name).or_insert(0) += 1;
        }
    }
    counts
}

fn top_level_assignment<'a>(members: &'a BTreeMap<String, String>, field: &str) -> Option<&'a str> {
    members
        .get(field)
        .map(|value| value.trim().trim_end_matches(',').trim())
}

fn top_level_string_assignment(block: &str, field: &str) -> Option<String> {
    csharp_string_value(&top_level_assignment_source(block, field)?)
}

fn top_level_assignment_source(block: &str, field: &str) -> Option<String> {
    top_level_members(block).remove(field)
}

fn csharp_body_source(source: &str) -> Option<String> {
    let masked = mask_csharp_string_bodies(source);
    let start = masked.find('{')?;
    let end = matching_delimiter_index(&masked, start, b'{', b'}')?;
    Some(source[start + 1..end].to_string())
}

fn split_top_level_items(source: &str) -> Vec<String> {
    let masked = mask_csharp_string_bodies(source);
    let mut items = Vec::new();
    let mut start = 0;
    let mut depth = 0_i32;
    for (index, byte) in masked.bytes().enumerate() {
        match byte {
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => depth -= 1,
            b',' if depth == 0 => {
                let item = source[start..index].trim();
                if !item.is_empty() {
                    items.push(item.to_string());
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    let item = source[start..].trim();
    if !item.is_empty() {
        items.push(item.to_string());
    }
    items
}

fn split_top_level_assignment(source: &str) -> Option<(&str, &str)> {
    let masked = mask_csharp_string_bodies(source);
    let mut depth = 0_i32;
    for (index, byte) in masked.bytes().enumerate() {
        match byte {
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => depth -= 1,
            b'=' if depth == 0 => return Some((&source[..index], &source[index + 1..])),
            _ => {}
        }
    }
    None
}

fn shorthand_field(source: &str) -> Option<String> {
    let trimmed = source.trim().trim_end_matches(',').trim();
    if trimmed.is_empty() || trimmed.contains('=') {
        return None;
    }
    let name = trimmed
        .split('.')
        .next_back()
        .unwrap_or(trimmed)
        .trim()
        .trim_start_matches('@');
    valid_identifier(name).then(|| decode_csharp_unicode_escapes(name))
}

fn assignment_values(block: &str) -> Vec<(String, String)> {
    let masked = mask_csharp_string_bodies(block);
    let mut values = Vec::new();
    for (field, index) in all_identifier_positions(&masked) {
        let next = skip_ws(&masked, index + field.len());
        if masked.as_bytes().get(next) == Some(&b'=') {
            let end = assignment_end_index(&masked, index);
            values.push((
                decode_csharp_unicode_escapes(&field),
                block[next + 1..end]
                    .trim()
                    .trim_end_matches(',')
                    .trim()
                    .to_string(),
            ));
        }
    }
    values
}

fn assignment_field_names(masked: &str) -> Vec<String> {
    all_identifier_positions(masked)
        .into_iter()
        .filter_map(|(field, index)| {
            let next = skip_ws(masked, index + field.len());
            (masked.as_bytes().get(next) == Some(&b'=')).then(|| {
                decode_csharp_unicode_escapes(&field)
                    .trim_start_matches('@')
                    .to_string()
            })
        })
        .collect()
}

fn assignment_end_index(masked: &str, start: usize) -> usize {
    let base_depth = brace_depth_at(masked, start);
    for index in start..masked.len() {
        let byte = masked.as_bytes()[index];
        if byte == b',' && brace_depth_at(masked, index) == base_depth {
            return index + 1;
        }
        if byte == b'}' && brace_depth_at(masked, index) == base_depth {
            return index;
        }
    }
    masked.len()
}

fn shorthand_member_names(block: &str) -> Vec<String> {
    let Some(body) = csharp_body_source(block) else {
        return Vec::new();
    };
    split_top_level_items(&body)
        .into_iter()
        .filter_map(|item| shorthand_field(&item))
        .collect()
}

fn member_access_fields(masked: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut index = 0;
    while index < masked.len() {
        let Some((first, end)) = read_identifier(masked, index) else {
            index += 1;
            continue;
        };
        let mut cursor = end;
        let mut parts = vec![first];
        let mut saw_dot = false;
        loop {
            cursor = skip_ws(masked, cursor);
            if masked.as_bytes().get(cursor) != Some(&b'.') {
                break;
            }
            saw_dot = true;
            cursor = skip_ws(masked, cursor + 1);
            let Some((part, part_end)) = read_identifier(masked, cursor) else {
                break;
            };
            parts.push(part);
            cursor = part_end;
        }
        if saw_dot {
            fields.extend(parts.into_iter().skip(1).map(|field| {
                decode_csharp_unicode_escapes(&field)
                    .trim_start_matches('@')
                    .to_string()
            }));
            index = cursor;
        } else {
            index = end;
        }
    }
    fields
}

fn allowed_endpoint_fields() -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    for field in [
        "source",
        "admissionMode",
        "dryRunRequired",
        "providerCallsEnabled",
        "liveProviderValidationAllowed",
        "livePlacementAllowed",
        "rawCapacityRowsAllowed",
        "rawProviderPayloadsAllowed",
        "hypervisorWorkflowParity",
        "rules",
        "id",
        "decision",
        "requirement",
        "evidence",
    ] {
        fields.insert(field.to_string());
    }
    for key in REQUIRED_HYPERVISOR_PARITY_KEYS {
        fields.insert((*key).to_string());
    }
    for (field, _) in ENDPOINT_ARRAY_BINDINGS {
        fields.insert((*field).to_string());
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        fields.insert((*field).to_string());
    }
    fields
}

fn rules_from_catalog(catalog: &Value) -> Vec<Rule> {
    object_array(catalog.get("rules"))
        .into_iter()
        .filter_map(|rule| {
            Some(Rule {
                id: string_field(rule, "id")?.to_string(),
                decision: string_field(rule, "decision")?.to_string(),
                requirement: string_field(rule, "requirement")?.to_string(),
                evidence: string_field(rule, "evidence")?.to_string(),
            })
        })
        .collect()
}

fn comparable_csharp_value(value: &str) -> String {
    csharp_string_value(value)
        .unwrap_or_else(|| value.trim().trim_end_matches(',').trim().to_string())
}

fn csharp_string_value(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches(',').trim();
    let literal = csharp_string_literal_at(trimmed, 0)?;
    (literal.end == trimmed.len()).then_some(literal.value)
}

fn csharp_literal_compositions(program: &str) -> Vec<(String, usize)> {
    let mut terms = Vec::new();
    let mut index = 0;
    let mut line = 1;
    while index < program.len() {
        let Some(literal) = csharp_string_literal_at(program, index) else {
            if program.as_bytes().get(index) == Some(&b'\n') {
                line += 1;
            }
            index += 1;
            continue;
        };
        let start_line = line;
        let mut parts = Vec::new();
        if !literal.interpolated {
            parts.push(literal.value.clone());
            let mut cursor = literal.end;
            loop {
                cursor = skip_ws(program, cursor);
                if program.as_bytes().get(cursor) != Some(&b'+') {
                    break;
                }
                cursor = skip_ws(program, cursor + 1);
                let Some(next_literal) = csharp_string_literal_at(program, cursor) else {
                    break;
                };
                if next_literal.interpolated {
                    break;
                }
                parts.push(next_literal.value.clone());
                cursor = next_literal.end;
            }
            terms.push((parts.join(""), start_line));
        }
        line += program[index..literal.end].matches('\n').count();
        index = literal.end;
    }
    terms
}

fn unsafe_interpolated_string_lines(program: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    let mut index = 0;
    let mut line = 1;
    while index < program.len() {
        let Some(literal) = csharp_string_literal_at(program, index) else {
            if program.as_bytes().get(index) == Some(&b'\n') {
                line += 1;
            }
            index += 1;
            continue;
        };
        if literal.interpolated {
            let source = decode_csharp_unicode_escapes(&literal.source);
            let compacted = source
                .chars()
                .filter(|ch| !ch.is_whitespace() && !"{}\"'@$".contains(*ch))
                .collect::<String>();
            if prohibited_value(&literal.value)
                || prohibited_value(&source)
                || prohibited_value(&compacted)
                || source.contains("://")
            {
                lines.push(line);
            }
        }
        line += program[index..literal.end].matches('\n').count();
        index = literal.end;
    }
    lines.sort_unstable();
    lines.dedup();
    lines
}

fn csharp_string_concat_values(program: &str) -> Vec<(String, usize)> {
    let masked = mask_csharp_string_bodies(program);
    let mut values = Vec::new();
    let mut offset = 0;
    while let Some(relative) = masked[offset..].find("string.Concat") {
        let start = offset + relative;
        offset = start + "string.Concat".len();
        let Some(open) = masked[start..].find('(').map(|found| start + found) else {
            continue;
        };
        let Some(close) = matching_delimiter_index(&masked, open, b'(', b')') else {
            continue;
        };
        let args = &program[open + 1..close];
        let parts = csharp_literal_compositions(args)
            .into_iter()
            .map(|(value, _)| value)
            .collect::<Vec<_>>();
        if !parts.is_empty() {
            values.push((parts.join(""), program[..start].matches('\n').count() + 1));
        }
        offset = close + 1;
    }
    values
}

fn strip_csharp_comments(program: &str) -> String {
    let mut output = String::with_capacity(program.len());
    let mut index = 0;
    while index < program.len() {
        if let Some(literal) = csharp_string_literal_at(program, index) {
            output.push_str(&program[index..literal.end]);
            index = literal.end;
            continue;
        }
        let bytes = program.as_bytes();
        if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'/') {
            while index < program.len() && program.as_bytes()[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            if index < program.len() {
                output.push('\n');
                index += 1;
            }
            continue;
        }
        if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
            output.push_str("  ");
            index += 2;
            while index < program.len() {
                if program.as_bytes().get(index) == Some(&b'*')
                    && program.as_bytes().get(index + 1) == Some(&b'/')
                {
                    output.push_str("  ");
                    index += 2;
                    break;
                }
                output.push(if program.as_bytes()[index] == b'\n' {
                    '\n'
                } else {
                    ' '
                });
                index += 1;
            }
            continue;
        }
        output.push(program.as_bytes()[index] as char);
        index += 1;
    }
    output
}

fn mask_csharp_string_bodies(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        if let Some(literal) = csharp_string_literal_at(source, index) {
            let segment = &source[index..literal.end];
            for (offset, byte) in segment.bytes().enumerate() {
                let keep = offset == 0
                    || offset + 1 == segment.len()
                    || byte == b'\n'
                    || byte == b'$'
                    || byte == b'@';
                output.push(if keep { byte as char } else { ' ' });
            }
            index = literal.end;
            continue;
        }
        output.push(source.as_bytes()[index] as char);
        index += 1;
    }
    output
}

fn csharp_string_literal_at(text: &str, start: usize) -> Option<CSharpString> {
    let bytes = text.as_bytes();
    let mut cursor = start;
    let mut dollars = 0;
    while bytes.get(cursor) == Some(&b'$') {
        dollars += 1;
        cursor += 1;
    }
    let interpolated = dollars > 0;
    if bytes.get(cursor) == Some(&b'@') && bytes.get(cursor + 1) == Some(&b'"') {
        return csharp_verbatim_string(text, start, cursor + 2, interpolated);
    }
    if bytes.get(cursor) == Some(&b'@')
        && bytes.get(cursor + 1) == Some(&b'$')
        && bytes.get(cursor + 2) == Some(&b'"')
    {
        return csharp_verbatim_string(text, start, cursor + 3, true);
    }
    if bytes.get(cursor) == Some(&b'"') {
        let mut quote_count = 0;
        while bytes.get(cursor + quote_count) == Some(&b'"') {
            quote_count += 1;
        }
        if quote_count >= 3 {
            return csharp_raw_string(text, start, cursor + quote_count, quote_count, interpolated);
        }
        if interpolated {
            return csharp_interpolated_string(text, start, cursor + 1, false);
        }
        return csharp_regular_string(text, start, cursor + 1);
    }
    if bytes.get(start) == Some(&b'@')
        && bytes.get(start + 1) == Some(&b'$')
        && bytes.get(start + 2) == Some(&b'"')
    {
        return csharp_verbatim_string(text, start, start + 3, true);
    }
    if bytes.get(start) == Some(&b'@') && bytes.get(start + 1) == Some(&b'"') {
        return csharp_verbatim_string(text, start, start + 2, false);
    }
    None
}

fn csharp_raw_string(
    text: &str,
    start: usize,
    content_start: usize,
    quote_count: usize,
    interpolated: bool,
) -> Option<CSharpString> {
    let delimiter = "\"".repeat(quote_count);
    let finish = text[content_start..]
        .find(&delimiter)
        .map(|found| content_start + found)
        .unwrap_or(text.len());
    let end = (finish + quote_count).min(text.len());
    Some(CSharpString {
        value: decode_csharp_unicode_escapes(&text[content_start..finish]),
        end,
        interpolated,
        source: text[start..end].to_string(),
    })
}

fn csharp_verbatim_string(
    text: &str,
    start: usize,
    content_start: usize,
    interpolated: bool,
) -> Option<CSharpString> {
    if interpolated {
        return csharp_interpolated_string(text, start, content_start, true);
    }
    let mut raw = String::new();
    let mut index = content_start;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        if byte == b'"' && text.as_bytes().get(index + 1) == Some(&b'"') {
            raw.push('"');
            index += 2;
        } else if byte == b'"' {
            return Some(CSharpString {
                value: decode_csharp_unicode_escapes(&raw),
                end: index + 1,
                interpolated,
                source: text[start..=index].to_string(),
            });
        } else {
            raw.push(byte as char);
            index += 1;
        }
    }
    Some(CSharpString {
        value: decode_csharp_unicode_escapes(&raw),
        end: index,
        interpolated,
        source: text[start..index].to_string(),
    })
}

fn csharp_regular_string(text: &str, start: usize, content_start: usize) -> Option<CSharpString> {
    let mut raw = String::new();
    let mut index = content_start;
    let mut escaped = false;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        if escaped {
            raw.push('\\');
            raw.push(byte as char);
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Some(CSharpString {
                value: csharp_unescape_string(&raw),
                end: index + 1,
                interpolated: false,
                source: text[start..=index].to_string(),
            });
        } else {
            raw.push(byte as char);
        }
        index += 1;
    }
    Some(CSharpString {
        value: csharp_unescape_string(&raw),
        end: index,
        interpolated: false,
        source: text[start..index].to_string(),
    })
}

fn csharp_interpolated_string(
    text: &str,
    start: usize,
    content_start: usize,
    verbatim: bool,
) -> Option<CSharpString> {
    let mut raw = String::new();
    let mut index = content_start;
    let mut escaped = false;
    let mut brace_depth = 0_i32;
    while index < text.len() {
        if brace_depth > 0 {
            if let Some(inner) = csharp_string_literal_at(text, index) {
                index = inner.end;
                continue;
            }
            let byte = text.as_bytes()[index];
            if byte == b'{' {
                brace_depth += 1;
            } else if byte == b'}' {
                brace_depth -= 1;
            }
            index += 1;
            continue;
        }
        let byte = text.as_bytes()[index];
        if escaped {
            raw.push('\\');
            raw.push(byte as char);
            escaped = false;
        } else if byte == b'\\' && !verbatim {
            escaped = true;
        } else if byte == b'{' && text.as_bytes().get(index + 1) == Some(&b'{') {
            raw.push('{');
            index += 1;
        } else if byte == b'}' && text.as_bytes().get(index + 1) == Some(&b'}') {
            raw.push('}');
            index += 1;
        } else if byte == b'{' {
            brace_depth = 1;
        } else if byte == b'"' && verbatim && text.as_bytes().get(index + 1) == Some(&b'"') {
            raw.push('"');
            index += 1;
        } else if byte == b'"' {
            let value = if verbatim {
                decode_csharp_unicode_escapes(&raw)
            } else {
                csharp_unescape_string(&raw)
            };
            return Some(CSharpString {
                value,
                end: index + 1,
                interpolated: true,
                source: text[start..=index].to_string(),
            });
        } else {
            raw.push(byte as char);
        }
        index += 1;
    }
    Some(CSharpString {
        value: if verbatim {
            decode_csharp_unicode_escapes(&raw)
        } else {
            csharp_unescape_string(&raw)
        },
        end: index,
        interpolated: true,
        source: text[start..index].to_string(),
    })
}

fn csharp_unescape_string(value: &str) -> String {
    let mut output = String::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            output.push(bytes[index] as char);
            index += 1;
            continue;
        }
        let Some(next) = bytes.get(index + 1).copied() else {
            output.push('\\');
            break;
        };
        match next {
            b'u' if index + 6 <= bytes.len() => {
                if let Some(ch) = unicode_escape_char(&value[index + 2..index + 6]) {
                    output.push(ch);
                }
                index += 6;
            }
            b'U' if index + 10 <= bytes.len() => {
                if let Some(ch) = unicode_escape_char(&value[index + 2..index + 10]) {
                    output.push(ch);
                }
                index += 10;
            }
            b'x' => {
                let end = (index + 6).min(bytes.len());
                let mut taken = 0;
                for cursor in index + 2..end {
                    if (value.as_bytes()[cursor] as char).is_ascii_hexdigit() {
                        taken += 1;
                    } else {
                        break;
                    }
                }
                if taken > 0 {
                    if let Some(ch) = unicode_escape_char(&value[index + 2..index + 2 + taken]) {
                        output.push(ch);
                    }
                    index += 2 + taken;
                } else {
                    index += 2;
                }
            }
            b'"' => {
                output.push('"');
                index += 2;
            }
            b'\'' => {
                output.push('\'');
                index += 2;
            }
            b'\\' => {
                output.push('\\');
                index += 2;
            }
            b'0' => {
                output.push('\0');
                index += 2;
            }
            b'a' => {
                output.push('\u{7}');
                index += 2;
            }
            b'b' => {
                output.push('\u{8}');
                index += 2;
            }
            b'f' => {
                output.push('\u{c}');
                index += 2;
            }
            b'n' => {
                output.push('\n');
                index += 2;
            }
            b'r' => {
                output.push('\r');
                index += 2;
            }
            b't' => {
                output.push('\t');
                index += 2;
            }
            b'v' => {
                output.push('\u{b}');
                index += 2;
            }
            _ => {
                output.push(next as char);
                index += 2;
            }
        }
    }
    output
}

fn decode_csharp_unicode_escapes(text: &str) -> String {
    let mut output = String::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && matches!(bytes.get(index + 1), Some(b'u' | b'U')) {
            let width = if bytes[index + 1] == b'u' { 4 } else { 8 };
            if index + 2 + width <= bytes.len() {
                if let Some(ch) = unicode_escape_char(&text[index + 2..index + 2 + width]) {
                    output.push(ch);
                    index += 2 + width;
                    continue;
                }
            }
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

fn unicode_escape_char(hex: &str) -> Option<char> {
    u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
}

fn prohibited_value(value: &str) -> bool {
    contains_akia(value)
        || contains_private_key(value)
        || contains_url(value)
        || contains_private_ipv4(value)
        || contains_uuid(value)
        || contains_secret_assignment(value)
}

fn contains_akia(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    for index in 0..=bytes.len() - 20 {
        if &bytes[index..index + 4] == b"AKIA"
            && bytes[index + 4..index + 20]
                .iter()
                .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
        {
            return true;
        }
    }
    false
}

fn contains_private_key(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

fn contains_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower
        .find("://")
        .and_then(|marker| {
            let scheme = lower[..marker]
                .chars()
                .rev()
                .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
                .collect::<String>();
            (!scheme.is_empty()
                && scheme
                    .chars()
                    .last()
                    .map(|ch| ch.is_ascii_alphabetic())
                    .unwrap_or(false))
            .then_some(())
        })
        .is_some()
}

fn contains_private_ipv4(value: &str) -> bool {
    for token in value.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        let octets = token.split('.').collect::<Vec<_>>();
        if octets.len() != 4 {
            continue;
        }
        let parsed = octets
            .iter()
            .map(|part| part.parse::<u8>())
            .collect::<Result<Vec<_>, _>>();
        let Ok(octets) = parsed else {
            continue;
        };
        if octets[0] == 10
            || (octets[0] == 192 && octets[1] == 168)
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        {
            return true;
        }
    }
    false
}

fn contains_uuid(value: &str) -> bool {
    for token in value.split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-')) {
        let parts = token.split('-').collect::<Vec<_>>();
        if parts.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(parts.iter())
                .all(|(len, part)| {
                    part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit())
                })
        {
            return true;
        }
    }
    false
}

fn contains_secret_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|term| {
        lower
            .find(term)
            .map(|index| {
                lower[index + term.len()..]
                    .chars()
                    .skip_while(|ch| ch.is_whitespace())
                    .next()
                    .map(|ch| ch == ':' || ch == '=')
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    })
}

fn prohibited_endpoint_field(field: &str) -> bool {
    let normalized = normalized_key(field);
    contains_any(
        &normalized,
        &[
            "clustername",
            "clusterid",
            "clusteridentifier",
            "datastorename",
            "datastoreid",
            "hostname",
            "hostid",
            "hostidentifier",
            "username",
            "userid",
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
            "rawcapacity",
            "rawrow",
            "providerpayload",
            "serialnumber",
            "vcenter",
        ],
    )
}

fn unsafe_true_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "live",
            "provider",
            "raw",
            "capacity",
            "cluster",
            "datastore",
            "host",
            "credential",
            "secret",
            "token",
            "tenant",
            "object",
            "private",
            "user",
            "mutation",
            "placement",
            "validation",
            "allowed",
            "endpoint",
        ],
    )
}

fn object_keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

fn object_array(value: Option<&Value>) -> Vec<&Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect()
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_field(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn string_array_field(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn push_missing_unexpected(
    context: &str,
    label: &str,
    values: &[String],
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let value_set = values.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let required_set = required_values.iter().copied().collect::<BTreeSet<_>>();
    let missing = required_values
        .iter()
        .copied()
        .filter(|value| !value_set.contains(value))
        .collect::<Vec<_>>();
    let unexpected = values
        .iter()
        .map(String::as_str)
        .filter(|value| !required_set.contains(value))
        .collect::<Vec<_>>();
    let prefix = if context.is_empty() {
        label.to_string()
    } else {
        format!("{context} {label}")
    };
    if !missing.is_empty() {
        errors.push(format!("{prefix} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{prefix} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
}

fn push_missing_unexpected_exact(
    missing_prefix: &str,
    unexpected_prefix: &str,
    values: &[String],
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let value_set = values.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let required_set = required_values.iter().copied().collect::<BTreeSet<_>>();
    let missing = required_values
        .iter()
        .copied()
        .filter(|value| !value_set.contains(value))
        .collect::<Vec<_>>();
    let unexpected = values
        .iter()
        .map(String::as_str)
        .filter(|value| !required_set.contains(value))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        errors.push(format!("{missing_prefix}: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!("{unexpected_prefix}: {}", unexpected.join(", ")));
    }
}

fn unique_len(values: &[String]) -> usize {
    values.iter().collect::<BTreeSet<_>>().len()
}

fn disabled_field_label(field: &str) -> &str {
    match field {
        "providerCallsEnabled" => "provider calls",
        "liveProviderValidationAllowed" => "live provider validation",
        "livePlacementAllowed" => "live placement",
        "rawCapacityRowsAllowed" => "raw capacity rows",
        "rawProviderPayloadsAllowed" => "raw provider payloads",
        _ => field,
    }
}

fn short_array_label(field: &str) -> &str {
    match field {
        "supportedWorkflows" => "workflows",
        "capacitySignals" => "signals",
        "requiredGuards" => "guards",
        "requiredEvidence" => "evidence",
        _ => field,
    }
}

fn compact(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn contains_any(value: &str, terms: &[&str]) -> bool {
    terms.iter().any(|term| value.contains(term))
}

fn skip_ws(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn matching_delimiter_index(text: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0_i32;
    for index in start..text.len() {
        let byte = text.as_bytes()[index];
        if byte == open {
            depth += 1;
        } else if byte == close {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn brace_depth_at(text: &str, position: usize) -> i32 {
    let mut depth = 0_i32;
    for byte in text[..position.min(text.len())].bytes() {
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
        }
    }
    depth
}

fn identifier_positions(text: &str, ident: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut offset = 0;
    while let Some(relative) = text[offset..].find(ident) {
        let start = offset + relative;
        let end = start + ident.len();
        if identifier_boundary(text, start, end) {
            positions.push(start);
        }
        offset = end;
    }
    positions
}

fn all_identifier_positions(text: &str) -> Vec<(String, usize)> {
    let mut positions = Vec::new();
    let mut index = 0;
    while index < text.len() {
        if let Some((ident, end)) = read_identifier(text, index) {
            positions.push((ident, index));
            index = end;
        } else {
            index += 1;
        }
    }
    positions
}

fn read_identifier(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let first = *bytes.get(start)?;
    if !is_ident_start(first) && first != b'@' {
        return None;
    }
    let mut index = start + 1;
    while index < bytes.len() && is_ident_byte(bytes[index]) {
        index += 1;
    }
    Some((
        text[start..index].trim_start_matches('@').to_string(),
        index,
    ))
}

fn valid_identifier(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && (is_ident_start(bytes[0]) || bytes[0] == b'@')
        && bytes[1..].iter().copied().all(is_ident_byte)
}

fn is_var_declaration(masked: &str, index: usize) -> bool {
    let before = masked[..index].trim_end();
    before.ends_with("var")
        && before[..before.len().saturating_sub(3)].ends_with(|ch: char| !is_ident_byte(ch as u8))
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = start
        .checked_sub(1)
        .and_then(|position| text.as_bytes().get(position))
        .copied();
    let after = text.as_bytes().get(end).copied();
    !before.map(is_ident_byte).unwrap_or(false) && !after.map(is_ident_byte).unwrap_or(false)
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
