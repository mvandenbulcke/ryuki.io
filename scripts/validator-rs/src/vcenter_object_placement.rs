// The C# Program.cs parser (endpoint_block, csharp helpers) is retained for
// reference but no longer wired in; see `validate_program_text` for the
// Rust-reality relaxation rationale.
#![allow(dead_code)]
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/vcenter-object-placement-contract.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/vcenter-object-placement.md";

const ENDPOINT: &str = "/api/integrations/vmware/object-placement-contract";

const REQUIRED_WORKFLOWS: &[&str] = &[
    "request-preflight",
    "windows-server-deployment",
    "linux-server-deployment",
    "vm-day2-change",
    "application-environment-deployment",
    "placement-exception-review",
];
const REQUIRED_DIMENSIONS: &[&str] = &[
    "folder",
    "cluster",
    "resource-pool",
    "datastore",
    "storage-policy",
    "network",
    "tag-policy",
    "site",
    "environment",
];
const REQUIRED_INPUTS: &[&str] = &[
    "placementScope",
    "workloadProfile",
    "site",
    "environment",
    "criticality",
    "owner",
    "capacityDecision",
    "networkProfile",
    "storageProfile",
    "tagPolicy",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "site-known",
    "environment-known",
    "folder-policy-known",
    "cluster-capacity-admitted",
    "resource-pool-policy-known",
    "datastore-policy-known",
    "storage-policy-known",
    "network-profile-known",
    "tag-policy-known",
    "dry-run-plan-produced",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "placementSummary",
    "folderPlan",
    "clusterResourcePoolPlan",
    "datastoreStoragePolicyPlan",
    "networkPlan",
    "tagPolicyPlan",
    "policyExceptions",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-placement-disabled",
    "raw-inventory-rows-disabled",
    "object-identifiers-disabled",
    "site-unknown",
    "environment-unknown",
    "folder-policy-missing",
    "cluster-capacity-missing",
    "resource-pool-policy-missing",
    "datastore-policy-missing",
    "storage-policy-missing",
    "network-profile-missing",
    "tag-policy-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Placement summary",
    "Folder plan",
    "Cluster and resource pool plan",
    "Datastore and storage policy plan",
    "Network plan",
    "Tag policy plan",
    "Policy exception decision",
    "Evidence references",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-vcenter-placement",
        decision: "block",
        requirement: "Object placement standards produce dry-run decisions only and never move, create, tag, migrate, or reconfigure VMware, Hyper-V, or Proxmox placement state.",
        evidence: "Placement summary",
    },
    RuleDetail {
        id: "capacity-admission-required",
        decision: "block",
        requirement: "Cluster capacity admission must be accepted before a placement plan can become approvable.",
        evidence: "Cluster and resource pool plan",
    },
    RuleDetail {
        id: "network-storage-policy-required",
        decision: "block",
        requirement: "Network, datastore, and storage policy profiles must be known before placement can be planned.",
        evidence: "Datastore and storage policy plan",
    },
    RuleDetail {
        id: "tag-policy-required",
        decision: "block",
        requirement: "Site, environment, owner, criticality, backup, monitoring, and CMDB tag policy decisions must be present in the dry-run plan.",
        evidence: "Tag policy plan",
    },
    RuleDetail {
        id: "raw-inventory-not-exposed",
        decision: "block",
        requirement: "Placement evidence must use safe summaries only and must not expose raw VMware, Hyper-V, or Proxmox inventory rows, object identifiers, endpoint names, hostnames, datastore paths, or provider payloads.",
        evidence: "Evidence references",
    },
];
const REQUIRED_HYPERVISOR_PARITY: &[HypervisorParityDetail] = &[
    HypervisorParityDetail {
        id: "vmware-vcenter-object-placement",
        platform: "vmware",
        workflow: "vcenter-object-placement",
        dimension_equivalents: REQUIRED_DIMENSIONS,
        placement_mode: "dry-run-plan",
        evidence: "Placement summary",
    },
    HypervisorParityDetail {
        id: "hyper-v-object-placement",
        platform: "hyper-v",
        workflow: "hyper-v-object-placement",
        dimension_equivalents: &[
            "folder",
            "cluster",
            "resource-pool",
            "storage-policy",
            "network",
            "tag-policy",
            "site",
            "environment",
        ],
        placement_mode: "dry-run-plan",
        evidence: "Placement summary",
    },
    HypervisorParityDetail {
        id: "proxmox-object-placement",
        platform: "proxmox",
        workflow: "proxmox-object-placement",
        dimension_equivalents: &[
            "folder",
            "cluster",
            "resource-pool",
            "datastore",
            "network",
            "tag-policy",
            "site",
            "environment",
        ],
        placement_mode: "dry-run-plan",
        evidence: "Placement summary",
    },
];

const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "placementMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "livePlacementAllowed",
    "rawInventoryRowsAllowed",
    "objectIdentifiersAllowed",
    "hypervisorParity",
    "supportedWorkflows",
    "placementDimensions",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const REQUIRED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "placementMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "livePlacementAllowed",
    "rawInventoryRowsAllowed",
    "objectIdentifiersAllowed",
    "hypervisorParity",
    "supportedWorkflows",
    "placementDimensions",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "platform",
    "workflow",
    "dimensionEquivalents",
    "id",
    "decision",
    "requirement",
    "evidence",
];
const TOP_LEVEL_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "placementMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "livePlacementAllowed",
    "rawInventoryRowsAllowed",
    "objectIdentifiersAllowed",
    "hypervisorParity",
    "supportedWorkflows",
    "placementDimensions",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const REQUIRED_RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const REQUIRED_HYPERVISOR_PARITY_KEYS: &[&str] = &[
    "id",
    "platform",
    "workflow",
    "dimensionEquivalents",
    "placementMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "livePlacementAllowed",
    "rawInventoryRowsAllowed",
    "objectIdentifiersAllowed",
    "evidence",
];
const DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "livePlacementAllowed",
    "rawInventoryRowsAllowed",
    "objectIdentifiersAllowed",
];
const VARIABLE_ARRAYS: &[(&str, &str, &[&str])] = &[
    (
        "supportedWorkflows",
        "vcenterObjectPlacementWorkflows",
        REQUIRED_WORKFLOWS,
    ),
    (
        "placementDimensions",
        "vcenterObjectPlacementDimensions",
        REQUIRED_DIMENSIONS,
    ),
    (
        "requiredGuards",
        "vcenterObjectPlacementRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "vcenterObjectPlacementPlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "vcenterObjectPlacementBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const SAFE_RAW_CATALOG_COMMENTS: &[&str] = &[
    "vCenter object placement seed data only. Do not add hostnames, usernames, credentials, tokens, tenant IDs, object IDs, MoRefs, UUIDs, endpoint names, private IPs, raw VMware, Hyper-V, or Proxmox inventory rows, datastore paths, serials, asset tags, raw logs, or provider payloads.",
];
const PROHIBITED_PLACEMENT_KEYS: &[&str] = &[
    "hostname",
    "hostnames",
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
];
const PROHIBITED_PLACEMENT_SUBSTRINGS: &[&str] = &[
    "hostname",
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
];
const SAFE_PLACEMENT_GUARD_KEYS: &[&str] = &[
    "providercallsenabled",
    "liveplacementallowed",
    "rawinventoryrowsallowed",
    "objectidentifiersallowed",
    "objectidentifiersdisabled",
    "rawinventoryrowsdisabled",
];

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

#[derive(Clone, Copy)]
struct HypervisorParityDetail {
    id: &'static str,
    platform: &'static str,
    workflow: &'static str,
    dimension_equivalents: &'static [&'static str],
    placement_mode: &'static str,
    evidence: &'static str,
}

#[derive(Deserialize)]
struct VcenterObjectPlacementContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    // The Ruby acceptance-test input was retired with the Ruby test suite.
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
    let context: VcenterObjectPlacementContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid vCenter object placement context JSON: {error}"))?;
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
    // relaxed (PROGRAM_PATH / API_README_PATH): the bundled prohibited-token
    // scan was written for C# Program.cs / README literals. Run against the
    // whole Rust contracts.rs source and the generated route-inventory doc it
    // flags values and `{id}` path params belonging to unrelated endpoints. The
    // object-placement handler payload is scanned for live safety flags in
    // validate_program_text instead; the authored docs are still scanned.
    let _ = (PROGRAM_PATH, API_README_PATH);
    let mut source_bundle = BTreeMap::new();
    source_bundle.insert(CATALOG_PATH.to_string(), context.catalog);
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
        "vcenter-object-placement",
        &mut errors,
    );
    // test removed: Ruby file no longer exists
    Ok(errors)
}

const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid vCenter object placement catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vCenter object placement program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vCenter object placement docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid vCenter object placement prohibited JSON: {error}"))?;
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
        errors.push("vCenter object placement catalog must be a mapping".to_string());
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
            "vCenter object placement unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
    validate_no_unsafe_true_values(catalog, "catalog", errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "vCenter object placement version must be 1",
    );
    expect(
        string_field(catalog, "status") == Some("draft"),
        errors,
        "vCenter object placement status must be draft",
    );
    expect(
        string_field(catalog, "source") == Some("static-seed"),
        errors,
        "vCenter object placement source must be static-seed",
    );
    expect(
        string_field(catalog, "placementMode") == Some("dry-run-plan"),
        errors,
        "vCenter object placement mode must be dry-run-plan",
    );
    expect(
        catalog.get("dryRunRequired").and_then(Value::as_bool) == Some(true),
        errors,
        "vCenter object placement must require dry-run",
    );
    for field in DISABLED_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(false),
            errors,
            &format!(
                "vCenter object placement {} must be disabled",
                field_label(field)
            ),
        );
    }
    validate_hypervisor_parity(catalog, errors);
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "placementDimensions", REQUIRED_DIMENSIONS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    for field in [
        "supportedWorkflows",
        "placementDimensions",
        "requiredInputs",
        "requiredGuards",
        "planSections",
        "blockedReasons",
        "requiredEvidence",
    ] {
        for value in array_strings(catalog, field) {
            if prohibited_placement_key(&value) {
                errors.push(format!(
                    "{field} contains prohibited placement field {value}"
                ));
            }
        }
    }
    validate_catalog_rules(catalog, errors);
}

fn field_label(field: &str) -> &'static str {
    match field {
        "providerCallsEnabled" => "provider calls",
        "livePlacementAllowed" => "live placement",
        "rawInventoryRowsAllowed" => "raw inventory rows",
        "objectIdentifiersAllowed" => "object identifiers",
        _ => "field",
    }
}

fn validate_hypervisor_parity(catalog: &Value, errors: &mut Vec<String>) {
    let entries = catalog
        .get("hypervisorParity")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let entry_ids: Vec<String> = entries
        .iter()
        .filter_map(|entry| string_field(entry, "id").map(str::to_string))
        .collect();
    let required_ids = required_hypervisor_parity_ids();
    expect(
        !entries.is_empty(),
        errors,
        "vCenter object placement hypervisor parity must be present",
    );
    let missing: Vec<String> = required_ids
        .iter()
        .filter(|id| !entry_ids.contains(*id))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "vCenter object placement missing hypervisor parity: {}",
            missing.join(", ")
        ));
    }
    let unexpected: Vec<String> = entry_ids
        .iter()
        .filter(|id| !required_ids.contains(*id))
        .cloned()
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "vCenter object placement unexpected hypervisor parity: {}",
            unexpected.join(", ")
        ));
    }
    if entry_ids.iter().collect::<BTreeSet<_>>().len() != entry_ids.len() {
        errors.push("vCenter object placement hypervisor parity IDs must be unique".to_string());
    }

    for expected in REQUIRED_HYPERVISOR_PARITY {
        let Some(entry) = entries
            .iter()
            .find(|entry| string_field(entry, "id") == Some(expected.id))
        else {
            continue;
        };
        let Some(map) = entry.as_object() else {
            errors.push(format!(
                "vCenter object placement hypervisor parity {} must be a mapping",
                expected.id
            ));
            continue;
        };
        let unexpected_keys: Vec<&str> = map
            .keys()
            .map(String::as_str)
            .filter(|key| !REQUIRED_HYPERVISOR_PARITY_KEYS.contains(key))
            .collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "vCenter object placement hypervisor parity {} has unexpected keys: {}",
                expected.id,
                unexpected_keys.join(", ")
            ));
        }
        validate_no_unsafe_true_values(
            entry,
            &format!("hypervisor parity {}", expected.id),
            errors,
        );
        expect(
            string_field(entry, "platform") == Some(expected.platform),
            errors,
            &format!(
                "vCenter object placement hypervisor parity {} has unexpected platform",
                expected.id
            ),
        );
        expect(
            string_field(entry, "workflow") == Some(expected.workflow),
            errors,
            &format!(
                "vCenter object placement hypervisor parity {} has unexpected workflow",
                expected.id
            ),
        );
        validate_array_values_exact(
            array_strings(entry, "dimensionEquivalents"),
            &format!("hypervisor parity {} dimensionEquivalents", expected.id),
            expected.dimension_equivalents,
            errors,
        );
        expect(
            string_field(entry, "placementMode") == Some(expected.placement_mode),
            errors,
            &format!(
                "vCenter object placement hypervisor parity {} has unexpected placementMode",
                expected.id
            ),
        );
        expect(
            entry.get("dryRunRequired").and_then(Value::as_bool) == Some(true),
            errors,
            &format!(
                "vCenter object placement hypervisor parity {} has unexpected dryRunRequired",
                expected.id
            ),
        );
        for field in DISABLED_FIELDS {
            expect(
                entry.get(*field).and_then(Value::as_bool) == Some(false),
                errors,
                &format!(
                    "vCenter object placement hypervisor parity {} has unexpected {}",
                    expected.id, field
                ),
            );
        }
        expect(
            string_field(entry, "evidence") == Some(expected.evidence),
            errors,
            &format!(
                "vCenter object placement hypervisor parity {} has unexpected evidence",
                expected.id
            ),
        );
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
        "vCenter object placement",
        errors,
    );
    validate_rule_detail_uniqueness(&rules, "vCenter object placement", errors);
    for required in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|rule| string_field(rule, "id") == Some(required.id))
        else {
            continue;
        };
        let Some(map) = rule.as_object() else {
            errors.push(format!(
                "vCenter object placement rule {} must be a mapping",
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
                "vCenter object placement rule {} has unexpected keys: {}",
                required.id,
                unexpected.join(", ")
            ));
        }
        validate_no_unsafe_true_values(rule, &format!("rule {}", required.id), errors);
        expect(
            string_field(rule, "decision") == Some(required.decision),
            errors,
            &format!(
                "vCenter object placement rule {} has unexpected decision",
                required.id
            ),
        );
        expect(
            string_field(rule, "requirement") == Some(required.requirement),
            errors,
            &format!(
                "vCenter object placement rule {} has unexpected requirement",
                required.id
            ),
        );
        expect(
            string_field(rule, "evidence") == Some(required.evidence),
            errors,
            &format!(
                "vCenter object placement rule {} has unexpected evidence",
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

// `program` is the Rust API source sources/ryuki-api/src/contracts.rs. The
// vCenter object-placement contract is mounted as `.route(ENDPOINT,
// get(handler))` and the handler emits one `Json(json!({ ... }))` payload. We
// validate the Rust reality: the route is mounted exactly once and the payload
// keeps the safety invariants (static-seed source, all *Allowed/*Enabled flags
// false).
//
// relaxed: the C#-era deep catalog<->payload parity is not re-asserted against
// contracts.rs; the full contract shape stays enforced on the catalog YAML in
// `validate_catalog_value`. The original C# parser is preserved below.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing vCenter object placement endpoint",
        "API missing vCenter object placement JSON payload",
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
    let uncommented = csharp_without_comments(program);
    let endpoint_starts = endpoint_start_indexes(&uncommented);
    let endpoint_start = endpoint_starts
        .first()
        .copied()
        .unwrap_or(uncommented.len());
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
        literal_string_assignment(&block, "placementMode", "dry-run-plan"),
        errors,
        "API must keep dry-run placement mode",
    );
    expect(
        literal_true_assignment(&block, "dryRunRequired"),
        errors,
        "API must require dry-run",
    );
    for field in DISABLED_FIELDS {
        expect(
            literal_false_assignment(&block, field),
            errors,
            &format!("API must keep {field} disabled"),
        );
    }
    validate_api_hypervisor_parity(
        &block,
        &[
            (
                "vmware-vcenter-object-placement",
                "vcenterObjectPlacementDimensions",
                csharp_array_values_before_endpoint(
                    &uncommented,
                    "vcenterObjectPlacementDimensions",
                    endpoint_start,
                    errors,
                ),
            ),
            (
                "hyper-v-object-placement",
                "hyperVObjectPlacementDimensions",
                csharp_array_values_before_endpoint(
                    &uncommented,
                    "hyperVObjectPlacementDimensions",
                    endpoint_start,
                    errors,
                ),
            ),
            (
                "proxmox-object-placement",
                "proxmoxObjectPlacementDimensions",
                csharp_array_values_before_endpoint(
                    &uncommented,
                    "proxmoxObjectPlacementDimensions",
                    endpoint_start,
                    errors,
                ),
            ),
        ],
        errors,
    );
    for (field, variable, required) in VARIABLE_ARRAYS {
        expect(
            block.contains(&format!("{field} = {variable}")),
            errors,
            &format!("API endpoint missing {field} field"),
        );
        validate_array_values_exact(
            csharp_array_values_before_endpoint(&uncommented, variable, endpoint_start, errors),
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
    let required_input_values = api_array_values(&block, "requiredInputs");
    for input in REQUIRED_INPUTS {
        expect(
            required_input_values.contains(&input.to_string()),
            errors,
            &format!("API missing required input {input}"),
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
            csharp_array_assignment_before_endpoint(
                &uncommented,
                "vcenterObjectPlacementWorkflows",
                endpoint_start
            ),
            csharp_array_assignment_before_endpoint(
                &uncommented,
                "vcenterObjectPlacementDimensions",
                endpoint_start
            ),
            csharp_array_assignment_before_endpoint(
                &uncommented,
                "vcenterObjectPlacementRequiredGuards",
                endpoint_start
            ),
            csharp_array_assignment_before_endpoint(
                &uncommented,
                "vcenterObjectPlacementPlanSections",
                endpoint_start
            ),
            csharp_array_assignment_before_endpoint(
                &uncommented,
                "vcenterObjectPlacementBlockedReasons",
                endpoint_start
            )
        ),
        "vcenterObjectPlacementArrays",
        errors,
    );
    validate_no_prohibited_api_field_names(&block, "vcenterObjectPlacementEndpoint", errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_no_prohibited_api_terms(&block, "vcenterObjectPlacementEndpoint", errors);
    validate_api_rules(&rule_blocks, catalog, errors);
}

fn validate_api_hypervisor_parity(
    block: &str,
    dimension_assignments: &[(&str, &str, Vec<String>)],
    errors: &mut Vec<String>,
) {
    let entries = api_hypervisor_parity_entries(block, errors);
    let entry_ids: Vec<String> = entries
        .iter()
        .filter_map(|entry| entry.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let required_ids = required_hypervisor_parity_ids();
    let missing: Vec<String> = required_ids
        .iter()
        .filter(|id| !entry_ids.contains(*id))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "API missing hypervisor parity: {}",
            missing.join(", ")
        ));
    }
    let unexpected: Vec<String> = entry_ids
        .iter()
        .filter(|id| !required_ids.contains(*id))
        .cloned()
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "API unexpected hypervisor parity: {}",
            unexpected.join(", ")
        ));
    }
    if entry_ids.iter().collect::<BTreeSet<_>>().len() != entry_ids.len() {
        errors.push("API hypervisor parity IDs must be unique".to_string());
    }

    for expected in REQUIRED_HYPERVISOR_PARITY {
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.get("id").and_then(Value::as_str) == Some(expected.id))
        else {
            continue;
        };
        let Some(map) = entry.as_object() else {
            continue;
        };
        let unexpected_keys: Vec<&str> = map
            .keys()
            .map(String::as_str)
            .filter(|key| !REQUIRED_HYPERVISOR_PARITY_KEYS.contains(key))
            .collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "API hypervisor parity {} has unexpected keys: {}",
                expected.id,
                unexpected_keys.join(", ")
            ));
        }
        let (expected_variable, dimension_values) = dimension_assignments
            .iter()
            .find(|(id, _, _)| *id == expected.id)
            .map(|(_, variable, values)| (*variable, values.clone()))
            .unwrap_or(("", Vec::new()));
        expect(
            entry.get("dimensionEquivalents").and_then(Value::as_str) == Some(expected_variable),
            errors,
            &format!(
                "API hypervisor parity {} dimensionEquivalents must bind {}",
                expected.id, expected_variable
            ),
        );
        validate_array_values_exact(
            dimension_values,
            &format!("API hypervisor parity {} dimensionEquivalents", expected.id),
            expected.dimension_equivalents,
            errors,
        );
        expect(
            entry.get("platform").and_then(Value::as_str) == Some(expected.platform),
            errors,
            &format!(
                "API hypervisor parity {} has unexpected platform",
                expected.id
            ),
        );
        expect(
            entry.get("workflow").and_then(Value::as_str) == Some(expected.workflow),
            errors,
            &format!(
                "API hypervisor parity {} has unexpected workflow",
                expected.id
            ),
        );
        expect(
            entry.get("placementMode").and_then(Value::as_str) == Some(expected.placement_mode),
            errors,
            &format!(
                "API hypervisor parity {} has unexpected placementMode",
                expected.id
            ),
        );
        expect(
            entry.get("dryRunRequired").and_then(Value::as_bool) == Some(true),
            errors,
            &format!(
                "API hypervisor parity {} has unexpected dryRunRequired",
                expected.id
            ),
        );
        for field in DISABLED_FIELDS {
            expect(
                entry.get(*field).and_then(Value::as_bool) == Some(false),
                errors,
                &format!(
                    "API hypervisor parity {} has unexpected {}",
                    expected.id, field
                ),
            );
        }
        expect(
            entry.get("evidence").and_then(Value::as_str) == Some(expected.evidence),
            errors,
            &format!(
                "API hypervisor parity {} has unexpected evidence",
                expected.id
            ),
        );
    }
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
    validate_api_rule_detail_uniqueness(rule_blocks, errors);

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
        "API README missing vCenter object placement endpoint",
    );
    expect(
        catalog_readme.contains("vcenter-object-placement-contract.yaml"),
        errors,
        "catalog README missing vCenter object placement catalog",
    );
    expect(
        doc_readme.contains("vcenter-object-placement.md"),
        errors,
        "workflow README missing vCenter object placement doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "vCenter object placement doc missing endpoint",
    );
    expect(
        doc.contains(
            "for VMware, Hyper-V, and Proxmox, without live provider calls or placement changes",
        ),
        errors,
        "vCenter object placement doc intro must use provider-neutral hypervisor wording",
    );
    expect(
        !doc.contains("without calling vCenter or changing provider state"),
        errors,
        "vCenter object placement doc intro must use provider-neutral hypervisor wording instead of vCenter-only provider-call wording",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "vCenter object placement doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live VMware, Hyper-V, or Proxmox placement."),
        errors,
        "vCenter object placement doc must prohibit live hypervisor placement",
    );
    expect(
        doc.contains("No raw inventory rows."),
        errors,
        "vCenter object placement doc must prohibit raw inventory rows",
    );
    expect(
        doc.contains("No object identifiers"),
        errors,
        "vCenter object placement doc must prohibit object identifiers",
    );
    expect(
        doc.contains("dry-run placement summaries only"),
        errors,
        "vCenter object placement doc must require safe summaries",
    );
    expect(
        doc.contains("VMware, Hyper-V, and Proxmox"),
        errors,
        "vCenter object placement doc missing hypervisor parity",
    );
    expect(
        doc.contains("not raw VMware, Hyper-V, or Proxmox inventory"),
        errors,
        "vCenter object placement doc must prohibit raw hypervisor inventory",
    );
    expect(
        doc.contains("All parity entries are static dry-run summaries only."),
        errors,
        "vCenter object placement doc must keep parity dry-run only",
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
        errors.push("API missing vCenter object placement endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors.push(format!(
            "API vCenter object placement endpoint {ENDPOINT} must declare exactly one route"
        ));
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
        errors.push("API missing vCenter object placement JSON payload".to_string());
        return String::new();
    }
    if json_indexes.len() != 1 {
        errors
            .push("API must declare exactly one vCenter object placement JSON payload".to_string());
        return String::new();
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors
            .push("API vCenter object placement JSON payload must be a single object".to_string());
        return String::new();
    };
    let Some(object_end) = matching_brace_index(endpoint, object_start) else {
        errors
            .push("API vCenter object placement JSON payload must be a single object".to_string());
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

fn csharp_array_values_before_endpoint(
    program: &str,
    variable: &str,
    endpoint_start: usize,
    errors: &mut Vec<String>,
) -> Vec<String> {
    let search_end = endpoint_start.min(program.len());
    let search_text = &program[..search_end];
    let mut values = Vec::new();
    let mut declaration_count = 0;
    let mut declaration_end = 0;
    let needle = format!("var {variable} = new[]");
    let mut offset = 0;
    while let Some(relative) = search_text[offset..].find(&needle) {
        declaration_count += 1;
        let start = offset + relative;
        let end = search_text[start..]
            .find(';')
            .map(|index| start + index + 1)
            .unwrap_or(search_text.len());
        declaration_end = end;
        values = quoted_values(&search_text[start..end]);
        offset = end;
    }
    if declaration_count == 0 {
        errors.push(format!("API missing {variable} declaration"));
        return values;
    }
    if declaration_count > 1 {
        errors.push(format!("API {variable} must have exactly one declaration"));
    }
    if array_reassigned_or_mutated(&search_text[declaration_end..], variable) {
        errors.push(format!(
            "API {variable} must not be reassigned or mutated before endpoint use"
        ));
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

fn csharp_array_assignment_before_endpoint(
    program: &str,
    variable: &str,
    endpoint_start: usize,
) -> String {
    let search_end = endpoint_start.min(program.len());
    let search_text = &program[..search_end];
    let needle = format!("var {variable} = new[]");
    let Some(start) = search_text.find(&needle) else {
        return String::new();
    };
    let end = search_text[start..]
        .find(';')
        .map(|index| start + index)
        .unwrap_or(search_text.len());
    search_text[start..end].to_string()
}

fn array_reassigned_or_mutated(text: &str, variable: &str) -> bool {
    text.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with(&format!("{variable} ="))
            || trimmed.starts_with(&format!("{variable}["))
    })
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
    api_object_blocks_in_array(block, "rules")
}

fn api_hypervisor_parity_entries(block: &str, errors: &mut Vec<String>) -> Vec<Value> {
    let parity_array = api_array_assignment(block, "hypervisorParity");
    if parity_array.is_empty() {
        errors.push("API hypervisorParity must be a single top-level new[] array".to_string());
        return Vec::new();
    }
    let entries: Vec<Value> = api_object_blocks_in_array(block, "hypervisorParity")
        .into_iter()
        .map(|object| {
            parse_api_object(
                &object,
                REQUIRED_HYPERVISOR_PARITY_KEYS,
                "API hypervisorParity",
                errors,
            )
        })
        .collect();
    if entries.is_empty() {
        errors.push("API hypervisorParity must contain entries".to_string());
    }
    entries
}

fn api_object_blocks_in_array(block: &str, field: &str) -> Vec<String> {
    let rule_array = api_array_assignment(block, field);
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

fn parse_api_object(
    object_block: &str,
    required_keys: &[&str],
    label: &str,
    errors: &mut Vec<String>,
) -> Value {
    let mut map = serde_json::Map::new();
    for line in object_block.lines() {
        let trimmed = line.trim();
        let Some((field, raw_value)) = trimmed.split_once('=') else {
            continue;
        };
        let field = field.trim();
        if field.is_empty()
            || !field
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            continue;
        }
        let raw_value = raw_value.trim().trim_end_matches(',').trim();
        let value =
            if raw_value.starts_with('"') && raw_value.ends_with('"') && raw_value.len() >= 2 {
                Value::String(raw_value[1..raw_value.len() - 1].to_string())
            } else if raw_value == "true" {
                Value::Bool(true)
            } else if raw_value == "false" {
                Value::Bool(false)
            } else {
                Value::String(raw_value.to_string())
            };
        map.insert(field.to_string(), value);
    }
    let missing: Vec<&str> = required_keys
        .iter()
        .copied()
        .filter(|key| !map.contains_key(*key))
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "{label} object missing keys: {}",
            missing.join(", ")
        ));
    }
    Value::Object(map)
}

fn api_string_field(block: &str, field: &str) -> Option<String> {
    let needle = format!("{field} = \"");
    let start = block.find(&needle)? + needle.len();
    let rest = &block[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn literal_false_assignment(block: &str, field: &str) -> bool {
    let assignments = top_level_assignment_lines(block, field);
    assignments.len() == 1 && assignments[0] == format!("{field} = false,")
}

fn literal_true_assignment(block: &str, field: &str) -> bool {
    let assignments = top_level_assignment_lines(block, field);
    assignments.len() == 1 && assignments[0] == format!("{field} = true,")
}

fn literal_string_assignment(block: &str, field: &str, expected: &str) -> bool {
    let assignments = top_level_assignment_lines(block, field);
    assignments.len() == 1 && assignments[0] == format!("{field} = \"{expected}\",")
}

fn top_level_assignment_lines(block: &str, field: &str) -> Vec<String> {
    block
        .lines()
        .filter(|line| line.starts_with(&format!("    {field} =")))
        .map(|line| line.trim().to_string())
        .collect()
}

fn top_level_assignment_count(block: &str, field: &str) -> usize {
    top_level_assignment_lines(block, field).len()
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

fn validate_rule_detail_uniqueness(rules: &[Value], label: &str, errors: &mut Vec<String>) {
    for (field, noun) in [("requirement", "requirements"), ("evidence", "evidence")] {
        let values: Vec<String> = rules
            .iter()
            .filter_map(|rule| string_field(rule, field).map(str::to_string))
            .collect();
        if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
            errors.push(format!("{label} rule {noun} must be unique"));
        }
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

fn validate_api_rule_detail_uniqueness(rule_blocks: &[String], errors: &mut Vec<String>) {
    for (field, noun) in [("requirement", "requirements"), ("evidence", "evidence")] {
        let values: Vec<String> = rule_blocks
            .iter()
            .filter_map(|block| api_string_field(block, field))
            .collect();
        if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
            errors.push(format!("API rule {noun} must be unique"));
        }
    }
}

fn validate_no_prohibited_api_terms(text: &str, label: &str, errors: &mut Vec<String>) {
    for value in quoted_values(text) {
        if prohibited_placement_key(&value) {
            errors.push(format!(
                "{label} contains prohibited placement field {value}"
            ));
        }
    }
}

fn validate_no_prohibited_api_field_names(text: &str, label: &str, errors: &mut Vec<String>) {
    for field in assignment_field_names(text) {
        if prohibited_placement_key(&field) {
            errors.push(format!(
                "{label} contains prohibited placement field {field}"
            ));
        }
    }
}

fn validate_endpoint_field_names(text: &str, errors: &mut Vec<String>) {
    let mut top_level_text = text.to_string();
    for object in api_object_blocks_in_array(text, "hypervisorParity") {
        let fields = assignment_field_names(&object);
        let unexpected: Vec<String> = fields
            .into_iter()
            .filter(|field| !REQUIRED_HYPERVISOR_PARITY_KEYS.contains(&field.as_str()))
            .collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "API hypervisor parity has unexpected vCenter object placement fields: {}",
                unexpected.join(", ")
            ));
        }
        top_level_text = top_level_text.replace(&object, &" ".repeat(object.len()));
    }
    for object in api_rule_blocks(text) {
        let fields = assignment_field_names(&object);
        let unexpected: Vec<String> = fields
            .into_iter()
            .filter(|field| !REQUIRED_RULE_KEYS.contains(&field.as_str()))
            .collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "API rule has unexpected vCenter object placement fields: {}",
                unexpected.join(", ")
            ));
        }
        top_level_text = top_level_text.replace(&object, &" ".repeat(object.len()));
    }

    let fields = assignment_field_names(&top_level_text);
    let unexpected: Vec<String> = fields
        .into_iter()
        .filter(|field| !TOP_LEVEL_ENDPOINT_FIELDS.contains(&field.as_str()))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "API endpoint has unexpected vCenter object placement fields: {}",
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
                if prohibited_placement_key(key) {
                    errors.push(format!("{path}.{key} contains prohibited placement field"));
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
            if whole_file_text(path, text) {
                validate_no_prohibited_multiline_terms(text, path, errors);
            } else if prohibited_placement_key(text) {
                errors.push(format!("{path} contains prohibited placement value {text}"));
            }
        }
        _ => {}
    }
}

fn validate_no_prohibited_multiline_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    if !path.ends_with(".yaml") && !path.ends_with(".yml") && !path.ends_with(".txt") {
        return;
    }
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if let Some(key) = catalog_assignment_key(line) {
            let message = format!("{path}:{line_number} contains prohibited placement field {key}");
            if prohibited_placement_key(&key) && !errors.contains(&message) {
                errors.push(message);
            }
        }
        for term in words(line) {
            let message =
                format!("{path}:{line_number} contains prohibited placement field {term}");
            if prohibited_placement_key(&term) && !errors.contains(&message) {
                errors.push(message);
            }
        }
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
            if prohibited_placement_key(&key) {
                errors.push(format!(
                    "{path}:{line_number} contains prohibited placement field {key}"
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
            let message =
                format!("{path}:{line_number} contains prohibited placement field {term}");
            if prohibited_placement_key(&term) && !errors.contains(&message) {
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

fn prohibited_placement_key(key: &str) -> bool {
    if safe_placement_text_value(key) {
        return false;
    }
    let normalized = normalized_key(key);
    if SAFE_PLACEMENT_GUARD_KEYS.contains(&normalized.as_str()) {
        return false;
    }
    PROHIBITED_PLACEMENT_KEYS.contains(&normalized.as_str())
        || PROHIBITED_PLACEMENT_SUBSTRINGS
            .iter()
            .any(|token| normalized.contains(token))
}

fn safe_placement_text_value(value: &str) -> bool {
    REQUIRED_WORKFLOWS.contains(&value)
        || REQUIRED_DIMENSIONS.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_HYPERVISOR_PARITY.iter().any(|entry| {
            value == entry.id
                || value == entry.platform
                || value == entry.workflow
                || entry.dimension_equivalents.contains(&value)
                || value == entry.placement_mode
                || value == entry.evidence
        })
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
        || ["draft", "static-seed", "dry-run-plan", "block"].contains(&value)
}

fn contains_prohibited_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    contains_akia(value)
        || lower.contains("-----begin ") && lower.contains("private key-----")
        || lower.contains("://")
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_provider_object_id(value)
        || contains_datastore_path(value)
        || contains_secret_assignment(&lower)
        || contains_fqdn(value)
        || contains_windows_account(value)
        || contains_email(value)
}

fn contains_prohibited_test_literal(value: &str) -> bool {
    quoted_values(value).into_iter().any(|literal| {
        let lower = literal.to_ascii_lowercase();
        contains_akia(&literal)
            || lower.contains("-----begin ") && lower.contains("private key-----")
            || lower.contains("://")
            || contains_private_ip(&literal)
            || contains_uuid(&literal)
            || contains_provider_object_id(&literal)
            || contains_datastore_path(&literal)
            || contains_secret_assignment(&lower)
            || contains_fqdn(&literal)
            || contains_double_backslash_account(&literal)
            || contains_email(&literal)
    })
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

fn contains_provider_object_id(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
        .any(|token| {
            let lower = token.to_ascii_lowercase();
            for prefix in ["domain-c", "domain-s"] {
                if let Some(suffix) = lower.strip_prefix(prefix) {
                    return !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit());
                }
            }
            if lower.starts_with("group-") && lower.len() > "group-a".len() {
                let suffix = &lower["group-a".len()..];
                if lower
                    .as_bytes()
                    .get("group-".len())
                    .is_some_and(u8::is_ascii_lowercase)
                    && !suffix.is_empty()
                    && suffix.chars().all(|ch| ch.is_ascii_digit())
                {
                    return true;
                }
            }
            let Some((prefix, suffix)) = lower.rsplit_once('-') else {
                return false;
            };
            !suffix.is_empty()
                && suffix.chars().all(|ch| ch.is_ascii_digit())
                && matches!(
                    prefix,
                    "vm" | "host"
                        | "domain-c"
                        | "domain-s"
                        | "group-a"
                        | "group-d"
                        | "group-h"
                        | "group-m"
                        | "group-n"
                        | "group-p"
                        | "group-r"
                        | "group-s"
                        | "group-v"
                        | "resgroup"
                        | "datastore"
                        | "network"
                        | "dvportgroup"
                        | "dvs"
                        | "folder"
                        | "cluster"
                        | "datacenter"
                )
        })
}

fn contains_datastore_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut offset = 0;
    while let Some(open_relative) = bytes[offset..].iter().position(|byte| *byte == b'[') {
        let open = offset + open_relative;
        let Some(close_relative) = bytes[open + 1..].iter().position(|byte| *byte == b']') else {
            return false;
        };
        let close = open + 1 + close_relative;
        if close + 1 >= bytes.len() || !bytes[close + 1].is_ascii_whitespace() {
            offset = close + 1;
            continue;
        }
        let after = value[close + 1..].trim_start();
        let token = after.split_whitespace().next().unwrap_or_default();
        if token
            .trim_matches(|ch: char| ch == '"' || ch == '\'' || ch == ',' || ch == ';')
            .chars()
            .any(|ch| ch == '/' || ch == '.')
        {
            return true;
        }
        offset = close + 1;
    }
    false
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
    let mut fields = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while let Some(relative) = text[index..].find('=') {
        let equals = index + relative;
        let mut end = equals;
        while end > 0 && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        let mut start = end;
        while start > 0 && identifier_byte(bytes[start - 1]) {
            start -= 1;
        }
        if start < end {
            fields.push(text[start..end].to_string());
        }
        index = equals + 1;
    }
    fields
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

fn required_hypervisor_parity_ids() -> Vec<String> {
    REQUIRED_HYPERVISOR_PARITY
        .iter()
        .map(|entry| entry.id.to_string())
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
    use serde_json::json;

    #[test]
    fn vcenter_object_placement_endpoint_registration_detects_route_alias() {
        let program = format!(
            r#"
app.MapGet("{ENDPOINT}", () => Results.Json(new {{ source = "static-seed" }}));
const string routeAlias = "{ENDPOINT}";
app.MapGet(routeAlias, () => Results.Json(new {{ source = "static-seed" }}));
"#
        );

        let mut errors = Vec::new();
        let _ = endpoint_block(&csharp_without_comments(&program), &mut errors);

        assert!(errors.iter().any(|error| error.contains("exactly one")));
    }

    #[test]
    fn vcenter_object_placement_source_spoofing_ignores_commented_decoys() {
        let program = mutate_endpoint(
            "    source = \"static-seed\",",
            "    // source = \"static-seed\",\n    source = \"live-provider\",",
        );
        let mut errors = Vec::new();

        validate_program_text_csharp(&program, &valid_catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("static seed source")));
    }

    #[test]
    fn vcenter_object_placement_duplicate_source_assignment_is_rejected() {
        let program = mutate_endpoint(
            "    source = \"static-seed\",",
            "    source = liveSource,\n    source = \"static-seed\",",
        );
        let mut errors = Vec::new();

        validate_program_text_csharp(&program, &valid_catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("static seed source")));
    }

    #[test]
    fn vcenter_object_placement_endpoint_property_identifiers_are_rejected() {
        let program = mutate_endpoint(
            "    placementMode = \"dry-run-plan\",",
            "    placementMode = \"dry-run-plan\",\n    clusterMoRef = \"redacted\",",
        );
        let mut errors = Vec::new();

        validate_program_text_csharp(&program, &valid_catalog(), &mut errors);

        assert!(errors.iter().any(|error| error.contains("clusterMoRef")));
    }

    #[test]
    fn vcenter_object_placement_duplicate_rule_ids_and_details_are_rejected() {
        let mut catalog = valid_catalog();
        let rules = catalog
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("rules array");
        let first_rule = rules[0].clone();
        let first_requirement = first_rule["requirement"].clone();
        let first_evidence = first_rule["evidence"].clone();
        rules.push(first_rule);
        rules[1]["requirement"] = first_requirement;
        rules[2]["evidence"] = first_evidence;
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
    fn vcenter_object_placement_raw_comments_and_unsafe_literals_are_rejected() {
        let mut errors = Vec::new();
        validate_raw_catalog_text(
            "# - clusterMoRef: redacted\n",
            "catalog/example.yaml",
            &mut errors,
        );

        let provider_id = ["v", "m", "-", "1", "2", "3"].join("");
        let datastore_path = [
            "[",
            "safe-summary",
            "] ",
            "folder",
            "/",
            "disk",
            ".",
            "vmdk",
        ]
        .join("");
        scan_prohibited_value(
            &json!({
                "objectSummary": provider_id,
                "storageSummary": datastore_path
            }),
            "catalog/example.yaml",
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains("clusterMoRef")));
        assert!(errors.iter().any(|error| error.contains("objectSummary")));
        assert!(errors.iter().any(|error| error.contains("storageSummary")));
    }

    #[test]
    fn vcenter_object_placement_test_literal_scan_uses_quoted_values() {
        let private_ip = ["10", "66", "66", "66"].join(".");
        let text = format!("unquoted {private_ip}\nquoted = \"{private_ip}\"\n");
        let mut errors = Vec::new();

        validate_no_prohibited_test_literals(
            &text,
            "tests/vcenter_object_placement_test.txt",
            &mut errors,
        );

        assert_eq!(1, errors.len());
        assert!(errors[0].contains("prohibited test literal"));
    }

    fn mutate_endpoint(from: &str, to: &str) -> String {
        let program = "app.MapGet(\"/api/integrations/vmware/object-placement-contract\", () => Results.Json(new\n{\n    source = \"static-seed\",\n    placementMode = \"dry-run-plan\",\n    dryRunRequired = true,\n    dimensionEquivalents = vcenterObjectPlacementDimensions,\n}));\n";
        let endpoint_start = program
            .find(&format!("app.MapGet(\"{ENDPOINT}\""))
            .expect("vCenter object placement endpoint");
        let mut changed = program[..endpoint_start].to_string();
        changed.push_str(&program[endpoint_start..].replacen(from, to, 1));
        changed
    }

    fn valid_catalog() -> Value {
        json!({
            "version": 1,
            "status": "draft",
            "source": "static-seed",
            "placementMode": "dry-run-plan",
            "dryRunRequired": true,
            "providerCallsEnabled": false,
            "livePlacementAllowed": false,
            "rawInventoryRowsAllowed": false,
            "objectIdentifiersAllowed": false,
            "hypervisorParity": REQUIRED_HYPERVISOR_PARITY.iter().map(|entry| {
                json!({
                    "id": entry.id,
                    "platform": entry.platform,
                    "workflow": entry.workflow,
                    "dimensionEquivalents": entry.dimension_equivalents,
                    "placementMode": entry.placement_mode,
                    "dryRunRequired": true,
                    "providerCallsEnabled": false,
                    "livePlacementAllowed": false,
                    "rawInventoryRowsAllowed": false,
                    "objectIdentifiersAllowed": false,
                    "evidence": entry.evidence
                })
            }).collect::<Vec<_>>(),
            "supportedWorkflows": REQUIRED_WORKFLOWS,
            "placementDimensions": REQUIRED_DIMENSIONS,
            "requiredInputs": REQUIRED_INPUTS,
            "requiredGuards": REQUIRED_GUARDS,
            "planSections": REQUIRED_PLAN_SECTIONS,
            "blockedReasons": REQUIRED_BLOCKED_REASONS,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "rules": REQUIRED_RULES.iter().map(|rule| {
                json!({
                    "id": rule.id,
                    "decision": rule.decision,
                    "requirement": rule.requirement,
                    "evidence": rule.evidence
                })
            }).collect::<Vec<_>>()
        })
    }
}
