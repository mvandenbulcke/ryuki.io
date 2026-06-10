use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/vm-decommission-quarantine-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/vm-decommission-quarantine.md";
const ENDPOINT: &str = "/api/integrations/vmware/decommission-quarantine-contract";

const REQUIRED_STAGES: &[&str] = &[
    "intake-review",
    "dependency-review",
    "backup-retention-review",
    "monitoring-disable-plan",
    "cmdb-retirement-plan",
    "quarantine-window-plan",
    "rollback-window-review",
    "final-disposition-review",
];
const REQUIRED_DOMAINS: &[&str] = &[
    "vcenter-placement",
    "backup-retention",
    "monitoring-state",
    "cmdb-state",
    "dns-dependency",
    "owner-approval",
    "rollback-window",
    "evidence-readiness",
];
const REQUIRED_INPUTS: &[&str] = &[
    "platformCiKey",
    "targetScope",
    "site",
    "environment",
    "owner",
    "businessJustification",
    "dependencyReview",
    "backupRetentionNeed",
    "quarantineWindow",
    "cmdbContext",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "request-preflight-ready",
    "cmdb-ci-known",
    "owner-approval-assigned",
    "dependency-impact-reviewed",
    "backup-retention-reviewed",
    "monitoring-disable-reviewed",
    "quarantine-window-approved",
    "rollback-plan-ready",
    "final-disposition-blocked",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "quarantineSummary",
    "dependencyReview",
    "backupRetentionReview",
    "monitoringPlan",
    "cmdbRetirementPlan",
    "quarantineWindow",
    "rollbackPlan",
    "finalDispositionHold",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-decommission-disabled",
    "live-delete-disabled",
    "raw-inventory-rows-disabled",
    "object-identifiers-disabled",
    "cmdb-ci-unknown",
    "owner-approval-missing",
    "dependency-review-missing",
    "backup-retention-missing",
    "monitoring-disable-review-missing",
    "quarantine-window-missing",
    "rollback-plan-missing",
    "final-disposition-blocked",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Quarantine summary",
    "Dependency review",
    "Backup retention review",
    "Monitoring disable plan",
    "CMDB retirement plan",
    "Quarantine window",
    "Rollback plan",
    "Final disposition hold",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveDecommissionAllowed",
    "liveDeletionAllowed",
    "rawInventoryRowsAllowed",
    "objectIdentifiersAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "quarantineMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveDecommissionAllowed",
    "liveDeletionAllowed",
    "rawInventoryRowsAllowed",
    "objectIdentifiersAllowed",
    "quarantineStages",
    "quarantineDomains",
    "hypervisorParityCoverage",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const HYPERVISOR_PARITY_KEYS: &[&str] = &[
    "platform",
    "placementReview",
    "dependencyReview",
    "backupReview",
    "monitoringReview",
    "retirementReview",
    "executionBoundary",
    "evidenceBoundary",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("quarantineStages", "vmDecommissionQuarantineStages"),
    ("quarantineDomains", "vmDecommissionQuarantineDomains"),
    ("requiredGuards", "vmDecommissionQuarantineRequiredGuards"),
    ("planSections", "vmDecommissionQuarantinePlanSections"),
    ("blockedReasons", "vmDecommissionQuarantineBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const SAFE_RAW_CATALOG_COMMENTS: &[&str] = &[
    "VM decommission quarantine seed data only. Do not add VM names, hostnames, usernames, credentials, tokens, tenant IDs, object IDs, MoRefs, UUIDs, endpoints, private IPs, raw inventory rows, datastore paths, serials, asset tags, raw logs, or provider payloads.",
];
const PROHIBITED_FIELD_TOKENS: &[&str] = &[
    "vmname",
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
    "dnsrecord",
];

const REQUIRED_HYPERVISOR_PARITY: &[HypervisorParityRef] = &[
    HypervisorParityRef {
        platform: "vmware",
        placement_review: "vcenter-placement-review",
        dependency_review: "dependency-review",
        backup_review: "backup-retention-review",
        monitoring_review: "monitoring-disable-plan",
        retirement_review: "cmdb-retirement-plan",
        execution_boundary: "dry-run-plan-only",
        evidence_boundary: "safe-summary-only",
    },
    HypervisorParityRef {
        platform: "hyper-v",
        placement_review: "failover-cluster-placement-review",
        dependency_review: "dependency-review",
        backup_review: "backup-retention-review",
        monitoring_review: "monitoring-disable-plan",
        retirement_review: "cmdb-retirement-plan",
        execution_boundary: "dry-run-plan-only",
        evidence_boundary: "safe-summary-only",
    },
    HypervisorParityRef {
        platform: "proxmox",
        placement_review: "cluster-node-placement-review",
        dependency_review: "dependency-review",
        backup_review: "backup-retention-review",
        monitoring_review: "monitoring-disable-plan",
        retirement_review: "cmdb-retirement-plan",
        execution_boundary: "dry-run-plan-only",
        evidence_boundary: "safe-summary-only",
    },
];

const REQUIRED_RULES: &[RuleRef] = &[
    RuleRef {
        id: "no-live-vm-decommission",
        decision: "block",
        requirement: "VM decommission quarantine produces dry-run plans only and never moves, tags, disables, deletes, or retires live infrastructure records.",
        evidence: "Quarantine summary",
    },
    RuleRef {
        id: "backup-retention-required",
        decision: "block",
        requirement: "Backup retention need and recovery expectations must be reviewed before any quarantine window can be approved.",
        evidence: "Backup retention review",
    },
    RuleRef {
        id: "dependency-review-required",
        decision: "block",
        requirement: "Application, DNS, monitoring, backup, and CMDB dependencies must be reviewed before quarantine planning continues.",
        evidence: "Dependency review",
    },
    RuleRef {
        id: "monitoring-cmdb-plan-required",
        decision: "block",
        requirement: "Monitoring disablement and CMDB retirement must be represented as review plans only until separate live change approval exists.",
        evidence: "Monitoring disable plan",
    },
    RuleRef {
        id: "final-delete-blocked",
        decision: "block",
        requirement: "Final disposition remains blocked in this contract; deletion requires a later separately approved execution workflow.",
        evidence: "Final disposition hold",
    },
    RuleRef {
        id: "raw-vm-inventory-not-exposed",
        decision: "block",
        requirement: "Quarantine evidence must use safe summaries only and must not expose raw VM inventory rows, object identifiers, endpoint names, hostnames, datastore paths, serials, or provider payloads.",
        evidence: "Evidence references",
    },
];

#[derive(Deserialize)]
struct ValidationContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    #[serde(default)]
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
}

#[derive(Clone, Copy)]
struct RuleRef {
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

#[derive(Clone, Copy)]
struct HypervisorParityRef {
    platform: &'static str,
    placement_review: &'static str,
    dependency_review: &'static str,
    backup_review: &'static str,
    monitoring_review: &'static str,
    retirement_review: &'static str,
    execution_boundary: &'static str,
    evidence_boundary: &'static str,
}

#[derive(Clone)]
struct HypervisorParity {
    platform: String,
    placement_review: String,
    dependency_review: String,
    backup_review: String,
    monitoring_review: String,
    retirement_review: String,
    execution_boundary: String,
    evidence_boundary: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ValidationContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid VM decommission quarantine context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_raw_catalog_text(&context.catalog_text, CATALOG_PATH, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.program), PROGRAM_PATH, &mut errors);
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
    // test removed: Ruby file no longer exists

    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid VM decommission quarantine catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid VM decommission quarantine program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid VM decommission quarantine docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid VM decommission quarantine prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    if payload
        .value
        .as_str()
        .is_some_and(|text| text.contains('\n'))
    {
        scan_raw_catalog_text(
            payload.value.as_str().unwrap_or_default(),
            &payload.path,
            &mut errors,
        );
    }
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("VM decommission quarantine catalog must be a mapping".to_string());
        return;
    };

    let actual_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected_keys: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "VM decommission quarantine unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }

    expect(
        value_i64(catalog, "version") == Some(1),
        errors,
        "VM decommission quarantine version must be 1",
    );
    expect(
        value_str(catalog, "status") == Some("draft"),
        errors,
        "VM decommission quarantine status must be draft",
    );
    expect(
        value_str(catalog, "source") == Some("static-seed"),
        errors,
        "VM decommission quarantine source must be static-seed",
    );
    expect(
        value_str(catalog, "quarantineMode") == Some("dry-run-plan"),
        errors,
        "VM decommission quarantine mode must be dry-run-plan",
    );
    expect(
        value_bool(catalog, "dryRunRequired") == Some(true),
        errors,
        "VM decommission quarantine must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            value_bool(catalog, field) == Some(false),
            errors,
            format!("VM decommission quarantine {field} must be disabled"),
        );
    }

    validate_required_array(catalog, "quarantineStages", REQUIRED_STAGES, errors);
    validate_required_array(catalog, "quarantineDomains", REQUIRED_DOMAINS, errors);
    validate_hypervisor_parity_shape(catalog.get("hypervisorParityCoverage"), "catalog", errors);
    validate_hypervisor_parity(
        catalog_hypervisor_parity(catalog),
        "hypervisorParityCoverage",
        errors,
    );
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_no_unsafe_true_values(catalog, "catalog", errors);
    validate_required_rules(catalog, errors);
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
        format!("{field} must be non-empty array"),
    );
    let required: BTreeSet<String> = required_values
        .iter()
        .map(|value| value.to_string())
        .collect();
    let actual: BTreeSet<String> = values.iter().cloned().collect();
    let missing: Vec<String> = required.difference(&actual).cloned().collect();
    let unexpected: Vec<String> = actual.difference(&required).cloned().collect();
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
        format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited quarantine field {value}"
            ));
        }
    }
}

fn validate_hypervisor_parity_shape(value: Option<&Value>, label: &str, errors: &mut Vec<String>) {
    let Some(values) = value.and_then(Value::as_array) else {
        errors.push(format!("{label} must be non-empty array"));
        return;
    };
    let expected_keys: BTreeSet<&str> = HYPERVISOR_PARITY_KEYS.iter().copied().collect();
    for entry in values {
        let Some(object) = entry.as_object() else {
            errors.push(format!("{label} entries must be objects"));
            continue;
        };
        let platform = object
            .get("platform")
            .and_then(Value::as_str)
            .unwrap_or("(missing platform)");
        let actual_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        let unexpected: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "hypervisor parity {platform} has unexpected keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "hypervisor parity {platform} missing keys: {}",
                missing.join(", ")
            ));
        }
    }
}

fn catalog_hypervisor_parity(catalog: &Value) -> Option<Vec<HypervisorParity>> {
    Some(
        catalog
            .get("hypervisorParityCoverage")?
            .as_array()?
            .iter()
            .filter_map(|entry| {
                Some(HypervisorParity {
                    platform: value_str_direct(entry, "platform")?.to_string(),
                    placement_review: value_str_direct(entry, "placementReview")?.to_string(),
                    dependency_review: value_str_direct(entry, "dependencyReview")?.to_string(),
                    backup_review: value_str_direct(entry, "backupReview")?.to_string(),
                    monitoring_review: value_str_direct(entry, "monitoringReview")?.to_string(),
                    retirement_review: value_str_direct(entry, "retirementReview")?.to_string(),
                    execution_boundary: value_str_direct(entry, "executionBoundary")?.to_string(),
                    evidence_boundary: value_str_direct(entry, "evidenceBoundary")?.to_string(),
                })
            })
            .collect(),
    )
}

fn validate_hypervisor_parity(
    values: Option<Vec<HypervisorParity>>,
    label: &str,
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("{label} must be non-empty array"));
        return;
    };
    if values.is_empty() {
        errors.push(format!("{label} must be non-empty array"));
    }
    let platforms: Vec<String> = values.iter().map(|entry| entry.platform.clone()).collect();
    let expected: BTreeSet<String> = REQUIRED_HYPERVISOR_PARITY
        .iter()
        .map(|entry| entry.platform.to_string())
        .collect();
    let actual: BTreeSet<String> = platforms.iter().cloned().collect();
    let missing: Vec<String> = expected.difference(&actual).cloned().collect();
    let unexpected: Vec<String> = actual.difference(&expected).cloned().collect();
    if !missing.is_empty() {
        errors.push(format!("{label} missing platforms: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{label} unexpected platforms: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        platforms.len() == actual.len(),
        errors,
        format!("{label} platforms must be unique"),
    );

    for expected_entry in REQUIRED_HYPERVISOR_PARITY {
        let Some(entry) = values
            .iter()
            .find(|candidate| candidate.platform == expected_entry.platform)
        else {
            continue;
        };
        expect(
            entry.placement_review == expected_entry.placement_review,
            errors,
            format!(
                "hypervisor parity {} has unexpected placementReview",
                expected_entry.platform
            ),
        );
        expect(
            entry.dependency_review == expected_entry.dependency_review,
            errors,
            format!(
                "hypervisor parity {} has unexpected dependencyReview",
                expected_entry.platform
            ),
        );
        expect(
            entry.backup_review == expected_entry.backup_review,
            errors,
            format!(
                "hypervisor parity {} has unexpected backupReview",
                expected_entry.platform
            ),
        );
        expect(
            entry.monitoring_review == expected_entry.monitoring_review,
            errors,
            format!(
                "hypervisor parity {} has unexpected monitoringReview",
                expected_entry.platform
            ),
        );
        expect(
            entry.retirement_review == expected_entry.retirement_review,
            errors,
            format!(
                "hypervisor parity {} has unexpected retirementReview",
                expected_entry.platform
            ),
        );
        expect(
            entry.execution_boundary == expected_entry.execution_boundary,
            errors,
            format!(
                "hypervisor parity {} has unexpected executionBoundary",
                expected_entry.platform
            ),
        );
        expect(
            entry.evidence_boundary == expected_entry.evidence_boundary,
            errors,
            format!(
                "hypervisor parity {} has unexpected evidenceBoundary",
                expected_entry.platform
            ),
        );
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| value_str_direct(rule, "id").map(str::to_string))
        .collect();
    let expected: BTreeSet<String> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id.to_string())
        .collect();
    let actual: BTreeSet<String> = rule_ids.iter().cloned().collect();
    let missing: Vec<String> = expected.difference(&actual).cloned().collect();
    let unexpected: Vec<String> = actual.difference(&expected).cloned().collect();
    if !missing.is_empty() {
        errors.push(format!(
            "VM decommission quarantine missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "VM decommission quarantine unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.len() == actual.len(),
        errors,
        "VM decommission quarantine rule IDs must be unique",
    );

    let expected_rule_keys: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
    let mut detail_keys = Vec::new();
    for rule in &rules {
        let label = value_str_direct(rule, "id").unwrap_or("(missing id)");
        let Some(object) = rule.as_object() else {
            errors.push(format!(
                "VM decommission quarantine rule {label} must be a mapping"
            ));
            continue;
        };
        let actual_rule_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        let unexpected_rule_keys: Vec<&str> = actual_rule_keys
            .difference(&expected_rule_keys)
            .copied()
            .collect();
        if !unexpected_rule_keys.is_empty() {
            errors.push(format!(
                "VM decommission quarantine rule {label} has unexpected keys: {}",
                unexpected_rule_keys.join(", ")
            ));
        }
        validate_no_unsafe_true_values(rule, &format!("rule {label}"), errors);
        detail_keys.push(format!(
            "{}|{}|{}",
            value_str_direct(rule, "decision").unwrap_or_default(),
            value_str_direct(rule, "requirement").unwrap_or_default(),
            value_str_direct(rule, "evidence").unwrap_or_default()
        ));
    }
    let detail_set: BTreeSet<String> = detail_keys.iter().cloned().collect();
    expect(
        detail_keys.len() == detail_set.len(),
        errors,
        "VM decommission quarantine rule details must be unique",
    );

    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| value_str_direct(candidate, "id") == Some(expected_rule.id))
        else {
            continue;
        };
        expect(
            value_str_direct(rule, "decision") == Some(expected_rule.decision),
            errors,
            format!(
                "VM decommission quarantine rule {} has unexpected decision",
                expected_rule.id
            ),
        );
        expect(
            value_str_direct(rule, "requirement") == Some(expected_rule.requirement),
            errors,
            format!(
                "VM decommission quarantine rule {} has unexpected requirement",
                expected_rule.id
            ),
        );
        expect(
            value_str_direct(rule, "evidence") == Some(expected_rule.evidence),
            errors,
            format!(
                "VM decommission quarantine rule {} has unexpected evidence",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let block = endpoint_block(&uncommented_program, errors);
    if block.is_empty() {
        return;
    }

    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static seed source",
    );
    expect(
        exact_string_assignment(&block, "quarantineMode", "dry-run-plan"),
        errors,
        "API must keep dry-run quarantine mode",
    );
    expect(
        exact_endpoint_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    validate_hypervisor_parity_shape_from_api(&block, errors);
    validate_hypervisor_parity(
        endpoint_hypervisor_parity(&block, "API", errors),
        "API hypervisorParityCoverage",
        errors,
    );
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            format!("API endpoint missing {field} field"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array(catalog.get(*field)),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            string_array(catalog.get(*field)),
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
    expected_values: Vec<String>,
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let expected: BTreeSet<String> = expected_values.iter().cloned().collect();
    let actual: BTreeSet<String> = values.iter().cloned().collect();
    let missing: Vec<String> = expected.difference(&actual).cloned().collect();
    let unexpected: Vec<String> = actual.difference(&expected).cloned().collect();
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
        format!("API {field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited quarantine field {value}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = api_rules(block);
    let catalog_rules = catalog_rules(catalog);
    let api_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let catalog_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_set: BTreeSet<String> = api_ids.iter().cloned().collect();
    let catalog_set: BTreeSet<String> = catalog_ids.iter().cloned().collect();
    for id in catalog_set.difference(&api_set) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_set.difference(&catalog_set) {
        errors.push(format!("API unexpected rules: {id}"));
    }
    expect(
        api_ids.len() == api_set.len(),
        errors,
        "API rule IDs must be unique",
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
            format!("API missing rule requirement {}", catalog_rule.id),
        );
        expect(
            api_rule.evidence == catalog_rule.evidence,
            errors,
            format!("API rule {} has wrong evidence", catalog_rule.id),
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
        "API README missing VM decommission quarantine endpoint",
    );
    expect(
        catalog_readme.contains("vm-decommission-quarantine-contract.yaml"),
        errors,
        "catalog README missing VM decommission quarantine catalog",
    );
    expect(
        doc_readme.contains("vm-decommission-quarantine.md"),
        errors,
        "workflow README missing VM decommission quarantine doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "VM decommission quarantine doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "VM decommission quarantine doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live VM decommission"),
        errors,
        "VM decommission quarantine doc must prohibit live decommission",
    );
    expect(
        doc.contains("No raw inventory rows."),
        errors,
        "VM decommission quarantine doc must prohibit raw inventory rows",
    );
    expect(
        doc.contains("No VM names"),
        errors,
        "VM decommission quarantine doc must prohibit VM identifiers",
    );
    expect(
        doc.contains("dry-run quarantine summaries only"),
        errors,
        "VM decommission quarantine doc must require dry-run summaries",
    );
    expect(
        doc.contains("not raw VMware, Hyper-V, Proxmox, or provider inventory"),
        errors,
        "VM decommission quarantine doc must prohibit raw hypervisor inventory",
    );
    expect(
        doc.contains("VMware, Hyper-V, and Proxmox"),
        errors,
        "VM decommission quarantine doc missing hypervisor parity",
    );
}

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(uncommented_program);
    if starts.is_empty() {
        errors.push("API missing VM decommission quarantine endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors.push(format!(
            "API {ENDPOINT} endpoint must be declared exactly one time"
        ));
        return String::new();
    }
    let start_index = starts[0];
    let next_index =
        next_endpoint_index(uncommented_program, start_index).unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_index].to_string()
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

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    line_start_indexes(&program[start_index + 1..])
        .into_iter()
        .map(|index| start_index + 1 + index)
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

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    block.lines().any(|line| line.trim() == expected)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    block.lines().any(|line| line.trim() == expected)
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[]");
    let start = program.find(&marker)?;
    let open = program[start..].find('{').map(|index| start + index)?;
    let close = program[open..].find("};").map(|index| open + index)?;
    Some(csharp_string_literals(&program[open + 1..close]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[]");
    let start = block.find(&marker)?;
    let open = block[start..].find('{').map(|index| start + index)?;
    let close = matching_brace(block, open)?;
    Some(csharp_string_literals(&block[open + 1..close]))
}

fn validate_hypervisor_parity_shape_from_api(block: &str, errors: &mut Vec<String>) {
    let Some((_, body)) = object_array_span(block, "hypervisorParityCoverage") else {
        errors.push(
            "API hypervisorParityCoverage must be a single top-level new[] array".to_string(),
        );
        return;
    };
    let expected_keys: BTreeSet<&str> = HYPERVISOR_PARITY_KEYS.iter().copied().collect();
    for object_body in object_array_entries(body) {
        let fields: BTreeSet<String> = assignment_fields(&object_body).into_iter().collect();
        let refs: BTreeSet<&str> = fields.iter().map(String::as_str).collect();
        let label = quoted_assignment(&object_body, "platform")
            .unwrap_or_else(|| "(missing platform)".to_string());
        let unexpected: Vec<&str> = refs.difference(&expected_keys).copied().collect();
        let missing: Vec<&str> = expected_keys.difference(&refs).copied().collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "API hypervisor parity {label} has unexpected keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "API hypervisorParityCoverage object missing keys: {}",
                missing.join(", ")
            ));
        }
    }
}

fn endpoint_hypervisor_parity(
    block: &str,
    source: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<HypervisorParity>> {
    let Some((_, body)) = object_array_span(block, "hypervisorParityCoverage") else {
        errors.push(format!(
            "{source} hypervisorParityCoverage must be a single top-level new[] array"
        ));
        return None;
    };
    let entries: Vec<HypervisorParity> = object_array_entries(body)
        .into_iter()
        .filter_map(|object_body| {
            Some(HypervisorParity {
                platform: quoted_assignment(&object_body, "platform")?,
                placement_review: quoted_assignment(&object_body, "placementReview")?,
                dependency_review: quoted_assignment(&object_body, "dependencyReview")?,
                backup_review: quoted_assignment(&object_body, "backupReview")?,
                monitoring_review: quoted_assignment(&object_body, "monitoringReview")?,
                retirement_review: quoted_assignment(&object_body, "retirementReview")?,
                execution_boundary: quoted_assignment(&object_body, "executionBoundary")?,
                evidence_boundary: quoted_assignment(&object_body, "evidenceBoundary")?,
            })
        })
        .collect();
    if entries.is_empty() {
        errors.push(format!(
            "{source} hypervisorParityCoverage must contain entries"
        ));
    }
    Some(entries)
}

fn api_rules(block: &str) -> Vec<Rule> {
    let Some((_, body)) = object_array_span(block, "rules") else {
        return Vec::new();
    };
    object_array_entries(body)
        .into_iter()
        .filter_map(|object_body| {
            Some(Rule {
                id: quoted_assignment(&object_body, "id")?,
                decision: quoted_assignment(&object_body, "decision")?,
                requirement: quoted_assignment(&object_body, "requirement")?,
                evidence: quoted_assignment(&object_body, "evidence")?,
            })
        })
        .collect()
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            Some(Rule {
                id: value_str_direct(rule, "id")?.to_string(),
                decision: value_str_direct(rule, "decision")?.to_string(),
                requirement: value_str_direct(rule, "requirement")?.to_string(),
                evidence: value_str_direct(rule, "evidence")?.to_string(),
            })
        })
        .collect()
}

fn object_array_span<'a>(block: &'a str, field: &str) -> Option<(usize, &'a str)> {
    let marker = format!("{field} = new[]");
    let start = block.find(&marker)?;
    let open = block[start..].find('{').map(|index| start + index)?;
    let close = matching_brace(block, open)?;
    Some((open, &block[open + 1..close]))
}

fn object_array_entries(body: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while let Some(relative) = body[offset..].find("new") {
        let start = offset + relative;
        let open = skip_ascii_whitespace(body, start + "new".len());
        if body.as_bytes().get(open) != Some(&b'{') {
            offset = start + "new".len();
            continue;
        }
        let Some(close) = matching_brace(body, open) else {
            break;
        };
        entries.push(body[open + 1..close].to_string());
        offset = close + 1;
    }
    entries
}

fn quoted_assignment(text: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = text.find(&marker)? + marker.len();
    let tail = &text[start..];
    let mut value = String::new();
    let mut escape = false;
    for ch in tail.chars() {
        if escape {
            value.push(ch);
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else if ch == '"' {
            return Some(value);
        } else {
            value.push(ch);
        }
    }
    None
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let fields = assignment_fields(&strip_csharp_string_literals(block));
    let allowed: BTreeSet<&str> = [
        "source",
        "quarantineMode",
        "dryRunRequired",
        "hypervisorParityCoverage",
        "quarantineStages",
        "quarantineDomains",
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
    ]
    .into_iter()
    .chain(REQUIRED_DISABLED_FIELDS.iter().copied())
    .chain(HYPERVISOR_PARITY_KEYS.iter().copied())
    .collect();
    let actual: BTreeSet<String> = fields.iter().cloned().collect();
    let unexpected: Vec<String> = actual
        .iter()
        .filter(|field| !allowed.contains(field.as_str()))
        .cloned()
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "API endpoint has unexpected VM decommission quarantine fields: {}",
            unexpected.join(", ")
        ));
    }
    for field in fields {
        if !safe_text_value(&field) && prohibited_field(&field) {
            errors.push(format!(
                "vmDecommissionQuarantineEndpoint contains prohibited quarantine field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(text: &str, errors: &mut Vec<String>) {
    for (field, value) in assignment_values(text) {
        if value == "true" && unsafe_flag_name(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_no_unsafe_true_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if child.as_bool() == Some(true) && unsafe_flag_name(key) {
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

fn unsafe_flag_name(field: &str) -> bool {
    let lowered = field.to_ascii_lowercase();
    [
        "live",
        "provider",
        "execution",
        "action",
        "remediation",
        "delete",
        "decommission",
    ]
    .iter()
    .any(|token| lowered.contains(token))
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if !safe_text_value(key) && prohibited_field(key) {
                    errors.push(format!("{path}.{key} contains prohibited quarantine field"));
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
                for (index, line) in text.lines().enumerate() {
                    if vm_decommission_text_line(path, line) && prohibited_literal(line) {
                        errors.push(format!("{path}:{} contains prohibited value", index + 1));
                    }
                }
                return;
            }
            if prohibited_literal(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if !safe_text_value(text) && prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited quarantine value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn scan_raw_catalog_text(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if prohibited_literal(line) {
            errors.push(format!("{path}:{line_number} contains prohibited value"));
        }
        for key in assignment_like_keys(line) {
            if !safe_text_value(&key) && prohibited_field(&key) {
                errors.push(format!(
                    "{path}:{line_number} contains prohibited quarantine field {key}"
                ));
            }
        }
        let Some(comment) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let comment = comment.trim();
        if comment.is_empty() || SAFE_RAW_CATALOG_COMMENTS.contains(&comment) {
            continue;
        }
        for term in identifier_terms(comment.trim_start_matches("- ")) {
            if !safe_text_value(&term) && prohibited_field(&term) {
                let message =
                    format!("{path}:{line_number} contains prohibited quarantine field {term}");
                if !errors.contains(&message) {
                    errors.push(message);
                }
            }
        }
    }
}

fn scan_test_literals(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if prohibited_literal(line) {
            errors.push(format!(
                "{path}:{} contains prohibited test literal",
                index + 1
            ));
        }
    }
}

fn prohibited_literal(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin ") && lower.contains("private key-----")
        || lower.contains("akia")
        || has_url_scheme(value)
        || has_private_ip(value)
        || has_uuid(value)
        || has_provider_identifier(value)
        || has_datastore_path(value)
        || has_credential_assignment(value)
        || has_fqdn(value)
        || has_domain_user(value)
        || has_email(value)
}

fn has_url_scheme(value: &str) -> bool {
    value.find("://").is_some_and(|index| {
        index > 0
            && value[..index]
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
            && value[..index]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
    })
}

fn has_private_ip(value: &str) -> bool {
    normalized_tokens(value).into_iter().any(|token| {
        let octets: Vec<&str> = token.split('.').collect();
        if octets.len() != 4 {
            return false;
        }
        let parsed: Option<Vec<u8>> = octets.iter().map(|part| part.parse::<u8>().ok()).collect();
        let Some(parsed) = parsed else {
            return false;
        };
        parsed[0] == 10
            || (parsed[0] == 192 && parsed[1] == 168)
            || (parsed[0] == 172 && (16..=31).contains(&parsed[1]))
    })
}

fn has_uuid(value: &str) -> bool {
    normalized_tokens(value).into_iter().any(|token| {
        let parts: Vec<&str> = token.split('-').collect();
        parts.len() == 5
            && [8, 4, 4, 4, 12]
                .into_iter()
                .zip(parts.iter())
                .all(|(length, part)| {
                    part.len() == length && part.chars().all(|ch| ch.is_ascii_hexdigit())
                })
    })
}

fn has_provider_identifier(value: &str) -> bool {
    normalized_tokens(value).into_iter().any(|token| {
        let lower = token.to_ascii_lowercase();
        [
            "vm",
            "host",
            "domain-c",
            "domain-s",
            "group",
            "resgroup",
            "datastore",
            "network",
            "dvportgroup",
            "dvs",
            "folder",
            "cluster",
            "datacenter",
        ]
        .iter()
        .any(|prefix| {
            lower.strip_prefix(prefix).is_some_and(|rest| {
                let rest = rest.strip_prefix('-').unwrap_or(rest);
                !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit())
            })
        })
    })
}

fn has_datastore_path(value: &str) -> bool {
    value.split('[').skip(1).any(|tail| {
        let Some((name, rest)) = tail.split_once(']') else {
            return false;
        };
        !name.trim().is_empty()
            && rest.trim_start().contains('/')
            && name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ' '))
    })
}

fn has_credential_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|key| {
        lower.contains(key)
            && (lower.contains(':') || lower.contains('='))
            && lower
                .split([':', '='])
                .nth(1)
                .is_some_and(|tail| !tail.trim().is_empty())
    })
}

fn has_fqdn(value: &str) -> bool {
    normalized_tokens(value).into_iter().any(|token| {
        let lower = token.to_ascii_lowercase();
        lower.matches('.').count() >= 2
            && lower.split('.').all(|part| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            })
    })
}

fn has_domain_user(value: &str) -> bool {
    value.contains('\\')
        && value.split('\\').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        })
}

fn has_email(value: &str) -> bool {
    normalized_tokens(value).into_iter().any(|token| {
        let lower = token.to_ascii_lowercase();
        let Some((local, domain)) = lower.split_once('@') else {
            return false;
        };
        !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
    })
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_normalized(&normalized) {
        return false;
    }
    PROHIBITED_FIELD_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
}

fn safe_text_value(value: &str) -> bool {
    REQUIRED_STAGES.contains(&value)
        || REQUIRED_DOMAINS.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || REQUIRED_CATALOG_KEYS.contains(&value)
        || RULE_KEYS.contains(&value)
        || HYPERVISOR_PARITY_KEYS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || matches!(
            value,
            "draft" | "static-seed" | "dry-run-plan" | "block" | "true" | "false"
        )
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
        || REQUIRED_HYPERVISOR_PARITY.iter().any(|entry| {
            value == entry.platform
                || value == entry.placement_review
                || value == entry.dependency_review
                || value == entry.backup_review
                || value == entry.monitoring_review
                || value == entry.retirement_review
                || value == entry.execution_boundary
                || value == entry.evidence_boundary
        })
}

fn safe_text_normalized(value: &str) -> bool {
    safe_text_value(value)
        || [
            "providercallsenabled",
            "livedecommissionallowed",
            "livedeletionallowed",
            "objectidentifiersallowed",
            "objectidentifiersdisabled",
            "rawinventoryrowsallowed",
            "rawinventoryrowsdisabled",
        ]
        .contains(&value)
        || REQUIRED_STAGES
            .iter()
            .any(|entry| normalize(entry) == value)
        || REQUIRED_DOMAINS
            .iter()
            .any(|entry| normalize(entry) == value)
        || REQUIRED_INPUTS
            .iter()
            .any(|entry| normalize(entry) == value)
        || REQUIRED_GUARDS
            .iter()
            .any(|entry| normalize(entry) == value)
        || REQUIRED_PLAN_SECTIONS
            .iter()
            .any(|entry| normalize(entry) == value)
        || REQUIRED_BLOCKED_REASONS
            .iter()
            .any(|entry| normalize(entry) == value)
        || REQUIRED_EVIDENCE
            .iter()
            .any(|entry| normalize(entry) == value)
        || REQUIRED_RULES.iter().any(|rule| {
            normalize(rule.id) == value
                || normalize(rule.decision) == value
                || normalize(rule.requirement) == value
                || normalize(rule.evidence) == value
        })
        || REQUIRED_HYPERVISOR_PARITY.iter().any(|entry| {
            normalize(entry.platform) == value
                || normalize(entry.placement_review) == value
                || normalize(entry.dependency_review) == value
                || normalize(entry.backup_review) == value
                || normalize(entry.monitoring_review) == value
                || normalize(entry.retirement_review) == value
                || normalize(entry.execution_boundary) == value
                || normalize(entry.evidence_boundary) == value
        })
}

fn assignment_fields(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut fields = Vec::new();
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
        if probe < chars.len() && chars[probe] == '=' && chars.get(probe + 1) != Some(&'=') {
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

fn csharp_string_literals(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        if chars[index] != '"' {
            index += 1;
            continue;
        }
        index += 1;
        let mut value = String::new();
        let mut escape = false;
        while index < chars.len() {
            let ch = chars[index];
            index += 1;
            if escape {
                value.push(ch);
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                values.push(value);
                break;
            } else {
                value.push(ch);
            }
        }
    }
    values
}

fn strip_csharp_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '/' && chars.peek() == Some(&'/') {
            out.push(' ');
            out.push(' ');
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
                out.push(' ');
            }
        } else if ch == '/' && chars.peek() == Some(&'*') {
            out.push(' ');
            out.push(' ');
            chars.next();
            let mut previous = '\0';
            for next in chars.by_ref() {
                out.push(if next == '\n' { '\n' } else { ' ' });
                if previous == '*' && next == '/' {
                    break;
                }
                previous = next;
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn strip_csharp_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escape = false;
    for ch in text.chars() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
                out.push('"');
            } else {
                out.push(' ');
            }
        } else if ch == '"' {
            in_string = true;
            out.push('"');
        } else {
            out.push(ch);
        }
    }
    out
}

fn matching_brace(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open) != Some(&b'{') {
        return None;
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (offset, ch) in text[open..].char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
        } else if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                return Some(open + offset);
            }
        }
    }
    None
}

fn assignment_like_keys(line: &str) -> Vec<String> {
    let stripped = line
        .trim_start()
        .strip_prefix('#')
        .unwrap_or(line)
        .trim_start()
        .strip_prefix("- ")
        .unwrap_or_else(|| {
            line.trim_start()
                .strip_prefix('#')
                .unwrap_or(line)
                .trim_start()
        });
    let Some((key, _)) = stripped
        .split_once(':')
        .or_else(|| stripped.split_once('='))
    else {
        return Vec::new();
    };
    let key = key.trim();
    if key
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
    {
        vec![key.to_string()]
    } else {
        Vec::new()
    }
}

fn identifier_terms(text: &str) -> Vec<String> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(text.match_indices('\n').map(|(index, _)| index + 1))
        .filter(|index| *index < text.len())
        .collect()
}

fn skip_horizontal_whitespace(text: &str, start: usize) -> usize {
    let mut cursor = start;
    while text
        .as_bytes()
        .get(cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        cursor += 1;
    }
    cursor
}

fn skip_ascii_whitespace(text: &str, start: usize) -> usize {
    let mut cursor = start;
    while text
        .as_bytes()
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    cursor
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_identifier_continue) && !after.is_some_and(is_identifier_continue)
}

fn last_identifier(text: &str) -> Option<String> {
    text.split(|character: char| !is_identifier_continue(character))
        .rfind(|part| !part.is_empty())
        .map(str::to_string)
}

fn normalized_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| {
        !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '@' || ch == '.')
    })
    .filter(|token| !token.is_empty())
    .map(str::to_string)
    .collect()
}

fn normalize(text: &str) -> String {
    text.chars()
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

fn vm_decommission_text_line(path: &str, line: &str) -> bool {
    (path.ends_with(PROGRAM_PATH)
        && (line.contains(ENDPOINT) || line.contains("vmDecommissionQuarantine")))
        || path.ends_with(DOC_PATH)
        || path.ends_with(CATALOG_PATH)
        || ((path.ends_with(API_README_PATH)
            || path.ends_with(CATALOG_README_PATH)
            || path.ends_with(DOC_README_PATH))
            && (line.contains(ENDPOINT) || line.contains("VM Decommission Quarantine")))
}

fn value_i64(value: &Value, field: &str) -> Option<i64> {
    value.get(field)?.as_i64()
}

fn value_str<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field)?.as_str()
}

fn value_bool(value: &Value, field: &str) -> Option<bool> {
    value.get(field)?.as_bool()
}

fn value_str_direct<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.as_object()?.get(field)?.as_str()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.as_str().map(str::to_string))
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

    #[test]
    fn vm_decommission_endpoint_registration_detects_route_alias() {
        let program = format!(
            "const string routeAlias = \"{ENDPOINT}\";\napp.MapGet(routeAlias, () => Results.Json(new {{ source = \"static-seed\" }}));"
        );

        let starts = endpoint_start_indexes(&program);
        assert_eq!(starts.len(), 1);
        assert_eq!(program[starts[0]..].find("app.MapGet"), Some(0));
    }
}
