use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/vm-day2-change-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/vm-day2-change.md";
const ENDPOINT: &str = "/api/integrations/vmware/day2-change-contract";
const REQUIRED_ACTIONS: &[&str] = &[
    "resize-cpu",
    "resize-memory",
    "add-disk",
    "extend-disk",
    "add-nic",
    "remove-nic",
    "move-network",
    "migrate-storage",
    "migrate-host",
    "update-tags",
    "plan-cross-hypervisor-migration",
];
const REQUIRED_INPUTS: &[&str] = &[
    "platformCiKey",
    "changeType",
    "targetScope",
    "site",
    "environment",
    "owner",
    "capacityNeed",
    "maintenanceWindow",
    "rollbackPlan",
    "migrationDirection",
    "migrationMethod",
    "downtimeClass",
    "sourceBackupVerification",
    "sourceQuarantineWindow",
    "targetGuestTooling",
    "cutoverValidationPlan",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "request-preflight-ready",
    "capacity-admission-ready",
    "cmdb-ci-known",
    "backup-state-known",
    "monitoring-impact-reviewed",
    "approval-route-assigned",
    "lock-scope-defined",
    "rollback-plan-ready",
    "cold-offline-default",
    "source-backup-verified",
    "source-quarantine-planned",
    "downtime-window-approved",
    "target-guest-tooling-planned",
    "cutover-validation-ready",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "changeSummary",
    "currentState",
    "desiredState",
    "capacityImpact",
    "networkImpact",
    "backupMonitoringImpact",
    "cmdbUpdatePlan",
    "lockPlan",
    "rollbackNotes",
    "verificationPlan",
    "migrationMethodMatrix",
    "downtimePlan",
    "sourceQuarantine",
    "targetGuestTooling",
    "cutoverValidation",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-change-disabled",
    "stale-inventory",
    "capacity-not-approved",
    "cmdb-context-ambiguous",
    "backup-state-unknown",
    "monitoring-impact-unknown",
    "maintenance-window-missing",
    "lock-scope-missing",
    "rollback-plan-missing",
    "migration-method-unknown",
    "downtime-class-missing",
    "source-backup-unverified",
    "source-quarantine-missing",
    "target-guest-tooling-missing",
    "cutover-validation-missing",
    "approval-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Request payload summary",
    "VM change dry-run plan",
    "Capacity impact",
    "Network impact",
    "Backup and monitoring impact",
    "CMDB update plan",
    "Approval decisions",
    "Lock record",
    "Verification plan",
    "Migration method matrix",
    "Downtime class",
    "Source backup verification",
    "Source quarantine plan",
    "Target guest tooling plan",
    "Cutover validation plan",
    "Evidence references",
];
const REQUIRED_MIGRATION_DIRECTIONS: &[&str] = &[
    "vmware-to-hyperv",
    "hyperv-to-vmware",
    "vmware-to-proxmox",
    "hyperv-to-proxmox",
    "proxmox-to-vmware",
    "proxmox-to-hyperv",
];
const REQUIRED_MIGRATION_PLATFORMS: &[&str] = &["VMware", "Hyper-V", "Proxmox"];
const REQUIRED_MIGRATION_ENDPOINTS: &[(&str, &str, &str)] = &[
    ("vmware-to-hyperv", "VMware", "Hyper-V"),
    ("hyperv-to-vmware", "Hyper-V", "VMware"),
    ("vmware-to-proxmox", "VMware", "Proxmox"),
    ("hyperv-to-proxmox", "Hyper-V", "Proxmox"),
    ("proxmox-to-vmware", "Proxmox", "VMware"),
    ("proxmox-to-hyperv", "Proxmox", "Hyper-V"),
];
const REQUIRED_MIGRATION_METHOD_CLASS: &str = "cold-offline-v2v";
const REQUIRED_MIGRATION_DOWNTIME_CLASS: &str = "planned-outage";
const REQUIRED_MIGRATION_ROLLBACK_MODEL: &str = "source-quarantine-reverse-plan";
const REQUIRED_MIGRATION_TOOLING_POSTURE: &str = "tool-selected-at-execution-readiness";
const REQUIRED_MIGRATION_SOURCE_SAFETY: &str = "backup-verified-source-quarantined";
const REQUIRED_MIGRATION_TARGET_GUEST_TOOLING: &str = "target-native-guest-tools-after-validation";
const REQUIRED_MIGRATION_SAFETY_RULES: &[&str] = &[
    "static-equivalence-only",
    "provider-mutation-blocked",
    "live-execution-blocked",
    "cold-offline-default",
    "source-compatibility-reviewed",
    "target-capacity-admission-ready",
    "network-equivalence-reviewed",
    "storage-format-mapping-reviewed",
    "backup-monitoring-rebind-plan",
    "downtime-window-approved",
    "source-backup-verified",
    "source-quarantine-planned",
    "target-guest-tooling-planned",
    "cutover-validation-plan",
    "rollback-or-reverse-plan",
    "evidence-redacted",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedActions", "vmDay2Actions"),
    ("requiredGuards", "vmDay2RequiredGuards"),
    ("planSections", "vmDay2PlanSections"),
    ("blockedReasons", "vmDay2BlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const API_MIGRATION_STRING_FIELDS: &[&str] = &[
    "direction",
    "sourcePlatform",
    "targetPlatform",
    "coverage",
    "executionPosture",
    "methodClass",
    "downtimeClass",
    "rollbackModel",
    "toolingPosture",
    "sourceSafetyPosture",
    "targetGuestTooling",
];
const API_MIGRATION_BOOLEAN_FIELDS: &[&str] = &["providerMutationAllowed", "liveExecutionAllowed"];
const TOP_LEVEL_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "changeMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveChangeAllowed",
    "supportedActions",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "migrationEquivalenceMatrix",
    "rules",
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "changeMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveChangeAllowed",
    "supportedActions",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "migrationEquivalenceMatrix",
    "requiredSafetyRules",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "direction",
    "sourcePlatform",
    "targetPlatform",
    "coverage",
    "executionPosture",
    "methodClass",
    "downtimeClass",
    "rollbackModel",
    "toolingPosture",
    "sourceSafetyPosture",
    "targetGuestTooling",
    "providerMutationAllowed",
    "liveExecutionAllowed",
];
const PROHIBITED_KEYS: &[&str] = &[
    "password",
    "credential",
    "credentials",
    "secret",
    "token",
    "bearer",
    "tenantid",
    "tenantidentifier",
    "subscriptionid",
    "subscriptionidentifier",
    "objectid",
    "objectidentifier",
    "principalid",
    "principalidentifier",
    "privateip",
    "privatenetwork",
    "serialnumber",
    "providerpayload",
    "rawprovider",
    "rawinventory",
    "rawlog",
    "rawrow",
    "recipientemail",
    "recipientaddress",
    "recipientdata",
    "endpointurl",
    "url",
    "hostname",
    "hostidentifier",
    "username",
    "userid",
    "useridentifier",
    "vmobjectid",
    "vcenterobjectid",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-vm-change",
        decision: "block",
        requirement: "VM day-2 changes and migration equivalence plans produce dry-run plans only and never call VMware, Hyper-V, Proxmox, or worker execution.",
        evidence: "VM change dry-run plan",
    },
    RuleDetail {
        id: "capacity-admission-required",
        decision: "block",
        requirement: "CPU, memory, disk, storage, and host movement plans require capacity admission before approval.",
        evidence: "Capacity impact",
    },
    RuleDetail {
        id: "network-impact-reviewed",
        decision: "block",
        requirement: "NIC and network movement plans require network impact review before approval.",
        evidence: "Network impact",
    },
    RuleDetail {
        id: "backup-monitoring-impact-required",
        decision: "block",
        requirement: "Backup and monitoring impact must be known before approval.",
        evidence: "Backup and monitoring impact",
    },
    RuleDetail {
        id: "lock-and-rollback-required",
        decision: "block",
        requirement: "Lock scope, rollback plan, and verification plan are required before future execution can be considered.",
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

#[derive(Clone)]
struct ApiMigrationEntry {
    fields: BTreeMap<String, String>,
    booleans: BTreeMap<String, bool>,
    safety_rules: Option<Vec<String>>,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid VM day-2 change context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(&context.catalog, CATALOG_PATH, &mut errors);
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    scan_prohibited_text(&context.program, PROGRAM_PATH, &mut errors);
    scan_prohibited_text(&context.api_readme, API_README_PATH, &mut errors);
    scan_prohibited_text(&context.doc, DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid VM day-2 change catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid VM day-2 change program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid VM day-2 change docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid VM day-2 change prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("VM day-2 change catalog must be a YAML mapping".to_string());
        return;
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "VM day-2 change version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "VM day-2 change status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "VM day-2 change source must be static-seed",
    );
    expect(
        string_value(catalog, "changeMode") == Some("dry-run-plan"),
        errors,
        "VM day-2 change mode must be dry-run-plan",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "VM day-2 change must require dry-run",
    );
    expect(
        bool_value(catalog, "providerCallsEnabled") == Some(false),
        errors,
        "VM day-2 change provider calls must be disabled",
    );
    expect(
        bool_value(catalog, "liveChangeAllowed") == Some(false),
        errors,
        "VM day-2 change live change must be disabled",
    );
    validate_required_array(catalog, "supportedActions", REQUIRED_ACTIONS, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_migration_equivalence_matrix(catalog, errors);
    validate_required_rules(catalog, errors);
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

fn validate_migration_equivalence_matrix(catalog: &Value, errors: &mut Vec<String>) {
    let matrix = object_array(
        catalog.get("migrationEquivalenceMatrix"),
        "migrationEquivalenceMatrix",
        errors,
    );
    expect(
        !matrix.is_empty(),
        errors,
        "migrationEquivalenceMatrix must be non-empty array",
    );
    let directions: Vec<String> = matrix
        .iter()
        .map(|entry| {
            string_value(entry, "direction")
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let sources: Vec<String> = matrix
        .iter()
        .map(|entry| {
            string_value(entry, "sourcePlatform")
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let targets: Vec<String> = matrix
        .iter()
        .map(|entry| {
            string_value(entry, "targetPlatform")
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    validate_presence_set(
        "migrationEquivalenceMatrix",
        "directions",
        REQUIRED_MIGRATION_DIRECTIONS,
        &directions,
        errors,
    );
    expect(
        directions.iter().collect::<BTreeSet<_>>().len() == directions.len(),
        errors,
        "migrationEquivalenceMatrix directions must be unique",
    );
    validate_presence_set(
        "migrationEquivalenceMatrix",
        "source platforms",
        REQUIRED_MIGRATION_PLATFORMS,
        &sources,
        errors,
    );
    validate_presence_set(
        "migrationEquivalenceMatrix",
        "target platforms",
        REQUIRED_MIGRATION_PLATFORMS,
        &targets,
        errors,
    );
    for entry in matrix {
        let direction = string_value(&entry, "direction").unwrap_or("unknown");
        if let Some((_, source, target)) = REQUIRED_MIGRATION_ENDPOINTS
            .iter()
            .find(|(candidate, _, _)| *candidate == direction)
        {
            expect(
                string_value(&entry, "sourcePlatform") == Some(*source),
                errors,
                format!("migrationEquivalenceMatrix {direction} sourcePlatform must be {source}"),
            );
            expect(
                string_value(&entry, "targetPlatform") == Some(*target),
                errors,
                format!("migrationEquivalenceMatrix {direction} targetPlatform must be {target}"),
            );
        } else {
            errors.push(format!(
                "migrationEquivalenceMatrix unexpected direction {direction}"
            ));
        }
        expect(
            string_value(&entry, "coverage") == Some("static-equivalence-plan"),
            errors,
            format!(
                "migrationEquivalenceMatrix {direction} coverage must be static-equivalence-plan"
            ),
        );
        expect(
            string_value(&entry, "executionPosture") == Some("blocked-live-execution"),
            errors,
            format!("migrationEquivalenceMatrix {direction} executionPosture must be blocked-live-execution"),
        );
        expect(
            string_value(&entry, "methodClass") == Some(REQUIRED_MIGRATION_METHOD_CLASS),
            errors,
            format!("migrationEquivalenceMatrix {direction} methodClass must be {REQUIRED_MIGRATION_METHOD_CLASS}"),
        );
        expect(
            string_value(&entry, "downtimeClass") == Some(REQUIRED_MIGRATION_DOWNTIME_CLASS),
            errors,
            format!("migrationEquivalenceMatrix {direction} downtimeClass must be {REQUIRED_MIGRATION_DOWNTIME_CLASS}"),
        );
        expect(
            string_value(&entry, "rollbackModel") == Some(REQUIRED_MIGRATION_ROLLBACK_MODEL),
            errors,
            format!("migrationEquivalenceMatrix {direction} rollbackModel must be {REQUIRED_MIGRATION_ROLLBACK_MODEL}"),
        );
        expect(
            string_value(&entry, "toolingPosture") == Some(REQUIRED_MIGRATION_TOOLING_POSTURE),
            errors,
            format!("migrationEquivalenceMatrix {direction} toolingPosture must be {REQUIRED_MIGRATION_TOOLING_POSTURE}"),
        );
        expect(
            string_value(&entry, "sourceSafetyPosture") == Some(REQUIRED_MIGRATION_SOURCE_SAFETY),
            errors,
            format!("migrationEquivalenceMatrix {direction} sourceSafetyPosture must be {REQUIRED_MIGRATION_SOURCE_SAFETY}"),
        );
        expect(
            string_value(&entry, "targetGuestTooling") == Some(REQUIRED_MIGRATION_TARGET_GUEST_TOOLING),
            errors,
            format!("migrationEquivalenceMatrix {direction} targetGuestTooling must be {REQUIRED_MIGRATION_TARGET_GUEST_TOOLING}"),
        );
        expect(
            bool_value(&entry, "providerMutationAllowed") == Some(false),
            errors,
            format!("migrationEquivalenceMatrix {direction} provider mutation must be blocked"),
        );
        expect(
            bool_value(&entry, "liveExecutionAllowed") == Some(false),
            errors,
            format!("migrationEquivalenceMatrix {direction} live execution must be blocked"),
        );
        let rules = strict_string_array_like(&entry, "requiredSafetyRules", errors);
        validate_migration_safety_rules(direction, &rules, errors);
    }
}

fn validate_presence_set(
    label: &str,
    kind: &str,
    required: &[&str],
    values: &[String],
    errors: &mut Vec<String>,
) {
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|item| !value_set.contains(item))
        .collect();
    if !missing.is_empty() {
        errors.push(format!("{label} missing {kind}: {}", missing.join(", ")));
    }
}

fn validate_migration_safety_rules(direction: &str, rules: &[String], errors: &mut Vec<String>) {
    expect(
        !rules.is_empty(),
        errors,
        format!(
            "migrationEquivalenceMatrix {direction} requiredSafetyRules must be non-empty array"
        ),
    );
    let required_set: BTreeSet<&str> = REQUIRED_MIGRATION_SAFETY_RULES.iter().copied().collect();
    let rule_set: BTreeSet<&str> = rules.iter().map(String::as_str).collect();
    let missing: Vec<&str> = REQUIRED_MIGRATION_SAFETY_RULES
        .iter()
        .copied()
        .filter(|item| !rule_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = rules
        .iter()
        .map(String::as_str)
        .filter(|item| !required_set.contains(item))
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "migrationEquivalenceMatrix {direction} missing safety rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "migrationEquivalenceMatrix {direction} unexpected safety rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rules.iter().collect::<BTreeSet<_>>().len() == rules.len(),
        errors,
        format!("migrationEquivalenceMatrix {direction} safety rules must be unique"),
    );
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = object_array(catalog.get("rules"), "rules", errors);
    let parsed = catalog_rule_records(&rules, errors);
    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let actual_ids: Vec<&str> = parsed.iter().map(|rule| rule.id.as_str()).collect();
    let actual_set: BTreeSet<&str> = actual_ids.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_set.contains(id))
        .collect();
    let unexpected: Vec<&str> = actual_ids
        .iter()
        .copied()
        .filter(|id| !expected_ids.contains(id))
        .collect();
    expect(
        actual_ids.iter().collect::<BTreeSet<_>>().len() == actual_ids.len(),
        errors,
        "VM day-2 change rule IDs must be unique",
    );
    expect(
        missing.is_empty(),
        errors,
        format!("VM day-2 change missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "VM day-2 change unexpected rules: {}",
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
        "VM day-2 change rule details must be unique",
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = parsed.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "VM day-2 change rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "VM day-2 change rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "VM day-2 change rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn catalog_rule_records(rules: &[Value], errors: &mut Vec<String>) -> Vec<Rule> {
    let mut parsed = Vec::new();
    for rule in rules {
        let Some(map) = rule.as_object() else {
            errors.push("VM day-2 change rules must be objects".to_string());
            continue;
        };
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let label = if id.is_empty() {
            "unknown"
        } else {
            id.as_str()
        };
        for key in map.keys() {
            if !RULE_KEYS.contains(&key.as_str()) {
                errors.push(format!(
                    "VM day-2 change rule {label} unexpected field {key}"
                ));
            }
        }
        for field in RULE_KEYS {
            if !rule.get(*field).is_some_and(Value::is_string) {
                errors.push(format!("VM day-2 change rule {label} missing {field}"));
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

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
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
        exact_string_assignment(&block, "changeMode", "dry-run-plan"),
        errors,
        "API must keep dry-run plan mode",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must keep dryRunRequired true",
    );
    expect(
        exact_assignment(&block, "providerCallsEnabled", "false"),
        errors,
        "API must keep providerCallsEnabled disabled",
    );
    expect(
        exact_assignment(&block, "liveChangeAllowed", "false"),
        errors,
        "API must keep liveChangeAllowed disabled",
    );
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(program, variable, field, errors);
        validate_api_array(field, values, string_array_like(catalog, field), errors);
        validate_bound_array_not_reassigned(program, variable, field, errors);
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field, errors);
        validate_api_array(
            field,
            values,
            required.iter().map(|item| item.to_string()).collect(),
            errors,
        );
    }
    validate_api_migration_equivalence_matrix(&block, catalog, errors);
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

fn validate_api_migration_equivalence_matrix(
    block: &str,
    catalog: &Value,
    errors: &mut Vec<String>,
) {
    let Some(array_block) = endpoint_array_block(block, "migrationEquivalenceMatrix", errors)
    else {
        return;
    };
    let members = top_level_array_members(&array_block);
    let mut api_matrix = Vec::new();
    for (index, member) in members.iter().enumerate() {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        let label = format!("API migrationEquivalenceMatrix entry {}", index + 1);
        let Some(object) = direct_object_block(text, &label, errors) else {
            continue;
        };
        api_matrix.push(parse_api_migration_entry(&object, &label, errors));
    }
    if api_matrix.is_empty() {
        errors.push("API migrationEquivalenceMatrix must be non-empty array".to_string());
    }
    let catalog_matrix = object_array(
        catalog.get("migrationEquivalenceMatrix"),
        "migrationEquivalenceMatrix",
        errors,
    );
    let catalog_by_direction: BTreeMap<String, Value> = catalog_matrix
        .into_iter()
        .filter_map(|entry| Some((string_value(&entry, "direction")?.to_string(), entry)))
        .collect();
    let catalog_directions: Vec<String> = catalog_by_direction.keys().cloned().collect();
    let api_directions: Vec<String> = api_matrix
        .iter()
        .filter_map(|entry| entry.fields.get("direction").cloned())
        .collect();
    let catalog_set: BTreeSet<&str> = catalog_directions.iter().map(String::as_str).collect();
    let api_set: BTreeSet<&str> = api_directions.iter().map(String::as_str).collect();
    let missing: Vec<&str> = catalog_directions
        .iter()
        .map(String::as_str)
        .filter(|direction| !api_set.contains(direction))
        .collect();
    let unexpected: Vec<&str> = api_directions
        .iter()
        .map(String::as_str)
        .filter(|direction| !catalog_set.contains(direction))
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "API migrationEquivalenceMatrix missing directions: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "API migrationEquivalenceMatrix unexpected directions: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        api_directions.iter().collect::<BTreeSet<_>>().len() == api_directions.len(),
        errors,
        "API migrationEquivalenceMatrix directions must be unique",
    );
    for api_entry in api_matrix {
        let Some(direction) = api_entry.fields.get("direction") else {
            continue;
        };
        let Some(catalog_entry) = catalog_by_direction.get(direction) else {
            continue;
        };
        for field in API_MIGRATION_STRING_FIELDS {
            let api_value = api_entry.fields.get(*field).map(String::as_str);
            expect(
                api_value == string_value(catalog_entry, field),
                errors,
                format!("API migrationEquivalenceMatrix {direction} {field} must match catalog"),
            );
        }
        for field in API_MIGRATION_BOOLEAN_FIELDS {
            let api_value = api_entry.booleans.get(*field).copied();
            expect(
                api_value == bool_value(catalog_entry, field),
                errors,
                format!("API migrationEquivalenceMatrix {direction} {field} must match catalog"),
            );
        }
        let catalog_rules = string_array_like(catalog_entry, "requiredSafetyRules");
        validate_api_array(
            &format!("migrationEquivalenceMatrix {direction} requiredSafetyRules"),
            api_entry.safety_rules.clone(),
            catalog_rules.clone(),
            errors,
        );
        if let Some(api_rules) = api_entry.safety_rules {
            expect(
                api_rules == catalog_rules,
                errors,
                format!("API migrationEquivalenceMatrix {direction} requiredSafetyRules must match catalog"),
            );
        }
    }
}

fn parse_api_migration_entry(
    object: &str,
    label: &str,
    errors: &mut Vec<String>,
) -> ApiMigrationEntry {
    let mut fields = BTreeMap::new();
    let mut booleans = BTreeMap::new();
    for field in API_MIGRATION_STRING_FIELDS {
        if let Some(value) = required_string_assignment(object, field, label, errors) {
            fields.insert((*field).to_string(), value);
        }
    }
    for field in API_MIGRATION_BOOLEAN_FIELDS {
        if let Some(value) = required_boolean_assignment(object, field, label, errors) {
            booleans.insert((*field).to_string(), value);
        }
    }
    let safety_rules = endpoint_inline_array_values(object, "requiredSafetyRules", errors);
    ApiMigrationEntry {
        fields,
        booleans,
        safety_rules,
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = parsed_catalog_rules(catalog);
    let api_rules = direct_api_rule_objects(block, errors);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let missing: Vec<&str> = catalog_ids.difference(&api_ids).copied().collect();
    let unexpected: Vec<&str> = api_ids.difference(&catalog_ids).copied().collect();
    if !missing.is_empty() {
        errors.push(format!("API missing rule {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!("API has unexpected rule {}", unexpected.join(", ")));
    }
    let ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
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
        ids.iter().collect::<BTreeSet<_>>().len() == ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        details.iter().collect::<BTreeSet<_>>().len() == details.len(),
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
    for field in top_level_assignment_fields(block) {
        if TOP_LEVEL_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_key(&field) {
            errors.push(format!(
                "API endpoint has prohibited VM day-2 change field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected VM day-2 change field {field}"
            ));
        }
    }
    for field in assignment_fields(block) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if prohibited_key(&field) {
            errors.push(format!(
                "API endpoint has prohibited VM day-2 change field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected VM day-2 change field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in assignment_value_texts(block) {
        if compact(&value) != "true" || field == "dryRunRequired" {
            continue;
        }
        if unsafe_true_flag(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_docs_text(api_readme: &str, doc: &str, errors: &mut Vec<String>) {
    let active_readme = markdown_without_comments(api_readme);
    let active_doc = markdown_without_comments(doc);
    expect(
        active_readme.contains(ENDPOINT),
        errors,
        "API README missing VM day-2 change endpoint",
    );
    expect(
        active_doc.contains(ENDPOINT),
        errors,
        "VM day-2 change doc missing endpoint",
    );
    expect(
        active_doc.contains("No live provider calls."),
        errors,
        "VM day-2 change doc must prohibit provider calls",
    );
    expect(
        active_doc.contains("No live VMware, Hyper-V, or Proxmox changes."),
        errors,
        "VM day-2 change doc must prohibit live hypervisor changes",
    );
    expect(
        active_doc.contains("No worker execution."),
        errors,
        "VM day-2 change doc must prohibit worker execution",
    );
    expect(
        active_doc.contains("provider-safe change plans"),
        errors,
        "VM day-2 change doc must require provider-safe plans",
    );
    expect(
        active_doc.contains("not raw hypervisor output"),
        errors,
        "VM day-2 change doc must prohibit raw hypervisor output",
    );
    expect(
        active_doc.contains("migration equivalence matrix"),
        errors,
        "VM day-2 change doc must include migration equivalence matrix",
    );
    expect(
        active_doc.contains("blocked live execution"),
        errors,
        "VM day-2 change doc must include blocked live execution posture",
    );
    expect(
        active_doc.contains("provider mutation"),
        errors,
        "VM day-2 change doc must include provider mutation posture",
    );
    expect(
        active_doc.contains("cold/offline V2V"),
        errors,
        "VM day-2 change doc must include cold/offline V2V posture",
    );
    expect(
        active_doc.contains("planned outage"),
        errors,
        "VM day-2 change doc must include planned outage posture",
    );
    expect(
        active_doc.contains("source quarantine"),
        errors,
        "VM day-2 change doc must include source quarantine posture",
    );
    expect(
        active_doc.contains("rollback or reverse plan"),
        errors,
        "VM day-2 change doc must include rollback or reverse plan posture",
    );
    expect(
        active_doc.contains("source backup verification"),
        errors,
        "VM day-2 change doc must include source backup verification",
    );
    expect(
        active_doc.contains("target-native guest tooling"),
        errors,
        "VM day-2 change doc must include target-native guest tooling",
    );
    expect(
        active_doc.contains("warm/live migration remains a later tool-specific exception"),
        errors,
        "VM day-2 change doc must include warm/live exception posture",
    );
    for platform in REQUIRED_MIGRATION_PLATFORMS {
        expect(
            active_doc.contains(platform),
            errors,
            format!("VM day-2 change doc missing migration platform {platform}"),
        );
    }
    for direction in REQUIRED_MIGRATION_DIRECTIONS {
        expect(
            active_doc.contains(direction),
            errors,
            format!("VM day-2 change doc missing migration direction {direction}"),
        );
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> Option<String> {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing VM day-2 change endpoint".to_string());
        return None;
    }
    if starts.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT}"));
        return None;
    }
    let start = starts[0];
    let next = mapget_start_indexes(program)
        .into_iter()
        .find(|index| *index > start)
        .unwrap_or(program.len());
    Some(program[start..next].to_string())
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    mapget_start_indexes(program)
        .into_iter()
        .filter(|start| mapget_route_literal(program, *start).as_deref() == Some(ENDPOINT))
        .collect()
}

fn mapget_start_indexes(program: &str) -> Vec<usize> {
    let masked = csharp_code_mask(program);
    identifier_positions(&masked, "app")
        .into_iter()
        .filter(|start| mapget_open_paren(&masked, *start).is_some())
        .collect()
}

fn mapget_route_literal(program: &str, start: usize) -> Option<String> {
    let masked = csharp_code_mask(program);
    let open = mapget_open_paren(&masked, start)?;
    let index = skip_ws(program, open + 1);
    string_literal_at(program, index).map(|(value, _)| value)
}

fn mapget_open_paren(masked: &str, start: usize) -> Option<usize> {
    let mut index = start + "app".len();
    index = skip_ws(masked, index);
    if masked.as_bytes().get(index) != Some(&b'.') {
        return None;
    }
    index = skip_ws(masked, index + 1);
    if !identifier_at(masked, index, "MapGet") {
        return None;
    }
    index = skip_ws(masked, index + "MapGet".len());
    if masked.as_bytes().get(index) == Some(&b'(') {
        Some(index)
    } else {
        None
    }
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> Option<String> {
    let masked = csharp_code_mask(endpoint);
    let json_indexes = find_all(&masked, "Results.Json(new");
    if json_indexes.is_empty() {
        errors.push("API missing VM day-2 change JSON payload".to_string());
        return None;
    }
    if json_indexes.len() != 1 {
        errors.push("API must declare exactly one VM day-2 change JSON payload".to_string());
        return None;
    }
    let Some(object_start) = masked[json_indexes[0]..]
        .find('{')
        .map(|offset| offset + json_indexes[0])
    else {
        errors.push("API VM day-2 change JSON payload is malformed".to_string());
        return None;
    };
    let Some(object_end) = matching_brace_index(&masked, object_start) else {
        errors.push("API VM day-2 change JSON payload is malformed".to_string());
        return Some(endpoint[object_start..].to_string());
    };
    Some(endpoint[object_start..=object_end].to_string())
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let bodies = csharp_array_bodies(program, variable);
    if bodies.len() != 1 {
        errors.push(format!(
            "API {field} array must declare exactly one literal {variable} array"
        ));
        return None;
    }
    csharp_array_literal_values(&bodies[0], &format!("API {field}"), errors)
}

fn csharp_array_bodies(program: &str, variable: &str) -> Vec<String> {
    let masked = csharp_code_mask(program);
    let pattern = format!("var {variable} = new[] {{");
    let mut bodies = Vec::new();
    let mut offset = 0;
    while let Some(found) = masked[offset..].find(&pattern) {
        let start = offset + found;
        let open = start + pattern.len() - 1;
        if let Some(close) = matching_brace_index(&masked, open) {
            let after = skip_ws(&masked, close + 1);
            if masked.as_bytes().get(after) == Some(&b';') {
                bodies.push(program[open + 1..close].to_string());
            }
            offset = close + 1;
        } else {
            offset = start + pattern.len();
        }
    }
    bodies
}

fn csharp_array_literal_values(
    body: &str,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let mut values = Vec::new();
    for member in split_top_level_members(body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        let Some((value, end)) = string_literal_at(text, 0) else {
            errors.push(format!("{label} array contains non-static values"));
            continue;
        };
        if !text[end..].trim().is_empty() {
            errors.push(format!("{label} array contains non-static values"));
            continue;
        }
        values.push(value);
    }
    Some(values)
}

fn validate_bound_array_not_reassigned(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let masked = csharp_code_mask(program);
    let mut assignments = Vec::new();
    for index in identifier_positions(&masked, variable) {
        let next = skip_ws(&masked, index + variable.len());
        if masked.as_bytes().get(next) == Some(&b'=') {
            assignments.push(is_var_declaration(&masked, index));
        }
    }
    if assignments.len() != 1 || assignments.iter().any(|declaration| !declaration) {
        errors.push(format!(
            "API {field} bound array {variable} must not be reassigned"
        ));
    }
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
    let text = texts[0].trim().trim_end_matches(',').trim();
    let prefix = format!("{field} = new[] ");
    if !text.starts_with(&prefix) {
        errors.push(format!("API {field} array contains non-static values"));
        return None;
    }
    let open = text.find('{')?;
    let close = matching_brace_index(text, open)?;
    if !text[close + 1..].trim().is_empty() {
        errors.push(format!("API {field} array contains non-static values"));
        return None;
    }
    csharp_array_literal_values(&text[open + 1..close], &format!("API {field}"), errors)
}

fn direct_api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(array_block) = endpoint_array_block(block, "rules", errors) else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    for member in top_level_array_members(&array_block) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        let Some(object) = direct_object_block(text, "API rules", errors) else {
            continue;
        };
        let fields = top_level_assignment_fields(&object);
        let rule = Rule {
            id: rule_string_field(&object, "id").unwrap_or_default(),
            decision: rule_string_field(&object, "decision").unwrap_or_default(),
            requirement: rule_string_field(&object, "requirement").unwrap_or_default(),
            evidence: rule_string_field(&object, "evidence").unwrap_or_default(),
        };
        for field in fields {
            if !RULE_KEYS.contains(&field.as_str()) {
                errors.push(format!(
                    "API rule {} has unexpected field {field}",
                    if rule.id.is_empty() {
                        "unknown"
                    } else {
                        &rule.id
                    }
                ));
            }
        }
        for (field, value) in [
            ("id", &rule.id),
            ("decision", &rule.decision),
            ("requirement", &rule.requirement),
            ("evidence", &rule.evidence),
        ] {
            if value.is_empty() {
                errors.push(format!("API rule missing {field}"));
            }
        }
        rules.push(rule);
    }
    rules
}

fn direct_object_block(text: &str, label: &str, errors: &mut Vec<String>) -> Option<String> {
    let masked = csharp_code_mask(text);
    if !masked.trim_start().starts_with("new") {
        errors.push(format!(
            "{label} array members must be direct anonymous literal objects"
        ));
        return None;
    }
    let Some(open) = masked.find('{') else {
        errors.push(format!(
            "{label} array members must be direct anonymous literal objects"
        ));
        return None;
    };
    if compact(&masked[..open]) != "new" {
        errors.push(format!(
            "{label} array members must be direct anonymous literal objects"
        ));
        return None;
    }
    let Some(close) = matching_brace_index(&masked, open) else {
        errors.push(format!(
            "{label} array members must be direct anonymous literal objects"
        ));
        return None;
    };
    if !text[close + 1..].trim().is_empty() {
        errors.push(format!(
            "{label} array members must be direct anonymous literal objects"
        ));
        return None;
    }
    Some(text[open..=close].to_string())
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
    let start = indexes[0];
    let Some(open) = block[start..].find('{').map(|offset| offset + start) else {
        errors.push(format!("API {field} array is malformed"));
        return None;
    };
    let masked = csharp_code_mask(block);
    let Some(close) = matching_brace_index(&masked, open) else {
        errors.push(format!("API {field} array is malformed"));
        return None;
    };
    if compact(&block[start..open]) != format!("{field}=new[]") {
        errors.push(format!(
            "API {field} array must use exact top-level {field} = new[] assignment"
        ));
        return None;
    }
    Some(block[open..=close].to_string())
}

fn rule_string_field(object: &str, field: &str) -> Option<String> {
    required_string_assignment(object, field, "API rule", &mut Vec::new())
}

fn required_string_assignment(
    block: &str,
    field: &str,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<String> {
    let texts = top_level_assignment_texts(block, field);
    if texts.len() != 1 {
        errors.push(format!("{label} {field} must be declared once"));
        return None;
    }
    let text = texts[0].trim().trim_end_matches(',').trim();
    let eq = text.find('=')?;
    let rest = text[eq + 1..].trim_start();
    let Some((value, end)) = string_literal_at(rest, 0) else {
        errors.push(format!("{label} {field} must be a static string"));
        return None;
    };
    if !rest[end..].trim().is_empty() {
        errors.push(format!("{label} {field} must be a static string"));
        return None;
    }
    Some(value)
}

fn required_boolean_assignment(
    block: &str,
    field: &str,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<bool> {
    let texts = top_level_assignment_texts(block, field);
    if texts.len() != 1 {
        errors.push(format!("{label} {field} must be declared once"));
        return None;
    }
    let text = texts[0].trim().trim_end_matches(',').trim();
    let eq = text.find('=')?;
    let value = compact(&text[eq + 1..]);
    match value.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => {
            errors.push(format!("{label} {field} must be a static boolean"));
            None
        }
    }
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1 && compact(&texts[0]) == format!("{field}={value},")
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let texts = top_level_assignment_texts(block, field);
    texts.len() == 1 && compact(&texts[0]) == format!("{field}=\"{value}\",")
}

fn top_level_assignment_texts(block: &str, field: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    top_level_assignment_indexes(block, field)
        .into_iter()
        .map(|index| {
            block[index..assignment_end_index(&masked, index)]
                .trim()
                .to_string()
        })
        .collect()
}

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
    let masked = csharp_code_mask(block);
    identifier_positions(&masked, field)
        .into_iter()
        .filter(|index| {
            let next = skip_ws(&masked, index + field.len());
            masked.as_bytes().get(next) == Some(&b'=') && brace_depth_at(&masked, *index) == 1
        })
        .collect()
}

fn assignment_end_index(masked: &str, start: usize) -> usize {
    for index in start..masked.len() {
        let byte = masked.as_bytes()[index];
        if byte == b',' && brace_depth_at(masked, index) == 1 {
            return index + 1;
        }
        if byte == b'}' && brace_depth_at(masked, index) == 1 {
            return index;
        }
    }
    masked.len()
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let mut fields = Vec::new();
    for (field, index) in all_identifier_positions(&masked) {
        let next = skip_ws(&masked, index + field.len());
        if masked.as_bytes().get(next) == Some(&b'=') && brace_depth_at(&masked, index) == 1 {
            fields.push(field);
        }
    }
    fields
}

fn assignment_fields(block: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let mut fields = Vec::new();
    for (field, index) in all_identifier_positions(&masked) {
        let next = skip_ws(&masked, index + field.len());
        if masked.as_bytes().get(next) == Some(&b'=') {
            fields.push(field);
        }
    }
    fields
}

fn assignment_value_texts(block: &str) -> Vec<(String, String)> {
    let masked = csharp_code_mask(block);
    let mut values = Vec::new();
    for (field, index) in all_identifier_positions(&masked) {
        let next = skip_ws(&masked, index + field.len());
        if masked.as_bytes().get(next) == Some(&b'=') {
            let end = assignment_end_index(&masked, index);
            values.push((
                field,
                block[next + 1..end]
                    .trim()
                    .trim_end_matches(',')
                    .to_string(),
            ));
        }
    }
    values
}

fn top_level_object_members(block: &str) -> Vec<String> {
    let text = block.trim();
    let body = if text.starts_with('{') && text.ends_with('}') {
        &text[1..text.len() - 1]
    } else {
        text
    };
    split_top_level_members(body)
}

fn top_level_array_members(array_block: &str) -> Vec<String> {
    top_level_object_members(array_block)
}

fn split_top_level_members(body: &str) -> Vec<String> {
    let masked = csharp_code_mask(body);
    let mut members = Vec::new();
    let mut start = 0;
    for index in 0..masked.len() {
        if masked.as_bytes()[index] == b',' && brace_depth_at(&masked, index) == 0 {
            members.push(body[start..index].to_string());
            start = index + 1;
        }
    }
    members.push(body[start..].to_string());
    members
}

fn parsed_catalog_rules(catalog: &Value) -> Vec<Rule> {
    object_array_readonly(catalog.get("rules"))
        .into_iter()
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

fn object_array(value: Option<&Value>, label: &str, errors: &mut Vec<String>) -> Vec<Value> {
    let Some(values) = value.and_then(Value::as_array) else {
        errors.push(format!("{label} must be an array"));
        return Vec::new();
    };
    values
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            if item.is_object() {
                Some(item.clone())
            } else {
                errors.push(format!("{label}[{index}] must be an object"));
                None
            }
        })
        .collect()
}

fn object_array_readonly(value: Option<&Value>) -> Vec<&Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.is_object())
        .collect()
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_key(key) {
                    errors.push(format!("{child_path} contains prohibited key"));
                }
                if prohibited_value(key) {
                    errors.push(format!("{child_path} contains prohibited value"));
                }
                scan_prohibited_value(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => scan_prohibited_text(text, path, errors),
        _ => {
            let text = value.to_string();
            if prohibited_value(&text) {
                errors.push(format!("{path} contains prohibited value"));
            }
        }
    }
}

fn scan_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
}

fn prohibited_value(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("://")
        || lower.contains("-----begin ") && lower.contains("private key-----")
        || lower.contains("akia")
        || contains_private_ip(&lower)
        || contains_uuid_like(&lower)
        || contains_secret_assignment(&lower)
}

fn prohibited_key(key: &str) -> bool {
    let normalized = normalize(key);
    PROHIBITED_KEYS
        .iter()
        .any(|term| normalized == *term || normalized.contains(term))
}

fn unsafe_true_flag(field: &str) -> bool {
    let normalized = normalize(field);
    [
        "live",
        "provider",
        "worker",
        "raw",
        "credential",
        "secret",
        "token",
        "tenant",
        "subscription",
        "object",
        "principal",
        "private",
        "user",
        "host",
        "execution",
        "mutation",
        "approval",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            let octets: Vec<u16> = candidate
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect();
            octets.len() == 4
                && octets.iter().all(|octet| *octet <= 255)
                && (octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1])))
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
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|term| {
        let mut offset = 0;
        while let Some(found) = text[offset..].find(term) {
            let index = offset + found;
            let tail = text[index + term.len()..].trim_start();
            if matches!(tail.as_bytes().first(), Some(b':') | Some(b'='))
                && tail[1..].chars().any(|ch| !ch.is_whitespace())
            {
                return true;
            }
            offset = index + term.len();
        }
        false
    })
}

fn csharp_code_mask(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            let finish = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|found| index + found)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            let finish = find_bytes(text, "*/", index + 2)
                .map(|found| found + 2)
                .unwrap_or(bytes.len());
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes.get(index..index + 3) == Some(br#"""""#) {
            let finish = raw_string_end(text, index);
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index] == b'"' {
            let finish = quoted_end(bytes, index, b'"');
            mask_range(&mut result, index, finish);
            index = finish;
        } else if bytes[index] == b'\'' {
            let finish = quoted_end(bytes, index, b'\'');
            mask_range(&mut result, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8(result).expect("mask keeps valid utf-8")
}

fn markdown_without_comments(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut index = 0;
    while let Some(start) = text[index..].find("<!--") {
        let start = index + start;
        result.push_str(&text[index..start]);
        let finish = text[start + 4..]
            .find("-->")
            .map(|found| start + 4 + found + 3)
            .unwrap_or(text.len());
        for ch in text[start..finish].chars() {
            result.push(if ch == '\n' { '\n' } else { ' ' });
        }
        index = finish;
    }
    result.push_str(&text[index..]);
    result
}

fn mask_range(bytes: &mut [u8], start: usize, finish: usize) {
    for byte in bytes.iter_mut().take(finish).skip(start) {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn raw_string_end(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut quotes = 0;
    while bytes.get(start + quotes) == Some(&b'"') {
        quotes += 1;
    }
    let delimiter = "\"".repeat(quotes);
    find_bytes(text, &delimiter, start + quotes)
        .map(|finish| finish + quotes)
        .unwrap_or(bytes.len())
}

fn quoted_end(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut index = start + 1;
    let mut escaped = false;
    while index < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == quote {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn string_literal_at(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut value = String::new();
    let mut index = start + 1;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            value.push(byte as char);
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Some((value, index + 1));
        } else {
            value.push(byte as char);
        }
        index += 1;
    }
    None
}

fn matching_brace_index(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0;
    for index in open..text.len() {
        match text.as_bytes()[index] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn brace_depth_at(text: &str, target: usize) -> i32 {
    let mut depth = 0;
    for byte in text.as_bytes().iter().take(target) {
        match byte {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
    }
    depth
}

fn identifier_positions(text: &str, needle: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut offset = 0;
    while let Some(found) = text[offset..].find(needle) {
        let start = offset + found;
        let end = start + needle.len();
        if identifier_at(text, start, needle) {
            positions.push(start);
        }
        offset = end;
    }
    positions
}

fn identifier_at(text: &str, start: usize, needle: &str) -> bool {
    if text.get(start..start + needle.len()) != Some(needle) {
        return false;
    }
    let before = start
        .checked_sub(1)
        .and_then(|index| text.as_bytes().get(index));
    let after = text.as_bytes().get(start + needle.len());
    !before.is_some_and(|byte| is_ident_continue(*byte))
        && !after.is_some_and(|byte| is_ident_continue(*byte))
}

fn all_identifier_positions(text: &str) -> Vec<(String, usize)> {
    let mut items = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if is_ident_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_ident_continue(bytes[index]) {
                index += 1;
            }
            items.push((text[start..index].to_string(), start));
        } else {
            index += 1;
        }
    }
    items
}

fn is_var_declaration(masked: &str, index: usize) -> bool {
    let prefix = masked[..index].trim_end();
    prefix.ends_with("var")
        && prefix
            .as_bytes()
            .get(prefix.len().saturating_sub(4))
            .is_none_or(|byte| !is_ident_continue(*byte))
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_ws(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn find_all(text: &str, needle: &str) -> Vec<usize> {
    let mut indexes = Vec::new();
    let mut offset = 0;
    while let Some(found) = text[offset..].find(needle) {
        let index = offset + found;
        indexes.push(index);
        offset = index + needle.len();
    }
    indexes
}

fn find_bytes(text: &str, needle: &str, start: usize) -> Option<usize> {
    text[start..].find(needle).map(|found| start + found)
}

fn compact(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
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

fn strict_string_array_like(value: &Value, key: &str, errors: &mut Vec<String>) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(values)) => values
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                if let Some(text) = item.as_str() {
                    Some(text.to_string())
                } else {
                    errors.push(format!("{key}[{index}] must be a string"));
                    None
                }
            })
            .collect(),
        Some(Value::String(text)) => vec![text.to_string()],
        Some(_) => {
            errors.push(format!("{key} must be an array of strings"));
            Vec::new()
        }
        None => Vec::new(),
    }
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
