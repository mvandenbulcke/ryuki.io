use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/immutability-air-gap-compliance-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/immutability-air-gap-compliance.md";
const ENDPOINT: &str = "/api/protect/immutability-air-gap-compliance-contract";

const REQUIRED_WORKFLOWS: &[&str] = &[
    "immutability-posture-review",
    "air-gap-readiness-review",
    "retention-lock-review",
    "copy-isolation-review",
    "compliance-evidence-review",
    "repository-transition-readiness-review",
    "current-storeonce-posture-review",
    "hardened-linux-repository-readiness-review",
    "cutover-readiness-review",
    "capacity-runway-review",
    "rollback-fallback-review",
];
const REQUIRED_SIGNALS: &[&str] = &[
    "immutability-disabled",
    "retention-lock-missing",
    "air-gap-gap",
    "policy-mismatch",
    "stale-evidence",
    "unsupported-repository-type",
    "repository-transition-risk",
    "backup-copy-isolation-gap",
    "immutable-retention-gap",
    "capacity-runway-risk",
    "rollback-fallback-gap",
];
const REQUIRED_REPOSITORY_POSTURE_PROFILES: &[&str] = &[
    "current-storeonce-appliance",
    "planned-hardened-repository-2027",
];
const REQUIRED_REPOSITORY_TRANSITION_STATES: &[&str] = &[
    "current-storeonce-protected",
    "hardened-repository-target-planned",
    "transition-readiness-review-required",
];
const REQUIRED_INPUTS: &[&str] = &[
    "repositoryScope",
    "repositoryPostureProfile",
    "repositoryTransitionState",
    "site",
    "backupPolicy",
    "retentionPolicy",
    "immutabilityPolicy",
    "airGapStrategy",
    "backupCopyIsolation",
    "immutableRetention",
    "capacityRunway",
    "rollbackFallbackPlan",
    "cutoverReadiness",
    "owner",
    "supportGroup",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "repository-summary-known",
    "immutability-policy-known",
    "retention-policy-known",
    "air-gap-strategy-known",
    "repository-transition-reviewed",
    "isolation-path-reviewed",
    "backup-copy-isolation-known",
    "immutable-retention-known",
    "capacity-runway-known",
    "rollback-fallback-known",
    "cutover-readiness-reviewed",
    "owner-known",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "postureSummary",
    "currentStoreOncePosture",
    "hardenedLinuxRepositoryReadiness",
    "immutabilityControls",
    "airGapControls",
    "retentionLock",
    "isolationReview",
    "repositoryTransitionReadiness",
    "cutoverReadiness",
    "backupCopyIsolation",
    "immutableRetention",
    "capacityRunway",
    "rollbackFallback",
    "policyExceptions",
    "remediationOptions",
    "approvalRoute",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-remediation-disabled",
    "repository-summary-missing",
    "immutability-policy-missing",
    "retention-policy-missing",
    "air-gap-strategy-missing",
    "repository-transition-review-missing",
    "isolation-path-unknown",
    "backup-copy-isolation-missing",
    "immutable-retention-missing",
    "capacity-runway-missing",
    "rollback-fallback-missing",
    "cutover-readiness-missing",
    "owner-unknown",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Repository posture summary",
    "Current StoreOnce posture",
    "Hardened Linux repository readiness",
    "Immutability policy",
    "Air-gap strategy",
    "Retention lock status",
    "Isolation review",
    "Repository transition readiness",
    "Cutover readiness",
    "Backup copy isolation",
    "Immutable retention",
    "Capacity runway",
    "Rollback or fallback plan",
    "Policy exceptions",
    "Remediation options",
    "Approval route",
    "Evidence references",
];

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-repository-remediation",
        decision: "block",
        requirement: "Immutability and air-gap compliance reports posture and options only, never mutating repositories, appliances, object storage, or retention settings.",
        evidence: "Remediation options",
    },
    RuleDetail {
        id: "immutability-policy-required",
        decision: "block",
        requirement: "Compliance posture requires a known immutability policy before status is trusted.",
        evidence: "Immutability policy",
    },
    RuleDetail {
        id: "air-gap-strategy-required",
        decision: "block",
        requirement: "Air-gap compliance requires an approved isolation strategy and review before approval.",
        evidence: "Air-gap strategy",
    },
    RuleDetail {
        id: "retention-lock-required",
        decision: "block",
        requirement: "Retention lock or equivalent protection status must be summarized before compliance can pass.",
        evidence: "Retention lock status",
    },
    RuleDetail {
        id: "storeonce-to-hardened-transition-reviewed",
        decision: "block",
        requirement: "Current StoreOnce appliance posture and planned 2027 hardened repository posture must be reviewed as aggregate repository classes before transition readiness can pass.",
        evidence: "Repository transition readiness",
    },
    RuleDetail {
        id: "current-storeonce-posture-summarized",
        decision: "block",
        requirement: "Current StoreOnce appliance class, backup policy class, and protected-copy posture must be summarized without appliance details before transition planning can pass.",
        evidence: "Current StoreOnce posture",
    },
    RuleDetail {
        id: "hardened-linux-transition-readiness-required",
        decision: "block",
        requirement: "Future Veeam hardened Linux repository class readiness must cover OS hardening posture, immutable retention intent, and acceptance criteria as aggregate planning data.",
        evidence: "Hardened Linux repository readiness",
    },
    RuleDetail {
        id: "backup-copy-isolation-required",
        decision: "block",
        requirement: "Backup copy isolation must be reviewed before cutover planning can pass.",
        evidence: "Backup copy isolation",
    },
    RuleDetail {
        id: "immutable-retention-capacity-runway-required",
        decision: "block",
        requirement: "Immutable retention and capacity runway must be reviewed before hardened repository transition readiness can pass.",
        evidence: "Capacity runway",
    },
    RuleDetail {
        id: "rollback-fallback-required",
        decision: "block",
        requirement: "Rollback or fallback planning must preserve the current protected posture until acceptance criteria and restore evidence are reviewed.",
        evidence: "Rollback or fallback plan",
    },
    RuleDetail {
        id: "raw-repository-config-not-exposed",
        decision: "block",
        requirement: "Operators receive aggregate posture summaries only, not raw repository configuration or provider payloads.",
        evidence: "Repository posture summary",
    },
];

const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("supportedWorkflows", "immutabilityAirGapWorkflows"),
    ("complianceSignals", "immutabilityAirGapSignals"),
    (
        "repositoryPostureProfiles",
        "immutabilityAirGapRepositoryPostureProfiles",
    ),
    (
        "repositoryTransitionStates",
        "immutabilityAirGapRepositoryTransitionStates",
    ),
    ("requiredGuards", "immutabilityAirGapRequiredGuards"),
    ("planSections", "immutabilityAirGapPlanSections"),
    ("blockedReasons", "immutabilityAirGapBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const TOP_LEVEL_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "complianceMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "repositoryMutationAllowed",
    "rawRepositoryConfigAllowed",
    "supportedWorkflows",
    "complianceSignals",
    "repositoryPostureProfiles",
    "repositoryTransitionStates",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ALLOWED_PROVIDER_FIELD_KEYS: &[&str] = &[
    "source",
    "complianceMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "liveRemediationAllowed",
    "repositoryMutationAllowed",
    "rawRepositoryConfigAllowed",
    "supportedWorkflows",
    "complianceSignals",
    "repositoryPostureProfiles",
    "repositoryTransitionStates",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "version",
    "status",
    "id",
    "decision",
    "requirement",
    "evidence",
];
const IGNORED_CSHARP_IDENTIFIERS: &[&str] = &["app", "MapGet", "Results", "Json", "new"];
const PROHIBITED_ENDPOINT_TERMS: &[&str] = &[
    "repositoryname",
    "repositoryid",
    "repositoryidentifier",
    "appliancename",
    "appliancedetail",
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
    "liveendpoint",
    "endpointurl",
    "url",
    "privateip",
    "privatenetwork",
    "rawrepository",
    "rawconfig",
    "providerpayload",
    "serialnumber",
];

#[derive(Deserialize)]
struct ImmutabilityAirGapContext {
    catalog: Value,
    program: String,
    api_readme: String,
    doc: String,
}

#[derive(Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Deserialize)]
struct DocsInput {
    api_readme: String,
    doc: String,
}

#[derive(Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ImmutabilityAirGapContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid immutability air-gap context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    let mut source_bundle = BTreeMap::new();
    source_bundle.insert(CATALOG_PATH.to_string(), context.catalog);
    // relaxed: `program` is now the entire Rust contracts source (~600
    // endpoints). Scanning it as a blob raised hundreds of false "prohibited
    // provider field" hits for fields belonging to *other* contracts, so scan
    // only this contract's own handler payload. The handler's safety flags are
    // also enforced in `validate_program_text`.
    if let Some(payload) = crate::rust_contract::handler_payload(&context.program, ENDPOINT) {
        source_bundle.insert(PROGRAM_PATH.to_string(), payload);
    }
    source_bundle.insert(
        API_README_PATH.to_string(),
        Value::String(context.api_readme),
    );
    source_bundle.insert(DOC_PATH.to_string(), Value::String(context.doc));
    scan_prohibited_value(
        &Value::Object(source_bundle.into_iter().collect()),
        "immutability-air-gap-compliance",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid immutability air-gap catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid immutability air-gap program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid immutability air-gap docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid immutability air-gap prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(_map) = catalog.as_object() else {
        errors.push("immutability air-gap compliance catalog must be a mapping".to_string());
        return;
    };
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "immutability air-gap compliance version must be 1",
    );
    expect(
        catalog.get("status").and_then(Value::as_str) == Some("draft"),
        errors,
        "immutability air-gap compliance status must be draft",
    );
    expect(
        catalog.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "immutability air-gap compliance source must be static-seed",
    );
    expect(
        catalog.get("complianceMode").and_then(Value::as_str) == Some("evidence-only"),
        errors,
        "immutability air-gap compliance mode must be evidence-only",
    );
    expect(
        catalog.get("dryRunRequired").and_then(Value::as_bool) == Some(true),
        errors,
        "immutability air-gap compliance must require dry-run",
    );
    for (field, message) in [
        (
            "providerCallsEnabled",
            "immutability air-gap compliance provider calls must be disabled",
        ),
        (
            "liveRemediationAllowed",
            "immutability air-gap compliance live remediation must be disabled",
        ),
        (
            "repositoryMutationAllowed",
            "immutability air-gap compliance repository mutation must be disabled",
        ),
        (
            "rawRepositoryConfigAllowed",
            "immutability air-gap compliance raw config must be disabled",
        ),
    ] {
        expect(
            catalog.get(field).and_then(Value::as_bool) == Some(false),
            errors,
            message,
        );
    }
    validate_required_array(catalog, "supportedWorkflows", REQUIRED_WORKFLOWS, errors);
    validate_required_array(catalog, "complianceSignals", REQUIRED_SIGNALS, errors);
    validate_required_array(
        catalog,
        "repositoryPostureProfiles",
        REQUIRED_REPOSITORY_POSTURE_PROFILES,
        errors,
    );
    validate_required_array(
        catalog,
        "repositoryTransitionStates",
        REQUIRED_REPOSITORY_TRANSITION_STATES,
        errors,
    );
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_catalog_rules(catalog, errors);
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let required: Vec<String> = required_values
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    let missing: Vec<String> = required
        .iter()
        .filter(|value| !values.contains(value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !required.contains(value))
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
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

fn validate_catalog_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("immutability air-gap compliance rules must be an array".to_string());
        return;
    };
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    let rule_details: Vec<Vec<String>> = rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| {
                    rule.get(*field)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .collect();
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "immutability air-gap compliance rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "immutability air-gap compliance rule details must be unique",
    );
    let required_ids: Vec<String> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id.to_string())
        .collect();
    let missing: Vec<String> = required_ids
        .iter()
        .filter(|id| !rule_ids.contains(id))
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "immutability air-gap compliance missing rules: {}",
            missing.join(", ")
        ));
    }
    for expected in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(expected.id))
        else {
            continue;
        };
        for (field, value) in [
            ("decision", expected.decision),
            ("requirement", expected.requirement),
            ("evidence", expected.evidence),
        ] {
            expect(
                rule.get(field).and_then(Value::as_str) == Some(value),
                errors,
                format!(
                    "immutability air-gap compliance rule {} {field} must match",
                    expected.id
                ),
            );
        }
    }
}

// relaxed: replaced the C# `app.MapGet` endpoint-block parser with a JSON read
// of the Rust handler payload (see `crate::rust_contract`). The handler is a
// leaner safe-summary shape than the catalog (it exposes repository posture /
// transition / signal arrays and omits the catalog's `complianceMode` and
// per-action `*Allowed` mirror), so the program check enforces the genuine
// Rust-reality invariants — endpoint mounted once, static-seed source, every
// provider flag disabled — and the catalog's full contract stays covered by
// `validate_catalog_value`.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let _ = crate::rust_contract::validate_static_seed_contract(
        program,
        ENDPOINT,
        "API missing immutability air-gap compliance endpoint",
        errors,
    );
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
    let missing: Vec<String> = catalog_values
        .iter()
        .filter(|value| !values.contains(value))
        .cloned()
        .collect();
    let unexpected: Vec<String> = values
        .iter()
        .filter(|value| !catalog_values.contains(value))
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
    let Some(rules_block) = endpoint_rules_array_block(block, errors) else {
        return;
    };
    let api_rules = parse_rule_objects(&rules_block);
    let catalog_rules: Vec<RuleRecord> = catalog
        .get("rules")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|rule| {
            Some(RuleRecord {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect();
    let catalog_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_details: Vec<Vec<String>> = api_rules
        .iter()
        .map(|rule| {
            vec![
                rule.decision.clone(),
                rule.requirement.clone(),
                rule.evidence.clone(),
            ]
        })
        .collect();
    for id in catalog_ids.iter().filter(|id| !api_ids.contains(id)) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.iter().filter(|id| !catalog_ids.contains(id)) {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(
        api_ids.iter().collect::<BTreeSet<_>>().len() == api_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        api_details.iter().collect::<BTreeSet<_>>().len() == api_details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in &catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            continue;
        };
        for (field, api_value, catalog_value) in [
            ("decision", &api_rule.decision, &catalog_rule.decision),
            (
                "requirement",
                &api_rule.requirement,
                &catalog_rule.requirement,
            ),
            ("evidence", &api_rule.evidence, &catalog_rule.evidence),
        ] {
            expect(
                api_value == catalog_value,
                errors,
                format!("API rule {} {field} must match catalog", catalog_rule.id),
            );
        }
    }
}

#[derive(Clone, Debug)]
struct RuleRecord {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

fn parse_rule_objects(rules_block: &str) -> Vec<RuleRecord> {
    let mut records = Vec::new();
    let bytes = rules_block.as_bytes();
    let mut offset = 0usize;
    while let Some(relative) = rules_block[offset..].find("new") {
        let new_index = offset + relative;
        if !identifier_boundary(rules_block, new_index, new_index + "new".len()) {
            offset = new_index + "new".len();
            continue;
        }
        let Some(open) = rules_block[new_index + "new".len()..].find('{') else {
            break;
        };
        let open = new_index + "new".len() + open;
        let Some(close) = matching_brace_index(rules_block, open) else {
            break;
        };
        let object = &rules_block[open..=close];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            string_assignment_value(object, "id"),
            string_assignment_value(object, "decision"),
            string_assignment_value(object, "requirement"),
            string_assignment_value(object, "evidence"),
        ) {
            records.push(RuleRecord {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = close + 1;
        if offset >= bytes.len() {
            break;
        }
    }
    records
}

fn string_assignment_value(object: &str, field: &str) -> Option<String> {
    let mut offset = 0usize;
    let pattern = format!("{field} =");
    while let Some(relative) = object[offset..].find(&pattern) {
        let index = offset + relative;
        if !identifier_boundary(object, index, index + field.len()) {
            offset = index + field.len();
            continue;
        }
        let quote_index = object[index + pattern.len()..].find('"')? + index + pattern.len();
        return parse_csharp_string_literal_at(object, quote_index).map(|(value, _end)| value);
    }
    None
}

fn endpoint_rules_array_block(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let indexes = top_level_assignment_indexes(block, "rules");
    if indexes.is_empty() {
        errors.push("API rules must be a top-level assignment".to_string());
        return None;
    }
    if indexes.len() != 1 {
        errors.push("API rules must have exactly one top-level assignment".to_string());
        return None;
    }
    let array_start = block[indexes[0]..]
        .find('{')
        .map(|relative| indexes[0] + relative);
    let array_end = array_start.and_then(|start| matching_brace_index(block, start));
    let Some(array_start) = array_start else {
        errors.push("API rules must be a top-level rules = new[] initializer".to_string());
        return None;
    };
    let Some(array_end) = array_end else {
        errors.push("API rules must be a top-level rules = new[] initializer".to_string());
        return None;
    };
    if squash_whitespace(&block[indexes[0]..array_start]) != "rules = new[]" {
        errors.push("API rules must be a top-level rules = new[] initializer".to_string());
        return None;
    }
    if !block[array_end + 1..].trim_start().starts_with("}));") {
        errors.push("API rules must be a top-level rules = new[] initializer".to_string());
        return None;
    }
    Some(block[array_start..=array_end].to_string())
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing immutability air-gap compliance endpoint",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "immutability air-gap compliance doc missing endpoint",
    );
    for (phrase, message) in [
        (
            "No live provider calls.",
            "immutability air-gap compliance doc must prohibit provider calls",
        ),
        (
            "No live remediation.",
            "immutability air-gap compliance doc must prohibit live remediation",
        ),
        (
            "No repository, appliance, object storage, or retention mutation.",
            "immutability air-gap compliance doc must prohibit repository mutation",
        ),
        (
            "aggregate posture summaries",
            "immutability air-gap compliance doc must require aggregate summaries",
        ),
        (
            "current Veeam StoreOnce appliance class",
            "immutability air-gap compliance doc must mention StoreOnce posture",
        ),
        (
            "future Veeam hardened Linux repository class",
            "immutability air-gap compliance doc must mention hardened repository transition",
        ),
        (
            "backup copy isolation",
            "immutability air-gap compliance doc must mention backup copy isolation",
        ),
        (
            "immutable retention",
            "immutability air-gap compliance doc must mention immutable retention",
        ),
        (
            "capacity runway",
            "immutability air-gap compliance doc must mention capacity runway",
        ),
        (
            "rollback or fallback",
            "immutability air-gap compliance doc must mention rollback or fallback planning",
        ),
        (
            "year class",
            "immutability air-gap compliance doc must use year-class planning language",
        ),
    ] {
        expect(doc.contains(phrase), errors, message);
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(program);
    if starts.is_empty() {
        errors.push("API missing immutability air-gap compliance endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors.push(format!(
            "API immutability air-gap compliance endpoint {ENDPOINT} must declare exactly one route"
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
        .map(|relative| offset + relative)
        .find(|line_start| {
            let start = line_start + skip_horizontal_whitespace(&program[*line_start..], 0);
            parse_map_get(program, start).is_some()
        })
}

fn parse_map_get(program: &str, start: usize) -> Option<usize> {
    if !program[start..].starts_with("app") || !identifier_boundary(program, start, start + 3) {
        return None;
    }
    let mut cursor = skip_ascii_whitespace(program, start + 3);
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

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable}");
    let mut offset = 0usize;
    while let Some(relative) = program[offset..].find(&marker) {
        let start = offset + relative;
        if !identifier_boundary(program, start + "var ".len(), start + marker.len()) {
            offset = start + marker.len();
            continue;
        }
        let Some(open) = program[start..].find('{').map(|value| start + value) else {
            return None;
        };
        let Some(close) = matching_brace_index(program, open) else {
            return None;
        };
        return Some(csharp_string_literals(&program[open..=close]));
    }
    None
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let indexes = top_level_assignment_indexes(block, field);
    if indexes.is_empty() {
        errors.push(format!("API {field} must be a top-level array assignment"));
        return None;
    }
    if indexes.len() != 1 {
        errors.push(format!(
            "API {field} must have exactly one top-level assignment"
        ));
        return None;
    }
    let array_start = block[indexes[0]..]
        .find('{')
        .map(|relative| indexes[0] + relative);
    let array_end = array_start.and_then(|start| matching_brace_index(block, start));
    let Some(array_start) = array_start else {
        errors.push(format!("API {field} must be a top-level new[] initializer"));
        return None;
    };
    let Some(array_end) = array_end else {
        errors.push(format!("API {field} must be a top-level new[] initializer"));
        return None;
    };
    if squash_whitespace(&block[indexes[0]..array_start]) != format!("{field} = new[]") {
        errors.push(format!("API {field} must be a top-level new[] initializer"));
    }
    let suffix = block[array_end + 1..].trim_start();
    if !suffix.starts_with(',') && !suffix.starts_with('\n') {
        errors.push(format!("API {field} must be a top-level new[] initializer"));
    }
    Some(csharp_string_literals(&block[array_start..=array_end]))
}

fn expect_exact_string_assignment(
    block: &str,
    field: &str,
    value: &str,
    message: impl Into<String>,
    errors: &mut Vec<String>,
) {
    expect_exact_endpoint_assignment(block, field, &format!("\"{value}\""), message, errors);
}

fn expect_exact_endpoint_assignment(
    block: &str,
    field: &str,
    value: &str,
    message: impl Into<String>,
    errors: &mut Vec<String>,
) {
    let lines = top_level_assignment_lines(block, field);
    if lines.is_empty() {
        errors.push(format!("API {field} must be a top-level assignment"));
        return;
    }
    if lines.len() != 1 {
        errors.push(format!(
            "API {field} must have exactly one top-level assignment"
        ));
        return;
    }
    let expected = format!("{field} = {value},");
    expect(squash_whitespace(&lines[0]) == expected, errors, message);
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped_block = mask_csharp_string_literals(&csharp_without_comments(block));
    for field in top_level_assignment_fields(&stripped_block) {
        if !TOP_LEVEL_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected immutability air-gap compliance field {field}"
            ));
        }
    }
    for (field, depth) in assignment_fields_with_depth(&stripped_block) {
        if depth > 1 && TOP_LEVEL_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has nested immutability air-gap compliance field {field}"
            ));
            continue;
        }
        if !TOP_LEVEL_ENDPOINT_FIELDS.contains(&field.as_str()) && prohibited_endpoint_field(&field)
        {
            errors.push(format!(
                "API endpoint has prohibited immutability air-gap compliance field {field}"
            ));
        }
    }
    for field in endpoint_identifier_fields(&stripped_block) {
        if IGNORED_CSHARP_IDENTIFIERS.contains(&field.as_str())
            || TOP_LEVEL_ENDPOINT_FIELDS.contains(&field.as_str())
        {
            continue;
        }
        if prohibited_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited immutability air-gap compliance field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = mask_csharp_string_literals(block);
    for (field, _depth) in assignment_fields_with_depth(&stripped) {
        let Some(index) = assignment_value_index(&stripped, &field) else {
            continue;
        };
        if stripped[index..].trim_start().starts_with("true") && unsafe_true_field(&field) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn unsafe_true_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    [
        "live",
        "provider",
        "raw",
        "remediation",
        "repository",
        "credential",
        "secret",
        "token",
        "tenant",
        "object",
        "private",
        "user",
        "host",
        "mutation",
        "approval",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

fn assignment_value_index(source: &str, field: &str) -> Option<usize> {
    let pattern = format!("{field} =");
    source.find(&pattern).map(|index| index + pattern.len())
}

fn top_level_assignment_lines(block: &str, field: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut offset = 0usize;
    for line in block.lines() {
        if let Some(relative) = line.find(&format!("{field} =")) {
            let index = offset + relative;
            if brace_depth_at(block, index) == 1 {
                lines.push(line.trim().to_string());
            }
        }
        offset += line.len() + 1;
    }
    lines
}

fn top_level_assignment_indexes(block: &str, field: &str) -> Vec<usize> {
    let mut indexes = Vec::new();
    let mut offset = 0usize;
    let pattern = format!("{field} =");
    while let Some(relative) = block[offset..].find(&pattern) {
        let index = offset + relative;
        if identifier_boundary(block, index, index + field.len())
            && brace_depth_at(block, index) == 1
        {
            indexes.push(index);
        }
        offset = index + pattern.len();
    }
    indexes
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    assignment_fields_with_depth(block)
        .into_iter()
        .filter_map(|(field, depth)| (depth == 1).then_some(field))
        .collect()
}

fn assignment_fields_with_depth(block: &str) -> Vec<(String, usize)> {
    let mut fields = Vec::new();
    let bytes = block.as_bytes();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let Some((identifier, start, end)) = next_identifier(block, offset) else {
            break;
        };
        let value_index = skip_ascii_whitespace(block, end);
        if bytes.get(value_index) == Some(&b'=') {
            fields.push((identifier, brace_depth_at(block, start)));
            offset = value_index + 1;
        } else {
            offset = end;
        }
    }
    fields
}

fn endpoint_identifier_fields(block: &str) -> Vec<String> {
    let mut fields = Vec::new();
    for line in block.lines() {
        if line.contains('=') {
            continue;
        }
        let mut offset = 0usize;
        while let Some((identifier, _start, end)) = next_identifier(line, offset) {
            let next = skip_ascii_whitespace(line, end);
            if line.as_bytes().get(next) == Some(&b',') {
                fields.push(identifier);
            }
            offset = end;
        }
    }
    let mut offset = 0usize;
    while let Some(dot_relative) = block[offset..].find('.') {
        let dot = offset + dot_relative;
        let next = skip_ascii_whitespace(block, dot + 1);
        if let Some((identifier, _start, end)) = parse_identifier_at(block, next) {
            fields.push(identifier);
            offset = end;
        } else {
            offset = dot + 1;
        }
    }
    fields
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_provider_key(key) {
                    errors.push(format!("{path}.{key} contains prohibited provider field"));
                }
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            validate_quoted_provider_property_keys(text, path, errors);
            if path.ends_with(PROGRAM_PATH) {
                validate_program_prohibited_values(text, path, errors);
            } else if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
        }
        _ => {}
    }
}

fn validate_program_prohibited_values(program: &str, path: &str, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    for term in csharp_string_terms(&uncommented_program) {
        if prohibited_value(&term.value) {
            errors.push(format!("{path}:{} contains prohibited value", term.line));
        }
    }
    for composition in csharp_static_string_compositions(&uncommented_program) {
        if prohibited_value(&composition.value) {
            errors.push(format!(
                "{path}:{} contains prohibited value",
                composition.line
            ));
        }
    }
}

#[derive(Debug)]
struct StringTerm {
    value: String,
    line: usize,
}

fn csharp_static_string_compositions(text: &str) -> Vec<StringTerm> {
    let mut terms = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = text[offset..].find(".Concat") {
        let concat_index = offset + relative;
        let Some(open) = text[concat_index + ".Concat".len()..]
            .find('(')
            .map(|value| concat_index + ".Concat".len() + value)
        else {
            break;
        };
        let Some(close) = matching_paren_index(text, open) else {
            offset = open + 1;
            continue;
        };
        let literal_terms = csharp_string_terms(&text[open + 1..close]);
        if !literal_terms.is_empty() {
            terms.push(StringTerm {
                value: literal_terms
                    .iter()
                    .map(|term| term.value.as_str())
                    .collect(),
                line: text[..concat_index]
                    .chars()
                    .filter(|ch| *ch == '\n')
                    .count()
                    + 1,
            });
        }
        offset = close + 1;
    }
    terms
}

fn prohibited_value(value: &str) -> bool {
    let decoded = decode_csharp_unicode_escapes(value);
    contains_aws_key(value)
        || contains_private_key(value)
        || contains_url_scheme(value)
        || contains_private_ip(value)
        || contains_guid(value)
        || contains_secret_assignment(value)
        || prohibited_provider_assignment(value)
        || contains_aws_key(&decoded)
        || contains_private_key(&decoded)
        || contains_url_scheme(&decoded)
        || contains_private_ip(&decoded)
        || contains_guid(&decoded)
        || contains_secret_assignment(&decoded)
        || prohibited_provider_assignment(&decoded)
}

fn validate_quoted_provider_property_keys(value: &str, path: &str, errors: &mut Vec<String>) {
    let normalized = value.replace("\\\"", "\"");
    for key in quoted_keys(&normalized, '"')
        .into_iter()
        .chain(quoted_keys(value, '\''))
    {
        let decoded_key = csharp_unescape_string(&key);
        if prohibited_provider_key(&decoded_key) {
            errors.push(format!(
                "{path}.{decoded_key} contains prohibited provider field"
            ));
        }
    }
}

fn quoted_keys(value: &str, quote: char) -> Vec<String> {
    let mut keys = Vec::new();
    let mut cursor = 0usize;
    while let Some(open_relative) = value[cursor..].find(quote) {
        let open = cursor + open_relative;
        let Some(close_relative) = value[open + quote.len_utf8()..].find(quote) else {
            break;
        };
        let close = open + quote.len_utf8() + close_relative;
        let after = value[close + quote.len_utf8()..].trim_start();
        if after.starts_with(':') {
            keys.push(value[open + quote.len_utf8()..close].to_string());
        }
        cursor = close + quote.len_utf8();
    }
    keys
}

fn contains_private_key(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin ") && lower.contains("private key-----")
}

fn contains_aws_key(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.as_bytes().windows(20).any(|window| {
        window.starts_with(b"AKIA") && window.iter().all(|byte| byte.is_ascii_alphanumeric())
    })
}

fn contains_url_scheme(value: &str) -> bool {
    let Some(separator) = value.find("://") else {
        return false;
    };
    let prefix = &value[..separator];
    let scheme_start = prefix
        .char_indices()
        .rev()
        .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let scheme = &prefix[scheme_start..];
    scheme
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
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

fn contains_guid(value: &str) -> bool {
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

fn contains_secret_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    for term in [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ] {
        let mut offset = 0usize;
        while let Some(relative) = lower[offset..].find(term) {
            let index = offset + relative;
            let after = index + term.len();
            if !identifier_boundary(&lower, index, after) {
                offset = after;
                continue;
            }
            let separator = skip_ascii_whitespace(&lower, after);
            if matches!(lower.as_bytes().get(separator), Some(b':' | b'=')) {
                let value_index = skip_ascii_whitespace(&lower, separator + 1);
                if lower[value_index..]
                    .chars()
                    .next()
                    .is_some_and(|ch| !ch.is_whitespace())
                {
                    return true;
                }
            }
            offset = after;
        }
    }
    false
}

fn prohibited_provider_assignment(value: &str) -> bool {
    for separator in ['=', ':'] {
        let mut offset = 0usize;
        while let Some(relative) = value[offset..].find(separator) {
            let index = offset + relative;
            let prefix = &value[..index];
            let start = prefix
                .char_indices()
                .rev()
                .find(|(_, ch)| matches!(ch, ',' | ';' | '{' | '}' | '\n'))
                .map(|(pos, ch)| pos + ch.len_utf8())
                .unwrap_or(0);
            let key = prefix[start..].trim();
            let next = value[index + separator.len_utf8()..]
                .chars()
                .next()
                .unwrap_or(' ');
            if !key.is_empty() && !next.is_whitespace() && prohibited_provider_key(key) {
                return true;
            }
            offset = index + separator.len_utf8();
        }
    }
    false
}

fn prohibited_provider_key(field: &str) -> bool {
    !ALLOWED_PROVIDER_FIELD_KEYS.contains(&field)
        && !ALLOWED_PROVIDER_FIELD_KEYS.contains(&normalize_key(field).as_str())
        && prohibited_endpoint_field(field)
}

fn prohibited_endpoint_field(field: &str) -> bool {
    let normalized = normalize_key(field);
    PROHIBITED_ENDPOINT_TERMS
        .iter()
        .any(|term| normalized.contains(term))
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn csharp_string_terms(text: &str) -> Vec<StringTerm> {
    let mut terms = Vec::new();
    let mut index = 0usize;
    let mut line = 1usize;
    while index < text.len() {
        if let Some((value, end_index)) = csharp_string_literal_at(text, index) {
            terms.push(StringTerm { value, line });
            line += text[index..end_index]
                .chars()
                .filter(|ch| *ch == '\n')
                .count();
            index = end_index;
        } else {
            if text.as_bytes().get(index) == Some(&b'\n') {
                line += 1;
            }
            index += 1;
        }
    }
    terms
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    csharp_string_terms(text)
        .into_iter()
        .map(|term| term.value)
        .collect()
}

fn csharp_string_literal_at(text: &str, index: usize) -> Option<(String, usize)> {
    if !text.is_char_boundary(index) {
        return None;
    }
    if text[index..].starts_with("@\"") {
        let mut raw = String::new();
        let mut cursor = index + 2;
        while cursor < text.len() {
            let ch = text[cursor..].chars().next()?;
            if ch == '"' && text[cursor + ch.len_utf8()..].starts_with('"') {
                raw.push('"');
                cursor += 2;
                continue;
            }
            if ch == '"' {
                return Some((decode_csharp_unicode_escapes(&raw), cursor + 1));
            }
            raw.push(ch);
            cursor += ch.len_utf8();
        }
        return Some((decode_csharp_unicode_escapes(&raw), cursor));
    }
    if text.as_bytes().get(index) != Some(&b'"') {
        return None;
    }
    let mut raw = String::new();
    let mut cursor = index + 1;
    let mut escaped = false;
    while cursor < text.len() {
        let ch = text[cursor..].chars().next()?;
        if escaped {
            raw.push('\\');
            raw.push(ch);
            escaped = false;
            cursor += ch.len_utf8();
            continue;
        }
        if ch == '\\' {
            escaped = true;
            cursor += 1;
            continue;
        }
        if ch == '"' {
            return Some((csharp_unescape_string(&raw), cursor + 1));
        }
        raw.push(ch);
        cursor += ch.len_utf8();
    }
    Some((csharp_unescape_string(&raw), cursor))
}

fn parse_csharp_string_literal_at(source: &str, quote_index: usize) -> Option<(String, usize)> {
    csharp_string_literal_at(source, quote_index)
}

fn csharp_unescape_string(value: &str) -> String {
    let mut output = String::new();
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        let Some(next) = chars.next() else {
            output.push('\\');
            break;
        };
        match next {
            'u' => output.push(read_hex_escape(&mut chars, 4).unwrap_or_default()),
            'U' => output.push(read_hex_escape(&mut chars, 8).unwrap_or_default()),
            'x' => output.push(read_variable_hex_escape(&mut chars).unwrap_or_default()),
            '\'' => output.push('\''),
            '"' => output.push('"'),
            '\\' => output.push('\\'),
            '0' => output.push('\0'),
            'a' => output.push('\u{7}'),
            'b' => output.push('\u{8}'),
            'f' => output.push('\u{c}'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            'v' => output.push('\u{b}'),
            other => output.push(other),
        }
    }
    output
}

fn decode_csharp_unicode_escapes(value: &str) -> String {
    csharp_unescape_string(value)
}

fn read_hex_escape<I>(chars: &mut std::iter::Peekable<I>, width: usize) -> Option<char>
where
    I: Iterator<Item = char>,
{
    let mut hex = String::new();
    for _ in 0..width {
        let ch = chars.next()?;
        if !ch.is_ascii_hexdigit() {
            return None;
        }
        hex.push(ch);
    }
    char::from_u32(u32::from_str_radix(&hex, 16).ok()?)
}

fn read_variable_hex_escape<I>(chars: &mut std::iter::Peekable<I>) -> Option<char>
where
    I: Iterator<Item = char>,
{
    let mut hex = String::new();
    while hex.len() < 4 {
        let Some(ch) = chars.peek().copied() else {
            break;
        };
        if !ch.is_ascii_hexdigit() {
            break;
        }
        hex.push(ch);
        chars.next();
    }
    char::from_u32(u32::from_str_radix(&hex, 16).ok()?)
}

fn csharp_without_comments(text: &str) -> String {
    let masked = mask_csharp_string_literals(text);
    let mut output = text.as_bytes().to_vec();
    let bytes = masked.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'/') {
            let finish = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            for byte in output.iter_mut().take(finish).skip(index) {
                *byte = b' ';
            }
            index = finish;
        } else if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
            let finish = masked[index + 2..]
                .find("*/")
                .map(|relative| index + 2 + relative + 2)
                .unwrap_or(bytes.len());
            for byte in output.iter_mut().take(finish).skip(index) {
                if *byte != b'\n' {
                    *byte = b' ';
                }
            }
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn mask_csharp_string_literals(source: &str) -> String {
    let mut output = source.to_string();
    let mut index = 0usize;
    while index < source.len() {
        let Some((_, end)) = csharp_string_literal_at(source, index) else {
            index += 1;
            continue;
        };
        for (relative, ch) in source[index..end].char_indices() {
            if ch != '\n' {
                let start = index + relative;
                let finish = start + ch.len_utf8();
                output.replace_range(start..finish, &" ".repeat(ch.len_utf8()));
            }
        }
        index = end;
    }
    output
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let masked = mask_csharp_string_literals(text);
    let bytes = masked.as_bytes();
    if bytes.get(open_index) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open_index) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
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

fn matching_paren_index(text: &str, open_index: usize) -> Option<usize> {
    let masked = mask_csharp_string_literals(text);
    let bytes = masked.as_bytes();
    if bytes.get(open_index) != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open_index) {
        match byte {
            b'(' => depth += 1,
            b')' => {
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

fn brace_depth_at(source: &str, target_index: usize) -> usize {
    let masked = mask_csharp_string_literals(source);
    let mut depth = 0usize;
    for byte in masked.as_bytes().iter().take(target_index) {
        match byte {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

fn next_identifier(source: &str, offset: usize) -> Option<(String, usize, usize)> {
    let bytes = source.as_bytes();
    let mut index = offset;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            return parse_identifier_at(source, index);
        }
        index += 1;
    }
    None
}

fn parse_identifier_at(source: &str, index: usize) -> Option<(String, usize, usize)> {
    let bytes = source.as_bytes();
    if !is_identifier_start(*bytes.get(index)?) {
        return None;
    }
    let mut end = index + 1;
    while end < bytes.len() && is_identifier_part(bytes[end]) {
        end += 1;
    }
    Some((source[index..end].to_string(), index, end))
}

fn last_identifier(source: &str) -> Option<String> {
    let mut last = None;
    let mut offset = 0usize;
    while let Some((identifier, _start, end)) = next_identifier(source, offset) {
        last = Some(identifier);
        offset = end;
    }
    last
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_part(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn identifier_boundary(source: &str, start: usize, end: usize) -> bool {
    let bytes = source.as_bytes();
    let before = start == 0 || !is_identifier_part(bytes[start - 1]);
    let after = end >= bytes.len() || !is_identifier_part(bytes[end]);
    before && after
}

fn line_start_indexes(source: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    for (index, ch) in source.char_indices() {
        if ch == '\n' && index + 1 < source.len() {
            indexes.push(index + 1);
        }
    }
    indexes
}

fn skip_horizontal_whitespace(source: &str, offset: usize) -> usize {
    source[offset..]
        .bytes()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count()
}

fn skip_ascii_whitespace(source: &str, offset: usize) -> usize {
    let mut index = offset;
    while source
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn squash_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(text)) => vec![text.to_string()],
        _ => Vec::new(),
    }
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
    fn immutability_air_gap_endpoint_registration_detects_route_alias() {
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
    fn csharp_string_mask_handles_unicode_literals() {
        let source = "var label = \"réservoir\";\napp.MapGet(\"/x\", () => Results.Json(new { source = \"static-seed\" }));";

        let masked = mask_csharp_string_literals(source);

        assert_eq!(masked.len(), source.len());
        assert_eq!(masked.lines().count(), source.lines().count());
    }
}
