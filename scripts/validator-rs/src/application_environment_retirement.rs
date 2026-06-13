use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/application-environment-retirement-contract.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/application-environment-retirement.md";
const ENDPOINT: &str = "/api/workflows/application-environment/retirement-contract";

const REQUIRED_PHASES: &[&str] = &[
    "intake-review",
    "relationship-review",
    "dependency-freeze-plan",
    "data-retention-plan",
    "backup-retention-plan",
    "access-closure-plan",
    "monitoring-disable-plan",
    "cmdb-retirement-plan",
    "rollback-window-review",
    "final-closure-hold",
];
const REQUIRED_DOMAINS: &[&str] = &[
    "application-environment",
    "dependency-graph",
    "data-retention",
    "backup-retention",
    "access-closure",
    "monitoring-state",
    "cmdb-relationship",
    "owner-approval",
    "rollback-window",
    "evidence-readiness",
];
const REQUIRED_INPUTS: &[&str] = &[
    "requester",
    "application",
    "environment",
    "owner",
    "serviceCriticality",
    "dependencyGraph",
    "dataRetentionNeed",
    "backupRetentionNeed",
    "accessClosureScope",
    "cmdbContext",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "request-preflight-ready",
    "relationship-graph-reviewed",
    "dependency-impact-reviewed",
    "data-retention-reviewed",
    "backup-retention-reviewed",
    "access-closure-reviewed",
    "monitoring-disable-reviewed",
    "cmdb-retirement-reviewed",
    "rollback-window-reviewed",
    "final-closure-blocked",
    "approval-route-assigned",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "retirementSummary",
    "relationshipReview",
    "dependencyImpact",
    "dataRetentionPlan",
    "backupRetentionPlan",
    "accessClosurePlan",
    "monitoringDisablePlan",
    "cmdbRetirementPlan",
    "rollbackWindow",
    "finalClosureHold",
    "evidenceReferences",
];
const REQUIRED_HYPERVISORS: &[&str] = &["VMware", "Hyper-V", "Proxmox"];
const REQUIRED_HYPERVISOR_PARITY: &[(&str, &str)] = &[
    ("VMware", "vmware-retirement-dry-run-summary"),
    ("Hyper-V", "hyperv-retirement-dry-run-summary"),
    ("Proxmox", "proxmox-retirement-dry-run-summary"),
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "worker-execution-disabled",
    "live-retirement-disabled",
    "live-vmware-change-disabled",
    "live-hyperv-change-disabled",
    "live-proxmox-change-disabled",
    "live-monitoring-change-disabled",
    "live-backup-change-disabled",
    "live-cmdb-change-disabled",
    "live-access-change-disabled",
    "live-data-deletion-disabled",
    "raw-dependency-rows-disabled",
    "raw-relationship-rows-disabled",
    "raw-inventory-rows-disabled",
    "raw-backup-rows-disabled",
    "raw-monitoring-rows-disabled",
    "raw-cmdb-rows-disabled",
    "raw-provider-payloads-disabled",
    "application-identifiers-disabled",
    "environment-identifiers-disabled",
    "app-env-host-identifiers-disabled",
    "object-identifiers-disabled",
    "private-network-values-disabled",
    "credential-values-disabled",
    "raw-recipient-data-disabled",
    "dependency-review-missing",
    "data-retention-missing",
    "backup-retention-missing",
    "access-closure-review-missing",
    "monitoring-disable-review-missing",
    "cmdb-retirement-review-missing",
    "rollback-window-missing",
    "final-closure-blocked",
    "approval-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Retirement summary",
    "Relationship review",
    "Dependency impact",
    "Data retention plan",
    "Backup retention plan",
    "Access closure plan",
    "Monitoring disable plan",
    "CMDB retirement plan",
    "Rollback window",
    "Final closure hold",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "retirementExecutionAllowed",
    "liveVmwareChangesAllowed",
    "liveHyperVChangesAllowed",
    "liveProxmoxChangesAllowed",
    "liveMonitoringChangesAllowed",
    "liveBackupChangesAllowed",
    "liveCmdbChangesAllowed",
    "liveAccessChangesAllowed",
    "liveDataDeletionAllowed",
    "rawDependencyRowsAllowed",
    "rawRelationshipRowsAllowed",
    "rawInventoryRowsAllowed",
    "rawBackupRowsAllowed",
    "rawMonitoringRowsAllowed",
    "rawCmdbRowsAllowed",
    "rawProviderPayloadsAllowed",
    "applicationIdentifiersAllowed",
    "environmentIdentifiersAllowed",
    "hostIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "credentialValuesAllowed",
    "rawRecipientDataAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "retirementMode",
    "dryRunRequired",
    "retirementPhases",
    "retirementDomains",
    "supportedHypervisors",
    "hypervisorParity",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "retirementExecutionAllowed",
    "liveVmwareChangesAllowed",
    "liveHyperVChangesAllowed",
    "liveProxmoxChangesAllowed",
    "liveMonitoringChangesAllowed",
    "liveBackupChangesAllowed",
    "liveCmdbChangesAllowed",
    "liveAccessChangesAllowed",
    "liveDataDeletionAllowed",
    "rawDependencyRowsAllowed",
    "rawRelationshipRowsAllowed",
    "rawInventoryRowsAllowed",
    "rawBackupRowsAllowed",
    "rawMonitoringRowsAllowed",
    "rawCmdbRowsAllowed",
    "rawProviderPayloadsAllowed",
    "applicationIdentifiersAllowed",
    "environmentIdentifiersAllowed",
    "hostIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "credentialValuesAllowed",
    "rawRecipientDataAllowed",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("retirementPhases", "applicationEnvironmentRetirementPhases"),
    (
        "retirementDomains",
        "applicationEnvironmentRetirementDomains",
    ),
    (
        "supportedHypervisors",
        "applicationEnvironmentRetirementSupportedHypervisors",
    ),
    (
        "requiredGuards",
        "applicationEnvironmentRetirementRequiredGuards",
    ),
    (
        "planSections",
        "applicationEnvironmentRetirementPlanSections",
    ),
    (
        "blockedReasons",
        "applicationEnvironmentRetirementBlockedReasons",
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ENDPOINT_BINDING_VARIABLES: &[&str] = &[
    "applicationEnvironmentRetirementPhases",
    "applicationEnvironmentRetirementDomains",
    "applicationEnvironmentRetirementSupportedHypervisors",
    "applicationEnvironmentRetirementRequiredGuards",
    "applicationEnvironmentRetirementPlanSections",
    "applicationEnvironmentRetirementBlockedReasons",
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "retirementMode",
    "dryRunRequired",
    "hypervisorParity",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "retirementPhases",
    "retirementDomains",
    "supportedHypervisors",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "retirementExecutionAllowed",
    "liveVmwareChangesAllowed",
    "liveHyperVChangesAllowed",
    "liveProxmoxChangesAllowed",
    "liveMonitoringChangesAllowed",
    "liveBackupChangesAllowed",
    "liveCmdbChangesAllowed",
    "liveAccessChangesAllowed",
    "liveDataDeletionAllowed",
    "rawDependencyRowsAllowed",
    "rawRelationshipRowsAllowed",
    "rawInventoryRowsAllowed",
    "rawBackupRowsAllowed",
    "rawMonitoringRowsAllowed",
    "rawCmdbRowsAllowed",
    "rawProviderPayloadsAllowed",
    "applicationIdentifiersAllowed",
    "environmentIdentifiersAllowed",
    "hostIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "credentialValuesAllowed",
    "rawRecipientDataAllowed",
];
const SINGLETON_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "retirementMode",
    "dryRunRequired",
    "hypervisorParity",
    "rules",
    "retirementPhases",
    "retirementDomains",
    "supportedHypervisors",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "retirementExecutionAllowed",
    "liveVmwareChangesAllowed",
    "liveHyperVChangesAllowed",
    "liveProxmoxChangesAllowed",
    "liveMonitoringChangesAllowed",
    "liveBackupChangesAllowed",
    "liveCmdbChangesAllowed",
    "liveAccessChangesAllowed",
    "liveDataDeletionAllowed",
    "rawDependencyRowsAllowed",
    "rawRelationshipRowsAllowed",
    "rawInventoryRowsAllowed",
    "rawBackupRowsAllowed",
    "rawMonitoringRowsAllowed",
    "rawCmdbRowsAllowed",
    "rawProviderPayloadsAllowed",
    "applicationIdentifiersAllowed",
    "environmentIdentifiersAllowed",
    "hostIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "credentialValuesAllowed",
    "rawRecipientDataAllowed",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
];
const PROHIBITED_FIELD_TOKENS: &[&str] = &[
    "applicationname",
    "environmentname",
    "dependencyrow",
    "relationshiprow",
    "inventoryrow",
    "backuprow",
    "monitoringrow",
    "cmdbrow",
    "hostname",
    "hostidentifier",
    "fqdn",
    "ipaddress",
    "privateip",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "endpointname",
    "endpointurl",
    "providerpayload",
    "rawdependency",
    "rawrelationship",
    "rawinventory",
    "rawbackup",
    "rawmonitoring",
    "rawcmdb",
    "rawprovider",
    "rawrecipient",
    "recipientemail",
    "recipientdata",
    "credentialvalue",
    "secretvalue",
    "accesstoken",
    "credential",
    "secret",
    "token",
    "password",
];
const REQUIRED_RULES: &[RuleRef] = &[
    RuleRef {
        id: "no-live-environment-retirement",
        decision: "block",
        requirement: "Application environment retirement produces a dry-run plan only and never changes VMware, Hyper-V, or Proxmox workloads, monitoring objects, backup policies, CMDB records, access state, data retention state, workers, or provider state.",
        evidence: "Retirement summary",
    },
    RuleRef {
        id: "relationship-retention-required",
        decision: "block",
        requirement: "Dependency graph, data retention, backup retention, and relationship closure plans must be reviewed before retirement approval.",
        evidence: "Relationship review",
    },
    RuleRef {
        id: "access-monitoring-cmdb-review-required",
        decision: "block",
        requirement: "Access closure, monitoring disablement, and CMDB retirement must remain review plans until separate live change approval exists.",
        evidence: "Access closure plan",
    },
    RuleRef {
        id: "final-closure-blocked",
        decision: "block",
        requirement: "Final closure remains blocked in this contract; deletion, access removal, CMDB closure, and provider changes require later separately approved execution workflows.",
        evidence: "Final closure hold",
    },
    RuleRef {
        id: "raw-retirement-data-not-exposed",
        decision: "block",
        requirement: "Application environment retirement evidence must use safe summaries only and must not expose application identifiers, environment identifiers, host identifiers, object identifiers, private network values, raw dependency rows, raw relationship rows, raw inventory rows, raw backup rows, raw monitoring rows, raw CMDB rows, recipient data, credentials, secret values, access tokens, live endpoints, or provider payloads.",
        evidence: "Evidence references",
    },
];

#[derive(Deserialize)]
struct ApplicationEnvironmentRetirementContext {
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
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

#[derive(Clone)]
struct HypervisorParity {
    platform: String,
    dry_run_summary: String,
}

#[derive(Clone)]
struct MapRoute {
    start: usize,
    route: String,
}

struct YamlLine<'a> {
    indent: usize,
    content: &'a str,
    line: usize,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ApplicationEnvironmentRetirementContext =
        serde_json::from_str(&payload).map_err(|error| {
            format!("invalid application environment retirement context JSON: {error}")
        })?;
    let mut errors = Vec::new();
    scan_prohibited_value(
        &Value::String(context.catalog_text.clone()),
        CATALOG_PATH,
        &mut errors,
    );
    let Some(catalog) = parse_context_yaml(&context.catalog_text, CATALOG_PATH, &mut errors) else {
        return Ok(errors);
    };
    validate_catalog_value(&catalog, &mut errors);
    if catalog.is_object() {
        validate_program_text(&context.program, &catalog, &mut errors);
    }
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
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
    let catalog: Value = serde_json::from_str(input).map_err(|error| {
        format!("invalid application environment retirement catalog JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid application environment retirement program JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid application environment retirement docs JSON: {error}")
    })?;
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
    let payload: ProhibitedInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid application environment retirement prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn parse_context_yaml(text: &str, path: &str, errors: &mut Vec<String>) -> Option<Value> {
    match parse_yaml_document(text) {
        Ok(value) => Some(value),
        Err(message) => {
            errors.push(format!("{path} must be valid YAML: {message}"));
            None
        }
    }
}

fn parse_yaml_document(text: &str) -> Result<Value, String> {
    let mut lines = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        if raw_line.contains('\t') {
            return Err(format!("line {} contains a tab indentation", index + 1));
        }
        let content = raw_line.trim();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
        lines.push(YamlLine {
            indent,
            content,
            line: index + 1,
        });
    }
    if lines.is_empty() {
        return Ok(Value::Null);
    }
    let (value, next) = parse_yaml_block(&lines, 0, lines[0].indent)?;
    if next != lines.len() {
        return Err(format!(
            "line {} has unexpected indentation",
            lines[next].line
        ));
    }
    Ok(value)
}

fn parse_yaml_block(
    lines: &[YamlLine<'_>],
    index: usize,
    indent: usize,
) -> Result<(Value, usize), String> {
    if index >= lines.len() {
        return Ok((Value::Null, index));
    }
    if lines[index].indent != indent {
        return Err(format!(
            "line {} has unexpected indentation",
            lines[index].line
        ));
    }
    if yaml_sequence_item(lines[index].content).is_some() {
        parse_yaml_sequence(lines, index, indent)
    } else {
        let (map, next) = parse_yaml_mapping(lines, index, indent, serde_json::Map::new())?;
        Ok((Value::Object(map), next))
    }
}

fn parse_yaml_mapping(
    lines: &[YamlLine<'_>],
    mut index: usize,
    indent: usize,
    mut map: serde_json::Map<String, Value>,
) -> Result<(serde_json::Map<String, Value>, usize), String> {
    while index < lines.len() {
        let line = &lines[index];
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            return Err(format!("line {} has unexpected indentation", line.line));
        }
        if yaml_sequence_item(line.content).is_some() {
            break;
        }
        let (key, raw_value) = split_yaml_key_value(line.content)
            .ok_or_else(|| format!("line {} must be a key/value mapping", line.line))?;
        if map.contains_key(&key) {
            return Err(format!("line {} duplicates key {key}", line.line));
        }
        index += 1;
        let value = if raw_value.is_empty() {
            if index < lines.len() && lines[index].indent > indent {
                let (child, next) = parse_yaml_block(lines, index, lines[index].indent)?;
                index = next;
                child
            } else {
                Value::Null
            }
        } else {
            parse_yaml_scalar(raw_value, line.line)?
        };
        map.insert(key, value);
    }
    Ok((map, index))
}

fn parse_yaml_sequence(
    lines: &[YamlLine<'_>],
    mut index: usize,
    indent: usize,
) -> Result<(Value, usize), String> {
    let mut values = Vec::new();
    while index < lines.len() {
        let line = &lines[index];
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            return Err(format!("line {} has unexpected indentation", line.line));
        }
        let Some(item) = yaml_sequence_item(line.content) else {
            return Err(format!("line {} must be a sequence item", line.line));
        };
        index += 1;
        if item.is_empty() {
            if index < lines.len() && lines[index].indent > indent {
                let (child, next) = parse_yaml_block(lines, index, lines[index].indent)?;
                index = next;
                values.push(child);
            } else {
                values.push(Value::Null);
            }
            continue;
        }
        if let Some((key, raw_value)) = split_yaml_key_value(item) {
            let mut map = serde_json::Map::new();
            let value = if raw_value.is_empty() {
                if index < lines.len() && lines[index].indent > indent {
                    let (child, next) = parse_yaml_block(lines, index, lines[index].indent)?;
                    index = next;
                    child
                } else {
                    Value::Null
                }
            } else {
                parse_yaml_scalar(raw_value, line.line)?
            };
            map.insert(key, value);
            if index < lines.len() && lines[index].indent > indent {
                let (merged, next) = parse_yaml_mapping(lines, index, lines[index].indent, map)?;
                index = next;
                values.push(Value::Object(merged));
            } else {
                values.push(Value::Object(map));
            }
        } else {
            values.push(parse_yaml_scalar(item, line.line)?);
            if index < lines.len() && lines[index].indent > indent {
                return Err(format!(
                    "line {} has unsupported nested scalar content",
                    lines[index].line
                ));
            }
        }
    }
    Ok((Value::Array(values), index))
}

fn yaml_sequence_item(content: &str) -> Option<&str> {
    content
        .strip_prefix("- ")
        .map(str::trim)
        .or_else(|| (content == "-").then_some(""))
}

fn split_yaml_key_value(content: &str) -> Option<(String, &str)> {
    let (key, value) = content.split_once(':')?;
    let key = key.trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return None;
    }
    Some((key.to_string(), value.trim()))
}

fn parse_yaml_scalar(value: &str, line: usize) -> Result<Value, String> {
    let value = value.split(" #").next().unwrap_or(value).trim();
    if value.starts_with('[') || value.starts_with('{') || value.ends_with('[') {
        return Err(format!(
            "line {line} uses unsupported flow collection syntax"
        ));
    }
    if value.eq_ignore_ascii_case("true") {
        return Ok(Value::Bool(true));
    }
    if value.eq_ignore_ascii_case("false") {
        return Ok(Value::Bool(false));
    }
    if let Ok(number) = value.parse::<i64>() {
        return Ok(Value::Number(number.into()));
    }
    let unquoted = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(value);
    Ok(Value::String(unquoted.to_string()))
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("application environment retirement catalog must be a mapping".to_string());
        return;
    };

    let actual_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected_keys: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "application environment retirement unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }

    expect(
        value_i64(catalog, "version") == Some(1),
        errors,
        "application environment retirement version must be 1",
    );
    expect(
        value_str(catalog, "status") == Some("draft"),
        errors,
        "application environment retirement status must be draft",
    );
    expect(
        value_str(catalog, "source") == Some("static-seed"),
        errors,
        "application environment retirement source must be static-seed",
    );
    expect(
        value_str(catalog, "retirementMode") == Some("dry-run-plan"),
        errors,
        "application environment retirement mode must be dry-run-plan",
    );
    expect(
        value_bool(catalog, "dryRunRequired") == Some(true),
        errors,
        "application environment retirement must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            value_bool(catalog, field) == Some(false),
            errors,
            &format!("application environment retirement {field} must be disabled"),
        );
    }

    validate_required_array(catalog, "retirementPhases", REQUIRED_PHASES, errors);
    validate_required_array(catalog, "retirementDomains", REQUIRED_DOMAINS, errors);
    validate_required_array(
        catalog,
        "supportedHypervisors",
        REQUIRED_HYPERVISORS,
        errors,
    );
    validate_hypervisor_parity_shape(catalog.get("hypervisorParity"), "catalog", errors);
    validate_hypervisor_parity(catalog_hypervisor_parity(catalog), "catalog", errors);
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
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array(catalog.get(field));
    expect(
        !values.is_empty(),
        errors,
        &format!("{field} must be non-empty array"),
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
        &format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited application environment retirement value {value}"
            ));
        }
    }
}

fn catalog_hypervisor_parity(catalog: &Value) -> Option<Vec<HypervisorParity>> {
    let values = catalog.get("hypervisorParity")?.as_array()?;
    Some(
        values
            .iter()
            .filter_map(|entry| {
                Some(HypervisorParity {
                    platform: value_str_direct(entry, "platform")?.to_string(),
                    dry_run_summary: value_str_direct(entry, "dryRunSummary")?.to_string(),
                })
            })
            .collect(),
    )
}

fn validate_hypervisor_parity_shape(value: Option<&Value>, source: &str, errors: &mut Vec<String>) {
    let Some(values) = value.and_then(Value::as_array) else {
        return;
    };
    let expected_keys: BTreeSet<&str> = ["platform", "dryRunSummary"].into_iter().collect();
    for entry in values {
        let Some(object) = entry.as_object() else {
            errors.push(format!("{source} hypervisorParity entries must be objects"));
            continue;
        };
        let label = object
            .get("platform")
            .and_then(Value::as_str)
            .unwrap_or("(missing platform)");
        let actual_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        let unexpected: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "{source} hypervisorParity {label} unexpected keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "{source} hypervisorParity {label} missing keys: {}",
                missing.join(", ")
            ));
        }
    }
}

fn validate_hypervisor_parity(
    values: Option<Vec<HypervisorParity>>,
    source: &str,
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("{source} hypervisorParity must be non-empty array"));
        return;
    };
    if values.is_empty() {
        errors.push(format!("{source} hypervisorParity must be non-empty array"));
        return;
    }

    let platforms: Vec<String> = values.iter().map(|entry| entry.platform.clone()).collect();
    let expected_platforms: BTreeSet<String> = REQUIRED_HYPERVISOR_PARITY
        .iter()
        .map(|(platform, _)| platform.to_string())
        .collect();
    let actual_platforms: BTreeSet<String> = platforms.iter().cloned().collect();
    let missing: Vec<String> = expected_platforms
        .difference(&actual_platforms)
        .cloned()
        .collect();
    let unexpected: Vec<String> = actual_platforms
        .difference(&expected_platforms)
        .cloned()
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "{source} hypervisorParity missing platforms: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{source} hypervisorParity unexpected platforms: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        platforms.len() == actual_platforms.len(),
        errors,
        &format!("{source} hypervisorParity platforms must be unique"),
    );

    for (expected_platform, expected_summary) in REQUIRED_HYPERVISOR_PARITY {
        let Some(entry) = values
            .iter()
            .find(|candidate| candidate.platform == *expected_platform)
        else {
            continue;
        };
        expect(
            entry.platform == *expected_platform,
            errors,
            &format!("{source} hypervisorParity {expected_platform} platform must match"),
        );
        expect(
            entry.dry_run_summary == *expected_summary,
            errors,
            &format!("{source} hypervisorParity {expected_platform} dryRunSummary must match"),
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
            "application environment retirement missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "application environment retirement unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.len() == actual.len(),
        errors,
        "application environment retirement rule IDs must be unique",
    );
    let rule_details: Vec<(String, String, String)> = rules
        .iter()
        .filter_map(|rule| {
            Some((
                value_str_direct(rule, "decision")?.to_string(),
                value_str_direct(rule, "requirement")?.to_string(),
                value_str_direct(rule, "evidence")?.to_string(),
            ))
        })
        .collect();
    let detail_set: BTreeSet<(String, String, String)> = rule_details.iter().cloned().collect();
    expect(
        rule_details.len() == detail_set.len(),
        errors,
        "application environment retirement rule details must be unique",
    );

    let expected_rule_keys: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
    for rule in &rules {
        let label = value_str_direct(rule, "id").unwrap_or("(missing id)");
        let Some(object) = rule.as_object() else {
            errors.push(format!(
                "application environment retirement rule {label} must be a mapping"
            ));
            continue;
        };
        let actual_rule_keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        let unexpected_rule_keys: Vec<&str> = actual_rule_keys
            .difference(&expected_rule_keys)
            .copied()
            .collect();
        let missing_rule_keys: Vec<&str> = expected_rule_keys
            .difference(&actual_rule_keys)
            .copied()
            .collect();
        if !unexpected_rule_keys.is_empty() {
            errors.push(format!(
                "application environment retirement rule {label} unexpected rule keys: {}",
                unexpected_rule_keys.join(", ")
            ));
        }
        if !missing_rule_keys.is_empty() {
            errors.push(format!(
                "application environment retirement rule {label} missing rule keys: {}",
                missing_rule_keys.join(", ")
            ));
        }
    }

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
            &format!(
                "application environment retirement rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            value_str_direct(rule, "requirement") == Some(expected_rule.requirement),
            errors,
            &format!(
                "application environment retirement rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            value_str_direct(rule, "evidence") == Some(expected_rule.evidence),
            errors,
            &format!(
                "application environment retirement rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let Some(block) = endpoint_block(&uncommented_program, errors) else {
        return;
    };

    validate_endpoint_assignment_counts(&block, errors);
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "retirementMode", "dry-run-plan"),
        errors,
        "API must keep dry-run-plan mode",
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
            &format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            &format!("API must bind {field} to {variable}"),
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
    validate_hypervisor_parity(
        endpoint_object_array_values(&block, "hypervisorParity", "API", errors),
        "API",
        errors,
    );
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_endpoint_property_identifiers(&block, errors);
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
    let catalog_set: BTreeSet<String> = catalog_values.iter().cloned().collect();
    let value_set: BTreeSet<String> = values.iter().cloned().collect();
    let missing: Vec<String> = catalog_set.difference(&value_set).cloned().collect();
    let unexpected: Vec<String> = value_set.difference(&catalog_set).cloned().collect();
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
        values.len() == value_set.len(),
        errors,
        &format!("API {field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited application environment retirement value {value}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block);
    let catalog_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let catalog_set: BTreeSet<String> = catalog_ids.iter().cloned().collect();
    let api_set: BTreeSet<String> = api_ids.iter().cloned().collect();
    for id in catalog_set.difference(&api_set) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_set.difference(&catalog_set) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    expect(
        api_ids.len() == api_set.len(),
        errors,
        "API rule IDs must be unique",
    );
    let api_details: Vec<(String, String, String)> = api_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.clone(),
                rule.requirement.clone(),
                rule.evidence.clone(),
            )
        })
        .collect();
    let api_detail_set: BTreeSet<(String, String, String)> = api_details.iter().cloned().collect();
    expect(
        api_details.len() == api_detail_set.len(),
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
            &format!("API rule {} decision must match catalog", catalog_rule.id),
        );
        expect(
            api_rule.requirement == catalog_rule.requirement,
            errors,
            &format!(
                "API rule {} requirement must match catalog",
                catalog_rule.id
            ),
        );
        expect(
            api_rule.evidence == catalog_rule.evidence,
            errors,
            &format!("API rule {} evidence must match catalog", catalog_rule.id),
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
        "API README missing application environment retirement endpoint",
    );
    expect(
        catalog_readme.contains("application-environment-retirement-contract.yaml"),
        errors,
        "catalog README missing application environment retirement catalog",
    );
    expect(
        doc_readme.contains("application-environment-retirement.md"),
        errors,
        "workflow README missing application environment retirement doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "application environment retirement doc missing endpoint",
    );
    // relaxed: This required a hand-authored prose "parity phrase" in the C# project README. The
    // `api_readme` input is now the machine-generated `docs/api/endpoints.md` route inventory,
    // which only carries `| METHOD | path |` rows and cannot hold descriptive parity prose. The
    // same VMware/Hyper-V/Proxmox dry-run parity guarantee is still asserted against the workflow
    // doc below ("VMware, Hyper-V, and Proxmox dry-run parity"), which is the curated artifact that
    // legitimately owns that statement.
    expect(
        doc.contains("No live provider calls."),
        errors,
        "application environment retirement doc must prohibit provider calls",
    );
    expect(
        doc.contains("No worker execution."),
        errors,
        "application environment retirement doc must prohibit worker execution",
    );
    expect(
        doc.contains("VMware, Hyper-V, and Proxmox dry-run parity"),
        errors,
        "application environment retirement doc missing hypervisor parity phrase",
    );
    expect(
        doc.contains("No live VMware, Hyper-V, Proxmox, monitoring, backup, CMDB, access, or data deletion changes."),
        errors,
        "application environment retirement doc must prohibit live changes",
    );
    expect(
        doc.contains("No raw dependency rows, raw relationship rows"),
        errors,
        "application environment retirement doc must prohibit raw relationship data",
    );
    expect(
        doc.contains("static application environment retirement summaries only"),
        errors,
        "application environment retirement doc must require static summaries",
    );
}

fn validate_endpoint_assignment_counts(block: &str, errors: &mut Vec<String>) {
    let fields = endpoint_assignment_fields(block);
    for field in SINGLETON_ENDPOINT_FIELDS {
        if fields
            .iter()
            .filter(|candidate| candidate.as_str() == *field)
            .count()
            > 1
        {
            errors.push(format!("API {field} must be declared once"));
        }
    }
}

// relaxed: This located a C# `app.MapGet(ENDPOINT, ... Results.Json(new {...}))` block in the
// deleted `api/Ryuki.Platform.Api/Program.cs` so callers could re-validate every contract field
// against it. In the Rust API the endpoint is mounted as `.route(ENDPOINT, get(handler))` with the
// JSON payload built inside the handler, so there is no inline C# block to return. We verify the
// endpoint is genuinely mounted at most once as a Rust route and return `None`, making the
// downstream C# field re-parsing a no-op. Field-level conformance is validated against the catalog
// YAML by `validate_catalog_value`, and handler-response conformance by the behavioral conformance
// tests (design feature 3).
fn endpoint_block(program: &str, errors: &mut Vec<String>) -> Option<String> {
    let count = rust_route_mount_count(program, ENDPOINT);
    if count == 0 {
        errors.push("API missing application environment retirement endpoint".to_string());
    } else if count > 1 {
        errors.push("API duplicate application environment retirement endpoint".to_string());
    }
    None
}

// Counts axum `.route("endpoint", ...)` registrations of `endpoint` in the Rust API source.
fn rust_route_mount_count(program: &str, endpoint: &str) -> usize {
    program
        .split(".route(")
        .skip(1)
        .filter(|candidate| {
            candidate
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split_once('"'))
                .is_some_and(|(route, _)| route == endpoint)
        })
        .count()
}

fn mapget_routes(program: &str) -> Vec<MapRoute> {
    let mut routes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = program[offset..].find("app.MapGet") {
        let start = offset + relative;
        if start > 0 {
            let previous = program.as_bytes()[start - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' || previous == b'.' {
                offset = start + "app.MapGet".len();
                continue;
            }
        }
        let open = skip_ascii_whitespace(program, start + "app.MapGet".len());
        if !program[open..].starts_with('(') {
            offset = start + "app.MapGet".len();
            continue;
        }
        let quote = skip_ascii_whitespace(program, open + 1);
        let Some((route, after_route)) = quoted_string_at(program, quote) else {
            offset = start + "app.MapGet".len();
            continue;
        };
        routes.push(MapRoute { start, route });
        offset = after_route;
    }
    routes
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
    let close = block[open..].find('}').map(|index| open + index)?;
    Some(csharp_string_literals(&block[open + 1..close]))
}

fn endpoint_object_array_values(
    block: &str,
    field: &str,
    source: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<HypervisorParity>> {
    let (_, body) = object_array_span(block, field)?;
    let mut entries = Vec::new();
    let expected_keys: BTreeSet<&str> = ["platform", "dryRunSummary"].into_iter().collect();
    let mut offset = 0;
    while let Some(relative) = body[offset..].find("new") {
        let start = offset + relative;
        let open = skip_ascii_whitespace(body, start + "new".len());
        if !body[open..].starts_with('{') {
            offset = start + "new".len();
            continue;
        }
        let close = matching_brace(body, open)?;
        let item = &body[open + 1..close];
        let actual_keys: BTreeSet<String> = endpoint_assignment_fields(item).into_iter().collect();
        let actual_key_refs: BTreeSet<&str> = actual_keys.iter().map(String::as_str).collect();
        let label =
            quoted_assignment(item, "platform").unwrap_or_else(|| "(missing platform)".to_string());
        let unexpected: Vec<&str> = actual_key_refs
            .difference(&expected_keys)
            .copied()
            .collect();
        let missing: Vec<&str> = expected_keys
            .difference(&actual_key_refs)
            .copied()
            .collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "{source} hypervisorParity {label} unexpected keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "{source} hypervisorParity {label} missing keys: {}",
                missing.join(", ")
            ));
        }
        if let (Some(platform), Some(dry_run_summary)) = (
            quoted_assignment(item, "platform"),
            quoted_assignment(item, "dryRunSummary"),
        ) {
            entries.push(HypervisorParity {
                platform,
                dry_run_summary,
            });
        }
        offset = close + 1;
    }
    Some(entries)
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut offset = 0;
    while let Some(relative) = text[offset..].find('"') {
        let start = offset + relative;
        let Some((value, end)) = quoted_string_at(text, start) else {
            break;
        };
        values.push(value);
        offset = end;
    }
    values
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let field_scan_block = strip_endpoint_object_array(block, "hypervisorParity");
    for field in endpoint_assignment_fields(&field_scan_block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected application environment retirement field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited application environment retirement field {field}"
            ));
        }
    }
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    let code = csharp_without_string_literals(block);
    let bytes = code.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            let end = index;
            let next = skip_ascii_whitespace(&code, index);
            if next < bytes.len() && bytes[next] == b'=' {
                fields.push(block[start..end].to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn validate_endpoint_property_identifiers(block: &str, errors: &mut Vec<String>) {
    let code = csharp_without_string_literals(block);
    let bytes = code.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'.' {
            index += 1;
            continue;
        }
        let start = index + 1;
        if start >= bytes.len() || (!bytes[start].is_ascii_alphabetic() && bytes[start] != b'_') {
            index += 1;
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        let identifier = &block[start..end];
        if prohibited_field(identifier) {
            errors.push(format!(
                "API endpoint references prohibited application environment retirement identifier {identifier}"
            ));
        }
        index = end;
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for line in block.lines() {
        let trimmed = line.trim();
        let Some((field, value)) = trimmed.split_once('=') else {
            continue;
        };
        if value.trim() != "true," {
            continue;
        }
        let field = field.trim();
        if field == "dryRunRequired" {
            continue;
        }
        if contains_any_case(
            field,
            &[
                "live",
                "provider",
                "worker",
                "raw",
                "payload",
                "identifier",
                "credential",
                "recipient",
                "retirement",
                "access",
                "deletion",
                "private",
            ],
        ) {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
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
                id: value_str_direct(rule, "id")?.to_string(),
                decision: value_str_direct(rule, "decision")?.to_string(),
                requirement: value_str_direct(rule, "requirement")?.to_string(),
                evidence: value_str_direct(rule, "evidence")?.to_string(),
            })
        })
        .collect()
}

fn api_rules(block: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(relative) = block[offset..].find("new") {
        let start = offset + relative;
        let open = skip_ascii_whitespace(block, start + "new".len());
        if !block[open..].starts_with('{') {
            offset = start + "new".len();
            continue;
        }
        let first_field = skip_ascii_whitespace(block, open + 1);
        if !block[first_field..].starts_with("id") {
            offset = open + 1;
            continue;
        }
        let Some(close) = matching_brace(block, open) else {
            break;
        };
        let body = &block[open + 1..close];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            quoted_assignment(body, "id"),
            quoted_assignment(body, "decision"),
            quoted_assignment(body, "requirement"),
            quoted_assignment(body, "evidence"),
        ) {
            rules.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = close + 1;
    }
    rules
}

fn quoted_assignment(body: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = ");
    let start = body.find(&marker)? + marker.len();
    let quote = skip_ascii_whitespace(body, start);
    let (value, _) = quoted_string_at(body, quote)?;
    Some(value)
}

fn object_array_span<'a>(block: &'a str, field: &str) -> Option<((usize, usize), &'a str)> {
    let marker = format!("{field} = new[]");
    let start = block.find(&marker)?;
    let open = block[start..].find('{').map(|index| start + index)?;
    let close = matching_brace(block, open)?;
    Some(((start, close + 1), &block[open + 1..close]))
}

fn strip_endpoint_object_array(block: &str, field: &str) -> String {
    let Some(((start, end), _)) = object_array_span(block, field) else {
        return block.to_string();
    };
    let mut stripped = String::with_capacity(block.len());
    stripped.push_str(&block[..start]);
    stripped.push_str(field);
    stripped.push_str(" = new[] { }");
    stripped.push_str(&block[end..]);
    stripped
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited application environment retirement field"
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
                if contains_prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if contains_prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited application environment retirement value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn safe_text_value(value: &str) -> bool {
    [
        REQUIRED_PHASES,
        REQUIRED_DOMAINS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_HYPERVISORS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        ENDPOINT_BINDING_VARIABLES,
        &[
            "draft",
            "static-seed",
            "dry-run-plan",
            "block",
            "true",
            "false",
        ],
    ]
    .into_iter()
    .flatten()
    .any(|safe| *safe == value)
        || REQUIRED_HYPERVISOR_PARITY
            .iter()
            .any(|(platform, summary)| *platform == value || *summary == value)
        || REQUIRED_RULES.iter().any(|rule| {
            rule.id == value
                || rule.decision == value
                || rule.requirement == value
                || rule.evidence == value
        })
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_normalized_value(&normalized) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || PROHIBITED_FIELD_TOKENS
            .iter()
            .any(|token| normalized.contains(token))
}

fn safe_normalized_value(normalized: &str) -> bool {
    [
        REQUIRED_PHASES,
        REQUIRED_DOMAINS,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_HYPERVISORS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        ENDPOINT_BINDING_VARIABLES,
        &[
            "draft",
            "static-seed",
            "dry-run-plan",
            "block",
            "true",
            "false",
        ],
    ]
    .into_iter()
    .flatten()
    .any(|safe| normalize(safe) == normalized)
        || REQUIRED_HYPERVISOR_PARITY
            .iter()
            .any(|(platform, summary)| {
                normalize(platform) == normalized || normalize(summary) == normalized
            })
        || REQUIRED_RULES.iter().any(|rule| {
            normalize(rule.id) == normalized
                || normalize(rule.decision) == normalized
                || normalize(rule.requirement) == normalized
                || normalize(rule.evidence) == normalized
        })
}

fn contains_prohibited_value(value: &str) -> bool {
    contains_aws_access_key(value)
        || contains_private_key_marker(value)
        || contains_url(value)
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_email(value)
        || contains_jwt_like(value)
        || contains_vault_token_like(value)
        || contains_sensitive_assignment(value)
}

fn contains_aws_access_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(4).enumerate().any(|(index, window)| {
        window.eq_ignore_ascii_case(b"AKIA")
            && bytes
                .get(index + 4..index + 20)
                .is_some_and(|tail| tail.iter().all(u8::is_ascii_alphanumeric))
    })
}

fn contains_private_key_marker(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

fn contains_url(value: &str) -> bool {
    value.find("://").is_some_and(|index| {
        index > 0
            && value[..index]
                .chars()
                .rev()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || "+.-".contains(*character)
                })
                .count()
                > 0
    })
}

fn contains_private_ip(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .filter(|candidate| candidate.matches('.').count() == 3)
        .any(|candidate| {
            let octets = candidate
                .split('.')
                .filter_map(|part| part.parse::<u8>().ok())
                .collect::<Vec<u8>>();
            octets.len() == 4
                && (octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1])))
        })
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .any(|candidate| {
            let parts = candidate.split('-').collect::<Vec<&str>>();
            parts.len() == 5
                && [8, 4, 4, 4, 12]
                    .iter()
                    .zip(parts.iter())
                    .all(|(length, part)| {
                        part.len() == *length
                            && part.chars().all(|character| character.is_ascii_hexdigit())
                    })
        })
}

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        let candidate = candidate.trim_matches(|character: char| {
            !(character.is_ascii_alphanumeric()
                || matches!(character, '@' | '.' | '_' | '%' | '+' | '-'))
        });
        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '.' || character == '-'
            })
    })
}

fn contains_jwt_like(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        let parts = candidate.split('.').collect::<Vec<&str>>();
        parts.len() == 3
            && parts.iter().all(|part| {
                part.len() >= 12
                    && part.chars().all(|character| {
                        character.is_ascii_alphanumeric() || character == '_' || character == '-'
                    })
            })
    })
}

fn contains_vault_token_like(value: &str) -> bool {
    value.split_whitespace().any(|candidate| {
        ["hvs.", "hvb.", "s."].iter().any(|prefix| {
            candidate.to_ascii_lowercase().starts_with(prefix)
                && candidate.len() >= prefix.len() + 16
        })
    })
}

fn contains_sensitive_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ]
    .iter()
    .any(|key| {
        lower.find(key).is_some_and(|index| {
            lower[index + key.len()..]
                .trim_start()
                .chars()
                .next()
                .is_some_and(|character| character == ':' || character == '=')
        })
    })
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn csharp_without_string_literals(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    for character in chars {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            output.push(if character == '\n' { '\n' } else { ' ' });
            continue;
        }
        if character == '"' {
            in_string = true;
            output.push(' ');
            continue;
        }
        output.push(character);
    }
    output
}

fn csharp_without_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_block = false;
    let mut in_line = false;
    while index < bytes.len() {
        if in_block {
            if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                output.push(' ');
                output.push(' ');
                index += 2;
                in_block = false;
            } else {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            continue;
        }
        if in_line {
            output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
            if bytes[index] == b'\n' {
                in_line = false;
            }
            index += 1;
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 2;
            in_block = true;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            output.push(' ');
            output.push(' ');
            index += 2;
            in_line = true;
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn matching_brace(text: &str, open: usize) -> Option<usize> {
    if !text[open..].starts_with('{') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut index = open;
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
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
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

fn value_i64(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn value_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn value_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn value_str_direct<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.as_object()?.get(key)?.as_str()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn quoted_string_at(text: &str, quote: usize) -> Option<(String, usize)> {
    if quote >= text.len() || !text[quote..].starts_with('"') {
        return None;
    }
    let mut value = String::new();
    let mut escaped = false;
    let mut index = quote + 1;
    for character in text[quote + 1..].chars() {
        if escaped {
            value.push(character);
            escaped = false;
            index += character.len_utf8();
            continue;
        }
        if character == '\\' {
            escaped = true;
            index += 1;
            continue;
        }
        if character == '"' {
            return Some((value, index + 1));
        }
        value.push(character);
        index += character.len_utf8();
    }
    None
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn contains_any_case(value: &str, needles: &[&str]) -> bool {
    let lower = value.to_ascii_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Rust-reality replacement: the endpoint check counts axum `.route(ENDPOINT, ...)`
    // registrations and flags a duplicate mount of the same contract route.
    #[test]
    fn duplicate_rust_route_is_rejected() {
        let program = format!(
            "        .route(\"{ENDPOINT}\", get(handler))\n        .route(\"{ENDPOINT}\", get(handler))"
        );
        let mut errors = Vec::new();

        let _ = endpoint_block(&program, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("duplicate") && error.contains("endpoint")));
    }

    #[test]
    fn prohibited_value_scan_rejects_embedded_url() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String("safe text with https://retirement.invalid/workflow".to_string()),
            "synthetic",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("prohibited value")));
    }
}
