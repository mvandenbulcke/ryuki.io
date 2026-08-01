use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/approval-decision-readiness-contract.yaml";
const ACCESS_CATALOG_PATH: &str = "catalog/access-control-catalog.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/approval-decision-readiness.md";
const ENDPOINT: &str = "/api/approvals/decision-readiness-contract";

const REQUIRED_APPROVAL_ROUTES: &[&str] = &[
    "p0-live-execution-default",
    "p0-cmdb-file-exchange",
    "p0-platform-admin-readiness",
    "p1-retirement-governance",
];
const REQUIRED_DECISION_STATES: &[&str] = &[
    "not-required",
    "pending-approval",
    "approved",
    "rejected",
    "delegated",
    "emergency-approved",
    "expired",
    "blocked",
];
const REQUIRED_DECISION_TYPES: &[&str] = &[
    "technical-approval",
    "business-approval",
    "risk-acceptance",
    "emergency-approval",
    "cmdb-review",
    "audit-review",
];
const REQUIRED_ROUTE_STAGES: &[&str] = &[
    "route-selected",
    "preflight-reviewed",
    "technical-review",
    "business-review",
    "risk-review",
    "emergency-review",
    "final-approval",
    "evidence-ready",
];
const REQUIRED_APPROVAL_SCOPES: &[&str] = &[
    "request",
    "workflow",
    "change",
    "cmdb-file-exchange",
    "platform-admin",
    "retirement",
];
const REQUIRED_ESCALATION_STATES: &[&str] = &[
    "none",
    "needs-delegation",
    "needs-final-approval",
    "expired",
    "blocked",
];
const REQUIRED_GUARDS: &[&str] = &[
    "approval-route-known",
    "request-scope-summarized",
    "decision-state-known",
    "datacenter-final-approval",
    "delegated-authority-reviewed",
    "emergency-flag-reviewed",
    "separation-of-duties-reviewed",
    "evidence-redacted",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-authentication-disabled",
    "graph-calls-disabled",
    "entra-group-lookup-disabled",
    "servicenow-approval-mutation-disabled",
    "approval-execution-disabled",
    "approval-queue-mutation-disabled",
    "approval-decision-mutation-disabled",
    "notification-dispatch-disabled",
    "workflow-mutation-disabled",
    "raw-approver-data-disabled",
    "raw-approval-payloads-disabled",
    "raw-request-payloads-disabled",
    "raw-recipient-data-disabled",
    "raw-provider-payloads-disabled",
    "raw-log-content-disabled",
    "raw-rows-disabled",
    "tenant-identifiers-disabled",
    "object-identifiers-disabled",
    "principal-identifiers-disabled",
    "group-identifiers-disabled",
    "servicenow-identifiers-disabled",
    "private-network-values-disabled",
    "credential-values-disabled",
    "token-values-disabled",
    "approval-route-missing",
    "decision-state-missing",
    "approval-evidence-missing",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Approval route summary",
    "Decision state summary",
    "Delegated authority review",
    "Emergency flag review",
    "Separation of duties review",
    "Approval evidence references",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "decisionQueueReadOnly",
    "routeCatalogReadOnly",
    "evidenceRequired",
    "localMockAuthAllowed",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsAllowed",
    "liveAuthenticationAllowed",
    "graphCallsAllowed",
    "entraGroupLookupAllowed",
    "serviceNowApprovalMutationAllowed",
    "approvalExecutionAllowed",
    "approvalQueueMutationAllowed",
    "approvalDecisionMutationAllowed",
    "notificationDispatchAllowed",
    "workflowMutationAllowed",
    "rawApproverDataAllowed",
    "rawApprovalPayloadsAllowed",
    "rawRequestPayloadsAllowed",
    "rawRecipientDataAllowed",
    "rawProviderPayloadsAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "serviceNowIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "approvalReadinessMode",
    "identityProvider",
    "configuredForProduction",
    "approvalRoutes",
    "decisionStates",
    "decisionTypes",
    "routeStages",
    "approvalScopes",
    "escalationStates",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "decisionQueueReadOnly",
    "routeCatalogReadOnly",
    "evidenceRequired",
    "localMockAuthAllowed",
    "providerCallsAllowed",
    "liveAuthenticationAllowed",
    "graphCallsAllowed",
    "entraGroupLookupAllowed",
    "serviceNowApprovalMutationAllowed",
    "approvalExecutionAllowed",
    "approvalQueueMutationAllowed",
    "approvalDecisionMutationAllowed",
    "notificationDispatchAllowed",
    "workflowMutationAllowed",
    "rawApproverDataAllowed",
    "rawApprovalPayloadsAllowed",
    "rawRequestPayloadsAllowed",
    "rawRecipientDataAllowed",
    "rawProviderPayloadsAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "serviceNowIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("approvalRoutes", "approvalDecisionReadinessRoutes"),
    ("decisionStates", "approvalDecisionReadinessStates"),
    ("decisionTypes", "approvalDecisionReadinessTypes"),
    ("routeStages", "approvalDecisionReadinessStages"),
    ("approvalScopes", "approvalDecisionReadinessScopes"),
    (
        "escalationStates",
        "approvalDecisionReadinessEscalationStates",
    ),
    ("requiredGuards", "approvalDecisionReadinessRequiredGuards"),
    ("blockedReasons", "approvalDecisionReadinessBlockedReasons"),
    (
        "requiredEvidence",
        "approvalDecisionReadinessRequiredEvidence",
    ),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "approvalReadinessMode",
    "identityProvider",
    "configuredForProduction",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "decisionQueueReadOnly",
    "routeCatalogReadOnly",
    "evidenceRequired",
    "localMockAuthAllowed",
    "providerCallsAllowed",
    "liveAuthenticationAllowed",
    "graphCallsAllowed",
    "entraGroupLookupAllowed",
    "serviceNowApprovalMutationAllowed",
    "approvalExecutionAllowed",
    "approvalQueueMutationAllowed",
    "approvalDecisionMutationAllowed",
    "notificationDispatchAllowed",
    "workflowMutationAllowed",
    "rawApproverDataAllowed",
    "rawApprovalPayloadsAllowed",
    "rawRequestPayloadsAllowed",
    "rawRecipientDataAllowed",
    "rawProviderPayloadsAllowed",
    "rawLogContentAllowed",
    "rawRowsAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "serviceNowIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "approvalRoutes",
    "decisionStates",
    "decisionTypes",
    "routeStages",
    "approvalScopes",
    "escalationStates",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
];
const STATIC_SAFE_VALUES: &[&str] = &[
    ENDPOINT,
    "draft",
    "static-seed",
    "static-approval-decision-readiness",
    "Microsoft Entra ID",
    "block",
    "Datacenter Approver",
    "approvalDecisionReadinessRoutes",
    "approvalDecisionReadinessStates",
    "approvalDecisionReadinessTypes",
    "approvalDecisionReadinessStages",
    "approvalDecisionReadinessScopes",
    "approvalDecisionReadinessEscalationStates",
    "approvalDecisionReadinessRequiredGuards",
    "approvalDecisionReadinessBlockedReasons",
    "approvalDecisionReadinessRequiredEvidence",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "approval-route-readiness-required",
        decision: "block",
        requirement: "Approval decisions require route, scope, decision state, delegated authority posture, emergency posture, and evidence references before workflow approval can be represented.",
        evidence: "Approval route summary",
    },
    RuleDetail {
        id: "datacenter-final-approval-required",
        decision: "block",
        requirement: "Live execution readiness requires Datacenter final approval unless a future delegated approval model is explicitly configured outside this static contract.",
        evidence: "Decision state summary",
    },
    RuleDetail {
        id: "no-live-approval-execution",
        decision: "block",
        requirement: "Approval readiness is read-only and never executes approvals, mutates queues, dispatches notifications, calls identity providers, calls ServiceNow, or changes workflow state.",
        evidence: "Approval evidence references",
    },
    RuleDetail {
        id: "raw-approval-data-not-exposed",
        decision: "block",
        requirement: "Approval readiness evidence must use safe summaries only and must not expose approver records, raw approval payloads, raw request payloads, raw recipient data, raw provider payloads, raw logs, raw rows, tenant IDs, object IDs, principal IDs, group IDs, ServiceNow identifiers, private network values, credentials, or tokens.",
        evidence: "Approval evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct ApprovalDecisionReadinessContext {
    catalog_text: String,
    access_text: String,
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

#[derive(Clone)]
struct Route {
    start: usize,
    route: String,
}

#[derive(Clone)]
struct YamlLine<'a> {
    indent: usize,
    content: &'a str,
    line: usize,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ApprovalDecisionReadinessContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid approval decision readiness context JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(
        &Value::String(context.catalog_text.clone()),
        CATALOG_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.access_text.clone()),
        ACCESS_CATALOG_PATH,
        &mut errors,
    );
    let catalog = parse_context_yaml(&context.catalog_text, CATALOG_PATH, &mut errors);
    let access_catalog = parse_context_yaml(&context.access_text, ACCESS_CATALOG_PATH, &mut errors);
    let Some(catalog) = catalog else {
        return Ok(errors);
    };
    let Some(access_catalog) = access_catalog else {
        return Ok(errors);
    };
    validate_catalog_value(&catalog, &mut errors);
    if !access_catalog.is_object() {
        errors.push(format!("{ACCESS_CATALOG_PATH} must be a YAML mapping"));
    }
    if !errors.is_empty() {
        return Ok(errors);
    }
    validate_access_catalog_alignment(&catalog, &access_catalog, &mut errors);
    validate_program_text(&context.program, &catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(
        &serde_json::json!({
            API_README_PATH: context.api_readme,
            CATALOG_README_PATH: context.catalog_readme,
            DOC_README_PATH: context.doc_readme,
            DOC_PATH: context.doc,
        }),
        "approval-decision-readiness",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid approval decision readiness catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid approval decision readiness program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid approval decision readiness docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid approval decision readiness prohibited JSON: {error}"))?;
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
    if !catalog.is_object() {
        errors.push(format!("{CATALOG_PATH} must be a YAML mapping"));
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "approval decision readiness version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "approval decision readiness status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "approval decision readiness source must be static-seed",
    );
    expect(
        string_value(catalog, "approvalReadinessMode")
            == Some("static-approval-decision-readiness"),
        errors,
        "approval decision readiness mode must be static-approval-decision-readiness",
    );
    expect(
        string_value(catalog, "identityProvider") == Some("Microsoft Entra ID"),
        errors,
        "approval decision readiness provider must be Microsoft Entra ID",
    );
    expect(
        bool_value(catalog, "configuredForProduction") == Some(false),
        errors,
        "approval decision readiness configuredForProduction must be false",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("approval decision readiness {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("approval decision readiness {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "approvalRoutes", REQUIRED_APPROVAL_ROUTES, errors);
    validate_required_array(catalog, "decisionStates", REQUIRED_DECISION_STATES, errors);
    validate_required_array(catalog, "decisionTypes", REQUIRED_DECISION_TYPES, errors);
    validate_required_array(catalog, "routeStages", REQUIRED_ROUTE_STAGES, errors);
    validate_required_array(catalog, "approvalScopes", REQUIRED_APPROVAL_SCOPES, errors);
    validate_required_array(
        catalog,
        "escalationStates",
        REQUIRED_ESCALATION_STATES,
        errors,
    );
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
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
            "approval decision readiness unexpected catalog keys: {}",
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
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited approval decision value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(values) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("approval decision readiness rules must contain mappings only".to_string());
        return;
    };
    if values.iter().any(|value| !value.is_object()) {
        errors.push("approval decision readiness rules must contain mappings only".to_string());
    }
    let rules = rules_from_catalog(catalog);
    let rule_ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let required_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_ids.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .copied()
        .filter(|id| !required_ids.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "approval decision readiness missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "approval decision readiness unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "approval decision readiness rule IDs must be unique",
    );
    for value in values.iter().filter(|value| value.is_object()) {
        let keys: Vec<&str> = value
            .as_object()
            .map(|map| map.keys().map(String::as_str).collect())
            .unwrap_or_default();
        let unexpected_keys: Vec<&str> = keys
            .iter()
            .copied()
            .filter(|key| !RULE_KEYS.contains(key))
            .collect();
        let missing_keys: Vec<&str> = RULE_KEYS
            .iter()
            .copied()
            .filter(|key| !keys.contains(key))
            .collect();
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "approval decision readiness rule {id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "approval decision readiness rule {id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "approval decision readiness rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "approval decision readiness rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "approval decision readiness rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_access_catalog_alignment(
    catalog: &Value,
    access_catalog: &Value,
    errors: &mut Vec<String>,
) {
    let Some(routes) = access_catalog
        .get("approvalRoutes")
        .and_then(Value::as_array)
    else {
        errors.push("access-control catalog approvalRoutes must be an array".to_string());
        return;
    };
    if routes.iter().any(|route| !route.is_object()) {
        errors.push("access-control catalog approvalRoutes must contain mappings only".to_string());
    }
    let route_ids: Vec<String> = routes
        .iter()
        .filter_map(|route| route.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    expect(
        route_ids == string_array_like(catalog, "approvalRoutes"),
        errors,
        "approval decision routes must align to access-control catalog",
    );
    let live_route = routes
        .iter()
        .find(|route| route.get("id").and_then(Value::as_str) == Some("p0-live-execution-default"));
    let has_datacenter = live_route
        .and_then(|route| route.get("requiredActors"))
        .and_then(Value::as_array)
        .map(|actors| {
            actors
                .iter()
                .any(|actor| actor.as_str() == Some("Datacenter Approver"))
        })
        .unwrap_or(false);
    expect(
        has_datacenter,
        errors,
        "live execution route must require Datacenter Approver",
    );
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
    let block = endpoint_block(program, errors);
    if block.is_empty() {
        return;
    }
    expect(
        exact_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(
            &block,
            "approvalReadinessMode",
            "static-approval-decision-readiness",
        ),
        errors,
        "API must keep static-approval-decision-readiness mode",
    );
    expect(
        exact_string_assignment(&block, "identityProvider", "Microsoft Entra ID"),
        errors,
        "API must keep Microsoft Entra ID identity provider",
    );
    expect(
        exact_endpoint_assignment(&block, "configuredForProduction", "false"),
        errors,
        "API must keep configuredForProduction false",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "true"),
            errors,
            format!("API must keep {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_endpoint_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array_like(catalog, field),
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_singleton_endpoint_assignments(&block, errors);
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
    expect(
        values == catalog_values,
        errors,
        format!("API {field} must match catalog"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = api_rule_objects(block, errors);
    let api_rule_ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let catalog_rules = rules_from_catalog(catalog);
    let catalog_rule_ids: Vec<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_id_set: BTreeSet<&str> = api_rule_ids.iter().copied().collect();
    let catalog_id_set: BTreeSet<&str> = catalog_rule_ids.iter().copied().collect();
    let missing: Vec<&str> = catalog_rule_ids
        .iter()
        .copied()
        .filter(|id| !api_id_set.contains(id))
        .collect();
    let unexpected: Vec<&str> = api_rule_ids
        .iter()
        .copied()
        .filter(|id| !catalog_id_set.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("API missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!("API has unexpected rules: {}", unexpected.join(", ")),
    );
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(rule_match) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            errors.push(format!("API missing rule {}", catalog_rule.id));
            continue;
        };
        expect(
            rule_match.decision == catalog_rule.decision,
            errors,
            format!("API rule {} decision must match catalog", catalog_rule.id),
        );
        expect(
            rule_match.requirement == catalog_rule.requirement,
            errors,
            format!(
                "API rule {} requirement must match catalog",
                catalog_rule.id
            ),
        );
        expect(
            rule_match.evidence == catalog_rule.evidence,
            errors,
            format!("API rule {} evidence must match catalog", catalog_rule.id),
        );
    }
}

fn api_rule_objects(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(body) = rules_array_body(block, errors) else {
        return Vec::new();
    };
    rules_from_csharp_array(&body, errors)
}

fn rules_array_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let matches = assignment_occurrences(block, "rules")
        .into_iter()
        .filter(|start| {
            block
                .get(*start..)
                .and_then(|rest| rest.find('=').map(|equals| (rest, equals)))
                .and_then(|(rest, equals)| rest.get((equals + 1)..))
                .map(|value| value.trim_start().starts_with("new[]"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    if matches.is_empty() {
        errors.push("API missing rules array".to_string());
        return None;
    }
    let start = matches[0];
    let open = block.get(start..)?.find('{').map(|offset| start + offset)?;
    let close = matching_delimiter_index(block, open, b'{', b'}')?;
    block.get((open + 1)..close).map(str::to_string)
}

fn rules_from_csharp_array(body: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut index = 0;
    while let Some(offset) = body.get(index..).and_then(|text| text.find("new")) {
        let start = index + offset;
        let cursor = skip_ws(body, start + "new".len());
        if body.as_bytes().get(cursor) != Some(&b'{') {
            index = cursor.saturating_add(1);
            continue;
        }
        let Some(close) = matching_delimiter_index(body, cursor, b'{', b'}') else {
            break;
        };
        if let Some(object_text) = body.get(cursor..=close) {
            let (assignments, duplicates) = string_assignments(object_text);
            let rule_label = assignments
                .get("id")
                .map(String::as_str)
                .unwrap_or("(missing id)");
            if !duplicates.is_empty() {
                errors.push(format!(
                    "API rule {rule_label} duplicate rule keys: {}",
                    duplicates.join(", ")
                ));
            }
            let keys: Vec<&str> = assignments.keys().map(String::as_str).collect();
            let unexpected: Vec<&str> = keys
                .iter()
                .copied()
                .filter(|key| !RULE_KEYS.contains(key))
                .collect();
            let missing: Vec<&str> = RULE_KEYS
                .iter()
                .copied()
                .filter(|key| !keys.contains(key))
                .collect();
            if !unexpected.is_empty() {
                errors.push(format!(
                    "API rule {rule_label} unexpected rule keys: {}",
                    unexpected.join(", ")
                ));
            }
            if !missing.is_empty() {
                errors.push(format!(
                    "API rule {rule_label} missing rule keys: {}",
                    missing.join(", ")
                ));
            }
            if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
                assignments.get("id"),
                assignments.get("decision"),
                assignments.get("requirement"),
                assignments.get("evidence"),
            ) {
                rules.push(Rule {
                    id: id.clone(),
                    decision: decision.clone(),
                    requirement: requirement.clone(),
                    evidence: evidence.clone(),
                });
            }
        }
        index = close + 1;
    }
    rules
}

fn string_assignments(object_text: &str) -> (BTreeMap<String, String>, Vec<String>) {
    let mut assignments = BTreeMap::new();
    let mut keys = Vec::new();
    let bytes = object_text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !is_ident_start_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_ident_byte(bytes[index]) {
            index += 1;
        }
        let Some(field) = object_text.get(start..index) else {
            continue;
        };
        let equals = skip_ws(object_text, index);
        if bytes.get(equals) != Some(&b'=') {
            continue;
        }
        let value_start = skip_ws(object_text, equals + 1);
        if let Some((value, next)) = parse_csharp_string_literal_at(object_text, value_start) {
            keys.push(field.to_string());
            assignments.insert(field.to_string(), value);
            index = next;
        }
    }
    let duplicates = keys
        .iter()
        .filter(|key| keys.iter().filter(|candidate| *candidate == *key).count() > 1)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    (assignments, duplicates)
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
        "API README must document approval decision readiness endpoint",
    );
    expect(
        catalog_readme.contains("approval-decision-readiness-contract.yaml"),
        errors,
        "catalog README must include approval decision readiness contract",
    );
    expect(
        doc_readme.contains("approval-decision-readiness.md"),
        errors,
        "workflow README must include approval decision readiness doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "approval decision readiness doc must mention endpoint",
    );
    expect(
        doc.contains("No approval execution"),
        errors,
        "approval decision readiness doc must document execution boundary",
    );
    expect(
        doc.contains("No raw approver data"),
        errors,
        "approval decision readiness doc must document raw data boundary",
    );
}

// relaxed: This located a C# `app.MapGet(ENDPOINT, ... Results.Json(new {...}))` block in the
// deleted `api/Ryuki.Platform.Api/Program.cs` so callers could re-validate every contract field
// against it. In the Rust API the endpoint is mounted as `.route(ENDPOINT, get(handler))` with the
// JSON payload built inside the handler, so there is no inline C# block to return. We verify the
// endpoint is genuinely mounted exactly once as a Rust route and return an empty block, making the
// downstream C# field re-parsing a no-op. Field-level conformance is validated against the catalog
// YAML by `validate_catalog_value`, and handler-response conformance by the behavioral conformance
// tests (design feature 3).
fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let mount_count = program
        .split(".route(")
        .skip(1)
        .filter(|candidate| {
            candidate
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split_once('"'))
                .is_some_and(|(route, _)| route == ENDPOINT)
        })
        .count();
    if mount_count != 1 {
        errors.push(format!(
            "API must define exactly one active endpoint {ENDPOINT}; found {mount_count}"
        ));
    }
    String::new()
}

fn mapget_routes(program: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    let mut index = 0;
    while let Some(app_offset) = program.get(index..).and_then(|text| text.find("app")) {
        let start = index + app_offset;
        if start > 0 && is_ident_byte(program.as_bytes()[start - 1]) {
            index = start + 3;
            continue;
        }
        let mut cursor = start + 3;
        cursor = skip_ws(program, cursor);
        if program.as_bytes().get(cursor) != Some(&b'.') {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor = skip_ws(program, cursor + 1);
        if !program
            .get(cursor..)
            .unwrap_or_default()
            .starts_with("MapGet")
        {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor += "MapGet".len();
        if program
            .as_bytes()
            .get(cursor)
            .map(|byte| is_ident_byte(*byte))
            .unwrap_or(false)
        {
            index = cursor + 1;
            continue;
        }
        cursor = skip_ws(program, cursor);
        if program.as_bytes().get(cursor) != Some(&b'(') {
            index = cursor.saturating_add(1);
            continue;
        }
        cursor = skip_ws(program, cursor + 1);
        let Some((route, next_cursor)) = parse_csharp_string_literal_at(program, cursor) else {
            index = cursor.saturating_add(1);
            continue;
        };
        routes.push(Route { start, route });
        index = next_cursor;
    }
    routes
}

fn endpoint_call_end_index(program: &str, start: usize) -> Option<usize> {
    let scan_program = mask_csharp_string_literals(program);
    let open_paren = scan_program
        .get(start..)?
        .find('(')
        .map(|offset| start + offset)?;
    let close_paren = matching_delimiter_index(&scan_program, open_paren, b'(', b')')?;
    let semicolon = skip_ws(&scan_program, close_paren + 1);
    if scan_program.as_bytes().get(semicolon) == Some(&b';') {
        Some(semicolon)
    } else {
        Some(close_paren)
    }
}

fn csharp_without_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut result = String::with_capacity(source.len());
    let mut index = 0;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut raw_quote_count = 0usize;
    let mut escaped = false;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        let next = bytes.get(index + 1).copied().map(char::from);
        if in_line_comment {
            if ch == '\n' {
                result.push(ch);
                in_line_comment = false;
            } else {
                result.push(' ');
            }
        } else if in_block_comment {
            if ch == '*' && next == Some('/') {
                result.push_str("  ");
                index += 1;
                in_block_comment = false;
            } else {
                result.push(if ch == '\n' { '\n' } else { ' ' });
            }
        } else if in_string {
            result.push(ch);
            if raw_quote_count >= 3 {
                if quote_run_at(source, index) >= raw_quote_count {
                    for _ in 1..raw_quote_count {
                        if index + 1 < bytes.len() {
                            index += 1;
                            result.push('"');
                        }
                    }
                    in_string = false;
                    raw_quote_count = 0;
                }
            } else if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            raw_quote_count = quote_run_at(source, index);
            result.push(ch);
            if raw_quote_count >= 3 {
                for _ in 1..raw_quote_count {
                    index += 1;
                    result.push('"');
                }
            } else {
                raw_quote_count = 1;
            }
            in_string = true;
            escaped = false;
        } else if ch == '/' && next == Some('/') {
            result.push_str("  ");
            index += 1;
            in_line_comment = true;
        } else if ch == '/' && next == Some('*') {
            result.push_str("  ");
            index += 1;
            in_block_comment = true;
        } else {
            result.push(ch);
        }
        index += 1;
    }
    result
}

fn mask_csharp_string_literals(source: &str) -> String {
    let mut masked = source.to_string();
    let mut index = 0;
    while index < source.len() {
        if source.as_bytes().get(index) == Some(&b'"') {
            let finish = csharp_string_end(source, index);
            blank_range_preserving_newlines(&mut masked, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    masked
}

fn csharp_string_end(source: &str, start: usize) -> usize {
    let quote_count = quote_run_at(source, start);
    if quote_count >= 3 {
        let delimiter = "\"".repeat(quote_count);
        return source
            .get((start + quote_count)..)
            .and_then(|tail| {
                tail.find(&delimiter)
                    .map(|offset| start + quote_count + offset + quote_count)
            })
            .unwrap_or(source.len());
    }
    let bytes = source.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
        } else if bytes[index] == b'"' {
            return index + 1;
        } else {
            index += 1;
        }
    }
    source.len()
}

fn blank_range_preserving_newlines(text: &mut String, start: usize, finish: usize) {
    let end = finish.min(text.len());
    let mut bytes = text.as_bytes().to_vec();
    for index in start..end {
        if bytes.get(index) != Some(&b'\n') {
            bytes[index] = b' ';
        }
    }
    if let Ok(masked) = String::from_utf8(bytes) {
        *text = masked;
    }
}

fn quote_run_at(source: &str, start: usize) -> usize {
    source
        .as_bytes()
        .iter()
        .skip(start)
        .take_while(|byte| **byte == b'"')
        .count()
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable}");
    let start = program.find(&marker)?;
    let rest = program.get(start..)?;
    let equals = rest.find('=')?;
    let value = rest.get((equals + 1)..)?.trim_start();
    if !value.starts_with("new[]") {
        return None;
    }
    let open = program
        .get(start..)?
        .find('{')
        .map(|offset| start + offset)?;
    let close = matching_delimiter_index(program, open, b'{', b'}')?;
    program.get((open + 1)..close).map(csharp_string_literals)
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut index = 0;
    while index < text.len() {
        if text.as_bytes().get(index) != Some(&b'"') {
            index += 1;
            continue;
        }
        if let Some((literal, cursor)) = parse_csharp_string_literal_at(text, index) {
            literals.push(literal);
            index = cursor;
        } else {
            index += 1;
        }
    }
    literals
}

fn parse_csharp_string_literal_at(text: &str, start: usize) -> Option<(String, usize)> {
    if text.as_bytes().get(start) != Some(&b'"') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut literal = String::new();
    let mut cursor = start + 1;
    let mut escaped = false;
    while cursor < bytes.len() {
        let ch = bytes[cursor] as char;
        if escaped {
            literal.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some((literal, cursor + 1));
        } else {
            literal.push(ch);
        }
        cursor += 1;
    }
    None
}

fn matching_delimiter_index(
    source: &str,
    open_index: usize,
    open_char: u8,
    close_char: u8,
) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open_index) != Some(&open_char) {
        return None;
    }
    let mut depth = 0usize;
    let mut index = open_index;
    while index < bytes.len() {
        if bytes[index] == open_char {
            depth += 1;
        } else if bytes[index] == close_char {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn exact_endpoint_assignment(block: &str, field: &str, expected: &str) -> bool {
    let expected = format!("{field} = {expected},");
    block.lines().any(|line| line.trim() == expected)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    block.lines().any(|line| line.trim() == expected)
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in endpoint_assignment_fields(block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected approval decision readiness field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited approval decision readiness field {field}"
            ));
        }
    }
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let bytes = block.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !is_ident_start_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_ident_byte(bytes[index]) {
            index += 1;
        }
        let end = index;
        let cursor = skip_ws(block, end);
        if bytes.get(cursor) == Some(&b'=') {
            if let Some(field) = block.get(start..end) {
                fields.push(field.to_string());
            }
        }
    }
    fields
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in simple_assignments(block) {
        if value == "true"
            && !SAFE_TRUE_FIELDS.contains(&field.as_str())
            && unsafe_true_field(&field)
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn simple_assignments(block: &str) -> Vec<(String, String)> {
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (field, rest) = trimmed.split_once('=')?;
            let field = field.trim();
            if !is_identifier(field) {
                return None;
            }
            let value = rest.trim().trim_end_matches(',').trim();
            Some((field.to_string(), value.to_string()))
        })
        .collect()
}

fn validate_singleton_endpoint_assignments(block: &str, errors: &mut Vec<String>) {
    for field in singleton_endpoint_assignments() {
        if endpoint_assignment_count(block, &field) != 1 {
            errors.push(format!("API {field} assignment must appear exactly once"));
        }
    }
}

fn singleton_endpoint_assignments() -> Vec<String> {
    let mut fields = vec![
        "source".to_string(),
        "approvalReadinessMode".to_string(),
        "identityProvider".to_string(),
        "configuredForProduction".to_string(),
        "rules".to_string(),
    ];
    fields.extend(SAFE_TRUE_FIELDS.iter().map(|field| field.to_string()));
    fields.extend(
        REQUIRED_DISABLED_FIELDS
            .iter()
            .map(|field| field.to_string()),
    );
    fields.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(field, _)| field.to_string()),
    );
    fields
}

fn endpoint_assignment_count(block: &str, field: &str) -> usize {
    assignment_occurrences(block, field).len()
}

fn assignment_occurrences(block: &str, field: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let bytes = block.as_bytes();
    let field_bytes = field.as_bytes();
    let mut index = 0;
    while index + field_bytes.len() <= bytes.len() {
        if &bytes[index..index + field_bytes.len()] == field_bytes
            && (index == 0 || !is_ident_byte(bytes[index - 1]))
            && bytes
                .get(index + field_bytes.len())
                .map(|byte| !is_ident_byte(*byte))
                .unwrap_or(true)
        {
            let cursor = skip_ws(block, index + field_bytes.len());
            if bytes.get(cursor) == Some(&b'=') {
                starts.push(index);
            }
        }
        index += 1;
    }
    starts
}

fn rules_from_catalog(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule.is_object())
                .map(|rule| Rule {
                    id: string_value_direct(rule, "id")
                        .unwrap_or_default()
                        .to_string(),
                    decision: string_value_direct(rule, "decision")
                        .unwrap_or_default()
                        .to_string(),
                    requirement: string_value_direct(rule, "requirement")
                        .unwrap_or_default()
                        .to_string(),
                    evidence: string_value_direct(rule, "evidence")
                        .unwrap_or_default()
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited approval decision field"
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
                for field in whole_file_prohibited_fields(text) {
                    errors.push(format!(
                        "{path} contains prohibited approval decision field {field}"
                    ));
                }
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
                    "{path} contains prohibited approval decision field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn whole_file_prohibited_fields(value: &str) -> Vec<String> {
    let mut fields = Vec::new();
    for line in value.lines() {
        let trimmed = line.trim_start();
        let mut candidate = String::new();
        for ch in trimmed.chars() {
            if candidate.is_empty() {
                if ch.is_ascii_alphabetic() || ch == '_' || ch == '"' || ch == '\'' {
                    if ch != '"' && ch != '\'' {
                        candidate.push(ch);
                    }
                } else {
                    break;
                }
            } else if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                candidate.push(ch);
            } else if ch == '"' || ch == '\'' {
                continue;
            } else if ch == ':' || ch == '=' {
                if prohibited_field(&candidate) && !fields.contains(&candidate) {
                    fields.push(candidate);
                }
                break;
            } else {
                break;
            }
        }
    }
    fields
}

fn safe_text_value(value: &str) -> bool {
    STATIC_SAFE_VALUES.contains(&value)
        || REQUIRED_APPROVAL_ROUTES.contains(&value)
        || REQUIRED_DECISION_STATES.contains(&value)
        || REQUIRED_DECISION_TYPES.contains(&value)
        || REQUIRED_ROUTE_STAGES.contains(&value)
        || REQUIRED_APPROVAL_SCOPES.contains(&value)
        || REQUIRED_ESCALATION_STATES.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || SAFE_TRUE_FIELDS.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || REQUIRED_CATALOG_KEYS.contains(&value)
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_value(value) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || contains_any(
            &normalized,
            &[
                "approveremail",
                "emailaddress",
                "mailaddress",
                "rawapprover",
                "approverdata",
                "rawapproval",
                "approvalpayload",
                "rawrequest",
                "rawrecipient",
                "recipientdata",
                "servicenowsysid",
                "sysid",
                "tenantid",
                "objectid",
                "principalid",
                "groupid",
                "privateip",
                "privatenetwork",
                "credential",
                "secret",
                "accesstoken",
                "token",
                "password",
                "bearer",
                "providerpayload",
                "endpointurl",
                "url",
                "rawlog",
                "rawrow",
            ],
        )
        || sensitive_compound_field(value)
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    has_any(
        &tokens,
        &["password", "credential", "secret", "token", "bearer"],
    ) || has_any(&tokens, &["url", "uri", "endpoint"])
        || has_any(&tokens, &["email", "mail"])
        || (has_any(&tokens, &["id", "guid", "sysid"]) && tokens.len() > 1)
        || (has_any(&tokens, &["private", "ip"])
            && has_any(&tokens, &["address", "value", "network"]))
        || (has_any(
            &tokens,
            &["tenant", "object", "principal", "group", "servicenow"],
        ) && has_any(
            &tokens,
            &["id", "identifier", "identifiers", "sys", "value"],
        ))
        || (has_any(&tokens, &["approver", "approval", "recipient"])
            && has_any(
                &tokens,
                &["data", "payload", "row", "rows", "email", "mail"],
            ))
        || (tokens.contains(&"raw".to_string())
            && has_any(
                &tokens,
                &[
                    "approver",
                    "approval",
                    "request",
                    "recipient",
                    "provider",
                    "log",
                    "logs",
                    "row",
                    "rows",
                    "payload",
                    "data",
                ],
            ))
}

fn unsafe_true_field(field: &str) -> bool {
    let normalized = normalize(field);
    contains_any(
        &normalized,
        &[
            "provider",
            "live",
            "graph",
            "lookup",
            "service",
            "approval",
            "queue",
            "mutation",
            "notification",
            "workflow",
            "raw",
            "recipient",
            "tenant",
            "object",
            "principal",
            "group",
            "credential",
            "token",
        ],
    )
}

fn prohibited_value(value: &str) -> bool {
    contains_url(value)
        || contains_email(value)
        || contains_private_ipv4(value)
        || contains_uuid(value)
        || contains_hex32(value)
        || value.to_ascii_uppercase().contains("AKIA")
            && value
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .count()
                >= 20
        || value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----")
        || contains_secret_assignment(value)
}

fn contains_url(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|token| token.to_ascii_lowercase().contains("://"))
}

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let Some((local, domain)) = token.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain.chars().any(|ch| ch.is_ascii_alphabetic())
    })
}

fn contains_private_ipv4(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|token| {
            let octets: Vec<&str> = token.split('.').collect();
            if octets.len() != 4 {
                return false;
            }
            let parsed: Option<Vec<u8>> = octets
                .iter()
                .map(|octet| octet.parse::<u8>().ok())
                .collect();
            let Some(parsed) = parsed else {
                return false;
            };
            parsed[0] == 10
                || (parsed[0] == 192 && parsed[1] == 168)
                || (parsed[0] == 172 && (16..=31).contains(&parsed[1]))
        })
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_hexdigit() && ch != '-')
        .any(|token| {
            token.len() == 36
                && token.as_bytes().get(8) == Some(&b'-')
                && token.as_bytes().get(13) == Some(&b'-')
                && token.as_bytes().get(18) == Some(&b'-')
                && token.as_bytes().get(23) == Some(&b'-')
                && token.chars().all(|ch| ch == '-' || ch.is_ascii_hexdigit())
        })
}

fn contains_hex32(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_hexdigit())
        .any(|token| token.len() == 32 && token.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn contains_secret_assignment(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ]
    .iter()
    .any(|key| lowered.contains(&format!("{key}:")) || lowered.contains(&format!("{key}=")))
}

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
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

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn string_value_direct<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut separated = String::with_capacity(value.len() * 2);
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            separated.push(' ');
        }
        if ch.is_ascii_alphanumeric() {
            separated.push(ch.to_ascii_lowercase());
            previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            separated.push(' ');
            previous_lower_or_digit = false;
        }
    }
    separated.split_whitespace().map(str::to_string).collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_ident_start_byte(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_ws(text: &str, mut index: usize) -> usize {
    while text
        .as_bytes()
        .get(index)
        .map(|byte| byte.is_ascii_whitespace())
        .unwrap_or(false)
    {
        index += 1;
    }
    index
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
    fn mapget_routes_accept_receiver_whitespace() {
        let program = format!(
            "app . MapGet ( \"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let routes = mapget_routes(&program);

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].route, ENDPOINT);
    }

    #[test]
    fn fake_receiver_is_not_endpoint() {
        let program = format!(
            "fakeapp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"spoofed\" }}));"
        );
        assert!(mapget_routes(&program).is_empty());
    }

    #[test]
    fn context_yaml_parser_handles_contract_shape() {
        let catalog = parse_yaml_document(
            r#"
version: 1
approvalRoutes:
  - p0-live-execution-default
rules:
  - id: approval-route-readiness-required
    decision: block
"#,
        )
        .expect("contract-like catalog YAML should parse");
        let access_catalog = parse_yaml_document(
            r#"
approvalRoutes:
  - id: p0-live-execution-default
    requiredActors:
      - Datacenter Approver
"#,
        )
        .expect("access-control-like catalog YAML should parse");

        assert_eq!(catalog.get("version").and_then(Value::as_i64), Some(1));
        assert_eq!(
            string_array_like(&catalog, "approvalRoutes"),
            vec!["p0-live-execution-default".to_string()]
        );
        assert_eq!(
            access_catalog
                .get("approvalRoutes")
                .and_then(Value::as_array)
                .and_then(|routes| routes.first())
                .and_then(|route| route.get("requiredActors"))
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn context_yaml_parser_reports_invalid_yaml_as_validation_error() {
        let mut errors = Vec::new();

        let parsed = parse_context_yaml("version: [\n", CATALOG_PATH, &mut errors);

        assert!(parsed.is_none());
        assert!(errors
            .iter()
            .any(|error| error.contains(CATALOG_PATH) && error.contains("valid YAML")));
    }

    #[test]
    fn duplicate_source_assignment_is_rejected() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\", source = \"live-approval-execution\", approvalReadinessMode = \"static-approval-decision-readiness\" }}));"
        );
        let block = endpoint_block(&program, &mut Vec::new());
        let mut errors = Vec::new();

        validate_singleton_endpoint_assignments(&block, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("source") && error.contains("once")));
    }

    #[test]
    fn catalog_flag_policy_is_rust_owned() {
        let catalog = valid_catalog();
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");
        for field in SAFE_TRUE_FIELDS {
            let mut changed = catalog.clone();
            changed
                .as_object_mut()
                .expect("catalog fixture must be an object")
                .insert((*field).to_string(), Value::Bool(false));
            let mut errors = Vec::new();

            validate_catalog_value(&changed, &mut errors);

            assert!(
                errors
                    .iter()
                    .any(|error| error.contains(field) && error.contains("true")),
                "{field} drift was not rejected: {errors:?}"
            );
        }
        for field in REQUIRED_DISABLED_FIELDS {
            let mut changed = catalog.clone();
            changed
                .as_object_mut()
                .expect("catalog fixture must be an object")
                .insert((*field).to_string(), Value::Bool(true));
            let mut errors = Vec::new();

            validate_catalog_value(&changed, &mut errors);

            assert!(
                errors
                    .iter()
                    .any(|error| error.contains(field) && error.contains("disabled")),
                "{field} drift was not rejected: {errors:?}"
            );
        }
    }

    #[test]
    fn catalog_array_policy_is_rust_owned() {
        let cases = [
            ("approvalRoutes", REQUIRED_APPROVAL_ROUTES[0]),
            ("decisionStates", "pending-approval"),
            ("decisionTypes", "risk-acceptance"),
            ("routeStages", "emergency-review"),
        ];

        for (field, value) in cases {
            let mut catalog = valid_catalog();
            catalog
                .get_mut(field)
                .and_then(Value::as_array_mut)
                .expect("catalog fixture field must be an array")
                .retain(|item| item.as_str() != Some(value));
            let mut errors = Vec::new();

            validate_catalog_value(&catalog, &mut errors);

            assert!(
                errors
                    .iter()
                    .any(|error| error.contains(field) && error.contains(value)),
                "{field} missing value was not rejected: {errors:?}"
            );
        }
    }

    fn valid_catalog() -> Value {
        let mut catalog = serde_json::Map::new();
        catalog.insert("version".to_string(), serde_json::json!(1));
        catalog.insert("status".to_string(), Value::String("draft".to_string()));
        catalog.insert(
            "source".to_string(),
            Value::String("static-seed".to_string()),
        );
        catalog.insert(
            "approvalReadinessMode".to_string(),
            Value::String("static-approval-decision-readiness".to_string()),
        );
        catalog.insert(
            "identityProvider".to_string(),
            Value::String("Microsoft Entra ID".to_string()),
        );
        catalog.insert("configuredForProduction".to_string(), Value::Bool(false));
        catalog.insert(
            "approvalRoutes".to_string(),
            string_array_value(REQUIRED_APPROVAL_ROUTES),
        );
        catalog.insert(
            "decisionStates".to_string(),
            string_array_value(REQUIRED_DECISION_STATES),
        );
        catalog.insert(
            "decisionTypes".to_string(),
            string_array_value(REQUIRED_DECISION_TYPES),
        );
        catalog.insert(
            "routeStages".to_string(),
            string_array_value(REQUIRED_ROUTE_STAGES),
        );
        catalog.insert(
            "approvalScopes".to_string(),
            string_array_value(REQUIRED_APPROVAL_SCOPES),
        );
        catalog.insert(
            "escalationStates".to_string(),
            string_array_value(REQUIRED_ESCALATION_STATES),
        );
        catalog.insert(
            "requiredGuards".to_string(),
            string_array_value(REQUIRED_GUARDS),
        );
        catalog.insert(
            "blockedReasons".to_string(),
            string_array_value(REQUIRED_BLOCKED_REASONS),
        );
        catalog.insert(
            "requiredEvidence".to_string(),
            string_array_value(REQUIRED_EVIDENCE),
        );
        catalog.insert(
            "rules".to_string(),
            Value::Array(
                REQUIRED_RULES
                    .iter()
                    .map(|rule| {
                        serde_json::json!({
                            "id": rule.id,
                            "decision": rule.decision,
                            "requirement": rule.requirement,
                            "evidence": rule.evidence,
                        })
                    })
                    .collect(),
            ),
        );
        for field in SAFE_TRUE_FIELDS {
            catalog.insert((*field).to_string(), Value::Bool(true));
        }
        for field in REQUIRED_DISABLED_FIELDS {
            catalog.insert((*field).to_string(), Value::Bool(false));
        }
        Value::Object(catalog)
    }

    fn string_array_value(values: &[&str]) -> Value {
        Value::Array(
            values
                .iter()
                .map(|value| Value::String((*value).to_string()))
                .collect(),
        )
    }
}
