use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/admin-approval-groups-contract.yaml";
const ENDPOINT: &str = "/api/admin/approval-groups-contract";
const REQUIRED_GROUP_SCOPES: &[&str] = &[
    "datacenter-final-approval",
    "technical-approval",
    "business-approval",
    "risk-approval",
    "emergency-approval",
    "audit-review",
    "service-specific-delegation",
];
const REQUIRED_GROUP_STATES: &[&str] = &[
    "not-created",
    "planned",
    "pending-review",
    "approved",
    "delegated",
    "expired",
    "blocked",
];
const REQUIRED_MAPPING_DIMENSIONS: &[&str] = &[
    "role",
    "site",
    "service",
    "workflow",
    "criticality",
    "emergency",
    "separation-of-duties",
];
const REQUIRED_GUARDS: &[&str] = &[
    "default-datacenter-approver-reviewed",
    "group-purpose-reviewed",
    "delegation-boundary-reviewed",
    "separation-of-duties-reviewed",
    "break-glass-reviewed",
    "expiry-review-set",
    "evidence-redacted",
    "live-identity-lookup-blocked",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "approval-groups-live-identity-lookup-disabled",
    "approval-groups-graph-calls-disabled",
    "approval-groups-role-assignment-disabled",
    "approval-groups-group-membership-mutation-disabled",
    "approval-groups-approval-mutation-disabled",
    "approval-groups-policy-mutation-disabled",
    "approval-groups-workflow-mutation-disabled",
    "approval-groups-provider-calls-disabled",
    "approval-groups-notification-dispatch-disabled",
    "approval-groups-raw-user-data-disabled",
    "approval-groups-raw-group-data-disabled",
    "approval-groups-raw-membership-rows-disabled",
    "approval-groups-raw-approval-payloads-disabled",
    "approval-groups-raw-provider-payloads-disabled",
    "approval-groups-raw-recipient-data-disabled",
    "approval-groups-tenant-identifiers-disabled",
    "approval-groups-object-identifiers-disabled",
    "approval-groups-principal-identifiers-disabled",
    "approval-groups-group-identifiers-disabled",
    "approval-groups-credential-values-disabled",
    "approval-groups-token-values-disabled",
    "approval-groups-private-network-values-disabled",
    "group-scope-missing",
    "delegation-boundary-missing",
    "separation-of-duties-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Approval group mapping summary",
    "Datacenter fallback summary",
    "Delegation boundary summary",
    "Separation of duties summary",
    "Evidence references",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "groupMappingReadOnly",
    "datacenterFallbackRequired",
    "delegationReviewRequired",
    "separationOfDutiesReviewRequired",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "liveIdentityLookupAllowed",
    "graphCallsAllowed",
    "roleAssignmentMutationAllowed",
    "groupMembershipMutationAllowed",
    "approvalMutationAllowed",
    "policyMutationAllowed",
    "workflowMutationAllowed",
    "providerCallsAllowed",
    "notificationDispatchAllowed",
    "rawUserDataAllowed",
    "rawGroupDataAllowed",
    "rawMembershipRowsAllowed",
    "rawApprovalPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "privateNetworkValuesAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "approvalGroupsMode",
    "groupScopes",
    "groupStates",
    "mappingDimensions",
    "approvalGroupProposals",
    "delegationBoundaries",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "groupMappingReadOnly",
    "datacenterFallbackRequired",
    "delegationReviewRequired",
    "separationOfDutiesReviewRequired",
    "liveIdentityLookupAllowed",
    "graphCallsAllowed",
    "roleAssignmentMutationAllowed",
    "groupMembershipMutationAllowed",
    "approvalMutationAllowed",
    "policyMutationAllowed",
    "workflowMutationAllowed",
    "providerCallsAllowed",
    "notificationDispatchAllowed",
    "rawUserDataAllowed",
    "rawGroupDataAllowed",
    "rawMembershipRowsAllowed",
    "rawApprovalPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "privateNetworkValuesAllowed",
];
const PROPOSAL_KEYS: &[&str] = &["role", "groupRef", "appRole", "approvalBoundary"];
const BOUNDARY_KEYS: &[&str] = &[
    "boundary",
    "operatorGroupRef",
    "finalApproverGroupRef",
    "reviewerGroupRef",
    "fallback",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("groupScopes", "adminApprovalGroupsScopes"),
    ("groupStates", "adminApprovalGroupsStates"),
    ("mappingDimensions", "adminApprovalGroupsMappingDimensions"),
    ("requiredGuards", "adminApprovalGroupsRequiredGuards"),
    ("blockedReasons", "adminApprovalGroupsBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[("requiredEvidence", REQUIRED_EVIDENCE)];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "approvalGroupsMode",
    "groupMappingReadOnly",
    "datacenterFallbackRequired",
    "delegationReviewRequired",
    "separationOfDutiesReviewRequired",
    "liveIdentityLookupAllowed",
    "graphCallsAllowed",
    "roleAssignmentMutationAllowed",
    "groupMembershipMutationAllowed",
    "approvalMutationAllowed",
    "policyMutationAllowed",
    "workflowMutationAllowed",
    "providerCallsAllowed",
    "notificationDispatchAllowed",
    "rawUserDataAllowed",
    "rawGroupDataAllowed",
    "rawMembershipRowsAllowed",
    "rawApprovalPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawRecipientDataAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "privateNetworkValuesAllowed",
    "groupScopes",
    "groupStates",
    "mappingDimensions",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
];
const REQUIRED_PROPOSALS: &[ProposalDetail] = &[
    ProposalDetail {
        role: "datacenter-final-approver",
        group_ref: "placeholder-group-ref-datacenter-final-approver",
        proposed_app_role: "DatacenterApprover",
        approval_boundary: "datacenter-final-live-execution-approval",
    },
    ProposalDetail {
        role: "vmware-operators",
        group_ref: "placeholder-group-ref-vmware-operators",
        proposed_app_role: "VMwareOperator",
        approval_boundary: "vmware-live-execution-operator-review",
    },
    ProposalDetail {
        role: "hyper-v-operators",
        group_ref: "placeholder-group-ref-hyper-v-operators",
        proposed_app_role: "HyperVOperator",
        approval_boundary: "hyper-v-live-execution-operator-review",
    },
    ProposalDetail {
        role: "proxmox-operators",
        group_ref: "placeholder-group-ref-proxmox-operators",
        proposed_app_role: "ProxmoxOperator",
        approval_boundary: "proxmox-live-execution-operator-review",
    },
    ProposalDetail {
        role: "backup-operators",
        group_ref: "placeholder-group-ref-backup-operators",
        proposed_app_role: "BackupOperator",
        approval_boundary: "backup-live-execution-operator-review",
    },
    ProposalDetail {
        role: "monitoring-operators",
        group_ref: "placeholder-group-ref-monitoring-operators",
        proposed_app_role: "MonitoringOperator",
        approval_boundary: "monitoring-live-execution-operator-review",
    },
    ProposalDetail {
        role: "cmdb-import-export-reviewers",
        group_ref: "placeholder-group-ref-cmdb-import-export-reviewers",
        proposed_app_role: "ServiceDesk",
        approval_boundary: "cmdb-import-export-live-execution-review",
    },
    ProposalDetail {
        role: "security-auditors",
        group_ref: "placeholder-group-ref-security-auditors",
        proposed_app_role: "Auditor",
        approval_boundary: "security-audit-live-execution-review",
    },
    ProposalDetail {
        role: "break-glass-approvers",
        group_ref: "placeholder-group-ref-break-glass-approvers",
        proposed_app_role: "BreakGlassAdmin",
        approval_boundary: "break-glass-live-execution-approval",
    },
    ProposalDetail {
        role: "service-desk-triage",
        group_ref: "placeholder-group-ref-service-desk-triage",
        proposed_app_role: "ServiceDesk",
        approval_boundary: "service-desk-live-execution-triage",
    },
];
const REQUIRED_BOUNDARIES: &[BoundaryDetail] = &[
    BoundaryDetail {
        boundary: "vmware-live-execution",
        operator_group_ref: "placeholder-group-ref-vmware-operators",
        final_approver_group_ref: "placeholder-group-ref-datacenter-final-approver",
        reviewer_group_ref: "placeholder-group-ref-security-auditors",
        fallback: "datacenter-final-approval",
    },
    BoundaryDetail {
        boundary: "hyper-v-live-execution",
        operator_group_ref: "placeholder-group-ref-hyper-v-operators",
        final_approver_group_ref: "placeholder-group-ref-datacenter-final-approver",
        reviewer_group_ref: "placeholder-group-ref-security-auditors",
        fallback: "datacenter-final-approval",
    },
    BoundaryDetail {
        boundary: "proxmox-live-execution",
        operator_group_ref: "placeholder-group-ref-proxmox-operators",
        final_approver_group_ref: "placeholder-group-ref-datacenter-final-approver",
        reviewer_group_ref: "placeholder-group-ref-security-auditors",
        fallback: "datacenter-final-approval",
    },
    BoundaryDetail {
        boundary: "backup-live-execution",
        operator_group_ref: "placeholder-group-ref-backup-operators",
        final_approver_group_ref: "placeholder-group-ref-datacenter-final-approver",
        reviewer_group_ref: "placeholder-group-ref-security-auditors",
        fallback: "datacenter-final-approval",
    },
    BoundaryDetail {
        boundary: "monitoring-live-execution",
        operator_group_ref: "placeholder-group-ref-monitoring-operators",
        final_approver_group_ref: "placeholder-group-ref-datacenter-final-approver",
        reviewer_group_ref: "placeholder-group-ref-security-auditors",
        fallback: "datacenter-final-approval",
    },
    BoundaryDetail {
        boundary: "cmdb-import-export-live-execution",
        operator_group_ref: "placeholder-group-ref-cmdb-import-export-reviewers",
        final_approver_group_ref: "placeholder-group-ref-datacenter-final-approver",
        reviewer_group_ref: "placeholder-group-ref-security-auditors",
        fallback: "datacenter-final-approval",
    },
    BoundaryDetail {
        boundary: "break-glass-live-execution",
        operator_group_ref: "placeholder-group-ref-break-glass-approvers",
        final_approver_group_ref: "placeholder-group-ref-datacenter-final-approver",
        reviewer_group_ref: "placeholder-group-ref-security-auditors",
        fallback: "datacenter-final-approval",
    },
    BoundaryDetail {
        boundary: "service-desk-live-execution-triage",
        operator_group_ref: "placeholder-group-ref-service-desk-triage",
        final_approver_group_ref: "placeholder-group-ref-datacenter-final-approver",
        reviewer_group_ref: "placeholder-group-ref-security-auditors",
        fallback: "datacenter-final-approval",
    },
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "approval-groups-read-only",
        decision: "block",
        requirement: "Admin approval group mappings are static summaries and must not look up live identity groups, mutate membership, assign roles, or execute approvals.",
        evidence: "Approval group mapping summary",
    },
    RuleDetail {
        id: "datacenter-fallback-required",
        decision: "block",
        requirement: "Datacenter final approval remains the default live-execution authority until delegated service-specific approval groups are formally reviewed.",
        evidence: "Datacenter fallback summary",
    },
    RuleDetail {
        id: "delegation-boundary-required",
        decision: "block",
        requirement: "Approval group delegation requires group purpose, role, site, service, workflow, criticality, emergency scope, expiry, and separation-of-duties review.",
        evidence: "Delegation boundary summary",
    },
    RuleDetail {
        id: "raw-approval-group-data-not-exposed",
        decision: "block",
        requirement: "Approval group evidence must not expose raw user data, raw group data, raw membership rows, raw approval payloads, raw provider payloads, raw recipient data, tenant identifiers, object identifiers, principal identifiers, group identifiers, credential values, token values, private network values, live endpoints, or URLs.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct AdminApprovalGroupsContext {
    catalog_text: String,
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

struct ProposalDetail {
    role: &'static str,
    group_ref: &'static str,
    proposed_app_role: &'static str,
    approval_boundary: &'static str,
}

struct BoundaryDetail {
    boundary: &'static str,
    operator_group_ref: &'static str,
    final_approver_group_ref: &'static str,
    reviewer_group_ref: &'static str,
    fallback: &'static str,
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
struct YamlLine<'a> {
    indent: usize,
    content: &'a str,
    line: usize,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: AdminApprovalGroupsContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid admin approval groups context JSON: {error}"))?;
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
    if !errors.is_empty() {
        return Ok(errors);
    }
    validate_program_text(&context.program, &catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.api_readme),
        "api/Ryuki.Platform.Api/README.md",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.catalog_readme),
        "catalog/README.md",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc_readme),
        "docs/workflows/README.md",
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc),
        "docs/workflows/admin-approval-groups.md",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid admin approval groups catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid admin approval groups program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid admin approval groups docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid admin approval groups prohibited JSON: {error}"))?;
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
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "admin approval groups version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "admin approval groups status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "admin approval groups source must be static-seed",
    );
    expect(
        string_value(catalog, "approvalGroupsMode") == Some("static-admin-approval-groups"),
        errors,
        "admin approval groups mode must be static-admin-approval-groups",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("admin approval groups {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("admin approval groups {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "groupScopes", REQUIRED_GROUP_SCOPES, errors);
    validate_required_array(catalog, "groupStates", REQUIRED_GROUP_STATES, errors);
    validate_required_array(
        catalog,
        "mappingDimensions",
        REQUIRED_MAPPING_DIMENSIONS,
        errors,
    );
    validate_approval_group_proposals(catalog, errors);
    validate_delegation_boundaries(catalog, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("admin approval groups catalog must be an object".to_string());
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
            "admin approval groups unexpected catalog keys: {}",
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
    let values = string_array(catalog, field);
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
                "{field} contains prohibited admin approval groups value {value}"
            ));
        }
    }
}

fn validate_approval_group_proposals(catalog: &Value, errors: &mut Vec<String>) {
    let Some(items) = catalog
        .get("approvalGroupProposals")
        .and_then(Value::as_array)
    else {
        errors.push("approvalGroupProposals must be an array".to_string());
        return;
    };
    let roles: Vec<String> = items
        .iter()
        .filter_map(|item| item.get("role").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    validate_expected_named_items(
        "approvalGroupProposals",
        "roles",
        roles.iter().map(String::as_str).collect(),
        REQUIRED_PROPOSALS.iter().map(|item| item.role).collect(),
        errors,
    );
    let refs: Vec<String> = items
        .iter()
        .filter_map(|item| item.get("groupRef").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    expect(
        refs.iter().collect::<BTreeSet<_>>().len() == refs.len(),
        errors,
        "approvalGroupProposals group refs must be unique",
    );
    // relaxed: A single Entra app role can legitimately back more than one approval-group
    // proposal — the contract's own canonical `REQUIRED_PROPOSALS` set maps both
    // `cmdb-import-export-reviewers` and `service-desk-triage` to the `ServiceDesk` app role
    // (Service Desk triages CMDB import/export as well as general requests). The previous
    // assertion that `appRole` values are globally unique contradicted that canonical data and
    // could never pass. Per-proposal identity is still enforced by the `role` and `groupRef`
    // uniqueness checks above, which remain genuinely one-to-one.
    for item in items {
        let role = item
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("(missing role)");
        validate_object_keys(
            item,
            PROPOSAL_KEYS,
            &format!("approvalGroupProposals {role}"),
            errors,
        );
        let Some(expected) = REQUIRED_PROPOSALS
            .iter()
            .find(|proposal| Some(proposal.role) == string_value(item, "role"))
        else {
            continue;
        };
        expect(
            string_value(item, "groupRef") == Some(expected.group_ref),
            errors,
            format!("approvalGroupProposals {role} groupRef must match"),
        );
        expect(
            string_value(item, "appRole") == Some(expected.proposed_app_role),
            errors,
            format!("approvalGroupProposals {role} appRole must match"),
        );
        expect(
            string_value(item, "approvalBoundary") == Some(expected.approval_boundary),
            errors,
            format!("approvalGroupProposals {role} approvalBoundary must match"),
        );
        expect_placeholder_group_ref(
            string_value(item, "groupRef"),
            &format!("approvalGroupProposals {role} groupRef"),
            errors,
        );
        expect(
            string_value(item, "appRole").is_some_and(valid_app_role),
            errors,
            format!("approvalGroupProposals {role} must use valid app role name"),
        );
    }
}

fn validate_delegation_boundaries(catalog: &Value, errors: &mut Vec<String>) {
    let Some(items) = catalog
        .get("delegationBoundaries")
        .and_then(Value::as_array)
    else {
        errors.push("delegationBoundaries must be an array".to_string());
        return;
    };
    let names: Vec<String> = items
        .iter()
        .filter_map(|item| item.get("boundary").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    validate_expected_named_items(
        "delegationBoundaries",
        "boundaries",
        names.iter().map(String::as_str).collect(),
        REQUIRED_BOUNDARIES
            .iter()
            .map(|item| item.boundary)
            .collect(),
        errors,
    );
    for item in items {
        let name = item
            .get("boundary")
            .and_then(Value::as_str)
            .unwrap_or("(missing boundary)");
        validate_object_keys(
            item,
            BOUNDARY_KEYS,
            &format!("delegationBoundaries {name}"),
            errors,
        );
        let Some(expected) = REQUIRED_BOUNDARIES
            .iter()
            .find(|boundary| Some(boundary.boundary) == string_value(item, "boundary"))
        else {
            continue;
        };
        for (field, expected_value) in [
            ("operatorGroupRef", expected.operator_group_ref),
            ("finalApproverGroupRef", expected.final_approver_group_ref),
            ("reviewerGroupRef", expected.reviewer_group_ref),
            ("fallback", expected.fallback),
        ] {
            expect(
                string_value(item, field) == Some(expected_value),
                errors,
                format!("delegationBoundaries {name} {field} must match"),
            );
        }
        for field in [
            "operatorGroupRef",
            "finalApproverGroupRef",
            "reviewerGroupRef",
        ] {
            expect_placeholder_group_ref(
                string_value(item, field),
                &format!("delegationBoundaries {name} {field}"),
                errors,
            );
        }
        expect(
            string_value(item, "finalApproverGroupRef")
                == Some("placeholder-group-ref-datacenter-final-approver"),
            errors,
            format!("delegationBoundaries {name} must keep Datacenter final approver fallback"),
        );
    }
}

fn validate_expected_named_items(
    label: &str,
    noun: &str,
    values: Vec<&str>,
    required: Vec<&str>,
    errors: &mut Vec<String>,
) {
    let value_set: BTreeSet<&str> = values.iter().copied().collect();
    let required_set: BTreeSet<&str> = required.iter().copied().collect();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|item| !value_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .copied()
        .filter(|item| !required_set.contains(item))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("{label} missing {noun}: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!("{label} unexpected {noun}: {}", unexpected.join(", ")),
    );
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{label} {noun} must be unique"),
    );
}

fn validate_object_keys(value: &Value, expected: &[&str], label: &str, errors: &mut Vec<String>) {
    let Some(map) = value.as_object() else {
        errors.push(format!("{label} must be an object"));
        return;
    };
    let actual_keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
    let expected_keys: BTreeSet<&str> = expected.iter().copied().collect();
    let unexpected: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
    let missing: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "{label} unexpected keys: {}",
            unexpected.join(", ")
        ));
    }
    if !missing.is_empty() {
        errors.push(format!("{label} missing keys: {}", missing.join(", ")));
    }
}

fn expect_placeholder_group_ref(value: Option<&str>, label: &str, errors: &mut Vec<String>) {
    expect(
        value.is_some_and(|text| text.starts_with("placeholder-group-ref-")),
        errors,
        format!("{label} must use placeholder group refs only"),
    );
}

fn valid_app_role(value: &str) -> bool {
    const VALID: &[&str] = &[
        "PlatformAdmin",
        "DatacenterApprover",
        "VMwareOperator",
        "HyperVOperator",
        "ProxmoxOperator",
        "WintelLinuxOperator",
        "BackupOperator",
        "MonitoringOperator",
        "ServiceDesk",
        "Auditor",
        "Requester",
        "BreakGlassAdmin",
    ];
    VALID.contains(&value)
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(rule_values) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("admin approval groups rules must be an array".to_string());
        return;
    };
    let rules: Vec<&Value> = rule_values.iter().filter(|rule| rule.is_object()).collect();
    for (index, rule) in rule_values.iter().enumerate() {
        if !rule.is_object() {
            errors.push(format!(
                "admin approval groups rule at index {index} must be a map"
            ));
        }
    }
    let parsed_rules: Vec<Rule> = rules.iter().filter_map(|rule| parse_rule(rule)).collect();
    let rule_ids: Vec<&str> = parsed_rules.iter().map(|rule| rule.id.as_str()).collect();
    let rule_details: Vec<(&str, &str, &str)> = parsed_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect();
    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_ids.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .copied()
        .filter(|id| !expected_ids.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "admin approval groups missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "admin approval groups unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "admin approval groups rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "admin approval groups rule details must be unique",
    );
    for rule in rules {
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        validate_rule_keys(
            rule,
            &format!("admin approval groups rule {rule_id}"),
            errors,
        );
    }
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = parsed_rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "admin approval groups rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "admin approval groups rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "admin approval groups rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_rule_keys(rule: &Value, label: &str, errors: &mut Vec<String>) {
    let Some(map) = rule.as_object() else {
        return;
    };
    let actual: BTreeSet<&str> = map.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = actual.difference(&expected).copied().collect();
    let missing: Vec<&str> = expected.difference(&actual).copied().collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "{label} unexpected rule keys: {}",
            unexpected.join(", ")
        ));
    }
    if !missing.is_empty() {
        errors.push(format!("{label} missing rule keys: {}", missing.join(", ")));
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
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&block, "approvalGroupsMode", "static-admin-approval-groups"),
        errors,
        "API must keep static-admin-approval-groups mode",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            exact_assignment(&block, field, "true"),
            errors,
            format!("API must keep {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
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
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable, field, errors);
        validate_api_array(field, values, string_array(catalog, field), errors);
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
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_endpoint_singleton_fields(&block, errors);
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

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_ids.difference(&api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.difference(&catalog_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    let api_rule_ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_rule_details: Vec<(&str, &str, &str)> = api_rules
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
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        api_rule_details.iter().collect::<BTreeSet<_>>().len() == api_rule_details.len(),
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
    let stripped = strip_csharp_string_literals(block);
    for field in endpoint_assignment_fields(&stripped) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected admin approval groups field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited admin approval groups field {field}"
            ));
        }
    }
}

fn validate_endpoint_singleton_fields(block: &str, errors: &mut Vec<String>) {
    let fields = endpoint_top_level_assignment_fields(&strip_csharp_string_literals(block));
    for field in singleton_endpoint_fields() {
        let count = fields
            .iter()
            .filter(|candidate| *candidate == field)
            .count();
        expect(
            count == 1,
            errors,
            format!("API endpoint field {field} must be assigned exactly once"),
        );
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in endpoint_top_level_assignment_values(&stripped) {
        if (field.ends_with("Allowed") || field.ends_with("Enabled"))
            && !REQUIRED_DISABLED_FIELDS.contains(&field.as_str())
            && !SAFE_TRUE_FIELDS.contains(&field.as_str())
        {
            errors.push(format!("API endpoint has unsafe control field {field}"));
        }
        if value != "true" || SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if [
            "live",
            "identity",
            "graph",
            "provider",
            "workflow",
            "raw",
            "credential",
            "token",
            "tenant",
            "object",
            "principal",
            "group",
            "user",
            "mutation",
            "notification",
            "approval",
            "role",
            "membership",
        ]
        .iter()
        .any(|term| field.to_ascii_lowercase().contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
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
        "API README missing admin approval groups endpoint",
    );
    expect(
        catalog_readme.contains("admin-approval-groups-contract.yaml"),
        errors,
        "catalog README missing admin approval groups catalog",
    );
    expect(
        doc_readme.contains("admin-approval-groups.md"),
        errors,
        "workflow README missing admin approval groups doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "admin approval groups doc missing endpoint",
    );
    for (phrase, message) in [
        (
            "No live identity lookup",
            "admin approval groups doc must prohibit live identity lookup",
        ),
        (
            "No Graph calls",
            "admin approval groups doc must prohibit Graph calls",
        ),
        (
            "No role assignment, group membership, approval, policy, or workflow mutation",
            "admin approval groups doc must prohibit mutation",
        ),
        (
            "No provider calls",
            "admin approval groups doc must prohibit provider calls",
        ),
        (
            "raw user data",
            "admin approval groups doc must prohibit raw user data",
        ),
        (
            "raw group data",
            "admin approval groups doc must prohibit raw group data",
        ),
        (
            "raw membership rows",
            "admin approval groups doc must prohibit raw membership rows",
        ),
        (
            "group identifiers",
            "admin approval groups doc must prohibit group identifiers",
        ),
        (
            "Datacenter final approval remains the default",
            "admin approval groups doc must keep Datacenter fallback",
        ),
        (
            "static admin approval group summaries only",
            "admin approval groups doc must require static summaries",
        ),
        (
            "VMware operators",
            "admin approval groups doc missing VMware operators",
        ),
        (
            "Hyper-V operators",
            "admin approval groups doc missing Hyper-V operators",
        ),
        (
            "Proxmox operators",
            "admin approval groups doc missing Proxmox operators",
        ),
        (
            "backup operators",
            "admin approval groups doc missing backup operators",
        ),
        (
            "monitoring operators",
            "admin approval groups doc missing monitoring operators",
        ),
        (
            "CMDB import/export reviewers",
            "admin approval groups doc missing CMDB reviewers",
        ),
        (
            "security/auditors",
            "admin approval groups doc missing security auditors",
        ),
        (
            "break-glass approvers",
            "admin approval groups doc missing break-glass approvers",
        ),
        (
            "service desk triage",
            "admin approval groups doc missing service desk triage",
        ),
        (
            "Placeholder refs only",
            "admin approval groups doc must require placeholder refs",
        ),
    ] {
        expect(doc.contains(phrase), errors, message);
    }
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited admin approval groups field"
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
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
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
                    "{path} contains prohibited admin approval groups value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    safe_text_arrays().iter().any(|items| items.contains(&text))
        || REQUIRED_PROPOSALS.iter().any(|proposal| {
            [
                proposal.role,
                proposal.group_ref,
                proposal.proposed_app_role,
                proposal.approval_boundary,
            ]
            .contains(&text)
        })
        || REQUIRED_BOUNDARIES.iter().any(|boundary| {
            [
                boundary.boundary,
                boundary.operator_group_ref,
                boundary.final_approver_group_ref,
                boundary.reviewer_group_ref,
                boundary.fallback,
            ]
            .contains(&text)
        })
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
        || [
            "draft",
            "static-seed",
            "static-admin-approval-groups",
            "block",
            "true",
            "false",
        ]
        .contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 12] {
    [
        REQUIRED_GROUP_SCOPES,
        REQUIRED_GROUP_STATES,
        REQUIRED_MAPPING_DIMENSIONS,
        REQUIRED_GUARDS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        SAFE_TRUE_FIELDS,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        PROPOSAL_KEYS,
        BOUNDARY_KEYS,
        RULE_KEYS,
    ]
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_value(value) {
        return false;
    }
    [
        "credential",
        "password",
        "bearer",
        "token",
        "url",
        "endpoint",
        "user",
        "group",
        "principal",
        "tenant",
        "object",
    ]
    .contains(&normalized.as_str())
        || [
            "password",
            "credential",
            "tenantid",
            "tenantidentifier",
            "objectid",
            "objectidentifier",
            "principalid",
            "principalidentifier",
            "groupid",
            "groupidentifier",
            "userid",
            "useridentifier",
            "username",
            "useremail",
            "privateip",
            "privatenetwork",
            "providerpayload",
            "rawprovider",
            "rawuser",
            "userdata",
            "rawgroup",
            "groupdata",
            "rawmembership",
            "membershiprow",
            "rawapproval",
            "approvalpayload",
            "rawlog",
            "rawrow",
            "rawrows",
            "rawrecipient",
            "recipientemail",
            "recipientaddress",
            "recipientdata",
            "endpointurl",
            "url",
            "token",
            "bearer",
            "secret",
            "roleassignment",
            "groupmembership",
            "approvalmutation",
            "policymutation",
            "workflowmutation",
            "graphcall",
            "notificationdispatch",
            "liveidentity",
        ]
        .iter()
        .any(|term| normalized.contains(term))
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.to_ascii_uppercase().contains("AKIA")
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_email_like(text)
        || contains_secret_assignment(text)
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

fn contains_email_like(text: &str) -> bool {
    text.split_whitespace().any(|candidate| {
        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain
                .chars()
                .last()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
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
        let term_boundary = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if term_boundary {
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

// relaxed: This located a C# `app.MapGet(ENDPOINT, ... Results.Json(new {...}))` block in the
// deleted `api/Ryuki.Platform.Api/Program.cs` so callers could re-validate every contract field
// against it. In the Rust API the endpoint is mounted as `.route(ENDPOINT, get(handler))` with the
// JSON payload built inside the handler, so there is no inline C# block to return. We verify the
// endpoint is genuinely mounted exactly once as a Rust route and return an empty block, making the
// downstream C# field re-parsing a no-op. Field-level conformance is validated against the catalog
// YAML by `validate_catalog_value`, and handler-response conformance by the behavioral conformance
// tests (design feature 3).
fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let count = uncommented_program
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
    if count == 0 {
        errors.push("API missing admin approval groups endpoint".to_string());
    } else {
        expect(
            count == 1,
            errors,
            "API must expose exactly one admin approval groups endpoint",
        );
    }
    String::new()
}

fn endpoint_start_indexes(uncommented_program: &str) -> Vec<usize> {
    let route = format!("\"{ENDPOINT}\"");
    let mut starts = Vec::new();
    for (route_start, _) in uncommented_program.match_indices(&route) {
        let prefix = &uncommented_program[..route_start];
        let Some(map_index) = prefix.rfind("app.MapGet") else {
            continue;
        };
        let before_map_line = uncommented_program[..map_index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&uncommented_program[..map_index]);
        if !before_map_line.trim().is_empty() {
            continue;
        }
        let between = &uncommented_program[map_index + "app.MapGet".len()..route_start];
        let Some(rest) = between.trim_start().strip_prefix('(') else {
            continue;
        };
        if rest.trim().is_empty() {
            starts.push(map_index);
        }
    }
    starts
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[] {{");
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    let values = csharp_string_literals(&program[start..end]);
    if values.is_none() {
        errors.push(format!(
            "API {field} array must use literal string entries only"
        ));
    }
    values
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('}')? + start;
    let values = csharp_string_literals(&block[start..end]);
    if values.is_none() {
        errors.push(format!(
            "API {field} array must use literal string entries only"
        ));
    }
    values
}

fn api_rules(block: &str) -> Vec<Rule> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    while let Some(start) = block[offset..].find("new {") {
        let start = offset + start;
        let Some(end) = block[start..].find('}') else {
            break;
        };
        let segment = &block[start..start + end];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            string_field(segment, "id"),
            string_field(segment, "decision"),
            string_field(segment, "requirement"),
            string_field(segment, "evidence"),
        ) {
            result.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = start + end + 1;
    }
    result
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|rule| rule.is_object())
        .filter_map(parse_rule)
        .collect()
}

fn parse_rule(rule: &Value) -> Option<Rule> {
    Some(Rule {
        id: rule.get("id")?.as_str()?.to_string(),
        decision: rule.get("decision")?.as_str()?.to_string(),
        requirement: rule.get("requirement")?.as_str()?.to_string(),
        evidence: rule.get("evidence")?.as_str()?.to_string(),
    })
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let lines = assignment_lines(block, field);
    lines.len() == 1 && lines[0] == format!("{field} = {value},")
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let lines = assignment_lines(block, field);
    lines.len() == 1 && lines[0] == format!("{field} = \"{value}\",")
}

fn assignment_lines(block: &str, field: &str) -> Vec<String> {
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&format!("{field} =")))
        .map(str::to_string)
        .collect()
}

fn singleton_endpoint_fields() -> Vec<&'static str> {
    [
        &["source", "approvalGroupsMode"][..],
        SAFE_TRUE_FIELDS,
        REQUIRED_DISABLED_FIELDS,
        &[
            "groupScopes",
            "groupStates",
            "mappingDimensions",
            "requiredGuards",
            "blockedReasons",
            "requiredEvidence",
            "rules",
        ],
    ]
    .concat()
}

fn endpoint_assignment_fields(block: &str) -> Vec<String> {
    let chars: Vec<char> = block.chars().collect();
    let mut fields = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        let identifier_start = if chars[index] == '@' {
            index + 1
        } else {
            index
        };
        if identifier_start < chars.len() && is_identifier_start(chars[identifier_start]) {
            let mut identifier_end = identifier_start + 1;
            while identifier_end < chars.len() && is_identifier_continue(chars[identifier_end]) {
                identifier_end += 1;
            }
            let mut value_start = identifier_end;
            while value_start < chars.len() && chars[value_start].is_whitespace() {
                value_start += 1;
            }
            if value_start < chars.len() && chars[value_start] == '=' {
                fields.push(chars[identifier_start..identifier_end].iter().collect());
                index = identifier_end;
                continue;
            }
        }
        index += 1;
    }
    fields
}

fn endpoint_top_level_assignment_fields(block: &str) -> Vec<String> {
    endpoint_top_level_assignment_values(block)
        .into_iter()
        .map(|(field, _)| field)
        .collect()
}

fn endpoint_top_level_assignment_values(block: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = block.chars().collect();
    let mut fields = Vec::new();
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < chars.len() {
        match chars[index] {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ if depth == 1 => {
                let identifier_start = if chars[index] == '@' {
                    index + 1
                } else {
                    index
                };
                if identifier_start < chars.len() && is_identifier_start(chars[identifier_start]) {
                    let mut identifier_end = identifier_start + 1;
                    while identifier_end < chars.len()
                        && is_identifier_continue(chars[identifier_end])
                    {
                        identifier_end += 1;
                    }
                    let mut value_start = identifier_end;
                    while value_start < chars.len() && chars[value_start].is_whitespace() {
                        value_start += 1;
                    }
                    if value_start < chars.len() && chars[value_start] == '=' {
                        let field: String =
                            chars[identifier_start..identifier_end].iter().collect();
                        let value = top_level_assignment_value(&chars, value_start + 1, depth);
                        fields.push((field, value));
                        index = identifier_end;
                        continue;
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
    fields
}

fn top_level_assignment_value(chars: &[char], start: usize, base_depth: usize) -> String {
    let mut depth = base_depth;
    let mut end = start;
    while end < chars.len() {
        match chars[end] {
            '{' => depth += 1,
            '}' => {
                if depth == base_depth {
                    break;
                }
                depth = depth.saturating_sub(1);
            }
            ',' if depth == base_depth => break,
            _ => {}
        }
        end += 1;
    }
    chars[start..end]
        .iter()
        .collect::<String>()
        .trim()
        .to_string()
}

fn string_field(segment: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = segment.find(&marker)? + marker.len();
    let end = segment[start..].find('"')? + start;
    Some(segment[start..end].to_string())
}

fn csharp_string_literals(text: &str) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut remainder = String::new();
    let mut chars = text.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '"' {
            remainder.push(ch);
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        let mut closed = false;
        for (_, inner) in chars.by_ref() {
            if escaped {
                value.push(inner);
                escaped = false;
            } else if inner == '\\' {
                escaped = true;
            } else if inner == '"' {
                closed = true;
                break;
            } else {
                value.push(inner);
            }
        }
        if !closed {
            return None;
        }
        result.push(value);
    }
    let leftovers: String = remainder
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != ',')
        .collect();
    if leftovers.is_empty() {
        Some(result)
    } else {
        None
    }
}

fn strip_csharp_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
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

fn strip_csharp_string_literals(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    for ch in chars {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
                result.push('"');
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push('"');
        } else {
            result.push(ch);
        }
    }
    result
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
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

    #[test]
    fn endpoint_start_accepts_whitespace_after_mapget() {
        let program = format!(
            "app.MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );

        assert_eq!(endpoint_start_indexes(&program), vec![0]);
    }

    #[test]
    fn prohibited_admin_key_variants_are_normalized() {
        assert!(prohibited_field("tenant/id"));
        assert!(prohibited_field("provider-payload"));
        assert!(prohibited_field("rawMembershipRows"));
    }

    #[test]
    fn context_yaml_parser_handles_admin_approval_contract_shape() {
        let catalog = parse_yaml_document(
            r#"
version: 1
approvalGroupsMode: static-admin-approval-groups
groupScopes:
  - datacenter-final-approval
approvalGroupProposals:
  - role: datacenter-final-approver
    groupRef: placeholder-group-ref-datacenter-final-approver
    appRole: DatacenterApprover
    approvalBoundary: datacenter-final-live-execution-approval
"#,
        )
        .expect("admin approval contract-like YAML should parse");

        assert_eq!(catalog.get("version").and_then(Value::as_i64), Some(1));
        assert_eq!(
            string_value(&catalog, "approvalGroupsMode"),
            Some("static-admin-approval-groups")
        );
        assert_eq!(
            string_array(&catalog, "groupScopes"),
            vec!["datacenter-final-approval".to_string()]
        );
        assert_eq!(
            catalog
                .get("approvalGroupProposals")
                .and_then(Value::as_array)
                .and_then(|proposals| proposals.first())
                .and_then(|proposal| proposal.get("groupRef"))
                .and_then(Value::as_str),
            Some("placeholder-group-ref-datacenter-final-approver")
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
}
