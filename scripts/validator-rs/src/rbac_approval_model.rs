use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/rbac-approval-model-contract.yaml";
const ACCESS_CATALOG_PATH: &str = "catalog/access-control-catalog.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/rbac-approval-model.md";
const ENDPOINT: &str = "/api/identity/rbac-approval-model-contract";

const REQUIRED_ROLES: &[&str] = &[
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
const REQUIRED_CAPABILITIES: &[&str] = &["request", "approve", "execute", "admin", "audit"];
const REQUIRED_APPROVAL_ROUTES: &[&str] = &[
    "p0-live-execution-default",
    "p0-cmdb-file-exchange",
    "p0-platform-admin-readiness",
    "p1-retirement-governance",
];
const REQUIRED_EXECUTION_GUARDS: &[&str] = &[
    "validation-passed",
    "provider-safe-dry-run",
    "required-approvals",
    "active-lock",
    "redacted-evidence-ready",
    "dependency-health-known",
    "secret-reference-approved",
];
const REQUIRED_INPUTS: &[&str] = &[
    "roleActionMatrix",
    "approvalRouteSummary",
    "executionGuardSummary",
    "requestContext",
    "approvalDecisionSummary",
    "emergencyApprovalSummary",
    "evidenceManifest",
];
const REQUIRED_SEPARATION_CONTROLS: &[&str] = &[
    "requester-cannot-execute",
    "executor-cannot-final-approve-own-request",
    "datacenter-final-approval-required",
    "break-glass-audited",
    "auditor-read-only",
    "platform-admin-break-glass-reviewed",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-authentication-disabled",
    "graph-lookup-disabled",
    "entra-group-lookup-disabled",
    "servicenow-mutation-disabled",
    "approval-execution-disabled",
    "role-assignment-mutation-disabled",
    "policy-mutation-disabled",
    "workflow-mutation-disabled",
    "raw-user-data-disabled",
    "raw-claim-payloads-disabled",
    "raw-group-rows-disabled",
    "raw-approval-payloads-disabled",
    "tenant-identifiers-disabled",
    "app-identifiers-disabled",
    "client-identifiers-disabled",
    "object-identifiers-disabled",
    "principal-identifiers-disabled",
    "group-identifiers-disabled",
    "credential-values-disabled",
    "token-values-disabled",
    "raw-provider-payloads-disabled",
    "missing-role-mapping",
    "missing-approval-route",
    "missing-execution-guard",
    "missing-separation-of-duties",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "RBAC model summary",
    "Role action matrix",
    "Approval route summary",
    "Execution guard summary",
    "Segregation of duties review",
    "Emergency approval review",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsAllowed",
    "liveAuthenticationAllowed",
    "graphCallsAllowed",
    "entraGroupLookupAllowed",
    "serviceNowApprovalMutationAllowed",
    "approvalExecutionAllowed",
    "roleAssignmentMutationAllowed",
    "policyMutationAllowed",
    "workflowMutationAllowed",
    "rawUserDataAllowed",
    "rawClaimPayloadsAllowed",
    "rawGroupRowsAllowed",
    "rawApprovalPayloadsAllowed",
    "tenantIdentifiersAllowed",
    "appIdentifiersAllowed",
    "clientIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "rawProviderPayloadsAllowed",
];
const SAFE_TRUE_FIELDS: &[&str] = &["localMockAuthAllowed"];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "modelMode",
    "identityProvider",
    "configuredForProduction",
    "localMockAuthAllowed",
    "roles",
    "capabilities",
    "approvalRoutes",
    "executionGuards",
    "requiredInputs",
    "separationOfDutiesControls",
    "blockedReasons",
    "requiredEvidence",
    "portalRoleGroupProposals",
    "rules",
    "providerCallsAllowed",
    "liveAuthenticationAllowed",
    "graphCallsAllowed",
    "entraGroupLookupAllowed",
    "serviceNowApprovalMutationAllowed",
    "approvalExecutionAllowed",
    "roleAssignmentMutationAllowed",
    "policyMutationAllowed",
    "workflowMutationAllowed",
    "rawUserDataAllowed",
    "rawClaimPayloadsAllowed",
    "rawGroupRowsAllowed",
    "rawApprovalPayloadsAllowed",
    "tenantIdentifiersAllowed",
    "appIdentifiersAllowed",
    "clientIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "rawProviderPayloadsAllowed",
];
const PORTAL_ROLE_GROUP_KEYS: &[&str] = &[
    "role",
    "title",
    "modelRole",
    "placeholderGroupRef",
    "appRole",
    "capabilities",
    "approvalRouteRefs",
    "accessBoundary",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    ("roles", "rbacApprovalModelRoles", REQUIRED_ROLES),
    (
        "capabilities",
        "rbacApprovalModelCapabilities",
        REQUIRED_CAPABILITIES,
    ),
    (
        "approvalRoutes",
        "rbacApprovalModelApprovalRoutes",
        REQUIRED_APPROVAL_ROUTES,
    ),
    (
        "executionGuards",
        "rbacApprovalModelExecutionGuards",
        REQUIRED_EXECUTION_GUARDS,
    ),
    (
        "requiredInputs",
        "rbacApprovalModelRequiredInputs",
        REQUIRED_INPUTS,
    ),
    (
        "separationOfDutiesControls",
        "rbacApprovalModelSeparationOfDutiesControls",
        REQUIRED_SEPARATION_CONTROLS,
    ),
    (
        "blockedReasons",
        "rbacApprovalModelBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
    (
        "requiredEvidence",
        "rbacApprovalModelRequiredEvidence",
        REQUIRED_EVIDENCE,
    ),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "modelMode",
    "identityProvider",
    "configuredForProduction",
    "localMockAuthAllowed",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "providerCallsAllowed",
    "liveAuthenticationAllowed",
    "graphCallsAllowed",
    "entraGroupLookupAllowed",
    "serviceNowApprovalMutationAllowed",
    "approvalExecutionAllowed",
    "roleAssignmentMutationAllowed",
    "policyMutationAllowed",
    "workflowMutationAllowed",
    "rawUserDataAllowed",
    "rawClaimPayloadsAllowed",
    "rawGroupRowsAllowed",
    "rawApprovalPayloadsAllowed",
    "tenantIdentifiersAllowed",
    "appIdentifiersAllowed",
    "clientIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "credentialValuesAllowed",
    "tokenValuesAllowed",
    "rawProviderPayloadsAllowed",
    "roles",
    "capabilities",
    "approvalRoutes",
    "executionGuards",
    "requiredInputs",
    "separationOfDutiesControls",
    "blockedReasons",
    "requiredEvidence",
];

#[derive(Clone, Copy)]
struct PortalRoleGroup {
    role: &'static str,
    title: &'static str,
    model_role: &'static str,
    placeholder_group_ref: &'static str,
    proposed_app_role: &'static str,
    capabilities: &'static [&'static str],
    approval_route_refs: &'static [&'static str],
}

const REQUIRED_PORTAL_ROLE_GROUPS: &[PortalRoleGroup] = &[
    PortalRoleGroup {
        role: "PlatformAdmin",
        title: "Platform Admins",
        model_role: "PlatformAdmin",
        placeholder_group_ref: "group-ref:ryuki-portal-platform-admins",
        proposed_app_role: "PlatformAdmin",
        capabilities: &["admin", "approve", "audit"],
        approval_route_refs: &["p0-platform-admin-readiness"],
    },
    PortalRoleGroup {
        role: "DatacenterApprover",
        title: "Approvers",
        model_role: "DatacenterApprover",
        placeholder_group_ref: "group-ref:ryuki-portal-approvers",
        proposed_app_role: "DatacenterApprover",
        capabilities: &["approve", "audit"],
        approval_route_refs: &["p0-live-execution-default", "p1-retirement-governance"],
    },
    PortalRoleGroup {
        role: "VMwareOperator",
        title: "VMware Operators",
        model_role: "VMwareOperator",
        placeholder_group_ref: "group-ref:ryuki-portal-vmware-operators",
        proposed_app_role: "VMwareOperator",
        capabilities: &["execute", "audit"],
        approval_route_refs: &["p0-live-execution-default"],
    },
    PortalRoleGroup {
        role: "HyperVOperator",
        title: "Hyper-V Operators",
        model_role: "HyperVOperator",
        placeholder_group_ref: "group-ref:ryuki-portal-hyper-v-operators",
        proposed_app_role: "HyperVOperator",
        capabilities: &["execute", "audit"],
        approval_route_refs: &["p0-live-execution-default"],
    },
    PortalRoleGroup {
        role: "ProxmoxOperator",
        title: "Proxmox Operators",
        model_role: "ProxmoxOperator",
        placeholder_group_ref: "group-ref:ryuki-portal-proxmox-operators",
        proposed_app_role: "ProxmoxOperator",
        capabilities: &["execute", "audit"],
        approval_route_refs: &["p0-live-execution-default"],
    },
    PortalRoleGroup {
        role: "WintelLinuxOperator",
        title: "Wintel/Linux Operators",
        model_role: "WintelLinuxOperator",
        placeholder_group_ref: "group-ref:ryuki-portal-wintel-linux-operators",
        proposed_app_role: "WintelLinuxOperator",
        capabilities: &["execute", "audit"],
        approval_route_refs: &["p0-live-execution-default"],
    },
    PortalRoleGroup {
        role: "BackupOperator",
        title: "Backup Operators",
        model_role: "BackupOperator",
        placeholder_group_ref: "group-ref:ryuki-portal-backup-operators",
        proposed_app_role: "BackupOperator",
        capabilities: &["execute", "audit"],
        approval_route_refs: &["p0-live-execution-default"],
    },
    PortalRoleGroup {
        role: "MonitoringOperator",
        title: "Monitoring Operators",
        model_role: "MonitoringOperator",
        placeholder_group_ref: "group-ref:ryuki-portal-monitoring-operators",
        proposed_app_role: "MonitoringOperator",
        capabilities: &["execute", "audit"],
        approval_route_refs: &["p0-live-execution-default"],
    },
    PortalRoleGroup {
        role: "ServiceDesk",
        title: "Service Desk",
        model_role: "ServiceDesk",
        placeholder_group_ref: "group-ref:ryuki-portal-service-desk",
        proposed_app_role: "ServiceDesk",
        capabilities: &["request", "audit"],
        approval_route_refs: &["p0-cmdb-file-exchange", "p1-retirement-governance"],
    },
    PortalRoleGroup {
        role: "Auditor",
        title: "Auditor",
        model_role: "Auditor",
        placeholder_group_ref: "group-ref:ryuki-portal-auditors",
        proposed_app_role: "Auditor",
        capabilities: &["audit"],
        approval_route_refs: &["p0-live-execution-default", "p1-retirement-governance"],
    },
    PortalRoleGroup {
        role: "Requester",
        title: "Requester",
        model_role: "Requester",
        placeholder_group_ref: "group-ref:ryuki-portal-requesters",
        proposed_app_role: "Requester",
        capabilities: &["request"],
        approval_route_refs: &["p1-retirement-governance"],
    },
    PortalRoleGroup {
        role: "BreakGlassAdmin",
        title: "Break-Glass",
        model_role: "BreakGlassAdmin",
        placeholder_group_ref: "group-ref:ryuki-portal-break-glass",
        proposed_app_role: "BreakGlassAdmin",
        capabilities: &["admin", "audit"],
        approval_route_refs: &["p0-live-execution-default", "p0-platform-admin-readiness"],
    },
];

#[derive(Clone, Copy)]
struct RequiredRule {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

const REQUIRED_RULES: &[RequiredRule] = &[
    RequiredRule {
        id: "no-live-rbac-provider-execution",
        decision: "block",
        requirement: "RBAC approval model reports static readiness only and never calls identity providers, Microsoft Graph, ServiceNow, policy engines, approval systems, or provider APIs.",
        evidence: "RBAC model summary",
    },
    RequiredRule {
        id: "access-catalog-alignment-required",
        decision: "block",
        requirement: "Model roles, capabilities, approval routes, execution guards, and evidence records must align with the static access-control catalog before workflow consumption.",
        evidence: "Role action matrix",
    },
    RequiredRule {
        id: "separation-of-duties-required",
        decision: "block",
        requirement: "Requester, executor, approver, administrator, emergency, and audit duties must preserve least privilege and prevent approval or execution bypasses.",
        evidence: "Segregation of duties review",
    },
    RequiredRule {
        id: "raw-rbac-data-not-exposed",
        decision: "block",
        requirement: "RBAC approval evidence must use safe summaries only and must not expose user records, claim payloads, group rows, tenant IDs, app IDs, client IDs, object IDs, principal IDs, group IDs, credentials, tokens, approval payloads, ServiceNow payloads, or provider payloads.",
        evidence: "Evidence references",
    },
];

#[derive(Deserialize)]
struct ContextInput {
    catalog: Value,
    access_catalog: Value,
    catalog_text: String,
    access_text: String,
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
struct AccessCatalogInput {
    model: Value,
    access_catalog: Value,
}

#[derive(Deserialize)]
struct DocsInput {
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Deserialize)]
struct ScanInput {
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let input = fs::read_to_string(path)
        .map_err(|error| format!("failed to read RBAC approval model context: {error}"))?;
    let context: ContextInput = serde_json::from_str(&input)
        .map_err(|error| format!("invalid RBAC approval model context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.access_text),
        ACCESS_CATALOG_PATH,
        &mut errors,
    );
    validate_access_catalog_alignment_value(&context.catalog, &context.access_catalog, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
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
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid RBAC approval model catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid RBAC approval model program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_access_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let payload: AccessCatalogInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid RBAC approval model access catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_access_catalog_alignment_value(&payload.model, &payload.access_catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid RBAC approval model docs JSON: {error}"))?;
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
    let payload: ScanInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid RBAC approval model scan JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "RBAC approval model version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "RBAC approval model status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "RBAC approval model source must be static-seed",
    );
    expect(
        string_value(catalog, "modelMode") == Some("static-rbac-approval-model"),
        errors,
        "RBAC approval model mode must be static-rbac-approval-model",
    );
    expect(
        string_value(catalog, "identityProvider") == Some("Microsoft Entra ID"),
        errors,
        "RBAC approval model provider must be Microsoft Entra ID",
    );
    expect(
        bool_value(catalog, "configuredForProduction") == Some(false),
        errors,
        "RBAC approval model configuredForProduction must be false",
    );
    expect(
        bool_value(catalog, "localMockAuthAllowed") == Some(true),
        errors,
        "RBAC approval model must keep local mock auth allowed",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("RBAC approval model {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "roles", REQUIRED_ROLES, errors);
    validate_required_array(catalog, "capabilities", REQUIRED_CAPABILITIES, errors);
    validate_required_array(catalog, "approvalRoutes", REQUIRED_APPROVAL_ROUTES, errors);
    validate_required_array(
        catalog,
        "executionGuards",
        REQUIRED_EXECUTION_GUARDS,
        errors,
    );
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(
        catalog,
        "separationOfDutiesControls",
        REQUIRED_SEPARATION_CONTROLS,
        errors,
    );
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_portal_role_group_proposals(catalog, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        errors.push("RBAC approval model catalog must be a YAML mapping".to_string());
        return;
    };
    let keys = map.keys().map(String::as_str).collect::<Vec<_>>();
    let required = REQUIRED_CATALOG_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let actual = keys.iter().copied().collect::<BTreeSet<_>>();
    let missing = REQUIRED_CATALOG_KEYS
        .iter()
        .copied()
        .filter(|key| !actual.contains(key))
        .collect::<Vec<_>>();
    let unexpected = keys
        .iter()
        .copied()
        .filter(|key| !required.contains(key))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        errors.push(format!(
            "RBAC approval model missing catalog keys: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "RBAC approval model unexpected catalog keys: {}",
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
    let required_set = required.iter().copied().collect::<BTreeSet<_>>();
    let value_set = values.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let missing = required
        .iter()
        .copied()
        .filter(|item| !value_set.contains(item))
        .collect::<Vec<_>>();
    let unexpected = values
        .iter()
        .map(String::as_str)
        .filter(|item| !required_set.contains(item))
        .collect::<Vec<_>>();
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
                "{field} contains prohibited RBAC approval value {value}"
            ));
        }
    }
}

fn validate_portal_role_group_proposals(catalog: &Value, errors: &mut Vec<String>) {
    let Some(proposals) = catalog
        .get("portalRoleGroupProposals")
        .and_then(Value::as_array)
    else {
        errors.push("portalRoleGroupProposals must be array".to_string());
        return;
    };
    let roles = proposals
        .iter()
        .filter_map(|proposal| string_value(proposal, "role"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let expected_roles = REQUIRED_PORTAL_ROLE_GROUPS
        .iter()
        .map(|proposal| proposal.role)
        .collect::<Vec<_>>();
    expect(
        roles == expected_roles,
        errors,
        "portalRoleGroupProposals roles must match required Ryuki portal groups",
    );
    expect(
        roles.iter().collect::<BTreeSet<_>>().len() == roles.len(),
        errors,
        "portalRoleGroupProposals roles must be unique",
    );
    let refs = proposals
        .iter()
        .filter_map(|proposal| string_value(proposal, "placeholderGroupRef"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    expect(
        refs.iter().collect::<BTreeSet<_>>().len() == refs.len(),
        errors,
        "portalRoleGroupProposals placeholder group refs must be unique",
    );
    let names = proposals
        .iter()
        .filter_map(|proposal| string_value(proposal, "appRole"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    expect(
        names.iter().collect::<BTreeSet<_>>().len() == names.len(),
        errors,
        "portalRoleGroupProposals proposed app roles must be unique",
    );
    for proposal in proposals {
        let role = string_value(proposal, "role").unwrap_or("(missing role)");
        validate_object_keys(
            proposal,
            PORTAL_ROLE_GROUP_KEYS,
            &format!("portalRoleGroupProposals {role}"),
            errors,
        );
        let Some(expected) = REQUIRED_PORTAL_ROLE_GROUPS
            .iter()
            .find(|candidate| Some(candidate.role) == string_value(proposal, "role"))
        else {
            errors.push(format!("portalRoleGroupProposals unexpected role {role}"));
            continue;
        };
        for (field, expected_value) in [
            ("title", expected.title),
            ("modelRole", expected.model_role),
            ("placeholderGroupRef", expected.placeholder_group_ref),
            ("appRole", expected.proposed_app_role),
        ] {
            expect(
                string_value(proposal, field) == Some(expected_value),
                errors,
                format!("portalRoleGroupProposals {role} {field} must match static proposal"),
            );
        }
        expect(
            placeholder_group_ref(string_value(proposal, "placeholderGroupRef")),
            errors,
            format!("portalRoleGroupProposals {role} must use placeholder group ref"),
        );
        expect(
            string_value(proposal, "appRole").is_some_and(valid_app_role),
            errors,
            format!("portalRoleGroupProposals {role} must use valid app role name"),
        );
        validate_string_array_exact(
            proposal,
            "capabilities",
            expected.capabilities,
            &format!("portalRoleGroupProposals {role}"),
            errors,
        );
        validate_string_array_exact(
            proposal,
            "approvalRouteRefs",
            expected.approval_route_refs,
            &format!("portalRoleGroupProposals {role}"),
            errors,
        );
        expect(
            string_value(proposal, "accessBoundary")
                .is_some_and(|value| value.contains("disabled")),
            errors,
            format!("portalRoleGroupProposals {role} access boundary must keep live integration disabled"),
        );
    }
}

fn validate_string_array_exact(
    value: &Value,
    field: &str,
    expected: &[&str],
    label: &str,
    errors: &mut Vec<String>,
) {
    let values = string_array(value, field);
    expect(
        values
            == expected
                .iter()
                .map(|item| (*item).to_string())
                .collect::<Vec<_>>(),
        errors,
        format!("{label} {field} must match static proposal"),
    );
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = rule_values(catalog.get("rules"), "RBAC approval model", errors);
    let rule_ids = rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<Vec<_>>();
    expect(
        rule_ids.len() == REQUIRED_RULES.len(),
        errors,
        "RBAC approval model rule count must match required rules",
    );
    let expected_ids = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .collect::<Vec<_>>();
    push_missing_unexpected(
        "RBAC approval model",
        "rules",
        &rule_ids,
        &expected_ids,
        errors,
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "RBAC approval model rule IDs must be unique",
    );
    let rule_details = rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect::<Vec<_>>();
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "RBAC approval model rule details must be unique",
    );
    if let Some(rule_items) = catalog.get("rules").and_then(Value::as_array) {
        for item in rule_items {
            let id = string_value(item, "id").unwrap_or("(missing id)");
            validate_object_keys(
                item,
                RULE_KEYS,
                &format!("RBAC approval model rule {id}"),
                errors,
            );
        }
    }
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        for (field, actual, expected) in [
            ("decision", rule.decision.as_str(), expected_rule.decision),
            (
                "requirement",
                rule.requirement.as_str(),
                expected_rule.requirement,
            ),
            ("evidence", rule.evidence.as_str(), expected_rule.evidence),
        ] {
            expect(
                actual == expected,
                errors,
                format!(
                    "RBAC approval model rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

fn validate_access_catalog_alignment_value(
    model: &Value,
    access_catalog: &Value,
    errors: &mut Vec<String>,
) {
    let role_ids = object_field_strings(access_catalog, "roles", "id");
    expect(
        role_ids == string_array(model, "roles"),
        errors,
        "access-control roles must match RBAC approval model roles",
    );
    expect(
        role_ids.iter().collect::<BTreeSet<_>>().len() == role_ids.len(),
        errors,
        "access-control role IDs must be unique",
    );
    validate_role_permissions(access_catalog, errors);

    let route_ids = object_field_strings(access_catalog, "approvalRoutes", "id");
    expect(
        route_ids == string_array(model, "approvalRoutes"),
        errors,
        "access-control approval routes must match RBAC approval model routes",
    );
    expect(
        route_ids.iter().collect::<BTreeSet<_>>().len() == route_ids.len(),
        errors,
        "access-control approval route IDs must be unique",
    );
    validate_approval_routes(access_catalog, errors);

    let guard_ids = object_field_strings(access_catalog, "executionGuards", "id");
    expect(
        guard_ids == string_array(model, "executionGuards"),
        errors,
        "access-control execution guards must match RBAC approval model guards",
    );
    for guard in object_array(access_catalog, "executionGuards") {
        let id = string_value(guard, "id").unwrap_or("(missing id)");
        expect(
            string_value(guard, "decision") == Some("block"),
            errors,
            format!("access-control execution guard {id} must block"),
        );
        let evidence = string_value(guard, "evidence").unwrap_or_default();
        expect(
            REQUIRED_EVIDENCE.contains(&evidence)
                || [
                    "result",
                    "plan",
                    "decisions",
                    "record",
                    "manifest",
                    "status",
                    "state",
                ]
                .iter()
                .any(|suffix| evidence.ends_with(suffix)),
            errors,
            format!("access-control execution guard {id} must expose safe evidence"),
        );
    }
}

fn validate_role_permissions(access_catalog: &Value, errors: &mut Vec<String>) {
    let roles = object_array(access_catalog, "roles");
    let role_by_id = roles
        .iter()
        .filter_map(|role| Some((string_value(role, "id")?, *role)))
        .collect::<BTreeMap<_, _>>();
    let requester = role_by_id.get("requester").copied();
    let auditor = role_by_id.get("auditor").copied();
    let datacenter = role_by_id.get("datacenter-approver").copied();
    let platform_admin = role_by_id.get("platform-admin").copied();
    expect(
        requester.is_some_and(|role| bool_value(role, "canRequest") == Some(true)),
        errors,
        "requester must be able to request",
    );
    expect(
        requester.is_some_and(|role| {
            bool_value(role, "canApprove") == Some(false)
                && bool_value(role, "canExecute") == Some(false)
                && bool_value(role, "canAdmin") == Some(false)
        }),
        errors,
        "requester must not approve, execute, or admin",
    );
    expect(
        auditor.is_some_and(|role| {
            bool_value(role, "canApprove") == Some(false)
                && bool_value(role, "canExecute") == Some(false)
                && bool_value(role, "canAdmin") == Some(false)
                && bool_value(role, "canAudit") == Some(true)
        }),
        errors,
        "auditor must not approve, execute, or admin",
    );
    expect(
        datacenter.is_some_and(|role| {
            bool_value(role, "canApprove") == Some(true)
                && bool_value(role, "canExecute") == Some(false)
        }),
        errors,
        "datacenter-approver must approve without execute",
    );
    expect(
        platform_admin.is_some_and(|role| {
            bool_value(role, "canAdmin") == Some(true) && bool_value(role, "canAudit") == Some(true)
        }),
        errors,
        "platform-admin must admin and audit",
    );
}

fn validate_approval_routes(access_catalog: &Value, errors: &mut Vec<String>) {
    let roles = object_array(access_catalog, "roles");
    let approver_by_title = roles
        .iter()
        .filter_map(|role| {
            Some((
                string_value(role, "title")?,
                bool_value(role, "canApprove")?,
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let routes = object_array(access_catalog, "approvalRoutes");
    for route in routes.iter().copied() {
        let id = string_value(route, "id").unwrap_or("(missing id)");
        let required_actors = string_array(route, "requiredActors");
        expect(
            !required_actors.is_empty(),
            errors,
            format!("approval route {id} must have required actors"),
        );
        expect(
            string_array(route, "evidence").contains(&"Approval decisions".to_string()),
            errors,
            format!("approval route {id} must require approval decision evidence"),
        );
        for actor in required_actors {
            if let Some(can_approve) = approver_by_title.get(actor.as_str()) {
                expect(
                    *can_approve,
                    errors,
                    format!("approval route {id} required actor {actor} must be able to approve"),
                );
            }
        }
    }
    let live_route = routes
        .iter()
        .find(|route| string_value(route, "id") == Some("p0-live-execution-default"));
    expect(
        live_route.is_some_and(|route| {
            string_array(route, "requiredActors").contains(&"Datacenter Approver".to_string())
        }),
        errors,
        "p0-live-execution-default must require Datacenter Approver",
    );
    expect(
        live_route.is_some_and(|route| bool_value(route, "emergencyAllowed") == Some(true)),
        errors,
        "p0-live-execution-default must keep emergency review allowed",
    );
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = csharp_without_comments(program);
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
        exact_string_assignment(&block, "modelMode", "static-rbac-approval-model"),
        errors,
        "API must keep static-rbac-approval-model mode",
    );
    expect(
        exact_string_assignment(&block, "identityProvider", "Microsoft Entra ID"),
        errors,
        "API must keep Microsoft Entra ID provider",
    );
    expect(
        exact_assignment(&block, "configuredForProduction", "false"),
        errors,
        "API must keep configuredForProduction false",
    );
    expect(
        exact_assignment(&block, "localMockAuthAllowed", "true"),
        errors,
        "API must keep localMockAuthAllowed true",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&block, field, "false"),
            errors,
            format!("API must keep {field} disabled"),
        );
    }
    for (field, variable, required) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&block, field, variable),
            errors,
            format!("API must bind {field} to {variable}"),
        );
        let values = csharp_array_values(&uncommented_program, variable, field, errors);
        validate_api_array(
            field,
            values,
            string_array(catalog, field),
            required,
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_endpoint_singleton_fields(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let blocks = extract_endpoint_blocks(program);
    if blocks.is_empty() {
        errors.push(format!("API missing endpoint {ENDPOINT}"));
        return String::new();
    }
    if blocks.len() != 1 {
        errors.push(format!("API must register exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let Some(block) = endpoint_payload_block(&blocks[0], errors) else {
        return String::new();
    };
    block
}

fn extract_endpoint_blocks(program: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    each_mapget_registration(program, |start, open_paren, close_paren| {
        let args = &program[open_paren + 1..close_paren];
        let route_expression = first_top_level_argument(args);
        if static_route_value(&route_expression, Some(program), Some(start), &[]).as_deref()
            != Some(ENDPOINT)
        {
            return;
        }
        let statement_end = find_statement_end(program, close_paren + 1)
            .map(|index| index + 1)
            .unwrap_or(close_paren + 1);
        blocks.push(program[start..statement_end].to_string());
    });
    blocks
}

fn endpoint_payload_block(endpoint: &str, errors: &mut Vec<String>) -> Option<String> {
    let json_indexes = results_json_indexes(endpoint);
    if json_indexes.is_empty() {
        errors.push(format!("API endpoint {ENDPOINT} missing JSON payload"));
        return None;
    }
    if json_indexes.len() != 1 {
        errors.push("API RBAC approval endpoint must declare exactly one JSON payload".to_string());
        return None;
    }
    let json_index = json_indexes[0];
    let Some(object_start) = endpoint[json_index..]
        .find('{')
        .map(|index| json_index + index)
    else {
        errors.push("API RBAC approval JSON payload must be a single object".to_string());
        return None;
    };
    let Some(object_end) = matching_delimiter_index(endpoint, object_start, b'{', b'}') else {
        errors.push("API RBAC approval JSON payload must be a single object".to_string());
        return None;
    };
    Some(endpoint[object_start..=object_end].to_string())
}

fn results_json_indexes(endpoint: &str) -> Vec<usize> {
    let masked = csharp_code_mask(endpoint);
    let mut indexes = Vec::new();
    let mut offset = 0usize;
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
        if masked.as_bytes().get(cursor) == Some(&b'(') {
            indexes.push(start);
        }
    }
    indexes
}

fn validate_api_array(
    field: &str,
    values: Option<Vec<String>>,
    catalog_values: Vec<String>,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    if values == catalog_values {
        return;
    }
    let required_values = required
        .iter()
        .map(|item| (*item).to_string())
        .collect::<Vec<_>>();
    if values == required_values {
        errors.push(format!("API {field} must match catalog"));
        return;
    }
    errors.push(format!("API {field} must match catalog"));
    push_missing_unexpected(
        "API",
        field,
        &values.iter().map(String::as_str).collect::<Vec<_>>(),
        &catalog_values
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        errors,
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = rule_values(catalog.get("rules"), "RBAC approval model", errors);
    let api_rules = api_rules(block);
    let api_ids = api_rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<Vec<_>>();
    let catalog_ids = catalog_rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<Vec<_>>();
    expect(
        api_ids.len() == catalog_ids.len(),
        errors,
        "API RBAC approval rule count must match catalog",
    );
    push_missing_unexpected("API", "rules", &api_ids, &catalog_ids, errors);
    expect(
        api_ids.iter().collect::<BTreeSet<_>>().len() == api_ids.len(),
        errors,
        "API RBAC approval rule IDs must be unique",
    );
    let api_details = api_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect::<Vec<_>>();
    expect(
        api_details.iter().collect::<BTreeSet<_>>().len() == api_details.len(),
        errors,
        "API RBAC approval rule details must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            errors.push(format!("API missing rule {}", catalog_rule.id));
            continue;
        };
        for (field, actual, expected) in [
            (
                "decision",
                api_rule.decision.as_str(),
                catalog_rule.decision.as_str(),
            ),
            (
                "requirement",
                api_rule.requirement.as_str(),
                catalog_rule.requirement.as_str(),
            ),
            (
                "evidence",
                api_rule.evidence.as_str(),
                catalog_rule.evidence.as_str(),
            ),
        ] {
            expect(
                actual == expected,
                errors,
                format!("API rule {} {field} must match catalog", catalog_rule.id),
            );
        }
    }
}

fn api_rules(block: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let masked = csharp_code_mask(block);
    let mut offset = 0usize;
    while let Some(relative) = masked[offset..].find("new") {
        let start = offset + relative;
        offset = start + "new".len();
        if !identifier_boundary(&masked, start, start + "new".len()) {
            continue;
        }
        let object_start = skip_ascii_whitespace(&masked, start + "new".len());
        if masked.as_bytes().get(object_start) != Some(&b'{') {
            continue;
        }
        let Some(object_end) = matching_delimiter_index(&masked, object_start, b'{', b'}') else {
            continue;
        };
        let object = &block[object_start..=object_end];
        let assignments = assignment_map(object);
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            assignments.get("id"),
            assignments.get("decision"),
            assignments.get("requirement"),
            assignments.get("evidence"),
        ) {
            rules.push(Rule {
                id: trim_csharp_string(id),
                decision: trim_csharp_string(decision),
                requirement: trim_csharp_string(requirement),
                evidence: trim_csharp_string(evidence),
            });
        }
        offset = object_end + 1;
    }
    rules
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped = csharp_code_mask(block);
    for field in assignment_fields(&stripped) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected RBAC approval field {field}"
            ));
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited RBAC approval field {field}"
            ));
        }
        validate_allowed_suffix_key(&field, &format!("API endpoint.{field}"), errors);
    }
}

fn validate_endpoint_singleton_fields(block: &str, errors: &mut Vec<String>) {
    let fields = top_level_assignment_fields(block);
    for field in singleton_endpoint_fields() {
        let count = fields
            .iter()
            .filter(|candidate| candidate.as_str() == field)
            .count();
        expect(
            count == 1,
            errors,
            format!("API endpoint field {field} must be unique"),
        );
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for (field, value) in top_level_assignment_values(block) {
        if value == "true"
            && !SAFE_TRUE_FIELDS.contains(&field.as_str())
            && unsafe_true_field(&field)
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
        "API README must document RBAC approval model endpoint",
    );
    expect(
        catalog_readme.contains("rbac-approval-model-contract.yaml"),
        errors,
        "catalog README must include RBAC approval model contract",
    );
    expect(
        doc_readme.contains("rbac-approval-model.md"),
        errors,
        "workflow README must include RBAC approval model doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "RBAC approval model doc must mention endpoint",
    );
    expect(
        doc.contains("No live authentication"),
        errors,
        "RBAC approval model doc must document live auth boundary",
    );
    expect(
        doc.contains("access-control catalog"),
        errors,
        "RBAC approval model doc must mention access-control catalog alignment",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited RBAC approval field"
                    ));
                }
                validate_allowed_suffix_key(key, &child_path, errors);
                scan_prohibited_value(child, &child_path, errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => scan_prohibited_text(text, path, errors),
        _ => {}
    }
}

fn scan_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if whole_file_text(path, text) {
        if prohibited_value(text) {
            errors.push(format!("{path} contains prohibited value"));
        }
        if source_identifier_path(path) {
            validate_source_identifiers(text, path, errors);
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
            "{path} contains prohibited RBAC approval field {text}"
        ));
    }
}

fn validate_source_identifiers(value: &str, path: &str, errors: &mut Vec<String>) {
    for identifier in source_identifiers(&csharp_without_comments(value)) {
        if safe_text_value(&identifier) {
            continue;
        }
        if prohibited_field(&identifier) {
            errors.push(format!(
                "{path} contains prohibited RBAC approval field {identifier}"
            ));
        }
        validate_allowed_suffix_key(&identifier, &format!("{path}.{identifier}"), errors);
    }
}

fn validate_allowed_suffix_key(key: &str, path: &str, errors: &mut Vec<String>) {
    if key.ends_with("Allowed")
        && !REQUIRED_DISABLED_FIELDS.contains(&key)
        && !SAFE_TRUE_FIELDS.contains(&key)
    {
        errors.push(format!("{path} contains unsupported allowed flag {key}"));
    }
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn source_identifier_path(path: &str) -> bool {
    path.ends_with(".cs")
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    safe_text_arrays().iter().any(|items| items.contains(&text))
        || REQUIRED_PORTAL_ROLE_GROUPS.iter().any(|proposal| {
            [
                proposal.role,
                proposal.title,
                proposal.model_role,
                proposal.placeholder_group_ref,
                proposal.proposed_app_role,
            ]
            .contains(&text)
                || proposal.capabilities.contains(&text)
                || proposal.approval_route_refs.contains(&text)
        })
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
        || [
            "draft",
            "static-seed",
            "static-rbac-approval-model",
            "Microsoft Entra ID",
            "block",
            "true",
            "false",
        ]
        .contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 11] {
    [
        REQUIRED_ROLES,
        REQUIRED_CAPABILITIES,
        REQUIRED_APPROVAL_ROUTES,
        REQUIRED_EXECUTION_GUARDS,
        REQUIRED_INPUTS,
        REQUIRED_SEPARATION_CONTROLS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
        PORTAL_ROLE_GROUP_KEYS,
    ]
}

fn prohibited_field(value: &str) -> bool {
    if safe_text_value(value) {
        return false;
    }
    let normalized = normalize(value);
    [
        "credential",
        "password",
        "bearer",
        "token",
        "url",
        "endpoint",
    ]
    .contains(&normalized.as_str())
        || [
            "userid",
            "useridentifier",
            "userprincipalname",
            "upn",
            "mailaddress",
            "emailaddress",
            "accountid",
            "tenantid",
            "tenantidentifier",
            "subscriptionid",
            "subscriptionidentifier",
            "appid",
            "clientid",
            "objectid",
            "principalid",
            "groupid",
            "serialnumber",
            "rawclaim",
            "claimpayload",
            "rawgroup",
            "grouprow",
            "approvalpayload",
            "servicenowpayload",
            "providerpayload",
            "credential",
            "secret",
            "accesstoken",
            "token",
            "password",
            "bearer",
            "endpointurl",
            "url",
        ]
        .iter()
        .any(|term| normalized.contains(term))
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
        || (has_any(&tokens, &["id", "guid"]) && tokens.len() > 1)
        || (has_any(
            &tokens,
            &[
                "user",
                "tenant",
                "app",
                "client",
                "object",
                "principal",
                "group",
                "account",
            ],
        ) && has_any(
            &tokens,
            &[
                "id",
                "identifier",
                "key",
                "value",
                "data",
                "record",
                "records",
                "row",
                "rows",
                "payload",
                "claims",
            ],
        ))
        || (tokens.contains(&"raw".to_string())
            && has_any(
                &tokens,
                &[
                    "user", "claim", "claims", "group", "rows", "approval", "provider", "payload",
                ],
            ))
        || (tokens.contains(&"bypass".to_string())
            && has_any(&tokens, &["approval", "rbac", "role", "execution"]))
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut expanded = String::with_capacity(value.len() * 2);
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            expanded.push(' ');
        }
        if ch.is_ascii_alphanumeric() {
            expanded.push(ch.to_ascii_lowercase());
            previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            expanded.push(' ');
            previous_lower_or_digit = false;
        }
    }
    expanded
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn prohibited_value(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("akia")
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || lower.contains("://")
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_email_like(text)
        || contains_internal_hostname(text)
        || contains_secret_assignment(&lower)
}

fn contains_private_ip(text: &str) -> bool {
    for candidate in text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        let octets = candidate.split('.').collect::<Vec<_>>();
        if octets.len() != 4 {
            continue;
        }
        let Some(parsed) = octets
            .iter()
            .map(|part| part.parse::<u16>().ok())
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        if parsed.iter().any(|octet| *octet > 255) {
            continue;
        }
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
            let parts = candidate.split('-').collect::<Vec<_>>();
            parts.len() == 5
                && [8usize, 4, 4, 4, 12]
                    .iter()
                    .zip(parts.iter())
                    .all(|(len, part)| {
                        part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit())
                    })
        })
}

fn contains_email_like(text: &str) -> bool {
    text.split_ascii_whitespace().any(|candidate| {
        let trimmed = candidate.trim_matches(|ch: char| {
            !ch.is_ascii_alphanumeric() && ch != '@' && ch != '.' && ch != '-' && ch != '_'
        });
        let Some((local, domain)) = trimmed.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain.rsplit('.').next().is_some_and(|tld| tld.len() >= 2)
    })
}

fn contains_internal_hostname(text: &str) -> bool {
    text.split_ascii_whitespace().any(|candidate| {
        let trimmed = candidate
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-');
        let lower = trimmed.to_ascii_lowercase();
        lower.ends_with(".internal")
            || lower.ends_with(".local")
            || lower.ends_with(".corp")
            || lower.ends_with(".lan")
    })
}

fn contains_secret_assignment(lower: &str) -> bool {
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
        lower.find(key).is_some_and(|start| {
            lower[start + key.len()..]
                .trim_start()
                .starts_with([':', '='])
        })
    })
}

fn first_top_level_argument(args: &str) -> String {
    split_top_level(args)
        .first()
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn static_route_value(
    expression: &str,
    program: Option<&str>,
    position: Option<usize>,
    seen_variables: &[String],
) -> Option<String> {
    let expression = strip_outer_parentheses(expression.trim());
    if is_plain_identifier(&expression) {
        if let (Some(program), Some(position)) = (program, position) {
            if seen_variables.contains(&expression) {
                return None;
            }
            if let Some(declaration) =
                static_route_variable_declaration(program, &expression, position)
            {
                let mut seen = seen_variables.to_vec();
                seen.push(expression.clone());
                return static_route_value(&declaration, Some(program), Some(position), &seen);
            }
        }
    }
    let parts = split_top_level_plus(&expression);
    if parts.len() == 1 {
        return csharp_string_literal_value(&expression);
    }
    let mut values = Vec::new();
    for part in parts {
        values.push(static_route_value(
            &part,
            program,
            position,
            seen_variables,
        )?);
    }
    Some(values.join(""))
}

fn static_route_variable_declaration(
    program: &str,
    variable: &str,
    position: usize,
) -> Option<String> {
    let mut declarations = Vec::new();
    let mut index = 0usize;
    while let Some(start) = next_code_match(program, variable, index) {
        if start >= position {
            break;
        }
        index = start + variable.len();
        if !identifier_boundary(program, start, start + variable.len()) {
            continue;
        }
        let prefix = &program[..start];
        let prefix_ok = ["var", "string", "const string"].iter().any(|keyword| {
            let trimmed_len = prefix.trim_end().len();
            trimmed_len >= keyword.len()
                && prefix[..trimmed_len].ends_with(keyword)
                && prefix[..trimmed_len - keyword.len()]
                    .chars()
                    .last()
                    .map(|ch| !is_identifier_byte(ch as u8))
                    .unwrap_or(true)
        });
        let cursor = skip_ascii_whitespace(program, start + variable.len());
        if !prefix_ok || program.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        if let Some(statement_end) = find_statement_end(program, cursor + 1) {
            declarations.push(program[cursor + 1..statement_end].trim().to_string());
        }
    }
    (declarations.len() == 1).then(|| declarations.remove(0))
}

fn each_mapget_registration(program: &str, mut callback: impl FnMut(usize, usize, usize)) {
    let mut index = 0usize;
    while let Some(start) = next_app_mapget_match(program, index) {
        let Some(open_relative) = program[start..].find('(') else {
            break;
        };
        let open = start + open_relative;
        let Some(close) = matching_delimiter_index(program, open, b'(', b')') else {
            break;
        };
        callback(start, open, close);
        index = close + 1;
    }
}

fn next_app_mapget_match(program: &str, start: usize) -> Option<usize> {
    let mut index = start;
    while let Some(candidate) = next_code_match(program, "app", index) {
        let mut cursor = candidate + "app".len();
        if !identifier_boundary(program, candidate, candidate + "app".len()) {
            index = candidate + "app".len();
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor);
        if program.as_bytes().get(cursor) != Some(&b'.') {
            index = candidate + "app".len();
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor + 1);
        if !program[cursor..].starts_with("MapGet")
            || !identifier_boundary(program, cursor, cursor + "MapGet".len())
        {
            index = candidate + "app".len();
            continue;
        }
        cursor = skip_ascii_whitespace(program, cursor + "MapGet".len());
        if program.as_bytes().get(cursor) == Some(&b'(') {
            return Some(candidate);
        }
        index = candidate + "app".len();
    }
    None
}

fn next_code_match(text: &str, needle: &str, start: usize) -> Option<usize> {
    let mut index = start;
    while index < text.len() {
        if text.as_bytes().get(index) == Some(&b'"') {
            index = csharp_string_end(text, index).unwrap_or(text.len());
            continue;
        }
        if text[index..].starts_with(needle) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn find_statement_end(text: &str, start: usize) -> Option<usize> {
    let mut index = start;
    let mut curly = 0isize;
    let mut paren = 0isize;
    let mut bracket = 0isize;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(text, index)?;
            continue;
        }
        match byte {
            b'{' => curly += 1,
            b'}' => curly -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b';' if curly == 0 && paren == 0 && bracket == 0 => return Some(index),
            _ => {}
        }
        index += 1;
    }
    None
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let masked = csharp_code_mask(program);
    let mut bodies = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = masked[offset..].find(variable) {
        let start = offset + relative;
        let end = start + variable.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) {
            continue;
        }
        if !masked[..start].trim_end().ends_with("var") {
            continue;
        }
        let mut cursor = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(cursor) != Some(&b'=') {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + 1);
        if !masked[cursor..].starts_with("new[]") {
            continue;
        }
        cursor = skip_ascii_whitespace(&masked, cursor + "new[]".len());
        if masked.as_bytes().get(cursor) != Some(&b'{') {
            continue;
        }
        if let Some(close) = matching_delimiter_index(program, cursor, b'{', b'}') {
            bodies.push(program[cursor + 1..close].to_string());
        }
    }
    if bodies.len() != 1 {
        errors.push(format!(
            "API {field} array must declare exactly one literal {variable} array"
        ));
        return None;
    }
    Some(csharp_string_literals(&bodies[0]))
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < text.len() {
        if text.as_bytes().get(index) == Some(&b'"') {
            if let Some(end) = csharp_string_end(text, index) {
                if let Some(value) = csharp_string_literal_value(&text[index..end]) {
                    values.push(value);
                }
                index = end;
                continue;
            }
        }
        index += 1;
    }
    values
}

fn exact_assignment(block: &str, field: &str, expected: &str) -> bool {
    let values = top_level_assignment_values(block)
        .into_iter()
        .filter_map(|(candidate, value)| (candidate == field).then_some(value))
        .collect::<Vec<_>>();
    values.len() == 1 && values[0] == expected
}

fn exact_string_assignment(block: &str, field: &str, expected: &str) -> bool {
    let quoted = format!("\"{expected}\"");
    exact_assignment(block, field, &quoted)
}

fn top_level_assignment_values(block: &str) -> Vec<(String, String)> {
    let masked = csharp_code_mask(block);
    let mut values = Vec::new();
    for line_start in line_start_indexes(&masked) {
        let line_end = masked[line_start..]
            .find('\n')
            .map(|relative| line_start + relative)
            .unwrap_or(masked.len());
        let line = &masked[line_start..line_end];
        let original = &block[line_start..line_end];
        let Some((field, equals)) = first_assignment_on_line(line) else {
            continue;
        };
        if brace_depth_at(&masked, line_start + equals) != 1 {
            continue;
        }
        let value = original[equals + 1..]
            .trim()
            .trim_end_matches(',')
            .trim()
            .to_string();
        values.push((field, value));
    }
    values
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    top_level_assignment_values(block)
        .into_iter()
        .map(|(field, _)| field)
        .collect()
}

fn first_assignment_on_line(line: &str) -> Option<(String, usize)> {
    let bytes = line.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            let field = line[start..index].to_string();
            let cursor = skip_ascii_whitespace(line, index);
            if bytes.get(cursor) == Some(&b'=') && bytes.get(cursor + 1) != Some(&b'=') {
                return Some((field, cursor));
            }
        } else {
            index += 1;
        }
    }
    None
}

fn assignment_fields(block: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let bytes = block.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            let cursor = skip_ascii_whitespace(block, index);
            if bytes.get(cursor) == Some(&b'=') && bytes.get(cursor + 1) != Some(&b'=') {
                fields.push(block[start..index].to_string());
            }
        } else {
            index += 1;
        }
    }
    fields
}

fn assignment_map(block: &str) -> BTreeMap<String, String> {
    assignment_fields(block)
        .into_iter()
        .filter_map(|field| {
            top_level_or_inline_assignment_value(block, &field).map(|value| (field, value))
        })
        .collect()
}

fn top_level_or_inline_assignment_value(block: &str, field: &str) -> Option<String> {
    let masked = csharp_code_mask(block);
    let mut offset = 0usize;
    while let Some(relative) = masked[offset..].find(field) {
        let start = offset + relative;
        let end = start + field.len();
        offset = end;
        if !identifier_boundary(&masked, start, end) {
            continue;
        }
        let equals = skip_ascii_whitespace(&masked, end);
        if masked.as_bytes().get(equals) != Some(&b'=') {
            continue;
        }
        let value_start = skip_ascii_whitespace(block, equals + 1);
        let value_end = assignment_value_end(&masked, value_start);
        return Some(block[value_start..value_end].trim().to_string());
    }
    None
}

fn assignment_value_end(masked: &str, start: usize) -> usize {
    let mut index = start;
    let mut curly = 0isize;
    let mut paren = 0isize;
    let mut bracket = 0isize;
    while index < masked.len() {
        match masked.as_bytes()[index] {
            b'{' => curly += 1,
            b'}' if curly == 0 => return index,
            b'}' => curly -= 1,
            b'(' => paren += 1,
            b')' if paren == 0 => return index,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' if bracket == 0 => return index,
            b']' => bracket -= 1,
            b',' if curly == 0 && paren == 0 && bracket == 0 => return index,
            b'\n' if curly == 0 && paren == 0 && bracket == 0 => return index,
            _ => {}
        }
        index += 1;
    }
    masked.len()
}

fn singleton_endpoint_fields() -> Vec<&'static str> {
    let mut fields = vec![
        "source",
        "modelMode",
        "identityProvider",
        "configuredForProduction",
        "localMockAuthAllowed",
        "rules",
    ];
    fields.extend(REQUIRED_DISABLED_FIELDS);
    fields.extend(ENDPOINT_ARRAY_BINDINGS.iter().map(|(field, _, _)| *field));
    fields
}

fn rule_values(value: Option<&Value>, label: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(items) = value.and_then(Value::as_array) else {
        errors.push(format!("{label} rules must be array"));
        return Vec::new();
    };
    let mut rules = Vec::new();
    for item in items {
        if !item.is_object() {
            errors.push(format!("{label} rules must be array of objects"));
            continue;
        }
        let Some(id) = string_value(item, "id") else {
            continue;
        };
        rules.push(Rule {
            id: id.to_string(),
            decision: string_value(item, "decision")
                .unwrap_or_default()
                .to_string(),
            requirement: string_value(item, "requirement")
                .unwrap_or_default()
                .to_string(),
            evidence: string_value(item, "evidence")
                .unwrap_or_default()
                .to_string(),
        });
    }
    rules
}

fn validate_object_keys(value: &Value, expected: &[&str], label: &str, errors: &mut Vec<String>) {
    let Some(map) = value.as_object() else {
        errors.push(format!("{label} must be object"));
        return;
    };
    let actual = map.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_set = expected.iter().copied().collect::<BTreeSet<_>>();
    let unexpected = actual
        .difference(&expected_set)
        .copied()
        .collect::<Vec<_>>();
    let missing = expected_set
        .difference(&actual)
        .copied()
        .collect::<Vec<_>>();
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

fn object_array<'a>(value: &'a Value, field: &str) -> Vec<&'a Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn object_field_strings(value: &Value, array_field: &str, item_field: &str) -> Vec<String> {
    object_array(value, array_field)
        .iter()
        .filter_map(|item| string_value(item, item_field))
        .map(str::to_string)
        .collect()
}

fn string_array(value: &Value, field: &str) -> Vec<String> {
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

fn placeholder_group_ref(value: Option<&str>) -> bool {
    value.is_some_and(|text| {
        text.strip_prefix("group-ref:ryuki-portal-")
            .is_some_and(|rest| {
                !rest.is_empty()
                    && rest.split('-').all(|part| {
                        !part.is_empty()
                            && part
                                .chars()
                                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
                    })
            })
    })
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

fn push_missing_unexpected(
    prefix: &str,
    field: &str,
    values: &[&str],
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let value_set = values.iter().copied().collect::<BTreeSet<_>>();
    let required_set = required.iter().copied().collect::<BTreeSet<_>>();
    let missing = required
        .iter()
        .copied()
        .filter(|item| !value_set.contains(item))
        .collect::<Vec<_>>();
    let unexpected = values
        .iter()
        .copied()
        .filter(|item| !required_set.contains(item))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        errors.push(format!(
            "{prefix} {field} missing values: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{prefix} {field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let end = csharp_string_end(text, index).unwrap_or(text.len());
            output.push_str(&text[index..end]);
            index = end;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push_str("  ");
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index + 1 < bytes.len() {
                output.push_str("  ");
                index += 2;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_code_mask(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push_str("  ");
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index + 1 < bytes.len() {
                output.push_str("  ");
                index += 2;
            }
        } else if bytes[index] == b'"' {
            let end = csharp_string_end(text, index).unwrap_or(text.len());
            while index < end {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn csharp_string_literal_value(expression: &str) -> Option<String> {
    let expression = expression.trim();
    let quote = expression.find('"')?;
    let prefix = &expression[..quote];
    if !prefix.chars().all(|ch| ch == '@' || ch == '$') {
        return None;
    }
    let end = csharp_string_end(expression, quote)?;
    if !expression[end..].trim().is_empty() {
        return None;
    }
    let body = if expression[quote..].starts_with("\"\"\"") {
        let delimiter_len = expression[quote..]
            .bytes()
            .take_while(|byte| *byte == b'"')
            .count();
        &expression[quote + delimiter_len..end - delimiter_len]
    } else {
        &expression[quote + 1..end - 1]
    };
    if prefix.contains('$') && body.contains(['{', '}']) {
        return None;
    }
    if prefix.contains('@') {
        return Some(body.replace("\"\"", "\""));
    }
    Some(csharp_unescape_string(body))
}

fn trim_csharp_string(value: &str) -> String {
    csharp_string_literal_value(value).unwrap_or_else(|| value.trim().trim_matches('"').to_string())
}

fn csharp_string_end(text: &str, start: usize) -> Option<usize> {
    if text.as_bytes().get(start) != Some(&b'"') {
        return None;
    }
    let quote_count = text[start..]
        .bytes()
        .take_while(|byte| *byte == b'"')
        .count();
    if quote_count >= 3 {
        let delimiter = "\"".repeat(quote_count);
        return text[start + quote_count..]
            .find(&delimiter)
            .map(|relative| start + quote_count + relative + quote_count)
            .or(Some(text.len()));
    }
    let verbatim = start > 0 && text.as_bytes().get(start - 1) == Some(&b'@');
    let mut index = start + 1;
    while index < text.len() {
        let byte = text.as_bytes()[index];
        let next = text.as_bytes().get(index + 1).copied();
        if verbatim && byte == b'"' && next == Some(b'"') {
            index += 2;
            continue;
        }
        if byte == b'"' {
            return Some(index + 1);
        }
        if !verbatim && byte == b'\\' && next.is_some() {
            index += 2;
        } else {
            index += 1;
        }
    }
    Some(text.len())
}

fn csharp_unescape_string(body: &str) -> String {
    let mut value = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            value.push(ch);
            continue;
        }
        match chars.next() {
            Some('"') => value.push('"'),
            Some('\\') => value.push('\\'),
            Some('/') => value.push('/'),
            Some('b') => value.push('\u{0008}'),
            Some('f') => value.push('\u{000c}'),
            Some('n') => value.push('\n'),
            Some('r') => value.push('\r'),
            Some('t') => value.push('\t'),
            Some(other) => value.push(other),
            None => value.push('\\'),
        }
    }
    value
}

fn matching_delimiter_index(source: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    let mut index = start;
    while index < source.len() {
        let byte = source.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(source, index).unwrap_or(source.len());
            continue;
        }
        if byte == open {
            depth += 1;
        } else if byte == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn brace_depth_at(source: &str, target_index: usize) -> usize {
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < target_index && index < source.len() {
        match source.as_bytes()[index] {
            b'"' => {
                index = csharp_string_end(source, index).unwrap_or(source.len());
                continue;
            }
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    depth
}

fn split_top_level(expression: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut curly = 0isize;
    let mut paren = 0isize;
    let mut bracket = 0isize;
    while index < expression.len() {
        let byte = expression.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(expression, index).unwrap_or(expression.len());
            continue;
        }
        match byte {
            b'{' => curly += 1,
            b'}' => curly -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b',' if curly == 0 && paren == 0 && bracket == 0 => {
                parts.push(expression[start..index].to_string());
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    parts.push(expression[start..].to_string());
    parts
}

fn split_top_level_plus(expression: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut curly = 0isize;
    let mut paren = 0isize;
    let mut bracket = 0isize;
    while index < expression.len() {
        let byte = expression.as_bytes()[index];
        if byte == b'"' {
            index = csharp_string_end(expression, index).unwrap_or(expression.len());
            continue;
        }
        match byte {
            b'{' => curly += 1,
            b'}' => curly -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'+' if curly == 0 && paren == 0 && bracket == 0 => {
                parts.push(expression[start..index].trim().to_string());
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    parts.push(expression[start..].trim().to_string());
    parts
}

fn strip_outer_parentheses(expression: &str) -> String {
    let mut current = expression.trim().to_string();
    loop {
        if !current.starts_with('(') {
            return current;
        }
        let Some(close) = matching_delimiter_index(&current, 0, b'(', b')') else {
            return current;
        };
        if close != current.len() - 1 {
            return current;
        }
        current = current[1..close].trim().to_string();
    }
}

fn source_identifiers(text: &str) -> Vec<String> {
    let masked = csharp_code_mask(text);
    let bytes = masked.as_bytes();
    let mut identifiers = BTreeSet::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            identifiers.insert(masked[start..index].to_string());
        } else {
            index += 1;
        }
    }
    identifiers.into_iter().collect()
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    let mut indexes = vec![0];
    for (index, byte) in text.as_bytes().iter().enumerate() {
        if *byte == b'\n' && index + 1 < text.len() {
            indexes.push(index + 1);
        }
    }
    indexes
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

fn identifier_boundary(source: &str, start: usize, end: usize) -> bool {
    let bytes = source.as_bytes();
    (start == 0 || !is_identifier_byte(bytes[start - 1]))
        && (end >= bytes.len() || !is_identifier_byte(bytes[end]))
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_plain_identifier(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| is_identifier_start(*byte))
        && value
            .as_bytes()
            .iter()
            .all(|byte| is_identifier_byte(*byte))
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn unsafe_true_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    [
        "provider",
        "live",
        "graph",
        "approval",
        "role",
        "policy",
        "workflow",
        "raw",
        "tenant",
        "app",
        "client",
        "object",
        "principal",
        "group",
        "credential",
        "token",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
