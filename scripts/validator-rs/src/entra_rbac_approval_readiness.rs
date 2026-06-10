use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/entra-rbac-approval-readiness-contract.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/entra-rbac-approval-readiness.md";
const ENDPOINT: &str = "/api/identity/entra-rbac-approval-readiness-contract";

const REQUIRED_SURFACES: &[&str] = &[
    "oidc-configuration-readiness",
    "protected-api-readiness",
    "app-role-readiness",
    "group-claim-readiness",
    "role-action-matrix-readiness",
    "approval-route-readiness",
    "local-mock-boundary-readiness",
    "audit-evidence-readiness",
    "break-glass-readiness",
];
const REQUIRED_INPUTS: &[&str] = &[
    "identityProviderDecision",
    "runtimeConfigurationSummary",
    "protectedApiProfile",
    "appRoleMappingSummary",
    "groupClaimMappingSummary",
    "roleActionMatrix",
    "approvalRouteSummary",
    "localMockBoundary",
    "breakGlassSummary",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "identity-provider-confirmed",
    "runtime-config-externalized",
    "protected-api-profile-reviewed",
    "app-role-mapping-reviewed",
    "group-claim-mapping-reviewed",
    "role-action-matrix-reviewed",
    "approval-routes-reviewed",
    "local-mock-boundary-enforced",
    "break-glass-reviewed",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "readinessSummary",
    "identityProviderBoundary",
    "runtimeConfiguration",
    "protectedApiReadiness",
    "roleMappingReview",
    "approvalRouteReview",
    "localMockBoundary",
    "breakGlassReview",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-authentication-disabled",
    "token-validation-disabled",
    "graph-calls-disabled",
    "entra-group-lookup-disabled",
    "app-registration-change-disabled",
    "role-assignment-change-disabled",
    "approval-execution-disabled",
    "servicenow-approval-change-disabled",
    "raw-user-data-disabled",
    "raw-claim-payloads-disabled",
    "raw-group-rows-disabled",
    "tenant-identifiers-disabled",
    "app-identifiers-disabled",
    "client-identifiers-disabled",
    "object-identifiers-disabled",
    "principal-identifiers-disabled",
    "group-identifiers-disabled",
    "credential-values-disabled",
    "raw-provider-payloads-disabled",
    "runtime-config-missing",
    "protected-api-profile-missing",
    "role-mapping-missing",
    "approval-route-missing",
    "local-mock-boundary-missing",
    "break-glass-review-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Identity readiness summary",
    "Runtime configuration review",
    "Protected API readiness",
    "Role mapping review",
    "Approval route review",
    "Local mock boundary",
    "Break-glass review",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "liveAuthenticationEnabled",
    "tokenValidationEnabled",
    "graphCallsAllowed",
    "entraGroupLookupAllowed",
    "appRegistrationChangesAllowed",
    "roleAssignmentChangesAllowed",
    "approvalExecutionAllowed",
    "serviceNowApprovalChangesAllowed",
    "rawUserDataAllowed",
    "rawClaimPayloadsAllowed",
    "rawGroupRowsAllowed",
    "tenantIdentifiersAllowed",
    "appIdentifiersAllowed",
    "clientIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "credentialValuesAllowed",
    "rawProviderPayloadsAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "readinessMode",
    "identityProvider",
    "configuredForProduction",
    "localMockAuthAllowed",
    "readinessSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "providerCallsEnabled",
    "liveAuthenticationEnabled",
    "tokenValidationEnabled",
    "graphCallsAllowed",
    "entraGroupLookupAllowed",
    "appRegistrationChangesAllowed",
    "roleAssignmentChangesAllowed",
    "approvalExecutionAllowed",
    "serviceNowApprovalChangesAllowed",
    "rawUserDataAllowed",
    "rawClaimPayloadsAllowed",
    "rawGroupRowsAllowed",
    "tenantIdentifiersAllowed",
    "appIdentifiersAllowed",
    "clientIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "credentialValuesAllowed",
    "rawProviderPayloadsAllowed",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "readinessSurfaces",
        "entraRbacApprovalReadinessSurfaces",
        REQUIRED_SURFACES,
    ),
    (
        "requiredGuards",
        "entraRbacApprovalReadinessRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "entraRbacApprovalReadinessPlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "entraRbacApprovalReadinessBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const SAFE_TRUE_FIELDS: &[&str] = &["localMockAuthAllowed"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "readinessMode",
    "identityProvider",
    "configuredForProduction",
    "localMockAuthAllowed",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "providerCallsEnabled",
    "liveAuthenticationEnabled",
    "tokenValidationEnabled",
    "graphCallsAllowed",
    "entraGroupLookupAllowed",
    "appRegistrationChangesAllowed",
    "roleAssignmentChangesAllowed",
    "approvalExecutionAllowed",
    "serviceNowApprovalChangesAllowed",
    "rawUserDataAllowed",
    "rawClaimPayloadsAllowed",
    "rawGroupRowsAllowed",
    "tenantIdentifiersAllowed",
    "appIdentifiersAllowed",
    "clientIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "groupIdentifiersAllowed",
    "credentialValuesAllowed",
    "rawProviderPayloadsAllowed",
    "readinessSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
];
const REQUIRED_RULE_DETAILS: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-auth-provider-execution",
        "block",
        "Entra RBAC approval readiness reports static readiness only and never validates live sign-ins, calls Microsoft Graph, looks up groups, changes app registrations, assigns roles, executes approvals, changes ServiceNow approvals, or mutates provider state.",
        "Identity readiness summary",
    ),
    (
        "runtime-config-externalized",
        "block",
        "Runtime identity configuration, protected API settings, app role mapping, and group claim mapping must remain deployment configuration outside committed files.",
        "Runtime configuration review",
    ),
    (
        "role-and-approval-readiness-required",
        "block",
        "Role action matrix, approval routes, break-glass handling, and local mock boundary must be reviewed before production authentication can be accepted.",
        "Approval route review",
    ),
    (
        "raw-entra-readiness-data-not-exposed",
        "block",
        "Readiness evidence must use safe summaries only and must not expose user records, claim payloads, group rows, tenant IDs, app IDs, client IDs, object IDs, principal IDs, group IDs, credentials, tokens, Microsoft Graph payloads, ServiceNow payloads, or provider payloads.",
        "Evidence references",
    ),
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Entra RBAC approval readiness seed data only. Do not add credentials, tokens, tenant IDs, app IDs, client IDs, object IDs, principal IDs, group IDs, user records, claim payloads, group rows, app-registration payloads, Microsoft Graph payloads, ServiceNow payloads, or provider payloads.",
    "- No live authentication or token validation.",
    "- No user records, claim payloads, group rows, tenant IDs, app IDs, client IDs, object IDs, principal IDs, group IDs, credential values, tokens, Microsoft Graph payloads, ServiceNow payloads, or provider payloads.",
    "requirement: Readiness evidence must use safe summaries only and must not expose user records, claim payloads, group rows, tenant IDs, app IDs, client IDs, object IDs, principal IDs, group IDs, credentials, tokens, Microsoft Graph payloads, ServiceNow payloads, or provider payloads.",
];

#[derive(Deserialize)]
struct ValidationContext {
    catalog: Value,
    catalog_text: String,
    program: String,
    #[serde(alias = "readme")]
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
    #[serde(alias = "readme")]
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
struct EndpointBlock {
    start: usize,
    text: String,
}

struct ArrayDeclaration {
    end: usize,
    values: Vec<String>,
}

#[derive(Clone)]
struct Assignment {
    field: String,
    value: String,
    start: usize,
}

#[derive(Clone)]
struct ApiRule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let input = fs::read_to_string(path)
        .map_err(|error| format!("failed to read context JSON {}: {error}", path.display()))?;
    let context: ValidationContext = serde_json::from_str(&input)
        .map_err(|error| format!("invalid Entra RBAC approval readiness context JSON: {error}"))?;

    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_no_prohibited_values(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    validate_program_value(&context.program, &context.catalog, &mut errors);
    validate_docs_values(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    let docs = serde_json::json!({
        API_README_PATH: context.api_readme,
        CATALOG_README_PATH: context.catalog_readme,
        DOC_README_PATH: context.doc_readme,
        DOC_PATH: context.doc,
    });
    validate_no_prohibited_values(&docs, "entra-rbac-approval-readiness", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid Entra RBAC approval readiness catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid Entra RBAC approval readiness program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_value(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid Entra RBAC approval readiness docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_values(
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
        .map_err(|error| format!("invalid Entra RBAC approval readiness scan JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("Entra RBAC approval readiness catalog must be an object".to_string());
        return;
    };

    let keys: Vec<String> = object.keys().cloned().collect();
    let unexpected: Vec<&str> = keys
        .iter()
        .map(String::as_str)
        .filter(|key| !REQUIRED_CATALOG_KEYS.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "Entra RBAC approval readiness unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }

    expect(
        integer_field(catalog, "version") == Some(1),
        errors,
        "Entra RBAC approval readiness version must be 1",
    );
    expect(
        string_field(catalog, "status") == Some("draft"),
        errors,
        "Entra RBAC approval readiness status must be draft",
    );
    expect(
        string_field(catalog, "source") == Some("static-seed"),
        errors,
        "Entra RBAC approval readiness source must be static-seed",
    );
    expect(
        string_field(catalog, "readinessMode") == Some("static-readiness"),
        errors,
        "Entra RBAC approval readiness mode must be static-readiness",
    );
    expect(
        string_field(catalog, "identityProvider") == Some("Microsoft Entra ID"),
        errors,
        "Entra RBAC approval readiness provider must be Microsoft Entra ID",
    );
    expect(
        bool_field(catalog, "configuredForProduction") == Some(false),
        errors,
        "Entra RBAC approval readiness configuredForProduction must be false",
    );
    expect(
        bool_field(catalog, "localMockAuthAllowed") == Some(true),
        errors,
        "Entra RBAC approval readiness must keep local mock auth allowed for non-prod",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_field(catalog, field) == Some(false),
            errors,
            &format!("Entra RBAC approval readiness {field} must be disabled"),
        );
    }

    validate_required_array(catalog, "readinessSurfaces", REQUIRED_SURFACES, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    validate_no_prohibited_values(catalog, CATALOG_PATH, errors);
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
    let actual: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let required: BTreeSet<&str> = required_values.iter().copied().collect();
    let missing: Vec<&str> = required.difference(&actual).copied().collect();
    let unexpected: Vec<&str> = actual.difference(&required).copied().collect();
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
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited identity value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "{field} contains prohibited identity phrase {phrase}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog.get("rules").and_then(Value::as_array);
    let Some(rules) = rules else {
        errors.push("Entra RBAC approval readiness missing rules".to_string());
        return;
    };
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let actual: BTreeSet<&str> = rule_ids.iter().map(String::as_str).collect();
    let required: BTreeSet<&str> = REQUIRED_RULE_DETAILS.iter().map(|rule| rule.0).collect();
    let missing: Vec<&str> = required.difference(&actual).copied().collect();
    let unexpected: Vec<&str> = actual.difference(&required).copied().collect();
    if !missing.is_empty() {
        errors.push(format!(
            "Entra RBAC approval readiness missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "Entra RBAC approval readiness unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.len() == actual.len(),
        errors,
        "Entra RBAC approval readiness rule IDs must be unique",
    );
    for (id, decision, requirement, evidence) in REQUIRED_RULE_DETAILS {
        let Some(rule) = rules
            .iter()
            .find(|candidate| string_field(candidate, "id") == Some(*id))
        else {
            continue;
        };
        expect(
            string_field(rule, "decision") == Some(*decision),
            errors,
            &format!("Entra RBAC approval readiness rule {id} decision must match"),
        );
        expect(
            string_field(rule, "requirement") == Some(*requirement),
            errors,
            &format!("Entra RBAC approval readiness rule {id} requirement must match"),
        );
        expect(
            string_field(rule, "evidence") == Some(*evidence),
            errors,
            &format!("Entra RBAC approval readiness rule {id} evidence must match"),
        );
    }
}

fn validate_program_value(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let blocks = extract_endpoint_blocks(program);
    if blocks.is_empty() {
        errors.push("API missing Entra RBAC approval readiness endpoint".to_string());
        return;
    }
    if blocks.len() != 1 {
        errors.push(format!("API must expose exactly one {ENDPOINT} endpoint"));
    }
    let block = &blocks[0];
    let top_level_assignments = assignments_at_brace_depth(&block.text, 1);

    expect(
        exact_string_assignment(&top_level_assignments, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&top_level_assignments, "readinessMode", "static-readiness"),
        errors,
        "API must keep static-readiness mode",
    );
    expect(
        exact_string_assignment(
            &top_level_assignments,
            "identityProvider",
            "Microsoft Entra ID",
        ),
        errors,
        "API must keep Microsoft Entra ID provider",
    );
    expect(
        exact_assignment(&top_level_assignments, "configuredForProduction", "false"),
        errors,
        "API must keep configuredForProduction disabled",
    );
    expect(
        exact_assignment(&top_level_assignments, "localMockAuthAllowed", "true"),
        errors,
        "API must keep localMockAuthAllowed true",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exact_assignment(&top_level_assignments, field, "false"),
            errors,
            &format!("API must keep {field} disabled"),
        );
    }

    for (field, variable, _) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_assignment(&top_level_assignments, field, variable),
            errors,
            &format!("API must bind {field} to {variable}"),
        );
        let values = validate_endpoint_array_binding_unchanged(
            program,
            block.start,
            variable,
            field,
            errors,
        );
        validate_api_array(field, values, &catalog_string_array(catalog, field), errors);
    }
    for (field, _) in ENDPOINT_INLINE_ARRAYS {
        let values = values_for_field(&top_level_assignments, field);
        if values.len() != 1 {
            errors.push(format!("API must define exactly one {field} inline array"));
        }
        let inline_values = values
            .first()
            .and_then(|value| inline_array_values_from_assignment(value));
        validate_api_array(
            field,
            inline_values,
            &catalog_string_array(catalog, field),
            errors,
        );
    }

    validate_api_rules(&block.text, catalog, errors);
    validate_endpoint_field_names(&block.text, errors);
    validate_no_unsafe_true_flags(&top_level_assignments, errors);
}

fn validate_api_array(
    field: &str,
    values: Option<Vec<String>>,
    catalog_values: &[String],
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let actual: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let catalog: BTreeSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = catalog.difference(&actual).copied().collect();
    let unexpected: Vec<&str> = actual.difference(&catalog).copied().collect();
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
        &format!("API {field} values must be unique"),
    );
    for value in values {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited identity value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited identity phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = api_rules(block);
    let catalog_rules = catalog_rules(catalog);
    let api_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let catalog_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_set: BTreeSet<&str> = api_ids.iter().map(String::as_str).collect();
    let catalog_set: BTreeSet<&str> = catalog_ids.iter().map(String::as_str).collect();
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

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in assignment_fields(block) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected Entra RBAC approval readiness field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited identity field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(assignments: &[Assignment], errors: &mut Vec<String>) {
    for assignment in assignments {
        if assignment.value != "true" || SAFE_TRUE_FIELDS.contains(&assignment.field.as_str()) {
            continue;
        }
        let name = assignment.field.to_ascii_lowercase();
        if [
            "live",
            "provider",
            "auth",
            "token",
            "graph",
            "group",
            "app",
            "role",
            "approval",
            "servicenow",
            "raw",
            "identifier",
            "principal",
            "tenant",
            "object",
            "credential",
        ]
        .iter()
        .any(|needle| name.contains(needle))
        {
            errors.push(format!(
                "API endpoint has unsafe true flag {}",
                assignment.field
            ));
        }
    }
}

fn validate_docs_values(
    api_readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    errors: &mut Vec<String>,
) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing Entra RBAC approval readiness endpoint",
    );
    expect(
        catalog_readme.contains("entra-rbac-approval-readiness-contract.yaml"),
        errors,
        "catalog README missing Entra RBAC approval readiness catalog",
    );
    expect(
        doc_readme.contains("entra-rbac-approval-readiness.md"),
        errors,
        "workflow README missing Entra RBAC approval readiness doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "Entra RBAC approval readiness doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "Entra RBAC approval readiness doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live authentication or token validation."),
        errors,
        "Entra RBAC approval readiness doc must prohibit live auth",
    );
    expect(
        doc.contains("No Microsoft Graph calls or Entra group lookup."),
        errors,
        "Entra RBAC approval readiness doc must prohibit Graph and group lookup",
    );
    expect(
        doc.contains("Use static readiness summaries only."),
        errors,
        "Entra RBAC approval readiness doc must require static summaries",
    );
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if prohibited_field(key) {
                    errors.push(format!("{path}.{key} contains prohibited identity field"));
                }
                validate_no_prohibited_values(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_prohibited_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if contains_prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if entra_readiness_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if contains_prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if let Some(phrase) = prohibited_phrase(text) {
                errors.push(format!(
                    "{path} contains prohibited identity phrase {phrase}"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!("{path} contains prohibited identity value {text}"));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !entra_readiness_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{path}:{} contains prohibited identity phrase {phrase}",
                index + 1
            ));
        }
        for term in text_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited identity field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn extract_endpoint_blocks(program: &str) -> Vec<EndpointBlock> {
    let masked = csharp_code_mask(program);
    let mut blocks = Vec::new();
    let mut index = 0;
    while let Some(start) = next_code_match(&masked, "app.MapGet(", index) {
        let paren = start + "app.MapGet".len();
        let route_start = skip_ascii_whitespace(program, paren + 1);
        let route = route_argument_value(program, route_start, start);
        if route.as_deref() == Some(ENDPOINT) {
            let close = matching_delimiter_index(&masked, paren, b'(', b')')
                .unwrap_or(masked.len().saturating_sub(1));
            let mut end = close + 1;
            while end < masked.len() && masked.as_bytes()[end].is_ascii_whitespace() {
                end += 1;
            }
            if end < masked.len() && masked.as_bytes()[end] == b';' {
                end += 1;
            }
            blocks.push(EndpointBlock {
                start,
                text: program[start..end].to_string(),
            });
        }
        index = start + "app.MapGet(".len();
    }
    blocks
}

fn route_argument_value(program: &str, route_start: usize, before: usize) -> Option<String> {
    let bytes = program.as_bytes();
    if route_start >= bytes.len() {
        return None;
    }
    if bytes[route_start] == b'"' {
        return csharp_string_literal_value(program, route_start).map(|(value, _)| value);
    }
    if !is_identifier_start(bytes[route_start]) {
        return None;
    }
    let mut end = route_start + 1;
    while end < bytes.len() && is_identifier_continue(bytes[end]) {
        end += 1;
    }
    static_route_value(program, &program[route_start..end], before)
}

fn static_route_value(program: &str, variable: &str, before: usize) -> Option<String> {
    let prefix = &program[..before];
    let masked = csharp_code_mask(prefix);
    let mut index = 0;
    while let Some(start) = identifier_match(&masked, variable, index) {
        if declaration_prefix_ok(&masked, start) {
            let after_variable = skip_ascii_whitespace(prefix, start + variable.len());
            if after_variable < prefix.len() && prefix.as_bytes()[after_variable] == b'=' {
                let value_start = skip_ascii_whitespace(prefix, after_variable + 1);
                if let Some((value, _)) = csharp_string_literal_value(prefix, value_start) {
                    return Some(value);
                }
            }
        }
        index = start + variable.len();
    }
    None
}

fn validate_endpoint_array_binding_unchanged(
    program: &str,
    endpoint_start: usize,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let prefix = &program[..endpoint_start];
    let declarations = endpoint_array_binding_declarations(prefix, variable);
    if declarations.len() != 1 {
        errors.push(format!(
            "API {field} array binding {variable} must have exactly one declaration before endpoint"
        ));
    }
    let Some(declaration) = declarations.first() else {
        errors.push(format!(
            "API missing {field} array binding declaration {variable}"
        ));
        return None;
    };
    let after_declaration = &prefix[declaration.end..];
    let masked_after = csharp_code_mask(after_declaration);
    if identifier_match(&masked_after, variable, 0).is_some() {
        errors.push(format!(
            "API {field} array binding {variable} must not be referenced before endpoint use"
        ));
    }
    Some(declaration.values.clone())
}

fn endpoint_array_binding_declarations(prefix: &str, variable: &str) -> Vec<ArrayDeclaration> {
    let masked = csharp_code_mask(prefix);
    let mut declarations = Vec::new();
    let mut index = 0;
    while let Some(start) = identifier_match(&masked, variable, index) {
        if declaration_prefix_ok(&masked, start) {
            let after_variable = skip_ascii_whitespace(&masked, start + variable.len());
            if after_variable < masked.len() && masked.as_bytes()[after_variable] == b'=' {
                let after_equals = skip_ascii_whitespace(&masked, after_variable + 1);
                if starts_with_new_array(&masked, after_equals) {
                    let Some(open_offset) = masked[after_equals..].find('{') else {
                        index = start + variable.len();
                        continue;
                    };
                    let open = after_equals + open_offset;
                    if let Some(close) = matching_delimiter_index(&masked, open, b'{', b'}') {
                        let mut end = close + 1;
                        while end < masked.len() && masked.as_bytes()[end].is_ascii_whitespace() {
                            end += 1;
                        }
                        if end < masked.len() && masked.as_bytes()[end] == b';' {
                            end += 1;
                        }
                        declarations.push(ArrayDeclaration {
                            end,
                            values: csharp_string_literals(&prefix[(open + 1)..close]),
                        });
                    }
                }
            }
        }
        index = start + variable.len();
    }
    declarations
}

fn declaration_prefix_ok(masked: &str, variable_start: usize) -> bool {
    let tail_start = variable_start.saturating_sub(64);
    let tail = &masked[tail_start..variable_start];
    let compact: String = tail
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    compact.ends_with("var") || compact.ends_with("conststring") || compact.ends_with("string[]")
}

fn starts_with_new_array(masked: &str, start: usize) -> bool {
    masked
        .as_bytes()
        .get(start..)
        .is_some_and(|slice| slice.starts_with(b"new[]"))
}

fn exact_assignment(assignments: &[Assignment], field: &str, expected: &str) -> bool {
    let values = values_for_field(assignments, field);
    values.len() == 1 && values[0] == expected
}

fn exact_string_assignment(assignments: &[Assignment], field: &str, expected: &str) -> bool {
    exact_assignment(assignments, field, &format!("\"{expected}\""))
}

fn values_for_field(assignments: &[Assignment], field: &str) -> Vec<String> {
    assignments
        .iter()
        .filter(|assignment| assignment.field == field)
        .map(|assignment| assignment.value.clone())
        .collect()
}

fn assignments_at_brace_depth(block: &str, required_depth: usize) -> Vec<Assignment> {
    let masked = csharp_code_mask(block);
    assignments(block)
        .into_iter()
        .filter(|assignment| brace_depth_before(&masked, assignment.start) == required_depth)
        .collect()
}

fn assignments(block: &str) -> Vec<Assignment> {
    let masked = csharp_code_mask(block);
    let bytes = masked.as_bytes();
    let mut values = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !is_identifier_start(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_identifier_continue(bytes[index]) {
            index += 1;
        }
        let field = &masked[start..index];
        let equals = skip_ascii_whitespace(&masked, index);
        if equals >= bytes.len()
            || bytes[equals] != b'='
            || bytes.get(equals + 1) == Some(&b'=')
            || equals > 0 && matches!(bytes[equals - 1], b'!' | b'<' | b'>')
        {
            continue;
        }
        let value_start = skip_ascii_whitespace(block, equals + 1);
        let value_end = assignment_value_end(&masked, value_start);
        let value = block[value_start..value_end]
            .trim()
            .trim_end_matches(',')
            .trim()
            .to_string();
        values.push(Assignment {
            field: field.to_string(),
            value,
            start,
        });
        index = value_end.saturating_add(1);
    }
    values
}

fn assignment_fields(block: &str) -> Vec<String> {
    let masked = csharp_code_mask(block);
    let bytes = masked.as_bytes();
    let mut fields = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !is_identifier_start(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_identifier_continue(bytes[index]) {
            index += 1;
        }
        let equals = skip_ascii_whitespace(&masked, index);
        if equals < bytes.len()
            && bytes[equals] == b'='
            && bytes.get(equals + 1) != Some(&b'=')
            && !(equals > 0 && matches!(bytes[equals - 1], b'!' | b'<' | b'>'))
        {
            fields.push(masked[start..index].to_string());
        }
    }
    fields
}

fn assignment_value_end(masked: &str, start: usize) -> usize {
    let bytes = masked.as_bytes();
    let mut index = start;
    let mut paren_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => {
                if brace_depth == 0 {
                    break;
                }
                brace_depth -= 1;
            }
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b',' if paren_depth == 0 && brace_depth == 0 && bracket_depth == 0 => break,
            b'\n' if paren_depth == 0 && brace_depth == 0 && bracket_depth == 0 => break,
            _ => {}
        }
        index += 1;
    }
    index
}

fn brace_depth_before(masked: &str, end: usize) -> usize {
    let mut depth = 0usize;
    for byte in masked.as_bytes().iter().take(end) {
        match *byte {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

fn inline_array_values_from_assignment(value: &str) -> Option<Vec<String>> {
    let masked = csharp_code_mask(value);
    let open = masked.find('{')?;
    let close = matching_delimiter_index(&masked, open, b'{', b'}')?;
    Some(csharp_string_literals(&value[(open + 1)..close]))
}

fn api_rules(block: &str) -> Vec<ApiRule> {
    let masked = csharp_code_mask(block);
    let mut rules = Vec::new();
    let mut index = 0;
    while let Some(new_index) = next_code_match(&masked, "new", index) {
        let open = skip_ascii_whitespace(&masked, new_index + 3);
        if open >= masked.len() || masked.as_bytes()[open] != b'{' {
            index = new_index + 3;
            continue;
        }
        let Some(close) = matching_delimiter_index(&masked, open, b'{', b'}') else {
            index = new_index + 3;
            continue;
        };
        let object_text = &block[open..=close];
        let assignments = assignments_at_brace_depth(object_text, 1);
        let id = string_assignment_value(&assignments, "id");
        let decision = string_assignment_value(&assignments, "decision");
        let requirement = string_assignment_value(&assignments, "requirement");
        let evidence = string_assignment_value(&assignments, "evidence");
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) =
            (id, decision, requirement, evidence)
        {
            rules.push(ApiRule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        index = new_index + 3;
    }
    rules
}

fn string_assignment_value(assignments: &[Assignment], field: &str) -> Option<String> {
    values_for_field(assignments, field)
        .first()
        .and_then(|value| {
            if value.starts_with('"') {
                csharp_string_literal_value(value, 0).map(|(parsed, _)| parsed)
            } else {
                None
            }
        })
}

fn catalog_rules(catalog: &Value) -> Vec<ApiRule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            Some(ApiRule {
                id: string_field(rule, "id")?.to_string(),
                decision: string_field(rule, "decision")?.to_string(),
                requirement: string_field(rule, "requirement")?.to_string(),
                evidence: string_field(rule, "evidence")?.to_string(),
            })
        })
        .collect()
}

fn csharp_code_mask(text: &str) -> String {
    let mut output = text.as_bytes().to_vec();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let start = index;
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            mask_range(&mut output, start, index);
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let start = index;
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            mask_range(&mut output, start, index);
            continue;
        }
        if bytes[index] == b'@' && bytes.get(index + 1) == Some(&b'"') {
            let start = index;
            index += 2;
            while index < bytes.len() {
                if bytes[index] == b'"' {
                    if bytes.get(index + 1) == Some(&b'"') {
                        index += 2;
                    } else {
                        index += 1;
                        break;
                    }
                } else {
                    index += 1;
                }
            }
            mask_range(&mut output, start, index);
            continue;
        }
        if bytes[index] == b'$' && bytes.get(index + 1) == Some(&b'"') {
            let start = index;
            index = csharp_string_end(text, index + 1).unwrap_or(bytes.len());
            mask_range(&mut output, start, index);
            continue;
        }
        if bytes[index] == b'"' {
            let start = index;
            index = csharp_string_end(text, index).unwrap_or(bytes.len());
            mask_range(&mut output, start, index);
            continue;
        }
        if bytes[index] == b'\'' {
            let start = index;
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index += 2;
                } else if bytes[index] == b'\'' {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
            mask_range(&mut output, start, index);
            continue;
        }
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn mask_range(output: &mut [u8], start: usize, end: usize) {
    let capped_end = end.min(output.len());
    for byte in &mut output[start..capped_end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn csharp_string_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
        } else if bytes[index] == b'"' {
            return Some(index + 1);
        } else {
            index += 1;
        }
    }
    None
}

fn csharp_string_literal_value(text: &str, start: usize) -> Option<(String, usize)> {
    let end = csharp_string_end(text, start)?;
    Some((text[(start + 1)..(end - 1)].to_string(), end))
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < text.len() {
        let Some(offset) = text[index..].find('"') else {
            break;
        };
        let start = index + offset;
        if let Some((value, end)) = csharp_string_literal_value(text, start) {
            values.push(value);
            index = end;
        } else {
            break;
        }
    }
    values
}

fn matching_delimiter_index(source: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(start) != Some(&open) {
        return None;
    }
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(start) {
        if *byte == open {
            depth += 1;
        } else if *byte == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn next_code_match(text: &str, needle: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let needle = needle.as_bytes();
    if needle.is_empty() || start >= bytes.len() {
        return None;
    }
    let mut index = start;
    while index + needle.len() <= bytes.len() {
        if &bytes[index..index + needle.len()] == needle {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn identifier_match(text: &str, identifier: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let identifier_bytes = identifier.as_bytes();
    let mut index = start;
    while let Some(candidate) = next_code_match(text, identifier, index) {
        let before = candidate == 0 || !is_identifier_continue(bytes[candidate - 1]);
        let after_index = candidate + identifier_bytes.len();
        let after = after_index >= bytes.len() || !is_identifier_continue(bytes[after_index]);
        if before && after {
            return Some(candidate);
        }
        index = candidate + 1;
    }
    None
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    let bytes = text.as_bytes();
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn is_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn integer_field(value: &Value, field: &str) -> Option<i64> {
    value.get(field).and_then(Value::as_i64)
}

fn bool_field(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
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

fn catalog_string_array(catalog: &Value, field: &str) -> Vec<String> {
    string_array(catalog.get(field))
}

fn safe_text_value(value: &str) -> bool {
    value == "draft"
        || value == "static-seed"
        || value == "static-readiness"
        || value == "Microsoft Entra ID"
        || REQUIRED_SURFACES.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || REQUIRED_CATALOG_KEYS.contains(&value)
        || SAFE_TRUE_FIELDS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable, _)| *variable == value)
        || REQUIRED_RULE_DETAILS
            .iter()
            .any(|(id, decision, requirement, evidence)| {
                value == *id || value == *decision || value == *requirement || value == *evidence
            })
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet = stripped.strip_prefix("- ").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped) || safe_text_value(bullet)
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    if normalized.is_empty() || safe_normalized_value(&normalized) {
        return false;
    }
    [
        "userid",
        "useridentifier",
        "userprincipalname",
        "upn",
        "mailaddress",
        "emailaddress",
        "accountid",
        "tenantid",
        "appid",
        "clientid",
        "objectid",
        "principalid",
        "groupid",
        "rawclaim",
        "claimpayload",
        "rawgroup",
        "grouprow",
        "appregistrationpayload",
        "graphpayload",
        "servicenowpayload",
        "providerpayload",
        "credential",
        "secret",
        "token",
        "password",
        "bearer",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn safe_normalized_value(normalized: &str) -> bool {
    [
        "draft",
        "static-seed",
        "static-readiness",
        "Microsoft Entra ID",
    ]
    .iter()
    .any(|safe| normalize_identifier(safe) == normalized)
        || REQUIRED_SURFACES
            .iter()
            .chain(REQUIRED_INPUTS)
            .chain(REQUIRED_GUARDS)
            .chain(REQUIRED_PLAN_SECTIONS)
            .chain(REQUIRED_BLOCKED_REASONS)
            .chain(REQUIRED_EVIDENCE)
            .chain(REQUIRED_DISABLED_FIELDS)
            .chain(REQUIRED_CATALOG_KEYS)
            .chain(SAFE_TRUE_FIELDS)
            .any(|safe| normalize_identifier(safe) == normalized)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable, _)| normalize_identifier(variable) == normalized)
        || REQUIRED_RULE_DETAILS
            .iter()
            .flat_map(|(id, decision, requirement, evidence)| [id, decision, requirement, evidence])
            .any(|safe| normalize_identifier(safe) == normalized)
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let tokens = word_tokens(value);
    if has_adjacent(&tokens, "user", &["record", "records"]) {
        return Some("user record");
    }
    if has_adjacent(&tokens, "claim", &["payload", "payloads"]) {
        return Some("claim payload");
    }
    if has_adjacent(&tokens, "group", &["row", "rows"]) {
        return Some("group rows");
    }
    if has_adjacent(&tokens, "tenant", &["id", "ids"]) {
        return Some("tenant ID");
    }
    if has_adjacent(&tokens, "app", &["id", "ids"]) {
        return Some("app ID");
    }
    if has_adjacent(&tokens, "client", &["id", "ids"]) {
        return Some("client ID");
    }
    if has_adjacent(&tokens, "object", &["id", "ids"]) {
        return Some("object ID");
    }
    if has_adjacent(&tokens, "principal", &["id", "ids"]) {
        return Some("principal ID");
    }
    if has_adjacent(&tokens, "group", &["id", "ids"]) {
        return Some("group ID");
    }
    if has_triplet(&tokens, "microsoft", "graph", &["payload", "payloads"]) {
        return Some("Microsoft Graph payload");
    }
    if has_adjacent(&tokens, "servicenow", &["payload", "payloads"]) {
        return Some("ServiceNow payload");
    }
    if has_adjacent(&tokens, "provider", &["payload", "payloads"]) {
        return Some("provider payload");
    }
    if tokens
        .iter()
        .any(|token| token == "token" || token == "tokens")
    {
        return Some("tokens");
    }
    if tokens
        .iter()
        .any(|token| token == "credential" || token == "credentials")
    {
        return Some("credentials");
    }
    None
}

fn word_tokens(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn text_terms(value: &str) -> Vec<String> {
    value
        .split(|character: char| {
            !character.is_ascii_alphanumeric() && character != '_' && character != '-'
        })
        .filter(|token| {
            token
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
        })
        .map(str::to_string)
        .collect()
}

fn has_adjacent(tokens: &[String], first: &str, seconds: &[&str]) -> bool {
    tokens
        .windows(2)
        .any(|window| window[0] == first && seconds.contains(&window[1].as_str()))
}

fn has_triplet(tokens: &[String], first: &str, second: &str, thirds: &[&str]) -> bool {
    tokens.windows(3).any(|window| {
        window[0] == first && window[1] == second && thirds.contains(&window[2].as_str())
    })
}

fn contains_prohibited_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    contains_aws_access_key(value)
        || lower.contains("-----begin ") && lower.contains("private key-----")
        || contains_url_scheme(value)
        || contains_private_ip(value)
        || contains_uuid(value)
        || contains_email(value)
        || contains_assignment_secret(&lower)
}

fn contains_aws_access_key(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut index = 0;
    while index + 20 <= bytes.len() {
        if bytes[index..].starts_with(b"AKIA")
            && bytes[index + 4..index + 20]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return true;
        }
        index += 1;
    }
    false
}

fn contains_url_scheme(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if bytes[index].is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || matches!(bytes[index], b'+' | b'.' | b'-'))
            {
                index += 1;
            }
            if index > start && bytes.get(index..index + 3) == Some(b"://") {
                return true;
            }
        }
        index += 1;
    }
    false
}

fn contains_private_ip(value: &str) -> bool {
    for token in value.split(|character: char| !character.is_ascii_digit() && character != '.') {
        let parts: Vec<u16> = token
            .split('.')
            .filter_map(|part| part.parse::<u16>().ok())
            .collect();
        if parts.len() != 4 || parts.iter().any(|part| *part > 255) {
            continue;
        }
        if parts[0] == 10
            || parts[0] == 192 && parts[1] == 168
            || parts[0] == 172 && (16..=31).contains(&parts[1])
        {
            return true;
        }
    }
    false
}

fn contains_uuid(value: &str) -> bool {
    for token in value.split(|character: char| !character.is_ascii_hexdigit() && character != '-') {
        let bytes = token.as_bytes();
        if bytes.len() == 36
            && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
            && bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
        {
            return true;
        }
    }
    false
}

fn contains_email(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        token.contains('@')
            && token
                .rsplit('@')
                .next()
                .is_some_and(|tail| tail.contains('.'))
    })
}

fn contains_assignment_secret(lower: &str) -> bool {
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
                .chars()
                .skip_while(|character| character.is_ascii_whitespace())
                .next()
                .is_some_and(|character| character == ':' || character == '=')
        })
    })
}

fn entra_readiness_text_path(path: &str) -> bool {
    [
        CATALOG_PATH,
        DOC_PATH,
        API_README_PATH,
        CATALOG_README_PATH,
        DOC_README_PATH,
    ]
    .iter()
    .any(|text_path| path.ends_with(text_path))
}

fn entra_readiness_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(CATALOG_PATH) || path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("entra-rbac")
        || lower.contains("approval-readiness")
        || lower.contains(&ENDPOINT.to_ascii_lowercase())
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|extension| path.ends_with(extension))
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}
