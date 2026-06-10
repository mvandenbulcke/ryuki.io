use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/local-privilege-access-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/local-privilege-access.md";
const ENDPOINT: &str = "/api/identity/local-privilege-access-contract";

const REQUIRED_ACTIONS: &[&str] = &[
    "local-admin-grant-review",
    "local-admin-remove-review",
    "sudo-grant-review",
    "sudo-remove-review",
    "expiry-review",
    "break-glass-review",
];
const REQUIRED_SCOPES: &[&str] = &[
    "windows-local-admin",
    "linux-sudo",
    "directory-group-membership",
    "privileged-role-expiry",
    "break-glass-access",
    "service-desk-escalation",
];
const REQUIRED_INPUTS: &[&str] = &[
    "ticketContext",
    "requesterSummary",
    "accessAction",
    "targetScopeSummary",
    "privilegeProfile",
    "operatingSystemFamily",
    "expiryWindow",
    "owner",
    "supportGroup",
    "approvalRoute",
    "rollbackPlan",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "ticket-context-known",
    "requester-authorized",
    "target-scope-summarized",
    "privilege-profile-reviewed",
    "os-family-supported",
    "expiry-window-reviewed",
    "approval-route-assigned",
    "worker-capability-reviewed",
    "rollback-plan-ready",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "accessSummary",
    "targetScope",
    "privilegeProfileReview",
    "directoryGroupReview",
    "sudoersReview",
    "expiryAndReview",
    "workerRouting",
    "rollbackPlan",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "worker-execution-disabled",
    "live-directory-change-disabled",
    "live-local-admin-change-disabled",
    "live-sudoers-change-disabled",
    "live-servicenow-change-disabled",
    "ad-group-membership-change-disabled",
    "sudoers-file-change-disabled",
    "privilege-grant-disabled",
    "privilege-removal-disabled",
    "raw-user-data-disabled",
    "raw-group-data-disabled",
    "raw-membership-rows-disabled",
    "raw-sudoers-content-disabled",
    "raw-request-payloads-disabled",
    "raw-provider-payloads-disabled",
    "principal-identifiers-disabled",
    "target-identifiers-disabled",
    "privilege-host-identifiers-disabled",
    "credential-values-disabled",
    "unsupported-access-action",
    "requester-not-authorized",
    "approval-missing",
    "expiry-missing",
    "worker-capability-unknown",
    "rollback-plan-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Privilege request summary",
    "Target scope summary",
    "Privilege profile review",
    "Directory group review",
    "Sudoers review",
    "Expiry and review window",
    "Worker capability decision",
    "Approval route",
    "Rollback plan",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "liveDirectoryChangesAllowed",
    "liveLocalAdminChangesAllowed",
    "liveSudoersChangesAllowed",
    "liveServiceNowChangesAllowed",
    "adGroupMembershipChangesAllowed",
    "sudoersFileChangesAllowed",
    "privilegeGrantAllowed",
    "privilegeRemovalAllowed",
    "rawUserDataAllowed",
    "rawGroupDataAllowed",
    "rawMembershipRowsAllowed",
    "rawSudoersContentAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "principalIdentifiersAllowed",
    "targetIdentifiersAllowed",
    "hostIdentifiersAllowed",
    "credentialValuesAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "accessMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "liveDirectoryChangesAllowed",
    "liveLocalAdminChangesAllowed",
    "liveSudoersChangesAllowed",
    "liveServiceNowChangesAllowed",
    "adGroupMembershipChangesAllowed",
    "sudoersFileChangesAllowed",
    "privilegeGrantAllowed",
    "privilegeRemovalAllowed",
    "rawUserDataAllowed",
    "rawGroupDataAllowed",
    "rawMembershipRowsAllowed",
    "rawSudoersContentAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "principalIdentifiersAllowed",
    "targetIdentifiersAllowed",
    "hostIdentifiersAllowed",
    "credentialValuesAllowed",
    "accessActions",
    "accessScopes",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str, &[&str])] = &[
    (
        "accessActions",
        "localPrivilegeAccessActions",
        REQUIRED_ACTIONS,
    ),
    (
        "accessScopes",
        "localPrivilegeAccessScopes",
        REQUIRED_SCOPES,
    ),
    (
        "requiredGuards",
        "localPrivilegeAccessRequiredGuards",
        REQUIRED_GUARDS,
    ),
    (
        "planSections",
        "localPrivilegeAccessPlanSections",
        REQUIRED_PLAN_SECTIONS,
    ),
    (
        "blockedReasons",
        "localPrivilegeAccessBlockedReasons",
        REQUIRED_BLOCKED_REASONS,
    ),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const SAFE_TRUE_FIELDS: &[&str] = &["dryRunRequired"];
const TOP_LEVEL_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "accessMode",
    "dryRunRequired",
    "rules",
    "providerCallsEnabled",
    "workerExecutionAllowed",
    "liveDirectoryChangesAllowed",
    "liveLocalAdminChangesAllowed",
    "liveSudoersChangesAllowed",
    "liveServiceNowChangesAllowed",
    "adGroupMembershipChangesAllowed",
    "sudoersFileChangesAllowed",
    "privilegeGrantAllowed",
    "privilegeRemovalAllowed",
    "rawUserDataAllowed",
    "rawGroupDataAllowed",
    "rawMembershipRowsAllowed",
    "rawSudoersContentAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "principalIdentifiersAllowed",
    "targetIdentifiersAllowed",
    "hostIdentifiersAllowed",
    "credentialValuesAllowed",
    "accessActions",
    "accessScopes",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
];
const REQUIRED_RULE_DETAILS: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-privilege-changes",
        "block",
        "Local privilege access requests produce review plans only and never grant, remove, or modify local administrator membership, AD group membership, sudoers files, ServiceNow records, workers, or provider state.",
        "Privilege request summary",
    ),
    (
        "approval-expiry-and-worker-required",
        "block",
        "Requester authorization, approval route, expiry window, worker capability review, and rollback plan must be present before future privilege execution can be considered.",
        "Approval route",
    ),
    (
        "directory-and-sudoers-review-required",
        "block",
        "Directory group impact, local administrator scope, sudoers policy, operating system family, and target scope must be reviewed before accepting a privilege request.",
        "Privilege profile review",
    ),
    (
        "raw-privilege-data-not-exposed",
        "block",
        "Local privilege access evidence must use safe summaries only and must not expose user names, account names, group names, email addresses, UPNs, sAMAccountNames, principal IDs, tenant IDs, object IDs, hostnames, FQDNs, target identifiers, raw membership rows, raw sudoers content, sudoers lines, sudo commands, raw request payloads, raw log content, raw recipient data, private IPs, credentials, secret values, access tokens, or provider payloads.",
        "Evidence references",
    ),
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Local privilege access seed data only. Do not add user names, account names, group names, email addresses, UPNs, sAMAccountNames, hostnames, FQDNs, target identifiers, principal IDs, tenant IDs, object IDs, private IPs, raw membership rows, raw sudoers content, sudoers lines, sudo commands, credentials, tokens, raw request payloads, raw logs, raw recipient data, or provider payloads.",
    "- No user names, account names, group names, email addresses, UPNs, sAMAccountNames, hostnames, FQDNs, target identifiers, principal identifiers, tenant identifiers, object identifiers, private network details, raw membership rows, raw sudoers content, sudoers lines, sudo commands, credential values, secret values, access tokens, raw request payloads, raw log content, raw recipient data, or provider payloads in committed files.",
    "| `/api/identity/local-privilege-access-contract` | Static local admin and sudo access request contract; live privilege changes and raw identity data disabled. |",
    "requirement: Local privilege access evidence must use safe summaries only and must not expose user names, account names, group names, email addresses, UPNs, sAMAccountNames, principal IDs, tenant IDs, object IDs, hostnames, FQDNs, target identifiers, raw membership rows, raw sudoers content, sudoers lines, sudo commands, raw request payloads, raw log content, raw recipient data, private IPs, credentials, secret values, access tokens, or provider payloads.",
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
    literal: bool,
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
        .map_err(|error| format!("invalid local privilege access context JSON: {error}"))?;

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
        PROGRAM_PATH: context.program,
        API_README_PATH: context.api_readme,
        CATALOG_README_PATH: context.catalog_readme,
        DOC_README_PATH: context.doc_readme,
        DOC_PATH: context.doc,
    });
    validate_no_prohibited_values(&docs, "local-privilege-access", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid local privilege access catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid local privilege access program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_value(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid local privilege access docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid local privilege access scan JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("local privilege access catalog must be an object".to_string());
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
            "local privilege access unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }

    expect(
        integer_field(catalog, "version") == Some(1),
        errors,
        "local privilege access version must be 1",
    );
    expect(
        string_field(catalog, "status") == Some("draft"),
        errors,
        "local privilege access status must be draft",
    );
    expect(
        string_field(catalog, "source") == Some("static-seed"),
        errors,
        "local privilege access source must be static-seed",
    );
    expect(
        string_field(catalog, "accessMode") == Some("review-only"),
        errors,
        "local privilege access mode must be review-only",
    );
    expect(
        bool_field(catalog, "dryRunRequired") == Some(true),
        errors,
        "local privilege access must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_field(catalog, field) == Some(false),
            errors,
            &format!("local privilege access {field} must be disabled"),
        );
    }

    validate_required_array(catalog, "accessActions", REQUIRED_ACTIONS, errors);
    validate_required_array(catalog, "accessScopes", REQUIRED_SCOPES, errors);
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
                "{field} contains prohibited local privilege access value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "{field} contains prohibited local privilege access phrase {phrase}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog.get("rules").and_then(Value::as_array);
    let Some(rules) = rules else {
        errors.push("local privilege access missing rules".to_string());
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
            "local privilege access missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "local privilege access unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.len() == actual.len(),
        errors,
        "local privilege access rule IDs must be unique",
    );
    for rule in rules {
        let Some(object) = rule.as_object() else {
            continue;
        };
        let unexpected_keys: Vec<&str> = object
            .keys()
            .map(String::as_str)
            .filter(|key| !["id", "decision", "requirement", "evidence"].contains(key))
            .collect();
        if !unexpected_keys.is_empty() {
            let id = string_field(rule, "id").unwrap_or("unknown");
            errors.push(format!(
                "local privilege access rule {id} unexpected keys: {}",
                unexpected_keys.join(", ")
            ));
        }
    }
    validate_rule_detail_uniqueness(&catalog_rules(catalog), "local privilege access", errors);
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
            &format!("local privilege access rule {id} decision must match"),
        );
        expect(
            string_field(rule, "requirement") == Some(*requirement),
            errors,
            &format!("local privilege access rule {id} requirement must match"),
        );
        expect(
            string_field(rule, "evidence") == Some(*evidence),
            errors,
            &format!("local privilege access rule {id} evidence must match"),
        );
    }
}

fn validate_program_value(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let blocks = extract_endpoint_blocks(program);
    if blocks.is_empty() {
        errors.push("API missing local privilege access endpoint".to_string());
        return;
    }
    if blocks.len() != 1 {
        errors.push(format!("API must expose exactly one {ENDPOINT} endpoint"));
    }
    let block = &blocks[0];
    validate_endpoint_payload_shape(&block.text, errors);
    let top_level_assignments = assignments_at_brace_depth(&block.text, 1);

    expect(
        exact_string_assignment(&top_level_assignments, "source", "static-seed"),
        errors,
        "API must keep static-seed source",
    );
    expect(
        exact_string_assignment(&top_level_assignments, "accessMode", "review-only"),
        errors,
        "API must keep review-only mode",
    );
    expect(
        exact_assignment(&top_level_assignments, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
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
        validate_endpoint_array_binding_not_mutated(&block.text, variable, field, errors);
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
            .and_then(|value| inline_array_values_from_assignment(field, value, errors));
        validate_api_array(
            field,
            inline_values,
            &catalog_string_array(catalog, field),
            errors,
        );
    }

    validate_api_rules(&block.text, catalog, errors);
    validate_endpoint_field_names(&block.text, errors);
    validate_no_unsafe_true_flags(&block.text, errors);
    validate_endpoint_prohibited_values(&block.text, errors);
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
                "API {field} contains prohibited local privilege access value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited local privilege access phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = endpoint_rules_array_block(block, errors)
        .map(|rules_block| api_rules(rules_block, errors))
        .unwrap_or_default();
    let catalog_rules = catalog_rules(catalog);
    let api_ids: Vec<String> = api_rules.iter().map(|rule| rule.id.clone()).collect();
    let catalog_ids: Vec<String> = catalog_rules.iter().map(|rule| rule.id.clone()).collect();
    let api_set: BTreeSet<&str> = api_ids.iter().map(String::as_str).collect();
    let catalog_set: BTreeSet<&str> = catalog_ids.iter().map(String::as_str).collect();
    for id in catalog_set.difference(&api_set) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_set.difference(&catalog_set) {
        errors.push(format!("API has unexpected rule {id}"));
    }
    expect(
        api_ids.len() == api_set.len(),
        errors,
        "API rule IDs must be unique",
    );
    validate_rule_detail_uniqueness(&api_rules, "API", errors);
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
    for assignment in assignments_at_brace_depth(block, 1) {
        let field = assignment.field;
        if !TOP_LEVEL_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected local privilege access field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited local privilege access field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for field in true_assignment_fields(block) {
        if SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        let name = field.to_ascii_lowercase();
        if [
            "live",
            "provider",
            "worker",
            "auth",
            "token",
            "directory",
            "admin",
            "sudo",
            "group",
            "privilege",
            "approval",
            "servicenow",
            "raw",
            "distinguished",
            "domain",
            "security",
            "host",
            "identifier",
            "principal",
            "tenant",
            "object",
            "credential",
            "payload",
            "recipient",
        ]
        .iter()
        .any(|needle| name.contains(needle))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn true_assignment_fields(block: &str) -> Vec<String> {
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
        if equals >= bytes.len()
            || bytes[equals] != b'='
            || bytes.get(equals + 1) == Some(&b'=')
            || equals > 0 && matches!(bytes[equals - 1], b'!' | b'<' | b'>')
        {
            continue;
        }
        let value_start = skip_ascii_whitespace(&masked, equals + 1);
        if identifier_at(&masked, value_start, "true") {
            fields.push(masked[start..index].to_string());
        }
    }
    fields
}

fn validate_endpoint_prohibited_values(block: &str, errors: &mut Vec<String>) {
    for (index, line) in block.lines().enumerate() {
        if contains_prohibited_value(line) {
            errors.push(format!(
                "API endpoint line {} contains prohibited value",
                index + 1
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
        "API README missing local privilege access endpoint",
    );
    expect(
        catalog_readme.contains("local-privilege-access-contract.yaml"),
        errors,
        "catalog README missing local privilege access catalog",
    );
    expect(
        doc_readme.contains("local-privilege-access.md"),
        errors,
        "workflow README missing local privilege access doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "local privilege access doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "local privilege access doc must prohibit provider calls",
    );
    expect(
        doc.contains("No worker execution."),
        errors,
        "local privilege access doc must prohibit worker execution",
    );
    expect(
        doc.contains("No live directory changes."),
        errors,
        "local privilege access doc must prohibit directory changes",
    );
    expect(
        doc.contains("No live local administrator changes."),
        errors,
        "local privilege access doc must prohibit local administrator changes",
    );
    expect(
        doc.contains("No live sudoers changes."),
        errors,
        "local privilege access doc must prohibit sudoers changes",
    );
    expect(
        doc.contains("No privilege grant or removal."),
        errors,
        "local privilege access doc must prohibit privilege changes",
    );
    expect(
        doc.contains("static local privilege access summaries only"),
        errors,
        "local privilege access doc must require static summaries",
    );
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited local privilege access field"
                    ));
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
                if local_privilege_text_path(path) {
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
                    "{path} contains prohibited local privilege access phrase {phrase}"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited local privilege access value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    if path.ends_with(PROGRAM_PATH) {
        validate_program_text_terms(text, path, errors);
        return;
    }

    for (index, line) in text.lines().enumerate() {
        if safe_text_line(line) {
            continue;
        }
        let prohibited_key = prohibited_line_key(line);
        if let Some(key) = prohibited_key.as_deref() {
            errors.push(format!(
                "{path}:{} contains prohibited local privilege access key {key}",
                index + 1
            ));
        }
        if !local_privilege_text_line(path, line) && prohibited_key.is_none() {
            continue;
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{path}:{} contains prohibited local privilege access phrase {phrase}",
                index + 1
            ));
        }
        if contains_prohibited_value(line) {
            errors.push(format!("{path}:{} contains prohibited value", index + 1));
        }
        for term in text_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited local privilege access field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn validate_program_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    let mut in_block_comment = false;
    for (index, line) in text.lines().enumerate() {
        for fragment in program_sensitive_fragments(line, &mut in_block_comment) {
            if fragment.text.trim().is_empty() || safe_text_line(fragment.text) {
                continue;
            }
            if fragment.kind == ProgramFragmentKind::String
                && !program_string_fragment_in_scope(fragment.source)
            {
                continue;
            }
            if let Some(key) = prohibited_program_key(fragment.text) {
                errors.push(format!(
                    "{path}:{} contains prohibited local privilege access key {key}",
                    index + 1
                ));
            }
            if contains_prohibited_value(fragment.text) {
                errors.push(format!("{path}:{} contains prohibited value", index + 1));
            }
            if let Some(phrase) = prohibited_phrase(fragment.text) {
                errors.push(format!(
                    "{path}:{} contains prohibited local privilege access phrase {phrase}",
                    index + 1
                ));
            }
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum ProgramFragmentKind {
    Comment,
    String,
}

struct ProgramFragment<'a> {
    text: &'a str,
    source: &'a str,
    kind: ProgramFragmentKind,
}

fn program_sensitive_fragments<'a>(
    line: &'a str,
    in_block_comment: &mut bool,
) -> Vec<ProgramFragment<'a>> {
    let mut fragments = Vec::new();
    let mut index = 0usize;
    while index < line.len() {
        if *in_block_comment {
            if let Some(offset) = line[index..].find("*/") {
                let finish = index + offset;
                fragments.push(ProgramFragment {
                    text: &line[index..finish],
                    source: line,
                    kind: ProgramFragmentKind::Comment,
                });
                index = finish + 2;
                *in_block_comment = false;
            } else {
                fragments.push(ProgramFragment {
                    text: &line[index..],
                    source: line,
                    kind: ProgramFragmentKind::Comment,
                });
                break;
            }
            continue;
        }

        let line_comment = line[index..].find("//").map(|offset| index + offset);
        let block_comment = line[index..].find("/*").map(|offset| index + offset);
        if let Some(line_start) = line_comment
            .filter(|line_start| block_comment.is_none_or(|block_start| *line_start < block_start))
        {
            fragments.push(ProgramFragment {
                text: &line[line_start..],
                source: line,
                kind: ProgramFragmentKind::Comment,
            });
            break;
        }
        if let Some(block_start) = block_comment {
            if let Some(offset) = line[(block_start + 2)..].find("*/") {
                let finish = block_start + 2 + offset;
                fragments.push(ProgramFragment {
                    text: &line[block_start..(finish + 2)],
                    source: line,
                    kind: ProgramFragmentKind::Comment,
                });
                index = finish + 2;
            } else {
                fragments.push(ProgramFragment {
                    text: &line[block_start..],
                    source: line,
                    kind: ProgramFragmentKind::Comment,
                });
                *in_block_comment = true;
                break;
            }
        } else {
            break;
        }
    }

    for literal in csharp_line_string_literals(line) {
        fragments.push(ProgramFragment {
            text: literal,
            source: line,
            kind: ProgramFragmentKind::String,
        });
    }
    fragments
}

fn csharp_line_string_literals(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let start = index + 1;
        index += 1;
        let mut escaped = false;
        while index < bytes.len() {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                values.push(&line[start..index]);
                break;
            }
            index += 1;
        }
        index += 1;
    }
    values
}

fn program_string_fragment_in_scope(line: &str) -> bool {
    local_privilege_program_line(line) || var_string_assignment_line(line)
}

fn local_privilege_program_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("local privilege")
        || lower.contains("local-privilege")
        || lower.contains("privilege access")
        || lower.contains(&ENDPOINT.to_ascii_lowercase())
}

fn var_string_assignment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    if !(trimmed.starts_with("var ") || trimmed.starts_with("string ")) {
        return false;
    }
    match trimmed.split_once('=') {
        Some((_, tail)) => tail.trim_start().starts_with('"'),
        None => false,
    }
}

fn prohibited_line_key(line: &str) -> Option<String> {
    prohibited_text_key(line)
}

fn prohibited_program_key(line: &str) -> Option<String> {
    prohibited_text_key(line).or_else(|| prohibited_field_key(line))
}

fn prohibited_text_key(line: &str) -> Option<String> {
    text_terms(line)
        .into_iter()
        .find(|term| prohibited_text_key_normalized(&normalize_identifier(term)))
}

fn prohibited_field_key(line: &str) -> Option<String> {
    text_terms(line)
        .into_iter()
        .find(|term| prohibited_field(term))
}

fn prohibited_text_key_normalized(normalized: &str) -> bool {
    [
        "tenantid",
        "tenantidentifier",
        "objectid",
        "objectidentifier",
        "subscriptionid",
        "hostname",
        "hostidentifier",
        "fqdn",
        "endpointname",
        "endpointurl",
        "liveendpoint",
        "targeturl",
        "targetid",
        "targetidentifier",
        "principalid",
        "principalidentifier",
        "privateip",
        "privatenetwork",
        "serialnumber",
        "apikey",
        "privatekey",
        "rawproviderpayload",
        "rawproviderpayloads",
        "providerpayload",
        "providerpayloads",
        "provideroutput",
        "recipientdata",
    ]
    .contains(&normalized)
}

fn validate_endpoint_payload_shape(block: &str, errors: &mut Vec<String>) {
    let spans = results_json_new_spans(block);
    if spans.is_empty() {
        errors.push(
            "API local privilege access endpoint must use direct Results.Json payload".to_string(),
        );
        return;
    }
    if spans.len() != 1 {
        errors.push("API must declare exactly one local privilege access JSON payload".to_string());
        return;
    }
    let (results_start, new_end) = spans[0];
    let masked = csharp_code_mask(block);
    if !direct_results_json_preamble(&masked[..results_start]) {
        errors.push(
            "API local privilege access endpoint must use direct Results.Json payload with no block-lambda preamble"
                .to_string(),
        );
    }
    let object_start = skip_ascii_whitespace(&masked, new_end);
    if object_start >= masked.len() || masked.as_bytes()[object_start] != b'{' {
        errors.push(
            "API local privilege access Results.Json payload must use a single anonymous object"
                .to_string(),
        );
        return;
    }
    let Some(object_end) = matching_delimiter_index(&masked, object_start, b'{', b'}') else {
        errors.push(
            "API local privilege access Results.Json payload must use a single anonymous object"
                .to_string(),
        );
        return;
    };
    let tail = block[(object_end + 1)..].trim();
    if tail != "));" {
        if tail.starts_with('.') {
            errors.push(
                "API local privilege access Results.Json payload must close directly with no transforms"
                    .to_string(),
            );
        } else if tail.contains("AddEndpointFilter") {
            errors.push(
                "API local privilege access MapGet endpoint must close directly with no endpoint filters"
                    .to_string(),
            );
        } else {
            errors.push(
                "API local privilege access Results.Json payload must use a single anonymous object and close the MapGet call directly with no transforms or endpoint filters"
                    .to_string(),
            );
        }
    }
}

fn direct_results_json_preamble(preamble: &str) -> bool {
    let trimmed = preamble.trim_end();
    trimmed.ends_with("() =>") && !trimmed.contains('{')
}

fn payload_object_close(block: &str) -> Option<usize> {
    let masked = csharp_code_mask(block);
    let new_end = results_json_new_indexes(block).first().copied()?;
    let object_start = skip_ascii_whitespace(&masked, new_end);
    matching_delimiter_index(&masked, object_start, b'{', b'}')
}

fn results_json_new_indexes(block: &str) -> Vec<usize> {
    results_json_new_spans(block)
        .into_iter()
        .map(|(_, new_end)| new_end)
        .collect()
}

fn results_json_new_spans(block: &str) -> Vec<(usize, usize)> {
    let masked = csharp_code_mask(block);
    let mut indexes = Vec::new();
    let mut index = 0;
    while let Some(results_start) = identifier_match(&masked, "Results", index) {
        let dot = skip_ascii_whitespace(&masked, results_start + "Results".len());
        if masked.as_bytes().get(dot) != Some(&b'.') {
            index = results_start + "Results".len();
            continue;
        }
        let json = skip_ascii_whitespace(&masked, dot + 1);
        if !identifier_at(&masked, json, "Json") {
            index = results_start + "Results".len();
            continue;
        }
        let paren = skip_ascii_whitespace(&masked, json + "Json".len());
        if masked.as_bytes().get(paren) != Some(&b'(') {
            index = results_start + "Results".len();
            continue;
        }
        let new_start = skip_ascii_whitespace(&masked, paren + 1);
        if identifier_at(&masked, new_start, "new") {
            indexes.push((results_start, new_start + "new".len()));
        }
        index = results_start + "Results".len();
    }
    indexes
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
            let next_endpoint = next_code_match(&masked, "\napp.MapGet(", start + 1);
            let close = matching_delimiter_index(&masked, paren, b'(', b')');
            let mut end = match (close, next_endpoint) {
                (Some(close), Some(next)) if close < next => close + 1,
                (Some(close), None) => close + 1,
                (_, Some(next)) => next,
                (None, None) => masked.len(),
            };
            if close.is_some_and(|close| end == close + 1) {
                while end < masked.len() && masked.as_bytes()[end].is_ascii_whitespace() {
                    end += 1;
                }
                if end < masked.len() && masked.as_bytes()[end] == b';' {
                    end += 1;
                }
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
    if contains_array_mutation(&masked_after, variable) {
        errors.push(format!(
            "API {field} array variable {variable} must not be mutated before endpoint use"
        ));
    }
    if !declaration.literal {
        errors.push(format!(
            "API {field} array binding {variable} must use literal string entries only"
        ));
    }
    Some(declaration.values.clone())
}

fn validate_endpoint_array_binding_not_mutated(
    block: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    let Some(results_start) = results_json_new_spans(block).first().map(|span| span.0) else {
        return;
    };
    let before_json = csharp_code_mask(&block[..results_start]);
    if contains_array_mutation(&before_json, variable) {
        errors.push(format!(
            "API {field} array variable {variable} must not be mutated before endpoint use"
        ));
    }
}

fn contains_array_mutation(text: &str, variable: &str) -> bool {
    let mut index = 0usize;
    while let Some(start) = identifier_match(text, variable, index) {
        let after = skip_ascii_whitespace(text, start + variable.len());
        if text.as_bytes().get(after) == Some(&b'=') {
            return true;
        }
        if text.as_bytes().get(after) == Some(&b'[') {
            return true;
        }
        if text.as_bytes().get(after) == Some(&b'.') {
            let method = skip_ascii_whitespace(text, after + 1);
            if [
                "Append", "Concat", "Where", "Select", "Union", "Prepend", "SetValue", "Add",
                "Clear",
            ]
            .iter()
            .any(|name| identifier_at(text, method, name))
            {
                return true;
            }
        }
        index = start + variable.len();
    }

    let mut search = 0usize;
    while let Some(array_start) = identifier_match(text, "Array", search) {
        let dot = skip_ascii_whitespace(text, array_start + "Array".len());
        if text.as_bytes().get(dot) != Some(&b'.') {
            search = array_start + "Array".len();
            continue;
        }
        if let Some(open) = text[dot..].find('(').map(|offset| dot + offset) {
            let argument_start = skip_ascii_whitespace(text, open + 1);
            let argument_start = if identifier_at(text, argument_start, "ref") {
                skip_ascii_whitespace(text, argument_start + "ref".len())
            } else {
                argument_start
            };
            if identifier_at(text, argument_start, variable) {
                return true;
            }
        }
        search = dot + 1;
    }
    false
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
                        let (values, literal) =
                            csharp_array_literal_values(&prefix[(open + 1)..close]);
                        declarations.push(ArrayDeclaration {
                            end,
                            values,
                            literal,
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

fn inline_array_values_from_assignment(
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let masked = csharp_code_mask(value);
    let trimmed = masked.trim();
    if !trimmed.starts_with("new[]") {
        errors.push(format!(
            "API {field} array must use literal string entries only"
        ));
        return None;
    }
    let open = masked.find('{')?;
    let close = matching_delimiter_index(&masked, open, b'{', b'}')?;
    if !masked[(close + 1)..].trim().is_empty() {
        errors.push(format!(
            "API {field} array must use literal string entries only"
        ));
    }
    let (values, literal) = csharp_array_literal_values(&value[(open + 1)..close]);
    if !literal {
        errors.push(format!(
            "API {field} array must use literal string entries only"
        ));
    }
    Some(values)
}

fn endpoint_rules_array_block<'a>(block: &'a str, errors: &mut Vec<String>) -> Option<&'a str> {
    let masked = csharp_code_mask(block);
    let assignments: Vec<Assignment> = assignments_at_brace_depth(block, 1)
        .into_iter()
        .filter(|assignment| assignment.field == "rules")
        .collect();
    if assignments.is_empty() {
        errors.push("API missing rules array".to_string());
        return None;
    }
    if assignments.len() != 1 {
        errors.push("API rules array must be declared once".to_string());
        return None;
    }

    let start = assignments[0].start;
    let equals = masked[start..].find('=').map(|offset| start + offset)?;
    let after_equals = skip_ascii_whitespace(&masked, equals + 1);
    if !starts_with_new_array(&masked, after_equals) {
        errors.push("API rules array must use direct new[] literal array".to_string());
        return None;
    }
    let Some(open_offset) = masked[after_equals..].find('{') else {
        errors.push("API rules array must use direct new[] literal array".to_string());
        return None;
    };
    let open = after_equals + open_offset;
    let Some(close) = matching_delimiter_index(&masked, open, b'{', b'}') else {
        errors.push("API rules array must use direct new[] literal array".to_string());
        return None;
    };
    let Some(payload_close) = payload_object_close(block) else {
        errors.push("API local privilege access JSON payload must be a single object".to_string());
        return None;
    };
    if close >= payload_close || !masked[(close + 1)..payload_close].trim().is_empty() {
        errors.push("API rules array must use direct new[] literal array".to_string());
    }
    Some(&block[open..=close])
}

fn api_rules(block: &str, errors: &mut Vec<String>) -> Vec<ApiRule> {
    let mut rules = Vec::new();
    for member in top_level_array_members(block) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        let masked = csharp_code_mask(text);
        if !identifier_at(&masked, 0, "new") {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let open = skip_ascii_whitespace(&masked, "new".len());
        if open >= masked.len() || masked.as_bytes()[open] != b'{' {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let Some(close) = matching_delimiter_index(&masked, open, b'{', b'}') else {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        };
        if !masked[(close + 1)..].trim().is_empty() {
            errors.push(
                "API rules array members must be direct anonymous literal objects".to_string(),
            );
            continue;
        }
        let object_text = &text[open..=close];
        let assignments = assignments_at_brace_depth(object_text, 1);
        let id = string_assignment_value(&assignments, "id");
        let decision = string_assignment_value(&assignments, "decision");
        let requirement = string_assignment_value(&assignments, "requirement");
        let evidence = string_assignment_value(&assignments, "evidence");
        let rule_label = id.as_deref().unwrap_or("unknown");
        for assignment in &assignments {
            if !["id", "decision", "requirement", "evidence"].contains(&assignment.field.as_str()) {
                errors.push(format!(
                    "API rule {rule_label} has unexpected field {}",
                    assignment.field
                ));
            }
        }
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
    }
    rules
}

fn top_level_array_members(array_block: &str) -> Vec<&str> {
    let body = array_block
        .trim()
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(array_block);
    split_top_level_members(body)
}

fn split_top_level_members(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut members = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == b'{' {
            depth += 1;
        } else if bytes[index] == b'}' {
            depth = depth.saturating_sub(1);
        } else if bytes[index] == b',' && depth == 0 {
            members.push(&body[start..index]);
            start = index + 1;
        }
        index += 1;
    }
    members.push(&body[start..]);
    members
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

fn validate_rule_detail_uniqueness(rules: &[ApiRule], label: &str, errors: &mut Vec<String>) {
    let mut details = BTreeSet::new();
    for rule in rules {
        if !details.insert((
            rule.decision.as_str(),
            rule.requirement.as_str(),
            rule.evidence.as_str(),
        )) {
            errors.push(format!("{label} rule details must be unique"));
            return;
        }
    }
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

fn csharp_array_literal_values(body: &str) -> (Vec<String>, bool) {
    let mut values = Vec::new();
    let mut literal = true;
    for member in array_members(body) {
        let text = member.trim();
        if text.is_empty() {
            continue;
        }
        if let Some((value, end)) = csharp_string_literal_value(text, 0) {
            if end == text.len() {
                values.push(value);
                continue;
            }
        }
        literal = false;
    }
    (values, literal)
}

fn array_members(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut members = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            in_string = true;
        } else if bytes[index] == b',' {
            members.push(&body[start..index]);
            start = index + 1;
        }
        index += 1;
    }
    members.push(&body[start..]);
    members
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

fn identifier_at(text: &str, start: usize, identifier: &str) -> bool {
    let bytes = text.as_bytes();
    let identifier_bytes = identifier.as_bytes();
    let Some(slice) = bytes.get(start..start + identifier_bytes.len()) else {
        return false;
    };
    let before = start == 0 || !is_identifier_continue(bytes[start - 1]);
    let after_index = start + identifier_bytes.len();
    let after = after_index >= bytes.len() || !is_identifier_continue(bytes[after_index]);
    before && after && slice == identifier_bytes
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
        || value == "review-only"
        || value == "block"
        || REQUIRED_ACTIONS.contains(&value)
        || REQUIRED_SCOPES.contains(&value)
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
    let id = stripped.strip_prefix("- id: ").unwrap_or(stripped);
    let requirement = stripped.strip_prefix("requirement: ").unwrap_or(stripped);
    let evidence = stripped.strip_prefix("evidence: ").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped)
        || safe_text_value(bullet)
        || safe_text_value(id)
        || safe_text_value(requirement)
        || safe_text_value(evidence)
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    if normalized.is_empty() || safe_normalized_value(&normalized) {
        return false;
    }
    [
        "username",
        "userid",
        "useridentifier",
        "userprincipalname",
        "userprincipal",
        "upn",
        "samaccountname",
        "mailaddress",
        "email",
        "accountname",
        "accountid",
        "accountidentifier",
        "groupname",
        "groupid",
        "groupidentifier",
        "localadmingroup",
        "sudoersline",
        "sudocommand",
        "hostname",
        "fqdn",
        "targetid",
        "targetidentifier",
        "principalid",
        "principalidentifier",
        "tenantid",
        "tenantidentifier",
        "objectid",
        "objectidentifier",
        "subscriptionid",
        "hostidentifier",
        "endpointname",
        "endpointurl",
        "liveendpoint",
        "targeturl",
        "privateip",
        "privatenetwork",
        "serialnumber",
        "apikey",
        "privatekey",
        "rawmembership",
        "membershiprow",
        "rawsudoers",
        "sudoerscontent",
        "rawrequest",
        "requestpayload",
        "rawlog",
        "logcontent",
        "rawrecipient",
        "recipientdata",
        "providerpayload",
        "provideroutput",
        "credentialvalue",
        "secretvalue",
        "accesstoken",
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
    ["draft", "static-seed", "review-only", "block"]
        .iter()
        .any(|safe| normalize_identifier(safe) == normalized)
        || REQUIRED_ACTIONS
            .iter()
            .chain(REQUIRED_SCOPES)
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
    if has_adjacent(&tokens, "user", &["name", "names"]) {
        return Some("user name");
    }
    if has_adjacent(&tokens, "account", &["name", "names"]) {
        return Some("account name");
    }
    if has_adjacent(&tokens, "group", &["name", "names"]) {
        return Some("group name");
    }
    if has_adjacent(&tokens, "email", &["address", "addresses"]) {
        return Some("email address");
    }
    if tokens
        .iter()
        .any(|token| token == "samaccountname" || token == "samaccountnames")
    {
        return Some("sAMAccountName");
    }
    if has_triplet(&tokens, "raw", "membership", &["row", "rows"]) {
        return Some("raw membership rows");
    }
    if has_triplet(&tokens, "raw", "sudoers", &["content"]) {
        return Some("raw sudoers content");
    }
    if has_adjacent(&tokens, "sudoers", &["line", "lines"]) {
        return Some("sudoers line");
    }
    if has_adjacent(&tokens, "sudo", &["command", "commands"]) {
        return Some("sudo command");
    }
    if has_adjacent(&tokens, "host", &["name", "names"]) {
        return Some("host name");
    }
    if has_adjacent(&tokens, "target", &["identifier", "identifiers"]) {
        return Some("target identifier");
    }
    if has_adjacent(&tokens, "principal", &["id", "ids"]) {
        return Some("principal ID");
    }
    if has_adjacent(&tokens, "principal", &["identifier", "identifiers"]) {
        return Some("principal identifier");
    }
    if has_adjacent(&tokens, "tenant", &["id", "ids"]) {
        return Some("tenant ID");
    }
    if has_adjacent(&tokens, "object", &["id", "ids"]) {
        return Some("object ID");
    }
    if has_adjacent(&tokens, "private", &["ip", "ips"]) {
        return Some("private IP");
    }
    if has_triplet(&tokens, "raw", "log", &["content"]) {
        return Some("raw log content");
    }
    if has_triplet(&tokens, "raw", "recipient", &["data"]) {
        return Some("raw recipient data");
    }
    if has_adjacent(&tokens, "recipient", &["data"]) {
        return Some("recipient data");
    }
    if has_adjacent(&tokens, "provider", &["payload", "payloads"]) {
        return Some("provider payload");
    }
    if has_adjacent(&tokens, "credential", &["value", "values"]) {
        return Some("credential value");
    }
    if has_adjacent(&tokens, "secret", &["value", "values"]) {
        return Some("secret value");
    }
    if has_adjacent(&tokens, "access", &["token", "tokens"]) {
        return Some("access token");
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
        || contains_sid(value)
        || contains_distinguished_name(value)
        || contains_windows_account(value)
        || contains_public_fqdn(value)
        || contains_email(value)
        || contains_sensitive_path(value)
        || contains_sudo_all(value)
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

fn contains_sid(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let parts: Vec<&str> = token
            .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '-')
            .split('-')
            .collect();
        parts.len() >= 6
            && parts.first() == Some(&"S")
            && parts.iter().skip(1).all(|part| {
                !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
            })
    })
}

fn contains_windows_account(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let token = token.trim_matches(|character: char| {
            !character.is_ascii_alphanumeric() && !matches!(character, '\\' | '.' | '_' | '-')
        });
        let Some((left, right)) = token.split_once('\\') else {
            return false;
        };
        !left.is_empty()
            && !right.is_empty()
            && left.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            })
            && right.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            })
    })
}

fn contains_distinguished_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if (lower.contains("cn=") || lower.contains("ou=") || lower.contains("dc="))
        && lower.contains(",")
        && lower.contains(",dc=")
    {
        return true;
    }
    value.split_whitespace().any(|token| {
        let parts: Vec<&str> = token
            .trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '=' && character != ','
            })
            .split(',')
            .collect();
        parts.len() >= 2
            && parts.iter().all(|part| {
                let lower = part.to_ascii_lowercase();
                lower.starts_with("cn=") || lower.starts_with("ou=") || lower.starts_with("dc=")
            })
    })
}

fn contains_public_fqdn(value: &str) -> bool {
    value
        .split(|character: char| {
            character.is_ascii_whitespace()
                || matches!(character, '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']')
        })
        .any(|token| {
            let token = token.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '-' && character != '.'
            });
            let labels: Vec<&str> = token.split('.').collect();
            labels.len() >= 3
                && labels.iter().all(|label| {
                    !label.is_empty()
                        && label
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric() || character == '-')
                })
                && !contains_private_ip(token)
        })
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

fn contains_sensitive_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "/etc/",
        "/var/",
        "/home/",
        "/opt/",
        "/srv/",
        "/tmp/",
        "/usr/",
        "/windows/",
        "/programdata/",
        "/program files/",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn contains_sudo_all(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("sudo") && lower.contains("all=(all)") && lower.contains(" all")
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

fn local_privilege_text_path(path: &str) -> bool {
    [
        CATALOG_PATH,
        PROGRAM_PATH,
        DOC_PATH,
        API_README_PATH,
        CATALOG_README_PATH,
        DOC_README_PATH,
    ]
    .iter()
    .any(|text_path| path.ends_with(text_path))
}

fn local_privilege_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(CATALOG_PATH) || path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("local privilege")
        || lower.contains("local-privilege")
        || lower.contains("local admin")
        || lower.contains("sudo")
        || lower.contains("privilege access")
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
