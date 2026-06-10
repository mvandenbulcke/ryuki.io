use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/security-baseline-contract.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/security-baseline.md";
const ARCHITECTURE_DOC_PATH: &str = "docs/architecture/security-baseline.md";
const NO_SECRET_SCAN_PATH: &str = "scripts/no-secret-scan.sh";
const BUILD_SHEET_PATH: &str = "docs/platform-build-sheet.md";
const ENDPOINT: &str = "/api/platform/security-baseline-contract";

const REQUIRED_SOURCE_INPUT_REFS: &[&str] = &[
    "source-ref-product-brief",
    "source-ref-brand-purpose",
    "source-ref-logo-asset",
    "source-ref-customization-spec-set",
];
const REQUIRED_CONTROLS: &[&str] = &[
    "no-secrets",
    "identity-rbac-approval",
    "dry-run-first",
    "request-lifecycle-gates",
    "vault-secret-reference",
    "browser-isolation",
    "network-isolation",
    "evidence-redaction",
    "least-privilege-adapters",
    "safe-failure-degraded-mode",
    "verification-gates",
];
const REQUIRED_VERIFICATION_GATES: &[&str] = &[
    "markdown-review",
    "no-secret-scan",
    "diff-check",
    "unit-tests",
    "contract-tests",
    "build",
    "container-build",
    "kubernetes-validation",
    "browser-checks",
];
const REQUIRED_INPUTS: &[&str] = &[
    "securityScope",
    "controlSummary",
    "rbacApprovalSummary",
    "dryRunSummary",
    "networkIsolationSummary",
    "evidenceRedactionSummary",
    "verificationSummary",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "no-secret-scan-ready",
    "rbac-approval-reviewed",
    "dry-run-gates-reviewed",
    "browser-isolation-reviewed",
    "network-isolation-reviewed",
    "redaction-reviewed",
    "least-privilege-reviewed",
    "verification-gates-reviewed",
    "safe-failure-reviewed",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "noSecretsPolicy",
    "identityRbacApproval",
    "dryRunLifecycle",
    "secretReferenceModel",
    "browserNetworkIsolation",
    "evidenceRedaction",
    "adapterLeastPrivilege",
    "degradedMode",
    "verificationGates",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-authentication-disabled",
    "workflow-mutation-disabled",
    "policy-mutation-disabled",
    "approval-bypass-disabled",
    "rbac-bypass-disabled",
    "browser-vendor-endpoint-disabled",
    "raw-request-payloads-disabled",
    "raw-provider-payloads-disabled",
    "raw-evidence-payloads-disabled",
    "raw-log-content-disabled",
    "credential-values-disabled",
    "secret-values-disabled",
    "access-token-values-disabled",
    "raw-recipient-data-disabled",
    "no-secret-scan-missing",
    "rbac-approval-review-missing",
    "dry-run-gate-review-missing",
    "browser-isolation-review-missing",
    "network-isolation-review-missing",
    "redaction-review-missing",
    "verification-gates-missing",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Security baseline summary",
    "No-secret scan result",
    "RBAC and approval review",
    "Dry-run gate review",
    "Browser isolation review",
    "Network isolation review",
    "Evidence redaction review",
    "Least privilege review",
    "Verification gate review",
    "Evidence references",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "noSecretPolicyRequired",
    "browserIsolationRequired",
    "networkIsolationRequired",
    "rbacApprovalRequired",
    "dryRunRequired",
    "redactedEvidenceRequired",
    "verificationGatesRequired",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsAllowed",
    "liveAuthenticationAllowed",
    "workflowMutationAllowed",
    "policyMutationAllowed",
    "approvalBypassAllowed",
    "rbacBypassAllowed",
    "browserVendorEndpointAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawLogContentAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "accessTokenValuesAllowed",
    "rawRecipientDataAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "baselineMode",
    "noSecretPolicyRequired",
    "browserIsolationRequired",
    "networkIsolationRequired",
    "rbacApprovalRequired",
    "dryRunRequired",
    "redactedEvidenceRequired",
    "verificationGatesRequired",
    "securityControls",
    "verificationGates",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "providerCallsAllowed",
    "liveAuthenticationAllowed",
    "workflowMutationAllowed",
    "policyMutationAllowed",
    "approvalBypassAllowed",
    "rbacBypassAllowed",
    "browserVendorEndpointAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawLogContentAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "accessTokenValuesAllowed",
    "rawRecipientDataAllowed",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("securityControls", "securityBaselineControls"),
    ("verificationGates", "securityBaselineVerificationGates"),
    ("requiredGuards", "securityBaselineRequiredGuards"),
    ("planSections", "securityBaselinePlanSections"),
    ("blockedReasons", "securityBaselineBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "baselineMode",
    "noSecretPolicyRequired",
    "browserIsolationRequired",
    "networkIsolationRequired",
    "rbacApprovalRequired",
    "dryRunRequired",
    "redactedEvidenceRequired",
    "verificationGatesRequired",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "securityControls",
    "verificationGates",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "providerCallsAllowed",
    "liveAuthenticationAllowed",
    "workflowMutationAllowed",
    "policyMutationAllowed",
    "approvalBypassAllowed",
    "rbacBypassAllowed",
    "browserVendorEndpointAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawLogContentAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "accessTokenValuesAllowed",
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

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-secrets-required",
        decision: "block",
        requirement: "Security baseline readiness requires no committed sensitive auth material, deployment-specific identifiers, private network details, direct provider routes, or raw provider content.",
        evidence: "No-secret scan result",
    },
    RuleDetail {
        id: "rbac-approval-required",
        decision: "block",
        requirement: "Role mapping, least privilege, approval route, execution authority, and emergency handling must be reviewed before live execution can be considered.",
        evidence: "RBAC and approval review",
    },
    RuleDetail {
        id: "dry-run-lifecycle-required",
        decision: "block",
        requirement: "Write-capable workflows must keep dry-run planning, approval, lock, verification, status callback, and redacted evidence gates before execution readiness.",
        evidence: "Dry-run gate review",
    },
    RuleDetail {
        id: "browser-network-isolation-required",
        decision: "block",
        requirement: "Browser access must remain limited to portal-ui and platform-api while namespace traffic stays deny-by-default with reviewed allowances.",
        evidence: "Network isolation review",
    },
    RuleDetail {
        id: "redaction-and-verification-required",
        decision: "block",
        requirement: "Evidence redaction and appropriate verification gates must pass before any implementation slice can be accepted.",
        evidence: "Verification gate review",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    architecture_doc: String,
    architecture_readme: String,
    no_secret_scan: String,
    build_sheet: String,
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
    architecture_doc: String,
    architecture_readme: String,
    no_secret_scan: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

#[derive(Debug, Deserialize)]
struct BuildSheetInput {
    build_sheet: String,
}

#[derive(Clone, Copy)]
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

struct MapRoute {
    start: usize,
    route: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid security baseline context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &context.architecture_doc,
        &context.architecture_readme,
        &context.no_secret_scan,
        &mut errors,
    );
    validate_build_sheet_source_inputs_text(&context.build_sheet, &mut errors);
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
    scan_prohibited_value(
        &Value::String(context.architecture_doc),
        ARCHITECTURE_DOC_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(no_secret_scan_without_signature_patterns(
            &context.no_secret_scan,
        )),
        NO_SECRET_SCAN_PATH,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid security baseline catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid security baseline program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid security baseline docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.api_readme,
        &payload.catalog_readme,
        &payload.doc_readme,
        &payload.doc,
        &payload.architecture_doc,
        &payload.architecture_readme,
        &payload.no_secret_scan,
        &mut errors,
    );
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid security baseline prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

pub fn validate_build_sheet_source_inputs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: BuildSheetInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid security baseline build sheet JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_build_sheet_source_inputs_text(&payload.build_sheet, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("security baseline catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "security baseline version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "security baseline status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "security baseline source must be static-seed",
    );
    expect(
        string_value(catalog, "baselineMode") == Some("static-security-baseline"),
        errors,
        "security baseline mode must be static-security-baseline",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("security baseline {field} must be required"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("security baseline {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "securityControls", REQUIRED_CONTROLS, errors);
    validate_required_array(
        catalog,
        "verificationGates",
        REQUIRED_VERIFICATION_GATES,
        errors,
    );
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let expected: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !expected.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "security baseline unexpected catalog keys: {}",
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
                "{field} contains prohibited security baseline value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rule_values(catalog);
    let parsed_rules: Vec<Rule> = rules
        .iter()
        .filter_map(|rule| rule_from_value(rule))
        .collect();
    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let rule_ids: Vec<&str> = parsed_rules.iter().map(|rule| rule.id.as_str()).collect();
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
        format!("security baseline missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "security baseline unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "security baseline rule IDs must be unique",
    );
    for rule in rules {
        let Some(map) = rule.as_object() else {
            errors.push("security baseline rule must be a mapping".to_string());
            continue;
        };
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        let actual_keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
        let unexpected_keys: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing_keys: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "security baseline rule {rule_id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "security baseline rule {rule_id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = parsed_rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "security baseline rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "security baseline rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "security baseline rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let Some(block) = endpoint_block(&uncommented_program, errors) else {
        return;
    };
    expect(
        exactly_one_string_assignment(&block, "source", "static-seed"),
        errors,
        "API must keep exactly one static-seed source",
    );
    expect(
        exactly_one_string_assignment(&block, "baselineMode", "static-security-baseline"),
        errors,
        "API must keep exactly one static-security-baseline mode",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            exactly_one_endpoint_assignment(&block, field, "true"),
            errors,
            format!("API must keep exactly one {field} true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            exactly_one_endpoint_assignment(&block, field, "false"),
            errors,
            format!("API must keep exactly one {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exactly_one_endpoint_assignment(&block, field, variable),
            errors,
            format!("API must bind exactly one {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array_like(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            string_array_like(catalog, field),
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
    let catalog_rules: Vec<Rule> = catalog_rule_values(catalog)
        .iter()
        .filter_map(|rule| rule_from_value(rule))
        .collect();
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
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
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

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let code = csharp_code_surface(block);
    for field in assignment_fields(&code) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected security baseline field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited security baseline field {field}"
            ));
        }
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for field in top_level_assignment_fields(&code) {
        *counts.entry(field).or_insert(0) += 1;
    }
    for (field, count) in counts {
        if count > 1 {
            errors.push(format!(
                "API endpoint has duplicate security baseline field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let code = csharp_code_surface(block);
    for (field, value) in assignment_values(&code) {
        if value != "true" {
            continue;
        }
        let lowered = field.to_ascii_lowercase();
        if [
            "provider",
            "live",
            "workflow",
            "policy",
            "approval",
            "rbac",
            "browser",
            "raw",
            "credential",
            "secret",
            "token",
            "recipient",
        ]
        .iter()
        .any(|term| lowered.contains(term))
            && !SAFE_TRUE_FIELDS.contains(&field.as_str())
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_docs_text(
    api_readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    architecture_doc: &str,
    architecture_readme: &str,
    no_secret_scan: &str,
    errors: &mut Vec<String>,
) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing security baseline endpoint",
    );
    expect(
        catalog_readme.contains("security-baseline-contract.yaml"),
        errors,
        "catalog README missing security baseline catalog",
    );
    expect(
        doc_readme.contains("security-baseline.md"),
        errors,
        "workflow README missing security baseline doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "security baseline doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "security baseline doc must prohibit provider calls",
    );
    expect(
        doc.contains("No live authentication or token validation."),
        errors,
        "security baseline doc must prohibit live auth",
    );
    expect(
        architecture_readme.contains("Security Baseline"),
        errors,
        "architecture README missing security baseline",
    );
    expect(
        architecture_doc.contains("Secrets must never be committed"),
        errors,
        "architecture security baseline missing no-secret rule",
    );
    expect(
        architecture_doc.contains("Live execution requires validation, approval, locking, execution, verification, evidence, and status callback."),
        errors,
        "architecture security baseline missing execution lifecycle",
    );
    expect(
        architecture_doc.contains("Browser code must call only `portal-ui` and `platform-api`"),
        errors,
        "architecture security baseline missing browser isolation",
    );
    expect(
        architecture_doc.contains("Network policy starts from deny-all."),
        errors,
        "architecture security baseline missing deny-all network policy",
    );
    expect(
        architecture_doc
            .contains("Evidence must be redacted before storage, export, display, or indexing."),
        errors,
        "architecture security baseline missing evidence redaction",
    );
    expect(
        architecture_doc.contains("Each adapter must use its own identity."),
        errors,
        "architecture security baseline missing adapter least privilege",
    );
    expect(
        no_secret_scan.contains("AKIA[0-9A-Z]{16}"),
        errors,
        "no-secret scan missing access key pattern",
    );
    expect(
        no_secret_scan.contains("PRIVATE KEY"),
        errors,
        "no-secret scan missing private key pattern",
    );
    expect(
        no_secret_scan.contains("access_token"),
        errors,
        "no-secret scan missing token pattern",
    );
}

fn validate_build_sheet_source_inputs_text(build_sheet: &str, errors: &mut Vec<String>) {
    let source_section = markdown_section(build_sheet, "## Source Inputs Reviewed");
    expect(
        source_section.contains("| Source reference | Use In This Build Sheet |"),
        errors,
        "build sheet source inputs must use source references",
    );
    let ref_scan_text = strip_html_comments(&source_section);
    let refs = source_input_refs(&ref_scan_text);
    let ref_set: BTreeSet<&str> = refs.iter().map(String::as_str).collect();
    let required_set: BTreeSet<&str> = REQUIRED_SOURCE_INPUT_REFS.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_SOURCE_INPUT_REFS
        .iter()
        .copied()
        .filter(|item| !ref_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = refs
        .iter()
        .map(String::as_str)
        .filter(|item| !required_set.contains(item))
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "build sheet source input refs missing: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "build sheet source input refs unexpected: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        refs.iter().collect::<BTreeSet<_>>().len() == refs.len(),
        errors,
        "build sheet source input refs must be unique",
    );

    let mut in_source_section = false;
    for (index, line) in build_sheet.lines().enumerate() {
        if line == "## Source Inputs Reviewed" {
            in_source_section = true;
        } else if in_source_section && line.starts_with("## ") {
            in_source_section = false;
        }
        let lowered = line.to_ascii_lowercase();
        let raw_source_path = lowered.contains("sources/");
        let raw_source_filename = in_source_section
            && [".pdf", ".png", ".xml", ".docx", ".xlsx", ".vsdx", ".md"]
                .iter()
                .any(|extension| lowered.contains(extension));
        if raw_source_path || raw_source_filename {
            errors.push(format!(
                "{BUILD_SHEET_PATH}:{} exposes raw source filename detail",
                index + 1
            ));
        }
    }
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited security baseline field"
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
                    "{path} contains prohibited security baseline field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> Option<String> {
    let routes = mapget_routes(program);
    let matching: Vec<&MapRoute> = routes
        .iter()
        .filter(|route| route.route == ENDPOINT)
        .collect();
    if matching.len() != 1 {
        errors.push(format!(
            "API must expose exactly one active endpoint {ENDPOINT}"
        ));
        if matching.is_empty() {
            return None;
        }
    }
    let start = matching[0].start;
    let end = routes
        .iter()
        .find(|route| route.start > start)
        .map_or(program.len(), |route| route.start);
    Some(program[start..end].to_string())
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

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let variable_index = program.find(variable)?;
    let equals =
        program[variable_index + variable.len()..].find('=')? + variable_index + variable.len();
    let array_start = program[equals..].find('{')? + equals + 1;
    let array_end = program[array_start..].find("};")? + array_start;
    Some(csharp_string_literals(&program[array_start..array_end]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let field_index = block.find(field)?;
    let equals = block[field_index + field.len()..].find('=')? + field_index + field.len();
    let array_start = block[equals..].find('{')? + equals + 1;
    let array_end = block[array_start..].find('}')? + array_start;
    Some(csharp_string_literals(&block[array_start..array_end]))
}

fn api_rules(block: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(relative) = block[offset..].find("id") {
        let id_index = offset + relative;
        if !field_assignment_at(block, id_index, "id") {
            offset = id_index + 2;
            continue;
        }
        let object_start = block[..id_index].rfind('{').unwrap_or(id_index);
        let object_end = block[id_index..]
            .find('}')
            .map(|end| id_index + end)
            .unwrap_or(block.len());
        let object = &block[object_start..object_end];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            string_assignment_value(object, "id"),
            string_assignment_value(object, "decision"),
            string_assignment_value(object, "requirement"),
            string_assignment_value(object, "evidence"),
        ) {
            rules.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = object_end.saturating_add(1);
    }
    rules
}

fn string_assignment_value(object: &str, field: &str) -> Option<String> {
    let mut offset = 0;
    while let Some(relative) = object[offset..].find(field) {
        let index = offset + relative;
        if !field_assignment_at(object, index, field) {
            offset = index + field.len();
            continue;
        }
        let equals = object[index + field.len()..].find('=')? + index + field.len();
        let quote = skip_ascii_whitespace(object, equals + 1);
        return quoted_string_at(object, quote).map(|(value, _)| value);
    }
    None
}

fn field_assignment_at(text: &str, index: usize, field: &str) -> bool {
    if !text[index..].starts_with(field) {
        return false;
    }
    if index > 0 {
        let previous = text.as_bytes()[index - 1];
        if previous.is_ascii_alphanumeric() || previous == b'_' {
            return false;
        }
    }
    let after = index + field.len();
    if text
        .as_bytes()
        .get(after)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return false;
    }
    let equals = skip_ascii_whitespace(text, after);
    text[equal_boundary(equals, text.len())..].starts_with('=')
}

fn exactly_one_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    endpoint_assignment_count(block, field) == 1
        && exact_endpoint_assignment_count(block, field, value) == 1
}

fn exactly_one_string_assignment(block: &str, field: &str, value: &str) -> bool {
    endpoint_assignment_count(block, field) == 1
        && exact_string_assignment_count(block, field, value) == 1
}

fn endpoint_assignment_count(block: &str, field: &str) -> usize {
    assignment_fields(&csharp_code_surface(block))
        .iter()
        .filter(|candidate| candidate.as_str() == field)
        .count()
}

fn exact_endpoint_assignment_count(block: &str, field: &str, value: &str) -> usize {
    let expected = format!("{field} = {value},");
    block.lines().filter(|line| line.trim() == expected).count()
}

fn exact_string_assignment_count(block: &str, field: &str, value: &str) -> usize {
    let expected = format!("{field} = \"{value}\",");
    block.lines().filter(|line| line.trim() == expected).count()
}

fn assignment_fields(code: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let bytes = code.as_bytes();
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
            let equals = skip_ascii_whitespace(code, end);
            if code[equal_boundary(equals, code.len())..].starts_with('=') {
                fields.push(code[start..end].to_string());
            }
            continue;
        }
        index += 1;
    }
    fields
}

fn top_level_assignment_fields(code: &str) -> Vec<String> {
    let Some(results_index) = code.find("Results.Json(new") else {
        return Vec::new();
    };
    let Some(object_offset) = code[results_index..].find('{') else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    let mut depth = 0_i64;
    let mut position = results_index + object_offset;
    for line in code[position..].lines() {
        let trimmed = line.trim_start();
        if depth == 1 {
            if let Some(field) = leading_assignment_field(trimmed) {
                fields.push(field.to_string());
            }
        }
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        position += line.len() + 1;
        if depth <= 0 && position > results_index + object_offset {
            break;
        }
    }
    fields
}

fn assignment_values(code: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();
    for field in assignment_fields(code) {
        let Some(index) = code.find(&field) else {
            continue;
        };
        let after = index + field.len();
        let equals = skip_ascii_whitespace(code, after);
        if !code[equals..].starts_with('=') {
            continue;
        }
        let value_start = skip_ascii_whitespace(code, equals + 1);
        let value = code[value_start..]
            .split(|ch: char| ch == ',' || ch.is_whitespace())
            .next()
            .unwrap_or("")
            .to_string();
        values.push((field, value));
    }
    values
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < text.len() {
        let Some(relative) = text[index..].find('"') else {
            break;
        };
        let quote = index + relative;
        if let Some((value, next)) = quoted_string_at(text, quote) {
            values.push(value);
            index = next;
        } else {
            break;
        }
    }
    values
}

fn strip_csharp_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if in_string {
            result.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push(ch);
            index += 1;
            continue;
        }
        if ch == '/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                result.push(' ');
                index += 1;
            }
            continue;
        }
        if ch == '/' && bytes.get(index + 1) == Some(&b'*') {
            result.push(' ');
            result.push(' ');
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                result.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index + 1 < bytes.len() {
                result.push(' ');
                result.push(' ');
                index += 2;
            }
            continue;
        }
        result.push(ch);
        index += 1;
    }
    result
}

fn csharp_code_surface(text: &str) -> String {
    let without_comments = strip_csharp_comments(text);
    let mut result = String::with_capacity(without_comments.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in without_comments.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            result.push(if ch == '\n' { '\n' } else { ' ' });
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push(' ');
        } else {
            result.push(ch);
        }
    }
    result
}

fn quoted_string_at(text: &str, quote: usize) -> Option<(String, usize)> {
    if !text[quote..].starts_with('"') {
        return None;
    }
    let mut value = String::new();
    let mut escaped = false;
    let mut index = quote + 1;
    for (relative, ch) in text[index..].char_indices() {
        let absolute = index + relative;
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            return Some((value, absolute + 1));
        }
        value.push(ch);
    }
    index = text.len();
    Some((value, index))
}

fn markdown_section(markdown: &str, heading: &str) -> String {
    let mut capture = false;
    let mut lines = Vec::new();
    for line in markdown.lines() {
        if line == heading {
            capture = true;
            continue;
        }
        if capture && line.starts_with("## ") {
            break;
        }
        if capture {
            lines.push(line);
        }
    }
    lines.join("\n")
}

fn strip_html_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while let Some(start_relative) = text[index..].find("<!--") {
        let start = index + start_relative;
        output.push_str(&text[index..start]);
        let Some(end_relative) = text[start + 4..].find("-->") else {
            index = text.len();
            break;
        };
        index = start + 4 + end_relative + 3;
    }
    output.push_str(&text[index..]);
    output
}

fn source_input_refs(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let first_cell = trimmed.strip_prefix('|')?.split('|').next()?.trim();
            if first_cell.starts_with("source-ref-")
                && first_cell
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
            {
                Some(first_cell.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn no_secret_scan_without_signature_patterns(text: &str) -> String {
    let mut in_patterns = false;
    let mut output = String::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("patterns=(") {
            in_patterns = true;
            output.push_str("# scanner signature patterns redacted for meta-scan\n");
        } else if in_patterns && trimmed.starts_with(')') {
            in_patterns = false;
            output.push_str("# scanner signature patterns end\n");
        } else if in_patterns {
            output.push_str("# scanner signature pattern redacted\n");
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    while text
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn equal_boundary(index: usize, len: usize) -> usize {
    if index > len {
        len
    } else {
        index
    }
}

fn leading_assignment_field(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    if !bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    let mut end = 1;
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
        end += 1;
    }
    let equals = skip_ascii_whitespace(line, end);
    if line[equal_boundary(equals, line.len())..].starts_with('=') {
        Some(&line[..end])
    } else {
        None
    }
}

fn catalog_rule_values(catalog: &Value) -> Vec<&Value> {
    match catalog.get("rules") {
        Some(Value::Array(values)) => values.iter().collect(),
        Some(value) => vec![value],
        None => Vec::new(),
    }
}

fn rule_from_value(value: &Value) -> Option<Rule> {
    Some(Rule {
        id: value.get("id")?.as_str()?.to_string(),
        decision: value.get("decision")?.as_str()?.to_string(),
        requirement: value.get("requirement")?.as_str()?.to_string(),
        evidence: value.get("evidence")?.as_str()?.to_string(),
    })
}

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    match value.get(field) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(value)) => vec![value.to_string()],
        _ => Vec::new(),
    }
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn safe_text_value(value: &str) -> bool {
    REQUIRED_CONTROLS
        .iter()
        .chain(REQUIRED_VERIFICATION_GATES)
        .chain(REQUIRED_INPUTS)
        .chain(REQUIRED_GUARDS)
        .chain(REQUIRED_PLAN_SECTIONS)
        .chain(REQUIRED_BLOCKED_REASONS)
        .chain(REQUIRED_EVIDENCE)
        .chain(SAFE_TRUE_FIELDS)
        .chain(REQUIRED_DISABLED_FIELDS)
        .chain(REQUIRED_CATALOG_KEYS)
        .any(|candidate| *candidate == value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || ["draft", "static-seed", "static-security-baseline", "block"].contains(&value)
        || REQUIRED_RULES.iter().any(|rule| {
            rule.id == value
                || rule.decision == value
                || rule.requirement == value
                || rule.evidence == value
        })
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    if safe_normalized_values().contains(normalized.as_str()) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || prohibited_field_pattern(&normalized)
        || sensitive_compound_field(value)
}

fn safe_normalized_values() -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for value in REQUIRED_CONTROLS
        .iter()
        .chain(REQUIRED_VERIFICATION_GATES)
        .chain(REQUIRED_INPUTS)
        .chain(REQUIRED_GUARDS)
        .chain(REQUIRED_PLAN_SECTIONS)
        .chain(REQUIRED_BLOCKED_REASONS)
        .chain(REQUIRED_EVIDENCE)
        .chain(SAFE_TRUE_FIELDS)
        .chain(REQUIRED_DISABLED_FIELDS)
        .chain(REQUIRED_CATALOG_KEYS)
    {
        values.insert(normalize_identifier(value));
    }
    for (_, variable) in ENDPOINT_ARRAY_BINDINGS {
        values.insert(normalize_identifier(variable));
    }
    for value in ["draft", "static-seed", "static-security-baseline", "block"] {
        values.insert(normalize_identifier(value));
    }
    for rule in REQUIRED_RULES {
        values.insert(normalize_identifier(rule.id));
        values.insert(normalize_identifier(rule.decision));
        values.insert(normalize_identifier(rule.requirement));
        values.insert(normalize_identifier(rule.evidence));
    }
    values
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn prohibited_field_pattern(normalized: &str) -> bool {
    [
        "tenantidentifier",
        "tenantid",
        "objectidentifier",
        "objectid",
        "privateip",
        "credentialvalue",
        "secretvalue",
        "accesstoken",
        "token",
        "password",
        "bearer",
        "rawrequest",
        "rawprovider",
        "rawevidence",
        "rawlog",
        "recipientemail",
        "recipientaddress",
        "recipientdata",
        "stacktrace",
        "browservendor",
        "directprovider",
        "approvalbypass",
        "rbacbypass",
        "implementationinternal",
        "providerpayload",
        "endpointurl",
        "url",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    has_any(&tokens, &["password", "credential", "token", "bearer"])
        || has_any(&tokens, &["url", "uri", "endpoint", "fqdn"])
        || (has_any(&tokens, &["id", "guid"]) && tokens.len() > 1)
        || (has_any(&tokens, &["private", "ip", "host", "dns"])
            && has_any(&tokens, &["address", "name"]))
        || (has_any(
            &tokens,
            &[
                "provider",
                "tenant",
                "object",
                "recipient",
                "browser",
                "vendor",
            ],
        ) && has_any(
            &tokens,
            &[
                "name",
                "url",
                "uri",
                "endpoint",
                "id",
                "identifier",
                "key",
                "value",
                "data",
                "address",
                "payload",
                "row",
                "rows",
                "content",
            ],
        ))
        || (tokens.iter().any(|token| token == "raw")
            && has_any(
                &tokens,
                &[
                    "request",
                    "provider",
                    "evidence",
                    "log",
                    "logs",
                    "payload",
                    "rows",
                    "recipient",
                ],
            ))
        || (tokens.iter().any(|token| token == "bypass") && has_any(&tokens, &["approval", "rbac"]))
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut previous_was_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && previous_was_lower_or_digit && !current.is_empty() {
                tokens.push(current);
                current = String::new();
            }
            current.push(ch.to_ascii_lowercase());
            previous_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            if !current.is_empty() {
                tokens.push(current);
                current = String::new();
            }
            previous_was_lower_or_digit = false;
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn prohibited_value(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    contains_access_key_like(value)
        || (upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----"))
        || contains_url_scheme(value)
        || contains_private_ip(value)
        || contains_guid(value)
        || contains_jwt_like(value)
        || contains_vault_token_like(value)
        || contains_auth_assignment(value)
}

fn contains_access_key_like(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut index = 0;
    while index + 20 <= bytes.len() {
        if &bytes[index..index + 4] == b"AKIA"
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
    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    let before = &value[..scheme_end];
    let scheme_start = before
        .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '+' || ch == '.' || ch == '-'))
        .map_or(0, |index| index + 1);
    let scheme = &before[scheme_start..];
    scheme
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '.' || ch == '-')
}

fn contains_private_ip(value: &str) -> bool {
    for token in value.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        let octets: Vec<&str> = token.split('.').collect();
        if octets.len() != 4 {
            continue;
        }
        let parsed: Vec<Option<u16>> = octets.iter().map(|octet| octet.parse().ok()).collect();
        let [Some(first), Some(second), Some(third), Some(fourth)] = parsed.as_slice() else {
            continue;
        };
        if *first <= 255
            && *second <= 255
            && *third <= 255
            && *fourth <= 255
            && (*first == 10
                || (*first == 192 && *second == 168)
                || (*first == 172 && (16..=31).contains(second)))
        {
            return true;
        }
    }
    false
}

fn contains_guid(value: &str) -> bool {
    for token in value.split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-')) {
        let parts: Vec<&str> = token.split('-').collect();
        if parts.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(parts.iter())
                .all(|(length, part)| {
                    part.len() == *length && part.chars().all(|ch| ch.is_ascii_hexdigit())
                })
        {
            return true;
        }
    }
    false
}

fn contains_jwt_like(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let trimmed = token.trim_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
        });
        let parts: Vec<&str> = trimmed.split('.').collect();
        parts.len() == 3
            && parts.iter().all(|part| {
                part.len() >= 12
                    && part
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            })
    })
}

fn contains_vault_token_like(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let trimmed = token.trim_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
        });
        ["hvs.", "hvb.", "s."]
            .iter()
            .any(|prefix| trimmed.to_ascii_lowercase().starts_with(prefix))
            && trimmed.len() >= 18
    })
}

fn contains_auth_assignment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    for term in [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ] {
        let mut offset = 0;
        while let Some(relative) = lower[offset..].find(term) {
            let start = offset + relative + term.len();
            let after = skip_ascii_whitespace(&lower, start);
            if lower[after..].starts_with(':') || lower[after..].starts_with('=') {
                let value_start = skip_ascii_whitespace(&lower, after + 1);
                if lower
                    .as_bytes()
                    .get(value_start)
                    .is_some_and(|byte| !byte.is_ascii_whitespace())
                {
                    return true;
                }
            }
            offset = start;
        }
    }
    false
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|extension| path.ends_with(extension))
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
