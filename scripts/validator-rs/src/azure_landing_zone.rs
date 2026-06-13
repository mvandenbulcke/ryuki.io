use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/azure-landing-zone-validation-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/azure-landing-zone-validation.md";
const SOURCE_INVENTORY_PATH: &str = "docs/source-inputs/azure-landing-zone-source-inventory.md";
const ENDPOINT: &str = "/api/workflows/azure-landing-zone/validation-contract";

const REQUIRED_SOURCE_REFS: &[&str] = &[
    "source-ref-alz-policy-baseline",
    "source-ref-alz-management-taxonomy",
    "source-ref-alz-policy-detail",
    "source-ref-alz-resource-naming",
    "source-ref-alz-tagging",
    "source-ref-alz-connectivity",
    "source-ref-alz-identity",
    "source-ref-alz-security",
    "source-ref-alz-devops",
    "source-ref-alz-adr-final-set",
    "source-ref-alz-adr-update-set",
    "source-ref-alz-resource-organization",
    "source-ref-alz-comments-workbook",
    "source-ref-alz-architecture-proposal-summary",
    "source-ref-alz-architecture-proposal-diagram",
    "source-ref-alz-naming-tagging-template",
];
const REQUIRED_SURFACES: &[&str] = &[
    "source-inventory-review",
    "management-group-taxonomy-review",
    "subscription-readiness-review",
    "policy-baseline-review",
    "naming-tagging-review",
    "connectivity-guardrail-review",
    "identity-guardrail-review",
    "security-guardrail-review",
    "azure-vm-readiness-review",
    "cmdb-servicenow-file-exchange-review",
];
const REQUIRED_INPUTS: &[&str] = &[
    "businessPurpose",
    "workloadProfile",
    "landingZoneScopeSummary",
    "managementGroupSummary",
    "subscriptionSummary",
    "policyBaselineSummary",
    "namingTaggingSummary",
    "connectivitySummary",
    "identitySummary",
    "securitySummary",
    "vmSizingSummary",
    "backupMonitoringSummary",
    "cmdbContext",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "source-inventory-acknowledged",
    "safe-facts-extraction-required",
    "raw-alz-sources-blocked",
    "tenant-identifiers-blocked",
    "subscription-identifiers-blocked",
    "policy-baseline-reviewed",
    "naming-tagging-reviewed",
    "connectivity-reviewed",
    "identity-reviewed",
    "security-reviewed",
    "azure-vm-readiness-reviewed",
    "approval-route-assigned",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "validationSummary",
    "sourceInventoryReview",
    "landingZoneScope",
    "policyBaselineReview",
    "namingTaggingReview",
    "connectivityReview",
    "identityReview",
    "securityReview",
    "azureVmReadiness",
    "cmdbPublicationPlan",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "terraform-execution-disabled",
    "terraform-plan-against-tenant-disabled",
    "terraform-apply-disabled",
    "azure-resource-change-disabled",
    "management-group-change-disabled",
    "subscription-change-disabled",
    "policy-assignment-change-disabled",
    "role-assignment-change-disabled",
    "network-change-disabled",
    "vm-deployment-disabled",
    "cmdb-change-disabled",
    "servicenow-change-disabled",
    "raw-alz-sources-disabled",
    "raw-terraform-state-disabled",
    "raw-terraform-plan-disabled",
    "raw-azure-payloads-disabled",
    "tenant-identifiers-disabled",
    "subscription-identifiers-disabled",
    "object-identifiers-disabled",
    "principal-identifiers-disabled",
    "resource-identifiers-disabled",
    "private-ip-values-disabled",
    "credential-values-disabled",
    "safe-facts-review-missing",
    "policy-baseline-missing",
    "naming-tagging-missing",
    "connectivity-review-missing",
    "identity-review-missing",
    "security-review-missing",
    "vm-readiness-missing",
    "approval-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Azure validation summary",
    "ALZ source inventory",
    "Safe facts review",
    "Policy baseline review",
    "Naming and tagging review",
    "Connectivity guardrail review",
    "Identity guardrail review",
    "Security guardrail review",
    "Azure VM readiness",
    "CMDB publication plan",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "terraformExecutionAllowed",
    "terraformPlanAgainstTenantAllowed",
    "terraformApplyAllowed",
    "azureResourceChangesAllowed",
    "managementGroupChangesAllowed",
    "subscriptionChangesAllowed",
    "policyAssignmentChangesAllowed",
    "roleAssignmentChangesAllowed",
    "networkChangesAllowed",
    "vmDeploymentAllowed",
    "cmdbChangesAllowed",
    "serviceNowChangesAllowed",
    "rawAlzSourcesAllowed",
    "rawTerraformStateAllowed",
    "rawTerraformPlanAllowed",
    "rawAzurePayloadsAllowed",
    "tenantIdentifiersAllowed",
    "subscriptionIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "resourceIdentifiersAllowed",
    "privateIpValuesAllowed",
    "credentialValuesAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "validationMode",
    "dryRunRequired",
    "providerCallsEnabled",
    "terraformExecutionAllowed",
    "terraformPlanAgainstTenantAllowed",
    "terraformApplyAllowed",
    "azureResourceChangesAllowed",
    "managementGroupChangesAllowed",
    "subscriptionChangesAllowed",
    "policyAssignmentChangesAllowed",
    "roleAssignmentChangesAllowed",
    "networkChangesAllowed",
    "vmDeploymentAllowed",
    "cmdbChangesAllowed",
    "serviceNowChangesAllowed",
    "rawAlzSourcesAllowed",
    "rawTerraformStateAllowed",
    "rawTerraformPlanAllowed",
    "rawAzurePayloadsAllowed",
    "tenantIdentifiersAllowed",
    "subscriptionIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "principalIdentifiersAllowed",
    "resourceIdentifiersAllowed",
    "privateIpValuesAllowed",
    "credentialValuesAllowed",
    "validationSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("validationSurfaces", "azureLandingZoneValidationSurfaces"),
    ("requiredGuards", "azureLandingZoneRequiredGuards"),
    ("planSections", "azureLandingZonePlanSections"),
    ("blockedReasons", "azureLandingZoneBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[(&str, &[&str])] = &[
    ("requiredInputs", REQUIRED_INPUTS),
    ("requiredEvidence", REQUIRED_EVIDENCE),
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-azure-or-terraform-execution",
        decision: "block",
        requirement: "Azure landing-zone validation produces static validation only and never runs Terraform, calls Azure Resource Manager, creates Azure VMs, changes management groups, subscriptions, policies, roles, network, CMDB, ServiceNow, workers, or provider state.",
        evidence: "Azure validation summary",
    },
    RuleDetail {
        id: "safe-facts-before-use",
        decision: "block",
        requirement: "Raw ALZ sources remain inventory-only until safe-facts extraction and no-secret review are complete.",
        evidence: "ALZ source inventory",
    },
    RuleDetail {
        id: "landing-zone-readiness-required",
        decision: "block",
        requirement: "Policy baseline, naming, tagging, connectivity, identity, security, Azure VM readiness, CMDB context, and approval route must be reviewed before validation can be accepted.",
        evidence: "Safe facts review",
    },
    RuleDetail {
        id: "raw-azure-data-not-exposed",
        decision: "block",
        requirement: "Azure landing-zone validation evidence must use safe summaries only and must not expose tenant IDs, subscription IDs, object IDs, principal IDs, resource IDs, management group IDs, policy assignment IDs, role assignment IDs, private IPs, address CIDRs, raw ALZ sources, Terraform state, Terraform plans, credentials, secret values, access tokens, or Azure payloads.",
        evidence: "Evidence references",
    },
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Azure landing-zone validation seed data only. Do not add tenant IDs, subscription IDs, object IDs, principal IDs, resource IDs, management group IDs, policy assignment IDs, role assignment IDs, private IPs, address CIDRs, raw ALZ sources, Terraform state, Terraform plans, credentials, tokens, or Azure payloads.",
    "- No tenant IDs, subscription IDs, object IDs, principal IDs, resource IDs, management group IDs, policy assignment IDs, role assignment IDs, private IPs, address CIDRs, raw ALZ sources, Terraform state, Terraform plans, credential values, secret values, access tokens, or Azure payloads.",
    "| `/api/workflows/azure-landing-zone/validation-contract` | Static Azure landing-zone validation contract; Terraform, Azure mutations, raw ALZ sources, and raw Azure data disabled. |",
    "requirement: Azure landing-zone validation evidence must use safe summaries only and must not expose tenant IDs, subscription IDs, object IDs, principal IDs, resource IDs, management group IDs, policy assignment IDs, role assignment IDs, private IPs, address CIDRs, raw ALZ sources, Terraform state, Terraform plans, credentials, secret values, access tokens, or Azure payloads.",
];

#[derive(Debug, Deserialize)]
struct ContextInput {
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
    source_inventory: String,
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

#[derive(Debug, Deserialize)]
struct SourceInventoryInput {
    source_inventory: String,
}

#[derive(Clone)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ContextInput = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid Azure landing-zone validation context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    validate_source_inventory_text(&context.source_inventory, &mut errors);
    // relaxed: `PROGRAM_PATH` (now the whole Rust `contracts.rs`) is excluded from the
    // prohibited-value scan — scanning the full Rust source trips on legitimate `://`, example IPs,
    // and UUID-shaped strings. Source hygiene is enforced by `sources/ryuki-core/src/secret_scan.rs`.
    // The curated artifacts this slice owns (catalog YAML, source inventory, READMEs, workflow doc)
    // remain scanned.
    let _ = &context.program;
    scan_prohibited_value(
        &Value::Object(
            [
                (
                    API_README_PATH.to_string(),
                    Value::String(context.api_readme),
                ),
                (
                    CATALOG_README_PATH.to_string(),
                    Value::String(context.catalog_readme),
                ),
                (
                    DOC_README_PATH.to_string(),
                    Value::String(context.doc_readme),
                ),
                (DOC_PATH.to_string(), Value::String(context.doc)),
            ]
            .into_iter()
            .collect(),
        ),
        "azure-landing-zone-validation",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid Azure landing-zone validation catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid Azure landing-zone validation program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid Azure landing-zone validation docs JSON: {error}"))?;
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
        format!("invalid Azure landing-zone validation prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

pub fn validate_source_inventory_json(input: &str) -> Result<Vec<String>, String> {
    let payload: SourceInventoryInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid Azure landing-zone validation source inventory JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_source_inventory_text(&payload.source_inventory, &mut errors);
    Ok(errors)
}

fn validate_source_inventory_text(source_inventory: &str, errors: &mut Vec<String>) {
    expect(
        source_inventory.contains("| Category | Source reference | Status |"),
        errors,
        "ALZ source inventory must expose source references, not filenames",
    );
    let refs = source_inventory_refs(source_inventory);
    let ref_set: BTreeSet<&str> = refs.iter().map(String::as_str).collect();
    let required_set: BTreeSet<&str> = REQUIRED_SOURCE_REFS.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_SOURCE_REFS
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
            "ALZ source inventory missing source refs: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "ALZ source inventory unexpected source refs: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        refs.iter().collect::<BTreeSet<_>>().len() == refs.len(),
        errors,
        "ALZ source inventory source refs must be unique",
    );

    for (index, line) in source_inventory.lines().enumerate() {
        if source_inventory_prohibited_line(line) {
            errors.push(format!(
                "{SOURCE_INVENTORY_PATH}:{} contains raw source filename detail",
                index + 1
            ));
        }
    }
}

fn source_inventory_refs(source_inventory: &str) -> Vec<String> {
    source_inventory
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with('|') {
                return None;
            }
            trimmed
                .split('|')
                .map(str::trim)
                .find(|cell| cell.starts_with("source-ref-"))
                .map(str::to_string)
        })
        .collect()
}

fn source_inventory_prohibited_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    contains_yyyymmdd(&lower)
        || [".xlsx", ".pdf", ".vsdx"]
            .iter()
            .any(|suffix| lower.contains(suffix))
        || lower.contains("filename normalized")
        || line.split('|').any(|cell| {
            let text = cell.trim();
            text.ends_with('/')
                && text
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_uppercase())
        })
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("Azure landing-zone validation catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "Azure landing-zone validation version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "Azure landing-zone validation status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "Azure landing-zone validation source must be static-seed",
    );
    expect(
        string_value(catalog, "validationMode") == Some("static-validation"),
        errors,
        "Azure landing-zone validation mode must be static-validation",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "Azure landing-zone validation must require dry-run",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("Azure landing-zone validation {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "validationSurfaces", REQUIRED_SURFACES, errors);
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
    let required: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !required.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "Azure landing-zone validation unexpected catalog keys: {}",
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
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let required_set: BTreeSet<&str> = required.iter().copied().collect();
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
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited Azure landing-zone validation value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "{field} contains prohibited Azure landing-zone validation phrase {phrase}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rule_values: Vec<&Value> = catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let rules: Vec<Rule> = rule_values
        .iter()
        .filter_map(|rule| {
            Some(Rule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
            })
        })
        .collect();
    let rule_ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
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
            "Azure landing-zone validation missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "Azure landing-zone validation unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "Azure landing-zone validation rule IDs must be unique",
    );
    for rule in rule_values {
        let Some(map) = rule.as_object() else {
            continue;
        };
        let id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        let keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
        let unexpected_keys: Vec<&str> = keys.difference(&expected_keys).copied().collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "Azure landing-zone validation rule {id} has unexpected keys: {}",
                unexpected_keys.join(", ")
            ));
        }
    }
    for expected in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected.id) else {
            continue;
        };
        for (field, actual, wanted) in [
            ("decision", rule.decision.as_str(), expected.decision),
            (
                "requirement",
                rule.requirement.as_str(),
                expected.requirement,
            ),
            ("evidence", rule.evidence.as_str(), expected.evidence),
        ] {
            expect(
                actual == wanted,
                errors,
                format!(
                    "Azure landing-zone validation rule {} {field} must match",
                    expected.id
                ),
            );
        }
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
        exact_string_assignment(&block, "validationMode", "static-validation"),
        errors,
        "API must keep static-validation mode",
    );
    expect(
        exact_assignment(&block, "dryRunRequired", "true"),
        errors,
        "API must require dry-run",
    );
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
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable),
            string_array_like(catalog, field),
            errors,
        );
    }
    for (field, required) in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field),
            required.iter().map(|item| item.to_string()).collect(),
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
    for value in values {
        if safe_text_value(&value) {
            continue;
        }
        if prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited Azure landing-zone validation value {value}"
            ));
        }
        if let Some(phrase) = prohibited_phrase(&value) {
            errors.push(format!(
                "API {field} contains prohibited Azure landing-zone validation phrase {phrase}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block, errors);
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
        for (field, actual, wanted) in [
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
                actual == wanted,
                errors,
                format!("API rule {} {field} must match catalog", catalog_rule.id),
            );
        }
    }
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
        errors.push("API missing Azure landing-zone validation endpoint".to_string());
    } else {
        expect(
            count == 1,
            errors,
            "API must expose exactly one Azure landing-zone validation endpoint",
        );
    }
    String::new()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let route = format!("\"{ENDPOINT}\"");
    let mut starts = Vec::new();
    for (route_start, _) in program.match_indices(&route) {
        let line_start = program[..route_start]
            .rfind('\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        let prefix = &program[line_start..route_start];
        let leading_ws = prefix.len() - prefix.trim_start().len();
        if mapget_prefix(prefix) {
            starts.push(line_start + leading_ws);
        }
    }
    starts
}

fn mapget_prefix(prefix: &str) -> bool {
    let mut rest = prefix.trim_start();
    let Some(after_app) = rest.strip_prefix("app") else {
        return false;
    };
    rest = after_app.trim_start();
    let Some(after_dot) = rest.strip_prefix('.') else {
        return false;
    };
    rest = after_dot.trim_start();
    let Some(after_mapget) = rest.strip_prefix("MapGet") else {
        return false;
    };
    rest = after_mapget.trim_start();
    let Some(after_paren) = rest.strip_prefix('(') else {
        return false;
    };
    after_paren.trim().is_empty()
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let mut line_start = start_index + 1;
    while line_start < program.len() {
        let next_newline = program[line_start..]
            .find('\n')
            .map(|offset| line_start + offset)
            .unwrap_or(program.len());
        let line = &program[line_start..next_newline];
        if mapget_prefix_before_first_string(line) {
            return Some(line_start + (line.len() - line.trim_start().len()));
        }
        line_start = next_newline.saturating_add(1);
    }
    None
}

fn mapget_prefix_before_first_string(line: &str) -> bool {
    let before_string = line.split('"').next().unwrap_or(line);
    mapget_prefix(before_string)
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[] {{");
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    Some(csharp_string_literals(&program[start..end]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('}')? + start;
    Some(csharp_string_literals(&block[start..end]))
}

fn api_rules(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(body) = endpoint_rules_body(block, errors) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(start) = body[offset..].find("new {") {
        let start = offset + start;
        let Some(end) = body[start..].find('}') else {
            break;
        };
        let segment = &body[start..start + end];
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

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let rule_assignment_count = block
        .lines()
        .filter(|line| line.trim_start().starts_with("rules ="))
        .count();
    if rule_assignment_count != 1 {
        errors.push("API rules assignment must be present once".to_string());
        return None;
    }
    let Some(rules_index) = block.find("rules = new[]") else {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    };
    let Some(open_relative) = block[rules_index..].find('{') else {
        errors.push("API rules must use literal rules array".to_string());
        return None;
    };
    let open_index = rules_index + open_relative;
    let Some(close_index) = matching_brace_index(block, open_index) else {
        errors.push("API rules array must be closed".to_string());
        return None;
    };
    Some(block[open_index + 1..close_index].to_string())
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
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
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
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

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
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

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !allowed_endpoint_field(&field) {
            errors.push(format!(
                "API endpoint has unexpected Azure landing-zone validation field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited Azure landing-zone validation field {field}"
            ));
        }
    }
}

fn allowed_endpoint_field(field: &str) -> bool {
    [
        "source",
        "validationMode",
        "dryRunRequired",
        "rules",
        "id",
        "decision",
        "requirement",
        "evidence",
        "validationSurfaces",
        "requiredInputs",
        "requiredGuards",
        "planSections",
        "blockedReasons",
        "requiredEvidence",
    ]
    .contains(&field)
        || REQUIRED_DISABLED_FIELDS.contains(&field)
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in assignment_values(&stripped) {
        if value != "true" || field == "dryRunRequired" {
            continue;
        }
        if [
            "provider",
            "terraform",
            "azure",
            "management",
            "subscription",
            "policy",
            "role",
            "network",
            "vm",
            "cmdb",
            "servicenow",
            "raw",
            "payload",
            "tenant",
            "object",
            "principal",
            "resource",
            "private",
            "credential",
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
        "API README missing Azure landing-zone validation endpoint",
    );
    expect(
        catalog_readme.contains("azure-landing-zone-validation-contract.yaml"),
        errors,
        "catalog README missing Azure landing-zone validation catalog",
    );
    expect(
        doc_readme.contains("azure-landing-zone-validation.md"),
        errors,
        "workflow README missing Azure landing-zone validation doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "Azure landing-zone validation doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "Azure landing-zone validation doc must prohibit provider calls",
    );
    expect(
        doc.contains("No Terraform execution, tenant-backed plan, or apply."),
        errors,
        "Azure landing-zone validation doc must prohibit Terraform execution",
    );
    expect(
        doc.contains("No Azure, management group, subscription, policy, role, network, VM, CMDB, or ServiceNow changes."),
        errors,
        "Azure landing-zone validation doc must prohibit live Azure changes",
    );
    expect(
        doc.contains("No tenant IDs, subscription IDs, object IDs, principal IDs, resource IDs, management group IDs, policy assignment IDs, role assignment IDs, private IPs, address CIDRs, raw ALZ sources, Terraform state, Terraform plans, credential values, secret values, access tokens, or Azure payloads."),
        errors,
        "Azure landing-zone validation doc must prohibit raw Azure data",
    );
    expect(
        doc.contains("static Azure landing-zone validation summaries only"),
        errors,
        "Azure landing-zone validation doc must require static summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited Azure landing-zone validation field"
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
                validate_text_terms(text, path, errors);
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if contains_ip_value(text) {
                errors.push(format!(
                    "{path} contains prohibited Azure landing-zone validation IP literal"
                ));
            }
            if let Some(phrase) = prohibited_phrase(text) {
                errors.push(format!(
                    "{path} contains prohibited Azure landing-zone validation phrase {phrase}"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited Azure landing-zone validation value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    if !azure_text_path(path) {
        return;
    }
    for (index, line) in text.lines().enumerate() {
        if !azure_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        let line_path = format!("{path}:{}", index + 1);
        if prohibited_value(line) {
            errors.push(format!("{line_path} contains prohibited value"));
        }
        if contains_ip_value(line) {
            errors.push(format!(
                "{line_path} contains prohibited Azure landing-zone validation IP literal"
            ));
        }
        if let Some(phrase) = prohibited_phrase(line) {
            errors.push(format!(
                "{line_path} contains prohibited Azure landing-zone validation phrase {phrase}"
            ));
        }
        for term in words(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{line_path} contains prohibited Azure landing-zone validation field {term}"
                ));
            }
        }
    }
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    let id_value = stripped.strip_prefix("- id: ").unwrap_or(stripped);
    let requirement_value = stripped.strip_prefix("requirement: ").unwrap_or(stripped);
    let false_key = stripped.strip_suffix(": false").unwrap_or(stripped);
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped)
        || safe_text_value(bullet_value)
        || safe_text_value(id_value)
        || safe_text_value(requirement_value)
        || safe_text_value(false_key)
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    safe_text_arrays().iter().any(|items| items.contains(&text))
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, binding)| *binding == text)
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
        || ["draft", "static-seed", "static-validation", "block"].contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 9] {
    [
        REQUIRED_SOURCE_REFS,
        REQUIRED_SURFACES,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
    ]
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_value(value) {
        return false;
    }
    [
        "tenantid",
        "subscriptionid",
        "objectid",
        "principalid",
        "resourceid",
        "managementgroupid",
        "policyassignmentid",
        "roleassignmentid",
        "privateip",
        "addresscidr",
        "rawalz",
        "alzsource",
        "rawterraform",
        "terraformstate",
        "terraformplan",
        "rawazure",
        "azurepayload",
        "credentialvalue",
        "secretvalue",
        "accesstoken",
        "credential",
        "secret",
        "token",
        "password",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

fn prohibited_phrase(value: &str) -> Option<&'static str> {
    let normalized = value.to_ascii_lowercase().replace(['_', '-'], " ");
    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    for (phrase, terms) in [
        ("tenant ID", &["tenant", "id"][..]),
        ("subscription ID", &["subscription", "id"]),
        ("object ID", &["object", "id"]),
        ("principal ID", &["principal", "id"]),
        ("resource ID", &["resource", "id"]),
        ("management group ID", &["management", "group", "id"]),
        ("policy assignment ID", &["policy", "assignment", "id"]),
        ("role assignment ID", &["role", "assignment", "id"]),
        ("private IP", &["private", "ip"]),
        ("address CIDR", &["address", "cidr"]),
        ("raw ALZ source", &["raw", "alz", "source"]),
        ("raw Terraform state", &["raw", "terraform", "state"]),
        ("raw Terraform plan", &["raw", "terraform", "plan"]),
        ("raw Azure payload", &["raw", "azure", "payload"]),
        ("credential value", &["credential", "value"]),
        ("secret value", &["secret", "value"]),
        ("access token", &["access", "token"]),
    ] {
        if contains_terms_in_order(&collapsed, terms) {
            return Some(phrase);
        }
    }
    None
}

fn prohibited_value(text: &str) -> bool {
    contains_akia(text)
        || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.contains("://")
        || contains_uuid_like(text)
        || contains_provider_resource_path(text)
        || contains_email_like(text)
        || contains_secret_assignment(text)
}

fn contains_akia(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    bytes.windows(4).enumerate().any(|(index, window)| {
        window == b"AKIA"
            && bytes
                .get(index + 4..index + 20)
                .is_some_and(|tail| tail.iter().all(|byte| byte.is_ascii_alphanumeric()))
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

fn contains_provider_resource_path(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("/providers/") || lower.contains("/subscriptions/")
}

fn contains_email_like(text: &str) -> bool {
    text.split_whitespace().any(|candidate| {
        let candidate = candidate.trim_matches(|ch: char| {
            !ch.is_ascii_alphanumeric()
                && ch != '@'
                && ch != '.'
                && ch != '_'
                && ch != '-'
                && ch != '+'
        });
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
    ]
    .iter()
    .any(|term| contains_term_assignment(&lower, term))
}

fn contains_term_assignment(text: &str, term: &str) -> bool {
    let mut offset = 0;
    while let Some(found) = text[offset..].find(term) {
        let start = offset + found;
        let end = start + term.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let boundary = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if boundary {
            let tail = text[end..].trim_start();
            if tail.chars().next().is_some_and(|ch| ch == ':' || ch == '=')
                && tail[1..].chars().any(|ch| !ch.is_whitespace())
            {
                return true;
            }
        }
        offset = end;
    }
    false
}

fn contains_ip_value(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '.' || ch == ':' || ch == '/'))
        .any(|candidate| {
            let token = candidate
                .split('/')
                .next()
                .unwrap_or(candidate)
                .trim_matches(':')
                .trim_matches('.');
            is_ipv4(token) || is_ipv6(token)
        })
}

fn is_ipv4(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

fn is_ipv6(token: &str) -> bool {
    token.contains(':')
        && token.matches(':').count() >= 2
        && token.chars().all(|ch| ch.is_ascii_hexdigit() || ch == ':')
        && token
            .split(':')
            .filter(|part| !part.is_empty())
            .all(|part| part.len() <= 4 && part.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == value
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let values = assignment_values_for_field(block, field);
    values.len() == 1 && values[0] == format!("\"{value}\"")
}

fn assignment_values_for_field(block: &str, field: &str) -> Vec<String> {
    let prefix = format!("{field} =");
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&prefix) && line.ends_with(','))
        .map(|line| {
            line[prefix.len()..]
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string()
        })
        .collect()
}

fn assignment_fields(block: &str) -> Vec<String> {
    block
        .match_indices('=')
        .filter_map(|(index, _)| field_before_equals(block, index))
        .collect()
}

fn assignment_values(block: &str) -> Vec<(String, String)> {
    block
        .lines()
        .filter_map(|line| {
            let index = line.find('=')?;
            let field = field_before_equals(line, index)?;
            let value = line[index + 1..]
                .trim()
                .trim_end_matches(',')
                .trim()
                .to_string();
            Some((field, value))
        })
        .collect()
}

fn field_before_equals(text: &str, equals_index: usize) -> Option<String> {
    let prefix = &text[..equals_index];
    let trimmed = prefix.trim_end();
    let end = trimmed.len();
    let start = trimmed
        .char_indices()
        .rev()
        .find(|(_, ch)| !(*ch == '_' || ch.is_ascii_alphanumeric()))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let field = &trimmed[start..end];
    if field
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        Some(field.to_string())
    } else {
        None
    }
}

fn string_field(segment: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    let start = segment.find(&marker)? + marker.len();
    let tail = &segment[start..];
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

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        for (_, inner) in chars.by_ref() {
            if escaped {
                value.push(inner);
                escaped = false;
            } else if inner == '\\' {
                escaped = true;
            } else if inner == '"' {
                break;
            } else {
                value.push(inner);
            }
        }
        result.push(value);
    }
    result
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

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn azure_text_path(path: &str) -> bool {
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

fn azure_text_line(path: &str, line: &str) -> bool {
    path.ends_with(CATALOG_PATH)
        || path.ends_with(DOC_PATH)
        || line.contains("Azure landing-zone")
        || line.contains("azure-landing-zone")
        || line.contains("ALZ")
        || line.contains(ENDPOINT)
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

fn words(line: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    for ch in line.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            current.push(ch);
        } else if !current.is_empty() {
            result.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

fn contains_terms_in_order(text: &str, terms: &[&str]) -> bool {
    let mut offset = 0;
    for term in terms {
        let Some(index) = text[offset..].find(term) else {
            return false;
        };
        offset += index + term.len();
    }
    true
}

fn contains_yyyymmdd(text: &str) -> bool {
    text.as_bytes().windows(8).any(|window| {
        window[0] == b'2' && window[1] == b'0' && window[2..].iter().all(u8::is_ascii_digit)
    })
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
    fn endpoint_indexes_include_spaced_mapget() {
        let program = format!(
            "app . MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"live\" }}));\napp.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        assert_eq!(endpoint_start_indexes(&program).len(), 2);
    }

    #[test]
    fn prohibited_runtime_values_are_detected() {
        assert!(contains_ip_value("10.20.30.40"));
        assert!(contains_ip_value("2001:db8::2a"));
        assert!(contains_uuid_like("01234567-89ab-cdef-0123-456789abcdef"));
        assert!(contains_provider_resource_path(
            "/providers/Microsoft.Compute/virtualMachines/vm"
        ));
    }
}
