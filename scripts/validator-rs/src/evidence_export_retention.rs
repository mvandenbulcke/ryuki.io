use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/evidence-export-retention-contract.yaml";
const MANIFEST_CATALOG_PATH: &str = "catalog/evidence-manifest-catalog.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/evidence-export-retention.md";
const ENDPOINT: &str = "/api/evidence/export-retention-contract";
const REQUIRED_REDACTION_STATES: &[&str] = &["pending", "redacted", "blocked"];
const REQUIRED_EXPORT_READINESS: &[&str] = &[
    "draft",
    "redaction-pending",
    "ready-for-audit",
    "ready-for-cab",
    "ready-for-incident-review",
    "ready-for-handover",
    "blocked",
];
const REQUIRED_EXPORT_TARGETS: &[&str] = &[
    "audit-review",
    "cab-review",
    "incident-review",
    "handover",
    "cmdb-file-exchange",
];
const REQUIRED_PROHIBITED_CONTENT: &[&str] = &[
    "credential values",
    "bearer material",
    "private key material",
    "generated certificates",
    "Vault initialization material",
    "raw provider payloads",
    "unfiltered logs",
    "stack traces",
    "tenant identifiers",
    "object identifiers",
    "private network addresses",
    "raw recipient data",
    "raw rows",
    "serial numbers",
];
const REQUIRED_RETENTION_CLASSES: &[&str] = &[
    "operational-review",
    "audit-retained",
    "cab-retained",
    "incident-retained",
    "handover-retained",
    "cmdb-exchange-retained",
];
const REQUIRED_AUDIT_SEARCH_STATES: &[&str] = &[
    "query-draft",
    "redaction-filtered",
    "metadata-only",
    "ready-for-review",
    "blocked",
];
const REQUIRED_SEARCH_FACETS: &[&str] = &[
    "workflow-family",
    "redaction-state",
    "export-readiness",
    "retention-class",
    "record-type",
    "review-state",
    "created-bucket",
];
const REQUIRED_PACKAGE_FIELDS: &[&str] = &[
    "packageReference",
    "workflowFamily",
    "redactionState",
    "exportReadiness",
    "retentionClass",
    "recordTypes",
    "safeExportTarget",
    "reviewState",
    "createdBucket",
    "evidenceReferences",
];
const REQUIRED_GUARDS: &[&str] = &[
    "redaction-state-redacted",
    "export-readiness-approved",
    "retention-class-assigned",
    "metadata-only-search",
    "no-raw-payloads",
    "recipient-data-redacted",
    "provider-payloads-blocked",
    "retention-review-recorded",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Export package summary",
    "Redaction state review",
    "Retention class decision",
    "Audit search scope summary",
    "Prohibited content review",
    "Evidence references",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-evidence-mutation-disabled",
    "export-package-mutation-disabled",
    "retention-policy-mutation-disabled",
    "live-audit-search-disabled",
    "audit-search-query-disabled",
    "evidence-payloads-disabled",
    "raw-request-payloads-disabled",
    "raw-provider-payloads-disabled",
    "raw-evidence-payloads-disabled",
    "raw-log-content-disabled",
    "unfiltered-logs-disabled",
    "stack-traces-disabled",
    "raw-rows-disabled",
    "serial-numbers-disabled",
    "export-without-redaction-disabled",
    "credential-values-disabled",
    "secret-values-disabled",
    "token-values-disabled",
    "tenant-identifiers-disabled",
    "object-identifiers-disabled",
    "private-network-values-disabled",
    "raw-recipient-data-disabled",
    "retention-class-missing",
    "metadata-only-search-missing",
    "redaction-review-missing",
];
const SAFE_TRUE_FIELDS: &[&str] = &[
    "exportIndexReadOnly",
    "retentionPolicyReadOnly",
    "auditSearchReadOnly",
    "redactionRequired",
    "metadataOnlySearchRequired",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsAllowed",
    "liveEvidenceMutationAllowed",
    "exportPackageMutationAllowed",
    "retentionPolicyMutationAllowed",
    "liveAuditSearchAllowed",
    "auditSearchQueryAllowed",
    "evidencePayloadsAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawLogContentAllowed",
    "unfilteredLogsAllowed",
    "stackTracesAllowed",
    "rawRowsAllowed",
    "serialNumbersAllowed",
    "exportWithoutRedactionAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "rawRecipientDataAllowed",
];
const CATALOG_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "exportRetentionMode",
    "manifestCatalog",
    "redactionStates",
    "exportReadiness",
    "safeExportTargets",
    "prohibitedContent",
    "retentionClasses",
    "auditSearchStates",
    "searchFacets",
    "safeExportPackageFields",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "exportIndexReadOnly",
    "retentionPolicyReadOnly",
    "auditSearchReadOnly",
    "redactionRequired",
    "metadataOnlySearchRequired",
    "providerCallsAllowed",
    "liveEvidenceMutationAllowed",
    "exportPackageMutationAllowed",
    "retentionPolicyMutationAllowed",
    "liveAuditSearchAllowed",
    "auditSearchQueryAllowed",
    "evidencePayloadsAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawLogContentAllowed",
    "unfilteredLogsAllowed",
    "stackTracesAllowed",
    "rawRowsAllowed",
    "serialNumbersAllowed",
    "exportWithoutRedactionAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "rawRecipientDataAllowed",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("redactionStates", "evidenceExportRetentionRedactionStates"),
    ("exportReadiness", "evidenceExportRetentionReadiness"),
    ("safeExportTargets", "evidenceExportRetentionTargets"),
    (
        "prohibitedContent",
        "evidenceExportRetentionProhibitedContent",
    ),
    ("retentionClasses", "evidenceExportRetentionClasses"),
    (
        "auditSearchStates",
        "evidenceExportRetentionAuditSearchStates",
    ),
    ("searchFacets", "evidenceExportRetentionSearchFacets"),
    (
        "safeExportPackageFields",
        "evidenceExportRetentionPackageFields",
    ),
    ("requiredGuards", "evidenceExportRetentionRequiredGuards"),
    ("blockedReasons", "evidenceExportRetentionBlockedReasons"),
    (
        "requiredEvidence",
        "evidenceExportRetentionRequiredEvidence",
    ),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "exportRetentionMode",
    "manifestCatalog",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "exportIndexReadOnly",
    "retentionPolicyReadOnly",
    "auditSearchReadOnly",
    "redactionRequired",
    "metadataOnlySearchRequired",
    "providerCallsAllowed",
    "liveEvidenceMutationAllowed",
    "exportPackageMutationAllowed",
    "retentionPolicyMutationAllowed",
    "liveAuditSearchAllowed",
    "auditSearchQueryAllowed",
    "evidencePayloadsAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawLogContentAllowed",
    "unfilteredLogsAllowed",
    "stackTracesAllowed",
    "rawRowsAllowed",
    "serialNumbersAllowed",
    "exportWithoutRedactionAllowed",
    "credentialValuesAllowed",
    "secretValuesAllowed",
    "tokenValuesAllowed",
    "tenantIdentifiersAllowed",
    "objectIdentifiersAllowed",
    "privateNetworkValuesAllowed",
    "rawRecipientDataAllowed",
    "redactionStates",
    "exportReadiness",
    "safeExportTargets",
    "prohibitedContent",
    "retentionClasses",
    "auditSearchStates",
    "searchFacets",
    "safeExportPackageFields",
    "requiredGuards",
    "blockedReasons",
    "requiredEvidence",
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
        id: "redacted-export-package-required",
        decision: "block",
        requirement: "Evidence export packages require redacted state, export readiness, safe export target, retention class, and evidence references before audit, CAB, incident, handover, or CMDB file exchange use.",
        evidence: "Export package summary",
    },
    RuleDetail {
        id: "retention-policy-review-required",
        decision: "block",
        requirement: "Retention class, retention review state, expiry posture, and legal hold interaction must be summarized before retained evidence packages can be accepted.",
        evidence: "Retention class decision",
    },
    RuleDetail {
        id: "audit-search-metadata-only",
        decision: "block",
        requirement: "Audit search exposes metadata-only package summaries and never queries live providers, raw evidence payloads, raw logs, recipient data, identifiers, or provider payloads.",
        evidence: "Audit search scope summary",
    },
    RuleDetail {
        id: "raw-evidence-export-data-not-exposed",
        decision: "block",
        requirement: "Evidence export and retention views must use safe summaries only and must not expose raw request payloads, raw provider payloads, raw evidence payloads, raw log content, unfiltered logs, stack traces, raw rows, serial numbers, credentials, secrets, tokens, tenant IDs, object IDs, private network values, or raw recipient data.",
        evidence: "Prohibited content review",
    },
];

#[derive(Debug, Deserialize)]
struct EvidenceExportRetentionContext {
    catalog: Value,
    manifest: Value,
    catalog_text: String,
    manifest_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ManifestAlignmentInput {
    catalog: Value,
    manifest: Value,
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
    keys: Vec<String>,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: EvidenceExportRetentionContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid evidence export retention context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_manifest_alignment_value(&context.catalog, &context.manifest, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.manifest_text),
        MANIFEST_CATALOG_PATH,
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
        .map_err(|error| format!("invalid evidence export retention catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_manifest_alignment_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ManifestAlignmentInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid evidence export retention manifest alignment JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_manifest_alignment_value(&payload.catalog, &payload.manifest, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence export retention program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence export retention docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid evidence export retention prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("evidence export retention catalog root must be mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "evidence export retention version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "evidence export retention status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "evidence export retention source must be static-seed",
    );
    expect(
        string_value(catalog, "exportRetentionMode") == Some("static-evidence-export-retention"),
        errors,
        "evidence export retention mode must be static-evidence-export-retention",
    );
    expect(
        string_value(catalog, "manifestCatalog") == Some("evidence-manifest-catalog"),
        errors,
        "evidence export retention must name manifest catalog",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("evidence export retention {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("evidence export retention {field} must be disabled"),
        );
    }
    validate_required_array(
        catalog,
        "redactionStates",
        REQUIRED_REDACTION_STATES,
        errors,
    );
    validate_required_array(
        catalog,
        "exportReadiness",
        REQUIRED_EXPORT_READINESS,
        errors,
    );
    validate_required_array(
        catalog,
        "safeExportTargets",
        REQUIRED_EXPORT_TARGETS,
        errors,
    );
    validate_required_array(
        catalog,
        "prohibitedContent",
        REQUIRED_PROHIBITED_CONTENT,
        errors,
    );
    validate_required_array(
        catalog,
        "retentionClasses",
        REQUIRED_RETENTION_CLASSES,
        errors,
    );
    validate_required_array(
        catalog,
        "auditSearchStates",
        REQUIRED_AUDIT_SEARCH_STATES,
        errors,
    );
    validate_required_array(catalog, "searchFacets", REQUIRED_SEARCH_FACETS, errors);
    validate_required_array(
        catalog,
        "safeExportPackageFields",
        REQUIRED_PACKAGE_FIELDS,
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
    let allowed: BTreeSet<&str> = CATALOG_FIELDS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "evidence export retention unexpected catalog keys: {}",
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
                "{field} contains prohibited evidence export retention value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rule_hashes(catalog, errors);
    let rule_ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
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
            "evidence export retention missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "evidence export retention unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "evidence export retention rule IDs must be unique",
    );
    expect_unique_rule_details(
        &rules,
        errors,
        "evidence export retention rule details must be unique",
    );
    for rule in &rules {
        let actual_keys: BTreeSet<&str> = rule.keys.iter().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = RULE_FIELDS.iter().copied().collect();
        let unexpected_keys: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing_keys: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "evidence export retention rule {} unexpected rule keys: {}",
                if rule.id.is_empty() {
                    "(missing id)"
                } else {
                    &rule.id
                },
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "evidence export retention rule {} missing rule keys: {}",
                if rule.id.is_empty() {
                    "(missing id)"
                } else {
                    &rule.id
                },
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
                "evidence export retention rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "evidence export retention rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "evidence export retention rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn catalog_rule_hashes(catalog: &Value, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(Value::Array(rule_values)) = catalog.get("rules") else {
        errors.push("evidence export retention rules must be array of mappings".to_string());
        return Vec::new();
    };
    let mut rules = Vec::new();
    for rule_value in rule_values {
        let Some(map) = rule_value.as_object() else {
            errors.push("evidence export retention rule entry must be mapping".to_string());
            continue;
        };
        let actual_keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = RULE_FIELDS.iter().copied().collect();
        let unexpected_keys: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing_keys: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        let id = string_value(rule_value, "id").unwrap_or("(missing id)");
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "evidence export retention rule {id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "evidence export retention rule {id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
        rules.push(Rule {
            id: string_value(rule_value, "id")
                .unwrap_or_default()
                .to_string(),
            decision: string_value(rule_value, "decision")
                .unwrap_or_default()
                .to_string(),
            requirement: string_value(rule_value, "requirement")
                .unwrap_or_default()
                .to_string(),
            evidence: string_value(rule_value, "evidence")
                .unwrap_or_default()
                .to_string(),
            keys: map.keys().map(|key| key.to_string()).collect(),
        });
    }
    rules
}

fn validate_manifest_alignment_value(contract: &Value, manifest: &Value, errors: &mut Vec<String>) {
    for (contract_field, manifest_field) in [
        ("redactionStates", "redactionStates"),
        ("exportReadiness", "exportReadiness"),
        ("safeExportTargets", "safeExportTargets"),
        ("retentionClasses", "retentionClasses"),
    ] {
        expect(
            string_array_like(contract, contract_field)
                == string_array_like(manifest, manifest_field),
            errors,
            format!("manifest {manifest_field} must align to evidence export retention contract"),
        );
    }
    let manifest_prohibited = string_array_like(manifest, "prohibitedContent");
    let contract_prohibited = string_array_like(contract, "prohibitedContent");
    let contract_set: BTreeSet<&str> = contract_prohibited.iter().map(String::as_str).collect();
    let missing: Vec<&str> = manifest_prohibited
        .iter()
        .map(String::as_str)
        .filter(|value| !contract_set.contains(value))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "manifest prohibitedContent must be covered by evidence export retention contract: {}",
            missing.join(", ")
        ),
    );
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
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
            "exportRetentionMode",
            "static-evidence-export-retention",
        ),
        errors,
        "API must keep static-evidence-export-retention mode",
    );
    expect(
        exact_string_assignment(&block, "manifestCatalog", "evidence-manifest-catalog"),
        errors,
        "API must keep manifest catalog",
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
    let uncommented_program = strip_csharp_comments(program);
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
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_endpoint_identifier_terms(&block, errors);
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
    expect(
        values == catalog_values,
        errors,
        format!("API {field} must match catalog"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules = catalog_rules(catalog);
    let api_rules = api_rules(block);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let missing: Vec<&str> = catalog_ids.difference(&api_ids).copied().collect();
    let unexpected: Vec<&str> = api_ids.difference(&catalog_ids).copied().collect();
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
    let api_rule_ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect_unique_rule_details(&api_rules, errors, "API rule details must be unique");
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            errors.push(format!("API missing rule {}", catalog_rule.id));
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
    for field in assignment_fields(&stripped) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected evidence export retention field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited evidence export retention field {field}"
            ));
        }
    }
}

fn validate_endpoint_identifier_terms(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    let mut seen = BTreeSet::new();
    for term in identifier_terms(&stripped) {
        if !seen.insert(term.clone()) || safe_identifier(&term) {
            continue;
        }
        if prohibited_field(&term) {
            errors.push(format!(
                "API endpoint uses prohibited evidence export retention identifier {term}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in assignment_values(&stripped) {
        if value != "true" || SAFE_TRUE_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if [
            "provider",
            "live",
            "payload",
            "raw",
            "log",
            "trace",
            "export",
            "credential",
            "secret",
            "token",
            "tenant",
            "object",
            "private",
            "recipient",
            "search",
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
        "API README must document evidence export retention endpoint",
    );
    expect(
        catalog_readme.contains("evidence-export-retention-contract.yaml"),
        errors,
        "catalog README must include evidence export retention contract",
    );
    expect(
        doc_readme.contains("evidence-export-retention.md"),
        errors,
        "workflow README must include evidence export retention doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "evidence export retention doc must mention endpoint",
    );
    expect(
        doc.contains("No raw evidence payloads"),
        errors,
        "evidence export retention doc must document raw data boundary",
    );
    expect(
        doc.contains("metadata-only audit search"),
        errors,
        "evidence export retention doc must document metadata-only search",
    );
    expect(
        doc.contains("evidence-manifest-catalog.yaml"),
        errors,
        "evidence export retention doc must mention manifest catalog",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited evidence export retention field"
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
                    "{path} contains prohibited evidence export retention field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn catalog_rules(catalog: &Value) -> Vec<Rule> {
    catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            let map = rule.as_object()?;
            Some(Rule {
                id: string_value(rule, "id").unwrap_or_default().to_string(),
                decision: string_value(rule, "decision")
                    .unwrap_or_default()
                    .to_string(),
                requirement: string_value(rule, "requirement")
                    .unwrap_or_default()
                    .to_string(),
                evidence: string_value(rule, "evidence")
                    .unwrap_or_default()
                    .to_string(),
                keys: map.keys().map(|key| key.to_string()).collect(),
            })
        })
        .collect()
}

fn api_rules(block: &str) -> Vec<Rule> {
    let Some(body) = endpoint_rules_body(block) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut offset = 0usize;
    while let Some(relative_start) = body[offset..].find("new {") {
        let start = offset + relative_start;
        let Some(relative_end) = body[start..].find('}') else {
            break;
        };
        let segment = &body[start..start + relative_end];
        let assignments = string_assignments(segment);
        let keys: Vec<String> = assignments.iter().map(|(key, _)| key.clone()).collect();
        if keys.iter().all(|key| !RULE_FIELDS.contains(&key.as_str())) {
            offset = start + relative_end + 1;
            continue;
        }
        result.push(Rule {
            id: assignment_value(&assignments, "id").unwrap_or_default(),
            decision: assignment_value(&assignments, "decision").unwrap_or_default(),
            requirement: assignment_value(&assignments, "requirement").unwrap_or_default(),
            evidence: assignment_value(&assignments, "evidence").unwrap_or_default(),
            keys,
        });
        offset = start + relative_end + 1;
    }
    result
}

fn endpoint_rules_body(block: &str) -> Option<String> {
    let rules_index = block.find("rules = new[]")?;
    let open_index = block[rules_index..].find('{')? + rules_index;
    let close_index = matching_brace_index(block, open_index)?;
    Some(block[open_index + 1..close_index].to_string())
}

fn string_assignments(segment: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = segment.chars().collect();
    let mut assignments = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        let key: String = chars[start..index].iter().collect();
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) != Some(&'=') {
            continue;
        }
        probe += 1;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if chars.get(probe) != Some(&'"') {
            continue;
        }
        probe += 1;
        let mut value = String::new();
        let mut escape = false;
        while probe < chars.len() {
            let ch = chars[probe];
            probe += 1;
            if escape {
                value.push(ch);
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                break;
            } else {
                value.push(ch);
            }
        }
        assignments.push((key, value));
        index = probe;
    }
    assignments
}

fn assignment_value(assignments: &[(String, String)], field: &str) -> Option<String> {
    assignments
        .iter()
        .rev()
        .find(|(key, _)| key == field)
        .map(|(_, value)| value.clone())
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let code_map = csharp_code_outside_literals(program);
    let endpoint_indexes = endpoint_start_indexes(&code_map, program);
    if endpoint_indexes.is_empty() {
        errors.push(format!("API missing endpoint {ENDPOINT}"));
        return String::new();
    }
    if endpoint_indexes.len() != 1 {
        errors.push(format!("API must define exactly one {ENDPOINT} endpoint"));
        return String::new();
    }
    let uncommented_program = strip_csharp_comments(program);
    let start_index = endpoint_indexes[0];
    let next_index =
        next_endpoint_index(&code_map, start_index).unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_index].to_string()
}

fn endpoint_start_indexes(code_map: &str, source: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let marker = "app.MapGet(";
    for (index, _) in code_map.match_indices(marker) {
        let line_prefix = code_map[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&code_map[..index]);
        if !line_prefix.trim().is_empty() {
            continue;
        }
        let tail = &source[index..];
        let route = format!("app.MapGet(\"{ENDPOINT}\"");
        if tail.starts_with(&route) {
            starts.push(index);
        }
    }
    starts
}

fn next_endpoint_index(code_map: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = code_map[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let line_prefix = code_map[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&code_map[..index]);
        if line_prefix.trim().is_empty() {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[]");
    if program.matches(&marker).count() != 1 {
        return None;
    }
    let declaration_start = program.find(&marker)? + marker.len();
    let start = program[declaration_start..].find('{')? + declaration_start + 1;
    let end = program[start..].find("};")? + start;
    csharp_string_literals(&program[start..end])
}

fn csharp_string_literals(text: &str) -> Option<Vec<String>> {
    let mut values = Vec::new();
    let mut remainder = String::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            remainder.push(ch);
            continue;
        }
        let mut value = String::new();
        let mut closed = false;
        let mut escape = false;
        for next in chars.by_ref() {
            if escape {
                value.push(next);
                escape = false;
            } else if next == '\\' {
                escape = true;
            } else if next == '"' {
                closed = true;
                break;
            } else {
                value.push(next);
            }
        }
        if !closed {
            return None;
        }
        values.push(value);
    }
    let leftovers: String = remainder
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != ',')
        .collect();
    if leftovers.is_empty() {
        Some(values)
    } else {
        None
    }
}

fn exact_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    assignment_lines(block, field).as_slice() == [expected]
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    assignment_lines(block, field).as_slice() == [expected]
}

fn assignment_lines(block: &str, field: &str) -> Vec<String> {
    let marker = format!("{field} =");
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with(&marker) {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn assignment_fields(text: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        let field: String = chars[start..index].iter().collect();
        let mut probe = index;
        while probe < chars.len() && chars[probe].is_whitespace() {
            probe += 1;
        }
        if probe < chars.len() && chars[probe] == '=' && chars.get(probe + 1) != Some(&'=') {
            fields.push(field);
        }
    }
    fields
}

fn assignment_values(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once('=')?;
            let field = left.split_whitespace().last()?.trim().to_string();
            if field.is_empty() || !field.chars().all(is_identifier_continue) {
                return None;
            }
            let value = right
                .trim()
                .trim_end_matches(',')
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            Some((field, value))
        })
        .collect()
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

fn strip_csharp_comments(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            index = csharp_string_end(text, index);
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let finish = text[index..]
                .find('\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let finish = text[index + 2..]
                .find("*/")
                .map(|relative| index + 2 + relative + 2)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn csharp_code_outside_literals(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let finish = csharp_string_end(text, index);
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let finish = text[index..]
                .find('\n')
                .map(|relative| index + relative)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let finish = text[index + 2..]
                .find("*/")
                .map(|relative| index + 2 + relative + 2)
                .unwrap_or(bytes.len());
            blank_range(&mut bytes, index, finish);
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn strip_csharp_string_literals(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let finish = csharp_string_end(text, index);
            blank_range(&mut bytes, index, finish);
            if index < bytes.len() {
                bytes[index] = b'"';
            }
            if finish > 0 && finish <= bytes.len() {
                bytes[finish - 1] = b'"';
            }
            index = finish;
        } else {
            index += 1;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn csharp_string_end(text: &str, start_index: usize) -> usize {
    let quote_count = consecutive_quote_count(text.as_bytes(), start_index);
    if quote_count >= 3 {
        return csharp_raw_string_end(text, start_index, quote_count);
    }
    let bytes = text.as_bytes();
    let mut index = start_index + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
        } else if bytes[index] == b'"' {
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn csharp_raw_string_end(text: &str, start_index: usize, quote_count: usize) -> usize {
    let delimiter = "\"".repeat(quote_count);
    text[start_index + quote_count..]
        .find(&delimiter)
        .map(|relative| start_index + quote_count + relative + quote_count)
        .unwrap_or(text.len())
}

fn consecutive_quote_count(bytes: &[u8], start_index: usize) -> usize {
    let mut index = start_index;
    while bytes.get(index) == Some(&b'"') {
        index += 1;
    }
    index - start_index
}

fn blank_range(bytes: &mut [u8], start: usize, finish: usize) {
    for byte in &mut bytes[start..finish] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
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
        || [
            "draft",
            "static-seed",
            "static-evidence-export-retention",
            "evidence-manifest-catalog",
            "block",
            "true",
            "false",
        ]
        .contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 13] {
    [
        REQUIRED_REDACTION_STATES,
        REQUIRED_EXPORT_READINESS,
        REQUIRED_EXPORT_TARGETS,
        REQUIRED_PROHIBITED_CONTENT,
        REQUIRED_RETENTION_CLASSES,
        REQUIRED_AUDIT_SEARCH_STATES,
        REQUIRED_SEARCH_FACETS,
        REQUIRED_PACKAGE_FIELDS,
        REQUIRED_GUARDS,
        REQUIRED_EVIDENCE,
        REQUIRED_BLOCKED_REASONS,
        SAFE_TRUE_FIELDS,
        REQUIRED_DISABLED_FIELDS,
    ]
}

fn safe_identifier(value: &str) -> bool {
    safe_text_value(value)
        || CATALOG_FIELDS.contains(&value)
        || ALLOWED_ENDPOINT_FIELDS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || ["app", "MapGet", "Results", "Json", "new", "var"].contains(&value)
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_value(value) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || [
            "tenantid",
            "objectid",
            "privateip",
            "rawrequest",
            "rawprovider",
            "rawevidence",
            "rawlog",
            "rawrow",
            "unfilteredlog",
            "stacktrace",
            "serialnumber",
            "serial",
            "credential",
            "secret",
            "accesstoken",
            "token",
            "password",
            "bearer",
            "recipientemail",
            "recipientaddress",
            "recipientdata",
            "providerpayload",
            "evidencepayload",
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
        || (has_any(&tokens, &["private", "ip"])
            && has_any(&tokens, &["address", "value", "network"]))
        || (has_any(&tokens, &["tenant", "object", "recipient"])
            && has_any(
                &tokens,
                &["id", "identifier", "key", "value", "data", "address"],
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
                    "row",
                    "rows",
                    "payload",
                    "recipient",
                    "data",
                ],
            ))
        || (tokens.iter().any(|token| token == "stack")
            && tokens.iter().any(|token| token == "trace"))
        || (tokens.iter().any(|token| token == "serial")
            && has_any(&tokens, &["number", "numbers", "value", "values"]))
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut normalized = String::new();
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            normalized.push(' ');
        }
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            normalized.push(' ');
            previous_lower_or_digit = false;
        }
    }
    normalized.split_whitespace().map(str::to_string).collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || contains_aws_access_key(text)
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_email_like(text)
        || contains_secret_assignment(text)
}

fn contains_aws_access_key(text: &str) -> bool {
    normalized_tokens(text).iter().any(|token| {
        token.len() == 20
            && token.to_ascii_uppercase().starts_with("AKIA")
            && token.chars().all(|ch| ch.is_ascii_alphanumeric())
    })
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
        let candidate = candidate.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | ',' | ';' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>'
            )
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
        let boundary_before = !before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        let boundary_after = !after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if boundary_before && boundary_after {
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

fn identifier_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !is_identifier_start(chars[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && is_identifier_continue(chars[index]) {
            index += 1;
        }
        terms.push(chars[start..index].iter().collect());
    }
    terms
}

fn normalized_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.'))
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
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

fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

fn expect_unique_rule_details(rules: &[Rule], errors: &mut Vec<String>, message: &str) {
    let seen: BTreeSet<(&str, &str, &str)> = rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect();
    expect(seen.len() == rules.len(), errors, message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Map};

    fn catalog() -> Value {
        let mut catalog = Map::new();
        insert(&mut catalog, "version", json!(1));
        insert(&mut catalog, "status", json!("draft"));
        insert(&mut catalog, "source", json!("static-seed"));
        insert(
            &mut catalog,
            "exportRetentionMode",
            json!("static-evidence-export-retention"),
        );
        insert(
            &mut catalog,
            "manifestCatalog",
            json!("evidence-manifest-catalog"),
        );
        for field in SAFE_TRUE_FIELDS {
            insert(&mut catalog, field, json!(true));
        }
        for field in REQUIRED_DISABLED_FIELDS {
            insert(&mut catalog, field, json!(false));
        }
        insert(
            &mut catalog,
            "redactionStates",
            json!(REQUIRED_REDACTION_STATES),
        );
        insert(
            &mut catalog,
            "exportReadiness",
            json!(REQUIRED_EXPORT_READINESS),
        );
        insert(
            &mut catalog,
            "safeExportTargets",
            json!(REQUIRED_EXPORT_TARGETS),
        );
        insert(
            &mut catalog,
            "prohibitedContent",
            json!(REQUIRED_PROHIBITED_CONTENT),
        );
        insert(
            &mut catalog,
            "retentionClasses",
            json!(REQUIRED_RETENTION_CLASSES),
        );
        insert(
            &mut catalog,
            "auditSearchStates",
            json!(REQUIRED_AUDIT_SEARCH_STATES),
        );
        insert(&mut catalog, "searchFacets", json!(REQUIRED_SEARCH_FACETS));
        insert(
            &mut catalog,
            "safeExportPackageFields",
            json!(REQUIRED_PACKAGE_FIELDS),
        );
        insert(&mut catalog, "requiredGuards", json!(REQUIRED_GUARDS));
        insert(
            &mut catalog,
            "blockedReasons",
            json!(REQUIRED_BLOCKED_REASONS),
        );
        insert(&mut catalog, "requiredEvidence", json!(REQUIRED_EVIDENCE));
        insert(
            &mut catalog,
            "rules",
            json!(REQUIRED_RULES
                .iter()
                .map(|rule| json!({
                    "id": rule.id,
                    "decision": rule.decision,
                    "requirement": rule.requirement,
                    "evidence": rule.evidence,
                }))
                .collect::<Vec<_>>()),
        );
        Value::Object(catalog)
    }

    fn insert(catalog: &mut Map<String, Value>, key: &str, value: Value) {
        catalog.insert(key.to_string(), value);
    }

    fn csharp_array(values: &[&str]) -> String {
        values
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn csharp_rules() -> String {
        REQUIRED_RULES
            .iter()
            .map(|rule| {
                format!(
                    "new {{ id = \"{}\", decision = \"{}\", requirement = \"{}\", evidence = \"{}\" }}",
                    rule.id, rule.decision, rule.requirement, rule.evidence
                )
            })
            .collect::<Vec<_>>()
            .join(",\n        ")
    }

    fn valid_program() -> String {
        format!(
            r#"var evidenceExportRetentionRedactionStates = new[] {{ {} }};
var evidenceExportRetentionReadiness = new[] {{ {} }};
var evidenceExportRetentionTargets = new[] {{ {} }};
var evidenceExportRetentionProhibitedContent = new[] {{ {} }};
var evidenceExportRetentionClasses = new[] {{ {} }};
var evidenceExportRetentionAuditSearchStates = new[] {{ {} }};
var evidenceExportRetentionSearchFacets = new[] {{ {} }};
var evidenceExportRetentionPackageFields = new[] {{ {} }};
var evidenceExportRetentionRequiredGuards = new[] {{ {} }};
var evidenceExportRetentionBlockedReasons = new[] {{ {} }};
var evidenceExportRetentionRequiredEvidence = new[] {{ {} }};
app.MapGet("{ENDPOINT}", () => Results.Json(new
{{
    source = "static-seed",
    exportRetentionMode = "static-evidence-export-retention",
    manifestCatalog = "evidence-manifest-catalog",
    exportIndexReadOnly = true,
    retentionPolicyReadOnly = true,
    auditSearchReadOnly = true,
    redactionRequired = true,
    metadataOnlySearchRequired = true,
    providerCallsAllowed = false,
    liveEvidenceMutationAllowed = false,
    exportPackageMutationAllowed = false,
    retentionPolicyMutationAllowed = false,
    liveAuditSearchAllowed = false,
    auditSearchQueryAllowed = false,
    evidencePayloadsAllowed = false,
    rawRequestPayloadsAllowed = false,
    rawProviderPayloadsAllowed = false,
    rawEvidencePayloadsAllowed = false,
    rawLogContentAllowed = false,
    unfilteredLogsAllowed = false,
    stackTracesAllowed = false,
    rawRowsAllowed = false,
    serialNumbersAllowed = false,
    exportWithoutRedactionAllowed = false,
    credentialValuesAllowed = false,
    secretValuesAllowed = false,
    tokenValuesAllowed = false,
    tenantIdentifiersAllowed = false,
    objectIdentifiersAllowed = false,
    privateNetworkValuesAllowed = false,
    rawRecipientDataAllowed = false,
    redactionStates = evidenceExportRetentionRedactionStates,
    exportReadiness = evidenceExportRetentionReadiness,
    safeExportTargets = evidenceExportRetentionTargets,
    prohibitedContent = evidenceExportRetentionProhibitedContent,
    retentionClasses = evidenceExportRetentionClasses,
    auditSearchStates = evidenceExportRetentionAuditSearchStates,
    searchFacets = evidenceExportRetentionSearchFacets,
    safeExportPackageFields = evidenceExportRetentionPackageFields,
    requiredGuards = evidenceExportRetentionRequiredGuards,
    blockedReasons = evidenceExportRetentionBlockedReasons,
    requiredEvidence = evidenceExportRetentionRequiredEvidence,
    rules = new[]
    {{
        {}
    }}
}}));"#,
            csharp_array(REQUIRED_REDACTION_STATES),
            csharp_array(REQUIRED_EXPORT_READINESS),
            csharp_array(REQUIRED_EXPORT_TARGETS),
            csharp_array(REQUIRED_PROHIBITED_CONTENT),
            csharp_array(REQUIRED_RETENTION_CLASSES),
            csharp_array(REQUIRED_AUDIT_SEARCH_STATES),
            csharp_array(REQUIRED_SEARCH_FACETS),
            csharp_array(REQUIRED_PACKAGE_FIELDS),
            csharp_array(REQUIRED_GUARDS),
            csharp_array(REQUIRED_BLOCKED_REASONS),
            csharp_array(REQUIRED_EVIDENCE),
            csharp_rules()
        )
    }

    #[test]
    fn duplicate_rule_ids_and_details_are_rejected() {
        let mut catalog = catalog();
        let duplicate_rule = catalog
            .get("rules")
            .and_then(Value::as_array)
            .and_then(|rules| rules.first())
            .cloned()
            .expect("catalog has rules");
        catalog
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("catalog rules are an array")
            .push(duplicate_rule);
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("rule IDs must be unique")));
        assert!(errors
            .iter()
            .any(|error| error.contains("rule details must be unique")));
    }

    #[test]
    fn commented_endpoint_decoy_does_not_satisfy_mode() {
        let program = valid_program().replacen(
            "exportRetentionMode = \"static-evidence-export-retention\",",
            "// exportRetentionMode = \"static-evidence-export-retention\",\n    exportRetentionMode = \"live-evidence-export\",",
            1,
        );
        let mut errors = Vec::new();

        validate_program_text(&program, &catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("static-evidence-export-retention")));
    }

    #[test]
    fn commented_valid_endpoint_does_not_mask_suffix_route() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}-live\", () => Results.Json(new {{ source = \"static-seed\" }}));\n// app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();

        let _ = endpoint_block(&program, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("missing endpoint")));
    }

    #[test]
    fn source_assignment_spoofing_is_rejected() {
        let program = valid_program().replacen(
            "source = \"static-seed\",",
            "source = \"static-seed\",\n    source = \"live-provider\",",
            1,
        );
        let mut errors = Vec::new();

        validate_program_text(&program, &catalog(), &mut errors);

        assert!(errors.iter().any(|error| error.contains("source")));
    }

    #[test]
    fn endpoint_property_identifier_is_rejected() {
        let program = valid_program().replacen(
            "requiredEvidence = evidenceExportRetentionRequiredEvidence,",
            "requiredEvidence = safeSummary.endpointUrl,",
            1,
        );
        let mut errors = Vec::new();

        validate_program_text(&program, &catalog(), &mut errors);

        assert!(errors.iter().any(|error| error.contains("endpointUrl")));
    }

    #[test]
    fn api_rule_details_are_rejected_when_duplicated() {
        let program = valid_program().replacen(
            "new { id = \"retention-policy-review-required\", decision = \"block\", requirement = \"Retention class, retention review state, expiry posture, and legal hold interaction must be summarized before retained evidence packages can be accepted.\", evidence = \"Retention class decision\" }",
            "new { id = \"retention-policy-review-required\", decision = \"block\", requirement = \"Evidence export packages require redacted state, export readiness, safe export target, retention class, and evidence references before audit, CAB, incident, handover, or CMDB file exchange use.\", evidence = \"Export package summary\" }",
            1,
        );
        let mut errors = Vec::new();

        validate_program_text(&program, &catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("API rule details must be unique")));
    }

    #[test]
    fn quoted_broad_suffix_provider_literal_is_rejected() {
        let mut errors = Vec::new();

        scan_prohibited_value(
            &Value::String(r#""rawProviderPayloadsAllowed": true"#.to_string()),
            "synthetic.notes",
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("synthetic.notes") && error.contains("prohibited")));
    }

    #[test]
    fn unsafe_provider_identifier_true_flag_is_rejected() {
        let program = valid_program().replacen(
            "exportRetentionMode = \"static-evidence-export-retention\",",
            "exportRetentionMode = \"static-evidence-export-retention\",\n    providerPayloadAllowed = true,",
            1,
        );
        let mut errors = Vec::new();

        validate_program_text(&program, &catalog(), &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("providerPayloadAllowed")));
    }
}
