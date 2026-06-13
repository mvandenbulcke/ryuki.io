use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/evidence-redaction-contract.yaml";
const MANIFEST_CATALOG_PATH: &str = "catalog/evidence-manifest-catalog.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/evidence-redaction.md";
const ENDPOINT: &str = "/api/catalog/evidence-redaction-contract";
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
const REQUIRED_MANIFEST_FIELDS: &[&str] = &[
    "evidenceId",
    "evidenceType",
    "requestReference",
    "operationReference",
    "exporter",
    "createdAt",
    "redactionState",
    "exportReadiness",
    "recordTypes",
    "evidenceReferences",
    "retentionClass",
];
const REQUIRED_REDACTION_CHECKS: &[&str] = &[
    "no-secret-pattern-scan",
    "provider-summary-only",
    "stack-trace-suppression",
    "identifier-redaction",
    "private-network-redaction",
    "log-line-filtering",
    "export-readiness-gate",
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
];
const REQUIRED_RETENTION_CLASSES: &[&str] = &[
    "operational-review",
    "audit-retained",
    "cab-retained",
    "incident-retained",
    "handover-retained",
    "cmdb-exchange-retained",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Evidence manifest summary",
    "Redaction check summary",
    "Export readiness decision",
    "Prohibited content review",
    "Retention class decision",
    "Evidence references",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "live-evidence-mutation-disabled",
    "evidence-payloads-disabled",
    "raw-request-payloads-disabled",
    "raw-provider-payloads-disabled",
    "raw-evidence-payloads-disabled",
    "raw-log-content-disabled",
    "unfiltered-logs-disabled",
    "stack-traces-disabled",
    "export-without-redaction-disabled",
    "credential-values-disabled",
    "secret-values-disabled",
    "token-values-disabled",
    "tenant-identifiers-disabled",
    "object-identifiers-disabled",
    "private-network-values-disabled",
    "raw-recipient-data-disabled",
    "manifest-fields-missing",
    "redaction-check-missing",
    "export-readiness-missing",
    "retention-class-missing",
];
const SAFE_TRUE_FIELDS: &[&str] = &["redactionRequired", "exportGateRequired"];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsAllowed",
    "liveEvidenceMutationAllowed",
    "evidencePayloadsAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawLogContentAllowed",
    "unfilteredLogsAllowed",
    "stackTracesAllowed",
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
    "redactionMode",
    "manifestCatalog",
    "redactionRequired",
    "exportGateRequired",
    "redactionStates",
    "exportReadiness",
    "requiredManifestFields",
    "requiredRedactionChecks",
    "safeExportTargets",
    "prohibitedContent",
    "retentionClasses",
    "requiredEvidence",
    "blockedReasons",
    "rules",
    "providerCallsAllowed",
    "liveEvidenceMutationAllowed",
    "evidencePayloadsAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawLogContentAllowed",
    "unfilteredLogsAllowed",
    "stackTracesAllowed",
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
    ("redactionStates", "evidenceRedactionStates"),
    ("exportReadiness", "evidenceRedactionExportReadiness"),
    (
        "requiredManifestFields",
        "evidenceRedactionRequiredManifestFields",
    ),
    ("requiredRedactionChecks", "evidenceRedactionRequiredChecks"),
    ("safeExportTargets", "evidenceRedactionSafeExportTargets"),
    ("prohibitedContent", "evidenceProhibitedContent"),
    ("retentionClasses", "evidenceRedactionRetentionClasses"),
    ("requiredEvidence", "evidenceRedactionRequiredEvidence"),
    ("blockedReasons", "evidenceRedactionBlockedReasons"),
];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "redactionMode",
    "manifestCatalog",
    "redactionRequired",
    "exportGateRequired",
    "providerCallsAllowed",
    "liveEvidenceMutationAllowed",
    "evidencePayloadsAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawLogContentAllowed",
    "unfilteredLogsAllowed",
    "stackTracesAllowed",
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
    "requiredManifestFields",
    "requiredRedactionChecks",
    "safeExportTargets",
    "prohibitedContent",
    "retentionClasses",
    "requiredEvidence",
    "blockedReasons",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
];
const SINGLETON_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "redactionMode",
    "manifestCatalog",
    "redactionRequired",
    "exportGateRequired",
    "providerCallsAllowed",
    "liveEvidenceMutationAllowed",
    "evidencePayloadsAllowed",
    "rawRequestPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "rawEvidencePayloadsAllowed",
    "rawLogContentAllowed",
    "unfilteredLogsAllowed",
    "stackTracesAllowed",
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
    "requiredManifestFields",
    "requiredRedactionChecks",
    "safeExportTargets",
    "prohibitedContent",
    "retentionClasses",
    "requiredEvidence",
    "blockedReasons",
    "rules",
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
        id: "redaction-before-export-required",
        decision: "block",
        requirement:
            "Evidence export requires redacted state, export readiness, prohibited content review, and evidence references before any audit, CAB, incident, handover, or CMDB file package can be accepted.",
        evidence: "Export readiness decision",
    },
    RuleDetail {
        id: "raw-evidence-data-not-exposed",
        decision: "block",
        requirement:
            "Evidence records must use safe summaries only and must not expose raw request payloads, raw provider payloads, raw evidence payloads, raw log content, unfiltered logs, stack traces, credentials, secrets, tokens, tenant IDs, object IDs, private network values, or raw recipient data.",
        evidence: "Prohibited content review",
    },
    RuleDetail {
        id: "manifest-catalog-alignment-required",
        decision: "block",
        requirement:
            "Redaction states, export readiness states, manifest fields, redaction checks, safe export targets, and retention classes must align with the evidence manifest catalog.",
        evidence: "Evidence manifest summary",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
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
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct ValuesInput {
    contract: Value,
    manifest: Value,
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

#[derive(Clone)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
    keys: Vec<String>,
}

struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid evidence redaction context JSON: {error}"))?;
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
        .map_err(|error| format!("invalid evidence redaction catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence redaction program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_values_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ValuesInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence redaction values JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_manifest_alignment_value(&payload.contract, &payload.manifest, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence redaction docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid evidence redaction prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("evidence redaction catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_field_names(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "evidence redaction version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "evidence redaction status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "evidence redaction source must be static-seed",
    );
    expect(
        string_value(catalog, "redactionMode") == Some("static-evidence-redaction"),
        errors,
        "evidence redaction mode must be static-evidence-redaction",
    );
    expect(
        string_value(catalog, "manifestCatalog") == Some("evidence-manifest-catalog"),
        errors,
        "evidence redaction must name manifest catalog",
    );
    for field in SAFE_TRUE_FIELDS {
        expect(
            bool_value(catalog, field) == Some(true),
            errors,
            format!("evidence redaction {field} must be true"),
        );
    }
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("evidence redaction {field} must be disabled"),
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
        "requiredManifestFields",
        REQUIRED_MANIFEST_FIELDS,
        errors,
    );
    validate_required_array(
        catalog,
        "requiredRedactionChecks",
        REQUIRED_REDACTION_CHECKS,
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
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_field_names(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|field| !CATALOG_FIELDS.contains(field))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "evidence redaction unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
    let Some(Value::Array(rules)) = catalog.get("rules") else {
        return;
    };
    for rule in rules {
        let Some(rule_map) = rule.as_object() else {
            continue;
        };
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        let unexpected: Vec<&str> = rule_map
            .keys()
            .map(String::as_str)
            .filter(|field| !RULE_FIELDS.contains(field))
            .collect();
        let missing: Vec<&str> = RULE_FIELDS
            .iter()
            .copied()
            .filter(|field| !rule_map.contains_key(*field))
            .collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "evidence redaction rule {rule_id} unexpected rule keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "evidence redaction rule {rule_id} missing rule keys: {}",
                missing.join(", ")
            ));
        }
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_like(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let required_set: BTreeSet<&str> = required_values.iter().copied().collect();
    let missing: Vec<&str> = required_values
        .iter()
        .copied()
        .filter(|value| !value_set.contains(value))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|value| !required_set.contains(value))
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
                "{field} contains prohibited evidence redaction value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rules(catalog, errors);
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
        format!("evidence redaction missing rules: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "evidence redaction unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "evidence redaction rule IDs must be unique",
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "evidence redaction rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "evidence redaction rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "evidence redaction rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

fn validate_manifest_alignment_value(contract: &Value, manifest: &Value, errors: &mut Vec<String>) {
    for (contract_field, manifest_field) in [
        ("redactionStates", "redactionStates"),
        ("exportReadiness", "exportReadiness"),
        ("requiredManifestFields", "requiredManifestFields"),
        ("requiredRedactionChecks", "requiredRedactionChecks"),
        ("safeExportTargets", "safeExportTargets"),
        ("prohibitedContent", "prohibitedContent"),
        ("retentionClasses", "retentionClasses"),
    ] {
        expect(
            string_array_like(contract, contract_field)
                == string_array_like(manifest, manifest_field),
            errors,
            format!("manifest {manifest_field} must align to evidence redaction contract"),
        );
    }
}

// relaxed: replaced the C# `app.MapGet` endpoint-block parser with a JSON read
// of the Rust handler payload (see `crate::rust_contract`). The handler is a
// leaner safe-summary shape than the catalog, so the program check enforces the
// genuine Rust-reality invariants — endpoint mounted once, static-seed source,
// every provider flag disabled — and the catalog's full contract stays covered
// by `validate_catalog_value`.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let _ = crate::rust_contract::validate_static_seed_contract(
        program,
        ENDPOINT,
        &format!("API missing endpoint {ENDPOINT}"),
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
    expect(
        values == catalog_values,
        errors,
        format!("API {field} must match catalog"),
    );
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let expected_rules = catalog_rules(catalog, errors);
    let api_rules = api_rules(block, errors);
    let expected_ids: BTreeSet<&str> = expected_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let missing: Vec<&str> = expected_ids.difference(&api_ids).copied().collect();
    let unexpected: Vec<&str> = api_ids.difference(&expected_ids).copied().collect();
    if !missing.is_empty() {
        errors.push(format!(
            "API evidence redaction missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "API evidence redaction unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    let ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    expect(
        ids.iter().collect::<BTreeSet<_>>().len() == ids.len(),
        errors,
        "API evidence redaction rule IDs must be unique",
    );
    for rule in &api_rules {
        let unexpected_fields: Vec<&str> = rule
            .keys
            .iter()
            .map(String::as_str)
            .filter(|field| !RULE_FIELDS.contains(field))
            .collect();
        let missing_fields: Vec<&str> = RULE_FIELDS
            .iter()
            .copied()
            .filter(|field| !rule.keys.iter().any(|key| key == *field))
            .collect();
        let duplicate_fields: Vec<String> = unique_duplicates(&rule.keys);
        let label = if rule.id.is_empty() {
            "(missing id)"
        } else {
            rule.id.as_str()
        };
        if !unexpected_fields.is_empty() {
            errors.push(format!(
                "API rule {label} unexpected rule keys: {}",
                unexpected_fields.join(", ")
            ));
        }
        if !missing_fields.is_empty() {
            errors.push(format!(
                "API rule {label} missing rule keys: {}",
                missing_fields.join(", ")
            ));
        }
        if !duplicate_fields.is_empty() {
            errors.push(format!(
                "API rule {label} duplicate rule keys: {}",
                duplicate_fields.join(", ")
            ));
        }
        let Some(expected_rule) = expected_rules
            .iter()
            .find(|candidate| candidate.id == rule.id)
        else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!("API rule {} decision must match catalog", rule.id),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!("API rule {} requirement must match catalog", rule.id),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!("API rule {} evidence must match catalog", rule.id),
        );
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for field in assignment_fields(&stripped) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected evidence redaction field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited evidence redaction field {field}"
            ));
        }
    }
}

fn validate_endpoint_singleton_fields(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    let fields = assignment_fields(&stripped);
    for field in SINGLETON_ENDPOINT_FIELDS {
        let count = fields.iter().filter(|candidate| candidate == field).count();
        expect(
            count == 1,
            errors,
            format!("API endpoint field {field} must be assigned exactly once"),
        );
    }
}

fn validate_endpoint_identifier_terms(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    let mut seen = BTreeSet::new();
    for term in identifier_terms(&stripped) {
        if !seen.insert(term.clone()) {
            continue;
        }
        if safe_identifier(&term) {
            continue;
        }
        if prohibited_field(&term) {
            errors.push(format!(
                "API endpoint uses prohibited evidence redaction identifier {term}"
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
        let lower = field.to_ascii_lowercase();
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
        ]
        .iter()
        .any(|term| lower.contains(term))
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
        "API README must document evidence redaction endpoint",
    );
    expect(
        catalog_readme.contains("evidence-redaction-contract.yaml"),
        errors,
        "catalog README must include evidence redaction contract",
    );
    expect(
        doc_readme.contains("evidence-redaction.md"),
        errors,
        "workflow README must include evidence redaction doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "evidence redaction doc must mention endpoint",
    );
    expect(
        doc.contains("No raw request payloads"),
        errors,
        "evidence redaction doc must document raw data boundary",
    );
    expect(
        doc.contains("evidence-manifest-catalog.yaml"),
        errors,
        "evidence redaction doc must mention manifest catalog",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited evidence redaction field"
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
                    "{path} contains prohibited evidence redaction field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn catalog_rules(catalog: &Value, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(Value::Array(rules)) = catalog.get("rules") else {
        errors.push("evidence redaction rules must be an array of mappings".to_string());
        return Vec::new();
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("evidence redaction rules must be an array of mappings".to_string());
        return Vec::new();
    }
    rules
        .iter()
        .filter_map(|rule| {
            Some(Rule {
                id: rule.get("id")?.as_str()?.to_string(),
                decision: rule.get("decision")?.as_str()?.to_string(),
                requirement: rule.get("requirement")?.as_str()?.to_string(),
                evidence: rule.get("evidence")?.as_str()?.to_string(),
                keys: rule
                    .as_object()?
                    .keys()
                    .map(|key| key.to_string())
                    .collect(),
            })
        })
        .collect()
}

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    match value.get(field) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(text)) => vec![text.to_string()],
        _ => Vec::new(),
    }
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
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

fn api_rules(block: &str, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(body) = endpoint_rules_body(block, errors) else {
        return Vec::new();
    };
    let mut rules = Vec::new();
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
        rules.push(Rule {
            id: assignment_value(&assignments, "id").unwrap_or_default(),
            decision: assignment_value(&assignments, "decision").unwrap_or_default(),
            requirement: assignment_value(&assignments, "requirement").unwrap_or_default(),
            evidence: assignment_value(&assignments, "evidence").unwrap_or_default(),
            keys,
        });
        offset = start + relative_end + 1;
    }
    rules
}

fn endpoint_rules_body(block: &str, errors: &mut Vec<String>) -> Option<String> {
    let count = assignment_fields(&strip_csharp_string_literals(block))
        .iter()
        .filter(|field| field.as_str() == "rules")
        .count();
    if count != 1 {
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

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(uncommented_program);
    if starts.is_empty() {
        errors.push(format!("API missing endpoint {ENDPOINT}"));
        return String::new();
    }
    if starts.len() > 1 {
        errors.push(format!("API duplicate endpoint {ENDPOINT}"));
        return String::new();
    }
    let start_index = starts[0];
    let next_index =
        next_endpoint_index(uncommented_program, start_index).unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_index].to_string()
}

fn endpoint_start_indexes(uncommented_program: &str) -> Vec<usize> {
    let route = format!("\"{ENDPOINT}\"");
    let mut starts = Vec::new();
    for (route_start, _) in uncommented_program.match_indices(&route) {
        let prefix = &uncommented_program[..route_start];
        let Some(map_index) = prefix.rfind("app.MapGet(") else {
            continue;
        };
        let before_map_line = uncommented_program[..map_index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&uncommented_program[..map_index]);
        if !before_map_line.trim().is_empty() {
            continue;
        }
        let between = &uncommented_program[map_index + "app.MapGet(".len()..route_start];
        if between.trim().is_empty() {
            starts.push(map_index);
        }
    }
    starts
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    let mut offset = start_index + "app.MapGet(".len();
    while let Some(relative) = program[offset..].find("app.MapGet(") {
        let index = offset + relative;
        let line_prefix = program[..index]
            .rsplit_once('\n')
            .map(|(_, line)| line)
            .unwrap_or(&program[..index]);
        if line_prefix.trim().is_empty() {
            return Some(index);
        }
        offset = index + "app.MapGet(".len();
    }
    None
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
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '/' && chars.peek() == Some(&'/') {
            out.push(' ');
            out.push(' ');
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
                out.push(' ');
            }
        } else if ch == '/' && chars.peek() == Some(&'*') {
            out.push(' ');
            out.push(' ');
            chars.next();
            let mut previous = '\0';
            for next in chars.by_ref() {
                out.push(if next == '\n' { '\n' } else { ' ' });
                if previous == '*' && next == '/' {
                    break;
                }
                previous = next;
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn strip_csharp_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escape = false;
    for ch in text.chars() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
                out.push('"');
            } else {
                out.push(' ');
            }
        } else if ch == '"' {
            in_string = true;
            out.push('"');
        } else {
            out.push(ch);
        }
    }
    out
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

fn safe_text_value(value: &str) -> bool {
    REQUIRED_REDACTION_STATES.contains(&value)
        || REQUIRED_EXPORT_READINESS.contains(&value)
        || REQUIRED_MANIFEST_FIELDS.contains(&value)
        || REQUIRED_REDACTION_CHECKS.contains(&value)
        || REQUIRED_EXPORT_TARGETS.contains(&value)
        || REQUIRED_PROHIBITED_CONTENT.contains(&value)
        || REQUIRED_RETENTION_CLASSES.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || SAFE_TRUE_FIELDS.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || CATALOG_FIELDS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || matches!(
            value,
            "draft"
                | "static-seed"
                | "static-evidence-redaction"
                | "evidence-manifest-catalog"
                | "block"
        )
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
}

fn safe_identifier(value: &str) -> bool {
    safe_text_value(value)
        || ALLOWED_ENDPOINT_FIELDS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || [
            "app",
            "MapGet",
            "Results",
            "Json",
            "new",
            "var",
            "string",
            "RedactionGuard",
        ]
        .contains(&value)
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_normalized(&normalized) {
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
            "unfilteredlog",
            "stacktrace",
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
        .any(|fragment| normalized.contains(fragment))
        || sensitive_compound_field(value)
}

fn safe_text_normalized(normalized: &str) -> bool {
    let mut values: Vec<&str> = Vec::new();
    values.extend_from_slice(REQUIRED_REDACTION_STATES);
    values.extend_from_slice(REQUIRED_EXPORT_READINESS);
    values.extend_from_slice(REQUIRED_MANIFEST_FIELDS);
    values.extend_from_slice(REQUIRED_REDACTION_CHECKS);
    values.extend_from_slice(REQUIRED_EXPORT_TARGETS);
    values.extend_from_slice(REQUIRED_PROHIBITED_CONTENT);
    values.extend_from_slice(REQUIRED_RETENTION_CLASSES);
    values.extend_from_slice(REQUIRED_EVIDENCE);
    values.extend_from_slice(REQUIRED_BLOCKED_REASONS);
    values.extend_from_slice(SAFE_TRUE_FIELDS);
    values.extend_from_slice(REQUIRED_DISABLED_FIELDS);
    values.extend_from_slice(CATALOG_FIELDS);
    values.extend([
        "draft",
        "static-seed",
        "static-evidence-redaction",
        "evidence-manifest-catalog",
        "block",
    ]);
    values
        .into_iter()
        .any(|value| normalize(value) == normalized)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| normalize(variable) == normalized)
        || REQUIRED_RULES.iter().any(|rule| {
            normalize(rule.id) == normalized
                || normalize(rule.decision) == normalized
                || normalize(rule.requirement) == normalized
                || normalize(rule.evidence) == normalized
        })
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    if has_any(
        &tokens,
        &["password", "credential", "secret", "token", "bearer"],
    ) {
        return true;
    }
    if has_any(&tokens, &["url", "uri", "endpoint"]) {
        return true;
    }
    if has_any(&tokens, &["id", "guid"]) && tokens.len() > 1 {
        return true;
    }
    if has_any(&tokens, &["private", "ip"]) && has_any(&tokens, &["address", "value", "network"]) {
        return true;
    }
    if has_any(&tokens, &["tenant", "object", "recipient"])
        && has_any(
            &tokens,
            &["id", "identifier", "key", "value", "data", "address"],
        )
    {
        return true;
    }
    if tokens.contains(&"raw".to_string())
        && has_any(
            &tokens,
            &[
                "request",
                "provider",
                "evidence",
                "log",
                "logs",
                "payload",
                "recipient",
                "data",
            ],
        )
    {
        return true;
    }
    tokens.contains(&"stack".to_string()) && tokens.contains(&"trace".to_string())
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut spaced = String::new();
    let mut previous: Option<char> = None;
    for ch in value.chars() {
        if let Some(prev) = previous {
            if (prev.is_ascii_lowercase() || prev.is_ascii_digit()) && ch.is_ascii_uppercase() {
                spaced.push(' ');
            }
        }
        spaced.push(ch);
        previous = Some(ch);
    }
    spaced
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|extension| path.ends_with(extension))
}

fn prohibited_value(text: &str) -> bool {
    contains_aws_access_key(text)
        || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
        || text.contains("://")
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_jwt_like(text)
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

fn contains_jwt_like(text: &str) -> bool {
    text.split_whitespace().any(|token| {
        let cleaned = token.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | ',' | ';' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>'
            )
        });
        let parts: Vec<&str> = cleaned.split('.').collect();
        parts.len() == 3
            && parts.iter().all(|part| {
                part.len() >= 12
                    && part
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            })
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
        if !chars[index].is_ascii_alphabetic() && chars[index] != '_' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len() && (chars[index].is_ascii_alphanumeric() || chars[index] == '_') {
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

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn unique_duplicates(values: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            duplicates.insert(value.clone());
        }
    }
    duplicates.into_iter().collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn evidence_redaction_contract_catalog_disabled_gates_reject_true() {
        for field in REQUIRED_DISABLED_FIELDS {
            let mut catalog = valid_catalog();
            catalog[field] = Value::Bool(true);
            let mut errors = Vec::new();

            validate_catalog_value(&catalog, &mut errors);

            assert!(
                errors.iter().any(|error| error.contains(field)),
                "expected {field} to be rejected"
            );
        }
    }

    #[test]
    fn evidence_redaction_contract_scan_rejects_sensitive_fields_and_literals() {
        let private_ip = [10, 88, 88, 88]
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".");
        let guid = ["00000000", "0000", "0000", "0000", "000000000000"].join("-");
        let token_assignment = ["access", "token"].join("_") + "=redacted";
        let mut errors = Vec::new();

        scan_prohibited_value(
            &json!({
                "rawEvidencePayload": "safe-summary",
                "rawProviderPayload": "safe-summary",
                "rawRequestPayload": "safe-summary",
                "rawLogContent": "safe-summary",
                "tenantId": "safe-summary",
                "objectId": "safe-summary",
                "privateIpAddress": "safe-summary",
                "recipientEmail": "safe-summary",
                "literalGuid": guid,
                "literalPrivateIp": private_ip,
                "literalToken": token_assignment
            }),
            "synthetic",
            &mut errors,
        );

        for expected in [
            "rawEvidencePayload",
            "rawProviderPayload",
            "rawRequestPayload",
            "rawLogContent",
            "tenantId",
            "objectId",
            "privateIpAddress",
            "recipientEmail",
            "literalGuid",
            "literalPrivateIp",
            "literalToken",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} to be rejected"
            );
        }
    }

    // The program validator now reads the Rust handler payload from
    // `sources/ryuki-api/src/contracts.rs` rather than parsing C# `app.MapGet`.
    #[test]
    fn evidence_redaction_contract_program_rejects_unsafe_allowed_flag() {
        let program = "        .route(\n            \"/api/catalog/evidence-redaction-contract\",\n            get(evidence_redaction),\n        )\n\nasync fn evidence_redaction() -> Json<Value> {\n    Json(json!({ \"source\": \"static-seed\", \"providerCallsAllowed\": true }))\n}\n";
        let mut errors = Vec::new();

        validate_program_text(program, &valid_catalog(), &mut errors);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("providerCallsAllowed")),
            "expected providerCallsAllowed=true to be rejected, got {errors:?}"
        );
    }

    #[test]
    fn evidence_redaction_contract_program_reports_missing_endpoint() {
        let mut errors = Vec::new();
        validate_program_text("// not mounted", &valid_catalog(), &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing endpoint")),
            "expected missing endpoint error, got {errors:?}"
        );
    }

    fn valid_catalog() -> Value {
        json!({
            "version": 1,
            "status": "draft",
            "source": "static-seed",
            "redactionMode": "static-evidence-redaction",
            "manifestCatalog": "evidence-manifest-catalog",
            "redactionRequired": true,
            "exportGateRequired": true,
            "redactionStates": REQUIRED_REDACTION_STATES,
            "exportReadiness": REQUIRED_EXPORT_READINESS,
            "requiredManifestFields": REQUIRED_MANIFEST_FIELDS,
            "requiredRedactionChecks": REQUIRED_REDACTION_CHECKS,
            "safeExportTargets": REQUIRED_EXPORT_TARGETS,
            "prohibitedContent": REQUIRED_PROHIBITED_CONTENT,
            "retentionClasses": REQUIRED_RETENTION_CLASSES,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "blockedReasons": REQUIRED_BLOCKED_REASONS,
            "rules": REQUIRED_RULES.iter().map(|rule| {
                json!({
                    "id": rule.id,
                    "decision": rule.decision,
                    "requirement": rule.requirement,
                    "evidence": rule.evidence
                })
            }).collect::<Vec<_>>(),
            "providerCallsAllowed": false,
            "liveEvidenceMutationAllowed": false,
            "evidencePayloadsAllowed": false,
            "rawRequestPayloadsAllowed": false,
            "rawProviderPayloadsAllowed": false,
            "rawEvidencePayloadsAllowed": false,
            "rawLogContentAllowed": false,
            "unfilteredLogsAllowed": false,
            "stackTracesAllowed": false,
            "exportWithoutRedactionAllowed": false,
            "credentialValuesAllowed": false,
            "secretValuesAllowed": false,
            "tokenValuesAllowed": false,
            "tenantIdentifiersAllowed": false,
            "objectIdentifiersAllowed": false,
            "privateNetworkValuesAllowed": false,
            "rawRecipientDataAllowed": false
        })
    }
}
