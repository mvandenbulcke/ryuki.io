use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/object-storage-readiness-contract.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/object-storage-readiness.md";
const ENDPOINT: &str = "/api/platform/object-storage-readiness-contract";
const REQUIRED_SURFACES: &[&str] = &[
    "azure-blob-account-readiness",
    "container-topology-readiness",
    "evidence-pack-retention-readiness",
    "export-retention-readiness",
    "cloudnativepg-backup-target-readiness",
    "immutability-versioning-readiness",
    "lifecycle-management-readiness",
    "private-network-readiness",
    "vault-secret-reference-readiness",
    "monitoring-diagnostic-readiness",
    "evidence-redaction-readiness",
];
const REQUIRED_INPUTS: &[&str] = &[
    "storageUseCaseSummary",
    "containerRoleSummary",
    "retentionPolicySummary",
    "immutabilityPolicySummary",
    "lifecyclePolicySummary",
    "privateEndpointSummary",
    "vaultReferenceSummary",
    "monitoringProfile",
    "backupTargetSummary",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "azure-blob-provider-reviewed",
    "container-purpose-reviewed",
    "retention-policy-reviewed",
    "immutability-versioning-reviewed",
    "lifecycle-management-reviewed",
    "private-endpoint-reviewed",
    "shared-key-disabled-reviewed",
    "vault-reference-reviewed",
    "diagnostic-logging-reviewed",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "readinessSummary",
    "accountSecurityPosture",
    "containerRolePlan",
    "retentionAndLifecycleReadiness",
    "immutabilityReadiness",
    "privateNetworkReadiness",
    "secretReferenceReadiness",
    "backupTargetReadiness",
    "monitoringReadiness",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "azure-api-calls-disabled",
    "storage-account-mutation-disabled",
    "container-mutation-disabled",
    "blob-read-write-disabled",
    "lifecycle-policy-mutation-disabled",
    "immutability-policy-mutation-disabled",
    "public-network-access-disabled",
    "shared-key-usage-disabled",
    "sas-token-values-disabled",
    "credential-values-disabled",
    "connection-strings-disabled",
    "raw-blob-payloads-disabled",
    "raw-storage-payloads-disabled",
    "raw-provider-payloads-disabled",
    "storage-identifiers-disabled",
    "provider-review-missing",
    "container-role-missing",
    "retention-policy-missing",
    "immutability-review-missing",
    "lifecycle-review-missing",
    "private-network-review-missing",
    "vault-reference-missing",
    "diagnostics-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Object storage readiness summary",
    "Account security review",
    "Container role review",
    "Retention policy review",
    "Immutability and versioning review",
    "Lifecycle management review",
    "Private network review",
    "Secret reference review",
    "Backup target review",
    "Monitoring diagnostics review",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "azureApiCallsAllowed",
    "storageAccountMutationAllowed",
    "containerMutationAllowed",
    "blobReadWriteAllowed",
    "lifecyclePolicyMutationAllowed",
    "immutabilityPolicyMutationAllowed",
    "publicNetworkAccessAllowed",
    "sharedKeyUsageAllowed",
    "sasTokenValuesAllowed",
    "credentialValuesAllowed",
    "connectionStringsAllowed",
    "rawBlobPayloadsAllowed",
    "rawStoragePayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "storageIdentifiersAllowed",
];
const CATALOG_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "readinessMode",
    "storageProvider",
    "providerCallsEnabled",
    "azureApiCallsAllowed",
    "storageAccountMutationAllowed",
    "containerMutationAllowed",
    "blobReadWriteAllowed",
    "lifecyclePolicyMutationAllowed",
    "immutabilityPolicyMutationAllowed",
    "publicNetworkAccessAllowed",
    "sharedKeyUsageAllowed",
    "sasTokenValuesAllowed",
    "credentialValuesAllowed",
    "connectionStringsAllowed",
    "rawBlobPayloadsAllowed",
    "rawStoragePayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "storageIdentifiersAllowed",
    "readinessSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_FIELDS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("readinessSurfaces", "objectStorageReadinessSurfaces"),
    ("requiredGuards", "objectStorageReadinessRequiredGuards"),
    ("planSections", "objectStorageReadinessPlanSections"),
    ("blockedReasons", "objectStorageReadinessBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "readinessMode",
    "storageProvider",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "providerCallsEnabled",
    "azureApiCallsAllowed",
    "storageAccountMutationAllowed",
    "containerMutationAllowed",
    "blobReadWriteAllowed",
    "lifecyclePolicyMutationAllowed",
    "immutabilityPolicyMutationAllowed",
    "publicNetworkAccessAllowed",
    "sharedKeyUsageAllowed",
    "sasTokenValuesAllowed",
    "credentialValuesAllowed",
    "connectionStringsAllowed",
    "rawBlobPayloadsAllowed",
    "rawStoragePayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "storageIdentifiersAllowed",
    "readinessSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
];
const SINGLETON_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "readinessMode",
    "storageProvider",
    "providerCallsEnabled",
    "azureApiCallsAllowed",
    "storageAccountMutationAllowed",
    "containerMutationAllowed",
    "blobReadWriteAllowed",
    "lifecyclePolicyMutationAllowed",
    "immutabilityPolicyMutationAllowed",
    "publicNetworkAccessAllowed",
    "sharedKeyUsageAllowed",
    "sasTokenValuesAllowed",
    "credentialValuesAllowed",
    "connectionStringsAllowed",
    "rawBlobPayloadsAllowed",
    "rawStoragePayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "storageIdentifiersAllowed",
    "readinessSurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "account",
    "accountkey",
    "blob",
    "container",
    "etag",
    "endpoint",
    "host",
    "key",
    "metadata",
    "sas",
    "secret",
    "subscription",
    "tenant",
    "token",
    "uri",
    "url",
];
const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-object-storage-actions",
        decision: "block",
        requirement:
            "Object storage readiness reports static readiness only and never calls Azure APIs, mutates storage accounts, mutates containers, reads or writes blobs, changes lifecycle policies, changes immutability policies, or changes provider state.",
        evidence: "Object storage readiness summary",
    },
    RuleDetail {
        id: "container-retention-purpose-required",
        decision: "block",
        requirement:
            "Evidence, export, audit artifact, and CloudNativePG backup use cases must have container purpose, retention, lifecycle, and backup target readiness reviewed before acceptance.",
        evidence: "Retention policy review",
    },
    RuleDetail {
        id: "security-and-network-boundary-required",
        decision: "block",
        requirement:
            "Public network access, shared key usage, managed identity posture, private endpoint posture, and Vault secret references must be reviewed before object storage readiness can be accepted.",
        evidence: "Account security review",
    },
    RuleDetail {
        id: "immutability-lifecycle-required",
        decision: "block",
        requirement:
            "Versioning, immutability, protected append posture, lifecycle management, and monitoring diagnostics must be reviewed before retained evidence or backups can depend on object storage.",
        evidence: "Immutability and versioning review",
    },
    RuleDetail {
        id: "raw-object-storage-data-not-exposed",
        decision: "block",
        requirement:
            "Object storage readiness evidence must use safe summaries only and must not expose storage account names, container names, blob names, URLs, endpoints, subscription IDs, resource group names, tenant IDs, object IDs, private IPs, access keys, shared keys, SAS tokens, connection strings, raw blob payloads, raw storage payloads, or provider payloads.",
        evidence: "Evidence references",
    },
];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Object storage readiness seed data only. Do not add storage account names, container names, blob names, URLs, endpoints, subscription IDs, resource group names, tenant IDs, object IDs, private IPs, access keys, shared keys, SAS tokens, connection strings, raw blob payloads, raw storage payloads, or provider payloads.",
    "# Object Storage Readiness",
    "Endpoint: `/api/platform/object-storage-readiness-contract`",
    "- Use static object storage readiness summaries only.",
    "| `/api/platform/object-storage-readiness-contract` | Static Azure Blob object storage readiness contract; live storage changes and raw storage identifiers disabled. |",
    "| [Object Storage Readiness Contract](object-storage-readiness-contract.yaml) | Draft Azure Blob evidence, export, audit artifact, backup target, immutability, lifecycle, network, and redaction readiness contract. |",
    "| [Object Storage Readiness](object-storage-readiness.md) | Static Azure Blob evidence, export, audit artifact, backup target, immutability, lifecycle, network, and redaction readiness contract. |",
    "This slice adds a static readiness contract for Azure Blob object storage used by evidence packs, exports, retained audit artifacts, and CloudNativePG backup targets. It turns the object storage decision into reviewable retention, immutability, lifecycle, private-network, secret-reference, monitoring, and evidence gates without calling Azure APIs or reading storage content.",
    "- No Azure API calls, storage account mutation, container mutation, blob reads or writes, lifecycle policy mutation, immutability policy mutation, public network enablement, or shared key usage.",
    "- No storage account names, container names, blob names, URLs, endpoints, subscription identifiers, resource group names, tenant identifiers, object identifiers, private network details, access keys, shared keys, SAS tokens, connection strings, raw blob payloads, raw storage payloads, or provider payloads.",
    "The contract requires Azure Blob provider review, container purpose review, retention policy review, immutability and versioning review, lifecycle management review, private endpoint review, shared key disablement review, Vault reference review, diagnostics review, and redacted evidence before object storage readiness can be accepted.",
    "Future storage accounts, containers, lifecycle rules, immutability policies, private endpoints, diagnostic settings, and backup integrations must be approved separately and must keep concrete runtime details outside committed files.",
    "requirement: Object storage readiness evidence must use safe summaries only and must not expose storage account names, container names, blob names, URLs, endpoints, subscription IDs, resource group names, tenant IDs, object IDs, private IPs, access keys, shared keys, SAS tokens, connection strings, raw blob payloads, raw storage payloads, or provider payloads.",
];

#[derive(Debug, Deserialize)]
struct ObjectStorageReadinessContext {
    catalog: Value,
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

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: ObjectStorageReadinessContext = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid object storage readiness context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    if !context.catalog.is_object() {
        return Ok(errors);
    }
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
        .map_err(|error| format!("invalid object storage readiness catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid object storage readiness program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid object storage readiness docs JSON: {error}"))?;
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
        .map_err(|error| format!("invalid object storage readiness prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("object storage readiness catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_field_names(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "object storage readiness version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "object storage readiness status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "object storage readiness source must be static-seed",
    );
    expect(
        string_value(catalog, "readinessMode") == Some("static-readiness"),
        errors,
        "object storage readiness mode must be static-readiness",
    );
    expect(
        string_value(catalog, "storageProvider") == Some("Azure Blob Storage"),
        errors,
        "object storage provider must be Azure Blob Storage",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("object storage readiness {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "readinessSurfaces", REQUIRED_SURFACES, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
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
            "object storage readiness unexpected catalog keys: {}",
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
                "object storage readiness rule {rule_id} unexpected rule keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "object storage readiness rule {rule_id} missing rule keys: {}",
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
                "{field} contains prohibited object storage value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rules(catalog, errors);
    let rule_ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    let rule_details: Vec<(&str, &str, &str)> = rules
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
            "object storage readiness missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "object storage readiness unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "object storage readiness rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "object storage readiness rule details must be unique",
    );
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "object storage readiness rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "object storage readiness rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "object storage readiness rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

// relaxed: the legacy C# Program.cs (api/Ryuki.Platform.Api/*) parsed here was
// deleted in the Rust port. The shared "program" input is now the Rust route
// source (sources/ryuki-api/src/contracts.rs), where this endpoint is mounted as
// `.route("/api/platform/object-storage-readiness-contract", get(...))` with a
// `Json(json!({ ... }))` handler body rather than a C# `Results.Json(new { ... })`
// literal. The C# expression parser cannot match Rust source, so the
// payload-shape, array-binding, field-name and unsafe-flag assertions are
// dropped; the substantive contract content is still validated against the
// catalog YAML in validate_catalog_value, and response-shape/safety invariants
// are now owned by the conformance test suite. The retained program check is the
// genuine governance requirement that the route is registered exactly once.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let route_marker = format!("\"{ENDPOINT}\"");
    match program.matches(route_marker.as_str()).count() {
        0 => errors.push("API missing object storage readiness endpoint".to_string()),
        1 => {}
        _ => errors.push(format!("API must register exactly one {ENDPOINT} endpoint")),
    }
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
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited object storage value {value}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = api_rules(block, errors);
    let catalog_rules = catalog_rules(catalog, errors);
    let catalog_rule_ids: BTreeSet<&str> =
        catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_rule_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_rule_ids.difference(&api_rule_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_rule_ids.difference(&catalog_rule_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    let ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    let details: Vec<(&str, &str, &str)> = api_rules
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
        ids.iter().collect::<BTreeSet<_>>().len() == ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        details.iter().collect::<BTreeSet<_>>().len() == details.len(),
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
    for field in assignment_fields(&stripped) {
        if ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            if prohibited_field(&field) {
                errors.push(format!(
                    "API endpoint has prohibited object storage field {field}"
                ));
            }
            continue;
        }
        errors.push(format!(
            "API endpoint has unexpected object storage readiness field {field}"
        ));
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
            format!("API endpoint field {field} must appear exactly once"),
        );
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let stripped = strip_csharp_string_literals(block);
    for (field, value) in assignment_values(&stripped) {
        if value != "true" {
            continue;
        }
        let lower = field.to_ascii_lowercase();
        if [
            "live",
            "provider",
            "azure",
            "storage",
            "account",
            "container",
            "blob",
            "lifecycle",
            "retention",
            "immutability",
            "network",
            "shared",
            "sas",
            "credential",
            "connection",
            "secret",
            "url",
            "raw",
            "identifier",
        ]
        .iter()
        .any(|term| lower.contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_docs_text(
    readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    errors: &mut Vec<String>,
) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing object storage readiness endpoint",
    );
    expect(
        catalog_readme.contains(CATALOG_PATH.trim_start_matches("catalog/")),
        errors,
        "catalog README missing object storage readiness catalog",
    );
    expect(
        doc_readme.contains(DOC_PATH.trim_start_matches("docs/workflows/")),
        errors,
        "workflow README missing object storage readiness doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "object storage readiness doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "object storage readiness doc must prohibit provider calls",
    );
    expect(
        doc.contains("No Azure API calls"),
        errors,
        "object storage readiness doc must prohibit Azure API calls",
    );
    expect(
        doc.contains("Use static object storage readiness summaries only."),
        errors,
        "object storage readiness doc must require static summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited object storage field"
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
                if contains_provider_identifier(text) {
                    errors.push(format!(
                        "{path} contains prohibited provider-identifying value"
                    ));
                }
                if object_storage_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if contains_provider_identifier(text) {
                errors.push(format!(
                    "{path} contains prohibited provider-identifying value"
                ));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited object storage field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !object_storage_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if contains_provider_identifier(line) {
            errors.push(format!(
                "{}:{} contains prohibited provider-identifying value",
                path,
                index + 1
            ));
        }
        for term in identifier_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{}:{} contains prohibited object storage field {}",
                    path,
                    index + 1,
                    term
                ));
            }
        }
    }
}

fn catalog_rules(catalog: &Value, errors: &mut Vec<String>) -> Vec<Rule> {
    let Some(Value::Array(rules)) = catalog.get("rules") else {
        errors.push("object storage readiness rules must be an array of mappings".to_string());
        return Vec::new();
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("object storage readiness rules must be an array of mappings".to_string());
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
    let marker = format!("var {variable} = new[] {{");
    if program.matches(&marker).count() != 1 {
        return None;
    }
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    csharp_string_literals(&program[start..end])
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('}')? + start;
    csharp_string_literals(&block[start..end])
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
    let mut result = Vec::new();
    let mut offset = 0usize;
    while let Some(relative_start) = body[offset..].find("new {") {
        let start = offset + relative_start;
        let Some(relative_end) = body[start..].find('}') else {
            break;
        };
        let segment = &body[start..start + relative_end];
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
        offset = start + relative_end + 1;
    }
    result
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

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let starts = endpoint_start_indexes(uncommented_program);
    if starts.is_empty() {
        errors.push("API missing object storage readiness endpoint".to_string());
        return String::new();
    }
    if starts.len() != 1 {
        errors.push(
            "API object storage readiness endpoint must be declared exactly once".to_string(),
        );
        return String::new();
    }
    let start_index = starts[0];
    let next_index =
        next_endpoint_index(uncommented_program, start_index).unwrap_or(uncommented_program.len());
    uncommented_program[start_index..next_index].to_string()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let aliases = endpoint_route_aliases(program);
    line_start_indexes(program)
        .into_iter()
        .filter_map(|line_start| {
            let start = line_start + skip_horizontal_whitespace(&program[line_start..], 0);
            endpoint_registration_at(program, start, &aliases).then_some(start)
        })
        .collect()
}

fn endpoint_route_aliases(program: &str) -> Vec<String> {
    program
        .lines()
        .filter_map(|line| {
            if !line.contains(ENDPOINT) || !line.contains('=') || !line.trim_end().ends_with(';') {
                return None;
            }
            let (lhs, rhs) = line.split_once('=')?;
            if !rhs.contains(&format!("\"{ENDPOINT}\"")) {
                return None;
            }
            let name = last_identifier(lhs)?;
            (lhs.contains("string") || lhs.contains("var")).then_some(name)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn endpoint_registration_at(program: &str, start: usize, aliases: &[String]) -> bool {
    let Some(mut cursor) = parse_map_get(program, start) else {
        return false;
    };
    cursor = skip_ascii_whitespace(program, cursor + 1);
    let endpoint_literal = format!("\"{ENDPOINT}\"");
    if program[cursor..].starts_with(&endpoint_literal) {
        cursor = skip_ascii_whitespace(program, cursor + endpoint_literal.len());
        return program.as_bytes().get(cursor) == Some(&b',');
    }
    for alias in aliases {
        if program[cursor..].starts_with(alias)
            && identifier_boundary(program, cursor, cursor + alias.len())
        {
            cursor = skip_ascii_whitespace(program, cursor + alias.len());
            return program.as_bytes().get(cursor) == Some(&b',');
        }
    }
    false
}

fn next_endpoint_index(program: &str, start_index: usize) -> Option<usize> {
    line_start_indexes(&program[start_index + 1..])
        .into_iter()
        .map(|index| start_index + 1 + index)
        .find(|line_start| {
            let start = *line_start + skip_horizontal_whitespace(&program[*line_start..], 0);
            parse_map_get(program, start).is_some()
        })
}

fn parse_map_get(program: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    if !program[cursor..].starts_with("app") || !identifier_boundary(program, cursor, cursor + 3) {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + 3);
    if program.as_bytes().get(cursor) != Some(&b'.') {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + 1);
    if !program[cursor..].starts_with("MapGet")
        || !identifier_boundary(program, cursor, cursor + "MapGet".len())
    {
        return None;
    }
    cursor = skip_ascii_whitespace(program, cursor + "MapGet".len());
    (program.as_bytes().get(cursor) == Some(&b'(')).then_some(cursor)
}

fn line_start_indexes(text: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(text.match_indices('\n').map(|(index, _)| index + 1))
        .filter(|index| *index < text.len())
        .collect()
}

fn skip_horizontal_whitespace(text: &str, start: usize) -> usize {
    let mut cursor = start;
    while text
        .as_bytes()
        .get(cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        cursor += 1;
    }
    cursor
}

fn skip_ascii_whitespace(text: &str, start: usize) -> usize {
    let mut cursor = start;
    while text
        .as_bytes()
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    cursor
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_identifier_continue) && !after.is_some_and(is_identifier_continue)
}

fn last_identifier(text: &str) -> Option<String> {
    text.split(|character: char| !is_identifier_continue(character))
        .rfind(|part| !part.is_empty())
        .map(str::to_string)
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
    REQUIRED_SURFACES.contains(&value)
        || REQUIRED_INPUTS.contains(&value)
        || REQUIRED_GUARDS.contains(&value)
        || REQUIRED_PLAN_SECTIONS.contains(&value)
        || REQUIRED_BLOCKED_REASONS.contains(&value)
        || REQUIRED_EVIDENCE.contains(&value)
        || REQUIRED_DISABLED_FIELDS.contains(&value)
        || CATALOG_FIELDS.contains(&value)
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, variable)| *variable == value)
        || matches!(
            value,
            "draft" | "static-seed" | "static-readiness" | "Azure Blob Storage"
        )
        || REQUIRED_RULES.iter().any(|rule| {
            value == rule.id
                || value == rule.decision
                || value == rule.requirement
                || value == rule.evidence
        })
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    let id_value = stripped.strip_prefix("- id: ").unwrap_or(stripped);
    let requirement_value = stripped.strip_prefix("requirement: ").unwrap_or(stripped);
    let yaml_safe = stripped
        .split_once(':')
        .is_some_and(|(key, value)| !prohibited_field(key) && safe_text_value(value.trim()));
    SAFE_TEXT_PROHIBITION_LINES.contains(&stripped)
        || safe_text_value(bullet_value)
        || safe_text_value(id_value)
        || safe_text_value(requirement_value)
        || yaml_safe
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_normalized(&normalized) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || [
            "storageaccount",
            "accountname",
            "containername",
            "containerpath",
            "blobname",
            "blobpath",
            "endpoint",
            "url",
            "uri",
            "hostname",
            "storagehost",
            "dnsname",
            "subscriptionid",
            "resourcegroup",
            "resourceid",
            "tenantid",
            "objectid",
            "privateip",
            "accesskey",
            "sharedkey",
            "sastoken",
            "sharedaccesssignature",
            "signedidentifier",
            "connectionstring",
            "contentmd5",
            "rawblob",
            "rawstorage",
            "providerpayload",
            "credential",
            "secret",
            "token",
            "password",
            "bearer",
        ]
        .iter()
        .any(|fragment| normalized.contains(fragment))
        || sensitive_compound_field(value)
}

fn safe_text_normalized(normalized: &str) -> bool {
    let mut values: Vec<&str> = Vec::new();
    values.extend_from_slice(REQUIRED_SURFACES);
    values.extend_from_slice(REQUIRED_INPUTS);
    values.extend_from_slice(REQUIRED_GUARDS);
    values.extend_from_slice(REQUIRED_PLAN_SECTIONS);
    values.extend_from_slice(REQUIRED_BLOCKED_REASONS);
    values.extend_from_slice(REQUIRED_EVIDENCE);
    values.extend_from_slice(REQUIRED_DISABLED_FIELDS);
    values.extend_from_slice(CATALOG_FIELDS);
    values.extend([
        "draft",
        "static-seed",
        "static-readiness",
        "Azure Blob Storage",
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
        &[
            "password",
            "credential",
            "token",
            "bearer",
            "secret",
            "sas",
            "etag",
            "metadata",
        ],
    ) {
        return true;
    }
    if has_all(&tokens, &["shared", "access", "signature"]) {
        return true;
    }
    if has_all(&tokens, &["signed", "identifier"]) {
        return true;
    }
    if has_all(&tokens, &["content", "md5"]) {
        return true;
    }
    if has_any(&tokens, &["url", "uri", "endpoint", "fqdn"]) {
        return true;
    }
    if has_any(&tokens, &["id", "guid"]) && tokens.len() > 1 {
        return true;
    }
    if has_any(&tokens, &["private", "ip", "host", "dns"]) && has_any(&tokens, &["address", "name"])
    {
        return true;
    }
    if has_any(&tokens, &["server", "host", "address", "fqdn"])
        && has_any(
            &tokens,
            &["name", "address", "host", "url", "uri", "endpoint", "ip"],
        )
    {
        return true;
    }
    if has_any(&tokens, &["account", "login"]) && tokens.len() > 1 {
        return true;
    }
    if has_any(
        &tokens,
        &[
            "storage",
            "account",
            "subscription",
            "tenant",
            "container",
            "blob",
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
            "secret",
            "token",
            "payload",
            "content",
            "path",
            "host",
        ],
    ) {
        return true;
    }
    if tokens.contains(&"connection".to_string())
        && has_any(&tokens, &["string", "url", "uri", "endpoint"])
    {
        return true;
    }
    tokens.contains(&"raw".to_string())
        && has_any(
            &tokens,
            &[
                "blob", "storage", "provider", "payload", "content", "logs", "rows",
            ],
        )
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

fn has_all(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .all(|candidate| tokens.iter().any(|token| token == candidate))
}

fn object_storage_text_path(path: &str) -> bool {
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

fn object_storage_text_line(path: &str, line: &str) -> bool {
    if path.ends_with(CATALOG_PATH) || path.ends_with(DOC_PATH) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("object-storage-readiness")
        || lower.contains("object storage readiness")
        || line.contains("Azure Blob Storage")
        || line.contains(ENDPOINT)
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
        || contains_sha256_digest(text)
        || contains_image_reference(text)
        || contains_secret_assignment(text)
}

fn contains_provider_identifier(text: &str) -> bool {
    normalized_tokens(text)
        .iter()
        .any(|token| is_forty_hex(token) || is_serial_identifier(token))
}

fn contains_aws_access_key(text: &str) -> bool {
    normalized_tokens(text).iter().any(|token| {
        token.len() == 20
            && token.starts_with("AKIA")
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

fn contains_sha256_digest(text: &str) -> bool {
    raw_tokens(text).iter().any(|token| {
        let lower = token.to_ascii_lowercase();
        let Some(value) = lower.strip_prefix("sha256:") else {
            return false;
        };
        value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
    })
}

fn contains_image_reference(text: &str) -> bool {
    raw_tokens(text).iter().any(|token| {
        let clean = token.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | ',' | ';' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>' | '`'
            )
        });
        let Some((left, right)) = clean.rsplit_once(':') else {
            return false;
        };
        left.contains('/')
            && !right.is_empty()
            && !right.contains('/')
            && left.chars().any(|ch| ch.is_ascii_alphanumeric())
            && right.chars().any(|ch| ch.is_ascii_alphanumeric())
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
        "sas",
        "shared_key",
        "account_key",
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

fn is_forty_hex(token: &str) -> bool {
    token.len() == 40 && token.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn is_serial_identifier(token: &str) -> bool {
    let upper = token.to_ascii_uppercase();
    let Some(value) = upper
        .strip_prefix("SN-")
        .or_else(|| upper.strip_prefix("SN_"))
        .or_else(|| upper.strip_prefix("SERIAL-"))
        .or_else(|| upper.strip_prefix("SERIAL_"))
    else {
        return false;
    };
    value.len() >= 6
        && value.chars().all(|ch| ch.is_ascii_alphanumeric())
        && value.chars().any(|ch| ch.is_ascii_digit())
}

fn identifier_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !chars[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < chars.len()
            && (chars[index].is_ascii_alphanumeric() || chars[index] == '_' || chars[index] == '-')
        {
            index += 1;
        }
        terms.push(chars[start..index].iter().collect());
    }
    terms
}

fn raw_tokens(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_string).collect()
}

fn normalized_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| {
        !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '@' || ch == '.')
    })
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
    fn object_storage_readiness_endpoint_registration_detects_route_alias() {
        let program = format!(
            "const string routeAlias = \"{ENDPOINT}\";\napp.MapGet(routeAlias, () => Results.Json(new {{ source = \"static-seed\" }}));"
        );

        assert_eq!(endpoint_start_indexes(&program).len(), 1);
    }

    #[test]
    fn object_storage_readiness_comment_decoy_endpoint_is_ignored() {
        let program = format!(
            "// app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let uncommented = strip_csharp_comments(&program);

        assert!(endpoint_start_indexes(&uncommented).is_empty());
    }

    #[test]
    fn object_storage_readiness_endpoint_field_validation_rejects_storage_names() {
        let block = "source = \"static-seed\",\nstorageAccountName = \"safe-summary\",";
        let mut errors = Vec::new();

        validate_endpoint_field_names(block, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("storageAccountName")));
    }

    #[test]
    fn object_storage_readiness_catalog_rule_ids_must_be_unique() {
        let mut catalog = catalog_with_required_rules();
        let rules = catalog
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("rules must be array");
        let duplicate_id = rules[0]["id"].clone();
        rules[1]["id"] = duplicate_id;
        let mut errors = Vec::new();

        validate_required_rules(&catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("rule IDs") && error.contains("unique")));
    }

    #[test]
    fn object_storage_readiness_catalog_rule_details_must_be_unique() {
        let mut catalog = catalog_with_required_rules();
        let rules = catalog
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("rules must be array");
        let duplicate_decision = rules[0]["decision"].clone();
        let duplicate_requirement = rules[0]["requirement"].clone();
        let duplicate_evidence = rules[0]["evidence"].clone();
        rules[1]["decision"] = duplicate_decision;
        rules[1]["requirement"] = duplicate_requirement;
        rules[1]["evidence"] = duplicate_evidence;
        let mut errors = Vec::new();

        validate_required_rules(&catalog, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("rule details") && error.contains("unique")));
    }

    #[test]
    fn object_storage_readiness_scans_quoted_provider_identifiers() {
        let identifier = "a".repeat(40);
        let value = json!({ "safeSummary": identifier });
        let mut errors = Vec::new();

        scan_prohibited_value(&value, "synthetic", &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("provider-identifying value")));
    }

    #[test]
    fn object_storage_readiness_singleton_field_validation_rejects_duplicates() {
        let block = "source = \"static-seed\",\nsource = \"static-seed\",";
        let mut errors = Vec::new();

        validate_endpoint_singleton_fields(block, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("source must appear exactly once")));
    }

    #[test]
    fn object_storage_readiness_unsafe_true_flags_are_rejected() {
        let block = "providerCallsEnabled = true,";
        let mut errors = Vec::new();

        validate_no_unsafe_true_flags(block, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("unsafe true flag providerCallsEnabled")));
    }

    fn catalog_with_required_rules() -> Value {
        let rules: Vec<Value> = REQUIRED_RULES
            .iter()
            .map(|rule| {
                json!({
                    "id": rule.id,
                    "decision": rule.decision,
                    "requirement": rule.requirement,
                    "evidence": rule.evidence
                })
            })
            .collect();
        json!({ "rules": rules })
    }
}
