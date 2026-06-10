use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/cmdb-file-exchange-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const DOC_PATH: &str = "docs/workflows/cmdb-file-exchange.md";
const ENDPOINT: &str = "/api/integrations/servicenow/cmdb-file-contract";
const REQUIRED_FIELDS: &[&str] = &[
    "ciName",
    "fqdn",
    "ciClass",
    "lifecycleStatus",
    "environment",
    "application",
    "businessOwner",
    "technicalOwner",
    "supportGroup",
    "country",
    "siteCode",
    "datacenter",
    "osFamily",
    "osVersion",
    "criticality",
    "patchGroup",
    "maintenanceWindow",
    "rebootPolicy",
    "backupPolicy",
    "monitoringProfile",
    "relationshipKey",
];
const REQUIRED_WORKBOOK_SHAPE: &[&str] = &[
    "worksheet-count-one",
    "row-count-fifteen",
    "data-row-count-fourteen",
    "column-count-twenty-eight",
];
const REQUIRED_SANITIZED_FIELD_CATEGORIES: &[&str] = &[
    "identity",
    "ownership",
    "classification",
    "governance-evidence",
    "operating-system",
    "lifecycle",
    "service-context",
    "location",
    "normalized-fallback",
];
const REQUIRED_NORMALIZED_HEADER_EXPECTATIONS: &[&str] = &[
    "actual-headers-remain-deployment-configuration",
    "map-to-normalized-import-fields",
    "unmapped-columns-require-review",
    "duplicate-normalized-fields-require-review",
    "actual-header-value-storage-disabled",
];
const REQUIRED_SYNTHETIC_CATEGORY_EXAMPLES: &[&str] = &[
    "identity synthetic-ci-name",
    "ownership synthetic-business-owner",
    "classification synthetic-ci-class",
    "governance-evidence synthetic-file-hash-reference",
    "operating-system synthetic-os-family",
    "lifecycle synthetic-lifecycle-state",
    "service-context synthetic-environment",
    "location synthetic-site-code",
    "normalized-fallback synthetic-review-note",
];
const REQUIRED_EXPORT_FIELDS: &[&str] = &[
    "ciName",
    "changeReason",
    "proposedLifecycleStatus",
    "proposedOwner",
    "proposedSupportGroup",
    "proposedBackupPolicy",
    "proposedMonitoringProfile",
    "evidenceReferences",
];
const REQUIRED_IMPORT_EVIDENCE: &[&str] = &[
    "File hash",
    "Header mapping",
    "Validation result",
    "Accepted row count",
    "Rejected rows",
    "Import user",
    "Evidence references",
];
const REQUIRED_EXPORT_EVIDENCE: &[&str] = &[
    "Request payload summary",
    "Validation result",
    "Export package",
    "Accepted/rejected rows",
    "Reviewer approval",
    "Evidence references",
];
const REQUIRED_REJECTIONS: &[&str] = &[
    "missing-ci-identity",
    "ambiguous-ci-identity",
    "unknown-site-code",
    "missing-owner",
    "missing-support-group",
    "invalid-environment",
    "missing-evidence-reference",
];
const REQUIRED_SOURCE_WORKBOOK_POLICY: &[(&str, PolicyValue)] = &[
    (
        "sourceRef",
        PolicyValue::Text("source-ref-deployment-servicenow-cmdb-workbook"),
    ),
    ("sourceFoundState", PolicyValue::Text("source-found")),
    ("sourceMissingState", PolicyValue::Text("source-missing")),
    ("missingSourceDecision", PolicyValue::Text("block")),
    (
        "headerMappingReview",
        PolicyValue::Text("normalized-field-review"),
    ),
    (
        "fileHashEvidence",
        PolicyValue::Text("required-before-preview"),
    ),
    ("sourceRowCaptureEnabled", PolicyValue::Bool(false)),
    ("actualHeaderValueStorage", PolicyValue::Text("disabled")),
];
const REQUIRED_RULE_DETAILS: &[(&str, &str, &str, &str)] = &[
    (
        "no-live-servicenow-api",
        "block",
        "CMDB exchange uses files only until live ServiceNow API integration is approved.",
        "Validation result",
    ),
    (
        "header-mapping-required",
        "block",
        "Actual spreadsheet headers must map to normalized fields before preview or import.",
        "Header mapping",
    ),
    (
        "row-level-evidence-required",
        "block",
        "Accepted and rejected rows must be counted and preserved as redacted evidence references.",
        "Accepted/rejected rows",
    ),
    (
        "source-reference-only",
        "block",
        "Supplied CMDB Excel source must be referenced only by sourceRef with file hash evidence and normalized header mapping review.",
        "File hash",
    ),
    (
        "source-missing-blocker",
        "block",
        "Missing CMDB Excel source must produce source-missing and block preview or import.",
        "Validation result",
    ),
    (
        "workbook-row-capture-disabled",
        "block",
        "Workbook row capture remains disabled for source-found and source-missing handling.",
        "Validation result",
    ),
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "integrationMode",
    "liveApiEnabled",
    "providerCallsEnabled",
    "sourceSystem",
    "targetUse",
    "sourceWorkbookPolicy",
    "workbookShape",
    "sanitizedFieldCategories",
    "normalizedHeaderExpectations",
    "syntheticCategoryExamples",
    "normalizedImportFields",
    "requiredImportEvidence",
    "exportPackageFields",
    "requiredExportEvidence",
    "rejectionReasons",
    "rules",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const SOURCE_WORKBOOK_POLICY_KEYS: &[&str] = &[
    "sourceRef",
    "sourceFoundState",
    "sourceMissingState",
    "missingSourceDecision",
    "headerMappingReview",
    "fileHashEvidence",
    "sourceRowCaptureEnabled",
    "actualHeaderValueStorage",
];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("workbookShape", "cmdbWorkbookShape"),
    ("sanitizedFieldCategories", "cmdbSanitizedFieldCategories"),
    (
        "normalizedHeaderExpectations",
        "cmdbNormalizedHeaderExpectations",
    ),
    ("syntheticCategoryExamples", "cmdbSyntheticCategoryExamples"),
    ("normalizedImportFields", "cmdbNormalizedImportFields"),
    ("rejectionReasons", "cmdbRejectionReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &[
    "requiredImportEvidence",
    "exportPackageFields",
    "requiredExportEvidence",
];
const BASE_ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "integrationMode",
    "liveApiEnabled",
    "providerCallsEnabled",
    "workbookShape",
    "sanitizedFieldCategories",
    "normalizedHeaderExpectations",
    "syntheticCategoryExamples",
    "normalizedImportFields",
    "requiredImportEvidence",
    "exportPackageFields",
    "requiredExportEvidence",
    "rejectionReasons",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "url",
    "endpoint",
    "tenant",
    "object",
    "sysid",
    "privateip",
    "payload",
    "row",
    "rows",
];
const PROHIBITED_FIELD_NEEDLES: &[&str] = &[
    "password",
    "credential",
    "secret",
    "token",
    "bearer",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "principalid",
    "principalidentifier",
    "privateip",
    "privatenetwork",
    "providerpayload",
    "rawprovider",
    "rawcmdb",
    "cmdbrow",
    "rawrow",
    "rawrows",
    "rawpayload",
    "payload",
    "instanceid",
    "instanceidentifier",
    "tableid",
    "tableidentifier",
    "sysid",
    "sysidentifier",
    "servicenowinstance",
    "endpointurl",
    "url",
    "username",
    "userid",
    "useridentifier",
];
const ALLOWED_POLICY_TEXT_LINES: &[&str] = &[
    "- No ServiceNow instance identifiers, user credentials, tokens, table sys identifiers, object identifiers, private network details, or raw CMDB rows in committed files.",
    "- Row-level outcomes are evidence references, not raw spreadsheet payloads.",
    "The optional CMDB Excel source is represented by a neutral `sourceRef` only: `source-ref-deployment-servicenow-cmdb-workbook`. Operator-supplied workbook files remain outside committed artifacts, and committed guidance must not copy workbook filenames, workbook header values, or workbook rows.",
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    program: String,
    api_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct CatalogInput {
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    api_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: Option<String>,
}

#[derive(Copy, Clone)]
enum PolicyValue {
    Text(&'static str),
    Bool(bool),
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid CMDB file exchange context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_no_tracked_source_workbook_reference(&context.catalog, CATALOG_PATH, &mut errors);
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(&context.api_readme, &context.doc, &mut errors);
    validate_no_tracked_source_workbook_reference(
        &Value::String(context.doc.clone()),
        DOC_PATH,
        &mut errors,
    );
    let mut file_scope = Map::new();
    file_scope.insert(CATALOG_PATH.to_string(), context.catalog);
    file_scope.insert(PROGRAM_PATH.to_string(), Value::String(context.program));
    file_scope.insert(
        API_README_PATH.to_string(),
        Value::String(context.api_readme),
    );
    file_scope.insert(DOC_PATH.to_string(), Value::String(context.doc));
    validate_no_prohibited_values_at(
        &Value::Object(file_scope),
        "cmdb-file-exchange",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let payload: CatalogInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB file exchange catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB file exchange program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB file exchange docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.api_readme, &payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid CMDB file exchange prohibited scan JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values_at(
        &payload.value,
        payload.path.as_deref().unwrap_or("cmdb-file-exchange"),
        &mut errors,
    );
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    let Some(object) = catalog.as_object() else {
        errors.push("cmdb file exchange catalog must be object".to_string());
        return;
    };
    validate_catalog_keys(object, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "cmdb file exchange version must be 1",
    );
    expect(
        value_string(catalog, "status") == Some("draft"),
        errors,
        "cmdb file exchange status must be draft",
    );
    expect(
        value_string(catalog, "integrationMode") == Some("file-based"),
        errors,
        "cmdb exchange must be file-based",
    );
    expect(
        catalog.get("liveApiEnabled").and_then(Value::as_bool) == Some(false),
        errors,
        "cmdb live API must be disabled",
    );
    expect(
        catalog.get("providerCallsEnabled").and_then(Value::as_bool) == Some(false),
        errors,
        "cmdb provider calls must be disabled",
    );
    expect(
        value_string(catalog, "sourceSystem") == Some("ServiceNow CMDB export"),
        errors,
        "cmdb source system must be ServiceNow CMDB export",
    );
    expect(
        value_string(catalog, "targetUse") == Some("import-preview-validate-export"),
        errors,
        "cmdb target use must be import-preview-validate-export",
    );
    validate_source_workbook_policy(catalog.get("sourceWorkbookPolicy"), errors);
    validate_required_array(catalog, "workbookShape", REQUIRED_WORKBOOK_SHAPE, errors);
    validate_required_array(
        catalog,
        "sanitizedFieldCategories",
        REQUIRED_SANITIZED_FIELD_CATEGORIES,
        errors,
    );
    validate_required_array(
        catalog,
        "normalizedHeaderExpectations",
        REQUIRED_NORMALIZED_HEADER_EXPECTATIONS,
        errors,
    );
    validate_required_array(
        catalog,
        "syntheticCategoryExamples",
        REQUIRED_SYNTHETIC_CATEGORY_EXAMPLES,
        errors,
    );
    validate_required_array(catalog, "normalizedImportFields", REQUIRED_FIELDS, errors);
    validate_required_array(
        catalog,
        "requiredImportEvidence",
        REQUIRED_IMPORT_EVIDENCE,
        errors,
    );
    validate_required_array(
        catalog,
        "exportPackageFields",
        REQUIRED_EXPORT_FIELDS,
        errors,
    );
    validate_required_array(
        catalog,
        "requiredExportEvidence",
        REQUIRED_EXPORT_EVIDENCE,
        errors,
    );
    validate_required_array(catalog, "rejectionReasons", REQUIRED_REJECTIONS, errors);
    validate_required_rules(catalog, errors);
    validate_no_tracked_source_workbook_reference(catalog, CATALOG_PATH, errors);
    validate_no_prohibited_values_at(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(object: &Map<String, Value>, errors: &mut Vec<String>) {
    let allowed: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "cmdb file exchange unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_source_workbook_policy(policy: Option<&Value>, errors: &mut Vec<String>) {
    let Some(object) = policy.and_then(Value::as_object) else {
        errors.push("cmdb source workbook policy must be present".to_string());
        return;
    };
    let allowed: BTreeSet<&str> = SOURCE_WORKBOOK_POLICY_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    let present: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let missing: Vec<&str> = SOURCE_WORKBOOK_POLICY_KEYS
        .iter()
        .copied()
        .filter(|key| !present.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "cmdb source workbook policy unexpected keys: {}",
            unexpected.join(", ")
        ));
    }
    if !missing.is_empty() {
        errors.push(format!(
            "cmdb source workbook policy missing keys: {}",
            missing.join(", ")
        ));
    }
    for (field, expected_value) in REQUIRED_SOURCE_WORKBOOK_POLICY {
        let matches = match expected_value {
            PolicyValue::Text(expected) => object
                .get(*field)
                .and_then(Value::as_str)
                .is_some_and(|actual| actual == *expected),
            PolicyValue::Bool(expected) => object
                .get(*field)
                .and_then(Value::as_bool)
                .is_some_and(|actual| actual == *expected),
        };
        expect(
            matches,
            errors,
            &format!("cmdb source workbook policy {field} must match"),
        );
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = value_string_array(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        &format!("{field} must be non-empty array"),
    );
    let missing: Vec<&str> = required_values
        .iter()
        .copied()
        .filter(|value| !values.iter().any(|actual| actual == value))
        .collect();
    let required_set: BTreeSet<&str> = required_values.iter().copied().collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|value| !required_set.contains(value))
        .collect();
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
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        &format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited cmdb file exchange value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut rule_ids = Vec::new();
    let mut rule_details = Vec::new();
    for rule in &rules {
        if let Some(id) = rule.get("id").and_then(Value::as_str) {
            rule_ids.push(id.to_string());
        }
        if let Some(object) = rule.as_object() {
            let allowed: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
            let present: BTreeSet<&str> = object.keys().map(String::as_str).collect();
            let unexpected: Vec<&str> = object
                .keys()
                .map(String::as_str)
                .filter(|key| !allowed.contains(key))
                .collect();
            let missing: Vec<&str> = RULE_KEYS
                .iter()
                .copied()
                .filter(|key| !present.contains(key))
                .collect();
            let id = rule
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("(missing id)");
            if !unexpected.is_empty() {
                errors.push(format!(
                    "cmdb file exchange rule {id} unexpected rule keys: {}",
                    unexpected.join(", ")
                ));
            }
            if !missing.is_empty() {
                errors.push(format!(
                    "cmdb file exchange rule {id} missing rule keys: {}",
                    missing.join(", ")
                ));
            }
            if let (Some(decision), Some(requirement), Some(evidence)) = (
                rule.get("decision").and_then(Value::as_str),
                rule.get("requirement").and_then(Value::as_str),
                rule.get("evidence").and_then(Value::as_str),
            ) {
                rule_details.push(format!("{decision}\0{requirement}\0{evidence}"));
            }
        }
    }
    let required_rules: Vec<&str> = REQUIRED_RULE_DETAILS
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect();
    let missing: Vec<&str> = required_rules
        .iter()
        .copied()
        .filter(|id| !rule_ids.iter().any(|actual| actual == id))
        .collect();
    let required_set: BTreeSet<&str> = required_rules.iter().copied().collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .map(String::as_str)
        .filter(|id| !required_set.contains(id))
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "cmdb file exchange missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "cmdb file exchange unexpected rules: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "cmdb file exchange rule IDs must be unique",
    );
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "cmdb file exchange rule details must be unique",
    );
    for (id, expected_decision, expected_requirement, expected_evidence) in REQUIRED_RULE_DETAILS {
        let rule = rules
            .iter()
            .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(*id));
        let Some(rule) = rule else { continue };
        expect(
            rule.get("decision").and_then(Value::as_str) == Some(*expected_decision),
            errors,
            &format!("cmdb file exchange rule {id} decision must match"),
        );
        expect(
            rule.get("requirement").and_then(Value::as_str) == Some(*expected_requirement),
            errors,
            &format!("cmdb file exchange rule {id} requirement must match"),
        );
        expect(
            rule.get("evidence").and_then(Value::as_str) == Some(*expected_evidence),
            errors,
            &format!("cmdb file exchange rule {id} evidence must match"),
        );
    }
}

fn validate_program_text(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    validate_no_interpolated_string_decoys(program, errors);
    let uncommented_program = csharp_without_comments(program);
    expect(
        active_endpoint_count(&uncommented_program) == 1,
        errors,
        &format!("API must register exactly one {ENDPOINT} endpoint"),
    );
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
        exact_string_assignment(&block, "integrationMode", "file-based"),
        errors,
        "API must keep file-based integration mode",
    );
    expect(
        exact_endpoint_assignment(&block, "liveApiEnabled", "false"),
        errors,
        "API must keep liveApiEnabled disabled",
    );
    expect(
        exact_endpoint_assignment(&block, "providerCallsEnabled", "false"),
        errors,
        "API must keep providerCallsEnabled disabled",
    );
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        expect(
            exact_endpoint_assignment(&block, field, variable),
            errors,
            &format!("API must bind {field} to {variable}"),
        );
        validate_api_array_binding(
            &uncommented_program,
            field,
            variable,
            &value_string_array(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        let values = endpoint_inline_array_values(&block, field, errors);
        validate_api_array(field, values, &value_string_array(catalog, field), errors);
    }
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_no_prohibited_values_at(&Value::String(block), PROGRAM_PATH, errors);
}

fn validate_api_array_binding(
    program: &str,
    field: &str,
    variable: &str,
    catalog_values: &[String],
    errors: &mut Vec<String>,
) {
    validate_endpoint_array_variable_not_mutated(program, field, variable, errors);
    validate_api_array(
        field,
        csharp_array_values(program, variable, errors),
        catalog_values,
        errors,
    );
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
    let missing: Vec<&str> = catalog_values
        .iter()
        .map(String::as_str)
        .filter(|value| !values.iter().any(|actual| actual == value))
        .collect();
    let catalog_set: BTreeSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|value| !catalog_set.contains(value))
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
        &format!("API {field} values must be unique"),
    );
}

fn validate_docs_text(readme: &str, doc: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing CMDB file endpoint",
    );
    expect(
        doc.contains("No live ServiceNow API calls."),
        errors,
        "CMDB doc must prohibit live ServiceNow API calls",
    );
    expect(
        doc.contains("Actual spreadsheet headers are deployment configuration"),
        errors,
        "CMDB doc must keep actual headers deployment-specific",
    );
    expect(
        doc.contains("not raw spreadsheet payloads"),
        errors,
        "CMDB doc must reject raw spreadsheet payloads",
    );
    expect(
        doc.contains("source-found"),
        errors,
        "CMDB doc must describe source-found handling",
    );
    expect(
        doc.contains("source-missing"),
        errors,
        "CMDB doc must describe source-missing handling",
    );
    expect(
        doc.contains("sourceRef"),
        errors,
        "CMDB doc must use sourceRef for workbook reference",
    );
    expect(
        doc.contains("workbook row extraction disabled"),
        errors,
        "CMDB doc must disable workbook row extraction",
    );
    expect(
        doc.contains("file hash evidence"),
        errors,
        "CMDB doc must require file hash evidence",
    );
    expect(
        doc.contains("local task-state or queue notes only"),
        errors,
        "CMDB doc must keep source candidate metadata local-only",
    );
    expect(
        doc.contains("sanitized field categories"),
        errors,
        "CMDB doc must describe sanitized field categories",
    );
    expect(
        doc.contains("worksheet-count-one"),
        errors,
        "CMDB doc must describe sanitized workbook shape",
    );
    expect(
        doc.contains("syntheticCategoryExamples"),
        errors,
        "CMDB doc must describe synthetic category examples",
    );
    validate_no_tracked_source_workbook_reference(
        &Value::String(doc.to_string()),
        DOC_PATH,
        errors,
    );
}

fn validate_no_tracked_source_workbook_reference(
    value: &Value,
    path: &str,
    errors: &mut Vec<String>,
) {
    for fragment in source_reference_text_fragments(value) {
        if contains_workbook_reference(&fragment) {
            errors.push(format!(
                "{path} contains tracked workbook filename or spreadsheet path"
            ));
        }
    }
}

fn source_reference_text_fragments(value: &Value) -> Vec<String> {
    match value {
        Value::Object(object) => object
            .iter()
            .flat_map(|(key, child)| {
                let mut fragments = vec![key.to_string()];
                fragments.extend(source_reference_text_fragments(child));
                fragments
            })
            .collect(),
        Value::Array(values) => values
            .iter()
            .flat_map(source_reference_text_fragments)
            .collect(),
        Value::String(text) => text.lines().map(|line| line.trim().to_string()).collect(),
        other => vec![other.to_string()],
    }
}

fn endpoint_block(uncommented_program: &str, errors: &mut Vec<String>) -> String {
    let Some(start) = endpoint_start_indexes(uncommented_program).first().copied() else {
        errors.push("API missing CMDB file contract endpoint".to_string());
        return String::new();
    };
    let search_start = uncommented_program[start..]
        .find('\n')
        .map(|offset| start + offset + 1)
        .unwrap_or(uncommented_program.len());
    let masked_program = csharp_string_segments_masked(uncommented_program);
    let next_start = map_get_start_indexes(&masked_program[search_start..])
        .first()
        .map(|offset| search_start + offset)
        .unwrap_or(uncommented_program.len());
    uncommented_program[start..next_start].to_string()
}

fn csharp_string_segments_masked(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(delimiter) = raw_string_delimiter_at(text, index) {
            let end = raw_string_end_index(text, index, delimiter);
            append_masked_csharp_string(&mut output, &text[index..end]);
            index = end;
        } else if let Some(start_length) = verbatim_string_start_length(text, index) {
            let end = verbatim_string_end_index(text, index, start_length);
            append_masked_csharp_string(&mut output, &text[index..end]);
            index = end;
        } else if in_string {
            output.push(if byte == b'\n' { '\n' } else { ' ' });
            if byte == b'\\' {
                if let Some(next) = bytes.get(index + 1) {
                    output.push(if *next == b'\n' { '\n' } else { ' ' });
                    index += 2;
                    continue;
                }
            }
            if byte == b'"' {
                in_string = false;
            }
            index += 1;
        } else if byte == b'"' {
            output.push(' ');
            in_string = true;
            index += 1;
        } else {
            output.push(byte as char);
            index += 1;
        }
    }
    output
}

fn active_endpoint_count(uncommented_program: &str) -> usize {
    endpoint_start_indexes(uncommented_program).len()
}

fn endpoint_start_indexes(program: &str) -> Vec<usize> {
    let mut indexes = Vec::new();
    let mut offset = 0;
    for line in program.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.contains(".MapGet(") && trimmed.contains(&format!("\"{ENDPOINT}\"")) {
            indexes.push(offset + (line.len() - trimmed.len()));
        }
        offset += line.len();
    }
    indexes
}

fn map_get_start_indexes(program: &str) -> Vec<usize> {
    let mut indexes = Vec::new();
    let mut offset = 0;
    for line in program.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.contains(".MapGet(") {
            indexes.push(offset + (line.len() - trimmed.len()));
        }
        offset += line.len();
    }
    indexes
}

fn validate_no_interpolated_string_decoys(program: &str, errors: &mut Vec<String>) {
    for segment in interpolated_strings(program) {
        if segment.contains(ENDPOINT)
            || contains_any(
                &segment,
                &[
                    "liveApiEnabled",
                    "providerCallsEnabled",
                    "MapGet",
                    "Results.Json",
                ],
            )
        {
            errors.push(
                "API must not hide CMDB file exchange endpoint or safety controls inside interpolated strings"
                    .to_string(),
            );
        }
    }
}

fn interpolated_strings(text: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut index = 0;
    while index < text.len() {
        if let Some(delimiter) = raw_string_delimiter_at(text, index) {
            let end = raw_string_end_index(text, index, delimiter);
            if delimiter.0 > 0 {
                segments.push(text[index..end].to_string());
            }
            index = end;
        } else if let Some(start_length) = verbatim_string_start_length(text, index) {
            let end = verbatim_string_end_index(text, index, start_length);
            if text[index..].starts_with("$\"")
                || text[index..].starts_with("$@\"")
                || text[index..].starts_with("@$\"")
            {
                segments.push(text[index..end].to_string());
            }
            index = end;
        } else {
            index += 1;
        }
    }
    segments
}

fn csharp_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        let char = bytes[index] as char;
        let next = bytes.get(index + 1).map(|byte| *byte as char);
        if in_string {
            output.push(char);
            if char == '\\' {
                if let Some(next_char) = next {
                    output.push(next_char);
                    index += 2;
                    continue;
                }
            }
            if char == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if let Some(delimiter) = raw_string_delimiter_at(text, index) {
            let end = raw_string_end_index(text, index, delimiter);
            append_masked_csharp_string(&mut output, &text[index..end]);
            index = end;
        } else if let Some(start_length) = verbatim_string_start_length(text, index) {
            let end = verbatim_string_end_index(text, index, start_length);
            append_masked_csharp_string(&mut output, &text[index..end]);
            index = end;
        } else if char == '"' {
            in_string = true;
            output.push(char);
            index += 1;
        } else if char == '/' && next == Some('/') {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() && bytes[index] as char != '\n' {
                output.push(' ');
                index += 1;
            }
        } else if char == '/' && next == Some('*') {
            output.push_str("  ");
            index += 2;
            while index < bytes.len() {
                if bytes[index] as char == '*'
                    && bytes.get(index + 1).map(|byte| *byte as char) == Some('/')
                {
                    output.push_str("  ");
                    index += 2;
                    break;
                }
                output.push(if bytes[index] as char == '\n' {
                    '\n'
                } else {
                    ' '
                });
                index += 1;
            }
        } else {
            output.push(char);
            index += 1;
        }
    }
    output
}

fn raw_string_delimiter_at(text: &str, index: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut dollar_count = 0;
    while bytes.get(index + dollar_count) == Some(&b'$') {
        dollar_count += 1;
    }
    let quote_index = index + dollar_count;
    if bytes.get(quote_index) != Some(&b'"') {
        return None;
    }
    let mut quote_count = 0;
    while bytes.get(quote_index + quote_count) == Some(&b'"') {
        quote_count += 1;
    }
    (quote_count >= 3).then_some((dollar_count, quote_count))
}

fn raw_string_end_index(text: &str, start_index: usize, delimiter: (usize, usize)) -> usize {
    let delimiter_text = "\"".repeat(delimiter.1);
    let body_start = start_index + delimiter.0 + delimiter.1;
    text[body_start..]
        .find(&delimiter_text)
        .map(|offset| body_start + offset + delimiter.1)
        .unwrap_or(text.len())
}

fn verbatim_string_start_length(text: &str, index: usize) -> Option<usize> {
    let tail = &text[index..];
    if tail.starts_with("@\"") {
        Some(2)
    } else if tail.starts_with("$@\"") || tail.starts_with("@$\"") {
        Some(3)
    } else {
        None
    }
}

fn verbatim_string_end_index(text: &str, start_index: usize, start_length: usize) -> usize {
    let bytes = text.as_bytes();
    let mut index = start_index + start_length;
    while index < bytes.len() {
        if bytes[index] == b'"' && bytes.get(index + 1) == Some(&b'"') {
            index += 2;
        } else if bytes[index] == b'"' {
            return index + 1;
        } else {
            index += 1;
        }
    }
    text.len()
}

fn append_masked_csharp_string(output: &mut String, segment: &str) {
    for char in segment.chars() {
        output.push(if char == '\n' { '\n' } else { ' ' });
    }
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let start = exact_array_declaration_start(program, variable)?;
    let after_marker = &program[start + "var ".len() + variable.len()..];
    let equals = after_marker.find('=')?;
    let after_equals = after_marker[equals + 1..].trim_start();
    if !after_equals.starts_with("new[]") {
        return None;
    }
    let absolute_after_equals =
        start + "var ".len() + variable.len() + equals + 1 + after_marker[equals + 1..].len()
            - after_equals.len();
    let open = program[absolute_after_equals..].find('{')? + absolute_after_equals;
    let close = program[open + 1..].find("};")? + open + 1;
    let body = &program[open + 1..close];
    if !string_literal_array_body(body) {
        errors.push(format!(
            "API {variable} array must contain only string literals"
        ));
    }
    Some(csharp_string_literals(body))
}

fn exact_array_declaration_start(program: &str, variable: &str) -> Option<usize> {
    let mut offset = 0;
    for line in program.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("var ") {
            if let Some(after_name) = rest.strip_prefix(variable) {
                if after_name
                    .trim_start()
                    .strip_prefix('=')
                    .is_some_and(|tail| tail.trim_start().starts_with("new[]"))
                {
                    return Some(offset + line.len() - trimmed.len());
                }
            }
        }
        offset += line.len();
    }
    None
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    if endpoint_assignment_count(block, field) != 1 {
        errors.push(format!("API {field} inline array must be declared once"));
        return None;
    }
    let assignment = find_field_assignment(block, field)?;
    let after = block[assignment..].find("new[]")? + assignment;
    let open = block[after..].find('{')? + after;
    let close = block[open + 1..].find('}')? + open + 1;
    let body = &block[open + 1..close];
    let tail_end = next_endpoint_property_offset(&block[close + 1..])
        .map(|offset| close + 1 + offset)
        .unwrap_or(block.len());
    let tail = &block[close + 1..tail_end];
    if !tail.trim().is_empty() && tail.trim() != "," {
        errors.push(format!(
            "API {field} inline array assignment must terminate after closing brace or comma"
        ));
    }
    if !string_literal_array_body(body) {
        errors.push(format!(
            "API {field} array must contain only string literals"
        ));
    }
    Some(csharp_string_literals(body))
}

fn next_endpoint_property_offset(text: &str) -> Option<usize> {
    let allowed: BTreeSet<&str> = BASE_ALLOWED_ENDPOINT_FIELDS.iter().copied().collect();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("}));") {
            return Some(offset + line.len() - trimmed.len());
        }
        if let Some(field) = leading_assignment_field(trimmed) {
            if allowed.contains(field.as_str()) {
                return Some(offset + line.len() - trimmed.len());
            }
        }
        offset += line.len();
    }
    None
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut values = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        index += 1;
        let mut value = String::new();
        while index < bytes.len() {
            let char = bytes[index] as char;
            if char == '\\' {
                if let Some(next) = bytes.get(index + 1) {
                    value.push(*next as char);
                    index += 2;
                    continue;
                }
            }
            if char == '"' {
                index += 1;
                break;
            }
            value.push(char);
            index += 1;
        }
        values.push(value);
    }
    values
}

fn string_literal_array_body(body: &str) -> bool {
    strip_csharp_string_literals(body)
        .replace("\"\"", "")
        .chars()
        .all(|char| char == ',' || char.is_whitespace())
}

fn validate_endpoint_array_variable_not_mutated(
    program: &str,
    field: &str,
    variable: &str,
    errors: &mut Vec<String>,
) {
    let Some(declaration_start) = exact_array_declaration_start(program, variable) else {
        return;
    };
    let declaration_end = program[declaration_start..]
        .find("};")
        .map(|offset| declaration_start + offset + 2)
        .unwrap_or(declaration_start);
    let remaining = strip_csharp_string_literals(&program[declaration_end..]);
    for line in remaining.lines() {
        if !line.contains(variable) {
            continue;
        }
        let trimmed = line.trim();
        if trimmed == format!("{field} = {variable},") || trimmed == format!("{field} = {variable}")
        {
            continue;
        }
        errors.push(format!(
            "API {variable} array binding must not be mutated, reassigned, or transformed after declaration"
        ));
        return;
    }
}

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    endpoint_assignment_count(block, field) == 1
        && block.lines().any(|line| {
            let trimmed = line.trim();
            trimmed == format!("{field} = {value},") || trimmed == format!("{field} = {value}")
        })
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    endpoint_assignment_count(block, field) == 1
        && block.lines().any(|line| {
            let trimmed = line.trim();
            trimmed == format!("{field} = \"{value}\",")
                || trimmed == format!("{field} = \"{value}\"")
        })
}

fn endpoint_assignment_count(block: &str, field: &str) -> usize {
    let stripped = strip_csharp_string_literals(block);
    assignment_fields(&stripped)
        .iter()
        .filter(|candidate| candidate.as_str() == field)
        .count()
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let allowed: BTreeSet<&str> = BASE_ALLOWED_ENDPOINT_FIELDS.iter().copied().collect();
    for field in assignment_fields(&strip_csharp_string_literals(block)) {
        if allowed.contains(field.as_str()) {
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited cmdb file exchange field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected cmdb file exchange field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for line in strip_csharp_string_literals(block).lines() {
        let Some(field) = leading_assignment_field(line.trim_start()) else {
            continue;
        };
        let lower = line.to_ascii_lowercase();
        if lower.contains("true")
            && normalized_contains_any(
                &field,
                &[
                    "live",
                    "provider",
                    "raw",
                    "credential",
                    "secret",
                    "token",
                    "tenant",
                    "object",
                    "principal",
                    "private",
                    "user",
                    "identifier",
                    "sys",
                    "row",
                    "payload",
                    "mutation",
                    "api",
                    "allowed",
                    "enabled",
                ],
            )
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_no_prohibited_values_at(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if prohibited_field(key) {
                    errors.push(format!(
                        "{path}.{key} contains prohibited cmdb file exchange field"
                    ));
                }
                validate_no_prohibited_values_at(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_prohibited_values_at(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                validate_whole_file_text(text, path, errors);
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text)
                || prohibited_text(text)
                || prohibited_header_capture_text(text)
            {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited cmdb file exchange value {text}"
                ));
            }
        }
        _ => {}
    }
}

fn safe_text_value(value: &str) -> bool {
    let mut safe = BTreeSet::new();
    for values in [
        REQUIRED_FIELDS,
        REQUIRED_WORKBOOK_SHAPE,
        REQUIRED_SANITIZED_FIELD_CATEGORIES,
        REQUIRED_NORMALIZED_HEADER_EXPECTATIONS,
        REQUIRED_SYNTHETIC_CATEGORY_EXAMPLES,
        REQUIRED_EXPORT_FIELDS,
        REQUIRED_IMPORT_EVIDENCE,
        REQUIRED_EXPORT_EVIDENCE,
        REQUIRED_REJECTIONS,
        REQUIRED_CATALOG_KEYS,
        RULE_KEYS,
        SOURCE_WORKBOOK_POLICY_KEYS,
        &[
            "static-seed",
            "draft",
            "file-based",
            "import-preview-validate-export",
            "false",
            "ServiceNow CMDB export",
        ],
    ] {
        for item in values {
            safe.insert(*item);
        }
    }
    for (id, decision, requirement, evidence) in REQUIRED_RULE_DETAILS {
        safe.insert(*id);
        safe.insert(*decision);
        safe.insert(*requirement);
        safe.insert(*evidence);
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        safe.insert(*field);
        safe.insert(*variable);
    }
    for field in BASE_ALLOWED_ENDPOINT_FIELDS {
        safe.insert(*field);
    }
    for (field, policy_value) in REQUIRED_SOURCE_WORKBOOK_POLICY {
        safe.insert(*field);
        if let PolicyValue::Text(text) = policy_value {
            safe.insert(*text);
        }
    }
    safe.contains(value)
}

fn prohibited_field(value: &str) -> bool {
    if safe_text_value(value) {
        return false;
    }
    let normalized = normalize_identifier(value);
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || PROHIBITED_FIELD_NEEDLES
            .iter()
            .any(|needle| normalized.contains(needle))
        || prohibited_capture_field(&normalized)
}

fn prohibited_capture_field(normalized: &str) -> bool {
    (normalized.starts_with("raw")
        && (normalized.contains("row") || normalized.contains("payload")))
        || (normalized.contains("header")
            && contains_any(
                normalized,
                &[
                    "value", "values", "name", "names", "sample", "samples", "capture",
                ],
            )
            && contains_any(
                normalized,
                &["actual", "raw", "source", "workbook", "header"],
            ))
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn validate_whole_file_text(value: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in whole_file_scan_text(value, path).lines().enumerate() {
        let scan_line = line.trim();
        if scan_line.is_empty() {
            continue;
        }
        if prohibited_value(scan_line)
            || ((prohibited_text(scan_line) || prohibited_header_capture_text(scan_line))
                && !ALLOWED_POLICY_TEXT_LINES.contains(&scan_line))
        {
            errors.push(format!("{path}:{} contains prohibited value", index + 1));
        }
    }
}

fn whole_file_scan_text(value: &str, path: &str) -> String {
    if path.ends_with(PROGRAM_PATH) && value.contains(ENDPOINT) {
        return endpoint_block(&csharp_without_comments(value), &mut Vec::new());
    }
    value.to_string()
}

fn prohibited_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let upper = value.to_ascii_uppercase();
    upper.contains("AKIA")
        || upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
        || lower.contains("://")
        || contains_private_ip(value)
        || contains_uuid(value)
        || [
            "password",
            "client_secret",
            "access_token",
            "refresh_token",
            "bearer",
            "token",
        ]
        .iter()
        .any(|key| lower.contains(&format!("{key}=")) || lower.contains(&format!("{key}:")))
}

fn prohibited_text(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    contains_any(
        &normalized,
        &[
            "rawcmdbrow",
            "rawcmdbrows",
            "rawcmdbpayload",
            "rawcmdbpayloads",
            "rawspreadsheetrow",
            "rawspreadsheetrows",
            "rawspreadsheetpayload",
            "rawspreadsheetpayloads",
            "sysid",
            "tenantid",
            "tenantids",
            "tenantidentifier",
            "tenantidentifiers",
            "objectid",
            "objectids",
            "objectidentifier",
            "objectidentifiers",
            "principalid",
            "principalids",
            "principalidentifier",
            "principalidentifiers",
            "instanceid",
            "instanceids",
            "instanceidentifier",
            "instanceidentifiers",
            "tableid",
            "tableids",
            "tableidentifier",
            "tableidentifiers",
        ],
    )
}

fn prohibited_header_capture_text(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    contains_any(
        &normalized,
        &[
            "actualheader",
            "rawheader",
            "sourceheader",
            "workbookheader",
        ],
    ) && contains_any(
        &normalized,
        &[
            "value", "values", "name", "names", "sample", "samples", "capture",
        ],
    )
}

fn contains_workbook_reference(fragment: &str) -> bool {
    let lower = fragment.to_ascii_lowercase();
    lower.contains(".xlsx") || lower.contains("cmdb_ci_server.xlsx")
}

fn value_string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn value_string_array(value: &Value, field: &str) -> Vec<String> {
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

fn find_field_assignment(block: &str, field: &str) -> Option<usize> {
    let mut offset = 0;
    for line in block.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if leading_assignment_field(trimmed).as_deref() == Some(field) {
            return Some(offset + line.len() - trimmed.len());
        }
        offset += line.len();
    }
    None
}

fn assignment_fields(stripped: &str) -> Vec<String> {
    let mut fields = Vec::new();
    for line in stripped.lines() {
        if let Some(field) = leading_assignment_field(line.trim_start()) {
            fields.push(field);
        }
    }
    fields
}

fn leading_assignment_field(line: &str) -> Option<String> {
    let mut chars = line.chars().peekable();
    let first = chars.peek().copied()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    let mut field = String::new();
    while let Some(char) = chars.peek().copied() {
        if char.is_ascii_alphanumeric() || char == '_' {
            field.push(char);
            chars.next();
        } else {
            break;
        }
    }
    while chars.peek().is_some_and(|char| char.is_whitespace()) {
        chars.next();
    }
    (chars.peek() == Some(&'=')).then_some(field)
}

fn strip_csharp_string_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            output.push(bytes[index] as char);
            index += 1;
            continue;
        }
        output.push_str("\"\"");
        index += 1;
        while index < bytes.len() {
            if bytes[index] == b'\\' {
                index += 2;
            } else if bytes[index] == b'"' {
                index += 1;
                break;
            } else {
                index += 1;
            }
        }
    }
    output
}

fn contains_private_ip(value: &str) -> bool {
    for token in value.split(|char: char| !(char.is_ascii_digit() || char == '.')) {
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 4 {
            continue;
        }
        let octets: Option<Vec<u8>> = parts.iter().map(|part| part.parse::<u8>().ok()).collect();
        let Some(octets) = octets else { continue };
        if octets[0] == 10
            || (octets[0] == 192 && octets[1] == 168)
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        {
            return true;
        }
    }
    false
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|char: char| !(char.is_ascii_hexdigit() || char == '-'))
        .any(|token| {
            token.len() == 36
                && [8, 13, 18, 23]
                    .iter()
                    .all(|index| token.as_bytes()[*index] == b'-')
                && token.chars().enumerate().all(|(index, char)| {
                    [8, 13, 18, 23].contains(&index) || char.is_ascii_hexdigit()
                })
        })
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|char| char.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn normalized_contains_any(value: &str, needles: &[&str]) -> bool {
    let normalized = normalize_identifier(value);
    needles.iter().any(|needle| normalized.contains(needle))
}

fn expect(condition: bool, errors: &mut Vec<String>, message: &str) {
    if !condition {
        errors.push(message.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csharp_comment_stripping_preserves_comment_markers_inside_strings() {
        let source = r#"
var first = "synthetic // marker"; var second = "kept";
var third = "synthetic /* marker */ kept"; var fourth = "also kept";
var fifth = "kept"; // removed comment
"#;

        let stripped = csharp_without_comments(source);

        assert!(stripped.contains("var second = \"kept\";"));
        assert!(stripped.contains("synthetic /* marker */ kept"));
        assert!(stripped.contains("var fourth = \"also kept\";"));
        assert!(!stripped.contains("removed comment"));
    }

    #[test]
    fn non_interpolated_endpoint_string_decoys_do_not_count_as_routes() {
        let decoy = format!(
            r#"
var rawEndpointDecoy = """
app.MapGet("{ENDPOINT}", () => Results.Json(new
{{
    source = "static-seed",
    integrationMode = "file-based",
    liveApiEnabled = false,
    providerCallsEnabled = false
}}));
""";

var verbatimEndpointDecoy = @"app.MapGet(""{ENDPOINT}"", () => Results.Json(new
{{
    source = ""static-seed"",
    integrationMode = ""file-based"",
    liveApiEnabled = false,
    providerCallsEnabled = false
}}));";
"#
        );

        assert_eq!(0, active_endpoint_count(&csharp_without_comments(&decoy)));
    }

    #[test]
    fn safe_policy_text_stays_allowed_while_raw_capture_fields_are_rejected() {
        assert!(safe_text_value(
            "source-ref-deployment-servicenow-cmdb-workbook"
        ));
        assert!(!prohibited_field(
            "source-ref-deployment-servicenow-cmdb-workbook"
        ));
        assert!(prohibited_field("actualHeaderValues"));
        assert!(prohibited_field("rawWorkbookRowsCaptured"));
    }
}
