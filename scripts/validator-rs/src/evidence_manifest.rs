use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const STATUSES: &[&str] = &["draft", "active"];
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
    "Vault initialization material",
    "raw provider payloads",
    "unfiltered logs",
    "stack traces",
    "private network addresses",
    "raw recipient data",
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    access_catalog: Value,
    offering_catalog: Value,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct CatalogInput {
    catalog: Value,
    access_catalog: Value,
    offering_catalog: Value,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid evidence manifest context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(
        &context.catalog,
        &context.access_catalog,
        &context.offering_catalog,
        &mut errors,
    );
    validate_doc_text(&context.doc, &mut errors);
    validate_no_prohibited_values(&context.catalog, "evidence-manifest-catalog", &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let payload: CatalogInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence manifest catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(
        &payload.catalog,
        &payload.access_catalog,
        &payload.offering_catalog,
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence manifest docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_doc_text(&payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid evidence manifest prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(
    catalog: &Value,
    access_catalog: &Value,
    offering_catalog: &Value,
    errors: &mut Vec<String>,
) {
    if !catalog.is_object() {
        errors.push("evidence-manifest-catalog must be a mapping".to_string());
        return;
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "evidence-manifest-catalog version must be 1",
    );
    expect(
        string_value(catalog, "status").is_some_and(|status| STATUSES.contains(&status)),
        errors,
        "evidence-manifest-catalog status is invalid",
    );
    expect(
        non_empty_string(catalog.get("manifestPurpose")),
        errors,
        "manifestPurpose is required",
    );
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
    validate_record_types(catalog, access_catalog, offering_catalog, errors);
    validate_kebab_arrays(catalog, errors);
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
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|item| !value_set.contains(item))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("{field} missing values: {}", missing.join(", ")),
    );
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
}

fn validate_record_types(
    catalog: &Value,
    access_catalog: &Value,
    offering_catalog: &Value,
    errors: &mut Vec<String>,
) {
    let record_types = string_array_like(catalog, "recordTypes");
    let record_set: BTreeSet<&str> = record_types.iter().map(String::as_str).collect();
    let access_records = access_required_records(access_catalog);
    let offering_records = offering_evidence_records(offering_catalog);
    let missing_access: Vec<&str> = access_records
        .iter()
        .map(String::as_str)
        .filter(|record| !record_set.contains(record))
        .collect();
    let missing_offering: Vec<&str> = offering_records
        .iter()
        .map(String::as_str)
        .filter(|record| !record_set.contains(record))
        .collect();

    expect(
        !record_types.is_empty(),
        errors,
        "recordTypes must be non-empty array",
    );
    expect(
        missing_access.is_empty(),
        errors,
        format!(
            "recordTypes must cover access evidence records: {}",
            missing_access.join(", ")
        ),
    );
    expect(
        missing_offering.is_empty(),
        errors,
        format!(
            "recordTypes must cover offering evidence records: {}",
            missing_offering.join(", ")
        ),
    );
    expect(
        record_set.contains("Redacted execution log"),
        errors,
        "recordTypes must include Redacted execution log",
    );
    expect(
        record_set.contains("Evidence references"),
        errors,
        "recordTypes must include Evidence references",
    );
}

fn validate_kebab_arrays(catalog: &Value, errors: &mut Vec<String>) {
    for field in [
        "redactionStates",
        "exportReadiness",
        "requiredRedactionChecks",
        "safeExportTargets",
        "retentionClasses",
    ] {
        for value in string_array_like(catalog, field) {
            expect(
                is_kebab_case(&value),
                errors,
                format!("{field} value {value:?} must be kebab-case"),
            );
        }
    }
}

fn validate_doc_text(text: &str, errors: &mut Vec<String>) {
    expect(
        text.contains("Evidence manifests are indexes for redacted records"),
        errors,
        "evidence redaction doc must define manifest purpose",
    );
    expect(
        text.contains("Failed redaction blocks export"),
        errors,
        "evidence redaction doc must block failed redaction export",
    );
    expect(
        text.contains("raw provider payloads are not stored"),
        errors,
        "evidence redaction doc must reject raw provider payloads",
    );
}

fn validate_no_prohibited_values(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                validate_no_prohibited_values(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_prohibited_values(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) if prohibited_value(text) => {
            errors.push(format!("{path} contains prohibited value"));
        }
        _ => {}
    }
}

fn access_required_records(access_catalog: &Value) -> Vec<String> {
    access_catalog
        .get("evidenceProfile")
        .and_then(|profile| profile.get("requiredRecords"))
        .map(string_array_from_value)
        .unwrap_or_default()
}

fn offering_evidence_records(offering_catalog: &Value) -> Vec<String> {
    let mut records = BTreeSet::new();
    if let Some(offerings) = offering_catalog.get("offerings").and_then(Value::as_array) {
        for offering in offerings {
            for record in offering
                .get("evidence")
                .map(string_array_from_value)
                .unwrap_or_default()
            {
                records.insert(record);
            }
        }
    }
    records.into_iter().collect()
}

fn prohibited_value(text: &str) -> bool {
    text.contains("://")
        || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
        || text.contains("AKIA")
        || contains_private_ip(text)
        || contains_uuid_like(text)
        || contains_secret_assignment(text)
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            let octets: Vec<u16> = candidate
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect();
            octets.len() == 4
                && octets.iter().all(|octet| *octet <= 255)
                && (octets[0] == 10
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1])))
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

fn is_kebab_case(value: &str) -> bool {
    let mut previous_dash = false;
    let mut saw_char = false;
    for ch in value.chars() {
        if ch == '-' {
            if previous_dash || !saw_char {
                return false;
            }
            previous_dash = true;
        } else if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            saw_char = true;
            previous_dash = false;
        } else {
            return false;
        }
    }
    saw_char && !previous_dash
}

fn non_empty_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn string_array_like(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .map(string_array_from_value)
        .unwrap_or_default()
}

fn string_array_from_value(value: &Value) -> Vec<String> {
    match value {
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Value::String(text) => vec![text.to_string()],
        _ => Vec::new(),
    }
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
    fn assignment_pattern_rejects_bearer_values() {
        let bearer_assignment = format!("{}={}", "bearer", "unsafevalue");
        let client_secret_assignment = format!("{}: {}", "client_secret", "unsafevalue");
        assert!(prohibited_value(&bearer_assignment));
        assert!(prohibited_value(&client_secret_assignment));
        assert!(!prohibited_value("bearer material"));
    }
}
