use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const STATUSES: &[&str] = &["draft", "active"];
const REQUIRED_KINDS: &[&str] = &[
    "adapter-credential",
    "worker-credential",
    "database-credential",
    "object-storage-credential",
    "pki-material",
    "recovery-material",
    "signing-material",
];
const REQUIRED_FIELDS: &[&str] = &[
    "schemaVersion",
    "referenceId",
    "providerId",
    "providerConfigVersion",
    "deploymentId",
    "trustDomainId",
    "kind",
    "purpose",
    "scope",
    "ownerRole",
    "consumerComponent",
    "versionSelector",
    "rotationPolicy",
    "readinessState",
    "evidenceRequirement",
];
const REQUIRED_STATES: &[&str] = &[
    "missing",
    "pending-approval",
    "configured",
    "admitted",
    "rotation-due",
    "blocked",
    "quarantined",
    "retired",
];
const REQUIRED_CONSUMERS: &[&str] = &[
    "platform-api",
    "platform-worker",
    "inventory-sync",
    "evidence-service",
    "vmware-adapter",
    "hyperv-adapter",
    "proxmox-adapter",
    "veeam-br-adapter",
    "veeam-one-adapter",
    "zabbix-adapter",
    "servicenow-adapter",
    "image-factory-controller",
    "secret-materialization-controller",
];
const REQUIRED_ROTATION_POLICIES: &[&str] = &[
    "deployment-managed",
    "scheduled-rotation",
    "emergency-rotation",
    "certificate-renewal",
    "manual-break-glass-review",
];
const REQUIRED_PROHIBITED_FIELDS: &[&str] = &[
    "value",
    "password",
    "token",
    "clientSecret",
    "privateKey",
    "tenantId",
    "objectId",
    "subscriptionId",
    "endpoint",
    "url",
];
const REQUIRED_RULES: &[&str] = &[
    "capability-registry-required",
    "provider-fallbacks-disabled",
    "provider-capabilities-admitted",
    "no-secret-values-in-reference",
    "deployment-paths-outside-catalog",
    "rotation-policy-required",
];

const REQUIRED_PROVIDER_CLASSES: &[&str] = &[
    "lease-capable-secret-service",
    "cloud-secret-manager",
    "deployment-injection",
    "enterprise-plugin-adapter",
    "development-adapter",
];
const REQUIRED_CAPABILITY_INTERFACES: &[&str] =
    &["resolve-read", "publish-version", "materialize-reload"];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    doc: String,
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
        .map_err(|error| format!("invalid secret reference context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_doc_text(&context.doc, &mut errors);
    validate_no_prohibited_shape(
        &context.catalog,
        "secret-reference-catalog",
        &mut errors,
        false,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid secret reference catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid secret reference docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_doc_text(&payload.doc, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid secret reference prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_prohibited_shape(&payload.value, &payload.path, &mut errors, false);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("secret-reference-catalog must be a mapping".to_string());
        return;
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(2),
        errors,
        "secret-reference-catalog version must be 2",
    );
    expect(
        string_value(catalog, "status").is_some_and(|status| STATUSES.contains(&status)),
        errors,
        "secret-reference-catalog status is invalid",
    );
    expect(
        string_value(catalog, "providerModel") == Some("capability-registry"),
        errors,
        "providerModel must be capability-registry",
    );
    expect(
        string_value(catalog, "managementInterface") == Some("provider-adapter"),
        errors,
        "managementInterface must be provider-adapter",
    );
    expect(
        string_value(catalog, "fallbackPolicy") == Some("disabled"),
        errors,
        "fallbackPolicy must be disabled",
    );
    for removed in ["primaryProvider", "managementCli", "futureProviders"] {
        expect(
            catalog.get(removed).is_none(),
            errors,
            format!("retired field {removed} must be absent"),
        );
    }
    validate_required_array(
        catalog,
        "admittedProviderClasses",
        REQUIRED_PROVIDER_CLASSES,
        errors,
    );
    validate_required_array(
        catalog,
        "capabilityInterfaces",
        REQUIRED_CAPABILITY_INTERFACES,
        errors,
    );
    expect(
        non_empty_string(catalog.get("referencePurpose")),
        errors,
        "referencePurpose is required",
    );
    validate_required_array(catalog, "referenceKinds", REQUIRED_KINDS, errors);
    validate_required_array(catalog, "requiredReferenceFields", REQUIRED_FIELDS, errors);
    validate_required_array(catalog, "readinessStates", REQUIRED_STATES, errors);
    validate_required_array(catalog, "allowedConsumers", REQUIRED_CONSUMERS, errors);
    validate_required_array(
        catalog,
        "rotationPolicies",
        REQUIRED_ROTATION_POLICIES,
        errors,
    );
    validate_required_array(
        catalog,
        "prohibitedFields",
        REQUIRED_PROHIBITED_FIELDS,
        errors,
    );
    validate_rules(catalog, errors);
    validate_kebab_arrays(catalog, errors);
    validate_no_provider_fallback_fields(catalog, "secret-reference-catalog", errors);
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

fn validate_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules: Vec<&Value> = catalog
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().map(String::as_str).collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .copied()
        .filter(|rule| !actual_ids.contains(rule))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("rules missing values: {}", missing.join(", ")),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "rule ids must be unique",
    );
    for (index, rule) in rules.iter().enumerate() {
        let prefix = format!("rules[{index}]");
        let id = rule.get("id").and_then(Value::as_str).unwrap_or_default();
        expect(
            is_kebab_case(id),
            errors,
            format!("{prefix} id must be kebab-case"),
        );
        expect(
            rule.get("decision").and_then(Value::as_str) == Some("block"),
            errors,
            format!("{prefix} decision must be block"),
        );
        expect(
            non_empty_string(rule.get("requirement")),
            errors,
            format!("{prefix} requirement is required"),
        );
        expect(
            non_empty_string(rule.get("evidence")),
            errors,
            format!("{prefix} evidence is required"),
        );
    }
}

fn validate_kebab_arrays(catalog: &Value, errors: &mut Vec<String>) {
    for field in [
        "admittedProviderClasses",
        "referenceKinds",
        "readinessStates",
        "allowedConsumers",
        "rotationPolicies",
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
        text.contains(
            "Secret references let platform code and manifests point to runtime-resolved material",
        ),
        errors,
        "secret reference doc must define purpose",
    );
    expect(
        text.contains("Secret references use the platform's capability registry"),
        errors,
        "secret reference doc must state capability-registry provider direction",
    );
    expect(
        text.contains("there is no universal runtime provider"),
        errors,
        "secret reference doc must prohibit a universal runtime provider",
    );
    expect(
        text.contains("Resolution, dynamic issuance, lease control, key custody"),
        errors,
        "secret reference doc must separate provider capabilities",
    );
    expect(
        text.contains("Adapters and workers fail closed"),
        errors,
        "secret reference doc must require fail-closed behavior",
    );
}

fn validate_no_prohibited_shape(
    value: &Value,
    path: &str,
    errors: &mut Vec<String>,
    allow_prohibited_field_list: bool,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                let allowed_key = path == "secret-reference-catalog" && key == "prohibitedFields";
                if !allowed_key && key == "prohibitedFields" {
                    errors.push(format!("{child_path} uses non-root prohibitedFields"));
                }
                if !allowed_key && prohibited_key(key) {
                    errors.push(format!(
                        "{child_path} uses prohibited secret-bearing key name"
                    ));
                }
                validate_no_prohibited_shape(child, &child_path, errors, allowed_key);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_prohibited_shape(
                    child,
                    &format!("{path}[{index}]"),
                    errors,
                    allow_prohibited_field_list,
                );
            }
        }
        Value::String(text) if !allow_prohibited_field_list && prohibited_value(text) => {
            errors.push(format!("{path} contains prohibited value"));
        }
        _ => {}
    }
}

fn prohibited_key(key: &str) -> bool {
    let key_text = key.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "token",
        "clientsecret",
        "client_secret",
        "client-secret",
        "tenantid",
        "tenant_id",
        "tenant-id",
        "objectid",
        "object_id",
        "object-id",
        "subscriptionid",
        "subscription_id",
        "subscription-id",
        "privatekey",
        "private_key",
        "private-key",
        "value",
    ]
    .iter()
    .any(|suffix| key_text.ends_with(suffix))
        || {
            let segments = key_segments(key);
            segments
                .iter()
                .any(|segment| segment == "endpoint" || segment == "url")
                || segments
                    .windows(2)
                    .any(|window| window[0] == "end" && window[1] == "point")
        }
}

fn validate_no_provider_fallback_fields(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                let normalized = key_segments(key).join("-");
                if [
                    "future-providers",
                    "fallback-providers",
                    "secondary-provider",
                    "legacy-provider",
                    "provider-fallbacks",
                ]
                .contains(&normalized.as_str())
                {
                    errors.push(format!("{child_path} declares a retired provider fallback"));
                }
                validate_no_provider_fallback_fields(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_provider_fallback_fields(child, &format!("{path}[{index}]"), errors);
            }
        }
        _ => {}
    }
}

fn key_segments(key: &str) -> Vec<String> {
    let mut spaced = String::with_capacity(key.len() * 2);
    let mut previous: Option<char> = None;
    let mut chars = key.chars().peekable();
    while let Some(ch) = chars.next() {
        let next = chars.peek().copied();
        if let Some(prev) = previous {
            if (prev.is_ascii_lowercase() || prev.is_ascii_digit()) && ch.is_ascii_uppercase()
                || prev.is_ascii_uppercase()
                    && ch.is_ascii_uppercase()
                    && next.is_some_and(|next_ch| next_ch.is_ascii_lowercase())
            {
                spaced.push(' ');
            }
        }
        if ch.is_ascii_alphanumeric() {
            spaced.push(ch.to_ascii_lowercase());
        } else {
            spaced.push(' ');
        }
        previous = Some(ch);
    }
    spaced.split_whitespace().map(str::to_string).collect()
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

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_and_url_key_variants_are_segmented() {
        assert!(prohibited_key("endpointAlias"));
        assert!(prohibited_key("urlReference"));
        assert!(prohibited_key("primaryEndpoint"));
        assert!(prohibited_key("end_point"));
        assert!(!prohibited_key("curlCommand"));
        assert!(!prohibited_key("scurlHandle"));
    }

    #[test]
    fn provider_names_are_allowed_but_fallback_fields_are_not() {
        let allowed = serde_json::json!({
            "admittedProviders": ["hashicorp-vault", "openbao", "cyberark"]
        });
        let mut errors = Vec::new();
        validate_no_provider_fallback_fields(&allowed, "catalog", &mut errors);
        assert!(
            errors.is_empty(),
            "provider products are not fallback semantics"
        );

        let retired = serde_json::json!({"fallbackProviders": ["example"]});
        validate_no_provider_fallback_fields(&retired, "catalog", &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("retired provider fallback")));
    }
}
