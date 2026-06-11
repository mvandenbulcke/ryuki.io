use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const ENDPOINT: &str = "/api/observe/synthetic-health-check-contract";

const REQUIRED_ROUTES: &[&str] = &[
    "/api/observe/synthetic-health-check-contract",
    "/api/observe/synthetic/run/{check_id}",
    "/api/observe/synthetic/run-all",
    "/api/observe/synthetic/status/{check_id}",
    "/api/observe/synthetic/dashboard",
    "/api/observe/synthetic/outages",
];

const REQUIRED_HANDLERS: &[&str] = &[
    "observe_synthetic_health_check_contract",
    "synthetic_run_check",
    "synthetic_run_all",
    "synthetic_status",
    "synthetic_dashboard",
    "synthetic_outages",
];

const REQUIRED_ENGINE_FUNCTIONS: &[&str] = &[
    "run_check",
    "run_all_checks",
    "get_check_status",
    "get_dashboard",
    "get_outage_report",
];

const PROHIBITED_KEYS: &[&str] = &[
    "hostname",
    "hostidentifier",
    "username",
    "userid",
    "useridentifier",
    "credential",
    "secret",
    "token",
    "password",
    "tenantid",
    "tenantidentifier",
    "objectid",
    "objectidentifier",
    "liveendpoint",
    "endpointurl",
    "targeturl",
    "url",
    "privateip",
    "privatenetwork",
    "rawprobe",
    "rawalert",
    "alertpayload",
    "certificateserial",
    "serialnumber",
    "providerpayload",
    "sessionid",
    "checkid",
    "jobid",
];

#[derive(Debug, Deserialize)]
struct Context {
    catalog: Value,
    lib_rs: String,
    contracts_rs: String,
    synthetic_health_rs: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct CatalogInput {
    catalog: Value,
    lib_rs: String,
    contracts_rs: String,
    synthetic_health_rs: String,
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
        .map_err(|error| format!("invalid synthetic health check context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_lib_rs(&context.lib_rs, &mut errors);
    validate_synthetic_health_rs(&context.synthetic_health_rs, &mut errors);
    validate_contracts_rs(&context.contracts_rs, &mut errors);
    scan_prohibited_value(
        &context.catalog,
        "catalog/synthetic-health-check-contract.yaml",
        &mut errors,
    );
    scan_prohibited_text(
        &context.doc,
        "docs/workflows/synthetic-health-checks.md",
        &mut errors,
    );
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let context: CatalogInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid synthetic health check catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    validate_lib_rs(&context.lib_rs, &mut errors);
    validate_synthetic_health_rs(&context.synthetic_health_rs, &mut errors);
    validate_contracts_rs(&context.contracts_rs, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    validate_catalog_json(input)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    validate_catalog_json(input)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid synthetic health check prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("synthetic health check catalog must be a mapping".to_string());
        return;
    }
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "synthetic health check version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "synthetic health check status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "synthetic health check source must be static-seed",
    );
    expect(
        bool_value(catalog, "dryRunRequired") == Some(true),
        errors,
        "synthetic health check must require dry-run",
    );
    expect(
        bool_value(catalog, "providerCallsEnabled") == Some(false),
        errors,
        "synthetic health check provider calls must be disabled",
    );
    expect(
        bool_value(catalog, "liveChecksAllowed") == Some(false),
        errors,
        "synthetic health check live checks must be disabled",
    );
    expect(
        bool_value(catalog, "externalProbesAllowed") == Some(false),
        errors,
        "synthetic health check external probes must be disabled",
    );
    expect(
        bool_value(catalog, "zabbixMutationAllowed") == Some(false),
        errors,
        "synthetic health check Zabbix mutation must be disabled",
    );
    expect(
        bool_value(catalog, "rawProbeOutputAllowed") == Some(false),
        errors,
        "synthetic health check raw probe output must be disabled",
    );
}

fn validate_lib_rs(lib_rs: &str, errors: &mut Vec<String>) {
    expect(
        lib_rs.contains("pub mod synthetic_health;"),
        errors,
        "ryuki-engine lib.rs missing synthetic_health module declaration",
    );
}

fn validate_synthetic_health_rs(source: &str, errors: &mut Vec<String>) {
    for func in REQUIRED_ENGINE_FUNCTIONS {
        expect(
            source.contains(&format!("pub fn {func}")),
            errors,
            format!("synthetic_health module missing function: {func}"),
        );
    }
    expect(
        source.contains("DRY-RUN"),
        errors,
        "synthetic_health module must produce DRY-RUN output",
    );
}

fn validate_contracts_rs(contracts_rs: &str, errors: &mut Vec<String>) {
    for route in REQUIRED_ROUTES {
        expect(
            contracts_rs.contains(route),
            errors,
            format!("contracts.rs missing route: {route}"),
        );
    }
    for handler in REQUIRED_HANDLERS {
        expect(
            contracts_rs.contains(&format!("fn {handler}")),
            errors,
            format!("contracts.rs missing handler: {handler}"),
        );
    }
    expect(
        contracts_rs.contains("use ryuki_engine::synthetic_health;"),
        errors,
        "contracts.rs missing synthetic_health import",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_key(key) {
                    errors.push(format!("{child_path} contains prohibited provider field"));
                }
                scan_prohibited_value(child, &child_path, errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => scan_prohibited_text(text, path, errors),
        _ => {}
    }
}

fn scan_prohibited_text(text: &str, path: &str, errors: &mut Vec<String>) {
    if prohibited_value(text) {
        errors.push(format!("{path} contains prohibited value"));
    }
    for identifier in text_identifiers(text) {
        if prohibited_key(&identifier) {
            errors.push(format!("{path} contains prohibited field {identifier}"));
        }
    }
}

fn text_identifiers(text: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'-')
            {
                index += 1;
            }
            identifiers.push(text[start..index].to_ascii_lowercase());
        } else {
            index += 1;
        }
    }
    let unique: BTreeSet<String> = identifiers.into_iter().collect();
    unique.into_iter().collect()
}

fn prohibited_key(key: &str) -> bool {
    let normalized = key
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    PROHIBITED_KEYS.contains(&normalized.as_str())
        || PROHIBITED_KEYS.iter().any(|term| normalized.contains(term))
}

fn prohibited_value(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("://")
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || lower.contains("akia")
        || contains_private_ip(&lower)
        || contains_uuid_like(&lower)
        || contains_secret_assignment(&lower)
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
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    .iter()
    .any(|term| {
        text.find(term).is_some_and(|index| {
            let tail = text[index + term.len()..].trim_start();
            matches!(tail.as_bytes().first(), Some(b':') | Some(b'='))
                && tail[1..].chars().any(|ch| !ch.is_whitespace())
        })
    })
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sources_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn read_sources_file(path: &str) -> String {
        std::fs::read_to_string(sources_root().join(path)).unwrap_or_default()
    }

    #[test]
    fn lib_rs_declares_synthetic_health() {
        let lib_rs = read_sources_file("sources/ryuki-engine/src/lib.rs");
        let synthetic_health_rs = read_sources_file("sources/ryuki-engine/src/synthetic_health.rs");
        let mut errors = Vec::new();
        validate_lib_rs(&lib_rs, &mut errors);
        validate_synthetic_health_rs(&synthetic_health_rs, &mut errors);
        assert!(
            errors.is_empty(),
            "synthetic_health validation errors: {:?}",
            errors
        );
    }

    #[test]
    fn contracts_rs_has_all_routes_and_handlers() {
        let contracts_rs = read_sources_file("sources/ryuki-api/src/contracts.rs");
        let mut errors = Vec::new();
        validate_contracts_rs(&contracts_rs, &mut errors);
        assert!(
            errors.is_empty(),
            "contracts.rs synthetic health validation errors: {:?}",
            errors
        );
    }
}
