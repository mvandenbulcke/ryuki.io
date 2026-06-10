use crate::yaml_utils::validate_yaml_duplicate_keys_text;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const REQUIRED_SERVICES: &[&str] = &["platform-api", "platform-db", "portal-ui"];
const ALLOWED_TOP_LEVEL_KEYS: &[&str] = &["name", "networks", "services", "volumes"];
const PROHIBITED_SERVICE_KEYS: &[&str] = &[
    "additional_hosts",
    "container_name",
    "dns",
    "external_links",
    "extra_hosts",
    "hostname",
    "links",
    "mac_address",
    "network_mode",
    "networks",
    "privileged",
    "profiles",
    "secrets",
];
const PROHIBITED_KEY_PARTS: &[&str] = &[
    "accesskey",
    "accesstoken",
    "apikey",
    "bearer",
    "clientsecret",
    "credential",
    "endpoint",
    "host",
    "hostname",
    "objectid",
    "password",
    "privateip",
    "providertenantid",
    "refreshtoken",
    "secret",
    "serial",
    "subscriptionid",
    "tenantid",
    "token",
    "uri",
    "url",
];
const SAFE_TEXT_VALUES: &[&str] = &[
    "ryuki-infrastructure-platform",
    "Dockerfile",
    "platform",
    "ryuki-net",
    "bridge",
    "platform-api",
    "platform-db",
    "ryuki/platform-api:rust-dev",
    "ryuki/portal-ui:rust-dev",
    "postgres:16-alpine",
    "sources/ryuki-api/Dockerfile",
    "portal/portal-ui/Dockerfile",
    "../..",
    "18080:8080",
    "18000:8080",
    "5432:5432",
    "http://localhost:8080/health",
    "http://localhost:3000/health",
];
const SECRET_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
];
const HOST_ASSIGNMENT_KEYS: &[&str] = &["host", "hostname", "fqdn", "serial"];

const PLATFORM_DB_ENV_WHITELIST: &[&str] = &["POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"];
const PLATFORM_API_ENV_WHITELIST: &[&str] = &[
    "DATABASE_URL",
    "ENTRA_TENANT_ID",
    "ENTRA_CLIENT_ID",
    "ENTRA_AUTHORITY",
    "PLATFORM_NAME",
    "PLATFORM_URL",
    "AUTH_MODE",
    "API_BIND_ADDR",
];

#[derive(Debug, Deserialize)]
struct Context {
    compose: Value,
}

#[derive(Debug, Deserialize)]
struct ComposeInput {
    compose: Value,
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
        .map_err(|error| format!("invalid compose context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_compose_value(&context.compose, &mut errors);
    scan_prohibited_value(&context.compose, "compose", &mut errors);
    Ok(errors)
}

pub fn validate_values_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ComposeInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid compose values JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_compose_value(&payload.compose, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid compose prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_compose_value(compose: &Value, errors: &mut Vec<String>) {
    expect(
        object_keys(compose) == key_set(ALLOWED_TOP_LEVEL_KEYS),
        errors,
        "compose top-level keys must be exactly name, services, networks",
    );
    expect(
        str_at(compose, &["name"]) == Some("ryuki-infrastructure-platform"),
        errors,
        "compose name must be ryuki-infrastructure-platform",
    );

    let services = object_at(compose, &["services"]);
    expect(
        services
            .map(|value| object_keys(value) == key_set(REQUIRED_SERVICES))
            .unwrap_or(false),
        errors,
        format!(
            "compose services must be exactly {}",
            REQUIRED_SERVICES.join(", ")
        ),
    );

    for service_name in REQUIRED_SERVICES {
        let service = services.and_then(|value| value.get(*service_name));
        validate_service(service_name, service, errors);
    }

    expect(
        compose
            .get("services")
            .and_then(|s| s.get("portal-ui"))
            .and_then(|p| p.get("depends_on"))
            .and_then(|d| d.get("platform-api"))
            .and_then(|a| a.get("condition"))
            .and_then(|c| c.as_str())
            == Some("service_healthy"),
        errors,
        "portal-ui must depend on platform-api with condition service_healthy",
    );
    expect(
        compose
            .get("services")
            .and_then(|s| s.get("platform-api"))
            .and_then(|p| p.get("depends_on"))
            .and_then(|d| d.get("platform-db"))
            .and_then(|a| a.get("condition"))
            .and_then(|c| c.as_str())
            == Some("service_healthy"),
        errors,
        "platform-api must depend on platform-db with condition service_healthy",
    );
    expect(
        object_at(compose, &["networks"])
            .map(|value| object_keys(value) == key_set(&["ryuki-net"]))
            .unwrap_or(false),
        errors,
        "compose networks must be exactly ryuki-net",
    );
    expect(
        str_at(compose, &["networks", "ryuki-net", "driver"]) == Some("bridge"),
        errors,
        "ryuki-net network must use bridge driver",
    );
    expect(
        object_at(compose, &["networks", "ryuki-net"])
            .map(|value| object_keys(value) == key_set(&["driver"]))
            .unwrap_or(false)
            && str_at(compose, &["networks", "ryuki-net", "driver"]) == Some("bridge"),
        errors,
        "ryuki-net network must define only bridge driver",
    );
}

fn validate_service(service_name: &str, service: Option<&Value>, errors: &mut Vec<String>) {
    let allowed_keys = allowed_service_keys(service_name);
    expect(
        service
            .map(|value| object_keys(value) == key_set(allowed_keys))
            .unwrap_or(false),
        errors,
        format!(
            "{service_name} service keys must be exactly {}",
            allowed_keys.join(", ")
        ),
    );
    if let Some(service) = service {
        validate_no_prohibited_service_keys(service_name, service, errors);
    }
    if service_has_build(service_name) {
        expect(
            service.and_then(|value| str_at(value, &["build", "context"]))
                == Some(allowed_context(service_name)),
            errors,
            format!("{service_name} build context is invalid"),
        );
        expect(
            service.and_then(|value| str_at(value, &["build", "dockerfile"]))
                == Some(allowed_dockerfile(service_name)),
            errors,
            format!("{service_name} Dockerfile path is invalid"),
        );
        expect(
            service
                .and_then(|value| object_at(value, &["build"]))
                .map(|value| object_keys(value) == key_set(&["context", "dockerfile"]))
                .unwrap_or(false),
            errors,
            format!("{service_name} build keys must be exactly context, dockerfile"),
        );
    }
    expect(
        service.and_then(|value| str_at(value, &["image"])) == Some(allowed_image(service_name)),
        errors,
        format!("{service_name} image must be local placeholder"),
    );
    expect(
        string_array_at_required(service, &["ports"]) == Some(allowed_ports(service_name)),
        errors,
        format!("{service_name} ports are invalid"),
    );
    expect(
        string_array_at_required(service, &["networks"]) == Some(vec!["ryuki-net".to_string()]),
        errors,
        format!("{service_name} must use ryuki-net network only"),
    );
}

fn validate_no_prohibited_service_keys(
    service_name: &str,
    service: &Value,
    errors: &mut Vec<String>,
) {
    let Some(map) = service.as_object() else {
        return;
    };
    for key in PROHIBITED_SERVICE_KEYS {
        if *key == "networks"
            && string_array_at_required(Some(service), &["networks"])
                == Some(vec!["ryuki-net".to_string()])
        {
            continue;
        }
        if service_name == "platform-db" && (*key == "environment" || *key == "volumes") {
            continue;
        }
        if service_name == "platform-api" && (*key == "environment") {
            continue;
        }
        if map.contains_key(*key) {
            errors.push(format!("{service_name} must not define {key} in skeleton"));
        }
    }
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let in_platform_db_env = path.ends_with("platform-db.environment")
                    || path.ends_with("services.platform-db.environment");
                let is_db_env_whitelisted =
                    in_platform_db_env && PLATFORM_DB_ENV_WHITELIST.contains(&key.as_str());
                let in_platform_api_env = path.ends_with("platform-api.environment")
                    || path.ends_with("services.platform-api.environment");
                let is_api_env_whitelisted =
                    in_platform_api_env && PLATFORM_API_ENV_WHITELIST.contains(&key.as_str());
                if !is_db_env_whitelisted && !is_api_env_whitelisted && prohibited_key(key) {
                    errors.push(format!("{path}.{key} contains prohibited key"));
                }
                scan_prohibited_value(child, &format!("{path}.{key}"), errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if SAFE_TEXT_VALUES.contains(&text.as_str()) {
                return;
            }
            if contains_prohibited_value(text) || contains_hostname_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
        }
        _ => {}
    }
}

fn allowed_service_keys(service_name: &str) -> &'static [&'static str] {
    match service_name {
        "platform-api" => &[
            "build",
            "depends_on",
            "env_file",
            "environment",
            "healthcheck",
            "image",
            "networks",
            "ports",
        ],
        "portal-ui" => &[
            "build",
            "depends_on",
            "healthcheck",
            "image",
            "networks",
            "ports",
        ],
        "platform-db" => &[
            "environment",
            "healthcheck",
            "image",
            "networks",
            "ports",
            "volumes",
        ],
        _ => &[],
    }
}

fn allowed_context(service_name: &str) -> &'static str {
    match service_name {
        "platform-api" | "portal-ui" => "../..",
        _ => "",
    }
}

fn allowed_dockerfile(service_name: &str) -> &'static str {
    match service_name {
        "platform-api" => "sources/ryuki-api/Dockerfile",
        "portal-ui" => "portal/portal-ui/Dockerfile",
        _ => "",
    }
}

fn allowed_image(service_name: &str) -> &'static str {
    match service_name {
        "platform-api" => "ryuki/platform-api:rust-dev",
        "portal-ui" => "ryuki/portal-ui:rust-dev",
        "platform-db" => "postgres:16-alpine",
        _ => "",
    }
}

fn allowed_ports(service_name: &str) -> Vec<String> {
    match service_name {
        "platform-api" => vec!["18080:8080".to_string()],
        "portal-ui" => vec!["18000:8080".to_string()],
        "platform-db" => vec!["5432:5432".to_string()],
        _ => Vec::new(),
    }
}

fn service_has_build(service_name: &str) -> bool {
    matches!(service_name, "platform-api" | "portal-ui")
}

fn object_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_object()?;
    Some(current)
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn string_array_at_required(value: Option<&Value>, path: &[&str]) -> Option<Vec<String>> {
    let mut current = value?;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(ToString::to_string))
            .collect(),
        Value::String(text) => Some(vec![text.to_string()]),
        _ => None,
    }
}

fn object_keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

fn key_set(keys: &[&str]) -> BTreeSet<String> {
    keys.iter().map(|key| key.to_string()).collect()
}

fn prohibited_key(value: &str) -> bool {
    let normalized: String = value
        .to_ascii_lowercase()
        .chars()
        .filter(|candidate| candidate.is_ascii_alphanumeric())
        .collect();
    PROHIBITED_KEY_PARTS
        .iter()
        .any(|part| normalized.contains(part))
}

fn contains_prohibited_value(text: &str) -> bool {
    contains_aws_access_key(text)
        || contains_private_key_header(text)
        || contains_url(text)
        || contains_ipv4(text)
        || contains_uuid(text)
        || HOST_ASSIGNMENT_KEYS
            .iter()
            .any(|key| contains_assignment(text, key))
        || SECRET_ASSIGNMENT_KEYS
            .iter()
            .any(|key| contains_assignment(text, key))
}

fn contains_aws_access_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    for window in bytes.windows(20) {
        if window[0..4].eq_ignore_ascii_case(b"AKIA")
            && window[4..20]
                .iter()
                .all(|value| value.is_ascii_digit() || value.is_ascii_uppercase())
        {
            return true;
        }
    }
    false
}

fn contains_private_key_header(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

fn contains_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(offset) = lower[search_from..].find("://") {
        let marker = search_from + offset;
        let scheme_start = lower[..marker]
            .char_indices()
            .rev()
            .find(|(_, value)| !(value.is_ascii_alphanumeric() || matches!(value, '+' | '.' | '-')))
            .map(|(index, value)| index + value.len_utf8())
            .unwrap_or(0);
        let scheme = &lower[scheme_start..marker];
        if scheme
            .chars()
            .next()
            .map(|value| value.is_ascii_alphabetic())
            .unwrap_or(false)
            && scheme
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '.' | '-'))
            && lower[marker + 3..]
                .chars()
                .next()
                .map(|value| !value.is_whitespace())
                .unwrap_or(false)
        {
            return true;
        }
        search_from = marker + 3;
    }
    false
}

fn contains_ipv4(text: &str) -> bool {
    text.split(|value: char| !(value.is_ascii_digit() || value == '.'))
        .filter(|token| token.contains('.'))
        .any(|token| {
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() < 4 {
                return false;
            }
            parts.windows(4).any(|octets| {
                octets
                    .iter()
                    .all(|octet| !octet.is_empty() && octet.parse::<u8>().is_ok())
            })
        })
}

fn contains_uuid(text: &str) -> bool {
    for token in text.split(|value: char| !(value.is_ascii_hexdigit() || value == '-')) {
        let parts: Vec<&str> = token.split('-').collect();
        if parts.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(parts.iter())
                .all(|(length, part)| {
                    part.len() == *length && part.chars().all(|c| c.is_ascii_hexdigit())
                })
        {
            return true;
        }
    }
    false
}

fn contains_assignment(text: &str, key: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(offset) = lower[search_from..].find(key) {
        let start = search_from + offset;
        let end = start + key.len();
        let before_ok = lower[..start]
            .chars()
            .next_back()
            .map(|value| !is_key_char(value))
            .unwrap_or(true);
        let after = lower[end..].trim_start();
        if before_ok && (after.starts_with(':') || after.starts_with('=')) {
            let assigned = after[1..].trim_start();
            if !assigned.is_empty() {
                return true;
            }
        }
        search_from = end;
    }
    false
}

fn contains_hostname_value(text: &str) -> bool {
    text.split(|value: char| !(value.is_ascii_alphanumeric() || value == '.' || value == '-'))
        .map(|token| token.trim_matches(|value| value == '.' || value == '-'))
        .filter(|token| token.contains('.'))
        .any(valid_hostname)
}

fn valid_hostname(token: &str) -> bool {
    let labels: Vec<&str> = token.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let Some(tld) = labels.last() else {
        return false;
    };
    if !(2..=63).contains(&tld.len()) || !tld.chars().all(|value| value.is_ascii_alphabetic()) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || value == '-')
            && label
                .chars()
                .next()
                .map(|value| value.is_ascii_alphanumeric())
                .unwrap_or(false)
            && label
                .chars()
                .last()
                .map(|value| value.is_ascii_alphanumeric())
                .unwrap_or(false)
    })
}

fn is_key_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, '_' | '-')
}

#[derive(Debug, Deserialize)]
struct YamlDuplicateInput {
    text: String,
    path: String,
}

pub fn validate_yaml_duplicates_json(input: &str) -> Result<Vec<String>, String> {
    let payload: YamlDuplicateInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid compose YAML duplicate JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_yaml_duplicate_keys_text(&payload.text, &payload.path, &mut errors);
    Ok(errors)
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

    // ── allowed_context tests (RED before reconciliation) ─────────────

    #[test]
    fn allowed_context_must_return_root_for_both_services() {
        // RED: currently returns crate-local paths
        assert_eq!(allowed_context("platform-api"), "../..");
        assert_eq!(allowed_context("portal-ui"), "../..");
    }

    // ── allowed_dockerfile tests (RED before reconciliation) ──────────

    #[test]
    fn allowed_dockerfile_must_return_explicit_paths() {
        // GREEN after reconciliation — validates the new allowed_dockerfile helper
        assert_eq!(
            allowed_dockerfile("platform-api"),
            "sources/ryuki-api/Dockerfile"
        );
        assert_eq!(
            allowed_dockerfile("portal-ui"),
            "portal/portal-ui/Dockerfile"
        );
    }

    // ── validate_values_json with root-context compose ────────────────

    #[test]
    fn root_context_compose_is_accepted() {
        let input = json!({
            "compose": {
                "name": "ryuki-infrastructure-platform",
                "services": {
                    "platform-db": {
                        "image": "postgres:16-alpine",
                        "environment": {
                            "POSTGRES_USER": "ryuki",
                            "POSTGRES_PASSWORD": "ryuki_dev",
                            "POSTGRES_DB": "ryuki_platform"
                        },
                        "ports": ["5432:5432"],
                        "volumes": ["pgdata:/var/lib/postgresql"],
                        "networks": ["ryuki-net"],
                        "healthcheck": {
                            "test": ["CMD", "pg_isready", "-U", "ryuki"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "10s"
                        }
                    },
                    "platform-api": {
                        "build": {
                            "context": "../..",
                            "dockerfile": "sources/ryuki-api/Dockerfile"
                        },
                        "image": "ryuki/platform-api:rust-dev",
                        "ports": ["18080:8080"],
                        "depends_on": {
                            "platform-db": {
                                "condition": "service_healthy"
                            }
                        },
                        "networks": ["ryuki-net"],
                        "healthcheck": {
                            "test": ["CMD", "curl", "-f", "http://localhost:8080/health"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "10s"
                        }
                    },
                    "portal-ui": {
                        "build": {
                            "context": "../..",
                            "dockerfile": "portal/portal-ui/Dockerfile"
                        },
                        "image": "ryuki/portal-ui:rust-dev",
                        "ports": ["18000:8080"],
                        "depends_on": {
                            "platform-api": {
                                "condition": "service_healthy"
                            }
                        },
                        "networks": ["ryuki-net"],
                        "healthcheck": {
                            "test": ["CMD", "curl", "-f", "http://localhost:3000/health"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "15s"
                        }
                    }
                },
                "networks": {
                    "ryuki-net": {
                        "driver": "bridge"
                    }
                },
                "volumes": {
                    "pgdata": {}
                }
            }
        })
        .to_string();
        let result = validate_values_json(&input);
        assert!(
            result.is_ok(),
            "Root-context compose should be accepted but got: {:?}",
            result
        );
        let errors = result.unwrap();
        assert!(
            errors
                .iter()
                .all(|e| !e.contains("context") && !e.contains("Dockerfile")),
            "Root-context compose should not produce context/Dockerfile errors: {:?}",
            errors
        );
    }

    // ── validate_values_json rejects old crate-local contexts ────────

    #[test]
    fn crate_local_context_api_is_rejected() {
        let input = json!({
            "compose": {
                "name": "ryuki-infrastructure-platform",
                "services": {
                    "platform-api": {
                        "build": {
                            "context": "../../sources/ryuki-api",
                            "dockerfile": "Dockerfile"
                        },
                        "image": "ryuki/platform-api:rust-dev",
                        "ports": ["18080:8080"],
                        "networks": ["platform"],
                        "healthcheck": {
                            "test": ["CMD", "curl", "-f", "http://localhost:8080/health"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "10s"
                        }
                    },
                    "portal-ui": {
                        "build": {
                            "context": "../..",
                            "dockerfile": "portal/portal-ui/Dockerfile"
                        },
                        "image": "ryuki/portal-ui:rust-dev",
                        "ports": ["18000:8080"],
                        "depends_on": {
                            "platform-api": {
                                "condition": "service_healthy"
                            }
                        },
                        "networks": ["platform"],
                        "healthcheck": {
                            "test": ["CMD", "curl", "-f", "http://localhost:3000/health"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "15s"
                        }
                    }
                },
                "networks": {
                    "platform": {
                        "driver": "bridge"
                    }
                }
            }
        })
        .to_string();
        let result = validate_values_json(&input);
        assert!(
            result.is_ok(),
            "Crate-local API context validation should complete but got error: {:?}",
            result
        );
        let errors = result.unwrap();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("context") || e.contains("Dockerfile")),
            "Crate-local API context should be rejected but got: {:?}",
            errors
        );
    }

    #[test]
    fn crate_local_context_both_services_are_rejected() {
        let input = json!({
            "compose": {
                "name": "ryuki-infrastructure-platform",
                "services": {
                    "platform-api": {
                        "build": {
                            "context": "../../sources/ryuki-api",
                            "dockerfile": "Dockerfile"
                        },
                        "image": "ryuki/platform-api:rust-dev",
                        "ports": ["18080:8080"],
                        "networks": ["platform"],
                        "healthcheck": {
                            "test": ["CMD", "curl", "-f", "http://localhost:8080/health"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "10s"
                        }
                    },
                    "portal-ui": {
                        "build": {
                            "context": "../../portal/portal-ui",
                            "dockerfile": "Dockerfile"
                        },
                        "image": "ryuki/portal-ui:rust-dev",
                        "ports": ["18000:8080"],
                        "depends_on": {
                            "platform-api": {
                                "condition": "service_healthy"
                            }
                        },
                        "networks": ["platform"],
                        "healthcheck": {
                            "test": ["CMD", "curl", "-f", "http://localhost:3000/health"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "15s"
                        }
                    }
                },
                "networks": {
                    "platform": {
                        "driver": "bridge"
                    }
                }
            }
        })
        .to_string();
        let errors = validate_values_json(&input).unwrap();
        assert!(
            errors.iter().any(|e| e.contains("context")),
            "Both crate-local services should be rejected: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("Dockerfile")),
            "Both bare-Dockerfile services should be rejected: {:?}",
            errors
        );
    }

    #[test]
    fn wrong_dockerfile_path_is_rejected() {
        let input = json!({
            "compose": {
                "name": "ryuki-infrastructure-platform",
                "services": {
                    "platform-api": {
                        "build": {
                            "context": "../..",
                            "dockerfile": "wrong/path/Dockerfile"
                        },
                        "image": "ryuki/platform-api:rust-dev",
                        "ports": ["18080:8080"],
                        "networks": ["platform"],
                        "healthcheck": {
                            "test": ["CMD", "curl", "-f", "http://localhost:8080/health"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "10s"
                        }
                    },
                    "portal-ui": {
                        "build": {
                            "context": "../..",
                            "dockerfile": "portal/portal-ui/Dockerfile"
                        },
                        "image": "ryuki/portal-ui:rust-dev",
                        "ports": ["18000:8080"],
                        "depends_on": {
                            "platform-api": {
                                "condition": "service_healthy"
                            }
                        },
                        "networks": ["platform"],
                        "healthcheck": {
                            "test": ["CMD", "curl", "-f", "http://localhost:3000/health"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "15s"
                        }
                    }
                },
                "networks": {
                    "platform": {
                        "driver": "bridge"
                    }
                }
            }
        })
        .to_string();
        let errors = validate_values_json(&input).unwrap();
        assert!(
            errors.iter().any(|e| e.contains("Dockerfile")),
            "Wrong dockerfile path should be rejected: {:?}",
            errors
        );
    }

    #[test]
    fn portal_crate_local_context_is_rejected() {
        let input = json!({
            "compose": {
                "name": "ryuki-infrastructure-platform",
                "services": {
                    "platform-api": {
                        "build": {
                            "context": "../..",
                            "dockerfile": "sources/ryuki-api/Dockerfile"
                        },
                        "image": "ryuki/platform-api:rust-dev",
                        "ports": ["18080:8080"],
                        "networks": ["platform"],
                        "healthcheck": {
                            "test": ["CMD", "curl", "-f", "http://localhost:8080/health"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "10s"
                        }
                    },
                    "portal-ui": {
                        "build": {
                            "context": "../../portal/portal-ui",
                            "dockerfile": "Dockerfile"
                        },
                        "image": "ryuki/portal-ui:rust-dev",
                        "ports": ["18000:8080"],
                        "depends_on": {
                            "platform-api": {
                                "condition": "service_healthy"
                            }
                        },
                        "networks": ["platform"],
                        "healthcheck": {
                            "test": ["CMD", "curl", "-f", "http://localhost:3000/health"],
                            "interval": "30s",
                            "timeout": "5s",
                            "retries": 3,
                            "start_period": "15s"
                        }
                    }
                },
                "networks": {
                    "platform": {
                        "driver": "bridge"
                    }
                }
            }
        })
        .to_string();
        let errors = validate_values_json(&input).unwrap();
        assert!(
            errors.iter().any(|e| e.contains("context")),
            "Portal crate-local context should be rejected: {:?}",
            errors
        );
    }
}
