use crate::yaml_utils::validate_yaml_duplicate_keys_text;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const VALUES_PATH: &str = "deploy/kubernetes/vault/values-ha-raft.yaml";
const README_PATH: &str = "deploy/kubernetes/vault/README.md";
const RUNBOOK_PATH: &str = "deploy/kubernetes/vault/bootstrap-runbook.md";
const PROHIBITED_KEY_PARTS: &[&str] = &[
    "tenantid",
    "tenantidentifier",
    "subscriptionid",
    "subscriptionidentifier",
    "objectid",
    "objectidentifier",
    "privateip",
    "privatenetwork",
    "endpoint",
    "serviceendpoint",
    "providerendpoint",
    "vaulturl",
    "vaultaddress",
    "vaultnamespace",
    "secretpath",
    "secretvalue",
    "policyname",
    "rolename",
    "serviceaccounttoken",
    "roottoken",
    "recoverykey",
    "unsealkey",
    "auditlogline",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "providerpayload",
    "rawproviderpayload",
    "rawvaultpayload",
    "rawkubernetespayload",
    "credential",
    "credentials",
    "password",
    "bearer",
    "token",
    "tokens",
    "apikey",
    "privatekey",
];
const SECRET_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "client_secret",
    "secret_key",
    "access_token",
    "refresh_token",
    "bearer",
    "root_token",
    "unseal_key",
    "recovery_key",
    "api_key",
    "private_key",
    "token",
];

#[derive(Debug, Deserialize)]
struct Context {
    values: Value,
    values_text: String,
    readme: String,
    runbook: String,
}

#[derive(Debug, Deserialize)]
struct ValuesInput {
    values: Value,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    readme: String,
    runbook: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
    #[serde(default)]
    source_text: bool,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid vault foundation context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_source_text(&context.values_text, VALUES_PATH, &mut errors);
    validate_source_text(&context.readme, README_PATH, &mut errors);
    validate_source_text(&context.runbook, RUNBOOK_PATH, &mut errors);
    validate_values_value(&context.values, &mut errors);
    validate_docs_text(&context.readme, &context.runbook, &mut errors);
    scan_prohibited_value(&context.values, "vault values", &mut errors);
    Ok(errors)
}

pub fn validate_values_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ValuesInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vault foundation values JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_values_value(&payload.values, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vault foundation docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(&payload.readme, &payload.runbook, &mut errors);
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vault foundation prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    if payload.source_text {
        if let Some(text) = payload.value.as_str() {
            validate_source_text(text, &payload.path, &mut errors);
        } else {
            errors.push(format!("{} source text must be a string", payload.path));
        }
    } else {
        scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    }
    Ok(errors)
}

fn validate_values_value(values: &Value, errors: &mut Vec<String>) {
    expect(
        bool_at(values, &["global", "enabled"]) == Some(true),
        errors,
        "Vault global chart support must be enabled",
    );
    expect(
        bool_at(values, &["global", "tlsDisable"]) == Some(false),
        errors,
        "Vault TLS must stay enabled",
    );
    expect(
        bool_at(values, &["injector", "enabled"]) == Some(false),
        errors,
        "Vault injector must remain disabled in foundation slice",
    );
    expect(
        bool_at(values, &["server", "enabled"]) == Some(true),
        errors,
        "Vault server must be enabled",
    );
    expect(
        bool_at(values, &["server", "standalone", "enabled"]) == Some(false),
        errors,
        "Vault standalone mode must be disabled",
    );
    expect(
        bool_at(values, &["server", "serviceAccount", "create"]) == Some(true),
        errors,
        "Vault ServiceAccount must be chart-managed",
    );
    expect(
        str_at(values, &["server", "serviceAccount", "name"]) == Some("vault"),
        errors,
        "Vault ServiceAccount name must be vault",
    );
    validate_storage(values, errors);
    validate_availability(values, errors);
    validate_raft(values, errors);
    validate_ui(values, errors);
}

fn validate_storage(values: &Value, errors: &mut Vec<String>) {
    expect(
        bool_at(values, &["server", "dataStorage", "enabled"]) == Some(true),
        errors,
        "Vault data storage must be enabled",
    );
    expect(
        str_at(values, &["server", "dataStorage", "size"]) == Some("50Gi"),
        errors,
        "Vault data storage must reserve 50Gi in foundation",
    );
    expect(
        str_at(values, &["server", "dataStorage", "accessMode"]) == Some("ReadWriteOnce"),
        errors,
        "Vault data storage must use ReadWriteOnce",
    );
    expect(
        str_at(values, &["server", "dataStorage", "mountPath"]) == Some("/vault/data"),
        errors,
        "Vault data storage must mount at /vault/data",
    );
    expect(
        bool_at(values, &["server", "auditStorage", "enabled"]) == Some(true),
        errors,
        "Vault audit storage must be enabled",
    );
    expect(
        str_at(values, &["server", "auditStorage", "size"]) == Some("20Gi"),
        errors,
        "Vault audit storage must reserve 20Gi in foundation",
    );
    expect(
        str_at(values, &["server", "auditStorage", "accessMode"]) == Some("ReadWriteOnce"),
        errors,
        "Vault audit storage must use ReadWriteOnce",
    );
    expect(
        str_at(values, &["server", "auditStorage", "mountPath"]) == Some("/vault/audit"),
        errors,
        "Vault audit storage must mount at /vault/audit",
    );
    expect(
        str_at(
            values,
            &[
                "server",
                "persistentVolumeClaimRetentionPolicy",
                "whenDeleted",
            ],
        ) == Some("Retain"),
        errors,
        "Vault PVCs must be retained when deleted",
    );
    expect(
        str_at(
            values,
            &[
                "server",
                "persistentVolumeClaimRetentionPolicy",
                "whenScaled",
            ],
        ) == Some("Retain"),
        errors,
        "Vault PVCs must be retained when scaled",
    );

    let volume_names = array_at(values, &["server", "extraVolumes"])
        .map(|volumes| {
            volumes
                .iter()
                .filter_map(|volume| volume.get("name").and_then(Value::as_str))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    expect(
        volume_names.contains(&"vault-server-tls"),
        errors,
        "Vault TLS secret volume reference is required",
    );
    let unique_names: BTreeSet<&str> = volume_names.iter().copied().collect();
    expect(
        unique_names.len() == volume_names.len(),
        errors,
        "Vault extra volume names must be unique",
    );
}

fn validate_availability(values: &Value, errors: &mut Vec<String>) {
    expect(
        bool_at(values, &["server", "podDisruptionBudget", "enabled"]) == Some(true),
        errors,
        "Vault PodDisruptionBudget must be enabled",
    );
    expect(
        i64_at(values, &["server", "podDisruptionBudget", "maxUnavailable"]) == Some(1),
        errors,
        "Vault PodDisruptionBudget must allow at most one unavailable pod",
    );
    expect(
        bool_at(values, &["server", "networkPolicy", "enabled"]) == Some(true),
        errors,
        "Vault chart NetworkPolicy must be enabled",
    );
    let affinity = str_at(values, &["server", "affinity"]).unwrap_or("");
    expect(
        affinity.contains("podAntiAffinity"),
        errors,
        "Vault server anti-affinity must be configured",
    );
    expect(
        affinity.contains("kubernetes.io/hostname"),
        errors,
        "Vault server anti-affinity must spread by node",
    );
}

fn validate_raft(values: &Value, errors: &mut Vec<String>) {
    let raft_config = str_at(values, &["server", "ha", "raft", "config"]).unwrap_or("");
    let active_config = hcl_without_comments(raft_config);
    expect(
        bool_at(values, &["server", "ha", "enabled"]) == Some(true),
        errors,
        "Vault HA mode must be enabled",
    );
    expect(
        i64_at(values, &["server", "ha", "replicas"]) == Some(3),
        errors,
        "Vault HA mode must use three replicas",
    );
    expect(
        bool_at(values, &["server", "ha", "raft", "enabled"]) == Some(true),
        errors,
        "Vault integrated Raft must be enabled",
    );
    expect(
        bool_at(values, &["server", "ha", "raft", "setNodeId"]) == Some(true),
        errors,
        "Vault Raft node IDs must be set by chart",
    );
    let storage_config = hcl_block_body(&active_config, "storage", "raft").unwrap_or_default();
    expect(
        !storage_config.is_empty() || hcl_block_body(&active_config, "storage", "raft").is_some(),
        errors,
        "Vault config must use integrated Raft storage",
    );
    expect(
        hcl_assignment(&storage_config, "path", "\"/vault/data\""),
        errors,
        "Vault Raft storage path must use /vault/data",
    );
    expect(
        hcl_block_body(&active_config, "service_registration", "kubernetes").is_some(),
        errors,
        "Vault config must enable Kubernetes service registration",
    );
    let listener_config = hcl_block_body(&active_config, "listener", "tcp").unwrap_or_default();
    expect(
        !listener_config.is_empty(),
        errors,
        "Vault config must expose a TCP listener",
    );
    expect(
        hcl_assignment(&listener_config, "tls_disable", "0"),
        errors,
        "Vault listener TLS must be required",
    );
    expect(
        !hcl_assignment(&listener_config, "tls_disable", "1"),
        errors,
        "Vault listener must not disable TLS",
    );
    expect(
        hcl_key_assigned(&listener_config, "tls_cert_file"),
        errors,
        "Vault TLS certificate file must be configured",
    );
    expect(
        hcl_key_assigned(&listener_config, "tls_key_file"),
        errors,
        "Vault TLS key file must be configured",
    );
    expect(
        hcl_key_assigned(&listener_config, "tls_client_ca_file"),
        errors,
        "Vault TLS client CA file must be configured",
    );
}

fn validate_ui(values: &Value, errors: &mut Vec<String>) {
    expect(
        bool_at(values, &["ui", "enabled"]) == Some(true),
        errors,
        "Vault UI must be enabled for operator bootstrap",
    );
    expect(
        str_at(values, &["ui", "serviceType"]) == Some("ClusterIP"),
        errors,
        "Vault UI service must stay ClusterIP",
    );
}

fn validate_docs_text(readme: &str, runbook: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains("does not contain initialized Vault data"),
        errors,
        "Vault README must state no initialized data is stored",
    );
    expect(
        readme.contains("Azure Key Vault auto-unseal remains an environment overlay"),
        errors,
        "Vault README must keep auto-unseal environment-specific",
    );
    expect(
        runbook.contains("vault audit enable file file_path=/vault/audit/vault-audit.log"),
        errors,
        "Vault runbook must enable file audit logging",
    );
    expect(
        runbook.contains("This runbook is provider-safe"),
        errors,
        "Vault runbook must state the bootstrap boundary is provider-safe",
    );
    expect(
        runbook.contains("approved operator process"),
        errors,
        "Vault runbook must require approved-time operator handling",
    );
    expect(
        runbook.contains("Do not paste unseal material"),
        errors,
        "Vault runbook must guard unseal material",
    );
    expect(
        runbook.contains("Helm chart version and values file hash"),
        errors,
        "Vault runbook must define safe evidence",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if prohibited_key(key) {
                    errors.push(format!("{path}.{key} contains prohibited key {key}"));
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
            if text.contains('\n') {
                for (index, line) in text.lines().enumerate() {
                    scan_prohibited_value(
                        &Value::String(line.to_string()),
                        &format!("{path}:{}", index + 1),
                        errors,
                    );
                }
                return;
            }
            if prohibited_key(text) {
                errors.push(format!("{path} contains prohibited key {text}"));
            }
            if contains_prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
        }
        _ => {}
    }
}

fn validate_source_text(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        let location = format!("{path}:{}", index + 1);
        if contains_prohibited_value(line) {
            errors.push(format!("{location} contains prohibited value"));
        }
        for term in assignment_terms(line) {
            if prohibited_key(&term) {
                errors.push(format!("{location} contains prohibited key {term}"));
            }
        }
        for term in word_terms(line) {
            if source_key_term(line, &term) && prohibited_key(&term) {
                errors.push(format!("{location} contains prohibited key {term}"));
            }
        }
    }
}

fn assignment_terms(line: &str) -> Vec<String> {
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let mut terms = Vec::new();
    for (position, (start, value)) in chars.iter().enumerate() {
        if !value.is_ascii_alphabetic() {
            continue;
        }
        let previous = if *start == 0 {
            None
        } else {
            line[..*start].chars().next_back()
        };
        let before_ok = previous
            .map(|previous| !is_source_key_char(previous) || matches!(previous, '"' | '\''))
            .unwrap_or(true);
        if !before_ok {
            continue;
        }
        let mut end = *start + value.len_utf8();
        for (_, candidate) in chars.iter().skip(position + 1) {
            if candidate.is_ascii_alphanumeric() || matches!(candidate, '.' | '_' | '-') {
                end += candidate.len_utf8();
            } else {
                break;
            }
        }
        let rest = line[end..]
            .strip_prefix('"')
            .or_else(|| line[end..].strip_prefix('\''))
            .unwrap_or(&line[end..])
            .trim_start();
        if rest.starts_with(':') || rest.starts_with('=') {
            terms.push(line[*start..end].to_string());
        }
    }
    terms
}

fn word_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut start = None;
    for (index, value) in line.char_indices() {
        if value.is_ascii_alphanumeric() || value == '_' || value == '-' {
            if start.is_none() && value.is_ascii_alphabetic() {
                start = Some(index);
            }
        } else if let Some(token_start) = start.take() {
            terms.push(line[token_start..index].to_string());
        }
    }
    if let Some(token_start) = start {
        terms.push(line[token_start..].to_string());
    }
    terms
}

fn source_key_term(line: &str, term: &str) -> bool {
    term.chars()
        .any(|value| value.is_ascii_uppercase() || matches!(value, '_' | '-'))
        || assignment_terms(line)
            .iter()
            .any(|candidate| candidate == term)
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
        || contains_private_ip(text)
        || contains_uuid(text)
        || contains_secret_assignment(text)
}

fn contains_aws_access_key(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(offset) = lower[search_from..].find("akia") {
        let start = search_from + offset;
        let end = start + 20;
        if end <= text.len()
            && text[start + 4..end]
                .chars()
                .all(|value| value.is_ascii_alphanumeric())
        {
            return true;
        }
        search_from = start + 4;
    }
    false
}

fn contains_private_key_header(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("-----begin ") && lower.contains("private key-----")
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

fn contains_private_ip(text: &str) -> bool {
    for token in text.split(|value: char| !(value.is_ascii_digit() || value == '.' || value == '/'))
    {
        let address = token.split('/').next().unwrap_or("");
        let octets: Vec<&str> = address.split('.').collect();
        if octets.len() != 4 {
            continue;
        }
        let parsed: Option<Vec<u8>> = octets
            .iter()
            .map(|octet| octet.parse::<u8>().ok())
            .collect();
        let Some(octets) = parsed else {
            continue;
        };
        if octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
        {
            return true;
        }
    }
    false
}

fn contains_uuid(text: &str) -> bool {
    for token in text.split(|value: char| !(value.is_ascii_hexdigit() || value == '-')) {
        let parts: Vec<&str> = token.split('-').collect();
        if parts.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(parts.iter())
                .all(|(expected, part)| {
                    part.len() == *expected && part.chars().all(|c| c.is_ascii_hexdigit())
                })
        {
            return true;
        }
    }
    false
}

fn contains_secret_assignment(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SECRET_ASSIGNMENT_KEYS
        .iter()
        .any(|key| has_assignment_value(&lower, key))
}

fn has_assignment_value(line: &str, key: &str) -> bool {
    let mut search_from = 0;
    while let Some(offset) = line[search_from..].find(key) {
        let start = search_from + offset;
        let end = start + key.len();
        let before_ok = start == 0
            || line[..start]
                .chars()
                .next_back()
                .map(|value| !is_word_char(value))
                .unwrap_or(true);
        let after_ok = line[end..]
            .chars()
            .next()
            .map(|value| !is_word_char(value))
            .unwrap_or(true);
        if before_ok && after_ok {
            let rest = line[end..].trim_start();
            if let Some(value) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) {
                if !value.split_whitespace().next().unwrap_or("").is_empty() {
                    return true;
                }
            }
        }
        search_from = end;
    }
    false
}

fn hcl_without_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_block = false;
    while index < bytes.len() {
        if in_block {
            if bytes.get(index) == Some(&b'*') && bytes.get(index + 1) == Some(&b'/') {
                output.push_str("  ");
                index += 2;
                in_block = false;
            } else {
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
        } else if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
            output.push_str("  ");
            index += 2;
            in_block = true;
        } else if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else if bytes[index] == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}

fn hcl_block_body(config: &str, block_type: &str, label: &str) -> Option<String> {
    let mut body = String::new();
    let mut collecting = false;
    for line in config.lines() {
        if collecting {
            if line.starts_with('}') {
                return Some(body);
            }
            body.push_str(line);
            body.push('\n');
        } else if hcl_block_line(line, block_type, label) {
            let after_open = line.split_once('{').map(|(_, rest)| rest).unwrap_or("");
            if let Some((inline_body, _)) = after_open.split_once('}') {
                return Some(inline_body.to_string());
            }
            collecting = true;
        }
    }
    None
}

fn hcl_block_line(line: &str, block_type: &str, label: &str) -> bool {
    let Some(rest) = line.strip_prefix(block_type) else {
        return false;
    };
    let rest = rest.trim_start();
    let expected_label = format!("\"{label}\"");
    let Some(rest) = rest.strip_prefix(&expected_label) else {
        return false;
    };
    rest.trim_start().starts_with('{')
}

fn hcl_assignment(config: &str, key: &str, expected_value: &str) -> bool {
    config.lines().any(|line| {
        let Some((left, right)) = line.split_once('=') else {
            return false;
        };
        left.trim() == key && right.trim() == expected_value
    })
}

fn hcl_key_assigned(config: &str, key: &str) -> bool {
    config.lines().any(|line| {
        let Some((left, _)) = line.split_once('=') else {
            return false;
        };
        left.trim() == key
    })
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    value_at(value, path).and_then(Value::as_bool)
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at(value, path).and_then(Value::as_str)
}

fn i64_at(value: &Value, path: &[&str]) -> Option<i64> {
    value_at(value, path).and_then(Value::as_i64)
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Vec<Value>> {
    value_at(value, path).and_then(Value::as_array)
}

fn is_source_key_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, '.' | '_' | '-')
}

fn is_word_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || value == '_'
}

#[derive(Debug, Deserialize)]
struct YamlDuplicateInput {
    text: String,
    path: String,
}

pub fn validate_yaml_duplicates_json(input: &str) -> Result<Vec<String>, String> {
    let payload: YamlDuplicateInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vault foundation YAML duplicate JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_yaml_duplicate_keys_text(&payload.text, &payload.path, &mut errors);
    Ok(errors)
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}
