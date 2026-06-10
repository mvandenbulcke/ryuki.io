use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const TEMPLATE_PATH: &str = "docs/source-inputs/deployment-input-request-template.md";
const README_PATH: &str = "docs/source-inputs/README.md";
const REQUIRED_SECTIONS: &[&str] = &[
    "Intake Rules",
    "Source Reference Register",
    "ServiceNow CMDB Headers",
    "Entra Role And Group Mapping",
    "Harbor Model",
    "Vault Model",
    "Azure Blob And Key Vault Model",
    "Firmware Baseline Model",
    "Zabbix Mapping",
    "Veeam Assumptions",
    "Ingress DNS And Load-Balancer Model",
    "Submission Checklist",
];
const REQUIRED_SOURCE_REFS: &[&str] = &[
    "source-ref-deployment-servicenow-cmdb-headers",
    "source-ref-deployment-entra-role-group-map",
    "source-ref-deployment-harbor-model",
    "source-ref-deployment-vault-model",
    "source-ref-deployment-azure-storage-keyvault-model",
    "source-ref-deployment-firmware-baseline-model",
    "source-ref-deployment-zabbix-mapping",
    "source-ref-deployment-veeam-assumptions",
    "source-ref-deployment-ingress-dns-lb-model",
];
const REQUIRED_SAFE_PHRASES: &[&str] = &[
    "source references and `sanitized-*` placeholders only",
    "No live provider calls.",
    "Raw source material stays outside committed docs, code, tests, fixtures, bundles, evidence, and logs.",
];
const REQUIRED_DOMAIN_FACTS: &[&str] = &[
    "N-1 approval rule",
    "Lenovo XCC SNMP exception",
    "Current repository platform",
    "Future repository platform",
    "Proposal needed",
];
const ALLOWED_PROHIBITION_LINES: &[&str] = &[
    "Source input documents describe how supplied raw material may be used safely. They do not copy secret values, raw provider payloads, tenant IDs, object IDs, credentials, private IPs, or sensitive diagrams into implementation artifacts.",
    "Use this static template to request deployment-time implementation inputs without committing live provider values, secrets, tokens, tenant identifiers, object identifiers, subscription identifiers, private addresses, serials, raw provider payloads, logs, rows, or real customer, host, user, or recipient data.",
    "- No credentials, tokens, secret values, keys, certificates, or recovery material.",
    "- No tenant IDs, object IDs, subscription IDs, resource IDs, serial numbers, private IPs, email addresses, real DNS names, URLs, raw payloads, raw logs, raw rows, or raw filenames.",
];
const RAW_FILENAME_EXTENSIONS: &[&str] = &[
    "csv", "xls", "xlsx", "json", "log", "txt", "xml", "zip", "pdf", "vsd", "vsdx", "har", "pcap",
    "sql",
];
const SECRET_ASSIGNMENT_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "api-key",
    "apikey",
    "client_secret",
    "client-secret",
    "private_key",
    "private-key",
];
const RAW_DATA_WORDS: &[&str] = &[
    "payload",
    "payloads",
    "log",
    "logs",
    "row",
    "rows",
    "export",
    "exports",
    "response",
    "responses",
    "dump",
    "dumps",
    "file",
    "files",
    "filename",
    "filenames",
];
const PROHIBITED_IDENTIFIER_TOKENS: &[(&str, &str)] = &[
    ("endpointId", "endpointid"),
    ("endpointIdentifier", "endpointidentifier"),
    ("endpointName", "endpointname"),
    ("endpointHostName", "endpointhostname"),
    ("endpointDnsName", "endpointdnsname"),
    ("endpointFqdn", "endpointfqdn"),
    ("endpointUrl", "endpointurl"),
    ("endpointUri", "endpointuri"),
    ("endpointAddress", "endpointaddress"),
    ("endpointIpAddress", "endpointipaddress"),
    ("endpointPrivateIpAddress", "endpointprivateipaddress"),
    ("tenantId", "tenantid"),
    ("tenantIdentifier", "tenantidentifier"),
    ("objectId", "objectid"),
    ("objectIdentifier", "objectidentifier"),
    ("subscriptionId", "subscriptionid"),
    ("resourceId", "resourceid"),
    ("privateIp", "privateip"),
    ("privateNetwork", "privatenetwork"),
    ("serialNumber", "serialnumber"),
    ("rawProviderPayload", "rawproviderpayload"),
    ("providerPayload", "providerpayload"),
    ("rawDeploymentPayload", "rawdeploymentpayload"),
    ("rawRequestPayload", "rawrequestpayload"),
    ("rawTemplatePayload", "rawtemplatepayload"),
    ("rawDestinationData", "rawdestinationdata"),
    ("recipientData", "recipientdata"),
    ("customerData", "customerdata"),
    ("hostName", "hostname"),
    ("hostId", "hostid"),
    ("userName", "username"),
    ("userId", "userid"),
    ("customerId", "customerid"),
];

#[derive(Debug, Deserialize)]
struct Context {
    template: String,
    readme: String,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    template: Option<String>,
    readme: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    text: String,
    path: String,
}

#[derive(Clone, Debug)]
struct SourceRegisterRow {
    source_ref: Option<String>,
    source_ref_count: usize,
    source_ref_exact: bool,
    details: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid deployment input template context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_template_text(&context.template, &mut errors);
    validate_readme_text(&context.readme, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid deployment input template docs JSON: {error}"))?;
    let mut errors = Vec::new();
    if let Some(template) = payload.template {
        validate_template_text(&template, &mut errors);
    }
    if let Some(readme) = payload.readme {
        validate_readme_text(&readme, &mut errors);
    }
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid deployment input template prohibited-text JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_no_prohibited_values(&payload.text, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_template_text(template: &str, errors: &mut Vec<String>) {
    let active_template = markdown_structure_text(template);
    let active_template = active_template.as_str();

    for section in REQUIRED_SECTIONS {
        expect(
            active_template
                .lines()
                .any(|line| line == format!("## {section}")),
            errors,
            format!("deployment input template missing section {section}"),
        );
    }

    let refs = source_refs(active_template);
    let missing: Vec<&str> = REQUIRED_SOURCE_REFS
        .iter()
        .copied()
        .filter(|source_ref| !refs.iter().any(|candidate| candidate == source_ref))
        .collect();
    let mut unique_refs = refs.clone();
    unique_refs.sort();
    unique_refs.dedup();
    let unexpected: Vec<String> = unique_refs
        .iter()
        .filter(|source_ref| !REQUIRED_SOURCE_REFS.contains(&source_ref.as_str()))
        .cloned()
        .collect();

    if !missing.is_empty() {
        errors.push(format!(
            "deployment input template missing source refs: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "deployment input template has unexpected source refs: {}",
            unexpected.join(", ")
        ));
    }
    validate_source_reference_register(active_template, errors);
    for source_ref in REQUIRED_SOURCE_REFS {
        expect(
            refs.iter()
                .filter(|candidate| *candidate == source_ref)
                .count()
                >= 2,
            errors,
            format!("deployment input template must use {source_ref} in register and section"),
        );
    }

    for phrase in REQUIRED_SAFE_PHRASES {
        expect(
            active_template.contains(phrase),
            errors,
            format!("deployment input template missing safe-use phrase {phrase}"),
        );
    }
    for phrase in REQUIRED_DOMAIN_FACTS {
        expect(
            active_template.contains(phrase),
            errors,
            format!("deployment input template missing domain fact {phrase}"),
        );
    }

    validate_no_prohibited_values(template, TEMPLATE_PATH, errors);
}

fn validate_readme_text(readme: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains("deployment-input-request-template.md"),
        errors,
        "source input README missing deployment input template link",
    );
    validate_no_prohibited_values(readme, README_PATH, errors);
}

fn validate_no_prohibited_values(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if allowed_prohibition_line(line) {
            continue;
        }

        let location = format!("{path}:{}", index + 1);
        if contains_url(line) {
            errors.push(format!("{location} contains raw URL"));
        }
        if contains_email(line) {
            errors.push(format!("{location} contains raw email address"));
        }
        if contains_uuid(line) || contains_azure_resource_id(line) {
            errors.push(format!("{location} contains raw identifier"));
        }
        if contains_private_ip(line) {
            errors.push(format!("{location} contains private IP literal"));
        }
        if contains_serial_like_value(line) {
            errors.push(format!("{location} contains serial-like value"));
        }
        if contains_secret_assignment(line) {
            errors.push(format!("{location} contains secret or token assignment"));
        }
        if contains_raw_filename(line) {
            errors.push(format!("{location} contains raw source filename"));
        }
        if contains_raw_data_phrase(line) {
            errors.push(format!("{location} contains raw data phrase"));
        }
        if let Some(identifier) = prohibited_identifier(line) {
            errors.push(format!(
                "{location} contains prohibited provider-identifying literal {identifier}"
            ));
        }
    }
}

fn validate_source_reference_register(text: &str, errors: &mut Vec<String>) {
    let rows = source_reference_register_rows(text);
    let register_refs: Vec<String> = rows
        .iter()
        .filter_map(|row| row.source_ref.clone())
        .collect();
    let missing: Vec<&str> = REQUIRED_SOURCE_REFS
        .iter()
        .copied()
        .filter(|source_ref| {
            !register_refs
                .iter()
                .any(|candidate| candidate == source_ref)
        })
        .collect();
    let mut unexpected = register_refs
        .iter()
        .filter(|source_ref| !REQUIRED_SOURCE_REFS.contains(&source_ref.as_str()))
        .cloned()
        .collect::<Vec<String>>();
    unexpected.sort();
    unexpected.dedup();

    if !missing.is_empty() {
        errors.push(format!(
            "deployment input template source reference register missing source refs: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "deployment input template source reference register has unexpected source refs: {}",
            unexpected.join(", ")
        ));
    }
    if let Some(duplicates) = duplicate_values(register_refs.iter().map(String::as_str)) {
        errors.push(format!(
            "deployment input template source reference register IDs must be unique: {}",
            duplicates.join(", ")
        ));
    }
    if let Some(duplicates) = duplicate_values(
        rows.iter()
            .map(|row| row.details.as_str())
            .filter(|details| !details.is_empty()),
    ) {
        errors.push(format!(
            "deployment input template source reference register details must be unique: {}",
            duplicates.join(", ")
        ));
    }
    if rows
        .iter()
        .any(|row| row.source_ref_count != 1 || !row.source_ref_exact)
    {
        errors.push(
            "deployment input template source reference register source assignments must contain exactly one source ref"
                .to_string(),
        );
    }
}

fn source_reference_register_rows(text: &str) -> Vec<SourceRegisterRow> {
    let mut rows = Vec::new();
    let mut in_register = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "## Source Reference Register" {
            in_register = true;
            continue;
        }
        if in_register && trimmed.starts_with("## ") {
            break;
        }
        if !in_register || !trimmed.starts_with('|') {
            continue;
        }

        let cells: Vec<String> = trimmed
            .trim_matches('|')
            .split('|')
            .map(|cell| cell.trim().to_string())
            .collect();
        if cells.len() < 3
            || cells[0].eq_ignore_ascii_case("input area")
            || cells[1].eq_ignore_ascii_case("source reference")
            || cells.iter().all(|cell| cell.chars().all(|ch| ch == '-'))
        {
            continue;
        }
        let source_ref_cell = unquote_cell(&cells[1]);
        let refs = source_refs(source_ref_cell);
        let source_ref_exact = refs
            .first()
            .map(|source_ref| refs.len() == 1 && source_ref_cell == source_ref)
            .unwrap_or(false);
        rows.push(SourceRegisterRow {
            source_ref: source_ref_exact.then(|| refs[0].clone()),
            source_ref_count: refs.len(),
            source_ref_exact,
            details: unquote_cell(&cells[2]).to_string(),
        });
    }

    rows
}

fn unquote_cell(cell: &str) -> &str {
    let cell = cell.trim();
    cell.strip_prefix('`')
        .and_then(|value| value.strip_suffix('`'))
        .map(str::trim)
        .unwrap_or(cell)
}

fn duplicate_values<'a>(values: impl Iterator<Item = &'a str>) -> Option<Vec<String>> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value.to_string()).or_insert(0usize) += 1;
    }
    let duplicates: Vec<String> = counts
        .into_iter()
        .filter_map(|(value, count)| (count > 1).then_some(value))
        .collect();
    (!duplicates.is_empty()).then_some(duplicates)
}

fn source_refs(text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut search_from = 0;
    while let Some(offset) = text[search_from..].find("source-ref-") {
        let start = search_from + offset;
        let end = text[start..]
            .char_indices()
            .find(|(_, value)| {
                !(value.is_ascii_lowercase() || value.is_ascii_digit() || *value == '-')
            })
            .map(|(index, _)| start + index)
            .unwrap_or(text.len());
        if end == start + "source-ref-".len() {
            search_from = end;
            continue;
        }
        let before_ok = start == 0
            || text[..start]
                .chars()
                .next_back()
                .map(|value| !is_source_ref_boundary_char(value))
                .unwrap_or(true);
        let after_ok = end == text.len()
            || text[end..]
                .chars()
                .next()
                .map(|value| !is_source_ref_boundary_char(value))
                .unwrap_or(true);
        if before_ok && after_ok {
            refs.push(text[start..end].to_string());
        }
        search_from = end;
    }
    refs
}

fn markdown_without_html_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut index = 0;

    while let Some(offset) = text[index..].find("<!--") {
        let start = index + offset;
        output.push_str(&text[index..start]);
        let Some(end_offset) = text[start + 4..].find("-->") else {
            output.push_str(&comment_padding(&text[start..]));
            return output;
        };
        let end = start + 4 + end_offset + 3;
        output.push_str(&comment_padding(&text[start..end]));
        index = end;
    }

    output.push_str(&text[index..]);
    output
}

fn markdown_structure_text(text: &str) -> String {
    markdown_without_fenced_code(&markdown_without_html_comments(text))
}

fn markdown_without_fenced_code(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut in_fence: Option<String> = None;

    for line in text.split_inclusive('\n') {
        let line_without_newline = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = line_without_newline.trim_start();
        let fence_marker = fence_marker(trimmed);
        if let Some(marker) = fence_marker {
            output.push_str(&comment_padding(line));
            if in_fence.as_deref() == Some(marker) {
                in_fence = None;
            } else if in_fence.is_none() {
                in_fence = Some(marker.to_string());
            }
            continue;
        }

        if in_fence.is_some() || is_indented_code_line(line_without_newline) {
            output.push_str(&comment_padding(line));
        } else {
            output.push_str(line);
        }
    }

    output
}

fn fence_marker(trimmed_line: &str) -> Option<&'static str> {
    if trimmed_line.starts_with("```") {
        Some("```")
    } else if trimmed_line.starts_with("~~~") {
        Some("~~~")
    } else {
        None
    }
}

fn is_indented_code_line(line: &str) -> bool {
    line.starts_with("    ") || line.starts_with('\t')
}

fn comment_padding(comment: &str) -> String {
    comment
        .chars()
        .map(|value| if value == '\n' { '\n' } else { ' ' })
        .collect()
}

fn allowed_prohibition_line(line: &str) -> bool {
    ALLOWED_PROHIBITION_LINES.contains(&line.trim())
}

fn contains_url(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
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

fn contains_email(line: &str) -> bool {
    for token in line.split(|value: char| {
        !(value.is_ascii_alphanumeric() || matches!(value, '.' | '_' | '%' | '+' | '-' | '@'))
    }) {
        let token = token.trim_matches(|value: char| {
            matches!(
                value,
                '<' | '>' | '(' | ')' | '[' | ']' | '"' | '\'' | ',' | ';' | ':' | '.'
            )
        });
        let Some((local, domain)) = token.split_once('@') else {
            continue;
        };
        if !local.is_empty()
            && domain.contains('.')
            && local.chars().all(|value| {
                value.is_ascii_alphanumeric() || matches!(value, '.' | '_' | '%' | '+' | '-')
            })
            && domain
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, '.' | '-'))
            && domain
                .rsplit('.')
                .next()
                .map(|tld| tld.len() >= 2)
                .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn contains_uuid(line: &str) -> bool {
    for token in line.split(|value: char| !(value.is_ascii_hexdigit() || value == '-')) {
        let parts: Vec<&str> = token.split('-').collect();
        if parts.len() != 5 {
            continue;
        }
        let shape_ok = [8, 4, 4, 4, 12]
            .iter()
            .zip(parts.iter())
            .all(|(expected, part)| {
                part.len() == *expected && part.chars().all(|c| c.is_ascii_hexdigit())
            });
        let version_ok = parts[2]
            .chars()
            .next()
            .map(|value| matches!(value.to_ascii_lowercase(), '1'..='5'))
            .unwrap_or(false);
        let variant_ok = parts[3]
            .chars()
            .next()
            .map(|value| matches!(value.to_ascii_lowercase(), '8' | '9' | 'a' | 'b'))
            .unwrap_or(false);
        if shape_ok && version_ok && variant_ok {
            return true;
        }
    }
    false
}

fn contains_azure_resource_id(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "/subscriptions/",
        "/tenants/",
        "/resourcegroups/",
        "/providers/",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn contains_private_ip(line: &str) -> bool {
    for token in line.split(|value: char| !(value.is_ascii_digit() || value == '.' || value == '/'))
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
            || octets[0] == 127
            || (octets[0] == 169 && octets[1] == 254)
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
        {
            return true;
        }
    }
    false
}

fn contains_serial_like_value(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    ["serial", "service tag", "asset tag"]
        .iter()
        .any(|key| has_assignment_with_min_len(&lower, key, 6))
}

fn contains_secret_assignment(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    SECRET_ASSIGNMENT_KEYS
        .iter()
        .any(|key| has_assignment_with_min_len(&lower, key, 1))
}

fn has_assignment_with_min_len(line: &str, key: &str, min_len: usize) -> bool {
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
            if let Some(rest) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) {
                let value = rest.split_whitespace().next().unwrap_or("");
                if value.len() >= min_len {
                    return true;
                }
            }
        }
        search_from = end;
    }
    false
}

fn contains_raw_filename(line: &str) -> bool {
    for token in line.split_whitespace() {
        let token = token.trim_matches(|value: char| {
            matches!(
                value,
                '`' | '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>' | ',' | ';' | ':' | '.'
            )
        });
        let Some((name, extension)) = token.rsplit_once('.') else {
            continue;
        };
        let extension = extension.to_ascii_lowercase();
        if !name.is_empty() && RAW_FILENAME_EXTENSIONS.contains(&extension.as_str()) {
            return true;
        }
    }
    false
}

fn contains_raw_data_phrase(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    RAW_DATA_WORDS.iter().any(|word| {
        contains_phrase(&lower, &format!("raw {word}"))
            || contains_phrase(&lower, &format!("raw provider {word}"))
    })
}

fn prohibited_identifier(line: &str) -> Option<&'static str> {
    let normalized = normalize_identifier(line);
    PROHIBITED_IDENTIFIER_TOKENS
        .iter()
        .find_map(|(display, token)| normalized.contains(token).then_some(*display))
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn contains_phrase(text: &str, phrase: &str) -> bool {
    let mut search_from = 0;
    while let Some(offset) = text[search_from..].find(phrase) {
        let start = search_from + offset;
        let end = start + phrase.len();
        if is_left_boundary(text, start) && is_right_boundary(text, end) {
            return true;
        }
        search_from = end;
    }
    false
}

fn is_left_boundary(text: &str, index: usize) -> bool {
    index == 0
        || text[..index]
            .chars()
            .next_back()
            .map(|value| !is_word_char(value))
            .unwrap_or(true)
}

fn is_right_boundary(text: &str, index: usize) -> bool {
    index >= text.len()
        || text[index..]
            .chars()
            .next()
            .map(|value| !is_word_char(value))
            .unwrap_or(true)
}

fn is_word_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || value == '_'
}

fn is_source_ref_boundary_char(value: char) -> bool {
    is_word_char(value) || value == '-'
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_template() -> &'static str {
        "# Deployment Input Request Template\n\n\
## Intake Rules\n\
Source input documents describe how supplied raw material may be used safely.\n\
Use this static template to request deployment-time implementation inputs without committing live provider values, secrets, tokens, tenant identifiers, object identifiers, subscription identifiers, private addresses, serials, raw provider payloads, logs, rows, or real customer, host, user, or recipient data.\n\
- No credentials, tokens, secret values, keys, certificates, or recovery material.\n\
- No tenant IDs, object IDs, subscription IDs, resource IDs, serial numbers, private IPs, email addresses, real DNS names, URLs, raw payloads, raw logs, raw rows, or raw filenames.\n\
\n\
## Source Reference Register\n\
| Input Area | Source Reference | Details |\n\
| --- | --- | --- |\n\
| ServiceNow CMDB headers | source-ref-deployment-servicenow-cmdb-headers | servicenow-headers |\n\
| Entra role and group mapping | source-ref-deployment-entra-role-group-map | entra-role-group |\n\
| Harbor registry model | source-ref-deployment-harbor-model | harbor-registry |\n\
| Vault model | source-ref-deployment-vault-model | vault-config |\n\
| Azure storage and key vault model | source-ref-deployment-azure-storage-keyvault-model | azure-storage |\n\
| Firmware baseline model | source-ref-deployment-firmware-baseline-model | firmware-baseline |\n\
| Zabbix mapping | source-ref-deployment-zabbix-mapping | zabbix-config |\n\
| Veeam assumptions | source-ref-deployment-veeam-assumptions | veeam-assumptions |\n\
| Ingress DNS and load balancer model | source-ref-deployment-ingress-dns-lb-model | ingress-dns |\n\
\n\
## ServiceNow CMDB Headers\n\
source references and `sanitized-*` placeholders only\n\
\n\
## Entra Role And Group Mapping\n\
No live provider calls.\n\
\n\
## Harbor Model\n\
Raw source material stays outside committed docs, code, tests, fixtures, bundles, evidence, and logs.\n\
\n\
## Vault Model\n\
N-1 approval rule\n\
\n\
## Azure Blob And Key Vault Model\n\
Lenovo XCC SNMP exception\n\
\n\
## Firmware Baseline Model\n\
Current repository platform\n\
\n\
## Zabbix Mapping\n\
Future repository platform\n\
\n\
## Veeam Assumptions\n\
Proposal needed\n\
\n\
## Ingress DNS And Load-Balancer Model\n\
\n\
## Submission Checklist\n\
"
    }

    #[test]
    fn commented_source_refs_do_not_satisfy_required_refs() {
        let source_ref = "source-ref-deployment-harbor-model";
        let template = format!(
            "{}\n<!-- {source_ref} {source_ref} -->\n",
            valid_template().replace(source_ref, &format!("{source_ref}-suffix"))
        );
        let mut errors = Vec::new();

        validate_template_text(&template, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("missing source refs") && error.contains(source_ref)));
        assert!(errors.iter().any(|error| {
            error.contains("unexpected source refs")
                && error.contains(&format!("{source_ref}-suffix"))
        }));
    }

    #[test]
    fn fenced_markdown_decoys_do_not_satisfy_required_structure() {
        let source_ref = "source-ref-deployment-harbor-model";
        let template_without_section = valid_template()
            .lines()
            .filter(|line| line.trim() != "## Harbor Model")
            .collect::<Vec<&str>>()
            .join("\n");
        let template = format!(
            "{}\n```\n## Harbor Model\n| Harbor registry model | {source_ref} |\n{source_ref}\n```\n",
            template_without_section.replace(source_ref, &format!("{source_ref}-suffix"))
        );
        let mut errors = Vec::new();

        validate_template_text(&template, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("missing section Harbor Model")));
        assert!(errors
            .iter()
            .any(|error| error.contains("missing source refs") && error.contains(source_ref)));
    }

    #[test]
    fn duplicate_source_register_ids_and_details_are_rejected() {
        let duplicate_row = valid_template()
            .lines()
            .find(|line| line.contains("| ServiceNow CMDB headers |"))
            .expect("valid template has source register row");
        let template = valid_template().replacen(
            "## ServiceNow CMDB Headers",
            &format!("{duplicate_row}\n## ServiceNow CMDB Headers"),
            1,
        );
        let mut errors = Vec::new();

        validate_template_text(&template, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("register IDs must be unique")));
        assert!(errors
            .iter()
            .any(|error| error.contains("register details must be unique")));
    }

    #[test]
    fn source_ref_suffix_spoofing_is_rejected() {
        let source_ref = "source-ref-deployment-vault-model";
        let spoofed_ref = format!("{source_ref}-allowed");
        let template = valid_template().replace(source_ref, &spoofed_ref);
        let mut errors = Vec::new();

        validate_template_text(&template, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("missing source refs") && error.contains(source_ref)));
        assert!(errors.iter().any(|error| {
            error.contains("unexpected source refs") && error.contains(&spoofed_ref)
        }));
    }

    #[test]
    fn source_register_assignment_spoofing_is_rejected() {
        let template = valid_template().replacen(
            "| Harbor registry model | source-ref-deployment-harbor-model |",
            "| Harbor registry model | source-ref-deployment-harbor-model source-ref-deployment-vault-model |",
            1,
        );
        let mut errors = Vec::new();

        validate_template_text(&template, &mut errors);

        assert!(errors.iter().any(|error| {
            error.contains("source assignments must contain exactly one source ref")
        }));
    }

    #[test]
    fn source_register_assignment_with_extra_text_is_rejected() {
        let template = valid_template().replacen(
            "| Harbor registry model | source-ref-deployment-harbor-model |",
            "| Harbor registry model | source-ref-deployment-harbor-model approved-note |",
            1,
        );
        let mut errors = Vec::new();

        validate_template_text(&template, &mut errors);

        assert!(errors.iter().any(|error| {
            error.contains("source assignments must contain exactly one source ref")
        }));
    }

    #[test]
    fn prohibited_identifier_scanning_is_not_quoted_value_only() {
        let mut errors = Vec::new();

        validate_no_prohibited_values(
            "new { objectId = \"safe-summary\" }\ntenantId: sanitized-placeholder\nraw_provider_payload: sanitized-placeholder\nprivateIpAddress = \"safe-summary\"\nendpointId: sanitized-placeholder\nendpointFqdn: sanitized-placeholder\n",
            "synthetic.md",
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains("objectId")));
        assert!(errors.iter().any(|error| error.contains("tenantId")));
        assert!(errors
            .iter()
            .any(|error| error.contains("rawProviderPayload")));
        assert!(errors.iter().any(|error| error.contains("privateIp")));
        assert!(errors.iter().any(|error| error.contains("endpointId")));
        assert!(errors.iter().any(|error| error.contains("endpointFqdn")));
    }

    #[test]
    fn prohibited_scanning_still_reads_comments() {
        let mut errors = Vec::new();
        let decoy = ["<!-- ", "password", "=", "synthetic-value", " -->\n"].concat();

        validate_no_prohibited_values(&decoy, "synthetic.md", &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("secret or token assignment")));
    }
}
