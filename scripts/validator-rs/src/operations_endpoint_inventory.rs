use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const DOC_PATH: &str = "docs/operations/endpoint-inventory.md";
const README_PATH: &str = "docs/operations/README.md";
const REQUIRED_CATEGORIES: &[&str] = &[
    "public-portal-routing",
    "vmware-platform",
    "veeam-platform",
    "zabbix-monitoring",
    "servicenow-file-exchange",
    "identity-directory",
    "dns-ipam-ca",
    "sql-inventory",
    "evidence-object-storage",
    "cloudnativepg-database",
    "vault-runtime-secrets",
    "vaultwarden-cli-secrets",
    "harbor-registry",
    "kubernetes-runtime",
    "azure-object-backup",
    "queue-outbox",
    "windows-gmsa-workers",
    "protected-runners",
    "platform-self-monitoring",
    "logging-metrics-traces",
];
const REQUIRED_STATUSES: &[&str] = &[
    "confirmed-category",
    "pending-approved-discovery",
    "deferred",
];
const REQUIRED_SECTIONS: &[&str] = &[
    "Endpoint Category Inventory",
    "Collection Boundary",
    "Browser Isolation",
    "Approved Discovery Outputs",
];
const REDACTION_BOUNDARY: &str = "no raw endpoint names, FQDNs, URLs, tenant identifiers, object identifiers, private network values, credentials, tokens, or provider payloads";
const VAULTWARDEN_STATIC_BOUNDARY: &str =
    "Vaultwarden and vaultwarden-cli entries remain static, dry-run, and approval-gated";
const LEGACY_SECRET_PROVIDER_WORDING: &[&str] = &["conjur", "cyberark", "hashicorp"];
const ALLOWED_VAULT_CATEGORY_IDS: &[&str] = &["vault-runtime-secrets"];
const README_LINK: &str = "[Endpoint Inventory](endpoint-inventory.md)";
const README_CATEGORY_RULE: &str = "endpoint categories only";

#[derive(Debug, Deserialize)]
struct Context {
    doc: String,
    readme: String,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    doc: Option<String>,
    readme: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    text: String,
    path: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid operations endpoint inventory context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_doc_text(&context.doc, &mut errors);
    validate_readme_text(&context.readme, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid operations endpoint inventory docs JSON: {error}"))?;
    let mut errors = Vec::new();
    if let Some(doc) = payload.doc {
        validate_doc_text(&doc, &mut errors);
    }
    if let Some(readme) = payload.readme {
        validate_readme_text(&readme, &mut errors);
    }
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid operations endpoint inventory prohibited-text JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_no_forbidden_text(&payload.text, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_doc_text(doc: &str, errors: &mut Vec<String>) {
    for section in REQUIRED_SECTIONS {
        expect(
            doc.contains(&format!("## {section}")),
            errors,
            format!("endpoint inventory missing section {section}"),
        );
    }
    expect(
        doc.contains(REDACTION_BOUNDARY),
        errors,
        "endpoint inventory must declare redaction boundary",
    );
    expect(
        doc.contains(VAULTWARDEN_STATIC_BOUNDARY),
        errors,
        "endpoint inventory must declare Vaultwarden and vaultwarden-cli static boundary",
    );
    if contains_legacy_secret_provider_wording(doc) {
        errors.push("endpoint inventory contains legacy secret provider wording".to_string());
    }
    validate_table_categories(doc, errors);
    validate_no_forbidden_text(doc, DOC_PATH, errors);
}

fn validate_table_categories(doc: &str, errors: &mut Vec<String>) {
    let mut categories = Vec::new();
    let mut active_table_lines = Vec::new();
    let mut in_html_comment = false;
    for (index, line) in doc.lines().enumerate() {
        let visible_line = line_without_html_comments(line, &mut in_html_comment);
        if let Some(category) = category_from_table_line(&visible_line) {
            categories.push(category);
        }
        if visible_line.starts_with("| `") {
            active_table_lines.push((index, visible_line));
        }
    }

    let missing: Vec<&str> = REQUIRED_CATEGORIES
        .iter()
        .copied()
        .filter(|required| !categories.iter().any(|category| category == required))
        .collect();
    let unexpected: Vec<&str> = categories
        .iter()
        .map(String::as_str)
        .filter(|category| !REQUIRED_CATEGORIES.contains(category))
        .collect();

    if !missing.is_empty() {
        errors.push(format!(
            "endpoint inventory missing categories: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "endpoint inventory unexpected categories: {}",
            unexpected.join(", ")
        ));
    }

    let unique: BTreeSet<&str> = categories.iter().map(String::as_str).collect();
    expect(
        unique.len() == categories.len(),
        errors,
        "endpoint inventory categories must be unique",
    );

    for (index, line) in active_table_lines {
        let columns: Vec<&str> = line
            .split('|')
            .map(str::trim)
            .filter(|column| !column.is_empty())
            .collect();
        let status = columns.last().copied().unwrap_or_default();
        if !REQUIRED_STATUSES.contains(&status) {
            errors.push(format!(
                "{DOC_PATH}:{} has invalid status {status}",
                index + 1
            ));
        }
    }
}

fn line_without_html_comments(line: &str, in_html_comment: &mut bool) -> String {
    let mut visible = String::new();
    let mut rest = line;

    loop {
        if *in_html_comment {
            let Some(end) = rest.find("-->") else {
                break;
            };
            *in_html_comment = false;
            rest = &rest[end + 3..];
            continue;
        }

        let Some(comment_start) = rest.find("<!--") else {
            visible.push_str(rest);
            break;
        };

        visible.push_str(&rest[..comment_start]);
        rest = &rest[comment_start + 4..];
        if let Some(comment_end) = rest.find("-->") {
            rest = &rest[comment_end + 3..];
        } else {
            *in_html_comment = true;
            break;
        }
    }

    visible
}

fn category_from_table_line(line: &str) -> Option<String> {
    if !line.starts_with('|') {
        return None;
    }

    let after_pipe = line[1..].trim_start();
    let category_start = after_pipe.strip_prefix('`')?;
    let end = category_start.find('`')?;
    let after_category = category_start[end + 1..].trim_start();
    if !after_category.starts_with('|') {
        return None;
    }

    Some(category_start[..end].to_string())
}

fn validate_readme_text(readme: &str, errors: &mut Vec<String>) {
    expect(
        readme.contains(README_LINK),
        errors,
        "operations README missing endpoint inventory link",
    );
    expect(
        readme.contains(README_CATEGORY_RULE),
        errors,
        "operations README must require endpoint categories only",
    );
    if contains_legacy_secret_provider_wording(readme) {
        errors.push("operations README contains legacy secret provider wording".to_string());
    }
    validate_no_forbidden_text(readme, README_PATH, errors);
}

fn validate_no_forbidden_text(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if line.starts_with("| Category Id |") || line.starts_with("|---") {
            continue;
        }

        if contains_forbidden_text(line) {
            errors.push(format!(
                "{path}:{} contains raw endpoint or placeholder detail",
                index + 1
            ));
        }
    }
}

fn contains_forbidden_text(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    contains_word(&lower, "tbd")
        || contains_phrase(&lower, "to confirm")
        || lower.contains("http://")
        || lower.contains("https://")
        || contains_domain_like(&lower)
        || contains_private_ipv4(&lower)
        || contains_uuid(&lower)
        || contains_secret_path(&lower)
        || contains_sensitive_assignment(&lower)
}

fn contains_word(text: &str, word: &str) -> bool {
    let mut search_from = 0;
    while let Some(offset) = text[search_from..].find(word) {
        let start = search_from + offset;
        let end = start + word.len();
        if is_word_boundary(text, start) && is_word_boundary(text, end) {
            return true;
        }
        search_from = end;
    }
    false
}

fn contains_phrase(text: &str, phrase: &str) -> bool {
    let mut search_from = 0;
    while let Some(offset) = text[search_from..].find(phrase) {
        let start = search_from + offset;
        let end = start + phrase.len();
        if is_word_boundary(text, start) && is_word_boundary(text, end) {
            return true;
        }
        search_from = end;
    }
    false
}

fn is_word_boundary(text: &str, byte_index: usize) -> bool {
    if byte_index == 0 || byte_index >= text.len() {
        return true;
    }
    let before = text[..byte_index].chars().next_back().unwrap_or(' ');
    let after = text[byte_index..].chars().next().unwrap_or(' ');
    !is_word_char(before) || !is_word_char(after)
}

fn is_word_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || value == '_'
}

fn contains_domain_like(line: &str) -> bool {
    for token in line.split(|value: char| !is_domain_char(value)) {
        let token = token.trim_matches('.');
        if !token.contains('.') {
            continue;
        }

        let labels: Vec<&str> = token.split('.').collect();
        if labels.len() < 2 || !labels.iter().all(|label| valid_domain_label(label)) {
            continue;
        }

        if labels.len() >= 3 || forbidden_two_label_suffix(labels[1]) {
            return true;
        }
    }
    false
}

fn is_domain_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || value == '-' || value == '.'
}

fn valid_domain_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '-')
}

fn forbidden_two_label_suffix(suffix: &str) -> bool {
    matches!(
        suffix,
        "local"
            | "lan"
            | "corp"
            | "internal"
            | "invalid"
            | "example"
            | "test"
            | "com"
            | "net"
            | "org"
            | "io"
            | "cloud"
            | "svc"
            | "cluster"
    )
}

fn contains_private_ipv4(line: &str) -> bool {
    for token in line.split(|value: char| !(value.is_ascii_digit() || value == '.')) {
        let octets: Vec<&str> = token.split('.').collect();
        if octets.len() != 4
            || !octets.iter().all(|octet| {
                !octet.is_empty() && octet.len() <= 3 && octet.chars().all(|c| c.is_ascii_digit())
            })
        {
            continue;
        }

        let first = octets[0].parse::<u16>().unwrap_or(999);
        let second = octets[1].parse::<u16>().unwrap_or(999);
        if first == 10
            || (first == 192 && second == 168)
            || (first == 172 && (16..=31).contains(&second))
        {
            return true;
        }
    }
    false
}

fn contains_uuid(line: &str) -> bool {
    for token in line.split(|value: char| !(value.is_ascii_hexdigit() || value == '-')) {
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

fn contains_secret_path(line: &str) -> bool {
    [
        "kv/",
        "secret/",
        "vault/",
        "vaultwarden/",
        "vaultwarden-cli/",
        "conjur/",
    ]
    .iter()
    .any(|prefix| contains_prefixed_path(line, prefix))
}

fn contains_legacy_secret_provider_wording(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if LEGACY_SECRET_PROVIDER_WORDING
        .iter()
        .any(|provider| contains_word(&lower, provider))
    {
        return true;
    }

    text.to_ascii_lowercase()
        .lines()
        .map(remove_allowed_vault_category_ids)
        .any(|line| contains_word(&line, "vault"))
}

fn remove_allowed_vault_category_ids(line: &str) -> String {
    ALLOWED_VAULT_CATEGORY_IDS
        .iter()
        .fold(line.to_string(), |current, category| {
            current.replace(category, "")
        })
}

fn contains_prefixed_path(line: &str, prefix: &str) -> bool {
    let mut search_from = 0;
    while let Some(offset) = line[search_from..].find(prefix) {
        let start = search_from + offset;
        let end = start + prefix.len();
        let boundary_ok = start == 0
            || line[..start]
                .chars()
                .next_back()
                .map(|value| !is_word_char(value) && value != '-')
                .unwrap_or(true);
        let has_path = line[end..]
            .chars()
            .next()
            .map(|value| value.is_ascii_alphanumeric() || matches!(value, '_' | '.' | '/' | '-'))
            .unwrap_or(false);
        if boundary_ok && has_path {
            return true;
        }
        search_from = end;
    }
    false
}

fn contains_sensitive_assignment(line: &str) -> bool {
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
        "client_id",
        "tenant_id",
        "object_id",
        "username",
        "user_name",
        "secret_path",
        "secret_ref",
        "secret_reference",
    ]
    .iter()
    .any(|key| has_assignment(line, key))
}

fn has_assignment(line: &str, key: &str) -> bool {
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
                if rest.chars().any(|value| !value.is_whitespace()) {
                    return true;
                }
            }
        }
        search_from = end;
    }
    false
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_doc() -> String {
        let mut doc = [
            "## Endpoint Category Inventory",
            "| Category Id | Summary | Status |",
            "|---|---|---|",
        ]
        .join("\n");
        doc.push('\n');
        for category in REQUIRED_CATEGORIES {
            doc.push_str(&format!(
                "| `{category}` | Static dry-run inventory summary | confirmed-category |\n"
            ));
        }
        doc.push_str("\n## Collection Boundary\n");
        doc.push_str(REDACTION_BOUNDARY);
        doc.push('\n');
        doc.push_str(VAULTWARDEN_STATIC_BOUNDARY);
        doc.push_str("\n\n## Browser Isolation\nStatic browser isolation only.\n");
        doc.push_str("\n## Approved Discovery Outputs\nApproved redacted summaries only.\n");
        doc
    }

    #[test]
    fn commented_required_category_decoy_does_not_satisfy_inventory() {
        let doc = valid_doc();
        let changed_doc = doc
            .lines()
            .filter(|line| !line.contains("`vault-runtime-secrets`"))
            .collect::<Vec<_>>()
            .join("\n");
        let changed_doc = format!(
            "{changed_doc}\n<!--\n| `vault-runtime-secrets` | Static dry-run inventory summary | confirmed-category |\n-->\n"
        );
        let mut errors = Vec::new();

        validate_doc_text(&changed_doc, &mut errors);

        assert!(errors.iter().any(|error| {
            error.contains("missing categories") && error.contains("vault-runtime-secrets")
        }));
    }

    #[test]
    fn commented_status_row_decoy_is_ignored() {
        let doc = format!(
            "{}\n<!--\n| `vault-runtime-secrets` | Static dry-run inventory summary | live-discovery |\n-->\n",
            valid_doc()
        );
        let mut errors = Vec::new();

        validate_doc_text(&doc, &mut errors);

        assert!(!errors
            .iter()
            .any(|error| error.contains("invalid status live-discovery")));
    }

    #[test]
    fn active_row_with_inline_comment_is_still_validated() {
        let doc = format!(
            "{}\n| `vault-runtime-secrets` | Static dry-run inventory summary | live-discovery | <!-- active row comment -->\n",
            valid_doc()
        );
        let mut errors = Vec::new();

        validate_doc_text(&doc, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("invalid status live-discovery")));
    }

    #[test]
    fn active_duplicate_row_with_inline_comment_is_still_validated() {
        let doc = format!(
            "{}\n| `vault-runtime-secrets` | Static dry-run inventory summary | confirmed-category | <!-- active row comment -->\n",
            valid_doc()
        );
        let mut errors = Vec::new();

        validate_doc_text(&doc, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("endpoint inventory categories must be unique")));
    }
}
