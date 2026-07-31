use crate::models::*;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "password",
    "secret",
    "token",
    "credential",
    "key",
    "private",
    "auth",
];

/// Keyword labels that indicate a secret when a *value* under a generic key
/// (e.g. `execution_log`, `config`, `http_headers`) presents them as a
/// field/assignment: the label immediately followed — tolerating surrounding
/// quotes and whitespace — by a `:` or `=` delimiter. The delimiter scan in
/// [`value_bears_secret`] handles every spelling (`password:`, `Password=`,
/// `"password":`, `token = ...`) from ONE entry per label, fixing an earlier
/// asymmetry where `Password=` (connection strings) and `token:` slipped through.
const SENSITIVE_VALUE_LABELS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "secret_access_key",
    "access_key",
    "client_key",
    "private_key",
    "secret_key",
    "client_secret",
    "credential",
    "token",
    "session_token",
    "api_key",
    "apikey",
    "api-key",
    "x-api-key",
];

/// Secret-bearing value markers that need no delimiter — a full auth-scheme
/// prefix carries the credential right after it. (`Authorization: Bearer <jwt>`
/// / `Authorization: Basic <base64>` riding in a value under a generic key.)
const SENSITIVE_VALUE_MARKERS: &[&str] = &["bearer ", "authorization: basic "];

const AUTHORIZATION_LABEL: &str = "authorization";
const AUTHORIZATION_SCHEMES: &[&str] = &["basic", "bearer"];
const COOKIE_HEADER_LABELS: &[&str] = &["cookie", "set-cookie", "set_cookie"];
/// Exact credential-bearing cookie names admitted by the shipped secure and
/// explicit-loopback runtimes. Cookie names are case-sensitive on the wire, but
/// evidence matching is case-insensitive because logs and serializers can
/// normalize their presentation.
const CREDENTIAL_COOKIE_NAMES: &[&str] = &[
    "__host-ryuki_session",
    "ryuki_session",
    "__host-entra_login_csrf",
    "entra_login_csrf",
    "__host-oidc_login_csrf",
    "oidc_login_csrf",
];
const STRUCTURED_HEADER_NAME_FIELDS: &[&str] =
    &["name", "key", "header", "header_name", "header-name"];
const STRUCTURED_HEADER_VALUE_FIELDS: &[&str] = &[
    "value",
    "values",
    "header_value",
    "header-value",
    "header_values",
    "header-values",
];
const MAX_NESTED_JSON_SECRET_DEPTH: usize = 4;
const MAX_STRUCTURED_SECRET_BYTES: usize = 256 * 1024;
const MAX_STRUCTURED_SECRET_NODES: usize = 4_096;
/// Canonical replacement emitted by every evidence and audit projection.
pub const REDACTED_EVIDENCE_VALUE: &str = "***REDACTED***";

fn is_cookie_header_name(value: &str) -> bool {
    COOKIE_HEADER_LABELS
        .iter()
        .any(|label| value.eq_ignore_ascii_case(label))
}

fn is_credential_cookie_name(value: &str) -> bool {
    CREDENTIAL_COOKIE_NAMES
        .iter()
        .any(|name| value.eq_ignore_ascii_case(name))
}

fn is_sensitive_cookie_name(value: &str) -> bool {
    is_cookie_header_name(value) || is_credential_cookie_name(value)
}

fn is_named_field(key: &str, names: &[&str]) -> bool {
    names.iter().any(|name| key.eq_ignore_ascii_case(name))
}

fn object_is_cookie_header_entry(entries: &serde_json::Map<String, serde_json::Value>) -> bool {
    let names_cookie_header = entries.iter().any(|(key, value)| {
        is_named_field(key, STRUCTURED_HEADER_NAME_FIELDS)
            && value.as_str().is_some_and(is_sensitive_cookie_name)
    });
    let has_header_value = entries
        .keys()
        .any(|key| is_named_field(key, STRUCTURED_HEADER_VALUE_FIELDS));
    names_cookie_header && has_header_value
}

fn array_is_cookie_header_entry(values: &[serde_json::Value]) -> bool {
    values.len() >= 2
        && values
            .first()
            .and_then(serde_json::Value::as_str)
            .is_some_and(is_sensitive_cookie_name)
}

fn authorization_scheme_bears_secret(value: &str) -> bool {
    let value_lower = value.trim_start().to_ascii_lowercase();
    AUTHORIZATION_SCHEMES.iter().any(|scheme| {
        value_lower.strip_prefix(*scheme).is_some_and(|rest| {
            rest.chars()
                .next()
                .is_some_and(|character| character.is_ascii_whitespace())
                && !rest.trim().is_empty()
        })
    })
}

/// Recognizes exact `Authorization`, `Cookie`, and `Set-Cookie` fields in valid
/// JSON, including nested objects and JSON-encoded object strings. Parsing
/// first also covers escaped key spellings such as `\u0043ookie` without
/// teaching the fallback a partial JSON decoder.
///
/// Depth and node budgets bound nested/encoded traversal. Exhaustion is treated
/// as sensitive so an attacker cannot bypass redaction by hiding a cookie after
/// an oversized prefix.
fn structured_header_bears_secret(
    value: &serde_json::Value,
    depth: usize,
    remaining_nodes: &mut usize,
) -> bool {
    if depth > MAX_NESTED_JSON_SECRET_DEPTH || *remaining_nodes == 0 {
        return true;
    }
    *remaining_nodes -= 1;

    match value {
        serde_json::Value::Object(entries) => {
            object_is_cookie_header_entry(entries)
                || entries.iter().any(|(key, value)| {
                    (key.eq_ignore_ascii_case(AUTHORIZATION_LABEL)
                        && value
                            .as_str()
                            .is_some_and(authorization_scheme_bears_secret))
                        || is_sensitive_cookie_name(key)
                        || structured_header_bears_secret(value, depth + 1, remaining_nodes)
                })
        }
        serde_json::Value::Array(values) => {
            array_is_cookie_header_entry(values)
                || values
                    .iter()
                    .any(|value| structured_header_bears_secret(value, depth + 1, remaining_nodes))
        }
        serde_json::Value::String(encoded) => {
            if header_text_bears_secret(encoded) {
                return true;
            }
            let encoded = encoded.trim_start();
            if depth >= MAX_NESTED_JSON_SECRET_DEPTH
                || (!encoded.starts_with('{') && !encoded.starts_with('['))
            {
                return false;
            }
            if encoded.len() > MAX_STRUCTURED_SECRET_BYTES {
                return true;
            }
            serde_json::from_str::<serde_json::Value>(encoded).is_ok_and(|nested| {
                structured_header_bears_secret(&nested, depth + 1, remaining_nodes)
            })
        }
        _ => false,
    }
}

/// Bounded shared detector for parsed structured evidence. API audit/detail
/// sinks use the same recognizer as string evidence so header maps, named
/// entries, tuples, and nested JSON cannot diverge between output surfaces.
pub fn structured_value_bears_secret(value: &serde_json::Value) -> bool {
    let mut remaining_nodes = MAX_STRUCTURED_SECRET_NODES;
    structured_header_bears_secret(value, 0, &mut remaining_nodes)
}

fn trim_assignment_syntax(value: &str) -> &str {
    value.trim_start_matches(|character: char| {
        character.is_ascii_whitespace() || matches!(character, '"' | '\'' | '\\')
    })
}

/// Fallback for log lines or provider output that embeds a header or escaped
/// JSON fragment inside otherwise non-JSON text. The label must start at a word
/// boundary, be followed by `:`/`=`, and carry a non-empty Basic/Bearer value.
fn authorization_assignment_bears_secret(value_lower: &str) -> bool {
    let mut offset = 0;
    while let Some(relative) = value_lower[offset..].find(AUTHORIZATION_LABEL) {
        let position = offset + relative;
        let after_label = position + AUTHORIZATION_LABEL.len();
        let is_word_boundary = value_lower[..position]
            .chars()
            .next_back()
            .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');

        if is_word_boundary {
            let after = trim_assignment_syntax(&value_lower[after_label..]);
            if let Some(assigned) = after.strip_prefix(':').or_else(|| after.strip_prefix('=')) {
                let assigned = trim_assignment_syntax(assigned);
                if authorization_scheme_bears_secret(assigned) {
                    return true;
                }
            }
        }

        offset = after_label;
    }
    false
}

/// Fallback for header-shaped plaintext or escaped fragments stored under a
/// generic evidence key. Only exact Cookie/Set-Cookie labels followed by a
/// field delimiter match, so safe prose such as "cookie policy enabled" is
/// preserved.
fn cookie_assignment_bears_secret(value_lower: &str) -> bool {
    for &label in COOKIE_HEADER_LABELS
        .iter()
        .chain(CREDENTIAL_COOKIE_NAMES.iter())
    {
        let mut offset = 0;
        while let Some(relative) = value_lower[offset..].find(label) {
            let position = offset + relative;
            let after_label = position + label.len();
            let is_word_boundary = value_lower[..position]
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');

            if is_word_boundary {
                let after = trim_assignment_syntax(&value_lower[after_label..]);
                if after.starts_with(':') || after.starts_with('=') {
                    return true;
                }
            }

            offset = after_label;
        }
    }
    false
}

fn header_text_bears_secret(value: &str) -> bool {
    let value_lower = value.to_lowercase();
    SENSITIVE_VALUE_MARKERS
        .iter()
        .any(|marker| value_lower.contains(marker))
        || authorization_assignment_bears_secret(&value_lower)
        || cookie_assignment_bears_secret(&value_lower)
}

/// True if an evidence value looks like it carries a secret: an exact structured
/// Authorization/Cookie header, a robust embedded header assignment, a
/// standalone auth marker, or a known secret label immediately followed by a
/// `:`/`=` delimiter. Requiring the delimiter avoids redacting an incidental
/// prose mention ("the password was rotated"); when in doubt this errs toward
/// OVER-redaction, which is fail-safe for audit/evidence output.
fn value_bears_secret(value: &str) -> bool {
    let structured_candidate = value.trim_start();
    if structured_candidate.starts_with('{')
        || structured_candidate.starts_with('[')
        || structured_candidate.starts_with('"')
    {
        if value.len() > MAX_STRUCTURED_SECRET_BYTES {
            return true;
        }
        if serde_json::from_str::<serde_json::Value>(value)
            .is_ok_and(|structured| structured_value_bears_secret(&structured))
        {
            return true;
        }
    }

    let value_lower = value.to_lowercase();
    if SENSITIVE_VALUE_MARKERS
        .iter()
        .any(|marker| value_lower.contains(marker))
        || authorization_assignment_bears_secret(&value_lower)
        || cookie_assignment_bears_secret(&value_lower)
    {
        return true;
    }
    for label in SENSITIVE_VALUE_LABELS {
        let mut rest = value_lower.as_str();
        while let Some(pos) = rest.find(label) {
            let after = &rest[pos + label.len()..];
            let delim = after.trim_start_matches(['"', '\'', '\\', ' ', '\t']);
            if delim.starts_with(':') || delim.starts_with('=') {
                return true;
            }
            rest = &rest[pos + label.len()..];
        }
    }
    false
}

pub fn collect_evidence(request: &Request) -> Result<EvidencePack, String> {
    let id = format!(
        "ev-{}",
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    let now = Utc::now().to_rfc3339();

    let mut items: Vec<EvidenceItem> = Vec::new();

    items.push(EvidenceItem {
        key: "request-payload-summary".into(),
        value: format!(
            "Request {} of type {} for site {} environment {} owner {} criticality {}",
            request.id,
            request.request_type,
            request.site,
            request.environment,
            request.owner,
            request.criticality
        ),
        redacted_value: None,
        redacted: false,
        evidence_type: EvidenceType::Summary,
    });

    for stage in &request.stages {
        for evidence in &stage.evidence {
            items.push(evidence.clone());
        }
    }

    if let Some(ref manifest_id) = request.evidence_manifest_id {
        items.push(EvidenceItem {
            key: "evidence-manifest-reference".into(),
            value: manifest_id.clone(),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::Summary,
        });
    }

    for approver in &request.approval_route {
        items.push(EvidenceItem {
            key: "approval-route-entry".into(),
            value: format!("Approver role: {}", approver),
            redacted_value: None,
            redacted: false,
            evidence_type: EvidenceType::ApprovalDecision,
        });
    }

    let mut pack = EvidencePack {
        id,
        request_id: request.id.clone(),
        items,
        redacted: false,
        created_at: now,
        format: "json".into(),
        compliance_checks: Vec::new(),
        metadata: HashMap::new(),
    };

    redact_evidence(&mut pack)?;

    pack.redacted = true;

    Ok(pack)
}

pub fn redact_evidence(pack: &mut EvidencePack) -> Result<(), String> {
    for item in pack.items.iter_mut() {
        let raw_value_is_sensitive = should_redact(&item.key, &item.value);
        let supplied_redacted_value_is_sensitive = item
            .redacted_value
            .as_deref()
            .is_some_and(|candidate| should_redact("", candidate));
        if raw_value_is_sensitive || supplied_redacted_value_is_sensitive {
            item.redacted = true;
            // A caller-controlled redacted_value is not trusted as a safe
            // substitute for a newly detected credential.
            item.redacted_value = Some(REDACTED_EVIDENCE_VALUE.into());
        }
        // For every redacted item (whether just flagged above or pre-marked
        // by the lifecycle), overwrite the raw value with the safe form so
        // the pack — and its digest — never carry a sensitive raw value.
        if item.redacted {
            let safe_value = item
                .redacted_value
                .clone()
                .unwrap_or_else(|| REDACTED_EVIDENCE_VALUE.into());
            item.value = safe_value.clone();
            item.redacted_value = Some(safe_value);
        }
    }
    for (key, value) in &mut pack.metadata {
        *value = redact_sensitive_text(key, value);
    }
    for check in &mut pack.compliance_checks {
        *check = redact_sensitive_text("", check);
    }
    pack.redacted = true;
    Ok(())
}

/// Whether an evidence/audit field should be redacted, by key name or by a
/// secret-bearing value pattern. Pure and pattern-only (no I/O); shared with the
/// API's audit-read redaction so the two stay consistent.
pub fn should_redact(key: &str, value: &str) -> bool {
    if key_bears_secret(key) {
        return true;
    }

    value_bears_secret(value)
}

fn key_bears_secret(key: &str) -> bool {
    let key_lower = key.to_lowercase();

    if is_sensitive_cookie_name(key.trim()) {
        return true;
    }

    for pattern in SENSITIVE_KEY_PATTERNS {
        if key_lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Return a display/persistence-safe representation of one free-text field.
/// Legitimate text is preserved byte-for-byte; detected credential material is
/// replaced with the one canonical marker.
pub fn redact_sensitive_text(key: &str, value: &str) -> String {
    if should_redact(key, value) {
        REDACTED_EVIDENCE_VALUE.to_string()
    } else {
        value.to_string()
    }
}

/// Recursively redact parsed JSON evidence using the same bounded header and
/// value detector as string evidence. This is the shared boundary used by API
/// audit/detail projection for historical structured rows.
pub fn redact_json_evidence_value(value: &serde_json::Value) -> serde_json::Value {
    let mut remaining_nodes = MAX_STRUCTURED_SECRET_NODES;
    redact_json_evidence_value_inner(value, None, 0, &mut remaining_nodes)
}

fn redact_json_evidence_value_inner(
    value: &serde_json::Value,
    field_key: Option<&str>,
    depth: usize,
    remaining_nodes: &mut usize,
) -> serde_json::Value {
    if depth > MAX_NESTED_JSON_SECRET_DEPTH || *remaining_nodes == 0 {
        return serde_json::Value::String(REDACTED_EVIDENCE_VALUE.to_string());
    }
    *remaining_nodes -= 1;

    match value {
        serde_json::Value::Object(entries) => {
            if object_is_cookie_header_entry(entries) {
                return serde_json::Value::String(REDACTED_EVIDENCE_VALUE.to_string());
            }
            let mut redacted = serde_json::Map::with_capacity(entries.len());
            for (key, child) in entries {
                let safe_child = if key_bears_secret(key) {
                    serde_json::Value::String(REDACTED_EVIDENCE_VALUE.to_string())
                } else {
                    redact_json_evidence_value_inner(child, Some(key), depth + 1, remaining_nodes)
                };
                redacted.insert(key.clone(), safe_child);
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(values) => {
            if array_is_cookie_header_entry(values) {
                return serde_json::Value::String(REDACTED_EVIDENCE_VALUE.to_string());
            }
            serde_json::Value::Array(
                values
                    .iter()
                    .map(|child| {
                        redact_json_evidence_value_inner(child, None, depth + 1, remaining_nodes)
                    })
                    .collect(),
            )
        }
        serde_json::Value::String(text) => {
            if should_redact(field_key.unwrap_or_default(), text) {
                serde_json::Value::String(REDACTED_EVIDENCE_VALUE.to_string())
            } else {
                value.clone()
            }
        }
        _ => value.clone(),
    }
}

pub fn export_evidence(pack: &EvidencePack, format: &str) -> Result<String, String> {
    if !pack.redacted {
        return Err("Cannot export unredacted evidence pack.".into());
    }

    let safe_pack = build_safe_export_pack(pack);

    match format {
        "json" => serde_json::to_string_pretty(&safe_pack).map_err(|e| e.to_string()),
        "yaml" => serde_yaml::to_string(&safe_pack).map_err(|e| e.to_string()),
        _ => Err(format!("Unsupported export format: {}", format)),
    }
}

/// Converts an evidence pack to a safe export representation where
/// redacted items expose only their redacted_value or a safe marker,
/// never the original sensitive value.
fn build_safe_export_pack(pack: &EvidencePack) -> serde_json::Value {
    let items: Vec<serde_json::Value> = pack
        .items
        .iter()
        .map(|item| {
            let dynamically_redacted = should_redact(&item.key, &item.value);
            let safe_value = safe_export_value(item);
            serde_json::json!({
                "key": item.key,
                "value": safe_value,
                "redacted": item.redacted || dynamically_redacted,
                "evidence_type": item.evidence_type,
            })
        })
        .collect();
    let metadata: HashMap<String, String> = pack
        .metadata
        .iter()
        .map(|(key, value)| (key.clone(), redact_sensitive_text(key, value)))
        .collect();
    let compliance_checks: Vec<String> = pack
        .compliance_checks
        .iter()
        .map(|check| redact_sensitive_text("", check))
        .collect();

    serde_json::json!({
        "id": pack.id,
        "request_id": pack.request_id,
        "items": items,
        "redacted": pack.redacted,
        "created_at": pack.created_at,
        "format": pack.format,
        "compliance_checks": compliance_checks,
        "metadata": metadata,
    })
}

/// Returns the safe export value for an evidence item.
/// - If redacted with redacted_value → uses that
/// - If redacted without redacted_value → uses safe marker
/// - If not redacted → uses original value
fn safe_export_value(item: &EvidenceItem) -> String {
    if should_redact(&item.key, &item.value) {
        REDACTED_EVIDENCE_VALUE.to_string()
    } else if item.redacted {
        item.redacted_value
            .as_deref()
            .filter(|candidate| !should_redact("", candidate))
            .unwrap_or(REDACTED_EVIDENCE_VALUE)
            .to_string()
    } else {
        item.value.clone()
    }
}

pub fn verify_evidence_compliance(pack: &EvidencePack) -> Result<Vec<String>, String> {
    let mut checks: Vec<String> = Vec::new();

    if !pack.redacted {
        checks.push("FAIL: Evidence pack is not redacted".into());
    } else {
        checks.push("PASS: Evidence pack is redacted".into());
    }

    let total = pack.items.len();
    let redacted_count = pack.items.iter().filter(|i| i.redacted).count();
    let unredacted_count = total - redacted_count;

    checks.push(format!(
        "Evidence items: {} total, {} redacted, {} unredacted",
        total, redacted_count, unredacted_count
    ));

    for item in &pack.items {
        if item.redacted && item.redacted_value.is_none() {
            checks.push(format!(
                "FAIL: Item '{}' is marked redacted but has no redacted_value",
                item.key
            ));
        }
        if !item.redacted && should_redact(&item.key, &item.value) {
            checks.push(format!(
                "FAIL: Item '{}' contains sensitive content but is not redacted",
                item.key
            ));
        }
    }

    let has_summary = pack
        .items
        .iter()
        .any(|i| matches!(i.evidence_type, EvidenceType::Summary));
    if !has_summary {
        checks.push("WARN: No summary evidence item found".into());
    }

    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_lifecycle;

    fn make_request_with_stages() -> Request {
        let mut req = request_lifecycle::create_request(
            "windows-server-deployment",
            RequestType::ServerDeployment,
            "alice",
            "bob",
            "DEFRA",
            "production",
            "critical",
        )
        .unwrap();
        req.approval_route.push("Datacenter Approver".into());
        req = request_lifecycle::transition_status(&req, RequestStatus::Validated).unwrap();
        let stages = request_lifecycle::plan_request(&req).unwrap();
        req.stages.extend(stages);
        req
    }

    #[test]
    fn test_collect_evidence_creates_redacted_pack() {
        let req = make_request_with_stages();
        let pack = collect_evidence(&req).unwrap();
        assert!(pack.redacted);
        assert!(!pack.items.is_empty());
    }

    #[test]
    fn test_redact_evidence_redacts_sensitive_keys() {
        let mut pack = EvidencePack {
            id: "ev-001".into(),
            request_id: "req-001".into(),
            items: vec![
                EvidenceItem {
                    key: "admin_password".into(),
                    value: "supersecret123".into(),
                    redacted_value: None,
                    redacted: false,
                    evidence_type: EvidenceType::ExecutionLog,
                },
                EvidenceItem {
                    key: "server_name".into(),
                    value: "web-server-01".into(),
                    redacted_value: None,
                    redacted: false,
                    evidence_type: EvidenceType::Summary,
                },
            ],
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        redact_evidence(&mut pack).unwrap();

        let password_item = pack
            .items
            .iter()
            .find(|i| i.key == "admin_password")
            .unwrap();
        assert!(password_item.redacted);
        assert_eq!(password_item.redacted_value, Some("***REDACTED***".into()));

        let server_item = pack.items.iter().find(|i| i.key == "server_name").unwrap();
        assert!(!server_item.redacted);
    }

    #[test]
    fn test_redact_evidence_redacts_token_in_value() {
        let mut pack = EvidencePack {
            id: "ev-002".into(),
            request_id: "req-002".into(),
            items: vec![EvidenceItem {
                key: "config".into(),
                value: "api_token=abc123xyz".into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        redact_evidence(&mut pack).unwrap();
        assert!(pack.items[0].redacted);
    }

    #[test]
    fn test_redact_evidence_redacts_bearer_token_under_generic_key() {
        // A JWT rides in an Authorization header inside a GENERIC-keyed evidence
        // value (the key is not sensitive), so only the value pattern can catch
        // it. Regression for the Bearer-token redaction gap.
        let mut pack = EvidencePack {
            id: "ev-bearer".into(),
            request_id: "req-bearer".into(),
            items: vec![EvidenceItem {
                key: "execution_log".into(),
                value: "GET /api/x -> 200; Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
                    .into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };
        redact_evidence(&mut pack).unwrap();
        assert!(
            pack.items[0].redacted,
            "an Authorization: Bearer token must be redacted even under a generic key"
        );
    }

    #[test]
    fn test_should_redact_bearer_and_secret_value_patterns() {
        assert!(should_redact(
            "execution_log",
            "Authorization: Bearer eyJabc.def.ghi"
        ));
        assert!(should_redact("config", "client_secret=topsecret")); // secret-scan-allow: test fixture, fake value asserting the secret= pattern is caught
        assert!(should_redact(
            "execution_log",
            r#"backend rejected \"client_key\": \"SYNTH-MARKER\""#
        ));
        assert!(should_redact(
            "execution_log",
            r#"nested={\"client_secret\":\"SYNTH-MARKER\"}"#
        ));
        assert!(should_redact("execution_log", "credential=SYNTH-MARKER"));
        assert!(
            !should_redact("status", "deployment ok, no credentials present"),
            "benign evidence must not be over-redacted"
        );
    }

    #[test]
    fn test_should_redact_structured_authorization_credentials() {
        for value in [
            r#"{"Authorization":"Basic SYNTH-BASIC-MARKER"}"#,
            r#"{"authorization":"Bearer SYNTH-BEARER-MARKER"}"#,
            r#"{"headers":{"\u0041uthorization":"Basic SYNTH-UNICODE-MARKER"}}"#,
            r#"nested={\"Authorization\":\"Basic SYNTH-ESCAPED-MARKER\"}"#,
            "Authorization = 'Bearer SYNTH-HEADER-MARKER'",
        ] {
            assert!(
                should_redact("execution_log", value),
                "structured credential must be redacted: {value}"
            );
        }

        for value in [
            r#"{"authorization":"Digest SYNTH-NONSECRET-METADATA"}"#,
            r#"{"authorization":"Basic"}"#,
            r#"{"authorization_url":"Basic SYNTH-NONSECRET-METADATA"}"#,
            r#"{"message":"authorization policy metadata only"}"#,
        ] {
            assert!(
                !should_redact("execution_log", value),
                "non-credential metadata must not be over-redacted: {value}"
            );
        }
    }

    #[test]
    fn test_should_redact_cookie_evidence_shapes_without_redacting_safe_metadata() {
        for (key, value) in [
            ("Cookie", "__Host-ryuki_session=SYNTH-REQUEST-COOKIE"),
            (
                "set-cookie",
                "__Host-ryuki_session=SYNTH-RESPONSE-COOKIE; Secure; HttpOnly",
            ),
            (
                "http_headers",
                "Cookie: __Host-ryuki_session=SYNTH-PLAINTEXT-REQUEST",
            ),
            (
                "http_headers",
                "Set-Cookie: __Host-ryuki_session=SYNTH-PLAINTEXT-RESPONSE; Secure",
            ),
            (
                "provider_output",
                r#"{"headers":{"Cookie":"__Host-ryuki_session=SYNTH-JSON-REQUEST"}}"#,
            ),
            (
                "provider_output",
                r#"{"headers":[{"name":"Set-Cookie","value":"__Host-ryuki_session=SYNTH-NAMED-RESPONSE"}]}"#,
            ),
            (
                "provider_output",
                r#"{"headers":[["Cookie","__Host-ryuki_session=SYNTH-TUPLE-REQUEST"]]}"#,
            ),
            (
                "provider_output",
                r#"{"response":"{\"headers\":{\"Set-Cookie\":\"__Host-ryuki_session=SYNTH-NESTED-RESPONSE\"}}"}"#,
            ),
            ("reason", "__Host-ryuki_session=SYNTH-BARE-SECURE-SESSION"),
            ("reason", "ryuki_session=SYNTH-BARE-LOOPBACK-SESSION"),
            ("reason", "__Host-entra_login_csrf=SYNTH-BARE-ENTRA-BINDING"),
            (
                "reason",
                "entra_login_csrf=SYNTH-BARE-LOOPBACK-ENTRA-BINDING",
            ),
            ("reason", "__Host-oidc_login_csrf=SYNTH-BARE-OIDC-BINDING"),
            ("reason", "oidc_login_csrf=SYNTH-BARE-LOOPBACK-OIDC-BINDING"),
        ] {
            assert!(
                should_redact(key, value),
                "cookie-bearing evidence must be redacted for key {key}"
            );
        }

        for (key, value) in [
            (
                "cookie_policy",
                "Secure and HttpOnly browser policy enabled",
            ),
            ("execution_log", "cookie policy enabled; SameSite is strict"),
            (
                "configuration",
                r#"{"cookie_policy":{"secure":true,"http_only":true}}"#,
            ),
            ("summary", "browser compatibility check completed"),
        ] {
            assert!(
                !should_redact(key, value),
                "non-secret cookie metadata must remain available for key {key}"
            );
        }
    }

    #[test]
    fn test_redact_and_export_remove_cookie_values_but_preserve_safe_evidence() {
        let raw_cookie_markers = [
            "SYNTH-COOKIE-KEY-MARKER",
            "SYNTH-COOKIE-LINE-MARKER",
            "SYNTH-SET-COOKIE-JSON-MARKER",
        ];
        let safe_summary = "browser policy validation passed";
        let mut pack = EvidencePack {
            id: "ev-cookie-redaction".into(),
            request_id: "req-cookie-redaction".into(),
            items: vec![
                EvidenceItem {
                    key: "Cookie".into(),
                    value: format!("__Host-ryuki_session={}", raw_cookie_markers[0]),
                    redacted_value: None,
                    redacted: false,
                    evidence_type: EvidenceType::ExecutionLog,
                },
                EvidenceItem {
                    key: "request_headers".into(),
                    value: format!("Cookie: __Host-ryuki_session={}", raw_cookie_markers[1]),
                    redacted_value: None,
                    redacted: false,
                    evidence_type: EvidenceType::ExecutionLog,
                },
                EvidenceItem {
                    key: "provider_output".into(),
                    value: format!(
                        r#"{{"headers":[{{"name":"Set-Cookie","value":"__Host-ryuki_session={}; Secure"}}]}}"#,
                        raw_cookie_markers[2]
                    ),
                    redacted_value: None,
                    redacted: false,
                    evidence_type: EvidenceType::ExecutionLog,
                },
                EvidenceItem {
                    key: "summary".into(),
                    value: safe_summary.into(),
                    redacted_value: None,
                    redacted: false,
                    evidence_type: EvidenceType::Summary,
                },
            ],
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        redact_evidence(&mut pack).unwrap();

        for item in &pack.items[..raw_cookie_markers.len()] {
            assert!(item.redacted, "cookie evidence must be marked redacted");
            assert_eq!(item.value, "***REDACTED***");
            assert_eq!(item.redacted_value.as_deref(), Some("***REDACTED***"));
        }
        assert!(!pack.items[raw_cookie_markers.len()].redacted);
        assert_eq!(pack.items[raw_cookie_markers.len()].value, safe_summary);

        let serialized_pack = serde_json::to_string(&pack).unwrap();
        let exported_pack = export_evidence(&pack, "json").unwrap();
        for marker in raw_cookie_markers {
            assert!(!serialized_pack.contains(marker));
            assert!(!exported_pack.contains(marker));
        }
        assert!(serialized_pack.contains(safe_summary));
        assert!(exported_pack.contains(safe_summary));
    }

    #[test]
    fn test_hostile_redacted_value_cannot_reintroduce_cookie_credential() {
        let raw_marker = "SYNTH-RAW-COOKIE-CANARY";
        let replacement_marker = "SYNTH-HOSTILE-REPLACEMENT-CANARY";
        let metadata_marker = "SYNTH-METADATA-COOKIE-CANARY";
        let compliance_marker = "SYNTH-COMPLIANCE-COOKIE-CANARY";
        let safe_metadata = "ordinary evidence metadata";
        let safe_compliance = "approval policy check passed";
        let mut pack = EvidencePack {
            id: "ev-hostile-redacted-value".into(),
            request_id: "req-hostile-redacted-value".into(),
            items: vec![EvidenceItem {
                key: "reason".into(),
                value: format!("__Host-ryuki_session={raw_marker}"),
                redacted_value: Some(format!("ryuki_session={replacement_marker}")),
                redacted: false,
                evidence_type: EvidenceType::ApprovalDecision,
            }],
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: vec![
                format!("Cookie: ryuki_session={compliance_marker}"),
                safe_compliance.into(),
            ],
            metadata: HashMap::from([
                (
                    "reason".into(),
                    format!("__Host-entra_login_csrf={metadata_marker}"),
                ),
                ("summary".into(), safe_metadata.into()),
            ]),
        };

        redact_evidence(&mut pack).unwrap();
        assert!(pack.items[0].redacted);
        assert_eq!(pack.items[0].value, REDACTED_EVIDENCE_VALUE);
        assert_eq!(
            pack.items[0].redacted_value.as_deref(),
            Some(REDACTED_EVIDENCE_VALUE)
        );
        assert_eq!(
            pack.metadata.get("reason").map(String::as_str),
            Some(REDACTED_EVIDENCE_VALUE)
        );
        assert_eq!(
            pack.metadata.get("summary").map(String::as_str),
            Some(safe_metadata)
        );
        assert_eq!(pack.compliance_checks[0], REDACTED_EVIDENCE_VALUE);
        assert_eq!(pack.compliance_checks[1], safe_compliance);

        let serialized = serde_json::to_string(&pack).unwrap();
        let exported = export_evidence(&pack, "json").unwrap();
        for marker in [
            raw_marker,
            replacement_marker,
            metadata_marker,
            compliance_marker,
        ] {
            assert!(!serialized.contains(marker));
            assert!(!exported.contains(marker));
        }
        assert!(serialized.contains(safe_metadata));
        assert!(serialized.contains(safe_compliance));
        assert!(exported.contains(safe_metadata));
        assert!(exported.contains(safe_compliance));
    }

    #[test]
    fn test_export_defensively_redacts_historical_metadata_and_compliance_values() {
        let metadata_marker = "SYNTH-HISTORICAL-METADATA-COOKIE-CANARY";
        let compliance_marker = "SYNTH-HISTORICAL-COMPLIANCE-COOKIE-CANARY";
        let safe_metadata = "ordinary historical metadata";
        let safe_compliance = "change-policy evidence present";
        let pack = EvidencePack {
            id: "ev-historical-metadata-export".into(),
            request_id: "req-historical-metadata-export".into(),
            items: Vec::new(),
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: vec![
                format!("Set-Cookie: oidc_login_csrf={compliance_marker}"),
                safe_compliance.into(),
            ],
            metadata: HashMap::from([
                (
                    "reason".into(),
                    format!("__Host-ryuki_session={metadata_marker}"),
                ),
                ("summary".into(), safe_metadata.into()),
            ]),
        };

        let exported = export_evidence(&pack, "json").unwrap();
        assert!(!exported.contains(metadata_marker));
        assert!(!exported.contains(compliance_marker));
        assert!(exported.contains(safe_metadata));
        assert!(exported.contains(safe_compliance));
        let exported: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(exported["metadata"]["reason"], REDACTED_EVIDENCE_VALUE);
        assert_eq!(exported["compliance_checks"][0], REDACTED_EVIDENCE_VALUE);
    }

    #[test]
    fn test_structured_json_redactor_handles_named_and_tuple_cookie_entries() {
        let named_marker = "SYNTH-NAMED-COOKIE-CANARY";
        let tuple_marker = "SYNTH-TUPLE-COOKIE-CANARY";
        let detail = serde_json::json!({
            "headers": [
                {
                    "name": "Cookie",
                    "value": format!("session={named_marker}")
                },
                [
                    "Set-Cookie",
                    format!("session={tuple_marker}"),
                    {"sensitive": true}
                ]
            ],
            "note": "ordinary audit context"
        });

        assert!(structured_value_bears_secret(&detail));
        let redacted = redact_json_evidence_value(&detail);
        let serialized = serde_json::to_string(&redacted).unwrap();
        assert!(!serialized.contains(named_marker));
        assert!(!serialized.contains(tuple_marker));
        assert_eq!(redacted["note"], "ordinary audit context");
    }

    #[test]
    fn test_redact_and_export_remove_escaped_structured_authorization() {
        let marker = "SYNTH-STRUCTURED-BASIC-MARKER";
        let mut pack = EvidencePack {
            id: "ev-structured-authorization".into(),
            request_id: "req-structured-authorization".into(),
            items: vec![EvidenceItem {
                key: "execution_log".into(),
                value: format!(r#"provider={{\"Authorization\":\"Basic {marker}\"}}"#),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        redact_evidence(&mut pack).unwrap();
        assert!(pack.items[0].redacted);
        assert_eq!(pack.items[0].value, "***REDACTED***");
        let exported = export_evidence(&pack, "json").unwrap();
        assert!(!exported.contains(marker));
    }

    #[test]
    fn test_should_redact_covers_both_colon_and_equals_spellings() {
        // Regression: `password=` (connection strings) and `token:` were NOT
        // matched while `password:` and `token=` were — an asymmetric bypass that
        // let the most common secret shape (a DB connection string) survive
        // redaction of a generic-keyed value shared with audit reads.
        // All values below are fake fixtures asserting redaction patterns are caught.
        assert!(
            should_redact("execution_log", "Server=db;Password=hunter2;"), // secret-scan-allow: fake fixture
            "connection-string Password= must be redacted"
        );
        assert!(
            should_redact("cmd", "psql --password=hunter2"), // secret-scan-allow: fake fixture
            "flag-style --password= must be redacted"
        );
        assert!(
            should_redact("http_headers", "X-Auth-Token: abc123"), // secret-scan-allow: fake fixture
            "token: spelling must be redacted"
        );
        assert!(
            should_redact("config", "api_token=abc123"), // secret-scan-allow: fake fixture
            "token= spelling must be redacted"
        );
        // Symmetry sanity: the previously-working spellings still match.
        assert!(should_redact("yaml", "password: hunter2")); // secret-scan-allow: fake fixture
        assert!(should_redact("env", "SECRET_TOKEN=abc")); // secret-scan-allow: fake fixture

        // Quoted-JSON, spaced, and additional label shapes (Codex-hardening).
        assert!(should_redact("json", "{\"password\":\"hunter2\"}")); // secret-scan-allow: fake fixture
        assert!(should_redact("json", "{'token' : 'abc'}")); // secret-scan-allow: fake fixture
        assert!(should_redact("dsn", "pwd=hunter2")); // secret-scan-allow: fake fixture
        assert!(should_redact("dsn", "passwd = hunter2")); // secret-scan-allow: fake fixture
        assert!(should_redact("aws", "aws_secret_access_key=AKIA")); // secret-scan-allow: fake fixture
        assert!(should_redact("hdr", "Authorization: Basic dXNlcjpwYXNz")); // secret-scan-allow: fake fixture

        // A benign value that merely contains the word 'password' in prose,
        // without a `:`/`=` delimiter, is NOT a value-pattern hit.
        assert!(
            !should_redact("note", "the password was rotated last week"),
            "prose mention without a delimiter must not over-redact"
        );
        assert!(
            !should_redact("log", "processing complete, no anomalies"),
            "benign log line must not over-redact"
        );
    }

    #[test]
    fn test_export_evidence_unredacted_fails() {
        let pack = EvidencePack {
            id: "ev-003".into(),
            request_id: "req-003".into(),
            items: Vec::new(),
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        assert!(export_evidence(&pack, "json").is_err());
    }

    #[test]
    fn test_export_evidence_json_format() {
        let pack = EvidencePack {
            id: "ev-004".into(),
            request_id: "req-004".into(),
            items: vec![EvidenceItem {
                key: "summary".into(),
                value: "All clear".into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::Summary,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        let exported = export_evidence(&pack, "json").unwrap();
        assert!(exported.contains("summary"));
        assert!(exported.contains("All clear"));
    }

    #[test]
    fn test_export_evidence_yaml_format() {
        let pack = EvidencePack {
            id: "ev-005".into(),
            request_id: "req-005".into(),
            items: vec![EvidenceItem {
                key: "summary".into(),
                value: "Test".into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::Summary,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "yaml".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        let exported = export_evidence(&pack, "yaml").unwrap();
        assert!(!exported.is_empty());
    }

    #[test]
    fn test_export_evidence_unsupported_format() {
        let pack = EvidencePack {
            id: "ev-006".into(),
            request_id: "req-006".into(),
            items: Vec::new(),
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        assert!(export_evidence(&pack, "csv").is_err());
    }

    #[test]
    fn test_verify_evidence_compliance_unredacted() {
        let pack = EvidencePack {
            id: "ev-007".into(),
            request_id: "req-007".into(),
            items: Vec::new(),
            redacted: false,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        let checks = verify_evidence_compliance(&pack).unwrap();
        assert!(checks.iter().any(|c| c.contains("not redacted")));
    }

    #[test]
    fn test_verify_evidence_compliance_redacted() {
        let pack = EvidencePack {
            id: "ev-008".into(),
            request_id: "req-008".into(),
            items: vec![EvidenceItem {
                key: "summary".into(),
                value: "Test".into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::Summary,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };

        let checks = verify_evidence_compliance(&pack).unwrap();
        assert!(checks.iter().any(|c| c.contains("redacted")));
    }

    #[test]
    fn test_collect_evidence_no_sensitive_data_leaked() {
        let req = make_request_with_stages();
        let pack = collect_evidence(&req).unwrap();
        let json = export_evidence(&pack, "json").unwrap();

        assert!(!json.contains("password"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("token"));
        assert!(!json.contains("credential"));
        assert!(!json.contains("api_key"));
    }

    #[test]
    fn test_export_evidence_original_sensitive_value_excluded() {
        // RED: current export serializes full EvidencePack including raw value.
        // The export MUST NOT contain the original sensitive value.
        let pack = EvidencePack {
            id: "ev-redact-001".into(),
            request_id: "req-001".into(),
            items: vec![EvidenceItem {
                key: "admin_password".into(),
                value: "supersecret123".into(),
                redacted_value: Some("***REDACTED***".into()),
                redacted: true,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };
        let exported = export_evidence(&pack, "json").unwrap();
        assert!(!exported.contains("supersecret123"));
        assert!(exported.contains("***REDACTED***"));
    }

    #[test]
    fn test_export_evidence_missing_redaction_uses_safe_marker() {
        // RED: item redacted but no redacted_value — must not expose original value.
        let pack = EvidencePack {
            id: "ev-redact-002".into(),
            request_id: "req-002".into(),
            items: vec![EvidenceItem {
                key: "token_field".into(),
                value: "leaked-token-abc".into(),
                redacted_value: None,
                redacted: true,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };
        let exported = export_evidence(&pack, "json").unwrap();
        assert!(!exported.contains("leaked-token-abc"));
        assert!(exported.contains("***REDACTED***"));
    }

    #[test]
    fn test_export_evidence_non_sensitive_value_preserved() {
        // Non-sensitive values must remain in the export.
        let pack = EvidencePack {
            id: "ev-redact-003".into(),
            request_id: "req-003".into(),
            items: vec![EvidenceItem {
                key: "server_name".into(),
                value: "web-server-01".into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::Summary,
            }],
            redacted: true,
            created_at: Utc::now().to_rfc3339(),
            format: "json".into(),
            compliance_checks: Vec::new(),
            metadata: HashMap::new(),
        };
        let exported = export_evidence(&pack, "json").unwrap();
        assert!(exported.contains("web-server-01"));
    }

    /// REGRESSION: the full pipeline (collect_evidence → redact_evidence) must
    /// not leak a raw sensitive value into the serialized pack JSON — the same
    /// representation that the API writes into `content.pack` and the portal
    /// renders in the JSON-export panel.
    ///
    /// We inject a stage with a pre-built EvidenceItem whose `key` matches a
    /// sensitive pattern and whose `value` holds a recognisable raw secret.
    /// After collect_evidence, we serialize the ENTIRE EvidencePack (the
    /// pack struct, not the safe-export wrapper) to JSON and assert:
    ///   - the raw secret is absent from the serialized bytes
    ///   - "***REDACTED***" is present in the serialized bytes
    #[test]
    fn test_regression_redact_evidence_raw_value_absent_in_serialized_pack() {
        let raw_secret = "password: hunter2";
        let mut req = make_request_with_stages();

        // Inject a stage that carries an item with the raw sensitive value.
        req.stages.push(Stage {
            name: "sensitive-stage".into(),
            status: StageStatus::Completed,
            started_at: None,
            completed_at: None,
            evidence: vec![EvidenceItem {
                key: "admin_password".into(),
                value: raw_secret.into(),
                redacted_value: None,
                redacted: false,
                evidence_type: EvidenceType::ExecutionLog,
            }],
            metadata: HashMap::new(),
        });

        let pack = collect_evidence(&req).expect("collect_evidence must succeed");

        // Serialize the FULL EvidencePack struct — the same path the API uses
        // when it calls serde_json::to_value(&pack) into content.pack.
        let serialized = serde_json::to_string(&pack).expect("pack must serialize");

        assert!(
            !serialized.contains(raw_secret),
            "raw secret must not appear in the serialized pack; found in: {serialized}"
        );
        assert!(
            serialized.contains("***REDACTED***"),
            "***REDACTED*** must appear in the serialized pack"
        );
    }
}
