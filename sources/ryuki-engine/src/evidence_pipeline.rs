use crate::models::*;
use chrono::Utc;
use serde::Deserialize;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::collections::{HashMap, HashSet};
use std::fmt;
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

/// Secret-bearing value markers that need no delimiter. The broad Bearer
/// marker is retained for JWT-like credentials, while Basic credentials use
/// the bounded canonical recognizer below so ordinary text such as `Basic
/// delegated` is not over-redacted.
const SENSITIVE_VALUE_MARKERS: &[&str] = &["bearer ", "authorization: basic "];

const AUTHORIZATION_LABEL: &str = "authorization";
const AUTHORIZATION_SCHEMES: &[&str] = &["basic", "bearer"];
const COOKIE_HEADER_LABELS: &[&str] = &["cookie", "set-cookie", "set_cookie"];
/// Exact credential-bearing cookie names used by the shipped runtimes or by
/// common application frameworks. Cookie names are case-sensitive on the wire,
/// but evidence matching is case-insensitive because logs and serializers can
/// normalize their presentation.
const CREDENTIAL_COOKIE_NAMES: &[&str] = &[
    "__host-ryuki_session",
    "ryuki_session",
    "__host-entra_login_csrf",
    "entra_login_csrf",
    "__host-oidc_login_csrf",
    "oidc_login_csrf",
    // Common framework session-cookie names can arrive in provider/audit text
    // without an enclosing Cookie header. Keep these exact (the assignment
    // parser still requires a field boundary plus ':'/'=') so generic evidence
    // catches credentials without treating ordinary session prose as secret.
    "session",
    "sessionid",
    "session_id",
    "jsessionid",
    "phpsessid",
    "asp.net_sessionid",
    "connect.sid",
    "laravel_session",
    "_session_id",
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
const MAX_EMBEDDED_STRUCTURED_END_CANDIDATES: usize = 32;
/// Upper bound for validating one standalone Basic credential. HTTP stacks
/// ordinarily cap the complete header below this size. A longer token-shaped
/// value after the Basic scheme fails closed without allocating or decoding it.
const MAX_STANDALONE_BASIC_CREDENTIAL_BYTES: usize = 8 * 1024;
/// Canonical replacement emitted by every evidence and audit projection.
pub const REDACTED_EVIDENCE_VALUE: &str = "***REDACTED***";

struct DuplicateKeyScanState {
    remaining_nodes: usize,
    fail_closed: bool,
}

impl DuplicateKeyScanState {
    fn consume_node(&mut self) -> bool {
        if self.remaining_nodes == 0 {
            self.fail_closed = true;
            false
        } else {
            self.remaining_nodes -= 1;
            true
        }
    }
}

struct DuplicateKeyScanSeed<'a> {
    state: &'a mut DuplicateKeyScanState,
}

impl<'de> DeserializeSeed<'de> for DuplicateKeyScanSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if !self.state.consume_node() {
            return Err(serde::de::Error::custom(
                "structured evidence duplicate-key scan exhausted its node budget",
            ));
        }
        deserializer.deserialize_any(DuplicateKeyScanVisitor { state: self.state })
    }
}

struct DuplicateKeyScanVisitor<'a> {
    state: &'a mut DuplicateKeyScanState,
}

impl<'de> Visitor<'de> for DuplicateKeyScanVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a valid JSON evidence value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(DuplicateKeyScanSeed {
                state: &mut *self.state,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !self.state.consume_node() {
                return Err(serde::de::Error::custom(
                    "structured evidence duplicate-key scan exhausted its node budget",
                ));
            }
            if !keys.insert(key) {
                self.state.fail_closed = true;
                return Err(serde::de::Error::custom(
                    "structured evidence contains a duplicate object key",
                ));
            }
            object.next_value_seed(DuplicateKeyScanSeed {
                state: &mut *self.state,
            })?;
        }
        Ok(())
    }
}

/// `serde_json::Value` intentionally retains only one value for a duplicate
/// object key. Evidence redaction cannot accept that ambiguity because a raw
/// credential can occupy a discarded occurrence. This bounded validation pass
/// observes every decoded key before materializing the ordinary value tree and
/// fails closed on either a duplicate key or budget exhaustion.
fn valid_json_has_ambiguous_structure(value: &str) -> bool {
    let mut state = DuplicateKeyScanState {
        remaining_nodes: MAX_STRUCTURED_SECRET_NODES,
        fail_closed: false,
    };
    let mut deserializer = serde_json::Deserializer::from_str(value);
    let scan = DuplicateKeyScanSeed { state: &mut state }
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end());

    state.fail_closed || scan.is_err()
}

enum StructuredFragmentScan {
    Safe { consumed_bytes: usize },
    Sensitive,
}

fn fragment_start_looks_structured(value: &str, offset: usize, opening: char) -> bool {
    let assigned = value[..offset]
        .trim_end()
        .chars()
        .next_back()
        .is_some_and(|character| matches!(character, ':' | '='));
    if assigned {
        return true;
    }

    let after_opening = value[offset + opening.len_utf8()..].trim_start();
    match opening {
        '{' => {
            after_opening.is_empty()
                || after_opening.starts_with('}')
                || after_opening.starts_with('"')
                || after_opening.starts_with("\\\"")
        }
        '[' => {
            after_opening.is_empty()
                || after_opening.starts_with(']')
                || after_opening.starts_with('"')
                || after_opening.starts_with("\\\"")
                || after_opening.starts_with('{')
                || after_opening.starts_with('[')
                || after_opening.starts_with('-')
                || after_opening.chars().next().is_some_and(|character| {
                    character.is_ascii_digit() || matches!(character, 't' | 'f' | 'n')
                })
        }
        _ => false,
    }
}

fn inspect_structured_fragment_prefix(value: &str, opening: char) -> StructuredFragmentScan {
    let closing = match opening {
        '{' => '}',
        '[' => ']',
        _ => return StructuredFragmentScan::Sensitive,
    };
    let mut candidates = 0;

    for (offset, character) in value.char_indices() {
        if offset >= MAX_STRUCTURED_SECRET_BYTES {
            return StructuredFragmentScan::Sensitive;
        }
        if character != closing {
            continue;
        }
        candidates += 1;
        if candidates > MAX_EMBEDDED_STRUCTURED_END_CANDIDATES {
            return StructuredFragmentScan::Sensitive;
        }

        let consumed_bytes = offset + character.len_utf8();
        if consumed_bytes > MAX_STRUCTURED_SECRET_BYTES {
            return StructuredFragmentScan::Sensitive;
        }
        let fragment = &value[..consumed_bytes];

        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(fragment) {
            return if valid_json_has_ambiguous_structure(fragment)
                || structured_value_bears_secret(&parsed)
            {
                StructuredFragmentScan::Sensitive
            } else {
                StructuredFragmentScan::Safe { consumed_bytes }
            };
        }

        let encoded = format!("\"{fragment}\"");
        let Ok(decoded) = serde_json::from_str::<String>(&encoded) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&decoded) else {
            continue;
        };
        return if valid_json_has_ambiguous_structure(&decoded)
            || structured_value_bears_secret(&parsed)
        {
            StructuredFragmentScan::Sensitive
        } else {
            StructuredFragmentScan::Safe { consumed_bytes }
        };
    }

    StructuredFragmentScan::Sensitive
}

/// Inspect complete direct or one-layer JSON-escaped objects/arrays embedded in
/// otherwise free-form evidence. Candidate counts and bytes are capped; a
/// structured-looking fragment that cannot be decoded completely fails closed.
fn embedded_structured_text_bears_secret(value: &str) -> bool {
    let mut search_offset = 0;
    while search_offset < value.len() {
        let Some((relative, opening)) = value[search_offset..]
            .char_indices()
            .find(|(_, character)| matches!(character, '{' | '['))
        else {
            break;
        };
        let offset = search_offset + relative;
        if !fragment_start_looks_structured(value, offset, opening) {
            search_offset = offset + opening.len_utf8();
            continue;
        }

        match inspect_structured_fragment_prefix(&value[offset..], opening) {
            StructuredFragmentScan::Sensitive => return true,
            StructuredFragmentScan::Safe { consumed_bytes } => {
                search_offset = offset + consumed_bytes;
            }
        }
    }
    false
}

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

/// Validate a value only after its direct map key or sibling/tuple name has
/// been bound to the exact `Authorization` header. This keeps unrelated header
/// values and empty Basic/Bearer scheme metadata from triggering redaction.
fn structured_authorization_value_bears_secret(
    value: &serde_json::Value,
    remaining_nodes: &mut usize,
) -> bool {
    if *remaining_nodes == 0 {
        return true;
    }
    *remaining_nodes -= 1;

    match value {
        serde_json::Value::String(value) => authorization_scheme_bears_secret(value),
        serde_json::Value::Array(values) => {
            for value in values {
                if *remaining_nodes == 0 {
                    return true;
                }
                *remaining_nodes -= 1;
                if value
                    .as_str()
                    .is_some_and(authorization_scheme_bears_secret)
                {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn object_is_sensitive_header_entry(
    entries: &serde_json::Map<String, serde_json::Value>,
    remaining_nodes: &mut usize,
) -> bool {
    let names_cookie_header = entries.iter().any(|(key, value)| {
        is_named_field(key, STRUCTURED_HEADER_NAME_FIELDS)
            && value.as_str().is_some_and(is_sensitive_cookie_name)
    });
    let names_authorization_header = entries.iter().any(|(key, value)| {
        is_named_field(key, STRUCTURED_HEADER_NAME_FIELDS)
            && value
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(AUTHORIZATION_LABEL))
    });
    let has_header_value = entries
        .keys()
        .any(|key| is_named_field(key, STRUCTURED_HEADER_VALUE_FIELDS));

    (names_cookie_header && has_header_value)
        || (names_authorization_header
            && entries.iter().any(|(key, value)| {
                is_named_field(key, STRUCTURED_HEADER_VALUE_FIELDS)
                    && structured_authorization_value_bears_secret(value, remaining_nodes)
            }))
}

fn array_is_sensitive_header_entry(
    values: &[serde_json::Value],
    remaining_nodes: &mut usize,
) -> bool {
    let Some(name) = values.first().and_then(serde_json::Value::as_str) else {
        return false;
    };
    let Some(value) = values.get(1) else {
        return false;
    };

    is_sensitive_cookie_name(name)
        || (name.eq_ignore_ascii_case(AUTHORIZATION_LABEL)
            && structured_authorization_value_bears_secret(value, remaining_nodes))
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

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_token68_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
}

fn base64_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Validate canonical RFC 4648 base64 and inspect the decoded bytes in-place.
/// Basic credentials encode `user-id ":" password`; requiring that delimiter
/// distinguishes credential material from safe prose such as `Basic mode`.
fn canonical_basic_credential_bears_user_pass(token: &[u8]) -> bool {
    if token.len() < 4
        || token.len() > MAX_STANDALONE_BASIC_CREDENTIAL_BYTES
        || !token.len().is_multiple_of(4)
    {
        return false;
    }

    let padding = token.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return false;
    }
    let data_len = token.len() - padding;
    if data_len == 0
        || token[..data_len]
            .iter()
            .any(|byte| base64_sextet(*byte).is_none())
        || token[data_len..].iter().any(|byte| *byte != b'=')
    {
        return false;
    }

    // RFC 4648 canonical encodings have zeroed unused bits in their final
    // sextet. Rejecting alternate encodings keeps this recognizer narrow and
    // prevents accepting a valid prefix of malformed token68 text.
    let final_sextet = base64_sextet(token[data_len - 1]).expect("validated base64 sextet");
    if (padding == 1 && final_sextet & 0b11 != 0) || (padding == 2 && final_sextet & 0b1111 != 0) {
        return false;
    }

    token.chunks_exact(4).any(|chunk| {
        let first = base64_sextet(chunk[0]).expect("validated base64 quartet");
        let second = base64_sextet(chunk[1]).expect("validated base64 quartet");
        let third = base64_sextet(chunk[2]).unwrap_or(0);
        let fourth = base64_sextet(chunk[3]).unwrap_or(0);
        let decoded = [
            (first << 2) | (second >> 4),
            (second << 4) | (third >> 2),
            (third << 6) | fourth,
        ];
        let decoded_len = if chunk[2] == b'=' {
            1
        } else if chunk[3] == b'=' {
            2
        } else {
            3
        };
        decoded[..decoded_len].contains(&b':')
    })
}

/// Recognize a standalone `Basic <base64(user:password)>` field or an embedded
/// occurrence under a generic key. Matching is ASCII case-insensitive, accepts
/// ASCII whitespace, requires an HTTP-token boundary before the scheme, and
/// consumes the complete token68 candidate before validating canonical base64.
fn standalone_basic_credential_bears_secret(value: &str) -> bool {
    const BASIC_SCHEME: &[u8] = b"basic";

    let bytes = value.as_bytes();
    let mut offset = 0;
    while offset + BASIC_SCHEME.len() <= bytes.len() {
        let after_scheme = offset + BASIC_SCHEME.len();
        if bytes[offset..after_scheme].eq_ignore_ascii_case(BASIC_SCHEME)
            && (offset == 0 || !is_http_token_byte(bytes[offset - 1]))
            && bytes.get(after_scheme).is_some_and(u8::is_ascii_whitespace)
        {
            let mut token_start = after_scheme;
            while bytes.get(token_start).is_some_and(u8::is_ascii_whitespace) {
                token_start += 1;
            }

            let mut token_end = token_start;
            while bytes
                .get(token_end)
                .is_some_and(|byte| is_token68_byte(*byte))
            {
                token_end += 1;
                if token_end - token_start > MAX_STANDALONE_BASIC_CREDENTIAL_BYTES {
                    return true;
                }
            }

            if canonical_basic_credential_bears_user_pass(&bytes[token_start..token_end]) {
                return true;
            }
        }
        offset += 1;
    }
    false
}

/// Recognizes exact `Authorization`, `Cookie`, and `Set-Cookie` fields in valid
/// JSON, including nested objects and JSON-encoded object strings. Parsing
/// first also covers escaped key spellings such as `\u0043ookie` without
/// teaching the fallback a partial JSON decoder.
///
/// Depth and node budgets bound nested/encoded traversal. Exhaustion is treated
/// as sensitive so an attacker cannot bypass redaction by hiding a credential
/// after an oversized prefix.
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
            object_is_sensitive_header_entry(entries, remaining_nodes)
                || entries.iter().any(|(key, value)| {
                    (key.eq_ignore_ascii_case(AUTHORIZATION_LABEL)
                        && structured_authorization_value_bears_secret(value, remaining_nodes))
                        || is_sensitive_cookie_name(key)
                        || structured_header_bears_secret(value, depth + 1, remaining_nodes)
                })
        }
        serde_json::Value::Array(values) => {
            array_is_sensitive_header_entry(values, remaining_nodes)
                || values
                    .iter()
                    .any(|value| structured_header_bears_secret(value, depth + 1, remaining_nodes))
        }
        serde_json::Value::String(encoded) => {
            if header_text_bears_secret(encoded) {
                return true;
            }
            let encoded = encoded.trim_start();
            if !encoded.starts_with('{') && !encoded.starts_with('[') {
                return false;
            }
            if depth >= MAX_NESTED_JSON_SECRET_DEPTH {
                return true;
            }
            if encoded.len() > MAX_STRUCTURED_SECRET_BYTES {
                return true;
            }
            let Ok(nested) = serde_json::from_str::<serde_json::Value>(encoded) else {
                return true;
            };
            valid_json_has_ambiguous_structure(encoded)
                || structured_header_bears_secret(&nested, depth + 1, remaining_nodes)
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

fn parse_json_array_prefix(value: &str) -> Option<serde_json::Value> {
    let mut deserializer = serde_json::Deserializer::from_str(value);
    let parsed = serde_json::Value::deserialize(&mut deserializer).ok()?;
    parsed.is_array().then_some(parsed)
}

fn parse_escaped_json_array_prefix(value: &str) -> Option<serde_json::Value> {
    let mut candidates = 0;
    for (offset, character) in value.char_indices() {
        if character != ']' {
            continue;
        }
        candidates += 1;
        if candidates > MAX_EMBEDDED_STRUCTURED_END_CANDIDATES {
            return None;
        }

        // Decode only through this candidate terminator. This keeps unrelated
        // trailing log text outside the synthetic JSON string while serde_json
        // decides whether a quoted `]` was data or the actual array boundary.
        let fragment = &value[..offset + character.len_utf8()];
        let encoded = format!("\"{fragment}\"");
        let Ok(decoded) = serde_json::from_str::<String>(&encoded) else {
            continue;
        };
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&decoded)
            && parsed.is_array()
        {
            return Some(parsed);
        }
    }
    None
}

fn authorization_array_assignment_bears_secret(value: &str) -> bool {
    if !value.starts_with('[') {
        return false;
    }
    if value.len() > MAX_STRUCTURED_SECRET_BYTES {
        return true;
    }

    let parsed = parse_json_array_prefix(value).or_else(|| parse_escaped_json_array_prefix(value));
    let Some(parsed) = parsed else {
        // An Authorization assignment that looks like an array but cannot be
        // decoded unambiguously is not safe evidence.
        return true;
    };

    let mut remaining_nodes = MAX_STRUCTURED_SECRET_NODES;
    structured_authorization_value_bears_secret(&parsed, &mut remaining_nodes)
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
                if authorization_scheme_bears_secret(assigned)
                    || authorization_array_assignment_bears_secret(assigned)
                {
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
        || standalone_basic_credential_bears_secret(value)
        || authorization_assignment_bears_secret(&value_lower)
        || cookie_assignment_bears_secret(&value_lower)
}

fn normalize_json_unicode_escapes_once(value: &str) -> Result<Option<String>, ()> {
    if !value.contains("\\u") {
        return Ok(None);
    }
    if value.len() > MAX_STRUCTURED_SECRET_BYTES {
        return Err(());
    }

    let bytes = value.as_bytes();
    let mut normalized = String::with_capacity(value.len());
    let mut copied_from = 0;
    let mut offset = 0;
    let mut changed = false;
    while offset < bytes.len() {
        if bytes[offset] != b'\\' {
            offset += value[offset..].chars().next().ok_or(())?.len_utf8();
            continue;
        }

        // Decode active JSON-style escapes while preserving escaped literals.
        // An even backslash run leaves `uXXXX` literal; an odd run makes only
        // its final slash active. Invalid escapes remain ordinary text, so
        // paths such as `C:\\users` are preserved.
        let escape_start = offset;
        while bytes.get(offset) == Some(&b'\\') {
            offset += 1;
        }
        let backslash_count = offset - escape_start;
        if backslash_count.is_multiple_of(2) || bytes.get(offset) != Some(&b'u') {
            continue;
        }

        let Some(first_hex) = bytes.get(offset + 1..offset + 5) else {
            continue;
        };
        let Ok(first_hex) = std::str::from_utf8(first_hex) else {
            continue;
        };
        let Ok(first) = u16::from_str_radix(first_hex, 16) else {
            continue;
        };
        let first_end = offset + 5;

        let (character, escape_end) = if (0xD800..=0xDBFF).contains(&first) {
            if bytes.get(first_end) != Some(&b'\\') || bytes.get(first_end + 1) != Some(&b'u') {
                continue;
            }
            let Some(second_hex) = bytes.get(first_end + 2..first_end + 6) else {
                continue;
            };
            let Ok(second_hex) = std::str::from_utf8(second_hex) else {
                continue;
            };
            let Ok(second) = u16::from_str_radix(second_hex, 16) else {
                continue;
            };
            if !(0xDC00..=0xDFFF).contains(&second) {
                continue;
            }
            let scalar =
                0x1_0000 + ((u32::from(first) - 0xD800) << 10) + (u32::from(second) - 0xDC00);
            let Some(character) = char::from_u32(scalar) else {
                continue;
            };
            (character, first_end + 6)
        } else if (0xDC00..=0xDFFF).contains(&first) {
            continue;
        } else {
            let Some(character) = char::from_u32(u32::from(first)) else {
                continue;
            };
            (character, first_end)
        };

        let active_escape_start = escape_start + backslash_count - 1;
        normalized.push_str(&value[copied_from..active_escape_start]);
        normalized.push(character);
        offset = escape_end;
        copied_from = escape_end;
        changed = true;
    }

    if !changed {
        Ok(None)
    } else {
        normalized.push_str(&value[copied_from..]);
        Ok(Some(normalized))
    }
}

/// True if an evidence value looks like it carries a secret: an exact structured
/// Authorization/Cookie header, a robust embedded header assignment, a
/// standalone auth marker, or a known secret label immediately followed by a
/// `:`/`=` delimiter. Requiring the delimiter avoids redacting an incidental
/// prose mention ("the password was rotated"); when in doubt this errs toward
/// OVER-redaction, which is fail-safe for audit/evidence output.
fn value_bears_secret(value: &str) -> bool {
    value_bears_secret_inner(value, true)
}

fn value_bears_secret_inner(value: &str, normalize_unicode: bool) -> bool {
    let structured_candidate = value.trim_start();
    let starts_structured_value = structured_candidate.starts_with('"')
        || structured_candidate
            .chars()
            .next()
            .filter(|opening| matches!(opening, '{' | '['))
            .is_some_and(|opening| {
                fragment_start_looks_structured(structured_candidate, 0, opening)
            });
    if starts_structured_value {
        if value.len() > MAX_STRUCTURED_SECRET_BYTES {
            return true;
        }
        let Ok(structured) = serde_json::from_str::<serde_json::Value>(value) else {
            return true;
        };
        if valid_json_has_ambiguous_structure(value) || structured_value_bears_secret(&structured) {
            return true;
        }
    }

    if embedded_structured_text_bears_secret(value) {
        return true;
    }

    if normalize_unicode && !starts_structured_value {
        match normalize_json_unicode_escapes_once(value) {
            Ok(Some(normalized)) if value_bears_secret_inner(&normalized, false) => return true,
            Err(()) => return true,
            Ok(Some(_)) | Ok(None) => {}
        }
    }

    let value_lower = value.to_lowercase();
    if SENSITIVE_VALUE_MARKERS
        .iter()
        .any(|marker| value_lower.contains(marker))
        || standalone_basic_credential_bears_secret(value)
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

fn redact_evidence_item(item: &mut EvidenceItem) {
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
    // For every redacted item (whether just flagged above or pre-marked by the
    // lifecycle), overwrite the raw value with the safe form so persistence
    // and digests never carry the sensitive raw value.
    if item.redacted {
        let safe_value = item
            .redacted_value
            .clone()
            .unwrap_or_else(|| REDACTED_EVIDENCE_VALUE.into());
        item.value = safe_value.clone();
        item.redacted_value = Some(safe_value);
    }
}

/// Redact the evidence and metadata attached to request stages before a stage
/// collection crosses an in-memory or durable persistence boundary.
pub fn redact_request_stages(stages: &mut [Stage]) {
    for stage in stages {
        for item in &mut stage.evidence {
            redact_evidence_item(item);
        }
        for (key, value) in &mut stage.metadata {
            *value = redact_sensitive_text(key, value);
        }
    }
}

pub fn redact_evidence(pack: &mut EvidencePack) -> Result<(), String> {
    for item in pack.items.iter_mut() {
        redact_evidence_item(item);
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
            if object_is_sensitive_header_entry(entries, remaining_nodes) {
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
            if array_is_sensitive_header_entry(values, remaining_nodes) {
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
    fn test_should_redact_standalone_basic_credentials_without_basic_prose() {
        for value in [
            "Basic dXNlcjpwYXNz",
            "bAsIc\tdTpwdw==",
            "stage=authorize (Basic dXNlcjpwYXNz); denied",
            "[retry] BASIC\r\ndXNlcjpwYXNz, upstream rejected the request",
        ] {
            assert!(
                should_redact("reason", value),
                "standalone Basic credential must be redacted: {value}"
            );
            assert_eq!(
                redact_sensitive_text("reason", value),
                REDACTED_EVIDENCE_VALUE
            );
        }

        for value in [
            "Basic",
            "Basic   ",
            "Basic delegated",
            "Basic bW9kZQ==",
            "Basic dXNlcjpwYXN",
            "Basic dXNlcjpwYXNz===",
            "Basic dTpwdx==",
            "Basic dXNlcjpwYXNz.",
            "NotBasic dXNlcjpwYXNz",
        ] {
            assert!(
                !should_redact("reason", value),
                "non-credential Basic metadata must remain available: {value}"
            );
            assert_eq!(redact_sensitive_text("reason", value), value);
        }

        let oversized_token = "A".repeat(MAX_STANDALONE_BASIC_CREDENTIAL_BYTES + 1);
        assert!(
            should_redact("reason", &format!("Basic {oversized_token}")),
            "an oversized token68-shaped credential must fail closed at the bound"
        );
    }

    #[test]
    fn test_should_redact_structured_authorization_credentials() {
        for value in [
            r#"{"Authorization":"Basic SYNTH-BASIC-MARKER"}"#,
            r#"{"authorization":"Bearer SYNTH-BEARER-MARKER"}"#,
            r#"{"Authorization":["Basic SYNTH-BASIC-ARRAY-MARKER"]}"#,
            r#"{"headers":{"authorization":["Digest public-metadata","Basic SYNTH-NESTED-BASIC-ARRAY-MARKER"]}}"#,
            r#"{"Authorization":["Basic SYNTH-DUPLICATE-DIRECT-MARKER"],"Authorization":["Basic"]}"#,
            r#"{"name":"Authorization","value":"Basic SYNTH-DUPLICATE-NAMED-MARKER","value":"Basic"}"#,
            r#""{\"Authorization\":[\"Basic SYNTH-NESTED-DUPLICATE-MARKER\"],\"Authorization\":[\"Basic\"]}""#,
            r#"nested={\"Authorization\":[\"Basic SYNTH-EMBEDDED-ARRAY-MARKER\"]}"#,
            r#"nested={\"Authorization\":[\"Digest public-metadata\",\"Basic SYNTH-EMBEDDED-LATER-ARRAY-MARKER\"],\"Authorization\":[\"Basic\"]}"#,
            r#"nested={\"Authorization\":[\"Digest ] public\",\"Basic SYNTH-QUOTED-DELIMITER-MARKER\"]}"#,
            r#"nested={\"Authorization\":[\"Bas\u0069c SYNTH-UNICODE-ARRAY-MARKER\"]}"#,
            r#"nested={\"\\u0041uthorization\":\"Bas\\u0069c SYNTH-ESCAPED-KEY-SCALAR-MARKER\"}"#,
            r#"nested={\"Authoriz\\u0061tion\":[\"Basic SYNTH-PARTIAL-ESCAPED-KEY-MARKER\"]}"#,
            r#"context {\u0022\u0041uthorization\u0022\u003a\u0022Bas\u0069c SYNTH-UNICODE-STRUCTURE-MARKER\u0022}"#,
            r#"context \u007b\u0022\u0041uthorization\u0022\u003a\u0022Bas\u0069c SYNTH-FULLY-ESCAPED-STRUCTURE-MARKER\u0022\u007d"#,
            r#"context \u0041uthorization: Bas\u0069c SYNTH-UNICODE-PLAINTEXT-MARKER"#,
            r#"note \uZZZZ; \u0041uthorization: Bas\u0069c SYNTH-LATE-UNICODE-PLAINTEXT-MARKER"#,
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
            r#"{"authorization":["Basic","Bearer","Digest public-metadata"]}"#,
            r#"{"authorization_url":"Basic SYNTH-NONSECRET-METADATA"}"#,
            r#"{"x-authorization-mode":["Basic delegated"]}"#,
            r#"nested={\"Authorization\":[\"Basic\",\"Bearer\",\"Digest public-metadata\"]}"#,
            r#"nested={\"Authorization\":[\"Digest ] public\",\"Bas\u0069c\"]}"#,
            r#"nested={\"\\u0041uthorization\":\"Basic\"} status="ok""#,
            r#"nested={\"message\":\"ordinary\"} status="ok""#,
            r#"context {\u0022\u0041uthorization\u0022\u003a\u0022Basic\u0022}"#,
            r#"context \u007b\u0022message\u0022\u003a\u0022ordinary\u0022\u007d"#,
            r#"context \uD83D\uDE80 deployment complete"#,
            r#"path=C:\users\operator\artifact.json"#,
            r#"literal=\uZZZZ ordinary metadata"#,
            r#"literal=\uD83D ordinary metadata"#,
            r#"literal=\\u0041uthorization: Basic public metadata"#,
            r#"nested={\"x-authorization-mode\":[\"Basic delegated\"]}"#,
            r#"{"left":{"value":"ordinary"},"right":{"value":"ordinary"}}"#,
            r#"[{"name":"X-Mode","value":"ordinary"},{"name":"X-Mode","value":"ordinary"}]"#,
            r#"{"message":"authorization policy metadata only"}"#,
        ] {
            assert!(
                !should_redact("execution_log", value),
                "non-credential metadata must not be over-redacted: {value}"
            );
        }
    }

    #[test]
    fn test_malformed_structured_evidence_fails_closed_without_redacting_prose() {
        for value in [
            r#"{"Authorization":["Basic SYNTH-MALFORMED-WHOLE""#,
            r#"nested={\"Authorization\":[\"Basic SYNTH-MALFORMED-EMBEDDED\""#,
            r#"nested={\"\\u0043ookie\":\"SYNTH-MALFORMED-COOKIE"#,
        ] {
            assert!(
                should_redact("execution_log", value),
                "malformed structured-looking evidence must fail closed: {value}"
            );
        }

        assert!(
            !should_redact("execution_log", "deployment {complete} successfully"),
            "ordinary brace-delimited prose must not be treated as JSON"
        );
        assert!(
            !should_redact("execution_log", "[INFO] deployment completed"),
            "ordinary bracket-prefixed log levels must not be treated as JSON"
        );
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
            (
                "provider_output",
                r#"nested={\"\\u0043ookie\":\"__Host-ryuki_session=SYNTH-ESCAPED-COOKIE-KEY\"}"#,
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
            ("reason", "JSESSIONID=SYNTH-BARE-JAVA-SESSION"),
            ("reason", "PHPSESSID=SYNTH-BARE-PHP-SESSION"),
            ("reason", "ASP.NET_SessionId=SYNTH-BARE-DOTNET-SESSION"),
            ("reason", "connect.sid=SYNTH-BARE-EXPRESS-SESSION"),
            ("reason", "session_id=SYNTH-BARE-GENERIC-SESSION"),
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
            (
                "configuration",
                r#"nested={\"\\u0043ookiePolicy\":\"ordinary metadata\"}"#,
            ),
            ("summary", "session policy enabled"),
            ("summary", "sessionidletimeout=30"),
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
    fn test_request_stage_redaction_canonicalizes_evidence_and_metadata_before_storage() {
        let raw_marker = "SYNTH-STAGE-RAW-SESSION-CANARY";
        let replacement_marker = "SYNTH-STAGE-REPLACEMENT-CANARY";
        let metadata_marker = "SYNTH-STAGE-METADATA-SESSION-CANARY";
        let mut stages = vec![Stage {
            name: "approve".into(),
            status: StageStatus::Failed,
            started_at: None,
            completed_at: None,
            evidence: vec![EvidenceItem {
                key: "approval-decision".into(),
                value: format!("JSESSIONID={raw_marker}"),
                redacted_value: Some(format!("session_id={replacement_marker}")),
                redacted: false,
                evidence_type: EvidenceType::ApprovalDecision,
            }],
            metadata: HashMap::from([
                ("reason".into(), format!("connect.sid={metadata_marker}")),
                ("decision".into(), "rejected".into()),
            ]),
        }];

        redact_request_stages(&mut stages);

        let serialized = serde_json::to_string(&stages).unwrap();
        for marker in [raw_marker, replacement_marker, metadata_marker] {
            assert!(!serialized.contains(marker));
        }
        assert_eq!(stages[0].evidence[0].value, REDACTED_EVIDENCE_VALUE);
        assert_eq!(
            stages[0].evidence[0].redacted_value.as_deref(),
            Some(REDACTED_EVIDENCE_VALUE)
        );
        assert_eq!(
            stages[0].metadata.get("reason").map(String::as_str),
            Some(REDACTED_EVIDENCE_VALUE)
        );
        assert_eq!(
            stages[0].metadata.get("decision").map(String::as_str),
            Some("rejected")
        );
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
    fn test_structured_json_redactor_treats_secret_id_as_credential_material() {
        let detail = serde_json::json!({
            "secret_id": "sec-reference-123",
            "secret_id_hint": "sec-reference-123",
            "secret_value": "ordinary-looking-but-keyed-secret",
            "resource_id": "sec-reference-123"
        });

        let redacted = redact_json_evidence_value(&detail);
        assert_eq!(redacted["secret_id"], REDACTED_EVIDENCE_VALUE);
        assert_eq!(redacted["secret_id_hint"], REDACTED_EVIDENCE_VALUE);
        assert_eq!(redacted["secret_value"], REDACTED_EVIDENCE_VALUE);
        assert_eq!(redacted["resource_id"], "sec-reference-123");

        let credential = serde_json::json!({
            "resource_id": "Basic YXVkaXQtdXNlcjpwYXNzd29yZA=="
        });
        assert_eq!(
            redact_json_evidence_value(&credential)["resource_id"],
            REDACTED_EVIDENCE_VALUE,
            "a neutral reference key must never bypass value-based credential detection"
        );
    }

    #[test]
    fn test_structured_json_redactor_handles_named_and_tuple_authorization_entries() {
        let named_marker = "SYNTH-NAMED-BASIC-CANARY";
        let tuple_marker = "SYNTH-TUPLE-BASIC-CANARY";
        let values_marker = "SYNTH-VALUES-BASIC-CANARY";
        let detail = serde_json::json!({
            "request": {
                "headers": [
                    {
                        "name": "Authorization",
                        "value": format!("Basic {named_marker}")
                    },
                    [
                        "authorization",
                        format!("Basic {tuple_marker}")
                    ],
                    {
                        "header_name": "AUTHORIZATION",
                        "header_values": [format!("Basic {values_marker}")]
                    }
                ]
            },
            "controls": [
                {"name": "Authorization", "value": "Basic"},
                ["Authorization", "Bearer"],
                {"name": "Authorization", "value": "Digest public-metadata"},
                {"name": "X-Authentication-Mode", "value": "Basic delegated"}
            ],
            "note": "ordinary audit context"
        });

        assert!(structured_value_bears_secret(&detail));
        assert!(
            should_redact("provider_output", &serde_json::to_string(&detail).unwrap()),
            "serialized structured evidence must use the same header-pair detector"
        );
        assert!(
            !structured_value_bears_secret(&detail["controls"]),
            "scheme-only and non-Authorization metadata must remain non-secret"
        );
        assert!(
            !should_redact(
                "provider_output",
                &serde_json::to_string(&detail["controls"]).unwrap()
            ),
            "serialized safe controls must not be over-redacted"
        );

        let redacted = redact_json_evidence_value(&detail);
        let serialized = serde_json::to_string(&redacted).unwrap();
        for marker in [named_marker, tuple_marker, values_marker] {
            assert!(
                !serialized.contains(marker),
                "structured Basic credential marker must not survive: {marker}"
            );
        }
        assert_eq!(redacted["request"]["headers"][0], REDACTED_EVIDENCE_VALUE);
        assert_eq!(redacted["request"]["headers"][1], REDACTED_EVIDENCE_VALUE);
        assert_eq!(redacted["request"]["headers"][2], REDACTED_EVIDENCE_VALUE);
        assert_eq!(redacted["controls"][0]["value"], "Basic");
        assert_eq!(redacted["controls"][1][1], "Bearer");
        assert_eq!(redacted["controls"][2]["value"], "Digest public-metadata");
        assert_eq!(redacted["controls"][3]["value"], "Basic delegated");
        assert_eq!(redacted["note"], "ordinary audit context");
    }

    #[test]
    fn test_structured_authorization_values_fail_closed_at_node_budget() {
        let oversized_values =
            vec![serde_json::Value::String("Basic".to_string()); MAX_STRUCTURED_SECRET_NODES + 1];
        let detail = serde_json::json!({
            "name": "Authorization",
            "values": oversized_values
        });

        assert!(
            structured_value_bears_secret(&detail),
            "an oversized named Authorization value list must fail closed"
        );
        assert_eq!(
            redact_json_evidence_value(&detail),
            REDACTED_EVIDENCE_VALUE,
            "the redactor must stop at the same bounded traversal limit"
        );
    }

    #[test]
    fn test_encoded_structured_value_fails_closed_at_depth_budget() {
        let mut credential = serde_json::Value::String(
            r#"{"Authorization":["Basic SYNTH-DEPTH-BUDGET-MARKER"]}"#.to_string(),
        );
        let mut safe_text = serde_json::Value::String("ordinary audit context".to_string());
        for _ in 0..MAX_NESTED_JSON_SECRET_DEPTH {
            credential = serde_json::json!({"nested": credential});
            safe_text = serde_json::json!({"nested": safe_text});
        }

        assert!(
            structured_value_bears_secret(&credential),
            "structured-looking content at the depth limit must fail closed"
        );
        assert!(
            !structured_value_bears_secret(&safe_text),
            "ordinary text at the depth limit must remain available"
        );
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
