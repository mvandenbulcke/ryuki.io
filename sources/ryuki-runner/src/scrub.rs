//! Output scrubbing — replace known secret values in runner output.
//!
//! # Security
//! This is the runner's pre-scrub layer. `evidence_pipeline::redact_evidence`
//! provides pattern-based redaction as a second defense layer. Both are needed:
//! - Pattern redaction catches common key patterns (password, token, etc.) but
//!   cannot catch provider-specific values that TF/Ansible may echo verbatim.
//! - Value-based scrubbing (this module) replaces the actual resolved secret
//!   values with `[REDACTED]`, regardless of the surrounding context.
//!
//! # Representation coverage
//! Providers frequently render values through JSON/HCL, URL, or shell
//! escaping before writing them. Go providers also use `encoding/json`, whose
//! HTML-safe and HTML-disabled modes differ from serde_json and replace invalid
//! UTF-8 bytes deterministically. The scrub set therefore includes those
//! bounded representations as well as the literal secret. Typed composites
//! such as Basic authentication are registered explicitly by the caller; this
//! module never guesses pairs or recursively expands encodings. Matches are
//! found against the original output and overlapping ranges are merged before
//! replacement, so the result is independent of secret ordering.

use zeroize::Zeroizing;

/// Maximum log excerpt stored in `RunOutcome.log`. Outputs longer than this
/// are truncated with a suffix indicating the truncation.
pub const MAX_LOG_BYTES: usize = 32 * 1024; // 32 KiB

/// Scrub `secret_values` from `output` WITHOUT truncating.
///
/// Each secret value is replaced with `[REDACTED]`. Replacement is
/// case-sensitive and applies to every occurrence. Use this when the full
/// scrubbed text matters — notably the `terraform show -json` output whose
/// SHA-256 is the live-apply plan-integrity digest: truncating it before
/// digesting would let two plans that differ only past the truncation point
/// collide, silently defeating the "apply only the approved plan" gate.
///
/// # Arguments
/// * `output` — raw captured stdout/stderr from the runner binary.
/// * `secret_values` — slice of byte-string values to redact.
pub fn scrub(output: &str, secret_values: &[&[u8]]) -> String {
    let variants = secret_variants(secret_values);
    if variants.is_empty() {
        return output.to_string();
    }

    let mut ranges = Vec::<(usize, usize)>::new();
    for variant in &variants {
        if variant.is_empty() || variant.len() > output.len() {
            continue;
        }
        let mut search_from = 0usize;
        while let Some(relative_start) = output[search_from..].find(variant.as_str()) {
            let start = search_from + relative_start;
            ranges.push((start, start + variant.len()));
            // Advance by one Unicode scalar rather than by the whole match so
            // overlapping occurrences (for example `aaa` in `aaaa`) are seen.
            let advance = output[start..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            search_from = start + advance;
        }
    }
    if ranges.is_empty() {
        return output.to_string();
    }

    ranges.sort_unstable();
    let mut merged = Vec::<(usize, usize)>::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }

    let mut scrubbed = String::with_capacity(output.len());
    let mut cursor = 0usize;
    for (start, end) in merged {
        scrubbed.push_str(&output[cursor..start]);
        scrubbed.push_str("[REDACTED]");
        cursor = end;
    }
    scrubbed.push_str(&output[cursor..]);
    scrubbed
}

fn secret_variants(secret_values: &[&[u8]]) -> Vec<Zeroizing<String>> {
    let mut variants = Vec::new();
    for secret in secret_values
        .iter()
        .copied()
        .filter(|value| !value.is_empty())
    {
        let upper_percent = percent_encode(secret, true, false);
        let lower_percent = percent_encode(secret, false, false);
        let upper_form_percent = percent_encode(secret, true, true);
        let lower_form_percent = percent_encode(secret, false, true);
        variants.push(Zeroizing::new(upper_percent));
        variants.push(Zeroizing::new(lower_percent));
        variants.push(Zeroizing::new(upper_form_percent));
        variants.push(Zeroizing::new(lower_form_percent));

        for escape_html in [true, false] {
            if let Some(go_json) = go_json_escape_variant(secret, escape_html) {
                variants.push(Zeroizing::new(go_json));
            }
        }

        let secret_str = match std::str::from_utf8(secret) {
            Ok(secret_str) => secret_str,
            Err(_) => {
                // `std::process::Output` is converted through
                // `String::from_utf8_lossy` before this boundary. Register the
                // same single, bounded representation so malformed provider
                // bytes cannot survive capture as literal U+FFFD characters.
                variants.push(Zeroizing::new(String::from_utf8_lossy(secret).into_owned()));
                continue;
            }
        };
        variants.push(Zeroizing::new(secret_str.to_string()));

        if let Ok(quoted) = serde_json::to_string(secret_str).map(Zeroizing::new) {
            if let Some(inner) = quoted
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
            {
                variants.push(Zeroizing::new(inner.to_string()));
            }
        }

        let shell_single = secret_str.replace('\'', "'\\''");
        variants.push(Zeroizing::new(shell_single));
        variants.push(Zeroizing::new(shell_backslash_escape(secret_str)));
        variants.push(Zeroizing::new(shell_mixed_escape(secret_str)));
    }

    variants.retain(|variant| !variant.is_empty());
    variants.sort_unstable_by(|left, right| {
        right
            .len()
            .cmp(&left.len())
            .then_with(|| left.as_str().cmp(right.as_str()))
    });
    variants.dedup_by(|left, right| left.as_str() == right.as_str());
    variants
}

/// Return the two canonical wire values for one explicitly typed Basic-auth
/// credential: the raw `username:password` octets and standard padded Base64.
///
/// The caller must establish the username/password relationship from trusted
/// schema metadata. This helper intentionally accepts only one pair and emits
/// exactly two non-recursive variants, preventing Cartesian or recursive
/// secret expansion. Empty components retain Basic-auth's defined boundary
/// forms (`username:` or `:password`); two absent/empty components produce no
/// value.
pub(crate) fn basic_auth_canonical_variants(
    username: Option<&[u8]>,
    password: Option<&[u8]>, // secret-scan-allow: typed parameter, not a literal credential
) -> Option<[Vec<u8>; 2]> {
    let username = username.filter(|value| !value.is_empty());
    let password = password.filter(|value| !value.is_empty()); // secret-scan-allow: typed value reference
    if username.is_none() && password.is_none() {
        return None;
    }

    let username_len = username.map_or(0, <[u8]>::len);
    let password_len = password.map_or(0, <[u8]>::len);
    let mut combined = Vec::with_capacity(username_len + password_len + 1);
    if let Some(username) = username {
        combined.extend_from_slice(username);
    }
    combined.push(b':');
    if let Some(password) = password {
        combined.extend_from_slice(password);
    }
    let encoded = standard_base64(&combined);
    Some([combined, encoded])
}

fn percent_encode(value: &[u8], uppercase: bool, space_as_plus: bool) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let hex = if uppercase { UPPER } else { LOWER };
    let mut encoded = String::with_capacity(value.len());
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else if space_as_plus && *byte == b' ' {
            encoded.push('+');
        } else {
            encoded.push('%');
            encoded.push(char::from(hex[usize::from(*byte >> 4)]));
            encoded.push(char::from(hex[usize::from(*byte & 0x0f)]));
        }
    }
    encoded
}

pub(crate) fn standard_base64(value: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(ALPHABET[(first >> 2) as usize]);
        encoded.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize]);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize]);
        } else {
            encoded.push(b'=');
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[(third & 0x3f) as usize]);
        } else {
            encoded.push(b'=');
        }
    }
    encoded
}

/// Encode the inner string bytes exactly as Go's `encoding/json` does.
///
/// Go supports two bounded modes: the default HTML-safe mode and
/// `Encoder.SetEscapeHTML(false)`. Both modes still escape U+2028/U+2029 and
/// replace every invalid UTF-8 byte with `\ufffd`. Registering both closes the
/// mixed-representation case (`<` left literal while U+2028 is escaped)
/// without guessing encodings or recursively expanding variants.
fn go_json_escape_variant(value: &[u8], escape_html: bool) -> Option<String> {
    let mut escaped = String::with_capacity(value.len());
    let mut changed = false;
    let mut index = 0usize;
    while index < value.len() {
        let byte = value[index];
        if byte.is_ascii() {
            index += 1;
            append_go_json_character(&mut escaped, char::from(byte), escape_html, &mut changed);
            continue;
        }

        let remaining = &value[index..];
        let valid_prefix_len = match std::str::from_utf8(remaining) {
            Ok(valid) => {
                for character in valid.chars() {
                    append_go_json_character(&mut escaped, character, escape_html, &mut changed);
                }
                break;
            }
            Err(error) => error.valid_up_to(),
        };
        if valid_prefix_len > 0 {
            let valid = std::str::from_utf8(&remaining[..valid_prefix_len])
                .expect("Utf8Error::valid_up_to identifies a valid prefix");
            for character in valid.chars() {
                append_go_json_character(&mut escaped, character, escape_html, &mut changed);
            }
            index += valid_prefix_len;
            continue;
        }

        // Go's utf8.DecodeRuneInString reports size 1 for malformed input, so
        // encoding/json emits one replacement escape per invalid byte.
        escaped.push_str("\\ufffd");
        changed = true;
        index += 1;
    }
    changed.then_some(escaped)
}

fn append_go_json_character(
    escaped: &mut String,
    character: char,
    escape_html: bool,
    changed: &mut bool,
) {
    use std::fmt::Write as _;

    match character {
        '"' => {
            escaped.push_str("\\\"");
            *changed = true;
        }
        '\\' => {
            escaped.push_str("\\\\");
            *changed = true;
        }
        '\u{0008}' => {
            escaped.push_str("\\b");
            *changed = true;
        }
        '\u{000c}' => {
            escaped.push_str("\\f");
            *changed = true;
        }
        '\n' => {
            escaped.push_str("\\n");
            *changed = true;
        }
        '\r' => {
            escaped.push_str("\\r");
            *changed = true;
        }
        '\t' => {
            escaped.push_str("\\t");
            *changed = true;
        }
        '<' if escape_html => {
            escaped.push_str("\\u003c");
            *changed = true;
        }
        '>' if escape_html => {
            escaped.push_str("\\u003e");
            *changed = true;
        }
        '&' if escape_html => {
            escaped.push_str("\\u0026");
            *changed = true;
        }
        '\u{2028}' => {
            escaped.push_str("\\u2028");
            *changed = true;
        }
        '\u{2029}' => {
            escaped.push_str("\\u2029");
            *changed = true;
        }
        character if character <= '\u{001f}' => {
            write!(escaped, "\\u{:04x}", character as u32).expect("writing to String cannot fail");
            *changed = true;
        }
        _ => escaped.push(character),
    }
}

pub(crate) fn append_go_json_escape_variants(values: &mut Vec<Vec<u8>>, value: &[u8]) {
    for escape_html in [true, false] {
        if let Some(escaped) = go_json_escape_variant(value, escape_html) {
            values.push(escaped.into_bytes());
        }
    }
}

fn shell_backslash_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '/') {
            escaped.push(character);
        } else {
            escaped.push('\\');
            escaped.push(character);
        }
    }
    escaped
}

fn shell_mixed_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\'' => escaped.push_str("'\\''"),
            '$' | '`' | '"' | '\\' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Scrub `secret_values` from `output`, then truncate to `MAX_LOG_BYTES`.
///
/// This is the default for human-readable evidence logs (init/plan/apply
/// console output), which are diagnostic and not integrity-bound. For the
/// digest-bound `terraform show -json` output use [`scrub`] instead.
///
/// # Returns
/// The scrubbed and truncated output as a `String`.
pub fn scrub_output(output: &str, secret_values: &[&[u8]]) -> String {
    truncate_log(&scrub(output, secret_values))
}

/// Truncate `log` to `MAX_LOG_BYTES`, appending a note if truncation occurred.
pub fn truncate_log(log: &str) -> String {
    if log.len() <= MAX_LOG_BYTES {
        return log.to_string();
    }
    // Find a safe UTF-8 boundary at or before MAX_LOG_BYTES.
    let boundary = (0..=MAX_LOG_BYTES)
        .rev()
        .find(|&i| log.is_char_boundary(i))
        .unwrap_or(0);
    format!(
        "{}\n[... output truncated at {} bytes]",
        &log[..boundary],
        MAX_LOG_BYTES
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_replaces_secret_values_in_output() {
        // NOTE: the fake credential value contains no colon/equals so the
        // no-secret-scan regex (which looks for "password: <value>") does not
        // match. The test still exercises scrubbing of arbitrary byte sequences.
        let secret = b"xK9mQvP2-test-cred-value";
        let output = "Connecting to host...\ncredential xK9mQvP2-test-cred-value present\nDone.";
        let scrubbed = scrub_output(output, &[secret.as_slice()]);
        assert!(
            !scrubbed.contains("xK9mQvP2-test-cred-value"),
            "secret must be scrubbed"
        );
        assert!(
            scrubbed.contains("[REDACTED]"),
            "replacement marker must be present"
        );
        // Non-secret content must survive.
        assert!(scrubbed.contains("Connecting to host"));
        assert!(scrubbed.contains("Done."));
    }

    #[test]
    fn scrub_output_no_secrets_returns_unchanged() {
        let output = "Plan: 2 to add, 0 to change, 0 to destroy.";
        let scrubbed = scrub_output(output, &[]);
        assert_eq!(scrubbed, output);
    }

    #[test]
    fn scrub_multiple_secrets() {
        let s1 = b"token-abc-123";
        let s2 = b"key-xyz-456";
        let output = "export TOKEN=token-abc-123 KEY=key-xyz-456";
        let scrubbed = scrub_output(output, &[s1.as_slice(), s2.as_slice()]);
        assert!(!scrubbed.contains("token-abc-123"));
        assert!(!scrubbed.contains("key-xyz-456"));
        assert_eq!(scrubbed.matches("[REDACTED]").count(), 2);
    }

    #[test]
    fn scrub_empty_secret_is_skipped() {
        // An empty secret would replace every character — must be skipped.
        let output = "some output";
        let scrubbed = scrub_output(output, &[b""]);
        assert_eq!(scrubbed, output);
    }

    #[test]
    fn scrub_multiple_occurrences() {
        let secret = b"mysecret";
        let output = "mysecret appears here and also mysecret again";
        let scrubbed = scrub_output(output, &[secret.as_slice()]);
        assert!(!scrubbed.contains("mysecret"));
        assert_eq!(scrubbed.matches("[REDACTED]").count(), 2);
    }

    #[test]
    fn truncate_log_short_output_unchanged() {
        let log = "short output";
        assert_eq!(truncate_log(log), log);
    }

    #[test]
    fn truncate_log_long_output_is_truncated() {
        let log = "x".repeat(MAX_LOG_BYTES + 100);
        let truncated = truncate_log(&log);
        assert!(truncated.len() < log.len());
        assert!(truncated.contains("[... output truncated at"));
    }

    #[test]
    fn scrub_does_not_truncate_large_output() {
        // The digest-bound show-json path relies on `scrub` returning the FULL
        // text: a plan larger than MAX_LOG_BYTES must survive intact so its
        // digest covers the whole plan, not just the first 32 KiB.
        let big = "y".repeat(MAX_LOG_BYTES + 4096);
        let scrubbed = scrub(&big, &[]);
        assert_eq!(scrubbed.len(), big.len(), "scrub must not truncate");
        assert!(!scrubbed.contains("truncated"));
    }

    #[test]
    fn scrub_still_redacts_without_truncating() {
        let secret = b"tail-secret-value";
        let mut output = "z".repeat(MAX_LOG_BYTES);
        output.push_str(" tail-secret-value");
        let scrubbed = scrub(&output, &[secret.as_slice()]);
        assert!(!scrubbed.contains("tail-secret-value"));
        assert!(scrubbed.contains("[REDACTED]"));
        assert!(scrubbed.len() > MAX_LOG_BYTES, "no truncation applied");
    }

    #[test]
    fn scrub_redacts_json_url_and_shell_representations() {
        let json_secret = b"quote\"slash\\line";
        let url_secret = b"api key/+";
        let shell_secret = b"shell'value$part";
        let output = concat!(
            "json=quote\\\"slash\\\\line\n",
            "url=api%20key%2F%2B\n",
            "form=api+key%2F%2B\n",
            "lower-form=api+key%2f%2b\n",
            "shell=shell'\\''value\\$part\n"
        );
        let scrubbed = scrub(
            output,
            &[
                json_secret.as_slice(),
                url_secret.as_slice(),
                shell_secret.as_slice(),
            ],
        );
        assert!(!scrubbed.contains("quote\\\"slash\\\\line"));
        assert!(!scrubbed.contains("api%20key%2F%2B"));
        assert!(!scrubbed.contains("api+key%2F%2B"));
        assert!(!scrubbed.contains("api+key%2f%2b"));
        assert!(!scrubbed.contains("shell'\\''value\\$part"));
        assert_eq!(scrubbed.matches("[REDACTED]").count(), 5);
    }

    #[test]
    fn scrub_redacts_go_json_provider_wire_representation() {
        let secret = "provider\"\\\n<>&\u{2028}\u{2029}";
        let output = r#"diagnostic=provider\"\\\n\u003c\u003e\u0026\u2028\u2029 status=failed"#;
        let scrubbed = scrub(output, &[secret.as_bytes()]);
        assert_eq!(scrubbed, "diagnostic=[REDACTED] status=failed");
        assert!(!scrubbed.contains("\\u003c"));
    }

    #[test]
    fn scrub_redacts_go_json_no_html_mixed_representation() {
        let secret = "provider<\u{2028}canary";
        let output = r#"diagnostic=provider<\u2028canary status=failed"#;
        let scrubbed = scrub(output, &[secret.as_bytes()]);
        assert_eq!(scrubbed, "diagnostic=[REDACTED] status=failed");
        assert!(!scrubbed.contains("provider<\\u2028canary"));
    }

    #[test]
    fn scrub_redacts_go_json_invalid_utf8_replacement_representation() {
        let secret = b"provider-\xff-canary";
        let output = r#"diagnostic=provider-\ufffd-canary status=failed"#;
        let scrubbed = scrub(output, &[secret.as_slice()]);
        assert_eq!(scrubbed, "diagnostic=[REDACTED] status=failed");
        assert!(!scrubbed.contains("provider-\\ufffd-canary"));
    }

    #[test]
    fn scrub_redacts_capture_lossy_invalid_utf8_representation() {
        let secret = b"provider-\xff-canary";
        let output = "diagnostic=provider-\u{fffd}-canary status=failed";
        let scrubbed = scrub(output, &[secret.as_slice()]);
        assert_eq!(scrubbed, "diagnostic=[REDACTED] status=failed");
        assert!(!scrubbed.contains("provider-\u{fffd}-canary"));
    }

    #[test]
    fn scrub_redacts_explicit_typed_basic_auth_wire_values() {
        let [combined, encoded] =
            basic_auth_canonical_variants(Some(b"basic-user-canary"), Some(b"basic-pass-canary"))
                .expect("typed pair");
        assert_eq!(encoded, b"YmFzaWMtdXNlci1jYW5hcnk6YmFzaWMtcGFzcy1jYW5hcnk=");
        let output = format!(
            "raw={} encoded={}",
            String::from_utf8_lossy(&combined),
            String::from_utf8_lossy(&encoded)
        );
        let scrubbed = scrub(&output, &[combined.as_slice(), encoded.as_slice()]);
        assert_eq!(scrubbed, "raw=[REDACTED] encoded=[REDACTED]");
    }

    #[test]
    fn scrub_does_not_guess_basic_auth_pairs_or_decode_unregistered_output() {
        let output = "status=healthy opaque=YmFzaWMtdXNlci1jYW5hcnk6YmFzaWMtcGFzcy1jYW5hcnk=";
        let scrubbed = scrub(
            output,
            &[
                b"basic-user-canary".as_slice(),
                b"basic-pass-canary".as_slice(),
            ],
        );
        assert_eq!(
            scrubbed, output,
            "only an explicitly typed pair may register a composite"
        );
    }

    #[test]
    fn basic_auth_canonical_variants_have_bounded_boundary_forms() {
        assert!(basic_auth_canonical_variants(None, None).is_none());
        assert!(basic_auth_canonical_variants(Some(b""), Some(b"")).is_none());

        let [username_only, username_only_encoded] =
            basic_auth_canonical_variants(Some(b"basic-user"), None).expect("username boundary");
        assert_eq!(username_only, b"basic-user:");
        assert_eq!(username_only_encoded, b"YmFzaWMtdXNlcjo=");

        let [password_only, password_only_encoded] =
            basic_auth_canonical_variants(None, Some(b"basic-pass")).expect("password boundary");
        assert_eq!(password_only, b":basic-pass");
        assert_eq!(password_only_encoded, standard_base64(b":basic-pass"));
    }

    #[test]
    fn scrub_merges_overlapping_secrets_independent_of_input_order() {
        let short = b"overlap-canary";
        let long = b"overlap-canary-tail";
        let output = "before overlap-canary-tail after";
        let short_first = scrub(output, &[short.as_slice(), long.as_slice()]);
        let long_first = scrub(output, &[long.as_slice(), short.as_slice()]);
        assert_eq!(short_first, "before [REDACTED] after");
        assert_eq!(short_first, long_first);
        assert!(!short_first.contains("tail"));
    }

    #[test]
    fn scrub_redacts_overlapping_occurrences_of_the_same_secret() {
        let scrubbed = scrub("aaaa", &[b"aaa"]);
        assert_eq!(scrubbed, "[REDACTED]");
    }
}
