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
//! escaping before writing them. The scrub set therefore includes those
//! deterministic representations as well as the literal secret. Matches are
//! found against the original output and overlapping ranges are merged before
//! replacement, so the result is independent of secret ordering.

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
        while let Some(relative_start) = output[search_from..].find(variant) {
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

fn secret_variants(secret_values: &[&[u8]]) -> Vec<String> {
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
        variants.push(upper_percent);
        variants.push(lower_percent);
        variants.push(upper_form_percent);
        variants.push(lower_form_percent);

        let Ok(secret_str) = std::str::from_utf8(secret) else {
            continue;
        };
        variants.push(secret_str.to_string());

        if let Ok(quoted) = serde_json::to_string(secret_str) {
            if let Some(inner) = quoted
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
            {
                variants.push(inner.to_string());
            }
        }

        let shell_single = secret_str.replace('\'', "'\\''");
        variants.push(shell_single);
        variants.push(shell_backslash_escape(secret_str));
        variants.push(shell_mixed_escape(secret_str));
    }

    variants.retain(|variant| !variant.is_empty());
    variants
        .sort_unstable_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    variants.dedup();
    variants
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
