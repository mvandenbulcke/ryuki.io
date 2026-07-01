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
//! # Performance
//! Scrubbing is linear in the number of secrets × output length. For
//! Slice 1 (dry-run), output is bounded by `MAX_LOG_BYTES`. This is
//! acceptable for the expected output sizes; a future slice may optimize
//! if very large outputs are expected.

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
    let mut result = output.to_string();
    for secret in secret_values {
        if secret.is_empty() {
            continue;
        }
        // Only redact if the secret is valid UTF-8 (it always should be for
        // env-var and vault-resolved string credentials, but guard defensively).
        if let Ok(secret_str) = std::str::from_utf8(secret) {
            if !secret_str.is_empty() {
                result = result.replace(secret_str, "[REDACTED]");
            }
        }
    }
    result
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
}
