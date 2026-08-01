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

use zeroize::{Zeroize, Zeroizing};

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
        variants.push(percent_encode(secret, true, false));
        variants.push(percent_encode(secret, false, false));
        variants.push(percent_encode(secret, true, true));
        variants.push(percent_encode(secret, false, true));

        for escape_html in [true, false] {
            if let Some(go_json) = go_json_escape_variant(secret, escape_html) {
                variants.push(go_json);
            }
        }

        let secret_str = match std::str::from_utf8(secret) {
            Ok(secret_str) => secret_str,
            Err(_) => {
                // `std::process::Output` is converted through
                // `String::from_utf8_lossy` before this boundary. Register the
                // same single, bounded representation so malformed provider
                // bytes cannot survive capture as literal U+FFFD characters.
                variants.push(lossy_utf8_variant(secret));
                continue;
            }
        };
        variants.push(zeroizing_copy(secret_str));
        variants.push(serde_json_escape_variant(secret_str));
        variants.push(shell_single_escape(secret_str));
        variants.push(shell_backslash_escape(secret_str));
        variants.push(shell_mixed_escape(secret_str));
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

fn zeroizing_copy(value: &str) -> Zeroizing<String> {
    let mut copied = Zeroizing::new(String::with_capacity(value.len()));
    let allocation = copied.as_ptr();
    copied.push_str(value);
    debug_assert_eq!(copied.len(), value.len());
    debug_assert_eq!(copied.as_ptr(), allocation);
    copied
}

fn percent_encode(value: &[u8], uppercase: bool, space_as_plus: bool) -> Zeroizing<String> {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let hex = if uppercase { UPPER } else { LOWER };
    let encoded_len = value.iter().try_fold(0usize, |length, byte| {
        let byte_len = if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~')
            || (space_as_plus && *byte == b' ')
        {
            1
        } else {
            3
        };
        length.checked_add(byte_len)
    });
    let encoded_len = encoded_len.expect("secret representation length must fit in address space");
    let mut encoded = Zeroizing::new(String::with_capacity(encoded_len));
    let allocation = encoded.as_ptr();
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
    debug_assert_eq!(encoded.len(), encoded_len);
    debug_assert_eq!(encoded.as_ptr(), allocation);
    encoded
}

fn lossy_utf8_variant(value: &[u8]) -> Zeroizing<String> {
    let encoded_len = lossy_utf8_len(value);
    let mut encoded = Zeroizing::new(String::with_capacity(encoded_len));
    let allocation = encoded.as_ptr();
    let mut remaining = value;

    loop {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                encoded.push_str(valid);
                break;
            }
            Err(error) => {
                let valid_up_to = error.valid_up_to();
                encoded.push_str(
                    std::str::from_utf8(&remaining[..valid_up_to])
                        .expect("Utf8Error valid prefix must be valid UTF-8"),
                );
                encoded.push('\u{fffd}');
                let Some(invalid_len) = error.error_len() else {
                    break;
                };
                remaining = &remaining[valid_up_to + invalid_len..];
            }
        }
    }

    debug_assert_eq!(encoded.len(), encoded_len);
    debug_assert_eq!(encoded.as_ptr(), allocation);
    encoded
}

fn lossy_utf8_len(value: &[u8]) -> usize {
    let mut encoded_len = 0usize;
    let mut remaining = value;
    loop {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                encoded_len = encoded_len
                    .checked_add(valid.len())
                    .expect("secret representation length must fit in address space");
                break;
            }
            Err(error) => {
                encoded_len = encoded_len
                    .checked_add(error.valid_up_to())
                    .and_then(|length| length.checked_add('\u{fffd}'.len_utf8()))
                    .expect("secret representation length must fit in address space");
                let Some(invalid_len) = error.error_len() else {
                    break;
                };
                remaining = &remaining[error.valid_up_to() + invalid_len..];
            }
        }
    }
    encoded_len
}

fn serde_json_escape_variant(value: &str) -> Zeroizing<String> {
    let encoded_len = value.chars().try_fold(0usize, |length, character| {
        length.checked_add(match character {
            '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => 2,
            character if character <= '\u{001f}' => 6,
            _ => character.len_utf8(),
        })
    });
    let encoded_len = encoded_len.expect("secret representation length must fit in address space");
    let mut escaped = Zeroizing::new(String::with_capacity(encoded_len));
    let allocation = escaped.as_ptr();
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{0008}' => escaped.push_str("\\b"),
            '\u{000c}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character <= '\u{001f}' => {
                append_ascii_control_escape(&mut escaped, character as u8);
            }
            _ => escaped.push(character),
        }
    }
    debug_assert_eq!(escaped.len(), encoded_len);
    debug_assert_eq!(escaped.as_ptr(), allocation);
    escaped
}

fn append_ascii_control_escape(escaped: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    escaped.push_str("\\u00");
    escaped.push(char::from(HEX[usize::from(byte >> 4)]));
    escaped.push(char::from(HEX[usize::from(byte & 0x0f)]));
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
fn go_json_escape_variant(value: &[u8], escape_html: bool) -> Option<Zeroizing<String>> {
    let (encoded_len, changed) = go_json_escape_len(value, escape_html);
    let mut escaped = Zeroizing::new(String::with_capacity(encoded_len));
    let allocation = escaped.as_ptr();
    let mut index = 0usize;
    while index < value.len() {
        let byte = value[index];
        if byte.is_ascii() {
            index += 1;
            append_go_json_character(&mut escaped, char::from(byte), escape_html);
            continue;
        }

        let remaining = &value[index..];
        let valid_prefix_len = match std::str::from_utf8(remaining) {
            Ok(valid) => {
                for character in valid.chars() {
                    append_go_json_character(&mut escaped, character, escape_html);
                }
                break;
            }
            Err(error) => error.valid_up_to(),
        };
        if valid_prefix_len > 0 {
            let valid = std::str::from_utf8(&remaining[..valid_prefix_len])
                .expect("Utf8Error::valid_up_to identifies a valid prefix");
            for character in valid.chars() {
                append_go_json_character(&mut escaped, character, escape_html);
            }
            index += valid_prefix_len;
            continue;
        }

        // Go's utf8.DecodeRuneInString reports size 1 for malformed input, so
        // encoding/json emits one replacement escape per invalid byte.
        escaped.push_str("\\ufffd");
        index += 1;
    }

    debug_assert_eq!(escaped.len(), encoded_len);
    debug_assert_eq!(escaped.as_ptr(), allocation);
    if changed {
        Some(escaped)
    } else {
        // This representation duplicates the literal variant. Wipe the
        // populated allocation explicitly instead of passing it through an
        // eager `then_some`, whose `None` branch would immediately drop it.
        escaped.zeroize();
        None
    }
}

fn go_json_escape_len(value: &[u8], escape_html: bool) -> (usize, bool) {
    let mut encoded_len = 0usize;
    let mut changed = false;
    let mut index = 0usize;
    while index < value.len() {
        let byte = value[index];
        if byte.is_ascii() {
            let (character_len, character_changed) =
                go_json_character_len(char::from(byte), escape_html);
            encoded_len = encoded_len
                .checked_add(character_len)
                .expect("secret representation length must fit in address space");
            changed |= character_changed;
            index += 1;
            continue;
        }

        let remaining = &value[index..];
        let valid_prefix_len = match std::str::from_utf8(remaining) {
            Ok(valid) => {
                for character in valid.chars() {
                    let (character_len, character_changed) =
                        go_json_character_len(character, escape_html);
                    encoded_len = encoded_len
                        .checked_add(character_len)
                        .expect("secret representation length must fit in address space");
                    changed |= character_changed;
                }
                break;
            }
            Err(error) => error.valid_up_to(),
        };
        if valid_prefix_len > 0 {
            let valid = std::str::from_utf8(&remaining[..valid_prefix_len])
                .expect("Utf8Error::valid_up_to identifies a valid prefix");
            for character in valid.chars() {
                let (character_len, character_changed) =
                    go_json_character_len(character, escape_html);
                encoded_len = encoded_len
                    .checked_add(character_len)
                    .expect("secret representation length must fit in address space");
                changed |= character_changed;
            }
            index += valid_prefix_len;
            continue;
        }

        encoded_len = encoded_len
            .checked_add("\\ufffd".len())
            .expect("secret representation length must fit in address space");
        changed = true;
        index += 1;
    }
    (encoded_len, changed)
}

fn go_json_character_len(character: char, escape_html: bool) -> (usize, bool) {
    match character {
        '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => (2, true),
        '<' | '>' | '&' if escape_html => (6, true),
        '\u{2028}' | '\u{2029}' => (6, true),
        character if character <= '\u{001f}' => (6, true),
        _ => (character.len_utf8(), false),
    }
}

fn append_go_json_character(escaped: &mut String, character: char, escape_html: bool) {
    match character {
        '"' => {
            escaped.push_str("\\\"");
        }
        '\\' => {
            escaped.push_str("\\\\");
        }
        '\u{0008}' => {
            escaped.push_str("\\b");
        }
        '\u{000c}' => {
            escaped.push_str("\\f");
        }
        '\n' => {
            escaped.push_str("\\n");
        }
        '\r' => {
            escaped.push_str("\\r");
        }
        '\t' => {
            escaped.push_str("\\t");
        }
        '<' if escape_html => {
            escaped.push_str("\\u003c");
        }
        '>' if escape_html => {
            escaped.push_str("\\u003e");
        }
        '&' if escape_html => {
            escaped.push_str("\\u0026");
        }
        '\u{2028}' => {
            escaped.push_str("\\u2028");
        }
        '\u{2029}' => {
            escaped.push_str("\\u2029");
        }
        character if character <= '\u{001f}' => {
            append_ascii_control_escape(escaped, character as u8);
        }
        _ => escaped.push(character),
    }
}

pub(crate) fn append_go_json_escape_variants(values: &mut Vec<Vec<u8>>, value: &[u8]) {
    for escape_html in [true, false] {
        if let Some(mut escaped) = go_json_escape_variant(value, escape_html) {
            values.push(std::mem::take(&mut *escaped).into_bytes());
        }
    }
}

fn shell_single_escape(value: &str) -> Zeroizing<String> {
    let encoded_len = value.chars().try_fold(value.len(), |length, character| {
        if character == '\'' {
            length.checked_add(3)
        } else {
            Some(length)
        }
    });
    let encoded_len = encoded_len.expect("secret representation length must fit in address space");
    let mut escaped = Zeroizing::new(String::with_capacity(encoded_len));
    let allocation = escaped.as_ptr();
    for character in value.chars() {
        if character == '\'' {
            escaped.push_str("'\\''");
        } else {
            escaped.push(character);
        }
    }
    debug_assert_eq!(escaped.len(), encoded_len);
    debug_assert_eq!(escaped.as_ptr(), allocation);
    escaped
}

fn shell_backslash_escape(value: &str) -> Zeroizing<String> {
    let encoded_len = value.chars().try_fold(0usize, |length, character| {
        length.checked_add(character.len_utf8()).and_then(|length| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '/') {
                Some(length)
            } else {
                length.checked_add(1)
            }
        })
    });
    let encoded_len = encoded_len.expect("secret representation length must fit in address space");
    let mut escaped = Zeroizing::new(String::with_capacity(encoded_len));
    let allocation = escaped.as_ptr();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '/') {
            escaped.push(character);
        } else {
            escaped.push('\\');
            escaped.push(character);
        }
    }
    debug_assert_eq!(escaped.len(), encoded_len);
    debug_assert_eq!(escaped.as_ptr(), allocation);
    escaped
}

fn shell_mixed_escape(value: &str) -> Zeroizing<String> {
    let encoded_len = value.chars().try_fold(0usize, |length, character| {
        let additional = match character {
            '\'' => 3,
            '$' | '`' | '"' | '\\' => 1,
            _ => 0,
        };
        length
            .checked_add(character.len_utf8())
            .and_then(|length| length.checked_add(additional))
    });
    let encoded_len = encoded_len.expect("secret representation length must fit in address space");
    let mut escaped = Zeroizing::new(String::with_capacity(encoded_len));
    let allocation = escaped.as_ptr();
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
    debug_assert_eq!(escaped.len(), encoded_len);
    debug_assert_eq!(escaped.as_ptr(), allocation);
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

/// Copy captured stdout/stderr into one exactly pre-sized zeroizing string and
/// clear the source buffers immediately.
///
/// `std::process::Output` owns ordinary `Vec<u8>` buffers. Runner output can
/// contain credentials before scrubbing, so callers must not leave those
/// allocations populated until ordinary drop. The source allocations and
/// lossy UTF-8 projections are placed under zeroizing ownership before the
/// destination is allocated. Its complete final capacity is reserved before
/// either stream is copied, so appending stderr cannot free a plaintext stdout
/// allocation during reallocation.
fn take_lossy_utf8(bytes: &mut Vec<u8>) -> Zeroizing<String> {
    let mut owned = Zeroizing::new(std::mem::take(bytes));
    match String::from_utf8(std::mem::take(&mut *owned)) {
        Ok(text) => Zeroizing::new(text),
        Err(error) => {
            let mut invalid = Zeroizing::new(error.into_bytes());
            // Each invalid input byte can expand to at most one three-byte
            // replacement character. Reserve that full bound before copying so
            // a valid plaintext prefix is never released by reallocation.
            let capacity = invalid
                .len()
                .checked_mul('\u{fffd}'.len_utf8())
                .expect("captured output length must fit in address space");
            let mut text = Zeroizing::new(String::with_capacity(capacity));
            let allocation = text.as_ptr();
            let mut remaining = invalid.as_slice();
            loop {
                match std::str::from_utf8(remaining) {
                    Ok(valid) => {
                        text.push_str(valid);
                        break;
                    }
                    Err(utf8_error) => {
                        let valid_up_to = utf8_error.valid_up_to();
                        text.push_str(
                            std::str::from_utf8(&remaining[..valid_up_to])
                                .expect("Utf8Error valid prefix must be valid UTF-8"),
                        );
                        text.push('\u{fffd}');
                        let Some(invalid_len) = utf8_error.error_len() else {
                            break;
                        };
                        remaining = &remaining[valid_up_to + invalid_len..];
                    }
                }
            }
            debug_assert_eq!(text.as_ptr(), allocation);
            invalid.zeroize();
            text
        }
    }
}

pub(crate) fn take_captured_output(
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
) -> Zeroizing<String> {
    let mut stdout_text = take_lossy_utf8(stdout);
    let mut stderr_text = take_lossy_utf8(stderr);

    let separator_len = usize::from(
        !stdout_text.is_empty() && !stdout_text.ends_with('\n') && !stderr_text.is_empty(),
    );
    let combined_len = stdout_text
        .len()
        .checked_add(separator_len)
        .and_then(|len| len.checked_add(stderr_text.len()))
        .expect("captured output length must fit in address space");
    let mut combined = Zeroizing::new(String::with_capacity(combined_len));
    let combined_allocation = combined.as_ptr();
    combined.push_str(&stdout_text);
    if !stderr_text.is_empty() {
        if separator_len != 0 {
            combined.push('\n');
        }
        combined.push_str(&stderr_text);
    }
    debug_assert_eq!(combined.len(), combined_len);
    debug_assert_eq!(combined.as_ptr(), combined_allocation);

    stdout_text.zeroize();
    stderr_text.zeroize();
    combined
}

/// Scrub a subprocess capture and clear its raw byte owners before returning
/// durable evidence.
pub(crate) fn scrub_captured_output(
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    secret_values: &[&[u8]],
    truncate: bool,
) -> String {
    let raw = take_captured_output(stdout, stderr);
    if truncate {
        scrub_output(&raw, secret_values)
    } else {
        scrub(&raw, secret_values)
    }
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
    fn variant_builders_match_percent_json_and_shell_wire_formats() {
        // Each builder also carries an internal pointer-stability assertion,
        // proving its checked precomputed capacity does not grow while the
        // plaintext representation is being written.
        assert_eq!(
            percent_encode(b"api key/+~", true, false).as_str(),
            "api%20key%2F%2B~"
        );
        assert_eq!(
            percent_encode(b"api key/+~", false, false).as_str(),
            "api%20key%2f%2b~"
        );
        assert_eq!(
            percent_encode(b"api key/+~", true, true).as_str(),
            "api+key%2F%2B~"
        );

        let json_value = "q\"\\\u{0000}\u{0008}\u{000c}\n\r\té";
        assert_eq!(
            serde_json_escape_variant(json_value).as_str(),
            r#"q\"\\\u0000\b\f\n\r\té"#
        );

        assert_eq!(shell_single_escape("a'b").as_str(), r"a'\''b");
        assert_eq!(shell_backslash_escape("a b$é/").as_str(), r"a\ b\$\é/");
        assert_eq!(
            shell_mixed_escape("a'b$`\"\\ é").as_str(),
            r#"a'\''b\$\`\"\\ é"#
        );
    }

    #[test]
    fn lossy_and_go_json_builders_match_invalid_and_both_html_modes() {
        let invalid = b"a\xf0(\x8c(z";
        assert_eq!(lossy_utf8_variant(invalid).as_str(), "a\u{fffd}(\u{fffd}(z");
        assert_eq!(
            go_json_escape_variant(invalid, true)
                .expect("invalid UTF-8 changes Go JSON output")
                .as_str(),
            r"a\ufffd(\ufffd(z"
        );

        let go_value = "p\"\\\n<>&\u{2028}\u{2029}";
        assert_eq!(
            go_json_escape_variant(go_value.as_bytes(), true)
                .expect("HTML-safe Go JSON changes output")
                .as_str(),
            r#"p\"\\\n\u003c\u003e\u0026\u2028\u2029"#
        );
        assert_eq!(
            go_json_escape_variant(go_value.as_bytes(), false)
                .expect("HTML-disabled Go JSON still changes output")
                .as_str(),
            r#"p\"\\\n<>&\u2028\u2029"#
        );

        assert!(go_json_escape_variant(b"unchanged-canary", true).is_none());
        assert!(go_json_escape_variant(b"unchanged-canary", false).is_none());
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
    fn scrub_captured_output_clears_raw_owners() {
        let secret = b"capture-secret-canary";
        let mut stdout = b"stdout capture-secret-canary".to_vec();
        let mut stderr = b"stderr capture-secret-canary".to_vec();
        let scrubbed = scrub_captured_output(&mut stdout, &mut stderr, &[secret.as_slice()], true);

        assert!(stdout.is_empty(), "raw stdout owner must be cleared");
        assert!(stderr.is_empty(), "raw stderr owner must be cleared");
        assert_eq!(scrubbed, "stdout [REDACTED]\nstderr [REDACTED]");
    }

    #[test]
    fn take_captured_output_preallocates_for_both_streams_and_preserves_lossy_text() {
        let mut stdout = Vec::from(b"short-stdout".as_slice());
        stdout.shrink_to_fit();
        let mut stderr = [b'X'; 4096].to_vec();
        stderr.extend_from_slice(b"-invalid-\xff");
        stderr.shrink_to_fit();

        let combined = take_captured_output(&mut stdout, &mut stderr);

        assert!(stdout.is_empty(), "raw stdout owner must be cleared");
        assert!(stderr.is_empty(), "raw stderr owner must be cleared");
        assert!(combined.starts_with("short-stdout\n"));
        assert!(combined.ends_with("-invalid-\u{fffd}"));
        assert_eq!(
            combined.len(),
            "short-stdout\n".len() + 4096 + "-invalid-\u{fffd}".len()
        );
    }

    #[test]
    fn lossy_capture_conversion_preallocates_for_invalid_byte_expansion() {
        let mut bytes = b"plaintext-prefix\xff\xfe\xfd".to_vec();
        let input_len = bytes.len();
        let text = take_lossy_utf8(&mut bytes);

        assert!(bytes.is_empty(), "raw capture owner must be cleared");
        assert_eq!(text.as_str(), "plaintext-prefix\u{fffd}\u{fffd}\u{fffd}");
        assert!(
            text.capacity() >= input_len * '\u{fffd}'.len_utf8(),
            "lossy conversion must reserve its no-growth expansion bound"
        );
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
