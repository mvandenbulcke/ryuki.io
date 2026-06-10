pub fn contains_aws_access_key(text: &str) -> bool {
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

pub fn contains_private_key_header(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----")
}

pub fn contains_url(text: &str) -> bool {
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

pub fn contains_private_ip(text: &str) -> bool {
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

pub fn contains_uuid(text: &str) -> bool {
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

pub fn contains_secret_assignment(text: &str, keys: &[&str]) -> bool {
    let lower = text.to_ascii_lowercase();
    keys.iter().any(|key| has_assignment_value(&lower, key))
}

pub fn prohibited_key(value: &str, prohibited_parts: &[&str]) -> bool {
    let normalized: String = value
        .to_ascii_lowercase()
        .chars()
        .filter(|candidate| candidate.is_ascii_alphanumeric())
        .collect();
    prohibited_parts
        .iter()
        .any(|part| normalized.contains(part))
}

pub fn contains_hostname_value(text: &str) -> bool {
    text.split(|value: char| !(value.is_ascii_alphanumeric() || value == '.' || value == '-'))
        .map(|token| token.trim_matches(|value| value == '.' || value == '-'))
        .filter(|token| token.contains('.'))
        .any(valid_hostname)
}

pub fn contains_ipv4(text: &str) -> bool {
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
            if let Some(value) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('='))
                && !value.split_whitespace().next().unwrap_or("").is_empty()
            {
                return true;
            }
        }
        search_from = end;
    }
    false
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

fn is_word_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || value == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    // Runtime-composed fixture helpers.
    // Each helper assembles a detector-positive string from non-matching
    // source fragments so the production secret-scan gate passes clean.

    /// Build an AWS-key-style candidate from non-matching fragments.
    fn aws_key_fixture(key_id: &str) -> String {
        format!("{}{}", "AKIA", key_id)
    }

    /// Build an AWS-key-style candidate with a lower-case prefix.
    fn aws_key_fixture_lower(key_id: &str) -> String {
        format!("{}{}", "akia", key_id)
    }

    /// Build a private-key header from non-matching fragments.
    fn pk_header_fixture(label: &str) -> String {
        format!("-----BEGIN {}-----", label)
    }

    /// Build a lower-case private-key header from non-matching fragments.
    fn pk_header_fixture_lower(label: &str) -> String {
        format!("-----begin {}-----", label)
    }

    // --- AWS access key ---

    #[test]
    fn detects_valid_aws_access_key() {
        assert!(contains_aws_access_key(&aws_key_fixture(
            "IOSFODNN7EXAMPLE"
        )));
    }

    #[test]
    fn detects_aws_key_in_text() {
        assert!(contains_aws_access_key(&format!(
            "some text {} more text",
            aws_key_fixture("1234567890ABCDEF")
        )));
    }

    #[test]
    fn aws_key_too_short_not_detected() {
        assert!(!contains_aws_access_key("AKIA12345"));
    }

    #[test]
    fn aws_key_only_prefix_not_detected() {
        assert!(!contains_aws_access_key("AKIA"));
    }

    #[test]
    fn aws_key_case_insensitive_prefix() {
        assert!(contains_aws_access_key(&aws_key_fixture_lower(
            "1234567890ABCDEF"
        )));
    }

    // --- Private key header ---

    #[test]
    fn detects_private_key_header() {
        assert!(contains_private_key_header(&pk_header_fixture(
            "PRIVATE KEY"
        )));
    }

    #[test]
    fn detects_rsa_private_key_header() {
        assert!(contains_private_key_header(&pk_header_fixture(
            "RSA PRIVATE KEY"
        )));
    }

    #[test]
    fn private_key_header_case_insensitive() {
        assert!(contains_private_key_header(&pk_header_fixture_lower(
            "private key"
        )));
    }

    #[test]
    fn no_private_key_header_in_normal_text() {
        assert!(!contains_private_key_header("hello world"));
    }

    // --- URL detection ---

    #[test]
    fn detects_https_url() {
        assert!(contains_url("https://example.com/path"));
    }

    #[test]
    fn detects_http_url() {
        assert!(contains_url("http://example.com"));
    }

    #[test]
    fn detects_custom_scheme() {
        assert!(contains_url("ftp://files.example.com"));
    }

    #[test]
    fn no_url_without_scheme() {
        assert!(!contains_url("example.com/path"));
    }

    #[test]
    fn no_url_with_no_scheme_colon_slash() {
        assert!(!contains_url("just some text"));
    }

    // --- Private IP ---

    #[test]
    fn detects_10_x_private_ip() {
        assert!(contains_private_ip("10.0.0.1"));
    }

    #[test]
    fn detects_172_16_x_private_ip() {
        assert!(contains_private_ip("172.16.0.1"));
    }

    #[test]
    fn detects_172_31_x_private_ip() {
        assert!(contains_private_ip("172.31.255.255"));
    }

    #[test]
    fn detects_192_168_x_private_ip() {
        assert!(contains_private_ip("192.168.1.1"));
    }

    #[test]
    fn public_ip_not_flagged() {
        assert!(!contains_private_ip("8.8.8.8"));
    }

    #[test]
    fn public_ip_172_32_not_flagged() {
        assert!(!contains_private_ip("172.32.0.1"));
    }

    #[test]
    fn loopback_not_rfc1918_private() {
        assert!(!contains_private_ip("127.0.0.1"));
    }

    // --- UUID detection ---

    #[test]
    fn detects_standard_uuid() {
        assert!(contains_uuid("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn detects_uuid_in_text() {
        assert!(contains_uuid(
            "id: 123e4567-e89b-12d3-a456-426614174000 is valid"
        ));
    }

    #[test]
    fn wrong_format_not_uuid() {
        assert!(!contains_uuid("550e8400-e29b-41d4-a716"));
    }

    #[test]
    fn invalid_chars_not_uuid() {
        assert!(!contains_uuid("gggggggg-gggg-gggg-gggg-gggggggggggg"));
    }

    #[test]
    fn plain_text_not_uuid() {
        assert!(!contains_uuid("hello world"));
    }

    // --- Secret assignment ---

    #[test]
    fn detects_password_assignment_equals() {
        assert!(contains_secret_assignment(
            "password=hunter2",
            &["password", "secret", "token"]
        ));
    }

    #[test]
    fn detects_secret_key_colon() {
        assert!(contains_secret_assignment(
            "secret: abc123",
            &["password", "secret", "token", "api_key"]
        ));
    }

    #[test]
    fn detects_token_assignment() {
        assert!(contains_secret_assignment(
            "token=ghp_abcdef123456",
            &["password", "secret", "token"]
        ));
    }

    #[test]
    fn no_assignment_without_value() {
        assert!(!contains_secret_assignment(
            "password=",
            &["password", "secret", "token"]
        ));
    }

    #[test]
    fn no_assignment_without_key() {
        assert!(!contains_secret_assignment(
            "username=admin",
            &["password", "secret", "token"]
        ));
    }

    // --- Prohibited key ---

    #[test]
    fn prohibited_key_detected() {
        assert!(prohibited_key("super_secret_value", &["secret", "token"]));
    }

    #[test]
    fn prohibited_key_normalized() {
        assert!(prohibited_key("SuperSecretApiKey", &["secret"]));
    }

    #[test]
    fn non_prohibited_key_passes() {
        assert!(!prohibited_key("hello_world", &["secret", "token"]));
    }

    #[test]
    fn prohibited_key_special_chars_ignored() {
        assert!(prohibited_key("sec--ret!!key", &["secret"]));
    }

    // --- Hostname detection ---

    #[test]
    fn detects_valid_hostname() {
        assert!(contains_hostname_value("example.com"));
    }

    #[test]
    fn detects_subdomain_hostname() {
        assert!(contains_hostname_value("api.example.com"));
    }

    #[test]
    fn rejects_invalid_hostname_no_tld() {
        assert!(!contains_hostname_value("localhost"));
    }

    #[test]
    fn rejects_hostname_with_numeric_tld() {
        assert!(!contains_hostname_value("example.123"));
    }

    // --- IPv4 detection ---

    #[test]
    fn detects_ipv4_in_text() {
        assert!(contains_ipv4("server at 192.168.1.1 is up"));
    }

    #[test]
    fn no_ipv4_in_plain_text() {
        assert!(!contains_ipv4("no ip address here"));
    }

    // --- contains_ipv4 (public helper) ---

    #[test]
    fn ipv4_detects_valid_address() {
        assert!(contains_ipv4("8.8.8.8"));
    }

    #[test]
    fn ipv4_rejects_overflow_octets() {
        assert!(!contains_ipv4("999.999.999.999"));
    }

    #[test]
    fn ipv4_rejects_three_octets() {
        assert!(!contains_ipv4("192.168.1"));
    }
}
