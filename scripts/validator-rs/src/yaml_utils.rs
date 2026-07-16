use std::collections::BTreeSet;

/// Returns the set of route paths registered through axum `.route("...", ...)`
/// calls in the Rust API sources, ignoring registrations inside `//` or `/* */`
/// comments. This is the Rust-reality replacement for the per-slice C# program
/// parsers (`app.MapGet("/path", ...)`) that the validator carried over from the
/// deleted `api/Ryuki.Platform.Api/Program.cs`.
pub fn rust_route_registrations(source: &str) -> BTreeSet<String> {
    let source = strip_rust_comments(source);
    source
        .split(".route(")
        .skip(1)
        .filter_map(|candidate| {
            let rest = candidate.trim_start();
            let route = rest.strip_prefix('"')?;
            let end = route.find('"')?;
            Some(route[..end].to_string())
        })
        .collect()
}

/// True when `endpoint` is mounted as an axum route in the Rust API source.
pub fn rust_route_present(source: &str, endpoint: &str) -> bool {
    rust_route_registrations(source).contains(endpoint)
}

/// Strips `//` line comments and `/* */` block comments while preserving string
/// literals, so commented-out `.route(...)` decoys are not counted as mounted
/// routes.
fn strip_rust_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            out.push('"');
            index += 1;
            while index < bytes.len() {
                let current = bytes[index];
                out.push(current as char);
                index += 1;
                if current == b'\\' && index < bytes.len() {
                    out.push(bytes[index] as char);
                    index += 1;
                } else if current == b'"' {
                    break;
                }
            }
            continue;
        }
        if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index += 2;
            continue;
        }
        out.push(byte as char);
        index += 1;
    }
    out
}

pub fn validate_yaml_duplicate_keys_text(text: &str, path: &str, errors: &mut Vec<String>) {
    let mut stack: Vec<(usize, BTreeSet<String>)> = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        if is_yaml_document_marker(line) {
            stack.clear();
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if let Some(item) = trimmed.strip_prefix("- ") {
            let item = item.trim_start();
            let Some(key) = yaml_key(item) else {
                continue;
            };
            let scope_indent = indent + 2;
            stack.push((scope_indent, BTreeSet::new()));
            if let Some((_, seen)) = stack.last_mut() {
                if !seen.insert(key.to_string()) {
                    errors.push(format!(
                        "{path}:{} has duplicate YAML key {key}",
                        line_index + 1
                    ));
                }
            }
            continue;
        }
        let Some(key) = yaml_key(trimmed) else {
            continue;
        };
        while stack.last().is_some_and(|(level, _)| *level > indent) {
            stack.pop();
        }
        if stack.last().is_none_or(|(level, _)| *level < indent) {
            stack.push((indent, BTreeSet::new()));
        }
        if let Some((_, seen)) = stack.last_mut() {
            if !seen.insert(key.to_string()) {
                errors.push(format!(
                    "{path}:{} has duplicate YAML key {key}",
                    line_index + 1
                ));
            }
        }
    }
}

fn is_yaml_document_marker(line: &str) -> bool {
    ["---", "..."].into_iter().any(|marker| {
        line.strip_prefix(marker)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
    })
}

fn yaml_key(trimmed_line: &str) -> Option<&str> {
    let (key, rest) = trimmed_line.split_once(':')?;
    if key.is_empty()
        || key
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
    {
        return None;
    }
    if rest.starts_with('/') {
        return None;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::validate_yaml_duplicate_keys_text;

    #[test]
    fn duplicate_keys_are_scoped_to_one_yaml_document() {
        let text = "apiVersion: v1\nkind: ConfigMap\n---\napiVersion: v1\nkind: Secret\n";
        let mut errors = Vec::new();
        validate_yaml_duplicate_keys_text(text, "multi.yaml", &mut errors);
        assert!(
            errors.is_empty(),
            "separate documents may reuse keys: {errors:?}"
        );
    }

    #[test]
    fn duplicate_keys_within_one_yaml_document_are_rejected() {
        let text = "apiVersion: v1\nkind: ConfigMap\nkind: Secret\n";
        let mut errors = Vec::new();
        validate_yaml_duplicate_keys_text(text, "duplicate.yaml", &mut errors);
        assert_eq!(errors, vec!["duplicate.yaml:3 has duplicate YAML key kind"]);
    }

    #[test]
    fn explicit_document_end_resets_duplicate_key_scope() {
        let text = "kind: ConfigMap\n... # first document\n--- # second document\nkind: Secret\n";
        let mut errors = Vec::new();
        validate_yaml_duplicate_keys_text(text, "explicit.yaml", &mut errors);
        assert!(errors.is_empty());
    }

    #[test]
    fn nested_key_scopes_reset_between_yaml_documents() {
        let text = "spec:\n  name: first\n---\nspec:\n  name: second\n";
        let mut errors = Vec::new();
        validate_yaml_duplicate_keys_text(text, "nested.yaml", &mut errors);
        assert!(
            errors.is_empty(),
            "all document-local scopes reset: {errors:?}"
        );
    }

    #[test]
    fn indented_block_scalar_marker_does_not_reset_document_scope() {
        let text = "kind: ConfigMap\ndata:\n  payload: |-\n    ---\nkind: Secret\n";
        let mut errors = Vec::new();
        validate_yaml_duplicate_keys_text(text, "scalar.yaml", &mut errors);
        assert_eq!(errors, vec!["scalar.yaml:5 has duplicate YAML key kind"]);
    }
}
