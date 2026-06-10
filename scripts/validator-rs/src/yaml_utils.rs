use std::collections::BTreeSet;

pub fn validate_yaml_duplicate_keys_text(text: &str, path: &str, errors: &mut Vec<String>) {
    let mut stack: Vec<(usize, BTreeSet<String>)> = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
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
