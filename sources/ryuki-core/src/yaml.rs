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
            if let Some((_, seen)) = stack.last_mut()
                && !seen.insert(key.to_string())
            {
                errors.push(format!(
                    "{path}:{} has duplicate YAML key {key}",
                    line_index + 1
                ));
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
        if let Some((_, seen)) = stack.last_mut()
            && !seen.insert(key.to_string())
        {
            errors.push(format!(
                "{path}:{} has duplicate YAML key {key}",
                line_index + 1
            ));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_errors(text: &str) -> Vec<String> {
        let mut errors = Vec::new();
        validate_yaml_duplicate_keys_text(text, "test.yaml", &mut errors);
        errors
    }

    #[test]
    fn no_duplicates_passes() {
        let yaml = "key1: value1\nkey2: value2\nkey3: value3\n";
        let errors = collect_errors(yaml);
        assert!(errors.is_empty(), "expected no errors: {errors:?}");
    }

    #[test]
    fn duplicate_top_level_key_detected() {
        let yaml = "key1: value1\nkey1: value2\n";
        let errors = collect_errors(yaml);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("key1"));
    }

    #[test]
    fn duplicate_nested_key_detected() {
        let yaml = "outer:\n  inner: a\n  inner: b\n";
        let errors = collect_errors(yaml);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("inner"));
    }

    #[test]
    fn duplicate_different_levels_is_ok() {
        let yaml = "key1: top\nnested:\n  key1: nested\n";
        let errors = collect_errors(yaml);
        assert!(errors.is_empty(), "expected no errors: {errors:?}");
    }

    #[test]
    fn empty_yaml_passes() {
        let yaml = "";
        let errors = collect_errors(yaml);
        assert!(errors.is_empty());
    }

    #[test]
    fn only_comments_passes() {
        let yaml = "# this is a comment\n# another comment\n";
        let errors = collect_errors(yaml);
        assert!(errors.is_empty());
    }

    #[test]
    fn list_items_no_duplicate() {
        let yaml = "items:\n  - name: a\n  - name: b\n  - name: c\n";
        let errors = collect_errors(yaml);
        assert!(errors.is_empty(), "expected no errors: {errors:?}");
    }

    #[test]
    fn duplicate_different_indentation_levels() {
        let yaml = "a:\n  b:\n    c: value1\n    c: value2\n  d: value\n";
        let errors = collect_errors(yaml);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("c"));
    }

    #[test]
    fn complex_nested_duplicates_at_depths() {
        let yaml = "level1:\n  level2:\n    level3:\n      dup: first\n      dup: second\n      unique: ok\n  level2b:\n    dup: another\n";
        let errors = collect_errors(yaml);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("dup"));
    }

    #[test]
    fn multiple_duplicates_across_nesting() {
        let yaml = "a: 1\na: 2\nb:\n  c: 3\n  c: 4\n";
        let errors = collect_errors(yaml);
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn ignores_url_like_values() {
        let yaml = "url: https://example.com\nhost: foo://bar\n";
        let errors = collect_errors(yaml);
        assert!(errors.is_empty(), "expected no errors: {errors:?}");
    }

    #[test]
    fn duplicate_list_key_independent_scopes() {
        let yaml = "items:\n  - name: a\n  - name: a\n";
        let errors = collect_errors(yaml);
        assert!(
            errors.is_empty(),
            "list entries are independent scopes: {errors:?}"
        );
    }
}
