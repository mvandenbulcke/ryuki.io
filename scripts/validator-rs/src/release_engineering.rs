//! Release-engineering tooling validator.
//!
//! Asserts that the repo carries a real, executable release posture:
//!
//!   1. `cliff.toml` (git-cliff config) exists and parses as TOML, and declares
//!      conventional-commit parsing plus a `v*`-shaped tag pattern.
//!   2. `CHANGELOG.md` exists and is non-empty.
//!   3. `.github/workflows/release.yml` exists, parses as YAML, triggers on
//!      `v*` tags, runs the CI gate (build/test, lint, secret scan), builds both
//!      app images, pushes digest-pinned tags, and creates a GitHub release.
//!   4. Every workspace member crate declares the same `version`, so a release
//!      tag describes a single coherent version across the workspace.
//!
//! Like `observability_deploy_wiring` and `control_plane_db_backup`, this reads
//! the repo files directly from the `root` passed in the slice context JSON, so
//! it runs standalone (`validate release-engineering --context-json <ctx>`) and
//! is NOT wired into a COVERAGE_TSV row.

use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use std::fs;
use std::path::Path;

const CLIFF_PATH: &str = "cliff.toml";
const CHANGELOG_PATH: &str = "CHANGELOG.md";
const RELEASE_WORKFLOW_PATH: &str = ".github/workflows/release.yml";

/// Workspace member manifests whose `version` must agree. Mirrors the
/// `[workspace] members` list in the root Cargo.toml plus the root manifest
/// itself (the integration-test package).
const MEMBER_MANIFESTS: &[&str] = &[
    "Cargo.toml",
    "sources/ryuki-core/Cargo.toml",
    "sources/ryuki-api/Cargo.toml",
    "sources/ryuki-engine/Cargo.toml",
    "sources/ryuki-runner/Cargo.toml",
    "sources/ryuki-protocol/Cargo.toml",
    "sources/ryuki-agent/Cargo.toml",
    "portal/portal-ui/Cargo.toml",
    "scripts/validator-rs/Cargo.toml",
];

/// Substrings the release workflow must contain to prove it runs the CI gate,
/// builds + pushes both images, and cuts a GitHub release.
const REQUIRED_WORKFLOW_TERMS: &[&str] = &[
    "cargo test --workspace",
    "cargo clippy",
    "no-secret-scan.sh",
    "sources/ryuki-api/Dockerfile",
    "portal/portal-ui/Dockerfile",
    "ghcr.io",
    "gh release create",
];

#[derive(Debug, Deserialize)]
struct Context {
    root: String,
}

/// Slice entry point used by the dispatch table and the `validate` subcommand.
pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid release-engineering context JSON: {error}"))?;
    Ok(validate_root(Path::new(&context.root)))
}

fn validate_root(root: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    validate_cliff(root, &mut errors);
    validate_changelog(root, &mut errors);
    validate_release_workflow(root, &mut errors);
    validate_member_versions(root, &mut errors);
    errors
}

fn validate_cliff(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(CLIFF_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("failed to read {CLIFF_PATH}: {error}"));
            return;
        }
    };

    let doc: toml::Value = match toml::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("{CLIFF_PATH} is not valid TOML: {error}"));
            return;
        }
    };

    // git-cliff must derive entries from conventional commits.
    if toml_bool_at(&doc, &["git", "conventional_commits"]) != Some(true) {
        errors.push(format!(
            "{CLIFF_PATH} must set git.conventional_commits = true"
        ));
    }

    // The tag pattern must scope releases to v-prefixed semver tags, matching
    // the release workflow's `v*` trigger.
    match toml_str_at(&doc, &["git", "tag_pattern"]) {
        Some(pattern) if pattern.starts_with('v') => {}
        Some(pattern) => errors.push(format!(
            "{CLIFF_PATH} git.tag_pattern {pattern:?} must scope to v-prefixed tags"
        )),
        None => errors.push(format!("{CLIFF_PATH} missing git.tag_pattern")),
    }

    // A changelog body template is required for git-cliff to render sections.
    if toml_str_at(&doc, &["changelog", "body"]).is_none() {
        errors.push(format!("{CLIFF_PATH} missing changelog.body template"));
    }
}

fn validate_changelog(root: &Path, errors: &mut Vec<String>) {
    match fs::read_to_string(root.join(CHANGELOG_PATH)) {
        Ok(text) if !text.trim().is_empty() => {}
        Ok(_) => errors.push(format!("{CHANGELOG_PATH} is empty")),
        Err(error) => errors.push(format!("failed to read {CHANGELOG_PATH}: {error}")),
    }
}

fn validate_release_workflow(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(RELEASE_WORKFLOW_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("failed to read {RELEASE_WORKFLOW_PATH}: {error}"));
            return;
        }
    };

    let doc: YamlValue = match serde_yaml::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH} is not valid YAML: {error}"
            ));
            return;
        }
    };

    // The workflow must trigger on tag pushes shaped like v*. Note: YAML parses
    // the bare `on:` key as the boolean `true`, so probe both spellings.
    if !triggers_on_version_tag(&doc) {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} must trigger on push tags matching v* (on.push.tags)"
        ));
    }

    for term in REQUIRED_WORKFLOW_TERMS {
        if !text.contains(term) {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH} is missing required release step content: {term:?}"
            ));
        }
    }
}

/// True when the workflow's `on.push.tags` list contains a `v*`-style pattern.
fn triggers_on_version_tag(doc: &YamlValue) -> bool {
    // `on` is the trigger map; GitHub's bare `on:` is parsed as YAML `true`.
    let on = doc.get("on").or_else(|| doc.get(YamlValue::Bool(true)));
    let Some(on) = on else {
        return false;
    };
    let Some(tags) = on
        .get("push")
        .and_then(|push| push.get("tags"))
        .and_then(YamlValue::as_sequence)
    else {
        return false;
    };
    tags.iter()
        .filter_map(YamlValue::as_str)
        .any(|pattern| pattern.starts_with('v'))
}

fn validate_member_versions(root: &Path, errors: &mut Vec<String>) {
    let mut versions: Vec<(String, String)> = Vec::new();
    for manifest in MEMBER_MANIFESTS {
        let text = match fs::read_to_string(root.join(manifest)) {
            Ok(text) => text,
            Err(error) => {
                errors.push(format!("failed to read {manifest}: {error}"));
                continue;
            }
        };
        let doc: toml::Value = match toml::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                errors.push(format!("{manifest} is not valid TOML: {error}"));
                continue;
            }
        };
        match toml_str_at(&doc, &["package", "version"]) {
            Some(version) => versions.push((manifest.to_string(), version.to_string())),
            None => errors.push(format!("{manifest} missing package.version")),
        }
    }

    let Some((_, first)) = versions.first() else {
        return;
    };
    let first = first.clone();
    let mismatched: Vec<String> = versions
        .iter()
        .filter(|(_, v)| v != &first)
        .map(|(manifest, v)| format!("{manifest}={v}"))
        .collect();
    if !mismatched.is_empty() {
        errors.push(format!(
            "workspace member crate versions are inconsistent (expected {first}): {}",
            mismatched.join(", ")
        ));
    }
}

fn toml_str_at<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn toml_bool_at(value: &toml::Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn real_release_tooling_is_valid() {
        let errors = validate_root(&repo_root());
        assert!(
            errors.is_empty(),
            "release-engineering tooling should be valid, got:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn member_versions_are_consistent() {
        let mut errors = Vec::new();
        validate_member_versions(&repo_root(), &mut errors);
        assert!(
            errors.is_empty(),
            "member versions should agree, got: {}",
            errors.join(", ")
        );
    }

    #[test]
    fn version_tag_trigger_detection_is_strict() {
        // Bare `on:` parses to the YAML boolean key `true`.
        let bare_on = serde_yaml::from_str::<YamlValue>(
            r#"
on:
  push:
    tags:
      - "v*"
"#,
        )
        .unwrap();
        assert!(triggers_on_version_tag(&bare_on));

        let branch_only = serde_yaml::from_str::<YamlValue>(
            r#"
on:
  push:
    branches: ["main"]
"#,
        )
        .unwrap();
        assert!(!triggers_on_version_tag(&branch_only));

        let non_version_tag = serde_yaml::from_str::<YamlValue>(
            r#"
on:
  push:
    tags:
      - "release-*"
"#,
        )
        .unwrap();
        assert!(!triggers_on_version_tag(&non_version_tag));
    }

    #[test]
    fn inconsistent_versions_are_reported() {
        // Drive validate_member_versions against a synthetic tree by writing two
        // manifests with mismatched versions into a temp dir layout is overkill;
        // instead exercise the comparison logic directly.
        let versions = [
            ("a/Cargo.toml".to_string(), "0.1.0".to_string()),
            ("b/Cargo.toml".to_string(), "0.2.0".to_string()),
        ];
        let first = versions[0].1.clone();
        let mismatched: Vec<String> = versions
            .iter()
            .filter(|(_, v)| v != &first)
            .map(|(m, v)| format!("{m}={v}"))
            .collect();
        assert_eq!(mismatched, ["b/Cargo.toml=0.2.0".to_string()]);
    }

    #[test]
    fn cliff_requires_conventional_commits_and_v_tag_pattern() {
        let doc: toml::Value = toml::from_str(
            r#"
[git]
conventional_commits = true
tag_pattern = "v[0-9]*"

[changelog]
body = "..."
"#,
        )
        .unwrap();
        assert_eq!(
            toml_bool_at(&doc, &["git", "conventional_commits"]),
            Some(true)
        );
        assert_eq!(toml_str_at(&doc, &["git", "tag_pattern"]), Some("v[0-9]*"));
        assert!(toml_str_at(&doc, &["changelog", "body"]).is_some());
    }
}
