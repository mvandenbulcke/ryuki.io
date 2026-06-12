//! Docker image build-context validation.
//!
//! The root Cargo.toml declares a `[workspace]` with five members plus a root
//! package whose `[[test]]` targets live under `tests/`. Any Dockerfile that
//! runs cargo against this workspace must therefore COPY the workspace
//! manifests, every member path, and `tests/` into the build context — a
//! partial COPY set fails at `cargo metadata` with "failed to load manifest
//! for workspace member". This slice asserts each Dockerfile's COPY set covers
//! that graph, and that the app images keep their static-dry-run execution
//! mode baked in.

use serde::Deserialize;
use std::fs;
use std::path::Path;

const API_EXECUTION_MODE_ENV: &str = "RYUKI_API_EXECUTION_MODE=static-dry-run";
const PORTAL_EXECUTION_MODE_ENV: &str = "RYUKI_PORTAL_EXECUTION_MODE=static-dry-run";

/// `sqlx::migrate!("../../migrations")` in sources/ryuki-api/src/database.rs
/// embeds the migrations directory at compile time.
const API_COMPILE_TIME_DIRS: &[&str] = &["migrations"];

#[derive(Debug, Deserialize)]
struct Context {
    #[serde(default)]
    workspace_manifest: String,
    #[serde(default)]
    api_dockerfile: String,
    #[serde(default)]
    portal_dockerfile: String,
    #[serde(default)]
    validator_dockerfile: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid docker-image context JSON: {error}"))?;

    let mut errors = Vec::new();

    let members = parse_workspace_members(&context.workspace_manifest);
    if context.workspace_manifest.trim().is_empty() {
        errors.push("root Cargo.toml is missing or empty; cannot derive workspace members".into());
    } else if members.is_empty() {
        errors.push("no [workspace] members parsed from root Cargo.toml".into());
    }

    errors.extend(validate_api_dockerfile(&context.api_dockerfile, &members));
    errors.extend(validate_portal_dockerfile(
        &context.portal_dockerfile,
        &members,
    ));
    // The validator image is optional (design allows rewrite-or-delete); when
    // present it builds the workspace too, so it needs the same COPY coverage.
    if !context.validator_dockerfile.trim().is_empty() {
        errors.extend(validate_workspace_coverage(
            &context.validator_dockerfile,
            "validator Dockerfile",
            &members,
        ));
    }

    Ok(errors)
}

fn validate_api_dockerfile(content: &str, members: &[String]) -> Vec<String> {
    let label = "platform-api Dockerfile";
    let mut errors = validate_workspace_coverage(content, label, members);
    if content.trim().is_empty() {
        return errors;
    }
    let sources = copy_sources(content);
    for dir in API_COMPILE_TIME_DIRS {
        if !covers(&sources, dir) {
            errors.push(format!(
                "{label}: COPY set does not cover {dir}/ (embedded at compile time via sqlx::migrate!)"
            ));
        }
    }
    if !content.contains(API_EXECUTION_MODE_ENV) {
        errors.push(format!(
            "{label}: must bake {API_EXECUTION_MODE_ENV} so a fresh image cannot execute live changes"
        ));
    }
    errors
}

fn validate_portal_dockerfile(content: &str, members: &[String]) -> Vec<String> {
    let label = "portal-ui Dockerfile";
    let mut errors = validate_workspace_coverage(content, label, members);
    if content.trim().is_empty() {
        return errors;
    }
    if !content.contains(PORTAL_EXECUTION_MODE_ENV) {
        errors.push(format!(
            "{label}: must bake {PORTAL_EXECUTION_MODE_ENV} so a fresh image cannot execute live changes"
        ));
    }
    errors
}

/// Assert the Dockerfile's COPY set covers the workspace manifests, every
/// `[workspace]` member path, and `tests/` (the root package's `[[test]]`
/// targets make it load-bearing for `cargo metadata`).
fn validate_workspace_coverage(content: &str, label: &str, members: &[String]) -> Vec<String> {
    let mut errors = Vec::new();
    if content.trim().is_empty() {
        errors.push(format!("{label}: file is missing or empty"));
        return errors;
    }

    let sources = copy_sources(content);
    for manifest in ["Cargo.toml", "Cargo.lock"] {
        if !covers(&sources, manifest) {
            errors.push(format!(
                "{label}: COPY set must include workspace {manifest}"
            ));
        }
    }
    for member in members {
        if !covers(&sources, member) {
            errors.push(format!(
                "{label}: COPY set does not cover workspace member {member}; cargo metadata will fail"
            ));
        }
    }
    if !covers(&sources, "tests") {
        errors.push(format!(
            "{label}: COPY set does not cover tests/ (root [[test]] targets make it load-bearing for cargo metadata)"
        ));
    }
    errors
}

/// Extract the `members` array of the `[workspace]` table from raw Cargo.toml
/// text. Self-contained line scan — the validator has no TOML dependency.
fn parse_workspace_members(manifest: &str) -> Vec<String> {
    let mut members = Vec::new();
    let mut in_workspace = false;
    let mut in_members = false;

    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_workspace = line == "[workspace]";
            in_members = false;
            continue;
        }
        if in_workspace && line.starts_with("members") {
            in_members = true;
        }
        if in_members {
            // Quoted strings sit at odd indices when splitting on '"'.
            for part in line.split('"').skip(1).step_by(2) {
                members.push(part.to_string());
            }
            if line.contains(']') {
                in_members = false;
            }
        }
    }

    members
}

/// Collect normalized build-context COPY sources from a Dockerfile.
/// Stage-to-stage copies (`COPY --from=...`) move build artifacts, not
/// context files, so they are excluded.
fn copy_sources(dockerfile: &str) -> Vec<String> {
    let mut sources = Vec::new();
    for raw in dockerfile.lines() {
        let line = raw.trim();
        if !line.starts_with("COPY") {
            continue;
        }
        let mut args: Vec<&str> = line.split_whitespace().skip(1).collect();
        if args.iter().any(|arg| arg.starts_with("--from=")) {
            continue;
        }
        args.retain(|arg| !arg.starts_with("--"));
        if args.len() < 2 {
            continue;
        }
        // Last argument is the destination; everything before it is a source.
        for src in &args[..args.len() - 1] {
            let normalized = src.trim_start_matches("./").trim_end_matches('/');
            sources.push(if normalized.is_empty() {
                ".".to_string()
            } else {
                normalized.to_string()
            });
        }
    }
    sources
}

/// A path is covered when the whole context is copied (`COPY . .`), the path
/// itself is copied, or an ancestor directory of the path is copied.
fn covers(sources: &[String], path: &str) -> bool {
    let path = path.trim_end_matches('/');
    sources
        .iter()
        .any(|source| source == "." || source == path || path.starts_with(&format!("{source}/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKSPACE_MANIFEST: &str = r#"
[workspace]
resolver = "3"
members = [
    "sources/ryuki-core",
    "sources/ryuki-api",
    "sources/ryuki-engine",
    "portal/portal-ui",
    "scripts/validator-rs",
]

[package]
name = "ryuki-integration-tests"
"#;

    fn members() -> Vec<String> {
        parse_workspace_members(WORKSPACE_MANIFEST)
    }

    fn full_copy_set() -> &'static str {
        concat!(
            "COPY Cargo.toml Cargo.lock ./\n",
            "COPY sources/ sources/\n",
            "COPY portal/ portal/\n",
            "COPY scripts/validator-rs/ scripts/validator-rs/\n",
            "COPY tests/ tests/\n",
        )
    }

    // ── workspace member parsing ──────────────────────────────────────────

    #[test]
    fn parses_workspace_members_from_manifest() {
        assert_eq!(
            members(),
            vec![
                "sources/ryuki-core",
                "sources/ryuki-api",
                "sources/ryuki-engine",
                "portal/portal-ui",
                "scripts/validator-rs",
            ]
        );
    }

    #[test]
    fn parses_single_line_members_array() {
        let manifest = "[workspace]\nmembers = [\"a/b\", \"c/d\"]\n";
        assert_eq!(parse_workspace_members(manifest), vec!["a/b", "c/d"]);
    }

    #[test]
    fn ignores_members_outside_workspace_table() {
        let manifest = "[package]\nmembers = [\"decoy\"]\n[workspace]\nmembers = [\"real\"]\n";
        assert_eq!(parse_workspace_members(manifest), vec!["real"]);
    }

    // ── COPY coverage ─────────────────────────────────────────────────────

    #[test]
    fn full_workspace_copy_set_covers_all_members() {
        let dockerfile = format!(
            "FROM rust:1.88-bookworm AS build\nWORKDIR /app\n{}RUN cargo build --release -p ryuki-api\n",
            full_copy_set()
        );
        let errors = validate_workspace_coverage(&dockerfile, "test", &members());
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn copy_dot_covers_everything() {
        let dockerfile = "FROM rust:1.88-bookworm AS build\nCOPY . .\nRUN cargo build\n";
        let errors = validate_workspace_coverage(dockerfile, "test", &members());
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn missing_member_paths_are_flagged() {
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm AS build\n",
            "COPY Cargo.toml Cargo.lock ./\n",
            "COPY sources/ sources/\n",
            "RUN cargo build --release -p ryuki-api\n",
        );
        let errors = validate_workspace_coverage(dockerfile, "test", &members());
        assert!(
            errors.iter().any(|e| e.contains("portal/portal-ui")),
            "expected portal member coverage error, got: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("scripts/validator-rs")),
            "expected validator member coverage error, got: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("tests/")),
            "expected tests/ coverage error, got: {errors:?}"
        );
    }

    #[test]
    fn missing_workspace_manifests_are_flagged() {
        let dockerfile = "FROM rust:1.88-bookworm AS build\nCOPY sources/ sources/\nCOPY portal/ portal/\nCOPY scripts/ scripts/\nCOPY tests/ tests/\nRUN cargo build\n";
        let errors = validate_workspace_coverage(dockerfile, "test", &members());
        assert!(
            errors.iter().any(|e| e.contains("Cargo.toml")),
            "expected Cargo.toml error, got: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("Cargo.lock")),
            "expected Cargo.lock error, got: {errors:?}"
        );
    }

    #[test]
    fn stage_copies_do_not_count_as_context_coverage() {
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm AS build\n",
            "COPY --from=planner /app/recipe.json recipe.json\n",
            "RUN cargo chef cook --release\n",
        );
        let errors = validate_workspace_coverage(dockerfile, "test", &members());
        assert!(
            !errors.is_empty(),
            "expected coverage errors when only stage copies exist"
        );
    }

    #[test]
    fn parent_directory_copy_covers_nested_member() {
        let sources = vec!["scripts".to_string()];
        assert!(covers(&sources, "scripts/validator-rs"));
        assert!(!covers(&sources, "scriptsx/other"));
    }

    #[test]
    fn empty_dockerfile_is_flagged() {
        let errors = validate_workspace_coverage("", "test", &members());
        assert!(
            errors.iter().any(|e| e.contains("missing or empty")),
            "expected missing-file error, got: {errors:?}"
        );
    }

    // ── app-image specifics ───────────────────────────────────────────────

    #[test]
    fn api_dockerfile_requires_migrations_and_dry_run_env() {
        let dockerfile = format!(
            "FROM rust:1.88-bookworm AS build\n{}RUN cargo build --release -p ryuki-api\n",
            full_copy_set()
        );
        let errors = validate_api_dockerfile(&dockerfile, &members());
        assert!(
            errors.iter().any(|e| e.contains("migrations")),
            "expected migrations coverage error, got: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains(API_EXECUTION_MODE_ENV)),
            "expected execution-mode env error, got: {errors:?}"
        );
    }

    #[test]
    fn complete_api_dockerfile_passes() {
        let dockerfile = format!(
            "FROM rust:1.88-bookworm AS build\n{}COPY migrations/ migrations/\nRUN cargo build --release -p ryuki-api\nFROM debian:bookworm-slim AS runtime\nENV RYUKI_API_EXECUTION_MODE=static-dry-run\nCOPY --from=build /app/target/release/ryuki-api /app/ryuki-api\n",
            full_copy_set()
        );
        let errors = validate_api_dockerfile(&dockerfile, &members());
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn portal_dockerfile_requires_dry_run_env() {
        let dockerfile = format!(
            "FROM rust:1.88-bookworm AS build\n{}RUN cargo leptos build --release -p ryuki-portal-ui\n",
            full_copy_set()
        );
        let errors = validate_portal_dockerfile(&dockerfile, &members());
        assert!(
            errors.iter().any(|e| e.contains(PORTAL_EXECUTION_MODE_ENV)),
            "expected execution-mode env error, got: {errors:?}"
        );
    }

    #[test]
    fn complete_portal_dockerfile_passes() {
        let dockerfile = format!(
            "FROM rust:1.88-bookworm AS build\n{}RUN cargo leptos build --release -p ryuki-portal-ui\nFROM debian:bookworm-slim AS runtime\nENV RYUKI_PORTAL_EXECUTION_MODE=static-dry-run\nCOPY --from=build /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui\nCOPY --from=build /app/target/site /app/site\n",
            full_copy_set()
        );
        let errors = validate_portal_dockerfile(&dockerfile, &members());
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }
}
