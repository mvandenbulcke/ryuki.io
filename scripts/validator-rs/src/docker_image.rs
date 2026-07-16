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
const CARGO_CHEF_VERSION: &str = "0.1.77";
const CARGO_LEPTOS_VERSION: &str = "0.3.7";

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
    validate_immutable_base_images(content, label, &mut errors);
    validate_cargo_install_pin(
        content,
        label,
        "cargo-chef",
        CARGO_CHEF_VERSION,
        &mut errors,
    );
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
    validate_immutable_base_images(content, label, &mut errors);
    validate_cargo_install_pin(
        content,
        label,
        "cargo-leptos",
        CARGO_LEPTOS_VERSION,
        &mut errors,
    );
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

fn validate_immutable_base_images(content: &str, label: &str, errors: &mut Vec<String>) {
    let mut stage_aliases: Vec<String> = Vec::new();

    for raw in content.lines() {
        let line = raw.trim();
        let fields: Vec<&str> = line.split_whitespace().collect();
        if !fields
            .first()
            .is_some_and(|keyword| keyword.eq_ignore_ascii_case("FROM"))
        {
            continue;
        }
        let Some(image_index) = fields
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(index, field)| (!field.starts_with("--")).then_some(index))
        else {
            errors.push(format!("{label}: malformed FROM instruction"));
            continue;
        };
        let image = fields[image_index];
        let is_internal_stage = stage_aliases
            .iter()
            .any(|alias| alias.eq_ignore_ascii_case(image));
        if image != "scratch" && !is_internal_stage && !is_immutable_image_reference(image) {
            errors.push(format!(
                "{label}: external base image {image:?} must retain a readable tag and pin a sha256 digest"
            ));
        }

        if fields
            .get(image_index + 1)
            .is_some_and(|field| field.eq_ignore_ascii_case("AS"))
        {
            if let Some(alias) = fields.get(image_index + 2) {
                stage_aliases.push((*alias).to_string());
            }
        }
    }
}

fn is_immutable_image_reference(image: &str) -> bool {
    let Some((readable, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    readable
        .rsplit('/')
        .next()
        .is_some_and(|name| name.contains(':'))
        && !readable.contains('@')
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_cargo_install_pin(
    content: &str,
    label: &str,
    package: &str,
    version: &str,
    errors: &mut Vec<String>,
) {
    let package_with_version = format!("{package}@");
    let mut installs: Vec<Vec<String>> = Vec::new();

    for instruction in logical_dockerfile_instructions(content) {
        let Some(separator) = instruction.find(|character: char| character.is_whitespace()) else {
            continue;
        };
        let (keyword, run) = instruction.split_at(separator);
        if !keyword.eq_ignore_ascii_case("RUN") {
            continue;
        }
        for command in docker_run_commands(run.trim()) {
            for arguments in cargo_install_invocations(&command) {
                if arguments.iter().any(|argument| {
                    argument == package || argument.starts_with(&package_with_version)
                }) {
                    installs.push(arguments);
                }
            }
        }
    }

    if installs.len() != 1 {
        errors.push(format!(
            "{label}: must contain exactly one cargo install command for {package}; found {}",
            installs.len()
        ));
        return;
    }

    let arguments = &installs[0];
    let package_count = arguments
        .iter()
        .filter(|argument| argument.as_str() == package)
        .count();
    let locked_count = arguments
        .iter()
        .filter(|argument| argument.as_str() == "--locked")
        .count();
    let mut versions = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--version" {
            versions.push(arguments.get(index + 1).map_or("", String::as_str));
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--version=") {
            versions.push(value);
        }
        index += 1;
    }

    if package_count != 1
        || locked_count != 1
        || versions.len() != 1
        || versions.first().copied() != Some(version)
        || arguments
            .iter()
            .any(|argument| is_forbidden_cargo_source_flag(argument))
        || arguments
            .iter()
            .any(|argument| argument.starts_with(&package_with_version))
    {
        errors.push(format!(
            "{label}: {package} must be installed once with literal --version {version} and exactly one --locked"
        ));
    }
}

fn is_forbidden_cargo_source_flag(argument: &str) -> bool {
    [
        "--git",
        "--path",
        "--registry",
        "--index",
        "--branch",
        "--tag",
        "--rev",
    ]
    .iter()
    .any(|flag| {
        argument == *flag
            || argument
                .strip_prefix(*flag)
                .is_some_and(|rest| rest.starts_with('='))
    })
}

/// Join Dockerfile line continuations so policy applies to logical RUN
/// instructions rather than one formatting-specific substring.
fn logical_dockerfile_instructions(content: &str) -> Vec<String> {
    let mut instructions = Vec::new();
    let mut current = String::new();

    for raw in content.lines() {
        let line = raw.trim();
        if current.is_empty() && (line.is_empty() || line.starts_with('#')) {
            continue;
        }
        let continued = line.ends_with('\\');
        let part = if continued {
            line.strip_suffix('\\').unwrap_or(line).trim_end()
        } else {
            line
        };
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(part);
        if !continued {
            instructions.push(std::mem::take(&mut current));
        }
    }

    if !current.trim().is_empty() {
        instructions.push(current);
    }
    instructions
}

/// Tokenize shell-form RUN commands just far enough to distinguish executable
/// commands, quoted arguments, assignments, and command separators. This keeps
/// comments or `echo "cargo install ..."` from satisfying the policy.
fn split_shell_commands(run: &str) -> Vec<Vec<String>> {
    fn push_token(token: &mut String, command: &mut Vec<String>) {
        if !token.is_empty() {
            command.push(std::mem::take(token));
        }
    }

    fn push_command(command: &mut Vec<String>, commands: &mut Vec<Vec<String>>) {
        if !command.is_empty() {
            commands.push(std::mem::take(command));
        }
    }

    let mut commands = Vec::new();
    let mut command = Vec::new();
    let mut token = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for character in run.chars() {
        if escaped {
            token.push(character);
            escaped = false;
            continue;
        }
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else if delimiter == '"' && character == '\\' {
                escaped = true;
            } else {
                token.push(character);
            }
            continue;
        }

        match character {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(character),
            ';' | '|' | '&' => {
                push_token(&mut token, &mut command);
                push_command(&mut command, &mut commands);
            }
            '#' if token.is_empty() => {
                push_command(&mut command, &mut commands);
                break;
            }
            value if value.is_whitespace() => push_token(&mut token, &mut command),
            value => token.push(value),
        }
    }
    if escaped {
        token.push('\\');
    }
    push_token(&mut token, &mut command);
    push_command(&mut command, &mut commands);
    commands
}

fn docker_run_commands(run: &str) -> Vec<Vec<String>> {
    let run = run.trim();
    if run.starts_with('[') {
        if let Ok(arguments) = serde_json::from_str::<Vec<String>>(run) {
            return vec![arguments];
        }
    }
    split_shell_commands(run)
}

fn cargo_install_invocations(command: &[String]) -> Vec<Vec<String>> {
    let mut installs = Vec::new();
    collect_cargo_install_invocations(command, 0, &mut installs);
    installs
}

fn collect_cargo_install_invocations(
    command: &[String],
    depth: usize,
    installs: &mut Vec<Vec<String>>,
) {
    if depth > 8 {
        // Fail closed for adversarial wrapper depth. The flattened tokens make
        // any target-package reference count as an unresolved replacement
        // install instead of disappearing from the policy model.
        installs.push(
            command
                .iter()
                .flat_map(|token| token.split_whitespace())
                .map(str::to_string)
                .collect(),
        );
        return;
    }

    let mut index = 0;
    loop {
        while command
            .get(index)
            .is_some_and(|token| is_shell_assignment(token))
        {
            index += 1;
        }

        let Some(executable) = command.get(index).map(|token| executable_name(token)) else {
            return;
        };
        match executable {
            "command" => {
                index += 1;
                while let Some(option) = command.get(index) {
                    if matches!(option.as_str(), "-v" | "-V") {
                        return;
                    }
                    if option == "--" || option == "-p" || option.starts_with('-') {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            "env" => {
                index += 1;
                let mut options = true;
                loop {
                    let Some(argument) = command.get(index) else {
                        return;
                    };
                    if is_shell_assignment(argument) {
                        index += 1;
                        continue;
                    }
                    if options && argument == "--" {
                        options = false;
                        index += 1;
                        continue;
                    }
                    if options && matches!(argument.as_str(), "-S" | "--split-string") {
                        if let Some(script) = command.get(index + 1) {
                            for nested in split_shell_commands(script) {
                                collect_cargo_install_invocations(&nested, depth + 1, installs);
                            }
                        }
                        return;
                    }
                    if options {
                        if let Some(script) = argument.strip_prefix("--split-string=") {
                            for nested in split_shell_commands(script) {
                                collect_cargo_install_invocations(&nested, depth + 1, installs);
                            }
                            return;
                        }
                    }
                    if options && matches!(argument.as_str(), "-u" | "--unset" | "-C" | "--chdir") {
                        index += 2;
                        continue;
                    }
                    if options && argument.starts_with('-') {
                        index += 1;
                        continue;
                    }
                    break;
                }
            }
            "sh" | "bash" => {
                if let Some(script) = shell_command_string(command, index) {
                    for nested in split_shell_commands(script) {
                        collect_cargo_install_invocations(&nested, depth + 1, installs);
                    }
                }
                return;
            }
            "cargo" => {
                if command
                    .get(index + 1)
                    .is_some_and(|token| token == "install")
                {
                    installs.push(command[index + 2..].to_vec());
                }
                return;
            }
            _ => return,
        }
    }
}

fn executable_name(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

fn shell_command_string(command: &[String], shell_index: usize) -> Option<&str> {
    command
        .iter()
        .enumerate()
        .skip(shell_index + 1)
        .find(|(_, option)| {
            option.starts_with('-')
                && !option.starts_with("--")
                && option[1..].bytes().any(|byte| byte == b'c')
        })
        .and_then(|(index, _)| command.get(index + 1))
        .map(String::as_str)
}

fn is_shell_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
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
            "FROM rust:1.88-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS build\n{}COPY migrations/ migrations/\nRUN cargo install cargo-chef --version 0.1.77 --locked\nRUN cargo build --release -p ryuki-api\nFROM debian:bookworm-slim@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb AS runtime\nENV RYUKI_API_EXECUTION_MODE=static-dry-run\nCOPY --from=build /app/target/release/ryuki-api /app/ryuki-api\n",
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
            "FROM rust:1.88-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS build\n{}RUN cargo install cargo-leptos --version 0.3.7 --locked\nRUN cargo leptos build --release -p ryuki-portal-ui\nFROM debian:bookworm-slim@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb AS runtime\nENV RYUKI_PORTAL_EXECUTION_MODE=static-dry-run\nCOPY --from=build /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui\nCOPY --from=build /app/target/site /app/site\n",
            full_copy_set()
        );
        let errors = validate_portal_dockerfile(&dockerfile, &members());
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn mutable_base_images_and_unversioned_build_tools_are_rejected() {
        let dockerfile = format!(
            "FROM rust:1.96-bookworm AS build\n{}RUN cargo install cargo-leptos --locked\nRUN cargo leptos build --release -p ryuki-portal-ui\nFROM debian:bookworm-slim AS runtime\nENV RYUKI_PORTAL_EXECUTION_MODE=static-dry-run\n",
            full_copy_set()
        );
        let errors = validate_portal_dockerfile(&dockerfile, &members());
        assert!(errors
            .iter()
            .any(|error| error.contains("rust:1.96-bookworm")));
        assert!(errors
            .iter()
            .any(|error| error.contains("debian:bookworm-slim")));
        assert!(errors
            .iter()
            .any(|error| error.contains("cargo-leptos") && error.contains("0.3.7")));
    }

    #[test]
    fn base_image_parser_does_not_allow_instruction_whitespace_bypass() {
        let mut errors = Vec::new();
        validate_immutable_base_images(
            "FROM\trust:1.96-bookworm AS Build\nFROM build AS runtime\n",
            "Dockerfile",
            &mut errors,
        );
        assert_eq!(errors.len(), 1, "unexpected base-image errors: {errors:?}");
        assert!(errors[0].contains("rust:1.96-bookworm"));
    }

    #[test]
    fn cargo_install_pin_accepts_flag_order_assignments_and_continuations() {
        let content = concat!(
            "RUN rustup target add wasm32-unknown-unknown \\\n",
            "    && CARGO_NET_OFFLINE=true cargo install --locked \\\n",
            "       --version=0.3.7 cargo-leptos\n",
        );
        let mut errors = Vec::new();
        validate_cargo_install_pin(
            content,
            "portal-ui Dockerfile",
            "cargo-leptos",
            "0.3.7",
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "valid exact install was rejected: {errors:?}"
        );
    }

    #[test]
    fn cargo_install_pin_accepts_command_and_env_wrappers() {
        let content = concat!(
            "RUN env CARGO_NET_OFFLINE=true command cargo install --locked \\\n",
            "    --version=0.3.7 cargo-leptos\n",
        );
        let mut errors = Vec::new();
        validate_cargo_install_pin(
            content,
            "portal-ui Dockerfile",
            "cargo-leptos",
            "0.3.7",
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "wrapped exact install failed: {errors:?}"
        );
    }

    #[test]
    fn cargo_install_pin_rejects_wrapped_and_nested_replacement_installs() {
        let pinned = "RUN cargo install cargo-leptos --version 0.3.7 --locked\n";
        for replacement in [
            "RUN command cargo install --force cargo-leptos\n",
            "RUN env CARGO_NET_OFFLINE=false cargo install --force cargo-leptos\n",
            "RUN /bin/sh -c 'command cargo install --force cargo-leptos'\n",
            "RUN [\"/bin/bash\", \"-c\", \"env cargo install --force cargo-leptos\"]\n",
        ] {
            let mut errors = Vec::new();
            validate_cargo_install_pin(
                &format!("{pinned}{replacement}"),
                "portal-ui Dockerfile",
                "cargo-leptos",
                "0.3.7",
                &mut errors,
            );
            assert!(
                errors.iter().any(|error| error.contains("found 2")),
                "wrapped replacement install was accepted: {replacement:?}; {errors:?}"
            );
        }
    }

    #[test]
    fn cargo_install_pin_rejects_missing_ranges_variables_decoys_and_duplicates() {
        let vulnerable = [
            "RUN cargo install cargo-leptos --locked\n",
            "RUN cargo install cargo-leptos --version ^0.3.7 --locked\n",
            "RUN cargo install cargo-leptos --version ${CARGO_LEPTOS_VERSION} --locked\n",
            "RUN cargo install cargo-leptos --version 0.3.7\n",
            "RUN echo 'cargo install cargo-leptos --version 0.3.7 --locked'\n",
            "RUN cargo build --release\n",
            concat!(
                "RUN cargo install cargo-leptos --version 0.3.7 --locked\n",
                "RUN cargo install --locked --version=0.3.7 cargo-leptos\n",
            ),
            "RUN cargo install cargo-leptos@0.3.7 --locked\n",
            "RUN cargo install cargo-leptos --version 0.3.7 --locked --git https://example.invalid/tool\n",
        ];

        for content in vulnerable {
            let mut errors = Vec::new();
            validate_cargo_install_pin(
                content,
                "portal-ui Dockerfile",
                "cargo-leptos",
                "0.3.7",
                &mut errors,
            );
            assert!(
                !errors.is_empty(),
                "vulnerable cargo install fixture was accepted: {content:?}"
            );
        }
    }
}
