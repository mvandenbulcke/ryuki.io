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
    if dockerfile_uses_custom_escape_directive(content) {
        errors.push(format!(
            "{label}: {package} install must use the default Dockerfile escape character so RUN instructions remain directly analyzable"
        ));
        return;
    }
    if dockerfile_uses_unsupported_shell_directive(content) {
        errors.push(format!(
            "{label}: {package} install cannot be validated with a custom Dockerfile SHELL directive"
        ));
        return;
    }

    let package_with_version = format!("{package}@");
    let mut installs: Vec<Vec<String>> = Vec::new();
    let mut total_install_count = 0usize;
    let mut unresolved_shell_control_flow = false;

    for instruction in logical_dockerfile_instructions(content) {
        let Some(separator) = instruction.find(|character: char| character.is_whitespace()) else {
            continue;
        };
        let (keyword, run) = instruction.split_at(separator);
        if !keyword.eq_ignore_ascii_case("RUN") {
            continue;
        }
        let Some(run) = docker_run_command_after_options(run.trim()) else {
            unresolved_shell_control_flow = true;
            continue;
        };
        let commands = if let Some(arguments) = docker_json_exec_arguments(run) {
            if json_exec_has_unresolved_cargo_install(&arguments, package) {
                unresolved_shell_control_flow = true;
            }
            vec![arguments]
        } else {
            if shell_run_has_unresolved_cargo_install(run, package) {
                unresolved_shell_control_flow = true;
            }
            split_shell_commands(run)
        };
        for command in commands {
            for arguments in cargo_install_invocations(&command) {
                total_install_count += 1;
                if arguments.iter().any(|argument| {
                    argument == package || argument.starts_with(&package_with_version)
                }) {
                    installs.push(arguments);
                }
            }
        }
    }

    if unresolved_shell_control_flow {
        errors.push(format!(
            "{label}: {package} install must be a directly analyzable command; shell control flow or dynamic command construction around cargo install is not allowed"
        ));
        return;
    }

    if total_install_count != 1 {
        errors.push(format!(
            "{label}: must contain exactly one cargo install command total while pinning {package}; found {total_install_count}"
        ));
        return;
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

fn dockerfile_uses_custom_escape_directive(content: &str) -> bool {
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some(comment) = line.strip_prefix('#') else {
            return false;
        };
        let Some((name, value)) = comment.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("escape") {
            return value.trim() != "\\";
        }
    }
    false
}

fn dockerfile_uses_unsupported_shell_directive(content: &str) -> bool {
    logical_dockerfile_instructions(content)
        .into_iter()
        .filter_map(|instruction| {
            let separator = instruction.find(char::is_whitespace)?;
            let (keyword, arguments) = instruction.split_at(separator);
            keyword
                .eq_ignore_ascii_case("SHELL")
                .then(|| arguments.trim().to_owned())
        })
        .any(|arguments| {
            serde_json::from_str::<Vec<String>>(&arguments).map_or(true, |arguments| {
                arguments.len() != 2
                    || !matches!(arguments[0].as_str(), "/bin/sh" | "sh")
                    || arguments[1] != "-c"
            })
        })
}

/// Reject target-tool installs embedded in shell grammar that this validator
/// intentionally does not try to execute or fully parse. Without this guard,
/// a Dockerfile could keep one valid direct pin while hiding a later
/// replacement install behind `if`, `case`, a loop, a function, or a
/// subshell; the direct-command collector would see only the harmless pin.
fn shell_run_has_unresolved_cargo_install(run: &str, package: &str) -> bool {
    analyze_shell_install(run, package, 0).unresolved
}

#[derive(Default)]
struct ShellInstallAnalysis {
    has_target_install: bool,
    unresolved: bool,
}

struct ShellSyntax {
    commands: Vec<Vec<ShellSyntaxWord>>,
    has_control_flow: bool,
    has_pipeline: bool,
    has_heredoc: bool,
}

struct ShellSyntaxWord {
    value: String,
    quoted: bool,
    expanded: bool,
}

fn analyze_shell_install(run: &str, package: &str, depth: usize) -> ShellInstallAnalysis {
    if depth > 8 {
        return ShellInstallAnalysis {
            has_target_install: true,
            unresolved: true,
        };
    }

    let syntax = shell_syntax(run);
    if syntax.has_heredoc {
        return ShellInstallAnalysis {
            has_target_install: true,
            unresolved: true,
        };
    }

    let package_is_present = syntax
        .commands
        .iter()
        .flatten()
        .any(|word| shell_syntax_word_is_package(word, package));
    let constructed_target_install = syntax
        .commands
        .iter()
        .flatten()
        .any(|word| shell_assignment_constructs_target_install(word, package));
    let has_install_word = syntax
        .commands
        .iter()
        .flatten()
        .any(|word| !word.quoted && word.value == "install");
    let cargo_has_dynamic_argv = syntax.commands.iter().any(|command| {
        command.iter().enumerate().any(|(index, word)| {
            !word.expanded
                && executable_name(&word.value) == "cargo"
                && command[index + 1..].iter().any(|argument| {
                    argument.expanded && shell_word_is_positional_parameter(&argument.value)
                })
        })
    });
    let mut analysis = ShellInstallAnalysis::default();

    for command in &syntax.commands {
        let (mut command_has_target, positional_expansion) =
            shell_command_has_target_install(command, package);
        let directly_embedded_target = command_has_target;
        let (executable_index, has_unsafe_wrapper) = shell_effective_executable_index(command);

        for script in command
            .iter()
            .filter(|word| word.expanded)
            .flat_map(|word| shell_command_substitution_bodies(&word.value))
        {
            let nested = analyze_shell_install(&script, package, depth + 1);
            command_has_target |= nested.has_target_install;
            analysis.unresolved |= nested.has_target_install || nested.unresolved;
        }

        if let Some(script) = shell_env_split_string(command) {
            let nested = analyze_shell_install(script, package, depth + 1);
            command_has_target |= nested.has_target_install;
            analysis.unresolved |= nested.unresolved;
        }

        if let Some(index) = executable_index {
            let executable = executable_name(&command[index].value);
            if command[index].expanded && !command[index].quoted {
                // Unquoted executable expansion can field-split into an
                // arbitrary executable, subcommand, and package argv sourced
                // from ENV/ARG values outside this RUN instruction.
                command_has_target = true;
                analysis.unresolved = true;
            }
            if directly_embedded_target && executable != "cargo" {
                let shell_positional_execution = if is_shell_executable(executable) {
                    shell_syntax_command_string(command, index)
                        .is_some_and(shell_script_uses_positional_command)
                } else if executable == "busybox"
                    && command
                        .get(index + 1)
                        .is_some_and(|word| is_shell_executable(executable_name(&word.value)))
                {
                    shell_syntax_command_string(command, index + 1)
                        .is_some_and(shell_script_uses_positional_command)
                } else {
                    true
                };
                analysis.unresolved |= shell_positional_execution;
            }
            if command[index].expanded {
                if let Some(script_word) = shell_syntax_command_word(command, index) {
                    if script_word.expanded {
                        command_has_target = true;
                        analysis.unresolved = true;
                    } else {
                        let nested = analyze_shell_install(&script_word.value, package, depth + 1);
                        command_has_target |= nested.has_target_install;
                        analysis.unresolved |= nested.has_target_install || nested.unresolved;
                    }
                }
            } else if is_shell_executable(executable) {
                if let Some(script_word) = shell_syntax_command_word(command, index) {
                    if script_word.expanded {
                        command_has_target = true;
                        analysis.unresolved = true;
                    } else {
                        let nested = analyze_shell_install(&script_word.value, package, depth + 1);
                        command_has_target |= nested.has_target_install;
                        analysis.unresolved |= nested.unresolved
                            || (is_alternate_shell_executable(executable)
                                && nested.has_target_install);
                    }
                } else {
                    command_has_target = true;
                    analysis.unresolved = true;
                }
            } else if executable == "busybox"
                && command
                    .get(index + 1)
                    .is_some_and(|word| is_shell_executable(executable_name(&word.value)))
            {
                if let Some(script_word) = shell_syntax_command_word(command, index + 1) {
                    if script_word.expanded {
                        command_has_target = true;
                        analysis.unresolved = true;
                    } else {
                        let nested = analyze_shell_install(&script_word.value, package, depth + 1);
                        command_has_target |= nested.has_target_install;
                        analysis.unresolved |= nested.has_target_install || nested.unresolved;
                    }
                } else {
                    command_has_target = true;
                    analysis.unresolved = true;
                }
            } else if executable == "eval" {
                let script = command[index + 1..]
                    .iter()
                    .map(|word| word.value.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                let nested = analyze_shell_install(&script, package, depth + 1);
                command_has_target |= nested.has_target_install;
                analysis.unresolved |= nested.has_target_install || nested.unresolved;
            } else if matches!(executable, "." | "source") {
                command_has_target = true;
                analysis.unresolved = true;
            } else if executable == "xargs" && shell_command_contains_cargo_install(command) {
                // xargs can obtain the package operand from stdin, so the
                // target cannot be proven even when it is absent from argv.
                command_has_target = true;
                analysis.unresolved = true;
            }
        }

        if command_has_target {
            analysis.has_target_install = true;
            analysis.unresolved |= positional_expansion || has_unsafe_wrapper;
        }
    }

    if syntax.has_pipeline
        && syntax
            .commands
            .iter()
            .any(|command| shell_command_is_interpreter_sink(command))
    {
        analysis.has_target_install = true;
        analysis.unresolved = true;
    }

    if package_is_present
        && syntax.commands.iter().any(|command| {
            let (index, _) = shell_effective_executable_index(command);
            index.is_some_and(|index| {
                command[index].expanded
                    && command
                        .get(index + 1)
                        .is_some_and(|word| word.value == "install" || word.expanded)
            })
        })
    {
        analysis.has_target_install = true;
        analysis.unresolved = true;
    }

    if constructed_target_install
        && syntax.commands.iter().any(|command| {
            let (index, _) = shell_effective_executable_index(command);
            index.is_some_and(|index| command[index].expanded)
        })
    {
        analysis.has_target_install = true;
        analysis.unresolved = true;
    }

    if package_is_present && has_install_word && cargo_has_dynamic_argv {
        analysis.has_target_install = true;
        analysis.unresolved = true;
    }

    if analysis.has_target_install && (syntax.has_control_flow || syntax.has_pipeline) {
        analysis.unresolved = true;
    }
    analysis
}

fn shell_command_has_target_install(command: &[ShellSyntaxWord], package: &str) -> (bool, bool) {
    for (index, word) in command.iter().enumerate() {
        if !word.expanded && executable_name(&word.value) == "cargo" {
            let Some(subcommand_index) = shell_cargo_install_subcommand_index(command, index)
            else {
                if command.get(index + 1).is_some_and(|subcommand| {
                    subcommand.expanded
                        && (!subcommand.quoted
                            || command[index + 2..].iter().any(|argument| {
                                argument.expanded || shell_syntax_word_is_package(argument, package)
                            }))
                }) {
                    return (true, true);
                }
                continue;
            };
            if command[subcommand_index + 1..]
                .iter()
                .any(|argument| is_forbidden_cargo_source_flag(&argument.value))
            {
                return (true, false);
            }
            let (has_literal_target, has_dynamic_target) =
                shell_cargo_install_target_operands(&command[subcommand_index + 1..], package);
            if has_literal_target || has_dynamic_target {
                return (true, has_dynamic_target);
            }
        }

        if word.expanded {
            let Some(subcommand) = command.get(index + 1) else {
                continue;
            };
            if (subcommand.value == "install" || subcommand.expanded)
                && command[index + 2..].iter().any(|argument| {
                    argument.expanded || shell_syntax_word_is_package(argument, package)
                })
            {
                return (true, true);
            }
        }
    }
    (false, false)
}

fn shell_command_contains_cargo_install(command: &[ShellSyntaxWord]) -> bool {
    command.iter().enumerate().any(|(index, word)| {
        !word.expanded
            && executable_name(&word.value) == "cargo"
            && shell_cargo_install_subcommand_index(command, index).is_some()
    })
}

fn shell_cargo_install_subcommand_index(
    command: &[ShellSyntaxWord],
    cargo_index: usize,
) -> Option<usize> {
    let mut index = cargo_index + 1;
    if command
        .get(index)
        .is_some_and(|word| !word.expanded && word.value.starts_with('+'))
    {
        index += 1;
    }
    loop {
        let word = command.get(index)?;
        if word.expanded {
            return None;
        }
        if word.value == "install" {
            return Some(index);
        }
        if cargo_global_option_consumes_value(&word.value) {
            index += 2;
            continue;
        }
        if word.value.starts_with('-') && word.value != "--" {
            index += 1;
            continue;
        }
        return None;
    }
}

fn cargo_global_option_consumes_value(option: &str) -> bool {
    matches!(option, "--color" | "--config" | "-Z")
}

fn shell_cargo_install_target_operands(
    arguments: &[ShellSyntaxWord],
    package: &str,
) -> (bool, bool) {
    let mut literal_target = false;
    let mut dynamic_target = false;
    let mut options = true;
    let mut index = 0;

    while let Some(argument) = arguments.get(index) {
        if let Some(consumes_following_operand) =
            shell_redirection_consumes_following_operand(&argument.value)
        {
            index += if consumes_following_operand { 2 } else { 1 };
            continue;
        }
        if options && argument.value == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && cargo_install_option_consumes_value(&argument.value) {
            index += 2;
            continue;
        }
        if options && argument.value.starts_with('-') {
            index += 1;
            continue;
        }
        literal_target |= shell_syntax_word_is_package(argument, package);
        dynamic_target |= argument.expanded;
        index += 1;
    }
    (literal_target, dynamic_target)
}

fn shell_redirection_consumes_following_operand(word: &str) -> Option<bool> {
    let redirection = word.trim_start_matches(|character: char| character.is_ascii_digit());
    if redirection.starts_with(">&") || redirection.starts_with("<&") {
        return Some(false);
    }
    for operator in ["&>>", "&>", "<>", ">>", "<<", ">", "<"] {
        if let Some(operand) = redirection.strip_prefix(operator) {
            return Some(operand.is_empty());
        }
    }
    None
}

fn cargo_install_option_consumes_value(option: &str) -> bool {
    matches!(
        option,
        "--version"
            | "--root"
            | "--path"
            | "--git"
            | "--branch"
            | "--tag"
            | "--rev"
            | "--registry"
            | "--index"
            | "--target"
            | "--target-dir"
            | "--bin"
            | "--example"
            | "--features"
            | "--profile"
            | "--jobs"
            | "--config"
            | "--color"
            | "-j"
            | "-F"
            | "-Z"
    )
}

fn shell_assignment_constructs_target_install(word: &ShellSyntaxWord, package: &str) -> bool {
    let Some((_, value)) = word.value.split_once('=') else {
        return false;
    };
    let words: Vec<ShellSyntaxWord> = value
        .split_whitespace()
        .map(|value| ShellSyntaxWord {
            value: value.to_string(),
            quoted: false,
            expanded: false,
        })
        .collect();
    shell_command_has_target_install(&words, package).0
}

fn shell_command_substitution_bodies(value: &str) -> Vec<String> {
    let characters: Vec<char> = value.chars().collect();
    let mut bodies = Vec::new();
    let mut index = 0;

    while index < characters.len() {
        if characters[index] == '`' {
            let start = index + 1;
            index = start;
            while index < characters.len() && characters[index] != '`' {
                if characters[index] == '\\' {
                    index += 1;
                }
                index += 1;
            }
            if index <= characters.len() {
                bodies.push(characters[start..index].iter().collect());
            }
            index += 1;
            continue;
        }
        if characters[index] != '$'
            || characters.get(index + 1) != Some(&'(')
            || characters.get(index + 2) == Some(&'(')
        {
            index += 1;
            continue;
        }

        let start = index + 2;
        index = start;
        let mut depth = 1usize;
        let mut quote: Option<char> = None;
        let mut escaped = false;
        while index < characters.len() {
            let character = characters[index];
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if let Some(delimiter) = quote {
                if character == delimiter {
                    quote = None;
                }
            } else if matches!(character, '\'' | '"') {
                quote = Some(character);
            } else if character == '(' {
                depth += 1;
            } else if character == ')' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            index += 1;
        }
        if depth == 0 {
            bodies.push(characters[start..index].iter().collect());
        }
        index += 1;
    }
    bodies
}

fn shell_command_is_interpreter_sink(command: &[ShellSyntaxWord]) -> bool {
    let (Some(index), _) = shell_effective_executable_index(command) else {
        return false;
    };
    let executable = executable_name(&command[index].value);
    is_shell_executable(executable)
        || executable == "xargs"
        || matches!(executable, "." | "source")
        || (executable == "busybox"
            && command
                .get(index + 1)
                .is_some_and(|word| is_shell_executable(executable_name(&word.value))))
}

fn shell_script_uses_positional_command(script: &str) -> bool {
    let syntax = shell_syntax(script);
    syntax.commands.iter().any(|command| {
        let (Some(index), _) = shell_effective_executable_index(command) else {
            return false;
        };
        command[index].expanded && shell_word_is_positional_parameter(&command[index].value)
    })
}

fn shell_word_is_positional_parameter(value: &str) -> bool {
    let parameter = value
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
        .or_else(|| value.strip_prefix('$'))
        .unwrap_or(value);
    let parameter = parameter.strip_prefix('!').unwrap_or(parameter);
    matches!(parameter, "@" | "*")
        || (!parameter.is_empty() && parameter.bytes().all(|byte| byte.is_ascii_digit()))
}

fn shell_syntax_word_is_package(word: &ShellSyntaxWord, package: &str) -> bool {
    let package_with_version = format!("{package}@");
    word.value == package
        || word.value.starts_with(&package_with_version)
        || word
            .value
            .split_once('=')
            .is_some_and(|(_, value)| value == package || value.starts_with(&package_with_version))
}

fn shell_effective_executable_index(command: &[ShellSyntaxWord]) -> (Option<usize>, bool) {
    let mut index = 0;
    let mut has_unsafe_wrapper = false;

    loop {
        while command
            .get(index)
            .is_some_and(|word| is_shell_assignment(&word.value))
        {
            index += 1;
        }
        let Some(executable) = command.get(index).map(|word| executable_name(&word.value)) else {
            return (None, has_unsafe_wrapper);
        };
        match executable {
            "command" => {
                index += 1;
                while let Some(option) = command.get(index) {
                    if matches!(option.value.as_str(), "-v" | "-V") {
                        return (None, has_unsafe_wrapper);
                    }
                    if option.value == "--" || option.value == "-p" || option.value.starts_with('-')
                    {
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
                        return (None, has_unsafe_wrapper);
                    };
                    if is_shell_assignment(&argument.value) {
                        index += 1;
                        continue;
                    }
                    if options && argument.value == "--" {
                        options = false;
                        index += 1;
                        continue;
                    }
                    if options
                        && matches!(argument.value.as_str(), "-u" | "--unset" | "-C" | "--chdir")
                    {
                        index += 2;
                        continue;
                    }
                    if options && argument.value.starts_with('-') {
                        index += 1;
                        continue;
                    }
                    break;
                }
            }
            "exec" => {
                has_unsafe_wrapper = true;
                index += 1;
            }
            _ => return (Some(index), has_unsafe_wrapper),
        }
    }
}

fn shell_env_split_string(command: &[ShellSyntaxWord]) -> Option<&str> {
    let mut index = 0;
    while command
        .get(index)
        .is_some_and(|word| is_shell_assignment(&word.value))
    {
        index += 1;
    }
    if command
        .get(index)
        .is_some_and(|word| executable_name(&word.value) == "command")
    {
        index += 1;
        while command
            .get(index)
            .is_some_and(|word| word.value.starts_with('-'))
        {
            index += 1;
        }
    }
    if !command
        .get(index)
        .is_some_and(|word| executable_name(&word.value) == "env")
    {
        return None;
    }

    for (option_index, option) in command.iter().enumerate().skip(index + 1) {
        if matches!(option.value.as_str(), "-S" | "--split-string") {
            return command
                .get(option_index + 1)
                .map(|word| word.value.as_str());
        }
        if let Some(script) = option.value.strip_prefix("--split-string=") {
            return Some(script);
        }
    }
    None
}

fn shell_syntax_command_word(
    command: &[ShellSyntaxWord],
    shell_index: usize,
) -> Option<&ShellSyntaxWord> {
    command
        .iter()
        .enumerate()
        .skip(shell_index + 1)
        .find(|(_, option)| {
            option.value.starts_with('-')
                && !option.value.starts_with("--")
                && option.value[1..].bytes().any(|byte| byte == b'c')
        })
        .and_then(|(index, _)| command.get(index + 1))
}

fn shell_syntax_command_string(command: &[ShellSyntaxWord], shell_index: usize) -> Option<&str> {
    shell_syntax_command_word(command, shell_index).map(|word| word.value.as_str())
}

fn is_shell_executable(executable: &str) -> bool {
    matches!(
        executable,
        "sh" | "bash" | "dash" | "ash" | "zsh" | "ksh" | "fish"
    )
}

fn is_alternate_shell_executable(executable: &str) -> bool {
    is_shell_executable(executable) && !matches!(executable, "sh" | "bash")
}

fn append_balanced_shell_expansion(
    value: &mut String,
    characters: &mut std::iter::Peekable<std::str::Chars<'_>>,
    opening: char,
    closing: char,
) {
    if characters.peek() != Some(&opening) {
        return;
    }
    value.push(characters.next().expect("peeked expansion delimiter"));
    let mut depth = 1usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for character in characters.by_ref() {
        value.push(character);
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character == opening {
            depth += 1;
        } else if character == closing {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
    }
}

fn append_backtick_shell_expansion(
    value: &mut String,
    characters: &mut std::iter::Peekable<std::str::Chars<'_>>,
) {
    let mut escaped = false;
    for character in characters.by_ref() {
        value.push(character);
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '`' {
            break;
        }
    }
}

fn shell_syntax(run: &str) -> ShellSyntax {
    fn push_word(
        value: &mut String,
        quoted: &mut bool,
        expanded: &mut bool,
        command: &mut Vec<ShellSyntaxWord>,
    ) {
        if !value.is_empty() {
            command.push(ShellSyntaxWord {
                value: std::mem::take(value),
                quoted: std::mem::take(quoted),
                expanded: std::mem::take(expanded),
            });
        }
    }

    fn push_command(
        value: &mut String,
        quoted: &mut bool,
        expanded: &mut bool,
        command: &mut Vec<ShellSyntaxWord>,
        commands: &mut Vec<Vec<ShellSyntaxWord>>,
    ) {
        push_word(value, quoted, expanded, command);
        if !command.is_empty() {
            commands.push(std::mem::take(command));
        }
    }

    let mut commands = Vec::new();
    let mut command = Vec::new();
    let mut value = String::new();
    let mut word_quoted = false;
    let mut word_expanded = false;
    let mut quote: Option<char> = None;
    let mut has_control_flow = false;
    let mut has_pipeline = false;
    let mut has_heredoc = false;
    let mut characters = run.chars().peekable();

    while let Some(character) = characters.next() {
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else if delimiter == '"' && character == '\\' {
                word_quoted = true;
                if let Some(escaped) = characters.next() {
                    value.push(escaped);
                }
            } else {
                if delimiter == '"' && matches!(character, '$' | '`') {
                    word_expanded = true;
                    if character == '`' {
                        has_control_flow = true;
                    }
                }
                value.push(character);
            }
            continue;
        }

        match character {
            '\\' => {
                word_quoted = true;
                if let Some(escaped) = characters.next() {
                    value.push(escaped);
                }
            }
            '\'' | '"' => {
                word_quoted = true;
                quote = Some(character);
            }
            '$' => {
                word_expanded = true;
                value.push(character);
                if characters.peek() == Some(&'{') {
                    append_balanced_shell_expansion(&mut value, &mut characters, '{', '}');
                } else if characters.peek() == Some(&'(') {
                    has_control_flow = true;
                    append_balanced_shell_expansion(&mut value, &mut characters, '(', ')');
                }
            }
            '`' => {
                word_expanded = true;
                has_control_flow = true;
                value.push(character);
                append_backtick_shell_expansion(&mut value, &mut characters);
            }
            '<' if characters.peek() == Some(&'<') => {
                characters.next();
                has_heredoc = true;
                value.push_str("<<");
            }
            ';' => push_command(
                &mut value,
                &mut word_quoted,
                &mut word_expanded,
                &mut command,
                &mut commands,
            ),
            '|' => {
                let logical_or = characters.peek() == Some(&'|');
                if logical_or {
                    characters.next();
                } else {
                    has_pipeline = true;
                    if characters.peek() == Some(&'&') {
                        characters.next();
                    }
                }
                push_command(
                    &mut value,
                    &mut word_quoted,
                    &mut word_expanded,
                    &mut command,
                    &mut commands,
                );
            }
            '&' => {
                let redirects_file_descriptor = (value.ends_with('>') || value.ends_with('<'))
                    && characters
                        .peek()
                        .is_some_and(|next| next.is_ascii_digit() || *next == '-' || *next == '$');
                let redirects_both_streams = value.is_empty() && characters.peek() == Some(&'>');
                if redirects_file_descriptor || redirects_both_streams {
                    value.push('&');
                    continue;
                }
                let logical_and = characters.peek() == Some(&'&');
                if logical_and {
                    characters.next();
                } else {
                    has_control_flow = true;
                }
                push_command(
                    &mut value,
                    &mut word_quoted,
                    &mut word_expanded,
                    &mut command,
                    &mut commands,
                );
            }
            '(' | ')' | '{' | '}' => {
                has_control_flow = true;
                push_command(
                    &mut value,
                    &mut word_quoted,
                    &mut word_expanded,
                    &mut command,
                    &mut commands,
                );
            }
            '#' if value.is_empty() => {
                for remainder in characters.by_ref() {
                    if remainder == '\n' {
                        break;
                    }
                }
                push_command(
                    &mut value,
                    &mut word_quoted,
                    &mut word_expanded,
                    &mut command,
                    &mut commands,
                );
            }
            '\n' => push_command(
                &mut value,
                &mut word_quoted,
                &mut word_expanded,
                &mut command,
                &mut commands,
            ),
            character if character.is_whitespace() => push_word(
                &mut value,
                &mut word_quoted,
                &mut word_expanded,
                &mut command,
            ),
            character => value.push(character),
        }
    }
    push_command(
        &mut value,
        &mut word_quoted,
        &mut word_expanded,
        &mut command,
        &mut commands,
    );

    for word in commands.iter().flatten() {
        if !word.quoted
            && (word.value == "!"
                || matches!(
                    word.value.as_str(),
                    "if" | "then"
                        | "elif"
                        | "else"
                        | "fi"
                        | "case"
                        | "esac"
                        | "for"
                        | "select"
                        | "while"
                        | "until"
                        | "do"
                        | "done"
                        | "function"
                        | "eval"
                ))
        {
            has_control_flow = true;
        }
    }

    ShellSyntax {
        commands,
        has_control_flow,
        has_pipeline,
        has_heredoc,
    }
}

fn json_exec_has_unresolved_cargo_install(arguments: &[String], package: &str) -> bool {
    let words: Vec<ShellSyntaxWord> = arguments
        .iter()
        .map(|argument| ShellSyntaxWord {
            value: argument.clone(),
            quoted: true,
            expanded: false,
        })
        .collect();
    if let Some(script) = shell_env_split_string(&words) {
        let nested = analyze_shell_install(script, package, 0);
        if nested.unresolved {
            return true;
        }
    }
    let (Some(index), has_unsafe_wrapper) = shell_effective_executable_index(&words) else {
        return false;
    };
    let executable = executable_name(&words[index].value);
    let (embedded_target, _) = shell_command_has_target_install(&words, package);
    if embedded_target && (executable != "cargo" || has_unsafe_wrapper) {
        return true;
    }
    if is_shell_executable(executable) {
        let Some(script) = shell_syntax_command_string(&words, index) else {
            return true;
        };
        return {
            let nested = analyze_shell_install(script, package, 0);
            let (positional_target, _) = shell_command_has_target_install(&words, package);
            nested.unresolved
                || (has_unsafe_wrapper && nested.has_target_install)
                || (is_alternate_shell_executable(executable) && nested.has_target_install)
                || (positional_target && shell_script_uses_positional_command(script))
        };
    }
    if executable == "busybox"
        && words
            .get(index + 1)
            .is_some_and(|word| is_shell_executable(executable_name(&word.value)))
    {
        let Some(script) = shell_syntax_command_string(&words, index + 1) else {
            return true;
        };
        return {
            let nested = analyze_shell_install(script, package, 0);
            nested.unresolved || nested.has_target_install
        };
    }
    executable == "xargs" && shell_command_contains_cargo_install(&words)
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

fn docker_run_command_after_options(mut run: &str) -> Option<&str> {
    while run.starts_with("--") {
        let separator = run.find(char::is_whitespace)?;
        let (option, remainder) = run.split_at(separator);
        if !["--mount=", "--network=", "--security=", "--device="]
            .iter()
            .any(|prefix| option.starts_with(prefix) && option.len() > prefix.len())
        {
            return None;
        }
        run = remainder.trim_start();
    }
    (!run.is_empty()).then_some(run)
}

fn docker_json_exec_arguments(run: &str) -> Option<Vec<String>> {
    let run = run.trim();
    if run.starts_with('[') {
        return serde_json::from_str::<Vec<String>>(run).ok();
    }
    None
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
            "exec" => {
                index += 1;
            }
            "sh" | "bash" | "dash" | "ash" | "zsh" | "ksh" | "fish" => {
                if let Some(script) = shell_command_string(command, index) {
                    for nested in split_shell_commands(script) {
                        collect_cargo_install_invocations(&nested, depth + 1, installs);
                    }
                }
                return;
            }
            "busybox"
                if command
                    .get(index + 1)
                    .is_some_and(|argument| is_shell_executable(executable_name(argument))) =>
            {
                if let Some(script) = shell_command_string(command, index + 1) {
                    for nested in split_shell_commands(script) {
                        collect_cargo_install_invocations(&nested, depth + 1, installs);
                    }
                }
                return;
            }
            "cargo" => {
                if let Some(subcommand_index) = cargo_install_subcommand_index(command, index) {
                    installs.push(command[subcommand_index + 1..].to_vec());
                }
                return;
            }
            _ => return,
        }
    }
}

fn cargo_install_subcommand_index(command: &[String], cargo_index: usize) -> Option<usize> {
    let mut index = cargo_index + 1;
    if command.get(index).is_some_and(|word| word.starts_with('+')) {
        index += 1;
    }
    loop {
        let word = command.get(index)?;
        if word == "install" {
            return Some(index);
        }
        if cargo_global_option_consumes_value(word) {
            index += 2;
            continue;
        }
        if word.starts_with('-') && word != "--" {
            index += 1;
            continue;
        }
        return None;
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
    fn cargo_install_pin_preserves_direct_continued_pins_for_both_build_tools() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let content = format!(
                "RUN CARGO_NET_OFFLINE=true command cargo install --locked \\\n                 --version={version} {package}\n"
            );
            let mut errors = Vec::new();
            validate_cargo_install_pin(&content, "Dockerfile", package, version, &mut errors);
            assert!(
                errors.is_empty(),
                "valid direct {package} pin was rejected: {errors:?}"
            );

            let json_exec = format!(
                "RUN [\"cargo\", \"install\", \"{package}\", \"--version\", \"{version}\", \"--locked\"]\n"
            );
            let mut json_errors = Vec::new();
            validate_cargo_install_pin(
                &json_exec,
                "Dockerfile",
                package,
                version,
                &mut json_errors,
            );
            assert!(
                json_errors.is_empty(),
                "valid JSON-exec {package} pin was rejected: {json_errors:?}"
            );
        }
    }

    #[test]
    fn cargo_install_pin_rejects_if_case_and_loop_replacement_installs() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            for replacement in [
                format!(
                    "RUN if true; then \\\n                         cargo install {package} --force; fi\n"
                ),
                format!(
                    "RUN tool={package}; case \"$tool\" in *)cargo install \"$tool\" --force ;; esac\n"
                ),
                format!(
                    "RUN for tool in {package}; do cargo install \"$tool\" --force; done\n"
                ),
                "RUN if true; then cargo install \"$BUILD_TOOL\" --force; fi\n"
                    .to_string(),
                format!(
                    "RUN cargo_cmd=cargo; tool={package}; if true; then \"$cargo_cmd\" install \"$tool\" --force; fi\n"
                ),
            ] {
                assert_shell_control_flow_replacement_is_rejected(
                    package,
                    version,
                    &replacement,
                );
            }
        }
    }

    #[test]
    fn cargo_install_pin_rejects_dynamic_positions_without_control_keywords() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            for replacement in [
                format!("RUN CARGO=cargo; \"$CARGO\" install {package} --force\n"),
                format!("RUN TOOL={package}; cargo install \"$TOOL\" --force\n"),
                format!("RUN SUBCOMMAND=install; cargo \"$SUBCOMMAND\" {package} --force\n"),
                format!(
                    "RUN SHELL=dash; \"$SHELL\" -c 'cargo install {package} --force'\n"
                ),
                format!(
                    "ENV REINSTALL=\"cargo install {package} --force\"\nRUN $REINSTALL\n"
                ),
                format!(
                    "ENV ARGS=\"install {package} --force\"\nRUN cargo $ARGS\n"
                ),
                format!("RUN cmd='cargo install {package} --force'; $cmd\n"),
                format!("ENV CARGO=cargo\nRUN ${{CARGO}} install {package} --force\n"),
                format!("RUN $(printf cargo) install {package} --force\n"),
                format!("RUN `printf cargo` install {package} --force\n"),
                format!("RUN echo \"$(cargo install {package} --force)\"\n"),
                format!(
                    "RUN c() {{ cargo \"$@\"; }}; c install {package} --force\n"
                ),
                format!("RUN set -- install {package} --force; cargo \"$@\"\n"),
                format!(
                    "RUN CARGO=cargo; SUBCOMMAND=install; TOOL={package}; \"$CARGO\" \"$SUBCOMMAND\" \"$TOOL\" --force\n"
                ),
            ] {
                assert_shell_control_flow_replacement_is_rejected(
                    package,
                    version,
                    &replacement,
                );
            }
        }
    }

    #[test]
    fn cargo_install_pin_rejects_function_subshell_and_nested_shell_replacements() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            for replacement in [
                format!(
                    "RUN install_tool() {{ cargo install {package} --force; }}; install_tool\n"
                ),
                format!("RUN (cargo install {package} --force)\n"),
                format!(
                    "RUN result=$(cargo install {package} --force)\n"
                ),
                format!("RUN ! cargo install {package} --force\n"),
                format!(
                    "RUN /bin/sh -c 'if true; then cargo install {package} --force; fi'\n"
                ),
                format!(
                    "RUN [\"/bin/bash\", \"-c\", \"if true; then cargo install {package} --force; fi\"]\n"
                ),
            ] {
                assert_shell_control_flow_replacement_is_rejected(
                    package,
                    version,
                    &replacement,
                );
            }
        }
    }

    #[test]
    fn cargo_install_pin_rejects_exec_alternate_shell_and_pipeline_wrappers() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let positional_json = format!(
                "RUN {}\n",
                serde_json::to_string(&[
                    "sh",
                    "-c",
                    "\"$0\" \"$@\"",
                    "cargo",
                    "install",
                    package,
                    "--force",
                ])
                .expect("serialize positional shell fixture")
            );
            for replacement in [
                format!("RUN exec cargo install {package} --force\n"),
                format!("RUN /bin/dash -c 'cargo install {package} --force'\n"),
                format!("RUN busybox sh -c 'cargo install {package} --force'\n"),
                format!("RUN env -S 'if true; then cargo install {package} --force; fi'\n"),
                format!("RUN printf '%s\\n' '{package}' | xargs cargo install --force\n"),
                format!("RUN printf 'cargo install {package} --force\\n' | sh\n"),
                format!(
                    "RUN printf '%s\\n' 'cargo install {package} --force' >/tmp/reinstall.sh && sh /tmp/reinstall.sh\n"
                ),
                format!(
                    "RUN printf '%s\\n' 'cargo install {package} --force' >/tmp/reinstall.sh && . /tmp/reinstall.sh\n"
                ),
                format!("RUN [\"dash\", \"-c\", \"cargo install {package} --force\"]\n"),
                format!("RUN timeout 600 cargo install {package} --force\n"),
                format!(
                    "RUN find /tmp -name marker -exec cargo install {package} --force \\;\n"
                ),
                format!(
                    "RUN sh -c '\"$0\" \"$@\"' cargo install {package} --force\n"
                ),
                format!("RUN sh -c '$1' _ 'cargo install {package} --force'\n"),
                format!(
                    "RUN sh -c \"$(printf '%s' 'cargo install {package} --force')\"\n"
                ),
                format!(
                    "RUN [\"timeout\", \"600\", \"cargo\", \"install\", \"{package}\", \"--force\"]\n"
                ),
                format!(
                    "RUN [\"rustup\", \"run\", \"stable\", \"cargo\", \"install\", \"{package}\", \"--force\"]\n"
                ),
                positional_json,
            ] {
                assert_shell_control_flow_replacement_is_rejected(package, version, &replacement);
            }
        }
    }

    #[test]
    fn cargo_install_pin_rejects_cargo_global_and_buildkit_replacements() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            for replacement in [
                format!("RUN cargo +stable install {package} --force\n"),
                format!("RUN cargo --color=never install {package} --force\n"),
                format!(
                    "RUN --mount=type=cache,target=/tmp/cargo-cache cargo install {package} --force\n"
                ),
                format!(
                    "RUN --mount=type=cache,target=/tmp/cargo-cache [\"cargo\", \"install\", \"{package}\", \"--force\"]\n"
                ),
                "COPY attacker /tmp/tool\nRUN cargo install --path /tmp/tool --force\n"
                    .to_string(),
            ] {
                assert_replacement_is_rejected(package, version, &replacement);
            }
        }
    }

    #[test]
    fn cargo_install_pin_rejects_heredocs_and_custom_escape_directives() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let pinned = format!("RUN cargo install {package} --version {version} --locked\n");
            for content in [
                format!("{pinned}RUN <<'EOF'\ncargo install {package} --force\nEOF\n"),
                format!("# escape=`\n{pinned}RUN `\n    cargo install {package} --force\n"),
                format!("{pinned}SHELL [\"cargo\", \"install\", \"--force\"]\nRUN {package}\n"),
            ] {
                let mut errors = Vec::new();
                validate_cargo_install_pin(&content, "Dockerfile", package, version, &mut errors);
                assert!(
                    errors.iter().any(|error| error.contains(package)),
                    "unsupported Docker framing was accepted for {package}: {content:?}; {errors:?}"
                );
            }
        }
    }

    #[test]
    fn cargo_install_pin_preserves_json_arguments_and_quoted_shell_data() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let json_exec = format!(
                "RUN [\"cargo\", \"install\", \"{package}\", \"--version\", \"{version}\", \"--locked\", \"--root\", \"/opt/{{tools}}\"]\n"
            );
            let mut json_errors = Vec::new();
            validate_cargo_install_pin(
                &json_exec,
                "Dockerfile",
                package,
                version,
                &mut json_errors,
            );
            assert!(
                json_errors.is_empty(),
                "JSON-exec data was mistaken for shell grammar for {package}: {json_errors:?}"
            );

            let shell = format!(
                "RUN cargo install {package} --version {version} --locked\n\
                 RUN if true; then printf '%s\\n' 'cargo install {package} (documentation only)' | grep -q documentation; fi\n"
            );
            let mut shell_errors = Vec::new();
            validate_cargo_install_pin(&shell, "Dockerfile", package, version, &mut shell_errors);
            assert!(
                shell_errors.is_empty(),
                "quoted shell data was mistaken for an invocation for {package}: {shell_errors:?}"
            );

            let default_escape = format!(
                r#"# escape=\
SHELL ["/bin/sh", "-c"]
RUN cargo install {package} --version {version} --locked
"#
            );
            let mut default_escape_errors = Vec::new();
            validate_cargo_install_pin(
                &default_escape,
                "Dockerfile",
                package,
                version,
                &mut default_escape_errors,
            );
            assert!(
                default_escape_errors.is_empty(),
                "default Docker escape directive was rejected for {package}: {default_escape_errors:?}"
            );

            let expanded_option_values = format!(
                "RUN cargo install {package} --version {version} --locked --root \"$CARGO_HOME\" --color \"$CARGO_COLOR\" > \"$LOG\" 2> \"$ERROR_LOG\" 3>&1\n"
            );
            let mut expanded_option_errors = Vec::new();
            validate_cargo_install_pin(
                &expanded_option_values,
                "Dockerfile",
                package,
                version,
                &mut expanded_option_errors,
            );
            assert!(
                expanded_option_errors.is_empty(),
                "expanded install-option values or fd redirection were mistaken for a package operand for {package}: {expanded_option_errors:?}"
            );
        }
    }

    fn assert_shell_control_flow_replacement_is_rejected(
        package: &str,
        version: &str,
        replacement: &str,
    ) {
        let pinned = format!("RUN cargo install {package} --version {version} --locked\n");
        let mut errors = Vec::new();
        validate_cargo_install_pin(
            &format!("{pinned}{replacement}"),
            "Dockerfile",
            package,
            version,
            &mut errors,
        );
        assert!(
            errors.iter().any(|error| {
                error.contains(package) && error.contains("shell control flow")
            }),
            "shell-control-flow replacement install was accepted for {package}: {replacement:?}; {errors:?}"
        );
    }

    fn assert_replacement_is_rejected(package: &str, version: &str, replacement: &str) {
        let pinned = format!("RUN cargo install {package} --version {version} --locked\n");
        let mut errors = Vec::new();
        validate_cargo_install_pin(
            &format!("{pinned}{replacement}"),
            "Dockerfile",
            package,
            version,
            &mut errors,
        );
        assert!(
            !errors.is_empty(),
            "replacement install was accepted for {package}: {replacement:?}"
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
