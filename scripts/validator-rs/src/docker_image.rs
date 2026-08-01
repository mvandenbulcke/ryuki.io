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
use serde_yaml::Value as YamlValue;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const API_EXECUTION_MODE_ENV: &str = "RYUKI_API_EXECUTION_MODE=static-dry-run";
const PORTAL_EXECUTION_MODE_ENV: &str = "RYUKI_PORTAL_EXECUTION_MODE=static-dry-run";
const PORTAL_RUNTIME_STAGE: &str = "runtime";
const PORTAL_BUILD_STAGE: &str = "build";
const PORTAL_RUNTIME_IMAGE: &str =
    "debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818";
const PORTAL_RUNTIME_WORKDIR: &str = "/app";
const PORTAL_RUNTIME_USER: &str = "10001:10001";
const PORTAL_RUNTIME_PORT: &str = "8080";
const PORTAL_RUNTIME_BINARY: &str = "/app/ryuki-portal-ui";
const PORTAL_RUNTIME_BINARY_COPY: &str = "COPY --from=build --chown=10001:10001 /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui";
const PORTAL_RUNTIME_SITE_COPY: &str =
    "COPY --from=build --chown=10001:10001 /app/target/site /app/site";
const PORTAL_RUNTIME_ENVIRONMENT: &[(&str, &str)] = &[
    ("LEPTOS_SITE_ROOT", "/app/site"),
    ("LEPTOS_SITE_ADDR", "0.0.0.0:8080"),
    ("RYUKI_PORTAL_PUBLIC_ORIGIN", "http://127.0.0.1:8080"),
    ("RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK", "true"),
    ("RYUKI_PORTAL_EXECUTION_MODE", "static-dry-run"),
];
const PORTAL_DOCKERFILE_PATH: &str = "portal/portal-ui/Dockerfile";
const RELEASE_WORKFLOW_PATH: &str = ".github/workflows/release.yml";
const RELEASE_RENDER_SCRIPT_PATH: &str = "scripts/release/render-kubernetes-images-v1.sh";
const RELEASE_RENDER_PATH: &str = "${{ runner.temp }}/ryuki-release-kubernetes.yaml";
const RELEASE_RENDER_COMMAND: &str = "bash scripts/release/render-kubernetes-images-v1.sh --root . --output \"${RENDER_PATH}\" --api-repository \"${API_REPOSITORY}\" --api-digest \"${API_DIGEST}\" --portal-repository \"${PORTAL_REPOSITORY}\" --portal-digest \"${PORTAL_DIGEST}\"";
const RELEASE_RENDER_VALIDATOR_COMMAND: &str = "cargo run --locked --manifest-path scripts/validator-rs/Cargo.toml -- validate-release-image-render kubernetes-manifest --render \"${RENDER_PATH}\" --api-digest \"${API_DIGEST}\" --portal-digest \"${PORTAL_DIGEST}\"";
const RELEASE_RENDER_HANDOFF_COMMAND: &str = r#"set -euo pipefail
render_bytes="$(LC_ALL=C wc -c < "${RENDER_PATH}" | tr -d '[:space:]')"
[[ "${render_bytes}" =~ ^[0-9]+$ && "${render_bytes}" -le 131072 ]]
{
  printf 'content-b64='
  base64 -w 0 "${RENDER_PATH}"
  printf '\nsha256=%s\n' "$(sha256sum "${RENDER_PATH}" | awk '{print $1}')"
} >> "${GITHUB_OUTPUT}""#;
const CARGO_CHEF_VERSION: &str = "0.1.77";
const CARGO_LEPTOS_VERSION: &str = "0.3.7";
const BASE_CARGO_PATH: &str = "/usr/local/cargo/bin/cargo";
const BASE_RUSTUP_PATH: &str = "/usr/local/cargo/bin/rustup";
const PROTECTED_TOOL_ROOT: &str = "/opt/ryuki-tools";
const BUILD_USER: &str = "10001:10001";
const BUILD_ENVIRONMENT: &str = "HOME=/home/ryuki-build CARGO_HOME=/var/cache/ryuki-cargo RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:/var/cache/ryuki-cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const API_SOURCE_REVISION_ARG: &str = "RYUKI_SOURCE_REVISION";
const API_FINAL_BUILD_RUN: &str = concat!(
    "set -eu; ",
    "if [ -n \"${RYUKI_SOURCE_REVISION:-}\" ]; then ",
    "case \"${RYUKI_SOURCE_REVISION}\" in ",
    "*[!0-9a-f]*) ",
    "echo \"RYUKI_SOURCE_REVISION must be exactly 40 or 64 lowercase hexadecimal characters\" >&2; ",
    "exit 1; ",
    ";; ",
    "esac; ",
    "revision_length=\"${#RYUKI_SOURCE_REVISION}\"; ",
    "if [ \"${revision_length}\" -ne 40 ] && [ \"${revision_length}\" -ne 64 ]; then ",
    "echo \"RYUKI_SOURCE_REVISION must be exactly 40 or 64 lowercase hexadecimal characters\" >&2; ",
    "exit 1; ",
    "fi; ",
    "export RYUKI_SOURCE_REVISION; ",
    "else ",
    "unset RYUKI_SOURCE_REVISION; ",
    "fi; ",
    "/usr/local/cargo/bin/cargo build --locked --release -p ryuki-api",
);

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
    release_workflow: String,
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
    validate_portal_release_binding(&context.release_workflow, &mut errors);
    validate_release_render_binding(&context.release_workflow, &mut errors);
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
    validate_protected_cargo_tool_lifecycle(
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
    validate_protected_cargo_tool_lifecycle(
        content,
        label,
        "cargo-leptos",
        CARGO_LEPTOS_VERSION,
        &mut errors,
    );
    validate_published_portal_runtime(content, label, &mut errors);
    errors
}

/// Bind the pushed portal digest to the one stage whose runtime configuration
/// the Dockerfile validator proves. Without an explicit target, BuildKit
/// publishes the final stage, so appending a later stage can silently detach
/// the release image from the reviewed `runtime` stage.
fn validate_portal_release_binding(content: &str, errors: &mut Vec<String>) {
    if content.trim().is_empty() {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: file is missing or empty; cannot bind the published portal image to stage {PORTAL_RUNTIME_STAGE:?}"
        ));
        return;
    }

    let workflow: YamlValue = match serde_yaml::from_str(content) {
        Ok(workflow) => workflow,
        Err(error) => {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH}: invalid workflow YAML: {error}"
            ));
            return;
        }
    };
    let Some(steps) = workflow
        .get("jobs")
        .and_then(|jobs| jobs.get("images"))
        .and_then(|images| images.get("steps"))
        .and_then(YamlValue::as_sequence)
    else {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: images job must contain one id=portal build-and-push step"
        ));
        return;
    };

    let portal_publishers: Vec<&YamlValue> = steps
        .iter()
        .filter(|step| {
            let uses_build_push = step
                .get("uses")
                .and_then(YamlValue::as_str)
                .is_some_and(|uses| uses.starts_with("docker/build-push-action@"));
            let uses_portal_dockerfile = step
                .get("with")
                .and_then(|settings| settings.get("file"))
                .and_then(YamlValue::as_str)
                .is_some_and(|file| file.trim_start_matches("./") == PORTAL_DOCKERFILE_PATH);
            uses_build_push && uses_portal_dockerfile
        })
        .collect();
    if portal_publishers.len() != 1 {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: images job must contain exactly one docker/build-push-action publisher for {PORTAL_DOCKERFILE_PATH}; found {}",
            portal_publishers.len()
        ));
        return;
    }

    let step = portal_publishers[0];
    let has_portal_id = step.get("id").and_then(YamlValue::as_str) == Some("portal");
    let uses_build_push = step
        .get("uses")
        .and_then(YamlValue::as_str)
        .is_some_and(|uses| uses.starts_with("docker/build-push-action@"));
    let settings = step.get("with");
    let context = settings
        .and_then(|settings| settings.get("context"))
        .and_then(YamlValue::as_str);
    let dockerfile = settings
        .and_then(|settings| settings.get("file"))
        .and_then(YamlValue::as_str);
    let target = settings
        .and_then(|settings| settings.get("target"))
        .and_then(YamlValue::as_str);
    let pushes = settings
        .and_then(|settings| settings.get("push"))
        .and_then(YamlValue::as_bool)
        == Some(true);

    if !has_portal_id
        || !uses_build_push
        || context != Some(".")
        || dockerfile != Some(PORTAL_DOCKERFILE_PATH)
        || target != Some(PORTAL_RUNTIME_STAGE)
        || !pushes
    {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: id=portal must use docker/build-push-action with repository context '.', file {PORTAL_DOCKERFILE_PATH}, push true, and target {PORTAL_RUNTIME_STAGE}"
        ));
    }
}

/// Require the release render to consume the immutable outputs of both image
/// publishers, validate the exact rendered bytes, and bind only that validated
/// handoff into the GitHub release. Registry provenance and cluster admission
/// remain external evidence; this control closes the repository-local digest
/// substitution gap only.
fn validate_release_render_binding(content: &str, errors: &mut Vec<String>) {
    let workflow: YamlValue = match serde_yaml::from_str(content) {
        Ok(workflow) => workflow,
        Err(_) => return,
    };
    let Some(images) = workflow.get("jobs").and_then(|jobs| jobs.get("images")) else {
        return;
    };
    let Some(steps) = images.get("steps").and_then(YamlValue::as_sequence) else {
        return;
    };

    let step_positions = |id: &str| {
        steps
            .iter()
            .enumerate()
            .filter(|(_, step)| step.get("id").and_then(YamlValue::as_str) == Some(id))
            .collect::<Vec<_>>()
    };
    let api = step_positions("api");
    let portal = step_positions("portal");
    let render = step_positions("kubernetes-render");
    let validator = step_positions("kubernetes-render-validator");
    let handoff = step_positions("kubernetes-render-handoff");
    if api.len() != 1
        || portal.len() != 1
        || render.len() != 1
        || validator.len() != 1
        || handoff.len() != 1
    {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: images job must contain exactly one api publisher, portal publisher, kubernetes-render, kubernetes-render-validator, and kubernetes-render-handoff step"
        ));
        return;
    }
    let (api_index, _) = api[0];
    let (portal_index, _) = portal[0];
    let (render_index, render_step) = render[0];
    let (validator_index, validator_step) = validator[0];
    let (handoff_index, handoff_step) = handoff[0];
    if render_index <= api_index.max(portal_index)
        || validator_index != render_index + 1
        || handoff_index != validator_index + 1
    {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: release render, exact-digest validator, and sealed handoff must run consecutively in that order after both image publishers"
        ));
    }

    let render_env = [
        (
            "API_REPOSITORY",
            "${{ env.REGISTRY }}/${{ github.repository_owner }}/${{ env.API_IMAGE }}",
        ),
        ("API_DIGEST", "${{ steps.api.outputs.digest }}"),
        (
            "PORTAL_REPOSITORY",
            "${{ env.REGISTRY }}/${{ github.repository_owner }}/${{ env.PORTAL_IMAGE }}",
        ),
        ("PORTAL_DIGEST", "${{ steps.portal.outputs.digest }}"),
        ("RENDER_PATH", RELEASE_RENDER_PATH),
    ];
    if !yaml_mapping_has_exact_keys(render_step, &["name", "id", "env", "run"])
        || !step_has_exact_env(render_step, &render_env)
        || !step_run_equals(render_step, RELEASE_RENDER_COMMAND)
    {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: kubernetes-render must run {RELEASE_RENDER_SCRIPT_PATH} with the exact api/portal publisher outputs and fixed runner-temp destination"
        ));
    }

    let validator_env = [
        ("API_DIGEST", "${{ steps.api.outputs.digest }}"),
        ("PORTAL_DIGEST", "${{ steps.portal.outputs.digest }}"),
        ("RENDER_PATH", RELEASE_RENDER_PATH),
    ];
    if !yaml_mapping_has_exact_keys(validator_step, &["name", "id", "env", "run"])
        || !step_has_exact_env(validator_step, &validator_env)
        || !step_run_equals(validator_step, RELEASE_RENDER_VALIDATOR_COMMAND)
    {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: kubernetes-render-validator must validate the exact render against both immutable publisher digest outputs"
        ));
    }

    if !yaml_mapping_has_exact_keys(handoff_step, &["name", "id", "env", "run"])
        || !step_has_exact_env(handoff_step, &[("RENDER_PATH", RELEASE_RENDER_PATH)])
        || !step_run_equals(handoff_step, RELEASE_RENDER_HANDOFF_COMMAND)
    {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: kubernetes-render-handoff must size-bound, digest, and encode only the validated runner-temp render"
        ));
    }

    let image_outputs = images.get("outputs");
    if image_outputs
        .and_then(|outputs| outputs.get("kubernetes-render-b64"))
        .and_then(YamlValue::as_str)
        != Some("${{ steps.kubernetes-render-handoff.outputs.content-b64 }}")
        || image_outputs
            .and_then(|outputs| outputs.get("kubernetes-render-sha256"))
            .and_then(YamlValue::as_str)
            != Some("${{ steps.kubernetes-render-handoff.outputs.sha256 }}")
    {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: images job must export only the sealed Kubernetes render bytes and digest"
        ));
    }

    let release = workflow.get("jobs").and_then(|jobs| jobs.get("release"));
    let release_env = release
        .and_then(|job| job.get("steps"))
        .and_then(YamlValue::as_sequence)
        .and_then(|steps| {
            steps
                .iter()
                .find(|step| step.get("id").and_then(YamlValue::as_str) == Some("publish"))
        })
        .and_then(|step| step.get("env"));
    let release_run = release
        .and_then(|job| job.get("steps"))
        .and_then(YamlValue::as_sequence)
        .and_then(|steps| {
            steps
                .iter()
                .find(|step| step.get("id").and_then(YamlValue::as_str) == Some("publish"))
        })
        .and_then(|step| step.get("run"))
        .and_then(YamlValue::as_str)
        .unwrap_or_default();
    if release_env
        .and_then(|env| env.get("KUBERNETES_RENDER_B64"))
        .and_then(YamlValue::as_str)
        != Some("${{ needs.images.outputs.kubernetes-render-b64 }}")
        || release_env
            .and_then(|env| env.get("KUBERNETES_RENDER_SHA256"))
            .and_then(YamlValue::as_str)
            != Some("${{ needs.images.outputs.kubernetes-render-sha256 }}")
        || !release_run.contains("actual_render_sha256")
        || !release_run.contains("${KUBERNETES_RENDER_SHA256}")
        || !release_run.contains("ryuki-release-kubernetes.yaml#Ryuki release Kubernetes render")
    {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH}: release publication must verify and attach the sealed Kubernetes render handoff"
        ));
    }
}

fn step_has_exact_env(step: &YamlValue, expected: &[(&str, &str)]) -> bool {
    step.get("env")
        .and_then(YamlValue::as_mapping)
        .is_some_and(|env| {
            env.len() == expected.len()
                && expected.iter().all(|(key, value)| {
                    env.get(YamlValue::String((*key).to_string()))
                        .and_then(YamlValue::as_str)
                        == Some(*value)
                })
        })
}

fn yaml_mapping_has_exact_keys(value: &YamlValue, expected: &[&str]) -> bool {
    value.as_mapping().is_some_and(|mapping| {
        mapping.len() == expected.len()
            && expected
                .iter()
                .all(|key| mapping.contains_key(YamlValue::String((*key).to_string())))
    })
}

fn step_run_equals(step: &YamlValue, expected: &str) -> bool {
    step.get("run")
        .and_then(YamlValue::as_str)
        .is_some_and(|run| run.split_whitespace().eq(expected.split_whitespace()))
}

/// Prove the reviewed contract inside the exact stage selected by the release
/// workflow. Matching text in a builder, comment, or unselected later stage is
/// not evidence about the image whose digest is pushed.
fn validate_published_portal_runtime(content: &str, label: &str, errors: &mut Vec<String>) {
    #[derive(Default)]
    struct RuntimeState {
        base: Option<String>,
        workdir: Option<String>,
        environment: HashMap<String, String>,
        environment_invalid: bool,
        copies: Vec<String>,
        user: Option<String>,
        exposes: Vec<String>,
        command: Option<Vec<String>>,
        forbidden_control: Vec<String>,
        artifact_copy_seen: bool,
        mutation_after_artifact_copy: Vec<String>,
    }

    let mut in_runtime = false;
    let mut runtime_stage_count = 0usize;
    let mut build_stage_count = 0usize;
    let mut runtime = RuntimeState::default();

    for instruction in logical_dockerfile_instructions(content) {
        let Some(separator) = instruction.find(char::is_whitespace) else {
            continue;
        };
        let (keyword, arguments) = instruction.split_at(separator);
        let arguments = arguments.trim();

        if keyword.eq_ignore_ascii_case("FROM") {
            let parsed = docker_from_base_and_alias(arguments);
            let alias = parsed.as_ref().and_then(|(_, alias)| alias.as_deref());
            if alias == Some(PORTAL_BUILD_STAGE) {
                build_stage_count += 1;
            }
            in_runtime = alias == Some(PORTAL_RUNTIME_STAGE);
            if in_runtime {
                runtime_stage_count += 1;
                runtime = RuntimeState::default();
                runtime.base = parsed.map(|(base, _)| base);
            }
            continue;
        }

        if !in_runtime {
            continue;
        }

        if keyword.eq_ignore_ascii_case("WORKDIR") {
            runtime.workdir = Some(arguments.to_string());
        } else if keyword.eq_ignore_ascii_case("ENV") {
            let Some(assignments) = docker_env_assignments(arguments) else {
                runtime.environment_invalid = true;
                continue;
            };
            for (key, value) in assignments {
                runtime.environment.insert(key, value);
            }
        } else if keyword.eq_ignore_ascii_case("COPY") {
            let reviewed_copy = instruction == PORTAL_RUNTIME_BINARY_COPY
                || instruction == PORTAL_RUNTIME_SITE_COPY;
            if runtime.artifact_copy_seen && !reviewed_copy {
                runtime
                    .mutation_after_artifact_copy
                    .push(instruction.clone());
            }
            runtime.artifact_copy_seen = true;
            runtime.copies.push(instruction);
        } else if keyword.eq_ignore_ascii_case("USER") {
            runtime.user = Some(arguments.to_string());
        } else if keyword.eq_ignore_ascii_case("EXPOSE") {
            runtime.exposes.push(arguments.to_string());
        } else if keyword.eq_ignore_ascii_case("CMD") {
            runtime.command = docker_json_exec_arguments(arguments);
        } else if keyword.eq_ignore_ascii_case("RUN") || keyword.eq_ignore_ascii_case("ADD") {
            if runtime.artifact_copy_seen {
                runtime
                    .mutation_after_artifact_copy
                    .push(instruction.clone());
            }
            if keyword.eq_ignore_ascii_case("ADD") {
                runtime.forbidden_control.push("ADD".to_string());
            }
        } else if ["ENTRYPOINT", "VOLUME", "SHELL", "HEALTHCHECK"]
            .iter()
            .any(|forbidden| keyword.eq_ignore_ascii_case(forbidden))
        {
            runtime.forbidden_control.push(keyword.to_ascii_uppercase());
        }
    }

    if runtime_stage_count != 1 {
        errors.push(format!(
            "{label}: must declare exactly one stage named {PORTAL_RUNTIME_STAGE:?}; found {runtime_stage_count}"
        ));
        return;
    }
    if build_stage_count != 1 {
        errors.push(format!(
            "{label}: published stage {PORTAL_RUNTIME_STAGE:?} must copy from one unambiguous stage named {PORTAL_BUILD_STAGE:?}; found {build_stage_count}"
        ));
    }
    if runtime.base.as_deref() != Some(PORTAL_RUNTIME_IMAGE) {
        errors.push(format!(
            "{label}: published stage {PORTAL_RUNTIME_STAGE:?} must use exact reviewed base {PORTAL_RUNTIME_IMAGE}"
        ));
    }
    if runtime.workdir.as_deref() != Some(PORTAL_RUNTIME_WORKDIR) {
        errors.push(format!(
            "{label}: published stage {PORTAL_RUNTIME_STAGE:?} must end with WORKDIR {PORTAL_RUNTIME_WORKDIR}"
        ));
    }
    let environment_is_exact = !runtime.environment_invalid
        && runtime.environment.len() == PORTAL_RUNTIME_ENVIRONMENT.len()
        && PORTAL_RUNTIME_ENVIRONMENT
            .iter()
            .all(|(key, value)| runtime.environment.get(*key).map(String::as_str) == Some(*value));
    if !environment_is_exact {
        errors.push(format!(
            "{label}: published stage {PORTAL_RUNTIME_STAGE:?} must declare only the exact reviewed environment, including {PORTAL_EXECUTION_MODE_ENV}, LEPTOS_SITE_ROOT=/app/site, and LEPTOS_SITE_ADDR=0.0.0.0:8080"
        ));
    }
    let copies_are_exact = runtime.copies.len() == 2
        && runtime.copies[0] == PORTAL_RUNTIME_BINARY_COPY
        && runtime.copies[1] == PORTAL_RUNTIME_SITE_COPY;
    if !copies_are_exact {
        errors.push(format!(
            "{label}: published stage {PORTAL_RUNTIME_STAGE:?} must contain only the exact reviewed binary and site COPY instructions from the unique {PORTAL_BUILD_STAGE:?} stage"
        ));
    }
    if !runtime.mutation_after_artifact_copy.is_empty() {
        errors.push(format!(
            "{label}: published stage {PORTAL_RUNTIME_STAGE:?} must not mutate runtime artifacts after their reviewed COPY instructions; found {:?}",
            runtime.mutation_after_artifact_copy
        ));
    }
    if runtime.user.as_deref() != Some(PORTAL_RUNTIME_USER) {
        errors.push(format!(
            "{label}: published stage {PORTAL_RUNTIME_STAGE:?} must end with USER {PORTAL_RUNTIME_USER}"
        ));
    }
    let exposes_only_port = runtime.exposes.len() == 1
        && runtime.exposes.first().map(String::as_str) == Some(PORTAL_RUNTIME_PORT);
    if !exposes_only_port {
        errors.push(format!(
            "{label}: published stage {PORTAL_RUNTIME_STAGE:?} must expose only port {PORTAL_RUNTIME_PORT}"
        ));
    }
    let command_is_exact = runtime
        .command
        .as_deref()
        .is_some_and(|command| command.len() == 1 && command[0] == PORTAL_RUNTIME_BINARY);
    if !command_is_exact {
        errors.push(format!(
            "{label}: published stage {PORTAL_RUNTIME_STAGE:?} must end with exact JSON CMD [\"{PORTAL_RUNTIME_BINARY}\"]"
        ));
    }
    if !runtime.forbidden_control.is_empty() {
        errors.push(format!(
            "{label}: published stage {PORTAL_RUNTIME_STAGE:?} must not add control instructions that can replace or mask the reviewed runtime contract; found {:?}",
            runtime.forbidden_control
        ));
    }
}

/// Parse the two Docker ENV forms used by the reviewed contract. Quoted or
/// interpolated values are deliberately rejected because the release
/// invariant requires literal, reviewable values.
fn docker_env_assignments(arguments: &str) -> Option<Vec<(String, String)>> {
    let fields: Vec<&str> = arguments.split_whitespace().collect();
    let first = fields.first()?;
    if first.contains('=') {
        return fields
            .into_iter()
            .map(|field| {
                let (key, value) = field.split_once('=')?;
                (!key.is_empty() && docker_env_value_is_literal(value))
                    .then(|| (key.to_string(), value.to_string()))
            })
            .collect();
    }

    let (key, value) = arguments.split_once(char::is_whitespace)?;
    let value = value.trim();
    (!key.is_empty() && !value.is_empty() && docker_env_value_is_literal(value))
        .then(|| vec![(key.to_string(), value.to_string())])
}

fn docker_env_value_is_literal(value: &str) -> bool {
    !value
        .chars()
        .any(|character| matches!(character, '$' | '"' | '\'' | '\\'))
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

#[derive(Clone)]
struct ProtectedToolStage {
    available: bool,
    preinstall_clean: bool,
    portal_prerequisite_seen: bool,
    external_rust_base: bool,
    setup_step: usize,
    environment_locked: bool,
    workdir_locked: bool,
    non_root: bool,
    tainted: bool,
    stage_protected_use_seen: bool,
    source_revision_arg_declared: bool,
    final_build_seen: bool,
    workdir: String,
}

impl Default for ProtectedToolStage {
    fn default() -> Self {
        Self {
            available: false,
            preinstall_clean: true,
            portal_prerequisite_seen: false,
            external_rust_base: false,
            setup_step: 0,
            environment_locked: false,
            workdir_locked: false,
            non_root: false,
            tainted: false,
            stage_protected_use_seen: false,
            source_revision_arg_declared: false,
            final_build_seen: false,
            workdir: "/".to_string(),
        }
    }
}

impl ProtectedToolStage {
    fn ready(&self, setup_steps: usize) -> bool {
        self.available
            && self.setup_step == setup_steps
            && self.environment_locked
            && self.workdir_locked
            && self.non_root
            && !self.tainted
            && self.workdir == "/app"
    }

    fn reset_stage_local_state(&mut self) {
        self.stage_protected_use_seen = false;
        self.source_revision_arg_declared = false;
        self.final_build_seen = false;
    }
}

/// Prove a finite, least-privilege install-to-use lifecycle for build tools.
///
/// The official Rust image exposes root-owned toolchains that are writable
/// while the image still runs as root. Trying to enumerate every shell,
/// interpreter, or file-copy primitive that could replace a protected binary
/// is not a complete defense. This contract therefore admits only a canonical
/// JSON-exec install and root-hardening sequence, permanently drops to an
/// unprivileged builder, and keeps every protected use on an immutable absolute
/// path. Descendant stages inherit both the proof state and any taint.
fn validate_protected_cargo_tool_lifecycle(
    content: &str,
    label: &str,
    package: &str,
    version: &str,
    errors: &mut Vec<String>,
) {
    if dockerfile_uses_syntax_frontend_directive(content) {
        errors.push(format!(
            "{label}: protected tool lifecycle does not allow a custom Dockerfile syntax frontend"
        ));
        return;
    }
    if dockerfile_uses_nondefault_escape_directive(content) {
        errors.push(format!(
            "{label}: protected tool lifecycle requires the default Dockerfile escape character"
        ));
        return;
    }
    if dockerfile_uses_heredoc_instruction_framing(content) {
        errors.push(format!(
            "{label}: protected tool lifecycle does not allow Docker heredoc instruction framing"
        ));
        return;
    }

    let tool_root = format!("{PROTECTED_TOOL_ROOT}/{package}-{version}");
    let tool_path = format!("{tool_root}/bin/{package}");
    let canonical_install = vec![
        BASE_CARGO_PATH.to_string(),
        "install".to_string(),
        package.to_string(),
        "--version".to_string(),
        version.to_string(),
        "--locked".to_string(),
        "--root".to_string(),
        tool_root.clone(),
    ];
    let expected_uses = canonical_protected_tool_uses(package, &tool_path);
    let expected_use_stages: &[&str] = match package {
        "cargo-chef" => &["planner", "build"],
        "cargo-leptos" => &["build"],
        _ => &[],
    };
    let install_stage = if package == "cargo-chef" {
        "chef"
    } else {
        "build"
    };
    let root_setup = canonical_protected_root_setup(&tool_root);
    let portal_prerequisite = vec![
        BASE_RUSTUP_PATH.to_string(),
        "target".to_string(),
        "add".to_string(),
        "wasm32-unknown-unknown".to_string(),
    ];

    let mut stages: HashMap<String, ProtectedToolStage> = HashMap::new();
    let mut aliases = HashSet::new();
    let mut current_name: Option<String> = None;
    let mut current = ProtectedToolStage::default();
    let mut anonymous_stage = 0usize;
    let mut install_count = 0usize;
    let mut prerequisite_count = 0usize;
    let mut uses_seen = 0usize;
    let mut api_final_build_count = 0usize;

    for instruction in logical_dockerfile_instructions(content) {
        let Some(separator) = instruction.find(char::is_whitespace) else {
            continue;
        };
        let (keyword, arguments) = instruction.split_at(separator);
        let arguments = arguments.trim();

        if keyword.eq_ignore_ascii_case("FROM") {
            if let Some(name) = current_name.take() {
                stages.insert(name, current.clone());
            }
            let Some((base, alias)) = docker_from_base_and_alias(arguments) else {
                errors.push(format!(
                    "{label}: malformed FROM instruction in protected tool lifecycle"
                ));
                current = ProtectedToolStage::default();
                continue;
            };
            let inherited = stages.get(&base.to_ascii_lowercase()).cloned();
            current = inherited.clone().unwrap_or_default();
            current.external_rust_base =
                inherited.is_none() && base.starts_with("rust:") && base.contains("@sha256:");
            if inherited.is_some() {
                current.reset_stage_local_state();
            }
            let (name, named_stage) = alias.map_or_else(
                || {
                    anonymous_stage += 1;
                    (format!("\0anonymous-stage-{anonymous_stage}"), false)
                },
                |alias| (alias, true),
            );
            let name = name.to_ascii_lowercase();
            if named_stage && !aliases.insert(name.clone()) {
                errors.push(format!(
                    "{label}: duplicate stage alias {name} is not allowed in the protected tool lifecycle"
                ));
                current.tainted = true;
            }
            current_name = Some(name);
            continue;
        }

        if current_name.is_none() {
            continue;
        }

        if keyword.eq_ignore_ascii_case("RUN") {
            let direct_json_exec = arguments.starts_with('[');
            let json_arguments = direct_json_exec
                .then(|| docker_json_exec_arguments(arguments))
                .flatten();
            let is_install =
                direct_json_exec && json_arguments.as_ref() == Some(&canonical_install);

            if is_install {
                install_count += 1;
                let prerequisite_ready = package != "cargo-leptos"
                    || (current.portal_prerequisite_seen && prerequisite_count == 1);
                if install_count != 1
                    || current.available
                    || !current.preinstall_clean
                    || !prerequisite_ready
                    || !current.external_rust_base
                    || current_name.as_deref() != Some(install_stage)
                {
                    errors.push(format!(
                        "{label}: {package} must be installed exactly once by canonical JSON exec in the pinned rust {install_stage} stage before any untrusted action"
                    ));
                    current.tainted = true;
                }
                current.available = true;
                current.setup_step = 0;
                continue;
            }

            let is_portal_prerequisite = package == "cargo-leptos"
                && !current.available
                && current.preinstall_clean
                && current.external_rust_base
                && current_name.as_deref() == Some(install_stage)
                && direct_json_exec
                && json_arguments.as_ref() == Some(&portal_prerequisite);
            if is_portal_prerequisite {
                prerequisite_count += 1;
                if prerequisite_count != 1 || current.portal_prerequisite_seen {
                    errors.push(format!(
                        "{label}: the canonical wasm target prerequisite must run exactly once before cargo-leptos installation"
                    ));
                    current.tainted = true;
                }
                current.portal_prerequisite_seen = true;
                continue;
            }

            if !current.available {
                current.preinstall_clean = false;
                continue;
            }

            if current.setup_step < root_setup.len() {
                if !direct_json_exec
                    || json_arguments.as_ref() != root_setup.get(current.setup_step)
                {
                    errors.push(format!(
                        "{label}: protected {package} root setup step {} must be the next exact JSON-exec action after installation",
                        current.setup_step + 1
                    ));
                    current.tainted = true;
                } else {
                    current.setup_step += 1;
                }
                continue;
            }

            let invokes_protected_path = json_arguments
                .as_ref()
                .and_then(|arguments| arguments.first())
                == Some(&tool_path);
            if invokes_protected_path {
                let expected = expected_uses.get(uses_seen);
                let expected_stage = expected_use_stages.get(uses_seen).copied();
                if !direct_json_exec
                    || !current.ready(root_setup.len())
                    || current.stage_protected_use_seen
                    || expected != json_arguments.as_ref()
                    || expected_stage != current_name.as_deref()
                {
                    errors.push(format!(
                        "{label}: protected {package} use must be the canonical JSON-exec action in its required non-root stage inheriting an untainted immutable install"
                    ));
                    current.tainted = true;
                } else {
                    current.stage_protected_use_seen = true;
                    uses_seen += 1;
                }
                continue;
            }

            let is_api_final_build = package == "cargo-chef"
                && current_name.as_deref() == Some("build")
                && current.stage_protected_use_seen
                && current.source_revision_arg_declared
                && !current.final_build_seen
                && arguments == API_FINAL_BUILD_RUN;
            if is_api_final_build && current.ready(root_setup.len()) {
                current.final_build_seen = true;
                api_final_build_count += 1;
                continue;
            }

            errors.push(format!(
                "{label}: arbitrary RUN instructions are forbidden once protected {package} installation begins"
            ));
            current.tainted = true;
            continue;
        }

        if !current.available {
            current.preinstall_clean = false;
            continue;
        }

        let stage_is_closed = current.final_build_seen
            || (current.stage_protected_use_seen
                && (package == "cargo-leptos" || current_name.as_deref() == Some("planner")));
        if stage_is_closed {
            errors.push(format!(
                "{label}: no instruction is allowed after the final protected {package} action in this build stage"
            ));
            current.tainted = true;
            continue;
        }

        if keyword.eq_ignore_ascii_case("ENV") {
            if current.setup_step == root_setup.len()
                && !current.environment_locked
                && !current.workdir_locked
                && !current.non_root
                && arguments == BUILD_ENVIRONMENT
            {
                current.environment_locked = true;
            } else {
                errors.push(format!(
                    "{label}: protected {package} stages permit only the canonical locked HOME/CARGO_HOME/RUSTUP_HOME/PATH environment before privilege drop"
                ));
                current.tainted = true;
            }
            continue;
        }

        if keyword.eq_ignore_ascii_case("WORKDIR") {
            if arguments == "/app"
                && current.environment_locked
                && (!current.workdir_locked || current.non_root)
            {
                current.workdir = "/app".to_string();
                current.workdir_locked = true;
            } else {
                errors.push(format!(
                    "{label}: protected {package} stages must use the literal WORKDIR /app after locking the builder environment"
                ));
                current.tainted = true;
            }
            continue;
        }

        if keyword.eq_ignore_ascii_case("USER") {
            if arguments == BUILD_USER
                && current.setup_step == root_setup.len()
                && current.environment_locked
                && current.workdir_locked
                && !current.non_root
            {
                current.non_root = true;
            } else {
                errors.push(format!(
                    "{label}: protected {package} stages must drop permanently to USER {BUILD_USER} after root setup"
                ));
                current.tainted = true;
            }
            continue;
        }

        if keyword.eq_ignore_ascii_case("COPY") {
            let valid_copy = docker_link_copy_destination(arguments)
                .and_then(|destination| normalize_docker_path(&current.workdir, &destination))
                .is_some_and(|destination| {
                    current.ready(root_setup.len())
                        && (destination == "/app" || destination.starts_with("/app/"))
                        && !paths_overlap(&destination, &tool_root)
                        && !paths_overlap(&destination, "/usr/local/cargo")
                });
            if !valid_copy {
                errors.push(format!(
                    "{label}: protected {package} COPY must use literal --link --chown={BUILD_USER} shell syntax after privilege drop and a static /app destination"
                ));
                current.tainted = true;
            }
            continue;
        }

        if keyword.eq_ignore_ascii_case("ARG")
            && package == "cargo-chef"
            && current_name.as_deref() == Some("build")
            && current.ready(root_setup.len())
            && current.stage_protected_use_seen
            && !current.source_revision_arg_declared
            && !current.final_build_seen
            && arguments == API_SOURCE_REVISION_ARG
        {
            current.source_revision_arg_declared = true;
            continue;
        }

        if keyword.eq_ignore_ascii_case("ADD") {
            errors.push(format!(
                "{label}: ADD is forbidden in protected {package} stages; use canonical COPY --link --chown={BUILD_USER} under /app"
            ));
        } else {
            errors.push(format!(
                "{label}: {keyword} is not allowed after protected {package} installation"
            ));
        }
        current.tainted = true;
    }

    if let Some(name) = current_name {
        stages.insert(name, current);
    }
    if install_count != 1 {
        errors.push(format!(
            "{label}: expected one canonical JSON-exec {package} install rooted at {tool_root}; found {install_count}"
        ));
    }
    if package == "cargo-leptos" && prerequisite_count != 1 {
        errors.push(format!(
            "{label}: expected one canonical JSON-exec wasm32-unknown-unknown rustup prerequisite; found {prerequisite_count}"
        ));
    }
    if package == "cargo-chef" && api_final_build_count != 1 {
        errors.push(format!(
            "{label}: expected one canonical non-root absolute-path ryuki-api build; found {api_final_build_count}"
        ));
    }
    if uses_seen != expected_uses.len() {
        errors.push(format!(
            "{label}: expected {} canonical absolute-path {package} uses; found {uses_seen}",
            expected_uses.len()
        ));
    }
}

fn canonical_protected_root_setup(tool_root: &str) -> Vec<Vec<String>> {
    vec![
        vec![
            "/usr/sbin/groupadd".to_string(),
            "--system".to_string(),
            "--gid".to_string(),
            "10001".to_string(),
            "ryuki-build".to_string(),
        ],
        vec![
            "/usr/sbin/useradd".to_string(),
            "--system".to_string(),
            "--uid".to_string(),
            "10001".to_string(),
            "--gid".to_string(),
            "ryuki-build".to_string(),
            "--create-home".to_string(),
            "--home-dir".to_string(),
            "/home/ryuki-build".to_string(),
            "--shell".to_string(),
            "/usr/sbin/nologin".to_string(),
            "ryuki-build".to_string(),
        ],
        vec![
            "/usr/bin/install".to_string(),
            "-d".to_string(),
            "-o".to_string(),
            "10001".to_string(),
            "-g".to_string(),
            "10001".to_string(),
            "-m".to_string(),
            "0755".to_string(),
            "/app".to_string(),
            "/var/cache/ryuki-cargo".to_string(),
        ],
        vec![
            "/usr/bin/chown".to_string(),
            "-R".to_string(),
            "0:0".to_string(),
            tool_root.to_string(),
            "/usr/local/cargo".to_string(),
            "/usr/local/rustup".to_string(),
        ],
        vec![
            "/usr/bin/chmod".to_string(),
            "-R".to_string(),
            "a-w".to_string(),
            tool_root.to_string(),
            "/usr/local/cargo".to_string(),
            "/usr/local/rustup".to_string(),
        ],
    ]
}

fn canonical_protected_tool_uses(package: &str, tool_path: &str) -> Vec<Vec<String>> {
    match package {
        "cargo-chef" => vec![
            vec![
                tool_path.to_string(),
                "chef".to_string(),
                "prepare".to_string(),
                "--recipe-path".to_string(),
                "recipe.json".to_string(),
            ],
            vec![
                tool_path.to_string(),
                "chef".to_string(),
                "cook".to_string(),
                "--locked".to_string(),
                "--release".to_string(),
                "--recipe-path".to_string(),
                "recipe.json".to_string(),
                "--package".to_string(),
                "ryuki-api".to_string(),
            ],
        ],
        "cargo-leptos" => vec![vec![
            tool_path.to_string(),
            "build".to_string(),
            "--release".to_string(),
            "-p".to_string(),
            "ryuki-portal-ui".to_string(),
        ]],
        _ => Vec::new(),
    }
}

fn docker_from_base_and_alias(arguments: &str) -> Option<(String, Option<String>)> {
    let fields: Vec<&str> = arguments.split_whitespace().collect();
    let base_index = fields.iter().position(|field| !field.starts_with("--"))?;
    let base = fields.get(base_index)?.to_ascii_lowercase();
    let alias = fields
        .get(base_index + 1)
        .filter(|field| field.eq_ignore_ascii_case("AS"))
        .and_then(|_| fields.get(base_index + 2))
        .map(|alias| alias.to_ascii_lowercase());
    Some((base, alias))
}

fn docker_link_copy_destination(arguments: &str) -> Option<String> {
    let arguments = arguments.trim();
    if arguments
        .chars()
        .any(|character| matches!(character, '"' | '\'' | '[' | ']' | '\\'))
    {
        return None;
    }
    let mut fields = arguments.split_whitespace().peekable();
    let mut has_link = false;
    let mut has_chown = false;
    let mut has_from = false;
    while fields.peek().is_some_and(|field| field.starts_with("--")) {
        let option = fields.next()?;
        if option == "--link" {
            if has_link {
                return None;
            }
            has_link = true;
            continue;
        }
        let (name, value) = option.split_once('=')?;
        let allowed = match name {
            "--from" => {
                let valid = !has_from
                    && !value.is_empty()
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    });
                has_from = true;
                valid
            }
            "--chown" => {
                let valid = !has_chown && value == BUILD_USER;
                has_chown = true;
                valid
            }
            _ => false,
        };
        if !allowed {
            return None;
        }
    }
    let paths: Vec<&str> = fields.collect();
    (has_link && has_chown && paths.len() >= 2).then(|| paths[paths.len() - 1].to_string())
}

fn normalize_docker_path(workdir: &str, path: &str) -> Option<String> {
    if path.is_empty()
        || path.contains('$')
        || path.contains('*')
        || path.contains('?')
        || path.contains('[')
        || path.split('/').any(|component| component == "..")
    {
        return None;
    }
    let combined = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{path}", workdir.trim_end_matches('/'))
    };
    let mut components = Vec::new();
    for component in combined.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            component => components.push(component),
        }
    }
    Some(format!("/{}", components.join("/")))
}

fn paths_overlap(left: &str, right: &str) -> bool {
    left == "/"
        || right == "/"
        || left == right
        || left.starts_with(&format!("{right}/"))
        || right.starts_with(&format!("{left}/"))
}

fn dockerfile_uses_nondefault_escape_directive(content: &str) -> bool {
    for raw in content.lines() {
        // Docker accepts a UTF-8 BOM at the beginning of a Dockerfile. Strip it
        // before interpreting parser directives so a BOM cannot make Docker use
        // backtick continuations while this validator still assumes backslash.
        let line = raw.strip_prefix('\u{feff}').unwrap_or(raw).trim();
        if line.is_empty() {
            continue;
        }
        let Some(comment) = line.strip_prefix('#') else {
            break;
        };
        let Some((name, value)) = comment.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("escape") && value.trim() != "\\" {
            return true;
        }
    }
    false
}

fn dockerfile_uses_syntax_frontend_directive(content: &str) -> bool {
    for raw in content.lines() {
        let line = raw.strip_prefix('\u{feff}').unwrap_or(raw).trim();
        if line.is_empty() {
            continue;
        }
        let Some(comment) = line.strip_prefix('#') else {
            break;
        };
        let Some((name, _)) = comment.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("syntax") {
            return true;
        }
    }
    false
}

/// Heredoc bodies are Dockerfile payload, not Dockerfile instructions. The
/// lifecycle validator deliberately parses a small closed instruction grammar;
/// allowing heredocs would let payload lines impersonate reviewed FROM/RUN
/// stages and satisfy that grammar without Docker executing those instructions.
///
/// The default escape character can also splice the two `<` bytes across a
/// physical line boundary (`<\\\n<`). Detect both forms before constructing any
/// logical instructions. Protected checked-in Dockerfiles do not require shell
/// redirection, so this ambiguity is rejected rather than reimplemented.
fn dockerfile_uses_heredoc_instruction_framing(content: &str) -> bool {
    content.lines().any(|raw| {
        let line = raw.strip_prefix('\u{feff}').unwrap_or(raw).trim();
        !line.is_empty()
            && !line.starts_with('#')
            && (line.contains("<<") || line.trim_end().ends_with("<\\"))
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
fn docker_json_exec_arguments(run: &str) -> Option<Vec<String>> {
    let run = run.trim();
    if run.starts_with('[') {
        return serde_json::from_str::<Vec<String>>(run).ok();
    }
    None
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
            "COPY --link --chown=10001:10001 Cargo.toml Cargo.lock ./\n",
            "COPY --link --chown=10001:10001 sources/ sources/\n",
            "COPY --link --chown=10001:10001 portal/ portal/\n",
            "COPY --link --chown=10001:10001 scripts/validator-rs/ scripts/validator-rs/\n",
            "COPY --link --chown=10001:10001 tests/ tests/\n",
        )
    }

    fn canonical_root_setup_fixture(package: &str, version: &str) -> String {
        let tool_root = format!("{PROTECTED_TOOL_ROOT}/{package}-{version}");
        let runs = canonical_protected_root_setup(&tool_root)
            .into_iter()
            .map(|arguments| {
                format!(
                    "RUN {}\n",
                    serde_json::to_string(&arguments).expect("serialize root setup fixture")
                )
            })
            .collect::<String>();
        format!("{runs}ENV {BUILD_ENVIRONMENT}\nWORKDIR /app\nUSER {BUILD_USER}\n")
    }

    fn portal_release_workflow(target: Option<&str>) -> String {
        let target = target
            .map(|target| format!("          target: {target}\n"))
            .unwrap_or_default();
        format!(
            "jobs:\n  images:\n    steps:\n      - id: portal\n        uses: docker/build-push-action@0123456789012345678901234567890123456789\n        with:\n          context: .\n          file: portal/portal-ui/Dockerfile\n{target}          push: true\n"
        )
    }

    fn canonical_portal_runtime_stage() -> String {
        format!(
            "FROM {image} AS {stage}\nWORKDIR {workdir}\nENV LEPTOS_SITE_ROOT=/app/site LEPTOS_SITE_ADDR=0.0.0.0:8080 RYUKI_PORTAL_PUBLIC_ORIGIN=http://127.0.0.1:8080 RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK=true RYUKI_PORTAL_EXECUTION_MODE=static-dry-run\n{binary_copy}\n{site_copy}\nUSER {user}\nEXPOSE {port}\nCMD [\"{binary}\"]\n",
            image = PORTAL_RUNTIME_IMAGE,
            stage = PORTAL_RUNTIME_STAGE,
            workdir = PORTAL_RUNTIME_WORKDIR,
            binary_copy = PORTAL_RUNTIME_BINARY_COPY,
            site_copy = PORTAL_RUNTIME_SITE_COPY,
            user = PORTAL_RUNTIME_USER,
            port = PORTAL_RUNTIME_PORT,
            binary = PORTAL_RUNTIME_BINARY,
        )
    }

    fn canonical_portal_runtime_with_builder() -> String {
        format!(
            "FROM rust:1.96-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS build\n{}",
            canonical_portal_runtime_stage()
        )
    }

    fn canonical_lifecycle_fixture(
        package: &str,
        version: &str,
        intervening: &str,
        install_run_prefix: &str,
        use_run_prefix: &str,
    ) -> String {
        let tool_root = format!("{PROTECTED_TOOL_ROOT}/{package}-{version}");
        let tool_path = format!("{tool_root}/bin/{package}");
        let install = serde_json::to_string(&vec![
            BASE_CARGO_PATH.to_string(),
            "install".to_string(),
            package.to_string(),
            "--version".to_string(),
            version.to_string(),
            "--locked".to_string(),
            "--root".to_string(),
            tool_root,
        ])
        .expect("serialize canonical install fixture");
        let uses = canonical_protected_tool_uses(package, &tool_path)
            .into_iter()
            .map(|arguments| {
                serde_json::to_string(&arguments).expect("serialize canonical use fixture")
            })
            .collect::<Vec<_>>();
        let root_setup = canonical_root_setup_fixture(package, version);

        if package == "cargo-chef" {
            format!(
                "FROM rust:1.96-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS chef\n{install_run_prefix}{install}\n{root_setup}{intervening}FROM chef AS planner\n{use_run_prefix}{}\nFROM chef AS build\n{use_run_prefix}{}\nARG {API_SOURCE_REVISION_ARG}\nRUN {API_FINAL_BUILD_RUN}\n",
                uses[0], uses[1],
            )
        } else {
            let prerequisite = serde_json::to_string(&vec![
                BASE_RUSTUP_PATH.to_string(),
                "target".to_string(),
                "add".to_string(),
                "wasm32-unknown-unknown".to_string(),
            ])
            .expect("serialize portal prerequisite fixture");
            format!(
                "FROM rust:1.96-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS build\nRUN {prerequisite}\n{install_run_prefix}{install}\n{root_setup}{intervening}{use_run_prefix}{}\n",
                uses[0]
            )
        }
    }

    fn canonical_install_arguments(package: &str, version: &str) -> Vec<String> {
        vec![
            BASE_CARGO_PATH.to_string(),
            "install".to_string(),
            package.to_string(),
            "--version".to_string(),
            version.to_string(),
            "--locked".to_string(),
            "--root".to_string(),
            format!("{PROTECTED_TOOL_ROOT}/{package}-{version}"),
        ]
    }

    fn replace_run_arguments(
        dockerfile: &str,
        original: &[String],
        replacement: &[String],
    ) -> String {
        let original = format!(
            "RUN {}\n",
            serde_json::to_string(original).expect("serialize original RUN fixture")
        );
        let replacement = format!(
            "RUN {}\n",
            serde_json::to_string(replacement).expect("serialize replacement RUN fixture")
        );
        let replaced = dockerfile.replacen(&original, &replacement, 1);
        assert_ne!(
            replaced, dockerfile,
            "canonical RUN fixture to replace was not present"
        );
        replaced
    }

    fn insert_after_run_arguments(dockerfile: &str, original: &[String], inserted: &str) -> String {
        let original = format!(
            "RUN {}\n",
            serde_json::to_string(original).expect("serialize insertion anchor fixture")
        );
        let replacement = format!("{original}{inserted}");
        let replaced = dockerfile.replacen(&original, &replacement, 1);
        assert_ne!(
            replaced, dockerfile,
            "canonical RUN fixture insertion anchor was not present"
        );
        replaced
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
        let setup = canonical_root_setup_fixture("cargo-chef", CARGO_CHEF_VERSION);
        let dockerfile = format!(
            "FROM rust:1.88-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS chef\nRUN [\"/usr/local/cargo/bin/cargo\", \"install\", \"cargo-chef\", \"--version\", \"0.1.77\", \"--locked\", \"--root\", \"/opt/ryuki-tools/cargo-chef-0.1.77\"]\n{setup}FROM chef AS planner\n{}COPY --link --chown=10001:10001 migrations/ migrations/\nRUN [\"/opt/ryuki-tools/cargo-chef-0.1.77/bin/cargo-chef\", \"chef\", \"prepare\", \"--recipe-path\", \"recipe.json\"]\nFROM chef AS build\nCOPY --link --chown=10001:10001 --from=planner /app/recipe.json recipe.json\nRUN [\"/opt/ryuki-tools/cargo-chef-0.1.77/bin/cargo-chef\", \"chef\", \"cook\", \"--locked\", \"--release\", \"--recipe-path\", \"recipe.json\", \"--package\", \"ryuki-api\"]\n{}COPY --link --chown=10001:10001 migrations/ migrations/\nARG {API_SOURCE_REVISION_ARG}\nRUN {API_FINAL_BUILD_RUN}\nFROM debian:bookworm-slim@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb AS runtime\nENV RYUKI_API_EXECUTION_MODE=static-dry-run\nCOPY --from=build /app/target/release/ryuki-api /app/ryuki-api\n",
            full_copy_set(),
            full_copy_set(),
        );
        let errors = validate_api_dockerfile(&dockerfile, &members());
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn portal_dockerfile_requires_dry_run_env() {
        let dockerfile = format!(
            "FROM rust:1.88-bookworm AS build\n{}RUN cargo leptos build --release -p ryuki-portal-ui\nFROM debian:bookworm-slim AS runtime\n",
            full_copy_set()
        );
        let errors = validate_portal_dockerfile(&dockerfile, &members());
        assert!(
            errors.iter().any(|e| e.contains(PORTAL_EXECUTION_MODE_ENV)),
            "expected execution-mode env error, got: {errors:?}"
        );
    }

    #[test]
    fn portal_runtime_rejects_execution_mode_decoy_in_build_stage() {
        let dockerfile = concat!(
            "FROM rust:1.96-bookworm AS build\n",
            "ENV RYUKI_PORTAL_EXECUTION_MODE=static-dry-run\n",
            "FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime\n",
            "CMD [\"/app/ryuki-portal-ui\"]\n",
        );
        let mut errors = Vec::new();
        validate_published_portal_runtime(dockerfile, "portal-ui Dockerfile", &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains(PORTAL_EXECUTION_MODE_ENV)),
            "a builder-stage text decoy must not satisfy runtime policy: {errors:?}"
        );
    }

    #[test]
    fn portal_runtime_rejects_later_execution_mode_override_in_same_stage() {
        let dockerfile = format!(
            "{}ENV RYUKI_PORTAL_EXECUTION_MODE=live\n",
            canonical_portal_runtime_with_builder()
        );
        let mut errors = Vec::new();
        validate_published_portal_runtime(&dockerfile, "portal-ui Dockerfile", &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains(PORTAL_EXECUTION_MODE_ENV)),
            "the final effective runtime assignment must be authoritative: {errors:?}"
        );
    }

    #[test]
    fn portal_runtime_rejects_later_user_and_command_overrides() {
        for unsafe_override in ["USER 0:0\n", "CMD [\"/bin/sh\"]\n"] {
            let dockerfile = format!(
                "{}{unsafe_override}",
                canonical_portal_runtime_with_builder()
            );
            let mut errors = Vec::new();
            validate_published_portal_runtime(&dockerfile, "portal-ui Dockerfile", &mut errors);
            assert!(
                !errors.is_empty(),
                "later runtime override was accepted: {unsafe_override:?}"
            );
        }
    }

    #[test]
    fn portal_runtime_rejects_artifact_overwrites_after_reviewed_copies() {
        for unsafe_mutation in [
            "RUN printf exploit > /app/ryuki-portal-ui\n",
            "COPY --from=build /tmp/exploit /app/ryuki-portal-ui\n",
            "ADD exploit /app/site/index.html\n",
        ] {
            let dockerfile = format!(
                "{}{unsafe_mutation}",
                canonical_portal_runtime_with_builder()
            );
            let mut errors = Vec::new();
            validate_published_portal_runtime(&dockerfile, "portal-ui Dockerfile", &mut errors);
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("must not mutate runtime artifacts")),
                "later runtime artifact mutation was accepted: {unsafe_mutation:?}; {errors:?}"
            );
        }
    }

    #[test]
    fn portal_runtime_rejects_duplicate_runtime_aliases() {
        let dockerfile = format!(
            "{}FROM {PORTAL_RUNTIME_IMAGE} AS {PORTAL_RUNTIME_STAGE}\n",
            canonical_portal_runtime_with_builder()
        );
        let mut errors = Vec::new();
        validate_published_portal_runtime(&dockerfile, "portal-ui Dockerfile", &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("exactly one stage named")),
            "duplicate runtime alias was accepted: {errors:?}"
        );
    }

    #[test]
    fn portal_release_binding_rejects_missing_or_changed_runtime_target() {
        for target in [None, Some("post-runtime")] {
            let mut errors = Vec::new();
            validate_portal_release_binding(&portal_release_workflow(target), &mut errors);
            assert!(
                !errors.is_empty(),
                "release target {target:?} must not detach publication from runtime"
            );
        }
    }

    #[test]
    fn portal_release_binding_rejects_additional_portal_publisher() {
        let mut workflow = portal_release_workflow(Some(PORTAL_RUNTIME_STAGE));
        workflow.push_str(
            "      - id: portal-escape\n        uses: docker/build-push-action@0123456789012345678901234567890123456789\n        with:\n          context: .\n          file: ./portal/portal-ui/Dockerfile\n          target: post-runtime\n          push: true\n",
        );
        let mut errors = Vec::new();
        validate_portal_release_binding(&workflow, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("exactly one docker/build-push-action publisher")),
            "an additional portal publisher bypassed the selected target: {errors:?}"
        );
    }

    #[test]
    fn checked_in_portal_release_targets_reviewed_runtime() {
        let mut errors = Vec::new();
        validate_portal_release_binding(
            include_str!("../../../.github/workflows/release.yml"),
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "checked-in portal release binding is invalid: {errors:?}"
        );
    }

    #[test]
    fn checked_in_release_binds_and_validates_exact_rendered_digests() {
        let mut errors = Vec::new();
        validate_release_render_binding(
            include_str!("../../../.github/workflows/release.yml"),
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "checked-in release render binding is invalid: {errors:?}"
        );
    }

    #[test]
    fn release_render_workflow_rejects_digest_and_handoff_mutations() {
        let workflow = include_str!("../../../.github/workflows/release.yml");
        let mutations = [
            (
                "renderer digest substitution",
                workflow.replacen(
                    "--portal-digest \"${PORTAL_DIGEST}\"",
                    "--portal-digest \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
                    1,
                ),
            ),
            (
                "validator removal",
                workflow.replacen(
                    "id: kubernetes-render-validator",
                    "id: kubernetes-render-validator-disabled",
                    1,
                ),
            ),
            (
                "validator continue-on-error bypass",
                workflow.replacen(
                    "        id: kubernetes-render-validator\n        env:",
                    "        id: kubernetes-render-validator\n        continue-on-error: true\n        env:",
                    1,
                ),
            ),
            (
                "post-validation render rewrite",
                workflow.replacen(
                    "      - name: Seal validated Kubernetes render handoff",
                    "      - name: Rewrite render after validation\n        run: printf exploit > \"${RENDER_PATH}\"\n      - name: Seal validated Kubernetes render handoff",
                    1,
                ),
            ),
            (
                "unsealed release attachment",
                workflow.replacen(
                    "ryuki-release-kubernetes.yaml#Ryuki release Kubernetes render",
                    "unvalidated-kubernetes.yaml#Ryuki release Kubernetes render",
                    1,
                ),
            ),
        ];

        for (label, mutation) in mutations {
            let mut errors = Vec::new();
            validate_release_render_binding(&mutation, &mut errors);
            assert!(
                !errors.is_empty(),
                "release workflow mutation {label} must fail closed"
            );
        }
    }

    #[test]
    fn portal_release_target_keeps_appended_stage_out_of_published_image() {
        let dockerfile = format!(
            concat!(
                "{}",
                "FROM runtime AS post-runtime\n",
                "USER 0:0\n",
                "ENV RYUKI_PORTAL_EXECUTION_MODE=live\n",
                "COPY --from=build /tmp/exploit /app/ryuki-portal-ui\n",
                "COPY --from=build /tmp/exploit-site /app/site\n",
                "CMD [\"/bin/sh\"]\n",
            ),
            canonical_portal_runtime_with_builder()
        );
        let mut errors = Vec::new();
        validate_portal_release_binding(
            &portal_release_workflow(Some(PORTAL_RUNTIME_STAGE)),
            &mut errors,
        );
        validate_published_portal_runtime(&dockerfile, "portal-ui Dockerfile", &mut errors);
        assert!(
            errors.is_empty(),
            "an appended stage is not published when release target is exactly runtime: {errors:?}"
        );
    }

    #[test]
    fn complete_portal_dockerfile_passes() {
        let setup = canonical_root_setup_fixture("cargo-leptos", CARGO_LEPTOS_VERSION);
        let dockerfile = format!(
            "FROM rust:1.88-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS build\nRUN [\"/usr/local/cargo/bin/rustup\", \"target\", \"add\", \"wasm32-unknown-unknown\"]\nRUN [\"/usr/local/cargo/bin/cargo\", \"install\", \"cargo-leptos\", \"--version\", \"0.3.7\", \"--locked\", \"--root\", \"/opt/ryuki-tools/cargo-leptos-0.3.7\"]\n{setup}{}RUN [\"/opt/ryuki-tools/cargo-leptos-0.3.7/bin/cargo-leptos\", \"build\", \"--release\", \"-p\", \"ryuki-portal-ui\"]\n{}",
            full_copy_set(),
            canonical_portal_runtime_stage(),
        );
        let errors = validate_portal_dockerfile(&dockerfile, &members());
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn checked_in_dockerfiles_prove_canonical_protected_tool_lifecycles() {
        for (content, label, package, version) in [
            (
                include_str!("../../../sources/ryuki-api/Dockerfile"),
                "platform-api Dockerfile",
                "cargo-chef",
                CARGO_CHEF_VERSION,
            ),
            (
                include_str!("../../../portal/portal-ui/Dockerfile"),
                "portal-ui Dockerfile",
                "cargo-leptos",
                CARGO_LEPTOS_VERSION,
            ),
        ] {
            let mut errors = Vec::new();
            validate_protected_cargo_tool_lifecycle(content, label, package, version, &mut errors);
            assert!(
                errors.is_empty(),
                "checked-in {package} lifecycle failed structural proof: {errors:?}"
            );
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_decoys_overwrites_and_identity_changes() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let tool_root = format!("{PROTECTED_TOOL_ROOT}/{package}-{version}");
            for intervening in [
                "RUN [\"/bin/sh\", \"-c\", \"true\"]\n".to_string(),
                format!("COPY --from=evil /tmp/fake \"{tool_root}/bin/{package}\"\n"),
                format!("COPY --from=evil [\"/tmp/fake\", \"{tool_root}/bin/{package}\"]\n"),
                format!("COPY tool-link /app/tool-link\nCOPY fake /app/tool-link/{package}\n"),
                "USER 10001:10001\nUSER 0:0\n".to_string(),
            ] {
                let dockerfile =
                    canonical_lifecycle_fixture(package, version, &intervening, "RUN ", "RUN ");
                let mut errors = Vec::new();
                validate_protected_cargo_tool_lifecycle(
                    &dockerfile,
                    "Dockerfile",
                    package,
                    version,
                    &mut errors,
                );
                assert!(
                    !errors.is_empty(),
                    "unsafe intervening lifecycle action was accepted for {package}: {intervening:?}"
                );
            }
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_buildkit_mount_shadowing() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            for (install_prefix, use_prefix) in [
                ("RUN --mount=from=evil,target=/usr/local/cargo ", "RUN "),
                ("RUN ", "RUN --mount=from=evil,target=/opt/ryuki-tools "),
            ] {
                let dockerfile =
                    canonical_lifecycle_fixture(package, version, "", install_prefix, use_prefix);
                let mut errors = Vec::new();
                validate_protected_cargo_tool_lifecycle(
                    &dockerfile,
                    "Dockerfile",
                    package,
                    version,
                    &mut errors,
                );
                assert!(
                    !errors.is_empty(),
                    "BuildKit mount shadowing was accepted for {package}: {dockerfile:?}"
                );
            }
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_nondefault_dockerfile_escape() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            for directive in [
                "# escape=`\n",
                "#escape=`\n",
                "# ESCAPE = `\n",
                "\u{feff}# escape=`\n",
            ] {
                let dockerfile = format!(
                    "{directive}{}",
                    canonical_lifecycle_fixture(package, version, "", "RUN ", "RUN ")
                );
                let mut errors = Vec::new();
                validate_protected_cargo_tool_lifecycle(
                    &dockerfile,
                    "Dockerfile",
                    package,
                    version,
                    &mut errors,
                );
                assert!(
                    errors
                        .iter()
                        .any(|error| error.contains("default Dockerfile escape")),
                    "nondefault Dockerfile escape {directive:?} was accepted for {package}: {errors:?}"
                );
            }
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_heredoc_instruction_spoofing() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let phantom_lifecycle =
                canonical_lifecycle_fixture(package, version, "", "RUN ", "RUN ");
            for heredoc_start in [
                "RUN <<'RYUKI_TOOL_LIFECYCLE'\n",
                "RUN <\\\n<'RYUKI_TOOL_LIFECYCLE'\n",
            ] {
                // Without an explicit heredoc rejection, the payload's FROM/RUN
                // lines are misread as real Dockerfile stages. The trailing
                // `true` makes the actual shell-form heredoc succeed even though
                // none of the apparent protected-tool instructions ran.
                let dockerfile = format!(
                    "FROM rust:1.96-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS actual\n{heredoc_start}{phantom_lifecycle}true\nRYUKI_TOOL_LIFECYCLE\n"
                );
                let mut errors = Vec::new();
                validate_protected_cargo_tool_lifecycle(
                    &dockerfile,
                    "Dockerfile",
                    package,
                    version,
                    &mut errors,
                );
                assert!(
                    errors
                        .iter()
                        .any(|error| error.contains("heredoc instruction framing")),
                    "heredoc lifecycle spoof was accepted for {package}: {dockerfile:?}; {errors:?}"
                );
            }
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_custom_syntax_frontends() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let dockerfile = format!(
                "# syntax=attacker.example/dockerfile:latest\n{}",
                canonical_lifecycle_fixture(package, version, "", "RUN ", "RUN ")
            );
            let mut errors = Vec::new();
            validate_protected_cargo_tool_lifecycle(
                &dockerfile,
                "Dockerfile",
                package,
                version,
                &mut errors,
            );
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("custom Dockerfile syntax frontend")),
                "custom syntax frontend was accepted for {package}: {errors:?}"
            );
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_renamed_interpreters_before_use() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let python = format!(
                r#"import subprocess; subprocess.run(["cargo", "install", "attacker-tool", "--bin", "{package}", "--force"], check=True)"#
            );
            let intervening = format!(
                "RUN I=/usr/bin/python3 && ln -s \"$I\" /tmp/opaque-runner\nRUN /tmp/opaque-runner -c '{python}'\n"
            );
            let dockerfile =
                canonical_lifecycle_fixture(package, version, &intervening, "RUN ", "RUN ");
            let mut errors = Vec::new();
            validate_protected_cargo_tool_lifecycle(
                &dockerfile,
                "Dockerfile",
                package,
                version,
                &mut errors,
            );
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("arbitrary RUN instructions")),
                "renamed interpreter lifecycle bypass was accepted for {package}: {errors:?}"
            );
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_post_install_execution_bypass_matrix() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let install = canonical_install_arguments(package, version);
            let tool_root = format!("{PROTECTED_TOOL_ROOT}/{package}-{version}");
            let overwrite = format!(
                "{BASE_CARGO_PATH} install attacker-tool --bin {package} --force --root {tool_root}"
            );
            let timeout = serde_json::to_string(&vec![
                "/usr/bin/timeout".to_string(),
                "600".to_string(),
                BASE_CARGO_PATH.to_string(),
                "install".to_string(),
                "attacker-tool".to_string(),
                "--bin".to_string(),
                package.to_string(),
                "--force".to_string(),
                "--root".to_string(),
                tool_root.clone(),
            ])
            .expect("serialize timeout wrapper fixture");
            let dash = serde_json::to_string(&vec![
                "/usr/bin/dash".to_string(),
                "-c".to_string(),
                overwrite.clone(),
            ])
            .expect("serialize dash wrapper fixture");
            let shell = serde_json::to_string(&vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                overwrite.clone(),
            ])
            .expect("serialize shell wrapper fixture");
            let python = serde_json::to_string(&vec![
                "/usr/bin/python3".to_string(),
                "-c".to_string(),
                format!(
                    "import subprocess; subprocess.run([{BASE_CARGO_PATH:?}, 'install', 'attacker-tool', '--bin', {package:?}, '--force', '--root', {tool_root:?}], check=True)"
                ),
            ])
            .expect("serialize Python subprocess fixture");
            let bypasses = [
                format!("RUN {timeout}\n"),
                format!("RUN exec {overwrite}\n"),
                format!("RUN {dash}\n"),
                format!("RUN {shell}\n"),
                format!(
                    "RUN printf '%s\\n' attacker-tool | /usr/bin/xargs {BASE_CARGO_PATH} install --bin {package} --force --root {tool_root}\n"
                ),
                format!("RUN {python}\n"),
                format!(
                    "RUN ${{CARGO_EXECUTABLE}} install attacker-tool --bin {package} --force --root {tool_root}\n"
                ),
                format!(
                    "RUN {BASE_CARGO_PATH} ${{CARGO_SUBCOMMAND}} attacker-tool --bin {package} --force --root {tool_root}\n"
                ),
                format!(
                    "RUN {BASE_CARGO_PATH} install ${{CARGO_PACKAGE}} --bin {package} --force --root {tool_root}\n"
                ),
                format!("RUN <<'EOF'\n{overwrite}\nEOF\n"),
            ];

            for bypass in bypasses {
                let canonical = canonical_lifecycle_fixture(package, version, "", "RUN ", "RUN ");
                let dockerfile = insert_after_run_arguments(&canonical, &install, &bypass);
                let mut errors = Vec::new();
                validate_protected_cargo_tool_lifecycle(
                    &dockerfile,
                    "Dockerfile",
                    package,
                    version,
                    &mut errors,
                );
                assert!(
                    errors.iter().any(|error| error.contains(
                        "root setup step 1 must be the next exact JSON-exec action"
                    )),
                    "post-install execution bypass was accepted for {package}: {bypass:?}; {errors:?}"
                );
            }
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_dynamic_canonical_positions() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let canonical = canonical_lifecycle_fixture(package, version, "", "RUN ", "RUN ");
            let install = canonical_install_arguments(package, version);
            for (position, expansion) in [
                (0, "${CARGO_EXECUTABLE}"),
                (1, "${CARGO_SUBCOMMAND}"),
                (2, "${CARGO_PACKAGE}"),
            ] {
                let mut dynamic = install.clone();
                dynamic[position] = expansion.to_string();
                let dockerfile = replace_run_arguments(&canonical, &install, &dynamic);
                let mut errors = Vec::new();
                validate_protected_cargo_tool_lifecycle(
                    &dockerfile,
                    "Dockerfile",
                    package,
                    version,
                    &mut errors,
                );
                assert!(
                    errors.iter().any(|error| error.contains(
                        "expected one canonical JSON-exec"
                    )),
                    "dynamic canonical install position {position} was accepted for {package}: {errors:?}"
                );
            }

            let tool_path = format!("{PROTECTED_TOOL_ROOT}/{package}-{version}/bin/{package}");
            let expected_use = canonical_protected_tool_uses(package, &tool_path)
                .into_iter()
                .next()
                .expect("protected tool has a canonical use");
            for (position, expansion) in [(0, "${TOOL_EXECUTABLE}"), (1, "${TOOL_SUBCOMMAND}")] {
                let mut dynamic = expected_use.clone();
                dynamic[position] = expansion.to_string();
                let dockerfile = replace_run_arguments(&canonical, &expected_use, &dynamic);
                let mut errors = Vec::new();
                validate_protected_cargo_tool_lifecycle(
                    &dockerfile,
                    "Dockerfile",
                    package,
                    version,
                    &mut errors,
                );
                assert!(
                    errors
                        .iter()
                        .any(|error| error.contains("canonical absolute-path")),
                    "dynamic canonical use position {position} was accepted for {package}: {errors:?}"
                );
            }
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_later_protected_binary_replacement() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let tool_path = format!("{PROTECTED_TOOL_ROOT}/{package}-{version}/bin/{package}");
            let canonical = canonical_lifecycle_fixture(package, version, "", "RUN ", "RUN ");
            let replacements = [
                format!(
                    "COPY --link --chown={BUILD_USER} fake-protected-tool {tool_path}\n"
                ),
                format!(
                    "RUN [\"/usr/bin/install\", \"-m\", \"0755\", \"/tmp/fake-protected-tool\", \"{tool_path}\"]\n"
                ),
                format!(
                    "FROM build AS post-build\nCOPY --link --chown={BUILD_USER} fake-protected-tool {tool_path}\n"
                ),
            ];
            for replacement in replacements {
                let dockerfile = format!("{canonical}{replacement}");
                let mut errors = Vec::new();
                validate_protected_cargo_tool_lifecycle(
                    &dockerfile,
                    "Dockerfile",
                    package,
                    version,
                    &mut errors,
                );
                assert!(
                    !errors.is_empty(),
                    "later protected-binary replacement was accepted for {package}: {replacement:?}"
                );
            }
        }
    }

    #[test]
    fn protected_tool_lifecycle_allows_only_the_default_escape_directive() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let dockerfile = format!(
                "# escape=\\\n{}",
                canonical_lifecycle_fixture(package, version, "", "RUN ", "RUN ")
            );
            let mut errors = Vec::new();
            validate_protected_cargo_tool_lifecycle(
                &dockerfile,
                "Dockerfile",
                package,
                version,
                &mut errors,
            );
            assert!(
                errors.is_empty(),
                "explicit default Dockerfile escape must preserve the canonical lifecycle: {errors:?}"
            );
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_mutable_copies_and_builder_control_changes() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            for intervening in [
                "COPY --link source /app/source\n",
                "COPY --chown=10001:10001 source /app/source\n",
                "COPY --link --chown=10001:10001 source /app/../opt/escape\n",
                "COPY --link --chown=10001:10001 [\"source\", \"/app/source\"]\n",
                "ADD source /app/source\n",
                "ENV PATH=/tmp:/usr/local/cargo/bin\n",
                "USER 0:0\n",
                "SHELL [\"/bin/bash\", \"-c\"]\n",
                "ONBUILD RUN [\"/bin/true\"]\n",
                "VOLUME /usr/local/cargo\n",
            ] {
                let dockerfile =
                    canonical_lifecycle_fixture(package, version, intervening, "RUN ", "RUN ");
                let mut errors = Vec::new();
                validate_protected_cargo_tool_lifecycle(
                    &dockerfile,
                    "Dockerfile",
                    package,
                    version,
                    &mut errors,
                );
                assert!(
                    !errors.is_empty(),
                    "mutable builder action was accepted for {package}: {intervening:?}"
                );
            }
        }
    }

    #[test]
    fn protected_tool_lifecycle_rejects_missing_hardening_and_external_use_stages() {
        for (package, version) in [
            ("cargo-chef", CARGO_CHEF_VERSION),
            ("cargo-leptos", CARGO_LEPTOS_VERSION),
        ] {
            let tool_root = format!("{PROTECTED_TOOL_ROOT}/{package}-{version}");
            let chmod = serde_json::to_string(
                canonical_protected_root_setup(&tool_root)
                    .last()
                    .expect("canonical chmod step"),
            )
            .expect("serialize chmod step");
            let without_hardening =
                canonical_lifecycle_fixture(package, version, "", "RUN ", "RUN ")
                    .replace(&format!("RUN {chmod}\n"), "");
            let external_required_stage = canonical_lifecycle_fixture(
                package,
                version,
                "",
                "RUN ",
                "RUN ",
            )
            .replace(
                if package == "cargo-chef" {
                    "FROM chef AS planner"
                } else {
                    "USER 10001:10001"
                },
                if package == "cargo-chef" {
                    "FROM rust:1.96-bookworm@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb AS planner"
                } else {
                    "USER 10001:10001\nFROM rust:1.96-bookworm@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb AS decoy"
                },
            );

            for dockerfile in [without_hardening, external_required_stage] {
                let mut errors = Vec::new();
                validate_protected_cargo_tool_lifecycle(
                    &dockerfile,
                    "Dockerfile",
                    package,
                    version,
                    &mut errors,
                );
                assert!(
                    !errors.is_empty(),
                    "incomplete or externally detached lifecycle was accepted for {package}"
                );
            }
        }
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
}
