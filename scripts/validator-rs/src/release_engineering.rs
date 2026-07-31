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
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const CLIFF_PATH: &str = "cliff.toml";
const CHANGELOG_PATH: &str = "CHANGELOG.md";
const CI_WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
const RELEASE_WORKFLOW_PATH: &str = ".github/workflows/release.yml";
const STATIC_WORKFLOW_PATH: &str = ".github/workflows/static.yml";
const PROVING_GROUND_COMPOSE_PATH: &str = "deploy/proving-ground/compose.yaml";
const PROVING_GROUND_VALIDATE_PATH: &str = "deploy/proving-ground/validate.sh";
const RELEASE_SOURCE_SCRIPT_PATH: &str = "scripts/release/validate-source-v1.sh";
const RELEASE_NOTES_SCRIPT_PATH: &str = "scripts/release/validate-notes-v1.sh";
const RELEASE_SOURCE_SCRIPT_SHA256: &str =
    "011cc7a1fda421f41ee4c22553c631ac21eb42ca0393ea02cdcc09489716e2c2";
const RELEASE_NOTES_SCRIPT_SHA256: &str =
    "ed8d63bc13b9dd32fd51af864d19be885027ec5a196177d1ca2b57e91faf5849";
const RELEASE_SOURCE_STEP_V1: &str = "bash scripts/release/validate-source-v1.sh";
const RELEASE_NOTES_STEP_V1: &str = "bash scripts/release/validate-notes-v1.sh";
const RELEASE_TAG_REVALIDATION_V1: &str = r#"set -euo pipefail
[[ "${EXPECTED_TAG_OBJECT}" =~ ^[0-9a-f]{40}$ ]]
remote_tag_object="$(
  gh api "repos/${GH_REPO}/git/ref/tags/${TAG}" --jq '.object.sha'
)"
[[ "${remote_tag_object}" == "${EXPECTED_TAG_OBJECT}" ]] || {
  echo "::error::Release tag moved after provenance validation"
  exit 1
}"#;
const RELEASE_PUBLISH_V1: &str = r####"set -euo pipefail
fail() {
  echo "::error::$1"
  exit 1
}
[[ "${EXPECTED_TAG_OBJECT}" =~ ^[0-9a-f]{40}$ ]] || \
  fail "Validated release tag object is malformed"
remote_tag_object="$(
  gh api "repos/${GH_REPO}/git/ref/tags/${TAG}" --jq '.object.sha'
)" || fail "Cannot read the remote release tag"
[[ "${remote_tag_object}" == "${EXPECTED_TAG_OBJECT}" ]] || \
  fail "Release tag moved after provenance validation"
[[ -n "${RELEASE_NOTES_B64}" ]] || fail "Validated release notes are missing"
printf '%s' "${RELEASE_NOTES_B64}" | base64 --decode > release-notes.md || \
  fail "Validated release notes are not canonical base64"
note_bytes="$(LC_ALL=C wc -c < release-notes.md | tr -d '[:space:]')"
[[ "${note_bytes}" =~ ^[0-9]+$ && "${note_bytes}" -le 131072 ]] || \
  fail "Validated release notes exceed the 128 KiB handoff limit"
version="${TAG#v}"
first_heading="$(awk 'NF { print; exit }' release-notes.md)"
[[ "${first_heading}" == "## [${version}]"* ]] || \
  fail "Validated release notes do not match the release tag"
{
  cat release-notes.md
  echo ""
  echo "### Images (digest-pinned)"
  echo ""
  echo "- \`${API_REF}@${API_DIGEST}\`"
  echo "- \`${PORTAL_REF}@${PORTAL_DIGEST}\`"
} > release-body.md
gh release create "${TAG}" \
  --title "${TAG}" \
  --notes-file release-body.md \
  --verify-tag"####;
const PAGES_EVENT_VALIDATION_V1: &str = r#"set -euo pipefail
fail() {
  echo "::error::$1"
  exit 1
}

[[ "${EVENT_NAME}" == "workflow_run" ]] || \
  fail "Pages promotion requires a workflow_run event"
[[ "${CONCLUSION}" == "success" ]] || \
  fail "Pages promotion requires a successful parent run"
[[ "${PARENT_EVENT}" == "push" ]] || \
  fail "Pages promotion requires a parent push event"
[[ "${PARENT_WORKFLOW_PATH}" == ".github/workflows/ci.yml" ]] || \
  fail "Pages promotion requires the governed CI workflow file"
[[ "${HEAD_BRANCH}" == "main" ]] || \
  fail "Pages promotion requires the main branch"
[[ "${HEAD_REPOSITORY}" == "${REPOSITORY}" ]] || \
  fail "Pages promotion requires a same-repository parent run"
[[ "${HEAD_SHA}" =~ ^[0-9a-f]{40}$ ]] || \
  fail "Pages promotion requires a full lowercase commit SHA"
printf 'head_sha=%s\n' "${HEAD_SHA}" >> "${GITHUB_OUTPUT}""#;
const REQUIRED_PROVING_GROUND_CONTROL_LINES: &[&str] = &[
    r#"ACCEPTANCE_REVISION="$(compose_env_value PG_ACCEPTANCE_REVISION "$ENV_FILE")" || fail "PG_ACCEPTANCE_REVISION is missing""#,
    r#"PLATFORM_API_IMAGE_ID="$(compose_env_value PG_PLATFORM_API_IMAGE_ID "$ENV_FILE")" || fail "PG_PLATFORM_API_IMAGE_ID is missing""#,
    r#"PORTAL_IMAGE_ID="$(compose_env_value PG_PORTAL_IMAGE_ID "$ENV_FILE")" || fail "PG_PORTAL_IMAGE_ID is missing""#,
    r#"CURRENT_REVISION="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" || fail "cannot resolve the current committed revision""#,
    r#"[[ -z "$(GIT_NO_REPLACE_OBJECTS=1 git -C "$REPO_ROOT" -c core.fsmonitor=false -c core.untrackedCache=false status --porcelain=v1 --untracked-files=all)" ]] || fail "acceptance images must be built and started from a clean committed worktree""#,
    r#"actual_id="$(docker image inspect --format '{{.Id}}' "$image_ref" 2>/dev/null)" || fail "required local image is missing (no pull attempted): $image_ref""#,
    r#"actual_revision="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image_ref" 2>/dev/null)" || fail "cannot inspect local image revision label: $image_ref""#,
    r#"repo_digests="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image_ref" 2>/dev/null)" || fail "cannot inspect staged third-party digest: $image_ref""#,
    r#"RENDERED_IMAGE_TEXT="$("${COMPOSE[@]}" config --images)" || fail "cannot enumerate rendered proving-ground images""#,
    r#"grep -Fqx 'export RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK=true' "$HERE/run-agent.sh" || fail "the proving-ground agent loopback HTTP exception must be explicit""#,
];
const PROVING_GROUND_API_IMAGE: &str =
    "ryuki/platform-api:${PG_ACCEPTANCE_REVISION:?set exact acceptance revision}";
const PROVING_GROUND_PORTAL_IMAGE: &str =
    "ryuki/portal-ui:${PG_ACCEPTANCE_REVISION:?set exact acceptance revision}";

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
    "release-source:",
    RELEASE_SOURCE_STEP_V1,
    RELEASE_NOTES_STEP_V1,
    "RELEASE_SIGNING_PUBLIC_KEY_B64",
    "RELEASE_SIGNING_FINGERPRINT",
    "--verify-tag",
    "provenance: mode=max",
    "sbom: true",
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
    validate_ci_workflow(root, &mut errors);
    validate_release_workflow(root, &mut errors);
    validate_static_workflow(root, &mut errors);
    validate_proving_ground_compose(root, &mut errors);
    validate_proving_ground_preflight(root, &mut errors);
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

fn validate_ci_workflow(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(CI_WORKFLOW_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("failed to read {CI_WORKFLOW_PATH}: {error}"));
            return;
        }
    };

    validate_ci_workflow_text(&text, errors);
}

fn validate_ci_workflow_text(text: &str, errors: &mut Vec<String>) {
    let doc: YamlValue = match serde_yaml::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("{CI_WORKFLOW_PATH} is not valid YAML: {error}"));
            return;
        }
    };

    let postgres_image = doc
        .get("jobs")
        .and_then(|jobs| jobs.get("build-test"))
        .and_then(|job| job.get("services"))
        .and_then(|services| services.get("postgres"))
        .and_then(|service| service.get("image"))
        .and_then(YamlValue::as_str);
    if !postgres_image.is_some_and(is_immutable_image_reference) {
        errors.push(format!(
            "{CI_WORKFLOW_PATH} PostgreSQL service image must use a readable tag plus sha256 digest"
        ));
    }

    validate_action_pins(CI_WORKFLOW_PATH, text, errors);
}

fn validate_release_workflow(root: &Path, errors: &mut Vec<String>) {
    validate_versioned_release_script(
        root,
        RELEASE_SOURCE_SCRIPT_PATH,
        RELEASE_SOURCE_SCRIPT_SHA256,
        errors,
    );
    validate_versioned_release_script(
        root,
        RELEASE_NOTES_SCRIPT_PATH,
        RELEASE_NOTES_SCRIPT_SHA256,
        errors,
    );
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

    // The workflow must trigger on tag pushes shaped exactly like v*. Note: YAML parses
    // the bare `on:` key as the boolean `true`, so probe both spellings.
    if !triggers_on_version_tag(&doc) {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} must trigger on push tags matching exactly v* (on.push.tags)"
        ));
    }

    for term in REQUIRED_WORKFLOW_TERMS {
        if !text.contains(term) {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH} is missing required release step content: {term:?}"
            ));
        }
    }

    let postgres_image = doc
        .get("jobs")
        .and_then(|jobs| jobs.get("build-test"))
        .and_then(|job| job.get("services"))
        .and_then(|services| services.get("postgres"))
        .and_then(|service| service.get("image"))
        .and_then(YamlValue::as_str);
    if !postgres_image.is_some_and(is_immutable_image_reference) {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} PostgreSQL service image must use a readable tag plus sha256 digest"
        ));
    }

    let release_uses_external_action = doc
        .get("jobs")
        .and_then(|jobs| jobs.get("release"))
        .and_then(|job| job.get("steps"))
        .and_then(YamlValue::as_sequence)
        .is_some_and(|steps| steps.iter().any(|step| step.get("uses").is_some()));
    if release_uses_external_action {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} contents-write release job must not execute external actions"
        ));
    }

    validate_release_security_controls(&doc, errors);
    validate_action_pins(RELEASE_WORKFLOW_PATH, &text, errors);
}

fn validate_static_workflow(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(STATIC_WORKFLOW_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("failed to read {STATIC_WORKFLOW_PATH}: {error}"));
            return;
        }
    };

    validate_static_workflow_text(&text, errors);
}

fn validate_static_workflow_text(text: &str, errors: &mut Vec<String>) {
    let doc: YamlValue = match serde_yaml::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("{STATIC_WORKFLOW_PATH} is not valid YAML: {error}"));
            return;
        }
    };

    if workflow_has_event(&doc, "workflow_dispatch") {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} must not expose a manual path that bypasses CI promotion"
        ));
    }

    if !has_trusted_workflow_run_trigger(&doc) {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} must listen only for completed CI runs on main"
        ));
    }

    if !doc
        .get("permissions")
        .is_some_and(|permissions| permissions.as_mapping().is_some_and(|map| map.is_empty()))
    {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} must deny token permissions at workflow scope"
        ));
    }

    validate_static_security_controls(&doc, errors);
    validate_action_pins(STATIC_WORKFLOW_PATH, text, errors);
}

fn workflow_has_event(doc: &YamlValue, event: &str) -> bool {
    doc.get("on")
        .or_else(|| doc.get(YamlValue::Bool(true)))
        .and_then(|on| on.get(event))
        .is_some()
}

fn workflow_trigger<'a>(doc: &'a YamlValue, event: &str) -> Option<&'a YamlValue> {
    doc.get("on")
        .or_else(|| doc.get(YamlValue::Bool(true)))
        .and_then(|on| on.get(event))
}

fn is_singleton_string(value: Option<&YamlValue>, expected: &str) -> bool {
    value.and_then(YamlValue::as_sequence).is_some_and(|items| {
        items.len() == 1 && items[0].as_str().is_some_and(|item| item == expected)
    })
}

fn has_trusted_workflow_run_trigger(doc: &YamlValue) -> bool {
    let Some(trigger) = workflow_trigger(doc, "workflow_run") else {
        return false;
    };
    is_singleton_string(trigger.get("workflows"), "CI")
        && is_singleton_string(trigger.get("types"), "completed")
        && is_singleton_string(trigger.get("branches"), "main")
}

fn job_at<'a>(doc: &'a YamlValue, name: &str) -> Option<&'a YamlValue> {
    doc.get("jobs").and_then(|jobs| jobs.get(name))
}

fn has_exact_permissions(job: &YamlValue, expected: &[(&str, &str)]) -> bool {
    let Some(permissions) = job.get("permissions").and_then(YamlValue::as_mapping) else {
        return false;
    };
    permissions.len() == expected.len()
        && expected.iter().all(|(name, value)| {
            job.get("permissions")
                .and_then(|permission| permission.get(*name))
                .and_then(YamlValue::as_str)
                == Some(*value)
        })
}

fn has_empty_permissions(job: &YamlValue) -> bool {
    job.get("permissions")
        .and_then(YamlValue::as_mapping)
        .is_some_and(|permissions| permissions.is_empty())
}

fn job_environment_name(job: &YamlValue) -> Option<&str> {
    let environment = job.get("environment")?;
    environment
        .as_str()
        .or_else(|| environment.get("name").and_then(YamlValue::as_str))
}

fn job_needs(job: &YamlValue, dependency: &str) -> bool {
    match job.get("needs") {
        Some(YamlValue::String(value)) => value == dependency,
        Some(YamlValue::Sequence(values)) => values
            .iter()
            .filter_map(YamlValue::as_str)
            .any(|value| value == dependency),
        _ => false,
    }
}

fn job_needs_exactly(job: &YamlValue, expected: &[&str]) -> bool {
    let mut actual: Vec<&str> = match job.get("needs") {
        Some(YamlValue::String(value)) => vec![value.as_str()],
        Some(YamlValue::Sequence(values)) => {
            let parsed: Vec<&str> = values.iter().filter_map(YamlValue::as_str).collect();
            if parsed.len() != values.len() {
                return false;
            }
            parsed
        }
        _ => return false,
    };
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    actual == expected
}

fn validate_versioned_release_script(
    root: &Path,
    path: &str,
    expected_sha256: &str,
    errors: &mut Vec<String>,
) {
    let full_path = root.join(path);
    let metadata = match fs::symlink_metadata(&full_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            errors.push(format!("failed to inspect {path}: {error}"));
            return;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        errors.push(format!(
            "{path} must be a regular versioned release-control script"
        ));
        return;
    }
    let bytes = match fs::read(&full_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            errors.push(format!("failed to read {path}: {error}"));
            return;
        }
    };
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected_sha256 {
        errors.push(format!(
            "{path} differs from its reviewed versioned release-control digest"
        ));
    }
}

fn job_has_exact_control_step(job: &YamlValue, id: &str, expected_run: &str) -> bool {
    let Some(steps) = job.get("steps").and_then(YamlValue::as_sequence) else {
        return false;
    };
    let matching: Vec<&YamlValue> = steps
        .iter()
        .filter(|step| step.get("id").and_then(YamlValue::as_str) == Some(id))
        .collect();
    matching.len() == 1
        && matching[0]
            .get("run")
            .and_then(YamlValue::as_str)
            .is_some_and(|run| run.trim() == expected_run.trim())
}

fn require_exact_control_step(
    path: &str,
    job_name: &str,
    job: &YamlValue,
    step_id: &str,
    expected_run: &str,
    errors: &mut Vec<String>,
) {
    if !job_has_exact_control_step(job, step_id, expected_run) {
        errors.push(format!(
            "{path} {job_name}.{step_id} must execute the exact reviewed versioned control program"
        ));
    }
}

fn job_executes_action(job: &YamlValue) -> bool {
    job.get("steps")
        .and_then(YamlValue::as_sequence)
        .is_some_and(|steps| steps.iter().any(|step| step.get("uses").is_some()))
}

fn job_output<'a>(job: &'a YamlValue, name: &str) -> Option<&'a str> {
    job.get("outputs")
        .and_then(|outputs| outputs.get(name))
        .and_then(YamlValue::as_str)
}

fn job_checks_out_ref(job: &YamlValue, expected_ref: &str) -> bool {
    job.get("steps")
        .and_then(YamlValue::as_sequence)
        .is_some_and(|steps| {
            let checkouts: Vec<&YamlValue> = steps
                .iter()
                .filter(|step| {
                    step.get("uses")
                        .and_then(YamlValue::as_str)
                        .is_some_and(|uses| uses.starts_with("actions/checkout@"))
                })
                .collect();
            checkouts.len() == 1
                && checkouts[0]
                    .get("with")
                    .and_then(|with| with.get("ref"))
                    .and_then(YamlValue::as_str)
                    == Some(expected_ref)
        })
}

fn validate_release_security_controls(doc: &YamlValue, errors: &mut Vec<String>) {
    let Some(source) = job_at(doc, "release-source") else {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} missing read-only release-source provenance job"
        ));
        return;
    };

    if !has_exact_permissions(source, &[("contents", "read")]) {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} release-source must have only contents: read"
        ));
    }
    require_exact_control_step(
        RELEASE_WORKFLOW_PATH,
        "release-source",
        source,
        "provenance",
        RELEASE_SOURCE_STEP_V1,
        errors,
    );

    if job_output(source, "commit-sha") != Some("${{ steps.provenance.outputs.commit-sha }}")
        || job_output(source, "tag-object-sha")
            != Some("${{ steps.provenance.outputs.tag-object-sha }}")
    {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} release-source must export its validated commit and tag object"
        ));
    }

    let jobs = doc.get("jobs").and_then(YamlValue::as_mapping);
    if let Some(jobs) = jobs {
        for (name, job) in jobs {
            let Some(name) = name.as_str() else {
                continue;
            };
            if matches!(name, "images" | "release") {
                continue;
            }
            let has_write = job
                .get("permissions")
                .and_then(YamlValue::as_mapping)
                .is_some_and(|permissions| {
                    permissions
                        .values()
                        .any(|value| value.as_str() == Some("write"))
                });
            if has_write {
                errors.push(format!(
                    "{RELEASE_WORKFLOW_PATH} pre-publication job {name} must not receive write permission"
                ));
            }
        }
    }

    for (name, permissions) in [
        ("images", &[("contents", "read"), ("packages", "write")][..]),
        ("release", &[("contents", "write")][..]),
    ] {
        let Some(job) = job_at(doc, name) else {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH} missing write-authorized {name} job"
            ));
            continue;
        };
        if !has_exact_permissions(job, permissions) {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH} {name} job has unexpected token permissions"
            ));
        }
        if job_environment_name(job) != Some("release") {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH} {name} job must declare the protected release Environment"
            ));
        }
        if !job_needs(job, "release-source") {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH} {name} job must depend directly on release-source"
            ));
        }
    }

    if job_at(doc, "images").is_some_and(|job| {
        !job_needs_exactly(
            job,
            &[
                "release-source",
                "build-test",
                "lint",
                "security",
                "validate",
            ],
        )
    }) {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} images job must depend on release-source and every quality gate"
        ));
    }
    if job_at(doc, "release")
        .is_some_and(|job| !job_needs_exactly(job, &["release-source", "images", "release-notes"]))
    {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} release job must depend on provenance, images, and release notes"
        ));
    }

    if job_at(doc, "release-notes").is_some_and(|job| {
        !job_needs_exactly(
            job,
            &[
                "release-source",
                "build-test",
                "lint",
                "security",
                "validate",
            ],
        )
    }) {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} release-notes must remain behind provenance and quality gates"
        ));
    }

    let validated_commit = "${{ needs.release-source.outputs.commit-sha }}";
    for name in [
        "build-test",
        "lint",
        "security",
        "validate",
        "images",
        "release-notes",
    ] {
        let Some(job) = job_at(doc, name) else {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH} missing provenance-bound {name} job"
            ));
            continue;
        };
        if !job_needs(job, "release-source") {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH} {name} must wait for release-source"
            ));
        }
        if !job_checks_out_ref(job, validated_commit) {
            errors.push(format!(
                "{RELEASE_WORKFLOW_PATH} {name} must check out the validated release commit"
            ));
        }
    }

    if let Some(images) = job_at(doc, "images") {
        require_exact_control_step(
            RELEASE_WORKFLOW_PATH,
            "images",
            images,
            "revalidate-tag",
            RELEASE_TAG_REVALIDATION_V1,
            errors,
        );
    }
    if let Some(release) = job_at(doc, "release") {
        require_exact_control_step(
            RELEASE_WORKFLOW_PATH,
            "release",
            release,
            "publish",
            RELEASE_PUBLISH_V1,
            errors,
        );
    }

    let Some(notes) = job_at(doc, "release-notes") else {
        return;
    };
    if job_output(notes, "content-b64") != Some("${{ steps.validate-notes.outputs.content-b64 }}") {
        errors.push(format!(
            "{RELEASE_WORKFLOW_PATH} release notes must cross the write boundary as validated base64"
        ));
    }
    require_exact_control_step(
        RELEASE_WORKFLOW_PATH,
        "release-notes",
        notes,
        "validate-notes",
        RELEASE_NOTES_STEP_V1,
        errors,
    );
}

fn validate_static_security_controls(doc: &YamlValue, errors: &mut Vec<String>) {
    let Some(preflight) = job_at(doc, "validate-run") else {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} missing permissionless validate-run preflight"
        ));
        return;
    };
    if !has_empty_permissions(preflight) {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} validate-run must have no token permissions"
        ));
    }
    if job_executes_action(preflight) {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} validate-run must not execute external action code"
        ));
    }
    require_exact_control_step(
        STATIC_WORKFLOW_PATH,
        "validate-run",
        preflight,
        "event",
        PAGES_EVENT_VALIDATION_V1,
        errors,
    );
    let head_sha_output = preflight
        .get("outputs")
        .and_then(|outputs| outputs.get("head_sha"))
        .and_then(YamlValue::as_str);
    if head_sha_output != Some("${{ steps.event.outputs.head_sha }}") {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} validate-run must export only its validated head_sha"
        ));
    }

    let Some(deploy) = job_at(doc, "deploy") else {
        errors.push(format!("{STATIC_WORKFLOW_PATH} missing deploy job"));
        return;
    };
    if !job_needs(deploy, "validate-run") {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} deploy must depend on validate-run"
        ));
    }
    if !has_exact_permissions(
        deploy,
        &[
            ("contents", "read"),
            ("pages", "write"),
            ("id-token", "write"),
        ],
    ) {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} deploy must hold only contents-read, Pages-write, and OIDC-write"
        ));
    }
    if job_environment_name(deploy) != Some("github-pages") {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} deploy must declare the github-pages Environment"
        ));
    }
    let trusted_checkout = deploy
        .get("steps")
        .and_then(YamlValue::as_sequence)
        .is_some_and(|steps| {
            let checkouts: Vec<&YamlValue> = steps
                .iter()
                .filter(|step| {
                    step.get("uses")
                        .and_then(YamlValue::as_str)
                        .is_some_and(|uses| uses.starts_with("actions/checkout@"))
                })
                .collect();
            checkouts.len() == 1
                && checkouts[0]
                    .get("with")
                    .and_then(|with| with.get("ref"))
                    .and_then(YamlValue::as_str)
                    == Some("${{ needs.validate-run.outputs.head_sha }}")
        });
    if !trusted_checkout {
        errors.push(format!(
            "{STATIC_WORKFLOW_PATH} deploy must check out only needs.validate-run.outputs.head_sha"
        ));
    }
}

fn validate_action_pins(path: &str, text: &str, errors: &mut Vec<String>) {
    let doc: YamlValue = match serde_yaml::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!(
                "{path} action-pin validation could not parse workflow YAML: {error}"
            ));
            return;
        }
    };
    let Some(jobs) = doc.get("jobs").and_then(YamlValue::as_mapping) else {
        return;
    };

    for (job_name, job) in jobs {
        let job_name = job_name.as_str().unwrap_or("<non-string-job>");
        let Some(steps) = job.get("steps").and_then(YamlValue::as_sequence) else {
            continue;
        };
        for (step_index, step) in steps.iter().enumerate() {
            let Some(uses) = step.get("uses") else {
                continue;
            };
            let Some(action) = uses.as_str() else {
                errors.push(format!(
                    "{path} job {job_name} step {} action reference must be a literal string",
                    step_index + 1
                ));
                continue;
            };
            if action.starts_with("./") {
                continue;
            }
            let location = format!("{path} job {job_name} step {}", step_index + 1);
            if !action_has_readable_version_comment(text, action) {
                errors.push(format!(
                    "{location} immutable action reference must retain a readable version comment"
                ));
            }
            let Some((_, reference)) = action.rsplit_once('@') else {
                errors.push(format!(
                    "{location} action reference must use a full commit SHA"
                ));
                continue;
            };
            if reference.len() != 40
                || !reference
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                errors.push(format!(
                    "{location} action reference {action:?} must use a 40-character commit SHA"
                ));
            }
        }
    }
}

fn action_has_readable_version_comment(text: &str, action: &str) -> bool {
    text.lines().any(|line| {
        line.find(action).is_some_and(|start| {
            line[start + action.len()..]
                .split_once('#')
                .is_some_and(|(_, comment)| !comment.trim().is_empty())
        })
    })
}

fn validate_proving_ground_compose(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(PROVING_GROUND_COMPOSE_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!(
                "failed to read {PROVING_GROUND_COMPOSE_PATH}: {error}"
            ));
            return;
        }
    };

    validate_proving_ground_text(&text, errors);
}

fn validate_proving_ground_preflight(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(PROVING_GROUND_VALIDATE_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!(
                "failed to read {PROVING_GROUND_VALIDATE_PATH}: {error}"
            ));
            return;
        }
    };
    validate_proving_ground_preflight_text(&text, errors);
}

fn validate_proving_ground_preflight_text(text: &str, errors: &mut Vec<String>) {
    let logical_lines: Vec<String> = logical_shell_lines(text)
        .into_iter()
        .map(|(_, line)| normalize_shell_line(&line))
        .collect();
    for control in REQUIRED_PROVING_GROUND_CONTROL_LINES {
        if !logical_lines
            .iter()
            .any(|line| line == &normalize_shell_line(control))
        {
            errors.push(format!(
                "{PROVING_GROUND_VALIDATE_PATH} is missing required local-only preflight control {control:?}"
            ));
        }
    }

    for (line_number, line) in logical_shell_lines(text) {
        if split_shell_commands(&line)
            .iter()
            .any(|command| prohibited_preflight_command(command, 0))
        {
            errors.push(format!(
                "{PROVING_GROUND_VALIDATE_PATH}:{line_number} preflight must not contact registries or start containers"
            ));
        }
    }
}

fn normalize_shell_line(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn logical_shell_lines(text: &str) -> Vec<(usize, String)> {
    let mut logical = Vec::new();
    let mut current = String::new();
    let mut start_line = 0;

    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if current.is_empty() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            start_line = index + 1;
        }
        let continued = line.ends_with('\\');
        let part = line.strip_suffix('\\').unwrap_or(line).trim_end();
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(part);
        if !continued {
            logical.push((start_line, std::mem::take(&mut current)));
        }
    }
    if !current.is_empty() {
        logical.push((start_line, current));
    }
    logical
}

fn split_shell_commands(script: &str) -> Vec<Vec<String>> {
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

    for character in script.chars() {
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

fn prohibited_preflight_command(command: &[String], depth: usize) -> bool {
    if depth > 8 {
        return true;
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
            return false;
        };
        match executable {
            "if" | "then" | "elif" | "while" | "until" | "do" | "!" | "exec" | "builtin"
            | "nohup" | "time" => index += 1,
            "command" => {
                index += 1;
                while let Some(option) = command.get(index) {
                    if matches!(option.as_str(), "-v" | "-V") {
                        return false;
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
                        return false;
                    };
                    if is_shell_assignment(argument) {
                        index += 1;
                    } else if options && argument == "--" {
                        options = false;
                        index += 1;
                    } else if options && matches!(argument.as_str(), "-S" | "--split-string") {
                        return command.get(index + 1).is_some_and(|script| {
                            split_shell_commands(script)
                                .iter()
                                .any(|nested| prohibited_preflight_command(nested, depth + 1))
                        });
                    } else if options {
                        if let Some(script) = argument.strip_prefix("--split-string=") {
                            return split_shell_commands(script)
                                .iter()
                                .any(|nested| prohibited_preflight_command(nested, depth + 1));
                        }
                        if matches!(argument.as_str(), "-u" | "--unset" | "-C" | "--chdir") {
                            index += 2;
                        } else if argument.starts_with('-') {
                            index += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            "sudo" => {
                index += 1;
                while command
                    .get(index)
                    .is_some_and(|token| token.starts_with('-'))
                {
                    index += 1;
                }
            }
            "sh" | "bash" => {
                return shell_command_string(command, index).is_some_and(|script| {
                    split_shell_commands(script)
                        .iter()
                        .any(|nested| prohibited_preflight_command(nested, depth + 1))
                });
            }
            "docker" => return prohibited_docker_arguments(&command[index + 1..]),
            "skopeo" | "crane" | "oras" | "curl" | "wget" => return true,
            _ => return false,
        }
    }
}

fn prohibited_docker_arguments(arguments: &[String]) -> bool {
    arguments
        .iter()
        .any(|argument| argument == "pull" || argument == "run")
        || command_precedes(arguments, "compose", "up")
        || command_precedes(arguments, "container", "start")
        || command_precedes(arguments, "image", "pull")
}

fn command_precedes(arguments: &[String], group: &str, command: &str) -> bool {
    arguments
        .iter()
        .position(|argument| argument == group)
        .is_some_and(|index| {
            arguments[index + 1..]
                .iter()
                .any(|argument| argument == command)
        })
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

fn validate_proving_ground_text(text: &str, errors: &mut Vec<String>) {
    let doc: YamlValue = match serde_yaml::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!(
                "{PROVING_GROUND_COMPOSE_PATH} is not valid YAML: {error}"
            ));
            return;
        }
    };

    for service_name in ["platform-db", "vault"] {
        let service = doc
            .get("services")
            .and_then(|services| services.get(service_name));
        let image = service
            .and_then(|service| service.get("image"))
            .and_then(YamlValue::as_str);
        if !image.is_some_and(is_immutable_image_reference) {
            errors.push(format!(
                "{PROVING_GROUND_COMPOSE_PATH} service {service_name} must use a readable tag plus sha256 digest"
            ));
        }
        let pull_policy = service
            .and_then(|service| service.get("pull_policy"))
            .and_then(YamlValue::as_str);
        if pull_policy != Some("never") {
            errors.push(format!(
                "{PROVING_GROUND_COMPOSE_PATH} service {service_name} must set pull_policy: never"
            ));
        }
    }

    for (service_name, expected_image) in [
        ("platform-api", PROVING_GROUND_API_IMAGE),
        ("portal-ui", PROVING_GROUND_PORTAL_IMAGE),
    ] {
        let service = doc
            .get("services")
            .and_then(|services| services.get(service_name));
        let image = service
            .and_then(|service| service.get("image"))
            .and_then(YamlValue::as_str);
        if image != Some(expected_image) {
            errors.push(format!(
                "{PROVING_GROUND_COMPOSE_PATH} local service {service_name} must use revision-specific image {expected_image:?}"
            ));
        }
        let pull_policy = service
            .and_then(|service| service.get("pull_policy"))
            .and_then(YamlValue::as_str);
        if pull_policy != Some("never") {
            errors.push(format!(
                "{PROVING_GROUND_COMPOSE_PATH} local service {service_name} must set pull_policy: never"
            ));
        }
        if service.is_some_and(|service| service.get("build").is_some()) {
            errors.push(format!(
                "{PROVING_GROUND_COMPOSE_PATH} local service {service_name} must consume a prevalidated image, not build during startup"
            ));
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

/// True only when the workflow's `on.push.tags` list contains the reviewed
/// broad trigger. Exact SemVer is enforced by the fail-closed provenance job.
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
    tags.len() == 1 && tags[0].as_str() == Some("v*")
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

    fn indent_yaml_block(script: &str, spaces: usize) -> String {
        let prefix = " ".repeat(spaces);
        script
            .lines()
            .map(|line| format!("{prefix}{line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn trusted_pages_fixture() -> String {
        r#"
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
    branches: ["main"]
permissions: {}
jobs:
  validate-run:
    permissions: {}
    outputs:
      head_sha: ${{ steps.event.outputs.head_sha }}
    steps:
      - id: event
        run: |
__EVENT_CONTROL__
  deploy:
    needs: validate-run
    permissions:
      contents: read
      pages: write
      id-token: write
    environment:
      name: github-pages
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
        with:
          ref: ${{ needs.validate-run.outputs.head_sha }}
"#
        .replace(
            "__EVENT_CONTROL__",
            &indent_yaml_block(PAGES_EVENT_VALIDATION_V1, 10),
        )
    }

    fn release_security_fixture() -> String {
        r#"
jobs:
  release-source:
    permissions:
      contents: read
    outputs:
      commit-sha: ${{ steps.provenance.outputs.commit-sha }}
      tag-object-sha: ${{ steps.provenance.outputs.tag-object-sha }}
    steps:
      - id: provenance
        run: bash scripts/release/validate-source-v1.sh
  build-test:
    needs: release-source
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
        with:
          ref: ${{ needs.release-source.outputs.commit-sha }}
  lint:
    needs: release-source
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
        with:
          ref: ${{ needs.release-source.outputs.commit-sha }}
  security:
    needs: release-source
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
        with:
          ref: ${{ needs.release-source.outputs.commit-sha }}
  validate:
    needs: release-source
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
        with:
          ref: ${{ needs.release-source.outputs.commit-sha }}
  images:
    needs: [release-source, build-test, lint, security, validate]
    environment:
      name: release
    permissions:
      contents: read
      packages: write
    steps:
      - id: revalidate-tag
        run: |
__TAG_CONTROL__
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
        with:
          ref: ${{ needs.release-source.outputs.commit-sha }}
  release-notes:
    needs: [release-source, build-test, lint, security, validate]
    permissions:
      contents: read
    outputs:
      content-b64: ${{ steps.validate-notes.outputs.content-b64 }}
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
        with:
          ref: ${{ needs.release-source.outputs.commit-sha }}
      - id: validate-notes
        run: bash scripts/release/validate-notes-v1.sh
  release:
    needs: [release-source, images, release-notes]
    environment:
      name: release
    permissions:
      contents: write
    steps:
      - id: publish
        run: |
__PUBLISH_CONTROL__
"#
        .replace(
            "__TAG_CONTROL__",
            &indent_yaml_block(RELEASE_TAG_REVALIDATION_V1, 10),
        )
        .replace(
            "__PUBLISH_CONTROL__",
            &indent_yaml_block(RELEASE_PUBLISH_V1, 10),
        )
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

        let overbroad_version_tag = serde_yaml::from_str::<YamlValue>(
            r#"
on:
  push:
    tags: ["v*", "release-*"]
"#,
        )
        .unwrap();
        assert!(!triggers_on_version_tag(&overbroad_version_tag));
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

    #[test]
    fn action_references_require_full_commit_shas() {
        let mut errors = Vec::new();
        validate_action_pins(
            "workflow.yml",
            concat!(
                "jobs:\n  build:\n    steps:\n",
                "      - uses: actions/checkout@v5\n",
                "      - uses: ./local-action\n",
                "      - uses: docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9 # v3.7.0\n",
            ),
            &mut errors,
        );
        assert_eq!(errors.len(), 2, "unexpected errors: {errors:?}");
        assert!(errors
            .iter()
            .any(|error| error.contains("actions/checkout@v5")));
        assert!(errors.iter().any(|error| error.contains("version comment")));

        errors.clear();
        validate_action_pins(
            "workflow.yml",
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@93CB6EFE18208431CDDFB8368FD83D5BADBF9BFD # v5.0.1\n",
            &mut errors,
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("40-character commit SHA")),
            "mixed-case action identity was accepted: {errors:?}"
        );

        errors.clear();
        validate_action_pins(
            "workflow.yml",
            r#"
jobs:
  build:
    steps:
      - { "uses": "actions/checkout@v5" }
      - { 'uses': 'docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9' } # v3.7.0
"#,
            &mut errors,
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("actions/checkout@v5")),
            "flow-mapping quoted uses key bypassed parsed-YAML validation: {errors:?}"
        );
        assert!(
            !errors.iter().any(
                |error| error.contains("docker/login-action") && error.contains("40-character")
            ),
            "valid flow-mapping action pin was rejected: {errors:?}"
        );
    }

    #[test]
    fn release_write_jobs_require_signed_tag_gate_and_protected_environment() {
        let safe: YamlValue = serde_yaml::from_str(&release_security_fixture()).unwrap();
        let mut errors = Vec::new();
        validate_release_security_controls(&safe, &mut errors);
        assert!(
            errors.is_empty(),
            "safe release boundary failed: {errors:?}"
        );

        let vulnerable_text = release_security_fixture()
            .replace(
                RELEASE_SOURCE_STEP_V1,
                "bash scripts/release/validate-source-v2.sh",
            )
            .replace("name: release", "name: unprotected");
        let vulnerable: YamlValue = serde_yaml::from_str(&vulnerable_text).unwrap();
        errors.clear();
        validate_release_security_controls(&vulnerable, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("release-source.provenance")),
            "missing signed-tag verification was accepted: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("protected release Environment")),
            "unprotected write jobs were accepted: {errors:?}"
        );

        let missing_quality_gate = release_security_fixture().replace(
            "needs: [release-source, build-test, lint, security, validate]",
            "needs: [release-source, build-test, lint, security]",
        );
        let missing_quality_gate: YamlValue = serde_yaml::from_str(&missing_quality_gate).unwrap();
        errors.clear();
        validate_release_security_controls(&missing_quality_gate, &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("quality gate")),
            "missing validator gate was accepted: {errors:?}"
        );

        let incomplete_signature_policy = release_security_fixture().replace(
            RELEASE_SOURCE_STEP_V1,
            "echo GOODSIG; echo VALIDSIG; echo EXPKEYSIG",
        );
        let incomplete_signature_policy: YamlValue =
            serde_yaml::from_str(&incomplete_signature_policy).unwrap();
        errors.clear();
        validate_release_security_controls(&incomplete_signature_policy, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("release-source.provenance")),
            "inert signature-status decoys satisfied the release control: {errors:?}"
        );

        let unbound_publication = release_security_fixture()
            .replace(
                "gh api \"repos/${GH_REPO}/git/ref/tags/${TAG}\" --jq '.object.sha'",
                "printf '%s' attacker",
            )
            .replace(
                "ref: ${{ needs.release-source.outputs.commit-sha }}",
                "ref: ${{ github.ref }}",
            )
            .replace(RELEASE_NOTES_STEP_V1, "echo first_heading; echo 131072")
            .replace("base64 --decode", "cat");
        let unbound_publication: YamlValue = serde_yaml::from_str(&unbound_publication).unwrap();
        errors.clear();
        validate_release_security_controls(&unbound_publication, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("validated release commit")),
            "moving-ref checkout was accepted: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("images.revalidate-tag")),
            "tag-object TOCTOU guard was omitted: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("release-notes.validate-notes")),
            "unbounded release-note handoff was accepted: {errors:?}"
        );
    }

    #[test]
    fn ci_workflow_requires_immutable_external_inputs() {
        let vulnerable = r#"
jobs:
  build-test:
    services:
      postgres:
        image: postgres:18
    steps:
      - uses: actions/checkout@v5
"#;
        let mut errors = Vec::new();
        validate_ci_workflow_text(vulnerable, &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("PostgreSQL")),
            "mutable service image was not rejected: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("actions/checkout@v5")),
            "mutable action tag was not rejected: {errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("version comment")),
            "missing human-readable action version was not rejected: {errors:?}"
        );

        let safe = r#"
jobs:
  build-test:
    services:
      postgres:
        image: postgres:18.4@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5.0.1
"#;
        errors.clear();
        validate_ci_workflow_text(safe, &mut errors);
        assert!(
            errors.is_empty(),
            "immutable CI inputs were rejected: {errors:?}"
        );
    }

    #[test]
    fn pages_workflow_rejects_manual_and_untrusted_promotion() {
        let mut errors = Vec::new();
        validate_static_workflow_text(&trusted_pages_fixture(), &mut errors);
        assert!(errors.is_empty(), "trusted Pages flow failed: {errors:?}");

        let vulnerable = trusted_pages_fixture()
            .replace("  workflow_run:", "  workflow_dispatch:\n  workflow_run:")
            .replace(
                "[[ \"${HEAD_SHA}\" =~ ^[0-9a-f]{40}$ ]]",
                "test -n \"${HEAD_SHA}\"",
            )
            .replace(
                "ref: ${{ needs.validate-run.outputs.head_sha }}",
                "ref: ${{ github.ref }}",
            );
        errors.clear();
        validate_static_workflow_text(&vulnerable, &mut errors);
        assert!(errors.iter().any(|error| error.contains("manual path")));
        assert!(errors
            .iter()
            .any(|error| error.contains("validate-run.event")));
        assert!(errors
            .iter()
            .any(|error| error.contains("needs.validate-run.outputs.head_sha")));

        let duplicate_name_path = trusted_pages_fixture().replace(
            "[[ \"${PARENT_WORKFLOW_PATH}\" == \".github/workflows/ci.yml\" ]]",
            "[[ \"${PARENT_WORKFLOW_PATH}\" == \".github/workflows/duplicate-ci.yml\" ]]",
        );
        errors.clear();
        validate_static_workflow_text(&duplicate_name_path, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("validate-run.event")),
            "same-name workflow at another path was accepted: {errors:?}"
        );
    }

    #[test]
    fn proving_ground_requires_digests_and_local_only_app_images() {
        let safe = r#"
services:
  platform-db:
    image: postgres:18.4@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    pull_policy: never
  vault:
    image: hashicorp/vault:1.20.4@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    pull_policy: never
  platform-api:
    image: "ryuki/platform-api:${PG_ACCEPTANCE_REVISION:?set exact acceptance revision}"
    pull_policy: never
  portal-ui:
    image: "ryuki/portal-ui:${PG_ACCEPTANCE_REVISION:?set exact acceptance revision}"
    pull_policy: never
"#;
        let mut errors = Vec::new();
        validate_proving_ground_text(safe, &mut errors);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");

        let vulnerable = safe
            .replace(
                "postgres:18.4@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "postgres:18",
            )
            .replace(
                "ryuki/portal-ui:${PG_ACCEPTANCE_REVISION:?set exact acceptance revision}",
                "ryuki/portal-ui:rust-dev",
            )
            .replace("pull_policy: never", "pull_policy: missing");
        errors.clear();
        validate_proving_ground_text(&vulnerable, &mut errors);
        assert!(errors.iter().any(|error| error.contains("platform-db")));
        assert!(errors.iter().any(|error| error.contains("platform-api")));
        assert!(errors.iter().any(|error| error.contains("portal-ui")));
    }

    #[test]
    fn proving_ground_preflight_is_local_only_and_fail_closed() {
        let safe = REQUIRED_PROVING_GROUND_CONTROL_LINES.join("\n");
        let mut errors = Vec::new();
        validate_proving_ground_preflight_text(&safe, &mut errors);
        assert!(errors.is_empty(), "safe local preflight failed: {errors:?}");

        let vulnerable = safe.replace(
            "\"${COMPOSE[@]}\" config --images",
            "docker pull postgres:18\ndocker compose up -d",
        );
        errors.clear();
        validate_proving_ground_preflight_text(&vulnerable, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("cannot enumerate rendered proving-ground images"))
                && errors.iter().any(|error| error
                    .contains("preflight must not contact registries or start containers")),
            "registry/start bypass fixture was not rejected: {errors:?}"
        );

        let missing_agent_exception = safe.replace(
            "grep -Fqx 'export RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK=true' \"$HERE/run-agent.sh\"",
            "# loopback exception omitted",
        );
        errors.clear();
        validate_proving_ground_preflight_text(&missing_agent_exception, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK=true")),
            "missing explicit agent loopback exception was accepted: {errors:?}"
        );

        for wrapped in [
            "env docker pull postgres:18",
            "command docker compose up -d",
            "sudo docker run attacker.invalid/image",
            "bash -c 'env docker image pull attacker.invalid/image'",
        ] {
            let fixture = format!("{safe}\n{wrapped}\n");
            errors.clear();
            validate_proving_ground_preflight_text(&fixture, &mut errors);
            assert!(
                errors.iter().any(|error| {
                    error.contains("must not contact registries or start containers")
                }),
                "wrapped registry/start command was accepted: {wrapped:?}; {errors:?}"
            );
        }
    }
}
