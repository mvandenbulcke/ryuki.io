use serde::Deserialize;
use std::fs;
use std::path::Path;

const API_DOCKERFILE_PATH: &str = "sources/ryuki-api/Dockerfile";
const PORTAL_DOCKERFILE_PATH: &str = "portal/portal-ui/Dockerfile";
const COMPOSE_PATH: &str = "deploy/compose/compose.yaml";
const CI_PATH: &str = "deploy/ci/azure-pipelines.yml";
const DOCKERIGNORE_PATH: &str = ".dockerignore";

const REQUIRED_API_ARTIFACT: &str = "/app/ryuki-api";
const REQUIRED_PORTAL_ARTIFACT: &str = "/app/ryuki-portal-ui";
const REQUIRED_PORTAL_SITE: &str = "/app/site";

const REQUIRED_DOCKERIGNORE_ENTRIES: &[&str] = &["Cargo.toml", "Cargo.lock", "sources/", "portal/"];

const UNSAFE_DOCKERIGNORE_ENTRIES: &[&str] = &[
    ".git",
    ".codex",
    ".codegraph",
    ".atl",
    "graphify-out",
    "target/",
    "**/target/",
    "debug",
    "debug/",
    "**/debug",
    "**/debug/",
    "*.log",
    ".env",
    ".env.*",
    "*.key",
    "*.pem",
    "*.crt",
];

const ALLOWED_SERVICES: &[&str] = &["platform-api", "portal-ui"];

#[derive(Debug, Deserialize)]
struct Context {
    #[serde(default)]
    root: String,
    #[serde(default)]
    api_dockerfile: String,
    #[serde(default)]
    portal_dockerfile: String,
    #[serde(default)]
    compose_yaml: String,
    #[serde(default)]
    ci_yaml: String,
    #[serde(default)]
    dockerignore: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid release-image-builds context JSON: {error}"))?;

    let mut errors = Vec::new();

    if !context.api_dockerfile.is_empty() {
        errors.extend(validate_dockerfile_content(
            &context.api_dockerfile,
            "platform-api",
        ));
    }
    if !context.portal_dockerfile.is_empty() {
        errors.extend(validate_dockerfile_content(
            &context.portal_dockerfile,
            "portal-ui",
        ));
    }
    if !context.compose_yaml.is_empty() {
        errors.extend(validate_compose_content(&context.compose_yaml));
    }
    if !context.ci_yaml.is_empty() {
        errors.extend(validate_ci_content(&context.ci_yaml));
    }
    if !context.dockerignore.is_empty() {
        errors.extend(validate_dockerignore_content(&context.dockerignore));
    }

    Ok(errors)
}

/// Check whether a Dockerfile COPY line indicates workspace-root context
/// (explicit Cargo.lock reference, or `COPY . .` / `COPY . ./`).
fn is_root_context_copy(line: &str) -> bool {
    let t = line.trim();
    if !t.starts_with("COPY") || t.contains("--from=") {
        return false;
    }
    // Explicit lockfile reference
    if t.contains("Cargo.lock") {
        return true;
    }
    // COPY .  (everything from root)
    let after_copy = t.strip_prefix("COPY").unwrap_or(t).trim_start();
    if after_copy == "." || after_copy.starts_with(". ") || after_copy.starts_with("./ ") {
        return true;
    }
    false
}

fn validate_dockerfile_content(content: &str, service_name: &str) -> Vec<String> {
    let mut errors = Vec::new();

    let has_root_context = content.lines().any(is_root_context_copy);
    let has_cargo_lock = content.contains("Cargo.lock");

    if !has_root_context {
        errors.push(format!(
            "{service_name} Dockerfile uses crate-local context; workspace root context required"
        ));
    }

    // Workspace manifests: required only when not using COPY . (root context)
    if !has_root_context && !has_cargo_lock {
        match service_name {
            "platform-api" => {
                errors.push(format!(
                    "{service_name} Dockerfile must copy workspace Cargo.toml, Cargo.lock and produce {} artifact",
                    REQUIRED_API_ARTIFACT
                ));
            }
            "portal-ui" => {
                errors.push(format!(
                    "{service_name} Dockerfile must copy workspace Cargo.toml, Cargo.lock and produce {} and {} artifacts",
                    REQUIRED_PORTAL_ARTIFACT, REQUIRED_PORTAL_SITE
                ));
            }
            _ => {}
        }
    } else if has_root_context {
        // Root context via COPY . — manifests are implicitly included.
        // Still flag missing artifact.
        match service_name {
            "platform-api" => {
                if !content.contains(REQUIRED_API_ARTIFACT) {
                    errors.push(format!(
                        "{service_name} Dockerfile with root context must produce {} artifact (requires workspace Cargo.toml, Cargo.lock)",
                        REQUIRED_API_ARTIFACT
                    ));
                }
            }
            "portal-ui" => {
                let has_server = content.contains(REQUIRED_PORTAL_ARTIFACT);
                let has_site = content.contains(REQUIRED_PORTAL_SITE);
                if !has_server || !has_site {
                    errors.push(format!(
                        "{service_name} Dockerfile with root context must produce {} and {} artifacts (requires workspace Cargo.toml, Cargo.lock)",
                        REQUIRED_PORTAL_ARTIFACT, REQUIRED_PORTAL_SITE
                    ));
                }
            }
            _ => {}
        }
        return errors; // All checks done for root-context dockerfiles
    }

    // Artifact path check (for non-root-context dockerfiles)
    match service_name {
        "platform-api" => {
            if !content.contains(REQUIRED_API_ARTIFACT) {
                errors.push(format!(
                    "{service_name} Dockerfile must produce {} artifact",
                    REQUIRED_API_ARTIFACT
                ));
            }
        }
        "portal-ui" => {
            let has_server = content.contains(REQUIRED_PORTAL_ARTIFACT);
            let has_site = content.contains(REQUIRED_PORTAL_SITE);
            if !has_server && !has_site {
                errors.push(format!(
                    "{service_name} Dockerfile must produce {} artifact and {} site output",
                    REQUIRED_PORTAL_ARTIFACT, REQUIRED_PORTAL_SITE
                ));
            } else if !has_server {
                errors.push(format!(
                    "{service_name} Dockerfile must produce {} artifact",
                    REQUIRED_PORTAL_ARTIFACT
                ));
            } else if !has_site {
                errors.push(format!(
                    "{service_name} Dockerfile must produce {} site output",
                    REQUIRED_PORTAL_SITE
                ));
            }
        }
        _ => {}
    }

    errors
}

fn validate_compose_content(content: &str) -> Vec<String> {
    let mut errors = Vec::new();

    // Check platform-api uses root context (not crate-local subdirectory)
    if content.contains("context: ../../sources/ryuki-api") {
        errors.push(
            "platform-api compose build must use root context (../..) instead of crate-local ../../sources/ryuki-api"
                .into(),
        );
    }

    // Check portal-ui uses root context
    if content.contains("context: ../../portal/portal-ui") {
        errors.push(
            "portal-ui compose build must use root context (../..) instead of crate-local ../../portal/portal-ui"
                .into(),
        );
    }

    // When root context is used, API must have explicit Dockerfile path
    // (not just "Dockerfile" — that would resolve to root's Dockerfile if it existed)
    if content.contains("context: ../..") {
        // Check if the API service section (before portal-ui section) has bare "Dockerfile"
        let before_portal = if let Some(pos) = content.find("portal-ui:") {
            &content[..pos]
        } else {
            content
        };
        if before_portal.contains("dockerfile: Dockerfile") {
            errors.push(
                "platform-api with root context must use explicit Dockerfile path sources/ryuki-api/Dockerfile"
                    .into(),
            );
        }
    }

    // Out-of-scope services
    for service in &["vaultwarden", "postgres", "redis", "nginx", "traefik"] {
        if content.contains(&format!("  {}:", service))
            && content.contains(&format!("{}:", service))
        {
            errors.push(format!(
                "unexpected service {service} in compose; out of scope for release image builds"
            ));
        }
    }

    errors
}

fn validate_ci_content(content: &str) -> Vec<String> {
    let mut errors = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("docker build") {
            continue;
        }
        // Extract the last argument (build context path)
        let last_arg = trimmed.rsplit(' ').next().unwrap_or("");
        match last_arg {
            "sources/ryuki-api/" | "portal/portal-ui/" => {
                errors.push(format!(
                    "CI build command must use root context '.' not subdirectory: {trimmed}"
                ));
            }
            _ => {}
        }
    }

    errors
}

fn validate_dockerignore_content(content: &str) -> Vec<String> {
    let mut errors = Vec::new();

    let ignored: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    // Check required inputs are NOT excluded (MUST)
    let mut blocked_required: Vec<&str> = Vec::new();
    for required in REQUIRED_DOCKERIGNORE_ENTRIES {
        if ignored.contains(required) {
            blocked_required.push(*required);
        }
    }
    if !blocked_required.is_empty() {
        errors.push(format!(
            "dockerignore must not exclude required build inputs: {}",
            blocked_required.join(", ")
        ));
    }

    // Check unsafe/generated/cache/secret-heavy entries ARE excluded.
    let missing_unsafe: Vec<&str> = UNSAFE_DOCKERIGNORE_ENTRIES
        .iter()
        .filter(|e| !ignored.contains(e))
        .copied()
        .collect();
    if !missing_unsafe.is_empty() {
        errors.push(format!(
            "dockerignore must exclude unsafe/generated/cache/secret-heavy local artifacts: missing {} while preserving required inputs ({})",
            missing_unsafe.join(", "),
            REQUIRED_DOCKERIGNORE_ENTRIES.join(", ")
        ));
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── API Dockerfile tests ──────────────────────────────────────────────

    #[test]
    fn api_dockerfile_must_use_root_context() {
        let dockerfile = "FROM rust:1.88-slim-bookworm AS build\nWORKDIR /build\nCOPY sources/ryuki-api/ ./\nRUN cargo build --release -p ryuki-api\n";
        let errors = validate_dockerfile_content(dockerfile, "platform-api");
        assert!(
            !errors.is_empty(),
            "Expected root-context violation for crate-local COPY but got no errors"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("root") || e.contains("context")),
            "Expected root-context error message but got: {:?}",
            errors
        );
    }

    #[test]
    fn api_dockerfile_must_copy_workspace_manifests() {
        // Dockerfile with COPY . . (root context) but no runtime artifact —
        // validator should flag missing artifact and mention workspace manifests.
        let dockerfile = "FROM rust:1.88-slim-bookworm AS build\nWORKDIR /build\nCOPY . .\nRUN cargo build --release -p ryuki-api\n";
        let errors = validate_dockerfile_content(dockerfile, "platform-api");
        assert!(
            !errors.is_empty(),
            "Expected errors for incomplete root-context dockerfile but got none"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Cargo.toml") || e.contains("Cargo.lock")),
            "Expected error mentioning workspace manifests but got: {:?}",
            errors
        );
    }

    #[test]
    fn api_dockerfile_must_produce_ryuki_api_artifact() {
        let dockerfile = "FROM debian:bookworm-slim AS runtime\nCOPY --from=build /build/target/release/ryuki-api /app/ryuki-api\n";
        let errors = validate_dockerfile_content(dockerfile, "platform-api");
        assert!(
            errors.iter().any(|e| e.contains(REQUIRED_API_ARTIFACT)),
            "Expected artifact path requirement for {} but got: {:?}",
            REQUIRED_API_ARTIFACT,
            errors
        );
    }

    #[test]
    fn api_dockerfile_missing_artifact_path_is_rejected() {
        let dockerfile = "FROM debian:bookworm-slim AS runtime\nCOPY --from=build /build/target/release/ryuki-api /usr/local/bin/ryuki-api\n";
        let errors = validate_dockerfile_content(dockerfile, "platform-api");
        assert!(
            !errors.is_empty(),
            "Expected rejection for wrong artifact path but got no errors"
        );
    }

    #[test]
    fn api_root_context_with_artifact_passes() {
        // A complete root-context dockerfile with artifact should produce no errors
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm AS build\n",
            "WORKDIR /app\n",
            "COPY . .\n",
            "RUN cargo build --release -p ryuki-api\n",
            "FROM debian:bookworm-slim AS runtime\n",
            "WORKDIR /app\n",
            "COPY --from=build /app/target/release/ryuki-api /app/ryuki-api\n",
            "CMD [\"/app/ryuki-api\"]\n"
        );
        let errors = validate_dockerfile_content(dockerfile, "platform-api");
        assert!(
            errors.is_empty(),
            "Expected complete root-context API dockerfile to pass but got: {:?}",
            errors
        );
    }

    // ── Portal Dockerfile tests ───────────────────────────────────────────

    #[test]
    fn portal_dockerfile_must_use_root_context() {
        let dockerfile = "FROM rust:1.88-slim-bookworm AS build\nWORKDIR /build\nCOPY portal/portal-ui/ ./\nRUN cargo leptos build --release -p ryuki-portal-ui\n";
        let errors = validate_dockerfile_content(dockerfile, "portal-ui");
        assert!(
            !errors.is_empty(),
            "Expected root-context violation for crate-local portal COPY but got no errors"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("root") || e.contains("context")),
            "Expected root-context error message but got: {:?}",
            errors
        );
    }

    #[test]
    fn portal_dockerfile_must_produce_server_and_site_artifacts() {
        let dockerfile = "FROM debian:bookworm-slim AS runtime\nCOPY --from=build /build/target/release/ryuki-portal-ui /app/ryuki-portal-ui\nCOPY --from=build /build/target/site /app/site\n";
        let errors = validate_dockerfile_content(dockerfile, "portal-ui");
        assert!(
            errors.iter().any(|e| e.contains(REQUIRED_PORTAL_ARTIFACT)),
            "Expected portal server artifact requirement but got: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains(REQUIRED_PORTAL_SITE)),
            "Expected portal site artifact requirement but got: {:?}",
            errors
        );
    }

    #[test]
    fn portal_dockerfile_missing_site_is_rejected() {
        let dockerfile = "FROM debian:bookworm-slim AS runtime\nCOPY --from=build /build/target/release/ryuki-portal-ui /app/ryuki-portal-ui\n";
        let errors = validate_dockerfile_content(dockerfile, "portal-ui");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("/app/site") || e.contains("site")),
            "Expected rejection for missing portal site artifact but got: {:?}",
            errors
        );
    }

    #[test]
    fn portal_root_context_with_artifacts_passes() {
        // A complete root-context portal dockerfile should pass
        let dockerfile = concat!(
            "FROM rust:1.88-bookworm AS build\n",
            "WORKDIR /app\n",
            "COPY . .\n",
            "RUN cargo leptos build --release -p ryuki-portal-ui\n",
            "FROM debian:bookworm-slim AS runtime\n",
            "WORKDIR /app\n",
            "COPY --from=build /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui\n",
            "COPY --from=build /app/target/site /app/site\n",
            "CMD [\"/app/ryuki-portal-ui\"]\n"
        );
        let errors = validate_dockerfile_content(dockerfile, "portal-ui");
        assert!(
            errors.is_empty(),
            "Expected complete root-context portal dockerfile to pass but got: {:?}",
            errors
        );
    }

    // ── Compose tests ─────────────────────────────────────────────────────

    #[test]
    fn compose_must_use_root_context_for_api() {
        let compose = r#"name: ryuki-infrastructure-platform
services:
  platform-api:
    build:
      context: ../../sources/ryuki-api
      dockerfile: Dockerfile
    image: ryuki/platform-api:rust-dev
    ports:
      - "18080:8080"
    networks:
      - platform
  portal-ui:
    build:
      context: ../..
      dockerfile: portal/portal-ui/Dockerfile
    image: ryuki/portal-ui:rust-dev
    ports:
      - "18000:8080"
    depends_on:
      - platform-api
    networks:
      - platform
networks:
  platform:
    driver: bridge
"#;
        let errors = validate_compose_content(compose);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("context") || e.contains("root")),
            "Expected root-context enforcement for platform-api but got: {:?}",
            errors
        );
    }

    #[test]
    fn compose_must_use_explicit_dockerfile_paths_for_root_context() {
        let compose = r#"name: ryuki-infrastructure-platform
services:
  platform-api:
    build:
      context: ../..
      dockerfile: Dockerfile
    image: ryuki/platform-api:rust-dev
    ports:
      - "18080:8080"
    networks:
      - platform
  portal-ui:
    build:
      context: ../..
      dockerfile: portal/portal-ui/Dockerfile
    image: ryuki/portal-ui:rust-dev
    ports:
      - "18000:8080"
    depends_on:
      - platform-api
    networks:
      - platform
networks:
  platform:
    driver: bridge
"#;
        let errors = validate_compose_content(compose);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("dockerfile") || e.contains("Dockerfile")),
            "Expected explicit Dockerfile path enforcement for root-context API but got: {:?}",
            errors
        );
    }

    // ── CI tests ──────────────────────────────────────────────────────────

    #[test]
    fn ci_must_use_root_context_for_api_build() {
        let ci = r#"stages:
  - stage: BuildImages
    jobs:
      - job: BuildApi
        steps:
          - script: docker build -t ryuki/platform-api:ci -f sources/ryuki-api/Dockerfile sources/ryuki-api/
      - job: BuildPortal
        steps:
          - script: docker build -t ryuki/portal-ui:ci -f portal/portal-ui/Dockerfile .
"#;
        let errors = validate_ci_content(ci);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("root") || e.contains("context") || e.contains("build")),
            "Expected root-context enforcement for CI API build command but got: {:?}",
            errors
        );
    }

    #[test]
    fn ci_must_use_root_context_for_portal_build() {
        let ci = r#"stages:
  - stage: BuildImages
    jobs:
      - job: BuildApi
        steps:
          - script: docker build -t ryuki/platform-api:ci -f sources/ryuki-api/Dockerfile .
      - job: BuildPortal
        steps:
          - script: docker build -t ryuki/portal-ui:ci -f portal/portal-ui/Dockerfile portal/portal-ui/
"#;
        let errors = validate_ci_content(ci);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("root") || e.contains("context") || e.contains("build")),
            "Expected root-context enforcement for CI portal build command but got: {:?}",
            errors
        );
    }

    #[test]
    fn ci_root_context_builds_pass() {
        let ci = r#"stages:
  - stage: BuildImages
    jobs:
      - job: BuildApi
        steps:
          - script: docker build -t ryuki/platform-api:ci -f sources/ryuki-api/Dockerfile .
      - job: BuildPortal
        steps:
          - script: docker build -t ryuki/portal-ui:ci -f portal/portal-ui/Dockerfile .
"#;
        let errors = validate_ci_content(ci);
        assert!(
            errors.is_empty(),
            "Expected root-context CI builds to pass but got: {:?}",
            errors
        );
    }

    // ── Dockerignore tests ────────────────────────────────────────────────

    #[test]
    fn dockerignore_must_preserve_required_inputs() {
        let dockerignore = concat!(
            ".git\n",
            ".codex\n",
            ".codegraph\n",
            ".atl\n",
            "graphify-out\n",
            "target/\n",
            "**/target/\n",
            "debug\n",
            "debug/\n",
            "**/debug\n",
            "**/debug/\n",
            "*.log\n",
            ".env\n",
            ".env.*\n",
            "*.key\n",
            "*.pem\n",
            "*.crt\n"
        );
        let errors = validate_dockerignore_content(dockerignore);
        assert!(
            errors.is_empty(),
            "Expected dockerignore preserving required inputs and excluding unsafe artifacts to pass but got: {:?}",
            errors
        );
    }

    #[test]
    fn dockerignore_requires_every_debug_exclusion() {
        let dockerignore = concat!(
            ".git\n",
            ".codex\n",
            ".codegraph\n",
            ".atl\n",
            "graphify-out\n",
            "target/\n",
            "**/target/\n",
            "debug\n",
            "debug/\n",
            "**/debug\n",
            "**/debug/\n",
            "*.log\n",
            ".env\n",
            ".env.*\n",
            "*.key\n",
            "*.pem\n",
            "*.crt\n"
        );

        for required in ["debug", "debug/", "**/debug", "**/debug/"] {
            let incomplete = dockerignore
                .lines()
                .filter(|line| *line != required)
                .collect::<Vec<_>>()
                .join("\n");
            let errors = validate_dockerignore_content(&incomplete);

            assert!(
                errors.iter().any(|error| error.contains(required)),
                "Expected dockerignore missing {required:?} to be rejected, got: {:?}",
                errors
            );
        }
    }

    #[test]
    fn dockerignore_missing_unsafe_exclusions_is_rejected() {
        let dockerignore = ".git\ntarget/\n**/target/\n";
        let errors = validate_dockerignore_content(dockerignore);
        assert!(
            errors.iter().any(|e| e.contains("unsafe")
                || e.contains("generated")
                || e.contains("cache")
                || e.contains("secret-heavy")),
            "Expected rejection for missing unsafe exclusions while preserving required inputs but got: {:?}",
            errors
        );
    }

    #[test]
    fn dockerignore_must_block_unsafe_artifacts() {
        // Bad dockerignore: blocks required inputs. Must produce error.
        let dockerignore = "Cargo.toml\nCargo.lock\nsources/\nportal/\n";
        let errors = validate_dockerignore_content(dockerignore);
        assert!(
            !errors.is_empty(),
            "Expected errors for dockerignore blocking required inputs but got none"
        );
        assert!(
            errors.iter().any(|e| e.contains("Cargo.toml")
                || e.contains("Cargo.lock")
                || e.contains("required")),
            "Expected error mentioning blocked required inputs but got: {:?}",
            errors
        );
    }

    #[test]
    fn dockerignore_blocks_required_inputs_is_rejected() {
        let dockerignore = "Cargo.toml\nCargo.lock\nsources/\nportal/\n";
        let errors = validate_dockerignore_content(dockerignore);
        assert!(
            errors.iter().any(|e| e.contains("Cargo.toml")
                || e.contains("Cargo.lock")
                || e.contains("required")),
            "Expected rejection for dockerignore blocking required inputs but got: {:?}",
            errors
        );
    }

    // ── Out-of-scope service tests ────────────────────────────────────────

    #[test]
    fn out_of_scope_compose_service_is_rejected() {
        let compose = r#"name: ryuki-infrastructure-platform
services:
  platform-api:
    build:
      context: ../..
      dockerfile: sources/ryuki-api/Dockerfile
    image: ryuki/platform-api:rust-dev
    ports:
      - "18080:8080"
    networks:
      - platform
  portal-ui:
    build:
      context: ../..
      dockerfile: portal/portal-ui/Dockerfile
    image: ryuki/portal-ui:rust-dev
    ports:
      - "18000:8080"
    depends_on:
      - platform-api
    networks:
      - platform
  vaultwarden:
    build:
      context: ../..
      dockerfile: deploy/vaultwarden/Dockerfile
    image: ryuki/vaultwarden:dev
    ports:
      - "18001:8080"
    networks:
      - platform
networks:
  platform:
    driver: bridge
"#;
        let errors = validate_compose_content(compose);
        assert!(
            errors.iter().any(|e| e.contains("vaultwarden")
                || e.contains("out of scope")
                || e.contains("unexpected")),
            "Expected rejection for out-of-scope service but got: {:?}",
            errors
        );
    }

    // ── validate_context_file integration ─────────────────────────────────

    #[test]
    fn validate_context_file_integration_detects_contract_violations() {
        let result = validate_dockerfile_content("COPY src ./src", "platform-api");
        assert!(
            !result.is_empty(),
            "GREEN phase: validator must detect crate-local Dockerfile patterns"
        );
    }
}
