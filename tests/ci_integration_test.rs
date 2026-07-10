//! Structural assertions for the GitHub Actions pipeline that gates `main`.
//!
//! The CI definition lives in `.github/workflows/ci.yml`; the GitHub Pages
//! deploy in `.github/workflows/static.yml` is gated on it via `workflow_run`.
//! These tests preserve the repo convention that the pipeline structure is
//! asserted by `cargo test` (previously against the now-deleted
//! `deploy/ci/azure-pipelines.yml`).

const CI_WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
const PAGES_WORKFLOW_PATH: &str = ".github/workflows/static.yml";

fn load_workflow(path: &str) -> serde_json::Value {
    let content = std::fs::read_to_string(path).unwrap();
    serde_yaml::from_str(&content).unwrap()
}

/// GitHub workflow trigger block. serde_yaml 0.9 keeps a plain `on:` key as the
/// string "on", but fall back to "true" in case a YAML-1.1 resolver is ever used.
fn triggers(workflow: &serde_json::Value) -> &serde_json::Value {
    workflow
        .get("on")
        .or_else(|| workflow.get("true"))
        .expect("workflow has no trigger block")
}

fn job<'a>(workflow: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    workflow["jobs"]
        .get(name)
        .unwrap_or_else(|| panic!("missing job: {name}"))
}

/// Concatenation of all `run:` step scripts in a job.
fn job_run_text(job: &serde_json::Value) -> String {
    job["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|step| step["run"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// All `uses:` action references in a job.
fn job_uses(job: &serde_json::Value) -> Vec<String> {
    job["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|step| step["uses"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn ci_workflow_is_valid_yaml() {
    let workflow = load_workflow(CI_WORKFLOW_PATH);
    assert_eq!(workflow["name"].as_str(), Some("CI"));
    assert!(workflow.get("jobs").is_some());
    assert!(
        workflow.get("on").is_some() || workflow.get("true").is_some(),
        "missing trigger block"
    );
}

#[test]
fn ci_triggers_on_push_and_pull_request_to_main() {
    let workflow = load_workflow(CI_WORKFLOW_PATH);
    let on = triggers(&workflow);

    for event in ["push", "pull_request"] {
        let branches: Vec<&str> = on[event]["branches"]
            .as_array()
            .unwrap_or_else(|| panic!("missing {event} branches"))
            .iter()
            .map(|b| b.as_str().unwrap())
            .collect();
        assert!(branches.contains(&"main"), "{event} must target main");
    }
}

#[test]
fn ci_has_required_jobs() {
    let workflow = load_workflow(CI_WORKFLOW_PATH);
    let jobs = workflow["jobs"].as_object().unwrap();

    for required in ["build-test", "lint", "security", "validate", "images"] {
        assert!(jobs.contains_key(required), "missing job: {required}");
    }
}

#[test]
fn build_test_job_builds_and_tests_whole_workspace() {
    let workflow = load_workflow(CI_WORKFLOW_PATH);
    let build_test = job(&workflow, "build-test");
    let run_text = job_run_text(build_test);

    assert!(run_text.contains("cargo build --workspace"));
    assert!(run_text.contains("cargo test --workspace"));
}

#[test]
fn rust_jobs_use_pinned_toolchain_and_cache() {
    let workflow = load_workflow(CI_WORKFLOW_PATH);

    for name in ["build-test", "lint", "validate"] {
        let uses = job_uses(job(&workflow, name));
        assert!(
            uses.iter().any(|u| u.contains("dtolnay/rust-toolchain")),
            "{name} must install the Rust toolchain"
        );
        assert!(
            uses.iter().any(|u| u.contains("Swatinem/rust-cache")),
            "{name} must use the cargo cache"
        );
    }
}

#[test]
fn lint_job_has_fmt_and_clippy() {
    let workflow = load_workflow(CI_WORKFLOW_PATH);
    let run_text = job_run_text(job(&workflow, "lint"));

    assert!(run_text.contains("cargo fmt --check --all"));
    assert!(run_text.contains("cargo clippy --workspace"));
}

#[test]
fn security_job_runs_ripgrep_secret_scan() {
    let workflow = load_workflow(CI_WORKFLOW_PATH);
    let run_text = job_run_text(job(&workflow, "security"));

    assert!(run_text.contains("./scripts/no-secret-scan.sh"));
    assert!(run_text.contains("ripgrep"), "scan requires ripgrep");
}

#[test]
fn validate_job_runs_validator_as_a_hard_gate() {
    let workflow = load_workflow(CI_WORKFLOW_PATH);
    let validate = job(&workflow, "validate");
    let run_text = job_run_text(validate);

    assert!(
        run_text.contains("cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all"),
        "validate job must run the validator run-all dispatcher"
    );
    assert!(
        run_text.contains("--root"),
        "run-all exits with a usage error unless --root is passed"
    );
    assert!(
        !run_text.contains("|| true"),
        "validator failures must not be shell-masked"
    );
    assert!(
        validate["continue-on-error"].is_null(),
        "validator failures must fail the CI job; continue-on-error is forbidden"
    );
}

#[test]
fn images_job_runs_only_on_main_push_and_needs_build_test() {
    let workflow = load_workflow(CI_WORKFLOW_PATH);
    let images = job(&workflow, "images");

    let condition = images["if"].as_str().unwrap();
    assert!(
        condition.contains("github.event_name == 'push'"),
        "images job must be restricted to push events"
    );
    assert!(
        condition.contains("refs/heads/main"),
        "images job must be restricted to main"
    );

    let needs = &images["needs"];
    let needs_build_test = needs.as_str() == Some("build-test")
        || needs
            .as_array()
            .is_some_and(|n| n.iter().any(|v| v.as_str() == Some("build-test")));
    assert!(needs_build_test, "images job must depend on build-test");
}

#[test]
fn images_job_builds_both_dockerfiles_from_root_context() {
    let workflow = load_workflow(CI_WORKFLOW_PATH);
    let images = job(&workflow, "images");

    let build_commands: Vec<&str> = images["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|step| step["run"].as_str())
        .filter(|run| run.contains("docker build"))
        .map(str::trim)
        .collect();

    for dockerfile in [
        "sources/ryuki-api/Dockerfile",
        "portal/portal-ui/Dockerfile",
    ] {
        let command = build_commands
            .iter()
            .find(|c| c.contains(&format!("-f {dockerfile}")))
            .unwrap_or_else(|| panic!("no docker build for {dockerfile}"));
        assert!(
            command.ends_with(" .") || command.ends_with(" ./"),
            "build for {dockerfile} must use root context '.': {command}"
        );
    }

    // CI builds images but never pushes them; releases are a separate concern.
    let run_text = job_run_text(images);
    assert!(
        !run_text.contains("docker push") && !run_text.contains("docker login"),
        "CI must not push images or log into registries"
    );
}

#[test]
fn ci_workflow_has_no_hardcoded_secrets() {
    let content = std::fs::read_to_string(CI_WORKFLOW_PATH).unwrap();

    let secret_assignment_patterns = [
        "password:",
        "password=",
        "secret:",
        "secret=",
        "token:",
        "token=",
        "credential:",
        "credential=",
    ];

    for line in content.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        // skip comments and step labels
        if lower.starts_with('#') || lower.starts_with("name:") || lower.starts_with("- name:") {
            continue;
        }

        for pattern in &secret_assignment_patterns {
            if lower.contains(pattern) {
                let after_pattern = lower.split(pattern).nth(1).unwrap_or("").trim();
                // only flag non-empty literal values that are not expression references
                if !after_pattern.is_empty() && !after_pattern.starts_with("${{") {
                    panic!("Potential hardcoded secret on line: {line}");
                }
            }
        }
    }
}

#[test]
fn azure_pipeline_definition_is_deleted() {
    assert!(
        !std::path::Path::new("deploy/ci/azure-pipelines.yml").exists(),
        "the unregistered Azure DevOps pipeline must stay deleted; CI lives in {CI_WORKFLOW_PATH}"
    );
}

#[test]
fn pages_deploy_is_gated_on_ci_workflow_run() {
    let workflow = load_workflow(PAGES_WORKFLOW_PATH);
    let on = triggers(&workflow);

    let workflow_run = on
        .get("workflow_run")
        .expect("static.yml must trigger via workflow_run");

    let gating_workflows: Vec<&str> = workflow_run["workflows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect();
    assert!(
        gating_workflows.contains(&"CI"),
        "Pages deploy must be gated on the CI workflow"
    );

    let branches: Vec<&str> = workflow_run["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_str().unwrap())
        .collect();
    assert!(branches.contains(&"main"));

    let deploy_condition = job(&workflow, "deploy")["if"].as_str().unwrap();
    assert!(
        deploy_condition.contains("github.event.workflow_run.conclusion == 'success'"),
        "deploy job must require a successful CI conclusion"
    );

    // Direct pushes to main must not trigger an ungated deploy anymore.
    assert!(
        on.get("push").is_none(),
        "static.yml must not deploy directly on push; CI gates the deploy"
    );
}

#[test]
fn pages_deploy_keeps_permissions_and_concurrency() {
    let workflow = load_workflow(PAGES_WORKFLOW_PATH);

    let permissions = workflow["permissions"].as_object().unwrap();
    assert_eq!(permissions["contents"].as_str(), Some("read"));
    assert_eq!(permissions["pages"].as_str(), Some("write"));
    assert_eq!(permissions["id-token"].as_str(), Some("write"));

    assert_eq!(
        workflow["concurrency"]["group"].as_str(),
        Some("pages"),
        "Pages deploys must keep the serialized concurrency group"
    );
    assert_eq!(
        workflow["concurrency"]["cancel-in-progress"].as_bool(),
        Some(false)
    );
}
