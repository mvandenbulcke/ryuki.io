#[test]
fn azure_pipelines_is_valid_yaml() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();
    assert!(parsed.get("stages").is_some());
    assert!(parsed.get("trigger").is_some());
}

#[test]
fn pipeline_has_build_test_and_deploy_stages() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();

    let stages = parsed["stages"].as_array().unwrap();
    let stage_names: Vec<&str> = stages
        .iter()
        .map(|s| s["stage"].as_str().unwrap_or(""))
        .collect();

    assert!(
        stage_names.contains(&"BuildTest"),
        "Missing BuildTest stage"
    );
    assert!(
        stage_names.contains(&"BuildImages"),
        "Missing BuildImages stage"
    );
    assert!(
        stage_names.contains(&"PushImages"),
        "Missing PushImages stage"
    );
}

#[test]
fn build_test_stage_has_required_jobs() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();

    let stage = parsed["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stage"].as_str() == Some("BuildTest"))
        .unwrap();
    let jobs = stage["jobs"].as_array().unwrap();
    let job_names: Vec<&str> = jobs.iter().map(|j| j["job"].as_str().unwrap()).collect();

    assert!(job_names.contains(&"Rust"), "Missing Rust job");
    assert!(job_names.contains(&"Security"), "Missing Security job");
    assert!(job_names.contains(&"Lint"), "Missing Lint job");
}

#[test]
fn pipeline_has_cargo_build_and_test() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();
    assert!(content.contains("cargo build --workspace"));
    assert!(content.contains("cargo test --workspace"));
}

#[test]
fn pipeline_had_no_hardcoded_secrets() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();

    let secret_assignment_patterns = [
        "password:",
        "password=",
        "secret:",
        "secret=",
        "token:",
        "token=",
        "key:",
        "key=",
        "credential:",
        "credential=",
    ];

    for line in content.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        // skip comments, metadata labels, pipeline variable references
        if lower.starts_with('#') || lower.starts_with("displayname") || lower.starts_with("name") {
            continue;
        }

        for pattern in &secret_assignment_patterns {
            if lower.contains(pattern) {
                let after_pattern = lower.split(pattern).nth(1).unwrap_or("").trim();
                // only flag if the value after the pattern is non-empty and not a variable reference
                if !after_pattern.is_empty()
                    && !after_pattern.starts_with("$(")
                    && !after_pattern.starts_with("placeholder")
                    && !after_pattern.starts_with("tls-")
                {
                    panic!("Potential hardcoded secret on line: {line}");
                }
            }
        }
    }
}

#[test]
fn pipeline_triggers_on_main_branch() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();

    let trigger_branches: Vec<&str> = parsed["trigger"]["branches"]["include"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_str().unwrap())
        .collect();
    assert!(trigger_branches.contains(&"main"));

    let pr_branches: Vec<&str> = parsed["pr"]["branches"]["include"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_str().unwrap())
        .collect();
    assert!(pr_branches.contains(&"main"));
}

#[test]
fn pipeline_variables_use_pipeline_secrets() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();

    let vars = parsed["variables"].as_object().unwrap();
    assert!(vars.contains_key("CONTAINER_REGISTRY"));
    assert!(vars.contains_key("CONTAINER_REGISTRY_USERNAME"));

    for (key, val) in vars {
        let val_str = val.as_str().unwrap_or("");
        assert!(
            val_str.starts_with("$(")
                || val_str.is_empty()
                || val_str == "CONTAINER_REGISTRY_PASSWORD",
            "Variable {} value appears hardcoded: {val_str}",
            key
        );
    }
}

#[test]
fn push_images_stage_only_runs_on_main() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();

    let push_stage = parsed["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stage"].as_str() == Some("PushImages"))
        .unwrap();

    let condition = push_stage["condition"].as_str().unwrap();
    assert!(
        condition.contains("refs/heads/main"),
        "PushImages must only run on main branch"
    );
}

#[test]
fn pipeline_has_ripgrep_secret_scan() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();
    assert!(content.contains("./scripts/no-secret-scan.sh"));
    assert!(content.contains("ripgrep"));
}

#[test]
fn pipeline_has_fmt_and_clippy() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();
    assert!(content.contains("cargo fmt --check --all"));
    assert!(content.contains("cargo clippy --workspace"));
}

#[test]
fn build_images_stage_uses_root_context() {
    let content = std::fs::read_to_string("deploy/ci/azure-pipelines.yml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();

    let build_stage = parsed["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stage"].as_str() == Some("BuildImages"))
        .unwrap();

    let jobs = build_stage["jobs"].as_array().unwrap();

    // Check API build: `-f sources/ryuki-api/Dockerfile .` (root context)
    let api_job = jobs
        .iter()
        .find(|j| j["job"].as_str() == Some("BuildApi"))
        .unwrap();
    let api_steps = api_job["steps"].as_array().unwrap();
    let api_script = api_steps[0]["script"].as_str().unwrap().trim();
    assert!(
        api_script.contains("-f sources/ryuki-api/Dockerfile"),
        "API build must use explicit Dockerfile path"
    );
    assert!(
        api_script.ends_with(" .") || api_script.ends_with(" ./"),
        "API build must use root context '.' not subdirectory: {}",
        api_script
    );

    // Check Portal build: `-f portal/portal-ui/Dockerfile .` (root context)
    let portal_job = jobs
        .iter()
        .find(|j| j["job"].as_str() == Some("BuildPortal"))
        .unwrap();
    let portal_steps = portal_job["steps"].as_array().unwrap();
    let portal_script = portal_steps[0]["script"].as_str().unwrap().trim();
    assert!(
        portal_script.contains("-f portal/portal-ui/Dockerfile"),
        "Portal build must use explicit Dockerfile path"
    );
    assert!(
        portal_script.ends_with(" .") || portal_script.ends_with(" ./"),
        "Portal build must use root context '.' not subdirectory: {}",
        portal_script
    );
}
