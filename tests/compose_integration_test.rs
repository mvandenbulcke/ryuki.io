#[test]
fn compose_file_is_valid_yaml() {
    let content = std::fs::read_to_string("deploy/compose/compose.yaml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();
    assert!(
        parsed
            .get("services")
            .unwrap()
            .get("platform-api")
            .is_some()
    );
    assert!(parsed.get("services").unwrap().get("portal-ui").is_some());
}

#[test]
fn compose_services_have_required_keys() {
    let content = std::fs::read_to_string("deploy/compose/compose.yaml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();
    let api = &parsed["services"]["platform-api"];
    assert!(api.get("build").is_some());
    assert!(api.get("ports").is_some());
    assert!(api.get("networks").is_some());
    assert!(api.get("healthcheck").is_some());

    let portal = &parsed["services"]["portal-ui"];
    assert!(portal.get("build").is_some());
    assert!(portal.get("ports").is_some());
    assert!(portal.get("depends_on").is_some());
    assert!(portal.get("healthcheck").is_some());
}

#[test]
fn compose_network_is_bridge() {
    let content = std::fs::read_to_string("deploy/compose/compose.yaml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();
    assert_eq!(parsed["networks"]["ryuki-net"]["driver"], "bridge");
}

#[test]
fn compose_services_use_root_context_with_explicit_dockerfiles() {
    let content = std::fs::read_to_string("deploy/compose/compose.yaml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();
    let api = &parsed["services"]["platform-api"];
    // Root-context contract: context must be the workspace root (../.. from deploy/compose/)
    assert_eq!(api["build"]["context"], "../..");
    // Dockerfile must be the full service-relative path from root
    assert_eq!(api["build"]["dockerfile"], "sources/ryuki-api/Dockerfile");

    let portal = &parsed["services"]["portal-ui"];
    assert_eq!(portal["build"]["context"], "../..");
    assert_eq!(portal["build"]["dockerfile"], "portal/portal-ui/Dockerfile");
}

#[test]
fn compose_ports_are_correctly_mapped() {
    let content = std::fs::read_to_string("deploy/compose/compose.yaml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();
    let api_ports = parsed["services"]["platform-api"]["ports"]
        .as_array()
        .unwrap();
    assert!(api_ports.iter().any(|p| p.as_str() == Some("18080:8080")));

    let portal_ports = parsed["services"]["portal-ui"]["ports"].as_array().unwrap();
    assert!(
        portal_ports
            .iter()
            .any(|p| p.as_str() == Some("18000:8080"))
    );
}

#[test]
fn compose_portal_depends_on_platform_api() {
    let content = std::fs::read_to_string("deploy/compose/compose.yaml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();
    let depends_on = &parsed["services"]["portal-ui"]["depends_on"];
    assert!(depends_on.get("platform-api").is_some());
    assert_eq!(depends_on["platform-api"]["condition"], "service_healthy");
}

#[test]
fn compose_services_have_healthchecks() {
    let content = std::fs::read_to_string("deploy/compose/compose.yaml").unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();

    let api_hc = &parsed["services"]["platform-api"]["healthcheck"];
    assert_eq!(api_hc["interval"], "30s");
    assert_eq!(api_hc["timeout"], "5s");
    assert_eq!(api_hc["retries"], 3);
    assert_eq!(api_hc["start_period"], "10s");
    let api_test = api_hc["test"].as_array().unwrap();
    assert_eq!(api_test[0], "CMD");
    assert_eq!(api_test[1], "curl");
    assert_eq!(api_test[2], "-f");
    assert_eq!(api_test[3], "http://localhost:8080/health");

    let portal_hc = &parsed["services"]["portal-ui"]["healthcheck"];
    assert_eq!(portal_hc["interval"], "30s");
    assert_eq!(portal_hc["timeout"], "5s");
    assert_eq!(portal_hc["retries"], 3);
    assert_eq!(portal_hc["start_period"], "15s");
    let portal_test = portal_hc["test"].as_array().unwrap();
    assert_eq!(portal_test[0], "CMD");
    assert_eq!(portal_test[1], "curl");
    assert_eq!(portal_test[2], "-f");
    assert_eq!(portal_test[3], "http://localhost:3000/health");
}
