use serde::Deserialize;
use std::collections::HashSet;

fn parse_multi_doc(path: &str) -> Vec<serde_yaml::Value> {
    let content = std::fs::read_to_string(path).unwrap();
    serde_yaml::Deserializer::from_str(&content)
        .map(|d| serde_yaml::Value::deserialize(d).unwrap())
        .collect()
}

fn field_str(doc: &serde_yaml::Value, path: &[&str]) -> String {
    let mut current = doc;
    for key in path {
        current = &current[key];
    }
    current.as_str().unwrap().to_string()
}

#[test]
fn namespace_manifest_is_valid() {
    let namespace = std::fs::read_to_string("deploy/kubernetes/base/namespace.yaml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&namespace).unwrap();
    assert_eq!(parsed["kind"], "Namespace");
    assert_eq!(parsed["metadata"]["name"], "ryuki-platform");
}

#[test]
fn deployments_file_is_valid_yaml() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    assert!(!docs.is_empty());
    for doc in &docs {
        assert_eq!(doc["kind"], "Deployment");
        assert_eq!(doc["apiVersion"], "apps/v1");
    }
}

#[test]
fn deployments_have_all_required_components() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    let names: HashSet<String> = docs
        .iter()
        .map(|d| d["metadata"]["name"].as_str().unwrap().to_string())
        .collect();

    let expected: HashSet<String> = ["portal-ui", "platform-api"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    assert_eq!(names, expected);
}

#[test]
fn deployments_have_required_keys() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    for doc in &docs {
        let name = doc["metadata"]["name"].as_str().unwrap();
        assert!(
            doc.get("spec").unwrap().get("replicas").is_some(),
            "{} missing replicas",
            name
        );
        assert!(
            doc["spec"]
                .get("selector")
                .unwrap()
                .get("matchLabels")
                .is_some(),
            "{} missing matchLabels",
            name
        );
        assert!(
            doc["spec"]["template"]["spec"]
                .get("serviceAccountName")
                .is_some(),
            "{} missing serviceAccountName",
            name
        );
        assert!(
            doc["spec"]["template"]["spec"]["containers"]
                .as_sequence()
                .is_some_and(|c| !c.is_empty()),
            "{} has no containers",
            name
        );
        assert!(
            doc["metadata"]["labels"]
                .get("app.kubernetes.io/part-of")
                .is_some(),
            "{} missing app.kubernetes.io/part-of label",
            name
        );
    }
}

#[test]
fn deployments_refer_to_existing_service_accounts() {
    let sa_docs = parse_multi_doc("deploy/kubernetes/base/serviceaccounts.yaml");
    let sa_names: HashSet<String> = sa_docs
        .iter()
        .map(|d| d["metadata"]["name"].as_str().unwrap().to_string())
        .collect();

    let deploy_docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    for doc in &deploy_docs {
        let sa_name = doc["spec"]["template"]["spec"]["serviceAccountName"]
            .as_str()
            .unwrap();
        assert!(
            sa_names.contains(sa_name),
            "Deployment {} references unknown ServiceAccount {}",
            doc["metadata"]["name"].as_str().unwrap(),
            sa_name
        );
    }
}

#[test]
fn services_file_is_valid_yaml() {
    let docs = parse_multi_doc("deploy/kubernetes/base/services.yaml");
    assert!(!docs.is_empty());
    for doc in &docs {
        assert_eq!(doc["kind"], "Service");
        assert_eq!(doc["apiVersion"], "v1");
        assert_eq!(doc["spec"]["type"], "ClusterIP");
    }
}

#[test]
fn services_match_deployments() {
    let deploy_docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    let deploy_names: HashSet<String> = deploy_docs
        .iter()
        .map(|d| d["metadata"]["name"].as_str().unwrap().to_string())
        .collect();

    let svc_docs = parse_multi_doc("deploy/kubernetes/base/services.yaml");
    let svc_names: HashSet<String> = svc_docs
        .iter()
        .map(|d| d["metadata"]["name"].as_str().unwrap().to_string())
        .collect();

    for svc_name in &svc_names {
        assert!(
            deploy_names.contains(svc_name),
            "Service {} has no matching Deployment",
            svc_name
        );
    }
}

#[test]
fn services_have_correct_selectors() {
    let docs = parse_multi_doc("deploy/kubernetes/base/services.yaml");
    for doc in &docs {
        let name = doc["metadata"]["name"].as_str().unwrap();
        let selector = &doc["spec"]["selector"];
        assert_eq!(
            selector["app.kubernetes.io/part-of"], "ryuki-infrastructure-platform",
            "{name} selector part-of mismatch"
        );
        assert_eq!(
            selector["app.kubernetes.io/name"], name,
            "{name} selector name mismatch"
        );
    }
}

#[test]
fn ingress_is_valid_yaml() {
    let ingress = std::fs::read_to_string("deploy/kubernetes/base/ingress.yaml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&ingress).unwrap();
    assert_eq!(parsed["kind"], "Ingress");
    assert_eq!(parsed["apiVersion"], "networking.k8s.io/v1");
    assert_eq!(parsed["spec"]["ingressClassName"], "nginx");
}

#[test]
fn ingress_routes_to_correct_services() {
    let ingress = std::fs::read_to_string("deploy/kubernetes/base/ingress.yaml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&ingress).unwrap();

    let paths = parsed["spec"]["rules"][0]["http"]["paths"]
        .as_sequence()
        .unwrap();

    let mut routes: Vec<(String, String)> = paths
        .iter()
        .map(|p| {
            (
                p["path"].as_str().unwrap().to_string(),
                p["backend"]["service"]["name"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect();
    routes.sort();

    assert_eq!(
        routes,
        vec![
            ("/".to_string(), "portal-ui".to_string()),
            ("/api".to_string(), "platform-api".to_string()),
        ]
    );
}

#[test]
fn ingress_has_tls_configured() {
    let ingress = std::fs::read_to_string("deploy/kubernetes/base/ingress.yaml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&ingress).unwrap();
    let tls = parsed["spec"]["tls"].as_sequence().unwrap();
    assert_eq!(tls.len(), 1);
    assert_eq!(tls[0]["secretName"], "platform-tls-placeholder");
}

#[test]
fn network_policies_file_is_valid_yaml() {
    let docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    assert!(!docs.is_empty());
    for doc in &docs {
        assert_eq!(doc["kind"], "NetworkPolicy");
        assert_eq!(doc["apiVersion"], "networking.k8s.io/v1");
        assert_eq!(doc["metadata"]["namespace"], "ryuki-platform");
    }
}

#[test]
fn network_policies_enforce_default_deny_ingress() {
    let docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    let deny = docs
        .iter()
        .find(|d| d["metadata"]["name"].as_str() == Some("default-deny-ingress"))
        .expect("default-deny-ingress policy not found");
    let pod_selector = deny["spec"]["podSelector"].as_mapping().unwrap();
    assert!(
        pod_selector.is_empty(),
        "default-deny-ingress must apply to all pods"
    );
    let types: Vec<&str> = deny["spec"]["policyTypes"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(types.contains(&"Ingress"));
}

#[test]
fn network_policies_enforce_default_deny_egress() {
    let docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    let deny = docs
        .iter()
        .find(|d| d["metadata"]["name"].as_str() == Some("default-deny-egress"))
        .expect("default-deny-egress policy not found");
    let pod_selector = deny["spec"]["podSelector"].as_mapping().unwrap();
    assert!(
        pod_selector.is_empty(),
        "default-deny-egress must apply to all pods"
    );
    let types: Vec<&str> = deny["spec"]["policyTypes"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(types.contains(&"Egress"));
}

#[test]
fn network_policies_allow_dns_egress() {
    let docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    let dns = docs
        .iter()
        .find(|d| d["metadata"]["name"].as_str() == Some("allow-egress-to-kube-dns"))
        .expect("allow-egress-to-kube-dns policy not found");

    let rules = dns["spec"]["egress"].as_sequence().unwrap();
    assert_eq!(rules.len(), 1);

    let to = &rules[0]["to"][0];
    assert_eq!(
        to["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
        "kube-system"
    );
    assert_eq!(to["podSelector"]["matchLabels"]["k8s-app"], "kube-dns");

    let ports = rules[0]["ports"].as_sequence().unwrap();
    assert_eq!(ports.len(), 2);
}

#[test]
fn network_policies_allow_portal_ui_to_api_egress() {
    let docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    let policy = docs
        .iter()
        .find(|d| d["metadata"]["name"].as_str() == Some("allow-portal-ui-egress-to-platform-api"))
        .expect("allow-portal-ui-egress-to-platform-api policy not found");

    assert_eq!(
        field_str(
            policy,
            &[
                "spec",
                "podSelector",
                "matchLabels",
                "app.kubernetes.io/name"
            ]
        ),
        "portal-ui"
    );

    let to = &policy["spec"]["egress"][0]["to"][0]["podSelector"]["matchLabels"];
    assert_eq!(to["app.kubernetes.io/name"], "platform-api");
}

// ── API/portal runtime hardening ───────────────────────────────────────────

#[test]
fn api_and_portal_deployments_have_probes() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    let portal = docs
        .iter()
        .find(|d| d["metadata"]["name"].as_str() == Some("portal-ui"))
        .expect("portal-ui Deployment not found");
    let api = docs
        .iter()
        .find(|d| d["metadata"]["name"].as_str() == Some("platform-api"))
        .expect("platform-api Deployment not found");

    let portal_containers = portal["spec"]["template"]["spec"]["containers"]
        .as_sequence()
        .unwrap();
    let api_containers = api["spec"]["template"]["spec"]["containers"]
        .as_sequence()
        .unwrap();

    let portal_readiness = &portal_containers[0]["readinessProbe"]["httpGet"];
    let portal_liveness = &portal_containers[0]["livenessProbe"]["httpGet"];
    let api_readiness = &api_containers[0]["readinessProbe"]["httpGet"];
    let api_liveness = &api_containers[0]["livenessProbe"]["httpGet"];

    assert_eq!(portal_readiness["path"].as_str().unwrap(), "/readyz");
    assert_eq!(portal_readiness["port"].as_i64().unwrap(), 8080);
    assert_eq!(portal_liveness["path"].as_str().unwrap(), "/healthz");
    assert_eq!(portal_liveness["port"].as_i64().unwrap(), 8080);
    assert_eq!(api_readiness["path"].as_str().unwrap(), "/ready");
    assert_eq!(api_readiness["port"].as_i64().unwrap(), 8080);
    assert_eq!(api_liveness["path"].as_str().unwrap(), "/health");
    assert_eq!(api_liveness["port"].as_i64().unwrap(), 8080);
}

#[test]
fn api_and_portal_deployments_have_resources() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    for name in &["portal-ui", "platform-api"] {
        let deployment = docs
            .iter()
            .find(|d| d["metadata"]["name"].as_str() == Some(name))
            .expect("Deployment not found");
        let container = &deployment["spec"]["template"]["spec"]["containers"]
            .as_sequence()
            .unwrap()[0];
        let resources = &container["resources"];
        let requests = &resources["requests"];
        let limits = &resources["limits"];

        assert_eq!(requests["cpu"].as_str().unwrap(), "50m");
        assert_eq!(requests["memory"].as_str().unwrap(), "128Mi");
        assert_eq!(limits["cpu"].as_str().unwrap(), "500m");
        assert_eq!(limits["memory"].as_str().unwrap(), "512Mi");
    }
}

#[test]
fn api_and_portal_deployments_have_pull_policy() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    for name in &["portal-ui", "platform-api"] {
        let deployment = docs
            .iter()
            .find(|d| d["metadata"]["name"].as_str() == Some(name))
            .expect("Deployment not found");
        let container = &deployment["spec"]["template"]["spec"]["containers"]
            .as_sequence()
            .unwrap()[0];
        assert_eq!(
            container["imagePullPolicy"].as_str().unwrap(),
            "IfNotPresent"
        );
    }
}

#[test]
fn api_and_portal_deployments_have_security_context() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    for name in &["portal-ui", "platform-api"] {
        let deployment = docs
            .iter()
            .find(|d| d["metadata"]["name"].as_str() == Some(name))
            .expect("Deployment not found");
        let container = &deployment["spec"]["template"]["spec"]["containers"]
            .as_sequence()
            .unwrap()[0];
        let sec = &container["securityContext"];

        assert_eq!(sec["runAsNonRoot"].as_bool().unwrap(), true);
        assert_eq!(sec["runAsUser"].as_i64().unwrap(), 10001);
        assert_eq!(sec["runAsGroup"].as_i64().unwrap(), 10001);
        assert_eq!(sec["allowPrivilegeEscalation"].as_bool().unwrap(), false);
        assert_eq!(sec["readOnlyRootFilesystem"].as_bool().unwrap(), true);
        assert_eq!(
            sec["capabilities"]["drop"]
                .as_sequence()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["ALL"]
        );
        assert_eq!(
            sec["seccompProfile"]["type"].as_str().unwrap(),
            "RuntimeDefault"
        );
    }
}

#[test]
fn deploys_have_correct_service_account_names() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    for doc in &docs {
        let name = doc["metadata"]["name"].as_str().unwrap();
        let sa = doc["spec"]["template"]["spec"]["serviceAccountName"]
            .as_str()
            .unwrap();
        assert_eq!(name, sa, "Deployment {name} ServiceAccount mismatch");
    }
}

#[test]
fn network_policies_cover_all_deployment_names() {
    let deploy_docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    let deploy_names: HashSet<String> = deploy_docs
        .iter()
        .map(|d| d["metadata"]["name"].as_str().unwrap().to_string())
        .collect();

    let np_docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");

    let mut covered: HashSet<String> = HashSet::new();
    for policy in &np_docs {
        if let Some(selector) = policy["spec"]["podSelector"]["matchLabels"].as_mapping() {
            if let Some(name) = selector.get("app.kubernetes.io/name") {
                covered.insert(name.as_str().unwrap().to_string());
            }
        }
        if let Some(selectors) = policy["spec"]["podSelector"]["matchExpressions"].as_sequence() {
            for expr in selectors {
                if expr["key"].as_str() == Some("app.kubernetes.io/name") {
                    for val in expr["values"].as_sequence().unwrap() {
                        covered.insert(val.as_str().unwrap().to_string());
                    }
                }
            }
        }
    }

    let uncovered: Vec<_> = deploy_names
        .iter()
        .filter(|n| !covered.contains(n.as_str()))
        .collect();
    assert!(
        uncovered.is_empty(),
        "Deployments without explicit NetworkPolicy coverage: {:?}",
        uncovered
    );
}
