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

fn is_qualified_immutable_image(image: &str) -> bool {
    let Some((name, digest)) = image.split_once('@') else {
        return false;
    };
    if name.contains('@') || digest.contains('@') || image.contains("://") {
        return false;
    }
    let Some((registry, repository)) = name.split_once('/') else {
        return false;
    };
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    registry.contains('.')
        && !repository.is_empty()
        && !repository.contains(':')
        && hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn image_digest_prefix(image: &str) -> &str {
    assert!(is_qualified_immutable_image(image));
    let digest = image
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .expect("qualified image digest");
    &digest[..12]
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
fn deployments_use_qualified_immutable_images() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    for deployment in &docs {
        let name = deployment["metadata"]["name"].as_str().unwrap();
        for container in deployment["spec"]["template"]["spec"]["containers"]
            .as_sequence()
            .unwrap()
        {
            let image = container["image"].as_str().unwrap();
            assert!(
                is_qualified_immutable_image(image),
                "Deployment {name} must use a qualified digest-only image, got {image}"
            );
        }
    }
}

#[test]
fn rendered_image_guard_rejects_tag_only_and_unqualified_rewrites() {
    let digest = "a".repeat(64);
    assert!(is_qualified_immutable_image(&format!(
        "registry.example.invalid/ryuki/portal-ui@sha256:{digest}"
    )));
    for rejected in [
        "ryuki/portal-ui:rust-dev".to_string(),
        "registry.example.invalid/ryuki/portal-ui:latest".to_string(),
        format!("ryuki/portal-ui@sha256:{digest}"),
        format!("registry.example.invalid/ryuki/portal-ui:latest@sha256:{digest}"),
        format!(
            "registry.example.invalid/ryuki/portal-ui@sha256:{}",
            "A".repeat(64)
        ),
    ] {
        assert!(
            !is_qualified_immutable_image(&rejected),
            "overlay rewrite must not admit {rejected}"
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
    assert_eq!(parsed["spec"]["ingressClassName"], "ryuki-platform");
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
fn network_policies_allow_portal_ui_https_egress_to_dedicated_ingress() {
    let docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    let policy = docs
        .iter()
        .find(|d| {
            d["metadata"]["name"].as_str()
                == Some("allow-portal-ui-egress-to-dedicated-ingress-https")
        })
        .expect("dedicated ingress egress policy not found");

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

    let egress = policy["spec"]["egress"]
        .as_sequence()
        .expect("portal-ui egress rules");
    assert_eq!(egress.len(), 1);
    let targets = egress[0]["to"].as_sequence().expect("portal-ui targets");
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
        "ingress-nginx"
    );
    assert_eq!(
        targets[0]["podSelector"]["matchLabels"]["app.kubernetes.io/name"],
        "ingress-nginx"
    );
    assert_eq!(
        targets[0]["podSelector"]["matchLabels"]["app.kubernetes.io/instance"],
        "ryuki-platform"
    );
    let ports = egress[0]["ports"]
        .as_sequence()
        .expect("portal-ui egress ports");
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0]["protocol"], "TCP");
    assert_eq!(ports[0]["port"], 443);

    for name in [
        "allow-ingress-to-portal-ui",
        "allow-ingress-to-platform-api",
    ] {
        let ingress_policy = docs
            .iter()
            .find(|document| document["metadata"]["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("{name} policy not found"));
        let peer = &ingress_policy["spec"]["ingress"][0]["from"][0];
        assert_eq!(
            peer["podSelector"]["matchLabels"]["app.kubernetes.io/instance"], "ryuki-platform",
            "{name} must admit only the dedicated ingress instance"
        );
    }
}

// ── Runtime configuration wiring (F3) ──────────────────────────────────────

fn find_deployment<'a>(docs: &'a [serde_yaml::Value], name: &str) -> &'a serde_yaml::Value {
    docs.iter()
        .find(|d| d["metadata"]["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("{name} Deployment not found"))
}

#[test]
fn platform_api_imports_config_map_and_exact_db_secret_key() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    let api = find_deployment(&docs, "platform-api");
    let env_from = api["spec"]["template"]["spec"]["containers"][0]["envFrom"]
        .as_sequence()
        .expect("platform-api container must declare envFrom");
    assert_eq!(env_from.len(), 1);
    assert_eq!(env_from[0]["configMapRef"]["name"], "platform-api-config");

    let config_map_refs: Vec<&str> = env_from
        .iter()
        .filter_map(|e| e["configMapRef"]["name"].as_str())
        .collect();
    let secret_refs: Vec<&str> = env_from
        .iter()
        .filter_map(|e| e["secretRef"]["name"].as_str())
        .collect();

    assert!(
        config_map_refs.contains(&"platform-api-config"),
        "platform-api envFrom must reference the platform-api-config ConfigMap"
    );
    assert!(
        secret_refs.is_empty(),
        "platform-api must not import a whole Secret through envFrom"
    );

    let env = api["spec"]["template"]["spec"]["containers"][0]["env"]
        .as_sequence()
        .expect("platform-api container must declare its exact secret key");
    assert_eq!(env.len(), 1);
    assert_eq!(env[0]["name"], "RYUKI_DATABASE_URL");
    assert_eq!(
        env[0]["valueFrom"]["secretKeyRef"]["name"],
        "ryuki-platform-api-db"
    );
    assert_eq!(
        env[0]["valueFrom"]["secretKeyRef"]["key"],
        "RYUKI_DATABASE_URL"
    );
    assert!(env[0]["value"].is_null());

    let pod = &api["spec"]["template"]["spec"];
    let volumes = pod["volumes"]
        .as_sequence()
        .expect("platform-api must project the CNPG CA");
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0]["name"], "cnpg-ca");
    assert_eq!(volumes[0]["secret"]["secretName"], "ryuki-platform-db-ca");
    assert_eq!(
        volumes[0]["secret"]["items"].as_sequence().unwrap().len(),
        1
    );
    assert_eq!(volumes[0]["secret"]["items"][0]["key"], "ca.crt");
    assert_eq!(volumes[0]["secret"]["items"][0]["path"], "ca.crt");
    let mounts = api["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
        .as_sequence()
        .expect("platform-api CA mount");
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0]["name"], "cnpg-ca");
    assert_eq!(mounts[0]["mountPath"], "/var/run/secrets/ryuki/cnpg");
    assert_eq!(mounts[0]["readOnly"], true);
}

#[test]
fn portal_ui_has_env_from_config_map() {
    let docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    let portal = find_deployment(&docs, "portal-ui");
    let env_from = portal["spec"]["template"]["spec"]["containers"][0]["envFrom"]
        .as_sequence()
        .expect("portal-ui container must declare envFrom");

    let config_map_refs: Vec<&str> = env_from
        .iter()
        .filter_map(|e| e["configMapRef"]["name"].as_str())
        .collect();
    assert!(
        config_map_refs.contains(&"portal-ui-config"),
        "portal-ui envFrom must reference the portal-ui-config ConfigMap"
    );
}

#[test]
fn referenced_config_maps_exist_in_manifest_set() {
    let cm_docs = parse_multi_doc("deploy/kubernetes/base/configmap.yaml");
    let cm_names: HashSet<String> = cm_docs
        .iter()
        .map(|d| {
            assert_eq!(d["kind"], "ConfigMap");
            assert_eq!(d["metadata"]["namespace"], "ryuki-platform");
            d["metadata"]["name"].as_str().unwrap().to_string()
        })
        .collect();

    let deploy_docs = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    for doc in &deploy_docs {
        let containers = doc["spec"]["template"]["spec"]["containers"]
            .as_sequence()
            .unwrap();
        for container in containers {
            let Some(env_from) = container["envFrom"].as_sequence() else {
                continue;
            };
            for entry in env_from {
                if let Some(name) = entry["configMapRef"]["name"].as_str() {
                    assert!(
                        cm_names.contains(name),
                        "Deployment {} references unknown ConfigMap {}",
                        doc["metadata"]["name"].as_str().unwrap(),
                        name
                    );
                }
            }
        }
    }
}

#[test]
fn platform_api_config_map_sets_database_required_and_no_secrets() {
    let cm_docs = parse_multi_doc("deploy/kubernetes/base/configmap.yaml");
    let api_cm = cm_docs
        .iter()
        .find(|d| d["metadata"]["name"].as_str() == Some("platform-api-config"))
        .expect("platform-api-config ConfigMap not found");
    let data = api_cm["data"].as_mapping().unwrap();

    assert_eq!(
        data.get("RYUKI_DATABASE__REQUIRED")
            .and_then(|v| v.as_str()),
        Some("true"),
        "platform-api-config must fail hard on database unavailability"
    );
    assert_eq!(
        data.get("RYUKI_SERVER__BIND_ADDRESS")
            .and_then(|v| v.as_str()),
        Some("0.0.0.0:8080")
    );
    assert!(
        !data.contains_key("RYUKI_DATABASE_URL"),
        "RYUKI_DATABASE_URL is secret-delivered and must not appear in the ConfigMap"
    );
    for (key, value) in data {
        let text = format!(
            "{}={}",
            key.as_str().unwrap_or_default(),
            value.as_str().unwrap_or_default()
        );
        assert!(
            !text.to_ascii_lowercase().contains("password"),
            "ConfigMap entry must not carry credential material: {text}"
        );
    }
}

#[test]
fn vso_secrets_materialize_referenced_secret_names() {
    let docs = parse_multi_doc("deploy/kubernetes/vault/vso-secrets.yaml");

    let kind_count = |kind: &str| {
        docs.iter()
            .filter(|document| document["kind"].as_str() == Some(kind))
            .count()
    };
    assert_eq!(kind_count("VaultConnection"), 1);
    assert_eq!(kind_count("VaultAuth"), 3);
    assert_eq!(kind_count("VaultStaticSecret"), 2);
    assert_eq!(kind_count("VaultDynamicSecret"), 1);

    let service_accounts = parse_multi_doc("deploy/kubernetes/base/serviceaccounts.yaml");
    let service_account_names: HashSet<String> = service_accounts
        .iter()
        .map(|doc| doc["metadata"]["name"].as_str().unwrap().to_string())
        .collect();
    for service_account in ["vault-db-owner", "vault-db-backup", "vault-api-db"] {
        assert!(
            service_account_names.contains(service_account),
            "dedicated materializer ServiceAccount {service_account} missing"
        );
        let account = service_accounts
            .iter()
            .find(|doc| doc["metadata"]["name"].as_str() == Some(service_account))
            .unwrap();
        assert_eq!(account["automountServiceAccountToken"], false);
    }

    for (auth_name, role, service_account) in [
        (
            "ryuki-db-owner-vault-auth",
            "ryuki-db-owner",
            "vault-db-owner",
        ),
        (
            "ryuki-db-backup-vault-auth",
            "ryuki-db-backup",
            "vault-db-backup",
        ),
        ("ryuki-api-db-vault-auth", "ryuki-api-db", "vault-api-db"),
    ] {
        let auth = docs
            .iter()
            .find(|doc| {
                doc["kind"].as_str() == Some("VaultAuth")
                    && doc["metadata"]["name"].as_str() == Some(auth_name)
            })
            .unwrap_or_else(|| panic!("VaultAuth {auth_name} not found"));
        assert_eq!(auth["spec"]["kubernetes"]["role"], role);
        assert_eq!(
            auth["spec"]["kubernetes"]["serviceAccount"],
            service_account
        );
    }

    let static_destinations: HashSet<String> = docs
        .iter()
        .filter(|d| d["kind"].as_str() == Some("VaultStaticSecret"))
        .map(|d| {
            d["spec"]["destination"]["name"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    let expected_static_destinations: HashSet<String> =
        ["ryuki-platform-db-superuser", "ryuki-platform-db-backup-s3"]
            .into_iter()
            .map(str::to_string)
            .collect();
    assert_eq!(static_destinations, expected_static_destinations);

    for (destination, auth_ref) in [
        ("ryuki-platform-db-superuser", "ryuki-db-owner-vault-auth"),
        ("ryuki-platform-db-backup-s3", "ryuki-db-backup-vault-auth"),
    ] {
        let secret = docs
            .iter()
            .find(|doc| {
                doc["kind"].as_str() == Some("VaultStaticSecret")
                    && doc["spec"]["destination"]["name"].as_str() == Some(destination)
            })
            .unwrap();
        assert_eq!(secret["spec"]["vaultAuthRef"], auth_ref);
        assert!(
            secret["spec"]["rolloutRestartTargets"].is_null(),
            "do not claim an unproven rollout consumer for {destination}"
        );
    }

    let runtime = docs
        .iter()
        .find(|document| {
            document["kind"].as_str() == Some("VaultDynamicSecret")
                && document["metadata"]["name"].as_str() == Some("ryuki-platform-api-db")
        })
        .expect("runtime VaultDynamicSecret");
    assert_eq!(runtime["spec"]["vaultAuthRef"], "ryuki-api-db-vault-auth");
    assert_eq!(runtime["spec"]["mount"], "database");
    assert_eq!(runtime["spec"]["path"], "creds/ryuki-app-runtime");
    assert_eq!(runtime["spec"]["revoke"], true);
    assert_eq!(runtime["spec"]["allowStaticCreds"], false);
    assert_eq!(
        runtime["metadata"]["annotations"]["ryuki.io/postgres-host"],
        "ryuki-platform-db-rw.ryuki-platform.svc:5432"
    );
    assert_eq!(
        runtime["spec"]["destination"]["name"],
        "ryuki-platform-api-db"
    );
    assert_eq!(
        runtime["spec"]["destination"]["transformation"]["excludeRaw"],
        true
    );
    assert!(
        runtime["spec"]["destination"]["transformation"]["templates"]["RYUKI_DATABASE_URL"]
            .is_mapping()
    );
    let url_template =
        runtime["spec"]["destination"]["transformation"]["templates"]["RYUKI_DATABASE_URL"]["text"]
            .as_str()
            .expect("runtime database URL template");
    assert!(
        url_template.contains("sslmode=verify-full&sslrootcert=/var/run/secrets/ryuki/cnpg/ca.crt")
    );
    assert!(!url_template.contains("sslmode=require"));
    assert_eq!(
        runtime["spec"]["rolloutRestartTargets"][0]["kind"],
        "Deployment"
    );
    assert_eq!(
        runtime["spec"]["rolloutRestartTargets"][0]["name"],
        "platform-api"
    );
    assert!(
        docs.iter().all(|document| {
            !document["metadata"]["name"]
                .as_str()
                .is_some_and(|name| name.contains("migrator"))
        }),
        "digest-scoped migration credentials must stay out of the continuously reconciled base"
    );
}

#[test]
fn cnpg_client_tls_contract_binds_ca_secret_and_server_dns_name() {
    let cluster =
        std::fs::read_to_string("deploy/kubernetes/cloudnativepg/cnpg-cluster.yaml").unwrap();
    let cluster: serde_yaml::Value = serde_yaml::from_str(&cluster).unwrap();
    assert_eq!(
        cluster["metadata"]["annotations"]["ryuki.io/required-server-dns-san"],
        "ryuki-platform-db-rw.ryuki-platform.svc"
    );
    assert_eq!(
        cluster["metadata"]["annotations"]["ryuki.io/client-ca-secret"],
        "ryuki-platform-db-ca"
    );
}

#[test]
fn vault_bootstrap_requires_exact_preverified_chart_archive() {
    let runbook = std::fs::read_to_string("deploy/kubernetes/vault/bootstrap-runbook.md").unwrap();
    for required in [
        "VAULT_HELM_CHART_ARCHIVE",
        "VAULT_HELM_CHART_VERSION",
        "VAULT_HELM_CHART_SHA256",
        "chart version must be exact MAJOR.MINOR.PATCH",
        "chart SHA-256 mismatch",
        "helm show chart \"$VAULT_HELM_CHART_ARCHIVE\"",
        "helm upgrade --install vault \"$VAULT_HELM_CHART_ARCHIVE\"",
    ] {
        assert!(
            runbook.contains(required),
            "missing chart guard: {required}"
        );
    }
    assert!(
        !runbook.contains("helm upgrade --install vault hashicorp/vault"),
        "installation must not resolve a repository-latest chart"
    );
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
    assert_eq!(api["spec"]["strategy"]["type"], "Recreate");
    assert!(
        api["spec"]["strategy"]["rollingUpdate"].is_null(),
        "platform-api must not overlap old and new authentication/secret-bearing replicas"
    );
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

        assert!(sec["runAsNonRoot"].as_bool().unwrap());
        assert_eq!(sec["runAsUser"].as_i64().unwrap(), 10001);
        assert_eq!(sec["runAsGroup"].as_i64().unwrap(), 10001);
        assert!(!sec["allowPrivilegeEscalation"].as_bool().unwrap());
        assert!(sec["readOnlyRootFilesystem"].as_bool().unwrap());
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
        if let Some(selector) = policy["spec"]["podSelector"]["matchLabels"].as_mapping()
            && let Some(name) = selector.get("app.kubernetes.io/name")
        {
            covered.insert(name.as_str().unwrap().to_string());
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

// ── Database network path (F4) ──────────────────────────────────────────────

fn find_policy<'a>(docs: &'a [serde_yaml::Value], name: &str) -> &'a serde_yaml::Value {
    docs.iter()
        .find(|d| d["metadata"]["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("{name} policy not found"))
}

fn ports_of(rule: &serde_yaml::Value) -> Vec<(String, i64)> {
    rule["ports"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["protocol"].as_str().unwrap().to_string(),
                p["port"].as_i64().unwrap(),
            )
        })
        .collect()
}

#[test]
fn network_policies_allow_platform_api_egress_to_db() {
    let docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    let policy = find_policy(&docs, "allow-platform-api-egress-to-db");

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
        "platform-api"
    );

    let rule = &policy["spec"]["egress"][0];
    assert_eq!(
        rule["to"][0]["podSelector"]["matchLabels"]["cnpg.io/cluster"],
        "ryuki-platform-db"
    );
    assert!(
        ports_of(rule).contains(&("TCP".to_string(), 5432)),
        "platform-api DB egress must allow TCP 5432"
    );
}

#[test]
fn network_policies_allow_db_ingress_from_platform_api() {
    let docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    let policy = find_policy(&docs, "allow-ingress-to-db-from-platform-api");

    assert_eq!(
        field_str(
            policy,
            &["spec", "podSelector", "matchLabels", "cnpg.io/cluster"]
        ),
        "ryuki-platform-db"
    );

    let rule = &policy["spec"]["ingress"][0];
    assert_eq!(
        rule["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/name"],
        "platform-api"
    );
    assert!(
        ports_of(rule).contains(&("TCP".to_string(), 5432)),
        "DB ingress from platform-api must allow TCP 5432"
    );
}

#[test]
fn network_policies_allow_cnpg_intra_cluster_traffic() {
    let docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    let policy = find_policy(&docs, "allow-db-intra-cluster");

    assert_eq!(
        field_str(
            policy,
            &["spec", "podSelector", "matchLabels", "cnpg.io/cluster"]
        ),
        "ryuki-platform-db"
    );
    let types: Vec<&str> = policy["spec"]["policyTypes"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(types.contains(&"Ingress"));
    assert!(types.contains(&"Egress"));

    for direction in ["ingress", "egress"] {
        let rule = &policy["spec"][direction][0];
        let peer_key = if direction == "ingress" { "from" } else { "to" };
        assert_eq!(
            rule[peer_key][0]["podSelector"]["matchLabels"]["cnpg.io/cluster"], "ryuki-platform-db",
            "{direction} peer must be the CNPG cluster pods"
        );
        let ports = ports_of(rule);
        assert!(
            ports.contains(&("TCP".to_string(), 5432)),
            "intra-cluster {direction} must allow TCP 5432"
        );
        assert!(
            ports.contains(&("TCP".to_string(), 8000)),
            "intra-cluster {direction} must allow TCP 8000 (status port)"
        );
    }
}

#[test]
fn network_policies_allow_db_ingress_from_cnpg_operator() {
    let docs = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    let policy = find_policy(&docs, "allow-ingress-to-db-from-cnpg-operator");

    assert_eq!(
        field_str(
            policy,
            &["spec", "podSelector", "matchLabels", "cnpg.io/cluster"]
        ),
        "ryuki-platform-db"
    );
    let rule = &policy["spec"]["ingress"][0];
    assert_eq!(
        rule["from"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
        "cnpg-system"
    );
    let ports = ports_of(rule);
    assert!(ports.contains(&("TCP".to_string(), 5432)));
    assert!(ports.contains(&("TCP".to_string(), 8000)));
}

// ── Dedicated embedded-migration cutover ───────────────────────────────────

#[test]
fn api_is_verify_only_and_migration_config_is_non_secret_apply_only() {
    let docs = parse_multi_doc("deploy/kubernetes/base/configmap.yaml");
    let api = docs
        .iter()
        .find(|doc| doc["metadata"]["name"].as_str() == Some("platform-api-config"))
        .expect("platform-api-config");
    assert_eq!(api["data"]["RYUKI_MIGRATION_MODE"], "verify-only");
    assert!(api["data"]["RYUKI_MIGRATION_DATABASE_URL"].is_null());

    let migration = docs
        .iter()
        .find(|doc| doc["metadata"]["name"].as_str() == Some("platform-api-migration-config"))
        .expect("platform-api-migration-config");
    assert_eq!(migration["data"]["RYUKI_MIGRATION_MODE"], "apply-only");
    assert_eq!(
        migration["data"]["RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS"],
        "1800"
    );
    assert_eq!(migration["data"]["RYUKI_MIGRATION_LOCK_TIMEOUT_SECS"], "60");
    assert!(migration["data"]["RYUKI_MIGRATION_DATABASE_URL"].is_null());
}

#[test]
fn migration_job_is_one_shot_hardened_and_uses_the_exact_api_image() {
    let jobs = parse_multi_doc("deploy/kubernetes/operations/migration-job.yaml");
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    assert_eq!(job["apiVersion"], "batch/v1");
    assert_eq!(job["kind"], "Job");
    let release_image = job["metadata"]["annotations"]["ryuki.io/release-image"]
        .as_str()
        .expect("migration release image");
    let digest_prefix = image_digest_prefix(release_image);
    assert_eq!(
        job["metadata"]["generateName"],
        format!("platform-api-migrations-{digest_prefix}-")
    );
    assert!(job["metadata"]["name"].is_null());
    assert_eq!(
        job["metadata"]["labels"]["ryuki.io/release-digest-prefix"],
        digest_prefix
    );
    assert_eq!(job["spec"]["completions"], 1);
    assert_eq!(job["spec"]["parallelism"], 1);
    assert_eq!(job["spec"]["backoffLimit"], 0);
    assert_eq!(job["spec"]["activeDeadlineSeconds"], 2400);
    assert!(job["spec"]["ttlSecondsAfterFinished"].is_null());
    for forbidden in [
        "podFailurePolicy",
        "podReplacementPolicy",
        "backoffLimitPerIndex",
        "maxFailedIndexes",
        "successPolicy",
    ] {
        assert!(
            job["spec"][forbidden].is_null(),
            "retry/replacement policy {forbidden} must remain absent"
        );
    }

    let pod = &job["spec"]["template"]["spec"];
    assert_eq!(pod["serviceAccountName"], "platform-api-migrator");
    assert_eq!(pod["automountServiceAccountToken"], false);
    assert_eq!(pod["enableServiceLinks"], false);
    assert_eq!(pod["restartPolicy"], "Never");
    let volumes = pod["volumes"]
        .as_sequence()
        .expect("migration CNPG CA volume");
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0]["name"], "cnpg-ca");
    assert_eq!(volumes[0]["secret"]["secretName"], "ryuki-platform-db-ca");
    assert_eq!(volumes[0]["secret"]["items"][0]["key"], "ca.crt");
    assert_eq!(volumes[0]["secret"]["items"][0]["path"], "ca.crt");
    let container = &pod["containers"][0];
    assert_eq!(container["name"], "platform-api-migrations");
    assert!(container["command"].is_null());
    assert!(container["args"].is_null());
    assert!(container["ports"].is_null());
    assert!(container["readinessProbe"].is_null());
    assert!(container["livenessProbe"].is_null());
    assert_eq!(container["volumeMounts"].as_sequence().unwrap().len(), 1);
    assert_eq!(container["volumeMounts"][0]["name"], "cnpg-ca");
    assert_eq!(
        container["volumeMounts"][0]["mountPath"],
        "/var/run/secrets/ryuki/cnpg"
    );
    assert_eq!(container["volumeMounts"][0]["readOnly"], true);

    let deployments = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    let api = find_deployment(&deployments, "platform-api");
    assert_eq!(
        container["image"],
        api["spec"]["template"]["spec"]["containers"][0]["image"]
    );
    assert_eq!(
        container["image"],
        job["metadata"]["annotations"]["ryuki.io/release-image"]
    );
    assert!(is_qualified_immutable_image(
        container["image"].as_str().unwrap()
    ));

    let env_from = container["envFrom"].as_sequence().expect("job envFrom");
    assert_eq!(
        env_from[0]["configMapRef"]["name"],
        "platform-api-migration-config"
    );
    assert_eq!(env_from.len(), 1);
    assert!(env_from[0]["secretRef"].is_null());
    let env = container["env"]
        .as_sequence()
        .expect("job exact secret env");
    assert_eq!(env.len(), 1);
    assert_eq!(env[0]["name"], "RYUKI_MIGRATION_DATABASE_URL");
    assert_eq!(
        env[0]["valueFrom"]["secretKeyRef"]["name"],
        format!("ryuki-platform-api-migrator-db-{digest_prefix}")
    );
    assert_eq!(
        env[0]["valueFrom"]["secretKeyRef"]["key"],
        "RYUKI_MIGRATION_DATABASE_URL"
    );
    assert!(env[0]["value"].is_null());
    assert_eq!(container["securityContext"]["runAsNonRoot"], true);
    assert_eq!(
        container["securityContext"]["allowPrivilegeEscalation"],
        false
    );
    assert_eq!(container["securityContext"]["readOnlyRootFilesystem"], true);
    assert_eq!(
        container["securityContext"]["capabilities"]["drop"][0],
        "ALL"
    );
    assert_eq!(
        container["securityContext"]["seccompProfile"]["type"],
        "RuntimeDefault"
    );
    assert!(container["resources"]["requests"]["cpu"].is_string());
    assert!(container["resources"]["limits"]["memory"].is_string());
}

#[test]
fn migration_cutover_contract_derives_identities_and_pins_writer_evidence() {
    let raw =
        std::fs::read_to_string("deploy/kubernetes/operations/migration-cutover-contract.yaml")
            .unwrap();
    let contract: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
    let release_image = contract["release"]["image"]
        .as_str()
        .expect("cutover release image");
    let digest_prefix = image_digest_prefix(release_image);
    assert_eq!(contract["release"]["digestPrefix"], digest_prefix);
    assert_eq!(
        contract["execution"]["generatedNamePrefix"],
        format!("platform-api-migrations-{digest_prefix}-")
    );
    assert_eq!(
        contract["credentials"]["migration"]["secretName"],
        format!("ryuki-platform-api-migrator-db-{digest_prefix}")
    );
    assert_eq!(
        contract["credentials"]["migration"]["vaultDynamicSecretName"],
        format!("ryuki-platform-api-migrator-db-{digest_prefix}")
    );
    assert_eq!(
        contract["credentials"]["migration"]["vaultAuthRole"],
        format!("ryuki-api-db-migrator-{digest_prefix}")
    );
    assert_eq!(
        contract["credentials"]["migration"]["vaultDatabaseRole"],
        format!("ryuki-schema-migrator-{digest_prefix}")
    );

    let workload_kinds: Vec<&str> = contract["drain"]["requiredWorkloadKinds"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        workload_kinds,
        ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    );
    let writer_selectors: Vec<&str> = contract["drain"]["requiredBaseWriterSelectors"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        writer_selectors,
        [
            "app.kubernetes.io/part-of=ryuki-infrastructure-platform,app.kubernetes.io/name=platform-api"
        ]
    );
    let session_fields: Vec<&str> = contract["drain"]["databaseSessionReadback"]["fields"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        session_fields,
        [
            "pid",
            "usename",
            "application_name",
            "backend_start",
            "xact_start",
            "state"
        ]
    );
}

#[test]
fn migration_job_and_secret_materializer_use_distinct_non_automounted_identities() {
    let deployments = parse_multi_doc("deploy/kubernetes/base/deployments.yaml");
    let api_image =
        find_deployment(&deployments, "platform-api")["spec"]["template"]["spec"]["containers"][0]
            ["image"]
            .as_str()
            .expect("platform-api image");
    let digest_prefix = image_digest_prefix(api_image);
    let migration_auth_name = format!("ryuki-api-db-migrator-vault-auth-{digest_prefix}");
    let migration_secret_name = format!("ryuki-platform-api-migrator-db-{digest_prefix}");
    let accounts = parse_multi_doc("deploy/kubernetes/base/serviceaccounts.yaml");
    for name in ["platform-api-migrator", "vault-api-db-migrator"] {
        let account = accounts
            .iter()
            .find(|doc| doc["metadata"]["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing ServiceAccount {name}"));
        assert_eq!(account["automountServiceAccountToken"], false);
    }

    let job = parse_multi_doc("deploy/kubernetes/operations/migration-job.yaml");
    assert_eq!(
        job[0]["spec"]["template"]["spec"]["serviceAccountName"],
        "platform-api-migrator"
    );

    let migration_vault =
        parse_multi_doc("deploy/kubernetes/operations/migration-vault-dynamic-secret.yaml");
    assert_eq!(migration_vault.len(), 2);
    let auth = migration_vault
        .iter()
        .find(|doc| {
            doc["kind"].as_str() == Some("VaultAuth")
                && doc["metadata"]["name"].as_str() == Some(migration_auth_name.as_str())
        })
        .expect("migrator VaultAuth");
    assert_eq!(
        auth["spec"]["kubernetes"]["serviceAccount"],
        "vault-api-db-migrator"
    );
    assert_eq!(
        auth["spec"]["kubernetes"]["role"],
        format!("ryuki-api-db-migrator-{digest_prefix}")
    );
    assert_eq!(
        auth["metadata"]["labels"]["ryuki.io/release-digest-prefix"],
        digest_prefix
    );

    let migration_secret = migration_vault
        .iter()
        .find(|doc| {
            doc["kind"].as_str() == Some("VaultDynamicSecret")
                && doc["spec"]["destination"]["name"].as_str()
                    == Some(migration_secret_name.as_str())
        })
        .expect("migrator VaultDynamicSecret");
    assert_eq!(
        migration_secret["spec"]["vaultAuthRef"],
        migration_auth_name
    );
    assert_eq!(
        migration_secret["spec"]["path"],
        format!("creds/ryuki-schema-migrator-{digest_prefix}")
    );
    assert_eq!(migration_secret["spec"]["mount"], "database");
    assert_eq!(migration_secret["spec"]["revoke"], true);
    assert_eq!(migration_secret["spec"]["allowStaticCreds"], false);
    assert_eq!(
        migration_secret["spec"]["destination"]["transformation"]["excludeRaw"],
        true
    );
    assert_eq!(
        migration_secret["metadata"]["labels"]["ryuki.io/release-digest-prefix"],
        digest_prefix
    );
    let migration_url_template = migration_secret["spec"]["destination"]["transformation"]
        ["templates"]["RYUKI_MIGRATION_DATABASE_URL"]["text"]
        .as_str()
        .expect("migration database URL template");
    assert!(
        migration_url_template
            .contains("sslmode=verify-full&sslrootcert=/var/run/secrets/ryuki/cnpg/ca.crt")
    );
    assert!(!migration_url_template.contains("sslmode=require"));
    assert!(
        migration_secret["spec"]["destination"]["transformation"]["templates"]
            ["RYUKI_MIGRATION_DATABASE_URL"]
            .is_mapping()
    );
    assert!(migration_secret["spec"]["rolloutRestartTargets"].is_null());

    let base_vault = parse_multi_doc("deploy/kubernetes/vault/vso-secrets.yaml");
    let app_secret = base_vault
        .iter()
        .find(|doc| {
            doc["kind"].as_str() == Some("VaultDynamicSecret")
                && doc["spec"]["destination"]["name"].as_str() == Some("ryuki-platform-api-db")
        })
        .expect("application VaultDynamicSecret");
    assert_ne!(
        migration_secret["spec"]["vaultAuthRef"],
        app_secret["spec"]["vaultAuthRef"]
    );
    assert_ne!(
        migration_secret["spec"]["destination"]["name"],
        app_secret["spec"]["destination"]["name"]
    );
}

#[test]
fn migration_job_has_only_its_dedicated_postgres_network_path() {
    let policies = parse_multi_doc("deploy/kubernetes/base/networkpolicies.yaml");
    let egress = find_policy(&policies, "allow-platform-api-migrations-egress-to-db");
    assert_eq!(
        egress["spec"]["podSelector"]["matchLabels"]["app.kubernetes.io/name"],
        "platform-api-migrations"
    );
    let egress_rule = &egress["spec"]["egress"][0];
    assert_eq!(
        egress_rule["to"][0]["podSelector"]["matchLabels"]["cnpg.io/cluster"],
        "ryuki-platform-db"
    );
    assert_eq!(ports_of(egress_rule), vec![("TCP".into(), 5432)]);

    let ingress = find_policy(
        &policies,
        "allow-ingress-to-db-from-platform-api-migrations",
    );
    let ingress_rule = &ingress["spec"]["ingress"][0];
    assert_eq!(
        ingress_rule["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/name"],
        "platform-api-migrations"
    );
    assert_eq!(ports_of(ingress_rule), vec![("TCP".into(), 5432)]);
}
