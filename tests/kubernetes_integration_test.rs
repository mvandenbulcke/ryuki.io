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

const SECURITY_ADMISSION_CONFIG_MAP: &str = "platform-security-admission-config";
const SECURITY_ADMISSION_KEYS: [&str; 7] = [
    "RYUKI_SECURITY_CONTRACT_ROOT",
    "RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH",
    "RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST",
    "RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH",
    "RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST",
    "RYUKI_EXPECTED_DEPLOYMENT_ID",
    "RYUKI_SECURITY_PROFILE",
];
const PRODUCTION_BUILD_MANIFEST_CONFIG_MAP: &str = "platform-production-build-manifest-pins";
const PRODUCTION_BUILD_MANIFEST_KEYS: &[&str] = &[
    "RYUKI_PRODUCTION_BUILD_MANIFEST_PATH",
    "RYUKI_PRODUCTION_BUILD_MANIFEST_DIGEST",
];
const CONFORMANCE_TRUST_CHECKPOINT_CONFIG_MAP: &str = "platform-conformance-trust-checkpoint-pins";
const CONFORMANCE_TRUST_CHECKPOINT_KEYS: &[&str] = &[
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_SOCKET",
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID",
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_KEY_ID",
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64",
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT",
    "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_MIN_AUTHORITY_EPOCH",
];
const DEPLOYED_WORKLOAD_ATTESTATION_CONFIG_MAP: &str =
    "platform-deployed-workload-attestation-pins";
const DEPLOYED_WORKLOAD_ATTESTATION_KEYS: &[&str] = &[
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_SOCKET",
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_AUTHORITY_ID",
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_KEY_ID",
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_BASE64",
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT",
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MIN_AUTHORITY_EPOCH",
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_ID",
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_VERSION",
    "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_DIGEST",
    "RYUKI_EXPECTED_WORKLOAD_ID",
];
const PUBLIC_INGRESS_ATTESTATION_CONFIG_MAP: &str = "platform-public-ingress-attestation-pins";
const PUBLIC_INGRESS_ATTESTATION_KEYS: &[&str] = &[
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_SOCKET",
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_AUTHORITY_ID",
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_KEY_ID",
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_BASE64",
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT",
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_MIN_AUTHORITY_EPOCH",
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_ID",
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_VERSION",
    "RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_DIGEST",
];
const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_CONFIG_MAP: &str =
    "platform-postgresql-infrastructure-attestation-pins";
const POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEYS: &[&str] = &[
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET",
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID",
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID",
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64",
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT",
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_MIN_AUTHORITY_EPOCH",
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID",
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_VERSION",
    "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST",
];
const FIRST_OWNER_AUTHORITY_CONFIG_MAP: &str = "platform-first-owner-authority-pins";
const FIRST_OWNER_AUTHORITY_KEYS: &[&str] = &[
    "RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_PATH",
    "RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST",
    "RYUKI_FIRST_OWNER_AUTHORITY_ID",
    "RYUKI_FIRST_OWNER_AUTHORITY_KEY_ID",
    "RYUKI_FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64",
    "RYUKI_FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT",
    "RYUKI_FIRST_OWNER_AUTHORITY_MIN_EPOCH",
];
const MIGRATION_PRODUCTION_PIN_GROUPS: &[(&str, &[&str], &str)] = &[
    (
        SECURITY_ADMISSION_CONFIG_MAP,
        &SECURITY_ADMISSION_KEYS,
        "ryuki.io/pin-security-admission-receipt",
    ),
    (
        PRODUCTION_BUILD_MANIFEST_CONFIG_MAP,
        PRODUCTION_BUILD_MANIFEST_KEYS,
        "ryuki.io/pin-production-build-manifest-receipt",
    ),
    (
        CONFORMANCE_TRUST_CHECKPOINT_CONFIG_MAP,
        CONFORMANCE_TRUST_CHECKPOINT_KEYS,
        "ryuki.io/pin-conformance-trust-checkpoint-receipt",
    ),
    (
        DEPLOYED_WORKLOAD_ATTESTATION_CONFIG_MAP,
        DEPLOYED_WORKLOAD_ATTESTATION_KEYS,
        "ryuki.io/pin-deployed-workload-attestation-receipt",
    ),
    (
        PUBLIC_INGRESS_ATTESTATION_CONFIG_MAP,
        PUBLIC_INGRESS_ATTESTATION_KEYS,
        "ryuki.io/pin-public-ingress-attestation-receipt",
    ),
    (
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_CONFIG_MAP,
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEYS,
        "ryuki.io/pin-postgresql-infrastructure-attestation-receipt",
    ),
    (
        FIRST_OWNER_AUTHORITY_CONFIG_MAP,
        FIRST_OWNER_AUTHORITY_KEYS,
        "ryuki.io/pin-first-owner-authority-receipt",
    ),
];
const SOCKET_PROJECTION_AUTHORITY_CONFIG_MAP: &str =
    "platform-migration-socket-projection-authority-pins";
const SOCKET_PROJECTION_AUTHORITY_KEYS: &[&str] = &[
    "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_AUTHORITY_ID",
    "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_KEY_ID",
    "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_PUBLIC_KEY_BASE64",
    "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_PUBLIC_KEY_FINGERPRINT",
    "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_MIN_AUTHORITY_EPOCH",
    "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_PROFILE_ID",
    "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_PROFILE_VERSION",
    "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_PROFILE_DIGEST",
];
const MIGRATION_RENDER_PIN_RECEIPT_ANNOTATIONS: [&str; 9] = [
    "ryuki.io/pin-migration-config-receipt",
    "ryuki.io/pin-security-admission-receipt",
    "ryuki.io/pin-production-build-manifest-receipt",
    "ryuki.io/pin-conformance-trust-checkpoint-receipt",
    "ryuki.io/pin-deployed-workload-attestation-receipt",
    "ryuki.io/pin-public-ingress-attestation-receipt",
    "ryuki.io/pin-postgresql-infrastructure-attestation-receipt",
    "ryuki.io/pin-first-owner-authority-receipt",
    "ryuki.io/pin-socket-projection-authority-receipt",
];
const MIGRATION_JOB_RYUKI_ANNOTATIONS: [&str; 15] = [
    "ryuki.io/cutover-contract",
    "ryuki.io/release-image",
    "ryuki.io/render-contract",
    "ryuki.io/render-mode",
    "ryuki.io/pin-migration-config-receipt",
    "ryuki.io/pin-security-admission-receipt",
    "ryuki.io/pin-production-build-manifest-receipt",
    "ryuki.io/pin-conformance-trust-checkpoint-receipt",
    "ryuki.io/pin-deployed-workload-attestation-receipt",
    "ryuki.io/pin-public-ingress-attestation-receipt",
    "ryuki.io/pin-postgresql-infrastructure-attestation-receipt",
    "ryuki.io/pin-first-owner-authority-receipt",
    "ryuki.io/pin-socket-projection-authority-receipt",
    "ryuki.io/socket-projection-receipt-digest",
    "ryuki.io/socket-contract-digest",
];
const MIGRATION_JOB_ENV_COUNT: usize = 1
    + SECURITY_ADMISSION_KEYS.len()
    + PRODUCTION_BUILD_MANIFEST_KEYS.len()
    + CONFORMANCE_TRUST_CHECKPOINT_KEYS.len()
    + DEPLOYED_WORKLOAD_ATTESTATION_KEYS.len()
    + PUBLIC_INGRESS_ATTESTATION_KEYS.len()
    + POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEYS.len()
    + FIRST_OWNER_AUTHORITY_KEYS.len();
const FINAL_RENDER_CONTRACT: &str = "migration-final-render-v1";
const SOURCE_TEMPLATE_MODE: &str = "source-template";
const FINAL_RENDER_MODE: &str = "final-render";
const FINAL_RENDER_REQUIRED_RUNTIME_CAPABILITY: &str =
    "in-cluster-final-render-admission-and-runtime-freshness-v1";
const RENDER_REQUIRED_SENTINEL: &str = "RENDER_REQUIRED";
const SOCKET_CONTRACT_DIGEST: &str =
    "sha256:369bca5b159d7535a2b3523796ff3632e9e7ca44f9a94b4140cc572163767697";
const AUTHORITY_SOCKET_CSI_DRIVER: &str = "authority-socket-projection.ryuki.io";
const POSTGRESQL_RELAY_VOLUME_NAME: &str = "postgresql-relay-workspace";
const POSTGRESQL_RELAY_MOUNT_PATH: &str = "/run/ryuki-postgresql-relay";
const POSTGRESQL_RELAY_SIZE_LIMIT: &str = "1Mi";
const MIGRATION_AUTHORITY_SOCKET_FIXTURE_SPECS: &[(&str, &str, &str)] = &[
    (
        "conformance-trust-checkpoint-socket",
        "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_SOCKET",
        "conformance-trust-checkpoint",
    ),
    (
        "deployed-workload-attestation-socket",
        "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_SOCKET",
        "deployed-workload-attestation",
    ),
    (
        "public-ingress-attestation-socket",
        "RYUKI_PUBLIC_INGRESS_ATTESTATION_SOCKET",
        "public-ingress-attestation",
    ),
    (
        "postgresql-infrastructure-attestation-socket",
        "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET",
        "postgresql-infrastructure-attestation",
    ),
];

#[derive(Clone)]
struct RenderedSocketPinFixture {
    volume_name: &'static str,
    environment_variable: &'static str,
    authority_class: &'static str,
    socket_path: String,
    fingerprint: String,
}
const PLATFORM_API_CONFIG_KEYS: [&str; 23] = [
    "RYUKI_SERVER__BIND_ADDRESS",
    "RYUKI_PLATFORM_URL",
    "RYUKI_DATABASE__REQUIRED",
    "RYUKI_MIGRATION_MODE",
    "RYUKI_DATABASE_EXPECTED_ROLE",
    "RYUKI_DATABASE_FORBIDDEN_ROLE",
    "RYUKI_SECRET_PROVIDER_RUNTIME__PROVIDER_ID",
    "RYUKI_SECRET_PROVIDER_RUNTIME__CONFIGURATION_VERSION",
    "RYUKI_SECRET_PROVIDER_RUNTIME__API_FLAVOR",
    "RYUKI_SECRET_PROVIDER_RUNTIME__ENDPOINT",
    "RYUKI_SECRET_PROVIDER_RUNTIME__CA_BUNDLE_PATH",
    "RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_AUTH_MOUNT",
    "RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_ROLE",
    "RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_AUDIENCE",
    "RYUKI_SECRET_PROVIDER_RUNTIME__PROJECTED_TOKEN_PATH",
    "RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_SERVICE_ACCOUNT_NAMESPACE",
    "RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_SERVICE_ACCOUNT_NAME",
    "RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_TOKEN_POLICY",
    "RYUKI_SECRET_REFERENCE_FINGERPRINT_KEYRING_PATH",
    "RYUKI_RETENTION__DAILY_BACKUPS",
    "RYUKI_RETENTION__WEEKLY_BACKUPS",
    "RYUKI_RETENTION__MONTHLY_BACKUPS",
    "RYUKI_RETENTION__YEARLY_BACKUPS",
];
const PLATFORM_API_MIGRATION_CONFIG_KEYS: [&str; 5] = [
    "RYUKI_MIGRATION_MODE",
    "RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS",
    "RYUKI_MIGRATION_LOCK_TIMEOUT_SECS",
    "RYUKI_MIGRATION_EXPECTED_ROLE",
    "RYUKI_APPLICATION_DATABASE_ROLE",
];
const PORTAL_UI_CONFIG_KEYS: [&str; 4] = [
    "RYUKI_API_URL",
    "RYUKI_PORTAL_PUBLIC_ORIGIN",
    "RYUKI_PORTAL_EXECUTION_MODE",
    "RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK",
];

fn assert_ordered_security_admission_env(env: &[serde_yaml::Value]) {
    assert_eq!(
        env.len(),
        SECURITY_ADMISSION_KEYS.len() + 1,
        "the exact database secret key must be followed by seven admission keys"
    );

    let names: Vec<&str> = env
        .iter()
        .map(|entry| entry["name"].as_str().expect("environment variable name"))
        .collect();
    let expected_names: Vec<&str> = std::iter::once(names[0])
        .chain(SECURITY_ADMISSION_KEYS)
        .collect();
    assert_eq!(
        names, expected_names,
        "security admission key order changed"
    );
    assert_eq!(
        names.iter().copied().collect::<HashSet<_>>().len(),
        names.len(),
        "environment keys must not be duplicated"
    );

    for (entry, expected_key) in env[1..].iter().zip(SECURITY_ADMISSION_KEYS) {
        assert_eq!(entry["name"], expected_key);
        assert_eq!(
            entry["valueFrom"]["configMapKeyRef"]["name"],
            SECURITY_ADMISSION_CONFIG_MAP
        );
        assert_eq!(entry["valueFrom"]["configMapKeyRef"]["key"], expected_key);
        assert!(
            entry["value"].is_null(),
            "{expected_key} must not have a literal value"
        );
        assert!(
            entry["valueFrom"]["secretKeyRef"].is_null(),
            "{expected_key} must come only from the admission ConfigMap"
        );
    }
}

fn migration_production_pin_env_error(
    env: &[serde_yaml::Value],
    release_digest_prefix: &str,
) -> Result<(), String> {
    if env.len() != MIGRATION_JOB_ENV_COUNT {
        return Err(format!(
            "expected {MIGRATION_JOB_ENV_COUNT} exact migration environment entries, found {}",
            env.len()
        ));
    }

    let database_url = &env[0];
    if database_url.as_mapping().map(|map| map.len()) != Some(2)
        || database_url["name"] != "RYUKI_MIGRATION_DATABASE_URL"
        || database_url["valueFrom"].as_mapping().map(|map| map.len()) != Some(1)
        || database_url["valueFrom"]["secretKeyRef"]
            .as_mapping()
            .map(|map| map.len())
            != Some(2)
        || database_url["valueFrom"]["secretKeyRef"]["key"] != "RYUKI_MIGRATION_DATABASE_URL"
        || !database_url["value"].is_null()
        || !database_url["valueFrom"]["configMapKeyRef"].is_null()
    {
        return Err("migration database URL must be one exact Secret key projection".to_string());
    }

    let expected: Vec<(String, &str)> = MIGRATION_PRODUCTION_PIN_GROUPS
        .iter()
        .flat_map(|(config_map, keys, _)| {
            let config_map = digest_scoped_pin_config_map_name(config_map, release_digest_prefix);
            keys.iter().map(move |key| (config_map.clone(), *key))
        })
        .collect();
    if expected.len() + 1 != MIGRATION_JOB_ENV_COUNT {
        return Err(format!(
            "migration production pin inventory has {} entries but the Job contract requires {}",
            expected.len() + 1,
            MIGRATION_JOB_ENV_COUNT
        ));
    }
    let names: Vec<&str> = env
        .iter()
        .map(|entry| {
            entry["name"]
                .as_str()
                .ok_or_else(|| "migration environment entry has no string name".to_string())
        })
        .collect::<Result<_, _>>()?;
    if names.iter().copied().collect::<HashSet<_>>().len() != names.len() {
        return Err("migration environment names must be unique".to_string());
    }

    for (entry, (expected_config_map, expected_key)) in env[1..].iter().zip(expected) {
        if entry.as_mapping().map(|map| map.len()) != Some(2)
            || entry["name"] != expected_key
            || entry["valueFrom"].as_mapping().map(|map| map.len()) != Some(1)
            || entry["valueFrom"]["configMapKeyRef"]
                .as_mapping()
                .map(|map| map.len())
                != Some(2)
            || entry["valueFrom"]["configMapKeyRef"]["name"] != expected_config_map.as_str()
            || entry["valueFrom"]["configMapKeyRef"]["key"] != expected_key
            || !entry["value"].is_null()
            || !entry["valueFrom"]["secretKeyRef"].is_null()
        {
            return Err(format!(
                "{expected_key} must be projected exactly from {expected_config_map}"
            ));
        }
    }

    Ok(())
}

fn assert_migration_production_pin_env(env: &[serde_yaml::Value], release_digest_prefix: &str) {
    migration_production_pin_env_error(env, release_digest_prefix)
        .unwrap_or_else(|error| panic!("invalid migration production pin projection: {error}"));
}

fn digest_scoped_pin_config_map_name(base_name: &str, release_digest_prefix: &str) -> String {
    format!("{base_name}-{release_digest_prefix}")
}

fn final_render_socket_fixture() -> (serde_yaml::Value, Vec<RenderedSocketPinFixture>) {
    let mut job = parse_multi_doc("deploy/kubernetes/operations/migration-job.yaml")
        .into_iter()
        .next()
        .expect("migration Job source template");
    let receipt_digest = format!("sha256:{}", "a".repeat(64));
    job["metadata"]["annotations"]["ryuki.io/render-mode"] =
        serde_yaml::Value::String(FINAL_RENDER_MODE.to_string());
    job["spec"]["suspend"] = serde_yaml::Value::Bool(false);
    job["metadata"]["annotations"]["ryuki.io/socket-projection-receipt-digest"] =
        serde_yaml::Value::String(receipt_digest.clone());

    let mut pins = Vec::new();
    for (index, (volume_name, environment_variable, authority_class)) in
        MIGRATION_AUTHORITY_SOCKET_FIXTURE_SPECS.iter().enumerate()
    {
        let socket_path = format!("/var/run/ryuki-authorities/{authority_class}/authority.sock");
        let mount_path = socket_path
            .rsplit_once('/')
            .expect("socket path parent")
            .0
            .to_string();
        let fingerprint = format!(
            "sha256:{}",
            char::from(b'c' + index as u8).to_string().repeat(64)
        );
        let volume = serde_yaml::to_value(serde_json::json!({
            "name": volume_name,
            "csi": {
                "driver": AUTHORITY_SOCKET_CSI_DRIVER,
                "readOnly": true,
                "volumeAttributes": {
                    "environmentVariable": environment_variable,
                    "authorityClass": authority_class,
                    "socketPath": socket_path
                }
            }
        }))
        .expect("inline CSI fixture volume");
        job["spec"]["template"]["spec"]["volumes"]
            .as_sequence_mut()
            .expect("migration Job volumes")
            .push(volume);
        let mount = serde_yaml::to_value(serde_json::json!({
            "name": volume_name,
            "mountPath": mount_path,
            "readOnly": true
        }))
        .expect("inline CSI fixture mount");
        job["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
            .as_sequence_mut()
            .expect("migration Job mounts")
            .push(mount);
        pins.push(RenderedSocketPinFixture {
            volume_name,
            environment_variable,
            authority_class,
            socket_path,
            fingerprint,
        });
    }

    (job, pins)
}

fn migration_relay_workspace_error(job: &serde_yaml::Value) -> Result<(), String> {
    let pod = &job["spec"]["template"]["spec"];
    let volumes = pod["volumes"]
        .as_sequence()
        .ok_or_else(|| "missing migration volumes".to_string())?;
    let mounts = pod["containers"][0]["volumeMounts"]
        .as_sequence()
        .ok_or_else(|| "missing migration volume mounts".to_string())?;
    let relay_volumes: Vec<&serde_yaml::Value> = volumes
        .iter()
        .filter(|volume| volume["name"].as_str() == Some(POSTGRESQL_RELAY_VOLUME_NAME))
        .collect();
    let relay_mounts: Vec<&serde_yaml::Value> = mounts
        .iter()
        .filter(|mount| mount["name"].as_str() == Some(POSTGRESQL_RELAY_VOLUME_NAME))
        .collect();
    let volume = relay_volumes
        .first()
        .copied()
        .unwrap_or(&serde_yaml::Value::Null);
    let mount = relay_mounts
        .first()
        .copied()
        .unwrap_or(&serde_yaml::Value::Null);
    if relay_volumes.len() != 1
        || relay_mounts.len() != 1
        || volume.as_mapping().map(|map| map.len()) != Some(2)
        || volume["emptyDir"].as_mapping().map(|map| map.len()) != Some(2)
        || volume["emptyDir"]["medium"].as_str() != Some("Memory")
        || volume["emptyDir"]["sizeLimit"].as_str() != Some(POSTGRESQL_RELAY_SIZE_LIMIT)
        || mount.as_mapping().map(|map| map.len()) != Some(3)
        || mount["mountPath"].as_str() != Some(POSTGRESQL_RELAY_MOUNT_PATH)
        || mount["readOnly"].as_bool() != Some(false)
    {
        return Err(
            "migration relay workspace must be one exact bounded memory emptyDir and writable mount"
                .to_string(),
        );
    }

    let pod_security = pod["securityContext"]
        .as_mapping()
        .ok_or_else(|| "missing migration Pod security context".to_string())?;
    let actual_security_keys: HashSet<&str> = pod_security
        .keys()
        .map(|key| {
            key.as_str()
                .ok_or_else(|| "migration Pod security key is not a string".to_string())
        })
        .collect::<Result<_, _>>()?;
    let expected_security_keys: HashSet<&str> = [
        "runAsNonRoot",
        "runAsUser",
        "runAsGroup",
        "fsGroup",
        "fsGroupChangePolicy",
        "seccompProfile",
    ]
    .into_iter()
    .collect();
    if actual_security_keys != expected_security_keys
        || pod["securityContext"]["runAsNonRoot"].as_bool() != Some(true)
        || pod["securityContext"]["runAsUser"].as_i64() != Some(10001)
        || pod["securityContext"]["runAsGroup"].as_i64() != Some(10001)
        || pod["securityContext"]["fsGroup"].as_i64() != Some(10001)
        || pod["securityContext"]["fsGroupChangePolicy"].as_str() != Some("OnRootMismatch")
        || pod["securityContext"]["seccompProfile"]
            .as_mapping()
            .map(|map| map.len())
            != Some(1)
        || pod["securityContext"]["seccompProfile"]["type"].as_str() != Some("RuntimeDefault")
    {
        return Err(
            "migration Pod security context must grant only GID 10001 ownership to projected volumes"
                .to_string(),
        );
    }

    let container_security = pod["containers"][0]["securityContext"]
        .as_mapping()
        .ok_or_else(|| "missing migration container security context".to_string())?;
    let actual_container_security_keys: HashSet<&str> = container_security
        .keys()
        .map(|key| {
            key.as_str()
                .ok_or_else(|| "migration container security key is not a string".to_string())
        })
        .collect::<Result<_, _>>()?;
    let expected_container_security_keys: HashSet<&str> = [
        "runAsNonRoot",
        "runAsUser",
        "runAsGroup",
        "allowPrivilegeEscalation",
        "readOnlyRootFilesystem",
        "capabilities",
        "seccompProfile",
    ]
    .into_iter()
    .collect();
    let drop_capabilities = pod["containers"][0]["securityContext"]["capabilities"]["drop"]
        .as_sequence()
        .ok_or_else(|| "missing migration dropped-capabilities inventory".to_string())?;
    if actual_container_security_keys != expected_container_security_keys
        || pod["containers"][0]["securityContext"]["runAsNonRoot"].as_bool() != Some(true)
        || pod["containers"][0]["securityContext"]["runAsUser"].as_i64() != Some(10001)
        || pod["containers"][0]["securityContext"]["runAsGroup"].as_i64() != Some(10001)
        || pod["containers"][0]["securityContext"]["allowPrivilegeEscalation"].as_bool()
            != Some(false)
        || pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"].as_bool() != Some(true)
        || pod["containers"][0]["securityContext"]["capabilities"]
            .as_mapping()
            .map(|map| map.len())
            != Some(1)
        || drop_capabilities.len() != 1
        || drop_capabilities[0].as_str() != Some("ALL")
        || pod["containers"][0]["securityContext"]["seccompProfile"]
            .as_mapping()
            .map(|map| map.len())
            != Some(1)
        || pod["containers"][0]["securityContext"]["seccompProfile"]["type"].as_str()
            != Some("RuntimeDefault")
    {
        return Err("migration container security context must remain closed".to_string());
    }

    Ok(())
}

fn final_render_socket_projection_error(
    job: &serde_yaml::Value,
    pins: &[RenderedSocketPinFixture],
) -> Result<(), String> {
    let receipt_digest =
        job["metadata"]["annotations"]["ryuki.io/socket-projection-receipt-digest"]
            .as_str()
            .ok_or_else(|| "missing receipt digest".to_string())?;
    let receipt_hex = receipt_digest
        .strip_prefix("sha256:")
        .filter(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| "receipt digest must be lowercase SHA-256".to_string())?;
    if receipt_hex.bytes().all(|byte| byte == b'0') {
        return Err("receipt digest must be nonzero".to_string());
    }
    let volumes = job["spec"]["template"]["spec"]["volumes"]
        .as_sequence()
        .ok_or_else(|| "missing final-render volumes".to_string())?;
    let mounts = job["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
        .as_sequence()
        .ok_or_else(|| "missing final-render mounts".to_string())?;
    if pins.len() != 4 || volumes.len() != 6 || mounts.len() != 6 {
        return Err(
            "final render must have one CA, one relay workspace, and exactly four socket projections"
                .to_string(),
        );
    }
    migration_relay_workspace_error(job)?;
    let expected_names: HashSet<&str> = std::iter::once("cnpg-ca")
        .chain(std::iter::once(POSTGRESQL_RELAY_VOLUME_NAME))
        .chain(pins.iter().map(|pin| pin.volume_name))
        .collect();
    let actual_volume_names: HashSet<&str> = volumes
        .iter()
        .map(|volume| {
            volume["name"]
                .as_str()
                .ok_or_else(|| "final-render volume name is not a string".to_string())
        })
        .collect::<Result<_, _>>()?;
    let actual_mount_names: HashSet<&str> = mounts
        .iter()
        .map(|mount| {
            mount["name"]
                .as_str()
                .ok_or_else(|| "final-render mount name is not a string".to_string())
        })
        .collect::<Result<_, _>>()?;
    if actual_volume_names != expected_names || actual_mount_names != expected_names {
        return Err(
            "final-render volume and mount names must match the closed inventory".to_string(),
        );
    }
    let mut paths = HashSet::new();
    let mut parents = HashSet::new();
    for pin in pins {
        if !pin.socket_path.starts_with('/')
            || !pin.socket_path.ends_with(".sock")
            || pin.socket_path.contains("//")
            || !paths.insert(pin.socket_path.as_str())
        {
            return Err("socket paths must be normalized absolute and distinct".to_string());
        }
        let parent = pin
            .socket_path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .filter(|parent| !parent.is_empty() && *parent != "/")
            .ok_or_else(|| "socket path must have a non-root parent".to_string())?;
        if !parents.insert(parent) {
            return Err("socket mount parents must be distinct".to_string());
        }
        let matching_volumes: Vec<&serde_yaml::Value> = volumes
            .iter()
            .filter(|volume| volume["name"].as_str() == Some(pin.volume_name))
            .collect();
        let matching_mounts: Vec<&serde_yaml::Value> = mounts
            .iter()
            .filter(|mount| mount["name"].as_str() == Some(pin.volume_name))
            .collect();
        let volume = matching_volumes
            .first()
            .copied()
            .unwrap_or(&serde_yaml::Value::Null);
        let mount = matching_mounts
            .first()
            .copied()
            .unwrap_or(&serde_yaml::Value::Null);
        let csi = &volume["csi"];
        let attributes = &csi["volumeAttributes"];
        if matching_volumes.len() != 1
            || matching_mounts.len() != 1
            || volume.as_mapping().map(|map| map.len()) != Some(2)
            || csi.as_mapping().map(|map| map.len()) != Some(3)
            || attributes.as_mapping().map(|map| map.len()) != Some(3)
            || csi["driver"].as_str() != Some(AUTHORITY_SOCKET_CSI_DRIVER)
            || csi["readOnly"].as_bool() != Some(true)
            || attributes["environmentVariable"].as_str() != Some(pin.environment_variable)
            || attributes["authorityClass"].as_str() != Some(pin.authority_class)
            || attributes["socketPath"].as_str() != Some(pin.socket_path.as_str())
            || mount.as_mapping().map(|map| map.len()) != Some(3)
            || mount["mountPath"].as_str() != Some(parent)
            || mount["readOnly"].as_bool() != Some(true)
        {
            return Err(format!(
                "invalid receipt-bound inline CSI projection {}",
                pin.volume_name
            ));
        }
    }
    let postgresql_fingerprint = &pins[3].fingerprint;
    if !postgresql_fingerprint.starts_with("sha256:")
        || postgresql_fingerprint.len() != 71
        || pins[..3]
            .iter()
            .any(|pin| pin.fingerprint == *postgresql_fingerprint)
    {
        return Err("PostgreSQL authority fingerprint must be valid and distinct".to_string());
    }
    Ok(())
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
    assert_ordered_security_admission_env(env);
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
    assert!(env[0]["valueFrom"]["configMapKeyRef"].is_null());

    let pod = &api["spec"]["template"]["spec"];
    assert_eq!(pod["serviceAccountName"], "platform-api");
    assert_eq!(pod["automountServiceAccountToken"], false);
    assert_eq!(pod["securityContext"]["runAsNonRoot"], true);
    assert_eq!(pod["securityContext"]["runAsUser"], 10001);
    assert_eq!(pod["securityContext"]["runAsGroup"], 10001);
    assert_eq!(pod["securityContext"]["fsGroup"], 10001);
    assert_eq!(
        pod["securityContext"]["fsGroupChangePolicy"],
        "OnRootMismatch"
    );

    let volumes = pod["volumes"].as_sequence().expect(
        "platform-api must project the CNPG CA, exact Vault auth inputs, and fingerprint keyring",
    );
    assert_eq!(
        volumes.len(),
        4,
        "only the CNPG CA, Vault workload JWT, Vault client CA, and fingerprint keyring may be projected"
    );
    assert_eq!(volumes[0]["name"], "cnpg-ca");
    assert_eq!(volumes[0]["secret"]["secretName"], "ryuki-platform-db-ca");
    assert_eq!(
        volumes[0]["secret"]["items"].as_sequence().unwrap().len(),
        1
    );
    assert_eq!(volumes[0]["secret"]["items"][0]["key"], "ca.crt");
    assert_eq!(volumes[0]["secret"]["items"][0]["path"], "ca.crt");

    assert_eq!(volumes[1]["name"], "vault-workload-token");
    assert_eq!(volumes[1]["projected"]["defaultMode"], 288);
    let token_sources = volumes[1]["projected"]["sources"]
        .as_sequence()
        .expect("Vault workload token must have one projected source");
    assert_eq!(token_sources.len(), 1);
    let token_request = &token_sources[0]["serviceAccountToken"];
    assert_eq!(token_request["audience"], "vault");
    assert_eq!(token_request["expirationSeconds"], 600);
    assert_eq!(token_request["path"], "token");

    assert_eq!(volumes[2]["name"], "vault-client-ca");
    assert_eq!(volumes[2]["secret"]["secretName"], "ryuki-vault-client-ca");
    assert_eq!(volumes[2]["secret"]["defaultMode"], 288);
    let vault_ca_items = volumes[2]["secret"]["items"]
        .as_sequence()
        .expect("Vault client CA projection must have one item");
    assert_eq!(vault_ca_items.len(), 1);
    assert_eq!(vault_ca_items[0]["key"], "ca.crt");
    assert_eq!(vault_ca_items[0]["path"], "ca.crt");

    assert_eq!(volumes[3]["name"], "secret-reference-fingerprint-keyring");
    assert_eq!(
        volumes[3]["secret"]["secretName"],
        "ryuki-secret-reference-fingerprint-keyring"
    );
    assert_eq!(volumes[3]["secret"]["defaultMode"], 288);
    let fingerprint_keyring_items = volumes[3]["secret"]["items"]
        .as_sequence()
        .expect("fingerprint keyring projection must have one item");
    assert_eq!(fingerprint_keyring_items.len(), 1);
    assert_eq!(fingerprint_keyring_items[0]["key"], "keyring");
    assert_eq!(fingerprint_keyring_items[0]["path"], "keyring");

    let mounts = api["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
        .as_sequence()
        .expect("platform-api trust and workload-auth mounts");
    assert_eq!(
        mounts.len(),
        4,
        "only the reviewed four volumes may be mounted"
    );
    assert_eq!(mounts[0]["name"], "cnpg-ca");
    assert_eq!(mounts[0]["mountPath"], "/var/run/secrets/ryuki/cnpg");
    assert_eq!(mounts[0]["readOnly"], true);
    assert!(mounts[0]["subPath"].is_null());

    assert_eq!(mounts[1]["name"], "vault-workload-token");
    assert_eq!(mounts[1]["mountPath"], "/var/run/secrets/ryuki/vault-auth");
    assert_eq!(mounts[1]["readOnly"], true);
    assert!(mounts[1]["subPath"].is_null());

    assert_eq!(mounts[2]["name"], "vault-client-ca");
    assert_eq!(mounts[2]["mountPath"], "/var/run/secrets/ryuki/vault-tls");
    assert_eq!(mounts[2]["readOnly"], true);
    assert!(mounts[2]["subPath"].is_null());

    assert_eq!(mounts[3]["name"], "secret-reference-fingerprint-keyring");
    assert_eq!(
        mounts[3]["mountPath"],
        "/var/run/secrets/ryuki/secret-reference-fingerprint"
    );
    assert_eq!(mounts[3]["readOnly"], true);
    assert!(mounts[3]["subPath"].is_null());
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
fn security_admission_config_map_is_a_required_external_input() {
    let cm_docs = parse_multi_doc("deploy/kubernetes/base/configmap.yaml");
    let checked_in_names: HashSet<&str> = cm_docs
        .iter()
        .filter_map(|document| document["metadata"]["name"].as_str())
        .collect();

    assert!(
        !checked_in_names.contains(SECURITY_ADMISSION_CONFIG_MAP),
        "{SECURITY_ADMISSION_CONFIG_MAP} must remain an external, release-reviewed input"
    );
}

#[test]
fn env_from_config_maps_have_exact_reviewed_key_allowlists() {
    let cm_docs = parse_multi_doc("deploy/kubernetes/base/configmap.yaml");

    for (name, expected_keys) in [
        ("platform-api-config", PLATFORM_API_CONFIG_KEYS.as_slice()),
        (
            "platform-api-migration-config",
            PLATFORM_API_MIGRATION_CONFIG_KEYS.as_slice(),
        ),
        ("portal-ui-config", PORTAL_UI_CONFIG_KEYS.as_slice()),
    ] {
        let config_map = cm_docs
            .iter()
            .find(|document| document["metadata"]["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing ConfigMap {name}"));
        let actual_keys: HashSet<&str> = config_map["data"]
            .as_mapping()
            .expect("ConfigMap data")
            .keys()
            .map(|key| key.as_str().expect("string ConfigMap data key"))
            .collect();
        let expected_keys: HashSet<&str> = expected_keys.iter().copied().collect();
        assert_eq!(
            actual_keys, expected_keys,
            "ConfigMap {name} must not widen its envFrom surface"
        );
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
    assert_eq!(
        data.get("RYUKI_SECRET_REFERENCE_FINGERPRINT_KEYRING_PATH")
            .and_then(|v| v.as_str()),
        Some("/var/run/secrets/ryuki/secret-reference-fingerprint/keyring"),
        "platform-api must read the dedicated fingerprint keyring from the exact projected file"
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
    let release_wrapper =
        std::fs::read_to_string("deploy/kubernetes/vault/release-approved-chart.sh").unwrap();
    for required in [
        "VAULT_HELM_CHART_ARCHIVE",
        "VAULT_HELM_CHART_VERSION",
        "VAULT_HELM_CHART_SHA256",
        "release-approved-chart.sh verify",
        "release-approved-chart.sh install",
    ] {
        assert!(
            runbook.contains(required),
            "runbook must delegate to the immutable chart wrapper: {required}"
        );
    }
    for required in [
        "VAULT_HELM_CHART_ARCHIVE",
        "VAULT_HELM_CHART_VERSION",
        "VAULT_HELM_CHART_SHA256",
        "chart version must be exact MAJOR.MINOR.PATCH",
        "chart SHA-256 mismatch",
        "chart_snapshot",
        "helm show chart \"$chart_snapshot\"",
        "helm template vault \"$chart_snapshot\"",
        "helm lint \"$chart_snapshot\"",
        "helm upgrade --install vault \"$chart_snapshot\"",
        "assert_snapshot",
    ] {
        assert!(
            release_wrapper.contains(required),
            "immutable chart wrapper is missing guard: {required}"
        );
    }
    assert!(
        !runbook.contains("helm upgrade --install vault hashicorp/vault")
            && !release_wrapper.contains("hashicorp/vault"),
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
        "180"
    );
    assert_eq!(migration["data"]["RYUKI_MIGRATION_LOCK_TIMEOUT_SECS"], "30");
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
    assert_eq!(job["spec"]["activeDeadlineSeconds"], 300);
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

    let annotations = job["metadata"]["annotations"]
        .as_mapping()
        .expect("migration Job annotations");
    let actual_annotation_keys: HashSet<&str> = annotations
        .keys()
        .map(|key| key.as_str().expect("annotation key"))
        .collect();
    let expected_annotation_keys: HashSet<&str> =
        MIGRATION_JOB_RYUKI_ANNOTATIONS.iter().copied().collect();
    assert_eq!(
        actual_annotation_keys, expected_annotation_keys,
        "Job annotation inventory must contain exactly 15 keys"
    );
    assert_eq!(
        job["metadata"]["annotations"]["ryuki.io/render-contract"],
        FINAL_RENDER_CONTRACT
    );
    assert_eq!(
        job["metadata"]["annotations"]["ryuki.io/render-mode"],
        SOURCE_TEMPLATE_MODE
    );
    assert_eq!(
        job["spec"]["suspend"], true,
        "the unresolved source template must be inert if submitted accidentally"
    );
    assert_eq!(
        job["metadata"]["annotations"]["ryuki.io/socket-contract-digest"],
        SOCKET_CONTRACT_DIGEST
    );
    for receipt_annotation in MIGRATION_RENDER_PIN_RECEIPT_ANNOTATIONS {
        assert_eq!(
            job["metadata"]["annotations"][receipt_annotation],
            RENDER_REQUIRED_SENTINEL
        );
    }
    assert_eq!(
        job["metadata"]["annotations"]["ryuki.io/socket-projection-receipt-digest"],
        RENDER_REQUIRED_SENTINEL
    );
    assert_eq!(
        annotations
            .values()
            .filter(|value| value.as_str() == Some(RENDER_REQUIRED_SENTINEL))
            .count(),
        10,
        "source template must retain nine pin receipts plus one socket receipt digest sentinel"
    );

    let pod = &job["spec"]["template"]["spec"];
    assert_eq!(pod["serviceAccountName"], "platform-api-migrator");
    assert_eq!(pod["automountServiceAccountToken"], false);
    assert_eq!(pod["enableServiceLinks"], false);
    assert_eq!(pod["restartPolicy"], "Never");
    migration_relay_workspace_error(job)
        .unwrap_or_else(|error| panic!("invalid migration relay workspace: {error}"));
    let volumes = pod["volumes"]
        .as_sequence()
        .expect("migration CNPG CA and relay-workspace volumes");
    assert_eq!(
        volumes.len(),
        2,
        "only the CNPG CA and bounded relay workspace may be projected"
    );
    assert_eq!(volumes[0].as_mapping().map(|map| map.len()), Some(2));
    assert_eq!(volumes[0]["name"], "cnpg-ca");
    assert_eq!(
        volumes[0]["secret"].as_mapping().map(|map| map.len()),
        Some(2)
    );
    assert_eq!(volumes[0]["secret"]["secretName"], "ryuki-platform-db-ca");
    assert_eq!(
        volumes[0]["secret"]["items"]
            .as_sequence()
            .map(|items| items.len()),
        Some(1)
    );
    assert_eq!(
        volumes[0]["secret"]["items"][0]
            .as_mapping()
            .map(|map| map.len()),
        Some(2)
    );
    assert_eq!(volumes[0]["secret"]["items"][0]["key"], "ca.crt");
    assert_eq!(volumes[0]["secret"]["items"][0]["path"], "ca.crt");
    assert_eq!(volumes[1].as_mapping().map(|map| map.len()), Some(2));
    assert_eq!(volumes[1]["name"], POSTGRESQL_RELAY_VOLUME_NAME);
    assert_eq!(
        volumes[1]["emptyDir"].as_mapping().map(|map| map.len()),
        Some(2)
    );
    assert_eq!(volumes[1]["emptyDir"]["medium"], "Memory");
    assert_eq!(
        volumes[1]["emptyDir"]["sizeLimit"],
        POSTGRESQL_RELAY_SIZE_LIMIT
    );
    let container = &pod["containers"][0];
    assert_eq!(container["name"], "platform-api-migrations");
    assert!(container["command"].is_null());
    assert!(container["args"].is_null());
    assert!(container["ports"].is_null());
    assert!(container["readinessProbe"].is_null());
    assert!(container["livenessProbe"].is_null());
    let mounts = container["volumeMounts"]
        .as_sequence()
        .expect("migration volume mounts");
    assert_eq!(
        mounts.len(),
        2,
        "only the CNPG CA and bounded relay workspace may be mounted"
    );
    assert_eq!(mounts[0].as_mapping().map(|map| map.len()), Some(3));
    assert_eq!(mounts[0]["name"], "cnpg-ca");
    assert_eq!(mounts[0]["mountPath"], "/var/run/secrets/ryuki/cnpg");
    assert_eq!(mounts[0]["readOnly"], true);
    assert!(mounts[0]["subPath"].is_null());
    assert_eq!(mounts[1].as_mapping().map(|map| map.len()), Some(3));
    assert_eq!(mounts[1]["name"], POSTGRESQL_RELAY_VOLUME_NAME);
    assert_eq!(mounts[1]["mountPath"], POSTGRESQL_RELAY_MOUNT_PATH);
    assert_eq!(mounts[1]["readOnly"], false);
    assert!(mounts[1]["subPath"].is_null());

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
    assert_migration_production_pin_env(env, digest_prefix);
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
    assert!(env[0]["valueFrom"]["configMapKeyRef"].is_null());
    let container_security = container["securityContext"]
        .as_mapping()
        .expect("migration container security context");
    let actual_container_security_keys: HashSet<&str> = container_security
        .keys()
        .map(|key| key.as_str().expect("container security key"))
        .collect();
    let expected_container_security_keys: HashSet<&str> = [
        "runAsNonRoot",
        "runAsUser",
        "runAsGroup",
        "allowPrivilegeEscalation",
        "readOnlyRootFilesystem",
        "capabilities",
        "seccompProfile",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        actual_container_security_keys, expected_container_security_keys,
        "migration container security context must remain closed"
    );
    assert_eq!(container["securityContext"]["runAsNonRoot"], true);
    assert_eq!(container["securityContext"]["runAsUser"], 10001);
    assert_eq!(container["securityContext"]["runAsGroup"], 10001);
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
fn migration_job_pin_projection_detects_missing_duplicate_miswired_and_inline_entries() {
    let jobs = parse_multi_doc("deploy/kubernetes/operations/migration-job.yaml");
    let release_image = jobs[0]["metadata"]["annotations"]["ryuki.io/release-image"]
        .as_str()
        .expect("migration release image");
    let digest_prefix = image_digest_prefix(release_image);
    let baseline = jobs[0]["spec"]["template"]["spec"]["containers"][0]["env"]
        .as_sequence()
        .expect("migration production env")
        .clone();
    assert_migration_production_pin_env(&baseline, digest_prefix);

    let governed_config_maps: HashSet<&str> = MIGRATION_PRODUCTION_PIN_GROUPS
        .iter()
        .map(|(config_map, _, _)| *config_map)
        .collect();
    assert_eq!(
        governed_config_maps.len(),
        MIGRATION_PRODUCTION_PIN_GROUPS.len(),
        "each production pin group must use an independently named ConfigMap"
    );

    let mut missing = baseline.clone();
    let index = missing
        .iter()
        .position(|entry| {
            entry["name"].as_str()
                == Some("RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST")
        })
        .expect("PostgreSQL profile digest pin");
    missing.remove(index);
    assert!(migration_production_pin_env_error(&missing, digest_prefix).is_err());

    let mut duplicate = baseline.clone();
    let duplicate_entry = duplicate[duplicate.len() - 2].clone();
    let last = duplicate.len() - 1;
    duplicate[last] = duplicate_entry;
    assert!(migration_production_pin_env_error(&duplicate, digest_prefix).is_err());

    let mut miswired_postgresql = baseline.clone();
    let entry = miswired_postgresql
        .iter_mut()
        .find(|entry| {
            entry["name"].as_str() == Some("RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET")
        })
        .expect("PostgreSQL socket pin");
    entry["valueFrom"]["configMapKeyRef"]["name"] =
        serde_yaml::Value::String(PUBLIC_INGRESS_ATTESTATION_CONFIG_MAP.to_string());
    assert!(migration_production_pin_env_error(&miswired_postgresql, digest_prefix).is_err());

    for (config_map, keys, _) in MIGRATION_PRODUCTION_PIN_GROUPS {
        let mut miswired_group = baseline.clone();
        let first_key = keys
            .first()
            .copied()
            .expect("nonempty production pin group");
        let entry = miswired_group
            .iter_mut()
            .find(|entry| entry["name"].as_str() == Some(first_key))
            .unwrap_or_else(|| panic!("missing first pin from {config_map}"));
        entry["valueFrom"]["configMapKeyRef"]["name"] =
            serde_yaml::Value::String("unreviewed-pin-source".to_string());
        assert!(
            migration_production_pin_env_error(&miswired_group, digest_prefix).is_err(),
            "miswired group {config_map} must fail closed"
        );

        if *config_map != POSTGRESQL_INFRASTRUCTURE_ATTESTATION_CONFIG_MAP {
            let mut missing_group = baseline.clone();
            let index = missing_group
                .iter()
                .position(|entry| entry["name"].as_str() == Some(first_key))
                .unwrap_or_else(|| panic!("missing first pin from {config_map}"));
            missing_group.remove(index);
            assert!(
                migration_production_pin_env_error(&missing_group, digest_prefix).is_err(),
                "missing pin from existing group {config_map} must fail closed"
            );

            let mut duplicate_group = baseline.clone();
            let index = duplicate_group
                .iter()
                .position(|entry| entry["name"].as_str() == Some(first_key))
                .unwrap_or_else(|| panic!("missing first pin from {config_map}"));
            duplicate_group[index + 1] = duplicate_group[index].clone();
            assert!(
                migration_production_pin_env_error(&duplicate_group, digest_prefix).is_err(),
                "duplicate pin in existing group {config_map} must fail closed"
            );
        }
    }

    let mut inline = baseline;
    let entry = inline
        .iter_mut()
        .find(|entry| {
            entry["name"].as_str()
                == Some("RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID")
        })
        .expect("PostgreSQL authority pin");
    *entry = serde_yaml::from_str(
        "name: RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID\nvalue: inline-authority\n",
    )
    .expect("inline mutation YAML");
    assert!(migration_production_pin_env_error(&inline, digest_prefix).is_err());
}

#[test]
fn final_render_socket_fixture_checks_diagnostic_shape_without_authorizing_execution() {
    let (job, pins) = final_render_socket_fixture();
    assert!(
        final_render_socket_projection_error(&job, &pins).is_ok(),
        "reviewed final-render inline CSI diagnostic shape must pass its structural check"
    );
    assert_eq!(
        job["spec"]["suspend"], false,
        "the fixture deliberately represents a would-be executable render that the validator must contain"
    );

    let mut mutations = Vec::new();
    let mut missing = job.clone();
    missing["spec"]["template"]["spec"]["volumes"]
        .as_sequence_mut()
        .expect("final-render volumes")
        .remove(2);
    mutations.push(("missing socket volume", missing));

    let mut wrong_driver = job.clone();
    wrong_driver["spec"]["template"]["spec"]["volumes"][2]["csi"]["driver"] =
        serde_yaml::Value::String("unreviewed.example.invalid".to_string());
    mutations.push(("unpinned CSI driver", wrong_driver));

    let mut writable = job.clone();
    writable["spec"]["template"]["spec"]["volumes"][2]["csi"]["readOnly"] =
        serde_yaml::Value::Bool(false);
    mutations.push(("writable CSI volume", writable));

    let mut substituted_path = job.clone();
    substituted_path["spec"]["template"]["spec"]["volumes"][2]["csi"]["volumeAttributes"]["socketPath"] =
        serde_yaml::Value::String("/var/run/substituted/authority.sock".to_string());
    mutations.push(("substituted socket path", substituted_path));

    let mut injected_receipt_digest = job.clone();
    injected_receipt_digest["spec"]["template"]["spec"]["volumes"][2]["csi"]["volumeAttributes"]
        ["receiptDigest"] = serde_yaml::Value::String(format!("sha256:{}", "7".repeat(64)));
    mutations.push((
        "forbidden CSI receipt digest carrier",
        injected_receipt_digest,
    ));

    let mut wrong_mount = job.clone();
    wrong_mount["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][2]["mountPath"] =
        serde_yaml::Value::String("/var/run/substituted".to_string());
    mutations.push(("miswired mount parent", wrong_mount));

    let mut alternate_source = job.clone();
    alternate_source["spec"]["template"]["spec"]["volumes"][2]["emptyDir"] =
        serde_yaml::to_value(serde_json::json!({})).expect("emptyDir mutation");
    mutations.push(("alternate volume source", alternate_source));

    let mut disk_backed_relay = job.clone();
    disk_backed_relay["spec"]["template"]["spec"]["volumes"][1]["emptyDir"]["medium"] =
        serde_yaml::Value::String(String::new());
    mutations.push(("disk-backed relay workspace", disk_backed_relay));

    let mut oversized_relay = job.clone();
    oversized_relay["spec"]["template"]["spec"]["volumes"][1]["emptyDir"]["sizeLimit"] =
        serde_yaml::Value::String("2Mi".to_string());
    mutations.push(("oversized relay workspace", oversized_relay));

    let mut read_only_relay_mount = job.clone();
    read_only_relay_mount["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][1]["readOnly"] =
        serde_yaml::Value::Bool(true);
    mutations.push(("read-only relay workspace mount", read_only_relay_mount));

    let mut wrong_relay_group = job.clone();
    wrong_relay_group["spec"]["template"]["spec"]["securityContext"]["fsGroup"] =
        serde_yaml::Value::Number(10002.into());
    mutations.push(("wrong relay workspace fsGroup", wrong_relay_group));

    for (label, invalid) in mutations {
        assert!(
            final_render_socket_projection_error(&invalid, &pins).is_err(),
            "final render must reject {label}"
        );
    }

    let mut duplicate_paths = pins.clone();
    duplicate_paths[1].socket_path = duplicate_paths[0].socket_path.clone();
    assert!(
        final_render_socket_projection_error(&job, &duplicate_paths).is_err(),
        "rendered ConfigMap socket paths must remain distinct"
    );

    let mut reused_postgresql_key = pins;
    reused_postgresql_key[3].fingerprint = reused_postgresql_key[0].fingerprint.clone();
    assert!(
        final_render_socket_projection_error(&job, &reused_postgresql_key).is_err(),
        "PostgreSQL key fingerprint must differ from the other authorities"
    );
}

#[test]
fn migration_production_execution_is_contained_until_runtime_admission_exists() {
    let contract_raw =
        std::fs::read_to_string("deploy/kubernetes/operations/migration-cutover-contract.yaml")
            .expect("migration cutover contract");
    let contract: serde_yaml::Value =
        serde_yaml::from_str(&contract_raw).expect("migration cutover contract YAML");
    let source_job = parse_multi_doc("deploy/kubernetes/operations/migration-job.yaml")
        .into_iter()
        .next()
        .expect("migration source Job");
    let (final_shape, _) = final_render_socket_fixture();

    assert_eq!(contract["productionExecutionEnabled"], false);
    assert_eq!(
        contract["runtimeAdmission"]["requiredCapability"],
        FINAL_RENDER_REQUIRED_RUNTIME_CAPABILITY
    );
    assert_eq!(contract["runtimeAdmission"]["capabilityAvailable"], false);
    assert_eq!(
        contract["runtimeAdmission"]["offlineSnapshotValidationOnly"],
        true
    );
    for field in [
        "snapshotAuthorizesJobCreation",
        "snapshotFencesConfigMapDeleteRecreate",
        "snapshotConsumesExecutionAttempt",
        "snapshotEnforcesReceiptExpiryAtPodStartOrRuntime",
    ] {
        assert_eq!(
            contract["runtimeAdmission"][field], false,
            "offline validation must not claim runtime enforcement for {field}"
        );
    }
    assert_eq!(source_job["spec"]["suspend"], true);
    assert_eq!(
        source_job["metadata"]["annotations"]["ryuki.io/render-mode"],
        SOURCE_TEMPLATE_MODE
    );
    assert_eq!(
        final_shape["metadata"]["annotations"]["ryuki.io/render-mode"],
        FINAL_RENDER_MODE
    );
    assert_eq!(
        contract["sequence"].as_sequence().map(Vec::len),
        Some(1),
        "contained contract must not retain an executable cutover sequence"
    );
    assert_eq!(
        contract["sequence"][0],
        "stop-production-execution-runtime-admission-unavailable"
    );
    assert!(
        contract["socketProjectionTrustAnchor"].is_null(),
        "production contract must not expose a manifest-selected trust-anchor input"
    );
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
    let final_render = &contract["finalRender"];
    assert_eq!(final_render["contractId"], FINAL_RENDER_CONTRACT);
    assert_eq!(final_render["sourceMode"], SOURCE_TEMPLATE_MODE);
    assert_eq!(final_render["finalMode"], FINAL_RENDER_MODE);
    assert_eq!(final_render["unresolvedSentinel"], RENDER_REQUIRED_SENTINEL);
    assert_eq!(final_render["atomicRewriteRequired"], true);
    assert_eq!(contract["productionExecutionEnabled"], false);
    assert_eq!(
        contract["runtimeAdmission"]["requiredCapability"],
        FINAL_RENDER_REQUIRED_RUNTIME_CAPABILITY
    );
    assert_eq!(
        final_render["pinConfigMapReceipt"]["immutableRequired"],
        true
    );
    assert_eq!(
        final_render["pinConfigMapReceipt"]["receiptMustExactlyMatchApiReadback"],
        true
    );
    assert_eq!(
        final_render["pinConfigMapReceipt"]["offlineSnapshotFencesEnvironmentConfigMapDeleteRecreate"],
        false
    );
    assert_eq!(
        final_render["pinConfigMapReceipt"]["offlineSnapshotFencesNonEnvironmentAuthorityDeleteRecreate"],
        false
    );
    assert_eq!(
        final_render["socketProjectionReceipt"]["exactSocketCount"],
        4
    );
    assert_eq!(
        final_render["socketProjectionReceipt"]["inlineCsiDriver"],
        AUTHORITY_SOCKET_CSI_DRIVER
    );
    assert_eq!(
        final_render["socketProjectionReceipt"]["inlineCsiReadOnlyRequired"],
        true
    );
    let exact_volume_attribute_keys: Vec<&str> =
        final_render["socketProjectionReceipt"]["exactVolumeAttributeKeys"]
            .as_sequence()
            .expect("exact CSI volume attributes")
            .iter()
            .map(|key| key.as_str().expect("CSI volume attribute key"))
            .collect();
    assert_eq!(
        exact_volume_attribute_keys,
        ["environmentVariable", "authorityClass", "socketPath"]
    );
    for flag in [
        "mountsAreSocketParentDirectories",
        "socketPathsDistinctRequired",
        "mountParentPathsDistinctRequired",
        "postgresqlFingerprintDistinctFromOtherAuthoritiesRequired",
    ] {
        assert_eq!(
            final_render["socketProjectionReceipt"][flag], true,
            "final-render socket projection gate {flag} must remain fail-closed"
        );
    }
    assert_eq!(
        final_render["socketProjectionReceipt"]["strictSignedEnvelopeContract"],
        "migration-socket-projection-receipt-v1"
    );
    assert_eq!(
        final_render["socketProjectionReceipt"]["receiptDigestForbiddenInCsiAttributes"],
        true
    );
    assert_eq!(
        final_render["socketProjectionReceipt"]["receiptMaximumAuthorizationSeconds"],
        300
    );
    assert_eq!(
        final_render["socketProjectionReceipt"]["receiptBindsReleaseImageAndAllNinePinConfigMapReceipts"],
        true
    );
    let receipt_payload = &contract["socketProjectionReceiptResource"]["envelope"]["payload"];
    assert_eq!(receipt_payload["pinConfigMapReceiptExactCount"], 9);
    let receipt_order: Vec<&str> = receipt_payload["pinConfigMapReceiptExactOrderByAnnotation"]
        .as_sequence()
        .expect("ordered pin ConfigMap receipt annotations")
        .iter()
        .map(|annotation| annotation.as_str().expect("pin receipt annotation"))
        .collect();
    assert_eq!(receipt_order, MIGRATION_RENDER_PIN_RECEIPT_ANNOTATIONS);
    assert_eq!(
        receipt_payload["offlineSnapshotAllNinePinReceiptsMustMatchApiReadback"],
        true
    );
    assert_eq!(
        final_render["closedSocketContractDigest"],
        SOCKET_CONTRACT_DIGEST
    );
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
    assert_eq!(contract["execution"]["activeDeadlineSeconds"], 300);
    assert_eq!(
        contract["execution"]["maximumProofAuthorizationSeconds"],
        300
    );
    assert_eq!(contract["execution"]["statementTimeoutSeconds"], 180);
    assert_eq!(contract["execution"]["lockTimeoutSeconds"], 30);
    assert_eq!(
        contract["execution"]["singleDatabaseTransactionRequired"],
        true
    );
    assert_eq!(
        contract["execution"]["sessionScopedAdvisoryLockBeforeBeginRequired"],
        true
    );
    assert_eq!(
        contract["execution"]["transactionScopedAdvisoryLockPromotionFirstStatementRequired"],
        true
    );
    assert_eq!(
        contract["execution"]["sessionScopedAdvisoryLockReleasedAfterPromotionRequired"],
        true
    );
    assert_eq!(
        contract["execution"]["migrationSqlCannotReleaseTransactionLockRequired"],
        true
    );

    let projections = &contract["productionPinProjections"];
    let migration_config = &projections["migrationConfig"];
    assert_eq!(
        migration_config["sourceTemplateConfigMapName"],
        "platform-api-migration-config"
    );
    assert_eq!(
        migration_config["finalConfigMapName"],
        digest_scoped_pin_config_map_name("platform-api-migration-config", digest_prefix)
    );
    let migration_config_keys: Vec<&str> = migration_config["configKeys"]
        .as_sequence()
        .expect("migration config keys")
        .iter()
        .map(|key| key.as_str().expect("migration config key"))
        .collect();
    assert_eq!(
        migration_config_keys, PLATFORM_API_MIGRATION_CONFIG_KEYS,
        "migration config pin inventory changed"
    );
    assert_eq!(
        migration_config["finalRenderMustRewriteEnvFromReference"],
        true
    );
    for (field, config_map, keys) in [
        (
            "baselineAdmission",
            digest_scoped_pin_config_map_name(SECURITY_ADMISSION_CONFIG_MAP, digest_prefix),
            SECURITY_ADMISSION_KEYS.as_slice(),
        ),
        (
            "buildManifest",
            digest_scoped_pin_config_map_name(PRODUCTION_BUILD_MANIFEST_CONFIG_MAP, digest_prefix),
            PRODUCTION_BUILD_MANIFEST_KEYS,
        ),
        (
            "conformanceTrustCheckpoint",
            digest_scoped_pin_config_map_name(
                CONFORMANCE_TRUST_CHECKPOINT_CONFIG_MAP,
                digest_prefix,
            ),
            CONFORMANCE_TRUST_CHECKPOINT_KEYS,
        ),
        (
            "deployedWorkloadAttestation",
            digest_scoped_pin_config_map_name(
                DEPLOYED_WORKLOAD_ATTESTATION_CONFIG_MAP,
                digest_prefix,
            ),
            DEPLOYED_WORKLOAD_ATTESTATION_KEYS,
        ),
        (
            "publicIngressAttestation",
            digest_scoped_pin_config_map_name(PUBLIC_INGRESS_ATTESTATION_CONFIG_MAP, digest_prefix),
            PUBLIC_INGRESS_ATTESTATION_KEYS,
        ),
        (
            "firstOwnerAuthority",
            digest_scoped_pin_config_map_name(FIRST_OWNER_AUTHORITY_CONFIG_MAP, digest_prefix),
            FIRST_OWNER_AUTHORITY_KEYS,
        ),
    ] {
        assert_eq!(projections[field]["configMapName"], config_map.as_str());
        let actual_keys: Vec<&str> = projections[field]["configKeys"]
            .as_sequence()
            .expect("production pin ConfigMap keys")
            .iter()
            .map(|key| key.as_str().expect("production pin key"))
            .collect();
        assert_eq!(actual_keys, keys, "pin inventory changed for {field}");
    }
    for flag in [
        "completeGroupsRequired",
        "releaseDigestPrefixBoundNamesRequired",
        "immutableConfigMapsRequired",
        "contentDigestAnnotationsRequired",
        "uidAndResourceVersionReadbackRequired",
        "jobReceiptAnnotationsRequired",
        "inlineValuesForbidden",
        "independentlyGovernedConfigMapsRequired",
        "renderedUnixSocketProjectionsRequired",
        "renderedSocketPathsMustEqualPins",
        "socketAvailabilityBeforeRunnerStartRequired",
        "hostPathFallbackForbidden",
    ] {
        assert_eq!(
            projections[flag], true,
            "production pin projection gate {flag} must stay fail-closed"
        );
    }
    assert_eq!(projections["exactPinConfigMapReceiptCount"], 9);
    for flag in [
        "productionOnly",
        "independentlyGovernedAuthorityRequired",
        "ed25519Required",
        "privateKeyInWorkloadForbidden",
        "detachedCertificateRequired",
        "descriptorPinnedRegularFileRequired",
        "symlinkProjectionForbidden",
        "materializationReceiptRequired",
    ] {
        assert_eq!(
            projections["firstOwnerAuthority"][flag], true,
            "first-owner projection gate {flag} must stay fail-closed"
        );
    }
    assert_eq!(
        projections["firstOwnerAuthority"]["socketProjectionRequired"], false,
        "the first-owner authority is pinned data and must not widen the four-socket inventory"
    );

    let socket_authority = &contract["socketProjectionAuthority"];
    assert_eq!(
        socket_authority["configMapName"],
        digest_scoped_pin_config_map_name(SOCKET_PROJECTION_AUTHORITY_CONFIG_MAP, digest_prefix)
    );
    let socket_authority_keys: Vec<&str> = socket_authority["configKeys"]
        .as_sequence()
        .expect("socket receipt authority pin keys")
        .iter()
        .map(|key| key.as_str().expect("socket receipt authority pin key"))
        .collect();
    assert_eq!(socket_authority_keys, SOCKET_PROJECTION_AUTHORITY_KEYS);
    assert_eq!(socket_authority["importedAsApplicationEnvironment"], false);
    assert_eq!(socket_authority["mountedInWorkload"], false);

    let postgresql = &contract["postgresqlInfrastructureAttestation"];
    assert_eq!(
        postgresql["configMapName"],
        digest_scoped_pin_config_map_name(
            POSTGRESQL_INFRASTRUCTURE_ATTESTATION_CONFIG_MAP,
            digest_prefix
        )
    );
    let postgresql_keys: Vec<&str> = postgresql["configKeys"]
        .as_sequence()
        .expect("PostgreSQL infrastructure pin keys")
        .iter()
        .map(|key| key.as_str().expect("PostgreSQL pin key"))
        .collect();
    assert_eq!(postgresql_keys, POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEYS);
    for flag in [
        "completeGroupRequired",
        "productionOnly",
        "inlineValuesForbidden",
        "independentlyGovernedConfigMapRequired",
        "independentlyGovernedAuthorityRequired",
        "ed25519Required",
        "privateKeyInWorkloadForbidden",
        "preprovisionedUnixSocketRequired",
        "renderedSocketPathMustEqualPin",
        "socketAvailabilityBeforeRunnerStartRequired",
        "hostPathFallbackForbidden",
        "receiptBoundTargetAndStorageRequired",
        "freshNonceRequired",
        "singleExchangeWithoutRetry",
        "socketDistinctFromCheckpointWorkloadAndIngressRequired",
        "keyFingerprintDistinctFromCheckpointWorkloadAndIngressRequired",
        "sqlVisibleFactsObservedLocallyRequired",
        "providerClusterAndStorageSignedEvidenceRequired",
        "directPgConnectionRequired",
        "sameVerifiedConnectionForDdlRequired",
        "sameVerifiedConnectionForPostflightRequired",
        "exactPostflightLedgerRequired",
    ] {
        assert_eq!(
            postgresql[flag], true,
            "PostgreSQL infrastructure gate {flag} must stay fail-closed"
        );
    }
    assert_eq!(postgresql["maximumAuthorizationSeconds"], 300);

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
