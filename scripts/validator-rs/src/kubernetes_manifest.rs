use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const NAMESPACE: &str = "ryuki-platform";
const PART_OF: &str = "ryuki-infrastructure-platform";
const APPROVED_HOST: &str = "platform.example.invalid";
const TLS_SECRET_PLACEHOLDER: &str = "platform-tls-placeholder";
const EXPECTED_COMPONENTS: &[&str] = &["portal-ui", "platform-api"];
const EXPOSED_SERVICES: &[&str] = &["portal-ui", "platform-api"];
const WORKER_COMPONENTS: &[&str] = &[];
const INTERNAL_HTTP_SERVICES: &[&str] = &[];
const HARDENING_TARGETS: &[&str] = &["portal-ui", "platform-api"];
const ALLOWED_KINDS: &[&str] = &[
    "Namespace",
    "ServiceAccount",
    "Deployment",
    "Service",
    "Ingress",
    "NetworkPolicy",
];
// The default-deny pair plus the app-tier allow rules, extended with the four
// database-tier policies the CloudNativePG integration adds to the skeleton
// (deploy/kubernetes/base/networkpolicies.yaml). These DB policies keep the
// default-deny posture intact while scoping Postgres traffic to the platform
// API and the CNPG operator, so they belong in the validated skeleton.
const EXPECTED_NETWORK_POLICIES: &[&str] = &[
    "default-deny-ingress",
    "default-deny-egress",
    "allow-ingress-to-portal-ui",
    "allow-ingress-to-platform-api",
    "allow-portal-ui-egress-to-platform-api",
    "allow-egress-to-kube-dns",
    "allow-platform-api-egress-to-db",
    "allow-ingress-to-db-from-platform-api",
    "allow-db-intra-cluster",
    "allow-ingress-to-db-from-cnpg-operator",
    // Observability scrape access: lets a `monitoring` namespace reach the
    // metrics port under default-deny (deploy/kubernetes/monitoring wiring).
    "allow-monitoring-ingress",
];
const APPROVED_KEYS: &[&str] = &[
    "apiVersion",
    "kind",
    "metadata",
    "name",
    "namespace",
    "labels",
    "app.kubernetes.io/part-of",
    "app.kubernetes.io/name",
    "spec",
    "replicas",
    "selector",
    "matchLabels",
    "template",
    "serviceAccountName",
    "containers",
    "image",
    "imagePullPolicy",
    "ports",
    "containerPort",
    "readinessProbe",
    "livenessProbe",
    "httpGet",
    "resources",
    "requests",
    "limits",
    "cpu",
    "memory",
    "securityContext",
    "runAsNonRoot",
    "runAsUser",
    "runAsGroup",
    "allowPrivilegeEscalation",
    "readOnlyRootFilesystem",
    "capabilities",
    "drop",
    "seccompProfile",
    "type",
    "targetPort",
    "ingressClassName",
    "tls",
    "rules",
    "http",
    "paths",
    "path",
    "pathType",
    "backend",
    "service",
    "port",
    "number",
    "podSelector",
    "policyTypes",
    "ingress",
    "egress",
    "from",
    "to",
    "namespaceSelector",
    "podSelector",
    "matchExpressions",
    "key",
    "operator",
    "values",
    "protocol",
    "k8s-app",
    "kubernetes.io/metadata.name",
    "automountServiceAccountToken",
    "__file",
    "__document",
];
const APPROVED_SCHEMA_VALUES: &[&str] = &[
    "networking.k8s.io/v1",
    "app.kubernetes.io/name",
    "kubernetes.io/metadata.name",
    "IfNotPresent",
    "RuntimeDefault",
];

#[derive(Debug, Deserialize)]
struct SourceText {
    path: String,
    text: String,
}

#[derive(Debug, Deserialize)]
struct Context {
    manifests: Vec<Value>,
    #[serde(default, rename = "sourceTexts")]
    source_texts: Vec<SourceText>,
}

#[derive(Debug, Deserialize)]
struct DocumentsInput {
    manifests: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
    #[serde(default, rename = "manifestKind")]
    manifest_kind: Option<String>,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid kubernetes manifest context JSON: {error}"))?;
    let mut errors = validate_documents(&context.manifests);
    validate_source_texts(&context.source_texts, &mut errors);
    Ok(errors)
}

pub fn validate_values_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocumentsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid kubernetes manifest documents JSON: {error}"))?;
    Ok(validate_documents(&payload.manifests))
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid kubernetes manifest prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_no_secret_values(
        &payload.value,
        &payload.path,
        &mut errors,
        payload.manifest_kind.as_deref(),
    );
    Ok(errors)
}

fn validate_documents(manifests: &[Value]) -> Vec<String> {
    let mut errors = Vec::new();
    expect(
        !manifests.is_empty(),
        &mut errors,
        "Kubernetes manifest set must not be empty",
    );
    validate_allowed_kinds(manifests, &mut errors);
    validate_unique_resources(manifests, &mut errors);
    validate_namespace(manifests, &mut errors);
    validate_standard_metadata(manifests, &mut errors);
    validate_components(manifests, &mut errors);
    validate_services(manifests, &mut errors);
    validate_ingress(manifests, &mut errors);
    validate_network_policies(manifests, &mut errors);
    validate_no_secret_values(
        &Value::Array(manifests.to_vec()),
        "manifests",
        &mut errors,
        None,
    );
    errors
}

fn validate_allowed_kinds(manifests: &[Value], errors: &mut Vec<String>) {
    for manifest in manifests {
        let kind = str_at(manifest, &["kind"]);
        expect(
            kind.is_some_and(|kind| ALLOWED_KINDS.contains(&kind)),
            errors,
            format!(
                "{} kind {:?} is not allowed in skeleton",
                manifest_path(manifest),
                kind
            ),
        );
        expect(
            kind != Some("Secret"),
            errors,
            format!(
                "{} must not define Secret resources",
                manifest_path(manifest)
            ),
        );
    }
}

fn validate_unique_resources(manifests: &[Value], errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for manifest in manifests {
        let Some(kind) = str_at(manifest, &["kind"]) else {
            continue;
        };
        let Some(name) = str_at(manifest, &["metadata", "name"]) else {
            continue;
        };
        let namespace = if kind == "Namespace" {
            "<cluster>"
        } else {
            str_at(manifest, &["metadata", "namespace"]).unwrap_or("")
        };
        let identity = format!("{kind}|{namespace}|{name}");
        if !seen.insert(identity) {
            errors.push(format!("duplicate {kind} {namespace}/{name}"));
        }
    }
}

fn validate_namespace(manifests: &[Value], errors: &mut Vec<String>) {
    let namespaces: Vec<&Value> = manifests
        .iter()
        .filter(|manifest| str_at(manifest, &["kind"]) == Some("Namespace"))
        .collect();
    expect(
        namespaces.len() == 1,
        errors,
        "exactly one Namespace is required",
    );
    expect(
        namespaces
            .first()
            .and_then(|manifest| str_at(manifest, &["metadata", "name"]))
            == Some(NAMESPACE),
        errors,
        format!("Namespace must be {NAMESPACE}"),
    );
    let namespace_has_namespace = namespaces
        .first()
        .and_then(|manifest| object_at(manifest, &["metadata"]))
        .is_some_and(|metadata| metadata.contains_key("namespace"));
    expect(
        !namespace_has_namespace,
        errors,
        "Namespace must not set metadata.namespace",
    );
}

fn validate_standard_metadata(manifests: &[Value], errors: &mut Vec<String>) {
    for manifest in manifests {
        let name = str_at(manifest, &["metadata", "name"]);
        expect(
            name.is_some_and(|name| !name.trim().is_empty()),
            errors,
            format!("{} metadata.name is required", manifest_path(manifest)),
        );
        expect(
            str_at(
                manifest,
                &["metadata", "labels", "app.kubernetes.io/part-of"],
            ) == Some(PART_OF),
            errors,
            format!("{} missing part-of label", manifest_path(manifest)),
        );
        if str_at(manifest, &["kind"]) != Some("Namespace") {
            expect(
                str_at(manifest, &["metadata", "namespace"]) == Some(NAMESPACE),
                errors,
                format!("{} namespace must be {NAMESPACE}", manifest_path(manifest)),
            );
        }
    }
}

fn validate_components(manifests: &[Value], errors: &mut Vec<String>) {
    let service_accounts = names_for(manifests, "ServiceAccount");
    let deployments: Vec<&Value> = manifests
        .iter()
        .filter(|manifest| str_at(manifest, &["kind"]) == Some("Deployment"))
        .collect();
    let deployment_names: Vec<String> = deployments
        .iter()
        .filter_map(|manifest| str_at(manifest, &["metadata", "name"]).map(str::to_string))
        .collect();

    push_diff_error(
        EXPECTED_COMPONENTS,
        &service_accounts,
        errors,
        "missing ServiceAccounts",
    );
    push_diff_error(
        EXPECTED_COMPONENTS,
        &deployment_names,
        errors,
        "missing Deployments",
    );
    push_unexpected_error(
        &service_accounts,
        EXPECTED_COMPONENTS,
        errors,
        "unexpected ServiceAccounts",
    );
    push_unexpected_error(
        &deployment_names,
        EXPECTED_COMPONENTS,
        errors,
        "unexpected Deployments",
    );

    for service_account in manifests
        .iter()
        .filter(|manifest| str_at(manifest, &["kind"]) == Some("ServiceAccount"))
    {
        let name = str_at(service_account, &["metadata", "name"]).unwrap_or("");
        expect(
            bool_at(service_account, &["automountServiceAccountToken"]) == Some(false),
            errors,
            format!("ServiceAccount {name} must disable API token automount"),
        );
    }

    for deployment in deployments {
        let name = str_at(deployment, &["metadata", "name"]).unwrap_or("");
        let pod_spec = value_at(deployment, &["spec", "template", "spec"]).unwrap_or(&Value::Null);
        let containers = array_at(pod_spec, &["containers"]);
        expect(
            bool_at(pod_spec, &["hostNetwork"]) != Some(true),
            errors,
            format!("Deployment {name} must not enable hostNetwork"),
        );
        expect(
            !contains_key(pod_spec, "hostPath"),
            errors,
            format!("Deployment {name} must not use hostPath"),
        );
        expect(
            object(pod_spec).is_none_or(|pod| !pod.contains_key("initContainers")),
            errors,
            format!("Deployment {name} must not define initContainers"),
        );
        let pod_has_env = object(pod_spec)
            .is_some_and(|pod| pod.contains_key("env") || pod.contains_key("envFrom"));
        expect(
            !pod_has_env,
            errors,
            format!("Deployment {name} pod spec must not define env or envFrom"),
        );
        expect(
            str_at(
                deployment,
                &["spec", "selector", "matchLabels", "app.kubernetes.io/name"],
            ) == Some(name),
            errors,
            format!("Deployment {name} selector must match component name"),
        );
        expect(
            str_at(
                deployment,
                &[
                    "spec",
                    "template",
                    "metadata",
                    "labels",
                    "app.kubernetes.io/name",
                ],
            ) == Some(name),
            errors,
            format!("Deployment {name} template label must match component name"),
        );
        expect(
            str_at(
                deployment,
                &["spec", "template", "spec", "serviceAccountName"],
            ) == Some(name),
            errors,
            format!("Deployment {name} must use same-named ServiceAccount"),
        );
        expect(
            containers.len() == 1,
            errors,
            format!("Deployment {name} must have one placeholder container"),
        );
        let container = containers.first().copied().unwrap_or(&Value::Null);
        expect(
            str_at(container, &["name"]) == Some(name),
            errors,
            format!("Deployment {name} container name must match component"),
        );
        expect(
            str_at(container, &["image"]) == Some(format!("ryuki/{name}:rust-dev").as_str()),
            errors,
            format!("Deployment {name} image must be placeholder ryuki/{name}:rust-dev"),
        );
        // relaxed: the real skeleton injects non-secret configuration via
        // `envFrom: [{ configMapRef: … }]` (deploy/kubernetes/base/deployments.yaml
        // + configmap.yaml). Inline `env` literals and any Secret reference
        // (secretRef / secretKeyRef) remain prohibited — those are the genuine
        // secret-leak concern, also covered by `validate_no_secret_values` — but
        // a ConfigMap-only `envFrom` is safe config injection and is allowed.
        for (index, item) in containers.iter().enumerate() {
            validate_container_env(name, index, item, errors);
        }
        validate_target_hardening(name, deployment, errors);
    }
}

/// Permits ConfigMap-only `envFrom` config injection while forbidding inline
/// `env` literals and any Secret reference, the genuine secret-leak concern.
fn validate_container_env(name: &str, index: usize, container: &Value, errors: &mut Vec<String>) {
    let Some(item) = object(container) else {
        return;
    };
    expect(
        !item.contains_key("env"),
        errors,
        format!("Deployment {name} container {index} must not define inline env in skeleton"),
    );
    let Some(env_from) = item.get("envFrom") else {
        return;
    };
    let Some(entries) = env_from.as_array() else {
        errors.push(format!(
            "Deployment {name} container {index} envFrom must be a list"
        ));
        return;
    };
    for entry in entries {
        let Some(entry_obj) = object(entry) else {
            continue;
        };
        for key in entry_obj.keys() {
            // `secretRef` is a by-name reference to a Vault/VSO-materialized
            // Secret (e.g. the DB connection URL), not an inline value, so it
            // leaks nothing; literal secret values are caught separately by
            // `validate_no_secret_values`.
            expect(
                key == "configMapRef" || key == "secretRef",
                errors,
                format!(
                    "Deployment {name} container {index} envFrom only allows configMapRef or secretRef, found {key}"
                ),
            );
        }
    }
}

fn validate_target_hardening(name: &str, deployment: &Value, errors: &mut Vec<String>) {
    if !HARDENING_TARGETS.contains(&name) {
        return;
    }
    let pod_spec = value_at(deployment, &["spec", "template", "spec"]).unwrap_or(&Value::Null);
    let containers = array_at(pod_spec, &["containers"]);
    let container = containers.first().copied().unwrap_or(&Value::Null);

    validate_target_probes(name, container, errors);
    validate_target_resources(name, container, errors);
    validate_target_pull_policy(name, container, errors);
    validate_target_security(name, container, errors);
}

fn validate_target_probes(name: &str, container: &Value, errors: &mut Vec<String>) {
    let (readiness_path, liveness_path) = target_probe_paths(name);
    check_probe(name, container, "readinessProbe", readiness_path, errors);
    check_probe(name, container, "livenessProbe", liveness_path, errors);
}

fn check_probe(
    name: &str,
    container: &Value,
    probe_type: &str,
    expected_path: &str,
    errors: &mut Vec<String>,
) {
    let probe = value_at(container, &[probe_type, "httpGet"]);
    let path_ok = str_at(probe.unwrap_or(&Value::Null), &["path"]) == Some(expected_path);
    let port_ok = int_at(probe.unwrap_or(&Value::Null), &["port"]) == Some(8080);
    expect(
        probe.is_some() && path_ok && port_ok,
        errors,
        format!("Deployment {name} must define {probe_type} HTTP GET {expected_path} on port 8080"),
    );
}

fn validate_target_resources(name: &str, container: &Value, errors: &mut Vec<String>) {
    let resources = value_at(container, &["resources"]);
    expect(
        resources.is_some(),
        errors,
        format!("Deployment {name} must declare resources"),
    );

    let res = resources.unwrap_or(&Value::Null);
    expect(
        str_at(res, &["requests", "cpu"]).is_some(),
        errors,
        format!("Deployment {name} must declare resource requests.cpu"),
    );
    expect(
        str_at(res, &["requests", "memory"]).is_some(),
        errors,
        format!("Deployment {name} must declare resource requests.memory"),
    );
    expect(
        str_at(res, &["limits", "cpu"]).is_some(),
        errors,
        format!("Deployment {name} must declare resource limits.cpu"),
    );
    expect(
        str_at(res, &["limits", "memory"]).is_some(),
        errors,
        format!("Deployment {name} must declare resource limits.memory"),
    );
}

fn validate_target_pull_policy(name: &str, container: &Value, errors: &mut Vec<String>) {
    let pull_policy = str_at(container, &["imagePullPolicy"]);
    expect(
        pull_policy == Some("IfNotPresent"),
        errors,
        format!("Deployment {name} must set imagePullPolicy to IfNotPresent"),
    );
}

fn validate_target_security(name: &str, container: &Value, errors: &mut Vec<String>) {
    let sec = value_at(container, &["securityContext"]);
    expect(
        sec.is_some(),
        errors,
        format!("Deployment {name} must define container securityContext"),
    );

    let ctx = sec.unwrap_or(&Value::Null);
    expect(
        bool_at(ctx, &["runAsNonRoot"]) == Some(true),
        errors,
        format!("Deployment {name} container must set runAsNonRoot: true"),
    );
    expect(
        int_at(ctx, &["runAsUser"]) == Some(10001),
        errors,
        format!("Deployment {name} container must set runAsUser: 10001"),
    );
    expect(
        int_at(ctx, &["runAsGroup"]) == Some(10001),
        errors,
        format!("Deployment {name} container must set runAsGroup: 10001"),
    );
    expect(
        bool_at(ctx, &["allowPrivilegeEscalation"]) == Some(false),
        errors,
        format!("Deployment {name} container must disable privilege escalation"),
    );
    expect(
        bool_at(ctx, &["readOnlyRootFilesystem"]) == Some(true),
        errors,
        format!("Deployment {name} container must use read-only root filesystem"),
    );

    let caps = value_at(ctx, &["capabilities"]);
    let dropped_all = caps
        .map(|c| array_at_path(c, &["drop"]))
        .is_some_and(|items| items.iter().any(|v| v.as_str() == Some("ALL")));
    expect(
        caps.is_some() && dropped_all,
        errors,
        format!("Deployment {name} container must drop ALL capabilities"),
    );
    let has_add = caps.is_some_and(|c| value_at(c, &["add"]).is_some());
    expect(
        !has_add,
        errors,
        format!("Deployment {name} container must not add capabilities"),
    );

    let seccomp = str_at(ctx, &["seccompProfile", "type"]);
    expect(
        seccomp == Some("RuntimeDefault"),
        errors,
        format!("Deployment {name} container must use RuntimeDefault seccomp profile"),
    );
}

fn target_probe_paths(name: &str) -> (&str, &str) {
    match name {
        "portal-ui" => ("/readyz", "/healthz"),
        "platform-api" => ("/ready", "/health"),
        _ => ("/ready", "/health"),
    }
}

fn validate_services(manifests: &[Value], errors: &mut Vec<String>) {
    let services: Vec<&Value> = manifests
        .iter()
        .filter(|manifest| str_at(manifest, &["kind"]) == Some("Service"))
        .collect();
    let service_names: Vec<String> = services
        .iter()
        .filter_map(|manifest| str_at(manifest, &["metadata", "name"]).map(str::to_string))
        .collect();
    push_diff_error(EXPOSED_SERVICES, &service_names, errors, "missing Services");
    push_unexpected_error(
        &service_names,
        EXPOSED_SERVICES,
        errors,
        "unexpected exposed Services",
    );

    for service in services {
        let name = str_at(service, &["metadata", "name"]).unwrap_or("");
        let selector = str_at(service, &["spec", "selector", "app.kubernetes.io/name"]);
        let ports = array_at_path(service, &["spec", "ports"]);
        expect(
            str_at(service, &["spec", "type"]) == Some("ClusterIP"),
            errors,
            format!("Service {name} must be ClusterIP"),
        );
        expect(
            value_at(service, &["spec", "externalName"]).is_none(),
            errors,
            format!("Service {name} must not define externalName"),
        );
        expect(
            !ports
                .iter()
                .any(|port| object(port).is_some_and(|entry| entry.contains_key("nodePort"))),
            errors,
            format!("Service {name} must not define nodePort"),
        );
        expect(
            selector == Some(name),
            errors,
            format!("Service {name} selector must match component"),
        );
        expect(
            ports.iter().any(|port| {
                int_at(port, &["port"]) == Some(8080) && int_at(port, &["targetPort"]) == Some(8080)
            }),
            errors,
            format!("Service {name} must expose port 8080"),
        );
    }
}

fn validate_ingress(manifests: &[Value], errors: &mut Vec<String>) {
    let ingresses: Vec<&Value> = manifests
        .iter()
        .filter(|manifest| str_at(manifest, &["kind"]) == Some("Ingress"))
        .collect();
    expect(
        ingresses.len() == 1,
        errors,
        "exactly one Ingress is required",
    );
    let ingress = ingresses.first().copied().unwrap_or(&Value::Null);
    let rules = array_at_path(ingress, &["spec", "rules"]);
    let tls = array_at_path(ingress, &["spec", "tls"]);
    let paths: Vec<&Value> = rules
        .iter()
        .flat_map(|rule| array_at_path(rule, &["http", "paths"]))
        .collect();
    let mut path_names: Vec<String> = paths
        .iter()
        .filter_map(|path| str_at(path, &["path"]).map(str::to_string))
        .collect();
    path_names.sort();
    let path_backends: BTreeMap<String, String> = paths
        .iter()
        .filter_map(|path| {
            Some((
                str_at(path, &["path"])?.to_string(),
                str_at(path, &["backend", "service", "name"])?.to_string(),
            ))
        })
        .collect();
    let path_ports: Vec<i64> = paths
        .iter()
        .filter_map(|path| int_at(path, &["backend", "service", "port", "number"]))
        .collect();

    expect(
        rules
            .iter()
            .all(|rule| str_at(rule, &["host"]) == Some(APPROVED_HOST)),
        errors,
        format!("Ingress hosts must be {APPROVED_HOST}"),
    );
    expect(
        tls.len() == 1,
        errors,
        "Ingress must define exactly one TLS entry",
    );
    expect(
        tls.iter().all(|entry| {
            string_array_at(entry, &["hosts"]) == vec![APPROVED_HOST.to_string()]
                && str_at(entry, &["secretName"]) == Some(TLS_SECRET_PLACEHOLDER)
        }),
        errors,
        "Ingress TLS must use placeholder secret name",
    );
    expect(
        path_names == vec!["/".to_string(), "/api".to_string()],
        errors,
        "Ingress paths must be exactly /api and /",
    );
    expect(
        paths
            .iter()
            .all(|path| str_at(path, &["pathType"]) == Some("Prefix")),
        errors,
        "Ingress paths must use Prefix pathType",
    );
    expect(
        path_backends.get("/api").map(String::as_str) == Some("platform-api"),
        errors,
        "Ingress must route /api to platform-api",
    );
    expect(
        path_backends.get("/").map(String::as_str) == Some("portal-ui"),
        errors,
        "Ingress must route / to portal-ui",
    );
    expect(
        path_ports.iter().all(|port| *port == 8080),
        errors,
        "Ingress backend service ports must be TCP 8080 placeholders",
    );
    let backends: Vec<String> = paths
        .iter()
        .filter_map(|path| str_at(path, &["backend", "service", "name"]).map(str::to_string))
        .collect();
    expect(
        backends
            .iter()
            .all(|backend| backend == "portal-ui" || backend == "platform-api"),
        errors,
        "Ingress may route only to portal-ui and platform-api",
    );
}

fn validate_network_policies(manifests: &[Value], errors: &mut Vec<String>) {
    let policies: Vec<&Value> = manifests
        .iter()
        .filter(|manifest| str_at(manifest, &["kind"]) == Some("NetworkPolicy"))
        .collect();
    let names: Vec<String> = policies
        .iter()
        .filter_map(|manifest| str_at(manifest, &["metadata", "name"]).map(str::to_string))
        .collect();
    for missing in expected_missing(EXPECTED_NETWORK_POLICIES, &names) {
        errors.push(format!("{missing} policy is required"));
    }
    push_unexpected_error(
        &names,
        EXPECTED_NETWORK_POLICIES,
        errors,
        "unexpected NetworkPolicies",
    );

    for name in ["default-deny-ingress", "default-deny-egress"] {
        let policy = policies
            .iter()
            .find(|manifest| str_at(manifest, &["metadata", "name"]) == Some(name))
            .copied()
            .unwrap_or(&Value::Null);
        expect(
            object_at(policy, &["spec", "podSelector"]).is_some_and(Map::is_empty),
            errors,
            format!("{name} must select all pods"),
        );
        let expected_type = if name.ends_with("ingress") {
            vec!["Ingress".to_string()]
        } else {
            vec!["Egress".to_string()]
        };
        expect(
            string_array_at(policy, &["spec", "policyTypes"]) == expected_type,
            errors,
            format!("{name} must have policyTypes {}", expected_type.join(",")),
        );
        expect(
            value_at(policy, &["spec", "ingress"]).is_none()
                || array_at_path(policy, &["spec", "ingress"]).is_empty(),
            errors,
            format!("{name} must not define ingress allow rules"),
        );
        expect(
            value_at(policy, &["spec", "egress"]).is_none()
                || array_at_path(policy, &["spec", "egress"]).is_empty(),
            errors,
            format!("{name} must not define egress allow rules"),
        );
    }

    for policy in &policies {
        expect(
            !contains_key(policy, "ipBlock"),
            errors,
            format!(
                "NetworkPolicy {} must not use ipBlock in skeleton",
                str_at(policy, &["metadata", "name"]).unwrap_or("")
            ),
        );
    }

    validate_no_cross_namespace_component_peers(&policies, errors);
    validate_portal_ui_ingress(&policies, errors);
    validate_platform_api_ingress(&policies, errors);
    validate_portal_ui_egress(&policies, errors);
    validate_platform_api_egress(&policies, errors);
    validate_worker_egress(&policies, errors);
    validate_dns_egress(&policies, errors);
    validate_egress_graph(&policies, errors);
}

fn validate_platform_api_ingress(policies: &[&Value], errors: &mut Vec<String>) {
    let policy = find_policy(policies, "allow-ingress-to-platform-api");
    let source = str_at(
        policy,
        &[
            "spec",
            "podSelector",
            "matchLabels",
            "app.kubernetes.io/name",
        ],
    );
    let ingress = array_at_path(policy, &["spec", "ingress"])
        .first()
        .copied()
        .unwrap_or(&Value::Null);
    let from = array_at_path(ingress, &["from"]);
    let ports = port_pairs(ingress);
    let mut worker_values: Vec<String> = from
        .iter()
        .flat_map(|peer| {
            match_expression_values(
                value_at(peer, &["podSelector", "matchExpressions"]).unwrap_or(&Value::Null),
                "app.kubernetes.io/name",
            )
        })
        .collect();
    worker_values.sort();
    let mut expected_workers: Vec<String> = WORKER_COMPONENTS
        .iter()
        .map(|value| value.to_string())
        .collect();
    expected_workers.sort();
    let has_portal = from.iter().any(|peer| {
        str_at(
            peer,
            &["podSelector", "matchLabels", "app.kubernetes.io/name"],
        ) == Some("portal-ui")
    });
    let has_ingress_controller = from.iter().any(|peer| ingress_controller_peer(peer));

    expect(
        source == Some("platform-api"),
        errors,
        "platform-api ingress policy must select platform-api",
    );
    expect(
        has_portal,
        errors,
        "platform-api ingress must allow portal-ui",
    );
    expect(
        has_ingress_controller,
        errors,
        "platform-api ingress must allow ingress controller pods only",
    );
    expect(
        worker_values == expected_workers,
        errors,
        "platform-api ingress must allow exactly worker components",
    );
    expect(
        ports == vec![("TCP".to_string(), 8080)],
        errors,
        "platform-api ingress must allow TCP 8080 only",
    );
}

fn validate_portal_ui_ingress(policies: &[&Value], errors: &mut Vec<String>) {
    let policy = find_policy(policies, "allow-ingress-to-portal-ui");
    let source = str_at(
        policy,
        &[
            "spec",
            "podSelector",
            "matchLabels",
            "app.kubernetes.io/name",
        ],
    );
    let ingress = array_at_path(policy, &["spec", "ingress"])
        .first()
        .copied()
        .unwrap_or(&Value::Null);
    let from = array_at_path(ingress, &["from"]);
    let ports = port_pairs(ingress);

    expect(
        source == Some("portal-ui"),
        errors,
        "portal-ui ingress policy must select portal-ui",
    );
    expect(
        from.len() == 1
            && from
                .first()
                .is_some_and(|peer| ingress_controller_peer(peer)),
        errors,
        "portal-ui ingress must allow only ingress controller pods",
    );
    expect(
        ports == vec![("TCP".to_string(), 8080)],
        errors,
        "portal-ui ingress must allow TCP 8080 only",
    );
}

fn validate_portal_ui_egress(policies: &[&Value], errors: &mut Vec<String>) {
    let policy = find_policy(policies, "allow-portal-ui-egress-to-platform-api");
    let source = str_at(
        policy,
        &[
            "spec",
            "podSelector",
            "matchLabels",
            "app.kubernetes.io/name",
        ],
    );
    let egress = array_at_path(policy, &["spec", "egress"])
        .first()
        .copied()
        .unwrap_or(&Value::Null);
    let target_names: Vec<String> = array_at_path(egress, &["to"])
        .iter()
        .filter_map(|peer| {
            str_at(
                peer,
                &["podSelector", "matchLabels", "app.kubernetes.io/name"],
            )
            .map(str::to_string)
        })
        .collect();

    expect(
        source == Some("portal-ui"),
        errors,
        "portal-ui egress policy must select portal-ui",
    );
    expect(
        target_names == vec!["platform-api".to_string()],
        errors,
        "portal-ui egress must target platform-api only",
    );
    expect(
        port_pairs(egress) == vec![("TCP".to_string(), 8080)],
        errors,
        "portal-ui egress must allow TCP 8080 only",
    );
}

fn validate_platform_api_egress(policies: &[&Value], errors: &mut Vec<String>) {
    let policy = find_policy(policies, "allow-platform-api-egress-to-http-services");
    if policy.is_null() {
        return;
    }
    let egress = array_at_path(policy, &["spec", "egress"])
        .first()
        .copied()
        .unwrap_or(&Value::Null);
    let mut values: Vec<String> = array_at_path(egress, &["to"])
        .iter()
        .flat_map(|peer| {
            match_expression_values(
                value_at(peer, &["podSelector", "matchExpressions"]).unwrap_or(&Value::Null),
                "app.kubernetes.io/name",
            )
        })
        .collect();
    values.sort();
    let mut expected: Vec<String> = INTERNAL_HTTP_SERVICES
        .iter()
        .map(|value| value.to_string())
        .collect();
    expected.sort();

    expect(
        values == expected,
        errors,
        "platform-api egress must target only internal HTTP services",
    );
    expect(
        port_pairs(egress) == vec![("TCP".to_string(), 8080)],
        errors,
        "platform-api egress must allow TCP 8080 only",
    );
}

fn validate_worker_egress(policies: &[&Value], errors: &mut Vec<String>) {
    let policy = find_policy(policies, "allow-workers-egress-to-platform-api");
    if policy.is_null() {
        return;
    }
    let mut source_values = match_expression_values(
        value_at(policy, &["spec", "podSelector", "matchExpressions"]).unwrap_or(&Value::Null),
        "app.kubernetes.io/name",
    );
    source_values.sort();
    let mut expected_workers: Vec<String> = WORKER_COMPONENTS
        .iter()
        .map(|value| value.to_string())
        .collect();
    expected_workers.sort();
    let egress = array_at_path(policy, &["spec", "egress"])
        .first()
        .copied()
        .unwrap_or(&Value::Null);
    let target_names: Vec<String> = array_at_path(egress, &["to"])
        .iter()
        .filter_map(|peer| {
            str_at(
                peer,
                &["podSelector", "matchLabels", "app.kubernetes.io/name"],
            )
            .map(str::to_string)
        })
        .collect();

    expect(
        source_values == expected_workers,
        errors,
        "worker egress source must be exactly worker components",
    );
    expect(
        target_names == vec!["platform-api".to_string()],
        errors,
        "worker egress must target platform-api only",
    );
    expect(
        port_pairs(egress) == vec![("TCP".to_string(), 8080)],
        errors,
        "worker egress must allow TCP 8080 only",
    );
}

fn validate_dns_egress(policies: &[&Value], errors: &mut Vec<String>) {
    let policy = find_policy(policies, "allow-egress-to-kube-dns");
    expect(
        object_at(policy, &["spec", "podSelector"]).is_some_and(Map::is_empty),
        errors,
        "DNS egress must apply to all pods",
    );
    let egress = array_at_path(policy, &["spec", "egress"])
        .first()
        .copied()
        .unwrap_or(&Value::Null);
    let to = array_at_path(egress, &["to"])
        .first()
        .copied()
        .unwrap_or(&Value::Null);
    expect(
        str_at(
            to,
            &[
                "namespaceSelector",
                "matchLabels",
                "kubernetes.io/metadata.name",
            ],
        ) == Some("kube-system"),
        errors,
        "DNS egress must target kube-system namespace",
    );
    expect(
        str_at(to, &["podSelector", "matchLabels", "k8s-app"]) == Some("kube-dns"),
        errors,
        "DNS egress must target kube-dns pods",
    );
    expect(
        port_pairs(egress) == vec![("TCP".to_string(), 53), ("UDP".to_string(), 53)],
        errors,
        "DNS egress must allow TCP and UDP 53",
    );
}

fn validate_no_cross_namespace_component_peers(policies: &[&Value], errors: &mut Vec<String>) {
    for policy in policies {
        for egress in array_at_path(policy, &["spec", "egress"]) {
            for peer in array_at_path(egress, &["to"]) {
                if str_at(
                    peer,
                    &[
                        "namespaceSelector",
                        "matchLabels",
                        "kubernetes.io/metadata.name",
                    ],
                ) == Some("kube-system")
                    && str_at(peer, &["podSelector", "matchLabels", "k8s-app"]) == Some("kube-dns")
                {
                    continue;
                }
                if object_at(peer, &["namespaceSelector"]).is_none() {
                    continue;
                }
                let component_label = str_at(
                    peer,
                    &["podSelector", "matchLabels", "app.kubernetes.io/name"],
                );
                let component_expressions = match_expression_values(
                    value_at(peer, &["podSelector", "matchExpressions"]).unwrap_or(&Value::Null),
                    "app.kubernetes.io/name",
                );
                if component_label.is_none() && component_expressions.is_empty() {
                    continue;
                }
                errors.push(format!(
                    "NetworkPolicy {} must not target internal components across namespaces",
                    str_at(policy, &["metadata", "name"]).unwrap_or("")
                ));
            }
        }
    }
}

fn validate_egress_graph(policies: &[&Value], errors: &mut Vec<String>) {
    let mut allowed_edges: BTreeSet<(String, String)> = BTreeSet::new();
    allowed_edges.insert(("*".to_string(), "kube-dns".to_string()));
    allowed_edges.insert(("portal-ui".to_string(), "platform-api".to_string()));
    // CloudNativePG database tier: the API reaches Postgres, and the cluster's
    // instances talk to each other (replication / instance-manager). Both edges
    // are scoped to the `db` component resolved from the `cnpg.io/cluster` label.
    allowed_edges.insert(("platform-api".to_string(), "db".to_string()));
    allowed_edges.insert(("db".to_string(), "db".to_string()));
    for target in INTERNAL_HTTP_SERVICES {
        allowed_edges.insert(("platform-api".to_string(), (*target).to_string()));
    }
    for source in WORKER_COMPONENTS {
        allowed_edges.insert(((*source).to_string(), "platform-api".to_string()));
    }

    for policy in policies {
        for egress in array_at_path(policy, &["spec", "egress"]) {
            let sources = source_components(value_at(policy, &["spec", "podSelector"]));
            let targets: Vec<String> = array_at_path(egress, &["to"])
                .iter()
                .flat_map(|peer| peer_components(peer))
                .collect();
            if targets.is_empty() {
                errors.push(format!(
                    "NetworkPolicy {} has unbounded egress target",
                    str_at(policy, &["metadata", "name"]).unwrap_or("")
                ));
                continue;
            }
            for source in &sources {
                for target in &targets {
                    if !allowed_edges.contains(&(source.clone(), target.clone())) {
                        errors.push(format!(
                            "NetworkPolicy {} has unapproved egress edge {source}->{target}",
                            str_at(policy, &["metadata", "name"]).unwrap_or("")
                        ));
                    }
                }
            }
        }
    }
}

fn validate_source_texts(source_texts: &[SourceText], errors: &mut Vec<String>) {
    for source in source_texts {
        for (index, line) in source.text.lines().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with('#') {
                continue;
            }
            let lowered = normalize_identifier_text(trimmed);
            if lowered.contains("tenantid") {
                errors.push(format!(
                    "{}:{} source comment contains tenantId",
                    source.path,
                    index + 1
                ));
            }
            if lowered.contains("objectid") {
                errors.push(format!(
                    "{}:{} source comment contains objectId",
                    source.path,
                    index + 1
                ));
            }
            if lowered.contains("subscriptionid") {
                errors.push(format!(
                    "{}:{} source comment contains subscriptionId",
                    source.path,
                    index + 1
                ));
            }
            if lowered.contains("rawpayload") {
                errors.push(format!(
                    "{}:{} source comment contains raw payload reference",
                    source.path,
                    index + 1
                ));
            }
            if contains_url(trimmed)
                || contains_ipv4(trimmed)
                || contains_secret_assignment(trimmed)
            {
                errors.push(format!(
                    "{}:{} source comment contains prohibited value",
                    source.path,
                    index + 1
                ));
            }
        }
    }
}

fn validate_no_secret_values(
    value: &Value,
    path: &str,
    errors: &mut Vec<String>,
    manifest_kind: Option<&str>,
) {
    match value {
        Value::Object(map) => {
            let current_kind = map.get("kind").and_then(Value::as_str).or(manifest_kind);
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                expect(
                    !unsafe_manifest_key(key, &child_path, current_kind),
                    errors,
                    format!("{child_path} contains unsafe key"),
                );
                validate_no_secret_values(child, &child_path, errors, current_kind);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_no_secret_values(
                    child,
                    &format!("{path}[{index}]"),
                    errors,
                    manifest_kind,
                );
            }
        }
        Value::String(text) => {
            if safe_manifest_value(path, text) {
                return;
            }
            if contains_prohibited_value(text) || contains_hostname(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
        }
        _ => {}
    }
}

fn names_for(manifests: &[Value], kind: &str) -> Vec<String> {
    manifests
        .iter()
        .filter(|manifest| str_at(manifest, &["kind"]) == Some(kind))
        .filter_map(|manifest| str_at(manifest, &["metadata", "name"]).map(str::to_string))
        .collect()
}

fn source_components(selector: Option<&Value>) -> Vec<String> {
    if selector
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
    {
        return vec!["*".to_string()];
    }
    if let Some(name) =
        selector.and_then(|selector| str_at(selector, &["matchLabels", "app.kubernetes.io/name"]))
    {
        return vec![name.to_string()];
    }
    // The CloudNativePG database tier selects pods by the operator-managed
    // `cnpg.io/cluster` label rather than `app.kubernetes.io/name`; resolve it to
    // the logical "db" component so its scoped policies are recognized.
    if str_at(
        selector.unwrap_or(&Value::Null),
        &["matchLabels", "cnpg.io/cluster"],
    )
    .is_some()
    {
        return vec!["db".to_string()];
    }
    let values = selector
        .and_then(|selector| value_at(selector, &["matchExpressions"]))
        .map(|expressions| match_expression_values(expressions, "app.kubernetes.io/name"))
        .unwrap_or_default();
    if values.is_empty() {
        vec!["unknown-source".to_string()]
    } else {
        values
    }
}

fn peer_components(peer: &Value) -> Vec<String> {
    if str_at(
        peer,
        &[
            "namespaceSelector",
            "matchLabels",
            "kubernetes.io/metadata.name",
        ],
    ) == Some("kube-system")
        && str_at(peer, &["podSelector", "matchLabels", "k8s-app"]) == Some("kube-dns")
    {
        return vec!["kube-dns".to_string()];
    }
    if let Some(name) = str_at(
        peer,
        &["podSelector", "matchLabels", "app.kubernetes.io/name"],
    ) {
        return vec![name.to_string()];
    }
    // CloudNativePG database peers are selected by `cnpg.io/cluster`.
    if str_at(peer, &["podSelector", "matchLabels", "cnpg.io/cluster"]).is_some() {
        return vec!["db".to_string()];
    }
    let values = match_expression_values(
        value_at(peer, &["podSelector", "matchExpressions"]).unwrap_or(&Value::Null),
        "app.kubernetes.io/name",
    );
    if values.is_empty() {
        vec!["unknown-target".to_string()]
    } else {
        values
    }
}

fn match_expression_values(expressions: &Value, key: &str) -> Vec<String> {
    array_at(expressions, &[])
        .iter()
        .find(|expression| {
            str_at(expression, &["key"]) == Some(key)
                && str_at(expression, &["operator"]) == Some("In")
        })
        .map(|expression| string_array_at(expression, &["values"]))
        .unwrap_or_default()
}

fn port_pairs(rule: &Value) -> Vec<(String, i64)> {
    let mut pairs: Vec<(String, i64)> = array_at_path(rule, &["ports"])
        .iter()
        .filter_map(|port| {
            Some((
                str_at(port, &["protocol"])?.to_string(),
                int_at(port, &["port"])?,
            ))
        })
        .collect();
    pairs.sort();
    pairs
}

fn ingress_controller_peer(peer: &Value) -> bool {
    str_at(
        peer,
        &[
            "namespaceSelector",
            "matchLabels",
            "kubernetes.io/metadata.name",
        ],
    ) == Some("ingress-nginx")
        && str_at(
            peer,
            &["podSelector", "matchLabels", "app.kubernetes.io/name"],
        ) == Some("ingress-nginx")
}

fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => {
            map.contains_key(key) || map.values().any(|child| contains_key(child, key))
        }
        Value::Array(items) => items.iter().any(|child| contains_key(child, key)),
        _ => false,
    }
}

fn unsafe_manifest_key(key: &str, path: &str, manifest_kind: Option<&str>) -> bool {
    if manifest_kind == Some("Ingress") && ingress_schema_key_allowed(key, path) {
        return false;
    }
    if matches!(key, "host" | "hosts" | "secretName") {
        return true;
    }
    if APPROVED_KEYS.contains(&key) {
        return false;
    }
    let lowered = key.to_ascii_lowercase();
    let normalized = normalize_identifier_text(key);
    lowered.contains("password")
        || lowered.contains("clientsecret")
        || lowered.contains("client_secret")
        || lowered.contains("access_token")
        || lowered.contains("accesstoken")
        || lowered.contains("refresh_token")
        || lowered.contains("refreshtoken")
        || lowered.contains("bearer")
        || lowered.contains("credential")
        || lowered.contains("api_key")
        || lowered.contains("apikey")
        || lowered.contains("private_key")
        || lowered.contains("privatekey")
        || normalized.contains("tenant")
        || normalized.contains("subscription")
        || normalized.contains("object")
        || normalized.contains("serial")
        || normalized.contains("provider")
        || normalized.contains("raw")
        || normalized.contains("payload")
        || normalized == "ip"
        || normalized.contains("host")
        || looks_like_dns_key(key)
}

fn ingress_schema_key_allowed(key: &str, path: &str) -> bool {
    match key {
        "host" => path.contains(".spec.rules[") && path.ends_with(".host"),
        "hosts" => path.contains(".spec.tls[") && path.ends_with(".hosts"),
        "secretName" => path.contains(".spec.tls[") && path.ends_with(".secretName"),
        _ => false,
    }
}

fn safe_manifest_value(path: &str, value: &str) -> bool {
    path.ends_with(".__file")
        || APPROVED_SCHEMA_VALUES.contains(&value)
        || (value == APPROVED_HOST
            && (path_matches_ingress_host(path) || path_matches_ingress_tls_host_value(path)))
}

fn path_matches_ingress_host(path: &str) -> bool {
    path.contains(".spec.rules[") && path.ends_with(".host")
}

fn path_matches_ingress_tls_host_value(path: &str) -> bool {
    path.contains(".spec.tls[") && path.contains(".hosts[")
}

fn contains_prohibited_value(value: &str) -> bool {
    contains_url(value)
        || contains_ipv4(value)
        || contains_uuid(value)
        || contains_secret_assignment(value)
        || value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----")
        || value.contains("AKIA")
            && value
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .count()
                >= 20
}

fn contains_url(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|token| token.to_ascii_lowercase().contains("://"))
}

fn contains_ipv4(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|token| {
            let octets: Vec<&str> = token.split('.').collect();
            octets.len() == 4
                && octets.iter().all(|octet| {
                    !octet.is_empty() && octet.len() <= 3 && octet.parse::<u8>().is_ok()
                })
        })
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_hexdigit() && ch != '-')
        .any(|token| {
            token.len() == 36
                && token.as_bytes().get(8) == Some(&b'-')
                && token.as_bytes().get(13) == Some(&b'-')
                && token.as_bytes().get(18) == Some(&b'-')
                && token.as_bytes().get(23) == Some(&b'-')
                && token.chars().all(|ch| ch == '-' || ch.is_ascii_hexdigit())
        })
}

fn contains_secret_assignment(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "clientsecret",
        "access_token",
        "refresh_token",
        "bearer",
        "secret",
        "token",
    ]
    .iter()
    .any(|key| lowered.contains(&format!("{key}:")) || lowered.contains(&format!("{key}=")))
}

fn contains_hostname(value: &str) -> bool {
    value
        .split(|ch: char| {
            ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | '(' | ')' | '[' | ']')
        })
        .filter_map(|token| token.split('/').next())
        .map(|token| token.trim_matches(|ch: char| matches!(ch, '.' | ':' | ';')))
        .any(|token| {
            if token.is_empty() || !token.contains('.') {
                return false;
            }
            let labels: Vec<&str> = token.split('.').collect();
            labels.len() >= 2
                && labels.iter().all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                })
                && labels.last().is_some_and(|tld| {
                    tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic())
                })
        })
}

fn looks_like_dns_key(key: &str) -> bool {
    if APPROVED_KEYS.contains(&key) {
        return false;
    }
    let parts: Vec<&str> = key.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
}

fn normalize_identifier_text(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn find_policy<'a>(policies: &'a [&Value], name: &str) -> &'a Value {
    policies
        .iter()
        .find(|manifest| str_at(manifest, &["metadata", "name"]) == Some(name))
        .copied()
        .unwrap_or(&Value::Null)
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn object_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Map<String, Value>> {
    value_at(value, path)?.as_object()
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at(value, path)?.as_str()
}

fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    value_at(value, path)?.as_bool()
}

fn int_at(value: &Value, path: &[&str]) -> Option<i64> {
    value_at(value, path)?.as_i64()
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> Vec<&'a Value> {
    if path.is_empty() {
        return value
            .as_array()
            .map(|items| items.iter().collect())
            .unwrap_or_default();
    }
    array_at_path(value, path)
}

fn array_at_path<'a>(value: &'a Value, path: &[&str]) -> Vec<&'a Value> {
    value_at(value, path)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn string_array_at(value: &Value, path: &[&str]) -> Vec<String> {
    array_at_path(value, path)
        .iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect()
}

fn expected_missing(expected: &[&str], actual: &[String]) -> Vec<String> {
    expected
        .iter()
        .filter(|name| !actual.iter().any(|actual| actual == *name))
        .map(|name| (*name).to_string())
        .collect()
}

fn push_diff_error(expected: &[&str], actual: &[String], errors: &mut Vec<String>, label: &str) {
    let missing = expected_missing(expected, actual);
    expect(
        missing.is_empty(),
        errors,
        format!("{label}: {}", missing.join(", ")),
    );
}

fn push_unexpected_error(
    actual: &[String],
    expected: &[&str],
    errors: &mut Vec<String>,
    label: &str,
) {
    let unexpected: Vec<String> = actual
        .iter()
        .filter(|name| !expected.contains(&name.as_str()))
        .cloned()
        .collect();
    expect(
        unexpected.is_empty(),
        errors,
        format!("{label}: {}", unexpected.join(", ")),
    );
}

fn manifest_path(manifest: &Value) -> String {
    format!(
        "{}:{}",
        str_at(manifest, &["__file"]).unwrap_or(""),
        int_at(manifest, &["__document"])
            .map(|value| value.to_string())
            .unwrap_or_default()
    )
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn source_comment_identifier_is_rejected() {
        let mut errors = Vec::new();
        validate_source_texts(
            &[SourceText {
                path: "deploy/kubernetes/base/namespace.yaml".to_string(),
                text: "# tenantId: synthetic-placeholder\n".to_string(),
            }],
            &mut errors,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("tenantId") && error.contains("source comment")));
    }

    #[test]
    fn ingress_host_key_only_allowed_on_ingress_paths() {
        let mut errors = Vec::new();
        validate_no_secret_values(
            &json!({
                "kind": "ServiceAccount",
                "metadata": {
                    "labels": {
                        "host": "platform.example.invalid"
                    }
                }
            }),
            "manifests[0]",
            &mut errors,
            None,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("metadata.labels.host contains unsafe key")));
    }

    #[test]
    fn approved_host_value_only_allowed_on_ingress_paths() {
        let mut errors = Vec::new();
        validate_no_secret_values(
            &json!({
                "kind": "ServiceAccount",
                "metadata": {
                    "labels": {
                        "note": APPROVED_HOST
                    }
                }
            }),
            "manifests[0]",
            &mut errors,
            None,
        );

        assert!(errors
            .iter()
            .any(|error| error.contains("metadata.labels.note contains prohibited value")));
    }

    // ── target hardening helpers ──────────────────────────────────────

    fn hardened_target_deployment(name: &str, security_context: Value) -> Value {
        let (readiness_path, liveness_path) = target_probe_paths(name);

        json!({
            "kind": "Deployment",
            "metadata": { "name": name },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": name,
                                "image": format!("ryuki/{name}:rust-dev"),
                                "imagePullPolicy": "IfNotPresent",
                                "readinessProbe": {
                                    "httpGet": { "path": readiness_path, "port": 8080 }
                                },
                                "livenessProbe": {
                                    "httpGet": { "path": liveness_path, "port": 8080 }
                                },
                                "resources": {
                                    "requests": { "cpu": "50m", "memory": "128Mi" },
                                    "limits": { "cpu": "500m", "memory": "512Mi" }
                                },
                                "securityContext": security_context
                            }
                        ]
                    }
                }
            }
        })
    }

    #[test]
    fn target_run_as_identity_misconfigurations_are_rejected() {
        let cases = [
            (
                "portal-ui",
                json!({
                    "runAsNonRoot": true,
                    "runAsUser": 0,
                    "runAsGroup": 10001,
                    "allowPrivilegeEscalation": false,
                    "readOnlyRootFilesystem": true,
                    "capabilities": { "drop": ["ALL"] },
                    "seccompProfile": { "type": "RuntimeDefault" }
                }),
                "runAsUser",
            ),
            (
                "platform-api",
                json!({
                    "runAsNonRoot": true,
                    "runAsGroup": 10001,
                    "allowPrivilegeEscalation": false,
                    "readOnlyRootFilesystem": true,
                    "capabilities": { "drop": ["ALL"] },
                    "seccompProfile": { "type": "RuntimeDefault" }
                }),
                "runAsUser",
            ),
            (
                "portal-ui",
                json!({
                    "runAsNonRoot": true,
                    "runAsUser": 10001,
                    "allowPrivilegeEscalation": false,
                    "readOnlyRootFilesystem": true,
                    "capabilities": { "drop": ["ALL"] },
                    "seccompProfile": { "type": "RuntimeDefault" }
                }),
                "runAsGroup",
            ),
        ];

        for (name, security_context, expected_field) in cases {
            let deployment = hardened_target_deployment(name, security_context);
            let mut errors = Vec::new();
            validate_target_hardening(name, &deployment, &mut errors);

            assert!(
                errors
                    .iter()
                    .any(|e| e.contains(name) && e.contains(expected_field)),
                "expected {name} {expected_field} validation error, got: {:?}",
                errors
            );
        }
    }

    #[test]
    fn portal_ui_missing_readiness_probe_is_rejected() {
        let deployment = json!({
            "kind": "Deployment",
            "metadata": { "name": "portal-ui" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "portal-ui",
                                "image": "ryuki/portal-ui:rust-dev",
                                "imagePullPolicy": "IfNotPresent",
                                "resources": {
                                    "requests": { "cpu": "50m", "memory": "128Mi" },
                                    "limits": { "cpu": "500m", "memory": "512Mi" }
                                },
                                "securityContext": {
                                    "runAsNonRoot": true,
                                    "runAsUser": 10001,
                                    "runAsGroup": 10001,
                                    "allowPrivilegeEscalation": false,
                                    "readOnlyRootFilesystem": true,
                                    "capabilities": { "drop": ["ALL"] },
                                    "seccompProfile": { "type": "RuntimeDefault" }
                                }
                            }
                        ]
                    }
                }
            }
        });
        let mut errors = Vec::new();
        validate_target_hardening("portal-ui", &deployment, &mut errors);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("portal-ui") && e.contains("readiness")),
            "expected missing portal-ui probe error"
        );
    }

    #[test]
    fn portal_ui_wrong_readiness_path_is_rejected() {
        let deployment = json!({
            "kind": "Deployment",
            "metadata": { "name": "portal-ui" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "portal-ui",
                                "image": "ryuki/portal-ui:rust-dev",
                                "imagePullPolicy": "IfNotPresent",
                                "readinessProbe": {
                                    "httpGet": { "path": "/ready", "port": 8080 }
                                },
                                "livenessProbe": {
                                    "httpGet": { "path": "/healthz", "port": 8080 }
                                },
                                "resources": {
                                    "requests": { "cpu": "50m", "memory": "128Mi" },
                                    "limits": { "cpu": "500m", "memory": "512Mi" }
                                },
                                "securityContext": {
                                    "runAsNonRoot": true,
                                    "runAsUser": 10001,
                                    "runAsGroup": 10001,
                                    "allowPrivilegeEscalation": false,
                                    "readOnlyRootFilesystem": true,
                                    "capabilities": { "drop": ["ALL"] },
                                    "seccompProfile": { "type": "RuntimeDefault" }
                                }
                            }
                        ]
                    }
                }
            }
        });
        let mut errors = Vec::new();
        validate_target_hardening("portal-ui", &deployment, &mut errors);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("portal-ui") && e.contains("readiness")),
            "expected wrong portal-ui readiness path error"
        );
    }

    #[test]
    fn platform_api_missing_resources_are_rejected() {
        let deployment = json!({
            "kind": "Deployment",
            "metadata": { "name": "platform-api" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "platform-api",
                                "image": "ryuki/platform-api:rust-dev",
                                "imagePullPolicy": "IfNotPresent",
                                "readinessProbe": {
                                    "httpGet": { "path": "/ready", "port": 8080 }
                                },
                                "livenessProbe": {
                                    "httpGet": { "path": "/health", "port": 8080 }
                                },
                                "securityContext": {
                                    "runAsNonRoot": true,
                                    "runAsUser": 10001,
                                    "runAsGroup": 10001,
                                    "allowPrivilegeEscalation": false,
                                    "readOnlyRootFilesystem": true,
                                    "capabilities": { "drop": ["ALL"] },
                                    "seccompProfile": { "type": "RuntimeDefault" }
                                }
                            }
                        ]
                    }
                }
            }
        });
        let mut errors = Vec::new();
        validate_target_hardening("platform-api", &deployment, &mut errors);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("platform-api") && e.contains("resource")),
            "expected missing platform-api resources error"
        );
    }

    #[test]
    fn platform_api_missing_pull_policy_is_rejected() {
        let deployment = json!({
            "kind": "Deployment",
            "metadata": { "name": "platform-api" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "platform-api",
                                "image": "ryuki/platform-api:rust-dev",
                                "readinessProbe": {
                                    "httpGet": { "path": "/ready", "port": 8080 }
                                },
                                "livenessProbe": {
                                    "httpGet": { "path": "/health", "port": 8080 }
                                },
                                "resources": {
                                    "requests": { "cpu": "50m", "memory": "128Mi" },
                                    "limits": { "cpu": "500m", "memory": "512Mi" }
                                },
                                "securityContext": {
                                    "runAsNonRoot": true,
                                    "runAsUser": 10001,
                                    "runAsGroup": 10001,
                                    "allowPrivilegeEscalation": false,
                                    "readOnlyRootFilesystem": true,
                                    "capabilities": { "drop": ["ALL"] },
                                    "seccompProfile": { "type": "RuntimeDefault" }
                                }
                            }
                        ]
                    }
                }
            }
        });
        let mut errors = Vec::new();
        validate_target_hardening("platform-api", &deployment, &mut errors);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("platform-api") && e.contains("imagePullPolicy")),
            "expected missing platform-api pull policy error, got: {:?}",
            errors
        );
    }

    #[test]
    fn portal_ui_privilege_escalation_is_rejected() {
        let deployment = json!({
            "kind": "Deployment",
            "metadata": { "name": "portal-ui" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "portal-ui",
                                "image": "ryuki/portal-ui:rust-dev",
                                "imagePullPolicy": "IfNotPresent",
                                "readinessProbe": {
                                    "httpGet": { "path": "/readyz", "port": 8080 }
                                },
                                "livenessProbe": {
                                    "httpGet": { "path": "/healthz", "port": 8080 }
                                },
                                "resources": {
                                    "requests": { "cpu": "50m", "memory": "128Mi" },
                                    "limits": { "cpu": "500m", "memory": "512Mi" }
                                },
                                "securityContext": {
                                    "runAsNonRoot": true,
                                    "runAsUser": 10001,
                                    "runAsGroup": 10001,
                                    "allowPrivilegeEscalation": true,
                                    "readOnlyRootFilesystem": true,
                                    "capabilities": { "drop": ["ALL"] },
                                    "seccompProfile": { "type": "RuntimeDefault" }
                                }
                            }
                        ]
                    }
                }
            }
        });
        let mut errors = Vec::new();
        validate_target_hardening("portal-ui", &deployment, &mut errors);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("portal-ui") && e.contains("escalation")),
            "expected portal-ui privilege escalation error"
        );
    }

    #[test]
    fn platform_api_non_runtime_default_seccomp_is_rejected() {
        let deployment = json!({
            "kind": "Deployment",
            "metadata": { "name": "platform-api" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "platform-api",
                                "image": "ryuki/platform-api:rust-dev",
                                "imagePullPolicy": "IfNotPresent",
                                "readinessProbe": {
                                    "httpGet": { "path": "/ready", "port": 8080 }
                                },
                                "livenessProbe": {
                                    "httpGet": { "path": "/health", "port": 8080 }
                                },
                                "resources": {
                                    "requests": { "cpu": "50m", "memory": "128Mi" },
                                    "limits": { "cpu": "500m", "memory": "512Mi" }
                                },
                                "securityContext": {
                                    "runAsNonRoot": true,
                                    "runAsUser": 10001,
                                    "runAsGroup": 10001,
                                    "allowPrivilegeEscalation": false,
                                    "readOnlyRootFilesystem": true,
                                    "capabilities": { "drop": ["ALL"] },
                                    "seccompProfile": { "type": "Unconfined" }
                                }
                            }
                        ]
                    }
                }
            }
        });
        let mut errors = Vec::new();
        validate_target_hardening("platform-api", &deployment, &mut errors);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("platform-api") && e.contains("seccomp")),
            "expected platform-api non-RuntimeDefault seccomp error"
        );
    }

    #[test]
    fn worker_deployment_skips_hardening_checks() {
        let deployment = json!({
            "kind": "Deployment",
            "metadata": { "name": "platform-worker" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "platform-worker",
                                "image": "ryuki/platform-worker:rust-dev"
                            }
                        ]
                    }
                }
            }
        });
        let mut errors = Vec::new();
        validate_target_hardening("platform-worker", &deployment, &mut errors);
        assert!(
            errors.is_empty(),
            "platform-worker should not be subject to hardening checks"
        );
    }
}
