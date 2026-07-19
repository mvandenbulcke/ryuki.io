use crate::yaml_utils::validate_yaml_duplicate_keys_text;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const NAMESPACE: &str = "ryuki-platform";
const VAULT_NAMESPACE: &str = "vault";
const PART_OF: &str = "ryuki-infrastructure-platform";
const APPROVED_HOST: &str = "platform.example.invalid";
const TLS_SECRET_PLACEHOLDER: &str = "platform-tls-placeholder";
const DEDICATED_INGRESS_CLASS: &str = "ryuki-platform";
const DEDICATED_INGRESS_INSTANCE: &str = "ryuki-platform";
const EXPECTED_COMPONENTS: &[&str] = &["portal-ui", "platform-api"];
const MIGRATION_JOB: &str = "platform-api-migrations";
const MIGRATION_JOB_TEMPLATE_PATH: &str = "deploy/kubernetes/operations/migration-job.yaml";
const MIGRATION_CUTOVER_CONTRACT_PATH: &str =
    "deploy/kubernetes/operations/migration-cutover-contract.yaml";
const MIGRATION_CREDENTIAL_TEMPLATE_PATH: &str =
    "deploy/kubernetes/operations/migration-vault-dynamic-secret.yaml";
const MIGRATION_SERVICE_ACCOUNT: &str = "platform-api-migrator";
const CNPG_CA_SECRET_NAME: &str = "ryuki-platform-db-ca";
const CNPG_CA_VOLUME_NAME: &str = "cnpg-ca";
const CNPG_CA_SECRET_KEY: &str = "ca.crt";
const CNPG_CA_MOUNT_PATH: &str = "/var/run/secrets/ryuki/cnpg";
const VAULT_WORKLOAD_AUTH_MANIFEST_PATH: &str = "deploy/kubernetes/vault/workload-auth.yaml";
const VAULT_KUBERNETES_AUTH_CONFIG_PATH: &str =
    "deploy/kubernetes/vault/kubernetes-auth-config.json";
const VAULT_PLATFORM_API_ROLE_PATH: &str =
    "deploy/kubernetes/vault/platform-api-kubernetes-role.json";
const VAULT_PLATFORM_API_POLICY_PATH: &str = "deploy/kubernetes/vault/platform-api-policy.hcl";
const VAULT_PLATFORM_API_POLICY_NAME: &str = "ryuki-platform-api-runtime";
const VAULT_WORKLOAD_TOKEN_VOLUME_NAME: &str = "vault-workload-token";
const VAULT_WORKLOAD_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/ryuki/vault-auth";
const VAULT_WORKLOAD_TOKEN_FILE_PATH: &str = "/var/run/secrets/ryuki/vault-auth/token";
const VAULT_CLIENT_CA_VOLUME_NAME: &str = "vault-client-ca";
const VAULT_CLIENT_CA_SECRET_NAME: &str = "ryuki-vault-client-ca";
const VAULT_CLIENT_CA_MOUNT_PATH: &str = "/var/run/secrets/ryuki/vault-tls";
const VAULT_CLIENT_CA_FILE_PATH: &str = "/var/run/secrets/ryuki/vault-tls/ca.crt";
const SECRET_REFERENCE_FINGERPRINT_KEYRING_VOLUME_NAME: &str =
    "secret-reference-fingerprint-keyring";
const SECRET_REFERENCE_FINGERPRINT_KEYRING_SECRET_NAME: &str =
    "ryuki-secret-reference-fingerprint-keyring";
const SECRET_REFERENCE_FINGERPRINT_KEYRING_KEY: &str = "keyring";
const SECRET_REFERENCE_FINGERPRINT_KEYRING_MOUNT_PATH: &str =
    "/var/run/secrets/ryuki/secret-reference-fingerprint";
const SECRET_REFERENCE_FINGERPRINT_KEYRING_FILE_PATH: &str =
    "/var/run/secrets/ryuki/secret-reference-fingerprint/keyring";
const VAULT_API_EGRESS_POLICY: &str = "allow-platform-api-egress-to-vault";
const VAULT_API_INGRESS_POLICY: &str = "allow-ingress-to-vault-from-platform-api";
const VAULT_TOKEN_REVIEW_BINDING: &str = "vault-tokenreview-auth-delegator";
const EXPECTED_CUTOVER_WORKLOAD_KINDS: &[&str] =
    &["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"];
const EXPECTED_BASE_WRITER_SELECTORS: &[&str] = &[
    "app.kubernetes.io/part-of=ryuki-infrastructure-platform,app.kubernetes.io/name=platform-api",
];
const EXPECTED_DATABASE_SESSION_FIELDS: &[&str] = &[
    "pid",
    "usename",
    "application_name",
    "backend_start",
    "xact_start",
    "state",
];
const EXPECTED_CONFIG_MAPS: &[&str] = &[
    "platform-api-config",
    "platform-api-migration-config",
    "portal-ui-config",
];
const PLATFORM_API_CONFIG_KEYS: &[&str] = &[
    "RYUKI_SERVER__BIND_ADDRESS",
    "RYUKI_PLATFORM_URL",
    "RYUKI_DATABASE__REQUIRED",
    "RYUKI_MIGRATION_MODE",
    "RYUKI_DATABASE_EXPECTED_ROLE",
    "RYUKI_DATABASE_FORBIDDEN_ROLE",
    "RYUKI_RETENTION__DAILY_BACKUPS",
    "RYUKI_RETENTION__WEEKLY_BACKUPS",
    "RYUKI_RETENTION__MONTHLY_BACKUPS",
    "RYUKI_RETENTION__YEARLY_BACKUPS",
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
];
const VAULT_RUNTIME_CONFIG_VALUES: &[(&str, &str)] = &[
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__PROVIDER_ID",
        "provider:hashicorp-vault-primary",
    ),
    ("RYUKI_SECRET_PROVIDER_RUNTIME__CONFIGURATION_VERSION", "1"),
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__API_FLAVOR",
        "hashicorp-vault-v1",
    ),
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__ENDPOINT",
        "https://vault.vault.svc:8200",
    ),
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__CA_BUNDLE_PATH",
        VAULT_CLIENT_CA_FILE_PATH,
    ),
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_AUTH_MOUNT",
        "kubernetes",
    ),
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_ROLE",
        "ryuki-platform-api",
    ),
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_AUDIENCE",
        "vault",
    ),
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__PROJECTED_TOKEN_PATH",
        VAULT_WORKLOAD_TOKEN_FILE_PATH,
    ),
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_SERVICE_ACCOUNT_NAMESPACE",
        NAMESPACE,
    ),
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_SERVICE_ACCOUNT_NAME",
        "platform-api",
    ),
    (
        "RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_TOKEN_POLICY",
        VAULT_PLATFORM_API_POLICY_NAME,
    ),
];
const PLATFORM_API_MIGRATION_CONFIG_KEYS: &[&str] = &[
    "RYUKI_MIGRATION_MODE",
    "RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS",
    "RYUKI_MIGRATION_LOCK_TIMEOUT_SECS",
    "RYUKI_MIGRATION_EXPECTED_ROLE",
    "RYUKI_APPLICATION_DATABASE_ROLE",
];
const PORTAL_UI_CONFIG_KEYS: &[&str] = &[
    "RYUKI_API_URL",
    "RYUKI_PORTAL_PUBLIC_ORIGIN",
    "RYUKI_PORTAL_EXECUTION_MODE",
    "RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK",
];
const SECURITY_ADMISSION_CONFIG_MAP: &str = "platform-security-admission-config";
const SECURITY_ADMISSION_KEYS: &[&str] = &[
    "RYUKI_SECURITY_CONTRACT_ROOT",
    "RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH",
    "RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST",
    "RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH",
    "RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST",
    "RYUKI_EXPECTED_DEPLOYMENT_ID",
    "RYUKI_SECURITY_PROFILE",
];
const EXPECTED_SERVICE_ACCOUNTS: &[&str] = &[
    "portal-ui",
    "platform-api",
    "platform-api-migrator",
    "vault-db-owner",
    "vault-db-backup",
    "vault-api-db",
    "vault-api-db-migrator",
];
const EXPOSED_SERVICES: &[&str] = &["portal-ui", "platform-api"];
const WORKER_COMPONENTS: &[&str] = &[];
const INTERNAL_HTTP_SERVICES: &[&str] = &[];
const HARDENING_TARGETS: &[&str] = &["portal-ui", "platform-api"];
const ALLOWED_KINDS: &[&str] = &[
    "Namespace",
    "ServiceAccount",
    "Deployment",
    "Job",
    "Service",
    "Ingress",
    "NetworkPolicy",
    "ConfigMap",
    "ClusterRoleBinding",
];
// The default-deny pair plus the app-tier allow rules, extended with the
// database-tier policies for the API, one-shot migrator, and CloudNativePG
// (deploy/kubernetes/base/networkpolicies.yaml). These DB policies keep the
// default-deny posture intact while scoping Postgres traffic to the platform
// API, one-shot migrator, and CNPG operator, so they belong in the validated
// skeleton.
const EXPECTED_NETWORK_POLICIES: &[&str] = &[
    "default-deny-ingress",
    "default-deny-egress",
    "allow-ingress-to-portal-ui",
    "allow-ingress-to-platform-api",
    "allow-portal-ui-egress-to-dedicated-ingress-https",
    "allow-egress-to-kube-dns",
    "allow-platform-api-egress-to-db",
    VAULT_API_EGRESS_POLICY,
    "allow-ingress-to-db-from-platform-api",
    "allow-platform-api-migrations-egress-to-db",
    "allow-ingress-to-db-from-platform-api-migrations",
    "allow-db-intra-cluster",
    "allow-ingress-to-db-from-cnpg-operator",
    // Observability scrape access: lets a `monitoring` namespace reach the
    // metrics port under default-deny (deploy/kubernetes/monitoring wiring).
    "allow-monitoring-ingress",
    VAULT_API_INGRESS_POLICY,
];
const APPROVED_KEYS: &[&str] = &[
    "apiVersion",
    "kind",
    "metadata",
    "name",
    "generateName",
    "namespace",
    "labels",
    "annotations",
    "app.kubernetes.io/part-of",
    "app.kubernetes.io/name",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/component",
    "component",
    "ryuki.io/secret-family",
    "ryuki.io/cutover-contract",
    "ryuki.io/release-image",
    "ryuki.io/release-digest-prefix",
    "spec",
    "replicas",
    "selector",
    "matchLabels",
    "template",
    "serviceAccountName",
    "containers",
    "volumes",
    "volumeMounts",
    "mountPath",
    "readOnly",
    "secret",
    "secretName",
    "items",
    "envFrom",
    "configMapRef",
    "configMapKeyRef",
    "secretRef",
    "env",
    "valueFrom",
    "secretKeyRef",
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
    "projected",
    "defaultMode",
    "sources",
    "serviceAccountToken",
    "audience",
    "expirationSeconds",
    "fsGroup",
    "fsGroupChangePolicy",
    "apiGroup",
    "roleRef",
    "subjects",
    "data",
    "__file",
    "__document",
];
const APPROVED_SCHEMA_VALUES: &[&str] = &[
    "networking.k8s.io/v1",
    "rbac.authorization.k8s.io/v1",
    "rbac.authorization.k8s.io",
    "app.kubernetes.io/name",
    "kubernetes.io/metadata.name",
    "IfNotPresent",
    "RuntimeDefault",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationIdentity {
    digest_prefix: String,
    job_generate_name: String,
    secret_name: String,
    vault_auth_role: String,
    vault_database_role: String,
}

impl MigrationIdentity {
    fn from_image(image: &str) -> Option<Self> {
        let digest = immutable_image_digest(image)?;
        let digest_prefix = digest.get(..12)?.to_string();
        Some(Self {
            job_generate_name: format!("platform-api-migrations-{digest_prefix}-"),
            secret_name: format!("ryuki-platform-api-migrator-db-{digest_prefix}"),
            vault_auth_role: format!("ryuki-api-db-migrator-{digest_prefix}"),
            vault_database_role: format!("ryuki-schema-migrator-{digest_prefix}"),
            digest_prefix,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SourceText {
    path: String,
    text: String,
}

#[derive(Debug, Deserialize)]
struct Context {
    manifests: Vec<Value>,
    #[serde(default, rename = "sourceTexts")]
    source_texts: Vec<SourceText>,
    #[serde(default, rename = "cutoverContract")]
    cutover_contract: Value,
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
    validate_cutover_contract(&context.cutover_contract, &context.manifests, &mut errors);
    validate_vault_external_auth_files(&context.source_texts, &mut errors);
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
    validate_config_maps(manifests, &mut errors);
    validate_components(manifests, &mut errors);
    validate_secret_reference_fingerprint_keyring_exposure(manifests, &mut errors);
    validate_migration_job(manifests, &mut errors);
    validate_services(manifests, &mut errors);
    validate_ingress(manifests, &mut errors);
    validate_network_policies(manifests, &mut errors);
    validate_vault_token_review_binding(manifests, &mut errors);
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
        let Some(name) = str_at(manifest, &["metadata", "name"])
            .or_else(|| str_at(manifest, &["metadata", "generateName"]))
        else {
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
        let generated_job = str_at(manifest, &["kind"]) == Some("Job")
            && name.is_none()
            && str_at(manifest, &["metadata", "generateName"])
                .is_some_and(|value| !value.trim().is_empty());
        expect(
            name.is_some_and(|name| !name.trim().is_empty()) || generated_job,
            errors,
            format!(
                "{} metadata.name is required except for the operations-only generated Job",
                manifest_path(manifest)
            ),
        );
        expect(
            str_at(
                manifest,
                &["metadata", "labels", "app.kubernetes.io/part-of"],
            ) == Some(PART_OF),
            errors,
            format!("{} missing part-of label", manifest_path(manifest)),
        );
        match (str_at(manifest, &["kind"]), name) {
            (Some("Namespace" | "ClusterRoleBinding"), _) => expect(
                value_at(manifest, &["metadata", "namespace"]).is_none(),
                errors,
                format!(
                    "{} cluster-scoped resource must not set metadata.namespace",
                    manifest_path(manifest)
                ),
            ),
            (Some("NetworkPolicy"), Some(VAULT_API_INGRESS_POLICY)) => expect(
                str_at(manifest, &["metadata", "namespace"]) == Some(VAULT_NAMESPACE),
                errors,
                format!(
                    "{} namespace must be {VAULT_NAMESPACE}",
                    manifest_path(manifest)
                ),
            ),
            _ => expect(
                str_at(manifest, &["metadata", "namespace"]) == Some(NAMESPACE),
                errors,
                format!("{} namespace must be {NAMESPACE}", manifest_path(manifest)),
            ),
        }
    }
}

fn validate_config_maps(manifests: &[Value], errors: &mut Vec<String>) {
    let names = names_for(manifests, "ConfigMap");
    push_diff_error(EXPECTED_CONFIG_MAPS, &names, errors, "missing ConfigMaps");
    push_unexpected_error(
        &names,
        EXPECTED_CONFIG_MAPS,
        errors,
        "unexpected ConfigMaps",
    );

    let find = |name: &str| {
        manifests
            .iter()
            .find(|manifest| {
                str_at(manifest, &["kind"]) == Some("ConfigMap")
                    && str_at(manifest, &["metadata", "name"]) == Some(name)
            })
            .unwrap_or(&Value::Null)
    };
    let api = find("platform-api-config");
    expect(
        object_at(api, &["data"])
            .is_some_and(|data| object_has_exact_keys(data, PLATFORM_API_CONFIG_KEYS))
            && str_at(api, &["data", "RYUKI_DATABASE__REQUIRED"]) == Some("true")
            && str_at(api, &["data", "RYUKI_MIGRATION_MODE"]) == Some("verify-only")
            && str_at(api, &["data", "RYUKI_DATABASE_EXPECTED_ROLE"]) == Some("ryuki_app_runtime")
            && str_at(api, &["data", "RYUKI_DATABASE_FORBIDDEN_ROLE"])
                == Some("ryuki_schema_migrator")
            && str_at(
                api,
                &["data", "RYUKI_SECRET_REFERENCE_FINGERPRINT_KEYRING_PATH"],
            ) == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_FILE_PATH)
            && VAULT_RUNTIME_CONFIG_VALUES
                .iter()
                .all(|(key, expected)| str_at(api, &["data", *key]) == Some(*expected)),
        errors,
        "platform-api-config must contain only the exact reviewed keys, require the database, use verify-only ryuki_app_runtime, forbid migrator membership, bind the exact value-free Vault workload-auth settings, and point to the exact projected SecretRef fingerprint keyring",
    );

    let migration = find("platform-api-migration-config");
    let migration_data = object_at(migration, &["data"]);
    expect(
        migration_data
            .is_some_and(|data| object_has_exact_keys(data, PLATFORM_API_MIGRATION_CONFIG_KEYS))
            && str_at(migration, &["data", "RYUKI_MIGRATION_MODE"]) == Some("apply-only")
            && str_at(
                migration,
                &["data", "RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS"],
            ) == Some("1800")
            && str_at(migration, &["data", "RYUKI_MIGRATION_LOCK_TIMEOUT_SECS"]) == Some("60")
            && str_at(migration, &["data", "RYUKI_MIGRATION_EXPECTED_ROLE"])
                == Some("ryuki_schema_migrator")
            && str_at(migration, &["data", "RYUKI_APPLICATION_DATABASE_ROLE"])
                == Some("ryuki_app_runtime"),
        errors,
        "platform-api-migration-config must contain only the exact reviewed keys with apply-only mode, 1800/60 timeouts, and exact migrator/application roles",
    );

    let portal = find("portal-ui-config");
    let expected_origin = format!("https://{APPROVED_HOST}");
    expect(
        object_at(portal, &["data"])
            .is_some_and(|data| object_has_exact_keys(data, PORTAL_UI_CONFIG_KEYS))
            && str_at(portal, &["data", "RYUKI_API_URL"]) == Some(expected_origin.as_str())
            && str_at(portal, &["data", "RYUKI_PORTAL_PUBLIC_ORIGIN"])
                == Some(expected_origin.as_str())
            && str_at(portal, &["data", "RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK"]) == Some("false"),
        errors,
        "portal-ui-config must contain only the exact reviewed keys and use the exact HTTPS ingress origin with insecure-loopback disabled",
    );

    for config_map in manifests
        .iter()
        .filter(|manifest| str_at(manifest, &["kind"]) == Some("ConfigMap"))
    {
        let data = object_at(config_map, &["data"]);
        expect(
            data.is_some_and(|entries| {
                !entries.contains_key("RYUKI_DATABASE_URL")
                    && !entries.contains_key("RYUKI_MIGRATION_DATABASE_URL")
            }),
            errors,
            format!(
                "ConfigMap {} must not carry a database connection URL",
                str_at(config_map, &["metadata", "name"]).unwrap_or("")
            ),
        );
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
        EXPECTED_SERVICE_ACCOUNTS,
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
        EXPECTED_SERVICE_ACCOUNTS,
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
        validate_container_image(name, container, errors);
        // Non-secret configuration is imported from one exact, key-allowlisted
        // ConfigMap. The API adds one reviewed Secret key and seven individually
        // pinned admission ConfigMap keys; whole-Secret envFrom imports are
        // forbidden so new Secret fields can never override policy configuration.
        for (index, item) in containers.iter().enumerate() {
            validate_container_env(name, index, item, errors);
        }
        if name == "platform-api" {
            let pod_spec =
                value_at(deployment, &["spec", "template", "spec"]).unwrap_or(&Value::Null);
            validate_cnpg_ca_mount("Deployment platform-api", pod_spec, container, 4, errors);
            validate_platform_api_vault_workload_auth(
                manifests, deployment, pod_spec, container, errors,
            );
            validate_platform_api_secret_reference_fingerprint_keyring(pod_spec, container, errors);
        }
        validate_target_hardening(name, deployment, errors);
    }
}

fn validate_migration_job(manifests: &[Value], errors: &mut Vec<String>) {
    let jobs: Vec<&Value> = manifests
        .iter()
        .filter(|manifest| str_at(manifest, &["kind"]) == Some("Job"))
        .collect();
    expect(
        jobs.len() == 1,
        errors,
        "exactly one operations-only platform-api migration Job template is required",
    );
    let job = jobs.first().copied().unwrap_or(&Value::Null);
    let api_image = platform_api_image(manifests);
    let migration_identity = api_image.and_then(MigrationIdentity::from_image);

    expect(
        str_at(job, &["apiVersion"]) == Some("batch/v1")
            && value_at(job, &["metadata", "name"]).is_none()
            && migration_identity.as_ref().is_some_and(|identity| {
                str_at(job, &["metadata", "generateName"])
                    == Some(identity.job_generate_name.as_str())
            }),
        errors,
        "migration Job must be batch/v1 with a generateName derived from the admitted image digest and no fixed name",
    );
    expect(
        int_at(job, &["spec", "completions"]) == Some(1)
            && int_at(job, &["spec", "parallelism"]) == Some(1)
            && int_at(job, &["spec", "backoffLimit"]) == Some(0),
        errors,
        "migration Job must run exactly once with completions/parallelism 1 and backoffLimit 0",
    );
    expect(
        object_at(job, &["spec"]).is_some_and(|spec| {
            object_has_exact_keys(
                spec,
                &[
                    "completions",
                    "parallelism",
                    "backoffLimit",
                    "activeDeadlineSeconds",
                    "template",
                ],
            )
        }),
        errors,
        "migration Job spec must contain only the reviewed one-shot fields; podFailurePolicy and all retry/replacement policy extensions are forbidden",
    );
    expect(
        int_at(job, &["spec", "activeDeadlineSeconds"]) == Some(2400)
            && value_at(job, &["spec", "ttlSecondsAfterFinished"]).is_none(),
        errors,
        "migration Job must use the reviewed 2400-second deadline and forbid automatic TTL deletion/recreation",
    );

    let pod_template = value_at(job, &["spec", "template"]).unwrap_or(&Value::Null);
    expect(
        str_at(
            pod_template,
            &["metadata", "labels", "app.kubernetes.io/name"],
        ) == Some(MIGRATION_JOB)
            && str_at(
                pod_template,
                &["metadata", "labels", "app.kubernetes.io/component"],
            ) == Some("database-migration-runner"),
        errors,
        "migration Job pod labels must identify the database-migration-runner",
    );
    let pod_spec = value_at(pod_template, &["spec"]).unwrap_or(&Value::Null);
    expect(
        str_at(pod_spec, &["serviceAccountName"]) == Some(MIGRATION_SERVICE_ACCOUNT),
        errors,
        format!("migration Job must use ServiceAccount {MIGRATION_SERVICE_ACCOUNT}"),
    );
    expect(
        bool_at(pod_spec, &["automountServiceAccountToken"]) == Some(false),
        errors,
        "migration Job must disable ServiceAccount token automount on the pod",
    );
    expect(
        bool_at(pod_spec, &["enableServiceLinks"]) == Some(false),
        errors,
        "migration Job must disable injected Service environment variables",
    );
    expect(
        str_at(pod_spec, &["restartPolicy"]) == Some("Never")
            && int_at(pod_spec, &["terminationGracePeriodSeconds"]) == Some(30),
        errors,
        "migration Job must use restartPolicy Never and a 30-second termination grace period",
    );
    expect(
        bool_at(pod_spec, &["hostNetwork"]) != Some(true)
            && !contains_key(pod_spec, "hostPath")
            && object(pod_spec).is_none_or(|pod| {
                !pod.contains_key("initContainers") && !pod.contains_key("ephemeralContainers")
            }),
        errors,
        "migration Job must not use host networking, host paths, init containers, or ephemeral containers",
    );
    let pod_security = value_at(pod_spec, &["securityContext"]).unwrap_or(&Value::Null);
    expect(
        bool_at(pod_security, &["runAsNonRoot"]) == Some(true)
            && int_at(pod_security, &["runAsUser"]) == Some(10001)
            && int_at(pod_security, &["runAsGroup"]) == Some(10001)
            && str_at(pod_security, &["seccompProfile", "type"]) == Some("RuntimeDefault"),
        errors,
        "migration Job pod must use the reviewed non-root identity and RuntimeDefault seccomp",
    );

    let containers = array_at(pod_spec, &["containers"]);
    expect(
        containers.len() == 1,
        errors,
        "migration Job must have exactly one container",
    );
    let container = containers.first().copied().unwrap_or(&Value::Null);
    expect(
        str_at(container, &["name"]) == Some(MIGRATION_JOB),
        errors,
        format!("migration Job container must be named {MIGRATION_JOB}"),
    );

    let job_image = str_at(container, &["image"]);
    expect(
        job_image.is_some_and(is_qualified_immutable_image) && job_image == api_image,
        errors,
        "migration Job image must be the exact digest-only platform-api Deployment image",
    );
    expect(
        str_at(
            job,
            &["metadata", "annotations", "ryuki.io/cutover-contract"],
        ) == Some("migration-cutover-v1")
            && str_at(job, &["metadata", "annotations", "ryuki.io/release-image"]) == job_image
            && migration_identity.as_ref().is_some_and(|identity| {
                str_at(
                    job,
                    &["metadata", "labels", "ryuki.io/release-digest-prefix"],
                ) == Some(identity.digest_prefix.as_str())
                    && str_at(
                        pod_template,
                        &["metadata", "labels", "ryuki.io/release-digest-prefix"],
                    ) == Some(identity.digest_prefix.as_str())
            }),
        errors,
        "migration Job metadata, pod label, and image must bind the exact cutover contract and derived digest prefix",
    );
    expect(
        str_at(container, &["imagePullPolicy"]) == Some("IfNotPresent"),
        errors,
        "migration Job must set imagePullPolicy to IfNotPresent",
    );

    for prohibited in [
        "command",
        "args",
        "ports",
        "readinessProbe",
        "livenessProbe",
        "startupProbe",
        "lifecycle",
    ] {
        expect(
            value_at(container, &[prohibited]).is_none(),
            errors,
            format!("migration Job container must not define {prohibited}"),
        );
    }

    let env_from = array_at_path(container, &["envFrom"]);
    let exact_config_ref = env_from.iter().any(|entry| {
        object(entry).is_some_and(|map| map.len() == 1)
            && object_at(entry, &["configMapRef"]).is_some_and(|reference| {
                reference.len() == 1
                    && str_at(entry, &["configMapRef", "name"])
                        == Some("platform-api-migration-config")
            })
    });
    expect(
        env_from.len() == 1
            && exact_config_ref
            && env_from
                .iter()
                .all(|entry| value_at(entry, &["secretRef"]).is_none()),
        errors,
        "migration Job envFrom must contain only platform-api-migration-config and no whole-Secret import",
    );
    let env = array_at_path(container, &["env"]);
    let migration_url = env.first().copied().unwrap_or(&Value::Null);
    expect(
        env.len() == SECURITY_ADMISSION_KEYS.len() + 1
            && object(migration_url).is_some_and(|entry| entry.len() == 2)
            && str_at(migration_url, &["name"]) == Some("RYUKI_MIGRATION_DATABASE_URL")
            && object_at(migration_url, &["valueFrom"])
                .is_some_and(|value_from| value_from.len() == 1)
            && object_at(migration_url, &["valueFrom", "secretKeyRef"])
                .is_some_and(|reference| reference.len() == 2)
            && migration_identity.as_ref().is_some_and(|identity| {
                str_at(migration_url, &["valueFrom", "secretKeyRef", "name"])
                    == Some(identity.secret_name.as_str())
            })
            && str_at(migration_url, &["valueFrom", "secretKeyRef", "key"])
                == Some("RYUKI_MIGRATION_DATABASE_URL")
            && value_at(migration_url, &["value"]).is_none(),
        errors,
        "migration Job must import the digest-scoped migrator URL key plus seven security-admission keys",
    );
    expect(
        env.get(1..)
            .is_some_and(exact_security_admission_env_entries),
        errors,
        "migration Job must import the exact seven security-admission ConfigMap keys",
    );

    validate_cnpg_ca_mount("migration Job", pod_spec, container, 1, errors);
    validate_migration_job_resources(container, errors);
    validate_migration_job_security(container, errors);
}

fn validate_cutover_contract(contract: &Value, manifests: &[Value], errors: &mut Vec<String>) {
    let api_image = platform_api_image(manifests);
    let migration_identity = api_image.and_then(MigrationIdentity::from_image);
    expect(
        str_at(contract, &["contractVersion"]) == Some("migration-cutover-v1")
            && str_at(contract, &["release", "namespace"]) == Some(NAMESPACE)
            && str_at(contract, &["release", "apiDeployment"]) == Some("platform-api")
            && str_at(contract, &["release", "migrationJobTemplate"])
                == Some(MIGRATION_JOB_TEMPLATE_PATH)
            && str_at(contract, &["release", "migrationCredentialTemplate"])
                == Some(MIGRATION_CREDENTIAL_TEMPLATE_PATH)
            && migration_identity.as_ref().is_some_and(|identity| {
                str_at(contract, &["release", "digestPrefix"])
                    == Some(identity.digest_prefix.as_str())
            })
            && str_at(contract, &["release", "apiMigrationMode"]) == Some("verify-only")
            && str_at(contract, &["release", "jobMigrationMode"]) == Some("apply-only"),
        errors,
        format!(
            "{MIGRATION_CUTOVER_CONTRACT_PATH} must bind the exact namespace, operation template, digest, and startup modes"
        ),
    );

    let job = manifests
        .iter()
        .find(|manifest| str_at(manifest, &["kind"]) == Some("Job"))
        .unwrap_or(&Value::Null);
    let job_image = array_at_path(job, &["spec", "template", "spec", "containers"])
        .first()
        .copied()
        .and_then(|container| str_at(container, &["image"]));
    expect(
        str_at(contract, &["release", "image"]) == api_image
            && api_image == job_image
            && migration_identity.as_ref().is_some_and(|identity| {
                str_at(contract, &["execution", "generatedNamePrefix"])
                    == Some(identity.job_generate_name.as_str())
                    && str_at(job, &["metadata", "generateName"])
                        == Some(identity.job_generate_name.as_str())
            }),
        errors,
        "cutover contract, generated Job, and verify-only API must use one exact image and digest-scoped name",
    );

    expect(
        string_array_matches_exact(
            contract,
            &["drain", "requiredWorkloadKinds"],
            EXPECTED_CUTOVER_WORKLOAD_KINDS,
        ) && string_array_matches_exact(
            contract,
            &["drain", "requiredBaseWriterSelectors"],
            EXPECTED_BASE_WRITER_SELECTORS,
        ) && string_array_matches_exact(
            contract,
            &["drain", "databaseSessionReadback", "fields"],
            EXPECTED_DATABASE_SESSION_FIELDS,
        ),
        errors,
        "cutover contract must retain the exact nonempty writer-kind, base-writer-selector, and database-session evidence inventories",
    );

    expect(
        bool_at(contract, &["drain", "withdrawIngressTraffic"]) == Some(true)
            && bool_at(contract, &["drain", "externalWriterInventoryRequired"]) == Some(true)
            && bool_at(contract, &["drain", "requireZeroWriterPods"]) == Some(true)
            && bool_at(contract, &["drain", "requireZeroLeasedOrRunningJobs"]) == Some(true)
            && bool_at(
                contract,
                &[
                    "drain",
                    "databaseSessionReadback",
                    "independentOperatorIdentityRequired",
                ],
            ) == Some(true)
            && bool_at(
                contract,
                &[
                    "drain",
                    "databaseSessionReadback",
                    "requireZeroNonOperatorSessions",
                ],
            ) == Some(true),
        errors,
        "cutover contract must withdraw traffic and prove every writer, lease, job, and non-operator database session drained",
    );

    expect(
        str_at(contract, &["credentials", "api", "secretName"]) == Some("ryuki-platform-api-db")
            && str_at(contract, &["credentials", "api", "secretKey"]) == Some("RYUKI_DATABASE_URL")
            && str_at(contract, &["credentials", "api", "expectedRole"])
                == Some("ryuki_app_runtime")
            && str_at(contract, &["credentials", "api", "delivery"]) == Some("VaultDynamicSecret")
            && migration_identity.as_ref().is_some_and(|identity| {
                str_at(contract, &["credentials", "migration", "secretName"])
                    == Some(identity.secret_name.as_str())
                    && str_at(
                        contract,
                        &["credentials", "migration", "vaultDynamicSecretName"],
                    ) == Some(identity.secret_name.as_str())
                    && str_at(contract, &["credentials", "migration", "vaultAuthRole"])
                        == Some(identity.vault_auth_role.as_str())
                    && str_at(contract, &["credentials", "migration", "vaultDatabaseRole"])
                        == Some(identity.vault_database_role.as_str())
            })
            && str_at(contract, &["credentials", "migration", "secretKey"])
                == Some("RYUKI_MIGRATION_DATABASE_URL")
            && str_at(contract, &["credentials", "migration", "expectedRole"])
                == Some("ryuki_schema_migrator")
            && str_at(contract, &["credentials", "migration", "delivery"])
                == Some("VaultDynamicSecret")
            && bool_at(contract, &["credentials", "migration", "createAfterDrain"]) == Some(true)
            && bool_at(
                contract,
                &["credentials", "migration", "revokeAndDeleteAfterReadback"],
            ) == Some(true),
        errors,
        "cutover contract must use exact dynamic API/migrator Secret keys and revoke the digest-scoped migration lease after readback",
    );

    expect(
        int_at(contract, &["execution", "completions"]) == Some(1)
            && int_at(contract, &["execution", "parallelism"]) == Some(1)
            && int_at(contract, &["execution", "backoffLimit"]) == Some(0)
            && int_at(contract, &["execution", "activeDeadlineSeconds"]) == Some(2400)
            && str_at(contract, &["execution", "createSemantics"]) == Some("create-once")
            && bool_at(contract, &["execution", "automaticTtlForbidden"]) == Some(true),
        errors,
        "cutover contract must create one non-retrying, non-TTL Job with the reviewed deadline",
    );

    let expected_sequence: Vec<String> = [
        "freeze-render-and-digest",
        "withdraw-traffic",
        "stop-and-drain-all-writers",
        "readback-zero-database-sessions",
        "create-jit-migration-credential",
        "create-generated-job-once",
        "wait-for-single-completion",
        "readback-role-and-migration-ledger",
        "revoke-jit-migration-credential",
        "start-matching-verify-only-api",
        "require-readiness",
        "enable-matching-workers",
        "restore-traffic",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    expect(
        string_array_at(contract, &["sequence"]) == expected_sequence,
        errors,
        "cutover contract sequence must drain, run/read back once, revoke migration credentials, and only then start the matching verify-only API/workers",
    );

    expect(
        bool_at(contract, &["readback", "requireJobComplete"]) == Some(true)
            && bool_at(contract, &["readback", "requireSingleSuccessfulPod"]) == Some(true)
            && bool_at(contract, &["readback", "requireNoRetryPods"]) == Some(true)
            && bool_at(contract, &["readback", "requireEmbeddedInventoryMatch"]) == Some(true)
            && bool_at(contract, &["readback", "requireNoDirtyMigration"]) == Some(true)
            && bool_at(contract, &["readback", "requireDatabaseRoleEvidence"]) == Some(true)
            && bool_at(contract, &["restart", "requireMatchingApiImage"]) == Some(true)
            && bool_at(contract, &["restart", "requireVerifyOnlyStartup"]) == Some(true)
            && bool_at(contract, &["restart", "requireReadyBeforeTraffic"]) == Some(true)
            && bool_at(contract, &["failure", "keepTrafficAndWritersStopped"]) == Some(true)
            && bool_at(contract, &["failure", "automaticRetryForbidden"]) == Some(true)
            && bool_at(
                contract,
                &["failure", "olderBinaryAgainstNewSchemaForbidden"],
            ) == Some(true),
        errors,
        "cutover readback/restart/failure gates must fail closed before traffic returns",
    );
}

fn validate_migration_job_resources(container: &Value, errors: &mut Vec<String>) {
    for (class, resource) in [
        ("requests", "cpu"),
        ("requests", "memory"),
        ("limits", "cpu"),
        ("limits", "memory"),
    ] {
        expect(
            str_at(container, &["resources", class, resource]).is_some(),
            errors,
            format!("migration Job must declare resources.{class}.{resource}"),
        );
    }
}

fn validate_migration_job_security(container: &Value, errors: &mut Vec<String>) {
    let security = value_at(container, &["securityContext"]).unwrap_or(&Value::Null);
    expect(
        bool_at(security, &["runAsNonRoot"]) == Some(true)
            && int_at(security, &["runAsUser"]) == Some(10001)
            && int_at(security, &["runAsGroup"]) == Some(10001),
        errors,
        "migration Job must run as non-root user/group 10001",
    );
    expect(
        bool_at(security, &["allowPrivilegeEscalation"]) == Some(false)
            && bool_at(security, &["privileged"]) != Some(true)
            && bool_at(security, &["readOnlyRootFilesystem"]) == Some(true),
        errors,
        "migration Job must disable privilege escalation and use a read-only root filesystem",
    );
    let capabilities = value_at(security, &["capabilities"]);
    expect(
        capabilities.is_some_and(|value| {
            array_at_path(value, &["drop"])
                .iter()
                .any(|entry| entry.as_str() == Some("ALL"))
                && value_at(value, &["add"]).is_none()
        }),
        errors,
        "migration Job must drop ALL capabilities and add none",
    );
    expect(
        str_at(security, &["seccompProfile", "type"]) == Some("RuntimeDefault"),
        errors,
        "migration Job must use RuntimeDefault seccomp",
    );
}

fn platform_api_image(manifests: &[Value]) -> Option<&str> {
    manifests
        .iter()
        .find(|manifest| {
            str_at(manifest, &["kind"]) == Some("Deployment")
                && str_at(manifest, &["metadata", "name"]) == Some("platform-api")
        })
        .and_then(|deployment| {
            array_at_path(deployment, &["spec", "template", "spec", "containers"])
                .first()
                .copied()
                .and_then(|container| str_at(container, &["image"]))
        })
}

fn object_has_exact_keys(map: &Map<String, Value>, expected: &[&str]) -> bool {
    map.len() == expected.len() && expected.iter().all(|key| map.contains_key(*key))
}

fn string_array_matches_exact(value: &Value, path: &[&str], expected: &[&str]) -> bool {
    let actual = string_array_at(value, path);
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
}

/// Kubernetes and rendered-overlay images must be digest-only and name an
/// explicit registry. Local Compose development tags are intentionally a
/// separate surface and cannot satisfy this contract.
fn validate_container_image(name: &str, container: &Value, errors: &mut Vec<String>) {
    let image = str_at(container, &["image"]);
    expect(
        image.is_some_and(is_qualified_immutable_image),
        errors,
        format!(
            "Deployment {name} image must be a qualified registry/repository@sha256:<64 lowercase hex> reference"
        ),
    );
}

fn is_qualified_immutable_image(image: &str) -> bool {
    if image.is_empty() || image.trim() != image || image.contains("://") {
        return false;
    }

    let mut reference_parts = image.split('@');
    let Some(name) = reference_parts.next() else {
        return false;
    };
    let Some(digest) = reference_parts.next() else {
        return false;
    };
    if reference_parts.next().is_some() {
        return false;
    }

    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return false;
    }

    let Some((registry, repository)) = name.split_once('/') else {
        return false;
    };
    if repository.is_empty() || repository.contains(':') {
        // A tag is unnecessary beside a digest and makes overlay rewrites more
        // error-prone; the admitted form is deliberately digest-only.
        return false;
    }

    let host = if let Some((host, port)) = registry.rsplit_once(':') {
        if port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().ok().is_none_or(|port| port == 0)
        {
            return false;
        }
        host
    } else {
        registry
    };
    if host.len() > 253
        || !host.contains('.')
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return false;
    }

    repository.len() <= 255
        && repository.split('/').all(|segment| {
            !segment.is_empty()
                && !matches!(segment, "." | "..")
                && segment.len() <= 128
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
}

fn immutable_image_digest(image: &str) -> Option<&str> {
    if !is_qualified_immutable_image(image) {
        return None;
    }
    image.rsplit_once("@sha256:").map(|(_, digest)| digest)
}

/// Require one exact allowlisted ConfigMap import per deployment, plus one exact
/// database URL Secret key and seven admission ConfigMap keys for the API.
/// Literal values and whole-Secret imports are refused.
fn validate_container_env(name: &str, index: usize, container: &Value, errors: &mut Vec<String>) {
    let Some(item) = object(container) else {
        return;
    };
    let expected_config = match name {
        "portal-ui" => "portal-ui-config",
        "platform-api" => "platform-api-config",
        _ => "",
    };
    let env_from = item.get("envFrom");
    expect(
        env_from.is_some_and(|value| {
            value.as_array().is_some_and(|entries| {
                entries.len() == 1
                    && object(&entries[0]).is_some_and(|entry| entry.len() == 1)
                    && object_at(&entries[0], &["configMapRef"])
                        .is_some_and(|reference| reference.len() == 1)
                    && str_at(&entries[0], &["configMapRef", "name"]) == Some(expected_config)
            })
        }),
        errors,
        format!("Deployment {name} container {index} must import only ConfigMap {expected_config}"),
    );

    let env = array_at_path(container, &["env"]);
    if name == "platform-api" {
        let entry = env.first().copied().unwrap_or(&Value::Null);
        expect(
            env.len() == SECURITY_ADMISSION_KEYS.len() + 1
                && object(entry).is_some_and(|map| map.len() == 2)
                && str_at(entry, &["name"]) == Some("RYUKI_DATABASE_URL")
                && object_at(entry, &["valueFrom"]).is_some_and(|value_from| value_from.len() == 1)
                && object_at(entry, &["valueFrom", "secretKeyRef"])
                    .is_some_and(|reference| reference.len() == 2)
                && str_at(entry, &["valueFrom", "secretKeyRef", "name"])
                    == Some("ryuki-platform-api-db")
                && str_at(entry, &["valueFrom", "secretKeyRef", "key"])
                    == Some("RYUKI_DATABASE_URL")
                && value_at(entry, &["value"]).is_none(),
            errors,
            "Deployment platform-api must import the database URL plus seven security-admission keys",
        );
        expect(
            env.get(1..)
                .is_some_and(exact_security_admission_env_entries),
            errors,
            "Deployment platform-api must import the exact seven security-admission ConfigMap keys",
        );
    } else {
        expect(
            env.is_empty() && !item.contains_key("env"),
            errors,
            format!("Deployment {name} container {index} must not define env"),
        );
    }

    for entry in array_at_path(container, &["envFrom"]) {
        expect(
            value_at(entry, &["secretRef"]).is_none(),
            errors,
            format!(
                "Deployment {name} container {index} must not import a whole Secret through envFrom"
            ),
        );
    }
    for entry in &env {
        expect(
            value_at(entry, &["value"]).is_none(),
            errors,
            format!("Deployment {name} container {index} env must not contain literal values"),
        );
    }
}

fn exact_security_admission_env_entries(entries: &[&Value]) -> bool {
    entries.len() == SECURITY_ADMISSION_KEYS.len()
        && entries
            .iter()
            .zip(SECURITY_ADMISSION_KEYS)
            .all(|(entry, expected_key)| {
                object(entry).is_some_and(|map| object_has_exact_keys(map, &["name", "valueFrom"]))
                    && str_at(entry, &["name"]) == Some(*expected_key)
                    && object_at(entry, &["valueFrom"])
                        .is_some_and(|map| object_has_exact_keys(map, &["configMapKeyRef"]))
                    && object_at(entry, &["valueFrom", "configMapKeyRef"])
                        .is_some_and(|map| object_has_exact_keys(map, &["name", "key"]))
                    && str_at(entry, &["valueFrom", "configMapKeyRef", "name"])
                        == Some(SECURITY_ADMISSION_CONFIG_MAP)
                    && str_at(entry, &["valueFrom", "configMapKeyRef", "key"])
                        == Some(*expected_key)
            })
}

fn validate_cnpg_ca_mount(
    owner: &str,
    pod_spec: &Value,
    container: &Value,
    expected_volume_count: usize,
    errors: &mut Vec<String>,
) {
    let volumes = array_at_path(pod_spec, &["volumes"]);
    let volume = volumes
        .iter()
        .copied()
        .find(|volume| str_at(volume, &["name"]) == Some(CNPG_CA_VOLUME_NAME))
        .unwrap_or(&Value::Null);
    let items = array_at_path(volume, &["secret", "items"]);
    let item = items.first().copied().unwrap_or(&Value::Null);
    expect(
        volumes.len() == expected_volume_count
            && object(volume).is_some_and(|map| object_has_exact_keys(map, &["name", "secret"]))
            && str_at(volume, &["name"]) == Some(CNPG_CA_VOLUME_NAME)
            && object_at(volume, &["secret"])
                .is_some_and(|map| object_has_exact_keys(map, &["secretName", "items"]))
            && str_at(volume, &["secret", "secretName"]) == Some(CNPG_CA_SECRET_NAME)
            && items.len() == 1
            && object(item).is_some_and(|map| object_has_exact_keys(map, &["key", "path"]))
            && str_at(item, &["key"]) == Some(CNPG_CA_SECRET_KEY)
            && str_at(item, &["path"]) == Some(CNPG_CA_SECRET_KEY),
        errors,
        format!("{owner} must project only the exact CNPG CA volume"),
    );

    let mounts = array_at_path(container, &["volumeMounts"]);
    let mount = mounts
        .iter()
        .copied()
        .find(|mount| str_at(mount, &["name"]) == Some(CNPG_CA_VOLUME_NAME))
        .unwrap_or(&Value::Null);
    expect(
        mounts.len() == expected_volume_count
            && object(mount)
                .is_some_and(|map| object_has_exact_keys(map, &["name", "mountPath", "readOnly"]))
            && str_at(mount, &["name"]) == Some(CNPG_CA_VOLUME_NAME)
            && str_at(mount, &["mountPath"]) == Some(CNPG_CA_MOUNT_PATH)
            && bool_at(mount, &["readOnly"]) == Some(true),
        errors,
        format!("{owner} must mount only the CNPG CA read-only"),
    );
}

fn validate_platform_api_vault_workload_auth(
    manifests: &[Value],
    deployment: &Value,
    pod_spec: &Value,
    container: &Value,
    errors: &mut Vec<String>,
) {
    const READ_ONLY_MODE: i64 = 0o440;

    let service_account = manifests
        .iter()
        .find(|manifest| {
            str_at(manifest, &["kind"]) == Some("ServiceAccount")
                && str_at(manifest, &["metadata", "name"]) == Some("platform-api")
                && str_at(manifest, &["metadata", "namespace"]) == Some(NAMESPACE)
        })
        .unwrap_or(&Value::Null);
    expect(
        bool_at(service_account, &["automountServiceAccountToken"]) == Some(false)
            && str_at(pod_spec, &["serviceAccountName"]) == Some("platform-api")
            && bool_at(pod_spec, &["automountServiceAccountToken"]) == Some(false),
        errors,
        "platform-api ServiceAccount and pod must both disable ambient API token automount",
    );

    let pod_security = object_at(pod_spec, &["securityContext"]);
    expect(
        pod_security.is_some_and(|security| {
            object_has_exact_keys(
                security,
                &[
                    "runAsNonRoot",
                    "runAsUser",
                    "runAsGroup",
                    "fsGroup",
                    "fsGroupChangePolicy",
                ],
            )
        }) && bool_at(pod_spec, &["securityContext", "runAsNonRoot"]) == Some(true)
            && int_at(pod_spec, &["securityContext", "runAsUser"]) == Some(10001)
            && int_at(pod_spec, &["securityContext", "runAsGroup"]) == Some(10001)
            && int_at(pod_spec, &["securityContext", "fsGroup"]) == Some(10001)
            && str_at(pod_spec, &["securityContext", "fsGroupChangePolicy"])
                == Some("OnRootMismatch"),
        errors,
        "platform-api pod securityContext must contain only the reviewed non-root identity, fsGroup 10001, and OnRootMismatch policy",
    );

    let volumes = array_at_path(pod_spec, &["volumes"]);
    let token_volume = volumes
        .iter()
        .copied()
        .find(|volume| str_at(volume, &["name"]) == Some(VAULT_WORKLOAD_TOKEN_VOLUME_NAME))
        .unwrap_or(&Value::Null);
    let token_sources = array_at_path(token_volume, &["projected", "sources"]);
    let token_source = token_sources.first().copied().unwrap_or(&Value::Null);
    expect(
        volumes.len() == 4
            && object(token_volume)
                .is_some_and(|map| object_has_exact_keys(map, &["name", "projected"]))
            && object_at(token_volume, &["projected"])
                .is_some_and(|map| object_has_exact_keys(map, &["defaultMode", "sources"]))
            && int_at(token_volume, &["projected", "defaultMode"]) == Some(READ_ONLY_MODE)
            && token_sources.len() == 1
            && object(token_source)
                .is_some_and(|map| object_has_exact_keys(map, &["serviceAccountToken"]))
            && object_at(token_source, &["serviceAccountToken"]).is_some_and(|map| {
                object_has_exact_keys(map, &["audience", "expirationSeconds", "path"])
            })
            && str_at(token_source, &["serviceAccountToken", "audience"]) == Some("vault")
            && int_at(token_source, &["serviceAccountToken", "expirationSeconds"]) == Some(600)
            && str_at(token_source, &["serviceAccountToken", "path"]) == Some("token"),
        errors,
        "platform-api must project exactly one mode-0440, 600-second, vault-audience ServiceAccount JWT at token",
    );

    let ca_volume = volumes
        .iter()
        .copied()
        .find(|volume| str_at(volume, &["name"]) == Some(VAULT_CLIENT_CA_VOLUME_NAME))
        .unwrap_or(&Value::Null);
    let ca_items = array_at_path(ca_volume, &["secret", "items"]);
    let ca_item = ca_items.first().copied().unwrap_or(&Value::Null);
    expect(
        object(ca_volume).is_some_and(|map| object_has_exact_keys(map, &["name", "secret"]))
            && object_at(ca_volume, &["secret"]).is_some_and(|map| {
                object_has_exact_keys(map, &["secretName", "defaultMode", "items"])
            })
            && str_at(ca_volume, &["secret", "secretName"]) == Some(VAULT_CLIENT_CA_SECRET_NAME)
            && int_at(ca_volume, &["secret", "defaultMode"]) == Some(READ_ONLY_MODE)
            && ca_items.len() == 1
            && object(ca_item).is_some_and(|map| object_has_exact_keys(map, &["key", "path"]))
            && str_at(ca_item, &["key"]) == Some(CNPG_CA_SECRET_KEY)
            && str_at(ca_item, &["path"]) == Some(CNPG_CA_SECRET_KEY),
        errors,
        "platform-api must project only the exact mode-0440 Vault client CA certificate",
    );

    let mounts = array_at_path(container, &["volumeMounts"]);
    let token_mount = mounts
        .iter()
        .copied()
        .find(|mount| str_at(mount, &["name"]) == Some(VAULT_WORKLOAD_TOKEN_VOLUME_NAME))
        .unwrap_or(&Value::Null);
    let ca_mount = mounts
        .iter()
        .copied()
        .find(|mount| str_at(mount, &["name"]) == Some(VAULT_CLIENT_CA_VOLUME_NAME))
        .unwrap_or(&Value::Null);
    let exact_read_only_mount = |mount: &Value, name: &str, mount_path: &str| {
        object(mount)
            .is_some_and(|map| object_has_exact_keys(map, &["name", "mountPath", "readOnly"]))
            && str_at(mount, &["name"]) == Some(name)
            && str_at(mount, &["mountPath"]) == Some(mount_path)
            && bool_at(mount, &["readOnly"]) == Some(true)
    };
    expect(
        mounts.len() == 4
            && exact_read_only_mount(
                token_mount,
                VAULT_WORKLOAD_TOKEN_VOLUME_NAME,
                VAULT_WORKLOAD_TOKEN_MOUNT_PATH,
            )
            && exact_read_only_mount(
                ca_mount,
                VAULT_CLIENT_CA_VOLUME_NAME,
                VAULT_CLIENT_CA_MOUNT_PATH,
            ),
        errors,
        "platform-api must mount the reviewed Vault JWT and CA volumes read-only without subPath and without widening the four-volume API projection inventory",
    );

    let config_map = manifests
        .iter()
        .find(|manifest| {
            str_at(manifest, &["kind"]) == Some("ConfigMap")
                && str_at(manifest, &["metadata", "name"]) == Some("platform-api-config")
        })
        .unwrap_or(&Value::Null);
    let config_keys = object_at(config_map, &["data"]);
    let direct_env_names: Vec<&str> = array_at_path(container, &["env"])
        .iter()
        .filter_map(|entry| str_at(entry, &["name"]))
        .collect();
    expect(
        config_keys.is_some_and(|data| object_has_exact_keys(data, PLATFORM_API_CONFIG_KEYS))
            && direct_env_names
                .iter()
                .all(|name| !name.starts_with("VAULT_"))
            && direct_env_names.iter().all(|name| {
                !matches!(
                    *name,
                    "RYUKI_VAULT_ALLOW_INSECURE_LOOPBACK"
                        | "RYUKI_SECRET_PROVIDER_RUNTIME__TLS_SKIP_VERIFY"
                        | "RYUKI_SECRET_PROVIDER_RUNTIME__STATIC_TOKEN"
                )
            }),
        errors,
        "platform-api may receive only the exact reviewed value-free Vault settings; VAULT_TOKEN, legacy VAULT_* variables, static tokens, and TLS bypasses are forbidden",
    );

    expect(
        str_at(deployment, &["metadata", "namespace"]) == Some(NAMESPACE),
        errors,
        "platform-api workload-auth deployment must remain in ryuki-platform",
    );
}

fn validate_platform_api_secret_reference_fingerprint_keyring(
    pod_spec: &Value,
    container: &Value,
    errors: &mut Vec<String>,
) {
    const READ_ONLY_MODE: i64 = 0o440;

    let volumes = array_at_path(pod_spec, &["volumes"]);
    let keyring_volume = volumes
        .iter()
        .copied()
        .find(|volume| {
            str_at(volume, &["name"]) == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_VOLUME_NAME)
        })
        .unwrap_or(&Value::Null);
    let keyring_items = array_at_path(keyring_volume, &["secret", "items"]);
    let keyring_item = keyring_items.first().copied().unwrap_or(&Value::Null);
    expect(
        volumes.len() == 4
            && object(keyring_volume)
                .is_some_and(|map| object_has_exact_keys(map, &["name", "secret"]))
            && object_at(keyring_volume, &["secret"]).is_some_and(|map| {
                object_has_exact_keys(map, &["secretName", "defaultMode", "items"])
            })
            && str_at(keyring_volume, &["secret", "secretName"])
                == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_SECRET_NAME)
            && int_at(keyring_volume, &["secret", "defaultMode"]) == Some(READ_ONLY_MODE)
            && keyring_items.len() == 1
            && object(keyring_item).is_some_and(|map| object_has_exact_keys(map, &["key", "path"]))
            && str_at(keyring_item, &["key"]) == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_KEY)
            && str_at(keyring_item, &["path"]) == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_KEY),
        errors,
        "platform-api must project only the exact mode-0440 SecretRef fingerprint keyring key",
    );

    let mounts = array_at_path(container, &["volumeMounts"]);
    let keyring_mount = mounts
        .iter()
        .copied()
        .find(|mount| {
            str_at(mount, &["name"]) == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_VOLUME_NAME)
        })
        .unwrap_or(&Value::Null);
    expect(
        mounts.len() == 4
            && object(keyring_mount)
                .is_some_and(|map| object_has_exact_keys(map, &["name", "mountPath", "readOnly"]))
            && str_at(keyring_mount, &["name"])
                == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_VOLUME_NAME)
            && str_at(keyring_mount, &["mountPath"])
                == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_MOUNT_PATH)
            && bool_at(keyring_mount, &["readOnly"]) == Some(true),
        errors,
        "platform-api must mount only the exact SecretRef fingerprint keyring directory read-only without subPath",
    );
}

fn validate_secret_reference_fingerprint_keyring_exposure(
    manifests: &[Value],
    errors: &mut Vec<String>,
) {
    for workload in manifests
        .iter()
        .filter(|manifest| matches!(str_at(manifest, &["kind"]), Some("Deployment" | "Job")))
    {
        let name = str_at(workload, &["metadata", "name"])
            .or_else(|| str_at(workload, &["metadata", "generateName"]))
            .unwrap_or("");
        if str_at(workload, &["kind"]) == Some("Deployment") && name == "platform-api" {
            continue;
        }
        let pod_spec = value_at(workload, &["spec", "template", "spec"]).unwrap_or(&Value::Null);
        let exposes_volume = array_at_path(pod_spec, &["volumes"]).iter().any(|volume| {
            str_at(volume, &["name"]) == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_VOLUME_NAME)
                || str_at(volume, &["secret", "secretName"])
                    == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_SECRET_NAME)
        });
        let exposes_mount = array_at_path(pod_spec, &["containers"])
            .iter()
            .flat_map(|container| array_at_path(container, &["volumeMounts"]))
            .any(|mount| {
                str_at(mount, &["name"]) == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_VOLUME_NAME)
                    || str_at(mount, &["mountPath"])
                        == Some(SECRET_REFERENCE_FINGERPRINT_KEYRING_MOUNT_PATH)
            });
        expect(
            !exposes_volume && !exposes_mount,
            errors,
            format!(
                "{name} must not receive the platform-api SecretRef fingerprint keyring projection"
            ),
        );
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
    validate_target_update_strategy(name, deployment, errors);
}

fn validate_target_update_strategy(name: &str, deployment: &Value, errors: &mut Vec<String>) {
    if name != "platform-api" {
        return;
    }
    let strategy = value_at(deployment, &["spec", "strategy"]);
    expect(
        strategy.and_then(|value| str_at(value, &["type"])) == Some("Recreate"),
        errors,
        "Deployment platform-api must use Recreate to prevent old/new schema, authority, or envFrom secret overlap",
    );
    expect(
        strategy
            .and_then(Value::as_object)
            .is_some_and(|value| !value.contains_key("rollingUpdate")),
        errors,
        "Deployment platform-api Recreate strategy must not define rollingUpdate",
    );
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
    expect(
        str_at(ingress, &["spec", "ingressClassName"]) == Some(DEDICATED_INGRESS_CLASS),
        errors,
        format!("Ingress must use the dedicated {DEDICATED_INGRESS_CLASS} ingress class"),
    );
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
    validate_vault_workload_auth_network(&policies, errors);
    validate_migration_database_network(&policies, errors);
    validate_worker_egress(&policies, errors);
    validate_dns_egress(&policies, errors);
    validate_egress_graph(&policies, errors);
}

fn validate_vault_workload_auth_network(policies: &[&Value], errors: &mut Vec<String>) {
    let egress_policy = find_policy(policies, VAULT_API_EGRESS_POLICY);
    let egress_rules = array_at_path(egress_policy, &["spec", "egress"]);
    let egress_rule = egress_rules.first().copied().unwrap_or(&Value::Null);
    let egress_targets = array_at_path(egress_rule, &["to"]);
    let egress_target = egress_targets.first().copied().unwrap_or(&Value::Null);
    expect(
        str_at(egress_policy, &["metadata", "namespace"]) == Some(NAMESPACE)
            && object_at(egress_policy, &["spec"]).is_some_and(|spec| {
                object_has_exact_keys(spec, &["podSelector", "policyTypes", "egress"])
            })
            && exact_match_labels_selector(
                value_at(egress_policy, &["spec", "podSelector"]).unwrap_or(&Value::Null),
                &[
                    ("app.kubernetes.io/part-of", PART_OF),
                    ("app.kubernetes.io/name", "platform-api"),
                ],
            )
            && string_array_at(egress_policy, &["spec", "policyTypes"])
                == vec!["Egress".to_string()],
        errors,
        "Vault egress policy must select only ryuki-platform/platform-api",
    );
    expect(
        egress_rules.len() == 1
            && object(egress_rule)
                .is_some_and(|rule| object_has_exact_keys(rule, &["to", "ports"]))
            && egress_targets.len() == 1
            && vault_server_peer(egress_target)
            && exact_single_tcp_port(egress_rule, 8200),
        errors,
        "Vault egress must target only vault/vault server pods on TCP 8200",
    );

    let ingress_policy = find_policy(policies, VAULT_API_INGRESS_POLICY);
    let ingress_rules = array_at_path(ingress_policy, &["spec", "ingress"]);
    let ingress_rule = ingress_rules.first().copied().unwrap_or(&Value::Null);
    let ingress_sources = array_at_path(ingress_rule, &["from"]);
    let ingress_source = ingress_sources.first().copied().unwrap_or(&Value::Null);
    expect(
        str_at(ingress_policy, &["metadata", "namespace"]) == Some(VAULT_NAMESPACE)
            && object_at(ingress_policy, &["spec"]).is_some_and(|spec| {
                object_has_exact_keys(spec, &["podSelector", "policyTypes", "ingress"])
            })
            && exact_match_labels_selector(
                value_at(ingress_policy, &["spec", "podSelector"]).unwrap_or(&Value::Null),
                &[("app.kubernetes.io/name", "vault"), ("component", "server")],
            )
            && string_array_at(ingress_policy, &["spec", "policyTypes"])
                == vec!["Ingress".to_string()],
        errors,
        "Vault ingress policy must select only vault/vault server pods",
    );
    expect(
        ingress_rules.len() == 1
            && object(ingress_rule)
                .is_some_and(|rule| object_has_exact_keys(rule, &["from", "ports"]))
            && ingress_sources.len() == 1
            && exact_namespaced_pod_peer(
                ingress_source,
                NAMESPACE,
                &[
                    ("app.kubernetes.io/part-of", PART_OF),
                    ("app.kubernetes.io/name", "platform-api"),
                ],
            )
            && exact_single_tcp_port(ingress_rule, 8200),
        errors,
        "Vault ingress must admit only ryuki-platform/platform-api on TCP 8200",
    );
}

fn validate_vault_token_review_binding(manifests: &[Value], errors: &mut Vec<String>) {
    let bindings: Vec<&Value> = manifests
        .iter()
        .filter(|manifest| str_at(manifest, &["kind"]) == Some("ClusterRoleBinding"))
        .collect();
    expect(
        bindings.len() == 1,
        errors,
        "exactly one Vault TokenReview ClusterRoleBinding is required",
    );
    let binding = bindings.first().copied().unwrap_or(&Value::Null);
    let labels = object_at(binding, &["metadata", "labels"]);
    let subjects = array_at_path(binding, &["subjects"]);
    let subject = subjects.first().copied().unwrap_or(&Value::Null);
    expect(
        object(binding).is_some_and(|map| {
            object_has_exact_keys(
                map,
                &["apiVersion", "kind", "metadata", "roleRef", "subjects"],
            )
        }) && str_at(binding, &["apiVersion"]) == Some("rbac.authorization.k8s.io/v1")
            && str_at(binding, &["metadata", "name"]) == Some(VAULT_TOKEN_REVIEW_BINDING)
            && object_at(binding, &["metadata"])
                .is_some_and(|map| object_has_exact_keys(map, &["name", "labels"]))
            && labels.is_some_and(|map| {
                object_has_exact_keys(
                    map,
                    &["app.kubernetes.io/part-of", "app.kubernetes.io/name"],
                )
            })
            && str_at(
                binding,
                &["metadata", "labels", "app.kubernetes.io/part-of"],
            ) == Some(PART_OF)
            && str_at(binding, &["metadata", "labels", "app.kubernetes.io/name"]) == Some("vault")
            && value_at(binding, &["metadata", "namespace"]).is_none(),
        errors,
        "Vault TokenReview binding must retain the exact cluster-scoped identity and labels",
    );
    expect(
        object_at(binding, &["roleRef"])
            .is_some_and(|map| object_has_exact_keys(map, &["apiGroup", "kind", "name"]))
            && str_at(binding, &["roleRef", "apiGroup"]) == Some("rbac.authorization.k8s.io")
            && str_at(binding, &["roleRef", "kind"]) == Some("ClusterRole")
            && str_at(binding, &["roleRef", "name"]) == Some("system:auth-delegator"),
        errors,
        "Vault TokenReview binding must reference only system:auth-delegator and never cluster-admin",
    );
    expect(
        subjects.len() == 1
            && object(subject)
                .is_some_and(|map| object_has_exact_keys(map, &["kind", "name", "namespace"]))
            && str_at(subject, &["kind"]) == Some("ServiceAccount")
            && str_at(subject, &["name"]) == Some("vault")
            && str_at(subject, &["namespace"]) == Some(VAULT_NAMESPACE),
        errors,
        "Vault TokenReview binding must contain only the vault/vault ServiceAccount subject",
    );
}

fn exact_single_tcp_port(rule: &Value, expected_port: i64) -> bool {
    let ports = array_at_path(rule, &["ports"]);
    ports.len() == 1
        && object(ports[0]).is_some_and(|port| object_has_exact_keys(port, &["protocol", "port"]))
        && str_at(ports[0], &["protocol"]) == Some("TCP")
        && int_at(ports[0], &["port"]) == Some(expected_port)
}

fn exact_match_labels_selector(selector: &Value, expected: &[(&str, &str)]) -> bool {
    object(selector).is_some_and(|map| object_has_exact_keys(map, &["matchLabels"]))
        && object_at(selector, &["matchLabels"]).is_some_and(|labels| {
            labels.len() == expected.len()
                && expected
                    .iter()
                    .all(|(key, value)| labels.get(*key).and_then(Value::as_str) == Some(*value))
        })
}

fn exact_namespaced_pod_peer(peer: &Value, namespace: &str, pod_labels: &[(&str, &str)]) -> bool {
    object(peer)
        .is_some_and(|map| object_has_exact_keys(map, &["namespaceSelector", "podSelector"]))
        && exact_match_labels_selector(
            value_at(peer, &["namespaceSelector"]).unwrap_or(&Value::Null),
            &[("kubernetes.io/metadata.name", namespace)],
        )
        && exact_match_labels_selector(
            value_at(peer, &["podSelector"]).unwrap_or(&Value::Null),
            pod_labels,
        )
}

fn vault_server_peer(peer: &Value) -> bool {
    exact_namespaced_pod_peer(
        peer,
        VAULT_NAMESPACE,
        &[("app.kubernetes.io/name", "vault"), ("component", "server")],
    )
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
        !has_portal,
        errors,
        "platform-api ingress must not admit portal-ui over cleartext; portal traffic returns through ingress HTTPS",
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
    let policy = find_policy(
        policies,
        "allow-portal-ui-egress-to-dedicated-ingress-https",
    );
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
    let targets = array_at_path(egress, &["to"]);

    expect(
        source == Some("portal-ui"),
        errors,
        "portal-ui egress policy must select portal-ui",
    );
    expect(
        targets.len() == 1
            && targets
                .first()
                .is_some_and(|peer| ingress_controller_peer(peer)),
        errors,
        "portal-ui HTTPS egress must target only the dedicated Ryuki ingress controller pods",
    );
    expect(
        port_pairs(egress) == vec![("TCP".to_string(), 443)],
        errors,
        "portal-ui egress must allow ingress HTTPS TCP 443 only",
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

fn validate_migration_database_network(policies: &[&Value], errors: &mut Vec<String>) {
    let egress_policy = find_policy(policies, "allow-platform-api-migrations-egress-to-db");
    let egress_rules = array_at_path(egress_policy, &["spec", "egress"]);
    let egress = egress_rules.first().copied().unwrap_or(&Value::Null);
    let targets = array_at_path(egress, &["to"]);
    expect(
        str_at(
            egress_policy,
            &[
                "spec",
                "podSelector",
                "matchLabels",
                "app.kubernetes.io/name",
            ],
        ) == Some(MIGRATION_JOB)
            && string_array_at(egress_policy, &["spec", "policyTypes"])
                == vec!["Egress".to_string()],
        errors,
        "migration database egress policy must select only the migration Job",
    );
    expect(
        egress_rules.len() == 1
            && targets.len() == 1
            && targets.first().is_some_and(|target| {
                str_at(target, &["podSelector", "matchLabels", "cnpg.io/cluster"])
                    == Some("ryuki-platform-db")
                    && value_at(target, &["namespaceSelector"]).is_none()
            })
            && port_pairs(egress) == vec![("TCP".to_string(), 5432)],
        errors,
        "migration database egress must target only ryuki-platform-db TCP 5432",
    );

    let ingress_policy = find_policy(policies, "allow-ingress-to-db-from-platform-api-migrations");
    let ingress_rules = array_at_path(ingress_policy, &["spec", "ingress"]);
    let ingress = ingress_rules.first().copied().unwrap_or(&Value::Null);
    let sources = array_at_path(ingress, &["from"]);
    expect(
        str_at(
            ingress_policy,
            &["spec", "podSelector", "matchLabels", "cnpg.io/cluster"],
        ) == Some("ryuki-platform-db")
            && string_array_at(ingress_policy, &["spec", "policyTypes"])
                == vec!["Ingress".to_string()],
        errors,
        "migration database ingress policy must select only ryuki-platform-db",
    );
    expect(
        ingress_rules.len() == 1
            && sources.len() == 1
            && sources.first().is_some_and(|source| {
                str_at(
                    source,
                    &["podSelector", "matchLabels", "app.kubernetes.io/part-of"],
                ) == Some(PART_OF)
                    && str_at(
                        source,
                        &["podSelector", "matchLabels", "app.kubernetes.io/name"],
                    ) == Some(MIGRATION_JOB)
                    && value_at(source, &["namespaceSelector"]).is_none()
            })
            && port_pairs(ingress) == vec![("TCP".to_string(), 5432)],
        errors,
        "migration database ingress must admit only the migration Job on TCP 5432",
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
                if ingress_controller_peer(peer) {
                    continue;
                }
                if vault_server_peer(peer)
                    && str_at(policy, &["metadata", "name"]) == Some(VAULT_API_EGRESS_POLICY)
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
    allowed_edges.insert(("portal-ui".to_string(), "ingress-nginx".to_string()));
    // CloudNativePG database tier: the API reaches Postgres, and the cluster's
    // instances talk to each other (replication / instance-manager). Both edges
    // are scoped to the `db` component resolved from the `cnpg.io/cluster` label.
    allowed_edges.insert(("platform-api".to_string(), "db".to_string()));
    allowed_edges.insert((MIGRATION_JOB.to_string(), "db".to_string()));
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
                    let dedicated_vault_edge = source == "platform-api"
                        && target == "vault"
                        && str_at(policy, &["metadata", "name"]) == Some(VAULT_API_EGRESS_POLICY);
                    if !dedicated_vault_edge
                        && !allowed_edges.contains(&(source.clone(), target.clone()))
                    {
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

fn validate_vault_external_auth_files(source_texts: &[SourceText], errors: &mut Vec<String>) {
    let exact_source = |path: &str| {
        let matches: Vec<&SourceText> = source_texts
            .iter()
            .filter(|source| source.path == path)
            .collect();
        (matches.len() == 1).then(|| matches[0].text.as_str())
    };

    let workload_auth_text = exact_source(VAULT_WORKLOAD_AUTH_MANIFEST_PATH);
    expect(
        workload_auth_text.is_some(),
        errors,
        format!("{VAULT_WORKLOAD_AUTH_MANIFEST_PATH} must be loaded exactly once"),
    );
    if let Some(text) = workload_auth_text {
        validate_yaml_duplicate_keys_text(text, VAULT_WORKLOAD_AUTH_MANIFEST_PATH, errors);
    }
    let workload_auth_documents = workload_auth_text
        .and_then(|text| {
            serde_yaml::Deserializer::from_str(text)
                .map(Value::deserialize)
                .collect::<Result<Vec<_>, _>>()
                .ok()
        })
        .unwrap_or_default();
    expect(
        workload_auth_documents.len() == 2
            && str_at(&workload_auth_documents[0], &["kind"]) == Some("NetworkPolicy")
            && str_at(&workload_auth_documents[0], &["metadata", "name"])
                == Some(VAULT_API_INGRESS_POLICY)
            && str_at(&workload_auth_documents[1], &["kind"]) == Some("ClusterRoleBinding")
            && str_at(&workload_auth_documents[1], &["metadata", "name"])
                == Some(VAULT_TOKEN_REVIEW_BINDING),
        errors,
        format!(
            "{VAULT_WORKLOAD_AUTH_MANIFEST_PATH} must contain only the exact Vault ingress policy and TokenReview binding"
        ),
    );

    let auth_config_text = exact_source(VAULT_KUBERNETES_AUTH_CONFIG_PATH);
    expect(
        auth_config_text.is_some(),
        errors,
        format!("{VAULT_KUBERNETES_AUTH_CONFIG_PATH} must be loaded exactly once"),
    );
    let auth_config = auth_config_text
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or(Value::Null);
    let auth_config_keys = [
        "disable_local_ca_jwt",
        "kubernetes_host",
        "use_annotations_as_alias_metadata",
    ];
    expect(
        object(&auth_config).is_some_and(|map| object_has_exact_keys(map, &auth_config_keys))
            && auth_config_text.is_some_and(|text| json_keys_appear_once(text, &auth_config_keys))
            && bool_at(&auth_config, &["disable_local_ca_jwt"]) == Some(false)
            && str_at(&auth_config, &["kubernetes_host"])
                == Some("https://kubernetes.default.svc:443")
            && bool_at(&auth_config, &["use_annotations_as_alias_metadata"]) == Some(false),
        errors,
        format!(
            "{VAULT_KUBERNETES_AUTH_CONFIG_PATH} must use only the in-cluster rotating reviewer identity and exact Kubernetes API endpoint"
        ),
    );

    let role_text = exact_source(VAULT_PLATFORM_API_ROLE_PATH);
    expect(
        role_text.is_some(),
        errors,
        format!("{VAULT_PLATFORM_API_ROLE_PATH} must be loaded exactly once"),
    );
    let role = role_text
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or(Value::Null);
    let role_keys = [
        "alias_name_source",
        "audience",
        "bound_service_account_names",
        "bound_service_account_namespaces",
        "token_explicit_max_ttl",
        "token_max_ttl",
        "token_no_default_policy",
        "token_num_uses",
        "token_period",
        "token_policies",
        "token_ttl",
        "token_type",
    ];
    expect(
        object(&role).is_some_and(|map| object_has_exact_keys(map, &role_keys))
            && role_text.is_some_and(|text| json_keys_appear_once(text, &role_keys))
            && str_at(&role, &["alias_name_source"]) == Some("serviceaccount_uid")
            && str_at(&role, &["audience"]) == Some("vault")
            && string_array_at(&role, &["bound_service_account_names"])
                == vec!["platform-api".to_string()]
            && string_array_at(&role, &["bound_service_account_namespaces"])
                == vec![NAMESPACE.to_string()]
            && int_at(&role, &["token_ttl"]) == Some(600)
            && int_at(&role, &["token_max_ttl"]) == Some(900)
            && int_at(&role, &["token_explicit_max_ttl"]) == Some(900)
            && int_at(&role, &["token_num_uses"]) == Some(0)
            && int_at(&role, &["token_period"]) == Some(0)
            && bool_at(&role, &["token_no_default_policy"]) == Some(true)
            && string_array_at(&role, &["token_policies"])
                == vec![VAULT_PLATFORM_API_POLICY_NAME.to_string()]
            && str_at(&role, &["token_type"]) == Some("service"),
        errors,
        format!(
            "{VAULT_PLATFORM_API_ROLE_PATH} must bind only the exact API ServiceAccount, vault audience, finite non-periodic service token, and dedicated no-default policy"
        ),
    );

    let policy_text = exact_source(VAULT_PLATFORM_API_POLICY_PATH);
    expect(
        policy_text.is_some(),
        errors,
        format!("{VAULT_PLATFORM_API_POLICY_PATH} must be loaded exactly once"),
    );
    let normalized_policy = policy_text
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let expected_policy = [
        "path \"secret/data/ryuki-platform/platform-api/*\" {",
        "capabilities = [\"read\"]",
        "}",
        "path \"secret/metadata/ryuki-platform/platform-api/*\" {",
        "capabilities = [\"read\"]",
        "}",
    ]
    .join("\n");
    expect(
        normalized_policy == expected_policy,
        errors,
        format!(
            "{VAULT_PLATFORM_API_POLICY_PATH} must grant read only on the exact API KV-v2 data and metadata prefixes"
        ),
    );
}

fn json_keys_appear_once(text: &str, keys: &[&str]) -> bool {
    keys.iter().all(|key| {
        let quoted = format!("\"{key}\"");
        text.matches(quoted.as_str()).count() == 1
    })
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
                    !unsafe_manifest_key(key, child, &child_path, current_kind),
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
        && str_at(
            peer,
            &["podSelector", "matchLabels", "app.kubernetes.io/instance"],
        ) == Some(DEDICATED_INGRESS_INSTANCE)
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

fn unsafe_manifest_key(key: &str, value: &Value, path: &str, manifest_kind: Option<&str>) -> bool {
    if manifest_kind == Some("Ingress") && ingress_schema_key_allowed(key, path) {
        return false;
    }
    if key == "secretName"
        && matches!(manifest_kind, Some("Deployment") | Some("Job"))
        && path.contains(".spec.template.spec.volumes[")
        && path.ends_with(".secret.secretName")
        && value.as_str().is_some_and(|name| {
            name == CNPG_CA_SECRET_NAME
                || name == VAULT_CLIENT_CA_SECRET_NAME
                || name == SECRET_REFERENCE_FINGERPRINT_KEYRING_SECRET_NAME
        })
    {
        // The two named CA Secrets are public trust material, while the
        // fingerprint keyring is a dedicated credential source. Their owning
        // workload validators require one exact item and read-only mount, so no
        // unrelated Secret key can cross into the client workload.
        return false;
    }
    if manifest_kind == Some("ConfigMap")
        && path.contains(".data.")
        && PLATFORM_API_CONFIG_KEYS.contains(&key)
    {
        // The exact ConfigMap key inventory and all security-sensitive values
        // are checked independently by `validate_config_maps`.
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
        || value == "0.0.0.0:8080"
        || value == format!("https://{APPROVED_HOST}")
        || (value == "https://vault.vault.svc:8200"
            && path.ends_with(".data.RYUKI_SECRET_PROVIDER_RUNTIME__ENDPOINT"))
        || (value == CNPG_CA_SECRET_KEY
            && path.contains(".spec.template.spec.volumes[")
            && (path.ends_with(".secret.items[0].key") || path.ends_with(".secret.items[0].path")))
        || (path.contains(".spec.template.spec.containers[")
            && path.ends_with(".image")
            && is_qualified_immutable_image(value))
        || (path.ends_with(".metadata.annotations.ryuki.io/release-image")
            && is_qualified_immutable_image(value))
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

    fn vault_manifest_fixture() -> Vec<Value> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        [
            "deploy/kubernetes/base/serviceaccounts.yaml",
            "deploy/kubernetes/base/configmap.yaml",
            "deploy/kubernetes/base/deployments.yaml",
            "deploy/kubernetes/base/networkpolicies.yaml",
            VAULT_WORKLOAD_AUTH_MANIFEST_PATH,
        ]
        .iter()
        .flat_map(|path| {
            let raw = fs::read_to_string(root.join(path))
                .unwrap_or_else(|error| panic!("{path} must be readable: {error}"));
            serde_yaml::Deserializer::from_str(&raw)
                .map(|document| {
                    Value::deserialize(document)
                        .unwrap_or_else(|error| panic!("{path} must parse: {error}"))
                })
                .collect::<Vec<_>>()
        })
        .collect()
    }

    fn vault_external_source_fixture() -> Vec<SourceText> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        [
            VAULT_WORKLOAD_AUTH_MANIFEST_PATH,
            VAULT_KUBERNETES_AUTH_CONFIG_PATH,
            VAULT_PLATFORM_API_ROLE_PATH,
            VAULT_PLATFORM_API_POLICY_PATH,
        ]
        .iter()
        .map(|path| SourceText {
            path: (*path).to_string(),
            text: fs::read_to_string(root.join(path))
                .unwrap_or_else(|error| panic!("{path} must be readable: {error}")),
        })
        .collect()
    }

    fn vault_manifest_errors(manifests: &[Value]) -> Vec<String> {
        let mut errors = Vec::new();
        validate_config_maps(manifests, &mut errors);
        let deployment = manifests
            .iter()
            .find(|manifest| {
                str_at(manifest, &["kind"]) == Some("Deployment")
                    && str_at(manifest, &["metadata", "name"]) == Some("platform-api")
            })
            .unwrap_or(&Value::Null);
        let pod_spec = value_at(deployment, &["spec", "template", "spec"]).unwrap_or(&Value::Null);
        let container = array_at_path(pod_spec, &["containers"])
            .first()
            .copied()
            .unwrap_or(&Value::Null);
        validate_cnpg_ca_mount(
            "Deployment platform-api",
            pod_spec,
            container,
            4,
            &mut errors,
        );
        validate_platform_api_vault_workload_auth(
            manifests,
            deployment,
            pod_spec,
            container,
            &mut errors,
        );
        validate_platform_api_secret_reference_fingerprint_keyring(
            pod_spec,
            container,
            &mut errors,
        );
        validate_secret_reference_fingerprint_keyring_exposure(manifests, &mut errors);
        let policies: Vec<&Value> = manifests
            .iter()
            .filter(|manifest| str_at(manifest, &["kind"]) == Some("NetworkPolicy"))
            .collect();
        validate_vault_workload_auth_network(&policies, &mut errors);
        validate_vault_token_review_binding(manifests, &mut errors);
        errors
    }

    #[test]
    fn checked_in_vault_workload_auth_contract_is_exact() {
        let manifests = vault_manifest_fixture();
        let errors = vault_manifest_errors(&manifests);
        assert!(
            errors.is_empty(),
            "checked-in Vault workload-auth manifests must pass: {errors:?}"
        );

        let sources = vault_external_source_fixture();
        let mut errors = Vec::new();
        validate_vault_external_auth_files(&sources, &mut errors);
        assert!(
            errors.is_empty(),
            "checked-in Vault bootstrap inputs must pass: {errors:?}"
        );
    }

    #[test]
    fn vault_projected_identity_ca_and_safe_env_contract_reject_mutations() {
        let manifests = vault_manifest_fixture();
        let api_index = manifests
            .iter()
            .position(|manifest| {
                str_at(manifest, &["kind"]) == Some("Deployment")
                    && str_at(manifest, &["metadata", "name"]) == Some("platform-api")
            })
            .expect("platform-api Deployment");

        for (label, pointer, replacement) in [
            (
                "ambient automount",
                "/spec/template/spec/automountServiceAccountToken",
                json!(true),
            ),
            (
                "wrong pod group",
                "/spec/template/spec/securityContext/fsGroup",
                json!(10002),
            ),
            (
                "writable token mode",
                "/spec/template/spec/volumes/1/projected/defaultMode",
                json!(0o660),
            ),
            (
                "wrong audience",
                "/spec/template/spec/volumes/1/projected/sources/0/serviceAccountToken/audience",
                json!("kubernetes"),
            ),
            (
                "long token lifetime",
                "/spec/template/spec/volumes/1/projected/sources/0/serviceAccountToken/expirationSeconds",
                json!(601),
            ),
            (
                "alternate token path",
                "/spec/template/spec/volumes/1/projected/sources/0/serviceAccountToken/path",
                json!("alternate"),
            ),
            (
                "substituted CA",
                "/spec/template/spec/volumes/2/secret/secretName",
                json!("unreviewed-ca"),
            ),
            (
                "writable CA mode",
                "/spec/template/spec/volumes/2/secret/defaultMode",
                json!(0o660),
            ),
            (
                "writable token mount",
                "/spec/template/spec/containers/0/volumeMounts/1/readOnly",
                json!(false),
            ),
            (
                "substituted fingerprint keyring",
                "/spec/template/spec/volumes/3/secret/secretName",
                json!("unreviewed-keyring"),
            ),
            (
                "writable fingerprint keyring mode",
                "/spec/template/spec/volumes/3/secret/defaultMode",
                json!(0o660),
            ),
            (
                "alternate fingerprint keyring key",
                "/spec/template/spec/volumes/3/secret/items/0/key",
                json!("alternate"),
            ),
            (
                "alternate fingerprint keyring item path",
                "/spec/template/spec/volumes/3/secret/items/0/path",
                json!("alternate"),
            ),
            (
                "writable fingerprint keyring mount",
                "/spec/template/spec/containers/0/volumeMounts/3/readOnly",
                json!(false),
            ),
            (
                "alternate fingerprint keyring mount path",
                "/spec/template/spec/containers/0/volumeMounts/3/mountPath",
                json!("/var/run/secrets/alternate"),
            ),
        ] {
            let mut invalid = manifests.clone();
            *invalid[api_index]
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("missing mutation pointer {pointer}")) = replacement;
            let errors = vault_manifest_errors(&invalid);
            assert!(
                !errors.is_empty(),
                "Vault workload-auth mutation {label} must fail closed"
            );
        }

        let mut extra_source = manifests.clone();
        extra_source[api_index]
            .pointer_mut("/spec/template/spec/volumes/1/projected/sources")
            .and_then(Value::as_array_mut)
            .expect("projected token sources")
            .push(json!({ "serviceAccountToken": {
                "audience": "vault", "expirationSeconds": 600, "path": "second-token"
            }}));
        assert!(!vault_manifest_errors(&extra_source).is_empty());

        let mut sub_path = manifests.clone();
        sub_path[api_index]
            .pointer_mut("/spec/template/spec/containers/0/volumeMounts/1")
            .and_then(Value::as_object_mut)
            .expect("Vault token mount")
            .insert("subPath".to_string(), json!("token"));
        assert!(!vault_manifest_errors(&sub_path).is_empty());

        let mut extra_keyring_item = manifests.clone();
        extra_keyring_item[api_index]
            .pointer_mut("/spec/template/spec/volumes/3/secret/items")
            .and_then(Value::as_array_mut)
            .expect("fingerprint keyring items")
            .push(json!({ "key": "additional", "path": "additional" }));
        assert!(
            !vault_manifest_errors(&extra_keyring_item).is_empty(),
            "an additional projected fingerprint keyring key must fail closed"
        );

        let mut keyring_sub_path = manifests.clone();
        keyring_sub_path[api_index]
            .pointer_mut("/spec/template/spec/containers/0/volumeMounts/3")
            .and_then(Value::as_object_mut)
            .expect("fingerprint keyring mount")
            .insert("subPath".to_string(), json!("keyring"));
        assert!(
            !vault_manifest_errors(&keyring_sub_path).is_empty(),
            "a fingerprint keyring subPath mount must fail closed"
        );

        let portal_index = manifests
            .iter()
            .position(|manifest| {
                str_at(manifest, &["kind"]) == Some("Deployment")
                    && str_at(manifest, &["metadata", "name"]) == Some("portal-ui")
            })
            .expect("portal-ui Deployment");
        let mut portal_exposure = manifests.clone();
        portal_exposure[portal_index]["spec"]["template"]["spec"]["volumes"] = json!([{
            "name": SECRET_REFERENCE_FINGERPRINT_KEYRING_VOLUME_NAME,
            "secret": {
                "secretName": SECRET_REFERENCE_FINGERPRINT_KEYRING_SECRET_NAME,
                "defaultMode": 0o440,
                "items": [{ "key": "keyring", "path": "keyring" }]
            }
        }]);
        portal_exposure[portal_index]["spec"]["template"]["spec"]["containers"][0]
            ["volumeMounts"] = json!([{
            "name": SECRET_REFERENCE_FINGERPRINT_KEYRING_VOLUME_NAME,
            "mountPath": SECRET_REFERENCE_FINGERPRINT_KEYRING_MOUNT_PATH,
            "readOnly": true
        }]);
        let errors = vault_manifest_errors(&portal_exposure);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("portal-ui") && error.contains("must not receive")),
            "the fingerprint keyring must remain exposed only to platform-api: {errors:?}"
        );

        for forbidden_name in [
            "VAULT_TOKEN",
            "VAULT_SKIP_VERIFY",
            "RYUKI_VAULT_ALLOW_INSECURE_LOOPBACK",
            "RYUKI_SECRET_PROVIDER_RUNTIME__TLS_SKIP_VERIFY",
        ] {
            let mut invalid = manifests.clone();
            invalid[api_index]
                .pointer_mut("/spec/template/spec/containers/0/env")
                .and_then(Value::as_array_mut)
                .expect("platform-api env")
                .push(json!({ "name": forbidden_name, "value": "forbidden" }));
            assert!(
                !vault_manifest_errors(&invalid).is_empty(),
                "forbidden environment key {forbidden_name} must fail closed"
            );
        }

        for mutation in [
            "remove-policy",
            "substitute-endpoint",
            "substitute-fingerprint-keyring-path",
            "add-static-token",
        ] {
            let mut invalid = manifests.clone();
            let config = invalid
                .iter_mut()
                .find(|manifest| {
                    str_at(manifest, &["kind"]) == Some("ConfigMap")
                        && str_at(manifest, &["metadata", "name"]) == Some("platform-api-config")
                })
                .expect("platform-api ConfigMap");
            let data = config["data"].as_object_mut().expect("ConfigMap data");
            match mutation {
                "remove-policy" => {
                    data.remove("RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_TOKEN_POLICY");
                }
                "substitute-endpoint" => {
                    data.insert(
                        "RYUKI_SECRET_PROVIDER_RUNTIME__ENDPOINT".to_string(),
                        json!("https://alternate.invalid:8200"),
                    );
                }
                "substitute-fingerprint-keyring-path" => {
                    data.insert(
                        "RYUKI_SECRET_REFERENCE_FINGERPRINT_KEYRING_PATH".to_string(),
                        json!("/var/run/secrets/alternate/keyring"),
                    );
                }
                "add-static-token" => {
                    data.insert("VAULT_TOKEN".to_string(), json!("forbidden"));
                }
                _ => unreachable!(),
            }
            assert!(
                !vault_manifest_errors(&invalid).is_empty(),
                "ConfigMap mutation {mutation} must fail closed"
            );
        }
    }

    #[test]
    fn vault_network_and_tokenreview_rbac_reject_mutations() {
        let manifests = vault_manifest_fixture();
        for (policy_name, pointer, replacement) in [
            (
                VAULT_API_EGRESS_POLICY,
                "/spec/podSelector/matchLabels/app.kubernetes.io~1name",
                json!("portal-ui"),
            ),
            (
                VAULT_API_EGRESS_POLICY,
                "/spec/egress/0/to/0/namespaceSelector/matchLabels/kubernetes.io~1metadata.name",
                json!("default"),
            ),
            (
                VAULT_API_EGRESS_POLICY,
                "/spec/egress/0/to/0/podSelector/matchLabels/component",
                json!("injector"),
            ),
            (
                VAULT_API_EGRESS_POLICY,
                "/spec/egress/0/ports/0/port",
                json!(443),
            ),
            (
                VAULT_API_INGRESS_POLICY,
                "/metadata/namespace",
                json!(NAMESPACE),
            ),
            (
                VAULT_API_INGRESS_POLICY,
                "/spec/ingress/0/from/0/namespaceSelector/matchLabels/kubernetes.io~1metadata.name",
                json!("default"),
            ),
            (
                VAULT_API_INGRESS_POLICY,
                "/spec/ingress/0/from/0/podSelector/matchLabels/app.kubernetes.io~1name",
                json!("portal-ui"),
            ),
            (
                VAULT_API_INGRESS_POLICY,
                "/spec/ingress/0/ports/0/port",
                json!(8201),
            ),
        ] {
            let mut invalid = manifests.clone();
            let policy = invalid
                .iter_mut()
                .find(|manifest| {
                    str_at(manifest, &["kind"]) == Some("NetworkPolicy")
                        && str_at(manifest, &["metadata", "name"]) == Some(policy_name)
                })
                .unwrap_or_else(|| panic!("missing NetworkPolicy {policy_name}"));
            *policy
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("missing mutation pointer {pointer}")) = replacement;
            let policies: Vec<&Value> = invalid
                .iter()
                .filter(|manifest| str_at(manifest, &["kind"]) == Some("NetworkPolicy"))
                .collect();
            let mut errors = Vec::new();
            validate_vault_workload_auth_network(&policies, &mut errors);
            assert!(
                !errors.is_empty(),
                "network mutation {policy_name}{pointer} must fail closed"
            );
        }

        let mut smuggled_vault_edge = manifests.clone();
        let database_egress = smuggled_vault_edge
            .iter_mut()
            .find(|manifest| {
                str_at(manifest, &["kind"]) == Some("NetworkPolicy")
                    && str_at(manifest, &["metadata", "name"])
                        == Some("allow-platform-api-egress-to-db")
            })
            .expect("platform-api database egress policy");
        database_egress["spec"]["egress"][0]["to"] = json!([{
            "namespaceSelector": { "matchLabels": {
                "kubernetes.io/metadata.name": VAULT_NAMESPACE
            }},
            "podSelector": { "matchLabels": {
                "app.kubernetes.io/name": "vault",
                "component": "server"
            }}
        }]);
        database_egress["spec"]["egress"][0]
            .as_object_mut()
            .expect("database egress rule")
            .remove("ports");
        let policies: Vec<&Value> = smuggled_vault_edge
            .iter()
            .filter(|manifest| str_at(manifest, &["kind"]) == Some("NetworkPolicy"))
            .collect();
        let mut errors = Vec::new();
        validate_no_cross_namespace_component_peers(&policies, &mut errors);
        validate_egress_graph(&policies, &mut errors);
        assert!(
            !errors.is_empty(),
            "an all-ports Vault edge smuggled into another expected API policy must fail closed"
        );

        for (label, pointer, replacement) in [
            ("cluster-admin", "/roleRef/name", json!("cluster-admin")),
            ("wrong subject", "/subjects/0/name", json!("platform-api")),
            ("wrong namespace", "/subjects/0/namespace", json!(NAMESPACE)),
        ] {
            let mut invalid = manifests.clone();
            let binding = invalid
                .iter_mut()
                .find(|manifest| str_at(manifest, &["kind"]) == Some("ClusterRoleBinding"))
                .expect("Vault TokenReview binding");
            *binding
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("missing RBAC mutation pointer {pointer}")) = replacement;
            let mut errors = Vec::new();
            validate_vault_token_review_binding(&invalid, &mut errors);
            assert!(!errors.is_empty(), "RBAC mutation {label} must fail closed");
        }

        let mut extra_subject = manifests.clone();
        extra_subject
            .iter_mut()
            .find(|manifest| str_at(manifest, &["kind"]) == Some("ClusterRoleBinding"))
            .and_then(|binding| binding.pointer_mut("/subjects"))
            .and_then(Value::as_array_mut)
            .expect("Vault TokenReview subjects")
            .push(
                json!({ "kind": "ServiceAccount", "name": "platform-api", "namespace": NAMESPACE }),
            );
        let mut errors = Vec::new();
        validate_vault_token_review_binding(&extra_subject, &mut errors);
        assert!(
            !errors.is_empty(),
            "additional RBAC subject must fail closed"
        );
    }

    #[test]
    fn vault_auth_role_and_policy_bootstrap_inputs_reject_mutations() {
        let sources = vault_external_source_fixture();

        for (path, pointer, replacement) in [
            (
                VAULT_KUBERNETES_AUTH_CONFIG_PATH,
                "/disable_local_ca_jwt",
                json!(true),
            ),
            (VAULT_PLATFORM_API_ROLE_PATH, "/audience", json!("other")),
            (VAULT_PLATFORM_API_ROLE_PATH, "/token_ttl", json!(901)),
            (
                VAULT_PLATFORM_API_ROLE_PATH,
                "/token_no_default_policy",
                json!(false),
            ),
            (
                VAULT_PLATFORM_API_ROLE_PATH,
                "/token_policies",
                json!(["default"]),
            ),
        ] {
            let mut invalid = sources.clone();
            let source = invalid
                .iter_mut()
                .find(|source| source.path == path)
                .unwrap_or_else(|| panic!("missing source {path}"));
            let mut document: Value =
                serde_json::from_str(&source.text).expect("JSON bootstrap input");
            *document
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("missing JSON mutation pointer {pointer}")) = replacement;
            source.text = serde_json::to_string_pretty(&document).expect("serialize mutation");
            let mut errors = Vec::new();
            validate_vault_external_auth_files(&invalid, &mut errors);
            assert!(
                !errors.is_empty(),
                "bootstrap mutation {path}{pointer} must fail closed"
            );
        }

        for (from, to) in [
            (
                "capabilities = [\"read\"]",
                "capabilities = [\"read\", \"update\"]",
            ),
            (
                "secret/data/ryuki-platform/platform-api/*",
                "secret/data/ryuki-platform/*",
            ),
        ] {
            let mut invalid = sources.clone();
            let policy = invalid
                .iter_mut()
                .find(|source| source.path == VAULT_PLATFORM_API_POLICY_PATH)
                .expect("Vault policy source");
            policy.text = policy.text.replacen(from, to, 1);
            let mut errors = Vec::new();
            validate_vault_external_auth_files(&invalid, &mut errors);
            assert!(
                !errors.is_empty(),
                "broadened Vault policy mutation must fail closed"
            );
        }

        let mut duplicate_key = sources.clone();
        let auth_config = duplicate_key
            .iter_mut()
            .find(|source| source.path == VAULT_KUBERNETES_AUTH_CONFIG_PATH)
            .expect("Vault Kubernetes auth config");
        auth_config.text = auth_config
            .text
            .replacen('{', "{\"disable_local_ca_jwt\": true,", 1);
        let mut errors = Vec::new();
        validate_vault_external_auth_files(&duplicate_key, &mut errors);
        assert!(
            !errors.is_empty(),
            "duplicate bootstrap JSON keys must fail closed"
        );
    }

    // ── target hardening helpers ──────────────────────────────────────

    #[test]
    fn rendered_image_rewrites_require_qualified_digest_only_references() {
        let digest = "a".repeat(64);
        let admitted = format!("registry.example.invalid/ryuki/portal-ui@sha256:{digest}");
        assert!(is_qualified_immutable_image(&admitted));

        for rejected in [
            "ryuki/portal-ui:rust-dev".to_string(),
            "registry.example.invalid/ryuki/portal-ui:stable".to_string(),
            format!("ryuki/portal-ui@sha256:{digest}"),
            format!("https://registry.example.invalid/ryuki/portal-ui@sha256:{digest}"),
            format!("registry.example.invalid/ryuki/portal-ui:stable@sha256:{digest}"),
            format!(
                "registry.example.invalid/ryuki/portal-ui@sha256:{}",
                "a".repeat(63)
            ),
            format!(
                "registry.example.invalid/ryuki/portal-ui@sha256:{}",
                "A".repeat(64)
            ),
        ] {
            assert!(
                !is_qualified_immutable_image(&rejected),
                "mutable or malformed rendered image must be rejected: {rejected}"
            );
            let mut errors = Vec::new();
            validate_container_image("portal-ui", &json!({ "image": rejected }), &mut errors);
            assert!(
                errors.iter().any(|error| error.contains("@sha256")),
                "validator must explain the immutable image contract: {errors:?}"
            );
        }
    }

    #[test]
    fn admitted_image_value_is_safe_only_at_a_container_image_path() {
        let image = format!(
            "registry.example.invalid/ryuki/platform-api@sha256:{}",
            "b".repeat(64)
        );
        assert!(safe_manifest_value(
            "manifests[0].spec.template.spec.containers[0].image",
            &image,
        ));
        assert!(
            !safe_manifest_value("manifests[0].metadata.labels.note", &image),
            "qualified registry hostnames are admitted only as validated image fields"
        );
    }

    #[test]
    fn platform_api_rollout_cannot_overlap_old_and_new_replicas() {
        for strategy in [
            json!({ "type": "RollingUpdate" }),
            json!({
                "type": "Recreate",
                "rollingUpdate": { "maxUnavailable": 0, "maxSurge": 1 }
            }),
            Value::Null,
        ] {
            let deployment = json!({ "spec": { "strategy": strategy } });
            let mut errors = Vec::new();
            validate_target_update_strategy("platform-api", &deployment, &mut errors);
            assert!(
                !errors.is_empty(),
                "overlapping or absent API rollout strategy must fail closed"
            );
        }

        let deployment = json!({ "spec": { "strategy": { "type": "Recreate" } } });
        let mut errors = Vec::new();
        validate_target_update_strategy("platform-api", &deployment, &mut errors);
        assert!(errors.is_empty(), "Recreate should be admitted: {errors:?}");
    }

    #[test]
    fn checked_in_platform_api_source_retains_recreate() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let raw = fs::read_to_string(root.join("deploy/kubernetes/base/deployments.yaml"))
            .expect("checked-in Deployments must be readable");
        let deployments: Vec<Value> = serde_yaml::Deserializer::from_str(&raw)
            .map(|document| Value::deserialize(document).expect("Deployment YAML must parse"))
            .collect();
        let platform_api = deployments
            .iter()
            .find(|deployment| {
                str_at(deployment, &["kind"]) == Some("Deployment")
                    && str_at(deployment, &["metadata", "name"]) == Some("platform-api")
            })
            .expect("platform-api Deployment must remain checked in");

        let mut errors = Vec::new();
        validate_target_update_strategy("platform-api", platform_api, &mut errors);
        assert!(
            errors.is_empty(),
            "checked-in platform-api must retain non-overlapping Recreate: {errors:?}"
        );
    }

    #[test]
    fn security_admission_config_map_entries_are_exact_and_fail_closed() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let raw = fs::read_to_string(root.join("deploy/kubernetes/base/deployments.yaml"))
            .expect("checked-in Deployments must be readable");
        let platform_api = serde_yaml::Deserializer::from_str(&raw)
            .map(|document| Value::deserialize(document).expect("Deployment YAML must parse"))
            .find(|deployment| str_at(deployment, &["metadata", "name"]) == Some("platform-api"))
            .expect("platform-api Deployment must remain checked in");
        let container = platform_api["spec"]["template"]["spec"]["containers"][0].clone();

        let mut baseline_errors = Vec::new();
        validate_container_env("platform-api", 0, &container, &mut baseline_errors);
        assert!(
            baseline_errors.is_empty(),
            "checked-in admission entries must pass: {baseline_errors:?}"
        );

        for key in SECURITY_ADMISSION_KEYS {
            for mutation in ["missing", "wrong ConfigMap", "literal value"] {
                let mut invalid = container.clone();
                let env = invalid["env"]
                    .as_array_mut()
                    .expect("platform-api env must be an array");
                let index = env
                    .iter()
                    .position(|entry| str_at(entry, &["name"]) == Some(*key))
                    .unwrap_or_else(|| panic!("checked-in env must contain {key}"));
                match mutation {
                    "missing" => {
                        env.remove(index);
                    }
                    "wrong ConfigMap" => {
                        env[index]["valueFrom"]["configMapKeyRef"]["name"] =
                            json!("unreviewed-admission-config");
                    }
                    "literal value" => {
                        env[index] = json!({ "name": key, "value": "unreviewed" });
                    }
                    _ => unreachable!(),
                }

                let mut errors = Vec::new();
                validate_container_env("platform-api", 0, &invalid, &mut errors);
                assert!(
                    !errors.is_empty(),
                    "{key} must fail closed when mutated as {mutation}"
                );
            }
        }
    }

    #[test]
    fn checked_in_migration_job_retains_the_one_shot_contract() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let deployments_raw =
            fs::read_to_string(root.join("deploy/kubernetes/base/deployments.yaml"))
                .expect("checked-in Deployments must be readable");
        let platform_api = serde_yaml::Deserializer::from_str(&deployments_raw)
            .map(|document| Value::deserialize(document).expect("Deployment YAML must parse"))
            .find(|deployment| {
                str_at(deployment, &["kind"]) == Some("Deployment")
                    && str_at(deployment, &["metadata", "name"]) == Some("platform-api")
            })
            .expect("platform-api Deployment must remain checked in");
        let job_raw = fs::read_to_string(root.join(MIGRATION_JOB_TEMPLATE_PATH))
            .expect("checked-in operations-only migration Job must be readable");
        let job: Value =
            serde_yaml::from_str(&job_raw).expect("checked-in migration Job YAML must parse");

        let mut errors = Vec::new();
        validate_migration_job(&[platform_api, job], &mut errors);
        assert!(
            errors.is_empty(),
            "checked-in migration Job must retain the reviewed one-shot contract: {errors:?}"
        );
    }

    #[test]
    fn platform_api_config_requires_the_database_flag_exactly_true() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let raw = fs::read_to_string(root.join("deploy/kubernetes/base/configmap.yaml"))
            .expect("checked-in ConfigMaps must be readable");
        let manifests: Vec<Value> = serde_yaml::Deserializer::from_str(&raw)
            .map(|document| Value::deserialize(document).expect("ConfigMap YAML must parse"))
            .collect();

        let mut errors = Vec::new();
        validate_config_maps(&manifests, &mut errors);
        assert!(
            errors.is_empty(),
            "checked-in ConfigMaps should pass: {errors:?}"
        );

        for replacement in [Some(json!("false")), None] {
            let mut invalid = manifests.clone();
            let api = invalid
                .iter_mut()
                .find(|manifest| {
                    str_at(manifest, &["metadata", "name"]) == Some("platform-api-config")
                })
                .expect("platform-api-config");
            let data = api["data"]
                .as_object_mut()
                .expect("platform-api-config data");
            if let Some(value) = replacement {
                data.insert("RYUKI_DATABASE__REQUIRED".to_string(), value);
            } else {
                data.remove("RYUKI_DATABASE__REQUIRED");
            }

            let mut errors = Vec::new();
            validate_config_maps(&invalid, &mut errors);
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("require the database")),
                "false or missing database-required flag must fail closed: {errors:?}"
            );
        }
    }

    #[test]
    fn checked_in_config_maps_reject_unreviewed_env_from_keys() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let raw = fs::read_to_string(root.join("deploy/kubernetes/base/configmap.yaml"))
            .expect("checked-in ConfigMaps must be readable");
        let manifests: Vec<Value> = serde_yaml::Deserializer::from_str(&raw)
            .map(|document| Value::deserialize(document).expect("ConfigMap YAML must parse"))
            .collect();

        for name in EXPECTED_CONFIG_MAPS {
            let mut invalid = manifests.clone();
            let config_map = invalid
                .iter_mut()
                .find(|manifest| str_at(manifest, &["metadata", "name"]) == Some(*name))
                .unwrap_or_else(|| panic!("missing checked-in ConfigMap {name}"));
            config_map["data"]
                .as_object_mut()
                .expect("ConfigMap data")
                .insert("RYUKI_UNREVIEWED_ENV".to_string(), json!("injected"));

            let mut errors = Vec::new();
            validate_config_maps(&invalid, &mut errors);
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("only the exact reviewed keys")),
                "ConfigMap {name} must reject an unreviewed envFrom key: {errors:?}"
            );
        }
    }

    #[test]
    fn checked_in_cutover_contract_binds_config_secret_digest_and_https_path() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(
            !root
                .join("deploy/kubernetes/base/migration-job.yaml")
                .exists(),
            "a continuously reconciled base must not contain the migration Job"
        );

        let mut manifests = Vec::new();
        for relative in [
            "deploy/kubernetes/base/configmap.yaml",
            "deploy/kubernetes/base/deployments.yaml",
            "deploy/kubernetes/base/networkpolicies.yaml",
            MIGRATION_JOB_TEMPLATE_PATH,
        ] {
            let raw = fs::read_to_string(root.join(relative))
                .unwrap_or_else(|error| panic!("{relative} must be readable: {error}"));
            manifests.extend(serde_yaml::Deserializer::from_str(&raw).map(|document| {
                Value::deserialize(document)
                    .unwrap_or_else(|error| panic!("{relative} must parse: {error}"))
            }));
        }
        let contract_raw = fs::read_to_string(root.join(MIGRATION_CUTOVER_CONTRACT_PATH))
            .expect("cutover contract must be readable");
        let contract: Value =
            serde_yaml::from_str(&contract_raw).expect("cutover contract must parse");

        let mut errors = Vec::new();
        validate_config_maps(&manifests, &mut errors);
        validate_migration_job(&manifests, &mut errors);
        validate_cutover_contract(&contract, &manifests, &mut errors);
        let policies: Vec<&Value> = manifests
            .iter()
            .filter(|manifest| str_at(manifest, &["kind"]) == Some("NetworkPolicy"))
            .collect();
        validate_portal_ui_egress(&policies, &mut errors);
        let api = manifests
            .iter()
            .find(|manifest| {
                str_at(manifest, &["kind"]) == Some("Deployment")
                    && str_at(manifest, &["metadata", "name"]) == Some("platform-api")
            })
            .expect("platform-api Deployment must be present");
        let api_container = array_at_path(api, &["spec", "template", "spec", "containers"])[0];
        validate_container_env("platform-api", 0, api_container, &mut errors);

        assert!(
            errors.is_empty(),
            "checked-in cutover objects must retain exact cross-object bindings: {errors:?}"
        );

        for (pointer, replacement) in [
            ("/drain/requiredWorkloadKinds", json!(["Deployment"])),
            ("/drain/requiredBaseWriterSelectors", json!([])),
            (
                "/drain/databaseSessionReadback/fields",
                json!(["pid", "usename"]),
            ),
        ] {
            let mut narrowed = contract.clone();
            *narrowed
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("missing contract pointer {pointer}")) = replacement;
            let mut errors = Vec::new();
            validate_cutover_contract(&narrowed, &manifests, &mut errors);
            assert!(
                errors.iter().any(|error| error.contains("exact nonempty")),
                "narrowed cutover inventory {pointer} must fail closed: {errors:?}"
            );
        }

        for pointer in [
            "/release/digestPrefix",
            "/execution/generatedNamePrefix",
            "/credentials/migration/vaultDynamicSecretName",
            "/credentials/migration/secretName",
            "/credentials/migration/vaultAuthRole",
            "/credentials/migration/vaultDatabaseRole",
        ] {
            let mut stale = contract.clone();
            *stale
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("missing contract pointer {pointer}")) = json!("stale");
            let mut errors = Vec::new();
            validate_cutover_contract(&stale, &manifests, &mut errors);
            assert!(
                !errors.is_empty(),
                "stale digest-scoped contract identity {pointer} must be rejected"
            );
        }
    }

    #[test]
    fn platform_api_hardening_retains_the_recreate_gate() {
        let security_context = json!({
            "runAsNonRoot": true,
            "runAsUser": 10001,
            "runAsGroup": 10001,
            "allowPrivilegeEscalation": false,
            "readOnlyRootFilesystem": true,
            "capabilities": { "drop": ["ALL"] },
            "seccompProfile": { "type": "RuntimeDefault" }
        });
        let mut deployment = hardened_target_deployment("platform-api", security_context);

        let mut errors = Vec::new();
        validate_target_hardening("platform-api", &deployment, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("must use Recreate")),
            "the top-level hardening path must retain the non-overlap gate: {errors:?}"
        );

        deployment["spec"]["strategy"] = json!({ "type": "Recreate" });
        let mut errors = Vec::new();
        validate_target_hardening("platform-api", &deployment, &mut errors);
        assert!(
            !errors.iter().any(|error| error.contains("Recreate")),
            "a valid Recreate strategy must satisfy the retained gate: {errors:?}"
        );
    }

    #[test]
    fn migration_job_is_one_shot_and_coupled_to_the_api_image() {
        let image = format!(
            "registry.example.invalid/ryuki/platform-api@sha256:{}",
            "c".repeat(64)
        );
        let api = json!({
            "kind": "Deployment",
            "metadata": { "name": "platform-api" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{ "name": "platform-api", "image": image }]
                    }
                }
            }
        });
        let job = migration_job_fixture(&image);

        let mut errors = Vec::new();
        validate_migration_job(&[api.clone(), job.clone()], &mut errors);
        assert!(
            errors.is_empty(),
            "reviewed migration Job should pass: {errors:?}"
        );

        let mut retrying = job.clone();
        retrying["spec"]["backoffLimit"] = json!(1);
        let mut errors = Vec::new();
        validate_migration_job(&[api.clone(), retrying], &mut errors);
        assert!(errors.iter().any(|error| error.contains("exactly once")));

        for (field, value) in [
            (
                "podFailurePolicy",
                json!({
                    "rules": [{
                        "action": "Ignore",
                        "onExitCodes": {
                            "containerName": MIGRATION_JOB,
                            "operator": "In",
                            "values": [1]
                        }
                    }]
                }),
            ),
            ("podReplacementPolicy", json!("Failed")),
            ("backoffLimitPerIndex", json!(0)),
        ] {
            let mut policy_extended = job.clone();
            policy_extended["spec"][field] = value;
            let mut errors = Vec::new();
            validate_migration_job(&[api.clone(), policy_extended], &mut errors);
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("retry/replacement")),
                "retry-affecting Job field {field} must be rejected: {errors:?}"
            );
        }

        let mut stale_identity = job.clone();
        stale_identity["metadata"]["generateName"] = json!("platform-api-migrations-111111111111-");
        let mut errors = Vec::new();
        validate_migration_job(&[api.clone(), stale_identity], &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("derived")),
            "a stale release identity must not survive an admitted digest change: {errors:?}"
        );

        let mut missing_ca = job.clone();
        missing_ca["spec"]["template"]["spec"]["volumes"] = json!([]);
        let mut errors = Vec::new();
        validate_migration_job(&[api.clone(), missing_ca], &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("CNPG CA")),
            "the migration client must retain its authenticated CA mount: {errors:?}"
        );

        let mut custom_command = job.clone();
        custom_command["spec"]["template"]["spec"]["containers"][0]["args"] = json!(["migrate"]);
        let mut errors = Vec::new();
        validate_migration_job(&[api.clone(), custom_command], &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("must not define args")));

        let mut different_image = job;
        different_image["spec"]["template"]["spec"]["containers"][0]["image"] = format!(
            "registry.example.invalid/ryuki/platform-api@sha256:{}",
            "d".repeat(64)
        )
        .into();
        let mut errors = Vec::new();
        validate_migration_job(&[api, different_image], &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("exact digest-only platform-api")));
    }

    fn migration_job_fixture(image: &str) -> Value {
        let identity = MigrationIdentity::from_image(image)
            .expect("test image must produce a migration identity");
        json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "generateName": identity.job_generate_name,
                "annotations": {
                    "ryuki.io/cutover-contract": "migration-cutover-v1",
                    "ryuki.io/release-image": image
                },
                "labels": {
                    "ryuki.io/release-digest-prefix": identity.digest_prefix
                }
            },
            "spec": {
                "completions": 1,
                "parallelism": 1,
                "backoffLimit": 0,
                "activeDeadlineSeconds": 2400,
                "template": {
                    "metadata": {
                        "labels": {
                            "app.kubernetes.io/name": MIGRATION_JOB,
                            "app.kubernetes.io/component": "database-migration-runner",
                            "ryuki.io/release-digest-prefix": identity.digest_prefix
                        }
                    },
                    "spec": {
                        "serviceAccountName": MIGRATION_SERVICE_ACCOUNT,
                        "automountServiceAccountToken": false,
                        "enableServiceLinks": false,
                        "restartPolicy": "Never",
                        "terminationGracePeriodSeconds": 30,
                        "volumes": [{
                            "name": CNPG_CA_VOLUME_NAME,
                            "secret": {
                                "secretName": CNPG_CA_SECRET_NAME,
                                "items": [{
                                    "key": CNPG_CA_SECRET_KEY,
                                    "path": CNPG_CA_SECRET_KEY
                                }]
                            }
                        }],
                        "securityContext": {
                            "runAsNonRoot": true,
                            "runAsUser": 10001,
                            "runAsGroup": 10001,
                            "seccompProfile": { "type": "RuntimeDefault" }
                        },
                        "containers": [{
                            "name": MIGRATION_JOB,
                            "image": image,
                            "imagePullPolicy": "IfNotPresent",
                            "volumeMounts": [{
                                "name": CNPG_CA_VOLUME_NAME,
                                "mountPath": CNPG_CA_MOUNT_PATH,
                                "readOnly": true
                            }],
                            "envFrom": [
                                {
                                    "configMapRef": {
                                        "name": "platform-api-migration-config"
                                    }
                                }
                            ],
                            "env": [
                                {
                                    "name": "RYUKI_MIGRATION_DATABASE_URL",
                                    "valueFrom": {
                                        "secretKeyRef": {
                                            "name": identity.secret_name,
                                            "key": "RYUKI_MIGRATION_DATABASE_URL"
                                        }
                                    }
                                },
                                {
                                    "name": "RYUKI_SECURITY_CONTRACT_ROOT",
                                    "valueFrom": { "configMapKeyRef": {
                                        "name": SECURITY_ADMISSION_CONFIG_MAP,
                                        "key": "RYUKI_SECURITY_CONTRACT_ROOT"
                                    }}
                                },
                                {
                                    "name": "RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH",
                                    "valueFrom": { "configMapKeyRef": {
                                        "name": SECURITY_ADMISSION_CONFIG_MAP,
                                        "key": "RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH"
                                    }}
                                },
                                {
                                    "name": "RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST",
                                    "valueFrom": { "configMapKeyRef": {
                                        "name": SECURITY_ADMISSION_CONFIG_MAP,
                                        "key": "RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST"
                                    }}
                                },
                                {
                                    "name": "RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH",
                                    "valueFrom": { "configMapKeyRef": {
                                        "name": SECURITY_ADMISSION_CONFIG_MAP,
                                        "key": "RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH"
                                    }}
                                },
                                {
                                    "name": "RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST",
                                    "valueFrom": { "configMapKeyRef": {
                                        "name": SECURITY_ADMISSION_CONFIG_MAP,
                                        "key": "RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST"
                                    }}
                                },
                                {
                                    "name": "RYUKI_EXPECTED_DEPLOYMENT_ID",
                                    "valueFrom": { "configMapKeyRef": {
                                        "name": SECURITY_ADMISSION_CONFIG_MAP,
                                        "key": "RYUKI_EXPECTED_DEPLOYMENT_ID"
                                    }}
                                },
                                {
                                    "name": "RYUKI_SECURITY_PROFILE",
                                    "valueFrom": { "configMapKeyRef": {
                                        "name": SECURITY_ADMISSION_CONFIG_MAP,
                                        "key": "RYUKI_SECURITY_PROFILE"
                                    }}
                                }
                            ],
                            "resources": {
                                "requests": { "cpu": "100m", "memory": "128Mi" },
                                "limits": { "cpu": "1", "memory": "512Mi" }
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
                        }]
                    }
                }
            }
        })
    }

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
