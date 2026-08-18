use crate::yaml_utils::validate_yaml_duplicate_keys_text;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use ryuki_core::conformance_trust::canonical_json_bytes;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

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
const POSTGRESQL_RELAY_VOLUME_NAME: &str = "postgresql-relay-workspace";
const POSTGRESQL_RELAY_MOUNT_PATH: &str = "/run/ryuki-postgresql-relay";
const POSTGRESQL_RELAY_SIZE_LIMIT: &str = "1Mi";
const FINAL_RENDER_CONTRACT: &str = "migration-final-render-v1";
const SOURCE_TEMPLATE_MODE: &str = "source-template";
const FINAL_RENDER_MODE: &str = "final-render";
const FINAL_RENDER_REQUIRED_RUNTIME_CAPABILITY: &str =
    "in-cluster-final-render-admission-and-runtime-freshness-v1";
const FINAL_RENDER_RUNTIME_ADMISSION_UNAVAILABLE_ERROR: &str = "final-render production execution is disabled: in-cluster-final-render-admission-and-runtime-freshness-v1 is unavailable; offline snapshot validation cannot fence ConfigMap deletion/recreation through Pod materialization, consume a one-shot execution attempt, or enforce receipt expiry at Pod start and runtime";
const MANIFEST_SELECTED_TRUST_ANCHOR_FORBIDDEN_ERROR: &str = "production Kubernetes validation does not accept a manifest-selected socket-projection trust anchor; the required in-cluster admission capability must receive an independently provisioned anchor outside the render request";
const RENDER_REQUIRED_SENTINEL: &str = "RENDER_REQUIRED";
const SOCKET_CONTRACT_DIGEST: &str =
    "sha256:369bca5b159d7535a2b3523796ff3632e9e7ca44f9a94b4140cc572163767697";
const RELEASE_DIGEST_PREFIX_ANNOTATION: &str = "ryuki.io/release-digest-prefix";
const CONTENT_DIGEST_ANNOTATION: &str = "ryuki.io/content-digest";
const RENDER_CONTRACT_ANNOTATION: &str = "ryuki.io/render-contract";
const RENDER_MODE_ANNOTATION: &str = "ryuki.io/render-mode";
const SOCKET_PROJECTION_RECEIPT_DIGEST_ANNOTATION: &str =
    "ryuki.io/socket-projection-receipt-digest";
const SOCKET_CONTRACT_DIGEST_ANNOTATION: &str = "ryuki.io/socket-contract-digest";
const SOCKET_PROJECTION_RECEIPT_RAW_DIGEST_ANNOTATION: &str =
    "ryuki.io/socket-projection-receipt-raw-digest";
const SOCKET_PROJECTION_RECEIPT_CONTRACT: &str = "migration-socket-projection-receipt-v1";
const SOCKET_PROJECTION_TRUST_ANCHOR_CONTRACT: &str = "migration-socket-projection-trust-anchor-v1";
const SOCKET_PROJECTION_SIGNATURE_DOMAIN: &str = "ryuki-v1/migration-socket-projection-receipt";
const SOCKET_PROJECTION_RECEIPT_CONFIG_MAP_PREFIX: &str = "platform-socket-projection-receipt-";
const SOCKET_PROJECTION_RECEIPT_DATA_KEY: &str = "receipt.json";
const SOCKET_PROJECTION_MAX_RECEIPT_BYTES: usize = 64 * 1024;
const SOCKET_PROJECTION_MAX_AUTHORIZATION_SECONDS: i64 = 300;
const AUTHORITY_SOCKET_CSI_DRIVER: &str = "authority-socket-projection.ryuki.io";
const AUTHORITY_SOCKET_CSI_ATTRIBUTE_KEYS: &[&str] =
    &["environmentVariable", "authorityClass", "socketPath"];
const MIGRATION_JOB_RYUKI_ANNOTATIONS: &[&str] = &[
    "ryuki.io/cutover-contract",
    "ryuki.io/release-image",
    RENDER_CONTRACT_ANNOTATION,
    RENDER_MODE_ANNOTATION,
    "ryuki.io/pin-migration-config-receipt",
    "ryuki.io/pin-security-admission-receipt",
    "ryuki.io/pin-production-build-manifest-receipt",
    "ryuki.io/pin-conformance-trust-checkpoint-receipt",
    "ryuki.io/pin-deployed-workload-attestation-receipt",
    "ryuki.io/pin-public-ingress-attestation-receipt",
    "ryuki.io/pin-postgresql-infrastructure-attestation-receipt",
    "ryuki.io/pin-first-owner-authority-receipt",
    "ryuki.io/pin-socket-projection-authority-receipt",
    SOCKET_PROJECTION_RECEIPT_DIGEST_ANNOTATION,
    SOCKET_CONTRACT_DIGEST_ANNOTATION,
];
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
const MIGRATION_APP_PIN_GROUPS: &[(&str, &[&str], &str)] = &[
    (
        SECURITY_ADMISSION_CONFIG_MAP,
        SECURITY_ADMISSION_KEYS,
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
const MIGRATION_RENDER_PIN_GROUPS: &[(&str, &[&str], &str)] = &[
    (
        "platform-api-migration-config",
        PLATFORM_API_MIGRATION_CONFIG_KEYS,
        "ryuki.io/pin-migration-config-receipt",
    ),
    (
        SECURITY_ADMISSION_CONFIG_MAP,
        SECURITY_ADMISSION_KEYS,
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
    (
        SOCKET_PROJECTION_AUTHORITY_CONFIG_MAP,
        SOCKET_PROJECTION_AUTHORITY_KEYS,
        "ryuki.io/pin-socket-projection-authority-receipt",
    ),
];
const MIGRATION_AUTHORITY_SOCKET_PROJECTIONS: &[(&str, &str, &str, &str, &str, &str, &str)] = &[
    (
        CONFORMANCE_TRUST_CHECKPOINT_CONFIG_MAP,
        "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_SOCKET",
        "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID",
        "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_KEY_ID",
        "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT",
        "conformance-trust-checkpoint-socket",
        "conformance-trust-checkpoint",
    ),
    (
        DEPLOYED_WORKLOAD_ATTESTATION_CONFIG_MAP,
        "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_SOCKET",
        "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_AUTHORITY_ID",
        "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_KEY_ID",
        "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT",
        "deployed-workload-attestation-socket",
        "deployed-workload-attestation",
    ),
    (
        PUBLIC_INGRESS_ATTESTATION_CONFIG_MAP,
        "RYUKI_PUBLIC_INGRESS_ATTESTATION_SOCKET",
        "RYUKI_PUBLIC_INGRESS_ATTESTATION_AUTHORITY_ID",
        "RYUKI_PUBLIC_INGRESS_ATTESTATION_KEY_ID",
        "RYUKI_PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT",
        "public-ingress-attestation-socket",
        "public-ingress-attestation",
    ),
    (
        POSTGRESQL_INFRASTRUCTURE_ATTESTATION_CONFIG_MAP,
        "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET",
        "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID",
        "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID",
        "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT",
        "postgresql-infrastructure-attestation-socket",
        "postgresql-infrastructure-attestation",
    ),
];
const MIGRATION_JOB_ENV_COUNT: usize = 1
    + SECURITY_ADMISSION_KEYS.len()
    + PRODUCTION_BUILD_MANIFEST_KEYS.len()
    + CONFORMANCE_TRUST_CHECKPOINT_KEYS.len()
    + DEPLOYED_WORKLOAD_ATTESTATION_KEYS.len()
    + PUBLIC_INGRESS_ATTESTATION_KEYS.len()
    + POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEYS.len()
    + FIRST_OWNER_AUTHORITY_KEYS.len();
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
    "ryuki.io/socket-projection-receipt-raw-digest",
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

#[derive(Debug, Clone)]
struct SocketProjectionTrustAnchor {
    authority_id: String,
    key_id: String,
    public_key: [u8; 32],
    public_key_base64: String,
    public_key_fingerprint: String,
    min_authority_epoch: u64,
    profile_id: String,
    profile_version: u64,
    profile_digest: String,
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
    #[serde(default, rename = "socketProjectionTrustAnchorPath")]
    untrusted_socket_projection_trust_anchor_path: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct DocumentsInput {
    manifests: Vec<Value>,
    #[serde(default, rename = "socketProjectionTrustAnchor")]
    untrusted_socket_projection_trust_anchor: Option<Value>,
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
    let mut errors = validate_documents(&context.manifests, None);
    if context
        .untrusted_socket_projection_trust_anchor_path
        .is_some()
    {
        errors.push(MANIFEST_SELECTED_TRUST_ANCHOR_FORBIDDEN_ERROR.to_string());
    }
    validate_cutover_contract(&context.cutover_contract, &context.manifests, &mut errors);
    validate_vault_external_auth_files(&context.source_texts, &mut errors);
    validate_source_texts(&context.source_texts, &mut errors);
    Ok(errors)
}

pub fn validate_values_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocumentsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid kubernetes manifest documents JSON: {error}"))?;
    let mut errors = validate_documents(&payload.manifests, None);
    if payload.untrusted_socket_projection_trust_anchor.is_some() {
        errors.push(MANIFEST_SELECTED_TRUST_ANCHOR_FORBIDDEN_ERROR.to_string());
    }
    Ok(errors)
}

/// Validate the deterministic post-publication release render against the
/// exact image digests returned by the two build-push steps. This mode is
/// intentionally stronger than source-template validation: fixture registries
/// and placeholder digests are useful in the checked-in base, but are never
/// admissible in a release artifact.
pub fn validate_release_image_render_file(
    path: &Path,
    expected_api_digest: &str,
    expected_portal_digest: &str,
) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut errors = Vec::new();
    validate_yaml_duplicate_keys_text(&payload, &path.display().to_string(), &mut errors);

    let documents = serde_yaml::Deserializer::from_str(&payload)
        .map(Value::deserialize)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("invalid release Kubernetes image render YAML: {error}"))?;
    expect(
        documents.iter().all(Value::is_object),
        &mut errors,
        "release Kubernetes image render must contain only mapping documents",
    );
    let manifests = documents
        .into_iter()
        .filter(Value::is_object)
        .collect::<Vec<_>>();

    errors.extend(validate_documents(&manifests, None));
    validate_release_image_binding(
        &manifests,
        expected_api_digest,
        expected_portal_digest,
        &mut errors,
    );
    Ok(errors)
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

fn validate_documents(
    manifests: &[Value],
    socket_projection_trust_anchor: Option<&Value>,
) -> Vec<String> {
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
    validate_migration_job(manifests, socket_projection_trust_anchor, &mut errors);
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

fn validate_release_image_binding(
    manifests: &[Value],
    expected_api_digest: &str,
    expected_portal_digest: &str,
    errors: &mut Vec<String>,
) {
    let expected_api_digest =
        validate_expected_release_digest("platform-api", expected_api_digest, errors);
    let expected_portal_digest =
        validate_expected_release_digest("portal-ui", expected_portal_digest, errors);
    if expected_api_digest.is_some() && expected_api_digest == expected_portal_digest {
        errors.push(
            "expected published platform-api and portal-ui digests must be distinct".to_string(),
        );
    }

    for (component, expected_digest) in [
        ("platform-api", expected_api_digest),
        ("portal-ui", expected_portal_digest),
    ] {
        let matching_deployments = manifests
            .iter()
            .filter(|manifest| {
                str_at(manifest, &["kind"]) == Some("Deployment")
                    && str_at(manifest, &["metadata", "name"]) == Some(component)
            })
            .collect::<Vec<_>>();
        let images = matching_deployments
            .first()
            .map(|deployment| {
                array_at_path(deployment, &["spec", "template", "spec", "containers"])
                    .iter()
                    .filter(|container| str_at(container, &["name"]) == Some(component))
                    .filter_map(|container| str_at(container, &["image"]))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        expect(
            matching_deployments.len() == 1 && images.len() == 1,
            errors,
            format!(
                "release Kubernetes image render must contain exactly one {component} Deployment with one same-named image"
            ),
        );
        let Some(image) = images.first().copied() else {
            continue;
        };
        expect(
            is_qualified_immutable_image(image),
            errors,
            format!(
                "release Kubernetes image render {component} image must be a qualified digest-only image reference"
            ),
        );
        expect(
            !image_uses_reserved_registry(image),
            errors,
            format!(
                "release Kubernetes image render {component} image must not use reserved registry.example.invalid"
            ),
        );

        let actual_digest = immutable_image_digest(image);
        expect(
            actual_digest.is_some_and(|digest| !is_release_digest_sentinel(digest)),
            errors,
            format!(
                "release Kubernetes image render {component} image must not use a zero or source-template sentinel digest"
            ),
        );
        if let Some(expected_digest) = expected_digest {
            expect(
                actual_digest == Some(expected_digest),
                errors,
                format!(
                    "release Kubernetes image render {component} image digest must equal the exact published digest sha256:{expected_digest}"
                ),
            );
        }
    }
}

fn validate_expected_release_digest<'a>(
    component: &str,
    digest: &'a str,
    errors: &mut Vec<String>,
) -> Option<&'a str> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        errors.push(format!(
            "expected published {component} digest is missing or malformed"
        ));
        return None;
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || is_release_digest_sentinel(hex)
    {
        errors.push(format!(
            "expected published {component} digest must be a non-sentinel sha256 digest with 64 lowercase hexadecimal characters"
        ));
        return None;
    }
    Some(hex)
}

fn image_uses_reserved_registry(image: &str) -> bool {
    image.split_once('/').is_some_and(|(registry, _)| {
        registry
            .split_once(':')
            .map(|(host, _)| host)
            .unwrap_or(registry)
            == "registry.example.invalid"
    })
}

fn is_release_digest_sentinel(digest: &str) -> bool {
    digest.bytes().all(|byte| byte == b'0') || digest.bytes().all(|byte| byte == b'1')
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
    let job = manifests
        .iter()
        .find(|manifest| str_at(manifest, &["kind"]) == Some("Job"));
    let final_render = job.is_some_and(|job| {
        str_at(job, &["metadata", "annotations", RENDER_MODE_ANNOTATION]) == Some(FINAL_RENDER_MODE)
    });
    let release_identity = job
        .and_then(|job| str_at(job, &["metadata", "annotations", "ryuki.io/release-image"]))
        .and_then(MigrationIdentity::from_image);
    let mut expected_names: Vec<String> = EXPECTED_CONFIG_MAPS
        .iter()
        .filter(|name| !final_render || **name != "platform-api-migration-config")
        .map(|name| (*name).to_string())
        .collect();
    if final_render {
        if let Some(identity) = &release_identity {
            expected_names.extend(MIGRATION_RENDER_PIN_GROUPS.iter().map(|(base_name, _, _)| {
                digest_scoped_pin_config_map_name(base_name, &identity.digest_prefix)
            }));
            if let Some(receipt_name) = job
                .and_then(|job| {
                    str_at(
                        job,
                        &[
                            "metadata",
                            "annotations",
                            SOCKET_PROJECTION_RECEIPT_DIGEST_ANNOTATION,
                        ],
                    )
                })
                .and_then(socket_projection_receipt_config_map_name)
            {
                expected_names.push(receipt_name);
            }
        }
    }
    let expected_name_refs: Vec<&str> = expected_names.iter().map(String::as_str).collect();
    push_diff_error(&expected_name_refs, &names, errors, "missing ConfigMaps");
    push_unexpected_error(&names, &expected_name_refs, errors, "unexpected ConfigMaps");

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

    let migration_config_name = if final_render {
        release_identity
            .as_ref()
            .map(|identity| {
                digest_scoped_pin_config_map_name(
                    "platform-api-migration-config",
                    &identity.digest_prefix,
                )
            })
            .unwrap_or_default()
    } else {
        "platform-api-migration-config".to_string()
    };
    let migration = find(&migration_config_name);
    let migration_data = object_at(migration, &["data"]);
    expect(
        migration_data
            .is_some_and(|data| object_has_exact_keys(data, PLATFORM_API_MIGRATION_CONFIG_KEYS))
            && str_at(migration, &["data", "RYUKI_MIGRATION_MODE"]) == Some("apply-only")
            && str_at(
                migration,
                &["data", "RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS"],
            ) == Some("180")
            && str_at(migration, &["data", "RYUKI_MIGRATION_LOCK_TIMEOUT_SECS"]) == Some("30")
            && str_at(migration, &["data", "RYUKI_MIGRATION_EXPECTED_ROLE"])
                == Some("ryuki_schema_migrator")
            && str_at(migration, &["data", "RYUKI_APPLICATION_DATABASE_ROLE"])
                == Some("ryuki_app_runtime"),
        errors,
        "platform-api-migration-config must contain only the exact reviewed keys with apply-only mode, 180/30 timeouts inside the 300-second proof lifetime, and exact migrator/application roles",
    );

    let portal = find("portal-ui-config");
    let expected_origin = format!("https://{APPROVED_HOST}");
    expect(
        object_at(portal, &["data"])
            .is_some_and(|data| object_has_exact_keys(data, PORTAL_UI_CONFIG_KEYS))
            && str_at(portal, &["data", "RYUKI_API_URL"]) == Some(expected_origin.as_str())
            && str_at(portal, &["data", "RYUKI_PORTAL_PUBLIC_ORIGIN"])
                == Some(expected_origin.as_str())
            && str_at(portal, &["data", "RYUKI_PORTAL_EXECUTION_MODE"]) == Some("live-provider")
            && str_at(portal, &["data", "RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK"]) == Some("false"),
        errors,
        "portal-ui-config must contain only the exact reviewed keys, use live-provider mode, and use the exact HTTPS ingress origin with insecure-loopback disabled",
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

fn validate_migration_job(
    manifests: &[Value],
    socket_projection_trust_anchor: Option<&Value>,
    errors: &mut Vec<String>,
) {
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
                    "suspend",
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
        int_at(job, &["spec", "activeDeadlineSeconds"]) == Some(300)
            && value_at(job, &["spec", "ttlSecondsAfterFinished"]).is_none(),
        errors,
        "migration Job must use the proof-bounded 300-second deadline and forbid automatic TTL deletion/recreation",
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
        object(pod_security).is_some_and(|security| {
            object_has_exact_keys(
                security,
                &[
                    "runAsNonRoot",
                    "runAsUser",
                    "runAsGroup",
                    "fsGroup",
                    "fsGroupChangePolicy",
                    "seccompProfile",
                ],
            )
        }) && bool_at(pod_security, &["runAsNonRoot"]) == Some(true)
            && int_at(pod_security, &["runAsUser"]) == Some(10001)
            && int_at(pod_security, &["runAsGroup"]) == Some(10001)
            && int_at(pod_security, &["fsGroup"]) == Some(10001)
            && str_at(pod_security, &["fsGroupChangePolicy"]) == Some("OnRootMismatch")
            && str_at(pod_security, &["seccompProfile", "type"]) == Some("RuntimeDefault"),
        errors,
        "migration Job pod must use the reviewed non-root identity, relay workspace group, and RuntimeDefault seccomp",
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
    validate_migration_render_binding(
        manifests,
        job,
        migration_identity.as_ref(),
        socket_projection_trust_anchor,
        errors,
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
    let migration_config_name = if str_at(job, &["metadata", "annotations", RENDER_MODE_ANNOTATION])
        == Some(FINAL_RENDER_MODE)
    {
        migration_identity.as_ref().map(|identity| {
            digest_scoped_pin_config_map_name(
                "platform-api-migration-config",
                &identity.digest_prefix,
            )
        })
    } else {
        Some("platform-api-migration-config".to_string())
    };
    let exact_config_ref = env_from.iter().any(|entry| {
        object(entry).is_some_and(|map| map.len() == 1)
            && object_at(entry, &["configMapRef"]).is_some_and(|reference| {
                reference.len() == 1
                    && str_at(entry, &["configMapRef", "name"]) == migration_config_name.as_deref()
            })
    });
    expect(
        env_from.len() == 1
            && exact_config_ref
            && env_from
                .iter()
                .all(|entry| value_at(entry, &["secretRef"]).is_none()),
        errors,
        "migration Job envFrom must contain only the source or immutable digest-scoped migration ConfigMap required by its render mode and no whole-Secret import",
    );
    let env = array_at_path(container, &["env"]);
    let migration_url = env.first().copied().unwrap_or(&Value::Null);
    expect(
        env.len() == MIGRATION_JOB_ENV_COUNT
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
        "migration Job must import the digest-scoped migrator URL key plus all 50 production pin keys",
    );
    expect(
        migration_identity.as_ref().is_some_and(|identity| {
            env.get(1..).is_some_and(|entries| {
                exact_migration_production_pin_env_entries(entries, &identity.digest_prefix)
            })
        }),
        errors,
        "migration Job must import the exact ordered, unique production pin keys from their independently governed ConfigMaps",
    );

    let expected_volume_count = if str_at(job, &["metadata", "annotations", RENDER_MODE_ANNOTATION])
        == Some(FINAL_RENDER_MODE)
    {
        2 + MIGRATION_AUTHORITY_SOCKET_PROJECTIONS.len()
    } else {
        2
    };
    validate_cnpg_ca_mount(
        "migration Job",
        pod_spec,
        container,
        expected_volume_count,
        errors,
    );
    validate_migration_relay_workspace(pod_spec, container, errors);
    validate_migration_job_resources(container, errors);
    validate_migration_job_security(container, errors);
}

fn validate_migration_render_binding(
    manifests: &[Value],
    job: &Value,
    migration_identity: Option<&MigrationIdentity>,
    socket_projection_trust_anchor: Option<&Value>,
    errors: &mut Vec<String>,
) {
    let annotations = object_at(job, &["metadata", "annotations"]);
    expect(
        annotations.is_some_and(|annotations| {
            let ryuki_annotations: Vec<&str> = annotations
                .keys()
                .filter(|key| key.starts_with("ryuki.io/"))
                .map(String::as_str)
                .collect();
            ryuki_annotations.len() == MIGRATION_JOB_RYUKI_ANNOTATIONS.len()
                && MIGRATION_JOB_RYUKI_ANNOTATIONS
                    .iter()
                    .all(|expected| ryuki_annotations.contains(expected))
                && str_at(
                    job,
                    &["metadata", "annotations", RENDER_CONTRACT_ANNOTATION],
                ) == Some(FINAL_RENDER_CONTRACT)
                && str_at(
                    job,
                    &["metadata", "annotations", SOCKET_CONTRACT_DIGEST_ANNOTATION],
                ) == Some(SOCKET_CONTRACT_DIGEST)
        }),
        errors,
        "migration Job must bind the exact final-render and closed socket-projection contracts",
    );

    match str_at(job, &["metadata", "annotations", RENDER_MODE_ANNOTATION]) {
        Some(SOURCE_TEMPLATE_MODE) => {
            let pin_receipts_are_unresolved =
                MIGRATION_RENDER_PIN_GROUPS
                    .iter()
                    .all(|(_, _, annotation)| {
                        str_at(job, &["metadata", "annotations", annotation])
                            == Some(RENDER_REQUIRED_SENTINEL)
                    });
            let socket_receipts_are_unresolved = str_at(
                job,
                &[
                    "metadata",
                    "annotations",
                    SOCKET_PROJECTION_RECEIPT_DIGEST_ANNOTATION,
                ],
            ) == Some(RENDER_REQUIRED_SENTINEL);
            expect(
                pin_receipts_are_unresolved
                    && socket_receipts_are_unresolved
                    && bool_at(job, &["spec", "suspend"]) == Some(true),
                errors,
                "source-template migration Job must remain suspended and retain every RENDER_REQUIRED receipt sentinel; no final render is currently executable",
            );
        }
        Some(FINAL_RENDER_MODE) => {
            // Offline validation cannot close the time-of-check/time-of-use
            // boundary. Keep this unconditional until the named in-cluster
            // admission and runtime capability is implemented and reviewed.
            errors.push(FINAL_RENDER_RUNTIME_ADMISSION_UNAVAILABLE_ERROR.to_string());
            expect(
                annotations.is_some_and(|annotations| {
                    !annotations
                        .values()
                        .any(|value| value.as_str() == Some(RENDER_REQUIRED_SENTINEL))
                }) && bool_at(job, &["spec", "suspend"]) == Some(false),
                errors,
                "final-render migration Job must resolve every RENDER_REQUIRED sentinel and explicitly clear source suspension",
            );
            validate_final_render_pin_config_maps(manifests, job, migration_identity, errors);
            validate_final_render_socket_receipt(
                manifests,
                job,
                migration_identity,
                socket_projection_trust_anchor,
                errors,
            );
            validate_final_render_socket_projections(manifests, job, migration_identity, errors);
        }
        _ => expect(
            false,
            errors,
            "migration Job render mode must be exactly source-template or final-render",
        ),
    }
}

fn validate_final_render_pin_config_maps(
    manifests: &[Value],
    job: &Value,
    migration_identity: Option<&MigrationIdentity>,
    errors: &mut Vec<String>,
) {
    let Some(identity) = migration_identity else {
        errors.push(
            "final-render migration Job requires one valid release image identity".to_string(),
        );
        return;
    };

    for (base_name, expected_keys, receipt_annotation) in MIGRATION_RENDER_PIN_GROUPS {
        let expected_name = digest_scoped_pin_config_map_name(base_name, &identity.digest_prefix);
        let matching: Vec<&Value> = manifests
            .iter()
            .filter(|manifest| {
                str_at(manifest, &["kind"]) == Some("ConfigMap")
                    && str_at(manifest, &["metadata", "name"]) == Some(expected_name.as_str())
            })
            .collect();
        let config_map = matching.first().copied().unwrap_or(&Value::Null);
        let data = object_at(config_map, &["data"]);
        let content_digest = data.and_then(canonical_config_map_data_digest);
        let uid = str_at(config_map, &["metadata", "uid"]);
        let resource_version = str_at(config_map, &["metadata", "resourceVersion"]);
        let annotation_digest = str_at(
            config_map,
            &["metadata", "annotations", CONTENT_DIGEST_ANNOTATION],
        );
        let expected_receipt = match (&content_digest, uid, resource_version) {
            (Some(content_digest), Some(uid), Some(resource_version)) => Some(format!(
                "{{\"configMapName\":\"{expected_name}\",\"uid\":\"{uid}\",\"resourceVersion\":\"{resource_version}\",\"contentDigest\":\"{content_digest}\"}}"
            )),
            _ => None,
        };
        let semantic_values_are_valid = *base_name != FIRST_OWNER_AUTHORITY_CONFIG_MAP
            || data.is_some_and(|data| {
                data.get("RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_PATH")
                    .and_then(Value::as_str)
                    .is_some_and(is_normalized_absolute_json_path)
                    && data
                        .get("RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST")
                        .and_then(Value::as_str)
                        .is_some_and(is_nonzero_sha256_digest)
            });

        expect(
            matching.len() == 1
                && bool_at(config_map, &["immutable"]) == Some(true)
                && value_at(config_map, &["binaryData"]).is_none()
                && data.is_some_and(|data| object_has_exact_keys(data, expected_keys))
                && data.is_some_and(|data| {
                    data.values().all(|value| {
                        value.as_str().is_some_and(|value| {
                            value != RENDER_REQUIRED_SENTINEL && !value.is_empty()
                        })
                    })
                })
                && str_at(
                    config_map,
                    &["metadata", "annotations", RELEASE_DIGEST_PREFIX_ANNOTATION],
                ) == Some(identity.digest_prefix.as_str())
                && content_digest.as_deref() == annotation_digest
                && uid.is_some_and(is_canonical_kubernetes_uid)
                && resource_version.is_some_and(is_canonical_resource_version)
                && expected_receipt.as_deref()
                    == str_at(job, &["metadata", "annotations", receipt_annotation])
                && semantic_values_are_valid,
            errors,
            format!(
                "final-render migration Job must bind immutable ConfigMap {expected_name} by exact keys, semantic pin values, canonical content digest, UID, resourceVersion, and receipt annotation"
            ),
        );
    }
}

fn validate_final_render_socket_receipt(
    manifests: &[Value],
    job: &Value,
    migration_identity: Option<&MigrationIdentity>,
    trust_anchor: Option<&Value>,
    errors: &mut Vec<String>,
) {
    if let Err(error) =
        validate_final_render_socket_receipt_inner(manifests, job, migration_identity, trust_anchor)
    {
        errors.push(format!(
            "final-render socket-projection receipt verification failed: {error}"
        ));
    }
}

fn validate_final_render_socket_receipt_inner(
    manifests: &[Value],
    job: &Value,
    migration_identity: Option<&MigrationIdentity>,
    trust_anchor: Option<&Value>,
) -> Result<(), String> {
    let identity = migration_identity
        .ok_or_else(|| "release image identity is missing or invalid".to_string())?;
    let anchor = parse_socket_projection_trust_anchor(trust_anchor.ok_or_else(|| {
        "diagnostic receipt verification has no injected test trust anchor; production trust-anchor inputs are forbidden until runtime admission exists"
            .to_string()
    })?)?;
    let authority_config_map_name = digest_scoped_pin_config_map_name(
        SOCKET_PROJECTION_AUTHORITY_CONFIG_MAP,
        &identity.digest_prefix,
    );
    let authority_config_map = exactly_one_named_config_map(manifests, &authority_config_map_name)?;
    let min_authority_epoch = anchor.min_authority_epoch.to_string();
    let profile_version = anchor.profile_version.to_string();
    let expected_authority_data = [
        (
            SOCKET_PROJECTION_AUTHORITY_KEYS[0],
            anchor.authority_id.as_str(),
        ),
        (SOCKET_PROJECTION_AUTHORITY_KEYS[1], anchor.key_id.as_str()),
        (
            SOCKET_PROJECTION_AUTHORITY_KEYS[2],
            anchor.public_key_base64.as_str(),
        ),
        (
            SOCKET_PROJECTION_AUTHORITY_KEYS[3],
            anchor.public_key_fingerprint.as_str(),
        ),
        (
            SOCKET_PROJECTION_AUTHORITY_KEYS[4],
            min_authority_epoch.as_str(),
        ),
        (
            SOCKET_PROJECTION_AUTHORITY_KEYS[5],
            anchor.profile_id.as_str(),
        ),
        (
            SOCKET_PROJECTION_AUTHORITY_KEYS[6],
            profile_version.as_str(),
        ),
        (
            SOCKET_PROJECTION_AUTHORITY_KEYS[7],
            anchor.profile_digest.as_str(),
        ),
    ];
    if !expected_authority_data
        .iter()
        .all(|(key, expected)| str_at(authority_config_map, &["data", key]) == Some(*expected))
    {
        return Err(
            "manifest socket-projection authority pins do not exactly match the independent trust anchor"
                .to_string(),
        );
    }

    let receipt_digest = str_at(
        job,
        &[
            "metadata",
            "annotations",
            SOCKET_PROJECTION_RECEIPT_DIGEST_ANNOTATION,
        ],
    )
    .filter(|value| is_nonzero_sha256_digest(value))
    .ok_or_else(|| "Job receipt digest annotation is missing or invalid".to_string())?;
    let receipt_config_map_name = socket_projection_receipt_config_map_name(receipt_digest)
        .ok_or_else(|| "Job receipt digest cannot form the content-addressed name".to_string())?;
    let receipt_config_map = exactly_one_named_config_map(manifests, &receipt_config_map_name)?;
    let data = object_at(receipt_config_map, &["data"])
        .ok_or_else(|| "receipt ConfigMap data is missing".to_string())?;
    if !object_has_exact_keys(data, &[SOCKET_PROJECTION_RECEIPT_DATA_KEY])
        || bool_at(receipt_config_map, &["immutable"]) != Some(true)
        || value_at(receipt_config_map, &["binaryData"]).is_some()
    {
        return Err(
            "receipt ConfigMap must be immutable with only canonical receipt.json data and no binaryData"
                .to_string(),
        );
    }
    let raw_receipt = str_at(
        receipt_config_map,
        &["data", SOCKET_PROJECTION_RECEIPT_DATA_KEY],
    )
    .ok_or_else(|| "receipt.json must be a string".to_string())?;
    if raw_receipt.len() > SOCKET_PROJECTION_MAX_RECEIPT_BYTES {
        return Err("receipt.json exceeds the 64 KiB limit".to_string());
    }
    let content_digest = canonical_config_map_data_digest(data)
        .ok_or_else(|| "receipt ConfigMap data cannot be canonicalized".to_string())?;
    let annotations = object_at(receipt_config_map, &["metadata", "annotations"])
        .ok_or_else(|| "receipt ConfigMap annotations are missing".to_string())?;
    if !object_has_exact_keys(
        annotations,
        &[
            RELEASE_DIGEST_PREFIX_ANNOTATION,
            CONTENT_DIGEST_ANNOTATION,
            SOCKET_PROJECTION_RECEIPT_RAW_DIGEST_ANNOTATION,
        ],
    ) || str_at(
        receipt_config_map,
        &["metadata", "annotations", RELEASE_DIGEST_PREFIX_ANNOTATION],
    ) != Some(identity.digest_prefix.as_str())
        || str_at(
            receipt_config_map,
            &["metadata", "annotations", CONTENT_DIGEST_ANNOTATION],
        ) != Some(content_digest.as_str())
        || str_at(
            receipt_config_map,
            &[
                "metadata",
                "annotations",
                SOCKET_PROJECTION_RECEIPT_RAW_DIGEST_ANNOTATION,
            ],
        ) != Some(receipt_digest)
    {
        return Err("receipt ConfigMap metadata does not bind its exact raw/content digests and release prefix".to_string());
    }
    if sha256_prefixed(raw_receipt.as_bytes()) != receipt_digest {
        return Err("receipt.json raw SHA-256 does not match the Job annotation".to_string());
    }

    let receipt = crate::security_conformance::parse_json_strict(raw_receipt.as_bytes())
        .map_err(|error| format!("receipt.json is not strict JSON: {error}"))?;
    let canonical_receipt = canonical_json_bytes(&receipt)
        .map_err(|error| format!("receipt canonicalization failed: {error}"))?;
    if canonical_receipt.as_slice() != raw_receipt.as_bytes() {
        return Err("receipt.json is not exact ryuki-canonical-json-v1".to_string());
    }
    let receipt_object =
        object(&receipt).ok_or_else(|| "receipt root must be an object".to_string())?;
    if !object_has_exact_keys(receipt_object, &["payload", "signature"]) {
        return Err("receipt root must contain only payload and signature".to_string());
    }
    let payload =
        value_at(&receipt, &["payload"]).ok_or_else(|| "receipt payload is missing".to_string())?;
    let payload_object =
        object(payload).ok_or_else(|| "receipt payload must be an object".to_string())?;
    if !object_has_exact_keys(
        payload_object,
        &[
            "canonicalization",
            "contractId",
            "expiresAtUnixSeconds",
            "notBeforeUnixSeconds",
            "pinConfigMapReceipts",
            "receiptAuthority",
            "releaseDigestPrefix",
            "releaseImage",
            "renderedJobPreimageDigest",
            "socketContractDigest",
            "socketProjections",
        ],
    ) {
        return Err("receipt payload has an unknown or missing v1 field".to_string());
    }
    let not_before = value_at(payload, &["notBeforeUnixSeconds"])
        .and_then(Value::as_i64)
        .ok_or_else(|| "notBeforeUnixSeconds must be an integer".to_string())?;
    let expires_at = value_at(payload, &["expiresAtUnixSeconds"])
        .and_then(Value::as_i64)
        .ok_or_else(|| "expiresAtUnixSeconds must be an integer".to_string())?;
    let now = Utc::now().timestamp();
    if not_before < 1
        || expires_at <= not_before
        || expires_at - not_before > SOCKET_PROJECTION_MAX_AUTHORIZATION_SECONDS
        || now < not_before
        || now >= expires_at
    {
        return Err(
            "receipt validity must be current in [notBefore, expiresAt) and no longer than 300 seconds"
                .to_string(),
        );
    }
    let receipt_authority = value_at(payload, &["receiptAuthority"])
        .ok_or_else(|| "receiptAuthority is missing".to_string())?;
    let receipt_authority_object = object(receipt_authority)
        .ok_or_else(|| "receiptAuthority must be an object".to_string())?;
    if !object_has_exact_keys(
        receipt_authority_object,
        &[
            "authorityEpoch",
            "authorityId",
            "keyId",
            "minAuthorityEpoch",
            "profileDigest",
            "profileId",
            "profileVersion",
            "publicKeyFingerprint",
        ],
    ) {
        return Err("receiptAuthority has an unknown or missing field".to_string());
    }
    let authority_epoch = value_at(receipt_authority, &["authorityEpoch"])
        .and_then(Value::as_u64)
        .filter(|epoch| *epoch >= anchor.min_authority_epoch)
        .ok_or_else(|| "receipt authority epoch is below the independent minimum".to_string())?;
    let expected_payload = serde_json::json!({
        "canonicalization": "ryuki-canonical-json-v1",
        "contractId": SOCKET_PROJECTION_RECEIPT_CONTRACT,
        "expiresAtUnixSeconds": expires_at,
        "notBeforeUnixSeconds": not_before,
        "pinConfigMapReceipts": expected_socket_receipt_pin_receipts(job)?,
        "receiptAuthority": {
            "authorityEpoch": authority_epoch,
            "authorityId": anchor.authority_id.as_str(),
            "keyId": anchor.key_id.as_str(),
            "minAuthorityEpoch": anchor.min_authority_epoch,
            "profileDigest": anchor.profile_digest.as_str(),
            "profileId": anchor.profile_id.as_str(),
            "profileVersion": anchor.profile_version,
            "publicKeyFingerprint": anchor.public_key_fingerprint.as_str(),
        },
        "releaseDigestPrefix": identity.digest_prefix.as_str(),
        "releaseImage": str_at(job, &["metadata", "annotations", "ryuki.io/release-image"])
            .ok_or_else(|| "Job release image annotation is missing".to_string())?,
        "renderedJobPreimageDigest": rendered_job_preimage_digest(job)?,
        "socketContractDigest": SOCKET_CONTRACT_DIGEST,
        "socketProjections": expected_socket_receipt_projections(manifests, identity)?,
    });
    if payload != &expected_payload {
        return Err("signed receipt payload does not exactly bind the rendered Job, nine ConfigMap receipts, authority pins, and four socket projections".to_string());
    }

    let signature = value_at(&receipt, &["signature"])
        .ok_or_else(|| "receipt signature is missing".to_string())?;
    if !object(signature).is_some_and(|signature| {
        object_has_exact_keys(signature, &["algorithm", "signatureBase64"])
    }) || str_at(signature, &["algorithm"]) != Some("ed25519")
    {
        return Err("receipt signature must be the exact Ed25519 v1 object".to_string());
    }
    let signature_bytes = decode_canonical_base64::<64>(
        str_at(signature, &["signatureBase64"])
            .ok_or_else(|| "signatureBase64 is missing".to_string())?,
        "receipt signature",
    )?;
    let canonical_payload = canonical_json_bytes(payload)
        .map_err(|error| format!("receipt payload canonicalization failed: {error}"))?;
    let signed = socket_projection_signing_bytes(&canonical_payload);
    let verifying_key = VerifyingKey::from_bytes(&anchor.public_key)
        .map_err(|_| "independent trust anchor contains an invalid Ed25519 key".to_string())?;
    if verifying_key.is_weak() {
        return Err("independent trust anchor contains a weak Ed25519 key".to_string());
    }
    verifying_key
        .verify_strict(&signed, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| "Ed25519 receipt signature verification failed".to_string())
}

fn parse_socket_projection_trust_anchor(
    value: &Value,
) -> Result<SocketProjectionTrustAnchor, String> {
    let anchor = object(value).ok_or_else(|| "trust anchor must be an object".to_string())?;
    if !object_has_exact_keys(
        anchor,
        &[
            "authorityId",
            "contractId",
            "keyId",
            "minAuthorityEpoch",
            "profileDigest",
            "profileId",
            "profileVersion",
            "publicKeyBase64",
            "publicKeyFingerprint",
        ],
    ) || str_at(value, &["contractId"]) != Some(SOCKET_PROJECTION_TRUST_ANCHOR_CONTRACT)
    {
        return Err("trust anchor has an unknown, missing, or invalid v1 field".to_string());
    }
    let authority_id = str_at(value, &["authorityId"])
        .filter(|value| is_render_identifier(value))
        .ok_or_else(|| "trust-anchor authorityId is invalid".to_string())?;
    let key_id = str_at(value, &["keyId"])
        .filter(|value| is_render_identifier(value))
        .ok_or_else(|| "trust-anchor keyId is invalid".to_string())?;
    let profile_id = str_at(value, &["profileId"])
        .filter(|value| is_render_identifier(value))
        .ok_or_else(|| "trust-anchor profileId is invalid".to_string())?;
    let profile_version = value_at(value, &["profileVersion"])
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| "trust-anchor profileVersion must be a positive integer".to_string())?;
    let profile_digest = str_at(value, &["profileDigest"])
        .filter(|value| is_nonzero_sha256_digest(value))
        .ok_or_else(|| "trust-anchor profileDigest is invalid".to_string())?;
    let min_authority_epoch = value_at(value, &["minAuthorityEpoch"])
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| "trust-anchor minAuthorityEpoch must be a positive integer".to_string())?;
    let public_key_base64 = str_at(value, &["publicKeyBase64"])
        .ok_or_else(|| "trust-anchor publicKeyBase64 is missing".to_string())?;
    let public_key = decode_canonical_base64::<32>(public_key_base64, "trust-anchor public key")?;
    let public_key_fingerprint = str_at(value, &["publicKeyFingerprint"])
        .filter(|value| is_nonzero_sha256_digest(value))
        .ok_or_else(|| "trust-anchor publicKeyFingerprint is invalid".to_string())?;
    if sha256_prefixed(&public_key) != public_key_fingerprint {
        return Err("trust-anchor public-key fingerprint does not match its raw key".to_string());
    }
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| "trust anchor contains an invalid Ed25519 public key".to_string())?;
    if verifying_key.is_weak() {
        return Err("trust anchor contains a weak Ed25519 public key".to_string());
    }
    Ok(SocketProjectionTrustAnchor {
        authority_id: authority_id.to_string(),
        key_id: key_id.to_string(),
        public_key,
        public_key_base64: public_key_base64.to_string(),
        public_key_fingerprint: public_key_fingerprint.to_string(),
        min_authority_epoch,
        profile_id: profile_id.to_string(),
        profile_version,
        profile_digest: profile_digest.to_string(),
    })
}

fn exactly_one_named_config_map<'a>(
    manifests: &'a [Value],
    name: &str,
) -> Result<&'a Value, String> {
    let matches: Vec<&Value> = manifests
        .iter()
        .filter(|manifest| {
            str_at(manifest, &["kind"]) == Some("ConfigMap")
                && str_at(manifest, &["metadata", "name"]) == Some(name)
        })
        .collect();
    if matches.len() != 1 {
        return Err(format!("expected exactly one ConfigMap {name}"));
    }
    Ok(matches[0])
}

fn expected_socket_receipt_pin_receipts(job: &Value) -> Result<Value, String> {
    MIGRATION_RENDER_PIN_GROUPS
        .iter()
        .map(|(_, _, annotation)| {
            let raw = str_at(job, &["metadata", "annotations", annotation])
                .filter(|value| is_canonical_pin_config_map_receipt(value))
                .ok_or_else(|| format!("Job pin receipt {annotation} is missing or invalid"))?;
            let receipt = crate::security_conformance::parse_json_strict(raw.as_bytes())
                .map_err(|error| format!("Job pin receipt {annotation} is invalid: {error}"))?;
            Ok(serde_json::json!({
                "annotation": annotation,
                "receipt": receipt,
            }))
        })
        .collect::<Result<Vec<_>, String>>()
        .map(Value::Array)
}

fn expected_socket_receipt_projections(
    manifests: &[Value],
    identity: &MigrationIdentity,
) -> Result<Value, String> {
    MIGRATION_AUTHORITY_SOCKET_PROJECTIONS
        .iter()
        .map(
            |(
                base_name,
                socket_key,
                authority_id_key,
                key_id_key,
                fingerprint_key,
                volume_name,
                authority_class,
            )| {
                let name = digest_scoped_pin_config_map_name(base_name, &identity.digest_prefix);
                let config_map = exactly_one_named_config_map(manifests, &name)?;
                let socket_path = str_at(config_map, &["data", socket_key])
                    .filter(|value| is_normalized_absolute_socket_path(value))
                    .ok_or_else(|| format!("{name} socket path is invalid"))?;
                let mount_path = normalized_socket_mount_parent(socket_path)
                    .ok_or_else(|| format!("{name} socket mount path is invalid"))?;
                let authority_id = str_at(config_map, &["data", authority_id_key])
                    .filter(|value| is_render_identifier(value))
                    .ok_or_else(|| format!("{name} authority id is invalid"))?;
                let key_id = str_at(config_map, &["data", key_id_key])
                    .filter(|value| is_render_identifier(value))
                    .ok_or_else(|| format!("{name} key id is invalid"))?;
                let fingerprint = str_at(config_map, &["data", fingerprint_key])
                    .filter(|value| is_nonzero_sha256_digest(value))
                    .ok_or_else(|| format!("{name} public-key fingerprint is invalid"))?;
                Ok(serde_json::json!({
                    "authorityClass": authority_class,
                    "authorityId": authority_id,
                    "csiDriver": AUTHORITY_SOCKET_CSI_DRIVER,
                    "environmentVariable": socket_key,
                    "keyId": key_id,
                    "mountPath": mount_path,
                    "publicKeyFingerprint": fingerprint,
                    "readOnly": true,
                    "socketPath": socket_path,
                    "volumeName": volume_name,
                }))
            },
        )
        .collect::<Result<Vec<_>, String>>()
        .map(Value::Array)
}

fn rendered_job_preimage_digest(job: &Value) -> Result<String, String> {
    let mut preimage = job.clone();
    preimage
        .pointer_mut("/metadata/annotations")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "Job annotations are missing".to_string())?
        .remove(SOCKET_PROJECTION_RECEIPT_DIGEST_ANNOTATION)
        .ok_or_else(|| "Job receipt digest annotation is missing".to_string())?;
    canonical_json_bytes(&preimage)
        .map(|bytes| sha256_prefixed(&bytes))
        .map_err(|error| format!("rendered Job canonicalization failed: {error}"))
}

fn socket_projection_signing_bytes(canonical_payload: &[u8]) -> Vec<u8> {
    let mut signed =
        Vec::with_capacity(16 + SOCKET_PROJECTION_SIGNATURE_DOMAIN.len() + canonical_payload.len());
    write_frame(&mut signed, SOCKET_PROJECTION_SIGNATURE_DOMAIN.as_bytes());
    write_frame(&mut signed, canonical_payload);
    signed
}

fn write_frame(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u64).to_le_bytes());
    buffer.extend_from_slice(value);
}

fn decode_canonical_base64<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| format!("{label} is not valid standard base64"))?;
    let decoded: [u8; N] = decoded
        .try_into()
        .map_err(|_| format!("{label} has the wrong decoded length"))?;
    if BASE64_STANDARD.encode(decoded) != value {
        return Err(format!("{label} is not canonical padded standard base64"));
    }
    Ok(decoded)
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn socket_projection_receipt_config_map_name(digest: &str) -> Option<String> {
    is_nonzero_sha256_digest(digest).then(|| {
        format!(
            "{SOCKET_PROJECTION_RECEIPT_CONFIG_MAP_PREFIX}{}",
            &digest["sha256:".len()..]
        )
    })
}

fn validate_final_render_socket_projections(
    manifests: &[Value],
    job: &Value,
    migration_identity: Option<&MigrationIdentity>,
    errors: &mut Vec<String>,
) {
    let Some(identity) = migration_identity else {
        errors.push(
            "final-render socket projections require one valid release image identity".to_string(),
        );
        return;
    };
    let pod_spec = value_at(job, &["spec", "template", "spec"]).unwrap_or(&Value::Null);
    let container = array_at_path(pod_spec, &["containers"])
        .first()
        .copied()
        .unwrap_or(&Value::Null);
    let volumes = array_at_path(pod_spec, &["volumes"]);
    let mounts = array_at_path(container, &["volumeMounts"]);
    let mut socket_paths = Vec::new();
    let mut mount_paths = Vec::new();
    let mut fingerprints = Vec::new();
    let mut all_projections_match = true;

    for (base_name, socket_key, _, _, fingerprint_key, volume_name, authority_class) in
        MIGRATION_AUTHORITY_SOCKET_PROJECTIONS
    {
        let config_map_name = digest_scoped_pin_config_map_name(base_name, &identity.digest_prefix);
        let config_maps: Vec<&Value> = manifests
            .iter()
            .filter(|manifest| {
                str_at(manifest, &["kind"]) == Some("ConfigMap")
                    && str_at(manifest, &["metadata", "name"]) == Some(config_map_name.as_str())
            })
            .collect();
        let config_map = config_maps.first().copied().unwrap_or(&Value::Null);
        let socket_path = str_at(config_map, &["data", socket_key]);
        let fingerprint = str_at(config_map, &["data", fingerprint_key]);
        let mount_path = socket_path.and_then(normalized_socket_mount_parent);
        if let Some(socket_path) = socket_path {
            socket_paths.push(socket_path.to_string());
        }
        if let Some(mount_path) = mount_path {
            mount_paths.push(mount_path.to_string());
        }
        if let Some(fingerprint) = fingerprint {
            fingerprints.push(fingerprint.to_string());
        }

        let matching_volumes: Vec<&Value> = volumes
            .iter()
            .copied()
            .filter(|volume| str_at(volume, &["name"]) == Some(*volume_name))
            .collect();
        let volume = matching_volumes.first().copied().unwrap_or(&Value::Null);
        let csi = value_at(volume, &["csi"]).unwrap_or(&Value::Null);
        let attributes = object_at(csi, &["volumeAttributes"]);
        let matching_mounts: Vec<&Value> = mounts
            .iter()
            .copied()
            .filter(|mount| str_at(mount, &["name"]) == Some(*volume_name))
            .collect();
        let mount = matching_mounts.first().copied().unwrap_or(&Value::Null);

        all_projections_match &= config_maps.len() == 1
            && socket_path.is_some_and(is_normalized_absolute_socket_path)
            && fingerprint.is_some_and(is_nonzero_sha256_digest)
            && matching_volumes.len() == 1
            && object(volume).is_some_and(|volume| object_has_exact_keys(volume, &["name", "csi"]))
            && object(csi).is_some_and(|csi| {
                object_has_exact_keys(csi, &["driver", "readOnly", "volumeAttributes"])
            })
            && str_at(csi, &["driver"]) == Some(AUTHORITY_SOCKET_CSI_DRIVER)
            && bool_at(csi, &["readOnly"]) == Some(true)
            && attributes.is_some_and(|attributes| {
                object_has_exact_keys(attributes, AUTHORITY_SOCKET_CSI_ATTRIBUTE_KEYS)
            })
            && str_at(csi, &["volumeAttributes", "environmentVariable"]) == Some(*socket_key)
            && str_at(csi, &["volumeAttributes", "authorityClass"]) == Some(*authority_class)
            && str_at(csi, &["volumeAttributes", "socketPath"]) == socket_path
            && matching_mounts.len() == 1
            && object(mount).is_some_and(|mount| {
                object_has_exact_keys(mount, &["name", "mountPath", "readOnly"])
            })
            && str_at(mount, &["mountPath"]) == mount_path
            && bool_at(mount, &["readOnly"]) == Some(true);
    }

    let expected_volume_names: BTreeSet<&str> = MIGRATION_AUTHORITY_SOCKET_PROJECTIONS
        .iter()
        .map(|(_, _, _, _, _, volume_name, _)| *volume_name)
        .chain(std::iter::once(CNPG_CA_VOLUME_NAME))
        .chain(std::iter::once(POSTGRESQL_RELAY_VOLUME_NAME))
        .collect();
    let actual_volume_names: BTreeSet<&str> = volumes
        .iter()
        .filter_map(|volume| str_at(volume, &["name"]))
        .collect();
    let actual_mount_names: BTreeSet<&str> = mounts
        .iter()
        .filter_map(|mount| str_at(mount, &["name"]))
        .collect();
    let distinct_socket_paths: BTreeSet<&str> = socket_paths.iter().map(String::as_str).collect();
    let distinct_mount_paths: BTreeSet<&str> = mount_paths.iter().map(String::as_str).collect();
    let postgresql_fingerprint = fingerprints.last();

    expect(
        all_projections_match
            && volumes.len() == 2 + MIGRATION_AUTHORITY_SOCKET_PROJECTIONS.len()
            && mounts.len() == 2 + MIGRATION_AUTHORITY_SOCKET_PROJECTIONS.len()
            && actual_volume_names == expected_volume_names
            && actual_mount_names == expected_volume_names
            && socket_paths.len() == MIGRATION_AUTHORITY_SOCKET_PROJECTIONS.len()
            && distinct_socket_paths.len() == MIGRATION_AUTHORITY_SOCKET_PROJECTIONS.len()
            && mount_paths.len() == MIGRATION_AUTHORITY_SOCKET_PROJECTIONS.len()
            && distinct_mount_paths.len() == MIGRATION_AUTHORITY_SOCKET_PROJECTIONS.len()
            && fingerprints.len() == MIGRATION_AUTHORITY_SOCKET_PROJECTIONS.len()
            && postgresql_fingerprint.is_some_and(|postgresql| {
                fingerprints[..fingerprints.len() - 1]
                    .iter()
                    .all(|fingerprint| fingerprint != postgresql)
            }),
        errors,
        "final-render migration Job must carry exactly four receipt-bound, read-only inline CSI authority socket projections with distinct normalized paths and an independent PostgreSQL key fingerprint",
    );
}

fn is_normalized_absolute_socket_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 255
        && value.ends_with(".sock")
        && !value.contains("//")
        && value.split('/').skip(1).all(|segment| {
            !segment.is_empty()
                && !matches!(segment, "." | "..")
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_uppercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
}

fn is_normalized_absolute_json_path(value: &str) -> bool {
    let path = Path::new(value);
    let components_are_lexically_normal = value.strip_prefix('/').is_some_and(|suffix| {
        !suffix.is_empty()
            && !suffix
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
    });
    value.len() <= 4096
        && path.is_absolute()
        && !value.contains('\\')
        && components_are_lexically_normal
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.extension().and_then(|extension| extension.to_str()) == Some("json")
}

fn normalized_socket_mount_parent(value: &str) -> Option<&str> {
    if !is_normalized_absolute_socket_path(value) {
        return None;
    }
    let (parent, file_name) = value.rsplit_once('/')?;
    (!parent.is_empty() && parent != "/" && !file_name.is_empty()).then_some(parent)
}

fn canonical_config_map_data_digest(data: &Map<String, Value>) -> Option<String> {
    let sorted: BTreeMap<&str, &str> = data
        .iter()
        .map(|(key, value)| Some((key.as_str(), value.as_str()?)))
        .collect::<Option<_>>()?;
    let bytes = serde_json::to_vec(&sorted).ok()?;
    Some(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn is_nonzero_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && hex.bytes().any(|byte| byte != b'0')
}

fn is_canonical_kubernetes_uid(value: &str) -> bool {
    is_canonical_kubernetes_readback_token(value)
}

fn is_canonical_resource_version(value: &str) -> bool {
    is_canonical_kubernetes_readback_token(value)
}

fn is_canonical_kubernetes_readback_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn is_render_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value.trim() == value
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b':' | b'.' | b'_' | b'-' | b'/')
        })
}

fn validate_final_render_cutover_contract(contract: &Value, errors: &mut Vec<String>) {
    let runtime_admission = value_at(contract, &["runtimeAdmission"]).unwrap_or(&Value::Null);
    expect(
        bool_at(contract, &["productionExecutionEnabled"]) == Some(false)
            && object(runtime_admission).is_some_and(|runtime_admission| {
                object_has_exact_keys(
                    runtime_admission,
                    &[
                        "requiredCapability",
                        "capabilityAvailable",
                        "offlineSnapshotValidationOnly",
                        "snapshotAuthorizesJobCreation",
                        "snapshotFencesConfigMapDeleteRecreate",
                        "snapshotConsumesExecutionAttempt",
                        "snapshotEnforcesReceiptExpiryAtPodStartOrRuntime",
                    ],
                )
            })
            && str_at(runtime_admission, &["requiredCapability"])
                == Some(FINAL_RENDER_REQUIRED_RUNTIME_CAPABILITY)
            && bool_at(runtime_admission, &["capabilityAvailable"]) == Some(false)
            && bool_at(runtime_admission, &["offlineSnapshotValidationOnly"]) == Some(true)
            && [
                "snapshotAuthorizesJobCreation",
                "snapshotFencesConfigMapDeleteRecreate",
                "snapshotConsumesExecutionAttempt",
                "snapshotEnforcesReceiptExpiryAtPodStartOrRuntime",
            ]
            .iter()
            .all(|field| bool_at(runtime_admission, &[field]) == Some(false)),
        errors,
        "cutover production execution must remain disabled until the exact in-cluster admission and runtime-freshness capability exists; snapshot validation cannot authorize Job creation, fence ConfigMap recreation, consume an attempt, or enforce runtime expiry",
    );

    let final_render = value_at(contract, &["finalRender"]).unwrap_or(&Value::Null);
    expect(
        object(final_render).is_some_and(|final_render| {
            object_has_exact_keys(
                final_render,
                &[
                    "contractId",
                    "sourceMode",
                    "finalMode",
                    "unresolvedSentinel",
                    "atomicRewriteRequired",
                    "unresolvedSentinelForbiddenInFinal",
                    "exactReleaseDigestPrefixRequired",
                    "sourceSuspendRequired",
                    "finalSuspendExplicitlyFalseRequired",
                    "jobAnnotations",
                    "pinConfigMapReceipt",
                    "socketProjectionReceipt",
                    "closedSocketContract",
                    "closedSocketContractDigestAlgorithm",
                    "closedSocketContractDigestPreimage",
                    "closedSocketContractDigest",
                ],
            )
        }) && str_at(final_render, &["contractId"]) == Some(FINAL_RENDER_CONTRACT)
            && str_at(final_render, &["sourceMode"]) == Some(SOURCE_TEMPLATE_MODE)
            && str_at(final_render, &["finalMode"]) == Some(FINAL_RENDER_MODE)
            && str_at(final_render, &["unresolvedSentinel"]) == Some(RENDER_REQUIRED_SENTINEL)
            && [
                "atomicRewriteRequired",
                "unresolvedSentinelForbiddenInFinal",
                "exactReleaseDigestPrefixRequired",
                "sourceSuspendRequired",
                "finalSuspendExplicitlyFalseRequired",
            ]
            .iter()
            .all(|field| bool_at(final_render, &[field]) == Some(true)),
        errors,
        "cutover finalRender must be the exact atomic source-template to final-render contract",
    );

    let job_annotations = value_at(final_render, &["jobAnnotations"]).unwrap_or(&Value::Null);
    expect(
        object(job_annotations).is_some_and(|annotations| {
            object_has_exact_keys(
                annotations,
                &["exactKeys", "unknownRyukiAnnotationsForbidden"],
            )
        }) && string_array_matches_exact(
            job_annotations,
            &["exactKeys"],
            MIGRATION_JOB_RYUKI_ANNOTATIONS,
        ) && bool_at(job_annotations, &["unknownRyukiAnnotationsForbidden"]) == Some(true),
        errors,
        "cutover finalRender must close the migration Job ryuki.io annotation inventory",
    );

    let pin_receipt = value_at(final_render, &["pinConfigMapReceipt"]).unwrap_or(&Value::Null);
    expect(
        object(pin_receipt).is_some_and(|receipt| {
            object_has_exact_keys(
                receipt,
                &[
                    "exactCanonicalJsonFields",
                    "unknownFieldsForbidden",
                    "contentDigestAlgorithm",
                    "contentDigestPreimage",
                    "binaryDataForbidden",
                    "configMapAnnotationsRequired",
                    "immutableRequired",
                    "receiptMustExactlyMatchApiReadback",
                    "uidAndResourceVersionAreOpaqueStrings",
                    "offlineSnapshotFencesEnvironmentConfigMapDeleteRecreate",
                    "offlineSnapshotFencesNonEnvironmentAuthorityDeleteRecreate",
                ],
            )
        }) && string_array_matches_exact(
            pin_receipt,
            &["exactCanonicalJsonFields"],
            &["configMapName", "uid", "resourceVersion", "contentDigest"],
        ) && string_array_matches_exact(
            pin_receipt,
            &["configMapAnnotationsRequired"],
            &[RELEASE_DIGEST_PREFIX_ANNOTATION, CONTENT_DIGEST_ANNOTATION],
        ) && str_at(pin_receipt, &["contentDigestAlgorithm"]) == Some("sha256")
            && str_at(pin_receipt, &["contentDigestPreimage"])
                == Some("canonical-sorted-json-data-object")
            && [
                "unknownFieldsForbidden",
                "binaryDataForbidden",
                "immutableRequired",
                "receiptMustExactlyMatchApiReadback",
                "uidAndResourceVersionAreOpaqueStrings",
            ]
            .iter()
            .all(|field| bool_at(pin_receipt, &[field]) == Some(true))
            && bool_at(
                pin_receipt,
                &["offlineSnapshotFencesEnvironmentConfigMapDeleteRecreate"],
            ) == Some(false)
            && bool_at(
                pin_receipt,
                &["offlineSnapshotFencesNonEnvironmentAuthorityDeleteRecreate"],
            ) == Some(false),
        errors,
        "cutover finalRender snapshot must bind immutable pin ConfigMaps by exact canonical content digest and API readback identity without claiming a post-validation deletion/recreation fence",
    );

    let socket_receipt =
        value_at(final_render, &["socketProjectionReceipt"]).unwrap_or(&Value::Null);
    expect(
        object(socket_receipt).is_some_and(|receipt| {
            object_has_exact_keys(
                receipt,
                &[
                    "sourceTemplateMayOmitDynamicSocketMounts",
                    "sourceTemplateExecutable",
                    "finalRenderMustCarryExactSocketProjections",
                    "exactSocketCount",
                    "inlineCsiDriver",
                    "inlineCsiReadOnlyRequired",
                    "exactVolumeAttributeKeys",
                    "deterministicVolumeNames",
                    "mountsAreSocketParentDirectories",
                    "socketPathsDistinctRequired",
                    "mountParentPathsDistinctRequired",
                    "postgresqlFingerprintDistinctFromOtherAuthoritiesRequired",
                    "authorityConfigMapContract",
                    "receiptConfigMapContract",
                    "strictSignedEnvelopeContract",
                    "receiptRawDigestAlgorithm",
                    "jobCarriesReceiptDigestOnly",
                    "renderedJobPreimageExcludesOnlyReceiptDigestAnnotation",
                    "receiptDigestForbiddenInCsiAttributes",
                    "receiptBindsReleaseImageAndAllNinePinConfigMapReceipts",
                    "receiptBindsExactRenderedJobPreimageDigest",
                    "receiptBindsExactSocketPathsAuthoritiesKeysAndFingerprints",
                    "receiptMaximumAuthorizationSeconds",
                    "finalSocketsReachableBeforeRunnerStartRequired",
                    "receiptAnnotations",
                ],
            )
        }) && bool_at(
            socket_receipt,
            &["sourceTemplateMayOmitDynamicSocketMounts"],
        ) == Some(true)
            && bool_at(socket_receipt, &["sourceTemplateExecutable"]) == Some(false)
            && int_at(socket_receipt, &["exactSocketCount"]) == Some(4)
            && str_at(socket_receipt, &["inlineCsiDriver"]) == Some(AUTHORITY_SOCKET_CSI_DRIVER)
            && string_array_matches_exact(
                socket_receipt,
                &["exactVolumeAttributeKeys"],
                AUTHORITY_SOCKET_CSI_ATTRIBUTE_KEYS,
            )
            && object_at(socket_receipt, &["deterministicVolumeNames"]).is_some_and(|names| {
                object_has_exact_keys(
                    names,
                    &[
                        "conformanceTrustCheckpoint",
                        "deployedWorkloadAttestation",
                        "publicIngressAttestation",
                        "postgresqlInfrastructureAttestation",
                    ],
                )
            })
            && str_at(
                socket_receipt,
                &["deterministicVolumeNames", "conformanceTrustCheckpoint"],
            ) == Some("conformance-trust-checkpoint-socket")
            && str_at(
                socket_receipt,
                &["deterministicVolumeNames", "deployedWorkloadAttestation"],
            ) == Some("deployed-workload-attestation-socket")
            && str_at(
                socket_receipt,
                &["deterministicVolumeNames", "publicIngressAttestation"],
            ) == Some("public-ingress-attestation-socket")
            && str_at(
                socket_receipt,
                &[
                    "deterministicVolumeNames",
                    "postgresqlInfrastructureAttestation",
                ],
            ) == Some("postgresql-infrastructure-attestation-socket")
            && int_at(socket_receipt, &["receiptMaximumAuthorizationSeconds"]) == Some(300)
            && str_at(socket_receipt, &["receiptRawDigestAlgorithm"]) == Some("sha256")
            && str_at(socket_receipt, &["authorityConfigMapContract"])
                == Some("socketProjectionAuthority")
            && str_at(socket_receipt, &["receiptConfigMapContract"])
                == Some("socketProjectionReceiptResource")
            && str_at(socket_receipt, &["strictSignedEnvelopeContract"])
                == Some(SOCKET_PROJECTION_RECEIPT_CONTRACT)
            && [
                "finalRenderMustCarryExactSocketProjections",
                "inlineCsiReadOnlyRequired",
                "mountsAreSocketParentDirectories",
                "socketPathsDistinctRequired",
                "mountParentPathsDistinctRequired",
                "postgresqlFingerprintDistinctFromOtherAuthoritiesRequired",
                "jobCarriesReceiptDigestOnly",
                "renderedJobPreimageExcludesOnlyReceiptDigestAnnotation",
                "receiptDigestForbiddenInCsiAttributes",
                "receiptBindsReleaseImageAndAllNinePinConfigMapReceipts",
                "receiptBindsExactRenderedJobPreimageDigest",
                "receiptBindsExactSocketPathsAuthoritiesKeysAndFingerprints",
                "finalSocketsReachableBeforeRunnerStartRequired",
            ]
            .iter()
            .all(|field| bool_at(socket_receipt, &[field]) == Some(true)),
        errors,
        "cutover finalRender must require one external signed four-socket projection receipt with a 300-second authorization lifetime",
    );

    let receipt_annotations =
        value_at(socket_receipt, &["receiptAnnotations"]).unwrap_or(&Value::Null);
    expect(
        object(receipt_annotations).is_some_and(|annotations| {
            object_has_exact_keys(
                annotations,
                &["digest", "authorityConfigMapReceipt", "contractDigest"],
            )
        }) && str_at(receipt_annotations, &["digest"])
            == Some(SOCKET_PROJECTION_RECEIPT_DIGEST_ANNOTATION)
            && str_at(receipt_annotations, &["authorityConfigMapReceipt"])
                == Some("ryuki.io/pin-socket-projection-authority-receipt")
            && str_at(receipt_annotations, &["contractDigest"])
                == Some(SOCKET_CONTRACT_DIGEST_ANNOTATION),
        errors,
        "cutover finalRender must map the signed socket receipt to the exact closed Job annotations",
    );

    let socket_contract = value_at(final_render, &["closedSocketContract"]).unwrap_or(&Value::Null);
    let expected_sockets = [
        (
            "RYUKI_CONFORMANCE_TRUST_CHECKPOINT_SOCKET",
            "conformance-trust-checkpoint",
        ),
        (
            "RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_SOCKET",
            "deployed-workload-attestation",
        ),
        (
            "RYUKI_PUBLIC_INGRESS_ATTESTATION_SOCKET",
            "public-ingress-attestation",
        ),
        (
            "RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET",
            "postgresql-infrastructure-attestation",
        ),
    ];
    let required_sockets = array_at_path(socket_contract, &["requiredSockets"]);
    let socket_digest = serde_json::to_vec(socket_contract)
        .ok()
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)));
    expect(
        object(socket_contract).is_some_and(|contract| {
            object_has_exact_keys(
                contract,
                &[
                    "contractId",
                    "requiredSockets",
                    "exactSocketCount",
                    "unixSocketsOnly",
                    "normalizedAbsolutePinnedPathsRequired",
                    "liveReachabilityBeforeRunnerStartRequired",
                    "privateAuthorityKeyInJobForbidden",
                    "inImageAuthorityFallbackForbidden",
                    "hostPathFallbackForbidden",
                    "postgresqlSocketDistinctFromEveryOtherSocket",
                    "postgresqlKeyFingerprintDistinctFromEveryOtherAuthority",
                ],
            )
        }) && str_at(socket_contract, &["contractId"])
            == Some("migration-authority-socket-projection-v1")
            && int_at(socket_contract, &["exactSocketCount"]) == Some(4)
            && required_sockets.len() == expected_sockets.len()
            && required_sockets.iter().zip(expected_sockets).all(
                |(socket, (environment, authority))| {
                    object(socket).is_some_and(|socket| {
                        object_has_exact_keys(socket, &["environmentVariable", "authorityClass"])
                    }) && str_at(socket, &["environmentVariable"]) == Some(environment)
                        && str_at(socket, &["authorityClass"]) == Some(authority)
                },
            )
            && [
                "unixSocketsOnly",
                "normalizedAbsolutePinnedPathsRequired",
                "liveReachabilityBeforeRunnerStartRequired",
                "privateAuthorityKeyInJobForbidden",
                "inImageAuthorityFallbackForbidden",
                "hostPathFallbackForbidden",
                "postgresqlSocketDistinctFromEveryOtherSocket",
                "postgresqlKeyFingerprintDistinctFromEveryOtherAuthority",
            ]
            .iter()
            .all(|field| bool_at(socket_contract, &[field]) == Some(true))
            && str_at(final_render, &["closedSocketContractDigestAlgorithm"]) == Some("sha256")
            && str_at(final_render, &["closedSocketContractDigestPreimage"])
                == Some("canonical-sorted-json-finalRender.closedSocketContract")
            && str_at(final_render, &["closedSocketContractDigest"])
                == Some(SOCKET_CONTRACT_DIGEST)
            && socket_digest.as_deref() == Some(SOCKET_CONTRACT_DIGEST),
        errors,
        "cutover finalRender must retain the exact canonical four-socket contract and matching SHA-256 digest",
    );
}

fn validate_cutover_contract(contract: &Value, manifests: &[Value], errors: &mut Vec<String>) {
    let api_image = platform_api_image(manifests);
    let migration_identity = api_image.and_then(MigrationIdentity::from_image);
    let scoped_pin_config_map = |base_name: &str| {
        migration_identity
            .as_ref()
            .map(|identity| digest_scoped_pin_config_map_name(base_name, &identity.digest_prefix))
            .unwrap_or_default()
    };
    let security_admission_config_map = scoped_pin_config_map(SECURITY_ADMISSION_CONFIG_MAP);
    let migration_config_map = scoped_pin_config_map("platform-api-migration-config");
    let production_build_config_map = scoped_pin_config_map(PRODUCTION_BUILD_MANIFEST_CONFIG_MAP);
    let checkpoint_config_map = scoped_pin_config_map(CONFORMANCE_TRUST_CHECKPOINT_CONFIG_MAP);
    let workload_config_map = scoped_pin_config_map(DEPLOYED_WORKLOAD_ATTESTATION_CONFIG_MAP);
    let ingress_config_map = scoped_pin_config_map(PUBLIC_INGRESS_ATTESTATION_CONFIG_MAP);
    let postgresql_config_map =
        scoped_pin_config_map(POSTGRESQL_INFRASTRUCTURE_ATTESTATION_CONFIG_MAP);
    let first_owner_config_map = scoped_pin_config_map(FIRST_OWNER_AUTHORITY_CONFIG_MAP);
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
    validate_final_render_cutover_contract(contract, errors);

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
        object_at(contract, &["productionPinProjections"]).is_some_and(|projections| {
            object_has_exact_keys(
                projections,
                &[
                    "migrationConfig",
                    "baselineAdmission",
                    "buildManifest",
                    "conformanceTrustCheckpoint",
                    "deployedWorkloadAttestation",
                    "publicIngressAttestation",
                    "firstOwnerAuthority",
                    "completeGroupsRequired",
                    "exactPinConfigMapReceiptCount",
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
                ],
            )
        }) && object_at(contract, &["productionPinProjections", "migrationConfig"]).is_some_and(
            |group| {
                object_has_exact_keys(
                    group,
                    &[
                        "sourceTemplateConfigMapName",
                        "finalConfigMapName",
                        "contentDigest",
                        "uid",
                        "resourceVersion",
                        "jobReceiptAnnotation",
                        "configKeys",
                        "sourceTemplateStableReferenceAllowed",
                        "finalRenderMustRewriteEnvFromReference",
                        "finalRenderDigestPrefixBoundNameRequired",
                        "immutableConfigMapRequired",
                        "contentDigestAnnotationRequired",
                        "uidAndResourceVersionReadbackRequired",
                        "exactKeyInventoryRequired",
                        "exactReviewedValuesRequired",
                    ],
                )
            },
        ) && str_at(
            contract,
            &[
                "productionPinProjections",
                "migrationConfig",
                "sourceTemplateConfigMapName",
            ],
        ) == Some("platform-api-migration-config")
            && str_at(
                contract,
                &[
                    "productionPinProjections",
                    "migrationConfig",
                    "finalConfigMapName",
                ],
            ) == Some(migration_config_map.as_str())
            && string_array_matches_exact(
                contract,
                &["productionPinProjections", "migrationConfig", "configKeys"],
                PLATFORM_API_MIGRATION_CONFIG_KEYS,
            )
            && str_at(
                contract,
                &[
                    "productionPinProjections",
                    "migrationConfig",
                    "jobReceiptAnnotation",
                ],
            ) == Some("ryuki.io/pin-migration-config-receipt")
            && [
                "sourceTemplateStableReferenceAllowed",
                "finalRenderMustRewriteEnvFromReference",
                "finalRenderDigestPrefixBoundNameRequired",
                "immutableConfigMapRequired",
                "contentDigestAnnotationRequired",
                "uidAndResourceVersionReadbackRequired",
                "exactKeyInventoryRequired",
                "exactReviewedValuesRequired",
            ]
            .iter()
            .all(|flag| {
                bool_at(
                    contract,
                    &["productionPinProjections", "migrationConfig", flag],
                ) == Some(true)
            })
            && exact_cutover_pin_group(
                contract,
                &["productionPinProjections", "baselineAdmission"],
                &security_admission_config_map,
                SECURITY_ADMISSION_KEYS,
                "ryuki.io/pin-security-admission-receipt",
            )
            && exact_cutover_pin_group(
                contract,
                &["productionPinProjections", "buildManifest"],
                &production_build_config_map,
                PRODUCTION_BUILD_MANIFEST_KEYS,
                "ryuki.io/pin-production-build-manifest-receipt",
            )
            && exact_cutover_pin_group(
                contract,
                &["productionPinProjections", "conformanceTrustCheckpoint"],
                &checkpoint_config_map,
                CONFORMANCE_TRUST_CHECKPOINT_KEYS,
                "ryuki.io/pin-conformance-trust-checkpoint-receipt",
            )
            && exact_cutover_pin_group(
                contract,
                &["productionPinProjections", "deployedWorkloadAttestation"],
                &workload_config_map,
                DEPLOYED_WORKLOAD_ATTESTATION_KEYS,
                "ryuki.io/pin-deployed-workload-attestation-receipt",
            )
            && exact_cutover_pin_group(
                contract,
                &["productionPinProjections", "publicIngressAttestation"],
                &ingress_config_map,
                PUBLIC_INGRESS_ATTESTATION_KEYS,
                "ryuki.io/pin-public-ingress-attestation-receipt",
            )
            && object_at(
                contract,
                &["productionPinProjections", "firstOwnerAuthority"],
            )
            .is_some_and(|group| {
                object_has_exact_keys(
                    group,
                    &[
                        "configMapName",
                        "contentDigest",
                        "uid",
                        "resourceVersion",
                        "jobReceiptAnnotation",
                        "configKeys",
                        "productionOnly",
                        "independentlyGovernedAuthorityRequired",
                        "ed25519Required",
                        "privateKeyInWorkloadForbidden",
                        "socketProjectionRequired",
                        "detachedCertificateRequired",
                        "descriptorPinnedRegularFileRequired",
                        "symlinkProjectionForbidden",
                        "materializationReceiptRequired",
                    ],
                )
            })
            && cutover_pin_group_fields_match(
                contract,
                &["productionPinProjections", "firstOwnerAuthority"],
                &first_owner_config_map,
                FIRST_OWNER_AUTHORITY_KEYS,
                "ryuki.io/pin-first-owner-authority-receipt",
            )
            && [
                "productionOnly",
                "independentlyGovernedAuthorityRequired",
                "ed25519Required",
                "privateKeyInWorkloadForbidden",
                "detachedCertificateRequired",
                "descriptorPinnedRegularFileRequired",
                "symlinkProjectionForbidden",
                "materializationReceiptRequired",
            ]
            .iter()
            .all(|flag| {
                bool_at(
                    contract,
                    &["productionPinProjections", "firstOwnerAuthority", flag],
                ) == Some(true)
            })
            && bool_at(
                contract,
                &[
                    "productionPinProjections",
                    "firstOwnerAuthority",
                    "socketProjectionRequired",
                ],
            ) == Some(false)
            && [
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
            ]
            .iter()
            .all(|flag| bool_at(contract, &["productionPinProjections", flag]) == Some(true))
            && int_at(
                contract,
                &["productionPinProjections", "exactPinConfigMapReceiptCount"],
            ) == Some(9),
        errors,
        "cutover contract must retain complete independently governed production pin groups, file bindings, and exact pre-start Unix-socket projection gates without hostPath fallback",
    );

    expect(
        object_at(contract, &["postgresqlInfrastructureAttestation"]).is_some_and(|attestation| {
            object_has_exact_keys(
                attestation,
                &[
                    "configMapName",
                    "contentDigest",
                    "uid",
                    "resourceVersion",
                    "jobReceiptAnnotation",
                    "configKeys",
                    "completeGroupRequired",
                    "productionOnly",
                    "releaseDigestPrefixBoundNameRequired",
                    "immutableConfigMapRequired",
                    "contentDigestAnnotationRequired",
                    "uidAndResourceVersionReadbackRequired",
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
                    "maximumAuthorizationSeconds",
                    "socketDistinctFromCheckpointWorkloadAndIngressRequired",
                    "keyFingerprintDistinctFromCheckpointWorkloadAndIngressRequired",
                    "sqlVisibleFactsObservedLocallyRequired",
                    "providerClusterAndStorageSignedEvidenceRequired",
                    "directPgConnectionRequired",
                    "sameVerifiedConnectionForDdlRequired",
                    "sameVerifiedConnectionForPostflightRequired",
                    "exactPostflightLedgerRequired",
                ],
            )
        }) && cutover_pin_group_fields_match(
            contract,
            &["postgresqlInfrastructureAttestation"],
            &postgresql_config_map,
            POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEYS,
            "ryuki.io/pin-postgresql-infrastructure-attestation-receipt",
        ) && [
            "completeGroupRequired",
            "productionOnly",
            "releaseDigestPrefixBoundNameRequired",
            "immutableConfigMapRequired",
            "contentDigestAnnotationRequired",
            "uidAndResourceVersionReadbackRequired",
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
        ]
        .iter()
        .all(|flag| {
            bool_at(contract, &["postgresqlInfrastructureAttestation", flag]) == Some(true)
        }) && int_at(
            contract,
            &[
                "postgresqlInfrastructureAttestation",
                "maximumAuthorizationSeconds",
            ],
        ) == Some(300),
        errors,
        "cutover contract must retain the closed PostgreSQL infrastructure attestation group and its receipt-bound same-session DDL/postflight gates",
    );

    expect(
        int_at(contract, &["execution", "completions"]) == Some(1)
            && int_at(contract, &["execution", "parallelism"]) == Some(1)
            && int_at(contract, &["execution", "backoffLimit"]) == Some(0)
            && int_at(contract, &["execution", "activeDeadlineSeconds"]) == Some(300)
            && int_at(contract, &["execution", "maximumProofAuthorizationSeconds"]) == Some(300)
            && int_at(contract, &["execution", "statementTimeoutSeconds"]) == Some(180)
            && int_at(contract, &["execution", "lockTimeoutSeconds"]) == Some(30)
            && [
                "directPgConnectionRequired",
                "singleDatabaseTransactionRequired",
                "sessionScopedAdvisoryLockBeforeBeginRequired",
                "transactionScopedAdvisoryLockPromotionFirstStatementRequired",
                "sessionScopedAdvisoryLockReleasedAfterPromotionRequired",
                "migrationSqlCannotReleaseTransactionLockRequired",
                "localSqlVisibleFactsOnlyFromDirectConnection",
                "providerClusterAndStorageOnlyFromSignedEvidence",
                "exactReceiptCompositionRequired",
                "preDdlRecheckInsideTransactionRequired",
                "allPendingMigrationsInsideTransactionRequired",
                "exactLedgerPostflightInsideTransactionRequired",
                "commitDispatchBeforeProofSafetyDeadlineRequired",
                "rollbackWholeWaveBeforeCommitDispatchRequired",
                "commitOutcomeUnknownReconciliationRequired",
            ]
            .iter()
            .all(|field| bool_at(contract, &["execution", field]) == Some(true))
            && str_at(contract, &["execution", "createSemantics"])
                == Some("disabled-until-runtime-admission")
            && bool_at(contract, &["execution", "automaticTtlForbidden"]) == Some(true),
        errors,
        "cutover contract must keep Job creation disabled while retaining the future non-retrying, single-transaction, bounded-deadline execution shape",
    );

    let expected_sequence: Vec<String> =
        ["stop-production-execution-runtime-admission-unavailable"]
            .into_iter()
            .map(str::to_string)
            .collect();
    expect(
        string_array_at(contract, &["sequence"]) == expected_sequence,
        errors,
        "cutover contract sequence must stop before draining, issuing credentials, or creating a Job while runtime admission is unavailable",
    );

    expect(
        bool_at(contract, &["readback", "requireJobComplete"]) == Some(true)
            && bool_at(contract, &["readback", "requireSingleSuccessfulPod"]) == Some(true)
            && bool_at(contract, &["readback", "requireNoRetryPods"]) == Some(true)
            && bool_at(contract, &["readback", "requireEmbeddedInventoryMatch"]) == Some(true)
            && bool_at(contract, &["readback", "requireNoDirtyMigration"]) == Some(true)
            && bool_at(contract, &["readback", "requireDatabaseRoleEvidence"]) == Some(true)
            && bool_at(
                contract,
                &["readback", "requireAttestedDatabaseIdentityEvidence"],
            ) == Some(true)
            && bool_at(
                contract,
                &["readback", "requireAttestedDurableStorageEvidence"],
            ) == Some(true)
            && bool_at(
                contract,
                &["readback", "requireExactPostflightLedgerEvidence"],
            ) == Some(true)
            && bool_at(contract, &["restart", "requireMatchingApiImage"]) == Some(true)
            && bool_at(contract, &["restart", "requireVerifyOnlyStartup"]) == Some(true)
            && bool_at(contract, &["restart", "requireReadyBeforeTraffic"]) == Some(true)
            && bool_at(contract, &["restart", "requireMatchingWorkersBeforeEnable"]) == Some(true)
            && bool_at(contract, &["failure", "keepTrafficAndWritersStopped"]) == Some(true)
            && bool_at(contract, &["failure", "automaticRetryForbidden"]) == Some(true)
            && bool_at(
                contract,
                &["failure", "olderBinaryAgainstNewSchemaForbidden"],
            ) == Some(true)
            && bool_at(contract, &["failure", "forwardFixOrCoupledRestoreRequired"]) == Some(true),
        errors,
        "cutover attestation readback/restart/failure gates must fail closed before traffic returns",
    );
}

fn exact_cutover_pin_group(
    contract: &Value,
    path: &[&str],
    expected_config_map: &str,
    expected_keys: &[&str],
    expected_receipt_annotation: &str,
) -> bool {
    object_at(contract, path).is_some_and(|group| {
        object_has_exact_keys(
            group,
            &[
                "configMapName",
                "contentDigest",
                "uid",
                "resourceVersion",
                "jobReceiptAnnotation",
                "configKeys",
            ],
        )
    }) && cutover_pin_group_fields_match(
        contract,
        path,
        expected_config_map,
        expected_keys,
        expected_receipt_annotation,
    )
}

fn cutover_pin_group_fields_match(
    contract: &Value,
    path: &[&str],
    expected_config_map: &str,
    expected_keys: &[&str],
    expected_receipt_annotation: &str,
) -> bool {
    let Some(group) = value_at(contract, path) else {
        return false;
    };
    str_at(group, &["configMapName"]) == Some(expected_config_map)
        && string_array_matches_exact(group, &["configKeys"], expected_keys)
        && str_at(group, &["contentDigest"]) == Some(RENDER_REQUIRED_SENTINEL)
        && str_at(group, &["uid"]) == Some(RENDER_REQUIRED_SENTINEL)
        && str_at(group, &["resourceVersion"]) == Some(RENDER_REQUIRED_SENTINEL)
        && str_at(group, &["jobReceiptAnnotation"]) == Some(expected_receipt_annotation)
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

fn exact_migration_production_pin_env_entries(
    entries: &[&Value],
    release_digest_prefix: &str,
) -> bool {
    let expected_len = MIGRATION_APP_PIN_GROUPS
        .iter()
        .map(|(_, keys, _)| keys.len())
        .sum::<usize>();
    if entries.len() != expected_len || expected_len + 1 != MIGRATION_JOB_ENV_COUNT {
        return false;
    }

    let mut seen_names = BTreeSet::new();
    let mut entries = entries.iter();
    for (config_map_base_name, expected_keys, _) in MIGRATION_APP_PIN_GROUPS {
        let expected_config_map =
            digest_scoped_pin_config_map_name(config_map_base_name, release_digest_prefix);
        for expected_key in *expected_keys {
            let Some(entry) = entries.next() else {
                return false;
            };
            if !object(entry).is_some_and(|map| object_has_exact_keys(map, &["name", "valueFrom"]))
                || str_at(entry, &["name"]) != Some(*expected_key)
                || !seen_names.insert(*expected_key)
                || !object_at(entry, &["valueFrom"])
                    .is_some_and(|map| object_has_exact_keys(map, &["configMapKeyRef"]))
                || !object_at(entry, &["valueFrom", "configMapKeyRef"])
                    .is_some_and(|map| object_has_exact_keys(map, &["name", "key"]))
                || str_at(entry, &["valueFrom", "configMapKeyRef", "name"])
                    != Some(expected_config_map.as_str())
                || str_at(entry, &["valueFrom", "configMapKeyRef", "key"]) != Some(*expected_key)
            {
                return false;
            }
        }
    }

    entries.next().is_none() && seen_names.len() == expected_len
}

fn digest_scoped_pin_config_map_name(base_name: &str, release_digest_prefix: &str) -> String {
    format!("{base_name}-{release_digest_prefix}")
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
        format!("{owner} must retain the exact CNPG CA volume and reviewed total volume inventory"),
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
        format!(
            "{owner} must retain the exact read-only CNPG CA mount and reviewed total mount inventory"
        ),
    );
}

fn validate_migration_relay_workspace(
    pod_spec: &Value,
    container: &Value,
    errors: &mut Vec<String>,
) {
    let volumes = array_at_path(pod_spec, &["volumes"]);
    let matching_volumes: Vec<&Value> = volumes
        .iter()
        .copied()
        .filter(|volume| str_at(volume, &["name"]) == Some(POSTGRESQL_RELAY_VOLUME_NAME))
        .collect();
    let volume = matching_volumes.first().copied().unwrap_or(&Value::Null);
    let empty_dir = value_at(volume, &["emptyDir"]).unwrap_or(&Value::Null);
    let mounts = array_at_path(container, &["volumeMounts"]);
    let matching_mounts: Vec<&Value> = mounts
        .iter()
        .copied()
        .filter(|mount| str_at(mount, &["name"]) == Some(POSTGRESQL_RELAY_VOLUME_NAME))
        .collect();
    let mount = matching_mounts.first().copied().unwrap_or(&Value::Null);

    expect(
        matching_volumes.len() == 1
            && object(volume).is_some_and(|map| object_has_exact_keys(map, &["name", "emptyDir"]))
            && object(empty_dir)
                .is_some_and(|map| object_has_exact_keys(map, &["medium", "sizeLimit"]))
            && str_at(empty_dir, &["medium"]) == Some("Memory")
            && str_at(empty_dir, &["sizeLimit"]) == Some(POSTGRESQL_RELAY_SIZE_LIMIT)
            && matching_mounts.len() == 1
            && object(mount)
                .is_some_and(|map| object_has_exact_keys(map, &["name", "mountPath", "readOnly"]))
            && str_at(mount, &["mountPath"]) == Some(POSTGRESQL_RELAY_MOUNT_PATH)
            && bool_at(mount, &["readOnly"]) == Some(false),
        errors,
        "migration Job must provide exactly one 1Mi memory-backed writable PostgreSQL relay workspace",
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
        || (path.ends_with(".data.receipt.json")
            && is_canonical_socket_projection_receipt_json(value))
        || (path.ends_with(".metadata.uid") && is_canonical_kubernetes_uid(value))
        || (path.contains(".metadata.annotations.ryuki.io/pin-")
            && path.ends_with("-receipt")
            && is_canonical_pin_config_map_receipt(value))
        || (path.contains(".spec.template.spec.volumes[")
            && path.ends_with(".csi.driver")
            && value == AUTHORITY_SOCKET_CSI_DRIVER)
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

fn is_canonical_socket_projection_receipt_json(value: &str) -> bool {
    if value.len() > SOCKET_PROJECTION_MAX_RECEIPT_BYTES {
        return false;
    }
    let Ok(receipt) = crate::security_conformance::parse_json_strict(value.as_bytes()) else {
        return false;
    };
    object(&receipt)
        .is_some_and(|receipt| object_has_exact_keys(receipt, &["payload", "signature"]))
        && canonical_json_bytes(&receipt).is_ok_and(|canonical| canonical == value.as_bytes())
}

fn is_canonical_pin_config_map_receipt(value: &str) -> bool {
    let Ok(receipt) = serde_json::from_str::<Value>(value) else {
        return false;
    };
    let Some(receipt_object) = object(&receipt) else {
        return false;
    };
    object_has_exact_keys(
        receipt_object,
        &["configMapName", "uid", "resourceVersion", "contentDigest"],
    ) && str_at(&receipt, &["configMapName"]).is_some_and(|name| {
        MIGRATION_RENDER_PIN_GROUPS.iter().any(|(base_name, _, _)| {
            name.strip_prefix(&format!("{base_name}-"))
                .is_some_and(|suffix| {
                    suffix.len() == 12
                        && suffix
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
        })
    }) && str_at(&receipt, &["uid"]).is_some_and(is_canonical_kubernetes_uid)
        && str_at(&receipt, &["resourceVersion"]).is_some_and(is_canonical_resource_version)
        && str_at(&receipt, &["contentDigest"]).is_some_and(is_nonzero_sha256_digest)
        && matches!(
            (
                str_at(&receipt, &["configMapName"]),
                str_at(&receipt, &["uid"]),
                str_at(&receipt, &["resourceVersion"]),
                str_at(&receipt, &["contentDigest"]),
            ),
            (Some(name), Some(uid), Some(resource_version), Some(content_digest))
                if value == format!(
                    "{{\"configMapName\":\"{name}\",\"uid\":\"{uid}\",\"resourceVersion\":\"{resource_version}\",\"contentDigest\":\"{content_digest}\"}}"
                )
        )
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
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
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
        validate_migration_job(&[platform_api, job], None, &mut errors);
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
        validate_migration_job(&manifests, None, &mut errors);
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

        for (pointer, replacement, expected_error) in [
            (
                "/productionPinProjections/buildManifest/configMapName",
                json!(SECURITY_ADMISSION_CONFIG_MAP),
                "production pin groups",
            ),
            (
                "/productionPinProjections/renderedUnixSocketProjectionsRequired",
                json!(false),
                "production pin groups",
            ),
            (
                "/productionPinProjections/hostPathFallbackForbidden",
                json!(false),
                "production pin groups",
            ),
            (
                "/postgresqlInfrastructureAttestation/configMapName",
                json!(PUBLIC_INGRESS_ATTESTATION_CONFIG_MAP),
                "PostgreSQL infrastructure attestation",
            ),
            (
                "/postgresqlInfrastructureAttestation/sameVerifiedConnectionForDdlRequired",
                json!(false),
                "PostgreSQL infrastructure attestation",
            ),
        ] {
            let mut weakened = contract.clone();
            *weakened
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("missing contract pointer {pointer}")) = replacement;
            let mut errors = Vec::new();
            validate_cutover_contract(&weakened, &manifests, &mut errors);
            assert!(
                errors.iter().any(|error| error.contains(expected_error)),
                "weakened cutover pin projection {pointer} must fail closed: {errors:?}"
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
        validate_migration_job(&[api.clone(), job.clone()], None, &mut errors);
        assert!(
            errors.is_empty(),
            "reviewed migration Job should pass: {errors:?}"
        );

        let mut retrying = job.clone();
        retrying["spec"]["backoffLimit"] = json!(1);
        let mut errors = Vec::new();
        validate_migration_job(&[api.clone(), retrying], None, &mut errors);
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
            validate_migration_job(&[api.clone(), policy_extended], None, &mut errors);
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
        validate_migration_job(&[api.clone(), stale_identity], None, &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("derived")),
            "a stale release identity must not survive an admitted digest change: {errors:?}"
        );

        let mut missing_ca = job.clone();
        missing_ca["spec"]["template"]["spec"]["volumes"] = json!([]);
        let mut errors = Vec::new();
        validate_migration_job(&[api.clone(), missing_ca], None, &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("CNPG CA")),
            "the migration client must retain its authenticated CA mount: {errors:?}"
        );

        let mut custom_command = job.clone();
        custom_command["spec"]["template"]["spec"]["containers"][0]["args"] = json!(["migrate"]);
        let mut errors = Vec::new();
        validate_migration_job(&[api.clone(), custom_command], None, &mut errors);
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
        validate_migration_job(&[api, different_image], None, &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("exact digest-only platform-api")));
    }

    #[test]
    fn migration_job_production_pins_reject_missing_duplicate_miswired_and_inline_entries() {
        let image = format!(
            "registry.example.invalid/ryuki/platform-api@sha256:{}",
            "e".repeat(64)
        );
        let api = json!({
            "kind": "Deployment",
            "metadata": { "name": "platform-api" },
            "spec": { "template": { "spec": { "containers": [{
                "name": "platform-api",
                "image": image
            }] } } }
        });
        let job = migration_job_fixture(&image);

        let mut mutations = Vec::new();

        let mut missing_postgresql_pin = job.clone();
        let env = missing_postgresql_pin["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array_mut()
            .expect("migration env");
        let index = env
            .iter()
            .position(|entry| {
                str_at(entry, &["name"])
                    == Some("RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST")
            })
            .expect("PostgreSQL profile digest pin");
        env.remove(index);
        mutations.push(("missing PostgreSQL pin", missing_postgresql_pin));

        let mut duplicate_postgresql_pin = job.clone();
        let env = duplicate_postgresql_pin["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array_mut()
            .expect("migration env");
        let duplicate = env[env.len() - 2].clone();
        let last = env.len() - 1;
        env[last] = duplicate;
        mutations.push(("duplicate PostgreSQL pin", duplicate_postgresql_pin));

        let mut miswired_postgresql_pin = job.clone();
        let env = miswired_postgresql_pin["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array_mut()
            .expect("migration env");
        let socket = env
            .iter_mut()
            .find(|entry| {
                str_at(entry, &["name"])
                    == Some("RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET")
            })
            .expect("PostgreSQL socket pin");
        socket["valueFrom"]["configMapKeyRef"]["name"] =
            json!(PUBLIC_INGRESS_ATTESTATION_CONFIG_MAP);
        mutations.push(("miswired PostgreSQL pin", miswired_postgresql_pin));

        for (config_map, keys, _) in MIGRATION_APP_PIN_GROUPS {
            let first_key = keys
                .first()
                .copied()
                .expect("nonempty production pin group");
            let mut miswired_group = job.clone();
            let env = miswired_group["spec"]["template"]["spec"]["containers"][0]["env"]
                .as_array_mut()
                .expect("migration env");
            let entry = env
                .iter_mut()
                .find(|entry| str_at(entry, &["name"]) == Some(first_key))
                .unwrap_or_else(|| panic!("missing first pin for {config_map}"));
            entry["valueFrom"]["configMapKeyRef"]["name"] = json!("unreviewed-pin-source");
            mutations.push(("miswired production pin group", miswired_group));

            if *config_map != POSTGRESQL_INFRASTRUCTURE_ATTESTATION_CONFIG_MAP {
                let mut missing_group = job.clone();
                let env = missing_group["spec"]["template"]["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .expect("migration env");
                let index = env
                    .iter()
                    .position(|entry| str_at(entry, &["name"]) == Some(first_key))
                    .unwrap_or_else(|| panic!("missing first pin for {config_map}"));
                env.remove(index);
                mutations.push(("missing existing production pin", missing_group));

                let mut duplicate_group = job.clone();
                let env = duplicate_group["spec"]["template"]["spec"]["containers"][0]["env"]
                    .as_array_mut()
                    .expect("migration env");
                let index = env
                    .iter()
                    .position(|entry| str_at(entry, &["name"]) == Some(first_key))
                    .unwrap_or_else(|| panic!("missing first pin for {config_map}"));
                env[index + 1] = env[index].clone();
                mutations.push(("duplicate existing production pin", duplicate_group));
            }
        }

        let mut inline_postgresql_pin = job.clone();
        let env = inline_postgresql_pin["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array_mut()
            .expect("migration env");
        let key = POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEYS[1];
        let entry = env
            .iter_mut()
            .find(|entry| str_at(entry, &["name"]) == Some(key))
            .expect("PostgreSQL authority pin");
        *entry = json!({ "name": key, "value": "inline-authority" });
        mutations.push(("inline PostgreSQL pin", inline_postgresql_pin));

        for (label, invalid) in mutations {
            let mut errors = Vec::new();
            validate_migration_job(&[api.clone(), invalid], None, &mut errors);
            assert!(
                errors.iter().any(|error| error.contains("production pin")),
                "{label} must fail closed: {errors:?}"
            );
        }

        let mut host_path = job;
        host_path["spec"]["template"]["spec"]["volumes"] = json!([{
            "name": "authority-socket",
            "hostPath": { "path": "/var/run/unreviewed.sock", "type": "Socket" }
        }]);
        let mut errors = Vec::new();
        validate_migration_job(&[api, host_path], None, &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("host paths")),
            "a hostPath authority socket fallback must fail closed: {errors:?}"
        );
    }

    #[test]
    fn migration_final_render_is_contained_even_with_valid_receipts_and_socket_contract() {
        let image = format!(
            "registry.example.invalid/ryuki/platform-api@sha256:{}",
            "f".repeat(64)
        );
        let (api, job, config_maps, trust_anchor) = final_render_migration_fixture(&image);
        let mut manifests = vec![api.clone(), job.clone()];
        manifests.extend(config_maps.clone());

        let mut errors = Vec::new();
        validate_migration_job(&manifests, Some(&trust_anchor), &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| { error == FINAL_RENDER_RUNTIME_ADMISSION_UNAVAILABLE_ERROR }),
            "a structurally valid final render must still fail closed on unavailable runtime admission: {errors:?}"
        );
        assert_eq!(
            errors
                .iter()
                .filter(|error| error.as_str() != FINAL_RENDER_RUNTIME_ADMISSION_UNAVAILABLE_ERROR)
                .count(),
            0,
            "the valid diagnostic fixture should fail only because production execution is contained: {errors:?}"
        );
        assert_eq!(
            array_at_path(&job, &["spec", "template", "spec", "volumes"]).len(),
            2 + MIGRATION_AUTHORITY_SOCKET_PROJECTIONS.len(),
            "the final render must carry only the CNPG CA, bounded relay workspace, and four pinned inline CSI sockets"
        );

        let mut mutations = Vec::new();
        let mut missing_anchor = Vec::new();
        validate_migration_job(&manifests, None, &mut missing_anchor);
        assert!(
            missing_anchor
                .iter()
                .any(|error| error.contains("injected test trust anchor")),
            "final render must reject manifest-only self trust: {missing_anchor:?}"
        );

        let mut changed_pin = manifests.clone();
        changed_pin[2]["data"][PLATFORM_API_MIGRATION_CONFIG_KEYS[1]] = json!("299");
        mutations.push(("migration config substitution", changed_pin));

        let mut changed_job = manifests.clone();
        changed_job[1]["spec"]["activeDeadlineSeconds"] = json!(299);
        mutations.push(("post-sign Job substitution", changed_job));

        let mut changed_socket = manifests.clone();
        changed_socket[1]["spec"]["template"]["spec"]["volumes"][2]["csi"]["volumeAttributes"]
            ["socketPath"] = json!("/var/run/substituted/authority.sock");
        mutations.push(("socket projection substitution", changed_socket));

        let receipt_index = manifests.len() - 1;
        let mut changed_content_digest = manifests.clone();
        changed_content_digest[receipt_index]["metadata"]["annotations"]
            [CONTENT_DIGEST_ANNOTATION] = json!(format!("sha256:{}", "1".repeat(64)));
        mutations.push((
            "receipt content digest substitution",
            changed_content_digest,
        ));

        let mut changed_raw_receipt = manifests.clone();
        let raw = changed_raw_receipt[receipt_index]["data"][SOCKET_PROJECTION_RECEIPT_DATA_KEY]
            .as_str()
            .expect("raw receipt")
            .to_string();
        changed_raw_receipt[receipt_index]["data"][SOCKET_PROJECTION_RECEIPT_DATA_KEY] =
            json!(raw.replace("ed25519", "ed25518"));
        mutations.push(("raw receipt substitution", changed_raw_receipt));

        for (label, invalid) in mutations {
            let mut errors = Vec::new();
            validate_migration_job(&invalid, Some(&trust_anchor), &mut errors);
            assert!(
                errors
                    .iter()
                    .any(|error| error.as_str() != FINAL_RENDER_RUNTIME_ADMISSION_UNAVAILABLE_ERROR),
                "final render must report {label} in addition to runtime containment: {errors:?}"
            );
        }
    }

    #[test]
    fn first_owner_final_render_certificate_pins_require_closed_value_shapes() {
        assert!(is_normalized_absolute_json_path(
            "/var/run/ryuki-first-owner/closure-certificate.json"
        ));
        for invalid in [
            "closure-certificate.json",
            "/var/run/../closure-certificate.json",
            "/var/run/ryuki-first-owner/closure-certificate.txt",
            "/var//run/ryuki-first-owner/closure-certificate.json",
            r"C:\\ryuki\\closure-certificate.json",
        ] {
            assert!(
                !is_normalized_absolute_json_path(invalid),
                "invalid certificate path must fail closed: {invalid}"
            );
        }

        assert!(is_nonzero_sha256_digest(&format!(
            "sha256:{}",
            "a".repeat(64)
        )));
        for invalid in [
            format!("sha256:{}", "0".repeat(64)),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            "a".repeat(64),
        ] {
            assert!(
                !is_nonzero_sha256_digest(&invalid),
                "invalid certificate digest must fail closed: {invalid}"
            );
        }
    }

    #[test]
    fn production_documents_reject_manifest_selected_socket_trust_anchor() {
        let input = json!({
            "manifests": [],
            "socketProjectionTrustAnchor": {
                "contractId": SOCKET_PROJECTION_TRUST_ANCHOR_CONTRACT
            }
        });
        let errors = validate_values_json(&input.to_string())
            .expect("production documents input must parse");
        assert!(
            errors
                .iter()
                .any(|error| error == MANIFEST_SELECTED_TRUST_ANCHOR_FORBIDDEN_ERROR),
            "inline trust-anchor input must be rejected explicitly: {errors:?}"
        );

        let context: Context = serde_json::from_value(json!({
            "manifests": [],
            "socketProjectionTrustAnchorPath": "/tmp/render-selected-anchor.json"
        }))
        .expect("context must parse to expose the forbidden field");
        assert!(
            context
                .untrusted_socket_projection_trust_anchor_path
                .is_some(),
            "a context-selected anchor path must never be silently ignored"
        );
    }

    #[test]
    fn source_template_migration_job_is_ca_only_and_remains_suspended() {
        let image = format!(
            "registry.example.invalid/ryuki/platform-api@sha256:{}",
            "9".repeat(64)
        );
        let job = migration_job_fixture(&image);
        let volumes = array_at_path(&job, &["spec", "template", "spec", "volumes"]);
        assert_eq!(volumes.len(), 2);
        assert_eq!(str_at(volumes[0], &["name"]), Some(CNPG_CA_VOLUME_NAME));
        assert_eq!(
            str_at(volumes[1], &["name"]),
            Some(POSTGRESQL_RELAY_VOLUME_NAME)
        );
        assert_eq!(str_at(volumes[1], &["emptyDir", "medium"]), Some("Memory"));
        assert_eq!(
            str_at(&job, &["metadata", "annotations", RENDER_MODE_ANNOTATION]),
            Some(SOURCE_TEMPLATE_MODE)
        );
        let mut errors = Vec::new();
        let api = json!({
            "kind": "Deployment",
            "metadata": { "name": "platform-api" },
            "spec": { "template": { "spec": { "containers": [{
                "name": "platform-api",
                "image": image
            }] } } }
        });
        validate_migration_job(&[api, job.clone()], None, &mut errors);
        assert!(
            !errors
                .iter()
                .any(|error| error == FINAL_RENDER_RUNTIME_ADMISSION_UNAVAILABLE_ERROR),
            "the suspended source template must remain structurally valid: {errors:?}"
        );
        for (_, _, receipt_annotation) in MIGRATION_RENDER_PIN_GROUPS {
            assert_eq!(
                str_at(&job, &["metadata", "annotations", receipt_annotation]),
                Some(RENDER_REQUIRED_SENTINEL)
            );
        }
    }

    fn migration_job_fixture(image: &str) -> Value {
        let identity = MigrationIdentity::from_image(image)
            .expect("test image must produce a migration identity");
        let secret_name = identity.secret_name.clone();
        let release_digest_prefix = identity.digest_prefix.clone();
        let mut job = json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "generateName": identity.job_generate_name,
                "annotations": {
                    "ryuki.io/cutover-contract": "migration-cutover-v1",
                    "ryuki.io/release-image": image,
                    "ryuki.io/render-contract": FINAL_RENDER_CONTRACT,
                    "ryuki.io/render-mode": SOURCE_TEMPLATE_MODE,
                    "ryuki.io/pin-migration-config-receipt": RENDER_REQUIRED_SENTINEL,
                    "ryuki.io/pin-security-admission-receipt": RENDER_REQUIRED_SENTINEL,
                    "ryuki.io/pin-production-build-manifest-receipt": RENDER_REQUIRED_SENTINEL,
                    "ryuki.io/pin-conformance-trust-checkpoint-receipt": RENDER_REQUIRED_SENTINEL,
                    "ryuki.io/pin-deployed-workload-attestation-receipt": RENDER_REQUIRED_SENTINEL,
                    "ryuki.io/pin-public-ingress-attestation-receipt": RENDER_REQUIRED_SENTINEL,
                    "ryuki.io/pin-postgresql-infrastructure-attestation-receipt": RENDER_REQUIRED_SENTINEL,
                    "ryuki.io/pin-first-owner-authority-receipt": RENDER_REQUIRED_SENTINEL,
                    "ryuki.io/pin-socket-projection-authority-receipt": RENDER_REQUIRED_SENTINEL,
                    "ryuki.io/socket-projection-receipt-digest": RENDER_REQUIRED_SENTINEL,
                    "ryuki.io/socket-contract-digest": SOCKET_CONTRACT_DIGEST
                },
                "labels": {
                    "ryuki.io/release-digest-prefix": identity.digest_prefix
                }
            },
            "spec": {
                "suspend": true,
                "completions": 1,
                "parallelism": 1,
                "backoffLimit": 0,
                "activeDeadlineSeconds": 300,
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
                        "volumes": [
                            {
                                "name": CNPG_CA_VOLUME_NAME,
                                "secret": {
                                    "secretName": CNPG_CA_SECRET_NAME,
                                    "items": [{
                                        "key": CNPG_CA_SECRET_KEY,
                                        "path": CNPG_CA_SECRET_KEY
                                    }]
                                }
                            },
                            {
                                "name": POSTGRESQL_RELAY_VOLUME_NAME,
                                "emptyDir": {
                                    "medium": "Memory",
                                    "sizeLimit": POSTGRESQL_RELAY_SIZE_LIMIT
                                }
                            }
                        ],
                        "securityContext": {
                            "runAsNonRoot": true,
                            "runAsUser": 10001,
                            "runAsGroup": 10001,
                            "fsGroup": 10001,
                            "fsGroupChangePolicy": "OnRootMismatch",
                            "seccompProfile": { "type": "RuntimeDefault" }
                        },
                        "containers": [{
                            "name": MIGRATION_JOB,
                            "image": image,
                            "imagePullPolicy": "IfNotPresent",
                            "volumeMounts": [
                                {
                                    "name": CNPG_CA_VOLUME_NAME,
                                    "mountPath": CNPG_CA_MOUNT_PATH,
                                    "readOnly": true
                                },
                                {
                                    "name": POSTGRESQL_RELAY_VOLUME_NAME,
                                    "mountPath": POSTGRESQL_RELAY_MOUNT_PATH,
                                    "readOnly": false
                                }
                            ],
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
        });
        let mut env = vec![json!({
            "name": "RYUKI_MIGRATION_DATABASE_URL",
            "valueFrom": {
                "secretKeyRef": {
                    "name": secret_name,
                    "key": "RYUKI_MIGRATION_DATABASE_URL"
                }
            }
        })];
        env.extend(migration_production_pin_entries(&release_digest_prefix));
        *job.pointer_mut("/spec/template/spec/containers/0/env")
            .expect("migration Job fixture env") = Value::Array(env);
        job
    }

    fn final_render_migration_fixture(image: &str) -> (Value, Value, Vec<Value>, Value) {
        let identity = MigrationIdentity::from_image(image)
            .expect("test image must produce a migration identity");
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_base64 = BASE64_STANDARD.encode(public_key);
        let public_key_fingerprint = sha256_prefixed(&public_key);
        let authority_id = "socket-projection-authority:release-renderer";
        let key_id = "socket-projection-key:release-renderer";
        let profile_id = "socket-projection-profile:release-renderer";
        let profile_version = 3_u64;
        let profile_digest = format!("sha256:{}", "b".repeat(64));
        let min_authority_epoch = 7_u64;
        let authority_epoch = 9_u64;
        let trust_anchor = json!({
            "authorityId": authority_id,
            "contractId": SOCKET_PROJECTION_TRUST_ANCHOR_CONTRACT,
            "keyId": key_id,
            "minAuthorityEpoch": min_authority_epoch,
            "profileDigest": profile_digest,
            "profileId": profile_id,
            "profileVersion": profile_version,
            "publicKeyBase64": public_key_base64,
            "publicKeyFingerprint": public_key_fingerprint,
        });
        let api = json!({
            "kind": "Deployment",
            "metadata": { "name": "platform-api" },
            "spec": { "template": { "spec": { "containers": [{
                "name": "platform-api",
                "image": image
            }] } } }
        });
        let mut job = migration_job_fixture(image);
        job["metadata"]["annotations"][RENDER_MODE_ANNOTATION] = json!(FINAL_RENDER_MODE);
        job["spec"]["suspend"] = json!(false);
        job["spec"]["template"]["spec"]["containers"][0]["envFrom"][0]["configMapRef"]["name"] =
            json!(digest_scoped_pin_config_map_name(
                "platform-api-migration-config",
                &identity.digest_prefix,
            ));

        let mut config_maps = Vec::new();
        for (index, (base_name, keys, receipt_annotation)) in
            MIGRATION_RENDER_PIN_GROUPS.iter().enumerate()
        {
            let name = digest_scoped_pin_config_map_name(base_name, &identity.digest_prefix);
            let uid = format!("00000000-0000-4000-8000-{index:012}");
            let resource_version = (index + 101).to_string();
            let projection_index = MIGRATION_AUTHORITY_SOCKET_PROJECTIONS
                .iter()
                .position(|(projection_base, _, _, _, _, _, _)| projection_base == base_name);
            let data: Map<String, Value> = keys
                .iter()
                .enumerate()
                .map(|(key_index, key)| {
                    let value = if *base_name == "platform-api-migration-config" {
                        match *key {
                            "RYUKI_MIGRATION_MODE" => "apply-only".to_string(),
                            "RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS" => "180".to_string(),
                            "RYUKI_MIGRATION_LOCK_TIMEOUT_SECS" => "30".to_string(),
                            "RYUKI_MIGRATION_EXPECTED_ROLE" => "ryuki_schema_migrator".to_string(),
                            "RYUKI_APPLICATION_DATABASE_ROLE" => "ryuki_app_runtime".to_string(),
                            _ => unreachable!("closed migration config key inventory"),
                        }
                    } else if *base_name == SOCKET_PROJECTION_AUTHORITY_CONFIG_MAP {
                        match *key {
                            "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_AUTHORITY_ID" => {
                                authority_id.to_string()
                            }
                            "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_KEY_ID" => {
                                key_id.to_string()
                            }
                            "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_PUBLIC_KEY_BASE64" => {
                                public_key_base64.clone()
                            }
                            "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_PUBLIC_KEY_FINGERPRINT" => {
                                public_key_fingerprint.clone()
                            }
                            "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_MIN_AUTHORITY_EPOCH" => {
                                min_authority_epoch.to_string()
                            }
                            "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_PROFILE_ID" => {
                                profile_id.to_string()
                            }
                            "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_PROFILE_VERSION" => {
                                profile_version.to_string()
                            }
                            "RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_PROFILE_DIGEST" => {
                                profile_digest.clone()
                            }
                            _ => unreachable!("closed socket authority key inventory"),
                        }
                    } else if *base_name == FIRST_OWNER_AUTHORITY_CONFIG_MAP {
                        match *key {
                            "RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_PATH" => {
                                "/var/run/ryuki-first-owner/closure-certificate.json".to_string()
                            }
                            "RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST" => {
                                format!("sha256:{}", "a".repeat(64))
                            }
                            _ => format!("pin-{index}-{key_index}"),
                        }
                    } else {
                        projection_index
                            .and_then(|projection_index| {
                                let (
                                    _,
                                    socket_key,
                                    authority_id_key,
                                    key_id_key,
                                    fingerprint_key,
                                    _,
                                    authority_class,
                                ) = MIGRATION_AUTHORITY_SOCKET_PROJECTIONS[projection_index];
                                if *key == socket_key {
                                    Some(format!(
                                    "/var/run/ryuki-authorities/{authority_class}/authority.sock"
                                ))
                                } else if *key == authority_id_key {
                                    Some(format!("authority:{authority_class}"))
                                } else if *key == key_id_key {
                                    Some(format!("key:{authority_class}"))
                                } else if *key == fingerprint_key {
                                    Some(format!(
                                        "sha256:{}",
                                        char::from(b'c' + projection_index as u8)
                                            .to_string()
                                            .repeat(64)
                                    ))
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_else(|| format!("pin-{index}-{key_index}"))
                    };
                    ((*key).to_string(), json!(value))
                })
                .collect();
            let content_digest =
                canonical_config_map_data_digest(&data).expect("string-only ConfigMap data");
            let config_map = json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": name,
                    "namespace": NAMESPACE,
                    "uid": uid,
                    "resourceVersion": resource_version,
                    "labels": { "app.kubernetes.io/part-of": PART_OF },
                    "annotations": {
                        (RELEASE_DIGEST_PREFIX_ANNOTATION): identity.digest_prefix,
                        (CONTENT_DIGEST_ANNOTATION): content_digest
                    }
                },
                "immutable": true,
                "data": Value::Object(data)
            });
            job["metadata"]["annotations"][*receipt_annotation] = json!(format!(
                "{{\"configMapName\":\"{name}\",\"uid\":\"{uid}\",\"resourceVersion\":\"{resource_version}\",\"contentDigest\":\"{content_digest}\"}}"
            ));
            config_maps.push(config_map);
        }

        let mut volumes = array_at_path(&job, &["spec", "template", "spec", "volumes"])
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let fixture_container = array_at_path(&job, &["spec", "template", "spec", "containers"])[0];
        let mut mounts = array_at_path(fixture_container, &["volumeMounts"])
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        for (base_name, socket_key, _, _, _, volume_name, authority_class) in
            MIGRATION_AUTHORITY_SOCKET_PROJECTIONS
        {
            let config_map_name =
                digest_scoped_pin_config_map_name(base_name, &identity.digest_prefix);
            let config_map = config_maps
                .iter()
                .find(|config_map| {
                    str_at(config_map, &["metadata", "name"]) == Some(config_map_name.as_str())
                })
                .expect("rendered socket pin ConfigMap");
            let socket_path = str_at(config_map, &["data", socket_key])
                .expect("rendered socket path")
                .to_string();
            let mount_path = normalized_socket_mount_parent(&socket_path)
                .expect("normalized socket parent")
                .to_string();
            volumes.push(json!({
                "name": volume_name,
                "csi": {
                    "driver": AUTHORITY_SOCKET_CSI_DRIVER,
                    "readOnly": true,
                    "volumeAttributes": {
                        "environmentVariable": socket_key,
                        "authorityClass": authority_class,
                        "socketPath": socket_path
                    }
                }
            }));
            mounts.push(json!({
                "name": volume_name,
                "mountPath": mount_path,
                "readOnly": true
            }));
        }
        *job.pointer_mut("/spec/template/spec/volumes")
            .expect("migration Job fixture volumes") = Value::Array(volumes);
        *job.pointer_mut("/spec/template/spec/containers/0/volumeMounts")
            .expect("migration Job fixture volume mounts") = Value::Array(mounts);

        let now = Utc::now().timestamp();
        let payload = json!({
            "canonicalization": "ryuki-canonical-json-v1",
            "contractId": SOCKET_PROJECTION_RECEIPT_CONTRACT,
            "expiresAtUnixSeconds": now + 295,
            "notBeforeUnixSeconds": now - 5,
            "pinConfigMapReceipts": expected_socket_receipt_pin_receipts(&job)
                .expect("fixture pin receipts"),
            "receiptAuthority": {
                "authorityEpoch": authority_epoch,
                "authorityId": authority_id,
                "keyId": key_id,
                "minAuthorityEpoch": min_authority_epoch,
                "profileDigest": profile_digest,
                "profileId": profile_id,
                "profileVersion": profile_version,
                "publicKeyFingerprint": public_key_fingerprint,
            },
            "releaseDigestPrefix": identity.digest_prefix,
            "releaseImage": image,
            "renderedJobPreimageDigest": rendered_job_preimage_digest(&job)
                .expect("fixture Job preimage"),
            "socketContractDigest": SOCKET_CONTRACT_DIGEST,
            "socketProjections": expected_socket_receipt_projections(&config_maps, &identity)
                .expect("fixture socket projections"),
        });
        let canonical_payload = canonical_json_bytes(&payload).expect("canonical fixture payload");
        let signature = signing_key.sign(&socket_projection_signing_bytes(&canonical_payload));
        let receipt = json!({
            "payload": payload,
            "signature": {
                "algorithm": "ed25519",
                "signatureBase64": BASE64_STANDARD.encode(signature.to_bytes()),
            }
        });
        let raw_receipt =
            String::from_utf8(canonical_json_bytes(&receipt).expect("canonical fixture receipt"))
                .expect("canonical JSON is UTF-8");
        let receipt_digest = sha256_prefixed(raw_receipt.as_bytes());
        job["metadata"]["annotations"][SOCKET_PROJECTION_RECEIPT_DIGEST_ANNOTATION] =
            json!(receipt_digest);
        let receipt_name = socket_projection_receipt_config_map_name(&receipt_digest)
            .expect("content-addressed receipt name");
        let receipt_data = Map::from_iter([(
            SOCKET_PROJECTION_RECEIPT_DATA_KEY.to_string(),
            json!(raw_receipt),
        )]);
        let receipt_content_digest =
            canonical_config_map_data_digest(&receipt_data).expect("receipt content digest");
        config_maps.push(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": receipt_name,
                "namespace": NAMESPACE,
                "labels": { "app.kubernetes.io/part-of": PART_OF },
                "annotations": {
                    (RELEASE_DIGEST_PREFIX_ANNOTATION): identity.digest_prefix,
                    (CONTENT_DIGEST_ANNOTATION): receipt_content_digest,
                    (SOCKET_PROJECTION_RECEIPT_RAW_DIGEST_ANNOTATION): receipt_digest,
                }
            },
            "immutable": true,
            "data": Value::Object(receipt_data),
        }));

        (api, job, config_maps, trust_anchor)
    }

    fn migration_production_pin_entries(release_digest_prefix: &str) -> Vec<Value> {
        MIGRATION_APP_PIN_GROUPS
            .iter()
            .flat_map(|(config_map, keys, _)| {
                let config_map =
                    digest_scoped_pin_config_map_name(config_map, release_digest_prefix);
                keys.iter().map(move |key| {
                    json!({
                        "name": key,
                        "valueFrom": {
                            "configMapKeyRef": {
                                "name": config_map,
                                "key": key
                            }
                        }
                    })
                })
            })
            .collect()
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

    fn release_image_binding_fixture(api_digest: &str, portal_digest: &str) -> Vec<Value> {
        vec![
            json!({
                "kind": "Deployment",
                "metadata": { "name": "platform-api" },
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{
                                "name": "platform-api",
                                "image": format!("ghcr.io/example/ryuki-platform-api@sha256:{api_digest}")
                            }]
                        }
                    }
                }
            }),
            json!({
                "kind": "Deployment",
                "metadata": { "name": "portal-ui" },
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{
                                "name": "portal-ui",
                                "image": format!("ghcr.io/example/ryuki-portal-ui@sha256:{portal_digest}")
                            }]
                        }
                    }
                }
            }),
        ]
    }

    #[test]
    fn release_image_render_binds_exact_published_image_digests() {
        let api_digest = "a".repeat(64);
        let portal_digest = "b".repeat(64);
        let manifests = release_image_binding_fixture(&api_digest, &portal_digest);
        let mut errors = Vec::new();
        validate_release_image_binding(
            &manifests,
            &format!("sha256:{api_digest}"),
            &format!("sha256:{portal_digest}"),
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "exact post-publication image digests must be admitted: {errors:?}"
        );

        let mut equal_digest_errors = Vec::new();
        validate_release_image_binding(
            &manifests,
            &format!("sha256:{api_digest}"),
            &format!("sha256:{api_digest}"),
            &mut equal_digest_errors,
        );
        assert!(
            equal_digest_errors
                .iter()
                .any(|error| error.contains("must be distinct")),
            "collapsed API/portal publisher outputs must fail closed: {equal_digest_errors:?}"
        );
    }

    #[test]
    fn release_image_render_rejects_portal_digest_and_registry_mutations() {
        let api_digest = "a".repeat(64);
        let portal_digest = "b".repeat(64);
        let expected_api = format!("sha256:{api_digest}");
        let expected_portal = format!("sha256:{portal_digest}");
        let valid = release_image_binding_fixture(&api_digest, &portal_digest);

        let mut cases = Vec::new();
        let mut missing = valid.clone();
        missing[1]["spec"]["template"]["spec"]["containers"][0]
            .as_object_mut()
            .expect("portal container")
            .remove("image");
        cases.push(("missing", missing, expected_portal.clone()));

        let mut reserved = valid.clone();
        reserved[1]["spec"]["template"]["spec"]["containers"][0]["image"] = json!(format!(
            "registry.example.invalid/ryuki/portal-ui@sha256:{portal_digest}"
        ));
        cases.push(("reserved registry", reserved, expected_portal.clone()));

        let mut reserved_port = valid.clone();
        reserved_port[1]["spec"]["template"]["spec"]["containers"][0]["image"] = json!(format!(
            "registry.example.invalid:443/ryuki/portal-ui@sha256:{portal_digest}"
        ));
        cases.push((
            "reserved registry with port",
            reserved_port,
            expected_portal.clone(),
        ));

        let mut zero = valid.clone();
        zero[1]["spec"]["template"]["spec"]["containers"][0]["image"] = json!(format!(
            "ghcr.io/example/ryuki-portal-ui@sha256:{}",
            "0".repeat(64)
        ));
        cases.push(("zero", zero, expected_portal.clone()));

        let mut sentinel = valid.clone();
        sentinel[1]["spec"]["template"]["spec"]["containers"][0]["image"] =
            json!("RENDER_REQUIRED");
        cases.push(("sentinel", sentinel, expected_portal.clone()));

        let mut mismatch = valid.clone();
        mismatch[1]["spec"]["template"]["spec"]["containers"][0]["image"] = json!(format!(
            "ghcr.io/example/ryuki-portal-ui@sha256:{}",
            "c".repeat(64)
        ));
        cases.push(("mismatched", mismatch, expected_portal.clone()));
        cases.push(("missing expected", valid, String::new()));

        for (label, manifests, expected_portal) in cases {
            let mut errors = Vec::new();
            validate_release_image_binding(
                &manifests,
                &expected_api,
                &expected_portal,
                &mut errors,
            );
            assert!(
                !errors.is_empty(),
                "release-image-render portal mutation {label} must fail closed"
            );
        }
    }

    #[test]
    fn release_image_render_rejects_non_mapping_documents() {
        let path = std::env::temp_dir().join(format!(
            "ryuki-release-image-render-non-mapping-{}.yaml",
            std::process::id()
        ));
        fs::write(&path, "scalar-document\n").expect("write non-mapping release render fixture");
        let errors = validate_release_image_render_file(
            &path,
            &format!("sha256:{}", "a".repeat(64)),
            &format!("sha256:{}", "b".repeat(64)),
        )
        .expect("non-mapping YAML remains parseable for fail-closed validation");
        let _ = fs::remove_file(&path);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("only mapping documents")),
            "a scalar YAML document must not be filtered out: {errors:?}"
        );
    }

    #[test]
    fn checked_in_release_renderer_is_deterministic_and_admissible() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let suffix = std::process::id();
        let first =
            std::env::temp_dir().join(format!("ryuki-release-image-render-{suffix}-first.yaml"));
        let second =
            std::env::temp_dir().join(format!("ryuki-release-image-render-{suffix}-second.yaml"));
        let api_digest = format!("sha256:{}", "a".repeat(64));
        let portal_digest = format!("sha256:{}", "b".repeat(64));

        for output in [&first, &second] {
            let status = std::process::Command::new("bash")
                .arg(root.join("scripts/release/render-kubernetes-images-v1.sh"))
                .args(["--root"])
                .arg(&root)
                .args(["--output"])
                .arg(output)
                .arg("--api-repository")
                .arg("ghcr.io/example/ryuki-platform-api")
                .arg("--api-digest")
                .arg(&api_digest)
                .arg("--portal-repository")
                .arg("ghcr.io/example/ryuki-portal-ui")
                .arg("--portal-digest")
                .arg(&portal_digest)
                .status()
                .expect("execute checked-in release renderer");
            assert!(status.success(), "checked-in release renderer must succeed");
        }

        let first_bytes = fs::read(&first).expect("read first release render");
        let second_bytes = fs::read(&second).expect("read second release render");
        assert_eq!(
            first_bytes, second_bytes,
            "same inputs must produce byte-identical release renders"
        );
        let errors = validate_release_image_render_file(&first, &api_digest, &portal_digest)
            .expect("validate checked-in release render");
        let _ = fs::remove_file(&first);
        let _ = fs::remove_file(&second);
        assert!(
            errors.is_empty(),
            "checked-in renderer output must satisfy the full manifest and exact image binding contracts: {errors:?}"
        );
    }
}
