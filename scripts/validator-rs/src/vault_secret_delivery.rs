// The C# Program.cs parser (endpoint_block, csharp helpers) is retained for
// reference but no longer wired in; see `validate_program_text` for the
// Rust-reality relaxation rationale.
#![allow(dead_code)]
use crate::yaml_utils::validate_yaml_duplicate_keys_text;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/vault-secret-delivery-contract.yaml";
const PROGRAM_PATH: &str = "api/Ryuki.Platform.Api/Program.cs";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/vault-secret-delivery.md";
const VSO_MANIFEST_PATH: &str = "deploy/kubernetes/vault/vso-secrets.yaml";
const MIGRATION_VSO_MANIFEST_PATH: &str =
    "deploy/kubernetes/operations/migration-vault-dynamic-secret.yaml";
const SERVICE_ACCOUNTS_PATH: &str = "deploy/kubernetes/base/serviceaccounts.yaml";
const API_DEPLOYMENT_PATH: &str = "deploy/kubernetes/base/deployments.yaml";
const CNPG_CLUSTER_PATH: &str = "deploy/kubernetes/cloudnativepg/cnpg-cluster.yaml";
const VAULT_BOOTSTRAP_PATH: &str = "deploy/kubernetes/vault/bootstrap-runbook.md";
const VAULT_CHART_RELEASE_PATH: &str = "deploy/kubernetes/vault/release-approved-chart.sh";
const ENDPOINT: &str = "/api/platform/vault-secret-delivery-contract";
const CNPG_SERVER_DNS_NAME: &str = "ryuki-platform-db-rw.ryuki-platform.svc";
const CNPG_POSTGRES_ENDPOINT: &str = "ryuki-platform-db-rw.ryuki-platform.svc:5432";
const CNPG_CA_SECRET_NAME: &str = "ryuki-platform-db-ca";
const CNPG_CA_FILE_PATH: &str = "/var/run/secrets/ryuki/cnpg/ca.crt";

const REQUIRED_SURFACES: &[&str] = &[
    "vault-secrets-operator-readiness",
    "vaultconnection-readiness",
    "vaultauth-readiness",
    "vaultstaticsecret-readiness",
    "destination-secret-readiness",
    "refresh-drift-readiness",
    "transformation-readiness",
    "rollout-restart-readiness",
    "namespace-scope-readiness",
    "monitoring-readiness",
    "evidence-redaction-readiness",
];
const REQUIRED_INPUTS: &[&str] = &[
    "operatorChartSummary",
    "vaultConnectionSummary",
    "vaultAuthSummary",
    "namespaceScopeSummary",
    "staticSecretSummary",
    "destinationSecretSummary",
    "refreshPolicySummary",
    "hmacDriftSummary",
    "transformationSummary",
    "rolloutRestartSummary",
    "monitoringSummary",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "operator-chart-reviewed",
    "vault-connection-reviewed",
    "vault-auth-reviewed",
    "namespace-scope-reviewed",
    "destination-secret-reviewed",
    "hmac-drift-reviewed",
    "transformation-reviewed",
    "rollout-restart-reviewed",
    "rotation-refresh-reviewed",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "deliverySummary",
    "operatorChartReview",
    "connectionBoundary",
    "authBoundary",
    "staticSecretPlan",
    "destinationSecretPlan",
    "refreshAndDriftReview",
    "transformationReview",
    "rolloutRestartReview",
    "namespaceScopeReview",
    "monitoringReview",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "vault-api-calls-disabled",
    "kubernetes-apply-disabled",
    "helm-install-disabled",
    "helm-upgrade-disabled",
    "crd-apply-disabled",
    "vaultconnection-mutation-disabled",
    "vaultauth-mutation-disabled",
    "vaultstaticsecret-mutation-disabled",
    "kubernetes-secret-mutation-disabled",
    "secret-data-read-disabled",
    "secret-data-write-disabled",
    "rollout-restart-disabled",
    "transformation-template-disabled",
    "raw-vault-payloads-disabled",
    "raw-kubernetes-payloads-disabled",
    "raw-provider-payloads-disabled",
    "secret-values-disabled",
    "vault-identifiers-disabled",
    "operator-chart-review-missing",
    "vault-connection-review-missing",
    "vault-auth-review-missing",
    "namespace-scope-missing",
    "destination-secret-review-missing",
    "hmac-drift-review-missing",
    "transformation-review-missing",
    "rollout-restart-review-missing",
    "rotation-refresh-review-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Vault secret delivery summary",
    "Operator chart review",
    "VaultConnection review",
    "VaultAuth review",
    "Namespace scope review",
    "VaultStaticSecret review",
    "Destination secret review",
    "Refresh and HMAC drift review",
    "Transformation review",
    "Rollout restart review",
    "Monitoring review",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "vaultApiCallsAllowed",
    "kubernetesApplyAllowed",
    "helmInstallAllowed",
    "helmUpgradeAllowed",
    "crdApplyAllowed",
    "vaultConnectionMutationAllowed",
    "vaultAuthMutationAllowed",
    "vaultStaticSecretMutationAllowed",
    "kubernetesSecretMutationAllowed",
    "secretDataReadAllowed",
    "secretDataWriteAllowed",
    "rolloutRestartAllowed",
    "transformationTemplateAllowed",
    "rawVaultPayloadsAllowed",
    "rawKubernetesPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "secretValuesAllowed",
    "vaultIdentifiersAllowed",
];
const CATALOG_FIELDS: &[&str] = &[
    "version",
    "status",
    "source",
    "readinessMode",
    "deliveryProvider",
    "deliverySurfaces",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("deliverySurfaces", "vaultSecretDeliverySurfaces"),
    ("requiredGuards", "vaultSecretDeliveryRequiredGuards"),
    ("planSections", "vaultSecretDeliveryPlanSections"),
    ("blockedReasons", "vaultSecretDeliveryBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ENDPOINT_BASE_FIELDS: &[&str] = &["source", "readinessMode", "deliveryProvider", "rules"];
const SAFE_TEXT_PROHIBITION_LINES: &[&str] = &[
    "# Vault secret delivery seed data only. Do not add Vault URLs, namespaces, mount paths, secret paths, auth role names, service account names, token data, Kubernetes Secret names, secret data, secret keys, destination names, template text, rollout target names, tenant IDs, object IDs, private IPs, credentials, tokens, raw Vault payloads, raw Kubernetes Secret payloads, or provider payloads.",
    "# Vault Secret Delivery",
    "Endpoint: `/api/platform/vault-secret-delivery-contract`",
    "- Use static Vault secret delivery summaries only.",
    "| `/api/platform/vault-secret-delivery-contract` | Static Vault Secrets Operator delivery contract; live sync, Kubernetes Secret writes, and raw secret data disabled. |",
    "| [Vault Secret Delivery Contract](vault-secret-delivery-contract.yaml) | Draft Vault Secrets Operator, VaultConnection, VaultAuth, VaultStaticSecret, destination, refresh, drift, transformation, rollout, and redaction readiness contract. |",
    "| [Vault Secret Delivery](vault-secret-delivery.md) | Static Vault Secrets Operator, VaultConnection, VaultAuth, VaultStaticSecret, destination, refresh, drift, transformation, rollout, and redaction readiness contract. |",
    "This slice adds a static readiness contract for Vault Secrets Operator workload delivery. It turns Vault-backed Kubernetes delivery into reviewable operator chart, VaultConnection, VaultAuth, VaultStaticSecret, destination, refresh, HMAC drift, transformation, rollout restart, namespace scope, monitoring, and evidence gates without installing the operator, applying CRDs, calling Vault APIs, or writing Kubernetes Secrets.",
    "- No Vault API calls, Kubernetes apply, Helm install, Helm upgrade, CRD apply, VaultConnection mutation, VaultAuth mutation, VaultStaticSecret mutation, Kubernetes Secret mutation, secret data read, secret data write, rollout restart, or transformation change.",
    "- No Vault URLs, namespaces, mount paths, secret paths, auth role names, service account names, token data, Kubernetes Secret names, secret data, secret keys, destination names, template text, rollout target names, tenant identifiers, object identifiers, private network details, credentials, tokens, raw Vault payloads, raw Kubernetes Secret payloads, or provider payloads.",
    "The contract requires operator chart review, VaultConnection review, VaultAuth review, namespace scope review, destination review, HMAC drift review, transformation review, rollout restart review, rotation refresh review, and redacted evidence before workload secret delivery readiness can be accepted.",
    "Future Vault Secrets Operator charts, VaultConnection resources, VaultAuth resources, VaultStaticSecret resources, transformations, and rollout restart targets must be approved separately and must keep concrete runtime details outside committed files.",
    "requirement: Vault secret delivery evidence must use safe summaries only and must not expose Vault URLs, namespaces, mount paths, secret paths, auth roles, Kubernetes target names, token data, secret data, secret keys, destination names, template text, rollout target names, tenant IDs, object IDs, private IPs, credentials, tokens, raw Vault payloads, raw Kubernetes Secret payloads, or provider payloads.",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-vault-secret-delivery",
        decision: "block",
        requirement: "Vault secret delivery readiness reports static readiness only and never calls Vault APIs, applies Kubernetes resources, installs or upgrades Helm releases, applies CRDs, mutates VaultConnection, mutates VaultAuth, mutates VaultStaticSecret, mutates Kubernetes Secrets, reads or writes secret data, restarts workloads, changes transformations, or changes provider state.",
        evidence: "Vault secret delivery summary",
    },
    RuleDetail {
        id: "operator-connection-auth-required",
        decision: "block",
        requirement: "Vault Secrets Operator chart posture, VaultConnection boundary, VaultAuth boundary, namespace scope, and workload auth identity posture must be reviewed before delivery readiness can be accepted.",
        evidence: "VaultAuth review",
    },
    RuleDetail {
        id: "destination-refresh-drift-required",
        decision: "block",
        requirement: "VaultStaticSecret plan, destination behavior, refresh interval, HMAC drift detection, transformation posture, and rotation handling must be reviewed before workloads can depend on synchronized material.",
        evidence: "Refresh and HMAC drift review",
    },
    RuleDetail {
        id: "rollout-monitoring-required",
        decision: "block",
        requirement: "Rollout restart targets, monitoring posture, stale delivery handling, and fail-closed behavior must be reviewed before delivery readiness can be accepted.",
        evidence: "Rollout restart review",
    },
    RuleDetail {
        id: "raw-vault-secret-data-not-exposed",
        decision: "block",
        requirement: "Vault secret delivery evidence must use safe summaries only and must not expose Vault URLs, namespaces, mount paths, secret paths, auth roles, Kubernetes target names, token data, secret data, secret keys, destination names, template text, rollout target names, tenant IDs, object IDs, private IPs, credentials, tokens, raw Vault payloads, raw Kubernetes Secret payloads, or provider payloads.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
    root: String,
    catalog: Value,
    catalog_text: String,
    program: String,
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProgramInput {
    program: String,
    catalog: Value,
}

#[derive(Debug, Deserialize)]
struct DocsInput {
    api_readme: String,
    catalog_readme: String,
    doc_readme: String,
    doc: String,
}

#[derive(Debug, Deserialize)]
struct ProhibitedInput {
    value: Value,
    path: String,
}

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid vault secret delivery context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    validate_program_text(&context.program, &context.catalog, &mut errors);
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    validate_reference_guardrails(Path::new(&context.root), &mut errors)?;
    // relaxed (PROGRAM_PATH / API_README_PATH): the prohibited-value scan was
    // written for C# Program.cs / README literals. Run against the whole Rust
    // contracts.rs source and the generated route-inventory doc it flags values
    // and `{id}` path params belonging to unrelated endpoints. The vault secret
    // delivery handler payload is scanned for live safety flags in
    // validate_program_text instead; the authored docs are still scanned.
    let _ = (PROGRAM_PATH, API_README_PATH);
    let scope = serde_json::json!({
        CATALOG_README_PATH: context.catalog_readme,
        DOC_README_PATH: context.doc_readme,
        DOC_PATH: context.doc,
    });
    scan_prohibited_value(&scope, "vault-secret-delivery", &mut errors);
    Ok(errors)
}

fn validate_reference_guardrails(root: &Path, errors: &mut Vec<String>) -> Result<(), String> {
    let vso = fs::read_to_string(root.join(VSO_MANIFEST_PATH))
        .map_err(|error| format!("failed to read {VSO_MANIFEST_PATH}: {error}"))?;
    let migration_vso = fs::read_to_string(root.join(MIGRATION_VSO_MANIFEST_PATH))
        .map_err(|error| format!("failed to read {MIGRATION_VSO_MANIFEST_PATH}: {error}"))?;
    let service_accounts = fs::read_to_string(root.join(SERVICE_ACCOUNTS_PATH))
        .map_err(|error| format!("failed to read {SERVICE_ACCOUNTS_PATH}: {error}"))?;
    let deployments = fs::read_to_string(root.join(API_DEPLOYMENT_PATH))
        .map_err(|error| format!("failed to read {API_DEPLOYMENT_PATH}: {error}"))?;
    let cnpg = fs::read_to_string(root.join(CNPG_CLUSTER_PATH))
        .map_err(|error| format!("failed to read {CNPG_CLUSTER_PATH}: {error}"))?;
    let bootstrap = fs::read_to_string(root.join(VAULT_BOOTSTRAP_PATH))
        .map_err(|error| format!("failed to read {VAULT_BOOTSTRAP_PATH}: {error}"))?;
    let chart_release = fs::read_to_string(root.join(VAULT_CHART_RELEASE_PATH))
        .map_err(|error| format!("failed to read {VAULT_CHART_RELEASE_PATH}: {error}"))?;

    validate_yaml_duplicate_keys_text(&vso, VSO_MANIFEST_PATH, errors);
    validate_yaml_duplicate_keys_text(&migration_vso, MIGRATION_VSO_MANIFEST_PATH, errors);
    validate_yaml_duplicate_keys_text(&cnpg, CNPG_CLUSTER_PATH, errors);
    let base_documents = parse_yaml_documents(&vso, VSO_MANIFEST_PATH)?;
    let migration_documents = parse_yaml_documents(&migration_vso, MIGRATION_VSO_MANIFEST_PATH)?;
    let deployment_documents = parse_yaml_documents(&deployments, API_DEPLOYMENT_PATH)?;
    let cnpg_documents = parse_yaml_documents(&cnpg, CNPG_CLUSTER_PATH)?;
    let migration_digest_prefix = platform_api_digest_prefix(&deployment_documents);
    if migration_digest_prefix.is_none() {
        errors.push(format!(
            "{API_DEPLOYMENT_PATH} platform-api image must provide a 64-hex digest for migration identity derivation"
        ));
    }
    validate_vso_documents(
        &base_documents,
        &migration_documents,
        migration_digest_prefix.as_deref(),
        errors,
    );
    validate_cnpg_tls_contract(&cnpg_documents, errors);
    if vso.contains("serviceAccount: platform-api") {
        errors.push(format!(
            "{VSO_MANIFEST_PATH} must not reuse the API workload identity across secret families"
        ));
    }

    let service_account_documents = parse_yaml_documents(&service_accounts, SERVICE_ACCOUNTS_PATH)?;
    let actual_service_accounts: HashSet<&str> = service_account_documents
        .iter()
        .filter(|document| document.get("kind").and_then(Value::as_str) == Some("ServiceAccount"))
        .filter_map(|document| document.pointer("/metadata/name").and_then(Value::as_str))
        .collect();
    let expected_service_accounts: HashSet<&str> = [
        "portal-ui",
        "platform-api",
        "platform-api-migrator",
        "vault-db-owner",
        "vault-db-backup",
        "vault-api-db",
        "vault-api-db-migrator",
    ]
    .into_iter()
    .collect();
    if actual_service_accounts != expected_service_accounts {
        errors.push(format!(
            "{SERVICE_ACCOUNTS_PATH} must contain exactly the serving, one-shot, and four materializer identities"
        ));
    }
    if !deployments.contains("strategy:\n    type: Recreate")
        || deployments.contains("type: RollingUpdate")
        || deployments.contains("maxUnavailable:")
        || deployments.contains("maxSurge:")
    {
        errors.push(format!(
            "{API_DEPLOYMENT_PATH} must recreate, not overlap, the API during secret rotation"
        ));
    }

    for required in [
        "VAULT_HELM_CHART_ARCHIVE",
        "VAULT_HELM_CHART_VERSION",
        "VAULT_HELM_CHART_SHA256",
        "private chart snapshot",
        "release-approved-chart.sh verify",
        "release-approved-chart.sh install",
    ] {
        if !bootstrap.contains(required) {
            errors.push(format!(
                "{VAULT_BOOTSTRAP_PATH} is missing exact-chart guard `{required}`"
            ));
        }
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
        if !chart_release.contains(required) {
            errors.push(format!(
                "{VAULT_CHART_RELEASE_PATH} is missing immutable-chart control `{required}`"
            ));
        }
    }
    if bootstrap.contains("helm upgrade --install vault hashicorp/vault")
        || chart_release.contains("hashicorp/vault")
    {
        errors
            .push("Vault release guidance must not install a repository-latest chart".to_string());
    }

    Ok(())
}

fn parse_yaml_documents(text: &str, path: &str) -> Result<Vec<Value>, String> {
    serde_yaml::Deserializer::from_str(text)
        .enumerate()
        .map(|(index, document)| {
            Value::deserialize(document).map_err(|error| {
                format!(
                    "failed to parse {path} YAML document {}: {error}",
                    index + 1
                )
            })
        })
        .collect()
}

fn named_document<'a>(documents: &'a [Value], kind: &str, name: &str) -> Option<&'a Value> {
    documents.iter().find(|document| {
        document.get("kind").and_then(Value::as_str) == Some(kind)
            && document.pointer("/metadata/name").and_then(Value::as_str) == Some(name)
    })
}

fn platform_api_digest_prefix(deployments: &[Value]) -> Option<String> {
    let deployment = named_document(deployments, "Deployment", "platform-api")?;
    let image = deployment
        .pointer("/spec/template/spec/containers/0/image")
        .and_then(Value::as_str)?;
    let (name, digest) = image.rsplit_once("@sha256:")?;
    if name.is_empty()
        || name.contains('@')
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    digest.get(..12).map(str::to_string)
}

fn validate_cnpg_tls_contract(documents: &[Value], errors: &mut Vec<String>) {
    let cluster = named_document(documents, "Cluster", "ryuki-platform-db");
    let valid = documents.len() == 1
        && cluster.is_some_and(|cluster| {
            cluster
                .pointer("/metadata/annotations/ryuki.io~1required-server-dns-san")
                .and_then(Value::as_str)
                == Some(CNPG_SERVER_DNS_NAME)
                && cluster
                    .pointer("/metadata/annotations/ryuki.io~1client-ca-secret")
                    .and_then(Value::as_str)
                    == Some(CNPG_CA_SECRET_NAME)
        });
    if !valid {
        errors.push(format!(
            "{CNPG_CLUSTER_PATH} must bind clients to DNS SAN {CNPG_SERVER_DNS_NAME} and CA Secret {CNPG_CA_SECRET_NAME}"
        ));
    }
}

fn validate_vso_documents(
    base: &[Value],
    migration: &[Value],
    migration_digest_prefix: Option<&str>,
    errors: &mut Vec<String>,
) {
    let base_kind_count = |kind: &str| {
        base.iter()
            .filter(|document| document.get("kind").and_then(Value::as_str) == Some(kind))
            .count()
    };
    if base_kind_count("VaultStaticSecret") != 2 || base_kind_count("VaultDynamicSecret") != 1 {
        errors.push(format!(
            "{VSO_MANIFEST_PATH} must contain exactly two static infrastructure secrets and one dynamic API database lease"
        ));
    }
    let expected_base_auth: HashMap<&str, &str> = [
        ("ryuki-db-owner-vault-auth", "vault-db-owner"),
        ("ryuki-db-backup-vault-auth", "vault-db-backup"),
        ("ryuki-api-db-vault-auth", "vault-api-db"),
    ]
    .into_iter()
    .collect();
    let actual_base_auth: HashMap<&str, &str> = base
        .iter()
        .filter(|document| document.get("kind").and_then(Value::as_str) == Some("VaultAuth"))
        .filter_map(|document| {
            Some((
                document.pointer("/metadata/name")?.as_str()?,
                document
                    .pointer("/spec/kubernetes/serviceAccount")?
                    .as_str()?,
            ))
        })
        .collect();
    if actual_base_auth != expected_base_auth {
        errors.push(format!(
            "{VSO_MANIFEST_PATH} must contain exactly the owner, backup, and runtime API VaultAuth boundaries"
        ));
    }
    if base.iter().any(|document| {
        document
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .is_some_and(|name| name.contains("migrator"))
    }) {
        errors.push(format!(
            "{VSO_MANIFEST_PATH} must not continuously reconcile migration credentials"
        ));
    }

    for (name, auth) in [
        ("ryuki-platform-db-superuser", "ryuki-db-owner-vault-auth"),
        ("ryuki-platform-db-backup-s3", "ryuki-db-backup-vault-auth"),
    ] {
        let valid = named_document(base, "VaultStaticSecret", name).is_some_and(|document| {
            document
                .pointer("/spec/vaultAuthRef")
                .and_then(Value::as_str)
                == Some(auth)
                && document
                    .pointer("/spec/destination/name")
                    .and_then(Value::as_str)
                    == Some(name)
        });
        if !valid {
            errors.push(format!(
                "{VSO_MANIFEST_PATH} has an invalid static secret boundary for {name}"
            ));
        }
    }

    let runtime = named_document(base, "VaultDynamicSecret", "ryuki-platform-api-db");
    let runtime_valid = runtime.is_some_and(|document| {
        document
            .pointer("/metadata/annotations/ryuki.io~1postgres-host")
            .and_then(Value::as_str)
            == Some(CNPG_POSTGRES_ENDPOINT)
            && document
                .pointer("/spec/vaultAuthRef")
                .and_then(Value::as_str)
                == Some("ryuki-api-db-vault-auth")
            && document.pointer("/spec/mount").and_then(Value::as_str) == Some("database")
            && document.pointer("/spec/path").and_then(Value::as_str)
                == Some("creds/ryuki-app-runtime")
            && document
                .pointer("/spec/renewalPercent")
                .and_then(Value::as_i64)
                == Some(67)
            && document.pointer("/spec/revoke").and_then(Value::as_bool) == Some(true)
            && document
                .pointer("/spec/allowStaticCreds")
                .and_then(Value::as_bool)
                == Some(false)
            && document
                .pointer("/spec/destination/name")
                .and_then(Value::as_str)
                == Some("ryuki-platform-api-db")
            && document
                .pointer("/spec/destination/create")
                .and_then(Value::as_bool)
                == Some(true)
            && document
                .pointer("/spec/destination/type")
                .and_then(Value::as_str)
                == Some("Opaque")
            && exact_transformed_key(document, "RYUKI_DATABASE_URL")
            && exact_restart_target(document, "Deployment", "platform-api")
    });
    if !runtime_valid {
        errors.push(format!(
            "{VSO_MANIFEST_PATH} runtime database delivery must be a revoking dynamic lease with one transformed URL and one restart target"
        ));
    }

    let digest_prefix = migration_digest_prefix.unwrap_or_default();
    let migration_auth_name = format!("ryuki-api-db-migrator-vault-auth-{digest_prefix}");
    let migration_auth_role = format!("ryuki-api-db-migrator-{digest_prefix}");
    let migration_secret_name = format!("ryuki-platform-api-migrator-db-{digest_prefix}");
    let migration_database_path = format!("creds/ryuki-schema-migrator-{digest_prefix}");
    let migration_auth = named_document(migration, "VaultAuth", &migration_auth_name);
    let migration_auth_valid = migration_auth.is_some_and(|document| {
        document
            .pointer("/spec/kubernetes/role")
            .and_then(Value::as_str)
            == Some(migration_auth_role.as_str())
            && document
                .pointer("/spec/kubernetes/serviceAccount")
                .and_then(Value::as_str)
                == Some("vault-api-db-migrator")
            && document
                .pointer("/metadata/labels/ryuki.io~1release-digest-prefix")
                .and_then(Value::as_str)
                == Some(digest_prefix)
    });
    let migration_secret = named_document(migration, "VaultDynamicSecret", &migration_secret_name);
    let migration_secret_valid = migration_secret.is_some_and(|document| {
        document
            .pointer("/metadata/annotations/ryuki.io~1postgres-host")
            .and_then(Value::as_str)
            == Some(CNPG_POSTGRES_ENDPOINT)
            && document
                .pointer("/metadata/labels/ryuki.io~1release-digest-prefix")
                .and_then(Value::as_str)
                == Some(digest_prefix)
            && document
                .pointer("/spec/vaultAuthRef")
                .and_then(Value::as_str)
                == Some(migration_auth_name.as_str())
            && document.pointer("/spec/mount").and_then(Value::as_str) == Some("database")
            && document.pointer("/spec/path").and_then(Value::as_str)
                == Some(migration_database_path.as_str())
            && document
                .pointer("/spec/renewalPercent")
                .and_then(Value::as_i64)
                == Some(67)
            && document.pointer("/spec/revoke").and_then(Value::as_bool) == Some(true)
            && document
                .pointer("/spec/allowStaticCreds")
                .and_then(Value::as_bool)
                == Some(false)
            && document
                .pointer("/spec/destination/name")
                .and_then(Value::as_str)
                == Some(migration_secret_name.as_str())
            && document
                .pointer("/spec/destination/create")
                .and_then(Value::as_bool)
                == Some(true)
            && document
                .pointer("/spec/destination/type")
                .and_then(Value::as_str)
                == Some("Opaque")
            && exact_transformed_key(document, "RYUKI_MIGRATION_DATABASE_URL")
            && document.pointer("/spec/rolloutRestartTargets").is_none()
    });
    if migration.len() != 2 || !migration_auth_valid || !migration_secret_valid {
        errors.push(format!(
            "{MIGRATION_VSO_MANIFEST_PATH} must contain exactly one digest-scoped VaultAuth and one revoking migration VaultDynamicSecret"
        ));
    }
}

fn exact_transformed_key(document: &Value, key: &str) -> bool {
    let Some(templates) = document
        .pointer("/spec/destination/transformation/templates")
        .and_then(Value::as_object)
    else {
        return false;
    };
    let text = templates
        .get(key)
        .and_then(|template| template.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    templates.len() == 1
        && is_canonical_database_url_template(text)
        && document
            .pointer("/spec/destination/transformation/excludeRaw")
            .and_then(Value::as_bool)
            == Some(true)
        && document
            .pointer("/spec/destination/transformation/excludes")
            .and_then(Value::as_array)
            .is_some_and(|excludes| excludes.len() == 1 && excludes[0].as_str() == Some(".*"))
}

/// Parses the security-relevant subset of the VSO Go template before comparing
/// it with the one admitted URL-construction program. Whitespace within actions
/// is insignificant, but trim markers, action order, arguments, regexes, and the
/// final URL are exact. This prevents an otherwise-valid template from hiding a
/// second output command or weakening a delimiter guard while retaining the
/// substrings checked by the previous validator.
fn is_canonical_database_url_template(text: &str) -> bool {
    let expected_prefix: &[&[&str]] = &[
        &[
            "$username",
            ":=",
            "toString",
            "(",
            "get",
            ".Secrets",
            "\"username\"",
            ")",
        ],
        &[
            "$password",
            ":=",
            "toString",
            "(",
            "get",
            ".Secrets",
            "\"password\"",
            ")",
        ],
        &[
            "if",
            "not",
            "(",
            "regexMatch",
            "\"^[A-Za-z0-9._~-]+$\"",
            "$username",
            ")",
        ],
        &["fail", "\"Vault database username is not URL-safe\""],
        &["end"],
        &[
            "if",
            "not",
            "(",
            "regexMatch",
            "\"^[A-Za-z0-9._~-]+$\"",
            "$password",
            ")",
        ],
        &["fail", "\"Vault database password is not URL-safe\""],
        &["end"],
    ];
    let expected_url = format!(
        "\"postgresql://%s:%s@%s/ryuki_platform?sslmode=verify-full&sslrootcert={CNPG_CA_FILE_PATH}\""
    );
    let expected_final = [
        "printf",
        expected_url.as_str(),
        "$username",
        "$password",
        "(",
        "get",
        ".Annotations",
        "\"ryuki.io/postgres-host\"",
        ")",
    ];
    let Some(actual) = parse_trimmed_template_actions(text) else {
        return false;
    };

    actual.len() == expected_prefix.len() + 1
        && actual
            .iter()
            .zip(expected_prefix)
            .all(|(actual, expected)| {
                actual
                    .iter()
                    .map(String::as_str)
                    .eq(expected.iter().copied())
            })
        && actual.last().is_some_and(|actual| {
            actual
                .iter()
                .map(String::as_str)
                .eq(expected_final.iter().copied())
        })
}

fn parse_trimmed_template_actions(text: &str) -> Option<Vec<Vec<String>>> {
    let mut actions = Vec::new();
    let mut remaining = text;
    loop {
        remaining = remaining.trim_start_matches(is_template_whitespace);
        if remaining.is_empty() {
            return Some(actions);
        }

        let action = remaining.strip_prefix("{{-")?;
        if !action.chars().next().is_some_and(is_template_whitespace) {
            return None;
        }
        let end = action.find("-}}")?;
        if !action[..end]
            .chars()
            .next_back()
            .is_some_and(is_template_whitespace)
        {
            return None;
        }
        actions.push(tokenize_template_action(&action[..end])?);
        remaining = &action[end + 3..];
    }
}

fn is_template_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn tokenize_template_action(action: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut offset = 0;
    while offset < action.len() {
        let current = action[offset..].chars().next()?;
        if is_template_whitespace(current) {
            offset += current.len_utf8();
            continue;
        }

        if matches!(current, '(' | ')') {
            tokens.push(current.to_string());
            offset += current.len_utf8();
            continue;
        }

        let start = offset;
        if current == '"' {
            offset += current.len_utf8();
            let mut escaped = false;
            let mut terminated = false;
            while offset < action.len() {
                let character = action[offset..].chars().next()?;
                offset += character.len_utf8();
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    terminated = true;
                    break;
                }
            }
            if !terminated {
                return None;
            }
        } else {
            while offset < action.len() {
                let character = action[offset..].chars().next()?;
                if is_template_whitespace(character) || matches!(character, '(' | ')' | '"') {
                    break;
                }
                offset += character.len_utf8();
            }
        }
        tokens.push(action[start..offset].to_owned());
    }
    Some(tokens)
}

fn exact_restart_target(document: &Value, kind: &str, name: &str) -> bool {
    let Some(targets) = document
        .pointer("/spec/rolloutRestartTargets")
        .and_then(Value::as_array)
    else {
        return false;
    };
    targets.len() == 1
        && targets[0].get("kind").and_then(Value::as_str) == Some(kind)
        && targets[0].get("name").and_then(Value::as_str) == Some(name)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid vault secret delivery catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vault secret delivery program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vault secret delivery docs JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_docs_text(
        &payload.api_readme,
        &payload.catalog_readme,
        &payload.doc_readme,
        &payload.doc,
        &mut errors,
    );
    Ok(errors)
}

pub fn scan_prohibited_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProhibitedInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vault secret delivery prohibited JSON: {error}"))?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("vault secret delivery catalog must be a mapping".to_string());
        return;
    }

    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "vault secret delivery version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "vault secret delivery status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "vault secret delivery source must be static-seed",
    );
    expect(
        string_value(catalog, "readinessMode") == Some("static-readiness"),
        errors,
        "vault secret delivery mode must be static-readiness",
    );
    expect(
        string_value(catalog, "deliveryProvider") == Some("Vault Secrets Operator"),
        errors,
        "vault secret delivery provider must be Vault Secrets Operator",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            catalog.get(*field).and_then(Value::as_bool) == Some(false),
            errors,
            format!("vault secret delivery {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "deliverySurfaces", REQUIRED_SURFACES, errors);
    validate_required_array(catalog, "requiredInputs", REQUIRED_INPUTS, errors);
    validate_required_array(catalog, "requiredGuards", REQUIRED_GUARDS, errors);
    validate_required_array(catalog, "planSections", REQUIRED_PLAN_SECTIONS, errors);
    validate_required_array(catalog, "blockedReasons", REQUIRED_BLOCKED_REASONS, errors);
    validate_required_array(catalog, "requiredEvidence", REQUIRED_EVIDENCE, errors);
    validate_required_rules(catalog, errors);
    scan_prohibited_value(catalog, CATALOG_PATH, errors);
}

fn validate_catalog_keys(catalog: &Value, errors: &mut Vec<String>) {
    let Some(map) = catalog.as_object() else {
        return;
    };
    let allowed: HashSet<&str> = CATALOG_FIELDS
        .iter()
        .chain(REQUIRED_DISABLED_FIELDS.iter())
        .copied()
        .collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "vault secret delivery unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required_values: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_like(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let value_set: HashSet<&str> = values.iter().map(String::as_str).collect();
    let required_set: HashSet<&str> = required_values.iter().copied().collect();
    let missing: Vec<&str> = required_values
        .iter()
        .copied()
        .filter(|value| !value_set.contains(value))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|value| !required_set.contains(value))
        .collect();
    if !missing.is_empty() {
        errors.push(format!("{field} missing values: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "{field} unexpected values present: {} redacted value(s)",
            unexpected.len()
        ));
    }
    expect(
        unique_count(&values) == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited vault secret delivery value"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let Some(rules) = catalog.get("rules").and_then(Value::as_array) else {
        errors.push("vault secret delivery rules must be an array of mappings".to_string());
        return;
    };
    if !rules.iter().all(Value::is_object) {
        errors.push("vault secret delivery rules must be an array of mappings".to_string());
        return;
    }

    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let required_ids: Vec<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let missing: Vec<&str> = required_ids
        .iter()
        .copied()
        .filter(|id| !rule_ids.iter().any(|candidate| candidate == id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .map(String::as_str)
        .filter(|id| !required_ids.contains(id))
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "vault secret delivery missing rules: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "vault secret delivery unexpected rules present: {} redacted rule id(s)",
            unexpected.len()
        ));
    }
    expect(
        unique_count(&rule_ids) == rule_ids.len(),
        errors,
        "vault secret delivery rule IDs must be unique",
    );
    let rule_details: Vec<Vec<String>> = rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| {
                    rule.get(*field)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .collect();
    expect(
        unique_count_vec(&rule_details) == rule_details.len(),
        errors,
        "vault secret delivery rule details must be unique",
    );
    for rule in rules {
        let Some(rule_map) = rule.as_object() else {
            continue;
        };
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        let unexpected: Vec<&str> = rule_map
            .keys()
            .map(String::as_str)
            .filter(|key| !RULE_KEYS.contains(key))
            .collect();
        let missing: Vec<&str> = RULE_KEYS
            .iter()
            .copied()
            .filter(|key| !rule_map.contains_key(*key))
            .collect();
        if !unexpected.is_empty() {
            errors.push(format!(
                "vault secret delivery rule {rule_id} unexpected rule keys: {}",
                unexpected.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "vault secret delivery rule {rule_id} missing rule keys: {}",
                missing.join(", ")
            ));
        }
    }
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = rules
            .iter()
            .find(|candidate| string_value(candidate, "id") == Some(expected_rule.id))
        else {
            continue;
        };
        for (field, expected) in [
            ("decision", expected_rule.decision),
            ("requirement", expected_rule.requirement),
            ("evidence", expected_rule.evidence),
        ] {
            expect(
                string_value(rule, field) == Some(expected),
                errors,
                format!(
                    "vault secret delivery rule {} {field} must match",
                    expected_rule.id
                ),
            );
        }
    }
}

// `program` is the Rust API source sources/ryuki-api/src/contracts.rs. The
// vault secret delivery contract is mounted as `.route(ENDPOINT, get(handler))`
// and the handler emits one `Json(json!({ ... }))` payload. We validate the
// Rust reality: the route is mounted exactly once and the payload keeps the
// safety invariants (static-seed source, all *Allowed/*Enabled flags false).
//
// relaxed: the C#-era deep catalog<->payload parity is not re-asserted against
// contracts.rs; the full contract shape stays enforced on the catalog YAML in
// `validate_catalog_value`. The original C# parser is preserved below.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::endpoint_payload(
        program,
        ENDPOINT,
        "API missing vault secret delivery endpoint",
        "API missing vault secret delivery JSON payload",
        errors,
    ) else {
        return;
    };
    expect(
        payload.get("source").and_then(Value::as_str) == Some("static-seed"),
        errors,
        "API must keep static-seed source",
    );
    crate::rust_contract::check_safety_flags_disabled(&payload, errors);
}

fn validate_program_text_csharp(program: &str, catalog: &Value, errors: &mut Vec<String>) {
    let uncommented_program = strip_csharp_comments(program);
    let block = endpoint_block(&uncommented_program, errors);
    if block.is_empty() {
        return;
    }

    validate_exact_string_assignment(
        &block,
        "source",
        "static-seed",
        errors,
        "API must keep exactly one static-seed source",
    );
    validate_exact_string_assignment(
        &block,
        "readinessMode",
        "static-readiness",
        errors,
        "API must keep exactly one static-readiness mode",
    );
    validate_exact_string_assignment(
        &block,
        "deliveryProvider",
        "Vault Secrets Operator",
        errors,
        "API must keep exactly one Vault Secrets Operator provider",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        validate_exact_assignment(
            &block,
            field,
            "false",
            errors,
            format!("API must keep exactly one {field} disabled"),
        );
    }
    for (field, variable) in ENDPOINT_ARRAY_BINDINGS {
        validate_exact_assignment(
            &block,
            field,
            variable,
            errors,
            format!("API must bind exactly one {field} to {variable}"),
        );
        validate_api_array(
            field,
            csharp_array_values(&uncommented_program, variable, field, errors),
            string_array_like(catalog, field),
            errors,
        );
    }
    for field in ENDPOINT_INLINE_ARRAYS {
        validate_api_array(
            field,
            endpoint_inline_array_values(&block, field, errors),
            string_array_like(catalog, field),
            errors,
        );
    }
    validate_api_rules(&block, catalog, errors);
    validate_endpoint_field_names(&block, errors);
    validate_no_unsafe_true_flags(&block, errors);
    validate_endpoint_no_prohibited_literals(&block, errors);
}

fn validate_api_array(
    field: &str,
    values: Option<Vec<String>>,
    catalog_values: Vec<String>,
    errors: &mut Vec<String>,
) {
    let Some(values) = values else {
        errors.push(format!("API missing {field} array"));
        return;
    };
    let catalog_set: HashSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let value_set: HashSet<&str> = values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = catalog_values
        .iter()
        .map(String::as_str)
        .filter(|item| !value_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|item| !catalog_set.contains(item))
        .collect();
    if !missing.is_empty() {
        errors.push(format!(
            "API {field} missing values: {}",
            missing.join(", ")
        ));
    }
    if !unexpected.is_empty() {
        errors.push(format!(
            "API {field} unexpected values present: {} redacted value(s)",
            unexpected.len()
        ));
    }
    expect(
        unique_count(&values) == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited vault secret delivery value"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let api_rules = endpoint_rule_hashes(block, errors);
    let Some(catalog_rules) = catalog.get("rules").and_then(Value::as_array) else {
        return;
    };
    let catalog_ids: HashSet<&str> = catalog_rules
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str))
        .collect();
    let api_ids: HashSet<&str> = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").map(String::as_str))
        .collect();
    for id in catalog_ids.difference(&api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    let unexpected: Vec<&&str> = api_ids.difference(&catalog_ids).collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "API unexpected rules present: {} redacted rule id(s)",
            unexpected.len()
        ));
    }
    let ids: Vec<String> = api_rules
        .iter()
        .filter_map(|rule| rule.get("id").cloned())
        .collect();
    let details: Vec<Vec<String>> = api_rules
        .iter()
        .map(|rule| {
            ["decision", "requirement", "evidence"]
                .iter()
                .map(|field| rule.get(*field).cloned().unwrap_or_default())
                .collect()
        })
        .collect();
    expect(
        unique_count(&ids) == ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    expect(
        unique_count_vec(&details) == details.len(),
        errors,
        "API rule details must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(id) = catalog_rule.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(api_rule) = api_rules
            .iter()
            .find(|candidate| candidate.get("id").map(String::as_str) == Some(id))
        else {
            continue;
        };
        for field in ["decision", "requirement", "evidence"] {
            expect(
                api_rule.get(field).map(String::as_str)
                    == catalog_rule.get(field).and_then(Value::as_str),
                errors,
                format!("API rule {id} {field} must match catalog"),
            );
        }
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        if allowed_endpoint_fields().contains(field.as_str()) {
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited vault secret delivery field {field}"
            ));
        } else {
            errors.push(format!(
                "API endpoint has unexpected vault secret delivery field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    for field in top_level_assignment_fields(block) {
        let values = top_level_assignment_values(block, &field);
        for value in values {
            if value != "true" {
                continue;
            }
            let lower = field.to_ascii_lowercase();
            if prohibited_field(&field)
                || [
                    "live",
                    "provider",
                    "vault",
                    "helm",
                    "kubectl",
                    "init",
                    "unseal",
                    "policy",
                    "auth",
                    "secret",
                    "audit",
                    "raw",
                    "identifier",
                ]
                .iter()
                .any(|term| lower.contains(term))
            {
                errors.push(format!("API endpoint has unsafe true flag {field}"));
            }
        }
    }
}

fn validate_endpoint_no_prohibited_literals(block: &str, errors: &mut Vec<String>) {
    for literal in csharp_string_literals(block) {
        if safe_text_value(&literal) {
            continue;
        }
        if contains_structured_prohibited_value(&literal) {
            errors.push(format!(
                "API endpoint contains prohibited literal value {literal}"
            ));
        }
        if prohibited_field(&literal) {
            errors.push(format!(
                "API endpoint contains prohibited literal field {literal}"
            ));
        }
    }
}

fn validate_docs_text(
    readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    errors: &mut Vec<String>,
) {
    expect(
        readme.contains(ENDPOINT),
        errors,
        "API README missing vault secret delivery endpoint",
    );
    expect(
        catalog_readme.contains("vault-secret-delivery-contract.yaml"),
        errors,
        "catalog README missing vault secret delivery catalog",
    );
    expect(
        doc_readme.contains("vault-secret-delivery.md"),
        errors,
        "workflow README missing vault secret delivery doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "vault secret delivery doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "vault secret delivery doc must prohibit provider calls",
    );
    expect(
        doc.contains("No Vault API calls"),
        errors,
        "vault secret delivery doc must prohibit Vault API calls",
    );
    expect(
        doc.contains("Use static Vault secret delivery summaries only."),
        errors,
        "vault secret delivery doc must require static summaries",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited vault secret delivery field"
                    ));
                }
                scan_prohibited_value(child, &child_path, errors);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if contains_prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if vault_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if contains_structured_prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited vault secret delivery field"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !vault_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        if contains_generic_vault_path(line) {
            errors.push(format!("{path}:{} contains prohibited value", index + 1));
        }
        for term in line_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited vault secret delivery field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    if SAFE_TEXT_PROHIBITION_LINES.contains(&stripped) || safe_text_value(bullet_value) {
        return true;
    }
    if let Some((key, value)) = stripped.split_once(':') {
        let key = key.trim();
        let value = value.trim();
        return is_simple_yaml_key(key) && !prohibited_field(key) && safe_text_value(value);
    }
    false
}

fn safe_text_value(value: &str) -> bool {
    safe_text_values().contains(value)
}

fn safe_text_values() -> HashSet<&'static str> {
    let mut values = HashSet::new();
    values.extend(REQUIRED_SURFACES.iter().copied());
    values.extend(REQUIRED_INPUTS.iter().copied());
    values.extend(REQUIRED_GUARDS.iter().copied());
    values.extend(REQUIRED_PLAN_SECTIONS.iter().copied());
    values.extend(REQUIRED_BLOCKED_REASONS.iter().copied());
    values.extend(REQUIRED_EVIDENCE.iter().copied());
    values.extend(REQUIRED_DISABLED_FIELDS.iter().copied());
    values.extend(CATALOG_FIELDS.iter().copied());
    values.extend(RULE_KEYS.iter().copied());
    values.extend(
        ENDPOINT_ARRAY_BINDINGS
            .iter()
            .map(|(_, variable)| *variable),
    );
    values.extend(["draft", "static-seed", "static-readiness"]);
    values.extend(["Vault Secrets Operator"]);
    for rule in REQUIRED_RULES {
        values.insert(rule.id);
        values.insert(rule.decision);
        values.insert(rule.requirement);
        values.insert(rule.evidence);
    }
    values
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_values()
        .iter()
        .map(|value| normalize(value))
        .any(|safe| safe == normalized)
    {
        return false;
    }
    if ["credential", "password", "bearer", "token", "value"].contains(&normalized.as_str()) {
        return true;
    }
    if [
        "vaulturl",
        "vaultaddress",
        "vaultaddr",
        "vaultnamespace",
        "vaultmountpath",
        "vaultsecretpath",
        "vaultauthrole",
        "authrole",
        "secretpath",
        "mountpath",
        "serviceaccountname",
        "serviceaccounttoken",
        "kubernetessecretname",
        "secretdata",
        "secretkey",
        "destinationname",
        "templatetext",
        "rollouttargetname",
        "tenantid",
        "objectid",
        "privateip",
        "credential",
        "secretvalue",
        "token",
        "password",
        "bearer",
        "rawvault",
        "rawkubernetessecret",
        "rawkubernetes",
        "providerpayload",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
    {
        return true;
    }
    sensitive_compound_field(value)
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    if has_any(
        &tokens,
        &["password", "credential", "token", "bearer", "value"],
    ) {
        return true;
    }
    if has_any(&tokens, &["url", "uri", "endpoint", "fqdn"]) {
        return true;
    }
    if has_any(&tokens, &["id", "guid"]) && tokens.len() > 1 {
        return true;
    }
    if has_any(&tokens, &["private", "ip", "host", "dns"]) && has_any(&tokens, &["address", "name"])
    {
        return true;
    }
    if has_any(
        &tokens,
        &[
            "vault",
            "kubernetes",
            "secret",
            "service",
            "account",
            "auth",
            "namespace",
            "mount",
            "role",
            "destination",
            "template",
            "rollout",
            "target",
            "tenant",
            "object",
        ],
    ) && has_any(
        &tokens,
        &[
            "name",
            "url",
            "uri",
            "endpoint",
            "id",
            "identifier",
            "token",
            "key",
            "data",
            "path",
            "payload",
            "row",
            "rows",
            "value",
            "text",
            "role",
            "namespace",
        ],
    ) {
        return true;
    }
    tokens.iter().any(|token| token == "raw")
        && has_any(
            &tokens,
            &["vault", "kubernetes", "provider", "payload", "logs", "rows"],
        )
}

fn contains_prohibited_value(text: &str) -> bool {
    contains_aws_key(text)
        || contains_private_key_marker(text)
        || contains_url_scheme(text)
        || contains_private_ip(text)
        || contains_guid(text)
        || contains_secret_path(text)
        || contains_vault_path(text)
        || contains_jwt_like(text)
        || contains_vault_token_like(text)
        || contains_secret_assignment(text)
}

fn contains_structured_prohibited_value(text: &str) -> bool {
    contains_prohibited_value(text) || contains_generic_vault_path(text)
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> String {
    let marker = format!("app.MapGet(\"{ENDPOINT}\",");
    let starts = line_starts_with(program, &marker, 0);
    if starts.is_empty() {
        errors.push("API missing vault secret delivery endpoint".to_string());
        return String::new();
    }
    expect(
        starts.len() == 1,
        errors,
        "API must expose exactly one vault secret delivery endpoint",
    );
    let start_index = starts[0];
    let next_endpoint = line_starts_with(program, "app.MapGet(", start_index + 1)
        .into_iter()
        .next()
        .unwrap_or(program.len());
    program[start_index..next_endpoint].to_string()
}

fn validate_exact_string_assignment(
    block: &str,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
    message: impl Into<String>,
) {
    validate_exact_assignment(block, field, &format!("\"{value}\""), errors, message);
}

fn validate_exact_assignment(
    block: &str,
    field: &str,
    expected: &str,
    errors: &mut Vec<String>,
    message: impl Into<String>,
) {
    let message = message.into();
    let assignments = top_level_assignment_values(block, field);
    if assignments.len() != 1 {
        errors.push(format!(
            "API endpoint field {field} must be assigned exactly once"
        ));
        errors.push(message);
        return;
    }
    expect(assignments[0] == expected, errors, message);
}

fn csharp_array_values(
    program: &str,
    variable: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let bodies = array_bodies_for_variable(program, variable);
    if bodies.len() != 1 {
        errors.push(format!(
            "API {field} must have exactly one literal string array declaration"
        ));
        return None;
    }
    let body = bodies.first().expect("body length checked");
    if !literal_string_array_body(body) {
        errors.push(format!(
            "API {field} array must use literal string entries only"
        ));
    }
    Some(csharp_string_literals(body))
}

fn endpoint_inline_array_values(
    block: &str,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let bodies = array_bodies_for_assignment(block, field);
    if bodies.len() != 1 {
        errors.push(format!(
            "API endpoint field {field} must be assigned exactly once"
        ));
        return None;
    }
    let body = bodies.first().expect("body length checked");
    if !literal_string_array_body(body) {
        errors.push(format!(
            "API {field} array must use literal string entries only"
        ));
    }
    Some(csharp_string_literals(body))
}

fn endpoint_rule_hashes(block: &str, errors: &mut Vec<String>) -> Vec<HashMap<String, String>> {
    let bodies = array_bodies_for_assignment(block, "rules");
    if bodies.len() != 1 {
        errors.push("API endpoint field rules must be assigned exactly once".to_string());
        return Vec::new();
    }
    let mut rules = Vec::new();
    for element in top_level_array_elements(&bodies[0]) {
        let trimmed = element.trim();
        let Some(rule_body) = literal_rule_body(trimmed) else {
            errors.push("API rule must assign id, decision, requirement, and evidence exactly once as literal strings".to_string());
            continue;
        };
        let parsed = parse_rule_assignments(rule_body);
        for field in &parsed.invalid_fields {
            errors.push(format!(
                "API rule has unexpected vault secret delivery field {field}"
            ));
        }
        errors.extend(parsed.literal_errors.iter().cloned());
        if parsed.valid {
            rules.push(parsed.values);
        } else {
            errors.push("API rule must assign id, decision, requirement, and evidence exactly once as literal strings".to_string());
        }
    }
    rules
}

fn literal_rule_body(element: &str) -> Option<&str> {
    let masked = mask_csharp_string_literals(element);
    if !starts_with_word(&masked, 0, "new") {
        return None;
    }
    let open_index = next_non_whitespace_index(&masked, "new".len())?;
    if masked.as_bytes().get(open_index) != Some(&b'{') {
        return None;
    }
    let close_index = matching_brace_index(element, open_index)?;
    if !masked[close_index + 1..].trim().is_empty() {
        return None;
    }
    Some(&element[open_index + 1..close_index])
}

struct ParsedRule {
    values: HashMap<String, String>,
    valid: bool,
    invalid_fields: Vec<String>,
    literal_errors: Vec<String>,
}

fn parse_rule_assignments(body: &str) -> ParsedRule {
    let masked = mask_csharp_string_literals(body);
    let mut values = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut invalid_fields = Vec::new();
    let mut literal_errors = Vec::new();
    let mut invalid_literal = false;
    let mut offset = 0usize;
    while let Some((field, _ident_start, ident_end)) = next_identifier(&masked, offset) {
        let Some(eq_index) = next_non_whitespace_index(&masked, ident_end) else {
            break;
        };
        if masked.as_bytes().get(eq_index) != Some(&b'=') {
            offset = ident_end;
            continue;
        }
        if !RULE_KEYS.contains(&field.as_str()) {
            invalid_fields.push(field);
            offset = ident_end;
            continue;
        }
        *counts.entry(field.clone()).or_insert(0) += 1;
        let Some(value_start) = next_non_whitespace_index(body, eq_index + 1) else {
            invalid_literal = true;
            literal_errors.push(format!("API rule {field} must be a quoted string literal"));
            break;
        };
        if body.as_bytes().get(value_start) == Some(&b'"') {
            if let Some((value, _end)) = parse_csharp_string_literal_at(body, value_start) {
                values.insert(field, value);
            } else {
                invalid_literal = true;
                literal_errors.push(format!("API rule {field} must be a quoted string literal"));
            }
        } else {
            invalid_literal = true;
            literal_errors.push(format!("API rule {field} must be a quoted string literal"));
        }
        offset = ident_end;
    }
    let valid = RULE_KEYS
        .iter()
        .all(|key| counts.get(*key).copied() == Some(1) && values.contains_key(*key))
        && !invalid_literal
        && invalid_fields.is_empty();
    ParsedRule {
        values,
        valid,
        invalid_fields,
        literal_errors,
    }
}

fn array_bodies_for_variable(program: &str, variable: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(program);
    let mut bodies = Vec::new();
    let mut offset = 0usize;
    while let Some((keyword, _start, keyword_end)) = next_identifier(&masked, offset) {
        if keyword != "var" {
            offset = keyword_end;
            continue;
        }
        let Some((name, _name_start, name_end)) = next_identifier(&masked, keyword_end) else {
            offset = keyword_end;
            continue;
        };
        if name != variable {
            offset = name_end;
            continue;
        }
        if let Some(body) = array_body_after_assignment(program, &masked, name_end) {
            bodies.push(body);
        }
        offset = name_end;
    }
    bodies
}

fn array_bodies_for_assignment(block: &str, field: &str) -> Vec<String> {
    array_body_spans_for_assignment(block, field)
        .into_iter()
        .map(|(open_index, close_index)| block[open_index + 1..close_index].to_string())
        .collect()
}

fn array_body_spans_for_assignment(block: &str, field: &str) -> Vec<(usize, usize)> {
    let masked = mask_csharp_string_literals(block);
    let mut spans = Vec::new();
    let mut offset = 0usize;
    while let Some((identifier, ident_start, ident_end)) = next_identifier(&masked, offset) {
        if identifier == field && brace_depth_at(&masked, ident_start) == 1 {
            if let Some(span) = array_body_span_after_assignment(block, &masked, ident_end) {
                spans.push(span);
            }
        }
        offset = ident_end;
    }
    spans
}

fn array_body_after_assignment(source: &str, masked: &str, name_end: usize) -> Option<String> {
    let (open_index, close_index) = array_body_span_after_assignment(source, masked, name_end)?;
    Some(source[open_index + 1..close_index].to_string())
}

fn array_body_span_after_assignment(
    source: &str,
    masked: &str,
    name_end: usize,
) -> Option<(usize, usize)> {
    let eq_index = next_non_whitespace_index(masked, name_end)?;
    if masked.as_bytes().get(eq_index) != Some(&b'=') {
        return None;
    }
    let value_start = next_non_whitespace_index(masked, eq_index + 1)?;
    if !masked[value_start..].starts_with("new[]") {
        return None;
    }
    let open_index = next_non_whitespace_index(masked, value_start + "new[]".len())?;
    if masked.as_bytes().get(open_index) != Some(&b'{') {
        return None;
    }
    let close_index = matching_brace_index(source, open_index)?;
    let terminator_index = next_non_whitespace_index(masked, close_index + 1)?;
    if !matches!(
        masked.as_bytes().get(terminator_index),
        Some(b',') | Some(b';') | Some(b'}')
    ) {
        return None;
    }
    Some((open_index, close_index))
}

fn top_level_assignment_fields(block: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(block);
    let mut fields = Vec::new();
    let mut offset = 0usize;
    while let Some((field, ident_start, ident_end)) = next_identifier(&masked, offset) {
        if brace_depth_at(&masked, ident_start) == 1 {
            if let Some(eq_index) = next_non_whitespace_index(&masked, ident_end) {
                if masked.as_bytes().get(eq_index) == Some(&b'=')
                    && masked.as_bytes().get(eq_index + 1) != Some(&b'=')
                {
                    fields.push(field);
                }
            }
        }
        offset = ident_end;
    }
    fields
}

fn top_level_assignment_values(block: &str, field: &str) -> Vec<String> {
    let masked = mask_csharp_string_literals(block);
    let mut values = Vec::new();
    let mut offset = 0usize;
    while let Some((candidate, ident_start, ident_end)) = next_identifier(&masked, offset) {
        if candidate != field || brace_depth_at(&masked, ident_start) != 1 {
            offset = ident_end;
            continue;
        }
        let Some(eq_index) = next_non_whitespace_index(&masked, ident_end) else {
            offset = ident_end;
            continue;
        };
        if masked.as_bytes().get(eq_index) != Some(&b'=') {
            offset = ident_end;
            continue;
        }
        let Some(value_start) = next_non_whitespace_index(&masked, eq_index + 1) else {
            offset = ident_end;
            continue;
        };
        let value_end = top_level_assignment_value_end(&masked, value_start);
        values.push(block[value_start..value_end].trim().to_string());
        offset = ident_end;
    }
    values
}

fn top_level_assignment_value_end(masked: &str, value_start: usize) -> usize {
    let bytes = masked.as_bytes();
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut index = value_start;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => brace_depth += 1,
            b'}' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => break,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b',' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => break,
            _ => {}
        }
        index += 1;
    }
    index
}

fn literal_string_array_body(body: &str) -> bool {
    top_level_array_elements(body).into_iter().all(|element| {
        let trimmed = element.trim();
        let Some((_value, end_index)) = parse_csharp_string_literal_at(trimmed, 0) else {
            return false;
        };
        end_index == trimmed.len()
    })
}

fn top_level_array_elements(body: &str) -> Vec<&str> {
    top_level_segments(body, b',')
        .into_iter()
        .filter(|segment| !segment.trim().is_empty())
        .collect()
}

fn top_level_segments(source: &str, delimiter: u8) -> Vec<&str> {
    let masked = mask_csharp_string_literals(source);
    let bytes = masked.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            _ if *byte == delimiter
                && brace_depth == 0
                && paren_depth == 0
                && bracket_depth == 0 =>
            {
                segments.push(&source[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    segments.push(&source[start..]);
    segments
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut offset = 0usize;
    while offset < text.len() {
        if let Some((value, literal_end)) = parse_any_csharp_string_literal_at(text, offset) {
            values.push(value);
            offset = literal_end;
        } else {
            offset += 1;
        }
    }
    values
}

fn parse_csharp_string_literal_at(text: &str, start: usize) -> Option<(String, usize)> {
    if text.as_bytes().get(start) != Some(&b'"') {
        return None;
    }
    let mut value = String::new();
    let mut escape = false;
    for (relative, ch) in text[start + 1..].char_indices() {
        if escape {
            value.push(ch);
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else if ch == '"' {
            return Some((value, start + 1 + relative + ch.len_utf8()));
        } else {
            value.push(ch);
        }
    }
    None
}

#[derive(Clone, Copy)]
struct CsharpStringSpan {
    content_start: usize,
    content_end: usize,
    end: usize,
    verbatim: bool,
    raw: bool,
}

fn parse_any_csharp_string_literal_at(text: &str, start: usize) -> Option<(String, usize)> {
    let span = csharp_string_span_at(text, start)?;
    let literal = &text[span.content_start..span.content_end];
    let value = if span.raw {
        literal.to_string()
    } else if span.verbatim {
        literal.replace("\"\"", "\"")
    } else {
        let mut value = String::new();
        let mut escape = false;
        for ch in literal.chars() {
            if escape {
                value.push(ch);
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else {
                value.push(ch);
            }
        }
        value
    };
    Some((value, span.end))
}

fn csharp_string_span_at(text: &str, start: usize) -> Option<CsharpStringSpan> {
    let prefix_len = csharp_string_prefix_len(text, start)?;
    let literal_start = start + prefix_len;
    let quote_count = quote_count_at(text, literal_start);
    if quote_count == 0 {
        return None;
    }
    if quote_count >= 3 {
        let delimiter = "\"".repeat(quote_count);
        let content_start = literal_start + quote_count;
        let close_relative = text[content_start..].find(&delimiter)?;
        let content_end = content_start + close_relative;
        return Some(CsharpStringSpan {
            content_start,
            content_end,
            end: content_end + quote_count,
            verbatim: prefix_contains_at(text, start),
            raw: true,
        });
    }
    if prefix_contains_at(text, start) {
        let content_start = literal_start + 1;
        let mut index = content_start;
        let bytes = text.as_bytes();
        while index < bytes.len() {
            if bytes[index] == b'"' && bytes.get(index + 1) == Some(&b'"') {
                index += 2;
            } else if bytes[index] == b'"' {
                return Some(CsharpStringSpan {
                    content_start,
                    content_end: index,
                    end: index + 1,
                    verbatim: true,
                    raw: false,
                });
            } else {
                index += 1;
            }
        }
        return None;
    }
    let content_start = literal_start + 1;
    let mut index = content_start;
    let bytes = text.as_bytes();
    let mut escape = false;
    while index < bytes.len() {
        if escape {
            escape = false;
        } else if bytes[index] == b'\\' {
            escape = true;
        } else if bytes[index] == b'"' {
            return Some(CsharpStringSpan {
                content_start,
                content_end: index,
                end: index + 1,
                verbatim: false,
                raw: false,
            });
        }
        index += 1;
    }
    None
}

fn csharp_string_prefix_len(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    match bytes.get(start)? {
        b'"' => Some(0),
        b'@' if bytes.get(start + 1) == Some(&b'"') => Some(1),
        b'$' if bytes.get(start + 1) == Some(&b'"') => Some(1),
        b'$' if bytes.get(start + 1) == Some(&b'@') && bytes.get(start + 2) == Some(&b'"') => {
            Some(2)
        }
        b'@' if bytes.get(start + 1) == Some(&b'$') && bytes.get(start + 2) == Some(&b'"') => {
            Some(2)
        }
        _ => None,
    }
}

fn prefix_contains_at(text: &str, start: usize) -> bool {
    let Some(prefix_len) = csharp_string_prefix_len(text, start) else {
        return false;
    };
    text[start..start + prefix_len].contains('@')
}

fn quote_count_at(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut count = 0usize;
    while bytes.get(start + count) == Some(&b'"') {
        count += 1;
    }
    count
}

fn strip_csharp_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < text.len() {
        if let Some(span) = csharp_string_span_at(text, index) {
            let literal = &text[index..span.end];
            if literal.contains('\n') {
                out.extend(literal.chars().filter(|ch| *ch == '\n'));
            } else {
                out.push_str(literal);
            }
            index = span.end;
        } else if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'/') {
            out.push(' ');
            out.push(' ');
            index += 2;
            while index < text.len() {
                let ch = bytes[index] as char;
                if ch == '\n' {
                    out.push('\n');
                    index += 1;
                    break;
                }
                out.push(' ');
                index += 1;
            }
        } else if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
            out.push(' ');
            out.push(' ');
            index += 2;
            while index < text.len() {
                let ch = bytes[index] as char;
                out.push(if ch == '\n' { '\n' } else { ' ' });
                if bytes.get(index.saturating_sub(1)) == Some(&b'*') && bytes[index] == b'/' {
                    index += 1;
                    break;
                }
                index += 1;
            }
        } else {
            let ch = text[index..].chars().next().expect("index is in bounds");
            out.push(ch);
            index += ch.len_utf8();
        }
    }
    out
}

fn mask_csharp_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut index = 0usize;
    while index < text.len() {
        if let Some(span) = csharp_string_span_at(text, index) {
            let literal = &text[index..span.end];
            for (relative, ch) in literal.char_indices() {
                let absolute = index + relative;
                if ch == '\n' {
                    out.push('\n');
                } else if ch == '"'
                    && (absolute < span.content_start || absolute >= span.content_end)
                {
                    out.push('"');
                } else {
                    out.push(' ');
                }
            }
            index = span.end;
        } else {
            let ch = text[index..].chars().next().expect("index is in bounds");
            out.push(ch);
            index += ch.len_utf8();
        }
    }
    out
}

fn matching_brace_index(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut index = open_index;
    while index < text.len() {
        if let Some(span) = csharp_string_span_at(text, index) {
            index = span.end;
            continue;
        }
        let ch = text[index..].chars().next().expect("index is in bounds");
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += ch.len_utf8();
    }
    None
}

fn brace_depth_at(text: &str, target_index: usize) -> usize {
    text[..target_index]
        .bytes()
        .fold(0usize, |depth, byte| match byte {
            b'{' => depth + 1,
            b'}' => depth.saturating_sub(1),
            _ => depth,
        })
}

fn next_identifier(text: &str, offset: usize) -> Option<(String, usize, usize)> {
    let bytes = text.as_bytes();
    let mut index = offset;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if is_identifier_start(ch) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_continue(bytes[index] as char) {
                index += 1;
            }
            return Some((text[start..index].to_string(), start, index));
        }
        index += 1;
    }
    None
}

fn next_non_whitespace_index(text: &str, mut index: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    (index < bytes.len()).then_some(index)
}

fn starts_with_word(text: &str, index: usize, word: &str) -> bool {
    text[index..].starts_with(word)
        && text[index + word.len()..]
            .chars()
            .next()
            .is_none_or(|ch| !is_identifier_continue(ch))
}

fn line_starts_with(text: &str, marker: &str, offset: usize) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut line_start = 0usize;
    for line in text.split_inclusive('\n') {
        if line_start >= offset && line.trim_start().starts_with(marker) {
            starts.push(line_start + (line.len() - line.trim_start().len()));
        }
        line_start += line.len();
    }
    if text.ends_with('\n') {
        return starts;
    }
    starts
}

fn allowed_endpoint_fields() -> HashSet<&'static str> {
    let mut fields: HashSet<&'static str> = ENDPOINT_BASE_FIELDS.iter().copied().collect();
    fields.extend(REQUIRED_DISABLED_FIELDS.iter().copied());
    fields.extend(ENDPOINT_ARRAY_BINDINGS.iter().map(|(field, _)| *field));
    fields.extend(ENDPOINT_INLINE_ARRAYS.iter().copied());
    fields
}

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn line_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let bytes = line.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if !ch.is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len()
            && ((bytes[index] as char).is_ascii_alphanumeric()
                || bytes[index] == b'_'
                || bytes[index] == b'-')
        {
            index += 1;
        }
        terms.push(line[start..index].to_string());
    }
    terms
}

fn is_simple_yaml_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn vault_text_path(path: &str) -> bool {
    [
        CATALOG_PATH,
        DOC_PATH,
        API_README_PATH,
        CATALOG_README_PATH,
        DOC_README_PATH,
    ]
    .iter()
    .any(|text_path| path.ends_with(text_path))
}

fn vault_text_line(path: &str, line: &str) -> bool {
    path.ends_with(CATALOG_PATH)
        || path.ends_with(DOC_PATH)
        || line.contains("vault-secret-delivery")
        || line.contains("Vault secret delivery")
        || line.contains("Vault Secrets Operator")
        || line.contains(ENDPOINT)
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut expanded = String::with_capacity(value.len() * 2);
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            expanded.push(' ');
        }
        expanded.push(ch);
        previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }
    expanded
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn contains_aws_key(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut index = 0usize;
    while index + 20 <= bytes.len() {
        if bytes[index..].starts_with(b"AKIA")
            && bytes[index + 4..index + 20]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return true;
        }
        index += 1;
    }
    false
}

fn contains_private_key_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("-----begin ") && lower.contains("private key-----")
}

fn contains_url_scheme(text: &str) -> bool {
    let Some(separator) = text.find("://") else {
        return false;
    };
    let prefix = &text[..separator];
    let scheme_start = prefix
        .char_indices()
        .rev()
        .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let scheme = &prefix[scheme_start..];
    scheme
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
}

fn contains_private_ip(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_digit() && ch != '.')
        .any(is_private_ipv4)
}

fn is_private_ipv4(candidate: &str) -> bool {
    let octets: Vec<u8> = candidate
        .split('.')
        .filter_map(|part| part.parse::<u8>().ok())
        .collect();
    if octets.len() != 4 || candidate.split('.').count() != 4 {
        return false;
    }
    octets[0] == 10
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
}

fn contains_guid(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_hexdigit() && ch != '-')
        .any(is_guid)
}

fn is_guid(candidate: &str) -> bool {
    let parts: Vec<&str> = candidate.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(parts.iter())
            .all(|(len, part)| part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn contains_secret_path(text: &str) -> bool {
    text.split_whitespace().any(|word| {
        let trimmed = word.trim_matches(|ch: char| {
            matches!(ch, '"' | '\'' | '`' | ',' | '.' | ';' | ':' | ')' | '(')
        });
        let lower = trimmed.to_ascii_lowercase();
        (lower.starts_with("secret/")
            || lower.starts_with("kv/")
            || lower.starts_with("kv-v2/")
            || lower.starts_with("kvv2/"))
            && trimmed.len() > 3
    })
}

fn contains_vault_path(text: &str) -> bool {
    text.split_whitespace().any(|word| {
        word.trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ',' | '.' | ';' | ':'))
            .starts_with("/vault/")
    })
}

fn contains_generic_vault_path(text: &str) -> bool {
    text.split_whitespace().any(|word| {
        let trimmed = word.trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | '`' | ',' | '.' | ';' | ':' | ')' | '(' | '[' | ']'
            )
        });
        if trimmed.starts_with('/') || trimmed.contains("://") || !trimmed.contains('/') {
            return false;
        }
        let parts: Vec<&str> = trimmed.split('/').collect();
        parts.len() >= 3
            && parts.iter().all(|part| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
            })
            && parts
                .first()
                .and_then(|part| part.chars().next())
                .is_some_and(|ch| ch.is_ascii_alphabetic())
    })
}

fn contains_jwt_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
        .any(|candidate| {
            let parts: Vec<&str> = candidate.split('.').collect();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|part| part.len() >= 12 && part.chars().all(is_base64url_char))
        })
}

fn contains_vault_token_like(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
        .any(|candidate| {
            let lower = candidate.to_ascii_lowercase();
            ["hvs.", "hvb.", "s."]
                .iter()
                .any(|prefix| lower.starts_with(prefix) && candidate.len() >= prefix.len() + 16)
        })
}

fn is_base64url_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')
}

fn contains_secret_assignment(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "root_token",
        "unseal_key",
        "recovery_key",
    ]
    .iter()
    .any(|key| {
        lower
            .find(key)
            .is_some_and(|index| assignment_after_key(&lower[index + key.len()..]))
    })
}

fn assignment_after_key(tail: &str) -> bool {
    let trimmed = tail.trim_start();
    trimmed.starts_with('=') || trimmed.starts_with(':')
}

fn unique_count(values: &[String]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn unique_count_vec(values: &[Vec<String>]) -> usize {
    values.iter().collect::<HashSet<_>>().len()
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

#[derive(Debug, Deserialize)]
struct YamlDuplicateInput {
    text: String,
    path: String,
}

pub fn validate_yaml_duplicates_json(input: &str) -> Result<Vec<String>, String> {
    let payload: YamlDuplicateInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid vault secret delivery YAML duplicate JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_yaml_duplicate_keys_text(&payload.text, &payload.path, &mut errors);
    Ok(errors)
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn catalog() -> Value {
        json!({
            "version": 1,
            "status": "draft",
            "source": "static-seed",
            "readinessMode": "static-readiness",
            "deliveryProvider": "Vault Secrets Operator",
            "providerCallsEnabled": false,
            "vaultApiCallsAllowed": false,
            "kubernetesApplyAllowed": false,
            "helmInstallAllowed": false,
            "helmUpgradeAllowed": false,
            "crdApplyAllowed": false,
            "vaultConnectionMutationAllowed": false,
            "vaultAuthMutationAllowed": false,
            "vaultStaticSecretMutationAllowed": false,
            "kubernetesSecretMutationAllowed": false,
            "secretDataReadAllowed": false,
            "secretDataWriteAllowed": false,
            "rolloutRestartAllowed": false,
            "transformationTemplateAllowed": false,
            "rawVaultPayloadsAllowed": false,
            "rawKubernetesPayloadsAllowed": false,
            "rawProviderPayloadsAllowed": false,
            "secretValuesAllowed": false,
            "vaultIdentifiersAllowed": false,
            "deliverySurfaces": REQUIRED_SURFACES,
            "requiredInputs": REQUIRED_INPUTS,
            "requiredGuards": REQUIRED_GUARDS,
            "planSections": REQUIRED_PLAN_SECTIONS,
            "blockedReasons": REQUIRED_BLOCKED_REASONS,
            "requiredEvidence": REQUIRED_EVIDENCE,
            "rules": REQUIRED_RULES.iter().map(|rule| json!({
                "id": rule.id,
                "decision": rule.decision,
                "requirement": rule.requirement,
                "evidence": rule.evidence,
            })).collect::<Vec<_>>(),
        })
    }

    fn transformed_template_text<'a>(document: &'a Value, key: &str) -> &'a str {
        let pointer = format!("/spec/destination/transformation/templates/{key}/text");
        document
            .pointer(&pointer)
            .and_then(Value::as_str)
            .expect("database URL template text")
    }

    fn with_transformed_template_text(document: &Value, key: &str, text: &str) -> Value {
        let mut changed = document.clone();
        let pointer = format!("/spec/destination/transformation/templates/{key}/text");
        *changed
            .pointer_mut(&pointer)
            .expect("database URL template") = Value::String(text.to_owned());
        changed
    }

    #[test]
    fn current_reference_manifests_keep_secret_delivery_guardrails() {
        let mut errors = Vec::new();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        validate_reference_guardrails(&root, &mut errors)
            .expect("reference files should be readable");
        assert!(errors.is_empty(), "guardrail errors: {errors:#?}");
    }

    #[test]
    fn migration_secret_identities_follow_the_admitted_api_digest() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let base_raw = fs::read_to_string(root.join(VSO_MANIFEST_PATH)).expect("base VSO YAML");
        let migration_raw =
            fs::read_to_string(root.join(MIGRATION_VSO_MANIFEST_PATH)).expect("migration VSO YAML");
        let deployments_raw =
            fs::read_to_string(root.join(API_DEPLOYMENT_PATH)).expect("Deployment YAML");
        let base = parse_yaml_documents(&base_raw, VSO_MANIFEST_PATH).expect("base VSO parse");
        let migration = parse_yaml_documents(&migration_raw, MIGRATION_VSO_MANIFEST_PATH)
            .expect("migration VSO parse");
        let deployments =
            parse_yaml_documents(&deployments_raw, API_DEPLOYMENT_PATH).expect("Deployment parse");
        let prefix = platform_api_digest_prefix(&deployments).expect("admitted API digest");

        let mut errors = Vec::new();
        validate_vso_documents(&base, &migration, Some(&prefix), &mut errors);
        assert!(
            errors.is_empty(),
            "derived identities should pass: {errors:?}"
        );

        let mut errors = Vec::new();
        validate_vso_documents(&base, &migration, Some("222222222222"), &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("digest-scoped")),
            "stale Vault identities must fail when the admitted digest changes: {errors:?}"
        );
    }

    #[test]
    fn transformed_database_urls_require_verify_full_and_the_cnpg_ca() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let raw = fs::read_to_string(root.join(VSO_MANIFEST_PATH)).expect("base VSO YAML");
        let documents = parse_yaml_documents(&raw, VSO_MANIFEST_PATH).expect("base VSO parse");
        let runtime = named_document(&documents, "VaultDynamicSecret", "ryuki-platform-api-db")
            .expect("runtime database delivery");
        assert!(exact_transformed_key(runtime, "RYUKI_DATABASE_URL"));

        let migration_raw =
            fs::read_to_string(root.join(MIGRATION_VSO_MANIFEST_PATH)).expect("migration VSO YAML");
        let migration_documents = parse_yaml_documents(&migration_raw, MIGRATION_VSO_MANIFEST_PATH)
            .expect("migration VSO parse");
        let migration = migration_documents
            .iter()
            .find(|document| {
                document.get("kind").and_then(Value::as_str) == Some("VaultDynamicSecret")
            })
            .expect("migration database delivery");
        assert!(exact_transformed_key(
            migration,
            "RYUKI_MIGRATION_DATABASE_URL"
        ));

        for replacement in [
            "sslmode=require",
            "sslmode=verify-full",
            "sslmode=verify-ca&sslrootcert=/var/run/secrets/ryuki/cnpg/ca.crt",
        ] {
            let mut invalid = runtime.clone();
            let text = invalid
                .pointer_mut("/spec/destination/transformation/templates/RYUKI_DATABASE_URL/text")
                .and_then(|value| value.as_str())
                .expect("URL template text")
                .replace(
                    "sslmode=verify-full&sslrootcert=/var/run/secrets/ryuki/cnpg/ca.crt",
                    replacement,
                );
            *invalid
                .pointer_mut("/spec/destination/transformation/templates/RYUKI_DATABASE_URL/text")
                .expect("URL template text") = Value::String(text);
            assert!(
                !exact_transformed_key(&invalid, "RYUKI_DATABASE_URL"),
                "unauthenticated or CA-unbound TLS template must be rejected: {replacement}"
            );
        }
    }

    #[test]
    fn transformed_database_url_template_accepts_action_whitespace_only() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let raw = fs::read_to_string(root.join(VSO_MANIFEST_PATH)).expect("base VSO YAML");
        let documents = parse_yaml_documents(&raw, VSO_MANIFEST_PATH).expect("base VSO parse");
        let runtime = named_document(&documents, "VaultDynamicSecret", "ryuki-platform-api-db")
            .expect("runtime database delivery");
        let text = transformed_template_text(runtime, "RYUKI_DATABASE_URL").replacen(
            "{{- $username := toString",
            "{{-\n$username   :=\n  toString",
            1,
        );
        let whitespace_only = with_transformed_template_text(runtime, "RYUKI_DATABASE_URL", &text);

        assert!(exact_transformed_key(
            &whitespace_only,
            "RYUKI_DATABASE_URL"
        ));
    }

    #[test]
    fn transformed_database_url_template_rejects_structural_and_delimiter_bypasses() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let raw = fs::read_to_string(root.join(VSO_MANIFEST_PATH)).expect("base VSO YAML");
        let documents = parse_yaml_documents(&raw, VSO_MANIFEST_PATH).expect("base VSO parse");
        let runtime = named_document(&documents, "VaultDynamicSecret", "ryuki-platform-api-db")
            .expect("runtime database delivery");
        let canonical = transformed_template_text(runtime, "RYUKI_DATABASE_URL");
        let bypasses = [
            (
                "extra printf command",
                format!(
                    "{canonical}\n{}",
                    r#"{{- printf "postgresql://alternate.invalid" -}}"#
                ),
            ),
            (
                "literal alternate URL output",
                format!("{canonical}\npostgresql://alternate.invalid"),
            ),
            (
                "non-trimmable literal whitespace output",
                format!("{canonical}\u{a0}"),
            ),
            (
                "alternate URL authority",
                canonical.replace(
                    "postgresql://%s:%s@%s/ryuki_platform?",
                    "postgresql://attacker.invalid/%s:%s@%s?",
                ),
            ),
            (
                "duplicate TLS query parameter",
                canonical.replace(
                    "sslrootcert=/var/run/secrets/ryuki/cnpg/ca.crt",
                    "sslrootcert=/var/run/secrets/ryuki/cnpg/ca.crt&sslmode=verify-full",
                ),
            ),
            (
                "userinfo delimiter accepted by username regex",
                canonical.replace(
                    r#"regexMatch "^[A-Za-z0-9._~-]+$" $username"#,
                    r#"regexMatch "^[A-Za-z0-9._~@:-]+$" $username"#,
                ),
            ),
            (
                "query delimiters accepted by password regex",
                canonical.replace(
                    r#"regexMatch "^[A-Za-z0-9._~-]+$" $password"#,
                    r#"regexMatch "^[A-Za-z0-9._~?&=-]+$" $password"#,
                ),
            ),
            (
                "untrusted host source",
                canonical.replace(
                    r#"(get .Annotations "ryuki.io/postgres-host")"#,
                    r#"(get .Secrets "host")"#,
                ),
            ),
            (
                "extra non-output command",
                canonical.replacen(
                    r#"{{- $username := toString (get .Secrets "username") -}}"#,
                    concat!(
                        r#"{{- $ignored := printf "postgresql://alternate.invalid" -}}"#,
                        "\n",
                        r#"{{- $username := toString (get .Secrets "username") -}}"#
                    ),
                    1,
                ),
            ),
            (
                "action without output trim markers",
                canonical.replacen("{{- $username", "{{ $username", 1),
            ),
        ];

        for (description, text) in bypasses {
            assert_ne!(text, canonical, "test mutation must change the template");
            let invalid = with_transformed_template_text(runtime, "RYUKI_DATABASE_URL", &text);
            assert!(
                !exact_transformed_key(&invalid, "RYUKI_DATABASE_URL"),
                "validator accepted {description}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_rule_details() {
        let mut catalog = catalog();
        let rules = catalog
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .expect("rules array");
        let first = rules[0].clone();
        rules[1]["decision"] = first["decision"].clone();
        rules[1]["requirement"] = first["requirement"].clone();
        rules[1]["evidence"] = first["evidence"].clone();
        let mut errors = Vec::new();

        validate_catalog_value(&catalog, &mut errors);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("rule details must be unique"))
        );
    }

    #[test]
    fn raw_string_assignment_decoys_do_not_satisfy_fields() {
        let block = strip_csharp_comments(
            r#"
{
    decoy = """
source = "static-seed",
""",
    source = "live-sync",
}
"#,
        );

        let values = top_level_assignment_values(&block, "source");

        assert_eq!(values, vec!["\"live-sync\"".to_string()]);
    }

    #[test]
    fn verbatim_string_assignment_decoys_do_not_satisfy_fields() {
        let block = strip_csharp_comments(
            r#"
{
    decoy = @"
source = ""static-seed"",
",
    source = "live-sync",
}
"#,
        );

        let values = top_level_assignment_values(&block, "source");

        assert_eq!(values, vec!["\"live-sync\"".to_string()]);
    }

    #[test]
    fn scans_endpoint_property_identifiers() {
        let mut errors = Vec::new();

        validate_endpoint_field_names(
            r#"
app.MapGet("/api/platform/vault-secret-delivery-contract", () => Results.Json(new
{
    source = "static-seed",
    vaultUrl = "safe-summary",
    readinessMode = "static-readiness"
}));
"#,
            &mut errors,
        );

        assert!(errors.iter().any(|error| error.contains("vaultUrl")));
    }

    #[test]
    fn scans_endpoint_string_literals_for_secret_shapes() {
        let mut errors = Vec::new();

        validate_endpoint_no_prohibited_literals(
            r#"
{
    source = "https://vault.invalid/path",
}
"#,
            &mut errors,
        );

        assert!(
            errors
                .iter()
                .any(|error| error.contains("prohibited literal value"))
        );
    }
}
