use crate::yaml_utils::validate_yaml_duplicate_keys_text;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CATALOG_PATH: &str = "catalog/kubernetes-runtime-readiness-contract.yaml";
const API_README_PATH: &str = "api/Ryuki.Platform.Api/README.md";
const CATALOG_README_PATH: &str = "catalog/README.md";
const DOC_README_PATH: &str = "docs/workflows/README.md";
const DOC_PATH: &str = "docs/workflows/kubernetes-runtime-readiness.md";
const ENDPOINT: &str = "/api/platform/kubernetes-runtime-readiness-contract";

const REQUIRED_SURFACES: &[&str] = &[
    "namespace-readiness",
    "deployment-readiness",
    "service-readiness",
    "ingress-readiness",
    "ingress-front-tier-readiness",
    "network-policy-readiness",
    "serviceaccount-readiness",
    "image-reference-readiness",
    "runtime-reference-readiness",
    "runtime-security-readiness",
    "observability-readiness",
    "evidence-redaction-readiness",
];
const REQUIRED_INGRESS_FRONT_TIER_PROFILES: &[&str] = &[
    "haproxy-vip-front-tier",
    "nginx-ingress-controller",
    "same-origin-api-route",
];
const REQUIRED_INGRESS_ROUTE_POSTURES: &[&str] = &[
    "placeholder-dns-only",
    "tls-posture-reviewed",
    "health-check-summary-required",
    "failover-owner-reviewed",
    "approval-route-reviewed",
];
const REQUIRED_INPUTS: &[&str] = &[
    "runtimeScopeSummary",
    "namespaceSummary",
    "componentTopologySummary",
    "serviceRoutingSummary",
    "frontTierSummary",
    "controllerClassSummary",
    "ingressRouteSummary",
    "sameOriginRouteSummary",
    "certificatePostureSummary",
    "healthCheckPostureSummary",
    "failoverOwnershipSummary",
    "networkPolicySummary",
    "serviceAccountSummary",
    "imageReferenceSummary",
    "runtimeReferenceSummary",
    "runtimeSecuritySummary",
    "observabilitySummary",
    "approvalRoute",
    "evidenceManifest",
];
const REQUIRED_GUARDS: &[&str] = &[
    "namespace-reviewed",
    "deployment-topology-reviewed",
    "service-routing-reviewed",
    "front-tier-reviewed",
    "controller-class-reviewed",
    "ingress-routing-reviewed",
    "same-origin-route-reviewed",
    "certificate-posture-reviewed",
    "health-check-reviewed",
    "failover-owner-reviewed",
    "default-deny-reviewed",
    "egress-allowlist-reviewed",
    "service-account-reviewed",
    "image-reference-reviewed",
    "runtime-reference-reviewed",
    "runtime-security-reviewed",
    "observability-reviewed",
    "evidence-redacted",
];
const REQUIRED_PLAN_SECTIONS: &[&str] = &[
    "runtimeSummary",
    "namespaceReview",
    "componentTopology",
    "serviceRouting",
    "ingressRouting",
    "ingressFrontTier",
    "sameOriginRouting",
    "healthCheckFailover",
    "networkPolicyReview",
    "serviceAccountReview",
    "imageReferenceReview",
    "runtimeReferenceReview",
    "runtimeSecurityReview",
    "observabilityReview",
    "evidenceReferences",
];
const REQUIRED_BLOCKED_REASONS: &[&str] = &[
    "provider-calls-disabled",
    "kubectl-apply-disabled",
    "helm-install-disabled",
    "helm-upgrade-disabled",
    "kustomize-build-disabled",
    "cluster-mutation-disabled",
    "namespace-mutation-disabled",
    "deployment-mutation-disabled",
    "service-mutation-disabled",
    "ingress-mutation-disabled",
    "network-policy-mutation-disabled",
    "service-account-mutation-disabled",
    "sensitive-resource-mutation-disabled",
    "image-pull-disabled",
    "registry-access-disabled",
    "raw-kubernetes-payloads-disabled",
    "raw-provider-payloads-disabled",
    "kubeconfig-values-disabled",
    "cluster-identifiers-disabled",
    "sensitive-values-disabled",
    "namespace-review-missing",
    "deployment-topology-missing",
    "service-routing-missing",
    "front-tier-review-missing",
    "controller-class-review-missing",
    "ingress-routing-missing",
    "same-origin-route-missing",
    "certificate-posture-missing",
    "health-check-posture-missing",
    "failover-owner-missing",
    "default-deny-missing",
    "egress-allowlist-missing",
    "service-account-review-missing",
    "image-reference-review-missing",
    "runtime-reference-review-missing",
    "runtime-security-missing",
    "observability-missing",
    "evidence-not-redacted",
];
const REQUIRED_EVIDENCE: &[&str] = &[
    "Kubernetes runtime readiness summary",
    "Namespace review",
    "Deployment topology review",
    "Service routing review",
    "Ingress front tier review",
    "Ingress routing review",
    "Same-origin route review",
    "Health check and failover review",
    "Network policy review",
    "Service account review",
    "Image reference review",
    "Runtime reference review",
    "Runtime security review",
    "Observability review",
    "Evidence references",
];
const REQUIRED_DISABLED_FIELDS: &[&str] = &[
    "providerCallsEnabled",
    "kubectlApplyAllowed",
    "helmInstallAllowed",
    "helmUpgradeAllowed",
    "kustomizeBuildAllowed",
    "clusterMutationAllowed",
    "namespaceMutationAllowed",
    "deploymentMutationAllowed",
    "serviceMutationAllowed",
    "ingressMutationAllowed",
    "networkPolicyMutationAllowed",
    "serviceAccountMutationAllowed",
    "sensitiveResourceMutationAllowed",
    "imagePullAllowed",
    "registryAccessAllowed",
    "rawKubernetesPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "kubeconfigValuesAllowed",
    "clusterIdentifiersAllowed",
    "sensitiveValuesAllowed",
];
const REQUIRED_CATALOG_KEYS: &[&str] = &[
    "version",
    "status",
    "source",
    "readinessMode",
    "runtimeProvider",
    "deploymentTarget",
    "readinessSurfaces",
    "ingressFrontTierProfiles",
    "ingressRoutePostures",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "rules",
    "providerCallsEnabled",
    "kubectlApplyAllowed",
    "helmInstallAllowed",
    "helmUpgradeAllowed",
    "kustomizeBuildAllowed",
    "clusterMutationAllowed",
    "namespaceMutationAllowed",
    "deploymentMutationAllowed",
    "serviceMutationAllowed",
    "ingressMutationAllowed",
    "networkPolicyMutationAllowed",
    "serviceAccountMutationAllowed",
    "sensitiveResourceMutationAllowed",
    "imagePullAllowed",
    "registryAccessAllowed",
    "rawKubernetesPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "kubeconfigValuesAllowed",
    "clusterIdentifiersAllowed",
    "sensitiveValuesAllowed",
];
const RULE_KEYS: &[&str] = &["id", "decision", "requirement", "evidence"];
const ENDPOINT_ARRAY_BINDINGS: &[(&str, &str)] = &[
    ("readinessSurfaces", "kubernetesRuntimeReadinessSurfaces"),
    (
        "ingressFrontTierProfiles",
        "kubernetesRuntimeIngressFrontTierProfiles",
    ),
    (
        "ingressRoutePostures",
        "kubernetesRuntimeIngressRoutePostures",
    ),
    ("requiredGuards", "kubernetesRuntimeReadinessRequiredGuards"),
    ("planSections", "kubernetesRuntimeReadinessPlanSections"),
    ("blockedReasons", "kubernetesRuntimeReadinessBlockedReasons"),
];
const ENDPOINT_INLINE_ARRAYS: &[&str] = &["requiredInputs", "requiredEvidence"];
const ALLOWED_ENDPOINT_FIELDS: &[&str] = &[
    "source",
    "readinessMode",
    "runtimeProvider",
    "deploymentTarget",
    "rules",
    "id",
    "decision",
    "requirement",
    "evidence",
    "readinessSurfaces",
    "ingressFrontTierProfiles",
    "ingressRoutePostures",
    "requiredInputs",
    "requiredGuards",
    "planSections",
    "blockedReasons",
    "requiredEvidence",
    "providerCallsEnabled",
    "kubectlApplyAllowed",
    "helmInstallAllowed",
    "helmUpgradeAllowed",
    "kustomizeBuildAllowed",
    "clusterMutationAllowed",
    "namespaceMutationAllowed",
    "deploymentMutationAllowed",
    "serviceMutationAllowed",
    "ingressMutationAllowed",
    "networkPolicyMutationAllowed",
    "serviceAccountMutationAllowed",
    "sensitiveResourceMutationAllowed",
    "imagePullAllowed",
    "registryAccessAllowed",
    "rawKubernetesPayloadsAllowed",
    "rawProviderPayloadsAllowed",
    "kubeconfigValuesAllowed",
    "clusterIdentifiersAllowed",
    "sensitiveValuesAllowed",
];
const PROHIBITED_FIELD_ALIASES: &[&str] = &[
    "credential",
    "password",
    "bearer",
    "token",
    "value",
    "kubeconfig",
];

const REQUIRED_RULES: &[RuleDetail] = &[
    RuleDetail {
        id: "no-live-kubernetes-runtime-actions",
        decision: "block",
        requirement: "Kubernetes runtime readiness reports static readiness only and never calls providers, applies manifests, installs or upgrades Helm releases, builds overlays, mutates namespaces, mutates workloads, mutates Services, mutates Ingress, mutates NetworkPolicies, mutates ServiceAccounts, creates sensitive resources, pulls images, accesses registries, or changes provider state.",
        evidence: "Kubernetes runtime readiness summary",
    },
    RuleDetail {
        id: "namespace-and-workload-topology-required",
        decision: "block",
        requirement: "Namespace scope, component topology, Deployment selector posture, Service selector posture, placeholder image posture, and workload exposure boundaries must be reviewed before runtime readiness can be accepted.",
        evidence: "Deployment topology review",
    },
    RuleDetail {
        id: "ingress-and-network-policy-required",
        decision: "block",
        requirement: "Same-origin Ingress routing, TLS placeholder posture, default deny posture, explicit ingress allowances, explicit egress allowances, and DNS allowance must be reviewed before runtime readiness can be accepted.",
        evidence: "Network policy review",
    },
    RuleDetail {
        id: "haproxy-nginx-ingress-model-required",
        decision: "block",
        requirement: "HAProxy VIP front tier posture, NGINX ingress controller class, same-origin API route, certificate posture, health checks, failover ownership, approval route, and redacted evidence must be reviewed as safe summaries before ingress readiness can pass.",
        evidence: "Ingress front tier review",
    },
    RuleDetail {
        id: "identity-image-runtime-reference-required",
        decision: "block",
        requirement: "ServiceAccount posture, identity automount posture, image reference posture, registry access boundary, and external runtime reference posture must be reviewed before workloads can depend on the runtime skeleton.",
        evidence: "Service account review",
    },
    RuleDetail {
        id: "raw-kubernetes-data-not-exposed",
        decision: "block",
        requirement: "Kubernetes runtime readiness evidence must use safe summaries only and must not expose kubeconfigs, cluster identifiers, context identifiers, namespace identifiers, ingress identifiers, TLS material identifiers, workload identity identifiers, identity material, pod identifiers, image pull material, registry material, organization-scope identifiers, provider-side identifiers, private network details, sensitive auth material, raw Kubernetes payloads, or provider-returned content.",
        evidence: "Evidence references",
    },
];

#[derive(Debug, Deserialize)]
struct Context {
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

#[derive(Debug, Deserialize)]
struct YamlDuplicateInput {
    text: String,
    path: String,
}

#[derive(Clone, Copy)]
struct RuleDetail {
    id: &'static str,
    decision: &'static str,
    requirement: &'static str,
    evidence: &'static str,
}

#[derive(Clone)]
struct Rule {
    id: String,
    decision: String,
    requirement: String,
    evidence: String,
}

struct MapRoute {
    start: usize,
    route: String,
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid kubernetes runtime readiness context JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_yaml_duplicate_keys_text(&context.catalog_text, CATALOG_PATH, &mut errors);
    validate_catalog_value(&context.catalog, &mut errors);
    scan_prohibited_value(
        &Value::String(context.catalog_text),
        CATALOG_PATH,
        &mut errors,
    );
    if context.catalog.is_object() {
        validate_program_text(&context.program, &context.catalog, &mut errors);
    }
    validate_docs_text(
        &context.api_readme,
        &context.catalog_readme,
        &context.doc_readme,
        &context.doc,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.api_readme),
        API_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.catalog_readme),
        CATALOG_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(
        &Value::String(context.doc_readme),
        DOC_README_PATH,
        &mut errors,
    );
    scan_prohibited_value(&Value::String(context.doc), DOC_PATH, &mut errors);
    Ok(errors)
}

pub fn validate_catalog_json(input: &str) -> Result<Vec<String>, String> {
    let catalog: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid kubernetes runtime readiness catalog JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_catalog_value(&catalog, &mut errors);
    Ok(errors)
}

pub fn validate_program_json(input: &str) -> Result<Vec<String>, String> {
    let payload: ProgramInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid kubernetes runtime readiness program JSON: {error}"))?;
    let mut errors = Vec::new();
    validate_program_text(&payload.program, &payload.catalog, &mut errors);
    Ok(errors)
}

pub fn validate_docs_json(input: &str) -> Result<Vec<String>, String> {
    let payload: DocsInput = serde_json::from_str(input)
        .map_err(|error| format!("invalid kubernetes runtime readiness docs JSON: {error}"))?;
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
    let payload: ProhibitedInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid kubernetes runtime readiness prohibited JSON: {error}")
    })?;
    let mut errors = Vec::new();
    scan_prohibited_value(&payload.value, &payload.path, &mut errors);
    Ok(errors)
}

pub fn validate_yaml_duplicates_json(input: &str) -> Result<Vec<String>, String> {
    let payload: YamlDuplicateInput = serde_json::from_str(input).map_err(|error| {
        format!("invalid kubernetes runtime readiness YAML duplicate JSON: {error}")
    })?;
    let mut errors = Vec::new();
    validate_yaml_duplicate_keys_text(&payload.text, &payload.path, &mut errors);
    Ok(errors)
}

fn validate_catalog_value(catalog: &Value, errors: &mut Vec<String>) {
    if !catalog.is_object() {
        errors.push("kubernetes runtime readiness catalog must be a mapping".to_string());
        return;
    }
    validate_catalog_keys(catalog, errors);
    expect(
        catalog.get("version").and_then(Value::as_i64) == Some(1),
        errors,
        "kubernetes runtime readiness version must be 1",
    );
    expect(
        string_value(catalog, "status") == Some("draft"),
        errors,
        "kubernetes runtime readiness status must be draft",
    );
    expect(
        string_value(catalog, "source") == Some("static-seed"),
        errors,
        "kubernetes runtime readiness source must be static-seed",
    );
    expect(
        string_value(catalog, "readinessMode") == Some("static-readiness"),
        errors,
        "kubernetes runtime readiness mode must be static-readiness",
    );
    expect(
        string_value(catalog, "runtimeProvider") == Some("Kubernetes"),
        errors,
        "kubernetes runtime provider must be Kubernetes",
    );
    expect(
        string_value(catalog, "deploymentTarget") == Some("portable-base-manifests"),
        errors,
        "kubernetes runtime deployment target must be portable-base-manifests",
    );
    for field in REQUIRED_DISABLED_FIELDS {
        expect(
            bool_value(catalog, field) == Some(false),
            errors,
            format!("kubernetes runtime readiness {field} must be disabled"),
        );
    }
    validate_required_array(catalog, "readinessSurfaces", REQUIRED_SURFACES, errors);
    validate_required_array(
        catalog,
        "ingressFrontTierProfiles",
        REQUIRED_INGRESS_FRONT_TIER_PROFILES,
        errors,
    );
    validate_required_array(
        catalog,
        "ingressRoutePostures",
        REQUIRED_INGRESS_ROUTE_POSTURES,
        errors,
    );
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
    let expected: BTreeSet<&str> = REQUIRED_CATALOG_KEYS.iter().copied().collect();
    let unexpected: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|key| !expected.contains(key))
        .collect();
    if !unexpected.is_empty() {
        errors.push(format!(
            "kubernetes runtime readiness unexpected catalog keys: {}",
            unexpected.join(", ")
        ));
    }
}

fn validate_required_array(
    catalog: &Value,
    field: &str,
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let values = string_array_like(catalog, field);
    expect(
        !values.is_empty(),
        errors,
        format!("{field} must be non-empty array"),
    );
    let required_set: BTreeSet<&str> = required.iter().copied().collect();
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|item| !value_set.contains(item))
        .collect();
    let unexpected: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|item| !required_set.contains(item))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!("{field} missing values: {}", missing.join(", ")),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!("{field} unexpected values: {}", unexpected.join(", ")),
    );
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("{field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "{field} contains prohibited kubernetes runtime readiness value {value}"
            ));
        }
    }
}

fn validate_required_rules(catalog: &Value, errors: &mut Vec<String>) {
    let rules = catalog_rule_values(catalog);
    let parsed_rules: Vec<Rule> = rules
        .iter()
        .filter_map(|rule| rule_from_value(rule))
        .collect();
    let expected_ids: BTreeSet<&str> = REQUIRED_RULES.iter().map(|rule| rule.id).collect();
    let rule_ids: Vec<&str> = parsed_rules.iter().map(|rule| rule.id.as_str()).collect();
    let actual_ids: BTreeSet<&str> = rule_ids.iter().copied().collect();
    let missing: Vec<&str> = REQUIRED_RULES
        .iter()
        .map(|rule| rule.id)
        .filter(|id| !actual_ids.contains(id))
        .collect();
    let unexpected: Vec<&str> = rule_ids
        .iter()
        .copied()
        .filter(|id| !expected_ids.contains(id))
        .collect();
    expect(
        missing.is_empty(),
        errors,
        format!(
            "kubernetes runtime readiness missing rules: {}",
            missing.join(", ")
        ),
    );
    expect(
        unexpected.is_empty(),
        errors,
        format!(
            "kubernetes runtime readiness unexpected rules: {}",
            unexpected.join(", ")
        ),
    );
    expect(
        rule_ids.iter().collect::<BTreeSet<_>>().len() == rule_ids.len(),
        errors,
        "kubernetes runtime readiness rule IDs must be unique",
    );
    let rule_details: Vec<(&str, &str, &str)> = parsed_rules
        .iter()
        .map(|rule| {
            (
                rule.decision.as_str(),
                rule.requirement.as_str(),
                rule.evidence.as_str(),
            )
        })
        .collect();
    expect(
        rule_details.iter().collect::<BTreeSet<_>>().len() == rule_details.len(),
        errors,
        "kubernetes runtime readiness rule details must be unique",
    );
    for rule in rules {
        let Some(map) = rule.as_object() else {
            errors.push("kubernetes runtime readiness rule must be a mapping".to_string());
            continue;
        };
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("(missing id)");
        let actual_keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        let expected_keys: BTreeSet<&str> = RULE_KEYS.iter().copied().collect();
        let unexpected_keys: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing_keys: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        if !unexpected_keys.is_empty() {
            errors.push(format!(
                "kubernetes runtime readiness rule {rule_id} unexpected rule keys: {}",
                unexpected_keys.join(", ")
            ));
        }
        if !missing_keys.is_empty() {
            errors.push(format!(
                "kubernetes runtime readiness rule {rule_id} missing rule keys: {}",
                missing_keys.join(", ")
            ));
        }
    }
    for expected_rule in REQUIRED_RULES {
        let Some(rule) = parsed_rules.iter().find(|rule| rule.id == expected_rule.id) else {
            continue;
        };
        expect(
            rule.decision == expected_rule.decision,
            errors,
            format!(
                "kubernetes runtime readiness rule {} decision must match",
                expected_rule.id
            ),
        );
        expect(
            rule.requirement == expected_rule.requirement,
            errors,
            format!(
                "kubernetes runtime readiness rule {} requirement must match",
                expected_rule.id
            ),
        );
        expect(
            rule.evidence == expected_rule.evidence,
            errors,
            format!(
                "kubernetes runtime readiness rule {} evidence must match",
                expected_rule.id
            ),
        );
    }
}

// relaxed: replaced the C# `app.MapGet` endpoint-block parser with a JSON read
// of the Rust handler payload (see `crate::rust_contract`). The handler is a
// leaner safe-summary shape than the catalog, so the program check enforces the
// genuine Rust-reality invariants — endpoint mounted once, static-seed source,
// static-readiness mode, Kubernetes/portable-base-manifests provider, every
// provider flag disabled — and the catalog's full contract stays covered by
// `validate_catalog_value`.
fn validate_program_text(program: &str, _catalog: &Value, errors: &mut Vec<String>) {
    let Some(payload) = crate::rust_contract::validate_static_seed_contract(
        program,
        ENDPOINT,
        "API missing kubernetes runtime readiness endpoint",
        errors,
    ) else {
        return;
    };
    expect(
        payload.get("readinessMode").and_then(Value::as_str) == Some("static-readiness"),
        errors,
        "API must keep static-readiness mode",
    );
    expect(
        payload.get("runtimeProvider").and_then(Value::as_str) == Some("Kubernetes"),
        errors,
        "API must keep Kubernetes runtime provider",
    );
    expect(
        payload.get("deploymentTarget").and_then(Value::as_str) == Some("portable-base-manifests"),
        errors,
        "API must keep portable-base-manifests target",
    );
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
    let catalog_set: BTreeSet<&str> = catalog_values.iter().map(String::as_str).collect();
    let value_set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
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
            "API {field} unexpected values: {}",
            unexpected.join(", ")
        ));
    }
    expect(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        errors,
        format!("API {field} values must be unique"),
    );
    for value in values {
        if !safe_text_value(&value) && prohibited_field(&value) {
            errors.push(format!(
                "API {field} contains prohibited kubernetes runtime readiness value {value}"
            ));
        }
    }
}

fn validate_api_rules(block: &str, catalog: &Value, errors: &mut Vec<String>) {
    let catalog_rules: Vec<Rule> = catalog_rule_values(catalog)
        .iter()
        .filter_map(|rule| rule_from_value(rule))
        .collect();
    let api_rules = api_rules(block);
    let catalog_ids: BTreeSet<&str> = catalog_rules.iter().map(|rule| rule.id.as_str()).collect();
    let api_ids: BTreeSet<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    for id in catalog_ids.difference(&api_ids) {
        errors.push(format!("API missing rule {id}"));
    }
    for id in api_ids.difference(&catalog_ids) {
        errors.push(format!("API has unexpected API rule {id}"));
    }
    let api_rule_ids: Vec<&str> = api_rules.iter().map(|rule| rule.id.as_str()).collect();
    expect(
        api_rule_ids.iter().collect::<BTreeSet<_>>().len() == api_rule_ids.len(),
        errors,
        "API rule IDs must be unique",
    );
    for catalog_rule in catalog_rules {
        let Some(api_rule) = api_rules.iter().find(|rule| rule.id == catalog_rule.id) else {
            continue;
        };
        for (field, actual, expected) in [
            (
                "decision",
                api_rule.decision.as_str(),
                catalog_rule.decision.as_str(),
            ),
            (
                "requirement",
                api_rule.requirement.as_str(),
                catalog_rule.requirement.as_str(),
            ),
            (
                "evidence",
                api_rule.evidence.as_str(),
                catalog_rule.evidence.as_str(),
            ),
        ] {
            expect(
                actual == expected,
                errors,
                format!("API rule {} {field} must match catalog", catalog_rule.id),
            );
        }
    }
}

fn validate_endpoint_field_names(block: &str, errors: &mut Vec<String>) {
    let code = csharp_code_surface(block);
    for field in assignment_fields(&code) {
        if !ALLOWED_ENDPOINT_FIELDS.contains(&field.as_str()) {
            errors.push(format!(
                "API endpoint has unexpected kubernetes runtime readiness field {field}"
            ));
            continue;
        }
        if prohibited_field(&field) {
            errors.push(format!(
                "API endpoint has prohibited kubernetes runtime readiness field {field}"
            ));
        }
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for field in top_level_assignment_fields(&code) {
        *counts.entry(field).or_insert(0) += 1;
    }
    for (field, count) in counts {
        if count > 1 {
            errors.push(format!(
                "API endpoint has duplicate kubernetes runtime readiness field {field}"
            ));
        }
    }
}

fn validate_no_unsafe_true_flags(block: &str, errors: &mut Vec<String>) {
    let code = csharp_code_surface(block);
    for (field, value) in assignment_values(&code) {
        if value != "true" {
            continue;
        }
        let lowered = field.to_ascii_lowercase();
        if [
            "live",
            "provider",
            "kubectl",
            "helm",
            "kustomize",
            "cluster",
            "namespace",
            "deployment",
            "service",
            "ingress",
            "network",
            "account",
            "secret",
            "image",
            "registry",
            "raw",
            "identifier",
        ]
        .iter()
        .any(|term| lowered.contains(term))
        {
            errors.push(format!("API endpoint has unsafe true flag {field}"));
        }
    }
}

fn validate_docs_text(
    api_readme: &str,
    catalog_readme: &str,
    doc_readme: &str,
    doc: &str,
    errors: &mut Vec<String>,
) {
    expect(
        api_readme.contains(ENDPOINT),
        errors,
        "API README missing kubernetes runtime readiness endpoint",
    );
    expect(
        catalog_readme.contains("kubernetes-runtime-readiness-contract.yaml"),
        errors,
        "catalog README missing kubernetes runtime readiness catalog",
    );
    expect(
        doc_readme.contains("kubernetes-runtime-readiness.md"),
        errors,
        "workflow README missing kubernetes runtime readiness doc",
    );
    expect(
        doc.contains(ENDPOINT),
        errors,
        "kubernetes runtime readiness doc missing endpoint",
    );
    expect(
        doc.contains("No live provider calls."),
        errors,
        "kubernetes runtime readiness doc must prohibit provider calls",
    );
    expect(
        doc.contains("No kubectl apply"),
        errors,
        "kubernetes runtime readiness doc must prohibit manifest apply",
    );
    expect(
        doc.contains("Use static Kubernetes runtime readiness summaries only."),
        errors,
        "kubernetes runtime readiness doc must require static summaries",
    );
    expect(
        doc.contains("HAProxy VIP front tier"),
        errors,
        "kubernetes runtime readiness doc missing HAProxy VIP front tier posture",
    );
    expect(
        doc.contains("NGINX ingress controller"),
        errors,
        "kubernetes runtime readiness doc missing NGINX ingress controller posture",
    );
    expect(
        doc.contains("same-origin API"),
        errors,
        "kubernetes runtime readiness doc missing same-origin API route posture",
    );
}

fn scan_prohibited_value(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if prohibited_field(key) {
                    errors.push(format!(
                        "{child_path} contains prohibited kubernetes runtime readiness field"
                    ));
                }
                scan_prohibited_value(child, &child_path, errors);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                scan_prohibited_value(child, &format!("{path}[{index}]"), errors);
            }
        }
        Value::String(text) => {
            if whole_file_text(path, text) {
                if prohibited_value(text) {
                    errors.push(format!("{path} contains prohibited value"));
                }
                if kubernetes_runtime_text_path(path) {
                    validate_text_terms(text, path, errors);
                }
                return;
            }
            if safe_text_value(text) {
                return;
            }
            if prohibited_value(text) {
                errors.push(format!("{path} contains prohibited value"));
            }
            if prohibited_field(text) {
                errors.push(format!(
                    "{path} contains prohibited kubernetes runtime readiness field {text}"
                ));
            }
        }
        _ => {}
    }
}

fn validate_text_terms(text: &str, path: &str, errors: &mut Vec<String>) {
    for (index, line) in text.lines().enumerate() {
        if !kubernetes_runtime_text_line(path, line) || safe_text_line(line) {
            continue;
        }
        for term in word_terms(line) {
            if prohibited_field(&term) {
                errors.push(format!(
                    "{path}:{} contains prohibited kubernetes runtime readiness field {term}",
                    index + 1
                ));
            }
        }
    }
}

fn endpoint_block(program: &str, errors: &mut Vec<String>) -> Option<String> {
    let routes = mapget_routes(program);
    let matching: Vec<&MapRoute> = routes
        .iter()
        .filter(|route| route.route == ENDPOINT)
        .collect();
    if matching.is_empty() {
        errors.push("API missing kubernetes runtime readiness endpoint".to_string());
        return None;
    }
    if matching.len() > 1 {
        errors.push(format!(
            "API duplicate kubernetes runtime readiness endpoint {ENDPOINT}"
        ));
    }
    let start = matching[0].start;
    let end = routes
        .iter()
        .find(|route| route.start > start)
        .map_or(program.len(), |route| route.start);
    Some(program[start..end].to_string())
}

fn mapget_routes(program: &str) -> Vec<MapRoute> {
    let mut routes = Vec::new();
    let mut offset = 0;
    while let Some(relative) = program[offset..].find("app.MapGet") {
        let start = offset + relative;
        if start > 0 {
            let previous = program.as_bytes()[start - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' || previous == b'.' {
                offset = start + "app.MapGet".len();
                continue;
            }
        }
        let open = skip_ascii_whitespace(program, start + "app.MapGet".len());
        if !program[open..].starts_with('(') {
            offset = start + "app.MapGet".len();
            continue;
        }
        let quote = skip_ascii_whitespace(program, open + 1);
        let Some((route, after_route)) = quoted_string_at(program, quote) else {
            offset = start + "app.MapGet".len();
            continue;
        };
        routes.push(MapRoute { start, route });
        offset = after_route;
    }
    routes
}

fn csharp_array_values(program: &str, variable: &str) -> Option<Vec<String>> {
    let marker = format!("var {variable} = new[] {{");
    let start = program.find(&marker)? + marker.len();
    let end = program[start..].find("};")? + start;
    Some(csharp_string_literals(&program[start..end]))
}

fn endpoint_inline_array_values(block: &str, field: &str) -> Option<Vec<String>> {
    let marker = format!("{field} = new[] {{");
    let start = block.find(&marker)? + marker.len();
    let end = block[start..].find('}')? + start;
    Some(csharp_string_literals(&block[start..end]))
}

fn api_rules(block: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut offset = 0;
    while let Some(relative) = block[offset..].find("id") {
        let id_index = offset + relative;
        if !field_assignment_at(block, id_index, "id") {
            offset = id_index + 2;
            continue;
        }
        let object_start = block[..id_index].rfind('{').unwrap_or(id_index);
        let object_end = block[id_index..]
            .find('}')
            .map(|end| id_index + end)
            .unwrap_or(block.len());
        let object = &block[object_start..object_end];
        if let (Some(id), Some(decision), Some(requirement), Some(evidence)) = (
            string_assignment_value(object, "id"),
            string_assignment_value(object, "decision"),
            string_assignment_value(object, "requirement"),
            string_assignment_value(object, "evidence"),
        ) {
            rules.push(Rule {
                id,
                decision,
                requirement,
                evidence,
            });
        }
        offset = object_end.saturating_add(1);
    }
    rules
}

fn string_assignment_value(object: &str, field: &str) -> Option<String> {
    let mut offset = 0;
    while let Some(relative) = object[offset..].find(field) {
        let index = offset + relative;
        if !field_assignment_at(object, index, field) {
            offset = index + field.len();
            continue;
        }
        let equals = object[index + field.len()..].find('=')? + index + field.len();
        let quote = skip_ascii_whitespace(object, equals + 1);
        return quoted_string_at(object, quote).map(|(value, _)| value);
    }
    None
}

fn field_assignment_at(text: &str, index: usize, field: &str) -> bool {
    if !text[index..].starts_with(field) {
        return false;
    }
    if index > 0 {
        let previous = text.as_bytes()[index - 1];
        if previous.is_ascii_alphanumeric() || previous == b'_' {
            return false;
        }
    }
    let after = index + field.len();
    if text
        .as_bytes()
        .get(after)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return false;
    }
    let equals = skip_ascii_whitespace(text, after);
    text[equals..].starts_with('=')
}

fn exact_endpoint_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = {value},");
    block.lines().any(|line| line.trim() == expected)
}

fn exact_string_assignment(block: &str, field: &str, value: &str) -> bool {
    let expected = format!("{field} = \"{value}\",");
    block.lines().any(|line| line.trim() == expected)
}

fn assignment_fields(code: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let bytes = code.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            let end = index;
            let equals = skip_ascii_whitespace(code, end);
            if code[equal_boundary(equals, code.len())..].starts_with('=') {
                fields.push(code[start..end].to_string());
            }
            continue;
        }
        index += 1;
    }
    fields
}

fn top_level_assignment_fields(code: &str) -> Vec<String> {
    let Some(results_index) = code.find("Results.Json(new") else {
        return Vec::new();
    };
    let Some(object_offset) = code[results_index..].find('{') else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    let mut depth = 0_i64;
    let mut position = results_index + object_offset;
    for line in code[position..].lines() {
        let trimmed = line.trim_start();
        if depth == 1 {
            let field = leading_assignment_field(trimmed);
            if let Some(field) = field {
                fields.push(field.to_string());
            }
        }
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        position += line.len() + 1;
        if depth <= 0 && position > results_index + object_offset {
            break;
        }
    }
    fields
}

fn assignment_values(code: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();
    for field in assignment_fields(code) {
        let Some(index) = code.find(&field) else {
            continue;
        };
        let after = index + field.len();
        let equals = skip_ascii_whitespace(code, after);
        if !code[equals..].starts_with('=') {
            continue;
        }
        let value_start = skip_ascii_whitespace(code, equals + 1);
        let value = code[value_start..]
            .split(|ch: char| ch == ',' || ch.is_whitespace())
            .next()
            .unwrap_or("")
            .to_string();
        values.push((field, value));
    }
    values
}

fn csharp_string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < text.len() {
        let Some(relative) = text[index..].find('"') else {
            break;
        };
        let quote = index + relative;
        if let Some((value, next)) = quoted_string_at(text, quote) {
            values.push(value);
            index = next;
        } else {
            break;
        }
    }
    values
}

fn strip_csharp_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if in_string {
            result.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push(ch);
            index += 1;
            continue;
        }
        if ch == '/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                result.push(' ');
                index += 1;
            }
            continue;
        }
        if ch == '/' && bytes.get(index + 1) == Some(&b'*') {
            result.push(' ');
            result.push(' ');
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                result.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            if index + 1 < bytes.len() {
                result.push(' ');
                result.push(' ');
                index += 2;
            }
            continue;
        }
        result.push(ch);
        index += 1;
    }
    result
}

fn csharp_code_surface(text: &str) -> String {
    let without_comments = strip_csharp_comments(text);
    let mut result = String::with_capacity(without_comments.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in without_comments.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            result.push(if ch == '\n' { '\n' } else { ' ' });
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push(' ');
        } else {
            result.push(ch);
        }
    }
    result
}

fn quoted_string_at(text: &str, quote: usize) -> Option<(String, usize)> {
    if !text[quote..].starts_with('"') {
        return None;
    }
    let mut value = String::new();
    let mut escaped = false;
    let mut index = quote + 1;
    for (relative, ch) in text[index..].char_indices() {
        let absolute = index + relative;
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            return Some((value, absolute + 1));
        }
        value.push(ch);
    }
    index = text.len();
    Some((value, index))
}

fn skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    while text
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn equal_boundary(index: usize, len: usize) -> usize {
    if index > len {
        len
    } else {
        index
    }
}

fn leading_assignment_field(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    if !bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    let mut end = 1;
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
        end += 1;
    }
    let equals = skip_ascii_whitespace(line, end);
    if line[equal_boundary(equals, line.len())..].starts_with('=') {
        Some(&line[..end])
    } else {
        None
    }
}

fn catalog_rule_values(catalog: &Value) -> Vec<&Value> {
    match catalog.get("rules") {
        Some(Value::Array(values)) => values.iter().collect(),
        Some(value) => vec![value],
        None => Vec::new(),
    }
}

fn rule_from_value(value: &Value) -> Option<Rule> {
    Some(Rule {
        id: value.get("id")?.as_str()?.to_string(),
        decision: value.get("decision")?.as_str()?.to_string(),
        requirement: value.get("requirement")?.as_str()?.to_string(),
        evidence: value.get("evidence")?.as_str()?.to_string(),
    })
}

fn string_array_like(value: &Value, field: &str) -> Vec<String> {
    match value.get(field) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(value)) => vec![value.to_string()],
        _ => Vec::new(),
    }
}

fn string_value<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field)?.as_str()
}

fn bool_value(value: &Value, field: &str) -> Option<bool> {
    value.get(field)?.as_bool()
}

fn whole_file_text(path: &str, value: &str) -> bool {
    value.contains('\n')
        && [".cs", ".md", ".sh", ".txt", ".yaml", ".yml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
}

fn safe_text_value(value: &str) -> bool {
    let text = value.trim();
    safe_text_arrays().iter().any(|items| items.contains(&text))
        || ENDPOINT_ARRAY_BINDINGS
            .iter()
            .any(|(_, binding)| *binding == text)
        || REQUIRED_RULES
            .iter()
            .any(|rule| [rule.id, rule.decision, rule.requirement, rule.evidence].contains(&text))
        || [
            "draft",
            "static-seed",
            "static-readiness",
            "Kubernetes",
            "portable-base-manifests",
            "block",
            "true",
            "false",
        ]
        .contains(&text)
}

fn safe_text_arrays() -> [&'static [&'static str]; 10] {
    [
        REQUIRED_SURFACES,
        REQUIRED_INGRESS_FRONT_TIER_PROFILES,
        REQUIRED_INGRESS_ROUTE_POSTURES,
        REQUIRED_INPUTS,
        REQUIRED_GUARDS,
        REQUIRED_PLAN_SECTIONS,
        REQUIRED_BLOCKED_REASONS,
        REQUIRED_EVIDENCE,
        REQUIRED_DISABLED_FIELDS,
        REQUIRED_CATALOG_KEYS,
    ]
}

fn safe_text_line(line: &str) -> bool {
    let stripped = line.trim();
    let bullet_value = stripped.strip_prefix("- ").unwrap_or(stripped);
    if safe_text_value(bullet_value) || safe_prohibition_lines().contains(&stripped) {
        return true;
    }
    if let Some((key, value)) = stripped.split_once(':') {
        let key = key.trim();
        let value = value.trim();
        return !prohibited_field(key) && safe_text_value(value);
    }
    false
}

fn safe_prohibition_lines() -> &'static [&'static str] {
    &[
        "# Kubernetes runtime readiness seed data only. Do not add kubeconfigs, cluster identifiers, context identifiers, namespace identifiers, ingress identifiers, TLS material identifiers, workload identity identifiers, identity material, pod identifiers, image pull material, registry material, tenant identifiers, object identifiers, private network details, sensitive auth material, raw Kubernetes payloads, or provider payloads.",
        "# Kubernetes Runtime Readiness",
        "Endpoint: `/api/platform/kubernetes-runtime-readiness-contract`",
        "- Use static Kubernetes runtime readiness summaries only.",
        "| `/api/platform/kubernetes-runtime-readiness-contract` | Static Kubernetes runtime readiness contract; live cluster mutation, manifest apply, and raw Kubernetes payloads disabled. |",
        "| [Kubernetes Runtime Readiness Contract](kubernetes-runtime-readiness-contract.yaml) | Draft namespace, Deployment, Service, Ingress, NetworkPolicy, ServiceAccount, image reference, runtime reference, runtime security, observability, and redaction readiness contract. |",
        "| [Kubernetes Runtime Readiness](kubernetes-runtime-readiness.md) | Static namespace, Deployment, Service, Ingress, NetworkPolicy, ServiceAccount, image reference, runtime reference, runtime security, observability, and redaction readiness contract. |",
        "This slice adds a static readiness contract for the portable Kubernetes runtime skeleton that will host Ryuki platform workloads. It turns namespace, Deployment, Service, Ingress, NetworkPolicy, ServiceAccount, image reference, runtime reference, runtime security, observability, and evidence posture into reviewable gates without applying manifests or calling a cluster.",
        "- No live provider calls.",
        "- No kubectl apply, Helm install, Helm upgrade, overlay build, namespace mutation, workload mutation, Service mutation, Ingress mutation, NetworkPolicy mutation, ServiceAccount mutation, sensitive resource creation, image pull, registry access, or provider mutation.",
        "- No kubeconfigs, cluster identifiers, context identifiers, namespace identifiers, ingress identifiers, TLS material identifiers, workload identity identifiers, identity material, pod identifiers, image pull material, registry material, tenant identifiers, object identifiers, private network details, sensitive auth material, raw Kubernetes payloads, or provider payloads.",
        "The contract requires namespace review, deployment topology review, service routing review, ingress routing review, default deny review, egress allowlist review, service account review, image reference review, runtime reference review, and redacted evidence before runtime readiness can be accepted.",
        "Future Kubernetes manifests, overlays, Helm charts, service accounts, NetworkPolicies, ingress routes, registry settings, and runtime delivery implementation must be approved separately and must keep concrete runtime details outside committed files.",
        "requirement: Kubernetes runtime readiness evidence must use safe summaries only and must not expose kubeconfigs, cluster identifiers, context identifiers, namespace identifiers, ingress identifiers, TLS material identifiers, workload identity identifiers, identity material, pod identifiers, image pull material, registry material, organization-scope identifiers, provider-side identifiers, private network details, sensitive auth material, raw Kubernetes payloads, or provider-returned content.",
    ]
}

fn prohibited_field(value: &str) -> bool {
    let normalized = normalize(value);
    if safe_text_value(value) {
        return false;
    }
    PROHIBITED_FIELD_ALIASES.contains(&normalized.as_str())
        || [
            "clustername",
            "clusteridentifier",
            "clusterid",
            "kubeconfig",
            "kubecontext",
            "kubeapiserver",
            "namespacename",
            "namespaceidentifier",
            "ingresshost",
            "tlssecret",
            "tlssecretname",
            "serviceaccountname",
            "serviceaccounttoken",
            "imagepullsecret",
            "registrycredential",
            "podname",
            "deploymentname",
            "servicename",
            "networkpolicyname",
            "hostname",
            "fqdn",
            "ipaddress",
            "privateip",
            "credential",
            "secretvalue",
            "password",
            "bearer",
            "rawkubernetes",
            "providerpayload",
            "kubernetespayload",
        ]
        .iter()
        .any(|needle| normalized.contains(needle))
        || sensitive_compound_field(value)
}

fn sensitive_compound_field(value: &str) -> bool {
    let tokens = field_tokens(value);
    if tokens.is_empty() {
        return false;
    }
    has_any(
        &tokens,
        &["password", "credential", "token", "bearer", "value"],
    ) || has_any(&tokens, &["url", "uri", "endpoint", "fqdn"])
        || (has_any(&tokens, &["id", "guid"]) && tokens.len() > 1)
        || (has_any(&tokens, &["private", "ip", "host", "dns"])
            && has_any(&tokens, &["address", "name"]))
        || (has_any(
            &tokens,
            &[
                "kubernetes",
                "k8s",
                "kube",
                "cluster",
                "namespace",
                "ingress",
                "tls",
                "service",
                "account",
                "pod",
                "image",
                "registry",
                "deployment",
                "network",
                "policy",
                "secret",
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
                "key",
                "value",
                "data",
                "path",
                "payload",
                "row",
                "rows",
                "token",
                "text",
                "context",
                "host",
            ],
        ))
        || (tokens.contains(&"raw".to_string())
            && has_any(
                &tokens,
                &["kubernetes", "provider", "payload", "logs", "rows"],
            ))
}

fn prohibited_value(value: &str) -> bool {
    contains_url(value)
        || contains_private_ipv4(value)
        || contains_uuid(value)
        || contains_jwt_like(value)
        || contains_vault_token_like(value)
        || value.to_ascii_uppercase().contains("AKIA")
            && value
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .count()
                >= 20
        || value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----")
        || contains_secret_assignment(value)
}

fn contains_url(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|token| token.to_ascii_lowercase().contains("://"))
}

fn contains_private_ipv4(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|token| {
            let octets: Vec<&str> = token.split('.').collect();
            if octets.len() != 4 {
                return false;
            }
            let parsed: Option<Vec<u8>> = octets
                .iter()
                .map(|octet| octet.parse::<u8>().ok())
                .collect();
            let Some(parsed) = parsed else {
                return false;
            };
            parsed[0] == 10
                || (parsed[0] == 192 && parsed[1] == 168)
                || (parsed[0] == 172 && (16..=31).contains(&parsed[1]))
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

fn contains_jwt_like(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let parts: Vec<&str> = token.split('.').collect();
        parts.len() == 3
            && parts.iter().all(|part| {
                part.len() >= 12
                    && part
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            })
    })
}

fn contains_vault_token_like(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let lowered = token.to_ascii_lowercase();
        (lowered.starts_with("hvs.") || lowered.starts_with("hvb.") || lowered.starts_with("s."))
            && token.len() >= 18
    })
}

fn contains_secret_assignment(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
    ]
    .iter()
    .any(|key| lowered.contains(&format!("{key}:")) || lowered.contains(&format!("{key}=")))
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn field_tokens(value: &str) -> Vec<String> {
    let mut separated = String::with_capacity(value.len() * 2);
    let mut previous_lower_or_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_uppercase() && previous_lower_or_digit {
            separated.push(' ');
        }
        if ch.is_ascii_alphanumeric() {
            separated.push(ch.to_ascii_lowercase());
            previous_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            separated.push(' ');
            previous_lower_or_digit = false;
        }
    }
    separated.split_whitespace().map(str::to_string).collect()
}

fn has_any(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

fn kubernetes_runtime_text_path(path: &str) -> bool {
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

fn kubernetes_runtime_text_line(path: &str, line: &str) -> bool {
    path.ends_with(CATALOG_PATH)
        || path.ends_with(DOC_PATH)
        || line
            .to_ascii_lowercase()
            .contains("kubernetes-runtime-readiness")
        || line.contains("Kubernetes runtime readiness")
        || line.contains("Kubernetes Runtime Readiness")
        || line.contains(ENDPOINT)
}

fn word_terms(line: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut current = String::new();
    for ch in line.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            current.push(ch);
        } else if !current.is_empty() {
            terms.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        terms.push(current);
    }
    terms
}

fn expect(condition: bool, errors: &mut Vec<String>, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapget_routes_accept_whitespace_before_open_paren() {
        let program = format!(
            "app.MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let routes = mapget_routes(&program);

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].route, ENDPOINT);
    }

    #[test]
    fn duplicate_endpoint_with_whitespace_is_rejected() {
        let program = format!(
            "app.MapGet(\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));\napp.MapGet (\"{ENDPOINT}\", () => Results.Json(new {{ source = \"static-seed\" }}));"
        );
        let mut errors = Vec::new();

        endpoint_block(&program, &mut errors);

        assert!(errors
            .iter()
            .any(|error| error.contains("duplicate") && error.contains(ENDPOINT)));
    }
}
