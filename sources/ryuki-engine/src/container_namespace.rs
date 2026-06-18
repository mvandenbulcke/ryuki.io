use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NamespaceStatus {
    Active,
    Creating,
    Terminating,
    Suspended,
}

impl std::fmt::Display for NamespaceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NamespaceStatus::Active => write!(f, "Active"),
            NamespaceStatus::Creating => write!(f, "Creating"),
            NamespaceStatus::Terminating => write!(f, "Terminating"),
            NamespaceStatus::Suspended => write!(f, "Suspended"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Environment {
    Dev,
    Test,
    Staging,
    Prod,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Dev => write!(f, "Dev"),
            Environment::Test => write!(f, "Test"),
            Environment::Staging => write!(f, "Staging"),
            Environment::Prod => write!(f, "Prod"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RequestStatus {
    Draft,
    Validated,
    Approved,
    Provisioned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    pub cpu_limit: u32,
    pub cpu_request: u32,
    pub memory_limit_gb: u32,
    pub memory_request_gb: u32,
    pub storage_gb: u32,
    pub max_pods: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sNamespace {
    pub id: String,
    pub name: String,
    pub cluster: String,
    pub site: String,
    pub resource_quota: ResourceQuota,
    pub network_policy: String,
    pub service_accounts: Vec<String>,
    pub status: NamespaceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRequest {
    pub id: String,
    pub requester: String,
    pub namespace_name: String,
    pub cluster: String,
    pub site: String,
    pub cpu_request: u32,
    pub memory_gb: u32,
    pub storage_gb: u32,
    pub environment: Environment,
    pub purpose: String,
    pub status: RequestStatus,
}

// ─── Pure helpers ──────────────────────────────────────────────────────────────

pub fn build_quota(cpu: u32, memory_gb: u32, storage_gb: u32) -> ResourceQuota {
    // saturating_mul so an unvalidated call can never panic (debug) or silently
    // wrap (release). validate_capacity_bounds is the real gate (-> 400) and
    // guarantees these products fit i32 for any request that reaches the repo.
    ResourceQuota {
        cpu_limit: cpu.saturating_mul(2),
        cpu_request: cpu,
        memory_limit_gb: memory_gb.saturating_mul(2),
        memory_request_gb: memory_gb,
        storage_gb,
        max_pods: cpu.saturating_mul(8).max(16),
    }
}

pub fn parse_environment(environment: &str) -> Result<Environment, String> {
    match environment {
        "Dev" => Ok(Environment::Dev),
        "Test" => Ok(Environment::Test),
        "Staging" => Ok(Environment::Staging),
        "Prod" => Ok(Environment::Prod),
        other => Err(format!(
            "Invalid environment: {other}. Must be Dev, Test, Staging, or Prod"
        )),
    }
}

pub fn validate_capacity(cpu: u32, memory: u32, storage: u32) -> Result<(), String> {
    if cpu == 0 {
        return Err("cpu must be greater than zero".into());
    }
    if memory == 0 {
        return Err("memory must be greater than zero".into());
    }
    if storage == 0 {
        return Err("storage must be greater than zero".into());
    }
    Ok(())
}

/// Validate that the RAW cpu/memory/storage AND the DERIVED quota columns that
/// build_quota persists (cpu_limit = cpu*2, memory_limit_gb = memory*2,
/// max_pods = cpu*8) all fit in i32 (the DB INTEGER columns). Checked with
/// checked_mul so an oversized request is rejected here (-> 400) rather than
/// overflowing u32 in build_quota or failing i32::try_from in the repo (-> 500).
pub fn validate_capacity_bounds(cpu: u32, memory: u32, storage: u32) -> Result<(), String> {
    let max = i32::MAX as u32;
    for (value, label) in [(cpu, "cpu"), (memory, "memory"), (storage, "storage")] {
        if value > max {
            return Err(format!("{label} value {value} exceeds maximum allowed"));
        }
    }
    for (base, mult, label) in [
        (cpu, 2u32, "cpu_limit"),
        (cpu, 8, "max_pods"),
        (memory, 2, "memory_limit_gb"),
    ] {
        match base.checked_mul(mult) {
            Some(product) if product <= max => {}
            _ => {
                return Err(format!(
                    "{label} (derived from {base}*{mult}) exceeds maximum allowed"
                ));
            }
        }
    }
    Ok(())
}

/// Build a new K8sNamespace (Creating status) and its paired ContainerRequest (Provisioned).
/// IDs use full Uuid::new_v4().
pub fn build_namespace_and_request(
    name: &str,
    cluster: &str,
    site: &str,
    cpu: u32,
    memory: u32,
    storage: u32,
    environment: Environment,
) -> (K8sNamespace, ContainerRequest) {
    let ns_id = Uuid::new_v4().to_string();
    let req_id = Uuid::new_v4().to_string();
    let namespace = K8sNamespace {
        id: ns_id.clone(),
        name: name.to_string(),
        cluster: cluster.to_string(),
        site: site.to_string(),
        resource_quota: build_quota(cpu, memory, storage),
        network_policy: format!(
            "{}-{}-default",
            site.to_lowercase(),
            environment.to_string().to_lowercase()
        ),
        service_accounts: vec![format!("{name}-deployer")],
        status: NamespaceStatus::Creating,
    };
    let request = ContainerRequest {
        id: req_id,
        requester: "platform-engineering".into(),
        namespace_name: name.to_string(),
        cluster: cluster.to_string(),
        site: site.to_string(),
        cpu_request: cpu,
        memory_gb: memory,
        storage_gb: storage,
        environment,
        purpose: "Namespace provisioning".into(),
        status: RequestStatus::Provisioned,
    };
    (namespace, request)
}

// ─── Pure read surface (degrades to empty slices when called without a store) ──

pub fn list_namespaces(site: &str, namespaces: &[K8sNamespace]) -> Value {
    let filtered: Vec<&K8sNamespace> = if site.is_empty() {
        namespaces.iter().collect()
    } else {
        namespaces.iter().filter(|ns| ns.site == site).collect()
    };
    json!({
        "source": "database",
        "site": if site.is_empty() { "all" } else { site },
        "count": filtered.len(),
        "namespaces": filtered
    })
}

pub fn get_namespace_response(namespace: &K8sNamespace) -> Value {
    json!({
        "source": "database",
        "namespace": namespace,
        "resource_quota": namespace.resource_quota
    })
}

pub fn get_cluster_utilization(site: &str, namespaces: &[K8sNamespace]) -> Value {
    let mut clusters: BTreeMap<String, (usize, u32, u32)> = BTreeMap::new();

    for namespace in namespaces
        .iter()
        .filter(|ns| site.is_empty() || ns.site == site)
    {
        let entry = clusters
            .entry(namespace.cluster.clone())
            .or_insert((0, 0, 0));
        entry.0 += 1;
        entry.1 += namespace.resource_quota.cpu_request;
        entry.2 += namespace.resource_quota.memory_request_gb;
    }

    let utilization: Vec<Value> = clusters
        .into_iter()
        .map(
            |(cluster, (namespace_count, total_cpu_allocated, total_memory_allocated_gb))| {
                json!({
                    "cluster": cluster,
                    "namespace_count": namespace_count,
                    "total_cpu_allocated": total_cpu_allocated,
                    "total_memory_allocated_gb": total_memory_allocated_gb
                })
            },
        )
        .collect();

    json!({
        "source": "database",
        "site": if site.is_empty() { "all" } else { site },
        "clusters": utilization
    })
}

pub fn validate_namespace_name_response(
    name: &str,
    cluster: &str,
    existing: Option<&K8sNamespace>,
) -> Value {
    json!({
        "source": "database",
        "name": name,
        "cluster": cluster,
        "available": existing.is_none(),
        "reason": existing.map(|ns| format!("Namespace already exists with id {}", ns.id))
    })
}

pub fn get_k8s_summary(site: &str, namespaces: &[K8sNamespace]) -> Value {
    let filtered: Vec<&K8sNamespace> = namespaces
        .iter()
        .filter(|ns| site.is_empty() || ns.site == site)
        .collect();
    let clusters: BTreeSet<String> = filtered.iter().map(|ns| ns.cluster.clone()).collect();
    let total_cpu_allocated: u32 = filtered
        .iter()
        .map(|ns| ns.resource_quota.cpu_request)
        .sum();
    let total_memory_allocated_gb: u32 = filtered
        .iter()
        .map(|ns| ns.resource_quota.memory_request_gb)
        .sum();
    let total_storage_allocated_gb: u32 =
        filtered.iter().map(|ns| ns.resource_quota.storage_gb).sum();

    json!({
        "source": "database",
        "site": if site.is_empty() { "all" } else { site },
        "total_namespaces": filtered.len(),
        "clusters": clusters.len(),
        "total_cpu_allocated": total_cpu_allocated,
        "total_memory_allocated_gb": total_memory_allocated_gb,
        "total_storage_allocated_gb": total_storage_allocated_gb
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ns(
        id: &str,
        name: &str,
        cluster: &str,
        site: &str,
        status: NamespaceStatus,
    ) -> K8sNamespace {
        K8sNamespace {
            id: id.into(),
            name: name.into(),
            cluster: cluster.into(),
            site: site.into(),
            resource_quota: build_quota(4, 8, 100),
            network_policy: "deny-by-default".into(),
            service_accounts: vec!["test-deployer".into()],
            status,
        }
    }

    #[test]
    fn test_build_quota() {
        let q = build_quota(8, 16, 200);
        assert_eq!(q.cpu_limit, 16);
        assert_eq!(q.cpu_request, 8);
        assert_eq!(q.memory_limit_gb, 32);
        assert_eq!(q.memory_request_gb, 16);
        assert_eq!(q.storage_gb, 200);
        assert_eq!(q.max_pods, 64);
    }

    #[test]
    fn test_build_quota_min_pods() {
        // cpu=1 -> cpu*8=8 < 16, so max_pods=16
        let q = build_quota(1, 2, 10);
        assert_eq!(q.max_pods, 16);
    }

    #[test]
    fn test_parse_environment_valid() {
        assert_eq!(parse_environment("Dev").unwrap(), Environment::Dev);
        assert_eq!(parse_environment("Test").unwrap(), Environment::Test);
        assert_eq!(parse_environment("Staging").unwrap(), Environment::Staging);
        assert_eq!(parse_environment("Prod").unwrap(), Environment::Prod);
    }

    #[test]
    fn test_parse_environment_invalid() {
        assert!(parse_environment("dev").is_err());
        assert!(parse_environment("production").is_err());
        assert!(parse_environment("").is_err());
    }

    #[test]
    fn test_validate_capacity_zero_rejected() {
        assert!(validate_capacity(0, 8, 100).is_err());
        assert!(validate_capacity(4, 0, 100).is_err());
        assert!(validate_capacity(4, 8, 0).is_err());
        assert!(validate_capacity(4, 8, 100).is_ok());
    }

    #[test]
    fn test_build_namespace_and_request() {
        let env = Environment::Staging;
        let (ns, req) = build_namespace_and_request(
            "frpar-api-staging",
            "frpar-k8s-01",
            "FRPAR",
            10,
            24,
            250,
            env,
        );
        assert_eq!(ns.name, "frpar-api-staging");
        assert_eq!(ns.cluster, "frpar-k8s-01");
        assert_eq!(ns.site, "FRPAR");
        assert_eq!(ns.status, NamespaceStatus::Creating);
        assert_eq!(ns.network_policy, "frpar-staging-default");
        assert_eq!(ns.service_accounts, vec!["frpar-api-staging-deployer"]);
        assert!(!ns.id.is_empty());

        assert_eq!(req.namespace_name, "frpar-api-staging");
        assert_eq!(req.cluster, "frpar-k8s-01");
        assert_eq!(req.status, RequestStatus::Provisioned);
        assert_eq!(req.cpu_request, 10);
        assert_eq!(req.memory_gb, 24);
        assert_eq!(req.storage_gb, 250);
    }

    #[test]
    fn test_list_namespaces_filter() {
        let namespaces = vec![
            make_ns(
                "ns-1",
                "defra-apps",
                "defra-aks-01",
                "DEFRA",
                NamespaceStatus::Active,
            ),
            make_ns(
                "ns-2",
                "gblon-obs",
                "gblon-k8s-01",
                "GBLON",
                NamespaceStatus::Active,
            ),
        ];
        let all = list_namespaces("", &namespaces);
        assert_eq!(all["count"], 2);
        let defra = list_namespaces("DEFRA", &namespaces);
        assert_eq!(defra["count"], 1);
        assert_eq!(defra["namespaces"][0]["id"], "ns-1");
    }

    #[test]
    fn test_list_namespaces_empty_db() {
        let result = list_namespaces("DEFRA", &[]);
        assert_eq!(result["count"], 0);
        assert!(result["namespaces"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_get_namespace_response() {
        let ns = make_ns(
            "ns-1",
            "defra-apps",
            "defra-aks-01",
            "DEFRA",
            NamespaceStatus::Active,
        );
        let resp = get_namespace_response(&ns);
        assert_eq!(resp["namespace"]["id"], "ns-1");
        assert_eq!(resp["resource_quota"]["cpu_request"], 4);
    }

    #[test]
    fn test_validate_namespace_name_response_available() {
        let resp = validate_namespace_name_response("new-ns", "defra-aks-01", None);
        assert_eq!(resp["available"], true);
        assert!(resp["reason"].is_null());
    }

    #[test]
    fn test_validate_namespace_name_response_taken() {
        let ns = make_ns(
            "ns-1",
            "defra-apps",
            "defra-aks-01",
            "DEFRA",
            NamespaceStatus::Active,
        );
        let resp = validate_namespace_name_response("defra-apps", "defra-aks-01", Some(&ns));
        assert_eq!(resp["available"], false);
        assert!(resp["reason"].as_str().unwrap().contains("ns-1"));
    }

    #[test]
    fn test_get_cluster_utilization() {
        let namespaces = vec![
            make_ns(
                "ns-1",
                "defra-apps",
                "defra-aks-01",
                "DEFRA",
                NamespaceStatus::Active,
            ),
            make_ns(
                "ns-2",
                "defra-data",
                "defra-aks-02",
                "DEFRA",
                NamespaceStatus::Active,
            ),
            make_ns(
                "ns-3",
                "gblon-obs",
                "gblon-k8s-01",
                "GBLON",
                NamespaceStatus::Active,
            ),
        ];
        let util = get_cluster_utilization("DEFRA", &namespaces);
        let clusters = util["clusters"].as_array().unwrap();
        assert_eq!(clusters.len(), 2);
        assert!(clusters.iter().any(|c| c["cluster"] == "defra-aks-01"));
    }

    #[test]
    fn test_get_k8s_summary() {
        let namespaces = vec![
            make_ns(
                "ns-1",
                "frpar-api",
                "frpar-k8s-01",
                "FRPAR",
                NamespaceStatus::Creating,
            ),
            make_ns(
                "ns-2",
                "frpar-edge",
                "frpar-k8s-01",
                "FRPAR",
                NamespaceStatus::Active,
            ),
        ];
        let summary = get_k8s_summary("FRPAR", &namespaces);
        assert_eq!(summary["total_namespaces"], 2);
        assert_eq!(summary["clusters"], 1);
        // build_quota(4,8,100) -> cpu_request=4 each -> total=8
        assert_eq!(summary["total_cpu_allocated"], 8);
    }

    #[test]
    fn test_enum_serde_roundtrip() {
        // Confirm serde serializes to PascalCase variant name (no rename attribute)
        let s = serde_json::to_value(NamespaceStatus::Active).unwrap();
        assert_eq!(s.as_str().unwrap(), "Active");
        let s = serde_json::to_value(NamespaceStatus::Terminating).unwrap();
        assert_eq!(s.as_str().unwrap(), "Terminating");
        let e = serde_json::to_value(Environment::Staging).unwrap();
        assert_eq!(e.as_str().unwrap(), "Staging");
        let r = serde_json::to_value(RequestStatus::Provisioned).unwrap();
        assert_eq!(r.as_str().unwrap(), "Provisioned");
    }
}
