use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};
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

type ContainerStore = (Vec<K8sNamespace>, Vec<ContainerRequest>);

static CONTAINER_STORE: OnceLock<Mutex<ContainerStore>> = OnceLock::new();

fn store() -> &'static Mutex<ContainerStore> {
    CONTAINER_STORE.get_or_init(|| Mutex::new((seed_namespaces(), seed_requests())))
}

fn quota(cpu: u32, memory_gb: u32, storage_gb: u32) -> ResourceQuota {
    ResourceQuota {
        cpu_limit: cpu * 2,
        cpu_request: cpu,
        memory_limit_gb: memory_gb * 2,
        memory_request_gb: memory_gb,
        storage_gb,
        max_pods: (cpu * 8).max(16),
    }
}

fn seed_namespaces() -> Vec<K8sNamespace> {
    vec![
        K8sNamespace {
            id: "k8s-defra-app-001".into(),
            name: "defra-apps-dev".into(),
            cluster: "defra-aks-01".into(),
            site: "DEFRA".into(),
            resource_quota: quota(8, 16, 200),
            network_policy: "deny-by-default".into(),
            service_accounts: vec!["defra-app-deployer".into(), "defra-app-reader".into()],
            status: NamespaceStatus::Active,
        },
        K8sNamespace {
            id: "k8s-defra-data-001".into(),
            name: "defra-data-prod".into(),
            cluster: "defra-aks-02".into(),
            site: "DEFRA".into(),
            resource_quota: quota(24, 96, 800),
            network_policy: "restricted-egress".into(),
            service_accounts: vec!["defra-data-runner".into()],
            status: NamespaceStatus::Active,
        },
        K8sNamespace {
            id: "k8s-gblon-obs-001".into(),
            name: "gblon-observability".into(),
            cluster: "gblon-k8s-01".into(),
            site: "GBLON".into(),
            resource_quota: quota(16, 64, 500),
            network_policy: "monitoring-ingress".into(),
            service_accounts: vec!["gblon-prometheus".into(), "gblon-grafana".into()],
            status: NamespaceStatus::Active,
        },
        K8sNamespace {
            id: "k8s-gblon-build-001".into(),
            name: "gblon-build-test".into(),
            cluster: "gblon-k8s-02".into(),
            site: "GBLON".into(),
            resource_quota: quota(12, 32, 300),
            network_policy: "ci-egress".into(),
            service_accounts: vec!["gblon-build-runner".into()],
            status: NamespaceStatus::Suspended,
        },
        K8sNamespace {
            id: "k8s-frpar-api-001".into(),
            name: "frpar-api-staging".into(),
            cluster: "frpar-k8s-01".into(),
            site: "FRPAR".into(),
            resource_quota: quota(10, 24, 250),
            network_policy: "staging-shared".into(),
            service_accounts: vec!["frpar-api-deployer".into()],
            status: NamespaceStatus::Creating,
        },
        K8sNamespace {
            id: "k8s-frpar-edge-001".into(),
            name: "frpar-edge-prod".into(),
            cluster: "frpar-k8s-01".into(),
            site: "FRPAR".into(),
            resource_quota: quota(20, 48, 400),
            network_policy: "edge-restricted".into(),
            service_accounts: vec!["frpar-edge-runtime".into()],
            status: NamespaceStatus::Active,
        },
    ]
}

fn seed_requests() -> Vec<ContainerRequest> {
    vec![
        ContainerRequest {
            id: "cr-defra-001".into(),
            requester: "alice.platform".into(),
            namespace_name: "defra-risk-dev".into(),
            cluster: "defra-aks-01".into(),
            site: "DEFRA".into(),
            cpu_request: 4,
            memory_gb: 12,
            storage_gb: 100,
            environment: Environment::Dev,
            purpose: "Risk model development".into(),
            status: RequestStatus::Validated,
        },
        ContainerRequest {
            id: "cr-gblon-001".into(),
            requester: "bob.sre".into(),
            namespace_name: "gblon-chaos-test".into(),
            cluster: "gblon-k8s-02".into(),
            site: "GBLON".into(),
            cpu_request: 6,
            memory_gb: 16,
            storage_gb: 120,
            environment: Environment::Test,
            purpose: "Chaos testing sandbox".into(),
            status: RequestStatus::Draft,
        },
        ContainerRequest {
            id: "cr-frpar-001".into(),
            requester: "carla.apps".into(),
            namespace_name: "frpar-payments-staging".into(),
            cluster: "frpar-k8s-01".into(),
            site: "FRPAR".into(),
            cpu_request: 8,
            memory_gb: 24,
            storage_gb: 200,
            environment: Environment::Staging,
            purpose: "Payments pre-prod validation".into(),
            status: RequestStatus::Approved,
        },
        ContainerRequest {
            id: "cr-defra-002".into(),
            requester: "diego.data".into(),
            namespace_name: "defra-analytics-prod".into(),
            cluster: "defra-aks-02".into(),
            site: "DEFRA".into(),
            cpu_request: 16,
            memory_gb: 64,
            storage_gb: 500,
            environment: Environment::Prod,
            purpose: "Analytics production workloads".into(),
            status: RequestStatus::Approved,
        },
    ]
}

fn parse_environment(environment: &str) -> Result<Environment, String> {
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

fn validate_capacity(cpu: u32, memory: u32, storage: u32) -> Result<(), String> {
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

pub fn list_namespaces(site: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let namespaces: Vec<K8sNamespace> = if site.is_empty() {
        store.0.clone()
    } else {
        store
            .0
            .iter()
            .filter(|ns| ns.site == site)
            .cloned()
            .collect()
    };

    Ok(json!({
        "source": "dry-run",
        "site": if site.is_empty() { "all" } else { site },
        "count": namespaces.len(),
        "namespaces": namespaces
    }))
}

pub fn get_namespace(id: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let namespace = store
        .0
        .iter()
        .find(|ns| ns.id == id)
        .ok_or_else(|| format!("Namespace '{id}' not found"))?;

    Ok(json!({
        "source": "dry-run",
        "namespace": namespace,
        "resource_quota": namespace.resource_quota
    }))
}

pub fn provision_namespace(
    name: &str,
    cluster: &str,
    site: &str,
    cpu: u32,
    memory: u32,
    storage: u32,
    environment: &str,
) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if cluster.trim().is_empty() {
        return Err("cluster cannot be empty".into());
    }
    if site.trim().is_empty() {
        return Err("site cannot be empty".into());
    }
    validate_capacity(cpu, memory, storage)?;
    let parsed_environment = parse_environment(environment)?;

    let mut store = store().lock().unwrap();
    if store.0.iter().any(|ns| {
        ns.name == name && ns.cluster == cluster && ns.status != NamespaceStatus::Terminating
    }) {
        return Err(format!(
            "Namespace '{name}' already exists on cluster '{cluster}'"
        ));
    }

    let id = format!(
        "k8s-{}-{}",
        site.to_lowercase(),
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
    );
    let namespace = K8sNamespace {
        id: id.clone(),
        name: name.to_string(),
        cluster: cluster.to_string(),
        site: site.to_string(),
        resource_quota: quota(cpu, memory, storage),
        network_policy: format!(
            "{}-{}-default",
            site.to_lowercase(),
            parsed_environment.to_string().to_lowercase()
        ),
        service_accounts: vec![format!("{}-deployer", name)],
        status: NamespaceStatus::Creating,
    };
    let request = ContainerRequest {
        id: format!("cr-{}", id.trim_start_matches("k8s-")),
        requester: "platform-engineering (mock)".into(),
        namespace_name: name.to_string(),
        cluster: cluster.to_string(),
        site: site.to_string(),
        cpu_request: cpu,
        memory_gb: memory,
        storage_gb: storage,
        environment: parsed_environment,
        purpose: "Namespace provisioning dry-run".into(),
        status: RequestStatus::Provisioned,
    };

    store.0.push(namespace.clone());
    store.1.push(request.clone());

    Ok(json!({
        "source": "dry-run",
        "provisioned": true,
        "namespace": namespace,
        "request": request
    }))
}

pub fn update_quota(id: &str, cpu: u32, memory: u32, storage: u32) -> Result<Value, String> {
    validate_capacity(cpu, memory, storage)?;
    let mut store = store().lock().unwrap();
    let namespace = store
        .0
        .iter_mut()
        .find(|ns| ns.id == id)
        .ok_or_else(|| format!("Namespace '{id}' not found"))?;

    if namespace.status == NamespaceStatus::Terminating {
        return Err(format!(
            "Cannot update quota for terminating namespace '{id}'"
        ));
    }

    namespace.resource_quota = quota(cpu, memory, storage);

    Ok(json!({
        "source": "dry-run",
        "updated": true,
        "namespace": namespace
    }))
}

pub fn suspend_namespace(id: &str) -> Result<Value, String> {
    set_namespace_status(id, NamespaceStatus::Suspended)
}

pub fn resume_namespace(id: &str) -> Result<Value, String> {
    set_namespace_status(id, NamespaceStatus::Active)
}

pub fn terminate_namespace(id: &str) -> Result<Value, String> {
    set_namespace_status(id, NamespaceStatus::Terminating)
}

fn set_namespace_status(id: &str, status: NamespaceStatus) -> Result<Value, String> {
    let mut store = store().lock().unwrap();
    let namespace = store
        .0
        .iter_mut()
        .find(|ns| ns.id == id)
        .ok_or_else(|| format!("Namespace '{id}' not found"))?;

    namespace.status = status;

    Ok(json!({
        "source": "dry-run",
        "namespace": namespace
    }))
}

pub fn get_cluster_utilization(site: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let mut clusters: BTreeMap<String, (usize, u32, u32)> = BTreeMap::new();

    for namespace in store
        .0
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

    Ok(json!({
        "source": "dry-run",
        "site": if site.is_empty() { "all" } else { site },
        "clusters": utilization
    }))
}

pub fn validate_namespace_name(name: &str, cluster: &str) -> Result<Value, String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".into());
    }
    if cluster.trim().is_empty() {
        return Err("cluster cannot be empty".into());
    }

    let store = store().lock().unwrap();
    let existing = store.0.iter().find(|ns| {
        ns.name == name && ns.cluster == cluster && ns.status != NamespaceStatus::Terminating
    });

    Ok(json!({
        "source": "dry-run",
        "name": name,
        "cluster": cluster,
        "available": existing.is_none(),
        "reason": existing.map(|ns| format!("Namespace already exists with id {}", ns.id))
    }))
}

pub fn get_k8s_summary(site: &str) -> Result<Value, String> {
    let store = store().lock().unwrap();
    let namespaces: Vec<&K8sNamespace> = store
        .0
        .iter()
        .filter(|ns| site.is_empty() || ns.site == site)
        .collect();
    let clusters: BTreeSet<String> = namespaces.iter().map(|ns| ns.cluster.clone()).collect();
    let total_cpu_allocated: u32 = namespaces
        .iter()
        .map(|ns| ns.resource_quota.cpu_request)
        .sum();
    let total_memory_allocated_gb: u32 = namespaces
        .iter()
        .map(|ns| ns.resource_quota.memory_request_gb)
        .sum();
    let total_storage_allocated_gb: u32 = namespaces
        .iter()
        .map(|ns| ns.resource_quota.storage_gb)
        .sum();

    Ok(json!({
        "source": "dry-run",
        "site": if site.is_empty() { "all" } else { site },
        "total_namespaces": namespaces.len(),
        "clusters": clusters.len(),
        "total_cpu_allocated": total_cpu_allocated,
        "total_memory_allocated_gb": total_memory_allocated_gb,
        "total_storage_allocated_gb": total_storage_allocated_gb
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provision_and_list_namespaces() {
        let name = format!(
            "defra-test-{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let provisioned =
            provision_namespace(&name, "defra-aks-01", "DEFRA", 3, 8, 90, "Dev").unwrap();

        assert_eq!(provisioned["provisioned"], true);
        assert_eq!(provisioned["namespace"]["name"], name);
        assert_eq!(provisioned["namespace"]["status"], "Creating");

        let listed = list_namespaces("DEFRA").unwrap();
        assert!(listed["count"].as_u64().unwrap() >= 3);
        assert!(
            listed["namespaces"]
                .as_array()
                .unwrap()
                .iter()
                .any(|ns| ns["name"] == name)
        );
    }

    #[test]
    fn test_update_quota() {
        let updated = update_quota("k8s-defra-app-001", 14, 40, 350).unwrap();

        assert_eq!(updated["updated"], true);
        assert_eq!(updated["namespace"]["resource_quota"]["cpu_request"], 14);
        assert_eq!(
            updated["namespace"]["resource_quota"]["memory_request_gb"],
            40
        );
        assert_eq!(updated["namespace"]["resource_quota"]["storage_gb"], 350);
    }

    #[test]
    fn test_suspend_and_resume() {
        let name = format!(
            "gblon-suspend-{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let namespace =
            provision_namespace(&name, "gblon-k8s-01", "GBLON", 2, 4, 50, "Test").unwrap();
        let id = namespace["namespace"]["id"].as_str().unwrap();

        let suspended = suspend_namespace(id).unwrap();
        assert_eq!(suspended["namespace"]["status"], "Suspended");

        let resumed = resume_namespace(id).unwrap();
        assert_eq!(resumed["namespace"]["status"], "Active");
    }

    #[test]
    fn test_terminate_namespace() {
        let name = format!(
            "frpar-terminate-{}",
            Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        let namespace =
            provision_namespace(&name, "frpar-k8s-01", "FRPAR", 2, 4, 50, "Staging").unwrap();
        let id = namespace["namespace"]["id"].as_str().unwrap();

        let terminated = terminate_namespace(id).unwrap();
        assert_eq!(terminated["namespace"]["status"], "Terminating");
    }

    #[test]
    fn test_validate_unique_name() {
        let duplicate = validate_namespace_name("defra-apps-dev", "defra-aks-01").unwrap();
        assert_eq!(duplicate["available"], false);

        let unique = validate_namespace_name("defra-new-namespace", "defra-aks-01").unwrap();
        assert_eq!(unique["available"], true);
    }

    #[test]
    fn test_cluster_utilization() {
        let utilization = get_cluster_utilization("DEFRA").unwrap();
        let clusters = utilization["clusters"].as_array().unwrap();

        assert!(
            clusters
                .iter()
                .any(|cluster| cluster["cluster"] == "defra-aks-01")
        );
        assert!(
            clusters
                .iter()
                .any(|cluster| cluster["cluster"] == "defra-aks-02")
        );
        assert!(
            clusters
                .iter()
                .all(|cluster| cluster["namespace_count"].as_u64().unwrap() > 0)
        );
    }

    #[test]
    fn test_k8s_summary() {
        let summary = get_k8s_summary("FRPAR").unwrap();

        assert_eq!(summary["site"], "FRPAR");
        assert!(summary["total_namespaces"].as_u64().unwrap() >= 2);
        assert!(summary["clusters"].as_u64().unwrap() >= 1);
        assert!(summary["total_cpu_allocated"].as_u64().unwrap() >= 30);
        assert!(summary["total_memory_allocated_gb"].as_u64().unwrap() >= 72);
    }
}
