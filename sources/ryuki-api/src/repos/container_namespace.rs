//! Repository functions for `k8s_namespaces` and `container_requests`.
//!
//! # ID type
//! Both tables use TEXT primary keys (full UUID strings, e.g.
//! "550e8400-e29b-41d4-a716-446655440000").  Ids are bound and decoded
//! directly as `String`.
//!
//! # Enum encoding
//! `NamespaceStatus`, `Environment`, and `RequestStatus` have NO serde rename,
//! so the serde form == variant name == PascalCase == DB CHECK value.
//! Decode via `serde_json::from_value(Value::String(raw))` — no match helpers.
//! Confirmed CHECK constraints:
//!   status IN ('Active','Creating','Terminating','Suspended')
//!   environment IN ('Dev','Test','Staging','Prod')
//!   status IN ('Draft','Validated','Approved','Provisioned')
//!
//! # ResourceQuota flattening
//! `K8sNamespace.resource_quota` is a value object with 6 u32 fields, all
//! flattened into columns on `k8s_namespaces`.
//! Read: `u32::try_from(i32_val)` — negative values are a Decode error.
//! Write: `i32::try_from(u32_val)` — values exceeding i32::MAX are rejected
//! by the engine's `validate_capacity_bounds` before reaching the DB.
//!
//! # service_accounts TEXT[]
//! `k8s_namespaces.service_accounts` is `TEXT[]`.  sqlx decodes it natively
//! into `Vec<String>`.  Writes bind a `Vec<String>` slice directly.
//!
//! # provision_namespace transaction
//! Atomically: INSERT k8s_namespaces + INSERT container_requests in ONE tx.
//! Unique violation on (cluster, name) is propagated as `sqlx::Error`
//! (handler maps `is_unique_violation()` → 409).
//!
//! # Status transitions
//! suspend / resume / terminate are simple UPDATE status WHERE id = $1
//! RETURNING.  No from-state guards at the repo level; the handler enforces
//! the Terminating guard (no update if already Terminating — 409 illegal).

use ryuki_engine::container_namespace::{
    ContainerRequest, Environment, K8sNamespace, NamespaceStatus, RequestStatus, ResourceQuota,
};
use serde_json::Value;
use sqlx::PgPool;

// ─── Enum helpers ─────────────────────────────────────────────────────────────

fn enum_to_db<T: serde::Serialize>(val: &T) -> String {
    serde_json::to_value(val)
        .expect("enum serialization cannot fail")
        .as_str()
        .expect("enum serde value must be a string")
        .to_owned()
}

fn enum_from_db<T: serde::de::DeserializeOwned>(raw: &str, column: &str) -> Result<T, sqlx::Error> {
    serde_json::from_value(Value::String(raw.to_owned()))
        .map_err(|e| sqlx::Error::Decode(format!("{column}: corrupt value '{raw}': {e}").into()))
}

// ─── Column lists ─────────────────────────────────────────────────────────────

const NS_COLUMNS: &str = "id, name, cluster, site, \
     cpu_limit, cpu_request, memory_limit_gb, memory_request_gb, storage_gb, max_pods, \
     network_policy, service_accounts, status";

#[allow(dead_code)]
const REQ_COLUMNS: &str = "id, requester, namespace_name, cluster, site, \
     cpu_request, memory_gb, storage_gb, environment, purpose, status";

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct K8sNamespaceRow {
    id: String,
    name: String,
    cluster: String,
    site: String,
    cpu_limit: i32,
    cpu_request: i32,
    memory_limit_gb: i32,
    memory_request_gb: i32,
    storage_gb: i32,
    max_pods: i32,
    network_policy: String,
    service_accounts: Vec<String>,
    status: String,
}

impl K8sNamespaceRow {
    fn into_model(self) -> Result<K8sNamespace, sqlx::Error> {
        let status: NamespaceStatus = enum_from_db(&self.status, "k8s_namespaces.status")?;

        let cpu_limit = u32::try_from(self.cpu_limit).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "k8s_namespaces.cpu_limit: corrupt value {}: {e}",
                    self.cpu_limit
                )
                .into(),
            )
        })?;
        let cpu_request = u32::try_from(self.cpu_request).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "k8s_namespaces.cpu_request: corrupt value {}: {e}",
                    self.cpu_request
                )
                .into(),
            )
        })?;
        let memory_limit_gb = u32::try_from(self.memory_limit_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "k8s_namespaces.memory_limit_gb: corrupt value {}: {e}",
                    self.memory_limit_gb
                )
                .into(),
            )
        })?;
        let memory_request_gb = u32::try_from(self.memory_request_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "k8s_namespaces.memory_request_gb: corrupt value {}: {e}",
                    self.memory_request_gb
                )
                .into(),
            )
        })?;
        let storage_gb = u32::try_from(self.storage_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "k8s_namespaces.storage_gb: corrupt value {}: {e}",
                    self.storage_gb
                )
                .into(),
            )
        })?;
        let max_pods = u32::try_from(self.max_pods).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "k8s_namespaces.max_pods: corrupt value {}: {e}",
                    self.max_pods
                )
                .into(),
            )
        })?;

        Ok(K8sNamespace {
            id: self.id,
            name: self.name,
            cluster: self.cluster,
            site: self.site,
            resource_quota: ResourceQuota {
                cpu_limit,
                cpu_request,
                memory_limit_gb,
                memory_request_gb,
                storage_gb,
                max_pods,
            },
            network_policy: self.network_policy,
            service_accounts: self.service_accounts,
            status,
        })
    }
}

#[allow(dead_code)]
#[derive(sqlx::FromRow)]
struct ContainerRequestRow {
    id: String,
    requester: String,
    namespace_name: String,
    cluster: String,
    site: String,
    cpu_request: i32,
    memory_gb: i32,
    storage_gb: i32,
    environment: String,
    purpose: String,
    status: String,
}

impl ContainerRequestRow {
    fn into_model(self) -> Result<ContainerRequest, sqlx::Error> {
        let environment: Environment =
            enum_from_db(&self.environment, "container_requests.environment")?;
        let status: RequestStatus = enum_from_db(&self.status, "container_requests.status")?;
        let cpu_request = u32::try_from(self.cpu_request).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "container_requests.cpu_request: corrupt value {}: {e}",
                    self.cpu_request
                )
                .into(),
            )
        })?;
        let memory_gb = u32::try_from(self.memory_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "container_requests.memory_gb: corrupt value {}: {e}",
                    self.memory_gb
                )
                .into(),
            )
        })?;
        let storage_gb = u32::try_from(self.storage_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "container_requests.storage_gb: corrupt value {}: {e}",
                    self.storage_gb
                )
                .into(),
            )
        })?;
        Ok(ContainerRequest {
            id: self.id,
            requester: self.requester,
            namespace_name: self.namespace_name,
            cluster: self.cluster,
            site: self.site,
            cpu_request,
            memory_gb,
            storage_gb,
            environment,
            purpose: self.purpose,
            status,
        })
    }
}

// ─── Read functions ───────────────────────────────────────────────────────────

pub async fn list_namespaces(pool: &PgPool, site: &str) -> Result<Vec<K8sNamespace>, sqlx::Error> {
    let rows: Vec<K8sNamespaceRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {NS_COLUMNS} FROM k8s_namespaces ORDER BY id"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {NS_COLUMNS} FROM k8s_namespaces WHERE site = $1 ORDER BY id"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };
    rows.into_iter().map(|r| r.into_model()).collect()
}

pub async fn get_namespace(pool: &PgPool, id: &str) -> Result<Option<K8sNamespace>, sqlx::Error> {
    let row: Option<K8sNamespaceRow> = sqlx::query_as(&format!(
        "SELECT {NS_COLUMNS} FROM k8s_namespaces WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// Find a namespace by (cluster, name), ignoring Terminating ones (as the
/// engine's duplicate check does).  Used by validate_namespace_name.
pub async fn find_active_namespace_by_name(
    pool: &PgPool,
    name: &str,
    cluster: &str,
) -> Result<Option<K8sNamespace>, sqlx::Error> {
    let row: Option<K8sNamespaceRow> = sqlx::query_as(&format!(
        "SELECT {NS_COLUMNS} FROM k8s_namespaces \
         WHERE name = $1 AND cluster = $2 AND status <> 'Terminating'"
    ))
    .bind(name)
    .bind(cluster)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

#[allow(dead_code)]
pub async fn list_requests(
    pool: &PgPool,
    site: &str,
) -> Result<Vec<ContainerRequest>, sqlx::Error> {
    let rows: Vec<ContainerRequestRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {REQ_COLUMNS} FROM container_requests ORDER BY id"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {REQ_COLUMNS} FROM container_requests WHERE site = $1 ORDER BY id"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };
    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── Write functions ──────────────────────────────────────────────────────────

/// Atomically INSERT a K8sNamespace + ContainerRequest in one transaction.
/// Unique violation on (cluster, name) propagates as sqlx::Error (caller maps to 409).
pub async fn provision_namespace(
    pool: &PgPool,
    ns: &K8sNamespace,
    req: &ContainerRequest,
) -> Result<(), sqlx::Error> {
    // Convert u32 quota fields to i32 for INTEGER columns.
    // These conversions are infallible at this point because validate_capacity_bounds
    // rejected oversized values in the handler.
    let cpu_limit = i32::try_from(ns.resource_quota.cpu_limit)
        .map_err(|e| sqlx::Error::Decode(format!("cpu_limit overflow: {e}").into()))?;
    let cpu_request_ns = i32::try_from(ns.resource_quota.cpu_request)
        .map_err(|e| sqlx::Error::Decode(format!("cpu_request overflow: {e}").into()))?;
    let memory_limit_gb = i32::try_from(ns.resource_quota.memory_limit_gb)
        .map_err(|e| sqlx::Error::Decode(format!("memory_limit_gb overflow: {e}").into()))?;
    let memory_request_gb = i32::try_from(ns.resource_quota.memory_request_gb)
        .map_err(|e| sqlx::Error::Decode(format!("memory_request_gb overflow: {e}").into()))?;
    let storage_gb_ns = i32::try_from(ns.resource_quota.storage_gb)
        .map_err(|e| sqlx::Error::Decode(format!("storage_gb overflow: {e}").into()))?;
    let max_pods = i32::try_from(ns.resource_quota.max_pods)
        .map_err(|e| sqlx::Error::Decode(format!("max_pods overflow: {e}").into()))?;

    let cpu_request_req = i32::try_from(req.cpu_request)
        .map_err(|e| sqlx::Error::Decode(format!("req.cpu_request overflow: {e}").into()))?;
    let memory_gb_req = i32::try_from(req.memory_gb)
        .map_err(|e| sqlx::Error::Decode(format!("req.memory_gb overflow: {e}").into()))?;
    let storage_gb_req = i32::try_from(req.storage_gb)
        .map_err(|e| sqlx::Error::Decode(format!("req.storage_gb overflow: {e}").into()))?;

    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT INTO k8s_namespaces \
         (id, name, cluster, site, \
          cpu_limit, cpu_request, memory_limit_gb, memory_request_gb, storage_gb, max_pods, \
          network_policy, service_accounts, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(&ns.id)
    .bind(&ns.name)
    .bind(&ns.cluster)
    .bind(&ns.site)
    .bind(cpu_limit)
    .bind(cpu_request_ns)
    .bind(memory_limit_gb)
    .bind(memory_request_gb)
    .bind(storage_gb_ns)
    .bind(max_pods)
    .bind(&ns.network_policy)
    .bind(&ns.service_accounts)
    .bind(enum_to_db(&ns.status))
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO container_requests \
         (id, requester, namespace_name, cluster, site, \
          cpu_request, memory_gb, storage_gb, environment, purpose, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(&req.id)
    .bind(&req.requester)
    .bind(&req.namespace_name)
    .bind(&req.cluster)
    .bind(&req.site)
    .bind(cpu_request_req)
    .bind(memory_gb_req)
    .bind(storage_gb_req)
    .bind(enum_to_db(&req.environment))
    .bind(&req.purpose)
    .bind(enum_to_db(&req.status))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Outcome of a guarded namespace mutation (quota update / status change). The
/// guard (`status <> 'Terminating'`) is applied atomically in the UPDATE so a
/// concurrent terminate cannot be clobbered (no read-then-write TOCTOU).
#[derive(Debug)]
pub enum TransitionOutcome {
    /// The row was updated; carries the fresh model.
    Updated(Box<K8sNamespace>),
    /// No row with that id exists (handler -> 404).
    NotFound,
    /// The row exists but is Terminating, so the guard rejected it (handler -> 409).
    Terminating,
}

async fn namespace_exists(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM k8s_namespaces WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
}

/// Update the 6 quota columns for a namespace by id, guarded so a Terminating
/// namespace (or one concurrently terminated) is rejected atomically.
pub async fn update_quota(
    pool: &PgPool,
    id: &str,
    cpu: u32,
    memory: u32,
    storage: u32,
) -> Result<TransitionOutcome, sqlx::Error> {
    use ryuki_engine::container_namespace::build_quota;
    let quota = build_quota(cpu, memory, storage);

    let cpu_limit = i32::try_from(quota.cpu_limit)
        .map_err(|e| sqlx::Error::Decode(format!("cpu_limit overflow: {e}").into()))?;
    let cpu_request = i32::try_from(quota.cpu_request)
        .map_err(|e| sqlx::Error::Decode(format!("cpu_request overflow: {e}").into()))?;
    let memory_limit_gb = i32::try_from(quota.memory_limit_gb)
        .map_err(|e| sqlx::Error::Decode(format!("memory_limit_gb overflow: {e}").into()))?;
    let memory_request_gb = i32::try_from(quota.memory_request_gb)
        .map_err(|e| sqlx::Error::Decode(format!("memory_request_gb overflow: {e}").into()))?;
    let storage_gb = i32::try_from(quota.storage_gb)
        .map_err(|e| sqlx::Error::Decode(format!("storage_gb overflow: {e}").into()))?;
    let max_pods = i32::try_from(quota.max_pods)
        .map_err(|e| sqlx::Error::Decode(format!("max_pods overflow: {e}").into()))?;

    let row: Option<K8sNamespaceRow> = sqlx::query_as(&format!(
        "UPDATE k8s_namespaces \
         SET cpu_limit = $1, cpu_request = $2, memory_limit_gb = $3, memory_request_gb = $4, \
             storage_gb = $5, max_pods = $6, updated_at = NOW() \
         WHERE id = $7 AND status <> 'Terminating' \
         RETURNING {NS_COLUMNS}"
    ))
    .bind(cpu_limit)
    .bind(cpu_request)
    .bind(memory_limit_gb)
    .bind(memory_request_gb)
    .bind(storage_gb)
    .bind(max_pods)
    .bind(id)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) => Ok(TransitionOutcome::Updated(Box::new(r.into_model()?))),
        None if namespace_exists(pool, id).await? => Ok(TransitionOutcome::Terminating),
        None => Ok(TransitionOutcome::NotFound),
    }
}

/// Set namespace status, guarded so a Terminating namespace cannot be mutated
/// (you cannot suspend/resume a terminating namespace, and a second concurrent
/// terminate cannot re-terminate). The guard is atomic with the UPDATE.
pub async fn set_namespace_status(
    pool: &PgPool,
    id: &str,
    status: &NamespaceStatus,
) -> Result<TransitionOutcome, sqlx::Error> {
    let row: Option<K8sNamespaceRow> = sqlx::query_as(&format!(
        "UPDATE k8s_namespaces \
         SET status = $1, updated_at = NOW() \
         WHERE id = $2 AND status <> 'Terminating' \
         RETURNING {NS_COLUMNS}"
    ))
    .bind(enum_to_db(status))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) => Ok(TransitionOutcome::Updated(Box::new(r.into_model()?))),
        None if namespace_exists(pool, id).await? => Ok(TransitionOutcome::Terminating),
        None => Ok(TransitionOutcome::NotFound),
    }
}

// ─── DB integration tests ─────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api --lib -- --test-threads=1 container_namespace_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.
#[cfg(test)]
mod container_namespace_db_tests {
    use super::*;
    use ryuki_engine::container_namespace::{
        build_namespace_and_request, parse_environment, validate_capacity,
        validate_capacity_bounds, Environment, NamespaceStatus,
    };
    use uuid::Uuid;

    async fn test_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("container_namespace_db_tests: RYUKI_DATABASE_URL not set — skipping");
                return None;
            }
        };
        let db = PgPool::connect(&url)
            .await
            .expect("RYUKI_DATABASE_URL is set but connection failed");
        crate::database::run_migrations(&db)
            .await
            .expect("migrations must apply cleanly");
        Some(db)
    }

    fn sfx() -> String {
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("x")
            .to_owned()
    }

    // ─── Seed data reads ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_seeded_namespaces() {
        let Some(db) = test_pool().await else {
            return;
        };
        let all = list_namespaces(&db, "")
            .await
            .expect("list_namespaces all failed");
        assert!(
            all.len() >= 6,
            "migration 081 seeds 6 namespaces, got {}",
            all.len()
        );

        let defra = list_namespaces(&db, "DEFRA")
            .await
            .expect("list_namespaces DEFRA failed");
        assert_eq!(defra.len(), 2, "DEFRA has 2 seeded namespaces");

        let frpar = list_namespaces(&db, "FRPAR")
            .await
            .expect("list_namespaces FRPAR failed");
        assert_eq!(frpar.len(), 2, "FRPAR has 2 seeded namespaces");
    }

    #[tokio::test]
    async fn test_get_namespace_by_id() {
        let Some(db) = test_pool().await else {
            return;
        };
        let ns = get_namespace(&db, "k8s-defra-app-001")
            .await
            .expect("get_namespace failed")
            .expect("k8s-defra-app-001 must be present");

        assert_eq!(ns.site, "DEFRA");
        assert_eq!(ns.name, "defra-apps-dev");
        assert_eq!(ns.cluster, "defra-aks-01");
        assert_eq!(ns.status, NamespaceStatus::Active);
        // service_accounts TEXT[] round-trip
        assert!(ns
            .service_accounts
            .contains(&"defra-app-deployer".to_string()));
        assert!(ns
            .service_accounts
            .contains(&"defra-app-reader".to_string()));
        // Flattened quota decode: quota(8,16,200)
        assert_eq!(ns.resource_quota.cpu_request, 8);
        assert_eq!(ns.resource_quota.cpu_limit, 16);
        assert_eq!(ns.resource_quota.memory_request_gb, 16);
        assert_eq!(ns.resource_quota.memory_limit_gb, 32);
        assert_eq!(ns.resource_quota.storage_gb, 200);
        assert_eq!(ns.resource_quota.max_pods, 64);

        let absent = get_namespace(&db, "k8s-nonexistent")
            .await
            .expect("must not error for absent");
        assert!(absent.is_none());
    }

    #[tokio::test]
    async fn test_enum_roundtrip_all_status_values() {
        let Some(db) = test_pool().await else {
            return;
        };
        // Active
        let active = get_namespace(&db, "k8s-defra-app-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.status, NamespaceStatus::Active);

        // Suspended
        let suspended = get_namespace(&db, "k8s-gblon-build-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(suspended.status, NamespaceStatus::Suspended);

        // Creating
        let creating = get_namespace(&db, "k8s-frpar-api-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(creating.status, NamespaceStatus::Creating);
    }

    #[tokio::test]
    async fn test_list_seeded_requests() {
        let Some(db) = test_pool().await else {
            return;
        };
        let all = list_requests(&db, "")
            .await
            .expect("list_requests all failed");
        assert!(
            all.len() >= 4,
            "migration 081 seeds 4 requests, got {}",
            all.len()
        );

        // Environment enum round-trip
        let req = all
            .iter()
            .find(|r| r.id == "cr-defra-001")
            .expect("cr-defra-001 must be present");
        assert_eq!(req.environment, Environment::Dev);
        assert_eq!(req.cpu_request, 4);
        assert_eq!(req.memory_gb, 12);
        assert_eq!(req.storage_gb, 100);

        let req_prod = all
            .iter()
            .find(|r| r.id == "cr-defra-002")
            .expect("cr-defra-002 must be present");
        assert_eq!(req_prod.environment, Environment::Prod);

        let req_staging = all
            .iter()
            .find(|r| r.id == "cr-frpar-001")
            .expect("cr-frpar-001 must be present");
        assert_eq!(req_staging.environment, Environment::Staging);

        let req_test = all
            .iter()
            .find(|r| r.id == "cr-gblon-001")
            .expect("cr-gblon-001 must be present");
        assert_eq!(req_test.environment, Environment::Test);
    }

    // ─── Provision ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_provision_namespace_success() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let name = format!("defra-test-ns-{sfx}");
        let env = parse_environment("Dev").unwrap();
        validate_capacity(4, 8, 100).unwrap();
        validate_capacity_bounds(4, 8, 100).unwrap();
        let (ns, req) = build_namespace_and_request(&name, "defra-aks-01", "DEFRA", 4, 8, 100, env);
        let ns_id = ns.id.clone();
        let req_id = req.id.clone();

        provision_namespace(&db, &ns, &req)
            .await
            .expect("provision_namespace failed");

        // Namespace must be retrievable with correct quota + status
        let fetched = get_namespace(&db, &ns_id)
            .await
            .expect("get_namespace failed")
            .expect("namespace must exist after provision");
        assert_eq!(fetched.name, name);
        assert_eq!(fetched.status, NamespaceStatus::Creating);
        assert_eq!(fetched.resource_quota.cpu_request, 4);
        assert_eq!(fetched.resource_quota.cpu_limit, 8);
        assert_eq!(fetched.resource_quota.memory_request_gb, 8);
        assert_eq!(fetched.resource_quota.memory_limit_gb, 16);
        assert_eq!(fetched.resource_quota.storage_gb, 100);
        // cpu=4 -> max_pods=max(32,16)=32
        assert_eq!(fetched.resource_quota.max_pods, 32);
        assert_eq!(fetched.service_accounts, vec![format!("{name}-deployer")]);

        // Paired request must also exist
        let req_row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM container_requests WHERE id = $1")
                .bind(&req_id)
                .fetch_optional(&db)
                .await
                .expect("query failed");
        assert!(req_row.is_some(), "paired request must be in DB");

        // Cleanup
        sqlx::query("DELETE FROM container_requests WHERE id = $1")
            .bind(&req_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM k8s_namespaces WHERE id = $1")
            .bind(&ns_id)
            .execute(&db)
            .await
            .ok();
    }

    #[tokio::test]
    async fn test_provision_duplicate_cluster_name_unique_violation() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let name = format!("defra-dup-ns-{sfx}");
        let env1 = parse_environment("Dev").unwrap();
        let env2 = parse_environment("Test").unwrap();
        let (ns1, req1) =
            build_namespace_and_request(&name, "defra-aks-01", "DEFRA", 4, 8, 100, env1);
        let (ns2, req2) =
            build_namespace_and_request(&name, "defra-aks-01", "DEFRA", 4, 8, 100, env2);
        let ns1_id = ns1.id.clone();
        let req1_id = req1.id.clone();

        provision_namespace(&db, &ns1, &req1)
            .await
            .expect("first provision must succeed");

        let err = provision_namespace(&db, &ns2, &req2)
            .await
            .expect_err("duplicate (cluster, name) must error");
        assert!(
            err.as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false),
            "expected unique-violation on (cluster, name), got: {err:?}"
        );

        // Cleanup
        sqlx::query("DELETE FROM container_requests WHERE id = $1")
            .bind(&req1_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM k8s_namespaces WHERE id = $1")
            .bind(&ns1_id)
            .execute(&db)
            .await
            .ok();
    }

    // ─── Update quota ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_update_quota_changes_columns() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let name = format!("gblon-quota-test-{sfx}");
        let env = parse_environment("Test").unwrap();
        let (ns, req) = build_namespace_and_request(&name, "gblon-k8s-01", "GBLON", 4, 8, 100, env);
        let ns_id = ns.id.clone();
        let req_id = req.id.clone();

        provision_namespace(&db, &ns, &req)
            .await
            .expect("provision failed");

        // Update quota: cpu=12, memory=32, storage=300
        let updated = match update_quota(&db, &ns_id, 12, 32, 300)
            .await
            .expect("update_quota failed")
        {
            TransitionOutcome::Updated(ns) => *ns,
            other => panic!("expected Updated, got {other:?}"),
        };
        assert_eq!(updated.resource_quota.cpu_request, 12);
        assert_eq!(updated.resource_quota.cpu_limit, 24);
        assert_eq!(updated.resource_quota.memory_request_gb, 32);
        assert_eq!(updated.resource_quota.memory_limit_gb, 64);
        assert_eq!(updated.resource_quota.storage_gb, 300);
        assert_eq!(updated.resource_quota.max_pods, 96);

        // Not found returns NotFound
        let absent = update_quota(&db, "k8s-nonexistent", 4, 8, 100)
            .await
            .expect("must not error for absent");
        assert!(matches!(absent, TransitionOutcome::NotFound));

        // Cleanup
        sqlx::query("DELETE FROM container_requests WHERE id = $1")
            .bind(&req_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM k8s_namespaces WHERE id = $1")
            .bind(&ns_id)
            .execute(&db)
            .await
            .ok();
    }

    // ─── Status transitions ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_suspend_resume_terminate_transitions() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let name = format!("frpar-transition-test-{sfx}");
        let env = parse_environment("Staging").unwrap();
        let (ns, req) = build_namespace_and_request(&name, "frpar-k8s-01", "FRPAR", 4, 8, 100, env);
        let ns_id = ns.id.clone();
        let req_id = req.id.clone();

        provision_namespace(&db, &ns, &req)
            .await
            .expect("provision failed");

        let updated_ns = |o: TransitionOutcome| match o {
            TransitionOutcome::Updated(ns) => *ns,
            other => panic!("expected Updated, got {other:?}"),
        };

        // Creating -> Suspended
        let suspended = updated_ns(
            set_namespace_status(&db, &ns_id, &NamespaceStatus::Suspended)
                .await
                .expect("suspend failed"),
        );
        assert_eq!(suspended.status, NamespaceStatus::Suspended);

        // Suspended -> Active (resume)
        let resumed = updated_ns(
            set_namespace_status(&db, &ns_id, &NamespaceStatus::Active)
                .await
                .expect("resume failed"),
        );
        assert_eq!(resumed.status, NamespaceStatus::Active);

        // Active -> Terminating
        let terminated = updated_ns(
            set_namespace_status(&db, &ns_id, &NamespaceStatus::Terminating)
                .await
                .expect("terminate failed"),
        );
        assert_eq!(terminated.status, NamespaceStatus::Terminating);

        // Guard: once Terminating, further transitions are rejected (no clobber).
        let blocked = set_namespace_status(&db, &ns_id, &NamespaceStatus::Suspended)
            .await
            .expect("must not error");
        assert!(
            matches!(blocked, TransitionOutcome::Terminating),
            "suspending a Terminating namespace must be rejected"
        );
        let quota_blocked = update_quota(&db, &ns_id, 4, 8, 100)
            .await
            .expect("must not error");
        assert!(
            matches!(quota_blocked, TransitionOutcome::Terminating),
            "updating quota on a Terminating namespace must be rejected"
        );

        // Not found returns NotFound
        let absent = set_namespace_status(&db, "k8s-nonexistent", &NamespaceStatus::Active)
            .await
            .expect("must not error for absent");
        assert!(matches!(absent, TransitionOutcome::NotFound));

        // Cleanup
        sqlx::query("DELETE FROM container_requests WHERE id = $1")
            .bind(&req_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM k8s_namespaces WHERE id = $1")
            .bind(&ns_id)
            .execute(&db)
            .await
            .ok();
    }

    #[tokio::test]
    async fn test_find_active_namespace_by_name_ignores_terminating() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let name = format!("defra-active-check-{sfx}");
        let env = parse_environment("Dev").unwrap();
        let (ns, req) = build_namespace_and_request(&name, "defra-aks-01", "DEFRA", 4, 8, 100, env);
        let ns_id = ns.id.clone();
        let req_id = req.id.clone();

        provision_namespace(&db, &ns, &req)
            .await
            .expect("provision failed");

        // Should be found (Creating status, not Terminating)
        let found = find_active_namespace_by_name(&db, &name, "defra-aks-01")
            .await
            .expect("find failed");
        assert!(found.is_some());

        // Set to Terminating — should now return None
        set_namespace_status(&db, &ns_id, &NamespaceStatus::Terminating)
            .await
            .expect("terminate failed");
        let not_found = find_active_namespace_by_name(&db, &name, "defra-aks-01")
            .await
            .expect("find failed");
        assert!(
            not_found.is_none(),
            "Terminating namespace must not appear as active"
        );

        // Cleanup
        sqlx::query("DELETE FROM container_requests WHERE id = $1")
            .bind(&req_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM k8s_namespaces WHERE id = $1")
            .bind(&ns_id)
            .execute(&db)
            .await
            .ok();
    }
}
