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
//! # Authoritative scope provenance
//! Every application-visible namespace is bound to an active row in
//! `k8s_cluster_environment_scopes`, whose cluster identity is in
//! `k8s_cluster_registry` and whose site is the current active canonical row in
//! `site_registry`. The handler locks that authority before constructing and
//! inserting the paired namespace/request rows. Legacy rows without an explicit
//! binding remain quarantined and are excluded from reads/mutations.
//!
//! # Status transitions
//! suspend / resume / terminate lock the active cluster authority, repeat the
//! immutable scope tuple in the UPDATE compare-and-swap, and reject a
//! Terminating namespace atomically.

use ryuki_engine::container_namespace::{
    ContainerRequest, Environment, K8sNamespace, NamespaceStatus, RequestStatus, ResourceQuota,
};
use serde_json::Value;
use sqlx::{PgConnection, PgPool};

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

const NS_COLUMNS: &str = "n.id, n.name, n.cluster_scope_id, n.cluster, n.site, n.environment, \
     n.cpu_limit, n.cpu_request, n.memory_limit_gb, n.memory_request_gb, n.storage_gb, n.max_pods, \
     n.network_policy, n.service_accounts, n.status";

const AUTHORIZED_NAMESPACE_PREDICATE: &str = "n.scope_state = 'Verified' \
     AND EXISTS ( \
         SELECT 1 \
         FROM k8s_cluster_environment_scopes AS cluster_scope \
         JOIN k8s_cluster_registry AS cluster_registry \
           ON cluster_registry.id = cluster_scope.cluster_id \
          AND cluster_registry.cluster_name = cluster_scope.cluster_name \
          AND cluster_registry.site = cluster_scope.site \
         JOIN site_registry AS current_site \
           ON current_site.unlocode = cluster_registry.site \
          AND current_site.active = TRUE \
         WHERE cluster_scope.id = n.cluster_scope_id \
           AND cluster_scope.cluster_name = n.cluster \
           AND cluster_scope.site = n.site \
           AND cluster_scope.environment = n.environment \
           AND cluster_scope.lifecycle_state = 'Active' \
           AND cluster_registry.lifecycle_state = 'Active' \
     )";

#[allow(dead_code)]
const REQ_COLUMNS: &str = "request.id, request.requester, request.namespace_name, \
     request.cluster_scope_id, request.cluster, request.site, request.cpu_request, \
     request.memory_gb, request.storage_gb, request.environment, request.purpose, request.status";

const AUTHORIZED_REQUEST_PREDICATE: &str = "request.scope_state = 'Verified' \
     AND EXISTS ( \
         SELECT 1 \
         FROM k8s_cluster_environment_scopes AS cluster_scope \
         JOIN k8s_cluster_registry AS cluster_registry \
           ON cluster_registry.id = cluster_scope.cluster_id \
          AND cluster_registry.cluster_name = cluster_scope.cluster_name \
          AND cluster_registry.site = cluster_scope.site \
         JOIN site_registry AS current_site \
           ON current_site.unlocode = cluster_registry.site \
          AND current_site.active = TRUE \
         WHERE cluster_scope.id = request.cluster_scope_id \
           AND cluster_scope.cluster_name = request.cluster \
           AND cluster_scope.site = request.site \
           AND cluster_scope.environment = request.environment \
           AND cluster_scope.lifecycle_state = 'Active' \
           AND cluster_registry.lifecycle_state = 'Active' \
     )";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterScopeAuthority {
    pub scope_id: String,
    pub cluster_id: String,
    pub cluster: String,
    pub site: String,
    pub environment: Environment,
    pub cluster_authority_version: i64,
    pub scope_authority_version: i64,
    pub inventory_source: String,
}

impl ClusterScopeAuthority {
    pub fn matches_declared_scope(&self, site: &str, environment: Environment) -> bool {
        self.site == site && self.environment == environment
    }
}

#[derive(sqlx::FromRow)]
struct ClusterScopeAuthorityRow {
    scope_id: String,
    cluster_id: String,
    cluster: String,
    site: String,
    environment: String,
    cluster_authority_version: i64,
    scope_authority_version: i64,
    inventory_source: String,
}

impl ClusterScopeAuthorityRow {
    fn into_authority(self) -> Result<ClusterScopeAuthority, sqlx::Error> {
        Ok(ClusterScopeAuthority {
            scope_id: self.scope_id,
            cluster_id: self.cluster_id,
            cluster: self.cluster,
            site: self.site,
            environment: enum_from_db(
                &self.environment,
                "k8s_cluster_environment_scopes.environment",
            )?,
            cluster_authority_version: self.cluster_authority_version,
            scope_authority_version: self.scope_authority_version,
            inventory_source: self.inventory_source,
        })
    }
}

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct K8sNamespaceRow {
    id: String,
    name: String,
    cluster_scope_id: String,
    cluster: String,
    site: String,
    environment: String,
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
        let environment: Environment =
            enum_from_db(&self.environment, "k8s_namespaces.environment")?;

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
            cluster_scope_id: self.cluster_scope_id,
            cluster: self.cluster,
            site: self.site,
            environment,
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
    cluster_scope_id: String,
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
            cluster_scope_id: self.cluster_scope_id,
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

/// List all application-visible namespaces within both principal scope axes.
/// Empty arrays mean unrestricted on that axis; non-empty arrays are pushed
/// into SQL before rows are decoded. Quarantined/inactive authority is excluded.
pub async fn list_namespaces(
    pool: &PgPool,
    sites: &[String],
    environments: &[String],
) -> Result<Vec<K8sNamespace>, sqlx::Error> {
    let rows: Vec<K8sNamespaceRow> = sqlx::query_as(&format!(
        "SELECT {NS_COLUMNS} FROM k8s_namespaces AS n \
         WHERE {AUTHORIZED_NAMESPACE_PREDICATE} \
           AND (cardinality($1::text[]) = 0 OR n.site = ANY($1)) \
           AND (cardinality($2::text[]) = 0 OR n.environment = ANY($2)) \
         ORDER BY n.id"
    ))
    .bind(sites)
    .bind(environments)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// List namespaces (optionally site-filtered) bounded to one `LIMIT`/`OFFSET`
/// page (#14). `ORDER BY id` is a unique key, so the page is a stable cut. A
/// SEPARATE fn from [`list_namespaces`] because the aggregate callers need the
/// full set — only the list endpoint pages.
pub async fn list_namespaces_page(
    pool: &PgPool,
    sites: &[String],
    environments: &[String],
    limit: i64,
    offset: i64,
) -> Result<Vec<K8sNamespace>, sqlx::Error> {
    let rows: Vec<K8sNamespaceRow> = sqlx::query_as(&format!(
        "SELECT {NS_COLUMNS} FROM k8s_namespaces AS n \
         WHERE {AUTHORIZED_NAMESPACE_PREDICATE} \
           AND (cardinality($1::text[]) = 0 OR n.site = ANY($1)) \
           AND (cardinality($2::text[]) = 0 OR n.environment = ANY($2)) \
         ORDER BY n.id LIMIT $3 OFFSET $4"
    ))
    .bind(sites)
    .bind(environments)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count namespaces (optionally site-filtered) — the pagination total for
/// [`list_namespaces_page`], using the SAME `WHERE` so the count matches the page.
pub async fn count_namespaces(
    pool: &PgPool,
    sites: &[String],
    environments: &[String],
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM k8s_namespaces AS n \
         WHERE {AUTHORIZED_NAMESPACE_PREDICATE} \
           AND (cardinality($1::text[]) = 0 OR n.site = ANY($1)) \
           AND (cardinality($2::text[]) = 0 OR n.environment = ANY($2))"
    ))
    .bind(sites)
    .bind(environments)
    .fetch_one(pool)
    .await
}

pub async fn get_namespace(pool: &PgPool, id: &str) -> Result<Option<K8sNamespace>, sqlx::Error> {
    let row: Option<K8sNamespaceRow> = sqlx::query_as(&format!(
        "SELECT {NS_COLUMNS} FROM k8s_namespaces AS n \
         WHERE n.id = $1 AND {AUTHORIZED_NAMESPACE_PREDICATE}"
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
    sites: &[String],
    environments: &[String],
) -> Result<Option<K8sNamespace>, sqlx::Error> {
    let row: Option<K8sNamespaceRow> = sqlx::query_as(&format!(
        "SELECT {NS_COLUMNS} FROM k8s_namespaces AS n \
         WHERE n.name = $1 AND n.cluster = $2 AND n.status <> 'Terminating' \
           AND {AUTHORIZED_NAMESPACE_PREDICATE} \
           AND (cardinality($3::text[]) = 0 OR n.site = ANY($3)) \
           AND (cardinality($4::text[]) = 0 OR n.environment = ANY($4))"
    ))
    .bind(name)
    .bind(cluster)
    .bind(sites)
    .bind(environments)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

#[allow(dead_code)]
pub async fn list_requests(
    pool: &PgPool,
    sites: &[String],
    environments: &[String],
) -> Result<Vec<ContainerRequest>, sqlx::Error> {
    let rows: Vec<ContainerRequestRow> = sqlx::query_as(&format!(
        "SELECT {REQ_COLUMNS} FROM container_requests AS request \
         WHERE {AUTHORIZED_REQUEST_PREDICATE} \
           AND (cardinality($1::text[]) = 0 OR request.site = ANY($1)) \
           AND (cardinality($2::text[]) = 0 OR request.environment = ANY($2)) \
         ORDER BY request.id"
    ))
    .bind(sites)
    .bind(environments)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── Write functions ──────────────────────────────────────────────────────────

/// Resolve and lock the active authority for a concrete cluster/environment.
/// The row locks are held by the caller's transaction through both inserts, so
/// trusted inventory cannot deactivate/rebind the authority between validation
/// and persistence.
pub async fn lock_cluster_scope(
    conn: &mut PgConnection,
    cluster: &str,
    environment: Environment,
) -> Result<Option<ClusterScopeAuthority>, sqlx::Error> {
    let row: Option<ClusterScopeAuthorityRow> = sqlx::query_as(
        "SELECT cluster_scope.id AS scope_id, registry.id AS cluster_id, \
                registry.cluster_name AS cluster, registry.site, cluster_scope.environment, \
                registry.authority_version AS cluster_authority_version, \
                cluster_scope.authority_version AS scope_authority_version, \
                cluster_scope.inventory_source \
         FROM k8s_cluster_registry AS registry \
         JOIN k8s_cluster_environment_scopes AS cluster_scope \
           ON cluster_scope.cluster_id = registry.id \
          AND cluster_scope.cluster_name = registry.cluster_name \
          AND cluster_scope.site = registry.site \
         JOIN site_registry AS current_site \
           ON current_site.unlocode = registry.site \
          AND current_site.active = TRUE \
         WHERE registry.cluster_name = $1 \
           AND cluster_scope.environment = $2 \
           AND registry.lifecycle_state = 'Active' \
           AND cluster_scope.lifecycle_state = 'Active' \
         FOR UPDATE OF registry, cluster_scope \
         FOR SHARE OF current_site",
    )
    .bind(cluster)
    .bind(enum_to_db(&environment))
    .fetch_optional(&mut *conn)
    .await?;
    row.map(ClusterScopeAuthorityRow::into_authority)
        .transpose()
}

/// Insert a namespace and its paired request through the caller-owned
/// transaction after [`lock_cluster_scope`] and authorization. Unique violation
/// on (cluster, name) propagates for the handler to map to 409.
pub async fn provision_namespace(
    conn: &mut PgConnection,
    ns: &K8sNamespace,
    req: &ContainerRequest,
) -> Result<(), sqlx::Error> {
    if ns.cluster_scope_id.is_empty()
        || ns.cluster_scope_id != req.cluster_scope_id
        || ns.cluster != req.cluster
        || ns.site != req.site
        || ns.environment != req.environment
    {
        return Err(sqlx::Error::Protocol(
            "namespace/request cluster authority provenance mismatch".into(),
        ));
    }
    let authority = lock_cluster_scope(conn, &ns.cluster, ns.environment)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
    if authority.scope_id != ns.cluster_scope_id
        || authority.cluster != ns.cluster
        || authority.site != ns.site
        || authority.environment != ns.environment
    {
        return Err(sqlx::Error::Protocol(
            "namespace coordinates do not match locked cluster authority".into(),
        ));
    }
    let scope_provenance = format!(
        "cluster={}:v{};scope={}:v{};source={}",
        authority.cluster_id,
        authority.cluster_authority_version,
        authority.scope_id,
        authority.scope_authority_version,
        authority.inventory_source
    );

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

    sqlx::query(
        "INSERT INTO k8s_namespaces \
         (id, name, cluster_scope_id, cluster, site, environment, \
          cpu_limit, cpu_request, memory_limit_gb, memory_request_gb, storage_gb, max_pods, \
          network_policy, service_accounts, status, scope_state, scope_provenance) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'Verified', $16)",
    )
    .bind(&ns.id)
    .bind(&ns.name)
    .bind(&ns.cluster_scope_id)
    .bind(&ns.cluster)
    .bind(&ns.site)
    .bind(enum_to_db(&ns.environment))
    .bind(cpu_limit)
    .bind(cpu_request_ns)
    .bind(memory_limit_gb)
    .bind(memory_request_gb)
    .bind(storage_gb_ns)
    .bind(max_pods)
    .bind(&ns.network_policy)
    .bind(&ns.service_accounts)
    .bind(enum_to_db(&ns.status))
    .bind(&scope_provenance)
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO container_requests \
         (id, requester, namespace_name, cluster_scope_id, cluster, site, \
          cpu_request, memory_gb, storage_gb, environment, purpose, status, scope_state, scope_provenance) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'Verified', $13)",
    )
    .bind(&req.id)
    .bind(&req.requester)
    .bind(&req.namespace_name)
    .bind(&req.cluster_scope_id)
    .bind(&req.cluster)
    .bind(&req.site)
    .bind(cpu_request_req)
    .bind(memory_gb_req)
    .bind(storage_gb_req)
    .bind(enum_to_db(&req.environment))
    .bind(&req.purpose)
    .bind(enum_to_db(&req.status))
    .bind(&scope_provenance)
    .execute(&mut *conn)
    .await?;

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

async fn namespace_exists_in_authority(
    conn: &mut PgConnection,
    expected: &K8sNamespace,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS( \
             SELECT 1 FROM k8s_namespaces AS n \
             WHERE n.id = $1 \
               AND n.cluster_scope_id = $2 \
               AND n.cluster = $3 \
               AND n.site = $4 \
               AND n.environment = $5 \
               AND {AUTHORIZED_NAMESPACE_PREDICATE} \
         )"
    ))
    .bind(&expected.id)
    .bind(&expected.cluster_scope_id)
    .bind(&expected.cluster)
    .bind(&expected.site)
    .bind(enum_to_db(&expected.environment))
    .fetch_one(&mut *conn)
    .await
}

async fn lock_expected_namespace_authority(
    conn: &mut PgConnection,
    expected: &K8sNamespace,
) -> Result<bool, sqlx::Error> {
    let locked: Option<i32> = sqlx::query_scalar(
        "SELECT 1 \
         FROM k8s_cluster_environment_scopes AS cluster_scope \
         JOIN k8s_cluster_registry AS cluster_registry \
           ON cluster_registry.id = cluster_scope.cluster_id \
          AND cluster_registry.cluster_name = cluster_scope.cluster_name \
          AND cluster_registry.site = cluster_scope.site \
         JOIN site_registry AS current_site \
           ON current_site.unlocode = cluster_registry.site \
          AND current_site.active = TRUE \
         WHERE cluster_scope.id = $1 \
           AND cluster_scope.cluster_name = $2 \
           AND cluster_scope.site = $3 \
           AND cluster_scope.environment = $4 \
           AND cluster_scope.lifecycle_state = 'Active' \
           AND cluster_registry.lifecycle_state = 'Active' \
         FOR UPDATE OF cluster_scope, cluster_registry \
         FOR SHARE OF current_site",
    )
    .bind(&expected.cluster_scope_id)
    .bind(&expected.cluster)
    .bind(&expected.site)
    .bind(enum_to_db(&expected.environment))
    .fetch_optional(&mut *conn)
    .await?;
    Ok(locked.is_some())
}

/// Update the 6 quota columns for a namespace by id, guarded so a Terminating
/// namespace (or one concurrently terminated) is rejected atomically.
pub async fn update_quota(
    conn: &mut PgConnection,
    expected: &K8sNamespace,
    cpu: u32,
    memory: u32,
    storage: u32,
) -> Result<TransitionOutcome, sqlx::Error> {
    if !lock_expected_namespace_authority(conn, expected).await? {
        return Ok(TransitionOutcome::NotFound);
    }
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
        "UPDATE k8s_namespaces AS n \
         SET cpu_limit = $1, cpu_request = $2, memory_limit_gb = $3, memory_request_gb = $4, \
             storage_gb = $5, max_pods = $6, updated_at = NOW() \
         WHERE n.id = $7 \
           AND n.cluster_scope_id = $8 \
           AND n.cluster = $9 \
           AND n.site = $10 \
           AND n.environment = $11 \
           AND n.status <> 'Terminating' \
           AND {AUTHORIZED_NAMESPACE_PREDICATE} \
         RETURNING {NS_COLUMNS}"
    ))
    .bind(cpu_limit)
    .bind(cpu_request)
    .bind(memory_limit_gb)
    .bind(memory_request_gb)
    .bind(storage_gb)
    .bind(max_pods)
    .bind(&expected.id)
    .bind(&expected.cluster_scope_id)
    .bind(&expected.cluster)
    .bind(&expected.site)
    .bind(enum_to_db(&expected.environment))
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some(r) => Ok(TransitionOutcome::Updated(Box::new(r.into_model()?))),
        None if namespace_exists_in_authority(conn, expected).await? => {
            Ok(TransitionOutcome::Terminating)
        }
        None => Ok(TransitionOutcome::NotFound),
    }
}

/// Set namespace status, guarded so a Terminating namespace cannot be mutated
/// (you cannot suspend/resume a terminating namespace, and a second concurrent
/// terminate cannot re-terminate). The guard is atomic with the UPDATE.
pub async fn set_namespace_status(
    conn: &mut PgConnection,
    expected: &K8sNamespace,
    status: &NamespaceStatus,
) -> Result<TransitionOutcome, sqlx::Error> {
    if !lock_expected_namespace_authority(conn, expected).await? {
        return Ok(TransitionOutcome::NotFound);
    }
    let row: Option<K8sNamespaceRow> = sqlx::query_as(&format!(
        "UPDATE k8s_namespaces AS n \
         SET status = $1, updated_at = NOW() \
         WHERE n.id = $2 \
           AND n.cluster_scope_id = $3 \
           AND n.cluster = $4 \
           AND n.site = $5 \
           AND n.environment = $6 \
           AND n.status <> 'Terminating' \
           AND {AUTHORIZED_NAMESPACE_PREDICATE} \
         RETURNING {NS_COLUMNS}"
    ))
    .bind(enum_to_db(status))
    .bind(&expected.id)
    .bind(&expected.cluster_scope_id)
    .bind(&expected.cluster)
    .bind(&expected.site)
    .bind(enum_to_db(&expected.environment))
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some(r) => Ok(TransitionOutcome::Updated(Box::new(r.into_model()?))),
        None if namespace_exists_in_authority(conn, expected).await? => {
            Ok(TransitionOutcome::Terminating)
        }
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

    async fn build_and_provision(
        db: &PgPool,
        name: &str,
        cluster: &str,
        declared_site: &str,
        environment: Environment,
    ) -> Result<(K8sNamespace, ContainerRequest), sqlx::Error> {
        let mut tx = db.begin().await?;
        let authority = lock_cluster_scope(&mut tx, cluster, environment)
            .await?
            .ok_or(sqlx::Error::RowNotFound)?;
        if !authority.matches_declared_scope(declared_site, environment) {
            return Err(sqlx::Error::Protocol(
                "declared namespace scope does not match cluster authority".into(),
            ));
        }
        let (ns, req) = build_namespace_and_request(
            name,
            "container-repository-test",
            &authority.scope_id,
            &authority.cluster,
            &authority.site,
            4,
            8,
            100,
            authority.environment,
        );
        provision_namespace(&mut tx, &ns, &req).await?;
        tx.commit().await?;
        Ok((ns, req))
    }

    // ─── Seed data reads ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_seeded_namespaces() {
        let Some(db) = test_pool().await else {
            return;
        };
        let all = list_namespaces(&db, &[], &[])
            .await
            .expect("list_namespaces all failed");
        assert!(
            all.len() >= 6,
            "migration 081 seeds 6 namespaces, got {}",
            all.len()
        );
        assert_eq!(
            count_namespaces(&db, &[], &[])
                .await
                .expect("count_namespaces all"),
            all.len() as i64,
            "#14: count_namespaces matches the full unpaged set"
        );

        let defra = list_namespaces(&db, &["DEFRA".to_string()], &[])
            .await
            .expect("list_namespaces DEFRA failed");
        assert_eq!(defra.len(), 2, "DEFRA has 2 seeded namespaces");

        let frpar = list_namespaces(&db, &["FRPAR".to_string()], &[])
            .await
            .expect("list_namespaces FRPAR failed");
        assert_eq!(frpar.len(), 2, "FRPAR has 2 seeded namespaces");

        let frpar_staging = list_namespaces(&db, &["FRPAR".to_string()], &["Staging".to_string()])
            .await
            .expect("list_namespaces FRPAR/Staging failed");
        assert_eq!(frpar_staging.len(), 1, "environment is a SQL scope axis");
        assert_eq!(frpar_staging[0].environment, Environment::Staging);

        let foreign_environment =
            list_namespaces(&db, &["DEFRA".to_string()], &["Test".to_string()])
                .await
                .expect("list_namespaces DEFRA/Test failed");
        assert!(
            foreign_environment.is_empty(),
            "a foreign environment must not leak same-site namespaces"
        );

        // #14 pagination: LIMIT bounds the page; OFFSET advances it disjointly
        // under the unique `ORDER BY id`.
        let page1 = list_namespaces_page(&db, &[], &[], 3, 0)
            .await
            .expect("page1");
        let page2 = list_namespaces_page(&db, &[], &[], 3, 3)
            .await
            .expect("page2");
        assert_eq!(page1.len(), 3, "LIMIT 3 bounds the first page");
        assert!(!page2.is_empty(), "second page continues (>=6 seeded)");
        assert!(
            page1.iter().all(|n| page2.iter().all(|m| m.id != n.id)),
            "offset page is disjoint from the first (stable id order)"
        );
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
        assert_eq!(ns.environment, Environment::Dev);
        assert_eq!(ns.cluster_scope_id, "cluster-scope-defra-aks-01-dev");
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
        let all = list_requests(&db, &[], &[])
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

    #[test]
    fn test_cluster_authority_matching_is_exact_on_both_axes() {
        let authority = ClusterScopeAuthority {
            scope_id: "scope-1".into(),
            cluster_id: "cluster-1".into(),
            cluster: "cluster-a".into(),
            site: "DEFRA".into(),
            environment: Environment::Prod,
            cluster_authority_version: 1,
            scope_authority_version: 1,
            inventory_source: "test".into(),
        };
        assert!(authority.matches_declared_scope("DEFRA", Environment::Prod));
        assert!(!authority.matches_declared_scope("GBLON", Environment::Prod));
        assert!(!authority.matches_declared_scope("DEFRA", Environment::Dev));
    }

    #[test]
    fn test_migration_and_repository_require_current_canonical_site_authority() {
        let migration = include_str!("../../../../migrations/178_k8s_cluster_authority.sql");
        assert!(migration.contains("k8s_cluster_registry_site_canonical"));
        assert!(migration.contains("CHECK (site = upper(btrim(site)) AND site <> '')"));
        assert!(migration.contains("k8s_cluster_registry_site_fk"));
        assert!(migration.contains("REFERENCES site_registry (unlocode)"));
        assert!(migration.contains("non-overlapping cutover"));
        assert!(migration.contains("WITH reviewed_request_scope"));
        assert!(migration.contains("WHERE request.id = reviewed.request_id"));
        assert!(migration.contains("request.requester = reviewed.expected_requester"));
        assert!(migration.contains("request.purpose = reviewed.expected_purpose"));
        assert!(migration.contains("ROW(NEW.scope_state, NEW.cluster_scope_id"));
        assert!(migration.contains("IF TG_OP = 'INSERT'"));
        assert!(migration.contains("FOR SHARE OF registry, cluster_scope, current_site"));
        assert!(migration.contains("NEW.scope_provenance := derived_provenance"));
        assert!(migration.contains("BEFORE INSERT OR UPDATE ON k8s_namespaces"));
        assert!(migration.contains("BEFORE INSERT OR UPDATE ON container_requests"));
        assert!(!migration.contains(
            "WHERE request.cluster = scope.cluster_name\n  AND request.site = scope.site"
        ));

        for predicate in [AUTHORIZED_NAMESPACE_PREDICATE, AUTHORIZED_REQUEST_PREDICATE] {
            assert!(predicate.contains("JOIN site_registry AS current_site"));
            assert!(predicate.contains("current_site.unlocode = cluster_registry.site"));
            assert!(predicate.contains("current_site.active = TRUE"));
        }
    }

    #[tokio::test]
    async fn test_verified_request_scope_cannot_downgrade_then_rebind() {
        let Some(db) = test_pool().await else {
            return;
        };

        let downgrade = sqlx::query(
            "UPDATE container_requests \
             SET scope_state = 'Quarantined' \
             WHERE id = 'cr-defra-001'",
        )
        .execute(&db)
        .await
        .expect_err("a verified request cannot be downgraded to open a rebind window");
        assert!(
            downgrade
                .to_string()
                .contains("verified Kubernetes scope provenance is immutable"),
            "immutability trigger must reject the first bypass statement: {downgrade}"
        );

        let rebind = sqlx::query(
            "UPDATE container_requests \
             SET scope_state = 'Verified', \
                 cluster_scope_id = 'cluster-scope-gblon-k8s-02-test', \
                 cluster = 'gblon-k8s-02', \
                 site = 'GBLON', \
                 environment = 'Test', \
                 scope_provenance = 'forged-two-statement-rebind' \
             WHERE id = 'cr-defra-001'",
        )
        .execute(&db)
        .await
        .expect_err("the second rebind statement must also fail while the row stays verified");
        assert!(
            rebind
                .to_string()
                .contains("verified Kubernetes scope provenance is immutable"),
            "immutability trigger must reject the rebind statement: {rebind}"
        );

        let state: (String, String, String, String, String) = sqlx::query_as(
            "SELECT scope_state, cluster_scope_id, cluster, site, environment \
             FROM container_requests WHERE id = 'cr-defra-001'",
        )
        .fetch_one(&db)
        .await
        .expect("read unchanged curated request");
        assert_eq!(
            state,
            (
                "Verified".to_string(),
                "cluster-scope-defra-aks-01-dev".to_string(),
                "defra-aks-01".to_string(),
                "DEFRA".to_string(),
                "Dev".to_string(),
            )
        );
    }

    #[tokio::test]
    async fn test_direct_request_insert_cannot_forge_scope_provenance() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(db) = test_pool().await else {
            return;
        };
        let request_id = format!("cr-derived-scope-{}", sfx());
        sqlx::query(
            "INSERT INTO container_requests \
                 (id, requester, namespace_name, cluster_scope_id, cluster, site, \
                  cpu_request, memory_gb, storage_gb, environment, purpose, status, \
                  scope_state, scope_provenance) \
             VALUES ($1, 'direct-sql', 'derived-authority', \
                     'cluster-scope-gblon-k8s-02-test', 'defra-aks-01', 'GBLON', \
                     1, 1, 1, 'Dev', 'direct insert regression', 'Draft', \
                     'Verified', 'caller-forged-provenance')",
        )
        .bind(&request_id)
        .execute(&db)
        .await
        .expect("active hierarchy should derive insert provenance");

        let state: (String, String, String, String) = sqlx::query_as(
            "SELECT scope_state, cluster_scope_id, site, scope_provenance \
             FROM container_requests WHERE id = $1",
        )
        .bind(&request_id)
        .fetch_one(&db)
        .await
        .expect("read database-derived request authority");
        assert_eq!(state.0, "Verified");
        assert_eq!(state.1, "cluster-scope-defra-aks-01-dev");
        assert_eq!(state.2, "DEFRA");
        assert_ne!(state.3, "caller-forged-provenance");
        assert!(state.3.contains("cluster=cluster-defra-aks-01:v"));
        assert!(state.3.contains("scope=cluster-scope-defra-aks-01-dev:v"));

        let invalid_id = format!("cr-no-authority-{}", sfx());
        let rejected = sqlx::query(
            "INSERT INTO container_requests \
                 (id, requester, namespace_name, cluster, site, cpu_request, memory_gb, \
                  storage_gb, environment, purpose, status, scope_state, scope_provenance) \
             VALUES ($1, 'direct-sql', 'no-authority', 'unknown-cluster', 'DEFRA', \
                     1, 1, 1, 'Dev', 'negative direct insert', 'Draft', \
                     'Verified', 'caller-forged-provenance')",
        )
        .bind(&invalid_id)
        .execute(&db)
        .await
        .expect_err("an insert without active inventory authority must fail closed");
        assert!(
            rejected
                .to_string()
                .contains("active Kubernetes cluster scope authority is required for insert"),
            "unexpected direct-insert rejection: {rejected}"
        );

        sqlx::query("DELETE FROM container_requests WHERE id = $1")
            .bind(&request_id)
            .execute(&db)
            .await
            .expect("clean derived-provenance fixture as migration owner");
    }

    #[tokio::test]
    async fn test_cluster_registry_rejects_padded_unknown_and_inactive_site_authority() {
        let Some(db) = test_pool().await else {
            return;
        };
        let token = sfx();

        let padded = sqlx::query(
            "INSERT INTO k8s_cluster_registry \
             (id, cluster_name, site, lifecycle_state, inventory_source) \
             VALUES ($1, $2, ' DEFRA ', 'Active', 'test-padded-site')",
        )
        .bind(format!("cluster-padded-{token}"))
        .bind(format!("padded-cluster-{token}"))
        .execute(&db)
        .await
        .expect_err("padded site key must violate the canonical-site check");
        assert_eq!(
            padded.as_database_error().and_then(|error| error.code()),
            Some(std::borrow::Cow::Borrowed("23514")),
            "expected PostgreSQL check_violation"
        );

        let unknown_site = format!("UNKNOWN{}", token.to_ascii_uppercase());
        let unknown = sqlx::query(
            "INSERT INTO k8s_cluster_registry \
             (id, cluster_name, site, lifecycle_state, inventory_source) \
             VALUES ($1, $2, $3, 'Active', 'test-unknown-site')",
        )
        .bind(format!("cluster-unknown-{token}"))
        .bind(format!("unknown-cluster-{token}"))
        .bind(&unknown_site)
        .execute(&db)
        .await
        .expect_err("unknown site key must violate the site_registry foreign key");
        assert_eq!(
            unknown.as_database_error().and_then(|error| error.code()),
            Some(std::borrow::Cow::Borrowed("23503")),
            "expected PostgreSQL foreign_key_violation"
        );

        let inactive_site = format!("TEST{}", token.to_ascii_uppercase());
        let cluster_id = format!("cluster-inactive-site-{token}");
        let cluster_name = format!("inactive-site-cluster-{token}");
        let scope_id = format!("scope-inactive-site-{token}");
        let mut tx = db.begin().await.expect("begin inactive-site fixture");
        sqlx::query(
            "INSERT INTO site_registry \
             (unlocode, name, country, country_code, timezone, active, code_system) \
             VALUES ($1, 'Inactive test site', 'Test', 'ZZ', 'Etc/UTC', FALSE, 'custom')",
        )
        .bind(&inactive_site)
        .execute(&mut *tx)
        .await
        .expect("insert inactive canonical site");
        sqlx::query(
            "INSERT INTO k8s_cluster_registry \
             (id, cluster_name, site, lifecycle_state, inventory_source) \
             VALUES ($1, $2, $3, 'Active', 'test-inactive-site')",
        )
        .bind(&cluster_id)
        .bind(&cluster_name)
        .bind(&inactive_site)
        .execute(&mut *tx)
        .await
        .expect("inactive site may remain referenced as inventory history");
        sqlx::query(
            "INSERT INTO k8s_cluster_environment_scopes \
             (id, cluster_id, cluster_name, site, environment, lifecycle_state, inventory_source) \
             VALUES ($1, $2, $3, $4, 'Dev', 'Active', 'test-inactive-site')",
        )
        .bind(&scope_id)
        .bind(&cluster_id)
        .bind(&cluster_name)
        .bind(&inactive_site)
        .execute(&mut *tx)
        .await
        .expect("insert scope under inactive site");
        assert!(
            lock_cluster_scope(&mut tx, &cluster_name, Environment::Dev)
                .await
                .expect("inactive-site authority lookup")
                .is_none(),
            "an active cluster/scope cannot confer authority through an inactive site"
        );
        tx.rollback().await.expect("rollback inactive-site fixture");
    }

    #[tokio::test]
    async fn test_cluster_authority_unknown_inactive_and_locking() {
        let _serial = crate::database::DB_TEST_SERIAL.lock().await;
        let Some(db) = test_pool().await else {
            return;
        };

        let mut tx = db.begin().await.expect("begin authority lookup");
        assert!(
            lock_cluster_scope(&mut tx, "unknown-cluster", Environment::Dev)
                .await
                .expect("unknown lookup")
                .is_none()
        );
        assert!(
            lock_cluster_scope(&mut tx, "defra-aks-01", Environment::Test)
                .await
                .expect("unsupported environment lookup")
                .is_none(),
            "an environment not in the authority relation must fail closed"
        );
        let authority = lock_cluster_scope(&mut tx, "defra-aks-01", Environment::Dev)
            .await
            .expect("authority lookup")
            .expect("active authority");
        assert!(authority.matches_declared_scope("DEFRA", Environment::Dev));
        assert!(!authority.matches_declared_scope("GBLON", Environment::Dev));

        // The authority row is locked until the provisioning transaction ends.
        let mut competing = db.begin().await.expect("begin competing inventory tx");
        sqlx::query("SET LOCAL lock_timeout = '100ms'")
            .execute(&mut *competing)
            .await
            .expect("set lock timeout");
        let blocked = sqlx::query(
            "UPDATE k8s_cluster_environment_scopes \
             SET lifecycle_state = 'Inactive', authority_version = authority_version + 1 \
             WHERE id = $1",
        )
        .bind(&authority.scope_id)
        .execute(&mut *competing)
        .await
        .expect_err("authority mutation must wait behind the provisioning lock");
        assert_eq!(
            blocked.as_database_error().and_then(|error| error.code()),
            Some(std::borrow::Cow::Borrowed("55P03")),
            "expected PostgreSQL lock_not_available"
        );
        competing.rollback().await.ok();

        let mut competing_site = db.begin().await.expect("begin competing site tx");
        sqlx::query("SET LOCAL lock_timeout = '100ms'")
            .execute(&mut *competing_site)
            .await
            .expect("set site lock timeout");
        let blocked_site =
            sqlx::query("UPDATE site_registry SET active = FALSE WHERE unlocode = $1")
                .bind(&authority.site)
                .execute(&mut *competing_site)
                .await
                .expect_err("site deactivation must wait behind the provisioning authority lock");
        assert_eq!(
            blocked_site
                .as_database_error()
                .and_then(|error| error.code()),
            Some(std::borrow::Cow::Borrowed("55P03")),
            "expected PostgreSQL lock_not_available for current site authority"
        );
        competing_site.rollback().await.ok();
        tx.rollback().await.expect("release authority lock");

        // An inactive scope no longer resolves, and can be restored by the
        // trusted inventory owner without rebinding its immutable coordinates.
        sqlx::query(
            "UPDATE k8s_cluster_environment_scopes \
             SET lifecycle_state = 'Inactive', authority_version = authority_version + 1 \
             WHERE id = $1",
        )
        .bind(&authority.scope_id)
        .execute(&db)
        .await
        .expect("deactivate authority");
        let mut inactive_tx = db.begin().await.expect("begin inactive lookup");
        assert!(
            lock_cluster_scope(&mut inactive_tx, "defra-aks-01", Environment::Dev)
                .await
                .expect("inactive lookup")
                .is_none()
        );
        inactive_tx.rollback().await.ok();
        assert!(
            get_namespace(&db, "k8s-defra-app-001")
                .await
                .expect("inactive-authority namespace read")
                .is_none(),
            "rows under inactive authority must be quarantined from reads"
        );
        sqlx::query(
            "UPDATE k8s_cluster_environment_scopes \
             SET lifecycle_state = 'Active', authority_version = authority_version + 1 \
             WHERE id = $1",
        )
        .bind(&authority.scope_id)
        .execute(&db)
        .await
        .expect("restore authority");
    }

    #[tokio::test]
    async fn test_site_deactivation_quarantines_reads_and_mutations_at_current_authority() {
        let Some(db) = test_pool().await else {
            return;
        };
        let token = sfx();
        let site = format!("TEST{}", token.to_ascii_uppercase());
        let cluster_id = format!("cluster-current-site-{token}");
        let cluster_name = format!("current-site-cluster-{token}");
        let scope_id = format!("scope-current-site-{token}");

        let mut inventory = db.begin().await.expect("begin current-site fixture");
        sqlx::query(
            "INSERT INTO site_registry \
             (unlocode, name, country, country_code, timezone, active, code_system) \
             VALUES ($1, 'Current test site', 'Test', 'ZZ', 'Etc/UTC', TRUE, 'custom')",
        )
        .bind(&site)
        .execute(&mut *inventory)
        .await
        .expect("insert active canonical site");
        sqlx::query(
            "INSERT INTO k8s_cluster_registry \
             (id, cluster_name, site, lifecycle_state, inventory_source) \
             VALUES ($1, $2, $3, 'Active', 'test-current-site')",
        )
        .bind(&cluster_id)
        .bind(&cluster_name)
        .bind(&site)
        .execute(&mut *inventory)
        .await
        .expect("insert current-site cluster");
        sqlx::query(
            "INSERT INTO k8s_cluster_environment_scopes \
             (id, cluster_id, cluster_name, site, environment, lifecycle_state, inventory_source) \
             VALUES ($1, $2, $3, $4, 'Dev', 'Active', 'test-current-site')",
        )
        .bind(&scope_id)
        .bind(&cluster_id)
        .bind(&cluster_name)
        .bind(&site)
        .execute(&mut *inventory)
        .await
        .expect("insert current-site scope");
        inventory
            .commit()
            .await
            .expect("commit current-site fixture");

        let name = format!("current-site-namespace-{token}");
        let (ns, req) = build_and_provision(&db, &name, &cluster_name, &site, Environment::Dev)
            .await
            .expect("active current site must authorize provisioning");

        let mut mutation = db.begin().await.expect("begin mutation race");
        let updated = match update_quota(&mut mutation, &ns, 2, 4, 20)
            .await
            .expect("current-site quota mutation")
        {
            TransitionOutcome::Updated(namespace) => *namespace,
            other => panic!("expected current authority update, got {other:?}"),
        };
        let mut deactivation = db.begin().await.expect("begin racing deactivation");
        sqlx::query("SET LOCAL lock_timeout = '100ms'")
            .execute(&mut *deactivation)
            .await
            .expect("set deactivation lock timeout");
        let blocked = sqlx::query("UPDATE site_registry SET active = FALSE WHERE unlocode = $1")
            .bind(&site)
            .execute(&mut *deactivation)
            .await
            .expect_err("in-flight namespace mutation must retain the site authority lock");
        assert_eq!(
            blocked.as_database_error().and_then(|error| error.code()),
            Some(std::borrow::Cow::Borrowed("55P03")),
            "expected PostgreSQL lock_not_available"
        );
        deactivation.rollback().await.ok();
        mutation
            .commit()
            .await
            .expect("commit mutation before deactivation");

        sqlx::query("UPDATE site_registry SET active = FALSE WHERE unlocode = $1")
            .bind(&site)
            .execute(&db)
            .await
            .expect("deactivate current site");

        assert!(
            get_namespace(&db, &ns.id)
                .await
                .expect("read after site deactivation")
                .is_none(),
            "site deactivation must immediately quarantine a namespace read"
        );
        assert!(
            list_namespaces(&db, &[], &[])
                .await
                .expect("list after site deactivation")
                .iter()
                .all(|candidate| candidate.id != ns.id),
            "site deactivation must quarantine namespace lists and aggregates"
        );
        assert!(
            list_requests(&db, &[], &[])
                .await
                .expect("request list after site deactivation")
                .iter()
                .all(|candidate| candidate.id != req.id),
            "site deactivation must quarantine the paired request"
        );
        let mut inactive_lookup = db.begin().await.expect("begin inactive lookup");
        assert!(
            lock_cluster_scope(&mut inactive_lookup, &cluster_name, Environment::Dev)
                .await
                .expect("lookup after site deactivation")
                .is_none(),
            "provisioning authority must fail closed after site deactivation"
        );
        inactive_lookup.rollback().await.ok();

        let mut rejected_mutations = db.begin().await.expect("begin rejected mutations");
        assert!(matches!(
            update_quota(&mut rejected_mutations, &updated, 8, 16, 80)
                .await
                .expect("quota result under inactive site"),
            TransitionOutcome::NotFound
        ));
        assert!(matches!(
            set_namespace_status(
                &mut rejected_mutations,
                &updated,
                &NamespaceStatus::Suspended,
            )
            .await
            .expect("status result under inactive site"),
            TransitionOutcome::NotFound
        ));
        rejected_mutations.rollback().await.ok();

        let raw: (i32, String) =
            sqlx::query_as("SELECT cpu_request, status FROM k8s_namespaces WHERE id = $1")
                .bind(&ns.id)
                .fetch_one(&db)
                .await
                .expect("read quarantined row for unchanged-state proof");
        assert_eq!(raw, (2, "Creating".into()));

        sqlx::query("UPDATE site_registry SET active = TRUE WHERE unlocode = $1")
            .bind(&site)
            .execute(&db)
            .await
            .expect("reactivate current site");
        assert!(
            get_namespace(&db, &ns.id)
                .await
                .expect("read after current-site reactivation")
                .is_some(),
            "only the current active canonical site row restores authority"
        );

        sqlx::query("DELETE FROM container_requests WHERE id = $1")
            .bind(&req.id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM k8s_namespaces WHERE id = $1")
            .bind(&ns.id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM k8s_cluster_environment_scopes WHERE id = $1")
            .bind(&scope_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM k8s_cluster_registry WHERE id = $1")
            .bind(&cluster_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM site_registry WHERE unlocode = $1")
            .bind(&site)
            .execute(&db)
            .await
            .ok();
    }

    #[tokio::test]
    async fn test_unregistered_namespace_insert_is_rejected() {
        let Some(db) = test_pool().await else {
            return;
        };
        let id = format!("legacy-k8s-{}", sfx());
        let name = format!("legacy-ns-{}", sfx());
        let error = sqlx::query(
            "INSERT INTO k8s_namespaces \
             (id, name, cluster, site, cpu_limit, cpu_request, memory_limit_gb, \
              memory_request_gb, storage_gb, max_pods, network_policy, service_accounts, status) \
             VALUES ($1, $2, 'unregistered-cluster', 'DEFRA', 2, 1, 4, 2, 10, 16, \
                     'deny-by-default', '{}', 'Creating')",
        )
        .bind(&id)
        .bind(&name)
        .execute(&db)
        .await
        .expect_err("post-cutover inserts without active authority must fail closed");
        assert_eq!(
            error
                .as_database_error()
                .and_then(|database_error| database_error.code())
                .as_deref(),
            Some("P0001")
        );
        assert!(error
            .to_string()
            .contains("active Kubernetes cluster scope authority is required for insert"));
        let persisted: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM k8s_namespaces WHERE id = $1)")
                .bind(&id)
                .fetch_one(&db)
                .await
                .expect("check rejected namespace absence");
        assert!(
            !persisted,
            "a rejected post-cutover namespace must leave no quarantined row"
        );
    }

    // ─── Provision ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_provision_namespace_success() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let name = format!("defra-test-ns-{sfx}");
        validate_capacity(4, 8, 100).unwrap();
        validate_capacity_bounds(4, 8, 100).unwrap();
        let (ns, req) = build_and_provision(
            &db,
            &name,
            "defra-aks-01",
            "DEFRA",
            parse_environment("Dev").unwrap(),
        )
        .await
        .expect("provision_namespace failed");
        let ns_id = ns.id.clone();
        let req_id = req.id.clone();

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

        let provenance: (String, String, String, String) = sqlx::query_as(
            "SELECT cluster_scope_id, environment, scope_state, scope_provenance \
             FROM k8s_namespaces WHERE id = $1",
        )
        .bind(&ns_id)
        .fetch_one(&db)
        .await
        .expect("scope provenance query");
        assert_eq!(provenance.0, ns.cluster_scope_id);
        assert_eq!(provenance.1, "Dev");
        assert_eq!(provenance.2, "Verified");
        assert!(provenance.3.contains("cluster=cluster-defra-aks-01:v"));
        assert!(provenance
            .3
            .contains("scope=cluster-scope-defra-aks-01-dev:v"));

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
        let (ns1, req1) =
            build_and_provision(&db, &name, "defra-aks-01", "DEFRA", Environment::Dev)
                .await
                .expect("first provision must succeed");
        let ns1_id = ns1.id.clone();
        let req1_id = req1.id.clone();

        let mut tx = db.begin().await.expect("begin second provision");
        let authority = lock_cluster_scope(&mut tx, "defra-aks-01", Environment::Dev)
            .await
            .expect("lock authority")
            .expect("active authority");
        let (ns2, req2) = build_namespace_and_request(
            &name,
            "container-repository-test",
            &authority.scope_id,
            &authority.cluster,
            &authority.site,
            4,
            8,
            100,
            authority.environment,
        );

        let err = provision_namespace(&mut tx, &ns2, &req2)
            .await
            .expect_err("duplicate (cluster, name) must error");
        tx.rollback().await.ok();
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
        let (ns, req) = build_and_provision(&db, &name, "gblon-k8s-01", "GBLON", Environment::Prod)
            .await
            .expect("provision failed");
        let ns_id = ns.id.clone();
        let req_id = req.id.clone();

        // Update quota: cpu=12, memory=32, storage=300
        let mut tx = db.begin().await.expect("begin");
        let updated = match update_quota(&mut tx, &ns, 12, 32, 300)
            .await
            .expect("update_quota failed")
        {
            TransitionOutcome::Updated(ns) => *ns,
            other => panic!("expected Updated, got {other:?}"),
        };
        let mut competing = db.begin().await.expect("begin competing authority update");
        sqlx::query("SET LOCAL lock_timeout = '100ms'")
            .execute(&mut *competing)
            .await
            .expect("set lock timeout");
        sqlx::query(
            "UPDATE k8s_cluster_environment_scopes \
             SET lifecycle_state = 'Inactive', authority_version = authority_version + 1 \
             WHERE id = $1",
        )
        .bind(&updated.cluster_scope_id)
        .execute(&mut *competing)
        .await
        .expect_err("mutation transaction must retain the authority lock");
        competing.rollback().await.ok();
        tx.commit().await.expect("commit");
        assert_eq!(updated.resource_quota.cpu_request, 12);
        assert_eq!(updated.resource_quota.cpu_limit, 24);
        assert_eq!(updated.resource_quota.memory_request_gb, 32);
        assert_eq!(updated.resource_quota.memory_limit_gb, 64);
        assert_eq!(updated.resource_quota.storage_gb, 300);
        assert_eq!(updated.resource_quota.max_pods, 96);

        // The SQL compare-and-swap repeats immutable authority, site, and
        // environment coordinates. A stale/forged pre-load cannot mutate it.
        let mut foreign_site = updated.clone();
        foreign_site.site = "DEFRA".into();
        let mut tx_foreign_site = db.begin().await.expect("begin foreign site CAS");
        assert!(matches!(
            update_quota(&mut tx_foreign_site, &foreign_site, 2, 4, 20)
                .await
                .expect("foreign site CAS"),
            TransitionOutcome::NotFound
        ));
        tx_foreign_site.rollback().await.ok();

        let mut foreign_environment = updated.clone();
        foreign_environment.environment = Environment::Dev;
        let mut tx_foreign_environment = db.begin().await.expect("begin foreign env CAS");
        assert!(matches!(
            update_quota(&mut tx_foreign_environment, &foreign_environment, 2, 4, 20)
                .await
                .expect("foreign environment CAS"),
            TransitionOutcome::NotFound
        ));
        tx_foreign_environment.rollback().await.ok();

        let unchanged = get_namespace(&db, &ns_id)
            .await
            .expect("read after rejected CAS")
            .expect("namespace remains visible");
        assert_eq!(unchanged.resource_quota.cpu_request, 12);
        assert_eq!(unchanged.site, "GBLON");
        assert_eq!(unchanged.environment, Environment::Prod);

        // Not found returns NotFound
        let mut absent_expected = updated.clone();
        absent_expected.id = "k8s-nonexistent".into();
        let mut tx_absent = db.begin().await.expect("begin");
        let absent = update_quota(&mut tx_absent, &absent_expected, 4, 8, 100)
            .await
            .expect("must not error for absent");
        tx_absent.rollback().await.ok();
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
        let (ns, req) =
            build_and_provision(&db, &name, "frpar-k8s-01", "FRPAR", Environment::Staging)
                .await
                .expect("provision failed");
        let ns_id = ns.id.clone();
        let req_id = req.id.clone();

        let updated_ns = |o: TransitionOutcome| match o {
            TransitionOutcome::Updated(ns) => *ns,
            other => panic!("expected Updated, got {other:?}"),
        };

        // Creating -> Suspended
        let mut tx1 = db.begin().await.expect("begin");
        let suspended = updated_ns(
            set_namespace_status(&mut tx1, &ns, &NamespaceStatus::Suspended)
                .await
                .expect("suspend failed"),
        );
        tx1.commit().await.expect("commit");
        assert_eq!(suspended.status, NamespaceStatus::Suspended);

        // Suspended -> Active (resume)
        let mut tx2 = db.begin().await.expect("begin");
        let resumed = updated_ns(
            set_namespace_status(&mut tx2, &suspended, &NamespaceStatus::Active)
                .await
                .expect("resume failed"),
        );
        tx2.commit().await.expect("commit");
        assert_eq!(resumed.status, NamespaceStatus::Active);

        // Active -> Terminating
        let mut tx3 = db.begin().await.expect("begin");
        let terminated = updated_ns(
            set_namespace_status(&mut tx3, &resumed, &NamespaceStatus::Terminating)
                .await
                .expect("terminate failed"),
        );
        tx3.commit().await.expect("commit");
        assert_eq!(terminated.status, NamespaceStatus::Terminating);

        // Guard: once Terminating, further transitions are rejected (no clobber).
        let mut tx4 = db.begin().await.expect("begin");
        let blocked = set_namespace_status(&mut tx4, &terminated, &NamespaceStatus::Suspended)
            .await
            .expect("must not error");
        tx4.rollback().await.ok();
        assert!(
            matches!(blocked, TransitionOutcome::Terminating),
            "suspending a Terminating namespace must be rejected"
        );
        let mut tx5 = db.begin().await.expect("begin");
        let quota_blocked = update_quota(&mut tx5, &terminated, 4, 8, 100)
            .await
            .expect("must not error");
        tx5.rollback().await.ok();
        assert!(
            matches!(quota_blocked, TransitionOutcome::Terminating),
            "updating quota on a Terminating namespace must be rejected"
        );

        // Not found returns NotFound
        let mut absent_expected = terminated.clone();
        absent_expected.id = "k8s-nonexistent".into();
        let mut tx6 = db.begin().await.expect("begin");
        let absent = set_namespace_status(&mut tx6, &absent_expected, &NamespaceStatus::Active)
            .await
            .expect("must not error for absent");
        tx6.rollback().await.ok();
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
        let (ns, req) = build_and_provision(&db, &name, "defra-aks-01", "DEFRA", Environment::Dev)
            .await
            .expect("provision failed");
        let ns_id = ns.id.clone();
        let req_id = req.id.clone();

        // Should be found (Creating status, not Terminating)
        let found = find_active_namespace_by_name(
            &db,
            &name,
            "defra-aks-01",
            &["DEFRA".to_string()],
            &["Dev".to_string()],
        )
        .await
        .expect("find failed");
        assert!(found.is_some());

        let foreign = find_active_namespace_by_name(
            &db,
            &name,
            "defra-aks-01",
            &["GBLON".to_string()],
            &["Dev".to_string()],
        )
        .await
        .expect("foreign scoped find failed");
        assert!(
            foreign.is_none(),
            "validate-name must not become a cross-site identifier oracle"
        );

        // Set to Terminating — should now return None
        let mut tx_term = db.begin().await.expect("begin");
        set_namespace_status(&mut tx_term, &ns, &NamespaceStatus::Terminating)
            .await
            .expect("terminate failed");
        tx_term.commit().await.expect("commit");
        let not_found = find_active_namespace_by_name(
            &db,
            &name,
            "defra-aks-01",
            &["DEFRA".to_string()],
            &["Dev".to_string()],
        )
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
