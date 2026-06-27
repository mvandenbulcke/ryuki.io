//! Repository functions for `lb_virtual_servers`, `lb_pools`, `lb_pool_members`,
//! and `lb_requests`.
//!
//! # ID type
//! All four tables use TEXT primary keys (e.g. "vs-defra-web", "pool-defra-web",
//! "lbr-defra-001"). Ids are bound and decoded directly as `String`.
//!
//! # Enum encoding
//! All six enums derive `#[serde(rename_all = "kebab-case")]`.  The DB CHECK
//! constraints store the kebab-case serde form (e.g. "round-robin",
//! "source-ip", "least-connections").  We decode via
//! `serde_json::from_value(Value::String(raw))` — no match helper needed because
//! serde already knows the mapping.  Writes serialize via
//! `serde_json::to_value(&enum).unwrap().as_str().unwrap().to_owned()` or the
//! `enum_to_db` helper below.
//!
//! # Integer widths
//! `port` and `weight` are `u16` in the engine but `INTEGER` (i32) in Postgres.
//! Read: `u16::try_from(i32_val)` — a negative or out-of-range value is a Decode
//! error (corrupt row → 500).
//! Write: `i32::from(u16_val)` — u16 always fits i32, but we are explicit.
//!
//! # TEXT[]
//! `lb_requests.pool_members` is `TEXT[]`.  sqlx decodes it natively into
//! `Vec<String>` when the row field is typed `Vec<String>`.  Writes bind a
//! `Vec<String>` slice directly.
//!
//! # Pool members (child table)
//! `lb_pool_members` rows are aggregated into `LbPool.members` on read.
//! The list/get functions JOIN or sub-query to assemble the full struct.
//!
//! # provision_lb transaction
//! Creates an `LbPool` + its members + an `LbVirtualServer` + an `LbRequest`
//! atomically in ONE transaction (same order as the FK dependency: pool → members
//! → virtual_server → request).
//!
//! # VS status transitions
//! drain / disable / enable are FREE SET (the engine has no from-state guard).
//! The handler is: load → UPDATE status → return updated VS.

use ryuki_engine::load_balancer::{
    LbPool, LbProtocol, LbRequest, LbVirtualServer, PersistenceMethod, PoolAlgorithm, PoolMember,
    PoolMemberStatus, VirtualServerStatus,
};
use serde_json::Value;
use sqlx::PgPool;

// ─── Enum helpers ─────────────────────────────────────────────────────────────

/// Serialize an engine enum to its kebab-case DB form using serde.
/// Panics only if the enum's serde impl produces a non-string value, which
/// cannot happen for these unit-variant enums.
fn enum_to_db<T: serde::Serialize>(val: &T) -> String {
    serde_json::to_value(val)
        .expect("enum serialization cannot fail")
        .as_str()
        .expect("enum serde value must be a string")
        .to_owned()
}

/// Decode a raw DB string into an engine enum via serde.
/// A decode failure means the persisted row is corrupt → surfaced as
/// `sqlx::Error::Decode` so the handler maps it to 500.
fn enum_from_db<T: serde::de::DeserializeOwned>(raw: &str, column: &str) -> Result<T, sqlx::Error> {
    serde_json::from_value(Value::String(raw.to_owned()))
        .map_err(|e| sqlx::Error::Decode(format!("{column}: corrupt value '{raw}': {e}").into()))
}

// ─── Column constants ─────────────────────────────────────────────────────────

pub const VS_COLUMNS: &str =
    "id, name, vip, port, protocol, pool_id, site, ssl_profile, persistence_method, status";

pub const POOL_COLUMNS: &str = "id, name, site, algorithm, health_monitor";

pub const MEMBER_COLUMNS: &str = "pool_id, hostname, ip, port, weight, status";

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct LbVirtualServerRow {
    pub id: String,
    pub name: String,
    pub vip: String,
    pub port: i32,
    pub protocol: String,
    pub pool_id: String,
    pub site: String,
    pub ssl_profile: Option<String>,
    pub persistence_method: String,
    pub status: String,
}

impl LbVirtualServerRow {
    pub fn into_model(self) -> Result<LbVirtualServer, sqlx::Error> {
        let port = u16::try_from(self.port).map_err(|e| {
            sqlx::Error::Decode(
                format!("lb_virtual_servers.port: corrupt value {}: {e}", self.port).into(),
            )
        })?;
        let protocol: LbProtocol = enum_from_db(&self.protocol, "lb_virtual_servers.protocol")?;
        let persistence_method: PersistenceMethod = enum_from_db(
            &self.persistence_method,
            "lb_virtual_servers.persistence_method",
        )?;
        let status: VirtualServerStatus = enum_from_db(&self.status, "lb_virtual_servers.status")?;
        Ok(LbVirtualServer {
            id: self.id,
            name: self.name,
            vip: self.vip,
            port,
            protocol,
            pool_id: self.pool_id,
            site: self.site,
            ssl_profile: self.ssl_profile,
            persistence_method,
            status,
        })
    }
}

#[derive(sqlx::FromRow)]
pub struct LbPoolRow {
    pub id: String,
    pub name: String,
    pub site: String,
    pub algorithm: String,
    pub health_monitor: Option<String>,
}

impl LbPoolRow {
    pub fn into_model(self, members: Vec<PoolMember>) -> Result<LbPool, sqlx::Error> {
        let algorithm: PoolAlgorithm = enum_from_db(&self.algorithm, "lb_pools.algorithm")?;
        Ok(LbPool {
            id: self.id,
            name: self.name,
            site: self.site,
            members,
            algorithm,
            health_monitor: self.health_monitor,
        })
    }
}

#[derive(sqlx::FromRow)]
pub struct LbPoolMemberRow {
    #[allow(dead_code)]
    pub pool_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: i32,
    pub weight: i32,
    pub status: String,
}

impl LbPoolMemberRow {
    pub fn into_model(self) -> Result<PoolMember, sqlx::Error> {
        let port = u16::try_from(self.port).map_err(|e| {
            sqlx::Error::Decode(
                format!("lb_pool_members.port: corrupt value {}: {e}", self.port).into(),
            )
        })?;
        let weight = u16::try_from(self.weight).map_err(|e| {
            sqlx::Error::Decode(
                format!("lb_pool_members.weight: corrupt value {}: {e}", self.weight).into(),
            )
        })?;
        let status: PoolMemberStatus = enum_from_db(&self.status, "lb_pool_members.status")?;
        Ok(PoolMember {
            hostname: self.hostname,
            ip: self.ip,
            port,
            weight,
            status,
        })
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Load all members for a given pool_id.
async fn load_pool_members(pool: &PgPool, pool_id: &str) -> Result<Vec<PoolMember>, sqlx::Error> {
    let rows: Vec<LbPoolMemberRow> = sqlx::query_as(&format!(
        "SELECT {MEMBER_COLUMNS} FROM lb_pool_members WHERE pool_id = $1 ORDER BY hostname"
    ))
    .bind(pool_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Load a single LbPool (with members) by id. Returns Ok(None) when absent.
async fn load_pool_with_members(
    pool: &PgPool,
    pool_id: &str,
) -> Result<Option<LbPool>, sqlx::Error> {
    let row: Option<LbPoolRow> = sqlx::query_as(&format!(
        "SELECT {POOL_COLUMNS} FROM lb_pools WHERE id = $1"
    ))
    .bind(pool_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let members = load_pool_members(pool, pool_id).await?;
    Ok(Some(row.into_model(members)?))
}

/// Public wrapper around `load_pool_with_members` for use in contract handlers.
pub async fn load_pool_with_members_pub(
    pool: &PgPool,
    pool_id: &str,
) -> Result<Option<LbPool>, sqlx::Error> {
    load_pool_with_members(pool, pool_id).await
}

// ─── Read functions ───────────────────────────────────────────────────────────

/// List all virtual servers (optionally filtered by site).
/// Degrade to empty vec when called with no DB — handled by the handler.
pub async fn list_virtual_servers(
    pool: &PgPool,
    site: &str,
) -> Result<Vec<LbVirtualServer>, sqlx::Error> {
    let rows: Vec<LbVirtualServerRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {VS_COLUMNS} FROM lb_virtual_servers ORDER BY id"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {VS_COLUMNS} FROM lb_virtual_servers WHERE site = $1 ORDER BY id"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Get a single virtual server by id. Returns Ok(None) when absent.
pub async fn get_virtual_server(
    pool: &PgPool,
    id: &str,
) -> Result<Option<LbVirtualServer>, sqlx::Error> {
    let row: Option<LbVirtualServerRow> = sqlx::query_as(&format!(
        "SELECT {VS_COLUMNS} FROM lb_virtual_servers WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// Get a virtual server and its pool (with members) by VS id.
/// Returns Ok(None) when the VS is absent.
///
/// Test-only: the handler path (`lb_vs_get`) now loads the VS first, applies the
/// site-scope guard, and only then loads the pool — so an out-of-scope caller
/// can never trigger a pool/member decode error that would betray the VS's
/// existence (#2). This joint loader is retained for repo-layer assembly tests.
#[cfg(test)]
pub async fn get_virtual_server_with_pool(
    pool: &PgPool,
    id: &str,
) -> Result<Option<(LbVirtualServer, LbPool)>, sqlx::Error> {
    let Some(vs) = get_virtual_server(pool, id).await? else {
        return Ok(None);
    };
    let lb_pool = load_pool_with_members(pool, &vs.pool_id).await?;
    // The pool FK is enforced; absent pool is a data integrity error.
    let lb_pool = lb_pool.ok_or_else(|| {
        sqlx::Error::Decode(
            format!(
                "lb_virtual_servers.pool_id: pool '{}' referenced by vs '{}' not found",
                vs.pool_id, id
            )
            .into(),
        )
    })?;
    Ok(Some((vs, lb_pool)))
}

/// Get lb_status aggregates for a site (or all sites if site is empty).
pub async fn get_lb_status(
    pool: &PgPool,
    site: &str,
) -> Result<(i64, i64, i64, i64, i64, i64), sqlx::Error> {
    // Returns: (vs_count, pool_count, up_members, down_members, offline_vs, draining_vs)
    let (vs_count, offline_vs, draining_vs): (i64, i64, i64) = if site.is_empty() {
        sqlx::query_as(
            "SELECT \
                COUNT(*), \
                COUNT(*) FILTER (WHERE status = 'offline'), \
                COUNT(*) FILTER (WHERE status = 'draining') \
             FROM lb_virtual_servers",
        )
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT \
                COUNT(*), \
                COUNT(*) FILTER (WHERE status = 'offline'), \
                COUNT(*) FILTER (WHERE status = 'draining') \
             FROM lb_virtual_servers WHERE site = $1",
        )
        .bind(site)
        .fetch_one(pool)
        .await?
    };

    let (pool_count,): (i64,) = if site.is_empty() {
        sqlx::query_as("SELECT COUNT(*) FROM lb_pools")
            .fetch_one(pool)
            .await?
    } else {
        sqlx::query_as("SELECT COUNT(*) FROM lb_pools WHERE site = $1")
            .bind(site)
            .fetch_one(pool)
            .await?
    };

    // Members are filtered by joining with pools (site filter)
    let (up_members, down_members): (i64, i64) = if site.is_empty() {
        sqlx::query_as(
            "SELECT \
                COUNT(*) FILTER (WHERE m.status = 'up'), \
                COUNT(*) FILTER (WHERE m.status = 'down') \
             FROM lb_pool_members m",
        )
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT \
                COUNT(*) FILTER (WHERE m.status = 'up'), \
                COUNT(*) FILTER (WHERE m.status = 'down') \
             FROM lb_pool_members m \
             JOIN lb_pools p ON p.id = m.pool_id \
             WHERE p.site = $1",
        )
        .bind(site)
        .fetch_one(pool)
        .await?
    };

    Ok((
        vs_count,
        pool_count,
        up_members,
        down_members,
        offline_vs,
        draining_vs,
    ))
}

/// Check whether a VIP is in use at a site. Returns None if available.
pub async fn find_vip_conflict(
    pool: &PgPool,
    vip: &str,
    site: &str,
) -> Result<Option<LbVirtualServer>, sqlx::Error> {
    let row: Option<LbVirtualServerRow> = sqlx::query_as(&format!(
        "SELECT {VS_COLUMNS} FROM lb_virtual_servers WHERE vip = $1 AND site = $2 LIMIT 1"
    ))
    .bind(vip)
    .bind(site)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

// ─── Write functions ──────────────────────────────────────────────────────────

/// Provision a new load balancer configuration atomically:
///   1. INSERT INTO lb_pools
///   2. INSERT INTO lb_pool_members (one per member)
///   3. INSERT INTO lb_virtual_servers
///   4. INSERT INTO lb_requests
///
/// Returns (LbVirtualServer, LbPool, LbRequest) on success.
pub async fn provision_lb(
    db: &PgPool,
    vs: &LbVirtualServer,
    lb_pool: &LbPool,
    request: &LbRequest,
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;

    // 1. Insert pool
    sqlx::query(
        "INSERT INTO lb_pools (id, name, site, algorithm, health_monitor) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&lb_pool.id)
    .bind(&lb_pool.name)
    .bind(&lb_pool.site)
    .bind(enum_to_db(&lb_pool.algorithm))
    .bind(&lb_pool.health_monitor)
    .execute(&mut *tx)
    .await?;

    // 2. Insert pool members
    for member in &lb_pool.members {
        sqlx::query(
            "INSERT INTO lb_pool_members (pool_id, hostname, ip, port, weight, status) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&lb_pool.id)
        .bind(&member.hostname)
        .bind(&member.ip)
        .bind(i32::from(member.port))
        .bind(i32::from(member.weight))
        .bind(enum_to_db(&member.status))
        .execute(&mut *tx)
        .await?;
    }

    // 3. Insert virtual server
    sqlx::query(
        "INSERT INTO lb_virtual_servers \
         (id, name, vip, port, protocol, pool_id, site, ssl_profile, persistence_method, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&vs.id)
    .bind(&vs.name)
    .bind(&vs.vip)
    .bind(i32::from(vs.port))
    .bind(enum_to_db(&vs.protocol))
    .bind(&vs.pool_id)
    .bind(&vs.site)
    .bind(&vs.ssl_profile)
    .bind(enum_to_db(&vs.persistence_method))
    .bind(enum_to_db(&vs.status))
    .execute(&mut *tx)
    .await?;

    // 4. Insert request
    sqlx::query(
        "INSERT INTO lb_requests \
         (id, requester, virtual_server_name, vip, port, protocol, site, pool_members, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&request.id)
    .bind(&request.requester)
    .bind(&request.virtual_server_name)
    .bind(&request.vip)
    .bind(i32::from(request.port))
    .bind(enum_to_db(&request.protocol))
    .bind(&request.site)
    .bind(&request.pool_members)
    .bind(enum_to_db(&request.status))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Add a pool member. Returns Ok(pool_id) on success.
/// Unique violation (pool_id, hostname PK) → caller maps to 409.
pub async fn add_pool_member(
    executor: impl sqlx::PgExecutor<'_>,
    pool_id: &str,
    member: &PoolMember,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO lb_pool_members (pool_id, hostname, ip, port, weight, status) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(pool_id)
    .bind(&member.hostname)
    .bind(&member.ip)
    .bind(i32::from(member.port))
    .bind(i32::from(member.weight))
    .bind(enum_to_db(&member.status))
    .execute(executor)
    .await?;
    Ok(())
}

/// Remove a pool member by (pool_id, hostname).
/// Returns Ok(true) when deleted, Ok(false) when absent.
pub async fn remove_pool_member(
    executor: impl sqlx::PgExecutor<'_>,
    pool_id: &str,
    hostname: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM lb_pool_members WHERE pool_id = $1 AND hostname = $2")
        .bind(pool_id)
        .bind(hostname)
        .execute(executor)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Update a virtual server's status (free set — no from-state guard).
/// Returns Ok(Some(vs)) on success, Ok(None) when vs absent.
pub async fn update_vs_status(
    executor: impl sqlx::PgExecutor<'_>,
    id: &str,
    status: &VirtualServerStatus,
) -> Result<Option<LbVirtualServer>, sqlx::Error> {
    let row: Option<LbVirtualServerRow> = sqlx::query_as(&format!(
        "UPDATE lb_virtual_servers SET status = $2, updated_at = NOW() \
         WHERE id = $1 \
         RETURNING {VS_COLUMNS}"
    ))
    .bind(id)
    .bind(enum_to_db(status))
    .fetch_optional(executor)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// Update a VS's structural fields, leaving its identity (vip/site/name/pool)
/// and live status untouched. PARTIAL and atomic: each of port/protocol/
/// persistence updates ONLY when its argument is `Some` (`COALESCE` keeps the
/// column otherwise), so two concurrent partial updates cannot clobber each
/// other's omitted fields (no read-modify-write). `ssl_profile` is three-state:
/// `update_ssl == false` keeps it, `true` sets it to `ssl_value` (which may be
/// `None` to clear). Returns the updated VS, or `Ok(None)` when no such VS
/// exists.
#[allow(clippy::too_many_arguments)]
pub async fn update_virtual_server(
    executor: impl sqlx::PgExecutor<'_>,
    id: &str,
    port: Option<u16>,
    protocol: Option<&LbProtocol>,
    persistence: Option<&PersistenceMethod>,
    update_ssl: bool,
    ssl_value: Option<&str>,
) -> Result<Option<LbVirtualServer>, sqlx::Error> {
    let row: Option<LbVirtualServerRow> = sqlx::query_as(&format!(
        "UPDATE lb_virtual_servers SET \
            port = COALESCE($2, port), \
            protocol = COALESCE($3, protocol), \
            persistence_method = COALESCE($4, persistence_method), \
            ssl_profile = CASE WHEN $5 THEN $6 ELSE ssl_profile END, \
            updated_at = NOW() \
         WHERE id = $1 \
         RETURNING {VS_COLUMNS}"
    ))
    .bind(id)
    .bind(port.map(i32::from))
    .bind(protocol.map(enum_to_db))
    .bind(persistence.map(enum_to_db))
    .bind(update_ssl)
    .bind(ssl_value)
    .fetch_optional(executor)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// Delete a VS and orphan-clean its backing pool. Runs in ONE transaction: the
/// VS row AND its parent pool row are locked (`FOR UPDATE`) — the pool lock is
/// what serializes a concurrent provision adding another VS to the same pool
/// (its FK insert takes a KEY SHARE lock on the pool row, which conflicts), so
/// the orphan check cannot race. The pool is deleted only if no other VS still
/// references it (members cascade). Returns `false` when the VS did not exist.
pub async fn delete_virtual_server(
    conn: &mut sqlx::PgConnection,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT pool_id FROM lb_virtual_servers WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((pool_id,)) = row else {
        return Ok(false);
    };
    // Lock the parent pool row so a concurrent provision referencing it
    // serializes against our orphan check below.
    sqlx::query("SELECT id FROM lb_pools WHERE id = $1 FOR UPDATE")
        .bind(&pool_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM lb_virtual_servers WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    // Drop the backing pool only when nothing references it anymore.
    sqlx::query(
        "DELETE FROM lb_pools WHERE id = $1 \
         AND NOT EXISTS (SELECT 1 FROM lb_virtual_servers WHERE pool_id = $1)",
    )
    .bind(&pool_id)
    .execute(&mut *conn)
    .await?;
    Ok(true)
}

// ─── DB integration tests ─────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api --lib -- --test-threads=1 load_balancer_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.
#[cfg(test)]
mod load_balancer_db_tests {
    use super::*;
    use ryuki_engine::load_balancer::{
        LbPool, LbProtocol, LbRequest, LbRequestStatus, LbVirtualServer, PersistenceMethod,
        PoolAlgorithm, PoolMember, PoolMemberStatus, VirtualServerStatus,
    };
    use uuid::Uuid;

    async fn test_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("load_balancer_db_tests: RYUKI_DATABASE_URL not set — skipping");
                return None;
            }
        };
        let db = PgPool::connect(&url)
            .await
            .expect("RYUKI_DATABASE_URL is set but connection failed");
        crate::database::run_migrations(&db)
            .await
            .expect("migrations must apply cleanly when RYUKI_DATABASE_URL is set");
        Some(db)
    }

    fn suffix() -> String {
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("x")
            .to_owned()
    }

    #[tokio::test]
    async fn test_list_virtual_servers_returns_seeded_rows() {
        let Some(db) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // All sites
        let vss = list_virtual_servers(&db, "")
            .await
            .expect("list_virtual_servers failed");
        assert!(vss.len() >= 4, "migration 072 seeds 4 virtual servers");

        // Filtered by DEFRA
        let defra = list_virtual_servers(&db, "DEFRA")
            .await
            .expect("list_virtual_servers DEFRA failed");
        assert_eq!(defra.len(), 2, "DEFRA has 2 seeded virtual servers");

        // Members aggregated: get one VS with pool to verify member count
        let (vs, pool) = get_virtual_server_with_pool(&db, "vs-defra-web")
            .await
            .expect("get_virtual_server_with_pool failed")
            .expect("vs-defra-web must be present");
        assert_eq!(vs.site, "DEFRA");
        assert_eq!(pool.members.len(), 2, "pool-defra-web has 2 members");
        assert!(pool.members.iter().any(|m| m.hostname == "defra-web-01"));
        assert!(pool.members.iter().any(|m| m.hostname == "defra-web-02"));
    }

    #[tokio::test]
    async fn test_get_virtual_server_by_id_and_absent() {
        let Some(db) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let found = get_virtual_server(&db, "vs-gblon-api")
            .await
            .expect("get_virtual_server failed");
        assert!(found.is_some(), "vs-gblon-api must be present");
        let vs = found.unwrap();
        assert_eq!(vs.site, "GBLON");
        assert_eq!(vs.protocol, LbProtocol::Https);

        let absent = get_virtual_server(&db, "vs-nonexistent")
            .await
            .expect("get_virtual_server must not error for absent id");
        assert!(absent.is_none(), "absent id must return None");
    }

    #[tokio::test]
    async fn test_provision_lb_creates_pool_vs_request() {
        let Some(db) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let sfx = suffix();
        let site = format!("TESTSITE{}", sfx.to_ascii_uppercase());
        let pool_id = format!("pool-test-{sfx}");
        let vs_id = format!("vs-test-{sfx}");
        let req_id = format!("lbr-test-{sfx}");

        let lb_pool = LbPool {
            id: pool_id.clone(),
            name: format!("test-pool-{sfx}"),
            site: site.clone(),
            members: vec![PoolMember {
                hostname: format!("member-{sfx}"),
                ip: "10.99.1.1".into(),
                port: 8080,
                weight: 1,
                status: PoolMemberStatus::Up,
            }],
            algorithm: PoolAlgorithm::RoundRobin,
            health_monitor: Some("tcp-connect".into()),
        };
        let vs = LbVirtualServer {
            id: vs_id.clone(),
            name: format!("test-vs-{sfx}"),
            vip: format!("10.99.99.{}", u8::MAX),
            port: 443,
            protocol: LbProtocol::Https,
            pool_id: pool_id.clone(),
            site: site.clone(),
            ssl_profile: Some("standard-tls".into()),
            persistence_method: PersistenceMethod::None,
            status: VirtualServerStatus::Online,
        };
        let request = LbRequest {
            id: req_id.clone(),
            requester: "test-requester".into(),
            virtual_server_name: vs.name.clone(),
            vip: vs.vip.clone(),
            port: 443,
            protocol: LbProtocol::Https,
            site: site.clone(),
            pool_members: vec![format!("member-{sfx}")],
            status: LbRequestStatus::Provisioned,
        };

        provision_lb(&db, &vs, &lb_pool, &request)
            .await
            .expect("provision_lb transaction failed");

        // Verify VS exists
        let loaded_vs = get_virtual_server(&db, &vs_id)
            .await
            .expect("get_virtual_server failed")
            .expect("VS must exist after provision");
        assert_eq!(loaded_vs.vip, vs.vip);
        assert_eq!(loaded_vs.protocol, LbProtocol::Https);

        // Verify pool with members
        let loaded_pool = load_pool_with_members(&db, &pool_id)
            .await
            .expect("load_pool_with_members failed")
            .expect("pool must exist after provision");
        assert_eq!(loaded_pool.members.len(), 1);
        assert_eq!(loaded_pool.members[0].hostname, format!("member-{sfx}"));

        // Verify request
        let (req_row,): (String,) = sqlx::query_as("SELECT status FROM lb_requests WHERE id = $1")
            .bind(&req_id)
            .fetch_one(&db)
            .await
            .expect("request must exist");
        assert_eq!(req_row, "provisioned");

        // Cleanup
        sqlx::query("DELETE FROM lb_virtual_servers WHERE id = $1")
            .bind(&vs_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM lb_requests WHERE id = $1")
            .bind(&req_id)
            .execute(&db)
            .await
            .ok();
        // members deleted by CASCADE when pool deleted
        sqlx::query("DELETE FROM lb_pools WHERE id = $1")
            .bind(&pool_id)
            .execute(&db)
            .await
            .ok();
    }

    #[tokio::test]
    async fn test_update_and_delete_virtual_server() {
        let Some(db) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let sfx = suffix();
        let site = format!("TESTSITE{}", sfx.to_ascii_uppercase());
        let pool_id = format!("pool-upd-{sfx}");
        let vs_id = format!("vs-upd-{sfx}");
        let req_id = format!("lbr-upd-{sfx}");

        let lb_pool = LbPool {
            id: pool_id.clone(),
            name: format!("upd-pool-{sfx}"),
            site: site.clone(),
            members: vec![PoolMember {
                hostname: format!("m-{sfx}"),
                ip: "10.99.2.1".into(),
                port: 8080,
                weight: 1,
                status: PoolMemberStatus::Up,
            }],
            algorithm: PoolAlgorithm::RoundRobin,
            health_monitor: None,
        };
        let vs = LbVirtualServer {
            id: vs_id.clone(),
            name: format!("upd-vs-{sfx}"),
            vip: format!("10.99.98.{}", u8::MAX),
            port: 80,
            protocol: LbProtocol::Http,
            pool_id: pool_id.clone(),
            site: site.clone(),
            ssl_profile: None,
            persistence_method: PersistenceMethod::None,
            status: VirtualServerStatus::Online,
        };
        let request = LbRequest {
            id: req_id.clone(),
            requester: "t".into(),
            virtual_server_name: vs.name.clone(),
            vip: vs.vip.clone(),
            port: 80,
            protocol: LbProtocol::Http,
            site: site.clone(),
            pool_members: vec![format!("m-{sfx}")],
            status: LbRequestStatus::Provisioned,
        };
        provision_lb(&db, &vs, &lb_pool, &request)
            .await
            .expect("provision");

        // UPDATE: http→https, 80→443, set ssl + cookie persistence.
        let updated = update_virtual_server(
            &db,
            &vs_id,
            Some(443),
            Some(&LbProtocol::Https),
            Some(&PersistenceMethod::Cookie),
            true,
            Some("std-tls"),
        )
        .await
        .expect("update")
        .expect("vs present");
        assert_eq!(updated.port, 443);
        assert_eq!(updated.protocol, LbProtocol::Https);
        assert_eq!(updated.persistence_method, PersistenceMethod::Cookie);
        assert_eq!(updated.ssl_profile.as_deref(), Some("std-tls"));

        // A partial update (only persistence) leaves the other fields intact —
        // proving COALESCE keeps omitted columns (no read-modify-write clobber).
        let partial = update_virtual_server(
            &db,
            &vs_id,
            None,
            None,
            Some(&PersistenceMethod::None),
            false,
            None,
        )
        .await
        .expect("partial update")
        .expect("vs present");
        assert_eq!(partial.port, 443, "port preserved");
        assert_eq!(partial.protocol, LbProtocol::Https, "protocol preserved");
        assert_eq!(
            partial.persistence_method,
            PersistenceMethod::None,
            "persistence changed"
        );
        assert_eq!(
            partial.ssl_profile.as_deref(),
            Some("std-tls"),
            "ssl preserved"
        );

        // DELETE removes the VS and orphan-cleans the (now unreferenced) pool.
        let mut tx = db.begin().await.expect("begin");
        let deleted = delete_virtual_server(&mut tx, &vs_id)
            .await
            .expect("delete");
        tx.commit().await.expect("commit");
        assert!(deleted);
        assert!(
            get_virtual_server(&db, &vs_id)
                .await
                .expect("get")
                .is_none(),
            "VS is gone"
        );
        let pool_gone: Option<(String,)> = sqlx::query_as("SELECT id FROM lb_pools WHERE id = $1")
            .bind(&pool_id)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(pool_gone.is_none(), "the orphaned pool was cleaned");
        // Deleting an absent VS returns false, not an error.
        let mut tx = db.begin().await.expect("begin");
        let deleted_absent = delete_virtual_server(&mut tx, &vs_id)
            .await
            .expect("delete-absent");
        tx.commit().await.expect("commit");
        assert!(!deleted_absent);

        sqlx::query("DELETE FROM lb_requests WHERE id = $1")
            .bind(&req_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query("DELETE FROM lb_pools WHERE id = $1")
            .bind(&pool_id)
            .execute(&db)
            .await
            .ok();
    }

    // Regression for the VIP TOCTOU HIGH: the UNIQUE(vip, site) index must reject
    // a second provision of the same vip+site (the concurrent loser), which the
    // handler maps to 409 instead of committing a duplicate VIP.
    #[tokio::test]
    async fn test_provision_duplicate_vip_site_unique_violation() {
        let Some(db) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let sfx = suffix();
        let site = format!("DUPSITE{}", sfx.to_ascii_uppercase());
        let vip = "10.77.77.77".to_string();

        let mk = |tag: &str| {
            let pool_id = format!("pool-dup-{tag}-{sfx}");
            let lb_pool = LbPool {
                id: pool_id.clone(),
                name: format!("dup-pool-{tag}-{sfx}"),
                site: site.clone(),
                members: Vec::new(),
                algorithm: PoolAlgorithm::RoundRobin,
                health_monitor: None,
            };
            let vs = LbVirtualServer {
                id: format!("vs-dup-{tag}-{sfx}"),
                name: format!("dup-vs-{tag}-{sfx}"),
                vip: vip.clone(),
                port: 443,
                protocol: LbProtocol::Https,
                pool_id: pool_id.clone(),
                site: site.clone(),
                ssl_profile: None,
                persistence_method: PersistenceMethod::None,
                status: VirtualServerStatus::Online,
            };
            let request = LbRequest {
                id: format!("lbr-dup-{tag}-{sfx}"),
                requester: "t".into(),
                virtual_server_name: vs.name.clone(),
                vip: vip.clone(),
                port: 443,
                protocol: LbProtocol::Https,
                site: site.clone(),
                pool_members: Vec::new(),
                status: LbRequestStatus::Provisioned,
            };
            (lb_pool, vs, request)
        };

        let (p1, v1, r1) = mk("a");
        provision_lb(&db, &v1, &p1, &r1)
            .await
            .expect("first provision should succeed");

        // Second VS: different ids, SAME (vip, site) -> unique violation.
        let (p2, v2, r2) = mk("b");
        let err = provision_lb(&db, &v2, &p2, &r2)
            .await
            .expect_err("duplicate (vip, site) must error");
        assert!(
            err.as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false),
            "expected a unique-violation on (vip, site), got {err:?}"
        );

        // Cleanup (the second provision rolled back; clean the first + any pool-b).
        for id in [&v1.id, &v2.id] {
            sqlx::query("DELETE FROM lb_virtual_servers WHERE id = $1")
                .bind(id)
                .execute(&db)
                .await
                .ok();
        }
        for id in [&r1.id, &r2.id] {
            sqlx::query("DELETE FROM lb_requests WHERE id = $1")
                .bind(id)
                .execute(&db)
                .await
                .ok();
        }
        for id in [&p1.id, &p2.id] {
            sqlx::query("DELETE FROM lb_pools WHERE id = $1")
                .bind(id)
                .execute(&db)
                .await
                .ok();
        }
    }

    #[tokio::test]
    async fn test_add_pool_member_and_duplicate_unique_violation() {
        let Some(db) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let sfx = suffix();
        let pool_id = format!("pool-addmem-{sfx}");

        // Insert a minimal pool first
        sqlx::query("INSERT INTO lb_pools (id, name, site, algorithm) VALUES ($1, $2, $3, $4)")
            .bind(&pool_id)
            .bind(format!("addmem-pool-{sfx}"))
            .bind("TESTAM")
            .bind("round-robin")
            .execute(&db)
            .await
            .expect("insert pool");

        let member = PoolMember {
            hostname: format!("mem-{sfx}"),
            ip: "10.1.2.3".into(),
            port: 8080,
            weight: 1,
            status: PoolMemberStatus::Up,
        };

        add_pool_member(&db, &pool_id, &member)
            .await
            .expect("first add_pool_member must succeed");

        // Duplicate insert → unique violation on (pool_id, hostname) PK
        let err = add_pool_member(&db, &pool_id, &member)
            .await
            .expect_err("duplicate add_pool_member must error");
        assert!(
            err.as_database_error()
                .and_then(|e| e.code())
                .map(|c| c == "23505")
                .unwrap_or(false),
            "duplicate member must produce a unique-violation (23505), got: {err}"
        );

        // Cleanup
        sqlx::query("DELETE FROM lb_pools WHERE id = $1")
            .bind(&pool_id)
            .execute(&db)
            .await
            .ok();
    }

    #[tokio::test]
    async fn test_remove_pool_member() {
        let Some(db) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let sfx = suffix();
        let pool_id = format!("pool-rmmem-{sfx}");

        sqlx::query("INSERT INTO lb_pools (id, name, site, algorithm) VALUES ($1, $2, $3, $4)")
            .bind(&pool_id)
            .bind(format!("rmmem-pool-{sfx}"))
            .bind("TESTRM")
            .bind("weighted")
            .execute(&db)
            .await
            .expect("insert pool");

        let member = PoolMember {
            hostname: format!("mem-rm-{sfx}"),
            ip: "10.2.3.4".into(),
            port: 9090,
            weight: 2,
            status: PoolMemberStatus::Down,
        };

        add_pool_member(&db, &pool_id, &member)
            .await
            .expect("add member");

        let removed = remove_pool_member(&db, &pool_id, &member.hostname)
            .await
            .expect("remove_pool_member failed");
        assert!(removed, "remove must return true for existing member");

        // Not found → false
        let not_found = remove_pool_member(&db, &pool_id, &member.hostname)
            .await
            .expect("remove absent member must not error");
        assert!(!not_found, "absent member must return false");

        // Cleanup
        sqlx::query("DELETE FROM lb_pools WHERE id = $1")
            .bind(&pool_id)
            .execute(&db)
            .await
            .ok();
    }

    #[tokio::test]
    async fn test_drain_disable_enable_vs_status() {
        let Some(db) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // vs-defra-web starts 'online' per seed
        let drained = update_vs_status(&db, "vs-defra-web", &VirtualServerStatus::Draining)
            .await
            .expect("drain failed")
            .expect("vs-defra-web must exist");
        assert_eq!(drained.status, VirtualServerStatus::Draining);

        let disabled = update_vs_status(&db, "vs-defra-web", &VirtualServerStatus::Offline)
            .await
            .expect("disable failed")
            .expect("vs-defra-web must exist");
        assert_eq!(disabled.status, VirtualServerStatus::Offline);

        let enabled = update_vs_status(&db, "vs-defra-web", &VirtualServerStatus::Online)
            .await
            .expect("enable failed")
            .expect("vs-defra-web must exist");
        assert_eq!(enabled.status, VirtualServerStatus::Online);

        // Absent VS → None
        let absent = update_vs_status(&db, "vs-nonexistent", &VirtualServerStatus::Online)
            .await
            .expect("update absent vs must not error");
        assert!(absent.is_none(), "absent VS must return None");
    }

    #[tokio::test]
    async fn test_pool_member_status_and_enum_roundtrip() {
        let Some(db) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // gblon-api members: one 'up', one 'down'
        let (vs, pool) = get_virtual_server_with_pool(&db, "vs-gblon-api")
            .await
            .expect("get_virtual_server_with_pool failed")
            .expect("vs-gblon-api must exist");
        assert_eq!(vs.protocol, LbProtocol::Https);
        assert!(pool
            .members
            .iter()
            .any(|m| m.status == PoolMemberStatus::Up));
        assert!(pool
            .members
            .iter()
            .any(|m| m.status == PoolMemberStatus::Down));

        // frpar member status: disabled
        let (_, frpar_pool) = get_virtual_server_with_pool(&db, "vs-frpar-tcp")
            .await
            .expect("get_virtual_server_with_pool failed")
            .expect("vs-frpar-tcp must exist");
        assert!(frpar_pool
            .members
            .iter()
            .any(|m| m.status == PoolMemberStatus::Disabled));

        // Enum round-trip: verify that 'least-connections' decodes to LeastConnections
        assert_eq!(frpar_pool.algorithm, PoolAlgorithm::LeastConnections);
        // Verify 'draining' VS status decodes
        let draining_vs = get_virtual_server(&db, "vs-defra-admin")
            .await
            .expect("get_virtual_server failed")
            .expect("vs-defra-admin must exist");
        assert_eq!(draining_vs.status, VirtualServerStatus::Draining);
        assert_eq!(draining_vs.persistence_method, PersistenceMethod::SourceIp);
    }
}
