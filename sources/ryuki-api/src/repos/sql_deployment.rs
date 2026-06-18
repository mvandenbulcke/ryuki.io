//! Repository functions for `sql_deployments` and `sql_deployment_operations`
//! (migration 043_sql_deployments.sql).
//!
//! # UUID discipline
//! `sql_deployments.id` is a UUID PK. SELECT casts: `id::text AS id`.
//! On bind: `Uuid::parse_str(id)` — malformed id → `Ok(None)` (caller → 404).
//!
//! # Enum encoding
//! - `status` stored as kebab-case text matching `DeploymentStatus` serde form
//!   ("draft", "backed-up", …). `serde_json::from_value` works directly.
//! - `edition` stored as PascalCase ("Standard", "Enterprise", "Developer").
//!   `SQLEdition` uses `rename_all = "PascalCase"` — serde decode works directly.
//! - `sql_version` stored as '2019' / '2022'. `SQLVersion` uses
//!   `rename_all = "kebab-case"` → "sql-2019" — MISMATCH.
//!   Use `sql_version_from_db` helper; write via `Display` ("2019" / "2022").
//! - `cluster_mode` stored as 'Standalone' / 'FCI' / 'AG'. `ClusterMode` uses
//!   `rename_all = "UPPERCASE"` → "STANDALONE" — MISMATCH for Standalone.
//!   Use `cluster_mode_from_db` helper; write via `Display` ("Standalone" / …).
//!
//! # Timestamps
//! All TIMESTAMPTZ columns decoded as `DateTime<Utc>`, converted to RFC 3339
//! strings in `into_model`. NEVER `::text` on a timestamp column.
//!
//! # Integer columns
//! cpu / memory_gb / disk columns are INTEGER in the DB (i32 in sqlx).
//! `into_model` decodes via `u32::try_from(i32_val)` — negative values are a
//! DB corruption signal and produce a Decode error (never silently wrap).
//! On INSERT, engine u32 values are converted via `i32::try_from` before bind;
//! values that exceed i32::MAX return a Decode error (body-supplied, rejected
//! at handler level before reaching here, but guarded defensively).
//!
//! # JSONB
//! `sql_deployment_operations.payload` and `.result` are JSONB, decoded as
//! `serde_json::Value` by sqlx. Nullable columns are `Option<serde_json::Value>`.
//!
//! # CAS design
//! Lifecycle mutations load the deployment, run the engine guard (pure), then
//! perform a status-CAS: `UPDATE … WHERE id = $1 AND status = $2 RETURNING id`.
//! An operations audit row is inserted in the SAME transaction.
//! Zero rows affected → `Ok(None)` (caller → 409).

use chrono::{DateTime, Utc};
use ryuki_engine::sql_deployment::{
    ClusterMode, DeploymentStatus, SQLDeployment, SQLEdition, SQLVersion,
};
use sqlx::PgPool;
use uuid::Uuid;

// ─── DB ↔ enum helpers ────────────────────────────────────────────────────────

/// Decode a `sql_version` DB string ('2019' / '2022') to the engine enum.
/// `SQLVersion` serde uses kebab-case so direct serde decode would fail.
fn sql_version_from_db(raw: &str) -> Result<SQLVersion, sqlx::Error> {
    match raw {
        "2019" => Ok(SQLVersion::Sql2019),
        "2022" => Ok(SQLVersion::Sql2022),
        other => Err(sqlx::Error::Decode(
            format!("sql_deployments.sql_version: unknown value '{other}'").into(),
        )),
    }
}

/// Decode a `cluster_mode` DB string ('Standalone' / 'FCI' / 'AG') to the engine enum.
/// `ClusterMode` serde uses UPPERCASE so 'Standalone' → decode failure without this helper.
fn cluster_mode_from_db(raw: &str) -> Result<ClusterMode, sqlx::Error> {
    match raw {
        "Standalone" => Ok(ClusterMode::Standalone),
        "FCI" => Ok(ClusterMode::FCI),
        "AG" => Ok(ClusterMode::AG),
        other => Err(sqlx::Error::Decode(
            format!("sql_deployments.cluster_mode: unknown value '{other}'").into(),
        )),
    }
}

/// Decode a `edition` DB string ('Standard' / 'Enterprise' / 'Developer') to the engine enum.
/// `SQLEdition` serde uses PascalCase which matches — this helper centralises the Decode error.
fn edition_from_db(raw: &str) -> Result<SQLEdition, sqlx::Error> {
    serde_json::from_value(serde_json::Value::String(raw.to_string())).map_err(|e| {
        sqlx::Error::Decode(format!("sql_deployments.edition: unknown value '{raw}': {e}").into())
    })
}

/// Decode a `status` DB string (kebab-case) to the engine enum.
/// `DeploymentStatus` serde uses kebab-case — serde decode works directly.
fn status_from_db(raw: &str) -> Result<DeploymentStatus, sqlx::Error> {
    serde_json::from_value(serde_json::Value::String(raw.to_string())).map_err(|e| {
        sqlx::Error::Decode(format!("sql_deployments.status: unknown value '{raw}': {e}").into())
    })
}

// ─── Column list ──────────────────────────────────────────────────────────────

pub const COLUMNS: &str = "id::text AS id, \
     instance_name, \
     sql_version, \
     edition, \
     cpu, \
     memory_gb, \
     data_disk_gb, \
     log_disk_gb, \
     tempdb_disk_gb, \
     collation_name, \
     service_account, \
     site, \
     cluster_mode, \
     status, \
     created_at, \
     updated_at";

// ─── Row struct ───────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct SQLDeploymentRow {
    pub id: String,
    pub instance_name: String,
    pub sql_version: String,
    pub edition: String,
    pub cpu: i32,
    pub memory_gb: i32,
    pub data_disk_gb: i32,
    pub log_disk_gb: i32,
    pub tempdb_disk_gb: i32,
    pub collation_name: String,
    pub service_account: String,
    pub site: String,
    pub cluster_mode: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SQLDeploymentRow {
    pub fn into_model(self) -> Result<SQLDeployment, sqlx::Error> {
        let sql_version = sql_version_from_db(&self.sql_version)?;
        let edition = edition_from_db(&self.edition)?;
        let cluster_mode = cluster_mode_from_db(&self.cluster_mode)?;
        let status = status_from_db(&self.status)?;

        let cpu = u32::try_from(self.cpu).map_err(|e| {
            sqlx::Error::Decode(format!("sql_deployments.cpu out of range: {e}").into())
        })?;
        let memory_gb = u32::try_from(self.memory_gb).map_err(|e| {
            sqlx::Error::Decode(format!("sql_deployments.memory_gb out of range: {e}").into())
        })?;
        let data_disk_gb = u32::try_from(self.data_disk_gb).map_err(|e| {
            sqlx::Error::Decode(format!("sql_deployments.data_disk_gb out of range: {e}").into())
        })?;
        let log_disk_gb = u32::try_from(self.log_disk_gb).map_err(|e| {
            sqlx::Error::Decode(format!("sql_deployments.log_disk_gb out of range: {e}").into())
        })?;
        let tempdb_disk_gb = u32::try_from(self.tempdb_disk_gb).map_err(|e| {
            sqlx::Error::Decode(format!("sql_deployments.tempdb_disk_gb out of range: {e}").into())
        })?;

        Ok(SQLDeployment {
            id: self.id,
            instance_name: self.instance_name,
            sql_version,
            edition,
            cpu,
            memory_gb,
            data_disk_gb,
            log_disk_gb,
            tempdb_disk_gb,
            collation_name: self.collation_name,
            service_account: self.service_account,
            site: self.site,
            cluster_mode,
            status,
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
        })
    }
}

// ─── i32 bind helpers ─────────────────────────────────────────────────────────

fn to_i32(val: u32, field: &str) -> Result<i32, sqlx::Error> {
    i32::try_from(val).map_err(|e| {
        sqlx::Error::Decode(
            format!("sql_deployments.{field}: value {val} out of i32 range: {e}").into(),
        )
    })
}

// ─── Read functions ───────────────────────────────────────────────────────────

/// Get a single deployment by UUID string id. Malformed id → Ok(None).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<SQLDeployment>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<SQLDeploymentRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM sql_deployments WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// List deployments by site. If site is empty, returns all deployments.
pub async fn list_by_site(pool: &PgPool, site: &str) -> Result<Vec<SQLDeployment>, sqlx::Error> {
    let rows: Vec<SQLDeploymentRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM sql_deployments ORDER BY created_at DESC"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM sql_deployments WHERE site = $1 ORDER BY created_at DESC"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── Write functions ──────────────────────────────────────────────────────────

/// Insert a new deployment + a 'plan' operations row in a single transaction.
/// Returns the persisted deployment (re-read through the column query).
pub async fn insert(
    pool: &PgPool,
    deployment: &SQLDeployment,
    payload: serde_json::Value,
) -> Result<SQLDeployment, sqlx::Error> {
    let id = Uuid::new_v4();

    let cpu = to_i32(deployment.cpu, "cpu")?;
    let memory_gb = to_i32(deployment.memory_gb, "memory_gb")?;
    let data_disk_gb = to_i32(deployment.data_disk_gb, "data_disk_gb")?;
    let log_disk_gb = to_i32(deployment.log_disk_gb, "log_disk_gb")?;
    let tempdb_disk_gb = to_i32(deployment.tempdb_disk_gb, "tempdb_disk_gb")?;

    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT INTO sql_deployments \
         (id, instance_name, sql_version, edition, cpu, memory_gb, \
          data_disk_gb, log_disk_gb, tempdb_disk_gb, collation_name, \
          service_account, site, cluster_mode, status, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())",
    )
    .bind(id)
    .bind(&deployment.instance_name)
    .bind(deployment.sql_version.to_string())
    .bind(deployment.edition.to_string())
    .bind(cpu)
    .bind(memory_gb)
    .bind(data_disk_gb)
    .bind(log_disk_gb)
    .bind(tempdb_disk_gb)
    .bind(&deployment.collation_name)
    .bind(&deployment.service_account)
    .bind(&deployment.site)
    .bind(deployment.cluster_mode.to_string())
    .bind(deployment.status.to_string())
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO sql_deployment_operations \
         (deployment_id, operation_type, status, payload, result, started_at, completed_at) \
         VALUES ($1, 'plan', 'completed', $2, NULL, NOW(), NOW())",
    )
    .bind(id)
    .bind(&payload)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    get(pool, &id.to_string()).await?.ok_or_else(|| {
        sqlx::Error::Decode("sql_deployments: row vanished immediately after insert".into())
    })
}

/// CAS: advance the deployment status from `expected_status` to `new_status`
/// AND insert an operations audit row — all in one transaction.
///
/// Returns `Ok(None)` when the CAS misses (status changed concurrently → 409).
pub async fn transition(
    pool: &PgPool,
    id: &str,
    operation_type: &str,
    expected_status: &str,
    new_status: &str,
    payload: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
) -> Result<Option<SQLDeployment>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let mut tx = pool.begin().await?;

    let affected = sqlx::query(
        "UPDATE sql_deployments \
         SET status = $1, updated_at = NOW() \
         WHERE id = $2 AND status = $3",
    )
    .bind(new_status)
    .bind(uid)
    .bind(expected_status)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if affected == 0 {
        tx.rollback().await?;
        return Ok(None);
    }

    sqlx::query(
        "INSERT INTO sql_deployment_operations \
         (deployment_id, operation_type, status, payload, result, started_at, completed_at) \
         VALUES ($1, $2, 'completed', $3, $4, NOW(), NOW())",
    )
    .bind(uid)
    .bind(operation_type)
    .bind(&payload)
    .bind(&result)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    get(pool, id).await
}

// ─── DB integration tests ─────────────────────────────────────────────────────
//
// Run with:
//   cargo test -p ryuki-api --bins sql_deployment_db_tests -- --test-threads=1
//
// Tests SKIP when the DB connection cannot be established.
#[cfg(test)]
mod sql_deployment_db_tests {
    use super::*;
    use ryuki_engine::sql_deployment::{guard_configure, guard_install, plan_deployment};
    use serde_json::json;

    static DB_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform".to_string()
        });
        if url.is_empty() {
            return None;
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .ok()?;
        crate::database::run_migrations(&pool).await.ok()?;
        Some(pool)
    }

    async fn cleanup_deployment(pool: &PgPool, id: &str) {
        if let Ok(uid) = Uuid::parse_str(id) {
            sqlx::query("DELETE FROM sql_deployments WHERE id = $1")
                .bind(uid)
                .execute(pool)
                .await
                .ok();
        }
    }

    fn make_plan_req(instance_name: &str, site: &str, cluster: &str) -> serde_json::Value {
        json!({
            "instance_name": instance_name,
            "sql_version": "2022",
            "edition": "Enterprise",
            "cpu": 8,
            "memory_gb": 64,
            "data_disk_gb": 500,
            "log_disk_gb": 200,
            "tempdb_disk_gb": 100,
            "collation": "Latin1_General_CI_AS",
            "service_account": "svc-sql-test@ryuki.local",
            "site": site,
            "cluster_mode": cluster
        })
    }

    // ── get_inventory returns seeded rows ──

    #[tokio::test]
    async fn get_inventory_returns_seeded_rows() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB not available");
            return;
        };

        // Migration 043 seeds 2 deployments: DEFRA (AG) and GBLON (Standalone)
        let all = list_by_site(&pool, "").await.expect("list all");
        assert!(all.len() >= 2, "migration 043 seeds 2 deployments");

        let defra = list_by_site(&pool, "DEFRA").await.expect("list DEFRA");
        assert!(!defra.is_empty());
        for d in &defra {
            assert_eq!(d.site, "DEFRA");
        }

        let gblon = list_by_site(&pool, "GBLON").await.expect("list GBLON");
        assert!(!gblon.is_empty());
        for d in &gblon {
            assert_eq!(d.site, "GBLON");
        }
    }

    // ── plan creates a deployment + operations row ──

    #[tokio::test]
    async fn plan_creates_deployment_and_operations_row() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB not available");
            return;
        };

        let req = make_plan_req("NLAMS-SQL-TEST-01", "NLAMS", "AG");
        let (deployment, plan_json) = plan_deployment(req).expect("engine plan");
        let inserted = insert(&pool, &deployment, plan_json).await.expect("insert");

        assert!(!inserted.id.is_empty());
        assert_eq!(inserted.instance_name, "NLAMS-SQL-TEST-01");
        assert_eq!(inserted.site, "NLAMS");
        assert_eq!(inserted.status, DeploymentStatus::Planned);
        assert_eq!(inserted.sql_version, SQLVersion::Sql2022);
        assert_eq!(inserted.cluster_mode, ClusterMode::AG);
        assert_eq!(inserted.cpu, 8);
        assert_eq!(inserted.memory_gb, 64);

        // Verify operations row exists
        let uid = Uuid::parse_str(&inserted.id).unwrap();
        let (op_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sql_deployment_operations WHERE deployment_id = $1 AND operation_type = 'plan'",
        )
        .bind(uid)
        .fetch_one(&pool)
        .await
        .expect("count ops");
        assert_eq!(op_count, 1, "one plan operations row");

        cleanup_deployment(&pool, &inserted.id).await;
    }

    // ── a duplicate (site, instance_name) surfaces a unique violation ──
    // The sql_deploy_plan handler maps this to 409 (not the blanket 500), so the
    // repo must propagate a database unique-violation error here.
    #[tokio::test]
    async fn duplicate_site_instance_surfaces_unique_violation() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB not available");
            return;
        };

        let (dep, plan) = plan_deployment(make_plan_req("ZZTEST-SQL-DUP", "DEDUS", "Standalone"))
            .expect("engine plan");
        let first = insert(&pool, &dep, plan).await.expect("first insert");

        let (dep2, plan2) = plan_deployment(make_plan_req("ZZTEST-SQL-DUP", "DEDUS", "Standalone"))
            .expect("engine plan 2");
        let err = insert(&pool, &dep2, plan2)
            .await
            .expect_err("duplicate (site, instance_name) must error");
        assert!(
            err.as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false),
            "expected a unique-violation error, got {err:?}"
        );

        cleanup_deployment(&pool, &first.id).await;
    }

    // ── lifecycle transition advances status AND inserts operations row ──

    #[tokio::test]
    async fn lifecycle_transition_advances_status_and_inserts_ops_row() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB not available");
            return;
        };

        let req = make_plan_req("FRPAR-SQL-TEST-01", "FRPAR", "Standalone");
        let (deployment, plan_json) = plan_deployment(req).expect("engine plan");
        let inserted = insert(&pool, &deployment, plan_json).await.expect("insert");

        // planned → installing (validate guard first)
        let loaded = get(&pool, &inserted.id)
            .await
            .expect("get")
            .expect("exists");
        guard_install(&loaded).expect("guard_install should pass for Planned");

        let installing = transition(
            &pool,
            &inserted.id,
            "install",
            "planned",
            "installing",
            None,
            Some(json!({ "action": "mock-install" })),
        )
        .await
        .expect("transition")
        .expect("transition succeeded");

        assert_eq!(installing.status, DeploymentStatus::Installing);

        // Verify operations row
        let uid = Uuid::parse_str(&inserted.id).unwrap();
        let (op_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sql_deployment_operations WHERE deployment_id = $1 AND operation_type = 'install'",
        )
        .bind(uid)
        .fetch_one(&pool)
        .await
        .expect("count install ops");
        assert_eq!(op_count, 1, "one install operations row");

        // installing → configuring
        let loaded2 = get(&pool, &inserted.id)
            .await
            .expect("get")
            .expect("exists");
        guard_configure(&loaded2).expect("guard_configure should pass for Installing");

        let configuring = transition(
            &pool,
            &inserted.id,
            "configure",
            "installing",
            "configuring",
            None,
            Some(json!({ "action": "mock-configure" })),
        )
        .await
        .expect("transition")
        .expect("configuring succeeded");

        assert_eq!(configuring.status, DeploymentStatus::Configuring);

        cleanup_deployment(&pool, &inserted.id).await;
    }

    // ── illegal transition / CAS miss → rejected ──

    #[tokio::test]
    async fn illegal_transition_and_cas_miss_rejected() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB not available");
            return;
        };

        let req = make_plan_req("DEBER-SQL-TEST-01", "DEBER", "Standalone");
        let (deployment, plan_json) = plan_deployment(req).expect("engine plan");
        let inserted = insert(&pool, &deployment, plan_json).await.expect("insert");

        // Engine guard: planned deployment cannot be configured (must be Installing)
        let loaded = get(&pool, &inserted.id)
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(loaded.status, DeploymentStatus::Planned);
        let guard_err = guard_configure(&loaded);
        assert!(
            guard_err.is_err(),
            "configure guard must reject Planned status"
        );

        // Repo CAS miss: wrong expected_status (installing when actual is planned)
        let miss = transition(
            &pool,
            &inserted.id,
            "configure",
            "installing", // wrong — deployment is planned
            "configuring",
            None,
            None,
        )
        .await
        .expect("no DB error");
        assert!(
            miss.is_none(),
            "CAS miss when expected_status does not match → Ok(None)"
        );

        // Malformed UUID → Ok(None), not error
        let malformed = get(&pool, "not-a-uuid").await.expect("get malformed");
        assert!(malformed.is_none());

        cleanup_deployment(&pool, &inserted.id).await;
    }

    // ── cluster_mode round-trip: DB 'Standalone' decodes correctly ──

    #[tokio::test]
    async fn cluster_mode_standalone_round_trip() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: DB not available");
            return;
        };

        let req = make_plan_req("GBLON-SQL-ROUNDTRIP", "GBLON", "Standalone");
        let (deployment, plan_json) = plan_deployment(req).expect("engine plan");
        let inserted = insert(&pool, &deployment, plan_json).await.expect("insert");

        // Round-trip: the DB stores 'Standalone'; the cluster_mode_from_db helper
        // must decode it to ClusterMode::Standalone (not fail due to UPPERCASE serde mismatch).
        let loaded = get(&pool, &inserted.id)
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(
            loaded.cluster_mode,
            ClusterMode::Standalone,
            "DB 'Standalone' must decode to ClusterMode::Standalone via cluster_mode_from_db"
        );

        // Also verify against the seeded GBLON row (which also has Standalone)
        let gblon_rows = list_by_site(&pool, "GBLON").await.expect("list GBLON");
        assert!(
            gblon_rows
                .iter()
                .any(|d| d.cluster_mode == ClusterMode::Standalone),
            "seeded GBLON row must also decode cluster_mode=Standalone"
        );

        cleanup_deployment(&pool, &inserted.id).await;
    }
}
