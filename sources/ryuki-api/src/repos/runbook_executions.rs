//! Repository functions for `runbook_executions`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! The full `RunbookExecution` is round-tripped through the `execution_json`
//! JSONB column so later calls can reconstruct the entity faithfully. The
//! scalar columns (`runbook_id`, `status`, `site`, `started_by`) are kept in
//! sync for queryability but are not used during reconstruction.

use ryuki_engine::runbook_execution::{ExecutionStatus, RunbookExecution};
use sqlx::PgPool;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. JSONB → text so we can `serde_json::from_str` the full
/// entity. `id` is already TEXT (not UUID), so no cast is needed. `xmin` is the
/// row's system version (the xid that last wrote it) — selected as text so the
/// caller can carry it as an optimistic-lock token (see `transition`).
pub const COLUMNS: &str =
    "id, status, site_authority_epoch, execution_json::text AS execution_json, \
     xmin::text AS row_version";

// ─── Row struct ──────────────────────────────────────────────────────────────

/// Minimal row struct — the full entity lives in `execution_json`; the `status`
/// column is selected separately, and `row_version` carries the row's `xmin` so
/// `transition` can apply a content-agnostic optimistic lock.
#[derive(sqlx::FromRow)]
pub struct RunbookExecutionRow {
    pub id: String,
    pub status: String,
    /// Exact site-registry generation captured when the execution was created.
    /// NULL identifies quarantined pre-epoch history.
    pub site_authority_epoch: Option<i64>,
    /// Raw JSON text from JSONB::text cast — the full `RunbookExecution`.
    pub execution_json: Option<String>,
    /// `xmin::text` — the row version at read time (optimistic-lock token).
    pub row_version: String,
}

impl RunbookExecutionRow {
    /// Convert a DB row into the engine model by deserialising `execution_json`.
    ///
    /// The `status` column is authoritative on read and is patched into the
    /// entity after deserialisation (it may have been updated by `transition`).
    pub fn into_model(self) -> Result<RunbookExecution, sqlx::Error> {
        let raw = self
            .execution_json
            .ok_or_else(|| sqlx::Error::Decode("runbook_executions.execution_json: NULL".into()))?;

        let mut entity: RunbookExecution = serde_json::from_str(&raw).map_err(|e| {
            sqlx::Error::Decode(
                format!("runbook_executions.execution_json: corrupt persisted value: {e}").into(),
            )
        })?;

        // Override the embedded status with the authoritative DB column value
        // (it may have been updated by `transition` after the initial insert).
        entity.status = decode_status(&self.status)
            .map_err(|e| sqlx::Error::Decode(format!("runbook_executions.status: {e}").into()))?;

        // Override the id with the DB-authoritative value.
        entity.id = self.id;
        // The scalar binding is authoritative even if a legacy/corrupt JSON
        // projection omitted it. The database trigger keeps new Verified rows
        // byte-for-value equivalent at write time.
        entity.site_authority_epoch = self.site_authority_epoch;

        Ok(entity)
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for an `ExecutionStatus` as stored in the DB.
/// These match the `#[serde(rename_all = "kebab-case")]` derivation.
pub fn status_str(s: &ExecutionStatus) -> &'static str {
    match s {
        ExecutionStatus::Draft => "draft",
        ExecutionStatus::Approved => "approved",
        ExecutionStatus::Running => "running",
        ExecutionStatus::Completed => "completed",
        ExecutionStatus::Failed => "failed",
        ExecutionStatus::RolledBack => "rolled-back",
    }
}

fn decode_status(s: &str) -> Result<ExecutionStatus, String> {
    // The status is stored as a kebab-case string (e.g. "draft", "rolled-back").
    // Wrap in quotes for serde_json to deserialise as a unit-variant string.
    serde_json::from_str(&format!("\"{s}\"")).map_err(|e| format!("unknown status '{s}': {e}"))
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a new runbook execution. The caller supplies the model with an
/// already-generated text id (e.g. "rbx-defra-abc1234"). The statement locks
/// the exact current active-site authority; unknown or inactive sites fail
/// without inserting a row.
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    exec: &mut RunbookExecution,
) -> Result<(), sqlx::Error> {
    ryuki_engine::runbook_execution::validate_execution_invariants(exec).map_err(|error| {
        sqlx::Error::Protocol(format!("runbook execution invariant violation: {error}"))
    })?;
    let execution_json = serde_json::to_value(&*exec).map_err(|e| {
        sqlx::Error::Decode(format!("runbook_executions: serialize failed: {e}").into())
    })?;

    let bound_epoch: Option<i64> = sqlx::query_scalar(
        "WITH active_site AS ( \
             SELECT unlocode, authority_epoch FROM site_registry \
             WHERE unlocode COLLATE \"C\" = $4::text COLLATE \"C\" AND active = TRUE \
             FOR SHARE \
         ) \
         INSERT INTO runbook_executions \
         (id, runbook_id, status, site, started_by, execution_json, \
          invariant_state, invariant_reason, site_authority_epoch) \
         SELECT $1, $2, $3, active_site.unlocode, $5, \
                jsonb_set( \
                    $6, \
                    '{site_authority_epoch}', \
                    to_jsonb(active_site.authority_epoch), \
                    TRUE \
                ), \
                'Verified', NULL, active_site.authority_epoch \
         FROM active_site \
         RETURNING site_authority_epoch",
    )
    .bind(&exec.id)
    .bind(&exec.runbook_id)
    .bind(status_str(&exec.status))
    .bind(&exec.site)
    .bind(&exec.started_by)
    .bind(execution_json)
    .fetch_optional(executor)
    .await?;

    let Some(bound_epoch) = bound_epoch else {
        return Err(sqlx::Error::Protocol(
            "runbook execution requires a current active canonical site".into(),
        ));
    };
    // Creation authority is server-derived. Ignore any pre-binding carried by
    // the caller and return the exact value that the INSERT persisted.
    exec.site_authority_epoch = Some(bound_epoch);

    Ok(())
}

/// Fetch one runbook execution by text id, with its row-version token. A missing
/// id returns `Ok(None)`; callers map that to 404. The returned `String` is the
/// `xmin` token to pass back to `transition` for an optimistic-lock CAS.
pub async fn get(
    pool: &PgPool,
    id: &str,
) -> Result<Option<(RunbookExecution, String)>, sqlx::Error> {
    let row: Option<RunbookExecutionRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM runbook_executions WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => {
            let version = r.row_version.clone();
            Ok(Some((r.into_model()?, version)))
        }
        None => Ok(None),
    }
}

/// Return runbook executions for a given site, newest first, capped at `limit`
/// rows. The `limit` is a defense-in-depth bound (callers pass the shared
/// `MAX_LIST_ROWS`) so a site with a large execution history never returns an
/// unbounded result set — mirroring `runbook_active`'s `LIMIT MAX_LIST_ROWS`.
pub async fn list(
    pool: &PgPool,
    site: &str,
    limit: i64,
) -> Result<Vec<RunbookExecution>, sqlx::Error> {
    let rows: Vec<RunbookExecutionRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM runbook_executions WHERE site = $1 \
         ORDER BY created_at DESC, id DESC LIMIT $2"
    ))
    .bind(site)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Atomically transition a runbook execution to its new state IFF the row has
/// NOT been written since it was read — guarded on the `xmin` row version
/// (`expected_version`, the token returned by `get`). Returns `Ok(false)` when
/// the row is absent, was modified concurrently, or a forward transition's
/// exact captured site authority epoch is no longer active (caller → 409), and
/// `Ok(true)` on success. The active-site row is held `FOR SHARE` until the
/// caller-owned transaction ends, so a concurrent deactivation or rename
/// cannot race an admitted transition.
/// Protective terminalization to Failed or RolledBack remains available after
/// deactivation so operators can stop or unwind work safely.
///
/// Guarding on `xmin` rather than the `status` value is deliberate: some
/// transitions (e.g. step execution) keep the SAME status while mutating
/// `execution_json`, so a status-only CAS would let two concurrent step writes
/// both "succeed" and the later one silently clobber the earlier. The row
/// version changes on EVERY write, so it catches same-status races too.
///
/// Both `status` (scalar column for queryability) and `execution_json` (full
/// entity snapshot) are updated atomically within a transaction.
pub async fn transition(
    executor: &mut sqlx::PgConnection,
    id: &str,
    expected_version: &str,
    updated: &RunbookExecution,
) -> Result<bool, sqlx::Error> {
    ryuki_engine::runbook_execution::validate_execution_invariants(updated).map_err(|error| {
        sqlx::Error::Protocol(format!("runbook execution invariant violation: {error}"))
    })?;
    let execution_json = serde_json::to_value(updated).map_err(|e| {
        sqlx::Error::Decode(format!("runbook_executions: serialize failed: {e}").into())
    })?;
    let Some(site_authority_epoch) = updated.site_authority_epoch else {
        return Ok(false);
    };
    if site_authority_epoch <= 0 {
        return Ok(false);
    }

    let res = sqlx::query(
        "WITH active_site AS ( \
             SELECT unlocode, authority_epoch FROM site_registry \
             WHERE unlocode COLLATE \"C\" = $5::text COLLATE \"C\" \
               AND active = TRUE \
               AND authority_epoch = $6 \
             FOR SHARE \
         ) \
         UPDATE runbook_executions AS execution SET \
         status = $2, \
         execution_json = $3, \
         updated_at = NOW() \
         WHERE execution.id = $1 \
           AND execution.xmin = $4::xid \
           AND execution.invariant_state = 'Verified' \
           AND execution.site COLLATE \"C\" = $5::text COLLATE \"C\" \
           AND execution.site_authority_epoch = $6 \
           AND ( \
               $2 IN ('failed', 'rolled-back') \
               OR EXISTS ( \
                   SELECT 1 FROM active_site \
                   WHERE active_site.unlocode COLLATE \"C\" = execution.site COLLATE \"C\" \
               ) \
           )",
    )
    .bind(id)
    .bind(status_str(&updated.status))
    .bind(execution_json)
    .bind(expected_version)
    .bind(&updated.site)
    .bind(site_authority_epoch)
    .execute(&mut *executor)
    .await?;

    if res.rows_affected() == 0 {
        return Ok(false);
    }

    Ok(true)
}
