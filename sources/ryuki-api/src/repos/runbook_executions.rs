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
    "id, status, execution_json::text AS execution_json, xmin::text AS row_version";

// ─── Row struct ──────────────────────────────────────────────────────────────

/// Minimal row struct — the full entity lives in `execution_json`; the `status`
/// column is selected separately, and `row_version` carries the row's `xmin` so
/// `transition` can apply a content-agnostic optimistic lock.
#[derive(sqlx::FromRow)]
pub struct RunbookExecutionRow {
    pub id: String,
    pub status: String,
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
/// already-generated text id (e.g. "rbx-defra-abc1234").
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    exec: &RunbookExecution,
) -> Result<(), sqlx::Error> {
    ryuki_engine::runbook_execution::validate_execution_invariants(exec).map_err(|error| {
        sqlx::Error::Protocol(format!("runbook execution invariant violation: {error}"))
    })?;
    let execution_json = serde_json::to_value(exec).map_err(|e| {
        sqlx::Error::Decode(format!("runbook_executions: serialize failed: {e}").into())
    })?;

    sqlx::query(
        "INSERT INTO runbook_executions \
         (id, runbook_id, status, site, started_by, execution_json, \
          invariant_state, invariant_reason) \
         VALUES ($1, $2, $3, $4, $5, $6, 'Verified', NULL)",
    )
    .bind(&exec.id)
    .bind(&exec.runbook_id)
    .bind(status_str(&exec.status))
    .bind(&exec.site)
    .bind(&exec.started_by)
    .bind(execution_json)
    .execute(executor)
    .await?;

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
/// the row is absent or was modified concurrently (caller → 409), `Ok(true)` on
/// success.
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

    let res = sqlx::query(
        "UPDATE runbook_executions SET \
         status = $2, \
         execution_json = $3, \
         updated_at = NOW() \
         WHERE id = $1 AND xmin = $4::xid AND invariant_state = 'Verified'",
    )
    .bind(id)
    .bind(status_str(&updated.status))
    .bind(execution_json)
    .bind(expected_version)
    .execute(&mut *executor)
    .await?;

    if res.rows_affected() == 0 {
        return Ok(false);
    }

    Ok(true)
}
