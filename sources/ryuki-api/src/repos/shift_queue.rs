//! Repository functions for `shift_queue`.
//!
//! The shift queue is the operations work-item surface (migration 029). Until
//! #52 every INSERT into it lived inline in tests/seeds; this is the first
//! reusable writer, kept minimal and scoped to the restore-test producers
//! (`restore-test-overdue`, `restore-test-failed`).
//!
//! # Dedup (no natural key)
//! `shift_queue` has only a PK on `id`. To enqueue at-most-one OPEN item per
//! system+type, [`enqueue_if_absent`] is an atomic single-statement
//! `INSERT … SELECT … WHERE NOT EXISTS … ON CONFLICT DO NOTHING`. The `WHERE NOT
//! EXISTS` skips the insert in the common already-queued case; the untargeted
//! `ON CONFLICT DO NOTHING` is the belt-and-suspenders that makes a racing
//! insert hit the matching partial unique index
//! (`uq_shift_queue_open_restore_overdue` in migration 122,
//! `uq_shift_queue_open_restore_failed` in migration 123) and be silently
//! dropped instead of aborting the caller's transaction. Under the
//! single-leader scheduler tick the race is already impossible; the ON CONFLICT
//! just makes it structurally safe.

use sqlx::{PgExecutor, PgPool};

/// The overdue/never-tested restore signal (#52 slice 1). Fixed so the dedup key
/// and the partial unique index always agree.
pub const RESTORE_OVERDUE_ITEM_TYPE: &str = "restore-test-overdue";

/// The FAILED-latest restore signal (#52 slice 2). Fixed so the dedup key and the
/// partial unique index always agree.
pub const RESTORE_FAILED_ITEM_TYPE: &str = "restore-test-failed";

/// The OVERDUE secret-rotation signal (#7). A secret whose `next_rotation_due` has
/// passed. Fixed so the dedup key and the partial unique index always agree.
pub const SECRET_ROTATION_DUE_ITEM_TYPE: &str = "secret-rotation-due";

/// The INVALID secret-rotation-date signal (#7, codex MAJOR). A secret whose
/// `next_rotation_due` is not parseable as RFC3339 — surfaced (not silently skipped) so
/// the data-integrity problem is visible. Fixed so the dedup key and the partial unique
/// index always agree.
pub const SECRET_ROTATION_INVALID_ITEM_TYPE: &str = "secret-rotation-invalid-due";

/// The EXPIRING/EXPIRED legal-hold signal (#17). An Active hold within 30 days of (or
/// past) its `expiry_date`. Fixed so the dedup key and the partial unique index agree.
pub const LEGAL_HOLD_EXPIRY_ITEM_TYPE: &str = "legal-hold-expiring";

/// Enqueue ONE open `item_type` work item for `source_ci_key` iff no OPEN
/// (`resolved = false`) item already exists for that system+type. Returns
/// `rows_affected()` — `1` when a new item was inserted, `0` when one already
/// existed (or a concurrent writer raced and the ON CONFLICT dropped this one).
///
/// `item_type` is a code-controlled constant (`RESTORE_OVERDUE_ITEM_TYPE` /
/// `RESTORE_FAILED_ITEM_TYPE`), never user input; it is bound into BOTH the
/// INSERT and the NOT EXISTS dedup predicate so the produced row and the dedup
/// key can never drift.
///
/// `metadata` is bound as a JSON string and cast to `jsonb`. Rejects an empty/
/// whitespace `source_ci_key`: it is not a meaningful asset identity, and a blank
/// key would group unrelated systems together under the dedup. (A partial unique
/// index permits multiple NULL keys — but `metadata->>'source_ci_key'` is never
/// NULL here since we always write the key — so the guard is about blankness, not
/// NULL multiplicity.)
///
/// Executor-generic (`impl PgExecutor`) so the scheduler tick can run it on
/// `&mut *tx` and any future caller can run it on a pool.
pub async fn enqueue_if_absent(
    executor: impl PgExecutor<'_>,
    item_type: &str,
    source_ci_key: &str,
    title: &str,
    description: &str,
    priority: &str,
    metadata: &str,
) -> Result<u64, sqlx::Error> {
    if source_ci_key.trim().is_empty() {
        return Err(sqlx::Error::Protocol(
            "enqueue_if_absent: source_ci_key must not be empty".into(),
        ));
    }
    let result = sqlx::query(
        "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
         SELECT $1, $2, $3, $4, $5::jsonb \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM shift_queue \
             WHERE item_type = $1 \
               AND resolved = false \
               AND metadata->>'source_ci_key' = $6 \
         ) \
         ON CONFLICT DO NOTHING",
    )
    .bind(item_type)
    .bind(title)
    .bind(description)
    .bind(priority)
    .bind(metadata)
    .bind(source_ci_key)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Secret-safe triage projection for the operator list endpoint. `metadata` (jsonb)
/// is DELIBERATELY excluded (the shift-contract's `no-raw-provider-payloads` rule;
/// `/my-items` omits it too).
#[derive(Debug, sqlx::FromRow)]
pub struct ShiftQueueListRow {
    pub id: String,
    pub item_type: String,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub assigned_to: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub acknowledged: bool,
    pub escalated: bool,
    pub resolved: bool,
}

/// Optional filters for [`list_filtered`]. Every field is `None` ⇒ "do not filter".
#[derive(Debug, Default)]
pub struct ShiftQueueFilter<'a> {
    pub item_type: Option<&'a str>,
    pub priority: Option<&'a str>,
    pub assigned_to: Option<&'a str>,
    pub resolved: Option<bool>,
    pub acknowledged: Option<bool>,
    pub escalated: Option<bool>,
    /// `Some(true)` ⇒ only UNASSIGNED (`assigned_to IS NULL`); `Some(false)` ⇒ only
    /// assigned; `None` ⇒ no filter.
    pub unassigned: Option<bool>,
}

/// Filtered + paginated operator triage list.
///
/// EVERY filter is a BOUND parameter applied via the `($N::type IS NULL OR
/// col = $N)` pattern — an unset filter matches every row, and NO user input is ever
/// concatenated into SQL (injection-safe). Ordered `priority ASC` (P1<P2<P3) then
/// `created_at ASC` (oldest-waiting first — the triage backlog order) then `id ASC`
/// as an IMMUTABLE tiebreaker, so offset pagination is deterministic even when
/// priority + created_at tie. The caller passes `limit + 1` to derive `has_more`
/// without a COUNT.
pub async fn list_filtered(
    pool: &PgPool,
    filter: &ShiftQueueFilter<'_>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ShiftQueueListRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id::text AS id, item_type, title, description, priority, assigned_to, \
                created_at, acknowledged, escalated, resolved \
         FROM shift_queue \
         WHERE ($1::text IS NULL OR item_type = $1) \
           AND ($2::text IS NULL OR priority = $2) \
           AND ($3::text IS NULL OR assigned_to = $3) \
           AND ($4::bool IS NULL OR resolved = $4) \
           AND ($5::bool IS NULL OR acknowledged = $5) \
           AND ($6::bool IS NULL OR escalated = $6) \
           AND ($7::bool IS NULL OR (assigned_to IS NULL) = $7) \
         ORDER BY priority ASC, created_at ASC, id ASC \
         LIMIT $8 OFFSET $9",
    )
    .bind(filter.item_type)
    .bind(filter.priority)
    .bind(filter.assigned_to)
    .bind(filter.resolved)
    .bind(filter.acknowledged)
    .bind(filter.escalated)
    .bind(filter.unassigned)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}
