//! Repository functions for `shift_queue`.
//!
//! The shift queue is the operations work-item surface (migration 029). Until
//! #52 every INSERT into it lived inline in tests/seeds; this is the first
//! reusable writer, kept minimal and scoped to the `restore-test-overdue`
//! producer.
//!
//! # Dedup (no natural key)
//! `shift_queue` has only a PK on `id`. To enqueue at-most-one OPEN item per
//! system+type, [`enqueue_if_absent`] is an atomic single-statement
//! `INSERT … SELECT … WHERE NOT EXISTS … ON CONFLICT DO NOTHING`. The `WHERE NOT
//! EXISTS` skips the insert in the common already-queued case; the untargeted
//! `ON CONFLICT DO NOTHING` is the belt-and-suspenders that makes a racing
//! insert hit the partial unique index `uq_shift_queue_open_restore_overdue`
//! (migration 122) and be silently dropped instead of aborting the caller's
//! transaction. Under the single-leader scheduler tick the race is already
//! impossible; the ON CONFLICT just makes it structurally safe.

use sqlx::PgExecutor;

/// The only `item_type` this writer produces. Fixed so the dedup key and the
/// partial unique index always agree.
const RESTORE_OVERDUE_ITEM_TYPE: &str = "restore-test-overdue";

/// Enqueue ONE open `restore-test-overdue` work item for `source_ci_key` iff no
/// OPEN (`resolved = false`) item already exists for that system+type. Returns
/// `rows_affected()` — `1` when a new item was inserted, `0` when one already
/// existed (or a concurrent writer raced and the ON CONFLICT dropped this one).
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
    .bind(RESTORE_OVERDUE_ITEM_TYPE)
    .bind(title)
    .bind(description)
    .bind(priority)
    .bind(metadata)
    .bind(source_ci_key)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
