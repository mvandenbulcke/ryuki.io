//! Durable scheduler / background-job engine (#1).
//!
//! A single tick loop, elected leader across replicas, drives recurring work
//! durably: it claims due [`schedules`] rows, runs ONLY read-only job kinds (the
//! slice-1 safety boundary enforced by [`ryuki_engine::scheduler::job_is_read_only`]),
//! records a `job_executions` row, and advances `next_run_at` off the DB clock.
//!
//! Design choices that matter:
//! - **Leader election:** each tick takes a transaction-scoped advisory lock
//!   ([`pg_try_advisory_xact_lock`]). Only one replica wins a given tick; the
//!   others no-op. The lock auto-releases at COMMIT/ROLLBACK, so a crashed
//!   leader never wedges the schedule.
//! - **Claim:** `FOR UPDATE SKIP LOCKED` lets the (single) leader claim due rows
//!   without blocking on any row another transaction holds.
//! - **No backfill storms:** an overdue schedule advances to `NOW() + interval`,
//!   not `last + interval`, so a leader that was down does NOT replay every
//!   missed run — it resumes on the normal cadence.
//! - **DB clock only:** dueness and advancement are computed against `NOW()`
//!   server-side; no client clock is trusted (mirrors the idempotency sweep).
//!
//! The pure scheduling math (validation, due predicate, next-run, read-only
//! classifier) lives in `ryuki_engine::scheduler` and is unit-tested there.

use sqlx::{Acquire, PgPool, Postgres, Transaction};
use tokio::time::{interval, Duration};

/// Advisory-lock key for the tick leader election. Distinct from every other
/// advisory key in the codebase (e.g. the audit chain lock) so the two never
/// contend. Bytes spell "SCHED\0".
const SCHEDULER_TICK_LOCK_KEY: i64 = 0x5343_4845_4400;

/// Most due schedules a single tick will claim and run. A safety bound so one
/// tick cannot do unbounded work; remaining due rows are picked up next tick.
const MAX_BATCH: i64 = 100;

/// A due schedule row claimed by the tick.
#[derive(sqlx::FromRow)]
struct DueSchedule {
    id: String,
    job_kind: String,
    interval_secs: i64,
}

/// A schedule as exposed by the read API. No secrets live on a schedule, so the
/// view is the row verbatim minus bookkeeping columns.
#[derive(serde::Serialize, sqlx::FromRow)]
pub struct ScheduleView {
    pub id: String,
    pub name: String,
    pub job_kind: String,
    pub interval_secs: i64,
    pub enabled: bool,
    pub next_run_at: chrono::DateTime<chrono::Utc>,
    pub last_run_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One recorded job run as exposed by the read API.
#[derive(serde::Serialize, sqlx::FromRow)]
pub struct ExecutionView {
    pub id: String,
    pub schedule_id: String,
    pub job_kind: String,
    pub status: String,
    pub detail: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Run a single job kind inside the tick transaction and return its
/// `(status, detail)`. A non-read-only or unknown kind is REFUSED — recorded as
/// `skipped`, never executed — which is the slice-1 safety boundary: the durable
/// engine cannot run a side-effecting kind until a later slice adds it behind a
/// policy gate. The only runnable kind today is the read-only `health_probe`,
/// which proves the scheduler and DB are alive.
async fn run_job(
    tx: &mut Transaction<'_, Postgres>,
    job_kind: &str,
) -> Result<(String, Option<String>), sqlx::Error> {
    if !ryuki_engine::scheduler::job_is_read_only(job_kind) {
        return Ok((
            "skipped".to_string(),
            Some(format!("unsupported job kind: {job_kind}")),
        ));
    }
    match job_kind {
        "health_probe" => {
            // Read-only liveness check: a single aggregate read. Proves the DB
            // is reachable and the loop is alive. The count is an aggregate
            // health signal, not a row/secret/id. A DB error here propagates so
            // the per-schedule savepoint rolls back and records a failure.
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests")
                .fetch_one(&mut **tx)
                .await?;
            Ok((
                "succeeded".to_string(),
                Some(format!("probe ok; requests_observed={count}")),
            ))
        }
        // Unreachable: job_is_read_only gated above. Kept exhaustive and safe.
        other => Ok((
            "skipped".to_string(),
            Some(format!("unsupported job kind: {other}")),
        )),
    }
}

/// Record one execution row for a schedule. `started_at`/`finished_at` use
/// `clock_timestamp()` (true wall-clock), NOT `NOW()` (which is the transaction
/// start time and would mis-stamp a long batch).
async fn insert_execution(
    tx: &mut Transaction<'_, Postgres>,
    schedule_id: &str,
    job_kind: &str,
    status: &str,
    detail: &Option<String>,
) -> Result<(), sqlx::Error> {
    let exec_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO job_executions \
         (id, schedule_id, job_kind, status, detail, started_at, finished_at) \
         VALUES ($1, $2, $3, $4, $5, clock_timestamp(), clock_timestamp())",
    )
    .bind(&exec_id)
    .bind(schedule_id)
    .bind(job_kind)
    .bind(status)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Advance a schedule to its next run: `clock_timestamp() + interval`, with NO
/// backfill of missed runs (an overdue schedule resumes on cadence, it does not
/// replay every miss). Advancing off `clock_timestamp()` — the real completion
/// instant, not the transaction start — guarantees the next run is genuinely in
/// the future even after a long tick, so a slow batch cannot cause an immediate
/// re-run. `interval_secs` is clamped to the engine's validated bounds as a
/// belt-and-suspenders guard on top of the table CHECK, so an out-of-range value
/// can never overflow `make_interval` or busy-spin the loop.
async fn advance_schedule(
    tx: &mut Transaction<'_, Postgres>,
    schedule_id: &str,
    interval_secs: i64,
) -> Result<(), sqlx::Error> {
    let bounded = interval_secs.clamp(
        ryuki_engine::scheduler::MIN_INTERVAL_SECS as i64,
        ryuki_engine::scheduler::MAX_INTERVAL_SECS as i64,
    );
    sqlx::query(
        "UPDATE schedules \
         SET last_run_at = clock_timestamp(), \
             next_run_at = clock_timestamp() + make_interval(secs => $1::double precision), \
             updated_at = clock_timestamp() \
         WHERE id = $2",
    )
    .bind(bounded as f64)
    .bind(schedule_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Run a single claimed schedule and record + advance it. Any DB error
/// propagates so the caller can roll back this schedule's savepoint without
/// losing the rest of the batch.
async fn run_and_record(
    tx: &mut Transaction<'_, Postgres>,
    sched: &DueSchedule,
) -> Result<(), sqlx::Error> {
    let (status, detail) = run_job(tx, &sched.job_kind).await?;
    insert_execution(tx, &sched.id, &sched.job_kind, &status, &detail).await?;
    advance_schedule(tx, &sched.id, sched.interval_secs).await?;
    Ok(())
}

/// Run one scheduler tick: elect leadership, claim every due schedule, and run
/// each in its OWN savepoint so one failing schedule never rolls back the rest
/// of the batch. Returns the number of schedules run successfully (0 when this
/// replica did not win leadership or nothing was due). Idempotent and safe to
/// call concurrently across replicas — only the leader does work.
pub async fn tick_once(pool: &PgPool) -> Result<usize, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Leader election: only the replica that wins this tx-scoped lock ticks. The
    // others see `false` and no-op (their tx rolls back on drop, releasing
    // nothing they hold). The lock auto-releases at COMMIT below. Combined with
    // FOR UPDATE SKIP LOCKED on the claim, a given due schedule runs at most once
    // per tick across the whole fleet.
    let is_leader: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(SCHEDULER_TICK_LOCK_KEY)
        .fetch_one(&mut *tx)
        .await?;
    if !is_leader {
        return Ok(0);
    }

    let due: Vec<DueSchedule> = sqlx::query_as(
        "SELECT id, job_kind, interval_secs FROM schedules \
         WHERE enabled AND next_run_at <= NOW() \
         ORDER BY next_run_at ASC \
         LIMIT $1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(MAX_BATCH)
    .fetch_all(&mut *tx)
    .await?;

    let mut ran = 0usize;
    for sched in &due {
        // Per-schedule savepoint: a DB error running or recording THIS schedule
        // rolls back only its own work, never the claim or the other schedules.
        let mut sp = tx.begin().await?;
        match run_and_record(&mut sp, sched).await {
            Ok(()) => {
                sp.commit().await?;
                ran += 1;
            }
            Err(error) => {
                // Roll back the poisoned savepoint (restoring the parent tx to a
                // healthy state), then record a `failed` execution and STILL
                // advance in a fresh savepoint so the bad schedule does not stay
                // due and starve the loop. A genuine DB outage makes the fresh
                // savepoint fail too, aborting the whole tick — correct: it
                // retries next interval rather than spinning.
                sp.rollback().await?;
                tracing::error!(
                    schedule = %sched.id,
                    %error,
                    "scheduler job failed; recording failure and advancing"
                );
                let mut sp2 = tx.begin().await?;
                insert_execution(
                    &mut sp2,
                    &sched.id,
                    &sched.job_kind,
                    "failed",
                    &Some("job failed; see server logs".to_string()),
                )
                .await?;
                advance_schedule(&mut sp2, &sched.id, sched.interval_secs).await?;
                sp2.commit().await?;
            }
        }
    }

    tx.commit().await?;
    Ok(ran)
}

/// List all schedules, newest-created first.
pub async fn list_schedules(pool: &PgPool) -> Result<Vec<ScheduleView>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, name, job_kind, interval_secs, enabled, next_run_at, last_run_at \
         FROM schedules ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
}

/// List the most recent job executions across all schedules, newest first.
pub async fn list_recent_executions(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<ExecutionView>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, schedule_id, job_kind, status, detail, started_at, finished_at \
         FROM job_executions ORDER BY started_at DESC LIMIT $1",
    )
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await
}

/// Spawn the background scheduler tick. Call once at startup after the DB pool
/// is available; the task runs until the runtime shuts down. Each tick is
/// leader-elected and idempotent, so a duplicate spawn is harmless.
pub fn spawn_scheduler(pool: PgPool, tick_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(tick_secs));
        ticker.tick().await; // skip the immediate first tick (just started)
        loop {
            ticker.tick().await;
            match tick_once(&pool).await {
                Ok(ran) if ran > 0 => {
                    tracing::info!(ran, "scheduler tick ran due jobs");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(error = %error, "scheduler tick failed");
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// DB-gated integration tests — claim/advance, unknown-kind refusal, read views.
// Each SKIPS when RYUKI_DATABASE_URL is unset.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;

    async fn global_pool() -> Option<&'static PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()
            .expect("RYUKI_DATABASE_URL is set but the DB connection failed");
        let _ = crate::database::run_migrations(pool).await;
        Some(pool)
    }

    /// Plant a single due schedule, tick, and assert it ran exactly once, was
    /// advanced into the future, and recorded a succeeded execution.
    #[tokio::test]
    async fn tick_runs_due_schedule_records_execution_and_advances() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let id = "sched-test-due-7f1";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test probe', 'health_probe', 3600, TRUE, NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();

        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "at least the planted due schedule ran");

        // It was advanced into the future (no longer due).
        let still_due: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM schedules WHERE id = $1 AND next_run_at <= NOW()",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(still_due, 0, "schedule was advanced past now");

        // It recorded a succeeded execution.
        let succeeded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM job_executions \
             WHERE schedule_id = $1 AND status = 'succeeded'",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(succeeded >= 1, "a succeeded execution was recorded");

        // A second immediate tick does NOT re-run it (no longer due).
        let exec_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM job_executions WHERE schedule_id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap();
        let _ = tick_once(pool).await.unwrap();
        let exec_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM job_executions WHERE schedule_id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(
            exec_before, exec_after,
            "an advanced schedule is not re-run on the next immediate tick"
        );

        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    /// An unknown / non-read-only job kind is REFUSED: the engine records it as
    /// `skipped` and never executes it, but still advances the schedule so it
    /// does not spin.
    #[tokio::test]
    async fn unknown_kind_is_skipped_not_executed() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let id = "sched-test-unknown-9c2";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'danger', 'live_apply', 3600, TRUE, NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();

        let _ = tick_once(pool).await.unwrap();

        let skipped: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM job_executions \
             WHERE schedule_id = $1 AND status = 'skipped'",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(skipped >= 1, "an unsupported kind is recorded as skipped");
        let succeeded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM job_executions \
             WHERE schedule_id = $1 AND status = 'succeeded'",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(succeeded, 0, "an unsupported kind is never executed");

        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    /// A disabled schedule is never claimed, even when overdue.
    #[tokio::test]
    async fn disabled_schedule_is_not_run() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let id = "sched-test-disabled-3a8";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'off', 'health_probe', 3600, FALSE, NOW() - INTERVAL '1 hour')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();

        let _ = tick_once(pool).await.unwrap();

        let execs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM job_executions WHERE schedule_id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(execs, 0, "a disabled schedule is never run");

        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    /// The read views return the seeded self-health probe and its executions.
    #[tokio::test]
    async fn read_views_expose_schedules_and_executions() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // The migration seeds the platform self-health probe.
        let schedules = list_schedules(pool).await.unwrap();
        assert!(
            schedules.iter().any(|s| s.job_kind == "health_probe"),
            "the seeded health probe is listed"
        );

        // Force at least one execution to exist, then read the view.
        let _ = tick_once(pool).await.unwrap();
        let execs = list_recent_executions(pool, 50).await.unwrap();
        // Not asserting non-empty (another test may have cleaned up its rows),
        // only that the view query shape is valid and bounded.
        assert!(execs.len() <= 50, "the execution view honors its limit");
    }
}
