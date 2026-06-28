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
use tokio::time::{interval, Duration, MissedTickBehavior};

/// Advisory-lock key for the tick leader election. Distinct from every other
/// advisory key in the codebase (e.g. the audit chain lock) so the two never
/// contend. Bytes spell "SCHED\0".
const SCHEDULER_TICK_LOCK_KEY: i64 = 0x5343_4845_4400;

/// Most due schedules a single tick will claim and run. A safety bound so one
/// tick cannot do unbounded work; remaining due rows are picked up next tick.
const MAX_BATCH: i64 = 100;

/// How far ahead `maintain_review_scan` (#39) advances a request's
/// `next_maintain_review_at` after flagging it — the recurring operational-review
/// cadence. A single constant, easy to retune; the scan itself runs daily.
const REVIEW_INTERVAL: &str = "90 days";

/// Most Operational requests a single `maintain_review_scan` claims and flags per
/// tick. Bounds the per-tick work the same way [`MAX_BATCH`] bounds schedules;
/// remaining due requests are picked up on the next daily scan.
const MAINTAIN_REVIEW_BATCH: i64 = 100;

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
/// `(status, detail)`. A kind that is not schedulable (unknown, or live/
/// side-effecting) is REFUSED — recorded as `skipped`, never executed. The
/// safety boundary is `job_is_schedulable`: read-only kinds plus explicitly
/// enumerated SAFE-INTERNAL-WRITE kinds (which persist only to our own tables via
/// pure dry-run engine logic, no provider/live call). Runnable kinds today:
/// `health_probe` (read-only liveness), `synthetic_health_run` (records simulated
/// probe results), `maintain_review_scan` (flags Operational requests due for
/// review via domain events), and `connection_health_sweep` (appends a dry-run
/// health-check row per integration connection). Every write happens on `tx`, so
/// a failure rolls back within the schedule's savepoint.
async fn run_job(
    tx: &mut Transaction<'_, Postgres>,
    job_kind: &str,
) -> Result<(String, Option<String>), sqlx::Error> {
    if !ryuki_engine::scheduler::job_is_schedulable(job_kind) {
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
        "synthetic_health_run" => {
            // Safe-internal dry-run: list every ENABLED check across all sites
            // (the scheduler is a platform-wide internal principal, not scoped),
            // run the PURE engine simulation, and persist each result on `tx` so a
            // failure rolls back with this schedule's savepoint. `detail` is kept
            // aggregate-only (a count) — never per-site/tenant data — because it is
            // surfaced via /api/ops/scheduler/executions.
            let checks = crate::repos::synthetic_health::list_all_enabled_checks(&mut **tx).await?;
            let results = ryuki_engine::synthetic_health::run_all_checks(&checks);
            for result in &results {
                crate::repos::synthetic_health::insert_result(&mut **tx, result).await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!("ran {} synthetic health check(s)", results.len())),
            ))
        }
        "maintain_review_scan" => {
            // Safe-internal write (#39): flag Operational requests due for a
            // recurring review. The claim+advance is ONE atomic UPDATE on `tx`:
            // it selects due Operational rows (FOR UPDATE SKIP LOCKED), advances
            // their next_maintain_review_at by REVIEW_INTERVAL, and RETURNs the
            // rows it claimed. This races a concurrent retire safely — that
            // request either already left 'operational' (not matched) or runs
            // after and sees the advanced timestamp; SKIP LOCKED plus the
            // single-leader tick prevent any double-emit. Lock order (requests
            // row → domain_events) matches apply_transition_audited, so no
            // deadlock. NULL = initial review due, ordered first.
            #[derive(sqlx::FromRow)]
            struct DueRequest {
                id: String,
                site: String,
                environment: String,
            }
            // REVIEW_INTERVAL is a code-controlled const (never user input), so
            // interpolating it into the interval literal is safe; the batch bound
            // is still a parameter.
            let sql = format!(
                "UPDATE requests \
                 SET next_maintain_review_at = NOW() + INTERVAL '{REVIEW_INTERVAL}', updated_at = NOW() \
                 WHERE id IN ( \
                     SELECT id FROM requests \
                     WHERE status = 'operational' \
                       AND (next_maintain_review_at IS NULL OR next_maintain_review_at <= NOW()) \
                     ORDER BY next_maintain_review_at NULLS FIRST, id \
                     LIMIT $1 \
                     FOR UPDATE SKIP LOCKED \
                 ) \
                 RETURNING id::text, site, environment"
            );
            let due: Vec<DueRequest> = sqlx::query_as(&sql)
                .bind(MAINTAIN_REVIEW_BATCH)
                .fetch_all(&mut **tx)
                .await?;

            // One review-due domain event per claimed request, on the SAME tx so
            // the flags and events commit (or roll back) together. Payload is
            // minimal and non-sensitive, and carries NO `to_status` — so it stays
            // a NORMAL /api/events entry, not an alert-feed item.
            for req in &due {
                let payload = serde_json::json!({
                    "request_id": req.id,
                    "note": "operational review due",
                });
                crate::repos::domain_events::insert(
                    &mut **tx,
                    crate::repos::domain_events::NewEvent {
                        event_type: "request.maintain-review-due",
                        aggregate_type: "request",
                        aggregate_id: &req.id,
                        site: Some(&req.site),
                        environment: Some(&req.environment),
                        actor: "system",
                        payload,
                    },
                )
                .await?;
            }
            // Aggregate-only detail (a count) — never per-request/tenant data —
            // because it is surfaced via /api/ops/scheduler/executions.
            Ok((
                "succeeded".to_string(),
                Some(format!("queued {} maintain review(s)", due.len())),
            ))
        }
        "connection_health_sweep" => {
            // Safe-internal dry-run (#19): list EVERY integration connection
            // (there is no `enabled` column — probe them all), run the PURE
            // `test_connection_stub` (no live provider call, no live credential
            // resolver), append a connection_health_checks history row, AND
            // refresh each connection's last_test_* — all on `tx`, so a failure
            // rolls back with this schedule's savepoint. `credential_status` is a
            // DETERMINISTIC STUB value derived from credential_ref presence (the
            // same verdict the stub implies); the live `resolve_credentials` is
            // never called here, keeping the sweep stub-only. `detail` is kept
            // aggregate-only (a count) — never per-connection ids — because it is
            // surfaced via /api/ops/scheduler/executions.
            let connections =
                crate::repos::integration_connections::list_all_connections(&mut **tx).await?;
            let tested_at = chrono::Utc::now().to_rfc3339();
            for conn in &connections {
                let result = ryuki_engine::integration_connections::test_connection_stub(conn);
                // Deterministic stub verdict: the stub only inspects ref presence
                // (it never resolves the secret), so mirror that here.
                let credential_status = if conn.credential_ref.is_empty() {
                    "ref-missing"
                } else {
                    "ref-present"
                };
                crate::repos::integration_connections::insert_health_check(
                    &mut **tx,
                    &conn.id,
                    &result.status,
                    credential_status,
                    &result.message,
                )
                .await?;
                let combined = format!("{};creds={}", result.status, credential_status);
                crate::repos::integration_connections::update_last_test(
                    &mut **tx, &conn.id, &tested_at, &combined,
                )
                .await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!("probed {} connection(s)", connections.len())),
            ))
        }
        // Unreachable: job_is_schedulable gated above. Kept exhaustive and safe.
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
    // #26: bound each tick and apply backpressure so a slow or wedged tick cannot
    // pin the loop into back-to-back catch-up ticks.
    // - Skip missed ticks: after a tick that overran the interval, resume on the
    //   next aligned boundary instead of bursting a run of catch-up ticks (the
    //   default Burst behavior).
    // - Per-tick timeout: a GENEROUS guard (>= 5 min, or 4x the interval) so a
    //   genuinely hung tick — one that escapes the DB-level statement/lock
    //   timeouts (#12) via an application-level stall — is aborted and retried on
    //   the next tick rather than starving the loop forever. Dropping the tick
    //   future rolls back its transaction (the advisory xact lock is released),
    //   so an abort is safe and the next leader simply retries.
    let tick_timeout = Duration::from_secs(tick_secs.saturating_mul(4).max(300));
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(tick_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await; // skip the immediate first tick (just started)
        loop {
            ticker.tick().await;
            match tokio::time::timeout(tick_timeout, tick_once(&pool)).await {
                Ok(Ok(ran)) if ran > 0 => {
                    tracing::info!(ran, "scheduler tick ran due jobs");
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    tracing::error!(error = %error, "scheduler tick failed");
                }
                Err(_elapsed) => {
                    tracing::error!(
                        tick_timeout_secs = tick_timeout.as_secs(),
                        "scheduler tick exceeded its timeout and was aborted; retrying next tick"
                    );
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

    /// #40: a due `synthetic_health_run` schedule runs every ENABLED check inside
    /// the tick tx, persists a result per check, records a succeeded execution, and
    /// advances. Proves the safe-internal-write kind is dispatched (not skipped).
    #[tokio::test]
    async fn tick_runs_synthetic_health_and_persists_results() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Seed one enabled health check; capture its generated id.
        let check_id: String = sqlx::query_scalar(
            "INSERT INTO health_checks (name, check_type, endpoint, site, enabled) \
             VALUES ('sched-synth-test', 'http', 'https://example.test/health', 'GBLON', true) \
             RETURNING id::text",
        )
        .fetch_one(pool)
        .await
        .unwrap();

        let sched_id = "sched-test-synth-9c2";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(sched_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test synth run', 'synthetic_health_run', 3600, TRUE, \
             NOW() - INTERVAL '1 minute')",
        )
        .bind(sched_id)
        .execute(pool)
        .await
        .unwrap();

        let before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM check_results WHERE check_id = $1::uuid")
                .bind(&check_id)
                .fetch_one(pool)
                .await
                .unwrap();

        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "at least the planted synthetic schedule ran");

        // A result was persisted for our seeded check (proves the arm ran, not
        // skipped, and wrote inside the tx).
        let after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM check_results WHERE check_id = $1::uuid")
                .bind(&check_id)
                .fetch_one(pool)
                .await
                .unwrap();
        assert!(
            after > before,
            "the scheduled synthetic run persisted a result for the seeded check"
        );

        // The schedule recorded a succeeded execution and was advanced.
        let succeeded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM job_executions \
             WHERE schedule_id = $1 AND status = 'succeeded' AND job_kind = 'synthetic_health_run'",
        )
        .bind(sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(
            succeeded >= 1,
            "a succeeded synthetic_health_run execution was recorded"
        );
        let still_due: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM schedules WHERE id = $1 AND next_run_at <= NOW()",
        )
        .bind(sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(still_due, 0, "schedule was advanced past now");

        // Cleanup: results (FK) before the check.
        sqlx::query("DELETE FROM check_results WHERE check_id = $1::uuid")
            .bind(&check_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(sched_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM health_checks WHERE id = $1::uuid")
            .bind(&check_id)
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

    // ---- #39 maintain_review_scan ------------------------------------------

    /// Seed one request with an explicit status and `next_maintain_review_at`,
    /// returning its generated id. `review_at` is raw SQL (e.g. `NULL` or
    /// `NOW() + INTERVAL '30 days'`) so a test can plant a due / not-due row.
    async fn seed_maintain_request(pool: &PgPool, status: &str, review_at_sql: &str) -> String {
        let sql = format!(
            "INSERT INTO requests \
             (request_type, status, stage, site, environment, name, created_by, next_maintain_review_at) \
             VALUES ('server-deployment', $1, 'operational', 'GBLON', 'production', \
                     'maintain-test', 'system', {review_at_sql}) \
             RETURNING id::text"
        );
        sqlx::query_scalar(&sql)
            .bind(status)
            .fetch_one(pool)
            .await
            .expect("seed maintain request")
    }

    /// Plant a guaranteed-due `maintain_review_scan` schedule so a single tick
    /// runs the scan, regardless of when the migration-seeded daily schedule last
    /// advanced (an earlier test's tick may already have pushed it into the
    /// future). Returns its id for cleanup.
    async fn seed_due_maintain_schedule(pool: &PgPool) -> String {
        let id = "sched-test-maintain-due-1f3";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test maintain scan', 'maintain_review_scan', 86400, TRUE, \
             NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        id.to_string()
    }

    async fn maintain_event_count(pool: &PgPool, request_id: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM domain_events \
             WHERE event_type = 'request.maintain-review-due' AND aggregate_id = $1",
        )
        .bind(request_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn cleanup_maintain_request(pool: &PgPool, request_id: &str) {
        sqlx::query("DELETE FROM domain_events WHERE aggregate_id = $1")
            .bind(request_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM requests WHERE id = $1::uuid")
            .bind(request_id)
            .execute(pool)
            .await
            .ok();
    }

    /// Test 1: a due Operational request (NULL next_maintain_review_at) gets
    /// exactly one review-due event after a tick AND its timestamp is advanced
    /// ~REVIEW_INTERVAL into the future.
    #[tokio::test]
    async fn maintain_scan_flags_due_operational_request() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_maintain_request(pool, "operational", "NULL").await;
        let sched_id = seed_due_maintain_schedule(pool).await;

        let _ = tick_once(pool).await.unwrap();

        assert_eq!(
            maintain_event_count(pool, &req_id).await,
            1,
            "exactly one review-due event for the due Operational request"
        );
        // Payload contract (load-bearing): {request_id, note} and crucially NO
        // `to_status` — that absence keeps the event a normal /api/events entry and
        // OUT of the alert feed (codex fix #1). A regression that added to_status,
        // renamed request_id, or dropped note must fail here.
        let (p_req, p_note, has_to_status): (Option<String>, Option<String>, bool) =
            sqlx::query_as(
                "SELECT payload->>'request_id', payload->>'note', (payload ? 'to_status') \
                 FROM domain_events \
                 WHERE aggregate_id = $1 AND event_type = 'request.maintain-review-due' \
                 ORDER BY id DESC LIMIT 1",
            )
            .bind(&req_id)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            p_req.as_deref(),
            Some(req_id.as_str()),
            "payload request_id"
        );
        assert_eq!(
            p_note.as_deref(),
            Some("operational review due"),
            "payload note"
        );
        assert!(
            !has_to_status,
            "maintain-review-due must NOT carry to_status (normal event, not an alert)"
        );

        // The timestamp was advanced ~90d (REVIEW_INTERVAL) — bracketed so a wrong
        // interval is caught, not merely 'sometime after 80 days'.
        let advanced: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM requests \
             WHERE id = $1::uuid \
               AND next_maintain_review_at BETWEEN NOW() + INTERVAL '89 days' \
                                               AND NOW() + INTERVAL '91 days'",
        )
        .bind(&req_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(advanced, 1, "next_maintain_review_at advanced to ~90d");

        // The scheduler execution detail is the aggregate count ONLY — no per-
        // request / tenant data leaks via /api/ops/scheduler/executions.
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'maintain_review_scan' \
               AND status = 'succeeded' \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let detail = detail.unwrap_or_default();
        // Aggregate-only contract: EXACTLY "queued <N> maintain review(s)" where the
        // middle token is a bare number — no site/env/request identifiers can leak
        // in. "queued GBLON production maintain review(s)" or "queued many ..." fail.
        let count_token = detail
            .strip_prefix("queued ")
            .and_then(|s| s.strip_suffix(" maintain review(s)"));
        assert!(
            count_token.is_some_and(|n| n.parse::<u64>().is_ok()),
            "detail must be exactly 'queued <N> maintain review(s)': {detail:?}"
        );

        cleanup_maintain_request(pool, &req_id).await;
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();
    }

    /// Test 2: a not-due Operational request (review_at = NOW()+30d) gets no
    /// event and its timestamp is left unchanged.
    #[tokio::test]
    async fn maintain_scan_skips_not_due_request() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_maintain_request(pool, "operational", "NOW() + INTERVAL '30 days'").await;
        let sched_id = seed_due_maintain_schedule(pool).await;
        let before: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT next_maintain_review_at FROM requests WHERE id = $1::uuid")
                .bind(&req_id)
                .fetch_one(pool)
                .await
                .unwrap();

        let _ = tick_once(pool).await.unwrap();

        assert_eq!(
            maintain_event_count(pool, &req_id).await,
            0,
            "a not-due request is never flagged"
        );
        let after: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT next_maintain_review_at FROM requests WHERE id = $1::uuid")
                .bind(&req_id)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(before, after, "a not-due request's timestamp is unchanged");

        cleanup_maintain_request(pool, &req_id).await;
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();
    }

    /// Test 3: a non-Operational request (even with a NULL/overdue timestamp) is
    /// never selected by the scan.
    #[tokio::test]
    async fn maintain_scan_ignores_non_operational_request() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // A completed (not yet Operational) request with NULL review timestamp.
        let req_id = seed_maintain_request(pool, "completed", "NULL").await;
        let sched_id = seed_due_maintain_schedule(pool).await;

        let _ = tick_once(pool).await.unwrap();

        assert_eq!(
            maintain_event_count(pool, &req_id).await,
            0,
            "a non-Operational request is never flagged"
        );
        let untouched: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM requests \
             WHERE id = $1::uuid AND next_maintain_review_at IS NULL",
        )
        .bind(&req_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(untouched, 1, "its timestamp stays NULL");

        cleanup_maintain_request(pool, &req_id).await;
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();
    }

    /// Test 4: a second immediate tick does NOT re-emit — the first tick advanced
    /// the timestamp into the future, so the request is no longer due.
    #[tokio::test]
    async fn maintain_scan_does_not_re_emit_on_second_tick() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = seed_maintain_request(pool, "operational", "NULL").await;

        let sched_id = seed_due_maintain_schedule(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            maintain_event_count(pool, &req_id).await,
            1,
            "first tick flags the request once"
        );

        // Re-plant a due scan schedule so the scan ACTUALLY runs a second time —
        // proving the request-level guard (the advanced timestamp), not merely
        // the schedule-level one, is what prevents a re-emit.
        let _ = seed_due_maintain_schedule(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            maintain_event_count(pool, &req_id).await,
            1,
            "a second immediate tick does not re-emit (timestamp now in the future)"
        );

        cleanup_maintain_request(pool, &req_id).await;
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();
    }

    /// Test 6: migration 119's guarded DDL is idempotent — re-running each
    /// statement (the migration already ran in global_pool) is a clean no-op and
    /// leaves exactly one seeded scan schedule.
    #[tokio::test]
    async fn migration_119_is_idempotent() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Re-apply the guarded statements; each must be a no-op, not an error.
        sqlx::query(
            "ALTER TABLE requests ADD COLUMN IF NOT EXISTS next_maintain_review_at TIMESTAMPTZ",
        )
        .execute(pool)
        .await
        .expect("ADD COLUMN IF NOT EXISTS re-runs cleanly");
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_requests_next_maintain_review \
             ON requests (next_maintain_review_at) WHERE status = 'operational'",
        )
        .execute(pool)
        .await
        .expect("CREATE INDEX IF NOT EXISTS re-runs cleanly");
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ('33333333-3333-4333-8333-333333333333', \
                     'Maintain review scan (operational requests)', 'maintain_review_scan', \
                     86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");

        // Exactly one seeded scan schedule exists (the ON CONFLICT prevented a dup).
        let seeded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM schedules WHERE id = '33333333-3333-4333-8333-333333333333'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            seeded, 1,
            "exactly one maintain_review_scan schedule is seeded"
        );
    }

    // ---- #19 connection_health_sweep ---------------------------------------

    /// Seed one integration connection with the given id and credential_ref,
    /// returning its id. `created_at`/`updated_at` have no DB default, so they are
    /// supplied explicitly.
    async fn seed_connection(pool: &PgPool, id: &str, credential_ref: &str) {
        sqlx::query("DELETE FROM integration_connections WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO integration_connections \
             (id, vendor_type, name, endpoint_url, credential_source, credential_ref, \
              created_by, created_at, updated_at) \
             VALUES ($1, 'vmware', 'sweep-test', 'https://vcenter.example.test', 'env-var', \
                     $2, 'system', NOW()::text, NOW()::text)",
        )
        .bind(id)
        .bind(credential_ref)
        .execute(pool)
        .await
        .expect("seed integration connection");
    }

    /// Plant a guaranteed-due `connection_health_sweep` schedule so a single tick
    /// runs the sweep regardless of when the migration-seeded one last advanced.
    /// Returns its id for cleanup.
    ///
    /// Disables the migration-seeded sweep (id `4444…`) first so EXACTLY ONE sweep
    /// is due in the tick — otherwise both would run and append two rows per
    /// connection, breaking the per-tick count assertions. Disabling (not
    /// deleting) is safe: the next `global_pool()` re-runs the migration whose
    /// `ON CONFLICT DO NOTHING` leaves the disabled row untouched.
    async fn seed_due_sweep_schedule(pool: &PgPool) -> String {
        sqlx::query(
            "UPDATE schedules SET enabled = FALSE \
             WHERE id = '44444444-4444-4444-8444-444444444444'",
        )
        .execute(pool)
        .await
        .ok();
        let id = "sched-test-connsweep-due-2e4";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test conn sweep', 'connection_health_sweep', 300, TRUE, \
             NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        id.to_string()
    }

    /// Re-enable the migration-seeded sweep (id `4444…`) that
    /// [`seed_due_sweep_schedule`] disabled, so the suite leaves the PRODUCTION
    /// schedule in its shipped (enabled) state. Without this, `ON CONFLICT DO
    /// NOTHING` on re-migration would preserve the disabled row and silently turn
    /// the real sweep off for any later reader (and `migration_120_is_idempotent`
    /// asserts it is enabled).
    async fn restore_migration_sweep(pool: &PgPool) {
        sqlx::query(
            "UPDATE schedules SET enabled = TRUE \
             WHERE id = '44444444-4444-4444-8444-444444444444'",
        )
        .execute(pool)
        .await
        .ok();
    }

    async fn health_check_count(pool: &PgPool, connection_id: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM connection_health_checks WHERE connection_id = $1")
            .bind(connection_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// The most recent connection_health_checks row content for a connection,
    /// returned as (endpoint_status, credential_status, message). Used to verify
    /// the swept row's COLUMN VALUES (not just its existence) and that the
    /// persisted message is secret-free.
    async fn latest_health_check(pool: &PgPool, connection_id: &str) -> (String, String, String) {
        sqlx::query_as(
            "SELECT endpoint_status, credential_status, message FROM connection_health_checks \
             WHERE connection_id = $1 ORDER BY checked_at DESC LIMIT 1",
        )
        .bind(connection_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn cleanup_connection(pool: &PgPool, connection_id: &str) {
        // connection_health_checks cascades on the connection FK, but delete it
        // explicitly so the assertions of other tests are not perturbed.
        sqlx::query("DELETE FROM connection_health_checks WHERE connection_id = $1")
            .bind(connection_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM integration_connections WHERE id = $1")
            .bind(connection_id)
            .execute(pool)
            .await
            .ok();
    }

    /// Test 1: three connections (two with a credential_ref, one WITHOUT) + a
    /// guaranteed-due sweep. One tick → each gains a fresh connection_health_checks
    /// row AND its last_test_at/last_test_result are updated. Verifies BOTH stub
    /// branches (ref-present→reachable-stub, ref-missing→unreachable), the EXACT
    /// row column values, the exact `<status>;creds=<verdict>` last_test_result
    /// format the portal parses, that the persisted message is secret-free (never
    /// contains the credential_ref), and that the execution detail is EXACTLY
    /// `probed <N> connection(s)` with a bare count token (no per-connection leak).
    #[tokio::test]
    async fn connection_sweep_probes_all_and_updates_freshness() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let id_a = "ic-sweep-test-aaaa0001";
        let id_b = "ic-sweep-test-bbbb0002";
        let id_c = "ic-sweep-test-cccc0001"; // empty credential_ref → ref-missing
        seed_connection(pool, id_a, "API_KEY_A").await;
        seed_connection(pool, id_b, "API_KEY_B").await;
        seed_connection(pool, id_c, "").await;
        let sched_id = seed_due_sweep_schedule(pool).await;

        let before_a = health_check_count(pool, id_a).await;
        let before_b = health_check_count(pool, id_b).await;
        let before_c = health_check_count(pool, id_c).await;

        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "at least the planted sweep schedule ran");

        // Each connection gained exactly one new history row.
        assert_eq!(
            health_check_count(pool, id_a).await,
            before_a + 1,
            "connection A gained one health-check row"
        );
        assert_eq!(
            health_check_count(pool, id_b).await,
            before_b + 1,
            "connection B gained one health-check row"
        );
        assert_eq!(
            health_check_count(pool, id_c).await,
            before_c + 1,
            "connection C (no ref) gained one health-check row"
        );

        // ref-present branch (A): the swept row stores the exact stub verdict and
        // the FULL secret-free stub message — and NEVER the credential_ref value.
        let (ep_a, cred_a, msg_a) = latest_health_check(pool, id_a).await;
        assert_eq!(ep_a, "reachable-stub", "A endpoint_status");
        assert_eq!(cred_a, "ref-present", "A credential_status");
        assert_eq!(
            msg_a,
            "DRY-RUN: endpoint URL shape valid; credential_source=env-var ref present. \
             No live call made.",
            "A message is the exact stub output"
        );
        assert!(
            !msg_a.contains("API_KEY_A"),
            "A message must NOT leak the credential_ref: {msg_a}"
        );

        // ref-missing branch (C): empty ref flips the stub to unreachable; the
        // deterministic credential verdict is ref-missing, with the exact message.
        let (ep_c, cred_c, msg_c) = latest_health_check(pool, id_c).await;
        assert_eq!(ep_c, "unreachable", "C endpoint_status (empty ref)");
        assert_eq!(cred_c, "ref-missing", "C credential_status (empty ref)");
        assert_eq!(
            msg_c, "DRY-RUN: validation failed — credential_ref is empty",
            "C message is the exact stub output"
        );

        // last_test_* refreshed with the EXACT `<status>;creds=<verdict>` format the
        // portal integrations table parses (mirrors the on-demand probe).
        let expect = [
            (id_a, "reachable-stub;creds=ref-present"),
            (id_b, "reachable-stub;creds=ref-present"),
            (id_c, "unreachable;creds=ref-missing"),
        ];
        for (id, want) in expect {
            let (at, result): (Option<String>, Option<String>) = sqlx::query_as(
                "SELECT last_test_at, last_test_result FROM integration_connections WHERE id = $1",
            )
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
            assert!(at.is_some(), "last_test_at set for {id}");
            assert_eq!(
                result.as_deref(),
                Some(want),
                "last_test_result exact format for {id}"
            );
        }

        // Aggregate-only detail contract: EXACTLY "probed <N> connection(s)" with a
        // bare number — no connection ids can leak via /api/ops/scheduler/executions.
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'connection_health_sweep' \
               AND status = 'succeeded' \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let detail = detail.unwrap_or_default();
        let count_token = detail
            .strip_prefix("probed ")
            .and_then(|s| s.strip_suffix(" connection(s)"));
        assert!(
            count_token.is_some_and(|n| n.parse::<u64>().is_ok()),
            "detail must be exactly 'probed <N> connection(s)': {detail:?}"
        );

        cleanup_connection(pool, id_a).await;
        cleanup_connection(pool, id_b).await;
        cleanup_connection(pool, id_c).await;
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();
        restore_migration_sweep(pool).await;
    }

    /// Test 2: a SECOND tick appends another row per connection — the sweep records
    /// a time series, NOT a one-shot (no dedup, unlike the maintain scan).
    #[tokio::test]
    async fn connection_sweep_grows_time_series_no_dedup() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let id = "ic-sweep-test-cccc0003";
        seed_connection(pool, id, "API_KEY_C").await;

        let before = health_check_count(pool, id).await;

        let _ = seed_due_sweep_schedule(pool).await;
        let _ = tick_once(pool).await.unwrap();
        let after_first = health_check_count(pool, id).await;
        assert_eq!(after_first, before + 1, "first tick appends one row");

        // Re-plant a due sweep so it ACTUALLY runs a second time, proving the
        // sweep itself appends again (no per-connection dedup guard).
        let sched_id = seed_due_sweep_schedule(pool).await;
        let _ = tick_once(pool).await.unwrap();
        let after_second = health_check_count(pool, id).await;
        assert_eq!(
            after_second,
            before + 2,
            "a second tick appends another row (time series, not one-shot)"
        );

        cleanup_connection(pool, id).await;
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();
        restore_migration_sweep(pool).await;
    }

    /// Test 3: migration 120's seed is idempotent AND its seeded row matches the
    /// shipped contract. Re-running the seed INSERT is a clean no-op (ON CONFLICT),
    /// leaving exactly one row with the exact id/name/kind/interval/enabled/creator
    /// the migration ships — so a prior test leaving it disabled or a future
    /// retune of the seed is caught here, not silently.
    #[tokio::test]
    async fn migration_120_is_idempotent() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ('44444444-4444-4444-8444-444444444444', \
                     'Connection health sweep (all connections)', 'connection_health_sweep', \
                     300, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");

        // Exactly one row for the fixed id (no duplicate from the re-run).
        let seeded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM schedules WHERE id = '44444444-4444-4444-8444-444444444444'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            seeded, 1,
            "exactly one connection_health_sweep schedule is seeded"
        );

        // The seeded row matches the shipped migration contract verbatim. Asserting
        // enabled=TRUE here is the guard that catches any test (or future code) that
        // disables the production sweep and fails to restore it.
        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = '44444444-4444-4444-8444-444444444444'",
            )
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            name, "Connection health sweep (all connections)",
            "seed name"
        );
        assert_eq!(kind, "connection_health_sweep", "seed job_kind");
        assert_eq!(interval, 300, "seed interval_secs (5-minute cadence)");
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");
    }
}
