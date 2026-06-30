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

/// Policy window for `restore_overdue_scan` (#52): a system whose last SUCCESSFUL
/// restore test is older than this is flagged as overdue. Matches the
/// `overdue_after_days` default (90) of the #47 read endpoint. A single const,
/// easy to retune; the scan itself runs daily.
const RESTORE_OVERDUE_DAYS: i64 = 90;

/// Refresh window for `golden_image_stale_scan` (#60): a PROMOTED golden image whose
/// last build is older than this is flagged as stale (a missed monthly rebuild = missing
/// recent patches). 35 days = one month plus a few days of grace. A single const, easy to
/// retune; the scan itself runs daily.
const GOLDEN_IMAGE_STALE_DAYS: i32 = 35;

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
/// review via domain events), `connection_health_sweep` (appends a dry-run
/// health-check row per integration connection), and `restore_overdue_scan`
/// (enqueues a deduped shift_queue item per overdue/never-tested system). Every
/// write happens on `tx`, so a failure rolls back within the schedule's
/// savepoint.
///
/// A history table that the newest-N-per-partition retention prune can target. A
/// CLOSED SET (not a free string) so the table/partition/timestamp identifiers
/// `format!`'d into the prune SQL can only ever be one of these hardcoded triples
/// — never caller-supplied, so the dynamic SQL is injection-safe by construction.
#[derive(Debug, Clone, Copy)]
enum PruneTarget {
    JobExecutions,
    ConnectionHealthChecks,
    CheckResults,
}

impl PruneTarget {
    /// `(table, partition_column, timestamp_column)` — all compile-time literals.
    fn parts(self) -> (&'static str, &'static str, &'static str) {
        match self {
            PruneTarget::JobExecutions => ("job_executions", "schedule_id", "started_at"),
            PruneTarget::ConnectionHealthChecks => {
                ("connection_health_checks", "connection_id", "checked_at")
            }
            PruneTarget::CheckResults => ("check_results", "check_id", "executed_at"),
        }
    }
}

/// Generalized retention prune: keep the newest `keep_per_partition` rows PER the
/// target's partition column, delete at most `max_per_run` of the GLOBALLY OLDEST
/// over-cap rows this run. The per-run cap bounds the victim set so the first prune
/// of a large backlog never does one giant DELETE (WAL/locks/timeout); the backlog
/// drains over several runs, then steady-state deletes only the new over-cap rows.
/// Returns the number of rows deleted. Guards against a non-positive `keep`/`cap`
/// (which would otherwise delete everything). Identifiers come ONLY from the closed
/// `PruneTarget` enum, so the `format!`'d SQL is injection-safe.
async fn prune_history_newest_n(
    conn: &mut sqlx::PgConnection,
    target: PruneTarget,
    keep_per_partition: i64,
    max_per_run: i64,
) -> Result<u64, sqlx::Error> {
    if keep_per_partition <= 0 || max_per_run <= 0 {
        return Ok(0);
    }
    let (table, partition_col, ts_col) = target.parts();
    let sql = format!(
        "DELETE FROM {table} WHERE id IN ( \
            SELECT id FROM ( \
                SELECT id, {ts_col}, ROW_NUMBER() OVER ( \
                    PARTITION BY {partition_col} ORDER BY {ts_col} DESC NULLS LAST, id DESC \
                ) AS rn \
                FROM {table} \
            ) ranked WHERE rn > $1 \
            ORDER BY {ts_col} ASC, id ASC \
            LIMIT $2 \
        )"
    );
    let deleted = sqlx::query(&sql)
        .bind(keep_per_partition)
        .bind(max_per_run)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(deleted)
}

/// Thin wrapper over [`prune_history_newest_n`] for `job_executions` (keeps the
/// existing prune tests + call site unchanged).
async fn prune_job_executions(
    conn: &mut sqlx::PgConnection,
    keep_per_schedule: i64,
    max_per_run: i64,
) -> Result<u64, sqlx::Error> {
    prune_history_newest_n(
        conn,
        PruneTarget::JobExecutions,
        keep_per_schedule,
        max_per_run,
    )
    .await
}

/// Prune RESOLVED `shift_queue` items older than `retention_days`, capped at
/// `max_per_run`. A DIFFERENT shape than [`prune_history_newest_n`] (newest-N): an OPEN
/// item (`resolved = false`) is LIVE work and is NEVER pruned regardless of count or age.
/// `resolved = true AND resolved_at IS NULL` (a resolved row with no timestamp) is also
/// kept — there is no age anchor. The OUTER DELETE re-asserts the full predicate (not just
/// `id IN`) so the invariant holds even under a concurrent re-open. The per-run cap bounds
/// the DELETE so the first prune of a years-old backlog drains over several daily runs.
/// `shift_queue` has no append-only trigger and no inbound FK, so the DELETE is safe.
/// All SQL is constant; `retention_days`/`max_per_run` are bound params (no injection).
async fn prune_resolved_shift_queue(
    conn: &mut sqlx::PgConnection,
    retention_days: i64,
    max_per_run: i64,
) -> Result<u64, sqlx::Error> {
    if retention_days <= 0 || max_per_run <= 0 {
        return Ok(0);
    }
    let deleted = sqlx::query(
        "DELETE FROM shift_queue \
         WHERE resolved = true \
           AND resolved_at IS NOT NULL \
           AND resolved_at < NOW() - ($1::bigint * INTERVAL '1 day') \
           AND id IN ( \
               SELECT id FROM shift_queue \
               WHERE resolved = true AND resolved_at IS NOT NULL \
                 AND resolved_at < NOW() - ($1::bigint * INTERVAL '1 day') \
               ORDER BY resolved_at ASC, id ASC \
               LIMIT $2 \
           )",
    )
    .bind(retention_days)
    .bind(max_per_run)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(deleted)
}

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
        "restore_overdue_scan" => {
            // Safe-internal write (#52): READ restore-test recency across ALL
            // sites (the scheduler is a platform-wide internal principal, not
            // scoped, so site/env are None), classify each system with the PURE
            // engine, and enqueue ONE deduped shift_queue work item per AT-RISK
            // system. Reads restore_requests and writes only our own shift_queue
            // — NO provider/live call. All on `tx`, so a failure rolls back with
            // this schedule's savepoint. `detail` is kept aggregate-only (a
            // count) — never per-system ids — because it is surfaced via
            // /api/ops/scheduler/executions.
            let rows =
                crate::repos::restore_requests::restore_test_recency(&mut **tx, None, None).await?;
            let now_unix = chrono::Utc::now().timestamp();
            let overdue_after_secs = RESTORE_OVERDUE_DAYS * 86_400;
            let mut enqueued: u64 = 0;
            for row in &rows {
                // Skip a degenerate empty asset key (source_ci_key is NOT NULL but
                // has no non-empty CHECK in mig 007): enqueue_if_absent rejects an
                // empty key, and letting that `?` propagate would abort the WHOLE
                // tick on every scan — one malformed row poisoning fan-out for every
                // healthy system. Skip it instead (the recency aggregate would have
                // grouped it as a degenerate identity anyway).
                if row.source_ci_key.trim().is_empty() {
                    continue;
                }
                let last_unix = row.last_successful_test.map(|t| t.timestamp());
                let recency = ryuki_engine::backup_recency::classify_restore_recency(
                    last_unix,
                    now_unix,
                    overdue_after_secs,
                );
                if !recency.is_at_risk() {
                    continue;
                }
                let reason = recency.as_str();
                // source_ci_key is a config-item identifier (an asset key, not a
                // secret) — the same value the public #47 read endpoint returns.
                let title = format!("Restore test {reason}: {}", row.source_ci_key);
                // Title AND description both key off the single classifier verdict
                // (`recency`) so they can never diverge (codex): the verdict is the
                // one source of truth for overdue-vs-never-tested, not a second
                // read of the Option.
                let description = match recency {
                    ryuki_engine::backup_recency::RestoreTestRecency::NeverTested => format!(
                        "No successful restore test on record ({} request(s), 0 verified). \
                         Verify recoverability.",
                        row.total_requests
                    ),
                    _ => {
                        let last = row
                            .last_successful_test
                            .map(|t| t.to_rfc3339())
                            .unwrap_or_else(|| "unknown".to_string());
                        format!(
                            "No successful restore test in over {RESTORE_OVERDUE_DAYS} days \
                             (last success: {last}). Verify recoverability."
                        )
                    }
                };
                let metadata = serde_json::json!({
                    "source_ci_key": row.source_ci_key,
                    "last_successful_test": row.last_successful_test.map(|t| t.to_rfc3339()),
                    "successful_test_count": row.successful_test_count,
                    "reason": reason,
                })
                .to_string();
                enqueued += crate::repos::shift_queue::enqueue_if_absent(
                    &mut **tx,
                    crate::repos::shift_queue::RESTORE_OVERDUE_ITEM_TYPE,
                    &row.source_ci_key,
                    &title,
                    &description,
                    "P2",
                    &metadata,
                )
                .await?;
            }
            // Second signal (#52 slice 2): systems whose MOST RECENT restore test
            // FAILED — a known, fresh recoverability failure (vs merely stale).
            // Blank asset keys are skipped PER-ROW below (in Rust, matching
            // enqueue_if_absent's trim()), so any whitespace key is excluded. A
            // system can receive BOTH an overdue AND a failed item (distinct
            // signals, distinct item_types); dedup is per item_type.
            let failed = crate::repos::restore_requests::latest_failed_systems(&mut **tx).await?;
            let mut failed_enqueued: u64 = 0;
            for source_ci_key in &failed {
                // Skip a blank asset key with the SAME trim() check enqueue_if_absent
                // uses, so a tab/newline/space-only key can never abort the tick
                // (mirrors the overdue arm). The query no longer SQL-filters blanks.
                if source_ci_key.trim().is_empty() {
                    continue;
                }
                let title = format!("Restore test FAILED (latest): {source_ci_key}");
                let description = "The most recent restore test for this system FAILED. \
                                   Investigate recoverability."
                    .to_string();
                let metadata = serde_json::json!({
                    "source_ci_key": source_ci_key,
                    "reason": "failed_latest",
                })
                .to_string();
                failed_enqueued += crate::repos::shift_queue::enqueue_if_absent(
                    &mut **tx,
                    crate::repos::shift_queue::RESTORE_FAILED_ITEM_TYPE,
                    source_ci_key,
                    &title,
                    &description,
                    "P2",
                    &metadata,
                )
                .await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!(
                    "enqueued {enqueued} overdue, {failed_enqueued} failed restore item(s)"
                )),
            ))
        }
        "dr_test_overdue_scan" => {
            // Safe-internal write (#58): READ dr_plans (active/approved) across all
            // sites, flag plans whose next_test_due is in the PAST, and enqueue ONE
            // deduped shift_queue item per overdue plan. Reads dr_plans and writes
            // only our own shift_queue — NO provider/live/destructive call. All on
            // `tx`, so a failure rolls back with this schedule's savepoint. `detail`
            // is aggregate-only (counts, never per-plan ids) because it is surfaced
            // via /api/ops/scheduler/executions.
            let rows =
                crate::repos::dr_plans::active_plans_for_overdue_scan(&mut **tx).await?;
            let now = chrono::Utc::now();
            let mut overdue: u64 = 0;
            let mut enqueued: u64 = 0;
            for row in rows {
                // Fail-safe per-row: a single corrupt `plan_json` that won't
                // deserialize to a DrPlan is SKIPPED, not propagated — one malformed
                // persisted row must NOT abort the scan for every healthy plan (the
                // corruption still surfaces on the DR read endpoints, which decode the
                // same blob). Mirrors restore_overdue_scan's per-row resilience.
                let Ok(plan) = row.into_model() else {
                    continue;
                };
                // A blank id can't be a dedup key (enqueue_if_absent rejects it) and
                // would otherwise abort this scan — skip it (mirrors restore's blank-key
                // skip). The TEXT PK forbids NULL but not '' for a directly-imported row.
                if plan.id.trim().is_empty() {
                    continue;
                }
                // An unparseable/empty next_test_due on an otherwise-valid plan is
                // SKIPPED for the same reason.
                let Ok(due) = chrono::DateTime::parse_from_rfc3339(plan.next_test_due.trim())
                else {
                    continue;
                };
                if due.with_timezone(&chrono::Utc) > now {
                    continue; // not yet due
                }
                overdue += 1;
                let title = format!("DR test overdue: {}", plan.name);
                let last = plan.last_tested.as_deref().unwrap_or("never");
                let description = format!(
                    "DR plan '{}' ({}) is overdue for a recoverability test (due {}, last tested {}). \
                     Schedule a DR test to verify recoverability.",
                    plan.name, plan.site, plan.next_test_due, last
                );
                // `source_ci_key` is the plan id — the enqueue_if_absent dedup predicate
                // checks `metadata->>'source_ci_key'`, so it MUST appear there too for the
                // partial unique index (uq_shift_queue_open_dr_test_overdue) to agree.
                let metadata = serde_json::json!({
                    "source_ci_key": plan.id,
                    "site": plan.site,
                    "next_test_due": plan.next_test_due,
                    "last_tested": plan.last_tested,
                })
                .to_string();
                enqueued += crate::repos::shift_queue::enqueue_if_absent(
                    &mut **tx,
                    crate::repos::shift_queue::DR_TEST_OVERDUE_ITEM_TYPE,
                    &plan.id,
                    &title,
                    &description,
                    "P2",
                    &metadata,
                )
                .await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!("{overdue} DR plan(s) overdue, {enqueued} enqueued")),
            ))
        }
        "patch_wave_overdue_scan" => {
            // Safe-internal write (#59): READ patch_waves in status 'Scheduled' (each
            // committed to start at schedule->>'start'), flag any whose start is in the
            // PAST — a MISSED patch window (scheduled but never moved to InProgress) —
            // and enqueue ONE deduped shift_queue item per missed wave. Reads patch_waves
            // and writes only our own shift_queue — NO provider/live/destructive call.
            // All on `tx`, so a failure rolls back with this schedule's savepoint.
            // `detail` is aggregate-only (counts, never per-wave ids) because it is
            // surfaced via /api/ops/scheduler/executions.
            let waves =
                crate::repos::patch_waves::scheduled_waves_for_overdue_scan(&mut **tx).await?;
            let now = chrono::Utc::now();
            let mut overdue: u64 = 0;
            let mut enqueued: u64 = 0;
            for wave in waves {
                // A blank id can't be a dedup key (enqueue_if_absent rejects it) — skip it.
                if wave.id.trim().is_empty() {
                    continue;
                }
                // Fail-safe per-row: a missing/unparseable schedule start is SKIPPED so
                // one bad row can never abort the scan (mirrors dr_test_overdue_scan).
                let Ok(start) = chrono::DateTime::parse_from_rfc3339(wave.scheduled_start.trim())
                else {
                    continue;
                };
                if start.with_timezone(&chrono::Utc) > now {
                    continue; // window not yet reached
                }
                overdue += 1;
                // Wave name defaults to '' in the schema — fall back to the id for a
                // legible work-item title.
                let label = if wave.name.trim().is_empty() {
                    wave.id.as_str()
                } else {
                    wave.name.as_str()
                };
                let title = format!("Patch wave overdue: {label}");
                let description = format!(
                    "Patch wave '{label}' was scheduled to start at {} but is still in \
                     status 'Scheduled' — its maintenance window has passed. Investigate \
                     or reschedule.",
                    wave.scheduled_start
                );
                // `source_ci_key` is the wave id — the enqueue_if_absent dedup predicate
                // checks `metadata->>'source_ci_key'`, so it MUST appear there too for the
                // partial unique index (uq_shift_queue_open_patch_wave_overdue) to agree.
                let metadata = serde_json::json!({
                    "source_ci_key": wave.id,
                    "scheduled_start": wave.scheduled_start,
                })
                .to_string();
                enqueued += crate::repos::shift_queue::enqueue_if_absent(
                    &mut **tx,
                    crate::repos::shift_queue::PATCH_WAVE_OVERDUE_ITEM_TYPE,
                    &wave.id,
                    &title,
                    &description,
                    "P2",
                    &metadata,
                )
                .await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!("{overdue} patch wave(s) overdue, {enqueued} enqueued")),
            ))
        }
        "golden_image_stale_scan" => {
            // Safe-internal write (#60): READ promoted golden images whose build_date is
            // older than the monthly refresh window (GOLDEN_IMAGE_STALE_DAYS) — the live
            // base image has missed its rebuild and lacks recent patches — and enqueue ONE
            // deduped shift_queue item per stale image. Reads golden_images, writes only
            // our own shift_queue — NO provider/live/destructive call. The SQL date filter
            // does the staleness selection on the real build_date column (no parse). All on
            // `tx` (rolls back with this schedule's savepoint). `detail` is aggregate-only
            // (counts, never per-image ids) — surfaced via /api/ops/scheduler/executions.
            let stale = crate::repos::golden_images::stale_promoted_images(
                &mut **tx,
                GOLDEN_IMAGE_STALE_DAYS,
            )
            .await?;
            let mut enqueued: u64 = 0;
            for img in &stale {
                // A blank id can't be a dedup key (enqueue_if_absent rejects it) — skip it.
                if img.id.trim().is_empty() {
                    continue;
                }
                let title = format!("Golden image stale: {}", img.image_name);
                let description = format!(
                    "Golden image '{}' ({}) was last built {} — over {GOLDEN_IMAGE_STALE_DAYS} \
                     days ago, past its monthly refresh window. Rebuild to pick up recent \
                     patches.",
                    img.image_name,
                    img.site_scope,
                    img.build_date.to_rfc3339()
                );
                // `source_ci_key` is the image id — the enqueue_if_absent dedup predicate
                // checks `metadata->>'source_ci_key'`, so it MUST appear there too for the
                // partial unique index (uq_shift_queue_open_golden_image_stale) to agree.
                let metadata = serde_json::json!({
                    "source_ci_key": img.id,
                    "image_name": img.image_name,
                    "site_scope": img.site_scope,
                    "build_date": img.build_date.to_rfc3339(),
                })
                .to_string();
                // P3: staleness is a refresh hygiene reminder, lower urgency than a missed
                // maintenance window or overdue recoverability test (which are P2).
                enqueued += crate::repos::shift_queue::enqueue_if_absent(
                    &mut **tx,
                    crate::repos::shift_queue::GOLDEN_IMAGE_STALE_ITEM_TYPE,
                    &img.id,
                    &title,
                    &description,
                    "P3",
                    &metadata,
                )
                .await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!(
                    "{} golden image(s) stale, {enqueued} enqueued",
                    stale.len()
                )),
            ))
        }
        "noise_suppression_expiry_scan" => {
            // Safe-internal write (#61): a suppression is a TIME-BOXED mute — once its
            // `suppress_until` window elapses the trigger must return to the active board
            // so its noise is visible again. Flip every noisy_trigger that is status
            // 'Suppressed' AND whose `suppress_until` is in the PAST (<= NOW()) back to
            // 'Active', clearing `suppress_until`. Mutates ONLY our own noisy_triggers
            // table — NO provider/live/destructive call. The expiry predicate runs in SQL
            // on the real `suppress_until` TIMESTAMPTZ column (no string parse, no per-row
            // fail-safe needed: the UPDATE touches only already-expired rows and is
            // naturally idempotent — once 'Active' a row never re-matches). `suppress_until
            // IS NOT NULL` is semantically redundant with `<= NOW()` (NULL never compares
            // true) but documents that indefinite suppressions are deliberately left alone.
            // All on `tx`, so a failure rolls back with this schedule's savepoint. `detail`
            // is aggregate-only (a count) — surfaced via /api/ops/scheduler/executions.
            let reverted = sqlx::query(
                "UPDATE noisy_triggers \
                 SET status = 'Active', suppress_until = NULL, updated_at = NOW() \
                 WHERE status = 'Suppressed' AND suppress_until IS NOT NULL \
                   AND suppress_until <= NOW()",
            )
            .execute(&mut **tx)
            .await?
            .rows_affected();
            Ok((
                "succeeded".to_string(),
                Some(format!(
                    "{reverted} expired suppression(s) reverted to Active"
                )),
            ))
        }
        "secret_rotation_due_scan" => {
            // Safe-internal write (#7): READ secret rotation metadata across ALL sites
            // (platform-wide internal principal — not scoped), classify each with the
            // PURE engine, and enqueue ONE deduped shift_queue item per OVERDUE secret.
            // Reads managed_secrets and writes only our own shift_queue — NO Vault/live
            // call. All on `tx` (rolls back with this schedule's savepoint). `detail` is
            // aggregate-only (counts), never per-secret data — it is surfaced via
            // /api/ops/scheduler/executions. SELECTs ONLY non-sensitive columns — NEVER
            // `vault_path` (a Vault pointer) or `secret_type`. Excludes `retired`
            // (decommissioned) and `rotating` (a rotation in flight — its stale past due
            // date would be a spurious duplicate); `expired`/`failed` ARE kept (overdue,
            // need attention).
            #[derive(sqlx::FromRow)]
            struct SecretScanRow {
                id: String,
                name: String,
                next_rotation_due: String,
                site: String,
                owner: String,
            }
            let rows: Vec<SecretScanRow> = sqlx::query_as(
                "SELECT id, name, next_rotation_due, site, owner FROM managed_secrets \
                 WHERE status NOT IN ('retired', 'rotating') ORDER BY id",
            )
            .fetch_all(&mut **tx)
            .await?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let mut overdue: u64 = 0;
            let mut invalid: u64 = 0;
            for row in &rows {
                // Skip a degenerate empty id with the SAME trim() check
                // enqueue_if_absent uses, so it can never abort the tick.
                if row.id.trim().is_empty() {
                    continue;
                }
                match chrono::DateTime::parse_from_rfc3339(&row.next_rotation_due) {
                    Ok(due) => {
                        // Compare in MILLIS so a fractional-second due time is not marked
                        // overdue ~1s early (codex). Future → skip; reached/passed → enqueue.
                        let recency =
                            ryuki_engine::secrets_rotation::classify_secret_rotation_recency(
                                due.timestamp_millis(),
                                now_ms,
                            );
                        if !recency.is_due() {
                            continue;
                        }
                        // name/site/owner are operator-facing work fields (not secret
                        // material); vault_path/secret_type are NEVER surfaced.
                        let title = format!("Secret rotation overdue: {}", row.name);
                        let description = format!(
                            "Secret '{}' ({}, owner {}) is overdue for rotation \
                             (due {}). Rotate it.",
                            row.name, row.site, row.owner, row.next_rotation_due
                        );
                        let metadata = serde_json::json!({
                            "source_ci_key": row.id,
                            "name": row.name,
                            "site": row.site,
                            "owner": row.owner,
                            "next_rotation_due": row.next_rotation_due,
                            "reason": "overdue",
                        })
                        .to_string();
                        overdue += crate::repos::shift_queue::enqueue_if_absent(
                            &mut **tx,
                            crate::repos::shift_queue::SECRET_ROTATION_DUE_ITEM_TYPE,
                            &row.id,
                            &title,
                            &description,
                            "P2",
                            &metadata,
                        )
                        .await?;
                    }
                    Err(_) => {
                        // Second signal (codex MAJOR): a malformed next_rotation_due is a
                        // data-integrity problem — SURFACE it as its own deduped item
                        // rather than silently skipping (a permanent blind spot). The bad
                        // value is a (corrupt) date string, not secret material.
                        let title = format!("Secret rotation date invalid: {}", row.name);
                        let description = format!(
                            "Secret '{}' ({}, owner {}) has an unparseable \
                             next_rotation_due ('{}'). Fix its rotation schedule.",
                            row.name, row.site, row.owner, row.next_rotation_due
                        );
                        let metadata = serde_json::json!({
                            "source_ci_key": row.id,
                            "name": row.name,
                            "site": row.site,
                            "owner": row.owner,
                            "invalid_next_rotation_due": row.next_rotation_due,
                            "reason": "invalid-due-date",
                        })
                        .to_string();
                        invalid += crate::repos::shift_queue::enqueue_if_absent(
                            &mut **tx,
                            crate::repos::shift_queue::SECRET_ROTATION_INVALID_ITEM_TYPE,
                            &row.id,
                            &title,
                            &description,
                            "P2",
                            &metadata,
                        )
                        .await?;
                    }
                }
            }
            Ok((
                "succeeded".to_string(),
                Some(format!(
                    "enqueued {overdue} overdue, {invalid} invalid secret rotation item(s)"
                )),
            ))
        }
        "legal_hold_expiry_scan" => {
            // Safe-internal write (#17): surface Active legal holds within 30 days of (or
            // past) their expiry as deduped shift_queue work — mirrors the on-demand
            // /api/protect/legal-hold/expiring predicate. Reads legal_holds, writes only
            // our own shift_queue — NO state change to the hold (releasing/expiring a hold
            // is a deliberate audited human action). All on `tx`. SECRET HYGIENE: the
            // SELECT NEVER reads `reason` (sensitive litigation/investigation free text)
            // or `audit_trail` — only operator-triage identity. Shift-queue readers are
            // `execute`-tier ⊆ the `audit`-tier legal-hold readers, so name/type are safe.
            #[derive(sqlx::FromRow)]
            struct LegalHoldScanRow {
                id: String,
                server_or_app_name: String,
                hold_type: String,
                expiry_date: chrono::DateTime<chrono::Utc>,
                site: String,
            }
            // The DB filters to the actionable window (TIMESTAMPTZ <= NOW()+30d — safe,
            // no string cast). The classifier then sets expired-vs-soon AND double-guards
            // against DB/Rust clock skew (codex MAJOR: a near-edge row that classifies
            // Active is skipped — a queue item never carries an `active` verdict).
            let rows: Vec<LegalHoldScanRow> = sqlx::query_as(
                "SELECT id, server_or_app_name, hold_type, expiry_date, site FROM legal_holds \
                 WHERE status = 'Active' AND expiry_date <= NOW() + INTERVAL '30 days' \
                 ORDER BY id",
            )
            .fetch_all(&mut **tx)
            .await?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let soon_window_ms: i64 = 30 * 86_400_000;
            let mut enqueued: u64 = 0;
            for row in &rows {
                if row.id.trim().is_empty() {
                    continue;
                }
                let verdict = ryuki_engine::legal_hold::classify_legal_hold_expiry(
                    row.expiry_date.timestamp_millis(),
                    now_ms,
                    soon_window_ms,
                );
                // Belt-and-suspenders against clock skew: never enqueue a non-actionable
                // (active) verdict even if SQL selected it near the window edge.
                if !verdict.is_actionable() {
                    continue;
                }
                let state = verdict.as_str();
                // server_or_app_name + hold_type are operator-triage identity (safe for
                // the execute-tier queue); the hold `reason`/`audit_trail` are NEVER here.
                let title = format!("Legal hold {state}: {}", row.server_or_app_name);
                let description = format!(
                    "{} legal hold on '{}' ({}, {}) — expiry {}. Decide to release or extend.",
                    row.hold_type,
                    row.server_or_app_name,
                    row.site,
                    state,
                    row.expiry_date.to_rfc3339()
                );
                let metadata = serde_json::json!({
                    "source_ci_key": row.id,
                    "name": row.server_or_app_name,
                    "hold_type": row.hold_type,
                    "site": row.site,
                    "expiry_date": row.expiry_date.to_rfc3339(),
                    // `expiry_state` (NOT `reason`) — legal_holds has a sensitive `reason`
                    // column, so the verdict uses a distinct key (codex MINOR).
                    "expiry_state": state,
                })
                .to_string();
                enqueued += crate::repos::shift_queue::enqueue_if_absent(
                    &mut **tx,
                    crate::repos::shift_queue::LEGAL_HOLD_EXPIRY_ITEM_TYPE,
                    &row.id,
                    &title,
                    &description,
                    "P2",
                    &metadata,
                )
                .await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!("enqueued {enqueued} expiring legal hold(s)")),
            ))
        }
        "recertification_overdue_scan" => {
            // Safe-internal write (#12): surface Active recertification campaigns past their
            // end_date as deduped shift_queue work — mirrors legal_hold_expiry_scan. Reads
            // recertification_campaigns, writes only our own shift_queue — NO state change to the
            // campaign and NO access revocation / provider change (the recertification system is
            // deliberately review-only: "no-live-access-changes"). recertification_campaigns has
            // NO sensitive free-text column, so the surfaced governance metadata (name / type /
            // reviewer group / counts / dates) is safe for the execute-tier queue.
            #[derive(sqlx::FromRow)]
            struct RecertScanRow {
                id: String,
                name: String,
                start_date: chrono::DateTime<chrono::Utc>,
                end_date: chrono::DateTime<chrono::Utc>,
                review_type: String,
                reviewer_group: String,
                reviews_count: i32,
                completed_count: i32,
            }
            // `end_date <= NOW()` is a SUPERSET of the `>=` classifier; the classifier then
            // double-guards against DB/Rust clock skew (a near-edge row that the CP clock says is
            // not-yet-due is skipped — a queue item never carries a non-actionable verdict).
            let rows: Vec<RecertScanRow> = sqlx::query_as(
                "SELECT id, name, start_date, end_date, review_type, reviewer_group, \
                        reviews_count, completed_count \
                 FROM recertification_campaigns \
                 WHERE status = 'Active' AND end_date <= NOW() ORDER BY id",
            )
            .fetch_all(&mut **tx)
            .await?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let mut enqueued: u64 = 0;
            for row in &rows {
                if row.id.trim().is_empty() {
                    continue;
                }
                let verdict =
                    ryuki_engine::access_recertification::classify_recertification_overdue(
                        row.end_date.timestamp_millis(),
                        now_ms,
                    );
                if !verdict.is_actionable() {
                    continue;
                }
                // INSTANCE-specific dedup key (codex): a reused campaign id never lets a stale
                // item suppress a new overdue campaign; stable across a deadline extension
                // (start_date does not move). Microsecond precision matches the stored
                // TIMESTAMPTZ exactly (codex MINOR).
                let source_ci_key = format!("{}@{}", row.id, row.start_date.timestamp_micros());
                let title = format!("Recertification overdue: {}", row.name);
                let description = format!(
                    "{} campaign '{}' (reviewer group {}) blew its recertification deadline {} — \
                     {}/{} reviews complete. Review and close it.",
                    row.review_type,
                    row.name,
                    row.reviewer_group,
                    row.end_date.to_rfc3339(),
                    row.completed_count,
                    row.reviews_count,
                );
                let metadata = serde_json::json!({
                    "source_ci_key": source_ci_key,
                    "campaign_id": row.id,
                    "name": row.name,
                    "review_type": row.review_type,
                    "reviewer_group": row.reviewer_group,
                    "start_date": row.start_date.to_rfc3339(),
                    "end_date": row.end_date.to_rfc3339(),
                    "reviews_count": row.reviews_count,
                    "completed_count": row.completed_count,
                    "due_state": verdict.as_str(),
                })
                .to_string();
                enqueued += crate::repos::shift_queue::enqueue_if_absent(
                    &mut **tx,
                    crate::repos::shift_queue::RECERTIFICATION_OVERDUE_ITEM_TYPE,
                    &source_ci_key,
                    &title,
                    &description,
                    "P2",
                    &metadata,
                )
                .await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!(
                    "enqueued {enqueued} overdue recertification campaign(s)"
                )),
            ))
        }
        "certificate_expiry_scan" => {
            // Safe-internal write (run-3): surface TLS certs within (or past) the 30-day
            // actionable window as deduped shift_queue work — mirrors legal_hold_expiry_scan.
            // Reads certificates, writes only our own shift_queue — NO cert mutation (renewal /
            // revoke stays a deliberate action). `certificates` holds only cert METADATA (no
            // private key), so every surfaced field is safe for the execute-tier queue.
            #[derive(sqlx::FromRow)]
            struct CertScanRow {
                id: String,
                common_name: String,
                hostname: String,
                service_type: String,
                site: String,
                valid_to: chrono::DateTime<chrono::Utc>,
                status: String,
            }
            // Predicate on valid_to (NOT the un-synced status column): a genuinely-past cert is
            // surfaced even if its stored status is stale.
            let rows: Vec<CertScanRow> = sqlx::query_as(
                "SELECT id::text, common_name, hostname, service_type, site, valid_to, status \
                 FROM certificates WHERE valid_to <= NOW() + INTERVAL '30 days' ORDER BY valid_to",
            )
            .fetch_all(&mut **tx)
            .await?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let soon_window_ms: i64 = 30 * 86_400_000;
            let mut enqueued: u64 = 0;
            for row in &rows {
                if row.id.trim().is_empty() {
                    continue;
                }
                let verdict = ryuki_engine::certificate_lifecycle::classify_certificate_expiry(
                    row.valid_to.timestamp_millis(),
                    now_ms,
                    soon_window_ms,
                );
                if !verdict.is_actionable() {
                    continue;
                }
                let state = verdict.as_str();
                // Priority by state: an expired cert is an outage NOW (P1); expiring-soon is P2.
                let priority = if matches!(
                    verdict,
                    ryuki_engine::certificate_lifecycle::CertificateExpiry::Expired
                ) {
                    "P1"
                } else {
                    "P2"
                };
                let title = format!("Certificate {state}: {}", row.common_name);
                let description = format!(
                    "{} certificate '{}' on {} ({}) — valid_to {}. Renew or replace it.",
                    row.service_type,
                    row.common_name,
                    row.hostname,
                    row.site,
                    row.valid_to.to_rfc3339(),
                );
                let metadata = serde_json::json!({
                    "source_ci_key": row.id,
                    "common_name": row.common_name,
                    "hostname": row.hostname,
                    "service_type": row.service_type,
                    "site": row.site,
                    "valid_to": row.valid_to.to_rfc3339(),
                    "cert_status": row.status,
                    "expiry_state": state,
                })
                .to_string();
                enqueued += crate::repos::shift_queue::enqueue_if_absent(
                    &mut **tx,
                    crate::repos::shift_queue::CERTIFICATE_EXPIRY_ITEM_TYPE,
                    &row.id,
                    &title,
                    &description,
                    priority,
                    &metadata,
                )
                .await?;
                // REFRESH the OPEN item to the CURRENT state so an expiring-soon item upgrades to
                // expired (and P2→P1) on a later scan — enqueue_if_absent's ON CONFLICT DO NOTHING
                // would otherwise leave the first-seen label/priority stale (codex).
                sqlx::query(
                    "UPDATE shift_queue \
                     SET title = $2, description = $3, priority = $4, metadata = $5::jsonb, \
                         updated_at = NOW() \
                     WHERE item_type = 'certificate-expiring' AND resolved = false \
                       AND metadata->>'source_ci_key' = $1",
                )
                .bind(&row.id)
                .bind(&title)
                .bind(&description)
                .bind(priority)
                .bind(&metadata)
                .execute(&mut **tx)
                .await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!(
                    "enqueued {enqueued} expiring/expired certificate(s)"
                )),
            ))
        }
        "gmsa_expiry_scan" => {
            // Safe-internal write (run-3): surface gMSA accounts whose managed-password rotation
            // deadline (last_rotation_at + managed_password_interval_days) is within (or past) a
            // 7-day window as deduped shift_queue work — mirrors certificate_expiry_scan. Reads
            // gmsa_accounts, writes only shift_queue — NO gMSA mutation. The gMSA PASSWORD is never
            // in this table, so every surfaced field is safe for the execute-tier queue.
            #[derive(sqlx::FromRow)]
            struct GmsaScanRow {
                id: String,
                name: String,
                sam_account_name: String,
                site: String,
                status: String,
                next_rotation: chrono::DateTime<chrono::Utc>,
            }
            // Predicate on the COMPUTED next_rotation (NOT the un-synced status column);
            // `managed_password_interval_days > 0` keeps bad data (0/negative interval) from
            // becoming permanent overdue noise (codex). The SQL predicate (DB NOW()) is a COARSE
            // PREFILTER; the pure classifier (CP clock) is the AUTHORITATIVE actionability guard.
            // The prefilter window is 8 days while the classifier window is 7, so the prefilter is
            // a strict SUPERSET of the actionable set — even a ~1h DST calendar-vs-86.4Mms-day drift
            // (if the DB ran off UTC) cannot push a 7-day-actionable row outside the 8-day prefilter,
            // so no actionable row is ever missed; the classifier discards the 7–8 day rows as
            // Current (codex).
            let rows: Vec<GmsaScanRow> = sqlx::query_as(
                "SELECT id::text, name, sam_account_name, site, status, \
                        (last_rotation_at + managed_password_interval_days * INTERVAL '1 day') \
                          AS next_rotation \
                 FROM gmsa_accounts \
                 WHERE status <> 'Revoked' AND managed_password_interval_days > 0 \
                   AND last_rotation_at + managed_password_interval_days * INTERVAL '1 day' \
                         <= NOW() + INTERVAL '8 days' \
                 ORDER BY next_rotation",
            )
            .fetch_all(&mut **tx)
            .await?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let soon_window_ms: i64 = 7 * 86_400_000;
            let mut enqueued: u64 = 0;
            for row in &rows {
                if row.id.trim().is_empty() {
                    continue;
                }
                let verdict = ryuki_engine::gmsa_lifecycle::classify_gmsa_expiry(
                    row.next_rotation.timestamp_millis(),
                    now_ms,
                    soon_window_ms,
                );
                if !verdict.is_actionable() {
                    continue;
                }
                let state = verdict.as_str();
                // Overdue → P2 (security-hygiene degradation, not an outage like an expired cert);
                // due-soon → P3.
                let priority = if matches!(
                    verdict,
                    ryuki_engine::gmsa_lifecycle::GmsaExpiry::Overdue
                ) {
                    "P2"
                } else {
                    "P3"
                };
                let title = format!("gMSA rotation {state}: {}", row.name);
                let description = format!(
                    "gMSA '{}' ({}) at {} — managed-password rotation due {}. Verify AD-side \
                     auto-rotation is occurring and refresh the control-plane record.",
                    row.name,
                    row.sam_account_name,
                    row.site,
                    row.next_rotation.to_rfc3339(),
                );
                let metadata = serde_json::json!({
                    "source_ci_key": row.id,
                    "name": row.name,
                    "sam_account_name": row.sam_account_name,
                    "site": row.site,
                    "next_rotation": row.next_rotation.to_rfc3339(),
                    "gmsa_status": row.status,
                    "expiry_state": state,
                })
                .to_string();
                enqueued += crate::repos::shift_queue::enqueue_if_absent(
                    &mut **tx,
                    crate::repos::shift_queue::GMSA_EXPIRY_ITEM_TYPE,
                    &row.id,
                    &title,
                    &description,
                    priority,
                    &metadata,
                )
                .await?;
                // REFRESH the OPEN item to the CURRENT state so a due-soon item upgrades to overdue
                // (and P3→P2) on a later scan — enqueue_if_absent's ON CONFLICT DO NOTHING would
                // otherwise leave the first-seen label/priority stale (codex).
                sqlx::query(
                    "UPDATE shift_queue \
                     SET title = $2, description = $3, priority = $4, metadata = $5::jsonb, \
                         updated_at = NOW() \
                     WHERE item_type = 'gmsa-expiring' AND resolved = false \
                       AND metadata->>'source_ci_key' = $1",
                )
                .bind(&row.id)
                .bind(&title)
                .bind(&description)
                .bind(priority)
                .bind(&metadata)
                .execute(&mut **tx)
                .await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!(
                    "enqueued {enqueued} overdue/due-soon gMSA rotation(s)"
                )),
            ))
        }
        "oob_cert_expiry_scan" => {
            // Safe-internal write (run-3): surface out-of-band (iLO/iDRAC/IPMI) management endpoints
            // whose TLS cert is within (or past) a 30-day window as deduped shift_queue work —
            // mirrors certificate_expiry_scan and REUSES its pure classifier (same TLS-cert-expiry
            // shape). Reads oob_endpoints, writes only shift_queue — NO OOB mutation. The surfaced
            // fields are operational identity (no IPMI/cred), so all safe for the execute-tier queue.
            #[derive(sqlx::FromRow)]
            struct OobScanRow {
                id: String,
                endpoint_type: String,
                hostname: String,
                site: String,
                cert_expiry: chrono::DateTime<chrono::Utc>,
            }
            // Predicate on cert_expiry (NOT the possibly-stale `certificate_valid` boolean — the
            // cert-scan lesson). The SQL predicate (DB NOW(), 31-day window) is a COARSE PREFILTER
            // that is a strict SUPERSET of the 30-day classifier window — so a ~1h DST drift can't
            // drop a 30-day-actionable row (the gMSA lesson); the pure classifier (CP clock) is the
            // authoritative guard, discarding the 30–31 day rows as Valid.
            let rows: Vec<OobScanRow> = sqlx::query_as(
                "SELECT id::text, endpoint_type, hostname, site, cert_expiry \
                 FROM oob_endpoints \
                 WHERE cert_expiry <= NOW() + INTERVAL '31 days' \
                 ORDER BY cert_expiry",
            )
            .fetch_all(&mut **tx)
            .await?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let soon_window_ms: i64 = 30 * 86_400_000;
            let mut enqueued: u64 = 0;
            for row in &rows {
                if row.id.trim().is_empty() {
                    continue;
                }
                let verdict = ryuki_engine::certificate_lifecycle::classify_certificate_expiry(
                    row.cert_expiry.timestamp_millis(),
                    now_ms,
                    soon_window_ms,
                );
                if !verdict.is_actionable() {
                    continue;
                }
                let state = verdict.as_str();
                // Expired → P2, expiring-soon → P3. An OOB cert covers INTERNAL management access
                // (a security/access degradation), NOT a user-facing outage like a public cert — so
                // P2, not the cert scan's P1.
                let priority = if matches!(
                    verdict,
                    ryuki_engine::certificate_lifecycle::CertificateExpiry::Expired
                ) {
                    "P2"
                } else {
                    "P3"
                };
                let title = format!("OOB cert {state}: {} ({})", row.hostname, row.endpoint_type);
                let description = format!(
                    "Out-of-band management endpoint '{}' ({}) at {} — TLS cert_expiry {}. Rotate \
                     the OOB management certificate before secure access lapses.",
                    row.hostname,
                    row.endpoint_type,
                    row.site,
                    row.cert_expiry.to_rfc3339(),
                );
                let metadata = serde_json::json!({
                    "source_ci_key": row.id,
                    "endpoint_type": row.endpoint_type,
                    "hostname": row.hostname,
                    "site": row.site,
                    "cert_expiry": row.cert_expiry.to_rfc3339(),
                    "expiry_state": state,
                })
                .to_string();
                enqueued += crate::repos::shift_queue::enqueue_if_absent(
                    &mut **tx,
                    crate::repos::shift_queue::OOB_CERT_EXPIRY_ITEM_TYPE,
                    &row.id,
                    &title,
                    &description,
                    priority,
                    &metadata,
                )
                .await?;
                // REFRESH the OPEN item to the CURRENT state so an expiring-soon item upgrades to
                // expired (and P3→P2) on a later scan — enqueue_if_absent's ON CONFLICT DO NOTHING
                // would otherwise leave the first-seen label/priority stale (codex).
                sqlx::query(
                    "UPDATE shift_queue \
                     SET title = $2, description = $3, priority = $4, metadata = $5::jsonb, \
                         updated_at = NOW() \
                     WHERE item_type = 'oob-cert-expiring' AND resolved = false \
                       AND metadata->>'source_ci_key' = $1",
                )
                .bind(&row.id)
                .bind(&title)
                .bind(&description)
                .bind(priority)
                .bind(&metadata)
                .execute(&mut **tx)
                .await?;
            }
            Ok((
                "succeeded".to_string(),
                Some(format!(
                    "enqueued {enqueued} expiring/expired OOB management cert(s)"
                )),
            ))
        }
        "job_executions_prune" => {
            // Safe-internal write (run-3): bound the unbounded job_executions run history (a row
            // per tick — the 5-min connection_health_sweep alone is 288/day) by keeping the newest
            // KEEP_PER_SCHEDULE rows PER schedule. A PER-RUN CAP keeps the first prune of a years-old
            // backlog from doing one giant DELETE; a large backlog drains over a few daily runs.
            // KEEP is sized to the FASTEST cadence (5-min → ~35 days at 10000); slower schedules
            // over-retain harmlessly (rows are tiny) but stay bounded.
            const KEEP_PER_SCHEDULE: i64 = 10_000;
            const MAX_PER_RUN: i64 = 20_000;
            let pruned = prune_job_executions(tx, KEEP_PER_SCHEDULE, MAX_PER_RUN).await?;
            Ok((
                "succeeded".to_string(),
                Some(format!("pruned {pruned} old job_executions row(s)")),
            ))
        }
        "connection_health_checks_prune" => {
            // Safe-internal write (run-3): bound the FASTEST-growing history table — the 5-min
            // connection_health_sweep appends one row PER connection PER sweep (~288/day/connection).
            // Keep the newest KEEP_PER_CONNECTION per connection_id. Runs HOURLY (NOT daily like the
            // job_executions prune) so the per-run cap keeps up with per-connection growth
            // (#connections × 12/hour ≤ cap covers ~1666 connections) with gentle per-run deletes.
            const KEEP_PER_CONNECTION: i64 = 10_000;
            const MAX_PER_RUN: i64 = 20_000;
            let pruned = prune_history_newest_n(
                tx,
                PruneTarget::ConnectionHealthChecks,
                KEEP_PER_CONNECTION,
                MAX_PER_RUN,
            )
            .await?;
            Ok((
                "succeeded".to_string(),
                Some(format!(
                    "pruned {pruned} old connection_health_checks row(s)"
                )),
            ))
        }
        "check_results_prune" => {
            // Safe-internal write (correctness swarm): bound the synthetic-health-probe history.
            // The hourly synthetic_health_run appends one check_results row PER enabled health_check
            // per tick. Keep the newest per check_id. Runs HOURLY (codex): a DAILY cap of 20000 only
            // keeps up below ~833 checks (#checks × 24/day); hourly → ~20000-check headroom.
            const KEEP_PER_CHECK: i64 = 10_000;
            const MAX_PER_RUN: i64 = 20_000;
            let pruned =
                prune_history_newest_n(tx, PruneTarget::CheckResults, KEEP_PER_CHECK, MAX_PER_RUN)
                    .await?;
            Ok((
                "succeeded".to_string(),
                Some(format!("pruned {pruned} old check_results row(s)")),
            ))
        }
        "shift_queue_prune" => {
            // Safe-internal write (run-5): bound the unbounded RESOLVED shift_queue history. OPEN
            // items (resolved=false) are live work and are NEVER pruned; only resolved items older
            // than the retention window. Slow-growing (deduped one-per-asset), so DAILY suffices.
            const RETENTION_DAYS: i64 = 90;
            const MAX_PER_RUN: i64 = 20_000;
            let pruned = prune_resolved_shift_queue(tx, RETENTION_DAYS, MAX_PER_RUN).await?;
            Ok((
                "succeeded".to_string(),
                Some(format!("pruned {pruned} resolved shift_queue row(s)")),
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

    // ---- #52 restore_overdue_scan ------------------------------------------

    /// The migration-122-seeded restore_overdue_scan id. Tests disable it so
    /// exactly ONE scan is due per tick (otherwise both would scan and the
    /// migration scan could enqueue items for unrelated fixtures left by other
    /// tests, breaking the per-tick count assertions).
    const RESTORE_SCAN_SEED_ID: &str = "55555555-5555-4555-8555-555555555555";

    /// Seed one restore_request for `source_ci_key` with the given status and an
    /// `updated_at` backdated by `age_secs` seconds. `updated_at` is what the
    /// recency aggregate uses for a success-state row, so backdating it controls
    /// the classified age precisely.
    async fn seed_restore_request(pool: &PgPool, source_ci_key: &str, status: &str, age_secs: i64) {
        sqlx::query(
            "INSERT INTO restore_requests \
             (source_ci_key, restore_type, restore_point, target_site, \
              target_environment, owner, status, updated_at) \
             VALUES ($1, 'FullVm', 'rp-1', 'GBLON', 'production', 'sys', $2, \
                     NOW() - make_interval(secs => $3::double precision))",
        )
        .bind(source_ci_key)
        .bind(status)
        .bind(age_secs as f64)
        .execute(pool)
        .await
        .expect("seed restore request");
    }

    /// Plant a guaranteed-due `restore_overdue_scan` schedule so a single tick
    /// runs the scan. Disables the migration-seeded scan first so EXACTLY ONE is
    /// due. Returns the planted schedule id for cleanup.
    async fn seed_due_restore_scan(pool: &PgPool) -> String {
        sqlx::query("UPDATE schedules SET enabled = FALSE WHERE id = $1")
            .bind(RESTORE_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
        let id = "sched-test-restorescan-due-9c2";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test restore scan', 'restore_overdue_scan', 86400, TRUE, \
             NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        id.to_string()
    }

    /// Re-enable the migration-seeded scan that [`seed_due_restore_scan`]
    /// disabled, so the suite leaves the PRODUCTION schedule shipped (enabled).
    async fn restore_migration_restore_scan(pool: &PgPool) {
        sqlx::query("UPDATE schedules SET enabled = TRUE WHERE id = $1")
            .bind(RESTORE_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
    }

    /// Count OPEN restore-test-overdue shift_queue items for a system.
    async fn open_overdue_count(pool: &PgPool, source_ci_key: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue \
             WHERE item_type = 'restore-test-overdue' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(source_ci_key)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Count OPEN restore-test-failed shift_queue items for a system (#52 slice 2).
    async fn open_failed_count(pool: &PgPool, source_ci_key: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue \
             WHERE item_type = 'restore-test-failed' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(source_ci_key)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    // ---- #7 secret_rotation_due_scan ---------------------------------------

    /// The migration-125-seeded secret_rotation_due_scan id. Tests disable it so
    /// exactly ONE scan is due per tick (mirrors RESTORE_SCAN_SEED_ID).
    const SECRET_SCAN_SEED_ID: &str = "66666666-6666-4666-8666-666666666666";

    /// Seed one managed_secrets row. `next_rotation_due` is bound as a TEXT value
    /// (caller passes an RFC3339 string for overdue/future, or a malformed string to
    /// exercise the invalid-date signal). All columns are NOT NULL; `vault_path` is a
    /// dummy pointer — the scan must NEVER read or surface it.
    async fn seed_managed_secret(pool: &PgPool, id: &str, status: &str, next_rotation_due: &str) {
        let last_rotated = (chrono::Utc::now() - chrono::Duration::days(120)).to_rfc3339();
        sqlx::query(
            "INSERT INTO managed_secrets \
             (id, name, secret_type, vault_path, rotation_interval_days, last_rotated, \
              next_rotation_due, status, owner, site) \
             VALUES ($1, $2, 'token', 'secret/data/dummy', 90, $3, $4, $5, 'team-x', 'DEFRA')",
        )
        .bind(id)
        .bind(id) // name == id for a unique, recognizable fixture
        .bind(&last_rotated)
        .bind(next_rotation_due)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed managed secret");
    }

    /// Plant a guaranteed-due `secret_rotation_due_scan` schedule so a single tick
    /// runs the scan. Disables the migration-seeded scan first so EXACTLY ONE is due.
    async fn seed_due_secret_scan(pool: &PgPool) -> String {
        sqlx::query("UPDATE schedules SET enabled = FALSE WHERE id = $1")
            .bind(SECRET_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
        let id = "sched-test-secretscan-due-6f3";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test secret scan', 'secret_rotation_due_scan', 86400, TRUE, \
             NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        id.to_string()
    }

    /// Re-enable the migration-seeded scan that [`seed_due_secret_scan`] disabled.
    async fn restore_migration_secret_scan(pool: &PgPool) {
        sqlx::query("UPDATE schedules SET enabled = TRUE WHERE id = $1")
            .bind(SECRET_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
    }

    /// Count OPEN shift_queue items of `item_type` for a secret id (source_ci_key).
    async fn open_secret_item_count(pool: &PgPool, item_type: &str, id: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue \
             WHERE item_type = $1 AND resolved = false AND metadata->>'source_ci_key' = $2",
        )
        .bind(item_type)
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn cleanup_secret_fixture(pool: &PgPool, id: &str) {
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM managed_secrets WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    /// OVERDUE active/expired/failed secrets are enqueued; FUTURE/retired/rotating are
    /// NOT; the enqueued item carries the right fields and NO vault_path; the detail is
    /// the aggregate two-count format.
    #[tokio::test]
    async fn secret_rotation_scan_enqueues_overdue_and_filters() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let past = (chrono::Utc::now() - chrono::Duration::days(2)).to_rfc3339();
        let future = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
        let overdue_active = format!("sr-active-{suffix}");
        let overdue_expired = format!("sr-expired-{suffix}");
        let overdue_failed = format!("sr-failed-{suffix}");
        let future_active = format!("sr-future-{suffix}");
        let overdue_retired = format!("sr-retired-{suffix}");
        let overdue_rotating = format!("sr-rotating-{suffix}");
        seed_managed_secret(pool, &overdue_active, "active", &past).await;
        seed_managed_secret(pool, &overdue_expired, "expired", &past).await;
        seed_managed_secret(pool, &overdue_failed, "failed", &past).await;
        seed_managed_secret(pool, &future_active, "active", &future).await;
        seed_managed_secret(pool, &overdue_retired, "retired", &past).await;
        seed_managed_secret(pool, &overdue_rotating, "rotating", &past).await;

        let sched_id = seed_due_secret_scan(pool).await;
        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "at least the planted secret scan ran");

        // Enqueued: overdue active/expired/failed — each exactly once.
        for id in [&overdue_active, &overdue_expired, &overdue_failed] {
            assert_eq!(
                open_secret_item_count(pool, "secret-rotation-due", id).await,
                1,
                "overdue secret {id} must enqueue exactly one due item"
            );
        }
        // NOT enqueued: future (not due), retired + rotating (filtered).
        for id in [&future_active, &overdue_retired, &overdue_rotating] {
            assert_eq!(
                open_secret_item_count(pool, "secret-rotation-due", id).await,
                0,
                "secret {id} must NOT be enqueued"
            );
        }

        // The enqueued item's exact fields + secret hygiene (NO vault_path key).
        let (item_type, title, priority, reason, meta_key, vault_path): (
            String,
            String,
            String,
            String,
            String,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT item_type, title, priority, metadata->>'reason', \
                    metadata->>'source_ci_key', metadata->>'vault_path' \
             FROM shift_queue \
             WHERE item_type = 'secret-rotation-due' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(&overdue_active)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(item_type, "secret-rotation-due", "item_type");
        assert_eq!(
            title,
            format!("Secret rotation overdue: {overdue_active}"),
            "title"
        );
        assert_eq!(priority, "P2", "priority");
        assert_eq!(reason, "overdue", "metadata.reason");
        assert_eq!(meta_key, overdue_active, "metadata.source_ci_key");
        assert!(
            vault_path.is_none(),
            "vault_path must NEVER be surfaced in shift_queue metadata"
        );

        // Aggregate-only detail: EXACTLY "enqueued <O> overdue, <I> invalid secret
        // rotation item(s)" — assert the FORMAT (the global overdue count is
        // environment-dependent in a shared DB).
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'secret_rotation_due_scan' \
               AND status = 'succeeded' ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let detail = detail.unwrap_or_default();
        let counts = detail
            .strip_prefix("enqueued ")
            .and_then(|s| s.strip_suffix(" invalid secret rotation item(s)"))
            .and_then(|s| s.split_once(" overdue, "));
        assert!(
            counts.is_some_and(|(o, i)| o.parse::<u64>().is_ok() && i.parse::<u64>().is_ok()),
            "detail must be 'enqueued <O> overdue, <I> invalid secret rotation item(s)': {detail:?}"
        );

        for id in [
            &overdue_active,
            &overdue_expired,
            &overdue_failed,
            &future_active,
            &overdue_retired,
            &overdue_rotating,
        ] {
            cleanup_secret_fixture(pool, id).await;
        }
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();
        restore_migration_secret_scan(pool).await;
    }

    /// A malformed next_rotation_due is SURFACED as a secret-rotation-invalid-due item
    /// (codex MAJOR) and does NOT abort the tick — no silent blind spot.
    #[tokio::test]
    async fn secret_rotation_scan_surfaces_malformed_without_aborting() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let id = format!("sr-malformed-{}", uuid::Uuid::new_v4());
        seed_managed_secret(pool, &id, "active", "not-a-valid-rfc3339-date").await;

        let sched_id = seed_due_secret_scan(pool).await;
        let ran = tick_once(pool).await.unwrap();
        assert!(
            ran >= 1,
            "the tick ran and did NOT abort on the malformed row"
        );

        assert_eq!(
            open_secret_item_count(pool, "secret-rotation-invalid-due", &id).await,
            1,
            "a malformed next_rotation_due is surfaced as an invalid item"
        );
        assert_eq!(
            open_secret_item_count(pool, "secret-rotation-due", &id).await,
            0,
            "a malformed secret is NOT counted as overdue"
        );
        let (reason, invalid_val, vault_path): (String, String, Option<String>) = sqlx::query_as(
            "SELECT metadata->>'reason', metadata->>'invalid_next_rotation_due', \
                    metadata->>'vault_path' FROM shift_queue \
             WHERE item_type = 'secret-rotation-invalid-due' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(&id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(reason, "invalid-due-date", "metadata.reason");
        assert_eq!(
            invalid_val, "not-a-valid-rfc3339-date",
            "the bad value is captured"
        );
        assert!(vault_path.is_none(), "vault_path must never be surfaced");

        cleanup_secret_fixture(pool, &id).await;
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();
        restore_migration_secret_scan(pool).await;
    }

    /// A second tick (re-planted due) does NOT duplicate the open item (dedup). The
    /// re-plant is REQUIRED because tick_once advances next_run_at (codex MAJOR).
    #[tokio::test]
    async fn secret_rotation_scan_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let id = format!("sr-dedup-{}", uuid::Uuid::new_v4());
        let past = (chrono::Utc::now() - chrono::Duration::days(5)).to_rfc3339();
        seed_managed_secret(pool, &id, "active", &past).await;

        let sched1 = seed_due_secret_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_secret_item_count(pool, "secret-rotation-due", &id).await,
            1,
            "first tick enqueues one item"
        );

        // Re-plant a due schedule so the scan ACTUALLY runs again, then assert no dup.
        let sched2 = seed_due_secret_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_secret_item_count(pool, "secret-rotation-due", &id).await,
            1,
            "a second tick does NOT duplicate the open item"
        );

        cleanup_secret_fixture(pool, &id).await;
        for s in [&sched1, &sched2] {
            sqlx::query("DELETE FROM schedules WHERE id = $1")
                .bind(s)
                .execute(pool)
                .await
                .ok();
        }
        restore_migration_secret_scan(pool).await;
    }

    // ---- #17 legal_hold_expiry_scan ----------------------------------------

    /// The migration-126-seeded legal_hold_expiry_scan id (disabled in tests).
    const LEGAL_HOLD_SCAN_SEED_ID: &str = "77777777-7777-4777-8777-777777777777";

    /// Seed one Active/Released legal hold with the given expiry. The `reason` is a
    /// recognizable SENSITIVE marker so the hygiene test can assert it never leaks into
    /// the shift_queue item.
    async fn seed_legal_hold(
        pool: &PgPool,
        id: &str,
        status: &str,
        expiry: chrono::DateTime<chrono::Utc>,
    ) {
        sqlx::query(
            "INSERT INTO legal_holds \
             (id, server_or_app_name, hold_type, reason, initiated_by, expiry_date, status, site) \
             VALUES ($1, $2, 'Litigation', 'SENSITIVE-litigation-detail-must-not-leak', \
                     'legal-team', $3, $4, 'GBLON')",
        )
        .bind(id)
        .bind(format!("asset-{id}"))
        .bind(expiry)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed legal hold");
    }

    async fn seed_due_legal_hold_scan(pool: &PgPool) -> String {
        sqlx::query("UPDATE schedules SET enabled = FALSE WHERE id = $1")
            .bind(LEGAL_HOLD_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
        let id = "sched-test-legalholdscan-due-7a4";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test legal hold scan', 'legal_hold_expiry_scan', 86400, TRUE, \
             NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        id.to_string()
    }

    async fn restore_migration_legal_hold_scan(pool: &PgPool) {
        sqlx::query("UPDATE schedules SET enabled = TRUE WHERE id = $1")
            .bind(LEGAL_HOLD_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
    }

    async fn open_lh_item_count(pool: &PgPool, id: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue \
             WHERE item_type = 'legal-hold-expiring' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn cleanup_legal_hold(pool: &PgPool, id: &str) {
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM legal_holds WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }

    /// Active holds that are EXPIRED or EXPIRING-SOON (≤30d) are enqueued with the right
    /// expiry_state; FAR-FUTURE + RELEASED holds are NOT; the sensitive `reason` NEVER
    /// leaks into the item; no item carries an `active` verdict.
    #[tokio::test]
    async fn legal_hold_scan_enqueues_and_protects_reason() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();
        let expired = format!("lh-expired-{suffix}");
        let soon = format!("lh-soon-{suffix}");
        let far = format!("lh-far-{suffix}");
        let released = format!("lh-released-{suffix}");
        // Seed comfortably away from the 30d boundary to avoid wall-clock edge flakiness.
        seed_legal_hold(pool, &expired, "Active", now - chrono::Duration::days(2)).await;
        seed_legal_hold(pool, &soon, "Active", now + chrono::Duration::days(10)).await;
        seed_legal_hold(pool, &far, "Active", now + chrono::Duration::days(60)).await;
        seed_legal_hold(pool, &released, "Released", now - chrono::Duration::days(2)).await;

        let sched_id = seed_due_legal_hold_scan(pool).await;
        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "the planted legal-hold scan ran");

        assert_eq!(
            open_lh_item_count(pool, &expired).await,
            1,
            "expired enqueued"
        );
        assert_eq!(
            open_lh_item_count(pool, &soon).await,
            1,
            "expiring-soon enqueued"
        );
        assert_eq!(
            open_lh_item_count(pool, &far).await,
            0,
            "far-future NOT enqueued"
        );
        assert_eq!(
            open_lh_item_count(pool, &released).await,
            0,
            "released NOT enqueued"
        );

        // expiry_state verdicts are correct (and there is NO 'active' verdict anywhere).
        let state = |id: String| async move {
            sqlx::query_scalar::<_, String>(
                "SELECT metadata->>'expiry_state' FROM shift_queue \
                 WHERE item_type = 'legal-hold-expiring' AND metadata->>'source_ci_key' = $1",
            )
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
        };
        assert_eq!(state(expired.clone()).await, "expired");
        assert_eq!(state(soon.clone()).await, "expiring_soon");
        let active_items: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue WHERE item_type = 'legal-hold-expiring' \
             AND metadata->>'expiry_state' = 'active'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            active_items, 0,
            "no queue item ever carries an 'active' verdict"
        );

        // Secret hygiene: the sensitive hold `reason` NEVER appears in the item (title,
        // description, or metadata) — only operator-triage identity is surfaced.
        let leaked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue WHERE item_type = 'legal-hold-expiring' \
             AND (title LIKE '%SENSITIVE-litigation%' OR description LIKE '%SENSITIVE-litigation%' \
                  OR metadata::text LIKE '%SENSITIVE-litigation%')",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            leaked, 0,
            "the hold reason must NEVER leak into the work item"
        );

        // Aggregate detail format.
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'legal_hold_expiry_scan' \
               AND status = 'succeeded' ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let detail = detail.unwrap_or_default();
        let count = detail
            .strip_prefix("enqueued ")
            .and_then(|s| s.strip_suffix(" expiring legal hold(s)"));
        assert!(
            count.is_some_and(|n| n.parse::<u64>().is_ok()),
            "detail must be 'enqueued <N> expiring legal hold(s)': {detail:?}"
        );

        for id in [&expired, &soon, &far, &released] {
            cleanup_legal_hold(pool, id).await;
        }
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();
        restore_migration_legal_hold_scan(pool).await;
    }

    /// A second tick (re-planted due) does NOT duplicate the open item (dedup).
    #[tokio::test]
    async fn legal_hold_scan_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let id = format!("lh-dedup-{}", uuid::Uuid::new_v4());
        seed_legal_hold(
            pool,
            &id,
            "Active",
            chrono::Utc::now() - chrono::Duration::days(3),
        )
        .await;

        let s1 = seed_due_legal_hold_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_lh_item_count(pool, &id).await,
            1,
            "first tick enqueues one"
        );

        let s2 = seed_due_legal_hold_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_lh_item_count(pool, &id).await,
            1,
            "second tick does not duplicate"
        );

        cleanup_legal_hold(pool, &id).await;
        for s in [&s1, &s2] {
            sqlx::query("DELETE FROM schedules WHERE id = $1")
                .bind(s)
                .execute(pool)
                .await
                .ok();
        }
        restore_migration_legal_hold_scan(pool).await;
    }

    /// Seed one restore_request with EXPLICIT `updated_at` AND `created_at`
    /// backdated by the given second offsets. The latest-Failed detection's
    /// tie-break orders by `updated_at DESC, created_at DESC, id DESC`, so the
    /// precedence test needs to pin both timestamps independently.
    /// Seed a restore request with an EXPLICIT id, an EXPLICIT `updated_at` instant
    /// (bound directly — NOT `NOW()`, so two rows can share the EXACT same
    /// `updated_at`), and an age-based `created_at`. Lets a tie-break test pin an
    /// exact `updated_at` tie and make `id` ordering OPPOSE the correct `created_at`
    /// answer — proving `created_at` (not `id`) decides the latest row.
    async fn seed_restore_request_at_id(
        pool: &PgPool,
        id: &str,
        source_ci_key: &str,
        status: &str,
        updated_at: chrono::DateTime<chrono::Utc>,
        created_age_secs: i64,
    ) {
        sqlx::query(
            "INSERT INTO restore_requests \
             (id, source_ci_key, restore_type, restore_point, target_site, \
              target_environment, owner, status, updated_at, created_at) \
             VALUES ($1::uuid, $2, 'FullVm', 'rp-1', 'GBLON', 'production', 'sys', $3, \
                     $4, NOW() - make_interval(secs => $5::double precision))",
        )
        .bind(id)
        .bind(source_ci_key)
        .bind(status)
        .bind(updated_at)
        .bind(created_age_secs as f64)
        .execute(pool)
        .await
        .expect("seed restore request (explicit id + timestamps)");
    }

    async fn cleanup_restore_fixtures(pool: &PgPool, source_ci_key: &str, sched_id: &str) {
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(source_ci_key)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM restore_requests WHERE source_ci_key = $1")
            .bind(source_ci_key)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(sched_id)
            .execute(pool)
            .await
            .ok();
        restore_migration_restore_scan(pool).await;
    }

    /// Test 1+2: an overdue system (last success >90d) → exactly ONE open item
    /// with the exact column values + metadata; a SECOND tick does NOT duplicate.
    #[tokio::test]
    async fn restore_scan_enqueues_overdue_then_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-ros-overdue-{suffix}");
        // Last success 100 days ago > 90d window.
        seed_restore_request(pool, &key, "Completed", 100 * 86_400).await;
        let sched_id = seed_due_restore_scan(pool).await;

        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "at least the planted restore scan ran");
        assert_eq!(
            open_overdue_count(pool, &key).await,
            1,
            "exactly one open restore-test-overdue item"
        );

        // Exact column values + metadata of the enqueued item.
        let (item_type, title, priority, reason, meta_key, succ_count): (
            String,
            String,
            String,
            String,
            String,
            i64,
        ) = sqlx::query_as(
            "SELECT item_type, title, priority, metadata->>'reason', \
                    metadata->>'source_ci_key', \
                    (metadata->>'successful_test_count')::bigint \
             FROM shift_queue \
             WHERE item_type = 'restore-test-overdue' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(&key)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(item_type, "restore-test-overdue", "item_type");
        assert_eq!(title, format!("Restore test overdue: {key}"), "title");
        assert_eq!(priority, "P2", "priority");
        assert_eq!(reason, "overdue", "metadata.reason");
        assert_eq!(meta_key, key, "metadata.source_ci_key");
        assert_eq!(succ_count, 1, "metadata.successful_test_count");

        // Aggregate-only detail contract: EXACTLY "enqueued <O> overdue, <F>
        // failed restore item(s)" with two bare count tokens.
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'restore_overdue_scan' \
               AND status = 'succeeded' \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let detail = detail.unwrap_or_default();
        let counts = detail
            .strip_prefix("enqueued ")
            .and_then(|s| s.strip_suffix(" failed restore item(s)"))
            .and_then(|s| s.split_once(" overdue, "));
        assert!(
            counts.is_some_and(|(o, f)| o.parse::<u64>().is_ok() && f.parse::<u64>().is_ok()),
            "detail must be exactly 'enqueued <O> overdue, <F> failed restore item(s)': {detail:?}"
        );

        // Dedup: a second tick does NOT create a duplicate open item.
        let sched_id2 = seed_due_restore_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_overdue_count(pool, &key).await,
            1,
            "a second tick does not duplicate the open item"
        );

        cleanup_restore_fixtures(pool, &key, &sched_id).await;
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id2)
            .execute(pool)
            .await
            .ok();
        restore_migration_restore_scan(pool).await;
    }

    /// Test 3: a recently-tested system (last success < 90d) → no item.
    #[tokio::test]
    async fn restore_scan_skips_recent_system() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-ros-recent-{suffix}");
        seed_restore_request(pool, &key, "Verified", 10 * 86_400).await; // 10d ago
        let sched_id = seed_due_restore_scan(pool).await;

        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_overdue_count(pool, &key).await,
            0,
            "a recently-tested system is not flagged"
        );

        cleanup_restore_fixtures(pool, &key, &sched_id).await;
    }

    /// Fix B (codex): a degenerate whitespace-only `source_ci_key` is SKIPPED and
    /// does NOT abort the tick — a healthy overdue system in the SAME scan is still
    /// flagged, and the execution records success. (`source_ci_key` is NOT NULL but
    /// has no non-empty CHECK, so a blank key is representable; it must not poison
    /// fan-out for every other system.)
    #[tokio::test]
    async fn restore_scan_skips_blank_key_without_aborting() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let good = format!("ci-ros-good-{suffix}");
        let blank = "   ";
        seed_restore_request(pool, blank, "Completed", 100 * 86_400).await; // overdue, blank key
        seed_restore_request(pool, &good, "Completed", 100 * 86_400).await; // overdue, valid key
        let sched_id = seed_due_restore_scan(pool).await;

        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "the scan ran (not aborted by the blank-key row)");
        assert_eq!(
            open_overdue_count(pool, &good).await,
            1,
            "the healthy overdue system is still flagged despite the blank-key row"
        );
        assert_eq!(
            open_overdue_count(pool, blank).await,
            0,
            "the blank-key row is skipped, not enqueued"
        );
        let succeeded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'restore_overdue_scan' \
               AND status = 'succeeded'",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(succeeded >= 1, "the scan execution succeeded (no rollback)");

        cleanup_restore_fixtures(pool, &good, &sched_id).await;
        sqlx::query("DELETE FROM restore_requests WHERE source_ci_key = $1")
            .bind(blank)
            .execute(pool)
            .await
            .ok();
    }

    /// Test 4: a never-succeeded system (requests exist, none Verified/Completed)
    /// → flagged with metadata.reason='never_tested' (NOT 'overdue').
    #[tokio::test]
    async fn restore_scan_flags_never_tested() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-ros-never-{suffix}");
        seed_restore_request(pool, &key, "Draft", 1).await; // never reached success
        let sched_id = seed_due_restore_scan(pool).await;

        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_overdue_count(pool, &key).await,
            1,
            "a never-succeeded system is flagged"
        );
        let (reason, succ_count): (String, i64) = sqlx::query_as(
            "SELECT metadata->>'reason', \
                    (metadata->>'successful_test_count')::bigint \
             FROM shift_queue \
             WHERE item_type = 'restore-test-overdue' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(&key)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            reason, "never_tested",
            "reason is never_tested, not overdue"
        );
        assert_eq!(succ_count, 0, "no successful tests on record");

        cleanup_restore_fixtures(pool, &key, &sched_id).await;
    }

    /// Test 5: re-flag after resolution — once an operator RESOLVES the item and
    /// the system is STILL overdue at the next scan, a fresh open item is created.
    #[tokio::test]
    async fn restore_scan_reflags_after_resolution() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-ros-reflag-{suffix}");
        seed_restore_request(pool, &key, "Completed", 120 * 86_400).await;

        let sched_id = seed_due_restore_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(open_overdue_count(pool, &key).await, 1, "initial flag");

        // Operator resolves the item.
        sqlx::query(
            "UPDATE shift_queue SET resolved = true, resolved_at = NOW() \
             WHERE item_type = 'restore-test-overdue' \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(&key)
        .execute(pool)
        .await
        .unwrap();
        assert_eq!(
            open_overdue_count(pool, &key).await,
            0,
            "no open item after resolve"
        );

        // A subsequent tick (still overdue) creates a NEW open item.
        let sched_id2 = seed_due_restore_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_overdue_count(pool, &key).await,
            1,
            "a fresh open item is created after the prior one was resolved"
        );

        cleanup_restore_fixtures(pool, &key, &sched_id).await;
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id2)
            .execute(pool)
            .await
            .ok();
        restore_migration_restore_scan(pool).await;
    }

    /// Test 6: threshold boundary — a system whose last success is EXACTLY
    /// `RESTORE_OVERDUE_DAYS` days old is NOT flagged (classifier uses
    /// `age > threshold`); at +1 second it IS flagged. Locks the queue behavior
    /// at the threshold, not just directionally. Uses two distinct keys so both
    /// directions are exercised in one serialized run.
    #[tokio::test]
    async fn restore_scan_threshold_boundary() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let key_at = format!("ci-ros-at-{suffix}");
        let key_over = format!("ci-ros-over-{suffix}");
        let window = RESTORE_OVERDUE_DAYS * 86_400;
        // Backdate a couple of seconds under/over the boundary to absorb the
        // wall-clock drift between the seed NOW() and the scan's Utc::now(): the
        // "at" fixture sits just inside the window (not flagged), the "over"
        // fixture just past it (flagged).
        seed_restore_request(pool, &key_at, "Completed", window - 5).await;
        seed_restore_request(pool, &key_over, "Completed", window + 5).await;
        let sched_id = seed_due_restore_scan(pool).await;

        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_overdue_count(pool, &key_at).await,
            0,
            "a system at/under the threshold is NOT flagged"
        );
        assert_eq!(
            open_overdue_count(pool, &key_over).await,
            1,
            "a system just past the threshold IS flagged"
        );

        cleanup_restore_fixtures(pool, &key_at, &sched_id).await;
        cleanup_restore_fixtures(pool, &key_over, &sched_id).await;
    }

    /// Test 7: migration 122's seed is idempotent AND its seeded row matches the
    /// shipped contract; the partial unique index rejects a SECOND open duplicate.
    #[tokio::test]
    async fn migration_122_is_idempotent_and_index_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Re-running the seed INSERT is a clean no-op (ON CONFLICT).
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'Restore overdue scan (all systems)', 'restore_overdue_scan', \
                     86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(RESTORE_SCAN_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");

        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = $1",
            )
            .bind(RESTORE_SCAN_SEED_ID)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(name, "Restore overdue scan (all systems)", "seed name");
        assert_eq!(kind, "restore_overdue_scan", "seed job_kind");
        assert_eq!(interval, 86400, "seed interval_secs (daily cadence)");
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");

        // The partial unique index rejects a SECOND open item for the same
        // item_type+source_ci_key. First insert succeeds; the direct second
        // insert (bypassing enqueue_if_absent's NOT EXISTS) hits the index.
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-ros-idx-{suffix}");
        let meta = serde_json::json!({ "source_ci_key": key }).to_string();
        sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('restore-test-overdue', 't', 'd', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await
        .expect("first open item inserts");
        let dup = sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('restore-test-overdue', 't2', 'd2', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await;
        assert!(
            dup.is_err(),
            "the partial unique index rejects a second OPEN duplicate"
        );

        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(&key)
            .execute(pool)
            .await
            .ok();
    }

    /// #7: migration 125's seed is idempotent AND its TWO partial unique indexes
    /// (secret-rotation-due + secret-rotation-invalid-due) each dedup an open item.
    #[tokio::test]
    async fn migration_125_is_idempotent_and_indexes_dedup() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Re-running the seed INSERT is a clean no-op (ON CONFLICT).
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'Secret rotation due scan (all secrets)', 'secret_rotation_due_scan', \
                     86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(SECRET_SCAN_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");
        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = $1",
            )
            .bind(SECRET_SCAN_SEED_ID)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(name, "Secret rotation due scan (all secrets)", "seed name");
        assert_eq!(kind, "secret_rotation_due_scan", "seed job_kind");
        assert_eq!(interval, 86400, "seed interval_secs (daily)");
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");

        // BOTH partial unique indexes reject a second open item for the same key.
        for item_type in ["secret-rotation-due", "secret-rotation-invalid-due"] {
            let key = format!("sr-idx-{}-{}", item_type, uuid::Uuid::new_v4());
            let meta = serde_json::json!({ "source_ci_key": key }).to_string();
            sqlx::query(
                "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
                 VALUES ($1, 't', 'd', 'P2', $2::jsonb)",
            )
            .bind(item_type)
            .bind(&meta)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("first {item_type} item inserts: {e}"));
            let dup = sqlx::query(
                "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
                 VALUES ($1, 't2', 'd2', 'P2', $2::jsonb)",
            )
            .bind(item_type)
            .bind(&meta)
            .execute(pool)
            .await;
            assert!(
                dup.is_err(),
                "the {item_type} index rejects a second OPEN duplicate"
            );
            sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
                .bind(&key)
                .execute(pool)
                .await
                .ok();
        }
    }

    /// #17: migration 126's seed is idempotent AND its partial unique index
    /// (legal-hold-expiring) dedups an open item.
    #[tokio::test]
    async fn migration_126_is_idempotent_and_index_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'Legal hold expiry scan (all holds)', 'legal_hold_expiry_scan', \
                     86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(LEGAL_HOLD_SCAN_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");
        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = $1",
            )
            .bind(LEGAL_HOLD_SCAN_SEED_ID)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(name, "Legal hold expiry scan (all holds)", "seed name");
        assert_eq!(kind, "legal_hold_expiry_scan", "seed job_kind");
        assert_eq!(interval, 86400, "seed interval_secs (daily)");
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");

        let key = format!("lh-idx-{}", uuid::Uuid::new_v4());
        let meta = serde_json::json!({ "source_ci_key": key }).to_string();
        sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('legal-hold-expiring', 't', 'd', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await
        .expect("first legal-hold-expiring item inserts");
        let dup = sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('legal-hold-expiring', 't2', 'd2', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await;
        assert!(
            dup.is_err(),
            "the legal-hold-expiring index rejects a second OPEN duplicate"
        );
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(&key)
            .execute(pool)
            .await
            .ok();
    }

    // ---- #12: recertification overdue scan ----------------------------------

    const RECERT_SCAN_SEED_ID: &str = "88888888-8888-4888-8888-888888888888";

    /// Seed an Active|Completed recertification campaign with a chosen end_date.
    async fn seed_recert_campaign(pool: &PgPool, id: &str, end_date: &str, status: &str) {
        sqlx::query(
            "INSERT INTO recertification_campaigns \
             (id, name, start_date, end_date, review_type, reviewer_group, \
              reviews_count, completed_count, status) \
             VALUES ($1, $2, NOW() - INTERVAL '60 days', $3::timestamptz, 'ADGroup', \
                     'identity-governance', 3, 1, $4)",
        )
        .bind(id)
        .bind(format!("test campaign {id}"))
        .bind(end_date)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed campaign");
    }

    async fn open_recert_item_count(pool: &PgPool, campaign_id: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue \
             WHERE item_type = 'recertification-overdue' AND resolved = false \
               AND metadata->>'campaign_id' = $1",
        )
        .bind(campaign_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn migration_129_is_idempotent_and_index_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'Recertification overdue scan (all campaigns)', 'recertification_overdue_scan', \
                     86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(RECERT_SCAN_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");
        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = $1",
            )
            .bind(RECERT_SCAN_SEED_ID)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            name, "Recertification overdue scan (all campaigns)",
            "seed name"
        );
        assert_eq!(kind, "recertification_overdue_scan", "seed job_kind");
        assert_eq!(interval, 86400, "seed interval_secs (daily)");
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");

        let key = format!("recert-idx-{}@123", uuid::Uuid::new_v4());
        let meta = serde_json::json!({ "source_ci_key": key }).to_string();
        sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('recertification-overdue', 't', 'd', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await
        .expect("first recertification-overdue item inserts");
        let dup = sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('recertification-overdue', 't2', 'd2', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await;
        assert!(
            dup.is_err(),
            "the recertification-overdue index rejects a second OPEN duplicate"
        );
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(&key)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn recertification_scan_enqueues_overdue_only_and_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let overdue = format!("arcamp-overdue-{suffix}");
        let future = format!("arcamp-future-{suffix}");
        let completed = format!("arcamp-completed-{suffix}");
        let past = (chrono::Utc::now() - chrono::Duration::days(2)).to_rfc3339();
        let ahead = (chrono::Utc::now() + chrono::Duration::days(20)).to_rfc3339();
        seed_recert_campaign(pool, &overdue, &past, "Active").await;
        seed_recert_campaign(pool, &future, &ahead, "Active").await;
        seed_recert_campaign(pool, &completed, &past, "Completed").await;

        // Run the scan directly (twice) to prove enqueue + dedup.
        for _ in 0..2 {
            let mut tx = pool.begin().await.unwrap();
            let (status, _) = run_job(&mut tx, "recertification_overdue_scan")
                .await
                .unwrap();
            assert_eq!(status, "succeeded");
            tx.commit().await.unwrap();
        }

        // Overdue Active → exactly one item (dedup held across the two runs).
        assert_eq!(
            open_recert_item_count(pool, &overdue).await,
            1,
            "an overdue Active campaign enqueues exactly one item"
        );
        // Future Active + overdue Completed → none.
        assert_eq!(
            open_recert_item_count(pool, &future).await,
            0,
            "a not-yet-due campaign is not enqueued"
        );
        assert_eq!(
            open_recert_item_count(pool, &completed).await,
            0,
            "a Completed campaign is not enqueued"
        );

        // The enqueued item's fields + the instance-specific source_ci_key + due_state.
        let (title, priority, due_state, source_key): (String, String, String, String) =
            sqlx::query_as(
                "SELECT title, priority, metadata->>'due_state', metadata->>'source_ci_key' \
                 FROM shift_queue WHERE item_type = 'recertification-overdue' AND resolved = false \
                   AND metadata->>'campaign_id' = $1",
            )
            .bind(&overdue)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            title,
            format!("Recertification overdue: test campaign {overdue}")
        );
        assert_eq!(priority, "P2");
        assert_eq!(due_state, "overdue");
        assert!(
            source_key.starts_with(&format!("{overdue}@")),
            "source_ci_key is instance-specific ({{id}}@{{start_ms}}): {source_key}"
        );

        // Cleanup.
        for id in [&overdue, &future, &completed] {
            sqlx::query("DELETE FROM shift_queue WHERE metadata->>'campaign_id' = $1")
                .bind(id)
                .execute(pool)
                .await
                .ok();
            sqlx::query("DELETE FROM recertification_campaigns WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await
                .ok();
        }
    }

    /// codex MAJOR fix lock: a STALE open item from a previous instance of a reused
    /// campaign id (a DIFFERENT `{id}@{start}` key) must NOT suppress a genuinely-new
    /// overdue campaign that reused the id.
    #[tokio::test]
    async fn recertification_scan_instance_key_does_not_suppress_reused_id() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let id = format!("arcamp-reused-{suffix}");
        let past = (chrono::Utc::now() - chrono::Duration::days(2)).to_rfc3339();

        // A STALE open item from a "previous instance" of this id — an OLD instance key.
        let stale_meta = serde_json::json!({
            "source_ci_key": format!("{id}@1"),
            "campaign_id": id,
        })
        .to_string();
        sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('recertification-overdue', 'stale', 'd', 'P2', $1::jsonb)",
        )
        .bind(&stale_meta)
        .execute(pool)
        .await
        .expect("seed stale item");

        // A NEW overdue campaign instance that REUSES the id (start_date NOW()-60d, so its
        // instance key `{id}@{micros}` differs from the stale `{id}@1`).
        seed_recert_campaign(pool, &id, &past, "Active").await;

        let mut tx = pool.begin().await.unwrap();
        run_job(&mut tx, "recertification_overdue_scan")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        // Both items are open: the stale one was NOT a dedup match for the new instance key.
        assert_eq!(
            open_recert_item_count(pool, &id).await,
            2,
            "a stale item with a different instance key must not suppress the new campaign"
        );

        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'campaign_id' = $1")
            .bind(&id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM recertification_campaigns WHERE id = $1")
            .bind(&id)
            .execute(pool)
            .await
            .ok();
    }

    // ---- run-3: certificate expiry scan -------------------------------------

    const CERT_SCAN_SEED_ID: &str = "99999999-9999-4999-8999-999999999999";

    /// Seed a certificate with a chosen `valid_to` (an rfc3339 string) + status. Returns its id.
    async fn seed_certificate(pool: &PgPool, valid_to: &str, status: &str) -> String {
        let cn = format!("test-{}.local", uuid::Uuid::new_v4().simple());
        sqlx::query_scalar::<_, uuid::Uuid>(
            "INSERT INTO certificates \
             (common_name, subject, valid_from, valid_to, service_type, hostname, site, status) \
             VALUES ($1, 'CN=test', NOW() - INTERVAL '365 days', $2::timestamptz, 'IIS', \
                     'web.test.local', 'GBLON', $3) RETURNING id",
        )
        .bind(&cn)
        .bind(valid_to)
        .bind(status)
        .fetch_one(pool)
        .await
        .expect("seed certificate")
        .to_string()
    }

    async fn open_cert_item(pool: &PgPool, cert_id: &str) -> Option<(String, String)> {
        sqlx::query_as::<_, (String, String)>(
            "SELECT priority, metadata->>'expiry_state' FROM shift_queue \
             WHERE item_type = 'certificate-expiring' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(cert_id)
        .fetch_optional(pool)
        .await
        .unwrap()
    }

    async fn cleanup_cert(pool: &PgPool, cert_id: &str) {
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(cert_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM certificates WHERE id = $1::uuid")
            .bind(cert_id)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn migration_130_is_idempotent_and_index_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'Certificate expiry scan (all certs)', 'certificate_expiry_scan', \
                     86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(CERT_SCAN_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");
        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = $1",
            )
            .bind(CERT_SCAN_SEED_ID)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(name, "Certificate expiry scan (all certs)", "seed name");
        assert_eq!(kind, "certificate_expiry_scan", "seed job_kind");
        assert_eq!(interval, 86400, "seed interval_secs (daily)");
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");

        let key = format!("cert-idx-{}", uuid::Uuid::new_v4());
        let meta = serde_json::json!({ "source_ci_key": key }).to_string();
        sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('certificate-expiring', 't', 'd', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await
        .expect("first certificate-expiring item inserts");
        let dup = sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('certificate-expiring', 't2', 'd2', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await;
        assert!(
            dup.is_err(),
            "the certificate-expiring index rejects a second OPEN duplicate"
        );
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(&key)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn certificate_scan_enqueues_by_state_and_refreshes() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let past = (chrono::Utc::now() - chrono::Duration::days(3)).to_rfc3339();
        let soon = (chrono::Utc::now() + chrono::Duration::days(10)).to_rfc3339();
        let far = (chrono::Utc::now() + chrono::Duration::days(120)).to_rfc3339();
        // A stale 'Active'-status cert with a PAST valid_to is still surfaced (predicate on valid_to).
        let expired = seed_certificate(pool, &past, "Active").await;
        let expiring = seed_certificate(pool, &soon, "Active").await;
        let healthy = seed_certificate(pool, &far, "Active").await;

        let run = |pool: &'static PgPool| async move {
            let mut tx = pool.begin().await.unwrap();
            let (status, _) = run_job(&mut tx, "certificate_expiry_scan").await.unwrap();
            assert_eq!(status, "succeeded");
            tx.commit().await.unwrap();
        };
        run(pool).await;

        // Expired → P1/"expired"; expiring-soon → P2/"expiring-soon"; far-future → none.
        assert_eq!(
            open_cert_item(pool, &expired).await,
            Some(("P1".into(), "expired".into())),
            "an expired cert is P1/expired"
        );
        assert_eq!(
            open_cert_item(pool, &expiring).await,
            Some(("P2".into(), "expiring-soon".into())),
            "an expiring-soon cert is P2/expiring-soon"
        );
        assert_eq!(
            open_cert_item(pool, &healthy).await,
            None,
            "far-future not surfaced"
        );

        // REFRESH: move the expiring-soon cert's valid_to into the past, re-scan → the SAME open
        // item upgrades to expired/P1 (no duplicate).
        sqlx::query(
            "UPDATE certificates SET valid_to = NOW() - INTERVAL '1 day' WHERE id = $1::uuid",
        )
        .bind(&expiring)
        .execute(pool)
        .await
        .unwrap();
        run(pool).await;
        assert_eq!(
            open_cert_item(pool, &expiring).await,
            Some(("P1".into(), "expired".into())),
            "the open item upgraded expiring-soon → expired (P2 → P1) on re-scan"
        );
        let cnt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue WHERE item_type = 'certificate-expiring' \
             AND resolved = false AND metadata->>'source_ci_key' = $1",
        )
        .bind(&expiring)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(cnt, 1, "refresh upgrades in place — no duplicate item");

        cleanup_cert(pool, &expired).await;
        cleanup_cert(pool, &expiring).await;
        cleanup_cert(pool, &healthy).await;
    }

    // ─── gmsa_expiry_scan (run-3) ───────────────────────────────────────────────

    const GMSA_SCAN_SEED_ID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

    /// Seed a gMSA account whose next-rotation deadline = `last_rotation_at +
    /// interval_days`. Returns the new id.
    async fn seed_gmsa(
        pool: &PgPool,
        last_rotation_at: &str,
        interval_days: i32,
        status: &str,
    ) -> String {
        let name = format!("svc-test-{}", uuid::Uuid::new_v4().simple());
        sqlx::query_scalar::<_, uuid::Uuid>(
            "INSERT INTO gmsa_accounts \
             (name, sam_account_name, dns_host_name, site, status, \
              managed_password_interval_days, last_rotation_at) \
             VALUES ($1, $2, $3, 'GBLON', $4, $5, $6::timestamptz) RETURNING id",
        )
        .bind(&name)
        .bind(format!("{name}$"))
        .bind(format!("{name}.corp.local"))
        .bind(status)
        .bind(interval_days)
        .bind(last_rotation_at)
        .fetch_one(pool)
        .await
        .expect("seed gmsa")
        .to_string()
    }

    async fn open_gmsa_item(pool: &PgPool, gmsa_id: &str) -> Option<(String, String)> {
        sqlx::query_as::<_, (String, String)>(
            "SELECT priority, metadata->>'expiry_state' FROM shift_queue \
             WHERE item_type = 'gmsa-expiring' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(gmsa_id)
        .fetch_optional(pool)
        .await
        .unwrap()
    }

    async fn cleanup_gmsa(pool: &PgPool, gmsa_id: &str) {
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(gmsa_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM gmsa_accounts WHERE id = $1::uuid")
            .bind(gmsa_id)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn gmsa_scan_enqueues_by_state_and_refreshes() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // interval 30d: overdue (rotated 40d ago → next −10d), due-soon (rotated 25d ago →
        // next +5d, within the 7d window), healthy (rotated 1d ago → next +29d).
        let overdue_rot = (chrono::Utc::now() - chrono::Duration::days(40)).to_rfc3339();
        let duesoon_rot = (chrono::Utc::now() - chrono::Duration::days(25)).to_rfc3339();
        let healthy_rot = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        let overdue = seed_gmsa(pool, &overdue_rot, 30, "Active").await;
        let duesoon = seed_gmsa(pool, &duesoon_rot, 30, "Active").await;
        let healthy = seed_gmsa(pool, &healthy_rot, 30, "Active").await;

        let run = |pool: &'static PgPool| async move {
            let mut tx = pool.begin().await.unwrap();
            let (status, _) = run_job(&mut tx, "gmsa_expiry_scan").await.unwrap();
            assert_eq!(status, "succeeded");
            tx.commit().await.unwrap();
        };
        run(pool).await;

        // Overdue → P2/"overdue"; due-soon → P3/"due-soon"; far-future → none.
        assert_eq!(
            open_gmsa_item(pool, &overdue).await,
            Some(("P2".into(), "overdue".into())),
            "an overdue gMSA rotation is P2/overdue"
        );
        assert_eq!(
            open_gmsa_item(pool, &duesoon).await,
            Some(("P3".into(), "due-soon".into())),
            "a due-soon gMSA rotation is P3/due-soon"
        );
        assert_eq!(
            open_gmsa_item(pool, &healthy).await,
            None,
            "a not-yet-due gMSA is not surfaced"
        );

        // REFRESH: push the due-soon account's last_rotation deep into the past → next_rotation
        // past → re-scan upgrades the SAME open item to overdue/P2 (no duplicate).
        sqlx::query(
            "UPDATE gmsa_accounts SET last_rotation_at = NOW() - INTERVAL '60 days' \
             WHERE id = $1::uuid",
        )
        .bind(&duesoon)
        .execute(pool)
        .await
        .unwrap();
        run(pool).await;
        assert_eq!(
            open_gmsa_item(pool, &duesoon).await,
            Some(("P2".into(), "overdue".into())),
            "the open item upgraded due-soon → overdue (P3 → P2) on re-scan"
        );
        let cnt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue WHERE item_type = 'gmsa-expiring' \
             AND resolved = false AND metadata->>'source_ci_key' = $1",
        )
        .bind(&duesoon)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(cnt, 1, "refresh upgrades in place — no duplicate item");

        cleanup_gmsa(pool, &overdue).await;
        cleanup_gmsa(pool, &duesoon).await;
        cleanup_gmsa(pool, &healthy).await;
    }

    /// A Revoked account, or one with a non-positive (0 or negative) rotation
    /// interval, is never surfaced — both excluded by the WHERE guards.
    #[tokio::test]
    async fn gmsa_scan_skips_revoked_and_nonpositive_interval() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let long_ago = (chrono::Utc::now() - chrono::Duration::days(400)).to_rfc3339();
        // All three are WAY overdue by the deadline, but excluded by the WHERE guards.
        let revoked = seed_gmsa(pool, &long_ago, 30, "Revoked").await;
        let zero_interval = seed_gmsa(pool, &long_ago, 0, "Active").await;
        let negative_interval = seed_gmsa(pool, &long_ago, -5, "Active").await;

        let mut tx = pool.begin().await.unwrap();
        let (status, _) = run_job(&mut tx, "gmsa_expiry_scan").await.unwrap();
        assert_eq!(status, "succeeded");
        tx.commit().await.unwrap();

        assert_eq!(
            open_gmsa_item(pool, &revoked).await,
            None,
            "a Revoked account is decommissioned — never surfaced"
        );
        assert_eq!(
            open_gmsa_item(pool, &zero_interval).await,
            None,
            "a 0-interval account is guarded out (no permanent overdue noise)"
        );
        assert_eq!(
            open_gmsa_item(pool, &negative_interval).await,
            None,
            "a negative-interval account is guarded out by `> 0`"
        );

        cleanup_gmsa(pool, &revoked).await;
        cleanup_gmsa(pool, &zero_interval).await;
        cleanup_gmsa(pool, &negative_interval).await;
    }

    #[tokio::test]
    async fn migration_134_is_idempotent_and_gmsa_index_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Seed idempotency (mirrors the migration's INSERT … ON CONFLICT DO NOTHING).
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'gMSA rotation expiry scan (all accounts)', 'gmsa_expiry_scan', \
                     86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(GMSA_SCAN_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");
        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = $1",
            )
            .bind(GMSA_SCAN_SEED_ID)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(name, "gMSA rotation expiry scan (all accounts)", "seed name");
        assert_eq!(kind, "gmsa_expiry_scan", "seed job_kind");
        assert_eq!(interval, 86400, "seed interval_secs (daily)");
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");

        // Self-contained index (the local DB may be behind on migrations): create it with the
        // SAME DDL the migration uses (IF NOT EXISTS → a no-op once the migration has applied),
        // then prove it rejects a 2nd OPEN duplicate.
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_gmsa_expiring \
             ON shift_queue (item_type, (metadata->>'source_ci_key')) \
             WHERE resolved = false AND item_type = 'gmsa-expiring'",
        )
        .execute(pool)
        .await
        .expect("the gmsa-expiring partial unique index DDL is valid");

        let key = format!("gmsa-idx-{}", uuid::Uuid::new_v4());
        let meta = serde_json::json!({ "source_ci_key": key }).to_string();
        sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('gmsa-expiring', 't', 'd', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await
        .expect("first gmsa-expiring item inserts");
        let dup = sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('gmsa-expiring', 't2', 'd2', 'P3', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await;
        assert!(
            dup.is_err(),
            "the gmsa-expiring index rejects a second OPEN duplicate"
        );
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(&key)
            .execute(pool)
            .await
            .ok();
    }

    // ─── oob_cert_expiry_scan (run-3) ───────────────────────────────────────────

    const OOB_SCAN_SEED_ID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

    /// Seed an OOB endpoint with the given cert_expiry (rfc3339). Returns the new id.
    async fn seed_oob(pool: &PgPool, cert_expiry: &str) -> String {
        let host = format!("ilo-{}.mgmt.local", uuid::Uuid::new_v4().simple());
        sqlx::query_scalar::<_, uuid::Uuid>(
            "INSERT INTO oob_endpoints \
             (endpoint_type, hostname, ip_address, site, firmware_version, certificate_valid, \
              cert_expiry) \
             VALUES ('iLO', $1, '10.0.0.1', 'GBLON', '2.50', true, $2::timestamptz) RETURNING id",
        )
        .bind(&host)
        .bind(cert_expiry)
        .fetch_one(pool)
        .await
        .expect("seed oob endpoint")
        .to_string()
    }

    async fn open_oob_item(pool: &PgPool, oob_id: &str) -> Option<(String, String)> {
        sqlx::query_as::<_, (String, String)>(
            "SELECT priority, metadata->>'expiry_state' FROM shift_queue \
             WHERE item_type = 'oob-cert-expiring' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(oob_id)
        .fetch_optional(pool)
        .await
        .unwrap()
    }

    async fn cleanup_oob(pool: &PgPool, oob_id: &str) {
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(oob_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM oob_endpoints WHERE id = $1::uuid")
            .bind(oob_id)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn oob_cert_scan_enqueues_by_state_and_refreshes() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let past = (chrono::Utc::now() - chrono::Duration::days(3)).to_rfc3339();
        let soon = (chrono::Utc::now() + chrono::Duration::days(10)).to_rfc3339();
        let far = (chrono::Utc::now() + chrono::Duration::days(120)).to_rfc3339();
        let expired = seed_oob(pool, &past).await;
        let expiring = seed_oob(pool, &soon).await;
        let healthy = seed_oob(pool, &far).await;

        let run = |pool: &'static PgPool| async move {
            let mut tx = pool.begin().await.unwrap();
            let (status, _) = run_job(&mut tx, "oob_cert_expiry_scan").await.unwrap();
            assert_eq!(status, "succeeded");
            tx.commit().await.unwrap();
        };
        run(pool).await;

        // Expired → P2/"expired"; expiring-soon → P3/"expiring-soon"; far-future → none.
        assert_eq!(
            open_oob_item(pool, &expired).await,
            Some(("P2".into(), "expired".into())),
            "an expired OOB cert is P2/expired"
        );
        assert_eq!(
            open_oob_item(pool, &expiring).await,
            Some(("P3".into(), "expiring-soon".into())),
            "an expiring-soon OOB cert is P3/expiring-soon"
        );
        assert_eq!(
            open_oob_item(pool, &healthy).await,
            None,
            "far-future not surfaced"
        );

        // REFRESH: move the expiring-soon endpoint's cert_expiry into the past, re-scan → the SAME
        // open item upgrades to expired/P2 (no duplicate).
        sqlx::query(
            "UPDATE oob_endpoints SET cert_expiry = NOW() - INTERVAL '1 day' WHERE id = $1::uuid",
        )
        .bind(&expiring)
        .execute(pool)
        .await
        .unwrap();
        run(pool).await;
        assert_eq!(
            open_oob_item(pool, &expiring).await,
            Some(("P2".into(), "expired".into())),
            "the open item upgraded expiring-soon → expired (P3 → P2) on re-scan"
        );
        let cnt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue WHERE item_type = 'oob-cert-expiring' \
             AND resolved = false AND metadata->>'source_ci_key' = $1",
        )
        .bind(&expiring)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(cnt, 1, "refresh upgrades in place — no duplicate item");

        cleanup_oob(pool, &expired).await;
        cleanup_oob(pool, &expiring).await;
        cleanup_oob(pool, &healthy).await;
    }

    #[tokio::test]
    async fn migration_135_is_idempotent_and_oob_index_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'OOB management cert expiry scan (all endpoints)', 'oob_cert_expiry_scan', \
                     86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(OOB_SCAN_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");
        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = $1",
            )
            .bind(OOB_SCAN_SEED_ID)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            name, "OOB management cert expiry scan (all endpoints)",
            "seed name"
        );
        assert_eq!(kind, "oob_cert_expiry_scan", "seed job_kind");
        assert_eq!(interval, 86400, "seed interval_secs (daily)");
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");

        // Self-contained index (the local DB may be behind on migrations): same DDL as the
        // migration (IF NOT EXISTS → a no-op once it has applied), then prove it dedups.
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_oob_cert_expiring \
             ON shift_queue (item_type, (metadata->>'source_ci_key')) \
             WHERE resolved = false AND item_type = 'oob-cert-expiring'",
        )
        .execute(pool)
        .await
        .expect("the oob-cert-expiring partial unique index DDL is valid");

        let key = format!("oob-idx-{}", uuid::Uuid::new_v4());
        let meta = serde_json::json!({ "source_ci_key": key }).to_string();
        sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('oob-cert-expiring', 't', 'd', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await
        .expect("first oob-cert-expiring item inserts");
        let dup = sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('oob-cert-expiring', 't2', 'd2', 'P3', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await;
        assert!(
            dup.is_err(),
            "the oob-cert-expiring index rejects a second OPEN duplicate"
        );
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(&key)
            .execute(pool)
            .await
            .ok();
    }

    // ---- run-5: shift_queue resolved-history prune --------------------------

    const SHIFT_QUEUE_PRUNE_SEED_ID: &str = "ffffffff-ffff-4fff-8fff-ffffffffffff";

    /// Seed a `sqprune-test` shift_queue item keyed by source_ci_key, with an explicit
    /// resolved flag + a raw `resolved_at` SQL expression (test-controlled literal).
    async fn seed_shift_item(pool: &PgPool, key: &str, resolved: bool, resolved_at_sql: &str) {
        sqlx::query(&format!(
            "INSERT INTO shift_queue \
             (item_type, title, description, priority, metadata, resolved, resolved_at) \
             VALUES ('sqprune-test', 't', 'd', 'P3', $1::jsonb, $2, {resolved_at_sql})"
        ))
        .bind(serde_json::json!({ "source_ci_key": key }).to_string())
        .bind(resolved)
        .execute(pool)
        .await
        .expect("seed shift_queue item");
    }

    async fn shift_item_exists(pool: &PgPool, key: &str) -> bool {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue \
             WHERE item_type = 'sqprune-test' AND metadata->>'source_ci_key' = $1",
        )
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap();
        n > 0
    }

    #[tokio::test]
    async fn shift_queue_prune_deletes_old_resolved_keeps_the_rest() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let t = uuid::Uuid::new_v4().simple().to_string();
        let old = format!("old-{t}");
        let recent = format!("recent-{t}");
        let open = format!("open-{t}");
        let reopened = format!("reopened-{t}");
        let nullres = format!("nullres-{t}");

        seed_shift_item(pool, &old, true, "NOW() - INTERVAL '200 days'").await; // → pruned
        seed_shift_item(pool, &recent, true, "NOW() - INTERVAL '5 days'").await; // keep (recent)
        seed_shift_item(pool, &open, false, "NULL").await; // keep (OPEN = live work)
        // A REOPENED item: resolved=false but with an OLD non-null resolved_at — the
        // resolved=true predicate must still exclude it (codex).
        seed_shift_item(pool, &reopened, false, "NOW() - INTERVAL '300 days'").await;
        seed_shift_item(pool, &nullres, true, "NULL").await; // keep (no age anchor)

        let mut tx = pool.begin().await.unwrap();
        let (status, _) = run_job(&mut tx, "shift_queue_prune").await.unwrap();
        assert_eq!(status, "succeeded");
        tx.commit().await.unwrap();

        assert!(
            !shift_item_exists(pool, &old).await,
            "a resolved item older than the retention window is pruned"
        );
        assert!(
            shift_item_exists(pool, &recent).await,
            "a recently-resolved item (within retention) survives"
        );
        assert!(
            shift_item_exists(pool, &open).await,
            "an OPEN item (resolved=false) is NEVER pruned — live work"
        );
        assert!(
            shift_item_exists(pool, &reopened).await,
            "a REOPENED item (resolved=false with an old resolved_at) is NEVER pruned"
        );
        assert!(
            shift_item_exists(pool, &nullres).await,
            "a resolved item with NULL resolved_at survives (no age anchor)"
        );

        for k in [&old, &recent, &open, &reopened, &nullres] {
            sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
                .bind(k)
                .execute(pool)
                .await
                .ok();
        }
    }

    #[tokio::test]
    async fn migration_137_is_idempotent_and_index_valid() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'Shift-queue resolved-history prune', 'shift_queue_prune', 86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(SHIFT_QUEUE_PRUNE_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");
        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = $1",
            )
            .bind(SHIFT_QUEUE_PRUNE_SEED_ID)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(name, "Shift-queue resolved-history prune", "seed name");
        assert_eq!(kind, "shift_queue_prune", "seed job_kind");
        assert_eq!(interval, 86400, "seed interval_secs (daily)");
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");

        // Self-contained retention index (the local DB may be behind on migrations); same DDL
        // as the migration (IF NOT EXISTS → a no-op once it has applied).
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_shift_queue_resolved_prune \
             ON shift_queue (resolved_at ASC NULLS LAST, id ASC) \
             WHERE resolved = true AND resolved_at IS NOT NULL",
        )
        .execute(pool)
        .await
        .expect("the shift_queue retention index DDL is valid");
    }

    // ---- run-3: job_executions retention prune ------------------------------

    const PRUNE_SCAN_SEED_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    async fn seed_schedule(pool: &PgPool, id: &str) {
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'prune-test', 'health_probe', 3600, FALSE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .execute(pool)
        .await
        .expect("seed schedule");
    }

    /// Insert a job_executions row for `schedule_id` aged `age_secs` in the past.
    async fn seed_execution(pool: &PgPool, schedule_id: &str, age_secs: i64) -> String {
        let id = format!("je-{}", uuid::Uuid::new_v4());
        sqlx::query(
            "INSERT INTO job_executions (id, schedule_id, job_kind, status, started_at) \
             VALUES ($1, $2, 'health_probe', 'succeeded', NOW() - ($3 * INTERVAL '1 second'))",
        )
        .bind(&id)
        .bind(schedule_id)
        .bind(age_secs)
        .execute(pool)
        .await
        .expect("seed execution");
        id
    }

    async fn exec_count(pool: &PgPool, schedule_id: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM job_executions WHERE schedule_id = $1")
            .bind(schedule_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Clear the whole run-history table for a deterministic prune test (DB tests are
    /// serialized; job_executions is re-populated by later ticks).
    async fn clear_job_executions(pool: &PgPool) {
        sqlx::query("DELETE FROM job_executions")
            .execute(pool)
            .await
            .expect("clear job_executions");
    }

    async fn prune(pool: &PgPool, keep: i64, max_per_run: i64) -> u64 {
        let mut tx = pool.begin().await.unwrap();
        let n = prune_job_executions(&mut tx, keep, max_per_run)
            .await
            .expect("prune");
        tx.commit().await.unwrap();
        n
    }

    #[tokio::test]
    async fn migration_131_is_idempotent() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'Job-executions history prune (all schedules)', 'job_executions_prune', \
                     86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(PRUNE_SCAN_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");
        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = $1",
            )
            .bind(PRUNE_SCAN_SEED_ID)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            name, "Job-executions history prune (all schedules)",
            "seed name"
        );
        assert_eq!(kind, "job_executions_prune", "seed job_kind");
        assert_eq!(interval, 86400, "seed interval_secs (daily)");
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");
    }

    #[tokio::test]
    async fn prune_keeps_newest_n_per_schedule() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        clear_job_executions(pool).await;
        let a = format!("sched-a-{}", uuid::Uuid::new_v4());
        let b = format!("sched-b-{}", uuid::Uuid::new_v4());
        seed_schedule(pool, &a).await;
        seed_schedule(pool, &b).await;
        // A: 5 rows aged 50,40,30,20,10s ago (10s = newest). B: 2 rows.
        let mut a_ids = vec![];
        for age in [50, 40, 30, 20, 10] {
            a_ids.push(seed_execution(pool, &a, age).await);
        }
        seed_execution(pool, &b, 20).await;
        seed_execution(pool, &b, 10).await;

        // keep=3, a large cap so the per-run cap does not interfere.
        let deleted = prune(pool, 3, 1_000_000).await;
        assert_eq!(
            deleted, 2,
            "A's 2 oldest are deleted (5 - keep 3); B (2 <= 3) untouched"
        );
        assert_eq!(exec_count(pool, &a).await, 3, "A keeps its newest 3");
        assert_eq!(exec_count(pool, &b).await, 2, "B is untouched");
        // The survivors are the NEWEST (the two oldest, age 50 + 40, are gone).
        for old in &a_ids[..2] {
            let exists: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM job_executions WHERE id = $1")
                    .bind(old)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(exists, 0, "an oldest A row was pruned");
        }
        // A second prune is a clean no-op.
        assert_eq!(prune(pool, 3, 1_000_000).await, 0, "idempotent at the cap");

        clear_job_executions(pool).await;
    }

    #[tokio::test]
    async fn prune_per_run_cap_drains_over_runs() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        clear_job_executions(pool).await;
        let a = format!("sched-cap-{}", uuid::Uuid::new_v4());
        seed_schedule(pool, &a).await;
        for age in [60, 50, 40, 30, 20, 10] {
            seed_execution(pool, &a, age).await;
        }
        // keep=2, cap=2: 4 over-cap rows drain 2 at a time over two runs, then a no-op.
        assert_eq!(prune(pool, 2, 2).await, 2, "first run deletes the 2 oldest");
        assert_eq!(prune(pool, 2, 2).await, 2, "second run deletes the next 2");
        assert_eq!(prune(pool, 2, 2).await, 0, "now at the cap — nothing more");
        assert_eq!(exec_count(pool, &a).await, 2, "exactly keep=2 survive");

        clear_job_executions(pool).await;
    }

    #[tokio::test]
    async fn prune_tie_break_deterministic_and_guard() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        clear_job_executions(pool).await;
        let a = format!("sched-tie-{}", uuid::Uuid::new_v4());
        seed_schedule(pool, &a).await;
        // Two rows with the EXACT SAME started_at (a fixed timestamp, not two separate
        // NOW() calls) beyond keep=1 — so the id-DESC tiebreak is what decides.
        for _ in 0..2 {
            sqlx::query(
                "INSERT INTO job_executions (id, schedule_id, job_kind, status, started_at) \
                 VALUES ($1, $2, 'health_probe', 'succeeded', '2026-01-01T00:00:00Z'::timestamptz)",
            )
            .bind(format!("je-{}", uuid::Uuid::new_v4()))
            .bind(&a)
            .execute(pool)
            .await
            .expect("seed tied execution");
        }
        // Deterministic (id DESC tiebreak): exactly one survives, no error.
        assert_eq!(
            prune(pool, 1, 100).await,
            1,
            "one of the tied rows is pruned"
        );
        assert_eq!(
            exec_count(pool, &a).await,
            1,
            "the tiebreak leaves exactly one"
        );

        // Guard: a non-positive keep/cap deletes NOTHING.
        assert_eq!(prune(pool, 0, 100).await, 0, "keep<=0 deletes nothing");
        assert_eq!(prune(pool, 1, 0).await, 0, "cap<=0 deletes nothing");
        assert_eq!(exec_count(pool, &a).await, 1, "the surviving row is intact");

        clear_job_executions(pool).await;
    }

    // ---- run-3: connection_health_checks prune (generalized helper) ----------

    const CHC_PRUNE_SEED_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    async fn seed_connection_for_prune(pool: &PgPool, id: &str) {
        sqlx::query(
            "INSERT INTO integration_connections \
             (id, vendor_type, name, endpoint_url, credential_source, credential_ref, \
              status, readiness, execution_mode, created_by, created_at, updated_at) \
             VALUES ($1, 'servicenow', 'chc', 'https://x.example', 'env-var', 'RYUKI_INTEGRATION__X', \
                     'configured', 'configured', 'static-dry-run', 'sys', NOW(), NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .execute(pool)
        .await
        .expect("seed connection");
    }

    async fn seed_health_check(pool: &PgPool, connection_id: &str, age_secs: i64) -> String {
        let id = format!("chc-{}", uuid::Uuid::new_v4());
        sqlx::query(
            "INSERT INTO connection_health_checks \
             (id, connection_id, checked_at, endpoint_status, credential_status) \
             VALUES ($1, $2, NOW() - ($3 * INTERVAL '1 second'), 'ok', 'resolved')",
        )
        .bind(&id)
        .bind(connection_id)
        .bind(age_secs)
        .execute(pool)
        .await
        .expect("seed health check");
        id
    }

    async fn chc_count(pool: &PgPool, connection_id: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM connection_health_checks WHERE connection_id = $1")
            .bind(connection_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn connection_health_checks_prune_keeps_newest_n_per_connection() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query("DELETE FROM connection_health_checks")
            .execute(pool)
            .await
            .expect("clear chc");
        let c1 = format!("ic-chc1-{}", uuid::Uuid::new_v4());
        let c2 = format!("ic-chc2-{}", uuid::Uuid::new_v4());
        seed_connection_for_prune(pool, &c1).await;
        seed_connection_for_prune(pool, &c2).await;
        // c1: 5 checks aged 50..10s (10s = newest); capture the 2 OLDEST ids (age 50, 40).
        let mut c1_ids = vec![];
        for age in [50, 40, 30, 20, 10] {
            c1_ids.push(seed_health_check(pool, &c1, age).await);
        }
        seed_health_check(pool, &c2, 20).await;
        seed_health_check(pool, &c2, 10).await;

        // The generalized helper targets connection_health_checks, partitioned by connection_id.
        let mut tx = pool.begin().await.unwrap();
        let deleted =
            prune_history_newest_n(&mut tx, PruneTarget::ConnectionHealthChecks, 3, 1_000_000)
                .await
                .expect("prune chc");
        tx.commit().await.unwrap();
        assert_eq!(
            deleted, 2,
            "c1's 2 oldest pruned (5 - keep 3); c2 (2 <= 3) untouched"
        );
        assert_eq!(chc_count(pool, &c1).await, 3, "c1 keeps its newest 3");
        assert_eq!(chc_count(pool, &c2).await, 2, "c2 is untouched");
        // The survivors are the NEWEST: the 2 OLDEST (age 50, 40) are the ones deleted (codex).
        for old in &c1_ids[..2] {
            let gone: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM connection_health_checks WHERE id = $1")
                    .bind(old)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(gone, 0, "an OLDEST c1 check was pruned (newest survive)");
        }

        sqlx::query("DELETE FROM connection_health_checks")
            .execute(pool)
            .await
            .ok();
        for id in [&c1, &c2] {
            sqlx::query("DELETE FROM integration_connections WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await
                .ok();
        }
    }

    #[tokio::test]
    async fn migration_132_is_idempotent() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'Connection health-checks history prune (all connections)', \
                     'connection_health_checks_prune', 3600, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(CHC_PRUNE_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");
        let (name, kind, interval, enabled, created_by): (String, String, i64, bool, String) =
            sqlx::query_as(
                "SELECT name, job_kind, interval_secs, enabled, created_by FROM schedules \
                 WHERE id = $1",
            )
            .bind(CHC_PRUNE_SEED_ID)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            name, "Connection health-checks history prune (all connections)",
            "seed name"
        );
        assert_eq!(kind, "connection_health_checks_prune", "seed job_kind");
        assert_eq!(
            interval, 3600,
            "seed interval_secs (HOURLY — keeps up with per-connection growth)"
        );
        assert!(enabled, "seed ships enabled");
        assert_eq!(created_by, "system", "seed created_by");
    }

    // ---- correctness swarm: check_results prune (reuses the generalized helper) ----

    const CHECK_RESULTS_PRUNE_SEED_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    #[tokio::test]
    async fn check_results_prune_keeps_newest_n_per_check() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Seed a parent health_check (FK target), then > keep check_results for it.
        let check_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO health_checks (name, check_type, endpoint, expected_status, \
             interval_seconds, site, enabled) \
             VALUES ($1, 'http', 'x.example', 200, 60, 'DEFRA', false) RETURNING id",
        )
        .bind(format!("crp-{}", uuid::Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("seed health_check");
        // The prune is GLOBAL, so clear the whole (run-history) table for a deterministic
        // `deleted` count (DB tests are serialized; check_results is re-populated by ticks).
        sqlx::query("DELETE FROM check_results")
            .execute(pool)
            .await
            .expect("clear check_results");
        for age in [50, 40, 30, 20, 10] {
            sqlx::query(
                "INSERT INTO check_results (check_id, status, executed_at) \
                 VALUES ($1, 'pass', NOW() - ($2 * INTERVAL '1 second'))",
            )
            .bind(check_id)
            .bind(age as i64)
            .execute(pool)
            .await
            .expect("seed check_result");
        }

        let mut tx = pool.begin().await.unwrap();
        let deleted = prune_history_newest_n(&mut tx, PruneTarget::CheckResults, 3, 1_000_000)
            .await
            .expect("prune check_results");
        tx.commit().await.unwrap();
        assert_eq!(deleted, 2, "the 2 oldest of 5 are pruned (keep 3)");
        let kept: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM check_results WHERE check_id = $1")
                .bind(check_id)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(kept, 3, "keeps the newest 3 per check_id");

        sqlx::query("DELETE FROM check_results WHERE check_id = $1")
            .bind(check_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM health_checks WHERE id = $1")
            .bind(check_id)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn migration_133_is_idempotent() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Start from a clean slot so the test is deterministic for a FRESH DB (and corrects a
        // local DB that applied an earlier interval before this migration was finalized). The FK
        // cascade clears this schedule's job_executions (re-populated by later ticks).
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(CHECK_RESULTS_PRUNE_SEED_ID)
            .execute(pool)
            .await
            .ok();
        // The migration's seed, run TWICE — the second is a clean no-op (idempotent).
        for _ in 0..2 {
            sqlx::query(
                "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
                 VALUES ($1, 'Check-results history prune (all health checks)', 'check_results_prune', \
                         3600, TRUE, NOW(), 'system') \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(CHECK_RESULTS_PRUNE_SEED_ID)
            .execute(pool)
            .await
            .expect("seed INSERT ON CONFLICT re-runs cleanly");
        }
        let (kind, interval): (String, i64) =
            sqlx::query_as("SELECT job_kind, interval_secs FROM schedules WHERE id = $1")
                .bind(CHECK_RESULTS_PRUNE_SEED_ID)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(kind, "check_results_prune", "seed job_kind");
        assert_eq!(
            interval, 3600,
            "seed interval_secs (HOURLY — keeps the cap ahead of per-check growth)"
        );
    }

    // ---- #52 slice 2: FAILED-latest signal ----------------------------------

    /// Slice-2 test 1: a system whose newest restore_request is `Failed` → exactly
    /// ONE open restore-test-failed item with the right metadata, and the detail
    /// reports the failed count.
    #[tokio::test]
    async fn restore_scan_flags_latest_failed() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-rf-failed-{suffix}");
        // Latest (and only) attempt is Failed. Age is irrelevant for the failed
        // signal — keep it recent so it is NOT also overdue.
        seed_restore_request(pool, &key, "Failed", 1).await;
        let sched_id = seed_due_restore_scan(pool).await;

        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "the planted restore scan ran");
        assert_eq!(
            open_failed_count(pool, &key).await,
            1,
            "exactly one open restore-test-failed item"
        );

        let (item_type, title, priority, reason): (String, String, String, String) =
            sqlx::query_as(
                "SELECT item_type, title, priority, metadata->>'reason' \
                 FROM shift_queue \
                 WHERE item_type = 'restore-test-failed' AND resolved = false \
                   AND metadata->>'source_ci_key' = $1",
            )
            .bind(&key)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(item_type, "restore-test-failed", "item_type");
        assert_eq!(
            title,
            format!("Restore test FAILED (latest): {key}"),
            "title"
        );
        assert_eq!(priority, "P2", "priority");
        assert_eq!(reason, "failed_latest", "metadata.reason");

        let detail = latest_scan_detail(pool, &sched_id).await;
        let failed = parse_failed_count(&detail);
        // Deterministic: one latest-Failed system is seeded and the suite is
        // serialized + self-cleaning, so the count is exactly 1 (not just >= 1).
        assert_eq!(failed, 1, "detail reports exactly one failed: {detail:?}");

        cleanup_restore_fixtures(pool, &key, &sched_id).await;
    }

    /// Slice-2 test 2: an OLD Failed then a NEWER Verified → NOT flagged (only the
    /// latest status matters; the system's most recent attempt succeeded).
    #[tokio::test]
    async fn restore_scan_latest_success_not_failed_flagged() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-rf-recovered-{suffix}");
        // Older Failed, newer Verified — latest is success. Keep the Verified
        // recent so it is not overdue either.
        seed_restore_request(pool, &key, "Failed", 30 * 86_400).await;
        seed_restore_request(pool, &key, "Verified", 1).await;
        let sched_id = seed_due_restore_scan(pool).await;

        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_failed_count(pool, &key).await,
            0,
            "a system whose latest attempt succeeded is NOT failed-flagged"
        );

        cleanup_restore_fixtures(pool, &key, &sched_id).await;
    }

    /// Slice-2 test 3: dedup + count accounting — a second tick adds no duplicate
    /// failed item AND its detail reports `failed = 0` (the count is
    /// `rows_affected`, not candidates).
    #[tokio::test]
    async fn restore_scan_failed_dedups_and_counts_rows_affected() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-rf-dedup-{suffix}");
        seed_restore_request(pool, &key, "Failed", 1).await;
        let sched_id = seed_due_restore_scan(pool).await;

        let _ = tick_once(pool).await.unwrap();
        assert_eq!(open_failed_count(pool, &key).await, 1, "first tick flags");

        // Second tick: still latest-Failed, but an open item already exists → no
        // duplicate AND the failed count for THIS tick is 0 (rows_affected).
        let sched_id2 = seed_due_restore_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_failed_count(pool, &key).await,
            1,
            "a second tick does not duplicate the open failed item"
        );
        let detail = latest_scan_detail(pool, &sched_id2).await;
        assert_eq!(
            parse_failed_count(&detail),
            0,
            "the second tick's detail reports failed = 0 (rows_affected): {detail:?}"
        );

        cleanup_restore_fixtures(pool, &key, &sched_id).await;
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(&sched_id2)
            .execute(pool)
            .await
            .ok();
        restore_migration_restore_scan(pool).await;
    }

    /// Slice-2 test 4: both signals — a system that is overdue AND latest-failed →
    /// BOTH a restore-test-overdue and a restore-test-failed open item.
    #[tokio::test]
    async fn restore_scan_both_signals() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-rf-both-{suffix}");
        // An OLD success (overdue: >90d, last success long ago) plus a NEWER Failed
        // (latest is Failed). Both signals must fire independently.
        seed_restore_request(pool, &key, "Completed", 120 * 86_400).await;
        seed_restore_request(pool, &key, "Failed", 1).await;
        let sched_id = seed_due_restore_scan(pool).await;

        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_overdue_count(pool, &key).await,
            1,
            "overdue item present (last success is stale)"
        );
        assert_eq!(
            open_failed_count(pool, &key).await,
            1,
            "failed item present (latest attempt failed)"
        );

        cleanup_restore_fixtures(pool, &key, &sched_id).await;
    }

    /// Slice-2 test 5: the combined detail format is EXACTLY
    /// "enqueued <O> overdue, <F> failed restore item(s)" with both counts ≥ 1
    /// when one system is overdue and another is latest-failed.
    #[tokio::test]
    async fn restore_scan_combined_detail_format() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let overdue_key = format!("ci-rf-cd-overdue-{suffix}");
        let failed_key = format!("ci-rf-cd-failed-{suffix}");
        seed_restore_request(pool, &overdue_key, "Completed", 120 * 86_400).await;
        seed_restore_request(pool, &failed_key, "Failed", 1).await;
        let sched_id = seed_due_restore_scan(pool).await;

        let _ = tick_once(pool).await.unwrap();

        let detail = latest_scan_detail(pool, &sched_id);
        let detail = detail.await;
        let counts = detail
            .strip_prefix("enqueued ")
            .and_then(|s| s.strip_suffix(" failed restore item(s)"))
            .and_then(|s| s.split_once(" overdue, "));
        let (overdue, failed) = counts.unwrap_or_else(|| {
            panic!(
                "detail must match 'enqueued <O> overdue, <F> failed restore item(s)': {detail:?}"
            )
        });
        assert!(
            overdue.parse::<u64>().unwrap() >= 1,
            "overdue count ≥ 1: {detail:?}"
        );
        assert!(
            failed.parse::<u64>().unwrap() >= 1,
            "failed count ≥ 1: {detail:?}"
        );

        cleanup_restore_fixtures(pool, &overdue_key, &sched_id).await;
        cleanup_restore_fixtures(pool, &failed_key, &sched_id).await;
    }

    /// Slice-2 test 6: latest-status precedence on equal `updated_at` — a Failed
    /// and a Verified row with the SAME `updated_at` but
    /// `created_at(Verified) > created_at(Failed)` → NOT flagged (the
    /// chronologically-newer success wins the `created_at DESC` tiebreak).
    #[tokio::test]
    async fn restore_scan_latest_precedence_equal_updated_at() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-rf-prec-{suffix}");
        // Same updated_at (10s ago for both); Verified created MORE recently
        // (created 5s ago) than Failed (created 20s ago) → newer attempt is the
        // success, so NOT flagged.
        //
        // To make this a TRUE guard for the `created_at` tiebreak (and not pass by
        // luck of random UUIDs), give the WRONG-answer row (Failed) the
        // HIGHER-sorting id and the right one (Verified) the LOWER. Then a buggy
        // `updated_at DESC, id DESC` tiebreak (no created_at) would pick Failed →
        // flagged; only the correct `created_at DESC` precedence picks Verified →
        // NOT flagged. The id node keeps the random suffix so runs never collide.
        let node = &suffix.simple().to_string()[20..32];
        let failed_id = format!("ffffffff-ffff-4fff-8fff-{node}");
        let verified_id = format!("00000000-0000-4000-8000-{node}");
        // ONE shared updated_at instant bound to BOTH rows, so the tie is EXACT
        // (per-statement NOW() would give the second row a newer updated_at and the
        // tiebreak would never reach created_at/id). Verified is created later.
        let shared_updated = chrono::Utc::now();
        seed_restore_request_at_id(pool, &failed_id, &key, "Failed", shared_updated, 20).await;
        seed_restore_request_at_id(pool, &verified_id, &key, "Verified", shared_updated, 5).await;
        let sched_id = seed_due_restore_scan(pool).await;

        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_failed_count(pool, &key).await,
            0,
            "on an equal-updated_at tie, the chronologically-newer success wins \
             (created_at decides, NOT the id fallback)"
        );

        cleanup_restore_fixtures(pool, &key, &sched_id).await;
    }

    /// Slice-2 test 7: blank-`source_ci_key` latest-Failed rows — both a
    /// SPACES-only key AND a TAB/NEWLINE-only key — alongside a valid latest-Failed
    /// system → the valid one is flagged and the scan succeeds. The arm skips blanks
    /// in Rust with the same `trim()` `enqueue_if_absent` uses, so ANY whitespace
    /// kind is excluded and never aborts the tick (a SQL `btrim` would miss
    /// tab/newline).
    #[tokio::test]
    async fn restore_scan_blank_failed_key_does_not_abort() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let good = format!("ci-rf-good-{suffix}");
        let spaces = "   ";
        let tabnl = "\t\n"; // tab/newline-only: would survive a SQL btrim filter
        seed_restore_request(pool, spaces, "Failed", 1).await; // latest-Failed, blank key
        seed_restore_request(pool, tabnl, "Failed", 1).await; // latest-Failed, ws key
        seed_restore_request(pool, &good, "Failed", 1).await; // latest-Failed, valid key
        let sched_id = seed_due_restore_scan(pool).await;

        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "the scan ran (not aborted by the blank-key rows)");
        assert_eq!(
            open_failed_count(pool, &good).await,
            1,
            "the valid latest-Failed system is flagged despite the blank-key rows"
        );
        assert_eq!(
            open_failed_count(pool, spaces).await,
            0,
            "the spaces-only key is skipped, not enqueued"
        );
        assert_eq!(
            open_failed_count(pool, tabnl).await,
            0,
            "the tab/newline-only key is skipped, not enqueued"
        );
        let succeeded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'restore_overdue_scan' \
               AND status = 'succeeded'",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(succeeded >= 1, "the scan execution succeeded (no rollback)");

        cleanup_restore_fixtures(pool, &good, &sched_id).await;
        for blank in [spaces, tabnl] {
            sqlx::query("DELETE FROM restore_requests WHERE source_ci_key = $1")
                .bind(blank)
                .execute(pool)
                .await
                .ok();
        }
    }

    /// Slice-2 test 8: migration 123's partial unique index is idempotent (a
    /// re-create is a no-op) AND rejects a SECOND open restore-test-failed
    /// duplicate for the same system.
    #[tokio::test]
    async fn migration_123_is_idempotent_and_index_dedups() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Re-running the index DDL is a clean no-op (IF NOT EXISTS).
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_restore_failed \
             ON shift_queue (item_type, (metadata->>'source_ci_key')) \
             WHERE resolved = false AND item_type = 'restore-test-failed'",
        )
        .execute(pool)
        .await
        .expect("re-creating the index is idempotent");

        // The partial unique index rejects a SECOND open item for the same
        // item_type+source_ci_key. First insert succeeds; the direct second
        // insert (bypassing enqueue_if_absent's NOT EXISTS) hits the index.
        let suffix = uuid::Uuid::new_v4();
        let key = format!("ci-rf-idx-{suffix}");
        let meta = serde_json::json!({ "source_ci_key": key }).to_string();
        sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('restore-test-failed', 't', 'd', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await
        .expect("first open failed item inserts");
        let dup = sqlx::query(
            "INSERT INTO shift_queue (item_type, title, description, priority, metadata) \
             VALUES ('restore-test-failed', 't2', 'd2', 'P2', $1::jsonb)",
        )
        .bind(&meta)
        .execute(pool)
        .await;
        assert!(
            dup.is_err(),
            "the partial unique index rejects a second OPEN failed duplicate"
        );

        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' = $1")
            .bind(&key)
            .execute(pool)
            .await
            .ok();
    }

    /// Fetch the most recent succeeded `restore_overdue_scan` detail for a schedule.
    async fn latest_scan_detail(pool: &PgPool, sched_id: &str) -> String {
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'restore_overdue_scan' \
               AND status = 'succeeded' \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        detail.unwrap_or_default()
    }

    /// Parse the `<F>` failed-count token out of the combined detail string.
    fn parse_failed_count(detail: &str) -> u64 {
        detail
            .strip_prefix("enqueued ")
            .and_then(|s| s.strip_suffix(" failed restore item(s)"))
            .and_then(|s| s.split_once(" overdue, "))
            .and_then(|(_, f)| f.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("unparseable combined detail: {detail:?}"))
    }

    // ---- #58 dr_test_overdue_scan ------------------------------------------

    /// The migration-139-seeded dr_test_overdue_scan id. Tests disable it so
    /// exactly ONE scan is due per tick (mirrors RESTORE_SCAN_SEED_ID pattern).
    const DR_SCAN_SEED_ID: &str = "a0a0a0a0-a0a0-4a0a-8a0a-a0a0a0a0a0a0";

    /// Build a valid DrPlan JSON blob for use in dr_plans test fixtures.
    fn dr_plan_json(id: &str, name: &str, site: &str, next_test_due: &str, last_tested: Option<&str>) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "site": site,
            "target_site": "GBLON",
            "systems": ["sys-01"],
            "rpo_minutes": 15,
            "rto_minutes": 120,
            "last_tested": last_tested,
            "next_test_due": next_test_due,
            "status": "active"
        })
    }

    /// Seed a dr_plans row directly. `status` is the DB scalar column value
    /// ('active', 'approved', 'draft', 'expired').
    async fn seed_dr_plan(
        pool: &PgPool,
        id: &str,
        name: &str,
        site: &str,
        status: &str,
        next_test_due: &str,
        last_tested: Option<&str>,
    ) {
        let plan_json = dr_plan_json(id, name, site, next_test_due, last_tested);
        sqlx::query(
            "INSERT INTO dr_plans (id, name, site, status, plan_json) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(name)
        .bind(site)
        .bind(status)
        .bind(plan_json)
        .execute(pool)
        .await
        .expect("seed dr_plan");
    }

    /// Plant a guaranteed-due `dr_test_overdue_scan` schedule so a single tick
    /// runs the scan. Disables the migration-seeded scan first so EXACTLY ONE is
    /// due. Returns the planted schedule id for cleanup.
    async fn seed_due_dr_scan(pool: &PgPool) -> String {
        sqlx::query("UPDATE schedules SET enabled = FALSE WHERE id = $1")
            .bind(DR_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
        let id = "sched-test-drtestscan-due-4f7";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test dr test scan', 'dr_test_overdue_scan', 86400, TRUE, \
             NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        id.to_string()
    }

    /// Re-enable the migration-seeded scan that [`seed_due_dr_scan`] disabled.
    async fn restore_migration_dr_scan(pool: &PgPool) {
        sqlx::query("UPDATE schedules SET enabled = TRUE WHERE id = $1")
            .bind(DR_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
    }

    /// Count OPEN dr-test-overdue shift_queue items for a plan id.
    async fn open_dr_overdue_count(pool: &PgPool, plan_id: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue \
             WHERE item_type = 'dr-test-overdue' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(plan_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// An overdue active plan enqueues exactly one item; a future-due plan does not.
    /// A second run dedups: count stays at 1. The detail string is aggregate-only.
    #[tokio::test]
    async fn dr_test_overdue_scan_enqueues_overdue_plans() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let overdue_id = format!("drp-test-overdue-{suffix}");
        let future_id = format!("drp-test-future-{suffix}");
        let past = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        let future = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

        seed_dr_plan(
            pool,
            &overdue_id,
            &format!("DR overdue plan {suffix}"),
            "DEFRA",
            "active",
            &past,
            None,
        )
        .await;
        seed_dr_plan(
            pool,
            &future_id,
            &format!("DR future plan {suffix}"),
            "GBLON",
            "active",
            &future,
            None,
        )
        .await;

        let sched_id = seed_due_dr_scan(pool).await;

        // Cleanup shift_queue and job_executions BEFORE asserting (mirrors sibling
        // tests' cleanup-before-assert discipline so prior fixture state does not
        // leak into the count assertions).
        sqlx::query(
            "DELETE FROM shift_queue WHERE metadata->>'source_ci_key' IN ($1, $2)",
        )
        .bind(&overdue_id)
        .bind(&future_id)
        .execute(pool)
        .await
        .ok();
        sqlx::query("DELETE FROM job_executions WHERE schedule_id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();

        // First tick: overdue plan enqueued, future plan skipped.
        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "at least the planted dr scan ran");
        assert_eq!(
            open_dr_overdue_count(pool, &overdue_id).await,
            1,
            "overdue plan gets exactly one open dr-test-overdue item"
        );
        assert_eq!(
            open_dr_overdue_count(pool, &future_id).await,
            0,
            "future plan is not enqueued"
        );

        // Detail is aggregate-only: "<N> DR plan(s) overdue, <M> enqueued".
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'dr_test_overdue_scan' \
               AND status = 'succeeded' \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let detail = detail.unwrap_or_default();
        // Verify it matches "<N> DR plan(s) overdue, <M> enqueued" with two
        // bare count tokens and NO plan id or name.
        let parsed = detail
            .split_once(" DR plan(s) overdue, ")
            .and_then(|(o, rest)| {
                let m = rest.strip_suffix(" enqueued")?;
                Some((o.parse::<u64>().ok()?, m.parse::<u64>().ok()?))
            });
        assert!(
            parsed.is_some_and(|(o, e)| o >= 1 && e >= 1),
            "detail must be '<N> DR plan(s) overdue, <M> enqueued': {detail:?}"
        );

        // Second tick: dedup holds — still exactly one open item.
        let sched_id2 = seed_due_dr_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_dr_overdue_count(pool, &overdue_id).await,
            1,
            "a second tick does not duplicate the open item"
        );

        // Final cleanup.
        sqlx::query(
            "DELETE FROM shift_queue WHERE metadata->>'source_ci_key' IN ($1, $2)",
        )
        .bind(&overdue_id)
        .bind(&future_id)
        .execute(pool)
        .await
        .ok();
        for id in [&overdue_id, &future_id] {
            sqlx::query("DELETE FROM dr_plans WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await
                .ok();
        }
        sqlx::query("DELETE FROM schedules WHERE id IN ($1, $2)")
            .bind(&sched_id)
            .bind(&sched_id2)
            .execute(pool)
            .await
            .ok();
        restore_migration_dr_scan(pool).await;
    }

    // ---- #59 patch_wave_overdue_scan ---------------------------------------

    /// The migration-140-seeded patch_wave_overdue_scan id. Tests disable it so
    /// exactly ONE scan is due per tick (mirrors DR_SCAN_SEED_ID pattern).
    const PATCH_SCAN_SEED_ID: &str = "b0b0b0b0-b0b0-4b0b-8b0b-b0b0b0b0b0b0";

    /// Seed a patch_waves row in status 'Scheduled' with the given window start.
    async fn seed_patch_wave(pool: &PgPool, id: &str, name: &str, start: &str) {
        sqlx::query(
            "INSERT INTO patch_waves (id, site, os_family, status, name, schedule) \
             VALUES ($1::uuid, 'TESTSITE', 'Linux', 'Scheduled', $2, \
                     jsonb_build_object('start', $3::text)) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(name)
        .bind(start)
        .execute(pool)
        .await
        .expect("seed patch_wave");
    }

    /// Plant a guaranteed-due `patch_wave_overdue_scan` schedule. Disables the
    /// migration-seeded scan first so EXACTLY ONE is due. Returns the planted id.
    async fn seed_due_patch_scan(pool: &PgPool) -> String {
        sqlx::query("UPDATE schedules SET enabled = FALSE WHERE id = $1")
            .bind(PATCH_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
        let id = "sched-test-patchscan-due-9c2";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test patch wave scan', 'patch_wave_overdue_scan', 86400, TRUE, \
             NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        id.to_string()
    }

    /// Re-enable the migration-seeded scan that [`seed_due_patch_scan`] disabled.
    async fn restore_migration_patch_scan(pool: &PgPool) {
        sqlx::query("UPDATE schedules SET enabled = TRUE WHERE id = $1")
            .bind(PATCH_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
    }

    /// Count OPEN patch-wave-overdue shift_queue items for a wave id.
    async fn open_patch_overdue_count(pool: &PgPool, wave_id: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue \
             WHERE item_type = 'patch-wave-overdue' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(wave_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// A Scheduled wave with a past window start enqueues exactly one item; a
    /// future-start wave does not. A second run dedups. Detail is aggregate-only.
    #[tokio::test]
    async fn patch_wave_overdue_scan_enqueues_missed_windows() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let overdue_id = uuid::Uuid::new_v4().to_string();
        let future_id = uuid::Uuid::new_v4().to_string();
        let past = (chrono::Utc::now() - chrono::Duration::days(3)).to_rfc3339();
        let future = (chrono::Utc::now() + chrono::Duration::days(3)).to_rfc3339();

        seed_patch_wave(pool, &overdue_id, &format!("patch overdue {suffix}"), &past).await;
        seed_patch_wave(pool, &future_id, &format!("patch future {suffix}"), &future).await;

        let sched_id = seed_due_patch_scan(pool).await;

        // Cleanup shift_queue + job_executions BEFORE asserting (mirrors sibling
        // tests' cleanup-before-assert discipline).
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' IN ($1, $2)")
            .bind(&overdue_id)
            .bind(&future_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM job_executions WHERE schedule_id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();

        // First tick: overdue wave enqueued, future wave skipped.
        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "at least the planted patch scan ran");
        assert_eq!(
            open_patch_overdue_count(pool, &overdue_id).await,
            1,
            "missed-window wave gets exactly one open patch-wave-overdue item"
        );
        assert_eq!(
            open_patch_overdue_count(pool, &future_id).await,
            0,
            "a wave whose window has not arrived is not enqueued"
        );

        // Detail is aggregate-only: "<N> patch wave(s) overdue, <M> enqueued".
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'patch_wave_overdue_scan' \
               AND status = 'succeeded' \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let detail = detail.unwrap_or_default();
        let parsed = detail
            .split_once(" patch wave(s) overdue, ")
            .and_then(|(o, rest)| {
                let m = rest.strip_suffix(" enqueued")?;
                Some((o.parse::<u64>().ok()?, m.parse::<u64>().ok()?))
            });
        assert!(
            parsed.is_some_and(|(o, e)| o >= 1 && e >= 1),
            "detail must be '<N> patch wave(s) overdue, <M> enqueued': {detail:?}"
        );

        // Second tick: dedup holds — still exactly one open item.
        let sched_id2 = seed_due_patch_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_patch_overdue_count(pool, &overdue_id).await,
            1,
            "a second tick does not duplicate the open item"
        );

        // Final cleanup.
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' IN ($1, $2)")
            .bind(&overdue_id)
            .bind(&future_id)
            .execute(pool)
            .await
            .ok();
        for id in [&overdue_id, &future_id] {
            sqlx::query("DELETE FROM patch_waves WHERE id = $1::uuid")
                .bind(id)
                .execute(pool)
                .await
                .ok();
        }
        sqlx::query("DELETE FROM schedules WHERE id IN ($1, $2)")
            .bind(&sched_id)
            .bind(&sched_id2)
            .execute(pool)
            .await
            .ok();
        restore_migration_patch_scan(pool).await;
    }

    // ---- #60 golden_image_stale_scan ---------------------------------------

    /// The migration-141-seeded golden_image_stale_scan id. Tests disable it so
    /// exactly ONE scan is due per tick (mirrors DR_SCAN_SEED_ID pattern).
    const GIMG_SCAN_SEED_ID: &str = "c0c0c0c0-c0c0-4c0c-8c0c-c0c0c0c0c0c0";

    /// Seed a PROMOTED golden_images row with the given build_date.
    async fn seed_golden_image(pool: &PgPool, id: &str, name: &str, built: &str) {
        sqlx::query(
            "INSERT INTO golden_images \
                 (id, image_name, os_family, os_version, distro, build_date, status, site_scope) \
             VALUES ($1::uuid, $2, 'Linux', '24.04', 'ubuntu', $3::timestamptz, 'promoted', 'TESTSITE') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(name)
        .bind(built)
        .execute(pool)
        .await
        .expect("seed golden_image");
    }

    /// Plant a guaranteed-due `golden_image_stale_scan` schedule. Disables the
    /// migration-seeded scan first so EXACTLY ONE is due. Returns the planted id.
    async fn seed_due_gimg_scan(pool: &PgPool) -> String {
        sqlx::query("UPDATE schedules SET enabled = FALSE WHERE id = $1")
            .bind(GIMG_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
        let id = "sched-test-gimgscan-due-7e1";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test golden image scan', 'golden_image_stale_scan', 86400, TRUE, \
             NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        id.to_string()
    }

    /// Re-enable the migration-seeded scan that [`seed_due_gimg_scan`] disabled.
    async fn restore_migration_gimg_scan(pool: &PgPool) {
        sqlx::query("UPDATE schedules SET enabled = TRUE WHERE id = $1")
            .bind(GIMG_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
    }

    /// Count OPEN golden-image-stale shift_queue items for an image id.
    async fn open_gimg_stale_count(pool: &PgPool, image_id: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM shift_queue \
             WHERE item_type = 'golden-image-stale' AND resolved = false \
               AND metadata->>'source_ci_key' = $1",
        )
        .bind(image_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// A promoted image older than the refresh window enqueues exactly one item; a
    /// freshly-built one does not. A second run dedups. Detail is aggregate-only.
    #[tokio::test]
    async fn golden_image_stale_scan_enqueues_stale_promoted_images() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let stale_id = uuid::Uuid::new_v4().to_string();
        let fresh_id = uuid::Uuid::new_v4().to_string();
        // Stale: built 60 days ago (> GOLDEN_IMAGE_STALE_DAYS = 35). Fresh: 5 days ago.
        let stale_built = (chrono::Utc::now() - chrono::Duration::days(60)).to_rfc3339();
        let fresh_built = (chrono::Utc::now() - chrono::Duration::days(5)).to_rfc3339();

        seed_golden_image(pool, &stale_id, &format!("stale-img-{suffix}"), &stale_built).await;
        seed_golden_image(pool, &fresh_id, &format!("fresh-img-{suffix}"), &fresh_built).await;

        let sched_id = seed_due_gimg_scan(pool).await;

        // Cleanup shift_queue + job_executions BEFORE asserting.
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' IN ($1, $2)")
            .bind(&stale_id)
            .bind(&fresh_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM job_executions WHERE schedule_id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();

        // First tick: stale image enqueued, fresh image skipped.
        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "at least the planted golden-image scan ran");
        assert_eq!(
            open_gimg_stale_count(pool, &stale_id).await,
            1,
            "stale promoted image gets exactly one open golden-image-stale item"
        );
        assert_eq!(
            open_gimg_stale_count(pool, &fresh_id).await,
            0,
            "a freshly-built image is not enqueued"
        );

        // Detail is aggregate-only: "<N> golden image(s) stale, <M> enqueued".
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'golden_image_stale_scan' \
               AND status = 'succeeded' \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let detail = detail.unwrap_or_default();
        let parsed = detail
            .split_once(" golden image(s) stale, ")
            .and_then(|(o, rest)| {
                let m = rest.strip_suffix(" enqueued")?;
                Some((o.parse::<u64>().ok()?, m.parse::<u64>().ok()?))
            });
        assert!(
            parsed.is_some_and(|(o, e)| o >= 1 && e >= 1),
            "detail must be '<N> golden image(s) stale, <M> enqueued': {detail:?}"
        );

        // Second tick: dedup holds — still exactly one open item.
        let sched_id2 = seed_due_gimg_scan(pool).await;
        let _ = tick_once(pool).await.unwrap();
        assert_eq!(
            open_gimg_stale_count(pool, &stale_id).await,
            1,
            "a second tick does not duplicate the open item"
        );

        // Final cleanup.
        sqlx::query("DELETE FROM shift_queue WHERE metadata->>'source_ci_key' IN ($1, $2)")
            .bind(&stale_id)
            .bind(&fresh_id)
            .execute(pool)
            .await
            .ok();
        for id in [&stale_id, &fresh_id] {
            sqlx::query("DELETE FROM golden_images WHERE id = $1::uuid")
                .bind(id)
                .execute(pool)
                .await
                .ok();
        }
        sqlx::query("DELETE FROM schedules WHERE id IN ($1, $2)")
            .bind(&sched_id)
            .bind(&sched_id2)
            .execute(pool)
            .await
            .ok();
        restore_migration_gimg_scan(pool).await;
    }

    // ---- #61 noise_suppression_expiry_scan ---------------------------------

    /// The migration-142-seeded noise_suppression_expiry_scan id. Tests disable it
    /// so exactly ONE scan is due per tick (mirrors GIMG_SCAN_SEED_ID pattern).
    const NOISE_SCAN_SEED_ID: &str = "d0d0d0d0-d0d0-4d0d-8d0d-d0d0d0d0d0d0";

    /// Seed a Suppressed `noisy_triggers` row whose `suppress_until` is `until` (an
    /// rfc3339 string bound as timestamptz). Host drives the derived site; the
    /// severity/count fields are filler — the scan keys only on status + suppress_until.
    async fn seed_suppressed_trigger(pool: &PgPool, id: &str, host: &str, until: &str) {
        sqlx::query(
            "INSERT INTO noisy_triggers \
                 (id, trigger_name, host, severity, event_count_last_24h, avg_interval_minutes, \
                  flapping, suggested_action, status, suppress_until, suppress_reason) \
             VALUES ($1::uuid, 'test trigger', $2, 'warning', 42, 12.0, false, 'tune', \
                     'Suppressed', $3::timestamptz, 'test suppression') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(host)
        .bind(until)
        .execute(pool)
        .await
        .expect("seed suppressed noisy_trigger");
    }

    /// Plant a guaranteed-due `noise_suppression_expiry_scan` schedule. Disables the
    /// migration-seeded scan first so EXACTLY ONE is due. Returns the planted id.
    async fn seed_due_noise_scan(pool: &PgPool) -> String {
        sqlx::query("UPDATE schedules SET enabled = FALSE WHERE id = $1")
            .bind(NOISE_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
        let id = "sched-test-noisescan-due-7e1";
        sqlx::query("DELETE FROM schedules WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at) \
             VALUES ($1, 'test noise suppression scan', 'noise_suppression_expiry_scan', 86400, TRUE, \
             NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        id.to_string()
    }

    /// Re-enable the migration-seeded scan that [`seed_due_noise_scan`] disabled.
    async fn restore_migration_noise_scan(pool: &PgPool) {
        sqlx::query("UPDATE schedules SET enabled = TRUE WHERE id = $1")
            .bind(NOISE_SCAN_SEED_ID)
            .execute(pool)
            .await
            .ok();
    }

    /// Read (status, suppress_until-is-null, updated_at) for one trigger id.
    async fn trigger_state(
        pool: &PgPool,
        id: &str,
    ) -> (String, bool, chrono::DateTime<chrono::Utc>) {
        sqlx::query_as(
            "SELECT status, suppress_until IS NULL, updated_at \
             FROM noisy_triggers WHERE id = $1::uuid",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// An EXPIRED suppression (suppress_until in the past) flips to Active with
    /// suppress_until cleared; a still-active suppression (future window) is left
    /// untouched. A second tick does not re-touch the already-reverted row.
    #[tokio::test]
    async fn noise_suppression_expiry_scan_reverts_expired_suppressions() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let expired_id = uuid::Uuid::new_v4().to_string();
        let active_id = uuid::Uuid::new_v4().to_string();
        // Expired: window closed 2 days ago. Active: window closes in 2 days.
        let past = (chrono::Utc::now() - chrono::Duration::days(2)).to_rfc3339();
        let future = (chrono::Utc::now() + chrono::Duration::days(2)).to_rfc3339();

        for id in [&expired_id, &active_id] {
            sqlx::query("DELETE FROM noisy_triggers WHERE id = $1::uuid")
                .bind(id)
                .execute(pool)
                .await
                .ok();
        }
        seed_suppressed_trigger(pool, &expired_id, "srv-frpar-web01.example.local", &past).await;
        seed_suppressed_trigger(pool, &active_id, "srv-gblon-net01.example.local", &future).await;

        let sched_id = seed_due_noise_scan(pool).await;
        sqlx::query("DELETE FROM job_executions WHERE schedule_id = $1")
            .bind(&sched_id)
            .execute(pool)
            .await
            .ok();

        // First tick: the expired suppression flips, the active one is untouched.
        let ran = tick_once(pool).await.unwrap();
        assert!(ran >= 1, "at least the planted noise scan ran");

        let (e_status, e_null, e_updated) = trigger_state(pool, &expired_id).await;
        assert_eq!(e_status, "Active", "expired suppression reverts to Active");
        assert!(e_null, "expired suppression clears suppress_until");

        let (a_status, a_null, _) = trigger_state(pool, &active_id).await;
        assert_eq!(
            a_status, "Suppressed",
            "an unexpired suppression is left Suppressed"
        );
        assert!(!a_null, "an unexpired suppression keeps its suppress_until");

        // Detail is aggregate-only: "<N> expired suppression(s) reverted to Active", N >= 1.
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'noise_suppression_expiry_scan' \
               AND status = 'succeeded' \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&sched_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let detail = detail.unwrap_or_default();
        let parsed = detail
            .strip_suffix(" expired suppression(s) reverted to Active")
            .and_then(|n| n.parse::<u64>().ok());
        assert!(
            parsed.is_some_and(|n| n >= 1),
            "detail must be '<N> expired suppression(s) reverted to Active': {detail:?}"
        );

        // Second tick (re-plant — the first advanced next_run_at): the scan runs AGAIN,
        // finds nothing left to revert (tick 1 already flipped every expired row
        // table-wide), and does NOT re-touch the already-reverted row. Idempotency is
        // proven three ways: the second job actually executed (ran2 >= 1), its detail
        // reports 0 reverted, and the row's updated_at is byte-identical.
        let sched_id2 = seed_due_noise_scan(pool).await;
        let ran2 = tick_once(pool).await.unwrap();
        assert!(ran2 >= 1, "the re-planted noise scan ran a second time");
        let (e_status2, _, e_updated2) = trigger_state(pool, &expired_id).await;
        assert_eq!(e_status2, "Active", "already-reverted row stays Active");
        assert_eq!(
            e_updated, e_updated2,
            "scan does not re-touch an already-Active row"
        );
        let detail2: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM job_executions \
             WHERE schedule_id = $1 AND job_kind = 'noise_suppression_expiry_scan' \
               AND status = 'succeeded' \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&sched_id2)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            detail2.unwrap_or_default(),
            "0 expired suppression(s) reverted to Active",
            "a second scan finds nothing left to revert (tick 1 cleared every expired row)"
        );

        // Cleanup.
        for id in [&expired_id, &active_id] {
            sqlx::query("DELETE FROM noisy_triggers WHERE id = $1::uuid")
                .bind(id)
                .execute(pool)
                .await
                .ok();
        }
        sqlx::query("DELETE FROM schedules WHERE id IN ($1, $2)")
            .bind(&sched_id)
            .bind(&sched_id2)
            .execute(pool)
            .await
            .ok();
        restore_migration_noise_scan(pool).await;
    }

    /// Migration 142's seed is idempotent (re-running ON CONFLICT is a clean no-op
    /// whose row matches the contract) AND its lookup index exists.
    #[tokio::test]
    async fn migration_142_is_idempotent_and_seeds_noise_scan() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query(
            "INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by) \
             VALUES ($1, 'Noise suppression expiry scan (all sites)', 'noise_suppression_expiry_scan', \
                     86400, TRUE, NOW(), 'system') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(NOISE_SCAN_SEED_ID)
        .execute(pool)
        .await
        .expect("seed INSERT ON CONFLICT re-runs cleanly");
        let (name, kind, interval, created_by): (String, String, i64, String) = sqlx::query_as(
            "SELECT name, job_kind, interval_secs, created_by FROM schedules WHERE id = $1",
        )
        .bind(NOISE_SCAN_SEED_ID)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            name, "Noise suppression expiry scan (all sites)",
            "seed name"
        );
        assert_eq!(kind, "noise_suppression_expiry_scan", "seed job_kind");
        assert_eq!(interval, 86400, "seed interval_secs (daily)");
        assert_eq!(created_by, "system", "seed created_by");

        // Assert the index DEFINITION, not just its name: the scan relies on the PARTIAL
        // predicate (status='Suppressed' AND suppress_until IS NOT NULL) to keep the daily
        // probe tight, so a future edit that drops the partial clause must fail this test.
        let indexdef: Option<String> = sqlx::query_scalar(
            "SELECT indexdef FROM pg_indexes \
             WHERE indexname = 'idx_noisy_triggers_suppress_expiry'",
        )
        .fetch_optional(pool)
        .await
        .unwrap();
        let indexdef = indexdef.expect("migration 142 creates idx_noisy_triggers_suppress_expiry");
        assert!(
            indexdef.contains("status = 'Suppressed'")
                && indexdef.contains("suppress_until IS NOT NULL"),
            "the suppress-expiry index must be PARTIAL on the scan predicate: {indexdef:?}"
        );
    }
}
