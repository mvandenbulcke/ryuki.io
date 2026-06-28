# #52 (slice 2) — Route FAILED-latest restore tests into the work queue

Status: design — codex plan-review round 1 NEEDS-CHANGES, all fixed below
((major) blank-key exclusion at the query source; (major) chronological tie-break
`updated_at DESC, created_at DESC, id DESC`; (minor) count = rows_affected with a
second-tick `failed=0` test; (nit) named item-type constants). Completes the #52
feature title
("DR-overdue/FAILED tests") by adding the FAILED-latest signal alongside the
shipped overdue/never-tested slice (553e4af). Reuses that slice's
`shift_queue::enqueue_if_absent` + the `restore_overdue_scan` job.

## Goal
Slice 1 routes systems whose last SUCCESSFUL restore test is overdue/never-tested.
But a system whose MOST RECENT restore test FAILED is the more urgent, more
actionable signal — a known, fresh recoverability failure (vs merely stale). Add a
second work-queue item type, `restore-test-failed`, enqueued for any system whose
LATEST `restore_requests` row is in `Failed` status.

## Detection — latest-status (NOT any-failed)
"Latest is Failed" — not "has ever failed". A system that failed last month but
succeeded yesterday is NOT flagged (its latest attempt succeeded). Executor-generic
query (runs on the tick tx):
```sql
SELECT source_ci_key FROM (
    SELECT DISTINCT ON (source_ci_key) source_ci_key, status
    FROM restore_requests
    ORDER BY source_ci_key, updated_at DESC, created_at DESC, id DESC
) latest
WHERE status = 'Failed' AND btrim(source_ci_key) <> ''
ORDER BY source_ci_key
```
`DISTINCT ON (source_ci_key) ... ORDER BY source_ci_key, updated_at DESC` picks the
newest row per system; the outer `WHERE status='Failed'` keeps only systems whose
newest attempt failed. New fn `restore_requests::latest_failed_systems(executor) ->
Vec<String>` (source_ci_keys).

CODEX FIX (major — tie-break): `id` is a `gen_random_uuid()` (NOT chronological),
so `id DESC` alone could pick the wrong row on an equal-`updated_at` tie (e.g. a
Failed and a Verified row stamped the same instant). The tiebreak is therefore
`updated_at DESC, created_at DESC, id DESC` — `created_at` (NOT NULL) gives the
chronologically-newest row, with `id` only as a final deterministic fallback. An
equal-`updated_at` test asserts the correct row wins.

CODEX FIX (major — blank key): `source_ci_key` is `NOT NULL` but has no non-empty
CHECK, and `enqueue_if_absent` REJECTS a blank key (would abort the tick). The
query excludes blanks at the source (`AND btrim(source_ci_key) <> ''`), so a blank
latest-Failed row never reaches the enqueue (mirrors the overdue arm's skip). A DB
test proves one blank latest-Failed row does not abort the scan.

## Fold into `restore_overdue_scan` (one scan, two signals)
The scan is "route restore tests needing attention", so the FAILED loop joins the
existing arm rather than a second job/schedule (avoids a duplicate daily tick +
seed). After the existing overdue loop:
1. `let failed = restore_requests::latest_failed_systems(&mut **tx).await?;` (already
   blank-filtered at the source, so no per-row skip needed in the loop).
2. For each `source_ci_key`, `enqueue_if_absent(&mut **tx,
   RESTORE_FAILED_ITEM_TYPE, key, title, description, "P2", metadata)` — deduped
   exactly like overdue.
   - title: `"Restore test FAILED (latest): {source_ci_key}"`
   - description: `"The most recent restore test for this system FAILED. Investigate recoverability."`
   - metadata: `{"source_ci_key": key, "reason": "failed_latest"}`
3. Count `failed_enqueued += rows_affected` (the ACTUAL inserts, not candidate
   count — so an already-open item contributes 0, like overdue).

A system can receive BOTH an overdue AND a failed item (distinct signals, distinct
item_types) — intentional; they convey different things and dedup is per
item_type. (Codex-review question: should FAILED suppress the overdue item for the
same system to cut noise, or keep them independent?)

### Detail format change
The arm's `detail` becomes a combined aggregate:
`"enqueued {overdue} overdue, {failed} failed restore item(s)"` (still aggregate-
only — two counts, never per-system ids). The slice-1 test that asserts the exact
overdue-only detail string is updated to the combined format (the only change to a
shipped #52 test).

## Generalize `enqueue_if_absent` (add `item_type`)
`enqueue_if_absent` currently hardcodes `RESTORE_OVERDUE_ITEM_TYPE`. Add an
`item_type: &str` parameter (bound into both the INSERT and the NOT EXISTS
predicate); the empty-`source_ci_key` rejection and the WHERE-NOT-EXISTS + ON
CONFLICT DO NOTHING stay. CODEX FIX (nit — named constants): keep
`RESTORE_OVERDUE_ITEM_TYPE` and add `pub const RESTORE_FAILED_ITEM_TYPE:
&str = "restore-test-failed"` in `repos/shift_queue.rs`; BOTH call sites pass the
constant (never a string literal) so the values can't drift from the partial-index
predicates. Item-type values are code-controlled constants, never user input.

## Migration 123 — second partial unique index
Mirror slice-1's `uq_shift_queue_open_restore_overdue` for the new type:
```sql
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_restore_failed
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'restore-test-failed';
```
No new table/column/schedule (the `restore_overdue_scan` schedule already runs the
combined arm). Idempotent (`IF NOT EXISTS`).

## Tests (extend the slice-1 restore_scan db_tests)
1. **Latest-failed flagged**: seed a system whose newest restore_request is
   `Failed` → tick → one open `restore-test-failed` item with the right metadata;
   detail shows the failed count.
2. **Latest-success NOT flagged**: seed a system with an OLD `Failed` then a NEWER
   `Verified` → no `restore-test-failed` item (only the latest status matters).
3. **Dedup + count accounting** (codex): a second tick adds no duplicate failed
   item AND its detail reports `failed = 0` (the count is `rows_affected`, not
   candidates — the still-latest-Failed system contributes 0 when an open item
   already exists).
4. **Both signals**: a system that is overdue AND latest-failed → BOTH a
   `restore-test-overdue` and a `restore-test-failed` open item.
5. **Combined detail** format asserted exactly.
6. **Latest-status precedence** (codex tie-break): a system with a Failed and a
   Verified row at the SAME `updated_at` but `created_at(Verified) > created_at(Failed)`
   → NOT flagged (the chronologically-newer success wins the tiebreak).
7. **Blank key does not abort** (codex): a blank-`source_ci_key` latest-Failed row
   present alongside a valid latest-Failed system → the valid one is still flagged
   and the scan succeeds (the blank is excluded at the query source).
8. **Migration 123**: idempotency + the new partial unique index rejects a second
   open `restore-test-failed` duplicate for the same system.

## Files
- migrations/123_restore_failed_index.sql (new — the second partial unique index)
- sources/ryuki-api/src/repos/restore_requests.rs (`latest_failed_systems`)
- sources/ryuki-api/src/repos/shift_queue.rs (`enqueue_if_absent` + `item_type`)
- sources/ryuki-api/src/scheduler.rs (extend the arm + the combined detail + tests)
- NO engine change (job kind unchanged; the existing allowlist entry covers it).

## Out of scope (follow-ups)
- DR-PLAN drill overdue (`dr_test_runs` / `dr_plans.plan_json.next_test_due`) — a
  separate signal/source.
- Auto-priority escalation (a failed test could warrant P1).
