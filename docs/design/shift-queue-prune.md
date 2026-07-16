# shift_queue resolved-history prune (run-5)

## Problem

`shift_queue` (mig 029) accumulates RESOLVED items forever: a work item is enqueued (the durable
scans dedup one per at-risk asset), then RESOLVED (`resolved = true`, `resolved_at` set) when handled
— but nothing ever deletes it. The run-3 prune sweep bounded the FAST-growing per-tick tables
(job_executions / connection_health_checks / check_results) but missed `shift_queue`. Growth is SLOW
(deduped, one row per asset-incident), but UNBOUNDED over time — a real, if gradual, disk-space
concern (the standing /goal's focus).

## Approach — a NEW prune shape (resolved + age), NOT newest-N-per-partition

The existing `PruneTarget` prune keeps the newest-N rows PER partition — wrong for `shift_queue`,
where OPEN items (`resolved = false`) are LIVE work that must NEVER be pruned regardless of count.
The right shape is **resolved + age**: prune only RESOLVED items whose `resolved_at` is older than a
retention window, leaving every open item and recent resolved history intact.

A focused `prune_resolved_shift_queue(conn, retention_days, max_per_run) -> u64` (in
`ryuki-api/src/scheduler.rs`):
```sql
DELETE FROM shift_queue
WHERE resolved = true
  AND resolved_at IS NOT NULL
  AND resolved_at < NOW() - ($1::bigint * INTERVAL '1 day')
  AND id IN (
    SELECT id FROM shift_queue
    WHERE resolved = true AND resolved_at IS NOT NULL
      AND resolved_at < NOW() - ($1::bigint * INTERVAL '1 day')
    ORDER BY resolved_at ASC, id ASC
    LIMIT $2 )
```
- Guarded: `retention_days <= 0 || max_per_run <= 0` → `Ok(0)` (never an unbounded/footgun DELETE).
- `WHERE resolved = true` — OPEN items are never touched (live work). The OUTER DELETE re-asserts the
  full predicate (not just `id IN`) so the invariant holds even under a concurrent re-open or with a
  manually supplied id list.
- `resolved = true AND resolved_at IS NULL` (a resolved row with no timestamp — a data anomaly) is
  KEPT, never pruned: there is no age anchor. A test asserts it survives.
- A per-run cap bounds the DELETE so the FIRST prune of a years-old backlog drains over several daily
  runs rather than one giant DELETE (the job_executions-prune lesson).
- `shift_queue` has NO append-only trigger (unlike audit_log/domain_events), so the DELETE is allowed.
  NO inbound FK references shift_queue (verified), so deleting a resolved row breaks nothing.
- All SQL literals are compile-time constants; `retention_days`/`max_per_run` are bound params — no
  injection surface.

`run_job` arm `shift_queue_prune` (DAILY): `RETENTION_DAYS = 90` (a quarter of resolved work history
is ample for triage review), `MAX_PER_RUN = 20000`. (Note: the `shift-resolve` audit records only the
item id and enqueues are direct inserts, so the audit/event trail is NOT a full row replacement;
90 days of in-table history is the actual retention.)

Engine `job_is_schedulable` allowlist gains `shift_queue_prune` (safe-internal-write) + matrix/_live
tests. Migration `137_shift_queue_prune.sql`: seed one enabled DAILY (86400s) schedule (fixed id
`ffffffff-ffff-4fff-8fff-ffffffffffff` — continues …gmsa=dddd, oob=eeee → shift-queue=ffff; valid
v4) + a retention index matching the prune's predicate+ORDER BY:
`(resolved_at ASC NULLS LAST, id ASC) WHERE resolved = true AND resolved_at IS NOT NULL` (review note:
`resolved` is redundant in the partial key; `id` gives the deterministic tiebreak the ORDER BY uses).

## Tests
- DB: seed N old-resolved + M recent-resolved + K open items; run_job prunes only the old-resolved
  (open + recent + within-cap survive); a per-run cap drains a large old backlog over runs; an open
  item is NEVER pruned even when ancient (resolved=false).
- Engine: `shift_queue_prune` schedulable + NOT read-only; `_live` refused.
- Migration idempotency + the retention index (self-contained for the behind-migrations local DB).

## Risk / rollback
Additive: one prune fn + run_job arm, one allowlist entry, one seed migration + index. Prunes ONLY
resolved items older than 90 days; open work and recent history are untouched; the authoritative
trail (audit_log/domain_events) is unaffected. Rollback = revert + disable the seeded schedule.
