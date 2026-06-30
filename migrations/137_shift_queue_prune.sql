-- 137_shift_queue_prune.sql — bound the unbounded RESOLVED shift_queue history (run-5).
--
-- shift_queue (mig 029) accumulates RESOLVED items forever: a work item is enqueued (the durable
-- scans dedup one per at-risk asset), then resolved (resolved=true, resolved_at set) when handled —
-- and nothing ever deletes it. The run-3 prune sweep bounded the fast-growing per-tick tables
-- (job_executions / connection_health_checks / check_results) but missed this one. Growth is slow
-- (deduped), but unbounded over time — a gradual disk-space concern.
--
-- This seeds a DAILY shift_queue_prune. The tick DELETEs only RESOLVED items older than the
-- retention window (90 days, in the run_job arm), capped per run. OPEN items (resolved=false) are
-- LIVE work and are NEVER pruned, regardless of count or age; resolved-but-NULL-resolved_at rows are
-- also kept (no age anchor). shift_queue has no append-only trigger and no inbound FK, so the DELETE
-- is safe.

-- Seed one enabled DAILY (86400s) prune. Fixed id (continues the seed sequence ...gmsa=dddd,
-- oob=eeee -> shift-queue=ffff; valid v4: version nibble 4, variant nibble 8) so a re-run is a no-op.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'ffffffff-ffff-4fff-8fff-ffffffffffff',
    'Shift-queue resolved-history prune',
    'shift_queue_prune',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Retention index matching the prune's predicate + ORDER BY EXACTLY: partial on
-- (resolved = true AND resolved_at IS NOT NULL), keyed on (resolved_at ASC, id ASC). `resolved` is
-- redundant in the partial key; `id` gives the deterministic tiebreak the prune's ORDER BY uses.
-- The explicit `ASC NULLS LAST` matches the prune's ORDER BY (it also matches the ascending-btree
-- default, NULLS LAST) and is moot here anyway — the partial predicate excludes NULL resolved_at.
CREATE INDEX IF NOT EXISTS idx_shift_queue_resolved_prune
    ON shift_queue (resolved_at ASC NULLS LAST, id ASC)
    WHERE resolved = true AND resolved_at IS NOT NULL;
