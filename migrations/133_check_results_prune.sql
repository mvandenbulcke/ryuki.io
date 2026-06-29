-- 133_check_results_prune.sql — bound the synthetic-health check_results history (correctness swarm).
--
-- The durable scheduler seeds an ENABLED, HOURLY synthetic_health_run job (mig 116). Every tick it
-- lists each enabled health_check and appends ONE check_results row (mig 016) — ~#checks × 24/day —
-- and NOTHING prunes it (the run-3 prune sweep covered job_executions + connection_health_checks but
-- missed this sibling). A standing disk-space concern, the same class run-3 was built to close.
--
-- This migration seeds an HOURLY check_results_prune, reusing the generalized newest-N-per-partition
-- prune (keep newest 10000 per check_id, per-run cap 20000). HOURLY (not daily): a DAILY cap of 20000
-- only keeps up below ~833 enabled checks (#checks × 24/day); HOURLY makes the per-run delta
-- #checks/hour, so the cap covers ~20000 checks (codex) — robust headroom while the per-run delete
-- stays gentle. check_results has no append-only trigger, so the prune DELETE is allowed; the FK to
-- health_checks is the parent direction (deleting check_results rows is fine).

-- Seed one enabled HOURLY (3600s) prune. Fixed id (continues the seed sequence ...cert=9999,
-- job-exec-prune=aaaa, chc-prune=bbbb -> check-results-prune=cccc) so a re-run is a no-op.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    'Check-results history prune (all health checks)',
    'check_results_prune',
    3600,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Retention index matching the prune's window ORDER BY EXACTLY (PARTITION BY check_id ORDER BY
-- executed_at DESC NULLS LAST, id DESC) — explicit NULLS LAST (vs the btree default NULLS FIRST) so
-- the planner uses the index for ordering instead of a sort. executed_at is NOT NULL, but the
-- ordering must still match.
CREATE INDEX IF NOT EXISTS idx_check_results_prune
    ON check_results (check_id, executed_at DESC NULLS LAST, id DESC);
