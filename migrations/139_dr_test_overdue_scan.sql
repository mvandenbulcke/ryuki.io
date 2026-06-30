-- 139_dr_test_overdue_scan.sql — proactively surface overdue DR tests as work-queue items.
--
-- DR plans carry a `next_test_due` date in their `plan_json`. Until now the only way
-- an operator learns a plan is overdue for a recoverability test is by polling the
-- read endpoint. This migration adds a PROACTIVE scan so overdue DR tests surface as
-- actionable work without manual polling.
--
-- It reuses the durable-scheduler SAFE-INTERNAL-WRITE recipe (#40/#39/#19/#52): seed
-- one enabled `dr_test_overdue_scan` schedule. The tick reads `dr_plans` (status
-- 'active' or 'approved'), classifies each plan by comparing `next_test_due` against
-- NOW(), and enqueues ONE deduped `shift_queue` item per overdue plan. Reads dr_plans
-- and writes only our own shift_queue — NO provider/live/destructive call.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id so a re-run is a
-- no-op; ON CONFLICT DO NOTHING leaves the operator free to disable or retune it
-- without the migration re-asserting it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    'a0a0a0a0-a0a0-4a0a-8a0a-a0a0a0a0a0a0',
    'DR test overdue scan (all sites)',
    'dr_test_overdue_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Make the dedup STRUCTURAL as well as procedural (defense-in-depth + documents
-- the intended key): at most one OPEN dr-test-overdue item per plan. The partial
-- predicate constrains only `resolved = false` rows, so it never blocks the
-- post-resolution re-flag. `shift_queue` has no natural key (only a PK on `id`);
-- this is the only unique constraint the enqueue's untargeted `ON CONFLICT DO NOTHING`
-- can hit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_dr_test_overdue
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'dr-test-overdue';
