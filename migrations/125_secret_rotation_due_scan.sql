-- 125_secret_rotation_due_scan.sql — route overdue secret rotations into the work queue (#7).
--
-- `managed_secrets` carries a `next_rotation_due`, but the only way an operator
-- learns a secret is overdue is by polling GET /api/protect/secrets/due. This
-- migration adds a PROACTIVE scan so overdue rotations surface as actionable work
-- without manual polling.
--
-- It reuses the durable-scheduler SAFE-INTERNAL-WRITE recipe (#52/#40/#39/#19):
-- seed one enabled `secret_rotation_due_scan` schedule. The tick reads secret
-- rotation metadata across all sites (excluding `retired`/`rotating`), classifies
-- each with the pure `secrets_rotation::classify_secret_rotation_recency`, and
-- enqueues ONE deduped `shift_queue` item per OVERDUE secret — plus a separate
-- `secret-rotation-invalid-due` item for any secret whose `next_rotation_due` is
-- unparseable (so a data-integrity problem is surfaced, not silently skipped). It
-- reads `managed_secrets` and writes only our own `shift_queue` — no Vault/live
-- call, and NEVER reads or surfaces `vault_path`.

-- Seed one enabled scan on a daily (86400s) cadence. Fixed id so a re-run is a
-- no-op; ON CONFLICT DO NOTHING leaves the operator free to disable or retune it
-- without the migration re-asserting it.
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    '66666666-6666-4666-8666-666666666666',
    'Secret rotation due scan (all secrets)',
    'secret_rotation_due_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;

-- Make the dedup STRUCTURAL as well as procedural (defense-in-depth + documents
-- the intended key): at most one OPEN item per secret per signal. The partial
-- predicate constrains only `resolved = false` rows, so it never blocks the
-- post-resolution re-flag once a secret becomes due again. `shift_queue` has no
-- natural key (only a PK on `id`); these are the unique constraints the enqueue's
-- untargeted `ON CONFLICT DO NOTHING` can hit. One index per item_type (mirrors
-- migrations 122 + 123 for the restore signals).
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_secret_rotation_due
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'secret-rotation-due';

CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_secret_rotation_invalid
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'secret-rotation-invalid-due';
