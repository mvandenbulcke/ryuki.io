-- DR-plan DELETE prerequisite: an ON DELETE RESTRICT foreign key on
-- dr_test_runs.plan_id so that
--   (a) a plan that has test-run HISTORY cannot be deleted (the runs are
--       audit-relevant evidence), and
--   (b) a concurrent dr_test_start cannot ORPHAN a run against a just-deleted
--       plan (its run INSERT fails the FK instead of leaving dangling history).
--
-- The three steps are ordered and idempotent (safe to re-run): the backfill is a
-- no-op when the seed rows already exist, the orphan guard passes on a healthy DB,
-- and the FK add is guarded (scoped to THIS table + FK target) so a re-run does NOT
-- re-add the constraint; the subsequent VALIDATE is a cheap no-op once the
-- constraint is already validated. An older DB (087 marked-applied but its seed rows
-- somehow absent) is repaired BEFORE the constraint is validated.

-- 1. BACKFILL the migration-087 seed plans. On a healthy DB these already exist
--    (no-op via ON CONFLICT). On a DB whose 087 seed rows are absent this restores
--    them, so the static-store seed plans always have a dr_plans row and a
--    concurrent dr_test_start can never fail the FK for a seed plan.
INSERT INTO dr_plans (id, name, site, status, plan_json, created_at, updated_at)
VALUES
  ('drp-defra-001', 'DEFRA production full-site failover', 'DEFRA', 'active',
   '{"id":"drp-defra-001","name":"DEFRA production full-site failover","site":"DEFRA","target_site":"GBLON","systems":["defra-app-01","defra-db-01"],"rpo_minutes":15,"rto_minutes":120,"last_tested":"2026-05-13T00:00:00Z","next_test_due":"2026-06-12T00:00:00Z","status":"active"}',
   '2026-05-13T00:00:00Z', '2026-05-13T00:00:00Z'),
  ('drp-gblon-001', 'GBLON storage partial failover', 'GBLON', 'approved',
   '{"id":"drp-gblon-001","name":"GBLON storage partial failover","site":"GBLON","target_site":"FRPAR","systems":["gblon-vsan-01","gblon-vsan-02"],"rpo_minutes":30,"rto_minutes":180,"last_tested":"2026-06-10T00:00:00Z","next_test_due":"2026-07-10T00:00:00Z","status":"approved"}',
   '2026-06-10T00:00:00Z', '2026-06-10T00:00:00Z'),
  ('drp-frpar-001', 'FRPAR communications tabletop', 'FRPAR', 'draft',
   '{"id":"drp-frpar-001","name":"FRPAR communications tabletop","site":"FRPAR","target_site":"DEFRA","systems":["frpar-core-01","frpar-fw-01"],"rpo_minutes":60,"rto_minutes":240,"last_tested":null,"next_test_due":"2026-06-20T00:00:00Z","status":"draft"}',
   '2026-04-01T00:00:00Z', '2026-04-01T00:00:00Z')
ON CONFLICT (id) DO NOTHING;

-- 2. FAIL LOUDLY on any remaining orphan run. If a dr_test_runs row references a
--    plan_id not present in dr_plans (after the backfill), an operator must resolve
--    it before the FK can be added. Silently DELETEing audit-relevant test history
--    is not an acceptable default, so we RAISE instead.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM dr_test_runs r
    WHERE NOT EXISTS (SELECT 1 FROM dr_plans p WHERE p.id = r.plan_id)
  ) THEN
    RAISE EXCEPTION 'orphan dr_test_runs exist (plan_id not in dr_plans); resolve before adding the FK -- refusing to drop history';
  END IF;
END $$;

-- 3. Add the ON DELETE RESTRICT FK. The guard is scoped to THIS relation AND its FK
--    target (conname alone is not globally unique, so a same-named constraint on
--    another table/schema must not make us skip adding ours). We add it NOT VALID
--    first — which STILL enforces the FK on every NEW insert immediately, so a
--    concurrent dr_test_start can never orphan a run — and then VALIDATE the
--    pre-existing rows (step 2 already proved there are none on a healthy DB, so this
--    passes; a racing orphan would make VALIDATE fail loudly rather than slip
--    through). NOTE: add + validate run inside this migration's single transaction,
--    so the add's lock is held through validation; that is acceptable because
--    dr_test_runs is small (the scan is fast). VALIDATE runs unconditionally so an
--    existing-but-unvalidated constraint is finalized too; it is a no-op once valid.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_dr_test_runs_plan'
      AND conrelid = 'dr_test_runs'::regclass
      AND confrelid = 'dr_plans'::regclass
      AND contype = 'f'
  ) THEN
    ALTER TABLE dr_test_runs
      ADD CONSTRAINT fk_dr_test_runs_plan
      FOREIGN KEY (plan_id) REFERENCES dr_plans(id) ON DELETE RESTRICT NOT VALID;
  END IF;
  ALTER TABLE dr_test_runs VALIDATE CONSTRAINT fk_dr_test_runs_plan;
END $$;
