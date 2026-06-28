-- 123_restore_failed_index.sql — route FAILED-latest restore tests into the work
-- queue (#52 slice 2).
--
-- Slice 1 (migration 122) routes systems whose last SUCCESSFUL restore test is
-- overdue/never-tested. Slice 2 adds the more urgent FAILED-latest signal: a
-- system whose MOST RECENT restore_request is in `Failed` status. The scan logic
-- folds into the existing `restore_overdue_scan` arm (one tick, two signals), so
-- this migration adds NO new table/column/schedule — only the second partial
-- unique index that mirrors slice 1's `uq_shift_queue_open_restore_overdue`.
--
-- Make the dedup STRUCTURAL as well as procedural (defense-in-depth + documents
-- the intended key): at most one OPEN restore-test-failed item per system. The
-- partial predicate constrains only `resolved = false` rows, so it never blocks
-- the post-resolution re-flag. This is the unique constraint the enqueue's
-- untargeted `ON CONFLICT DO NOTHING` can hit for the failed item_type.
-- Idempotent (`IF NOT EXISTS`).
CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_restore_failed
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'restore-test-failed';
