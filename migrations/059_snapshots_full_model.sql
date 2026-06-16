-- Extend snapshots to hold the full SnapshotRecord model.
--
-- Migration 006 created the base table without the `metadata` JSONB column
-- and defaulted `status` to lowercase 'draft'. This migration adds the missing
-- column, fixes the default, and pins the legal status set at the DB boundary.
--
-- There are no seed INSERT rows in migration 006, so no status normalisation
-- UPDATEs are required before the CHECK constraint.

ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Migration 006 defaulted status to lowercase 'draft', but the repo layer
-- round-trips serde PascalCase variant names. Align the column DEFAULT so a
-- defaulted insert can never be CAS-incompatible (it would read back as 'Draft'
-- yet the optimistic-lock WHERE status = 'Draft' would miss the stored 'draft').
ALTER TABLE snapshots ALTER COLUMN status SET DEFAULT 'Draft';

-- Pin the legal enum set at the database boundary so a bad write (or a future
-- migration typo) cannot persist a status the repo cannot decode.
ALTER TABLE snapshots ADD CONSTRAINT snapshots_status_check
    CHECK (status IN ('Draft', 'ReviewRequested', 'ExpiryApproved', 'StaleFlagged',
                      'RemediationPlanned', 'Expired', 'Completed', 'Failed'));
