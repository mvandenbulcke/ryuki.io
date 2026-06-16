-- Extend backup_coverage_reports and restore_requests to hold the full engine
-- models.
--
-- Migration 007 created the base tables without `metadata` JSONB columns and
-- defaulted `status` to lowercase values. This migration adds the missing
-- columns, fixes the defaults, normalizes any pre-existing rows, and pins the
-- legal value sets at the DB boundary.

ALTER TABLE backup_coverage_reports ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE backup_coverage_reports ALTER COLUMN status SET DEFAULT 'Generated';

ALTER TABLE restore_requests ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE restore_requests ALTER COLUMN status SET DEFAULT 'Draft';

-- Normalize any pre-existing rows from the migration-007 lowercase/kebab forms
-- to the serde PascalCase the repo round-trips, BEFORE the CHECK constraints.
-- 007 ships no seed rows, so these are no-ops on a clean DB — but they keep the
-- migration safe against any rows created before this slice (e.g. a long-lived
-- dev database), instead of failing the new CHECKs.
UPDATE backup_coverage_reports SET status = initcap(status)
    WHERE status IN ('generated', 'reviewing', 'accepted');
UPDATE backup_coverage_reports SET status = 'ActionRequired' WHERE status = 'action_required';

UPDATE restore_requests SET status = initcap(status)
    WHERE status IN ('draft', 'validated', 'planned', 'approved', 'locked',
                     'executed', 'verified', 'completed', 'failed');
UPDATE restore_requests SET restore_type = CASE restore_type
    WHEN 'full-vm' THEN 'FullVm'
    WHEN 'file-level' THEN 'FileLevel'
    WHEN 'application-item' THEN 'ApplicationItem'
    WHEN 'instant-vm-recovery' THEN 'InstantVmRecovery'
    ELSE restore_type
END;
-- The engine model stores the approver in metadata; backfill any existing
-- `approver` column value into metadata so it is not lost.
UPDATE restore_requests
    SET metadata = jsonb_set(metadata, '{approver}', to_jsonb(approver))
    WHERE approver IS NOT NULL AND approver <> '' AND NOT (metadata ? 'approver');

-- Pin the legal sets and non-negative count invariants at the DB boundary.
ALTER TABLE backup_coverage_reports ADD CONSTRAINT backup_coverage_reports_status_check
    CHECK (status IN ('Generated', 'Reviewing', 'ActionRequired', 'Accepted'));
ALTER TABLE backup_coverage_reports ADD CONSTRAINT backup_coverage_reports_counts_check
    CHECK (total_assets >= 0 AND covered_assets >= 0 AND missing_backup >= 0
           AND missing_dr_replica >= 0 AND stale_policy >= 0 AND coverage_percentage >= 0);

ALTER TABLE restore_requests ADD CONSTRAINT restore_requests_status_check
    CHECK (status IN ('Draft', 'Validated', 'Planned', 'Approved', 'Locked',
                      'Executed', 'Verified', 'Completed', 'Failed'));
ALTER TABLE restore_requests ADD CONSTRAINT restore_requests_type_check
    CHECK (restore_type IN ('FullVm', 'FileLevel', 'ApplicationItem', 'InstantVmRecovery'));
