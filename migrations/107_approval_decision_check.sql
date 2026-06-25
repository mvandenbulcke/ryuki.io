-- 107_approval_decision_check.sql — constrain the approval-decision domain (#4).
--
-- request_approval_decisions.decision (migration 047) was a free TEXT column.
-- The API only ever writes 'approved'|'rejected', and the quorum evaluator (#4)
-- counts on exactly those values — an unexpected value (a future bug, a manual
-- insert, a migration) would be SILENTLY ignored and miscount the quorum. Pin
-- the domain at the DB level so an invalid decision is rejected, not miscounted.
--
-- Guarded so re-application is a no-op. All existing rows are already
-- 'approved'/'rejected', so the constraint validates cleanly.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'request_approval_decisions_decision_check'
    ) THEN
        ALTER TABLE request_approval_decisions
            ADD CONSTRAINT request_approval_decisions_decision_check
            CHECK (decision IN ('approved', 'rejected'));
    END IF;
END $$;
