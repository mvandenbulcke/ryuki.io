-- 118_request_required_approval_roles.sql — multi-role approval quorum ENFORCEMENT (#4).
--
-- Today requests_approve flips Planned->Approved on a SINGLE approval; the quorum
-- is only REPORTED (requests_approval_quorum) over request_approval_decisions. This
-- column lets a request require N distinct approving roles before it reaches
-- Approved. DEFAULT 1 backfills every existing row, so the default single-approval
-- flow is unchanged; only requests whose required_approval_roles is raised above 1
-- (a deferred policy follow-up) hold at Planned until the quorum is met.
--
-- Idempotent: `ADD COLUMN IF NOT EXISTS` is a no-op on re-run, and the CHECK
-- constraint is added inside a guarded DO block keyed on its name so re-running
-- the migration never errors on a duplicate constraint.

ALTER TABLE requests
    ADD COLUMN IF NOT EXISTS required_approval_roles INTEGER NOT NULL DEFAULT 1;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'requests_required_approval_roles_range'
    ) THEN
        ALTER TABLE requests
            ADD CONSTRAINT requests_required_approval_roles_range
            CHECK (required_approval_roles BETWEEN 1 AND 10);
    END IF;
END $$;
