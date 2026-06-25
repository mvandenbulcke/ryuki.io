-- 109_requests_enum_checks.sql — domain CHECK constraints on requests enum
-- columns (swarm-review findings #1/#2, 2026-06-25).
--
-- requests.request_type and requests.status were free TEXT (migration 003) even
-- though the engine fixes their valid values (RequestType — 14 variants — and
-- RequestStatus). Handlers validate on create, but a direct SQL write or a code
-- bug could persist a value the lifecycle state machine cannot interpret.
--
-- Added NOT VALID: the constraint applies to ALL future INSERT/UPDATEs
-- immediately, but the one-time historical-row scan is skipped — so the
-- migration applies cleanly against an accumulated requests table regardless of
-- any legacy value. (No migration seeds requests; rows are runtime-written and
-- already valid.) Status allows the legacy read-aliases the parser accepts
-- (executed/verified) so an UPDATE to any legacy row never trips the check.
-- Guarded so re-application is a no-op.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'requests_request_type_check'
    ) THEN
        ALTER TABLE requests
            ADD CONSTRAINT requests_request_type_check
            CHECK (request_type IN (
                'server-deployment', 'patch-maintenance', 'reboot-orchestration',
                'controlled-restore', 'zabbix-onboarding', 'cmdb-import',
                'cmdb-update-export', 'operator-runbook-launch',
                'application-environment-retirement', 'vm-decommission-quarantine',
                'request-preflight', 'vm-day2-change', 'snapshot-governance',
                'backup-coverage-report'
            )) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'requests_status_check'
    ) THEN
        ALTER TABLE requests
            ADD CONSTRAINT requests_status_check
            CHECK (status IN (
                'draft', 'intake', 'validated', 'planned', 'approved', 'locked',
                'executing', 'executed', 'verifying', 'verified', 'completed',
                'protecting', 'operational', 'retired', 'failed', 'rejected',
                'cancelled'
            )) NOT VALID;
    END IF;
END $$;
