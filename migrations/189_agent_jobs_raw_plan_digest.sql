-- Persist the direct commitment to the complete canonical Terraform plan.
-- This is deliberately distinct from evidence_digest, which commits only to
-- the retained safe-projection evidence bytes.

ALTER TABLE agent_jobs
    ADD COLUMN raw_plan_digest TEXT,
    ADD CONSTRAINT agent_jobs_raw_plan_digest_check
        CHECK (
            raw_plan_digest IS NULL
            OR (
                raw_plan_digest ~ '^[0-9a-f]{64}$'
                AND mode = 'LivePlan'
                AND status = 'Succeeded'
                AND result_status = 'planned'
                AND signed_envelope IS NOT NULL
            )
        );

COMMENT ON COLUMN agent_jobs.raw_plan_digest IS
    'Signed SHA-256 commitment to the complete canonical raw Terraform plan; present only for successful LivePlan results and never interchangeable with evidence_digest.';

COMMENT ON COLUMN job_steps.live_plan_digest IS
    'Raw canonical Terraform plan digest copied from the exact successful LivePlan job/attempt; used for step-scoped approval, never the evidence digest.';
