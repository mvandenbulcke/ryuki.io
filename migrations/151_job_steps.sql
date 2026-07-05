-- 151_job_steps.sql — persistence for a request's multi-step orchestration plan
-- (#42 slice 2a). Each row is one step of a request's ordered plan: its stable
-- key, its dependency keys, the IaC reference to dispatch when it becomes ready,
-- its readiness-relevant status (mirrors ryuki_engine::job_orchestration::
-- StepStatus), and a back-link to the agent_job dispatched for it (if any).
-- The pure dependency-readiness core (validate_plan / ready_steps) lives in
-- ryuki-engine and is DB-free; this table is only the durable state that core
-- reads and updates. depends_on is a plain TEXT[] (not a join table) because the
-- dependency graph is authored once per request and read back as a whole plan
-- (see repos::job_steps::load_plan), never queried edge-by-edge.
CREATE TABLE IF NOT EXISTS job_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES requests(id),
    step_key TEXT NOT NULL,
    depends_on TEXT[] NOT NULL DEFAULT '{}',
    iac_ref TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending','Running','Succeeded','Failed')),
    agent_job_id UUID REFERENCES agent_jobs(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_job_steps_request_step UNIQUE (request_id, step_key)
);

CREATE INDEX IF NOT EXISTS idx_job_steps_request_id ON job_steps (request_id);
CREATE INDEX IF NOT EXISTS idx_job_steps_agent_job_id ON job_steps (agent_job_id) WHERE agent_job_id IS NOT NULL;
