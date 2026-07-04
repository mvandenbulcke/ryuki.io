-- 146_agent_jobs_origin.sql — mark scheduler-created drift-recheck jobs (#31 slice 2).
-- A nullable origin tag distinguishes a scheduled drift-recheck LivePlan (origin='drift_recheck')
-- from a normal operator/request-path job (origin NULL). The CP only classifies drift for the former,
-- so an operator plan preview (expected to show changes) never emits a spurious drift event.
-- Nullable + no default so every existing INSERT INTO agent_jobs (which omits origin) still works.
ALTER TABLE agent_jobs ADD COLUMN IF NOT EXISTS origin TEXT;
