-- Persist the engine's ordered-step contract at the database boundary. Legacy
-- snapshots that cannot prove the contract remain readable but quarantined;
-- they cannot transition and must be restarted from the catalog.

SET LOCAL lock_timeout = '30s';
LOCK TABLE runbook_executions IN ACCESS EXCLUSIVE MODE;

ALTER TABLE runbook_executions
    ADD COLUMN invariant_state TEXT NOT NULL DEFAULT 'Quarantined',
    ADD COLUMN invariant_reason TEXT DEFAULT 'writer-contract-required';

CREATE OR REPLACE FUNCTION runbook_execution_invariants_hold(
    p_id TEXT,
    p_runbook_id TEXT,
    p_status TEXT,
    p_site TEXT,
    p_started_by TEXT,
    p_execution JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
DECLARE
    expected_steps INTEGER;
    positive_count INTEGER;
    distinct_count INTEGER;
    marker_count INTEGER;
BEGIN
    expected_steps := CASE p_runbook_id
        WHEN 'patch-windows-server' THEN 3
        WHEN 'restart-service' THEN 3
        WHEN 'certificate-renewal' THEN 3
        WHEN 'dns-record-update' THEN 3
        WHEN 'firewall-rule-change' THEN 3
        ELSE NULL
    END;
    IF expected_steps IS NULL
       OR jsonb_typeof(p_execution) <> 'object'
       OR jsonb_typeof(p_execution->'steps_results') <> 'array'
       OR jsonb_typeof(p_execution->'id') <> 'string'
       OR jsonb_typeof(p_execution->'runbook_id') <> 'string'
       OR jsonb_typeof(p_execution->'status') <> 'string'
       OR jsonb_typeof(p_execution->'site') <> 'string'
       OR jsonb_typeof(p_execution->'started_by') <> 'string'
       OR p_execution->>'id' IS DISTINCT FROM p_id
       OR p_execution->>'runbook_id' IS DISTINCT FROM p_runbook_id
       OR p_execution->>'status' IS DISTINCT FROM p_status
       OR p_execution->>'site' IS DISTINCT FROM p_site
       OR p_execution->>'started_by' IS DISTINCT FROM p_started_by
       OR p_status NOT IN ('draft', 'approved', 'running', 'completed',
                           'failed', 'rolled-back') THEN
        RETURN FALSE;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(p_execution->'steps_results') AS item(step)
        WHERE jsonb_typeof(step) <> 'object'
           OR step->>'step_order' IS NULL
           OR step->>'step_order' !~ '^(0|[1-9][0-9]{0,8})$'
           OR step->>'status' IS NULL
           OR step->>'status' NOT IN ('pending', 'running', 'completed', 'failed')
           OR step->'output' IS NULL
           OR jsonb_typeof(step->'output') <> 'string'
           OR (step->>'started_at' IS NOT NULL
               AND jsonb_typeof(step->'started_at') <> 'string')
           OR (step->>'completed_at' IS NOT NULL
               AND jsonb_typeof(step->'completed_at') <> 'string')
           OR CASE step->>'status'
                WHEN 'pending' THEN
                    step->>'started_at' IS NOT NULL
                    OR step->>'completed_at' IS NOT NULL
                WHEN 'running' THEN
                    step->>'started_at' IS NULL
                    OR step->>'completed_at' IS NOT NULL
                ELSE
                    step->>'started_at' IS NULL
                    OR step->>'completed_at' IS NULL
              END
    ) THEN
        RETURN FALSE;
    END IF;

    SELECT count(*) FILTER (WHERE (step->>'step_order')::integer > 0),
           count(DISTINCT (step->>'step_order')::integer)
               FILTER (WHERE (step->>'step_order')::integer > 0),
           count(*) FILTER (WHERE (step->>'step_order')::integer = 0)
    INTO positive_count, distinct_count, marker_count
    FROM jsonb_array_elements(p_execution->'steps_results') AS item(step);

    IF positive_count <> expected_steps
       OR distinct_count <> expected_steps
       OR EXISTS (
            SELECT 1
            FROM jsonb_array_elements(p_execution->'steps_results') AS item(step)
            WHERE (step->>'step_order')::integer > expected_steps
       )
       OR (p_status = 'failed' AND marker_count <> 1)
       OR (p_status <> 'failed' AND marker_count <> 0)
       OR EXISTS (
            SELECT 1
            FROM jsonb_array_elements(p_execution->'steps_results') AS item(step)
            WHERE (step->>'step_order')::integer = 0
              AND step->>'status' <> 'failed'
       ) THEN
        RETURN FALSE;
    END IF;

    -- Any non-pending step requires every lower positive order to be complete.
    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(p_execution->'steps_results') AS current_item(current_step)
        WHERE (current_step->>'step_order')::integer > 0
          AND current_step->>'status' <> 'pending'
          AND EXISTS (
              SELECT 1
              FROM jsonb_array_elements(p_execution->'steps_results') AS prior_item(prior_step)
              WHERE (prior_step->>'step_order')::integer > 0
                AND (prior_step->>'step_order')::integer <
                    (current_step->>'step_order')::integer
                AND prior_step->>'status' <> 'completed'
          )
    ) THEN
        RETURN FALSE;
    END IF;

    IF p_status IN ('draft', 'approved') AND EXISTS (
        SELECT 1 FROM jsonb_array_elements(p_execution->'steps_results') AS item(step)
        WHERE (step->>'step_order')::integer > 0
          AND step->>'status' <> 'pending'
    ) THEN
        RETURN FALSE;
    ELSIF p_status = 'running' AND (
        NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(p_execution->'steps_results') AS item(step)
            WHERE (step->>'step_order')::integer > 0
              AND step->>'status' <> 'pending'
        )
        OR EXISTS (
            SELECT 1 FROM jsonb_array_elements(p_execution->'steps_results') AS item(step)
            WHERE (step->>'step_order')::integer > 0
              AND step->>'status' = 'failed'
        )
    ) THEN
        RETURN FALSE;
    ELSIF p_status = 'completed' AND EXISTS (
        SELECT 1 FROM jsonb_array_elements(p_execution->'steps_results') AS item(step)
        WHERE (step->>'step_order')::integer > 0
          AND step->>'status' <> 'completed'
    ) THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
END;
$$;

UPDATE runbook_executions
SET invariant_state = CASE
        WHEN public.runbook_execution_invariants_hold(
            id, runbook_id, status, site, started_by, execution_json
        ) THEN 'Verified'
        ELSE 'Quarantined'
    END,
    invariant_reason = CASE
        WHEN public.runbook_execution_invariants_hold(
            id, runbook_id, status, site, started_by, execution_json
        ) THEN NULL
        ELSE 'legacy-runbook-execution-must-be-restarted'
    END;

ALTER TABLE runbook_executions
    ADD CONSTRAINT runbook_executions_invariant_state_check
        CHECK (invariant_state IN ('Verified', 'Quarantined')),
    ADD CONSTRAINT runbook_executions_invariant_reason_check
        CHECK (
            (invariant_state = 'Verified' AND invariant_reason IS NULL)
            OR
            (invariant_state = 'Quarantined'
             AND invariant_reason IS NOT NULL
             AND invariant_reason <> '')
        );

CREATE OR REPLACE FUNCTION enforce_runbook_execution_invariants()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.invariant_state = 'Quarantined' THEN
        RAISE EXCEPTION
            'quarantined runbook execution must be restarted, not transitioned'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'UPDATE'
       AND (NEW.invariant_state IS DISTINCT FROM OLD.invariant_state
            OR NEW.invariant_reason IS DISTINCT FROM OLD.invariant_reason) THEN
        RAISE EXCEPTION 'runbook invariant classification is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'UPDATE'
       AND (NEW.id IS DISTINCT FROM OLD.id
            OR NEW.runbook_id IS DISTINCT FROM OLD.runbook_id
            OR NEW.site IS DISTINCT FROM OLD.site
            OR NEW.started_by IS DISTINCT FROM OLD.started_by) THEN
        RAISE EXCEPTION 'runbook execution identity is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'UPDATE' AND NOT (
        (OLD.status = 'draft' AND NEW.status IN ('draft', 'approved', 'failed', 'rolled-back'))
        OR (OLD.status = 'approved' AND NEW.status IN ('approved', 'running', 'failed', 'rolled-back'))
        OR (OLD.status = 'running' AND NEW.status IN ('running', 'completed', 'failed', 'rolled-back'))
    ) THEN
        RAISE EXCEPTION 'illegal runbook execution status transition'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.invariant_state = 'Verified'
       AND NOT public.runbook_execution_invariants_hold(
            NEW.id,
            NEW.runbook_id,
            NEW.status,
            NEW.site,
            NEW.started_by,
            NEW.execution_json
       ) THEN
        RAISE EXCEPTION 'runbook execution violates ordered-step invariants'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS runbook_executions_enforce_invariants
ON runbook_executions;
CREATE TRIGGER runbook_executions_enforce_invariants
BEFORE INSERT OR UPDATE ON runbook_executions
FOR EACH ROW EXECUTE FUNCTION enforce_runbook_execution_invariants();

REVOKE ALL ON FUNCTION runbook_execution_invariants_hold(
    TEXT, TEXT, TEXT, TEXT, TEXT, JSONB
) FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_runbook_execution_invariants() FROM PUBLIC;

DO $$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.runbook_execution_invariants_hold('
             || 'TEXT, TEXT, TEXT, TEXT, TEXT, JSONB) FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_runbook_execution_invariants() '
             || 'FROM ryuki_app_runtime';
    END IF;
END;
$$;
