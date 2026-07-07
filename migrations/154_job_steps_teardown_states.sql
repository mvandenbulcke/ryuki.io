-- 154_job_steps_teardown_states.sql — teardown step states (#42 slice B2-2).
--
-- Auto compensating teardown (docs/design/live-apply-per-step.md): when a step
-- of a multi-step LIVE request fails after earlier steps applied, the CP rolls
-- the applied steps back in REVERSE dependency order. Two new step statuses
-- track that rollback:
--   * 'TearingDown' — a LiveDestroy job is dispatched for this (previously
--     'Applied') step and is in flight; and
--   * 'ToreDown'    — its LiveDestroy succeeded; the step's applied resources
--     have been destroyed.
--
-- The request itself stays 'executing' while it tears down (so the teardown
-- LiveDestroy results still route through backlink_request_execution), then
-- advances to 'failed' once every applied step is ToreDown — a clean rollback.
-- A teardown that itself FAILS halts: the request goes 'failed' with applied/
-- TearingDown steps left intact for an operator (no RequestStatus enum variant
-- is added — the step statuses under a failed request are the needs-operator
-- signal). Widening an auto-named inline CHECK follows the mig 151/152
-- precedent (drop + re-add); old values are a subset of the new set.
ALTER TABLE job_steps DROP CONSTRAINT IF EXISTS job_steps_status_check;
ALTER TABLE job_steps ADD CONSTRAINT job_steps_status_check
    CHECK (status IN (
        'Pending', 'Running', 'Succeeded', 'Failed',
        'Planning', 'AwaitingApproval', 'Applying', 'Applied',
        'TearingDown', 'ToreDown'
    ));
