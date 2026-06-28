-- #39 Maintain lifecycle stage (recurring operational review).
--
-- `Operational` is a long-lived resting state with no recurring review. This
-- migration adds the per-request review-due timestamp the scheduled
-- `maintain_review_scan` job advances, an index to find due rows cheaply, and
-- seeds one enabled daily schedule so the platform begins flagging Operational
-- requests for review automatically. The scan is a SAFE-INTERNAL-WRITE: it only
-- records domain events and advances this timestamp (no provider/live call).
--
-- NULL semantics: next_maintain_review_at IS NULL means "enrolled, initial
-- review due" — a newly-Operational request gets ONE initial review-due event on
-- the next scan, then one every REVIEW_INTERVAL thereafter. No backfill and NO
-- change to requests_publish (avoids blast radius): a request that reaches
-- Operational simply keeps the column at its DEFAULT NULL and is picked up.

-- Per-request review-due instant. Nullable (DEFAULT NULL = initial review due).
-- Guarded so re-application is a no-op.
ALTER TABLE requests ADD COLUMN IF NOT EXISTS next_maintain_review_at TIMESTAMPTZ;

-- Supports the scan's due-row lookup
-- (WHERE status = 'operational' AND (next_maintain_review_at IS NULL OR <= NOW())
--  ORDER BY next_maintain_review_at NULLS FIRST, id) without a full scan as the
-- requests table grows. Partial on the Operational rows the scan ever touches.
CREATE INDEX IF NOT EXISTS idx_requests_next_maintain_review
    ON requests (next_maintain_review_at)
    WHERE status = 'operational';

-- Seed one enabled, daily maintain-review scan. Fixed id so a re-run is a no-op;
-- ON CONFLICT DO NOTHING leaves the operator free to disable or retune it without
-- the migration re-asserting it. Daily cadence bounds work while keeping the
-- review feedback loop responsive; the scan processes due Operational requests
-- across all sites (the scheduler is a platform-wide internal principal).
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES (
    '33333333-3333-4333-8333-333333333333',
    'Maintain review scan (operational requests)',
    'maintain_review_scan',
    86400,
    TRUE,
    NOW(),
    'system'
)
ON CONFLICT (id) DO NOTHING;
