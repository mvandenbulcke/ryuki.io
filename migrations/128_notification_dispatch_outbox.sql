-- 128_notification_dispatch_outbox.sql — the dry-run seam for outbound notification delivery (#9).
--
-- Notifications today are in-app only (portal_notifications, mig 083); SmtpConfig is dead code
-- and no send/webhook path exists. This table records, per notification, which OUTBOUND channels
-- it would be dispatched to — as DRY-RUN TELEMETRY (status 'dry_run_logged', no network I/O). A
-- later slice flips it to real sending (status 'pending' -> 'sent'/'failed') by RE-PLANNING from
-- the notification at send time; it must NOT promote these dry-run rows.
--
-- All constraints are IMMEDIATE (NOT DEFERRABLE): the emit path records plans inside a SAVEPOINT
-- so an outbox failure never rolls back the in-app notification / operational alert it describes,
-- and a savepoint only protects failures surfaced before RELEASE — a deferred constraint would
-- instead fail at the outer commit and defeat the fail-open guarantee (codex).

CREATE TABLE IF NOT EXISTS notification_dispatch_outbox (
    id              TEXT PRIMARY KEY,                          -- "ndo-{uuid}"
    notification_id TEXT NOT NULL REFERENCES portal_notifications(id) ON DELETE CASCADE,
    channel         TEXT NOT NULL CHECK (channel IN ('email', 'webhook')),
    status          TEXT NOT NULL DEFAULT 'dry_run_logged'
                        CHECK (status IN ('pending', 'dry_run_logged', 'sent', 'failed', 'skipped')),
    planned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dispatched_at   TIMESTAMPTZ,
    -- One row per (notification, channel): re-emitting the same immutable notification is a no-op
    -- (ON CONFLICT DO NOTHING). The unique index also serves the FK cascade lookup by notification_id.
    UNIQUE (notification_id, channel)
);

-- Default admin listing is `ORDER BY planned_at DESC LIMIT n` with no status filter.
CREATE INDEX IF NOT EXISTS idx_notification_dispatch_outbox_planned
    ON notification_dispatch_outbox (planned_at DESC);

-- Status-filtered listing (`?status=` + newest-first).
CREATE INDEX IF NOT EXISTS idx_notification_dispatch_outbox_status_planned
    ON notification_dispatch_outbox (status, planned_at DESC);
