-- migration 083: portal_notifications — per-recipient in-portal notification feed (Theme 9 slice 1).
-- A non-critical convenience feed emitted (best-effort, post-commit) on request-lifecycle transitions.
CREATE TABLE IF NOT EXISTS portal_notifications (
    id              TEXT PRIMARY KEY,
    recipient_kind  TEXT NOT NULL CHECK (recipient_kind IN ('Role','User')),
    recipient_id    TEXT NOT NULL,
    event           TEXT NOT NULL,                 -- the lifecycle action, e.g. 'request.approve'
    request_id      UUID,                          -- nullable; the related request (no FK — fail-open decoupling)
    severity        TEXT NOT NULL CHECK (severity IN ('Info','Success','Warning','Critical')),
    title           TEXT NOT NULL,
    body            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_portal_notifications_recipient
    ON portal_notifications (recipient_kind, recipient_id, created_at);

-- Per-user read receipts. A notification is "read" BY A GIVEN USER iff a receipt
-- row exists for (notification_id, user_id). This gives every recipient an
-- INDEPENDENT read-state even for a shared role-targeted notification: when one
-- approver reads the "awaiting approval" notification, the others still see it
-- unread. (No users table exists to enumerate role members, so receipts are
-- created lazily on mark-read rather than fanned out at emit time.)
CREATE TABLE IF NOT EXISTS portal_notification_reads (
    notification_id TEXT NOT NULL REFERENCES portal_notifications(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL,
    read_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (notification_id, user_id)
);

-- A couple of seeds so the read API has data in a fresh DB. NULL request_id = system notifications.
INSERT INTO portal_notifications (id, recipient_kind, recipient_id, event, request_id, severity, title, body)
VALUES
    ('pn-seed-0001','Role','DatacenterApprover','request.plan',NULL,'Info','Request awaiting approval','A request has been planned and is awaiting approval.'),
    ('pn-seed-0002','User','static-user','request.verify',NULL,'Success','Request completed','Your request has completed successfully.')
ON CONFLICT (id) DO NOTHING;
