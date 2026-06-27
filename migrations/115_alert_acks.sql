-- 115_alert_acks.sql — operator acknowledgement of alerts (#11 slice 2e).
--
-- Alerts are DERIVED from the append-only domain_events stream (no materialized
-- alerts table). Acknowledgement is the one piece of mutable, alert-specific
-- state, so it lives in this satellite keyed by the domain_events row id: one ack
-- per alert event. The feed (GET /api/events/alerts) LEFT-joins this to show
-- which alerts have been seen, by whom, and when. Re-acking updates in place.

CREATE TABLE IF NOT EXISTS alert_acks (
    -- The acknowledged alert == a domain_events row. FK guarantees the alert
    -- exists; the events table is append-only so the referent never changes.
    event_id        BIGINT PRIMARY KEY REFERENCES domain_events(id),
    acknowledged_by TEXT        NOT NULL,
    acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    note            TEXT
);
