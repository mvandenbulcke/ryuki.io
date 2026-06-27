-- 110_domain_events.sql — operational domain-event stream (#11, swarm finding #11).
--
-- A durable, append-only log of OPERATIONAL events emitted as significant state
-- changes are committed (initially: every request lifecycle transition, emitted
-- atomically with its audit row in apply_transition_audited). This is distinct
-- from `audit_log`:
--   * audit_log is the security/compliance trail — hash-chained, redacted,
--     tamper-evident, keyed to the actor and the request.
--   * domain_events is the OPERATIONAL stream — a feed other subsystems consume
--     to drive alert generation, dashboards, and downstream automation.
--
-- Append-only by convention: the API only ever INSERTs and SELECTs. `payload`
-- carries references/summary only — never secrets, keys, or vault paths.

CREATE TABLE IF NOT EXISTS domain_events (
    id             BIGSERIAL PRIMARY KEY,
    -- Dotted event name, e.g. 'request.approve', 'request.verify'.
    event_type     TEXT NOT NULL,
    -- The aggregate this event is about, e.g. 'request'.
    aggregate_type TEXT NOT NULL,
    -- The aggregate's id (the request id, etc.).
    aggregate_id   TEXT NOT NULL,
    -- Optional scope so consumers (and the read API) can filter per site/env.
    site           TEXT,
    environment    TEXT,
    -- The principal whose action produced the event (from the verified session).
    actor          TEXT NOT NULL,
    -- Non-secret summary/references for the event (e.g. from/to status).
    payload        JSONB NOT NULL DEFAULT '{}',
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Newest-first feed reads.
CREATE INDEX IF NOT EXISTS idx_domain_events_occurred
    ON domain_events (occurred_at DESC);
-- Per-aggregate history ("all events for request X").
CREATE INDEX IF NOT EXISTS idx_domain_events_aggregate
    ON domain_events (aggregate_type, aggregate_id);
-- Per-type feed ("all request.approve events"), newest first.
CREATE INDEX IF NOT EXISTS idx_domain_events_type
    ON domain_events (event_type, occurred_at DESC);
-- Per-site filtering for scoped reads.
CREATE INDEX IF NOT EXISTS idx_domain_events_site
    ON domain_events (site);
