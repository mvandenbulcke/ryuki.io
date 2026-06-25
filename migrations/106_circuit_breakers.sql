-- 106_circuit_breakers.sql — persisted circuit-breaker state per integration
-- connection (#30).
--
-- One breaker per connection guards calls to a flaky provider/adapter: the pure
-- ryuki_engine::circuit_breaker state machine decides transitions; this table
-- just persists the latest state so it survives restarts and is shared across
-- API workers. Absence of a row means a healthy (Closed) breaker. The breaker
-- cascades away with its connection.

CREATE TABLE IF NOT EXISTS circuit_breakers (
    connection_id         TEXT PRIMARY KEY
        REFERENCES integration_connections (id) ON DELETE CASCADE,
    state                 TEXT NOT NULL DEFAULT 'closed'
        CHECK (state IN ('closed', 'open', 'half_open')),
    consecutive_failures  INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    consecutive_successes INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_successes >= 0),
    -- Unix seconds when the breaker last entered Open (drives the cooldown);
    -- NULL whenever the breaker is not Open.
    opened_at_unix        BIGINT,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- opened_at_unix is meaningful only while Open, and must be set when Open.
    CONSTRAINT circuit_breakers_open_has_timestamp
        CHECK ((state = 'open') = (opened_at_unix IS NOT NULL))
);
