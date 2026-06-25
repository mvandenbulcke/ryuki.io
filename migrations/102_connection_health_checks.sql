-- 102_connection_health_checks.sql — integration connection health history (#19).
--
-- POST /api/integrations/{id}/test runs a connection health probe but kept only
-- the LATEST result (last_test_at/last_test_result on the connection). This adds
-- a durable HISTORY so an operator can see health over time (and so a future
-- scheduled monitor — gated on the scheduler's write-capable job kinds, #11 —
-- can append automatically). One row per check; cascades with its connection.

CREATE TABLE IF NOT EXISTS connection_health_checks (
    id                TEXT PRIMARY KEY,
    connection_id     TEXT NOT NULL
                      REFERENCES integration_connections (id) ON DELETE CASCADE,
    checked_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    endpoint_status   TEXT NOT NULL,
    credential_status TEXT NOT NULL,
    message           TEXT
);

-- The history read: most-recent checks for a connection.
CREATE INDEX IF NOT EXISTS idx_connection_health_checks_conn
    ON connection_health_checks (connection_id, checked_at DESC);
