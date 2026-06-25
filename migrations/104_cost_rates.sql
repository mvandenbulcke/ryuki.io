-- 104_cost_rates.sql — chargeback/showback cost rates (#46).
--
-- Builds on usage metering (#45): a per-request-type unit cost lets the
-- chargeback report allocate cost to each site as
--   sum over request types of (request_count * unit_cost).
-- One rate per request_type (UPSERT on conflict). Currency is informational —
-- the report assumes a single currency across the active rates.

CREATE TABLE IF NOT EXISTS cost_rates (
    id           TEXT PRIMARY KEY,
    request_type TEXT NOT NULL UNIQUE,
    unit_cost    DOUBLE PRECISION NOT NULL CHECK (unit_cost >= 0),
    currency     TEXT NOT NULL DEFAULT 'USD',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A finite, non-negative rate (NaN would poison every allocation).
    CONSTRAINT cost_rates_unit_cost_finite
        CHECK (unit_cost > '-Infinity'::float8 AND unit_cost < 'Infinity'::float8)
);
