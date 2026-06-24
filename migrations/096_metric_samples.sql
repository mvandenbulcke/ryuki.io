-- 096_metric_samples.sql — general time-series metric history (#34).
--
-- The control plane had only domain-specific point-in-time snapshots
-- (site_capacity, vm_utilization, capacity_history) and no general substrate for
-- recording an arbitrary named metric over time and forecasting it. This adds
-- one: an append-only series of (metric_key, optional site/env scope, value,
-- observed_at). It is the foundation the AIOps chain consumes — anomaly
-- detection (#35) reads the summary mean/stddev, suggestion/what-if (#36/#37)
-- read the linear forecast, budget alerts (#53/#54) compare a projection to a
-- threshold. The forecasting math is pure (ryuki_engine::metric_forecast).
--
-- This is NOT a replacement for Prometheus (the raw-infra-metric source of
-- truth); it stores the control plane's own derived/business metrics (cost,
-- capacity, utilization aggregates) that drive planning.

CREATE TABLE IF NOT EXISTS metric_samples (
    id          TEXT PRIMARY KEY,
    -- Dotted metric identifier, e.g. 'cost.monthly_usd', 'capacity.cpu_util_pct'.
    metric_key  TEXT NOT NULL,
    -- Optional scope; NULL = a platform-wide metric not tied to a site/env.
    site        TEXT,
    environment TEXT,
    value       DOUBLE PRECISION NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Reject non-finite values durably (the API also guards this): NaN fails
    -- `value = value`, and ±Infinity are excluded explicitly. A non-finite
    -- sample would poison every forecast computed off the series.
    CONSTRAINT metric_samples_value_finite
        CHECK (value = value
               AND value <> 'Infinity'::float8
               AND value <> '-Infinity'::float8)
);

-- The read path: a series for one metric_key (optionally scoped) in time order.
CREATE INDEX IF NOT EXISTS idx_metric_samples_series
    ON metric_samples (metric_key, site, environment, observed_at);
