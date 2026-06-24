-- 097_metric_budgets.sql — cost/capacity budget thresholds (#53).
--
-- A budget is a threshold on a metric_samples series (#34): "alert when this
-- metric in this scope goes above (a cost/usage cap) or below (a capacity floor)
-- the threshold". The budget status endpoint evaluates each enabled budget
-- against both the latest observed value AND the forecast peak (so a trend that
-- is about to breach is surfaced before it does), using the pure
-- ryuki_engine::metric_budget evaluator.

CREATE TABLE IF NOT EXISTS metric_budgets (
    id          TEXT PRIMARY KEY,
    metric_key  TEXT NOT NULL,
    -- Optional scope; NULL = a platform-wide budget on the platform-wide series.
    site        TEXT,
    environment TEXT,
    threshold   DOUBLE PRECISION NOT NULL,
    -- 'above' = breach when the value exceeds the threshold (cost/usage cap);
    -- 'below' = breach when the value falls under it (capacity/headroom floor).
    comparison  TEXT NOT NULL DEFAULT 'above'
                CHECK (comparison IN ('above', 'below')),
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- The threshold must be finite. NOTE: Postgres treats `NaN = NaN` as TRUE
    -- and NaN as greater than every non-NaN value, so a range check is the
    -- correct way to exclude NaN AND ±Infinity: a finite value is strictly
    -- between -Inf and +Inf; NaN fails `< 'Infinity'` (NaN is not < anything),
    -- and ±Inf fail their own bound.
    CONSTRAINT metric_budgets_threshold_finite
        CHECK (threshold > '-Infinity'::float8 AND threshold < 'Infinity'::float8)
);

-- The status endpoint scans enabled budgets, evaluating each against its series.
CREATE INDEX IF NOT EXISTS idx_metric_budgets_enabled
    ON metric_budgets (metric_key)
    WHERE enabled;
