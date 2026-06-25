-- 103_slo_definitions.sql — SLO / error-budget definitions (#25).
--
-- An SLO is a target reliability (e.g. 0.999) over a window, measured as
-- GOOD events / TOTAL events. Both counts come from the metric_samples
-- substrate (#34): an operator records `good_metric_key` and `total_metric_key`
-- samples, and GET /api/metrics/slo/status sums them over the window and
-- computes attainment + error-budget burn via the pure ryuki_engine::slo.

CREATE TABLE IF NOT EXISTS slo_definitions (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    -- Target reliability in the open interval (0, 1), e.g. 0.999.
    target           DOUBLE PRECISION NOT NULL CHECK (target > 0 AND target < 1),
    window_days      INTEGER NOT NULL DEFAULT 30 CHECK (window_days BETWEEN 1 AND 365),
    good_metric_key  TEXT NOT NULL,
    total_metric_key TEXT NOT NULL,
    site             TEXT,
    environment      TEXT,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_slo_definitions_enabled
    ON slo_definitions (id)
    WHERE enabled;
