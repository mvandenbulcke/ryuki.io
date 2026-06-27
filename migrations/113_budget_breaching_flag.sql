-- 113_budget_breaching_flag.sql — dedup flag for the budget-breach emitter (#11 slice 2c).
--
-- The background budget-breach scan (spawn_budget_breach_scan) emits a
-- `budget.breach` domain event only when a metric budget TRANSITIONS into breach,
-- and `budget.recovered` when it transitions back — not on every tick. This
-- boolean records the last definitively-evaluated state per budget so the scan
-- can detect the transition (false→true / true→false) and dedup. Transient
-- evaluations (series-read error, no data) leave it unchanged, so a flapping or
-- gapping metric source never spams. Mirrors slo_definitions.breaching (mig 112).

ALTER TABLE metric_budgets
    ADD COLUMN IF NOT EXISTS breaching BOOLEAN NOT NULL DEFAULT FALSE;
