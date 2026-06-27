-- 112_slo_breaching_flag.sql — dedup flag for the SLO-breach event emitter (#11 slice 2b).
--
-- The background SLO-breach scan (spawn_slo_breach_scan) emits a `slo.breach`
-- domain event only when an SLO TRANSITIONS into breach, and `slo.recovered`
-- when it transitions back — not on every tick. This boolean records the last
-- definitively-evaluated state per SLO so the scan can detect the transition
-- (false→true / true→false) and dedup. NULL/transient (error / insufficient
-- data) evaluations leave it unchanged, so a flapping data source does not spam.

ALTER TABLE slo_definitions
    ADD COLUMN IF NOT EXISTS breaching BOOLEAN NOT NULL DEFAULT FALSE;
