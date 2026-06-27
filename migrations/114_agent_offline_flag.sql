-- 114_agent_offline_flag.sql — dedup flag for the agent-offline emitter (#11 slice 2d).
--
-- The background agent-offline scan (spawn_agent_offline_scan) emits an
-- `agent.offline` domain event only when an APPROVED agent that has checked in
-- before goes stale (last_seen_at older than the liveness threshold), and
-- `agent.online` when it checks back in — not on every tick. This boolean records
-- the last emitted liveness state per agent so the scan can detect the transition
-- and dedup. An approved-but-never-seen agent (last_seen_at IS NULL) is "not yet
-- online", not "went offline", and is skipped — so it never flips this flag.
-- Mirrors slo_definitions.breaching (112) / metric_budgets.breaching (113).

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS offline_alerted BOOLEAN NOT NULL DEFAULT FALSE;
