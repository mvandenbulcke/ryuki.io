-- 143_agents_protocol_version.sql — record each agent's CP↔agent wire protocol version.
--
-- The wire contract (ryuki-protocol) gained a schema-compatibility marker
-- (ryuki_protocol::PROTOCOL_VERSION, carried in the x-ryuki-protocol-version
-- header on every agent request). This column records the version an agent last
-- asserted — set at registration and refreshed on heartbeat — for audit /
-- operator visibility ONLY. It is NOT a dispatch gate: the live, per-request
-- gate is the poll/result header check against SUPPORTED_PROTOCOL_VERSIONS, so a
-- drifted agent is rejected on the actual request, not on a possibly-stale row.
--
-- Backfill = 1: every agent enrolled before versioning existed spoke the schema
-- that predates the header, which is version 1 (matches PROTOCOL_VERSION_LEGACY).
-- BIGINT, not INT: the wire type is u32, whose max (4_294_967_295) overflows a
-- signed INT (i32) — BIGINT (i64) holds all of u32 losslessly. Bind `u32 as i64`
-- on write, read `i64 as u32` on read.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS protocol_version BIGINT NOT NULL DEFAULT 1
    CHECK (protocol_version > 0);
