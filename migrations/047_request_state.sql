-- 047_request_state.sql — durable request lifecycle state (design-doc P2).
--
-- BEFORE this wave the `requests` table held only scalars plus a VM-shaped
-- cpu/memory_gb. It could not represent the other ~13 request types, and on
-- restart the engine Request was rebuilt with EMPTY stages/approval_route and a
-- FABRICATED "DRY-RUN: Planned execution..." plan string. The audit_log
-- (migration 046) records who-did-what-when, but it is a satellite ledger, not
-- the request's own durable lifecycle.
--
-- This migration makes the request lifecycle DURABLE. The engine's source of
-- truth is `ryuki_engine::models::Request` (stages: Vec<Stage>, approval_route:
-- Vec<String>, metadata: HashMap), and every transition handler already
-- round-trips the WHOLE Request through serde_json. So the lifecycle blobs are
-- stored as JSONB, mirroring that model 1:1 — hydration becomes a single
-- serde_json::from_value and avoids a stage-row join + ordering layer the
-- engine does not need. The ONE thing that gets a normalized table is approval
-- decisions (request_approval_decisions): they are queried/uniqued per-role and
-- are Separation-of-Duties relevant.
--
-- FORWARD-ONLY / BACKWARD-COMPAT: every new column is added with a DEFAULT so
-- the pre-existing rows remain valid (payload='{}', stages='[]', plan=null,
-- criticality='standard'). The existing scalar columns
-- (request_type/status/stage/site/environment/name/cpu/memory_gb/justification/
-- created_by/created_at/updated_at) are NOT dropped or repurposed: they stay as
-- the cheap list projection, and the VM-shaped cpu/memory remain a denormalized
-- convenience copy of `payload` for server-deployment back-compat. `payload` is
-- authoritative for all 14 request types.

ALTER TABLE requests
    ADD COLUMN payload JSONB NOT NULL DEFAULT '{}'::jsonb,            -- full typed request body per request type
    ADD COLUMN stages JSONB NOT NULL DEFAULT '[]'::jsonb,            -- serde of Vec<ryuki_engine::models::Stage>: durable lifecycle history
    ADD COLUMN approval_route JSONB NOT NULL DEFAULT '[]'::jsonb,    -- serde of Vec<String> (the engine field)
    ADD COLUMN plan JSONB NOT NULL DEFAULT 'null'::jsonb,           -- serde of the produced plan stages (Vec<Stage>) OR null until planned
    ADD COLUMN validation_results JSONB NOT NULL DEFAULT 'null'::jsonb, -- serde of the last ValidationResult or null
    ADD COLUMN criticality TEXT NOT NULL DEFAULT 'standard',         -- was hardcoded "standard" in db_row_to_request
    ADD COLUMN requester TEXT,                                       -- nullable; backfilled from created_by; the SoD anchor
    ADD COLUMN owner TEXT,                                           -- nullable; request owner (distinct from requester)
    ADD COLUMN evidence_manifest_id TEXT;                            -- nullable; the engine Option<String> field, kept NULL this wave

-- Backfill the SoD anchor for legacy rows: a request created before this wave
-- has no requester/owner column, so seed both from the verified created_by.
UPDATE requests SET requester = created_by, owner = created_by WHERE requester IS NULL;

-- request_approval_decisions — the durable, normalized approval ledger.
-- A satellite of `requests` (like audit_log). One row per approval-route role
-- decision. The future multi-approver SoD checks read this table; this wave
-- writes single-role approve/reject. The decision row is INSERTed inside the
-- SAME transaction as the status-flip CAS UPDATE + audit_log insert, so a row
-- can never be approved/rejected without its decision row.
CREATE TABLE request_approval_decisions (
    id BIGSERIAL PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES requests(id),
    role TEXT NOT NULL,                 -- the approval-route role this decision satisfies (e.g. 'DatacenterApprover')
    decision TEXT NOT NULL,             -- 'approved' | 'rejected'
    actor TEXT NOT NULL,                -- AuthSession.user_id (verified principal, never client-supplied)
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT,                        -- the mandatory reject reason; NULL for approve
    CONSTRAINT uq_request_role UNIQUE (request_id, role)
);

CREATE INDEX idx_rad_request ON request_approval_decisions (request_id, decided_at);
