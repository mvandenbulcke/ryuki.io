-- 046_audit_log.sql — append-only audit trail for request lifecycle transitions.
--
-- This wave introduces the durable who-did-what-when record for the request
-- lifecycle. The `requests` table keeps the LIVE state (status/stage); this
-- table is a satellite of `requests` via request_id and records every
-- transition (create + validate/plan/approve/lock/execute/verify + the new
-- reject/cancel) with the REAL verified session identity from the AuthSession.
--
-- SCOPE: exactly ONE table this wave. We deliberately do NOT create
-- request_events / approvals / evidence_packs / locks tables — those are later
-- waves. Actor attribution is normalized here, not denormalized onto
-- `requests` (no approved_by/transitioned_by columns are added), keeping the
-- requests schema stable and the trail append-only.
--
-- TAMPER-EVIDENCE: a BEFORE UPDATE OR DELETE trigger makes this table
-- append-only — INSERT is the only permitted write path, for the application
-- DB role and for any later bug alike. Hash-chaining (the design doc's
-- prev_hash/entry_hash) is EXPLICITLY OUT OF SCOPE this wave; the append-only
-- trigger is the tamper-evidence floor for now.

CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  request_id UUID REFERENCES requests(id),        -- nullable: non-request audit later
  actor_principal TEXT NOT NULL,                  -- AuthSession.user_id (the verified identity)
  actor_display TEXT,                             -- AuthSession.display_name
  actor_roles TEXT[] NOT NULL DEFAULT '{}',       -- AuthSession.roles snapshot at action time
  provider_mode TEXT NOT NULL,                    -- AuthSession.provider_mode ('local'|'entra-id'|'static-dry-run')
  action TEXT NOT NULL,                           -- 'request.validate','request.plan','request.approve','request.lock','request.execute','request.verify','request.create','request.reject','request.cancel'
  from_stage TEXT,                                -- request.stage BEFORE (NULL for create)
  to_stage TEXT NOT NULL,                         -- request.stage AFTER
  from_status TEXT,                               -- request.status BEFORE
  to_status TEXT NOT NULL,                        -- request.status AFTER
  detail JSONB NOT NULL DEFAULT '{}',             -- reason text (reject/cancel), non-secret context
  outcome TEXT NOT NULL DEFAULT 'applied'         -- 'applied'|'denied' (denied = 403 attempts, audit-relevant)
);

CREATE INDEX idx_audit_log_request ON audit_log (request_id, occurred_at);
CREATE INDEX idx_audit_log_actor ON audit_log (actor_principal, occurred_at);
CREATE INDEX idx_audit_log_action ON audit_log (action, occurred_at);

-- Append-only enforcement: any UPDATE or DELETE against audit_log raises,
-- so neither the application nor a later code change can rewrite or delete
-- history. INSERT remains the only permitted write path.
CREATE OR REPLACE FUNCTION audit_log_no_mutate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_no_mutate();

-- TRUNCATE does not fire row-level triggers, so without a statement-level
-- guard the entire trail could be erased in one statement despite the
-- row-level block above. Close that gap so append-only actually holds.
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_no_mutate();
