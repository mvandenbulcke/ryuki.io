-- 094_audit_log_hash_chain.sql — tamper-evident hash chain for audit_log.
--
-- Migration 046 made audit_log append-only via a BEFORE UPDATE OR DELETE
-- trigger but explicitly DEFERRED hash-chaining. This adds it: each new row
-- carries `entry_hash = sha256(prev_hash ++ canonical(content))` chained to its
-- predecessor's entry_hash, so a privileged operator who bypasses the trigger
-- (or restores a doctored backup) cannot rewrite or reorder history without the
-- chain failing re-verification (POST /api/audit/log/verify).
--
-- Both columns are NULLABLE: rows written before this migration have NULL
-- hashes and are not part of the chain. The chain begins at the first row
-- inserted after this migration (its prev_hash is the GENESIS sentinel). The
-- hash covers the app-known CONTENT (actor, action, from/to, detail, outcome,
-- request_id) — NOT the DB-generated id/occurred_at — and the prev→entry link
-- seals ordering, insertion, and deletion.
--
-- ADD COLUMN is DDL, not a row UPDATE, so it does not fire the append-only
-- trigger.

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash  TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash TEXT;

-- Walking the chain in insert order = id order over the chained rows.
CREATE INDEX IF NOT EXISTS idx_audit_log_entry_hash
    ON audit_log (id)
    WHERE entry_hash IS NOT NULL;
