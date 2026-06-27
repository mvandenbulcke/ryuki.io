-- 111_domain_events_append_only.sql — make the domain-event stream immutable.
--
-- `domain_events` (migration 110) is an operational feed other subsystems trust
-- to faithfully reflect committed state changes. The application only ever
-- INSERTs and SELECTs it; this enforces that at the database so a bug — or a
-- privileged operator — cannot rewrite or erase history. Mirrors the audit_log
-- append-only posture (migration 046): a row-level guard blocks UPDATE/DELETE,
-- and a statement-level guard blocks TRUNCATE (which does not fire row triggers).

CREATE OR REPLACE FUNCTION domain_events_no_mutate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'domain_events is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER domain_events_append_only
    BEFORE UPDATE OR DELETE ON domain_events
    FOR EACH ROW EXECUTE FUNCTION domain_events_no_mutate();

CREATE TRIGGER domain_events_no_truncate
    BEFORE TRUNCATE ON domain_events
    FOR EACH STATEMENT EXECUTE FUNCTION domain_events_no_mutate();
