-- Exact, non-TOAST accounting for per-principal idempotency response budgets.
--
-- The value is generated from the authoritative response body, so claim,
-- finalization, release, stale takeover, and batched retention deletes cannot
-- drift an auxiliary counter. The existing (user_scope, key) primary key is
-- already ordered by user_scope and supports each bounded aggregate scan.

ALTER TABLE idempotency_records
    ADD COLUMN response_bytes BIGINT
        GENERATED ALWAYS AS (
            COALESCE(octet_length(response_body), 0)::BIGINT
        ) STORED;

COMMENT ON COLUMN idempotency_records.response_bytes IS
    'Generated UTF-8 octet count used for atomic per-principal replay storage admission';

-- Mixed-version writers are not budget-compatible: the pre-162 middleware
-- neither holds the per-principal admission lock nor fails closed on claim
-- errors. The platform-api Deployment therefore uses a non-overlapping
-- `Recreate` cutover. This trigger is the database-side backstop: even if an
-- operator accidentally overlaps versions, an old replica cannot INSERT,
-- stale-takeover UPDATE, or finalize an unbudgeted row. Contract-v2 writers set
-- the transaction-local marker only after taking the exact advisory lock below.
CREATE OR REPLACE FUNCTION enforce_idempotency_writer_contract()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    principal_lock BIGINT;
    holds_principal_lock BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.user_scope IS DISTINCT FROM OLD.user_scope THEN
        RAISE EXCEPTION 'idempotency user_scope is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'idempotency_records_writer_contract';
    END IF;

    principal_lock := hashtextextended(
        'ryuki:idempotency:principal:'::TEXT || NEW.user_scope::TEXT,
        0
    );
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks AS held
        WHERE held.locktype = 'advisory'
          AND held.pid = pg_backend_pid()
          AND held.database = (
              SELECT oid FROM pg_catalog.pg_database
              WHERE datname = current_database()
          )
          -- PostgreSQL represents the one-BIGINT advisory-lock namespace as
          -- the unsigned high/low 32-bit halves plus objsubid=1.
          AND held.classid::BIGINT = ((principal_lock >> 32) & 4294967295)
          AND held.objid::BIGINT = (principal_lock & 4294967295)
          AND held.objsubid = 1
          AND held.granted
    ) INTO holds_principal_lock;

    IF current_setting('ryuki.idempotency_writer_contract', TRUE) IS DISTINCT FROM '2'
       OR NOT holds_principal_lock THEN
        RAISE EXCEPTION 'idempotency writer contract v2 and principal admission lock are required'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'idempotency_records_writer_contract';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER idempotency_records_writer_contract
BEFORE INSERT OR UPDATE ON idempotency_records
FOR EACH ROW
EXECUTE FUNCTION enforce_idempotency_writer_contract();

COMMENT ON FUNCTION enforce_idempotency_writer_contract() IS
    'Fences pre-budget idempotency writers; requires contract v2 plus the matching transaction advisory lock';
