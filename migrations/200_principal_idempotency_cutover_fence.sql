-- 200_principal_idempotency_cutover_fence.sql
--
-- Migration 199 necessarily discarded replay rows whose legacy provider
-- subjects could not be translated into opaque principal UUIDs.  A completed
-- mutation may have committed immediately before that cutover while its HTTP
-- response was lost.  Reopening the new namespace before the old 24-hour
-- replay contract expires would let the retry execute a second time.
--
-- Keep the schema/migration owner usable for fresh-database installation and
-- bounded migration fixtures. A pristine install is explicitly recorded and
-- may serve immediately; an upgrade fails every least-privilege application
-- writer closed until more than 24 hours after the mandatory traffic drain
-- that precedes migration 199. The ledger timestamp is transaction-start time,
-- and the extra five minutes conservatively extend that drain-anchored window;
-- it is deliberately not described as a commit timestamp. Production
-- postflight separately proves that the serving role owns neither the ledger
-- nor application tables, so this exception cannot authorize HTTP serving.
-- Bumping the transaction marker to v3 fences contract-v2 writers; the
-- independently required non-overlapping deployment remains the boundary for
-- pre-162 fail-open binaries.

SET LOCAL lock_timeout = '30s';

LOCK TABLE idempotency_records IN ACCESS EXCLUSIVE MODE;

DO $preflight$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM public._sqlx_migrations
        WHERE version = 199
          AND success
    ) THEN
        RAISE EXCEPTION
            'successful migration 199 ledger evidence is required before migration 200'
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM idempotency_records
        WHERE response_status IS NULL
           OR response_body IS NULL
    ) THEN
        RAISE EXCEPTION
            'in-flight idempotency claims must be drained or reconciled before migration 200'
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM idempotency_records AS record
        LEFT JOIN principals AS principal
          ON principal.principal_id::TEXT = record.user_scope
        WHERE principal.principal_id IS NULL
    ) THEN
        RAISE EXCEPTION
            'idempotency rows must use an existing canonical opaque principal namespace before migration 200'
            USING ERRCODE = '55000';
    END IF;
END;
$preflight$;

CREATE TABLE idempotency_principal_cutover_state (
    singleton BOOLEAN NOT NULL DEFAULT TRUE,
    requires_fence BOOLEAN NOT NULL,
    fence_until TIMESTAMPTZ,
    established_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT idempotency_principal_cutover_state_pkey
        PRIMARY KEY (singleton),
    CONSTRAINT idempotency_principal_cutover_state_singleton_check
        CHECK (singleton),
    CONSTRAINT idempotency_principal_cutover_state_shape_check
        CHECK (requires_fence = (fence_until IS NOT NULL))
);

INSERT INTO idempotency_principal_cutover_state (
    singleton,
    requires_fence,
    fence_until
)
SELECT
    TRUE,
    install.mode IS DISTINCT FROM 'fresh-install-v1',
    CASE
        WHEN install.mode = 'fresh-install-v1' THEN NULL
        ELSE migration.installed_on + make_interval(secs => 86700)
    END
FROM public._sqlx_migrations AS migration
CROSS JOIN LATERAL (
    SELECT current_setting(
        'ryuki.idempotency_principal_cutover_install_mode',
        TRUE
    ) AS mode
) AS install
WHERE migration.version = 199
  AND migration.success;

COMMENT ON TABLE idempotency_principal_cutover_state IS
    'Immutable owner-managed evidence distinguishing a pristine install from an upgrade that must preserve the pre-199 replay window';

REVOKE ALL ON TABLE idempotency_principal_cutover_state FROM PUBLIC;

CREATE OR REPLACE FUNCTION enforce_idempotency_writer_contract()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    principal_lock BIGINT;
    holds_principal_lock BOOLEAN;
    principal_cutover_requires_fence BOOLEAN;
    principal_cutover_fence_until TIMESTAMPTZ;
    caller_owns_migration_ledger BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.user_scope IS DISTINCT FROM OLD.user_scope THEN
        RAISE EXCEPTION 'idempotency user_scope is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'idempotency_records_writer_contract';
    END IF;

    IF TG_OP <> 'DELETE' THEN
        principal_lock := hashtextextended(
            'ryuki:idempotency:principal:'::TEXT || NEW.user_scope::TEXT,
            0
        );
        SELECT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_locks AS held
            WHERE held.locktype = 'advisory'
              AND held.mode = 'ExclusiveLock'
              AND held.pid = pg_backend_pid()
              AND held.database = (
                  SELECT oid FROM pg_catalog.pg_database
                  WHERE datname = current_database()
              )
              AND held.classid::BIGINT = ((principal_lock >> 32) & 4294967295)
              AND held.objid::BIGINT = (principal_lock & 4294967295)
              AND held.objsubid = 1
              AND held.granted
        ) INTO holds_principal_lock;

        IF current_setting('ryuki.idempotency_writer_contract', TRUE) IS DISTINCT FROM '3'
           OR NOT holds_principal_lock THEN
            RAISE EXCEPTION 'idempotency writer contract v3 and principal admission lock are required'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'idempotency_records_writer_contract';
        END IF;
    END IF;

    SELECT cutover.requires_fence,
           cutover.fence_until,
           pg_catalog.pg_get_userbyid(ledger.relowner) = current_user
    INTO principal_cutover_requires_fence,
         principal_cutover_fence_until,
         caller_owns_migration_ledger
    FROM public.idempotency_principal_cutover_state AS cutover
    JOIN pg_catalog.pg_class AS ledger
      ON ledger.oid = 'public._sqlx_migrations'::pg_catalog.regclass
    WHERE cutover.singleton;

    IF principal_cutover_requires_fence IS NULL THEN
        RAISE EXCEPTION 'principal idempotency cutover state is unavailable'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'idempotency_principal_namespace_cutover_fence';
    END IF;

    IF caller_owns_migration_ledger IS DISTINCT FROM TRUE
       AND principal_cutover_requires_fence
       AND clock_timestamp() < principal_cutover_fence_until THEN
        RAISE EXCEPTION 'principal idempotency namespace cutover retention window is active'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'idempotency_principal_namespace_cutover_fence';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;

    IF caller_owns_migration_ledger IS DISTINCT FROM TRUE
       AND NOT EXISTS (
            SELECT 1
            FROM public.principals AS principal
            WHERE principal.principal_id::TEXT = NEW.user_scope
       ) THEN
        RAISE EXCEPTION 'idempotency user_scope must name an existing canonical opaque principal'
            USING ERRCODE = '23503',
                  CONSTRAINT = 'idempotency_records_principal_namespace';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER idempotency_records_writer_contract ON idempotency_records;

CREATE TRIGGER idempotency_records_writer_contract
BEFORE INSERT OR UPDATE OR DELETE ON idempotency_records
FOR EACH ROW
EXECUTE FUNCTION enforce_idempotency_writer_contract();

ALTER TABLE idempotency_records
    ENABLE ALWAYS TRIGGER idempotency_records_writer_contract;

COMMENT ON FUNCTION enforce_idempotency_writer_contract() IS
    'Fences pre-v3 writers and blocks non-owner replay mutations for at least 24 hours after the opaque-principal namespace cutover';

REVOKE ALL ON FUNCTION enforce_idempotency_writer_contract() FROM PUBLIC;

DO $privileges$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.enforce_idempotency_writer_contract() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE '
             || 'public.idempotency_principal_cutover_state '
             || 'FROM ryuki_app_runtime';
    END IF;
END;
$privileges$;
