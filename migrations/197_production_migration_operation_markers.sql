-- Durable witness for resolving a lost production COMMIT acknowledgement.
--
-- The operation id is a domain-separated digest of the release, exact
-- independently attested PostgreSQL target, and final embedded inventory. The
-- row is inserted only after postflight succeeds and in the same transaction
-- as every migration and ledger row. Its presence therefore proves that the
-- corresponding transaction committed; absence never proves rollback.
CREATE TABLE public.production_migration_operations (
    operation_id TEXT PRIMARY KEY,
    release_binding_digest TEXT NOT NULL,
    target_binding_digest TEXT NOT NULL,
    migration_inventory_digest TEXT NOT NULL,
    attestation_response_digest TEXT NOT NULL,
    session_binding_digest TEXT NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL
);

COMMENT ON TABLE public.production_migration_operations IS
    'Append-only, non-secret completion witnesses for production migration commit reconciliation';

REVOKE ALL PRIVILEGES ON TABLE public.production_migration_operations FROM PUBLIC;

CREATE FUNCTION public.prevent_production_migration_operation_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'production migration operation markers are permanent and append-only'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER production_migration_operations_no_mutation
BEFORE UPDATE OR DELETE ON public.production_migration_operations
FOR EACH ROW EXECUTE FUNCTION public.prevent_production_migration_operation_mutation();

CREATE TRIGGER production_migration_operations_no_truncate
BEFORE TRUNCATE ON public.production_migration_operations
FOR EACH STATEMENT EXECUTE FUNCTION public.prevent_production_migration_operation_mutation();
