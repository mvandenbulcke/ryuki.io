-- Persist patch-wave maker/checker authority outside caller-editable metadata.
--
-- Existing rows predate authenticated maker capture. They remain readable as
-- `unresolved-legacy`, but cannot cross into an approval-bearing lifecycle
-- state. New plans are written as `verified-principal` by the repository and
-- approval records exactly one distinct checker in the same status CAS.
ALTER TABLE patch_waves
    ADD COLUMN maker_binding_state TEXT NOT NULL DEFAULT 'unresolved-legacy',
    ADD COLUMN maker_principal_id UUID,
    ADD COLUMN approved_by_principal_id UUID;

ALTER TABLE patch_waves
    ADD CONSTRAINT patch_waves_maker_binding_state_check
        CHECK (maker_binding_state IN ('unresolved-legacy', 'verified-principal')),
    ADD CONSTRAINT patch_waves_maker_provenance_complete
        CHECK (
            (
                maker_binding_state = 'unresolved-legacy'
                AND maker_principal_id IS NULL
                AND approved_by_principal_id IS NULL
            )
            OR
            (
                maker_binding_state = 'verified-principal'
                AND maker_principal_id IS NOT NULL
                AND maker_principal_id <> '00000000-0000-0000-0000-000000000000'::UUID
                AND (
                    (
                        status IN ('Draft', 'Validated')
                        AND approved_by_principal_id IS NULL
                    )
                    OR
                    (
                        status IN ('Approved', 'Scheduled', 'InProgress', 'Completed', 'Failed')
                        AND approved_by_principal_id IS NOT NULL
                        AND approved_by_principal_id <>
                            '00000000-0000-0000-0000-000000000000'::UUID
                        AND approved_by_principal_id <> maker_principal_id
                    )
                )
            )
        );

COMMENT ON COLUMN patch_waves.maker_binding_state IS
    'verified-principal for newly planned waves; unresolved-legacy rows cannot be approved';
COMMENT ON COLUMN patch_waves.maker_principal_id IS
    'Immutable opaque principal that planned this patch wave; NULL only for legacy rows';
COMMENT ON COLUMN patch_waves.approved_by_principal_id IS
    'Immutable distinct checker captured atomically with Validated-to-Approved';

CREATE OR REPLACE FUNCTION enforce_patch_wave_maker_checker()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    entering_approval_lifecycle BOOLEAN;
BEGIN
    IF NEW.maker_binding_state IS DISTINCT FROM OLD.maker_binding_state
       OR NEW.maker_principal_id IS DISTINCT FROM OLD.maker_principal_id
    THEN
        RAISE EXCEPTION 'patch-wave maker provenance is immutable'
            USING ERRCODE = '23514';
    END IF;

    entering_approval_lifecycle :=
        OLD.status IN ('Draft', 'Validated')
        AND NEW.status IN ('Approved', 'Scheduled', 'InProgress', 'Completed');

    IF OLD.maker_binding_state = 'unresolved-legacy'
       AND (
            entering_approval_lifecycle
            OR OLD.status IN ('Approved', 'Scheduled', 'InProgress')
       )
    THEN
        RAISE EXCEPTION 'legacy patch wave lacks verified maker/checker provenance'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.maker_binding_state = 'verified-principal'
       AND entering_approval_lifecycle
       AND (
            OLD.status <> 'Validated'
            OR NEW.status <> 'Approved'
            OR OLD.approved_by_principal_id IS NOT NULL
            OR NEW.approved_by_principal_id IS NULL
            OR NEW.approved_by_principal_id = OLD.maker_principal_id
       )
    THEN
        RAISE EXCEPTION 'patch-wave approval requires a distinct checker'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.approved_by_principal_id IS DISTINCT FROM OLD.approved_by_principal_id
       AND NOT (
            OLD.maker_binding_state = 'verified-principal'
            AND OLD.status = 'Validated'
            AND NEW.status = 'Approved'
            AND OLD.approved_by_principal_id IS NULL
            AND NEW.approved_by_principal_id IS NOT NULL
            AND NEW.approved_by_principal_id <> OLD.maker_principal_id
       )
    THEN
        RAISE EXCEPTION 'patch-wave checker provenance is immutable'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_patch_wave_maker_checker
BEFORE UPDATE OF
    status,
    maker_binding_state,
    maker_principal_id,
    approved_by_principal_id
ON patch_waves
FOR EACH ROW
EXECUTE FUNCTION enforce_patch_wave_maker_checker();
