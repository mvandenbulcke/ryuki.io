-- Firmware exception authority is a two-principal, time-bounded lifecycle.
--
-- Existing rows cannot prove who requested the exception separately from the
-- recorded approver. They are therefore quarantined as Legacy and never grant
-- exception authority. Operators must submit a new request for an explicit,
-- verified approver to accept.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM firmware_exceptions
        WHERE expiry_date !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
           OR to_char(to_date(expiry_date, 'YYYY-MM-DD'), 'YYYY-MM-DD') <> expiry_date
    ) THEN
        RAISE EXCEPTION
            'firmware_exceptions contains a non-canonical expiry_date; refusing lifecycle migration';
    END IF;
END;
$$;

ALTER TABLE firmware_exceptions
    ADD COLUMN requested_by TEXT,
    ADD COLUMN status TEXT,
    ADD COLUMN version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN approved_at TIMESTAMPTZ,
    ADD COLUMN expired_at TIMESTAMPTZ,
    ADD COLUMN revoked_at TIMESTAMPTZ;

UPDATE firmware_exceptions
SET requested_by = 'legacy-unattributed',
    status = 'Legacy';

ALTER TABLE firmware_exceptions
    ALTER COLUMN requested_by SET NOT NULL,
    ALTER COLUMN status SET NOT NULL,
    ALTER COLUMN approved_by DROP NOT NULL,
    ALTER COLUMN expiry_date TYPE DATE USING expiry_date::date;

ALTER TABLE firmware_exceptions
    ADD CONSTRAINT firmware_exceptions_requester_nonblank
        CHECK (NULLIF(BTRIM(requested_by), '') IS NOT NULL AND requested_by = BTRIM(requested_by)),
    ADD CONSTRAINT firmware_exceptions_approver_nonblank
        CHECK (
            approved_by IS NULL
            OR (NULLIF(BTRIM(approved_by), '') IS NOT NULL AND approved_by = BTRIM(approved_by))
        ),
    ADD CONSTRAINT firmware_exceptions_status_valid
        CHECK (status IN ('Pending', 'Approved', 'Expired', 'Revoked', 'Legacy')),
    ADD CONSTRAINT firmware_exceptions_version_positive
        CHECK (version > 0),
    ADD CONSTRAINT firmware_exceptions_lifecycle_shape
        CHECK (
            (status = 'Pending'
                AND approved_by IS NULL
                AND approved_at IS NULL
                AND expired_at IS NULL
                AND revoked_at IS NULL)
            OR (status = 'Approved'
                AND approved_by IS NOT NULL
                AND BTRIM(approved_by) <> BTRIM(requested_by)
                AND approved_at IS NOT NULL
                AND expired_at IS NULL
                AND revoked_at IS NULL)
            OR (status = 'Expired'
                AND expired_at IS NOT NULL
                AND revoked_at IS NULL
                AND (
                    (approved_by IS NULL AND approved_at IS NULL)
                    OR (
                        approved_by IS NOT NULL
                        AND approved_at IS NOT NULL
                        AND BTRIM(approved_by) <> BTRIM(requested_by)
                    )
                ))
            OR (status = 'Revoked'
                AND approved_by IS NOT NULL
                AND approved_at IS NOT NULL
                AND expired_at IS NULL
                AND revoked_at IS NOT NULL)
            OR (status = 'Legacy'
                AND approved_at IS NULL
                AND expired_at IS NULL
                AND revoked_at IS NULL)
        );

-- Only one unresolved decision may exist for a device. Expired and revoked
-- history remains available without blocking a fresh request.
CREATE UNIQUE INDEX idx_firmware_exceptions_one_open_per_device
    ON firmware_exceptions (device_id)
    WHERE status IN ('Pending', 'Approved');

CREATE INDEX idx_firmware_exceptions_effective_authority
    ON firmware_exceptions (device_id, status, expiry_date, id);

CREATE OR REPLACE FUNCTION enforce_firmware_exception_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'Pending'
           OR NEW.version <> 1
           OR NEW.approved_by IS NOT NULL
           OR NEW.approved_at IS NOT NULL
           OR NEW.expired_at IS NOT NULL
           OR NEW.revoked_at IS NOT NULL
           OR NEW.expiry_date < CURRENT_DATE
           OR NEW.expiry_date > CURRENT_DATE + 365 THEN
            RAISE EXCEPTION
                'new firmware exceptions must enter Pending with a database-date expiry no more than 365 days away'
                USING ERRCODE = '23514';
        END IF;
        NEW.created_at := statement_timestamp();
        RETURN NEW;
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.device_id IS DISTINCT FROM OLD.device_id
       OR NEW.reason IS DISTINCT FROM OLD.reason
       OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
       OR NEW.expiry_date IS DISTINCT FROM OLD.expiry_date
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION
            'firmware exception authority fields are immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION
            'firmware exception transition must advance version exactly once'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.status = 'Pending' AND NEW.status = 'Approved' THEN
        IF OLD.expiry_date < CURRENT_DATE
           OR NEW.approved_by IS NULL
           OR BTRIM(NEW.approved_by) = BTRIM(OLD.requested_by)
           OR NEW.expired_at IS NOT NULL
           OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION
                'firmware exception approval requires an unexpired request and distinct checker'
                USING ERRCODE = '23514';
        END IF;
        NEW.approved_at := statement_timestamp();
        NEW.expired_at := NULL;
        NEW.revoked_at := NULL;
        RETURN NEW;
    END IF;

    IF OLD.status = 'Pending' AND NEW.status = 'Expired' THEN
        IF OLD.expiry_date >= CURRENT_DATE
           OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION
                'firmware exception may expire only after the database-date boundary'
                USING ERRCODE = '23514';
        END IF;
        NEW.approved_by := NULL;
        NEW.approved_at := NULL;
        NEW.expired_at := statement_timestamp();
        NEW.revoked_at := NULL;
        RETURN NEW;
    END IF;

    IF OLD.status = 'Approved' AND NEW.status = 'Expired' THEN
        IF OLD.expiry_date >= CURRENT_DATE
           OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
           OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
           OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION
                'firmware exception expiry must preserve checker evidence after the database-date boundary'
                USING ERRCODE = '23514';
        END IF;
        NEW.approved_by := OLD.approved_by;
        NEW.approved_at := OLD.approved_at;
        NEW.expired_at := statement_timestamp();
        NEW.revoked_at := NULL;
        RETURN NEW;
    END IF;

    IF OLD.status = 'Approved' AND NEW.status = 'Revoked' THEN
        IF NEW.approved_by IS DISTINCT FROM OLD.approved_by
           OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
           OR NEW.expired_at IS NOT NULL THEN
            RAISE EXCEPTION
                'firmware exception revocation must preserve checker evidence'
                USING ERRCODE = '23514';
        END IF;
        NEW.approved_by := OLD.approved_by;
        NEW.approved_at := OLD.approved_at;
        NEW.expired_at := NULL;
        NEW.revoked_at := statement_timestamp();
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'invalid firmware exception transition from % to %', OLD.status, NEW.status
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER firmware_exception_transition_guard
BEFORE INSERT OR UPDATE ON firmware_exceptions
FOR EACH ROW
EXECUTE FUNCTION enforce_firmware_exception_transition();

-- Accepted and rejected risk evidence is append-only for ordinary writers.
-- The schema owner retains one narrow maintenance function for disposable
-- fixtures and explicitly approved retention work; deleting a parent firmware
-- record cannot silently cascade through this guard.
CREATE OR REPLACE FUNCTION reject_firmware_exception_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    table_owner OID;
BEGIN
    SELECT relowner
    INTO table_owner
    FROM pg_class
    WHERE oid = 'public.firmware_exceptions'::regclass;

    IF TG_OP = 'DELETE'
       AND current_setting('ryuki.firmware_ledger_maintenance', TRUE) =
           'owner-device-purge-v1'
       AND CURRENT_USER::regrole::oid = table_owner THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'firmware exception history is append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER firmware_exception_no_delete
BEFORE DELETE ON firmware_exceptions
FOR EACH ROW
EXECUTE FUNCTION reject_firmware_exception_removal();

CREATE TRIGGER firmware_exception_no_truncate
BEFORE TRUNCATE ON firmware_exceptions
FOR EACH STATEMENT
EXECUTE FUNCTION reject_firmware_exception_removal();

CREATE OR REPLACE FUNCTION purge_firmware_exceptions_for_maintenance(
    target_device_id TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    removed BIGINT;
BEGIN
    PERFORM set_config(
        'ryuki.firmware_ledger_maintenance',
        'owner-device-purge-v1',
        TRUE
    );
    DELETE FROM public.firmware_exceptions
    WHERE device_id = target_device_id;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$;

REVOKE ALL ON FUNCTION purge_firmware_exceptions_for_maintenance(TEXT)
    FROM PUBLIC;

COMMENT ON TABLE firmware_exceptions IS
    'Two-principal firmware risk-acceptance requests; database date and lifecycle status determine authority.';
COMMENT ON COLUMN firmware_exceptions.requested_by IS
    'Server-derived maker identity. Never accepted from the request payload.';
COMMENT ON COLUMN firmware_exceptions.approved_by IS
    'Server-derived approval-capable checker identity; distinct from requested_by.';
COMMENT ON COLUMN firmware_exceptions.expiry_date IS
    'Database-computed inclusive final authority date; ineffective when expiry_date < CURRENT_DATE.';
COMMENT ON COLUMN firmware_exceptions.version IS
    'Monotonic lifecycle CAS version; every state transition advances exactly once.';
