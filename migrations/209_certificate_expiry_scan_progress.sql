-- 209_certificate_expiry_scan_progress.sql
--
-- Bound the certificate-expiry scheduler with a durable composite keyset.
-- Each cycle scans one immutable epoch using the indexed
-- (expiry_scan_epoch, valid_to, id) order. A processed certificate moves to the
-- next epoch in the same transaction as its queue effect and cursor. Inserts
-- and identity/deadline changes during a cycle are also routed to that next epoch, so a
-- mutable valid_to cannot move behind the cursor, re-enter later pages, or keep
-- the active cycle alive. The fixed high-water tuple is defense in depth.
--
-- Rolling-version fence:
--   * the ACCESS EXCLUSIVE locks drain old certificate schedulers/writers;
--   * the physical v2 job kind is unknown to an old binary;
--   * legacy job-kind writes are rejected; and
--   * schedule advancement and epoch movement require the transaction-local
--     v2 marker.
-- Required rollout is drain -> migration -> v2 binary. This is deliberately
-- offline DDL; deployers must retry lock contention in a reviewed window rather
-- than removing the finite lock timeout.

SET LOCAL lock_timeout = '30s';
LOCK TABLE schedules, certificates IN ACCESS EXCLUSIVE MODE;

INSERT INTO scheduler_protocol_versions (component, protocol_version)
VALUES ('certificate_expiry_scan', 2);

UPDATE schedules
   SET job_kind = 'certificate_expiry_scan_v2',
       updated_at = clock_timestamp()
 WHERE job_kind = 'certificate_expiry_scan';

ALTER TABLE schedules
    ADD CONSTRAINT schedules_certificate_expiry_scan_protocol_v2
    CHECK (job_kind <> 'certificate_expiry_scan');

-- One global epoch is safe only with one physical certificate scanner. The
-- seeded job is already singleton; fail migration rather than silently choosing
-- among an operator-created duplicate.
CREATE UNIQUE INDEX uq_schedules_certificate_expiry_scan_v2
    ON schedules (job_kind)
    WHERE job_kind = 'certificate_expiry_scan_v2' AND enabled;

CREATE TABLE certificate_expiry_scan_state (
    singleton    BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    active_epoch BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO certificate_expiry_scan_state (singleton, active_epoch)
VALUES (TRUE, FALSE);

-- The constant default is metadata-only for legacy rows. All rows begin in the
-- first epoch; the trigger below owns future insert/update assignment.
ALTER TABLE certificates
    ADD COLUMN expiry_scan_epoch BOOLEAN NOT NULL DEFAULT FALSE;

-- Rust/JSON scheduling accepts canonical RFC3339 years. Preserve any historical
-- out-of-range PostgreSQL timestamp for operator reconciliation, but keep it out
-- of the active index and reject new values that the worker cannot decode.
ALTER TABLE certificates
    ADD CONSTRAINT certificates_expiry_scan_timestamp_bounds
    CHECK (
        valid_to >= TIMESTAMPTZ '0001-01-01 00:00:00+00'
        AND valid_to < TIMESTAMPTZ '10000-01-01 00:00:00+00'
    ) NOT VALID;

CREATE INDEX idx_certificates_expiry_scheduler_page
    ON certificates (expiry_scan_epoch, valid_to ASC, id ASC)
    WHERE octet_length(site) BETWEEN 1 AND 32
      AND valid_to >= TIMESTAMPTZ '0001-01-01 00:00:00+00'
      AND valid_to < TIMESTAMPTZ '10000-01-01 00:00:00+00';

-- Progress belongs to the singleton schedule definition. A NULL cursor means
-- the first page. Every continuation commits the last claimed (valid_to, id),
-- while the epoch equality makes the mutable business deadline stable for the
-- active population.
CREATE TABLE certificate_expiry_scan_progress (
    schedule_id         TEXT PRIMARY KEY
        REFERENCES schedules (id) ON DELETE CASCADE,
    global_slot         BOOLEAN NOT NULL DEFAULT TRUE UNIQUE CHECK (global_slot),
    job_kind            TEXT NOT NULL DEFAULT 'certificate_expiry_scan_v2'
        CHECK (job_kind = 'certificate_expiry_scan_v2'),
    protocol_version    SMALLINT NOT NULL DEFAULT 2
        CHECK (protocol_version = 2),
    scan_epoch          BOOLEAN NOT NULL,
    cursor_valid_to     TIMESTAMPTZ,
    cursor_id           UUID,
    high_water_valid_to TIMESTAMPTZ NOT NULL,
    high_water_id       UUID NOT NULL,
    cycle_cutoff        TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((cursor_valid_to IS NULL) = (cursor_id IS NULL)),
    CHECK (
        cursor_valid_to IS NULL
        OR ROW(cursor_valid_to, cursor_id)
           <= ROW(high_water_valid_to, high_water_id)
    )
);

COMMENT ON TABLE certificate_expiry_scan_progress IS
'Atomic epoch/cursor/high-water state for bounded (valid_to,id) certificate expiry pages.';

CREATE FUNCTION protect_certificate_expiry_scan_progress()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('ryuki.scheduler_certificate_expiry_protocol', true)
           IS DISTINCT FROM '2' THEN
        RAISE EXCEPTION 'certificate expiry scan progress is scheduler-owned'
            USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER certificate_expiry_scan_progress_delete_guard
BEFORE DELETE ON certificate_expiry_scan_progress
FOR EACH ROW
EXECUTE FUNCTION protect_certificate_expiry_scan_progress();

CREATE FUNCTION protect_active_certificate_expiry_schedule()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM certificate_expiry_scan_progress
         WHERE schedule_id = OLD.id
    ) THEN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION
                'certificate expiry schedule cannot be deleted while a scan cycle is active'
                USING ERRCODE = '55000';
        ELSIF NEW.enabled IS DISTINCT FROM OLD.enabled
           OR NEW.job_kind IS DISTINCT FROM OLD.job_kind THEN
            RAISE EXCEPTION
                'certificate expiry schedule cannot change while a scan cycle is active'
                USING ERRCODE = '55000';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER schedules_active_certificate_expiry_scan_guard
BEFORE DELETE OR UPDATE OF enabled, job_kind ON schedules
FOR EACH ROW
EXECUTE FUNCTION protect_active_certificate_expiry_schedule();

CREATE FUNCTION enforce_certificate_expiry_schedule_protocol_v2()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('ryuki.scheduler_certificate_expiry_protocol', true)
           IS DISTINCT FROM '2' THEN
        RAISE EXCEPTION
            'certificate-expiry scheduler protocol v2 is required to advance schedule %',
            OLD.id
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER schedules_certificate_expiry_protocol_v2_guard
BEFORE UPDATE OF last_run_at, next_run_at ON schedules
FOR EACH ROW
WHEN (OLD.job_kind = 'certificate_expiry_scan_v2'
      OR NEW.job_kind = 'certificate_expiry_scan_v2')
EXECUTE FUNCTION enforce_certificate_expiry_schedule_protocol_v2();

-- Route inserts and deadline mutations away from an in-flight epoch. Both
-- states visible around the atomic finish transition map to the same target:
-- old active + progress -> next, or new active + no progress -> active. A
-- pre-cycle table SHARE lock drains writers before the first high-water read.
CREATE FUNCTION enforce_certificate_expiry_scan_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_epoch BOOLEAN;
    scan_active   BOOLEAN;
    target_epoch BOOLEAN;
BEGIN
    SELECT state.active_epoch,
           EXISTS (SELECT 1 FROM certificate_expiry_scan_progress)
      INTO current_epoch, scan_active
      FROM certificate_expiry_scan_state AS state
     WHERE state.singleton;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'certificate expiry scan state is missing'
            USING ERRCODE = '55000';
    END IF;

    target_epoch := CASE
        WHEN scan_active THEN NOT current_epoch
        ELSE current_epoch
    END;

    IF TG_OP = 'INSERT' THEN
        NEW.expiry_scan_epoch := target_epoch;
    ELSIF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.valid_to IS DISTINCT FROM OLD.valid_to THEN
        NEW.expiry_scan_epoch := target_epoch;
    ELSIF NEW.expiry_scan_epoch IS DISTINCT FROM OLD.expiry_scan_epoch THEN
        IF current_setting('ryuki.scheduler_certificate_expiry_protocol', true)
               IS DISTINCT FROM '2'
           OR NEW.expiry_scan_epoch IS DISTINCT FROM target_epoch THEN
            RAISE EXCEPTION 'certificate expiry scan epoch is database-owned'
                USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificates_expiry_scan_epoch_guard
BEFORE INSERT OR UPDATE OF id, valid_to, expiry_scan_epoch ON certificates
FOR EACH ROW
EXECUTE FUNCTION enforce_certificate_expiry_scan_epoch();
