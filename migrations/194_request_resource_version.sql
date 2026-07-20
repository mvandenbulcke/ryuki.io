-- 194_request_resource_version.sql
--
-- Give every request a database-owned, positive, monotonic security version.
-- The version is not a caller-managed optimistic-lock token: ordinary writers
-- may compare it in a WHERE clause, but may never assign it. A separate trigger
-- advances it exactly once whenever persisted request state (other than the
-- bookkeeping updated_at timestamp) changes. This keeps rolling replicas and
-- direct SQL writers on the same fail-closed version boundary.

-- A prior interrupted/manual installation may already have installed either
-- trigger.  Remove it before repairing nullable/non-positive legacy values;
-- the canonical triggers are recreated below in this same transaction.
DROP TRIGGER IF EXISTS trg_requests_resource_version_owned ON requests;
DROP TRIGGER IF EXISTS trg_requests_zz_resource_version ON requests;

-- A clean installation uses PostgreSQL's metadata-only constant-default path
-- and does not scan the table while its short ACCESS EXCLUSIVE lock is held.
-- The existing-column branch makes a resumed/partially-applied rollout
-- converge safely: IF NOT EXISTS alone would silently accept a nullable or
-- otherwise incompatible pre-existing column.
DO $$
DECLARE
    version_type REGTYPE;
    version_identity "char";
    version_generated "char";
    constraint_type "char";
    constraint_enforced BOOLEAN;
    normalized_expression TEXT;
BEGIN
    SELECT attribute_catalog.atttypid::regtype,
           attribute_catalog.attidentity,
           attribute_catalog.attgenerated
    INTO version_type, version_identity, version_generated
    FROM pg_catalog.pg_attribute AS attribute_catalog
    WHERE attribute_catalog.attrelid = 'public.requests'::regclass
      AND attribute_catalog.attname = 'resource_version'
      AND attribute_catalog.attnum > 0
      AND NOT attribute_catalog.attisdropped;

    IF NOT FOUND THEN
        ALTER TABLE requests
            ADD COLUMN resource_version BIGINT NOT NULL DEFAULT 1;
    ELSE
        IF version_type <> 'bigint'::regtype
           OR version_identity <> ''
           OR version_generated <> '' THEN
            RAISE EXCEPTION
                'requests.resource_version has an incompatible pre-existing definition'
                USING ERRCODE = '55000';
        END IF;

        -- Validate an existing same-named constraint structurally instead of
        -- trusting its name. A decoy CHECK (TRUE), or an incompatible partial
        -- installation, must never suppress the real positive boundary.
        SELECT constraint_catalog.contype,
               constraint_catalog.conenforced,
               LOWER(REGEXP_REPLACE(
                   pg_catalog.pg_get_expr(
                       constraint_catalog.conbin,
                       constraint_catalog.conrelid
                   ),
                   '[[:space:]()]',
                   '',
                   'g'
               ))
        INTO constraint_type, constraint_enforced, normalized_expression
        FROM pg_catalog.pg_constraint AS constraint_catalog
        WHERE constraint_catalog.conname =
                  'requests_resource_version_positive'
          AND constraint_catalog.conrelid = 'public.requests'::regclass
          AND constraint_catalog.connamespace = 'public'::regnamespace;

        IF FOUND
           AND (
                constraint_type <> 'c'
                OR constraint_enforced IS NOT TRUE
                OR normalized_expression <> 'resource_version>0'
           ) THEN
            RAISE EXCEPTION
                'requests_resource_version_positive has an incompatible definition'
                USING ERRCODE = '55000';
        END IF;

        -- Repair only invalid values from a partial pre-existing column.
        -- Positive versions are retained exactly.
        UPDATE requests
        SET resource_version = 1
        WHERE resource_version IS NULL OR resource_version <= 0;
    END IF;
END $$;

ALTER TABLE requests
    ALTER COLUMN resource_version SET DEFAULT 1;

DO $$
DECLARE
    constraint_type "char";
    constraint_enforced BOOLEAN;
    normalized_expression TEXT;
BEGIN
    SELECT constraint_catalog.contype,
           constraint_catalog.conenforced,
           LOWER(REGEXP_REPLACE(
               pg_catalog.pg_get_expr(
                   constraint_catalog.conbin,
                   constraint_catalog.conrelid
               ),
               '[[:space:]()]',
               '',
               'g'
           ))
    INTO constraint_type, constraint_enforced, normalized_expression
    FROM pg_catalog.pg_constraint AS constraint_catalog
    WHERE constraint_catalog.conname = 'requests_resource_version_positive'
      AND constraint_catalog.conrelid = 'public.requests'::regclass
      AND constraint_catalog.connamespace = 'public'::regnamespace;

    IF FOUND THEN
        IF constraint_type <> 'c'
           OR constraint_enforced IS NOT TRUE
           OR normalized_expression <> 'resource_version>0' THEN
            RAISE EXCEPTION
                'requests_resource_version_positive has an incompatible definition'
                USING ERRCODE = '55000';
        END IF;
    ELSE
        ALTER TABLE requests
            ADD CONSTRAINT requests_resource_version_positive
            CHECK (resource_version > 0) NOT VALID;
    END IF;
END $$;

-- A nullable partial column needs a separately validated proof before SET NOT
-- NULL can become a short catalog operation.  Migration 195 validates this
-- check with a lock compatible with normal row reads/writes, sets NOT NULL,
-- and removes the temporary proof constraint.
DO $$
DECLARE
    version_attnum SMALLINT;
    version_is_not_null BOOLEAN;
    constraint_type "char";
    constraint_enforced BOOLEAN;
    normalized_expression TEXT;
    native_constraint_count BIGINT;
    native_constraint_enforced BOOLEAN;
BEGIN
    SELECT attribute_catalog.attnum, attribute_catalog.attnotnull
    INTO version_attnum, version_is_not_null
    FROM pg_catalog.pg_attribute AS attribute_catalog
    WHERE attribute_catalog.attrelid = 'public.requests'::regclass
      AND attribute_catalog.attname = 'resource_version'
      AND attribute_catalog.attnum > 0
      AND NOT attribute_catalog.attisdropped;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'requests.resource_version is missing'
            USING ERRCODE = '55000';
    END IF;

    -- Inspect the temporary proof by structure even when the column already
    -- carries native NOT NULL metadata. PostgreSQL 18 stores named native
    -- NOT NULL constraints in pg_constraint too, so name-only acceptance can
    -- otherwise make migration 195 drop the wrong object.
    SELECT constraint_catalog.contype,
           constraint_catalog.conenforced,
           LOWER(REGEXP_REPLACE(
               pg_catalog.pg_get_expr(
                   constraint_catalog.conbin,
                   constraint_catalog.conrelid
               ),
               '[[:space:]()]',
               '',
               'g'
           ))
    INTO constraint_type, constraint_enforced, normalized_expression
    FROM pg_catalog.pg_constraint AS constraint_catalog
    WHERE constraint_catalog.conname =
              'requests_resource_version_not_null_check'
      AND constraint_catalog.conrelid = 'public.requests'::regclass
      AND constraint_catalog.connamespace = 'public'::regnamespace;

    IF FOUND
       AND (
            constraint_type <> 'c'
            OR constraint_enforced IS NOT TRUE
            OR normalized_expression <> 'resource_versionisnotnull'
       ) THEN
        RAISE EXCEPTION
            'requests_resource_version_not_null_check has an incompatible definition'
            USING ERRCODE = '55000';
    END IF;

    SELECT COUNT(*), BOOL_AND(constraint_catalog.conenforced)
    INTO native_constraint_count, native_constraint_enforced
    FROM pg_catalog.pg_constraint AS constraint_catalog
    WHERE constraint_catalog.contype = 'n'
      AND constraint_catalog.conrelid = 'public.requests'::regclass
      AND constraint_catalog.connamespace = 'public'::regnamespace
      AND constraint_catalog.conkey = ARRAY[version_attnum]::SMALLINT[];

    IF native_constraint_count > 1
       OR version_is_not_null <> (native_constraint_count = 1)
       OR (
            native_constraint_count = 1
            AND native_constraint_enforced IS NOT TRUE
       ) THEN
        RAISE EXCEPTION
            'requests.resource_version has incompatible native NOT NULL metadata'
            USING ERRCODE = '55000';
    END IF;

    IF NOT version_is_not_null
       AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_constraint AS constraint_catalog
            WHERE constraint_catalog.conname =
                      'requests_resource_version_not_null_check'
              AND constraint_catalog.conrelid = 'public.requests'::regclass
              AND constraint_catalog.connamespace = 'public'::regnamespace
       ) THEN
        ALTER TABLE requests
            ADD CONSTRAINT requests_resource_version_not_null_check
            CHECK (resource_version IS NOT NULL) NOT VALID;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION reject_caller_managed_request_resource_version()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- An UPDATE OF trigger fires when the column is named in SET, including a
    -- same-value assignment. Rejecting that form prevents both rollback and
    -- reuse while still allowing the later automatic trigger to assign NEW.
    RAISE EXCEPTION 'request resource_version is database-managed'
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS trg_requests_resource_version_owned ON requests;
CREATE TRIGGER trg_requests_resource_version_owned
BEFORE UPDATE OF resource_version ON requests
FOR EACH ROW
EXECUTE FUNCTION reject_caller_managed_request_resource_version();
ALTER TABLE requests
    ENABLE ALWAYS TRIGGER trg_requests_resource_version_owned;

CREATE OR REPLACE FUNCTION advance_request_resource_version()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    meaningful_change BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- DEFAULT is only a compatibility aid for old INSERT column lists. A
        -- writer that names an arbitrary positive value is normalized too.
        NEW.resource_version := 1;
        RETURN NEW;
    END IF;

    -- Compare the complete row dynamically so later additive request columns
    -- are versioned automatically. updated_at is bookkeeping and
    -- resource_version is owned by this trigger; neither makes an otherwise
    -- no-op UPDATE security-relevant.
    meaningful_change :=
        (to_jsonb(NEW) - 'updated_at' - 'resource_version')
        IS DISTINCT FROM
        (to_jsonb(OLD) - 'updated_at' - 'resource_version');

    IF NOT meaningful_change THEN
        NEW.resource_version := OLD.resource_version;
        RETURN NEW;
    END IF;

    IF OLD.resource_version = 9223372036854775807 THEN
        RAISE EXCEPTION 'request resource_version exhausted'
            USING ERRCODE = '22003';
    END IF;

    NEW.resource_version := OLD.resource_version + 1;
    RETURN NEW;
END;
$$;

-- PostgreSQL runs same-kind triggers in name order. The zz suffix makes this
-- trigger observe changes made by the existing request lifecycle trigger before
-- calculating the single final version increment.
DROP TRIGGER IF EXISTS trg_requests_zz_resource_version ON requests;
CREATE TRIGGER trg_requests_zz_resource_version
BEFORE INSERT OR UPDATE ON requests
FOR EACH ROW
EXECUTE FUNCTION advance_request_resource_version();
ALTER TABLE requests
    ENABLE ALWAYS TRIGGER trg_requests_zz_resource_version;

-- A canonical resource id may not be deleted and reinserted with version 1 by
-- the production runtime.  Owner-backed disposable databases retain their
-- fixture cleanup path; production startup independently proves the runtime is
-- not the table owner.  The force setting is shared with migration 174 so DB
-- tests can exercise the strict branch while connected as the owner.
CREATE OR REPLACE FUNCTION reject_runtime_request_resource_deletion()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    request_table_owner OID;
    enforce_runtime_contract BOOLEAN;
BEGIN
    SELECT relation_catalog.relowner
    INTO request_table_owner
    FROM pg_catalog.pg_class AS relation_catalog
    WHERE relation_catalog.oid = 'public.requests'::regclass;

    enforce_runtime_contract := request_table_owner IS NULL
        OR CURRENT_USER::regrole::oid <> request_table_owner
        OR COALESCE(
            current_setting('ryuki.force_request_runtime_contract', TRUE) =
                'runtime-v1',
            FALSE
        );

    IF enforce_runtime_contract THEN
        RAISE EXCEPTION
            'request resources cannot be deleted or truncated by the runtime'
            USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_requests_resource_version_no_delete ON requests;
CREATE TRIGGER trg_requests_resource_version_no_delete
BEFORE DELETE ON requests
FOR EACH ROW
EXECUTE FUNCTION reject_runtime_request_resource_deletion();
ALTER TABLE requests
    ENABLE ALWAYS TRIGGER trg_requests_resource_version_no_delete;

DROP TRIGGER IF EXISTS trg_requests_resource_version_no_truncate ON requests;
CREATE TRIGGER trg_requests_resource_version_no_truncate
BEFORE TRUNCATE ON requests
FOR EACH STATEMENT
EXECUTE FUNCTION reject_runtime_request_resource_deletion();
ALTER TABLE requests
    ENABLE ALWAYS TRIGGER trg_requests_resource_version_no_truncate;
