-- 195_validate_request_resource_version.sql
--
-- Validate the online checks installed by migration 194 after its short
-- ACCESS EXCLUSIVE catalog transaction has committed. VALIDATE CONSTRAINT
-- uses a lock compatible with ordinary SELECT/INSERT/UPDATE/DELETE traffic.
-- Every object is proven structurally before it is validated or dropped;
-- PostgreSQL 18 can store both NOT ENFORCED checks and named native NOT NULL
-- constraints in pg_constraint, so a matching name is not sufficient proof.

DO $$
DECLARE
    constraint_type "char";
    constraint_enforced BOOLEAN;
    constraint_validated BOOLEAN;
    normalized_expression TEXT;
BEGIN
    SELECT constraint_catalog.contype,
           constraint_catalog.conenforced,
           constraint_catalog.convalidated,
           LOWER(REGEXP_REPLACE(
               pg_catalog.pg_get_expr(
                   constraint_catalog.conbin,
                   constraint_catalog.conrelid
               ),
               '[[:space:]()]',
               '',
               'g'
           ))
    INTO constraint_type,
         constraint_enforced,
         constraint_validated,
         normalized_expression
    FROM pg_catalog.pg_constraint AS constraint_catalog
    WHERE constraint_catalog.conname = 'requests_resource_version_positive'
      AND constraint_catalog.conrelid = 'public.requests'::regclass
      AND constraint_catalog.connamespace = 'public'::regnamespace;

    IF NOT FOUND
       OR constraint_type <> 'c'
       OR constraint_enforced IS NOT TRUE
       OR normalized_expression <> 'resource_version>0' THEN
        RAISE EXCEPTION
            'requests_resource_version_positive has an incompatible definition'
            USING ERRCODE = '55000';
    END IF;

    IF NOT constraint_validated THEN
        ALTER TABLE requests
            VALIDATE CONSTRAINT requests_resource_version_positive;
    END IF;
END $$;

DO $$
DECLARE
    version_attnum SMALLINT;
    version_is_not_null BOOLEAN;
    temporary_constraint_exists BOOLEAN := FALSE;
    constraint_type "char";
    constraint_enforced BOOLEAN;
    constraint_validated BOOLEAN;
    normalized_expression TEXT;
    native_constraint_name TEXT;
    native_constraint_count BIGINT;
    native_constraint_enforced BOOLEAN;
    native_constraint_validated BOOLEAN;
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

    SELECT constraint_catalog.contype,
           constraint_catalog.conenforced,
           constraint_catalog.convalidated,
           LOWER(REGEXP_REPLACE(
               pg_catalog.pg_get_expr(
                   constraint_catalog.conbin,
                   constraint_catalog.conrelid
               ),
               '[[:space:]()]',
               '',
               'g'
           ))
    INTO constraint_type,
         constraint_enforced,
         constraint_validated,
         normalized_expression
    FROM pg_catalog.pg_constraint AS constraint_catalog
    WHERE constraint_catalog.conname =
              'requests_resource_version_not_null_check'
      AND constraint_catalog.conrelid = 'public.requests'::regclass
      AND constraint_catalog.connamespace = 'public'::regnamespace;

    temporary_constraint_exists := FOUND;
    IF temporary_constraint_exists THEN
        IF constraint_type <> 'c'
           OR constraint_enforced IS NOT TRUE
           OR normalized_expression <> 'resource_versionisnotnull' THEN
            RAISE EXCEPTION
                'requests_resource_version_not_null_check has an incompatible definition'
                USING ERRCODE = '55000';
        END IF;

        IF NOT constraint_validated THEN
            ALTER TABLE requests
                VALIDATE CONSTRAINT requests_resource_version_not_null_check;
        END IF;
        ALTER TABLE requests
            ALTER COLUMN resource_version SET NOT NULL;
    ELSIF NOT version_is_not_null THEN
        RAISE EXCEPTION
            'requests.resource_version lacks a validated NOT NULL proof'
            USING ERRCODE = '55000';
    END IF;

    -- PostgreSQL 18 records native NOT NULL constraints in pg_constraint.
    -- Validate an interrupted NOT NULL NOT VALID installation by its exact
    -- constrained column, never by a caller-controlled or reused name.
    SELECT COUNT(*),
           MIN(constraint_catalog.conname::TEXT),
           BOOL_AND(constraint_catalog.conenforced),
           BOOL_AND(constraint_catalog.convalidated)
    INTO native_constraint_count,
         native_constraint_name,
         native_constraint_enforced,
         native_constraint_validated
    FROM pg_catalog.pg_constraint AS constraint_catalog
    WHERE constraint_catalog.contype = 'n'
      AND constraint_catalog.conrelid = 'public.requests'::regclass
      AND constraint_catalog.connamespace = 'public'::regnamespace
      AND constraint_catalog.conkey = ARRAY[version_attnum]::SMALLINT[];

    IF native_constraint_count <> 1
       OR native_constraint_enforced IS NOT TRUE THEN
        RAISE EXCEPTION
            'requests.resource_version has incompatible native NOT NULL metadata'
            USING ERRCODE = '55000';
    END IF;

    IF native_constraint_validated IS NOT TRUE THEN
        EXECUTE pg_catalog.format(
            'ALTER TABLE public.requests VALIDATE CONSTRAINT %I',
            native_constraint_name
        );
    END IF;

    SELECT attribute_catalog.attnotnull,
           COUNT(constraint_catalog.oid),
           BOOL_AND(
               constraint_catalog.conenforced
               AND constraint_catalog.convalidated
           )
    INTO version_is_not_null,
         native_constraint_count,
         native_constraint_validated
    FROM pg_catalog.pg_attribute AS attribute_catalog
    LEFT JOIN pg_catalog.pg_constraint AS constraint_catalog
      ON constraint_catalog.contype = 'n'
     AND constraint_catalog.conrelid = attribute_catalog.attrelid
     AND constraint_catalog.connamespace = 'public'::regnamespace
     AND constraint_catalog.conkey = ARRAY[attribute_catalog.attnum]::SMALLINT[]
    WHERE attribute_catalog.attrelid = 'public.requests'::regclass
      AND attribute_catalog.attname = 'resource_version'
      AND attribute_catalog.attnum > 0
      AND NOT attribute_catalog.attisdropped
    GROUP BY attribute_catalog.attnotnull;

    IF version_is_not_null IS NOT TRUE
       OR native_constraint_count <> 1
       OR native_constraint_validated IS NOT TRUE THEN
        RAISE EXCEPTION
            'requests.resource_version NOT NULL validation did not converge'
            USING ERRCODE = '55000';
    END IF;

    IF temporary_constraint_exists THEN
        ALTER TABLE requests
            DROP CONSTRAINT requests_resource_version_not_null_check;
    END IF;
END $$;
