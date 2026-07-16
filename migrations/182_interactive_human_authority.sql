-- Provider-neutral interactive-human authority assignments.
--
-- This is an intentionally session-invalidating and mixed-reader-fencing
-- cutover. Pre-182 interactive sessions encode an empty site/environment list
-- as both "unknown" and "global"; those meanings cannot be recovered safely.
-- Existing identity keys are therefore quarantined as explicit Unknown (or
-- preserved as Revoked), never inferred to be Global. A configured local
-- bootstrap or a governed provider assignment must explicitly activate them.
--
-- SECURITY COMPATIBILITY BREAK: all pre-182 API replicas must be stopped
-- before this migration is applied and may not be restarted afterward. The
-- repository Kubernetes deployment uses Recreate for this reason. Although
-- the schema fences old persisted-session readers and writers, a pre-182
-- direct Entra bearer path does not consult PostgreSQL and cannot be fenced by
-- any database trigger. Rollback restores the database and the pre-182 binary
-- together only after stopping every reader and invalidating every interactive
-- credential generation. Restoring a pre-182 schema/data snapshot by itself is
-- forbidden because it can resurrect ambiguous pre-cutover sessions.

LOCK TABLE identity_authorities IN ACCESS EXCLUSIVE MODE;
LOCK TABLE sessions IN ACCESS EXCLUSIVE MODE;
LOCK TABLE api_tokens IN ACCESS EXCLUSIVE MODE;

DELETE FROM sessions;

-- No pre-182 token records the human authority that issued it. Preserve the
-- row as audit evidence, but clear every latent privilege and make it
-- permanently unusable; owner_principal is caller-supplied metadata and must
-- never be guessed into an authority tuple.
UPDATE api_tokens
SET token_valid = FALSE,
    revoked_at = COALESCE(revoked_at, NOW()),
    roles = ARRAY[]::TEXT[],
    site_scope = NULL,
    environment_scope = NULL;

CREATE FUNCTION human_authority_values_are_canonical(items TEXT[], value_kind TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    value TEXT;
    previous TEXT := NULL;
BEGIN
    IF cardinality(items) > 64 OR value_kind NOT IN ('role', 'scope') THEN
        RETURN FALSE;
    END IF;
    FOREACH value IN ARRAY items LOOP
        IF value IS NULL
            OR value = ''
            OR value <> btrim(value)
            OR length(value) > 256
            OR (previous IS NOT NULL AND previous COLLATE "C" >= value COLLATE "C")
            OR (value_kind = 'role' AND value !~ '^[A-Za-z0-9]+$')
            OR (value_kind = 'scope' AND value !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$')
        THEN
            RETURN FALSE;
        END IF;
        previous := value;
    END LOOP;
    RETURN TRUE;
END;
$$;

CREATE TABLE human_authority_assignments (
    provider TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    assignment_version BIGINT NOT NULL DEFAULT 1
        CHECK (assignment_version > 0),
    assignment_status TEXT NOT NULL
        CHECK (assignment_status IN ('unknown', 'active', 'revoked')),
    role_allowlist TEXT[] NOT NULL DEFAULT '{}',
    site_authority_mode TEXT NOT NULL
        CHECK (site_authority_mode IN ('unknown', 'global', 'scoped', 'revoked')),
    site_scope TEXT[] NOT NULL DEFAULT '{}',
    environment_authority_mode TEXT NOT NULL
        CHECK (environment_authority_mode IN ('unknown', 'global', 'scoped', 'revoked')),
    environment_scope TEXT[] NOT NULL DEFAULT '{}',
    source_kind TEXT NOT NULL
        CHECK (source_kind IN ('migration-quarantine', 'local-config', 'governed', 'provider-lifecycle')),
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, issuer, subject),
    UNIQUE (provider, issuer, subject, assignment_version),
    CHECK (length(provider) BETWEEN 1 AND 64),
    CHECK (provider ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'),
    CHECK (length(issuer) BETWEEN 1 AND 2048),
    CHECK (length(subject) BETWEEN 1 AND 512),
    CHECK (length(updated_by) BETWEEN 1 AND 512),
    CHECK (cardinality(role_allowlist) <= 64),
    CHECK (cardinality(site_scope) <= 64),
    CHECK (cardinality(environment_scope) <= 64),
    CHECK (array_position(role_allowlist, NULL) IS NULL),
    CHECK (array_position(site_scope, NULL) IS NULL),
    CHECK (array_position(environment_scope, NULL) IS NULL),
    CHECK (array_position(role_allowlist, '') IS NULL),
    CHECK (array_position(site_scope, '') IS NULL),
    CHECK (array_position(environment_scope, '') IS NULL),
    CHECK (human_authority_values_are_canonical(role_allowlist, 'role')),
    CHECK (human_authority_values_are_canonical(site_scope, 'scope')),
    CHECK (human_authority_values_are_canonical(environment_scope, 'scope')),
    CHECK (
        (assignment_status = 'unknown'
            AND site_authority_mode = 'unknown'
            AND environment_authority_mode = 'unknown'
            AND cardinality(role_allowlist) = 0
            AND cardinality(site_scope) = 0
            AND cardinality(environment_scope) = 0)
        OR
        (assignment_status = 'active'
            AND cardinality(role_allowlist) BETWEEN 1 AND 64
            AND site_authority_mode IN ('global', 'scoped')
            AND environment_authority_mode IN ('global', 'scoped')
            AND ((site_authority_mode = 'global' AND cardinality(site_scope) = 0)
                OR (site_authority_mode = 'scoped' AND cardinality(site_scope) BETWEEN 1 AND 64))
            AND ((environment_authority_mode = 'global' AND cardinality(environment_scope) = 0)
                OR (environment_authority_mode = 'scoped' AND cardinality(environment_scope) BETWEEN 1 AND 64)))
        OR
        (assignment_status = 'revoked'
            AND site_authority_mode = 'revoked'
            AND environment_authority_mode = 'revoked'
            AND cardinality(role_allowlist) = 0
            AND cardinality(site_scope) = 0
            AND cardinality(environment_scope) = 0)
    )
);

INSERT INTO human_authority_assignments (
    provider,
    issuer,
    subject,
    assignment_version,
    assignment_status,
    role_allowlist,
    site_authority_mode,
    site_scope,
    environment_authority_mode,
    environment_scope,
    source_kind,
    updated_by
)
SELECT
    provider,
    issuer,
    subject,
    1,
    CASE WHEN authority_status = 'revoked' THEN 'revoked' ELSE 'unknown' END,
    ARRAY[]::TEXT[],
    CASE WHEN authority_status = 'revoked' THEN 'revoked' ELSE 'unknown' END,
    ARRAY[]::TEXT[],
    CASE WHEN authority_status = 'revoked' THEN 'revoked' ELSE 'unknown' END,
    ARRAY[]::TEXT[],
    'migration-quarantine',
    'migration-182'
FROM identity_authorities;

-- `active-scoped-v2` is a deliberate binary-generation fence. Pre-182 readers
-- require the literal `active` and therefore cannot accept sessions minted by
-- this schema. Pre-182 writers attempt to write `active`, which the new check
-- rejects. New readers and every 165-era writer/reconciler use only the v2
-- literal after this cutover.
ALTER TABLE identity_authorities
    DROP CONSTRAINT identity_authorities_authority_status_check;

UPDATE identity_authorities
SET authority_status = 'active-scoped-v2',
    authority_epoch = authority_epoch + 1,
    updated_at = NOW()
WHERE authority_status = 'active';

ALTER TABLE identity_authorities
    ALTER COLUMN authority_status DROP DEFAULT,
    ADD CONSTRAINT identity_authorities_authority_status_check
    CHECK (authority_status IN ('active-scoped-v2', 'revoked'));

ALTER TABLE identity_authorities
    ADD CONSTRAINT identity_authorities_exact_epoch_key
    UNIQUE (provider, issuer, subject, authority_epoch);

ALTER TABLE sessions
    DROP CONSTRAINT sessions_identity_authority_fk,
    ADD COLUMN human_authority_version BIGINT NOT NULL
        CHECK (human_authority_version > 0),
    ADD COLUMN site_authority_mode TEXT NOT NULL,
    ADD COLUMN site_scope TEXT[] NOT NULL,
    ADD COLUMN environment_authority_mode TEXT NOT NULL,
    ADD COLUMN environment_scope TEXT[] NOT NULL,
    ADD CONSTRAINT sessions_roles_canonical_check CHECK (
        human_authority_values_are_canonical(roles, 'role')
    ),
    ADD CONSTRAINT sessions_site_authority_shape_check CHECK (
        (site_authority_mode = 'global' AND cardinality(site_scope) = 0)
        OR (site_authority_mode = 'scoped' AND cardinality(site_scope) BETWEEN 1 AND 64)
    ),
    ADD CONSTRAINT sessions_environment_authority_shape_check CHECK (
        (environment_authority_mode = 'global' AND cardinality(environment_scope) = 0)
        OR (environment_authority_mode = 'scoped' AND cardinality(environment_scope) BETWEEN 1 AND 64)
    ),
    ADD CONSTRAINT sessions_site_scope_members_check CHECK (
        array_position(site_scope, NULL) IS NULL
        AND array_position(site_scope, '') IS NULL
        AND human_authority_values_are_canonical(site_scope, 'scope')
    ),
    ADD CONSTRAINT sessions_environment_scope_members_check CHECK (
        array_position(environment_scope, NULL) IS NULL
        AND array_position(environment_scope, '') IS NULL
        AND human_authority_values_are_canonical(environment_scope, 'scope')
    ),
    ADD CONSTRAINT sessions_exact_identity_authority_fk
        FOREIGN KEY (
            provider,
            identity_issuer,
            identity_subject,
            identity_authority_epoch
        )
        REFERENCES identity_authorities
            (provider, issuer, subject, authority_epoch)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    ADD CONSTRAINT sessions_human_authority_fk
        FOREIGN KEY (provider, identity_issuer, identity_subject, human_authority_version)
        REFERENCES human_authority_assignments
            (provider, issuer, subject, assignment_version)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;

CREATE INDEX sessions_human_authority_idx
    ON sessions (
        provider,
        identity_issuer,
        identity_subject,
        human_authority_version,
        identity_authority_epoch
    );

ALTER TABLE api_tokens
    ADD COLUMN issued_by_provider TEXT,
    ADD COLUMN issued_by_issuer TEXT,
    ADD COLUMN issued_by_subject TEXT,
    ADD COLUMN issued_by_identity_epoch BIGINT,
    ADD COLUMN issued_by_human_authority_version BIGINT,
    ADD COLUMN issued_by_roles TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN issued_by_site_authority_mode TEXT,
    ADD COLUMN issued_by_site_scope TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN issued_by_environment_authority_mode TEXT,
    ADD COLUMN issued_by_environment_scope TEXT[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT api_tokens_issued_by_identity_fk
        FOREIGN KEY (issued_by_provider, issued_by_issuer, issued_by_subject)
        REFERENCES identity_authorities (provider, issuer, subject)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    ADD CONSTRAINT api_tokens_roles_canonical_check CHECK (
        human_authority_values_are_canonical(roles, 'role')
    ),
    ADD CONSTRAINT api_tokens_issued_by_roles_canonical_check CHECK (
        human_authority_values_are_canonical(issued_by_roles, 'role')
    ),
    ADD CONSTRAINT api_tokens_issued_by_site_scope_canonical_check CHECK (
        human_authority_values_are_canonical(issued_by_site_scope, 'scope')
    ),
    ADD CONSTRAINT api_tokens_issued_by_environment_scope_canonical_check CHECK (
        human_authority_values_are_canonical(issued_by_environment_scope, 'scope')
    ),
    ADD CONSTRAINT api_tokens_revocation_shape_check CHECK (
        revoked_at IS NULL OR token_valid = FALSE
    ),
    ADD CONSTRAINT api_tokens_issued_by_authority_shape_check CHECK (
        (
            token_valid = FALSE
            AND issued_by_provider IS NULL
            AND issued_by_issuer IS NULL
            AND issued_by_subject IS NULL
            AND issued_by_identity_epoch IS NULL
            AND issued_by_human_authority_version IS NULL
            AND issued_by_site_authority_mode IS NULL
            AND issued_by_environment_authority_mode IS NULL
            AND cardinality(issued_by_roles) = 0
            AND cardinality(issued_by_site_scope) = 0
            AND cardinality(issued_by_environment_scope) = 0
        )
        OR
        (
            issued_by_provider IS NOT NULL
            AND issued_by_issuer IS NOT NULL
            AND issued_by_subject IS NOT NULL
            AND issued_by_identity_epoch IS NOT NULL
            AND issued_by_human_authority_version IS NOT NULL
            AND issued_by_site_authority_mode IS NOT NULL
            AND issued_by_environment_authority_mode IS NOT NULL
            AND issued_by_identity_epoch > 0
            AND issued_by_human_authority_version > 0
            AND (token_valid OR revoked_at IS NOT NULL)
            AND expires_at IS NOT NULL
            AND expires_at > created_at
            AND expires_at <= created_at + INTERVAL '24 hours'
            AND cardinality(issued_by_roles) BETWEEN 1 AND 64
            AND (
                (issued_by_site_authority_mode = 'global'
                    AND cardinality(issued_by_site_scope) = 0)
                OR (issued_by_site_authority_mode = 'scoped'
                    AND cardinality(issued_by_site_scope) BETWEEN 1 AND 64)
            )
            AND (
                (issued_by_environment_authority_mode = 'global'
                    AND cardinality(issued_by_environment_scope) = 0)
                OR (issued_by_environment_authority_mode = 'scoped'
                    AND cardinality(issued_by_environment_scope) BETWEEN 1 AND 64)
            )
        )
    );

CREATE INDEX api_tokens_issued_by_human_authority_idx
    ON api_tokens (
        issued_by_provider,
        issued_by_issuer,
        issued_by_subject,
        issued_by_human_authority_version,
        issued_by_identity_epoch
    );

CREATE FUNCTION human_authority_lock_key(
    key_provider TEXT,
    key_issuer TEXT,
    key_subject TEXT
)
RETURNS BIGINT
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT hashtextextended(
        'ryuki:interactive-human-authority:v2:'
        || length(key_provider)::TEXT || ':' || key_provider
        || length(key_issuer)::TEXT || ':' || key_issuer
        || length(key_subject)::TEXT || ':' || key_subject,
        0
    );
$$;

CREATE FUNCTION human_authority_writer_contract_is_held(
    key_provider TEXT,
    key_issuer TEXT,
    key_subject TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    authority_lock BIGINT;
BEGIN
    authority_lock := human_authority_lock_key(
        key_provider,
        key_issuer,
        key_subject
    );
    RETURN current_setting('ryuki.human_authority_writer_contract', TRUE) = '2'
        AND EXISTS (
            SELECT 1
            FROM pg_catalog.pg_locks AS held
            WHERE held.locktype = 'advisory'
              AND held.pid = pg_backend_pid()
              AND held.mode = 'ExclusiveLock'
              AND held.database = (
                  SELECT oid
                  FROM pg_catalog.pg_database
                  WHERE datname = current_database()
              )
              AND held.classid::BIGINT = ((authority_lock >> 32) & 4294967295)
              AND held.objid::BIGINT = (authority_lock & 4294967295)
              AND held.objsubid = 1
              AND held.granted
        );
END;
$$;

CREATE FUNCTION enforce_human_authority_insert_contract()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT human_authority_writer_contract_is_held(
        NEW.provider,
        NEW.issuer,
        NEW.subject
    ) THEN
        RAISE EXCEPTION 'interactive human authority writer contract v2 is required'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'interactive_human_authority_writer_contract';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_authorities_insert_contract
BEFORE INSERT ON identity_authorities
FOR EACH ROW
EXECUTE FUNCTION enforce_human_authority_insert_contract();

CREATE TRIGGER human_authority_assignments_insert_contract
BEFORE INSERT ON human_authority_assignments
FOR EACH ROW
EXECUTE FUNCTION enforce_human_authority_insert_contract();

CREATE FUNCTION enforce_identity_authority_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    semantic_change BOOLEAN;
BEGIN
    IF NOT human_authority_writer_contract_is_held(
        OLD.provider,
        OLD.issuer,
        OLD.subject
    ) THEN
        RAISE EXCEPTION 'interactive human authority writer contract v2 is required'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'identity_authorities_writer_contract';
    END IF;

    IF NEW.provider <> OLD.provider
        OR NEW.issuer <> OLD.issuer
        OR NEW.subject <> OLD.subject
    THEN
        RAISE EXCEPTION 'identity authority key is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.source_watermark < OLD.source_watermark THEN
        RAISE EXCEPTION 'identity authority source watermark may not decrease'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.authority_status = 'revoked'
        AND NEW.authority_status <> 'revoked'
        AND current_setting('ryuki.identity_authority_reactivation', TRUE)
            IS DISTINCT FROM 'governed-v2'
    THEN
        RAISE EXCEPTION 'revoked identity authority requires explicit governed reactivation'
            USING ERRCODE = '23514';
    END IF;

    semantic_change :=
        NEW.authority_digest IS DISTINCT FROM OLD.authority_digest
        OR NEW.authority_status IS DISTINCT FROM OLD.authority_status
        OR NEW.source_watermark IS DISTINCT FROM OLD.source_watermark;

    IF NEW.authority_epoch < OLD.authority_epoch
        OR NEW.authority_epoch > OLD.authority_epoch + 1
        OR (semantic_change AND NEW.authority_epoch <> OLD.authority_epoch + 1)
    THEN
        RAISE EXCEPTION 'identity authority epoch must advance exactly once per semantic change'
            USING ERRCODE = '23514';
    END IF;

    IF semantic_change OR NEW.authority_epoch <> OLD.authority_epoch THEN
        DELETE FROM sessions
        WHERE provider = OLD.provider
          AND identity_issuer = OLD.issuer
          AND identity_subject = OLD.subject;

        UPDATE api_tokens
        SET token_valid = FALSE,
            revoked_at = COALESCE(revoked_at, NOW())
        WHERE issued_by_provider = OLD.provider
          AND issued_by_issuer = OLD.issuer
          AND issued_by_subject = OLD.subject
          AND token_valid;
    END IF;

    NEW.updated_at := CASE
        WHEN semantic_change OR NEW.authority_epoch <> OLD.authority_epoch
        THEN NOW()
        ELSE OLD.updated_at
    END;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_authorities_epoch_guard
BEFORE UPDATE ON identity_authorities
FOR EACH ROW
EXECUTE FUNCTION enforce_identity_authority_epoch();

CREATE FUNCTION prevent_identity_authority_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'identity authorities are monotonic tombstones and may not be deleted'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER identity_authorities_delete_guard
BEFORE DELETE ON identity_authorities
FOR EACH ROW
EXECUTE FUNCTION prevent_identity_authority_delete();

CREATE TRIGGER identity_authorities_truncate_guard
BEFORE TRUNCATE ON identity_authorities
FOR EACH STATEMENT
EXECUTE FUNCTION prevent_identity_authority_delete();

CREATE FUNCTION enforce_human_authority_assignment_version()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    semantic_change BOOLEAN;
BEGIN
    IF NOT human_authority_writer_contract_is_held(
        OLD.provider,
        OLD.issuer,
        OLD.subject
    ) THEN
        RAISE EXCEPTION 'interactive human authority writer contract v2 is required'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'human_authority_assignments_writer_contract';
    END IF;

    IF NEW.provider <> OLD.provider
        OR NEW.issuer <> OLD.issuer
        OR NEW.subject <> OLD.subject
    THEN
        RAISE EXCEPTION 'human authority assignment identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    semantic_change :=
        NEW.assignment_status IS DISTINCT FROM OLD.assignment_status
        OR NEW.role_allowlist IS DISTINCT FROM OLD.role_allowlist
        OR NEW.site_authority_mode IS DISTINCT FROM OLD.site_authority_mode
        OR NEW.site_scope IS DISTINCT FROM OLD.site_scope
        OR NEW.environment_authority_mode IS DISTINCT FROM OLD.environment_authority_mode
        OR NEW.environment_scope IS DISTINCT FROM OLD.environment_scope
        OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
        OR NEW.updated_by IS DISTINCT FROM OLD.updated_by;

    IF NEW.assignment_version < OLD.assignment_version
        OR NEW.assignment_version > OLD.assignment_version + 1
        OR (semantic_change AND NEW.assignment_version <> OLD.assignment_version + 1)
    THEN
        RAISE EXCEPTION 'human authority assignment version must advance exactly once per change'
            USING ERRCODE = '23514';
    END IF;

    -- The assignment row is already write-locked before this BEFORE trigger.
    -- Delete under that lock so a concurrent mint cannot insert an old-version
    -- session between a repository delete and this security transition.
    IF semantic_change OR NEW.assignment_version <> OLD.assignment_version THEN
        DELETE FROM sessions
        WHERE provider = OLD.provider
          AND identity_issuer = OLD.issuer
          AND identity_subject = OLD.subject;

        UPDATE api_tokens
        SET token_valid = FALSE,
            revoked_at = COALESCE(revoked_at, NOW())
        WHERE issued_by_provider = OLD.provider
          AND issued_by_issuer = OLD.issuer
          AND issued_by_subject = OLD.subject
          AND token_valid;
    END IF;

    NEW.updated_at := CASE
        WHEN semantic_change OR NEW.assignment_version <> OLD.assignment_version
        THEN NOW()
        ELSE OLD.updated_at
    END;
    RETURN NEW;
END;
$$;

CREATE TRIGGER human_authority_assignment_version_guard
BEFORE UPDATE ON human_authority_assignments
FOR EACH ROW
EXECUTE FUNCTION enforce_human_authority_assignment_version();

CREATE FUNCTION prevent_human_authority_assignment_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'human authority assignments are monotonic tombstones and may not be deleted'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER human_authority_assignment_delete_guard
BEFORE DELETE ON human_authority_assignments
FOR EACH ROW
EXECUTE FUNCTION prevent_human_authority_assignment_delete();

CREATE TRIGGER human_authority_assignment_truncate_guard
BEFORE TRUNCATE ON human_authority_assignments
FOR EACH STATEMENT
EXECUTE FUNCTION prevent_human_authority_assignment_delete();

CREATE FUNCTION enforce_session_human_authority()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    assignment human_authority_assignments%ROWTYPE;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'interactive session credentials and authority are immutable; revoke and reissue'
            USING ERRCODE = '23514';
    END IF;

    IF NOT human_authority_writer_contract_is_held(
        NEW.provider,
        NEW.identity_issuer,
        NEW.identity_subject
    ) THEN
        RAISE EXCEPTION 'interactive human authority writer contract v2 is required'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'sessions_human_authority_writer_contract';
    END IF;

    -- Deterministic lock order for every mint: identity, then assignment.
    PERFORM 1
    FROM identity_authorities
    WHERE provider = NEW.provider
      AND issuer = NEW.identity_issuer
      AND subject = NEW.identity_subject
      AND authority_epoch = NEW.identity_authority_epoch
      AND authority_status = 'active-scoped-v2'
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'interactive session requires the exact active identity epoch'
            USING ERRCODE = '23514';
    END IF;

    SELECT *
    INTO assignment
    FROM human_authority_assignments
    WHERE provider = NEW.provider
      AND issuer = NEW.identity_issuer
      AND subject = NEW.identity_subject
      AND assignment_version = NEW.human_authority_version
    FOR SHARE;

    IF NOT FOUND OR assignment.assignment_status <> 'active' THEN
        RAISE EXCEPTION 'interactive session requires a current active human authority assignment'
            USING ERRCODE = '23514';
    END IF;

    IF cardinality(NEW.roles) = 0
        OR NOT (NEW.roles <@ assignment.role_allowlist)
    THEN
        RAISE EXCEPTION 'interactive session roles exceed the human authority assignment'
            USING ERRCODE = '23514';
    END IF;

    IF assignment.site_authority_mode = 'scoped' THEN
        IF NEW.site_authority_mode <> 'scoped'
            OR NOT (NEW.site_scope <@ assignment.site_scope)
        THEN
            RAISE EXCEPTION 'interactive session site authority exceeds the assignment'
                USING ERRCODE = '23514';
        END IF;
    ELSIF assignment.site_authority_mode <> 'global' THEN
        RAISE EXCEPTION 'interactive session site authority is not active'
            USING ERRCODE = '23514';
    END IF;

    IF assignment.environment_authority_mode = 'scoped' THEN
        IF NEW.environment_authority_mode <> 'scoped'
            OR NOT (NEW.environment_scope <@ assignment.environment_scope)
        THEN
            RAISE EXCEPTION 'interactive session environment authority exceeds the assignment'
                USING ERRCODE = '23514';
        END IF;
    ELSIF assignment.environment_authority_mode <> 'global' THEN
        RAISE EXCEPTION 'interactive session environment authority is not active'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER sessions_human_authority_guard
BEFORE INSERT OR UPDATE ON sessions
FOR EACH ROW
EXECUTE FUNCTION enforce_session_human_authority();

CREATE FUNCTION api_token_scope_is_canonical(raw_scope TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    scope_values TEXT[];
BEGIN
    IF raw_scope IS NULL THEN
        RETURN TRUE;
    END IF;
    IF raw_scope = '' OR raw_scope <> btrim(raw_scope) THEN
        RETURN FALSE;
    END IF;
    scope_values := string_to_array(raw_scope, ',');
    RETURN array_to_string(scope_values, ',') = raw_scope
        AND human_authority_values_are_canonical(scope_values, 'scope');
END;
$$;

ALTER TABLE api_tokens
    ADD CONSTRAINT api_tokens_site_scope_canonical_check
        CHECK (api_token_scope_is_canonical(site_scope)),
    ADD CONSTRAINT api_tokens_environment_scope_canonical_check
        CHECK (api_token_scope_is_canonical(environment_scope));

CREATE FUNCTION enforce_api_token_issuing_authority()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    assignment human_authority_assignments%ROWTYPE;
    token_site_scope TEXT[];
    token_environment_scope TEXT[];
BEGIN
    IF NEW.revoked_at IS NOT NULL AND NEW.token_valid THEN
        RAISE EXCEPTION 'a revoked API token must be invalid'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.revoked_at IS NOT NULL
        AND NEW.revoked_at > statement_timestamp()
    THEN
        RAISE EXCEPTION 'API token revocation time may not be in the future'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
            OR NEW.name IS DISTINCT FROM OLD.name
            OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
            OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
            OR NEW.owner_principal IS DISTINCT FROM OLD.owner_principal
            OR NEW.roles IS DISTINCT FROM OLD.roles
            OR NEW.site_scope IS DISTINCT FROM OLD.site_scope
            OR NEW.environment_scope IS DISTINCT FROM OLD.environment_scope
            OR NEW.issued_by_provider IS DISTINCT FROM OLD.issued_by_provider
            OR NEW.issued_by_issuer IS DISTINCT FROM OLD.issued_by_issuer
            OR NEW.issued_by_subject IS DISTINCT FROM OLD.issued_by_subject
            OR NEW.issued_by_identity_epoch IS DISTINCT FROM OLD.issued_by_identity_epoch
            OR NEW.issued_by_human_authority_version
                IS DISTINCT FROM OLD.issued_by_human_authority_version
            OR NEW.issued_by_roles IS DISTINCT FROM OLD.issued_by_roles
            OR NEW.issued_by_site_authority_mode
                IS DISTINCT FROM OLD.issued_by_site_authority_mode
            OR NEW.issued_by_site_scope IS DISTINCT FROM OLD.issued_by_site_scope
            OR NEW.issued_by_environment_authority_mode
                IS DISTINCT FROM OLD.issued_by_environment_authority_mode
            OR NEW.issued_by_environment_scope
                IS DISTINCT FROM OLD.issued_by_environment_scope
        THEN
            RAISE EXCEPTION 'API token credential, authority, and actor provenance are immutable'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.token_valid = FALSE AND NEW.token_valid = TRUE THEN
            RAISE EXCEPTION 'an invalid API token may not be reactivated'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.revoked_at IS NOT NULL
            AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
        THEN
            RAISE EXCEPTION 'an API token revocation is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
            AND NEW.revoked_at IS NULL
        THEN
            RAISE EXCEPTION 'API token revocation time must be current and monotonic'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.token_valid AND NOT NEW.token_valid AND NEW.revoked_at IS NULL THEN
            RAISE EXCEPTION 'API token invalidation must record its revocation time'
                USING ERRCODE = '23514';
        END IF;

        -- Parent identity/assignment invalidation is a pure fail-closed
        -- transition. Do not re-lock those parent rows from the token trigger:
        -- doing so would invert identity -> assignment -> token ordering while
        -- a parent BEFORE UPDATE trigger already owns its row lock.
        IF OLD.token_valid
            AND NOT NEW.token_valid
            AND OLD.revoked_at IS NULL
            AND NEW.revoked_at IS NOT NULL
        THEN
            RETURN NEW;
        END IF;
    END IF;

    IF NEW.issued_by_provider IS NULL
        OR NEW.issued_by_issuer IS NULL
        OR NEW.issued_by_subject IS NULL
    THEN
        IF NEW.token_valid THEN
            RAISE EXCEPTION 'active API token requires exact issuing human authority'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.created_at > statement_timestamp() THEN
        RAISE EXCEPTION 'API token creation time may not be in the future'
            USING ERRCODE = '23514';
    END IF;

    IF NOT human_authority_writer_contract_is_held(
        NEW.issued_by_provider,
        NEW.issued_by_issuer,
        NEW.issued_by_subject
    ) THEN
        RAISE EXCEPTION 'interactive human authority writer contract v2 is required'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'api_tokens_human_authority_writer_contract';
    END IF;

    IF NEW.owner_principal <> NEW.issued_by_subject THEN
        RAISE EXCEPTION 'API token actor must equal its governed issuing subject'
            USING ERRCODE = '23514';
    END IF;

    PERFORM 1
    FROM identity_authorities
    WHERE provider = NEW.issued_by_provider
      AND issuer = NEW.issued_by_issuer
      AND subject = NEW.issued_by_subject
      AND authority_epoch = NEW.issued_by_identity_epoch
      AND authority_status = 'active-scoped-v2'
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'API token requires the exact active issuing identity epoch'
            USING ERRCODE = '23514';
    END IF;

    SELECT *
    INTO assignment
    FROM human_authority_assignments
    WHERE provider = NEW.issued_by_provider
      AND issuer = NEW.issued_by_issuer
      AND subject = NEW.issued_by_subject
      AND assignment_version = NEW.issued_by_human_authority_version
    FOR SHARE;
    IF NOT FOUND OR assignment.assignment_status <> 'active' THEN
        RAISE EXCEPTION 'API token requires the exact active issuing assignment'
            USING ERRCODE = '23514';
    END IF;

    IF cardinality(NEW.issued_by_roles) = 0
        OR NOT (NEW.issued_by_roles <@ assignment.role_allowlist)
        OR NOT (NEW.roles <@ NEW.issued_by_roles)
    THEN
        RAISE EXCEPTION 'API token roles exceed issuing human authority'
            USING ERRCODE = '23514';
    END IF;

    IF assignment.site_authority_mode = 'scoped' THEN
        IF NEW.issued_by_site_authority_mode <> 'scoped'
            OR NOT (NEW.issued_by_site_scope <@ assignment.site_scope)
        THEN
            RAISE EXCEPTION 'API token issuing site authority exceeds assignment'
                USING ERRCODE = '23514';
        END IF;
    ELSIF assignment.site_authority_mode <> 'global' THEN
        RAISE EXCEPTION 'API token issuing site authority is not active'
            USING ERRCODE = '23514';
    END IF;

    IF assignment.environment_authority_mode = 'scoped' THEN
        IF NEW.issued_by_environment_authority_mode <> 'scoped'
            OR NOT (NEW.issued_by_environment_scope <@ assignment.environment_scope)
        THEN
            RAISE EXCEPTION 'API token issuing environment authority exceeds assignment'
                USING ERRCODE = '23514';
        END IF;
    ELSIF assignment.environment_authority_mode <> 'global' THEN
        RAISE EXCEPTION 'API token issuing environment authority is not active'
            USING ERRCODE = '23514';
    END IF;

    token_site_scope := CASE
        WHEN NEW.site_scope IS NULL THEN ARRAY[]::TEXT[]
        ELSE string_to_array(NEW.site_scope, ',')
    END;
    IF NEW.site_scope IS NULL THEN
        IF NEW.issued_by_site_authority_mode <> 'global' THEN
            RAISE EXCEPTION 'unrestricted API token site authority requires Global issuer'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.issued_by_site_authority_mode = 'scoped'
        AND NOT (token_site_scope <@ NEW.issued_by_site_scope)
    THEN
        RAISE EXCEPTION 'API token site scope exceeds issuing human authority'
            USING ERRCODE = '23514';
    END IF;

    token_environment_scope := CASE
        WHEN NEW.environment_scope IS NULL THEN ARRAY[]::TEXT[]
        ELSE string_to_array(NEW.environment_scope, ',')
    END;
    IF NEW.environment_scope IS NULL THEN
        IF NEW.issued_by_environment_authority_mode <> 'global' THEN
            RAISE EXCEPTION 'unrestricted API token environment authority requires Global issuer'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.issued_by_environment_authority_mode = 'scoped'
        AND NOT (token_environment_scope <@ NEW.issued_by_environment_scope)
    THEN
        RAISE EXCEPTION 'API token environment scope exceeds issuing human authority'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER api_tokens_issuing_authority_guard
BEFORE INSERT OR UPDATE OF
    id,
    name,
    token_hash,
    created_at,
    expires_at,
    owner_principal,
    roles,
    site_scope,
    environment_scope,
    token_valid,
    revoked_at,
    issued_by_provider,
    issued_by_issuer,
    issued_by_subject,
    issued_by_identity_epoch,
    issued_by_human_authority_version,
    issued_by_roles,
    issued_by_site_authority_mode,
    issued_by_site_scope,
    issued_by_environment_authority_mode,
    issued_by_environment_scope
ON api_tokens
FOR EACH ROW
EXECUTE FUNCTION enforce_api_token_issuing_authority();

CREATE FUNCTION enforce_api_token_last_used_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.last_used_at IS NOT NULL THEN
            RAISE EXCEPTION 'a new API token may not predeclare usage telemetry'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.last_used_at IS NULL THEN
        RAISE EXCEPTION 'API token usage telemetry may not be cleared'
            USING ERRCODE = '23514';
    END IF;
    IF NOT NEW.token_valid
        OR NEW.revoked_at IS NOT NULL
        OR NEW.expires_at IS NULL
        OR NEW.expires_at <= statement_timestamp()
    THEN
        RAISE EXCEPTION 'only a current active API token may record usage telemetry'
            USING ERRCODE = '23514';
    END IF;

    -- The caller merely signals successful use. PostgreSQL owns the evidence
    -- timestamp, and the row's current value wins if concurrent UPDATEs commit
    -- out of statement-start order. Caller-supplied past/future timestamps are
    -- therefore neither trusted nor capable of rewinding this telemetry.
    NEW.last_used_at := GREATEST(
        COALESCE(OLD.last_used_at, '-infinity'::TIMESTAMPTZ),
        statement_timestamp()
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER api_tokens_last_used_at_guard
BEFORE INSERT OR UPDATE OF last_used_at ON api_tokens
FOR EACH ROW
EXECUTE FUNCTION enforce_api_token_last_used_at();

CREATE FUNCTION prevent_api_token_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'API tokens are immutable evidence and may only be soft-revoked'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER api_tokens_delete_guard
BEFORE DELETE ON api_tokens
FOR EACH ROW
EXECUTE FUNCTION prevent_api_token_delete();

CREATE TRIGGER api_tokens_truncate_guard
BEFORE TRUNCATE ON api_tokens
FOR EACH STATEMENT
EXECUTE FUNCTION prevent_api_token_delete();

COMMENT ON TABLE human_authority_assignments IS
    'Provider-neutral role ceiling and explicit site/environment authority for interactive principals';
COMMENT ON COLUMN human_authority_assignments.assignment_version IS
    'Monotonic security generation; assignment changes delete matching sessions before advancing';
COMMENT ON COLUMN human_authority_assignments.assignment_status IS
    'Unknown and revoked never authenticate; Global exists only as an explicit active axis mode';
COMMENT ON COLUMN sessions.human_authority_version IS
    'Exact assignment generation captured atomically when the interactive session was minted';
COMMENT ON TABLE api_tokens IS
    'Immutable derived-credential evidence; authority changes and administrative revocation only transition token_valid/revoked_at';
COMMENT ON COLUMN api_tokens.issued_by_human_authority_version IS
    'Exact interactive-human assignment generation that bounded token issuance';
COMMENT ON COLUMN api_tokens.issued_by_identity_epoch IS
    'Exact interactive-human identity generation that bounded token issuance';
