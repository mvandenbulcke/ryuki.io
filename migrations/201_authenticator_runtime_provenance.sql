-- 201_authenticator_runtime_provenance.sql
--
-- SECURITY COMPATIBILITY BREAK: this migration is a non-overlapping cutover.
-- Stop every pre-201 API replica before applying it and do not restart one
-- afterward.  Version-2 login-state readers and writers are deliberately left
-- without their relation, while every pre-201 session and login state is
-- discarded because neither contains the exact authenticator origin that
-- established it.  Rollback restores the database and binary together only
-- after all post-cutover sessions and login states have been invalidated.

SET LOCAL lock_timeout = '30s';

LOCK TABLE sessions, oidc_login_states IN ACCESS EXCLUSIVE MODE;

-- D/P/Q/R and the independently derived origin digest cannot be reconstructed
-- from either legacy row shape.  Guessing would create an authority fallback.
DELETE FROM sessions;
DELETE FROM oidc_login_states;

-- The relation name remains stable for the v3 application, so rename the
-- authenticating column itself.  Every pre-201 reader and writer still names
-- bearer_verifier and therefore fails closed even if it never touches the new
-- nullable provenance column.
ALTER TABLE sessions
    RENAME COLUMN bearer_verifier TO session_bearer_verifier_v3;

-- The live principal-key authority column is also a binary-generation fence.
-- Historical principal_key_versions evidence intentionally retains its
-- original column name because those rows are append-only observations, not a
-- mutable authority surface.
ALTER TABLE principal_keys
    RENAME COLUMN authority_digest TO authority_digest_v3;

-- Principal migration 199 predates canonical provider-registry identifiers.
-- Preserve its existing local and legacy provider ids, while admitting only
-- the exact lower-case provider: namespace for the new registry-shaped ids.
DO $principal_provider_constraint_preflight$
DECLARE
    relation_name TEXT;
    relation_oid REGCLASS;
    length_constraint_name TEXT;
    pattern_constraint_name TEXT;
    length_definition TEXT;
    pattern_definition TEXT;
    provider_attribute_number SMALLINT;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY[
        'principal_provider_tombstones',
        'principal_keys',
        'principal_key_tombstones'
    ] LOOP
        relation_oid := pg_catalog.to_regclass('public.' || relation_name);
        IF relation_oid IS NULL THEN
            RAISE EXCEPTION
                'migration 201 requires predecessor relation public.%',
                relation_name
                USING ERRCODE = '55000';
        END IF;

        SELECT attribute.attnum
        INTO provider_attribute_number
        FROM pg_catalog.pg_attribute AS attribute
        WHERE attribute.attrelid = relation_oid
          AND attribute.attname = 'provider_id'
          AND NOT attribute.attisdropped;

        IF provider_attribute_number IS NULL THEN
            RAISE EXCEPTION
                'migration 201 requires public.%.provider_id',
                relation_name
                USING ERRCODE = '55000';
        END IF;

        length_constraint_name := relation_name || '_provider_id_check';
        pattern_constraint_name := relation_name || '_provider_id_check1';

        SELECT pg_catalog.pg_get_constraintdef(constraint_record.oid)
        INTO length_definition
        FROM pg_catalog.pg_constraint AS constraint_record
        WHERE constraint_record.conrelid = relation_oid
          AND constraint_record.conname = length_constraint_name
          AND constraint_record.contype = 'c'
          AND constraint_record.conenforced
          AND constraint_record.convalidated
          AND NOT constraint_record.condeferrable
          AND NOT constraint_record.condeferred
          AND NOT constraint_record.connoinherit
          AND constraint_record.conkey =
              ARRAY[provider_attribute_number]::SMALLINT[];

        SELECT pg_catalog.pg_get_constraintdef(constraint_record.oid)
        INTO pattern_definition
        FROM pg_catalog.pg_constraint AS constraint_record
        WHERE constraint_record.conrelid = relation_oid
          AND constraint_record.conname = pattern_constraint_name
          AND constraint_record.contype = 'c'
          AND constraint_record.conenforced
          AND constraint_record.convalidated
          AND NOT constraint_record.condeferrable
          AND NOT constraint_record.condeferred
          AND NOT constraint_record.connoinherit
          AND constraint_record.conkey =
              ARRAY[provider_attribute_number]::SMALLINT[];

        IF length_definition IS DISTINCT FROM
            'CHECK (((length(provider_id) >= 1) AND (length(provider_id) <= 64)))'
           OR pattern_definition IS DISTINCT FROM
            'CHECK ((provider_id ~ ''^[A-Za-z0-9][A-Za-z0-9._-]*$''::text))'
        THEN
            RAISE EXCEPTION
                'migration 201 found drifted provider-id constraints on public.% (length=%, pattern=%)',
                relation_name,
                COALESCE(length_definition, '<missing>'),
                COALESCE(pattern_definition, '<missing>')
                USING ERRCODE = '55000';
        END IF;
    END LOOP;
END;
$principal_provider_constraint_preflight$;

ALTER TABLE principal_provider_tombstones
    DROP CONSTRAINT principal_provider_tombstones_provider_id_check,
    DROP CONSTRAINT principal_provider_tombstones_provider_id_check1,
    ADD CONSTRAINT principal_provider_tombstones_provider_id_canonical_check
        CHECK (
            provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
            OR provider_id ~ '^provider:[a-z0-9][a-z0-9._-]{2,126}$'
        );

ALTER TABLE principal_keys
    DROP CONSTRAINT principal_keys_provider_id_check,
    DROP CONSTRAINT principal_keys_provider_id_check1,
    ADD CONSTRAINT principal_keys_provider_id_canonical_check
        CHECK (
            provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
            OR provider_id ~ '^provider:[a-z0-9][a-z0-9._-]{2,126}$'
        );

ALTER TABLE principal_key_tombstones
    DROP CONSTRAINT principal_key_tombstones_provider_id_check,
    DROP CONSTRAINT principal_key_tombstones_provider_id_check1,
    ADD CONSTRAINT principal_key_tombstones_provider_id_canonical_check
        CHECK (
            provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
            OR provider_id ~ '^provider:[a-z0-9][a-z0-9._-]{2,126}$'
        );

-- One append-only row is the exact provenance retained by every credential
-- issued through one admitted authenticator path.  The primary key is the
-- 32-byte ryuki-authenticator-origin-binding-v1 digest; D, P, Q, and R remain
-- separately named inputs and are never interchangeable with it or each other.
CREATE TABLE authenticator_authority_generations (
    authenticator_origin_binding_digest BYTEA PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    trust_domain_id TEXT NOT NULL,
    tenant_id TEXT,
    provider_id TEXT NOT NULL,
    provider_configuration_version BIGINT NOT NULL,
    provider_configuration_payload_digest BYTEA NOT NULL,
    provider_lifecycle_record_version BIGINT NOT NULL,
    provider_lifecycle_state TEXT NOT NULL,
    binding_document_id TEXT NOT NULL,
    binding_document_version BIGINT NOT NULL,
    binding_document_digest BYTEA NOT NULL,
    binding_document_locator TEXT NOT NULL,
    provider_policy_binding_digest BYTEA NOT NULL,
    runtime_binding_digest BYTEA NOT NULL,
    path_id TEXT NOT NULL,
    path_version BIGINT NOT NULL,
    path_kind TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT authenticator_authority_generations_digest_path_kind_key
        UNIQUE (authenticator_origin_binding_digest, path_kind),
    CONSTRAINT authenticator_authority_generations_digest_provider_path_key
        UNIQUE (
            authenticator_origin_binding_digest,
            provider_id,
            path_kind
        ),
    CONSTRAINT authenticator_authority_generations_complete_preimage_key
        UNIQUE NULLS NOT DISTINCT (
            deployment_id,
            trust_domain_id,
            tenant_id,
            provider_id,
            provider_configuration_version,
            provider_configuration_payload_digest,
            provider_lifecycle_record_version,
            provider_lifecycle_state,
            binding_document_id,
            binding_document_version,
            binding_document_digest,
            binding_document_locator,
            provider_policy_binding_digest,
            runtime_binding_digest,
            path_id,
            path_version,
            path_kind
        ),
    CONSTRAINT authenticator_authority_origin_digest_check CHECK (
        octet_length(authenticator_origin_binding_digest) = 32
        AND authenticator_origin_binding_digest <>
            decode(repeat('00', 32), 'hex')
    ),
    CONSTRAINT authenticator_authority_deployment_id_check CHECK (
        deployment_id ~ '^deployment:[a-z0-9][a-z0-9._-]{2,126}$'
    ),
    CONSTRAINT authenticator_authority_trust_domain_id_check CHECK (
        trust_domain_id ~ '^trust-domain:[a-z0-9][a-z0-9._-]{2,126}$'
    ),
    CONSTRAINT authenticator_authority_tenant_id_check CHECK (
        tenant_id IS NULL
        OR tenant_id ~ '^tenant:[a-z0-9][a-z0-9._-]{2,126}$'
    ),
    CONSTRAINT authenticator_authority_provider_id_check CHECK (
        provider_id ~ '^provider:[a-z0-9][a-z0-9._-]{2,126}$'
    ),
    CONSTRAINT authenticator_authority_provider_version_check CHECK (
        provider_configuration_version > 0
        AND provider_lifecycle_record_version > 0
    ),
    CONSTRAINT authenticator_authority_provider_lifecycle_check CHECK (
        provider_lifecycle_state = 'active'
    ),
    CONSTRAINT authenticator_authority_document_id_check CHECK (
        binding_document_id ~
            '^authenticator-runtime-binding:[a-z0-9][a-z0-9._-]{2,126}$'
    ),
    CONSTRAINT authenticator_authority_document_version_check CHECK (
        binding_document_version > 0
    ),
    CONSTRAINT authenticator_authority_document_locator_check CHECK (
        octet_length(binding_document_locator) BETWEEN 3 AND 1024
        AND binding_document_locator ~
            '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+[.]json$'
        AND binding_document_locator !~ '(^|/)[.][.]?(/|$)'
    ),
    CONSTRAINT authenticator_authority_path_id_check CHECK (
        path_id ~ '^authenticator-path:[a-z0-9][a-z0-9._-]{2,126}$'
    ),
    CONSTRAINT authenticator_authority_path_version_check CHECK (
        path_version > 0
    ),
    CONSTRAINT authenticator_authority_path_kind_check CHECK (
        path_kind IN ('bearer', 'browser-derived-session')
    ),
    CONSTRAINT authenticator_authority_digests_check CHECK (
        octet_length(provider_configuration_payload_digest) = 32
        AND octet_length(binding_document_digest) = 32
        AND octet_length(provider_policy_binding_digest) = 32
        AND octet_length(runtime_binding_digest) = 32
        AND provider_configuration_payload_digest <>
            decode(repeat('00', 32), 'hex')
        AND binding_document_digest <> decode(repeat('00', 32), 'hex')
        AND provider_policy_binding_digest <> decode(repeat('00', 32), 'hex')
        AND runtime_binding_digest <> decode(repeat('00', 32), 'hex')
    ),
    CONSTRAINT authenticator_authority_d_p_q_r_separation_check CHECK (
        binding_document_digest <> provider_configuration_payload_digest
        AND binding_document_digest <> provider_policy_binding_digest
        AND binding_document_digest <> runtime_binding_digest
        AND provider_configuration_payload_digest <>
            provider_policy_binding_digest
        AND provider_configuration_payload_digest <> runtime_binding_digest
        AND provider_policy_binding_digest <> runtime_binding_digest
    ),
    CONSTRAINT authenticator_authority_origin_separation_check CHECK (
        authenticator_origin_binding_digest <> binding_document_digest
        AND authenticator_origin_binding_digest <>
            provider_configuration_payload_digest
        AND authenticator_origin_binding_digest <>
            provider_policy_binding_digest
        AND authenticator_origin_binding_digest <> runtime_binding_digest
    )
);

COMMENT ON TABLE authenticator_authority_generations IS
    'Append-only exact authenticator origin provenance; FK existence is not currentness, which authenticator_authority_current_paths proves independently';
COMMENT ON COLUMN authenticator_authority_generations.binding_document_digest IS
    'D: SHA-256 of the exact raw authenticator-runtime-binding document bytes';
COMMENT ON COLUMN authenticator_authority_generations.provider_configuration_payload_digest IS
    'P: SHA-256 of the exact active provider configuration payload';
COMMENT ON COLUMN authenticator_authority_generations.provider_policy_binding_digest IS
    'Q: independently recomputed provider-policy binding digest';
COMMENT ON COLUMN authenticator_authority_generations.runtime_binding_digest IS
    'R: independently measured retained authenticator runtime binding digest';
COMMENT ON COLUMN authenticator_authority_generations.path_kind IS
    'Closed credential path class; browser state and federated sessions admit only browser-derived-session';
COMMENT ON COLUMN authenticator_authority_generations.recorded_at IS
    'Non-authoritative insertion metadata excluded from the canonical authenticator-origin preimage';
COMMENT ON CONSTRAINT authenticator_authority_generations_complete_preimage_key
    ON authenticator_authority_generations IS
    'Prevents one canonical D/P/Q/R origin preimage from being registered under multiple origin digests';
COMMENT ON CONSTRAINT authenticator_authority_generations_digest_path_kind_key
    ON authenticator_authority_generations IS
    'Composite FK target that closes bearer versus browser-derived-session substitution';

CREATE FUNCTION reject_authenticator_authority_generation_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION
        'authenticator authority generations are append-only and may not be updated, deleted, or truncated'
        USING ERRCODE = '23514',
              CONSTRAINT = 'authenticator_authority_generations_append_only';
END;
$$;

CREATE TRIGGER authenticator_authority_generations_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON authenticator_authority_generations
FOR EACH STATEMENT
EXECUTE FUNCTION reject_authenticator_authority_generation_mutation();

ALTER TABLE authenticator_authority_generations
    ENABLE ALWAYS TRIGGER authenticator_authority_generations_append_only;

-- Durable currentness is a database fact, not a process-local startup
-- observation. Every provider always owns one bearer pointer and one browser
-- pointer. Disabled paths retain the exact bearer generation anchoring that
-- provider epoch while exposing no current credential authority.
CREATE TABLE authenticator_authority_current_paths (
    provider_id TEXT NOT NULL,
    path_kind TEXT NOT NULL,
    path_status TEXT NOT NULL,
    current_origin_binding_digest BYTEA,
    provider_epoch_origin_binding_digest BYTEA NOT NULL,
    provider_epoch_path_kind TEXT NOT NULL,
    CONSTRAINT authenticator_authority_current_paths_pkey
        PRIMARY KEY (provider_id, path_kind),
    CONSTRAINT authenticator_authority_current_paths_provider_id_check CHECK (
        provider_id ~ '^provider:[a-z0-9][a-z0-9._-]{2,126}$'
    ),
    CONSTRAINT authenticator_authority_current_paths_path_kind_check CHECK (
        path_kind IN ('bearer', 'browser-derived-session')
    ),
    CONSTRAINT authenticator_authority_current_paths_path_status_check CHECK (
        path_status IN ('active', 'disabled')
    ),
    CONSTRAINT authenticator_authority_current_paths_epoch_path_check CHECK (
        provider_epoch_path_kind = 'bearer'
    ),
    CONSTRAINT authenticator_authority_current_paths_digest_check CHECK (
        octet_length(provider_epoch_origin_binding_digest) = 32
        AND provider_epoch_origin_binding_digest <>
            decode(repeat('00', 32), 'hex')
        AND (
            current_origin_binding_digest IS NULL
            OR (
                octet_length(current_origin_binding_digest) = 32
                AND current_origin_binding_digest <>
                    decode(repeat('00', 32), 'hex')
            )
        )
    ),
    CONSTRAINT authenticator_authority_current_paths_shape_check CHECK (
        (
            path_kind = 'bearer'
            AND (
                (
                    path_status = 'active'
                    AND current_origin_binding_digest IS NOT NULL
                    AND current_origin_binding_digest =
                        provider_epoch_origin_binding_digest
                )
                OR
                (
                    path_status = 'disabled'
                    AND current_origin_binding_digest IS NULL
                )
            )
        )
        OR
        (
            path_kind = 'browser-derived-session'
            AND (
                (
                    path_status = 'active'
                    AND current_origin_binding_digest IS NOT NULL
                )
                OR
                (
                    path_status = 'disabled'
                    AND current_origin_binding_digest IS NULL
                )
            )
        )
    ),
    CONSTRAINT authenticator_authority_current_paths_current_origin_fk
        FOREIGN KEY (
            current_origin_binding_digest,
            provider_id,
            path_kind
        )
        REFERENCES authenticator_authority_generations (
            authenticator_origin_binding_digest,
            provider_id,
            path_kind
        )
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT authenticator_authority_current_paths_epoch_origin_fk
        FOREIGN KEY (
            provider_epoch_origin_binding_digest,
            provider_id,
            provider_epoch_path_kind
        )
        REFERENCES authenticator_authority_generations (
            authenticator_origin_binding_digest,
            provider_id,
            path_kind
        )
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

COMMENT ON TABLE authenticator_authority_current_paths IS
    'Durable exact current authenticator path pointers; one atomic startup reconciliation owns both provider rows';
COMMENT ON COLUMN authenticator_authority_current_paths.current_origin_binding_digest IS
    'Exact current path origin, or NULL for an explicitly disabled bearer or browser-derived-session path';
COMMENT ON COLUMN authenticator_authority_current_paths.provider_epoch_origin_binding_digest IS
    'Exact bearer generation anchoring the provider configuration epoch for both path rows';

-- This singleton persists deployment-wide Local/disabled intent across
-- process restarts. A NULL floor is terminal for application authority: it is
-- created only when Local mode fences a clean database and requires a governed
-- migration/admin reset before any authenticator can be enabled.
CREATE TABLE authenticator_authority_runtime_mode (
    singleton BOOLEAN PRIMARY KEY,
    mode_status TEXT NOT NULL,
    minimum_provider_configuration_version BIGINT,
    CONSTRAINT authenticator_authority_runtime_mode_singleton_check CHECK (
        singleton
    ),
    CONSTRAINT authenticator_authority_runtime_mode_status_check CHECK (
        mode_status IN ('enabled', 'disabled')
    ),
    CONSTRAINT authenticator_authority_runtime_mode_floor_check CHECK (
        (
            mode_status = 'enabled'
            AND minimum_provider_configuration_version >= 1
        )
        OR
        (
            mode_status = 'disabled'
            AND (
                minimum_provider_configuration_version IS NULL
                OR minimum_provider_configuration_version >= 1
            )
        )
    )
);

INSERT INTO authenticator_authority_runtime_mode (
    singleton,
    mode_status,
    minimum_provider_configuration_version
) VALUES (TRUE, 'enabled', 1);

COMMENT ON TABLE authenticator_authority_runtime_mode IS
    'Singleton deployment-wide authenticator enablement fence and nonregressing provider-configuration floor';

CREATE FUNCTION enforce_authenticator_authority_runtime_mode_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    active_contract BOOLEAN;
    disable_contract BOOLEAN;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'ryuki-authenticator-authority-global-transition-v3',
            0
        )
    );
    IF TG_OP = 'INSERT'
       OR NEW.singleton IS DISTINCT FROM OLD.singleton
    THEN
        RAISE EXCEPTION
            'authenticator runtime-mode singleton identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    active_contract := COALESCE(
        current_setting(
            'ryuki.authenticator_runtime_mode_active_contract',
            TRUE
        ) = '3',
        FALSE
    );
    disable_contract := COALESCE(
        current_setting(
            'ryuki.authenticator_runtime_mode_disable_contract',
            TRUE
        ) = '3',
        FALSE
    );
    IF active_contract = disable_contract THEN
        RAISE EXCEPTION
            'exactly one authenticator runtime-mode writer contract is required'
            USING ERRCODE = '55000';
    END IF;

    IF active_contract THEN
        IF OLD.mode_status <> 'disabled'
           OR OLD.minimum_provider_configuration_version IS NULL
           OR NEW.mode_status <> 'enabled'
           OR NEW.minimum_provider_configuration_version IS DISTINCT FROM
                OLD.minimum_provider_configuration_version
        THEN
            RAISE EXCEPTION
                'authenticator runtime reactivation violates the durable floor'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.mode_status = 'disabled' THEN
        IF NEW.mode_status <> 'disabled'
           OR NEW.minimum_provider_configuration_version IS DISTINCT FROM
                OLD.minimum_provider_configuration_version
        THEN
            RAISE EXCEPTION
                'repeated authenticator disablement must be idempotent'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.mode_status <> 'disabled'
          OR (
              NEW.minimum_provider_configuration_version IS NOT NULL
              AND NEW.minimum_provider_configuration_version <=
                    OLD.minimum_provider_configuration_version
          )
    THEN
        RAISE EXCEPTION
            'authenticator disablement must install a strict floor or terminal fence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER authenticator_authority_runtime_mode_transition_guard
BEFORE INSERT OR UPDATE ON authenticator_authority_runtime_mode
FOR EACH ROW
EXECUTE FUNCTION enforce_authenticator_authority_runtime_mode_transition();

CREATE FUNCTION reject_authenticator_authority_runtime_mode_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION
        'authenticator runtime-mode singleton may not be deleted or truncated'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER authenticator_authority_runtime_mode_no_removal
BEFORE DELETE OR TRUNCATE ON authenticator_authority_runtime_mode
FOR EACH STATEMENT
EXECUTE FUNCTION reject_authenticator_authority_runtime_mode_removal();

ALTER TABLE authenticator_authority_runtime_mode
    ENABLE ALWAYS TRIGGER authenticator_authority_runtime_mode_transition_guard;
ALTER TABLE authenticator_authority_runtime_mode
    ENABLE ALWAYS TRIGGER authenticator_authority_runtime_mode_no_removal;

CREATE FUNCTION enforce_authenticator_authority_current_path_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    old_provider_epoch BIGINT;
    new_provider_epoch BIGINT;
    active_contract BOOLEAN;
    disable_contract BOOLEAN;
BEGIN
    active_contract := COALESCE(
        current_setting(
            'ryuki.authenticator_current_path_contract',
            TRUE
        ) = '3',
        FALSE
    );
    disable_contract := COALESCE(
        current_setting(
            'ryuki.authenticator_current_path_disable_contract',
            TRUE
        ) = '3',
        FALSE
    );
    IF active_contract = disable_contract THEN
        RAISE EXCEPTION
            'exactly one authenticator current-path writer contract is required'
            USING ERRCODE = '55000',
                  CONSTRAINT =
                      'authenticator_authority_current_paths_writer_contract';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'ryuki-authenticator-authority-global-transition-v3',
            0
        )
    );
    PERFORM pg_catalog.pg_advisory_xact_lock(
        public.principal_registry_provider_lock_key(NEW.provider_id)
    );

    IF TG_OP = 'INSERT' THEN
        IF disable_contract THEN
            RAISE EXCEPTION
                'authenticator disablement may not create pointer rows'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.provider_id, NEW.path_kind) IS DISTINCT FROM
       ROW(OLD.provider_id, OLD.path_kind)
    THEN
        RAISE EXCEPTION
            'authenticator current-path identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    SELECT generation.provider_configuration_version
    INTO STRICT old_provider_epoch
    FROM public.authenticator_authority_generations AS generation
    WHERE generation.authenticator_origin_binding_digest =
            OLD.provider_epoch_origin_binding_digest
      AND generation.provider_id = OLD.provider_id
      AND generation.path_kind = 'bearer'
    FOR SHARE;
    SELECT generation.provider_configuration_version
    INTO STRICT new_provider_epoch
    FROM public.authenticator_authority_generations AS generation
    WHERE generation.authenticator_origin_binding_digest =
            NEW.provider_epoch_origin_binding_digest
      AND generation.provider_id = NEW.provider_id
      AND generation.path_kind = 'bearer'
    FOR SHARE;

    IF disable_contract THEN
        IF NEW.path_status <> 'disabled'
           OR NEW.current_origin_binding_digest IS NOT NULL
           OR NEW.provider_epoch_origin_binding_digest IS DISTINCT FROM
                OLD.provider_epoch_origin_binding_digest
           OR NEW.provider_epoch_path_kind IS DISTINCT FROM
                OLD.provider_epoch_path_kind
           OR new_provider_epoch <> old_provider_epoch
        THEN
            RAISE EXCEPTION
                'authenticator disablement may only clear current authority at the retained epoch'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF new_provider_epoch < old_provider_epoch THEN
        RAISE EXCEPTION
            'authenticator provider configuration epoch may not regress'
            USING ERRCODE = '23514';
    ELSIF new_provider_epoch = old_provider_epoch
          AND ROW(
                NEW.path_status,
                NEW.current_origin_binding_digest,
                NEW.provider_epoch_origin_binding_digest,
                NEW.provider_epoch_path_kind
              ) IS DISTINCT FROM ROW(
                OLD.path_status,
                OLD.current_origin_binding_digest,
                OLD.provider_epoch_origin_binding_digest,
                OLD.provider_epoch_path_kind
              )
    THEN
        RAISE EXCEPTION
            'equal authenticator provider epoch permits exact row idempotency only'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER authenticator_authority_current_paths_transition_guard
BEFORE INSERT OR UPDATE ON authenticator_authority_current_paths
FOR EACH ROW
EXECUTE FUNCTION enforce_authenticator_authority_current_path_transition();

CREATE FUNCTION validate_authenticator_authority_current_provider()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM 1
    FROM public.authenticator_authority_current_paths AS bearer
    JOIN public.authenticator_authority_generations AS bearer_generation
      ON bearer_generation.authenticator_origin_binding_digest =
            bearer.provider_epoch_origin_binding_digest
     AND bearer_generation.provider_id = bearer.provider_id
     AND bearer_generation.path_kind = bearer.path_kind
    JOIN public.authenticator_authority_current_paths AS browser
      ON browser.provider_id = bearer.provider_id
     AND browser.path_kind = 'browser-derived-session'
     AND browser.provider_epoch_origin_binding_digest =
            bearer.provider_epoch_origin_binding_digest
     AND browser.provider_epoch_path_kind = 'bearer'
    LEFT JOIN public.authenticator_authority_generations AS browser_generation
      ON browser_generation.authenticator_origin_binding_digest =
            browser.current_origin_binding_digest
     AND browser_generation.provider_id = browser.provider_id
     AND browser_generation.path_kind = browser.path_kind
    WHERE bearer.provider_id = NEW.provider_id
      AND bearer.path_kind = 'bearer'
      AND bearer.provider_epoch_path_kind = 'bearer'
      AND (
          (
              bearer.path_status = 'disabled'
              AND bearer.current_origin_binding_digest IS NULL
              AND browser.path_status = 'disabled'
              AND browser.current_origin_binding_digest IS NULL
              AND browser_generation.authenticator_origin_binding_digest
                    IS NULL
          )
          OR
          (
              bearer.path_status = 'active'
              AND bearer.current_origin_binding_digest =
                    bearer.provider_epoch_origin_binding_digest
              AND (
                  (
                      browser.path_status = 'disabled'
                      AND browser.current_origin_binding_digest IS NULL
                      AND browser_generation.authenticator_origin_binding_digest
                            IS NULL
                  )
                  OR
                  (
                      browser.path_status = 'active'
                      AND browser.current_origin_binding_digest IS NOT NULL
                      AND browser_generation.authenticator_origin_binding_digest
                            IS NOT NULL
                      AND ROW(
                    browser_generation.deployment_id,
                    browser_generation.trust_domain_id,
                    browser_generation.tenant_id,
                    browser_generation.provider_id,
                    browser_generation.provider_configuration_version,
                    browser_generation.provider_configuration_payload_digest,
                    browser_generation.provider_lifecycle_record_version,
                    browser_generation.provider_lifecycle_state,
                    browser_generation.binding_document_id,
                    browser_generation.binding_document_version,
                    browser_generation.binding_document_digest,
                    browser_generation.binding_document_locator,
                    browser_generation.provider_policy_binding_digest,
                    browser_generation.runtime_binding_digest
                  ) IS NOT DISTINCT FROM ROW(
                    bearer_generation.deployment_id,
                    bearer_generation.trust_domain_id,
                    bearer_generation.tenant_id,
                    bearer_generation.provider_id,
                    bearer_generation.provider_configuration_version,
                    bearer_generation.provider_configuration_payload_digest,
                    bearer_generation.provider_lifecycle_record_version,
                    bearer_generation.provider_lifecycle_state,
                    bearer_generation.binding_document_id,
                    bearer_generation.binding_document_version,
                    bearer_generation.binding_document_digest,
                    bearer_generation.binding_document_locator,
                    bearer_generation.provider_policy_binding_digest,
                    bearer_generation.runtime_binding_digest
                  )
                  )
              )
          )
      );

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'authenticator current paths require one coherent bearer/browser provider epoch'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'authenticator_authority_current_provider_coherence';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER authenticator_authority_current_provider_coherence
AFTER INSERT OR UPDATE ON authenticator_authority_current_paths
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION validate_authenticator_authority_current_provider();

CREATE FUNCTION reject_authenticator_authority_current_path_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION
        'authenticator current paths may not be deleted or truncated'
        USING ERRCODE = '23514',
              CONSTRAINT =
                  'authenticator_authority_current_paths_no_removal';
END;
$$;

CREATE TRIGGER authenticator_authority_current_paths_no_removal
BEFORE DELETE OR TRUNCATE ON authenticator_authority_current_paths
FOR EACH STATEMENT
EXECUTE FUNCTION reject_authenticator_authority_current_path_removal();

ALTER TABLE authenticator_authority_current_paths
    ENABLE ALWAYS TRIGGER authenticator_authority_current_paths_transition_guard;
ALTER TABLE authenticator_authority_current_paths
    ENABLE ALWAYS TRIGGER authenticator_authority_current_provider_coherence;
ALTER TABLE authenticator_authority_current_paths
    ENABLE ALWAYS TRIGGER authenticator_authority_current_paths_no_removal;

CREATE FUNCTION reconcile_authenticator_authority_current_paths_v3(
    exact_bearer_origin_binding_digest BYTEA,
    exact_browser_origin_binding_digest BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    exact_bearer public.authenticator_authority_generations%ROWTYPE;
    exact_browser public.authenticator_authority_generations%ROWTYPE;
    current_bearer public.authenticator_authority_current_paths%ROWTYPE;
    current_browser public.authenticator_authority_current_paths%ROWTYPE;
    runtime_mode public.authenticator_authority_runtime_mode%ROWTYPE;
    current_epoch BIGINT;
    current_path_count BIGINT;
    desired_browser_status TEXT;
BEGIN
    IF octet_length(exact_bearer_origin_binding_digest) <> 32
       OR exact_bearer_origin_binding_digest =
            decode(repeat('00', 32), 'hex')
       OR (
            exact_browser_origin_binding_digest IS NOT NULL
            AND (
                octet_length(exact_browser_origin_binding_digest) <> 32
                OR exact_browser_origin_binding_digest =
                    decode(repeat('00', 32), 'hex')
            )
       )
    THEN
        RAISE EXCEPTION
            'authenticator current-path reconciliation requires exact nonzero digests'
            USING ERRCODE = '22023';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'ryuki-authenticator-authority-global-transition-v3',
            0
        )
    );
    SELECT mode.*
    INTO STRICT runtime_mode
    FROM public.authenticator_authority_runtime_mode AS mode
    WHERE mode.singleton
    FOR UPDATE;

    SELECT generation.*
    INTO exact_bearer
    FROM public.authenticator_authority_generations AS generation
    WHERE generation.authenticator_origin_binding_digest =
            exact_bearer_origin_binding_digest
      AND generation.path_kind = 'bearer'
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'exact registered bearer authenticator generation is required'
            USING ERRCODE = '23503';
    END IF;
    IF runtime_mode.minimum_provider_configuration_version IS NULL
       OR exact_bearer.provider_configuration_version <
            runtime_mode.minimum_provider_configuration_version
    THEN
        RAISE EXCEPTION
            'authenticator provider configuration is below the durable runtime-mode floor'
            USING ERRCODE = '23514';
    END IF;

    IF exact_browser_origin_binding_digest IS NOT NULL THEN
        SELECT generation.*
        INTO exact_browser
        FROM public.authenticator_authority_generations AS generation
        WHERE generation.authenticator_origin_binding_digest =
                exact_browser_origin_binding_digest
          AND generation.path_kind = 'browser-derived-session'
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'exact registered browser authenticator generation is required'
                USING ERRCODE = '23503';
        END IF;
        IF ROW(
                exact_browser.deployment_id,
                exact_browser.trust_domain_id,
                exact_browser.tenant_id,
                exact_browser.provider_id,
                exact_browser.provider_configuration_version,
                exact_browser.provider_configuration_payload_digest,
                exact_browser.provider_lifecycle_record_version,
                exact_browser.provider_lifecycle_state,
                exact_browser.binding_document_id,
                exact_browser.binding_document_version,
                exact_browser.binding_document_digest,
                exact_browser.binding_document_locator,
                exact_browser.provider_policy_binding_digest,
                exact_browser.runtime_binding_digest
            ) IS DISTINCT FROM ROW(
                exact_bearer.deployment_id,
                exact_bearer.trust_domain_id,
                exact_bearer.tenant_id,
                exact_bearer.provider_id,
                exact_bearer.provider_configuration_version,
                exact_bearer.provider_configuration_payload_digest,
                exact_bearer.provider_lifecycle_record_version,
                exact_bearer.provider_lifecycle_state,
                exact_bearer.binding_document_id,
                exact_bearer.binding_document_version,
                exact_bearer.binding_document_digest,
                exact_bearer.binding_document_locator,
                exact_bearer.provider_policy_binding_digest,
                exact_bearer.runtime_binding_digest
            )
        THEN
            RAISE EXCEPTION
                'active browser and bearer paths must share one exact provider epoch'
                USING ERRCODE = '23514';
        END IF;
        desired_browser_status := 'active';
    ELSE
        desired_browser_status := 'disabled';
    END IF;

    -- The global mode lock precedes this provider lock in every startup
    -- transition, while principal-key writes retain only the provider lock.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        public.principal_registry_provider_lock_key(exact_bearer.provider_id)
    );

    PERFORM current_path.provider_id
    FROM public.authenticator_authority_current_paths AS current_path
    WHERE current_path.provider_id = exact_bearer.provider_id
    ORDER BY current_path.path_kind
    FOR UPDATE;
    GET DIAGNOSTICS current_path_count = ROW_COUNT;

    PERFORM pg_catalog.set_config(
        'ryuki.authenticator_current_path_contract',
        '3',
        TRUE
    );
    SET CONSTRAINTS public.authenticator_authority_current_provider_coherence
        DEFERRED;

    IF current_path_count = 0 THEN
        IF runtime_mode.mode_status = 'disabled' THEN
            RAISE EXCEPTION
                'disabled authenticator runtime mode cannot admit an unanchored provider'
                USING ERRCODE = '23514';
        END IF;
        INSERT INTO public.authenticator_authority_current_paths (
            provider_id,
            path_kind,
            path_status,
            current_origin_binding_digest,
            provider_epoch_origin_binding_digest,
            provider_epoch_path_kind
        ) VALUES
        (
            exact_bearer.provider_id,
            'bearer',
            'active',
            exact_bearer_origin_binding_digest,
            exact_bearer_origin_binding_digest,
            'bearer'
        ),
        (
            exact_bearer.provider_id,
            'browser-derived-session',
            desired_browser_status,
            exact_browser_origin_binding_digest,
            exact_bearer_origin_binding_digest,
            'bearer'
        );
        RETURN exact_bearer.provider_id;
    ELSIF current_path_count <> 2 THEN
        RAISE EXCEPTION
            'authenticator provider current-path set is partial'
            USING ERRCODE = '55000';
    END IF;

    SELECT current_path.*
    INTO STRICT current_bearer
    FROM public.authenticator_authority_current_paths AS current_path
    WHERE current_path.provider_id = exact_bearer.provider_id
      AND current_path.path_kind = 'bearer';
    SELECT current_path.*
    INTO STRICT current_browser
    FROM public.authenticator_authority_current_paths AS current_path
    WHERE current_path.provider_id = exact_bearer.provider_id
      AND current_path.path_kind = 'browser-derived-session';

    SELECT generation.provider_configuration_version
    INTO STRICT current_epoch
    FROM public.authenticator_authority_generations AS generation
    WHERE generation.authenticator_origin_binding_digest =
            current_bearer.provider_epoch_origin_binding_digest
      AND generation.provider_id = current_bearer.provider_id
      AND generation.path_kind = 'bearer'
    FOR SHARE;

    IF exact_bearer.provider_configuration_version < current_epoch THEN
        RAISE EXCEPTION
            'authenticator provider configuration epoch may not regress'
            USING ERRCODE = '23514';
    ELSIF exact_bearer.provider_configuration_version = current_epoch THEN
        IF current_bearer.path_status IS DISTINCT FROM 'active'
           OR current_bearer.current_origin_binding_digest IS DISTINCT FROM
                exact_bearer_origin_binding_digest
           OR current_bearer.provider_epoch_origin_binding_digest
                IS DISTINCT FROM exact_bearer_origin_binding_digest
           OR current_browser.path_status IS DISTINCT FROM
                desired_browser_status
           OR current_browser.current_origin_binding_digest IS DISTINCT FROM
                exact_browser_origin_binding_digest
           OR current_browser.provider_epoch_origin_binding_digest
                IS DISTINCT FROM exact_bearer_origin_binding_digest
        THEN
            RAISE EXCEPTION
                'equal authenticator provider epoch permits exact idempotency only'
                USING ERRCODE = '23514';
        END IF;
        RETURN exact_bearer.provider_id;
    END IF;

    UPDATE public.authenticator_authority_current_paths
    SET path_status = 'active',
        current_origin_binding_digest =
            exact_bearer_origin_binding_digest,
        provider_epoch_origin_binding_digest =
            exact_bearer_origin_binding_digest,
        provider_epoch_path_kind = 'bearer'
    WHERE provider_id = exact_bearer.provider_id
      AND path_kind = 'bearer';

    UPDATE public.authenticator_authority_current_paths
    SET path_status = desired_browser_status,
        current_origin_binding_digest =
            exact_browser_origin_binding_digest,
        provider_epoch_origin_binding_digest =
            exact_bearer_origin_binding_digest,
        provider_epoch_path_kind = 'bearer'
    WHERE provider_id = exact_bearer.provider_id
      AND path_kind = 'browser-derived-session';

    IF runtime_mode.mode_status = 'disabled' THEN
        PERFORM pg_catalog.set_config(
            'ryuki.authenticator_runtime_mode_active_contract',
            '3',
            TRUE
        );
        UPDATE public.authenticator_authority_runtime_mode
        SET mode_status = 'enabled'
        WHERE singleton;
    END IF;

    RETURN exact_bearer.provider_id;
END;
$$;

CREATE FUNCTION disable_all_authenticator_authority_current_paths_v3()
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    runtime_mode public.authenticator_authority_runtime_mode%ROWTYPE;
    provider_record RECORD;
    observed_maximum_provider_version BIGINT;
    next_minimum_provider_version BIGINT;
    disabled_provider_count BIGINT;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'ryuki-authenticator-authority-global-transition-v3',
            0
        )
    );
    SELECT mode.*
    INTO STRICT runtime_mode
    FROM public.authenticator_authority_runtime_mode AS mode
    WHERE mode.singleton
    FOR UPDATE;

    FOR provider_record IN
        SELECT DISTINCT current_path.provider_id
        FROM public.authenticator_authority_current_paths AS current_path
        ORDER BY current_path.provider_id
    LOOP
        PERFORM pg_catalog.pg_advisory_xact_lock(
            public.principal_registry_provider_lock_key(
                provider_record.provider_id
            )
        );
    END LOOP;

    PERFORM current_path.provider_id
    FROM public.authenticator_authority_current_paths AS current_path
    ORDER BY current_path.provider_id, current_path.path_kind
    FOR UPDATE;

    IF runtime_mode.mode_status = 'enabled' THEN
        SELECT MAX(generation.provider_configuration_version)
        INTO observed_maximum_provider_version
        FROM public.authenticator_authority_generations AS generation;
        IF observed_maximum_provider_version IS NULL THEN
            next_minimum_provider_version := NULL;
        ELSE
            next_minimum_provider_version := GREATEST(
                observed_maximum_provider_version,
                runtime_mode.minimum_provider_configuration_version
            );
            IF next_minimum_provider_version = 9223372036854775807 THEN
                RAISE EXCEPTION
                    'authenticator provider configuration floor is exhausted'
                    USING ERRCODE = '22003';
            END IF;
            next_minimum_provider_version :=
                next_minimum_provider_version + 1;
        END IF;
    ELSE
        next_minimum_provider_version :=
            runtime_mode.minimum_provider_configuration_version;
    END IF;

    PERFORM pg_catalog.set_config(
        'ryuki.authenticator_current_path_disable_contract',
        '3',
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'ryuki.authenticator_runtime_mode_disable_contract',
        '3',
        TRUE
    );
    SET CONSTRAINTS public.authenticator_authority_current_provider_coherence
        DEFERRED;

    UPDATE public.authenticator_authority_current_paths
    SET path_status = 'disabled',
        current_origin_binding_digest = NULL;

    UPDATE public.authenticator_authority_runtime_mode
    SET mode_status = 'disabled',
        minimum_provider_configuration_version =
            next_minimum_provider_version
    WHERE singleton;

    SELECT COUNT(*)
    INTO disabled_provider_count
    FROM (
        SELECT current_path.provider_id
        FROM public.authenticator_authority_current_paths AS current_path
        GROUP BY current_path.provider_id
        HAVING COUNT(*) = 2
           AND BOOL_AND(current_path.path_status = 'disabled')
           AND BOOL_AND(
                current_path.current_origin_binding_digest IS NULL
           )
    ) AS disabled_provider;
    RETURN disabled_provider_count;
END;
$$;

-- Replace the migration-199 live-key trigger bodies after renaming the live
-- column.  The append-only principal_key_versions historical projection keeps
-- its original authority_digest column name.
CREATE OR REPLACE FUNCTION enforce_principal_key_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    contract_provider TEXT;
    contract_issuer TEXT;
    contract_subject TEXT;
    exact_bearer_origin_setting TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        contract_provider := NEW.provider_id;
        contract_issuer := NEW.issuer;
        contract_subject := NEW.subject;
    ELSE
        contract_provider := OLD.provider_id;
        contract_issuer := OLD.issuer;
        contract_subject := OLD.subject;
    END IF;
    IF NOT principal_registry_writer_contract_is_held(
        contract_provider,
        contract_issuer,
        contract_subject
    ) THEN
        RAISE EXCEPTION 'principal registry writer contract v1 is required'
            USING ERRCODE = '23514';
    END IF;

    IF contract_provider = 'local' THEN
        NULL;
    ELSIF contract_provider ~
            '^provider:[a-z0-9][a-z0-9._-]{2,126}$'
    THEN
        exact_bearer_origin_setting := current_setting(
            'ryuki.principal_bearer_origin_binding_digest_v3',
            TRUE
        );
        IF exact_bearer_origin_setting IS NULL
           OR exact_bearer_origin_setting !~ '^[0-9a-f]{64}$'
        THEN
            RAISE EXCEPTION
                'canonical federated principal write requires an exact transaction-local v3 bearer origin'
                USING ERRCODE = '23514';
        END IF;

        PERFORM 1
        FROM public.authenticator_authority_current_paths AS current_path
        WHERE current_path.provider_id = contract_provider
          AND current_path.path_kind = 'bearer'
          AND current_path.path_status = 'active'
          AND pg_catalog.encode(
                  current_path.current_origin_binding_digest,
                  'hex'
              ) = exact_bearer_origin_setting
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'canonical federated principal write bearer origin is not current'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION
            'legacy federated provider aliases may not write principal keys'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.key_state <> 'active'
           OR EXISTS (
               SELECT 1 FROM public.principal_provider_tombstones
               WHERE provider_id = NEW.provider_id
           )
           OR EXISTS (
               SELECT 1 FROM public.principal_key_tombstones
               WHERE provider_id = NEW.provider_id
                 AND issuer = NEW.issuer
                 AND subject = NEW.subject
           ) THEN
            RAISE EXCEPTION 'new principal key is tombstoned or not active'
                USING ERRCODE = '23514';
        END IF;
        NEW.key_version := 1;
        NEW.created_at := statement_timestamp();
        NEW.updated_at := NEW.created_at;
        NEW.tombstoned_at := NULL;
        RETURN NEW;
    END IF;

    IF ROW(NEW.principal_key_id, NEW.provider_id, NEW.issuer, NEW.subject,
           NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.principal_key_id, OLD.provider_id, OLD.issuer, OLD.subject,
           OLD.created_at) THEN
        RAISE EXCEPTION 'principal key tuple and identity are immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.key_state = 'tombstoned'
       OR NEW.key_version <> OLD.key_version + 1 THEN
        RAISE EXCEPTION 'principal key transition is terminal or not exactly versioned'
            USING ERRCODE = '23514';
    END IF;

    NEW.updated_at := statement_timestamp();
    IF NEW.key_state = 'active' THEN
        IF NEW.authority_digest_v3 IS NOT DISTINCT FROM
            OLD.authority_digest_v3
        THEN
            RAISE EXCEPTION
                'active principal key rotation requires a changed authority digest'
                USING ERRCODE = '23514';
        END IF;
        NEW.tombstoned_at := NULL;
    ELSIF NEW.key_state = 'tombstoned' THEN
        IF NEW.authority_digest_v3 IS DISTINCT FROM
            OLD.authority_digest_v3
        THEN
            RAISE EXCEPTION
                'principal key tombstone may not rewrite credential authority'
                USING ERRCODE = '23514';
        END IF;
        NEW.tombstoned_at := NEW.updated_at;
        UPDATE public.principal_links
        SET link_state = 'tombstoned',
            link_version = link_version + 1,
            transition_kind = 'provider-lifecycle',
            transition_reason = NEW.transition_reason,
            transitioned_by = NEW.transitioned_by
        WHERE principal_key_id = OLD.principal_key_id
          AND link_state <> 'tombstoned';
    ELSE
        RAISE EXCEPTION 'principal key state transition is invalid'
            USING ERRCODE = '23514';
    END IF;

    DELETE FROM public.sessions
    WHERE principal_key_id = OLD.principal_key_id;
    DELETE FROM public.idempotency_records AS replay
    USING public.principal_links AS link
    WHERE link.principal_key_id = OLD.principal_key_id
      AND replay.user_scope = link.principal_id::TEXT;
    UPDATE public.api_tokens
    SET token_valid = FALSE,
        revoked_at = COALESCE(revoked_at, statement_timestamp())
    WHERE principal_key_id = OLD.principal_key_id
      AND token_valid;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION append_principal_key_version()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO public.principal_key_versions (
        principal_key_id,
        key_version,
        authority_digest,
        key_state,
        transition_reason,
        transitioned_by,
        recorded_at
    ) VALUES (
        NEW.principal_key_id,
        NEW.key_version,
        NEW.authority_digest_v3,
        NEW.key_state,
        NEW.transition_reason,
        NEW.transitioned_by,
        NEW.updated_at
    );
    RETURN NEW;
END;
$$;

COMMENT ON COLUMN principal_keys.authority_digest_v3 IS
    'Opaque 32-byte live credential/configuration authority digest; renamed as a migration-201 old-binary SQL fence';

-- Remove the v2 relation altogether after renaming it.  Old binaries continue
-- to address `oidc_login_states` and therefore fail closed rather than writing
-- rows that omit the exact authenticator origin.
ALTER TABLE oidc_login_states RENAME TO oidc_login_states_v2_retired;
DROP TABLE oidc_login_states_v2_retired;
DROP FUNCTION enforce_oidc_login_state_admission_v2();

CREATE TABLE oidc_login_states_v3 (
    state TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    binding TEXT NOT NULL,
    authenticator_origin_binding_digest BYTEA NOT NULL,
    authenticator_path_kind TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT oidc_login_states_v3_state_origin_key
        UNIQUE (state, authenticator_origin_binding_digest),
    CONSTRAINT oidc_login_states_v3_state_check CHECK (
        state ~ '^[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT oidc_login_states_v3_nonce_check CHECK (
        nonce ~ '^[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT oidc_login_states_v3_pkce_verifier_check CHECK (
        pkce_verifier ~ '^[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT oidc_login_states_v3_binding_check CHECK (
        binding ~ '^[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT oidc_login_states_v3_origin_digest_check CHECK (
        octet_length(authenticator_origin_binding_digest) = 32
    ),
    CONSTRAINT oidc_login_states_v3_path_kind_check CHECK (
        authenticator_path_kind = 'browser-derived-session'
    ),
    CONSTRAINT oidc_login_states_v3_expiry_check CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '10 minutes'
    ),
    CONSTRAINT oidc_login_states_v3_origin_fk
        FOREIGN KEY (
            authenticator_origin_binding_digest,
            authenticator_path_kind
        )
        REFERENCES authenticator_authority_generations
            (authenticator_origin_binding_digest, path_kind)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE INDEX oidc_login_states_v3_expiry_state_idx
    ON oidc_login_states_v3 (expires_at, state);
CREATE INDEX oidc_login_states_v3_origin_expiry_state_idx
    ON oidc_login_states_v3 (
        authenticator_origin_binding_digest,
        expires_at,
        state
    );

COMMENT ON TABLE oidc_login_states_v3 IS
    'Single-use browser login states; redemption burns by state and must match the returned exact authenticator origin before returning protocol material';
COMMENT ON CONSTRAINT oidc_login_states_v3_state_origin_key
    ON oidc_login_states_v3 IS
    'Makes the exact state/origin pair an explicit schema identity for DELETE ... RETURNING redemption checks';

CREATE FUNCTION own_oidc_login_state_v3_timestamps()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- Overwrite caller-supplied values so lifetime always uses database time
    -- and cannot be widened by an application writer.
    NEW.created_at := statement_timestamp();
    NEW.expires_at := NEW.created_at + INTERVAL '10 minutes';
    RETURN NEW;
END;
$$;

CREATE TRIGGER oidc_login_states_v3_owned_timestamps
BEFORE INSERT ON oidc_login_states_v3
FOR EACH ROW
EXECUTE FUNCTION own_oidc_login_state_v3_timestamps();

CREATE FUNCTION enforce_oidc_login_state_contract_v3()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- Writers must establish this with SET LOCAL (or set_config(..., TRUE)) in
    -- the same transaction that performs allocation, cleanup, or redemption.
    IF current_setting('ryuki.oidc_login_state_contract', TRUE)
        IS DISTINCT FROM '3'
    THEN
        RAISE EXCEPTION 'OIDC login-state contract v3 is required'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'oidc_login_states_v3_writer_contract';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER oidc_login_states_v3_writer_contract
BEFORE INSERT OR DELETE ON oidc_login_states_v3
FOR EACH STATEMENT
EXECUTE FUNCTION enforce_oidc_login_state_contract_v3();

CREATE FUNCTION enforce_oidc_login_state_current_origin_v3()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM 1
    FROM public.authenticator_authority_generations AS generation
    JOIN public.authenticator_authority_current_paths AS current_path
      ON current_path.provider_id = generation.provider_id
     AND current_path.path_kind = generation.path_kind
     AND current_path.path_status = 'active'
     AND current_path.current_origin_binding_digest =
            generation.authenticator_origin_binding_digest
    WHERE generation.authenticator_origin_binding_digest =
            NEW.authenticator_origin_binding_digest
      AND generation.path_kind = 'browser-derived-session'
    FOR SHARE OF current_path;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'OIDC login state requires the exact active browser authenticator origin'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'oidc_login_states_v3_current_origin_binding';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER oidc_login_states_v3_current_origin_guard
BEFORE INSERT ON oidc_login_states_v3
FOR EACH ROW
EXECUTE FUNCTION enforce_oidc_login_state_current_origin_v3();

CREATE FUNCTION reject_oidc_login_state_v3_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'OIDC login-state v3 rows may not be updated or truncated'
        USING ERRCODE = '23514',
              CONSTRAINT = 'oidc_login_states_v3_immutable';
END;
$$;

CREATE TRIGGER oidc_login_states_v3_immutable
BEFORE UPDATE OR TRUNCATE ON oidc_login_states_v3
FOR EACH STATEMENT
EXECUTE FUNCTION reject_oidc_login_state_v3_mutation();

ALTER TABLE oidc_login_states_v3
    ENABLE ALWAYS TRIGGER oidc_login_states_v3_writer_contract;
ALTER TABLE oidc_login_states_v3
    ENABLE ALWAYS TRIGGER oidc_login_states_v3_immutable;
ALTER TABLE oidc_login_states_v3
    ENABLE ALWAYS TRIGGER oidc_login_states_v3_owned_timestamps;
ALTER TABLE oidc_login_states_v3
    ENABLE ALWAYS TRIGGER oidc_login_states_v3_current_origin_guard;

-- Local sessions do not have an external authenticator origin.  Every
-- provider:-qualified federated key must bind the exact origin digest whose
-- provider id equals the principal key provider id.
ALTER TABLE sessions
    ADD COLUMN authenticator_origin_binding_digest BYTEA,
    ADD CONSTRAINT sessions_authenticator_origin_digest_check CHECK (
        authenticator_origin_binding_digest IS NULL
        OR octet_length(authenticator_origin_binding_digest) = 32
    ),
    ADD CONSTRAINT sessions_authenticator_origin_fk
        FOREIGN KEY (authenticator_origin_binding_digest)
        REFERENCES authenticator_authority_generations
            (authenticator_origin_binding_digest)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE INDEX sessions_authenticator_origin_binding_idx
    ON sessions (authenticator_origin_binding_digest);

CREATE FUNCTION enforce_session_authenticator_origin()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    exact_provider_id TEXT;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'sessions are immutable; revoke and reissue'
            USING ERRCODE = '23514';
    END IF;

    SELECT key.provider_id
    INTO exact_provider_id
    FROM public.principal_keys AS key
    WHERE key.principal_key_id = NEW.principal_key_id
      AND key.key_version = NEW.principal_key_version
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'session requires the exact principal key generation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'sessions_authenticator_origin_binding';
    END IF;

    IF exact_provider_id = 'local' THEN
        IF NEW.authenticator_origin_binding_digest IS NOT NULL THEN
            RAISE EXCEPTION 'local session must not claim a federated authenticator origin'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'sessions_authenticator_origin_binding';
        END IF;
        RETURN NEW;
    END IF;

    IF exact_provider_id !~ '^provider:[a-z0-9][a-z0-9._-]{2,126}$'
        OR NEW.authenticator_origin_binding_digest IS NULL
    THEN
        RAISE EXCEPTION 'federated session requires a canonical provider and exact authenticator origin'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'sessions_authenticator_origin_binding';
    END IF;

    PERFORM 1
    FROM public.authenticator_authority_generations AS origin
    JOIN public.authenticator_authority_current_paths AS current_path
      ON current_path.provider_id = origin.provider_id
     AND current_path.path_kind = origin.path_kind
     AND current_path.path_status = 'active'
     AND current_path.current_origin_binding_digest =
            origin.authenticator_origin_binding_digest
    WHERE origin.authenticator_origin_binding_digest =
            NEW.authenticator_origin_binding_digest
      AND origin.provider_id = exact_provider_id
      AND origin.path_kind = 'browser-derived-session'
    FOR SHARE OF current_path;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'session authenticator origin is not the exact active principal-provider browser-derived-session path'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'sessions_authenticator_origin_binding';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER sessions_authenticator_origin_guard
BEFORE INSERT OR UPDATE ON sessions
FOR EACH ROW
EXECUTE FUNCTION enforce_session_authenticator_origin();

ALTER TABLE sessions
    ENABLE ALWAYS TRIGGER sessions_authenticator_origin_guard;

-- Capture PostgreSQL 18's own deparse of every reviewed CHECK expression.
-- Runtime postflight compares the live expression hash to this immutable,
-- migration-checksum-bound manifest instead of deleting parentheses/casts
-- with an unsafe textual normalizer.
CREATE TABLE authenticator_authority_check_manifest (
    table_name TEXT NOT NULL,
    constraint_name TEXT NOT NULL,
    expression_sha256 BYTEA NOT NULL,
    CONSTRAINT authenticator_authority_check_manifest_pkey
        PRIMARY KEY (table_name, constraint_name)
);

INSERT INTO authenticator_authority_check_manifest (
    table_name,
    constraint_name,
    expression_sha256
)
SELECT class.relname,
       constraint_catalog.conname,
       pg_catalog.sha256(
           pg_catalog.convert_to(
               pg_catalog.pg_get_expr(
                   constraint_catalog.conbin,
                   constraint_catalog.conrelid
               ),
               'UTF8'
           )
       )
FROM pg_catalog.pg_constraint AS constraint_catalog
JOIN pg_catalog.pg_class AS class
  ON class.oid = constraint_catalog.conrelid
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = class.relnamespace
WHERE namespace.nspname = 'public'
  AND constraint_catalog.contype = 'c'
  AND (
      constraint_catalog.conname IN (
          'principal_provider_tombstones_provider_id_canonical_check',
          'principal_keys_provider_id_canonical_check',
          'principal_key_tombstones_provider_id_canonical_check',
          'sessions_bearer_verifier_length',
          'sessions_authenticator_origin_digest_check'
      )
      OR (
          class.relname = 'authenticator_authority_generations'
          AND constraint_catalog.conname LIKE
                'authenticator_authority_%_check'
      )
      OR (
          class.relname = 'authenticator_authority_current_paths'
          AND constraint_catalog.conname LIKE
                'authenticator_authority_current_paths_%_check'
      )
      OR (
          class.relname = 'authenticator_authority_runtime_mode'
          AND constraint_catalog.conname LIKE
                'authenticator_authority_runtime_mode_%_check'
      )
      OR (
          class.relname = 'oidc_login_states_v3'
          AND constraint_catalog.conname LIKE
                'oidc_login_states_v3_%_check'
      )
  )
ORDER BY class.relname, constraint_catalog.conname;

CREATE FUNCTION reject_authenticator_authority_check_manifest_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION
        'authenticator CHECK-expression manifest is append-only and sealed'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER authenticator_authority_check_manifest_immutable
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON authenticator_authority_check_manifest
FOR EACH STATEMENT
EXECUTE FUNCTION reject_authenticator_authority_check_manifest_mutation();

ALTER TABLE authenticator_authority_check_manifest
    ENABLE ALWAYS TRIGGER authenticator_authority_check_manifest_immutable;

REVOKE ALL ON TABLE authenticator_authority_generations FROM PUBLIC;
REVOKE ALL ON TABLE authenticator_authority_current_paths FROM PUBLIC;
REVOKE ALL ON TABLE authenticator_authority_runtime_mode FROM PUBLIC;
REVOKE ALL ON TABLE authenticator_authority_check_manifest FROM PUBLIC;
REVOKE ALL ON TABLE oidc_login_states_v3 FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_authenticator_authority_generation_mutation()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_authenticator_authority_current_path_transition()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_authenticator_authority_current_provider()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_authenticator_authority_current_path_removal()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_authenticator_authority_runtime_mode_transition()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_authenticator_authority_runtime_mode_removal()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_authenticator_authority_check_manifest_mutation()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION reconcile_authenticator_authority_current_paths_v3(
    BYTEA,
    BYTEA
) FROM PUBLIC;
REVOKE ALL ON FUNCTION disable_all_authenticator_authority_current_paths_v3()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_oidc_login_state_contract_v3() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_oidc_login_state_current_origin_v3()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_oidc_login_state_v3_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION own_oidc_login_state_v3_timestamps() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_session_authenticator_origin() FROM PUBLIC;

DO $privileges$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON TABLE public.authenticator_authority_generations FROM ryuki_app_runtime';
        EXECUTE 'GRANT SELECT, INSERT ON TABLE public.authenticator_authority_generations TO ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.authenticator_authority_current_paths FROM ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.authenticator_authority_current_paths TO ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.authenticator_authority_runtime_mode FROM ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.authenticator_authority_runtime_mode TO ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.authenticator_authority_check_manifest FROM ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.authenticator_authority_check_manifest TO ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.oidc_login_states_v3 FROM ryuki_app_runtime';
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON TABLE public.oidc_login_states_v3 TO ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.reject_authenticator_authority_generation_mutation() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_authenticator_authority_current_path_transition() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.validate_authenticator_authority_current_provider() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.reject_authenticator_authority_current_path_removal() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_authenticator_authority_runtime_mode_transition() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.reject_authenticator_authority_runtime_mode_removal() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.reject_authenticator_authority_check_manifest_mutation() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.reconcile_authenticator_authority_current_paths_v3(BYTEA, BYTEA) FROM ryuki_app_runtime';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.reconcile_authenticator_authority_current_paths_v3(BYTEA, BYTEA) TO ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.disable_all_authenticator_authority_current_paths_v3() FROM ryuki_app_runtime';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.disable_all_authenticator_authority_current_paths_v3() TO ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_oidc_login_state_contract_v3() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_oidc_login_state_current_origin_v3() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.reject_oidc_login_state_v3_mutation() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.own_oidc_login_state_v3_timestamps() FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.enforce_session_authenticator_origin() FROM ryuki_app_runtime';
    END IF;
END;
$privileges$;
