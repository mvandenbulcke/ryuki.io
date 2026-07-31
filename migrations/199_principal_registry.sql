-- Stable provider-neutral principal registry.
--
-- SECURITY COMPATIBILITY BREAK: every pre-199 API replica must be stopped
-- before this migration. Legacy tuple/string identity data is retained only as
-- non-authoritative evidence. It is never inferred into a principal, key, link,
-- request owner, or approval actor.

SET LOCAL lock_timeout = '30s';

LOCK TABLE
    identity_authorities,
    human_authority_assignments,
    sessions,
    api_tokens,
    requests,
    request_approval_decisions,
    idempotency_records,
    agents
IN ACCESS EXCLUSIVE MODE;

-- Persisted credentials cannot be translated safely because no stable UUID
-- existed when they were issued.
DROP TRIGGER IF EXISTS sessions_human_authority_guard ON sessions;
DROP TRIGGER IF EXISTS api_tokens_issuing_authority_guard ON api_tokens;

DELETE FROM sessions;
TRUNCATE TABLE idempotency_records;
UPDATE api_tokens
SET token_valid = FALSE,
    revoked_at = COALESCE(revoked_at, statement_timestamp()),
    roles = ARRAY[]::TEXT[],
    site_scope = NULL,
    environment_scope = NULL;

DROP TRIGGER IF EXISTS identity_authorities_insert_contract ON identity_authorities;
DROP TRIGGER IF EXISTS identity_authorities_epoch_guard ON identity_authorities;
DROP TRIGGER IF EXISTS identity_authorities_delete_guard ON identity_authorities;
DROP TRIGGER IF EXISTS identity_authorities_truncate_guard ON identity_authorities;
DROP TRIGGER IF EXISTS human_authority_assignments_insert_contract
    ON human_authority_assignments;
DROP TRIGGER IF EXISTS human_authority_assignment_version_guard
    ON human_authority_assignments;
DROP TRIGGER IF EXISTS human_authority_assignment_delete_guard
    ON human_authority_assignments;
DROP TRIGGER IF EXISTS human_authority_assignment_truncate_guard
    ON human_authority_assignments;

ALTER TABLE sessions
    DROP CONSTRAINT IF EXISTS sessions_exact_identity_authority_fk,
    DROP CONSTRAINT IF EXISTS sessions_human_authority_fk,
    DROP CONSTRAINT IF EXISTS sessions_roles_canonical_check,
    DROP CONSTRAINT IF EXISTS sessions_site_authority_shape_check,
    DROP CONSTRAINT IF EXISTS sessions_environment_authority_shape_check,
    DROP CONSTRAINT IF EXISTS sessions_site_scope_members_check,
    DROP CONSTRAINT IF EXISTS sessions_environment_scope_members_check;

ALTER TABLE api_tokens
    DROP CONSTRAINT IF EXISTS api_tokens_issued_by_identity_fk,
    DROP CONSTRAINT IF EXISTS api_tokens_issued_by_authority_shape_check,
    DROP CONSTRAINT IF EXISTS api_tokens_issued_by_roles_canonical_check,
    DROP CONSTRAINT IF EXISTS api_tokens_issued_by_site_scope_canonical_check,
    DROP CONSTRAINT IF EXISTS api_tokens_issued_by_environment_scope_canonical_check,
    DROP CONSTRAINT IF EXISTS api_tokens_site_scope_canonical_check,
    DROP CONSTRAINT IF EXISTS api_tokens_environment_scope_canonical_check;

DROP INDEX IF EXISTS sessions_identity_authority_idx;
DROP INDEX IF EXISTS sessions_human_authority_idx;
DROP INDEX IF EXISTS api_tokens_issued_by_human_authority_idx;

ALTER TABLE identity_authorities
    RENAME TO legacy_identity_authority_evidence;
ALTER TABLE human_authority_assignments
    RENAME TO legacy_human_authority_evidence;

COMMENT ON TABLE legacy_identity_authority_evidence IS
    'Frozen pre-199 provider tuple authority evidence; never an authorization source';
COMMENT ON TABLE legacy_human_authority_evidence IS
    'Frozen pre-199 role/scope assignment evidence; never an authorization source';

CREATE TABLE principals (
    principal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_kind TEXT NOT NULL
        CHECK (principal_kind IN ('human', 'service', 'agent', 'system')),
    lifecycle_version BIGINT NOT NULL DEFAULT 1
        CHECK (lifecycle_version > 0),
    authority_version BIGINT NOT NULL DEFAULT 1
        CHECK (authority_version > 0),
    lifecycle_state TEXT NOT NULL
        CHECK (lifecycle_state IN (
            'active', 'suspended', 'deprovisioned', 'tombstoned'
        )),
    role_allowlist TEXT[] NOT NULL DEFAULT '{}',
    site_authority_mode TEXT NOT NULL,
    site_scope TEXT[] NOT NULL DEFAULT '{}',
    environment_authority_mode TEXT NOT NULL,
    environment_scope TEXT[] NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    tombstoned_at TIMESTAMPTZ,
    UNIQUE (
        principal_id,
        lifecycle_version,
        authority_version
    ),
    CHECK (principal_id <> '00000000-0000-0000-0000-000000000000'::UUID),
    CHECK (length(created_by) BETWEEN 1 AND 512),
    CHECK (human_authority_values_are_canonical(role_allowlist, 'role')),
    CHECK (human_authority_values_are_canonical(site_scope, 'scope')),
    CHECK (human_authority_values_are_canonical(environment_scope, 'scope')),
    CHECK (
        (
            lifecycle_state = 'active'
            AND principal_kind <> 'agent'
            AND cardinality(role_allowlist) BETWEEN 1 AND 64
            AND site_authority_mode IN ('global', 'scoped')
            AND environment_authority_mode IN ('global', 'scoped')
            AND (
                (site_authority_mode = 'global' AND cardinality(site_scope) = 0)
                OR (site_authority_mode = 'scoped'
                    AND cardinality(site_scope) BETWEEN 1 AND 64)
            )
            AND (
                (environment_authority_mode = 'global'
                    AND cardinality(environment_scope) = 0)
                OR (environment_authority_mode = 'scoped'
                    AND cardinality(environment_scope) BETWEEN 1 AND 64)
            )
        )
        OR
        (
            lifecycle_state = 'active'
            AND principal_kind = 'agent'
            AND cardinality(role_allowlist) = 0
            AND site_authority_mode = 'revoked'
            AND cardinality(site_scope) = 0
            AND environment_authority_mode = 'revoked'
            AND cardinality(environment_scope) = 0
        )
        OR
        (
            lifecycle_state IN ('suspended', 'deprovisioned', 'tombstoned')
            AND cardinality(role_allowlist) = 0
            AND site_authority_mode = 'revoked'
            AND cardinality(site_scope) = 0
            AND environment_authority_mode = 'revoked'
            AND cardinality(environment_scope) = 0
        )
    ),
    CHECK (
        (lifecycle_state = 'tombstoned' AND tombstoned_at IS NOT NULL)
        OR (lifecycle_state <> 'tombstoned' AND tombstoned_at IS NULL)
    )
);

CREATE TABLE principal_provider_tombstones (
    provider_tombstone_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id TEXT NOT NULL UNIQUE,
    tombstone_version BIGINT NOT NULL DEFAULT 1
        CHECK (tombstone_version > 0),
    reason TEXT NOT NULL,
    tombstoned_by TEXT NOT NULL,
    tombstoned_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CHECK (provider_tombstone_id <>
        '00000000-0000-0000-0000-000000000000'::UUID),
    CHECK (length(provider_id) BETWEEN 1 AND 64),
    CHECK (provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'),
    CHECK (length(reason) BETWEEN 1 AND 2048),
    CHECK (length(tombstoned_by) BETWEEN 1 AND 512)
);

CREATE TABLE principal_keys (
    principal_key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    key_version BIGINT NOT NULL DEFAULT 1
        CHECK (key_version > 0),
    authority_digest BYTEA NOT NULL
        CHECK (octet_length(authority_digest) = 32),
    key_state TEXT NOT NULL
        CHECK (key_state IN ('active', 'tombstoned')),
    transition_reason TEXT NOT NULL,
    transitioned_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    tombstoned_at TIMESTAMPTZ,
    UNIQUE (provider_id, issuer, subject),
    UNIQUE (principal_key_id, key_version),
    UNIQUE (
        principal_key_id,
        key_version,
        provider_id,
        issuer,
        subject
    ),
    CHECK (principal_key_id <>
        '00000000-0000-0000-0000-000000000000'::UUID),
    CHECK (length(provider_id) BETWEEN 1 AND 64),
    CHECK (provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'),
    CHECK (length(issuer) BETWEEN 1 AND 2048),
    CHECK (length(subject) BETWEEN 1 AND 512),
    CHECK (length(transition_reason) BETWEEN 1 AND 2048),
    CHECK (length(transitioned_by) BETWEEN 1 AND 512),
    CHECK (
        (key_state = 'tombstoned' AND tombstoned_at IS NOT NULL)
        OR (key_state = 'active' AND tombstoned_at IS NULL)
    )
);

CREATE TABLE principal_key_versions (
    principal_key_id UUID NOT NULL,
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    authority_digest BYTEA NOT NULL
        CHECK (octet_length(authority_digest) = 32),
    key_state TEXT NOT NULL
        CHECK (key_state IN ('active', 'tombstoned')),
    transition_reason TEXT NOT NULL,
    transitioned_by TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (principal_key_id, key_version),
    FOREIGN KEY (principal_key_id)
        REFERENCES principal_keys (principal_key_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (length(transition_reason) BETWEEN 1 AND 2048),
    CHECK (length(transitioned_by) BETWEEN 1 AND 512)
);

CREATE TABLE principal_links (
    principal_link_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_key_id UUID NOT NULL,
    principal_id UUID NOT NULL,
    link_version BIGINT NOT NULL DEFAULT 1
        CHECK (link_version > 0),
    link_state TEXT NOT NULL
        CHECK (link_state IN ('pending', 'active', 'unlinked', 'tombstoned')),
    transition_kind TEXT NOT NULL
        CHECK (transition_kind IN (
            'initial-verification',
            'proof-both-identities',
            'maker-checker-recovery',
            'provider-lifecycle',
            'administrative-tombstone'
        )),
    transition_reason TEXT NOT NULL,
    transitioned_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (principal_key_id),
    UNIQUE (
        principal_link_id,
        link_version,
        principal_key_id,
        principal_id
    ),
    UNIQUE (principal_link_id, principal_key_id, principal_id),
    FOREIGN KEY (principal_key_id)
        REFERENCES principal_keys (principal_key_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (principal_id)
        REFERENCES principals (principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (principal_link_id <>
        '00000000-0000-0000-0000-000000000000'::UUID),
    CHECK (length(transition_reason) BETWEEN 1 AND 2048),
    CHECK (length(transitioned_by) BETWEEN 1 AND 512)
);

CREATE TABLE principal_link_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_link_id UUID NOT NULL,
    principal_key_id UUID NOT NULL,
    principal_id UUID NOT NULL,
    link_version BIGINT NOT NULL CHECK (link_version > 0),
    link_state TEXT NOT NULL
        CHECK (link_state IN ('pending', 'active', 'unlinked', 'tombstoned')),
    transition_kind TEXT NOT NULL,
    transition_reason TEXT NOT NULL,
    transitioned_by TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (principal_link_id, link_version),
    FOREIGN KEY (principal_link_id)
        REFERENCES principal_links (principal_link_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (event_id <> '00000000-0000-0000-0000-000000000000'::UUID),
    CHECK (transition_kind IN (
        'initial-verification',
        'proof-both-identities',
        'maker-checker-recovery',
        'provider-lifecycle',
        'administrative-tombstone'
    )),
    CHECK (length(transition_reason) BETWEEN 1 AND 2048),
    CHECK (length(transitioned_by) BETWEEN 1 AND 512)
);

CREATE TABLE principal_key_tombstones (
    key_tombstone_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_key_id UUID NOT NULL UNIQUE,
    provider_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    key_version BIGINT NOT NULL CHECK (key_version > 0),
    reason TEXT NOT NULL,
    tombstoned_by TEXT NOT NULL,
    tombstoned_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (provider_id, issuer, subject),
    FOREIGN KEY (
        principal_key_id,
        key_version,
        provider_id,
        issuer,
        subject
    ) REFERENCES principal_keys (
        principal_key_id,
        key_version,
        provider_id,
        issuer,
        subject
    )
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (key_tombstone_id <>
        '00000000-0000-0000-0000-000000000000'::UUID),
    CHECK (length(provider_id) BETWEEN 1 AND 64),
    CHECK (provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'),
    CHECK (length(issuer) BETWEEN 1 AND 2048),
    CHECK (length(subject) BETWEEN 1 AND 512),
    CHECK (length(reason) BETWEEN 1 AND 2048),
    CHECK (length(tombstoned_by) BETWEEN 1 AND 512)
);

-- Execution agents are principals too, but their stable authority identity is
-- deliberately unrelated to the operator-chosen agent_id label. Existing
-- agents receive fresh random UUIDs during this locked, non-overlap cutover.
ALTER TABLE agents
    ADD COLUMN principal_id UUID;

UPDATE agents
SET principal_id = gen_random_uuid();

INSERT INTO principals (
    principal_id,
    principal_kind,
    lifecycle_state,
    role_allowlist,
    site_authority_mode,
    site_scope,
    environment_authority_mode,
    environment_scope,
    created_by
)
SELECT
    agent.principal_id,
    'agent',
    CASE
        WHEN agent.status = 'revoked' THEN 'deprovisioned'
        ELSE 'active'
    END,
    ARRAY[]::TEXT[],
    'revoked',
    ARRAY[]::TEXT[],
    'revoked',
    ARRAY[]::TEXT[],
    'migration-199-agent-cutover'
FROM agents AS agent;

ALTER TABLE agents
    ALTER COLUMN principal_id SET NOT NULL,
    ADD CONSTRAINT agents_principal_id_key UNIQUE (principal_id),
    ADD CONSTRAINT agents_principal_id_fkey
        FOREIGN KEY (principal_id)
        REFERENCES principals (principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

COMMENT ON COLUMN agents.principal_id IS
    'Random stable agent principal UUID; never derived from the mutable agent_id label';

ALTER TABLE sessions
    DROP COLUMN user_id,
    DROP COLUMN provider,
    DROP COLUMN identity_issuer,
    DROP COLUMN identity_subject,
    DROP COLUMN identity_authority_epoch,
    DROP COLUMN human_authority_version,
    DROP COLUMN site_authority_mode,
    DROP COLUMN site_scope,
    DROP COLUMN environment_authority_mode,
    DROP COLUMN environment_scope,
    ADD COLUMN principal_id UUID NOT NULL,
    ADD COLUMN principal_lifecycle_version BIGINT NOT NULL,
    ADD COLUMN principal_authority_version BIGINT NOT NULL,
    ADD COLUMN principal_key_id UUID NOT NULL,
    ADD COLUMN principal_key_version BIGINT NOT NULL,
    ADD COLUMN principal_link_id UUID NOT NULL,
    ADD COLUMN principal_link_version BIGINT NOT NULL,
    ADD COLUMN site_authority_mode TEXT NOT NULL,
    ADD COLUMN site_scope TEXT[] NOT NULL,
    ADD COLUMN environment_authority_mode TEXT NOT NULL,
    ADD COLUMN environment_scope TEXT[] NOT NULL,
    ADD CONSTRAINT sessions_roles_canonical_check CHECK (
        human_authority_values_are_canonical(roles, 'role')
    ),
    ADD CONSTRAINT sessions_site_authority_shape_check CHECK (
        (site_authority_mode = 'global' AND cardinality(site_scope) = 0)
        OR (site_authority_mode = 'scoped'
            AND cardinality(site_scope) BETWEEN 1 AND 64)
    ),
    ADD CONSTRAINT sessions_environment_authority_shape_check CHECK (
        (environment_authority_mode = 'global'
            AND cardinality(environment_scope) = 0)
        OR (environment_authority_mode = 'scoped'
            AND cardinality(environment_scope) BETWEEN 1 AND 64)
    ),
    ADD CONSTRAINT sessions_site_scope_members_check CHECK (
        human_authority_values_are_canonical(site_scope, 'scope')
    ),
    ADD CONSTRAINT sessions_environment_scope_members_check CHECK (
        human_authority_values_are_canonical(environment_scope, 'scope')
    ),
    ADD CONSTRAINT sessions_principal_fk
        FOREIGN KEY (principal_id)
        REFERENCES principals (principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT sessions_exact_key_version_fk
        FOREIGN KEY (principal_key_id, principal_key_version)
        REFERENCES principal_key_versions (principal_key_id, key_version)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT sessions_exact_link_fk
        FOREIGN KEY (
            principal_link_id,
            principal_key_id,
            principal_id
        ) REFERENCES principal_links (
            principal_link_id,
            principal_key_id,
            principal_id
        ) ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE INDEX sessions_principal_binding_idx ON sessions (
    principal_id,
    principal_lifecycle_version,
    principal_authority_version,
    principal_key_id,
    principal_key_version,
    principal_link_id,
    principal_link_version
);

ALTER TABLE api_tokens RENAME COLUMN owner_principal TO legacy_owner_label;
ALTER TABLE api_tokens RENAME COLUMN issued_by_provider TO legacy_issued_by_provider;
ALTER TABLE api_tokens RENAME COLUMN issued_by_issuer TO legacy_issued_by_issuer;
ALTER TABLE api_tokens RENAME COLUMN issued_by_subject TO legacy_issued_by_subject;
ALTER TABLE api_tokens RENAME COLUMN issued_by_identity_epoch
    TO legacy_issued_by_identity_epoch;
ALTER TABLE api_tokens RENAME COLUMN issued_by_human_authority_version
    TO legacy_issued_by_human_authority_version;
ALTER TABLE api_tokens RENAME COLUMN issued_by_roles TO legacy_issued_by_roles;
ALTER TABLE api_tokens RENAME COLUMN issued_by_site_authority_mode
    TO legacy_issued_by_site_authority_mode;
ALTER TABLE api_tokens RENAME COLUMN issued_by_site_scope
    TO legacy_issued_by_site_scope;
ALTER TABLE api_tokens RENAME COLUMN issued_by_environment_authority_mode
    TO legacy_issued_by_environment_authority_mode;
ALTER TABLE api_tokens RENAME COLUMN issued_by_environment_scope
    TO legacy_issued_by_environment_scope;

ALTER TABLE api_tokens
    ALTER COLUMN legacy_owner_label DROP NOT NULL;

ALTER TABLE api_tokens
    ADD COLUMN issuing_principal_id UUID,
    ADD COLUMN issuing_principal_lifecycle_version BIGINT,
    ADD COLUMN issuing_principal_authority_version BIGINT,
    ADD COLUMN principal_key_id UUID,
    ADD COLUMN principal_key_version BIGINT,
    ADD COLUMN principal_link_id UUID,
    ADD COLUMN principal_link_version BIGINT,
    ADD CONSTRAINT api_tokens_principal_fk
        FOREIGN KEY (issuing_principal_id)
        REFERENCES principals (principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT api_tokens_exact_key_version_fk
        FOREIGN KEY (principal_key_id, principal_key_version)
        REFERENCES principal_key_versions (principal_key_id, key_version)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT api_tokens_exact_link_fk
        FOREIGN KEY (
            principal_link_id,
            principal_key_id,
            issuing_principal_id
        ) REFERENCES principal_links (
            principal_link_id,
            principal_key_id,
            principal_id
        ) ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT api_tokens_principal_binding_shape_check CHECK (
        (
            token_valid = FALSE
            AND issuing_principal_id IS NULL
            AND issuing_principal_lifecycle_version IS NULL
            AND issuing_principal_authority_version IS NULL
            AND principal_key_id IS NULL
            AND principal_key_version IS NULL
            AND principal_link_id IS NULL
            AND principal_link_version IS NULL
        )
        OR
        (
            issuing_principal_id IS NOT NULL
            AND issuing_principal_lifecycle_version > 0
            AND issuing_principal_authority_version > 0
            AND principal_key_id IS NOT NULL
            AND principal_key_version > 0
            AND principal_link_id IS NOT NULL
            AND principal_link_version > 0
            AND expires_at IS NOT NULL
            AND expires_at > created_at
            AND expires_at <= created_at + INTERVAL '24 hours'
        )
    ),
    ADD CONSTRAINT api_tokens_site_scope_canonical_check CHECK (
        site_scope IS NULL
        OR (
            site_scope <> ''
            AND array_to_string(
                string_to_array(site_scope, ','), ','
            ) = site_scope
            AND human_authority_values_are_canonical(
                string_to_array(site_scope, ','), 'scope'
            )
        )
    ),
    ADD CONSTRAINT api_tokens_environment_scope_canonical_check CHECK (
        environment_scope IS NULL
        OR (
            environment_scope <> ''
            AND array_to_string(
                string_to_array(environment_scope, ','), ','
            ) = environment_scope
            AND human_authority_values_are_canonical(
                string_to_array(environment_scope, ','), 'scope'
            )
        )
    );

CREATE INDEX api_tokens_principal_binding_idx ON api_tokens (
    issuing_principal_id,
    issuing_principal_lifecycle_version,
    issuing_principal_authority_version,
    principal_key_id,
    principal_key_version,
    principal_link_id,
    principal_link_version
);

-- Request ownership and approval actors are cut over without translating any
-- bare subject strings. Existing rows remain immutable quarantined evidence.
ALTER TABLE requests RENAME COLUMN created_by TO legacy_created_by_label;
ALTER TABLE requests RENAME COLUMN requester TO legacy_requester_label;
ALTER TABLE requests RENAME COLUMN owner TO legacy_owner_label;

ALTER TABLE requests
    ADD COLUMN principal_binding_state TEXT NOT NULL
        DEFAULT 'legacy-quarantined',
    ADD COLUMN created_by_principal_id UUID,
    ADD COLUMN requester_principal_id UUID,
    ADD COLUMN owner_principal_id UUID,
    ADD CONSTRAINT requests_principal_binding_state_check CHECK (
        principal_binding_state IN ('legacy-quarantined', 'exact-v1')
    ),
    ADD CONSTRAINT requests_principal_binding_shape_check CHECK (
        (
            principal_binding_state = 'legacy-quarantined'
            AND created_by_principal_id IS NULL
            AND requester_principal_id IS NULL
            AND owner_principal_id IS NULL
        )
        OR
        (
            principal_binding_state = 'exact-v1'
            AND created_by_principal_id IS NOT NULL
            AND requester_principal_id IS NOT NULL
            AND owner_principal_id IS NOT NULL
        )
    ),
    ADD CONSTRAINT requests_created_by_principal_fk
        FOREIGN KEY (created_by_principal_id)
        REFERENCES principals (principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT requests_requester_principal_fk
        FOREIGN KEY (requester_principal_id)
        REFERENCES principals (principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT requests_owner_principal_fk
        FOREIGN KEY (owner_principal_id)
        REFERENCES principals (principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE INDEX requests_requester_principal_idx
    ON requests (requester_principal_id, created_at DESC)
    WHERE principal_binding_state = 'exact-v1';
CREATE INDEX requests_owner_principal_idx
    ON requests (owner_principal_id, created_at DESC)
    WHERE principal_binding_state = 'exact-v1';

ALTER TABLE request_approval_decisions
    RENAME COLUMN actor TO legacy_actor_label;
ALTER TABLE request_approval_decisions
    ALTER COLUMN legacy_actor_label DROP NOT NULL,
    ADD COLUMN principal_binding_state TEXT NOT NULL
        DEFAULT 'legacy-quarantined',
    ADD COLUMN actor_principal_id UUID,
    ADD COLUMN actor_principal_lifecycle_version BIGINT,
    ADD COLUMN actor_principal_authority_version BIGINT,
    ADD CONSTRAINT request_approval_actor_binding_state_check CHECK (
        principal_binding_state IN ('legacy-quarantined', 'exact-v1')
    ),
    ADD CONSTRAINT request_approval_actor_binding_shape_check CHECK (
        (
            principal_binding_state = 'legacy-quarantined'
            AND actor_principal_id IS NULL
            AND actor_principal_lifecycle_version IS NULL
            AND actor_principal_authority_version IS NULL
        )
        OR
        (
            principal_binding_state = 'exact-v1'
            AND actor_principal_id IS NOT NULL
            AND actor_principal_lifecycle_version > 0
            AND actor_principal_authority_version > 0
        )
    ),
    ADD CONSTRAINT request_approval_actor_principal_fk
        FOREIGN KEY (actor_principal_id)
        REFERENCES principals (principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE INDEX request_approval_actor_principal_idx
    ON request_approval_decisions (
        actor_principal_id,
        actor_principal_lifecycle_version,
        actor_principal_authority_version,
        decided_at
    ) WHERE principal_binding_state = 'exact-v1';

-- Replace the request lifecycle functions before old replicas can touch the
-- renamed TEXT columns. Only opaque principal UUID columns remain authoritative.
CREATE OR REPLACE FUNCTION enforce_request_rework_approval_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    is_rework BOOLEAN;
    review_basis_changed BOOLEAN;
    has_current_decisions BOOLEAN;
    approved_role_count BIGINT;
    approved_actor_count BIGINT;
    has_current_rejection BOOLEAN;
    request_table_owner OID;
    enforce_runtime_contract BOOLEAN;
    transition_allowed BOOLEAN;
BEGIN
    SELECT relowner INTO request_table_owner
    FROM pg_catalog.pg_class
    WHERE oid = 'public.requests'::regclass;
    enforce_runtime_contract := request_table_owner IS NULL
        OR CURRENT_USER::regrole::oid <> request_table_owner
        OR COALESCE(
            current_setting('ryuki.force_request_runtime_contract', TRUE)
                = 'runtime-v1',
            FALSE
        );

    IF TG_OP = 'INSERT' THEN
        IF enforce_runtime_contract
           AND (
               NEW.status <> 'intake'
               OR NEW.stage <> 'intake'
               OR NEW.approval_epoch <> 1
           ) THEN
            RAISE EXCEPTION
                'new requests must enter canonical intake state at approval epoch 1'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.principal_binding_state IS DISTINCT FROM OLD.principal_binding_state
       OR NEW.created_by_principal_id IS DISTINCT FROM OLD.created_by_principal_id
       OR NEW.requester_principal_id IS DISTINCT FROM OLD.requester_principal_id
       OR NEW.legacy_created_by_label IS DISTINCT FROM OLD.legacy_created_by_label
       OR NEW.legacy_requester_label IS DISTINCT FROM OLD.legacy_requester_label THEN
        RAISE EXCEPTION 'request lifecycle and maker identity are immutable'
            USING ERRCODE = '23514';
    END IF;

    is_rework := OLD.status IN ('validated', 'planned', 'approved', 'locked')
                 AND NEW.status = 'intake';
    IF is_rework THEN
        IF NEW.approval_epoch = OLD.approval_epoch THEN
            NEW.approval_epoch := OLD.approval_epoch + 1;
        ELSIF NEW.approval_epoch <> OLD.approval_epoch + 1 THEN
            RAISE EXCEPTION 'rework must advance approval_epoch exactly once'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.approval_epoch <> OLD.approval_epoch THEN
        RAISE EXCEPTION 'approval_epoch may change only during rework'
            USING ERRCODE = '23514';
    END IF;

    review_basis_changed := ROW(
        NEW.request_type,
        NEW.site,
        NEW.environment,
        NEW.name,
        NEW.cpu,
        NEW.memory_gb,
        NEW.justification,
        NEW.payload,
        NEW.plan,
        NEW.validation_results,
        NEW.criticality,
        NEW.required_approval_roles,
        NEW.created_by_principal_id,
        NEW.requester_principal_id,
        NEW.owner_principal_id,
        NEW.evidence_manifest_id
    ) IS DISTINCT FROM ROW(
        OLD.request_type,
        OLD.site,
        OLD.environment,
        OLD.name,
        OLD.cpu,
        OLD.memory_gb,
        OLD.justification,
        OLD.payload,
        OLD.plan,
        OLD.validation_results,
        OLD.criticality,
        OLD.required_approval_roles,
        OLD.created_by_principal_id,
        OLD.requester_principal_id,
        OLD.owner_principal_id,
        OLD.evidence_manifest_id
    );
    IF review_basis_changed AND NOT is_rework THEN
        IF OLD.status IN ('planned', 'approved', 'locked') THEN
            RAISE EXCEPTION
                'reviewed request authority is immutable until rework'
                USING ERRCODE = '23514';
        END IF;
        SELECT EXISTS (
            SELECT 1 FROM request_approval_decisions AS decision
            WHERE decision.request_id = OLD.id
              AND decision.approval_epoch = OLD.approval_epoch
        ) INTO has_current_decisions;
        IF has_current_decisions THEN
            RAISE EXCEPTION
                'reviewed request authority is immutable until rework'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NEW.status = 'planned'
       AND NEW.status IS DISTINCT FROM OLD.status
       AND NEW.required_approval_roles > 2 THEN
        RAISE EXCEPTION
            'planned requests may require at most two canonical approval roles'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.status IS DISTINCT FROM OLD.status
       AND NEW.status IN ('approved', 'locked') THEN
        IF NEW.status = 'approved' AND OLD.status <> 'planned' THEN
            RAISE EXCEPTION 'approved state may be entered only from planned'
                USING ERRCODE = '23514';
        ELSIF NEW.status = 'locked' AND OLD.status <> 'approved' THEN
            RAISE EXCEPTION 'locked state may be entered only from approved'
                USING ERRCODE = '23514';
        END IF;

        SELECT
            COUNT(DISTINCT decision.role) FILTER (
                WHERE decision.decision = 'approved'
                  AND decision.role IN ('DatacenterApprover', 'PlatformAdmin')
                  AND actor.lifecycle_state = 'active'
                  AND decision.role = ANY(actor.role_allowlist)
            ),
            COUNT(DISTINCT decision.actor_principal_id) FILTER (
                WHERE decision.decision = 'approved'
                  AND decision.role IN ('DatacenterApprover', 'PlatformAdmin')
                  AND actor.lifecycle_state = 'active'
                  AND decision.role = ANY(actor.role_allowlist)
            ),
            COALESCE(BOOL_OR(decision.decision = 'rejected'), FALSE)
        INTO approved_role_count, approved_actor_count, has_current_rejection
        FROM request_approval_decisions AS decision
        LEFT JOIN principals AS actor
          ON actor.principal_id = decision.actor_principal_id
         AND actor.lifecycle_version =
             decision.actor_principal_lifecycle_version
         AND actor.authority_version =
             decision.actor_principal_authority_version
         AND actor.principal_kind = 'human'
        WHERE decision.request_id = OLD.id
          AND decision.approval_epoch = OLD.approval_epoch
          AND decision.principal_binding_state = 'exact-v1'
          AND decision.actor_principal_id <> OLD.requester_principal_id;

        IF has_current_rejection
           OR approved_role_count < NEW.required_approval_roles
           OR approved_actor_count < NEW.required_approval_roles THEN
            RAISE EXCEPTION
                'approved or locked state requires current exact-principal quorum'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF enforce_runtime_contract
       AND NEW.status IS DISTINCT FROM OLD.status THEN
        transition_allowed := CASE OLD.status
            WHEN 'draft' THEN
                NEW.status IN ('intake', 'validated', 'failed', 'cancelled')
            WHEN 'intake' THEN
                NEW.status IN ('validated', 'failed', 'cancelled')
            WHEN 'validated' THEN
                NEW.status IN ('planned', 'intake', 'failed', 'cancelled')
            WHEN 'planned' THEN
                NEW.status IN (
                    'approved', 'rejected', 'intake', 'failed', 'cancelled'
                )
            WHEN 'approved' THEN
                NEW.status IN ('locked', 'intake', 'failed', 'cancelled')
            WHEN 'locked' THEN
                NEW.status IN ('executing', 'intake', 'failed', 'cancelled')
            WHEN 'executing' THEN NEW.status IN ('verifying', 'failed')
            WHEN 'executed' THEN NEW.status IN ('verifying', 'failed')
            WHEN 'verifying' THEN NEW.status IN ('completed', 'failed')
            WHEN 'verified' THEN NEW.status IN ('completed', 'failed')
            WHEN 'completed' THEN NEW.status = 'protecting'
            WHEN 'protecting' THEN NEW.status = 'operational'
            WHEN 'operational' THEN NEW.status = 'retired'
            ELSE FALSE
        END;
        IF NOT transition_allowed THEN
            RAISE EXCEPTION 'invalid request lifecycle transition from % to %',
                OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_current_request_approval_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_epoch BIGINT;
    current_status TEXT;
    request_table_owner OID;
    enforce_runtime_contract BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'approval decision evidence is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.decision NOT IN ('approved', 'rejected')
       OR NEW.role NOT IN ('DatacenterApprover', 'PlatformAdmin')
       OR NULLIF(BTRIM(NEW.role), '') IS NULL
       OR NEW.role <> BTRIM(NEW.role)
       OR char_length(NEW.role) > 255
       OR NEW.principal_binding_state <> 'exact-v1'
       OR NEW.actor_principal_id IS NULL
       OR (NEW.decision = 'approved' AND NEW.reason IS NOT NULL)
       OR (
           NEW.decision = 'rejected'
           AND (
               NULLIF(BTRIM(NEW.reason), '') IS NULL
               OR NEW.reason <> BTRIM(NEW.reason)
           )
       ) THEN
        RAISE EXCEPTION 'approval decision evidence has invalid canonical shape'
            USING ERRCODE = '23514';
    END IF;
    NEW.decided_at := statement_timestamp();

    SELECT approval_epoch, status
    INTO current_epoch, current_status
    FROM requests
    WHERE id = NEW.request_id
    FOR UPDATE;
    IF current_epoch IS NULL
       OR NEW.approval_epoch IS NULL
       OR NEW.approval_epoch <> current_epoch THEN
        RAISE EXCEPTION 'approval decision epoch is not current'
            USING ERRCODE = '23514';
    END IF;

    SELECT relowner INTO request_table_owner
    FROM pg_catalog.pg_class
    WHERE oid = 'public.requests'::regclass;
    enforce_runtime_contract := request_table_owner IS NULL
        OR CURRENT_USER::regrole::oid <> request_table_owner
        OR COALESCE(
            current_setting('ryuki.force_request_runtime_contract', TRUE)
                = 'runtime-v1',
            FALSE
        );
    IF enforce_runtime_contract
       AND (
           (NEW.decision = 'approved' AND current_status <> 'planned')
           OR (NEW.decision = 'rejected' AND current_status <> 'rejected')
       ) THEN
        RAISE EXCEPTION
            'approval decisions must follow canonical request decision order'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION principal_registry_advisory_lock_is_held(lock_key BIGINT)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT EXISTS (
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
          AND held.classid::BIGINT = ((lock_key >> 32) & 4294967295)
          AND held.objid::BIGINT = (lock_key & 4294967295)
          AND held.objsubid = 1
          AND held.granted
    );
$$;

CREATE FUNCTION principal_registry_provider_lock_key(key_provider TEXT)
RETURNS BIGINT
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT human_authority_lock_key(
        key_provider,
        'ryuki-provider-tombstone-v1',
        'ryuki-provider-tombstone-v1'
    );
$$;

CREATE FUNCTION principal_registry_writer_contract_is_held(
    key_provider TEXT,
    key_issuer TEXT,
    key_subject TEXT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT COALESCE(
               current_setting(
                   'ryuki.principal_registry_writer_contract', TRUE
               ) = '1',
               FALSE
           )
       AND principal_registry_advisory_lock_is_held(
               principal_registry_provider_lock_key(key_provider)
           )
       AND principal_registry_advisory_lock_is_held(
               human_authority_lock_key(
                   key_provider,
                   key_issuer,
                   key_subject
               )
           );
$$;

CREATE FUNCTION reject_principal_registry_evidence_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'principal registry evidence is append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER legacy_identity_authority_evidence_immutable
BEFORE INSERT OR UPDATE OR DELETE ON legacy_identity_authority_evidence
FOR EACH ROW EXECUTE FUNCTION reject_principal_registry_evidence_mutation();
CREATE TRIGGER legacy_identity_authority_evidence_no_truncate
BEFORE TRUNCATE ON legacy_identity_authority_evidence
FOR EACH STATEMENT EXECUTE FUNCTION reject_principal_registry_evidence_mutation();
CREATE TRIGGER legacy_human_authority_evidence_immutable
BEFORE INSERT OR UPDATE OR DELETE ON legacy_human_authority_evidence
FOR EACH ROW EXECUTE FUNCTION reject_principal_registry_evidence_mutation();
CREATE TRIGGER legacy_human_authority_evidence_no_truncate
BEFORE TRUNCATE ON legacy_human_authority_evidence
FOR EACH STATEMENT EXECUTE FUNCTION reject_principal_registry_evidence_mutation();

CREATE FUNCTION enforce_principal_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    lifecycle_changed BOOLEAN;
    authority_changed BOOLEAN;
    transition_allowed BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.lifecycle_state <> 'active' THEN
            RAISE EXCEPTION 'new principal must enter active lifecycle state'
                USING ERRCODE = '23514';
        END IF;
        NEW.lifecycle_version := 1;
        NEW.authority_version := 1;
        NEW.created_at := statement_timestamp();
        NEW.updated_at := NEW.created_at;
        NEW.tombstoned_at := NULL;
        RETURN NEW;
    END IF;

    IF NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.principal_kind IS DISTINCT FROM OLD.principal_kind
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'principal identity and provenance are immutable'
            USING ERRCODE = '23514';
    END IF;

    lifecycle_changed := NEW.lifecycle_state IS DISTINCT FROM OLD.lifecycle_state;
    authority_changed := ROW(
        NEW.role_allowlist,
        NEW.site_authority_mode,
        NEW.site_scope,
        NEW.environment_authority_mode,
        NEW.environment_scope
    ) IS DISTINCT FROM ROW(
        OLD.role_allowlist,
        OLD.site_authority_mode,
        OLD.site_scope,
        OLD.environment_authority_mode,
        OLD.environment_scope
    ) OR (
        pg_trigger_depth() > 1
        AND NEW.authority_version = OLD.authority_version + 1
    );

    transition_allowed := CASE OLD.lifecycle_state
        WHEN 'active' THEN NEW.lifecycle_state IN (
            'active', 'suspended', 'deprovisioned', 'tombstoned'
        )
        WHEN 'suspended' THEN NEW.lifecycle_state IN (
            'suspended', 'active', 'deprovisioned', 'tombstoned'
        )
        WHEN 'deprovisioned' THEN NEW.lifecycle_state IN (
            'deprovisioned', 'tombstoned'
        )
        WHEN 'tombstoned' THEN NEW.lifecycle_state = 'tombstoned'
        ELSE FALSE
    END;
    IF NOT transition_allowed THEN
        RAISE EXCEPTION 'invalid or terminal principal lifecycle transition'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.lifecycle_version <> OLD.lifecycle_version
            + CASE WHEN lifecycle_changed THEN 1 ELSE 0 END
       OR NEW.authority_version <> OLD.authority_version
            + CASE WHEN authority_changed THEN 1 ELSE 0 END THEN
        RAISE EXCEPTION 'principal lifecycle and authority versions must advance exactly once'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.tombstoned_at IS DISTINCT FROM OLD.tombstoned_at THEN
        IF NOT (lifecycle_changed AND NEW.lifecycle_state = 'tombstoned') THEN
            RAISE EXCEPTION 'principal tombstone time is database-managed'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF lifecycle_changed AND NEW.lifecycle_state = 'tombstoned' THEN
        NEW.tombstoned_at := statement_timestamp();
    ELSE
        NEW.tombstoned_at := OLD.tombstoned_at;
    END IF;

    IF lifecycle_changed OR authority_changed THEN
        DELETE FROM public.sessions
        WHERE principal_id = OLD.principal_id;
        DELETE FROM public.idempotency_records
        WHERE user_scope = OLD.principal_id::TEXT;
        UPDATE public.api_tokens
        SET token_valid = FALSE,
            revoked_at = COALESCE(revoked_at, statement_timestamp())
        WHERE issuing_principal_id = OLD.principal_id
          AND token_valid;
        NEW.updated_at := statement_timestamp();
    ELSE
        NEW.updated_at := OLD.updated_at;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER principals_lifecycle_guard
BEFORE INSERT OR UPDATE ON principals
FOR EACH ROW EXECUTE FUNCTION enforce_principal_lifecycle();

CREATE FUNCTION enforce_agent_principal_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    bound_principal_id UUID;
    principal_record public.principals%ROWTYPE;
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.principal_id IS DISTINCT FROM OLD.principal_id THEN
        RAISE EXCEPTION 'agent principal binding is immutable'
            USING ERRCODE = '23514';
    END IF;

    bound_principal_id := CASE
        WHEN TG_OP = 'DELETE' THEN OLD.principal_id
        ELSE NEW.principal_id
    END;

    SELECT * INTO principal_record
    FROM public.principals
    WHERE principal_id = bound_principal_id
    FOR UPDATE;
    IF NOT FOUND OR principal_record.principal_kind <> 'agent' THEN
        RAISE EXCEPTION 'agent requires an exact agent principal binding'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND NEW.status = 'revoked') THEN
        IF principal_record.lifecycle_state IN ('active', 'suspended') THEN
            UPDATE public.principals
            SET lifecycle_state = 'deprovisioned',
                lifecycle_version = lifecycle_version + 1,
                authority_version = authority_version + 1,
                role_allowlist = ARRAY[]::TEXT[],
                site_authority_mode = 'revoked',
                site_scope = ARRAY[]::TEXT[],
                environment_authority_mode = 'revoked',
                environment_scope = ARRAY[]::TEXT[]
            WHERE principal_id = bound_principal_id;
        ELSIF principal_record.lifecycle_state NOT IN (
            'deprovisioned', 'tombstoned'
        ) THEN
            RAISE EXCEPTION 'agent principal lifecycle cannot be deprovisioned'
                USING ERRCODE = '23514';
        END IF;
    ELSIF principal_record.lifecycle_state <> 'active'
          OR cardinality(principal_record.role_allowlist) <> 0
          OR principal_record.site_authority_mode <> 'revoked'
          OR cardinality(principal_record.site_scope) <> 0
          OR principal_record.environment_authority_mode <> 'revoked'
          OR cardinality(principal_record.environment_scope) <> 0 THEN
        RAISE EXCEPTION 'active agent requires empty interactive authority'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agents_principal_binding_guard
BEFORE INSERT OR UPDATE OR DELETE ON agents
FOR EACH ROW EXECUTE FUNCTION enforce_agent_principal_binding();

CREATE FUNCTION enforce_principal_provider_tombstone()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF current_setting(
           'ryuki.principal_registry_writer_contract', TRUE
       ) IS DISTINCT FROM '1'
       OR NOT principal_registry_advisory_lock_is_held(
           principal_registry_provider_lock_key(NEW.provider_id)
       ) THEN
        RAISE EXCEPTION 'principal registry provider writer contract v1 is required'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.principal_keys
        WHERE provider_id = NEW.provider_id
          AND key_state = 'active'
    ) THEN
        RAISE EXCEPTION 'provider keys must be tombstoned before provider removal'
            USING ERRCODE = '23514';
    END IF;
    NEW.tombstone_version := 1;
    NEW.tombstoned_at := statement_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER principal_provider_tombstone_insert_guard
BEFORE INSERT ON principal_provider_tombstones
FOR EACH ROW EXECUTE FUNCTION enforce_principal_provider_tombstone();

CREATE FUNCTION enforce_principal_key_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    contract_provider TEXT;
    contract_issuer TEXT;
    contract_subject TEXT;
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
        IF NEW.authority_digest IS NOT DISTINCT FROM OLD.authority_digest THEN
            RAISE EXCEPTION
                'active principal key rotation requires a changed authority digest'
                USING ERRCODE = '23514';
        END IF;
        NEW.tombstoned_at := NULL;
    ELSIF NEW.key_state = 'tombstoned' THEN
        IF NEW.authority_digest IS DISTINCT FROM OLD.authority_digest THEN
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

CREATE TRIGGER principal_keys_lifecycle_guard
BEFORE INSERT OR UPDATE ON principal_keys
FOR EACH ROW EXECUTE FUNCTION enforce_principal_key_lifecycle();

CREATE FUNCTION append_principal_key_version()
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
        NEW.authority_digest,
        NEW.key_state,
        NEW.transition_reason,
        NEW.transitioned_by,
        NEW.updated_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER principal_keys_append_version
AFTER INSERT OR UPDATE ON principal_keys
FOR EACH ROW EXECUTE FUNCTION append_principal_key_version();

CREATE FUNCTION record_principal_key_tombstone()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO public.principal_key_tombstones (
        key_tombstone_id,
        principal_key_id,
        provider_id,
        issuer,
        subject,
        key_version,
        reason,
        tombstoned_by,
        tombstoned_at
    ) VALUES (
        gen_random_uuid(),
        NEW.principal_key_id,
        NEW.provider_id,
        NEW.issuer,
        NEW.subject,
        NEW.key_version,
        NEW.transition_reason,
        NEW.transitioned_by,
        NEW.tombstoned_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER principal_keys_tombstone_evidence
AFTER UPDATE OF key_state ON principal_keys
FOR EACH ROW
WHEN (NEW.key_state = 'tombstoned' AND OLD.key_state <> 'tombstoned')
EXECUTE FUNCTION record_principal_key_tombstone();

CREATE FUNCTION enforce_principal_link_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    key_record public.principal_keys%ROWTYPE;
    principal_record public.principals%ROWTYPE;
    transition_allowed BOOLEAN;
BEGIN
    SELECT * INTO key_record
    FROM public.principal_keys
    WHERE principal_key_id = NEW.principal_key_id
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'principal link key does not exist'
            USING ERRCODE = '23503';
    END IF;
    IF NOT principal_registry_writer_contract_is_held(
        key_record.provider_id,
        key_record.issuer,
        key_record.subject
    ) THEN
        RAISE EXCEPTION 'principal registry writer contract v1 is required'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.link_state <> 'pending'
           OR NEW.transition_kind <> 'initial-verification'
           OR key_record.key_state <> 'active'
           OR EXISTS (
               SELECT 1 FROM public.principal_provider_tombstones
               WHERE provider_id = key_record.provider_id
           ) THEN
            RAISE EXCEPTION 'new principal link must enter verified pending state'
                USING ERRCODE = '23514';
        END IF;
        SELECT * INTO principal_record
        FROM public.principals
        WHERE principal_id = NEW.principal_id
        FOR SHARE;
        IF NOT FOUND OR principal_record.lifecycle_state <> 'active' THEN
            RAISE EXCEPTION 'new principal link requires an active principal'
                USING ERRCODE = '23514';
        END IF;
        NEW.link_version := 1;
        NEW.created_at := statement_timestamp();
        NEW.updated_at := NEW.created_at;
        UPDATE public.principals
        SET authority_version = authority_version + 1
        WHERE principal_id = NEW.principal_id;
        DELETE FROM public.idempotency_records
        WHERE user_scope = NEW.principal_id::TEXT;
        RETURN NEW;
    END IF;

    IF ROW(
        NEW.principal_link_id,
        NEW.principal_key_id,
        NEW.principal_id,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.principal_link_id,
        OLD.principal_key_id,
        OLD.principal_id,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'principal link identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    transition_allowed := CASE OLD.link_state
        WHEN 'pending' THEN NEW.link_state IN ('active', 'unlinked', 'tombstoned')
        WHEN 'active' THEN NEW.link_state IN ('unlinked', 'tombstoned')
        WHEN 'unlinked' THEN NEW.link_state IN ('active', 'tombstoned')
        WHEN 'tombstoned' THEN FALSE
        ELSE FALSE
    END;
    IF NOT transition_allowed
       OR NEW.link_version <> OLD.link_version + 1 THEN
        RAISE EXCEPTION 'principal link transition is invalid, terminal, or not versioned'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.link_state = 'active' THEN
        IF OLD.link_state = 'unlinked'
           AND NEW.transition_kind NOT IN (
               'proof-both-identities', 'maker-checker-recovery'
           ) THEN
            RAISE EXCEPTION 'relink requires dual proof or maker-checker recovery'
                USING ERRCODE = '23514';
        END IF;
        IF key_record.key_state <> 'active' THEN
            RAISE EXCEPTION 'active principal link requires an active key'
                USING ERRCODE = '23514';
        END IF;
        SELECT * INTO principal_record
        FROM public.principals
        WHERE principal_id = NEW.principal_id
        FOR SHARE;
        IF NOT FOUND OR principal_record.lifecycle_state <> 'active' THEN
            RAISE EXCEPTION 'active principal link requires an active principal'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    NEW.updated_at := statement_timestamp();
    UPDATE public.principals
    SET authority_version = authority_version + 1
    WHERE principal_id = OLD.principal_id;
    DELETE FROM public.idempotency_records
    WHERE user_scope = OLD.principal_id::TEXT;
    DELETE FROM public.sessions
    WHERE principal_link_id = OLD.principal_link_id;
    UPDATE public.api_tokens
    SET token_valid = FALSE,
        revoked_at = COALESCE(revoked_at, statement_timestamp())
    WHERE principal_link_id = OLD.principal_link_id
      AND token_valid;
    RETURN NEW;
END;
$$;

CREATE TRIGGER principal_links_lifecycle_guard
BEFORE INSERT OR UPDATE ON principal_links
FOR EACH ROW EXECUTE FUNCTION enforce_principal_link_lifecycle();

CREATE FUNCTION append_principal_link_event()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO public.principal_link_events (
        event_id,
        principal_link_id,
        principal_key_id,
        principal_id,
        link_version,
        link_state,
        transition_kind,
        transition_reason,
        transitioned_by,
        occurred_at
    ) VALUES (
        gen_random_uuid(),
        NEW.principal_link_id,
        NEW.principal_key_id,
        NEW.principal_id,
        NEW.link_version,
        NEW.link_state,
        NEW.transition_kind,
        NEW.transition_reason,
        NEW.transitioned_by,
        NEW.updated_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER principal_links_append_event
AFTER INSERT OR UPDATE ON principal_links
FOR EACH ROW EXECUTE FUNCTION append_principal_link_event();

CREATE FUNCTION enforce_principal_bound_session()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    key_record public.principal_keys%ROWTYPE;
    link_record public.principal_links%ROWTYPE;
    principal_record public.principals%ROWTYPE;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'sessions are immutable; revoke and reissue'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO key_record
    FROM public.principal_keys
    WHERE principal_key_id = NEW.principal_key_id
      AND key_version = NEW.principal_key_version
    FOR SHARE;
    IF NOT FOUND OR key_record.key_state <> 'active'
       OR NOT principal_registry_writer_contract_is_held(
           key_record.provider_id,
           key_record.issuer,
           key_record.subject
       ) THEN
        RAISE EXCEPTION 'session requires the exact active key and writer contract'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO link_record
    FROM public.principal_links
    WHERE principal_link_id = NEW.principal_link_id
      AND link_version = NEW.principal_link_version
      AND principal_key_id = NEW.principal_key_id
      AND principal_id = NEW.principal_id
    FOR SHARE;
    IF NOT FOUND OR link_record.link_state <> 'active' THEN
        RAISE EXCEPTION 'session requires the exact active principal link'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO principal_record
    FROM public.principals
    WHERE principal_id = NEW.principal_id
      AND lifecycle_version = NEW.principal_lifecycle_version
      AND authority_version = NEW.principal_authority_version
    FOR SHARE;
    IF NOT FOUND
       OR principal_record.lifecycle_state <> 'active'
       OR principal_record.principal_kind <> 'human' THEN
        RAISE EXCEPTION 'session requires the exact active principal authority'
            USING ERRCODE = '23514';
    END IF;
    IF cardinality(NEW.roles) = 0
       OR NOT (NEW.roles <@ principal_record.role_allowlist) THEN
        RAISE EXCEPTION 'session roles exceed principal authority'
            USING ERRCODE = '23514';
    END IF;
    IF principal_record.site_authority_mode = 'scoped'
       AND (
           NEW.site_authority_mode <> 'scoped'
           OR NOT (NEW.site_scope <@ principal_record.site_scope)
       ) THEN
        RAISE EXCEPTION 'session site scope exceeds principal authority'
            USING ERRCODE = '23514';
    END IF;
    IF principal_record.environment_authority_mode = 'scoped'
       AND (
           NEW.environment_authority_mode <> 'scoped'
           OR NOT (NEW.environment_scope <@ principal_record.environment_scope)
       ) THEN
        RAISE EXCEPTION 'session environment scope exceeds principal authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sessions_principal_binding_guard
BEFORE INSERT OR UPDATE ON sessions
FOR EACH ROW EXECUTE FUNCTION enforce_principal_bound_session();

CREATE FUNCTION enforce_principal_bound_api_token()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    key_record public.principal_keys%ROWTYPE;
    link_record public.principal_links%ROWTYPE;
    principal_record public.principals%ROWTYPE;
    token_site_scope TEXT[];
    token_environment_scope TEXT[];
BEGIN
    IF NEW.revoked_at IS NOT NULL AND NEW.token_valid THEN
        RAISE EXCEPTION 'revoked API token must be invalid'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.revoked_at > statement_timestamp() THEN
        RAISE EXCEPTION 'API token revocation time may not be in the future'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF ROW(
            NEW.id,
            NEW.name,
            NEW.token_hash,
            NEW.created_at,
            NEW.expires_at,
            NEW.roles,
            NEW.site_scope,
            NEW.environment_scope,
            NEW.issuing_principal_id,
            NEW.issuing_principal_lifecycle_version,
            NEW.issuing_principal_authority_version,
            NEW.principal_key_id,
            NEW.principal_key_version,
            NEW.principal_link_id,
            NEW.principal_link_version,
            NEW.legacy_owner_label,
            NEW.legacy_issued_by_provider,
            NEW.legacy_issued_by_issuer,
            NEW.legacy_issued_by_subject,
            NEW.legacy_issued_by_identity_epoch,
            NEW.legacy_issued_by_human_authority_version,
            NEW.legacy_issued_by_roles,
            NEW.legacy_issued_by_site_authority_mode,
            NEW.legacy_issued_by_site_scope,
            NEW.legacy_issued_by_environment_authority_mode,
            NEW.legacy_issued_by_environment_scope
        ) IS DISTINCT FROM ROW(
            OLD.id,
            OLD.name,
            OLD.token_hash,
            OLD.created_at,
            OLD.expires_at,
            OLD.roles,
            OLD.site_scope,
            OLD.environment_scope,
            OLD.issuing_principal_id,
            OLD.issuing_principal_lifecycle_version,
            OLD.issuing_principal_authority_version,
            OLD.principal_key_id,
            OLD.principal_key_version,
            OLD.principal_link_id,
            OLD.principal_link_version,
            OLD.legacy_owner_label,
            OLD.legacy_issued_by_provider,
            OLD.legacy_issued_by_issuer,
            OLD.legacy_issued_by_subject,
            OLD.legacy_issued_by_identity_epoch,
            OLD.legacy_issued_by_human_authority_version,
            OLD.legacy_issued_by_roles,
            OLD.legacy_issued_by_site_authority_mode,
            OLD.legacy_issued_by_site_scope,
            OLD.legacy_issued_by_environment_authority_mode,
            OLD.legacy_issued_by_environment_scope
        ) THEN
            RAISE EXCEPTION 'API token credential and principal binding are immutable'
                USING ERRCODE = '23514';
        END IF;
        IF NOT OLD.token_valid AND NEW.token_valid THEN
            RAISE EXCEPTION 'invalid API token may not be reactivated'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.revoked_at IS NOT NULL
           AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
            RAISE EXCEPTION 'API token revocation is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.token_valid AND NOT NEW.token_valid THEN
            IF NEW.revoked_at IS NULL THEN
                RAISE EXCEPTION 'API token invalidation requires revocation evidence'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.legacy_owner_label IS NOT NULL
       OR NEW.legacy_issued_by_provider IS NOT NULL
       OR NEW.legacy_issued_by_issuer IS NOT NULL
       OR NEW.legacy_issued_by_subject IS NOT NULL
       OR NEW.legacy_issued_by_identity_epoch IS NOT NULL
       OR NEW.legacy_issued_by_human_authority_version IS NOT NULL
       OR NEW.legacy_issued_by_site_authority_mode IS NOT NULL
       OR NEW.legacy_issued_by_environment_authority_mode IS NOT NULL
       OR cardinality(NEW.legacy_issued_by_roles) <> 0
       OR cardinality(NEW.legacy_issued_by_site_scope) <> 0
       OR cardinality(NEW.legacy_issued_by_environment_scope) <> 0 THEN
        RAISE EXCEPTION 'new API token may not carry legacy identity evidence'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.issuing_principal_id IS NULL
       OR NEW.principal_key_id IS NULL
       OR NEW.principal_link_id IS NULL THEN
        RAISE EXCEPTION 'new API token requires exact principal, key, and link UUIDs'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO key_record
    FROM public.principal_keys
    WHERE principal_key_id = NEW.principal_key_id
      AND key_version = NEW.principal_key_version
    FOR SHARE;
    IF NOT FOUND OR key_record.key_state <> 'active'
       OR NOT principal_registry_writer_contract_is_held(
           key_record.provider_id,
           key_record.issuer,
           key_record.subject
       ) THEN
        RAISE EXCEPTION 'API token requires exact active key and writer contract'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO link_record
    FROM public.principal_links
    WHERE principal_link_id = NEW.principal_link_id
      AND link_version = NEW.principal_link_version
      AND principal_key_id = NEW.principal_key_id
      AND principal_id = NEW.issuing_principal_id
    FOR SHARE;
    IF NOT FOUND OR link_record.link_state <> 'active' THEN
        RAISE EXCEPTION 'API token requires the exact active principal link'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO principal_record
    FROM public.principals
    WHERE principal_id = NEW.issuing_principal_id
      AND lifecycle_version = NEW.issuing_principal_lifecycle_version
      AND authority_version = NEW.issuing_principal_authority_version
    FOR SHARE;
    IF NOT FOUND
       OR principal_record.lifecycle_state <> 'active'
       OR principal_record.principal_kind <> 'human' THEN
        RAISE EXCEPTION 'API token requires exact active principal authority'
            USING ERRCODE = '23514';
    END IF;
    IF cardinality(NEW.roles) = 0
       OR NOT (NEW.roles <@ principal_record.role_allowlist) THEN
        RAISE EXCEPTION 'API token roles exceed principal authority'
            USING ERRCODE = '23514';
    END IF;

    token_site_scope := CASE WHEN NEW.site_scope IS NULL
        THEN ARRAY[]::TEXT[] ELSE string_to_array(NEW.site_scope, ',') END;
    token_environment_scope := CASE WHEN NEW.environment_scope IS NULL
        THEN ARRAY[]::TEXT[] ELSE string_to_array(NEW.environment_scope, ',') END;
    IF principal_record.site_authority_mode = 'scoped'
       AND (NEW.site_scope IS NULL
            OR NOT (token_site_scope <@ principal_record.site_scope)) THEN
        RAISE EXCEPTION 'API token site scope exceeds principal authority'
            USING ERRCODE = '23514';
    END IF;
    IF principal_record.environment_authority_mode = 'scoped'
       AND (NEW.environment_scope IS NULL
            OR NOT (token_environment_scope <@ principal_record.environment_scope)) THEN
        RAISE EXCEPTION 'API token environment scope exceeds principal authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER api_tokens_principal_binding_guard
BEFORE INSERT OR UPDATE OF
    id,
    name,
    token_hash,
    created_at,
    expires_at,
    roles,
    site_scope,
    environment_scope,
    token_valid,
    revoked_at,
    issuing_principal_id,
    issuing_principal_lifecycle_version,
    issuing_principal_authority_version,
    principal_key_id,
    principal_key_version,
    principal_link_id,
    principal_link_version,
    legacy_owner_label,
    legacy_issued_by_provider,
    legacy_issued_by_issuer,
    legacy_issued_by_subject,
    legacy_issued_by_identity_epoch,
    legacy_issued_by_human_authority_version,
    legacy_issued_by_roles,
    legacy_issued_by_site_authority_mode,
    legacy_issued_by_site_scope,
    legacy_issued_by_environment_authority_mode,
    legacy_issued_by_environment_scope
ON api_tokens
FOR EACH ROW EXECUTE FUNCTION enforce_principal_bound_api_token();

CREATE FUNCTION enforce_request_principal_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.principal_binding_state <> 'exact-v1'
           OR NEW.created_by_principal_id IS NULL
           OR NEW.requester_principal_id IS NULL
           OR NEW.owner_principal_id IS NULL
           OR NEW.legacy_created_by_label IS NOT NULL
           OR NEW.legacy_requester_label IS NOT NULL
           OR NEW.legacy_owner_label IS NOT NULL THEN
            RAISE EXCEPTION 'new request requires exact opaque principal bindings'
                USING ERRCODE = '23514';
        END IF;
        IF EXISTS (
            SELECT requested.principal_id
            FROM unnest(ARRAY[
                NEW.created_by_principal_id,
                NEW.requester_principal_id,
                NEW.owner_principal_id
            ]) AS requested(principal_id)
            WHERE NOT EXISTS (
                SELECT 1 FROM principals AS principal
                WHERE principal.principal_id = requested.principal_id
                  AND principal.lifecycle_state = 'active'
            )
        ) THEN
            RAISE EXCEPTION 'new request principal binding is not active'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.principal_binding_state = 'legacy-quarantined' THEN
        RAISE EXCEPTION 'legacy request identity is quarantined and immutable'
            USING ERRCODE = '55000';
    END IF;
    IF ROW(
        NEW.principal_binding_state,
        NEW.created_by_principal_id,
        NEW.requester_principal_id,
        NEW.owner_principal_id,
        NEW.legacy_created_by_label,
        NEW.legacy_requester_label,
        NEW.legacy_owner_label
    ) IS DISTINCT FROM ROW(
        OLD.principal_binding_state,
        OLD.created_by_principal_id,
        OLD.requester_principal_id,
        OLD.owner_principal_id,
        OLD.legacy_created_by_label,
        OLD.legacy_requester_label,
        OLD.legacy_owner_label
    ) THEN
        RAISE EXCEPTION 'request principal ownership is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_requests_00_principal_binding
BEFORE INSERT OR UPDATE ON requests
FOR EACH ROW EXECUTE FUNCTION enforce_request_principal_binding();

CREATE FUNCTION enforce_request_approval_principal_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    request_record public.requests%ROWTYPE;
    actor_record public.principals%ROWTYPE;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'approval decision principal evidence is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.principal_binding_state <> 'exact-v1'
       OR NEW.actor_principal_id IS NULL
       OR NEW.actor_principal_lifecycle_version IS NULL
       OR NEW.actor_principal_authority_version IS NULL
       OR NEW.legacy_actor_label IS NOT NULL THEN
        RAISE EXCEPTION 'new approval requires exact opaque actor binding'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO request_record
    FROM public.requests
    WHERE id = NEW.request_id
    FOR UPDATE;
    IF NOT FOUND OR request_record.principal_binding_state <> 'exact-v1' THEN
        RAISE EXCEPTION 'approval request has quarantined identity provenance'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.actor_principal_id = request_record.requester_principal_id THEN
        RAISE EXCEPTION 'request maker cannot approve the same request'
            USING ERRCODE = '23514';
    END IF;
    SELECT * INTO actor_record
    FROM public.principals
    WHERE principal_id = NEW.actor_principal_id
      AND lifecycle_version = NEW.actor_principal_lifecycle_version
      AND authority_version = NEW.actor_principal_authority_version
      AND lifecycle_state = 'active'
      AND principal_kind = 'human'
    FOR SHARE;
    IF NOT FOUND OR NOT (NEW.role = ANY(actor_record.role_allowlist)) THEN
        RAISE EXCEPTION 'approval actor principal authority is stale or inactive'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_request_approval_decision_00_principal_binding
BEFORE INSERT OR UPDATE ON request_approval_decisions
FOR EACH ROW EXECUTE FUNCTION enforce_request_approval_principal_binding();

CREATE FUNCTION enforce_request_current_principal_approval_quorum()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    approved_role_count BIGINT;
    approved_actor_count BIGINT;
BEGIN
    IF NEW.principal_binding_state = 'exact-v1'
       AND NEW.status IS DISTINCT FROM OLD.status
       AND NEW.status IN ('approved', 'locked') THEN
        SELECT
            COUNT(DISTINCT decision.role),
            COUNT(DISTINCT decision.actor_principal_id)
        INTO approved_role_count, approved_actor_count
        FROM request_approval_decisions AS decision
        JOIN principals AS actor
          ON actor.principal_id = decision.actor_principal_id
         AND actor.lifecycle_version =
             decision.actor_principal_lifecycle_version
         AND actor.authority_version =
             decision.actor_principal_authority_version
         AND actor.lifecycle_state = 'active'
         AND actor.principal_kind = 'human'
         AND decision.role = ANY(actor.role_allowlist)
        WHERE decision.request_id = OLD.id
          AND decision.approval_epoch = OLD.approval_epoch
          AND decision.principal_binding_state = 'exact-v1'
          AND decision.decision = 'approved'
          AND decision.actor_principal_id <> OLD.requester_principal_id;

        IF approved_role_count < NEW.required_approval_roles
           OR approved_actor_count < NEW.required_approval_roles THEN
            RAISE EXCEPTION 'request approval quorum contains stale principal authority'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_requests_01_principal_approval_quorum
BEFORE UPDATE OF status ON requests
FOR EACH ROW EXECUTE FUNCTION enforce_request_current_principal_approval_quorum();

CREATE FUNCTION reject_principal_registry_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'principal registry records are monotonic and may not be removed'
        USING ERRCODE = '55000';
END;
$$;

CREATE FUNCTION reject_principal_registry_append_only_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'principal registry tombstones and events are append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER principals_no_delete
BEFORE DELETE ON principals
FOR EACH ROW EXECUTE FUNCTION reject_principal_registry_removal();
CREATE TRIGGER principals_no_truncate
BEFORE TRUNCATE ON principals
FOR EACH STATEMENT EXECUTE FUNCTION reject_principal_registry_removal();
CREATE TRIGGER principal_keys_no_delete
BEFORE DELETE ON principal_keys
FOR EACH ROW EXECUTE FUNCTION reject_principal_registry_removal();
CREATE TRIGGER principal_keys_no_truncate
BEFORE TRUNCATE ON principal_keys
FOR EACH STATEMENT EXECUTE FUNCTION reject_principal_registry_removal();
CREATE TRIGGER principal_key_versions_no_update_or_delete
BEFORE UPDATE OR DELETE ON principal_key_versions
FOR EACH ROW EXECUTE FUNCTION reject_principal_registry_append_only_mutation();
CREATE TRIGGER principal_key_versions_no_truncate
BEFORE TRUNCATE ON principal_key_versions
FOR EACH STATEMENT EXECUTE FUNCTION reject_principal_registry_append_only_mutation();
CREATE TRIGGER principal_links_no_delete
BEFORE DELETE ON principal_links
FOR EACH ROW EXECUTE FUNCTION reject_principal_registry_removal();
CREATE TRIGGER principal_links_no_truncate
BEFORE TRUNCATE ON principal_links
FOR EACH STATEMENT EXECUTE FUNCTION reject_principal_registry_removal();

CREATE TRIGGER principal_link_events_no_update_or_delete
BEFORE UPDATE OR DELETE ON principal_link_events
FOR EACH ROW EXECUTE FUNCTION reject_principal_registry_append_only_mutation();
CREATE TRIGGER principal_link_events_no_truncate
BEFORE TRUNCATE ON principal_link_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_principal_registry_append_only_mutation();
CREATE TRIGGER principal_provider_tombstones_no_update_or_delete
BEFORE UPDATE OR DELETE ON principal_provider_tombstones
FOR EACH ROW EXECUTE FUNCTION reject_principal_registry_append_only_mutation();
CREATE TRIGGER principal_provider_tombstones_no_truncate
BEFORE TRUNCATE ON principal_provider_tombstones
FOR EACH STATEMENT EXECUTE FUNCTION reject_principal_registry_append_only_mutation();
CREATE TRIGGER principal_key_tombstones_no_update_or_delete
BEFORE UPDATE OR DELETE ON principal_key_tombstones
FOR EACH ROW EXECUTE FUNCTION reject_principal_registry_append_only_mutation();
CREATE TRIGGER principal_key_tombstones_no_truncate
BEFORE TRUNCATE ON principal_key_tombstones
FOR EACH STATEMENT EXECUTE FUNCTION reject_principal_registry_append_only_mutation();

-- These invariants must also hold for replication-role and maintenance paths.
ALTER TABLE legacy_identity_authority_evidence
    ENABLE ALWAYS TRIGGER legacy_identity_authority_evidence_immutable;
ALTER TABLE legacy_identity_authority_evidence
    ENABLE ALWAYS TRIGGER legacy_identity_authority_evidence_no_truncate;
ALTER TABLE legacy_human_authority_evidence
    ENABLE ALWAYS TRIGGER legacy_human_authority_evidence_immutable;
ALTER TABLE legacy_human_authority_evidence
    ENABLE ALWAYS TRIGGER legacy_human_authority_evidence_no_truncate;
ALTER TABLE principals ENABLE ALWAYS TRIGGER principals_lifecycle_guard;
ALTER TABLE principals ENABLE ALWAYS TRIGGER principals_no_delete;
ALTER TABLE principals ENABLE ALWAYS TRIGGER principals_no_truncate;
ALTER TABLE agents ENABLE ALWAYS TRIGGER agents_enrollment_contract_v3_insert;
ALTER TABLE agents ENABLE ALWAYS TRIGGER agents_enrollment_contract_v3_mutation;
ALTER TABLE agents ENABLE ALWAYS TRIGGER agents_principal_binding_guard;
ALTER TABLE principal_keys ENABLE ALWAYS TRIGGER principal_keys_lifecycle_guard;
ALTER TABLE principal_keys ENABLE ALWAYS TRIGGER principal_keys_append_version;
ALTER TABLE principal_keys ENABLE ALWAYS TRIGGER principal_keys_tombstone_evidence;
ALTER TABLE principal_keys ENABLE ALWAYS TRIGGER principal_keys_no_delete;
ALTER TABLE principal_keys ENABLE ALWAYS TRIGGER principal_keys_no_truncate;
ALTER TABLE principal_key_versions
    ENABLE ALWAYS TRIGGER principal_key_versions_no_update_or_delete;
ALTER TABLE principal_key_versions
    ENABLE ALWAYS TRIGGER principal_key_versions_no_truncate;
ALTER TABLE principal_links ENABLE ALWAYS TRIGGER principal_links_lifecycle_guard;
ALTER TABLE principal_links ENABLE ALWAYS TRIGGER principal_links_append_event;
ALTER TABLE principal_links ENABLE ALWAYS TRIGGER principal_links_no_delete;
ALTER TABLE principal_links ENABLE ALWAYS TRIGGER principal_links_no_truncate;
ALTER TABLE principal_link_events
    ENABLE ALWAYS TRIGGER principal_link_events_no_update_or_delete;
ALTER TABLE principal_link_events
    ENABLE ALWAYS TRIGGER principal_link_events_no_truncate;
ALTER TABLE principal_provider_tombstones
    ENABLE ALWAYS TRIGGER principal_provider_tombstone_insert_guard;
ALTER TABLE principal_provider_tombstones
    ENABLE ALWAYS TRIGGER principal_provider_tombstones_no_update_or_delete;
ALTER TABLE principal_provider_tombstones
    ENABLE ALWAYS TRIGGER principal_provider_tombstones_no_truncate;
ALTER TABLE principal_key_tombstones
    ENABLE ALWAYS TRIGGER principal_key_tombstones_no_update_or_delete;
ALTER TABLE principal_key_tombstones
    ENABLE ALWAYS TRIGGER principal_key_tombstones_no_truncate;
ALTER TABLE sessions ENABLE ALWAYS TRIGGER sessions_principal_binding_guard;
ALTER TABLE api_tokens ENABLE ALWAYS TRIGGER api_tokens_principal_binding_guard;
ALTER TABLE api_tokens ENABLE ALWAYS TRIGGER api_tokens_last_used_at_guard;
ALTER TABLE api_tokens ENABLE ALWAYS TRIGGER api_tokens_delete_guard;
ALTER TABLE api_tokens ENABLE ALWAYS TRIGGER api_tokens_truncate_guard;
ALTER TABLE requests ENABLE ALWAYS TRIGGER trg_requests_00_principal_binding;
ALTER TABLE requests
    ENABLE ALWAYS TRIGGER trg_requests_01_principal_approval_quorum;
ALTER TABLE requests ENABLE ALWAYS TRIGGER trg_requests_rework_approval_epoch;
ALTER TABLE requests ENABLE ALWAYS TRIGGER trg_requests_rejection_evidence;
ALTER TABLE request_approval_decisions
    ENABLE ALWAYS TRIGGER trg_request_approval_decision_00_principal_binding;
ALTER TABLE request_approval_decisions
    ENABLE ALWAYS TRIGGER trg_request_approval_decision_current_epoch;
ALTER TABLE request_approval_decisions
    ENABLE ALWAYS TRIGGER trg_request_approval_decision_no_delete;
ALTER TABLE request_approval_decisions
    ENABLE ALWAYS TRIGGER trg_request_approval_decision_no_truncate;

COMMENT ON TABLE principals IS
    'Stable opaque principals; email, display name, issuer, and provider subject never create or link a principal';
COMMENT ON COLUMN principals.principal_id IS
    'Database-generated random UUID that remains stable across governed provider links';
COMMENT ON COLUMN principals.authority_version IS
    'Exact monotonic authorization generation; role/scope or link changes invalidate all derived credentials';
COMMENT ON TABLE principal_keys IS
    'Exact immutable provider/issuer/subject tuples with versioned credential authority; tombstoned tuples can never be reused';
COMMENT ON COLUMN principal_keys.authority_digest IS
    'Opaque 32-byte credential/configuration authority digest; never return or log';
COMMENT ON TABLE principal_key_versions IS
    'Append-only exact key generations retained for session/token evidence across credential rotation';
COMMENT ON TABLE principal_links IS
    'Explicit versioned key-to-principal links; relinking requires dual proof or maker-checker recovery';
COMMENT ON TABLE principal_link_events IS
    'Append-only event projection for every principal link version';
COMMENT ON TABLE principal_provider_tombstones IS
    'Permanent provider-id removal tombstones; all provider keys must be tombstoned first';
COMMENT ON TABLE principal_key_tombstones IS
    'Permanent provider-qualified key tombstones preventing subject reuse';
COMMENT ON COLUMN requests.principal_binding_state IS
    'legacy-quarantined rows are immutable evidence; exact-v1 rows use only opaque principal UUID authority';
COMMENT ON COLUMN request_approval_decisions.actor_principal_id IS
    'Opaque approving principal UUID; legacy actor labels are non-authoritative evidence';

REVOKE ALL ON TABLE principals FROM PUBLIC;
REVOKE ALL ON TABLE principal_keys FROM PUBLIC;
REVOKE ALL ON TABLE principal_key_versions FROM PUBLIC;
REVOKE ALL ON TABLE principal_links FROM PUBLIC;
REVOKE ALL ON TABLE principal_link_events FROM PUBLIC;
REVOKE ALL ON TABLE principal_provider_tombstones FROM PUBLIC;
REVOKE ALL ON TABLE principal_key_tombstones FROM PUBLIC;
REVOKE ALL ON TABLE legacy_identity_authority_evidence FROM PUBLIC;
REVOKE ALL ON TABLE legacy_human_authority_evidence FROM PUBLIC;

REVOKE ALL ON FUNCTION principal_registry_advisory_lock_is_held(BIGINT)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION principal_registry_provider_lock_key(TEXT)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION principal_registry_writer_contract_is_held(
    TEXT, TEXT, TEXT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_principal_registry_evidence_mutation()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_principal_lifecycle() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_agent_principal_binding() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_principal_provider_tombstone() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_principal_key_lifecycle() FROM PUBLIC;
REVOKE ALL ON FUNCTION append_principal_key_version() FROM PUBLIC;
REVOKE ALL ON FUNCTION record_principal_key_tombstone() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_principal_link_lifecycle() FROM PUBLIC;
REVOKE ALL ON FUNCTION append_principal_link_event() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_principal_bound_session() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_principal_bound_api_token() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_request_principal_binding() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_request_approval_principal_binding()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_request_current_principal_approval_quorum()
    FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_principal_registry_removal() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_principal_registry_append_only_mutation()
    FROM PUBLIC;

DO $privileges$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON TABLE public.principals FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.principal_keys FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.principal_key_versions FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.principal_links FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.principal_link_events FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.principal_provider_tombstones FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.principal_key_tombstones FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.legacy_identity_authority_evidence FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.legacy_human_authority_evidence FROM ryuki_app_runtime';

        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.principals TO ryuki_app_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.principal_keys TO ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.principal_key_versions TO ryuki_app_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.principal_links TO ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.principal_link_events TO ryuki_app_runtime';
        EXECUTE 'GRANT SELECT, INSERT ON TABLE public.principal_provider_tombstones TO ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.principal_key_tombstones TO ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.legacy_identity_authority_evidence TO ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.legacy_human_authority_evidence TO ryuki_app_runtime';

        EXECUTE 'REVOKE ALL ON FUNCTION public.principal_registry_advisory_lock_is_held(BIGINT) FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.principal_registry_provider_lock_key(TEXT) FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION public.principal_registry_writer_contract_is_held(TEXT, TEXT, TEXT) FROM ryuki_app_runtime';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.principal_registry_provider_lock_key(TEXT) TO ryuki_app_runtime';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.principal_registry_writer_contract_is_held(TEXT, TEXT, TEXT) TO ryuki_app_runtime';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.human_authority_lock_key(TEXT, TEXT, TEXT) TO ryuki_app_runtime';
    END IF;
END;
$privileges$;
