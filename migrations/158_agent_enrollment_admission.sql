-- 158_agent_enrollment_admission.sql — trusted, bounded agent enrollment.
--
-- Registration remains reachable before an agent bearer exists, but an
-- anonymous caller can no longer allocate an identity. A trusted administrator
-- first creates a short-lived challenge bound to the intended agent id,
-- platform, and exact Ed25519 public key. The plaintext challenge is returned
-- once; only its hash is stored. Registration must prove possession of that
-- key and atomically consume the matching challenge.
--
-- Existing Pending rows have no such provenance and are removed during this
-- migration. Existing approved/revoked identities remain operable, but cannot
-- be used as evidence for a new Pending -> approved transition. Their
-- historical authority bindings are frozen; the only enrollment-authority
-- mutation still permitted for an unlinked legacy row is Approved -> Revoked.

CREATE TABLE agent_enrollment_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    public_key TEXT NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    secret_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'consumed', 'expired')),
    ttl_seconds INTEGER NOT NULL DEFAULT 900
        CHECK (ttl_seconds BETWEEN 60 AND 86400),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    -- Retain the immutable enrollment UUID as provenance even after an expired
    -- Pending agent row is cleaned up; this is deliberately not a foreign key.
    consumed_enrollment_id UUID,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (octet_length(agent_id) BETWEEN 1 AND 128),
    CHECK (octet_length(platform) BETWEEN 1 AND 128),
    CHECK (octet_length(public_key) BETWEEN 1 AND 64),
    CHECK (public_key_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
    CHECK (
        (status = 'pending' AND consumed_at IS NULL AND consumed_enrollment_id IS NULL)
        OR (status = 'consumed' AND consumed_at IS NOT NULL AND consumed_enrollment_id IS NOT NULL)
        OR (status = 'expired' AND consumed_at IS NULL AND consumed_enrollment_id IS NULL)
    )
);

-- At most one live provisioning decision may exist for a human-readable agent
-- id. Expired rows are moved to status=expired by the next issuance or
-- consumption transaction before a replacement is created.
CREATE UNIQUE INDEX idx_agent_enrollment_challenges_pending_agent
    ON agent_enrollment_challenges (agent_id)
    WHERE status = 'pending';

CREATE INDEX idx_agent_enrollment_challenges_expiry
    ON agent_enrollment_challenges (expires_at, id)
    WHERE status = 'pending';

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS enrollment_expires_at TIMESTAMPTZ
        DEFAULT (NOW() + INTERVAL '7 days'),
    ADD COLUMN IF NOT EXISTS enrollment_bounds_version SMALLINT,
    ADD COLUMN IF NOT EXISTS enrollment_challenge_id UUID;

-- `ADD COLUMN IF NOT EXISTS ... REFERENCES` silently skips the reference when
-- a partial/manual rollout pre-created only the column. Install one stable,
-- named constraint separately and reject a same-name drifted definition.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'agents'::regclass
          AND conname = 'agents_enrollment_challenge_id_fkey'
    ) THEN
        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint AS constraint_row
            WHERE constraint_row.conrelid = 'agents'::regclass
              AND constraint_row.conname = 'agents_enrollment_challenge_id_fkey'
              AND constraint_row.contype = 'f'
              AND constraint_row.confrelid = 'agent_enrollment_challenges'::regclass
              AND constraint_row.confdeltype = 'r'
              AND constraint_row.conkey = ARRAY[(
                  SELECT attribute.attnum
                  FROM pg_attribute AS attribute
                  WHERE attribute.attrelid = 'agents'::regclass
                    AND attribute.attname = 'enrollment_challenge_id'
                    AND NOT attribute.attisdropped
              )]::SMALLINT[]
              AND constraint_row.confkey = ARRAY[(
                  SELECT attribute.attnum
                  FROM pg_attribute AS attribute
                  WHERE attribute.attrelid = 'agent_enrollment_challenges'::regclass
                    AND attribute.attname = 'id'
                    AND NOT attribute.attisdropped
              )]::SMALLINT[]
        ) THEN
            RAISE EXCEPTION 'agents_enrollment_challenge_id_fkey has an unexpected definition'
                USING ERRCODE = '55000';
        END IF;
    ELSE
        ALTER TABLE agents
            ADD CONSTRAINT agents_enrollment_challenge_id_fkey
            FOREIGN KEY (enrollment_challenge_id)
            REFERENCES agent_enrollment_challenges(id)
            ON DELETE RESTRICT
            NOT VALID;
    END IF;
END;
$$;

ALTER TABLE agents
    VALIDATE CONSTRAINT agents_enrollment_challenge_id_fkey;

-- Provisioning challenges are immutable one-time grants. PostgreSQL owns both
-- lifecycle timestamps and derives the deadline from the bounded TTL so a
-- sibling/direct writer cannot extend a leaked grant. Consumed and expired are
-- terminal; consuming also proves that the exact challenge-bound Pending agent
-- row was inserted in the same transaction.
CREATE OR REPLACE FUNCTION enforce_agent_enrollment_challenge_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status IS DISTINCT FROM 'pending'
           OR NEW.consumed_at IS NOT NULL
           OR NEW.consumed_enrollment_id IS NOT NULL THEN
            RAISE EXCEPTION 'agent enrollment challenge must begin Pending and unconsumed'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.public_key_fingerprint IS DISTINCT FROM
           'sha256:' || encode(sha256(convert_to(NEW.public_key, 'UTF8')), 'hex') THEN
            RAISE EXCEPTION 'agent enrollment challenge public-key fingerprint mismatch'
                USING ERRCODE = '23514';
        END IF;
        NEW.created_at := statement_timestamp();
        NEW.expires_at := NEW.created_at + NEW.ttl_seconds * INTERVAL '1 second';
        RETURN NEW;
    END IF;

    IF ROW(NEW.id, NEW.agent_id, NEW.platform, NEW.public_key,
           NEW.public_key_fingerprint, NEW.secret_hash, NEW.ttl_seconds,
           NEW.expires_at, NEW.created_by, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.agent_id, OLD.platform, OLD.public_key,
           OLD.public_key_fingerprint, OLD.secret_hash, OLD.ttl_seconds,
           OLD.expires_at, OLD.created_by, OLD.created_at) THEN
        RAISE EXCEPTION 'agent enrollment challenge grant fields are immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.status IS DISTINCT FROM 'pending' THEN
        RAISE EXCEPTION 'consumed and expired enrollment challenges are terminal'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.status = 'consumed' THEN
        IF OLD.expires_at <= statement_timestamp()
           OR NEW.consumed_enrollment_id IS NULL THEN
            RAISE EXCEPTION 'only an active enrollment challenge may be consumed'
                USING ERRCODE = '23514';
        END IF;

        PERFORM 1
        FROM agents AS agent
        WHERE agent.id = NEW.consumed_enrollment_id
          AND agent.status = 'pending'
          AND agent.enrollment_challenge_id = OLD.id
          AND agent.agent_id = OLD.agent_id
          AND agent.platform = OLD.platform
          AND agent.public_key = OLD.public_key
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'consumed challenge is not bound to the exact Pending enrollment'
                USING ERRCODE = '23514';
        END IF;

        NEW.consumed_at := statement_timestamp();
        RETURN NEW;
    END IF;

    IF NEW.status = 'expired' THEN
        IF OLD.expires_at > statement_timestamp() THEN
            RAISE EXCEPTION 'an active enrollment challenge cannot be expired early'
                USING ERRCODE = '23514';
        END IF;
        NEW.consumed_at := NULL;
        NEW.consumed_enrollment_id := NULL;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid agent enrollment challenge lifecycle transition'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER agent_enrollment_challenge_lifecycle_guard
BEFORE INSERT OR UPDATE ON agent_enrollment_challenges
FOR EACH ROW
EXECUTE FUNCTION enforce_agent_enrollment_challenge_lifecycle();

-- Existing free-form rows are deliberately grandfathered at version 0. Their
-- identifiers and keys cannot be truncated or rewritten safely, and a plain
-- NOT VALID size constraint would still re-check (and strand) them on a later
-- security-critical revoke. Inserts after this migration commit default to the
-- bounded version 1, including inserts from an older application replica.
UPDATE agents
SET enrollment_bounds_version = 0
WHERE enrollment_bounds_version IS NULL;

ALTER TABLE agents
    ALTER COLUMN enrollment_bounds_version SET DEFAULT 1,
    ALTER COLUMN enrollment_bounds_version SET NOT NULL;

-- A pre-migration Pending row was allocated by the vulnerable anonymous
-- first-writer path. It must never become trusted merely because an
-- administrator later approves it, and retaining its unique agent_id would
-- preserve the attacker's onboarding denial. Remove only these untrusted
-- Pending allocations so a trusted challenge can admit the intended host.
DELETE FROM agents
WHERE status = 'pending'
  AND enrollment_challenge_id IS NULL;

ALTER TABLE agents
    ALTER COLUMN enrollment_expires_at SET DEFAULT (NOW() + INTERVAL '7 days');

-- A second repair after the default is installed is intentional defense in
-- depth for databases where the column existed from a partial/manual rollout.
UPDATE agents
SET enrollment_expires_at = NOW() + INTERVAL '7 days'
WHERE status = 'pending'
  AND enrollment_challenge_id IS NOT NULL
  AND enrollment_expires_at IS NULL;

-- The ADD COLUMN default populated historical Approved/Revoked rows too. They
-- carry no pending-admission deadline, so clear that accidental value before
-- validating the exact lifecycle shape below.
UPDATE agents
SET enrollment_expires_at = NULL
WHERE status <> 'pending'
  AND enrollment_expires_at IS NOT NULL;

-- Historical version-0 rows remain updateable so a malformed legacy credential
-- can still be revoked. PostgreSQL enforces the bounds on every version-1 row;
-- a later reviewed normalization can migrate individual legacy rows to version
-- 1 after repairing them. The irreversible trigger below forbids downgrades.
ALTER TABLE agents
    ADD CONSTRAINT agents_enrollment_bounds_version
        CHECK (enrollment_bounds_version IN (0, 1)) NOT VALID,
    ADD CONSTRAINT agents_agent_id_size
        CHECK (
            enrollment_bounds_version = 0
            OR octet_length(agent_id) BETWEEN 1 AND 128
        ) NOT VALID,
    ADD CONSTRAINT agents_platform_size
        CHECK (
            enrollment_bounds_version = 0
            OR octet_length(platform) BETWEEN 1 AND 128
        ) NOT VALID,
    ADD CONSTRAINT agents_public_key_size
        CHECK (
            enrollment_bounds_version = 0
            OR octet_length(public_key) BETWEEN 1 AND 64
        ) NOT VALID,
    ADD CONSTRAINT agents_capabilities_size
        CHECK (
            enrollment_bounds_version = 0
            OR octet_length(capabilities::text) <= 16384
        ) NOT VALID,
    ADD CONSTRAINT agents_pending_enrollment_has_expiry
        CHECK (
            (status = 'pending' AND enrollment_expires_at IS NOT NULL)
            OR (status <> 'pending' AND enrollment_expires_at IS NULL)
        ) NOT VALID,
    ADD CONSTRAINT agents_pending_enrollment_has_challenge
        CHECK (status <> 'pending' OR enrollment_challenge_id IS NOT NULL) NOT VALID;

-- Unlike the historical free-form size constraints, the lifecycle constraint
-- is fully repaired above and can be validated now. New and old replicas that
-- omit the column receive the default immediately after this migration commits.
ALTER TABLE agents
    VALIDATE CONSTRAINT agents_enrollment_bounds_version,
    VALIDATE CONSTRAINT agents_pending_enrollment_has_expiry,
    VALIDATE CONSTRAINT agents_pending_enrollment_has_challenge;

CREATE INDEX IF NOT EXISTS idx_agents_pending_enrollment_expiry
    ON agents (enrollment_expires_at, id)
    WHERE status = 'pending';

-- Fail closed across a rolling or rollback overlap. A v2 binary knows the
-- bounded-review marker but not challenge admission or proof of possession, so
-- v3 deliberately changes the required transaction-local marker. Old v1/v2
-- replicas cannot insert agent rows or mutate enrollment authority after
-- this trigger is installed.
CREATE OR REPLACE FUNCTION enforce_agent_enrollment_contract_v3()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('ryuki.agent_enrollment_contract', TRUE) IS DISTINCT FROM '3' THEN
        RAISE EXCEPTION 'agent enrollment contract v3 is required'
            USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'INSERT' THEN
        -- Every post-cutover identity starts at the same narrow admission
        -- boundary. Direct/future sibling writers cannot mint an approved or
        -- legacy row and bypass the public registration handler.
        IF NEW.enrollment_bounds_version IS DISTINCT FROM 1
           OR NEW.status IS DISTINCT FROM 'pending' THEN
            RAISE EXCEPTION 'new agent identities must use v1 challenge-bound Pending admission'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.enrollment_challenge_id IS NULL THEN
            RAISE EXCEPTION 'pending agent enrollment requires a trusted challenge'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.token_hash !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'agent bearer hash must be canonical lowercase SHA-256'
                USING ERRCODE = '23514';
        END IF;

        -- Pending admission lifetime is a database fact. Ignore a caller value
        -- (including the column default) and assign the reviewed seven-day
        -- window at the durable insert boundary.
        NEW.enrollment_expires_at := statement_timestamp() + INTERVAL '7 days';

        PERFORM 1
        FROM agent_enrollment_challenges AS challenge
        WHERE challenge.id = NEW.enrollment_challenge_id
          AND challenge.status = 'pending'
          AND challenge.expires_at > clock_timestamp()
          AND challenge.agent_id = NEW.agent_id
          AND challenge.platform = NEW.platform
          AND challenge.public_key = NEW.public_key;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'pending agent enrollment does not match an active trusted challenge'
                USING ERRCODE = '23514';
        END IF;

        RETURN NEW;
    END IF;

    -- There is no in-place credential rotation contract. Re-enrollment creates
    -- a new immutable row/key/token binding; changing only this hash would take
    -- over an already Approved workload identity.
    IF NEW.token_hash IS DISTINCT FROM OLD.token_hash THEN
        RAISE EXCEPTION 'agent bearer hash is immutable; revoke and re-enroll'
            USING ERRCODE = '23514';
    END IF;

    -- Pending expiry is immutable and may only be cleared by a terminal trust
    -- decision. Approval additionally rechecks the old deadline with the
    -- database clock so a marker-aware sibling cannot resurrect an elapsed row.
    IF OLD.status = 'pending' AND NEW.status = 'approved' THEN
        IF OLD.enrollment_expires_at IS NULL
           OR OLD.enrollment_expires_at <= statement_timestamp()
           OR NEW.enrollment_expires_at IS NOT NULL THEN
            RAISE EXCEPTION 'expired agent enrollment cannot be approved'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.status = 'pending' AND NEW.status = 'revoked' THEN
        IF NEW.enrollment_expires_at IS NOT NULL THEN
            RAISE EXCEPTION 'revoked agent enrollment must clear its pending deadline'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.enrollment_expires_at IS DISTINCT FROM OLD.enrollment_expires_at THEN
        RAISE EXCEPTION 'agent enrollment expiry is immutable'
            USING ERRCODE = '23514';
    END IF;

    -- The migration cannot prove who controlled a pre-cutover key. Keep an
    -- already-Approved legacy workload running for a controlled migration and
    -- preserve the ability to revoke it, but never let a marker-aware sibling
    -- writer change or recreate authority on an unlinked row.
    IF OLD.enrollment_challenge_id IS NULL THEN
        IF OLD.status = 'approved'
           AND NEW.status = 'revoked'
           AND OLD.agent_id IS NOT DISTINCT FROM NEW.agent_id
           AND OLD.platform IS NOT DISTINCT FROM NEW.platform
           AND OLD.capabilities IS NOT DISTINCT FROM NEW.capabilities
           AND OLD.public_key IS NOT DISTINCT FROM NEW.public_key
           AND OLD.enrollment_bounds_version IS NOT DISTINCT FROM NEW.enrollment_bounds_version
           AND NEW.enrollment_challenge_id IS NULL THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'legacy agent authority is frozen and may only be revoked'
            USING ERRCODE = '23514';
    END IF;

    -- Revocation is terminal at both the handler and durable-state boundaries.
    IF OLD.status = 'revoked' AND NEW.status IS DISTINCT FROM 'revoked' THEN
        RAISE EXCEPTION 'revoked agents must re-enroll under a new identity record'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'approved' AND NEW.status = 'pending' THEN
        RAISE EXCEPTION 'approved agents cannot return to pending enrollment'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.enrollment_bounds_version = 1
       AND NEW.enrollment_bounds_version = 0 THEN
        RAISE EXCEPTION 'bounded agent rows cannot be downgraded to legacy bounds'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.enrollment_challenge_id IS DISTINCT FROM NEW.enrollment_challenge_id THEN
        RAISE EXCEPTION 'an agent enrollment challenge binding is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.enrollment_challenge_id IS NOT NULL
       AND (OLD.agent_id IS DISTINCT FROM NEW.agent_id
            OR OLD.platform IS DISTINCT FROM NEW.platform
            OR OLD.public_key IS DISTINCT FROM NEW.public_key) THEN
        RAISE EXCEPTION 'a challenge-admitted agent identity, platform, and key are immutable'
            USING ERRCODE = '23514';
    END IF;

    -- Any transition into or mutation while approved must still refer to the
    -- exact consumed challenge. This is the database-side approval backstop;
    -- the API repeats the same check while holding the agent row lock.
    IF NEW.status = 'approved' AND NEW.enrollment_challenge_id IS NOT NULL THEN
        PERFORM 1
        FROM agent_enrollment_challenges AS challenge
        WHERE challenge.id = NEW.enrollment_challenge_id
          AND challenge.status = 'consumed'
          AND challenge.consumed_enrollment_id = NEW.id
          AND challenge.agent_id = NEW.agent_id
          AND challenge.platform = NEW.platform
          AND challenge.public_key = NEW.public_key;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'approved agent identity lacks a matching consumed enrollment challenge'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS agents_enrollment_contract_v2_insert ON agents;
DROP TRIGGER IF EXISTS agents_enrollment_contract_v2_mutation ON agents;
DROP TRIGGER IF EXISTS agents_enrollment_contract_v3_insert ON agents;
CREATE TRIGGER agents_enrollment_contract_v3_insert
    BEFORE INSERT ON agents
    FOR EACH ROW
    EXECUTE FUNCTION enforce_agent_enrollment_contract_v3();

DROP TRIGGER IF EXISTS agents_enrollment_contract_v3_mutation ON agents;
CREATE TRIGGER agents_enrollment_contract_v3_mutation
    BEFORE UPDATE OF agent_id, status, platform, capabilities, public_key,
        token_hash, enrollment_expires_at, enrollment_bounds_version,
        enrollment_challenge_id ON agents
    FOR EACH ROW
    WHEN (
        OLD.agent_id IS DISTINCT FROM NEW.agent_id
        OR OLD.status IS DISTINCT FROM NEW.status
        OR OLD.platform IS DISTINCT FROM NEW.platform
        OR OLD.capabilities IS DISTINCT FROM NEW.capabilities
        OR OLD.public_key IS DISTINCT FROM NEW.public_key
        OR OLD.token_hash IS DISTINCT FROM NEW.token_hash
        OR OLD.enrollment_expires_at IS DISTINCT FROM NEW.enrollment_expires_at
        OR OLD.enrollment_bounds_version IS DISTINCT FROM NEW.enrollment_bounds_version
        OR OLD.enrollment_challenge_id IS DISTINCT FROM NEW.enrollment_challenge_id
    )
    EXECUTE FUNCTION enforce_agent_enrollment_contract_v3();

DROP FUNCTION IF EXISTS enforce_agent_enrollment_contract_v2();
