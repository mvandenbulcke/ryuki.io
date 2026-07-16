-- Bind globally unique directory identities to one server-derived site
-- namespace. Existing inconsistent rows are quarantined for explicit review;
-- they are never transferred, activated, renamed, or deleted automatically.

ALTER TABLE ad_computers
    ADD COLUMN namespace_owner_site TEXT,
    ADD COLUMN namespace_policy_version TEXT,
    ADD COLUMN namespace_state TEXT NOT NULL DEFAULT 'Quarantined';

ALTER TABLE gmsa_accounts
    ADD COLUMN namespace_owner_site TEXT,
    ADD COLUMN namespace_policy_version TEXT,
    ADD COLUMN namespace_state TEXT NOT NULL DEFAULT 'Quarantined';

WITH parsed AS (
    SELECT
        computer.id,
        (regexp_match(
            computer.name,
            '^(.+)-(SRV|WS|DC|MGMT|TEST|DEV)-([0-9]{2,4})$'
        ))[1] AS name_site,
        (regexp_match(
            computer.name,
            '^(.+)-(SRV|WS|DC|MGMT|TEST|DEV)-([0-9]{2,4})$'
        ))[2] AS role
    FROM ad_computers AS computer
), classified AS (
    SELECT
        parsed.id,
        registry.unlocode AS owner_site,
        COALESCE(registry.active, false)
            AND registry.unlocode = computer.site
            AND (
                (parsed.role = 'DC'
                    AND computer.ou_path = 'OU=Domain Controllers,DC=corp,DC=local')
                OR
                (parsed.role <> 'DC'
                    AND computer.ou_path = ANY (ARRAY[
                        'OU=Servers,OU=' || registry.unlocode || ',DC=corp,DC=local',
                        'OU=Workstations,OU=' || registry.unlocode || ',DC=corp,DC=local',
                        'OU=DMZ,OU=' || registry.unlocode || ',DC=corp,DC=local',
                        'OU=Management,OU=' || registry.unlocode || ',DC=corp,DC=local',
                        'OU=Testing,OU=' || registry.unlocode || ',DC=corp,DC=local',
                        'OU=Development,OU=' || registry.unlocode || ',DC=corp,DC=local'
                    ]))
            ) AS verified
    FROM parsed
    JOIN ad_computers AS computer ON computer.id = parsed.id
    LEFT JOIN site_registry AS registry ON registry.unlocode = parsed.name_site
)
UPDATE ad_computers AS computer
SET namespace_owner_site = classified.owner_site,
    namespace_policy_version = CASE
        WHEN classified.verified THEN 'directory-namespace-v1'
        ELSE NULL
    END,
    namespace_state = CASE
        WHEN classified.verified THEN 'Verified'
        ELSE 'Quarantined'
    END
FROM classified
WHERE classified.id = computer.id;

-- Invalid legacy provenance becomes a sticky platform quarantine. Preserve the
-- original row and its evidence for trusted directory-owner reconciliation.
UPDATE ad_computers
SET status = CASE WHEN status = 'Deleted' THEN status ELSE 'Quarantined' END,
    metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
        'namespace_review_required', 'true',
        'namespace_review_reason', 'legacy directory name/site/OU authority mismatch'
    ),
    updated_at = NOW()
WHERE namespace_state = 'Quarantined';

WITH classified AS (
    SELECT
        account.id,
        owner.unlocode AS owner_site,
        COALESCE(owner.active, false)
            AND owner.unlocode = account.site AS verified
    FROM gmsa_accounts AS account
    LEFT JOIN LATERAL (
        SELECT registry.unlocode, registry.active
        FROM site_registry AS registry
        WHERE right(account.name, char_length(registry.unlocode) + 1)
                = '-' || lower(registry.unlocode)
          AND left(
                account.name,
                char_length(account.name) - char_length(registry.unlocode) - 1
              ) ~ '^svc-[a-z0-9]+(-[a-z0-9]+)*$'
        ORDER BY char_length(registry.unlocode) DESC, registry.unlocode
        LIMIT 1
    ) AS owner ON true
)
UPDATE gmsa_accounts AS account
SET namespace_owner_site = classified.owner_site,
    namespace_policy_version = CASE
        WHEN classified.verified THEN 'directory-namespace-v1'
        ELSE NULL
    END,
    namespace_state = CASE
        WHEN classified.verified THEN 'Verified'
        ELSE 'Quarantined'
    END,
    updated_at = CASE
        WHEN classified.verified THEN account.updated_at
        ELSE NOW()
    END
FROM classified
WHERE classified.id = account.id;

-- Migration-time proof: an inactive owner may reserve its namespace, but no
-- legacy row may be promoted to operational Verified state under that owner.
-- Runtime deactivation is deliberately non-destructive and is handled by the
-- read/write authorization gates below rather than rewriting resource state.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM ad_computers AS computer
        WHERE computer.namespace_state = 'Verified'
          AND NOT EXISTS (
                SELECT 1
                FROM site_registry AS registry
                WHERE registry.unlocode = computer.namespace_owner_site
                  AND registry.unlocode = computer.site
                  AND registry.active
          )
    ) OR EXISTS (
        SELECT 1
        FROM gmsa_accounts AS account
        WHERE account.namespace_state = 'Verified'
          AND NOT EXISTS (
                SELECT 1
                FROM site_registry AS registry
                WHERE registry.unlocode = account.namespace_owner_site
                  AND registry.unlocode = account.site
                  AND registry.active
          )
    ) THEN
        RAISE EXCEPTION 'legacy directory namespace backfill admitted an inactive owner'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

ALTER TABLE ad_computers
    ADD CONSTRAINT ad_computers_namespace_state_check
        CHECK (namespace_state IN ('Verified', 'Quarantined')),
    ADD CONSTRAINT ad_computers_verified_namespace_check
        CHECK (
            namespace_state = 'Quarantined'
            OR (
                namespace_owner_site IS NOT NULL
                AND namespace_owner_site = site
                AND namespace_policy_version IS NOT NULL
                AND namespace_policy_version = 'directory-namespace-v1'
            )
        ),
    ADD CONSTRAINT ad_computers_site_registry_fk
        FOREIGN KEY (site) REFERENCES site_registry(unlocode) NOT VALID,
    ADD CONSTRAINT ad_computers_namespace_owner_site_fk
        FOREIGN KEY (namespace_owner_site) REFERENCES site_registry(unlocode) NOT VALID;

ALTER TABLE gmsa_accounts
    ADD CONSTRAINT gmsa_accounts_namespace_state_check
        CHECK (namespace_state IN ('Verified', 'Quarantined')),
    ADD CONSTRAINT gmsa_accounts_verified_namespace_check
        CHECK (
            namespace_state = 'Quarantined'
            OR (
                namespace_owner_site IS NOT NULL
                AND namespace_owner_site = site
                AND namespace_policy_version IS NOT NULL
                AND namespace_policy_version = 'directory-namespace-v1'
            )
        ),
    ADD CONSTRAINT gmsa_accounts_site_registry_fk
        FOREIGN KEY (site) REFERENCES site_registry(unlocode) NOT VALID,
    ADD CONSTRAINT gmsa_accounts_namespace_owner_site_fk
        FOREIGN KEY (namespace_owner_site) REFERENCES site_registry(unlocode) NOT VALID;

CREATE TABLE ad_quarantine_recovery_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    computer_id UUID NOT NULL REFERENCES ad_computers(id) ON DELETE RESTRICT,
    expected_updated_at TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1024),
    requested_by TEXT NOT NULL CHECK (char_length(btrim(requested_by)) BETWEEN 1 AND 255),
    approved_by TEXT CHECK (approved_by IS NULL OR char_length(btrim(approved_by)) BETWEEN 1 AND 255),
    state TEXT NOT NULL DEFAULT 'Pending'
        CHECK (state IN ('Pending', 'Approved', 'Applied', 'Rejected', 'Expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    applied_at TIMESTAMPTZ,
    CHECK (approved_by IS NULL OR approved_by <> requested_by),
    CHECK (expires_at > created_at),
    CHECK (
        (state = 'Pending' AND approved_by IS NULL AND approved_at IS NULL AND applied_at IS NULL)
        OR (state = 'Approved' AND approved_by IS NOT NULL AND approved_at IS NOT NULL AND applied_at IS NULL)
        OR (state IN ('Rejected', 'Expired') AND applied_at IS NULL)
        OR (state = 'Applied' AND approved_by IS NOT NULL AND approved_at IS NOT NULL AND applied_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX ad_quarantine_recovery_one_open_review_idx
    ON ad_quarantine_recovery_reviews(computer_id)
    WHERE state IN ('Pending', 'Approved');

CREATE INDEX ad_quarantine_recovery_state_expiry_idx
    ON ad_quarantine_recovery_reviews(state, expires_at);

-- Every recovery-row mutation repeats current owner-site authorization and
-- holds a share lock through the caller transaction. Deactivation never edits
-- review or computer state; it simply prevents recovery until reactivation.
CREATE OR REPLACE FUNCTION ryuki_guard_ad_recovery_active_site()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    owner_active BOOLEAN;
BEGIN
    SELECT registry.active
    INTO owner_active
    FROM ad_computers AS computer
    JOIN site_registry AS registry
      ON registry.unlocode = computer.namespace_owner_site
    WHERE computer.id = NEW.computer_id
      AND computer.namespace_state = 'Verified'
      AND computer.namespace_owner_site = computer.site
    FOR SHARE OF computer, registry;

    IF NOT FOUND OR NOT owner_active THEN
        RAISE EXCEPTION 'AD quarantine recovery requires a currently active owner site'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER ad_quarantine_recovery_active_site_guard
BEFORE INSERT OR UPDATE ON ad_quarantine_recovery_reviews
FOR EACH ROW EXECUTE FUNCTION ryuki_guard_ad_recovery_active_site();

-- Recovery reviews are durable maker/checker evidence.  Fence legacy/direct
-- writers, make lifecycle timestamps database-owned, and prevent a checker or
-- evidence tuple from being rewritten after approval.
CREATE OR REPLACE FUNCTION ryuki_guard_ad_recovery_review_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('ryuki.ad_recovery_writer_contract', TRUE)
           IS DISTINCT FROM 'ad-recovery-v2' THEN
        RAISE EXCEPTION 'AD recovery writer contract v2 is required'
            USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'Pending'
           OR NEW.approved_by IS NOT NULL
           OR NEW.approved_at IS NOT NULL
           OR NEW.applied_at IS NOT NULL THEN
            RAISE EXCEPTION 'AD recovery review must begin Pending without checker evidence'
                USING ERRCODE = '23514';
        END IF;
        NEW.created_at := statement_timestamp();
        NEW.expires_at := NEW.created_at + INTERVAL '24 hours';
        RETURN NEW;
    END IF;

    IF ROW(NEW.id, NEW.computer_id, NEW.expected_updated_at, NEW.reason,
           NEW.requested_by, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.computer_id, OLD.expected_updated_at, OLD.reason,
           OLD.requested_by, OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'AD recovery review identity and maker evidence are immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'Pending' AND NEW.state = 'Approved' THEN
        IF NEW.approved_by IS NULL OR NEW.approved_by = OLD.requested_by THEN
            RAISE EXCEPTION 'AD recovery approval requires a distinct checker'
                USING ERRCODE = '23514';
        END IF;
        NEW.approved_at := statement_timestamp();
        NEW.applied_at := NULL;
    ELSIF OLD.state = 'Pending' AND NEW.state IN ('Rejected', 'Expired') THEN
        NEW.approved_by := NULL;
        NEW.approved_at := NULL;
        NEW.applied_at := NULL;
    ELSIF OLD.state = 'Approved' AND NEW.state = 'Applied' THEN
        IF NEW.approved_by IS DISTINCT FROM OLD.approved_by
           OR NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
            RAISE EXCEPTION 'AD recovery checker evidence is immutable'
                USING ERRCODE = '23514';
        END IF;
        NEW.applied_at := statement_timestamp();
    ELSIF OLD.state = 'Approved' AND NEW.state IN ('Rejected', 'Expired') THEN
        IF NEW.approved_by IS DISTINCT FROM OLD.approved_by
           OR NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
            RAISE EXCEPTION 'AD recovery checker evidence is immutable'
                USING ERRCODE = '23514';
        END IF;
        NEW.applied_at := NULL;
    ELSE
        RAISE EXCEPTION 'invalid AD recovery review lifecycle transition'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER ad_quarantine_recovery_lifecycle_guard
BEFORE INSERT OR UPDATE ON ad_quarantine_recovery_reviews
FOR EACH ROW EXECUTE FUNCTION ryuki_guard_ad_recovery_review_lifecycle();

-- Review rows are durable maker/checker evidence. Ordinary writers cannot
-- erase or truncate them after the decision has been consumed. The narrowly
-- scoped owner-only function below exists for disposable tests and explicitly
-- approved retention maintenance; the production application role is never
-- granted it.
CREATE OR REPLACE FUNCTION ryuki_reject_ad_recovery_review_removal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    table_owner OID;
BEGIN
    SELECT relowner
    INTO table_owner
    FROM pg_class
    WHERE oid = 'public.ad_quarantine_recovery_reviews'::regclass;

    IF TG_OP = 'DELETE'
       AND current_setting('ryuki.ad_recovery_ledger_maintenance', TRUE) =
           'owner-computer-purge-v1'
       AND CURRENT_USER::regrole::oid = table_owner THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'AD recovery review history is append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER ad_quarantine_recovery_no_delete
BEFORE DELETE ON ad_quarantine_recovery_reviews
FOR EACH ROW EXECUTE FUNCTION ryuki_reject_ad_recovery_review_removal();

CREATE TRIGGER ad_quarantine_recovery_no_truncate
BEFORE TRUNCATE ON ad_quarantine_recovery_reviews
FOR EACH STATEMENT EXECUTE FUNCTION ryuki_reject_ad_recovery_review_removal();

CREATE OR REPLACE FUNCTION purge_ad_recovery_reviews_for_maintenance(
    target_computer_id UUID
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
        'ryuki.ad_recovery_ledger_maintenance',
        'owner-computer-purge-v1',
        TRUE
    );
    DELETE FROM public.ad_quarantine_recovery_reviews
    WHERE computer_id = target_computer_id;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$;

REVOKE ALL ON FUNCTION purge_ad_recovery_reviews_for_maintenance(UUID)
    FROM PUBLIC;

CREATE OR REPLACE FUNCTION ryuki_guard_ad_directory_namespace()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    name_parts TEXT[];
    owner_active BOOLEAN;
    expected_ou TEXT;
    recovery_review_id UUID;
    recovery_is_valid BOOLEAN;
    validate_namespace BOOLEAN := false;
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.namespace_state = 'Quarantined' THEN
        RAISE EXCEPTION 'quarantined AD namespace provenance requires trusted repair'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.namespace_state = 'Verified' THEN
        SELECT registry.active
        INTO owner_active
        FROM site_registry AS registry
        WHERE registry.unlocode = OLD.namespace_owner_site
          AND OLD.namespace_owner_site = OLD.site
        FOR SHARE;
        IF NOT FOUND OR NOT owner_active THEN
            RAISE EXCEPTION 'AD computer mutation requires a currently active owner site'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF TG_OP = 'UPDATE'
       AND OLD.namespace_state = 'Verified'
       AND (
            NEW.name IS DISTINCT FROM OLD.name
            OR NEW.site IS DISTINCT FROM OLD.site
            OR NEW.namespace_owner_site IS DISTINCT FROM OLD.namespace_owner_site
            OR NEW.namespace_policy_version IS DISTINCT FROM OLD.namespace_policy_version
            OR NEW.namespace_state IS DISTINCT FROM OLD.namespace_state
       ) THEN
        RAISE EXCEPTION 'verified AD directory namespace ownership is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' THEN
        validate_namespace := true;
    ELSIF NEW.name IS DISTINCT FROM OLD.name
       OR NEW.site IS DISTINCT FROM OLD.site
       OR NEW.ou_path IS DISTINCT FROM OLD.ou_path
       OR NEW.namespace_owner_site IS DISTINCT FROM OLD.namespace_owner_site
       OR NEW.namespace_policy_version IS DISTINCT FROM OLD.namespace_policy_version
       OR NEW.namespace_state IS DISTINCT FROM OLD.namespace_state THEN
        validate_namespace := true;
    END IF;

    IF validate_namespace THEN
        IF NEW.namespace_state <> 'Verified'
           OR NEW.namespace_policy_version IS DISTINCT FROM 'directory-namespace-v1' THEN
            RAISE EXCEPTION 'new directory objects require verified namespace provenance'
                USING ERRCODE = '23514';
        END IF;

        name_parts := regexp_match(
            NEW.name,
            '^(.+)-(SRV|WS|DC|MGMT|TEST|DEV)-([0-9]{2,4})$'
        );
        IF name_parts IS NULL OR name_parts[1] <> NEW.site
           OR NEW.namespace_owner_site IS DISTINCT FROM NEW.site THEN
            RAISE EXCEPTION 'AD computer name namespace does not match owner site'
                USING ERRCODE = '23514';
        END IF;

        SELECT registry.active
        INTO owner_active
        FROM site_registry AS registry
        WHERE registry.unlocode = NEW.site
        FOR SHARE;
        IF NOT FOUND OR NOT owner_active THEN
            RAISE EXCEPTION 'AD computer owner site is unknown or inactive'
                USING ERRCODE = '23514';
        END IF;

        expected_ou := CASE name_parts[2]
            WHEN 'SRV' THEN 'OU=Servers,OU=' || NEW.site || ',DC=corp,DC=local'
            WHEN 'WS' THEN 'OU=Workstations,OU=' || NEW.site || ',DC=corp,DC=local'
            WHEN 'DC' THEN 'OU=Domain Controllers,DC=corp,DC=local'
            WHEN 'MGMT' THEN 'OU=Management,OU=' || NEW.site || ',DC=corp,DC=local'
            WHEN 'TEST' THEN 'OU=Testing,OU=' || NEW.site || ',DC=corp,DC=local'
            WHEN 'DEV' THEN 'OU=Development,OU=' || NEW.site || ',DC=corp,DC=local'
        END;

        IF TG_OP = 'INSERT' AND NEW.ou_path <> expected_ou THEN
            RAISE EXCEPTION 'AD prestage OU does not match server-derived role/site policy'
                USING ERRCODE = '23514';
        ELSIF TG_OP = 'UPDATE'
          AND name_parts[2] = 'DC'
          AND NEW.ou_path <> expected_ou THEN
            RAISE EXCEPTION 'domain controller OU is not canonical'
                USING ERRCODE = '23514';
        ELSIF TG_OP = 'UPDATE'
          AND name_parts[2] <> 'DC'
          AND NEW.ou_path <> ALL (ARRAY[
                'OU=Servers,OU=' || NEW.site || ',DC=corp,DC=local',
                'OU=Workstations,OU=' || NEW.site || ',DC=corp,DC=local',
                'OU=DMZ,OU=' || NEW.site || ',DC=corp,DC=local',
                'OU=Management,OU=' || NEW.site || ',DC=corp,DC=local',
                'OU=Testing,OU=' || NEW.site || ',DC=corp,DC=local',
                'OU=Development,OU=' || NEW.site || ',DC=corp,DC=local'
          ]) THEN
            RAISE EXCEPTION 'AD computer OU is outside its owner-site namespace'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.status = 'Quarantined' AND NEW.status IS DISTINCT FROM OLD.status THEN
            IF OLD.namespace_state <> 'Verified' OR NEW.status <> 'Disabled' THEN
                RAISE EXCEPTION 'quarantine is terminal without reviewed recovery to Disabled'
                    USING ERRCODE = '23514';
            END IF;

            BEGIN
                recovery_review_id := (NEW.metadata->>'quarantine_release_review_id')::uuid;
            EXCEPTION WHEN invalid_text_representation THEN
                RAISE EXCEPTION 'quarantine release review evidence is invalid'
                    USING ERRCODE = '23514';
            END;

            SELECT EXISTS (
                SELECT 1
                FROM ad_quarantine_recovery_reviews AS review
                WHERE review.id = recovery_review_id
                  AND review.computer_id = OLD.id
                  AND review.expected_updated_at = OLD.updated_at
                  AND review.state = 'Approved'
                  AND review.approved_by IS NOT NULL
                  AND review.approved_by <> review.requested_by
                  AND review.approved_at IS NOT NULL
                  AND review.expires_at > NOW()
                  AND NEW.metadata->>'quarantine_release_reason' = btrim(review.reason)
                  AND (NEW.metadata->>'quarantine_release_approved_at')::timestamptz
                        = review.approved_at
            )
            INTO recovery_is_valid;
            IF NOT COALESCE(recovery_is_valid, false) THEN
                RAISE EXCEPTION 'quarantine release lacks a fresh maker-checker review'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER ad_computers_directory_namespace_guard
BEFORE INSERT OR UPDATE ON ad_computers
FOR EACH ROW EXECUTE FUNCTION ryuki_guard_ad_directory_namespace();

CREATE OR REPLACE FUNCTION ryuki_guard_gmsa_directory_namespace()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    owner_site TEXT;
    owner_active BOOLEAN;
    validate_namespace BOOLEAN := false;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.namespace_state = 'Quarantined' THEN
            RAISE EXCEPTION 'quarantined gMSA namespace provenance requires trusted repair'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.name IS DISTINCT FROM OLD.name
           OR NEW.site IS DISTINCT FROM OLD.site
           OR NEW.namespace_owner_site IS DISTINCT FROM OLD.namespace_owner_site
           OR NEW.namespace_policy_version IS DISTINCT FROM OLD.namespace_policy_version
           OR NEW.namespace_state IS DISTINCT FROM OLD.namespace_state THEN
            RAISE EXCEPTION 'verified gMSA directory namespace ownership is immutable'
                USING ERRCODE = '23514';
        END IF;

        SELECT registry.active
        INTO owner_active
        FROM site_registry AS registry
        WHERE registry.unlocode = OLD.namespace_owner_site
          AND OLD.namespace_owner_site = OLD.site
        FOR SHARE;
        IF NOT FOUND OR NOT owner_active THEN
            RAISE EXCEPTION 'gMSA mutation requires a currently active owner site'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF TG_OP = 'INSERT' THEN
        validate_namespace := true;
    ELSIF NEW.name IS DISTINCT FROM OLD.name
       OR NEW.site IS DISTINCT FROM OLD.site
       OR NEW.namespace_owner_site IS DISTINCT FROM OLD.namespace_owner_site
       OR NEW.namespace_policy_version IS DISTINCT FROM OLD.namespace_policy_version
       OR NEW.namespace_state IS DISTINCT FROM OLD.namespace_state THEN
        validate_namespace := true;
    END IF;

    IF validate_namespace THEN
        -- Site registration and namespace-changing gMSA writes share this
        -- transaction-scoped lock. Otherwise a longer site suffix could be
        -- registered after resolution and reinterpret an accepted name.
        PERFORM pg_advisory_xact_lock(
            hashtextextended('ryuki:gmsa-site-namespace', 0)
        );

        IF NEW.namespace_state <> 'Verified'
           OR NEW.namespace_policy_version IS DISTINCT FROM 'directory-namespace-v1' THEN
            RAISE EXCEPTION 'new gMSA objects require verified namespace provenance'
                USING ERRCODE = '23514';
        END IF;

        SELECT registry.unlocode, registry.active
        INTO owner_site, owner_active
        FROM site_registry AS registry
        WHERE right(NEW.name, char_length(registry.unlocode) + 1)
                = '-' || lower(registry.unlocode)
          AND left(
                NEW.name,
                char_length(NEW.name) - char_length(registry.unlocode) - 1
              ) ~ '^svc-[a-z0-9]+(-[a-z0-9]+)*$'
        ORDER BY char_length(registry.unlocode) DESC, registry.unlocode
        LIMIT 1
        FOR SHARE;

        IF NOT FOUND OR NOT owner_active OR owner_site IS DISTINCT FROM NEW.site
           OR NEW.namespace_owner_site IS DISTINCT FROM NEW.site THEN
            RAISE EXCEPTION 'gMSA name namespace does not match an active owner site'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER gmsa_accounts_directory_namespace_guard
BEFORE INSERT OR UPDATE ON gmsa_accounts
FOR EACH ROW EXECUTE FUNCTION ryuki_guard_gmsa_directory_namespace();

-- Adding a longer governed suffix can change the canonical owner of an
-- existing global gMSA name. Serialize registry insertion with account writes
-- and reject any registration that would retroactively transfer ownership.
CREATE OR REPLACE FUNCTION ryuki_guard_gmsa_site_namespace_registration()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.unlocode IS DISTINCT FROM OLD.unlocode THEN
            RAISE EXCEPTION 'governed site namespace identifiers are immutable'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('ryuki:gmsa-site-namespace', 0)
    );

    IF EXISTS (
        SELECT 1
        FROM gmsa_accounts AS account
        WHERE account.namespace_state = 'Verified'
          AND right(account.name, char_length(NEW.unlocode) + 1)
                = '-' || lower(NEW.unlocode)
          AND account.site IS DISTINCT FROM NEW.unlocode
          AND NOT EXISTS (
                SELECT 1
                FROM site_registry AS longer_owner
                WHERE char_length(longer_owner.unlocode) > char_length(NEW.unlocode)
                  AND right(
                        account.name,
                        char_length(longer_owner.unlocode) + 1
                      ) = '-' || lower(longer_owner.unlocode)
          )
    ) THEN
        RAISE EXCEPTION 'site registration would transfer an existing gMSA namespace'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER site_registry_gmsa_namespace_guard
BEFORE INSERT OR UPDATE ON site_registry
FOR EACH ROW EXECUTE FUNCTION ryuki_guard_gmsa_site_namespace_registration();

CREATE OR REPLACE FUNCTION ryuki_guard_gmsa_host_namespace()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    account_id UUID;
    namespace_authorized BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.gmsa_account_id IS DISTINCT FROM OLD.gmsa_account_id THEN
        RAISE EXCEPTION 'gMSA host assignment ownership is immutable'
            USING ERRCODE = '23514';
    END IF;

    account_id := CASE
        WHEN TG_OP = 'DELETE' THEN OLD.gmsa_account_id
        ELSE NEW.gmsa_account_id
    END;
    SELECT account.namespace_state = 'Verified'
           AND account.namespace_owner_site = account.site
           AND registry.active
    INTO namespace_authorized
    FROM gmsa_accounts AS account
    JOIN site_registry AS registry
      ON registry.unlocode = account.namespace_owner_site
    WHERE account.id = account_id
    FOR SHARE OF account, registry;
    IF NOT COALESCE(namespace_authorized, false) THEN
        RAISE EXCEPTION 'gMSA host assignment requires verified provenance and an active owner site'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER gmsa_host_assignments_namespace_guard
BEFORE INSERT OR UPDATE OR DELETE ON gmsa_host_assignments
FOR EACH ROW EXECUTE FUNCTION ryuki_guard_gmsa_host_namespace();

CREATE INDEX ad_computers_namespace_review_idx
    ON ad_computers(namespace_state, namespace_owner_site, name);

CREATE INDEX gmsa_accounts_namespace_review_idx
    ON gmsa_accounts(namespace_state, namespace_owner_site, name);
