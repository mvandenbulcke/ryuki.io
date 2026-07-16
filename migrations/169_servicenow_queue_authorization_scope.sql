-- Bind every newly-created ServiceNow queue row to the authoritative CMDB
-- object and to the verified principal that created it.  Existing queue rows
-- intentionally remain unresolved (all new columns NULL) and are excluded by
-- the API until an operator reconciles them against current CMDB authority.

-- Migration 014 generated CI UUIDs at installation time. A familiar ci_name is
-- therefore not proof that the current row is the repository fixture rather
-- than an operator-managed replacement in a long-lived database. Do not infer
-- any legacy environment from that mutable name (or from type/site/owner
-- lookalikes). Every pre-existing CI remains unresolved for ServiceNow until a
-- separately reviewed mapping names its exact immutable configuration-item UUID.
CREATE TABLE configuration_item_environment_authority (
    id UUID PRIMARY KEY,
    configuration_item_id UUID NOT NULL UNIQUE
        REFERENCES configuration_items(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    environment TEXT NOT NULL CHECK (
        environment = BTRIM(environment) AND environment <> ''
    ),
    provenance_kind TEXT NOT NULL CHECK (
        provenance_kind IN ('reviewed-fixture-uuid', 'reviewed-operator-uuid')
    ),
    review_reference TEXT NOT NULL CHECK (
        review_reference = BTRIM(review_reference)
        AND review_reference <> ''
        AND CHAR_LENGTH(review_reference) <= 512
    ),
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (
        id,
        configuration_item_id,
        environment,
        provenance_kind,
        review_reference
    )
);

-- Admission of an authority record is itself fail closed: the exact CI must
-- currently carry the reviewed environment and resolve to an active canonical
-- site. No public API writes this table; reviewed fixture/operator mappings are
-- supplied by an explicit migration or similarly controlled administrative
-- process using pre-reviewed UUIDs.
CREATE OR REPLACE FUNCTION validate_configuration_item_environment_authority()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    ci_site TEXT;
    ci_environment TEXT;
    canonical_site TEXT;
BEGIN
    SELECT site, environment
    INTO ci_site, ci_environment
    FROM configuration_items
    WHERE id = NEW.configuration_item_id
    FOR SHARE;
    IF NOT FOUND
       OR ci_environment IS DISTINCT FROM NEW.environment
       OR ci_environment IS NULL
    THEN
        RAISE EXCEPTION 'configuration-item environment authority does not match the exact CI';
    END IF;

    SELECT unlocode
    INTO canonical_site
    FROM site_registry
    WHERE unlocode = ci_site AND active = true
    FOR SHARE;
    IF NOT FOUND OR canonical_site IS DISTINCT FROM ci_site THEN
        RAISE EXCEPTION 'configuration-item environment authority requires an active canonical site';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_configuration_item_environment_authority_validate
BEFORE INSERT ON configuration_item_environment_authority
FOR EACH ROW
EXECUTE FUNCTION validate_configuration_item_environment_authority();

CREATE OR REPLACE FUNCTION reject_configuration_item_environment_authority_rebind()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'configuration-item environment authority is immutable';
END;
$$;

CREATE TRIGGER trg_configuration_item_environment_authority_immutable
BEFORE UPDATE ON configuration_item_environment_authority
FOR EACH ROW
EXECUTE FUNCTION reject_configuration_item_environment_authority_rebind();

CREATE TRIGGER trg_configuration_item_environment_authority_no_truncate
BEFORE TRUNCATE ON configuration_item_environment_authority
FOR EACH STATEMENT
EXECUTE FUNCTION reject_configuration_item_environment_authority_rebind();

ALTER TABLE servicenow_queue
    ADD COLUMN ci_id UUID REFERENCES configuration_items(id) ON DELETE RESTRICT,
    ADD COLUMN environment_authority_id UUID,
    ADD COLUMN environment_provenance_kind TEXT,
    ADD COLUMN environment_review_reference TEXT,
    ADD COLUMN site TEXT,
    ADD COLUMN environment TEXT,
    ADD COLUMN ci_owner TEXT,
    ADD COLUMN requested_by TEXT;

-- A row is either unresolved legacy data (all binding fields NULL), or it has
-- one complete, non-blank binding.  Partial authority must never be persisted.
ALTER TABLE servicenow_queue
    ADD CONSTRAINT servicenow_queue_authority_binding_complete CHECK (
        (
            ci_id IS NULL
            AND environment_authority_id IS NULL
            AND environment_provenance_kind IS NULL
            AND environment_review_reference IS NULL
            AND site IS NULL
            AND environment IS NULL
            AND ci_owner IS NULL
            AND requested_by IS NULL
        )
        OR
        (
            ci_id IS NOT NULL
            AND environment_authority_id IS NOT NULL
            AND environment_provenance_kind IS NOT NULL
            AND environment_provenance_kind IN (
                'reviewed-fixture-uuid',
                'reviewed-operator-uuid'
            )
            AND environment_review_reference IS NOT NULL
            AND environment_review_reference = BTRIM(environment_review_reference)
            AND environment_review_reference <> ''
            AND CHAR_LENGTH(environment_review_reference) <= 512
            AND NULLIF(BTRIM(site), '') IS NOT NULL
            AND NULLIF(BTRIM(environment), '') IS NOT NULL
            AND NULLIF(BTRIM(ci_owner), '') IS NOT NULL
            AND NULLIF(BTRIM(requested_by), '') IS NOT NULL
        )
    ),
    ADD CONSTRAINT servicenow_queue_site_registry_fk
        FOREIGN KEY (site) REFERENCES site_registry(unlocode)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT servicenow_queue_environment_authority_fk
        FOREIGN KEY (
            environment_authority_id,
            ci_id,
            environment,
            environment_provenance_kind,
            environment_review_reference
        )
        REFERENCES configuration_item_environment_authority
            (
                id,
                configuration_item_id,
                environment,
                provenance_kind,
                review_reference
            )
        ON UPDATE RESTRICT ON DELETE RESTRICT;

-- Compatibility for writers that have not yet adopted this migration is
-- intentionally one-way: omitting every new binding field still creates the
-- all-NULL legacy shape, but that row is quarantined from every ServiceNow API
-- read and action. It cannot overlap the reviewed write path or be promoted by
-- a mutable name; reconciliation requires a separately reviewed exact-UUID
-- migration that supplies the complete provenance binding atomically.
--
-- This storage compatibility is not permission to overlap application
-- versions. Pre-169 binaries do not enforce the authority predicate when they
-- read or transition rows, so every old replica and transaction must be
-- stopped and drained before this migration and the reviewed writer are
-- admitted. Application-only rollback is unsafe once reviewed rows exist.

CREATE INDEX idx_snow_queue_authorized_pending
    ON servicenow_queue (site, environment, requested_by, created_at, id)
    WHERE ci_id IS NOT NULL AND status IN ('Pending', 'Ready');

CREATE INDEX idx_snow_queue_authorized_ci_history
    ON servicenow_queue (ci_id, requested_by, created_at, id)
    WHERE ci_id IS NOT NULL;

CREATE INDEX idx_snow_queue_environment_authority
    ON servicenow_queue (environment_authority_id, created_at, id)
    WHERE environment_authority_id IS NOT NULL;

-- The captured CMDB identity, scope axes, owner, creator, and target name are
-- authorization provenance rather than workflow fields. Ordinary lifecycle
-- updates may change status/external references only; reconciliation of a
-- quarantined legacy row requires a separately reviewed migration.
CREATE OR REPLACE FUNCTION reject_servicenow_queue_authority_rebind()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.ci_id IS DISTINCT FROM OLD.ci_id
       OR NEW.environment_authority_id IS DISTINCT FROM OLD.environment_authority_id
       OR NEW.environment_provenance_kind IS DISTINCT FROM OLD.environment_provenance_kind
       OR NEW.environment_review_reference IS DISTINCT FROM OLD.environment_review_reference
       OR NEW.ci_name IS DISTINCT FROM OLD.ci_name
       OR NEW.site IS DISTINCT FROM OLD.site
       OR NEW.environment IS DISTINCT FROM OLD.environment
       OR NEW.ci_owner IS DISTINCT FROM OLD.ci_owner
       OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
    THEN
        RAISE EXCEPTION 'ServiceNow queue authorization binding is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_servicenow_queue_authority_immutable
BEFORE UPDATE OF ci_id, environment_authority_id,
                 environment_provenance_kind, environment_review_reference,
                 ci_name, site, environment, ci_owner, requested_by
ON servicenow_queue
FOR EACH ROW
EXECUTE FUNCTION reject_servicenow_queue_authority_rebind();

COMMENT ON COLUMN configuration_items.environment IS
    'Candidate environment scope. NULL is unresolved; ServiceNow additionally requires an explicit immutable configuration_item_environment_authority UUID.';
COMMENT ON TABLE configuration_item_environment_authority IS
    'Explicit reviewed environment provenance for one exact immutable configuration_items UUID; names and mutable metadata never create rows here.';
COMMENT ON COLUMN configuration_item_environment_authority.review_reference IS
    'Non-secret reference to the reviewed mapping evidence; never inferred from a CI name.';
COMMENT ON COLUMN servicenow_queue.ci_id IS
    'Authoritative configuration_items identity captured while the CI row is locked.';
COMMENT ON COLUMN servicenow_queue.environment_authority_id IS
    'Exact reviewed environment-authority identity captured with the CI binding.';
COMMENT ON COLUMN servicenow_queue.environment_provenance_kind IS
    'Immutable snapshot of the reviewed authority provenance kind, bound by composite foreign key.';
COMMENT ON COLUMN servicenow_queue.environment_review_reference IS
    'Immutable non-secret review reference captured from the exact authority row; never inferred from a CI name.';
COMMENT ON COLUMN servicenow_queue.requested_by IS
    'Verified AuthSession user_id that created the queue row; never accepted from a request body.';
