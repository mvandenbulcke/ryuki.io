-- Bind snapshot-governance records to an authoritative CMDB resource.
--
-- `platform_ci_key`, `owner`, `support_group`, and metadata are descriptive
-- fields supplied by the workflow caller.  They are not authorization
-- identities.  The immutable configuration-item UUID is the authorization
-- relation; current site/environment membership is resolved through that UUID
-- by every snapshot query before a row can be materialized. The CMDB site's
-- exact active site-registry relation is part of that authority.

-- The original CMDB model carried only a site.  Environment is intentionally
-- nullable: NULL means the authoritative inventory has not classified that
-- axis yet.  An environment-scoped principal therefore cannot access such a
-- resource, while an unrestricted principal or a site-only scoped principal
-- can still operate on the known site relation.  No environment is guessed
-- from a CI name or mutable metadata.
ALTER TABLE configuration_items
    ADD COLUMN environment TEXT;

ALTER TABLE configuration_items
    ADD CONSTRAINT configuration_items_environment_shape_check
        CHECK (
            environment IS NULL
            OR (environment = btrim(environment) AND environment <> '')
        );

CREATE INDEX idx_configuration_items_environment
    ON configuration_items(environment)
    WHERE environment IS NOT NULL;

ALTER TABLE snapshots
    ADD COLUMN configuration_item_id UUID
        REFERENCES configuration_items(id) ON DELETE RESTRICT,
    ADD COLUMN created_by TEXT,
    ADD COLUMN scope_provenance TEXT NOT NULL DEFAULT 'unresolved-legacy';

-- Every pre-existing row stays quarantined. An exact equality between the
-- caller-supplied descriptive `platform_ci_key` and a mutable CMDB name is not
-- provenance for an authorization UUID, even when the name is currently
-- unique and its site is active. A later migration may classify that CMDB row
-- with an environment (migration 169 does so for a closed seed set); that must
-- never turn an unreviewed name collision into newly visible authority.
-- Releasing legacy rows requires a separate, explicitly reviewed mapping from
-- snapshot UUID to configuration-item UUID. No such mapping exists here.

ALTER TABLE snapshots
    ADD CONSTRAINT snapshots_scope_provenance_check
        CHECK (scope_provenance IN (
            'unresolved-legacy',
            'cmdb-configuration-item'
        )),
    ADD CONSTRAINT snapshots_scope_relation_check
        CHECK (
            (scope_provenance = 'unresolved-legacy'
                AND configuration_item_id IS NULL)
            OR
            (scope_provenance <> 'unresolved-legacy'
                AND configuration_item_id IS NOT NULL)
        ),
    ADD CONSTRAINT snapshots_new_scope_actor_check
        CHECK (
            scope_provenance <> 'cmdb-configuration-item'
            OR (created_by IS NOT NULL AND btrim(created_by) <> '')
        );

CREATE INDEX idx_snapshots_configuration_item_created
    ON snapshots(configuration_item_id, created_at DESC, id DESC)
    WHERE configuration_item_id IS NOT NULL;

COMMENT ON COLUMN configuration_items.environment IS
    'Authoritative environment scope; NULL is unresolved and cannot authorize an environment-scoped principal.';
COMMENT ON COLUMN snapshots.configuration_item_id IS
    'Immutable authoritative CMDB identity used for snapshot resource authorization.';
COMMENT ON COLUMN snapshots.created_by IS
    'Verified AuthSession principal captured at planning time; NULL only for legacy provenance.';
COMMENT ON COLUMN snapshots.scope_provenance IS
    'How the immutable snapshot-to-CMDB authorization relation was established.';

-- The relation and verified creator are authorization provenance, not ordinary
-- lifecycle fields. A later reviewed reconciliation migration may deliberately
-- release a quarantined row; application UPDATEs cannot silently rebind it.
CREATE OR REPLACE FUNCTION reject_snapshot_authority_rebind()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.configuration_item_id IS DISTINCT FROM OLD.configuration_item_id
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.scope_provenance IS DISTINCT FROM OLD.scope_provenance
    THEN
        RAISE EXCEPTION 'snapshot authorization provenance is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_snapshot_authority_immutable
BEFORE UPDATE OF configuration_item_id, created_by, scope_provenance
ON snapshots
FOR EACH ROW
EXECUTE FUNCTION reject_snapshot_authority_rebind();
