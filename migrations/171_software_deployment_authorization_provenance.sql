-- Bind software-deployment plans to immutable, authoritative CMDB provenance.
--
-- `server_name` remains a caller-supplied lookup key only until planning. New
-- plans resolve that key to `configuration_items.id` while holding the CMDB and
-- active-site rows locked, then persist the exact name/site/environment tuple.
-- Package name/version are similarly copied from a locked approved catalog row.
-- No server-name convention or request-body scope is authorization evidence.
ALTER TABLE software_deployments
    ADD COLUMN configuration_item_id UUID
        REFERENCES configuration_items(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD COLUMN site TEXT
        REFERENCES site_registry(unlocode) ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD COLUMN environment TEXT,
    ADD COLUMN maker_user_id TEXT,
    ADD COLUMN scope_provenance TEXT NOT NULL DEFAULT 'unresolved-legacy';

ALTER TABLE software_deployments
    ADD CONSTRAINT software_deployments_scope_provenance_check
        CHECK (scope_provenance IN (
            'unresolved-legacy',
            'cmdb-configuration-item'
        )),
    ADD CONSTRAINT software_deployments_authorization_provenance_complete
        CHECK (
            (
                scope_provenance = 'unresolved-legacy'
                AND configuration_item_id IS NULL
                AND site IS NULL
                AND environment IS NULL
                AND maker_user_id IS NULL
            )
            OR
            (
                scope_provenance = 'cmdb-configuration-item'
                AND configuration_item_id IS NOT NULL
                AND site IS NOT NULL
                AND site = BTRIM(site)
                AND site <> ''
                AND environment IS NOT NULL
                AND environment = BTRIM(environment)
                AND environment <> ''
                AND maker_user_id IS NOT NULL
                AND maker_user_id = BTRIM(maker_user_id)
                AND BTRIM(maker_user_id) <> ''
                AND requester = maker_user_id
                AND server_name = BTRIM(server_name)
                AND BTRIM(server_name) <> ''
                AND package_id = BTRIM(package_id)
                AND BTRIM(package_id) <> ''
                AND package_name = BTRIM(package_name)
                AND BTRIM(package_name) <> ''
                AND target_version = BTRIM(target_version)
                AND BTRIM(target_version) <> ''
            )
        );

-- Migration-032 fixtures and every other pre-migration row intentionally keep
-- `unresolved-legacy`. Their server names are not proof of CMDB identity, so
-- handlers exclude them from lifecycle transitions and history.
CREATE INDEX idx_software_deployments_scope_history
    ON software_deployments(
        configuration_item_id,
        site,
        environment,
        server_name,
        created_at,
        id
    )
    WHERE scope_provenance = 'cmdb-configuration-item';

COMMENT ON COLUMN software_deployments.configuration_item_id IS
    'Immutable authoritative CMDB target identity; NULL means unresolved legacy provenance.';
COMMENT ON COLUMN software_deployments.site IS
    'Canonical site copied from the locked CMDB target at planning; NULL legacy rows fail closed.';
COMMENT ON COLUMN software_deployments.environment IS
    'Canonical environment copied from the locked CMDB target at planning; NULL legacy rows fail closed.';
COMMENT ON COLUMN software_deployments.maker_user_id IS
    'Verified planning principal; NULL legacy rows fail closed and new rows match requester.';
COMMENT ON COLUMN software_deployments.scope_provenance IS
    'How the deployment target authorization relation was established.';

-- Classified inserts must agree with one exact active Server CI and the current
-- approved package row. Status transitions re-check the exact current CMDB/site
-- relation, while keeping the originally persisted package version stable even
-- if the catalog later advances. Unresolved legacy rows cannot transition.
CREATE OR REPLACE FUNCTION enforce_software_deployment_authority_relation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.scope_provenance = 'unresolved-legacy'
    THEN
        RAISE EXCEPTION 'unresolved legacy software deployment cannot transition';
    END IF;

    IF NEW.scope_provenance = 'cmdb-configuration-item' THEN
        PERFORM 1
        FROM configuration_items AS ci
        INNER JOIN site_registry AS sr
                ON sr.unlocode = ci.site AND sr.active = true
        WHERE ci.id = NEW.configuration_item_id
          AND ci.ci_name = NEW.server_name
          AND ci.ci_type = 'Server'
          AND ci.site = NEW.site
          AND ci.environment = NEW.environment
        FOR NO KEY UPDATE OF ci, sr;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'software deployment requires an exact active CMDB target relation';
        END IF;

        IF TG_OP = 'INSERT' THEN
            PERFORM 1
            FROM approved_packages AS approved_package
            WHERE approved_package.id = NEW.package_id
              AND approved_package.name = NEW.package_name
              AND approved_package.version = NEW.target_version
              AND (
                    approved_package.site_scope = 'all'
                    OR (
                        approved_package.site_scope = 'specific'
                        AND NEW.site = ANY(approved_package.site_scope_list)
                    )
              )
            FOR NO KEY UPDATE OF approved_package;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'software deployment requires exact approved package authority';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_software_deployment_authority_relation_insert
BEFORE INSERT
ON software_deployments
FOR EACH ROW
EXECUTE FUNCTION enforce_software_deployment_authority_relation();

CREATE TRIGGER trg_software_deployment_authority_relation_transition
BEFORE UPDATE OF status
ON software_deployments
FOR EACH ROW
EXECUTE FUNCTION enforce_software_deployment_authority_relation();

-- Target, package, and maker authority are plan facts, not mutable lifecycle
-- fields. Approval/execution/verification may advance status and evidence, but
-- cannot silently rebind a plan to another target, scope, package, or maker.
CREATE OR REPLACE FUNCTION reject_software_deployment_authority_rebind()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.configuration_item_id IS DISTINCT FROM OLD.configuration_item_id
       OR NEW.scope_provenance IS DISTINCT FROM OLD.scope_provenance
       OR NEW.server_name IS DISTINCT FROM OLD.server_name
       OR NEW.site IS DISTINCT FROM OLD.site
       OR NEW.environment IS DISTINCT FROM OLD.environment
       OR NEW.package_id IS DISTINCT FROM OLD.package_id
       OR NEW.package_name IS DISTINCT FROM OLD.package_name
       OR NEW.target_version IS DISTINCT FROM OLD.target_version
       OR NEW.requester IS DISTINCT FROM OLD.requester
       OR NEW.maker_user_id IS DISTINCT FROM OLD.maker_user_id
    THEN
        RAISE EXCEPTION 'software deployment authorization provenance is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_software_deployment_authority_immutable
BEFORE UPDATE OF
    configuration_item_id,
    scope_provenance,
    server_name,
    site,
    environment,
    package_id,
    package_name,
    target_version,
    requester,
    maker_user_id
ON software_deployments
FOR EACH ROW
EXECUTE FUNCTION reject_software_deployment_authority_rebind();
