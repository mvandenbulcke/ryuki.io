-- Bind every new VM Day-2 operation to one exact active Server CI. Request
-- strings are descriptive lookup input only: site and environment are copied
-- from the locked CMDB row, and the immutable UUID/provenance relation is
-- revalidated by PostgreSQL on every lifecycle write.
ALTER TABLE vm_day2_operations
    ADD COLUMN configuration_item_id UUID
        REFERENCES configuration_items(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD COLUMN target_provenance TEXT NOT NULL DEFAULT 'unresolved-legacy';

ALTER TABLE vm_day2_operations
    ADD CONSTRAINT vm_day2_operations_target_provenance_check
        CHECK (target_provenance IN (
            'unresolved-legacy',
            'cmdb-configuration-item'
        )),
    ADD CONSTRAINT vm_day2_operations_target_authority_complete
        CHECK (
            (
                target_provenance = 'unresolved-legacy'
                AND configuration_item_id IS NULL
                AND (
                    plan_json IS NULL
                    OR plan_json #> '{target_authority}' IS NULL
                )
            )
            OR
            (
                target_provenance = 'cmdb-configuration-item'
                AND configuration_item_id IS NOT NULL
                AND target_ci_key = BTRIM(target_ci_key)
                AND target_ci_key <> ''
                AND site = BTRIM(site)
                AND site <> ''
                AND environment = BTRIM(environment)
                AND environment <> ''
                AND plan_json IS NOT NULL
                AND plan_json #>> '{target_authority,configuration_item_id}' =
                    configuration_item_id::text
                AND plan_json #>> '{target_authority,provenance}' =
                    target_provenance
                AND plan_json #>> '{id}' = id::text
                AND plan_json #>> '{target_ci_key}' = target_ci_key
                AND plan_json #>> '{site}' = site
                AND plan_json #>> '{environment}' = environment
                AND plan_json #>> '{owner}' = owner
                AND plan_json #>> '{status}' = status
            )
        );

CREATE INDEX idx_vm_day2_operations_authoritative_target
    ON vm_day2_operations(
        configuration_item_id,
        site,
        environment,
        created_at,
        id
    )
    WHERE target_provenance = 'cmdb-configuration-item';

COMMENT ON COLUMN vm_day2_operations.configuration_item_id IS
    'Immutable authoritative CMDB Server UUID; NULL identifies unresolved legacy provenance.';
COMMENT ON COLUMN vm_day2_operations.target_provenance IS
    'How the VM Day-2 target authorization relation was established.';

-- Classified inserts and every plan/status rewrite lock and re-check the exact
-- current Server CI plus its active canonical site. Unresolved legacy rows may
-- be read for reconciliation but cannot transition.
CREATE OR REPLACE FUNCTION enforce_vm_day2_target_authority_relation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.target_provenance = 'unresolved-legacy' THEN
        RAISE EXCEPTION 'unresolved legacy VM Day-2 operation cannot be inserted or transitioned';
    END IF;

    IF TG_OP = 'INSERT' AND NEW.status <> 'Planned' THEN
        RAISE EXCEPTION 'new VM Day-2 operation must start in Planned status';
    END IF;

    PERFORM 1
    FROM configuration_items AS ci
    INNER JOIN site_registry AS sr
            ON sr.unlocode = ci.site AND sr.active = true
    WHERE ci.id = NEW.configuration_item_id
      AND ci.ci_name = NEW.target_ci_key
      AND ci.ci_type = 'Server'
      AND ci.site = NEW.site
      AND ci.environment = NEW.environment
    FOR NO KEY UPDATE OF ci, sr;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'VM Day-2 operation requires an exact active CMDB Server target';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_vm_day2_target_authority_insert
BEFORE INSERT
ON vm_day2_operations
FOR EACH ROW
EXECUTE FUNCTION enforce_vm_day2_target_authority_relation();

CREATE TRIGGER trg_vm_day2_target_authority_transition
BEFORE UPDATE OF status, plan_json
ON vm_day2_operations
FOR EACH ROW
EXECUTE FUNCTION enforce_vm_day2_target_authority_relation();

-- Target identity, provenance, and the copied authorization axes are plan
-- facts. Lifecycle evidence may evolve, but direct SQL cannot rebind either
-- the scalar columns or their embedded plan representation.
CREATE OR REPLACE FUNCTION reject_vm_day2_target_authority_rebind()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.configuration_item_id IS DISTINCT FROM OLD.configuration_item_id
       OR NEW.target_provenance IS DISTINCT FROM OLD.target_provenance
       OR NEW.target_ci_key IS DISTINCT FROM OLD.target_ci_key
       OR NEW.site IS DISTINCT FROM OLD.site
       OR NEW.environment IS DISTINCT FROM OLD.environment
       OR NEW.owner IS DISTINCT FROM OLD.owner
       OR (NEW.plan_json #> '{target_authority}')
            IS DISTINCT FROM (OLD.plan_json #> '{target_authority}')
       OR (NEW.plan_json #> '{target_ci_key}')
            IS DISTINCT FROM (OLD.plan_json #> '{target_ci_key}')
       OR (NEW.plan_json #> '{site}') IS DISTINCT FROM (OLD.plan_json #> '{site}')
       OR (NEW.plan_json #> '{environment}')
            IS DISTINCT FROM (OLD.plan_json #> '{environment}')
       OR (NEW.plan_json #> '{owner}') IS DISTINCT FROM (OLD.plan_json #> '{owner}')
    THEN
        RAISE EXCEPTION 'VM Day-2 target authorization provenance is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_vm_day2_target_authority_immutable
BEFORE UPDATE OF
    configuration_item_id,
    target_provenance,
    target_ci_key,
    site,
    environment,
    owner,
    plan_json
ON vm_day2_operations
FOR EACH ROW
EXECUTE FUNCTION reject_vm_day2_target_authority_rebind();
