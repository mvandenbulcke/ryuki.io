-- Migration 067: enum CHECK constraints on datacenter_readiness_checks.
--
-- Parity with the other readiness/capacity tables (e.g. backup_repositories,
-- migration 038) which already constrain their enum columns. Without these, a
-- bad manual/imported check_type or status would persist and turn the affected
-- reads into 500s (the engine decodes these strictly). The migration-040 seed
-- rows already use the canonical kebab-case values, so this applies cleanly.

ALTER TABLE datacenter_readiness_checks
    ADD CONSTRAINT datacenter_readiness_checks_check_type_check
        CHECK (check_type IN ('power', 'cooling', 'rack-space', 'switchport', 'firmware', 'capacity')),
    ADD CONSTRAINT datacenter_readiness_checks_status_check
        CHECK (status IN ('passed', 'failed', 'warning', 'not-checked'));
