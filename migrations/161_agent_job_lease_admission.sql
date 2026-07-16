-- 161_agent_job_lease_admission.sql — capability-aware, bounded agent leasing.
--
-- Job requirements are derived by the database from the control-plane-authored
-- JobSpec using an explicit allowlist of wired execution offerings.  A caller
-- cannot supply or override the generated value. Unknown/legacy offerings are
-- deliberately classified as `unclassified`, which the matcher never accepts.
-- This keeps every current and future INSERT path fail closed without relying
-- on each caller to remember a second authorization column.

CREATE OR REPLACE FUNCTION ryuki_agent_job_required_capabilities(job_spec JSONB)
RETURNS JSONB
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    offering TEXT;
BEGIN
    IF jsonb_typeof(job_spec) IS DISTINCT FROM 'object'
       OR jsonb_typeof(job_spec->'iac_ref') IS DISTINCT FROM 'string'
    THEN
        RETURN '{"tool":"unclassified"}'::jsonb;
    END IF;

    offering := split_part(job_spec->>'iac_ref', '@', 1);

    -- These labels mirror the closed, embedded IaC registry and the execution
    -- agent's runner selection. Do not add a generic substring/default rule:
    -- an unknown offering must be reviewed before it becomes dispatchable.
    CASE offering
        WHEN 'patch-maintenance',
             'zabbix-onboarding',
             'controlled-restore-request'
        THEN
            RETURN '{"tool":"ansible","provider_versions":{}}'::jsonb;

        WHEN 'linux-server-deployment',
             'windows-server-deployment'
        THEN
            -- Both embedded lock files pin source `vmware/vsphere` to this
            -- exact version. Capability documents use Terraform's local
            -- provider key `vsphere` (the protocol's documented convention),
            -- not the registry source address. The agent's approved tool
            -- version remains independently reviewed; no repository policy
            -- currently pins one Terraform CLI version.
            RETURN '{"tool":"terraform","provider_versions":{"vsphere":"2.16.1"}}'::jsonb;

        WHEN 'request-preflight'
        THEN
            RETURN '{"tool":"terraform","provider_versions":{}}'::jsonb;

        ELSE
            RETURN '{"tool":"unclassified"}'::jsonb;
    END CASE;
END;
$$;

-- Exact matcher for the administrator-approved Capabilities document and the
-- normalized requirement above. Optional requirement.version is supported for
-- future reviewed tool-version policy and is always an exact string match;
-- version ranges are intentionally not guessed or compared lexicographically.
CREATE OR REPLACE FUNCTION ryuki_agent_capabilities_satisfy_requirement(
    approved JSONB,
    requirement JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    tool_name TEXT;
    tool_capability JSONB;
    required_providers JSONB;
    approved_providers JSONB;
    required_provider RECORD;
BEGIN
    IF jsonb_typeof(approved) IS DISTINCT FROM 'object'
       OR jsonb_typeof(requirement) IS DISTINCT FROM 'object'
    THEN
        RETURN FALSE;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_object_keys(approved) AS approved_key(key)
        WHERE approved_key.key NOT IN ('terraform', 'ansible')
    ) THEN
        RETURN FALSE;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_object_keys(requirement) AS requirement_key(key)
        WHERE requirement_key.key NOT IN ('tool', 'version', 'provider_versions')
    ) THEN
        RETURN FALSE;
    END IF;

    IF jsonb_typeof(requirement->'tool') IS DISTINCT FROM 'string' THEN
        RETURN FALSE;
    END IF;
    tool_name := requirement->>'tool';
    IF tool_name NOT IN ('terraform', 'ansible') THEN
        RETURN FALSE;
    END IF;

    tool_capability := approved->tool_name;
    IF jsonb_typeof(tool_capability) IS DISTINCT FROM 'object'
       OR jsonb_typeof(tool_capability->'version') IS DISTINCT FROM 'string'
       OR btrim(tool_capability->>'version') = ''
       OR btrim(tool_capability->>'version') IS DISTINCT FROM tool_capability->>'version'
    THEN
        RETURN FALSE;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_object_keys(tool_capability) AS capability_key(key)
        WHERE capability_key.key NOT IN ('version', 'provider_versions')
    ) THEN
        RETURN FALSE;
    END IF;

    IF requirement ? 'version' THEN
        IF jsonb_typeof(requirement->'version') IS DISTINCT FROM 'string'
           OR btrim(requirement->>'version') = ''
           OR btrim(requirement->>'version') IS DISTINCT FROM requirement->>'version'
           OR tool_capability->>'version' IS DISTINCT FROM requirement->>'version'
        THEN
            RETURN FALSE;
        END IF;
    END IF;

    required_providers := COALESCE(requirement->'provider_versions', '{}'::jsonb);
    approved_providers := COALESCE(tool_capability->'provider_versions', '{}'::jsonb);
    IF jsonb_typeof(required_providers) IS DISTINCT FROM 'object'
       OR jsonb_typeof(approved_providers) IS DISTINCT FROM 'object'
       OR (
           tool_name = 'ansible'
           AND (
               required_providers <> '{}'::jsonb
               OR approved_providers <> '{}'::jsonb
           )
       )
    THEN
        RETURN FALSE;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_each(approved_providers) AS approved_provider(key, value)
        WHERE approved_provider.key = ''
           OR btrim(approved_provider.key) IS DISTINCT FROM approved_provider.key
           OR jsonb_typeof(approved_provider.value) IS DISTINCT FROM 'string'
           OR btrim(approved_provider.value #>> '{}') = ''
           OR btrim(approved_provider.value #>> '{}')
              IS DISTINCT FROM (approved_provider.value #>> '{}')
    ) THEN
        RETURN FALSE;
    END IF;

    FOR required_provider IN
        SELECT key, value
        FROM jsonb_each(required_providers)
    LOOP
        IF required_provider.key = ''
           OR btrim(required_provider.key) IS DISTINCT FROM required_provider.key
           OR jsonb_typeof(required_provider.value) IS DISTINCT FROM 'string'
           OR btrim(required_provider.value #>> '{}') = ''
           OR btrim(required_provider.value #>> '{}')
              IS DISTINCT FROM (required_provider.value #>> '{}')
           OR approved_providers->>required_provider.key
              IS DISTINCT FROM required_provider.value #>> '{}'
        THEN
            RETURN FALSE;
        END IF;
    END LOOP;

    RETURN TRUE;
END;
$$;

ALTER TABLE agent_jobs
    ADD COLUMN required_capabilities JSONB
    GENERATED ALWAYS AS (ryuki_agent_job_required_capabilities(spec)) STORED,
    ADD CONSTRAINT agent_jobs_required_capabilities_shape
    CHECK (
        jsonb_typeof(required_capabilities) = 'object'
        AND jsonb_typeof(required_capabilities->'tool') = 'string'
    );

-- Supports the active-lease admission check. This is intentionally non-unique:
-- existing over-cap rows remain representable during rollout, but the API will
-- not grant that agent another lease until all but zero active rows drain.
CREATE INDEX idx_agent_jobs_active_agent
    ON agent_jobs (agent_id)
    WHERE status IN ('Leased', 'Running');

-- Rolling/rollback bridge: an older API replica would otherwise keep running
-- its capability-blind, unbounded UPDATE after this migration. New replicas
-- set this transaction-local marker only after locking/revalidating the exact
-- approved agent row. The trigger does not acquire an agent lock itself (which
-- would invert the new agent->job lock order and introduce a deadlock).
CREATE OR REPLACE FUNCTION enforce_agent_job_lease_contract_v2()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('ryuki.agent_job_lease_contract', TRUE) IS DISTINCT FROM '2' THEN
        RAISE EXCEPTION 'agent job lease requires capability-aware bounded admission'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER enforce_agent_job_lease_contract_v2_trigger
BEFORE UPDATE OF status ON agent_jobs
FOR EACH ROW
WHEN (OLD.status = 'Pending' AND NEW.status = 'Leased')
EXECUTE FUNCTION enforce_agent_job_lease_contract_v2();
