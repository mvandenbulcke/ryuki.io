-- Permanent storage for an externally verified, deployment-bound first-owner
-- closure certificate. This is a storage boundary, not the bootstrap
-- authority: no runtime role may write it, and the owner-only writer below
-- must be called only after independent signature/capability verification.

SET LOCAL lock_timeout = '30s';

CREATE OR REPLACE FUNCTION first_owner_text_array_is_canonical(items TEXT[])
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
DECLARE
    item TEXT;
    previous TEXT := NULL;
BEGIN
    IF cardinality(items) NOT BETWEEN 1 AND 64 THEN
        RETURN FALSE;
    END IF;
    FOREACH item IN ARRAY items LOOP
        IF item IS NULL
           OR item !~ '^trust-domain:[a-z0-9][a-z0-9._-]{2,126}$'
           OR (previous IS NOT NULL AND previous COLLATE "C" >= item COLLATE "C")
        THEN
            RETURN FALSE;
        END IF;
        previous := item;
    END LOOP;
    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION first_owner_json_has_exact_keys(
    p_value JSONB,
    p_expected_keys TEXT[]
)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
    SELECT jsonb_typeof(p_value) = 'object'
       AND COALESCE(
            (
                SELECT array_agg(key ORDER BY key COLLATE "C")
                FROM jsonb_object_keys(p_value) AS object_keys(key)
            ),
            ARRAY[]::TEXT[]
       ) = p_expected_keys;
$$;

CREATE TABLE first_owner_closure_records (
    deployment_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    contract_kind TEXT NOT NULL,
    canonicalization TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    state_contract_version BIGINT NOT NULL,
    trust_domain_ids TEXT[] NOT NULL,
    tenancy_mode TEXT NOT NULL,
    tenant_id TEXT,
    authority_id TEXT NOT NULL,
    authority_key_id TEXT NOT NULL,
    authority_public_key_fingerprint TEXT NOT NULL,
    authority_epoch BIGINT NOT NULL,
    namespace_id TEXT NOT NULL,
    authority_namespace_digest TEXT NOT NULL,
    closure_status TEXT NOT NULL,
    closure_event_id TEXT NOT NULL UNIQUE,
    authority_sequence BIGINT NOT NULL,
    first_owner_principal_id TEXT NOT NULL,
    claim_request_digest TEXT NOT NULL UNIQUE,
    capability_id TEXT NOT NULL UNIQUE,
    capability_expires_at_text TEXT NOT NULL,
    capability_expires_at TIMESTAMPTZ NOT NULL,
    closed_at_not_before_text TEXT NOT NULL,
    closed_at_not_before TIMESTAMPTZ NOT NULL,
    closed_at_not_after_text TEXT NOT NULL,
    closed_at_not_after TIMESTAMPTZ NOT NULL,
    certificate_document JSONB NOT NULL,
    certificate_bytes BYTEA NOT NULL,
    closure_certificate_digest TEXT NOT NULL UNIQUE,
    authority_signature BYTEA NOT NULL,
    authority_signature_digest TEXT NOT NULL,
    closure_record_digest TEXT NOT NULL UNIQUE,
    audit_log_id BIGINT NOT NULL UNIQUE
        REFERENCES audit_log(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    domain_event_id BIGINT NOT NULL UNIQUE
        REFERENCES domain_events(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT first_owner_schema_version_check
        CHECK (schema_version = '1.0.0'),
    CONSTRAINT first_owner_contract_kind_check
        CHECK (contract_kind = 'first-owner-closure-certificate'),
    CONSTRAINT first_owner_canonicalization_check
        CHECK (canonicalization = 'ryuki-canonical-json-v1'),
    CONSTRAINT first_owner_signature_algorithm_check
        CHECK (signature_algorithm = 'ed25519'),
    CONSTRAINT first_owner_state_contract_check
        CHECK (state_contract_version > 0),
    CONSTRAINT first_owner_deployment_id_check CHECK (
        deployment_id ~ '^deployment:[a-z0-9][a-z0-9._-]{2,126}$'
    ),
    CONSTRAINT first_owner_trust_domains_check CHECK (
        first_owner_text_array_is_canonical(trust_domain_ids)
    ),
    CONSTRAINT first_owner_tenant_shape_check CHECK (
        (tenancy_mode = 'single_tenant' AND tenant_id IS NULL)
        OR (
            tenancy_mode = 'multi_tenant'
            AND tenant_id ~ '^tenant:[a-z0-9][a-z0-9._-]{2,126}$'
        )
    ),
    CONSTRAINT first_owner_authority_identifiers_check CHECK (
        authority_id ~ '^[a-z0-9][a-z0-9._:/-]{2,254}$'
        AND authority_key_id ~ '^[a-z0-9][a-z0-9._:/-]{2,254}$'
        AND namespace_id ~ '^[a-z0-9][a-z0-9._:/-]{2,254}$'
    ),
    CONSTRAINT first_owner_closure_identifiers_check CHECK (
        closure_event_id ~ '^[a-z0-9][a-z0-9._:/-]{2,254}$'
        AND first_owner_principal_id ~ '^[a-z0-9][a-z0-9._:/-]{2,254}$'
        AND capability_id ~ '^[a-z0-9][a-z0-9._:/-]{2,254}$'
    ),
    CONSTRAINT first_owner_authority_counters_check CHECK (
        authority_epoch > 0 AND authority_sequence > 0
    ),
    CONSTRAINT first_owner_closure_status_check
        CHECK (closure_status = 'closed'),
    CONSTRAINT first_owner_timestamps_check CHECK (
        closed_at_not_before <= closed_at_not_after
        AND closed_at_not_after < capability_expires_at
        AND closed_at_not_after <= recorded_at
        AND recorded_at < capability_expires_at
    ),
    CONSTRAINT first_owner_timestamp_text_shape_check CHECK (
        capability_expires_at_text ~
            '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$'
        AND closed_at_not_before_text ~
            '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$'
        AND closed_at_not_after_text ~
            '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$'
        AND capability_expires_at_text::TIMESTAMPTZ = capability_expires_at
        AND closed_at_not_before_text::TIMESTAMPTZ = closed_at_not_before
        AND closed_at_not_after_text::TIMESTAMPTZ = closed_at_not_after
    ),
    CONSTRAINT first_owner_certificate_size_check CHECK (
        octet_length(certificate_bytes) BETWEEN 1 AND 262144
    ),
    CONSTRAINT first_owner_signature_size_check CHECK (
        octet_length(authority_signature) = 64
    ),
    CONSTRAINT first_owner_certificate_digest_check CHECK (
        closure_certificate_digest =
            'sha256:' || encode(sha256(certificate_bytes), 'hex')
        AND closure_certificate_digest !~ '^sha256:0{64}$'
    ),
    CONSTRAINT first_owner_signature_digest_check CHECK (
        authority_signature_digest =
            'sha256:' || encode(sha256(authority_signature), 'hex')
        AND authority_signature_digest !~ '^sha256:0{64}$'
    ),
    CONSTRAINT first_owner_digest_shapes_check CHECK (
        authority_public_key_fingerprint ~ '^sha256:[0-9a-f]{64}$'
        AND authority_public_key_fingerprint !~ '^sha256:0{64}$'
        AND authority_namespace_digest ~ '^sha256:[0-9a-f]{64}$'
        AND authority_namespace_digest !~ '^sha256:0{64}$'
        AND claim_request_digest ~ '^sha256:[0-9a-f]{64}$'
        AND claim_request_digest !~ '^sha256:0{64}$'
        AND closure_record_digest ~ '^sha256:[0-9a-f]{64}$'
        AND closure_record_digest !~ '^sha256:0{64}$'
    ),
    CONSTRAINT first_owner_linkage_key UNIQUE (
        deployment_id,
        first_owner_principal_id,
        closure_event_id,
        closure_certificate_digest
    )
);

CREATE TABLE first_owner_privileged_domain_assignments (
    deployment_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    assignment_event_id TEXT NOT NULL UNIQUE,
    principal_id TEXT NOT NULL,
    first_owner_principal_id TEXT NOT NULL,
    closure_event_id TEXT NOT NULL,
    closure_certificate_digest TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (deployment_id, domain_id),
    CONSTRAINT first_owner_domain_id_check CHECK (domain_id IN (
        'audit-administration',
        'identity-administration',
        'live-execution-administration',
        'policy-administration',
        'secret-key-custody'
    )),
    CONSTRAINT first_owner_domain_identifiers_check CHECK (
        assignment_event_id ~ '^[a-z0-9][a-z0-9._:/-]{2,254}$'
        AND principal_id ~ '^[a-z0-9][a-z0-9._:/-]{2,254}$'
    ),
    CONSTRAINT first_owner_domain_linkage_fk FOREIGN KEY (
        deployment_id,
        first_owner_principal_id,
        closure_event_id,
        closure_certificate_digest
    ) REFERENCES first_owner_closure_records (
        deployment_id,
        first_owner_principal_id,
        closure_event_id,
        closure_certificate_digest
    ) ON UPDATE RESTRICT ON DELETE RESTRICT
);

-- These two helpers intentionally mirror the serde field names and wrapper
-- objects in ryuki_core::security_profile byte-for-byte.
CREATE OR REPLACE FUNCTION first_owner_authority_namespace_digest(
    p_record first_owner_closure_records
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT 'sha256:' || encode(sha256(convert_to(
        public.audit_canonical_json(jsonb_build_object(
            'authority_namespace', jsonb_build_object(
                'authority_epoch', p_record.authority_epoch,
                'authority_id', p_record.authority_id,
                'authority_key_id', p_record.authority_key_id,
                'authority_public_key_fingerprint',
                    p_record.authority_public_key_fingerprint,
                'deployment_id', p_record.deployment_id,
                'namespace_id', p_record.namespace_id,
                'state_contract_version', p_record.state_contract_version,
                'tenancy_mode', p_record.tenancy_mode,
                'tenant_id', p_record.tenant_id,
                'trust_domain_ids', to_jsonb(p_record.trust_domain_ids)
            ),
            'digest_contract', 'ryuki-first-owner-authority-namespace-v1'
        )),
        'UTF8'
    )), 'hex');
$$;

CREATE OR REPLACE FUNCTION first_owner_closure_record_digest(
    p_record first_owner_closure_records
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    -- Hash the exact validated signed strings, not a TIMESTAMPTZ rendering:
    -- PostgreSQL normalizes timestamp text while the core contract binds the
    -- original seconds-only RFC3339 bytes. Typed columns establish ordering.
    SELECT 'sha256:' || encode(sha256(convert_to(
        public.audit_canonical_json(jsonb_build_object(
            'closure_record', jsonb_build_object(
                'authority_namespace_digest', p_record.authority_namespace_digest,
                'authority_sequence', p_record.authority_sequence,
                'capability_expires_at', p_record.capability_expires_at_text,
                'capability_id', p_record.capability_id,
                'claim_request_digest', p_record.claim_request_digest,
                'closed_at_not_after', p_record.closed_at_not_after_text,
                'closed_at_not_before', p_record.closed_at_not_before_text,
                'closure_certificate_digest', p_record.closure_certificate_digest,
                'closure_event_id', p_record.closure_event_id,
                'deployment_id', p_record.deployment_id,
                'first_owner_principal_id', p_record.first_owner_principal_id,
                'state_contract_version', p_record.state_contract_version,
                'status', p_record.closure_status
            ),
            'digest_contract', 'ryuki-first-owner-closure-record-v1'
        )),
        'UTF8'
    )), 'hex');
$$;

CREATE OR REPLACE FUNCTION first_owner_closure_writer_contract_is_held(
    p_deployment_id TEXT
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT current_setting('ryuki.first_owner_closure_writer_contract', TRUE) = '1'
       AND EXISTS (
            SELECT 1
            FROM pg_locks AS held
            WHERE held.locktype = 'advisory'
              AND held.pid = pg_backend_pid()
              AND held.mode = 'ExclusiveLock'
              AND held.database = (
                    SELECT oid FROM pg_database WHERE datname = current_database()
              )
              AND held.classid::BIGINT = (
                    (hashtextextended(
                        'ryuki:first-owner-closure:v1:' || p_deployment_id, 0
                    ) >> 32) & 4294967295
              )
              AND held.objid::BIGINT = (
                    hashtextextended(
                        'ryuki:first-owner-closure:v1:' || p_deployment_id, 0
                    ) & 4294967295
              )
              AND held.objsubid = 1
              AND held.granted
       );
$$;

-- Predeclare the owner-only entry point so the SECURITY INVOKER insert
-- triggers can bind its immutable owner identity. The complete atomic body
-- replaces this fail-closed stub below in the same migration transaction.
CREATE OR REPLACE FUNCTION store_authority_verified_first_owner_closure(
    p_certificate_bytes BYTEA
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'first-owner closure storage is not initialized'
        USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION enforce_first_owner_closure_insert()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE
    namespace JSONB := NEW.certificate_document->'authority_namespace';
    closure JSONB := NEW.certificate_document->'closure';
    signature_base64 TEXT := NEW.certificate_document->>'signature_base64';
    writer_owner NAME;
BEGIN
    SELECT pg_get_userbyid(proowner)
    INTO writer_owner
    FROM pg_proc
    WHERE oid =
        'public.store_authority_verified_first_owner_closure(bytea)'::regprocedure;
    IF current_user IS DISTINCT FROM writer_owner
       OR NOT public.first_owner_closure_writer_contract_is_held(NEW.deployment_id)
    THEN
        RAISE EXCEPTION 'first-owner closure writer contract v1 is required'
            USING ERRCODE = '42501';
    END IF;

    NEW.recorded_at := statement_timestamp();
    IF NEW.certificate_bytes IS DISTINCT FROM convert_to(
        public.audit_canonical_json(NEW.certificate_document), 'UTF8'
    ) THEN
        RAISE EXCEPTION 'first-owner certificate bytes are not canonical JSON'
            USING ERRCODE = '23514';
    END IF;

    IF jsonb_typeof(NEW.certificate_document) IS DISTINCT FROM 'object'
       OR jsonb_typeof(namespace) IS DISTINCT FROM 'object'
       OR jsonb_typeof(closure) IS DISTINCT FROM 'object'
       OR jsonb_typeof(
            NEW.certificate_document->'privileged_domain_assignments'
       ) IS DISTINCT FROM 'array'
       OR jsonb_typeof(NEW.certificate_document->'schema_version')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(NEW.certificate_document->'contract_kind')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(NEW.certificate_document->'canonicalization')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(NEW.certificate_document->'signature_algorithm')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(NEW.certificate_document->'signature_base64')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(namespace->'state_contract_version')
            IS DISTINCT FROM 'number'
       OR namespace->>'state_contract_version' !~ '^(0|[1-9][0-9]*)$'
       OR jsonb_typeof(namespace->'deployment_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(namespace->'trust_domain_ids') IS DISTINCT FROM 'array'
       OR EXISTS (
            SELECT 1
            FROM jsonb_array_elements(namespace->'trust_domain_ids') AS item(value)
            WHERE jsonb_typeof(item.value) IS DISTINCT FROM 'string'
       )
       OR jsonb_typeof(namespace->'tenancy_mode') IS DISTINCT FROM 'string'
       OR (
            jsonb_typeof(namespace->'tenant_id') IS DISTINCT FROM 'null'
            AND jsonb_typeof(namespace->'tenant_id') IS DISTINCT FROM 'string'
       )
       OR jsonb_typeof(namespace->'authority_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(namespace->'authority_key_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(namespace->'authority_public_key_fingerprint')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(namespace->'authority_epoch') IS DISTINCT FROM 'number'
       OR namespace->>'authority_epoch' !~ '^(0|[1-9][0-9]*)$'
       OR jsonb_typeof(namespace->'namespace_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(closure->'state_contract_version')
            IS DISTINCT FROM 'number'
       OR closure->>'state_contract_version' !~ '^(0|[1-9][0-9]*)$'
       OR jsonb_typeof(closure->'deployment_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(closure->'authority_namespace_digest')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(closure->'status') IS DISTINCT FROM 'string'
       OR jsonb_typeof(closure->'closure_event_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(closure->'authority_sequence') IS DISTINCT FROM 'number'
       OR closure->>'authority_sequence' !~ '^(0|[1-9][0-9]*)$'
       OR jsonb_typeof(closure->'first_owner_principal_id')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(closure->'claim_request_digest')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(closure->'capability_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(closure->'capability_expires_at')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(closure->'closed_at_not_before')
            IS DISTINCT FROM 'string'
       OR jsonb_typeof(closure->'closed_at_not_after')
            IS DISTINCT FROM 'string'
    THEN
        RAISE EXCEPTION 'first-owner certificate has an invalid JSON scalar type'
            USING ERRCODE = '23514';
    END IF;

    IF NOT public.first_owner_json_has_exact_keys(
        NEW.certificate_document,
        ARRAY[
            'authority_namespace', 'canonicalization', 'closure',
            'contract_kind', 'privileged_domain_assignments', 'schema_version',
            'signature_algorithm', 'signature_base64'
        ]::TEXT[]
    ) OR NOT public.first_owner_json_has_exact_keys(
        namespace,
        ARRAY[
            'authority_epoch', 'authority_id', 'authority_key_id',
            'authority_public_key_fingerprint', 'deployment_id', 'namespace_id',
            'state_contract_version', 'tenancy_mode', 'tenant_id',
            'trust_domain_ids'
        ]::TEXT[]
    ) OR NOT public.first_owner_json_has_exact_keys(
        closure,
        ARRAY[
            'authority_namespace_digest', 'authority_sequence',
            'capability_expires_at', 'capability_id', 'claim_request_digest',
            'closed_at_not_after', 'closed_at_not_before', 'closure_event_id',
            'deployment_id', 'first_owner_principal_id',
            'state_contract_version', 'status'
        ]::TEXT[]
    ) THEN
        RAISE EXCEPTION 'first-owner certificate has an open or incomplete object shape'
            USING ERRCODE = '23514';
    END IF;

    IF jsonb_typeof(NEW.certificate_document->'privileged_domain_assignments')
            IS DISTINCT FROM 'array'
       OR jsonb_array_length(
            NEW.certificate_document->'privileged_domain_assignments'
       ) IS DISTINCT FROM 5
       OR EXISTS (
            SELECT 1
            FROM jsonb_array_elements(
                NEW.certificate_document->'privileged_domain_assignments'
            ) AS assignment(value)
            WHERE NOT public.first_owner_json_has_exact_keys(
                assignment.value,
                ARRAY['assignment_event_id', 'domain_id', 'principal_id']::TEXT[]
            )
               OR jsonb_typeof(assignment.value->'assignment_event_id')
                    IS DISTINCT FROM 'string'
               OR jsonb_typeof(assignment.value->'domain_id')
                    IS DISTINCT FROM 'string'
               OR jsonb_typeof(assignment.value->'principal_id')
                    IS DISTINCT FROM 'string'
       )
    THEN
        RAISE EXCEPTION 'first-owner certificate has an invalid privileged-domain set'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.certificate_document->>'schema_version'
            IS DISTINCT FROM NEW.schema_version
       OR NEW.certificate_document->>'contract_kind'
            IS DISTINCT FROM NEW.contract_kind
       OR NEW.certificate_document->>'canonicalization'
            IS DISTINCT FROM NEW.canonicalization
       OR NEW.certificate_document->>'signature_algorithm'
            IS DISTINCT FROM NEW.signature_algorithm
       OR (namespace->>'state_contract_version')::BIGINT
            IS DISTINCT FROM NEW.state_contract_version
       OR namespace->>'deployment_id' IS DISTINCT FROM NEW.deployment_id
       OR ARRAY(SELECT jsonb_array_elements_text(namespace->'trust_domain_ids'))
            IS DISTINCT FROM NEW.trust_domain_ids
       OR namespace->>'tenancy_mode' IS DISTINCT FROM NEW.tenancy_mode
       OR namespace->>'tenant_id' IS DISTINCT FROM NEW.tenant_id
       OR namespace->>'authority_id' IS DISTINCT FROM NEW.authority_id
       OR namespace->>'authority_key_id' IS DISTINCT FROM NEW.authority_key_id
       OR namespace->>'authority_public_key_fingerprint'
            IS DISTINCT FROM NEW.authority_public_key_fingerprint
       OR (namespace->>'authority_epoch')::BIGINT
            IS DISTINCT FROM NEW.authority_epoch
       OR namespace->>'namespace_id' IS DISTINCT FROM NEW.namespace_id
       OR (closure->>'state_contract_version')::BIGINT
            IS DISTINCT FROM NEW.state_contract_version
       OR closure->>'deployment_id' IS DISTINCT FROM NEW.deployment_id
       OR closure->>'authority_namespace_digest'
            IS DISTINCT FROM NEW.authority_namespace_digest
       OR closure->>'status' IS DISTINCT FROM NEW.closure_status
       OR closure->>'closure_event_id' IS DISTINCT FROM NEW.closure_event_id
       OR (closure->>'authority_sequence')::BIGINT
            IS DISTINCT FROM NEW.authority_sequence
       OR closure->>'first_owner_principal_id'
            IS DISTINCT FROM NEW.first_owner_principal_id
       OR closure->>'claim_request_digest'
            IS DISTINCT FROM NEW.claim_request_digest
       OR closure->>'capability_id' IS DISTINCT FROM NEW.capability_id
       OR closure->>'capability_expires_at'
            IS DISTINCT FROM NEW.capability_expires_at_text
       OR closure->>'closed_at_not_before'
            IS DISTINCT FROM NEW.closed_at_not_before_text
       OR closure->>'closed_at_not_after'
            IS DISTINCT FROM NEW.closed_at_not_after_text
       OR (closure->>'capability_expires_at')::TIMESTAMPTZ
            IS DISTINCT FROM NEW.capability_expires_at
       OR (closure->>'closed_at_not_before')::TIMESTAMPTZ
            IS DISTINCT FROM NEW.closed_at_not_before
       OR (closure->>'closed_at_not_after')::TIMESTAMPTZ
            IS DISTINCT FROM NEW.closed_at_not_after
    THEN
        RAISE EXCEPTION 'first-owner certificate columns do not match signed bytes'
            USING ERRCODE = '23514';
    END IF;

    IF closure->>'capability_expires_at'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$'
       OR closure->>'closed_at_not_before'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$'
       OR closure->>'closed_at_not_after'
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$'
    THEN
        RAISE EXCEPTION 'first-owner certificate timestamps are not canonical UTC RFC3339'
            USING ERRCODE = '23514';
    END IF;

    IF signature_base64 !~ '^[A-Za-z0-9+/]{86}==$'
       OR decode(signature_base64, 'base64') IS DISTINCT FROM NEW.authority_signature
    THEN
        RAISE EXCEPTION 'first-owner certificate signature is not canonical Ed25519 bytes'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.authority_namespace_digest IS DISTINCT FROM
        public.first_owner_authority_namespace_digest(NEW)
       OR NEW.closure_record_digest IS DISTINCT FROM
        public.first_owner_closure_record_digest(NEW)
    THEN
        RAISE EXCEPTION 'first-owner guard digest differs from the canonical core projection'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_first_owner_domain_insert()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE
    writer_owner NAME;
BEGIN
    SELECT pg_get_userbyid(proowner)
    INTO writer_owner
    FROM pg_proc
    WHERE oid =
        'public.store_authority_verified_first_owner_closure(bytea)'::regprocedure;
    IF current_user IS DISTINCT FROM writer_owner
       OR NOT public.first_owner_closure_writer_contract_is_held(NEW.deployment_id)
    THEN
        RAISE EXCEPTION 'first-owner closure writer contract v1 is required'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION enforce_first_owner_domain_set_complete()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    stored_assignments JSONB;
BEGIN
    SELECT jsonb_agg(
        jsonb_build_object(
            'assignment_event_id', assignment_event_id,
            'domain_id', domain_id,
            'principal_id', principal_id
        ) ORDER BY domain_id COLLATE "C"
    ) INTO stored_assignments
    FROM public.first_owner_privileged_domain_assignments
    WHERE deployment_id = NEW.deployment_id;

    IF stored_assignments IS DISTINCT FROM
        NEW.certificate_document->'privileged_domain_assignments'
    THEN
        RAISE EXCEPTION 'first-owner privileged-domain records are incomplete or differ from the certificate'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION prevent_first_owner_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'first-owner closure evidence is permanent and append-only'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER first_owner_closure_insert_contract
BEFORE INSERT ON first_owner_closure_records
FOR EACH ROW EXECUTE FUNCTION enforce_first_owner_closure_insert();
CREATE TRIGGER first_owner_closure_no_mutation
BEFORE UPDATE OR DELETE ON first_owner_closure_records
FOR EACH ROW EXECUTE FUNCTION prevent_first_owner_evidence_mutation();
CREATE TRIGGER first_owner_closure_no_truncate
BEFORE TRUNCATE ON first_owner_closure_records
FOR EACH STATEMENT EXECUTE FUNCTION prevent_first_owner_evidence_mutation();

CREATE TRIGGER first_owner_domain_insert_contract
BEFORE INSERT ON first_owner_privileged_domain_assignments
FOR EACH ROW EXECUTE FUNCTION enforce_first_owner_domain_insert();
CREATE TRIGGER first_owner_domain_no_mutation
BEFORE UPDATE OR DELETE ON first_owner_privileged_domain_assignments
FOR EACH ROW EXECUTE FUNCTION prevent_first_owner_evidence_mutation();
CREATE TRIGGER first_owner_domain_no_truncate
BEFORE TRUNCATE ON first_owner_privileged_domain_assignments
FOR EACH STATEMENT EXECUTE FUNCTION prevent_first_owner_evidence_mutation();

CREATE CONSTRAINT TRIGGER first_owner_domain_set_complete
AFTER INSERT ON first_owner_closure_records
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION enforce_first_owner_domain_set_complete();

-- Owner-only, single-statement storage API. A retry after a lost successful
-- response returns FALSE only when the exact certificate bytes already own the
-- deployment singleton; any distinct certificate is a permanent conflict.
CREATE OR REPLACE FUNCTION store_authority_verified_first_owner_closure(
    p_certificate_bytes BYTEA
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    document JSONB;
    namespace JSONB;
    closure JSONB;
    deployment TEXT;
    certificate_digest TEXT;
    signature BYTEA;
    namespace_digest TEXT;
    record_digest TEXT;
    audit_id BIGINT;
    event_id BIGINT;
    existing public.first_owner_closure_records%ROWTYPE;
    candidate public.first_owner_closure_records%ROWTYPE;
    assignment JSONB;
BEGIN
    IF p_certificate_bytes IS NULL
       OR octet_length(p_certificate_bytes) NOT BETWEEN 1 AND 262144
    THEN
        RAISE EXCEPTION 'first-owner certificate bytes are empty or oversized'
            USING ERRCODE = '22023';
    END IF;
    document := convert_from(p_certificate_bytes, 'UTF8')::JSONB;
    namespace := document->'authority_namespace';
    closure := document->'closure';
    deployment := namespace->>'deployment_id';
    IF deployment IS NULL THEN
        RAISE EXCEPTION 'first-owner certificate is missing deployment identity'
            USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'ryuki:first-owner-closure:v1:' || deployment, 0
    ));
    PERFORM set_config('ryuki.first_owner_closure_writer_contract', '1', TRUE);

    SELECT * INTO existing
    FROM public.first_owner_closure_records
    WHERE deployment_id = deployment
    FOR UPDATE;
    IF FOUND THEN
        IF existing.certificate_bytes = p_certificate_bytes THEN
            RETURN FALSE;
        END IF;
        RAISE EXCEPTION 'first-owner closure is already permanent for this deployment'
            USING ERRCODE = '23505';
    END IF;

    certificate_digest := 'sha256:' || encode(sha256(p_certificate_bytes), 'hex');
    signature := decode(document->>'signature_base64', 'base64');
    candidate.deployment_id := deployment;
    candidate.schema_version := document->>'schema_version';
    candidate.contract_kind := document->>'contract_kind';
    candidate.canonicalization := document->>'canonicalization';
    candidate.signature_algorithm := document->>'signature_algorithm';
    candidate.state_contract_version :=
        (namespace->>'state_contract_version')::BIGINT;
    candidate.trust_domain_ids := ARRAY(
        SELECT jsonb_array_elements_text(namespace->'trust_domain_ids')
    );
    candidate.tenancy_mode := namespace->>'tenancy_mode';
    candidate.tenant_id := namespace->>'tenant_id';
    candidate.authority_id := namespace->>'authority_id';
    candidate.authority_key_id := namespace->>'authority_key_id';
    candidate.authority_public_key_fingerprint :=
        namespace->>'authority_public_key_fingerprint';
    candidate.authority_epoch := (namespace->>'authority_epoch')::BIGINT;
    candidate.namespace_id := namespace->>'namespace_id';
    candidate.closure_status := closure->>'status';
    candidate.closure_event_id := closure->>'closure_event_id';
    candidate.authority_sequence := (closure->>'authority_sequence')::BIGINT;
    candidate.first_owner_principal_id := closure->>'first_owner_principal_id';
    candidate.claim_request_digest := closure->>'claim_request_digest';
    candidate.capability_id := closure->>'capability_id';
    candidate.capability_expires_at_text := closure->>'capability_expires_at';
    candidate.capability_expires_at :=
        (closure->>'capability_expires_at')::TIMESTAMPTZ;
    candidate.closed_at_not_before_text := closure->>'closed_at_not_before';
    candidate.closed_at_not_before :=
        (closure->>'closed_at_not_before')::TIMESTAMPTZ;
    candidate.closed_at_not_after_text := closure->>'closed_at_not_after';
    candidate.closed_at_not_after :=
        (closure->>'closed_at_not_after')::TIMESTAMPTZ;
    candidate.certificate_document := document;
    candidate.certificate_bytes := p_certificate_bytes;
    candidate.closure_certificate_digest := certificate_digest;
    candidate.authority_signature := signature;
    candidate.authority_signature_digest :=
        'sha256:' || encode(sha256(signature), 'hex');
    candidate.recorded_at := statement_timestamp();
    namespace_digest := public.first_owner_authority_namespace_digest(candidate);
    candidate.authority_namespace_digest := namespace_digest;
    record_digest := public.first_owner_closure_record_digest(candidate);
    candidate.closure_record_digest := record_digest;

    SELECT public.append_audit_log(
        NULL::UUID,
        closure->>'first_owner_principal_id',
        NULL::TEXT,
        ARRAY[]::TEXT[],
        'first-owner-authority',
        'platform.first-owner.close',
        NULL::TEXT,
        'bootstrap-closed',
        NULL::TEXT,
        'closed',
        jsonb_build_object(
            'authority_namespace_digest', namespace_digest,
            'closure_certificate_digest', certificate_digest,
            'closure_event_id', closure->>'closure_event_id',
            'deployment_id', deployment
        ),
        'applied'
    ) INTO audit_id;

    INSERT INTO public.domain_events (
        event_type, aggregate_type, aggregate_id, actor, payload, occurred_at
    ) VALUES (
        'platform.first-owner-closed',
        'deployment',
        deployment,
        closure->>'first_owner_principal_id',
        jsonb_build_object(
            'authority_namespace_digest', namespace_digest,
            'closure_certificate_digest', certificate_digest,
            'closure_event_id', closure->>'closure_event_id'
        ),
        (closure->>'closed_at_not_after')::TIMESTAMPTZ
    ) RETURNING id INTO event_id;

    INSERT INTO public.first_owner_closure_records (
        deployment_id, schema_version, contract_kind, canonicalization,
        signature_algorithm, state_contract_version, trust_domain_ids,
        tenancy_mode, tenant_id, authority_id, authority_key_id,
        authority_public_key_fingerprint, authority_epoch, namespace_id,
        authority_namespace_digest, closure_status, closure_event_id,
        authority_sequence, first_owner_principal_id, claim_request_digest,
        capability_id, capability_expires_at_text, capability_expires_at,
        closed_at_not_before_text, closed_at_not_before,
        closed_at_not_after_text, closed_at_not_after,
        certificate_document, certificate_bytes,
        closure_certificate_digest, authority_signature,
        authority_signature_digest, closure_record_digest,
        audit_log_id, domain_event_id
    ) VALUES (
        deployment,
        document->>'schema_version',
        document->>'contract_kind',
        document->>'canonicalization',
        document->>'signature_algorithm',
        (namespace->>'state_contract_version')::BIGINT,
        ARRAY(SELECT jsonb_array_elements_text(namespace->'trust_domain_ids')),
        namespace->>'tenancy_mode',
        namespace->>'tenant_id',
        namespace->>'authority_id',
        namespace->>'authority_key_id',
        namespace->>'authority_public_key_fingerprint',
        (namespace->>'authority_epoch')::BIGINT,
        namespace->>'namespace_id',
        namespace_digest,
        closure->>'status',
        closure->>'closure_event_id',
        (closure->>'authority_sequence')::BIGINT,
        closure->>'first_owner_principal_id',
        closure->>'claim_request_digest',
        closure->>'capability_id',
        closure->>'capability_expires_at',
        (closure->>'capability_expires_at')::TIMESTAMPTZ,
        closure->>'closed_at_not_before',
        (closure->>'closed_at_not_before')::TIMESTAMPTZ,
        closure->>'closed_at_not_after',
        (closure->>'closed_at_not_after')::TIMESTAMPTZ,
        document,
        p_certificate_bytes,
        certificate_digest,
        signature,
        'sha256:' || encode(sha256(signature), 'hex'),
        record_digest,
        audit_id,
        event_id
    ) RETURNING * INTO existing;

    FOR assignment IN
        SELECT value
        FROM jsonb_array_elements(document->'privileged_domain_assignments')
        ORDER BY value->>'domain_id' COLLATE "C"
    LOOP
        INSERT INTO public.first_owner_privileged_domain_assignments (
            deployment_id, domain_id, assignment_event_id, principal_id,
            first_owner_principal_id, closure_event_id,
            closure_certificate_digest, assigned_at
        ) VALUES (
            deployment,
            assignment->>'domain_id',
            assignment->>'assignment_event_id',
            assignment->>'principal_id',
            closure->>'first_owner_principal_id',
            closure->>'closure_event_id',
            certificate_digest,
            (closure->>'closed_at_not_after')::TIMESTAMPTZ
        );
    END LOOP;
    RETURN TRUE;
END;
$$;

COMMENT ON TABLE first_owner_closure_records IS
    'Permanent deployment-scoped first-owner closure evidence; never a bootstrap reopening signal';
COMMENT ON TABLE first_owner_privileged_domain_assignments IS
    'Signed initial domain assignments; rows do not by themselves authorize application actions';
COMMENT ON FUNCTION store_authority_verified_first_owner_closure(BYTEA) IS
    'Owner-only storage seam for a certificate already verified by the independent first-owner authority client';

REVOKE ALL ON TABLE first_owner_closure_records FROM PUBLIC;
REVOKE ALL ON TABLE first_owner_privileged_domain_assignments FROM PUBLIC;
REVOKE ALL ON FUNCTION first_owner_text_array_is_canonical(TEXT[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION first_owner_json_has_exact_keys(JSONB, TEXT[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION first_owner_authority_namespace_digest(
    first_owner_closure_records
) FROM PUBLIC;
REVOKE ALL ON FUNCTION first_owner_closure_record_digest(
    first_owner_closure_records
) FROM PUBLIC;
REVOKE ALL ON FUNCTION first_owner_closure_writer_contract_is_held(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_first_owner_closure_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_first_owner_domain_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_first_owner_domain_set_complete() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_first_owner_evidence_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION store_authority_verified_first_owner_closure(BYTEA) FROM PUBLIC;

DO $$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON TABLE public.first_owner_closure_records '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON TABLE public.first_owner_privileged_domain_assignments '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.first_owner_closure_records '
             || 'TO ryuki_app_runtime';
        EXECUTE 'GRANT SELECT ON TABLE public.first_owner_privileged_domain_assignments '
             || 'TO ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.first_owner_text_array_is_canonical(TEXT[]) '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.first_owner_json_has_exact_keys(JSONB, TEXT[]) '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.first_owner_authority_namespace_digest('
             || 'public.first_owner_closure_records) FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.first_owner_closure_record_digest('
             || 'public.first_owner_closure_records) FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.first_owner_closure_writer_contract_is_held(TEXT) '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.enforce_first_owner_closure_insert() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.enforce_first_owner_domain_insert() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.enforce_first_owner_domain_set_complete() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.prevent_first_owner_evidence_mutation() '
             || 'FROM ryuki_app_runtime';
        EXECUTE 'REVOKE ALL ON FUNCTION '
             || 'public.store_authority_verified_first_owner_closure(BYTEA) '
             || 'FROM ryuki_app_runtime';
    END IF;
END;
$$;
