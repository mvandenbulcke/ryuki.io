-- Migration 193 is immutable, ordered migration evidence and must not be
-- rewritten. Its tenant-shape constraint permits a tenant-scoped multi-tenant
-- first-owner closure even though the signed authority namespace is
-- deployment-owned. Correct that mismatch only through this forward
-- migration; never update, backfill, or delete signed closure rows.
--
-- On a pristine install the migration runner applies 193 and then 213 in the
-- same ordered migration wave before application readiness. The first-owner
-- installation ceremony must remain gated on schema version 213 or later, so
-- the owner-only storage function created by 193 cannot be invoked before this
-- deployment-scoped constraint is installed.

SET LOCAL lock_timeout = '30s';

-- One certificate spans both relations. Lock all table writers and table DDL
-- across the evidence boundary while its predecessor shape is attested and
-- replaced.
LOCK TABLE
    public.first_owner_closure_records,
    public.first_owner_privileged_domain_assignments
IN ACCESS EXCLUSIVE MODE;

-- Parse the exact migration-193 expression against the same relation. Keeping
-- this helper NOT VALID avoids scanning or reinterpreting immutable rows; its
-- normalized expression is used only as a catalog comparison witness.
ALTER TABLE public.first_owner_closure_records
    ADD CONSTRAINT first_owner_tenant_shape_expected_213 CHECK (
        (tenancy_mode = 'single_tenant' AND tenant_id IS NULL)
        OR (
            tenancy_mode = 'multi_tenant'
            AND tenant_id ~ '^tenant:[a-z0-9][a-z0-9._-]{2,126}$'
        )
    ) NOT VALID;

DO $first_owner_deployment_scope_preflight$
DECLARE
    closure_relation REGCLASS :=
        pg_catalog.to_regclass('public.first_owner_closure_records');
    domain_assignment_relation REGCLASS := pg_catalog.to_regclass(
        'public.first_owner_privileged_domain_assignments'
    );
    audit_relation REGCLASS := pg_catalog.to_regclass('public.audit_log');
    domain_event_relation REGCLASS := pg_catalog.to_regclass(
        'public.domain_events'
    );
    current_role_oid OID := pg_catalog.to_regrole(CURRENT_USER);
    runtime_role_oid OID := pg_catalog.to_regrole('ryuki_app_runtime');
    plpgsql_language_oid OID;
    closure_owner OID;
    domain_assignment_owner OID;
    tenancy_mode_attribute_number SMALLINT;
    tenant_id_attribute_number SMALLINT;
    tenancy_mode_type OID;
    tenant_id_type OID;
    tenancy_mode_collation OID;
    tenant_id_collation OID;
    tenancy_mode_type_modifier INTEGER;
    tenant_id_type_modifier INTEGER;
    tenancy_mode_array_dimensions INTEGER;
    tenant_id_array_dimensions INTEGER;
    tenancy_mode_not_null BOOLEAN;
    tenant_id_not_null BOOLEAN;
    tenancy_mode_has_default BOOLEAN;
    tenant_id_has_default BOOLEAN;
    actual_constraint_oid OID;
    expected_constraint_oid OID;
    actual_constraint RECORD;
    expected_constraint RECORD;
    actual_constraint_expression TEXT;
    expected_constraint_expression TEXT;
    writer_oid OID := pg_catalog.to_regprocedure(
        'public.store_authority_verified_first_owner_closure(bytea)'
    );
    text_array_function_oid OID := pg_catalog.to_regprocedure(
        'public.first_owner_text_array_is_canonical(text[])'
    );
    json_keys_function_oid OID := pg_catalog.to_regprocedure(
        'public.first_owner_json_has_exact_keys(jsonb,text[])'
    );
    authority_digest_function_oid OID := pg_catalog.to_regprocedure(
        'public.first_owner_authority_namespace_digest(public.first_owner_closure_records)'
    );
    closure_digest_function_oid OID := pg_catalog.to_regprocedure(
        'public.first_owner_closure_record_digest(public.first_owner_closure_records)'
    );
    writer_contract_function_oid OID := pg_catalog.to_regprocedure(
        'public.first_owner_closure_writer_contract_is_held(text)'
    );
    closure_insert_function_oid OID := pg_catalog.to_regprocedure(
        'public.enforce_first_owner_closure_insert()'
    );
    domain_insert_function_oid OID := pg_catalog.to_regprocedure(
        'public.enforce_first_owner_domain_insert()'
    );
    domain_complete_function_oid OID := pg_catalog.to_regprocedure(
        'public.enforce_first_owner_domain_set_complete()'
    );
    mutation_guard_function_oid OID := pg_catalog.to_regprocedure(
        'public.prevent_first_owner_evidence_mutation()'
    );
    audit_controlled_insert_function_oid OID := pg_catalog.to_regprocedure(
        'public.audit_log_controlled_insert_only()'
    );
    audit_no_mutate_function_oid OID := pg_catalog.to_regprocedure(
        'public.audit_log_no_mutate()'
    );
    writer_body_digest TEXT;
BEGIN
    IF closure_relation IS NULL
       OR domain_assignment_relation IS NULL
       OR audit_relation IS NULL
       OR domain_event_relation IS NULL
    THEN
        RAISE EXCEPTION
            'migration 213 requires the complete first-owner predecessor relation set'
            USING ERRCODE = '55000';
    END IF;

    SELECT language.oid
    INTO plpgsql_language_oid
    FROM pg_catalog.pg_language AS language
    WHERE language.lanname = 'plpgsql'
      AND language.lanpltrusted;

    SELECT class.relowner
    INTO closure_owner
    FROM pg_catalog.pg_class AS class
    WHERE class.oid = closure_relation
      AND class.relnamespace = 'public'::pg_catalog.regnamespace
      AND class.relkind = 'r'
      AND class.relpersistence = 'p'
      AND NOT class.relispartition
      AND NOT class.relrowsecurity
      AND NOT class.relforcerowsecurity;

    SELECT class.relowner
    INTO domain_assignment_owner
    FROM pg_catalog.pg_class AS class
    WHERE class.oid = domain_assignment_relation
      AND class.relnamespace = 'public'::pg_catalog.regnamespace
      AND class.relkind = 'r'
      AND class.relpersistence = 'p'
      AND NOT class.relispartition
      AND NOT class.relrowsecurity
      AND NOT class.relforcerowsecurity;

    IF current_role_oid IS NULL
       OR closure_owner IS DISTINCT FROM current_role_oid
       OR domain_assignment_owner IS DISTINCT FROM current_role_oid
       OR plpgsql_language_oid IS NULL
       OR EXISTS (
            SELECT 1
            FROM pg_catalog.pg_inherits AS inheritance
            WHERE inheritance.inhrelid IN (
                closure_relation,
                domain_assignment_relation
            )
               OR inheritance.inhparent IN (
                    closure_relation,
                    domain_assignment_relation
               )
       )
    THEN
        RAISE EXCEPTION
            'migration 213 found drifted first-owner ownership, relation kind, RLS, or inheritance posture'
            USING ERRCODE = '55000';
    END IF;

    SELECT
        attribute.attnum,
        attribute.atttypid,
        attribute.attcollation,
        attribute.atttypmod,
        attribute.attndims,
        attribute.attnotnull,
        attribute.atthasdef
    INTO
        tenancy_mode_attribute_number,
        tenancy_mode_type,
        tenancy_mode_collation,
        tenancy_mode_type_modifier,
        tenancy_mode_array_dimensions,
        tenancy_mode_not_null,
        tenancy_mode_has_default
    FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.attrelid = closure_relation
      AND attribute.attname = 'tenancy_mode'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND attribute.attgenerated = ''
      AND attribute.attidentity = '';

    SELECT
        attribute.attnum,
        attribute.atttypid,
        attribute.attcollation,
        attribute.atttypmod,
        attribute.attndims,
        attribute.attnotnull,
        attribute.atthasdef
    INTO
        tenant_id_attribute_number,
        tenant_id_type,
        tenant_id_collation,
        tenant_id_type_modifier,
        tenant_id_array_dimensions,
        tenant_id_not_null,
        tenant_id_has_default
    FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.attrelid = closure_relation
      AND attribute.attname = 'tenant_id'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND attribute.attgenerated = ''
      AND attribute.attidentity = '';

    IF tenancy_mode_attribute_number IS NULL
       OR tenant_id_attribute_number IS NULL
       OR tenancy_mode_type IS DISTINCT FROM
            'pg_catalog.text'::pg_catalog.regtype
       OR tenant_id_type IS DISTINCT FROM
            'pg_catalog.text'::pg_catalog.regtype
       OR tenancy_mode_collation IS DISTINCT FROM
            'pg_catalog."default"'::pg_catalog.regcollation
       OR tenant_id_collation IS DISTINCT FROM
            'pg_catalog."default"'::pg_catalog.regcollation
       OR tenancy_mode_type_modifier IS DISTINCT FROM -1
       OR tenant_id_type_modifier IS DISTINCT FROM -1
       OR tenancy_mode_array_dimensions IS DISTINCT FROM 0
       OR tenant_id_array_dimensions IS DISTINCT FROM 0
       OR tenancy_mode_not_null IS DISTINCT FROM TRUE
       OR tenant_id_not_null IS DISTINCT FROM FALSE
       OR tenancy_mode_has_default IS DISTINCT FROM FALSE
       OR tenant_id_has_default IS DISTINCT FROM FALSE
    THEN
        RAISE EXCEPTION
            'migration 213 found drifted tenancy_mode or tenant_id column shape'
            USING ERRCODE = '55000';
    END IF;

    SELECT constraint_record.oid
    INTO actual_constraint_oid
    FROM pg_catalog.pg_constraint AS constraint_record
    WHERE constraint_record.conrelid = closure_relation
      AND constraint_record.conname = 'first_owner_tenant_shape_check';

    SELECT constraint_record.oid
    INTO expected_constraint_oid
    FROM pg_catalog.pg_constraint AS constraint_record
    WHERE constraint_record.conrelid = closure_relation
      AND constraint_record.conname =
            'first_owner_tenant_shape_expected_213';

    IF actual_constraint_oid IS NULL OR expected_constraint_oid IS NULL THEN
        RAISE EXCEPTION
            'migration 213 requires the original and comparison tenant constraints'
            USING ERRCODE = '55000';
    END IF;

    SELECT constraint_record.*
    INTO actual_constraint
    FROM pg_catalog.pg_constraint AS constraint_record
    WHERE constraint_record.oid = actual_constraint_oid;

    SELECT constraint_record.*
    INTO expected_constraint
    FROM pg_catalog.pg_constraint AS constraint_record
    WHERE constraint_record.oid = expected_constraint_oid;

    IF actual_constraint.contype IS DISTINCT FROM 'c'
       OR actual_constraint.connamespace IS DISTINCT FROM
            'public'::pg_catalog.regnamespace
       OR actual_constraint.convalidated IS DISTINCT FROM TRUE
       OR actual_constraint.conenforced IS DISTINCT FROM TRUE
       OR actual_constraint.condeferrable IS DISTINCT FROM FALSE
       OR actual_constraint.condeferred IS DISTINCT FROM FALSE
       OR actual_constraint.conislocal IS DISTINCT FROM TRUE
       OR actual_constraint.coninhcount IS DISTINCT FROM 0
       OR actual_constraint.connoinherit IS DISTINCT FROM FALSE
       OR actual_constraint.conkey IS DISTINCT FROM ARRAY[
            tenancy_mode_attribute_number,
            tenant_id_attribute_number
       ]::SMALLINT[]
       OR expected_constraint.contype IS DISTINCT FROM 'c'
       OR expected_constraint.convalidated IS DISTINCT FROM FALSE
       OR expected_constraint.conenforced IS DISTINCT FROM TRUE
       OR expected_constraint.condeferrable IS DISTINCT FROM FALSE
       OR expected_constraint.condeferred IS DISTINCT FROM FALSE
       OR expected_constraint.conislocal IS DISTINCT FROM TRUE
       OR expected_constraint.coninhcount IS DISTINCT FROM 0
       OR expected_constraint.connoinherit IS DISTINCT FROM FALSE
       OR expected_constraint.conkey IS DISTINCT FROM ARRAY[
            tenancy_mode_attribute_number,
            tenant_id_attribute_number
       ]::SMALLINT[]
    THEN
        RAISE EXCEPTION
            'migration 213 found a structurally drifted tenant-shape constraint'
            USING ERRCODE = '55000';
    END IF;

    actual_constraint_expression := pg_catalog.pg_get_expr(
        actual_constraint.conbin,
        actual_constraint.conrelid,
        FALSE
    );
    expected_constraint_expression := pg_catalog.pg_get_expr(
        expected_constraint.conbin,
        expected_constraint.conrelid,
        FALSE
    );

    IF actual_constraint_expression IS DISTINCT FROM
        expected_constraint_expression
    THEN
        RAISE EXCEPTION
            'migration 213 refuses drifted first_owner_tenant_shape_check (actual=%, expected=%)',
            COALESCE(actual_constraint_expression, '<missing>'),
            COALESCE(expected_constraint_expression, '<missing>')
            USING ERRCODE = '55000';
    END IF;

    -- The writer and readback both rely on migration 193's singleton and
    -- linkage constraints. Attest them by exact column identity rather than
    -- auto-generated names, which PostgreSQL may truncate differently.
    IF EXISTS (
        WITH expected(
            relation_oid,
            constraint_type,
            key_columns,
            referenced_relation_oid,
            referenced_columns
        ) AS (
            VALUES
                (
                    closure_relation::OID,
                    'p'::"char",
                    ARRAY['deployment_id']::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    closure_relation::OID,
                    'u'::"char",
                    ARRAY['closure_event_id']::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    closure_relation::OID,
                    'u'::"char",
                    ARRAY['claim_request_digest']::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    closure_relation::OID,
                    'u'::"char",
                    ARRAY['capability_id']::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    closure_relation::OID,
                    'u'::"char",
                    ARRAY['closure_certificate_digest']::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    closure_relation::OID,
                    'u'::"char",
                    ARRAY['closure_record_digest']::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    closure_relation::OID,
                    'u'::"char",
                    ARRAY['audit_log_id']::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    closure_relation::OID,
                    'u'::"char",
                    ARRAY['domain_event_id']::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    closure_relation::OID,
                    'u'::"char",
                    ARRAY[
                        'deployment_id',
                        'first_owner_principal_id',
                        'closure_event_id',
                        'closure_certificate_digest'
                    ]::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    closure_relation::OID,
                    'f'::"char",
                    ARRAY['audit_log_id']::TEXT[],
                    audit_relation::OID,
                    ARRAY['id']::TEXT[]
                ),
                (
                    closure_relation::OID,
                    'f'::"char",
                    ARRAY['domain_event_id']::TEXT[],
                    domain_event_relation::OID,
                    ARRAY['id']::TEXT[]
                ),
                (
                    domain_assignment_relation::OID,
                    'p'::"char",
                    ARRAY['deployment_id', 'domain_id']::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    domain_assignment_relation::OID,
                    'u'::"char",
                    ARRAY['assignment_event_id']::TEXT[],
                    NULL::OID,
                    NULL::TEXT[]
                ),
                (
                    domain_assignment_relation::OID,
                    'f'::"char",
                    ARRAY[
                        'deployment_id',
                        'first_owner_principal_id',
                        'closure_event_id',
                        'closure_certificate_digest'
                    ]::TEXT[],
                    closure_relation::OID,
                    ARRAY[
                        'deployment_id',
                        'first_owner_principal_id',
                        'closure_event_id',
                        'closure_certificate_digest'
                    ]::TEXT[]
                )
        )
        SELECT 1
        FROM expected
        WHERE (
            SELECT pg_catalog.count(*)
            FROM pg_catalog.pg_constraint AS constraint_record
            WHERE constraint_record.conrelid = expected.relation_oid
              AND constraint_record.contype = expected.constraint_type
              AND constraint_record.convalidated
              AND constraint_record.conenforced
              AND NOT constraint_record.condeferrable
              AND NOT constraint_record.condeferred
              AND constraint_record.conislocal
              AND constraint_record.coninhcount = 0
              AND NOT constraint_record.connoinherit
              AND ARRAY(
                    SELECT attribute.attname::TEXT
                    FROM pg_catalog.unnest(constraint_record.conkey)
                         WITH ORDINALITY AS key_column(attribute_number, ordinal)
                    JOIN pg_catalog.pg_attribute AS attribute
                      ON attribute.attrelid = constraint_record.conrelid
                     AND attribute.attnum = key_column.attribute_number
                     AND attribute.attnum > 0
                     AND NOT attribute.attisdropped
                    ORDER BY key_column.ordinal
              ) = expected.key_columns
              AND (
                    expected.constraint_type <> 'f'::"char"
                    OR (
                        constraint_record.confrelid =
                            expected.referenced_relation_oid
                        AND constraint_record.confmatchtype = 's'::"char"
                        AND constraint_record.confupdtype = 'r'::"char"
                        AND constraint_record.confdeltype = 'r'::"char"
                        AND ARRAY(
                            SELECT attribute.attname::TEXT
                            FROM pg_catalog.unnest(constraint_record.confkey)
                                 WITH ORDINALITY AS referenced_key(
                                    attribute_number,
                                    ordinal
                                 )
                            JOIN pg_catalog.pg_attribute AS attribute
                              ON attribute.attrelid = constraint_record.confrelid
                             AND attribute.attnum =
                                    referenced_key.attribute_number
                             AND attribute.attnum > 0
                             AND NOT attribute.attisdropped
                            ORDER BY referenced_key.ordinal
                        ) = expected.referenced_columns
                    )
              )
              AND EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_index AS index_record
                    WHERE index_record.indexrelid = constraint_record.conindid
                      AND index_record.indrelid = CASE
                            WHEN expected.constraint_type = 'f'::"char"
                                THEN expected.referenced_relation_oid
                            ELSE expected.relation_oid
                          END
                      AND index_record.indisunique
                      AND index_record.indisvalid
                      AND index_record.indisready
                      AND index_record.indislive
              )
        ) IS DISTINCT FROM 1
    ) THEN
        RAISE EXCEPTION
            'migration 213 found drifted first-owner singleton or linkage constraints'
            USING ERRCODE = '55000';
    END IF;

    IF writer_oid IS NULL
       OR text_array_function_oid IS NULL
       OR json_keys_function_oid IS NULL
       OR authority_digest_function_oid IS NULL
       OR closure_digest_function_oid IS NULL
       OR writer_contract_function_oid IS NULL
       OR closure_insert_function_oid IS NULL
       OR domain_insert_function_oid IS NULL
       OR domain_complete_function_oid IS NULL
       OR mutation_guard_function_oid IS NULL
       OR audit_controlled_insert_function_oid IS NULL
       OR audit_no_mutate_function_oid IS NULL
    THEN
        RAISE EXCEPTION
            'migration 213 requires the complete migration-193 writer and trigger-function set'
            USING ERRCODE = '55000';
    END IF;

    -- Reviewed SHA-256 of the exact UTF-8 prosrc, including the leading and
    -- trailing LF bytes between migration 193's dollar-quote delimiters.
    SELECT pg_catalog.encode(
        pg_catalog.sha256(pg_catalog.convert_to(procedure.prosrc, 'UTF8')),
        'hex'
    )
    INTO writer_body_digest
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid = writer_oid
      AND procedure.pronamespace = 'public'::pg_catalog.regnamespace
      AND procedure.proowner = current_role_oid
      AND procedure.prolang = plpgsql_language_oid
      AND procedure.prokind = 'f'
      AND procedure.prorettype = 'pg_catalog.bool'::pg_catalog.regtype
      AND procedure.prosecdef
      AND NOT procedure.proleakproof
      AND NOT procedure.proisstrict
      AND procedure.provolatile = 'v'
      AND procedure.proparallel = 'u'
      AND procedure.proconfig IS NOT DISTINCT FROM
            ARRAY['search_path=pg_catalog']::TEXT[];

    IF writer_body_digest IS DISTINCT FROM
        '76921ca4534306f66105e87a3fa646397ec3999fd0e8d5ca55e24f638d6210f4'
    THEN
        RAISE EXCEPTION
            'migration 213 found a drifted first-owner writer definition (body_sha256=%)',
            COALESCE(writer_body_digest, '<unavailable>')
            USING ERRCODE = '55000';
    END IF;

    -- The writer is only as strong as every function it invokes directly or
    -- through its insert/audit triggers. Pin exact prosrc and execution
    -- metadata so a same-signature permissive replacement cannot authorize or
    -- preserve forgeable closure evidence.
    IF EXISTS (
        WITH expected(
            function_oid,
            body_digest,
            language_name,
            return_type,
            security_definer,
            strict,
            volatility
        ) AS (
            VALUES
                (
                    text_array_function_oid,
                    'f972b0ff939cc2bc33f59d807877b63a8af0af3a531e8e9651dcb85a5964fe33',
                    'plpgsql'::NAME,
                    'pg_catalog.bool'::pg_catalog.regtype,
                    FALSE,
                    TRUE,
                    'i'::"char"
                ),
                (
                    json_keys_function_oid,
                    'f93496b6250a84a4c9c420f72a1dc709de2ffaf137a5ac0dfa17365032712924',
                    'sql'::NAME,
                    'pg_catalog.bool'::pg_catalog.regtype,
                    FALSE,
                    TRUE,
                    'i'::"char"
                ),
                (
                    authority_digest_function_oid,
                    'bfe38c7a80aebaf0b4b3cfba0e005277e85fd7e8cfbc3c3138fbd766431910e8',
                    'sql'::NAME,
                    'pg_catalog.text'::pg_catalog.regtype,
                    TRUE,
                    TRUE,
                    'i'::"char"
                ),
                (
                    closure_digest_function_oid,
                    'b498625613f85d2083edd7c8f40435d388876af6aa19c4d344f02728926d031d',
                    'sql'::NAME,
                    'pg_catalog.text'::pg_catalog.regtype,
                    TRUE,
                    TRUE,
                    'i'::"char"
                ),
                (
                    writer_contract_function_oid,
                    'ae0008e2fd84d35942190ceee16092e411477d4cf3f8f0a22cd2193f416422a6',
                    'sql'::NAME,
                    'pg_catalog.bool'::pg_catalog.regtype,
                    TRUE,
                    TRUE,
                    's'::"char"
                ),
                (
                    closure_insert_function_oid,
                    '5347f1723483a6250e751023126a37d3b0a8f3e13d1514b5054f5d3e1ed1dcd5',
                    'plpgsql'::NAME,
                    'pg_catalog.trigger'::pg_catalog.regtype,
                    FALSE,
                    FALSE,
                    'v'::"char"
                ),
                (
                    domain_insert_function_oid,
                    '0361adc365bdc749ea01431c6c2f9cdb025826d00820948fb3a1d46052aef362',
                    'plpgsql'::NAME,
                    'pg_catalog.trigger'::pg_catalog.regtype,
                    FALSE,
                    FALSE,
                    'v'::"char"
                ),
                (
                    domain_complete_function_oid,
                    '64a91cbb31503b9444ffad66532ce970f29b8b1abd2f394bd7882dfdde2df91b',
                    'plpgsql'::NAME,
                    'pg_catalog.trigger'::pg_catalog.regtype,
                    TRUE,
                    FALSE,
                    'v'::"char"
                ),
                (
                    mutation_guard_function_oid,
                    '83062108b3313bb9485d600aa701139a0515f4d1160faa0d4f9386538f85ca7b',
                    'plpgsql'::NAME,
                    'pg_catalog.trigger'::pg_catalog.regtype,
                    FALSE,
                    FALSE,
                    'v'::"char"
                ),
                (
                    writer_oid,
                    '76921ca4534306f66105e87a3fa646397ec3999fd0e8d5ca55e24f638d6210f4',
                    'plpgsql'::NAME,
                    'pg_catalog.bool'::pg_catalog.regtype,
                    TRUE,
                    FALSE,
                    'v'::"char"
                ),
                (
                    pg_catalog.to_regprocedure(
                        'public.audit_canonical_json(jsonb)'
                    ),
                    '65ff781b91a8b78563c29c993d8ebd7dfabf35d664d4dc3bbd850dd836b87b3a',
                    'plpgsql'::NAME,
                    'pg_catalog.text'::pg_catalog.regtype,
                    FALSE,
                    TRUE,
                    'i'::"char"
                ),
                (
                    pg_catalog.to_regprocedure(
                        'public.audit_canonical_payload(uuid,text,text,text[],text,text,text,text,text,text,jsonb,text)'
                    ),
                    '587398f07b4b05a178c35bef4bc966452d1b326c6ab2cf70f9d351b2e3ad0cb2',
                    'sql'::NAME,
                    'pg_catalog.text'::pg_catalog.regtype,
                    FALSE,
                    FALSE,
                    'i'::"char"
                ),
                (
                    pg_catalog.to_regprocedure(
                        'public.audit_chain_hash_v2(text,text)'
                    ),
                    '422293eea147008e5c0fb2c151461a1bd4498c5d8b18394aa2d30ee19ec50b19',
                    'sql'::NAME,
                    'pg_catalog.text'::pg_catalog.regtype,
                    FALSE,
                    TRUE,
                    'i'::"char"
                ),
                (
                    pg_catalog.to_regprocedure(
                        'public.append_audit_log(uuid,text,text,text[],text,text,text,text,text,text,jsonb,text)'
                    ),
                    'f8599e4bf27412849e6697e8acaf8ab05da3967b91dc877107303a4e6f96ede7',
                    'plpgsql'::NAME,
                    'pg_catalog.int8'::pg_catalog.regtype,
                    TRUE,
                    FALSE,
                    'v'::"char"
                ),
                (
                    audit_controlled_insert_function_oid,
                    'e4a5549f1e4d170e62ae103c2d156a4301c5a2a59a5945dd0815abc8a21348aa',
                    'plpgsql'::NAME,
                    'pg_catalog.trigger'::pg_catalog.regtype,
                    FALSE,
                    FALSE,
                    'v'::"char"
                )
        )
        SELECT 1
        FROM expected
        LEFT JOIN pg_catalog.pg_proc AS procedure
          ON procedure.oid = expected.function_oid
        LEFT JOIN pg_catalog.pg_language AS language
          ON language.oid = procedure.prolang
        WHERE expected.function_oid IS NULL
           OR procedure.oid IS NULL
           OR procedure.pronamespace IS DISTINCT FROM
                'public'::pg_catalog.regnamespace
           OR procedure.proowner IS DISTINCT FROM current_role_oid
           OR language.lanname IS DISTINCT FROM expected.language_name
           OR procedure.prokind IS DISTINCT FROM 'f'
           OR procedure.prorettype IS DISTINCT FROM expected.return_type
           OR procedure.prosecdef IS DISTINCT FROM expected.security_definer
           OR procedure.proleakproof IS DISTINCT FROM FALSE
           OR procedure.proisstrict IS DISTINCT FROM expected.strict
           OR procedure.provolatile IS DISTINCT FROM expected.volatility
           OR procedure.proparallel IS DISTINCT FROM 'u'
           OR procedure.proconfig IS DISTINCT FROM
                ARRAY['search_path=pg_catalog']::TEXT[]
           OR pg_catalog.encode(
                pg_catalog.sha256(
                    pg_catalog.convert_to(procedure.prosrc, 'UTF8')
                ),
                'hex'
           ) IS DISTINCT FROM expected.body_digest
    ) THEN
        RAISE EXCEPTION
            'migration 213 found drifted first-owner writer dependency definitions'
            USING ERRCODE = '55000';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_language AS language
          ON language.oid = procedure.prolang
        WHERE procedure.oid = audit_no_mutate_function_oid
          AND procedure.pronamespace = 'public'::pg_catalog.regnamespace
          AND procedure.proowner = current_role_oid
          AND language.lanname = 'plpgsql'
          AND procedure.prokind = 'f'
          AND procedure.prorettype =
                'pg_catalog.trigger'::pg_catalog.regtype
          AND NOT procedure.prosecdef
          AND NOT procedure.proleakproof
          AND NOT procedure.proisstrict
          AND procedure.provolatile = 'v'
          AND procedure.proparallel = 'u'
          AND procedure.proconfig IS NULL
          AND pg_catalog.encode(
                pg_catalog.sha256(
                    pg_catalog.convert_to(procedure.prosrc, 'UTF8')
                ),
                'hex'
          ) = '29c97d608d9335181f4103c7df773b42c7275b4b48e187288fc9785bb3b87663'
    ) THEN
        RAISE EXCEPTION
            'migration 213 found a drifted audit append-only guard definition'
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        WITH expected(function_oid, security_definer) AS (
            VALUES
                (closure_insert_function_oid, FALSE),
                (domain_insert_function_oid, FALSE),
                (domain_complete_function_oid, TRUE),
                (mutation_guard_function_oid, FALSE)
        )
        SELECT 1
        FROM expected
        LEFT JOIN pg_catalog.pg_proc AS procedure
          ON procedure.oid = expected.function_oid
        WHERE procedure.oid IS NULL
           OR procedure.pronamespace IS DISTINCT FROM
                'public'::pg_catalog.regnamespace
           OR procedure.proowner IS DISTINCT FROM current_role_oid
           OR procedure.prolang IS DISTINCT FROM plpgsql_language_oid
           OR procedure.prokind IS DISTINCT FROM 'f'
           OR procedure.prorettype IS DISTINCT FROM
                'pg_catalog.trigger'::pg_catalog.regtype
           OR procedure.pronargs IS DISTINCT FROM 0
           OR procedure.prosecdef IS DISTINCT FROM expected.security_definer
           OR procedure.proleakproof IS DISTINCT FROM FALSE
           OR procedure.proisstrict IS DISTINCT FROM FALSE
           OR procedure.provolatile IS DISTINCT FROM 'v'
           OR procedure.proparallel IS DISTINCT FROM 'u'
           OR procedure.proconfig IS DISTINCT FROM
                ARRAY['search_path=pg_catalog']::TEXT[]
    ) THEN
        RAISE EXCEPTION
            'migration 213 found drifted first-owner trigger-function metadata'
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        WITH expected(
            relation_oid,
            trigger_name,
            function_oid,
            trigger_type,
            is_constraint,
            is_deferrable,
            is_initially_deferred
        ) AS (
            VALUES
                (
                    closure_relation::OID,
                    'first_owner_closure_insert_contract'::NAME,
                    closure_insert_function_oid,
                    7::SMALLINT,
                    FALSE,
                    FALSE,
                    FALSE
                ),
                (
                    closure_relation::OID,
                    'first_owner_closure_no_mutation'::NAME,
                    mutation_guard_function_oid,
                    27::SMALLINT,
                    FALSE,
                    FALSE,
                    FALSE
                ),
                (
                    closure_relation::OID,
                    'first_owner_closure_no_truncate'::NAME,
                    mutation_guard_function_oid,
                    34::SMALLINT,
                    FALSE,
                    FALSE,
                    FALSE
                ),
                (
                    closure_relation::OID,
                    'first_owner_domain_set_complete'::NAME,
                    domain_complete_function_oid,
                    5::SMALLINT,
                    TRUE,
                    TRUE,
                    TRUE
                ),
                (
                    domain_assignment_relation::OID,
                    'first_owner_domain_insert_contract'::NAME,
                    domain_insert_function_oid,
                    7::SMALLINT,
                    FALSE,
                    FALSE,
                    FALSE
                ),
                (
                    domain_assignment_relation::OID,
                    'first_owner_domain_no_mutation'::NAME,
                    mutation_guard_function_oid,
                    27::SMALLINT,
                    FALSE,
                    FALSE,
                    FALSE
                ),
                (
                    domain_assignment_relation::OID,
                    'first_owner_domain_no_truncate'::NAME,
                    mutation_guard_function_oid,
                    34::SMALLINT,
                    FALSE,
                    FALSE,
                    FALSE
                ),
                (
                    audit_relation::OID,
                    'audit_log_controlled_insert'::NAME,
                    audit_controlled_insert_function_oid,
                    7::SMALLINT,
                    FALSE,
                    FALSE,
                    FALSE
                ),
                (
                    audit_relation::OID,
                    'audit_log_append_only'::NAME,
                    audit_no_mutate_function_oid,
                    27::SMALLINT,
                    FALSE,
                    FALSE,
                    FALSE
                ),
                (
                    audit_relation::OID,
                    'audit_log_no_truncate'::NAME,
                    audit_no_mutate_function_oid,
                    34::SMALLINT,
                    FALSE,
                    FALSE,
                    FALSE
                )
        ),
        actual AS (
            SELECT
                trigger.tgrelid AS relation_oid,
                trigger.tgname AS trigger_name,
                trigger.tgfoid AS function_oid,
                trigger.tgtype AS trigger_type,
                trigger.tgenabled,
                trigger.tgparentid,
                (trigger.tgconstraint <> 0) AS is_constraint,
                trigger.tgconstrrelid,
                trigger.tgconstrindid,
                trigger.tgdeferrable AS is_deferrable,
                trigger.tginitdeferred AS is_initially_deferred,
                trigger.tgnargs,
                trigger.tgargs,
                trigger.tgattr,
                trigger.tgqual,
                trigger.tgoldtable,
                trigger.tgnewtable
            FROM pg_catalog.pg_trigger AS trigger
            WHERE trigger.tgrelid IN (
                closure_relation,
                domain_assignment_relation,
                audit_relation
            )
              AND NOT trigger.tgisinternal
        )
        SELECT 1
        FROM expected
        FULL OUTER JOIN actual
          ON actual.relation_oid = expected.relation_oid
         AND actual.trigger_name = expected.trigger_name
        WHERE expected.relation_oid IS NULL
           OR actual.relation_oid IS NULL
           OR actual.function_oid IS DISTINCT FROM expected.function_oid
           OR actual.trigger_type IS DISTINCT FROM expected.trigger_type
           OR actual.tgenabled IS DISTINCT FROM 'O'
           OR actual.tgparentid IS DISTINCT FROM 0
           OR actual.is_constraint IS DISTINCT FROM expected.is_constraint
           OR actual.tgconstrrelid IS DISTINCT FROM 0
           OR actual.tgconstrindid IS DISTINCT FROM 0
           OR actual.is_deferrable IS DISTINCT FROM expected.is_deferrable
           OR actual.is_initially_deferred IS DISTINCT FROM
                expected.is_initially_deferred
           OR actual.tgnargs IS DISTINCT FROM 0
           OR pg_catalog.octet_length(actual.tgargs) IS DISTINCT FROM 0
           OR actual.tgattr::TEXT IS DISTINCT FROM ''
           OR actual.tgqual IS NOT NULL
           OR actual.tgoldtable IS NOT NULL
           OR actual.tgnewtable IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'migration 213 found a missing, extra, disabled, or drifted first-owner or audit trigger'
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS class
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                class.relacl,
                pg_catalog.acldefault('r', class.relowner)
            )
        ) AS privilege
        WHERE class.oid IN (
            closure_relation,
            domain_assignment_relation
          )
          AND (
                privilege.grantor IS DISTINCT FROM class.relowner
                OR privilege.is_grantable
                OR privilege.grantee = 0
                OR privilege.grantee NOT IN (
                    class.relowner,
                    COALESCE(runtime_role_oid, class.relowner)
                )
                OR (
                    runtime_role_oid IS NOT NULL
                    AND privilege.grantee = runtime_role_oid
                    AND privilege.privilege_type IS DISTINCT FROM 'SELECT'
                )
          )
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute AS attribute
        WHERE attribute.attrelid IN (
            closure_relation,
            domain_assignment_relation
        )
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND attribute.attacl IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'migration 213 found drifted first-owner table or column ACLs'
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS class
        CROSS JOIN LATERAL (
            SELECT
                pg_catalog.array_agg(
                    privilege.privilege_type
                    ORDER BY privilege.privilege_type COLLATE "C"
                ) FILTER (
                    WHERE privilege.grantee = class.relowner
                ) AS owner_privileges,
                pg_catalog.array_agg(
                    privilege.privilege_type
                    ORDER BY privilege.privilege_type COLLATE "C"
                ) FILTER (
                    WHERE runtime_role_oid IS NOT NULL
                      AND privilege.grantee = runtime_role_oid
                ) AS runtime_privileges
            FROM pg_catalog.aclexplode(
                COALESCE(
                    class.relacl,
                    pg_catalog.acldefault('r', class.relowner)
                )
            ) AS privilege
        ) AS acl_set
        WHERE class.oid IN (
            closure_relation,
            domain_assignment_relation
        )
          AND (
                acl_set.owner_privileges IS DISTINCT FROM ARRAY[
                    'DELETE',
                    'INSERT',
                    'MAINTAIN',
                    'REFERENCES',
                    'SELECT',
                    'TRIGGER',
                    'TRUNCATE',
                    'UPDATE'
                ]::TEXT[]
                OR (
                    runtime_role_oid IS NULL
                    AND acl_set.runtime_privileges IS NOT NULL
                )
                OR (
                    runtime_role_oid IS NOT NULL
                    AND acl_set.runtime_privileges IS DISTINCT FROM
                        ARRAY['SELECT']::TEXT[]
                )
          )
    ) THEN
        RAISE EXCEPTION
            'migration 213 found incomplete first-owner owner or runtime ACLs'
            USING ERRCODE = '55000';
    END IF;

    IF runtime_role_oid IS NOT NULL
       AND (
            NOT pg_catalog.has_table_privilege(
                runtime_role_oid,
                closure_relation,
                'SELECT'
            )
            OR NOT pg_catalog.has_table_privilege(
                runtime_role_oid,
                domain_assignment_relation,
                'SELECT'
            )
            OR EXISTS (
                SELECT 1
                FROM pg_catalog.unnest(ARRAY[
                    closure_relation::OID,
                    domain_assignment_relation::OID
                ]) AS protected_relation(relation_oid)
                CROSS JOIN pg_catalog.unnest(ARRAY[
                    'INSERT',
                    'UPDATE',
                    'DELETE',
                    'TRUNCATE',
                    'REFERENCES',
                    'TRIGGER',
                    'MAINTAIN',
                    'SELECT WITH GRANT OPTION'
                ]::TEXT[]) AS forbidden_privilege(privilege_name)
                WHERE pg_catalog.has_table_privilege(
                    runtime_role_oid,
                    protected_relation.relation_oid,
                    forbidden_privilege.privilege_name
                )
            )
       )
    THEN
        RAISE EXCEPTION
            'migration 213 requires read-only runtime access to first-owner evidence'
            USING ERRCODE = '55000';
    END IF;

    IF runtime_role_oid IS NOT NULL
       AND EXISTS (
            SELECT 1
            FROM pg_catalog.unnest(ARRAY[
                writer_oid,
                text_array_function_oid,
                json_keys_function_oid,
                authority_digest_function_oid,
                closure_digest_function_oid,
                writer_contract_function_oid,
                closure_insert_function_oid,
                domain_insert_function_oid,
                domain_complete_function_oid,
                mutation_guard_function_oid
            ]::OID[]) AS protected_function(function_oid)
            WHERE pg_catalog.has_function_privilege(
                runtime_role_oid,
                protected_function.function_oid,
                'EXECUTE'
            )
       )
    THEN
        RAISE EXCEPTION
            'migration 213 found effective runtime execution authority on first-owner functions'
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS procedure
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                procedure.proacl,
                pg_catalog.acldefault('f', procedure.proowner)
            )
        ) AS privilege
        WHERE procedure.oid = ANY(ARRAY[
            writer_oid,
            text_array_function_oid,
            json_keys_function_oid,
            authority_digest_function_oid,
            closure_digest_function_oid,
            writer_contract_function_oid,
            closure_insert_function_oid,
            domain_insert_function_oid,
            domain_complete_function_oid,
            mutation_guard_function_oid
        ]::OID[])
          AND (
                privilege.grantor IS DISTINCT FROM current_role_oid
                OR privilege.grantee IS DISTINCT FROM current_role_oid
                OR privilege.privilege_type IS DISTINCT FROM 'EXECUTE'
                OR privilege.is_grantable
          )
    ) THEN
        RAISE EXCEPTION
            'migration 213 found executable first-owner functions granted outside their owner'
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS procedure
        CROSS JOIN LATERAL (
            SELECT pg_catalog.array_agg(
                privilege.privilege_type
                ORDER BY privilege.privilege_type COLLATE "C"
            ) AS owner_privileges
            FROM pg_catalog.aclexplode(
                COALESCE(
                    procedure.proacl,
                    pg_catalog.acldefault('f', procedure.proowner)
                )
            ) AS privilege
            WHERE privilege.grantee = current_role_oid
        ) AS acl_set
        WHERE procedure.oid = ANY(ARRAY[
            writer_oid,
            text_array_function_oid,
            json_keys_function_oid,
            authority_digest_function_oid,
            closure_digest_function_oid,
            writer_contract_function_oid,
            closure_insert_function_oid,
            domain_insert_function_oid,
            domain_complete_function_oid,
            mutation_guard_function_oid
        ]::OID[])
          AND acl_set.owner_privileges IS DISTINCT FROM
                ARRAY['EXECUTE']::TEXT[]
    ) THEN
        RAISE EXCEPTION
            'migration 213 found incomplete first-owner function-owner ACLs'
            USING ERRCODE = '55000';
    END IF;

    -- A non-null tenant id is part of the signed immutable evidence. It cannot
    -- be repaired honestly by data mutation, so any such row blocks cutover.
    IF EXISTS (
        SELECT 1
        FROM public.first_owner_closure_records
        WHERE tenant_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'migration 213 cannot reinterpret existing tenant-owned first-owner closure evidence'
            USING ERRCODE = '55000';
    END IF;
END;
$first_owner_deployment_scope_preflight$;

ALTER TABLE public.first_owner_closure_records
    DROP CONSTRAINT first_owner_tenant_shape_expected_213;

-- The 193 writer maps a JSON null tenant_id to SQL NULL, and its insert trigger
-- explicitly accepts the signed JSON null scalar. Keeping those reviewed
-- functions unchanged while replacing only this check admits both tenancy
-- modes under the deployment-owned namespace.
ALTER TABLE public.first_owner_closure_records
    DROP CONSTRAINT first_owner_tenant_shape_check,
    ADD CONSTRAINT first_owner_tenant_shape_check CHECK (
        tenancy_mode IN ('single_tenant', 'multi_tenant')
        AND tenant_id IS NULL
    );

-- Parse the intended replacement on the same relation for exact post-DDL
-- readback, again without validating a helper against immutable evidence.
ALTER TABLE public.first_owner_closure_records
    ADD CONSTRAINT first_owner_tenant_shape_expected_213 CHECK (
        tenancy_mode IN ('single_tenant', 'multi_tenant')
        AND tenant_id IS NULL
    ) NOT VALID;

DO $first_owner_deployment_scope_postflight$
DECLARE
    closure_relation REGCLASS :=
        pg_catalog.to_regclass('public.first_owner_closure_records');
    tenancy_mode_attribute_number SMALLINT;
    tenant_id_attribute_number SMALLINT;
    actual_constraint_oid OID;
    expected_constraint_oid OID;
    actual_constraint RECORD;
    expected_constraint RECORD;
BEGIN
    SELECT attribute.attnum
    INTO tenancy_mode_attribute_number
    FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.attrelid = closure_relation
      AND attribute.attname = 'tenancy_mode'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped;

    SELECT attribute.attnum
    INTO tenant_id_attribute_number
    FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.attrelid = closure_relation
      AND attribute.attname = 'tenant_id'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped;

    SELECT constraint_record.oid
    INTO actual_constraint_oid
    FROM pg_catalog.pg_constraint AS constraint_record
    WHERE constraint_record.conrelid = closure_relation
      AND constraint_record.conname = 'first_owner_tenant_shape_check';

    SELECT constraint_record.oid
    INTO expected_constraint_oid
    FROM pg_catalog.pg_constraint AS constraint_record
    WHERE constraint_record.conrelid = closure_relation
      AND constraint_record.conname =
            'first_owner_tenant_shape_expected_213';

    IF closure_relation IS NULL
       OR tenancy_mode_attribute_number IS NULL
       OR tenant_id_attribute_number IS NULL
       OR actual_constraint_oid IS NULL
       OR expected_constraint_oid IS NULL
    THEN
        RAISE EXCEPTION
            'migration 213 cannot read back its replacement tenant constraint'
            USING ERRCODE = '55000';
    END IF;

    SELECT constraint_record.*
    INTO actual_constraint
    FROM pg_catalog.pg_constraint AS constraint_record
    WHERE constraint_record.oid = actual_constraint_oid;

    SELECT constraint_record.*
    INTO expected_constraint
    FROM pg_catalog.pg_constraint AS constraint_record
    WHERE constraint_record.oid = expected_constraint_oid;

    IF actual_constraint.contype IS DISTINCT FROM 'c'
       OR actual_constraint.connamespace IS DISTINCT FROM
            'public'::pg_catalog.regnamespace
       OR actual_constraint.convalidated IS DISTINCT FROM TRUE
       OR actual_constraint.conenforced IS DISTINCT FROM TRUE
       OR actual_constraint.condeferrable IS DISTINCT FROM FALSE
       OR actual_constraint.condeferred IS DISTINCT FROM FALSE
       OR actual_constraint.conislocal IS DISTINCT FROM TRUE
       OR actual_constraint.coninhcount IS DISTINCT FROM 0
       OR actual_constraint.connoinherit IS DISTINCT FROM FALSE
       OR actual_constraint.conkey IS DISTINCT FROM ARRAY[
            tenancy_mode_attribute_number,
            tenant_id_attribute_number
       ]::SMALLINT[]
       OR expected_constraint.contype IS DISTINCT FROM 'c'
       OR expected_constraint.convalidated IS DISTINCT FROM FALSE
       OR expected_constraint.conenforced IS DISTINCT FROM TRUE
       OR expected_constraint.condeferrable IS DISTINCT FROM FALSE
       OR expected_constraint.condeferred IS DISTINCT FROM FALSE
       OR expected_constraint.conislocal IS DISTINCT FROM TRUE
       OR expected_constraint.coninhcount IS DISTINCT FROM 0
       OR expected_constraint.connoinherit IS DISTINCT FROM FALSE
       OR expected_constraint.conkey IS DISTINCT FROM ARRAY[
            tenancy_mode_attribute_number,
            tenant_id_attribute_number
       ]::SMALLINT[]
       OR pg_catalog.pg_get_expr(
            actual_constraint.conbin,
            actual_constraint.conrelid,
            FALSE
       ) IS DISTINCT FROM pg_catalog.pg_get_expr(
            expected_constraint.conbin,
            expected_constraint.conrelid,
            FALSE
       )
    THEN
        RAISE EXCEPTION
            'migration 213 replacement tenant constraint failed exact catalog readback'
            USING ERRCODE = '55000';
    END IF;
END;
$first_owner_deployment_scope_postflight$;

ALTER TABLE public.first_owner_closure_records
    DROP CONSTRAINT first_owner_tenant_shape_expected_213;

COMMENT ON CONSTRAINT first_owner_tenant_shape_check
    ON public.first_owner_closure_records IS
    'First-owner closure evidence is deployment-owned in every supported tenancy mode; signed tenant_id must be null';
