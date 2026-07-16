-- Make every audit_log row part of one canonical hash domain and move appends
-- behind a generated-id, serialized SECURITY DEFINER writer. PostgreSQL 18's
-- built-in sha256(bytea) keeps this migration extension-free.

SET LOCAL lock_timeout = '30s';

LOCK TABLE audit_log IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM audit_log WHERE id <= 0) THEN
        RAISE EXCEPTION
            'audit_log contains a non-positive id; reconcile before cutover'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

-- Match serde_json's canonical representation: objects sort keys by bytewise
-- order, arrays preserve order, and jsonb scalar text is already normalized.
CREATE OR REPLACE FUNCTION audit_canonical_json(p_value JSONB)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
DECLARE
    value_kind TEXT := jsonb_typeof(p_value);
    canonical TEXT;
BEGIN
    IF value_kind = 'object' THEN
        SELECT '{' || COALESCE(
            string_agg(
                to_json(key)::text || ':' || public.audit_canonical_json(value),
                ',' ORDER BY key COLLATE "C"
            ),
            ''
        ) || '}'
        INTO canonical
        FROM jsonb_each(p_value);
        RETURN canonical;
    ELSIF value_kind = 'array' THEN
        SELECT '[' || COALESCE(
            string_agg(
                public.audit_canonical_json(value),
                ',' ORDER BY ordinal
            ),
            ''
        ) || ']'
        INTO canonical
        FROM jsonb_array_elements(p_value) WITH ORDINALITY AS item(value, ordinal);
        RETURN canonical;
    END IF;
    RETURN p_value::text;
END;
$$;

CREATE OR REPLACE FUNCTION audit_canonical_payload(
    p_request_id UUID,
    p_actor_principal TEXT,
    p_actor_display TEXT,
    p_actor_roles TEXT[],
    p_provider_mode TEXT,
    p_action TEXT,
    p_from_stage TEXT,
    p_to_stage TEXT,
    p_from_status TEXT,
    p_to_status TEXT,
    p_detail JSONB,
    p_outcome TEXT
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $$
    SELECT public.audit_canonical_json(jsonb_build_object(
        'request_id', p_request_id,
        'actor_principal', p_actor_principal,
        'actor_display', COALESCE(p_actor_display, ''),
        'actor_roles', p_actor_roles,
        'provider_mode', p_provider_mode,
        'action', p_action,
        'from_stage', p_from_stage,
        'to_stage', p_to_stage,
        'from_status', p_from_status,
        'to_status', p_to_status,
        'detail', p_detail,
        'outcome', p_outcome
    ));
$$;

-- v2 framing is unambiguous and identical in SQL and Rust:
-- 16 lowercase hex digits of byte length, then value, for both fields.
CREATE OR REPLACE FUNCTION audit_chain_hash_v2(p_prev_hash TEXT, p_payload TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
    SELECT encode(sha256(convert_to(
        lpad(to_hex(octet_length(p_prev_hash)), 16, '0') || p_prev_hash ||
        lpad(to_hex(octet_length(p_payload)), 16, '0') || p_payload,
        'UTF8'
    )), 'hex');
$$;

-- Migration 046's append-only trigger intentionally blocks UPDATE. Disable
-- only that row trigger inside this locked migration transaction, recompute the
-- COMPLETE chain (including pre-094 rows), then restore it before cutover.
ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only;

WITH RECURSIVE ordered AS (
    SELECT id,
           row_number() OVER (ORDER BY id) AS ordinal,
           public.audit_canonical_payload(
               request_id,
               actor_principal,
               actor_display,
               actor_roles,
               provider_mode,
               action,
               from_stage,
               to_stage,
               from_status,
               to_status,
               detail,
               outcome
           ) AS payload
    FROM audit_log
), chain AS (
    SELECT id,
           ordinal,
           'GENESIS'::text AS prev_hash,
           public.audit_chain_hash_v2('GENESIS', payload) AS entry_hash
    FROM ordered
    WHERE ordinal = 1

    UNION ALL

    SELECT next_row.id,
           next_row.ordinal,
           chain.entry_hash AS prev_hash,
           public.audit_chain_hash_v2(chain.entry_hash, next_row.payload) AS entry_hash
    FROM chain
    JOIN ordered AS next_row ON next_row.ordinal = chain.ordinal + 1
)
UPDATE audit_log AS target
SET prev_hash = chain.prev_hash,
    entry_hash = chain.entry_hash
FROM chain
WHERE target.id = chain.id;

ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only;

ALTER TABLE audit_log
    ALTER COLUMN prev_hash SET NOT NULL,
    ALTER COLUMN entry_hash SET NOT NULL,
    ADD CONSTRAINT audit_log_positive_id CHECK (id > 0),
    ADD CONSTRAINT audit_log_prev_hash_shape CHECK (
        prev_hash = 'GENESIS' OR prev_hash ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT audit_log_entry_hash_shape CHECK (
        entry_hash ~ '^[0-9a-f]{64}$'
    );

ALTER SEQUENCE audit_log_id_seq MINVALUE 1;

-- One controlled append surface: callers supply content only. The function
-- acquires the canonical chain lock before the sequence default is evaluated,
-- preventing both hash forks and late-commit lower-id export gaps.
CREATE OR REPLACE FUNCTION append_audit_log(
    p_request_id UUID,
    p_actor_principal TEXT,
    p_actor_display TEXT,
    p_actor_roles TEXT[],
    p_provider_mode TEXT,
    p_action TEXT,
    p_from_stage TEXT,
    p_to_stage TEXT,
    p_from_status TEXT,
    p_to_status TEXT,
    p_detail JSONB,
    p_outcome TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    predecessor TEXT;
    payload TEXT;
    new_hash TEXT;
    new_id BIGINT;
BEGIN
    IF p_actor_principal IS NULL
       OR p_actor_roles IS NULL
       OR p_provider_mode IS NULL
       OR p_action IS NULL
       OR p_to_stage IS NULL
       OR p_to_status IS NULL
       OR p_detail IS NULL
       OR p_outcome IS NULL THEN
        RAISE EXCEPTION 'audit append requires complete canonical content'
            USING ERRCODE = '23502';
    END IF;

    PERFORM pg_advisory_xact_lock(71834473681920::bigint);

    SELECT entry_hash
    INTO predecessor
    FROM public.audit_log
    ORDER BY id DESC
    LIMIT 1;
    predecessor := COALESCE(predecessor, 'GENESIS');

    payload := public.audit_canonical_payload(
        p_request_id,
        p_actor_principal,
        p_actor_display,
        p_actor_roles,
        p_provider_mode,
        p_action,
        p_from_stage,
        p_to_stage,
        p_from_status,
        p_to_status,
        p_detail,
        p_outcome
    );
    new_hash := public.audit_chain_hash_v2(predecessor, payload);

    INSERT INTO public.audit_log (
        request_id,
        actor_principal,
        actor_display,
        actor_roles,
        provider_mode,
        action,
        from_stage,
        to_stage,
        from_status,
        to_status,
        detail,
        outcome,
        prev_hash,
        entry_hash
    ) VALUES (
        p_request_id,
        p_actor_principal,
        p_actor_display,
        p_actor_roles,
        p_provider_mode,
        p_action,
        p_from_stage,
        p_to_stage,
        p_from_status,
        p_to_status,
        p_detail,
        p_outcome,
        predecessor,
        new_hash
    )
    RETURNING id INTO new_id;

    RETURN new_id;
END;
$$;

-- Even a mistakenly retained table INSERT grant cannot bypass the controlled
-- writer. Inside append_audit_log(), current_user is its SECURITY DEFINER owner;
-- direct runtime INSERT executes as the runtime role and is rejected.
CREATE OR REPLACE FUNCTION audit_log_controlled_insert_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    writer_owner NAME;
BEGIN
    SELECT pg_get_userbyid(proowner)
    INTO writer_owner
    FROM pg_proc
    WHERE oid = 'public.append_audit_log(uuid,text,text,text[],text,text,text,text,text,text,jsonb,text)'::regprocedure;

    IF current_user <> writer_owner THEN
        RAISE EXCEPTION 'audit_log inserts require append_audit_log()'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS audit_log_controlled_insert ON audit_log;
CREATE TRIGGER audit_log_controlled_insert
BEFORE INSERT ON audit_log
FOR EACH ROW EXECUTE FUNCTION audit_log_controlled_insert_only();

REVOKE ALL ON FUNCTION audit_canonical_json(JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_canonical_payload(
    UUID, TEXT, TEXT, TEXT[], TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, TEXT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_chain_hash_v2(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION append_audit_log(
    UUID, TEXT, TEXT, TEXT[], TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, TEXT
) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_log_controlled_insert_only() FROM PUBLIC;

DO $$
BEGIN
    IF pg_catalog.to_regrole('ryuki_app_runtime') IS NOT NULL THEN
        EXECUTE 'REVOKE INSERT ON TABLE public.audit_log FROM ryuki_app_runtime';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.append_audit_log('
             || 'UUID, TEXT, TEXT, TEXT[], TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, TEXT'
             || ') TO ryuki_app_runtime';
    END IF;
END;
$$;
