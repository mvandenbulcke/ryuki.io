-- 164_oidc_login_state_admission.sql — bounded public OIDC login-state allocation.
--
-- Generic OIDC and Entra authorization initiation are deliberately public, but
-- every accepted request allocates a durable single-use row.  The API now uses
-- one transaction-scoped advisory lock to serialize cleanup, exact active-row
-- quotas, and insertion across every replica.  This migration records the flow
-- class for the provider-specific quota and prevents an older replica from
-- bypassing the admission transaction during a rolling deployment or rollback.

ALTER TABLE oidc_login_states
    ADD COLUMN IF NOT EXISTS flow_kind TEXT NOT NULL DEFAULT 'legacy';

ALTER TABLE oidc_login_states
    DROP CONSTRAINT IF EXISTS oidc_login_states_flow_kind;

ALTER TABLE oidc_login_states
    ADD CONSTRAINT oidc_login_states_flow_kind
        CHECK (flow_kind IN ('legacy', 'oidc', 'entra')) NOT VALID;

ALTER TABLE oidc_login_states
    VALIDATE CONSTRAINT oidc_login_states_flow_kind;

-- Supports the provider-specific active-state count and the DB-time expiry
-- predicate used by the serialized admission transaction.
CREATE INDEX IF NOT EXISTS idx_oidc_login_states_flow_expiry
    ON oidc_login_states (flow_kind, expires_at);

CREATE INDEX IF NOT EXISTS idx_oidc_login_states_expiry_state
    ON oidc_login_states (expires_at, state);

-- Rolling-deployment guard only: the transaction-scoped advisory lock plus
-- cleanup/count/insert transaction in the current API is the quota authority.
-- This marker makes unaware older binaries fail closed after the migration; it
-- is not intended as proof that an arbitrary marked SQL writer held the lock.
CREATE OR REPLACE FUNCTION enforce_oidc_login_state_admission_v2()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('ryuki.oidc_login_state_contract', TRUE) IS DISTINCT FROM '2' THEN
        RAISE EXCEPTION 'OIDC login-state admission contract v2 is required'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.flow_kind NOT IN ('oidc', 'entra') THEN
        RAISE EXCEPTION 'new OIDC login state requires a current flow kind'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS oidc_login_state_admission_v2_insert ON oidc_login_states;
CREATE TRIGGER oidc_login_state_admission_v2_insert
    BEFORE INSERT ON oidc_login_states
    FOR EACH ROW
    EXECUTE FUNCTION enforce_oidc_login_state_admission_v2();
