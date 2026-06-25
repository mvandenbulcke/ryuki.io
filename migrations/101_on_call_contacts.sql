-- 101_on_call_contacts.sql — on-call / escalation contact registry (#61).
--
-- The platform had only a MOCK per-site incident commander
-- (ryuki_engine::incident_context). This adds a durable, administrable registry
-- of on-call / escalation contacts: who to page, in what escalation tier, for
-- which site. Operators manage it via /api/observe/oncall/contacts and incident
-- tooling resolves the right contact(s) by site + tier.

CREATE TABLE IF NOT EXISTS on_call_contacts (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    role            TEXT NOT NULL,
    -- NULL = a global contact (covers every site); a value scopes to that site.
    site            TEXT,
    -- Escalation order: 1 is paged first, higher tiers escalate.
    escalation_tier INTEGER NOT NULL DEFAULT 1
                    CHECK (escalation_tier BETWEEN 1 AND 5),
    email           TEXT,
    phone           TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A contact you cannot reach is useless: at least one NON-BLANK method is
    -- required. NULLIF(BTRIM(...), '') treats an empty/whitespace string as
    -- absent, so the DB backstop matches the API's "blank = no method" rule (a
    -- plain NOT NULL would let email='' slip past).
    CONSTRAINT on_call_contacts_has_method
        CHECK (NULLIF(BTRIM(email), '') IS NOT NULL
               OR NULLIF(BTRIM(phone), '') IS NOT NULL)
);

-- The resolve path: enabled contacts for a site, in escalation order.
CREATE INDEX IF NOT EXISTS idx_on_call_contacts_site_tier
    ON on_call_contacts (site, escalation_tier)
    WHERE enabled;
