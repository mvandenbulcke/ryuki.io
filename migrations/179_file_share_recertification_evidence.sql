-- 179_file_share_recertification_evidence.sql
--
-- A file share may be marked Compliant only by an immutable decision over an
-- immutable, authoritative evidence snapshot. Public API callers submit only
-- an evidence id; there is intentionally no public evidence-ingest route and
-- no live provider call in this migration or its application path.

ALTER TABLE file_shares
    ADD COLUMN governance_version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN last_recertification_decision_id UUID;

ALTER TABLE file_shares
    ADD CONSTRAINT file_shares_governance_version_positive
        CHECK (governance_version > 0);

CREATE TABLE file_share_recertification_evidence (
    id UUID PRIMARY KEY,
    share_id UUID NOT NULL REFERENCES file_shares(id),
    share_version BIGINT NOT NULL CHECK (share_version > 0),
    site TEXT NOT NULL CHECK (BTRIM(site) <> ''),
    evidence_source TEXT NOT NULL CHECK (
        evidence_source IN ('AuthoritativeProviderSnapshot', 'StaticFixture')
    ),
    collector_principal TEXT CHECK (
        collector_principal IS NULL OR (
            BTRIM(collector_principal) <> ''
            AND CHAR_LENGTH(collector_principal) <= 256
        )
    ),
    collector_attestation_ref TEXT CHECK (
        collector_attestation_ref IS NULL
        OR CHAR_LENGTH(collector_attestation_ref) <= 512
    ),
    acl_snapshot_version TEXT CHECK (
        acl_snapshot_version IS NULL OR (
            BTRIM(acl_snapshot_version) <> ''
            AND CHAR_LENGTH(acl_snapshot_version) <= 256
        )
    ),
    acl_snapshot_digest TEXT CHECK (
        acl_snapshot_digest IS NULL OR acl_snapshot_digest ~ '^[0-9A-Fa-f]{64}$'
    ),
    observed_at TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    owner_attested BOOLEAN NOT NULL DEFAULT false,
    owner_attested_by TEXT,
    reviewer TEXT,
    approver TEXT,
    group_access_reviewed BOOLEAN NOT NULL DEFAULT false,
    ntfs_acl_reviewed BOOLEAN NOT NULL DEFAULT false,
    share_permissions_reviewed BOOLEAN NOT NULL DEFAULT false,
    stale_access_reviewed BOOLEAN NOT NULL DEFAULT false,
    unresolved_findings INTEGER CHECK (unresolved_findings >= 0),
    owner_evidence_ref TEXT CHECK (
        owner_evidence_ref IS NULL OR CHAR_LENGTH(owner_evidence_ref) <= 512
    ),
    acl_evidence_ref TEXT CHECK (
        acl_evidence_ref IS NULL OR CHAR_LENGTH(acl_evidence_ref) <= 512
    ),
    reviewer_evidence_ref TEXT CHECK (
        reviewer_evidence_ref IS NULL OR CHAR_LENGTH(reviewer_evidence_ref) <= 512
    ),
    evidence_manifest_ref TEXT CHECK (
        evidence_manifest_ref IS NULL OR CHAR_LENGTH(evidence_manifest_ref) <= 512
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        observed_at IS NULL OR valid_until IS NULL OR valid_until > observed_at
    )
);

CREATE INDEX idx_file_share_recertification_evidence_share_version
    ON file_share_recertification_evidence (share_id, share_version, created_at DESC);

CREATE TABLE file_share_recertification_decisions (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL UNIQUE REFERENCES file_share_recertification_evidence(id),
    share_id UUID NOT NULL REFERENCES file_shares(id),
    share_version BIGINT NOT NULL CHECK (share_version > 0),
    site TEXT NOT NULL CHECK (BTRIM(site) <> ''),
    reviewer TEXT NOT NULL CHECK (BTRIM(reviewer) <> ''),
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    evidence_source TEXT NOT NULL CHECK (
        evidence_source IN ('AuthoritativeProviderSnapshot', 'StaticFixture')
    ),
    acl_snapshot_version TEXT CHECK (
        acl_snapshot_version IS NULL OR (
            BTRIM(acl_snapshot_version) <> ''
            AND CHAR_LENGTH(acl_snapshot_version) <= 256
        )
    ),
    acl_snapshot_digest TEXT CHECK (
        acl_snapshot_digest IS NULL OR acl_snapshot_digest ~ '^[0-9A-Fa-f]{64}$'
    ),
    evidence_manifest_ref TEXT CHECK (
        evidence_manifest_ref IS NULL OR CHAR_LENGTH(evidence_manifest_ref) <= 512
    ),
    status TEXT NOT NULL CHECK (status IN ('Compliant', 'Indeterminate')),
    reason TEXT NOT NULL CHECK (BTRIM(reason) <> ''),
    recertification_due TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (
            status = 'Compliant'
            AND recertification_due = reviewed_at + INTERVAL '8760 hours'
        )
        OR (status = 'Indeterminate' AND recertification_due IS NULL)
    )
);

CREATE INDEX idx_file_share_recertification_decisions_share_time
    ON file_share_recertification_decisions (share_id, reviewed_at DESC);

-- Enforce the load-bearing evidence rule in PostgreSQL as well as Rust so an
-- alternate repository caller cannot manufacture a Compliant decision by
-- populating only the result columns.
CREATE OR REPLACE FUNCTION file_share_recertification_validate_decision()
RETURNS trigger AS $$
DECLARE
    evidence file_share_recertification_evidence%ROWTYPE;
    share_row file_shares%ROWTYPE;
BEGIN
    -- Decision time is a database fact, not a caller assertion. The fixed
    -- 8760-hour interval matches the Rust policy's exact 365-day duration and
    -- cannot be extended through an alternate SQL/repository caller.
    NEW.reviewed_at := statement_timestamp();
    IF NEW.status = 'Compliant' THEN
        NEW.recertification_due := NEW.reviewed_at + INTERVAL '8760 hours';
    ELSE
        NEW.recertification_due := NULL;
    END IF;

    SELECT * INTO evidence
    FROM file_share_recertification_evidence
    WHERE id = NEW.evidence_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'recertification evidence does not exist';
    END IF;

    SELECT * INTO share_row
    FROM file_shares
    WHERE id = NEW.share_id;
    IF NOT FOUND OR evidence.share_id <> NEW.share_id THEN
        RAISE EXCEPTION 'recertification evidence is not bound to the decision share';
    END IF;
    IF NEW.evidence_source <> evidence.evidence_source
       OR NEW.acl_snapshot_version IS DISTINCT FROM evidence.acl_snapshot_version
       OR NEW.acl_snapshot_digest IS DISTINCT FROM evidence.acl_snapshot_digest
       OR NEW.evidence_manifest_ref IS DISTINCT FROM evidence.evidence_manifest_ref
    THEN
        RAISE EXCEPTION 'recertification decision evidence projection mismatch';
    END IF;

    IF NEW.status = 'Compliant' THEN
        IF evidence.evidence_source <> 'AuthoritativeProviderSnapshot'
           OR evidence.collector_principal IS NULL
           OR BTRIM(evidence.collector_principal) = ''
           OR evidence.collector_attestation_ref IS NULL
           OR BTRIM(evidence.collector_attestation_ref) = ''
           OR evidence.share_version <> NEW.share_version
           OR share_row.governance_version <> NEW.share_version
           OR evidence.site <> NEW.site
           OR share_row.site <> NEW.site
           OR evidence.acl_snapshot_version IS NULL
           OR BTRIM(evidence.acl_snapshot_version) = ''
           OR evidence.acl_snapshot_digest IS NULL
           OR evidence.acl_snapshot_digest !~ '^[0-9A-Fa-f]{64}$'
           OR evidence.observed_at IS NULL
           OR evidence.valid_until IS NULL
           OR evidence.observed_at > NEW.reviewed_at
           OR evidence.observed_at <= NEW.reviewed_at - INTERVAL '24 hours'
           OR evidence.valid_until <= NEW.reviewed_at
           OR NOT evidence.owner_attested
           OR evidence.owner_attested_by IS NULL
           OR BTRIM(evidence.owner_attested_by) <> share_row.owner
           OR evidence.reviewer IS NULL
           OR BTRIM(evidence.reviewer) <> NEW.reviewer
           OR evidence.approver IS NULL
           OR BTRIM(evidence.approver) = ''
           OR BTRIM(evidence.approver) = NEW.reviewer
           OR BTRIM(evidence.approver) = BTRIM(evidence.owner_attested_by)
           OR NOT evidence.group_access_reviewed
           OR NOT evidence.ntfs_acl_reviewed
           OR NOT evidence.share_permissions_reviewed
           OR NOT evidence.stale_access_reviewed
           OR evidence.unresolved_findings IS DISTINCT FROM 0
           OR evidence.owner_evidence_ref IS NULL
           OR BTRIM(evidence.owner_evidence_ref) = ''
           OR evidence.acl_evidence_ref IS NULL
           OR BTRIM(evidence.acl_evidence_ref) = ''
           OR evidence.reviewer_evidence_ref IS NULL
           OR BTRIM(evidence.reviewer_evidence_ref) = ''
           OR evidence.evidence_manifest_ref IS NULL
           OR BTRIM(evidence.evidence_manifest_ref) = ''
        THEN
            RAISE EXCEPTION 'Compliant recertification lacks authoritative bound evidence';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER file_share_recertification_validate_decision
    BEFORE INSERT ON file_share_recertification_decisions
    FOR EACH ROW EXECUTE FUNCTION file_share_recertification_validate_decision();

ALTER TABLE file_shares
    ADD CONSTRAINT file_shares_last_recertification_decision_fk
        FOREIGN KEY (last_recertification_decision_id)
        REFERENCES file_share_recertification_decisions(id);

CREATE OR REPLACE FUNCTION file_share_validate_compliant_decision_reference()
RETURNS trigger AS $$
DECLARE
    decision_share_id UUID;
    decision_status TEXT;
    decision_share_version BIGINT;
    decision_reviewed_at TIMESTAMPTZ;
    decision_recertification_due TIMESTAMPTZ;
BEGIN
    IF NEW.status = 'Compliant' THEN
        IF NEW.last_recertification_decision_id IS NULL THEN
            RAISE EXCEPTION 'Compliant file share requires a recertification decision';
        END IF;
        SELECT share_id, status, share_version, reviewed_at, recertification_due
        INTO decision_share_id, decision_status, decision_share_version,
             decision_reviewed_at, decision_recertification_due
        FROM file_share_recertification_decisions
        WHERE id = NEW.last_recertification_decision_id;
        IF NOT FOUND
           OR decision_share_id <> NEW.id
           OR decision_status <> 'Compliant'
           OR decision_share_version <> NEW.governance_version
           OR decision_recertification_due <= statement_timestamp()
           OR NEW.last_recertification IS DISTINCT FROM decision_reviewed_at
           OR NEW.recertification_due IS DISTINCT FROM decision_recertification_due
        THEN
            RAISE EXCEPTION 'file share references a foreign or stale compliance decision';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER file_share_validate_compliant_decision_insert
    BEFORE INSERT ON file_shares
    FOR EACH ROW EXECUTE FUNCTION file_share_validate_compliant_decision_reference();

CREATE TRIGGER file_share_validate_compliant_decision_update
    BEFORE UPDATE OF status, last_recertification_decision_id, governance_version,
                     last_recertification, recertification_due ON file_shares
    FOR EACH ROW EXECUTE FUNCTION file_share_validate_compliant_decision_reference();

-- Existing rows predate trustworthy evidence and cannot remain represented as
-- compliant merely because a static seed or the old evidence-free endpoint set
-- that value. Make them due and require a new evidence-backed decision.
UPDATE file_shares
SET status = 'NeedsRecertification',
    recertification_due = LEAST(recertification_due, NOW())
WHERE status = 'Compliant';

ALTER TABLE file_shares
    ADD CONSTRAINT file_shares_compliant_requires_decision
        CHECK (
            status <> 'Compliant'
            OR last_recertification_decision_id IS NOT NULL
        );

-- Changes to the protected share scope, identity, or ACL rows invalidate any
-- earlier decision and advance the exact snapshot version that new evidence
-- must name.
CREATE OR REPLACE FUNCTION file_share_metadata_bump_governance_version()
RETURNS trigger AS $$
BEGIN
    NEW.governance_version := OLD.governance_version + 1;
    NEW.status := 'NeedsRecertification';
    NEW.recertification_due := LEAST(OLD.recertification_due, NOW());
    NEW.last_recertification_decision_id := NULL;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER file_share_metadata_bump_governance_version
    BEFORE UPDATE OF unc_path, server_name, site, owner ON file_shares
    FOR EACH ROW
    WHEN (
        OLD.unc_path IS DISTINCT FROM NEW.unc_path
        OR OLD.server_name IS DISTINCT FROM NEW.server_name
        OR OLD.site IS DISTINCT FROM NEW.site
        OR OLD.owner IS DISTINCT FROM NEW.owner
    )
    EXECUTE FUNCTION file_share_metadata_bump_governance_version();

-- Governance versions are database-owned invalidation generations.  The
-- metadata trigger above overwrites any caller-supplied value with exactly
-- OLD + 1, while the NTFS row trigger below performs the same exact increment
-- from a nested trigger statement.  No top-level SQL writer may lower, jump,
-- or independently advance the generation: allowing a decrease would let a
-- writer relink an old, still-unexpired decision after a protected change.
--
-- Trigger names execute in lexical order.  The `z_` guard deliberately runs
-- after `file_share_metadata_bump_governance_version` when an UPDATE names both
-- metadata and governance_version, so the database-owned OLD + 1 value wins.
CREATE OR REPLACE FUNCTION file_share_guard_governance_version()
RETURNS trigger AS $$
DECLARE
    protected_metadata_changed BOOLEAN;
BEGIN
    IF NEW.governance_version IS NOT DISTINCT FROM OLD.governance_version THEN
        RETURN NEW;
    END IF;

    protected_metadata_changed :=
        NEW.unc_path IS DISTINCT FROM OLD.unc_path
        OR NEW.server_name IS DISTINCT FROM OLD.server_name
        OR NEW.site IS DISTINCT FROM OLD.site
        OR NEW.owner IS DISTINCT FROM OLD.owner;

    IF NEW.governance_version <> OLD.governance_version + 1 THEN
        RAISE EXCEPTION 'file-share governance version must advance exactly once'
            USING ERRCODE = '23514';
    END IF;

    -- At depth 1 this trigger was reached by caller SQL.  A protected metadata
    -- change is legitimate because the earlier metadata trigger owns the exact
    -- increment.  The only supported nested writer is the NTFS trigger below,
    -- which invalidates the same share after an ACL row change.
    IF NOT protected_metadata_changed AND pg_trigger_depth() <= 1 THEN
        RAISE EXCEPTION 'file-share governance version is database-owned'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.status <> 'NeedsRecertification'
       OR NEW.last_recertification_decision_id IS NOT NULL
       OR NEW.recertification_due > statement_timestamp() THEN
        RAISE EXCEPTION 'file-share governance advance must invalidate recertification authority'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER file_share_z_guard_governance_version
    BEFORE UPDATE OF governance_version ON file_shares
    FOR EACH ROW
    EXECUTE FUNCTION file_share_guard_governance_version();

CREATE OR REPLACE FUNCTION ntfs_permission_bump_share_governance_version()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'UPDATE' THEN
        UPDATE file_shares
        SET governance_version = governance_version + 1,
            status = 'NeedsRecertification',
            recertification_due = LEAST(recertification_due, NOW()),
            last_recertification_decision_id = NULL
        WHERE id = OLD.file_share_id;
    END IF;

    IF TG_OP = 'INSERT'
       OR (TG_OP = 'UPDATE' AND NEW.file_share_id IS DISTINCT FROM OLD.file_share_id)
    THEN
        UPDATE file_shares
        SET governance_version = governance_version + 1,
            status = 'NeedsRecertification',
            recertification_due = LEAST(recertification_due, NOW()),
            last_recertification_decision_id = NULL
        WHERE id = NEW.file_share_id;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ntfs_permission_bump_share_governance_version
    AFTER INSERT OR UPDATE OR DELETE ON ntfs_permissions
    FOR EACH ROW
    EXECUTE FUNCTION ntfs_permission_bump_share_governance_version();

CREATE OR REPLACE FUNCTION ntfs_permissions_no_truncate()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'ntfs_permissions cannot be truncated without per-share governance invalidation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ntfs_permissions_no_truncate
    BEFORE TRUNCATE ON ntfs_permissions
    FOR EACH STATEMENT EXECUTE FUNCTION ntfs_permissions_no_truncate();

-- Evidence and decisions are append-only facts. A corrected or newer review
-- uses a new evidence id, which is also the idempotency key for its decision.
CREATE OR REPLACE FUNCTION file_share_recertification_no_mutate()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'file-share recertification evidence and decisions are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER file_share_recertification_evidence_no_mutate
    BEFORE UPDATE OR DELETE ON file_share_recertification_evidence
    FOR EACH ROW EXECUTE FUNCTION file_share_recertification_no_mutate();

CREATE TRIGGER file_share_recertification_evidence_no_truncate
    BEFORE TRUNCATE ON file_share_recertification_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION file_share_recertification_no_mutate();

CREATE TRIGGER file_share_recertification_decisions_no_mutate
    BEFORE UPDATE OR DELETE ON file_share_recertification_decisions
    FOR EACH ROW EXECUTE FUNCTION file_share_recertification_no_mutate();

CREATE TRIGGER file_share_recertification_decisions_no_truncate
    BEFORE TRUNCATE ON file_share_recertification_decisions
    FOR EACH STATEMENT EXECUTE FUNCTION file_share_recertification_no_mutate();
