-- Pin the legal certificate status enum at the database boundary.
--
-- Migration 011 created the base table with a status TEXT column defaulting to
-- 'Active'. The serde PascalCase variant names ('Active', 'Expiring', 'Expired',
-- 'Revoked') are already correct in the seed rows — no normalisation required.
-- This constraint keeps a bad write or future migration typo from persisting a
-- value the repo cannot decode.

ALTER TABLE certificates ADD CONSTRAINT certificates_status_check
    CHECK (status IN ('Active', 'Expiring', 'Expired', 'Revoked'));
