-- Pin the legal hardware enum columns at the database boundary.
--
-- Migration 039 created hardware_assets with TEXT columns for vendor,
-- lifecycle_status, and support_status. The serde PascalCase variant names
-- are already correct in all six seed rows ('HPE'/'Lenovo', 'Production'/
-- 'Extended'/'Retiring', 'Supported'/'Expiring'/'Expired'). These constraints
-- keep a bad write or future migration typo from persisting a value the repo
-- cannot decode.
--
-- SupportStatus has three variants (Supported, Expiring, Expired); note the
-- engine does NOT have an EndOfLife variant — verify against hardware_lifecycle.rs.

ALTER TABLE hardware_assets ADD CONSTRAINT hardware_assets_vendor_check
    CHECK (vendor IN ('HPE', 'Lenovo'));

ALTER TABLE hardware_assets ADD CONSTRAINT hardware_assets_lifecycle_check
    CHECK (lifecycle_status IN ('Production', 'Extended', 'Retiring', 'Retired'));

ALTER TABLE hardware_assets ADD CONSTRAINT hardware_assets_support_check
    CHECK (support_status IN ('Supported', 'Expiring', 'Expired'));
