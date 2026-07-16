-- 191_metering_usage_query_indexes.sql
--
-- C280 admits only a closed 90-day window and gives the aggregate its own
-- two-second statement budget. Supply exact btree access paths for the two
-- dynamic SQL shapes as well: unrestricted audit callers seek by created_at,
-- while site-scoped callers seek by site and then created_at. The UUID primary
-- key is the stable final key for equal timestamps and preserves the same
-- `(created_at, id)` ordering contract used by bounded request reads.
--
-- These indexes are intentionally additive. They are built in the migration
-- transaction (rather than CONCURRENTLY) because sqlx migrations are
-- transactional; operators should schedule the build in a write-light window
-- when requests is already large.

CREATE INDEX idx_requests_metering_created_at_id
    ON requests (created_at DESC, id DESC);

CREATE INDEX idx_requests_metering_site_created_at_id
    ON requests (site, created_at DESC, id DESC);
