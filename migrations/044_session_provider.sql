-- Session provenance: which auth flow minted the session.
-- Rows that existed before this migration were minted by the mock dry-run
-- flow, so the default backfills them as 'static-dry-run'. The local login
-- flow writes 'local'; in AuthMode::Local the persisted-session lookup only
-- honors provider = 'local', so stale dry-run sessions never survive a
-- switch to local auth.
ALTER TABLE sessions ADD COLUMN provider TEXT NOT NULL DEFAULT 'static-dry-run';
