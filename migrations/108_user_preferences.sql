-- 108_user_preferences.sql — per-user scope preferences (#59 backend).
--
-- Stores each user's last-selected scope (preferred site / environment) so the
-- portal can default the scope selector. Keyed by the VERIFIED principal
-- (AuthSession.user_id), one row per user. Both fields are optional (NULL = no
-- preference). Values are free text (the portal renders the picker from the
-- real site/environment lists); the API validates length + control characters.

CREATE TABLE IF NOT EXISTS user_preferences (
    user_id               TEXT PRIMARY KEY,
    preferred_site        TEXT,
    preferred_environment TEXT,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
