-- 051_secrets_rotation.sql — durable managed secrets + rotation runs (P1 sweep).
--
-- Secret rotation governance (register POST /api/protect/secrets, rotate, force
-- rotate-all, mark-failed) and the rotation-run history lived only in a
-- process-local OnceLock<Mutex> engine static and reset on restart. Make them
-- durable. The engine stays pure (its static becomes the no-DB fallback) and
-- ryuki-api persists/reads here via sqlx.
--
-- These rows hold rotation METADATA ONLY — `vault_path` is a Vault reference,
-- never secret material — so seeding/persisting is safe (no secret values).
-- Enum columns store the EXACT serde strings (rename_all="kebab-case" hyphenates
-- each consecutive capital, so secret_type is: service-account /
-- database-credential / a-p-i-key (APIKey) / s-s-l-certificate (SSLCertificate)
-- / s-s-h-key (SSHKey) / token; status: active/expired/rotating/failed; run
-- status: running/completed/failed) so a row round-trips byte-for-byte via serde
-- into the engine ManagedSecret/RotationRun.
-- last_rotated/next_rotation_due/started_at/completed_at are RFC3339 TEXT (the
-- engine's own format) — date filters cast them to timestamptz in SQL.

CREATE TABLE IF NOT EXISTS managed_secrets (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    secret_type            TEXT NOT NULL,
    vault_path             TEXT NOT NULL,
    rotation_interval_days BIGINT NOT NULL,
    last_rotated           TEXT NOT NULL,
    next_rotation_due      TEXT NOT NULL,
    status                 TEXT NOT NULL DEFAULT 'active',
    owner                  TEXT NOT NULL,
    site                   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rotation_runs (
    id            TEXT PRIMARY KEY,
    secret_id     TEXT NOT NULL REFERENCES managed_secrets (id) ON DELETE CASCADE,
    started_at    TEXT NOT NULL,
    completed_at  TEXT,
    status        TEXT NOT NULL,
    rotated_by    TEXT NOT NULL,
    new_version   TEXT,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_managed_secrets_site ON managed_secrets (site);
CREATE INDEX IF NOT EXISTS idx_rotation_runs_secret ON rotation_runs (secret_id);

-- Seed the 8 demo secrets (exact engine seed_data() values; timestamps fixed
-- around 2026-06-13 — the static path keeps its dynamic now±days variants).
INSERT INTO managed_secrets (id, name, secret_type, vault_path, rotation_interval_days, last_rotated, next_rotation_due, status, owner, site) VALUES
    ('sr-defra-001', 'defra-api-deploy-token',  'token',               'kv/defra/app/deploy-token',          30, '2026-04-29T00:00:00+00:00', '2026-05-29T00:00:00+00:00', 'expired',  'platform.security',  'DEFRA'),
    ('sr-defra-002', 'defra-postgres-admin',    'database-credential', 'database/defra/postgres/admin',      14, '2026-06-05T00:00:00+00:00', '2026-06-19T00:00:00+00:00', 'active',   'database.ops',       'DEFRA'),
    ('sr-defra-003', 'defra-ingress-cert',      's-s-l-certificate',   'pki/defra/ingress',                  60, '2026-04-16T00:00:00+00:00', '2026-06-15T00:00:00+00:00', 'active',   'network.security',   'DEFRA'),
    ('sr-gblon-001', 'gblon-backup-service',    'service-account',     'kv/gblon/backup/service-account',    30, '2026-05-13T00:00:00+00:00', '2026-06-12T00:00:00+00:00', 'active',   'backup.ops',         'GBLON'),
    ('sr-gblon-002', 'gblon-automation-api',    'a-p-i-key',           'kv/gblon/automation/api-key',        45, '2026-06-01T00:00:00+00:00', '2026-07-16T00:00:00+00:00', 'active',   'automation.ops',     'GBLON'),
    ('sr-gblon-003', 'gblon-breakglass-ssh',    's-s-h-key',           'ssh/gblon/breakglass',               90, '2026-03-13T00:00:00+00:00', '2026-06-11T00:00:00+00:00', 'failed',   'site.reliability',   'GBLON'),
    ('sr-frpar-001', 'frpar-monitoring-token',  'token',               'kv/frpar/monitoring/token',          30, '2026-05-26T00:00:00+00:00', '2026-06-25T00:00:00+00:00', 'active',   'observability.ops',  'FRPAR'),
    ('sr-frpar-002', 'frpar-vault-replication', 'service-account',     'kv/frpar/vault/replication',         30, '2026-06-12T00:00:00+00:00', '2026-07-12T00:00:00+00:00', 'rotating', 'platform.security',  'FRPAR')
ON CONFLICT (id) DO NOTHING;

INSERT INTO rotation_runs (id, secret_id, started_at, completed_at, status, rotated_by, new_version, error_message) VALUES
    ('rr-defra-001', 'sr-defra-002', '2026-06-05T00:00:00+00:00', '2026-06-05T00:03:00+00:00', 'completed', 'alice.operator',     'v12', NULL),
    ('rr-defra-002', 'sr-defra-001', '2026-05-29T00:00:00+00:00', '2026-05-29T00:01:00+00:00', 'failed',    'vault-rotation-job', NULL,  'mock policy denied'),
    ('rr-gblon-001', 'sr-gblon-001', '2026-05-13T00:00:00+00:00', '2026-05-13T00:02:00+00:00', 'completed', 'backup.ops',         'v7',  NULL),
    ('rr-frpar-001', 'sr-frpar-002', '2026-06-12T23:15:00+00:00', NULL,                        'running',   'platform.security',  NULL,  NULL)
ON CONFLICT (id) DO NOTHING;
