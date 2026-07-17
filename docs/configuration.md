# Configuration

Ryuki configuration is loaded by the typed Rust `RyukiConfig` contract. Use `.env.example` as the canonical reference for environment variable names and defaults.

## Load Order

Configuration is merged in this order:

1. Environment variables with the `RYUKI_` prefix.
2. A local config file: `ryuki.toml`, `ryuki.json`, or `platform-config.json`.
3. Rust defaults.

Nested fields use `__` in environment variables. For example, `server.bind_address` becomes `RYUKI_SERVER__BIND_ADDRESS`.

`RyukiConfig::load()` does not parse `.env` files by itself. Use `.env` with Docker Compose, export variables into the host process environment, or use one of the supported config files for direct `cargo run` workflows.

## Deployment-security startup admission

Every API and migration process requires these seven values; none has a runtime
default and empty values fail closed:

| Variable | Required value |
|---|---|
| `RYUKI_SECURITY_CONTRACT_ROOT` | Absolute path to the immutable directory containing the profile and all referenced artifacts |
| `RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH` | Normalized relative path beneath that absolute root; absolute paths and traversal are rejected |
| `RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST` | Nonzero `sha256:<64 lowercase hex>` digest computed over the profile's exact raw bytes |
| `RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH` | Normalized relative `.json` path of the current trust-registry lineage head beneath the same immutable root; absolute paths, traversal, and non-JSON paths are rejected |
| `RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST` | Independently supplied, nonzero `sha256:<64 lowercase hex>` digest computed over that head's exact raw bytes |
| `RYUKI_EXPECTED_DEPLOYMENT_ID` | Independent canonical `deployment:` pin that must equal the document's deployment identity |
| `RYUKI_SECURITY_PROFILE` | Independent profile-class pin, exactly `development`, `test`, or `production`, that must equal the document |

Production also requires this independently pinned build-manifest pair:

| Variable | Required value |
|---|---|
| `RYUKI_PRODUCTION_BUILD_MANIFEST_PATH` | Normalized absolute `.json` path detached from the rollbackable security-contract root |
| `RYUKI_PRODUCTION_BUILD_MANIFEST_DIGEST` | Nonzero `sha256:<64 lowercase hex>` digest computed over the manifest's exact raw bytes |

The two variables form one complete binding: setting only one fails closed,
and both are mandatory when `RYUKI_SECURITY_PROFILE=production`. Development
and test deployments must leave both unset. The manifest independently pins the
expected build identity and claims an implementation-applicability inventory.
Startup independently derives that build-side inventory from the authenticated
ControlTrace and measured build facts and requires exact equality. It does not
derive deployment/provider applicability or authenticate deployed OCI
provenance. Semantic conformance closure and verification of live runtime facts
remain unconditional production blockers.

Production additionally requires these external checkpoint bindings:

| Variable | Required value |
|---|---|
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_SOCKET` | Absolute, lexically normalized Unix-socket path with a file name, no NUL, and at most 103 path bytes |
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID` | Independently pinned canonical id beginning `conformance-trust-checkpoint-authority:` |
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_KEY_ID` | Independently pinned canonical Ed25519 key id beginning `conformance-trust-checkpoint-key:` |
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64` | Canonical Base64 of exactly 32 raw Ed25519 public-key bytes |
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT` | Nonzero `sha256:<64 lowercase hex>` digest of those decoded public-key bytes |
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_MIN_AUTHORITY_EPOCH` | Positive independently held minimum authority fencing epoch |

All six values come from a separately governed workload/deployment trust
channel. They must never be supplied by, inferred from, or stored only beside
the rollbackable contract root, profile, registry, or conformance documents.

The deployment, profile, and trust-root-registry pins come from process
configuration, not from the documents being admitted. Preflight verifies the
root-owned, immutable, content-addressed root before
migration-mode or database configuration, application configuration, signing
keys, workers, router construction, or listener binding. The sole
configuration-free exception is the read-only `--dump-route-meta` maintenance
mode, which exits without starting runtime services.

The registry path and digest identify the current lineage head, not a
standalone key file. Version 1 has no predecessor; each later version contains
an exact content-addressed reference to version N-1. Preflight walks at most 16
versions back to version 1 and verifies every raw digest, identifier, and
contiguous link. For a production profile, trust-store construction then
verifies every effective-time and policy transition, decoded-key fingerprint,
and terminal tombstone before signature verification. Test and development
profiles construct no signature authority from their structural chain.
Historical snapshots do not become authority from signer-controlled `signed_at`.
After external reconciliation, however, an exact accepted-document record may
authorize a current or historical registry snapshot. An active key must be
valid for the complete trusted acceptance-time interval; a retired key is
accepted only when that complete interval is strictly before its cutoff.
Overlap keys cannot newly sign, and revoked or subsequently revoked keys always
fail closed. An interval that straddles any activation, retirement, revocation,
expiry, or freshness cutoff also fails closed.
Rolling back the profile and both independent head pins together is outside
what a self-contained hash chain can detect. Production therefore requires a
fresh domain-separated Ed25519 response from the separately pinned external
checkpoint authority. The request binds its nonce and digest, exact namespace,
candidate head including locator, validated lineage digest, and a unique sorted
lookup of at most 64 complete document digests. The response must prove
`external_strongly_consistent` state, exact equality with the authority's
current head, a current authority epoch/revision and one linearizable sequence
for head and document-acceptance events, trusted-time intervals that do not
straddle a cutoff, and exact accepted-document/signature/signer/registry
bindings. Startup never bootstraps, relocates, or advances checkpoint state;
administrative compare-and-swap and recovery reconciliation remain separate
operator workflows.

Files checked into `catalog/security-contracts/v1` with lifecycle
`implementation_only` are schema/conformance fixtures, not active deployment
authority, and cannot start the API or migration runner. A valid external
build-manifest binding still cannot start production until trusted semantic
conformance closure and live runtime facts can be verified. The proving ground
likewise requires a separately reviewed active
operator bundle and evidence; the repository does not publish or infer a
runnable profile digest.

This admission slice binds authentication to exactly one active provider
configuration. Only a matching mock/static development fixture can currently
pass, and it must use a literal loopback listener and public URL. The provider
schema does not yet project every security-relevant legacy `local` or
`entra-id` runtime value, so those live modes fail closed even under a migration
overlay. Their configuration sections below document implemented runtime
features, not a bypass around startup admission.

## Core Environment Variables

Copy `.env.example` to `.env` for Compose workflows, or export the same variables before running the API directly:

### PostgreSQL connection

| Variable | Description | Default |
|---|---|---|
| `RYUKI_DATABASE_URL` | PostgreSQL connection string | `postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform` |

### Server

| Variable | Description | Default |
|---|---|---|
| `RYUKI_SERVER__BIND_ADDRESS` | API listen address | `127.0.0.1:8080` |
| `RYUKI_SERVER__REQUEST_TIMEOUT_SECS` | Per-request timeout | `30` |
| `RYUKI_SERVER__MAX_BODY_SIZE_BYTES` | Maximum request body size | `10485760` |
| `RYUKI_SERVER__MAX_CONCURRENT_CONNECTIONS` | Connection concurrency limit | `512` |

### Entra ID

| Variable | Description | Default |
|---|---|---|
| `RYUKI_ENTRA_TENANT_ID` | Entra tenant ID | Required for `entra-id` auth |
| `RYUKI_ENTRA_CLIENT_ID` | App registration client ID | Required for `entra-id` auth |
| `RYUKI_ENTRA_AUTHORITY` | OIDC authority URL | `https://login.microsoftonline.com` |
| `RYUKI_ENTRA_REDIRECT_URI` | Browser SSO callback URL, e.g. `https://<host>/api/auth/entra/callback` | Required for the browser sign-in flow; empty leaves bearer-token auth only |
| `RYUKI_ENTRA_JWKS_TTL_SECS` | Cached JWKS lifetime in seconds (`1..=86400`) | `86400` |
| `RYUKI_ENTRA_LEEWAY_SECS` | Token `exp`/`nbf` clock leeway in seconds (`0..=300`) | `60` |

Two Entra paths coexist. Bearer-token validation (API callers presenting
`Authorization: Bearer <jwt>`) needs only tenant + client. The browser
sign-in flow (OIDC authorization-code with PKCE, the "Sign in with
Microsoft Entra ID" button) additionally needs `RYUKI_ENTRA_REDIRECT_URI`,
registered as a **Web** redirect to the server-side API/BFF callback. It is not
an SPA redirect: the server exchanges the authorization code and establishes
the browser session. Every Entra-mode launch also requires the runtime-only
`RYUKI_SESSION__CREDENTIAL_HMAC_KEY`, even when it initially uses only bearer
tokens, so browser sessions cannot later start with an unverifiable credential
store. An empty redirect URI keeps the browser button disabled.

Startup rejects a zero or greater-than-one-day Entra JWKS TTL so a successful
generation has a meaningful but bounded retirement deadline. It also rejects
token-clock leeway above five minutes; larger values would materially weaken
`exp` and `nbf` enforcement. These bounds are validated even before Entra mode
is enabled, preventing dormant unsafe configuration from becoming active later.

### Generic OIDC (current single-provider flow)

The current release also implements one provider-agnostic confidential OIDC
Authorization Code + PKCE flow. Set `RYUKI_OIDC__ENABLED=true` and configure all
of the following; the login and callback routes remain hidden when it is false.

| Variable | Description | Default |
|---|---|---|
| `RYUKI_OIDC__ISSUER` | Exact trusted issuer | Empty; required when enabled |
| `RYUKI_OIDC__AUTHORIZE_ENDPOINT` | Authorization endpoint | Empty; required when enabled |
| `RYUKI_OIDC__TOKEN_ENDPOINT` | Token endpoint | Empty; required when enabled |
| `RYUKI_OIDC__JWKS_URI` | Signing-key endpoint | Empty; required when enabled |
| `RYUKI_OIDC__CLIENT_ID` | Confidential client identifier | Empty; required when enabled |
| `RYUKI_OIDC__CLIENT_SECRET` | Runtime-injected confidential client secret | Empty; required when enabled |
| `RYUKI_OIDC__REDIRECT_URI` | Exact Web callback ending at `/api/auth/oidc/callback` | Empty; required when enabled |
| `RYUKI_OIDC__SCOPES` | Requested scopes as a JSON string array | `["openid","profile","email"]` |
| `RYUKI_OIDC__ROLES_CLAIM` | ID-token claim containing platform role values | `roles` |

Issuer, authorization, token, JWKS, and redirect URLs require HTTPS outside
explicit loopback unit tests. Token and signing-key clients never follow
redirects, and identity-provider JSON bodies are bounded by the bytes actually
received before parsing. Cached signing-key generations have a monotonic
absolute expiry; a failed refresh never revives an expired key. Persisted OIDC
and Entra browser sessions use `RYUKI_SESSION__COOKIE_MAX_AGE_SECS` as their
server-side maximum as well as their cookie lifetime.

Enabling this flow also requires PostgreSQL and the persisted-session verifier
key. It is the implemented bridge toward the
normative registry, but it is not yet the multi-issuer registry: simultaneous
providers, discovery-driven configuration, lifecycle/SCIM, WebAuthn emergency
access, service OAuth profiles, and workload identity remain specification
work rather than current launch claims.

### Vault (current secrets resolver)

The control plane resolves provider-credential handles through HashiCorp
Vault when both settings below are configured. Missing configuration fails the
dependent credential-resolution operation unless **both** the platform auth
mode (`mock-dry-run` or `static-dry-run`) and the individual connection
execution mode (`static-dry-run`) explicitly admit the local mock resolver. A
live connection never selects the mock resolver. Setting only one variable,
setting either variable blank, using an invalid transport, or configuring Vault
variables while another `secret_provider` is selected fails process startup.

| Variable | Description | Default |
|---|---|---|
| `VAULT_ADDR` | Vault server address, e.g. `https://vault.internal:8200` | Unset → fail closed outside explicit local dry-run |
| `VAULT_TOKEN` | Vault token with read access to the secret paths | Unset → fail closed outside explicit local dry-run |
| `RYUKI_VAULT_ALLOW_INSECURE_LOOPBACK` | Development exception for literal loopback HTTP only | `false` |
| `RYUKI_INTEGRATION__ENCRYPTION_KEY` | 32-byte base64/hex envelope key for persisted integration credentials | Unset; dependent encrypted operations fail |

Credential handles are `<mount>/<path>[#<field>]`, for example
`secret/ryuki/vcenter#password`. A `#field` selector is required unless the
secret has exactly one field. Values never appear in logs, errors, or
evidence.

`VAULT_ADDR` must be HTTPS and may not contain credentials, query text, or a
fragment. The client disables redirects and ambient proxies. The insecure flag
admits only a literal loopback IP such as `127.0.0.1` or `::1` for a deliberately
local proving ground; it never admits `localhost`, a container service name, or
a private network merely because that network is trusted. Production uses
authenticated TLS and workload identity or another short-lived bootstrap
instead of a process-wide static token.

This is the current compatibility adapter. Domain credential dispatch depends
on the provider-neutral `SecretResolver` capability, while `VAULT_TOKEN` is a
reusable, process-wide bearer credential and the string handle remains a
Vault-specific compatibility representation; neither is the production target.
Production must use a typed provider-qualified secret reference and workload/
managed identity or another explicitly approved short-lived bootstrap mechanism.
A missing or unimplemented provider must fail readiness or the dependent
operation instead of selecting a different adapter. See the
[secret-management provider contract](architecture/platform-security-boundary.md#pluggable-secret-management-providers).

### Platform

| Variable | Description | Default |
|---|---|---|
| `RYUKI_PLATFORM_NAME` | Display name for the platform | `Ryuki Infrastructure Platform` |
| `RYUKI_PLATFORM_URL` | Public base URL for the API | `http://localhost:18080` |
| `RYUKI_AUTH_MODE`     | `mock-dry-run`, `static-dry-run`, `entra-id`, or `local` | `mock-dry-run` |

The four primary modes above plus the separately enabled single generic-OIDC
flow describe the current implementation. The production target
is a provider registry with one or more generic OpenID Connect issuers, an
optional OIDC identity broker for SAML/LDAP/AD, a WebAuthn-based emergency
provider, scoped service credentials, and workload identity. Entra ID remains a
supported OIDC configuration rather than the only production identity source.
The current `local` mode uses password-backed sessions and is a development or
migration facility, not the production emergency-authentication target.
See the
[Platform Security Boundary Specification](architecture/platform-security-boundary.md#pluggable-authentication-providers).

### Interactive human authority assignments

Authentication proves a provider-qualified identity; it does not grant Ryuki
roles or resource reach. Every interactive local, generic OIDC, Entra, and
future brokered SAML/LDAP or passkey principal requires a durable assignment
keyed by the stable `(provider, canonical issuer, provider subject)` tuple.
Assignments carry a monotonic version, an explicit `unknown`, `active`, or
`revoked` state, a server-owned role allowlist, and independent site and
environment modes. An active axis is either explicitly `global` with no values
or `scoped` with a nonempty canonical list. Unknown, revoked, malformed, and
empty scoped assignments fail closed.

Provider claims are intersected with this assignment at browser-session
creation and on every direct-bearer admission. Persisted sessions capture the
exact assignment version and effective role/site/environment intersection;
assignment changes or revocation synchronously delete matching sessions. The
short process-local admission cache stores only a one-way authority-key
fingerprint plus the active assignment version and is never authentication
evidence without the database join.

For `RYUKI_AUTH_MODE=local`, the startup-owned assignment applies to every
configured local user and must be explicit:

| Variable | Values | Requirement |
|---|---|---|
| `RYUKI_LOCAL_AUTH__SITE_AUTHORITY` | `global` or `scoped` | Required with populated local users; omitted/`unknown` fails startup. |
| `RYUKI_LOCAL_AUTH__SITE_SCOPE` | Comma-separated canonical site ids | Empty only for explicit `global`; nonempty for `scoped`. |
| `RYUKI_LOCAL_AUTH__ENVIRONMENT_AUTHORITY` | `global` or `scoped` | Required with populated local users; omitted/`unknown` fails startup. |
| `RYUKI_LOCAL_AUTH__ENVIRONMENT_SCOPE` | Comma-separated canonical environment ids | Empty only for explicit `global`; nonempty for `scoped`. |

Federated assignments are deliberately not bootstrapped from token roles,
groups, email, or display name. Migration 182 quarantines existing identities
as Unknown. A governed assignment source must provision and read back the
provider-qualified row before sign-in can succeed. Live IdP claim/group
assignment and readback remain operator-owned trusted-access verification.

Current mock, static-admin, in-memory, and no-database branches exist so isolated
development and migration tests remain operable. They are not production
degraded modes. The target production profile requires durable PostgreSQL, an
approved secret store, and a non-development authenticator; a missing dependency
fails startup, readiness, or the dependent operation without activating a
privileged fallback. See
[configuration and deployment profiles](architecture/platform-security-boundary.md#configuration-and-deployment-profiles).

## Infrastructure Providers

Provider settings are typed enums. They select the intended platform integration, but adapters remain mock/static/dry-run unless a live integration is explicitly approved and implemented.

| Variable | Values | Default |
|---|---|---|
| `RYUKI_DATABASE_PROVIDER` | `cloudnativepg`, `postgres-local`, `aws-rds`, `azure-postgresql`, `gcp-cloud-sql` | `cloudnativepg` |
| `RYUKI_SECRET_PROVIDER` | `hashicorp-vault`, `aws-secrets-manager`, `azure-key-vault`, `gcp-secret-manager`, `bitwarden-secrets-manager`, `none` | `hashicorp-vault` |
| `RYUKI_KUBERNETES_RUNTIME` | `vsphere-vks`, `docker-compose`, `aks`, `eks`, `gke`, `openshift`, `rancher`, `none` | `vsphere-vks` |
| `RYUKI_HYPERVISOR_PROVIDER` | `vmware`, `hyperv`, `proxmox`, `nutanix-ahv`, `xen`, `kvm`, `none` | `vmware` |
| `RYUKI_MONITORING_PROVIDER` | `zabbix`, `prometheus`, `datadog`, `grafana`, `solarwinds`, `none` | `zabbix` |
| `RYUKI_BACKUP_PROVIDER` | `veeam`, `commvault`, `rubrik`, `cohesity`, `netbackup`, `none` | `veeam` |
| `RYUKI_STORAGE_PROVIDER` | `netapp`, `pure-storage`, `dell-powerstore`, `hpe-alletra`, `azure-blob`, `none` | `none` |
| `RYUKI_DNS_PROVIDER` | `infoblox`, `bluecat`, `windows-dns`, `route53`, `none` | `none` |
| `RYUKI_IPAM_PROVIDER` | `infoblox`, `phpipam`, `netbox`, `none` | `none` |
| `RYUKI_LOAD_BALANCER_PROVIDER` | `f5-bigip`, `citrix-adc`, `haproxy`, `nginx`, `none` | `none` |
| `RYUKI_FIREWALL_PROVIDER` | `palo-alto`, `checkpoint`, `fortinet`, `cisco-asa`, `none` | `none` |
| `RYUKI_BUILD_PROVIDER` | `jenkins`, `github-actions`, `azure-devops`, `argocd`, `none` | `none` |
| `RYUKI_NETWORK_PROVIDER` | `cisco-aci`, `vmware-nsx`, `evpn`, `none` | `none` |

## Nested Configuration Groups

Most operational settings are grouped under typed nested structs. Use double underscores when setting these through the environment.

| Group | Example variable | Purpose |
|---|---|---|
| `server` | `RYUKI_SERVER__POOL_MAX_CONNECTIONS` | Bind address, timeouts, body size, TLS paths, DB pool, compression, keep-alive, concurrency. |
| `cors` | `RYUKI_CORS__ALLOWED_ORIGINS` | Allowed origins and cache age. |
| `rate_limit` | `RYUKI_RATE_LIMIT__ENABLED` | Global and per-path request limits. |
| `logging` | `RYUKI_LOGGING__LEVEL` | Console log level and format. |
| `log_extended` | `RYUKI_LOG_EXTENDED__FILE_PATH` | Optional file logging and retention. |
| `security` | `RYUKI_SECURITY__CONTENT_SECURITY_POLICY` | CSP and optional HSTS settings. |
| `smtp` | `RYUKI_SMTP__ENABLED` | Email notification transport. |
| `session` | `RYUKI_SESSION__CREDENTIAL_HMAC_KEY` | Dedicated persisted-session verifier key plus cookie security settings. |
| `retention` | `RYUKI_RETENTION__DAILY_BACKUPS` | Backup retention windows. |
| `maintenance_window` | `RYUKI_MAINTENANCE_WINDOW__ENABLED` | Scheduled maintenance window metadata. |

### Persisted-session verifier key

`RYUKI_SESSION__CREDENTIAL_HMAC_KEY` is required before the listener binds
whenever Local, Entra, or generic OIDC sessions can be minted. Supply at least
32 random bytes through the selected secret manager or an equivalent
runtime-only secret injection; do not put the value in a committed TOML, JSON,
Compose, or Kubernetes manifest. The API stores only an HMAC-SHA256 verifier of
each 256-bit `rys_...` session token. The administrative session UUID is
unrelated metadata and cannot authenticate.

`RYUKI_SESSION__FEDERATED_AUTHORITY_MAX_STALENESS_SECS` bounds how long a
persisted non-local session may authorize without a fresh validated assertion
or trusted lifecycle heartbeat. It defaults to 900 seconds and cannot exceed
3600 seconds. Expiry at this bound fails closed and requires fresh identity
evidence; it does not claim that an IdP lifecycle connector delivered an event.

`RYUKI_SESSION__COOKIE_SECURE=false` is admitted only when
`RYUKI_PLATFORM_URL` is plain HTTP on a literal loopback host (`localhost`, a
`127.0.0.0/8` address, or `[::1]`). HTTPS and non-loopback public origins fail
startup unless Secure cookies remain enabled. This rule is derived from the
external platform URL rather than the API listener address, so TLS-terminating
reverse proxies and loopback-published container bridges keep the intended
policy. When generic OIDC or Entra browser callbacks are configured, their
redirect URLs must also use loopback HTTP before non-Secure cookie mode is
admitted.

This release supports one active verifier key. Changing it deliberately
invalidates all current bearers, so stale rows simply expire or are swept and
users sign in again. Zero-downtime key rotation requires the planned
versioned key-id/keyring extension; do not attempt overlap by retaining the old
UUID-as-bearer behavior.

### Secret-manager target architecture

The current control-plane resolver supports Vault and a development mock; the
provider enum lists additional intended platforms. The normative target is a
capability-based adapter registry for HashiCorp Vault, OpenBao, Azure Key Vault,
AWS Secrets Manager, Google Secret Manager, CyberArk, 1Password Connect,
Bitwarden Secrets Manager, and future approved plugins. CSI, External Secrets
Operator, and Vault Secrets Operator are modeled separately as materialization
controllers rather than being credited with lease-aware resolution capabilities.
Production adapters authenticate with managed/workload identity and report their
real versioning, lease, renewal, revocation, wrapping, PKI, and rotation
capabilities. Unsupported required capabilities fail closed.

See the
[secret-management provider contract](architecture/platform-security-boundary.md#pluggable-secret-management-providers).

## Validation

`RyukiConfig::validate()` returns hard errors that should block startup or mark config invalid. `RyukiConfig::validation_warnings()` returns advisory operational guidance, such as reminding operators to configure Vault externally when `RYUKI_SECRET_PROVIDER=hashicorp-vault`.

## Entra ID App Registration

See `docs/entra-app-registration.md` for the full app roles manifest and setup instructions.

### Summary

1. Register a new app in Entra admin center
2. Define app roles in the manifest (PlatformAdmin, DatacenterApprover, etc.)
3. Expose the API with a scope for the portal
4. Assign users/groups to roles in the Enterprise application blade
5. Set `RYUKI_ENTRA_TENANT_ID`, `RYUKI_ENTRA_CLIENT_ID`, and `RYUKI_AUTH_MODE=entra-id`

### Required Entra Configuration

- **App roles**: Defined in the manifest (see `docs/entra-app-registration.md`)
- **Redirect URI**: Web/server-side callback, for example `https://<host>/api/auth/entra/callback`; do not register the portal as an SPA token recipient
- **Token configuration**: Access tokens must include the `roles` claim
- **API permissions**: No delegated permissions required — app roles only

## PostgreSQL

The platform expects PostgreSQL 18. The local compose skeleton in `deploy/compose/compose.yaml` provisions:

- PostgreSQL 18 with user `ryuki` and database `ryuki_platform`
- Port `5432` exposed locally

For production, use CloudNativePG or a managed PostgreSQL service and set `RYUKI_DATABASE_URL` accordingly.

### Why PostgreSQL only

PostgreSQL is the **only** supported database — there is no MySQL, SQLite, or other backend, and there are no plans to add one. While the platform is built on `sqlx`, the schema and persistence layer depend on PostgreSQL-specific features that have no portable equivalent:

- **`xmin`-based optimistic concurrency.** Read-modify-write mutations guard against lost updates with `WHERE id = $1 AND xmin = $N::xid`. `xmin` is a PostgreSQL system column; MySQL and SQLite have no equivalent.
- **`JSONB`** columns and operators (`to_jsonb`, `jsonb_set`, `jsonb_array_elements`) store full entity snapshots and audit history.
- **`RETURNING`**, `ON CONFLICT` upserts, `gen_random_uuid()`, partial/`FILTER` aggregates, and `TIMESTAMPTZ` interval arithmetic are used throughout the migrations and queries.

`RYUKI_DATABASE_PROVIDER` selects the PostgreSQL *deployment* (CloudNativePG, a local container, AWS RDS, Azure Database for PostgreSQL, or GCP Cloud SQL) — every option is PostgreSQL.

## Admin Portal

### Logo and Branding

The platform name is configured via `RYUKI_PLATFORM_NAME`. Logo and branding assets are uploaded through the admin portal UI after deployment; no branding files are stored in the repository.

### Access Control

In the current `entra-id` mode, access is controlled by Entra app-role values
and `PlatformAdmin` grants full administrative access to the portal. This is a
transitional provider-specific mapping. The production target accepts verified
claims from any configured provider, normalizes them into one principal, and
authorizes typed actions at the platform boundary.
