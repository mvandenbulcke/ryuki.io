# Configuration

Ryuki configuration is loaded by the typed Rust `RyukiConfig` contract. Use `.env.example` as the canonical reference for environment variable names and defaults.

## Load Order

Configuration is merged in this order:

1. Environment variables with the `RYUKI_` prefix.
2. A local config file: `ryuki.toml`, `ryuki.json`, or `platform-config.json`.
3. Rust defaults.

Nested fields use `__` in environment variables. For example, `server.bind_address` becomes `RYUKI_SERVER__BIND_ADDRESS`.

`RyukiConfig::load()` does not parse `.env` files by itself. Use `.env` with Docker Compose, export variables into the host process environment, or use one of the supported config files for direct `cargo run` workflows.

## Core Environment Variables

Copy `.env.example` to `.env` for Compose workflows, or export the same variables before running the API directly:

### PostgreSQL

| Variable | Description | Default |
|---|---|---|
| `RYUKI_DATABASE_URL` | PostgreSQL connection string | `postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform` |

### Server

| Variable | Description | Default |
|---|---|---|
| `RYUKI_SERVER__BIND_ADDRESS` | API listen address | `0.0.0.0:8080` |
| `RYUKI_SERVER__REQUEST_TIMEOUT_SECS` | Per-request timeout | `30` |
| `RYUKI_SERVER__MAX_BODY_SIZE_BYTES` | Maximum request body size | `10485760` |
| `RYUKI_SERVER__MAX_CONCURRENT_CONNECTIONS` | Connection concurrency limit | `512` |

### Entra ID

| Variable | Description | Default |
|---|---|---|
| `RYUKI_ENTRA_TENANT_ID` | Entra tenant ID | Required for `entra-id` auth |
| `RYUKI_ENTRA_CLIENT_ID` | App registration client ID | Required for `entra-id` auth |
| `RYUKI_ENTRA_AUTHORITY` | OIDC authority URL | `https://login.microsoftonline.com` |

### Platform

| Variable | Description | Default |
|---|---|---|
| `RYUKI_PLATFORM_NAME` | Display name for the platform | `Ryuki Infrastructure Platform` |
| `RYUKI_PLATFORM_URL` | Public base URL for the API | `http://localhost:18080` |
| `RYUKI_AUTH_MODE`     | `mock-dry-run`, `static-dry-run`, `entra-id`, or `local` | `mock-dry-run` |

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
| `session` | `RYUKI_SESSION__COOKIE_SECURE` | Session cookie security settings. |
| `retention` | `RYUKI_RETENTION__DAILY_BACKUPS` | Backup retention windows. |
| `maintenance_window` | `RYUKI_MAINTENANCE_WINDOW__ENABLED` | Scheduled maintenance window metadata. |

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
- **Redirect URI**: SPA (single-page application) for the portal URL
- **Token configuration**: Access tokens must include the `roles` claim
- **API permissions**: No delegated permissions required — app roles only

## PostgreSQL

The platform expects PostgreSQL 18. The local compose skeleton in `deploy/compose/compose.yaml` provisions:

- PostgreSQL 18 with user `ryuki` and database `ryuki_platform`
- Port `5432` exposed locally

For production, use CloudNativePG or a managed PostgreSQL service and set `RYUKI_DATABASE_URL` accordingly.

## Admin Portal

### Logo and Branding

The platform name is configured via `RYUKI_PLATFORM_NAME`. Logo and branding assets are uploaded through the admin portal UI after deployment; no branding files are stored in the repository.

### Access Control

Access is controlled by Entra ID app roles. The `PlatformAdmin` role grants full administrative access to the portal.
