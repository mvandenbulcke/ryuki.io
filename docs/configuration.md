# Configuration

## Environment Variables

Copy `.env.example` to `.env` and configure:

### PostgreSQL

| Variable       | Description                  | Default                                         |
|----------------|------------------------------|-------------------------------------------------|
| `RYUKI_DATABASE_URL` | PostgreSQL connection string | `postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform` |

### Entra ID

| Variable           | Description                    | Default                            |
|--------------------|--------------------------------|------------------------------------|
| `RYUKI_ENTRA_TENANT_ID`  | Azure AD tenant ID             | (required for Entra auth)          |
| `RYUKI_ENTRA_CLIENT_ID`  | App registration client ID     | (required for Entra auth)          |
| `RYUKI_ENTRA_AUTHORITY`  | OIDC authority URL             | `https://login.microsoftonline.com`|

### Platform

| Variable        | Description                          | Default                          |
|-----------------|--------------------------------------|----------------------------------|
| `RYUKI_PLATFORM_NAME` | Display name for the platform        | `Ryuki Infrastructure Platform`  |
| `RYUKI_PLATFORM_URL`  | Base URL where the API is served     | `http://localhost:18080`         |
| `RYUKI_AUTH_MODE`     | `mock-dry-run`, `static-dry-run`, `entra-id`, or `local` | `mock-dry-run` |

### Infrastructure Providers (informational)

| Variable               | Provider type        | Default            |
|------------------------|----------------------|--------------------|
| `RYUKI_DATABASE_PROVIDER`    | CNPG operator        | `cloudnativepg`    |
| `RYUKI_SECRET_PROVIDER`      | Secrets management   | `hashicorp-vault`  |
| `RYUKI_KUBERNETES_RUNTIME`   | Kubernetes runtime   | `vsphere-vks`      |
| `RYUKI_MONITORING_PROVIDER`  | Monitoring system    | `zabbix`           |
| `RYUKI_BACKUP_PROVIDER`      | Backup system        | `veeam`            |

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

The platform expects a PostgreSQL database. The included `docker-compose.yml` provisions:

- PostgreSQL 16 with user `ryuki` and database `ryuki_platform`
- Port `5432` exposed locally

For production, use a managed PostgreSQL service and set `RYUKI_DATABASE_URL` accordingly.

## Admin Portal

### Logo and Branding

The platform name is configured via `RYUKI_PLATFORM_NAME`. Logo and branding assets are uploaded through the admin portal UI after deployment — no branding files are stored in the repository.

### Access Control

Access is controlled by Entra ID app roles. The `PlatformAdmin` role grants full administrative access to the portal.
