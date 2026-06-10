# Configuration

## Environment Variables

Copy `.env.example` to `.env` and configure:

### PostgreSQL

| Variable       | Description                  | Default                                         |
|----------------|------------------------------|-------------------------------------------------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform` |

### Entra ID

| Variable           | Description                    | Default                            |
|--------------------|--------------------------------|------------------------------------|
| `ENTRA_TENANT_ID`  | Azure AD tenant ID             | (required for live auth)           |
| `ENTRA_CLIENT_ID`  | App registration client ID     | (required for live auth)           |
| `ENTRA_AUTHORITY`  | OIDC authority URL             | `https://login.microsoftonline.com`|

### Platform

| Variable        | Description                          | Default                          |
|-----------------|--------------------------------------|----------------------------------|
| `PLATFORM_NAME` | Display name for the platform        | `Ryuki Infrastructure Platform`  |
| `PLATFORM_URL`  | Base URL where the API is served     | `http://localhost:18080`         |
| `AUTH_MODE`     | `mock-dry-run` or `entra-id-live`   | `mock-dry-run`                   |

### Infrastructure Providers (informational)

| Variable               | Provider type        | Default            |
|------------------------|----------------------|--------------------|
| `DATABASE_PROVIDER`    | CNPG operator        | `cloudnativepg`    |
| `SECRET_PROVIDER`      | Secrets management   | `hashicorp-vault`  |
| `KUBERNETES_RUNTIME`   | Kubernetes runtime   | `vsphere-vks`      |
| `MONITORING_PROVIDER`  | Monitoring system    | `zabbix`           |
| `BACKUP_PROVIDER`      | Backup system        | `veeam`            |

## Entra ID App Registration

See `docs/entra-app-registration.md` for the full app roles manifest and setup instructions.

### Summary

1. Register a new app in Entra admin center
2. Define app roles in the manifest (PlatformAdmin, DatacenterApprover, etc.)
3. Expose the API with a scope for the portal
4. Assign users/groups to roles in the Enterprise application blade
5. Set `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, and `AUTH_MODE=entra-id-live`

### Required Entra Configuration

- **App roles**: Defined in the manifest (see `docs/entra-app-registration.md`)
- **Redirect URI**: SPA (single-page application) for the portal URL
- **Token configuration**: Access tokens must include the `roles` claim
- **API permissions**: No delegated permissions required — app roles only

## PostgreSQL

The platform expects a PostgreSQL database. The included `docker-compose.yml` provisions:

- PostgreSQL 16 with user `ryuki` and database `ryuki_platform`
- Port `5432` exposed locally

For production, use a managed PostgreSQL service and set `DATABASE_URL` accordingly.

## Admin Portal

### Logo and Branding

The platform name is configured via `PLATFORM_NAME`. Logo and branding assets are uploaded through the admin portal UI after deployment — no branding files are stored in the repository.

### Access Control

Access is controlled by Entra ID app roles. The `PlatformAdmin` role grants full administrative access to the portal.
