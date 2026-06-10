# Site Management

Sites represent physical or logical locations managed by the platform (datacenters, branch offices, edge locations).

## How Sites Work

- Sites are created and managed through the **admin portal UI**
- Site data is stored in **PostgreSQL** — no hardcoded site data exists in the repository
- Sites can be imported in bulk or entered manually

## Site Fields

| Field      | Description                          |
|------------|--------------------------------------|
| Name       | Human-readable site identifier       |
| Country    | ISO country code                     |
| OU         | Organizational unit within the org   |
| Domain     | DNS domain associated with the site  |
| Timezone   | IANA timezone identifier             |
| Network    | Primary network / subnet             |
| Org        | Owning organization or business unit |

## Adding Sites

### Via the Admin Portal

1. Log in with a role that has site management permissions
2. Navigate to **Sites** in the admin portal
3. Click **Add Site** and fill in the fields
4. Save — the site is persisted to PostgreSQL

### Via CSV Import

1. Prepare a CSV with columns matching the site fields
2. In the admin portal, navigate to **Sites → Import**
3. Upload the CSV file
4. Review and confirm the import

## Important Notes

- **No hardcoded data**: The repository contains zero site-specific data (no CSV files with real site data, no configuration files with site names, no ADR PDFs with company names)
- **No sensitive data**: Site data lives in your PostgreSQL database, not in source control
- **Multi-tenancy**: The RBAC system via Entra ID app roles controls which users can view or manage which sites
