# Site Management

Sites represent physical locations managed by the platform. Ryuki recommends **UN/LOCODE** (United Nations Code for Trade and Transport Locations) because it provides a portable public identifier. Administrators can instead register an organization-specific custom site code.

## UN/LOCODE

UN/LOCODE codes are 5-character identifiers: a 2-character **ISO 3166-1 alpha-2** country code followed by a 3-character location code. Ryuki stores them without the optional display space and in uppercase, so `JP TYO` becomes `JPTYO`.

Registration validates this shape and requires `countryCode` to match the
first two characters. It does **not** query or certify membership in the
authoritative UNECE UN/LOCODE publication. The registering administrator is
asserting that the code, location name, country, and timezone are correct; use
an independently reviewed UNECE release when authoritative membership matters.

| Code   | City        | Country         |
|--------|-------------|-----------------|
| DEBER  | Berlin      | Germany         |
| DEFRA  | Frankfurt   | Germany         |
| GBLON  | London      | United Kingdom  |
| NLAMS  | Amsterdam   | Netherlands     |
| FRPAR  | Paris       | France          |
| USASH  | Ashburn     | United States   |
| SGSIN  | Singapore   | Singapore       |
| JPTYO  | Tokyo       | Japan           |

The bundled reference registry covers locations in Europe, North America, Asia-Pacific, the Middle East, South America, and Africa.

## Custom Codes

Custom codes are first-class registry entries. They use 2-32 ASCII letters, digits, dots, underscores, or hyphens, start and end with a letter or digit, and are stored in uppercase. For example, `dc-eu-01` is stored as `DC-EU-01`.

Every canonical code is globally unique across both code systems. A custom code cannot alias an existing UN/LOCODE, and a code cannot be re-registered with a different meaning. Site-scoped roles and records use this canonical value.

## Site Selection

The admin API exposes the reference set as a **country → city → UN/LOCODE** hierarchy, so a future site-management client can browse instead of memorizing codes:

1. Pick a country from the ISO 3166 list
2. Browse available cities in that country
3. Use the compact UN/LOCODE as the site code

The current request form is an editable site-code input with five recommended UN/LOCODE suggestions. It also accepts a custom code typed by the requester, but it does not yet load all registered codes into its datalist. Entering an unknown or inactive code does not bypass request validation.

```
GET /api/admin/sites/countries          → List 49 seeded countries with site counts
GET /api/admin/sites/countries/DE/cities → Berlin, Frankfurt, München, Hamburg, Düsseldorf
```

## Managing Sites

Registration and activation are currently API operations. The portal does not yet provide an admin site-registration panel.

### List Registered Sites

```
GET /api/admin/sites          → Reference and custom sites
GET /api/admin/sites?active=true → Currently active sites only
```

Responses expose `code` and `code_system`. The existing `unlocode` response field remains as a compatibility alias for `code`, including for custom entries.

### Register a Site

UN/LOCODE is the recommended code system:

```http
POST /api/admin/sites
Content-Type: application/json

{
  "code": "BEBRU",
  "codeSystem": "unlocode",
  "name": "Brussels",
  "country": "Belgium",
  "countryCode": "BE",
  "timezone": "Europe/Brussels",
  "active": false
}
```

`codeSystem` is required. For `unlocode`, `countryCode` must match the first two characters of the canonical code; the example therefore binds `BEBRU` to `BE`.

An organization-specific code uses the same endpoint with an explicit code system:

```json
{
  "code": "DC-EU-01",
  "codeSystem": "custom",
  "name": "Primary EU datacenter",
  "country": "Belgium",
  "countryCode": "BE",
  "timezone": "Europe/Brussels",
  "active": false
}
```

The optional `active` field defaults to `false`. Keep it false until the site's policy, capacity, and scoping configuration is ready, then activate it as a separate admin operation.

### Activate a Site

```
POST /api/admin/sites/NLRTM/activate
→ Rotterdam is now available for engine operations
```

### Deactivate a Site

```
POST /api/admin/sites/NLRTM/deactivate
→ Rotterdam is no longer available for new operations
```

### Search

```
GET /api/admin/sites/search?q=DC-EU-01   → Search by site code
GET /api/admin/sites/search?q=Frankfurt  → Search by city name
GET /api/admin/sites/search?q=DE         → Search by country code
GET /api/admin/sites/search?q=Netherlands → Search by country name
```

## Seeded Active Sites

| UN/LOCODE | City        | Country         |
|-----------|-------------|-----------------|
| DEBER     | Berlin      | Germany         |
| DEFRA     | Frankfurt   | Germany         |
| FRPAR     | Paris       | France          |
| GBLON     | London      | United Kingdom  |
| NLAMS     | Amsterdam   | Netherlands     |

## Important Notes

- **Reference vs custom**: The repository includes a UN/LOCODE seed set; administrators can add durable custom entries through the API.
- **Registered vs active**: Membership and operational availability are separate. Only active registered sites pass request validation for new operations.
- **Canonical identity**: Codes are normalized before storage and authorization checks. Configure role site scopes with the canonical uppercase code.
- **Governance**: Site registration, activation, and deactivation are admin operations and are audit-recorded when the database is enabled.
- **Registry vs placement policy**: Registration and activation make a code available to request validation and scoping; they do not create provider placement, capacity, agent, OU/folder derivation, or policy-guardrail bindings. The bundled `catalog/site-catalog.yaml` covers only its reviewed policy-bound subset. Add and review those operational bindings separately before a custom or newly registered site runs a workflow that depends on them.
