# Site Management

Sites represent physical locations managed by the platform. Ryuki uses **UN/LOCODE** (United Nations Code for Trade and Transport Locations) as the standard site identifier.

## UN/LOCODE

UN/LOCODE codes are 5-character identifiers: a 2-character **ISO 3166-1 alpha-2** country code followed by a 3-character location code.

| Code   | City        | Country         |
|--------|-------------|-----------------|
| DEBER  | Berlin      | Germany         |
| DEFRA  | Frankfurt   | Germany         |
| GBLON  | London      | United Kingdom  |
| NLAMS  | Amsterdam   | Netherlands     |
| FRPAR  | Paris       | France          |
| USASH  | Ashburn     | United States   |
| SGSIN  | Singapore   | Singapore       |
| JP TYO | Tokyo       | Japan           |

The reference registry contains **89 locations across 33 countries** covering Europe, North America, Asia-Pacific, Middle East, South America, and Africa.

## Site Selection Flow

Users select sites through a **country → city → UN/LOCODE** flow:

1. Pick a country from the ISO 3166 list
2. Browse available cities in that country
3. The UN/LOCODE is auto-populated

```
GET /api/admin/sites/countries          → List 33 countries with site counts
GET /api/admin/sites/countries/DE/cities → Berlin, Frankfurt, München, Hamburg, Düsseldorf
```

## Managing Sites

### List Reference Sites

```
GET /api/admin/sites          → All 89 reference locations
GET /api/admin/sites?active=true → Currently active sites only
```

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
GET /api/admin/sites/search?q=Frankfurt  → Search by city name
GET /api/admin/sites/search?q=DE         → Search by country code
GET /api/admin/sites/search?q=Netherlands → Search by country name
```

## Current Active Sites

| UN/LOCODE | City        | Country         |
|-----------|-------------|-----------------|
| DEBER     | Berlin      | Germany         |
| DEFRA     | Frankfurt   | Germany         |
| FRPAR     | Paris       | France          |
| GBLON     | London      | United Kingdom  |
| NLAMS     | Amsterdam   | Netherlands     |

## Important Notes

- **No hardcoded data**: Zero site-specific data exists in the repository. All sites are managed through the admin API.
- **Reference vs active**: The registry contains 89 reference locations. Only activated sites are available for engine operations.
- **UN/LOCODE standard**: Follows ISO 3166-1 country codes and UN/LOCODE location identifiers.
- **Multi-tenancy**: RBAC via Entra ID app roles controls which users can manage which sites.
