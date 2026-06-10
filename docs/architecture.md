# Architecture

## Stack

| Layer      | Technology               |
|------------|--------------------------|
| Portal     | Rust / Leptos (WASM)     |
| API        | Rust / Axum              |
| Engine     | Rust                     |
| Core       | Rust                     |
| Database   | PostgreSQL / sqlx        |
| Secrets    | HashiCorp Vault          |
| Auth       | Entra ID (OIDC / OAuth2) |

## Component Diagram

```
 Browser (WASM)
      │
      ▼
┌──────────┐
│  Portal  │  Leptos SPA, same-origin
│ portal-ui│
└────┬─────┘
     │ HTTP (JSON)
     ▼
┌──────────┐
│   API    │  Axum server, CORS (same-origin only)
│ ryuki-api│
└────┬─────┘
     │
     ▼
┌──────────┐
│  Engine  │  Business logic, auth, request lifecycle
│ryuki-eng │
└────┬─────┘
     │
     ▼
┌──────────┐     ┌──────────┐     ┌──────────┐
│   Core   │     │ PostgreSQL│     │  Vault   │
│ryuki-core│     │  (sqlx)  │     │ (secrets)│
└──────────┘     └──────────┘     └──────────┘
     │
     ▼
┌──────────────┐
│   Adapters   │  Pluggable provider implementations
│  (vsphere,   │
│  hyperv,     │
│  proxmox)    │
└──────────────┘
```

## Key Decisions

- **Same-origin**: Portal and API served from the same origin. CORS allows the Portal origin only.
- **Dry-run default**: All provider operations default to mock/dry-run unless `AUTH_MODE` is set to `entra-id-live`.
- **Vault secrets**: Platform secrets (DB credentials, provider tokens) stored in HashiCorp Vault, never in environment or config files.
- **Entra app roles**: RBAC via Entra ID app roles with `roles` claim in the access token. No group-name-to-role mapping.

## Network Policy

```
Browser ──► Portal (same-origin) ──► API ──► Database
                                        ├───► Vault
                                        └───► Adapters
```

Only the API server has access to the database, Vault, and provider adapters. The Portal communicates exclusively with the API.
