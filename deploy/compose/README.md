# Local Compose Skeleton

Compose file for local container bootstrap of the Ryuki Infrastructure Platform.

## Services

| Service | Image | Local Port | Purpose |
|---|---|---|---|
| `platform-db` | `postgres:18-alpine` | `5432` | PostgreSQL 18 database. |
| `platform-api` | `ryuki/platform-api:rust-dev` | `18080` | Rust platform API with health, readiness, and catalog endpoints. |
| `portal-ui` | `ryuki/portal-ui:rust-dev` | `18000` | Full-stack Rust/Leptos portal server. |

## Boundaries

- No Vault, provider adapters, worker execution, or external provider egress included.
- No credentials, tokens, tenant IDs, object IDs, private IPs, or provider endpoints embedded.
- Browser traffic reaches `portal-ui`; API contracts remain behind the Rust portal server boundary.

## Commands

```bash
docker compose -f deploy/compose/compose.yaml build
docker compose -f deploy/compose/compose.yaml up
```

Validate statically:

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all
```
