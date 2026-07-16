# Local Compose Skeleton

Compose file for local container bootstrap of the Ryuki Infrastructure Platform.

## Services

| Service | Image | Local Port | Purpose |
|---|---|---|---|
| `platform-db` | `postgres:18-alpine` | `5432` | PostgreSQL 18 database. |
| `platform-api` | `ryuki/platform-api:rust-dev` | `18080` | Rust platform API with health, readiness, and catalog endpoints. |
| `portal-ui` | `ryuki/portal-ui:rust-dev` | `18000` | Full-stack Rust/Leptos portal server. |

## Configuration

Compose uses the gitignored root `.env` only as interpolation input. It forwards
the local users, explicit site/environment authority modes and scopes, and
`RYUKI_SESSION__CREDENTIAL_HMAC_KEY` to `platform-api`; unrelated `.env`
settings are not attached to the container. The static validator attests these
forwarding descriptors, not the ignored values themselves. API startup
validates the local-user syntax, explicit authority shape, and session key
length.

The Compose file overrides the database URL to use the internal `platform-db`
service hostname instead of the host-local `localhost` default.

The API container listens on a bridge interface, so credential-free mock/static
authority is intentionally rejected. Before starting the full stack, put a
valid `RYUKI_LOCAL_AUTH__USERS` value, explicit
`RYUKI_LOCAL_AUTH__SITE_AUTHORITY` and
`RYUKI_LOCAL_AUTH__ENVIRONMENT_AUTHORITY` modes (plus scope lists when either
mode is `scoped`), and a random, at-least-32-byte
`RYUKI_SESSION__CREDENTIAL_HMAC_KEY` in the gitignored root `.env`; Compose
selects `local` authentication explicitly. The portal defaults to labeled
static dry-run data and is published only on `127.0.0.1:18000`. Provider-live
portal use needs a separately reviewed HTTPS upstream topology; this skeleton
does not weaken the transport guard to admit a cleartext bridge hostname.

## Boundaries

- No Vault, provider adapters, worker execution, or external provider egress included.
- No credentials, tokens, tenant IDs, object IDs, private IPs, or provider endpoints embedded.
- Browser traffic reaches `portal-ui`; API contracts remain behind the Rust portal server boundary.
- The `ryuki/*:rust-dev` images are local build outputs for this loopback
  Compose workflow only. Kubernetes manifests and rendered overlays require a
  fully qualified registry/repository plus an immutable SHA-256 digest and
  reject these development tags.

## Commands

```bash
docker compose --env-file .env -f deploy/compose/compose.yaml build
docker compose --env-file .env -f deploy/compose/compose.yaml up --wait
```

Validate statically:

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all
```
