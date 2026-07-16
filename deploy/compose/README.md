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

The API image fixes `RYUKI_SECURITY_CONTRACT_ROOT=/app/security-contract` and
Compose requires the profile path, exact raw-byte profile digest, expected
deployment id, `development|test|production` profile pin, and the normalized
`.json` path plus exact nonzero raw-byte digest of an independently approved
conformance trust-root registry from the gitignored environment through
`RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH` and
`RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST`. The registry and profile must
both reside beneath the root-owned immutable contract root. The selected
registry is a lineage head; every exact N-1 predecessor through version 1 must
also be baked into that root. Startup verifies the complete bounded chain, but
the chain is not an external monotonic checkpoint and cannot by itself detect
rollback of the profile and head pins together.
The checked-in bundle is `implementation_only`, so it
is not selected automatically and cannot start this stack. Until an active
typed provider profile can bind every runtime authentication value, the full
Compose startup is intentionally blocked. A migration overlay cannot grant
authority or enable live execution and therefore cannot admit legacy `local`
or `entra-id` mode.

The Compose file overrides the database URL to use the internal `platform-db`
service hostname instead of the host-local `localhost` default.

The API container listens on a bridge interface, so credential-free mock/static
authority is intentionally rejected. Compose selects legacy `local`
authentication explicitly, which the current content-addressed admission
loader also rejects because the password authority cannot be equated with a
typed WebAuthn provider record. The portal defaults to labeled static dry-run
data and is published only on `127.0.0.1:18000`. Provider-live portal use needs
a separately reviewed HTTPS upstream topology; this skeleton does not weaken
the transport guard to admit a cleartext bridge hostname.

## Boundaries

- No Vault, provider adapters, worker execution, or external provider egress included.
- No credentials, tokens, tenant IDs, object IDs, private IPs, or provider endpoints embedded.
- Browser traffic reaches `portal-ui`; API contracts remain behind the Rust portal server boundary.
- The `ryuki/*:rust-dev` images are local build outputs for this loopback
  Compose workflow only. Kubernetes manifests and rendered overlays require a
  fully qualified registry/repository plus an immutable SHA-256 digest and
  reject these development tags.

## Commands

The commands below require all security-admission and local-auth inputs
described above; Compose fails interpolation before creating containers when a
required pin is absent, and API admission remains fail-closed afterward for the
documented unresolved authority binding.

```bash
docker compose --env-file .env -f deploy/compose/compose.yaml build
docker compose --env-file .env -f deploy/compose/compose.yaml up --wait
```

Validate statically:

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all
```
