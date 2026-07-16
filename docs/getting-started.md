# Getting Started

## Prerequisites

- Rust 1.85+ (edition 2024)
- `cargo-leptos` and the `wasm32-unknown-unknown` Rust target
- Docker and Docker Compose
- PostgreSQL 18+

Install the portal build tooling once:

```bash
rustup target add wasm32-unknown-unknown
cargo install cargo-leptos --locked
```

## Quick Start

### 1. Clone and set up

```bash
git clone https://github.com/mvandenbulcke/ryuki.io.git ryuki-platform
cd ryuki-platform
cp .env.example .env
```

For Docker Compose workflows, edit `.env` and set `RYUKI_DATABASE_URL` to match your local PostgreSQL. For direct `cargo run`, export the needed `RYUKI_` variables or create `ryuki.toml`, `ryuki.json`, or `platform-config.json`; `.env` is not loaded automatically by the Rust config loader.

### 2. Start the database

```bash
docker compose -f deploy/compose/compose.yaml up -d platform-db
```

### 3. Build the workspace

```bash
cargo build --workspace
```

### 4. Run the API server on port 8081

The Rust config loader does not read `.env` itself. Export
`RYUKI_DATABASE_URL` in this shell without committing its value, then pass the
bind address explicitly so the portal can use its default port `8080`. Pass
additional authentication settings explicitly or through a supported Ryuki
config file rather than sourcing `.env` as shell code:

```bash
RYUKI_SERVER__BIND_ADDRESS=127.0.0.1:8081 \
  cargo run -p ryuki-api
```

Wait for `curl --fail http://127.0.0.1:8081/ready` to succeed.

### 5. Run the portal on port 8080

In a second terminal:

```bash
LEPTOS_SITE_ADDR=127.0.0.1:8080 \
RYUKI_API_URL=http://127.0.0.1:8081 \
RYUKI_PORTAL_PUBLIC_ORIGIN=http://127.0.0.1:8080 \
RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK=true \
RYUKI_PORTAL_EXECUTION_MODE=live-provider \
cargo leptos serve --manifest-path portal/portal-ui/Cargo.toml
```

Open `http://127.0.0.1:8080`. Without `live-provider`, the portal deliberately
uses its labeled static dry-run data instead of forwarding to the API.

The Compose stack uses different loopback host ports: API `18080`, portal
`18000`. Its bridged API uses local authentication rather than mock authority
on a non-loopback container listener. Before starting the full stack, set
`RYUKI_LOCAL_AUTH__USERS`, explicit site/environment authority modes (and
scope lists for `scoped` modes), and a random, at-least-32-byte
`RYUKI_SESSION__CREDENTIAL_HMAC_KEY` in the gitignored root `.env`. The default
Compose portal remains static dry-run at `http://127.0.0.1:18000`.

### 6. Run tests

```bash
cargo test --workspace
```

### 7. Run validators

Run from the repository root (the validator defaults `--root` to the current
directory; pass `--root <path>` to validate another checkout):

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all
```

For the complete pre-test gate, also run the format, Clippy, secret-scan, and
diff checks in [First Test Acceptance](first-test.md).

## Authentication Modes

Default is **mock-dry-run** — no real Entra ID, all operations are simulated.

To enable live Entra ID authentication:

1. Register an Entra ID application (see `docs/configuration.md`)
2. Export `RYUKI_AUTH_MODE=entra-id`, `RYUKI_ENTRA_TENANT_ID`, and
   `RYUKI_ENTRA_CLIENT_ID` into the API process (Compose may read them from the
   gitignored `.env`; direct Cargo runs do not)
3. Inject a random, at-least-32-byte
   `RYUKI_SESSION__CREDENTIAL_HMAC_KEY` at runtime
4. For browser SSO, also set the exact registered
   `RYUKI_ENTRA_REDIRECT_URI`; omit it only for deliberate bearer-only use
5. Restart the API and require `/ready`

For a non-Entra provider, the current release has a single generic OIDC + PKCE
profile under `RYUKI_OIDC__*`. See [Configuration](configuration.md#generic-oidc-current-single-provider-flow).
The platform boundary specification defines the remaining multi-provider,
brokered SAML/LDAP, WebAuthn emergency, service OAuth, and workload-identity
work.

## Project Structure

```
ryuki.io/
├── sources/
│   ├── ryuki-core/     # Shared types, YAML, secret scanning
│   ├── ryuki-api/      # Axum HTTP API server
│   └── ryuki-engine/   # Business logic, auth, adapters
├── portal/
│   └── portal-ui/      # Leptos SPA frontend
├── scripts/
│   └── validator-rs/   # Rust validators
├── tests/              # Integration tests
└── docs/               # Documentation
```
