# Getting Started

## Prerequisites

- Rust 1.85+ (edition 2024)
- Docker and Docker Compose
- PostgreSQL 18+

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

### 4. Run the API server

```bash
cargo run -p ryuki-api
```

The API listens on `http://localhost:8080` by default. The compose API service publishes container port `8080` as host port `18080`.

### 5. Run tests

```bash
cargo test --workspace
```

### 6. Run validators

Run from the repository root (the validator defaults `--root` to the current
directory; pass `--root <path>` to validate another checkout):

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all
```

## Authentication Modes

Default is **mock-dry-run** — no real Entra ID, all operations are simulated.

To enable live Entra ID authentication:

1. Register an Entra ID application (see `docs/configuration.md`)
2. Set `RYUKI_AUTH_MODE=entra-id` in `.env`
3. Set `RYUKI_ENTRA_TENANT_ID` and `RYUKI_ENTRA_CLIENT_ID`
4. Restart the API

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
