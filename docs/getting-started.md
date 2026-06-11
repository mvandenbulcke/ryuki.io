# Getting Started

## Prerequisites

- Rust 1.85+ (edition 2024)
- Docker and Docker Compose
- PostgreSQL 16+

## Quick Start

### 1. Clone and set up

```bash
git clone <repo-url> ryuki-platform
cd ryuki-platform
cp .env.example .env
```

Edit `.env` — set `RYUKI_DATABASE_URL` to match your local PostgreSQL.

### 2. Start the database

```bash
docker compose up -d
```

### 3. Build the workspace

```bash
cargo build --workspace
```

### 4. Run the API server

```bash
cargo run -p ryuki-api
```

The API starts at `http://localhost:18080`.

### 5. Run tests

```bash
cargo test --workspace
```

### 6. Run validators

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
