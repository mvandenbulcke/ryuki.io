# AGENTS.md

Ryuki Infrastructure Platform — Rust workspace for system engineer platform engineering.

## Stack

- **Portal UI**: Rust / Leptos / Axum SSR — `portal/portal-ui`
- **API**: Rust / Axum / sqlx — `sources/ryuki-api`
- **Engine**: Rust domain models — `sources/ryuki-engine`
- **Core**: Rust shared types — `sources/ryuki-core`
- **Validator**: Rust validation engine — `scripts/validator-rs`
- **Database**: PostgreSQL 18 (Docker / CloudNativePG)
- **Secrets**: HashiCorp Vault

## Build & Test

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --check --all
cargo clippy --workspace -- -D warnings
./scripts/no-secret-scan.sh
git diff --check
```

## Safety

- Never commit secrets, tokens, credentials, tenant IDs, object IDs, private IPs, connection strings, or raw provider data.
- Provider adapters are static/mock/dry-run until explicitly approved for live execution.
- Platform config lives in environment variables — `.env.example` is the reference, `.env` is gitignored.
- Database credentials are local dev only — production uses Vault.

## Conventions

- Rust 2024 edition. Workspace-level dependencies in root `Cargo.toml`.
- Portal follows Leptos SSR patterns with same-origin server functions.
- API endpoints use Axum state and extractors. No global mutable state.
- Validators are self-contained modules in `scripts/validator-rs/src/`.
- Database migrations live in `migrations/` and run via sqlx on startup.
- Commit messages: conventional commits (`feat:`, `fix:`, `refactor:`, `docs:`, `chore:`).
