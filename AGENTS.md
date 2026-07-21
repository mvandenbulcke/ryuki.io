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

For a complete one-shot verification wave, use the bounded disposable target:

```bash
make verify-clean
```

This is mandatory for coding agents and CI-style local checks. It disables
incremental compilation and full debug symbols for the temporary build, checks
free space and target size between gates, and removes the target on success,
failure, or interruption. Do not run parallel Cargo build/test/clippy commands
in the same checkout. Never leave ad-hoc `CARGO_TARGET_DIR` trees behind.

For iterative human development, the individual commands remain available:

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --check --all
cargo clippy --workspace -- -D warnings
./scripts/dependency-audit.sh
./scripts/no-secret-scan.sh
git diff --check
```

Use `make cache-status` to inspect the persistent development cache and
`make clean` when it is no longer useful. The one-shot defaults reserve 30 GiB
of free disk and cap the disposable target at 64 GiB; override them only with
`RYUKI_VERIFY_MIN_FREE_GIB` and `RYUKI_VERIFY_MAX_TARGET_GIB` after an explicit
capacity review.

The workspace development profile, which the test profile inherits, disables
incremental compilation and retains line-table-only debug information. This
trades slower iterative rebuilds for substantially lower `target/debug` growth.
For a deliberate interactive debugging session, opt in temporarily with
`CARGO_PROFILE_DEV_DEBUG=2`, `CARGO_PROFILE_TEST_DEBUG=2`, and
`CARGO_INCREMENTAL=1` as appropriate, then run `make clean` when it ends.

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
- AI agent co-authoring is permitted. `Co-Authored-By` trailers are allowed on commits.
