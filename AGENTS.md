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

This is mandatory for coding agents and CI-style local checks. It places both
Cargo target-dir and build-dir in one bounded external run directory, disables
incremental compilation and full debug symbols, and supervises every gate as a
process group. It stops surviving descendants on failure or interruption,
removes normal run state on exit, and reclaims stale interrupted state on the
next run. Do not run parallel Cargo build/test/clippy commands in the same
checkout or leave ad-hoc Cargo artifact trees behind.

Coding agents must never invoke `cargo build`, `cargo check`, `cargo test`,
`cargo clippy`, `cargo run`, or `cargo leptos` directly. Use the focused bounded
form for an individual build gate:

```bash
./scripts/verify-workspace-clean.sh -- cargo check -p ryuki-api
./scripts/verify-workspace-clean.sh -- cargo test -p ryuki-api <test-filter>
./scripts/verify-workspace-clean.sh -- cargo clippy -p ryuki-api -- -D warnings
```

The checked-in Cargo rustc wrapper is a final hard stop for repository-configured
direct, Make, IDE, and cargo-leptos paths. It supervises each compiler, linker,
and descendant process group, refuses new compiler work, and stops active work
when the effective target exceeds 24 GiB or free space falls below 30 GiB.

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

Persistent human-development target and build artifacts live in the sibling
`../.ryuki-target-ryuki.io` cache, never under the checkout. Use
`make cache-status` to inspect it and `make clean` when it is no longer useful.
Prefer `make run-api` and `make run-portal`; the latter also keeps the Leptos
site output external.

Tracked regular-file blockers at the repository-root `target` and `debug` paths,
plus `target` blockers in every workspace member, make Cargo fail closed when a
launcher does not discover repository configuration and falls back to
checkout-local artifact paths. Do not delete or replace these blockers. Docker
builds exclude them and retain their normal in-container `/app/target`.

The 24 GiB maximum target size and 30 GiB minimum free-space reserve are hard
repository build bounds. `RYUKI_VERIFY_*` and `RYUKI_CARGO_*` settings may only tighten
them by choosing a smaller target ceiling or a larger free-space reserve; they
must never weaken either bound.

The workspace development and test profiles both explicitly disable incremental
compilation and retain line-table-only debug information. (`cargo test` uses its
own profile; it does not inherit these overrides from `[profile.dev]`.) This
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
