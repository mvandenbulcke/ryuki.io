# CI/CD Pipeline

GitHub Actions pipeline for the Ryuki Infrastructure Platform.

## Pipeline Stages

1. **Build & Test** (parallel): Rust build/test, secret scan, lint/clippy.
2. **Validate**: Rust validator run-all, secret scan.
3. **Build Images**: Docker images for `ryuki-api` and `portal-ui`.
4. **Push Images** (main branch only): Tags and pushes images to the container registry.

## Running Locally

Use the root `Makefile`:

```bash
make build       # cargo build --workspace
make test        # cargo test --workspace
make lint        # cargo fmt --check + clippy
make validate    # cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all + secret scan
make compose-up  # Docker Compose local dev environment
```

Individual stages:

```bash
# Secret scan
./scripts/no-secret-scan.sh

# Rust lint
cargo fmt --check --all
cargo clippy --workspace -- -D warnings

# Validator
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all

# Container build (dry-run)
docker compose -f deploy/compose/compose.yaml up --build
```

## Environment Variables

Configure these as GitHub Actions secrets or repository variables:

| Variable | Description |
|---|---|
| `CONTAINER_REGISTRY` | Container registry URL |
| `CONTAINER_REGISTRY_USERNAME` | Registry username |
| `CONTAINER_REGISTRY_PASSWORD` | Registry password or access token |

Never commit these values to the repository.

## Prerequisites

- Rust toolchain
- ripgrep (`rg`) for secret scanning
- Docker for image builds
- A workspace-level `Cargo.toml` with `[workspace]` and `[workspace.dependencies]` sections
