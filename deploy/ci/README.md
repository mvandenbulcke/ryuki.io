# CI/CD Pipeline

CI for the Ryuki Infrastructure Platform runs on GitHub Actions. The workflow
definitions live in `.github/workflows/`, not in this directory:

- `.github/workflows/ci.yml` — the `CI` workflow gating `main`. Runs on every
  push and pull request targeting `main`.
- `.github/workflows/static.yml` — the GitHub Pages deploy of `./docs`
  (the live ryuki.io site). It triggers via `workflow_run` only after the `CI`
  workflow completes successfully on `main` (or manually via
  `workflow_dispatch`). Direct pushes to `main` still land in git as before;
  the site only redeploys on a green CI run.

The Azure DevOps pipeline definition that previously lived here
(`deploy/ci/azure-pipelines.yml`) was never registered with any Azure DevOps
organization and has been deleted. Its stages were ported 1:1 to `ci.yml`.
`tests/ci_integration_test.rs` asserts the structure of both workflows.

## CI jobs

| Job | Runs on | What it does |
|---|---|---|
| `build-test` | push + PR | `cargo build --workspace` and `cargo test --workspace` |
| `lint` | push + PR | `cargo fmt --check --all` and `cargo clippy --workspace -- -D warnings` |
| `security` | push + PR | `./scripts/no-secret-scan.sh` (ripgrep-based secret scan) |
| `validate` | push + PR | validator `run-all` (currently observational, see below) |
| `images` | push to `main` only | `docker build` of both application Dockerfiles from the repo root; no push |

Rust jobs install the toolchain via `dtolnay/rust-toolchain@stable` (the repo's
`rust-toolchain.toml` pins the stable channel) and cache build artifacts with
`Swatinem/rust-cache`.

The `validate` job runs
`cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all --root .`
but is marked `continue-on-error` for now: most validator slices still assert
the retired C# repository layout and fail against the current tree (run-all
reports the per-slice results as JSON). It becomes a hard gate once the
"Catalog, contract & documentation integrity" theme
(`docs/design/missing-features.md`) makes the slices green.

CI builds images for verification only and never pushes them, so no
container-registry credentials are configured. Release publication is a
separate, later concern (see the release-engineering design in
`docs/design/missing-features.md`). Never commit registry credentials or any
other secrets to the repository.

## Running the same checks locally

Use the root `Makefile`:

```bash
make build       # cargo build --workspace
make test        # cargo test --workspace
make lint        # cargo fmt --check + clippy
make validate    # validator run-all + secret scan
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
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all --root .

# Image builds (root context, same as CI)
docker build -t ryuki/platform-api:ci -f sources/ryuki-api/Dockerfile .
docker build -t ryuki/portal-ui:ci -f portal/portal-ui/Dockerfile .

# Pipeline structure tests
cargo test --test ci_integration_test
```

## Prerequisites

- Rust toolchain (rustup; `rust-toolchain.toml` selects the channel and
  components)
- ripgrep (`rg`) for secret scanning
- Docker for image builds
- A workspace-level `Cargo.toml` with `[workspace]` and
  `[workspace.dependencies]` sections
