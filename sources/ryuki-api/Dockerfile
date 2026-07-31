# Build from the repository root:
#   docker build -f sources/ryuki-api/Dockerfile .
#
# The root Cargo.toml declares five workspace members plus a root package with
# [[test]] targets under tests/, so cargo metadata needs the full workspace
# manifest graph (sources/, portal/, scripts/validator-rs/, tests/) to resolve.
# migrations/ is load-bearing too: sqlx::migrate!("../../migrations") embeds it
# at compile time (sources/ryuki-api/src/database.rs).

# rust:1.96-bookworm, pinned to the reviewed multi-platform index.
FROM rust:1.96-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS chef

RUN ["/usr/local/cargo/bin/cargo", "install", "cargo-chef", "--version", "0.1.77", "--locked", "--root", "/opt/ryuki-tools/cargo-chef-0.1.77"]
RUN ["/usr/sbin/groupadd", "--system", "--gid", "10001", "ryuki-build"]
RUN ["/usr/sbin/useradd", "--system", "--uid", "10001", "--gid", "ryuki-build", "--create-home", "--home-dir", "/home/ryuki-build", "--shell", "/usr/sbin/nologin", "ryuki-build"]
RUN ["/usr/bin/install", "-d", "-o", "10001", "-g", "10001", "-m", "0755", "/app", "/var/cache/ryuki-cargo"]
RUN ["/usr/bin/chown", "-R", "0:0", "/opt/ryuki-tools/cargo-chef-0.1.77", "/usr/local/cargo", "/usr/local/rustup"]
RUN ["/usr/bin/chmod", "-R", "a-w", "/opt/ryuki-tools/cargo-chef-0.1.77", "/usr/local/cargo", "/usr/local/rustup"]

ENV HOME=/home/ryuki-build CARGO_HOME=/var/cache/ryuki-cargo RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:/var/cache/ryuki-cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /app
USER 10001:10001

FROM chef AS planner

# Full workspace COPY set so `cargo metadata` resolves every member
COPY --link --chown=10001:10001 Cargo.toml Cargo.lock ./
COPY --link --chown=10001:10001 sources/ sources/
COPY --link --chown=10001:10001 portal/ portal/
COPY --link --chown=10001:10001 scripts/validator-rs/ scripts/validator-rs/
COPY --link --chown=10001:10001 tests/ tests/
COPY --link --chown=10001:10001 migrations/ migrations/
COPY --link --chown=10001:10001 catalog/ catalog/

RUN ["/opt/ryuki-tools/cargo-chef-0.1.77/bin/cargo-chef", "chef", "prepare", "--recipe-path", "recipe.json"]

FROM chef AS build

# Dependency layer: cached until the workspace dependency set changes
COPY --link --chown=10001:10001 --from=planner /app/recipe.json recipe.json
RUN ["/opt/ryuki-tools/cargo-chef-0.1.77/bin/cargo-chef", "chef", "cook", "--locked", "--release", "--recipe-path", "recipe.json", "--package", "ryuki-api"]

# Source layer: same full workspace COPY set as the planner stage
COPY --link --chown=10001:10001 Cargo.toml Cargo.lock ./
COPY --link --chown=10001:10001 sources/ sources/
COPY --link --chown=10001:10001 portal/ portal/
COPY --link --chown=10001:10001 scripts/validator-rs/ scripts/validator-rs/
COPY --link --chown=10001:10001 tests/ tests/
COPY --link --chown=10001:10001 migrations/ migrations/
COPY --link --chown=10001:10001 catalog/ catalog/

# Release builds pass the already validated tag commit. Keep the argument
# optional so ordinary local builds do not define option_env!("RYUKI_SOURCE_REVISION").
ARG RYUKI_SOURCE_REVISION
RUN set -eu; \
    if [ -n "${RYUKI_SOURCE_REVISION:-}" ]; then \
        case "${RYUKI_SOURCE_REVISION}" in \
            *[!0-9a-f]*) \
                echo "RYUKI_SOURCE_REVISION must be exactly 40 or 64 lowercase hexadecimal characters" >&2; \
                exit 1; \
                ;; \
        esac; \
        revision_length="${#RYUKI_SOURCE_REVISION}"; \
        if [ "${revision_length}" -ne 40 ] && [ "${revision_length}" -ne 64 ]; then \
            echo "RYUKI_SOURCE_REVISION must be exactly 40 or 64 lowercase hexadecimal characters" >&2; \
            exit 1; \
        fi; \
        export RYUKI_SOURCE_REVISION; \
    else \
        unset RYUKI_SOURCE_REVISION; \
    fi; \
    /usr/local/cargo/bin/cargo build --locked --release -p ryuki-api

# debian:bookworm-slim, pinned to the reviewed multi-platform index.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 ryuki \
    && useradd --system --uid 10001 --gid ryuki --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin ryuki \
    && install -d -o 10001 -g 10001 -m 0700 /app/keys \
    && install -d -o 0 -g 0 -m 0555 \
        /app/security-contract/catalog/security-contracts \
        /app/security-contract/docs/architecture \
        /app/security-contract/sources/ryuki-api/src

WORKDIR /app

ENV RYUKI_API_EXECUTION_MODE=static-dry-run

COPY --from=build --chown=0:0 --chmod=0555 /app/target/release/ryuki-api /app/ryuki-api
COPY --chown=0:0 catalog/security-contracts/ /app/security-contract/catalog/security-contracts/
COPY --chown=0:0 --chmod=0444 docs/architecture/platform-security-boundary.md /app/security-contract/docs/architecture/platform-security-boundary.md
COPY --chown=0:0 --chmod=0444 sources/ryuki-api/src/main.rs sources/ryuki-api/src/contracts.rs sources/ryuki-api/src/scheduler.rs sources/ryuki-api/src/agents.rs /app/security-contract/sources/ryuki-api/src/

# The admission loader reads this root but the runtime identity cannot mutate
# its content-addressed contract or normative specification dependency.
RUN chmod -R a-w /app/security-contract \
    && find /app/security-contract -type d -exec chmod 0555 {} + \
    && find /app/security-contract -type f -exec chmod 0444 {} +

# Match the Kubernetes runtime identity. The writable signing-key directory is
# prepared above; the rest of the runtime image remains root-owned and read-only
# to the service process.
USER 10001:10001

EXPOSE 8080

CMD ["/app/ryuki-api"]
