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

RUN cargo install cargo-chef --version 0.1.77 --locked

WORKDIR /app

FROM chef AS planner

# Full workspace COPY set so `cargo metadata` resolves every member
COPY Cargo.toml Cargo.lock ./
COPY sources/ sources/
COPY portal/ portal/
COPY scripts/validator-rs/ scripts/validator-rs/
COPY tests/ tests/
COPY migrations/ migrations/
COPY catalog/ catalog/

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build

# Dependency layer: cached until the workspace dependency set changes
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json --package ryuki-api

# Source layer: same full workspace COPY set as the planner stage
COPY Cargo.toml Cargo.lock ./
COPY sources/ sources/
COPY portal/ portal/
COPY scripts/validator-rs/ scripts/validator-rs/
COPY tests/ tests/
COPY migrations/ migrations/
COPY catalog/ catalog/

RUN cargo build --release -p ryuki-api

# debian:bookworm-slim, pinned to the reviewed multi-platform index.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 ryuki \
    && useradd --system --uid 10001 --gid ryuki --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin ryuki \
    && install -d -o 10001 -g 10001 -m 0700 /app/keys

WORKDIR /app

ENV RYUKI_API_EXECUTION_MODE=static-dry-run

COPY --from=build --chown=10001:10001 /app/target/release/ryuki-api /app/ryuki-api

# Match the Kubernetes runtime identity. The writable signing-key directory is
# prepared above; the rest of the runtime image remains root-owned and read-only
# to the service process.
USER 10001:10001

EXPOSE 8080

CMD ["/app/ryuki-api"]
