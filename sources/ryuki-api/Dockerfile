# Build from the repository root:
#   docker build -f sources/ryuki-api/Dockerfile .
#
# The root Cargo.toml declares five workspace members plus a root package with
# [[test]] targets under tests/, so cargo metadata needs the full workspace
# manifest graph (sources/, portal/, scripts/validator-rs/, tests/) to resolve.
# migrations/ is load-bearing too: sqlx::migrate!("../../migrations") embeds it
# at compile time (sources/ryuki-api/src/database.rs).

FROM rust:1.96-bookworm AS chef

RUN cargo install cargo-chef --locked

WORKDIR /app

FROM chef AS planner

# Full workspace COPY set so `cargo metadata` resolves every member
COPY Cargo.toml Cargo.lock ./
COPY sources/ sources/
COPY portal/ portal/
COPY scripts/validator-rs/ scripts/validator-rs/
COPY tests/ tests/
COPY migrations/ migrations/

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

RUN cargo build --release -p ryuki-api

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV RYUKI_API_EXECUTION_MODE=static-dry-run

COPY --from=build /app/target/release/ryuki-api /app/ryuki-api

EXPOSE 8080

CMD ["/app/ryuki-api"]
