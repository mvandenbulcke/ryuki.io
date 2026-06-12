# Build from the repository root:
#   docker build -f portal/portal-ui/Dockerfile .
#
# The root Cargo.toml declares five workspace members plus a root package with
# [[test]] targets under tests/, so cargo metadata needs the full workspace
# manifest graph (sources/, portal/, scripts/validator-rs/, tests/) to resolve.
# cargo-leptos drives the build here, so this stage favours a plain
# full-workspace COPY (ordered least- to most-frequently changing) over
# cargo-chef layer tricks.

FROM rust:1.96-bookworm AS build

WORKDIR /app

# Toolchain layer: cached independently of the workspace sources
RUN rustup target add wasm32-unknown-unknown \
    && cargo install cargo-leptos --locked

# Full workspace COPY set so `cargo metadata` resolves every member
COPY Cargo.toml Cargo.lock ./
COPY scripts/validator-rs/ scripts/validator-rs/
COPY tests/ tests/
COPY sources/ sources/
COPY portal/ portal/

RUN cargo leptos build --release -p ryuki-portal-ui

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV LEPTOS_SITE_ROOT=/app/site \
    LEPTOS_SITE_ADDR=0.0.0.0:8080 \
    RYUKI_PORTAL_EXECUTION_MODE=static-dry-run

COPY --from=build /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui
COPY --from=build /app/target/site /app/site

EXPOSE 8080

CMD ["/app/ryuki-portal-ui"]
