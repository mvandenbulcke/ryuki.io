FROM rust:1.88-bookworm AS build

WORKDIR /app

RUN rustup target add wasm32-unknown-unknown \
    && cargo install cargo-leptos --locked

# Copy workspace manifests and lockfile for dependency resolution
COPY Cargo.toml Cargo.lock ./
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
