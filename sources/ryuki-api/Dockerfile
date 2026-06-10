FROM rust:1.88-bookworm AS build

WORKDIR /app

# Copy workspace manifests and lockfile for dependency resolution
COPY Cargo.toml Cargo.lock ./
COPY sources/ sources/

RUN cargo build --release -p ryuki-api

FROM debian:bookworm-slim AS runtime

WORKDIR /app

ENV RYUKI_API_EXECUTION_MODE=static-dry-run

COPY --from=build /app/target/release/ryuki-api /app/ryuki-api

EXPOSE 8080

CMD ["/app/ryuki-api"]
