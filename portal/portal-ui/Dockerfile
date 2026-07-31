# Build from the repository root:
#   docker build -f portal/portal-ui/Dockerfile .
#
# The root Cargo.toml declares five workspace members plus a root package with
# [[test]] targets under tests/, so cargo metadata needs the full workspace
# manifest graph (sources/, portal/, scripts/validator-rs/, tests/) to resolve.
# cargo-leptos drives the build here, so this stage favours a plain
# full-workspace COPY (ordered least- to most-frequently changing) over
# cargo-chef layer tricks.

# rust:1.96-bookworm, pinned to the reviewed multi-platform index.
FROM rust:1.96-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS build

# Toolchain layer: cached independently of the workspace sources
RUN ["/usr/local/cargo/bin/rustup", "target", "add", "wasm32-unknown-unknown"]
RUN ["/usr/local/cargo/bin/cargo", "install", "cargo-leptos", "--version", "0.3.7", "--locked", "--root", "/opt/ryuki-tools/cargo-leptos-0.3.7"]
RUN ["/usr/sbin/groupadd", "--system", "--gid", "10001", "ryuki-build"]
RUN ["/usr/sbin/useradd", "--system", "--uid", "10001", "--gid", "ryuki-build", "--create-home", "--home-dir", "/home/ryuki-build", "--shell", "/usr/sbin/nologin", "ryuki-build"]
RUN ["/usr/bin/install", "-d", "-o", "10001", "-g", "10001", "-m", "0755", "/app", "/var/cache/ryuki-cargo"]
RUN ["/usr/bin/chown", "-R", "0:0", "/opt/ryuki-tools/cargo-leptos-0.3.7", "/usr/local/cargo", "/usr/local/rustup"]
RUN ["/usr/bin/chmod", "-R", "a-w", "/opt/ryuki-tools/cargo-leptos-0.3.7", "/usr/local/cargo", "/usr/local/rustup"]

ENV HOME=/home/ryuki-build CARGO_HOME=/var/cache/ryuki-cargo RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:/var/cache/ryuki-cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /app
USER 10001:10001

# Full workspace COPY set so `cargo metadata` resolves every member
COPY --link --chown=10001:10001 Cargo.toml Cargo.lock ./
COPY --link --chown=10001:10001 scripts/validator-rs/ scripts/validator-rs/
COPY --link --chown=10001:10001 tests/ tests/
COPY --link --chown=10001:10001 sources/ sources/
COPY --link --chown=10001:10001 portal/ portal/

RUN ["/opt/ryuki-tools/cargo-leptos-0.3.7/bin/cargo-leptos", "build", "--release", "-p", "ryuki-portal-ui"]

# debian:bookworm-slim, pinned to the reviewed multi-platform index.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl socat \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 ryuki \
    && useradd --system --uid 10001 --gid ryuki --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin ryuki

WORKDIR /app

# The standalone image is the documented loopback development image. Publish
# its container port on 127.0.0.1; deployment manifests override the public
# origin for their externally visible HTTPS address.
ENV LEPTOS_SITE_ROOT=/app/site \
    LEPTOS_SITE_ADDR=0.0.0.0:8080 \
    RYUKI_PORTAL_PUBLIC_ORIGIN=http://127.0.0.1:8080 \
    RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK=true \
    RYUKI_PORTAL_EXECUTION_MODE=static-dry-run

COPY --from=build --chown=10001:10001 /app/target/release/ryuki-portal-ui /app/ryuki-portal-ui
COPY --from=build --chown=10001:10001 /app/target/site /app/site

# Match the Kubernetes runtime identity and keep a compromised SSR process away
# from root-only container state.
USER 10001:10001

EXPOSE 8080

CMD ["/app/ryuki-portal-ui"]
