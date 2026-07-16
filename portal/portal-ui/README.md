# Portal UI

Full-stack Rust/Leptos operational portal with SSR and hydration.

## Stack

- **Framework**: Leptos with Axum SSR backend
- **Styling**: CSS custom properties (configurable accent colors)
- **API**: Same-origin server functions via `/portal/api/*`

## Development

```bash
rustup target add wasm32-unknown-unknown
cargo install cargo-leptos --locked

LEPTOS_SITE_ADDR=127.0.0.1:8080 \
RYUKI_PORTAL_PUBLIC_ORIGIN=http://127.0.0.1:8080 \
RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK=true \
RYUKI_PORTAL_EXECUTION_MODE=live-provider \
cargo leptos serve --manifest-path portal/portal-ui/Cargo.toml
```

The explicit `LEPTOS_SITE_ADDR` confines this direct development process to
loopback port `8080`; cargo-leptos metadata and the container image otherwise
use a container-compatible `0.0.0.0:8080` listener. The portal forwards server
functions to the API on port `8081` by default. Override `RYUKI_API_URL` when
the upstream is elsewhere. Run the local API with
`RYUKI_SERVER__BIND_ADDRESS=127.0.0.1:8081`. Omitting `live-provider` keeps the
portal in its labeled static dry-run mode.

`RYUKI_PORTAL_PUBLIC_ORIGIN` is required and is the exact browser origin
accepted for unsafe server-function requests. Both it and `RYUKI_API_URL`
must use HTTPS. Plain HTTP is accepted only for `localhost` or a loopback IP
when `RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK=true` is set explicitly for local
development or tests. Endpoint URLs cannot contain credentials, a path,
query string, or fragment.

Session and login-binding cookies derive their `Secure` attribute from that
validated public origin. HTTPS always requires `Secure`; the only non-Secure
case is explicitly enabled loopback HTTP. `RYUKI_PORTAL_COOKIE_SECURE` is an
optional startup assertion and cannot override the derived policy. HTTPS uses
the host-only `__Host-ryuki_session` name; explicitly enabled loopback HTTP
retains the unprefixed `ryuki_session` name for browser compatibility.

The `/portal/api/*` server-function boundary also enforces a streaming request
body limit, a non-queuing concurrency budget, and a wall-clock request
deadline. Defaults are 10 MiB, 128 concurrent requests, and 30 seconds. They
can be tuned with `RYUKI_PORTAL_SERVER_FN_MAX_BODY_BYTES`,
`RYUKI_PORTAL_SERVER_FN_MAX_CONCURRENT_REQUESTS`, and
`RYUKI_PORTAL_SERVER_FN_REQUEST_TIMEOUT_SECS`; invalid, zero, or unsafe values
fail startup instead of disabling the boundary.

## Build

```bash
cargo leptos build --release
```

## Architecture

- `src/app.rs` — root component, auth gate, shell/login routing
- `src/shell.rs` — navigation, session display, role filtering
- `src/server_boundary.rs` — same-origin API allowlist and server functions
- `src/views/` — page components (dashboard, login, requests, admin, workspaces)
- `src/models.rs` — typed view models with safe fallbacks
- `src/api.rs` — API path constants
- `styles.css` — design tokens and component styles
- `Dockerfile` — full-stack Leptos build and Rust server runtime image

The portal never calls providers or external APIs directly. All data flows through same-origin server functions to the platform API.
