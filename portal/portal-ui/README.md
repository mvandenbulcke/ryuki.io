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

RYUKI_PORTAL_EXECUTION_MODE=live-provider \
cargo leptos serve --manifest-path portal/portal-ui/Cargo.toml
```

The portal listens on loopback port `8080` and forwards same-origin server
functions to the API on port `8081` by default. Override `RYUKI_API_URL` when
the upstream is elsewhere. Run the local API with
`RYUKI_SERVER__BIND_ADDRESS=127.0.0.1:8081`. Omitting `live-provider` keeps the
portal in its labeled static dry-run mode.

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
