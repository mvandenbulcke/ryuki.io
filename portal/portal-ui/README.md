# Portal UI

Full-stack Rust/Leptos operational portal with SSR and hydration.

## Stack

- **Framework**: Leptos with Axum SSR backend
- **Styling**: CSS custom properties (configurable accent colors)
- **API**: Same-origin server functions via `/portal/api/*`

## Development

```bash
cargo leptos serve
```

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
