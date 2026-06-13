use crate::app::SessionResource;
use crate::models::{auth_session_fallback, AuthSession};
use crate::server_boundary::{perform_logout, PortalRouteStateSnapshot};
use crate::workspace_catalog::{nav_item_is_active, role_satisfies, PRIMARY_NAV_ITEMS};
use leptos::prelude::*;
use leptos_router::components::Outlet;
use leptos_router::hooks::use_location;

/// The ryū logo mark shared with the ryuki.io landing page. Colors come from
/// the shared `--logo-red`/`--logo-gold` tokens, which do not vary by theme;
/// they ride on `style` because SVG presentation attributes do not reliably
/// resolve `var()` in every browser.
#[component]
pub fn BrandMark() -> impl IntoView {
    view! {
        <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
                <path
                    d="M 35.5 15.3 A 20 20 0 1 0 50.0 26.2"
                    fill="none"
                    style="stroke: var(--logo-red)"
                    stroke-width="7.5"
                    stroke-linecap="round"
                />
                <path
                    d="M 15.5 18.5 L 6.8 19.7 M 8.6 35.0 L 3.3 42.0 M 15.5 51.5 L 16.7 60.2"
                    fill="none"
                    style="stroke: var(--logo-red)"
                    stroke-width="2.7"
                    stroke-linecap="round"
                />
                <path
                    d="M 35.5 15.3 C 31.5 10.8 27.0 9.3 22.5 10.3"
                    fill="none"
                    style="stroke: var(--logo-red)"
                    stroke-width="3"
                    stroke-linecap="round"
                />
                <path
                    d="M 46.5 24.5 L 43 18.5 L 44.5 14 L 40 9 L 46 10.5 L 50.5 4.5 L 51.5 11.5 L 57 13 L 53.5 17.5 L 53.8 22.5 Z"
                    style="fill: var(--logo-red)"
                />
                <circle cx="48.4" cy="13.2" r="1.6" style="fill: var(--logo-gold)" />
                <circle cx="32" cy="35" r="5.8" style="fill: var(--logo-gold)" />
            </svg>
        </span>
    }
}

#[component]
pub fn Shell(route_snapshot: PortalRouteStateSnapshot) -> impl IntoView {
    // The route snapshot arrives from the `load_portal_route_state` server
    // function via app.rs, so the context strip and data-* attributes report
    // the real upstream state (live / degraded-static / static-dry-run)
    // instead of always claiming the static skeleton.
    let degraded = route_snapshot.upstream_state == "degraded-static";
    // The real session arrives through context from the auth gate in app.rs;
    // the labeled synthetic fallback only covers out-of-gate renders.
    let auth_session = use_context::<AuthSession>().unwrap_or_else(auth_session_fallback);
    // Routed views (the dashboard hero, for one) read the snapshot from
    // context, so the layout shares it before destructuring its own labels.
    provide_context(route_snapshot.clone());
    // The current location drives the nav active state; the snapshot's
    // active_route reports the matched route the server rendered.
    let current_path = use_location().pathname;
    let active_route = route_snapshot.active_route.clone();
    let main_id = route_snapshot.active_workspace.clone();
    let site_scope_label = route_snapshot.site_scope_label.clone();
    let environment_scope_label = route_snapshot.environment_scope_label.clone();
    // The role pill carries real role information — the single role name or
    // the granted-role count — never the username dressed up as a role.
    let role_scope_label = match auth_session.roles.as_slice() {
        [] => "Role: none".to_string(),
        [role] => format!("Role: {role}"),
        roles => format!("Roles: {}", roles.len()),
    };
    let inventory_freshness_label = route_snapshot.inventory_freshness_label.clone();
    let backup_freshness_label = route_snapshot.backup_freshness_label.clone();
    let monitoring_freshness_label = route_snapshot.monitoring_freshness_label.clone();
    let execution_authority_label = route_snapshot.execution_authority_label.clone();
    let api_boundary = route_snapshot.api_boundary.clone();
    let execution_mode = route_snapshot.execution_mode.clone();
    let upstream_state = route_snapshot.upstream_state.clone();
    let route_state_path = route_snapshot.route_state_path.clone();
    let run_state_path = route_snapshot.run_state_path.clone();
    let route_state = route_snapshot.route_state.clone();
    let run_state = route_snapshot.run_state.clone();
    let route_safe_summary = route_snapshot.safe_summary.clone();
    let route_http_request_allowed = route_snapshot.http_request_allowed.to_string();
    let route_provider_calls_allowed = route_snapshot.provider_calls_allowed.to_string();
    let route_live_execution_allowed = route_snapshot.live_execution_allowed.to_string();
    let route_raw_state_allowed = route_snapshot.raw_route_state_allowed.to_string();
    let user_scope_label = format!("User: {}", auth_session.display_name);
    let user_roles = if auth_session.roles.is_empty() {
        "none".to_string()
    } else {
        auth_session.roles.join(", ")
    };

    let session_resource = use_context::<SessionResource>();
    let logout_action = Action::new(move |_: &()| async move {
        let _ = perform_logout().await;
        if let Some(resource) = session_resource {
            resource.refetch();
        }
    });
    let logout_pending = logout_action.pending();
    let on_signout_click = move |_| {
        logout_action.dispatch(());
    };

    let (theme_icon, set_theme_icon) = signal(String::from("\u{263C}\u{FE0F}"));

    #[cfg(not(feature = "hydrate"))]
    let _ = &set_theme_icon;

    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        // let-else guards: a missing window/document/document_element during
        // hydration must not panic the WASM runtime — just skip the icon sync.
        let Some(window) = web_sys::window() else {
            return;
        };
        let Some(doc) = window.document() else {
            return;
        };
        let Some(html) = doc.document_element() else {
            return;
        };
        let explicit = html.get_attribute("data-theme");
        let is_dark = match explicit.as_deref() {
            Some("dark") => true,
            Some("light") => false,
            _ => window
                .match_media("(prefers-color-scheme: dark)")
                .ok()
                .flatten()
                .map(|m| m.matches())
                .unwrap_or(false),
        };
        set_theme_icon.set(if is_dark {
            "\u{2600}\u{FE0F}".to_string()
        } else {
            "\u{1F319}".to_string()
        });
    });

    let on_theme_click = {
        move |_| {
            #[cfg(feature = "hydrate")]
            {
                // let-else guards: if window/document/document_element are
                // absent (e.g. SSR dry-run), bail early — nothing to toggle.
                let Some(window) = web_sys::window() else {
                    return;
                };
                let Some(doc) = window.document() else {
                    return;
                };
                let Some(html) = doc.document_element() else {
                    return;
                };
                // Storage may be denied (Safari Private Browsing, blocked
                // storage policy).  Degrade gracefully: the in-DOM toggle
                // ALWAYS runs; persistence is best-effort only.
                let storage = window.local_storage().ok().flatten();

                let current = html.get_attribute("data-theme");
                match current.as_deref() {
                    None | Some("") => {
                        let _ = html.set_attribute("data-theme", "dark");
                        if let Some(s) = &storage {
                            let _ = s.set_item("ryuki-theme", "dark");
                        }
                    }
                    Some("dark") => {
                        let _ = html.set_attribute("data-theme", "light");
                        if let Some(s) = &storage {
                            let _ = s.set_item("ryuki-theme", "light");
                        }
                    }
                    Some("light") => {
                        let _ = html.remove_attribute("data-theme");
                        if let Some(s) = &storage {
                            let _ = s.remove_item("ryuki-theme");
                        }
                    }
                    _ => {}
                }

                let explicit = html.get_attribute("data-theme");
                let is_dark = match explicit.as_deref() {
                    Some("dark") => true,
                    Some("light") => false,
                    _ => window
                        .match_media("(prefers-color-scheme: dark)")
                        .ok()
                        .flatten()
                        .map(|m| m.matches())
                        .unwrap_or(false),
                };
                set_theme_icon.set(if is_dark {
                    "\u{2600}\u{FE0F}".to_string()
                } else {
                    "\u{1F319}".to_string()
                });
            }
        }
    };

    view! {
        <div class="shell">
            <header class="topbar" aria-label="Product shell">
                <a class="brand" href="/" aria-label="Ryuki Infrastructure Platform home">
                    <BrandMark/>
                    <span>
                        <span class="brand-kicker">"Ryuki"</span>
                        <strong>"Infrastructure Platform"</strong>
                    </span>
                </a>
                <form class="search" role="search">
                    <label class="sr-only" for="global-search">"Global search"</label>
                    <input
                        id="global-search"
                        type="search"
                        placeholder="Global search — coming soon"
                        title="Global search is not yet available"
                        aria-disabled="true"
                        disabled=true
                    />
                </form>
                <div class="toolbar">
                    <div class="scope" aria-label="Current scope">
                        <span class="pill">{site_scope_label.clone()}</span>
                        <span class="pill">{environment_scope_label.clone()}</span>
                        <span class="pill role">{role_scope_label.clone()}</span>
                    </div>
                    <div class="session-info" aria-label="Session info">
                        <span class="pill user">{user_scope_label}</span>
                        <span class="table-note">"Roles: " {user_roles}</span>
                        <button
                            class="signout-button"
                            on:click=on_signout_click
                            disabled=move || logout_pending.get()
                        >
                            "Sign out"
                        </button>
                    </div>
                    <button
                        class="theme-toggle"
                        aria-label="Toggle theme"
                        on:click=on_theme_click
                    >
                        {move || theme_icon.get()}
                    </button>
                </div>
            </header>

            <Show when=move || degraded>
                <div class="boundary-degraded" role="status">
                    <strong>"API unreachable"</strong>
                    <span>
                        " — the portal is showing a read-only static preview; sign-in and changes are unavailable until the platform API is reachable again."
                    </span>
                </div>
            </Show>

            <nav class="nav" aria-label="Primary navigation">
                {PRIMARY_NAV_ITEMS
                    .iter()
                    .filter(|item| role_satisfies(&auth_session, item.required_role))
                    .map(|item| {
                        let href = item.href;
                        let class = move || {
                            if nav_item_is_active(&current_path.get(), href) {
                                "active"
                            } else {
                                ""
                            }
                        };
                        let aria_current = move || {
                            nav_item_is_active(&current_path.get(), href).then_some("page")
                        };
                        view! {
                            <a class=class aria-current=aria_current href=href>{item.label}</a>
                        }
                    })
                    .collect_view()}
            </nav>

            <main
                class="workspace"
                id=main_id
                data-active-route=active_route
                data-api-boundary=api_boundary
                data-execution-mode=execution_mode
                data-upstream-state=upstream_state
                data-route-state-path=route_state_path
                data-run-state-path=run_state_path
                data-route-state=route_state
                data-run-state=run_state
                data-http-request-allowed=route_http_request_allowed
                data-provider-calls-allowed=route_provider_calls_allowed
                data-live-execution-allowed=route_live_execution_allowed
                data-raw-route-state-allowed=route_raw_state_allowed
            >
                <section class="context" aria-label="Operational context" data-safe-summary=route_safe_summary>
                    <div class="context-scope">
                        <span class="eyebrow">"Context"</span>
                        <strong>{site_scope_label} " / " {environment_scope_label}</strong>
                    </div>
                    <div class="freshness">
                        <span>{inventory_freshness_label}</span>
                        <span>{backup_freshness_label}</span>
                        <span class="warn">{monitoring_freshness_label}</span>
                        <span>{execution_authority_label}</span>
                    </div>
                </section>

                <Outlet/>
            </main>
        </div>
    }
}
