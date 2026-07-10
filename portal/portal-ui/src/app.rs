use crate::models::{degraded_auth_session, AuthSession};
use crate::server_boundary::{get_auth_session, load_portal_route_state, PortalRouteStateSnapshot};
use crate::shell::Shell;
use crate::views::login::LoginView;
use crate::views::workspaces::{
    ActivityWorkspaceView, AdminWorkspaceView, AgentsWorkspaceView, ApprovalsWorkspaceView,
    CatalogWorkspaceView, CmdbWorkspaceView, DashboardWorkspaceView, EvidenceWorkspaceView,
    IntegrationsWorkspaceView, InventoryWorkspaceView, OperationsWorkspaceView,
    RequestDetailWorkspaceView, RequestNewWorkspaceView, RequestsWorkspaceView,
};
use leptos::prelude::*;
use leptos_meta::{provide_meta_context, Link, MetaTags, Stylesheet, Title};
use leptos_router::components::{ParentRoute, Route, Router, Routes};
use leptos_router::hooks::use_location;
use leptos_router::path;

/// The session resource shared through context so the login form and the
/// shell sign-out control can refetch the auth gate after login/logout.
pub type SessionResource = Resource<Result<Option<AuthSession>, ServerFnError>>;

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <script>
                    "(function(){try{var t=localStorage.getItem('ryuki-theme');if(t==='dark'||t==='light'){document.documentElement.setAttribute('data-theme',t)}}catch(e){}})()"
                </script>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Stylesheet id="ryuki-portal-css" href="/pkg/ryuki-portal-ui.css"/>
        <Link rel="icon" href="/favicon.svg"/>
        <Title text="Ryuki Infrastructure Platform"/>
        <Router>
            <Routes fallback=RouteNotFound>
                // The auth gate lives in the layout route, outside the child
                // routes: unauthenticated visitors see the login view for
                // every portal path, and after login the originally
                // requested path renders because the URL never changed.
                <ParentRoute path=path!("") view=PortalGate>
                    <Route path=path!("") view=DashboardWorkspaceView/>
                    <Route path=path!("catalog") view=CatalogWorkspaceView/>
                    <Route path=path!("requests") view=RequestsWorkspaceView/>
                    <Route path=path!("requests/new") view=RequestNewWorkspaceView/>
                    <Route path=path!("requests/:id") view=RequestDetailWorkspaceView/>
                    <Route path=path!("approvals") view=ApprovalsWorkspaceView/>
                    <Route path=path!("activity") view=ActivityWorkspaceView/>
                    <Route path=path!("inventory") view=InventoryWorkspaceView/>
                    <Route path=path!("cmdb") view=CmdbWorkspaceView/>
                    <Route path=path!("evidence") view=EvidenceWorkspaceView/>
                    <Route path=path!("operations") view=OperationsWorkspaceView/>
                    <Route path=path!("admin") view=AdminWorkspaceView/>
                    <Route path=path!("integrations") view=IntegrationsWorkspaceView/>
                    <Route path=path!("agents") view=AgentsWorkspaceView/>
                </ParentRoute>
            </Routes>
        </Router>
    }
}

/// The session-gated layout route. Every workspace route is a child of this
/// component, so the gate decides between login view and routed shell
/// exactly once, and client-side navigation between workspaces never
/// re-runs the session check.
#[component]
fn PortalGate() -> impl IntoView {
    let session_resource: SessionResource = Resource::new(|| (), |_| get_auth_session());
    provide_context(session_resource);

    // The route-state probe reports whether the data on screen is live,
    // degraded, or the static demo; the shell renders its context strip and
    // data-* attributes from this snapshot instead of a static skeleton.
    // The snapshot reports the originally requested path as the matched
    // route, so deep links are visible in the route-state evidence.
    let requested_path = use_location().pathname;
    let route_state_resource = Resource::new(
        || (),
        move |_| load_portal_route_state(requested_path.get_untracked()),
    );

    view! {
        <Suspense fallback=|| {
            view! {
                <div class="auth-gate-loading" aria-busy="true">
                    <p>"Checking session..."</p>
                </div>
            }
        }>
            {move || {
                Suspend::new(async move {
                    let route_snapshot = match route_state_resource.await {
                        Ok(snapshot) => snapshot,
                        // The route-state server function itself failing is
                        // indistinguishable from an unreachable upstream.
                        Err(_) => degraded_route_snapshot(&requested_path.get_untracked()),
                    };
                    match session_resource.await {
                        Ok(Some(session)) => {
                            view! { <AuthenticatedShell session=session route_snapshot=route_snapshot/> }
                                .into_any()
                        }
                        Ok(None) => view! { <LoginView/> }.into_any(),
                        // Live mode with the API unreachable: render the shell
                        // read-only with a degraded banner and zero roles. The
                        // snapshot is forced degraded so a racing probe can
                        // never label the shell live.
                        Err(_) => {
                            view! {
                                <DegradedShell route_snapshot=degraded_route_snapshot(
                                    &requested_path.get_untracked(),
                                )/>
                            }
                                .into_any()
                        }
                    }
                })
            }}
        </Suspense>
    }
}

/// The labeled degraded route snapshot; the constructor only fails when the
/// static allowlist itself is broken, which the fixture tests pin.
fn degraded_route_snapshot(requested_path: &str) -> PortalRouteStateSnapshot {
    PortalRouteStateSnapshot::degraded_static_fallback()
        .expect("degraded portal route state snapshot must build")
        .with_active_path(requested_path)
}

/// Provides the verified session through context, then renders the shell.
#[component]
fn AuthenticatedShell(
    session: AuthSession,
    route_snapshot: PortalRouteStateSnapshot,
) -> impl IntoView {
    provide_context(session);
    view! { <Shell route_snapshot=route_snapshot/> }
}

/// Zero-role degraded shell rendered when the upstream API is unreachable.
#[component]
fn DegradedShell(route_snapshot: PortalRouteStateSnapshot) -> impl IntoView {
    provide_context(degraded_auth_session());
    view! { <Shell route_snapshot=route_snapshot/> }
}

/// Rendered for paths outside the portal route table; the route list keeps
/// SSR and client routing in lockstep, so this is the only unmatched-path
/// surface.
#[component]
fn RouteNotFound() -> impl IntoView {
    view! {
        <main class="workspace" id="route-not-found">
            <section class="hero" aria-labelledby="route-not-found-title">
                <div>
                    <span class="eyebrow">"Navigation"</span>
                    <h1 id="route-not-found-title">"Page not found"</h1>
                    <p>"The requested path does not match any portal workspace route."</p>
                </div>
                <a class="primary-action" href="/">"Back to dashboard"</a>
            </section>
        </main>
    }
}
