use crate::models::auth_session_fallback;
use crate::server_boundary::PortalRouteStateSnapshot;
use crate::views::dashboard::DashboardView;
use crate::views::workspaces::WorkspaceSections;
use crate::workspace_catalog::{role_satisfies, PRIMARY_NAV_ITEMS};
use leptos::prelude::*;

pub fn is_authenticated() -> bool {
    true
}

#[component]
pub fn Shell() -> impl IntoView {
    let route_snapshot = PortalRouteStateSnapshot::static_dry_run()
        .expect("portal route state snapshot must be static and allowlisted");
    let auth_session = auth_session_fallback();
    let home_href = route_snapshot.active_route.clone();
    let main_id = route_snapshot.active_workspace.clone();
    let activity_href = route_snapshot.activity_route.clone();
    let activity_action_label = route_snapshot.activity_action_label.clone();
    let site_scope_label = route_snapshot.site_scope_label.clone();
    let environment_scope_label = route_snapshot.environment_scope_label.clone();
    let role_scope_label = route_snapshot.role_scope_label.clone();
    let inventory_freshness_label = route_snapshot.inventory_freshness_label.clone();
    let backup_freshness_label = route_snapshot.backup_freshness_label.clone();
    let monitoring_freshness_label = route_snapshot.monitoring_freshness_label.clone();
    let execution_authority_label = route_snapshot.execution_authority_label.clone();
    let api_boundary = route_snapshot.api_boundary.clone();
    let execution_mode = route_snapshot.execution_mode.clone();
    let route_state_path = route_snapshot.route_state_path.clone();
    let run_state_path = route_snapshot.run_state_path.clone();
    let route_state = route_snapshot.route_state.clone();
    let run_state = route_snapshot.run_state.clone();
    let route_safe_summary = route_snapshot.safe_summary.clone();
    let route_http_request_allowed = route_snapshot.http_request_allowed.to_string();
    let route_provider_calls_allowed = route_snapshot.provider_calls_allowed.to_string();
    let route_live_execution_allowed = route_snapshot.live_execution_allowed.to_string();
    let route_raw_state_allowed = route_snapshot.raw_route_state_allowed.to_string();
    let user_name = auth_session.display_name.clone();
    let user_roles = auth_session.roles.join(", ");

    view! {
        <div class="shell">
            <header class="topbar" aria-label="Product shell">
                <a class="brand" href=home_href aria-label="Ryuki Infrastructure Platform home">
                    <span class="brand-mark" aria-hidden="true">"R"</span>
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
                        placeholder="Search requests, CIs, evidence, servers, apps..."
                        disabled=true
                    />
                </form>
                <div class="scope" aria-label="Current scope">
                    <span class="pill">{site_scope_label.clone()}</span>
                    <span class="pill">{environment_scope_label.clone()}</span>
                    <span class="pill role">{role_scope_label.clone()}</span>
                </div>
                <div class="session-info" aria-label="Session info">
                    <span class="pill user">{user_name}</span>
                    <span class="table-note">"Roles: " {user_roles}</span>
                </div>
            </header>

            <nav class="nav" aria-label="Primary navigation">
                {PRIMARY_NAV_ITEMS
                    .iter()
                    .filter(|item| role_satisfies(&auth_session, item.required_role))
                    .map(|item| {
                        let class = if item.active { "active" } else { "" };
                        view! {
                            <a class=class href=item.href>{item.label}</a>
                        }
                    })
                    .collect_view()}
            </nav>

            <main
                class="workspace"
                id=main_id
                data-api-boundary=api_boundary
                data-execution-mode=execution_mode
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
                    <div>
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

                <section class="hero" aria-labelledby="dashboard-title">
                    <div>
                        <span class="eyebrow">"Dashboard"</span>
                        <h1 id="dashboard-title">"Operational control plane"</h1>
                        <p>
                            "Safe summaries for platform health, readiness, protected workloads, monitoring coverage, and blocked execution."
                        </p>
                    </div>
                    <a class="primary-action" href=activity_href>{activity_action_label}</a>
                </section>

                <DashboardView/>
                <WorkspaceSections/>
            </main>
        </div>
    }
}
