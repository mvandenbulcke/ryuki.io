/// Integrations workspace — functional surface (PR-B).
///
/// PR-A ships the plumbing (nav, route, server fns, models). The full
/// `IntegrationsList` and `IntegrationsForm` components ship in PR-B once
/// the structural gates are confirmed green.
use leptos::prelude::*;

/// Placeholder rendered inside `IntegrationsWorkspaceView` while PR-B is
/// pending. Honest: it signals that the workspace exists and is admin-gated
/// without fabricating data.
#[component]
pub fn IntegrationsPlaceholder() -> impl IntoView {
    view! {
        <div
            class="request-list-empty"
            aria-label="Integrations workspace"
            data-api-path="/api/integrations"
        >
            <p>"Integrations"</p>
            <p class="table-note">"Integration connection management is coming in the next release."</p>
        </div>
    }
}
