use crate::api::{admin_agents_path, platform_summary_path, same_origin_api_path};
use crate::models::{condense_timestamp, AgentSummary, AuthSession};
use crate::server_boundary::{approve_agent, get_admin_agents};
use crate::workspace_catalog::session_can;
use leptos::prelude::*;

// ── Pure helper functions ─────────────────────────────────────────────────────

/// CSS badge class for an agent enrollment status.
///
/// The API uses `pending | approved | revoked` as the canonical values.
pub(crate) fn status_badge_class(status: &str) -> &'static str {
    match status {
        "approved" => "badge good",
        "revoked" => "badge bad",
        "pending" => "badge neutral",
        _ => "badge neutral",
    }
}

// ─────────────────────────────────────────────────────────────────────────────

fn api_path_guard() -> &'static str {
    same_origin_api_path(admin_agents_path()).unwrap_or(platform_summary_path())
}

/// Zero-capability session used when no `AuthSession` is in context. An absent
/// context must HIDE the Approve button, never reveal it — so this carries no
/// roles and `token_valid = false`.
fn no_capability_session() -> AuthSession {
    AuthSession {
        user_id: String::new(),
        display_name: String::new(),
        roles: Vec::new(),
        token_valid: false,
        provider_mode: String::new(),
    }
}

/// Strips the leptos server-fn error prefix so the API's safe message surfaces
/// directly in the action feedback line.
fn server_error_message(error: &ServerFnError) -> String {
    let text = error.to_string();
    text.strip_prefix("error running server function: ")
        .map(str::to_string)
        .unwrap_or(text)
}

/// Agents workspace — read-only list of enrolled execution agents and their
/// recent jobs. Admin-only (PlatformAdmin gate enforced at the nav/route level;
/// the server fn additionally validates the same-origin path and requires a
/// live upstream session with admin scope).
#[component]
pub fn AgentListView() -> impl IntoView {
    let agents_api_path = api_path_guard();
    let list_resource = Resource::new(|| (), |_| get_admin_agents());
    // The verified session is provided by AuthenticatedShell (app.rs). An absent
    // context falls back to a zero-capability session so the Approve button is
    // hidden rather than shown. Only the `admin` capability (PlatformAdmin /
    // BreakGlassAdmin) may approve an enrollment.
    let session = use_context::<AuthSession>().unwrap_or_else(no_capability_session);
    let can_admin = session_can(&session, "admin");

    #[allow(deprecated)]
    let (action_feedback, set_action_feedback) = create_signal(String::new());
    #[allow(deprecated)]
    let (action_class, set_action_class) = create_signal("badge neutral");

    // Approve a pending enrollment. The agent's currently displayed platform is
    // re-affirmed as the authoritative value; on success the list is refetched
    // so the row's status flips to "approved".
    let approve_action = Action::new(move |args: &(String, String)| {
        let (agent_id, platform) = args.clone();
        set_action_feedback.set("Approving...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match approve_agent(agent_id, platform).await {
                Ok(result) => {
                    set_action_feedback.set(format!("Agent {} approved.", result.id));
                    set_action_class.set("badge good");
                    list_resource.refetch();
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    view! {
        <div class="request-list-view">
            <div class="request-list-toolbar">
                <h2 id="agents-list-title">"Execution agents"</h2>
                <Show when=move || !action_feedback.get().is_empty()>
                    <span class=move || action_class.get() role="status" aria-live="polite">
                        {move || action_feedback.get()}
                    </span>
                </Show>
            </div>

            <Suspense fallback=move || {
                view! {
                    <div
                        class="request-list-loading"
                        aria-busy="true"
                        data-api-path=agents_api_path
                    >
                        <p>"Loading agents..."</p>
                    </div>
                }
            }>
                {move || {
                    Suspend::new(async move {
                        let agents: Vec<AgentSummary> = match list_resource.await {
                            Ok(list) => list,
                            Err(_) => {
                                return view! {
                                    <div
                                        class="request-list-error"
                                        role="alert"
                                        data-api-path=agents_api_path
                                    >
                                        <p>"Platform API unreachable"</p>
                                        <p class="table-note">
                                            "Agent list could not be loaded. Check the platform API and reload this page."
                                        </p>
                                    </div>
                                }
                                .into_any();
                            }
                        };

                        if agents.is_empty() {
                            view! {
                                <div
                                    class="request-list-empty"
                                    aria-label="No agents enrolled"
                                    data-api-path=agents_api_path
                                >
                                    <p>"No execution agents enrolled."</p>
                                    <p class="table-note">
                                        "Register an agent by running the ryuki-runner on a platform host and completing the approval workflow."
                                    </p>
                                </div>
                            }
                            .into_any()
                        } else {
                            view! {
                                <div class="table-wrap">
                                    <table
                                        class="request-table dense-table"
                                        aria-label="Execution agents"
                                        data-api-path=agents_api_path
                                    >
                                        <thead>
                                            <tr>
                                                <th scope="col">"Agent ID"</th>
                                                <th scope="col">"Platform"</th>
                                                <th scope="col">"Status"</th>
                                                <th scope="col">"Last seen"</th>
                                                <th scope="col">"Jobs"</th>
                                                <Show when=move || can_admin>
                                                    <th scope="col">"Actions"</th>
                                                </Show>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {agents
                                                .into_iter()
                                                .map(|agent| {
                                                    let status_badge = status_badge_class(
                                                        &agent.status,
                                                    );
                                                    let last_seen = agent
                                                        .last_seen_at
                                                        .as_deref()
                                                        .map(condense_timestamp)
                                                        .unwrap_or_default();
                                                    // Approve is offered only to admins on a
                                                    // pending enrollment; the values needed to
                                                    // dispatch are captured before the row view.
                                                    let is_pending = agent.status == "pending";
                                                    let approve_id = agent.agent_id.clone();
                                                    let approve_platform = agent.platform.clone();

                                                    view! {
                                                        <tr class="request-row">
                                                            <td>
                                                                <span class="table-note">
                                                                    {agent.agent_id.clone()}
                                                                </span>
                                                            </td>
                                                            <td>{agent.platform.clone()}</td>
                                                            <td>
                                                                <span class=status_badge>
                                                                    {agent.status.clone()}
                                                                </span>
                                                            </td>
                                                            <td class="cell-date">
                                                                <span class="table-note">
                                                                    {last_seen}
                                                                </span>
                                                            </td>
                                                            <td>
                                                                {if agent.jobs.is_empty() {
                                                                    view! {
                                                                        <span class="table-note">
                                                                            "—"
                                                                        </span>
                                                                    }
                                                                    .into_any()
                                                                } else {
                                                                    view! {
                                                                        <ul class="agent-job-list">
                                                                            {agent
                                                                                .jobs
                                                                                .into_iter()
                                                                                .map(|job| {
                                                                                    let short_id = job
                                                                                        .id
                                                                                        .chars()
                                                                                        .take(8)
                                                                                        .collect::<String>();
                                                                                    let completed = job
                                                                                        .completed_at
                                                                                        .as_deref()
                                                                                        .map(condense_timestamp)
                                                                                        .unwrap_or_default();
                                                                                    let result = job
                                                                                        .result_status
                                                                                        .clone()
                                                                                        .unwrap_or_default();
                                                                                    view! {
                                                                                        <li class="agent-job-row">
                                                                                            <span class="table-note">
                                                                                                {short_id}
                                                                                            </span>
                                                                                            <span>
                                                                                                {job.mode.clone()}
                                                                                            </span>
                                                                                            <span>
                                                                                                {job.status.clone()}
                                                                                            </span>
                                                                                            {(!result.is_empty())
                                                                                                .then(|| {
                                                                                                    view! {
                                                                                                        <span class="table-note">
                                                                                                            {result}
                                                                                                        </span>
                                                                                                    }
                                                                                                })}
                                                                                            {(!completed.is_empty())
                                                                                                .then(|| {
                                                                                                    view! {
                                                                                                        <span class="table-note">
                                                                                                            {completed}
                                                                                                        </span>
                                                                                                    }
                                                                                                })}
                                                                                        </li>
                                                                                    }
                                                                                })
                                                                                .collect_view()}
                                                                        </ul>
                                                                    }
                                                                    .into_any()
                                                                }}
                                                            </td>
                                                            <Show when=move || can_admin>
                                                                <td>
                                                                    {if is_pending {
                                                                        let approve_id = approve_id.clone();
                                                                        let approve_platform = approve_platform
                                                                            .clone();
                                                                        view! {
                                                                            <button
                                                                                type="button"
                                                                                class="btn btn-primary"
                                                                                on:click=move |_| {
                                                                                    approve_action
                                                                                        .dispatch((
                                                                                            approve_id.clone(),
                                                                                            approve_platform.clone(),
                                                                                        ));
                                                                                }
                                                                            >
                                                                                "Approve"
                                                                            </button>
                                                                        }
                                                                            .into_any()
                                                                    } else {
                                                                        view! {
                                                                            <span class="table-note">"—"</span>
                                                                        }
                                                                            .into_any()
                                                                    }}
                                                                </td>
                                                            </Show>
                                                        </tr>
                                                    }
                                                })
                                                .collect_view()}
                                        </tbody>
                                    </table>
                                </div>
                            }
                            .into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

// ── Unit tests for extractable pure logic ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_badge_class_maps_all_agent_statuses() {
        assert_eq!(status_badge_class("approved"), "badge good");
        assert_eq!(status_badge_class("revoked"), "badge bad");
        assert_eq!(status_badge_class("pending"), "badge neutral");
        // Unknown values fall back to neutral.
        assert_eq!(status_badge_class("unknown"), "badge neutral");
        assert_eq!(status_badge_class(""), "badge neutral");
    }
}
