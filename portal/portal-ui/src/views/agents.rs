use crate::api::{admin_agents_path, platform_summary_path, same_origin_api_path};
use crate::models::{condense_timestamp, AgentSummary};
use crate::server_boundary::get_admin_agents;
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

/// Agents workspace — read-only list of enrolled execution agents and their
/// recent jobs. Admin-only (PlatformAdmin gate enforced at the nav/route level;
/// the server fn additionally validates the same-origin path and requires a
/// live upstream session with admin scope).
#[component]
pub fn AgentListView() -> impl IntoView {
    let agents_api_path = api_path_guard();
    let list_resource = Resource::new(|| (), |_| get_admin_agents());

    view! {
        <div class="request-list-view">
            <div class="request-list-toolbar">
                <h2 id="agents-list-title">"Execution agents"</h2>
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
