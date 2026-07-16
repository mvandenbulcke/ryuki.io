use crate::api::{admin_agents_path, platform_summary_path, same_origin_api_path};
use crate::models::{condense_timestamp, AgentSummary, AuthSession};
use crate::server_boundary::{approve_agent, get_admin_agents, revoke_agent};
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

/// Only a Pending roster snapshot carrying consumed challenge provenance may
/// reach the approval action. The API and database repeat this invariant.
pub(crate) fn agent_is_approvable(status: &str, cryptographically_admitted: bool) -> bool {
    status == "pending" && cryptographically_admitted
}

/// Exact reviewed enrollment snapshot dispatched by terminal revocation.
/// Keeping all three values together prevents the view from accidentally
/// falling back to the reusable human-readable agent id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentRevokeArgs {
    pub(crate) agent_id: String,
    pub(crate) enrollment_id: String,
    pub(crate) public_key_fingerprint: String,
}

pub(crate) fn agent_revoke_args(agent: &AgentSummary) -> AgentRevokeArgs {
    AgentRevokeArgs {
        agent_id: agent.agent_id.clone(),
        enrollment_id: agent.enrollment_id.clone(),
        public_key_fingerprint: agent.public_key_fingerprint.clone(),
    }
}

/// The two-click guard is keyed by immutable enrollment id. If a roster refresh
/// replaces a row under the same agent id, the replacement is never left armed.
pub(crate) fn revoke_binding_is_armed(
    armed_enrollment_id: Option<&str>,
    enrollment_id: &str,
) -> bool {
    armed_enrollment_id == Some(enrollment_id)
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
    // Two-click arm guard for per-enrollment "Revoke" (terminal, irreversible).
    // Holds the immutable enrollment_id awaiting a confirming second click, so
    // neither a lone misclick nor reuse of the human-readable agent id can revoke
    // a replacement enrollment.
    #[allow(deprecated)]
    let (revoke_armed, set_revoke_armed) = create_signal::<Option<String>>(None);

    // Approve a pending enrollment using the immutable row id and reviewed key
    // fingerprint displayed in the same roster snapshot. The API rejects a stale
    // snapshot; either success or rejection refetches the list.
    let approve_action = Action::new(move |args: &(String, String, String, String)| {
        let (agent_id, enrollment_id, public_key_fingerprint, platform) = args.clone();
        set_action_feedback.set("Approving...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match approve_agent(agent_id, enrollment_id, public_key_fingerprint, platform).await {
                Ok(result) => {
                    set_action_feedback.set(format!("Agent {} approved.", result.id));
                    set_action_class.set("badge good");
                    list_resource.refetch();
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                    // A 409 means the reviewed enrollment was replaced or
                    // expired. Refetch on every rejection so the operator never
                    // keeps acting on a stale approval binding.
                    list_resource.refetch();
                }
            }
        }
    });

    // Revoke one exact reviewed enrollment (pending or approved). Revocation is
    // terminal on the API side, so success or stale-binding rejection refetches
    // the list.
    let revoke_action = Action::new(move |args: &AgentRevokeArgs| {
        let args = args.clone();
        set_action_feedback.set("Revoking...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match revoke_agent(
                args.agent_id,
                args.enrollment_id,
                args.public_key_fingerprint,
            )
            .await
            {
                Ok(result) => {
                    set_action_feedback.set(format!("Agent {} revoked.", result.id));
                    set_action_class.set("badge good");
                    list_resource.refetch();
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                    list_resource.refetch();
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
                                        <p>"Agent roster unavailable or incomplete"</p>
                                        <p class="table-note">
                                            "Do not approve agents or close the enrollment cutover until the platform API returns the complete roster and the legacy inventory has been reviewed."
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
                                        "Stage a key-bound enrollment through trusted provisioning, run the agent on its platform host, then complete the separate approval review."
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
                                                <th scope="col">"Enrollment ID"</th>
                                                <th scope="col">"Key fingerprint"</th>
                                                <th scope="col">"Capability digest"</th>
                                                <th scope="col">"Platform"</th>
                                                <th scope="col">"Admission"</th>
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
                                                    // Approval is offered only for a Pending row
                                                    // whose consumed provisioning challenge is
                                                    // visible in the typed roster contract.
                                                    let cryptographically_admitted = agent
                                                        .cryptographically_admitted;
                                                    let is_approvable = agent_is_approvable(
                                                        &agent.status,
                                                        cryptographically_admitted,
                                                    );
                                                    // Revoke is offered for any non-revoked agent
                                                    // (pending = deny enrollment; approved = take
                                                    // offline). A revoked agent shows no action.
                                                    let is_revoked = agent.status == "revoked";
                                                    let approve_id = agent.agent_id.clone();
                                                    let approve_enrollment_id = agent
                                                        .enrollment_id
                                                        .clone();
                                                    let approve_public_key_fingerprint = agent
                                                        .public_key_fingerprint
                                                        .clone();
                                                    let approve_platform = agent.platform.clone();
                                                    let revoke_args = agent_revoke_args(&agent);

                                                    view! {
                                                        <tr class="request-row">
                                                            <td>
                                                                <span class="table-note">
                                                                    {agent.agent_id.clone()}
                                                                </span>
                                                            </td>
                                                            <td>
                                                                <span class="table-note">
                                                                    {agent.enrollment_id.clone()}
                                                                </span>
                                                            </td>
                                                            <td>
                                                                <code class="table-note">
                                                                    {agent.public_key_fingerprint.clone()}
                                                                </code>
                                                            </td>
                                                            <td>
                                                                <code class="table-note">
                                                                    {agent.capabilities_digest.clone()}
                                                                </code>
                                                            </td>
                                                            <td>{agent.platform.clone()}</td>
                                                            <td>
                                                                <span class="table-note">
                                                                    {if cryptographically_admitted {
                                                                        "Challenge-bound"
                                                                    } else {
                                                                        "Legacy/unverified"
                                                                    }}
                                                                </span>
                                                            </td>
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
                                                                    {if is_revoked {
                                                                        view! {
                                                                            <span class="table-note">"—"</span>
                                                                        }
                                                                            .into_any()
                                                                    } else {
                                                                        let approve_id = approve_id.clone();
                                                                        let approve_enrollment_id = approve_enrollment_id
                                                                            .clone();
                                                                        let approve_public_key_fingerprint = approve_public_key_fingerprint
                                                                            .clone();
                                                                        let approve_platform = approve_platform
                                                                            .clone();
                                                                        let revoke_args = revoke_args.clone();
                                                                        let revoke_enrollment_id_for_label = revoke_args
                                                                            .enrollment_id
                                                                            .clone();
                                                                        view! {
                                                                            <div class="agent-actions">
                                                                                {is_approvable
                                                                                    .then(|| {
                                                                                        let approve_id = approve_id.clone();
                                                                                        let approve_enrollment_id = approve_enrollment_id
                                                                                            .clone();
                                                                                        let approve_public_key_fingerprint = approve_public_key_fingerprint
                                                                                            .clone();
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
                                                                                                            approve_enrollment_id.clone(),
                                                                                                            approve_public_key_fingerprint.clone(),
                                                                                                            approve_platform.clone(),
                                                                                                        ));
                                                                                                }
                                                                                            >
                                                                                                "Approve"
                                                                                            </button>
                                                                                        }
                                                                                    })}
                                                                                <button
                                                                                    type="button"
                                                                                    class="btn btn-danger"
                                                                                    on:click=move |_| {
                                                                                        // Terminal, irreversible — require a
                                                                                        // confirming second click on THIS row.
                                                                                        if revoke_binding_is_armed(
                                                                                            revoke_armed.get().as_deref(),
                                                                                            &revoke_args.enrollment_id,
                                                                                        )
                                                                                        {
                                                                                            set_revoke_armed.set(None);
                                                                                            revoke_action
                                                                                                .dispatch(revoke_args.clone());
                                                                                        } else {
                                                                                            set_revoke_armed
                                                                                                .set(Some(revoke_args.enrollment_id.clone()));
                                                                                        }
                                                                                    }
                                                                                >
                                                                                    {move || {
                                                                                        if revoke_binding_is_armed(
                                                                                            revoke_armed.get().as_deref(),
                                                                                            &revoke_enrollment_id_for_label,
                                                                                        )
                                                                                        {
                                                                                            "Confirm revoke"
                                                                                        } else {
                                                                                            "Revoke"
                                                                                        }
                                                                                    }}
                                                                                </button>
                                                                            </div>
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
