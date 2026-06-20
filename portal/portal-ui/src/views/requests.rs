use crate::api::{platform_summary_path, request_list_path, same_origin_api_path};
use crate::models::{condense_timestamp, AuthSession, RequestSummary};
use crate::server_boundary::get_request_list;
use crate::workspace_catalog::session_can;
use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query_map};
use leptos_router::NavigateOptions;

/// Zero-capability session used when no `AuthSession` is in context. An absent
/// context must HIDE capability-gated controls, never reveal them — so this is
/// deliberately not `auth_session_fallback` (which carries PlatformAdmin).
fn no_capability_session() -> AuthSession {
    AuthSession {
        user_id: String::new(),
        display_name: String::new(),
        roles: Vec::new(),
        token_valid: false,
        provider_mode: String::new(),
    }
}

fn api_path(path: &'static str) -> &'static str {
    same_origin_api_path(path).unwrap_or(platform_summary_path())
}

/// Pure filtering function for the requests list.
///
/// Case-insensitive substring match across `id`, `name`, `request_type`,
/// `status`, and `site`. An empty `q` returns all rows unchanged so the
/// default (no search) view is identical to the pre-filter view.
pub fn filter_requests<'a>(requests: &'a [RequestSummary], q: &str) -> Vec<&'a RequestSummary> {
    if q.is_empty() {
        return requests.iter().collect();
    }
    let needle = q.to_lowercase();
    requests
        .iter()
        .filter(|r| {
            r.id.to_lowercase().contains(&needle)
                || r.name.to_lowercase().contains(&needle)
                || r.request_type.to_lowercase().contains(&needle)
                || r.status.to_lowercase().contains(&needle)
                || r.site.to_lowercase().contains(&needle)
        })
        .collect()
}

pub(crate) fn status_badge_class(status: &str) -> &'static str {
    match status {
        "intake" => "badge neutral",
        "validated" => "badge good",
        "approved" => "badge good",
        "executed" | "verified" | "completed" => "badge good",
        // Post-completion governed lifecycle (Theme 8).
        "protecting" | "operational" => "badge good",
        "retired" => "badge neutral",
        "failed" => "badge bad",
        "rejected" | "cancelled" => "badge bad",
        "executing" | "verifying" => "badge warn",
        _ => "badge neutral",
    }
}

pub(crate) fn status_label(status: &str) -> &'static str {
    match status {
        "intake" => "Intake",
        "validated" => "Validated",
        "planned" => "Planned",
        "approved" => "Approved",
        "locked" => "Locked",
        "executing" => "Executing",
        "executed" => "Executed",
        "verifying" => "Verifying",
        "verified" => "Verified",
        "completed" => "Completed",
        // Post-completion governed lifecycle (Theme 8).
        "protecting" => "Protecting",
        "operational" => "Operational",
        "retired" => "Retired",
        "failed" => "Failed",
        "rejected" => "Rejected",
        "cancelled" => "Cancelled",
        &_ => "Unknown",
    }
}

#[component]
pub fn RequestList() -> impl IntoView {
    let request_list_path_guard = api_path(request_list_path());
    let list_resource = Resource::new(|| (), |_| get_request_list());
    let navigate = use_navigate();
    // The verified session is provided by AuthenticatedShell (app.rs). An
    // absent context falls back to a zero-capability session so the control
    // is hidden rather than shown.
    let session = use_context::<AuthSession>().unwrap_or_else(no_capability_session);
    let can_request = session_can(&session, "request");

    // Reactive query param: re-filters whenever `?q=` changes without
    // re-fetching the server function.
    let query = use_query_map();
    let q_memo = Memo::new(move |_| query.with(|map| map.get("q").unwrap_or_default()));

    view! {
        <div class="request-list-view">
            <div class="request-list-toolbar">
                <h2 id="request-list-title">"Requests"</h2>
                <Show when=move || can_request>
                    <a class="btn btn-primary" href="/requests/new">
                        "New Request"
                    </a>
                </Show>
            </div>

            <Suspense fallback=move || {
                view! {
                    <div class="request-list-loading" aria-busy="true" data-api-path=request_list_path_guard>
                        <p>"Loading requests..."</p>
                    </div>
                }
            }>
                {move || {
                    let navigate = navigate.clone();
                    let q = q_memo.get();
                    Suspend::new(async move {
                        let requests: Vec<RequestSummary> = match list_resource.await {
                            Ok(list) => list,
                            // Live mode with the API unreachable: an explicit
                            // error state, never demo rows.
                            Err(_) => {
                                return view! {
                                    <div
                                        class="request-list-error"
                                        role="alert"
                                        data-api-path=request_list_path_guard
                                    >
                                        <p>"Platform API unreachable"</p>
                                        <p class="table-note">
                                            "Live request data cannot be loaded. Check the platform API and reload this page."
                                        </p>
                                    </div>
                                }
                                    .into_any();
                            }
                        };

                        if requests.is_empty() {
                            return view! {
                                <div class="request-list-empty" aria-label="No requests">
                                    <p>"No requests yet."</p>
                                    <p class="table-note">"Create a new request to get started."</p>
                                </div>
                            }
                                .into_any();
                        }

                        // Client-side filter: applied after the resource
                        // resolves so no extra server round-trip is needed.
                        let filtered: Vec<&RequestSummary> = filter_requests(&requests, &q);
                        let total = requests.len();
                        let match_count = filtered.len();
                        let active_query = q.clone();

                        if !active_query.is_empty() && match_count == 0 {
                            return view! {
                                <div class="request-list-empty" aria-label="No search results">
                                    <p>"No requests match " <strong>{active_query.clone()}</strong></p>
                                    <p class="table-note">
                                        "Try a different search term or "
                                        <a href="/requests">"clear the search"</a>
                                        " to see all requests."
                                    </p>
                                </div>
                            }
                                .into_any();
                        }

                        // Owned copies for the iterator below (refs can't
                        // outlive the borrowed `requests` vec in the view).
                        let display_rows: Vec<RequestSummary> =
                            filtered.into_iter().cloned().collect();
                        // Extra clone for the Show `when` closure (borrows
                        // the string reactively before the inner content
                        // closure captures it).
                        let show_query = active_query.clone();

                        view! {
                            <div class="table-wrap">
                                // Search result note — only shown when a query is active.
                                <Show when=move || !show_query.is_empty()>
                                    <p class="search-result-note table-note">
                                        {match_count} " result" {if match_count == 1 { "" } else { "s" }}
                                        " for " <strong>{active_query.clone()}</strong>
                                        " (of " {total} " total)"
                                    </p>
                                </Show>
                                <table
                                    class="request-table dense-table"
                                    aria-label="Request list"
                                    data-api-path=request_list_path_guard
                                >
                                    <thead>
                                        <tr>
                                            <th scope="col">"ID"</th>
                                            <th scope="col">"Type"</th>
                                            <th scope="col">"Name"</th>
                                            <th scope="col">"Site"</th>
                                            <th scope="col">"Env"</th>
                                            <th scope="col">"Status"</th>
                                            <th scope="col">"Stage"</th>
                                            <th scope="col">"Created"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {display_rows
                                            .into_iter()
                                            .map(|req| {
                                                let row_id = req.id.clone();
                                                let button_id = req.id.clone();
                                                let open_label = format!("Open request {}", req.id);
                                                let display_id = if req.id.len() > 8 {
                                                    req.id[..8].to_string()
                                                } else {
                                                    req.id.clone()
                                                };
                                                let badge_class = status_badge_class(&req.status);
                                                let status_text = status_label(&req.status);
                                                let stage_text = req.stage.clone();
                                                let row_navigate = navigate.clone();
                                                let button_navigate = navigate.clone();
                                                let on_row_click = move |_| {
                                                    row_navigate(
                                                        &format!("/requests/{row_id}"),
                                                        NavigateOptions::default(),
                                                    );
                                                };
                                                // Real button so the row is reachable and
                                                // activatable by keyboard, not mouse-only.
                                                let on_id_click = move |ev: leptos::ev::MouseEvent| {
                                                    ev.stop_propagation();
                                                    button_navigate(
                                                        &format!("/requests/{button_id}"),
                                                        NavigateOptions::default(),
                                                    );
                                                };
                                                view! {
                                                    <tr class="request-row clickable" on:click=on_row_click>
                                                        <td class="cell-id">
                                                            <button
                                                                class="row-link"
                                                                aria-label=open_label
                                                                on:click=on_id_click
                                                            >
                                                                {display_id}
                                                            </button>
                                                        </td>
                                                        <td>{req.request_type}</td>
                                                        <td>{req.name}</td>
                                                        <td>{req.site}</td>
                                                        <td>{req.environment}</td>
                                                        <td><span class=badge_class>{status_text}</span></td>
                                                        <td><span class="badge neutral">{stage_text}</span></td>
                                                        <td class="cell-date">{condense_timestamp(&req.created)}</td>
                                                    </tr>
                                                }
                                            })
                                            .collect_view()}
                                    </tbody>
                                </table>
                            </div>
                        }
                            .into_any()
                    })
                }}
            </Suspense>
        </div>
    }
}
