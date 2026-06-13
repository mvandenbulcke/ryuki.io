use crate::api::{approvals_pending_path, platform_summary_path, same_origin_api_path};
use crate::models::{condense_timestamp, AuthSession, RequestSummary};
use crate::server_boundary::get_approvals_pending;
use crate::views::requests::{status_badge_class, status_label};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;

/// Zero-capability session: an absent context HIDES approvals, never reveals them.
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

/// Approvals inbox — oldest-first queue of requests pending the current
/// approver's decision. Rows deep-link to `/requests/{id}` where the
/// existing approve/reject controls live.
#[component]
pub fn ApprovalsList() -> impl IntoView {
    let approvals_api_path_guard = api_path(approvals_pending_path());
    let list_resource = Resource::new(|| (), |_| get_approvals_pending());
    let navigate = use_navigate();
    // The verified session is provided by AuthenticatedShell (app.rs). An
    // absent context falls back to a zero-capability session so the list
    // is hidden rather than shown.
    let _session = use_context::<AuthSession>().unwrap_or_else(no_capability_session);

    view! {
        <div class="request-list-view">
            <div class="request-list-toolbar">
                <h2 id="approvals-list-title">"Approvals — pending my decision"</h2>
            </div>

            <Suspense fallback=move || {
                view! {
                    <div
                        class="request-list-loading"
                        aria-busy="true"
                        data-api-path=approvals_api_path_guard
                    >
                        <p>"Loading approvals..."</p>
                    </div>
                }
            }>
                {move || {
                    let navigate = navigate.clone();
                    Suspend::new(async move {
                        let approvals: Vec<RequestSummary> = match list_resource.await {
                            Ok(list) => list,
                            Err(_) => {
                                return view! {
                                    <div
                                        class="request-list-error"
                                        role="alert"
                                        data-api-path=approvals_api_path_guard
                                    >
                                        <p>"Platform API unreachable"</p>
                                        <p class="table-note">
                                            "Live approvals data cannot be loaded. Check the platform API and reload this page."
                                        </p>
                                    </div>
                                }
                                    .into_any();
                            }
                        };

                        if approvals.is_empty() {
                            view! {
                                <div
                                    class="request-list-empty"
                                    aria-label="No pending approvals"
                                >
                                    <p>"No requests awaiting your approval."</p>
                                </div>
                            }
                                .into_any()
                        } else {
                            view! {
                                <div class="table-wrap">
                                <table
                                    class="request-table dense-table"
                                    aria-label="Approvals list"
                                    data-api-path=approvals_api_path_guard
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
                                        {approvals
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
                                                let on_id_click =
                                                    move |ev: leptos::ev::MouseEvent| {
                                                        ev.stop_propagation();
                                                        button_navigate(
                                                            &format!("/requests/{button_id}"),
                                                            NavigateOptions::default(),
                                                        );
                                                    };
                                                view! {
                                                    <tr
                                                        class="request-row clickable"
                                                        on:click=on_row_click
                                                    >
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
                                                        <td>
                                                            <span class=badge_class>
                                                                {status_text}
                                                            </span>
                                                        </td>
                                                        <td>
                                                            <span class="badge neutral">
                                                                {stage_text}
                                                            </span>
                                                        </td>
                                                        <td class="cell-date">
                                                            {condense_timestamp(&req.created)}
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
