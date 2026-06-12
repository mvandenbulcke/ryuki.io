use crate::api::{platform_summary_path, request_list_path, same_origin_api_path};
use crate::models::{request_summary_fallbacks, RequestSummary};
use crate::server_boundary::get_request_list;
use leptos::prelude::*;

fn api_path(path: &'static str) -> &'static str {
    same_origin_api_path(path).unwrap_or(platform_summary_path())
}

fn status_badge_class(status: &str) -> &'static str {
    match status {
        "intake" => "badge neutral",
        "validated" => "badge good",
        "approved" => "badge good",
        "executed" => "badge good",
        "failed" => "badge bad",
        _ => "badge neutral",
    }
}

fn status_label(status: &str) -> &'static str {
    match status {
        "intake" => "Intake",
        "validated" => "Validated",
        "approved" => "Approved",
        "executed" => "Executed",
        "failed" => "Failed",
        &_ => "Unknown",
    }
}

#[component]
pub fn RequestList(
    #[prop(into)] on_select: Callback<String>,
    #[prop(into)] on_create: Callback<()>,
) -> impl IntoView {
    let request_list_path_guard = api_path(request_list_path());
    let list_resource = Resource::new(|| (), |_| get_request_list());

    view! {
        <div class="request-list-view">
            <div class="request-list-toolbar">
                <h2 id="request-list-title">"Requests"</h2>
                <button class="btn btn-primary" on:click=move |_| on_create.run(())>
                    "New Request"
                </button>
            </div>

            <Suspense fallback=move || {
                view! {
                    <div class="request-list-loading" aria-busy="true" data-api-path=request_list_path_guard>
                        <p>"Loading requests..."</p>
                    </div>
                }
            }>
                {move || {
                    Suspend::new(async move {
                        let requests: Vec<RequestSummary> = match list_resource.await {
                            Ok(list) => list,
                            Err(_) => request_summary_fallbacks(),
                        };

                        if requests.is_empty() {
                            view! {
                                <div class="request-list-empty" aria-label="No requests">
                                    <p>"No requests yet."</p>
                                    <p class="table-note">"Create a new request to get started."</p>
                                </div>
                            }
                                .into_any()
                        } else {
                            view! {
                                <div class="table-wrap">
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
                                        {requests
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
                                                let on_row_click = move |_| on_select.run(row_id.clone());
                                                // Real button so the row is reachable and
                                                // activatable by keyboard, not mouse-only.
                                                let on_id_click = move |ev: leptos::ev::MouseEvent| {
                                                    ev.stop_propagation();
                                                    on_select.run(button_id.clone());
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
                                                        <td class="cell-date">{req.created}</td>
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
