use crate::api::{platform_summary_path, request_detail_path};
use crate::models::AuthSession;
use crate::server_boundary::{
    approve_request, execute_request, get_request_detail, lock_request, plan_request,
    validate_request, verify_request,
};
use crate::workspace_catalog::session_can;
use leptos::prelude::*;
use leptos_router::hooks::use_params_map;

/// Zero-capability session used when no `AuthSession` is in context. An absent
/// context must HIDE every lifecycle button, never reveal one — so this is
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

/// Maps a lifecycle action to the capability that gates it, mirroring the
/// engine action->permission map (sources/ryuki-api/src/contracts.rs request
/// lifecycle handlers): validate/plan/lock/execute/verify require `execute`;
/// approve requires `approve`.
fn action_capability(action: &str) -> &'static str {
    match action {
        "approve" => "approve",
        // validate, plan, lock, execute, verify are operator-tier mechanics.
        _ => "execute",
    }
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

fn stage_label(stage: &str) -> &'static str {
    match stage {
        "intake" => "Intake",
        "validated" => "Validated",
        "planned" => "Planned",
        "approved" => "Approved",
        "locked" => "Locked",
        "executed" => "Executed",
        "verified" => "Verified",
        "failed" => "Failed",
        &_ => "Unknown",
    }
}

/// Strips the server-function transport prefix so action feedback badges
/// show the API/boundary message rather than the wire-format wrapper.
fn server_error_message(error: &leptos::prelude::ServerFnError) -> String {
    let text = error.to_string();
    text.strip_prefix("error running server function: ")
        .map(str::to_string)
        .unwrap_or(text)
}

fn action_label(action: &str) -> &'static str {
    match action {
        "validate" => "Validate",
        "plan" => "Plan",
        "approve" => "Approve",
        "lock" => "Lock",
        "execute" => "Execute",
        "verify" => "Verify",
        &_ => "Unknown",
    }
}

#[component]
pub fn RequestDetail() -> impl IntoView {
    // The request id arrives from the `/requests/:id` route, so request
    // detail pages are directly addressable deep links.
    let params = use_params_map();
    let request_id = Memo::new(move |_| params.read().get("id").unwrap_or_default());
    // The verified session is provided by AuthenticatedShell (app.rs). An
    // absent context falls back to a zero-capability session so buttons are
    // hidden rather than shown.
    let session = use_context::<AuthSession>().unwrap_or_else(no_capability_session);
    let detail_path = Memo::new(move |_| {
        request_detail_path(&request_id.get())
            .unwrap_or_else(|_| platform_summary_path().to_string())
    });
    let loading_detail_path = move || detail_path.get();
    let content_detail_path = move || detail_path.get();
    let detail_resource = Resource::new(move || request_id.get(), get_request_detail);

    #[allow(deprecated)]
    let (action_feedback, set_action_feedback) = create_signal(String::new());
    #[allow(deprecated)]
    let (action_class, set_action_class) = create_signal("badge neutral");

    let validate_action = Action::new(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Validating...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match validate_request(id).await {
                Ok(resp) => {
                    let succeeded = resp.success;
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if succeeded { "badge good" } else { "badge bad" });
                    if succeeded {
                        detail_resource.refetch();
                    }
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let plan_action = Action::new(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Planning...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match plan_request(id).await {
                Ok(resp) => {
                    let succeeded = resp.success;
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if succeeded { "badge good" } else { "badge bad" });
                    if succeeded {
                        detail_resource.refetch();
                    }
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let approve_action = Action::new(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Approving...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match approve_request(id).await {
                Ok(resp) => {
                    let succeeded = resp.success;
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if succeeded { "badge good" } else { "badge bad" });
                    if succeeded {
                        detail_resource.refetch();
                    }
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let lock_action = Action::new(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Locking...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match lock_request(id).await {
                Ok(resp) => {
                    let succeeded = resp.success;
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if succeeded { "badge good" } else { "badge bad" });
                    if succeeded {
                        detail_resource.refetch();
                    }
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let execute_action = Action::new(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Executing...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match execute_request(id).await {
                Ok(resp) => {
                    let succeeded = resp.success;
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if succeeded { "badge good" } else { "badge bad" });
                    if succeeded {
                        detail_resource.refetch();
                    }
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let verify_action = Action::new(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Verifying...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match verify_request(id).await {
                Ok(resp) => {
                    let succeeded = resp.success;
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if succeeded { "badge good" } else { "badge bad" });
                    if succeeded {
                        detail_resource.refetch();
                    }
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    view! {
        <div class="request-detail-view">
            <Suspense fallback=move || {
                view! {
                    <div class="request-detail-loading" aria-busy="true" data-api-path=loading_detail_path>
                        <p>"Loading request detail..."</p>
                    </div>
                }
            }>
                {move || {
                    let session = session.clone();
                    Suspend::new(async move {
                        let detail = match detail_resource.await {
                            Ok(d) => d,
                            // Live mode with the API unreachable: an explicit
                            // error state, never the demo detail.
                            Err(_) => {
                                return view! {
                                    <div
                                        class="request-detail-error"
                                        role="alert"
                                        data-api-path=content_detail_path
                                    >
                                        <p>"Platform API unreachable"</p>
                                        <p class="table-note">
                                            "Request detail cannot be loaded. Check the platform API and try again."
                                        </p>
                                        <a class="btn btn-secondary" href="/requests">
                                            "Back to list"
                                        </a>
                                    </div>
                                }
                                    .into_any();
                            }
                        };

                        let status_class = status_badge_class(&detail.status);
                        let stage_text = stage_label(&detail.stage);
                        let current_stage = detail.stage.clone();
                        // Gate each stage-available action on its capability,
                        // using the same action->permission map as the engine.
                        let actions: Vec<String> = detail
                            .actions_available
                            .iter()
                            .filter(|action| session_can(&session, action_capability(action)))
                            .cloned()
                            .collect();
                        let request_id_for_action = detail.id.clone();

                        view! {
                            <article
                                class="request-detail-panel"
                                aria-label="Request detail"
                                data-api-path=content_detail_path
                                data-request-id=detail.id.clone()
                            >
                                <div class="request-detail-head">
                                    <div>
                                        <span class="eyebrow">"Request"</span>
                                        <h2>{detail.request_type.clone()} " / " {detail.name.clone()}</h2>
                                    </div>
                                    <div class="request-detail-badges">
                                        <span class=status_class>{detail.status.clone()}</span>
                                        <span class="badge neutral">"Stage: " {stage_text}</span>
                                    </div>
                                    <a class="btn btn-secondary" href="/requests">
                                        "Back to list"
                                    </a>
                                </div>

                                <div class="stage-progression" aria-label="Request stage progression">
                                    <h3>"Stage Progression"</h3>
                                    <ol class="stage-stepper">
                                        {["intake", "validated", "planned", "approved", "locked", "executed", "verified"]
                                            .iter()
                                            .map(|stage| {
                                                let is_done = match current_stage.as_str() {
                                                    "intake" => false,
                                                    "validated" => *stage == "intake",
                                                    "planned" => matches!(*stage, "intake" | "validated"),
                                                    "approved" => matches!(*stage, "intake" | "validated" | "planned"),
                                                    "locked" => matches!(*stage, "intake" | "validated" | "planned" | "approved"),
                                                    "executed" => matches!(*stage, "intake" | "validated" | "planned" | "approved" | "locked"),
                                                    "verified" => true,
                                                    "failed" => false,
                                                    _ => false,
                                                };
                                                let step_class = if *stage == current_stage {
                                                    "stage-step active"
                                                } else if is_done {
                                                    "stage-step done"
                                                } else {
                                                    "stage-step pending"
                                                };
                                                let label = stage_label(stage);
                                                view! {
                                                    <li class=step_class>
                                                        <span class="stage-dot" aria-hidden="true"></span>
                                                        <span class="stage-label">{label}</span>
                                                    </li>
                                                }
                                            })
                                            .collect_view()}
                                    </ol>
                                </div>

                                <div class="request-info-grid">
                                    <div class="request-info-item">
                                        <strong>"Site"</strong>
                                        <span>{detail.site.clone()}</span>
                                    </div>
                                    <div class="request-info-item">
                                        <strong>"Environment"</strong>
                                        <span>{detail.environment.clone()}</span>
                                    </div>
                                    <div class="request-info-item">
                                        <strong>"CPU"</strong>
                                        <span>{detail.cpu} " cores"</span>
                                    </div>
                                    <div class="request-info-item">
                                        <strong>"Memory"</strong>
                                        <span>{detail.memory} " GB"</span>
                                    </div>
                                    <div class="request-info-item">
                                        <strong>"Justification"</strong>
                                        <span>{detail.justification.clone()}</span>
                                    </div>
                                    <div class="request-info-item">
                                        <strong>"Created"</strong>
                                        <span>{detail.created.clone()}</span>
                                    </div>
                                    <div class="request-info-item">
                                        <strong>"Updated"</strong>
                                        <span>{detail.updated.clone()}</span>
                                    </div>
                                </div>

                                <div class="request-actions">
                                    <h3>"Actions"</h3>
                                    <Show when=move || !action_feedback.get().is_empty()>
                                        <span class=action_class>{action_feedback}</span>
                                    </Show>
                                    <div class="action-buttons">
                                        {actions
                                            .iter()
                                            .map(|action| {
                                                let label = action_label(action);
                                                let is_approve = action == "approve";
                                                let btn_class = if is_approve { "btn btn-primary" } else { "btn btn-secondary" };
                                                let action = action.clone();
                                                let id = request_id_for_action.clone();
                                                view! {
                                                    <button
                                                        class=btn_class
                                                        on:click=move |_| {
                                                            match action.as_str() {
                                                                "validate" => { validate_action.dispatch(id.clone()); }
                                                                "plan" => { plan_action.dispatch(id.clone()); }
                                                                "approve" => { approve_action.dispatch(id.clone()); }
                                                                "lock" => { lock_action.dispatch(id.clone()); }
                                                                "execute" => { execute_action.dispatch(id.clone()); }
                                                                "verify" => { verify_action.dispatch(id.clone()); }
                                                                _ => {}
                                                            }
                                                        }
                                                    >
                                                        {label}
                                                    </button>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                </div>

                                <div class="request-timeline">
                                    <h3>"Stage Timeline"</h3>
                                    <div class="timeline-list" aria-label="Request stage progression">
                                        {detail.timeline
                                            .into_iter()
                                            .map(|event| {
                                                let stage_text = stage_label(&event.stage);
                                                view! {
                                                    <div class="timeline-item">
                                                        <span class="badge neutral">{stage_text}</span>
                                                        <strong>{event.stage.clone()}</strong>
                                                        <p>{event.description.clone()}</p>
                                                        <span class="table-note">{event.timestamp.clone()}</span>
                                                    </div>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                </div>
                            </article>
                        }
                            .into_any()
                    })
                }}
            </Suspense>
        </div>
    }
}
