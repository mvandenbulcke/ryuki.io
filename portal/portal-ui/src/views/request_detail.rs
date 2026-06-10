use crate::api::{platform_summary_path, request_detail_path, same_origin_api_path};
use crate::models::request_detail_fallback;
use crate::server_boundary::{
    approve_request, execute_request, get_request_detail, lock_request, plan_request,
    validate_request, verify_request,
};
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
pub fn RequestDetail(request_id: String, #[prop(into)] on_back: Callback<()>) -> impl IntoView {
    let detail_path_guard = api_path(request_detail_path());
    let detail_resource = Resource::new(move || request_id.clone(), get_request_detail);

    #[allow(deprecated)]
    let (action_feedback, set_action_feedback) = create_signal(String::new());
    #[allow(deprecated)]
    let (action_class, set_action_class) = create_signal("badge neutral");

    let validate_action = Action::new_unsync(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Validating...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match validate_request(id).await {
                Ok(resp) => {
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if resp.success {
                        "badge good"
                    } else {
                        "badge bad"
                    });
                }
                Err(e) => {
                    set_action_feedback.set(e.to_string());
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let plan_action = Action::new_unsync(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Planning...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match plan_request(id).await {
                Ok(resp) => {
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if resp.success {
                        "badge good"
                    } else {
                        "badge bad"
                    });
                }
                Err(e) => {
                    set_action_feedback.set(e.to_string());
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let approve_action = Action::new_unsync(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Approving...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match approve_request(id).await {
                Ok(resp) => {
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if resp.success {
                        "badge good"
                    } else {
                        "badge bad"
                    });
                }
                Err(e) => {
                    set_action_feedback.set(e.to_string());
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let lock_action = Action::new_unsync(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Locking...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match lock_request(id).await {
                Ok(resp) => {
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if resp.success {
                        "badge good"
                    } else {
                        "badge bad"
                    });
                }
                Err(e) => {
                    set_action_feedback.set(e.to_string());
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let execute_action = Action::new_unsync(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Executing...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match execute_request(id).await {
                Ok(resp) => {
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if resp.success {
                        "badge good"
                    } else {
                        "badge bad"
                    });
                }
                Err(e) => {
                    set_action_feedback.set(e.to_string());
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let verify_action = Action::new_unsync(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Verifying...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match verify_request(id).await {
                Ok(resp) => {
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if resp.success {
                        "badge good"
                    } else {
                        "badge bad"
                    });
                }
                Err(e) => {
                    set_action_feedback.set(e.to_string());
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    view! {
        <div class="request-detail-view">
            <Suspense fallback=move || {
                view! {
                    <div class="request-detail-loading" aria-busy="true" data-api-path=detail_path_guard>
                        <p>"Loading request detail..."</p>
                    </div>
                }
            }>
                {move || {
                    Suspend::new(async move {
                        let detail = match detail_resource.await {
                            Ok(d) => d,
                            Err(_) => request_detail_fallback("error"),
                        };

                        let status_class = status_badge_class(&detail.status);
                        let stage_text = stage_label(&detail.stage);
                        let current_stage = detail.stage.clone();
                        let actions = detail.actions_available.clone();
                        let request_id_for_action = detail.id.clone();

                        view! {
                            <article
                                class="request-detail-panel"
                                aria-label="Request detail"
                                data-api-path=detail_path_guard
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
                                    <button class="btn btn-secondary" on:click=move |_| on_back.run(())>
                                        "Back to list"
                                    </button>
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
