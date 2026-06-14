use crate::api::{platform_summary_path, request_detail_path};
use crate::models::{condense_timestamp, AuthSession, EvidencePackExport};
use crate::server_boundary::{
    approve_request, cancel_request, execute_request, get_request_audit, get_request_detail,
    get_request_evidence, lock_request, plan_request, reject_request, validate_request,
    verify_request,
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
        // approve and its inverse (reject) are the approver's decision.
        "approve" | "reject" => "approve",
        // cancel is a requester/admin act (withdraw the request).
        "cancel" => "request",
        // validate, plan, lock, execute, verify are operator-tier mechanics.
        _ => "execute",
    }
}

/// Reason-bearing decisions (reject/cancel) require a free-text reason and a
/// confirm step, unlike the bodyless forward-stage actions.
fn action_requires_reason(action: &str) -> bool {
    matches!(action, "reject" | "cancel")
}

pub(crate) fn status_badge_class(status: &str) -> &'static str {
    match status {
        "intake" => "badge neutral",
        "validated" => "badge good",
        "approved" => "badge good",
        "executed" | "verified" | "completed" => "badge good",
        "failed" => "badge bad",
        "rejected" | "cancelled" => "badge bad",
        "executing" | "verifying" => "badge warn",
        _ => "badge neutral",
    }
}

pub(crate) fn stage_label(stage: &str) -> &'static str {
    match stage {
        "intake" => "Intake",
        "validated" => "Validated",
        "planned" => "Planned",
        "approved" => "Approved",
        "locked" => "Locked",
        "executed" => "Executed",
        "verified" => "Verified",
        "completed" => "Completed",
        "failed" => "Failed",
        "rejected" => "Rejected",
        "cancelled" => "Cancelled",
        &_ => "Unknown",
    }
}

/// Whether a (portal-vocabulary) stage is a terminal "negative" outcome that
/// the stepper renders with a distinct terminal styling rather than the
/// normal forward progression.
fn is_terminal_stage(stage: &str) -> bool {
    matches!(stage, "rejected" | "cancelled")
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
        "reject" => "Reject",
        "cancel" => "Cancel",
        "lock" => "Lock",
        "execute" => "Execute",
        "verify" => "Verify",
        &_ => "Unknown",
    }
}

/// Button class for a lifecycle action: approve is the primary affirmative,
/// reject is destructive (danger), everything else is secondary.
fn action_button_class(action: &str) -> &'static str {
    match action {
        "approve" => "btn btn-primary",
        "reject" => "btn btn-danger",
        _ => "btn btn-secondary",
    }
}

/// Human-readable label for an audit action key (`request.reject`, etc.).
pub(crate) fn audit_action_label(action: &str) -> &'static str {
    match action {
        "request.create" => "Created",
        "request.validate" => "Validated",
        "request.plan" => "Planned",
        "request.approve" => "Approved",
        "request.reject" => "Rejected",
        "request.cancel" => "Cancelled",
        "request.lock" => "Locked",
        "request.execute" => "Executed",
        "request.verify" => "Verified",
        _ => "Updated",
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
    // The real, persisted audit trail is fetched separately and refetched
    // after every successful transition so the timeline stays live.
    let audit_resource = Resource::new(move || request_id.get(), get_request_audit);

    #[allow(deprecated)]
    let (action_feedback, set_action_feedback) = create_signal(String::new());
    #[allow(deprecated)]
    let (action_class, set_action_class) = create_signal("badge neutral");
    // The reason-bearing decision (reject/cancel) the user is confirming, plus
    // its free-text reason. `None` means no confirm panel is open.
    #[allow(deprecated)]
    let (pending_reason_action, set_pending_reason_action) = create_signal::<Option<String>>(None);
    #[allow(deprecated)]
    let (reason_text, set_reason_text) = create_signal(String::new());
    #[allow(deprecated)]
    let (reason_error, set_reason_error) = create_signal(String::new());

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
                        audit_resource.refetch();
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
                        audit_resource.refetch();
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
                        audit_resource.refetch();
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
                        audit_resource.refetch();
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
                        audit_resource.refetch();
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
                        audit_resource.refetch();
                    }
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    // Reject and cancel carry a mandatory reason; the action input is the
    // (id, reason) pair captured from the confirm panel. On success they close
    // the panel and refetch both the detail and the persisted audit trail.
    let reject_action = Action::new(move |args: &(String, String)| {
        let (id, reason) = args.clone();
        set_action_feedback.set("Rejecting...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match reject_request(id, reason).await {
                Ok(resp) => {
                    let succeeded = resp.success;
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if succeeded { "badge good" } else { "badge bad" });
                    if succeeded {
                        set_pending_reason_action.set(None);
                        set_reason_text.set(String::new());
                        set_reason_error.set(String::new());
                        detail_resource.refetch();
                        audit_resource.refetch();
                    }
                }
                Err(e) => {
                    set_action_feedback.set(server_error_message(&e));
                    set_action_class.set("badge bad");
                }
            }
        }
    });

    let cancel_action = Action::new(move |args: &(String, String)| {
        let (id, reason) = args.clone();
        set_action_feedback.set("Cancelling...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match cancel_request(id, reason).await {
                Ok(resp) => {
                    let succeeded = resp.success;
                    set_action_feedback.set(resp.message);
                    set_action_class.set(if succeeded { "badge good" } else { "badge bad" });
                    if succeeded {
                        set_pending_reason_action.set(None);
                        set_reason_text.set(String::new());
                        set_reason_error.set(String::new());
                        detail_resource.refetch();
                        audit_resource.refetch();
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

                        // The real, persisted audit trail. On a fetch failure
                        // (live API unreachable, or audit permission denied)
                        // fall back to the clearly-labeled synthetic single
                        // entry carried on the detail so the panel still renders.
                        let audit_rows = audit_resource.await.unwrap_or_default();
                        let synthetic_timeline = detail.timeline.clone();

                        let status_class = status_badge_class(&detail.status);
                        let stage_text = stage_label(&detail.stage);
                        let current_stage = detail.stage.clone();
                        let terminal_stage = is_terminal_stage(&current_stage);
                        let terminal_label = stage_label(&current_stage);
                        // Gate each stage-available action on its capability,
                        // using the same action->permission map as the engine.
                        let actions: Vec<String> = detail
                            .actions_available
                            .iter()
                            .filter(|action| session_can(&session, action_capability(action)))
                            .cloned()
                            .collect();
                        let request_id_for_action = detail.id.clone();

                        // Persisted-state fields surfaced in the detail panel.
                        // CPU/memory are only meaningful for VM-shaped types;
                        // non-VM types report 0 and render their real fields
                        // through the per-type payload section instead.
                        let has_compute = detail.cpu > 0 || detail.memory > 0;
                        let criticality = detail.criticality.clone();
                        let requester = detail.requester.clone();
                        let owner = detail.owner.clone();
                        let plan = detail.plan.clone();
                        let approval_route = detail.approval_route.clone();
                        let payload_fields = detail.payload_fields.clone();
                        // `Show when=` closures need Copy predicates, so the
                        // emptiness checks are hoisted to bools the closures
                        // capture by value (the data itself is cloned into the
                        // bodies below).
                        let has_criticality = !criticality.is_empty();
                        let has_requester = !requester.is_empty();
                        let has_owner = !owner.is_empty();
                        let has_plan = !plan.is_empty();
                        let has_approval_route = !approval_route.is_empty();
                        let has_payload = !payload_fields.is_empty();

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
                                                // A terminal reject/cancel leaves the forward steps
                                                // un-highlighted (none is the active step); the
                                                // distinct terminal step is appended after the row.
                                                let step_class = if !terminal_stage && *stage == current_stage {
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
                                        <Show when=move || terminal_stage>
                                            <li class="stage-step terminal">
                                                <span class="stage-dot" aria-hidden="true"></span>
                                                <span class="stage-label">{terminal_label}</span>
                                            </li>
                                        </Show>
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
                                    // CPU/Memory are VM-shaped scalars; render
                                    // them only when present (non-zero). Non-VM
                                    // request types surface their real fields
                                    // through the per-type payload section
                                    // below instead of showing "0 cores".
                                    <Show when=move || has_compute>
                                        <div class="request-info-item">
                                            <strong>"CPU"</strong>
                                            <span>{detail.cpu} " cores"</span>
                                        </div>
                                        <div class="request-info-item">
                                            <strong>"Memory"</strong>
                                            <span>{detail.memory} " GB"</span>
                                        </div>
                                    </Show>
                                    <Show when=move || has_criticality>
                                        <div class="request-info-item">
                                            <strong>"Criticality"</strong>
                                            <span>{criticality.clone()}</span>
                                        </div>
                                    </Show>
                                    <Show when=move || has_requester>
                                        <div class="request-info-item">
                                            <strong>"Requester"</strong>
                                            <span>{requester.clone()}</span>
                                        </div>
                                    </Show>
                                    <Show when=move || has_owner>
                                        <div class="request-info-item">
                                            <strong>"Owner"</strong>
                                            <span>{owner.clone()}</span>
                                        </div>
                                    </Show>
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

                                // Per-type request payload (the ~14 non-VM
                                // request shapes). Rendered generically so each
                                // type surfaces its real fields rather than
                                // assuming the VM cpu/memory shape.
                                <Show when=move || has_payload>
                                    <div class="request-payload" aria-label="Request details">
                                        <h3>"Request Details"</h3>
                                        <div class="request-info-grid">
                                            {payload_fields
                                                .clone()
                                                .into_iter()
                                                .map(|field| {
                                                    view! {
                                                        <div class="request-info-item">
                                                            <strong>{field.label}</strong>
                                                            <span>{field.value}</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    </div>
                                </Show>

                                // The real, persisted dry-run plan (replaces
                                // the old fabricated "DRY-RUN: Planned
                                // execution..." string). Hidden until a plan
                                // has actually been generated.
                                <Show when=move || has_plan>
                                    <div class="request-plan" aria-label="Dry-run plan">
                                        <h3>"Dry-Run Plan"</h3>
                                        <pre class="plan-text">{plan.clone()}</pre>
                                    </div>
                                </Show>

                                // The persisted approval route (ordered).
                                <Show when=move || has_approval_route>
                                    <div class="request-approval-route" aria-label="Approval route">
                                        <h3>"Approval Route"</h3>
                                        <ol class="approval-route-list">
                                            {approval_route
                                                .clone()
                                                .into_iter()
                                                .map(|step| view! { <li>{step}</li> })
                                                .collect_view()}
                                        </ol>
                                    </div>
                                </Show>

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
                                                let btn_class = action_button_class(action);
                                                let needs_reason = action_requires_reason(action);
                                                let action = action.clone();
                                                let id = request_id_for_action.clone();
                                                view! {
                                                    <button
                                                        class=btn_class
                                                        on:click=move |_| {
                                                            // Reason-bearing decisions open the confirm
                                                            // panel instead of dispatching immediately;
                                                            // the bodyless forward actions dispatch now.
                                                            if needs_reason {
                                                                set_reason_text.set(String::new());
                                                                set_reason_error.set(String::new());
                                                                set_pending_reason_action.set(Some(action.clone()));
                                                                return;
                                                            }
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
                                    <Show when=move || pending_reason_action.get().is_some()>
                                        {
                                            let id = request_id_for_action.clone();
                                            // The action being confirmed drives the heading, the
                                            // submit dispatch, and which engine fn runs.
                                            let pending = pending_reason_action.get().unwrap_or_default();
                                            let pending_label = action_label(&pending);
                                            let submit_pending = pending.clone();
                                            let submit_id = id.clone();
                                            view! {
                                                <div class="reason-panel" role="group" aria-label="Decision reason">
                                                    <label class="form-field">
                                                        <span>{pending_label} " reason (required)"</span>
                                                        <textarea
                                                            prop:value=move || reason_text.get()
                                                            on:input=move |ev| {
                                                                set_reason_text.set(event_target_value(&ev));
                                                            }
                                                            placeholder="Explain why this request is being rejected or cancelled"
                                                        ></textarea>
                                                    </label>
                                                    <Show when=move || !reason_error.get().is_empty()>
                                                        <span class="form-error" role="alert">{reason_error}</span>
                                                    </Show>
                                                    <div class="reason-actions">
                                                        <button
                                                            class="btn btn-danger"
                                                            on:click=move |_| {
                                                                let reason = reason_text.get();
                                                                if reason.trim().is_empty() {
                                                                    set_reason_error.set(
                                                                        "A reason is required.".to_string(),
                                                                    );
                                                                    return;
                                                                }
                                                                set_reason_error.set(String::new());
                                                                let args = (submit_id.clone(), reason);
                                                                match submit_pending.as_str() {
                                                                    "reject" => { reject_action.dispatch(args); }
                                                                    "cancel" => { cancel_action.dispatch(args); }
                                                                    _ => {}
                                                                }
                                                            }
                                                        >
                                                            "Confirm " {pending_label}
                                                        </button>
                                                        <button
                                                            class="btn btn-secondary"
                                                            on:click=move |_| {
                                                                set_pending_reason_action.set(None);
                                                                set_reason_text.set(String::new());
                                                                set_reason_error.set(String::new());
                                                            }
                                                        >
                                                            "Cancel"
                                                        </button>
                                                    </div>
                                                </div>
                                            }
                                        }
                                    </Show>
                                </div>

                                <div class="request-timeline">
                                    <h3>"Audit Trail"</h3>
                                    {if audit_rows.is_empty() {
                                        // SSR / unreachable / empty-trail fallback: the
                                        // clearly-labeled synthetic single entry.
                                        view! {
                                            <div class="timeline-list" aria-label="Request audit trail">
                                                <p class="table-note">
                                                    "Persisted audit trail unavailable — showing current lifecycle stage only."
                                                </p>
                                                {synthetic_timeline
                                                    .into_iter()
                                                    .map(|event| {
                                                        let stage_text = stage_label(&event.stage);
                                                        view! {
                                                            <div class="timeline-item">
                                                                <span class="badge neutral">{stage_text}</span>
                                                                <strong>{event.stage.clone()}</strong>
                                                                <p>{event.description.clone()}</p>
                                                                <span class="table-note">{condense_timestamp(&event.timestamp)}</span>
                                                            </div>
                                                        }
                                                    })
                                                    .collect_view()}
                                            </div>
                                        }
                                            .into_any()
                                    } else {
                                        let any_non_durable = audit_rows.iter().any(|row| !row.durable);
                                        view! {
                                            <div class="timeline-list" aria-label="Request audit trail">
                                                <Show when=move || any_non_durable>
                                                    <p class="table-note">
                                                        "Preview trail — entries are not durably persisted in this mode."
                                                    </p>
                                                </Show>
                                                {audit_rows
                                                    .into_iter()
                                                    .map(|row| {
                                                        let action_text = audit_action_label(&row.action);
                                                        let is_negative = matches!(
                                                            row.action.as_str(),
                                                            "request.reject" | "request.cancel",
                                                        );
                                                        let badge_class = if is_negative {
                                                            "badge bad"
                                                        } else {
                                                            "badge neutral"
                                                        };
                                                        let item_class = if is_negative {
                                                            "timeline-item terminal"
                                                        } else {
                                                            "timeline-item"
                                                        };
                                                        // Actor: prefer the display name, falling back
                                                        // to the verified principal.
                                                        let actor = if row.actor_display.is_empty() {
                                                            row.actor_principal.clone()
                                                        } else {
                                                            row.actor_display.clone()
                                                        };
                                                        let from_stage = row
                                                            .from_stage
                                                            .clone()
                                                            .filter(|stage| !stage.is_empty());
                                                        let transition = match from_stage {
                                                            Some(from) => format!(
                                                                "{} → {}",
                                                                stage_label(&crate::models::normalize_api_stage(&from)),
                                                                stage_label(&crate::models::normalize_api_stage(&row.to_stage)),
                                                            ),
                                                            None => stage_label(
                                                                &crate::models::normalize_api_stage(&row.to_stage),
                                                            )
                                                                .to_string(),
                                                        };
                                                        let reason = row.reason.clone();
                                                        view! {
                                                            <div class=item_class>
                                                                <span class=badge_class>{action_text}</span>
                                                                <strong>{actor}</strong>
                                                                <p>{transition}</p>
                                                                {reason
                                                                    .map(|reason| {
                                                                        view! {
                                                                            <p class="timeline-reason">
                                                                                "Reason: " {reason}
                                                                            </p>
                                                                        }
                                                                    })}
                                                                <span class="table-note">{condense_timestamp(&row.occurred_at)}</span>
                                                            </div>
                                                        }
                                                    })
                                                    .collect_view()}
                                            </div>
                                        }
                                            .into_any()
                                    }}
                                </div>
                            </article>
                        }
                            .into_any()
                    })
                }}
            </Suspense>
            <RequestEvidencePanel/>
        </div>
    }
}

/// Renders a loaded, digest-sealed compliance evidence pack: the tamper-evident
/// seal, its metadata, the redacted evidence items, and a JSON export.
fn render_evidence_pack(pack: EvidencePackExport) -> impl IntoView {
    let seal_badge = if pack.durable {
        view! { <span class="badge good">"Sealed · durable"</span> }.into_any()
    } else {
        view! { <span class="badge warn">"Preview · not sealed"</span> }.into_any()
    };
    let redaction_badge = if pack.redacted {
        view! { <span class="badge good">"Redacted"</span> }.into_any()
    } else {
        view! { <span class="badge warn">"Unredacted"</span> }.into_any()
    };
    let digest = pack.digest.clone();
    let algorithm = pack.algorithm.to_uppercase();
    let generated_at = pack.generated_at.clone();
    let item_count = pack.item_count;
    let audit_count = pack.audit_count;
    let pack_json = pack.pack_json.clone();
    let items = pack.items.clone();

    view! {
        <article class="workspace-detail-panel evidence-panel-card" aria-labelledby="evidence-panel-title">
            <div class="workspace-detail-head">
                <div>
                    <span class="eyebrow">"Compliance"</span>
                    <h2 id="evidence-panel-title">"Evidence pack"</h2>
                </div>
                {seal_badge}
            </div>
            <p class="workspace-detail-lede">
                "A tamper-evident export of this request's redacted evidence and its durable audit trail. The seal below is reproducible: re-exporting an unchanged request yields the same digest."
            </p>
            <div class="evidence-seal" aria-label="Evidence pack digest">
                <span class="evidence-seal-label">{algorithm} " digest"</span>
                <code class="evidence-seal-digest">{digest}</code>
            </div>
            <div class="evidence-meta">
                <span class="table-note">"Generated " {generated_at}</span>
                <span class="table-note">{item_count} " evidence items"</span>
                <span class="table-note">{audit_count} " audit entries"</span>
                {redaction_badge}
            </div>
            <div class="timeline-list" aria-label="Evidence items">
                {items
                    .into_iter()
                    .map(|item| {
                        let type_label = item.evidence_type.clone();
                        let redacted = item.redacted;
                        view! {
                            <div class="timeline-item">
                                <div class="timeline-row-head">
                                    <span class="badge neutral">{type_label}</span>
                                    {redacted
                                        .then(|| view! { <span class="badge warn">"redacted"</span> })}
                                </div>
                                <strong>{item.key.clone()}</strong>
                                <p>{item.value.clone()}</p>
                            </div>
                        }
                    })
                    .collect_view()}
            </div>
            <details class="evidence-export">
                <summary>"Export pack (JSON)"</summary>
                <pre class="evidence-json">{pack_json}</pre>
            </details>
        </article>
    }
}

/// `/requests/:id` compliance evidence — a digest-sealed, redacted pack bundling
/// the request's evidence and its durable audit trail. Audit-grade data, so the
/// panel is shown only to `audit`-capable sessions; others never see it.
#[component]
fn RequestEvidencePanel() -> impl IntoView {
    let params = use_params_map();
    let request_id = Memo::new(move |_| params.read().get("id").unwrap_or_default());
    let session = use_context::<AuthSession>().unwrap_or_else(no_capability_session);
    if !session_can(&session, "audit") {
        return ().into_any();
    }
    let evidence_resource = Resource::new(move || request_id.get(), get_request_evidence);

    view! {
        <section class="evidence-panel" aria-label="Compliance evidence pack">
            <Suspense fallback=|| {
                view! {
                    <article
                        class="workspace-detail-panel evidence-panel-card"
                        aria-labelledby="evidence-panel-title"
                        aria-busy="true"
                    >
                        <div class="workspace-detail-head">
                            <div>
                                <span class="eyebrow">"Compliance"</span>
                                <h2 id="evidence-panel-title">"Evidence pack"</h2>
                            </div>
                            <span class="badge neutral">"Sealing…"</span>
                        </div>
                    </article>
                }
            }>
                {move || {
                    Suspend::new(async move {
                        match evidence_resource.await {
                            Ok(pack) => render_evidence_pack(pack).into_any(),
                            Err(_) => {
                                view! {
                                    <article
                                        class="workspace-detail-panel evidence-panel-card"
                                        aria-labelledby="evidence-panel-title"
                                    >
                                        <div class="workspace-detail-head">
                                            <div>
                                                <span class="eyebrow">"Compliance"</span>
                                                <h2 id="evidence-panel-title">"Evidence pack"</h2>
                                            </div>
                                            <span class="badge bad">"Unavailable"</span>
                                        </div>
                                        <div class="empty-state" role="status">
                                            <p class="empty-state-title">"Evidence pack unavailable"</p>
                                            <p class="table-note">
                                                "The platform API is unreachable, so a sealed evidence pack cannot be generated. No unsealed or stale pack is shown."
                                            </p>
                                        </div>
                                    </article>
                                }
                                    .into_any()
                            }
                        }
                    })
                }}
            </Suspense>
        </section>
    }
    .into_any()
}
