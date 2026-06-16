use crate::api::{platform_summary_path, request_detail_path};
use crate::models::{condense_timestamp, AuthSession, EvidencePackExport};
use crate::server_boundary::{
    approve_live_apply_request, approve_request, cancel_request, execute_request,
    execute_request_live_plan, get_request_audit, get_request_detail, get_request_evidence,
    get_request_execution_job, lock_request, plan_request, reject_request, validate_request,
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
        // run-live-plan is an admin-only synthetic action (real terraform plan,
        // no mutation); only PlatformAdmin / BreakGlassAdmin roles see it.
        "run-live-plan" => "admin",
        // approve-live-apply is an admin-only action: mints a CP-signed
        // LiveApply grant from the request's completed LivePlan.
        "approve-live-apply" => "admin",
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
        // Legacy portal-vocab (DB normalize path) and canonical engine-vocab both accepted.
        "executed" | "verified" | "completed" | "Completed" => "badge good",
        "failed" | "Failed" => "badge bad",
        "rejected" | "cancelled" | "Rejected" | "Cancelled" => "badge bad",
        "executing" | "verifying" | "Executing" | "Verifying" => "badge warn",
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
        // Canonical engine-vocab milestones (used in the stage rail).
        "executing" => "Executing",
        "verifying" => "Verifying",
        "completed" => "Completed",
        // Legacy portal-vocab aliases produced by normalize_api_stage on DB rows.
        // Kept so the audit trail and timeline continue to render correctly for
        // existing persisted requests.
        "executed" => "Executed",
        "verified" => "Verified",
        "failed" => "Failed",
        "rejected" => "Rejected",
        "cancelled" => "Cancelled",
        &_ => "Unknown",
    }
}

/// Whether a (portal-vocabulary) stage is a terminal outcome that the stepper
/// renders with distinct terminal styling rather than forward progression.
/// Includes `"failed"` because a failed request has no active forward step to
/// highlight (the operator retries via a new validate/plan action).
fn is_terminal_stage(stage: &str) -> bool {
    matches!(stage, "failed" | "rejected" | "cancelled")
}

/// The ordered forward milestone sequence for the stage-progression rail.
/// Uses canonical engine-vocab: the same strings produced by
/// `RequestStatus::as_str()` for the executing/verifying/completed phases.
const STAGE_MILESTONES: &[&str] = &[
    "intake",
    "validated",
    "planned",
    "approved",
    "locked",
    "executing",
    "verifying",
    "completed",
];

/// Derives the effective stage for the progression rail from the portal
/// `detail.stage` and `detail.status`, bridging two vocabularies:
///
/// - **DB path**: `stage` column holds an action name (`execute`, `verify`),
///   which `normalize_api_stage` maps to `"executed"` / `"verified"`.
/// - **In-memory (no-DB) path**: the engine `Request` struct has no `stage`
///   field, so `detail.stage` arrives as `""`. The status field then carries
///   the truth (serialized as PascalCase by serde from the engine enum).
///
/// Both are normalized onto the canonical milestone vocab used by
/// `STAGE_MILESTONES` so the rail always lights up the correct step.
pub(crate) fn effective_stage_for_rail(stage: &str, status: &str) -> &'static str {
    match stage {
        // Already canonical forward milestones — return the 'static literal.
        "intake" => "intake",
        "validated" => "validated",
        "planned" => "planned",
        "approved" => "approved",
        "locked" => "locked",
        "executing" => "executing",
        "verifying" => "verifying",
        "completed" => "completed",
        // Terminal states also pass through as 'static literals.
        "failed" => "failed",
        "rejected" => "rejected",
        "cancelled" => "cancelled",
        // Legacy portal-vocab produced by normalize_api_stage on the DB path.
        // Map onto the canonical milestone names so the rail highlights them.
        "executed" => "executing",
        "verified" => "verifying",
        // Empty stage (in-memory / no-DB path): derive from status.
        // Accept both lowercase (DB / as_str()) and PascalCase (serde enum).
        _ => match status {
            "executing" | "Executing" => "executing",
            "verifying" | "Verifying" => "verifying",
            "completed" | "Completed" => "completed",
            "failed" | "Failed" => "failed",
            "rejected" | "Rejected" => "rejected",
            "cancelled" | "Cancelled" => "cancelled",
            "locked" | "Locked" => "locked",
            "approved" | "Approved" => "approved",
            "planned" | "Planned" => "planned",
            "validated" | "Validated" => "validated",
            "intake" | "Intake" => "intake",
            _ => "intake",
        },
    }
}

/// Determines the CSS class for one milestone `step` in the stage-progression
/// rail given the `current` effective stage (in canonical milestone vocab).
///
/// Returns:
/// - `"stage-step active"` — `step` is the current in-progress milestone.
/// - `"stage-step done"` — `step` precedes the current milestone in the forward
///   sequence (all earlier milestones are complete).
/// - `"stage-step pending"` — `step` follows the current milestone (not yet
///   reached).
///
/// Terminal stages (`failed`/`rejected`/`cancelled`) are handled at the call
/// site via `is_terminal_stage`; this function receives only forward milestones.
pub(crate) fn stage_step_state(step: &str, current: &str) -> &'static str {
    let step_pos = STAGE_MILESTONES.iter().position(|&m| m == step);
    let current_pos = STAGE_MILESTONES.iter().position(|&m| m == current);
    match (step_pos, current_pos) {
        (Some(s), Some(c)) if s < c => "stage-step done",
        (Some(s), Some(c)) if s == c => "stage-step active",
        _ => "stage-step pending",
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
        "reject" => "Reject",
        "cancel" => "Cancel",
        "lock" => "Lock",
        "execute" => "Execute",
        "run-live-plan" => "Run live plan",
        "approve-live-apply" => "Approve & apply",
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
    // Execution-agent job for this request (None when not yet dispatched).
    let execution_job_resource = Resource::new(move || request_id.get(), get_request_execution_job);

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

    let run_live_plan_action = Action::new(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Running live plan...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match execute_request_live_plan(id).await {
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

    let approve_live_apply_action = Action::new(move |id: &String| {
        let id = id.clone();
        set_action_feedback.set("Approving & applying...".to_string());
        set_action_class.set("badge neutral");
        async move {
            match approve_live_apply_request(id).await {
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
                        // Execution-agent job — None when not yet dispatched or
                        // in static dry-run mode; errors degrade to None so the
                        // panel renders a "not dispatched" note rather than
                        // blocking the whole detail view.
                        let execution_job = execution_job_resource.await.unwrap_or(None);
                        let synthetic_timeline = detail.timeline.clone();

                        let status_class = status_badge_class(&detail.status);
                        // Derive the effective rail stage from both `stage` and
                        // `status`, bridging the DB (action-name) and in-memory
                        // (empty stage / PascalCase status) vocabularies.
                        let effective_stage =
                            effective_stage_for_rail(&detail.stage, &detail.status).to_string();
                        let stage_text = stage_label(&effective_stage);
                        let current_stage = effective_stage.clone();
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
                        // "Run live plan" is a synthetic admin-only action: shown when
                        // "execute" is available (request is Locked) and the session
                        // holds the "admin" capability (PlatformAdmin / BreakGlassAdmin).
                        let show_live_plan = detail
                            .actions_available
                            .iter()
                            .any(|a| a == "execute")
                            && session_can(&session, "admin");
                        // "Approve & apply" is an admin-only action that mints a
                        // CP-signed LiveApply grant from the request's completed
                        // LivePlan. The API endpoint itself 409s if no live plan
                        // has been completed yet, so we use the same gate as
                        // show_live_plan for portal-side visibility: execute
                        // available (request is Locked) and admin session. The
                        // API enforces state correctness.
                        let show_approve_apply = detail
                            .actions_available
                            .iter()
                            .any(|a| a == "execute")
                            && session_can(&session, "admin");
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
                        // Stages with evidence (terraform-plan on plan stage,
                        // ansible-check on verify stage). Filtered to stages
                        // that actually carry at least one evidence item so the
                        // section is hidden for early-stage or legacy requests
                        // that never ran a runner.
                        let stages_with_evidence: Vec<_> = detail
                            .stages
                            .iter()
                            .filter(|s| !s.evidence.is_empty())
                            .cloned()
                            .collect();
                        let has_stage_evidence = !stages_with_evidence.is_empty();

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
                                        {STAGE_MILESTONES
                                            .iter()
                                            .map(|milestone| {
                                                // A terminal reject/cancel/fail leaves the forward
                                                // steps un-highlighted; the distinct terminal step
                                                // is appended after the forward row.
                                                let step_class = if terminal_stage {
                                                    "stage-step pending"
                                                } else {
                                                    stage_step_state(milestone, &current_stage)
                                                };
                                                let label = stage_label(milestone);
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

                                // Per-stage runner evidence (terraform-plan on
                                // the plan stage, ansible-check on the verify
                                // stage). Hidden for requests that have no
                                // runner evidence (pre-runner or early-stage).
                                // Each item value is rendered in a <pre> so
                                // multi-line plan/check output is readable.
                                // Redacted items show a visual indicator.
                                <Show when=move || has_stage_evidence>
                                    <div class="stage-evidence" aria-label="Stage runner evidence">
                                        <h3>"Stage Evidence"</h3>
                                        {stages_with_evidence
                                            .clone()
                                            .into_iter()
                                            .map(|stage| {
                                                let stage_label_text = stage_label(&stage.name);
                                                let evidence_items = stage.evidence.clone();
                                                view! {
                                                    <div class="stage-evidence-group">
                                                        <h4>{stage_label_text}</h4>
                                                        {evidence_items
                                                            .into_iter()
                                                            .map(|ev| {
                                                                let badge_class = if ev.redacted {
                                                                    "badge bad"
                                                                } else {
                                                                    "badge neutral"
                                                                };
                                                                let redacted_label = if ev.redacted {
                                                                    Some(" (redacted)")
                                                                } else {
                                                                    None
                                                                };
                                                                view! {
                                                                    <div
                                                                        class="stage-evidence-item"
                                                                        aria-label=ev.key.clone()
                                                                    >
                                                                        <div class="evidence-item-header">
                                                                            <code class="evidence-item-key">{ev.key.clone()}</code>
                                                                            <Show when=move || ev.redacted>
                                                                                <span class=badge_class>
                                                                                    {redacted_label}
                                                                                </span>
                                                                            </Show>
                                                                        </div>
                                                                        <pre class="evidence-item-value">{ev.value.clone()}</pre>
                                                                    </div>
                                                                }
                                                            })
                                                            .collect_view()}
                                                    </div>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                </Show>

                                // Execution-agent job dispatched for this request.
                                // Hidden when no job has been dispatched yet.
                                {match execution_job {
                                    Some(job) => {
                                        let result_status_display = if job.result_status.is_empty() {
                                            "—".to_string()
                                        } else {
                                            job.result_status.clone()
                                        };
                                        let digest_display =
                                            if job.evidence_digest_short.is_empty() {
                                                "—".to_string()
                                            } else {
                                                format!("{}…", job.evidence_digest_short)
                                            };
                                        let completed_display = if job.completed_at.is_empty() {
                                            "—".to_string()
                                        } else {
                                            job.completed_at.clone()
                                        };
                                        view! {
                                            <div
                                                class="execution-job-panel"
                                                aria-label="Execution job"
                                            >
                                                <h3>"Execution Job"</h3>
                                                <div class="request-info-grid">
                                                    <div class="request-info-item">
                                                        <strong>"Mode"</strong>
                                                        <span>{job.mode.clone()}</span>
                                                    </div>
                                                    <div class="request-info-item">
                                                        <strong>"Job status"</strong>
                                                        <span>{job.status.clone()}</span>
                                                    </div>
                                                    <div class="request-info-item">
                                                        <strong>"Result"</strong>
                                                        <span>{result_status_display}</span>
                                                    </div>
                                                    <div class="request-info-item">
                                                        <strong>"Evidence digest"</strong>
                                                        <code class="evidence-item-key">
                                                            {digest_display}
                                                        </code>
                                                    </div>
                                                    <div class="request-info-item">
                                                        <strong>"Dispatched"</strong>
                                                        <span>{job.created_at.clone()}</span>
                                                    </div>
                                                    <div class="request-info-item">
                                                        <strong>"Completed"</strong>
                                                        <span>{completed_display}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        }
                                            .into_any()
                                    }
                                    None => view! {
                                        <div
                                            class="execution-job-panel"
                                            aria-label="Execution job"
                                        >
                                            <h3>"Execution Job"</h3>
                                            <p class="table-note">
                                                "No execution job dispatched yet."
                                            </p>
                                        </div>
                                    }
                                        .into_any(),
                                }}

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
                                        // "Run live plan" — admin-only, shown alongside the
                                        // "Execute" button when the request is Locked. Triggers
                                        // a real terraform plan / ansible --check with no
                                        // mutation (POST .../execute?mode=live-plan).
                                        // Clone the id here so `request_id_for_action` remains
                                        // available for subsequent buttons and the reason-panel.
                                        {
                                            let live_plan_id = request_id_for_action.clone();
                                            view! {
                                                <Show when=move || show_live_plan>
                                                    {
                                                        let id = live_plan_id.clone();
                                                        view! {
                                                            <button
                                                                class="btn btn-secondary"
                                                                on:click=move |_| {
                                                                    run_live_plan_action.dispatch(id.clone());
                                                                }
                                                            >
                                                                "Run live plan"
                                                            </button>
                                                        }
                                                    }
                                                </Show>
                                            }
                                        }
                                        // "Approve & apply" — admin-only, shown when the
                                        // request is Locked (same gate as "Run live plan").
                                        // Mints a CP-signed LiveApply grant from the
                                        // request's completed LivePlan. The API 409s if no
                                        // live plan has been completed yet.
                                        {
                                            let approve_apply_id = request_id_for_action.clone();
                                            view! {
                                                <Show when=move || show_approve_apply>
                                                    {
                                                        let id = approve_apply_id.clone();
                                                        view! {
                                                            <button
                                                                class="btn btn-secondary"
                                                                on:click=move |_| {
                                                                    approve_live_apply_action
                                                                        .dispatch(id.clone());
                                                                }
                                                            >
                                                                "Approve & apply"
                                                            </button>
                                                        }
                                                    }
                                                </Show>
                                            }
                                        }
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

#[cfg(test)]
mod tests {
    use super::{action_capability, effective_stage_for_rail, stage_step_state, STAGE_MILESTONES};

    // ── action_capability ───────────────────────────────────────────────────

    #[test]
    fn run_live_plan_requires_admin_capability() {
        assert_eq!(
            action_capability("run-live-plan"),
            "admin",
            "run-live-plan must require the admin capability so only PlatformAdmin \
             and BreakGlassAdmin see the button"
        );
    }

    #[test]
    fn approve_live_apply_requires_admin_capability() {
        assert_eq!(
            action_capability("approve-live-apply"),
            "admin",
            "approve-live-apply must require the admin capability so only PlatformAdmin \
             and BreakGlassAdmin can mint a LiveApply grant"
        );
    }

    #[test]
    fn execute_requires_execute_capability() {
        // Regression guard: execute must NOT require admin (operator-tier mechanics).
        assert_eq!(action_capability("execute"), "execute");
    }

    // ── stage_step_state ────────────────────────────────────────────────────

    #[test]
    fn all_milestones_are_pending_at_intake() {
        // When current = "intake", only "intake" is active; everything else is pending.
        assert_eq!(stage_step_state("intake", "intake"), "stage-step active");
        for &m in STAGE_MILESTONES.iter().skip(1) {
            assert_eq!(
                stage_step_state(m, "intake"),
                "stage-step pending",
                "expected {m} to be pending when current=intake"
            );
        }
    }

    #[test]
    fn validated_marks_intake_done() {
        assert_eq!(stage_step_state("intake", "validated"), "stage-step done");
        assert_eq!(
            stage_step_state("validated", "validated"),
            "stage-step active"
        );
        assert_eq!(
            stage_step_state("planned", "validated"),
            "stage-step pending"
        );
    }

    #[test]
    fn planned_marks_intake_and_validated_done() {
        assert_eq!(stage_step_state("intake", "planned"), "stage-step done");
        assert_eq!(stage_step_state("validated", "planned"), "stage-step done");
        assert_eq!(stage_step_state("planned", "planned"), "stage-step active");
        assert_eq!(
            stage_step_state("approved", "planned"),
            "stage-step pending"
        );
    }

    #[test]
    fn approved_stage_progression() {
        assert_eq!(stage_step_state("intake", "approved"), "stage-step done");
        assert_eq!(stage_step_state("validated", "approved"), "stage-step done");
        assert_eq!(stage_step_state("planned", "approved"), "stage-step done");
        assert_eq!(
            stage_step_state("approved", "approved"),
            "stage-step active"
        );
        assert_eq!(stage_step_state("locked", "approved"), "stage-step pending");
    }

    #[test]
    fn locked_stage_progression() {
        assert_eq!(stage_step_state("intake", "locked"), "stage-step done");
        assert_eq!(stage_step_state("validated", "locked"), "stage-step done");
        assert_eq!(stage_step_state("planned", "locked"), "stage-step done");
        assert_eq!(stage_step_state("approved", "locked"), "stage-step done");
        assert_eq!(stage_step_state("locked", "locked"), "stage-step active");
        assert_eq!(
            stage_step_state("executing", "locked"),
            "stage-step pending"
        );
    }

    /// Regression: execute action → status "verifying" (engine skips "executing").
    /// The rail for stage "executing" must mark locked (and earlier) as done and
    /// show "executing" as active.
    #[test]
    fn executing_marks_locked_done_and_itself_active() {
        assert_eq!(stage_step_state("intake", "executing"), "stage-step done");
        assert_eq!(
            stage_step_state("validated", "executing"),
            "stage-step done"
        );
        assert_eq!(stage_step_state("planned", "executing"), "stage-step done");
        assert_eq!(stage_step_state("approved", "executing"), "stage-step done");
        assert_eq!(stage_step_state("locked", "executing"), "stage-step done");
        assert_eq!(
            stage_step_state("executing", "executing"),
            "stage-step active"
        );
        assert_eq!(
            stage_step_state("verifying", "executing"),
            "stage-step pending"
        );
        assert_eq!(
            stage_step_state("completed", "executing"),
            "stage-step pending"
        );
    }

    #[test]
    fn verifying_stage_progression() {
        assert_eq!(stage_step_state("locked", "verifying"), "stage-step done");
        assert_eq!(
            stage_step_state("executing", "verifying"),
            "stage-step done"
        );
        assert_eq!(
            stage_step_state("verifying", "verifying"),
            "stage-step active"
        );
        assert_eq!(
            stage_step_state("completed", "verifying"),
            "stage-step pending"
        );
    }

    /// Regression: completed request must mark EVERY forward milestone as done
    /// — previously "completed" had no milestone at all and showed nothing.
    #[test]
    fn completed_marks_all_milestones_done() {
        for &m in STAGE_MILESTONES {
            if m == "completed" {
                assert_eq!(
                    stage_step_state(m, "completed"),
                    "stage-step active",
                    "completed milestone should be active when current=completed"
                );
            } else {
                assert_eq!(
                    stage_step_state(m, "completed"),
                    "stage-step done",
                    "expected {m} to be done when current=completed"
                );
            }
        }
    }

    /// Terminal stages (failed/rejected/cancelled) are handled at the call site
    /// via `is_terminal_stage`; stage_step_state returns pending for unknown
    /// milestones so nothing lights up in the forward rail.
    #[test]
    fn terminal_stages_return_pending_for_forward_milestones() {
        for &terminal in &["failed", "rejected", "cancelled"] {
            for &m in STAGE_MILESTONES {
                assert_eq!(
                    stage_step_state(m, terminal),
                    "stage-step pending",
                    "expected {m} to be pending when current={terminal}"
                );
            }
        }
    }

    // ── effective_stage_for_rail ────────────────────────────────────────────

    /// Regression: legacy portal-vocab "executed" (DB normalize path) must map
    /// to canonical "executing" so the rail highlights the correct milestone.
    #[test]
    fn legacy_executed_maps_to_executing() {
        assert_eq!(
            effective_stage_for_rail("executed", "verifying"),
            "executing"
        );
    }

    /// Regression: legacy portal-vocab "verified" (DB normalize path) must map
    /// to canonical "verifying".
    #[test]
    fn legacy_verified_maps_to_verifying() {
        assert_eq!(
            effective_stage_for_rail("verified", "completed"),
            "verifying"
        );
    }

    /// In-memory (no-DB) path: `detail.stage` is empty; effective stage is
    /// derived from the lowercase status string.
    #[test]
    fn empty_stage_derives_from_status_lowercase() {
        assert_eq!(effective_stage_for_rail("", "executing"), "executing");
        assert_eq!(effective_stage_for_rail("", "verifying"), "verifying");
        assert_eq!(effective_stage_for_rail("", "completed"), "completed");
        assert_eq!(effective_stage_for_rail("", "failed"), "failed");
        assert_eq!(effective_stage_for_rail("", "rejected"), "rejected");
        assert_eq!(effective_stage_for_rail("", "cancelled"), "cancelled");
        assert_eq!(effective_stage_for_rail("", "locked"), "locked");
    }

    /// In-memory (no-DB) path: serde serializes the engine `RequestStatus` enum
    /// as PascalCase (no rename_all attribute); effective_stage_for_rail must
    /// handle both cases.
    #[test]
    fn empty_stage_derives_from_status_pascal_case() {
        assert_eq!(effective_stage_for_rail("", "Executing"), "executing");
        assert_eq!(effective_stage_for_rail("", "Verifying"), "verifying");
        assert_eq!(effective_stage_for_rail("", "Completed"), "completed");
        assert_eq!(effective_stage_for_rail("", "Failed"), "failed");
        assert_eq!(effective_stage_for_rail("", "Rejected"), "rejected");
        assert_eq!(effective_stage_for_rail("", "Cancelled"), "cancelled");
    }

    /// Canonical forward stages pass through unchanged.
    #[test]
    fn canonical_stages_pass_through() {
        for &m in STAGE_MILESTONES {
            assert_eq!(
                effective_stage_for_rail(m, "anything"),
                m,
                "canonical stage {m} should pass through unchanged"
            );
        }
    }
}
