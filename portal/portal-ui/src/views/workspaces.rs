use crate::api::same_origin_api_path;
use crate::api::{
    activity_operation_queue_path, admin_platform_settings_path, admin_rbac_roles_path,
    admin_sessions_path, admin_tokens_path, approval_decision_readiness_path, auth_status_path,
    boundary_status_path, catalog_offerings_path, catalog_recommendations_path,
    catalog_request_form_path, emergency_change_path, evidence_export_retention_path,
    operations_platform_health_path, operations_runbook_launch_path, platform_health_path,
    platform_status_path, platform_summary_path, request_intake_form_preview_path,
    shift_queue_path, site_catalog_path,
};
use crate::api_client::{
    cmdb_file_exchange_resource, cmdb_reconciliation_resource, cmdb_relationship_graph_resource,
    evidence_summary_resource, operation_runs_resource, policy_outcomes_resource,
    secret_references_resource, ApiResource,
};
use crate::models::{
    audit_gate_fallbacks, audit_workflow_fallbacks, auth_session_fallback,
    catalog_contract_fallbacks, catalog_readiness_fallbacks, condense_timestamp,
    normalize_api_stage, operation_run_fallbacks, platform_settings_summary_fallback,
    rbac_role_summary_fallbacks, request_intake_form_fallback, AdminSessionSummary,
    AdminTokenSummary, AuditEventRow, AuthSession, CreateTokenPayload, PlatformSettingsSummary,
    ALL_APP_ROLES,
};
use crate::server_boundary::{
    create_admin_token, get_activity_audit_feed, get_admin_platform_settings, get_auth_session,
    get_boundary_status, get_platform_health, get_platform_status, load_admin_sessions,
    load_admin_tokens, load_portal_activity_run_state, load_portal_evidence_summary_status,
    load_portal_inventory_capacity_status, reset_platform_settings, revoke_admin_session,
    revoke_admin_token, save_platform_settings, PortalActivityRunStateSnapshot,
    PortalCmdbWorkspaceSnapshot, PortalEvidenceSummarySnapshot, PortalInventoryCapacitySnapshot,
    PortalPolicyGuardrailsSnapshot, PortalRouteStateSnapshot, PortalSecretReferenceSnapshot,
    PortalServerBoundary,
};
use crate::views::dashboard::DashboardView;
use crate::views::request_create::RequestCreate;
use crate::views::request_detail::RequestDetail;
use crate::views::request_detail::{audit_action_label, stage_label};
use crate::views::requests::RequestList;
use crate::workspace_catalog::{role_satisfies, session_can, PRIMARY_WORKSPACES};
use leptos::prelude::*;

fn api_path(path: &'static str) -> &'static str {
    same_origin_api_path(path).unwrap_or(platform_summary_path())
}

fn resource_api_path<T>(resource: ApiResource<T>) -> &'static str {
    resource
        .same_origin_path()
        .unwrap_or(platform_summary_path())
}

/// Workspace summary cards from the typed registry. The dashboard renders
/// the full role-filtered grid as the workspace overview; each routed
/// workspace renders only its own card via `only`.
#[component]
fn WorkspaceSummaryCards(#[prop(optional)] only: Option<&'static str>) -> impl IntoView {
    // Real session roles arrive through context from the auth gate; the
    // labeled synthetic fallback only covers out-of-gate renders.
    let auth_session = use_context::<AuthSession>().unwrap_or_else(auth_session_fallback);

    // On an individual workspace tab a single summary card renders; the
    // multi-column grid would leave it half-width with an empty cell beside it,
    // so solo mode lays it out as a full-width header matching the detail panel
    // below. The dashboard (no `only`) keeps the multi-column card grid.
    let section_class = if only.is_some() {
        "workspace-sections workspace-sections--solo"
    } else {
        "workspace-sections"
    };

    view! {
        <section class=section_class aria-label="Primary workspaces">
            {PRIMARY_WORKSPACES
                .iter()
                .filter(move |workspace| {
                    only.is_none_or(|id| workspace.id == id)
                        && role_satisfies(&auth_session, workspace.required_role)
                })
                .map(|workspace| {
                    let primary_api_path = api_path((workspace.primary_api_path)());
                    let secondary_api_path = api_path((workspace.secondary_api_path)());
                    let open_label = format!("Open {}", workspace.title);

                    view! {
                        <article
                            class="workspace-panel"
                            data-workspace-id=workspace.id
                            data-api-path=primary_api_path
                            data-secondary-path=secondary_api_path
                            data-api-boundary=workspace.api_boundary
                            data-execution-mode=workspace.execution_mode
                        >
                            <div class="workspace-panel-head">
                                <span class="eyebrow">{workspace.label}</span>
                                <h2>{workspace.title}</h2>
                                <span class=workspace.badge_class>{workspace.badge}</span>
                            </div>
                            <p>{workspace.description}</p>
                            <ul class="workspace-points">
                                {workspace.points
                                    .iter()
                                    .map(|point| view! { <li>{*point}</li> })
                                    .collect_view()}
                            </ul>
                            {(only.is_none())
                                .then(|| {
                                    view! {
                                        <a
                                            class="workspace-open-link"
                                            href=workspace.href
                                            aria-label=open_label
                                        >
                                            "Open workspace"
                                        </a>
                                    }
                                })}
                        </article>
                    }
                })
                .collect_view()}
        </section>
    }
}

/// `/` — hero, dashboard summaries, and the workspace overview cards.
#[component]
pub fn DashboardWorkspaceView() -> impl IntoView {
    // The route-state snapshot arrives through context from the shell
    // layout; the static constructor only covers out-of-shell renders.
    let route_snapshot = use_context::<PortalRouteStateSnapshot>().unwrap_or_else(|| {
        PortalRouteStateSnapshot::static_dry_run()
            .expect("static portal route state snapshot must build")
    });
    let activity_href = route_snapshot.activity_route.clone();
    let activity_action_label = route_snapshot.activity_action_label.clone();

    view! {
        <section class="hero" aria-labelledby="dashboard-title">
            <div>
                <span class="eyebrow">"Dashboard"</span>
                <h1 id="dashboard-title">"Operational control plane"</h1>
                <p>
                    "Safe summaries for platform health, readiness, protected workloads, monitoring coverage, and blocked execution."
                </p>
            </div>
            <a class="primary-action" href=activity_href>{activity_action_label}</a>
        </section>

        <DashboardView/>
        <div class="workspace-area">
            <WorkspaceSummaryCards/>
        </div>
    }
}

/// `/catalog` — catalog readiness and the request-intake preview.
#[component]
pub fn CatalogWorkspaceView() -> impl IntoView {
    view! {
        <div class="workspace-area">
            <WorkspaceSummaryCards only="catalog"/>
            <section class="workspace-detail-grid" aria-label="Catalog workspace details">
                <CatalogWorkspaceDetail/>
                <RequestIntakePreview/>
            </section>
        </div>
    }
}

/// `/requests` — the request list; rows deep-link to `/requests/:id`.
#[component]
pub fn RequestsWorkspaceView() -> impl IntoView {
    view! {
        <div class="workspace-area">
            <WorkspaceSummaryCards only="requests"/>
            <section class="workspace-detail-grid" aria-label="Request workspace details">
                <RequestList/>
            </section>
        </div>
    }
}

/// `/requests/new` — the request intake form.
#[component]
pub fn RequestNewWorkspaceView() -> impl IntoView {
    view! {
        <div class="workspace-area">
            <section class="workspace-detail-grid" aria-label="New request form">
                <RequestCreate/>
            </section>
        </div>
    }
}

/// `/requests/:id` — one request's detail and lifecycle actions.
#[component]
pub fn RequestDetailWorkspaceView() -> impl IntoView {
    view! {
        <div class="workspace-area">
            <section class="workspace-detail-grid" aria-label="Request detail">
                <RequestDetail/>
            </section>
        </div>
    }
}

/// `/activity` — the durable governance audit feed (who-did-what-when across
/// every request), plus queue, run-state, and handover summaries.
#[component]
pub fn ActivityWorkspaceView() -> impl IntoView {
    view! {
        <div class="workspace-area">
            <WorkspaceSummaryCards only="activity"/>
            <section class="workspace-detail-grid" aria-label="Governance activity feed">
                <GovernanceActivityFeed/>
            </section>
            <section class="workspace-detail-grid" aria-label="Activity workspace details">
                <ActivityWorkspaceDetail/>
            </section>
        </div>
    }
}

/// `/inventory` — freshness, coverage, and capacity admission summaries.
#[component]
pub fn InventoryWorkspaceView() -> impl IntoView {
    view! {
        <div class="workspace-area">
            <WorkspaceSummaryCards only="inventory"/>
            <section class="workspace-detail-grid" aria-label="Inventory workspace details">
                <InventoryWorkspaceDetail/>
            </section>
        </div>
    }
}

/// `/cmdb` — file exchange, reconciliation, and relationship summaries.
#[component]
pub fn CmdbWorkspaceView() -> impl IntoView {
    view! {
        <div class="workspace-area">
            <WorkspaceSummaryCards only="cmdb"/>
            <section class="workspace-detail-grid" aria-label="CMDB workspace details">
                <CmdbWorkspaceDetail/>
            </section>
        </div>
    }
}

/// `/evidence` — redaction, export, and retention readiness.
#[component]
pub fn EvidenceWorkspaceView() -> impl IntoView {
    view! {
        <div class="workspace-area">
            <WorkspaceSummaryCards only="evidence"/>
            <section class="workspace-detail-grid" aria-label="Evidence workspace details">
                <EvidenceWorkspaceDetail/>
            </section>
        </div>
    }
}

/// `/operations` — run state, platform health, and policy guardrails.
#[component]
pub fn OperationsWorkspaceView() -> impl IntoView {
    view! {
        <div class="workspace-area">
            <WorkspaceSummaryCards only="operations"/>
            <section class="workspace-detail-grid" aria-label="Operations workspace details">
                <OperationsWorkspaceDetail/>
                <PolicyWorkspaceDetail/>
            </section>
        </div>
    }
}

/// `/admin` — platform settings, security posture, secret references, and
/// (for `admin`-capability sessions) token + session administration.
#[component]
pub fn AdminWorkspaceView() -> impl IntoView {
    // The admin workspace card is already role-gated to PlatformAdmin via the
    // catalog; the token/session panels are gated again on the `admin`
    // capability so non-admins never see them even if the route is reached.
    let auth_session = use_context::<AuthSession>().unwrap_or_else(auth_session_fallback);
    let is_admin = session_can(&auth_session, "admin");

    view! {
        <div class="workspace-area">
            <WorkspaceSummaryCards only="admin"/>
            <section class="workspace-detail-grid" aria-label="Admin workspace details">
                <AdminSettingsDetail/>
                <SecurityWorkspaceDetail/>
                <SecretReferenceWorkspaceDetail/>
                <Show when=move || is_admin fallback=|| ()>
                    <TokenAdministrationDetail/>
                    <SessionAdministrationDetail/>
                </Show>
            </section>
        </div>
    }
}

#[component]
fn CatalogWorkspaceDetail() -> impl IntoView {
    let catalog_api_path = api_path(catalog_offerings_path());
    let recommendations_api_path = api_path(catalog_recommendations_path());
    let request_form_api_path = api_path(catalog_request_form_path());
    let site_catalog_api_path = api_path(site_catalog_path());
    let contracts = catalog_contract_fallbacks();
    let readiness = catalog_readiness_fallbacks();

    view! {
        <article
            class="workspace-detail-panel"
            aria-labelledby="catalog-workspace-detail-title"
            data-api-path=catalog_api_path
            data-recommendations-path=recommendations_api_path
            data-form-path=request_form_api_path
            data-readiness-path=site_catalog_api_path
        >
            <div class="workspace-detail-head">
                <div>
                    <span class="eyebrow">"Catalog"</span>
                    <h2 id="catalog-workspace-detail-title">"Catalog workspace detail"</h2>
                </div>
                <span class="badge neutral">"Static catalog source"</span>
            </div>
            <div class="workspace-detail-columns">
                <div class="workspace-detail-list" aria-label="Catalog contract readiness">
                    {contracts
                        .into_iter()
                        .map(|contract| {
                            view! {
                                <div class="workspace-detail-item">
                                    <span class="badge neutral">{contract.readiness_state}</span>
                                    <strong>{contract.category}</strong>
                                    <p>{contract.safe_summary}</p>
                                    <span class="table-note">{contract.request_form_state} " / " {contract.recommendation_state}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
                <div class="workspace-detail-list" aria-label="Catalog governance readiness">
                    {readiness
                        .into_iter()
                        .map(|item| {
                            view! {
                                <div class="workspace-detail-item">
                                    <span class="badge warn">{item.readiness_state}</span>
                                    <strong>{item.surface}</strong>
                                    <p>{item.safe_summary}</p>
                                    <span class="table-note">{item.site_binding_state}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </div>
        </article>
    }
}

#[component]
fn RequestIntakePreview() -> impl IntoView {
    let form = request_intake_form_fallback();
    let form_api_path = api_path(request_intake_form_preview_path());

    view! {
        <article
            class="workspace-detail-panel"
            aria-labelledby="request-intake-preview-title"
            data-api-path=form_api_path
        >
            <div class="workspace-detail-head">
                <div>
                    <span class="eyebrow">"Catalog"</span>
                    <h2 id="request-intake-preview-title">"Request Intake (Preview)"</h2>
                </div>
                <span class="badge neutral">"Preview"</span>
            </div>
            <div class="workspace-detail-columns">
                <div class="workspace-detail-list" aria-label="Request intake form fields">
                    <div class="workspace-detail-item">
                        <p>{form.description.clone()}</p>
                    </div>
                    {form.fields
                        .into_iter()
                        .map(|field| {
                            let required_marker = if field.required {
                                Some(view! { <span class="badge warn">"Required"</span> })
                            } else {
                                None
                            };
                            let options_label = if field.field_type == "select" && !field.options.is_empty() {
                                field.options.join(", ")
                            } else {
                                String::new()
                            };
                            let type_label = field.field_type.clone();
                            view! {
                                <div class="workspace-detail-item">
                                    <span class="badge neutral">{type_label}</span>
                                    <strong>{field.label.clone()}</strong>
                                    <p>{field.placeholder.clone()}</p>
                                    {if !options_label.is_empty() {
                                        view! { <span class="table-note">"Options: " {options_label}</span> }.into_any()
                                    } else {
                                        view! { <span class="table-note">""</span> }.into_any()
                                    }}
                                    {required_marker}
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
                <div class="workspace-detail-list" aria-label="Form submission status">
                    <div class="workspace-detail-item">
                        <span class="badge bad">"Submit"</span>
                        <strong>"Request submission available in next release"</strong>
                        <p>"This form is a read-only preview. No data is collected or submitted."</p>
                        <span class="table-note">"No database / No mutations / Dry-run only"</span>
                    </div>
                </div>
            </div>
        </article>
    }
}

#[component]
fn SecretReferenceWorkspaceDetail() -> impl IntoView {
    let snapshot = PortalSecretReferenceSnapshot::static_dry_run()
        .expect("secret reference status must be allowlisted");
    let _secret_reference_resource_guard = resource_api_path(secret_references_resource());
    let secret_reference_api_path = snapshot.secret_references_path.clone();
    let provider = snapshot.provider.clone();
    let management_cli = snapshot.management_cli.clone();
    let readiness_state = snapshot.readiness_state.clone();
    let configured_for_production = snapshot.configured_for_production.to_string();
    let live_cli_execution_allowed = snapshot.live_cli_execution_allowed.to_string();
    let provider_calls_allowed = snapshot.provider_calls_allowed.to_string();
    let secret_values_allowed = snapshot.secret_values_allowed.to_string();
    let provider_paths_allowed = snapshot.provider_paths_allowed.to_string();
    let references = snapshot.secret_references;

    view! {
        <article
            class="workspace-detail-panel"
            aria-labelledby="secret-reference-workspace-detail-title"
            data-secret-reference-workspace-detail="true"
            data-api-path=secret_reference_api_path
            data-provider=provider
            data-management-cli=management_cli
            data-readiness-state=readiness_state
            data-configured-for-production=configured_for_production
            data-live-cli-execution-allowed=live_cli_execution_allowed
            data-provider-calls-allowed=provider_calls_allowed
            data-secret-values-allowed=secret_values_allowed
            data-provider-paths-allowed=provider_paths_allowed
        >
            <div class="workspace-detail-head">
                <div>
                    <span class="eyebrow">"Secrets"</span>
                    <h2 id="secret-reference-workspace-detail-title">"Secret-reference workspace detail"</h2>
                </div>
                <span class="badge bad">"CLI execution blocked"</span>
            </div>
            <div class="workspace-detail-columns">
                <div class="workspace-detail-list" aria-label="Secret-reference readiness">
                    {references
                        .into_iter()
                        .map(|reference| {
                            let cli_state = if reference.live_cli_execution_allowed {
                                "CLI execution allowed"
                            } else {
                                "CLI execution blocked"
                            };
                            let value_state = if reference.value_exposure_allowed {
                                "Values visible"
                            } else {
                                "Values blocked"
                            };
                            let path_state = if reference.provider_path_exposure_allowed {
                                "Provider paths visible"
                            } else {
                                "Provider paths blocked"
                            };
                            view! {
                                <div class="workspace-detail-item">
                                    <span class="badge bad">{cli_state}</span>
                                    <strong>{reference.consumer_scope}</strong>
                                    <p>{reference.safe_summary}</p>
                                    <span class="table-note">{reference.provider} " / " {reference.management_cli} " / " {reference.rotation_state} " / " {value_state} " / " {path_state}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </div>
        </article>
    }
}

/// Renders one row of the governance audit feed: action, actor, roles,
/// stage transition, outcome, reason, and a deep link to the request.
fn activity_feed_row(row: AuditEventRow) -> impl IntoView {
    let action_text = audit_action_label(&row.action);
    let is_negative = matches!(row.action.as_str(), "request.reject" | "request.cancel");
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
    // Prefer the verified display name, falling back to the principal.
    let actor = if row.actor_display.is_empty() {
        row.actor_principal.clone()
    } else {
        row.actor_display.clone()
    };
    let from_stage = row.from_stage.clone().filter(|stage| !stage.is_empty());
    let transition = match from_stage {
        Some(from) => format!(
            "{} → {}",
            stage_label(&normalize_api_stage(&from)),
            stage_label(&normalize_api_stage(&row.to_stage)),
        ),
        None => stage_label(&normalize_api_stage(&row.to_stage)).to_string(),
    };
    let timestamp = condense_timestamp(&row.occurred_at);
    let reason = row.reason.clone();
    let roles = row.actor_roles.clone();
    // Only surface a non-default outcome (a denial is the one that matters).
    let outcome_badge = match row.outcome.as_deref() {
        Some("applied") | Some("") | None => None,
        Some(other) => {
            let class = if other == "denied" {
                "badge bad"
            } else {
                "badge warn"
            };
            let label = other.to_string();
            Some(view! { <span class=class>{label}</span> })
        }
    };
    let request_link = row.request_id.clone().map(|id| {
        let href = format!("/requests/{id}");
        view! {
            <a class="timeline-link" href=href>
                "View request →"
            </a>
        }
    });
    let roles_view = (!roles.is_empty()).then(|| {
        view! {
            <div class="role-chips" aria-label="Actor roles">
                {roles
                    .into_iter()
                    .map(|role| view! { <span class="role-chip">{role}</span> })
                    .collect_view()}
            </div>
        }
    });

    view! {
        <li class=item_class>
            <div class="timeline-row-head">
                <span class=badge_class>{action_text}</span>
                {outcome_badge}
                <time class="timeline-time">{timestamp}</time>
            </div>
            <strong>{actor}</strong>
            {roles_view}
            <p>{transition}</p>
            {reason
                .map(|reason| {
                    view! { <p class="timeline-reason">"Reason: " {reason}</p> }
                })}
            {request_link}
        </li>
    }
}

/// The durable governance audit feed panel for a successfully-loaded feed.
fn activity_feed_panel(rows: Vec<AuditEventRow>) -> impl IntoView {
    let total = rows.len();
    let any_non_durable = rows.iter().any(|row| !row.durable);
    let count_label = if total == 1 {
        "1 recorded action".to_string()
    } else {
        format!("{total} recorded actions")
    };
    let durable_badge = if any_non_durable {
        view! { <span class="badge warn">"Preview — not persisted"</span> }.into_any()
    } else {
        view! { <span class="badge good">"Durable"</span> }.into_any()
    };
    let body = if rows.is_empty() {
        view! {
            <div class="empty-state" role="status">
                <p class="empty-state-title">"No governance activity yet"</p>
                <p class="table-note">
                    "Lifecycle actions — create, validate, plan, approve, lock, execute, verify — appear here with their verified actor as requests move through the control plane."
                </p>
            </div>
        }
        .into_any()
    } else {
        view! {
            <ol class="timeline-list activity-feed" aria-label="Governance activity timeline">
                {rows.into_iter().map(activity_feed_row).collect_view()}
            </ol>
        }
        .into_any()
    };

    view! {
        <article class="workspace-detail-panel" aria-labelledby="governance-activity-title">
            <div class="workspace-detail-head">
                <div>
                    <span class="eyebrow">"Activity"</span>
                    <h2 id="governance-activity-title">"Governance activity"</h2>
                </div>
                {durable_badge}
            </div>
            <p class="workspace-detail-lede">
                "The durable, append-only audit trail — every lifecycle action across all requests with its verified actor, roles, and outcome. " {count_label} "."
            </p>
            {body}
        </article>
    }
}

/// `/activity` flagship surface — the real `audit_log` feed served by
/// `GET /api/activity/audit`, newest first. The star of the "governed control
/// plane": every action with its verified actor. Never shows stale or
/// fabricated data — an unreachable API renders an explicit degraded state.
#[component]
fn GovernanceActivityFeed() -> impl IntoView {
    let feed = Resource::new(|| (), |_| get_activity_audit_feed());

    view! {
        <Suspense fallback=|| {
            view! {
                <article
                    class="workspace-detail-panel"
                    aria-labelledby="governance-activity-title"
                    aria-busy="true"
                >
                    <div class="workspace-detail-head">
                        <div>
                            <span class="eyebrow">"Activity"</span>
                            <h2 id="governance-activity-title">"Governance activity"</h2>
                        </div>
                        <span class="badge neutral">"Loading…"</span>
                    </div>
                    <div class="timeline-list activity-feed" aria-hidden="true">
                        <div class="timeline-item skeleton"></div>
                        <div class="timeline-item skeleton"></div>
                        <div class="timeline-item skeleton"></div>
                    </div>
                </article>
            }
        }>
            {move || {
                Suspend::new(async move {
                    match feed.await {
                        Ok(rows) => activity_feed_panel(rows).into_any(),
                        Err(_) => {
                            view! {
                                <article
                                    class="workspace-detail-panel"
                                    aria-labelledby="governance-activity-title"
                                >
                                    <div class="workspace-detail-head">
                                        <div>
                                            <span class="eyebrow">"Activity"</span>
                                            <h2 id="governance-activity-title">"Governance activity"</h2>
                                        </div>
                                        <span class="badge bad">"Feed unavailable"</span>
                                    </div>
                                    <div class="empty-state" role="status">
                                        <p class="empty-state-title">"Audit feed unavailable"</p>
                                        <p class="table-note">
                                            "The platform API is unreachable, so the durable governance trail cannot be shown. No stale or fabricated data is displayed."
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
    }
}

#[component]
fn ActivityWorkspaceDetail() -> impl IntoView {
    let activity_run_state = Resource::new(|| (), |_| load_portal_activity_run_state());

    view! {
        <Suspense fallback=|| {
            view! {
                <article
                    class="workspace-detail-panel"
                    aria-labelledby="activity-workspace-detail-title"
                    aria-busy="true"
                    data-api-path=api_path(activity_operation_queue_path())
                    data-shift-path=api_path(shift_queue_path())
                    data-run-state-path=resource_api_path(operation_runs_resource())
                    data-emergency-path=api_path(emergency_change_path())
                    data-worker-execution-allowed="false"
                    data-retry-execution-allowed="false"
                    data-provider-calls-allowed="false"
                    data-live-execution-allowed="false"
                    data-raw-logs-allowed="false"
                >
                    <div class="workspace-detail-head">
                        <div>
                            <span class="eyebrow">"Activity"</span>
                            <h2 id="activity-workspace-detail-title">"Activity workspace detail"</h2>
                        </div>
                        <span class="badge neutral">"Queue state snapshot"</span>
                    </div>
                </article>
            }
        }>
            {move || {
                Suspend::new(async move {
                    match activity_run_state.await {
                        Ok(snapshot) => {
                            let snapshot: PortalActivityRunStateSnapshot = snapshot;
                            let _activity_queue_path_guard = api_path(activity_operation_queue_path());
                            let _shift_queue_path_guard = api_path(shift_queue_path());
                            let activity_api_path = snapshot.activity_queue_path.clone();
                            let shift_api_path = snapshot.shift_queue_path.clone();
                            let run_state_api_path = snapshot.run_state_path.clone();
                            let emergency_api_path = api_path(emergency_change_path());
                            let queue_state = snapshot.queue_state.clone();
                            let run_state = snapshot.run_state.clone();
                            let worker_execution_allowed = snapshot.worker_execution_allowed.to_string();
                            let retry_execution_allowed = snapshot.retry_execution_allowed.to_string();
                            let provider_calls_allowed = snapshot.provider_calls_allowed.to_string();
                            let live_execution_allowed = snapshot.live_execution_allowed.to_string();
                            let raw_logs_allowed = snapshot.raw_logs_allowed.to_string();
                            let activity_queue = snapshot.activity_queue;
                            let operation_runs = snapshot.operation_runs;
                            let _workflows = audit_workflow_fallbacks();
                            let _gates = audit_gate_fallbacks();

                            view! {
                                <article
                                    class="workspace-detail-panel"
                                    aria-labelledby="activity-workspace-detail-title"
                                    data-api-path=activity_api_path
                                    data-shift-path=shift_api_path
                                    data-run-state-path=run_state_api_path
                                    data-emergency-path=emergency_api_path
                                    data-queue-state=queue_state
                                    data-run-state=run_state
                                    data-worker-execution-allowed=worker_execution_allowed
                                    data-retry-execution-allowed=retry_execution_allowed
                                    data-provider-calls-allowed=provider_calls_allowed
                                    data-live-execution-allowed=live_execution_allowed
                                    data-raw-logs-allowed=raw_logs_allowed
                                >
                                    <div class="workspace-detail-head">
                                        <div>
                                            <span class="eyebrow">"Activity"</span>
                                            <h2 id="activity-workspace-detail-title">"Activity workspace detail"</h2>
                                        </div>
                                        <span class="badge neutral">"Queue state snapshot"</span>
                                    </div>
                                    <div class="workspace-detail-columns">
                                        <div class="workspace-detail-list" aria-label="Audit workflow readiness">
                                            {activity_queue
                                                .into_iter()
                                                .map(|item| {
                                                    let worker_state = if item.worker_execution_allowed {
                                                        "Worker execution allowed"
                                                    } else {
                                                        "Worker execution blocked"
                                                    };
                                                    view! {
                                                        <div class="workspace-detail-item">
                                                            <span class="badge bad">{worker_state}</span>
                                                            <strong>{item.queue}</strong>
                                                            <p>{item.safe_summary}</p>
                                                            <span class="table-note">{item.queue_state} " / " {item.lock_state} " / " {item.retry_state} " / " {item.handover_state}</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                        <div class="workspace-detail-list" aria-label="Activity gate readiness">
                                            {operation_runs
                                                .into_iter()
                                                .map(|run| {
                                                    let run_mode = if run.dry_run {
                                                        "Dry-run only"
                                                    } else {
                                                        "Execution disabled"
                                                    };
                                                    let blocked_reason = run
                                                        .blocked_reason
                                                        .unwrap_or_else(|| "Execution gate not satisfied.".to_string());
                                                    view! {
                                                        <div class="workspace-detail-item">
                                                            <span class="badge neutral">{run.state}</span>
                                                            <strong>{run_mode}</strong>
                                                            <p>{blocked_reason}</p>
                                                            <span class="table-note">"Run state summary / retries blocked"</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    </div>
                                </article>
                            }
                                .into_any()
                        }
                        Err(_) => view! {
                            <article
                                class="workspace-detail-panel"
                                aria-labelledby="activity-workspace-detail-title"
                                data-api-path=api_path(activity_operation_queue_path())
                                data-shift-path=api_path(shift_queue_path())
                                data-run-state-path=resource_api_path(operation_runs_resource())
                                data-emergency-path=api_path(emergency_change_path())
                                data-worker-execution-allowed="false"
                                data-retry-execution-allowed="false"
                                data-provider-calls-allowed="false"
                                data-live-execution-allowed="false"
                                data-raw-logs-allowed="false"
                            >
                                <div class="workspace-detail-head">
                                    <div>
                                        <span class="eyebrow">"Activity"</span>
                                        <h2 id="activity-workspace-detail-title">"Activity workspace detail"</h2>
                                    </div>
                                    <span class="badge bad">"Run state unavailable"</span>
                                </div>
                                <div class="workspace-detail-list" aria-label="Activity gate readiness">
                                    <div class="workspace-detail-item">
                                        <span class="badge bad">"Execution blocked"</span>
                                        <strong>"Dry-run only"</strong>
                                        <p>"Activity run state remains unavailable from the static server boundary."</p>
                                        <span class="table-note">"Provider calls, live execution, and raw logs remain blocked"</span>
                                    </div>
                                </div>
                            </article>
                        }
                            .into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn InventoryWorkspaceDetail() -> impl IntoView {
    let inventory_capacity_status =
        Resource::new(|| (), |_| load_portal_inventory_capacity_status());

    view! {
        <Suspense fallback=|| {
            view! {
                <article
                    class="workspace-detail-panel"
                    aria-labelledby="inventory-workspace-detail-title"
                    aria-busy="true"
                    data-api-path=platform_summary_path()
                    data-risk-path=platform_summary_path()
                    data-capacity-path=platform_summary_path()
                    data-inventory-read-only="true"
                    data-stale-data-blocks-execution="true"
                    data-capacity-execution-allowed="false"
                    data-http-request-allowed="false"
                    data-provider-calls-allowed="false"
                    data-raw-inventory-rows-allowed="false"
                >
                    <div class="workspace-detail-head">
                        <div>
                            <span class="eyebrow">"Inventory"</span>
                            <h2 id="inventory-workspace-detail-title">"Inventory workspace detail"</h2>
                        </div>
                        <span class="badge stale">"Read-only inventory"</span>
                    </div>
                </article>
            }
        }>
            {move || {
                Suspend::new(async move {
                    match inventory_capacity_status.await {
                        Ok(snapshot) => {
                            let snapshot: PortalInventoryCapacitySnapshot = snapshot;
                            let inventory_api_path = snapshot.inventory_resource_path.clone();
                            let ownership_risk_api_path = snapshot.ownership_risk_path.clone();
                            let capacity_api_path = snapshot.capacity_admission_path.clone();
                            let inventory_read_only = snapshot.inventory_read_only.to_string();
                            let stale_data_blocks_execution =
                                snapshot.stale_data_blocks_execution.to_string();
                            let capacity_execution_allowed =
                                snapshot.capacity_execution_allowed.to_string();
                            let http_request_allowed = snapshot.http_request_allowed.to_string();
                            let provider_calls_allowed = snapshot.provider_calls_allowed.to_string();
                            let raw_inventory_rows_allowed =
                                snapshot.raw_inventory_rows_allowed.to_string();
                            let resources = snapshot.inventory_resources;
                            let capacity = snapshot.capacity_admissions;

                            view! {
                                <article
                                    class="workspace-detail-panel"
                                    aria-labelledby="inventory-workspace-detail-title"
                                    data-api-path=inventory_api_path
                                    data-risk-path=ownership_risk_api_path
                                    data-capacity-path=capacity_api_path
                                    data-inventory-read-only=inventory_read_only
                                    data-stale-data-blocks-execution=stale_data_blocks_execution
                                    data-capacity-execution-allowed=capacity_execution_allowed
                                    data-http-request-allowed=http_request_allowed
                                    data-provider-calls-allowed=provider_calls_allowed
                                    data-raw-inventory-rows-allowed=raw_inventory_rows_allowed
                                >
                                    <div class="workspace-detail-head">
                                        <div>
                                            <span class="eyebrow">"Inventory"</span>
                                            <h2 id="inventory-workspace-detail-title">"Inventory workspace detail"</h2>
                                        </div>
                                        <span class="badge stale">"Read-only inventory"</span>
                                    </div>
                                    <div class="workspace-detail-columns">
                                        <div class="workspace-detail-list" aria-label="Inventory freshness and coverage">
                                            {resources
                                                .into_iter()
                                                .map(|resource| {
                                                    let freshness_badge = if resource.freshness_state.contains("stale") {
                                                        "badge stale"
                                                    } else {
                                                        "badge neutral"
                                                    };
                                                    view! {
                                                        <div class="workspace-detail-item">
                                                            <span class=freshness_badge>{resource.freshness_state}</span>
                                                            <strong>{resource.view}</strong>
                                                            <p>{resource.safe_summary}</p>
                                                            <span class="table-note">{resource.coverage_state} " / " {resource.evidence_state}</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                        <div class="workspace-detail-list" aria-label="Capacity admission readiness">
                                            {capacity
                                                .into_iter()
                                                .map(|admission| {
                                                    let execution_state = if admission.execution_allowed {
                                                        "Execution allowed"
                                                    } else {
                                                        "Execution blocked"
                                                    };
                                                    view! {
                                                        <div class="workspace-detail-item">
                                                            <span class="badge bad">{execution_state}</span>
                                                            <strong>{admission.scope}</strong>
                                                            <p>{admission.safe_summary}</p>
                                                            <span class="table-note">{admission.admission_state} " / " {admission.headroom_state}</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    </div>
                                </article>
                            }
                                .into_any()
                        }
                        Err(_) => view! {
                            <article
                                class="workspace-detail-panel"
                                aria-labelledby="inventory-workspace-detail-title"
                                data-api-path=platform_summary_path()
                                data-risk-path=platform_summary_path()
                                data-capacity-path=platform_summary_path()
                                data-inventory-read-only="true"
                                data-stale-data-blocks-execution="true"
                                data-capacity-execution-allowed="false"
                                data-http-request-allowed="false"
                                data-provider-calls-allowed="false"
                                data-raw-inventory-rows-allowed="false"
                            >
                                <div class="workspace-detail-head">
                                    <div>
                                        <span class="eyebrow">"Inventory"</span>
                                        <h2 id="inventory-workspace-detail-title">"Inventory workspace detail"</h2>
                                    </div>
                                    <span class="badge bad">"Inventory status unavailable"</span>
                                </div>
                                <div class="workspace-detail-list" aria-label="Inventory capacity readiness">
                                    <div class="workspace-detail-item">
                                        <span class="badge bad">"Execution blocked"</span>
                                        <strong>"Read-only inventory"</strong>
                                        <p>"Inventory capacity status remains unavailable from the static server boundary."</p>
                                        <span class="table-note">"Provider calls, live execution, and raw inventory rows remain blocked"</span>
                                    </div>
                                </div>
                            </article>
                        }
                            .into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn CmdbWorkspaceDetail() -> impl IntoView {
    let snapshot =
        PortalCmdbWorkspaceSnapshot::static_dry_run().expect("CMDB status must be allowlisted");
    let _file_exchange_guard = resource_api_path(cmdb_file_exchange_resource());
    let _reconciliation_guard = resource_api_path(cmdb_reconciliation_resource());
    let _relationship_guard = resource_api_path(cmdb_relationship_graph_resource());
    let file_exchange_path = snapshot.file_exchange_path.clone();
    let reconciliation_path = snapshot.reconciliation_path.clone();
    let relationship_graph_path = snapshot.relationship_graph_path.clone();
    let file_import_execution_allowed = snapshot.file_import_execution_allowed.to_string();
    let file_export_execution_allowed = snapshot.file_export_execution_allowed.to_string();
    let live_api_allowed = snapshot.live_api_allowed.to_string();
    let cmdb_mutation_allowed = snapshot.cmdb_mutation_allowed.to_string();
    let relationship_mutation_allowed = snapshot.relationship_mutation_allowed.to_string();
    let provider_calls_allowed = snapshot.provider_calls_allowed.to_string();
    let raw_cmdb_rows_allowed = snapshot.raw_cmdb_rows_allowed.to_string();
    let raw_relationship_rows_allowed = snapshot.raw_relationship_rows_allowed.to_string();
    let evidence_redaction_required = snapshot.evidence_redaction_required.to_string();
    let file_exchange = snapshot.file_exchange;
    let reconciliation = snapshot.reconciliation;
    let relationships = snapshot.relationships;

    view! {
        <article
            class="workspace-detail-panel"
            aria-labelledby="cmdb-workspace-detail-title"
            data-cmdb-workspace-detail="true"
            data-api-path=reconciliation_path
            data-file-exchange-path=file_exchange_path
            data-relationship-graph-path=relationship_graph_path
            data-file-import-execution-allowed=file_import_execution_allowed
            data-file-export-execution-allowed=file_export_execution_allowed
            data-live-servicenow-api-allowed=live_api_allowed
            data-cmdb-mutation-allowed=cmdb_mutation_allowed
            data-relationship-mutation-allowed=relationship_mutation_allowed
            data-provider-calls-allowed=provider_calls_allowed
            data-raw-cmdb-rows-allowed=raw_cmdb_rows_allowed
            data-raw-relationship-rows-allowed=raw_relationship_rows_allowed
            data-evidence-redaction-required=evidence_redaction_required
        >
            <div class="workspace-detail-head">
                <div>
                    <span class="eyebrow">"CMDB"</span>
                    <h2 id="cmdb-workspace-detail-title">"CMDB workspace detail"</h2>
                </div>
                <span class="badge bad">"File exchange blocked"</span>
            </div>
            <div class="workspace-detail-columns">
                <div class="workspace-detail-list" aria-label="CMDB file exchange readiness">
                    {file_exchange
                        .into_iter()
                        .map(|exchange| {
                            let import_state = if exchange.file_import_execution_allowed {
                                "Import execution allowed"
                            } else {
                                "Import execution blocked"
                            };
                            let export_state = if exchange.file_export_execution_allowed {
                                "Export execution allowed"
                            } else {
                                "Export execution blocked"
                            };
                            let api_state = if exchange.live_api_allowed {
                                "Live ServiceNow API allowed"
                            } else {
                                "Live ServiceNow API blocked"
                            };
                            let row_state = if exchange.raw_cmdb_rows_allowed {
                                "Raw CMDB rows visible"
                            } else {
                                "Raw CMDB rows blocked"
                            };
                            view! {
                                <div class="workspace-detail-item">
                                    <span class="badge bad">{import_state}</span>
                                    <strong>{exchange.exchange}</strong>
                                    <p>{exchange.safe_summary}</p>
                                    <span class="table-note">{exchange.mapping_state} " / " {exchange.validation_state} " / " {exchange.evidence_state} " / " {export_state} " / " {api_state} " / " {row_state}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
                <div class="workspace-detail-list" aria-label="CMDB reconciliation readiness">
                    {reconciliation
                        .into_iter()
                        .map(|item| {
                            let mutation_state = if item.cmdb_mutation_allowed {
                                "CMDB mutation allowed"
                            } else {
                                "CMDB mutation blocked"
                            };
                            let row_state = if item.raw_cmdb_rows_allowed {
                                "Raw CMDB rows visible"
                            } else {
                                "Raw CMDB rows blocked"
                            };
                            view! {
                                <div class="workspace-detail-item">
                                    <span class="badge bad">{mutation_state}</span>
                                    <strong>{item.scope}</strong>
                                    <p>{item.safe_summary}</p>
                                    <span class="table-note">{item.reconciliation_state} " / " {item.review_state} " / " {item.evidence_state} " / " {row_state}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
                <div class="workspace-detail-list" aria-label="CMDB relationship graph readiness">
                    {relationships
                        .into_iter()
                        .map(|item| {
                            let mutation_state = if item.relationship_mutation_allowed {
                                "Relationship mutation allowed"
                            } else {
                                "Relationship mutation blocked"
                            };
                            let row_state = if item.raw_relationship_rows_allowed {
                                "Raw relationship rows visible"
                            } else {
                                "Raw relationship rows blocked"
                            };
                            view! {
                                <div class="workspace-detail-item">
                                    <span class="badge bad">{mutation_state}</span>
                                    <strong>{item.graph_scope}</strong>
                                    <p>{item.safe_summary}</p>
                                    <span class="table-note">{item.relationship_state} " / " {item.dependency_quality_state} " / " {item.evidence_state} " / " {row_state}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </div>
        </article>
    }
}

#[component]
fn PolicyWorkspaceDetail() -> impl IntoView {
    let snapshot = PortalPolicyGuardrailsSnapshot::static_dry_run()
        .expect("policy guardrails status must be allowlisted");
    let _policy_resource_guard = resource_api_path(policy_outcomes_resource());
    let _approval_readiness_guard = api_path(approval_decision_readiness_path());
    let policy_api_path = snapshot.policy_outcomes_path.clone();
    let approval_api_path = snapshot.approval_readiness_path.clone();
    let policy_gate_state = snapshot.policy_gate_state.clone();
    let approval_required = snapshot.approval_required.to_string();
    let execution_allowed = snapshot.execution_allowed.to_string();
    let http_request_allowed = snapshot.http_request_allowed.to_string();
    let provider_calls_allowed = snapshot.provider_calls_allowed.to_string();
    let live_execution_allowed = snapshot.live_execution_allowed.to_string();
    let raw_policy_payloads_allowed = snapshot.raw_policy_payloads_allowed.to_string();
    let policies = snapshot.policy_outcomes;
    let guardrails = snapshot.guardrails;

    view! {
        <article
            class="workspace-detail-panel"
            aria-labelledby="policy-workspace-detail-title"
            data-api-path=policy_api_path
            data-approval-path=approval_api_path
            data-policy-gate-state=policy_gate_state
            data-approval-required=approval_required
            data-execution-allowed=execution_allowed
            data-http-request-allowed=http_request_allowed
            data-provider-calls-allowed=provider_calls_allowed
            data-live-execution-allowed=live_execution_allowed
            data-raw-policy-payloads-allowed=raw_policy_payloads_allowed
        >
            <div class="workspace-detail-head">
                <div>
                    <span class="eyebrow">"Policy"</span>
                    <h2 id="policy-workspace-detail-title">"Policy workspace detail"</h2>
                </div>
                <span class="badge bad">"Policy guardrails"</span>
            </div>
            <div class="workspace-detail-columns">
                <div class="workspace-detail-list" aria-label="Policy outcome readiness">
                    {policies
                        .into_iter()
                        .map(|outcome| {
                            view! {
                                <div class="workspace-detail-item">
                                    <span class="badge bad">{outcome.decision}</span>
                                    <strong>{outcome.id}</strong>
                                    <p>{outcome.safe_summary}</p>
                                    <span class="table-note">"Static policy outcome / approval readiness"</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
                <div class="workspace-detail-list" aria-label="Policy guardrail enforcement">
                    {guardrails
                        .into_iter()
                        .map(|guardrail| {
                            let execution_state = if guardrail.execution_allowed {
                                "Execution allowed"
                            } else {
                                "Execution blocked"
                            };
                            view! {
                                <div class="workspace-detail-item">
                                    <span class="badge bad">{execution_state}</span>
                                    <strong>{guardrail.guardrail}</strong>
                                    <p>{guardrail.safe_summary}</p>
                                    <span class="table-note">{guardrail.enforcement_state} " / " {guardrail.aggregate_scope}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </div>
        </article>
    }
}

#[component]
fn EvidenceWorkspaceDetail() -> impl IntoView {
    let evidence_summary_status = Resource::new(|| (), |_| load_portal_evidence_summary_status());
    let evidence_resource_path = resource_api_path(evidence_summary_resource());
    let retention_resource_path = api_path(evidence_export_retention_path());

    view! {
        <Suspense fallback=move || {
            view! {
                <article
                    class="workspace-detail-panel"
                    aria-labelledby="evidence-workspace-detail-title"
                    aria-busy="true"
                    data-api-path=evidence_resource_path
                    data-retention-path=retention_resource_path
                    data-redaction-required="true"
                    data-export-allowed="false"
                    data-http-request-allowed="false"
                    data-provider-calls-allowed="false"
                    data-raw-evidence-payloads-allowed="false"
                >
                    <div class="workspace-detail-head">
                        <div>
                            <span class="eyebrow">"Evidence"</span>
                            <h2 id="evidence-workspace-detail-title">"Evidence workspace detail"</h2>
                        </div>
                        <span class="badge warn">"Evidence loading"</span>
                    </div>
                </article>
            }
        }>
            {move || {
                Suspend::new(async move {
                    match evidence_summary_status.await {
                        Ok(snapshot) => {
                            let snapshot: PortalEvidenceSummarySnapshot = snapshot;
                            let evidence_api_path = snapshot.evidence_summary_path.clone();
                            let retention_api_path = snapshot.retention_path.clone();
                            let redaction_required = snapshot.redaction_required.to_string();
                            let export_allowed = snapshot.export_allowed.to_string();
                            let evidence_http_request_allowed =
                                snapshot.http_request_allowed.to_string();
                            let evidence_provider_calls_allowed =
                                snapshot.provider_calls_allowed.to_string();
                            let raw_evidence_payloads_allowed =
                                snapshot.raw_evidence_payloads_allowed.to_string();
                            let summaries = snapshot.evidence_summaries;

                            view! {
                                <article
                                    class="workspace-detail-panel"
                                    aria-labelledby="evidence-workspace-detail-title"
                                    data-api-path=evidence_api_path
                                    data-retention-path=retention_api_path
                                    data-redaction-required=redaction_required
                                    data-export-allowed=export_allowed
                                    data-http-request-allowed=evidence_http_request_allowed
                                    data-provider-calls-allowed=evidence_provider_calls_allowed
                                    data-raw-evidence-payloads-allowed=raw_evidence_payloads_allowed
                                >
                                    <div class="workspace-detail-head">
                                        <div>
                                            <span class="eyebrow">"Evidence"</span>
                                            <h2 id="evidence-workspace-detail-title">"Evidence workspace detail"</h2>
                                        </div>
                                        <span class="badge warn">"Evidence redaction"</span>
                                    </div>
                                    <div class="workspace-detail-columns">
                                        <div class="workspace-detail-list" aria-label="Evidence redaction and export readiness">
                                            {summaries
                                                .into_iter()
                                                .map(|summary| {
                                                    let export_state = if summary.export_allowed {
                                                        "Export allowed"
                                                    } else {
                                                        "Export blocked"
                                                    };
                                                    let redaction_state = if summary.redaction_required {
                                                        "Redaction required"
                                                    } else {
                                                        "Redaction complete"
                                                    };
                                                    view! {
                                                        <div class="workspace-detail-item">
                                                            <span class="badge warn">{summary.state}</span>
                                                            <strong>{redaction_state}</strong>
                                                            <p>{export_state}</p>
                                                            <span class="table-note">"Redacted evidence summaries only"</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    </div>
                                </article>
                            }
                                .into_any()
                        }
                        Err(_) => view! {
                            <article
                                class="workspace-detail-panel"
                                aria-labelledby="evidence-workspace-detail-title"
                                data-api-path=evidence_resource_path
                                data-retention-path=retention_resource_path
                                data-redaction-required="true"
                                data-export-allowed="false"
                                data-http-request-allowed="false"
                                data-provider-calls-allowed="false"
                                data-raw-evidence-payloads-allowed="false"
                            >
                                <div class="workspace-detail-head">
                                    <div>
                                        <span class="eyebrow">"Evidence"</span>
                                        <h2 id="evidence-workspace-detail-title">"Evidence workspace detail"</h2>
                                    </div>
                                    <span class="badge bad">"Evidence unavailable"</span>
                                </div>
                                <div class="workspace-detail-columns">
                                    <div class="workspace-detail-list" aria-label="Evidence redaction and export readiness">
                                        <div class="workspace-detail-item">
                                            <span class="badge warn">"Redaction required"</span>
                                            <strong>"Evidence summary unavailable"</strong>
                                            <p>"Evidence summary status remains unavailable from the static server boundary."</p>
                                            <span class="table-note">"Provider calls and raw evidence payload exposure remain blocked"</span>
                                        </div>
                                        <div class="workspace-detail-item">
                                            <span class="badge bad">"Export blocked"</span>
                                            <strong>"Evidence export remains blocked"</strong>
                                            <p>"Retention and export readiness stay unavailable until the static summary loads."</p>
                                            <span class="table-note">"Redacted evidence summaries only"</span>
                                        </div>
                                    </div>
                                </div>
                            </article>
                        }
                            .into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn OperationsWorkspaceDetail() -> impl IntoView {
    let platform_health = Resource::new(|| (), |_| get_platform_health());
    let operation_api_path = resource_api_path(operation_runs_resource());
    let runbook_api_path = api_path(operations_runbook_launch_path());
    let health_api_path = api_path(operations_platform_health_path());
    let _platform_health_path_guard = api_path(platform_health_path());
    let runs = operation_run_fallbacks();

    view! {
        <article
            class="workspace-detail-panel"
            aria-labelledby="operations-workspace-detail-title"
            data-api-path=operation_api_path
            data-runbook-path=runbook_api_path
            data-health-path=health_api_path
            data-platform-health-path=platform_health_path()
        >
            <div class="workspace-detail-head">
                <div>
                    <span class="eyebrow">"Operations"</span>
                    <h2 id="operations-workspace-detail-title">"Operations workspace detail"</h2>
                </div>
                <span class="badge neutral">"Operation run state"</span>
            </div>
            <div class="workspace-detail-columns">
                <div class="workspace-detail-list" aria-label="Operation run state readiness">
                    {runs
                        .into_iter()
                        .map(|run| {
                            let run_mode = if run.dry_run {
                                "Dry-run only"
                            } else {
                                "Execution disabled"
                            };
                            let blocked_reason = run
                                .blocked_reason
                                .unwrap_or_else(|| "Execution gate not satisfied.".to_string());
                            view! {
                                <div class="workspace-detail-item">
                                    <span class="badge neutral">{run.state}</span>
                                    <strong>{run_mode}</strong>
                                    <p>{blocked_reason}</p>
                                    <span class="table-note">"Runbook launch and platform health stay static"</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
                <div class="workspace-detail-list" aria-label="Platform component health">
                    <Suspense fallback=|| {
                        view! {
                            <div class="workspace-detail-item">
                                <span class="badge neutral">"Loading"</span>
                                <strong>"Platform health"</strong>
                                <p>"Platform health is loading from the static server boundary."</p>
                            </div>
                        }
                    }>
                        {move || {
                            Suspend::new(async move {
                                match platform_health.await {
                                    Ok(health) => {
                                        let checks = health.checks;
                                        let overall = health.overall_status;
                                        let timestamp = condense_timestamp(&health.timestamp);
                                        view! {
                                            <div class="workspace-detail-item">
                                                <span class="badge good">{overall}</span>
                                                <strong>"Platform health"</strong>
                                                <p>"Component health checks"</p>
                                                <span class="table-note">{timestamp}</span>
                                            </div>
                                            {checks
                                                .into_iter()
                                                .map(|check| {
                                                    let check_badge_class = if check.status == "healthy" {
                                                        "badge good"
                                                    } else if check.status == "warning" {
                                                        "badge warn"
                                                    } else {
                                                        "badge bad"
                                                    };
                                                    view! {
                                                        <div class="workspace-detail-item">
                                                            <span class=check_badge_class>{check.status}</span>
                                                            <strong>{check.name}</strong>
                                                            <p>{check.message}</p>
                                                            <span class="table-note">{check.component} " / " {condense_timestamp(&check.last_check)}</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        }
                                            .into_any()
                                    }
                                    Err(_) => view! {
                                        <div class="workspace-detail-item">
                                            <span class="badge bad">"Unavailable"</span>
                                            <strong>"Platform health"</strong>
                                            <p>"Platform health status remains unavailable from the static server boundary."</p>
                                        </div>
                                    }
                                        .into_any(),
                                }
                            })
                        }}
                    </Suspense>
                </div>
            </div>
        </article>
    }
}

#[component]
fn SecurityWorkspaceDetail() -> impl IntoView {
    let auth_session = Resource::new(|| (), |_| get_auth_session());
    let boundary_status = Resource::new(|| (), |_| get_boundary_status());
    let platform_status = Resource::new(|| (), |_| get_platform_status());
    let _auth_status_path_guard = api_path(auth_status_path());
    let _boundary_status_path_guard = api_path(boundary_status_path());
    let _platform_status_path_guard = api_path(platform_status_path());

    view! {
        <Suspense fallback=|| {
            view! {
                <article
                    class="workspace-detail-panel"
                    aria-labelledby="security-workspace-detail-title"
                    aria-busy="true"
                    data-api-path=auth_status_path()
                    data-boundary-path=boundary_status_path()
                    data-platform-status-path=platform_status_path()
                    data-execution-mode="static-dry-run"
                >
                    <div class="workspace-detail-head">
                        <div>
                            <span class="eyebrow">"Security"</span>
                            <h2 id="security-workspace-detail-title">"Security workspace detail"</h2>
                        </div>
                        <span class="badge neutral">"Auth loading"</span>
                    </div>
                </article>
            }
        }>
            {move || {
                Suspend::new(async move {
                    let session_result = auth_session.await;
                    let boundary_result = boundary_status.await;
                    let platform_status_result = platform_status.await;

                    let session = session_result.as_ref().ok().and_then(|s| s.as_ref());
                    let user_id = session
                        .map(|s| s.user_id.clone())
                        .unwrap_or_else(|| "unavailable".to_string());
                    let display_name = session
                        .map(|s| s.display_name.clone())
                        .unwrap_or_else(|| "unavailable".to_string());
                    let roles: Vec<_> = session.map(|s| s.roles.clone()).unwrap_or_default();

                    let execution_mode = boundary_result
                        .as_ref()
                        .map(|bs| format!("{:?}", bs.execution_mode))
                        .unwrap_or_else(|_| "static-dry-run".to_string());
                    let http_allowed = boundary_result
                        .as_ref()
                        .map(|bs| bs.http_request_allowed.to_string())
                        .unwrap_or_else(|_| "false".to_string());
                    let provider_allowed = boundary_result
                        .as_ref()
                        .map(|bs| bs.provider_calls_allowed.to_string())
                        .unwrap_or_else(|_| "false".to_string());
                    let live_allowed = boundary_result
                        .as_ref()
                        .map(|bs| bs.live_execution_allowed.to_string())
                        .unwrap_or_else(|_| "false".to_string());
                    let raw_allowed = boundary_result
                        .as_ref()
                        .map(|bs| bs.raw_payload_allowed.to_string())
                        .unwrap_or_else(|_| "false".to_string());
                    let secrets_allowed = boundary_result
                        .as_ref()
                        .map(|bs| bs.secret_values_allowed.to_string())
                        .unwrap_or_else(|_| "false".to_string());
                    let customer_allowed = boundary_result
                        .as_ref()
                        .map(|bs| bs.customer_identifiers_allowed.to_string())
                        .unwrap_or_else(|_| "false".to_string());

                    let boundary_mode = platform_status_result
                        .as_ref()
                        .map(|s| s.boundary_mode.clone())
                        .unwrap_or_else(|_| "static-dry-run".to_string());

                    let exec_mode_attr = execution_mode.clone();
                    let http_attr = http_allowed.clone();
                    let provider_attr = provider_allowed.clone();
                    let live_attr = live_allowed.clone();

                    let exec_mode_text = execution_mode.clone();
                    let http_text = http_allowed.clone();
                    let provider_text = provider_allowed.clone();
                    let live_text = live_allowed.clone();

                    view! {
                        <article
                            class="workspace-detail-panel"
                            aria-labelledby="security-workspace-detail-title"
                            data-api-path=auth_status_path()
                            data-boundary-path=boundary_status_path()
                            data-platform-status-path=platform_status_path()
                            data-execution-mode=exec_mode_attr
                            data-http-request-allowed=http_attr
                            data-provider-calls-allowed=provider_attr
                            data-live-execution-allowed=live_attr
                            data-raw-payload-allowed=raw_allowed
                            data-secret-values-allowed=secrets_allowed
                            data-customer-identifiers-allowed=customer_allowed
                        >
                            <div class="workspace-detail-head">
                                <div>
                                    <span class="eyebrow">"Security"</span>
                                    <h2 id="security-workspace-detail-title">"Security workspace detail"</h2>
                                </div>
                                <span class="badge good">"Static session"</span>
                            </div>
                            <div class="workspace-detail-columns">
                                <div class="workspace-detail-list" aria-label="Auth session readiness">
                                    <div class="workspace-detail-item">
                                        <span class="badge neutral">{user_id}</span>
                                        <strong>{display_name}</strong>
                                        <p>"Static dry-run auth session"</p>
                                        <span class="table-note">"Same-origin auth status check"</span>
                                    </div>
                                    <div class="workspace-detail-item">
                                        <span class="badge neutral">"Roles"</span>
                                        <strong>"Assigned roles"</strong>
                                        <div class="boundary-flags" aria-label="Role badges">
                                            {roles
                                                .into_iter()
                                                .map(|role| {
                                                    view! {
                                                        <span class="badge neutral">{role}</span>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                        <span class="table-note">"Static session roles"</span>
                                    </div>
                                </div>
                                <div class="workspace-detail-list" aria-label="Boundary mode enforcement">
                                    <div class="workspace-detail-item">
                                        <span class="badge neutral">{boundary_mode}</span>
                                        <strong>"Boundary mode"</strong>
                                        <p>"All provider calls, secrets, and raw payloads blocked"</p>
                                        <span class="table-note">"Execution mode: " {exec_mode_text}</span>
                                    </div>
                                    <div class="workspace-detail-item">
                                        <span class="badge good">"Auth mode"</span>
                                        <strong>"Static dry-run authentication"</strong>
                                        <p>"No live provider identity checks"</p>
                                        <span class="table-note">"HTTP: " {http_text} " / Provider: " {provider_text} " / Live: " {live_text}</span>
                                    </div>
                                </div>
                            </div>
                        </article>
                    }
                        .into_any()
                })
            }}
        </Suspense>
    }
}

#[component]
fn AdminSettingsDetail() -> impl IntoView {
    #[allow(deprecated)]
    let settings_resource = Resource::new(|| (), |_| get_admin_platform_settings());
    let _boundary = PortalServerBoundary::static_dry_run();

    #[allow(deprecated)]
    let (tenant_id, set_tenant_id) = create_signal(String::new());
    #[allow(deprecated)]
    let (client_id, set_client_id) = create_signal(String::new());
    #[allow(deprecated)]
    let (authority, set_authority) = create_signal(String::new());
    #[allow(deprecated)]
    let (auth_mode, set_auth_mode) = create_signal(String::new());
    #[allow(deprecated)]
    let (db_provider, set_db_provider) = create_signal(String::new());
    #[allow(deprecated)]
    let (feedback, set_feedback) = create_signal(String::new());
    #[allow(deprecated)]
    let (feedback_class, set_feedback_class) = create_signal("badge neutral");

    let save_action = Action::new(move |input: &PlatformSettingsSummary| {
        let payload = input.clone();
        set_feedback.set("Saving...".to_string());
        set_feedback_class.set("badge neutral");
        async move {
            match save_platform_settings(payload).await {
                Ok(settings) => {
                    set_tenant_id.set(settings.entra_tenant_id.clone());
                    set_client_id.set(settings.entra_client_id.clone());
                    set_authority.set(settings.entra_authority.clone());
                    set_auth_mode.set(settings.auth_mode.clone());
                    set_db_provider.set(settings.database_provider.clone());
                    set_feedback.set("Settings saved".to_string());
                    set_feedback_class.set("badge good");
                }
                Err(_) => {
                    set_feedback.set("Preview only: settings were not persisted".to_string());
                    set_feedback_class.set("badge neutral");
                }
            }
        }
    });

    let reset_action = Action::new(move |_: &()| {
        set_feedback.set("Resetting...".to_string());
        set_feedback_class.set("badge neutral");
        async move {
            match reset_platform_settings().await {
                Ok(settings) => {
                    set_tenant_id.set(settings.entra_tenant_id.clone());
                    set_client_id.set(settings.entra_client_id.clone());
                    set_authority.set(settings.entra_authority.clone());
                    set_auth_mode.set(settings.auth_mode.clone());
                    set_db_provider.set(settings.database_provider.clone());
                    set_feedback.set("Settings reset to defaults".to_string());
                    set_feedback_class.set("badge good");
                }
                Err(_) => {
                    set_feedback.set("Preview only: settings were not reset".to_string());
                    set_feedback_class.set("badge neutral");
                }
            }
        }
    });

    view! {
        <Suspense fallback=|| {
            view! {
                <article
                    class="workspace-detail-panel"
                    aria-labelledby="admin-settings-detail-title"
                    aria-busy="true"
                    data-api-path=admin_rbac_roles_path()
                    data-platform-settings-path=admin_platform_settings_path()
                >
                    <div class="workspace-detail-head">
                        <div>
                            <span class="eyebrow">"Admin"</span>
                            <h2 id="admin-settings-detail-title">"Admin settings detail"</h2>
                        </div>
                        <span class="badge neutral">"Loading"</span>
                    </div>
                </article>
            }
        }>
            {move || {
                Suspend::new(async move {
                    let settings = match settings_resource.await {
                        Ok(s) => s,
                        Err(_) => platform_settings_summary_fallback(),
                    };

                    set_tenant_id.set(settings.entra_tenant_id.clone());
                    set_client_id.set(settings.entra_client_id.clone());
                    set_authority.set(settings.entra_authority.clone());
                    set_auth_mode.set(settings.auth_mode.clone());
                    set_db_provider.set(settings.database_provider.clone());

                    view! {
                        <article
                            class="workspace-detail-panel"
                            aria-labelledby="admin-settings-detail-title"
                            data-api-path=admin_rbac_roles_path()
                            data-platform-settings-path=admin_platform_settings_path()
                        >
                            <div class="workspace-detail-head">
                                <div>
                                    <span class="eyebrow">"Admin"</span>
                                    <h2 id="admin-settings-detail-title">"Platform settings"</h2>
                                </div>
                                <span class=feedback_class>{feedback}</span>
                            </div>
                            <div class="workspace-detail-columns">
                                <div class="workspace-detail-list" aria-label="Platform settings">
                                    <div class="workspace-detail-item">
                                        <strong>"Tenant ID"</strong>
                                        <input
                                            type="text"
                                            class="settings-input"
                                            placeholder="Entra tenant ID"
                                            prop:value=tenant_id
                                            on:input=move |ev| {
                                                let val = event_target_value(&ev);
                                                set_tenant_id.set(val);
                                            }
                                        />
                                        <span class="table-note">"Entra directory tenant ID"</span>
                                    </div>
                                    <div class="workspace-detail-item">
                                        <strong>"Client ID"</strong>
                                        <input
                                            type="text"
                                            class="settings-input"
                                            placeholder="Entra application client ID"
                                            prop:value=client_id
                                            on:input=move |ev| {
                                                let val = event_target_value(&ev);
                                                set_client_id.set(val);
                                            }
                                        />
                                        <span class="table-note">"Entra application registration client ID"</span>
                                    </div>
                                    <div class="workspace-detail-item">
                                        <strong>"Authority URL"</strong>
                                        <input
                                            type="text"
                                            class="settings-input"
                                            placeholder="https://login.microsoftonline.com"
                                            prop:value=authority
                                            on:input=move |ev| {
                                                let val = event_target_value(&ev);
                                                set_authority.set(val);
                                            }
                                        />
                                        <span class="table-note">"OAuth2 authority endpoint"</span>
                                    </div>
                                    <div class="workspace-detail-item">
                                        <strong>"Auth mode"</strong>
                                        <select
                                            class="settings-input"
                                            prop:value=auth_mode
                                            on:change=move |ev| {
                                                let val = event_target_value(&ev);
                                                set_auth_mode.set(val);
                                            }
                                        >
                                            <option value="mock-dry-run">"Mock dry-run"</option>
                                            <option value="entra-id">"Entra ID"</option>
                                        </select>
                                        <span class="table-note">"Authentication provider mode"</span>
                                    </div>
                                    <div class="workspace-detail-item">
                                        <span class="badge neutral">{db_provider}</span>
                                        <strong>"Database provider"</strong>
                                        <p>"Read-only"</p>
                                        <span class="table-note">"Managed by CloudNativePG in production"</span>
                                    </div>
                                    <div class="workspace-detail-item">
                                        <div class="settings-actions">
                                            <button
                                                class="btn btn-primary"
                                                on:click=move |_| {
                                                    let payload = PlatformSettingsSummary {
                                                        entra_tenant_id: tenant_id.get(),
                                                        entra_client_id: client_id.get(),
                                                        entra_authority: authority.get(),
                                                        auth_mode: auth_mode.get(),
                                                        database_provider: db_provider.get(),
                                                    };
                                                    save_action.dispatch(payload);
                                                }
                                            >
                                                "Save"
                                            </button>
                                            <button
                                                class="btn btn-secondary"
                                                on:click=move |_| {
                                                    reset_action.dispatch(());
                                                }
                                            >
                                                "Reset defaults"
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                <div class="workspace-detail-list" aria-label="Branding">
                                    <div class="workspace-detail-item branding-section">
                                        <strong>"Branding"</strong>
                                        <div class="branding-section">
                                            <div class="logo-upload-placeholder">
                                                <p>"No logo uploaded"</p>
                                                <p>"Upload your company logo"</p>
                                            </div>
                                            <div class="logo-upload-input">
                                                <input
                                                    type="file"
                                                    accept="image/png, image/jpeg, image/svg+xml"
                                                    disabled=true
                                                />
                                            </div>
                                            <div class="logo-preview" aria-label="Logo preview area">
                                                <p>"Logo upload coming in next release. Contact your administrator to configure."</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="workspace-detail-list" aria-label="App Roles">
                                    <div class="workspace-detail-item">
                                        <span class="badge neutral">"Entra ID"</span>
                                        <strong>"Roles are managed in Entra ID"</strong>
                                        <p>"App Registrations → App Roles"</p>
                                        <span class="table-note">"No group name mapping — roles claim in access token"</span>
                                    </div>
                                    {rbac_role_summary_fallbacks()
                                        .into_iter()
                                        .map(|role| {
                                            view! {
                                                <div class="workspace-detail-item">
                                                    <span class="badge neutral">{role.name.clone()}</span>
                                                    <strong>{role.description.clone()}</strong>
                                                    <p>{role.note.clone()}</p>
                                                    <span class="table-note">"App role configured in Entra ID manifest"</span>
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
    }
}

/// Renders a scope value or an em dash for an absent/empty scope.
fn scope_label(scope: &Option<String>) -> String {
    match scope {
        Some(value) if !value.is_empty() => value.clone(),
        _ => "—".to_string(),
    }
}

/// Renders a timestamp or an em dash for an absent one.
fn timestamp_label(value: &Option<String>) -> String {
    value
        .clone()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "—".to_string())
}

/// Status text + badge class for a token row: revoked > active > inactive.
/// Plaintext and hash are never part of this rendering.
fn token_status(token: &AdminTokenSummary) -> (&'static str, &'static str) {
    if token.revoked_at.as_deref().is_some_and(|v| !v.is_empty()) {
        ("Revoked", "badge bad")
    } else if token.token_valid {
        ("Active", "badge good")
    } else {
        ("Inactive", "badge neutral")
    }
}

/// Extracts a user-facing message from a server function error, falling back
/// to a generic label. Server function transport noise is never surfaced raw.
fn server_error_message(error: &ServerFnError, fallback: &str) -> String {
    let text = error.to_string();
    if text.is_empty() {
        fallback.to_string()
    } else {
        text
    }
}

/// Admin token management: list (hash never shown), create (one-time secret
/// reveal), and revoke. Gated by the caller on the `admin` capability.
#[component]
fn TokenAdministrationDetail() -> impl IntoView {
    let tokens_resource = Resource::new(|| (), |_| load_admin_tokens());
    // Working copy of the table so create/revoke can update it in place.
    let tokens = RwSignal::new(Vec::<AdminTokenSummary>::new());
    let loaded = RwSignal::new(false);

    let _tokens_path_guard = api_path(admin_tokens_path());

    // Create-form state.
    let name = RwSignal::new(String::new());
    let owner = RwSignal::new(String::new());
    let roles = RwSignal::new(Vec::<String>::new());
    let site_scope = RwSignal::new(String::new());
    let environment_scope = RwSignal::new(String::new());
    let expires_at = RwSignal::new(String::new());

    let feedback = RwSignal::new(String::new());
    let feedback_class = RwSignal::new("badge neutral");
    // The one-time plaintext secret. Held only transiently for the copy-once
    // callout; never written to storage and dropped when a new token is
    // created or the operator dismisses it.
    let revealed_secret = RwSignal::new(Option::<String>::None);
    let secret_input: NodeRef<leptos::html::Input> = NodeRef::new();

    let create_action = Action::new(move |payload: &CreateTokenPayload| {
        let payload = payload.clone();
        async move {
            feedback.set("Creating token...".to_string());
            feedback_class.set("badge neutral");
            match create_admin_token(payload).await {
                Ok(result) => {
                    tokens.update(|rows| rows.insert(0, result.metadata));
                    revealed_secret.set(Some(result.token));
                    feedback.set("Token created — copy the secret now".to_string());
                    feedback_class.set("badge good");
                    name.set(String::new());
                    owner.set(String::new());
                    roles.set(Vec::new());
                    site_scope.set(String::new());
                    environment_scope.set(String::new());
                    expires_at.set(String::new());
                }
                Err(err) => {
                    revealed_secret.set(None);
                    feedback.set(server_error_message(&err, "Token creation failed"));
                    feedback_class.set("badge bad");
                }
            }
        }
    });

    let revoke_action = Action::new(move |token_id: &String| {
        let token_id = token_id.clone();
        async move {
            match revoke_admin_token(token_id.clone()).await {
                Ok(result) => {
                    tokens.update(|rows| {
                        if let Some(row) = rows.iter_mut().find(|row| row.id == result.id) {
                            row.token_valid = false;
                            row.revoked_at.get_or_insert_with(|| "just now".to_string());
                        }
                    });
                    feedback.set("Token revoked".to_string());
                    feedback_class.set("badge good");
                }
                Err(err) => {
                    feedback.set(server_error_message(&err, "Token revoke failed"));
                    feedback_class.set("badge bad");
                }
            }
        }
    });

    let copy_secret = move |_| {
        #[cfg(feature = "hydrate")]
        if let Some(input) = secret_input.get() {
            use wasm_bindgen::JsCast;
            input.select();
            if let Some(html_document) = web_sys::window()
                .and_then(|window| window.document())
                .and_then(|document| document.dyn_into::<web_sys::HtmlDocument>().ok())
            {
                let _ = html_document.exec_command("copy");
            }
        }
        #[cfg(not(feature = "hydrate"))]
        let _ = &secret_input;
    };

    view! {
        <Suspense fallback=|| {
            view! {
                <article
                    class="workspace-detail-panel"
                    aria-labelledby="token-admin-detail-title"
                    aria-busy="true"
                    data-api-path=admin_tokens_path()
                >
                    <div class="workspace-detail-head">
                        <div>
                            <span class="eyebrow">"Admin"</span>
                            <h2 id="token-admin-detail-title">"API token administration"</h2>
                        </div>
                        <span class="badge neutral">"Loading"</span>
                    </div>
                </article>
            }
        }>
            {move || {
                Suspend::new(async move {
                    let initial = tokens_resource.await.unwrap_or_default();
                    if !loaded.get_untracked() {
                        tokens.set(initial);
                        loaded.set(true);
                    }
                    view! {
                        <article
                            class="workspace-detail-panel"
                            aria-labelledby="token-admin-detail-title"
                            data-api-path=admin_tokens_path()
                        >
                            <div class="workspace-detail-head">
                                <div>
                                    <span class="eyebrow">"Admin"</span>
                                    <h2 id="token-admin-detail-title">"API token administration"</h2>
                                </div>
                                <span class=move || feedback_class.get()>
                                    {move || {
                                        let text = feedback.get();
                                        if text.is_empty() {
                                            "Service accounts".to_string()
                                        } else {
                                            text
                                        }
                                    }}
                                </span>
                            </div>
                            <Show when=move || revealed_secret.get().is_some() fallback=|| ()>
                                <div class="token-secret-callout" role="status" aria-live="polite">
                                    <strong>"Copy this token now — it is shown only once."</strong>
                                    <p class="table-note">
                                        "The plaintext secret is never stored or shown again. If you lose it, revoke this token and create a new one."
                                    </p>
                                    <div class="token-secret-row">
                                        <input
                                            node_ref=secret_input
                                            class="settings-input token-secret-value"
                                            type="text"
                                            readonly=true
                                            aria-label="One-time token secret"
                                            prop:value=move || revealed_secret.get().unwrap_or_default()
                                        />
                                        <button class="btn btn-secondary" on:click=copy_secret>
                                            "Copy"
                                        </button>
                                        <button
                                            class="btn btn-secondary"
                                            on:click=move |_| revealed_secret.set(None)
                                        >
                                            "Dismiss"
                                        </button>
                                    </div>
                                </div>
                            </Show>
                            <div class="workspace-detail-columns">
                                <div class="workspace-detail-list" aria-label="Existing API tokens">
                                    <div class="table-wrap">
                                        <table class="dense-table">
                                            <thead>
                                                <tr>
                                                    <th>"Name"</th>
                                                    <th>"Owner"</th>
                                                    <th>"Roles"</th>
                                                    <th>"Scopes"</th>
                                                    <th>"Last used"</th>
                                                    <th>"Expires"</th>
                                                    <th>"Status"</th>
                                                    <th>"Action"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <For
                                                    each=move || tokens.get()
                                                    key=|token| (token.id.clone(), token.revoked_at.clone())
                                                    children=move |token| {
                                                        let (status_label, status_class) = token_status(&token);
                                                        let is_revoked = token
                                                            .revoked_at
                                                            .as_deref()
                                                            .is_some_and(|v| !v.is_empty());
                                                        let roles_label = if token.roles.is_empty() {
                                                            "—".to_string()
                                                        } else {
                                                            token.roles.join(", ")
                                                        };
                                                        let scopes_label = format!(
                                                            "{} / {}",
                                                            scope_label(&token.site_scope),
                                                            scope_label(&token.environment_scope),
                                                        );
                                                        let token_id = token.id.clone();
                                                        view! {
                                                            <tr>
                                                                <td>
                                                                    <strong>{token.name.clone()}</strong>
                                                                </td>
                                                                <td>{token.owner_principal.clone()}</td>
                                                                <td>{roles_label}</td>
                                                                <td>{scopes_label}</td>
                                                                <td>{timestamp_label(&token.last_used_at)}</td>
                                                                <td>{timestamp_label(&token.expires_at)}</td>
                                                                <td>
                                                                    <span class=status_class>{status_label}</span>
                                                                </td>
                                                                <td>
                                                                    <button
                                                                        class="btn btn-secondary"
                                                                        disabled=is_revoked
                                                                        on:click=move |_| {
                                                                            revoke_action.dispatch(token_id.clone());
                                                                        }
                                                                    >
                                                                        "Revoke"
                                                                    </button>
                                                                </td>
                                                            </tr>
                                                        }
                                                    }
                                                />
                                            </tbody>
                                        </table>
                                    </div>
                                    <span class="table-note">
                                        "Token hashes are never returned to the portal; only metadata is shown."
                                    </span>
                                </div>
                                <div class="workspace-detail-list" aria-label="Create API token">
                                    <div class="workspace-detail-item">
                                        <strong>"Create service-account token"</strong>
                                        <input
                                            type="text"
                                            class="settings-input"
                                            placeholder="Token name"
                                            prop:value=move || name.get()
                                            on:input=move |ev| name.set(event_target_value(&ev))
                                        />
                                        <input
                                            type="text"
                                            class="settings-input"
                                            placeholder="Owner principal (e.g. svc:ci-pipeline)"
                                            prop:value=move || owner.get()
                                            on:input=move |ev| owner.set(event_target_value(&ev))
                                        />
                                        <span class="table-note">"Roles (select at least one)"</span>
                                        <div class="role-multiselect" aria-label="Token roles">
                                            {ALL_APP_ROLES
                                                .iter()
                                                .map(|role| {
                                                    let role = role.to_string();
                                                    let role_for_checked = role.clone();
                                                    let role_for_toggle = role.clone();
                                                    view! {
                                                        <label class="role-option">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || {
                                                                    roles.get().contains(&role_for_checked)
                                                                }
                                                                on:change=move |_| {
                                                                    roles
                                                                        .update(|selected| {
                                                                            if let Some(pos) = selected
                                                                                .iter()
                                                                                .position(|r| r == &role_for_toggle)
                                                                            {
                                                                                selected.remove(pos);
                                                                            } else {
                                                                                selected.push(role_for_toggle.clone());
                                                                            }
                                                                        });
                                                                }
                                                            />
                                                            <span>{role.clone()}</span>
                                                        </label>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                        <input
                                            type="text"
                                            class="settings-input"
                                            placeholder="Site scope (optional)"
                                            prop:value=move || site_scope.get()
                                            on:input=move |ev| site_scope.set(event_target_value(&ev))
                                        />
                                        <input
                                            type="text"
                                            class="settings-input"
                                            placeholder="Environment scope (optional)"
                                            prop:value=move || environment_scope.get()
                                            on:input=move |ev| environment_scope.set(event_target_value(&ev))
                                        />
                                        <input
                                            type="text"
                                            class="settings-input"
                                            placeholder="Expires at (RFC 3339, optional)"
                                            prop:value=move || expires_at.get()
                                            on:input=move |ev| expires_at.set(event_target_value(&ev))
                                        />
                                        <div class="settings-actions">
                                            <button
                                                class="btn btn-primary"
                                                disabled=move || {
                                                    name.get().trim().is_empty()
                                                        || owner.get().trim().is_empty()
                                                        || roles.get().is_empty()
                                                }
                                                on:click=move |_| {
                                                    let optional = |value: String| {
                                                        let value = value.trim().to_string();
                                                        (!value.is_empty()).then_some(value)
                                                    };
                                                    create_action
                                                        .dispatch(CreateTokenPayload {
                                                            name: name.get().trim().to_string(),
                                                            owner_principal: owner.get().trim().to_string(),
                                                            roles: roles.get(),
                                                            site_scope: optional(site_scope.get()),
                                                            environment_scope: optional(environment_scope.get()),
                                                            expires_at: optional(expires_at.get()),
                                                        });
                                                }
                                            >
                                                "Create token"
                                            </button>
                                        </div>
                                        <span class="table-note">
                                            "The plaintext secret is returned exactly once on creation."
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </article>
                    }
                        .into_any()
                })
            }}
        </Suspense>
    }
}

/// Admin session management: list active sessions and revoke any of them
/// (closing the self-only logout gap). Gated by the caller on `admin`.
#[component]
fn SessionAdministrationDetail() -> impl IntoView {
    let sessions_resource = Resource::new(|| (), |_| load_admin_sessions());
    let sessions = RwSignal::new(Vec::<AdminSessionSummary>::new());
    let loaded = RwSignal::new(false);
    let feedback = RwSignal::new(String::new());
    let feedback_class = RwSignal::new("badge neutral");

    let _sessions_path_guard = api_path(admin_sessions_path());

    let revoke_action = Action::new(move |session_id: &String| {
        let session_id = session_id.clone();
        async move {
            match revoke_admin_session(session_id.clone()).await {
                Ok(result) => {
                    sessions.update(|rows| rows.retain(|row| row.id != result.id));
                    feedback.set("Session revoked".to_string());
                    feedback_class.set("badge good");
                }
                Err(err) => {
                    feedback.set(server_error_message(&err, "Session revoke failed"));
                    feedback_class.set("badge bad");
                }
            }
        }
    });

    view! {
        <Suspense fallback=|| {
            view! {
                <article
                    class="workspace-detail-panel"
                    aria-labelledby="session-admin-detail-title"
                    aria-busy="true"
                    data-api-path=admin_sessions_path()
                >
                    <div class="workspace-detail-head">
                        <div>
                            <span class="eyebrow">"Admin"</span>
                            <h2 id="session-admin-detail-title">"Session administration"</h2>
                        </div>
                        <span class="badge neutral">"Loading"</span>
                    </div>
                </article>
            }
        }>
            {move || {
                Suspend::new(async move {
                    let initial = sessions_resource.await.unwrap_or_default();
                    if !loaded.get_untracked() {
                        sessions.set(initial);
                        loaded.set(true);
                    }
                    view! {
                        <article
                            class="workspace-detail-panel"
                            aria-labelledby="session-admin-detail-title"
                            data-api-path=admin_sessions_path()
                        >
                            <div class="workspace-detail-head">
                                <div>
                                    <span class="eyebrow">"Admin"</span>
                                    <h2 id="session-admin-detail-title">"Session administration"</h2>
                                </div>
                                <span class=move || feedback_class.get()>
                                    {move || {
                                        let text = feedback.get();
                                        if text.is_empty() {
                                            "Active sessions".to_string()
                                        } else {
                                            text
                                        }
                                    }}
                                </span>
                            </div>
                            <div class="workspace-detail-columns">
                                <div class="workspace-detail-list" aria-label="Active sessions">
                                    <div class="table-wrap">
                                        <table class="dense-table">
                                            <thead>
                                                <tr>
                                                    <th>"User"</th>
                                                    <th>"Display name"</th>
                                                    <th>"Roles"</th>
                                                    <th>"Provider"</th>
                                                    <th>"Expires"</th>
                                                    <th>"Action"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <For
                                                    each=move || sessions.get()
                                                    key=|session| session.id.clone()
                                                    children=move |session| {
                                                        let roles_label = if session.roles.is_empty() {
                                                            "—".to_string()
                                                        } else {
                                                            session.roles.join(", ")
                                                        };
                                                        let session_id = session.id.clone();
                                                        view! {
                                                            <tr>
                                                                <td>
                                                                    <strong>{session.user_id.clone()}</strong>
                                                                </td>
                                                                <td>{session.display_name.clone()}</td>
                                                                <td>{roles_label}</td>
                                                                <td>{scope_label(&session.provider)}</td>
                                                                <td>{timestamp_label(&session.expires_at)}</td>
                                                                <td>
                                                                    <button
                                                                        class="btn btn-secondary"
                                                                        on:click=move |_| {
                                                                            revoke_action.dispatch(session_id.clone());
                                                                        }
                                                                    >
                                                                        "Revoke"
                                                                    </button>
                                                                </td>
                                                            </tr>
                                                        }
                                                    }
                                                />
                                            </tbody>
                                        </table>
                                    </div>
                                    <span class="table-note">
                                        "Revoking a session signs that principal out immediately."
                                    </span>
                                </div>
                            </div>
                        </article>
                    }
                        .into_any()
                })
            }}
        </Suspense>
    }
}
