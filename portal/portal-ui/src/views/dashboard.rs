use crate::api::{
    activity_operation_queue_path, approval_decision_readiness_path, auth_status_path,
    boundary_status_path, catalog_offerings_path, catalog_recommendations_path,
    catalog_request_form_path, emergency_change_path, platform_health_path, platform_status_path,
    platform_summary_path, same_origin_api_path, shift_queue_path, site_catalog_path,
};
use crate::api_client::{
    evidence_summary_resource, operation_runs_resource, policy_outcomes_resource,
    secret_references_resource, ApiResource,
};
use crate::models::{
    audit_gate_fallbacks, audit_workflow_fallbacks, catalog_contract_fallbacks,
    catalog_readiness_fallbacks, policy_outcome_fallbacks,
};
use crate::server_boundary::{
    get_auth_session, get_boundary_status, get_platform_health, get_platform_status,
    load_portal_boundary_status, load_portal_inventory_capacity_status,
    load_portal_request_preflight_status, PortalActivityRunStateSnapshot,
    PortalBoundaryStatusSnapshot, PortalEvidenceSummarySnapshot, PortalInventoryCapacitySnapshot,
    PortalRequestPreflightSnapshot, PortalSecretReferenceSnapshot,
};
use leptos::prelude::*;

fn api_path(path: &'static str) -> &'static str {
    same_origin_api_path(path).unwrap_or(platform_summary_path())
}

fn resource_api_path<T>(resource: ApiResource<T>) -> &'static str {
    resource
        .same_origin_path()
        .unwrap_or(platform_summary_path())
}

#[component]
fn PortalBoundaryStatus() -> impl IntoView {
    let boundary_status = Resource::new(|| (), |_| load_portal_boundary_status());

    view! {
        <Suspense fallback=|| {
            view! {
                <section
                    class="boundary-status"
                    aria-label="Portal server boundary status"
                    aria-busy="true"
                    data-api-boundary="same-origin-platform-api"
                    data-execution-mode="static-dry-run"
                    data-http-request-allowed="false"
                    data-raw-payload-allowed="false"
                    data-secret-values-allowed="false"
                    data-customer-identifiers-allowed="false"
                >
                    <div class="boundary-copy">
                        <span class="eyebrow">"Server boundary"</span>
                        <strong>"Loading static read plans"</strong>
                        <p>"Same-origin platform API summaries; server-side planning only."</p>
                    </div>
                    <div class="boundary-flags" aria-label="Portal safety flags">
                        <span class="badge neutral">"Static/dry-run"</span>
                        <span class="badge neutral">"HTTP disabled"</span>
                        <span class="badge neutral">"Raw payloads blocked"</span>
                        <span class="badge neutral">"Secrets blocked"</span>
                    </div>
                </section>
            }
        }>
            {move || {
                Suspend::new(async move {
                    match boundary_status.await {
                        Ok(snapshot) => {
                            let snapshot: PortalBoundaryStatusSnapshot = snapshot;
                            let read_plan_count = snapshot.read_plans.len();
                            let api_boundary = snapshot.api_boundary.clone();
                            let execution_mode = snapshot.execution_mode.clone();
                            let http_request_allowed = snapshot.http_request_allowed.to_string();
                            let raw_payload_allowed = snapshot.raw_payload_allowed.to_string();
                            let secret_values_allowed = snapshot.secret_values_allowed.to_string();
                            let customer_identifiers_allowed =
                                snapshot.customer_identifiers_allowed.to_string();
                            let read_plans = snapshot.read_plans;

                            view! {
                                <section
                                    class="boundary-status"
                                    aria-label="Portal server boundary status"
                                    data-api-boundary=api_boundary
                                    data-execution-mode=execution_mode
                                    data-http-request-allowed=http_request_allowed
                                    data-raw-payload-allowed=raw_payload_allowed
                                    data-secret-values-allowed=secret_values_allowed
                                    data-customer-identifiers-allowed=customer_identifiers_allowed
                                >
                                    <div class="boundary-copy">
                                        <span class="eyebrow">"Server boundary"</span>
                                        <strong>{read_plan_count} " static read plans"</strong>
                                        <p>"Same-origin platform API summaries; server-side planning only."</p>
                                    </div>
                                    <div class="boundary-flags" aria-label="Portal safety flags">
                                        <span class="badge neutral">"Static/dry-run"</span>
                                        <span class="badge neutral">"HTTP disabled"</span>
                                        <span class="badge neutral">"Raw payloads blocked"</span>
                                        <span class="badge neutral">"Secrets blocked"</span>
                                    </div>
                                    <div class="boundary-read-plans" aria-label="Core platform read plans">
                                        {read_plans
                                            .into_iter()
                                            .map(|plan| {
                                                let path = plan.path.clone();
                                                let resource_label_attr = plan.resource_label.clone();
                                                let resource_label_text = plan.resource_label;
                                                view! {
                                                    <span
                                                        class="boundary-chip"
                                                        data-api-path=path
                                                        data-resource=resource_label_attr
                                                    >
                                                        {resource_label_text}
                                                    </span>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                </section>
                            }
                                .into_any()
                        }
                        Err(_) => view! {
                            <section
                                class="boundary-status"
                                aria-label="Portal server boundary status"
                                data-api-boundary="same-origin-platform-api"
                                data-execution-mode="static-dry-run"
                                data-http-request-allowed="false"
                                data-raw-payload-allowed="false"
                                data-secret-values-allowed="false"
                                data-customer-identifiers-allowed="false"
                            >
                                <div class="boundary-copy">
                                    <span class="eyebrow">"Server boundary"</span>
                                    <strong>"Boundary status unavailable"</strong>
                                    <p>"Portal server boundary status remains unavailable from the static server boundary."</p>
                                </div>
                                <div class="boundary-flags" aria-label="Portal safety flags">
                                    <span class="badge neutral">"Static/dry-run"</span>
                                    <span class="badge neutral">"HTTP disabled"</span>
                                    <span class="badge neutral">"Raw payloads blocked"</span>
                                    <span class="badge neutral">"Secrets blocked"</span>
                                </div>
                            </section>
                        }
                            .into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn PortalRequestPreflightStatus() -> impl IntoView {
    let request_preflight_status = Resource::new(|| (), |_| load_portal_request_preflight_status());

    view! {
        <Suspense fallback=|| {
            view! {
                <section
                    class="contract-grid request-plan-grid"
                    aria-label="Request intake and dry-run planning summaries"
                    aria-busy="true"
                >
                    <article
                        class="panel contract-panel"
                        data-api-path=platform_summary_path()
                        data-preflight-path=platform_summary_path()
                        data-http-request-allowed="false"
                        data-provider-calls-allowed="false"
                        data-live-execution-allowed="false"
                        data-raw-payload-allowed="false"
                        data-secret-values-allowed="false"
                        data-customer-identifiers-allowed="false"
                    >
                        <div class="panel-head">
                            <div>
                                <span class="eyebrow">"Requests"</span>
                                <h2>"Request intake"</h2>
                            </div>
                            <span class="table-note">"Preflight loading"</span>
                        </div>
                        <div class="contract-list">
                            <div class="contract-item">
                                <span class="badge warn">"Preflight required"</span>
                                <strong>"Static request preflight"</strong>
                                <p>"Request preflight status is loading from the static server boundary."</p>
                                <span class="table-note">"Provider calls, live mutation, and raw payload exposure remain blocked"</span>
                            </div>
                        </div>
                    </article>

                    <article class="panel contract-panel" data-api-path=platform_summary_path()>
                        <div class="panel-head">
                            <div>
                                <span class="eyebrow">"Planning"</span>
                                <h2>"Dry-run execution plan"</h2>
                            </div>
                            <span class="table-note">"Execution blocked"</span>
                        </div>
                        <div class="contract-list">
                            <div class="contract-item">
                                <span class="badge bad">"Execution blocked"</span>
                                <strong>"Dry-run only"</strong>
                                <p>"Dry-run plan status is loading from the static server boundary."</p>
                                <span class="table-note">"No live mutation or provider-side execution"</span>
                            </div>
                        </div>
                    </article>
                </section>
            }
        }>
            {move || {
                Suspend::new(async move {
                    match request_preflight_status.await {
                        Ok(snapshot) => {
                            let snapshot: PortalRequestPreflightSnapshot = snapshot;
                            let request_api_path = snapshot.request_intake_path.clone();
                            let preflight_api_path = snapshot.preflight_path.clone();
                            let dry_run_api_path = snapshot.dry_run_plan_path.clone();
                            let preflight_gate_state = snapshot.preflight_gate_state.clone();
                            let request_http_request_allowed =
                                snapshot.http_request_allowed.to_string();
                            let request_provider_calls_allowed =
                                snapshot.provider_calls_allowed.to_string();
                            let request_live_execution_allowed =
                                snapshot.live_execution_allowed.to_string();
                            let request_raw_payload_allowed =
                                snapshot.raw_payload_allowed.to_string();
                            let request_secret_values_allowed =
                                snapshot.secret_values_allowed.to_string();
                            let request_customer_identifiers_allowed =
                                snapshot.customer_identifiers_allowed.to_string();
                            let request_summaries = snapshot.request_intake;
                            let dry_run_plans = snapshot.dry_run_plans;

                            view! {
                                <section
                                    class="contract-grid request-plan-grid"
                                    aria-label="Request intake and dry-run planning summaries"
                                >
                                    <article
                                        class="panel contract-panel"
                                        data-api-path=request_api_path
                                        data-preflight-path=preflight_api_path
                                        data-http-request-allowed=request_http_request_allowed
                                        data-provider-calls-allowed=request_provider_calls_allowed
                                        data-live-execution-allowed=request_live_execution_allowed
                                        data-raw-payload-allowed=request_raw_payload_allowed
                                        data-secret-values-allowed=request_secret_values_allowed
                                        data-customer-identifiers-allowed=request_customer_identifiers_allowed
                                    >
                                        <div class="panel-head">
                                            <div>
                                                <span class="eyebrow">"Requests"</span>
                                                <h2>"Request intake"</h2>
                                            </div>
                                            <span class="table-note">{preflight_gate_state}</span>
                                        </div>
                                        <div class="contract-list">
                                            {request_summaries
                                                .into_iter()
                                                .map(|summary| {
                                                    view! {
                                                        <div class="contract-item">
                                                            <span class="badge warn">{summary.validation_state}</span>
                                                            <strong>{summary.stage}</strong>
                                                            <p>{summary.safe_summary}</p>
                                                            <span class="table-note">{summary.approval_state}</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    </article>

                                    <article class="panel contract-panel" data-api-path=dry_run_api_path>
                                        <div class="panel-head">
                                            <div>
                                                <span class="eyebrow">"Planning"</span>
                                                <h2>"Dry-run execution plan"</h2>
                                            </div>
                                            <span class="table-note">"Execution blocked"</span>
                                        </div>
                                        <div class="contract-list">
                                            {dry_run_plans
                                                .into_iter()
                                                .map(|plan| {
                                                    let execution_state = if plan.execution_allowed {
                                                        "Execution allowed"
                                                    } else {
                                                        "Execution blocked"
                                                    };
                                                    let run_state = if plan.dry_run {
                                                        "Dry-run only"
                                                    } else {
                                                        "Execution disabled"
                                                    };
                                                    view! {
                                                        <div class="contract-item">
                                                            <span class="badge bad">{execution_state}</span>
                                                            <strong>{plan.workflow}</strong>
                                                            <p>{plan.safe_summary}</p>
                                                            <span class="table-note">{run_state} " / " {plan.required_gate}</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    </article>
                                </section>
                            }
                                .into_any()
                        }
                        Err(_) => view! {
                            <section
                                class="contract-grid request-plan-grid"
                                aria-label="Request intake and dry-run planning summaries"
                                data-http-request-allowed="false"
                                data-provider-calls-allowed="false"
                                data-live-execution-allowed="false"
                                data-raw-payload-allowed="false"
                                data-secret-values-allowed="false"
                                data-customer-identifiers-allowed="false"
                            >
                                <article
                                    class="panel contract-panel"
                                    data-api-path=platform_summary_path()
                                    data-preflight-path=platform_summary_path()
                                >
                                    <div class="panel-head">
                                        <div>
                                            <span class="eyebrow">"Requests"</span>
                                            <h2>"Request intake"</h2>
                                        </div>
                                        <span class="table-note">"Preflight unavailable"</span>
                                    </div>
                                    <div class="contract-list">
                                        <div class="contract-item">
                                            <span class="badge warn">"Preflight required"</span>
                                            <strong>"Request preflight unavailable"</strong>
                                            <p>"Request preflight status remains unavailable from the static server boundary."</p>
                                            <span class="table-note">"Provider calls, live mutation, and raw payload exposure remain blocked"</span>
                                        </div>
                                    </div>
                                </article>

                                <article class="panel contract-panel" data-api-path=platform_summary_path()>
                                    <div class="panel-head">
                                        <div>
                                            <span class="eyebrow">"Planning"</span>
                                            <h2>"Dry-run execution plan"</h2>
                                        </div>
                                        <span class="table-note">"Execution blocked"</span>
                                    </div>
                                    <div class="contract-list">
                                        <div class="contract-item">
                                            <span class="badge bad">"Execution blocked"</span>
                                            <strong>"Dry-run only"</strong>
                                            <p>"Dry-run execution plans remain unavailable from the static server boundary."</p>
                                            <span class="table-note">"No live mutation or provider-side execution"</span>
                                        </div>
                                    </div>
                                </article>
                            </section>
                        }
                            .into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn PortalInventoryCapacityStatus() -> impl IntoView {
    let inventory_capacity_status =
        Resource::new(|| (), |_| load_portal_inventory_capacity_status());

    view! {
        <Suspense fallback=|| {
            view! {
                <section
                    class="contract-grid inventory-capacity-grid"
                    aria-label="Inventory and capacity summaries"
                    aria-busy="true"
                >
                    <article
                        class="panel contract-panel"
                        data-api-path=platform_summary_path()
                        data-risk-path=platform_summary_path()
                        data-inventory-read-only="true"
                        data-http-request-allowed="false"
                        data-provider-calls-allowed="false"
                        data-raw-inventory-rows-allowed="false"
                    >
                        <div class="panel-head">
                            <div>
                                <span class="eyebrow">"Inventory"</span>
                                <h2>"Inventory overview"</h2>
                            </div>
                            <span class="table-note">"Inventory capacity loading"</span>
                        </div>
                        <div class="contract-list">
                            <div class="contract-item">
                                <span class="badge neutral">"Read-only inventory"</span>
                                <strong>"Static inventory capacity"</strong>
                                <p>"Inventory capacity status is loading from the static server boundary."</p>
                                <span class="table-note">"Provider calls and raw inventory rows remain blocked"</span>
                            </div>
                        </div>
                    </article>

                    <article
                        class="panel contract-panel"
                        data-api-path=platform_summary_path()
                        data-stale-data-blocks-execution="true"
                        data-capacity-execution-allowed="false"
                    >
                        <div class="panel-head">
                            <div>
                                <span class="eyebrow">"Capacity"</span>
                                <h2>"Capacity admission"</h2>
                            </div>
                            <span class="table-note">"Stale data blocks execution"</span>
                        </div>
                        <div class="contract-list">
                            <div class="contract-item">
                                <span class="badge bad">"Execution blocked"</span>
                                <strong>"Capacity admission loading"</strong>
                                <p>"Capacity admission remains blocked while the static server boundary loads."</p>
                                <span class="table-note">"No live capacity execution"</span>
                            </div>
                        </div>
                    </article>
                </section>
            }
        }>
            {move || {
                Suspend::new(async move {
                    match inventory_capacity_status.await {
                        Ok(snapshot) => {
                            let snapshot: PortalInventoryCapacitySnapshot = snapshot;
                            let inventory_api_path = snapshot.inventory_resource_path.clone();
                            let inventory_risk_api_path = snapshot.ownership_risk_path.clone();
                            let capacity_api_path = snapshot.capacity_admission_path.clone();
                            let inventory_read_only = snapshot.inventory_read_only.to_string();
                            let stale_data_blocks_execution =
                                snapshot.stale_data_blocks_execution.to_string();
                            let capacity_execution_allowed =
                                snapshot.capacity_execution_allowed.to_string();
                            let inventory_http_request_allowed =
                                snapshot.http_request_allowed.to_string();
                            let inventory_provider_calls_allowed =
                                snapshot.provider_calls_allowed.to_string();
                            let raw_inventory_rows_allowed =
                                snapshot.raw_inventory_rows_allowed.to_string();
                            let inventory_resources = snapshot.inventory_resources;
                            let capacity_admissions = snapshot.capacity_admissions;

                            view! {
                                <section class="contract-grid inventory-capacity-grid" aria-label="Inventory and capacity summaries">
                                    <article
                                        class="panel contract-panel"
                                        data-api-path=inventory_api_path
                                        data-risk-path=inventory_risk_api_path
                                        data-inventory-read-only=inventory_read_only
                                        data-http-request-allowed=inventory_http_request_allowed
                                        data-provider-calls-allowed=inventory_provider_calls_allowed
                                        data-raw-inventory-rows-allowed=raw_inventory_rows_allowed
                                    >
                                        <div class="panel-head">
                                            <div>
                                                <span class="eyebrow">"Inventory"</span>
                                                <h2>"Inventory overview"</h2>
                                            </div>
                                            <span class="table-note">"Read-only inventory"</span>
                                        </div>
                                        <div class="contract-list">
                                            {inventory_resources
                                                .into_iter()
                                                .map(|resource| {
                                                    let freshness_badge = if resource.freshness_state.contains("stale") {
                                                        "badge stale"
                                                    } else {
                                                        "badge neutral"
                                                    };
                                                    view! {
                                                        <div class="contract-item">
                                                            <span class=freshness_badge>{resource.freshness_state}</span>
                                                            <strong>{resource.view}</strong>
                                                            <p>{resource.safe_summary}</p>
                                                            <span class="table-note">{resource.coverage_state} " / " {resource.evidence_state}</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    </article>

                                    <article
                                        class="panel contract-panel"
                                        data-api-path=capacity_api_path
                                        data-stale-data-blocks-execution=stale_data_blocks_execution
                                        data-capacity-execution-allowed=capacity_execution_allowed
                                    >
                                        <div class="panel-head">
                                            <div>
                                                <span class="eyebrow">"Capacity"</span>
                                                <h2>"Capacity admission"</h2>
                                            </div>
                                            <span class="table-note">"Stale data blocks execution"</span>
                                        </div>
                                        <div class="contract-list">
                                            {capacity_admissions
                                                .into_iter()
                                                .map(|admission| {
                                                    let execution_state = if admission.execution_allowed {
                                                        "Execution allowed"
                                                    } else {
                                                        "Execution blocked"
                                                    };
                                                    view! {
                                                        <div class="contract-item">
                                                            <span class="badge bad">{execution_state}</span>
                                                            <strong>{admission.scope}</strong>
                                                            <p>{admission.safe_summary}</p>
                                                            <span class="table-note">{admission.admission_state} " / " {admission.headroom_state}</span>
                                                        </div>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    </article>
                                </section>
                            }
                                .into_any()
                        }
                        Err(_) => view! {
                            <section
                                class="contract-grid inventory-capacity-grid"
                                aria-label="Inventory and capacity summaries"
                                data-inventory-read-only="true"
                                data-http-request-allowed="false"
                                data-provider-calls-allowed="false"
                                data-raw-inventory-rows-allowed="false"
                                data-stale-data-blocks-execution="true"
                                data-capacity-execution-allowed="false"
                            >
                                <article
                                    class="panel contract-panel"
                                    data-api-path=platform_summary_path()
                                    data-risk-path=platform_summary_path()
                                >
                                    <div class="panel-head">
                                        <div>
                                            <span class="eyebrow">"Inventory"</span>
                                            <h2>"Inventory overview"</h2>
                                        </div>
                                        <span class="table-note">"Inventory capacity unavailable"</span>
                                    </div>
                                    <div class="contract-list">
                                        <div class="contract-item">
                                            <span class="badge neutral">"Read-only inventory"</span>
                                            <strong>"Static inventory capacity unavailable"</strong>
                                            <p>"Inventory capacity status remains unavailable from the static server boundary."</p>
                                            <span class="table-note">"Provider calls and raw inventory rows remain blocked"</span>
                                        </div>
                                    </div>
                                </article>

                                <article class="panel contract-panel" data-api-path=platform_summary_path()>
                                    <div class="panel-head">
                                        <div>
                                            <span class="eyebrow">"Capacity"</span>
                                            <h2>"Capacity admission"</h2>
                                        </div>
                                        <span class="table-note">"Stale data blocks execution"</span>
                                    </div>
                                    <div class="contract-list">
                                        <div class="contract-item">
                                            <span class="badge bad">"Execution blocked"</span>
                                            <strong>"Capacity admission unavailable"</strong>
                                            <p>"Capacity admission remains blocked while the static server boundary is unavailable."</p>
                                            <span class="table-note">"No live capacity execution"</span>
                                        </div>
                                    </div>
                                </article>
                            </section>
                        }
                            .into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn PlatformStatusSection() -> impl IntoView {
    let platform_status = Resource::new(|| (), |_| get_platform_status());
    let platform_health = Resource::new(|| (), |_| get_platform_health());
    let _platform_status_path_guard = api_path(platform_status_path());
    let _platform_health_path_guard = api_path(platform_health_path());
    let _boundary_status_path_guard = api_path(boundary_status_path());

    view! {
        <Suspense fallback=|| {
            view! {
                <section
                    class="contract-grid platform-status-grid"
                    aria-label="Platform status"
                    aria-busy="true"
                    data-api-path=platform_status_path()
                    data-health-path=platform_health_path()
                    data-execution-mode="static-dry-run"
                >
                    <article class="panel contract-panel" data-api-path=platform_status_path()>
                        <div class="panel-head">
                            <div>
                                <span class="eyebrow">"Platform"</span>
                                <h2>"Platform status"</h2>
                            </div>
                            <span class="table-note">"Loading"</span>
                        </div>
                        <div class="contract-list">
                            <div class="contract-item">
                                <span class="badge neutral">"Loading"</span>
                                <strong>"Platform status"</strong>
                                <p>"Platform status is loading from the static server boundary."</p>
                            </div>
                        </div>
                    </article>
                </section>
            }
        }>
            {move || {
                Suspend::new(async move {
                    let status_result = platform_status.await;
                    let health_result = platform_health.await;

                    let api_status = status_result
                        .as_ref()
                        .map(|s| s.api_status.clone())
                        .unwrap_or_else(|_| "unavailable".to_string());
                    let portal_status = status_result
                        .as_ref()
                        .map(|s| s.portal_status.clone())
                        .unwrap_or_else(|_| "unavailable".to_string());
                    let validator_status = status_result
                        .as_ref()
                        .map(|s| s.validator_status.clone())
                        .unwrap_or_else(|_| "unavailable".to_string());
                    let boundary_mode = status_result
                        .as_ref()
                        .map(|s| s.boundary_mode.clone())
                        .unwrap_or_else(|_| "static-dry-run".to_string());

                    let api_badge_class = if api_status == "healthy" { "badge good" } else { "badge bad" };
                    let portal_badge_class = if portal_status == "healthy" { "badge good" } else { "badge bad" };
                    let validator_badge_class = if validator_status == "passing" { "badge good" } else { "badge warn" };

                    let overall = health_result
                        .as_ref()
                        .map(|h| h.overall_status.clone())
                        .unwrap_or_else(|_| "unavailable".to_string());
                    let checks: Vec<_> = health_result
                        .as_ref()
                        .map(|h| h.checks.clone())
                        .unwrap_or_else(|_| vec![]);
                    let timestamp = health_result
                        .as_ref()
                        .map(|h| h.timestamp.clone())
                        .unwrap_or_else(|_| "unknown".to_string());

                    view! {
                        <section class="contract-grid platform-status-grid" aria-label="Platform status">
                            <article
                                class="panel contract-panel"
                                data-api-path=platform_status_path()
                                data-health-path=platform_health_path()
                                data-execution-mode=boundary_mode.clone()
                            >
                                <div class="panel-head">
                                    <div>
                                        <span class="eyebrow">"Platform"</span>
                                        <h2>"Platform status"</h2>
                                    </div>
                                    <span class="table-note">{overall.clone()}</span>
                                </div>
                                <div class="contract-list">
                                    <div class="contract-item">
                                        <span class=api_badge_class>{api_status}</span>
                                        <strong>"API status"</strong>
                                        <p>"Same-origin platform API gateway"</p>
                                    </div>
                                    <div class="contract-item">
                                        <span class=portal_badge_class>{portal_status}</span>
                                        <strong>"Portal status"</strong>
                                        <p>"Static shell serving safe summaries"</p>
                                    </div>
                                    <div class="contract-item">
                                        <span class=validator_badge_class>{validator_status}</span>
                                        <strong>"Validator status"</strong>
                                        <p>"Guardrail and contract checks passing"</p>
                                    </div>
                                    <div class="contract-item">
                                        <span class="badge neutral">{boundary_mode.clone()}</span>
                                        <strong>"Boundary mode"</strong>
                                        <p>"All provider calls, secrets, and raw payloads blocked"</p>
                                    </div>
                                </div>
                            </article>

                            <article class="panel contract-panel" data-api-path=platform_health_path()>
                                <div class="panel-head">
                                    <div>
                                        <span class="eyebrow">"Health"</span>
                                        <h2>"Component health"</h2>
                                    </div>
                                    <span class="table-note">{timestamp}</span>
                                </div>
                                <div class="contract-list">
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
                                                <div class="contract-item">
                                                    <span class=check_badge_class>{check.status}</span>
                                                    <strong>{check.name}</strong>
                                                    <p>{check.message}</p>
                                                    <span class="table-note">{check.component} " / " {check.last_check}</span>
                                                </div>
                                            }
                                        })
                                        .collect_view()}
                                </div>
                            </article>
                        </section>
                    }
                        .into_any()
                })
            }}
        </Suspense>
    }
}

#[component]
fn AuthStatusSection() -> impl IntoView {
    let auth_session = Resource::new(|| (), |_| get_auth_session());
    let boundary_status = Resource::new(|| (), |_| get_boundary_status());
    let _auth_status_path_guard = api_path(auth_status_path());
    let _boundary_status_path_guard = api_path(boundary_status_path());

    view! {
        <Suspense fallback=|| {
            view! {
                <section
                    class="contract-grid auth-status-grid"
                    aria-label="Auth status"
                    aria-busy="true"
                    data-api-path=auth_status_path()
                    data-execution-mode="static-dry-run"
                >
                    <article class="panel contract-panel" data-api-path=auth_status_path()>
                        <div class="panel-head">
                            <div>
                                <span class="eyebrow">"Auth"</span>
                                <h2>"Authentication status"</h2>
                            </div>
                            <span class="table-note">"Loading"</span>
                        </div>
                        <div class="contract-list">
                            <div class="contract-item">
                                <span class="badge neutral">"Loading"</span>
                                <strong>"Auth session"</strong>
                                <p>"Authentication status is loading from the static server boundary."</p>
                            </div>
                        </div>
                    </article>
                </section>
            }
        }>
            {move || {
                Suspend::new(async move {
                    let session_result = auth_session.await;
                    let boundary_result = boundary_status.await;

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

                    view! {
                        <section class="contract-grid auth-status-grid" aria-label="Auth status">
                            <article
                                class="panel contract-panel"
                                data-api-path=auth_status_path()
                                data-execution-mode=execution_mode.clone()
                                data-http-request-allowed=http_allowed
                                data-provider-calls-allowed=provider_allowed
                                data-live-execution-allowed=live_allowed
                            >
                                <div class="panel-head">
                                    <div>
                                        <span class="eyebrow">"Auth"</span>
                                        <h2>"Authentication status"</h2>
                                    </div>
                                    <span class="badge good">"Static session"</span>
                                </div>
                                <div class="contract-list">
                                    <div class="contract-item">
                                        <span class="badge neutral">{user_id}</span>
                                        <strong>{display_name}</strong>
                                        <p>"Static dry-run auth session"</p>
                                    </div>
                                    <div class="contract-item">
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
                                    <div class="contract-item">
                                        <span class="badge neutral">{execution_mode.clone()}</span>
                                        <strong>"Auth mode"</strong>
                                        <p>"Static dry-run authentication; no live provider identity checks"</p>
                                    </div>
                                </div>
                            </article>
                        </section>
                    }
                        .into_any()
                })
            }}
        </Suspense>
    }
}

#[component]
pub fn DashboardView() -> impl IntoView {
    let policy_api_path = resource_api_path(policy_outcomes_resource());
    let activity_snapshot = PortalActivityRunStateSnapshot::static_dry_run()
        .expect("activity run state must be allowlisted");
    let _activity_queue_path_guard = api_path(activity_operation_queue_path());
    let _shift_queue_path_guard = api_path(shift_queue_path());
    let activity_queue_api_path = activity_snapshot.activity_queue_path.clone();
    let shift_queue_api_path = activity_snapshot.shift_queue_path.clone();
    let operation_api_path = activity_snapshot.run_state_path.clone();
    let queue_state = activity_snapshot.queue_state.clone();
    let run_state = activity_snapshot.run_state.clone();
    let worker_execution_allowed = activity_snapshot.worker_execution_allowed.to_string();
    let retry_execution_allowed = activity_snapshot.retry_execution_allowed.to_string();
    let activity_provider_calls_allowed = activity_snapshot.provider_calls_allowed.to_string();
    let activity_live_execution_allowed = activity_snapshot.live_execution_allowed.to_string();
    let raw_logs_allowed = activity_snapshot.raw_logs_allowed.to_string();
    let activity_queue = activity_snapshot.activity_queue;
    let operation_runs = activity_snapshot.operation_runs;
    let _operation_resource_guard = resource_api_path(operation_runs_resource());
    let evidence_snapshot = PortalEvidenceSummarySnapshot::static_dry_run()
        .expect("evidence summary status must be allowlisted");
    let _evidence_resource_guard = resource_api_path(evidence_summary_resource());
    let evidence_api_path = evidence_snapshot.evidence_summary_path.clone();
    let evidence_retention_api_path = evidence_snapshot.retention_path.clone();
    let evidence_redaction_required = evidence_snapshot.redaction_required.to_string();
    let evidence_export_allowed = evidence_snapshot.export_allowed.to_string();
    let evidence_http_request_allowed = evidence_snapshot.http_request_allowed.to_string();
    let evidence_provider_calls_allowed = evidence_snapshot.provider_calls_allowed.to_string();
    let raw_evidence_payloads_allowed = evidence_snapshot.raw_evidence_payloads_allowed.to_string();
    let evidence_summaries = evidence_snapshot.evidence_summaries;
    let secret_reference_snapshot = PortalSecretReferenceSnapshot::static_dry_run()
        .expect("secret reference status must be allowlisted");
    let _secret_reference_resource_guard = resource_api_path(secret_references_resource());
    let secret_reference_api_path = secret_reference_snapshot.secret_references_path.clone();
    let secret_reference_provider = secret_reference_snapshot.provider.clone();
    let secret_reference_management_cli = secret_reference_snapshot.management_cli.clone();
    let secret_reference_readiness_state = secret_reference_snapshot.readiness_state.clone();
    let secret_reference_configured_for_production = secret_reference_snapshot
        .configured_for_production
        .to_string();
    let secret_live_cli_execution_allowed = secret_reference_snapshot
        .live_cli_execution_allowed
        .to_string();
    let secret_provider_calls_allowed =
        secret_reference_snapshot.provider_calls_allowed.to_string();
    let secret_values_allowed = secret_reference_snapshot.secret_values_allowed.to_string();
    let secret_provider_paths_allowed =
        secret_reference_snapshot.provider_paths_allowed.to_string();
    let secret_references = secret_reference_snapshot.secret_references;
    let catalog_api_path = api_path(catalog_offerings_path());
    let catalog_recommendations_api_path = api_path(catalog_recommendations_path());
    let catalog_request_form_api_path = api_path(catalog_request_form_path());
    let site_catalog_api_path = api_path(site_catalog_path());
    let approval_decision_api_path = api_path(approval_decision_readiness_path());
    let emergency_change_api_path = api_path(emergency_change_path());
    let catalog_contracts = catalog_contract_fallbacks();
    let catalog_readiness = catalog_readiness_fallbacks();
    let audit_workflows = audit_workflow_fallbacks();
    let _audit_gates = audit_gate_fallbacks();
    let policy_outcomes = policy_outcome_fallbacks();

    view! {
        <PortalBoundaryStatus/>

        <section class="cards" aria-label="Dashboard summary cards">
            <article class="card healthy">
                <span class="label">"Platform health"</span>
                <strong>"7 healthy / 2 warning"</strong>
                <p>"Portal, API, queue, workers, database, ingress, adapter readiness."</p>
                <span class="badge good">"Healthy"</span>
            </article>
            <article class="card warning">
                <span class="label">"Site readiness"</span>
                <strong>"9 ready / 2 blocked"</strong>
                <p>"Capacity, network, placement, firmware, and support coverage."</p>
                <span class="badge warn">"Review"</span>
            </article>
            <article class="card">
                <span class="label">"Open requests"</span>
                <strong>"31 open"</strong>
                <p>"6 awaiting approval, 4 at SLA risk, 1 emergency change."</p>
                <span class="badge neutral">"Approval"</span>
            </article>
            <article class="card critical">
                <span class="label">"Failed operations"</span>
                <strong>"5 failed / 2 retry-safe"</strong>
                <p>"Safe summaries only; evidence redacted before handover."</p>
                <span class="badge bad">"Failed"</span>
            </article>
            <article class="card warning">
                <span class="label">"Backup risk"</span>
                <strong>"18 gaps / 3 critical"</strong>
                <p>"Repository pressure, replica gaps, app-aware checks, restore tests."</p>
                <span class="badge warn">"Gap"</span>
            </article>
            <article class="card warning">
                <span class="label">"Monitoring gaps"</span>
                <strong>"42 assets"</strong>
                <p>"Host, template, proxy, owner, and alert-route reviews."</p>
                <span class="badge warn">"Drift"</span>
            </article>
            <article class="card stale">
                <span class="label">"Stale data"</span>
                <strong>"4 sources tracked"</strong>
                <p>"Freshness state controls whether workflows stay read-only."</p>
                <span class="badge stale">"Read-only if stale"</span>
            </article>
        </section>

        <PlatformStatusSection/>

        <AuthStatusSection/>

        <PortalRequestPreflightStatus/>

        <section class="contract-grid catalog-contract-grid" aria-label="Catalog contract summaries">
            <article class="panel contract-panel" data-api-path=catalog_api_path data-recommendations-path=catalog_recommendations_api_path data-form-path=catalog_request_form_api_path>
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">"Catalog"</span>
                        <h2>"Catalog contracts"</h2>
                    </div>
                    <span class="table-note">"Static catalog source"</span>
                </div>
                <div class="contract-list">
                    {catalog_contracts
                        .into_iter()
                        .map(|contract| {
                            view! {
                                <div class="contract-item">
                                    <span class="badge neutral">{contract.readiness_state}</span>
                                    <strong>{contract.category}</strong>
                                    <p>{contract.safe_summary}</p>
                                    <span class="table-note">{contract.request_form_state} " / " {contract.recommendation_state}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </article>

            <article class="panel contract-panel" data-api-path=site_catalog_api_path>
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">"Governance"</span>
                        <h2>"Offering readiness"</h2>
                    </div>
                    <span class="table-note">"Request forms aligned"</span>
                </div>
                <div class="contract-list">
                    {catalog_readiness
                        .into_iter()
                        .map(|readiness| {
                            view! {
                                <div class="contract-item">
                                    <span class="badge warn">{readiness.readiness_state}</span>
                                    <strong>{readiness.surface}</strong>
                                    <p>{readiness.safe_summary}</p>
                                    <span class="table-note">{readiness.site_binding_state}</span>
                                </div>
                            }
                    })
                    .collect_view()}
                </div>
            </article>

            <article
                class="panel contract-panel"
                data-secret-reference-readiness="true"
                data-api-path=secret_reference_api_path
                data-provider=secret_reference_provider
                data-management-cli=secret_reference_management_cli
                data-configured-for-production=secret_reference_configured_for_production
                data-live-cli-execution-allowed=secret_live_cli_execution_allowed
                data-provider-calls-allowed=secret_provider_calls_allowed
                data-secret-values-allowed=secret_values_allowed
                data-provider-paths-allowed=secret_provider_paths_allowed
            >
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">"Secrets"</span>
                        <h2>"Secret-reference readiness"</h2>
                    </div>
                    <span class="table-note">{secret_reference_readiness_state}</span>
                </div>
                <div class="contract-list">
                    {secret_references
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
                                <div class="contract-item">
                                    <span class="badge bad">{cli_state}</span>
                                    <strong>{reference.consumer_scope}</strong>
                                    <p>{reference.safe_summary}</p>
                                    <span class="table-note">{reference.provider} " / " {reference.management_cli} " / " {reference.rotation_state} " / " {value_state} " / " {path_state}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </article>
        </section>

        <PortalInventoryCapacityStatus/>

        <section class="contract-grid audit-workflow-grid" aria-label="Audit-safe workflow summaries">
            <article class="panel contract-panel" data-api-path=approval_decision_api_path data-activity-path=activity_queue_api_path.clone()>
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">"Audit"</span>
                        <h2>"Audit-safe workflows"</h2>
                    </div>
                    <span class="table-note">"Approval gates"</span>
                </div>
                <div class="contract-list">
                    {audit_workflows
                        .into_iter()
                        .map(|workflow| {
                            let execution_state = if workflow.execution_allowed {
                                "Execution allowed"
                            } else {
                                "Execution blocked"
                            };
                            view! {
                                <div class="contract-item">
                                    <span class="badge bad">{execution_state}</span>
                                    <strong>{workflow.workflow}</strong>
                                    <p>{workflow.safe_summary}</p>
                                    <span class="table-note">{workflow.approval_state} " / " {workflow.queue_state} " / " {workflow.evidence_state}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </article>

            <article
                class="panel contract-panel"
                data-api-path=activity_queue_api_path
                data-shift-path=shift_queue_api_path
                data-emergency-path=emergency_change_api_path
                data-queue-state=queue_state
                data-worker-execution-allowed=worker_execution_allowed
                data-retry-execution-allowed=retry_execution_allowed
                data-provider-calls-allowed=activity_provider_calls_allowed
                data-live-execution-allowed=activity_live_execution_allowed
                data-raw-logs-allowed=raw_logs_allowed
            >
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">"Activity"</span>
                        <h2>"Activity queue"</h2>
                    </div>
                    <span class="table-note">"Worker execution blocked"</span>
                </div>
                <div class="contract-list">
                    {activity_queue
                        .into_iter()
                        .map(|item| {
                            let worker_state = if item.worker_execution_allowed {
                                "Worker execution allowed"
                            } else {
                                "Worker execution blocked"
                            };
                            view! {
                                <div class="contract-item">
                                    <span class="badge bad">{worker_state}</span>
                                    <strong>{item.queue}</strong>
                                    <p>{item.safe_summary}</p>
                                    <span class="table-note">{item.queue_state} " / " {item.lock_state} " / " {item.retry_state} " / " {item.handover_state}</span>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </article>
        </section>

        <section class="contract-grid" aria-label="Policy, evidence, and run state summaries">
            <article class="panel contract-panel" data-api-path=policy_api_path>
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">"Guardrails"</span>
                        <h2>"Policy guardrails"</h2>
                    </div>
                    <span class="table-note">"Static contract fallback"</span>
                </div>
                <div class="contract-list">
                    {policy_outcomes
                        .into_iter()
                        .map(|outcome| {
                            view! {
                                <div class="contract-item">
                                    <span class="badge bad">{outcome.decision}</span>
                                    <strong>{outcome.id}</strong>
                                    <p>{outcome.safe_summary}</p>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </article>

            <article
                class="panel contract-panel"
                data-api-path=evidence_api_path
                data-retention-path=evidence_retention_api_path
                data-redaction-required=evidence_redaction_required
                data-export-allowed=evidence_export_allowed
                data-http-request-allowed=evidence_http_request_allowed
                data-provider-calls-allowed=evidence_provider_calls_allowed
                data-raw-evidence-payloads-allowed=raw_evidence_payloads_allowed
            >
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">"Audit"</span>
                        <h2>"Evidence redaction"</h2>
                    </div>
                    <span class="table-note">"Export blocked until redacted"</span>
                </div>
                <div class="contract-list">
                    {evidence_summaries
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
                                <div class="contract-item">
                                    <span class="badge warn">{summary.state}</span>
                                    <strong>{redaction_state}</strong>
                                    <p>{export_state}</p>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </article>

            <article class="panel contract-panel" data-api-path=operation_api_path data-run-state=run_state>
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">"Runs"</span>
                        <h2>"Operation run state"</h2>
                    </div>
                    <span class="table-note">"Dry-run only"</span>
                </div>
                <div class="contract-list">
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
                                <div class="contract-item">
                                    <span class="badge neutral">{run.state}</span>
                                    <strong>{run_mode}</strong>
                                    <p>{blocked_reason}</p>
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </article>
        </section>

        <section class="panel" aria-labelledby="site-table-title">
            <div class="panel-head">
                <div>
                    <span class="eyebrow">"Readiness"</span>
                    <h2 id="site-table-title">"Site readiness queue"</h2>
                </div>
                <span class="table-note">"Filtered: production, all sites"</span>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>"Site"</th>
                            <th>"Platform"</th>
                            <th>"Capacity"</th>
                            <th>"Network"</th>
                            <th>"Backup"</th>
                            <th>"Monitoring"</th>
                            <th>"CMDB"</th>
                            <th>"Freshness"</th>
                            <th>"Next action"</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>"Site Alpha"</strong></td>
                            <td>"Compute cluster"</td>
                            <td><span class="badge warn">"Warning"</span></td>
                            <td><span class="badge good">"Ready"</span></td>
                            <td><span class="badge warn">"Gap"</span></td>
                            <td><span class="badge good">"Covered"</span></td>
                            <td><span class="badge warn">"Drift"</span></td>
                            <td>"8m"</td>
                            <td>"Review risks"</td>
                        </tr>
                        <tr>
                            <td><strong>"Site Beta"</strong></td>
                            <td>"Storage edge"</td>
                            <td><span class="badge good">"Ready"</span></td>
                            <td><span class="badge good">"Ready"</span></td>
                            <td><span class="badge good">"Protected"</span></td>
                            <td><span class="badge warn">"Gap"</span></td>
                            <td><span class="badge good">"OK"</span></td>
                            <td>"6m"</td>
                            <td>"Fix coverage"</td>
                        </tr>
                        <tr>
                            <td><strong>"Site Gamma"</strong></td>
                            <td>"Virtualization pod"</td>
                            <td><span class="badge good">"Ready"</span></td>
                            <td><span class="badge good">"Ready"</span></td>
                            <td><span class="badge good">"Protected"</span></td>
                            <td><span class="badge good">"Covered"</span></td>
                            <td><span class="badge stale">"Stale"</span></td>
                            <td>"3d"</td>
                            <td>"Import CMDB"</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="panel" aria-labelledby="work-table-title">
            <div class="panel-head">
                <div>
                    <span class="eyebrow">"Handover"</span>
                    <h2 id="work-table-title">"Failed and blocked work"</h2>
                </div>
                <span class="table-note">"No raw provider payloads shown"</span>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>"Work item"</th>
                            <th>"Type"</th>
                            <th>"Scope"</th>
                            <th>"Env"</th>
                            <th>"Team"</th>
                            <th>"Stage"</th>
                            <th>"Safe summary"</th>
                            <th>"Evidence"</th>
                            <th>"Next action"</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>"Operation sample"</strong></td>
                            <td>"Build VM"</td>
                            <td>"Site Alpha"</td>
                            <td>"Prod"</td>
                            <td>"Platform"</td>
                            <td><span class="badge bad">"Verify failed"</span></td>
                            <td>"Guest readiness check failed after deployment."</td>
                            <td><span class="badge good">"Redacted"</span></td>
                            <td>"Retry check"</td>
                        </tr>
                        <tr>
                            <td><strong>"Request sample"</strong></td>
                            <td>"Restore"</td>
                            <td>"Global"</td>
                            <td>"Prod"</td>
                            <td>"Backup"</td>
                            <td><span class="badge warn">"Approval blocked"</span></td>
                            <td>"Datacenter approval is pending."</td>
                            <td><span class="badge neutral">"Pending"</span></td>
                            <td>"Review"</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <footer class="command-hint">
            "Command palette hint: search, request, runbook, server, app, incident, evidence."
        </footer>
    }
}
