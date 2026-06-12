use crate::api::same_origin_api_path;
use crate::api::{
    activity_operation_queue_path, admin_platform_settings_path, admin_rbac_roles_path,
    approval_decision_readiness_path, auth_status_path, boundary_status_path,
    catalog_offerings_path, catalog_recommendations_path, catalog_request_form_path,
    emergency_change_path, evidence_export_retention_path, operations_platform_health_path,
    operations_runbook_launch_path, platform_health_path, platform_status_path,
    platform_summary_path, request_intake_form_preview_path, shift_queue_path, site_catalog_path,
};
use crate::api_client::{
    cmdb_file_exchange_resource, cmdb_reconciliation_resource, cmdb_relationship_graph_resource,
    evidence_summary_resource, operation_runs_resource, policy_outcomes_resource,
    secret_references_resource, ApiResource,
};
use crate::models::{
    audit_gate_fallbacks, audit_workflow_fallbacks, auth_session_fallback,
    catalog_contract_fallbacks, catalog_readiness_fallbacks, operation_run_fallbacks,
    platform_settings_summary_fallback, rbac_role_summary_fallbacks, request_intake_form_fallback,
    PlatformSettingsSummary,
};
use crate::server_boundary::{
    get_admin_platform_settings, get_auth_session, get_boundary_status, get_platform_health,
    get_platform_status, load_portal_activity_run_state, load_portal_evidence_summary_status,
    load_portal_inventory_capacity_status, reset_platform_settings, save_platform_settings,
    PortalActivityRunStateSnapshot, PortalCmdbWorkspaceSnapshot, PortalEvidenceSummarySnapshot,
    PortalInventoryCapacitySnapshot, PortalPolicyGuardrailsSnapshot, PortalSecretReferenceSnapshot,
    PortalServerBoundary,
};
use crate::views::request_create::RequestCreate;
use crate::views::request_detail::RequestDetail;
use crate::views::requests::RequestList;
use crate::workspace_catalog::{role_satisfies, PRIMARY_WORKSPACES};
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
pub fn WorkspaceSections() -> impl IntoView {
    let auth_session = auth_session_fallback();

    view! {
        <div class="workspace-area">
            <section class="workspace-sections" aria-label="Primary workspaces">
                {PRIMARY_WORKSPACES
                    .iter()
                    .filter(|workspace| role_satisfies(&auth_session, workspace.required_role))
                    .map(|workspace| {
                        let primary_api_path = api_path((workspace.primary_api_path)());
                        let secondary_api_path = api_path((workspace.secondary_api_path)());

                        view! {
                            <article
                                class="workspace-panel"
                                id=workspace.id
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
                            </article>
                        }
                    })
                    .collect_view()}
            </section>

            <section class="workspace-detail-grid" aria-label="Request, catalog, secret reference, activity, inventory, CMDB, policy, evidence, operations, and security workspace details">
                <CatalogWorkspaceDetail/>
                <RequestIntakePreview/>
                <SecretReferenceWorkspaceDetail/>
                <RequestsWorkspaceDetail/>
                <ActivityWorkspaceDetail/>
                <InventoryWorkspaceDetail/>
                <CmdbWorkspaceDetail/>
                <PolicyWorkspaceDetail/>
                <EvidenceWorkspaceDetail/>
                <OperationsWorkspaceDetail/>
                <SecurityWorkspaceDetail/>
                <AdminSettingsDetail/>
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

#[component]
fn RequestsWorkspaceDetail() -> impl IntoView {
    #[allow(deprecated)]
    let (view, set_view) = create_signal(RequestsView::List);
    #[allow(deprecated)]
    let (selected_id, set_selected_id) = create_signal(String::new());

    let on_select = Callback::new(move |id: String| {
        set_selected_id.set(id);
        set_view.set(RequestsView::Detail);
    });

    let on_create = Callback::new(move |_: ()| {
        set_view.set(RequestsView::Create);
    });

    let on_back = Callback::new(move |_: ()| {
        set_view.set(RequestsView::List);
    });

    let on_created = Callback::new(move |id: String| {
        set_selected_id.set(id);
        set_view.set(RequestsView::Detail);
    });

    view! {
        {move || match view.get() {
            RequestsView::List => {
                view! { <RequestList on_select=on_select on_create=on_create/> }
                    .into_any()
            }
            RequestsView::Detail => {
                let id = selected_id.get();
                view! { <RequestDetail request_id=id on_back=on_back/> }
                    .into_any()
            }
            RequestsView::Create => {
                view! { <RequestCreate on_created=on_created on_back=on_back/> }
                    .into_any()
            }
        }}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestsView {
    List,
    Detail,
    Create,
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
                                        let timestamp = health.timestamp;
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
                                                            <span class="table-note">{check.component} " / " {check.last_check}</span>
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

                    let user_id = session_result
                        .as_ref()
                        .map(|s| s.user_id.clone())
                        .unwrap_or_else(|_| "unavailable".to_string());
                    let display_name = session_result
                        .as_ref()
                        .map(|s| s.display_name.clone())
                        .unwrap_or_else(|_| "unavailable".to_string());
                    let roles: Vec<_> = session_result
                        .as_ref()
                        .map(|s| s.roles.clone())
                        .unwrap_or_else(|_| vec![]);

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

    let save_action = Action::new_unsync(move |input: &PlatformSettingsSummary| {
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

    let reset_action = Action::new_unsync(move |_: &()| {
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
                                            <option value="entra-id-live">"Entra ID (Live)"</option>
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
