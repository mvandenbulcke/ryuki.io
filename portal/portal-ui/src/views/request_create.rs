use crate::api::{platform_summary_path, request_create_path, same_origin_api_path};
use crate::models::{AuthSession, CreateRequestPayload};
use crate::server_boundary::create_request;
use crate::workspace_catalog::session_can;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;

/// Zero-capability session used when no `AuthSession` is in context. An absent
/// context must HIDE the submit affordance, never reveal it — so this is
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

/// `(API value, display label)` pairs for the request-type select. The
/// values must stay in lockstep with the API's `parse_request_type`
/// vocabulary (sources/ryuki-api/src/contracts.rs) — anything else is
/// rejected at intake.
const REQUEST_TYPE_OPTIONS: &[(&str, &str)] = &[
    ("server-deployment", "Server Deployment"),
    ("patch-maintenance", "Patch Maintenance"),
    ("reboot-orchestration", "Reboot Orchestration"),
    ("controlled-restore", "Controlled Restore"),
    ("zabbix-onboarding", "Zabbix Onboarding"),
    ("cmdb-import", "CMDB Import"),
    ("cmdb-update-export", "CMDB Update / Export"),
    ("operator-runbook-launch", "Operator Runbook Launch"),
    (
        "application-environment-retirement",
        "Application Environment Retirement",
    ),
    ("vm-decommission-quarantine", "VM Decommission / Quarantine"),
    ("request-preflight", "Request Preflight"),
    ("vm-day2-change", "VM Day-2 Change"),
    ("snapshot-governance", "Snapshot Governance"),
    ("backup-coverage-report", "Backup Coverage Report"),
];

/// `(API value, display label)` pairs for the site select; values mirror the
/// engine's valid site codes (ryuki-engine request lifecycle).
const SITE_OPTIONS: &[(&str, &str)] = &[
    ("DEBER", "DEBER — Berlin"),
    ("DEFRA", "DEFRA — Frankfurt"),
    ("FRPAR", "FRPAR — Paris"),
    ("GBLON", "GBLON — London"),
    ("NLAMS", "NLAMS — Amsterdam"),
];

/// `(API value, display label)` pairs for the environment select; values
/// mirror the engine's valid environments (ryuki-engine request lifecycle).
const ENVIRONMENT_OPTIONS: &[(&str, &str)] = &[
    ("development", "Development"),
    ("test", "Test"),
    ("acceptance", "Acceptance"),
    ("production", "Production"),
];

/// The kind of input a per-type field renders as.
#[derive(Clone, Copy)]
pub(crate) enum FieldKind {
    Text,
    Number,
    Select,
    Textarea,
}

/// One per-type intake field. `key` is the snake_case payload key (the API
/// merges it into the request payload JSONB; the detail view humanizes it).
/// `required` marks fields whose absence yields a structurally meaningless
/// work-order — the conservative set is enumerated in the per-type tables
/// below.  CPU/Memory typed inputs are intentionally excluded: they are typed
/// `u32` signals with a guaranteed non-empty floor value, so marking them here
/// would add a parallel non-FieldDef code path for no correctness gain.
///
/// `pub(crate)` so the SSR test module can inspect fields without a Leptos runtime.
#[derive(Clone, Copy)]
pub(crate) struct FieldDef {
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
    pub(crate) kind: FieldKind,
    pub(crate) placeholder: &'static str,
    pub(crate) options: &'static [&'static str],
    pub(crate) required: bool,
}

const fn text(key: &'static str, label: &'static str, placeholder: &'static str) -> FieldDef {
    FieldDef {
        key,
        label,
        kind: FieldKind::Text,
        placeholder,
        options: &[],
        required: false,
    }
}
const fn number(key: &'static str, label: &'static str, placeholder: &'static str) -> FieldDef {
    FieldDef {
        key,
        label,
        kind: FieldKind::Number,
        placeholder,
        options: &[],
        required: false,
    }
}
const fn textarea(key: &'static str, label: &'static str, placeholder: &'static str) -> FieldDef {
    FieldDef {
        key,
        label,
        kind: FieldKind::Textarea,
        placeholder,
        options: &[],
        required: false,
    }
}
const fn select(
    key: &'static str,
    label: &'static str,
    placeholder: &'static str,
    options: &'static [&'static str],
) -> FieldDef {
    FieldDef {
        key,
        label,
        kind: FieldKind::Select,
        placeholder,
        options,
        required: false,
    }
}

/// Wraps a `FieldDef` to mark it as required. Stable const fn: mutable param
/// with field assignment is accepted by the Rust edition in use here.  If the
/// pinned toolchain rejects this form, replace with explicit `text_req` /
/// `select_req` variants; the required-field tables are the only call sites.
const fn req(mut def: FieldDef) -> FieldDef {
    def.required = true;
    def
}

// Per-type intake fields. `server-deployment` keeps the typed CPU/Memory inputs
// (rendered separately) and adds OS/disk here; every other type defines the
// fields meaningful to it. Keys are snake_case so the detail view humanizes them
// ("patch_wave" -> "Patch wave"). The API persists them into the payload JSONB.
//
// Required-field rationale (conservative rule: required iff an empty value has
// NO safe default / "not applicable" reading and yields a structurally
// meaningless work-order):
//   server-deployment  → operating_system (OS is identity of the deployment)
//   patch-maintenance  → target_host_group, maintenance_window (WHAT + WHEN)
//   reboot-orchestration → target_host_group, reboot_strategy (target + action)
//   controlled-restore → source_backup_id, restore_point, target_host (all load-bearing)
//   zabbix-onboarding  → target_host_group, monitoring_template (what to monitor + how)
//   cmdb-import        → source_system, record_type (source + record type)
//   cmdb-update-export → export_scope, format (scope + format define the export)
//   operator-runbook-launch → runbook_id (identity of the runbook)
//   application-environment-retirement → application, confirm_data_deletion (target + deliberate gate)
//   vm-decommission-quarantine → vm_identifier, action (which VM + what action)
//   request-preflight  → target_request_type (must name what it previews)
//   vm-day2-change     → vm_identifier, change_type (which VM + what change)
//   snapshot-governance → target_scope, snapshot_policy (scope + policy)
//   backup-coverage-report → report_scope, period (both define the report shape)
const SERVER_DEPLOYMENT_FIELDS: &[FieldDef] = &[
    req(select(
        "operating_system",
        "Operating System",
        "Select OS",
        &["Windows Server 2022", "RHEL 9", "Ubuntu 22.04 LTS"],
    )),
    number("data_disk_gb", "Data Disk GB", "e.g. 100"),
];
const PATCH_FIELDS: &[FieldDef] = &[
    req(text(
        "target_host_group",
        "Target Host Group",
        "e.g. wintel-prod-web",
    )),
    select(
        "patch_wave",
        "Patch Wave",
        "Select wave",
        &["Wave 1", "Wave 2", "Wave 3"],
    ),
    req(text(
        "maintenance_window",
        "Maintenance Window",
        "e.g. 2026-07-01 02:00 UTC",
    )),
    select(
        "reboot_required",
        "Reboot Required",
        "Select",
        &["Yes", "No"],
    ),
];
const REBOOT_FIELDS: &[FieldDef] = &[
    req(text(
        "target_host_group",
        "Target Host Group",
        "e.g. linux-prod-db",
    )),
    req(select(
        "reboot_strategy",
        "Reboot Strategy",
        "Select strategy",
        &["Rolling", "Sequential", "Parallel"],
    )),
    number(
        "drain_timeout_minutes",
        "Drain Timeout (minutes)",
        "e.g. 15",
    ),
];
const RESTORE_FIELDS: &[FieldDef] = &[
    req(text(
        "source_backup_id",
        "Source Backup ID",
        "e.g. bk-2026-06-30-0231",
    )),
    req(text(
        "restore_point",
        "Restore Point",
        "e.g. 2026-06-30 23:00 UTC",
    )),
    req(text("target_host", "Target Host", "e.g. srv-app-01")),
];
const ZABBIX_FIELDS: &[FieldDef] = &[
    req(text(
        "target_host_group",
        "Target Host Group",
        "e.g. monitored-prod",
    )),
    req(select(
        "monitoring_template",
        "Monitoring Template",
        "Select template",
        &["Linux", "Windows", "Network", "Database"],
    )),
    select(
        "alert_severity",
        "Alert Severity",
        "Select severity",
        &["Info", "Warning", "High", "Disaster"],
    ),
];
const CMDB_IMPORT_FIELDS: &[FieldDef] = &[
    req(select(
        "source_system",
        "Source System",
        "Select source",
        &["ServiceNow", "NetBox", "Spreadsheet"],
    )),
    req(text("record_type", "Record Type", "e.g. cmdb_ci_server")),
    select("dry_run", "Dry Run", "Select", &["Yes", "No"]),
];
const CMDB_EXPORT_FIELDS: &[FieldDef] = &[
    req(text("export_scope", "Export Scope", "e.g. site:DEFRA")),
    req(select(
        "format",
        "Format",
        "Select format",
        &["CSV", "JSON", "XML"],
    )),
    text("target_system", "Target System", "e.g. ServiceNow"),
];
const RUNBOOK_FIELDS: &[FieldDef] = &[
    req(text("runbook_id", "Runbook ID", "e.g. rb-failover-db")),
    textarea("parameters", "Parameters", "key=value per line"),
    select(
        "approval_required",
        "Approval Required",
        "Select",
        &["Yes", "No"],
    ),
];
const APP_RETIRE_FIELDS: &[FieldDef] = &[
    req(text("application", "Application", "e.g. app-team-web")),
    select(
        "retention_policy",
        "Retention Policy",
        "Select retention",
        &["30 days", "90 days", "365 days"],
    ),
    req(select(
        "confirm_data_deletion",
        "Confirm Data Deletion",
        "Select",
        &["No", "Yes"],
    )),
];
const VM_DECOMMISSION_FIELDS: &[FieldDef] = &[
    req(text("vm_identifier", "VM Identifier", "e.g. vm-app-0142")),
    req(select(
        "action",
        "Action",
        "Select action",
        &["Quarantine", "Decommission"],
    )),
    select(
        "snapshot_before",
        "Snapshot Before",
        "Select",
        &["Yes", "No"],
    ),
];
const PREFLIGHT_FIELDS: &[FieldDef] = &[
    req(text(
        "target_request_type",
        "Target Request Type",
        "e.g. server-deployment",
    )),
    text("scope", "Scope", "e.g. site:DEFRA env:production"),
];
const VM_DAY2_FIELDS: &[FieldDef] = &[
    req(text("vm_identifier", "VM Identifier", "e.g. vm-app-0142")),
    req(select(
        "change_type",
        "Change Type",
        "Select change",
        &["Resize", "Add disk", "Network change", "Reconfigure"],
    )),
    textarea("details", "Details", "Describe the change"),
];
const SNAPSHOT_FIELDS: &[FieldDef] = &[
    req(text(
        "target_scope",
        "Target Scope",
        "e.g. cluster:prod-vmw-01",
    )),
    req(select(
        "snapshot_policy",
        "Snapshot Policy",
        "Select policy",
        &["Daily", "Weekly", "Monthly"],
    )),
    number("retention_days", "Retention Days", "e.g. 30"),
];
const BACKUP_REPORT_FIELDS: &[FieldDef] = &[
    req(select(
        "report_scope",
        "Report Scope",
        "Select scope",
        &["Site", "Cluster", "Application"],
    )),
    req(select(
        "period",
        "Period",
        "Select period",
        &["Last 7 days", "Last 30 days", "Last 90 days"],
    )),
];

/// Resolves the per-type intake fields for a request type. Unknown types (none
/// expected — the select is fixed) render no extra fields.
///
/// Exposed as `pub(crate)` so the SSR test module can call it directly without
/// requiring a Leptos reactive runtime.
pub(crate) fn type_fields(request_type: &str) -> &'static [FieldDef] {
    match request_type {
        "server-deployment" => SERVER_DEPLOYMENT_FIELDS,
        "patch-maintenance" => PATCH_FIELDS,
        "reboot-orchestration" => REBOOT_FIELDS,
        "controlled-restore" => RESTORE_FIELDS,
        "zabbix-onboarding" => ZABBIX_FIELDS,
        "cmdb-import" => CMDB_IMPORT_FIELDS,
        "cmdb-update-export" => CMDB_EXPORT_FIELDS,
        "operator-runbook-launch" => RUNBOOK_FIELDS,
        "application-environment-retirement" => APP_RETIRE_FIELDS,
        "vm-decommission-quarantine" => VM_DECOMMISSION_FIELDS,
        "request-preflight" => PREFLIGHT_FIELDS,
        "vm-day2-change" => VM_DAY2_FIELDS,
        "snapshot-governance" => SNAPSHOT_FIELDS,
        "backup-coverage-report" => BACKUP_REPORT_FIELDS,
        _ => &[],
    }
}

/// Returns the labels of required per-type fields whose trimmed value is
/// absent or empty in `values`.
///
/// Pure function — no signals, no DOM, no Leptos runtime required.  Both the
/// production `is_valid()` closure and the SSR test module call this directly,
/// ensuring a single source of truth with no test-only fork.
///
/// Name and justification are top-level signals validated separately in
/// `is_valid()`; they are intentionally not threaded through this helper so it
/// stays focused on the per-type FieldDef domain.
pub(crate) fn missing_required_fields(
    request_type: &str,
    values: &std::collections::HashMap<String, String>,
) -> Vec<&'static str> {
    type_fields(request_type)
        .iter()
        .filter(|f| f.required)
        .filter(|f| {
            values
                .get(f.key)
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
        })
        .map(|f| f.label)
        .collect()
}

/// Renders one per-type field bound to the shared `values` map signal. Editing a
/// field upserts its `key` into the map; the value reads back from it.
fn dynamic_field(
    def: FieldDef,
    values: RwSignal<std::collections::HashMap<String, String>>,
) -> AnyView {
    let key = def.key.to_string();
    let id = format!("rtf-{}", def.key);
    let label_for = id.clone();
    match def.kind {
        FieldKind::Text | FieldKind::Number => {
            let read_key = key.clone();
            let write_key = key.clone();
            let input_type = match def.kind {
                FieldKind::Number => "number",
                _ => "text",
            };
            view! {
                <div class="form-field">
                    <label for=label_for>{def.label}</label>
                    <input
                        id=id
                        type=input_type
                        class="settings-input"
                        placeholder=def.placeholder
                        prop:value=move || values.get().get(&read_key).cloned().unwrap_or_default()
                        on:input=move |ev| {
                            let v = event_target_value(&ev);
                            values.update(|m| {
                                m.insert(write_key.clone(), v);
                            });
                        }
                    />
                </div>
            }
            .into_any()
        }
        FieldKind::Textarea => {
            let read_key = key.clone();
            let write_key = key.clone();
            view! {
                <div class="form-field">
                    <label for=label_for>{def.label}</label>
                    <textarea
                        id=id
                        class="settings-input"
                        placeholder=def.placeholder
                        prop:value=move || values.get().get(&read_key).cloned().unwrap_or_default()
                        on:input=move |ev| {
                            let v = event_target_value(&ev);
                            values.update(|m| {
                                m.insert(write_key.clone(), v);
                            });
                        }
                    ></textarea>
                </div>
            }
            .into_any()
        }
        FieldKind::Select => {
            let read_key = key.clone();
            let write_key = key.clone();
            view! {
                <div class="form-field">
                    <label for=label_for>{def.label}</label>
                    <select
                        id=id
                        class="settings-input"
                        prop:value=move || values.get().get(&read_key).cloned().unwrap_or_default()
                        on:change=move |ev| {
                            let v = event_target_value(&ev);
                            values.update(|m| {
                                m.insert(write_key.clone(), v);
                            });
                        }
                    >
                        <option value="">{def.placeholder}</option>
                        {def.options
                            .iter()
                            .map(|opt| view! { <option value=*opt>{*opt}</option> })
                            .collect_view()}
                    </select>
                </div>
            }
            .into_any()
        }
    }
}

#[component]
pub fn RequestCreate() -> impl IntoView {
    let create_path_guard = api_path(request_create_path());
    let navigate = use_navigate();
    // The verified session is provided by AuthenticatedShell (app.rs). A user
    // who reaches /requests/new without the "request" capability sees a
    // read-only notice rather than a form that would 403 on submit.
    let session = use_context::<AuthSession>().unwrap_or_else(no_capability_session);
    let can_request = session_can(&session, "request");

    if !can_request {
        return view! {
            <article
                class="request-create-panel"
                aria-labelledby="request-create-title"
                data-api-path=create_path_guard
            >
                <div class="request-create-head">
                    <div>
                        <span class="eyebrow">"Requests"</span>
                        <h2 id="request-create-title">"New Request"</h2>
                    </div>
                    <a class="btn btn-secondary" href="/requests">
                        "Back to list"
                    </a>
                </div>
                <div class="request-create-denied" role="alert">
                    <p>"Insufficient permission"</p>
                    <p class="table-note">
                        "Your role cannot file requests. Filing a request requires the request capability."
                    </p>
                </div>
            </article>
        }
        .into_any();
    }

    #[allow(deprecated)]
    let (request_type, set_request_type) = create_signal("server-deployment".to_string());
    #[allow(deprecated)]
    let (site, set_site) = create_signal("DEBER".to_string());
    #[allow(deprecated)]
    let (environment, set_environment) = create_signal("production".to_string());
    #[allow(deprecated)]
    let (name, set_name) = create_signal(String::new());
    #[allow(deprecated)]
    let (cpu, set_cpu) = create_signal(4u32);
    #[allow(deprecated)]
    let (memory, set_memory) = create_signal(16u32);
    #[allow(deprecated)]
    let (justification, set_justification) = create_signal(String::new());
    #[allow(deprecated)]
    let (feedback, set_feedback) = create_signal(String::new());
    #[allow(deprecated)]
    let (feedback_class, set_feedback_class) = create_signal("badge neutral");
    #[allow(deprecated)]
    let (show_errors, set_show_errors) = create_signal(false);
    // Per-type intake field values, keyed by snake_case field key. Cleared when
    // the request type changes so stale values from the previous type never leak.
    let field_values = RwSignal::new(std::collections::HashMap::<String, String>::new());

    let is_valid = move || {
        !name.get().trim().is_empty()
            && !justification.get().trim().is_empty()
            && missing_required_fields(&request_type.get(), &field_values.get()).is_empty()
    };

    let submit_action = Action::new(move |input: &CreateRequestPayload| {
        let payload = input.clone();
        let navigate = navigate.clone();
        set_feedback.set("Submitting request...".to_string());
        set_feedback_class.set("badge neutral");
        async move {
            match create_request(payload).await {
                Ok(_detail) => {
                    set_feedback.set("Request created".to_string());
                    set_feedback_class.set("badge good");
                    navigate("/requests", NavigateOptions::default());
                }
                Err(e) => {
                    let text = e.to_string();
                    let message = text
                        .strip_prefix("error running server function: ")
                        .map(str::to_string)
                        .unwrap_or(text);
                    set_feedback.set(message);
                    set_feedback_class.set("badge bad");
                }
            }
        }
    });

    view! {
        <article
            class="request-create-panel"
            aria-labelledby="request-create-title"
            data-api-path=create_path_guard
        >
            <div class="request-create-head">
                <div>
                    <span class="eyebrow">"Requests"</span>
                    <h2 id="request-create-title">"New Request"</h2>
                </div>
                <a class="btn btn-secondary" href="/requests">
                    "Cancel"
                </a>
            </div>

            <Show when=move || !feedback.get().is_empty()>
                <div class="form-feedback">
                    <span class=feedback_class>{feedback}</span>
                </div>
            </Show>

            <div class="request-create-form">
                <div class="form-field">
                    <label for="request-type">"Request Type"</label>
                    <select
                        id="request-type"
                        class="settings-input"
                        prop:value=request_type
                        on:change=move |ev| {
                            set_request_type.set(event_target_value(&ev));
                            // Drop the previous type's field values so they never
                            // bleed into a different request type's payload.
                            field_values.set(std::collections::HashMap::new());
                        }
                    >
                        {REQUEST_TYPE_OPTIONS
                            .iter()
                            .map(|(value, label)| view! { <option value=*value>{*label}</option> })
                            .collect_view()}
                    </select>
                    <span class="table-note">
                        {move || {
                            if request_type.get() == "server-deployment" {
                                "VM sizing (CPU / memory) applies to this request type."
                            } else {
                                "No VM sizing fields apply to this request type."
                            }
                        }}
                    </span>
                </div>

                <div class="form-field">
                    <label for="request-site">"Site"</label>
                    <select
                        id="request-site"
                        class="settings-input"
                        prop:value=site
                        on:change=move |ev| {
                            set_site.set(event_target_value(&ev));
                        }
                    >
                        {SITE_OPTIONS
                            .iter()
                            .map(|(value, label)| view! { <option value=*value>{*label}</option> })
                            .collect_view()}
                    </select>
                </div>

                <div class="form-field">
                    <label for="request-environment">"Environment"</label>
                    <select
                        id="request-environment"
                        class="settings-input"
                        prop:value=environment
                        on:change=move |ev| {
                            set_environment.set(event_target_value(&ev));
                        }
                    >
                        {ENVIRONMENT_OPTIONS
                            .iter()
                            .map(|(value, label)| view! { <option value=*value>{*label}</option> })
                            .collect_view()}
                    </select>
                </div>

                <div class="form-field">
                    <label for="request-name">"Name"</label>
                    <input
                        id="request-name"
                        type="text"
                        class="settings-input"
                        placeholder="e.g. srv-app-01"
                        prop:value=name
                        on:input=move |ev| {
                            set_name.set(event_target_value(&ev));
                        }
                    />
                    <Show when=move || show_errors.get() && name.get().trim().is_empty()>
                        <span class="form-error">"Name is required"</span>
                    </Show>
                </div>

                // VM sizing is only meaningful for server-deployment; the API's
                // build_request_payload reads cpu/memory only for that type, so
                // the form mirrors the contract — these fields appear (and are
                // only submitted) for Server Deployment, and disappear when the
                // request type changes to any of the other types.
                <Show when=move || request_type.get() == "server-deployment">
                    <div class="form-field">
                        <label for="request-cpu">"CPU cores"</label>
                        <input
                            id="request-cpu"
                            type="number"
                            class="settings-input"
                            placeholder="e.g. 4"
                            min="1"
                            prop:value=cpu
                            on:input=move |ev| {
                                let val: u32 = event_target_value(&ev).parse().unwrap_or(4);
                                set_cpu.set(val);
                            }
                        />
                    </div>

                    <div class="form-field">
                        <label for="request-memory">"Memory GB"</label>
                        <input
                            id="request-memory"
                            type="number"
                            class="settings-input"
                            placeholder="e.g. 16"
                            min="1"
                            prop:value=memory
                            on:input=move |ev| {
                                let val: u32 = event_target_value(&ev).parse().unwrap_or(16);
                                set_memory.set(val);
                            }
                        />
                    </div>
                </Show>

                // Per-type intake fields — reactively rendered for the selected
                // request type, so changing the type swaps in that type's fields.
                {move || {
                    type_fields(&request_type.get())
                        .iter()
                        .map(|def| dynamic_field(*def, field_values))
                        .collect_view()
                }}

                <div class="form-field">
                    <label for="request-justification">"Business Justification"</label>
                    <textarea
                        id="request-justification"
                        class="settings-input"
                        placeholder="Brief business justification for this request"
                        prop:value=justification
                        on:input=move |ev| {
                            set_justification.set(event_target_value(&ev));
                        }
                    ></textarea>
                    <Show when=move || show_errors.get() && justification.get().trim().is_empty()>
                        <span class="form-error">"Justification is required"</span>
                    </Show>
                </div>

                // Per-type required-field errors — shown after the user first
                // attempts to submit (show_errors) when any required field of
                // the currently selected type is empty.  Reuses the existing
                // show_errors signal and form-error CSS class; no new infra.
                <Show when=move || {
                    show_errors.get()
                        && !missing_required_fields(&request_type.get(), &field_values.get())
                            .is_empty()
                }>
                    <div class="form-field">
                        {move || {
                            missing_required_fields(&request_type.get(), &field_values.get())
                                .into_iter()
                                .map(|label| {
                                    view! {
                                        <span class="form-error">
                                            {label} " is required"
                                        </span>
                                    }
                                })
                                .collect_view()
                        }}
                    </div>
                </Show>

                <div class="form-actions">
                    <button
                        class="btn btn-primary"
                        on:click=move |_| {
                            set_show_errors.set(true);
                            if is_valid() {
                                // VM sizing is only sent for server-deployment; other
                                // types store 0 (not applicable) rather than the
                                // form defaults, matching the API's typed payload.
                                let selected_type = request_type.get();
                                let is_vm = selected_type == "server-deployment";
                                // Collect only the CURRENT type's non-empty fields,
                                // trimmed — so a stale key can never reach the payload.
                                let allowed: std::collections::HashSet<&str> =
                                    type_fields(&selected_type).iter().map(|d| d.key).collect();
                                let fields: std::collections::BTreeMap<String, String> = field_values
                                    .get()
                                    .into_iter()
                                    .filter(|(k, v)| {
                                        allowed.contains(k.as_str()) && !v.trim().is_empty()
                                    })
                                    .map(|(k, v)| (k, v.trim().to_string()))
                                    .collect();
                                let payload = CreateRequestPayload {
                                    request_type: selected_type,
                                    name: name.get().trim().to_string(),
                                    site: site.get(),
                                    environment: environment.get(),
                                    cpu: if is_vm { cpu.get() } else { 0 },
                                    memory: if is_vm { memory.get() } else { 0 },
                                    justification: justification.get().trim().to_string(),
                                    fields,
                                };
                                submit_action.dispatch(payload);
                            }
                        }
                    >
                        "Submit Request"
                    </button>
                    <a class="btn btn-secondary" href="/requests">
                        "Cancel"
                    </a>
                </div>
            </div>
        </article>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_type_options_match_api_intake_vocabulary() {
        let values: Vec<&str> = REQUEST_TYPE_OPTIONS
            .iter()
            .map(|(value, _)| *value)
            .collect();
        // Pinned to parse_request_type in sources/ryuki-api/src/contracts.rs.
        assert_eq!(
            values,
            vec![
                "server-deployment",
                "patch-maintenance",
                "reboot-orchestration",
                "controlled-restore",
                "zabbix-onboarding",
                "cmdb-import",
                "cmdb-update-export",
                "operator-runbook-launch",
                "application-environment-retirement",
                "vm-decommission-quarantine",
                "request-preflight",
                "vm-day2-change",
                "snapshot-governance",
                "backup-coverage-report",
            ]
        );
    }

    #[test]
    fn site_options_match_engine_site_codes() {
        let values: Vec<&str> = SITE_OPTIONS.iter().map(|(value, _)| *value).collect();
        // Pinned to VALID_SITES in sources/ryuki-engine/src/request_lifecycle.rs.
        assert_eq!(values, vec!["DEBER", "DEFRA", "FRPAR", "GBLON", "NLAMS"]);
    }

    #[test]
    fn environment_options_match_engine_environments() {
        let values: Vec<&str> = ENVIRONMENT_OPTIONS
            .iter()
            .map(|(value, _)| *value)
            .collect();
        // Pinned to VALID_ENVIRONMENTS in sources/ryuki-engine/src/request_lifecycle.rs.
        assert_eq!(
            values,
            vec!["development", "test", "acceptance", "production"]
        );
    }

    #[test]
    fn every_request_type_defines_intake_fields_with_snake_case_keys() {
        for (value, _) in REQUEST_TYPE_OPTIONS {
            let fields = type_fields(value);
            assert!(
                !fields.is_empty(),
                "request type {value} must define at least one intake field"
            );
            for field in fields {
                assert!(!field.key.is_empty() && !field.label.is_empty());
                assert!(
                    field
                        .key
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_'),
                    "field key {} must be snake_case so the detail view humanizes it",
                    field.key
                );
                match field.kind {
                    FieldKind::Select => assert!(
                        !field.options.is_empty(),
                        "select field {} must offer options",
                        field.key
                    ),
                    _ => assert!(
                        field.options.is_empty(),
                        "non-select field {} must not carry options",
                        field.key
                    ),
                }
            }
        }
        // An unknown type yields no extra fields rather than panicking.
        assert!(type_fields("not-a-real-type").is_empty());
    }

    #[test]
    fn every_option_has_a_humane_label_distinct_from_machine_values() {
        for (value, label) in REQUEST_TYPE_OPTIONS
            .iter()
            .chain(SITE_OPTIONS)
            .chain(ENVIRONMENT_OPTIONS)
        {
            assert!(!value.is_empty() && !label.is_empty());
            assert!(
                !label.contains("site-") && *label != "prod" && *label != "dev",
                "label {label} must be display text, not legacy demo vocabulary"
            );
        }
    }
}
