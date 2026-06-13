use crate::api::{platform_summary_path, request_create_path, same_origin_api_path};
use crate::models::CreateRequestPayload;
use crate::server_boundary::create_request;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;

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

#[component]
pub fn RequestCreate() -> impl IntoView {
    let create_path_guard = api_path(request_create_path());
    let navigate = use_navigate();

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

    let is_valid = move || !name.get().trim().is_empty() && !justification.get().trim().is_empty();

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
                        }
                    >
                        {REQUEST_TYPE_OPTIONS
                            .iter()
                            .map(|(value, label)| view! { <option value=*value>{*label}</option> })
                            .collect_view()}
                    </select>
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

                <div class="form-actions">
                    <button
                        class="btn btn-primary"
                        on:click=move |_| {
                            set_show_errors.set(true);
                            if is_valid() {
                                let payload = CreateRequestPayload {
                                    request_type: request_type.get(),
                                    name: name.get().trim().to_string(),
                                    site: site.get(),
                                    environment: environment.get(),
                                    cpu: cpu.get(),
                                    memory: memory.get(),
                                    justification: justification.get().trim().to_string(),
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
