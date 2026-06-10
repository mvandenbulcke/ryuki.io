use crate::api::{platform_summary_path, request_create_path, same_origin_api_path};
use crate::models::CreateRequestPayload;
use crate::server_boundary::create_request;
use leptos::prelude::*;

fn api_path(path: &'static str) -> &'static str {
    same_origin_api_path(path).unwrap_or(platform_summary_path())
}

#[component]
pub fn RequestCreate(
    #[prop(into)] on_created: Callback<String>,
    #[prop(into)] on_back: Callback<()>,
) -> impl IntoView {
    let create_path_guard = api_path(request_create_path());

    #[allow(deprecated)]
    let (request_type, set_request_type) = create_signal("VM".to_string());
    #[allow(deprecated)]
    let (site, set_site) = create_signal("site-alpha".to_string());
    #[allow(deprecated)]
    let (environment, set_environment) = create_signal("prod".to_string());
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

    let submit_action = Action::new_unsync(move |input: &CreateRequestPayload| {
        let payload = input.clone();
        set_feedback.set("Submitting request...".to_string());
        set_feedback_class.set("badge neutral");
        async move {
            match create_request(payload).await {
                Ok(detail) => {
                    set_feedback.set("Request created".to_string());
                    set_feedback_class.set("badge good");
                    on_created.run(detail.id);
                }
                Err(e) => {
                    set_feedback.set(e.to_string());
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
                <button class="btn btn-secondary" on:click=move |_| on_back.run(())>
                    "Cancel"
                </button>
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
                        <option value="VM">"VM"</option>
                        <option value="Application">"Application"</option>
                        <option value="SQL">"SQL"</option>
                        <option value="Network">"Network"</option>
                        <option value="Storage">"Storage"</option>
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
                        <option value="site-alpha">"site-alpha"</option>
                        <option value="site-bravo">"site-bravo"</option>
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
                        <option value="dev">"dev"</option>
                        <option value="test">"test"</option>
                        <option value="staging">"staging"</option>
                        <option value="prod">"prod"</option>
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
                    <button class="btn btn-secondary" on:click=move |_| on_back.run(())>
                        "Cancel"
                    </button>
                </div>
            </div>
        </article>
    }
}
