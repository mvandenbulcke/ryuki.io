use crate::api::{integrations_path, platform_summary_path, same_origin_api_path};
use crate::models::{
    condense_timestamp, CreateIntegrationPayload, IntegrationSummary, IntegrationTestResult,
    UpdateIntegrationPayload,
};
use crate::server_boundary::{
    create_integration, delete_integration, list_integrations, test_integration, update_integration,
};
use leptos::ev::MouseEvent;
use leptos::prelude::*;

// ── Pure helper functions (extractable, unit-testable) ────────────────────────

/// Human-readable label for a credential source key.
pub(crate) fn credential_source_label(source: &str) -> &'static str {
    match source {
        "secret-provider-ref" => "Secret provider",
        "vault" => "Vault",
        "db-encrypted" => "DB-encrypted",
        "env-var" => "Env-var",
        _ => "Unknown",
    }
}

/// CSS badge class for a credential source.
pub(crate) fn credential_source_badge_class(source: &str) -> &'static str {
    match source {
        "secret-provider-ref" => "badge good",
        "vault" => "badge good",
        "db-encrypted" => "badge warn",
        "env-var" => "badge neutral",
        _ => "badge neutral",
    }
}

/// CSS badge class for an integration status.
pub(crate) fn integration_status_badge_class(status: &str) -> &'static str {
    match status {
        "active" | "healthy" => "badge good",
        "degraded" | "testing" => "badge warn",
        "inactive" | "error" | "failed" => "badge bad",
        _ => "badge neutral",
    }
}

/// CSS badge class for an inline test result status.
pub(crate) fn test_status_badge_class(status: &str) -> &'static str {
    match status {
        "ok" | "pass" | "success" => "badge good",
        "blocked" | "pending" => "badge warn",
        "fail" | "error" | "timeout" => "badge bad",
        _ => "badge neutral",
    }
}

/// Returns `true` when a db-encrypted connection's secret field should be
/// treated as write-only (i.e. never pre-filled from server data).
///
/// This is a pure predicate extracted from the form logic so it can be unit-
/// tested independently from the Leptos component runtime.
pub(crate) fn credential_source_is_db_encrypted(source: &str) -> bool {
    source == "db-encrypted"
}

/// Locator-free credential readiness label used by the list projection.
pub(crate) fn credential_configuration_label(configured: bool) -> &'static str {
    if configured {
        "Configured"
    } else {
        "Not configured"
    }
}

// ─────────────────────────────────────────────────────────────────────────────

fn api_path_guard() -> &'static str {
    same_origin_api_path(integrations_path()).unwrap_or(platform_summary_path())
}

// ── Form state ────────────────────────────────────────────────────────────────

/// Which form is currently open, if any.
///
/// `Edit` boxes its payload to keep the enum variants similarly sized.
#[derive(Debug, Clone, PartialEq)]
enum FormMode {
    None,
    Add,
    Edit(Box<IntegrationSummary>),
}

// ── IntegrationsList ──────────────────────────────────────────────────────────

/// Integrations workspace — functional list + add/edit form.
///
/// Security invariants upheld here:
/// - `inline_secret` signal is initialized to `String::new()` and is NEVER
///   written from fetched server data. It is write-only at the browser.
/// - On edit, `credential_source` is rendered as a read-only badge (Slice-1
///   HARDENING-1 forbids changing it on update).
/// - No provider locator or complete SecretRef is present in
///   `IntegrationSummary`; the browser receives only configured/not-configured.
/// - Typed `secret-provider-ref` rows can edit noncredential fields only. The
///   portal never reconstructs or prefills a runtime SecretRef.
#[component]
pub fn IntegrationsList() -> impl IntoView {
    let integrations_api_path = api_path_guard();
    // Reactive list resource — triggers re-fetch when invalidated.
    let list = Resource::new(|| (), |_| list_integrations());
    // Re-fetch trigger (incremented after a successful mutation).
    let (refresh, set_refresh) = signal(0u32);
    // Active form mode.
    let (form_mode, set_form_mode) = signal(FormMode::None);
    // Inline test results keyed by connection id.
    let (test_result, set_test_result) = signal(Option::<(String, IntegrationTestResult)>::None);
    // Pending delete: connection id awaiting confirmation.
    let (pending_delete, set_pending_delete) = signal(Option::<String>::None);
    // Error messages from mutations.
    let (mutation_error, set_mutation_error) = signal(Option::<String>::None);

    // Re-fetch list when refresh counter changes.
    let list_refreshed = Resource::new(move || refresh.get(), |_| list_integrations());

    // We use `list_refreshed` instead of `list` so mutations trigger a re-fetch.
    // `list` is kept alive so the initial render doesn't need a separate trigger.
    let _ = list; // suppress unused warning — initial fetch covered by list_refreshed

    let on_add = move |_| {
        set_mutation_error.set(None);
        set_test_result.set(None);
        set_form_mode.set(FormMode::Add);
    };
    let on_cancel_form = move |_| {
        set_form_mode.set(FormMode::None);
        set_mutation_error.set(None);
    };

    view! {
        <div class="request-list-view">
            <div class="request-list-toolbar">
                <h2 id="integrations-list-title">"Integration connections"</h2>
                <Show when=move || form_mode.get() == FormMode::None>
                    <button class="btn btn-primary" on:click=on_add>
                        "Add connection"
                    </button>
                </Show>
            </div>

            // Mutation error banner
            <Show when=move || mutation_error.get().is_some()>
                <div class="request-list-error" role="alert" data-api-path=integrations_api_path>
                    <p>"Mutation failed"</p>
                    <p class="table-note">{move || mutation_error.get().unwrap_or_default()}</p>
                </div>
            </Show>

            // Add/edit form — shown above the list when active.
            //
            // SECURITY: The form is rendered via a keyed `{move || ...}` closure rather
            // than a `<Show>` wrapper so that switching FormMode (Add→Edit, Edit A→Edit B,
            // Edit→Add) causes the closure to re-execute and Leptos to tear down and
            // re-mount the component with a fresh set of signals.  This guarantees that
            // `inline_secret` — and every other field signal — is always re-initialized
            // to its default (empty) value on each mode transition, eliminating the
            // stale-secret-across-mode-switch risk identified in the GPT-5 Codex review.
            {move || {
                let current_mode = form_mode.get();
                if current_mode == FormMode::None {
                    None::<leptos::prelude::AnyView>
                } else {
                    Some(
                        view! {
                            <IntegrationsForm
                                mode=current_mode
                                on_cancel=on_cancel_form
                                on_success=move |_| {
                                    set_form_mode.set(FormMode::None);
                                    set_mutation_error.set(None);
                                    set_test_result.set(None);
                                    set_refresh.update(|n| *n += 1);
                                }
                                on_error=move |msg| {
                                    set_mutation_error.set(Some(msg));
                                }
                            />
                        }
                        .into_any(),
                    )
                }
            }}

            // List
            <Suspense fallback=move || {
                view! {
                    <div
                        class="request-list-loading"
                        aria-busy="true"
                        data-api-path=integrations_api_path
                    >
                        <p>"Loading integrations..."</p>
                    </div>
                }
            }>
                {move || {
                    Suspend::new(async move {
                        let integrations: Vec<IntegrationSummary> = match list_refreshed.await {
                            Ok(list) => list,
                            Err(_) => {
                                return view! {
                                    <div
                                        class="request-list-error"
                                        role="alert"
                                        data-api-path=integrations_api_path
                                    >
                                        <p>"Platform API unreachable"</p>
                                        <p class="table-note">
                                            "Integration connections could not be loaded. Check the platform API and reload this page."
                                        </p>
                                    </div>
                                }
                                .into_any();
                            }
                        };

                        if integrations.is_empty() {
                            view! {
                                <div
                                    class="request-list-empty"
                                    aria-label="No integrations configured"
                                    data-api-path=integrations_api_path
                                >
                                    <p>"No integration connections configured."</p>
                                    <p class="table-note">
                                        "Add a connection using the button above to register a vendor integration."
                                    </p>
                                </div>
                            }
                            .into_any()
                        } else {
                            let current_test = test_result.get();
                            view! {
                                <div class="table-wrap">
                                    <table
                                        class="request-table dense-table"
                                        aria-label="Integration connections"
                                        data-api-path=integrations_api_path
                                    >
                                        <thead>
                                            <tr>
                                                <th scope="col">"Vendor"</th>
                                                <th scope="col">"Name"</th>
                                                <th scope="col">"Endpoint"</th>
                                                <th scope="col">"Source"</th>
                                                <th scope="col">"Credential"</th>
                                                <th scope="col">"Status"</th>
                                                <th scope="col">"Last test"</th>
                                                <th scope="col">"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {integrations
                                                .into_iter()
                                                .map(|integration| {
                                                    let row_id = integration.id.clone();
                                                    let test_id = integration.id.clone();
                                                    let edit_id = integration.id.clone();
                                                    let delete_id = integration.id.clone();

                                                    let source_label = credential_source_label(
                                                        &integration.credential_source,
                                                    );
                                                    let source_badge = credential_source_badge_class(
                                                        &integration.credential_source,
                                                    );
                                                    let status_badge = integration_status_badge_class(
                                                        &integration.status,
                                                    );

                                                    let credential_display =
                                                        credential_configuration_label(
                                                            integration.credential_configured,
                                                        );
                                                    let last_test = integration
                                                        .last_test_at
                                                        .as_deref()
                                                        .map(condense_timestamp)
                                                        .unwrap_or_default();
                                                    let last_result = integration
                                                        .last_test_result
                                                        .clone()
                                                        .unwrap_or_default();
                                                    let last_result_badge = test_status_badge_class(
                                                        &last_result,
                                                    );

                                                    // Inline test result for this row (if any).
                                                    let inline_result = current_test
                                                        .as_ref()
                                                        .filter(|(id, _)| id == &row_id)
                                                        .map(|(_, r)| r.clone());

                                                    let on_test = move |_| {
                                                        let id = test_id.clone();
                                                        leptos::task::spawn_local(async move {
                                                            match test_integration(id.clone()).await {
                                                                Ok(result) => {
                                                                    set_test_result
                                                                        .set(Some((id, result)));
                                                                }
                                                                Err(e) => {
                                                                    set_mutation_error
                                                                        .set(Some(e.to_string()));
                                                                }
                                                            }
                                                        });
                                                    };

                                                    let integration_clone = IntegrationSummary {
                                                        id: edit_id.clone(),
                                                        vendor_type: integration.vendor_type.clone(),
                                                        name: integration.name.clone(),
                                                        endpoint_url: integration
                                                            .endpoint_url
                                                            .clone(),
                                                        site_scope: integration.site_scope.clone(),
                                                        credential_source: integration
                                                            .credential_source
                                                            .clone(),
                                                        credential_configured: integration
                                                            .credential_configured,
                                                        status: integration.status.clone(),
                                                        readiness: integration.readiness.clone(),
                                                        execution_mode: integration
                                                            .execution_mode
                                                            .clone(),
                                                        last_test_at: integration
                                                            .last_test_at
                                                            .clone(),
                                                        last_test_result: integration
                                                            .last_test_result
                                                            .clone(),
                                                        created_by: integration.created_by.clone(),
                                                        created_at: integration.created_at.clone(),
                                                        updated_at: integration.updated_at.clone(),
                                                    };
                                                    let on_edit = move |_| {
                                                        set_form_mode.set(FormMode::Edit(
                                                            Box::new(integration_clone.clone()),
                                                        ));
                                                        set_mutation_error.set(None);
                                                    };

                                                    let on_delete_request = move |_| {
                                                        set_pending_delete
                                                            .set(Some(delete_id.clone()));
                                                    };

                                                    view! {
                                                        <tr class="request-row">
                                                            <td>{integration.vendor_type.clone()}</td>
                                                            <td>{integration.name.clone()}</td>
                                                            <td class="cell-url">
                                                                <span class="table-note">
                                                                    {integration.endpoint_url.clone()}
                                                                </span>
                                                            </td>
                                                            <td>
                                                                <span class=source_badge>
                                                                    {source_label}
                                                                </span>
                                                            </td>
                                                            <td class="cell-ref">
                                                                <span class="table-note">
                                                                    {credential_display}
                                                                </span>
                                                            </td>
                                                            <td>
                                                                <span class=status_badge>
                                                                    {integration.status.clone()}
                                                                </span>
                                                            </td>
                                                            <td class="cell-date">
                                                                <span class=last_result_badge>
                                                                    {last_result}
                                                                </span>
                                                                <span class="table-note">
                                                                    {last_test}
                                                                </span>
                                                                {inline_result.map(|r| {
                                                                    let ep_badge = test_status_badge_class(
                                                                        &r.endpoint_status,
                                                                    );
                                                                    let cred_badge = test_status_badge_class(
                                                                        &r.credential_status,
                                                                    );
                                                                    view! {
                                                                        <div
                                                                            class="integration-test-result"
                                                                            aria-label="Test result"
                                                                        >
                                                                            <span class=ep_badge>
                                                                                "Endpoint: "
                                                                                {r.endpoint_status}
                                                                            </span>
                                                                            <span class="table-note">
                                                                                {r.endpoint_message}
                                                                            </span>
                                                                            <span class=cred_badge>
                                                                                "Credential: "
                                                                                {r.credential_status}
                                                                            </span>
                                                                            <span class="table-note">
                                                                                {r.credential_message}
                                                                            </span>
                                                                        </div>
                                                                    }
                                                                })}
                                                            </td>
                                                            <td class="cell-actions">
                                                                <button
                                                                    class="btn btn-sm"
                                                                    on:click=on_test
                                                                    aria-label=format!(
                                                                        "Test connection {}",
                                                                        integration.name.clone(),
                                                                    )
                                                                >
                                                                    "Test"
                                                                </button>
                                                                <button
                                                                    class="btn btn-sm"
                                                                    on:click=on_edit
                                                                    aria-label=format!(
                                                                        "Edit connection {}",
                                                                        integration.name.clone(),
                                                                    )
                                                                >
                                                                    "Edit"
                                                                </button>
                                                                <button
                                                                    class="btn btn-sm btn-danger"
                                                                    on:click=on_delete_request
                                                                    aria-label=format!(
                                                                        "Delete connection {}",
                                                                        integration.name.clone(),
                                                                    )
                                                                >
                                                                    "Delete"
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    }
                                                })
                                                .collect_view()}
                                        </tbody>
                                    </table>

                                    // Delete confirmation (below the table for the pending row)
                                    <Show when=move || pending_delete.get().is_some()>
                                        <DeleteConfirmation
                                            connection_id=move || {
                                                pending_delete.get().unwrap_or_default()
                                            }
                                            on_confirm=move |id: String| {
                                                leptos::task::spawn_local(async move {
                                                    match delete_integration(id).await {
                                                        Ok(_) => {
                                                            set_pending_delete.set(None);
                                                            set_refresh.update(|n| *n += 1);
                                                        }
                                                        Err(e) => {
                                                            set_pending_delete.set(None);
                                                            set_mutation_error
                                                                .set(Some(e.to_string()));
                                                        }
                                                    }
                                                });
                                            }
                                            on_cancel=move |_| {
                                                set_pending_delete.set(None);
                                            }
                                        />
                                    </Show>
                                </div>
                            }
                            .into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

// ── Delete confirmation ───────────────────────────────────────────────────────

#[component]
fn DeleteConfirmation<IdF, ConfirmF, CancelF>(
    connection_id: IdF,
    on_confirm: ConfirmF,
    on_cancel: CancelF,
) -> impl IntoView
where
    IdF: Fn() -> String + Send + Sync + 'static,
    ConfirmF: Fn(String) + Send + Sync + Clone + 'static,
    CancelF: Fn(MouseEvent) + Send + Sync + 'static,
{
    view! {
        <div class="confirmation-panel" role="dialog" aria-modal="true" aria-label="Confirm delete">
            <p class="confirmation-message">
                "Are you sure you want to delete this integration connection? This cannot be undone."
            </p>
            <div class="confirmation-actions">
                <button
                    class="btn btn-danger"
                    on:click=move |_| {
                        (on_confirm.clone())(connection_id());
                    }
                >
                    "Delete"
                </button>
                <button class="btn" on:click=on_cancel>
                    "Cancel"
                </button>
            </div>
        </div>
    }
}

// ── IntegrationsForm ──────────────────────────────────────────────────────────

/// Add / edit form for an integration connection.
///
/// ## Write-only secret invariants (enforced here)
///
/// 1. `inline_secret` signal is initialized to `String::new()` (empty).
/// 2. The signal is NEVER written from fetched server data — even on edit, the
///    password field starts blank. This guarantees write-only behavior.
/// 3. `autocomplete="new-password"` prevents browser autofill from populating
///    the field without user intent.
/// 4. On edit, an empty `inline_secret` string is sent in the payload; the
///    Slice-1 backend (`integration_update`) skips re-encryption when
///    `inline_secret` is empty, so the existing secret is preserved.
/// 5. `credential_source` is read-only on edit (rendered as a badge, not a
///    radio). Changing source requires delete + recreate (Slice-1 HARDENING-1).
/// 6. No credential locator is ever pre-filled. `IntegrationSummary` contains
///    only a configured bit, so edit forms start every legacy locator input
///    empty; typed SecretRef rows expose no credential input at all.
///
/// ## Remount-on-mode-change invariant
///
/// The parent renders this component inside a `{move || ...}` keyed closure.
/// `mode` is passed by VALUE (not as a `ReadSignal`), which means Leptos
/// re-executes the closure and re-creates this component — fresh signals,
/// empty `inline_secret` — every time the `FormMode` identity changes
/// (Add → Edit, Edit A → Edit B, Edit → Add, etc.).  This eliminates the
/// stale-state-across-mode-switch risk without needing an explicit reset
/// handler in every open path.
#[component]
fn IntegrationsForm<OnSuccess, OnError, OnCancel>(
    /// Current form mode, passed by value so a change causes a full remount.
    mode: FormMode,
    on_success: OnSuccess,
    on_error: OnError,
    on_cancel: OnCancel,
) -> impl IntoView
where
    OnSuccess: Fn(()) + Send + Sync + Clone + 'static,
    OnError: Fn(String) + Send + Sync + Clone + 'static,
    OnCancel: Fn(MouseEvent) + Send + Sync + Clone + 'static,
{
    let editing: Option<IntegrationSummary> = match mode {
        FormMode::Edit(s) => Some(*s),
        _ => None,
    };
    let is_edit = editing.is_some();

    // Field signals — pre-filled from the existing summary on edit.
    let (vendor_type, set_vendor_type) = signal(
        editing
            .as_ref()
            .map(|s| s.vendor_type.clone())
            .unwrap_or_default(),
    );
    let (name, set_name) = signal(editing.as_ref().map(|s| s.name.clone()).unwrap_or_default());
    let (endpoint_url, set_endpoint_url) = signal(
        editing
            .as_ref()
            .map(|s| s.endpoint_url.clone())
            .unwrap_or_default(),
    );
    let (site_scope, set_site_scope) = signal(
        editing
            .as_ref()
            .and_then(|s| s.site_scope.clone())
            .unwrap_or_default(),
    );

    // credential_source: on add → default "vault"; on edit → read-only (fixed from summary).
    let fixed_source: Option<String> = editing.as_ref().map(|s| s.credential_source.clone());
    let (credential_source, set_credential_source) =
        signal(fixed_source.clone().unwrap_or_else(|| "vault".to_string()));

    // Provider locators are write-only for every source. Never initialize this
    // signal from an IntegrationSummary or any other server response.
    let (credential_ref, set_credential_ref) = signal(String::new());

    // WRITE-ONLY: inline_secret is ALWAYS initialized to String::new().
    // It is NEVER written from server data. The comment below is load-bearing
    // documentation of the security invariant.
    let (inline_secret, set_inline_secret) = signal(String::new());
    // ↑ SECURITY: Do NOT write `inline_secret` from `editing` or any server
    //   response. This signal is write-only at the browser — the user enters
    //   a new secret; the existing secret is preserved when the field is left
    //   blank on edit (Slice-1 backend honors an empty inline_secret by
    //   skipping re-encryption).

    let (submitting, set_submitting) = signal(false);
    let (form_error, set_form_error) = signal(Option::<String>::None);

    let on_success_clone = on_success.clone();
    let on_error_clone = on_error.clone();

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if submitting.get_untracked() {
            return;
        }
        set_submitting.set(true);
        set_form_error.set(None);

        let vendor_type_val = vendor_type.get_untracked();
        let name_val = name.get_untracked();
        let endpoint_url_val = endpoint_url.get_untracked();
        let site_scope_val = {
            let s = site_scope.get_untracked();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        };
        let credential_source_val = credential_source.get_untracked();
        let credential_ref_val = credential_ref.get_untracked();
        // WRITE-ONLY: read the current value the user typed (or empty string).
        // Never set this from server data — only from explicit user input.
        let inline_secret_val = inline_secret.get_untracked();

        let on_success_submit = on_success_clone.clone();
        let on_error_submit = on_error_clone.clone();
        let edit_id: Option<String> = editing.as_ref().map(|s| s.id.clone());

        leptos::task::spawn_local(async move {
            let result = if let Some(id) = edit_id {
                // Edit path: UpdateIntegrationPayload
                // credential_source is intentionally absent (HARDENING-1).
                // inline_secret: empty = keep existing; non-empty = re-key.
                let payload = UpdateIntegrationPayload {
                    vendor_type: if vendor_type_val.is_empty() {
                        None
                    } else {
                        Some(vendor_type_val)
                    },
                    name: if name_val.is_empty() {
                        None
                    } else {
                        Some(name_val)
                    },
                    endpoint_url: if endpoint_url_val.is_empty() {
                        None
                    } else {
                        Some(endpoint_url_val)
                    },
                    site_scope: site_scope_val,
                    // Typed SecretRefs are governed outside this form. Existing
                    // typed rows preserve their exact admitted binding.
                    credential_secret_ref: None,
                    // credential_ref: None for db-encrypted (not shown/edited);
                    // Some(value) for vault/env-var.
                    credential_ref: if credential_source_val == "db-encrypted"
                        || credential_ref_val.is_empty()
                    {
                        None
                    } else {
                        Some(credential_ref_val)
                    },
                    // WRITE-ONLY: always the user-typed value or empty string.
                    inline_secret: inline_secret_val,
                };
                update_integration(id, payload).await.map(|_| ())
            } else {
                // Add path: CreateIntegrationPayload
                let payload = CreateIntegrationPayload {
                    vendor_type: vendor_type_val,
                    name: name_val,
                    endpoint_url: endpoint_url_val,
                    site_scope: site_scope_val,
                    credential_source: credential_source_val,
                    // The current typed SecretRef create path is API/governance
                    // driven; this legacy portal form never mints one.
                    credential_secret_ref: None,
                    // For db-encrypted: credential_ref is sent as empty string
                    // (the backend derives the ref from the encrypted secret).
                    credential_ref: credential_ref_val,
                    // WRITE-ONLY: user-typed value; must not be pre-filled.
                    inline_secret: inline_secret_val,
                };
                create_integration(payload).await.map(|_| ())
            };

            set_submitting.set(false);
            match result {
                Ok(()) => on_success_submit(()),
                Err(e) => {
                    let msg = e.to_string();
                    set_form_error.set(Some(msg.clone()));
                    on_error_submit(msg);
                }
            }
        });
    };

    let source_is_db = move || credential_source_is_db_encrypted(&credential_source.get());
    let source_is_vault = move || credential_source.get() == "vault";
    let source_is_env = move || credential_source.get() == "env-var";

    view! {
        <form
            class="integration-form workspace-detail-panel"
            aria-label=if is_edit { "Edit integration" } else { "Add integration" }
            on:submit=on_submit
        >
            <div class="workspace-detail-head">
                <div>
                    <span class="eyebrow">"Integrations"</span>
                    <h2>{if is_edit { "Edit connection" } else { "Add connection" }}</h2>
                </div>
            </div>

            // Form-level error
            <Show when=move || form_error.get().is_some()>
                <div class="form-field-error" role="alert">
                    <p>{move || form_error.get().unwrap_or_default()}</p>
                </div>
            </Show>

            <div class="form-fields">
                // Vendor type
                <div class="form-field">
                    <label for="int-vendor-type">"Vendor type"</label>
                    <input
                        id="int-vendor-type"
                        type="text"
                        name="vendor_type"
                        required=true
                        placeholder="e.g. vmware, zabbix, veeam"
                        value=vendor_type
                        on:input=move |ev| set_vendor_type.set(event_target_value(&ev))
                    />
                </div>

                // Name
                <div class="form-field">
                    <label for="int-name">"Name"</label>
                    <input
                        id="int-name"
                        type="text"
                        name="name"
                        required=true
                        placeholder="Human-readable label"
                        value=name
                        on:input=move |ev| set_name.set(event_target_value(&ev))
                    />
                </div>

                // Endpoint URL
                <div class="form-field">
                    <label for="int-endpoint-url">"Endpoint URL"</label>
                    <input
                        id="int-endpoint-url"
                        type="url"
                        name="endpoint_url"
                        required=true
                        placeholder="https://..."
                        value=endpoint_url
                        on:input=move |ev| set_endpoint_url.set(event_target_value(&ev))
                    />
                </div>

                // Site scope (optional)
                <div class="form-field">
                    <label for="int-site-scope">"Site scope (optional)"</label>
                    <input
                        id="int-site-scope"
                        type="text"
                        name="site_scope"
                        placeholder="Blank = global"
                        value=site_scope
                        on:input=move |ev| set_site_scope.set(event_target_value(&ev))
                    />
                </div>

                // Credential source
                <div class="form-field">
                    <label>"Credential source"</label>
                    {if is_edit {
                        // Read-only on edit (HARDENING-1: cannot change on update).
                        let source_display = credential_source_label(&fixed_source.clone().unwrap_or_default());
                        let source_badge = credential_source_badge_class(&fixed_source.clone().unwrap_or_default());
                        view! {
                            <div>
                                <span class=source_badge>{source_display}</span>
                                <p class="table-note">
                                    "To change credential source, delete this connection and create a new one."
                                </p>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="radio-group" role="radiogroup" aria-label="Credential source">
                                <label class="radio-label">
                                    <input
                                        type="radio"
                                        name="credential_source"
                                        value="vault"
                                        checked=move || credential_source.get() == "vault"
                                        on:change=move |_| set_credential_source.set("vault".to_string())
                                    />
                                    " Vault"
                                </label>
                                <label class="radio-label">
                                    <input
                                        type="radio"
                                        name="credential_source"
                                        value="db-encrypted"
                                        checked=move || credential_source.get() == "db-encrypted"
                                        on:change=move |_| set_credential_source.set("db-encrypted".to_string())
                                    />
                                    " DB-encrypted"
                                </label>
                                <label class="radio-label">
                                    <input
                                        type="radio"
                                        name="credential_source"
                                        value="env-var"
                                        checked=move || credential_source.get() == "env-var"
                                        on:change=move |_| set_credential_source.set("env-var".to_string())
                                    />
                                    " Env-var"
                                </label>
                            </div>
                        }.into_any()
                    }}
                </div>

                // Vault path (shown when source = vault)
                <Show when=source_is_vault>
                    <div class="form-field">
                        <label for="int-vault-path">"Vault path"</label>
                        <input
                            id="int-vault-path"
                            type="text"
                            name="credential_ref"
                            placeholder="e.g. kv/vcenter/prod"
                            value=credential_ref
                            on:input=move |ev| set_credential_ref.set(event_target_value(&ev))
                        />
                        <p class="table-note">
                            "Write-only provider locator. It is never shown or prefilled; leave blank on edit to keep the current binding."
                        </p>
                    </div>
                </Show>

                // DB-encrypted secret field (shown when source = db-encrypted)
                <Show when=source_is_db>
                    <div class="form-field">
                        <label for="int-inline-secret">
                            {if is_edit {
                                "New secret value"
                            } else {
                                "Secret value"
                            }}
                        </label>
                        // WRITE-ONLY: type="password", autocomplete="new-password" prevents
                        // browser autofill. The `value` attribute is intentionally NOT bound
                        // to any server-derived data — this field is always empty on mount.
                        <input
                            id="int-inline-secret"
                            type="password"
                            name="inline_secret"
                            autocomplete="new-password"
                            placeholder=if is_edit {
                                "Leave blank to keep the existing secret"
                            } else {
                                "Enter the secret value"
                            }
                            // NO `value=...` binding to inline_secret signal here —
                            // the signal is write-only and starts as String::new().
                            on:input=move |ev| set_inline_secret.set(event_target_value(&ev))
                        />
                        {if is_edit {
                            view! {
                                <p class="table-note">
                                    "Leave blank to keep the existing secret. Enter a new value to replace it."
                                </p>
                            }
                        } else {
                            view! {
                                <p class="table-note">
                                    "The secret is encrypted at rest (AES-256-GCM). It is never echoed back."
                                </p>
                            }
                        }}
                    </div>
                </Show>

                // Env-var key names (shown when source = env-var)
                <Show when=source_is_env>
                    <div class="form-field">
                        <label for="int-env-keys">"Env key names"</label>
                        <input
                            id="int-env-keys"
                            type="text"
                            name="credential_ref"
                            placeholder="e.g. RYUKI_INTEGRATION__VEEAM_API_TOKEN"
                            value=credential_ref
                            on:input=move |ev| set_credential_ref.set(event_target_value(&ev))
                        />
                        <p class="table-note">
                            "Write-only key names — never shown or prefilled. Leave blank on edit to keep the current binding. Must be prefixed with "
                            <code>"RYUKI_INTEGRATION__"</code>
                            ". Separate multiple keys with commas."
                        </p>
                    </div>
                </Show>
            </div>

            // Form actions
            <div class="form-actions">
                <button
                    type="submit"
                    class="btn btn-primary"
                    disabled=move || submitting.get()
                >
                    {move || if submitting.get() { "Saving..." } else if is_edit { "Save changes" } else { "Add connection" }}
                </button>
                <button
                    type="button"
                    class="btn"
                    on:click=on_cancel
                    disabled=move || submitting.get()
                >
                    "Cancel"
                </button>
            </div>
        </form>
    }
}

// ── Unit tests for extractable pure logic ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // T-B1: credential_source_label returns the correct human label for all sources
    #[test]
    fn credential_source_label_maps_all_sources() {
        assert_eq!(
            credential_source_label("secret-provider-ref"),
            "Secret provider"
        );
        assert_eq!(credential_source_label("vault"), "Vault");
        assert_eq!(credential_source_label("db-encrypted"), "DB-encrypted");
        assert_eq!(credential_source_label("env-var"), "Env-var");
        assert_eq!(credential_source_label("unknown-source"), "Unknown");
    }

    // T-B2: credential_source_badge_class returns a consistent badge class per source
    #[test]
    fn credential_source_badge_class_per_source() {
        assert_eq!(
            credential_source_badge_class("secret-provider-ref"),
            "badge good"
        );
        assert_eq!(credential_source_badge_class("vault"), "badge good");
        assert_eq!(credential_source_badge_class("db-encrypted"), "badge warn");
        assert_eq!(credential_source_badge_class("env-var"), "badge neutral");
        // Unknown falls back to neutral
        assert_eq!(credential_source_badge_class("other"), "badge neutral");
    }

    // T-B3: integration_status_badge_class distinguishes good/warn/bad/neutral
    #[test]
    fn integration_status_badge_class_maps_correctly() {
        assert_eq!(integration_status_badge_class("active"), "badge good");
        assert_eq!(integration_status_badge_class("healthy"), "badge good");
        assert_eq!(integration_status_badge_class("degraded"), "badge warn");
        assert_eq!(integration_status_badge_class("testing"), "badge warn");
        assert_eq!(integration_status_badge_class("inactive"), "badge bad");
        assert_eq!(integration_status_badge_class("error"), "badge bad");
        assert_eq!(integration_status_badge_class("failed"), "badge bad");
        assert_eq!(integration_status_badge_class("pending"), "badge neutral");
    }

    // T-B4: test_status_badge_class distinguishes pass/warn/fail
    #[test]
    fn test_status_badge_class_maps_correctly() {
        assert_eq!(test_status_badge_class("ok"), "badge good");
        assert_eq!(test_status_badge_class("pass"), "badge good");
        assert_eq!(test_status_badge_class("success"), "badge good");
        assert_eq!(test_status_badge_class("blocked"), "badge warn");
        assert_eq!(test_status_badge_class("pending"), "badge warn");
        assert_eq!(test_status_badge_class("fail"), "badge bad");
        assert_eq!(test_status_badge_class("error"), "badge bad");
        assert_eq!(test_status_badge_class("timeout"), "badge bad");
        assert_eq!(test_status_badge_class("unknown"), "badge neutral");
    }

    // T-B5: credential_source_is_db_encrypted is true only for "db-encrypted"
    // (this is the write-only invariant predicate)
    #[test]
    fn write_only_predicate_is_true_only_for_db_encrypted() {
        assert!(credential_source_is_db_encrypted("db-encrypted"));
        assert!(!credential_source_is_db_encrypted("vault"));
        assert!(!credential_source_is_db_encrypted("env-var"));
        assert!(!credential_source_is_db_encrypted(""));
        assert!(!credential_source_is_db_encrypted("DB-ENCRYPTED"));
    }

    // T-B6: the list exposes only locator-free configured/not-configured state.
    #[test]
    fn credential_configuration_label_is_locator_free() {
        assert_eq!(credential_configuration_label(true), "Configured");
        assert_eq!(credential_configuration_label(false), "Not configured");
    }
}
