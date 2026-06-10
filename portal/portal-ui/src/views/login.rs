use crate::api::admin_platform_settings_path;
use leptos::prelude::*;

#[component]
pub fn LoginView() -> impl IntoView {
    let platform_settings = Resource::new(|| (), |_| get_platform_settings());

    view! {
        <div class="login-page">
            <div class="login-card">
                <div class="login-brand">
                    <span class="brand-mark" aria-hidden="true">"R"</span>
                    <span>
                        <span class="brand-kicker">"Ryuki"</span>
                        <strong>"Infrastructure Platform"</strong>
                    </span>
                </div>

                <Suspense fallback=|| {
                    view! {
                        <div class="login-loader" aria-busy="true">
                            <p>"Loading platform settings..."</p>
                        </div>
                    }
                }>
                    {move || {
                        Suspend::new(async move {
                            let settings = platform_settings.await;
                            let entra_configured = settings
                                .as_ref()
                                .map(|s| !s.entra_tenant_id.is_empty())
                                .unwrap_or(false);

                            let login_action = Action::new(|_input: &()| async move {
                                perform_mock_login().await.ok()
                            });
                            let login_pending = login_action.pending();
                            let login_result = login_action.value();

                            let on_click = move |_| {
                                login_action.dispatch(());
                            };

                            if entra_configured {
                                view! {
                                    <div class="login-actions">
                                        <p class="login-description">
                                            "Sign in with your organizational account to access the platform."
                                        </p>
                                        <button
                                            class="login-button"
                                            on:click=on_click
                                            disabled=move || login_pending.get()
                                        >
                                            "Sign in with Microsoft Entra ID"
                                        </button>
                                        <Show when=move || login_pending.get()>
                                            <div class="login-status" aria-busy="true">
                                                <p>"Authenticating..."</p>
                                            </div>
                                        </Show>
                                        <Show when=move || login_result
                                            .get()
                                            .flatten()
                                            .map(|r| !r.success)
                                            .unwrap_or(false)
                                        >
                                            <div class="login-error">
                                                <span class="eyebrow">"Authentication Error"</span>
                                                <p>"Login failed. Please try again."</p>
                                            </div>
                                        </Show>
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <div class="login-warning">
                                        <span class="eyebrow">"Setup Required"</span>
                                        <p>
                                            "Entra SSO not configured. Contact your platform administrator."
                                        </p>
                                        <a class="login-link" href="#admin" data-api-path=admin_platform_settings_path()>
                                            "Go to Admin Settings"
                                        </a>
                                    </div>
                                }.into_any()
                            }
                        })
                    }}
                </Suspense>
            </div>
        </div>
    }
}

#[server(prefix = "/portal/api", endpoint = "platform-settings-login")]
async fn get_platform_settings() -> Result<crate::models::PlatformSettingsSummary, ServerFnError> {
    Ok(crate::models::platform_settings_summary_fallback())
}

#[server(prefix = "/portal/api", endpoint = "mock-login")]
async fn perform_mock_login() -> Result<crate::models::LoginResponse, ServerFnError> {
    Ok(crate::models::LoginResponse {
        session_id: "mock-session".to_string(),
        user_id: "platform-engineer".to_string(),
        display_name: "Platform Engineer".to_string(),
        email: "platform-engineer@ryuki.local".to_string(),
        roles: vec![
            "platform-engineer".to_string(),
            "operator".to_string(),
            "viewer".to_string(),
        ],
        success: true,
    })
}
