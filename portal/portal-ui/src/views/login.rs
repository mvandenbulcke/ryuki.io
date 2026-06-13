use crate::app::SessionResource;
use crate::server_boundary::{get_platform_summary, perform_login};
use crate::shell::BrandMark;
use leptos::prelude::*;

/// Strips the server-function transport prefix so the user sees the
/// deliberately generic message ("Invalid username or password") instead of
/// the wire-format wrapper.
fn login_error_text(error: &ServerFnError) -> String {
    let text = error.to_string();
    text.strip_prefix("error running server function: ")
        .map(str::to_string)
        .unwrap_or(text)
}

#[component]
pub fn LoginView() -> impl IntoView {
    let platform_summary = Resource::new(|| (), |_| get_platform_summary());
    let session_resource = use_context::<SessionResource>();

    let (username, set_username) = signal(String::new());
    let (password, set_password) = signal(String::new());

    let login_action = Action::new(move |credentials: &(String, String)| {
        let (username, password) = credentials.clone();
        async move {
            match perform_login(username, password).await {
                Ok(_session) => {
                    // The portal cookie is set by the server function; the
                    // auth gate re-resolves the session from it.
                    if let Some(resource) = session_resource {
                        resource.refetch();
                    }
                    Ok(())
                }
                Err(error) => Err(login_error_text(&error)),
            }
        }
    });
    let login_pending = login_action.pending();
    let login_result = login_action.value();

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let username_value = username.get();
        let password_value = password.get();
        if username_value.trim().is_empty() || password_value.is_empty() {
            return;
        }
        login_action.dispatch((username_value, password_value));
    };

    let on_continue_preview = move |_| {
        if let Some(resource) = session_resource {
            resource.refetch();
        }
    };

    let on_retry_summary = move |_| {
        platform_summary.refetch();
    };

    view! {
        <div class="login-page">
            <div class="login-card">
                <div class="login-brand">
                    <BrandMark/>
                    <span>
                        <span class="brand-kicker">"Ryuki"</span>
                        <strong>"Infrastructure Platform"</strong>
                    </span>
                </div>

                <p class="login-description">
                    "Sign in with your platform account to access the control plane."
                </p>

                <form class="login-form" on:submit=on_submit>
                    <div class="form-field">
                        <label for="login-username">"Username"</label>
                        <input
                            id="login-username"
                            type="text"
                            class="settings-input"
                            autocomplete="username"
                            prop:value=username
                            on:input=move |ev| set_username.set(event_target_value(&ev))
                        />
                    </div>
                    <div class="form-field">
                        <label for="login-password">"Password"</label>
                        <input
                            id="login-password"
                            type="password"
                            class="settings-input"
                            autocomplete="current-password"
                            prop:value=password
                            on:input=move |ev| set_password.set(event_target_value(&ev))
                        />
                    </div>
                    <button
                        class="login-button"
                        type="submit"
                        disabled=move || login_pending.get()
                    >
                        "Sign in"
                    </button>
                </form>

                <Show when=move || login_pending.get()>
                    <div class="login-status" aria-busy="true">
                        <p>"Authenticating..."</p>
                    </div>
                </Show>

                <Show when=move || {
                    matches!(login_result.get(), Some(Err(_))) && !login_pending.get()
                }>
                    <div class="login-error" role="alert">
                        <span class="eyebrow">"Authentication Error"</span>
                        <p>
                            {move || match login_result.get() {
                                Some(Err(message)) => message,
                                _ => String::new(),
                            }}
                        </p>
                    </div>
                </Show>

                <Suspense fallback=|| {
                    view! {
                        <div class="login-loader" aria-busy="true">
                            <p>"Loading platform context..."</p>
                        </div>
                    }
                }>
                    {move || {
                        Suspend::new(async move {
                            let mode = match platform_summary.await {
                                Ok(summary) => summary.authentication_mode,
                                // Live mode with the API unreachable surfaces
                                // as a server fn error; map it to the distinct
                                // degraded mode so the static-preview message
                                // never masks an API outage.
                                Err(_) => "degraded".to_string(),
                            };

                            if mode == "degraded" {
                                view! {
                                    <div class="login-warning" role="alert">
                                        <span class="eyebrow">"Platform API unreachable"</span>
                                        <p>
                                            "The platform API cannot be reached, so sign-in is unavailable right now. Try again once the API is back."
                                        </p>
                                        <button class="login-link" on:click=on_retry_summary>
                                            "Try again"
                                        </button>
                                    </div>
                                }
                                    .into_any()
                            } else if mode == "static-dry-run" {
                                // Static demo build: the auth gate is bypassed
                                // with the labeled synthetic session.
                                view! {
                                    <div class="login-static-note">
                                        <span class="eyebrow">"Static preview"</span>
                                        <p>
                                            "This portal build is a static dry-run preview; no live authentication is performed."
                                        </p>
                                        <button class="login-link" on:click=on_continue_preview>
                                            "Continue with the static preview session"
                                        </button>
                                    </div>
                                }
                                    .into_any()
                            } else if mode == "local" {
                                // Local-auth mode is the expected, fully working
                                // path: the form above signs in against local
                                // platform credentials. Keep the copy reassuring
                                // and neutral rather than warning-styled.
                                view! {
                                    <div class="login-note">
                                        <span class="eyebrow">"Local accounts"</span>
                                        <p>
                                            "Sign-in uses your local platform credentials. Enter the username and password issued for this platform above."
                                        </p>
                                    </div>
                                }
                                    .into_any()
                            } else if mode == "entra-id" {
                                view! {
                                    <div class="login-warning">
                                        <span class="eyebrow">"Entra ID"</span>
                                        <p>
                                            "Entra ID SSO is configured for this platform; the browser SSO flow is not wired in this release. Use a local platform account."
                                        </p>
                                    </div>
                                }
                                    .into_any()
                            } else {
                                // Generic fallback for any future/unknown mode.
                                // Must NOT misreport as Entra-specific.
                                view! {
                                    <div class="login-warning">
                                        <span class="eyebrow">"Sign-in"</span>
                                        <p>
                                            "This platform is configured with an authentication mode this portal build does not recognize. Use a local platform account to sign in."
                                        </p>
                                    </div>
                                }
                                    .into_any()
                            }
                        })
                    }}
                </Suspense>
            </div>
        </div>
    }
}
