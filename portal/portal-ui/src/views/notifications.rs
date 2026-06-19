use crate::models::condense_timestamp;
use crate::server_boundary::{
    get_notifications, get_notifications_unread_count, mark_all_notifications_read,
};
use leptos::prelude::*;

/// In-portal notification bell: an unread-count badge plus a dropdown listing
/// the current user's recent notifications, with a "Mark all read" action.
///
/// Reads go through the `get_notifications*` server functions (which self-scope
/// to the verified session and return empty in static/degraded mode); the
/// mark-all mutation posts through `mark_all_notifications_read` and refetches.
/// Per-item read/navigation is intentionally a later slice.
#[component]
pub fn NotificationBell() -> impl IntoView {
    let unread = Resource::new(|| (), |_| get_notifications_unread_count());
    let list = Resource::new(|| (), |_| get_notifications());
    let (panel_open, set_panel_open) = signal(false);

    // Mutation mirrors the shell's sign-out Action: dispatch, then refetch both
    // resources so the badge and list reflect the cleared state.
    let mark_all = Action::new(move |_: &()| async move {
        let _ = mark_all_notifications_read().await;
        unread.refetch();
        list.refetch();
    });
    let mark_all_pending = mark_all.pending();

    let on_toggle = move |_| set_panel_open.update(|open| *open = !*open);
    let on_mark_all = move |_| {
        mark_all.dispatch(());
    };

    view! {
        <div class="notif-wrap">
            <button
                class="notif-bell"
                aria-label="Notifications"
                aria-haspopup="true"
                on:click=on_toggle
            >
                <span class="notif-bell-icon" aria-hidden="true">"\u{1F514}"</span>
                <Suspense fallback=|| view! { <span></span> }>
                    {move || Suspend::new(async move {
                        let count = unread.await.unwrap_or(0);
                        if count > 0 {
                            view! {
                                <span
                                    class="notif-badge"
                                    aria-label=format!("{count} unread notifications")
                                >
                                    {count}
                                </span>
                            }
                                .into_any()
                        } else {
                            view! { <span></span> }.into_any()
                        }
                    })}
                </Suspense>
            </button>

            <Show when=move || panel_open.get()>
                <div class="notif-dropdown" role="menu" aria-label="Notifications">
                    <div class="notif-dropdown-head">
                        <span class="notif-dropdown-title">"Notifications"</span>
                        <button
                            class="notif-mark-all"
                            on:click=on_mark_all
                            disabled=move || mark_all_pending.get()
                        >
                            "Mark all read"
                        </button>
                    </div>
                    <div class="notif-dropdown-body">
                        <Suspense fallback=move || {
                            view! { <p class="notif-loading">"Loading notifications..."</p> }
                        }>
                            {move || Suspend::new(async move {
                                match list.await {
                                    Err(_) => {
                                        view! {
                                            <p class="notif-error" role="alert">
                                                "Notifications unavailable."
                                            </p>
                                        }
                                            .into_any()
                                    }
                                    Ok(items) if items.is_empty() => {
                                        view! { <p class="notif-empty">"No notifications."</p> }
                                            .into_any()
                                    }
                                    Ok(items) => {
                                        view! {
                                            <ul class="notif-list">
                                                {items
                                                    .into_iter()
                                                    .map(|n| {
                                                        let sev_class = format!(
                                                            "notif-sev sev-{}",
                                                            n.severity.to_lowercase(),
                                                        );
                                                        let item_class = if n.read {
                                                            "notif-item"
                                                        } else {
                                                            "notif-item unread"
                                                        };
                                                        let when = condense_timestamp(&n.created_at);
                                                        view! {
                                                            <li class=item_class>
                                                                <span
                                                                    class=sev_class
                                                                    aria-hidden="true"
                                                                ></span>
                                                                <div class="notif-item-main">
                                                                    <span class="notif-item-title">
                                                                        {n.title}
                                                                    </span>
                                                                    <span class="notif-item-body">{n.body}</span>
                                                                    <span class="notif-item-time">{when}</span>
                                                                </div>
                                                            </li>
                                                        }
                                                    })
                                                    .collect_view()}
                                            </ul>
                                        }
                                            .into_any()
                                    }
                                }
                            })}
                        </Suspense>
                    </div>
                </div>
            </Show>
        </div>
    }
}
