use crate::models::condense_timestamp;
use crate::server_boundary::{
    get_notifications, get_notifications_unread_count, mark_all_notifications_read,
    mark_notification_read,
};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;

/// True iff `id` is a single safe URL path segment for `/requests/{id}`:
/// non-empty and composed only of ASCII alphanumerics, `-`, or `_`. This is the
/// same policy the route matcher applies (`workspace_catalog::match_portal_route`),
/// so a deep-link the bell builds can never carry a slash, traversal, query, or
/// fragment that would redirect the client to a different route.
fn is_safe_request_segment(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// In-portal notification bell: an unread-count badge plus a dropdown listing
/// the current user's recent notifications, with a "Mark all read" action and
/// per-item mark-read + deep-link.
///
/// Reads go through the `get_notifications*` server functions (which self-scope
/// to the verified session and return empty in static/degraded mode); the
/// mark-all mutation posts through `mark_all_notifications_read` and the per-item
/// mutation through `mark_notification_read`, both refetching afterwards.
///
/// Activating an item marks THAT notification read and, when the notification
/// references a request, navigates to `/requests/{request_id}` so the operator
/// can act on the alert instead of hunting for it manually.
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

    // Per-item mark-read: records a read receipt for ONE notification, then
    // refetches so the badge count and the item's read styling update. Keyed by
    // the notification id passed at dispatch time.
    let mark_one = Action::new(move |id: &String| {
        let id = id.clone();
        async move {
            let _ = mark_notification_read(id).await;
            unread.refetch();
            list.refetch();
        }
    });

    // Refetch on panel open. Both resources are keyed on `()` and otherwise only
    // refetch after the user's own mark-read actions, so a notification that
    // arrived after page load would never appear and the badge would stay frozen
    // for the whole session. Refetching each time the panel opens picks up new
    // notifications on demand. (The effect depends only on panel_open, not on the
    // resource values, so there is no refetch loop; a background badge poll is a
    // possible follow-up.)
    Effect::new(move |_| {
        if panel_open.get() {
            unread.refetch();
            list.refetch();
        }
    });

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
                                                        // A notification that references a request
                                                        // deep-links to its detail; otherwise the
                                                        // item just marks itself read in place.
                                                        // The id is validated as a single safe path
                                                        // segment (same policy as the route matcher)
                                                        // before building the href, so a malformed
                                                        // API value can never inject a route, query,
                                                        // or traversal — it simply yields no link.
                                                        let target = n
                                                            .request_id
                                                            .as_ref()
                                                            .filter(|id| is_safe_request_segment(id))
                                                            .map(|id| format!("/requests/{id}"));
                                                        let has_link = target.is_some();
                                                        let aria_label = if has_link {
                                                            format!(
                                                                "{} — open the related request and mark read",
                                                                n.title,
                                                            )
                                                        } else {
                                                            format!("{} — mark read", n.title)
                                                        };
                                                        let notif_id = n.id.clone();
                                                        let on_activate = move |_| {
                                                            mark_one.dispatch(notif_id.clone());
                                                            if let Some(href) = target.clone() {
                                                                use_navigate()(
                                                                    &href,
                                                                    NavigateOptions::default(),
                                                                );
                                                            }
                                                        };
                                                        view! {
                                                            <li class=item_class>
                                                                <button
                                                                    class="notif-item-activate"
                                                                    aria-label=aria_label
                                                                    on:click=on_activate
                                                                >
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
                                                                </button>
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

#[cfg(test)]
mod notification_bell_tests {
    use super::is_safe_request_segment;

    #[test]
    fn safe_request_segment_accepts_ids_and_rejects_route_injection() {
        // Real request ids (UUIDs and the seed-style ids) are accepted.
        assert!(is_safe_request_segment(
            "7c9e6679-7425-40de-944b-e07fc1f90ae7"
        ));
        assert!(is_safe_request_segment("req-123"));
        assert!(is_safe_request_segment("REQ_42"));

        // Anything that could escape the single `/requests/{id}` segment — a
        // slash, traversal, query, fragment, or empty value — is rejected, so
        // no deep-link is built for it.
        for bad in [
            "", "..", "a/b", "../admin", "id?x=1", "id#frag", "a b", "%2e%2e",
        ] {
            assert!(
                !is_safe_request_segment(bad),
                "segment {bad:?} must be rejected"
            );
        }
    }
}
