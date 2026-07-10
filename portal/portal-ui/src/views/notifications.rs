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
/// fragment that would redirect the client to a different route. Shared with
/// the Evidence tab's pack directory (`views::workspaces`), which builds the
/// same `/requests/{id}` deep links.
pub(crate) fn is_safe_request_segment(id: &str) -> bool {
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
/// mutation through `mark_notification_read`, both refetching afterwards. In the
/// hydrated client the unread COUNT additionally polls in the background (see
/// below) so a notification arriving mid-session surfaces without user action.
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
    // refetch after the user's own mark-read actions, so the LIST is fetched on
    // demand: refetching each time the panel opens picks up new notifications.
    // (The effect depends only on panel_open, not on the resource values, so
    // there is no refetch loop. The badge count is additionally kept fresh by
    // the background poll below.)
    Effect::new(move |_| {
        if panel_open.get() {
            unread.refetch();
            list.refetch();
        }
    });

    // Background badge poll (hydrated client only): refetch the unread COUNT —
    // never the list — on a fixed period, so a notification arriving mid-session
    // shows up on the bell without the user opening the panel. Gated to the
    // hydrate build the same way the shell guards its client-only effects; the
    // SSR render must never attempt to poll. While the tab is hidden the
    // interval is stopped (and a defensive in-tick check skips refetches), so
    // background tabs do not spin; on becoming visible again the badge refetches
    // immediately and the interval restarts, so a returning user never waits a
    // full period for the count to catch up.
    #[cfg(feature = "hydrate")]
    {
        use std::time::Duration;

        const UNREAD_POLL_PERIOD: Duration = Duration::from_secs(60);

        /// True when the document reports itself hidden. A missing
        /// window/document (never expected in the hydrated client) counts as
        /// visible so the poll degrades to always-on rather than silently dead.
        fn document_hidden() -> bool {
            web_sys::window()
                .and_then(|window| window.document())
                .map(|document| document.hidden())
                .unwrap_or(false)
        }

        // The live interval handle is shared between the visibility listener
        // and unmount cleanup. A StoredValue works here because IntervalHandle
        // is a plain Copy + Send id, which keeps every closure below
        // `Send + Sync` as `on_cleanup` requires (no raw JS types captured).
        let poll_handle: StoredValue<Option<IntervalHandle>> = StoredValue::new(None);

        let start_poll = move || {
            if poll_handle.get_value().is_none() {
                let started = set_interval_with_handle(
                    move || {
                        // Defensive: even if a hide transition was missed, a
                        // hidden tab must not keep hitting the endpoint.
                        if !document_hidden() {
                            unread.refetch();
                        }
                    },
                    UNREAD_POLL_PERIOD,
                );
                if let Ok(handle) = started {
                    poll_handle.set_value(Some(handle));
                }
            }
        };
        let stop_poll = move || {
            if let Some(handle) = poll_handle.get_value() {
                handle.clear();
                poll_handle.set_value(None);
            }
        };

        // `visibilitychange` fires at the document and bubbles to the window
        // (HTML spec), so the window-level helper observes it in every engine
        // that can run this wasm bundle.
        let visibility_listener = window_event_listener_untyped("visibilitychange", move |_| {
            if document_hidden() {
                stop_poll();
            } else {
                unread.refetch();
                start_poll();
            }
        });

        // Component setup runs in the browser during hydration. If the tab is
        // already hidden (e.g. opened in the background) the listener starts
        // the poll on the first visible transition instead.
        if !document_hidden() {
            start_poll();
        }

        // Owner cleanups run BEFORE the owner's arena nodes are disposed, so
        // reading `poll_handle` here is safe; clearing the interval first also
        // guarantees no tick can fire against a disposed resource.
        on_cleanup(move || {
            stop_poll();
            visibility_listener.remove();
        });
    }

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
