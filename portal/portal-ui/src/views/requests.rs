use crate::api::{
    platform_summary_path, request_list_path, same_origin_api_path, REQUEST_LIST_SORT_DIRECTIONS,
    REQUEST_LIST_SORT_KEYS,
};
use crate::models::{condense_timestamp, AuthSession, RequestSummary};
use crate::server_boundary::{get_request_list, RequestListPage};
use crate::workspace_catalog::session_can;
use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query_map};
use leptos_router::NavigateOptions;

/// Zero-capability session used when no `AuthSession` is in context. An absent
/// context must HIDE capability-gated controls, never reveal them — so this is
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

/// Status values offered in the filter dropdown, paired with their display
/// label. Kept in lifecycle order so the dropdown reads like the request
/// timeline. The value is sent verbatim to the API's `status` facet (which
/// matches case-insensitively).
pub(crate) const STATUS_FILTER_OPTIONS: &[(&str, &str)] = &[
    ("intake", "Intake"),
    ("validated", "Validated"),
    ("planned", "Planned"),
    ("approved", "Approved"),
    ("locked", "Locked"),
    ("executing", "Executing"),
    ("executed", "Executed"),
    ("verifying", "Verifying"),
    ("verified", "Verified"),
    ("completed", "Completed"),
    ("protecting", "Protecting"),
    ("operational", "Operational"),
    ("retired", "Retired"),
    ("failed", "Failed"),
    ("rejected", "Rejected"),
    ("cancelled", "Cancelled"),
];

/// Page size for the request list. Mirrors `PAGE_SIZE` inside `get_request_list`
/// so the view's Prev/Next offsets step by the same amount the server pages by.
const PAGE_SIZE: u32 = 25;

/// The active facet selection, read from the URL query string. The URL is the
/// single source of truth so filters survive reload, deep-linking, and the
/// browser back button.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestFacets {
    pub status: String,
    pub site: String,
    pub environment: String,
    pub request_type: String,
    pub created_by: String,
    pub q: String,
    pub sort: String,
    pub direction: String,
    /// Pagination cursor (row offset). Default 0 is the first page; omitted from
    /// the URL when 0 so the default view stays a clean `/requests`.
    pub offset: u32,
}

impl RequestFacets {
    /// True when no facet narrows or reorders the list — the default view.
    /// Uses TRIMMED emptiness so a blank/whitespace-only facet (e.g. `?q=%20`)
    /// is not shown as active while the server drops it as empty.
    pub fn is_active(&self) -> bool {
        !self.status.trim().is_empty()
            || !self.site.trim().is_empty()
            || !self.environment.trim().is_empty()
            || !self.request_type.trim().is_empty()
            || !self.created_by.trim().is_empty()
            || !self.q.trim().is_empty()
            || !self.normalized_sort().is_empty()
    }

    /// The sort key, normalized to the API allowlist (empty when out of range).
    pub fn normalized_sort(&self) -> &str {
        if REQUEST_LIST_SORT_KEYS.contains(&self.sort.as_str()) {
            &self.sort
        } else {
            ""
        }
    }

    /// The sort direction, defaulting to `asc` whenever a valid sort key is set
    /// but the direction is absent or out of range.
    pub fn normalized_direction(&self) -> &str {
        if self.normalized_sort().is_empty() {
            return "";
        }
        if REQUEST_LIST_SORT_DIRECTIONS.contains(&self.direction.as_str()) {
            &self.direction
        } else {
            "asc"
        }
    }
}

/// Builds the `/requests?...` navigation URL from the active facets, omitting
/// empty facets so the default view stays a clean `/requests`. Values are
/// percent-encoded so a search term with spaces or reserved characters never
/// breaks the URL. Pure and unit-tested.
pub fn build_request_filter_url(facets: &RequestFacets) -> String {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    // Trim each facet: a blank/whitespace-only value carries no filter and must
    // not end up as `?q=%20` in the URL (the server drops it anyway).
    let status = facets.status.trim();
    let site = facets.site.trim();
    let environment = facets.environment.trim();
    let request_type = facets.request_type.trim();
    let created_by = facets.created_by.trim();
    let q = facets.q.trim();
    if !status.is_empty() {
        pairs.push(("status", status));
    }
    if !site.is_empty() {
        pairs.push(("site", site));
    }
    if !environment.is_empty() {
        pairs.push(("environment", environment));
    }
    if !request_type.is_empty() {
        pairs.push(("request_type", request_type));
    }
    if !created_by.is_empty() {
        pairs.push(("created_by", created_by));
    }
    if !q.is_empty() {
        pairs.push(("q", q));
    }
    let sort = facets.normalized_sort();
    if !sort.is_empty() {
        pairs.push(("sort", sort));
        pairs.push(("direction", facets.normalized_direction()));
    }
    // The pagination cursor is appended only when past the first page so the
    // default view keeps a clean `/requests` URL. `offset` is a numeric value
    // that needs no percent-encoding; its owned string outlives `pairs`.
    let offset_value = facets.offset.to_string();
    if facets.offset > 0 {
        pairs.push(("offset", offset_value.as_str()));
    }
    if pairs.is_empty() {
        return "/requests".to_string();
    }
    let mut out = String::from("/requests?");
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(key);
        out.push('=');
        out.push_str(&encode_query_component(value));
    }
    out
}

/// Percent-encodes a query-string component so caller-supplied facet values
/// cannot inject extra parameters or break the URL. Mirrors the server-side
/// encoder in `api.rs`.
fn encode_query_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let b = *byte;
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            encoded.push(b as char);
        } else {
            encoded.push('%');
            encoded.push(
                char::from_digit((b >> 4) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
            encoded.push(
                char::from_digit((b & 0x0f) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
        }
    }
    encoded
}

/// Pure filtering function for the requests list.
///
/// Case-insensitive substring match on `name` ONLY — the same field the API's
/// `q` facet matches server-side (and what the "Search by name" box advertises).
/// Matching the server keeps this client refinement consistent: the server
/// already applies `q`, and re-applying the identical rule here keeps the
/// rendered note (`N results for X`) honest without changing which rows show.
/// An empty/blank `q` returns all rows unchanged. Status and site are filtered
/// through their own dedicated facets, not through `q`.
pub fn filter_requests<'a>(requests: &'a [RequestSummary], q: &str) -> Vec<&'a RequestSummary> {
    let needle = q.trim().to_lowercase();
    if needle.is_empty() {
        return requests.iter().collect();
    }
    requests
        .iter()
        .filter(|r| r.name.to_lowercase().contains(&needle))
        .collect()
}

pub(crate) fn status_badge_class(status: &str) -> &'static str {
    match status {
        "intake" => "badge neutral",
        "validated" => "badge good",
        "approved" => "badge good",
        "executed" | "verified" | "completed" => "badge good",
        // Post-completion governed lifecycle (Theme 8).
        "protecting" | "operational" => "badge good",
        "retired" => "badge neutral",
        "failed" => "badge bad",
        "rejected" | "cancelled" => "badge bad",
        "executing" | "verifying" => "badge warn",
        _ => "badge neutral",
    }
}

pub(crate) fn status_label(status: &str) -> &'static str {
    match status {
        "intake" => "Intake",
        "validated" => "Validated",
        "planned" => "Planned",
        "approved" => "Approved",
        "locked" => "Locked",
        "executing" => "Executing",
        "executed" => "Executed",
        "verifying" => "Verifying",
        "verified" => "Verified",
        "completed" => "Completed",
        // Post-completion governed lifecycle (Theme 8).
        "protecting" => "Protecting",
        "operational" => "Operational",
        "retired" => "Retired",
        "failed" => "Failed",
        "rejected" => "Rejected",
        "cancelled" => "Cancelled",
        &_ => "Unknown",
    }
}

/// Columns that support server-side sorting, paired with the API `sort` key.
/// The label matches the `<th>` text; the key is from `REQUEST_LIST_SORT_KEYS`.
const SORTABLE_COLUMNS: &[(&str, &str)] = &[
    ("Type", "request_type"),
    ("Name", "name"),
    ("Site", "site"),
    ("Status", "status"),
    ("Created", "created_at"),
];

#[component]
pub fn RequestList() -> impl IntoView {
    let request_list_path_guard = api_path(request_list_path());
    let navigate = use_navigate();

    // The URL query string is the single source of truth for the active facets.
    let query = use_query_map();
    let facets_memo = Memo::new(move |_| {
        query.with(|map| RequestFacets {
            status: map.get("status").unwrap_or_default(),
            site: map.get("site").unwrap_or_default(),
            environment: map.get("environment").unwrap_or_default(),
            request_type: map.get("request_type").unwrap_or_default(),
            created_by: map.get("created_by").unwrap_or_default(),
            q: map.get("q").unwrap_or_default(),
            sort: map.get("sort").unwrap_or_default(),
            direction: map.get("direction").unwrap_or_default(),
            // A malformed/absent offset degrades to the first page.
            offset: map
                .get("offset")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0),
        })
    });

    // The resource is keyed on the facets: any filter/sort change re-fetches
    // server-side. With no facets it requests the unfiltered default list, so
    // the initial render is byte-identical to the pre-facet behavior.
    let list_resource = Resource::new(
        move || facets_memo.get(),
        |facets| async move {
            let sort = facets.normalized_sort();
            let direction = facets.normalized_direction();
            get_request_list(
                opt(&facets.status),
                opt(&facets.site),
                opt(&facets.environment),
                opt(&facets.request_type),
                opt(&facets.created_by),
                opt(&facets.q),
                opt(sort),
                opt(direction),
                Some(facets.offset),
            )
            .await
        },
    );

    // The verified session is provided by AuthenticatedShell (app.rs). An
    // absent context falls back to a zero-capability session so the control
    // is hidden rather than shown.
    let session = use_context::<AuthSession>().unwrap_or_else(no_capability_session);
    let can_request = session_can(&session, "request");

    // ── Filter-bar event handlers ─────────────────────────────────────────
    // Each control rewrites the URL; the resource and view react to the change.
    // Every FILTER change resets `offset` to 0 so a narrower filter never
    // strands the user on a now-empty later page. Only Prev/Next change offset.
    let nav_status = navigate.clone();
    let on_status_change = move |ev: leptos::ev::Event| {
        let mut next = facets_memo.get_untracked();
        next.status = event_target_value(&ev);
        next.offset = 0;
        nav_status(&build_request_filter_url(&next), NavigateOptions::default());
    };
    let nav_site = navigate.clone();
    let on_site_input = move |ev: leptos::ev::Event| {
        let mut next = facets_memo.get_untracked();
        next.site = event_target_value(&ev).trim().to_string();
        next.offset = 0;
        nav_site(&build_request_filter_url(&next), NavigateOptions::default());
    };
    let nav_environment = navigate.clone();
    let on_environment_input = move |ev: leptos::ev::Event| {
        let mut next = facets_memo.get_untracked();
        next.environment = event_target_value(&ev).trim().to_string();
        next.offset = 0;
        nav_environment(&build_request_filter_url(&next), NavigateOptions::default());
    };
    let nav_request_type = navigate.clone();
    let on_request_type_input = move |ev: leptos::ev::Event| {
        let mut next = facets_memo.get_untracked();
        next.request_type = event_target_value(&ev).trim().to_string();
        next.offset = 0;
        nav_request_type(&build_request_filter_url(&next), NavigateOptions::default());
    };
    let nav_created_by = navigate.clone();
    let on_created_by_input = move |ev: leptos::ev::Event| {
        let mut next = facets_memo.get_untracked();
        next.created_by = event_target_value(&ev).trim().to_string();
        next.offset = 0;
        nav_created_by(&build_request_filter_url(&next), NavigateOptions::default());
    };
    let nav_search = navigate.clone();
    let on_search_input = move |ev: leptos::ev::Event| {
        let mut next = facets_memo.get_untracked();
        next.q = event_target_value(&ev);
        next.offset = 0;
        nav_search(&build_request_filter_url(&next), NavigateOptions::default());
    };
    let nav_clear = navigate.clone();
    let on_clear = move |_| {
        nav_clear("/requests", NavigateOptions::default());
    };

    view! {
        <div class="request-list-view">
            <div class="request-list-toolbar">
                <h2 id="request-list-title">"Requests"</h2>
                <Show when=move || can_request>
                    <a class="btn btn-primary" href="/requests/new">
                        "New Request"
                    </a>
                </Show>
            </div>

            // ── Faceted filter bar ────────────────────────────────────────
            <div class="request-filter-bar" role="search" aria-label="Filter requests">
                <div class="filter-field">
                    <label for="request-filter-search">"Search"</label>
                    <input
                        id="request-filter-search"
                        type="search"
                        placeholder="Search by name"
                        autocomplete="off"
                        prop:value=move || facets_memo.get().q
                        on:input=on_search_input
                    />
                </div>
                <div class="filter-field">
                    <label for="request-filter-status">"Status"</label>
                    <select
                        id="request-filter-status"
                        prop:value=move || facets_memo.get().status
                        on:change=on_status_change
                    >
                        <option value="">"All statuses"</option>
                        {STATUS_FILTER_OPTIONS
                            .iter()
                            .map(|(value, label)| {
                                view! { <option value=*value>{*label}</option> }
                            })
                            .collect_view()}
                    </select>
                </div>
                <div class="filter-field">
                    <label for="request-filter-site">"Site"</label>
                    // Free-text like the other facets; the API filters server-side.
                    // (No datalist: with pagination the loaded page is only 25 rows,
                    // so page-derived suggestions would shrink and shift as the user
                    // pages — a stable site source is a separate future enhancement.)
                    <input
                        id="request-filter-site"
                        type="text"
                        placeholder="Any site"
                        autocomplete="off"
                        prop:value=move || facets_memo.get().site
                        on:change=on_site_input
                    />
                </div>
                <div class="filter-field">
                    <label for="request-filter-environment">"Environment"</label>
                    <input
                        id="request-filter-environment"
                        type="text"
                        placeholder="Any environment"
                        autocomplete="off"
                        prop:value=move || facets_memo.get().environment
                        on:change=on_environment_input
                    />
                </div>
                <div class="filter-field">
                    <label for="request-filter-request-type">"Request type"</label>
                    <input
                        id="request-filter-request-type"
                        type="text"
                        placeholder="Any type"
                        autocomplete="off"
                        prop:value=move || facets_memo.get().request_type
                        on:change=on_request_type_input
                    />
                </div>
                <div class="filter-field">
                    <label for="request-filter-created-by">"Created by"</label>
                    <input
                        id="request-filter-created-by"
                        type="text"
                        placeholder="Any user"
                        autocomplete="off"
                        prop:value=move || facets_memo.get().created_by
                        on:change=on_created_by_input
                    />
                </div>
                <Show when=move || facets_memo.get().is_active()>
                    <button class="btn btn-secondary filter-clear" type="button" on:click=on_clear.clone()>
                        "Clear filters"
                    </button>
                </Show>
            </div>

            <Suspense fallback=move || {
                view! {
                    <div class="request-list-loading" aria-busy="true" data-api-path=request_list_path_guard>
                        <p>"Loading requests..."</p>
                    </div>
                }
            }>
                {move || {
                    let navigate = navigate.clone();
                    let facets = facets_memo.get();
                    Suspend::new(async move {
                        let page: RequestListPage = match list_resource.await {
                            Ok(page) => page,
                            // Live mode with the API unreachable: an explicit
                            // error state, never demo rows.
                            Err(_) => {
                                return view! {
                                    <div
                                        class="request-list-error"
                                        role="alert"
                                        data-api-path=request_list_path_guard
                                    >
                                        <p>"Platform API unreachable"</p>
                                        <p class="table-note">
                                            "Live request data cannot be loaded. Check the platform API and reload this page."
                                        </p>
                                    </div>
                                }
                                    .into_any();
                            }
                        };

                        let requests: Vec<RequestSummary> = page.rows;
                        let has_next = page.has_next;
                        let offset = page.offset;
                        let active = facets.is_active();

                        // The server already filtered by `q`; re-apply locally so the
                        // rendered set, the range note, and the empty-state all agree
                        // even if the API contract drifts. Empty-state + range are
                        // derived from THIS set (not the raw page) so a re-filter that
                        // drops every row can never render an inverted "Showing 1-0".
                        let display_rows: Vec<RequestSummary> = filter_requests(&requests, &facets.q)
                            .into_iter()
                            .cloned()
                            .collect();
                        let page_count = display_rows.len();

                        if display_rows.is_empty() {
                            // A past-the-end page (e.g. a stale deep link to a
                            // high offset) is empty without meaning "no results":
                            // point the user back to page 1 of this same view.
                            if offset > 0 {
                                let mut first = facets.clone();
                                first.offset = 0;
                                let first_url = build_request_filter_url(&first);
                                return view! {
                                    <div class="request-list-empty" aria-label="No requests on this page">
                                        <p>"No requests on this page."</p>
                                        <p class="table-note">
                                            "Return to "
                                            <a href=first_url>"the first page"</a>
                                            "."
                                        </p>
                                    </div>
                                }
                                    .into_any();
                            }
                            // Distinguish "no requests at all" from "filters
                            // matched nothing" so the empty state is honest.
                            if active {
                                return view! {
                                    <div class="request-list-empty" aria-label="No matching requests">
                                        <p>"No requests match the current filters."</p>
                                        <p class="table-note">
                                            "Adjust or "
                                            <a href="/requests">"clear the filters"</a>
                                            " to see all requests."
                                        </p>
                                    </div>
                                }
                                    .into_any();
                            }
                            return view! {
                                <div class="request-list-empty" aria-label="No requests">
                                    <p>"No requests yet."</p>
                                    <p class="table-note">"Create a new request to get started."</p>
                                </div>
                            }
                                .into_any();
                        }

                        // No exact filtered total is reachable here (the upstream
                        // client drops X-Total-Count), so the note shows the page
                        // RANGE rather than "N of M". `range_from` is 1-based. Both
                        // are saturating and derived from `page_count` (the rendered
                        // set) so the label can never invert or overflow on a large
                        // offset.
                        let range_from = offset.saturating_add(1);
                        let range_to = offset.saturating_add(page_count as u32);
                        let range_note = format!("Showing {range_from}-{range_to}");
                        // A second owned copy: the note appears once above the
                        // table and once inside the pager, each in its own view
                        // closure (which capture by move).
                        let range_note_pager = range_note.clone();
                        let has_prev = offset > 0;
                        let show_pager = has_prev || has_next;

                        // Prev/Next rewrite only the offset, never the facets, so
                        // they page within the current filter/sort selection.
                        let mut prev_facets = facets.clone();
                        prev_facets.offset = offset.saturating_sub(PAGE_SIZE);
                        let prev_url = build_request_filter_url(&prev_facets);
                        let mut next_facets = facets.clone();
                        next_facets.offset = offset.saturating_add(PAGE_SIZE);
                        let next_url = build_request_filter_url(&next_facets);
                        let nav_prev = navigate.clone();
                        let nav_next = navigate.clone();
                        let on_prev = move |_| {
                            nav_prev(&prev_url, NavigateOptions::default());
                        };
                        let on_next = move |_| {
                            nav_next(&next_url, NavigateOptions::default());
                        };

                        let active_sort = facets.normalized_sort().to_string();
                        let active_direction = facets.normalized_direction().to_string();

                        view! {
                            <div class="table-wrap">
                                <Show when=move || active || show_pager>
                                    <p class="search-result-note table-note">
                                        {range_note.clone()}
                                    </p>
                                </Show>
                                <table
                                    class="request-table dense-table"
                                    aria-label="Request list"
                                    data-api-path=request_list_path_guard
                                >
                                    <thead>
                                        <tr>
                                            <th scope="col">"ID"</th>
                                            {SORTABLE_COLUMNS
                                                .iter()
                                                .map(|(label, key)| {
                                                    sortable_header(
                                                        label,
                                                        key,
                                                        &active_sort,
                                                        &active_direction,
                                                        facets_memo,
                                                        navigate.clone(),
                                                    )
                                                })
                                                .collect_view()}
                                            <th scope="col">"Env"</th>
                                            <th scope="col">"Stage"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {display_rows
                                            .into_iter()
                                            .map(|req| {
                                                let row_id = req.id.clone();
                                                let button_id = req.id.clone();
                                                let open_label = format!("Open request {}", req.id);
                                                let display_id = if req.id.len() > 8 {
                                                    req.id[..8].to_string()
                                                } else {
                                                    req.id.clone()
                                                };
                                                let badge_class = status_badge_class(&req.status);
                                                let status_text = status_label(&req.status);
                                                let stage_text = req.stage.clone();
                                                let row_navigate = navigate.clone();
                                                let button_navigate = navigate.clone();
                                                let on_row_click = move |_| {
                                                    row_navigate(
                                                        &format!("/requests/{row_id}"),
                                                        NavigateOptions::default(),
                                                    );
                                                };
                                                // Real button so the row is reachable and
                                                // activatable by keyboard, not mouse-only.
                                                let on_id_click = move |ev: leptos::ev::MouseEvent| {
                                                    ev.stop_propagation();
                                                    button_navigate(
                                                        &format!("/requests/{button_id}"),
                                                        NavigateOptions::default(),
                                                    );
                                                };
                                                view! {
                                                    <tr class="request-row clickable" on:click=on_row_click>
                                                        <td class="cell-id">
                                                            <button
                                                                class="row-link"
                                                                aria-label=open_label
                                                                on:click=on_id_click
                                                            >
                                                                {display_id}
                                                            </button>
                                                        </td>
                                                        <td>{req.request_type}</td>
                                                        <td>{req.name}</td>
                                                        <td>{req.site}</td>
                                                        <td><span class=badge_class>{status_text}</span></td>
                                                        <td class="cell-date">{condense_timestamp(&req.created)}</td>
                                                        <td>{req.environment}</td>
                                                        <td><span class="badge neutral">{stage_text}</span></td>
                                                    </tr>
                                                }
                                            })
                                            .collect_view()}
                                    </tbody>
                                </table>
                                <Show when=move || show_pager>
                                    <nav class="request-pagination" aria-label="Request list pages">
                                        <button
                                            class="btn btn-secondary"
                                            type="button"
                                            disabled=!has_prev
                                            on:click=on_prev.clone()
                                        >
                                            "Previous"
                                        </button>
                                        <span
                                            class="pagination-range table-note"
                                            aria-hidden="true"
                                        >
                                            {range_note_pager.clone()}
                                        </span>
                                        <button
                                            class="btn btn-secondary"
                                            type="button"
                                            disabled=!has_next
                                            on:click=on_next.clone()
                                        >
                                            "Next"
                                        </button>
                                    </nav>
                                </Show>
                            </div>
                        }
                            .into_any()
                    })
                }}
            </Suspense>
        </div>
    }
}

/// Maps a possibly-empty facet value to `Option<String>` for the server fn —
/// empty strings become `None` so the upstream sees the default behavior.
fn opt(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Renders a sortable `<th>`: clicking it toggles the sort direction for that
/// column (asc → desc → asc) and re-navigates with the updated `sort`/
/// `direction` facets. The active column carries an aria-sort indicator and an
/// arrow glyph so the current ordering is visible without color alone.
fn sortable_header(
    label: &'static str,
    key: &'static str,
    active_sort: &str,
    active_direction: &str,
    facets_memo: Memo<RequestFacets>,
    navigate: impl Fn(&str, NavigateOptions) + Clone + 'static,
) -> impl IntoView {
    let is_active = active_sort == key;
    let next_direction = if is_active && active_direction == "asc" {
        "desc"
    } else {
        "asc"
    };
    let aria_sort = if !is_active {
        "none"
    } else if active_direction == "desc" {
        "descending"
    } else {
        "ascending"
    };
    let arrow = if !is_active {
        ""
    } else if active_direction == "desc" {
        " \u{25BC}"
    } else {
        " \u{25B2}"
    };
    let next_direction = next_direction.to_string();
    let on_click = move |_| {
        let mut next = facets_memo.get_untracked();
        next.sort = key.to_string();
        next.direction = next_direction.clone();
        // Re-sorting changes which rows lead the list, so return to page 1.
        next.offset = 0;
        navigate(&build_request_filter_url(&next), NavigateOptions::default());
    };
    view! {
        <th scope="col" aria-sort=aria_sort class="sortable-col">
            <button class="sort-header" type="button" on:click=on_click>
                {label}
                <span class="sort-arrow" aria-hidden="true">{arrow}</span>
            </button>
        </th>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, name: &str, site: &str, status: &str) -> RequestSummary {
        RequestSummary {
            id: id.to_string(),
            request_type: "server".to_string(),
            name: name.to_string(),
            site: site.to_string(),
            environment: "prod".to_string(),
            status: status.to_string(),
            stage: status.to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn empty_facets_build_clean_default_url() {
        let facets = RequestFacets::default();
        assert!(!facets.is_active());
        assert_eq!(build_request_filter_url(&facets), "/requests");
    }

    #[test]
    fn facets_serialize_in_canonical_order_with_encoding() {
        let facets = RequestFacets {
            status: "approved".to_string(),
            site: "site-alpha".to_string(),
            q: "web db".to_string(),
            sort: "name".to_string(),
            direction: "desc".to_string(),
            ..Default::default()
        };
        assert!(facets.is_active());
        assert_eq!(
            build_request_filter_url(&facets),
            "/requests?status=approved&site=site-alpha&q=web%20db&sort=name&direction=desc"
        );
    }

    #[test]
    fn new_facets_serialize_in_canonical_order_with_encoding() {
        let facets = RequestFacets {
            environment: "prod".to_string(),
            request_type: "server deploy".to_string(),
            created_by: "alice@example.com".to_string(),
            ..Default::default()
        };
        assert!(facets.is_active());
        assert_eq!(
            build_request_filter_url(&facets),
            "/requests?environment=prod&request_type=server%20deploy&created_by=alice%40example.com"
        );
    }

    #[test]
    fn all_facets_serialize_in_canonical_order() {
        let facets = RequestFacets {
            status: "approved".to_string(),
            site: "site-a".to_string(),
            environment: "prod".to_string(),
            request_type: "server".to_string(),
            created_by: "bob".to_string(),
            q: "web".to_string(),
            sort: "name".to_string(),
            direction: "asc".to_string(),
            offset: 0,
        };
        assert!(facets.is_active());
        assert_eq!(
            build_request_filter_url(&facets),
            "/requests?status=approved&site=site-a&environment=prod&request_type=server&created_by=bob&q=web&sort=name&direction=asc"
        );
    }

    #[test]
    fn blank_new_facets_produce_clean_url() {
        let facets = RequestFacets {
            environment: "   ".to_string(),
            request_type: "".to_string(),
            created_by: " ".to_string(),
            ..Default::default()
        };
        assert!(!facets.is_active());
        assert_eq!(build_request_filter_url(&facets), "/requests");
    }

    #[test]
    fn invalid_sort_is_dropped_from_url() {
        let facets = RequestFacets {
            sort: "ssn".to_string(),
            direction: "asc".to_string(),
            ..Default::default()
        };
        // An out-of-allowlist sort key never reaches the URL.
        assert!(!facets.is_active());
        assert_eq!(build_request_filter_url(&facets), "/requests");
    }

    #[test]
    fn valid_sort_defaults_direction_to_asc() {
        let facets = RequestFacets {
            sort: "status".to_string(),
            direction: "garbage".to_string(),
            ..Default::default()
        };
        assert_eq!(facets.normalized_direction(), "asc");
        assert_eq!(
            build_request_filter_url(&facets),
            "/requests?sort=status&direction=asc"
        );
    }

    #[test]
    fn search_only_facet_builds_q_url() {
        let facets = RequestFacets {
            q: "api & web".to_string(),
            ..Default::default()
        };
        assert_eq!(
            build_request_filter_url(&facets),
            "/requests?q=api%20%26%20web"
        );
    }

    #[test]
    fn filter_requests_empty_query_returns_all() {
        let rows = vec![row("a", "Alpha", "s1", "intake")];
        assert_eq!(filter_requests(&rows, "").len(), 1);
    }

    #[test]
    fn filter_requests_matches_case_insensitively() {
        let rows = vec![
            row("a", "Web Server", "s1", "intake"),
            row("b", "Database", "s2", "approved"),
        ];
        let hits = filter_requests(&rows, "web");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "a");
    }

    #[test]
    fn opt_maps_blank_to_none() {
        assert_eq!(opt(""), None);
        assert_eq!(opt("   "), None);
        assert_eq!(opt("approved"), Some("approved".to_string()));
    }

    #[test]
    fn default_offset_is_omitted_from_url() {
        // The first page (offset 0) keeps the URL clean — no `offset=0` noise.
        let facets = RequestFacets {
            status: "approved".to_string(),
            ..Default::default()
        };
        assert_eq!(facets.offset, 0);
        assert_eq!(
            build_request_filter_url(&facets),
            "/requests?status=approved"
        );
    }

    #[test]
    fn nonzero_offset_is_appended_last() {
        // A later page carries `offset` after every facet, encoded clean.
        let facets = RequestFacets {
            status: "approved".to_string(),
            offset: 50,
            ..Default::default()
        };
        assert_eq!(
            build_request_filter_url(&facets),
            "/requests?status=approved&offset=50"
        );
    }

    #[test]
    fn offset_only_facet_builds_offset_url() {
        let facets = RequestFacets {
            offset: 25,
            ..Default::default()
        };
        // A bare offset is not an "active" filter, but it must still page.
        assert!(!facets.is_active());
        assert_eq!(build_request_filter_url(&facets), "/requests?offset=25");
    }

    #[test]
    fn resetting_offset_on_facet_change_drops_it_from_url() {
        // Mirrors the on:change handlers: a facet edit sets offset back to 0 so
        // the user lands on page 1, leaving a clean URL.
        let mut next = RequestFacets {
            status: "approved".to_string(),
            offset: 75,
            ..Default::default()
        };
        // Simulate changing the status facet, which resets the page.
        next.status = "failed".to_string();
        next.offset = 0;
        assert_eq!(build_request_filter_url(&next), "/requests?status=failed");
    }

    #[test]
    fn request_list_page_serde_round_trip() {
        use crate::server_boundary::RequestListPage;

        let page = RequestListPage {
            rows: vec![row("a", "Alpha", "site-a", "intake")],
            offset: 25,
            page_size: 25,
            has_next: true,
        };
        let json = serde_json::to_string(&page).expect("serialize page");
        let back: RequestListPage = serde_json::from_str(&json).expect("deserialize page");
        assert_eq!(back, page);
    }
}
