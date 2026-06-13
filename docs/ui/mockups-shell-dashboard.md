# Shell and Dashboard Mockups

Static wireframes for the Batch 2 product shell and the dashboard overview. These
are layout-only descriptions for a future implementation. No live execution, no
browser provider calls, and no external asset fetches.

## Product Shell Wireframe

The product shell wraps every workspace. From top to bottom and left to right it
contains:

- A scope band showing site, environment, role, data freshness, and execution
  authority.
- A primary navigation rail listing the nine stable workspaces: Dashboard,
  Catalog, Requests, Activity, Inventory, CMDB, Evidence, Operations, and Admin.
- A content region that hosts the active workspace.

The shell chrome is identical across workspaces; only the content region changes.

## Dashboard Overview Wireframe

The Dashboard Overview Wireframe is the default landing surface. It presents safe
summary cards only:

- Platform health summary (overall state plus a written status label).
- Open requests by lifecycle stage.
- Recent activity, summarized.
- Coverage and risk summaries for inventory, backup, and monitoring.

Every card shows a redacted, summarized state produced by the evidence pipeline.
No raw provider payloads, identifiers, or stack traces appear in any card,
tooltip, or panel.

## Light And Dark Mode Notes

The Light And Dark Mode Notes section records the theming requirements for the
shell and dashboard. Light and dark mode are both first-class product
requirements. The shell declares a light-and-dark color scheme and ships matching
accent, accent-text, surface, and status-badge tokens for each mode.

Status is never carried by color alone: every status badge pairs its hue with a
written label, and both themes meet the contrast targets in the accessibility
checklist.

## Acceptance Checklist For Future UI Implementation

- Shell chrome renders the scope band, navigation rail, and content region.
- Dashboard cards show safe summaries only.
- Keyboard focus is visible on every interactive element.
- Status is shown by text plus icon, never color alone.
- Light and dark mode both pass contrast review.

## Prohibitions

- No live provider calls.
- No raw provider payloads, identifiers, or stack traces in any view.
