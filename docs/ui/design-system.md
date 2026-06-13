# Design System

The design system defines how the Ryuki portal presents platform state safely.
It is referenced by the `portal-information-architecture`, `design-system`, and
`ui-mockup-acceptance` slices.

## Safe presentation

The portal renders redacted, summarized state only.

Presentation rule: Do not display raw JSON, provider payloads, stack traces, credentials, identifiers, or private network detail in any view, tooltip, or debug panel.

Every surface shows the safe summary produced by the evidence pipeline; raw detail never reaches the browser.

## Layout and components

Workspaces share a common shell: a scope band (site, environment, role, data
freshness, execution authority), a primary navigation rail, and a content region.
Components present provider-safe summaries and link to the per-contract runbooks
for detail rather than embedding raw records.

## Theme

Light and dark mode are both first-class product requirements. The portal
declares a light-and-dark color scheme and ships matching accent, accent-text,
surface, and status-badge tokens for each mode, so every surface stays legible
and contrast-safe whether the operator runs the light or the dark theme.

Status is never carried by color alone. Each accent has a text companion token,
and status badges pair their hue with a written label so the meaning survives in
both themes and for color-blind operators.
