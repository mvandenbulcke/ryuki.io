# Accessibility Checklist

This checklist defines the accessibility bar the Ryuki portal mockups and any
future implementation must clear. It is referenced by the `design-system` and
`ui-mockup-acceptance` slices and the per-contract workflow runbooks.

## Non-color status signalling

Every status badge must include text, not color alone. A red, amber, or grey hue
may reinforce a state, but the badge always carries a written label (for example
"Healthy", "Warning", "Failed", or "Stale") so the meaning survives for
color-blind operators and in high-contrast or printed views.

Stale, degraded, blocked, and safe-error states each get a distinct label and
icon in addition to their color, and they read the same way in light and dark
mode.

## Keyboard and focus

Focus must be visible at all times. Every interactive control shows a clear
focus-visible outline, focus order follows reading order, and no control can be
reached only by pointer. Skip links and landmark regions let keyboard operators
move between the scope band, navigation rail, and content region without
traversing every link.

## Contrast and theming

Text, badges, and accents meet contrast targets in both light and dark mode.
Accent colors are paired with an accent-text companion token so foreground text
on accent surfaces stays readable.

## Batch 2 Acceptance

Batch 2 Acceptance requires that the shell, dashboard, catalog, request,
inventory, CMDB, evidence, operations, and admin mockups each demonstrate:

- Visible keyboard focus on every interactive element.
- Status conveyed by text plus icon, never color alone.
- Stale, degraded, blocked, and safe-error states with explicit labels.
- Contrast-safe presentation in both light and dark mode.
- Safe summaries only, with no raw provider payloads, stack traces, or
  identifiers reaching the browser.

## Prohibitions

- No live provider calls.
- No raw provider payloads, stack traces, credentials, or identifiers in any
  view, tooltip, or debug panel.
