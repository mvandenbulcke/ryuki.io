# Evidence, Operations, and Admin Mockups

Static wireframes for the evidence, operations, and admin workspaces. These are
layout-only descriptions for a future implementation. No live execution, no
browser provider calls, and no external asset fetches.

## Browser Isolation Note

The browser-facing portal must remain limited to the portal-ui bundle and the
platform API. Vendor and infrastructure access is represented only as server-side
platform summaries: the browser bundle never calls an adapter, a provider, the
database, or the secret store directly. All privileged work crosses the portal
server-function boundary.

## Evidence Workspace Wireframe

The evidence surface lists evidence records as safe summaries with their redaction
state, export readiness, and controlled accepted or rejected counts. Selecting a
record shows the redacted summary; raw evidence payloads never reach the browser.

## Operations Workspace Wireframe

The operations surface shows the activity and run-state queues, runbook launch
readiness, and incident context as safe summaries. Run state is shown by written
status plus icon, and any blocked run shows its safe blocked reason.

## Admin Workspace Wireframe

The admin surface shows worker capability, feature-flag governance, approval
groups, delegation boundaries, and the persisted site registry as safe summaries.
Admin actions that change state are gated and shown with their authority context.

## Acceptance Checklist For Future UI Implementation

- Evidence records show redaction state, export readiness, and accepted or
  rejected counts as safe summaries.
- The browser-facing portal must remain limited to the portal bundle and the
  platform API.
- Keyboard focus is visible on every interactive element.
- Status is shown by text plus icon, never color alone.
- Light and dark mode both pass contrast review.

## Prohibitions

- No live provider calls.
- No raw provider payloads, identifiers, or stack traces in any view.
