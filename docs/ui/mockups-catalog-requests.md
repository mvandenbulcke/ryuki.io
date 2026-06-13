# Catalog and Request Mockups

Static wireframes for the catalog browse surface and the request intake and
detail surfaces. These are layout-only descriptions for a future implementation.
No live execution, no browser provider calls, and no external asset fetches.

## Catalog Browse Wireframe

The catalog browse surface lists the offering categories and the offerings within
each category. Each offering card shows a safe summary: title, category, a short
description, and the lifecycle stages the request will pass through. Selecting an
offering opens the request intake form.

## Request Intake Wireframe

The request intake form renders the offering's required inputs and approvals from
the catalog contract. It shows the lifecycle the request will follow
(Draft through to Completed) and the approvals required at each gate. The form
collects only the inputs the contract declares; it never collects credentials,
tokens, or raw provider detail.

## Request Detail Wireframe

The request detail surface shows the lifecycle state, the preflight decision, the
approvals collected, and the safe evidence summary. The preflight panel shows
whether the request is cleared to proceed and, when blocked, the safe blocked
reason.

Write-capable workflows block live execution. The preflight gate keeps every
write-capable workflow in a dry-run-only posture: the detail surface can show the
planned change and the blocked reason, but it can never trigger a live provider
call from the browser.

## Acceptance Checklist For Future UI Implementation

- Catalog cards and request forms show safe summaries only.
- The request detail surface renders the preflight decision and blocked reason.
- Write-capable workflows block live execution from the browser.
- Keyboard focus is visible on every interactive element.
- Status is shown by text plus icon, never color alone.
- Light and dark mode both pass contrast review.

## Prohibitions

- No live provider calls.
- No raw provider payloads, identifiers, or stack traces in any view.
