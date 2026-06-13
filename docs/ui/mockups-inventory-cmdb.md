# Inventory and CMDB Mockups

Static wireframes for the inventory and CMDB workspaces. These are layout-only
descriptions for a future implementation. No live execution, no browser provider
calls, and no external asset fetches.

## Inventory Overview Wireframe

The inventory overview surface presents coverage and ownership summaries: how much
of the estate is covered by inventory, backup, and monitoring, and where coverage
gaps and ownership risks sit. Every figure is a safe summary; individual records
are linked to their runbooks rather than embedded raw.

## CMDB Import Wireframe

The CMDB Import Wireframe describes how a CMDB import is reviewed before it is
accepted. It shows the import source summary, the proposed additions and changes
as counts, and the validation result. The import view presents safe summaries
only and never displays raw provider payloads or identifiers.

## CMDB Reconciliation And Export Wireframe

The CMDB Reconciliation And Export Wireframe shows the reconciliation result
between the platform's view and the CMDB: matched, drifted, and missing items as
counts, with safe summaries of each drift class. The export view shows what would
be exported as a redacted summary and records the export readiness state. No raw
records leave the boundary; exports are safe summaries only.

## Acceptance Checklist For Future UI Implementation

- Inventory and CMDB surfaces show safe summaries and counts only.
- Import and reconciliation views show validation and drift results without raw
  payloads.
- Keyboard focus is visible on every interactive element.
- Status is shown by text plus icon, never color alone.
- Light and dark mode both pass contrast review.

## Prohibitions

- No live provider calls.
- No raw provider payloads, identifiers, or stack traces in any view.
