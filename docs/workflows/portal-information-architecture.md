# Portal information architecture

## Purpose

Operator runbook for the **Portal information architecture** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `portal-information-architecture-contract.yaml`
- Serves contract route `/api/platform/portal-information-architecture-contract`.
- Validator slice `portal-information-architecture`
- Contract `portal-information-architecture-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    shellSummary
    navigationSummary
    personaSummary
    dashboardSummary
    catalogSummary
    requestLifecycleSummary
    inventoryCmdbEvidenceSummary
    operationsAdminSummary
    searchPaletteSummary
    scopeSelectorSummary
    evidenceManifest

Required guards and approvals (from the contract YAML).

    product-shell-reviewed
    primary-navigation-reviewed
    browser-isolation-reviewed
    same-origin-routing-reviewed
    role-visibility-reviewed
    scope-selector-reviewed
    freshness-state-reviewed
    evidence-redaction-reviewed
    admin-boundary-reviewed

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No direct browser calls.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- Axum-backed Leptos server.
- SSR.
- hydration.
- server-function boundary.
- static-only hosting remains disabled.

## Evidence

Required evidence (from the contract YAML).

    Portal shell review
    Navigation model review
    Persona defaults review
    Dashboard model review
    Catalog and request model review
    Activity, inventory, CMDB, and evidence review
    Operations and admin boundary review
    Search and command palette review
    Scope and freshness review
    Evidence safety review
