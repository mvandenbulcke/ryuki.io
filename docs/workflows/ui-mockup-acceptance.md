# UI mockup acceptance

## Purpose

Operator runbook for the **UI mockup acceptance** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `ui-mockup-acceptance-contract.yaml`
- Serves contract route `/api/platform/ui-mockup-acceptance-contract`.
- Validator slice `ui-mockup-acceptance`
- Contract `ui-mockup-acceptance-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    shellDashboardReview
    catalogRequestReview
    inventoryCmdbReview
    evidenceOperationsAdminReview
    accessibilitySummary
    browserIsolationSummary
    evidenceSafetySummary
    statusBehaviorSummary
    themeSummary
    evidenceManifest

Required guards and approvals (from the contract YAML).

    shell-dashboard-reviewed
    catalog-requests-reviewed
    inventory-cmdb-reviewed
    evidence-operations-admin-reviewed
    browser-isolation-reviewed
    accessibility-reviewed
    status-behavior-reviewed
    evidence-redaction-reviewed
    raw-detail-exclusion-reviewed

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live UI execution.
- No browser provider calls.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Shell and dashboard mockup review
    Catalog and request mockup review
    Inventory and CMDB mockup review
    Evidence operations and admin mockup review
    Accessibility acceptance review
    Browser isolation review
    Status behavior review
    Theme behavior review
    Evidence safety review
    Raw detail exclusion review
