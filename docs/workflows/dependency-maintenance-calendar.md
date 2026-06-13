# Dependency-aware maintenance calendar

## Purpose

Operator runbook for the **Dependency-aware maintenance calendar** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `dependency-maintenance-calendar-contract.yaml`
- Serves contract route `/api/patching/maintenance-calendar-contract`.
- Validator slice `dependency-maintenance-calendar`
- Contract `dependency-maintenance-calendar-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    maintenanceWindow
    affectedServices
    dependencyGraphSummary
    owner
    supportGroup
    site
    environment
    changeContext
    evidenceManifest

Required guards and approvals (from the contract YAML).

    cmdb-relationship-graph-ready
    patch-policy-imported
    maintenance-window-known
    dependency-order-known
    blackout-window-clear
    owner-known
    communications-draft-only
    approval-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live scheduling.
- No live notification send.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- aggregate maintenance plans and drafts.

## Evidence

Required evidence (from the contract YAML).

    Calendar summary
    Affected service summary
    Dependency order
    Conflict review
    Communication draft
    Approval decisions
    Handover notes
    Evidence references
