# Patch wave planning

## Purpose

Operator runbook for the **Patch wave planning** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `patch-maintenance-contract.yaml`
- Serves contract route `/api/patching/maintenance-contract`.
- Validator slice `patch-maintenance`
- Contract `patch-maintenance-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    patchCycle
    siteScope
    applicationScope
    environmentScope
    criticality
    dependencyContext
    maintenanceWindow
    rebootPolicy
    blackoutDates

Required guards and approvals (from the contract YAML).

    patch-policy-imported
    inventory-coverage-current
    backup-state-known
    monitoring-maintenance-ready
    approval-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- never enables live patch execution or reboot execution.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- provider-safe wave and reboot plans.

## Evidence

Required evidence (from the contract YAML).

    Request payload summary
    Validation result
    Wave plan summary
    Reboot queue summary
    Risk notes
    Approval decisions
    Handover notes
    Evidence references
