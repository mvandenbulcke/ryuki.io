# Reboot orchestration

## Purpose

Operator runbook for the **Reboot orchestration** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `reboot-orchestration-contract.yaml`
- Serves contract route `/api/patching/reboot-orchestration-contract`.
- Validator slice `reboot-orchestration`
- Contract `reboot-orchestration-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    patchCycle
    rebootScope
    maintenanceWindow
    dependencyOrder
    backupState
    monitoringMaintenance
    owner
    supportGroup
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    patch-policy-imported
    dependency-order-known
    maintenance-window-approved
    blackout-window-clear
    backup-state-known
    monitoring-maintenance-ready
    approval-route-assigned
    lock-scope-defined
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live reboot execution.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- provider-safe reboot queues.

## Evidence

Required evidence (from the contract YAML).

    Request payload summary
    Validation result
    Dependency order
    Reboot queue summary
    Maintenance window
    Backup state
    Monitoring maintenance plan
    Approval decisions
    Lock record
    Handover notes
    Evidence references
