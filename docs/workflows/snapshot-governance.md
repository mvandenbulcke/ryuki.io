# Snapshot governance

## Purpose

Operator runbook for the **Snapshot governance** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `snapshot-governance-contract.yaml`
- Serves contract route `/api/integrations/vmware/snapshot-governance-contract`.
- Validator slice `snapshot-governance`
- Contract `snapshot-governance-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    platformCiKey
    snapshotPurpose
    requestedExpiry
    owner
    supportGroup
    changeContext
    backupState
    maintenanceWindow
    evidenceManifest

Required guards and approvals (from the contract YAML).

    cmdb-ci-known
    owner-known
    backup-state-known
    expiry-policy-known
    approval-route-assigned
    lock-scope-defined
    rollback-notes-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live snapshot creation.
- No live snapshot deletion.
- not raw VMware, Hyper-V, or Proxmox snapshot inventory.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- provider-safe review and remediation plans.
- provider-neutral VMware, Hyper-V, and Proxmox wording.

## Evidence

Required evidence (from the contract YAML).

    Snapshot summary
    Policy decision
    Expiry review
    Backup impact
    Remediation dry-run plan
    Approval decisions
    Lock record
    Handover notes
    Evidence references
