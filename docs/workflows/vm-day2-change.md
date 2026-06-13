# VM day-2 change

## Purpose

Operator runbook for the **VM day-2 change** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `vm-day2-change-contract.yaml`
- Serves contract route `/api/integrations/vmware/day2-change-contract`.
- Validator slice `vm-day2-change`
- Contract `vm-day2-change-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    platformCiKey
    changeType
    targetScope
    site
    environment
    owner
    capacityNeed
    maintenanceWindow
    rollbackPlan
    migrationDirection
    migrationMethod
    downtimeClass
    sourceBackupVerification
    sourceQuarantineWindow
    targetGuestTooling
    cutoverValidationPlan
    evidenceManifest

Required guards and approvals (from the contract YAML).

    request-preflight-ready
    capacity-admission-ready
    cmdb-ci-known
    backup-state-known
    monitoring-impact-reviewed
    approval-route-assigned
    lock-scope-defined
    rollback-plan-ready
    cold-offline-default
    source-backup-verified
    source-quarantine-planned
    downtime-window-approved
    target-guest-tooling-planned
    cutover-validation-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live VMware, Hyper-V, or Proxmox changes.
- No worker execution.
- not raw hypervisor output.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- provider-safe change plans.
- migration equivalence matrix.
- blocked live execution.
- provider mutation.
- cold/offline V2V.
- planned outage.
- source quarantine.
- rollback or reverse plan.
- source backup verification.
- target-native guest tooling.
- warm/live migration remains a later tool-specific exception.
- VMware.
- Hyper-V.
- Proxmox.
- vmware-to-hyperv.
- hyperv-to-vmware.
- vmware-to-proxmox.
- hyperv-to-proxmox.
- proxmox-to-vmware.
- proxmox-to-hyperv.

## Evidence

Required evidence (from the contract YAML).

    Request payload summary
    VM change dry-run plan
    Capacity impact
    Network impact
    Backup and monitoring impact
    CMDB update plan
    Approval decisions
    Lock record
    Verification plan
    Migration method matrix
    Downtime class
    Source backup verification
    Source quarantine plan
    Target guest tooling plan
    Cutover validation plan
    Evidence references
