# VM decommission quarantine

## Purpose

Operator runbook for the **VM decommission quarantine** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `vm-decommission-quarantine-contract.yaml`
- Serves contract route `/api/integrations/vmware/decommission-quarantine-contract`.
- Validator slice `vm-decommission-quarantine`
- Contract `vm-decommission-quarantine-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    platformCiKey
    targetScope
    site
    environment
    owner
    businessJustification
    dependencyReview
    backupRetentionNeed
    quarantineWindow
    cmdbContext
    evidenceManifest

Required guards and approvals (from the contract YAML).

    request-preflight-ready
    cmdb-ci-known
    owner-approval-assigned
    dependency-impact-reviewed
    backup-retention-reviewed
    monitoring-disable-reviewed
    quarantine-window-approved
    rollback-plan-ready
    final-disposition-blocked
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live VM decommission.
- No raw inventory rows.
- No VM names.
- not raw VMware, Hyper-V, Proxmox, or provider inventory.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- dry-run quarantine summaries only.
- VMware, Hyper-V, and Proxmox.

## Evidence

Required evidence (from the contract YAML).

    Quarantine summary
    Dependency review
    Backup retention review
    Monitoring disable plan
    CMDB retirement plan
    Quarantine window
    Rollback plan
    Final disposition hold
    Evidence references
