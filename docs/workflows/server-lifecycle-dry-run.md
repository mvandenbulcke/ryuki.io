# Windows server deployment

## Purpose

Operator runbook for the **Windows server deployment** / **Linux server deployment** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `server-lifecycle-dry-run-contract.yaml`
- Serves contract route `/api/workflows/server-lifecycle/dry-run-contract`.
- Validator slice `server-lifecycle-dry-run`
- Contract `server-lifecycle-dry-run-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    businessPurpose
    requester
    owner
    site
    environment
    criticality
    hypervisorPlatform
    imageVersion
    vmSizing
    network
    backupPolicy
    monitoringProfile
    cmdbContext

Required guards and approvals (from the contract YAML).

    request-preflight-ready
    capacity-admission-ready
    inventory-coverage-current
    approval-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- never enables live execution.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- provider-safe plan.
- VMware.
- Hyper-V.
- Proxmox.
- live hypervisor execution disabled.
- sles.
- rhel.
- rocky-linux.
- alma-linux.
- ubuntu.
- debian.
- baseline plan.
- patch plan.
- monitoring plan.
- backup plan.
- CMDB plan.

## Evidence

Required evidence (from the contract YAML).

    Request payload summary
    Validation result
    Provider-safe plan
    Capacity check summary
    Policy assignments
    CMDB export package
    Evidence references
