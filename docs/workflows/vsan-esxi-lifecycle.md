# vSAN, ESXi, and host lifecycle

## Purpose

Operator runbook for the **vSAN, ESXi, and host lifecycle** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `vsan-esxi-lifecycle-contract.yaml`
- Serves contract route `/api/integrations/vmware/vsan-esxi-lifecycle-contract`.
- Validator slice `vsan-esxi-lifecycle`
- Contract `vsan-esxi-lifecycle-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    clusterScope
    site
    hypervisorPlatform
    platformProfile
    targetBaseline
    maintenanceWindow
    capacityDecision
    hardwareReadiness
    networkReadiness
    rollbackPlan
    evidenceManifest

Required guards and approvals (from the contract YAML).

    cluster-scope-known
    site-known
    platform-profile-known
    target-baseline-known
    hardware-readiness-reviewed
    network-readiness-reviewed
    capacity-admission-ready
    maintenance-window-approved
    rollback-plan-ready
    dry-run-plan-produced
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live vSAN, ESXi.
- No raw inventory rows.
- No host identifiers.
- not raw VMware, Hyper-V, or Proxmox host inventory.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- dry-run lifecycle summaries only.
- without calling VMware, Hyper-V, or Proxmox.
- VMware.
- Hyper-V.
- Proxmox.
- Platform lifecycle parity is limited to static dry-run summaries.

## Evidence

Required evidence (from the contract YAML).

    Lifecycle summary
    Current baseline summary
    Target baseline summary
    Hardware and firmware review
    Network and storage readiness
    Maintenance mode plan
    Capacity and failure-domain impact
    Rollback plan
    Policy exception decision
    Evidence references
