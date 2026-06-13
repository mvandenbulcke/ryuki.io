# Cluster capacity admission

## Purpose

Operator runbook for the **Cluster capacity admission** / **Cluster capacity admission check** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `cluster-capacity-admission-contract.yaml`
- Serves contract route `/api/integrations/vmware/cluster-capacity-admission-contract`.
- Validator slice `cluster-capacity-admission`
- Contract `cluster-capacity-admission-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    site
    clusterScope
    workloadProfile
    vmSizing
    storagePolicy
    availabilityTier
    reservationIntent
    growthWindow
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    cluster-summary-known
    compute-headroom-reviewed
    datastore-headroom-reviewed
    vsan-headroom-reviewed
    ha-failover-reviewed
    drs-balance-reviewed
    reservation-impact-reviewed
    growth-window-set
    owner-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live provider validation.
- No live VMware, Hyper-V, or Proxmox placement or mutation.
- not raw VMware, Hyper-V, or Proxmox capacity output.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- without calling VMware, Hyper-V, or Proxmox APIs.
- aggregate capacity summaries.
- Hypervisor Workflow Parity.
- VMware.
- Hyper-V.
- Proxmox.

## Evidence

Required evidence (from the contract YAML).

    Capacity admission summary
    Cluster scope summary
    Compute headroom
    Storage headroom
    HA and DRS risk
    Reservation impact
    Placement decision
    Exceptions and remediation
    Evidence references
