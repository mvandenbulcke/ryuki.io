# Object placement standards

## Purpose

Operator runbook for the **Object placement standards** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `vcenter-object-placement-contract.yaml`
- Serves contract route `/api/integrations/vmware/object-placement-contract`.
- Validator slice `vcenter-object-placement`
- Contract `vcenter-object-placement-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    placementScope
    workloadProfile
    site
    environment
    criticality
    owner
    capacityDecision
    networkProfile
    storageProfile
    tagPolicy
    evidenceManifest

Required guards and approvals (from the contract YAML).

    site-known
    environment-known
    folder-policy-known
    cluster-capacity-admitted
    resource-pool-policy-known
    datastore-policy-known
    storage-policy-known
    network-profile-known
    tag-policy-known
    dry-run-plan-produced
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live VMware, Hyper-V, or Proxmox placement.
- No raw inventory rows.
- No object identifiers.
- not raw VMware, Hyper-V, or Proxmox inventory.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- for VMware, Hyper-V, and Proxmox, without live provider calls or placement changes.
- dry-run placement summaries only.
- VMware, Hyper-V, and Proxmox.
- All parity entries are static dry-run summaries only.

## Evidence

Required evidence (from the contract YAML).

    Placement summary
    Folder plan
    Cluster and resource pool plan
    Datastore and storage policy plan
    Network plan
    Tag policy plan
    Policy exception decision
    Evidence references
