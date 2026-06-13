# Network port and VLAN readiness

## Purpose

Operator runbook for the **Network port and VLAN readiness** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `network-vlan-readiness-contract.yaml`
- Serves contract route `/api/operations/network-vlan-readiness-contract`.
- Validator slice `network-vlan-readiness`
- Contract `network-vlan-readiness-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    site
    networkScope
    workloadProfile
    platformProfile
    vlanPolicy
    portgroupPolicy
    redundancyRequirement
    maintenanceWindow
    owner
    evidenceManifest

Required guards and approvals (from the contract YAML).

    site-known
    network-scope-known
    vlan-catalog-reviewed
    portgroup-policy-reviewed
    switchport-capacity-reviewed
    uplink-redundancy-reviewed
    segmentation-reviewed
    maintenance-window-known
    owner-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live network changes.
- No raw inventory rows.
- No switch identifiers.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- network-safe readiness summaries only.

## Evidence

Required evidence (from the contract YAML).

    Readiness summary
    VLAN policy review
    Portgroup policy review
    Switchport capacity review
    Uplink and trunk review
    Segmentation review
    Exception decision
    Evidence references
