# Certificate lifecycle

## Purpose

Operator runbook for the **Certificate lifecycle** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `certificate-lifecycle-contract.yaml`
- Serves contract route `/api/operations/certificate-lifecycle-contract`.
- Validator slice `certificate-lifecycle`
- Contract `certificate-lifecycle-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    certificateScope
    targetProfile
    issuerProfile
    subjectPolicy
    validityWindow
    owner
    supportGroup
    maintenanceWindow
    rollbackPlan
    evidenceManifest

Required guards and approvals (from the contract YAML).

    certificate-scope-known
    target-profile-known
    issuer-profile-known
    subject-policy-reviewed
    private-key-material-blocked
    approval-route-assigned
    maintenance-window-known
    rollback-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live certificate actions.
- No private key material.
- No certificate serials or thumbprints.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- dry-run certificate plans only.
- without calling certificate authorities, DNS, VMware, Hyper-V, Proxmox, hardware interfaces, load balancers, ServiceNow, or any provider API.
- VMware, Hyper-V, and Proxmox certificate target coverage is static planning metadata only.

## Evidence

Required evidence (from the contract YAML).

    Certificate lifecycle summary
    Scope review
    Issuer readiness
    Subject policy decision
    Renewal or replacement plan
    Installation dry-run plan
    Rollback plan
    Approval route
    Evidence references
