# Worker capability routing

## Purpose

Operator runbook for the **Worker capability routing** / **Admin** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `worker-capability-contract.yaml`
- Serves contract route `/api/admin/worker-capability-contract`.
- Validator slice `worker-capability`
- Contract `worker-capability-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    workflowType
    requestedCapability
    site
    environment
    networkZone
    riskLevel
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    worker-registered
    capability-tag-known
    identity-reference-ready
    network-zone-approved
    approval-route-assigned
    dry-run-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live worker dispatch.
- No secret values.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Routing request summary
    Capability match
    Worker readiness
    Identity reference decision
    Network zone decision
    Approval route
    Dry-run readiness
    Evidence references
