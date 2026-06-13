# OS baseline compliance

## Purpose

Operator runbook for the **OS baseline compliance** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `os-baseline-compliance-contract.yaml`
- Serves contract route `/api/inventory/os-baseline-compliance-contract`.
- Validator slice `os-baseline-compliance`
- Contract `os-baseline-compliance-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    platformCiKey
    osFamily
    site
    environment
    owner
    supportGroup
    baselineProfile
    platformGuestToolingPosture
    inventoryFreshness
    evidenceManifest

Required guards and approvals (from the contract YAML).

    inventory-coverage-current
    baseline-profile-known
    os-family-supported
    owner-known
    platform-guest-tooling-posture-known
    worker-capability-known
    remediation-plan-dry-run
    approval-route-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.
- No live remediation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- normalized drift summaries.
- VMware Tools.
- Hyper-V integration services.
- Proxmox QEMU guest agent.

## Evidence

Required evidence (from the contract YAML).

    Compliance summary
    Baseline profile
    Platform guest tooling posture
    Drift finding summary
    Inventory freshness
    Remediation dry-run plan
    Approval decisions
    Handover notes
    Evidence references
