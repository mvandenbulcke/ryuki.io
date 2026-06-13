# Approved software deployment

## Purpose

Operator runbook for the **Approved software deployment** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `approved-software-deployment-contract.yaml`
- Serves contract route `/api/software/approved-deployment-contract`.
- Validator slice `approved-software-deployment`
- Contract `approved-software-deployment-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    packageId
    action
    targetScope
    osFamily
    versionPolicy
    owner
    supportGroup
    changeContext
    evidenceManifest

Required guards and approvals (from the contract YAML).

    package-approved
    version-policy-known
    target-scope-known
    os-family-supported
    worker-capability-known
    reboot-impact-reviewed
    approval-route-assigned
    rollback-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.
- No live install, update, remove, or package dispatch.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- approved package plans.

## Evidence

Required evidence (from the contract YAML).

    Request payload summary
    Package approval
    Version decision
    Deployment dry-run plan
    Reboot impact
    Rollback plan
    Verification plan
    Approval decisions
    Evidence references
