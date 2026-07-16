# AD computer object lifecycle

## Purpose

Operator runbook for the **AD computer object lifecycle** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `ad-computer-lifecycle-contract.yaml`
- Serves contract route `/api/identity/ad-computer-lifecycle-contract`.
- Validator slice `ad-computer-lifecycle`
- Contract `ad-computer-lifecycle-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    lifecycleAction
    requestContext
    targetComputerSummary
    ouPolicySummary
    lifecycleState
    cmdbState
    owner
    supportGroup
    approvalRoute
    rollbackPlan
    evidenceManifest

Required guards and approvals (from the contract YAML).

    request-context-known
    target-scope-summarized
    canonical-name-site-owner-bound
    server-derived-ou-policy-match
    namespace-provenance-verified
    current-owner-site-active
    quarantine-recovery-maker-checker
    ou-policy-reviewed
    lifecycle-action-supported
    cmdb-state-reviewed
    approval-route-assigned
    rollback-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.
- No live directory changes.
- No computer prestage, move, disable, delete, or recover actions.
- Namespace provenance and the active owner site are required for every
  platform-state read or mutation. Quarantined legacy rows require a fresh,
  version-bound maker/checker recovery and are never auto-promoted.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- static AD computer lifecycle summaries only.

## Evidence

Required evidence (from the contract YAML).

    Lifecycle review summary
    Target scope summary
    OU policy review
    CMDB reconciliation summary
    Approval route
    Rollback plan
    Recovery readiness
    Evidence references
