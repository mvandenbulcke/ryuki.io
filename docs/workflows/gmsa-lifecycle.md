# gMSA lifecycle

## Purpose

Operator runbook for the **gMSA lifecycle** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `gmsa-lifecycle-contract.yaml`
- Serves contract route `/api/identity/gmsa-lifecycle-contract`.
- Validator slice `gmsa-lifecycle`
- Contract `gmsa-lifecycle-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    lifecycleAction
    requestContext
    serviceAccountSummary
    retrievalScopeSummary
    workerUsageSummary
    kerberosPolicySummary
    spnPolicySummary
    delegationPolicySummary
    owner
    supportGroup
    approvalRoute
    rollbackPlan
    evidenceManifest

Required guards and approvals (from the contract YAML).

    request-context-known
    service-account-scope-summarized
    kds-root-key-readiness-reviewed
    retrieval-scope-reviewed
    kerberos-policy-reviewed
    spn-policy-reviewed
    delegation-risk-reviewed
    worker-capability-reviewed
    approval-route-assigned
    rollback-plan-ready
    recovery-readiness-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No worker execution.
- No live directory changes.
- No gMSA creation, assignment, validation, retire, password retrieval, managed password handling, SPN changes, or delegation changes.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- static gMSA lifecycle summaries only.

## Evidence

Required evidence (from the contract YAML).

    gMSA lifecycle review summary
    Service account scope summary
    Kerberos policy review
    SPN policy review
    Delegation risk review
    Worker usage review
    Approval route
    Rollback plan
    Recovery readiness
    Evidence references
