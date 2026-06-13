# Access review and ownership recertification

## Purpose

Operator runbook for the **Access review and ownership recertification** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `access-review-recertification-contract.yaml`
- Serves contract route `/api/identity/access-review-recertification-contract`.
- Validator slice `access-review-recertification`
- Contract `access-review-recertification-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    reviewScopeSummary
    recertificationCycle
    accessScope
    roleProfile
    ownershipSummary
    supportGroup
    riskTier
    reviewCadence
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    review-scope-summarized
    owner-known
    support-group-known
    approval-route-assigned
    evidence-redacted
    raw-identity-data-blocked
    expiry-date-set
    remediation-plan-ready

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live directory changes.
- No live ServiceNow changes.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- safe access review summaries only.

## Evidence

Required evidence (from the contract YAML).

    Access review summary
    Scope review
    Ownership decision
    Privileged access review
    Service account review
    Exception decision
    Remediation plan
    Evidence references
