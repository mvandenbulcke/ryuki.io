# Approval model

## Purpose

Operator runbook for the **Approval model** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `approval-decision-readiness-contract.yaml`
- Serves contract route `/api/approvals/decision-readiness-contract`.
- Validator slice `approval-decision-readiness`
- Contract `approval-decision-readiness-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    approval-route-known
    request-scope-summarized
    decision-state-known
    datacenter-final-approval
    delegated-authority-reviewed
    emergency-flag-reviewed
    separation-of-duties-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No approval execution.
- No raw approver data.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Approval route summary
    Decision state summary
    Delegated authority review
    Emergency flag review
    Separation of duties review
    Approval evidence references
