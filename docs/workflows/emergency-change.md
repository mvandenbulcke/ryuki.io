# Break-glass emergency change

## Purpose

Operator runbook for the **Break-glass emergency change** / **Operations** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `emergency-change-contract.yaml`
- Serves contract route `/api/operations/emergency-change-contract`.
- Validator slice `emergency-change`
- Contract `emergency-change-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    ticketContext
    emergencyReason
    requester
    affectedService
    targetScope
    businessImpact
    approver
    owner
    rollbackPlan
    evidenceManifest

Required guards and approvals (from the contract YAML).

    emergency-role-authorized
    incident-or-ticket-linked
    emergency-approver-assigned
    scope-bounded
    dry-run-ready
    lock-record-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No privileged worker execution.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- must not bypass approval.

## Evidence

Required evidence (from the contract YAML).

    Emergency request summary
    Incident or ticket reference
    Approval decisions
    Delegated authority
    Scope and lock record
    Dry-run plan summary
    Verification result
    Privileged worker log reference
    Evidence references
