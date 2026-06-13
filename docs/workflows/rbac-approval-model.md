# RBAC and approval model

## Purpose

Operator runbook for the **RBAC and approval model** / **Admin** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `rbac-approval-model-contract.yaml`
- Serves contract route `/api/identity/rbac-approval-model-contract`.
- Validator slice `rbac-approval-model`
- Contract `rbac-approval-model-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    roleActionMatrix
    approvalRouteSummary
    executionGuardSummary
    requestContext
    approvalDecisionSummary
    emergencyApprovalSummary
    evidenceManifest

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live authentication.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- access-control catalog.

## Evidence

Required evidence (from the contract YAML).

    RBAC model summary
    Role action matrix
    Approval route summary
    Execution guard summary
    Segregation of duties review
    Emergency approval review
    Evidence references
