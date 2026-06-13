# Security baseline

## Purpose

Operator runbook for the **Security baseline** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `security-baseline-contract.yaml`
- Serves contract route `/api/platform/security-baseline-contract`.
- Validator slice `security-baseline`
- Contract `security-baseline-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    securityScope
    controlSummary
    rbacApprovalSummary
    dryRunSummary
    networkIsolationSummary
    evidenceRedactionSummary
    verificationSummary
    evidenceManifest

Required guards and approvals (from the contract YAML).

    rbac-approval-reviewed
    dry-run-gates-reviewed
    browser-isolation-reviewed
    network-isolation-reviewed
    redaction-reviewed
    least-privilege-reviewed
    verification-gates-reviewed
    safe-failure-reviewed

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live authentication or token validation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- Secrets must never be committed.
- Live execution requires validation, approval, locking, execution, verification, evidence, and status callback.
- Browser code must call only `portal-ui` and `platform-api`
- Network policy starts from deny-all.
- Evidence must be redacted before storage, export, display, or indexing.
- Each adapter must use its own identity.

## Evidence

Required evidence (from the contract YAML).

    Security baseline summary
    RBAC and approval review
    Dry-run gate review
    Browser isolation review
    Network isolation review
    Evidence redaction review
    Least privilege review
    Verification gate review
    Evidence references
