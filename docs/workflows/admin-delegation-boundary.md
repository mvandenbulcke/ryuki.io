# Admin

## Purpose

Operator runbook for the **Admin** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `admin-delegation-boundary-contract.yaml`
- Serves contract route `/api/admin/delegation-boundary-contract`.
- Validator slice `admin-delegation-boundary`
- Contract `admin-delegation-boundary-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    delegate-role-known
    site-scope-known
    approval-route-assigned
    expiry-set
    separation-of-duties-reviewed
    break-glass-reviewed
    evidence-redacted
    live-delegation-blocked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live delegation changes.
- No role assignment, approval, policy, or workflow mutation.
- No Graph calls.
- No provider calls.
- No notification dispatch.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw user data.
- raw group data.
- raw delegation rows.
- tenant identifiers.
- static admin delegation-boundary summaries only.

## Evidence

Required evidence (from the contract YAML).

    Delegation boundary summary
    Site scope summary
    Role scope summary
    Approval route summary
    Expiry and review summary
    Evidence references
