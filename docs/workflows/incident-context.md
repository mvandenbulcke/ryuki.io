# Incident context panel

## Purpose

Operator runbook for the **Incident context panel** / **Operations** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `incident-context-contract.yaml`
- Serves contract route `/api/operations/incident-context-contract`.
- Validator slice `incident-context`
- Contract `incident-context-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    incidentContext
    ciIdentity
    application
    owner
    supportGroup
    site
    environment
    evidenceManifest

Required guards and approvals (from the contract YAML).

    incident-linked
    ci-identity-known
    owner-known
    support-group-known
    stale-data-marked
    evidence-redacted
    safe-next-action-set

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No raw provider payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- aggregate-safe incident context.

## Evidence

Required evidence (from the contract YAML).

    Incident summary
    CI identity summary
    Owner and support group
    Change context
    Backup state
    Monitoring state
    CMDB relationship summary
    Safe next actions
    Evidence references
