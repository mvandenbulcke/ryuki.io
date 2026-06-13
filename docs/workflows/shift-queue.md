# Handover and shift queue

## Purpose

Operator runbook for the **Handover and shift queue** / **Operations** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `shift-queue-contract.yaml`
- Serves contract route `/api/operations/shift-queue-contract`.
- Validator slice `shift-queue`
- Contract `shift-queue-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    queueItemSource
    severity
    owner
    supportGroup
    safeNextAction
    handoverNotes
    evidenceManifest

Required guards and approvals (from the contract YAML).

    owner-known
    support-group-known
    severity-assigned
    safe-next-action-set
    evidence-redacted
    stale-data-marked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No raw provider payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- safe summaries.

## Evidence

Required evidence (from the contract YAML).

    Queue item summary
    Owner assignment
    Safe next action
    Approval state
    Dependency health
    Handover notes
    Evidence references
