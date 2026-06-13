# Operations

## Purpose

Operator runbook for the **Operations** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `aiops-suggestion-contract.yaml`
- Serves contract route `/api/operations/aiops-suggestion-contract`.
- Validator slice `aiops-suggestion`
- Contract `aiops-suggestion-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    signalSummary
    affectedWorkflow
    healthDomain
    impactBand
    owner
    supportGroup
    reviewer
    evidenceManifest

Required guards and approvals (from the contract YAML).

    signal-summary-redacted
    correlation-static-only
    impact-band-known
    owner-route-known
    reviewer-assigned
    recommendation-redacted
    automation-disabled
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No raw operation rows, raw health rows, raw logs, raw user data, raw recipient data, ticket identifiers, incident identifiers, change identifiers, tenant identifiers, object identifiers, private network details, live endpoints, serial numbers, credentials, tokens, or provider payloads in committed files.
- never dispatch workers.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- AIOps suggestions use static, aggregate, or manually reviewed summaries only.

## Evidence

Required evidence (from the contract YAML).

    AIOps signal summary
    Static correlation summary
    Impact assessment
    Recommendation candidate
    Owner route
    Review route
    Safe next action
    Evidence references
