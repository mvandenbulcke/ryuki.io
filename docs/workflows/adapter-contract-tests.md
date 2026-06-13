# Adapter contract tests

## Purpose

Operator runbook for the **Adapter contract tests** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `adapter-contract-test-contract.yaml`
- Serves contract route `/api/integrations/adapter-contract-test-contract`.
- Validator slice `adapter-contract-test`
- Contract `adapter-contract-test-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    adapterDomain
    contractScope
    fixtureSet
    expectedState
    blockedReasonSet
    dryRunCapabilityState
    staleDataMarker
    owner
    evidenceManifest

Required guards and approvals (from the contract YAML).

    fixture-set-redacted
    provider-calls-blocked
    network-egress-blocked
    expected-state-declared
    blocked-reasons-declared
    stale-data-marked
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live provider validation.
- No live credentials.
- No network egress.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- mock contract test summaries only.

## Evidence

Required evidence (from the contract YAML).

    Contract test summary
    Fixture scope
    Readiness assertions
    Dry-run assertions
    Blocked default assertions
    Redaction assertions
    Evidence assertions
    Handover notes
