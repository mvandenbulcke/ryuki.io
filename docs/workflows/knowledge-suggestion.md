# Knowledge suggestion from failed operations

## Purpose

Operator runbook for the **Knowledge suggestion from failed operations** / **Operations** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `knowledge-suggestion-contract.yaml`
- Serves contract route `/api/operations/knowledge-suggestion-contract`.
- Validator slice `knowledge-suggestion`
- Contract `knowledge-suggestion-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    failurePatternSummary
    operationTaxonomy
    affectedWorkflow
    safeRecommendation
    owner
    supportGroup
    reviewer
    evidenceManifest

Required guards and approvals (from the contract YAML).

    pattern-summary-redacted
    taxonomy-known
    frequency-threshold-met
    impact-summary-known
    reviewer-assigned
    recommendation-redacted
    export-package-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live knowledge publish.
- No live ticket mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- safe pattern summaries and recommendation export packages only.

## Evidence

Required evidence (from the contract YAML).

    Failure pattern summary
    Operation taxonomy
    Impact summary
    Knowledge candidate
    Runbook candidate
    Review route
    Recommendation export package
    Evidence references
