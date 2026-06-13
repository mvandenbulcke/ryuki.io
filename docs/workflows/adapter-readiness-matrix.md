# Adapter readiness matrix

## Purpose

Operator runbook for the **Adapter readiness matrix** / **Admin** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `adapter-readiness-matrix-contract.yaml`
- Serves contract route `/api/integrations/adapter-readiness-matrix-contract`.
- Validator slice `adapter-readiness-matrix`
- Contract `adapter-readiness-matrix-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    adapterDomain
    site
    scope
    apiVersionState
    permissionScopeState
    reachabilityState
    dryRunCapabilityState
    staleDataMarker
    owner
    supportGroup
    evidenceManifest

Required guards and approvals (from the contract YAML).

    endpoint-not-raw
    api-version-reviewed
    permissions-reviewed
    stale-data-marked
    owner-known
    support-group-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live provider validation.
- No credential values or secret paths.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- readiness summaries only.

## Evidence

Required evidence (from the contract YAML).

    Readiness summary
    Adapter scope
    API version review
    Permission scope review
    Reachability state
    Stale-data marker
    Safe capabilities
    Evidence references
