# Catalog

## Purpose

Operator runbook for the **Catalog** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `offering-recommendations-contract.yaml`
- Serves contract route `/api/catalog/recommendations-contract`.
- Validator slice `offering-recommendations`
- Contract `offering-recommendations-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    catalog-source-reviewed
    role-scope-summarized
    application-profile-summarized
    site-scope-summarized
    approval-route-known
    dry-run-required
    evidence-redacted
    live-personalization-blocked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live personalization.
- No live catalog queries.
- No live request creation.
- No identity lookup.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- raw user data.
- raw application data.
- raw site data.
- raw recipient data.
- static offering recommendation summaries only.

## Evidence

Required evidence (from the contract YAML).

    Recommendation summary
    Role fit summary
    Application profile summary
    Site fit summary
    Evidence references
