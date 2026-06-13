# Catalog

## Purpose

Operator runbook for the **Catalog** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `request-form-contract.yaml`
- Serves contract route `/api/catalog/request-form-contract`.
- Validator slice `request-form-contract`
- Contract `request-form-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

The contract YAML does not declare structured inputs yet. Capture the requesting role, target site, environment, and the approval decision in the request record before the approve stage completes.

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live request creation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- form submission.
- raw form submissions.
- raw recipient data.

## Evidence

Required evidence (from the contract YAML).

    Form schema review
    Offering input coverage review
    Static schema boundary
    Dry-run policy review
    Evidence references
