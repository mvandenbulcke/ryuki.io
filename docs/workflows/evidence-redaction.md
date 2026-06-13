# Evidence and redaction model

## Purpose

Operator runbook for the **Evidence and redaction model** / **Evidence** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `evidence-redaction-contract.yaml`
- Serves contract route `/api/catalog/evidence-redaction-contract`.
- Validator slice `evidence-redaction-contract`
- Contract `evidence-redaction-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

The contract YAML does not declare structured inputs yet. Capture the requesting role, target site, environment, and the approval decision in the request record before the approve stage completes.

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No raw request payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- evidence-manifest-catalog.yaml.

## Evidence

Required evidence (from the contract YAML).

    Evidence manifest summary
    Redaction check summary
    Export readiness decision
    Prohibited content review
    Retention class decision
    Evidence references
