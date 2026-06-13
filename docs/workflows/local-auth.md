# Local auth

## Purpose

Operator runbook for the **Local auth** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `local-auth-contract.yaml`
- Serves contract route `/api/auth/local/roles`.
- Validator slice `local-auth`
- Contract `local-auth-contract.yaml` is marked active

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

The contract YAML does not declare structured inputs yet. Capture the requesting role, target site, environment, and the approval decision in the request record before the approve stage completes.

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- Also serves `/api/auth/local/me`.
- Also serves `/api/auth/local/decision`.
- It is not production authentication.
- configuredForProduction` is always `false`
- Microsoft Entra ID.

## Evidence

Evidence artifacts for this workflow are captured by the evidence pipeline and retained per the evidence export and retention contract.
