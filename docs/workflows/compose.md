# Compose

## Purpose

Operator runbook for the **Compose** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `compose-contract.yaml`
- Serves contract route `/api/platform/local-container-readiness-contract`.
- Validator slice `compose`
- Contract `compose-contract.yaml` is marked active

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

The contract YAML does not declare structured inputs yet. Capture the requesting role, target site, environment, and the approval decision in the request record before the approve stage completes.

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Evidence artifacts for this workflow are captured by the evidence pipeline and retained per the evidence export and retention contract.
