# Evidence manifest

## Purpose

Operator runbook for the **Evidence manifest** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

Evidence manifests are indexes for redacted records: every manifest entry references a record type, its redaction state, and a safe export target rather than the underlying sensitive data. The manifest exists so an auditor can confirm which evidence was produced and that each record passed redaction before it could leave the platform.

## Contract

- Contract definition `evidence-manifest-catalog.yaml`
- Serves contract route `/api/catalog/evidence-manifest`.
- Validator slice `evidence-manifest`
- Contract `evidence-manifest-catalog.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

The contract YAML does not declare structured inputs yet. Capture the requesting role, target site, environment, and the approval decision in the request record before the approve stage completes.

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

Failed redaction blocks export: a record whose redaction state is not confirmed clean can never be promoted to a safe export target, and the manifest records the blocked state instead. The platform guarantees raw provider payloads are not stored — manifests retain only redacted summaries and references, never unfiltered logs, stack traces, or raw provider responses.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Evidence artifacts for this workflow are captured by the evidence pipeline and retained per the evidence export and retention contract.
