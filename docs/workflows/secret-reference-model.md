# Secret reference catalog

## Purpose

Operator runbook for the **Secret reference catalog** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

Secret references let platform code and manifests point to runtime-resolved material without committing any secret value. A reference records who owns the material, which component consumes it, the rotation policy, and the readiness state — never the value itself.

## Provider direction

Vaultwarden is the runtime provider for every secret reference. References resolve against Vaultwarden at deploy- and run-time and are managed exclusively through the `vaultwarden-cli`. No legacy provider fallbacks are configured.

Adapters and workers fail closed when a referenced secret is missing, pending approval, or rotation-due: the workflow blocks rather than proceeding with an unresolved or stale credential.

## Contract

- Contract definition `secret-reference-catalog.yaml`
- Serves contract route `/api/catalog/secret-references`.
- Validator slice `secret-reference`
- Contract `secret-reference-catalog.yaml` is marked draft (version 1)

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
