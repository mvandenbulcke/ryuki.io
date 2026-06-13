# Request preflight and readiness gate

## Purpose

Operator runbook for the **Request preflight and readiness gate** / **Request preflight gate** / **Requests** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `request-preflight-contract.yaml`
- Serves contract route `/api/requests/preflight-contract`.
- Validator slice `request-preflight`
- Contract `request-preflight-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    requestedOffering
    owner
    site
    environment
    criticality
    dryRunPlan
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    requested-offering-known
    owner-known
    site-known
    environment-known
    criticality-known
    dry-run-plan-ready
    approval-route-assigned
    evidence-redacted
    provider-calls-blocked
    live-execution-blocked

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No raw request payloads, raw validation rows, raw provider payloads, raw inventory rows, raw CMDB rows, raw approval data, raw user data, raw recipient data, credential values, token values, tenant identifiers, object identifiers, principal identifiers, private network values, live endpoints, or URLs.
- never enables live execution.
- No request submission.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- Also serves `/api/workflows/preflight/local/decision`.
- performs no provider calls.
- static request preflight summaries only.
- preflight hypervisor scope is VMware, Hyper-V, and Proxmox.

## Evidence

Required evidence (from the contract YAML).

    Request input summary
    Validation stage summary
    Provider-safe dry-run decision
    Approval route summary
    Redacted evidence manifest
