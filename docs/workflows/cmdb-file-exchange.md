# CMDB Excel import

## Purpose

Operator runbook for the **CMDB Excel import** / **CMDB update export** / **CMDB** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `cmdb-file-exchange-contract.yaml`
- Serves contract route `/api/integrations/servicenow/cmdb-file-contract`.
- Validator slice `cmdb-file-exchange`
- Contract `cmdb-file-exchange-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

The contract YAML does not declare structured inputs yet. Capture the requesting role, target site, environment, and the approval decision in the request record before the approve stage completes.

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- Row-level outcomes are evidence references, not raw spreadsheet payloads.
- No live ServiceNow API calls.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- Actual spreadsheet headers are deployment configuration.
- source-found.
- source-missing.
- sourceRef.
- workbook row extraction disabled.
- file hash evidence.
- local task-state or queue notes only.
- sanitized field categories.
- worksheet-count-one.
- syntheticCategoryExamples.

## Evidence

Evidence artifacts for this workflow are captured by the evidence pipeline and retained per the evidence export and retention contract.
