# Future ServiceNow API integration

## Purpose

Operator runbook for the **Future ServiceNow API integration** / **CMDB** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `servicenow-future-api-contract.yaml`
- Serves contract route `/api/integrations/servicenow/future-api-contract`.
- Validator slice `servicenow-future-api`
- Contract `servicenow-future-api-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    integrationScope
    approvalRecord
    instanceProfile
    tableMappingSummary
    callbackPlan
    importSetPlan
    statusSyncPlan
    owner
    evidenceManifest

Required guards and approvals (from the contract YAML).

    live-api-approval-recorded
    instance-identifiers-externalized
    table-mapping-reviewed
    payload-redaction-reviewed
    dry-run-contract-reviewed
    rollback-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live ServiceNow API calls.
- No provider calls.
- No import set writes.
- No table API calls.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- static API readiness summaries only.

## Evidence

Required evidence (from the contract YAML).

    API readiness summary
    Approval record
    Instance configuration summary
    Table mapping summary
    Payload redaction review
    Rollback readiness
    Evidence references
