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

## Local queue authority cutover

Migration `169_servicenow_queue_authorization_scope.sql` is a non-overlapping
authorization cutover. Before applying it, stop every pre-169 API/portal
replica and drain its database transactions. Those binaries do not enforce the
new immutable CI, active-site, environment, owner, creator, and reviewed
provenance relation on reads or transitions, so schema compatibility alone is
not an authorization fence.

After the old replica count and active transaction set are proven zero, apply
the migration, add only explicitly reviewed environment-authority records that
name exact configuration-item UUIDs, and then start the matching application
version. Pre-169 writers that ran before the drain leave the all-NULL legacy
binding shape; the new application quarantines those rows from every list,
detail, validation, approval, submit, cancel, and history path. A familiar CI
name is never reconciliation evidence.

Do not roll the application back by itself after reviewed queue rows exist. A
rollback must first stop and drain the new replicas and then restore a mutually
compatible database and application release, or retain the new authorization
reader. Live ServiceNow submission and provider readback remain separately
blocked until the future integration approval and trusted-access evidence in
this runbook are satisfied.
