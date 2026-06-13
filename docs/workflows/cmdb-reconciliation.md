# CMDB CI reconciliation

## Purpose

Operator runbook for the **CMDB CI reconciliation** / **CMDB** coverage entries. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `cmdb-reconciliation-contract.yaml`
- Serves contract route `/api/cmdb/reconciliation-contract`.
- Validator slice `cmdb-reconciliation`
- Contract `cmdb-reconciliation-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    importBatch
    platformCiKey
    ciClass
    owner
    supportGroup
    site
    environment
    evidenceManifest

Required guards and approvals (from the contract YAML).

    cmdb-file-contract-validated
    header-mapping-complete
    inventory-coverage-current
    relationship-evidence-ready
    reviewer-approval-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live ServiceNow API calls.
- not raw spreadsheet payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- deterministic platform CI keys.

## Evidence

Required evidence (from the contract YAML).

    File hash
    Header mapping
    Validation result
    CMDB reconciliation summary
    Accepted/rejected rows
    Export package
    Reviewer approval
    Evidence references
