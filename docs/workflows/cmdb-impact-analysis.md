# CMDB

## Purpose

Operator runbook for the **CMDB** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `cmdb-impact-analysis-contract.yaml`
- Serves contract route `/api/cmdb/impact-analysis-contract`.
- Validator slice `cmdb-impact-analysis`
- Contract `cmdb-impact-analysis-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required guards and approvals (from the contract YAML).

    cmdb-file-contract-validated
    relationship-graph-reviewed
    impact-scope-reviewed
    dependency-quality-reviewed
    sync-state-reviewed
    reviewer-approval-assigned
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live ServiceNow API calls.
- No CMDB mutation.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- relationship mutation.
- raw CMDB rows.
- raw relationship rows.
- raw impact rows.
- raw recipient data.
- serial numbers.
- static CMDB impact summaries only.

## Evidence

Required evidence (from the contract YAML).

    Impact analysis summary
    App dependency quality summary
    ServiceNow sync state summary
    Relationship graph summary
    Evidence references
