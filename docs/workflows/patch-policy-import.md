# Patch policy import

## Purpose

Operator runbook for the **Patch policy import** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `patch-policy-import-contract.yaml`
- Serves contract route `/api/patching/policy-import-contract`.
- Validator slice `patch-policy-import`
- Contract `patch-policy-import-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    importBatch
    headerMapping
    platformCiKey
    patchGroup
    maintenanceWindow
    rebootPolicy
    owner
    evidenceManifest

Required guards and approvals (from the contract YAML).

    cmdb-file-contract-validated
    header-mapping-complete
    ci-identity-known
    maintenance-window-known
    reboot-policy-known
    owner-known
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live ServiceNow API calls.
- No raw export rows.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- file-based patch policy import contract.
- normalized policy summaries.

## Evidence

Required evidence (from the contract YAML).

    File hash
    Header mapping
    Validation result
    Accepted/rejected policy rows
    Maintenance window summary
    Reboot policy summary
    Wave seed summary
    Evidence references
