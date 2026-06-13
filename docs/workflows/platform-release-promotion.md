# Platform release promotion

## Purpose

Operator runbook for the **Platform release promotion** coverage entry. The platform serves a static, provider-safe contract for this slice; this page maps the contract to its catalog source, lifecycle, required inputs, prohibitions, and evidence expectations.

## Contract

- Contract definition `platform-release-promotion-contract.yaml`
- Serves contract route `/api/platform/release-promotion-contract`.
- Validator slice `platform-release-promotion`
- Contract `platform-release-promotion-contract.yaml` is marked draft (version 1)

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    releaseScope
    sourceVersionSummary
    environmentStage
    manifestRenderSummary
    chartLintSummary
    kustomizeBuildSummary
    approvalRoute
    rollbackPlan
    owner
    evidenceManifest

Required guards and approvals (from the contract YAML).

    release-scope-known
    source-version-summarized
    manifest-render-reviewed
    chart-lint-reviewed
    kustomize-build-reviewed
    image-reference-policy-reviewed
    approval-route-assigned
    rollback-plan-ready
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- No live provider calls.
- No live deployment.
- No registry push.
- No Helm upgrade.
- No kubectl apply.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- static release promotion summaries only.

## Evidence

Required evidence (from the contract YAML).

    Release summary
    Source version summary
    Helm lint summary
    Helm template render summary
    Kustomize build summary
    Manifest diff review
    Approval route
    Rollback readiness
    Evidence references
