# Local Container Readiness

## Purpose

This slice adds a static readiness contract for the local Compose skeleton used to run Ryuki portal and API shells. It turns compose file shape, service topology, build context, local ports, bridge-network boundary, dependency order, full-stack portal runtime boundary, excluded runtime scope, and evidence posture into reviewable gates without running containers.

## Contract

- Contract definition `local-container-readiness-contract.yaml`
- Validator slice `local-container-readiness`
- Contract `local-container-readiness-contract.yaml` is marked draft (version 1)

Endpoint: `/api/platform/local-container-readiness-contract`

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    composeSummary
    serviceTopologySummary
    buildContextSummary
    localPortSummary
    networkBoundarySummary
    dependencySummary
    portalRuntimeSummary
    excludedRuntimeSummary
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    compose-file-reviewed
    service-topology-reviewed
    build-context-reviewed
    local-port-reviewed
    network-boundary-reviewed
    dependency-reviewed
    portal-runtime-boundary-reviewed
    excluded-runtime-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- Use static local container readiness summaries only.
- No compose up, image build, container run, image push, registry access, service mutation, network mutation, port-binding change, environment value material, local volume mount, provider-backed service, external egress, or runtime-state change.
- No runtime endpoints, private network details, environment value material, registry material, organization-scope identifiers, provider-side identifiers, sensitive auth material, raw runtime payloads, or provider-returned content.
- No live provider calls.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Local container readiness summary
    Compose file review
    Service topology review
    Build context review
    Local port review
    Network boundary review
    Dependency review
    Portal runtime boundary review
    Excluded runtime review
    Evidence references
