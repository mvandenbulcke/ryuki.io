# Vault Secret Delivery

## Purpose

This slice adds a static readiness contract for Vault Secrets Operator workload delivery. It turns Vault-backed Kubernetes delivery into reviewable operator chart, VaultConnection, VaultAuth, VaultStaticSecret, destination, refresh, HMAC drift, transformation, rollout restart, namespace scope, monitoring, and evidence gates without installing the operator, applying CRDs, calling Vault APIs, or writing Kubernetes Secrets.

## Contract

- Contract definition `vault-secret-delivery-contract.yaml`
- Validator slice `vault-secret-delivery`
- Contract `vault-secret-delivery-contract.yaml` is marked draft (version 1)

Endpoint: `/api/platform/vault-secret-delivery-contract`

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    operatorChartSummary
    vaultConnectionSummary
    vaultAuthSummary
    namespaceScopeSummary
    refreshPolicySummary
    hmacDriftSummary
    transformationSummary
    rolloutRestartSummary
    monitoringSummary
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    operator-chart-reviewed
    vault-connection-reviewed
    vault-auth-reviewed
    namespace-scope-reviewed
    hmac-drift-reviewed
    transformation-reviewed
    rollout-restart-reviewed
    rotation-refresh-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- Use static Vault secret delivery summaries only.
- No Vault API calls, Kubernetes apply, Helm install, Helm upgrade, CRD apply, VaultConnection mutation, VaultAuth mutation, VaultStaticSecret mutation, Kubernetes Secret mutation, secret data read, secret data write, rollout restart, or transformation change.
- No Vault URLs, namespaces, mount paths, secret paths, auth role names, service account names, token data, Kubernetes Secret names, secret data, secret keys, destination names, template text, rollout target names, tenant identifiers, object identifiers, private network details, credentials, tokens, raw Vault payloads, raw Kubernetes Secret payloads, or provider payloads.
- No live provider calls.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Operator chart review
    VaultConnection review
    VaultAuth review
    Namespace scope review
    Refresh and HMAC drift review
    Transformation review
    Rollout restart review
    Monitoring review
    Evidence references
