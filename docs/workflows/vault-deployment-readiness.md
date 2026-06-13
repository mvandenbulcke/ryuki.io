# Vault Deployment Readiness

## Purpose

This slice adds a static readiness contract for the HashiCorp Vault foundation used by Ryuki runtime secrets, adapter credentials, Kubernetes workload references, and future PKI workflows. It turns Vault deployment and bootstrap into reviewable Helm chart, HA Raft, TLS, audit, network policy, Kubernetes auth, auto-unseal, backup, workload secret delivery, monitoring, and evidence gates without installing Vault or calling Vault APIs.

## Contract

- Contract definition `vault-deployment-readiness-contract.yaml`
- Validator slice `vault-deployment-readiness`
- Contract `vault-deployment-readiness-contract.yaml` is marked draft (version 1)

Endpoint: `/api/platform/vault-deployment-readiness-contract`

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    helmChartSummary
    valuesBaselineSummary
    haRaftTopologySummary
    tlsCertificateReferenceSummary
    storageClassSummary
    auditLoggingSummary
    networkPolicySummary
    kubernetesAuthSummary
    autoUnsealOverlaySummary
    backupRestoreSummary
    monitoringSummary
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    helm-chart-reviewed
    ha-raft-reviewed
    tls-reviewed
    audit-storage-reviewed
    network-policy-reviewed
    kubernetes-auth-reviewed
    auto-unseal-overlay-reviewed
    backup-restore-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- Use static Vault deployment readiness summaries only.
- No Vault API calls, Helm install, Helm upgrade, Kubernetes apply, Vault initialization, Vault unseal, policy mutation, Kubernetes auth mutation, secret write, injector mutation, auto-unseal mutation, or audit log read.
- No Vault URLs, namespaces, mount paths, secret paths, policy names, role names, service account token data, TLS material, root tokens, recovery keys, unseal keys, audit log lines, storage class names, tenant identifiers, object identifiers, private network details, credentials, tokens, raw Vault payloads, raw Kubernetes payloads, or provider payloads.
- No live provider calls.

## Requirements

No additional validator-pinned wording applies to this runbook beyond the contract facts above.

## Evidence

Required evidence (from the contract YAML).

    Vault deployment readiness summary
    Helm chart review
    HA Raft topology review
    TLS and certificate reference review
    Persistent storage review
    Audit logging review
    Network policy review
    Kubernetes auth review
    Auto-unseal overlay review
    Backup and restore review
    Evidence references
