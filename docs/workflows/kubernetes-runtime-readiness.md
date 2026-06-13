# Kubernetes Runtime Readiness

## Purpose

This slice adds a static readiness contract for the portable Kubernetes runtime skeleton that will host Ryuki platform workloads. It turns namespace, Deployment, Service, Ingress, NetworkPolicy, ServiceAccount, image reference, runtime reference, runtime security, observability, and evidence posture into reviewable gates without applying manifests or calling a cluster.

## Contract

- Contract definition `kubernetes-runtime-readiness-contract.yaml`
- Validator slice `kubernetes-runtime-readiness`
- Contract `kubernetes-runtime-readiness-contract.yaml` is marked draft (version 1)

Endpoint: `/api/platform/kubernetes-runtime-readiness-contract`

Re-validate with the ryuki-validator `run-all` subcommand from the checkout root.

## Lifecycle mapping

Requests against this contract follow the platform request lifecycle of draft, pending-approval, approved, queued, running, and completed, with failed and cancelled exits recorded as evidence. Contract execution maps to the catalog lifecycle stages of intake, validate, plan, approve, lock, execute, verify, protect, publish, maintain, and retire. Stages before execute are review steps and never run provider actions.

## Required inputs and approvals

Required inputs (from the contract YAML).

    runtimeScopeSummary
    namespaceSummary
    componentTopologySummary
    serviceRoutingSummary
    frontTierSummary
    controllerClassSummary
    ingressRouteSummary
    sameOriginRouteSummary
    certificatePostureSummary
    healthCheckPostureSummary
    failoverOwnershipSummary
    networkPolicySummary
    serviceAccountSummary
    imageReferenceSummary
    runtimeReferenceSummary
    runtimeSecuritySummary
    observabilitySummary
    approvalRoute
    evidenceManifest

Required guards and approvals (from the contract YAML).

    namespace-reviewed
    deployment-topology-reviewed
    service-routing-reviewed
    front-tier-reviewed
    controller-class-reviewed
    ingress-routing-reviewed
    same-origin-route-reviewed
    certificate-posture-reviewed
    health-check-reviewed
    failover-owner-reviewed
    default-deny-reviewed
    egress-allowlist-reviewed
    service-account-reviewed
    image-reference-reviewed
    runtime-reference-reviewed
    runtime-security-reviewed
    observability-reviewed
    evidence-redacted

## Prohibitions

Live execution remains blocked until this slice is separately approved for live runs.

- Use static Kubernetes runtime readiness summaries only.
- No live provider calls.
- No kubectl apply, Helm install, Helm upgrade, overlay build, namespace mutation, workload mutation, Service mutation, Ingress mutation, NetworkPolicy mutation, ServiceAccount mutation, sensitive resource creation, image pull, registry access, or provider mutation.
- No kubeconfigs, cluster identifiers, context identifiers, namespace identifiers, ingress identifiers, TLS material identifiers, workload identity identifiers, identity material, pod identifiers, image pull material, registry material, tenant identifiers, object identifiers, private network details, sensitive auth material, raw Kubernetes payloads, or provider payloads.

## Requirements

The slice validator pins the following wording and facts for this runbook.

- HAProxy VIP front tier.
- NGINX ingress controller.
- same-origin API.

## Evidence

Required evidence (from the contract YAML).

    Kubernetes runtime readiness summary
    Namespace review
    Deployment topology review
    Service routing review
    Ingress front tier review
    Ingress routing review
    Same-origin route review
    Health check and failover review
    Network policy review
    Service account review
    Image reference review
    Runtime reference review
    Runtime security review
    Observability review
    Evidence references
