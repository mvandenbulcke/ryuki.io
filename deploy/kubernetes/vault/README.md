# Vault Deployment Foundation

This folder defines the first static Vault deployment baseline for the Ryuki Infrastructure Platform. It is a Helm values foundation only; it does not contain initialized Vault data, unseal material, credentials, tenant IDs, endpoints, or secret values.

## Scope

- Official HashiCorp Vault Helm chart values for HA mode with integrated Raft storage.
- Three Vault server replicas with per-pod persistent data storage.
- TLS required at the Vault listener.
- Persistent audit storage mounted for a file audit device enabled during bootstrap.
- Pod disruption and anti-affinity settings for early availability posture.
- NetworkPolicy toggle enabled for chart-rendered Vault policies.

## Files

| File | Purpose |
|---|---|
| `values-ha-raft.yaml` | Static Helm values baseline for HA Raft Vault. |
| `bootstrap-runbook.md` | Safe render, install, initialize, unseal, and audit bootstrap sequence. |

## Boundaries

- Azure Key Vault auto-unseal remains an environment overlay and must not be committed here.
- TLS materials are created outside the repository and referenced only by Kubernetes secret name.
- Vault root tokens, recovery keys, unseal keys, audit output, credential paths with sensitive detail, and policy payloads must not be committed or copied into evidence.
- Workload secret delivery and Vault Secrets Operator integration are later slices after this foundation renders cleanly.

## Verification

Run static validation:

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- validate vault-foundation
```

When Helm is available, render and lint before any cluster install:

```bash
helm template vault hashicorp/vault --namespace vault -f deploy/kubernetes/vault/values-ha-raft.yaml
helm lint hashicorp/vault -f deploy/kubernetes/vault/values-ha-raft.yaml
```
