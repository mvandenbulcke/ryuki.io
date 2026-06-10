# Vault Bootstrap Runbook

This runbook is provider-safe. It records the bootstrap sequence and evidence boundaries, not live Vault initialization material.

## Preconditions

- Use the official HashiCorp Vault Helm chart.
- Create the `vault-server-tls` Kubernetes secret outside the repository with certificate, key, and CA files expected by `values-ha-raft.yaml`.
- Select the approved vSphere CSI storage class in a private environment overlay before production deployment.
- Configure Azure Key Vault auto-unseal only through deployment-time values or secret references outside this repository.
- Confirm that rendered manifests contain no Kubernetes Secret resources with embedded data.

## Render And Lint

```bash
helm template vault hashicorp/vault --namespace vault -f deploy/kubernetes/vault/values-ha-raft.yaml
helm lint hashicorp/vault -f deploy/kubernetes/vault/values-ha-raft.yaml
```

## Install Shape

```bash
helm upgrade --install vault hashicorp/vault --namespace vault --create-namespace -f deploy/kubernetes/vault/values-ha-raft.yaml
```

## Initialize And Unseal

Initialize Vault from the first server pod only. Store initialization output in the approved operator process, not in this repository, issue tracker, chat, logs, or evidence packs.

```bash
kubectl exec -n vault vault-0 -- vault operator init -key-shares=5 -key-threshold=3
```

Unseal each server pod using the approved operator process. Do not paste unseal material into shell history, documentation, or evidence.

```bash
kubectl exec -n vault vault-0 -- vault operator unseal
kubectl exec -n vault vault-1 -- vault operator unseal
kubectl exec -n vault vault-2 -- vault operator unseal
```

## Audit Logging

Enable a file audit device after initialization and unseal. The file path must use the persistent audit storage mount.

```bash
vault audit enable file file_path=/vault/audit/vault-audit.log
```

Audit logs are sensitive operational records. Export only redacted audit evidence references through the platform evidence workflow.

## Evidence To Keep

- Helm chart version and values file hash.
- Render and lint status.
- Pod readiness state and Raft peer count.
- Audit device enabled state.
- Storage class and PVC binding status.

## Evidence To Exclude

- Root tokens, unseal keys, recovery keys, generated certificates, private keys, credential values, tenant IDs, object IDs, raw audit lines, and secret paths with sensitive detail.
