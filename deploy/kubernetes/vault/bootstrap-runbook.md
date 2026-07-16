# Vault Bootstrap Runbook

This runbook is provider-safe. It records the bootstrap sequence and evidence boundaries, not live Vault initialization material.

## Preconditions

- Use the official HashiCorp Vault Helm chart.
- Obtain the organization-approved chart archive outside this repository. Set
  `VAULT_HELM_CHART_ARCHIVE` to that local archive, set
  `VAULT_HELM_CHART_VERSION` to its exact stable `MAJOR.MINOR.PATCH` version,
  and set `VAULT_HELM_CHART_SHA256` to the independently approved lowercase
  SHA-256 digest. This repository deliberately does not invent either value or
  claim external provenance.
- Create the `vault-server-tls` Kubernetes secret outside the repository with certificate, key, and CA files expected by `values-ha-raft.yaml`.
- Select the approved vSphere CSI storage class in a private environment overlay before production deployment.
- Configure Azure Key Vault auto-unseal only through deployment-time values or secret references outside this repository.
- Confirm that rendered manifests contain no Kubernetes Secret resources with embedded data.

## Verify, Render, And Lint

Use the repository wrapper to validate the exact operator-approved archive
before Helm parses or installs it. Version ranges, prerelease selectors,
repository-latest resolution, missing digests, uppercase/short digests,
symlink archives, and version mismatches fail closed.

The wrapper copies the source archive into a mode-`0700` temporary directory,
checks the approved digest and version on that private chart snapshot, and
passes only that one snapshot path to `helm show chart`, `helm template`, and
`helm lint`. It verifies the digest again after every Helm call. A concurrent
change to the operator-supplied source path therefore cannot swap the bytes
between validation and use.

```bash
set -eu
export VAULT_HELM_CHART_ARCHIVE="${APPROVED_VAULT_CHART_ARCHIVE:?set approved archive path}"
export VAULT_HELM_CHART_VERSION="${APPROVED_VAULT_CHART_VERSION:?set approved exact version}"
export VAULT_HELM_CHART_SHA256="${APPROVED_VAULT_CHART_SHA256:?set approved digest}"
./deploy/kubernetes/vault/release-approved-chart.sh verify
```

## Install Shape

Install mode repeats the digest/version checks, render, and lint in one process,
then passes that same private chart snapshot to `helm upgrade --install`. Do not
copy the Helm commands out of the wrapper or install directly from the source
archive or a repository tag.

```bash
./deploy/kubernetes/vault/release-approved-chart.sh install
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

- Exact Helm chart version, independently approved expected digest,
  verified archive digest, and values file hash. A matching digest proves only that the
  reviewed bytes were used consistently by render, lint, and install; external
  publisher provenance remains an operator-owned gate.
- Render and lint status.
- Pod readiness state and Raft peer count.
- Audit device enabled state.
- Storage class and PVC binding status.

## Evidence To Exclude

- Root tokens, unseal keys, recovery keys, generated certificates, private keys, credential values, tenant IDs, object IDs, raw audit lines, and secret paths with sensitive detail.
