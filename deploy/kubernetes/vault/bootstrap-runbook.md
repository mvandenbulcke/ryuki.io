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

Validate the exact operator-approved archive before Helm parses or installs it.
Version ranges, prerelease selectors, repository-latest resolution, missing
digests, and uppercase/short digests fail closed.

```bash
set -eu
: "${VAULT_HELM_CHART_ARCHIVE:?set to the approved local chart archive}"
: "${VAULT_HELM_CHART_VERSION:?set the exact approved MAJOR.MINOR.PATCH version}"
: "${VAULT_HELM_CHART_SHA256:?set the approved lowercase SHA-256 digest}"

case "$VAULT_HELM_CHART_VERSION" in
  *[!0-9.]*|.*|*.|*..*) echo "chart version must be exact MAJOR.MINOR.PATCH" >&2; exit 1 ;;
esac
old_ifs=$IFS
IFS=.
set -- ${VAULT_HELM_CHART_VERSION}
IFS=$old_ifs
[ "$#" -eq 3 ] || { echo "chart version must be exact MAJOR.MINOR.PATCH" >&2; exit 1; }
for component in "$@"; do
  case "$component" in
    ""|*[!0-9]*) echo "chart version must be exact MAJOR.MINOR.PATCH" >&2; exit 1 ;;
  esac
done
[ "${#VAULT_HELM_CHART_SHA256}" -eq 64 ] || { echo "chart SHA-256 must contain 64 lowercase hex characters" >&2; exit 1; }
case "$VAULT_HELM_CHART_SHA256" in
  *[!0-9a-f]*) echo "chart SHA-256 must contain 64 lowercase hex characters" >&2; exit 1 ;;
esac
[ -f "$VAULT_HELM_CHART_ARCHIVE" ] || { echo "approved chart archive is missing" >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  actual_chart_sha256=$(sha256sum "$VAULT_HELM_CHART_ARCHIVE" | awk '{print $1}')
else
  actual_chart_sha256=$(shasum -a 256 "$VAULT_HELM_CHART_ARCHIVE" | awk '{print $1}')
fi
[ "$actual_chart_sha256" = "$VAULT_HELM_CHART_SHA256" ] || { echo "chart SHA-256 mismatch" >&2; exit 1; }
helm show chart "$VAULT_HELM_CHART_ARCHIVE" | grep -Fx "version: $VAULT_HELM_CHART_VERSION" >/dev/null

helm template vault "$VAULT_HELM_CHART_ARCHIVE" --namespace vault -f deploy/kubernetes/vault/values-ha-raft.yaml
helm lint "$VAULT_HELM_CHART_ARCHIVE" -f deploy/kubernetes/vault/values-ha-raft.yaml
```

## Install Shape

```bash
helm upgrade --install vault "$VAULT_HELM_CHART_ARCHIVE" --namespace vault --create-namespace -f deploy/kubernetes/vault/values-ha-raft.yaml
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
  reviewed bytes were used; external provenance remains an operator-owned gate.
- Render and lint status.
- Pod readiness state and Raft peer count.
- Audit device enabled state.
- Storage class and PVC binding status.

## Evidence To Exclude

- Root tokens, unseal keys, recovery keys, generated certificates, private keys, credential values, tenant IDs, object IDs, raw audit lines, and secret paths with sensitive detail.
