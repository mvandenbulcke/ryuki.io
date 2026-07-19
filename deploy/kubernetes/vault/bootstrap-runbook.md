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

## Bind The Platform API Workload

The direct API resolver and Vault Secrets Operator use different Kubernetes
identities and different Vault roles. Do not point a `VaultAuth` resource at
`platform-api`, and do not add any VSO materializer ServiceAccount to the
`ryuki-platform-api` role.

After the chart has created the `vault` namespace, the `vault` ServiceAccount,
and ready Vault server pods, apply the Kubernetes half of the boundary:

```bash
kubectl apply -f deploy/kubernetes/vault/workload-auth.yaml
```

This creates the exact API-to-server network path and binds only
`vault:vault` to `system:auth-delegator`. It does not configure Vault. The Vault
network policy also requires an environment overlay that permits the server
pods to reach the target cluster's Kubernetes API endpoint for service account
authentication review;
that endpoint is cluster-specific and is deliberately not guessed here.

Create `ryuki-vault-client-ca` in `ryuki-platform` through the approved trust
distribution process. It must contain exactly one key named `ca.crt` with the
CA chain that validates `vault.vault.svc`; it must not contain a private key,
client certificate, token, or unrelated trust roots. The API deployment mounts
only that key, read-only, at
`/var/run/secrets/ryuki/vault-tls/ca.crt`.

Create `ryuki-secret-reference-fingerprint-keyring` in `ryuki-platform`
through the approved secret-distribution process. The Kubernetes Secret must
contain exactly one key named `keyring`; no second data key, annotation value,
or committed manifest may carry the material. The `keyring` file is UTF-8 text
with one nonempty record per line in exactly this shape:

```text
key:<id>=<base64 material>
```

`key:<id>` is the complete, unique fingerprint key identifier, and `<id>` must
be nonempty. Whitespace, blank lines, comments, and duplicate identifiers are
invalid. Material uses canonical padded standard Base64 and must decode to
32–128 bytes. The API reads the file only from
`/var/run/secrets/ryuki/secret-reference-fingerprint/keyring`; Kubernetes
projects only the `keyring` item at mode `0440`, and only the `platform-api`
container mounts its directory read-only under `fsGroup: 10001`. Never place
the file content in a process environment variable.

Rotate without breaking references that name the predecessor key. First add a
fresh, independently generated successor record while retaining every key ID
still referenced by persisted SecretRefs. Update the operator-owned Secret,
restart the `Recreate` API Deployment so startup reads the complete overlapping
keyring, and then admit new or rewritten references with the successor ID.
Inventory and rewrite all predecessor references under the normal generation
fence. Remove a predecessor only after an independent readback proves no stored
reference names it, then update the Secret and restart the API again. A missing
referenced key fails closed; do not bypass that failure by relabeling key IDs or
reusing material.

Operational evidence may record only the Secret name, namespace,
`resourceVersion`, projected path/mode, approved key IDs, rotation timestamps,
and value-free reference counts. Exclude the `keyring` payload, encoded or
decoded material, generated command lines, process environments, pod file
content, and Secret `data`/`stringData` from evidence, logs, tickets, chat, and
this repository.

An independently authorized Vault operator then applies the checked-in,
value-free auth configuration, policy, and role. Run these commands from the
repository root only after reviewing the exact three input files:

```bash
vault auth enable -path=kubernetes kubernetes
vault write auth/kubernetes/config @deploy/kubernetes/vault/kubernetes-auth-config.json
vault policy write ryuki-platform-api-runtime deploy/kubernetes/vault/platform-api-policy.hcl
vault write auth/kubernetes/role/ryuki-platform-api @deploy/kubernetes/vault/platform-api-kubernetes-role.json
```

`kubernetes-auth-config.json` intentionally omits the optional reviewer jwt field and
`kubernetes_ca_cert`: an in-cluster Vault uses its rotating local
ServiceAccount token and local Kubernetes CA. The role accepts only a
600-second, `vault`-audience projected JWT from
`ryuki-platform:platform-api`, issues a ten-minute service token, caps its
maximum and explicit maximum lifetime at fifteen minutes, and suppresses the
Vault `default` policy. Reauthentication,
not an unbounded periodic token, is the renewal boundary.

Before deploying the API, read the effective state back and require exact
agreement with the checked-in assets. Stop on wildcard subjects/namespaces,
extra policies, the `default` policy, zero/unbounded TTLs, a different audience,
or any write/list/delete/sudo capability:

```bash
vault read auth/kubernetes/config
vault read auth/kubernetes/role/ryuki-platform-api
vault policy read ryuki-platform-api-runtime
```

Finally, prove a login with a fresh projected `platform-api` JWT, validate that
the returned token has only `ryuki-platform-api-runtime`, and revoke the test
token. Never paste either JWT or Vault token into command history, logs,
evidence, chat, or this repository.

## Evidence To Keep

- Exact Helm chart version, independently approved expected digest,
  verified archive digest, and values file hash. A matching digest proves only that the
  reviewed bytes were used consistently by render, lint, and install; external
  publisher provenance remains an operator-owned gate.
- Render and lint status.
- Pod readiness state and Raft peer count.
- Audit device enabled state.
- Storage class and PVC binding status.
- Exact Kubernetes-auth config, role, and policy readback; redacted login
  metadata; and a successful bounded authentication-review, login, and revocation exercise.
- Exact `ryuki-vault-client-ca/ca.crt` digest and observed Vault server
  certificate DNS identity, without certificate private material.

## Evidence To Exclude

- Root tokens, unseal keys, recovery keys, generated certificates, private keys, credential values, tenant IDs, object IDs, raw audit lines, and secret paths with sensitive detail.
