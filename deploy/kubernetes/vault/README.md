# Vault Deployment Foundation

This folder defines the static Vault deployment and workload-materialization
baseline for the Ryuki Infrastructure Platform. It does not contain initialized Vault data,
unseal material, credentials, tenant IDs, live endpoints, secret
values, external role policies, or an organization-approved chart archive.

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
| `bootstrap-runbook.md` | Exact-version/digest chart verification plus safe render, install, initialize, unseal, and audit bootstrap sequence. |
| `release-approved-chart.sh` | Snapshot-bound release wrapper that gives chart metadata inspection, render, lint, and install the same digest-checked local archive. |
| `test-release-approved-chart.sh` | Executable regression for version/digest rejection, source-path mutation isolation, single-snapshot use, and tamper detection. |
| `vso-secrets.yaml` | Non-live Vault Secrets Operator skeleton with per-secret-family workload identities and a bounded API database rotation restart target. |
| `workload-auth.yaml` | Mirrored API-to-Vault network boundary plus the exact Vault server authentication-review delegation binding. |
| `kubernetes-auth-config.json` | Value-free in-cluster Kubernetes auth-method configuration; relies on the Vault pod's rotating local reviewer identity. |
| `platform-api-policy.hcl` | Read-only Vault policy for the API resolver's dedicated KV-v2 prefix. |
| `platform-api-kubernetes-role.json` | Exact `platform-api` ServiceAccount/audience binding with finite login session TTLs and no default policy. |

## Boundaries

- Azure Key Vault auto-unseal remains an environment overlay and must not be committed here.
- TLS materials are created outside the repository and referenced only by Kubernetes secret name.
- The `ryuki-vault-client-ca` Secret is created in `ryuki-platform` outside the
  repository and contains exactly one public `ca.crt` key. The API mounts it
  read-only; no client key or ambient root store satisfies this boundary.
- The independent `ryuki-secret-reference-fingerprint-keyring` Secret is also
  created outside the repository and contains exactly one Kubernetes Secret
  key named `keyring`. Only `platform-api` receives that key, mode `0440` and
  read-only, at the fixed path documented in `bootstrap-runbook.md`; the
  fingerprint key material is not a Vault credential and must not be reused as
  one.
- Direct API Vault authentication uses only the explicit 600-second projected
  JWT for `ryuki-platform:platform-api`, audience `vault`. Kubernetes' ambient
  ServiceAccount token mount remains disabled. VSO continues to use its four
  separate materializer identities and roles.
- `workload-auth.yaml` must be applied only after the Vault chart has created
  `vault:vault`. The Kubernetes resources do not configure Vault; the
  authorized operator separately applies and reads back the checked-in auth
  config, policy, and role as described in `bootstrap-runbook.md`.
- Vault server pods require cluster-specific egress to the Kubernetes API for
  service account authentication review. An adopted overlay must add that exact route; this portable
  baseline does not guess an API-server IP block.
- Database URL transformations require PostgreSQL `verify-full` mode and the
  CA path `/var/run/secrets/ryuki/cnpg/ca.crt`; workloads project only `ca.crt`
  from `ryuki-platform-db-ca`.
- Vault root tokens, recovery keys, unseal keys, audit output, credential paths with sensitive detail, and policy payloads must not be committed or copied into evidence.
- The committed VSO resources are a non-live skeleton. Rendered CRD support,
  VSO Kubernetes service-account issuance/RBAC, four least-privilege external Vault role policies
  (including the operations-only, digest-scoped migration database family),
  observed server-certificate DNS SAN
  `ryuki-platform-db-rw.ryuki-platform.svc`, actual CA/credential
  rotation/revocation overlap, and observed rollout remain deployment-owned
  evidence.

## Verification

Run static validation after including both the base documents and
`workload-auth.yaml` in the rendered deployment set:

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- validate vault-foundation
```

When Helm is available, follow `bootstrap-runbook.md`; it refuses repository-
latest resolution and requires an operator-approved local chart archive, exact
stable version, and independently approved SHA-256 before render or install.
The release wrapper does not establish publisher provenance; the organization-
approved archive and digest remain deployment-owned evidence.
