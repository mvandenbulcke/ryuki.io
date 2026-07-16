# CloudNativePG Deployment Skeleton

Static manifest skeleton for the HA PostgreSQL control-plane database. This is a minimum viable contract only — no live deployment, no credentials committed.

## Scope

- CloudNativePG `Cluster` CRD for the Ryuki Infrastructure Platform control-plane database.
- Three-instance HA topology with pod anti-affinity (build sheet database topology decision).
- vSphere CSI persistent storage for data and WAL volumes.
- Placeholder database name and secret references — real credentials are managed by Vault and injected by the Vault Secrets Operator at deploy-time.
- Barman Object Store backup target placeholder — real endpoint and credentials are deployment-time overlay.
- Separate stable `NOLOGIN` roles for application DML and schema-limited migration ownership; short-lived Vault logins must use SET-only membership in exactly one role.
- Client TLS contract requiring the operator-managed `ryuki-platform-db-ca`
  trust bundle and server DNS SAN `ryuki-platform-db-rw.ryuki-platform.svc`.

## Files

| File | Purpose |
|---|---|
| `cnpg-cluster.yaml` | Static `Cluster` manifest skeleton. |

## Prerequisites

- [CloudNativePG operator](https://cloudnative-pg.io/) installed in the Kubernetes cluster (`postgresql.cnpg.io/v1` CRD).
- [Vault Secrets Operator](https://developer.hashicorp.com/vault/docs/platform/k8s/vso) configured for secret synchronization.
- vSphere CSI driver providing the `vsphere-csi` storage class.
- Barman Object Store endpoint provisioned for backup archival (external to this repository).

## Boundaries

- Static / dry-run only. This manifest is never applied directly; it defines the contract that deployment tooling must satisfy.
- No passwords, connection strings, tokens, or credential material. All sensitive values reference Kubernetes secrets populated by Vault.
- The backup S3 endpoint and credentials are deployment-time overlays — the placeholder values here are syntactically valid but non-functional.
- Operator installation, Helm charts, and live cluster creation are separate concerns and must be approved independently.
- `postInitApplicationSQL` runs only for a fresh cluster. Existing databases require a reviewed one-time ownership and ACL handoff before strict migration preflight; this trusted operation is intentionally not encoded as continuously reconciled SQL.
- The manifest records the required CA Secret name and server DNS SAN, while
  observed certificate contents, issuer/CA rotation, Vault database role
  creation, TTL/renewal/revocation, and rotation overlap remain external
  deployment evidence not proved by this skeleton.

## Verification

Run static validation:

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- validate platform-database-readiness
```

When the CNPG operator is available, dry-run render and validate the manifest syntax:

```bash
kubectl apply --dry-run=client -f deploy/kubernetes/cloudnativepg/cnpg-cluster.yaml
```
