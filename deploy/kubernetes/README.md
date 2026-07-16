# Kubernetes Deployment Skeleton

The Kubernetes skeleton targets a portable runtime for early manifest validation. It does not include live credentials, real registry URLs, or provider endpoint access.

| Path | Purpose |
|---|---|
| [base](base/) | Namespace, service accounts, deployments, services, ingress, and NetworkPolicy baseline. |
| [vault](vault/) | Static HashiCorp Vault Helm values and bootstrap runbook for HA Raft foundation. |
| [operations](operations/) | Digest-scoped, create-once migration Job, JIT VaultDynamicSecret, and ordered cutover contract; never continuously reconciled. |

## Current Scope

- Namespace: `ryuki-platform`.
- Ingress host: `platform.example.invalid` synthetic placeholder; real DNS is deployment-time configuration.
- IngressClass: `ryuki-platform`; its controller instance must be dedicated to
  Ryuki and labeled `app.kubernetes.io/instance=ryuki-platform`. Reusing that
  label on a shared controller does not satisfy the egress boundary.
- Public ingress routes only to `portal-ui` and `platform-api`.
- Services are internal ClusterIP placeholders on port `8080`.
- API and portal images are digest-only references under the reserved,
  non-resolving `registry.example.invalid` registry. An adopted overlay must
  replace the whole reference with an approved registry/repository/digest.
- Default deny ingress and egress policies are present.
- Runtime and migration database URLs require `sslmode=verify-full` and the
  projected CloudNativePG `ryuki-platform-db-ca/ca.crt`. The final server
  certificate must contain `ryuki-platform-db-rw.ryuki-platform.svc` as a DNS
  SAN; certificate issuance and live readback remain deployment evidence.
- External provider egress remains future explicit policy work.
- Vault foundation values require HA Raft, TLS, persistent data and audit storage, retained PVCs, and no committed initialization material.

## Verification

Run the manifest validator against the final rendered document set after every
overlay or GitOps image rewrite. It rejects unqualified, tag-only, digest-less,
scheme-prefixed, malformed, or non-lowercase-SHA-256 image references. The
checked-in placeholder digests prove only the repository policy shape; adopted
registry resolution, signature verification, and the running image ID remain
deployment evidence.

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all
```
