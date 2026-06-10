# Kubernetes Deployment Skeleton

The Kubernetes skeleton targets a portable runtime for early manifest validation. It does not include live credentials, real registry URLs, or provider endpoint access.

| Path | Purpose |
|---|---|
| [base](base/) | Namespace, service accounts, deployments, services, ingress, and NetworkPolicy baseline. |
| [vault](vault/) | Static HashiCorp Vault Helm values and bootstrap runbook for HA Raft foundation. |

## Current Scope

- Namespace: `ryuki-platform`.
- Ingress host: `platform.example.invalid` synthetic placeholder; real DNS is deployment-time configuration.
- Public ingress routes only to `portal-ui` and `platform-api`.
- Services are internal ClusterIP placeholders on port `8080`.
- Default deny ingress and egress policies are present.
- External provider egress remains future explicit policy work.
- Vault foundation values require HA Raft, TLS, persistent data and audit storage, retained PVCs, and no committed initialization material.

## Verification

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all
```
