# Deployment Index

Deployment artifacts define local and Kubernetes skeletons for the Ryuki Infrastructure Platform. They are placeholders until image builds, registry names, runtime secrets, and environment-specific values are approved.

| Path | Purpose |
|---|---|
| [compose](compose/) | Local API/UI/database Compose skeleton for container bootstrap. |
| [kubernetes/base](kubernetes/base/) | Portable Kubernetes foundation for namespace, service accounts, deployments, services, ingress, and network policies. |
| [kubernetes/vault](kubernetes/vault/) | Vault HA Raft Helm values and safe bootstrap runbook. |

## Deployment Rules

- Do not commit credentials, tokens, tenant IDs, object IDs, private IPs, raw provider payloads, or real secret values.
- Use placeholder image names until Harbor registry and promotion policy are approved.
- Browser traffic reaches only ingress, `portal-ui`, and `platform-api`.
- External provider egress stays blocked until explicit adapter policies and credential references are approved.
- Validate all deployment changes with `cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all`.
