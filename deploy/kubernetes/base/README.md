# Kubernetes Base Manifests

Base manifests define the portable Kubernetes skeleton for Ryuki Infrastructure Platform components.

| File | Contents |
|---|---|
| `namespace.yaml` | `ryuki-platform` namespace. |
| `serviceaccounts.yaml` | One ServiceAccount per component. |
| `configmap.yaml` | Non-secret runtime settings: `platform-api-config` (`RYUKI_*` env including `RYUKI_DATABASE__REQUIRED=true`) and `portal-ui-config` (API base URL). |
| `deployments.yaml` | `portal-ui` and `platform-api` deployments with HTTP probes on port 8080, conservative resource requests/limits, non-root security contexts, `imagePullPolicy: IfNotPresent`, and `envFrom` wiring to the ConfigMaps plus the `ryuki-platform-api-db` Secret. |
| `services.yaml` | Internal ClusterIP services for `portal-ui` and `platform-api`. |
| `ingress.yaml` | NGINX ingress placeholder for `platform.example.invalid` and same-origin `/api`. |
| `networkpolicies.yaml` | Default-deny ingress/egress plus explicit UI/API/DNS allowances, the platform-api ↔ CNPG database path (TCP 5432 in both directions), CNPG intra-cluster and operator allowances (5432 + 8000), and a commented Vault:8200 egress stub. Deployment-time TODOs: the CNPG instance manager additionally needs egress to the kube-apiserver (cluster-specific ipBlock, supply via overlay), and Barman backups will need egress to the object-store endpoint. |

## Database configuration delivery

`platform-api` reads its non-secret settings from the `platform-api-config`
ConfigMap and `RYUKI_DATABASE_URL` from the `ryuki-platform-api-db` Secret.
That Secret — and the three Secrets the CNPG cluster references
(`ryuki-platform-db-superuser`, `ryuki-platform-db-app-user`,
`ryuki-platform-db-backup-s3`) — is materialized from Vault by the Vault
Secrets Operator (`../vault/vso-secrets.yaml`). Secret values live only in
Vault; no manifest in this repository carries credential material.

**Fallback without VSO**: create the same Secrets out-of-band (for example
`kubectl create secret generic ryuki-platform-api-db
--from-literal=RYUKI_DATABASE_URL=...` pointing at
`ryuki-platform-db-rw.ryuki-platform.svc:5432`). Never commit such a Secret or
its values to this repository.

Because `RYUKI_DATABASE__REQUIRED=true` is set in the ConfigMap, a
platform-api pod that cannot reach its database exits non-zero and
crash-loops visibly instead of silently serving from in-memory stores.

These manifests are not production-ready. Registry, TLS secret delivery, provider egress, and live deployment execution are later implementation slices.
