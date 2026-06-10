# Kubernetes Base Manifests

Base manifests define the portable Kubernetes skeleton for Ryuki Infrastructure Platform components.

| File | Contents |
|---|---|
| `namespace.yaml` | `ryuki-platform` namespace. |
| `serviceaccounts.yaml` | One ServiceAccount per component. |
| `deployments.yaml` | `portal-ui` and `platform-api` deployments with HTTP probes on port 8080, conservative resource requests/limits, non-root security contexts, and `imagePullPolicy: IfNotPresent`. |
| `services.yaml` | Internal ClusterIP services for `portal-ui` and `platform-api`. |
| `ingress.yaml` | NGINX ingress placeholder for `platform.example.invalid` and same-origin `/api`. |
| `networkpolicies.yaml` | Default-deny ingress/egress plus explicit UI/API/DNS allowances. |

These manifests are not production-ready. Registry, TLS secret delivery, Vault integration, database services, provider egress, and live deployment execution are later implementation slices.
