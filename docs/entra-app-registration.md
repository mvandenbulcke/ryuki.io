# Entra ID App Registration — App Roles

## Overview

The current Ryuki `entra-id` mode uses Entra ID **app roles** for RBAC instead
of group-name-to-role mapping. Roles are defined in the Entra app registration
manifest and assigned to users/groups in the enterprise application. The access
token issued by Entra ID contains a `roles` claim which the current platform
reads directly—no group-name mapping is needed.

This is a transitional provider-specific setup guide, not the final production
identity boundary. The target supports multiple OIDC providers and maps their
allowlisted claims into one provider-qualified principal and typed policy model.
See the
[Platform Security Boundary Specification](architecture/platform-security-boundary.md#pluggable-authentication-providers).

## Browser Redirect Registration

For portal sign-in, register the exact callback (for example,
`https://<host>/api/auth/entra/callback`) as a **Web** redirect URI. Do not
register the portal as an SPA token recipient. The server-side API/BFF validates
the authorization response, exchanges the code, and establishes the browser
session; tokens are not delivered to browser storage. Bearer-only API validation
does not require this redirect URI.

## App Roles Definition

Define these roles in the app registration manifest (Entra admin center → App
registrations → [Your App] → App roles). Merge the `appRoles` array below into
the application manifest. Do not replace the manifest's read-only `id` (object
id) or `appId` (client id). Replace every placeholder role `id` below with a
different generated GUID. The field semantics follow the
[Microsoft Graph app-manifest reference](https://learn.microsoft.com/en-us/entra/identity-platform/reference-microsoft-graph-app-manifest).

### Manifest Snippet

```json
{
  "appRoles": [
    {
      "allowedMemberTypes": ["User"],
      "description": "Full platform administration, approval, and audit access",
      "displayName": "Platform Admin",
      "id": "00000000-0000-0000-0000-000000000001",
      "isEnabled": true,
      "value": "PlatformAdmin"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Datacenter-level approval and audit",
      "displayName": "Datacenter Approver",
      "id": "00000000-0000-0000-0000-000000000002",
      "isEnabled": true,
      "value": "DatacenterApprover"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "VMware virtualization execution and audit",
      "displayName": "VMware Operator",
      "id": "00000000-0000-0000-0000-000000000003",
      "isEnabled": true,
      "value": "VMwareOperator"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Hyper-V virtualization execution and audit",
      "displayName": "Hyper-V Operator",
      "id": "00000000-0000-0000-0000-000000000004",
      "isEnabled": true,
      "value": "HyperVOperator"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Proxmox virtualization execution and audit",
      "displayName": "Proxmox Operator",
      "id": "00000000-0000-0000-0000-000000000005",
      "isEnabled": true,
      "value": "ProxmoxOperator"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Operating system execution and audit",
      "displayName": "Wintel/Linux Operator",
      "id": "00000000-0000-0000-0000-000000000006",
      "isEnabled": true,
      "value": "WintelLinuxOperator"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Backup execution and audit",
      "displayName": "Backup Operator",
      "id": "00000000-0000-0000-0000-000000000007",
      "isEnabled": true,
      "value": "BackupOperator"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Monitoring execution and audit",
      "displayName": "Monitoring Operator",
      "id": "00000000-0000-0000-0000-000000000008",
      "isEnabled": true,
      "value": "MonitoringOperator"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Service Desk triage, request, and audit access",
      "displayName": "Service Desk",
      "id": "00000000-0000-0000-0000-000000000009",
      "isEnabled": true,
      "value": "ServiceDesk"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Read-only audit access",
      "displayName": "Auditor",
      "id": "00000000-0000-0000-0000-000000000010",
      "isEnabled": true,
      "value": "Auditor"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Request-only access",
      "displayName": "Requester",
      "id": "00000000-0000-0000-0000-000000000011",
      "isEnabled": true,
      "value": "Requester"
    },
    {
      "allowedMemberTypes": ["User"],
      "description": "Current build: standing emergency admin; target: activation eligibility only",
      "displayName": "Break-Glass Admin",
      "id": "00000000-0000-0000-0000-000000000012",
      "isEnabled": true,
      "value": "BreakGlassAdmin"
    }
  ]
}
```

## How It Works

1. Roles are defined once in the app registration manifest (above).
2. Users and/or groups are assigned roles in the **Enterprise application** blade (not the app registration).
3. When a user authenticates, the access token issued by Entra ID includes a `roles` claim containing the assigned role values (e.g., `["PlatformAdmin", "Auditor"]`).
4. In the current build, verified Entra role values are mapped to platform permissions.
5. `check_permission()` maps verified role names to coarse permissions, while
   `check_operation_capability()` maps the same server-verified roles to a
   closed functional-operation capability. The identity provider never emits
   or selects Ryuki capability strings directly.

## Permissions by Role

The current platform recognises **12** app roles. Each role grants one or more
of five coarse permission tiers. Current authorization is checked per route: a
request must hold the permission tier the route requires.

### Permission tiers

| Tier | Grants |
| --- | --- |
| `admin` | Superuser — satisfies every other tier. Required for `/api/admin/*`, emergency-change mutations, `secrets/rotate-all`, **minting a live-apply grant** (`approve-live-apply`), dispatching a live terraform plan, and reading sensitive prefixes (`/api/protect/secrets`, `/api/ops/emergency`, `/api/admin`). |
| `approve` | Approve or reject requests, and maker/checker signoffs (`runbook/approve`, `patch/approve`, `software/approve`, `restore-approve`, `app-environment/approve`, `decommission/approve`, access-review `approve`/`revoke`/`exempt`). |
| `execute` | Default operator tier across `/api/protect`, `/api/identity`, `/api/network`, `/api/build`, `/api/vm`, `/api/maintain`, `/api/observe`, `/api/datacenter`, `/api/inventory`, `/api/cmdb`, `/api/analytics`, `/api/evidence`, `/api/retire`. High-impact functional operations listed below require a separate typed capability; `execute` alone never satisfies them. Dispatches **dry-run** jobs only. |
| `request` | Submit and cancel requests (a Requester can cancel only their own). |
| `audit` | Read the audit trail and evidence packs (`/api/requests/{id}/audit`, `/api/requests/{id}/evidence`, `/api/activity/audit`). |

The **superuser rule**: a session holding `admin` passes every permission check.
Safe reads use an exact closed classification. Enumerated requester-owned or
static reads are marked `request` and accept `request` **or** `audit`; audit-
grade reads require `audit`, operator working data requires `execute`, and
sensitive reads require `admin`. A new or unclassified read defaults to
`audit`, not requester visibility. Any unmatched state-changing route falls
back to `admin` (fail-closed) — a newly added mutating route is never silently
open.

### Functional operation capabilities

These current server-owned grants are evaluated before the coarse route tier.
They answer **which operation family** the principal may execute; site and
environment checks independently answer **where** it may act. `admin` remains
the intentional superuser override.

| Capability | Current non-admin grant | Protected operation |
| --- | --- | --- |
| `identity.ad-computer.delete` | None (admin-only until an identity-lifecycle role is governed) | Soft-delete an AD computer lifecycle record. |
| `network.firewall.manage` | None (admin-only until a network/firewall role is governed) | Firewall rule and rule-set mutations. |
| `monitoring.alert-routing.manage` | `MonitoringOperator` | Alert-route mutations. |
| `monitoring.alert.read` | `MonitoringOperator` | Read the scoped live operational-alert feed. |
| `monitoring.alert.acknowledge` | `MonitoringOperator` | Acknowledge scoped operational alerts. |
| `storage.array.decommission` | None (admin-only until a storage role is governed) | Decommission an empty in-scope storage array. |
| `software.deployment.execute` | `WintelLinuxOperator` | Advance an approved, in-scope software deployment to executed. |

The access-control and local-role catalog endpoints derive their permissions,
execution domains, and operation-capability lists from this same runtime role
registry. Catalog metadata cannot create an authority grant.

These are current implementation semantics. The target authorization boundary
evaluates a typed action against the final canonical resource and effective
scope; it does not make an external provider's role string the final decision.

### Current role → tier matrix

| Role | admin | approve | execute | request | audit |
| --- | :---: | :---: | :---: | :---: | :---: |
| `PlatformAdmin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `BreakGlassAdmin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `DatacenterApprover` | | ✓ | | | ✓ |
| `VMwareOperator` | | | ✓ | | ✓ |
| `HyperVOperator` | | | ✓ | | ✓ |
| `ProxmoxOperator` | | | ✓ | | ✓ |
| `WintelLinuxOperator` | | | ✓ | | ✓ |
| `BackupOperator` | | | ✓ | | ✓ |
| `MonitoringOperator` | | | ✓ | | ✓ |
| `ServiceDesk` | | | | ✓ | ✓ |
| `Requester` | | | | ✓ | |
| `Auditor` | | | | | ✓ |

(A ✓ in `admin` implies every other tier via the superuser rule; the table shows
each role's effective access.)

Notes:

- **Live execution is admin-only.** Only `PlatformAdmin` and `BreakGlassAdmin`
  can dispatch a live terraform plan or mint a live-apply grant. `execute`-tier
  operators run dry-run jobs only. See the Execution Model in the
  [Architecture](architecture.md) docs.
- **DatacenterApprover** approves but cannot execute; **Auditor** is strictly
  read-only; **Requester** can submit and cancel its own requests but cannot read
  audit trails.
- **BreakGlassAdmin is transitional in the current build.** Its Entra claim maps
  directly to standing `admin`, with the same effective permission as
  `PlatformAdmin`. Do not treat that mapping as production-ready emergency
  access.
- In the target model, `BreakGlassAdmin` is eligibility to request emergency
  activation, not standing emergency authority. Activation requires verified
  step-up and the governed emergency ceremony, issues a distinct short-lived
  grant, preserves scope and execution gates, alerts immediately, expires or is
  revoked explicitly, and is reviewed afterward. The app-role claim alone must
  not activate emergency power.

## Environment Configuration

Bearer-token validation uses the Entra tenant and client IDs. Every Entra-mode
launch also requires a dedicated persisted-session verifier key; browser sign-in
additionally needs the exact server-side Web callback URI:

```env
RYUKI_ENTRA_TENANT_ID=<your-tenant-id>
RYUKI_ENTRA_CLIENT_ID=<your-app-client-id>
RYUKI_ENTRA_AUTHORITY=https://login.microsoftonline.com
RYUKI_ENTRA_REDIRECT_URI=https://<host>/api/auth/entra/callback
RYUKI_AUTH_MODE=entra-id
# Inject at runtime from a secret manager; never commit the value.
RYUKI_SESSION__CREDENTIAL_HMAC_KEY=<at-least-32-random-bytes>
```

## Important Security Notes

- **Do NOT commit** the app registration manifest with real GUIDs, tenant IDs, or client IDs.
- The manifest snippet above uses placeholder GUIDs (`00000000-...`) for documentation only.
- Real role assignments are managed in the Entra admin center, not in code or Git.
- Role **values** (like `"PlatformAdmin"`) are safe to keep in source code as string constants — they are not secrets.
- Register the callback as a Web redirect and keep authorization-code and token handling server-side; do not expose tokens to SPA/browser storage.
- Until governed activation is implemented, assigning `BreakGlassAdmin` creates standing current-build admin authority. Keep it unassigned in a production-bound deployment rather than relying on the role name as a safety control.
