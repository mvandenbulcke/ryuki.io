# Entra ID App Registration — App Roles

## Overview

The Ryuki Infrastructure Platform uses Entra ID **app roles** for RBAC instead of group-name-to-role mapping. Roles are defined in the Entra app registration manifest and assigned to users/groups in the enterprise application. The access token issued by Entra ID contains a `roles` claim which the platform reads directly — no group name mapping needed.

## App Roles Definition

Define these roles in the app registration manifest (Entra admin center → App registrations → [Your App] → App roles). Replace `{APP_CLIENT_ID}` below with your actual client ID.

### Manifest Snippet

```json
{
  "id": "{APP_CLIENT_ID}",
  "appRoles": [
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Full platform administration, approval, and audit access",
      "displayName": "Platform Admin",
      "id": "00000000-0000-0000-0000-000000000001",
      "isEnabled": true,
      "value": "PlatformAdmin"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Datacenter-level approval and audit",
      "displayName": "Datacenter Approver",
      "id": "00000000-0000-0000-0000-000000000002",
      "isEnabled": true,
      "value": "DatacenterApprover"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "VMware virtualization execution and audit",
      "displayName": "VMware Operator",
      "id": "00000000-0000-0000-0000-000000000003",
      "isEnabled": true,
      "value": "VMwareOperator"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Hyper-V virtualization execution and audit",
      "displayName": "Hyper-V Operator",
      "id": "00000000-0000-0000-0000-000000000004",
      "isEnabled": true,
      "value": "HyperVOperator"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Proxmox virtualization execution and audit",
      "displayName": "Proxmox Operator",
      "id": "00000000-0000-0000-0000-000000000005",
      "isEnabled": true,
      "value": "ProxmoxOperator"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Operating system execution and audit",
      "displayName": "Wintel/Linux Operator",
      "id": "00000000-0000-0000-0000-000000000006",
      "isEnabled": true,
      "value": "WintelLinuxOperator"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Backup execution and audit",
      "displayName": "Backup Operator",
      "id": "00000000-0000-0000-0000-000000000007",
      "isEnabled": true,
      "value": "BackupOperator"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Monitoring execution and audit",
      "displayName": "Monitoring Operator",
      "id": "00000000-0000-0000-0000-000000000008",
      "isEnabled": true,
      "value": "MonitoringOperator"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Service Desk triage, request, and audit access",
      "displayName": "Service Desk",
      "id": "00000000-0000-0000-0000-000000000009",
      "isEnabled": true,
      "value": "ServiceDesk"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Read-only audit access",
      "displayName": "Auditor",
      "id": "00000000-0000-0000-0000-000000000010",
      "isEnabled": true,
      "value": "Auditor"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Request-only access",
      "displayName": "Requester",
      "id": "00000000-0000-0000-0000-000000000011",
      "isEnabled": true,
      "value": "Requester"
    },
    {
      "allowedMemberTypes": ["User", "Group"],
      "description": "Emergency administration and audit",
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
4. Verified Entra role values are mapped to platform permissions.
5. `check_permission()` maps verified role names to permissions for authorization decisions.

## Permissions by Role

The platform recognises **12** app roles. Each role grants one or more of five
coarse permission tiers. Authorization is checked per route: a request must hold
the permission tier the route requires.

### Permission tiers

| Tier | Grants |
| --- | --- |
| `admin` | Superuser — satisfies every other tier. Required for `/api/admin/*`, emergency-change mutations, `secrets/rotate-all`, **minting a live-apply grant** (`approve-live-apply`), dispatching a live terraform plan, and reading sensitive prefixes (`/api/protect/secrets`, `/api/ops/emergency`, `/api/admin`). |
| `approve` | Approve or reject requests, and maker/checker signoffs (`runbook/approve`, `patch/approve`, `software/approve`, `restore-approve`, `app-environment/approve`, `decommission/approve`, access-review `approve`/`revoke`/`exempt`). |
| `execute` | Operator-tier mutations across `/api/protect`, `/api/identity`, `/api/network`, `/api/build`, `/api/vm`, `/api/maintain`, `/api/observe`, `/api/datacenter`, `/api/inventory`, `/api/cmdb`, `/api/analytics`, `/api/evidence`, `/api/retire`. Dispatches **dry-run** jobs only. |
| `request` | Submit and cancel requests (a Requester can cancel only their own). |
| `audit` | Read the audit trail and evidence packs (`/api/requests/{id}/audit`, `/api/requests/{id}/evidence`, `/api/activity/audit`). |

The **superuser rule**: a session holding `admin` passes every permission check.
Ordinary (non-sensitive) GET reads require `audit` **or** `request`; sensitive
reads require `admin`. Any unmatched state-changing route falls back to `admin`
(fail-closed) — a newly added mutating route is never silently open.

### Role → tier matrix

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
- **BreakGlassAdmin** is the audited emergency role — same power as
  `PlatformAdmin`, intended for break-glass use and called out in the
  separation-of-duties controls.

## Environment Configuration

Only the Entra tenant and client IDs are needed:

```env
RYUKI_ENTRA_TENANT_ID=<your-tenant-id>
RYUKI_ENTRA_CLIENT_ID=<your-app-client-id>
RYUKI_ENTRA_AUTHORITY=https://login.microsoftonline.com
RYUKI_AUTH_MODE=entra-id
```

## Important Security Notes

- **Do NOT commit** the app registration manifest with real GUIDs, tenant IDs, or client IDs.
- The manifest snippet above uses placeholder GUIDs (`00000000-...`) for documentation only.
- Real role assignments are managed in the Entra admin center, not in code or Git.
- Role **values** (like `"PlatformAdmin"`) are safe to keep in source code as string constants — they are not secrets.
