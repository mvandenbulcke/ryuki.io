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
4. The platform's `get_roles_from_token()` function extracts the `roles` array from the token body.
5. `check_permission()` maps role names to permissions for authorization decisions.

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
