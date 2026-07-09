# RBAC & Scoping

Authorization has two independent layers. Roles decide **what** a principal may do, through five permission tiers. Scopes decide **where** they may do it, along two axes: site and environment. A request must pass both.

## Roles and permission tiers

Ryuki uses twelve fixed Entra app roles. Each maps to one or more permission tiers; coarse authorization checks tiers, while approval workflows additionally use canonical role names for approval routing and quorum bookkeeping. See [Entra App Registration](entra-app-registration.md) for the full role-to-tier matrix and how the `roles` claim is issued.

| Tier | Grants |
| --- | --- |
| `admin` | Platform administration. Superuser: satisfies every other tier. |
| `approve` | Approving requests through the governed lifecycle. |
| `execute` | Dispatching execution (dry-run by default; live modes have extra gates). |
| `request` | Creating and managing requests. |
| `audit` | Read access to audit trails and evidence. |

The roles: `PlatformAdmin`, `BreakGlassAdmin`, `DatacenterApprover`, `VMwareOperator`, `HyperVOperator`, `ProxmoxOperator`, `WintelLinuxOperator`, `BackupOperator`, `MonitoringOperator`, `ServiceDesk`, `Auditor`, and `Requester`.

Role assignment for people happens in the Entra enterprise application, not in Ryuki. Unknown roles on a token mint are rejected.

## Scopes

A principal's session carries a site scope and an environment scope, each a list of allowed values. An empty list means unrestricted on that axis.

Today, scopes are carried by **API tokens**: interactive sessions (Entra ID or local auth) are unscoped, and the dev auth modes run as an unscoped admin. To give an integration a narrow blast radius, mint it a scoped token.

## Enforcement semantics

The same rules apply across all scoped domains:

| Access pattern | Out-of-scope behavior |
| --- | --- |
| Read a single resource by id | `404`, identical to a missing row. Cross-scope probing never confirms existence. |
| Write or filter that explicitly names an out-of-scope site or environment | `403` |
| List endpoints | Results are silently narrowed to the principal's scope. A principal with multiple scopes must name one explicitly in the filter. |
| Fleet-wide or aggregate operations | `403` for scoped principals: an aggregate over data you cannot fully see is denied, not silently partial. |
| Resources that target a set of sites (for example patch waves) | Allowed only if every targeted site is in scope. |
| Environment-scoped principal reading a site-only resource | Empty result set; the axes do not substitute for each other. |

## Platform-wide rows and nullable axes

Some resources have optional site or environment columns. A `NULL` axis means "no value on that axis," not "visible to everyone":

- A row is platform-wide, and visible to any scoped principal, only when **both** site and environment are `NULL`.
- A row with a concrete site and `NULL` environment is invisible to an environment-scoped principal, and vice versa. The rule is symmetric.
- For by-id reads of single-axis resources, a platform-wide row is reachable only by unrestricted principals.

## Managing API tokens

| Route | Method | Notes |
| --- | --- | --- |
| `/api/admin/tokens` | POST | Create: name, owner principal, roles, optional `site_scope` and `environment_scope` (comma-separated), expiry. Admin tier, interactive session required: a token cannot mint tokens. |
| `/api/admin/tokens` | GET | List tokens. |
| `/api/admin/tokens/{id}` | GET / DELETE | Inspect / revoke. |
| `/api/admin/rbac-roles` | GET | The role and permission catalog, as the server enforces it. |

Tokens are create-and-revoke: there is no edit. To change a token's roles or scope, mint a replacement and revoke the old one.

## Authentication modes

`RYUKI_AUTH_MODE` selects how sessions are established; it never enables live provider calls (that is a separate, operator-gated setting).

| Mode | Behavior |
| --- | --- |
| `mock-dry-run` (default) | Static development session, unscoped admin. |
| `static-dry-run` | Same, without the mock provider affordances. |
| `local` | Local username/password sessions. |
| `entra-id` | Entra ID SSO. Bearer tokens are validated cryptographically (RS256, issuer, audience, expiry) against tenant JWKS. |

## A note on the portal

The portal filters navigation and actions by role for usability, but that is convenience, not security: every rule above is enforced server-side, and the API answers the same regardless of which client asks.
