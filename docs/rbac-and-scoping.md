# RBAC & Scoping

Authorization has two independent layers. Roles decide **what** a human
principal may do through five permissions. Scopes decide **where** the
principal may do it along two axes: site and environment. A request must pass
both. The route reference also uses access-class labels for composite reads and
non-human authentication; those labels are not roles.

## Roles and permissions

Ryuki uses twelve fixed Entra app roles. Each maps to one or more permissions;
coarse authorization checks permissions, while approval workflows additionally
use canonical role names for approval routing and quorum bookkeeping. See
[Entra App Registration](entra-app-registration.md) for the full role matrix and
how the `roles` claim is issued.

| Permission | Grants |
| --- | --- |
| `admin` | Platform administration. This is the superuser permission and satisfies every other permission check. |
| `approve` | Governed approval, rejection, rework, and maker/checker sign-offs. |
| `execute` | Operator mutations and designated operator working-data reads. Dry-run is the default; live modes have additional gates. |
| `request` | Creating requests and requester/self-service actions, subject to ownership checks where documented. |
| `audit` | Audit trails, evidence, and eligibility for ordinary authenticated reads. |

The roles: `PlatformAdmin`, `BreakGlassAdmin`, `DatacenterApprover`, `VMwareOperator`, `HyperVOperator`, `ProxmoxOperator`, `WintelLinuxOperator`, `BackupOperator`, `MonitoringOperator`, `ServiceDesk`, `Auditor`, and `Requester`.

Role assignment for people happens in the Entra enterprise application, not in Ryuki. Unknown roles on a token mint are rejected.

## Route access classes

The API Reference's **Access** value can be one of the five permissions above
or one of these effective route classes:

| Access class | Meaning |
| --- | --- |
| `read` | Composite authenticated access, satisfied by `audit` **or** `request` (and therefore by `admin`). It is not a permission stored on a role. Audit-grade reads still require `audit` specifically; sensitive and operator-data reads can require `admin` or `execute`. |
| `public` | No human session is required. This covers health/bootstrap and selected auth or agent-bootstrap routes; handlers still validate their inputs and configured mode. |
| `agent` | Bypasses human-session RBAC and authenticates with an agent `rya_...` bearer token plus the supported `x-ryuki-protocol-version`. Agent registration, the control-plane public key, and the agent OpenAPI document are public bootstrap exceptions. |
| `webhook` | Bypasses human-session RBAC but requires a valid `X-Hub-Signature-256` HMAC over the exact raw body. It is not anonymous access. |

These classes explain why the complete route surface cannot be described using
only the five role permissions. They describe how a caller reaches a route; role
permissions and scope checks continue to govern human API operations.

## Scopes

A principal's session carries a site scope and an environment scope, each a list of allowed values. An empty list means unrestricted on that axis.

Today, scopes are carried by **API tokens**: interactive sessions (Entra ID or local auth) are unscoped, and the dev auth modes run as an unscoped admin. To give an integration a narrow blast radius, mint it a scoped token.

## Enforcement semantics

The same rules apply across all scoped domains:

| Access pattern | Out-of-scope behavior |
| --- | --- |
| Read a single resource by id | `404`, identical to a missing row. Cross-scope probing never confirms existence. |
| Write, filtered read, or single-site aggregate that explicitly names an out-of-scope site or environment | `403` |
| List endpoint with no explicit site/environment filter | Results are silently narrowed across every site and environment in the principal's authorized scope. |
| Endpoint that resolves one optional site/environment filter | A principal with multiple allowed values must name one explicitly; an omitted ambiguous filter is rejected. |
| Cross-scope or fleet-wide aggregate | `403` for scoped principals: an aggregate over data the caller cannot fully see is denied, not silently partial. A single-site aggregate remains available when that site resolves within scope. |
| Resources that target a set of sites (for example patch waves) | Allowed only if every targeted site is in scope. |
| Environment-scoped principal listing a site-only resource without a filter | Empty result set; the axes do not substitute for each other. An explicit or by-id site read is rejected according to the filtered (`403`) or single-resource (`404`) rule above. |

## Platform-wide rows and nullable axes

Some resources have optional site or environment columns. A `NULL` axis means "no value on that axis," not "visible to everyone":

- A row is platform-wide, and visible to any scoped principal, only when **both** site and environment are `NULL`.
- A row with a concrete site and `NULL` environment is invisible to an environment-scoped principal, and vice versa. The rule is symmetric.
- For by-id reads of single-axis resources, a platform-wide row is reachable only by unrestricted principals.

## Managing API tokens

| Route | Method | Notes |
| --- | --- | --- |
| `/api/admin/tokens` | POST | Create: name, owner principal, roles, optional `site_scope` and `environment_scope` (comma-separated), expiry. `admin` permission, interactive session required: a token cannot mint tokens. |
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
