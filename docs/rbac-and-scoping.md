# RBAC & Scoping

Authorization has independent mandatory axes. Roles decide **what** a human
principal may do through five coarse permissions and, for selected high-impact
mutations, a closed typed operation capability. Scopes decide **where** the
principal may do it along two axes: site and environment. A request must pass
every applicable axis. Human routes publish their exact current permission or
functional-capability requirement; protocol entry points use separate
`public`, `agent`, or `webhook` classes. These access values are enforcement
metadata, not roles.

## Boundary convergence

This page documents the current RBAC vocabulary and scope behavior. Production
acceptance additionally requires the
[Platform Security Boundary Specification](architecture/platform-security-boundary.md):
all human and non-human authenticators normalize to one verified principal;
every route and internal operation maps to a typed action; the decisive policy
check evaluates the final canonical resource; and approval, transition, and
audit obligations are enforced atomically. The current path/permission and
handler-local checks are migration inputs, not the final control ownership
model.

## Roles and permissions

The current `entra-id` implementation uses twelve fixed Entra app-role values.
Each maps to one or more permissions; coarse authorization checks permissions,
while approval workflows additionally use canonical role names for approval
routing and quorum bookkeeping. This provider-specific mapping is transitional;
the target accepts allowlisted claims from any configured authenticator and
normalizes them before policy evaluation. See
[Entra App Registration](entra-app-registration.md) for the full role matrix and
how the `roles` claim is issued.

| Permission | Grants |
| --- | --- |
| `admin` | Platform administration. This is the superuser permission and satisfies every other permission check. |
| `approve` | Governed approval, rejection, rework, and maker/checker sign-offs. |
| `execute` | Operator mutations and designated operator working-data reads. Dry-run is the default; live modes have additional gates. |
| `request` | Creating requests and requester/self-service actions, subject to ownership checks where documented. |
| `audit` | Audit trails, evidence, and eligibility for ordinary authenticated reads. |

The coarse `execute` tier is not authority for every functional domain. The
server evaluates these typed capability identifiers before dispatch and repeats
the check in the protected handler:

| Capability | Current non-admin role |
| --- | --- |
| `identity.ad-computer.delete` | None; intentionally admin-only pending a governed identity-lifecycle role. |
| `network.firewall.manage` | None; intentionally admin-only pending a governed network/firewall role. |
| `monitoring.alert-routing.manage` | `MonitoringOperator`. |
| `monitoring.alert.read` | `MonitoringOperator`. |
| `monitoring.alert.acknowledge` | `MonitoringOperator`. |
| `storage.array.decommission` | None; intentionally admin-only pending a governed storage role. |
| `software.deployment.execute` | `WintelLinuxOperator`. |

`PlatformAdmin` and `BreakGlassAdmin` satisfy these capabilities through the
explicit `admin` superuser rule. A capability never substitutes for object
ownership, site/environment scope, approval, state-transition, or audit checks.

The current roles: `PlatformAdmin`, `BreakGlassAdmin`, `DatacenterApprover`, `VMwareOperator`, `HyperVOperator`, `ProxmoxOperator`, `WintelLinuxOperator`, `BackupOperator`, `MonitoringOperator`, `ServiceDesk`, `Auditor`, and `Requester`.

In current Entra mode, role assignment for people happens in the Entra
enterprise application, not in Ryuki. Unknown roles on a token mint are
rejected. Future providers must use an explicit, provider-qualified claim
mapping; role strings never select a verifier or link identities.

The current `BreakGlassAdmin` mapping grants standing `admin` and is
transitional. In the target model the external role establishes eligibility
only: a separate, stepped-up, audited, short-lived activation grants emergency
authority, and the role claim by itself grants none.

## Route access classes

The API Reference's **Access** value for a human route is its exact current
`request`, `audit`, `execute`, or `admin` tier. Safe reads do not inherit one
generic `read` class: the router owns a closed requester-readable manifest and
new or unclassified reads default to `audit`.

| Access class | Meaning |
| --- | --- |
| `request` on a safe read | Closed self-service/static compatibility class, satisfied by `request` **or** `audit` (and therefore by `admin`). Dynamic resources in this class require repository/handler ownership predicates. This behavior applies only to the enumerated route shapes; it is not the default for a new GET. |
| `audit` on a safe read | Default for a new or unclassified authenticated read and mandatory for audit-grade identity/evidence data. A `request`-only principal cannot use it. |
| `execute` on a safe read | Operator working data, such as the shift queue. It is not ordinary requester visibility. |
| `admin` on a safe read | Sensitive identity, secret, emergency, and administration data. |
| `public` | No human session is required. This covers health/bootstrap and selected auth or agent-bootstrap routes; handlers still validate their inputs and configured mode. |
| `agent` | Bypasses human-session RBAC and authenticates with an agent `rya_...` bearer token plus the supported `x-ryuki-protocol-version`. Agent registration, the control-plane public key, and the agent OpenAPI document are public bootstrap exceptions. |
| `webhook` | Bypasses human-session RBAC but requires a fresh v1 `X-Hub-Signature-256` envelope binding the fixed path, connection, timestamp, delivery ID, and exact-body digest. Accepted delivery IDs are atomically deduplicated. It is not anonymous access. |

The former generated `read` label is retired because it hid the difference
between requester-owned/static reads and audit-only data. Protocol classes
explain why the complete surface still cannot be described using only human
permissions. Scope and resource predicates continue after the route tier; the
tier alone never proves ownership or final-resource authorization.

## Scopes

A principal's current session representation carries a site scope and an
environment scope, each a list of allowed values. The current implementation
interprets an empty list as unrestricted on that axis. That is a migration
encoding, not the production target: unrestricted, unknown/unresolved,
not-applicable, and explicitly empty authority must be distinct validated
states, so a missing or malformed claim cannot widen access.

Today, scopes are carried by **API tokens**: interactive sessions (Entra ID or
local auth) are unscoped, and the development auth modes run as an unscoped
admin. Preserve that behavior only to operate current development/migration
deployments. To give a current integration a narrower blast radius, mint it a
scoped token; production acceptance requires explicit effective scope on every
actor kind under the
[canonical security context](architecture/platform-security-boundary.md#canonical-security-context).

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

This is the current role-based compatibility-token model. The production target
uses a credential-family id and version, an exact Ryuki audience, a closed action
allowlist (or role ceiling translated to actions), explicit site/environment
scope state, mandatory short TTL, and audited last-use/revocation metadata.
Rotation shows the replacement once, permits only a bounded overlap, then
revokes the prior version. Service tokens cannot satisfy interactive, step-up,
or break-glass obligations. See
[service credentials and API tokens](architecture/platform-security-boundary.md#service-credentials-and-api-tokens).

## Authentication modes

In the current compatibility implementation, `RYUKI_AUTH_MODE` selects how
sessions are established; it never enables live provider calls (that is a
separate, operator-gated setting). The target registry and explicit deployment
profile replace this switch; a missing profile or simultaneous legacy and
registry authority selection fails before binding unless a time-bounded,
non-authorizing migration overlay names the single source of truth.

| Mode | Behavior |
| --- | --- |
| `mock-dry-run` (default) | Static development session, unscoped admin. |
| `static-dry-run` | Same, without the mock provider affordances. |
| `local` | Current development/migration username/password sessions; not the production emergency-authentication target. |
| `entra-id` | Entra ID SSO. Bearer tokens are validated cryptographically (RS256, issuer, audience, expiry) against tenant JWKS. |

## A note on the portal

The portal filters navigation and actions by role for usability, but that is convenience, not security: every rule above is enforced server-side, and the API answers the same regardless of which client asks.
