# Portal Information Architecture

This page defines the stable information architecture for the Ryuki portal and the
runtime boundary it is built on. It is mirrored by the static
`/api/platform/portal-information-architecture-contract` endpoint and validated by
the `portal-information-architecture` slice.

## Stable navigation model

The portal exposes a fixed top-level navigation model.

The stable workspaces are: Dashboard, Catalog, Requests, Activity, Inventory, CMDB, Evidence, Operations, and Admin.

These nine workspaces are the stable anchors of the portal; new capabilities slot underneath an existing workspace rather than adding new top-level entries.

## Runtime boundary

The portal is a full-stack Leptos portal rendered as Axum-backed SSR with a
hydrated browser bundle. All privileged work crosses a server-function boundary:
the browser bundle calls only the portal server, which brokers reads against the
platform API. Static-only hosting remains disabled — the portal always runs as the
Axum-backed Leptos server, never as a pre-rendered static site.

## Scope and authority context

Every screen carries the operator's working context.

The scope band surfaces: site, environment, role, data freshness, and execution authority.

This makes it explicit which site and environment the operator is acting in, what their role permits, how fresh the inventory/backup/monitoring data is, and whether execution authority is currently granted.

## First Mockup Priorities For Batch 2

The first mockups to produce for Batch 2 are the product shell and the dashboard
overview, because every other workspace inherits the shell chrome and the scope
band. After those land, the catalog and request surfaces are mocked next so the
dry-run gate and acceptance checklist can be reviewed, followed by the inventory
and CMDB surfaces, and finally the evidence, operations, and admin surfaces.

The priority order is therefore: shell and dashboard, then catalog and requests,
then inventory and CMDB, then evidence, operations, and admin. Each mockup is a
static wireframe only and carries no live execution.

## Prohibitions

- No live provider calls.
- No direct browser calls to adapters, providers, the database, or the secret
  store; the browser bundle talks only to the portal server-function boundary.
