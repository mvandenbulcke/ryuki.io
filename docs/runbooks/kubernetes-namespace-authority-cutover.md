# Kubernetes namespace authority cutover

Migration 178 makes the canonical `site_registry` row part of Kubernetes
cluster authority. A namespace or request is visible and mutable only while its
exact cluster, environment scope, and canonical site row are all active. Site
deactivation is therefore an immediate authority revocation, not inventory
cleanup.

## Required non-overlapping rollout

This is not a rolling-compatible database change. Pre-178 API replicas do not
join `site_registry` when they read or mutate namespace authority, so they must
never overlap migration 178 or the replacement API release.

1. Remove API traffic and drain every pre-178 API replica.
2. Confirm those replicas and their open database transactions have exited.
3. Apply migration 178.
4. Start only API replicas that enforce the active canonical-site relation.
5. Verify that an active fixture resolves and that an inactive-site fixture is
   absent from get, list, provision, quota, and status operations.
6. Restore traffic.

The Kubernetes `platform-api` Deployment uses `Recreate`, which supplies the
required non-overlap only when the old pod is fully terminated before migration
178 is applied. A rollback must keep traffic stopped until a compatible build is
running; never restart a pre-178 binary against the migrated schema.

## Inventory writer locking

Namespace provisioning and mutations retain a shared lock on the current
`site_registry` row for their transaction. Deactivation either commits first
and the operation fails closed, or waits for an already-authorized transaction
to commit. Future inventory writers that touch more than one authority table
must use this lock order consistently:

1. `site_registry`
2. `k8s_cluster_registry`
3. `k8s_cluster_environment_scopes`

Keeping one global order avoids reverse-order deadlocks during deactivation or
inventory refresh. Do not treat the foreign key alone as an activity check: it
proves canonical identity and existence, while repository joins and transaction
locks enforce current active authority.
