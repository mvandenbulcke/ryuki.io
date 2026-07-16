# Database migration runner and API cutover

Production schema mutation is a one-shot release operation. The long-running
API verifies the migration ledger but never applies migrations. Both processes
use the same digest-pinned `platform-api` image, so they compare the database
against the same compile-time embedded migration inventory without a
hard-coded latest version.

## Startup modes

`RYUKI_MIGRATION_MODE` is a closed enum:

- `local-auto` is the default when the variable is absent. It preserves local
  development auto-apply behavior, but applies through an isolated
  one-connection migration pool rather than the application pool.
- `apply-only` requires `RYUKI_MIGRATION_DATABASE_URL`, applies every pending
  embedded migration with SQLx advisory locking, reads back the complete
  migration ledger, closes the pool, and exits. It never loads application
  provider/auth configuration, initializes the normal application pool, starts
  reconciliation or background loops, or binds an HTTP listener.
- `verify-only` uses only `RYUKI_DATABASE_URL`. It performs read-only checks of
  `_sqlx_migrations` and refuses process startup before readiness/listener
  creation when any embedded migration is missing, dirty, unexpected, or has a
  different checksum. It never creates the migration table or applies DDL.

The reviewed runner defaults are a 1,800-second statement timeout and a
60-second lock timeout. `RYUKI_MIGRATION_STATEMENT_TIMEOUT_SECS` must remain
between 60 and 7,200 seconds; `RYUKI_MIGRATION_LOCK_TIMEOUT_SECS` must remain
between 1 and 300 seconds and strictly below the statement timeout. A release
that needs a different envelope requires an explicit capacity and lock-impact
review before changing the non-secret Job ConfigMap.

## Credential and image boundary

The manifests keep four API database identities separate:

1. `vault-api-db` is the continuously reconciled Vault Secrets Operator
   TokenRequest identity for the runtime API database lease. It may request
   only `creds/ryuki-app-runtime`.
2. `platform-api` is the long-running workload identity. Its Deployment
   imports exactly `RYUKI_DATABASE_URL` through one `secretKeyRef`; it never
   imports a whole Secret. The short-lived database login may only assume the
   stable `ryuki_app_runtime` `NOLOGIN` role, which has ordinary application
   privileges and read-only access to `_sqlx_migrations`, but no schema
   ownership or general DDL privileges.
3. `vault-api-db-migrator` is the operations-only TokenRequest identity. Its
   digest-scoped VaultAuth and VaultDynamicSecret must be created only after
   the drain. The external Vault role may request only
   `creds/ryuki-schema-migrator-<digest-prefix>` and emits exactly
   `RYUKI_MIGRATION_DATABASE_URL` into the matching digest-scoped destination.
4. `platform-api-migrator` is the one-shot Job ServiceAccount. It consumes
   that one migration key through `secretKeyRef`; its short-lived database
   login may assume only the stable `ryuki_schema_migrator` `NOLOGIN` role
   authorized for the reviewed migration DDL and SQLx advisory lock.

No credential value belongs in Git, a ConfigMap, Job arguments, or logs. Before
adoption, retain evidence that the Vault auth bindings, Vault path policies,
Secret destinations, PostgreSQL grants, and credential revocation/rotation
timing match this separation. The migration Job image must be byte-for-byte
the same registry/repository digest as the replacement API Deployment.

## Ordered production cutover

Do not overlap pre-migration writers, the migration Job, or the replacement API.
The accepted tradeoff is a short control-plane outage.

1. Freeze and validate the release contract, the operations-only migration
   credential template, the generated Job template, and the replacement API
   Deployment against the same reviewed digest. Confirm the runtime API lease
   and exact-key import evidence is current, and confirm that no standing
   migration VaultAuth, VaultDynamicSecret, destination Secret, or Job exists.
2. Stop the old API (`replicas: 0`) and drain every external worker or scheduled
   writer for this control plane. Wait until all old API pods are deleted and
   prove no leased/running work or active database writer session from the old
   release remains. Do not rely on `Recreate` alone for workers deployed outside
   the base skeleton.
3. Using the frozen digest prefix, create the operations-only migrator
   VaultAuth and revoking VaultDynamicSecret. Require independent readback that
   the lease uses the reviewed digest-scoped Vault role and database role and
   that its destination contains exactly `RYUKI_MIGRATION_DATABASE_URL`.
4. Create exactly one generated `platform-api-migrations-<digest-prefix>-*`
   Job. Its
   `restartPolicy: Never`, `backoffLimit: 0`, single completion/parallelism, and
   2,400-second active deadline prevent an automatic second migration writer.
5. Require Job condition `Complete`. Capture its exit status and logs showing
   the dynamically discovered embedded migration count/latest version and
   successful post-apply readback. Using an independently authenticated
   operator read path, capture ordered `_sqlx_migrations` version, success, and
   checksum rows and prove there is no `success = false` row. Do not infer
   completeness from a numeric ceiling; the Job and replacement image compare
   every embedded version/checksum.
6. After the independent role and ledger readback passes, delete the
   digest-scoped VaultDynamicSecret and VaultAuth and prove the migration lease
   and destination Secret were revoked/deleted. Do this before starting any
   matching API or worker.
7. Only after revocation evidence passes, apply/recreate the `platform-api`
   Deployment with `RYUKI_MIGRATION_MODE=verify-only`. Require startup log
   evidence that the complete embedded inventory was accepted, then require
   `/ready` success before restoring traffic and external writers.
8. Retain the Job object/logs, frozen templates, revocation receipt, and
   database readback with the release evidence.
   Delete a prior completed Job only after its evidence has been archived and
   before intentionally creating the next release Job.

If the Job fails, times out, or reports a dirty/checksum/missing condition, keep
the API and workers stopped. Do not retry automatically, edit
`_sqlx_migrations`, run down migrations, or start an older API. Investigate the
DDL transaction and lock state, recover according to the reviewed migration,
then create a new one-shot Job only after explicit operator approval.

Local development may continue using the default `local-auto` mode. That
compatibility is not authorization to use the application database role as a
production migrator.
