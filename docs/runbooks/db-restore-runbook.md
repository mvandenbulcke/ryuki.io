# Control-Plane Database — Restore & Disaster-Recovery Runbook

Recovery procedures for the Ryuki control-plane PostgreSQL database, which runs
as a CloudNativePG (CNPG) `Cluster` named `ryuki-platform-db` in the
`ryuki-platform` namespace.

This database is the platform's own system of record. The platform governs
other systems' backup coverage; this runbook is how we recover **ourselves**.

## Backup model

| Concern | Where it is defined |
|---|---|
| CNPG `Cluster` (3-instance HA) | `deploy/kubernetes/cloudnativepg/cnpg-cluster.yaml` |
| Barman object-store target + WAL archive | `cnpg-cluster.yaml` → `spec.backup.barmanObjectStore` |
| Recurring base backup (daily 02:30 UTC) | `deploy/kubernetes/cloudnativepg/scheduled-backup.yaml` |
| Retention window (30d) | `cnpg-cluster.yaml` → `spec.backup.retentionPolicy` (retention is a Cluster field, not a ScheduledBackup field) |
| Retention intent (`RYUKI_RETENTION__*`) | `deploy/kubernetes/base/configmap.yaml` |

CNPG continuously archives Write-Ahead Log (WAL) segments to the object store.
That continuous WAL stream — combined with the most recent base backup — is what
enables **point-in-time recovery (PITR)** to any moment inside the retention
window, not just to a backup boundary.

> TODO(object-store): the real backup bucket, S3 endpoint, region, and the
> `ryuki-platform-db-backup-s3` credential secret are deployment-time values.
> The committed manifests carry non-functional placeholders
> (`s3://placeholder-bucket/`, `https://placeholder-s3-endpoint.invalid`).
> No backup is recoverable until those are replaced with real coordinates.

## Recovery time / point objectives

| Objective | Target | Basis |
|---|---|---|
| RPO (max data loss) | ≤ 5 min | Continuous WAL archiving |
| RTO (PITR) | ≤ 30 min | Bootstrap a recovery cluster from the object store + WAL replay, then cut over |
| RTO (full cluster loss) | ≤ 2 h | Bootstrap a new cluster from the object store |

> CNPG recovery is always a **new-cluster bootstrap + cutover**, never a true
> in-place restore: PITR provisions a fresh `Cluster` (`bootstrap.recovery` from
> the object store), which you then promote/cut over to. Plan the writer
> stop + endpoint cutover accordingly.

## Preconditions for any recovery

1. `kubectl` access to the cluster and the `ryuki-platform` namespace.
2. The CloudNativePG operator is installed and healthy.
3. The backup S3 credentials secret (`ryuki-platform-db-backup-s3`) is present
   in the namespace (synchronized by the Vault Secrets Operator).
4. You have confirmed the object store is reachable and lists recent backups.
5. **Stop every application generation** before recovery: withdraw traffic,
   scale every API replica to zero, stop schedulers, workers, agents, migration
   jobs, and operator-triggered execution, and wait for all database sessions
   and transactions to drain. Record the exact database backup/WAL boundary and
   the matching application image digest. Follow
   `docs/runbooks/database-migration-cutover.md`; if interactive authority may
   roll back, also follow
   `docs/runbooks/interactive-human-authority-cutover.md`.

```bash
# Confirm the operator and current cluster state.
kubectl -n ryuki-platform get cluster ryuki-platform-db -o wide
kubectl -n ryuki-platform get pods -l cnpg.io/cluster=ryuki-platform-db

# List the base backups that CNPG has recorded.
kubectl -n ryuki-platform get backups.postgresql.cnpg.io \
  -l cnpg.io/cluster=ryuki-platform-db
```

---

## Scenario A — Point-in-time recovery (PITR)

Use when the cluster is still healthy but data was corrupted/deleted at a known
(or estimated) time and you need to roll back to just before it — e.g. a bad
migration or an erroneous bulk delete. CNPG recovers by bootstrapping a **new**
cluster from the object store and replaying WAL up to the target time.

1. Identify the recovery target timestamp (UTC, RFC 3339). Pick a moment
   strictly **before** the damaging event.

2. Create a recovery cluster that bootstraps from the existing backup object
   store and stops WAL replay at the target. Apply it in the same namespace
   under a new name (e.g. `ryuki-platform-db-pitr`):

   ```yaml
   apiVersion: postgresql.cnpg.io/v1
   kind: Cluster
   metadata:
     name: ryuki-platform-db-pitr
     namespace: ryuki-platform
   spec:
     instances: 3
     storage:
       size: 10Gi
       storageClass: vsphere-csi
     bootstrap:
       recovery:
         source: ryuki-platform-db
         recoveryTarget:
           # Replay WAL up to (and not past) this instant.
           targetTime: "2026-06-20T12:00:00Z"
     externalClusters:
       - name: ryuki-platform-db
         barmanObjectStore:
           # Same destinationPath / endpointURL / s3Credentials as the
           # source cluster's spec.backup.barmanObjectStore.
           # TODO(object-store): fill from the real deploy-time target.
           destinationPath: s3://placeholder-bucket/
           endpointURL: https://placeholder-s3-endpoint.invalid
           s3Credentials:
             accessKeyIdSecret:
               name: ryuki-platform-db-backup-s3
               key: access_key_id
             secretAccessKeySecret:
               name: ryuki-platform-db-backup-s3
               key: secret_access_key
   ```

3. Wait for the recovery cluster to reach a healthy primary and finish WAL
   replay:

   ```bash
   kubectl -n ryuki-platform get cluster ryuki-platform-db-pitr -w
   ```

4. Validate the recovered data (row counts, the specific records that were
   damaged, latest sane timestamps). Read back the exact `_sqlx_migrations`
   version/checksum/dirty inventory and select only the binary digest that
   matches that restored schema. An unexpected, missing, dirty, or
   checksum-mismatched ledger is a stop condition.

5. Before cutover, invalidate persisted sessions and API tokens, API-side
   authority/verifier caches, and every applicable upstream credential/token
   generation required by the interactive-authority rollback runbook. Obtain
   upstream readback and wait the maximum issued-token lifetime when revocation
   is unavailable.

6. Cut over the database endpoint or promote the recovery cluster. Start only
   the exact matching binary in verify-only mode, prove its embedded migration
   inventory/checksums match `_sqlx_migrations`, then complete authority and
   readiness reconciliation before accepting traffic. Re-enable workers only
   after the API is ready; never run an old binary against a newer restored
   schema or restore only one half of the database/binary pair.

7. **Re-establish the backup posture on the recovered cluster.** The recovery
   manifest above only declares how to recover FROM the object store
   (`externalClusters`); it does NOT give the new cluster its own
   `spec.backup.barmanObjectStore`, so the recovered cluster is **not backing
   itself up**. Add the same `spec.backup` block (and retentionPolicy) from
   `cnpg-cluster.yaml` to the recovered/promoted cluster and re-apply the
   `ScheduledBackup` (pointed at the new cluster name) before treating recovery
   as complete — otherwise you are running unprotected.

8. Once verified and stable, decommission the damaged original cluster.

---

## Scenario B — Full cluster loss (DR)

Use when the entire CNPG cluster is gone — namespace deleted, storage lost, or
the whole Kubernetes cluster destroyed. The object store survives independently,
so we rebuild from it.

1. Ensure the target Kubernetes cluster has the CNPG operator installed and the
   backup credentials secret present (Vault Secrets Operator), plus the storage
   class (`vsphere-csi`).

2. Re-create the namespace and supporting resources if they are missing
   (`deploy/kubernetes/base/namespace.yaml`, network policies, config map).

3. Bootstrap a **fresh** cluster that recovers from the object store. This is the
   same `bootstrap.recovery` mechanism as PITR, but **without** a
   `recoveryTarget` — so it replays **all** archived WAL and recovers to the
   latest consistent point (lowest possible RPO):

   ```yaml
   apiVersion: postgresql.cnpg.io/v1
   kind: Cluster
   metadata:
     name: ryuki-platform-db
     namespace: ryuki-platform
   spec:
     instances: 3
     storage:
       size: 10Gi
       storageClass: vsphere-csi
     bootstrap:
       recovery:
         source: ryuki-platform-db
     externalClusters:
       - name: ryuki-platform-db
         barmanObjectStore:
           # TODO(object-store): real deploy-time destinationPath / endpointURL.
           destinationPath: s3://placeholder-bucket/
           endpointURL: https://placeholder-s3-endpoint.invalid
           s3Credentials:
             accessKeyIdSecret:
               name: ryuki-platform-db-backup-s3
               key: access_key_id
             secretAccessKeySecret:
               name: ryuki-platform-db-backup-s3
               key: secret_access_key
   ```

4. Wait for the cluster to become healthy and confirm it replayed WAL to the
   latest point:

   ```bash
   kubectl -n ryuki-platform get cluster ryuki-platform-db -w
   kubectl -n ryuki-platform get pods -l cnpg.io/cluster=ryuki-platform-db
   ```

5. Re-apply the recurring backup so the new cluster is protected again:

   ```bash
   kubectl apply -f deploy/kubernetes/cloudnativepg/scheduled-backup.yaml
   ```

6. Before starting any reader or writer, read back the exact
   `_sqlx_migrations` version/checksum/dirty inventory, select the matching
   application image digest, and complete the session/token/cache/upstream
   credential invalidation required by the two cutover runbooks above. Start
   only that binary in verify-only mode; prove authority/readiness, then restore
   traffic and workers in the documented order. Verify end-to-end login and a
   representative read/write path.

---

## Scenario C — Local developer recovery (compose)

For the local/compose stack there is no CNPG/Barman. Use the logical
`pg_dump`/`pg_restore` tooling instead:

```bash
make db-backup    # writes a timestamped dump under ./backups/
make db-restore FILE=backups/<dump-file>
```

These targets run against the compose database
(`postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform`). They are for
developer convenience and disaster drills on a throwaway database — they are
**not** the production recovery path (that is Scenario A/B above).

---

## Quarterly restore test (mandatory)

A backup that has never been restored is a hypothesis, not a backup. Run this
drill **every quarter** and record the result.

1. **Pick a target.** Choose a recovery target time within the last 24 h.

2. **Restore in isolation.** Bootstrap a throwaway recovery cluster
   (`ryuki-platform-db-drill`) from the object store using the Scenario A
   manifest, pointed at the target time. Do **not** touch the live cluster.

3. **Verify integrity.** Connect to the drill cluster and check:
   - the cluster reaches a healthy primary and finishes WAL replay;
   - core tables exist and row counts are within expected bounds;
   - the latest rows match the chosen recovery target time;
   - no WAL gaps were reported during replay.

4. **Measure.** Record the wall-clock time from "apply manifest" to "verified
   healthy" and compare against the RTO target (≤ 30 min for PITR). Record the
   effective RPO (target time vs. latest recoverable WAL).

5. **Tear down.** Delete the drill cluster and confirm its storage is reclaimed.

6. **Record.** Log the drill date, operator, backup ID used, recovery target,
   measured RTO/RPO, and pass/fail. File any gaps (e.g. retention too short,
   credentials drift, slow restore) as follow-up work.

> A restore-test failure is a SEV: it means the platform cannot currently
> recover itself. Treat it with the same urgency as a production outage.

## Related artifacts

- `deploy/kubernetes/cloudnativepg/cnpg-cluster.yaml` — the CNPG cluster + backup target.
- `deploy/kubernetes/cloudnativepg/scheduled-backup.yaml` — the recurring backup schedule.
- `deploy/kubernetes/base/configmap.yaml` — `RYUKI_RETENTION__*` retention intent.
- `Makefile` — `db-backup` / `db-restore` targets for the local/compose database.
