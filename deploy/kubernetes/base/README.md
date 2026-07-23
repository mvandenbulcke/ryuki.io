# Kubernetes Base Manifests

Base manifests define the portable Kubernetes skeleton for Ryuki Infrastructure Platform components.

| File | Contents |
|---|---|
| `namespace.yaml` | `ryuki-platform` namespace. |
| `serviceaccounts.yaml` | One ServiceAccount per serving component, a dedicated one-shot migration identity, and four non-auto-mounted TokenRequest identities that separate database owner, backup, API runtime, and migration secret materialization. |
| `configmap.yaml` | Non-secret runtime settings: verify-only `platform-api-config`, including the fixed path to the projected SecretRef fingerprint keyring; apply-only `platform-api-migration-config` with 180-second statement and 30-second lock deadlines inside the 300-second infrastructure-proof lifetime; and a fail-closed, static-dry-run `portal-ui-config` with non-resolving HTTPS placeholders. |
| `deployments.yaml` | `portal-ui` and `platform-api` deployments with HTTP probes on port 8080, conservative resource requests/limits, non-root security contexts, digest-only non-resolving image placeholders, exact allowlisted ConfigMap-only `envFrom`, exact database/admission key references, CA-only CloudNativePG and Vault trust mounts, one 600-second `vault`-audience projected API token, and the one-key SecretRef fingerprint-keyring projection. |
| `services.yaml` | Internal ClusterIP services for `portal-ui` and `platform-api`. |
| `ingress.yaml` | Dedicated `ryuki-platform` NGINX IngressClass placeholder for `platform.example.invalid` and same-origin `/api`. |
| `networkpolicies.yaml` | Default-deny ingress/egress plus explicit UI/API/DNS allowances, a dedicated ingress-controller instance selector, separate API and migration-Job ↔ CNPG database paths (TCP 5432 in both directions), CNPG intra-cluster and operator allowances (5432 + 8000), and the API half of the exact Vault:8200 path. `../vault/workload-auth.yaml` owns the matching Vault ingress half. Deployment-time TODOs: the CNPG instance manager and Vault authentication-review client additionally need egress to their cluster-specific kube-apiserver endpoint, and Barman backups need egress to the object-store endpoint. |

## Database configuration delivery

Production migration Job creation is currently disabled. The checked-in
validator performs offline snapshot validation only and rejects every
`final-render` with the
`in-cluster-final-render-admission-and-runtime-freshness-v1` unavailable error.
Snapshot validation cannot fence a ConfigMap delete/recreate between readback
and Pod materialization, consume a unique execution attempt, or enforce receipt
expiry when the Pod starts and while it runs. Do not clear `spec.suspend`, mint
a migration credential, or create this Job until those in-cluster admission and
runtime gates are implemented and independently reviewed.

The API Deployment requires the operator-owned stable
`platform-security-admission-config`. The one-shot migration source template is
suspended and cannot start a Pod if submitted accidentally. Its signed final
render shape would explicitly clear suspension, reference the immutable
`platform-security-admission-config-<digest-prefix>` and seven other
digest-scoped pin ConfigMaps, and bind every exact content digest, UID, and
resourceVersion in Job annotations and its signed socket-projection receipt.
That shape is retained for diagnostic validation; it is not executable and is
always rejected.
Seven individual `configMapKeyRef` entries import the absolute image path
`/app/security-contract`, relative profile path, raw-byte SHA-256 profile
digest, expected deployment id, explicit production profile, and the normalized
relative `.json` path plus independently pinned nonzero raw-byte SHA-256 digest
for the conformance trust-root registry; the latter use
`RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH` and
`RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST`. Whole-ConfigMap import is
forbidden for that group. The release image must bake the
exact reviewed contract tree into `/app/security-contract` as root-owned regular
files, including every content-addressed predecessor from the selected trust
registry head back to version 1. Startup rejects missing, gapped, relabeled,
resurrected, or digest-mismatched lineage before any runtime side effect. The
hash chain is not an external monotonic rollback checkpoint, so production
also requires the separately governed external checkpoint authority and its six
`RYUKI_CONFORMANCE_TRUST_CHECKPOINT_*` production bindings. This base
deliberately provisions neither the authority socket nor those pins, and they
must not be added to the rollbackable `platform-security-admission-config`.
An operator-owned overlay must authenticate and mount the local authority
socket and deliver the authority/key/fingerprint/minimum-epoch pins through a
separate workload/deployment trust channel. Until that SB-8 integration and its
recovery evidence exist, this skeleton cannot exercise checkpoint
reconciliation or claim production eligibility. The base does not fabricate
the admission ConfigMap, and its checked-in image contains only non-production
implementation fixtures, so an unoverlaid production render remains
fail-closed.

`platform-api` reads its non-secret settings from the `platform-api-config`
ConfigMap and `RYUKI_DATABASE_URL` from the `ryuki-platform-api-db` Secret.
The same ConfigMap pins the twelve value-free
`RYUKI_SECRET_PROVIDER_RUNTIME__*` fields for the direct Vault resolver. The
Deployment keeps `automountServiceAccountToken: false`, projects one
600-second `vault`-audience token at
`/var/run/secrets/ryuki/vault-auth/token`, and mounts only
`ryuki-vault-client-ca/ca.crt` at
`/var/run/secrets/ryuki/vault-tls/ca.crt`, both mode `0440` and read-only under
`fsGroup: 10001`. The direct API role is `ryuki-platform-api`; it is distinct
from every VSO `VaultAuth` and materializer ServiceAccount.

Secret-reference fingerprints use an independent HMAC keyring. An authorized
operator creates `ryuki-secret-reference-fingerprint-keyring` in
`ryuki-platform` with exactly one Kubernetes Secret key named `keyring`. The
Deployment projects only that key, mode `0440`, and mounts it read-only at
`/var/run/secrets/ryuki/secret-reference-fingerprint/keyring`; the ConfigMap
contains only that non-secret path. The keyring payload format and overlapping
rotation procedure are defined in `../vault/bootstrap-runbook.md`. Do not add
this material to an environment variable, manifest, log, or evidence bundle.

The checked-in one-shot source Job names `platform-api-migration-config`, but
that source mode is not admissible for execution. The diagnostic final-render
shape rewrites `envFrom` to immutable
`platform-api-migration-config-<digest-prefix>` and receipt-binds its exact five
reviewed keys and API identity. The other six application/security pin groups
are imported key-by-key from their immutable digest-scoped ConfigMaps. The
eighth, non-environment pin ConfigMap describes the socket-projection receipt
authority. Its key is not a trust anchor merely because the manifest supplies
it, and the production validator no longer accepts an inline or context-selected
anchor. A future in-cluster admission capability must receive its independently
provisioned anchor through a trust channel outside the render request. The strict
signed envelope is the sole `receipt.json` value in an immutable ConfigMap whose
name contains the complete 64-hex raw digest. Its metadata separately binds the
canonical `data`-object digest and raw receipt digest. It is neither mounted nor
imported as application environment; within the rendered Job and CSI graph,
only the excluded Job annotation carries the raw digest. See
`../operations/migration-cutover-contract.yaml` and
`../../../docs/runbooks/database-migration-cutover.md` for the eight pin receipts,
signed-envelope diagnostic validation, socket CSI projection shape, and the
currently unavailable runtime fences.

The Job reads only `RYUKI_MIGRATION_DATABASE_URL` from the distinct digest-
scoped `ryuki-platform-api-migrator-db-<digest-prefix>` Secret. The API runtime
lease and the two CNPG-referenced static Secrets
(`ryuki-platform-db-superuser` and `ryuki-platform-db-backup-s3`) are described
in `../vault/vso-secrets.yaml`. The operations-only migration lease and Job are
templates in `../operations/`; they are never part of the continuously
reconciled base. Secret values live only in Vault.

The migration container keeps `readOnlyRootFilesystem: true`. Its source Pod
has exactly two volumes and mounts: the read-only CloudNativePG CA and a
memory-backed `emptyDir` named `postgresql-relay-workspace`, bounded to `1Mi`
and mounted read-write at `/run/ryuki-postgresql-relay`. Pod `fsGroup: 10001`
with `fsGroupChangePolicy: OnRootMismatch` makes that directory available to
the non-root migration process solely for its owner-only, one-use local relay
socket; no credential or durable state belongs there. The rejected final-render
shape preserves those two entries and adds exactly four read-only authority-
socket CSI volumes and mounts, for a closed total of six. It must not
substitute a disk-backed workspace, widen the size limit, or reuse the relay
mount as an authority transport.

Both generated database URLs use `sslmode=verify-full` with
`sslrootcert=/var/run/secrets/ryuki/cnpg/ca.crt`. The API and one-shot Job
project only `ca.crt` from the operator-managed `ryuki-platform-db-ca` Secret;
the CA private key is not mounted. The final CloudNativePG server certificate
must contain `ryuki-platform-db-rw.ryuki-platform.svc` as an exact DNS SAN.
The manifest annotations and validator encode that contract, but observed
certificate contents and rotation remain deployment-owned evidence.

Portal SSR forwarding stays on external same-origin HTTPS. Its egress policy
selects only an ingress-nginx controller labeled
`app.kubernetes.io/instance=ryuki-platform`, and the Ingress uses the matching
`ryuki-platform` class. That controller must be a genuinely dedicated instance
which admits only this class; adding the label to a shared controller is not an
approved shortcut and leaves the lateral-routing risk unresolved.

Each secret family references a different VaultAuth and ServiceAccount. The
matching external Vault roles and policies are not present here and must be
proved independently least-privilege before adoption. The API database secret
declares `platform-api` as its sole known rollout restart target because the
Deployment consumes it through one explicit `secretKeyRef`; the Deployment uses `Recreate`, so
the old API process stops before the replacement reads the rotated value. The
accepted tradeoff is short control-plane downtime. This local linkage does not prove VSO CRD
compatibility, successful rotation, database credential overlap/revocation, or
production rollout behavior.

Vault database roles must create short-lived `NOINHERIT` login roles with a
finite expiry, direct database `CONNECT`, and exactly one membership: `SET TRUE,
INHERIT FALSE, ADMIN FALSE` in either `ryuki_app_runtime` or
`ryuki_schema_migrator`. Every physical connection performs `SET ROLE` and
attests the split `session_user`/`current_user`, ownership boundary, exact
per-table DML policy, sequence `USAGE`-only policy, and the single reviewed
SECURITY DEFINER entry point. The migration postflight reconciles and reads back
that policy before the Job can succeed.

CloudNativePG bootstrap SQL applies only to a new cluster. An existing database
needs a separately reviewed, privileged one-time ownership/ACL handoff before
strict migration preflight; the repository does not automate that trusted
rollout operation.

`Recreate` is also a database-writer compatibility boundary. In particular,
migration 162 installs the idempotency writer-contract fence only after the old
API process has stopped. Pre-162 middleware did not hold the per-principal
budget lock and failed open on a rejected claim, so a rendered environment must
not replace this with `RollingUpdate` during that cutover. The migration's
trigger is defense-in-depth against an accidental legacy write; it is not a
license for mixed-version request handling.

## Remediation migration cutover design (158-184; production blocked)

Migrations 158 through 184 require a traffic-off, non-overlap release boundary,
not a rolling compatibility window. The sequence below is retained as future
design context only. It is not an executable runbook while production migration
execution is disabled; operators must stop before step 1 rather than draining
traffic, issuing a credential, or creating a Job. After the missing in-cluster
admission and runtime-freshness capability is implemented, the full sequence
requires a new review before use:

1. Freeze one rendered release: the `platform-api` Deployment and
   `platform-api-migrations` Job must reference the same approved image digest.
   Validate the final overlay, retain `strategy.type: Recreate`, confirm the Job
   remains apply-only and the API remains verify-only, and prepare a tested
   pre-wave database restore point.
2. Withdraw API traffic, scale every old API replica to zero, and wait until its
   database sessions and transactions have drained. Stop and drain every old
   scheduler, worker, CronJob, and operator-triggered execution path too. This is
   mandatory for the migration 163 population protocol, migration 173 audit
   verifier, migration 181 reconciliation worker, and migration 183 metric/SLO
   breach loops; zero API pods alone does not prove an external worker is idle.
3. Review database capacity, WAL headroom, lock wait, and the dedicated Job's
   180-second statement and 30-second lock deadlines. Both must remain inside
   the 300-second PostgreSQL infrastructure-attestation lifetime; a migration
   that cannot fit must be decomposed and reviewed rather than granted a longer
   stale-proof window. Migrations 163 and 170 take explicit offline table
   locks, while migration 183 builds nine ordinary, non-concurrent indexes. Do not
   apply this wave during request traffic or background execution.
4. Only after the drain and independent zero-session readback, create the
   digest-scoped VaultAuth/VaultDynamicSecret and then create the generated
   one-shot migration Job once. Require one successful completion
   with no automatic retry, then read the exact
   `production_migration_operations` marker and `_sqlx_migrations` inventory
   back. Compare every installed version and checksum with the versions embedded
   in that exact image. A missing, dirty, extra, or checksum-mismatched row fails
   the release closed. `CommitOutcomeUnknown` is not a rollback signal: retain
   its operation id and use only an explicitly approved fresh attested marker
   reconciliation, never speculative DDL replay. Revoke and delete the migration
   lease after role/ledger readback and before API start.
5. Start only the matching new `Recreate` API image, initially with traffic
   still withdrawn. Its verify-only startup must independently accept the same
   dynamic `_sqlx_migrations` readback before `/ready` can succeed. Never let an
   API process apply schema changes at startup.
6. Reconcile authority before restoring traffic: confirm expected session
   invalidation, current migration 163 job protocol, reviewed migration 182
   human-authority assignments, and current migration 181 site generations.
   Confirm all nine migration 183 indexes are valid/ready and exercise the new
   metric/SLO overflow and partial-result behavior with traffic still withdrawn.
   Rows quarantined by migrations 167-171, 175, and 177-181 remain non-operative
   until individually proven; do not infer authority in bulk from legacy names.
   Re-enable only workers built from the matching image after these checks.
7. Restore traffic, observe readiness and authorization failures, and only then
   scale additional replicas of the same digest.

The focused matrix below explains why each overlap-sensitive remediation needs
that boundary. A database backstop protects only the operation it actually
guards; none of these entries authorizes an old reader or worker to coexist
with the new schema.

| Migration | Why an old process cannot overlap the cutover | Database backstop and its limit |
|---|---|---|
| 158 agent enrollment admission | Old enrollment code does not implement the challenge-bound Pending admission and proof-of-possession transition, so its endpoint contract cannot participate in the new flow. | The v3 writer GUC/trigger rejects pre-contract authority writes. It does not make old endpoints or read-side decisions compatible. |
| 162 idempotency principal budget | Pre-162 middleware omitted the exact per-principal budget lock and could fail open after a rejected claim. Mixed replicas therefore disagree on admission and accounting. | The trigger requires writer contract 2 and the advisory principal lock, so old writes fail. Failed old requests and old middleware behavior are still an outage/security risk. |
| 163 scheduler population progress | Old schedulers do not understand the version-2 physical job kinds or progress protocol and must not scan or advance the same population. The migration also performs an offline rewrite under explicit locks. | Protocol checks reject stale advancement, but cannot prevent an old worker from misreading jobs or competing for database, lock, and WAL capacity. |
| 165 identity authority epochs | A post-159 old reader can still validate a bearer verifier without joining the new identity epoch, accepting authority that the new release revokes. | The migration deletes sessions and constrains new epoch-aware writes. PostgreSQL cannot fence the old verifier-only `SELECT` path. |
| 167 incident context scope | Old incident readers and actions ignore site/CI binding and quarantine state, so unbound legacy records can become operational. | Triggers preserve verified bindings and keep legacy writes unbound/quarantined. They do not fence old reads or decisions over those rows. |
| 168 snapshot resource authority | Old snapshot code trusts descriptive resource fields instead of the immutable current CI/site authority relation. | Foreign keys and immutability checks protect classified writes, not the old descriptive read path. |
| 169 ServiceNow queue scope | Old queue workers do not require exact CI/environment/provenance and can process unresolved legacy work. | Old-shaped writes remain all-NULL and quarantined, and promotion is guarded. The database cannot stop an old worker from interpreting unresolved rows. |
| 170 shift queue scope | Old readers/actions ignore unresolved or quarantined authority and use the pre-cutover deduplication model. | Old-shaped writes remain unresolved and the replacement indexes keep them from suppressing verified work. Those indexes do not fence old reads; the migration also uses an offline lock. |
| 171 software deployment provenance | Old actions omit the exact CI/site/environment, maker, and package provenance checks and can act on unresolved legacy requests. | Classified inserts are validated while old-shaped writes stay unresolved. Existing old read/action semantics remain outside that fence. |
| 172 certificate query bounds | Old API query shapes can still perform offset/sort/count work outside the bounded current handlers. | Supporting indexes improve admitted queries but do not prevent resource-exhaustive old `SELECT` statements. |
| 173 audit verification jobs | Old API/background code can run the earlier synchronous or population-style audit verification instead of the durable bounded job protocol. | The job tables record the new protocol; there is no database fence that makes the old verifier compatible. |
| 174 approval lifecycle epoch | Old readers count historical approval decisions as current and therefore compute authority from the wrong epoch. | Removed defaults/conflict targets and lifecycle triggers reject old writes. They cannot fence the stale read interpretation. |
| 175 alert route scope | Old readers/actions ignore site/environment classification and can expose or mutate legacy-unclassified routes. | Foreign keys and immutability guards keep old-shaped writes legacy/unclassified. They do not make those rows safe for old readers. |
| 177 directory namespace recovery | Old AD/gMSA paths ignore Verified namespace provenance or the active owner-site relation, including host-assignment decisions. | Recovery/write guards enforce current owner authority. They do not fence old selects or in-process decisions. |
| 178 Kubernetes cluster authority | Old cluster paths do not join canonical site ownership to an active registry entry and can serve or mutate stale-site resources. | Canonicalization, foreign keys, and write guards protect the new relation, not old reads. |
| 179 file-share recertification evidence | Old recertification code cannot supply the authoritative evidence relation required for a Compliant decision and may interpret legacy decisions as current. | Decision/share triggers reject evidence-free Compliant writes. That deliberate incompatibility requires drain; it is not rolling support. |
| 180 firmware exception lifecycle | Old readers treat legacy approval fields as effective without the new status/version lifecycle. | Constraints and lifecycle triggers reject old-shaped writes. They do not fence old approval reads. |
| 181 canonical site generation | Old readers use the earlier hostname heuristic and ignore generation/quarantine; old reconciliation workers can publish stale ownership. | Generation and write guards protect current state, but not old reads or worker logic. Drain workers and reconcile the current generation before traffic. |
| 182 interactive human authority | Pre-182 Entra bearer admission can bypass the database entirely, so it can accept a human identity without the new active scoped assignment. | The migration deletes sessions and installs the scoped authority relation/status fence. No database trigger can fence the old direct-bearer path. |
| 183 resource query bounds | Old/new SQL remains valid, but old metric/SLO status handlers and breach workers enumerate all enabled definitions and perform per-definition series/window work. They can exhaust capacity or make definitive alert-state decisions where the new release returns overflow/partial and preserves state. | Nine ordinary non-concurrent indexes make the bounded probes stop predictably; they do not reject an old query or worker. Each build scans its table and blocks DML, not `SELECT`; review disk/temp/I/O/WAL/replica capacity and Job deadlines before the offline apply. |

Migrations 159-161 and 164 are part of the same non-overlap wave even though
their bearer, webhook, lease, and OIDC writer fences are not repeated in this
focused matrix. There are no migration files numbered 166 or 176.

Rollback is fail-closed. Stop all API replicas and workers before taking any
rollback action. Prefer a forward fix. If restoration is unavoidable, restore
the pre-wave database and its matching old binary as one coupled unit, then
invalidate sessions, cached authority, and applicable credential/authority
generations before any reader starts. Never run an old binary against the new
schema, never perform a database-only or binary-only rollback, and never reopen
traffic until the restored pair passes its own readiness and authority
reconciliation. Migration 182 additionally requires revoking any direct bearer
authority that the database could not fence; follow
`../../../docs/runbooks/interactive-human-authority-cutover.md` for that boundary.

**Fallback without VSO**: create the same Secrets out-of-band (for example
`kubectl create secret generic ryuki-platform-api-db
--from-literal=RYUKI_DATABASE_URL=...` pointing at
`ryuki-platform-db-rw.ryuki-platform.svc:5432`). Never commit such a Secret or
its values to this repository. Before a migration wave, and only after the
drain, separately create `ryuki-platform-api-migrator-db-<digest-prefix>` with only
`RYUKI_MIGRATION_DATABASE_URL`; it must use `sslmode=verify-full`, the same
CA-only mount and DNS name above, and the reviewed migration identity,
not a copy of the long-running application credential. Revoke and delete it
after readback and before starting the matching API.
The fallback operator must also recreate the API pods after database-secret
rotation and prove a bounded old-credential revocation window; an in-place
Secret update does not change an existing process environment.

## Image provenance boundary

The checked-in Kubernetes images use the reserved, non-resolving
`registry.example.invalid` registry and syntactically valid placeholder
SHA-256 digests. They are validation fixtures, not published artifacts or
provenance claims. Every environment overlay must replace each entire
`registry/repository@sha256:<64 lowercase hex>` reference with its approved
registry, repository, and digest. Digest-less, tag-only, unqualified, or
scheme-prefixed references fail the manifest validator. The same validation
must run on the final rendered manifests, after all overlay and GitOps image
rewrites; validating the base alone is not deployment evidence.

Local Compose remains a separate developer surface and may build/use the
`ryuki/*:rust-dev` tags on loopback. Those local tags must never be copied into
a Kubernetes base, overlay, or rendered deployment.

Because `RYUKI_DATABASE__REQUIRED=true` is set in the ConfigMap, a
platform-api pod that cannot reach its database exits non-zero and
crash-loops visibly instead of silently serving from in-memory stores.

The base intentionally does not select an API authenticator. Mock/static
authority is invalid on the pod's non-loopback listener, so a deployment
overlay must select and fully configure Local or Entra and must
inject both `RYUKI_SESSION__CREDENTIAL_HMAC_KEY` and the distinct
`RYUKI_SECURITY__CERTIFICATE_CURSOR_HMAC_KEY` through explicitly selected
Secret keys. Generic OIDC remains reserved and is rejected until its exact
D/P/Q/R runtime authority is implemented. The portal base remains
`static-dry-run`. A live overlay must replace both HTTPS placeholders with the
exact externally reachable same-origin ingress, set `live-provider`, and add
the corresponding dedicated-controller TLS egress path. The base never weakens
transport validation to admit a cleartext Kubernetes service name or a shared
ingress-controller route surface.

These manifests are not production-ready. Adopted registry provenance and
signature policy, observed CNPG certificate/SAN/CA rotation, dedicated ingress
controller deployment, provider egress, and live deployment execution are
later implementation slices.
