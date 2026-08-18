# Database migration runner and API cutover

Production schema mutation is a one-shot release operation. The long-running
API verifies the migration ledger but never applies migrations. Both processes
use the same digest-pinned `platform-api` image, so they compare the database
against the same compile-time embedded migration inventory without a
hard-coded latest version.

> **Production execution is disabled.** The Kubernetes validator is an offline
> snapshot checker, not runtime admission. It rejects every `final-render`
> because the required
> `in-cluster-final-render-admission-and-runtime-freshness-v1` capability is not
> implemented. A snapshot cannot fence ConfigMap deletion/recreation through
> Pod materialization, consume a unique migration attempt, or enforce receipt
> expiry when the Pod starts and while it runs. Do not drain production, mint a
> migration credential, clear `spec.suspend`, or create the migration Job from
> this repository.

## Startup modes

Before interpreting `RYUKI_MIGRATION_MODE` or opening a database connection,
every mode admits the same seven baseline deployment-security pins documented
in `docs/configuration.md`; production additionally requires its complete
build, checkpoint, deployed-workload, public-ingress, PostgreSQL-infrastructure,
and first-owner authority pin groups. Production `apply-only` additionally
requires its complete two-value first-owner closure-certificate path/digest
group. The one-shot Job uses the same root-owned contract tree baked into the
release image and imports every external value by an exact `ConfigMap` or
`Secret` key reference. A missing, inactive, unresolved, partial, or
digest-mismatched contract therefore exits before migration credentials or
PostgreSQL are touched.

`RYUKI_MIGRATION_MODE` is a closed enum:

- `local-auto` must be selected explicitly. It preserves local
  development auto-apply behavior, but applies through an isolated
  one-connection `PgPool` that is closed after verification rather than through
  the published application pool.
- `apply-only` requires `RYUKI_MIGRATION_DATABASE_URL` and, in production, the
  complete PostgreSQL infrastructure attestation pin group. It opens one direct
  TLS 1.3 channel and relays that one channel into a direct `PgConnection`. It
  takes the bounded session advisory lock before `BEGIN`, begins the
  repeatable-read transaction, promotes the lock to the same unreleaseable
  transaction-scoped advisory key, releases the session-scoped copy, sets the
  bounded local timeouts, and reads the exact SQL-visible session and ledger
  facts. While that same connection, transaction, and transaction lock remain
  held, it performs one fresh nonce-bound
  authority exchange without retry and accepts no proof with more than 300
  seconds of authorization.
  It exact-matches independently signed provider, cluster, and durable-storage
  evidence to the receipt, then performs the final pre-DDL check, every pending
  embedded migration, exact ledger postflight, and a non-secret content-addressed
  operation marker in that transaction. It dispatches `COMMIT` only while the
  proof is fresh. A pre-commit failure rolls back the wave; a lost or failed
  `COMMIT` acknowledgement is reported as `CommitOutcomeUnknown`, never as a
  rollback.
  It never loads application provider/auth configuration, initializes the
  normal application pool, starts reconciliation or background loops, or binds
  an HTTP listener.
- `verify-only` uses only `RYUKI_DATABASE_URL`. It performs read-only checks of
  `_sqlx_migrations` and refuses process startup before readiness/listener
  creation when any embedded migration is missing, dirty, unexpected, or has a
  different checksum. It never creates the migration table or applies DDL.

The reviewed production runner uses a 180-second statement timeout, a 30-second
lock timeout, a separate 30-second `COMMIT` acknowledgement deadline, and a
300-second Job deadline. The runtime's wider parser bounds do not authorize a
production override: the retained diagnostic render shape requires exactly
these values. All DDL,
ledger changes, ACL reconciliation, postflight, and operation-marker insertion
must finish before the proof safety margin; `COMMIT` is then dispatched as the
single boundary whose acknowledgement may be uncertain. A release that cannot
finish within this envelope needs a redesigned migration and fresh review, not
a longer proof or an in-place timeout increase.

Before the embedded inventory begins, the runner derives the principal-
idempotency cutover install mode from the signed preflight ledger. Only a
pristine database with no prior migration inventory receives
`fresh-install-v1`; every missing, retained, or ambiguous state is an upgrade.
Migration 200 persists that distinction in
`idempotency_principal_cutover_state`. Fresh installs can serve immediately.
Upgrades retain the migration-199 replay fence until its transaction-start
timestamp plus 24 hours and a conservative 300-second margin. Because the
mandatory traffic withdrawal and zero-session readback happen before `BEGIN`,
the fence cannot end until more than 24 hours after the final possible legacy
mutation; `_sqlx_migrations.installed_on` is not a commit timestamp. The serving
role can only read this state, and every strict connection re-attests the exact
row and writer-trigger boundary before it is published. The isolated migration
owner remains the authority for this durable install-mode evidence and must be
disabled with the rest of the one-shot migration credential after readback.

## Production pin resources and socket projection

The checked-in Job is a suspended `source-template`, not an admissible Job. It
contains exactly nine `RENDER_REQUIRED` pin-ConfigMap receipt sentinels plus one
socket-projection receipt-digest sentinel, and intentionally omits dynamic
socket mounts. Accidental submission therefore cannot start a Pod; the signed
final-render shape is retained only for diagnostic parsing and is always
rejected, including when it sets `spec.suspend: false`. The hardened source Pod
has exactly two volumes and mounts. It projects the
CloudNativePG CA read-only and mounts the `postgresql-relay-workspace`
memory-backed `emptyDir` read-write at `/run/ryuki-postgresql-relay`, with an
exact `1Mi` limit. Pod `fsGroup: 10001` and
`fsGroupChangePolicy: OnRootMismatch` let the non-root process create its
owner-only, one-use Unix relay socket despite `readOnlyRootFilesystem: true`;
the workspace must never hold a credential or durable state. Final render must
preserve those exact two entries and add only the four receipt-bound read-only
authority-socket CSI projections, producing exactly six volumes and six mounts.
A disk-backed, larger, renamed, differently owned, or authority-reused relay
workspace fails structural validation, but passing those shape checks never
authorizes Job creation.

A future admission-capable release environment would require these non-secret,
independently governed, `immutable: true` ConfigMaps. Do not create them as a
means of bypassing the current execution block:

| ConfigMap | Exact contents |
|---|---|
| `platform-api-migration-config-<digest-prefix>` | The exact five reviewed apply-only mode, timeout, and role values; final render replaces the source template's stable `envFrom` name with this immutable name |
| `platform-security-admission-config-<digest-prefix>` | The seven baseline contract/profile/registry/deployment pins |
| `platform-production-build-manifest-pins-<digest-prefix>` | The complete two-value production build-manifest binding |
| `platform-conformance-trust-checkpoint-pins-<digest-prefix>` | The complete six-value checkpoint authority binding |
| `platform-deployed-workload-attestation-pins-<digest-prefix>` | The complete ten-value workload authority, measurement-profile, and expected-workload binding |
| `platform-public-ingress-attestation-pins-<digest-prefix>` | The complete nine-value public-ingress authority/profile binding required by production startup |
| `platform-postgresql-infrastructure-attestation-pins-<digest-prefix>` | The complete nine-value PostgreSQL infrastructure authority/profile binding |
| `platform-first-owner-authority-pins-<digest-prefix>` | The complete seven-value first-owner binding: five always-required Ed25519 authority pins plus the complete-or-none two-value exact `apply-only` closure-certificate path/digest group; all seven are imported key-by-key and the group deliberately has no socket projection |
| `platform-migration-socket-projection-authority-pins-<digest-prefix>` | The exact eight `RYUKI_MIGRATION_SOCKET_PROJECTION_RECEIPT_*` authority/key/profile values; it is render-verification input only and is never imported as application environment or mounted into the Job |

These resources contain reviewed non-secret settings, selectors, public keys,
fingerprints, epochs, profile identities/versions/digests, and normalized
socket paths only. They contain no database password, bearer credential,
private signing key, or raw provider data. The sole migration connection
string remains the one exact key in the digest-scoped VaultDynamicSecret.

The two first-owner installation keys are
`RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_PATH` and
`RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST`. They are forbidden in serving,
`verify-only`, development, and test processes. The path must be normalized,
absolute, detached, and end in `.json`; descriptor-pinned traversal must reject
symlinks, require a regular file no larger than 262,144 bytes, and reject
group/other-writable mode bits. The digest must exactly equal the nonzero
lowercase `sha256:<64 lowercase hex>` digest of the file bytes. The Job imports
only those strings. It does not materialize the file or carry an independent
certificate-materialization receipt, so a projected ConfigMap/Secret symlink
does not satisfy the contract. Because final-render admission remains hard-
fenced as unavailable, the runner exits before opening or reading the path.

Each of the nine pin ConfigMap names ends in the same first 12 image-digest hex
characters as the Job. Its metadata carries `ryuki.io/release-digest-prefix` and
`ryuki.io/content-digest`; the content digest is SHA-256 of the canonical,
key-sorted JSON `data` object, and `binaryData` is forbidden. After creating
each immutable ConfigMap, read it back and capture its exact name,
`metadata.uid`, `metadata.resourceVersion`, and content digest. The final Job
carries one closed canonical-JSON receipt
annotation for each ConfigMap with exactly those four fields. The annotation,
rendered reference where applicable, ConfigMap metadata, and API readback must
match exactly. UID and resourceVersion are opaque byte strings, not assumed
UUIDs or decimal counters. These comparisons describe only the objects observed
in one offline snapshot. They do not fence deletion/recreation after validation:
the Job still dereferences names when Kubernetes materializes the Pod.
`immutable: true` prevents mutation of one object but does not prevent deletion
and name reuse. The missing in-cluster admission capability must hold that fence
through Pod materialization for all nine maps.

Kubernetes cannot project a live Unix socket from a ConfigMap or Secret. The
authority deployment mechanism is intentionally external to this repository.
A future independently governed in-cluster admission layer must supply exactly
four reachable authority sockets in the final Pod at the pinned paths. The
production validator accepts neither an inline trust anchor nor a trust-anchor
path selected by the render context. Unit tests may inject an anchor only to
exercise cryptographic parsing. The future admission capability must receive
the authority anchor through an independently provisioned trust channel outside
the render request; a manifest public key is never self-authenticating.

The authority emits a strict canonical root object with exactly `payload` and
`signature`. The payload identifies
`migration-socket-projection-receipt-v1` and
`ryuki-canonical-json-v1`; it binds the approved authority epoch and profile,
positive Unix-second `[notBefore, expiresAt)` validity interval of at most 300
seconds, exact release image and digest prefix, closed socket-contract digest,
all nine live ConfigMap receipts in the contract's annotation order, the exact
four path/authority/key/fingerprint/CSI projections, and the SHA-256 digest of
the canonical rendered Job preimage. The signature object contains only
`algorithm: ed25519` and a canonical padded `signatureBase64`; its
domain-separated, length-framed signature covers the canonical payload. Unknown
fields, duplicate keys, non-canonical encodings, weak keys, or a receipt outside
its interval fail offline validation. That time check is not runtime freshness:
a Pod may start later or continue after expiry unless the runner revalidates
the receipt before database access and while the authorization matters.

The complete canonical envelope is stored as the sole `receipt.json` data key
in an immutable
`platform-socket-projection-receipt-<receipt-digest-hex>` ConfigMap. The suffix
is all 64 lowercase hex characters of the SHA-256 digest of the exact
`receipt.json` bytes. Metadata contains exactly the release digest prefix, the
canonical key-sorted `data`-object content digest, and the independently checked
raw-receipt digest. Within the rendered Job and CSI graph, the final Job carries
that raw digest only in
`ryuki.io/socket-projection-receipt-digest`; CSI attributes must not duplicate
it. The signed Job preimage excludes only that annotation, eliminating a
self-referential digest. The snapshot validator can read and verify this shape,
but it cannot authorize Job creation. A future in-cluster capability would need
to atomically replace every sentinel and change `ryuki.io/render-mode` from
`source-template` to `final-render` while consuming a unique, non-replayable
attempt identity.

The source template does not claim these mounts, remains suspended, and must
never be submitted to Kubernetes. Every `final-render` also fails closed with a
specific runtime-admission-unavailable error, even if all sentinels, signatures,
pins, and socket shapes are valid. A sentinel, missing/mismatched projection,
invalid receipt, unreviewed injected container/volume, or changed closed-
contract digest adds a structural error; none can bypass the unconditional
production containment. Do not create the Job.

## PostgreSQL infrastructure attestation boundary

The production Job imports these nine non-secret pins, key-by-key, from the
independently governed
`platform-postgresql-infrastructure-attestation-pins-<digest-prefix>` ConfigMap:

- `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET`
- `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID`
- `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID`
- `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64`
- `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT`
- `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_MIN_AUTHORITY_EPOCH`
- `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID`
- `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_VERSION`
- `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST`

The group is complete-or-none, mandatory in production, and forbidden in
development/test. Provision its Ed25519 authority, public key, fencing floor,
profile, and Unix-socket projection independently of the release contract,
image, migration credential, database endpoint, and PostgreSQL operator. The
authority private key must never enter the Job. The rendered socket path must
name the pre-provisioned socket owned by that independent authority; the Job
must not create, replace, proxy, or fall back from it. Its socket path and
decoded-public-key fingerprint must each differ from the checkpoint,
deployed-workload, and public-ingress authorities.

The signed response is not sufficient on its own. It must bind a fresh nonce
and exact request digest to the receipt's `durable-postgresql` requirement,
deployment/trust/workload namespace, expected database provider and major
version, exact leaf-certificate-pinned provider route, database-identity digest, and
durable-storage digest. The proof may authorize at most 300 seconds. The runner
establishes one exclusive-CA TLS 1.3 channel, requires its peer leaf-certificate
digest to match the receipt-bound provider route before releasing credentials,
permits only SCRAM-SHA-256 authentication, binds the exporter into the request
tag, and relays only that channel into one direct `PgConnection`. The
authority must independently derive the same exporter at the database endpoint;
echoing a caller-supplied tag is insufficient. Provider identity, cluster
system identity, and storage bindings come from the independently signed
evidence; their typed digests and the local observations must together equal
the receipt exactly.

Immediately before DDL, the runner takes the reviewed bounded session-level
advisory lock on the direct backend and only then begins one repeatable-read
transaction. Its first transactional statement promotes the same key into a
transaction-scoped lock before releasing the session-scoped copy. This ordering
ensures a waiter cannot retain a stale pre-lock ledger/marker snapshot while
migration SQL cannot release the serialization fence. It rechecks proof integrity, freshness, and local SQL
facts; every pending migration and ledger mutation executes in that
transaction, followed by exact ledger readback, ACL verification, and insertion
of one durable operation marker derived from the release, exact attested target,
and final inventory. `COMMIT` is dispatched only while the proof is current. A
stale proof, mismatch, target change, DDL error, postflight mismatch, or deadline
before that dispatch rolls back the whole wave. A timeout or connection error
after dispatch has an unknown outcome: terminating the connection does not
prove rollback. The transaction-scoped lock remains held until PostgreSQL ends
the transaction. There is no automatic
authority or Job retry.

The marker lives in `public.production_migration_operations`. The application
role has read-only access; only the migration role can insert it. If an operator
explicitly starts a fresh one-shot attempt after `CommitOutcomeUnknown`, that
attempt obtains a new nonce-bound infrastructure attestation and checks the
exact deterministic operation id plus the complete embedded inventory before
any migration write. An exact marker converts the attempt into no-write
reconciliation and reports `reconciled_after_prior_attempt=true`. A missing or
mismatched marker never proves rollback and never authorizes blind replay.

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

## Production cutover is blocked

There is no authorized ordered production cutover in this revision. The only
contract sequence is
`stop-production-execution-runtime-admission-unavailable`. Stop before traffic
drain, migration-credential issuance, final-render creation, or any Kubernetes
Job submission.

Production execution may be reconsidered only after one independently reviewed
capability closes all of these boundaries:

1. In-cluster admission uses a trust anchor provisioned outside the render
   request and atomically validates the live Job, receipt, socket projections,
   and all nine ConfigMap identities through Pod materialization.
2. One immutable attempt identity is signed, consumed exactly once, and bound to
   a non-replayable Kubernetes Job identity; a replay cannot create a second
   generated Job.
3. The migration runtime revalidates the signed receipt and trusted time before
   touching its credential or database, and fails closed if authorization
   expires before the protected operation is complete.
4. Tests exercise deletion/recreation races, delayed Pod scheduling, receipt
   replay, and expiry after snapshot validation across the real admission and
   runtime boundary.

The retained signed-envelope, ConfigMap-receipt, socket-projection, SQL
transaction, readback, and recovery material describes the intended future
shape. Passing those offline checks is diagnostic evidence only and must never
be interpreted as permission to execute.

After any future capability is implemented and separately approved, if the
authority exchange, pre-DDL target/storage comparison, Job, or exact
postflight ledger fails or times out, keep the API and workers stopped. Do not
retry the exchange or Job automatically, reconnect to another target, edit
`_sqlx_migrations` or `production_migration_operations`, run down migrations, or
start an older API. For a failure explicitly reported before `COMMIT` dispatch,
confirm rollback through an independently authenticated read path before any
new attempt. For `CommitOutcomeUnknown`, assume neither commit nor rollback:
retain its operation id, read back the marker and exact final inventory, and
allow only an explicitly approved fresh one-shot attempt whose independent
attestation can reconcile that same marker. If no exact marker exists, stop for
manual recovery; do not replay DDL merely because the original connection was
hard-closed.

Local development may continue using the default `local-auto` mode. That
compatibility is not authorization to use the application database role as a
production migrator.
