# Configuration

Ryuki configuration is loaded by the typed Rust `RyukiConfig` contract. Use `.env.example` as the canonical reference for environment variable names and defaults.

## Load Order

Configuration is merged in this order:

1. Environment variables with the `RYUKI_` prefix.
2. A local config file: `ryuki.toml`, `ryuki.json`, or `platform-config.json`.
3. Rust defaults.

Nested fields use `__` in environment variables. For example, `server.bind_address` becomes `RYUKI_SERVER__BIND_ADDRESS`.

`RyukiConfig::load()` does not parse `.env` files by itself. Use `.env` with Docker Compose, export variables into the host process environment, or use one of the supported config files for direct `cargo run` workflows.

## Deployment-security startup admission

Every API and migration process requires these seven values; none has a runtime
default and empty values fail closed:

| Variable | Required value |
|---|---|
| `RYUKI_SECURITY_CONTRACT_ROOT` | Absolute path to the immutable directory containing the profile and all referenced artifacts |
| `RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH` | Normalized relative path beneath that absolute root; absolute paths and traversal are rejected |
| `RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST` | Nonzero `sha256:<64 lowercase hex>` digest computed over the profile's exact raw bytes |
| `RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH` | Normalized relative `.json` path of the current trust-registry lineage head beneath the same immutable root; absolute paths, traversal, and non-JSON paths are rejected |
| `RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST` | Independently supplied, nonzero `sha256:<64 lowercase hex>` digest computed over that head's exact raw bytes |
| `RYUKI_EXPECTED_DEPLOYMENT_ID` | Independent canonical `deployment:` pin that must equal the document's deployment identity |
| `RYUKI_SECURITY_PROFILE` | Independent profile-class pin, exactly `development`, `test`, or `production`, that must equal the document |

Production also requires this independently pinned build-manifest pair:

| Variable | Required value |
|---|---|
| `RYUKI_PRODUCTION_BUILD_MANIFEST_PATH` | Normalized absolute `.json` path detached from the rollbackable security-contract root |
| `RYUKI_PRODUCTION_BUILD_MANIFEST_DIGEST` | Nonzero `sha256:<64 lowercase hex>` digest computed over the manifest's exact raw bytes |

The two variables form one complete binding: setting only one fails closed,
and both are mandatory when `RYUKI_SECURITY_PROFILE=production`. Development
and test deployments must leave both unset. The manifest independently pins the
expected build identity and claims an implementation-applicability inventory.
Startup independently derives that build-side inventory from the authenticated
ControlTrace and measured build facts and requires exact equality. The loader
also retains exact provider descriptors and derives deployment/provider
applicability from authenticated facts. The independently pinned deployed-
workload attestation below supplies the deployed-OCI and executable facts.
Startup now derives the complete implementation-plus-deployment applicability
inventory, verifies the exact semantic receipt closure, and consumes the
checkpoint, current SB-9 root, authenticated documents, pinned profile/build,
and workload proof into one non-cloneable production-boundary proof. Production
serving now retains verified `HttpsPublicUrls`, `SecureCookies`,
`ApprovedSecretProvider`, `NonDevelopmentAuthenticator`, `DurablePostgresql`,
and `FirstOwnerPathClosed` witnesses. It still exits before database
publication, workers, routing, or listeners until exactly two receipt-bound
live runtime guards are implemented and verified:
`external-signing-key-material` and `mock-dependencies-disabled`. The overall
proposed normative production boundary is not complete. In particular, the
closed-state witness does not complete the broader SB-BOOT/AC-023 bootstrap,
ownership-transfer, recovery, and break-glass acceptance program.

Production additionally requires these external checkpoint bindings:

| Variable | Required value |
|---|---|
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_SOCKET` | Absolute, lexically normalized Unix-socket path with a file name, no NUL, and at most 103 path bytes |
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID` | Independently pinned canonical id beginning `conformance-trust-checkpoint-authority:` |
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_KEY_ID` | Independently pinned canonical Ed25519 key id beginning `conformance-trust-checkpoint-key:` |
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64` | Canonical Base64 of exactly 32 raw Ed25519 public-key bytes |
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT` | Nonzero `sha256:<64 lowercase hex>` digest of those decoded public-key bytes |
| `RYUKI_CONFORMANCE_TRUST_CHECKPOINT_MIN_AUTHORITY_EPOCH` | Positive independently held minimum authority fencing epoch |

All six values come from a separately governed workload/deployment trust
channel. They must never be supplied by, inferred from, or stored only beside
the rollbackable contract root, profile, registry, or conformance documents.

Production also requires this independently pinned deployed-workload
attestation binding:

| Variable | Required value |
|---|---|
| `RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_SOCKET` | Absolute, lexically normalized Unix-socket path with a file name, no NUL, and at most 103 path bytes |
| `RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_AUTHORITY_ID` | Independently pinned canonical id beginning `deployed-workload-attestation-authority:` |
| `RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_KEY_ID` | Independently pinned canonical Ed25519 key id beginning `deployed-workload-attestation-key:` |
| `RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_BASE64` | Canonical Base64 of exactly 32 raw Ed25519 public-key bytes |
| `RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT` | Nonzero `sha256:<64 lowercase hex>` digest of those decoded public-key bytes |
| `RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MIN_AUTHORITY_EPOCH` | Canonical positive base-10 independently held minimum authority fencing epoch, at most 9,007,199,254,740,991 |
| `RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_ID` | Independently pinned canonical id beginning `deployed-workload-measurement-profile:` |
| `RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_VERSION` | Canonical positive base-10 independently pinned profile version, at most 9,007,199,254,740,991 |
| `RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_DIGEST` | Independently pinned nonzero `sha256:<64 lowercase hex>` digest of the approved measurement profile |
| `RYUKI_EXPECTED_WORKLOAD_ID` | Independently pinned canonical `workload:` identity expected in the attested namespace |

These ten variables are one complete-or-none binding. Setting any one requires
all the others, and the complete group is mandatory in production alongside
the build-manifest pair and external checkpoint bindings. Development and test
deployments must leave all ten unset. Provision the authority, key,
fingerprint, measurement profile, and expected workload through an independent
deployment trust channel; startup never learns a pin from the contract root,
build manifest, or attestation response.

For each production admission, startup creates a fresh unpredictable 32-byte
nonce, sends it in one bounded request, and computes the digest of the request's
exact canonical bytes. It accepts only a corresponding domain-separated
Ed25519 response that exactly echoes that nonce and digest; matches the pinned
deployment and workload, the checkpoint-bound trust domain, and the pinned
authority, key, epoch floor, and measurement profile; and proves a current,
running, reconciled peer whose deployed OCI subject and executable match the
measured build facts. For an OCI index, the authority-signed child-manifest
resolution must be internally consistent. The short-lived proof remains bound
to that one admission and cannot be replayed or reused as authority for a later
startup.

Production also requires this independently pinned public-ingress attestation
binding:

| Variable | Required value |
|---|---|
| `RYUKI_PUBLIC_INGRESS_ATTESTATION_SOCKET` | Absolute, lexically normalized Unix-socket path with a file name, no NUL, and at most 103 path bytes |
| `RYUKI_PUBLIC_INGRESS_ATTESTATION_AUTHORITY_ID` | Independently pinned canonical id beginning `public-ingress-attestation-authority:` |
| `RYUKI_PUBLIC_INGRESS_ATTESTATION_KEY_ID` | Independently pinned canonical Ed25519 key id beginning `public-ingress-attestation-key:` |
| `RYUKI_PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_BASE64` | Canonical Base64 of exactly 32 raw Ed25519 public-key bytes |
| `RYUKI_PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT` | Nonzero `sha256:<64 lowercase hex>` digest of those decoded public-key bytes |
| `RYUKI_PUBLIC_INGRESS_ATTESTATION_MIN_AUTHORITY_EPOCH` | Canonical positive base-10 independently held minimum authority fencing epoch |
| `RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_ID` | Independently pinned canonical id beginning `ingress-attestation-profile:` |
| `RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_VERSION` | Canonical positive base-10 independently pinned profile version |
| `RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_DIGEST` | Independently pinned nonzero `sha256:<64 lowercase hex>` digest of the approved attestation profile |

These nine variables are complete-or-none, mandatory in production, and
forbidden in development/test. Startup sends exactly one fresh nonce-bound
request without retry and accepts only a short-lived domain-separated Ed25519
response from the pinned authority. The response must measure the exact API and
portal HTTPS origins, authoritative DNS sets, certificate chains, ingress route
generation, and API backend workload/artifact/instance binding selected by the
signed `HttpsPublicUrls` expectation. Because the expected ingress digest is
receipt-bound, its workload-instance binding is a stable provisioned deployment
identity known when that receipt is issued; a newly randomized identity cannot
satisfy a pre-existing receipt.

Production also requires this independently pinned PostgreSQL infrastructure
attestation binding:

| Variable | Required value |
|---|---|
| `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET` | Absolute, lexically normalized Unix-socket path with a file name, no NUL, and at most 103 path bytes |
| `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID` | Independently pinned canonical id beginning `postgresql-infrastructure-attestation-authority:` |
| `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID` | Independently pinned canonical Ed25519 key id beginning `postgresql-infrastructure-attestation-key:` |
| `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64` | Canonical Base64 of exactly 32 raw Ed25519 public-key bytes |
| `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT` | Nonzero `sha256:<64 lowercase hex>` digest of those decoded public-key bytes |
| `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_MIN_AUTHORITY_EPOCH` | Canonical positive base-10 independently held minimum authority fencing epoch, at most 9,007,199,254,740,991 |
| `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID` | Independently pinned canonical id beginning `postgresql-infrastructure-attestation-profile:` |
| `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_VERSION` | Canonical positive base-10 independently pinned profile version, at most 9,007,199,254,740,991 |
| `RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST` | Independently pinned nonzero `sha256:<64 lowercase hex>` digest of the approved attestation profile |

These nine variables are one complete-or-none group. They are mandatory for
every production process and forbidden in development/test. Provision the
authority, public key, epoch floor, profile, and Unix-socket projection through
an independently governed deployment channel; none may be inferred from the
rollbackable contract tree, build manifest, migration credential, connection
URL, PostgreSQL server, or attestation response. The PostgreSQL authority's
socket path and decoded-public-key fingerprint must each differ from the
checkpoint, deployed-workload, and public-ingress authorities.

PostgreSQL infrastructure attestation protocol v2 performs one bounded exchange
without retry for either an explicit `migration` or `application-serving`
session purpose. The purpose is bound with the fresh nonce into the TLS 1.3
exporter context, request tag, canonical request, and domain-separated Ed25519
response. The request also binds the receipt's `durable-postgresql`
requirement, deployment/trust/workload namespace, expected provider and
PostgreSQL major version, exact receipt-bound provider route, database-identity
digest, durable-storage digest, roles, and backend session. The proof
authorization is at most 300 seconds. The authority must independently derive
the same purpose-bound exporter at the database endpoint; an echoed client tag
or local SQL observation is insufficient. Its signed profile and session facts
must remain in exact lockstep with the independently supplied deployment pins
and receipt-bound expectations.

For `migration`, the runner relays the one exclusive-CA, SCRAM-SHA-256 TLS
channel into one direct PgConnection. For `application-serving`, startup
retains that exact channel, its bound loopback relay listener, the exact
application-role backend session, its local durable observation, and the same
SQLx pool.
Production requires `RYUKI_SERVER__POOL_MAX_CONNECTIONS=1` and
`RYUKI_SERVER__POOL_MIN_CONNECTIONS=1`; a wider pool, implicit reconnect,
fallback route, substituted role, or changed observation fails closed. The
pool allocation remains unpublished until the complete eight-guard runtime
admission succeeds, and it is remeasured at the serving startup fences.

Production also requires this independently pinned first-owner closure
authority binding:

| Variable | Required value |
|---|---|
| `RYUKI_FIRST_OWNER_AUTHORITY_ID` | Independently pinned canonical id beginning `first-owner-authority:` |
| `RYUKI_FIRST_OWNER_AUTHORITY_KEY_ID` | Independently pinned canonical Ed25519 key id beginning `first-owner-authority-key:` |
| `RYUKI_FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64` | Canonical Base64 of exactly 32 raw, non-weak Ed25519 public-key bytes |
| `RYUKI_FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT` | Nonzero `sha256:<64 lowercase hex>` digest of those decoded public-key bytes |
| `RYUKI_FIRST_OWNER_AUTHORITY_MIN_EPOCH` | Canonical positive base-10 independently held minimum authority fencing epoch, at most 9,007,199,254,740,991 |

These five variables are one complete-or-none group. They are mandatory for
every production process and forbidden in development/test. Provision them
through the independently governed deployment channel; none may be inferred
from the rollbackable contract tree, build manifest, closure certificate, or
database row. The key fingerprint must be cryptographically distinct from the
checkpoint, deployed-workload, public-ingress, and PostgreSQL-infrastructure
authority keys. There is no first-owner authority socket: the configured key
authenticates the permanent closure certificate stored in PostgreSQL.

Startup measures that certificate in a bounded, read-only, repeatable-read
snapshot through the exact retained `DurablePostgresql` application-serving
runtime. It requires exact canonical JSON with the closed schema. The pinned
authority at or above the epoch floor must strictly verify a signature over the
length-framed domain and exact canonical unsigned certificate after removing
only top-level `signature_base64`. The certificate bytes and digest, every
duplicated database
column, authority namespace and closure-record digests, the exact sorted set of
five privileged-domain assignments, and the linked atomic audit/domain-event
rows must agree with the receipt-bound `FirstOwnerPathClosed` expectation.
Startup retains that same PostgreSQL allocation and repeats the live snapshot
at the applicable pre-database, pre-worker, and final-listener fences; changed
content, channel identity, pool/session allocation, or receipt projection fails
closed.

This witness authenticates permanent closed-state evidence only. It does not
establish that the one-time claim ceremony, concurrent-winner/replay behavior,
ownership transfer, last-owner protection, recovery, or break-glass workflows
required by SB-BOOT and AC-023 are complete.

Production execution is currently contained: `apply-only` exits before reading
the migration credential until live Kubernetes render admission, one-use
attempt consumption, materialized-pin binding, and runtime receipt freshness
are implemented. Offline manifest validation is not execution authority.

Immediately before mutation, the runner acquires the reviewed bounded
session-level advisory lock and only then begins one repeatable-read database
transaction. As the transaction's first statement it acquires the same
transaction-scoped advisory lock, then releases the session-scoped copy. This
preserves a fresh pre-lock snapshot while making the serialization fence
unreleaseable by migration SQL. The runner rechecks proof
integrity/freshness and the local SQL-visible facts, applies every pending
embedded migration, exact-compares the complete resulting ledger, and inserts a
content-addressed non-secret operation marker. It dispatches `COMMIT` only while
the proof remains current and never reconnects or selects another target before
that boundary. Failures before dispatch roll back the wave. A timeout or error
after `COMMIT` was sent is instead `CommitOutcomeUnknown`: closing the
connection is not proof of rollback. Startup never retries automatically; an
explicitly approved fresh attempt must independently attest the target and
reconcile the exact durable marker plus final inventory before it can report
the prior operation complete.

The deployment, profile, and trust-root-registry pins come from process
configuration, not from the documents being admitted. Preflight verifies the
root-owned, immutable, content-addressed root before
migration-mode or database configuration, application configuration, signing
keys, workers, router construction, or listener binding. The sole
configuration-free exception is the read-only `--dump-route-meta` maintenance
mode, which exits without starting runtime services.

The registry path and digest identify the current lineage head, not a
standalone key file. Version 1 has no predecessor; each later version contains
an exact content-addressed reference to version N-1. Preflight walks at most 16
versions back to version 1 and verifies every raw digest, identifier, and
contiguous link. For a production profile, trust-store construction then
verifies every effective-time and policy transition, decoded-key fingerprint,
and terminal tombstone before signature verification. Test and development
profiles construct no signature authority from their structural chain.
Historical snapshots do not become authority from signer-controlled `signed_at`.
After external reconciliation, however, an exact accepted-document record may
authorize a current or historical registry snapshot. An active key must be
valid for the complete trusted acceptance-time interval; a retired key is
accepted only when that complete interval is strictly before its cutoff.
Overlap keys cannot newly sign, and revoked or subsequently revoked keys always
fail closed. An interval that straddles any activation, retirement, revocation,
expiry, or freshness cutoff also fails closed.
Rolling back the profile and both independent head pins together is outside
what a self-contained hash chain can detect. Production therefore requires a
fresh domain-separated Ed25519 response from the separately pinned external
checkpoint authority. The request binds its nonce and digest, exact namespace,
candidate head including locator, validated lineage digest, and a unique sorted
lookup of at most 4,096 complete document digests. The response must prove
`external_strongly_consistent` state, exact equality with the authority's
current head, a current authority epoch/revision and one linearizable sequence
for head and document-acceptance events, trusted-time intervals that do not
straddle a cutoff, and exact accepted-document/signature/signer/registry
bindings. Startup never bootstraps, relocates, or advances checkpoint state;
administrative compare-and-swap and recovery reconciliation remain separate
operator workflows.

Files checked into `catalog/security-contracts/v1` with lifecycle
`implementation_only` are schema/conformance fixtures, not active deployment
authority, and cannot start the API or migration runner. Even a valid sealed
semantic closure, build manifest, and deployed-workload proof cannot start
production until the remaining two receipt-bound live runtime guards are
implemented and verified: `external-signing-key-material` and
`mock-dependencies-disabled`. The proving ground
likewise requires a separately reviewed active
operator bundle and evidence; the repository does not publish or infer a
runnable profile digest.

This admission slice binds authentication to exactly one active provider
configuration. Only a matching mock/static development fixture can currently
pass, and it must use a literal loopback listener and public URL. The provider
schema does not yet project every security-relevant legacy `local` or
`entra-id` runtime value, so those live modes fail closed even under a migration
overlay. Their configuration sections below document implemented runtime
features, not a bypass around startup admission.

## Core Environment Variables

Copy `.env.example` to `.env` for Compose workflows, or export the same variables before running the API directly:

### PostgreSQL connection

| Variable | Description | Default |
|---|---|---|
| `RYUKI_DATABASE_URL` | PostgreSQL connection string | `postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform` |

### Server

| Variable | Description | Default |
|---|---|---|
| `RYUKI_SERVER__BIND_ADDRESS` | API listen address | `127.0.0.1:8080` |
| `RYUKI_SERVER__REQUEST_TIMEOUT_SECS` | Per-request timeout | `30` |
| `RYUKI_SERVER__MAX_BODY_SIZE_BYTES` | Maximum request body size | `10485760` |
| `RYUKI_SERVER__MAX_CONCURRENT_CONNECTIONS` | Connection concurrency limit | `512` |

### Entra ID

| Variable | Description | Default |
|---|---|---|
| `RYUKI_ENTRA_TENANT_ID` | Entra tenant ID | Required for `entra-id` auth |
| `RYUKI_ENTRA_CLIENT_ID` | App registration client ID | Required for `entra-id` auth |
| `RYUKI_ENTRA_AUTHORITY` | OIDC authority URL | `https://login.microsoftonline.com` |
| `RYUKI_ENTRA_REDIRECT_URI` | Browser SSO callback URL, e.g. `https://<host>/api/auth/entra/callback` | Required for the browser sign-in flow; empty leaves bearer-token auth only |
| `RYUKI_ENTRA_JWKS_TTL_SECS` | Cached JWKS lifetime in seconds (`1..=86400`) | `86400` |

Token clock skew is selected by the exact authenticated
`SecurityLimitProfile` referenced by the deployment profile. The retired
`RYUKI_ENTRA_LEEWAY_SECS` input is rejected at startup so an ambient setting
cannot compete with that authority.

Two Entra paths coexist. Bearer-token validation (API callers presenting
`Authorization: Bearer <jwt>`) needs only tenant + client. The browser
sign-in flow (OIDC authorization-code with PKCE, the "Sign in with
Microsoft Entra ID" button) additionally needs `RYUKI_ENTRA_REDIRECT_URI`,
registered as a **Web** redirect to the server-side API/BFF callback. It is not
an SPA redirect: the server exchanges the authorization code and establishes
the browser session. Every Entra-mode launch also requires the runtime-only
`RYUKI_SESSION__CREDENTIAL_HMAC_KEY`, even when it initially uses only bearer
tokens, so browser sessions cannot later start with an unverifiable credential
store. It also requires the separate
`RYUKI_SECURITY__CERTIFICATE_CURSOR_HMAC_KEY`; the two values must not match.
An empty redirect URI keeps the browser button disabled.

Startup rejects a zero or greater-than-one-day Entra JWKS TTL so a successful
generation has a meaningful but bounded retirement deadline. Authenticator
clock skew instead comes from the active `SecurityLimitProfile`: startup
requires the exact referenced TTL row to be active, enforced, integral,
applicable, inside its authenticated hard bounds, and equal to the selected
authenticator binding. A legacy ambient leeway setting is rejected rather than
kept as dormant competing authority.

### Generic OIDC (reserved single-provider inputs)

The configuration schema still retains the original single-provider generic
OIDC inputs, but the current runtime does not yet have an authenticated D/P/Q/R
authority for that path. `RYUKI_OIDC__ENABLED=true` is therefore rejected at
startup in every authentication mode, before the listener binds. Keep it false;
the login and callback routes are unavailable until the governed provider
registry can publish and retain the exact runtime authority.

| Variable | Description | Default |
|---|---|---|
| `RYUKI_OIDC__ISSUER` | Exact trusted issuer | Empty; required when enabled |
| `RYUKI_OIDC__AUTHORIZE_ENDPOINT` | Authorization endpoint | Empty; required when enabled |
| `RYUKI_OIDC__TOKEN_ENDPOINT` | Token endpoint | Empty; required when enabled |
| `RYUKI_OIDC__JWKS_URI` | Signing-key endpoint | Empty; required when enabled |
| `RYUKI_OIDC__CLIENT_ID` | Confidential client identifier | Empty; required when enabled |
| `RYUKI_OIDC__CLIENT_SECRET` | Runtime-injected confidential client secret | Empty; required when enabled |
| `RYUKI_OIDC__REDIRECT_URI` | Exact Web callback ending at `/api/auth/oidc/callback` | Empty; required when enabled |
| `RYUKI_OIDC__SCOPES` | Requested scopes as a JSON string array | `["openid","profile","email"]` |
| `RYUKI_OIDC__ROLES_CLAIM` | ID-token claim containing platform role values | `roles` |

The remaining fields are compatibility placeholders, not a launch contract.
When this path is implemented, issuer, authorization, token, JWKS, redirect,
client-authentication, cache, state, and derived-session behavior must all be
measured into one exact retained authority before these inputs can be enabled.
There is no development fallback that fabricates or borrows an Entra origin.

### Vault Kubernetes workload-authenticated resolver

Production HashiCorp Vault resolution uses a typed provider-qualified
`SecretRef` and one process-lifetime workload-authenticated runtime. It does not
use a process-wide static Vault token. Startup constructs that runtime, performs
the initial Kubernetes authentication and provider confirmation, independently
composes the singleton approved-provider D/P/R/I witness, and retains the exact
runtime and typed consumer allocations. One supervised maintenance task renews
or re-authenticates the lease through graceful HTTP drain. `/ready` fails when
the workload runtime, lease confirmation, generation fence, or typed resolver
owner is not current.

Configure exactly these twelve non-secret variables as one closed group. Every
field is required in production. In development and test, either supply all
twelve or none. Partial groups, blank or non-canonical values, and any unknown
name beginning `RYUKI_SECRET_PROVIDER_RUNTIME__` fail before CA, projected-JWT,
or provider I/O.

| Variable | Required value |
|---|---|
| `RYUKI_SECRET_PROVIDER_RUNTIME__PROVIDER_ID` | Canonical `provider:` id equal to the admitted active provider, for example `provider:hashicorp-vault-primary` |
| `RYUKI_SECRET_PROVIDER_RUNTIME__CONFIGURATION_VERSION` | Canonical positive base-10 version equal to the admitted provider configuration |
| `RYUKI_SECRET_PROVIDER_RUNTIME__API_FLAVOR` | Exactly `hashicorp-vault-v1`; the OpenBao identity remains separately cataloged and is not aliased to this runtime |
| `RYUKI_SECRET_PROVIDER_RUNTIME__ENDPOINT` | Normalized absolute HTTPS Vault base URL, without userinfo, query, fragment, escapes, or path traversal |
| `RYUKI_SECRET_PROVIDER_RUNTIME__CA_BUNDLE_PATH` | Exactly `/var/run/secrets/ryuki/vault-tls/ca.crt` |
| `RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_AUTH_MOUNT` | Exactly `kubernetes` |
| `RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_ROLE` | Exact admitted Vault Kubernetes role, for example `ryuki-platform-api` |
| `RYUKI_SECRET_PROVIDER_RUNTIME__KUBERNETES_AUDIENCE` | Exactly `vault` |
| `RYUKI_SECRET_PROVIDER_RUNTIME__PROJECTED_TOKEN_PATH` | Exactly `/var/run/secrets/ryuki/vault-auth/token` |
| `RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_SERVICE_ACCOUNT_NAMESPACE` | Exact Kubernetes workload namespace, for example `ryuki-platform` |
| `RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_SERVICE_ACCOUNT_NAME` | Exact Kubernetes ServiceAccount, for example `platform-api` |
| `RYUKI_SECRET_PROVIDER_RUNTIME__EXPECTED_TOKEN_POLICY` | Exact least-privilege Vault policy; `default` and `root` are rejected |

The Kubernetes Deployment disables default ServiceAccount-token automount and
projects one 600-second token with the singleton `vault` audience at
`/var/run/secrets/ryuki/vault-auth/token`. It mounts only the approved Vault CA
chain, read-only, at `/var/run/secrets/ryuki/vault-tls/ca.crt`. Both projections
use mode `0440` under `fsGroup: 10001`. The Vault client requires HTTPS and the
projected CA, follows no redirects, uses no ambient proxy or built-in trust
roots, bounds connection and request time, and bounds every response before
parsing. Login and lookup must confirm the expected namespace, ServiceAccount,
audience, role, policy, renewable service token, and finite TTL before secret
reads become ready.

#### Secret-reference fingerprint keyring

The HMAC authority for value-free `SecretRef` fingerprints is deliberately
separate from workload authentication, provider bearer material, session keys,
and credential-encryption keys. Production requires:

```text
RYUKI_SECRET_REFERENCE_FINGERPRINT_KEYRING_PATH=/var/run/secrets/ryuki/secret-reference-fingerprint/keyring
```

The selector cannot redirect the runtime to another path. Its canonical target
must be a regular UTF-8 file inside the fixed parent directory. This accepts
the contained symlink layout used by Kubernetes projected Secret volumes while
rejecting any symlink that escapes that directory. The file is nonempty and at
most 32 KiB, containing one to eight records. Each line is at most 512 bytes
and has exactly this form:

```text
key:<id>=<canonical padded standard Base64>
```

The complete unique key identifier starts with `key:`, is at most 256 bytes,
has a nonempty suffix, and contains only ASCII letters, digits, `:`, `.`, `_`,
`-`, and `/`. Material must decode to 32–128 bytes and re-encode byte-for-byte
to the supplied canonical padded standard Base64. Whitespace, blank lines,
comments, duplicate IDs, escaping symlinks, and extra records fail closed.

Rotate with overlap: add a fresh successor record while retaining every key ID
still named by persisted `SecretRef` values; update the operator-owned Secret;
restart the `Recreate` API Deployment; then create or rewrite references with
the successor. Remove a predecessor only after an independent readback proves
that no stored reference names it, then update the Secret and restart again.
Never relabel an existing ID or reuse its material.

#### Local dry-run compatibility only

`VAULT_ADDR`, `VAULT_TOKEN`, and
`RYUKI_VAULT_ALLOW_INSECURE_LOOPBACK` belong only to the legacy local dry-run
adapter and its `<mount>/<path>[#<field>]` handles. They are not production
fallbacks. Production rejects their ambient presence—even an empty value—before
reading the CA, projected JWT, or contacting Vault. It also rejects ambient
`VAULT_TOKEN_FILE`, `VAULT_CACERT`, `VAULT_NAMESPACE`, `VAULT_SKIP_VERIFY`,
`VAULT_CLIENT_CERT`, and `VAULT_CLIENT_KEY`.

For an explicit local dry-run, `VAULT_ADDR` and `VAULT_TOKEN` remain all-or-none
and the cleartext exception admits only an IP-literal loopback endpoint. Both
the platform auth mode (`mock-dry-run` or `static-dry-run`) and the individual
connection mode (`static-dry-run`) must admit mock resolution; a live connection
never falls back to it. A missing or unimplemented provider fails readiness or
the dependent operation instead of selecting another adapter. See the
[secret-management provider contract](architecture/platform-security-boundary.md#pluggable-secret-management-providers).

`RYUKI_INTEGRATION__ENCRYPTION_KEY` remains a separate 32-byte base64/hex
envelope key for legacy persisted inline credentials. It is not a Vault
workload-authentication or `SecretRef` fingerprint key.

### Platform

| Variable | Description | Default |
|---|---|---|
| `RYUKI_PLATFORM_NAME` | Display name for the platform | `Ryuki Infrastructure Platform` |
| `RYUKI_PLATFORM_URL` | Public base URL for the API | `http://localhost:18080` |
| `RYUKI_AUTH_MODE`     | `mock-dry-run`, `static-dry-run`, `entra-id`, or `local` | `mock-dry-run` |

The four primary modes above describe the current selectable implementation.
The retained generic-OIDC inputs are rejected until the production target—a
provider registry with one or more generic OpenID Connect issuers—can bind an
exact runtime authority. That target also includes an
optional OIDC identity broker for SAML/LDAP/AD, a WebAuthn-based emergency
provider, scoped service credentials, and workload identity. Entra ID remains a
supported OIDC configuration rather than the only production identity source.
The current `local` mode uses password-backed sessions and is a development or
migration facility, not the production emergency-authentication target.
See the
[Platform Security Boundary Specification](architecture/platform-security-boundary.md#pluggable-authentication-providers).

### Interactive human authority assignments

Authentication proves a provider-qualified identity; it does not grant Ryuki
roles or resource reach. Every interactive local, generic OIDC, Entra, and
future brokered SAML/LDAP or passkey principal requires a durable assignment
keyed by the stable `(provider, canonical issuer, provider subject)` tuple.
Assignments carry a monotonic version, an explicit `unknown`, `active`, or
`revoked` state, a server-owned role allowlist, and independent site and
environment modes. An active axis is either explicitly `global` with no values
or `scoped` with a nonempty canonical list. Unknown, revoked, malformed, and
empty scoped assignments fail closed.

Provider claims are intersected with this assignment at browser-session
creation and on every direct-bearer admission. Persisted sessions capture the
exact assignment version and effective role/site/environment intersection;
assignment changes or revocation synchronously delete matching sessions. The
short process-local admission cache stores only a one-way authority-key
fingerprint plus the active assignment version and is never authentication
evidence without the database join.

For `RYUKI_AUTH_MODE=local`, the startup-owned assignment applies to every
configured local user and must be explicit:

| Variable | Values | Requirement |
|---|---|---|
| `RYUKI_LOCAL_AUTH__SITE_AUTHORITY` | `global` or `scoped` | Required with populated local users; omitted/`unknown` fails startup. |
| `RYUKI_LOCAL_AUTH__SITE_SCOPE` | Comma-separated canonical site ids | Empty only for explicit `global`; nonempty for `scoped`. |
| `RYUKI_LOCAL_AUTH__ENVIRONMENT_AUTHORITY` | `global` or `scoped` | Required with populated local users; omitted/`unknown` fails startup. |
| `RYUKI_LOCAL_AUTH__ENVIRONMENT_SCOPE` | Comma-separated canonical environment ids | Empty only for explicit `global`; nonempty for `scoped`. |

Federated assignments are deliberately not bootstrapped from token roles,
groups, email, or display name. Migration 182 quarantines existing identities
as Unknown. A governed assignment source must provision and read back the
provider-qualified row before sign-in can succeed. Live IdP claim/group
assignment and readback remain operator-owned trusted-access verification.

Current mock, static-admin, in-memory, and no-database branches exist so isolated
development and migration tests remain operable. They are not production
degraded modes. The target production profile requires durable PostgreSQL, an
approved secret store, and a non-development authenticator; a missing dependency
fails startup, readiness, or the dependent operation without activating a
privileged fallback. See
[configuration and deployment profiles](architecture/platform-security-boundary.md#configuration-and-deployment-profiles).

## Infrastructure Providers

Provider settings are typed enums. They select the intended platform integration, but adapters remain mock/static/dry-run unless a live integration is explicitly approved and implemented.

| Variable | Values | Default |
|---|---|---|
| `RYUKI_DATABASE_PROVIDER` | `cloudnativepg`, `postgres-local`, `aws-rds`, `azure-postgresql`, `gcp-cloud-sql` | `cloudnativepg` |
| `RYUKI_SECRET_PROVIDER` | `hashicorp-vault`, `aws-secrets-manager`, `azure-key-vault`, `gcp-secret-manager`, `bitwarden-secrets-manager`, `none` | `hashicorp-vault` |
| `RYUKI_KUBERNETES_RUNTIME` | `vsphere-vks`, `docker-compose`, `aks`, `eks`, `gke`, `openshift`, `rancher`, `none` | `vsphere-vks` |
| `RYUKI_HYPERVISOR_PROVIDER` | `vmware`, `hyperv`, `proxmox`, `nutanix-ahv`, `xen`, `kvm`, `none` | `vmware` |
| `RYUKI_MONITORING_PROVIDER` | `zabbix`, `prometheus`, `datadog`, `grafana`, `solarwinds`, `none` | `zabbix` |
| `RYUKI_BACKUP_PROVIDER` | `veeam`, `commvault`, `rubrik`, `cohesity`, `netbackup`, `none` | `veeam` |
| `RYUKI_STORAGE_PROVIDER` | `netapp`, `pure-storage`, `dell-powerstore`, `hpe-alletra`, `azure-blob`, `none` | `none` |
| `RYUKI_DNS_PROVIDER` | `infoblox`, `bluecat`, `windows-dns`, `route53`, `none` | `none` |
| `RYUKI_IPAM_PROVIDER` | `infoblox`, `phpipam`, `netbox`, `none` | `none` |
| `RYUKI_LOAD_BALANCER_PROVIDER` | `f5-bigip`, `citrix-adc`, `haproxy`, `nginx`, `none` | `none` |
| `RYUKI_FIREWALL_PROVIDER` | `palo-alto`, `checkpoint`, `fortinet`, `cisco-asa`, `none` | `none` |
| `RYUKI_BUILD_PROVIDER` | `jenkins`, `github-actions`, `azure-devops`, `argocd`, `none` | `none` |
| `RYUKI_NETWORK_PROVIDER` | `cisco-aci`, `vmware-nsx`, `evpn`, `none` | `none` |

## Nested Configuration Groups

Most operational settings are grouped under typed nested structs. Use double underscores when setting these through the environment.

| Group | Example variable | Purpose |
|---|---|---|
| `server` | `RYUKI_SERVER__POOL_MAX_CONNECTIONS` | Bind address, timeouts, body size, TLS paths, DB pool, compression, keep-alive, concurrency. Production's purpose-bound PostgreSQL serving runtime requires both pool maximum and minimum to equal 1. |
| `cors` | `RYUKI_CORS__ALLOWED_ORIGINS` | Allowed origins and cache age. |
| `rate_limit` | `RYUKI_RATE_LIMIT__ENABLED` | Global and per-path request limits. |
| `logging` | `RYUKI_LOGGING__LEVEL` | Console log level and format. |
| `log_extended` | `RYUKI_LOG_EXTENDED__FILE_PATH` | Optional file logging and retention. |
| `security` | `RYUKI_SECURITY__CERTIFICATE_CURSOR_HMAC_KEY` | CSP, optional HSTS, and the dedicated certificate-pagination cursor MAC key. |
| `smtp` | `RYUKI_SMTP__ENABLED` | Email notification transport. |
| `session` | `RYUKI_SESSION__CREDENTIAL_HMAC_KEY` | Dedicated persisted-session verifier key plus cookie security settings. |
| `retention` | `RYUKI_RETENTION__DAILY_BACKUPS` | Backup retention windows. |
| `maintenance_window` | `RYUKI_MAINTENANCE_WINDOW__ENABLED` | Scheduled maintenance window metadata. |

### Certificate-pagination cursor key

`RYUKI_SECURITY__CERTIFICATE_CURSOR_HMAC_KEY` is required before the listener
binds for Local and Entra authentication. An admitted future generic-OIDC path
will require it as well.
Supply at least 32 random bytes through the selected secret manager or an
equivalent runtime-only injection. The value is excluded from serialized
configuration and redacted from `Debug` output. It must be distinct from
`RYUKI_SESSION__CREDENTIAL_HMAC_KEY`; startup rejects key reuse across these
purposes. Rotation invalidates outstanding certificate inventory and expiry
continuations, so clients must restart pagination with no cursor.

Only explicit credential-free `mock-dry-run` and `static-dry-run` modes may omit
this setting. Those modes are already restricted to literal loopback listeners
and origins, and use one process-ephemeral CSPRNG key; their cursors do not
survive a restart. The reserved generic-OIDC enable flag is rejected rather
than activating that development fallback.

### Browser-session security limits

The authenticated security-limit contract owns and reconciles the runtime
values used by an admitted browser authenticator. Environment settings cannot
override the selected limit profile: startup requires their admitted values to
match the exact resolved limits.

| Runtime limit | Required value |
|---|---|
| Browser/local session and cookie maximum age (`RYUKI_SESSION__COOKIE_MAX_AGE_SECS`) | `1..=86400` seconds; default `86400` |
| Federated-authority staleness (`RYUKI_SESSION__FEDERATED_AUTHORITY_MAX_STALENESS_SECS`) | `1..=3600` seconds; default `900`, and never greater than the session/cookie maximum age |
| Browser authorization-state lifetime | Exactly `600` seconds; selected through the security-limit profile, enforced from database-owned time, and not caller-configurable |

Any profile/runtime disagreement fails closed. In particular, there is no
environment variable or callback parameter that can extend the browser-state
lifetime beyond the database-owned 600-second contract.

### Persisted-session verifier key

`RYUKI_SESSION__CREDENTIAL_HMAC_KEY` is required before the listener binds
whenever Local or Entra sessions can be minted; a future admitted generic-OIDC
path will require it too. Supply at least
32 random bytes through the selected secret manager or an equivalent
runtime-only secret injection; do not put the value in a committed TOML, JSON,
Compose, or Kubernetes manifest. The API stores only an HMAC-SHA256 verifier of
each 256-bit `rys_...` session token. The administrative session UUID is
unrelated metadata and cannot authenticate. The verifier key must not equal
`RYUKI_SECURITY__CERTIFICATE_CURSOR_HMAC_KEY`; startup rejects shared key
material so session verification and cursor authentication remain separate
cryptographic purposes.

`RYUKI_SESSION__FEDERATED_AUTHORITY_MAX_STALENESS_SECS` bounds how long a
persisted non-local session may authorize without a fresh validated assertion
or trusted lifecycle heartbeat. It must remain within `1..=3600` seconds and
cannot exceed `RYUKI_SESSION__COOKIE_MAX_AGE_SECS`. Expiry at this bound fails
closed and requires fresh identity evidence; it does not claim that an IdP
lifecycle connector delivered an event.

`RYUKI_SESSION__COOKIE_SECURE=false` is admitted only when
`RYUKI_PLATFORM_URL` is plain HTTP on a literal loopback host (`localhost`, a
`127.0.0.0/8` address, or `[::1]`). HTTPS and non-loopback public origins fail
startup unless Secure cookies remain enabled. This rule is derived from the
external platform URL rather than the API listener address, so TLS-terminating
reverse proxies and loopback-published container bridges keep the intended
policy. Entra browser callbacks must also use a loopback-HTTP redirect before
non-Secure cookie mode is admitted. The same rule is reserved for a future
admitted generic-OIDC callback.

This release supports one active verifier key. Changing it deliberately
invalidates all current bearers, so stale rows simply expire or are swept and
users sign in again. Zero-downtime key rotation requires the planned
versioned key-id/keyring extension; do not attempt overlap by retaining the old
UUID-as-bearer behavior.

### Secret-manager target architecture

The current control-plane resolver supports Vault and a development mock; the
provider enum lists additional intended platforms. The normative target is a
capability-based adapter registry for HashiCorp Vault, OpenBao, Azure Key Vault,
AWS Secrets Manager, Google Secret Manager, CyberArk, 1Password Connect,
Bitwarden Secrets Manager, and future approved plugins. CSI, External Secrets
Operator, and Vault Secrets Operator are modeled separately as materialization
controllers rather than being credited with lease-aware resolution capabilities.
Production adapters authenticate with managed/workload identity and report their
real versioning, lease, renewal, revocation, wrapping, PKI, and rotation
capabilities. Unsupported required capabilities fail closed.

See the
[secret-management provider contract](architecture/platform-security-boundary.md#pluggable-secret-management-providers).

## Validation

`RyukiConfig::validate()` returns hard errors that should block startup or mark config invalid. `RyukiConfig::validation_warnings()` returns advisory operational guidance, such as reminding operators to configure Vault externally when `RYUKI_SECRET_PROVIDER=hashicorp-vault`.

## Entra ID App Registration

See `docs/entra-app-registration.md` for the full app roles manifest and setup instructions.

### Summary

1. Register a new app in Entra admin center
2. Define app roles in the manifest (PlatformAdmin, DatacenterApprover, etc.)
3. Expose the API with a scope for the portal
4. Assign users/groups to roles in the Enterprise application blade
5. Set `RYUKI_ENTRA_TENANT_ID`, `RYUKI_ENTRA_CLIENT_ID`, and `RYUKI_AUTH_MODE=entra-id`

### Required Entra Configuration

- **App roles**: Defined in the manifest (see `docs/entra-app-registration.md`)
- **Redirect URI**: Web/server-side callback, for example `https://<host>/api/auth/entra/callback`; do not register the portal as an SPA token recipient
- **Token configuration**: Access tokens must include the `roles` claim
- **API permissions**: No delegated permissions required — app roles only

## PostgreSQL

The platform expects PostgreSQL 18. The local compose skeleton in `deploy/compose/compose.yaml` provisions:

- PostgreSQL 18 with user `ryuki` and database `ryuki_platform`
- Port `5432` exposed locally

For production, use CloudNativePG or a managed PostgreSQL service and set
`RYUKI_DATABASE_URL` accordingly. The currently implemented purpose-bound
serving channel is intentionally single-channel: set
`RYUKI_SERVER__POOL_MAX_CONNECTIONS=1` and
`RYUKI_SERVER__POOL_MIN_CONNECTIONS=1` or `DurablePostgresql` admission fails.

### Why PostgreSQL only

PostgreSQL is the **only** supported database — there is no MySQL, SQLite, or other backend, and there are no plans to add one. While the platform is built on `sqlx`, the schema and persistence layer depend on PostgreSQL-specific features that have no portable equivalent:

- **`xmin`-based optimistic concurrency.** Read-modify-write mutations guard against lost updates with `WHERE id = $1 AND xmin = $N::xid`. `xmin` is a PostgreSQL system column; MySQL and SQLite have no equivalent.
- **`JSONB`** columns and operators (`to_jsonb`, `jsonb_set`, `jsonb_array_elements`) store full entity snapshots and audit history.
- **`RETURNING`**, `ON CONFLICT` upserts, `gen_random_uuid()`, partial/`FILTER` aggregates, and `TIMESTAMPTZ` interval arithmetic are used throughout the migrations and queries.

`RYUKI_DATABASE_PROVIDER` selects the PostgreSQL *deployment* (CloudNativePG, a local container, AWS RDS, Azure Database for PostgreSQL, or GCP Cloud SQL) — every option is PostgreSQL.

## Admin Portal

`RYUKI_PORTAL_EXECUTION_MODE` is mandatory and accepts exactly
`live-provider` or `static-dry-run`. External public origins must select
`live-provider`; `static-dry-run` is a preview-only mode accepted only when
`RYUKI_PORTAL_PUBLIC_ORIGIN` is explicitly loopback. A missing, blank, unknown,
or legacy `external-static` value fails portal startup instead of selecting
synthetic data implicitly.

### Logo and Branding

The platform name is configured via `RYUKI_PLATFORM_NAME`. Logo and branding assets are uploaded through the admin portal UI after deployment; no branding files are stored in the repository.

### Access Control

In the current `entra-id` mode, access is controlled by Entra app-role values
and `PlatformAdmin` grants full administrative access to the portal. This is a
transitional provider-specific mapping. The production target accepts verified
claims from any configured provider, normalizes them into one principal, and
authorizes typed actions at the platform boundary.
