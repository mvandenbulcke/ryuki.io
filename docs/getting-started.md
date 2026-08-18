# Getting Started

## Prerequisites

- Rust 1.85+ (edition 2024)
- `cargo-leptos` and the `wasm32-unknown-unknown` Rust target
- Docker and Docker Compose
- PostgreSQL 18+

Install the portal build tooling once:

```bash
rustup target add wasm32-unknown-unknown
cargo install cargo-leptos --locked
```

## Quick Start

### 1. Clone and set up

```bash
git clone https://github.com/mvandenbulcke/ryuki.io.git ryuki-platform
cd ryuki-platform
cp .env.example .env
```

For Docker Compose workflows, edit `.env` and set `RYUKI_DATABASE_URL` to match your local PostgreSQL. For direct `cargo run`, export the needed `RYUKI_` variables or create `ryuki.toml`, `ryuki.json`, or `platform-config.json`; `.env` is not loaded automatically by the Rust config loader.

### 2. Start the database

```bash
docker compose -f deploy/compose/compose.yaml up -d platform-db
```

### 3. Build the workspace

```bash
cargo build --workspace
```

### 4. Admit and run the API server on port 8081

The Rust config loader does not read `.env` itself. Export
`RYUKI_DATABASE_URL` in this shell without committing its value, then pass the
bind address explicitly so the portal can use its default port `8080`. Pass
additional authentication settings explicitly or through a supported Ryuki
config file rather than sourcing `.env` as shell code:

Before running, supply a reviewed active contract and independently approved
trust-root registry through all seven mandatory
inputs: `RYUKI_SECURITY_CONTRACT_ROOT`,
`RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH`,
`RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST`,
`RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH`,
`RYUKI_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST`, `RYUKI_EXPECTED_DEPLOYMENT_ID`,
and `RYUKI_SECURITY_PROFILE`. Both paths are normalized `.json` paths relative
to the absolute, immutable root; both digests are nonzero
`sha256:<64 lowercase hex>` values over the respective exact raw bytes; and the
deployment identity and profile class remain independent pins. See
[Deployment-security startup admission](configuration.md#deployment-security-startup-admission).
The selected registry is the head of a bounded, exact N-1 predecessor chain;
all referenced registry versions must be present as regular `.json` files
beneath the same immutable contract root. A valid chain alone cannot prevent
rollback of the profile and head pins as one unit, and production therefore
also requires `RYUKI_PRODUCTION_BUILD_MANIFEST_PATH` and
`RYUKI_PRODUCTION_BUILD_MANIFEST_DIGEST` as a complete-or-none pair. The path
must be a normalized absolute `.json` path detached from the rollbackable
contract root, and the digest must be a nonzero `sha256:<64 lowercase hex>`
value over the manifest's exact raw bytes. Production also requires
`RYUKI_CONFORMANCE_TRUST_CHECKPOINT_SOCKET`,
`RYUKI_CONFORMANCE_TRUST_CHECKPOINT_AUTHORITY_ID`,
`RYUKI_CONFORMANCE_TRUST_CHECKPOINT_KEY_ID`,
`RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_BASE64`,
`RYUKI_CONFORMANCE_TRUST_CHECKPOINT_PUBLIC_KEY_FINGERPRINT`, and
`RYUKI_CONFORMANCE_TRUST_CHECKPOINT_MIN_AUTHORITY_EPOCH`. Provision them from a
separately governed workload/deployment trust channel, never from the
rollbackable contract root. Startup only reconciles exact head version, raw
digest, and locator; it cannot bootstrap or auto-advance authority state.
Production also requires the complete deployed-workload attestation binding:
`RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_SOCKET`,
`RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_AUTHORITY_ID`,
`RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_KEY_ID`,
`RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_BASE64`,
`RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_PUBLIC_KEY_FINGERPRINT`,
`RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MIN_AUTHORITY_EPOCH`,
`RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_ID`,
`RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_VERSION`,
`RYUKI_DEPLOYED_WORKLOAD_ATTESTATION_MEASUREMENT_PROFILE_DIGEST`, and
`RYUKI_EXPECTED_WORKLOAD_ID`. These ten independently pinned values are
complete-or-none and mandatory alongside the build-manifest and checkpoint
bindings; development and test must leave all ten unset. Startup sends one
request containing a fresh nonce to the pinned Unix-socket authority, computes
the digest of the exact canonical request bytes, and accepts only a short-lived
Ed25519 response that echoes both values, so the proof cannot be replayed as a
later admission.
Production also requires the complete nine-value public-ingress binding:
`RYUKI_PUBLIC_INGRESS_ATTESTATION_SOCKET`,
`RYUKI_PUBLIC_INGRESS_ATTESTATION_AUTHORITY_ID`,
`RYUKI_PUBLIC_INGRESS_ATTESTATION_KEY_ID`,
`RYUKI_PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_BASE64`,
`RYUKI_PUBLIC_INGRESS_ATTESTATION_PUBLIC_KEY_FINGERPRINT`,
`RYUKI_PUBLIC_INGRESS_ATTESTATION_MIN_AUTHORITY_EPOCH`,
`RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_ID`,
`RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_VERSION`, and
`RYUKI_PUBLIC_INGRESS_ATTESTATION_PROFILE_DIGEST`. These independently pinned
production-only values select one external Ed25519 authority and approved
measurement profile. HTTP startup performs one fresh nonce-bound, no-retry
exchange and accepts only a short-lived observation of the receipt-bound HTTPS
origins, DNS/TLS state, ingress generation, and exact API backend workload.
The receipt therefore precommits a stable provisioned workload-instance
binding; it cannot be satisfied by a newly randomized identity.
Every production process additionally requires the complete, production-only
PostgreSQL infrastructure attestation group:
`RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_SOCKET`,
`RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_AUTHORITY_ID`,
`RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_KEY_ID`,
`RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_BASE64`,
`RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PUBLIC_KEY_FINGERPRINT`,
`RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_MIN_AUTHORITY_EPOCH`,
`RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_ID`,
`RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_VERSION`, and
`RYUKI_POSTGRESQL_INFRASTRUCTURE_ATTESTATION_PROFILE_DIGEST`. The nine values
are complete-or-none and must be independently provisioned; development and
test must leave them unset. The PostgreSQL socket and decoded-key fingerprint
must differ from the checkpoint, workload, and ingress authorities. PostgreSQL
infrastructure attestation v2 performs one fresh nonce-bound, no-retry Ed25519
exchange with an authorization ceiling of 300 seconds. It binds an explicit
`migration` or `application-serving` purpose alongside the fresh nonce in the
TLS 1.3 exporter context,
request tag, canonical request, and signed response. The independent authority
must derive the same purpose-bound exporter at the database endpoint and keep
its signed profile, route, identities, roles, and backend session in exact
lockstep with the deployment pins and receipt-bound expectation; an echoed
client tag is insufficient. Apply-only relays its measured channel into one
direct PgConnection. Serving retains the exact channel, its bound loopback
relay listener,
application-role session, and SQLx pool and therefore requires
`RYUKI_SERVER__POOL_MAX_CONNECTIONS=1` and
`RYUKI_SERVER__POOL_MIN_CONNECTIONS=1`; reconnect, fallback, or a wider pool
fails closed. After exact receipt matching, pre-DDL recheck, every pending
migration, exact ledger postflight, and the durable operation marker run in one
transaction. A pre-COMMIT failure rolls back; a lost COMMIT acknowledgement is
`CommitOutcomeUnknown` and needs a fresh independently attested reconciliation
run.
Every production process also requires the complete five-value first-owner
authority group: `RYUKI_FIRST_OWNER_AUTHORITY_ID`,
`RYUKI_FIRST_OWNER_AUTHORITY_KEY_ID`,
`RYUKI_FIRST_OWNER_AUTHORITY_PUBLIC_KEY_BASE64`,
`RYUKI_FIRST_OWNER_AUTHORITY_PUBLIC_KEY_FINGERPRINT`, and
`RYUKI_FIRST_OWNER_AUTHORITY_MIN_EPOCH`. The values are complete-or-none,
production-only, and independently provisioned; the ids begin
`first-owner-authority:` and `first-owner-authority-key:`, the key is canonical
Base64 for exactly 32 raw, non-weak Ed25519 bytes, its fingerprint is the
matching nonzero SHA-256 digest and is distinct from all four other authority
keys, and the epoch is a canonical positive integer. There is no first-owner
socket: startup uses the pinned key to authenticate the permanent closure
certificate read through the exact retained PostgreSQL serving runtime.
The one-shot production `apply-only` process additionally requires the exact
complete-or-none pair `RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_PATH` and
`RYUKI_FIRST_OWNER_CLOSURE_CERTIFICATE_DIGEST`. The path must be a normalized
absolute detached `.json` path traversed without symlinks to a regular file no
larger than 262,144 bytes and not group/other writable. The digest must be the
exact nonzero lowercase `sha256:<64 lowercase hex>` digest of those file bytes.
Both variables are forbidden in serving, `verify-only`, development, and test
processes. The checked-in Job imports only these two strings; it has no
certificate materializer or materialization receipt, and every production
final render remains rejected. While that hard fence is false, `apply-only`
exits before it opens or reads the configured certificate path.
Production execution remains disabled before credential loading until live
Kubernetes render admission, one-use attempt consumption, materialized-pin
binding, and runtime receipt freshness are implemented.
The build manifest pins expected build identity and claims an implementation-
applicability inventory; startup independently derives that build-side
inventory from the authenticated ControlTrace and measured build facts and
requires exact equality. The workload response independently proves the exact
deployed OCI subject and executable; for an OCI index, the authority-signed
child-manifest resolution must also be internally consistent. Startup now
derives the complete implementation-plus-deployment applicability inventory,
verifies exact semantic closure, and consumes the checkpoint, current SB-9
root, authenticated documents, pinned profile/build, and workload proof into
one non-cloneable production-boundary proof. Serving startup now retains six
verified witnesses: `HttpsPublicUrls`, `SecureCookies`,
`ApprovedSecretProvider`, `NonDevelopmentAuthenticator`, `DurablePostgresql`,
and `FirstOwnerPathClosed`. The last witness requires the pinned authority to
strictly verify the length-framed domain and exact canonical unsigned
certificate after removing only top-level `signature_base64`, plus exact
database columns and five privileged-domain assignments, linked atomic
audit/domain-event evidence, receipt-bound namespace/closure digests, and exact
remeasurement through the same PostgreSQL allocation at the applicable serving
fences. The measured pool remains unpublished, and startup still exits before
database publication, workers, routing, or listeners until the complete
eight-guard admission. Exactly two receipt-bound live runtime guards remain:
`external-signing-key-material` and `mock-dependencies-disabled`. The overall
proposed normative production boundary is not complete. The closed-state
witness also does not complete the broader SB-BOOT/AC-023 bootstrap,
ownership-transfer, recovery, or break-glass acceptance program.
The checked-in `implementation_only` fixtures cannot start the runtime, so this
quick start intentionally has no fabricated profile or digest.

```bash
RYUKI_SERVER__BIND_ADDRESS=127.0.0.1:8081 \
  cargo run -p ryuki-api
```

Wait for `curl --fail http://127.0.0.1:8081/ready` to succeed.

Admission runs before migration selection, database access, signing-key or
worker initialization, router construction, and listener binding. Only the
read-only `--dump-route-meta` maintenance command bypasses it and exits without
starting services.

### 5. Run the portal on port 8080

In a second terminal:

```bash
LEPTOS_SITE_ADDR=127.0.0.1:8080 \
RYUKI_API_URL=http://127.0.0.1:8081 \
RYUKI_PORTAL_PUBLIC_ORIGIN=http://127.0.0.1:8080 \
RYUKI_PORTAL_ALLOW_INSECURE_LOOPBACK=true \
RYUKI_PORTAL_EXECUTION_MODE=live-provider \
cargo leptos serve --manifest-path portal/portal-ui/Cargo.toml
```

Open `http://127.0.0.1:8080`. Portal execution mode is mandatory and closed.
The command above explicitly selects `live-provider`. To preview labeled static
data instead, set exactly `RYUKI_PORTAL_EXECUTION_MODE=static-dry-run` and keep
`RYUKI_PORTAL_PUBLIC_ORIGIN` explicitly loopback. Missing, blank, unknown, and
legacy `external-static` values fail startup; an external public origin cannot
select `static-dry-run`.

The Compose stack reserves host ports API `18080` and portal `18000`, but the
API's bridged listener is not loopback. The current admission slice refuses
credential-free authority there and also refuses legacy `local`/`entra-id`
authority until every runtime value is projected by the selected provider
contract. The full Compose API is therefore intentionally blocked; when run
independently, the portal can still use its labeled static dry-run data at
`http://127.0.0.1:18000` with the explicit loopback-only mode described above.

### 6. Run tests

```bash
cargo test --workspace
```

### 7. Run validators

Run from the repository root (the validator defaults `--root` to the current
directory; pass `--root <path>` to validate another checkout):

```bash
cargo run --manifest-path scripts/validator-rs/Cargo.toml -- run-all
```

For the complete pre-test gate, also run the format, Clippy, secret-scan, and
diff checks in [First Test Acceptance](first-test.md).

## Authentication Modes

Default is **mock-dry-run** — no real Entra ID, all operations are simulated.
After startup admission is enabled, it also requires one matching active
development fixture and literal loopback listener/public URL.

The Entra runtime flow is implemented, but startup admission currently blocks
live `entra-id` until the provider contract carries an exact typed projection
of tenant, issuer, client, redirect, endpoint, and credential authority. Once
that projection exists, the runtime settings are:

1. Register an Entra ID application (see `docs/configuration.md`)
2. Export `RYUKI_AUTH_MODE=entra-id`, `RYUKI_ENTRA_TENANT_ID`, and
   `RYUKI_ENTRA_CLIENT_ID` into the API process (Compose may read them from the
   gitignored `.env`; direct Cargo runs do not)
3. Inject a random, at-least-32-byte
   `RYUKI_SESSION__CREDENTIAL_HMAC_KEY` and a distinct random, at-least-32-byte
   `RYUKI_SECURITY__CERTIFICATE_CURSOR_HMAC_KEY` at runtime
4. For browser SSO, also set the exact registered
   `RYUKI_ENTRA_REDIRECT_URI`; omit it only for deliberate bearer-only use
5. Restart the API and require `/ready`

The `RYUKI_OIDC__*` generic-provider inputs are reserved but not currently
admitted: setting `RYUKI_OIDC__ENABLED=true` fails startup until an exact
D/P/Q/R runtime authority is implemented. See
[Configuration](configuration.md#generic-oidc-reserved-single-provider-inputs).
The platform boundary specification defines that provider-registry work along
with brokered SAML/LDAP, WebAuthn emergency, service OAuth, and workload
identity.

## Project Structure

```
ryuki.io/
├── sources/
│   ├── ryuki-core/     # Shared types, YAML, secret scanning
│   ├── ryuki-api/      # Axum HTTP API server
│   └── ryuki-engine/   # Business logic, auth, adapters
├── portal/
│   └── portal-ui/      # Leptos SPA frontend
├── scripts/
│   └── validator-rs/   # Rust validators
├── tests/              # Integration tests
└── docs/               # Documentation
```
