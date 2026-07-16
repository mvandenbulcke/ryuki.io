# Live-execution proving ground

A self-contained control-plane stack for testing provider execution (vCenter
and similar systems). The
[First Test Acceptance Specification](../../docs/first-test.md) is normative;
the [Agents & Live Execution guide](../../docs/agents-and-live-execution.md)
explains the wider execution model.
It has separate Compose volumes, networks, and ports, so `deploy/compose` and
its data remain untouched.

> **Current source gate:** production external subprocess execution is
> intentionally unavailable. Until a reviewed per-command containment adapter
> can attach before exec, kill every descendant, and wait for the scope to
> empty, the runner refuses before spawning Terraform or Ansible. The live
> sections below are a future acceptance procedure, not a claim that provider
> execution is currently enabled. This also blocks the external CLI phase of
> `OfflineDryRun`; only the control-plane, portal, enrollment, signing, and
> fail-closed no-spawn boundaries can be rehearsed in the current release.

| Piece | Where | Port |
| --- | --- | --- |
| PostgreSQL | Compose | 15432 |
| Vault (dev mode) | private API/Vault loopback; manage with `docker compose exec vault` | not published |
| Control-plane API (local auth, Vault resolver, persisted signing key) | Compose | 18081 |
| Portal (live-provider mode) | Compose | 18001 |
| Execution agent | host, `./run-agent.sh` | outbound only |

## Configure and validate

```bash
cd deploy/proving-ground
install -m 600 env.example .env
```

Replace the database, Vault, local-account, session-verifier, revision, and
image-ID placeholders in the gitignored `.env`. Generate
`PG_SESSION_CREDENTIAL_HMAC_KEY` with at least 32 random bytes; it is a
dedicated verifier key, not a user password. Replace both executable
placeholders with absolute, already-canonical regular-file paths and record the
exact Terraform and `ansible-playbook` core versions. The files and every
parent directory must be owned by root or the agent user and must not be
group/other writable (a root-owned sticky temporary directory is the only
writable-parent exception). Symlinks are rejected. Live mode requires both
executable SHA-256 fields to contain independently approved digests. Non-live
local validation may omit them. Before any version probe, the scripts copy each
configured tool into the agent-owned `agent-state/approved-tools/` directory,
hash that non-writable content-addressed copy, and pass only the verified copy
to the runner or cleanup flow. Leave the three vSphere credentials, the
non-secret provider authority id/version, and the non-secret backend
credential-authority id/revision empty while
`PG_AGENT_ALLOW_LIVE=false`; fill them only
before the approved live gate. The id must be an opaque
`provider-authority/vsphere/...` provisioning reference, never a server,
account, tenant, credential, or provider-returned value. Rotate its `v...`
version whenever any destination/account/credential member changes. Keep the
backend id in the form `backend-credential-authority/local/...` and rotate its
`v...` revision whenever the backend principal, destination, or credential set
changes. These references are trusted-access metadata in this proving ground;
they do not claim atomic co-resolution with secret material. Keep
`PG_AGENT_PLATFORM=DEFRA` and the bundled local backend template unchanged,
and keep the `requester` and `admin` accounts distinct. The requester creates
work; the admin approves the agent and drives every post-create request action,
including live apply. Successful single-job cleanup is currently out of band,
not an admin-approved control-plane destroy step.

Supply the active deployment profile and independently approved conformance
trust-root registry through their two normalized relative `.json` paths and
two exact nonzero lowercase `sha256:<64hex>` raw-byte digests. Both documents
are supplied through `PG_DEPLOYMENT_SECURITY_PROFILE_PATH`,
`PG_DEPLOYMENT_SECURITY_PROFILE_DIGEST`,
`PG_CONFORMANCE_TRUST_ROOT_REGISTRY_PATH`, and
`PG_CONFORMANCE_TRUST_ROOT_REGISTRY_DIGEST`. They must be root-owned regular
files beneath the immutable
`/app/security-contract` image tree; the proving ground never selects or
fabricates a registry, profile, or digest. The selected registry is the head of
an exact, bounded N-1 chain, so every predecessor through version 1 must also
be present in that tree. The chain does not replace an external monotonic head
checkpoint and cannot authorize production on its own.

Agent values are parsed as literal `KEY=value` text. HCL spaces, semicolons,
`$()`, and other shell metacharacters are not evaluated. Do not add an inline
comment to an agent value because it becomes part of that literal value.
Compose-only database, Vault, and local-account values are ignored by the
agent parser and are not exported to the agent process.

Build the app images from one clean committed revision and record their local
immutable IDs. The OCI revision label and revision-specific tag are both
mandatory; a reused `rust-dev` tag is never acceptance evidence:

```bash
REVISION="$(git -C ../.. rev-parse HEAD)"
test -z "$(git -C ../.. status --porcelain=v1 --untracked-files=all)"

docker build --pull=false \
  --label "org.opencontainers.image.revision=${REVISION}" \
  --tag "ryuki/platform-api:${REVISION}" \
  --file ../../sources/ryuki-api/Dockerfile ../..
docker build --pull=false \
  --label "org.opencontainers.image.revision=${REVISION}" \
  --tag "ryuki/portal-ui:${REVISION}" \
  --file ../../portal/portal-ui/Dockerfile ../..

docker image inspect --format '{{.Id}}' "ryuki/platform-api:${REVISION}"
docker image inspect --format '{{.Id}}' "ryuki/portal-ui:${REVISION}"
```

Put `REVISION` in `PG_ACCEPTANCE_REVISION` and the two printed `sha256:...`
IDs in `PG_PLATFORM_API_IMAGE_ID` and `PG_PORTAL_IMAGE_ID`. Pre-stage the exact
PostgreSQL and Vault digest references from `compose.yaml` through the approved
artifact channel. Publisher signature/provenance review and acquisition are
separate trusted-access steps; the local validator intentionally contacts no
registry and cannot establish publisher identity. Image IDs and revision labels
also assume the local daemon and builder are trusted; use independently verified
signed provenance when that local trust boundary is not acceptable.

The host agent additionally requires `REVISION` to be a valid signed commit.
Provision the full uppercase OpenPGP fingerprint of the independently approved
signer into checkout-local Git configuration through the trusted operator
channel (do not copy it from the checkout being approved):

```bash
git -C ../.. config --local \
  ryuki.provingGroundAcceptanceSignerFingerprint \
  '<FULL-40-CHARACTER-APPROVED-FINGERPRINT>'
```

`run-agent.sh` fails unless `HEAD` is exactly `PG_ACCEPTANCE_REVISION`, every
tracked and untracked source path is clean, `git verify-commit` succeeds with
that exact fingerprint, and the accepted tree remains unchanged. Before the
private `.env` is loaded, it performs an isolated release build with
`cargo build --locked --offline`, incremental compilation disabled, and a
disposable target directory. Pre-stage the locked Cargo dependencies in the
trusted local Cargo cache; the runner never contacts a registry. It records the
commit/tree, a SHA-256 digest of the accepted tree manifest, `Cargo.lock`, and
the resulting private agent executable in `agent-state/agent-build.manifest`,
then rechecks all bindings immediately before enrollment-key execution,
administrative enrollment, self-registration, and live-agent execution.

Any source, lockfile, accepted revision, signer, agent artifact, or manifest
change requires a newly reviewed signed commit, rebuilt app images and recorded
image IDs, an updated `.env`, and a fresh runner invocation. Never repair a
failed binding by editing the private manifest. The locally configured signer
fingerprint, OpenPGP keyring/trust policy, Cargo/Rust toolchain, dependency
cache, and host filesystem remain operator-provisioned trusted inputs; archive
their independent provenance with acceptance evidence when local-host trust is
insufficient.

Run the non-destructive smoke check before starting anything:

```bash
./validate.sh .env
```

It checks shell syntax (including the cleanup utility), literal env parsing,
approved Terraform/Ansible path provenance, private-copy digest binding, and
version identity, the two-account and `DEFRA` invariants, the session-verifier
length, backend placeholder rendering, the exact profile/trust-registry pins,
the `/ready` health gate, the loopback-only host ports,
the private API/Vault loopback, the portal's separate network namespace, the
non-root/capability-drop contract, the clean acceptance revision, each local
image ID/revision label, each staged third-party digest, and the rendered
`docker compose config`. It performs only local daemon inspection: it does not
pull, start containers, contact a registry, or contact a provider. These
repository checks prove the declared Compose shape only; they do not establish
the trustworthiness of the local daemon, pre-staged images, acceptance signer,
toolchain, or bootstrap channel, and must not be used as closure evidence for
those separate trust boundaries.

## Bring up the control plane

```bash
docker compose down
docker compose up -d --wait --force-recreate
curl --disable --fail --noproxy '*' http://127.0.0.1:18081/ready
```

Every service sets `pull_policy: never`, so startup also fails rather than
silently resolving missing content from a registry. Rerun `./validate.sh .env`
immediately before every `up`.

Do not enrol or dispatch work until `/ready` succeeds. Open
`http://127.0.0.1:18001` after that gate passes. The API alone shares Vault's
network namespace, and Vault listens only on `127.0.0.1:8200` inside that
namespace. The Vault dev token therefore never crosses a bridge or a published
host port. The portal runs in a separate namespace, is connected only to the
API-facing `portal-net`, and cannot join the PostgreSQL network. Its upstream
still satisfies the portal's literal-loopback cleartext gate: a fixed non-root
`socat` relay listens on portal loopback and forwards only to the API's Compose
alias. That bridge carries API traffic the portal already originates; Vault
continues to listen only on the different API/Vault loopback. Both application
containers run as UID/GID `10001` with every Linux capability dropped; Vault
runs as its image's `vault` user with only `IPC_LOCK` restored. PostgreSQL, the
API, and the portal are the only published services, and every binding remains
on host `127.0.0.1`.

Manage or seed the disposable Vault through its own container rather than
publishing the cleartext dev listener. The Vault CLI inherits the private
loopback address and dev token inside that trusted container; never print the
token or secret value:

```bash
docker compose exec vault vault status
# Example interactive seed; replace the path and field with the reviewed handle.
printf 'secret value: ' >&2
IFS= read -r -s SECRET_VALUE </dev/tty
printf '\n' >&2
printf '%s' "$SECRET_VALUE" | \
  docker compose exec -T vault vault kv put secret/ryuki/example value=- >/dev/null
unset SECRET_VALUE
```

This is deliberate proving-ground isolation, not a production transport
pattern. Production uses authenticated TLS or mTLS, scoped Vault policy tokens,
and separately scheduled workloads.

## Enrol the agent

Keep `PG_AGENT_ALLOW_LIVE=false` for the first pass.

Create a temporary PlatformAdmin session header outside the repository. The
header is a credential; keep it mode `0600`, never print it, and log it out as
soon as enrollment has been staged:

```bash
(
  set -euo pipefail
  BASE=http://127.0.0.1:18081
  umask 077
  AUTH_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ryuki-pg-enroll.XXXXXX")
  AUTH_DIR=$(cd "$AUTH_DIR" && pwd -P)
  ADMIN_HEADERS="$AUTH_DIR/admin.headers"
  cleanup_enrollment_session() {
    local status=$?
    trap - EXIT
    if test -f "$ADMIN_HEADERS"; then
      curl --disable --fail-with-body -sS --noproxy '*' \
        -X POST "$BASE/api/auth/local/logout" \
        -H "@$ADMIN_HEADERS" >/dev/null || true
    fi
    rm -rf "$AUTH_DIR"
    exit "$status"
  }
  trap cleanup_enrollment_session EXIT

  printf 'admin password: ' >&2
  IFS= read -r -s ADMIN_PASSWORD </dev/tty
  printf '\n' >&2
  ADMIN_LOGIN=$(printf '%s' "$ADMIN_PASSWORD" | \
    jq -Rs --arg username admin '{username: $username, password: .}' | \
    curl --disable --fail-with-body -sS --noproxy '*' \
      -X POST "$BASE/api/auth/local/login" \
      -H 'Content-Type: application/json' --data-binary @-)
  unset ADMIN_PASSWORD
  ADMIN_SESSION=$(printf '%s' "$ADMIN_LOGIN" | jq -er '.session_token')
  unset ADMIN_LOGIN
  printf 'X-Ryuki-Session-Id: %s\n' "$ADMIN_SESSION" > "$ADMIN_HEADERS"
  unset ADMIN_SESSION

  ./run-agent.sh --stage-enrollment "$ADMIN_HEADERS"

  curl --disable --fail-with-body -sS --noproxy '*' \
    -X POST "$BASE/api/auth/local/logout" \
    -H "@$ADMIN_HEADERS" >/dev/null
  rm -f "$ADMIN_HEADERS"
)
```

The staging run creates or loads the agent's durable Ed25519 key, asks the
authenticated control plane for a fresh 15-minute challenge bound to `DEFRA`
and that exact public key, signs the claim, self-registers, deletes the local
challenge response after success, and exits pending approval. The challenge is
never a committed `.env` value or a reusable deployment secret. If the run
fails before consumption, the private response remains under `agent-state/`
for a bounded retry with `./run-agent.sh`; after expiry, remove that response
and stage a new challenge with a new administrator session. If registration
was consumed but its one-time `rya_...` token could not be persisted, stop:
replaying the challenge cannot recover the token, and an administrator must
complete the approved enrollment-recovery procedure before restaging. The
proving ground deliberately provides no automatic identity deletion shortcut;
preserve the database and audit trail and treat that run as blocked.

Sign in as `admin`, review the immutable enrollment ID, public-key fingerprint,
platform, and `cryptographically_admitted` marker in the Agents view/API,
approve that exact pending enrollment, sign out, and then start its polling
loop:

```bash
./run-agent.sh
```

Each invocation rebuilds from the exact clean signed acceptance revision in a
disposable target with the locked dependency graph and no network access. The
private artifact and its source/dependency digests are verified again at every
credential-bearing execution boundary, so a stale or replaced agent fails
closed rather than silently reusing an older protocol or JobSpec.
`run-agent.sh` sets `RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK=true` only alongside
its fixed `http://127.0.0.1:18081` control-plane URL. This is an explicit local
development exception to the agent's fail-closed transport default; never carry
it into a non-loopback or deployed configuration.
Record the startup log entry `CP wire protocol is compatible` and require
`cp_protocol_version=6` and `agent_protocol_version=6`. Missing and v1-v5 peers
fail closed; v6 also binds live grants to the destination, exact planning-agent
enrollment/key, reviewed execution trust profile, and exact plan job/attempt.

Agent identity, token, and Terraform backend state live in `agent-state/`,
which is gitignored.

## Current no-spawn rehearsal

Complete this handoff before implementing or enabling external process
containment:

1. Confirm `.env` still has `PG_AGENT_ALLOW_LIVE=false` and restart the agent
   after any change.
2. Sign in as `requester`, create a minimal server-deployment request targeting
   `DEFRA`, submit it, record the request ID, and sign out. The Requester role
   creates work but cannot run operator transitions.
3. Sign in as `admin`. Validate and plan the request, review it, approve it,
   and lock it. The requester must never approve work they created. Review the
   timeline and confirm no provider process or state was created.
4. Exercise enrollment, polling, signing, and evidence handling only through
   tests or stubs that do not spawn Terraform or Ansible. A production attempt
   to execute `OfflineDryRun`, `LivePlan`, `LiveApply`, or `LiveDestroy` must
   stop at the missing-containment gate before process creation; it is not a
   successful dry-run acceptance result.
5. Preserve a separate governed request for the future refusal/containment
   acceptance wave. Do not dispatch it against a provider until the reviewed
   per-command containment adapter and the remaining gates below are present.

Do not continue until the no-spawn evidence and maker/checker handoff are both
understood and repeatable. Successful Terraform or Ansible dry-run evidence is
deferred with the external-process containment milestone.

## First live test

Use an isolated, disposable provider target. Ensure the backend template
contains `{STATE_KEY}`; it is replaced with a request/step-specific state key.
The local template also expands `{STATE_DIR}` to the absolute `agent-state`
directory. Keep that bundled local template for this first test. The agent does
not pass arbitrary backend credential environment variables into Terraform, so
an authenticated remote backend is not a proving-ground alternative.
Plan, apply, and cleanup must use the same approved agent and backend template.
Do not delete or re-enrol the agent between those phases.

The embedded server bundles pin `vmware/vsphere` 2.16.1 and enforce their
checksum lock read-only. That release documents vSphere 8.x/9.x support. A
vSphere 7.x target blocks this revision; do not override or delete the lock.

1. Stop the polling agent, set `PG_AGENT_ALLOW_LIVE=true` in `.env`, configure
   the required provider credentials plus `PG_PROVIDER_AUTHORITY_ID` and
   `PG_PROVIDER_AUTHORITY_VERSION`, `PG_BACKEND_CREDENTIAL_AUTHORITY_ID`, and
   `PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION`, rerun `./validate.sh .env`, and restart
   `./run-agent.sh`.
2. Sign in as `requester` and submit the primary minimal `DEFRA` request in the
   `test` environment. Record `PRIMARY_LIVE_REQUEST_ID` and its unique VM name,
   then sign out.
3. Sign in as `admin`. Validate, plan, approve, and lock the request, then
   dispatch `LivePlan`. A successful plan leaves the request `executing` while
   it waits for approval.
4. In Execution Job / Plan Review, require `digest_verified`, exactly one VM
   create, no update/delete/replace, the exact request placement, and the
   `request-<request-id>` state key. Raw Terraform or provider payloads are not
   an acceptable substitute for this projection.
5. Before approving apply, create a second, uniquely named request as
   `requester`; govern it through a successful `LivePlan` as `admin`. Require a
   different state key/path and prove the primary state file is unchanged as
   specified in Gate 4 of the normative acceptance document. Never approve the
   isolation request's apply; conclude it through request `fail`.
6. Run the exact `destroy-state.sh --preflight` command from Gate 4 with the
   primary request's original values. It must pass without initializing
   Terraform or contacting vSphere.
7. Return to `PRIMARY_LIVE_REQUEST_ID` and approve live apply with the two-click
   control. Wait for the latest
   `LiveApply` to be `Succeeded` with result `verified`; `applied` without a
   clean post-apply plan is a hard stop. Confirm the request is now
   `verifying`, inspect vSphere directly, and only then run request verification.

A missing credential, missing backend placeholder, or invalid grant produces a
signed, value-free refusal. Resolve the cause; do not bypass the gate.

After every `LiveApply` attempt, record both the isolated-state and direct
vSphere dispositions. If a job becomes `ReconcileRequired`, inspect both before
resolving it. Use `destroy-state.sh` only when the isolated state contains the
expected VM. If state is absent or mismatched while a provider object exists,
use a separately approved provider-recovery procedure instead; never force the
script against unrelated state. Once the disposition is known, the admin calls
`POST /api/admin/agents/jobs/{job_id}/reconcile` with a non-sensitive reason,
then `POST /api/requests/{id}/fail`. There is no in-place retry: any later
attempt starts with a fresh request, plan, review, and approval.

## Destroy real infrastructure first

Stopping Compose does not destroy infrastructure created by Terraform. The
current control plane emits `LiveDestroy` only as system-authorized,
reverse-order compensation after a partially applied multi-step request fails.
It does not expose an operator-triggered destroy for a successful request.

Cleanup is an acceptance gate for a successful live test. An
operator-governed destroy endpoint is future work, not a current cleanup
choice. The only accepted first-test route is the bundled out-of-band
`destroy-state.sh` procedure. Before approving live apply, run its exact
`--preflight` invocation from the acceptance specification. The real cleanup
reconstructs the original variables, initializes the exact isolated state,
shows a saved destroy plan, and applies only that plan after the operator types
the state key. Do not use `--yes` for the first test.

For the local backend, preserve the matching
`agent-state/terraform-request-<request-id>.tfstate` or
`agent-state/terraform-step-<step-id>.tfstate` file. Never use a different or
empty state as evidence that cleanup succeeded.

Run the out-of-band path from this directory with the exact values from the
applied job. For successful-request cleanup, first wait for the request to
reach a terminal state. For an uncertain apply, stop the polling agent and
inspect state/provider disposition before the reconcile and request-fail calls;
cleanup may therefore run while the parent remains `executing`. In either case,
stop the polling agent so it cannot start another job against the same backend,
and keep the control-plane database and `agent-state/`. This example names
placeholders; do not guess any value:

```bash
./destroy-state.sh \
  --state-key request-REQUEST_UUID \
  --offering linux-server-deployment \
  --request-id REQUEST_UUID \
  --vm-name ORIGINAL_VM_NAME \
  --site ORIGINAL_SITE \
  --environment ORIGINAL_ENVIRONMENT \
  --cpu ORIGINAL_CPU_COUNT \
  --memory-gb ORIGINAL_MEMORY_GB \
  --disk-size-gb ORIGINAL_DISK_SIZE_GB \
  --datacenter ORIGINAL_DATACENTER \
  --cluster ORIGINAL_CLUSTER \
  --datastore ORIGINAL_DATASTORE \
  --network ORIGINAL_NETWORK \
  --template ORIGINAL_TEMPLATE
```

The utility reads provider credentials and the bundled local backend template
from `.env`; it uses the same approved absolute Terraform executable as the
agent and validates it before exporting those credentials. It does not print
credentials or put them in its evidence file.
For a step state, use `step-STEP_UUID`. It refuses an empty state or a state
containing anything other than exactly one managed resource (the offering's
expected VM) and the bundle's five allowlisted read-only inventory data
sources. It then writes a value-free completion record under `agent-state/`
after Terraform reports an empty state.
Inspect vSphere directly, then and only then change the record to
`provider_verification=absent`, a nonempty `provider_verified_by`, and an RFC
3339 UTC `provider_verified_at`. If any original input or the exact state key
cannot be reconstructed, do not run the live apply: cleanup cannot be proven
safe.

When system auto-teardown is active, keep the control plane and agent running,
wait for every signed `LiveDestroy` result, and stop if any destroy fails. For
either cleanup path, inspect vSphere directly to verify the resource is absent
and verify that the matching Terraform state has no managed resources. Preserve
`agent-state/` and the control-plane database until both checks pass.

## Stop, reset, and re-enrol

After provider cleanup is verified:

```bash
docker compose down
```

This keeps the database and control-plane signing key. The existing agent token
remains valid when the stack returns.

For a clean control-plane reset, stop the agent and run:

```bash
docker compose down -v
rm -f agent-state/agent.token
docker compose up -d --wait
curl --disable --fail --noproxy '*' http://127.0.0.1:18081/ready
# Create a fresh temporary admin header as in "Enrol the agent", then:
./run-agent.sh --stage-enrollment "$ADMIN_HEADERS"
```

Deleting Compose volumes creates a new database and signing key. Removing only
`agent.token` preserves the agent identity and any Terraform state needed for
investigation, but no longer authorizes anonymous self-registration. A fresh
administrator-issued challenge bound to that existing key is mandatory.
Approve the new pending agent as `admin`, then run `./run-agent.sh` again to
resume polling.

Only after provider cleanup is independently verified may you remove all local
agent state:

```bash
rm -rf agent-state
```

That final command is irreversible and removes the local Terraform state that
would otherwise be needed to destroy or reconcile live resources.
