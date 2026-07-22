# First Test Acceptance Specification

This document defines what "ready for a first test" means for Ryuki. A goal
session, tracker entry, review, commit, or successful build is supporting
evidence, not acceptance by itself.

The first test has two milestones:

1. **Platform no-spawn rehearsal** proves the governed control-plane lifecycle,
   maker/checker handoff, enrollment, protocol, signing, and evidence seams
   without starting Terraform or Ansible. It must complete before any external-
   process or provider-connected work.
2. **First live vSphere test** proves plan, approval, apply, verification, state
   isolation, and cleanup against one approved disposable target.

The live milestone is optional until an operator approves the target and
credentials. It is blocked, not failed, when those external prerequisites are
unavailable. It must never be redirected to production merely to make the test
runnable.

The current source tree also blocks that live milestone by design: production
external subprocess execution refuses before spawn until a reviewed
per-command containment adapter can attach before exec, kill all descendants,
and wait for an empty scope. The live gates below therefore specify future
acceptance evidence; they do not assert working provider execution in this
snapshot. The current executable milestone is the no-spawn control-plane and
pure/stub protocol rehearsal. A successful external `OfflineDryRun` result is
deferred with the same containment adapter as live execution.

## Authority and scope

This document is normative for first-test scope and acceptance. Runtime protocol
types, lifecycle code, and migrations are the evidence for what is implemented;
they do not silently weaken an acceptance criterion. If the implementation and
this document disagree, the affected gate is blocked until both are reconciled.

Use the remaining documentation in this order:

1. [Agents & Live Execution](agents-and-live-execution.md) and
   `deploy/proving-ground/README.md` define current operator procedures.
   [Multi-Step Orchestration](orchestration.md) documents the disabled
   per-step live-apply boundary and future compensation groundwork; it is not
   an enabled operator procedure in this release.
2. Files under `docs/design/` and goal-session trackers are historical design
   records. They do not override implemented behavior or this acceptance gate.

The first live test is one **single-job Linux server deployment**. Do not set
`deployment_profile=managed-onboarding`; multi-step orchestration, Windows,
Ansible, production targets, provider API adapters, high availability, and
performance testing are outside this acceptance scope.

## Required roles and target

| Item | Requirement |
| --- | --- |
| Requester | A principal with `Requester`; creates the request, records its ID, signs out, and cannot run operator or approval transitions. |
| Approver/operator | A different principal with `PlatformAdmin`; approves the agent and drives every post-create transition, including request approval and live apply. |
| Agent | Approved for platform `DEFRA`, with Terraform installed and network access to the test vCenter. |
| Target | An explicitly approved, disposable vSphere target where one test VM can be created and removed. Approval includes the selected cluster's root resource pool and default VM folder used by the bundled IaC. |
| Credentials | Present only on the agent host as `RYUKI_LIVE_CRED_VSPHERE_USER`, `RYUKI_LIVE_CRED_VSPHERE_PASSWORD`, and `RYUKI_LIVE_CRED_VSPHERE_SERVER`. |
| State | A durable backend template containing `{STATE_KEY}`. The local proving ground also uses `{STATE_DIR}`. |
| Cleanup | The exact state-keyed destroy command is reviewed before live apply. A successful apply without a rehearsed cleanup path is not permitted. |

Use `deploy/proving-ground`, which supplies isolated Compose volumes, local
authentication, `/ready` health gating, literal environment parsing, and agent
state under its gitignored `agent-state/` directory.

## Tool and provider prerequisites

Before Gate 1, require all of the following on the operator/agent host:

- Rust stable with Cargo, rustfmt, and Clippy. `cargo-leptos` and the
  `wasm32-unknown-unknown` target are required only for a direct host portal
  build, not for the repository gates or the Compose portal image;
- Bash, Docker with Compose v2, Terraform, `curl`, `jq`, and `shasum`;
- outbound access to the Terraform registry for the exact, checksum-locked
  `vmware/vsphere` 2.16.1 provider embedded in both server bundles;
- a vSphere 8.x or 9.x target, matching the provider release's documented
  support matrix. A vSphere 7.x target blocks this revision; select and lock a
  reviewed compatible provider in source, then rerun Gate 1 instead of
  overriding the dependency lock;
- a trusted TLS chain for vCenter. The bundled provider sets
  `allow_unverified_ssl=false`; do not bypass certificate verification;
- a least-privilege vSphere account that can read the selected inventory and
  clone, configure, power, and delete a VM only in the approved disposable
  target;
- an isolated approved test port group and a generalized clone-safe template:
  no retained static IP, hostname, or machine identity; DHCP/cloud-init or an
  equivalent first-boot identity mechanism must prevent a network conflict;
- synchronized UTC time on the host running the agent and the control plane.
  Record the time source and prove absolute skew from a trusted source is at
  most five seconds immediately before live mode is enabled;
- enough local disk to preserve the control-plane volumes, agent identity,
  Terraform state, and value-free evidence until cleanup is accepted.

Record the tool versions, vCenter major version, exact provider version, and
approved vSphere privilege scope. A missing tool, unsupported vCenter,
registry path, trusted CA, or delete privilege blocks the live gate.

## Request contract

Prepare four distinct requests and record their IDs with these exact operator
labels:

| Label | Purpose | Required disposition |
| --- | --- | --- |
| `DRY_RUN_REQUEST_ID` | Complete the credential-free, provider-connection-free lifecycle. | `completed` in Gate 3. |
| `LIVE_REFUSAL_REQUEST_ID` | Prove that `LivePlan` refuses while live mode is disabled. | Terminal failure in Gate 3; never reuse it. |
| `PRIMARY_LIVE_REQUEST_ID` | Plan, apply, verify, and clean up the disposable VM. | `completed` before Gate 6 cleanup. |
| `ISOLATION_REQUEST_ID` | Prove a second plan resolves to a different state key. | Explicitly failed after its plan; never approve live apply. |

Use a different approved VM name for every request and record it as the
matching `*_VM_NAME` value. The placement may be shared. Record the following
approved inputs before creating any request:

| Field | Rule |
| --- | --- |
| `request_type` | `server-deployment` |
| `site` | `DEFRA` |
| `environment` | `test` |
| `name` | Unique ASCII test VM name, at most 160 bytes, approved for the disposable target. |
| `cpu` | Positive integer within the target policy. |
| `memory_gb` | Positive integer within the target policy. |
| `justification` | Names the approved first-test change record; contains no secret or provider data. |
| `fields.operating_system` | `RHEL 9` |
| `fields.datacenter` | Exact ASCII vSphere inventory name, at most 160 bytes. |
| `fields.cluster` | Exact ASCII vSphere inventory name, at most 160 bytes. |
| `fields.datastore` | Exact ASCII vSphere inventory name, at most 160 bytes. |
| `fields.network` | Exact ASCII name of the approved isolated test port group, at most 160 bytes. |
| `fields.template` | Exact ASCII name of the approved generalized, clone-safe Linux template, at most 160 bytes. |
| `fields.disk_size_gb` | Decimal digits encoded as a JSON string; the resulting positive integer must not shrink the template disk. |

VM and placement values must not contain control characters or `://`; the safe
Plan Review intentionally refuses values it cannot project without ambiguity.
Every value inside the `fields` object is encoded as a JSON string, including
`disk_size_gb` (for example, `"disk_size_gb": "80"`). The top-level `cpu` and
`memory_gb` values remain JSON numbers.
Placement values and Ryuki's requester, approver, agent, request, and job IDs
are non-secret test evidence. Credentials, raw-provider tenant or object IDs,
private addresses, and raw provider payloads never belong in the request,
audit notes, screenshots, or committed test evidence.

Before Gate 1, initialize one operator shell with the repository paths and
exact approved inputs below, and keep that shell through Gate 6. After Gate 2,
write each local login response's `session_token` to the matching mode-`0600`
header file; unsafe API methods require `X-Ryuki-Session-Id` and reject
cookie-only authorization. Session tokens are credentials: never print or
commit them. Administrative session UUIDs are management metadata and cannot
authenticate. Assign
each `*_REQUEST_ID` immediately after that request is created in its stated
gate.

```bash
BASE=http://127.0.0.1:18081
umask 077
REPO_ROOT=$(git rev-parse --show-toplevel)
PROVING_GROUND_DIR="$REPO_ROOT/deploy/proving-ground"
TEST_REVISION=$(git -C "$REPO_ROOT" rev-parse HEAD)
AUTH_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ryuki-first-test.XXXXXX")
AUTH_DIR=$(cd "$AUTH_DIR" && pwd -P)
REQUESTER_HEADERS="$AUTH_DIR/requester.headers"
ADMIN_HEADERS="$AUTH_DIR/admin.headers"

login_local() {
  local username=$1
  local header_file=$2
  local password login session_token
  printf '%s password: ' "$username" >&2
  IFS= read -r -s password </dev/tty
  printf '\n' >&2
  login=$(printf '%s' "$password" | \
    jq -Rs --arg username "$username" '{username: $username, password: .}' | \
    curl --disable --fail-with-body -sS --noproxy '*' \
      -X POST "$BASE/api/auth/local/login" \
      -H 'Content-Type: application/json' --data-binary @-)
  unset password
  session_token=$(printf '%s' "$login" | jq -er '.session_token')
  unset login
  printf 'X-Ryuki-Session-Id: %s\n' "$session_token" > "$header_file"
  unset session_token
}

logout_local() {
  local header_file=$1
  local logout_status=0
  if test -f "$header_file"; then
    curl --disable --fail-with-body -sS --noproxy '*' \
      -X POST "$BASE/api/auth/local/logout" \
      -H "@$header_file" >/dev/null || logout_status=$?
    rm -f "$header_file"
  fi
  return "$logout_status"
}

cleanup_auth() {
  logout_local "$REQUESTER_HEADERS" || true
  logout_local "$ADMIN_HEADERS" || true
  rm -rf "$AUTH_DIR"
}
trap cleanup_auth EXIT

DRY_RUN_REQUEST_ID='<dry-run-request-uuid>'
LIVE_REFUSAL_REQUEST_ID='<live-refusal-request-uuid>'
PRIMARY_LIVE_REQUEST_ID='<primary-live-request-uuid>'
ISOLATION_REQUEST_ID='<isolation-request-uuid>'
DRY_RUN_VM_NAME='<approved-dry-run-vm-name>'
LIVE_REFUSAL_VM_NAME='<approved-live-refusal-vm-name>'
PRIMARY_LIVE_VM_NAME='<approved-primary-vm-name>'
ISOLATION_VM_NAME='<approved-isolation-vm-name>'
CPU='<approved-cpu-count>'
MEMORY_GB='<approved-memory-gb>'
DISK_SIZE_GB='<approved-disk-size-gb>'
DATACENTER='<approved-datacenter-name>'
CLUSTER='<approved-cluster-name>'
DATASTORE='<approved-datastore-name>'
NETWORK='<approved-network-name>'
TEMPLATE='<approved-template-name>'
```

## Gate 1: repository checks

Run from a clean checkout of the exact revision to be tested:

```bash
cd "$REPO_ROOT"
test -n "$TEST_REVISION"
test "$(git rev-parse HEAD)" = "$TEST_REVISION"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
make verify-clean
(
  set -euo pipefail
  DB_TEST_CONTAINER="ryuki-gate1-db-${TEST_REVISION:0:12}-$$"
  DB_TEST_LOG="$(mktemp)"
  DB_TEST_TARGET="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-gate1-target.XXXXXX")"
  cleanup_gate1_db() {
    rm -f "$DB_TEST_LOG"
    rm -rf "$DB_TEST_TARGET"
    docker stop "$DB_TEST_CONTAINER" >/dev/null 2>&1 || true
  }
  trap cleanup_gate1_db EXIT
  docker run --detach --rm --name "$DB_TEST_CONTAINER" \
    --env POSTGRES_DB=ryuki_ci \
    --env POSTGRES_USER=postgres \
    --env POSTGRES_HOST_AUTH_METHOD=trust \
    --publish 127.0.0.1::5432 postgres:18
  for _ in {1..30}; do
    docker exec "$DB_TEST_CONTAINER" \
      pg_isready --username postgres --dbname ryuki_ci && break
    sleep 1
  done
  docker exec "$DB_TEST_CONTAINER" \
    pg_isready --username postgres --dbname ryuki_ci
  DB_TEST_BINDING="$(docker port "$DB_TEST_CONTAINER" 5432/tcp)"
  DB_TEST_PORT="${DB_TEST_BINDING##*:}"
  DB_TEST_URL="$(printf 'postgresql://%s@%s:%s/%s' \
    postgres 127.0.0.1 "$DB_TEST_PORT" ryuki_ci)"
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_TARGET_DIR="$DB_TEST_TARGET" \
    RYUKI_DATABASE_URL="$DB_TEST_URL" \
    cargo test -p ryuki-api -- --test-threads=1 --nocapture \
    2>&1 | tee "$DB_TEST_LOG"
  ! grep -Eqi \
    'SKIP: (RYUKI_DATABASE_URL|DB (connect failed|unavailable|not available)|no seeded|seed .* not present|no DEFRA)|RYUKI_DATABASE_URL not set|skipping (DB|database) tests' \
    "$DB_TEST_LOG"
)
```

Every command must exit `0`. `make verify-clean` runs the complete build,
workspace tests, formatting, Clippy, validators, dependency audit, secret
scan, and patch-hygiene checks in one capped disposable target. The PostgreSQL
block starts an ephemeral
PostgreSQL 18 container on a Docker-assigned loopback port, serializes the API
tests, fails if a database-backed test reports that it skipped for lack of a
database or fixture, and removes the container, test log, and its separate
disposable Cargo target on exit. Record
`TEST_REVISION` and the command results. Do not waive a failure as pre-existing;
fix it or mark the test blocked. Do not switch revisions or edit
tracked/untracked source through Gate 6: the agent binary embeds the tested IaC,
while the cleanup helper reads the current bundle from the checkout.

## Gate 2: proving-ground readiness

Follow `deploy/proving-ground/README.md` to create the gitignored `.env`. Keep
`PG_AGENT_ALLOW_LIVE=false` initially, then run:

```bash
cd "$PROVING_GROUND_DIR"
./validate.sh .env
docker compose -f ../compose/compose.yaml build platform-api portal-ui
docker compose down
docker compose up -d --wait --force-recreate
curl --disable --fail --noproxy '*' http://127.0.0.1:18081/ready
docker image inspect ryuki/platform-api:rust-dev ryuki/portal-ui:rust-dev \
  --format '{{.Id}}'
```

Acceptance requires:

- `.env` contains distinct requester and admin accounts.
- `PG_AGENT_PLATFORM` is exactly `DEFRA`.
- the active backend state-location attribute contains `{STATE_KEY}`; a comment or
  unrelated attribute does not satisfy the validator.
- no database, Vault, or local-account placeholder remains. Provider
  credentials may stay empty until the live gate.
- `/ready` succeeds; `/health` alone is not sufficient.
- API and portal images were rebuilt from `TEST_REVISION`, force-recreated, and
  their image IDs were recorded; a previously built `rust-dev` image is not
  acceptance evidence.
- before the agent starts, the operator records the preprovisioned Ed25519
  public-key fingerprint, creates a short-lived challenge for that exact agent
  id/platform/key through the admin API, and invokes `run-agent.sh
  --stage-enrollment` with a temporary mode-`0600` administrator session header
  outside the repository. The response is held only in the private gitignored
  agent-state directory until consumption; neither challenge field is stored in
  `.env`. The plaintext challenge is not recorded in test evidence;
- the agent proves possession of that key, consumes the challenge exactly once,
  persists its token, exits pending approval, and enters its poll loop only
  after the admin verifies `cryptographically_admitted: true` and approves the
  matching fingerprint and platform;
- control plane and agent negotiate protocol v7. Missing and v1-v6
  protocol headers are rejected rather than treated as compatible. Record the
  approved agent's startup log entry `CP wire protocol is compatible` with both
  `cp_protocol_version=7` and `agent_protocol_version=7`; the protocol rejection
  tests in Gate 1 are the evidence for older-version fail-closed behavior and
  for rejection of legacy live grants without exact destination, planning-agent
  enrollment/key, reviewed execution-profile, and exact plan-row bindings.
- direct vSphere inventory inspection proves all four recorded VM names are
  absent from the approved target folder/placement before any LivePlan;
- the host/control-plane clock evidence satisfies the five-second skew bound.

For API-driven steps, run `login_local requester "$REQUESTER_HEADERS"` before
each requester create and `logout_local "$REQUESTER_HEADERS"` immediately
after recording the request ID. Run `login_local admin "$ADMIN_HEADERS"` for
post-create actions and `logout_local "$ADMIN_HEADERS"` before returning to the
requester. Re-login after each handoff. Removing a header file without calling
logout does not revoke its server-side session. Portal-driven steps require the
equivalent explicit sign-out/sign-in handoff.

## Gate 3: platform no-spawn rehearsal

Keep live mode disabled for this entire gate.

1. Sign in as the requester and create the dry-run request using the complete
   request contract above. Record its `intake` status and request ID, then sign
   out.
2. Sign in as the admin. Run `validate` and `plan`. The observable request
   statuses become `validated`, then `planned`.
3. Review the plan, approve the request, and lock it. The statuses become
   `approved`, then `locked`.
4. Exercise enrollment, polling, protocol-v7 negotiation, result signing, and
   evidence handling only through pure/stub tests that do not spawn Terraform
   or Ansible. Preserve their value-free evidence.
5. Confirm the production runner reports the missing sealed containment
   capability before process creation for every external mode, including
   `OfflineDryRun`. This is expected fail-closed evidence, not a successful
   dry-run result. Keep the governed request locked for the future containment
   acceptance wave rather than claiming it reached `verifying` or `completed`.

Pass the current milestone only when the audit trail attributes creation and
approval to different principals, the v6 enrollment/signing/evidence seams are
exercised without an external child, and no provider resource or Terraform
state was created.

After the reviewed containment adapter exists, extend this gate with the
external `OfflineDryRun`: dispatch it, wait for the signed successful result,
require the request to move from `executing` to `verifying`, then run `verify`
and require `completed`. Only that future wave may claim successful Terraform
or Ansible dry-run evidence. It must still prove redaction and that no provider
resource or state was created.

Preserve a separate governed request for future live-refusal and containment
acceptance. `LivePlan` with live mode disabled must eventually produce a signed
refusal with no external spawn, but do not treat a pure/stub assertion as a
deployed-agent acceptance result. Do not reuse either Gate 3 request in the
live gates.

## Gate 4: live plan and state isolation

Stop the agent, set `PG_AGENT_ALLOW_LIVE=true`, fill the three vSphere
credential values, recheck the recorded revision and clean worktree, prove the
five-second clock-skew bound, rerun `./validate.sh .env`, and restart the agent:

```bash
test "$(git -C "$REPO_ROOT" rev-parse HEAD)" = "$TEST_REVISION"
test -z "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)"
cd "$PROVING_GROUND_DIR"

# Compare both the host and control-plane clocks with a TLS-authenticated
# external Date value. A value inside the sampling interval has zero measured
# skew; otherwise interval_skew reports its nearest-boundary gap.
interval_skew() {
  local value=$1 lower=$2 upper=$3
  if (( value < lower )); then
    printf '%s\n' "$((lower - value))"
  elif (( value > upper )); then
    printf '%s\n' "$((value - upper))"
  else
    printf '0\n'
  fi
}

TRUSTED_TIME_URL=https://www.cloudflare.com/
HOST_TRUST_BEFORE=$(date -u +%s)
TRUSTED_DATE=$(curl --disable --fail-with-body -sSI "$TRUSTED_TIME_URL" | \
  awk 'tolower($1) == "date:" { sub(/\r$/, ""); sub(/^[^:]*:[[:space:]]*/, ""); print; exit }')
HOST_TRUST_AFTER=$(date -u +%s)
test -n "$TRUSTED_DATE"
TRUSTED_EPOCH=$(docker compose exec -T platform-api \
  date -u --date="$TRUSTED_DATE" +%s)
TRUSTED_SKEW=$(interval_skew \
  "$TRUSTED_EPOCH" "$HOST_TRUST_BEFORE" "$HOST_TRUST_AFTER")

HOST_CP_BEFORE=$(date -u +%s)
CP_EPOCH=$(docker compose exec -T platform-api date -u +%s)
HOST_CP_AFTER=$(date -u +%s)
CP_SKEW=$(interval_skew "$CP_EPOCH" "$HOST_CP_BEFORE" "$HOST_CP_AFTER")
CP_TRUSTED_SKEW_BOUND=$((TRUSTED_SKEW + CP_SKEW))

printf 'clock_evidence trusted_source=%s trusted_date=%s host_trusted_skew_seconds=%s cp_host_skew_seconds=%s cp_trusted_skew_bound_seconds=%s\n' \
  "$TRUSTED_TIME_URL" "$TRUSTED_DATE" "$TRUSTED_SKEW" "$CP_SKEW" \
  "$CP_TRUSTED_SKEW_BOUND"
test "$TRUSTED_SKEW" -le 5
test "$CP_TRUSTED_SKEW_BOUND" -le 5
unset TRUSTED_DATE TRUSTED_TIME_URL

./validate.sh .env
```

Retain the single `clock_evidence` line. It contains the source, timestamp,
measured host skew, and conservative control-plane-to-trusted skew bound, not
credentials. If organizational policy designates a different trusted HTTPS
time endpoint, substitute that approved endpoint and record it with the
evidence; do not waive either comparison.

Keep the variable-bearing operator shell free for the remaining commands. In a
separate terminal, run the agent in the foreground and retain that terminal as
the stop handle:

```bash
cd "$(git rev-parse --show-toplevel)/deploy/proving-ground"
./run-agent.sh
```

Stop it with `Ctrl-C` before changing `.env`, switching revisions, or starting
Gate 6. Before accepting live work, retain an agent log entry whose message is
`fenced lease renewal succeeded`, whose `renewal_phase` is `initial`, and whose
job ID, attempt ID, lease generation, and renewed deadline match that running
attempt. The log deliberately excludes the fencing token.

The first
test uses the bundled local backend template exactly as supplied;
authenticated remote backends are outside this proving-ground gate. Create and
record `PRIMARY_LIVE_REQUEST_ID` as the requester, then validate, plan,
approve, and lock it with the same role handoff used in the rehearsal.

Before dispatching the primary LivePlan, require its UUID-derived state path to
be new. If it exists, stop and investigate; do not delete or reuse unfamiliar
state to make this check pass.

```bash
PRIMARY_STATE="$PROVING_GROUND_DIR/agent-state/terraform-request-$PRIMARY_LIVE_REQUEST_ID.tfstate"
test ! -e "$PRIMARY_STATE"
```

The admin dispatches `LivePlan` and waits for its terminal job result. A
successful plan leaves the request at `executing` because it is waiting for
human approval; it does not advance to `verifying`. In the portal, review the
Execution Job's server-derived Plan Review before approving live apply. Require
all of the following:

- the job is `Succeeded`, its result is `planned`, and it has a plan digest;
- the Plan Review says `digest_verified=true` and reports exactly one
  `virtual_machine` create, with zero update, delete, or replace actions;
- the plan contains no other managed resource, including a managed `no-op`;
  read-only inventory data sources are the only additional entries allowed;
- name, CPU, memory, disk, datacenter, cluster, datastore, network, and template
  in the Plan Review match the recorded request exactly; the control plane
  derives the VM shape from the managed resource's actual `change.after` and
  the placement names from the five expected data-source `change.after.name`
  values, and rejects missing or mismatched values;
- the Plan Review state key is `request-$PRIMARY_LIVE_REQUEST_ID`;
- the resolved local backend path is absolute and ends with
  `agent-state/terraform-request-$PRIMARY_LIVE_REQUEST_ID.tfstate`;
- no generic or shared Terraform state path is used;
- `agent-state/provider-authority.ref` exists and retains the same opaque,
  non-secret authority id/version from plan through apply and cleanup; trusted
  provisioning rotates that version whenever the destination, account, or any
  credential member changes, without recording or hashing those values;
- raw Terraform JSON, provider object identifiers, and credentials are absent
  from the portal/API projection, evidence export, screenshots, and
  operator-collected acceptance record. Exact digest-covered plan bytes remain
  restricted internal control-plane storage for re-deriving this projection.

The API refuses server live-apply approval when this digest-verified safe review
cannot be derived. Do not substitute raw Terraform output to bypass that gate.

Before any apply, rehearse the exact Gate 6 cleanup invocation by adding
`--preflight`. Use `PRIMARY_LIVE_REQUEST_ID`, `PRIMARY_LIVE_VM_NAME`, and every
recorded original input. The command must pass before continuing; it validates
the arguments, tools, environment, backend rendering, and Terraform input file
without initializing Terraform or contacting vSphere.

```bash
cd "$PROVING_GROUND_DIR"
./destroy-state.sh --preflight \
  --state-key "request-$PRIMARY_LIVE_REQUEST_ID" \
  --offering linux-server-deployment \
  --request-id "$PRIMARY_LIVE_REQUEST_ID" \
  --vm-name "$PRIMARY_LIVE_VM_NAME" \
  --site DEFRA \
  --environment test \
  --cpu "$CPU" \
  --memory-gb "$MEMORY_GB" \
  --disk-size-gb "$DISK_SIZE_GB" \
  --datacenter "$DATACENTER" \
  --cluster "$CLUSTER" \
  --datastore "$DATASTORE" \
  --network "$NETWORK" \
  --template "$TEMPLATE"
```

For isolation evidence, the requester creates `ISOLATION_REQUEST_ID` with its
own VM name and the admin governs it through a successful `LivePlan`. Never
approve its live apply. Before that second plan, require its own state path to
be absent. Also run the following against the primary state file; repeat it
afterward and require byte-for-byte identical output. A plan-only run may
legitimately leave an unused local state absent.

```bash
ISOLATION_STATE="$PROVING_GROUND_DIR/agent-state/terraform-request-$ISOLATION_REQUEST_ID.tfstate"
test ! -e "$ISOLATION_STATE"
if test -f "$PRIMARY_STATE"; then
  shasum -a 256 "$PRIMARY_STATE"
else
  printf 'absent  %s\n' "$PRIMARY_STATE"
fi
```

Also require the second Plan Review to report
`request-$ISOLATION_REQUEST_ID`; derive its corresponding different backend
path from the locked local template.
Conclude the isolation probe while it is still `executing`:

```bash
curl --disable --fail-with-body -sS --noproxy '*' -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/requests/$ISOLATION_REQUEST_ID/fail" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"First-test state-isolation probe concluded without apply"}'
```

From this point onward, every apply, verify, and cleanup action targets only
`PRIMARY_LIVE_REQUEST_ID`; do not reuse a generic `REQUEST_ID` variable.

## Gate 5: live apply and verification

1. The admin approves live apply only after reviewing Gate 4 evidence. This
   mints the control-plane-signed grant; `live-apply` is never dispatched via
   the generic execute endpoint. Capture its job ID for status and any required
   reconciliation:

   ```bash
   LIVE_APPLY=$(curl --disable --fail-with-body -sS --noproxy '*' \
     -H "@$ADMIN_HEADERS" \
     -X POST "$BASE/api/requests/$PRIMARY_LIVE_REQUEST_ID/approve-live-apply")
   APPLY_JOB_ID=$(printf '%s' "$LIVE_APPLY" | jq -er '.job_id')
   ```
2. Wait for the latest `LiveApply` job to finish. During plan review and apply,
   the request remains `executing`; only an accepted apply result advances it to
   `verifying`.
3. Require a `Succeeded` job with result `verified`, a matching approved-plan
   digest, an exact job-spec/grant binding, a successful Terraform apply
   summary, and a clean post-apply re-plan.
4. Inspect vSphere directly. Confirm exactly one VM exists with the recorded
   placement and sizing.
5. Run request verification only after the converged apply job and provider
   check pass. The API rejects plan-only, unbound, inconclusive, and drifted
   live executions even if a stale client offers the action.
   Require final request status `completed` and a sealed, redacted evidence
   pack.

After every `LiveApply` attempt, successful or not, record both the isolated
Terraform-state disposition and a direct vSphere disposition. Any plan drift,
expired or invalid grant, missing credential, digest mismatch, unexpected
provider object, or uncertain disposition is a hard stop. Do not retry live
apply on the same request.

If the job is `ReconcileRequired`, inspect the isolated state and vSphere out of
band before resolving it. When the state contains the expected VM resource, use
the guarded Gate 6 destroy procedure. When the state is absent or mismatched but
vSphere contains an object, do not force this script against unrelated state;
use a separately approved provider-recovery procedure and retain only
value-free evidence. After the provider and state dispositions are known, the
admin resolves the job with a non-sensitive reason:

```bash
curl --disable --fail-with-body -sS --noproxy '*' -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/admin/agents/jobs/$APPLY_JOB_ID/reconcile" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"Provider and isolated state reconciled under the approved recovery record"}'
```

That moves the job to `Failed` but deliberately leaves the parent request at
`executing`. Conclude it separately:

```bash
curl --disable --fail-with-body -sS --noproxy '*' -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/requests/$PRIMARY_LIVE_REQUEST_ID/fail" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"Live apply did not complete with a provable successful disposition"}'
```

For any other unsuccessful LiveApply status, perform the same state/provider
inspection and recovery, then call request `fail` if it is not already
terminal. A new attempt requires a fresh request, plan, review, and approval.

## Gate 6: mandatory cleanup

The control plane currently emits `LiveDestroy` only as compensation after a
failed multi-step run. It does not expose operator destroy for this successful
single-job request. Use the reviewed out-of-band procedure immediately after
Gate 5. Stop the polling agent first so it cannot start another job against the
same backend, but keep the control plane, database, and `agent-state/` intact:

```bash
test "$(git -C "$REPO_ROOT" rev-parse HEAD)" = "$TEST_REVISION"
test -z "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)"
cd "$PROVING_GROUND_DIR"
./destroy-state.sh \
  --state-key "request-$PRIMARY_LIVE_REQUEST_ID" \
  --offering linux-server-deployment \
  --request-id "$PRIMARY_LIVE_REQUEST_ID" \
  --vm-name "$PRIMARY_LIVE_VM_NAME" \
  --site DEFRA \
  --environment test \
  --cpu "$CPU" \
  --memory-gb "$MEMORY_GB" \
  --disk-size-gb "$DISK_SIZE_GB" \
  --datacenter "$DATACENTER" \
  --cluster "$CLUSTER" \
  --datastore "$DATASTORE" \
  --network "$NETWORK" \
  --template "$TEMPLATE"
```

Use the exact original values. The script refuses unless the state contains
exactly one managed resource, the offering's expected VM, plus only the five
allowlisted read-only inventory data sources from the bundle. It shows a saved
destroy plan, requires the exact state key as confirmation, and applies only
that plan. Do not use `--yes` for the first test.

Cleanup passes only when:

- Terraform reports no managed resources in the isolated state;
- direct vSphere inspection confirms the VM is absent;
- after direct vSphere inspection, the value-free cleanup record under
  `agent-state/` contains `provider_verification=absent`, a nonempty
  `provider_verified_by`, and an RFC 3339 UTC `provider_verified_at`;
- the control-plane database and `agent-state/` remain available until the
  result is reviewed.

Only then may the operator reset Compose volumes or remove `agent-state/`.
`docker compose down -v` does not destroy provider resources.

If the guarded destroy command or either absence check fails, mark the live
test `FAIL` and stop. Preserve the database, `agent-state/`, cleanup output, and
provider object. Inspect state and vSphere, then use a separately approved
recovery procedure; never reset volumes, delete state, or blindly rerun destroy.

## Result and evidence

Report each gate as `PASS`, `FAIL`, or `BLOCKED` with:

- tested Git revision and timestamps;
- requester, approver, agent, request, and job identifiers;
- command exit results without secrets or raw provider output;
- plan and apply summaries plus their digests;
- state key and backend object/path;
- request audit/evidence references;
- direct provider create and removal observations;
- cleanup record path and final managed-resource count.

The operator changes the cleanup record from `pending` to the exact accepted
provider-verification values only after directly confirming the VM is absent.

The first platform rehearsal is accepted when Gates 1 through 3 pass. The first
live vSphere test is accepted only when all six gates pass, including cleanup.
An applied VM that was not removed is a failed test, regardless of request
status.
