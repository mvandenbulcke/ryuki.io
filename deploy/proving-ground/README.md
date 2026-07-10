# Live-execution proving ground

A self-contained control-plane stack for testing provider execution (vCenter
and similar systems). The
[First Test Acceptance Specification](../../docs/first-test.md) is normative;
the [Agents & Live Execution guide](../../docs/agents-and-live-execution.md)
explains the wider execution model.
It has separate Compose volumes, a network, and ports, so `deploy/compose` and
its data remain untouched.

| Piece | Where | Port |
| --- | --- | --- |
| PostgreSQL | Compose | 15432 |
| Vault (dev mode) | Compose | 18200 |
| Control-plane API (local auth, Vault resolver, persisted signing key) | Compose | 18081 |
| Portal (live-provider mode) | Compose | 18001 |
| Execution agent | host, `./run-agent.sh` | outbound only |

## Configure and validate

```bash
cd deploy/proving-ground
install -m 600 env.example .env
```

Replace the database, Vault, and local-account placeholders in the gitignored
`.env`. Leave the three vSphere credentials empty while
`PG_AGENT_ALLOW_LIVE=false`; fill them only before the approved live gate. Keep
`PG_AGENT_PLATFORM=DEFRA` and the bundled local backend template unchanged,
and keep the `requester` and `admin` accounts distinct. The requester creates
work; the admin approves the agent and drives every post-create request action,
including live apply. Successful single-job cleanup is currently out of band,
not an admin-approved control-plane destroy step.

Agent values are parsed as literal `KEY=value` text. HCL spaces, semicolons,
`$()`, and other shell metacharacters are not evaluated. Do not add an inline
comment to an agent value because it becomes part of that literal value.
Compose-only database, Vault, and local-account values are ignored by the
agent parser and are not exported to the agent process.

Run the non-destructive smoke check before starting anything:

```bash
./validate.sh .env
```

It checks shell syntax (including the cleanup utility), literal env parsing,
the two-account and `DEFRA` invariants, backend placeholder rendering, the
`/ready` health gate, and `docker compose config`. It does not start containers
or contact a provider.

## Bring up the control plane

```bash
# Build the two images from the exact revision being tested. Rebuild them for
# every new acceptance revision; a stale rust-dev tag is not evidence.
docker compose -f ../compose/compose.yaml build platform-api portal-ui

docker compose down
docker compose up -d --wait --force-recreate
curl --fail http://localhost:18081/ready
```

Do not enrol or dispatch work until `/ready` succeeds. Open
`http://localhost:18001` after that gate passes.

## Enrol the agent

Keep `PG_AGENT_ALLOW_LIVE=false` for the first pass.

```bash
./run-agent.sh
```

The first run creates an Ed25519 identity, self-registers `DEFRA`, and exits
pending approval. Sign in as `admin`, approve the pending agent in the Agents
view, sign out, and then start its polling loop:

```bash
./run-agent.sh
```

Each invocation runs Cargo's incremental release build first, so the process
cannot silently reuse an agent binary from an older protocol or JobSpec.
Record the startup log entry `CP wire protocol is compatible` with
`cp_protocol_version=2` and `agent_protocol_version=2`.

Agent identity, token, and Terraform backend state live in `agent-state/`,
which is gitignored.

## Dry-run rehearsal

Complete this handoff before enabling provider access:

1. Confirm `.env` still has `PG_AGENT_ALLOW_LIVE=false` and restart the agent
   after any change.
2. Sign in as `requester`, create a minimal server-deployment request targeting
   `DEFRA`, submit it, record the request ID, and sign out. The Requester role
   creates work but cannot run operator transitions.
3. Sign in as `admin`. Validate and plan the request, review it, approve it,
   lock it, and dispatch the offline/dry-run execution. The requester must never
   approve work they created.
4. Let the agent process the `OfflineDryRun` job. Wait for the request to reach
   `verifying`, then run Verify as `admin` and require `completed`. Review the
   timeline and signed result without any provider mutation.
5. Create a separate request and govern it through lock, then dispatch
   `LivePlan` while live mode remains disabled. Require a signed refusal and no
   mutation. This is the directly testable refusal: `LiveApply` requires a
   successful plan and `LiveDestroy` is system-only.

Do not continue until the dry-run evidence and maker/checker handoff are both
understood and repeatable.

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
   the required provider credentials, rerun `./validate.sh .env`, and restart
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
from `.env`; it does not print credentials or put them in its evidence file.
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
curl --fail http://localhost:18081/ready
./run-agent.sh
```

Deleting Compose volumes creates a new database and signing key. Removing only
`agent.token` triggers self-registration while preserving the agent identity
and any Terraform state needed for investigation. Approve the new pending agent
as `admin`, then run `./run-agent.sh` again to resume polling.

Only after provider cleanup is independently verified may you remove all local
agent state:

```bash
rm -rf agent-state
```

That final command is irreversible and removes the local Terraform state that
would otherwise be needed to destroy or reconcile live resources.
