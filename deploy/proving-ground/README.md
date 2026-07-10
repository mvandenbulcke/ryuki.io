# Live-execution proving ground

A self-contained control-plane stack for testing real provider execution
(vCenter and friends) per the
[Agents & Live Execution guide](https://ryuki.io/agents-and-live-execution.html).
Separate compose project, volumes, network, and ports — the regular dev
stack (`deploy/compose`) and its data are untouched.

| Piece | Where | Port |
| --- | --- | --- |
| PostgreSQL | compose | 15432 |
| Vault (dev mode) | compose | 18200 |
| Control-plane API (`local` auth, Vault resolver, persisted signing key) | compose | 18081 |
| Portal (live-provider mode) | compose | 18001 |
| Execution agent | host, `./run-agent.sh` | outbound only |

## Bring-up

```bash
cd deploy/proving-ground
cp env.example .env          # fill in: passwords, platform, vSphere creds

# build the two images once (shared with the dev stack)
docker compose -f ../compose/compose.yaml build platform-api portal-ui

docker compose create        # containers exist, powered DOWN
docker compose up -d         # start when ready
```

Sign in at `http://localhost:18001` with a `PG_LOCAL_USERS` account.

## Enrol the agent

```bash
./run-agent.sh               # first run: self-registers, exits pending approval
# approve in the portal (Agents tab) or via the API as a PlatformAdmin
./run-agent.sh               # second run: loads the token, starts polling
```

Agent state (Ed25519 key, token, terraform state) lives in
`./agent-state/` (gitignored). Keep `PG_AGENT_ALLOW_LIVE=false` first and
rehearse the whole lifecycle dry-run; flip it to `true` only when you mean
it — live applies additionally require the plan-review approval chain, so
nothing mutates on a flag alone.

## First live test

Follow "Running a live apply against real infrastructure" in the guide:
dispatch a `LivePlan` for a vsphere server-deployment, review the plan
evidence, approve, and the agent applies the saved plan bytes. A missing
credential or backend produces a signed, value-free refusal — that is the
fail-closed design working, not a bug.

## Teardown

```bash
docker compose down          # keep volumes (DB + signing key survive)
docker compose down -v       # destroy volumes too (agents must re-enrol)
```
