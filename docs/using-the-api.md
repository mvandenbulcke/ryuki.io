# Using the API

Everything the portal does, it does through this API, and everything the API serves is available to your own tooling: the same authentication, the same permission tiers, the same audited lifecycle. This guide covers how to authenticate, the conventions every endpoint follows, and a complete request lifecycle you can run with curl. The [API Reference](api-reference.md) documents every route by area.

## Base URL and versioning

All routes live under `/api` on the control plane (the same origin the portal is served behind). Every response carries an `x-api-version` header. Health lives at `/health` and readiness at `/ready`, both unauthenticated.

## Authentication

The API supports three ways in, selected by the platform's `RYUKI_AUTH_MODE` (see [Configuration](configuration.md)):

**Development modes** (`mock-dry-run`, the default, and `static-dry-run`): requests run as a static admin session with no credentials. Nothing to configure; never run these against anything real.

**Local accounts** (`local`): sign in and use the returned session ID. Browser
safe reads may use the session cookie, but unsafe methods reject cookie-only
authorization as a CSRF defense; scripts must send `X-Ryuki-Session-Id`.

```bash
printf 'Password: ' >&2
IFS= read -r -s PASSWORD </dev/tty
printf '\n' >&2
LOGIN=$(printf '%s' "$PASSWORD" | \
  jq -Rs --arg username '<user>' '{username: $username, password: .}' | \
  curl --fail-with-body -sS -X POST 'https://<host>/api/auth/local/login' \
    -H 'Content-Type: application/json' --data-binary @-)
unset PASSWORD
SESSION_ID=$(printf '%s' "$LOGIN" | jq -er '.session_id')
unset LOGIN
umask 077
SESSION_HEADER=$(mktemp "${TMPDIR:-/tmp}/ryuki-session.XXXXXX")
printf 'X-Ryuki-Session-Id: %s\n' "$SESSION_ID" > "$SESSION_HEADER"
unset SESSION_ID

cleanup_session() {
  local logout_status=0
  if test -f "$SESSION_HEADER"; then
    curl --fail-with-body -sS -X POST \
      'https://<host>/api/auth/local/logout' \
      -H "@$SESSION_HEADER" >/dev/null || logout_status=$?
    rm -f "$SESSION_HEADER"
  fi
  return "$logout_status"
}
trap 'cleanup_session || true' EXIT

curl --fail-with-body -sS 'https://<host>/api/requests' \
  -H "@$SESSION_HEADER"
```

**Entra ID** (`entra-id`): browsers use the sign-in flow behind the portal's "Sign in with Microsoft Entra ID" button; non-interactive callers present a bearer JWT from the tenant, validated against its JWKS.

```bash
curl -s https://<host>/api/requests -H "Authorization: Bearer <entra-jwt>"
```

**API tokens** work in every mode and are the right choice for integrations. An admin mints one; the `ryk_...` value is returned exactly once. Tokens can carry site and environment scopes, which narrow everything the token sees — the recommended blast-radius control.

```bash
curl -s -X POST https://<host>/api/admin/tokens \
  -H "@$SESSION_HEADER" \
  -H "Content-Type: application/json" \
  -d '{"name": "ci-reader", "owner_principal": "ci@example.test", "roles": ["Auditor"], "site_scope": "DEFRA"}'

curl -s https://<host>/api/requests -H "Authorization: Bearer ryk_..."
```

## Authorization

Every route is gated by one of five permission tiers — `admin`, `approve`, `execute`, `request`, `audit` — derived from your roles, and results are narrowed by your site and environment scopes. The enforcement semantics (when you get a 404 versus a 403 versus a silently narrowed list) are documented in [RBAC & Scoping](rbac-and-scoping.md); the per-route tier appears in the [API Reference](api-reference.md).

## Conventions

**Errors** use HTTP status as the authoritative contract. Newer endpoints may
return a machine code, message, and optional detail, while legacy request and
agent handlers may return only a human-readable `error` string:

```json
{ "error": "VALIDATION_FAILED", "message": "site is not active", "detail": "..." }
```

Most `4xx` responses mean the request cannot succeed unchanged. A CAS `409`
requires reloading current state and deciding whether a new transition is still
valid; do not blindly replay it. `5xx` is the platform's problem. The bounded
agent, public, and operations-read subset additionally documents RFC
9457-shaped errors in the machine-readable [OpenAPI spec](api-reference.md);
the route-by-area reference covers the full registered control-plane surface.

**Pagination**: pagination-enabled list endpoints accept `limit` (default 500,
clamped to 1..1000) and `offset`. Object-shaped responses add `total`, `limit`,
and `offset` keys; bare-array responses carry the filtered total in an
`X-Total-Count` header instead. Check the route reference because pagination is
not yet universal. Totals are filtered and scope-aware, never whole-table
counts.

**Timestamps** are RFC 3339 strings. **Degraded behavior**: DB-authoritative
endpoints generally return `source: "no-db"` plus empty reads or `503` writes
when PostgreSQL is unavailable. Static contracts and selected in-memory
development handlers have their documented fallback behavior instead.

## Walkthrough: a request through its lifecycle

The heart of the platform is the governed request lifecycle. This walkthrough
maps directly to the proving ground: a `Requester` creates the request and a
different `PlatformAdmin` drives every later transition and evidence read.
It assumes PostgreSQL and an approved execution agent for `DEFRA`.
`mock-dry-run` maps every call to one static identity, so it cannot demonstrate
the required separation of duties. In `local` mode, sign in as the two
configured accounts and keep their session headers separate.

```bash
set -euo pipefail

BASE=http://127.0.0.1:18081
# The direct host-development API normally uses :8081 instead.
umask 077
AUTH_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ryuki-api-guide.XXXXXX")
REQUESTER_HEADERS="$AUTH_DIR/requester.headers"
ADMIN_HEADERS="$AUTH_DIR/admin.headers"

login_local() {
  local username=$1
  local header_file=$2
  local password login session_id
  printf '%s password: ' "$username" >&2
  IFS= read -r -s password </dev/tty
  printf '\n' >&2
  login=$(printf '%s' "$password" | \
    jq -Rs --arg username "$username" '{username: $username, password: .}' | \
    curl --fail-with-body -sS -X POST "$BASE/api/auth/local/login" \
      -H 'Content-Type: application/json' --data-binary @-)
  unset password
  session_id=$(printf '%s' "$login" | jq -er '.session_id')
  unset login
  printf 'X-Ryuki-Session-Id: %s\n' "$session_id" > "$header_file"
  unset session_id
}

logout_local() {
  local header_file=$1
  local logout_status=0
  if test -f "$header_file"; then
    curl --fail-with-body -sS -X POST "$BASE/api/auth/local/logout" \
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

login_local requester "$REQUESTER_HEADERS"
login_local admin "$ADMIN_HEADERS"

# 1. Create a server-deployment request as the requester.
# Replace every <...> value with an approved vSphere inventory name before
# selecting the live branch below.
CREATE=$(curl --fail-with-body -sS -H "@$REQUESTER_HEADERS" \
  -X POST "$BASE/api/requests" \
  -H "Content-Type: application/json" \
  -d '{
    "request_type": "server-deployment",
    "site": "DEFRA",
    "environment": "test",
    "name": "app-server-01",
    "cpu": 4,
    "memory_gb": 16,
    "justification": "First governed server deployment test",
    "fields": {
      "operating_system": "RHEL 9",
      "datacenter": "<vSphere-datacenter>",
      "cluster": "<vSphere-cluster>",
      "datastore": "<vSphere-datastore>",
      "network": "<vSphere-network>",
      "template": "<approved-vSphere-template>",
      "disk_size_gb": "80"
    }
  }')
REQ=$(printf '%s' "$CREATE" | jq -er '.id')

# 2. The admin drives every post-create governance stage.
curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/requests/$REQ/validate"
curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/requests/$REQ/plan"
curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/requests/$REQ/approve"
curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/requests/$REQ/lock"
```

All values under `fields` are JSON strings, including numeric-looking values
such as `disk_size_gb`. Top-level `cpu` and `memory_gb` are JSON numbers.

Execution is asynchronous. Use this helper after every execution or apply dispatch; it returns only for `Succeeded` and fails closed on every terminal failure state.

```bash
wait_for_latest_job() {
  expected_job=$1
  while true; do
    JOB_JSON=$(curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
      "$BASE/api/requests/$REQ/execution-job")
    CURRENT_JOB=$(printf '%s' "$JOB_JSON" | jq -er '.agent_job_id')
    JOB_STATUS=$(printf '%s' "$JOB_JSON" | jq -er '.status')

    if [ "$CURRENT_JOB" != "$expected_job" ]; then
      printf 'expected job %s, but request reports %s\n' \
        "$expected_job" "$CURRENT_JOB" >&2
      return 1
    fi

    printf 'job %s: %s\n' "$CURRENT_JOB" "$JOB_STATUS"
    case "$JOB_STATUS" in
      Succeeded) return 0 ;;
      Failed|Expired|ReconcileRequired|LiveRefused|DeadLettered|Cancelled)
        return 1
        ;;
    esac
    sleep 2
  done
}
```

Choose exactly one execution branch for this request. The default branch is
credential-free and provider-connection-free and is the right first pass;
Terraform registry downloads may still occur:

```bash
# 3a. Offline dry-run branch (default; no provider mutation).
EXECUTION=$(curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/requests/$REQ/execute")
EXECUTION_JOB=$(printf '%s' "$EXECUTION" | jq -er '.agent_job_id')
wait_for_latest_job "$EXECUTION_JOB"
```

For an explicitly authorized infrastructure test, start from a newly locked
request and use the live branch instead. This one-request walkthrough
illustrates the API calls; it is not the full four-request acceptance recipe in
[First Test Acceptance](first-test.md). Approve the disposable target before
dispatch. Live plan may read the provider and update backend lock or state
metadata, but it must not create, update, or delete provider resources. Live
apply is dispatched only after the admin approves the completed plan digest.
The current approval endpoints support only the reviewed Linux and Windows
vSphere single-VM bundles; other Terraform plans and Ansible check-mode results
remain preview-only.

```bash
# 3b. Live branch. Do not run this after branch 3a on the same request.
LIVE_PLAN=$(curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/requests/$REQ/execute?mode=live-plan")
PLAN_JOB=$(printf '%s' "$LIVE_PLAN" | jq -er '.agent_job_id')
wait_for_latest_job "$PLAN_JOB"

# Review only the server-derived, digest-verified projection. Do not approve
# from raw Terraform/provider output. Compare every placement value with the
# recorded request before continuing. The control plane has already required
# the VM's actual planned name/CPU/memory/disk and the five planned placement
# lookup names to match the JobSpec exactly.
PLAN_RESULT=$(curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  "$BASE/api/admin/agents/jobs/$PLAN_JOB/result")
printf '%s' "$PLAN_RESULT" | jq -e '
  .plan_review as $review
  | if ($review.digest_verified == true
      and $review.counts == {create: 1, update: 0, delete: 0, replace: 0})
    then $review
    else error("digest-verified single-create plan review is unavailable")
    end'
```

For the normative first test, stop here. Complete Gate 4's separate-request
state-isolation proof and the exact `destroy-state.sh --preflight` rehearsal.
Do not run the next block until both pass and you have returned to the primary
request.

```bash
LIVE_APPLY=$(curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/requests/$REQ/approve-live-apply")
APPLY_JOB=$(printf '%s' "$LIVE_APPLY" | jq -er '.job_id')
wait_for_latest_job "$APPLY_JOB"

# vSphere live applies must include a clean post-apply re-plan. An `applied`
# result without `verified` convergence is a hard stop.
APPLY_RESULT=$(curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  "$BASE/api/admin/agents/jobs/$APPLY_JOB/result")
APPLY_STATUS=$(printf '%s' "$APPLY_RESULT" | jq -er '.result_status')
test "$APPLY_STATUS" = verified
```

Only verify after the selected branch has succeeded and the signed agent result has advanced the request to `verifying`:

```bash
# 4. Confirm the asynchronous backlink before running verification.
REQUEST_JSON=$(curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  "$BASE/api/requests/$REQ")
REQUEST_STATUS=$(printf '%s' "$REQUEST_JSON" | jq -er '.status')
if [ "$REQUEST_STATUS" != "verifying" ]; then
  printf 'request is %s, expected verifying\n' "$REQUEST_STATUS" >&2
  exit 1
fi

curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  -X POST "$BASE/api/requests/$REQ/verify"

# 5. Read the state, the audit trail, and the sealed evidence pack.
curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  "$BASE/api/requests/$REQ"
curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  "$BASE/api/requests/$REQ/audit"
curl --fail-with-body -sS -H "@$ADMIN_HEADERS" \
  "$BASE/api/requests/$REQ/evidence"
```

If you selected the live branch, `completed` is not final acceptance. Record
the state/provider disposition after the apply, then immediately perform the
mandatory state-keyed cleanup and direct vSphere absence check in Gate 6 of
[First Test Acceptance](first-test.md). Preserve the database and agent state
until that evidence is accepted. An uncertain apply follows that document's
reconcile-and-fail procedure and is never retried on the same request.

Every transition is CAS-guarded (a conflicting transition answers 409),
attributed, and appended to the hash-chained audit trail. A successful LivePlan
records an agent-attributed approval pause while the request remains
`executing`; only the accepted execution result for the selected branch moves
the request to `verifying`.

From here: multi-step requests and per-step live approvals are covered in [Multi-Step Orchestration](orchestration.md), and taking execution to real infrastructure in [Agents & Live Execution](agents-and-live-execution.md).
