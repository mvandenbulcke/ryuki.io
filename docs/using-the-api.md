# Using the API

Everything the portal does, it does through this API, and the same surface is
available to your own tooling: the same authentication, authorization, scopes,
and audited lifecycle. This guide covers the cross-cutting conventions and a
complete request lifecycle you can run with curl. The
[API Reference](api/endpoints.md) documents every generated route by area.

## Base URL and versioning

Application routes live under `/api` on the control plane, normally on the same
origin as the portal. Three operational routes live at the top level: `/health`
and `/ready` are unauthenticated probes, while `/metrics` requires human API
authentication. The API is not URI-versioned. Normal routed responses carry the
server version in `x-api-version`.

## Authentication

`RYUKI_AUTH_MODE` selects one of four session-establishment modes (see
[Configuration](configuration.md)); service API tokens are a separate,
mode-independent credential type.

Those modes document the current API. The production target supports several
configured OpenID Connect providers simultaneously, brokered SAML/LDAP/AD,
local WebAuthn emergency access, OAuth service principals, scoped compatibility
tokens, and workload identity, all normalized into one principal model. See the
[Platform Security Boundary Specification](architecture/platform-security-boundary.md#pluggable-authentication-providers).

**Development modes** (`mock-dry-run`, the default, and `static-dry-run`): requests run as a static admin session with no credentials. Nothing to configure; never run these against anything real.

**Local accounts** (`local`, current development/migration behavior): sign in
with a username and password and use the returned `session_token`. It is a
256-bit opaque `rys_...` bearer disclosed only by the login response and
cookie; the database stores only its keyed HMAC verifier. Browser safe reads may
use the session cookie, but unsafe methods reject cookie-only authorization as a
CSRF defense; scripts send the token in `X-Ryuki-Session-Id` (a compatibility
header name). Never log, commit, or reuse the token between clients. UUIDs from
the admin session inventory are non-secret management IDs and cannot
authenticate.

```bash
printf 'Password: ' >&2
IFS= read -r -s PASSWORD </dev/tty
printf '\n' >&2
LOGIN=$(printf '%s' "$PASSWORD" | \
  jq -Rs --arg username '<user>' '{username: $username, password: .}' | \
  curl --fail-with-body -sS -X POST 'https://<host>/api/auth/local/login' \
    -H 'Content-Type: application/json' --data-binary @-)
unset PASSWORD
SESSION_TOKEN=$(printf '%s' "$LOGIN" | jq -er '.session_token')
unset LOGIN
umask 077
SESSION_HEADER=$(mktemp "${TMPDIR:-/tmp}/ryuki-session.XXXXXX")
printf 'X-Ryuki-Session-Id: %s\n' "$SESSION_TOKEN" > "$SESSION_HEADER"
unset SESSION_TOKEN

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

**Current API tokens** are the available compatibility credential for
integrations once the platform is using database-backed interactive
authentication. An interactive Local or Entra
administrator mints one; another API token cannot mint tokens. The `ryk_...`
value is returned exactly once. Tokens created while the platform is in
`mock-dry-run` or `static-dry-run` are persisted with `token_valid: false` and
cannot authenticate. Usable tokens can carry site and environment scopes, which
narrow everything the token sees—the recommended blast-radius control.

Current token authority is derived from role names plus optional site and
environment scope and expiry. It does not yet implement the production token
contract. The target groups rotated versions into a credential family, binds
each token to the Ryuki audience and an explicit closed action set, represents
scope states unambiguously, enforces a short maximum TTL, and rotates by issuing
a new credential id with a bounded observable overlap before revoking the old
version. Target tokens never gain browser, interactive, step-up, or emergency
authority. See
[service credentials and API tokens](architecture/platform-security-boundary.md#service-credentials-and-api-tokens).

```bash
curl -s -X POST https://<host>/api/admin/tokens \
  -H "@$SESSION_HEADER" \
  -H "Content-Type: application/json" \
  -d '{"name": "ci-reader", "owner_principal": "ci@example.test", "roles": ["Auditor"], "site_scope": "DEFRA"}'

curl -s https://<host>/api/requests -H "Authorization: Bearer ryk_..."
```

## Request headers

Header names are case-insensitive. Use only the credential type appropriate to
the route's access class.

| Header | When to send it |
| --- | --- |
| `Authorization: Bearer ...` | Human API routes accept exactly one applicable credential: a `ryk_...` API token, a validated Entra JWT, or an opaque `rys_...` persisted-session token. Token minting rejects `ryk_...` credentials and requires an interactive administrator. Agent routes use their own `rya_...` bearer tokens. |
| `X-Ryuki-Session-Id` | Compatibility carrier for the opaque `rys_...` session token used by the portal and scripts. Despite the header name, an administrative session UUID is never valid here. HTTPS uses the `__Host-ryuki_session` cookie; explicitly configured non-Secure loopback development uses `ryuki_session`. Either cookie can authorize safe reads only in its matching mode; cookie-only `POST`, `PUT`, `PATCH`, and `DELETE` requests are rejected as a CSRF defense. |
| `Content-Type: application/json` | Required when the route consumes a JSON body. Do not re-encode a webhook body after signing it: the v1 webhook message covers the exact-body SHA-256 digest. |
| `x-ryuki-protocol-version` | Required on agent registration, poll, acknowledgement, heartbeat, and result requests. This build accepts version `2`; missing, duplicate, malformed, or unsupported values return `400`. The public-key and OpenAPI bootstrap reads do not require it. |
| `X-Hub-Signature-256` | Required by the inbound webhook receiver. Send the hex HMAC-SHA256 of the Ryuki v1 canonical message (fixed POST path, connection ID, timestamp, delivery ID, and exact-body SHA-256), optionally prefixed with `sha256=`. |
| `X-Ryuki-Webhook-Timestamp` | Required by the inbound webhook receiver. Send canonical Unix time in seconds; it is signed and accepted only within five minutes of both receiver clocks. |
| `X-Ryuki-Webhook-Delivery-Id` | Required by the inbound webhook receiver. Send a unique 1-128 byte identifier using `[A-Za-z0-9._-]`; it is signed and atomically deduplicated per connection. |
| `Idempotency-Key` | Enables durable deduplication for authenticated, DB-backed human mutations. Use a unique, unguessable key for each logical operation; the emergency-initiate route requires one. |

During the secure-cookie migration, successful login/callback and logout
responses send the `__Host-ryuki_session` field and a separate `ryuki_session`
expiry field. Proxies must preserve these as independent `Set-Cookie` header
fields; they must not comma-join them. The expired legacy name is never accepted
as an HTTPS credential.

For inbound webhooks, compute the HMAC over this exact UTF-8 v1 message with no
trailing newline (replace the placeholders with the header/path values and the
lowercase hex SHA-256 of the exact body bytes):

```text
ryuki-webhook-v1
method:POST
path:/api/integrations/{connection_id}/webhook
connection-id:{connection_id}
timestamp:{unix_seconds}
delivery-id:{delivery_id}
body-sha256:{lowercase_hex_digest}
```

Webhook request bodies are capped at 256 KiB independently of the configurable
whole-API body limit.

Send only one credential carrier per request. Combining
`X-Ryuki-Session-Id`, `Authorization`, or either session-cookie name;
duplicating a session cookie; mixing its old/new names; or presenting a
malformed/invalid prefixed credential fails closed without falling through to
another identity.

## Authorization

Human-session mutations are gated by one of five role permissions: `admin`,
`approve`, `execute`, `request`, or `audit`. Safe reads and non-human entry
points also use effective access classes such as composite `read`, `public`,
`agent`, and `webhook`; those labels are not additional roles. Results are then
narrowed by site and environment scope. [RBAC & Scoping](rbac-and-scoping.md)
defines these labels and the `404`/`403`/filtered-list behavior. The effective
access requirement for each route appears in the
[API Reference](api/endpoints.md).

## Conventions

### Idempotent mutations

The idempotency layer applies to authenticated human `POST`, `PUT`, `PATCH`,
and `DELETE` requests when PostgreSQL is available. It is opt-in unless the
route says otherwise: without a usable key, or without a database, the request
continues without deduplication. A usable key is 1..200 bytes; an unguessable
UUID is a good default. Keys are isolated by authenticated principal.

Continuing without PostgreSQL is current development/migration behavior, not a
production failover guarantee. Production security mutations, sessions,
replay/idempotency recording, approvals, and authoritative audit fail closed
when their durable state is unavailable.

The server fingerprints the method, full path and query string, and exact body.
For the same key and fingerprint, a completed JSON response is replayed with
its stored status and an `Idempotency-Replayed: true` header. A concurrent
in-flight request returns `409`; reusing the key for a different fingerprint
returns `422`. Records become eligible for the best-effort hourly expiry sweep
after 24 hours; do not assume a key becomes claimable at an exact instant.

`5xx` responses and responses that cannot be replayed faithfully are not
stored. This includes non-JSON responses, responses with replay-significant
headers, and `Cache-Control: no-store` one-time-secret responses. The
idempotency capture path has a 1 MiB request/response buffer limit. The
high-blast-radius `POST /api/ops/emergency/initiate` route requires a usable key
and returns `400 IDEMPOTENCY_KEY_REQUIRED` when it is absent or invalid.

### Pagination

Pagination is not universal, and defaults and caps are route-specific. Offset
routes generally accept `limit` and `offset`. A bare-array response can expose
the filtered pre-page total in `X-Total-Count`; object responses instead carry
route-specific metadata such as `total`, `limit`, and `offset`. Cursor routes
use their documented cursor pair—for example, audit export uses `after_id` and
returns `next_after_id`. Keep any accompanying time window stable while
advancing a cursor. All totals and pages are scope-filtered; never infer a
whole-table count.

### Errors

HTTP status is the authoritative contract, but error bodies are not globally
uniform. Many human API and middleware errors use the project `ApiError` shape,
whose `detail` member is optional:

```json
{ "error": "VALIDATION_FAILED", "message": "site is not active", "detail": "..." }
```

Legacy, agent, webhook, and extractor paths may instead return a compact
`{"error":"..."}` object, plain text, or an empty body. `ApiError` is not an
RFC 9457 Problem Details representation: it does not promise the RFC
`type`/`title`/`status` members or `application/problem+json`. Parse the body
documented for the route and always retain the HTTP status.

Common cross-cutting statuses are `401` for missing or unverified
authentication, `403` for insufficient permission or an explicitly requested
out-of-scope target, `413` for an oversized body, `429` for rate limiting, and
`504` when the configured request timeout expires. A lifecycle CAS `409`
requires reloading current state and deciding whether a new transition remains
valid; do not blindly replay it.

### Response metadata, retries, and limits

Capture `x-request-id` and `traceresponse` from responses that include them and
use them when correlating client failures with server traces. For correlation,
the current middleware reuses the second dash-separated `traceparent` segment
when it is 32 characters long; it does not fully validate W3C Trace Context.
Otherwise the server creates a hyphenated UUID request ID. Treat
`traceresponse` as Ryuki correlation metadata, not a W3C-conformance guarantee.
Normal routed responses also include `x-api-version`. A rate-limit `429`
includes `Retry-After` in whole seconds.

The request timeout defaults to 30 seconds and produces `504 REQUEST_TIMEOUT`
when it expires. The configurable global request-body limit defaults to
10 MiB; routes and middleware such as idempotency may impose a smaller limit.

### Reference coverage

The HTML [API Reference](api/endpoints.md) is generated from the registered
route surface and covers every generated control-plane route. The
[machine-readable OpenAPI document](openapi.json) is deliberately bounded
to the agent protocol, selected public/bootstrap endpoints, and selected
operational reads. Absence from OpenAPI does not mean that a route is absent;
use the HTML reference for the complete inventory.

### Other data conventions

Timestamps are RFC 3339 strings. DB-authoritative endpoints generally return
`source: "no-db"` plus empty reads or `503` writes when PostgreSQL is
unavailable. Static contracts and selected in-memory development handlers have
their documented fallback behavior instead.

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
  local password login session_token
  printf '%s password: ' "$username" >&2
  IFS= read -r -s password </dev/tty
  printf '\n' >&2
  login=$(printf '%s' "$password" | \
    jq -Rs --arg username "$username" '{username: $username, password: .}' | \
    curl --fail-with-body -sS -X POST "$BASE/api/auth/local/login" \
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
